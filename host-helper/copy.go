// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// copyTimeout bounds one copy of a disk. A reflink takes a moment. A sparse copy of a large disk takes minutes.
const copyTimeout = 10 * time.Minute

// copyChunk is the size of one read when a sparse copy moves data.
const copyChunk = 4 << 20

// copyDisk copies a build's disk to one new file, saved-state.ext4, in the build's directory. The runner asks after it
// has frozen the guest's /build, to save the build's state. The request names only the build.
//
// A build the helper holds is accepted when its disk in the build's directory is the file the helper linked into the
// jail at start: the same device and inode. A build the helper does not hold is accepted under the rules of discard:
// its unit is not running, and its disk has one name. The helper opens the disk beneath the build's directory without
// following a link, and writes the copy with O_EXCL, so a file that is already there is never changed. It gives the copy
// to the runner's account with mode 0600. It does not mount, check or parse the disk.
func (h *Helper) copyDisk(id string) Reply {
	h.mu.Lock()
	rec, held := h.records[id]
	if !held {
		if h.discarding[id] {
			h.mu.Unlock()
			return refused(refuse(CodeAlreadyRunning, "the disk of build %s is already in use by the helper", id))
		}
		active, err := h.sys.Active(UnitName(id))
		if err != nil {
			h.mu.Unlock()
			return refused(refuse(CodeSystemd, "%v", err))
		}
		if active {
			h.mu.Unlock()
			return refused(refuse(CodeAlreadyRunning, "the unit of build %s is running, but this helper does not hold it", id))
		}
		// A start of this build waits for the copy to end. The lock is not held across the copy, so other builds go on.
		h.discarding[id] = true
		defer func() {
			h.mu.Lock()
			delete(h.discarding, id)
			h.mu.Unlock()
		}()
	}
	h.mu.Unlock()

	dirfd, refusal := h.openBuildDir(id)
	if refusal != nil {
		return refused(refusal)
	}
	defer unix.Close(dirfd)
	dirStat, err := h.ops.Fstat(dirfd)
	if err != nil {
		return refused(refuse(CodeBadFile, "the directory of build %s cannot be read: %v", id, err))
	}
	src, err := openBeneath(dirfd, fileDisk, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY)
	if err != nil {
		return refused(describeOpenError(fileDisk, err))
	}
	defer unix.Close(src)
	st, err := h.ops.Fstat(src)
	if err != nil {
		return refused(refuse(CodeBadFile, "%s cannot be read: %v", fileDisk, err))
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return refused(refuse(CodeBadFile, "%s is not a regular file", fileDisk))
	}
	if owner := int(st.Uid); owner != h.Cfg.RunnerUID && !h.inBuildRange(owner) {
		return refused(refuse(CodeBadFile, "%s is not owned by the runner's account or a build user", fileDisk))
	}
	if uint64(st.Dev) != uint64(dirStat.Dev) {
		return refused(refuse(CodeBadFile, "%s is not on the same file system as the build's directory", fileDisk))
	}
	if held {
		if refusal := h.matchJailLink(rec, st); refusal != nil {
			return refused(refusal)
		}
	} else if st.Nlink != 1 {
		// A disk with another name in the file system could be any file the runner holds, such as its credentials.
		return refused(refuse(CodeBadFile, "%s has %d names, not one, so it may be another file the runner holds", fileDisk, st.Nlink))
	}

	dst, err := unix.Openat(dirfd, fileSavedState, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if err == unix.EEXIST {
			return refused(refuse(CodeBadFile, "%s already exists in the directory of build %s", fileSavedState, id))
		}
		return refused(refuse(CodeBadFile, "%s cannot be made in the directory of build %s: %v", fileSavedState, id, err))
	}
	defer unix.Close(dst)
	fail := func(r *Refusal) Reply {
		_ = unix.Unlinkat(dirfd, fileSavedState, 0)
		return refused(r)
	}
	if err := h.ops.Fchown(dst, h.Cfg.RunnerUID, h.Cfg.RunnerGID); err != nil {
		return fail(refuse(CodeInternal, "the copy of the disk of build %s could not be given to the runner's account: %v", id, err))
	}
	if err := h.ops.Clone(dst, src); err != nil {
		if err := sparseCopy(dst, src, st.Size, time.Now().Add(copyTimeout)); err != nil {
			return fail(refuse(CodeInternal, "the disk of build %s could not be copied: %v", id, err))
		}
	}
	after, err := h.ops.Fstat(dst)
	if err != nil {
		return fail(refuse(CodeInternal, "the copy of the disk of build %s cannot be read: %v", id, err))
	}
	copied := after.Blocks * 512
	return Reply{Status: "ok", CopiedBytes: &copied}
}

// matchJailLink checks that the disk in the build's directory is the file the helper linked into the build's jail.
// Another file at that name could be any file the runner holds.
func (h *Helper) matchJailLink(rec *record, disk unix.Stat_t) *Refusal {
	chroot, err := unix.Open(rec.Chroot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return refuse(CodeBadFile, "the jail of build %s cannot be opened: %v", rec.Build, err)
	}
	defer unix.Close(chroot)
	linked, err := openBeneath(chroot, fileDisk, unix.O_PATH|unix.O_NOFOLLOW)
	if err != nil {
		return refuse(CodeBadFile, "the disk in the jail of build %s cannot be opened: %v", rec.Build, err)
	}
	defer unix.Close(linked)
	jail, err := fstat(linked)
	if err != nil {
		return refuse(CodeBadFile, "the disk in the jail of build %s cannot be read: %v", rec.Build, err)
	}
	if jail.Dev != disk.Dev || jail.Ino != disk.Ino {
		return refuse(CodeBadFile, "%s is not the file the helper linked into the jail of build %s", fileDisk, rec.Build)
	}
	return nil
}

// sparseCopy copies the data runs of src to dst and leaves its holes unallocated. It gives up at the deadline.
func sparseCopy(dst, src int, size int64, deadline time.Time) error {
	if err := unix.Ftruncate(dst, size); err != nil {
		return err
	}
	buf := make([]byte, copyChunk)
	var offset int64
	for offset < size {
		data, err := unix.Seek(src, offset, unix.SEEK_DATA)
		if err == unix.ENXIO {
			break
		}
		if err != nil {
			return err
		}
		hole, err := unix.Seek(src, data, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		for at := data; at < hole; {
			if time.Now().After(deadline) {
				return fmt.Errorf("the copy ran past %s and was stopped", copyTimeout)
			}
			want := int64(len(buf))
			if hole-at < want {
				want = hole - at
			}
			n, err := unix.Pread(src, buf[:want], at)
			if err != nil {
				return err
			}
			if n == 0 {
				break
			}
			for written := 0; written < n; {
				w, err := unix.Pwrite(dst, buf[written:n], at+int64(written))
				if err != nil {
					return err
				}
				written += w
			}
			at += int64(n)
		}
		offset = hole
	}
	return nil
}

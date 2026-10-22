// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// discardTimeout bounds one e2fsck. A forced check of a full cache disk takes minutes.
const discardTimeout = 10 * time.Minute

// maxE2fsckOutput bounds the error output the helper keeps from e2fsck.
const maxE2fsckOutput = 4096

// e2fsckPaths are the places the helper looks for e2fsck, in order. They are fixed: a root process does not search a
// PATH that an account other than root could change.
var e2fsckPaths = []string{"/usr/sbin/e2fsck", "/sbin/e2fsck"}

// cappedBuffer keeps the first maxE2fsckOutput bytes written to it and drops the rest.
type cappedBuffer struct{ buf bytes.Buffer }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := maxE2fsckOutput - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// runE2fsck runs `e2fsck -f -y -E discard` on the open file as the runner's account, and returns the exit status and
// the first of its error output. The file system on the disk was written by a build's guest, so the helper does not
// parse it as root. The file is handed over as descriptor 3, so the program opens no path.
func runE2fsck(fd, uid, gid int, limit time.Duration) (int, string, error) {
	program := ""
	for _, path := range e2fsckPaths {
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
			program = path
			break
		}
	}
	if program == "" {
		return -1, "", fmt.Errorf("e2fsck is not installed at %s", strings.Join(e2fsckPaths, " or "))
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return -1, "", err
	}
	file := os.NewFile(uintptr(dup), "build.ext4")
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, "-f", "-y", "-E", "discard", "/dev/fd/3")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.ExtraFiles = []*os.File{file}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	var stderr cappedBuffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, "", nil
	case ctx.Err() != nil:
		return -1, stderr.buf.String(), fmt.Errorf("e2fsck ran past %s and was stopped", limit)
	case errors.As(err, &exit):
		return exit.ExitCode(), stderr.buf.String(), nil
	}
	return -1, stderr.buf.String(), err
}

// discard gives the free blocks of a stopped build's disk back to the host. The runner asks after a builder microVM
// has stopped, and before it moves the disk back to the repository's image directory.
//
// The helper refuses a build that it holds, or whose unit is running, because that build has the disk open. It opens
// the disk beneath the runner's build directory without following a link. It accepts only a regular file with one name
// that belongs to the runner or to a build user. It gives the file to the runner's account and runs e2fsck as that
// account, so no program run as root reads what the guest wrote.
func (h *Helper) discard(id string) Reply {
	h.mu.Lock()
	if _, held := h.records[id]; held {
		h.mu.Unlock()
		return refused(refuse(CodeAlreadyRunning, "build %s is still running, so its disk is in use", id))
	}
	if h.discarding[id] {
		h.mu.Unlock()
		return refused(refuse(CodeAlreadyRunning, "the disk of build %s is already being checked", id))
	}
	active, err := h.sys.Active(UnitName(id))
	if err != nil {
		h.mu.Unlock()
		return refused(refuse(CodeSystemd, "%v", err))
	}
	if active {
		h.mu.Unlock()
		return refused(refuse(CodeAlreadyRunning, "the unit of build %s is running, so its disk is in use", id))
	}
	// A start of this build waits for the check to end. The lock is not held across e2fsck, so other builds go on.
	h.discarding[id] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.discarding, id)
		h.mu.Unlock()
	}()

	dirfd, refusal := h.openBuildDir(id)
	if refusal != nil {
		return refused(refusal)
	}
	defer unix.Close(dirfd)
	dirStat, err := h.ops.Fstat(dirfd)
	if err != nil {
		return refused(refuse(CodeBadFile, "the directory of build %s cannot be read: %v", id, err))
	}
	fd, err := openBeneath(dirfd, fileDisk, unix.O_RDWR|unix.O_NONBLOCK|unix.O_NOCTTY)
	if err != nil {
		return refused(describeOpenError(fileDisk, err))
	}
	defer unix.Close(fd)
	st, err := h.ops.Fstat(fd)
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
	// A disk with another name in the file system could be any file the runner holds, such as its credentials.
	if st.Nlink != 1 {
		return refused(refuse(CodeBadFile, "%s has %d names, not one, so it may be another file the runner holds", fileDisk, st.Nlink))
	}
	if int(st.Uid) != h.Cfg.RunnerUID || int(st.Gid) != h.Cfg.RunnerGID {
		if err := h.ops.Fchown(fd, h.Cfg.RunnerUID, h.Cfg.RunnerGID); err != nil {
			return refused(refuse(CodeInternal, "the disk of build %s could not be given to the runner's account: %v", id, err))
		}
	}
	status, output, err := h.ops.RunE2fsck(fd, h.Cfg.RunnerUID, h.Cfg.RunnerGID, discardTimeout)
	if err != nil {
		return refused(refuse(CodeInternal, "e2fsck on the disk of build %s failed: %v", id, err))
	}
	// Exit 0 is a clean file system, and 1 one that e2fsck repaired, as a killed builder leaves it.
	if status != 0 && status != 1 {
		return refused(refuse(CodeInternal, "e2fsck on the disk of build %s exited with status %d: %s", id, status, firstLine(output)))
	}
	after, err := h.ops.Fstat(fd)
	if err != nil {
		return refused(refuse(CodeInternal, "the disk of build %s cannot be read after the check: %v", id, err))
	}
	freed := (st.Blocks - after.Blocks) * 512
	if freed < 0 {
		freed = 0
	}
	return Reply{Status: "ok", FreedBytes: &freed}
}

func firstLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const (
	jailDirName = "firecracker"
	// The guest's vsock context id, which the runner's exec agent client and the guest agree on.
	guestCID  = 3
	vsockPath = "/run/v.sock"
)

// jailPaths are where one build's jail lives. The jailer builds this layout itself.
type jailPaths struct {
	top    string // <jail base>/firecracker
	dir    string // <top>/<id>
	chroot string // <dir>/root
	run    string // <chroot>/run
}

func (h *Helper) jailPathsFor(id string) jailPaths {
	top := filepath.Join(h.Cfg.JailBase, jailDirName)
	dir := filepath.Join(top, id)
	chroot := filepath.Join(dir, "root")
	return jailPaths{top: top, dir: dir, chroot: chroot, run: filepath.Join(chroot, "run")}
}

// machineConfig is the Firecracker configuration the jailed process reads. Every path in it is a fixed path inside
// the jail, and only the processor count, the memory and the boot arguments come from the runner.
func machineConfig(vm vmSettings) ([]byte, error) {
	type drive struct {
		ID       string `json:"drive_id"`
		Path     string `json:"path_on_host"`
		Root     bool   `json:"is_root_device"`
		ReadOnly bool   `json:"is_read_only"`
	}
	config := map[string]any{
		"boot-source": map[string]any{"kernel_image_path": "/" + fileKernel, "boot_args": vm.BootArgs},
		"drives": []drive{
			{ID: "rootfs", Path: "/" + fileRootfs, Root: true, ReadOnly: true},
			{ID: "build", Path: "/" + fileDisk, Root: false, ReadOnly: false},
		},
		"machine-config": map[string]any{"vcpu_count": vm.CPUs, "mem_size_mib": vm.MemoryMiB, "smt": false},
		"vsock":          map[string]any{"guest_cid": guestCID, "uds_path": vsockPath},
	}
	return json.MarshalIndent(config, "", "  ")
}

// linkFromFD gives the open file a second name. It links the file the descriptor holds, so a name the runner
// swapped after the check cannot change which file is linked.
func linkFromFD(fd int, dest string) error {
	return unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", fd), unix.AT_FDCWD, dest, unix.AT_SYMLINK_FOLLOW)
}

// relinkSockets points each socket's link in the jail's run directory at that socket, replacing an existing link in
// one step, so a connection Firecracker makes meanwhile finds the old socket or the new one. The build's user owns the
// run directory, so it is opened through the chroot without following a link, and every name is made inside it.
func relinkSockets(paths jailPaths, sockets []socketFile) error {
	root, err := unix.Open(paths.chroot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	run, err := unix.Openat(root, filepath.Base(paths.run), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(run)
	for _, socket := range sockets {
		name := fmt.Sprintf("v.sock_%d", socket.port)
		temp := name + ".new"
		if err := unix.Unlinkat(run, temp, 0); err != nil && err != unix.ENOENT {
			return fmt.Errorf("clearing %s: %w", temp, err)
		}
		if err := unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", socket.fd), run, temp, unix.AT_SYMLINK_FOLLOW); err != nil {
			return fmt.Errorf("linking %s into the jail: %w", socket.name, err)
		}
		if err := unix.Renameat(run, temp, run, name); err != nil {
			_ = unix.Unlinkat(run, temp, 0)
			return fmt.Errorf("linking %s into the jail: %w", socket.name, err)
		}
		// A rename between two names of one file does nothing, so a socket the runner did not make again leaves its
		// second name behind.
		if err := unix.Unlinkat(run, temp, 0); err != nil && err != unix.ENOENT {
			return fmt.Errorf("clearing %s: %w", temp, err)
		}
	}
	return nil
}

func mkdirExact(path string, mode uint32) error {
	if err := unix.Mkdir(path, mode); err != nil {
		return err
	}
	return unix.Chmod(path, mode)
}

func chownDir(ops Ops, path string, uid, gid int) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return ops.Fchown(fd, uid, gid)
}

// makeJail builds the jail for one build: a directory only the build's user and the runner's account can reach, holding
// the build's own files as links, the machine configuration and the directory for the vsock sockets. The one file whose
// owner it changes is the build's disk, which the build's user writes.
func (h *Helper) makeJail(id string, uid int, files *buildFiles) error {
	paths := h.jailPathsFor(id)
	if err := unix.Mkdir(paths.top, 0o711); err != nil && err != unix.EEXIST {
		return err
	}
	if err := unix.Chmod(paths.top, 0o711); err != nil {
		return err
	}
	if err := mkdirExact(paths.dir, 0o700); err != nil {
		return err
	}
	if err := h.ops.SetACL(paths.dir, h.Cfg.RunnerUID, 0o1, false); err != nil {
		return err
	}
	if err := mkdirExact(paths.chroot, 0o700); err != nil {
		return err
	}
	if err := h.ops.SetACL(paths.chroot, h.Cfg.RunnerUID, 0o1, false); err != nil {
		return err
	}
	if err := chownDir(h.ops, paths.chroot, uid, uid); err != nil {
		return err
	}
	if err := mkdirExact(paths.run, 0o700); err != nil {
		return err
	}
	if err := chownDir(h.ops, paths.run, uid, uid); err != nil {
		return err
	}
	// The runner's account opens the sockets Firecracker makes here: it may enter the directory, and every file made in
	// it carries the same access.
	if err := h.ops.SetACL(paths.run, h.Cfg.RunnerUID, 0o1, false); err != nil {
		return err
	}
	if err := h.ops.SetACL(paths.run, h.Cfg.RunnerUID, 0o7, true); err != nil {
		return err
	}
	for name, fd := range map[string]int{fileKernel: files.kernel, fileRootfs: files.rootfs, fileDisk: files.disk} {
		if err := linkFromFD(fd, filepath.Join(paths.chroot, name)); err != nil {
			return fmt.Errorf("linking %s into the jail: %w", name, err)
		}
	}
	for _, socket := range files.sockets {
		if err := linkFromFD(socket.fd, filepath.Join(paths.run, fmt.Sprintf("v.sock_%d", socket.port))); err != nil {
			return fmt.Errorf("linking %s into the jail: %w", socket.name, err)
		}
	}
	config, err := machineConfig(files.vm)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(paths.chroot, fileVM), config, 0o444); err != nil {
		return err
	}
	// Last, so a failure above has changed no file the runner holds.
	return h.ops.Fchown(files.disk, uid, uid)
}

// restoreRunnerAccess gives the runner's account its way back to the build's vsock socket. Once it starts, the jailer
// sets the jail's root and run directories to mode 0700. On a directory with an ACL, that also clears the mask the
// runner's entry depends on, so the runner could no longer reach the socket. Firecracker makes the socket only after
// the jailer is done, so once the socket exists the access is put back. The build's user owns both directories by
// then, so each is opened without following a link, and its ACL is set through the open file.
func (h *Helper) restoreRunnerAccess(paths jailPaths) error {
	root, err := unix.Open(paths.chroot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	run, err := unix.Openat(root, filepath.Base(paths.run), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(run)
	deadline := time.Now().Add(h.vsockWait)
	for {
		var st unix.Stat_t
		if err := unix.Fstatat(run, filepath.Base(vsockPath), &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("Firecracker made no vsock socket in %s within %s", paths.run, h.vsockWait)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, fd := range []int{root, run} {
		if err := h.ops.SetACLFD(fd, h.Cfg.RunnerUID, 0o1); err != nil {
			return err
		}
	}
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// removeJail removes one build's jail. It opens each name without following a link and does not cross into another file
// system, so nothing outside the jail is removed.
func (h *Helper) removeJail(id string) error {
	paths := h.jailPathsFor(id)
	top, err := unix.Open(paths.top, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return err
	}
	defer unix.Close(top)
	st, err := fstat(top)
	if err != nil {
		return err
	}
	return removeTree(top, id, uint64(st.Dev))
}

func removeTree(parent int, name string, dev uint64) error {
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(parent, name, 0)
	}
	if uint64(st.Dev) != dev {
		return fmt.Errorf("%s is on another file system than the jail, so it was not removed", name)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), name)
	names, err := dir.Readdirnames(-1)
	if err != nil {
		dir.Close()
		return err
	}
	for _, child := range names {
		if err := removeTree(fd, child, dev); err != nil {
			dir.Close()
			return err
		}
	}
	dir.Close()
	return unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
}

// ACL entries in the form the kernel stores in the system.posix_acl_* attributes.
const (
	aclVersion   = 2
	aclUserObj   = 0x01
	aclUser      = 0x02
	aclGroupObj  = 0x04
	aclMask      = 0x10
	aclOther     = 0x20
	aclUndefined = 0xffffffff
)

func aclEntry(tag uint16, perm uint16, id uint32) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint16(out[0:], tag)
	binary.LittleEndian.PutUint16(out[2:], perm)
	binary.LittleEndian.PutUint32(out[4:], id)
	return out
}

// encodeACL is the ACL for a directory its owner alone uses: the owner has full access, the runner's account has perm,
// and no one else has any.
func encodeACL(runnerUID int, perm uint16) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, aclVersion)
	for _, entry := range [][]byte{
		aclEntry(aclUserObj, 0o7, aclUndefined),
		aclEntry(aclUser, perm, uint32(runnerUID)),
		aclEntry(aclGroupObj, 0, aclUndefined),
		aclEntry(aclMask, perm, aclUndefined),
		aclEntry(aclOther, 0, aclUndefined),
	} {
		out = append(out, entry...)
	}
	return out
}

// setACLFD gives the runner's account perm on the open directory, as its access ACL.
func setACLFD(fd int, runnerUID int, perm uint16) error {
	if err := unix.Fsetxattr(fd, "system.posix_acl_access", encodeACL(runnerUID, perm), 0); err != nil {
		return fmt.Errorf("setting the ACL of an open directory: %w (the file system under the jail must support POSIX ACLs)", err)
	}
	return nil
}

// setACL gives the runner's account perm on the directory, as its access ACL or as the default ACL new files inherit.
func setACL(path string, runnerUID int, perm uint16, isDefault bool) error {
	name := "system.posix_acl_access"
	if isDefault {
		name = "system.posix_acl_default"
	}
	if err := unix.Setxattr(path, name, encodeACL(runnerUID, perm), 0); err != nil {
		return fmt.Errorf("setting the ACL of %s: %w (the file system under the jail must support POSIX ACLs)", path, err)
	}
	return nil
}

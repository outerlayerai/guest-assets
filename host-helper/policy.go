// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Refusal is the reason the helper will not do what a request asks.
type Refusal struct {
	Code   string
	Reason string
}

func (r *Refusal) Error() string { return r.Code + ": " + r.Reason }

func refuse(code, format string, args ...any) *Refusal {
	return &Refusal{Code: code, Reason: fmt.Sprintf(format, args...)}
}

var buildIDPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

// The vsock ports the guest's relay reaches, by the socket the runner serves
// for each. They are the runner's: the relay and tunnel, the gateway, Claude,
// and one port per destination.
const (
	portTunnel      = 3128
	portGateway     = 3126
	portClaude      = 3127
	portDestination = 3129
	maxDestinations = 256
)

var destinationSocket = regexp.MustCompile(`^dest-(\d{1,3})\.sock$`)

func socketPort(name string) (int, bool) {
	switch name {
	case "tunnel.sock":
		return portTunnel, true
	case "gateway.sock":
		return portGateway, true
	case "claude.sock":
		return portClaude, true
	}
	if match := destinationSocket.FindStringSubmatch(name); match != nil {
		index, _ := strconv.Atoi(match[1])
		if index < maxDestinations {
			return portDestination + index, true
		}
	}
	return 0, false
}

// The names of the files the runner leaves in a build's directory. They are
// fixed here, so a request cannot name any other file.
const (
	fileKernel = "kernel"
	fileRootfs = "rootfs.ext4"
	fileDisk   = "build.ext4"
	fileVM     = "vm.json"
)

const maxVMConfig = 64 * 1024

// vmSettings are the three values the helper takes from the runner's machine configuration.
type vmSettings struct {
	CPUs      int
	MemoryMiB int
	BootArgs  string
}

type socketFile struct {
	name string
	port int
	fd   int
}

// buildFiles are the files of one build, opened without following a link and checked.
type buildFiles struct {
	dirfd   int
	kernel  int
	rootfs  int
	disk    int
	sockets []socketFile
	vm      vmSettings
}

func (b *buildFiles) close() {
	for _, fd := range []int{b.kernel, b.rootfs, b.disk, b.dirfd} {
		if fd > 0 {
			unix.Close(fd)
		}
	}
	for _, s := range b.sockets {
		unix.Close(s.fd)
	}
}

const resolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV

// openBeneath opens name below dirfd. The open fails if any component is a link, leaves dirfd or crosses a mount.
func openBeneath(dirfd int, name string, flags uint64) (int, error) {
	how := &unix.OpenHow{Flags: flags | unix.O_CLOEXEC, Resolve: resolveFlags}
	for {
		fd, err := unix.Openat2(dirfd, name, how)
		if err == unix.EINTR {
			continue
		}
		return fd, err
	}
}

func fstat(fd int) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	return st, err
}

func (h *Helper) inBuildRange(uid int) bool {
	return uid >= h.Cfg.UIDBase && uid < h.Cfg.UIDBase+h.Cfg.UIDCount
}

func describeOpenError(name string, err error) *Refusal {
	switch err {
	case unix.ELOOP, unix.EXDEV, unix.ENOTDIR:
		return refuse(CodeBadFile, "%s is a symbolic link, or leaves the build's directory", name)
	case unix.ENOENT:
		return refuse(CodeBadFile, "%s does not exist", name)
	}
	return refuse(CodeBadFile, "%s cannot be opened: %v", name, err)
}

// openBuild opens the build's directory below the runner's build directory, then each fixed file in it. It changes nothing.
func (h *Helper) openBuild(id string, jailDev uint64) (*buildFiles, *Refusal) {
	files := &buildFiles{dirfd: -1, kernel: -1, rootfs: -1, disk: -1}
	fail := func(r *Refusal) (*buildFiles, *Refusal) {
		files.close()
		return nil, r
	}
	root, err := unix.Open(h.Cfg.BuildsRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(refuse(CodeOutsideBuilds, "the runner's build directory %s cannot be opened: %v", h.Cfg.BuildsRoot, err))
	}
	defer unix.Close(root)
	rootStat, err := h.ops.Fstat(root)
	if err != nil || int(rootStat.Uid) != h.Cfg.RunnerUID || rootStat.Mode&0o022 != 0 {
		return fail(refuse(CodeOutsideBuilds, "the build directory %s is not the runner's, or others can write it", h.Cfg.BuildsRoot))
	}
	dirfd, err := openBeneath(root, id, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return fail(refuse(CodeOutsideBuilds, "build %s is not a directory inside the runner's build directory: %v", id, err))
	}
	files.dirfd = dirfd
	dirStat, err := h.ops.Fstat(dirfd)
	if err != nil || int(dirStat.Uid) != h.Cfg.RunnerUID || dirStat.Mode&0o022 != 0 {
		return fail(refuse(CodeBadFile, "the directory of build %s is not the runner's, or others can write it", id))
	}

	// open opens one regular file the runner owns, on the jail's file system.
	open := func(name string, allowBuildUser bool) (int, unix.Stat_t, *Refusal) {
		fd, err := openBeneath(dirfd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY)
		if err != nil {
			return -1, unix.Stat_t{}, describeOpenError(name, err)
		}
		st, err := h.ops.Fstat(fd)
		if err != nil {
			unix.Close(fd)
			return -1, st, refuse(CodeBadFile, "%s cannot be read: %v", name, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			unix.Close(fd)
			return -1, st, refuse(CodeBadFile, "%s is not a regular file", name)
		}
		owner := int(st.Uid)
		if owner != h.Cfg.RunnerUID && !(allowBuildUser && h.inBuildRange(owner)) {
			unix.Close(fd)
			return -1, st, refuse(CodeBadFile, "%s is not owned by the runner's account", name)
		}
		if uint64(st.Dev) != jailDev {
			unix.Close(fd)
			return -1, st, refuse(CodeBadFile, "%s is not on the same file system as the jail, so it cannot be linked into it", name)
		}
		return fd, st, nil
	}

	var st unix.Stat_t
	var refusal *Refusal
	if files.kernel, st, refusal = open(fileKernel, false); refusal != nil {
		return fail(refusal)
	}
	if st.Mode&0o444 != 0o444 {
		return fail(refuse(CodeBadFile, "%s must be readable by every user, because the build's user reads it", fileKernel))
	}
	if files.rootfs, st, refusal = open(fileRootfs, false); refusal != nil {
		return fail(refusal)
	}
	if st.Mode&0o444 != 0o444 {
		return fail(refuse(CodeBadFile, "%s must be readable by every user, because the build's user reads it", fileRootfs))
	}
	if files.disk, st, refusal = open(fileDisk, true); refusal != nil {
		return fail(refusal)
	}
	// A disk with another name in the file system could be any file the runner holds, such as its credentials.
	if st.Nlink != 1 {
		return fail(refuse(CodeBadFile, "%s has %d names, not one, so it may be another file the runner holds", fileDisk, st.Nlink))
	}
	vmfd, vmStat, refusal := open(fileVM, false)
	if refusal != nil {
		return fail(refusal)
	}
	defer unix.Close(vmfd)
	if vmStat.Size > maxVMConfig {
		return fail(refuse(CodeBadFile, "%s is larger than %d bytes", fileVM, maxVMConfig))
	}
	settings, refusal := readVMSettings(vmfd)
	if refusal != nil {
		return fail(refusal)
	}
	files.vm = settings

	names, err := listNames(dirfd)
	if err != nil {
		return fail(refuse(CodeBadFile, "the directory of build %s cannot be listed: %v", id, err))
	}
	for _, name := range names {
		port, ok := socketPort(name)
		if !ok {
			continue
		}
		fd, err := openBeneath(dirfd, name, unix.O_PATH|unix.O_NOFOLLOW)
		if err != nil {
			return fail(describeOpenError(name, err))
		}
		files.sockets = append(files.sockets, socketFile{name: name, port: port, fd: fd})
		sst, err := h.ops.Fstat(fd)
		if err != nil || sst.Mode&unix.S_IFMT != unix.S_IFSOCK || int(sst.Uid) != h.Cfg.RunnerUID || uint64(sst.Dev) != jailDev {
			return fail(refuse(CodeBadFile, "%s is not a socket the runner owns on the jail's file system", name))
		}
	}
	return files, nil
}

func readVMSettings(fd int) (vmSettings, *Refusal) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return vmSettings{}, refuse(CodeBadFile, "%s cannot be read: %v", fileVM, err)
	}
	file := os.NewFile(uintptr(dup), fileVM)
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxVMConfig+1))
	if err != nil || len(data) > maxVMConfig {
		return vmSettings{}, refuse(CodeBadFile, "%s cannot be read", fileVM)
	}
	var parsed struct {
		Machine struct {
			CPUs int `json:"vcpu_count"`
			Mem  int `json:"mem_size_mib"`
		} `json:"machine-config"`
		Boot struct {
			Args string `json:"boot_args"`
		} `json:"boot-source"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return vmSettings{}, refuse(CodeBadFile, "%s is not JSON: %v", fileVM, err)
	}
	if parsed.Machine.CPUs < 1 || parsed.Machine.CPUs > 128 {
		return vmSettings{}, refuse(CodeBadFile, "%s asks for %d processors", fileVM, parsed.Machine.CPUs)
	}
	if parsed.Machine.Mem < 1 || parsed.Machine.Mem > 1<<20 {
		return vmSettings{}, refuse(CodeBadFile, "%s asks for %d MiB of memory", fileVM, parsed.Machine.Mem)
	}
	if len(parsed.Boot.Args) > 2048 || strings.ContainsAny(parsed.Boot.Args, "\x00\n") {
		return vmSettings{}, refuse(CodeBadFile, "%s holds boot arguments that are too long or hold a line break", fileVM)
	}
	return vmSettings{CPUs: parsed.Machine.CPUs, MemoryMiB: parsed.Machine.Mem, BootArgs: parsed.Boot.Args}, nil
}

// hashTrusted checks a binary is a regular file owned by the trusted user that no one else can write, and has the
// pinned hash. It hashes the open file, not the path.
func (h *Helper) hashTrusted(binary Binary, what string) *Refusal {
	fd, err := unix.Open(binary.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return refuse(CodeHashMismatch, "the %s at %s cannot be opened: %v", what, binary.Path, err)
	}
	file := os.NewFile(uintptr(fd), binary.Path)
	defer file.Close()
	st, err := h.ops.Fstat(fd)
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != h.ops.TrustedUID || st.Mode&0o022 != 0 {
		return refuse(CodeHashMismatch, "the %s at %s is not a regular file that only the trusted user can write", what, binary.Path)
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return refuse(CodeHashMismatch, "the %s at %s cannot be read: %v", what, binary.Path, err)
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != binary.SHA256 {
		return refuse(CodeHashMismatch, "the %s at %s has sha256 %s, not the pinned %s", what, binary.Path, got, binary.SHA256)
	}
	return nil
}

// checkJailBase checks each directory from the trust root down to the jail base is a real directory that only the
// trusted user owns and can write. A jail base the runner's account could rename would let it point root's file
// operations somewhere else.
func (h *Helper) checkJailBase() (uint64, *Refusal) {
	rel, err := filepath.Rel(h.ops.TrustRoot, h.Cfg.JailBase)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return 0, refuse(CodeBadFile, "the jail base %s is not below %s", h.Cfg.JailBase, h.ops.TrustRoot)
	}
	path := h.ops.TrustRoot
	var dev uint64
	parts := []string{}
	if rel != "." {
		parts = strings.Split(rel, string(filepath.Separator))
	}
	for _, part := range append([]string{""}, parts...) {
		path = filepath.Join(path, part)
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return 0, refuse(CodeBadFile, "the jail base %s cannot be read: %v", path, err)
		}
		if part == "" && path == h.ops.TrustRoot {
			// The trust root itself is trusted.
			dev = uint64(st.Dev)
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != h.ops.TrustedUID || st.Mode&0o022 != 0 {
			return 0, refuse(CodeBadFile, "%s is not a directory that only the trusted user can write, so it cannot hold the jail", path)
		}
		dev = uint64(st.Dev)
	}
	return dev, nil
}

// listNames lists the names in the open directory.
func listNames(dirfd int) ([]string, error) {
	dup, err := unix.Dup(dirfd)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(dup), "build")
	defer dir.Close()
	return dir.Readdirnames(-1)
}

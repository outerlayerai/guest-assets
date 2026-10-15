// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

const testBuild = "0123456789ab"

type chownCall struct {
	path     string
	uid, gid int
}

type aclCall struct {
	path      string
	runnerUID int
	perm      uint16
	isDefault bool
}

// fakeSystemd records every command and answers from maps.
type fakeSystemd struct {
	mu     sync.Mutex
	runs   [][]string
	stops  []string
	active map[string]bool
	oom    map[string]int
	runErr error
	// noSocket stands for a Firecracker that never makes its vsock socket.
	noSocket bool
}

func (f *fakeSystemd) Run(argv []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.runErr != nil {
		return f.runErr
	}
	f.runs = append(f.runs, append([]string(nil), argv...))
	var id, base string
	for i, arg := range argv {
		if i+1 >= len(argv) {
			continue
		}
		switch arg {
		case "--unit":
			f.active[argv[i+1]] = true
		case "--id":
			id = argv[i+1]
		case "--chroot-base-dir":
			base = argv[i+1]
		}
	}
	// As the jailer and Firecracker do: the jailer sets the jail's root and run directories to 0700, and Firecracker
	// then makes its vsock socket in the run directory.
	if id != "" && base != "" {
		root := filepath.Join(base, jailDirName, id, "root")
		for _, dir := range []string{root, filepath.Join(root, "run")} {
			if err := os.Chmod(dir, 0o700); err != nil {
				return err
			}
		}
		if !f.noSocket {
			if err := unix.Mknod(filepath.Join(root, vsockPath), unix.S_IFSOCK|0o770, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *fakeSystemd) Stop(unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops = append(f.stops, unit)
	delete(f.active, unit)
	return nil
}

func (f *fakeSystemd) Active(unit string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active[unit], nil
}

func (f *fakeSystemd) OOMKills(unit string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.oom[unit], nil
}

type fixture struct {
	t      *testing.T
	root   string
	builds string
	jail   string
	cfg    Config
	sd     *fakeSystemd
	h      *Helper
	chowns []chownCall
	acls   []aclCall
	// fstatEdit, when set, changes what the helper reads about an open file, by the file's path. A test uses it for an
	// owner or a device that an unprivileged test account cannot make.
	fstatEdit func(path string, st *unix.Stat_t)
	// trustRoot replaces the directory the jail base's ancestry check starts below.
	trustRoot string
	// trustedUIDDelta is added to the user that root-owned files must belong to.
	trustedUIDDelta int
}

// pathOf is the path an open descriptor names.
func pathOf(fd int) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return path
}

func shaOf(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeFile(t *testing.T, path string, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{t: t, root: root, builds: filepath.Join(root, "builds"), jail: filepath.Join(root, "jail")}
	for _, dir := range []string{f.builds, f.jail, filepath.Join(root, "state"), filepath.Join(root, "libexec")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	jailer := filepath.Join(root, "libexec", "jailer")
	firecracker := filepath.Join(root, "libexec", "firecracker")
	writeFile(t, jailer, "the jailer", 0o755)
	writeFile(t, firecracker, "firecracker", 0o755)
	f.cfg = Config{
		RunnerUID:          os.Getuid(),
		RunnerGID:          os.Getgid(),
		BuildsRoot:         f.builds,
		JailBase:           f.jail,
		StateDir:           filepath.Join(root, "state"),
		Socket:             filepath.Join(root, "state", "helper.sock"),
		UIDBase:            2_000_000,
		UIDCount:           4,
		Jailer:             Binary{Path: jailer, SHA256: shaOf(t, jailer)},
		Firecracker:        Binary{Path: firecracker, SHA256: shaOf(t, firecracker)},
		FirecrackerVersion: "1.16.2",
	}
	f.sd = &fakeSystemd{active: map[string]bool{}, oom: map[string]int{}}
	f.rebuild()
	return f
}

// rebuild makes the helper again from f.cfg, as after a restart.
func (f *fixture) rebuild() {
	f.t.Helper()
	trustRoot := f.root
	if f.trustRoot != "" {
		trustRoot = f.trustRoot
	}
	ops := Ops{
		TrustRoot:  trustRoot,
		TrustedUID: os.Getuid() + f.trustedUIDDelta,
		Fchown: func(fd, uid, gid int) error {
			f.chowns = append(f.chowns, chownCall{pathOf(fd), uid, gid})
			return nil
		},
		Fstat: func(fd int) (unix.Stat_t, error) {
			st, err := fstat(fd)
			if err == nil && f.fstatEdit != nil {
				f.fstatEdit(pathOf(fd), &st)
			}
			return st, err
		},
		SetACL: func(path string, runnerUID int, perm uint16, isDefault bool) error {
			f.acls = append(f.acls, aclCall{path, runnerUID, perm, isDefault})
			return nil
		},
		SetACLFD: func(fd int, runnerUID int, perm uint16) error {
			f.acls = append(f.acls, aclCall{pathOf(fd), runnerUID, perm, false})
			return nil
		},
	}
	h, err := NewHelper(f.cfg, f.sd, ops)
	if err != nil {
		f.t.Fatalf("NewHelper: %v", err)
	}
	f.h = h
}

// makeBuild writes the files the runner leaves in a build's directory.
func (f *fixture) makeBuild(id string) string {
	f.t.Helper()
	dir := filepath.Join(f.builds, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		f.t.Fatal(err)
	}
	writeFile(f.t, filepath.Join(dir, "kernel"), "kernel", 0o444)
	writeFile(f.t, filepath.Join(dir, "rootfs.ext4"), "rootfs", 0o444)
	writeFile(f.t, filepath.Join(dir, "build.ext4"), "build disk", 0o600)
	vm := fmt.Sprintf(`{"boot-source":{"kernel_image_path":"/etc/shadow","boot_args":"console=ttyS0 pci=off"},"drives":[{"drive_id":"rootfs","path_on_host":"/etc/passwd","is_root_device":true,"is_read_only":true}],"machine-config":{"vcpu_count":2,"mem_size_mib":2048,"smt":false},"vsock":{"guest_cid":3,"uds_path":"%s/v.sock"}}`, dir)
	writeFile(f.t, filepath.Join(dir, "vm.json"), vm, 0o600)
	for _, name := range []string{"tunnel.sock", "gateway.sock", "claude.sock", "dest-0.sock"} {
		if err := unix.Mknod(filepath.Join(dir, name), unix.S_IFSOCK|0o666, 0); err != nil {
			f.t.Fatal(err)
		}
	}
	return dir
}

func (f *fixture) start(id string) Reply {
	return f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStart, Build: id, Kind: KindBuild})
}

func (f *fixture) chroot(id string) string {
	return filepath.Join(f.jail, "firecracker", id, "root")
}

func mustRefuse(t *testing.T, reply Reply, code string) {
	t.Helper()
	if reply.Status != "refused" {
		t.Fatalf("want a refusal, got %+v", reply)
	}
	if code != "" && reply.Code != code {
		t.Fatalf("want refusal code %q, got %q (%s)", code, reply.Code, reply.Reason)
	}
}

func mustOK(t *testing.T, reply Reply) {
	t.Helper()
	if reply.Status != "ok" {
		t.Fatalf("want ok, got %+v", reply)
	}
}

func readReply(t *testing.T, conn net.Conn) Reply {
	t.Helper()
	var reply Reply
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatalf("reading the reply: %v", err)
	}
	return reply
}

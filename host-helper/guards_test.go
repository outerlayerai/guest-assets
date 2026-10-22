// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Each test in this file makes exactly one thing wrong and asserts the refusal code and reason of the guard that
// checks it. A test that left a second fault in place would pass when its own guard was removed.

// editFile changes what the helper reads about one file in the build's directory.
func (f *fixture) editFile(name string, edit func(*unix.Stat_t)) {
	f.fstatEdit = func(path string, st *unix.Stat_t) {
		if filepath.Base(path) == name && filepath.Base(filepath.Dir(path)) == testBuild {
			edit(st)
		}
	}
}

func (f *fixture) editPath(want string, edit func(*unix.Stat_t)) {
	f.fstatEdit = func(path string, st *unix.Stat_t) {
		if path == want {
			edit(st)
		}
	}
}

func mustRefuseBecause(t *testing.T, reply Reply, code, reason string) {
	t.Helper()
	mustRefuse(t, reply, code)
	if !strings.Contains(reply.Reason, reason) {
		t.Fatalf("want a reason with %q, got %q", reason, reply.Reason)
	}
}

func TestOpenBeneathRefusesAPathThatLeavesItsDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "secret"), "x", 0o600)
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "sub", "inside"), "x", 0o600)
	dirfd, err := unix.Open(filepath.Join(root, "sub"), unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirfd)

	if fd, err := openBeneath(dirfd, "inside", unix.O_RDONLY); err != nil {
		t.Fatalf("a file inside was refused: %v", err)
	} else {
		unix.Close(fd)
	}
	if fd, err := openBeneath(dirfd, "../secret", unix.O_RDONLY); err != unix.EXDEV {
		t.Fatalf("a path with .. opened or failed differently: fd %d, err %v", fd, err)
	}
}

func TestOpenBeneathRefusesALinkWhereverItPoints(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "target"), "x", 0o600)
	if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	dirfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirfd)

	if fd, err := openBeneath(dirfd, "link", unix.O_RDONLY); err != unix.ELOOP {
		t.Fatalf("a link inside the directory opened or failed differently: fd %d, err %v", fd, err)
	}
}

func TestOpenBeneathRefusesAPathThatCrossesAMount(t *testing.T) {
	dirfd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirfd)
	var st, rootSt unix.Stat_t
	if unix.Stat("/proc", &st) != nil || unix.Stat("/", &rootSt) != nil || st.Dev == rootSt.Dev {
		t.Skip("/proc is not a separate mount here")
	}

	if fd, err := openBeneath(dirfd, "proc/version", unix.O_RDONLY); err != unix.EXDEV {
		t.Fatalf("a path into another mount opened or failed differently: fd %d, err %v", fd, err)
	}
}

func TestRefusesADiskThatIsALinkToAFileInsideTheBuild(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	if err := os.Remove(filepath.Join(dir, "build.ext4")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("vm.json", filepath.Join(dir, "build.ext4")); err != nil {
		t.Fatal(err)
	}
	reply := f.start(testBuild)
	f.refusedWithoutChanges(reply, CodeBadFile)
	mustRefuseBecause(t, reply, CodeBadFile, "symbolic link")
}

func TestRefusesABuildsRootThatAGroupOrOthersCanWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0o775, 0o757} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			f := newFixture(t)
			f.makeBuild(testBuild)
			if err := os.Chmod(f.builds, mode); err != nil {
				t.Fatal(err)
			}
			f.refusedWithoutChanges(f.start(testBuild), CodeOutsideBuilds)
		})
	}
}

func TestRefusesABuildDirectoryThatAGroupOrOthersCanWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0o720, 0o702} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			f := newFixture(t)
			dir := f.makeBuild(testBuild)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			reply := f.start(testBuild)
			f.refusedWithoutChanges(reply, CodeBadFile)
			mustRefuseBecause(t, reply, CodeBadFile, "others can write it")
		})
	}
}

func TestRefusesABuildDirectoryTheRunnerDoesNotOwn(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	f.editPath(dir, func(st *unix.Stat_t) { st.Uid++ })
	reply := f.start(testBuild)
	f.refusedWithoutChanges(reply, CodeBadFile)
	mustRefuseBecause(t, reply, CodeBadFile, "is not the runner's")
}

func TestRefusesAFileThatIsNotOwnedByTheRunner(t *testing.T) {
	for _, name := range []string{"kernel", "rootfs.ext4", "build.ext4", "vm.json"} {
		for _, uid := range []uint32{uint32(os.Getuid()) + 1, uint32(2_000_000 - 1), uint32(2_000_000 + 4)} {
			t.Run(fmt.Sprintf("%s owned by %d", name, uid), func(t *testing.T) {
				f := newFixture(t)
				f.makeBuild(testBuild)
				f.editFile(name, func(st *unix.Stat_t) { st.Uid = uid })
				reply := f.start(testBuild)
				f.refusedWithoutChanges(reply, CodeBadFile)
				mustRefuseBecause(t, reply, CodeBadFile, "not owned by the runner")
			})
		}
	}
}

func TestOnlyTheDiskMayBelongToABuildUser(t *testing.T) {
	for _, name := range []string{"kernel", "rootfs.ext4", "vm.json"} {
		t.Run(name+" owned by a build user", func(t *testing.T) {
			f := newFixture(t)
			f.makeBuild(testBuild)
			f.editFile(name, func(st *unix.Stat_t) { st.Uid = 2_000_000 })
			f.refusedWithoutChanges(f.start(testBuild), CodeBadFile)
		})
	}
	// The first and the last user of the range are build users, so a disk a stopped build left behind is taken back.
	for _, uid := range []uint32{2_000_000, 2_000_003} {
		t.Run(fmt.Sprintf("disk owned by build user %d", uid), func(t *testing.T) {
			f := newFixture(t)
			f.makeBuild(testBuild)
			f.editFile("build.ext4", func(st *unix.Stat_t) { st.Uid = uid })
			mustOK(t, f.start(testBuild))
		})
	}
}

func TestRefusesAFileOnAnotherFileSystemThanTheJail(t *testing.T) {
	for _, name := range []string{"kernel", "rootfs.ext4", "build.ext4", "vm.json"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.makeBuild(testBuild)
			f.editFile(name, func(st *unix.Stat_t) { st.Dev++ })
			reply := f.start(testBuild)
			f.refusedWithoutChanges(reply, CodeBadFile)
			mustRefuseBecause(t, reply, CodeBadFile, "same file system as the jail")
		})
	}
}

func TestRefusesAFileThatIsNotARegularFile(t *testing.T) {
	for _, name := range []string{"kernel", "rootfs.ext4", "build.ext4", "vm.json"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			dir := f.makeBuild(testBuild)
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
			reply := f.start(testBuild)
			f.refusedWithoutChanges(reply, CodeBadFile)
			mustRefuseBecause(t, reply, CodeBadFile, "not a regular file")
		})
	}
}

func TestRefusesAKernelOrRootFilesystemThatEveryUserCannotRead(t *testing.T) {
	for _, name := range []string{"kernel", "rootfs.ext4"} {
		for _, mode := range []os.FileMode{0o440, 0o404, 0o400} {
			t.Run(fmt.Sprintf("%s %o", name, mode), func(t *testing.T) {
				f := newFixture(t)
				dir := f.makeBuild(testBuild)
				if err := os.Chmod(filepath.Join(dir, name), mode); err != nil {
					t.Fatal(err)
				}
				reply := f.start(testBuild)
				f.refusedWithoutChanges(reply, CodeBadFile)
				mustRefuseBecause(t, reply, CodeBadFile, "must be readable by every user")
			})
		}
	}
}

func TestChecksTheLimitsOfTheMachineConfiguration(t *testing.T) {
	long := strings.Repeat("a", 2048)
	cases := []struct {
		name     string
		cpus     int
		mem      int
		args     string
		accepted bool
		reason   string
	}{
		{"one processor", 1, 512, "pci=off", true, ""},
		{"128 processors", 128, 512, "pci=off", true, ""},
		{"no processor", 0, 512, "pci=off", false, "processors"},
		{"129 processors", 129, 512, "pci=off", false, "processors"},
		{"negative processors", -1, 512, "pci=off", false, "processors"},
		{"1 MiB", 1, 1, "pci=off", true, ""},
		{"the largest memory", 1, 1 << 20, "pci=off", true, ""},
		{"no memory", 1, 0, "pci=off", false, "of memory"},
		{"too much memory", 1, 1<<20 + 1, "pci=off", false, "of memory"},
		{"boot arguments of 2048 bytes", 1, 512, long, true, ""},
		{"boot arguments of 2049 bytes", 1, 512, long + "a", false, "boot arguments"},
		{"a line break in the boot arguments", 1, 512, "console=ttyS0\nroot=/dev/vdb", false, "boot arguments"},
		{"a NUL in the boot arguments", 1, 512, "console=ttyS0\x00root=/dev/vdb", false, "boot arguments"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			dir := f.makeBuild(testBuild)
			args, err := json.Marshal(c.args)
			if err != nil {
				t.Fatal(err)
			}
			vm := fmt.Sprintf(`{"machine-config":{"vcpu_count":%d,"mem_size_mib":%d},"boot-source":{"boot_args":%s}}`, c.cpus, c.mem, args)
			writeFile(t, filepath.Join(dir, "vm.json"), vm, 0o600)
			reply := f.start(testBuild)
			if c.accepted {
				mustOK(t, reply)
				return
			}
			f.refusedWithoutChanges(reply, CodeBadFile)
			mustRefuseBecause(t, reply, CodeBadFile, c.reason)
		})
	}
}

func TestRefusesAJailerOrFirecrackerOwnedByAnotherUser(t *testing.T) {
	for _, name := range []string{"jailer", "firecracker"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.makeBuild(testBuild)
			f.fstatEdit = func(path string, st *unix.Stat_t) {
				if filepath.Base(path) == name {
					st.Uid++
				}
			}
			reply := f.start(testBuild)
			f.refusedWithoutChanges(reply, CodeHashMismatch)
			mustRefuseBecause(t, reply, CodeHashMismatch, "only the trusted user can write")
		})
	}
}

func TestRefusesAJailerOrFirecrackerThatIsALink(t *testing.T) {
	for _, which := range []string{"jailer", "firecracker"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t)
			f.makeBuild(testBuild)
			path := f.cfg.Jailer.Path
			if which == "firecracker" {
				path = f.cfg.Firecracker.Path
			}
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Fatal(err)
			}
			f.refusedWithoutChanges(f.start(testBuild), CodeHashMismatch)
		})
	}
}

func TestRefusesAJailBaseOutsideTheTrustRoot(t *testing.T) {
	t.Run("a sibling of the trust root", func(t *testing.T) {
		f := newFixture(t)
		f.makeBuild(testBuild)
		f.trustRoot = filepath.Join(f.root, "trust")
		if err := os.Mkdir(f.trustRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		f.rebuild()
		reply := f.start(testBuild)
		f.refusedWithoutChanges(reply, CodeBadFile)
		mustRefuseBecause(t, reply, CodeBadFile, "is not below")
	})
	t.Run("the directory above the trust root", func(t *testing.T) {
		f := newFixture(t)
		f.makeBuild(testBuild)
		f.trustRoot = f.jail
		f.cfg.JailBase = f.root
		f.rebuild()
		reply := f.start(testBuild)
		f.refusedWithoutChanges(reply, CodeBadFile)
		mustRefuseBecause(t, reply, CodeBadFile, "is not below")
	})
}

func TestRefusesAJailBaseThatIsNotADirectory(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	file := filepath.Join(f.root, "not-a-directory")
	writeFile(t, file, "x", 0o644)
	f.cfg.JailBase = file
	f.rebuild()
	reply := f.start(testBuild)
	f.refusedWithoutChanges(reply, CodeBadFile)
	mustRefuseBecause(t, reply, CodeBadFile, "only the trusted user can write")
}

func TestRefusesAJailBaseThatTheTrustedUserDoesNotOwn(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.trustedUIDDelta = 1
	f.rebuild()
	reply := f.start(testBuild)
	f.refusedWithoutChanges(reply, CodeBadFile)
	mustRefuseBecause(t, reply, CodeBadFile, "only the trusted user can write")
}

func TestRefusesASocketThatIsNotASocketOwnedByTheRunnerOnTheJailsFileSystem(t *testing.T) {
	t.Run("a regular file", func(t *testing.T) {
		f := newFixture(t)
		dir := f.makeBuild(testBuild)
		if err := os.Remove(filepath.Join(dir, "tunnel.sock")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "tunnel.sock"), "x", 0o600)
		reply := f.start(testBuild)
		f.refusedWithoutChanges(reply, CodeBadFile)
		mustRefuseBecause(t, reply, CodeBadFile, "is not a socket")
	})
	t.Run("another owner", func(t *testing.T) {
		f := newFixture(t)
		f.makeBuild(testBuild)
		f.editFile("gateway.sock", func(st *unix.Stat_t) { st.Uid++ })
		reply := f.start(testBuild)
		f.refusedWithoutChanges(reply, CodeBadFile)
		mustRefuseBecause(t, reply, CodeBadFile, "is not a socket")
	})
	t.Run("another file system", func(t *testing.T) {
		f := newFixture(t)
		f.makeBuild(testBuild)
		f.editFile("claude.sock", func(st *unix.Stat_t) { st.Dev++ })
		reply := f.start(testBuild)
		f.refusedWithoutChanges(reply, CodeBadFile)
		mustRefuseBecause(t, reply, CodeBadFile, "is not a socket")
	})
}

func TestStartChangesTheOwnerOfTheChrootTheRunDirectoryAndTheDiskOnly(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	mustOK(t, f.start(testBuild))
	uid := f.chowns[0].uid
	if uid < f.cfg.UIDBase || uid >= f.cfg.UIDBase+f.cfg.UIDCount {
		t.Fatalf("the build user %d is outside the range", uid)
	}
	want := []chownCall{
		{f.chroot(testBuild), uid, uid},
		{filepath.Join(f.chroot(testBuild), "run"), uid, uid},
		{filepath.Join(dir, "build.ext4"), uid, uid},
	}
	if len(f.chowns) != len(want) {
		t.Fatalf("owners changed: %v", f.chowns)
	}
	for i := range want {
		if f.chowns[i] != want[i] {
			t.Fatalf("change %d is %+v, want %+v", i, f.chowns[i], want[i])
		}
	}
}

func TestRefusesAnUnreadableRequestFromAnotherAccountAsNotTheRunner(t *testing.T) {
	f := newFixture(t)
	f.cfg.RunnerUID = os.Getuid() + 1
	f.rebuild()
	path := filepath.Join(f.root, "state", "other.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer conn.Close()
		f.h.ServeConn(conn)
	}()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("this is not JSON\n")); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, readReply(t, conn), CodeNotRunner)
}

func TestLoadConfigRefusesAFileThatIsALink(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	real := writeConfig(t, t.TempDir(), f.cfg, 0o644)
	link := filepath.Join(dir, "helper.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link, os.Getuid()); err == nil {
		t.Fatal("a config that is a link was accepted")
	}
}

func TestDiscardRefusesADiskThatIsALinkToAFileInsideTheBuild(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	if err := os.Remove(filepath.Join(dir, "build.ext4")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("vm.json", filepath.Join(dir, "build.ext4")); err != nil {
		t.Fatal(err)
	}

	mustRefuseBecause(t, f.discard(testBuild), CodeBadFile, "symbolic link")
	if len(f.e2fsckRuns) != 0 || len(f.chowns) != 0 {
		t.Fatal("the helper acted on a link")
	}
}

func TestDiscardRefusesABuildOutsideTheRunnersBuildsRoot(t *testing.T) {
	for _, mode := range []os.FileMode{0o775, 0o757} {
		f := newFixture(t)
		f.makeBuild(testBuild)
		if err := os.Chmod(f.builds, mode); err != nil {
			t.Fatal(err)
		}

		mustRefuseBecause(t, f.discard(testBuild), CodeOutsideBuilds, "others can write it")
		if len(f.e2fsckRuns) != 0 {
			t.Fatalf("e2fsck ran with a builds root of mode %o", mode)
		}
	}
}

func TestDiscardRefusesABuildDirectoryThatIsALink(t *testing.T) {
	f := newFixture(t)
	other := t.TempDir()
	writeFile(t, filepath.Join(other, "build.ext4"), "x", 0o600)
	if err := os.Symlink(other, filepath.Join(f.builds, testBuild)); err != nil {
		t.Fatal(err)
	}

	mustRefuse(t, f.discard(testBuild), CodeOutsideBuilds)
	if len(f.e2fsckRuns) != 0 {
		t.Fatal("e2fsck ran through a linked build directory")
	}
}

func TestDiscardRefusesADiskThatIsNotARegularFile(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.editFile("build.ext4", func(st *unix.Stat_t) { st.Mode = st.Mode&^unix.S_IFMT | unix.S_IFBLK })

	mustRefuseBecause(t, f.discard(testBuild), CodeBadFile, "not a regular file")
	if len(f.e2fsckRuns) != 0 {
		t.Fatal("e2fsck ran on a device")
	}
}

func TestDiscardRefusesADiskAnotherAccountOwns(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.editFile("build.ext4", func(st *unix.Stat_t) { st.Uid = uint32(f.cfg.RunnerUID + 7) })

	mustRefuseBecause(t, f.discard(testBuild), CodeBadFile, "not owned by the runner's account or a build user")
	if len(f.e2fsckRuns) != 0 || len(f.chowns) != 0 {
		t.Fatal("the helper acted on a file another account owns")
	}
}

func TestDiscardRefusesADiskWithMoreThanOneName(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.editFile("build.ext4", func(st *unix.Stat_t) { st.Nlink = 2 })

	mustRefuseBecause(t, f.discard(testBuild), CodeBadFile, "2 names")
	if len(f.e2fsckRuns) != 0 || len(f.chowns) != 0 {
		t.Fatal("the helper acted on a file with two names")
	}
}

func TestDiscardRefusesADiskOnAnotherFileSystemThanTheBuildDirectory(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.editFile("build.ext4", func(st *unix.Stat_t) { st.Dev++ })

	mustRefuseBecause(t, f.discard(testBuild), CodeBadFile, "same file system")
}

func TestDiscardRefusesABuildWithNoDisk(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	if err := os.Remove(filepath.Join(dir, "build.ext4")); err != nil {
		t.Fatal(err)
	}

	mustRefuseBecause(t, f.discard(testBuild), CodeBadFile, "does not exist")
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func (f *fixture) refusedWithoutChanges(reply Reply, code string) {
	f.t.Helper()
	mustRefuse(f.t, reply, code)
	if len(f.sd.runs) != 0 {
		f.t.Fatalf("a refused start ran systemd-run: %v", f.sd.runs)
	}
	if len(f.chowns) != 0 {
		f.t.Fatalf("a refused start changed the owner of a file: %v", f.chowns)
	}
}

func TestRefusesABuildIdThatIsNotATwelveDigitHexName(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	for _, id := range []string{"", "..", "../builds", "0123456789a", "0123456789abc", "0123456789AB", "0123456789a/", testBuild + "/../" + testBuild, "/etc"} {
		f.refusedWithoutChanges(f.start(id), CodeBadBuild)
	}
}

func TestRefusesABuildDirectoryThatLeavesTheBuildsRoot(t *testing.T) {
	f := newFixture(t)
	outside := filepath.Join(f.root, "outside")
	for _, name := range []string{"kernel", "rootfs.ext4", "build.ext4", "vm.json"} {
		writeFile(t, filepath.Join(outside, name), "x", 0o600)
	}
	if err := os.Symlink(outside, filepath.Join(f.builds, testBuild)); err != nil {
		t.Fatal(err)
	}
	f.refusedWithoutChanges(f.start(testBuild), "")
	if _, err := os.Lstat(f.chroot(testBuild)); err == nil {
		t.Fatal("a chroot was made for a build directory outside the builds root")
	}
}

func TestRefusesAStartWhenTheBuildsRootIsNotTheRunnersOwn(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.cfg.RunnerUID = os.Getuid() + 1
	f.rebuild()
	reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStart, Build: testBuild, Kind: KindBuild})
	f.refusedWithoutChanges(reply, CodeOutsideBuilds)
}

func TestRefusesADiskThatIsASymlinkToAFileOutsideTheBuild(t *testing.T) {
	for _, name := range []string{"build.ext4", "kernel", "rootfs.ext4", "vm.json"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			dir := f.makeBuild(testBuild)
			target := filepath.Join(f.root, "secret")
			writeFile(t, target, "do not hand over", 0o600)
			before, _ := os.Stat(target)
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			f.refusedWithoutChanges(f.start(testBuild), CodeBadFile)
			after, _ := os.Stat(target)
			if !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("the symlink's target changed")
			}
			if _, err := os.Lstat(f.chroot(testBuild)); err == nil {
				t.Fatal("a chroot was left behind")
			}
		})
	}
}

func TestRefusesADiskThatIsAnotherNameForAFileTheRunnerHolds(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	other := filepath.Join(f.root, "runner.env")
	writeFile(t, other, "KEY=secret", 0o600)
	if err := os.Remove(filepath.Join(dir, "build.ext4")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(other, filepath.Join(dir, "build.ext4")); err != nil {
		t.Fatal(err)
	}
	f.refusedWithoutChanges(f.start(testBuild), CodeBadFile)
}

func TestRefusesADiskThatIsNotARegularFile(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	if err := os.Remove(filepath.Join(dir, "build.ext4")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "build.ext4"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.refusedWithoutChanges(f.start(testBuild), CodeBadFile)
}

func TestRefusesToStartWhenTheJailerDoesNotMatchItsPin(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	if err := os.WriteFile(f.cfg.Jailer.Path, []byte("a jailer that was changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.refusedWithoutChanges(f.start(testBuild), CodeHashMismatch)
	if _, err := os.Lstat(f.chroot(testBuild)); err == nil {
		t.Fatal("a chroot was made for a jailer that failed its check")
	}
}

func TestRefusesToStartWhenFirecrackerDoesNotMatchItsPin(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	if err := os.WriteFile(f.cfg.Firecracker.Path, []byte("a firecracker that was changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.refusedWithoutChanges(f.start(testBuild), CodeHashMismatch)
}

func TestRefusesAJailerThatAGroupOrOtherCanWrite(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	if err := os.Chmod(f.cfg.Jailer.Path, 0o775); err != nil {
		t.Fatal(err)
	}
	f.refusedWithoutChanges(f.start(testBuild), CodeHashMismatch)
}

func TestRefusesAJailBaseBelowADirectoryOthersCanWrite(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	if err := os.Chmod(f.jail, 0o777); err != nil {
		t.Fatal(err)
	}
	f.refusedWithoutChanges(f.start(testBuild), "")
	if err := os.Chmod(f.jail, 0o755); err != nil {
		t.Fatal(err)
	}
	mustOK(t, f.start(testBuild))
}

func TestRefusesARequestFromAnotherAccount(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	for _, op := range []string{OpHello, OpStart, OpStop, OpState, OpList} {
		reply := f.h.Handle(f.cfg.RunnerUID+1, Request{V: ProtocolVersion, Op: op, Build: testBuild})
		mustRefuse(t, reply, CodeNotRunner)
	}
	f.refusedWithoutChanges(f.h.Handle(f.cfg.RunnerUID+1, Request{V: ProtocolVersion, Op: OpStart, Build: testBuild}), CodeNotRunner)
}

func TestRefusesAConnectionWhoseSocketCredentialsAreNotTheRunners(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.cfg.RunnerUID = os.Getuid() + 1
	f.rebuild()
	path := filepath.Join(f.root, "state", "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
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
	if _, err := conn.Write([]byte(`{"v":1,"op":"hello"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	reply := readReply(t, conn)
	mustRefuse(t, reply, CodeNotRunner)
	<-done
}

func TestAnswersARunnerOnTheSocket(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.root, "state", "peer.sock")
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
	if _, err := conn.Write([]byte(`{"v":1,"op":"hello"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	reply := readReply(t, conn)
	mustOK(t, reply)
	if reply.Protocol != ProtocolVersion || reply.Firecracker != "1.16.2" {
		t.Fatalf("hello answered %+v", reply)
	}
}

func TestRefusesARequestWithAnUnknownOperationOrAnOversizedBody(t *testing.T) {
	f := newFixture(t)
	mustRefuse(t, f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: "run"}), CodeBadRequest)
	mustRefuse(t, f.h.Handle(f.cfg.RunnerUID, Request{V: 99, Op: OpStart, Build: testBuild}), CodeBadRequest)
}

func TestRefusesABuildDirectoryThatIsALinkToAnotherBuildInsideTheBuildsRoot(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	if err := os.Symlink(testBuild, filepath.Join(f.builds, "0123456789cd")); err != nil {
		t.Fatal(err)
	}
	f.refusedWithoutChanges(f.start("0123456789cd"), CodeOutsideBuilds)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func (f *fixture) relink(id string) Reply {
	return f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpRelink, Build: id})
}

// remakeSocket makes the socket name again, as a runner that starts again does: same path, a new file.
func remakeSocket(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mknod(filepath.Join(dir, name), unix.S_IFSOCK|0o666, 0); err != nil {
		t.Fatal(err)
	}
}

func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	sa, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(sa, sb)
}

func TestRelinkPointsTheJailAtTheSocketsTheRunnerMadeAgain(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	mustOK(t, f.start(testBuild))
	run := filepath.Join(f.chroot(testBuild), "run")
	remakeSocket(t, dir, "lease.sock")
	remakeSocket(t, dir, "tunnel.sock")
	if sameFile(t, filepath.Join(dir, "lease.sock"), filepath.Join(run, "v.sock_3125")) {
		t.Fatal("the jail's link already names the new socket before the relink")
	}

	reply := f.relink(testBuild)

	mustOK(t, reply)
	if reply.Unit != UnitName(testBuild) {
		t.Fatalf("the reply names unit %q", reply.Unit)
	}
	for name, port := range map[string]string{"tunnel.sock": "3128", "gateway.sock": "3126", "claude.sock": "3127", "dest-0.sock": "3129", "lease.sock": "3125"} {
		if !sameFile(t, filepath.Join(dir, name), filepath.Join(run, "v.sock_"+port)) {
			t.Fatalf("v.sock_%s is not the runner's %s", port, name)
		}
	}
	entries, err := os.ReadDir(run)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".new" {
			t.Fatalf("the relink left %s in the jail", entry.Name())
		}
	}
}

func TestRelinkReplacesALinkAnEarlierRelinkLeftHalfMade(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	mustOK(t, f.start(testBuild))
	run := filepath.Join(f.chroot(testBuild), "run")
	writeFile(t, filepath.Join(run, "v.sock_3125.new"), "left over", 0o600)
	remakeSocket(t, dir, "lease.sock")

	mustOK(t, f.relink(testBuild))

	if !sameFile(t, filepath.Join(dir, "lease.sock"), filepath.Join(run, "v.sock_3125")) {
		t.Fatal("v.sock_3125 is not the runner's new lease.sock")
	}
	if _, err := os.Lstat(filepath.Join(run, "v.sock_3125.new")); !os.IsNotExist(err) {
		t.Fatalf("the half-made link is still there: %v", err)
	}
}

func TestRelinkIsRefusedForABuildThisHelperDidNotStart(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)

	mustRefuseBecause(t, f.relink(testBuild), CodeNotRunning, "not one this helper started")

	if _, err := os.Stat(f.chroot(testBuild)); !os.IsNotExist(err) {
		t.Fatalf("a refused relink made a jail: %v", err)
	}
}

func TestRelinkIsRefusedWhenTheBuildsUnitIsNotRunning(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	mustOK(t, f.start(testBuild))
	run := filepath.Join(f.chroot(testBuild), "run")
	remakeSocket(t, dir, "lease.sock")
	f.sd.active[UnitName(testBuild)] = false

	mustRefuseBecause(t, f.relink(testBuild), CodeNotRunning, "is not running")

	if sameFile(t, filepath.Join(dir, "lease.sock"), filepath.Join(run, "v.sock_3125")) {
		t.Fatal("a refused relink changed the jail's link")
	}
}

func TestRelinkIsRefusedForANameThatIsNotABuildID(t *testing.T) {
	f := newFixture(t)

	mustRefuse(t, f.relink("../etc"), CodeBadBuild)
}

// The relink checks each socket as a start does, so the runner cannot have a file it holds, such as its credentials,
// linked into a jail the build's user can read.
func TestRelinkRefusesASocketNameThatIsNotASocketAndLeavesTheJailAsItWas(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	mustOK(t, f.start(testBuild))
	run := filepath.Join(f.chroot(testBuild), "run")
	if err := os.Remove(filepath.Join(dir, "tunnel.sock")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "tunnel.sock"), "the runner's credentials", 0o600)
	remakeSocket(t, dir, "lease.sock")
	before, err := os.Stat(filepath.Join(run, "v.sock_3128"))
	if err != nil {
		t.Fatal(err)
	}

	mustRefuseBecause(t, f.relink(testBuild), CodeBadFile, "is not a socket")

	after, err := os.Stat(filepath.Join(run, "v.sock_3128"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || after.Mode()&os.ModeSocket == 0 {
		t.Fatal("a refused relink changed v.sock_3128")
	}
	if sameFile(t, filepath.Join(dir, "lease.sock"), filepath.Join(run, "v.sock_3125")) {
		t.Fatal("a refused relink changed v.sock_3125")
	}
}

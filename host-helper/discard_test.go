// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func (f *fixture) discard(id string) Reply {
	return f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpDiscard, Build: id})
}

// fillDisk makes the build's disk hold `size` bytes of written blocks, as a builder leaves its cache disk.
func fillDisk(t *testing.T, dir string, size int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "build.ext4"), make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "build.ext4"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscardRunsE2fsckOnAStoppedBuildsDiskAsTheRunnersAccountAndReportsTheBytesFreed(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	fillDisk(t, dir, 4<<20)
	f.e2fsck = func(fd, uid, gid int, limit time.Duration) (int, string, error) {
		// The real program turns a discard of a free block range into a hole punch.
		if err := unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, 0, 3<<20); err != nil {
			t.Skipf("this file system cannot punch holes: %v", err)
		}
		return 1, "", nil
	}

	reply := f.discard(testBuild)

	mustOK(t, reply)
	if reply.FreedBytes == nil || *reply.FreedBytes < 3<<20 {
		t.Fatalf("want at least 3 MiB reported freed, got %v", reply.FreedBytes)
	}
	if len(f.e2fsckRuns) != 1 {
		t.Fatalf("want one e2fsck, got %d", len(f.e2fsckRuns))
	}
	run := f.e2fsckRuns[0]
	if run.path != filepath.Join(dir, "build.ext4") || run.uid != f.cfg.RunnerUID || run.gid != f.cfg.RunnerGID {
		t.Fatalf("e2fsck ran on %q as %d:%d", run.path, run.uid, run.gid)
	}
}

func TestDiscardGivesADiskOwnedByABuildUserToTheRunnerBeforeE2fsckRuns(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.editFile("build.ext4", func(st *unix.Stat_t) { st.Uid = uint32(f.cfg.UIDBase) })

	mustOK(t, f.discard(testBuild))

	if len(f.chowns) != 1 || f.chowns[0].uid != f.cfg.RunnerUID || f.chowns[0].gid != f.cfg.RunnerGID || filepath.Base(f.chowns[0].path) != "build.ext4" {
		t.Fatalf("want the disk given to the runner's account, got %+v", f.chowns)
	}
}

func TestDiscardChangesNoOwnerOfADiskTheRunnerAlreadyOwns(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)

	mustOK(t, f.discard(testBuild))

	if len(f.chowns) != 0 {
		t.Fatalf("want no ownership change, got %+v", f.chowns)
	}
}

func TestDiscardRefusesWhenE2fsckFindsErrorsItCannotFix(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.e2fsck = func(int, int, int, time.Duration) (int, string, error) {
		return 8, "\ne2fsck: Operational error\n", nil
	}

	reply := f.discard(testBuild)

	mustRefuseBecause(t, reply, CodeInternal, "status 8")
	mustRefuseBecause(t, reply, CodeInternal, "Operational error")
}

func TestDiscardRefusesWhenE2fsckCannotRun(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.e2fsck = func(int, int, int, time.Duration) (int, string, error) {
		return -1, "", os.ErrNotExist
	}

	mustRefuseBecause(t, f.discard(testBuild), CodeInternal, "failed")
}

func TestDiscardRefusesABuildTheHelperHolds(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	mustOK(t, f.start(testBuild))

	reply := f.discard(testBuild)

	mustRefuseBecause(t, reply, CodeAlreadyRunning, "still running")
	if len(f.e2fsckRuns) != 0 {
		t.Fatal("e2fsck ran on the disk of a running build")
	}
}

func TestDiscardRefusesABuildWhoseUnitIsRunning(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.sd.active[UnitName(testBuild)] = true

	mustRefuseBecause(t, f.discard(testBuild), CodeAlreadyRunning, "running")
	if len(f.e2fsckRuns) != 0 {
		t.Fatal("e2fsck ran on the disk of a running unit")
	}
}

func TestAStartOfABuildWhoseDiskIsBeingCheckedIsRefused(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	var during Reply
	f.e2fsck = func(int, int, int, time.Duration) (int, string, error) {
		during = f.start(testBuild)
		return 0, "", nil
	}

	mustOK(t, f.discard(testBuild))

	mustRefuseBecause(t, during, CodeAlreadyRunning, "being checked")
	// The mark is gone once the check ends, so a start then is not refused for it.
	mustOK(t, f.start(testBuild))
}

func TestDiscardDoesNotHoldTheLockWhileE2fsckRuns(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	other := "abcdef012345"
	f.makeBuild(other)
	var listed Reply
	f.e2fsck = func(int, int, int, time.Duration) (int, string, error) {
		done := make(chan Reply)
		go func() { done <- f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpList}) }()
		select {
		case listed = <-done:
		case <-time.After(5 * time.Second):
			t.Error("a list waited for the e2fsck")
		}
		return 0, "", nil
	}

	mustOK(t, f.discard(testBuild))

	mustOK(t, listed)
}

func TestDiscardWithoutABuildIDIsRefused(t *testing.T) {
	f := newFixture(t)

	reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpDiscard, Build: "../../etc"})

	mustRefuseBecause(t, reply, CodeBadBuild, "not a build id")
}

func TestDiscardIsForTheRunnersAccountOnly(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)

	reply := f.h.Handle(f.cfg.RunnerUID+1, Request{V: ProtocolVersion, Op: OpDiscard, Build: testBuild})

	mustRefuse(t, reply, CodeNotRunner)
	if len(f.e2fsckRuns) != 0 {
		t.Fatal("another account's request ran e2fsck")
	}
}

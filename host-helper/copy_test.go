// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func (f *fixture) copyDisk(id string) Reply {
	return f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpCopy, Build: id})
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("want no file at %s, got %v", path, err)
	}
}

func TestCopyWritesTheDiskOfAStoppedBuildToTheFixedNameWithModeZeroSixHundred(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	fillDisk(t, dir, 1<<20)

	reply := f.copyDisk(testBuild)

	mustOK(t, reply)
	copyPath := filepath.Join(dir, "saved-state.ext4")
	want, _ := os.ReadFile(filepath.Join(dir, "build.ext4"))
	got, err := os.ReadFile(copyPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("want the copy to hold the disk's bytes, got err %v and %d bytes", err, len(got))
	}
	st, _ := os.Stat(copyPath)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("want mode 0600, got %v", st.Mode().Perm())
	}
	if reply.CopiedBytes == nil || *reply.CopiedBytes <= 0 {
		t.Fatalf("want the copy's allocated bytes, got %v", reply.CopiedBytes)
	}
	if len(f.chowns) != 1 || f.chowns[0].uid != f.cfg.RunnerUID || f.chowns[0].gid != f.cfg.RunnerGID || filepath.Base(f.chowns[0].path) != "saved-state.ext4" {
		t.Fatalf("want the copy given to the runner's account, got %+v", f.chowns)
	}
}

func TestCopyOfASparseDiskLeavesTheHolesUnallocatedWhenTheFileSystemHasNoReflinks(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	disk := filepath.Join(dir, "build.ext4")
	if err := os.Truncate(disk, 64<<20); err != nil {
		t.Fatal(err)
	}
	file, _ := os.OpenFile(disk, os.O_WRONLY, 0)
	_, _ = file.WriteAt([]byte("head"), 0)
	_, _ = file.WriteAt([]byte("tail"), 64<<20-4)
	file.Close()
	f.clone = func(int, int) error { return unix.EOPNOTSUPP }

	reply := f.copyDisk(testBuild)

	mustOK(t, reply)
	copyPath := filepath.Join(dir, "saved-state.ext4")
	var st unix.Stat_t
	if err := unix.Stat(copyPath, &st); err != nil {
		t.Fatal(err)
	}
	if st.Size != 64<<20 || st.Blocks*512 >= 8<<20 {
		t.Fatalf("want a 64 MiB file with few allocated blocks, got size %d and %d allocated bytes", st.Size, st.Blocks*512)
	}
	want, _ := os.ReadFile(disk)
	got, _ := os.ReadFile(copyPath)
	if !bytes.Equal(got, want) {
		t.Fatal("the sparse copy differs from the disk")
	}
}

func TestCopyOfARunningBuildAcceptsTheDiskTheHelperLinkedIntoTheJail(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	mustOK(t, f.start(testBuild))

	reply := f.copyDisk(testBuild)

	mustOK(t, reply)
	got, err := os.ReadFile(filepath.Join(dir, "saved-state.ext4"))
	if err != nil || string(got) != "build disk" {
		t.Fatalf("want the disk's bytes in the copy, got %q and %v", got, err)
	}
}

func TestCopyRefusesDiskNotJailLink(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	mustOK(t, f.start(testBuild))
	// A file the runner holds takes the disk's name after the start. The jail still links the old disk.
	disk := filepath.Join(dir, "build.ext4")
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	writeFile(t, disk, "another file the runner holds", 0o600)

	reply := f.copyDisk(testBuild)

	mustRefuseBecause(t, reply, CodeBadFile, "not the file the helper linked")
	mustNotExist(t, filepath.Join(dir, "saved-state.ext4"))
}

func TestCopyRefusesExistingCopy(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	existing := filepath.Join(dir, "saved-state.ext4")
	writeFile(t, existing, "a file that is already here", 0o600)

	reply := f.copyDisk(testBuild)

	mustRefuseBecause(t, reply, CodeBadFile, "already exists")
	got, _ := os.ReadFile(existing)
	if string(got) != "a file that is already here" {
		t.Fatalf("want the existing file unchanged, got %q", got)
	}
}

func TestCopyRefusesAnExistingCopyThatIsALinkAndLeavesItsTargetUnchanged(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	target := filepath.Join(f.root, "target")
	writeFile(t, target, "target", 0o600)
	if err := os.Symlink(target, filepath.Join(dir, "saved-state.ext4")); err != nil {
		t.Fatal(err)
	}

	mustRefuse(t, f.copyDisk(testBuild), CodeBadFile)

	got, _ := os.ReadFile(target)
	if string(got) != "target" {
		t.Fatalf("want the target unchanged, got %q", got)
	}
}

func TestCopyRefusesABuildWhoseUnitIsRunningButTheHelperDoesNotHold(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	f.sd.active[UnitName(testBuild)] = true

	mustRefuseBecause(t, f.copyDisk(testBuild), CodeAlreadyRunning, "does not hold")
	mustNotExist(t, filepath.Join(dir, "saved-state.ext4"))
}

func TestCopyRefusesAStoppedBuildsDiskWithMoreThanOneName(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	if err := os.Link(filepath.Join(dir, "build.ext4"), filepath.Join(f.root, "other-name")); err != nil {
		t.Fatal(err)
	}

	mustRefuseBecause(t, f.copyDisk(testBuild), CodeBadFile, "names")
	mustNotExist(t, filepath.Join(dir, "saved-state.ext4"))
}

func TestCopyRefusesADiskThatIsASymlink(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	other := filepath.Join(f.root, "elsewhere")
	writeFile(t, other, "secret", 0o600)
	_ = os.Remove(filepath.Join(dir, "build.ext4"))
	if err := os.Symlink(other, filepath.Join(dir, "build.ext4")); err != nil {
		t.Fatal(err)
	}

	mustRefuse(t, f.copyDisk(testBuild), CodeBadFile)
	mustNotExist(t, filepath.Join(dir, "saved-state.ext4"))
}

func TestACopyOfABuildMakesAStartOfThatBuildWaitUntilItEnds(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	var during Reply
	f.clone = func(int, int) error {
		during = f.start(testBuild)
		return unix.EOPNOTSUPP
	}

	mustOK(t, f.copyDisk(testBuild))

	mustRefuseBecause(t, during, CodeAlreadyRunning, "being checked")
}

func TestCopyIsForTheRunnersAccountOnly(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)

	reply := f.h.Handle(f.cfg.RunnerUID+1, Request{V: ProtocolVersion, Op: OpCopy, Build: testBuild})

	mustRefuse(t, reply, CodeNotRunner)
	mustNotExist(t, filepath.Join(dir, "saved-state.ext4"))
}

func TestCopyWithoutABuildIDIsRefused(t *testing.T) {
	f := newFixture(t)

	reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpCopy, Build: "../../etc"})

	mustRefuseBecause(t, reply, CodeBadBuild, "not a build id")
}

func TestCopyRefusesADiskOwnedByAnAccountThatIsNeitherTheRunnerNorABuildUser(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	f.editFile("build.ext4", func(st *unix.Stat_t) { st.Uid = uint32(f.cfg.RunnerUID + 7) })

	mustRefuseBecause(t, f.copyDisk(testBuild), CodeBadFile, "not owned by the runner's account or a build user")
	mustNotExist(t, filepath.Join(dir, "saved-state.ext4"))
}

func TestCopyAcceptsADiskOwnedByABuildUser(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	f.editFile("build.ext4", func(st *unix.Stat_t) { st.Uid = uint32(f.cfg.UIDBase) })

	mustOK(t, f.copyDisk(testBuild))

	if _, err := os.Stat(filepath.Join(dir, "saved-state.ext4")); err != nil {
		t.Fatalf("want a copy, got %v", err)
	}
}

func TestCopyRefusesABuildWhoseDiskADiscardIsChecking(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	f.h.discarding[testBuild] = true

	mustRefuseBecause(t, f.copyDisk(testBuild), CodeAlreadyRunning, "already in use")
	mustNotExist(t, filepath.Join(dir, "saved-state.ext4"))
}

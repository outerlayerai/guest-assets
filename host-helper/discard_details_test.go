// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// e2fsckScript installs a program in place of e2fsck for the test, and returns the account the real runE2fsck must
// drop to. Dropping to another account needs root, so the test skips without it.
func e2fsckScript(t *testing.T, body string) (uid, gid int) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("running a program as another account needs root")
	}
	dir, err := os.MkdirTemp("", "e2fsck-script")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "e2fsck")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	saved := e2fsckPaths
	e2fsckPaths = []string{filepath.Join(dir, "missing"), script}
	t.Cleanup(func() { e2fsckPaths = saved })
	return 23456, 23457
}

func openDisk(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open(filepath.Join(t.TempDir(), "disk"), unix.O_RDWR|unix.O_CREAT, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func TestRunE2fsckRunsTheProgramAsTheGivenAccountWithNoOtherGroupsAFixedPathAndTheDiskAsDescriptor3(t *testing.T) {
	uid, gid := e2fsckScript(t, `echo "uid=$(/usr/bin/id -u) gid=$(/usr/bin/id -g) groups=$(/usr/bin/id -G) path=$PATH lc=$LC_ALL args=$* fd3=$([ -e /dev/fd/3 ] && echo yes)" >&2; exit 1`)

	status, output, err := runE2fsck(openDisk(t), uid, gid, time.Minute)

	if err != nil || status != 1 {
		t.Fatalf("want status 1 and no error, got %d, %v", status, err)
	}
	want := "uid=23456 gid=23457 groups=23457 path=/usr/sbin:/usr/bin:/sbin:/bin lc=C args=-f -y -E discard /dev/fd/3 fd3=yes"
	if strings.TrimSpace(output) != want {
		t.Fatalf("want %q, got %q", want, strings.TrimSpace(output))
	}
}

func TestRunE2fsckReturnsTheExitStatusOfTheProgram(t *testing.T) {
	uid, gid := e2fsckScript(t, `exit 2`)

	status, _, err := runE2fsck(openDisk(t), uid, gid, time.Minute)

	if err != nil || status != 2 {
		t.Fatalf("want status 2 and no error, got %d, %v", status, err)
	}
}

func TestRunE2fsckStopsAProgramThatRunsPastItsLimitAndSaysSo(t *testing.T) {
	uid, gid := e2fsckScript(t, `exec /bin/sleep 30`)
	started := time.Now()

	status, _, err := runE2fsck(openDisk(t), uid, gid, 300*time.Millisecond)

	if err == nil || !strings.Contains(err.Error(), "ran past") || status != -1 {
		t.Fatalf("want status -1 and an error that names the limit, got %d, %v", status, err)
	}
	if time.Since(started) > 10*time.Second {
		t.Fatal("the program was not stopped at its limit")
	}
}

func TestRunE2fsckKeepsOnlyTheFirstOfAProgramsLongErrorOutput(t *testing.T) {
	uid, gid := e2fsckScript(t, `/usr/bin/head -c 20000 /dev/zero | /usr/bin/tr '\0' 'x' >&2; exit 4`)

	_, output, err := runE2fsck(openDisk(t), uid, gid, time.Minute)

	if err != nil || len(output) != maxE2fsckOutput {
		t.Fatalf("want %d bytes kept, got %d (%v)", maxE2fsckOutput, len(output), err)
	}
}

func TestRunE2fsckNamesTheFixedPathsWhenNoneHoldsTheProgram(t *testing.T) {
	saved := e2fsckPaths
	t.Cleanup(func() { e2fsckPaths = saved })
	e2fsckPaths = []string{filepath.Join(t.TempDir(), "none"), t.TempDir()}

	status, _, err := runE2fsck(0, 0, 0, time.Minute)

	if err == nil || !strings.Contains(err.Error(), "not installed") || status != -1 {
		t.Fatalf("want status -1 and not installed, got %d, %v", status, err)
	}
}

func TestCappedBufferKeepsTheFirstBytesAcrossWritesAndReportsEveryWriteAsTaken(t *testing.T) {
	var c cappedBuffer
	first := strings.Repeat("a", maxE2fsckOutput-96)
	second := strings.Repeat("b", 200)
	third := strings.Repeat("c", 10)

	for _, p := range []string{first, second, third} {
		if n, err := c.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("want the whole write reported taken, got %d, %v", n, err)
		}
	}

	want := first + strings.Repeat("b", 96)
	if c.buf.String() != want {
		t.Fatalf("want %d bytes ending in 96 b, got %d bytes", len(want), c.buf.Len())
	}
}

func TestADiscardWhoseDiskIsAlreadyBeingCheckedIsRefused(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	var second Reply
	runs := 0
	f.e2fsck = func(int, int, int, time.Duration) (int, string, error) {
		runs++
		if runs == 1 {
			second = f.discard(testBuild)
		}
		return 0, "", nil
	}

	mustOK(t, f.discard(testBuild))

	mustRefuseBecause(t, second, CodeAlreadyRunning, "already being checked")
	if runs != 1 {
		t.Fatalf("want one e2fsck, got %d", runs)
	}
}

func TestADiscardGivesTheDiskToTheRunnersUserAndGroupInThatOrder(t *testing.T) {
	f := newFixture(t)
	f.cfg.RunnerGID = f.cfg.RunnerUID + 7
	f.rebuild()
	f.makeBuild(testBuild)
	f.editFile("build.ext4", func(st *unix.Stat_t) { st.Uid = uint32(f.cfg.UIDBase) })

	mustOK(t, f.discard(testBuild))

	if len(f.chowns) != 1 || f.chowns[0].uid != f.cfg.RunnerUID || f.chowns[0].gid != f.cfg.RunnerGID {
		t.Fatalf("want the disk given to %d:%d, got %+v", f.cfg.RunnerUID, f.cfg.RunnerGID, f.chowns)
	}
}

func TestADiscardGivesTheDiskToTheRunnersGroupWhenOnlyTheGroupDiffers(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.editFile("build.ext4", func(st *unix.Stat_t) { st.Gid = uint32(f.cfg.RunnerGID + 5) })

	mustOK(t, f.discard(testBuild))

	if len(f.chowns) != 1 {
		t.Fatalf("want one ownership change for a disk of another group, got %+v", f.chowns)
	}
}

func TestADiscardAcceptsExitStatus0And1OnlyAndRefusesStatus2(t *testing.T) {
	for status, accepted := range map[int]bool{0: true, 1: true, 2: false, 4: false} {
		f := newFixture(t)
		f.makeBuild(testBuild)
		f.e2fsck = func(int, int, int, time.Duration) (int, string, error) { return status, "output", nil }

		reply := f.discard(testBuild)

		if accepted {
			mustOK(t, reply)
		} else {
			mustRefuseBecause(t, reply, CodeInternal, "exited with status")
		}
	}
}

func TestADiscardReportsTheBlocksFreedIn512ByteUnitsExactly(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	fillDisk(t, dir, 4<<20)
	var want int64
	f.e2fsck = func(fd, uid, gid int, limit time.Duration) (int, string, error) {
		before, _ := fstat(fd)
		if err := unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, 0, 2<<20); err != nil {
			t.Skipf("this file system cannot punch holes: %v", err)
		}
		after, _ := fstat(fd)
		want = (before.Blocks - after.Blocks) * 512
		return 1, "", nil
	}

	reply := f.discard(testBuild)

	mustOK(t, reply)
	if want < 2<<20 || reply.FreedBytes == nil || *reply.FreedBytes != want {
		t.Fatalf("want exactly %d bytes freed, got %v", want, reply.FreedBytes)
	}
}

func TestADiscardAfterWhichTheDiskHoldsMoreBlocksReportsNothingFreed(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.e2fsck = func(fd, uid, gid int, limit time.Duration) (int, string, error) {
		if err := unix.Fallocate(fd, 0, 0, 4<<20); err != nil {
			t.Skipf("this file system cannot allocate: %v", err)
		}
		return 1, "", nil
	}

	reply := f.discard(testBuild)

	mustOK(t, reply)
	if reply.FreedBytes == nil || *reply.FreedBytes != 0 {
		t.Fatalf("want 0 bytes freed, got %v", reply.FreedBytes)
	}
}

func TestADiscardGivesE2fsckTenMinutes(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	var limit time.Duration
	f.e2fsck = func(_, _, _ int, l time.Duration) (int, string, error) {
		limit = l
		return 0, "", nil
	}

	mustOK(t, f.discard(testBuild))

	if limit != 10*time.Minute {
		t.Fatalf("want 10 minutes, got %s", limit)
	}
}

func TestAHelperMadeWithoutAnE2fsckRunnerUsesTheRealOne(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	saved := e2fsckPaths
	t.Cleanup(func() { e2fsckPaths = saved })
	e2fsckPaths = []string{filepath.Join(t.TempDir(), "none")}
	h, err := NewHelper(f.cfg, f.sd, Ops{TrustRoot: f.root, TrustedUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}

	reply := h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpDiscard, Build: testBuild})

	mustRefuseBecause(t, reply, CodeInternal, "not installed")
}

func TestAConnectionOutlastsADiscardThatTakesLongerThanTheUsualDeadline(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.e2fsck = func(int, int, int, time.Duration) (int, string, error) {
		time.Sleep(1500 * time.Millisecond)
		return 0, "", nil
	}
	socket := filepath.Join(t.TempDir(), "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.AcceptUnix()
		if err == nil {
			f.h.ServeConn(conn)
			conn.Close()
		}
	}()
	client, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := client.Write([]byte(`{"v":` + strconv.Itoa(ProtocolVersion) + `,"op":"discard","build":"` + testBuild + `"}` + "\n")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4096)
	n, err := client.Read(buf)

	if err != nil || !strings.Contains(string(buf[:n]), `"status":"ok"`) {
		t.Fatalf("want an ok reply, got %q, %v", buf[:n], err)
	}
}

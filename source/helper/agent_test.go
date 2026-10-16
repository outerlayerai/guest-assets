// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type result struct {
	stdout, stderr []byte
	exit           int32
	gotExit        bool
	frames         int
}

func startAgent(t *testing.T, allow func(net.Conn) bool) (dial func() net.Conn) {
	t.Helper()
	// Unix socket paths are length-limited, so keep the name short.
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	a := newAgent()
	a.PeerAllowed = allow
	go a.Serve(l)
	t.Cleanup(func() { l.Close() })
	return func() net.Conn {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
}

func allowAll(net.Conn) bool { return true }

// sendToRejecter writes a request to an agent that closes a peer it rejects without reading from it. The write can
// then fail with a broken pipe or a reset, which is the rejection the test expects, not a failure.
func sendToRejecter(t *testing.T, c net.Conn, argv []string) {
	t.Helper()
	b, _ := json.Marshal(Request{Argv: argv, Env: map[string]string{"PATH": "/usr/bin:/bin"}})
	if err := WriteFrame(c, TypeRequest, b); err != nil && !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatal(err)
	}
}

func sendRequest(t *testing.T, c net.Conn, argv []string, env map[string]string) {
	t.Helper()
	if env == nil {
		env = map[string]string{"PATH": "/usr/bin:/bin"}
	}
	b, _ := json.Marshal(Request{Argv: argv, Env: env})
	if err := WriteFrame(c, TypeRequest, b); err != nil {
		t.Fatal(err)
	}
}

func collect(t *testing.T, c net.Conn) result {
	t.Helper()
	var r result
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	for {
		f, err := ReadFrame(c)
		if err != nil {
			// A peer that closes with unread input resets the connection.
			if err != io.EOF && !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("read: %v (stdout=%q stderr=%q)", err, r.stdout, r.stderr)
			}
			return r
		}
		r.frames++
		switch f.Type {
		case TypeStdout:
			r.stdout = append(r.stdout, f.Payload...)
		case TypeStderr:
			r.stderr = append(r.stderr, f.Payload...)
		case TypeExit:
			code, err := DecodeExit(f.Payload)
			if err != nil {
				t.Fatal(err)
			}
			r.exit, r.gotExit = code, true
		default:
			t.Fatalf("unexpected frame type %d", f.Type)
		}
	}
}

func TestAgentOutputAndExitStatus(t *testing.T) {
	c := startAgent(t, allowAll)()
	sendRequest(t, c, []string{"/bin/sh", "-c", "echo out; echo err >&2; exit 3"}, nil)
	r := collect(t, c)
	if string(r.stdout) != "out\n" || string(r.stderr) != "err\n" || !r.gotExit || r.exit != 3 {
		t.Fatalf("got stdout=%q stderr=%q exit=%d/%v", r.stdout, r.stderr, r.exit, r.gotExit)
	}
}

func TestAgentStdinEcho(t *testing.T) {
	c := startAgent(t, allowAll)()
	sendRequest(t, c, []string{"cat"}, nil)
	WriteFrame(c, TypeStdin, []byte("hello "))
	WriteFrame(c, TypeStdin, []byte("world"))
	WriteFrame(c, TypeStdin, nil)
	r := collect(t, c)
	if string(r.stdout) != "hello world" || r.exit != 0 || !r.gotExit {
		t.Fatalf("got stdout=%q exit=%d", r.stdout, r.exit)
	}
}

func TestAgentKillFrame(t *testing.T) {
	c := startAgent(t, allowAll)()
	sendRequest(t, c, []string{"sleep", "60"}, nil)
	time.Sleep(200 * time.Millisecond)
	WriteFrame(c, TypeKill, nil)
	r := collect(t, c)
	if !r.gotExit || r.exit != 137 {
		t.Fatalf("got exit=%d/%v, want 137", r.exit, r.gotExit)
	}
}

func TestAgentKillsWholeProcessGroup(t *testing.T) {
	c := startAgent(t, allowAll)()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	sendRequest(t, c, []string{"/bin/sh", "-c", "sleep 60 & echo $! > " + pidFile + "; wait"}, nil)
	pid := waitForPid(t, pidFile)
	WriteFrame(c, TypeKill, nil)
	r := collect(t, c)
	if r.exit != 137 {
		t.Fatalf("exit=%d, want 137", r.exit)
	}
	waitGone(t, pid)
}

func waitForPid(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				return n
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("pid file never appeared")
	return 0
}

func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
		// A killed child of a dead parent is reaped by init; a zombie still answers kill(0).
		if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err != nil || strings.Contains(string(b), ") Z ") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid %d still running", pid)
}

func TestAgentConnectionCloseKillsCommand(t *testing.T) {
	c := startAgent(t, allowAll)()
	pidFile := filepath.Join(t.TempDir(), "pid")
	sendRequest(t, c, []string{"/bin/sh", "-c", "echo $$ > " + pidFile + "; exec sleep 60"}, nil)
	pid := waitForPid(t, pidFile)
	c.Close()
	waitGone(t, pid)
}

func TestAgentUnknownCommand(t *testing.T) {
	c := startAgent(t, allowAll)()
	sendRequest(t, c, []string{"definitely-not-a-command"}, nil)
	r := collect(t, c)
	if !r.gotExit || r.exit != 127 || !strings.Contains(string(r.stderr), "definitely-not-a-command") {
		t.Fatalf("got exit=%d stderr=%q", r.exit, r.stderr)
	}
}

func TestAgentBadCwd(t *testing.T) {
	c := startAgent(t, allowAll)()
	b, _ := json.Marshal(Request{Argv: []string{"/bin/true"}, Cwd: "/no/such/dir", Env: map[string]string{}})
	WriteFrame(c, TypeRequest, b)
	r := collect(t, c)
	if r.exit != 127 || len(r.stderr) == 0 {
		t.Fatalf("got exit=%d stderr=%q", r.exit, r.stderr)
	}
}

func TestAgentEnvIsExactlyTheRequests(t *testing.T) {
	c := startAgent(t, allowAll)()
	t.Setenv("LEAK_ME", "1")
	sendRequest(t, c, []string{"/usr/bin/env"}, map[string]string{"A": "b"})
	r := collect(t, c)
	if string(r.stdout) != "A=b\n" || r.exit != 0 {
		t.Fatalf("env output %q exit=%d", r.stdout, r.exit)
	}
}

func TestAgentDefaultPathResolvesButIsNotExported(t *testing.T) {
	c := startAgent(t, allowAll)()
	sendRequest(t, c, []string{"env"}, map[string]string{"Z": "1"})
	r := collect(t, c)
	if string(r.stdout) != "Z=1\n" {
		t.Fatalf("env output %q", r.stdout)
	}
}

func TestAgentCwd(t *testing.T) {
	c := startAgent(t, allowAll)()
	dir := t.TempDir()
	b, _ := json.Marshal(Request{Argv: []string{"/bin/pwd"}, Cwd: dir, Env: map[string]string{}})
	WriteFrame(c, TypeRequest, b)
	r := collect(t, c)
	got, _ := filepath.EvalSymlinks(strings.TrimSpace(string(r.stdout)))
	want, _ := filepath.EvalSymlinks(dir)
	if got != want {
		t.Fatalf("pwd %q, want %q", got, want)
	}
}

func TestAgentLargeOutputIsChunked(t *testing.T) {
	c := startAgent(t, allowAll)()
	sendRequest(t, c, []string{"/bin/sh", "-c", "head -c 300000 /dev/zero"}, nil)
	var total int
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	for {
		f, err := ReadFrame(c)
		if err != nil {
			t.Fatal(err)
		}
		if f.Type == TypeStdout {
			if len(f.Payload) > MaxChunk {
				t.Fatalf("chunk of %d bytes", len(f.Payload))
			}
			total += len(f.Payload)
		}
		if f.Type == TypeExit {
			break
		}
	}
	if total != 300000 {
		t.Fatalf("got %d bytes", total)
	}
}

func TestAgentRejectedPeerGetsNoFrames(t *testing.T) {
	var asked atomic.Int32
	c := startAgent(t, func(net.Conn) bool { asked.Add(1); return false })()
	sendToRejecter(t, c, []string{"/bin/echo", "hi"})
	r := collect(t, c)
	if r.frames != 0 || asked.Load() != 1 {
		t.Fatalf("frames=%d asked=%d", r.frames, asked.Load())
	}
}

func TestAgentNilHookRejects(t *testing.T) {
	c := startAgent(t, nil)()
	sendToRejecter(t, c, []string{"/bin/echo", "hi"})
	if r := collect(t, c); r.frames != 0 {
		t.Fatalf("frames=%d", r.frames)
	}
}

func TestAgentFirstFrameMustBeRequest(t *testing.T) {
	c := startAgent(t, allowAll)()
	WriteFrame(c, TypeStdin, []byte("x"))
	if r := collect(t, c); r.frames != 0 {
		t.Fatalf("frames=%d", r.frames)
	}
}

func TestResolveUser(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "passwd")
	gr := filepath.Join(dir, "group")
	os.WriteFile(pw, []byte("root:x:0:0::/root:/bin/sh\ndev:x:1001:1002::/home/dev:/bin/sh\n"), 0o644)
	os.WriteFile(gr, []byte("dev:x:1002:\ndocker:x:998:dev,other\nwheel:x:10:other\n"), 0o644)
	a := &Agent{PasswdPath: pw, GroupPath: gr}

	cases := []struct {
		spec   string
		nilCr  bool
		uid    uint32
		gid    uint32
		groups []uint32
		fail   bool
	}{
		{spec: "", nilCr: true},
		{spec: "root", nilCr: true},
		{spec: "dev", uid: 1001, gid: 1002, groups: []uint32{1002, 998}},
		{spec: "1001", uid: 1001, gid: 1002, groups: []uint32{1002, 998}},
		{spec: "1001:5", uid: 1001, gid: 5, groups: []uint32{}},
		{spec: "dev:docker", uid: 1001, gid: 998, groups: []uint32{}},
		{spec: "4000", uid: 4000, gid: 4000, groups: []uint32{}},
		{spec: "ghost", fail: true},
		{spec: "dev:nogroup", fail: true},
	}
	for _, tc := range cases {
		cr, err := a.resolveUser(tc.spec)
		if tc.fail {
			if err == nil {
				t.Errorf("%q: want error", tc.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.spec, err)
			continue
		}
		if tc.nilCr {
			if cr != nil {
				t.Errorf("%q: want no credential", tc.spec)
			}
			continue
		}
		if cr.Uid != tc.uid || cr.Gid != tc.gid || len(cr.Groups) != len(tc.groups) {
			t.Errorf("%q: got %+v, want uid=%d gid=%d groups=%v", tc.spec, *cr, tc.uid, tc.gid, tc.groups)
			continue
		}
		for i := range tc.groups {
			if cr.Groups[i] != tc.groups[i] {
				t.Errorf("%q: groups %v, want %v", tc.spec, cr.Groups, tc.groups)
			}
		}
	}
}

func TestVMInitArgv(t *testing.T) {
	def := vmInitArgv(func(string) string { return "" })
	if len(def) != 3 || def[0] != "/opt/outerlayer/bin/node" || def[2] != "vm-init" {
		t.Fatalf("default argv %v", def)
	}
	over := vmInitArgv(func(k string) string {
		if k == "OUTERLAYER_GUEST_VM_INIT" {
			return "/bin/sh -c  true"
		}
		return ""
	})
	if strings.Join(over, "|") != "/bin/sh|-c|true" {
		t.Fatalf("override argv %v", over)
	}
}

func TestReapAllCollectsExitedChildren(t *testing.T) {
	pid, err := syscall.ForkExec("/bin/sh", []string{"sh", "-c", "exit 7"}, &syscall.ProcAttr{})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ws, ok := reapAll()[pid]; ok {
			if statusCode(ws) != 7 {
				t.Fatalf("status %d, want 7", statusCode(ws))
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("child never reaped")
}

func TestProxyHalfClose(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	upL, _ := net.Listen("tcp", "127.0.0.1:0")
	defer upL.Close()
	go func() {
		c, _ := l.Accept()
		u, _ := net.Dial("tcp", upL.Addr().String())
		proxy(c, u)
	}()
	go func() {
		s, _ := upL.Accept()
		b, _ := io.ReadAll(s) // returns only if the client's half-close crosses the proxy
		s.Write(bytes.ToUpper(b))
		s.Close()
	}()
	cl, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	cl.Write([]byte("ping"))
	cl.(*net.TCPConn).CloseWrite()
	cl.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(cl)
	if err != nil || string(got) != "PING" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// sendDetached sends a request that asks for detached mode with its files in dir. The request is built as JSON so the
// test states the wire key, not a Go field name.
func sendDetached(t *testing.T, c net.Conn, dir string, argv []string) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"argv": argv, "user": "", "cwd": "", "env": map[string]string{"PATH": "/usr/bin:/bin"}, "detach": dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(c, TypeRequest, b); err != nil {
		t.Fatal(err)
	}
}

// readOneExit reads frames until the exit frame, and fails when none comes soon or when the agent sends output on
// the connection: a detached command's output goes to command.log and never to the connection.
func readOneExit(t *testing.T, c net.Conn) int32 {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := ReadFrame(c)
	if err != nil {
		t.Fatalf("the agent sent no frame for a detached request: %v", err)
	}
	if f.Type != TypeExit {
		t.Fatalf("the first frame has type %d, want the exit frame", f.Type)
	}
	status, err := DecodeExit(f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func waitForFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			return string(b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
	return ""
}

// AC-1291-01
func TestDetachedCommandKeepsRunningWhenItsConnectionDrops(t *testing.T) {
	c := startAgent(t, allowAll)()
	dir := filepath.Join(t.TempDir(), "run")
	sendDetached(t, c, dir, []string{"sleep", "30"})
	if status := readOneExit(t, c); status != 0 {
		t.Fatalf("the exit frame of a started detached command has status %d, want 0", status)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(waitForFile(t, filepath.Join(dir, "command.pid"))))
	if err != nil {
		t.Fatal(err)
	}
	// The kill ends the command and the agent then writes exit-code. Waiting for it keeps that write from racing
	// the removal of the temporary directory.
	t.Cleanup(func() {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		waitForFile(t, filepath.Join(dir, "exit-code"))
	})
	c.Close()
	time.Sleep(500 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("the command ended when its connection dropped: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "exit-code")); err == nil {
		t.Fatal("exit-code exists for a command that is still running")
	}
}

// AC-1291-02
func TestDetachedCommandLogHoldsStandardOutputAndError(t *testing.T) {
	c := startAgent(t, allowAll)()
	dir := filepath.Join(t.TempDir(), "run")
	sendDetached(t, c, dir, []string{"/bin/sh", "-c", "echo out; echo err >&2"})
	readOneExit(t, c)
	waitForFile(t, filepath.Join(dir, "exit-code"))
	log := waitForFile(t, filepath.Join(dir, "command.log"))
	if !strings.Contains(log, "out\n") || !strings.Contains(log, "err\n") {
		t.Fatalf("command.log is %q, want both streams", log)
	}
}

// AC-1291-03
func TestDetachedCommandExitCodeHoldsItsStatus(t *testing.T) {
	c := startAgent(t, allowAll)()
	dir := filepath.Join(t.TempDir(), "run")
	sendDetached(t, c, dir, []string{"/bin/sh", "-c", "exit 7"})
	readOneExit(t, c)
	if got := waitForFile(t, filepath.Join(dir, "exit-code")); got != "7\n" {
		t.Fatalf("exit-code is %q, want %q", got, "7\n")
	}
}

// AC-1291-04
func TestDetachedCommandEndedByASignalRecords128PlusTheSignal(t *testing.T) {
	c := startAgent(t, allowAll)()
	dir := filepath.Join(t.TempDir(), "run")
	sendDetached(t, c, dir, []string{"/bin/sh", "-c", "kill -TERM $$"})
	readOneExit(t, c)
	if got := waitForFile(t, filepath.Join(dir, "exit-code")); got != "143\n" {
		t.Fatalf("exit-code is %q, want %q", got, "143\n")
	}
}

// AC-1291-05
func TestDetachedRequestForACommandThatDoesNotExistRecords127(t *testing.T) {
	c := startAgent(t, allowAll)()
	dir := filepath.Join(t.TempDir(), "run")
	sendDetached(t, c, dir, []string{"definitely-not-a-command"})
	if status := readOneExit(t, c); status != 0 {
		t.Fatalf("the exit frame has status %d, want 0: the command's own status is in exit-code", status)
	}
	if got := waitForFile(t, filepath.Join(dir, "exit-code")); got != "127\n" {
		t.Fatalf("exit-code is %q, want %q", got, "127\n")
	}
}

func TestDetachedRequestForAFileThatCannotRunRecords126(t *testing.T) {
	c := startAgent(t, allowAll)()
	base := t.TempDir()
	plain := filepath.Join(base, "plain")
	if err := os.WriteFile(plain, []byte("not a program"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "run")
	sendDetached(t, c, dir, []string{plain})
	readOneExit(t, c)
	if got := waitForFile(t, filepath.Join(dir, "exit-code")); got != "126\n" {
		t.Fatalf("exit-code is %q, want %q", got, "126\n")
	}
}

func TestDetachedFilesAreWrittenWholeThroughARename(t *testing.T) {
	c := startAgent(t, allowAll)()
	dir := filepath.Join(t.TempDir(), "run")
	sendDetached(t, c, dir, []string{"/bin/sh", "-c", "exit 0"})
	readOneExit(t, c)
	waitForFile(t, filepath.Join(dir, "exit-code"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "command.log,command.pid,exit-code" {
		t.Fatalf("the detach directory holds %v, want command.log, command.pid and exit-code", names)
	}
}

// AC-1291-06
func TestCommandWithoutDetachedModeIsKilledWithItsProcessGroupWhenItsConnectionDrops(t *testing.T) {
	c := startAgent(t, allowAll)()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	sendRequest(t, c, []string{"/bin/sh", "-c", "sleep 60 & echo $! > " + pidFile + "; wait"}, nil)
	pid := waitForPid(t, pidFile)
	c.Close()
	waitGone(t, pid)
}

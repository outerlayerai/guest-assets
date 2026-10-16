// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The agent runs as root, and a detached command runs as the request's user in a directory that user owns. A link
// the user puts in that directory must not turn the agent's writes into writes to a file the user cannot write.
func TestDetachedCommandCannotRedirectTheAgentsExitCodeWriteThroughALink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the agent drops to another user only when it runs as root")
	}
	base := t.TempDir()
	// The test's temporary directories are root's alone; the command's user must reach the detach directory.
	for _, d := range []string{filepath.Dir(base), base} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	victim := filepath.Join(base, "root-only")
	if err := os.WriteFile(victim, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "run")
	c := startAgent(t, allowAll)()
	// The command runs as uid 65534 in the directory the agent created and gave to it.
	script := "ln -s " + victim + " " + filepath.Join(dir, "exit-code.partial") + "; exit 42"
	b, err := json.Marshal(map[string]any{"argv": []string{"/bin/sh", "-c", script}, "user": "65534", "cwd": "", "env": map[string]string{"PATH": "/usr/bin:/bin"}, "detach": dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(c, TypeRequest, b); err != nil {
		t.Fatal(err)
	}
	readOneExit(t, c)
	waitForFile(t, filepath.Join(dir, "exit-code"))
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret\n" {
		t.Fatalf("a root-only file outside the detach directory holds %q after the command linked exit-code.partial to it, want it unchanged", got)
	}
}

// A detach directory that already exists belongs to the request's user, who can leave a link named command.log in it.
// The agent opens command.log as root and hands the descriptor to the command.
func TestDetachedCommandLogIsNotOpenedThroughALinkInTheDetachDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the agent drops to another user only when it runs as root")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(base, "root-only")
	if err := os.WriteFile(victim, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "run")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "command.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(filepath.Join(dir, "command.log"), 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	c := startAgent(t, allowAll)()
	b, err := json.Marshal(map[string]any{"argv": []string{"/bin/sh", "-c", "echo appended"}, "user": "65534", "cwd": "", "env": map[string]string{"PATH": "/usr/bin:/bin"}, "detach": dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(c, TypeRequest, b); err != nil {
		t.Fatal(err)
	}
	readOneExit(t, c)
	waitForFile(t, filepath.Join(dir, "exit-code"))
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret\n" {
		t.Fatalf("a root-only file holds %q after a detached command of uid 65534 wrote to command.log, want it unchanged", got)
	}
}

// sendDetachedAs sends a detached request that runs as the given user.
func sendDetachedAs(t *testing.T, user, dir string, argv []string) {
	t.Helper()
	c := startAgent(t, allowAll)()
	b, err := json.Marshal(map[string]any{"argv": argv, "user": user, "cwd": "", "env": map[string]string{"PATH": "/usr/bin:/bin"}, "detach": dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(c, TypeRequest, b); err != nil {
		t.Fatal(err)
	}
	if status := readOneExit(t, c); status != 0 {
		t.Fatalf("the exit frame has status %d, want 0", status)
	}
}

// openTemp returns a directory the request's user can reach.
func openTemp(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	for _, d := range []string{filepath.Dir(base), base} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return base
}

// A link in a directory above the detach directory must not send the agent's writes elsewhere.
func TestDetachedRequestWhoseDirectoryPathHoldsALinkWritesNothingThroughIt(t *testing.T) {
	base := openTemp(t)
	target := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	c := startAgent(t, allowAll)()
	sendDetached(t, c, filepath.Join(base, "link", "run"), []string{"/bin/true"})
	f, err := ReadFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := DecodeExit(f.Payload); f.Type == TypeExit && status == 0 {
		t.Fatal("the agent started a command in a detach directory behind a link")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the agent wrote %d entries through a link on the directory path", len(entries))
	}
}

// A directory that already exists keeps its files, and command.log is appended to.
func TestDetachedRequestUsesAnExistingDirectoryAndAppendsToItsLog(t *testing.T) {
	dir := filepath.Join(openTemp(t), "run")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "command.log"), []byte("earlier\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sendDetachedAs(t, "", dir, []string{"/bin/echo", "later"})
	waitForFile(t, filepath.Join(dir, "exit-code"))
	if got := waitForFile(t, filepath.Join(dir, "command.log")); got != "earlier\nlater\n" {
		t.Fatalf("command.log is %q, want the earlier line and then the new one", got)
	}
}

func TestDetachedRequestWithARelativeDirectoryFailsToStart(t *testing.T) {
	c := startAgent(t, allowAll)()
	sendDetached(t, c, "relative/run", []string{"/bin/true"})
	f, err := ReadFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeStderr || !strings.Contains(string(f.Payload), "not an absolute path") {
		t.Fatalf("the first frame is type %d %q, want the stderr frame that names the relative path", f.Type, f.Payload)
	}
	if _, err := os.Stat("relative"); err == nil {
		os.RemoveAll("relative")
		t.Fatal("the agent created a directory from a relative path")
	}
}

func TestDetachedRequestForAMissingProgramNamedByAnAbsolutePathRecords127(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	sendDetachedAs(t, "", dir, []string{filepath.Join(t.TempDir(), "no-such-program")})
	if got := waitForFile(t, filepath.Join(dir, "exit-code")); got != "127\n" {
		t.Fatalf("exit-code is %q, want %q", got, "127\n")
	}
}

func TestDetachedCommandLogIsReadableByOtherUsers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	sendDetachedAs(t, "", dir, []string{"/bin/echo", "x"})
	waitForFile(t, filepath.Join(dir, "exit-code"))
	st, err := os.Stat(filepath.Join(dir, "command.log"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("command.log has mode %v, want -rw-r--r--: the runner reads it as another user", st.Mode().Perm())
	}
}

// The command runs in a session of its own, so its session id is its process id.
func TestDetachedCommandRunsInASessionOfItsOwn(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	sendDetachedAs(t, "", dir, []string{"/bin/sh", "-c", "sleep 30"})
	pid, err := strconv.Atoi(strings.TrimSpace(waitForFile(t, filepath.Join(dir, "command.pid"))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		waitForFile(t, filepath.Join(dir, "exit-code"))
	})
	sid, err := unix.Getsid(pid)
	if err != nil {
		t.Fatal(err)
	}
	if sid != pid {
		t.Fatalf("the command has session %d, want its own pid %d", sid, pid)
	}
}

// A detach directory the agent creates belongs to the request's user, so the command can write beside its log.
func TestDetachedDirectoryCreatedForAUserBelongsToThatUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the agent drops to another user only when it runs as root")
	}
	dir := filepath.Join(openTemp(t), "run")
	sendDetachedAs(t, "65534", dir, []string{"/bin/true"})
	waitForFile(t, filepath.Join(dir, "exit-code"))
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if owner := st.Sys().(*syscall.Stat_t).Uid; owner != 65534 {
		t.Fatalf("the detach directory belongs to uid %d, want 65534", owner)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The files of a detached command, in the directory its request names. The
// names and rules are those of `outerlayer build-command`, so the runner reads
// a microVM build and a container build in one way.
const (
	detachLogFile  = "command.log"
	detachPidFile  = "command.pid"
	detachExitFile = "exit-code"
)

// Exit statuses a shell reports for a command it cannot find, and for one it
// finds and cannot run.
const (
	statusNotFound    = 127
	statusNotRunnable = 126
)

// handleDetached starts the request's command so that it outlives the
// connection. The agent appends the command's output to command.log, writes
// its process id to command.pid and its exit status to exit-code, and answers
// with one exit frame of status 0 once the command has started or has failed
// to start. The command's own status is only in exit-code.
func (a *Agent) handleDetached(c interface{ Close() error }, w *connWriter, req *Request) {
	if !filepath.IsAbs(req.Detach) {
		failStart(w, fmt.Errorf("the detach directory %q is not an absolute path", req.Detach))
		return
	}
	cmd, buildErr := a.buildCommand(req, true)
	dir, err := a.openDetachDir(req)
	if err != nil {
		failStart(w, err)
		return
	}
	defer dir.Close()
	logFile, err := openLog(dir)
	if err != nil {
		failStart(w, err)
		return
	}
	defer logFile.Close()
	status, startErr := 0, buildErr
	if startErr == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, logFile, logFile
		startErr = cmd.Start()
	}
	if startErr != nil {
		fmt.Fprintf(logFile, "%v\n", startErr)
		status = statusNotRunnable
		if errors.Is(startErr, errCommandNotFound) || errors.Is(startErr, os.ErrNotExist) {
			status = statusNotFound
		}
		if err := writeWhole(dir, detachExitFile, strconv.Itoa(status)+"\n"); err != nil {
			failStart(w, err)
			return
		}
		_ = w.send(TypeExit, EncodeExit(0))
		c.Close()
		return
	}
	if err := writeWhole(dir, detachPidFile, strconv.Itoa(cmd.Process.Pid)+"\n"); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		failStart(w, err)
		return
	}
	_ = w.send(TypeExit, EncodeExit(0))
	// Closing the connection does not affect the command.
	c.Close()
	_ = cmd.Wait()
	// A volume the command filled cannot hold the file; the runner then reads an exit it never saw.
	_ = writeWhole(dir, detachExitFile, strconv.Itoa(int(exitStatus(cmd.ProcessState)))+"\n")
}

// openDetachDir returns the detach directory, created and owned by the
// request's user when it is missing.
//
// The agent runs as root and the request's user owns the directory, so the
// user can plant links in it, and in the directories above it. The agent walks
// the path one component at a time from "/" and opens each component without
// following a link. A link anywhere on the path is an error. Every later
// operation names a file relative to the returned directory, so no path is
// resolved a second time.
func (a *Agent) openDetachDir(req *Request) (*os.File, error) {
	cred, err := a.resolveUser(req.User)
	if err != nil {
		return nil, err
	}
	const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.Trim(filepath.Clean(req.Detach), "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, dirFlags, 0)
		created := false
		if errors.Is(err, unix.ENOENT) {
			if err = unix.Mkdirat(fd, part, 0o755); err == nil || errors.Is(err, unix.EEXIST) {
				created = err == nil
				next, err = unix.Openat(fd, part, dirFlags, 0)
			}
		}
		_ = unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("cannot use the detach directory %q: %w", req.Detach, err)
		}
		fd = next
		if created && i == len(parts)-1 && cred != nil {
			if err := unix.Fchown(fd, int(cred.Uid), int(cred.Gid)); err != nil {
				_ = unix.Close(fd)
				return nil, err
			}
		}
	}
	return os.NewFile(uintptr(fd), req.Detach), nil
}

// openLog opens command.log for appending. A link in its place is removed,
// not followed: the agent must not write through a link the user planted.
func openLog(dir *os.File) (*os.File, error) {
	// O_NONBLOCK keeps a planted pipe from blocking the open.
	const flags = unix.O_WRONLY | unix.O_APPEND | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	fd, err := unix.Openat(int(dir.Fd()), detachLogFile, flags, 0o644)
	if errors.Is(err, unix.ELOOP) {
		if err = unix.Unlinkat(int(dir.Fd()), detachLogFile, 0); err == nil {
			fd, err = unix.Openat(int(dir.Fd()), detachLogFile, flags|unix.O_EXCL, 0o644)
		}
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), detachLogFile)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", detachLogFile)
	}
	return f, nil
}

// writeWhole writes text under a temporary name and renames it, so a reader
// never sees half of the file. The temporary name is new and random, and it is
// created exclusively, so a link at a name the user guesses is never opened.
func writeWhole(dir *os.File, name, text string) error {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	partial := name + "." + hex.EncodeToString(suffix[:]) + ".partial"
	fd, err := unix.Openat(int(dir.Fd()), partial, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), partial)
	_, err = f.WriteString(text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(int(dir.Fd()), partial, int(dir.Fd()), name)
	}
	if err != nil {
		_ = unix.Unlinkat(int(dir.Fd()), partial, 0)
	}
	return err
}

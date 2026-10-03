// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const defaultPath = "/opt/outerlayer/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// drainTimeout bounds how long output pipes are read after the command and its
// process group are gone. A process that escaped the group can hold a pipe open.
const drainTimeout = 5 * time.Second

// Agent runs commands for the host over a stream listener.
type Agent struct {
	// PeerAllowed decides whether a connection may speak the protocol. A nil
	// hook rejects every peer.
	PeerAllowed func(net.Conn) bool
	PasswdPath  string
	GroupPath   string
}

func newAgent() *Agent {
	return &Agent{PasswdPath: "/etc/passwd", GroupPath: "/etc/group"}
}

func (a *Agent) peerAllowed(c net.Conn) bool {
	return a.PeerAllowed != nil && a.PeerAllowed(c)
}

// Serve accepts connections until the listener fails.
func (a *Agent) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go a.handle(c)
	}
}

// connWriter serializes frame writes from the output and exit paths.
type connWriter struct {
	mu sync.Mutex
	c  net.Conn
}

func (w *connWriter) send(typ byte, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return WriteFrame(w.c, typ, payload)
}

func (a *Agent) handle(c net.Conn) {
	defer c.Close()
	if !a.peerAllowed(c) {
		return
	}
	first, err := ReadFrame(c)
	if err != nil || first.Type != TypeRequest {
		return
	}
	var req Request
	if err := json.Unmarshal(first.Payload, &req); err != nil {
		return
	}
	w := &connWriter{c: c}
	cmd, err := a.buildCommand(&req)
	if err != nil {
		failStart(w, err)
		return
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		failStart(w, err)
		return
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		failStart(w, err)
		return
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		failStart(w, err)
		return
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdinR, outW, errW
	err = cmd.Start()
	stdinR.Close()
	outW.Close()
	errW.Close()
	if err != nil {
		stdinW.Close()
		outR.Close()
		errR.Close()
		failStart(w, err)
		return
	}
	pgid := cmd.Process.Pid

	stdin := newStdinWriter(stdinW)
	var killed sync.Once
	killGroup := func() {
		killed.Do(func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
	}
	go func() {
		for {
			f, err := ReadFrame(c)
			if err != nil {
				stdin.close()
				killGroup()
				return
			}
			switch f.Type {
			case TypeStdin:
				if len(f.Payload) == 0 {
					stdin.close()
				} else {
					stdin.push(f.Payload)
				}
			case TypeKill:
				killGroup()
			default:
				stdin.close()
				killGroup()
				return
			}
		}
	}()

	var pumps sync.WaitGroup
	pumps.Add(2)
	go pump(&pumps, outR, w, TypeStdout)
	go pump(&pumps, errR, w, TypeStderr)

	_ = cmd.Wait()
	// Anything the command left running in its group is cleaned up so its
	// output pipes close.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	drained := make(chan struct{})
	go func() { pumps.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(drainTimeout):
		outR.Close()
		errR.Close()
		<-drained
	}
	outR.Close()
	errR.Close()
	stdin.close()

	_ = w.send(TypeExit, EncodeExit(exitStatus(cmd.ProcessState)))
}

func failStart(w *connWriter, err error) {
	_ = w.send(TypeStderr, []byte(err.Error()+"\n"))
	_ = w.send(TypeExit, EncodeExit(127))
}

func exitStatus(ps *os.ProcessState) int32 {
	if ps == nil {
		return 127
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return int32(128 + int(ws.Signal()))
	}
	return int32(ps.ExitCode())
}

func pump(wg *sync.WaitGroup, r io.Reader, w *connWriter, typ byte) {
	defer wg.Done()
	buf := make([]byte, MaxChunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := w.send(typ, buf[:n]); werr != nil {
				// The host is gone; keep reading so the command never blocks on a full pipe.
				_, _ = io.Copy(io.Discard, r)
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// stdinWriter feeds the command's stdin from an unbounded queue so a command
// that does not read stdin cannot stall the frame reader.
type stdinWriter struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte
	closed bool
	f      *os.File
}

func newStdinWriter(f *os.File) *stdinWriter {
	s := &stdinWriter{f: f}
	s.cond = sync.NewCond(&s.mu)
	go s.run()
	return s
}

func (s *stdinWriter) push(b []byte) {
	s.mu.Lock()
	if !s.closed {
		s.queue = append(s.queue, b)
		s.cond.Signal()
	}
	s.mu.Unlock()
}

// close ends input once queued bytes are written.
func (s *stdinWriter) close() {
	s.mu.Lock()
	s.closed = true
	s.cond.Signal()
	s.mu.Unlock()
}

func (s *stdinWriter) run() {
	defer s.f.Close()
	broken := false
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && !s.closed {
			s.cond.Wait()
		}
		if len(s.queue) == 0 {
			s.mu.Unlock()
			return
		}
		b := s.queue[0]
		s.queue = s.queue[1:]
		s.mu.Unlock()
		if !broken {
			if _, err := s.f.Write(b); err != nil {
				broken = true
			}
		}
	}
}

func (a *Agent) buildCommand(req *Request) (*exec.Cmd, error) {
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		return nil, errors.New("empty command")
	}
	env := make([]string, 0, len(req.Env))
	searchPath, hasPath := req.Env["PATH"]
	for k, v := range req.Env {
		env = append(env, k+"="+v)
	}
	if !hasPath {
		searchPath = defaultPath
	}
	path, err := lookPath(req.Argv[0], searchPath)
	if err != nil {
		return nil, err
	}
	attr := &syscall.SysProcAttr{Setpgid: true}
	cred, err := a.resolveUser(req.User)
	if err != nil {
		return nil, err
	}
	attr.Credential = cred
	if req.Cwd != "" {
		if st, err := os.Stat(req.Cwd); err != nil || !st.IsDir() {
			return nil, fmt.Errorf("cannot use working directory %q", req.Cwd)
		}
	}
	return &exec.Cmd{Path: path, Args: req.Argv, Env: env, Dir: req.Cwd, SysProcAttr: attr}, nil
}

func lookPath(name, pathList string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range filepath.SplitList(pathList) {
		if dir == "" {
			dir = "."
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: command not found", name)
}

// resolveUser maps a user spec (name, uid, or uid:gid) to credentials. Empty
// or "root" means no privilege drop and returns nil.
func (a *Agent) resolveUser(spec string) (*syscall.Credential, error) {
	if spec == "" || spec == "root" {
		return nil, nil
	}
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	var uid, gid uint32
	var name string
	var havePasswd bool

	if n, err := strconv.ParseUint(userPart, 10, 32); err == nil {
		uid = uint32(n)
		if e, ok := a.passwdByUID(uid); ok {
			name, gid, havePasswd = e.name, e.gid, true
		}
	} else {
		e, ok := a.passwdByName(userPart)
		if !ok {
			return nil, fmt.Errorf("unknown user %q", userPart)
		}
		uid, gid, name, havePasswd = e.uid, e.gid, e.name, true
	}
	if !havePasswd && !hasGroup {
		gid = uid
	}
	if hasGroup {
		if n, err := strconv.ParseUint(groupPart, 10, 32); err == nil {
			gid = uint32(n)
		} else {
			g, ok := a.groupGID(groupPart)
			if !ok {
				return nil, fmt.Errorf("unknown group %q", groupPart)
			}
			gid = g
		}
	}
	groups := []uint32{}
	if havePasswd && !hasGroup {
		groups = a.supplementaryGroups(name, gid)
	}
	return &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}, nil
}

type passwdEntry struct {
	name     string
	uid, gid uint32
}

func readColonFile(path string, fn func(fields []string) bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if fn(strings.Split(line, ":")) {
			return
		}
	}
}

func (a *Agent) passwdLookup(match func(passwdEntry) bool) (passwdEntry, bool) {
	var found passwdEntry
	ok := false
	readColonFile(a.PasswdPath, func(f []string) bool {
		if len(f) < 4 {
			return false
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil {
			return false
		}
		e := passwdEntry{name: f[0], uid: uint32(uid), gid: uint32(gid)}
		if match(e) {
			found, ok = e, true
			return true
		}
		return false
	})
	return found, ok
}

func (a *Agent) passwdByName(name string) (passwdEntry, bool) {
	return a.passwdLookup(func(e passwdEntry) bool { return e.name == name })
}

func (a *Agent) passwdByUID(uid uint32) (passwdEntry, bool) {
	return a.passwdLookup(func(e passwdEntry) bool { return e.uid == uid })
}

func (a *Agent) groupGID(name string) (uint32, bool) {
	var gid uint32
	ok := false
	readColonFile(a.GroupPath, func(f []string) bool {
		if len(f) < 3 || f[0] != name {
			return false
		}
		n, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			return false
		}
		gid, ok = uint32(n), true
		return true
	})
	return gid, ok
}

// supplementaryGroups lists the primary group plus every group naming the user as a member.
func (a *Agent) supplementaryGroups(user string, primary uint32) []uint32 {
	groups := []uint32{primary}
	readColonFile(a.GroupPath, func(f []string) bool {
		if len(f) < 4 {
			return false
		}
		gid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil || uint32(gid) == primary {
			return false
		}
		for _, m := range strings.Split(f[3], ",") {
			if m == user {
				groups = append(groups, uint32(gid))
				break
			}
		}
		return false
	})
	return groups
}

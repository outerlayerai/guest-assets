// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

// Command outerlayer-host-helper starts each microVM build under Firecracker's
// jailer for the runner. It runs as root and does one job: start, stop, report
// and list builds, and give a running build's jail the runner's sockets again,
// for the runner's account only. A request names a build id
// and its kind and time limit; every path and user comes from the root-owned
// config or from the build's own files, which the helper checks first.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Ops holds the privileged system calls, so a test records them instead.
type Ops struct {
	// TrustRoot is the directory the ancestry check starts below. It is "/" in production.
	TrustRoot string
	// TrustedUID is the user root-owned files must belong to. It is 0 in production.
	TrustedUID int
	// Fchown changes the owner of an open file.
	Fchown func(fd, uid, gid int) error
	// SetACL gives the runner's account perm on path, as an access or default ACL.
	SetACL func(path string, runnerUID int, perm uint16, isDefault bool) error
	// SetACLFD gives the runner's account perm on an open directory, as its access ACL.
	SetACLFD func(fd int, runnerUID int, perm uint16) error
	// Fstat reads the owner, type, mode and device of an open file. A test uses it to give a file an owner or a
	// device the test account cannot create.
	Fstat func(fd int) (unix.Stat_t, error)
}

// record is what the helper keeps about a build it started. It is written under the state directory, which is
// memory-backed, so it is lost at reboot together with the units it names.
type record struct {
	Build  string `json:"build"`
	Kind   string `json:"kind"`
	UID    int    `json:"uid"`
	Unit   string `json:"unit"`
	Chroot string `json:"chroot"`
}

// Helper serves requests for one runner.
type Helper struct {
	Cfg Config
	sys Systemd
	ops Ops
	mu  sync.Mutex
	// records are the builds this helper holds, by build id.
	records map[string]*record
	// vsockWait is how long a start waits for Firecracker to make its vsock socket.
	vsockWait time.Duration
}

// defaultVsockWait bounds a start's wait for the socket. Firecracker makes it within a second of starting, and the
// runner gives a start 30 seconds.
const defaultVsockWait = 10 * time.Second

// NewHelper builds a helper from a config. Builds an earlier process of the helper started are read back from the
// state directory.
func NewHelper(cfg Config, sys Systemd, ops Ops) (*Helper, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if ops.TrustRoot == "" {
		ops.TrustRoot = "/"
	}
	if ops.Fchown == nil {
		ops.Fchown = unix.Fchown
	}
	if ops.SetACL == nil {
		ops.SetACL = setACL
	}
	if ops.SetACLFD == nil {
		ops.SetACLFD = setACLFD
	}
	if ops.Fstat == nil {
		ops.Fstat = fstat
	}
	h := &Helper{Cfg: cfg, sys: sys, ops: ops, records: map[string]*record{}, vsockWait: defaultVsockWait}
	if err := os.MkdirAll(h.recordsDir(), 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(h.recordsDir())
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(h.recordsDir(), entry.Name()))
		if err != nil {
			continue
		}
		var rec record
		if json.Unmarshal(data, &rec) == nil && buildIDPattern.MatchString(rec.Build) {
			h.records[rec.Build] = &rec
		}
	}
	return h, nil
}

func (h *Helper) recordsDir() string { return filepath.Join(h.Cfg.StateDir, "builds") }

func (h *Helper) recordPath(id string) string { return filepath.Join(h.recordsDir(), id+".json") }

func (h *Helper) saveRecord(rec *record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return os.WriteFile(h.recordPath(rec.Build), data, 0o600)
}

func refused(r *Refusal) Reply { return Reply{Status: "refused", Code: r.Code, Reason: r.Reason} }

// Handle answers one request from a caller with peerUID.
func (h *Helper) Handle(peerUID int, req Request) Reply {
	if peerUID != h.Cfg.RunnerUID {
		return refused(refuse(CodeNotRunner, "the request comes from user %d, not the runner's account", peerUID))
	}
	if req.Op == OpHello {
		return Reply{Status: "ok", Protocol: ProtocolVersion, Firecracker: h.Cfg.FirecrackerVersion}
	}
	if req.V != ProtocolVersion {
		return refused(refuse(CodeBadRequest, "the helper speaks protocol %d, not %d", ProtocolVersion, req.V))
	}
	switch req.Op {
	case OpList:
		return h.list()
	case OpStart, OpStop, OpState, OpRelink:
		if !buildIDPattern.MatchString(req.Build) {
			return refused(refuse(CodeBadBuild, "%q is not a build id: twelve lower-case hex digits", req.Build))
		}
	default:
		return refused(refuse(CodeBadRequest, "%q is not an operation", req.Op))
	}
	switch req.Op {
	case OpStart:
		return h.start(req.Build, req.Kind, req.TimeLimitMinutes)
	case OpStop:
		return h.stop(req.Build)
	case OpRelink:
		return h.relink(req.Build)
	default:
		return h.state(req.Build)
	}
}

// relink points a running build's jail at the runner's sockets as they are now. The jail holds hard links, which name
// the sockets the runner had when the build started. A runner that starts again makes its sockets anew, so those links
// name sockets no process listens on, and the runner cannot write the jail to replace them. The sockets pass the same
// checks as at start.
func (h *Helper) relink(id string) Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, held := h.records[id]
	if !held {
		return refused(refuse(CodeNotRunning, "build %s is not one this helper started", id))
	}
	active, err := h.sys.Active(rec.Unit)
	if err != nil {
		return refused(refuse(CodeSystemd, "%v", err))
	}
	if !active {
		return refused(refuse(CodeNotRunning, "the unit of build %s is not running", id))
	}
	jailDev, refusal := h.checkJailBase()
	if refusal != nil {
		return refused(refusal)
	}
	dirfd, refusal := h.openBuildDir(id)
	if refusal != nil {
		return refused(refusal)
	}
	defer unix.Close(dirfd)
	sockets, refusal := h.openSockets(id, dirfd, jailDev)
	if refusal != nil {
		return refused(refusal)
	}
	defer closeSockets(sockets)
	if err := relinkSockets(h.jailPathsFor(id), sockets); err != nil {
		return refused(refuse(CodeInternal, "the sockets of build %s could not be linked into its jail again: %v", id, err))
	}
	return Reply{Status: "ok", Unit: rec.Unit}
}

func (h *Helper) list() Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	builds := make([]string, 0, len(h.records))
	for id := range h.records {
		builds = append(builds, id)
	}
	sort.Strings(builds)
	return Reply{Status: "ok", Builds: builds}
}

func (h *Helper) state(id string) Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	unit := UnitName(id)
	active, err := h.sys.Active(unit)
	if err != nil {
		return refused(refuse(CodeSystemd, "%v", err))
	}
	kills, err := h.sys.OOMKills(unit)
	if err != nil {
		kills = 0
	}
	return Reply{Status: "ok", Unit: unit, Active: &active, OOMKills: &kills}
}

func (h *Helper) freeUID() (int, bool) {
	used := map[int]bool{}
	for _, rec := range h.records {
		used[rec.UID] = true
	}
	for uid := h.Cfg.UIDBase; uid < h.Cfg.UIDBase+h.Cfg.UIDCount; uid++ {
		if !used[uid] {
			return uid, true
		}
	}
	return 0, false
}

func (h *Helper) start(id, kind string, timeLimitMinutes int) Reply {
	if kind == "" {
		kind = KindBuild
	}
	if kind != KindBuild && kind != KindCheck {
		return refused(refuse(CodeBadRequest, "%q is not a kind of build", kind))
	}
	// 0 means the request names no limit. A value outside the runner's range is a bug in the caller, so it is refused.
	if timeLimitMinutes != 0 && (timeLimitMinutes < MinTimeLimitMinutes || timeLimitMinutes > MaxTimeLimitMinutes) {
		return refused(refuse(CodeBadRequest, "a time limit of %d minutes is not between %d and %d", timeLimitMinutes, MinTimeLimitMinutes, MaxTimeLimitMinutes))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, held := h.records[id]; held {
		return refused(refuse(CodeAlreadyRunning, "build %s is already running", id))
	}
	jailDev, refusal := h.checkJailBase()
	if refusal != nil {
		return refused(refusal)
	}
	// A jail an earlier helper left, with no unit to match, is removed first: its links would make the build's disk look
	// like a file with more than one name.
	if err := h.removeJail(id); err != nil {
		return refused(refuse(CodeInternal, "an old jail of build %s could not be removed: %v", id, err))
	}
	if refusal := h.hashTrusted(h.Cfg.Jailer, "jailer"); refusal != nil {
		return refused(refusal)
	}
	if refusal := h.hashTrusted(h.Cfg.Firecracker, "Firecracker"); refusal != nil {
		return refused(refusal)
	}
	files, refusal := h.openBuild(id, jailDev)
	if refusal != nil {
		return refused(refusal)
	}
	defer files.close()
	uid, ok := h.freeUID()
	if !ok {
		return refused(refuse(CodeNoUser, "all %d build users are in use", h.Cfg.UIDCount))
	}
	if err := h.makeJail(id, uid, files); err != nil {
		_ = h.removeJail(id)
		return refused(refuse(CodeInternal, "the jail of build %s could not be made: %v", id, err))
	}
	if err := h.sys.Run(startArgv(h.Cfg, id, uid, files.vm.MemoryMiB, timeLimitMinutes)); err != nil {
		_ = h.removeJail(id)
		return refused(refuse(CodeSystemd, "systemd could not start the unit: %v", err))
	}
	paths := h.jailPathsFor(id)
	if err := h.restoreRunnerAccess(paths); err != nil {
		_ = h.sys.Stop(UnitName(id))
		_ = h.removeJail(id)
		return refused(refuse(CodeInternal, "the runner could not be given its way to build %s's vsock socket: %v", id, err))
	}
	rec := &record{Build: id, Kind: kind, UID: uid, Unit: UnitName(id), Chroot: paths.chroot}
	if err := h.saveRecord(rec); err != nil {
		_ = h.sys.Stop(rec.Unit)
		_ = h.removeJail(id)
		return refused(refuse(CodeInternal, "the record of build %s could not be written: %v", id, err))
	}
	h.records[id] = rec
	return Reply{Status: "ok", Unit: rec.Unit, Chroot: rec.Chroot, Vsock: filepath.Join(paths.run, "v.sock")}
}

func (h *Helper) stop(id string) Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	unit := UnitName(id)
	if err := h.sys.Stop(unit); err != nil {
		return refused(refuse(CodeSystemd, "the unit %s could not be stopped: %v", unit, err))
	}
	if err := h.removeJail(id); err != nil {
		return refused(refuse(CodeInternal, "the jail of build %s could not be removed: %v", id, err))
	}
	_ = os.Remove(h.recordPath(id))
	delete(h.records, id)
	return Reply{Status: "ok", Unit: unit}
}

const (
	// maxRequest bounds what the helper reads from a caller before it decides whether to answer.
	maxRequest   = 4096
	connDeadline = 30 * time.Second
)

func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return int(cred.Uid), nil
}

// ServeConn reads one request from conn, checks who sent it and answers.
func (h *Helper) ServeConn(conn *net.UnixConn) {
	_ = conn.SetDeadline(time.Now().Add(connDeadline))
	peer, err := peerUID(conn)
	reply := Reply{}
	if err != nil {
		reply = refused(refuse(CodeNotRunner, "the caller's account could not be read: %v", err))
	} else {
		line, readErr := bufio.NewReaderSize(io.LimitReader(conn, maxRequest), maxRequest).ReadBytes('\n')
		var req Request
		switch {
		case peer != h.Cfg.RunnerUID:
			reply = h.Handle(peer, req)
		case readErr != nil && readErr != io.EOF:
			reply = refused(refuse(CodeBadRequest, "the request could not be read: %v", readErr))
		case json.Unmarshal(line, &req) != nil:
			reply = refused(refuse(CodeBadRequest, "the request is not one JSON object on a line"))
		default:
			reply = h.Handle(peer, req)
		}
	}
	data, _ := json.Marshal(reply)
	_, _ = conn.Write(append(data, '\n'))
}

func serve(configPath string) error {
	cfg, err := LoadConfig(configPath, 0)
	if err != nil {
		return err
	}
	sys, err := realSystemd()
	if err != nil {
		return err
	}
	h, err := NewHelper(cfg, sys, Ops{TrustRoot: "/", TrustedUID: 0})
	if err != nil {
		return err
	}
	_ = os.Remove(cfg.Socket)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	// Only the runner's account opens the socket. The peer check in ServeConn is a second guard.
	if err := os.Chown(cfg.Socket, cfg.RunnerUID, cfg.RunnerGID); err != nil {
		return err
	}
	if err := os.Chmod(cfg.Socket, 0o600); err != nil {
		return err
	}
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			h.ServeConn(conn)
		}()
	}
}

func main() {
	config := flag.String("config", "", "path to the root-owned helper config")
	flag.Parse()
	if *config == "" {
		fmt.Fprintln(os.Stderr, "usage: outerlayer-host-helper --config <path>")
		os.Exit(2)
	}
	if err := serve(*config); err != nil {
		fmt.Fprintln(os.Stderr, "outerlayer-host-helper:", err)
		os.Exit(1)
	}
}

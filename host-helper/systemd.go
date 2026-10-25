// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Systemd is everything the helper asks of systemd, so a test puts a recorder
// in its place.
type Systemd interface {
	// Run starts a transient unit with systemd-run and the given arguments.
	Run(argv []string) error
	// Stop stops the unit. A unit that is not loaded is not an error.
	Stop(unit string) error
	// Active reports whether the unit is running.
	Active(unit string) (bool, error)
	// OOMKills is the out-of-memory kill count of the unit's cgroup.
	OOMKills(unit string) (int, error)
}

const (
	// reclaimHeadroomBytes is added to the guest's memory where the kernel starts reclaiming the unit's page cache.
	reclaimHeadroomBytes = 256 * 1024 * 1024
	// killHeadroomBytes is added to the guest's memory where the kernel kills the unit's processes.
	killHeadroomBytes = 1024 * 1024 * 1024
	unitPrefix        = "outerlayer-build-"
	// defaultSlice holds the builds of a runner whose config names no slice.
	defaultSlice = "system.slice"
	// cleanupMarginMinutes is added to the runner's time limit. It matches the stop margin of the runner's own service unit.
	cleanupMarginMinutes = 10
)

// ioWeight is the I/O weight of every build's unit. It is the kernel's default, so each build gets an equal share of a
// disk that acts on weights, and a build that runs alone is not slowed. Setting the property also turns on the io
// controller for the unit. No request field changes it.
const ioWeight = 100

// buildSlice is the slice that holds this runner's builds.
func (c Config) buildSlice() string {
	if c.Slice == "" {
		return defaultSlice
	}
	return c.Slice
}

// sliceCgroupPath is the cgroup path of a slice below the cgroup root. A dash in a slice name nests it: systemd keeps
// a-b-c.slice at a.slice/a-b.slice/a-b-c.slice. The jailer needs this path, and so does the read of the kill count.
func sliceCgroupPath(slice string) string {
	name := strings.TrimSuffix(slice, ".slice")
	parts := strings.Split(name, "-")
	path := make([]string, 0, len(parts))
	for i := range parts {
		path = append(path, strings.Join(parts[:i+1], "-")+".slice")
	}
	return strings.Join(path, "/")
}

// UnitName is the transient unit that holds one build.
func UnitName(id string) string { return unitPrefix + id }

// startArgv is the systemd-run command line that starts the jailer for a build.
// The jailer runs Firecracker as uid:uid in a new PID namespace. The unit has
// no network, so the guest's only way out is the runner's sockets in the jail.
//
// The jailer's own process exits 0 once it has cloned Firecracker into the new
// namespace. RemainAfterExit keeps the unit active after that, so systemd does
// not signal the cgroup (Firecracker is init of its namespace and ignores
// SIGTERM). The default KillMode still kills every process of the unit on a
// stop, and KillSignal=SIGKILL makes that kill the first signal: a SIGTERM
// never reaches Firecracker, so systemd would otherwise wait out TimeoutStopSec
// before it kills, and the runner's stop request would time out first. The
// runner kills an unjailed Firecracker with SIGKILL too. UMask=0007 lets the
// runner open the vsock socket Firecracker makes in the jail: the kernel
// applies the creator's umask to a new socket, and the run directory's default
// ACL then caps the runner's entry at the socket's group bits. Under systemd's
// default 0022 that cap is r-x, and connecting needs write. The unit is not
// collected when it ends: a unit the kernel killed for want of memory keeps
// Result=oom-kill until Stop clears it, because systemd removes the cgroup and
// its memory.events with the unit.
//
// With a time limit, the unit gets RuntimeMaxSec of the limit plus
// cleanupMarginMinutes. The runner ends its own build at the limit; the margin
// is for its cleanup. systemd applies RuntimeMaxSec only while the unit is
// running, and the unit is "active (exited)" once the jailer's process has
// gone. ExitType=cgroup keeps the unit running while Firecracker is in its
// cgroup, so the limit ends a build that no runner manages. systemd 249 and
// older reject ExitType, so Run replaces it with a stop timer there.
func startArgv(cfg Config, id string, uid int, memoryMiB int, timeLimitMinutes int) []string {
	unit := UnitName(id)
	memory := int64(memoryMiB) * 1024 * 1024
	var limit []string
	if timeLimitMinutes > 0 {
		limit = []string{
			"--property", "ExitType=cgroup",
			"--property", "RuntimeMaxSec=" + strconv.Itoa((timeLimitMinutes+cleanupMarginMinutes)*60),
		}
	}
	argv := []string{
		"--unit", unit,
		"--description", "OuterLayer microVM " + id,
		"--slice", cfg.buildSlice(),
		"--quiet",
		"--property", "Type=exec",
		"--property", "RemainAfterExit=yes",
		"--property", "KillSignal=SIGKILL",
		"--property", "UMask=0007",
		"--property", "PrivateNetwork=yes",
		"--property", "MemoryHigh=" + strconv.FormatInt(memory+reclaimHeadroomBytes, 10),
		"--property", "MemoryMax=" + strconv.FormatInt(memory+killHeadroomBytes, 10),
		"--property", "MemorySwapMax=0",
		"--property", "IOWeight=" + strconv.Itoa(ioWeight),
	}
	argv = append(argv, limit...)
	return append(argv,
		cfg.Jailer.Path,
		"--id", id,
		"--exec-file", cfg.Firecracker.Path,
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(uid),
		"--chroot-base-dir", cfg.JailBase,
		"--new-pid-ns",
		"--cgroup-version", "2",
		"--parent-cgroup", sliceCgroupPath(cfg.buildSlice())+"/"+unit+".service",
		"--",
		"--no-api",
		"--config-file", "/vm.json",
	)
}

// exitTypeMinVersion is the first systemd that knows the ExitType property.
const exitTypeMinVersion = 250

type realSystemdRunner struct {
	systemdRun, systemctl string
	cgroupRoot            string
	// slice holds the builds; empty means system.slice.
	slice string
	// version reports the systemd version, or 0 when it cannot be read. It is read once.
	version     func() int
	versionOnce sync.Once
	versionNum  int
}

var versionLine = regexp.MustCompile(`^systemd (\d+)`)

func (r *realSystemdRunner) systemdVersion() int {
	r.versionOnce.Do(func() {
		if r.version != nil {
			r.versionNum = r.version()
			return
		}
		out, err := output(exec.Command(r.systemctl, "--version"))
		if err != nil {
			return
		}
		if match := versionLine.FindStringSubmatch(strings.TrimSpace(out)); match != nil {
			r.versionNum, _ = strconv.Atoi(match[1])
		}
	})
	return r.versionNum
}

func limitTimerUnit(unit string) string { return unit + "-limit" }

// withoutExitType drops the ExitType property from a systemd-run command line and returns the unit's RuntimeMaxSec
// in seconds, or 0 when the line has none.
func withoutExitType(argv []string) ([]string, int) {
	kept := make([]string, 0, len(argv))
	seconds := 0
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--property" && i+1 < len(argv) {
			key, value, _ := strings.Cut(argv[i+1], "=")
			if key == "ExitType" {
				i++
				continue
			}
			if key == "RuntimeMaxSec" {
				seconds, _ = strconv.Atoi(value)
			}
		}
		kept = append(kept, argv[i])
	}
	return kept, seconds
}

func findTool(name string) (string, error) {
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s not found", name)
}

// realSystemd runs the real systemd-run and systemctl.
func realSystemd(slice string) (Systemd, error) {
	run, err := findTool("systemd-run")
	if err != nil {
		return nil, err
	}
	ctl, err := findTool("systemctl")
	if err != nil {
		return nil, err
	}
	return &realSystemdRunner{systemdRun: run, systemctl: ctl, cgroupRoot: "/sys/fs/cgroup", slice: slice}, nil
}

func output(cmd *exec.Cmd) (string, error) {
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s: %w: %s", filepath.Base(cmd.Path), err, strings.TrimSpace(errOut.String()))
	}
	return out.String(), nil
}

// Run starts the unit. A systemd older than exitTypeMinVersion, or one whose version is unknown, gets the unit without
// ExitType and a companion timer that stops the unit at its RuntimeMaxSec: the unit is "active (exited)" after the
// jailer's process ends, and systemd does not enforce RuntimeMaxSec in that state.
func (r *realSystemdRunner) Run(argv []string) error {
	if r.systemdVersion() >= exitTypeMinVersion {
		_, err := output(exec.Command(r.systemdRun, argv...))
		return err
	}
	plain, seconds := withoutExitType(argv)
	if _, err := output(exec.Command(r.systemdRun, plain...)); err != nil {
		return err
	}
	if seconds == 0 {
		return nil
	}
	unit := ""
	for i, arg := range argv {
		if arg == "--unit" && i+1 < len(argv) {
			unit = argv[i+1]
		}
	}
	timer := []string{
		"--unit", limitTimerUnit(unit), "--quiet",
		"--on-active=" + strconv.Itoa(seconds), "--timer-property=AccuracySec=1s",
		r.systemctl, "stop", unit + ".service",
	}
	if _, err := output(exec.Command(r.systemdRun, timer...)); err != nil {
		_ = r.Stop(unit)
		return fmt.Errorf("the time limit timer of %s could not be started: %w", unit, err)
	}
	return nil
}

func (r *realSystemdRunner) Stop(unit string) error {
	// The companion timer exists only on a systemd without ExitType, and an ended build may have used it up already.
	_, _ = output(exec.Command(r.systemctl, "stop", limitTimerUnit(unit)+".timer"))
	if _, err := output(exec.Command(r.systemctl, "stop", unit+".service")); err != nil {
		// A unit that is not loaded is already stopped.
		active, activeErr := r.Active(unit)
		if activeErr == nil && !active {
			return nil
		}
		return err
	}
	// A unit left failed (for example by the OOM killer) is not collected, so clear it. An unloaded unit has
	// nothing to clear.
	_, _ = output(exec.Command(r.systemctl, "reset-failed", unit+".service"))
	return nil
}

func (r *realSystemdRunner) Active(unit string) (bool, error) {
	out, _ := output(exec.Command(r.systemctl, "is-active", unit+".service"))
	switch strings.TrimSpace(out) {
	case "active", "activating", "deactivating", "reloading":
		return true, nil
	case "inactive", "failed", "unknown", "":
		return false, nil
	}
	return false, errors.New("systemctl is-active answered " + strings.TrimSpace(out))
}

var oomKillLine = regexp.MustCompile(`(?m)^oom_kill (\d+)$`)

// OOMKills is the kernel's count of kills in the unit's cgroup. systemd removes the cgroup, and its memory.events,
// when the unit ends, so a unit that ended with Result=oom-kill counts as one kill.
func (r *realSystemdRunner) OOMKills(unit string) (int, error) {
	slice := r.slice
	if slice == "" {
		slice = defaultSlice
	}
	data, err := os.ReadFile(filepath.Join(r.cgroupRoot, sliceCgroupPath(slice), unit+".service", "memory.events"))
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	if err == nil {
		if match := oomKillLine.FindSubmatch(data); match != nil {
			kills, convErr := strconv.Atoi(string(match[1]))
			if convErr != nil || kills > 0 {
				return kills, convErr
			}
		}
	}
	out, showErr := output(exec.Command(r.systemctl, "show", "--property=Result", "--value", unit+".service"))
	if showErr == nil && strings.TrimSpace(out) == "oom-kill" {
		return 1, nil
	}
	return 0, nil
}

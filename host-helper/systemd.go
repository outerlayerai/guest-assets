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
	unitSlice         = "system.slice"
)

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
// stop. The unit is not collected when it ends: a unit the kernel killed for
// want of memory keeps Result=oom-kill until Stop clears it, because systemd
// removes the cgroup and its memory.events with the unit.
func startArgv(cfg Config, id string, uid int, memoryMiB int) []string {
	unit := UnitName(id)
	memory := int64(memoryMiB) * 1024 * 1024
	return []string{
		"--unit", unit,
		"--description", "OuterLayer microVM " + id,
		"--slice", unitSlice,
		"--quiet",
		"--property", "Type=exec",
		"--property", "RemainAfterExit=yes",
		"--property", "PrivateNetwork=yes",
		"--property", "MemoryHigh=" + strconv.FormatInt(memory+reclaimHeadroomBytes, 10),
		"--property", "MemoryMax=" + strconv.FormatInt(memory+killHeadroomBytes, 10),
		"--property", "MemorySwapMax=0",
		cfg.Jailer.Path,
		"--id", id,
		"--exec-file", cfg.Firecracker.Path,
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(uid),
		"--chroot-base-dir", cfg.JailBase,
		"--new-pid-ns",
		"--cgroup-version", "2",
		"--parent-cgroup", unitSlice + "/" + unit + ".service",
		"--",
		"--no-api",
		"--config-file", "/vm.json",
	}
}

type realSystemdRunner struct {
	systemdRun, systemctl string
	cgroupRoot            string
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
func realSystemd() (Systemd, error) {
	run, err := findTool("systemd-run")
	if err != nil {
		return nil, err
	}
	ctl, err := findTool("systemctl")
	if err != nil {
		return nil, err
	}
	return &realSystemdRunner{systemdRun: run, systemctl: ctl, cgroupRoot: "/sys/fs/cgroup"}, nil
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

func (r *realSystemdRunner) Run(argv []string) error {
	_, err := output(exec.Command(r.systemdRun, argv...))
	return err
}

func (r *realSystemdRunner) Stop(unit string) error {
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
	data, err := os.ReadFile(filepath.Join(r.cgroupRoot, unitSlice, unit+".service", "memory.events"))
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

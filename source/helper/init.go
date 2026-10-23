// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	vmInitDefault = "/opt/outerlayer/bin/node /opt/outerlayer/cli/dist/index.js vm-init"
	vmInitEnvVar  = "OUTERLAYER_GUEST_VM_INIT"
	initPath      = "/opt/outerlayer/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

type mountSpec struct {
	source, target, fstype, data string
	flags                        uintptr
}

const stdFlags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC

var initMounts = []mountSpec{
	{"proc", "/proc", "proc", "", stdFlags},
	{"sysfs", "/sys", "sysfs", "", stdFlags},
	{"devtmpfs", "/dev", "devtmpfs", "mode=0755", unix.MS_NOSUID},
	{"devpts", "/dev/pts", "devpts", "gid=5,mode=620,ptmxmode=666", unix.MS_NOSUID | unix.MS_NOEXEC},
	{"tmpfs", "/dev/shm", "tmpfs", "mode=1777", unix.MS_NOSUID | unix.MS_NODEV},
	{"tmpfs", "/run", "tmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_NODEV},
}

func mountAll(specs []mountSpec) error {
	for _, m := range specs {
		if err := os.MkdirAll(m.target, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", m.target, err)
		}
		err := unix.Mount(m.source, m.target, m.fstype, m.flags, m.data)
		if err != nil && err != unix.EBUSY {
			return fmt.Errorf("mount %s: %w", m.target, err)
		}
	}
	return nil
}

// loopbackUp sets IFF_UP on lo without a netlink dependency.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// vmInitArgv returns the command init runs. The env lookup lets tests
// override it.
func vmInitArgv(getenv func(string) string) []string {
	if v := strings.Fields(getenv(vmInitEnvVar)); len(v) > 0 {
		return v
	}
	return strings.Fields(vmInitDefault)
}

func vmInitEnv() []string {
	return []string{"PATH=" + initPath, "HOME=/root"}
}

// reapAll collects every exited child without blocking. It returns the
// reaped pids with their wait statuses.
func reapAll() map[int]syscall.WaitStatus {
	out := map[int]syscall.WaitStatus{}
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || pid <= 0 {
			return out
		}
		out[pid] = ws
	}
}

// waitFor blocks until the given pid exits and returns its status. Other
// exited children, such as orphans reparented to init, are reaped meanwhile.
func waitFor(pid int) syscall.WaitStatus {
	for {
		var ws syscall.WaitStatus
		got, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return syscall.WaitStatus(1 << 8)
		}
		if got == pid {
			return ws
		}
	}
}

func statusCode(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

// reapForever never returns: PID 1 exiting panics the kernel.
func reapForever() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGCHLD)
	for {
		reapAll()
		select {
		case <-ch:
		case <-time.After(time.Second):
		}
	}
}

// powerOff ends the microVM and never returns. Firecracker keeps running when
// an x86 guest powers off, and exits when the guest resets its CPU, so the
// guest restarts rather than powering off.
func powerOff() {
	endMicroVM(unix.Sync, unix.Reboot)
	for {
		time.Sleep(time.Hour)
	}
}

// endMicroVM writes the guest's file systems out, then restarts the guest.
func endMicroVM(sync func(), reboot func(cmd int) error) {
	sync()
	_ = reboot(unix.LINUX_REBOOT_CMD_RESTART)
}

// startLeaseWatchdog runs the lease watchdog when the kernel command line names
// a lease port, and reports whether it started one. It runs inside init, so a
// build's own processes cannot stop it. A guest with no lease port runs no
// watchdog and never powers itself off.
func startLeaseWatchdog(ctx context.Context, readCmdline func() ([]byte, error), dialPort func(port uint32) (net.Conn, error), off func()) bool {
	cmdline, err := readCmdline()
	if err != nil {
		return false
	}
	port, ok := leasePortFromCmdline(string(cmdline))
	if !ok {
		return false
	}
	dial := func() (net.Conn, error) {
		conn, err := dialPort(port)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	go runLeaseWatchdog(ctx, dial, off)
	return true
}

func startInitLeaseWatchdog() {
	startLeaseWatchdog(
		context.Background(),
		func() ([]byte, error) { return os.ReadFile("/proc/cmdline") },
		dialHost,
		powerOff,
	)
}

func runInit() int {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "init: must run as PID 1")
		return 1
	}
	if err := mountAll(initMounts); err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
	}
	if err := loopbackUp(); err != nil {
		fmt.Fprintf(os.Stderr, "init: bring up lo: %v\n", err)
	}
	startInitLeaseWatchdog()
	argv := vmInitArgv(os.Getenv)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = vmInitEnv()
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stdout, "vm-init failed: %v\n", err)
		powerOff()
	}
	status := statusCode(waitFor(cmd.Process.Pid))
	if status != 0 {
		fmt.Fprintf(os.Stdout, "vm-init failed: %d\n", status)
		powerOff()
	}
	reapForever()
	return 0
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func unitProperties(argv []string) map[string]string {
	props := map[string]string{}
	for i, arg := range argv {
		if arg == "--property" && i+1 < len(argv) {
			key, value, _ := strings.Cut(argv[i+1], "=")
			props[key] = value
		}
	}
	return props
}

func hasArg(argv []string, want string) bool {
	for _, arg := range argv {
		if arg == want {
			return true
		}
	}
	return false
}

// Under --new-pid-ns (and under --daemonize) the jailer clones Firecracker and
// its own process exits 0. systemd treats a Type=exec or Type=simple unit
// whose main process has exited as finished: with RemainAfterExit=no it sends
// SIGTERM to the rest of the cgroup, then SIGKILL after TimeoutStopSec. The
// unit must keep a main process alive, or stay active after the main process
// exits, so Firecracker runs until the runner stops the build.
func TestTheBuildsUnitOutlivesTheJailersOwnProcess(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	argv := f.sd.runs[0]
	jailerExits := hasArg(argv, "--new-pid-ns") || hasArg(argv, "--daemonize")
	if !jailerExits {
		return
	}
	props := unitProperties(argv)
	if props["RemainAfterExit"] == "yes" {
		return
	}
	if props["Type"] == "forking" && props["PIDFile"] != "" {
		return
	}
	t.Fatalf("the jailer's process exits after it clones Firecracker, and the unit then stops and kills Firecracker: %v", argv)
}

// Firecracker is init of its PID namespace, so the SIGTERM that systemd sends
// first on a stop never reaches it, and systemd waits TimeoutStopSec (90 s by
// default) before SIGKILL. The runner waits 30 seconds for a stop, so the
// stop must kill at once, as the runner kills an unjailed Firecracker.
func TestAStopKillsFirecrackerAtOnce(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	if props := unitProperties(f.sd.runs[0]); props["KillSignal"] != "SIGKILL" {
		t.Fatalf("a stop sends SIGTERM first, which Firecracker never receives as its namespace's init: %v", f.sd.runs[0])
	}
}

// The runner reaches the guest's exec agent through the vsock socket that
// Firecracker makes in the jail's run directory. The kernel applies the
// creator's umask to a new socket, and the directory's default ACL then caps
// the runner's entry at the socket's group bits. Under systemd's default
// umask, 0022, that cap is r-x: connecting needs write, so every connection
// from the runner is refused and the build looks as if its agent never started.
func TestTheRunnerCanConnectToTheSocketFirecrackerMakes(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	umask := unitProperties(f.sd.runs[0])["UMask"]
	mask, err := strconv.ParseUint(umask, 8, 32)
	if umask == "" || err != nil || mask&0o070 != 0 {
		t.Fatalf("the unit's umask %q takes group bits from the socket, and so the runner's write access: %v", umask, f.sd.runs[0])
	}
}

// After a unit ends, systemd removes its cgroup, so memory.events is gone.
// With --collect it also unloads the unit, so its Result (oom-kill) is gone
// too. A build the kernel killed for want of memory must still be reported
// as such after its unit has ended.
func TestOOMKillsAreStillReportedAfterTheUnitEnded(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	if hasArg(f.sd.runs[0], "--collect") {
		t.Fatalf("the unit is collected when it ends, so nothing records that the kernel killed it: %v", f.sd.runs[0])
	}

	dir := t.TempDir()
	systemctl := filepath.Join(dir, "systemctl")
	// The answers real systemd gives for a unit that failed with result oom-kill and is not collected.
	script := `#!/bin/sh
case "$*" in
  *is-active*) echo failed; exit 3 ;;
  *show*--value*) echo oom-kill ;;
  *show*) echo Result=oom-kill ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(systemctl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	real := &realSystemdRunner{systemdRun: "/bin/false", systemctl: systemctl, cgroupRoot: filepath.Join(dir, "cgroup")}
	kills, err := real.OOMKills(UnitName(testBuild))
	if err != nil {
		t.Fatal(err)
	}
	if kills == 0 {
		t.Fatal("a unit that ended by the OOM killer, with its cgroup removed, reports no out-of-memory kill")
	}
}

// A stand-in systemctl that logs every call and answers is-active and show from the files next to it.
func fakeSystemctl(t *testing.T, result string) (*realSystemdRunner, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\ncase \"$*\" in\n  *show*--value*) echo " + result + " ;;\n  *is-active*) echo inactive; exit 3 ;;\n  *) exit 0 ;;\nesac\n"
	path := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &realSystemdRunner{systemdRun: "/bin/false", systemctl: path, cgroupRoot: filepath.Join(dir, "cgroup")}, log
}

func TestTheKernelsCountOfKillsInTheLiveCgroupIsReported(t *testing.T) {
	real, _ := fakeSystemctl(t, "success")
	cg := filepath.Join(real.cgroupRoot, unitSlice, UnitName(testBuild)+".service")
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cg, "memory.events"), []byte("low 0\nhigh 0\nmax 0\noom 3\noom_kill 3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kills, err := real.OOMKills(UnitName(testBuild))
	if err != nil || kills != 3 {
		t.Fatalf("want 3 kills, got %d, %v", kills, err)
	}
}

func TestAUnitThatEndedWithoutAKillReportsNone(t *testing.T) {
	real, _ := fakeSystemctl(t, "success")
	kills, err := real.OOMKills(UnitName(testBuild))
	if err != nil || kills != 0 {
		t.Fatalf("want 0 kills, got %d, %v", kills, err)
	}
}

func TestStoppingAUnitClearsItsFailedState(t *testing.T) {
	real, log := fakeSystemctl(t, "oom-kill")
	if err := real.Stop(UnitName(testBuild)); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "reset-failed "+UnitName(testBuild)+".service") {
		t.Fatalf("a failed unit stays loaded unless it is reset: %s", calls)
	}
}

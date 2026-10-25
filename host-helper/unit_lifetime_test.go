// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"encoding/json"
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
	cg := filepath.Join(real.cgroupRoot, defaultSlice, UnitName(testBuild)+".service")
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

func (f *fixture) startWithLimit(minutes int) []string {
	f.t.Helper()
	f.makeBuild(testBuild)
	reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStart, Build: testBuild, Kind: KindBuild, TimeLimitMinutes: minutes})
	mustOK(f.t, reply)
	return f.sd.runs[len(f.sd.runs)-1]
}

// AC-1291-14
func TestAStartRequestThatNamesATimeLimitGivesTheUnitThatLimitPlusTenMinutes(t *testing.T) {
	for _, minutes := range []int{1, 480, 1320} {
		f := newFixture(t)
		argv := f.startWithLimit(minutes)
		want := strconv.Itoa((minutes + 10) * 60)
		if got := unitProperties(argv)["RuntimeMaxSec"]; got != want {
			t.Fatalf("a limit of %d minutes gave RuntimeMaxSec=%q, want %q: %v", minutes, got, want, argv)
		}
	}
}

// AC-1291-15
func TestAStartRequestThatNamesNoTimeLimitGivesTheUnitNoRuntimeLimit(t *testing.T) {
	f := newFixture(t)
	argv := f.startWithLimit(0)
	if got, set := unitProperties(argv)["RuntimeMaxSec"]; set {
		t.Fatalf("a request with no time limit gave RuntimeMaxSec=%q: %v", got, argv)
	}
}

func TestAStartRequestWithATimeLimitOutsideTheRunnersRangeIsRefused(t *testing.T) {
	for _, minutes := range []int{-1, 1321, 100000} {
		f := newFixture(t)
		f.makeBuild(testBuild)
		reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStart, Build: testBuild, Kind: KindBuild, TimeLimitMinutes: minutes})
		mustRefuse(t, reply, CodeBadRequest)
		if len(f.sd.runs) != 0 {
			t.Fatalf("a limit of %d minutes started a unit: %v", minutes, f.sd.runs)
		}
	}
}

func TestATimeLimitIsPassedToTheUnitOfAChecksMicroVMToo(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	mustOK(t, f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStart, Build: testBuild, Kind: KindCheck, TimeLimitMinutes: 30}))
	if got := unitProperties(f.sd.runs[0])["RuntimeMaxSec"]; got != "2400" {
		t.Fatalf("RuntimeMaxSec=%q, want 2400", got)
	}
}

// systemd applies RuntimeMaxSec only while a unit is running. The jailer's own process exits, so without ExitType=cgroup
// the unit is "active (exited)" and the limit is never enforced.
func TestAUnitWithARuntimeLimitStaysRunningWhileFirecrackerIsInItsCgroup(t *testing.T) {
	f := newFixture(t)
	props := unitProperties(f.startWithLimit(30))
	if props["RuntimeMaxSec"] == "" || props["ExitType"] != "cgroup" {
		t.Fatalf("RuntimeMaxSec=%q ExitType=%q: a runtime limit needs ExitType=cgroup", props["RuntimeMaxSec"], props["ExitType"])
	}
}

func TestTheWireKeyOfTheTimeLimitIsTimeLimitMinutes(t *testing.T) {
	var req Request
	if err := json.Unmarshal([]byte(`{"v":1,"op":"start","build":"b","timeLimitMinutes":30}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.TimeLimitMinutes != 30 {
		t.Fatalf("timeLimitMinutes decoded as %d, want 30", req.TimeLimitMinutes)
	}
	out, err := json.Marshal(Request{V: 1, Op: OpStart, TimeLimitMinutes: 45})
	if err != nil || !strings.Contains(string(out), `"timeLimitMinutes":45`) {
		t.Fatalf("encoded as %s, %v", out, err)
	}
}

func TestAStartRequestWithNoTimeLimitAndTheMinimumTimeLimitAreAccepted(t *testing.T) {
	for _, minutes := range []int{0, MinTimeLimitMinutes} {
		f := newFixture(t)
		f.startWithLimit(minutes)
	}
}

// Stand-in systemd-run and systemctl that log every call.
func fakeTools(t *testing.T, version int) (*realSystemdRunner, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	for _, name := range []string{"systemd-run", "systemctl"} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> " + log + "\nexit 0\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r := &realSystemdRunner{
		systemdRun: filepath.Join(dir, "systemd-run"), systemctl: filepath.Join(dir, "systemctl"),
		cgroupRoot: filepath.Join(dir, "cgroup"), version: func() int { return version },
	}
	return r, log
}

func readCalls(t *testing.T, log string) string {
	t.Helper()
	data, err := os.ReadFile(log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

func TestSystemd250AndLaterStartsTheUnitWithExitTypeAndNoTimer(t *testing.T) {
	r, log := fakeTools(t, 250)
	f := newFixture(t)
	if err := r.Run(startArgv(f.cfg, testBuild, 1000, 512, 30)); err != nil {
		t.Fatal(err)
	}
	calls := readCalls(t, log)
	if !strings.Contains(calls, "ExitType=cgroup") || strings.Contains(calls, "--on-active") {
		t.Fatalf("a systemd that knows ExitType needs it and no timer: %s", calls)
	}
}

func TestSystemd249StartsTheUnitWithoutExitTypeAndAStopTimerAtTheRuntimeLimit(t *testing.T) {
	for _, version := range []int{249, 0} {
		r, log := fakeTools(t, version)
		f := newFixture(t)
		if err := r.Run(startArgv(f.cfg, testBuild, 1000, 512, 30)); err != nil {
			t.Fatal(err)
		}
		calls := readCalls(t, log)
		if strings.Contains(calls, "ExitType=") || !strings.Contains(calls, "RuntimeMaxSec=2400") {
			t.Fatalf("version %d: the unit must keep RuntimeMaxSec and drop ExitType: %s", version, calls)
		}
		want := "--unit " + UnitName(testBuild) + "-limit --quiet --on-active=2400 --timer-property=AccuracySec=1s " + r.systemctl + " stop " + UnitName(testBuild) + ".service"
		if !strings.Contains(calls, want) {
			t.Fatalf("version %d: no stop timer %q in: %s", version, want, calls)
		}
	}
}

func TestSystemd249StartsNoTimerForAUnitWithNoLimit(t *testing.T) {
	r, log := fakeTools(t, 249)
	f := newFixture(t)
	if err := r.Run(startArgv(f.cfg, testBuild, 1000, 512, 0)); err != nil {
		t.Fatal(err)
	}
	if calls := readCalls(t, log); strings.Contains(calls, "--on-active") {
		t.Fatalf("a unit with no limit got a timer: %s", calls)
	}
}

func TestStoppingABuildStopsItsLimitTimer(t *testing.T) {
	r, log := fakeTools(t, 249)
	if err := r.Stop(UnitName(testBuild)); err != nil {
		t.Fatal(err)
	}
	if calls := readCalls(t, log); !strings.Contains(calls, "systemctl stop "+UnitName(testBuild)+"-limit.timer") {
		t.Fatalf("a build that ends before its limit leaves its timer behind: %s", calls)
	}
}

func TestAFailedStopTimerStopsTheUnitAndFailsTheStart(t *testing.T) {
	r, log := fakeTools(t, 249)
	script := "#!/bin/sh\necho \"systemd-run $*\" >> " + log + "\ncase \"$*\" in *--on-active*) exit 1 ;; esac\nexit 0\n"
	if err := os.WriteFile(r.systemdRun, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	if err := r.Run(startArgv(f.cfg, testBuild, 1000, 512, 30)); err == nil {
		t.Fatal("a unit with no way to enforce its limit started")
	}
	if calls := readCalls(t, log); !strings.Contains(calls, "systemctl stop "+UnitName(testBuild)+".service") {
		t.Fatalf("the unit was left running: %s", calls)
	}
}

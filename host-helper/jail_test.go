// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func flagValue(argv []string, flag string) string {
	for i, arg := range argv {
		if arg == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

func (f *fixture) startOK(id string, kind string) Reply {
	f.t.Helper()
	f.makeBuild(id)
	reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStart, Build: id, Kind: kind})
	mustOK(f.t, reply)
	return reply
}

// Once it starts, the jailer sets the jail's root and run directories to mode
// 0700. On a directory with an ACL that clears the mask, so the runner's entry
// no longer lets it reach the vsock socket: every connection is refused with
// EACCES. Once Firecracker has made the socket, the helper puts that access back.
func TestStartGivesTheRunnerItsWayBackToTheSocketAfterTheJailerRuns(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	paths := f.h.jailPathsFor(testBuild)
	if len(f.acls) < 2 {
		t.Fatalf("too few ACLs were set: %v", f.acls)
	}
	last := f.acls[len(f.acls)-2:]
	want := []aclCall{{paths.chroot, f.cfg.RunnerUID, 0o1, false}, {paths.run, f.cfg.RunnerUID, 0o1, false}}
	for i := range want {
		if last[i] != want[i] {
			t.Fatalf("after the unit started, the ACLs set were %v, want %v", last, want)
		}
	}
}

// A Firecracker that never makes its socket ends the start: the unit is
// stopped and the jail removed, so nothing is left for cleanup to find.
func TestStartIsRefusedWhenFirecrackerMakesNoSocket(t *testing.T) {
	f := newFixture(t)
	f.sd.noSocket = true
	f.h.vsockWait = 50 * time.Millisecond
	f.makeBuild(testBuild)
	reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStart, Build: testBuild, Kind: KindBuild})
	mustRefuseBecause(t, reply, CodeInternal, "no vsock socket")
	if len(f.sd.stops) != 1 || f.sd.stops[0] != UnitName(testBuild) {
		t.Fatalf("the unit was not stopped: %v", f.sd.stops)
	}
	if _, err := os.Stat(f.h.jailPathsFor(testBuild).dir); !os.IsNotExist(err) {
		t.Fatalf("the jail is still there: %v", err)
	}
}

func TestStartRunsTheBuildInAUnitNamedForIt(t *testing.T) {
	f := newFixture(t)
	reply := f.startOK(testBuild, KindBuild)
	if len(f.sd.runs) != 1 {
		t.Fatalf("want one systemd-run, got %v", f.sd.runs)
	}
	argv := f.sd.runs[0]
	if got := flagValue(argv, "--unit"); got != "outerlayer-build-"+testBuild {
		t.Fatalf("unit is %q in %v", got, argv)
	}
	if reply.Unit != "outerlayer-build-"+testBuild {
		t.Fatalf("reply names unit %q", reply.Unit)
	}
	if reply.Chroot != f.chroot(testBuild) || reply.Vsock != filepath.Join(f.chroot(testBuild), "run", "v.sock") {
		t.Fatalf("reply names chroot %q and vsock %q", reply.Chroot, reply.Vsock)
	}
}

func TestStartRunsTheJailerWithoutPCIAndWithAFixedCommandLine(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	argv := f.sd.runs[0]
	rest := argv
	for i, arg := range argv {
		if arg == f.cfg.Jailer.Path {
			rest = argv[i+1:]
			break
		}
	}
	split := -1
	for i, arg := range rest {
		if arg == "--" {
			split = i
		}
	}
	if split < 0 {
		t.Fatalf("no -- separator in %v", rest)
	}
	jailed := rest[split+1:]
	if strings.Join(jailed, " ") != "--no-api --config-file /vm.json" {
		t.Fatalf("Firecracker is given %v", jailed)
	}
	for _, arg := range argv {
		if strings.Contains(arg, "enable-pci") {
			t.Fatalf("the command line enables PCI: %v", argv)
		}
	}
	if flagValue(rest[:split], "--exec-file") != f.cfg.Firecracker.Path || flagValue(rest[:split], "--id") != testBuild {
		t.Fatalf("jailer arguments %v", rest[:split])
	}
	if flagValue(rest[:split], "--chroot-base-dir") != f.jail || flagValue(rest[:split], "--cgroup-version") != "2" {
		t.Fatalf("jailer arguments %v", rest[:split])
	}
	if flagValue(rest[:split], "--parent-cgroup") != "system.slice/outerlayer-build-"+testBuild+".service" {
		t.Fatalf("jailer arguments %v", rest[:split])
	}
	if !strings.Contains(strings.Join(rest[:split], " "), "--new-pid-ns") {
		t.Fatalf("no new PID namespace in %v", rest[:split])
	}
	if !strings.Contains(strings.Join(argv, " "), "PrivateNetwork=yes") {
		t.Fatalf("the unit has a network: %v", argv)
	}
}

type limitVectors struct {
	ReclaimHeadroomBytes int64 `json:"reclaimHeadroomBytes"`
	KillHeadroomBytes    int64 `json:"killHeadroomBytes"`
}

func TestUnitCarriesTheBuildsMemoryLimits(t *testing.T) {
	data, err := os.ReadFile("testdata/limits.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors limitVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	joined := strings.Join(f.sd.runs[0], " ")
	const mib = 1024 * 1024
	high := int64(2048)*mib + vectors.ReclaimHeadroomBytes
	max := int64(2048)*mib + vectors.KillHeadroomBytes
	for _, want := range []string{"MemoryHigh=" + itoa(high), "MemoryMax=" + itoa(max), "MemorySwapMax=0"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("%q is missing from %v", want, f.sd.runs[0])
		}
	}
}

func TestMemoryLimitsFollowTheRunnersMachineConfiguration(t *testing.T) {
	f := newFixture(t)
	dir := f.makeBuild(testBuild)
	vm := `{"machine-config":{"vcpu_count":4,"mem_size_mib":512,"smt":false},"boot-source":{"boot_args":"pci=off"}}`
	writeFile(t, filepath.Join(dir, "vm.json"), vm, 0o600)
	mustOK(t, f.start(testBuild))
	if !strings.Contains(strings.Join(f.sd.runs[0], " "), "MemoryMax="+itoa(512*1024*1024+1024*1024*1024)) {
		t.Fatalf("limits ignore vm.json: %v", f.sd.runs[0])
	}
}

func TestStartGivesTheJailOnlyTheBuildsOwnFiles(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	chroot := f.chroot(testBuild)
	dir := filepath.Join(f.builds, testBuild)
	for _, name := range []string{"kernel", "rootfs.ext4", "build.ext4"} {
		a, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.Stat(filepath.Join(chroot, name))
		if err != nil {
			t.Fatalf("%s is not in the chroot: %v", name, err)
		}
		if !os.SameFile(a, b) {
			t.Fatalf("%s in the chroot is not the build's own file", name)
		}
	}
	for name, port := range map[string]string{"tunnel.sock": "3128", "gateway.sock": "3126", "claude.sock": "3127", "dest-0.sock": "3129", "lease.sock": "3125"} {
		a, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.Stat(filepath.Join(chroot, "run", "v.sock_"+port))
		if err != nil {
			t.Fatalf("no link for %s: %v", name, err)
		}
		if !os.SameFile(a, b) {
			t.Fatalf("v.sock_%s is not %s", port, name)
		}
	}
	entries, _ := os.ReadDir(chroot)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if strings.Join(names, ",") != "build.ext4,kernel,rootfs.ext4,run,vm.json" {
		t.Fatalf("the chroot holds %v", names)
	}
}

func TestStartWritesTheMachineConfigurationFromThreeFieldsOnly(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	data, err := os.ReadFile(filepath.Join(f.chroot(testBuild), "vm.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, host := range []string{"/etc/shadow", "/etc/passwd", f.builds} {
		if strings.Contains(text, host) {
			t.Fatalf("vm.json holds a host path %q: %s", host, text)
		}
	}
	var cfg struct {
		BootSource struct {
			Kernel   string `json:"kernel_image_path"`
			BootArgs string `json:"boot_args"`
		} `json:"boot-source"`
		Drives []struct {
			ID   string `json:"drive_id"`
			Path string `json:"path_on_host"`
		} `json:"drives"`
		Machine struct {
			CPUs int `json:"vcpu_count"`
			Mem  int `json:"mem_size_mib"`
		} `json:"machine-config"`
		Vsock struct {
			Path string `json:"uds_path"`
		} `json:"vsock"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.BootSource.Kernel != "/kernel" || cfg.Vsock.Path != "/run/v.sock" || cfg.Machine.CPUs != 2 || cfg.Machine.Mem != 2048 || cfg.BootSource.BootArgs != "console=ttyS0 pci=off" {
		t.Fatalf("configuration %+v", cfg)
	}
	if len(cfg.Drives) != 2 || cfg.Drives[0].Path != "/rootfs.ext4" || cfg.Drives[1].Path != "/build.ext4" {
		t.Fatalf("drives %+v", cfg.Drives)
	}
	if strings.Contains(text, "network-interfaces") {
		t.Fatal("the guest has a network device")
	}
}

func TestStartChangesTheOwnerOfTheBuildDiskOnly(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	// The chroot's own directories are made by the helper; the one shared file it hands over is the disk.
	if len(f.chowns) < 1 {
		t.Fatal("no owner was changed")
	}
	uid := f.chowns[len(f.chowns)-1].uid
	if uid < f.cfg.UIDBase || uid >= f.cfg.UIDBase+f.cfg.UIDCount {
		t.Fatalf("the disk went to uid %d, outside the build range", uid)
	}
	if flagValue(f.sd.runs[0], "--uid") == "" {
		t.Fatalf("no --uid in %v", f.sd.runs[0])
	}
}

func TestStartGivesTheRunnersAccountAccessToTheRunDirectoryOnly(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	var sawDefault bool
	for _, acl := range f.acls {
		if acl.runnerUID != f.cfg.RunnerUID {
			t.Fatalf("an ACL names uid %d, not the runner's", acl.runnerUID)
		}
		if !strings.HasPrefix(acl.path, f.chroot(testBuild)) && acl.path != filepath.Join(f.jail, "firecracker", testBuild) {
			t.Fatalf("an ACL was set outside the build's jail: %s", acl.path)
		}
		if acl.isDefault && acl.path == filepath.Join(f.chroot(testBuild), "run") {
			sawDefault = true
		}
	}
	if !sawDefault {
		t.Fatalf("run/ has no default ACL for the runner: %+v", f.acls)
	}
}

func TestTwoBuildsRunAsDifferentUsers(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	f.startOK("fedcba987654", KindBuild)
	a, b := flagValue(f.sd.runs[0], "--uid"), flagValue(f.sd.runs[1], "--uid")
	if a == "" || b == "" || a == b {
		t.Fatalf("users %q and %q", a, b)
	}
	if flagValue(f.sd.runs[0], "--gid") == flagValue(f.sd.runs[1], "--gid") {
		t.Fatal("the builds share a group")
	}
}

func TestTheBuildUserIsNeitherTheRunnerNorRootAndSharesNoGroupWithIt(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	uid, gid := flagValue(f.sd.runs[0], "--uid"), flagValue(f.sd.runs[0], "--gid")
	for _, id := range []string{uid, gid} {
		if id == "0" || id == itoa(int64(f.cfg.RunnerUID)) || id == itoa(int64(f.cfg.RunnerGID)) {
			t.Fatalf("build user and group %s/%s overlap the runner's or root", uid, gid)
		}
	}
}

func TestChecksMicroVMGetsAUserAndUnitOfItsOwn(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	f.startOK("aaaaaaaaaaaa", KindCheck)
	if len(f.sd.runs) != 2 {
		t.Fatalf("want two units, got %v", f.sd.runs)
	}
	if flagValue(f.sd.runs[1], "--unit") != "outerlayer-build-aaaaaaaaaaaa" || flagValue(f.sd.runs[0], "--unit") == flagValue(f.sd.runs[1], "--unit") {
		t.Fatalf("units %v", f.sd.runs)
	}
	if flagValue(f.sd.runs[0], "--uid") == flagValue(f.sd.runs[1], "--uid") {
		t.Fatal("the check microVM runs as the build's user")
	}
	joined := strings.Join(f.sd.runs[1], " ")
	if !strings.Contains(joined, "PrivateNetwork=yes") || !strings.Contains(joined, f.cfg.Jailer.Path) {
		t.Fatalf("the check microVM is not jailed and cut off: %v", f.sd.runs[1])
	}
	reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpList})
	mustOK(t, reply)
	if strings.Join(reply.Builds, ",") != testBuild+",aaaaaaaaaaaa" {
		t.Fatalf("list answered %v", reply.Builds)
	}
}

func TestRefusesToStartABuildTwice(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	mustRefuse(t, f.start(testBuild), CodeAlreadyRunning)
	if len(f.sd.runs) != 1 {
		t.Fatalf("a second unit was started: %v", f.sd.runs)
	}
}

func TestRefusesAStartWhenEveryBuildUserIsTaken(t *testing.T) {
	f := newFixture(t)
	ids := []string{"000000000001", "000000000002", "000000000003", "000000000004"}
	for _, id := range ids {
		f.startOK(id, KindBuild)
	}
	f.makeBuild("000000000005")
	mustRefuse(t, f.start("000000000005"), CodeNoUser)
	mustOK(t, f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStop, Build: ids[0]}))
	mustOK(t, f.start("000000000005"))
}

func TestStopStopsTheUnitAndRemovesTheChroot(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	dir := filepath.Join(f.builds, testBuild)
	before, _ := os.Stat(filepath.Join(dir, "rootfs.ext4"))
	reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStop, Build: testBuild})
	mustOK(t, reply)
	if len(f.sd.stops) != 1 || f.sd.stops[0] != "outerlayer-build-"+testBuild {
		t.Fatalf("stops %v", f.sd.stops)
	}
	if _, err := os.Lstat(filepath.Dir(f.chroot(testBuild))); err == nil {
		t.Fatal("the chroot is still there")
	}
	after, err := os.Stat(filepath.Join(dir, "rootfs.ext4"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("stopping removed the build's own file: %v", err)
	}
	list := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpList})
	if len(list.Builds) != 0 {
		t.Fatalf("list still holds %v", list.Builds)
	}
}

func TestStopDoesNotFollowALinkOutOfTheChroot(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	outside := filepath.Join(f.root, "precious")
	writeFile(t, filepath.Join(outside, "file"), "keep", 0o600)
	if err := os.Symlink(outside, filepath.Join(f.chroot(testBuild), "run", "escape")); err != nil {
		t.Fatal(err)
	}
	mustOK(t, f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStop, Build: testBuild}))
	if _, err := os.Stat(filepath.Join(outside, "file")); err != nil {
		t.Fatalf("stop followed a link out of the chroot: %v", err)
	}
}

func TestStateReportsTheUnitAndItsOutOfMemoryKills(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	f.sd.oom["outerlayer-build-"+testBuild] = 2
	reply := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpState, Build: testBuild})
	mustOK(t, reply)
	if reply.Active == nil || !*reply.Active || reply.OOMKills == nil || *reply.OOMKills != 2 {
		t.Fatalf("state answered %+v", reply)
	}
	delete(f.sd.active, "outerlayer-build-"+testBuild)
	reply = f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpState, Build: testBuild})
	if reply.Active == nil || *reply.Active {
		t.Fatalf("state answered %+v", reply)
	}
}

func TestAHelperThatRestartsStillHoldsTheBuildsItStarted(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	uid := flagValue(f.sd.runs[0], "--uid")
	f.rebuild()
	list := f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpList})
	if strings.Join(list.Builds, ",") != testBuild {
		t.Fatalf("list answered %v", list.Builds)
	}
	f.startOK("bbbbbbbbbbbb", KindBuild)
	if flagValue(f.sd.runs[1], "--uid") == uid {
		t.Fatal("a new build was given the user of one still running")
	}
}

func TestAStartThatSystemdRefusesLeavesNoChroot(t *testing.T) {
	f := newFixture(t)
	f.makeBuild(testBuild)
	f.sd.runErr = os.ErrPermission
	mustRefuse(t, f.start(testBuild), CodeSystemd)
	if _, err := os.Lstat(filepath.Dir(f.chroot(testBuild))); err == nil {
		t.Fatal("the chroot was left behind")
	}
	f.sd.runErr = nil
	mustOK(t, f.start(testBuild))
}

func TestARestartedBuildKeepsItsDiskAfterStop(t *testing.T) {
	f := newFixture(t)
	f.startOK(testBuild, KindBuild)
	mustOK(t, f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStop, Build: testBuild}))
	// The disk now belongs to the first build user; a start after a stop must still accept it.
	f.chowns = nil
	mustOK(t, f.start(testBuild))
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

// proves AC-1337-02
func TestStartWritesACPUTemplateThatClearsVMXAndSVMWhateverTheRequestHolds(t *testing.T) {
	for _, kind := range []string{KindBuild, KindCheck} {
		f := newFixture(t)
		dir := f.makeBuild(testBuild)
		// A runner that sends its own cpu-config, or a template under another key, changes nothing.
		vm := `{"machine-config":{"vcpu_count":2,"mem_size_mib":2048,"smt":false},"boot-source":{"boot_args":"pci=off"},` +
			`"cpu-config":{"cpuid_modifiers":[{"leaf":"0x1","subleaf":"0x0","flags":0,"modifiers":[{"register":"ecx","bitmap":"0b11111111111111111111111111111111"}]}]}}`
		writeFile(t, filepath.Join(dir, "vm.json"), vm, 0o600)
		mustOK(t, f.h.Handle(f.cfg.RunnerUID, Request{V: ProtocolVersion, Op: OpStart, Build: testBuild, Kind: kind}))
		data, err := os.ReadFile(filepath.Join(f.chroot(testBuild), "vm.json"))
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			CPU struct {
				Modifiers []struct {
					Leaf      string `json:"leaf"`
					Subleaf   string `json:"subleaf"`
					Modifiers []struct {
						Register string `json:"register"`
						Bitmap   string `json:"bitmap"`
					} `json:"modifiers"`
				} `json:"cpuid_modifiers"`
			} `json:"cpu-config"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		var cleared []string
		for _, entry := range cfg.CPU.Modifiers {
			for _, m := range entry.Modifiers {
				digits := strings.TrimPrefix(m.Bitmap, "0b")
				if len(digits) != 32 {
					t.Fatalf("%s: bitmap %q is not 32 bits", kind, m.Bitmap)
				}
				for i, c := range digits {
					switch c {
					case '0':
						cleared = append(cleared, fmt.Sprintf("%s/%s %s bit %d", entry.Leaf, entry.Subleaf, m.Register, 31-i))
					case 'x':
					default:
						t.Fatalf("%s: bitmap %q sets a bit", kind, m.Bitmap)
					}
				}
			}
		}
		sort.Strings(cleared)
		if strings.Join(cleared, ",") != "0x1/0x0 ecx bit 5,0x80000001/0x0 ecx bit 2" {
			t.Fatalf("%s: the template clears %v", kind, cleared)
		}
	}
}

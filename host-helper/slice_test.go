// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSliceCgroupPathFollowsSystemdsDashNesting(t *testing.T) {
	cases := map[string]string{
		"system.slice":                   "system.slice",
		"builds.slice":                   "builds.slice",
		"outerlayer-runner-builds.slice": "outerlayer.slice/outerlayer-runner.slice/outerlayer-runner-builds.slice",
		"a-b.slice":                      "a.slice/a-b.slice",
	}
	for slice, want := range cases {
		if got := sliceCgroupPath(slice); got != want {
			t.Errorf("sliceCgroupPath(%q) = %q, want %q", slice, got, want)
		}
	}
}

func TestBuildsStartInTheConfiguredSlice(t *testing.T) {
	f := newFixture(t)
	f.cfg.Slice = "outerlayer-runner-builds.slice"
	argv := startArgv(f.cfg, testBuild, 1000, 512, 30)
	if got := flagValue(argv, "--slice"); got != "outerlayer-runner-builds.slice" {
		t.Fatalf("systemd-run is given the slice %q: %v", got, argv)
	}
	want := "outerlayer.slice/outerlayer-runner.slice/outerlayer-runner-builds.slice/outerlayer-build-" + testBuild + ".service"
	if got := flagValue(argv, "--parent-cgroup"); got != want {
		t.Fatalf("the jailer is given the parent cgroup %q, want %q", got, want)
	}
}

func TestBuildsStartInSystemSliceWhenNoSliceIsConfigured(t *testing.T) {
	f := newFixture(t)
	f.cfg.Slice = ""
	argv := startArgv(f.cfg, testBuild, 1000, 512, 30)
	if got := flagValue(argv, "--slice"); got != "system.slice" {
		t.Fatalf("systemd-run is given the slice %q: %v", got, argv)
	}
	if got := flagValue(argv, "--parent-cgroup"); got != "system.slice/outerlayer-build-"+testBuild+".service" {
		t.Fatalf("the jailer is given the parent cgroup %q", got)
	}
}

func TestOOMKillsAreReadFromTheConfiguredSlicesCgroup(t *testing.T) {
	real, _ := fakeSystemctl(t, "success")
	real.slice = "outerlayer-runner-builds.slice"
	cg := filepath.Join(real.cgroupRoot, "outerlayer.slice", "outerlayer-runner.slice", "outerlayer-runner-builds.slice", UnitName(testBuild)+".service")
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cg, "memory.events"), []byte("oom 2\noom_kill 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kills, err := real.OOMKills(UnitName(testBuild))
	if err != nil || kills != 2 {
		t.Fatalf("want 2 kills, got %d, %v", kills, err)
	}
}

func TestLoadConfigReadsTheSliceOfTheBuilds(t *testing.T) {
	f := newFixture(t)
	f.cfg.Slice = "outerlayer-runner-builds.slice"
	path := writeConfig(t, t.TempDir(), f.cfg, 0o644)
	got, err := LoadConfig(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if got.Slice != "outerlayer-runner-builds.slice" {
		t.Fatalf("slice %q", got.Slice)
	}
}

func TestLoadConfigRefusesASliceThatIsNotASliceUnitName(t *testing.T) {
	for _, slice := range []string{"builds", "builds.service", "../x.slice", "a/b.slice", "-.slice", "a--b.slice", "a-.slice", "a b.slice", "-a.slice", "-a-b.slice", strings.Repeat("a", 300) + ".slice"} {
		f := newFixture(t)
		f.cfg.Slice = slice
		path := writeConfig(t, t.TempDir(), f.cfg, 0o644)
		if _, err := LoadConfig(path, os.Getuid()); err == nil {
			t.Errorf("the slice %q was accepted", slice)
		}
	}
}

func TestServeGivesTheConfiguredSliceToTheSystemdClient(t *testing.T) {
	f := newFixture(t)
	f.cfg.Slice = "outerlayer-runner-builds.slice"
	path := writeConfig(t, t.TempDir(), f.cfg, 0o644)
	original, originalUID := newSystemd, serveTrustedUID
	serveTrustedUID = os.Getuid()
	t.Cleanup(func() { newSystemd, serveTrustedUID = original, originalUID })
	var got []string
	stop := errors.New("stop before listening")
	newSystemd = func(slice string) (Systemd, error) {
		got = append(got, slice)
		return nil, stop
	}
	if err := serve(path); !errors.Is(err, stop) {
		t.Fatalf("serve returned %v, want the error from the systemd client", err)
	}
	if len(got) != 1 || got[0] != "outerlayer-runner-builds.slice" {
		t.Fatalf("serve gave the systemd client the slices %q", got)
	}
}

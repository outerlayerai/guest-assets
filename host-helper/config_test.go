// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, dir string, cfg Config, mode os.FileMode) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "helper.json")
	writeFile(t, path, string(data), mode)
	return path
}

func TestLoadConfigReadsAFileThatOnlyTheTrustedUserCanWrite(t *testing.T) {
	f := newFixture(t)
	path := writeConfig(t, t.TempDir(), f.cfg, 0o644)
	got, err := LoadConfig(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if got.BuildsRoot != f.cfg.BuildsRoot || got.Firecracker.SHA256 != f.cfg.Firecracker.SHA256 || got.UIDCount != 4 {
		t.Fatalf("config %+v", got)
	}
}

func TestLoadConfigRefusesAFileAGroupOrOtherCanWrite(t *testing.T) {
	f := newFixture(t)
	path := writeConfig(t, t.TempDir(), f.cfg, 0o664)
	if _, err := LoadConfig(path, os.Getuid()); err == nil {
		t.Fatal("a group-writable config was accepted")
	}
}

func TestLoadConfigRefusesAFileTheTrustedUserDoesNotOwn(t *testing.T) {
	f := newFixture(t)
	path := writeConfig(t, t.TempDir(), f.cfg, 0o644)
	if _, err := LoadConfig(path, os.Getuid()+1); err == nil {
		t.Fatal("a config owned by another user was accepted")
	}
}

func TestLoadConfigRefusesADirectoryAGroupOrOtherCanWrite(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	path := writeConfig(t, dir, f.cfg, 0o644)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path, os.Getuid()); err == nil {
		t.Fatal("a config in a world-writable directory was accepted")
	}
}

func TestLoadConfigRefusesAConfigWithoutAUserRange(t *testing.T) {
	f := newFixture(t)
	f.cfg.UIDCount = 0
	path := writeConfig(t, t.TempDir(), f.cfg, 0o644)
	if _, err := LoadConfig(path, os.Getuid()); err == nil {
		t.Fatal("an empty user range was accepted")
	}
}

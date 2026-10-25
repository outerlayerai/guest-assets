// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

// Binary is a file the helper runs, and the SHA-256 it must have.
type Binary struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Config is the root-owned file the installer writes. Everything a request
// cannot name comes from here.
type Config struct {
	RunnerUID          int    `json:"runnerUid"`
	RunnerGID          int    `json:"runnerGid"`
	BuildsRoot         string `json:"buildsRoot"`
	JailBase           string `json:"jailBase"`
	StateDir           string `json:"stateDir"`
	Socket             string `json:"socket"`
	UIDBase            int    `json:"uidBase"`
	UIDCount           int    `json:"uidCount"`
	Jailer             Binary `json:"jailer"`
	Firecracker        Binary `json:"firecracker"`
	FirecrackerVersion string `json:"firecrackerVersion"`
	// Slice is the systemd slice that holds every build of this runner, such as "acme-runner-builds.slice". Empty
	// means system.slice. The installer writes the slice unit with the memory and CPU limits of all the builds together.
	Slice string `json:"slice"`
}

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// slicePattern matches a slice unit name: dash-separated parts of letters, digits, ":", "_" and ".", then ".slice". A
// dash nests a slice under the slice named by the parts before it, so a part may not be empty.
var slicePattern = regexp.MustCompile(`^[A-Za-z0-9:_.]+(-[A-Za-z0-9:_.]+)*\.slice$`)

// maxSliceName is systemd's limit on a unit name.
const maxSliceName = 255

// maxUID keeps every build user below 2^31, because some tools read an id as a signed 32-bit number.
const maxUID = 2_147_483_647

// Validate checks the values a request cannot change.
func (c Config) Validate() error {
	for name, path := range map[string]string{
		"buildsRoot": c.BuildsRoot, "jailBase": c.JailBase, "stateDir": c.StateDir, "socket": c.Socket,
		"jailer.path": c.Jailer.Path, "firecracker.path": c.Firecracker.Path,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%s must be a clean absolute path, got %q", name, path)
		}
	}
	for name, sum := range map[string]string{"jailer.sha256": c.Jailer.SHA256, "firecracker.sha256": c.Firecracker.SHA256} {
		if !sha256Pattern.MatchString(sum) {
			return fmt.Errorf("%s must be 64 lower-case hex digits", name)
		}
	}
	if c.Slice != "" && (len(c.Slice) > maxSliceName || !slicePattern.MatchString(c.Slice)) {
		return fmt.Errorf("slice %q is not the name of a slice unit", c.Slice)
	}
	if c.UIDCount < 1 || c.UIDBase < 1 || c.UIDBase+c.UIDCount > maxUID {
		return fmt.Errorf("the build user range %d+%d is empty or out of bounds", c.UIDBase, c.UIDCount)
	}
	if c.RunnerUID >= c.UIDBase && c.RunnerUID < c.UIDBase+c.UIDCount {
		return errors.New("the runner's account is inside the build user range")
	}
	if c.RunnerGID >= c.UIDBase && c.RunnerGID < c.UIDBase+c.UIDCount {
		return errors.New("the runner's group is inside the build user range")
	}
	return nil
}

// checkOwnedAndClosed refuses a file or directory that trustedUID does not own or that a group or other can write.
func checkOwnedAndClosed(path string, trustedUID int, wantDir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if wantDir != info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not the kind of file expected", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != trustedUID {
		return fmt.Errorf("%s is not owned by user %d", path, trustedUID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by a group or by others", path)
	}
	return nil
}

// LoadConfig reads the config at path. It refuses a file, or a directory
// above it, that trustedUID does not own or that a group or other can write.
func LoadConfig(path string, trustedUID int) (Config, error) {
	if err := checkOwnedAndClosed(path, trustedUID, false); err != nil {
		return Config{}, err
	}
	if err := checkOwnedAndClosed(filepath.Dir(path), trustedUID, true); err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// Firecracker exits when an x86 guest resets its CPU, and keeps running when the
// guest powers off, so a guest that powered off would leave its microVM running.
func TestGuestEndsItsMicroVMByWritingItsDisksOutThenRestarting(t *testing.T) {
	var calls []string
	var commands []int
	endMicroVM(
		func() { calls = append(calls, "sync") },
		func(cmd int) error {
			calls = append(calls, "reboot")
			commands = append(commands, cmd)
			return nil
		},
	)
	if !slices.Equal(calls, []string{"sync", "reboot"}) {
		t.Fatalf("calls = %v, want sync then reboot", calls)
	}
	if !slices.Equal(commands, []int{unix.LINUX_REBOOT_CMD_RESTART}) {
		t.Fatalf("reboot commands = %#x, want only LINUX_REBOOT_CMD_RESTART (%#x)", commands, unix.LINUX_REBOOT_CMD_RESTART)
	}
}

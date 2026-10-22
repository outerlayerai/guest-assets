// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

// The device's route and rule keep traffic that Docker forwards from a bridge off the device: only a program on this
// machine, whose packets enter routing through the loopback interface, selects the device's table.
func TestTheRuleSelectsTheDeviceTableOnlyForLocalTraffic(t *testing.T) {
	rule := tunRule()
	if rule.IifName != "lo" || rule.Table != routeTable || rule.Priority != rulePriority {
		t.Fatalf("rule %+v", rule)
	}
	if rulePriority <= 32766 {
		t.Fatalf("priority %d does not come after the main table", rulePriority)
	}
}

func TestTheRouteIsADefaultRouteInItsOwnTable(t *testing.T) {
	route := tunRoute(7)
	if route.LinkIndex != 7 || route.Table != routeTable || route.Scope != netlink.SCOPE_LINK {
		t.Fatalf("route %+v", route)
	}
	ones, bits := route.Dst.Mask.Size()
	if ones != 0 || bits != 32 || !route.Dst.IP.Equal(net.IPv4zero) {
		t.Fatalf("destination %v", route.Dst)
	}
}

func TestTheDeviceHasOneHostAddressAndNoConnectedRoute(t *testing.T) {
	addr := tunAddr()
	ones, bits := addr.Mask.Size()
	if !addr.IP.Equal(net.IPv4(198, 18, 0, 1)) || ones != 32 || bits != 32 {
		t.Fatalf("address %v", addr)
	}
	if tunMTU != 1500 {
		t.Fatalf("MTU %d", tunMTU)
	}
}

func TestTheDeviceHasNoIPv6AndNoReversePathFilter(t *testing.T) {
	got := tunSysctls("tun7")
	want := [][2]string{
		{"/proc/sys/net/ipv6/conf/tun7/disable_ipv6", "1"},
		{"/proc/sys/net/ipv4/conf/tun7/rp_filter", "0"},
	}
	if len(got) != len(want) {
		t.Fatalf("settings %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("setting %d is %v, want %v", i, got[i], want[i])
		}
	}
}

func TestNetFlagDefaults(t *testing.T) {
	cfg, status := parseNetFlags(nil)
	if status != 0 {
		t.Fatalf("status %d", status)
	}
	want := netConfig{tun: "tun0", dns: "127.0.0.53:53", ready: defaultReady, hosts: "/etc/hosts", tunnelPort: 3128}
	if cfg != want {
		t.Fatalf("got %+v", cfg)
	}
	if defaultReady != "/run/outerlayer-net.ready" {
		t.Fatalf("ready file %s", defaultReady)
	}
}

func TestNetFlagsTakeAValidPortOnly(t *testing.T) {
	cfg, status := parseNetFlags([]string{"--tunnel-port", "65535", "--tun", "x", "--ready", "/r", "--hosts", "/h", "--dns", "1.2.3.4:5"})
	if status != 0 || cfg != (netConfig{tun: "x", dns: "1.2.3.4:5", ready: "/r", hosts: "/h", tunnelPort: 65535}) {
		t.Fatalf("got %+v, %d", cfg, status)
	}
	for _, port := range []string{"0", "65536", "-1", "x"} {
		if _, status := parseNetFlags([]string{"--tunnel-port", port}); status != 2 {
			t.Errorf("port %q gave status %d", port, status)
		}
	}
	if _, status := parseNetFlags([]string{"--nope"}); status != 2 {
		t.Errorf("an unknown flag gave status %d", status)
	}
}

func TestTheReadyFileAppearsWholeAndLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ready")
	if err := writeReady(path); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "ready\n" {
		t.Fatalf("read %q, %v", data, err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("the temporary file remains: %v", err)
	}
	if err := writeReady(filepath.Join(dir, "missing", "ready")); err == nil {
		t.Fatal("a write into a missing directory succeeded")
	}
}

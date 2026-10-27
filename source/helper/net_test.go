// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestNetFlagsTakeARelayAddressAndTheDropOption(t *testing.T) {
	cfg, status := parseNetFlags([]string{"--relay", "127.0.0.1:3128", "--drop-privileges"})
	if status != 0 {
		t.Fatalf("status %d", status)
	}
	if cfg.relay != "127.0.0.1:3128" || !cfg.dropPrivileges {
		t.Fatalf("got %+v", cfg)
	}
	for _, relay := range []string{"127.0.0.1", "127.0.0.1:", ":"} {
		if _, status := parseNetFlags([]string{"--relay", relay}); status != 2 {
			t.Errorf("relay %q gave status %d", relay, status)
		}
	}
}

// A container's /proc/sys is read-only. The runner sets the device's settings when it starts the container, so the
// helper must not write a setting that already has its value, and still writes one that does not.
func TestOnlyASettingWithAnotherValueIsWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rp_filter")
	if err := os.WriteFile(path, []byte("0\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := writeSysctl(path, "0"); err != nil {
		t.Fatalf("a setting that already had its value was written: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSysctl(path, "1"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "1" {
		t.Fatalf("the setting is %q, want 1", got)
	}
}

// Beside a container build, a program's connection to a name reaches the build's relay over TCP as the request the
// tunnel reads, and the helper opens no vsock connection.
// proves AC-1754-12
func TestAProgramsConnectionToANameReachesTheRelayAsAConnectRequest(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	saved := dialTunnel
	defer func() { dialTunnel = saved }()
	dialTunnel = func(port uint32) (net.Conn, error) {
		t.Errorf("the stack dialled vsock port %d", port)
		return nil, os.ErrInvalid
	}
	cfg, status := parseNetFlags([]string{"--relay", listener.Addr().String()})
	if status != 0 {
		t.Fatalf("status %d", status)
	}
	r := newRigWith(t, tunnelDialer(cfg))
	addr := r.assign("repo.maven.apache.org")
	go func() {
		if c, err := r.dial(addr, 443); err == nil {
			c.Close()
		}
	}()

	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	far, err := listener.Accept()
	if err != nil {
		t.Fatalf("the relay accepted no connection: %v", err)
	}
	defer far.Close()
	_ = far.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(far)
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the request: %v (%q)", err, head.String())
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	if want := "CONNECT repo.maven.apache.org:443 HTTP/1.1\r\nHost: repo.maven.apache.org:443\r\n\r\n"; head.String() != want {
		t.Fatalf("the relay received %q, want %q", head.String(), want)
	}
}

// Without a relay address, the stack still reaches the tunnel over vsock, at the port the flags name.
func TestWithoutARelayTheStackDialsVsockAtTheTunnelPort(t *testing.T) {
	saved := dialTunnel
	defer func() { dialTunnel = saved }()
	var dialled []uint32
	dialTunnel = func(port uint32) (net.Conn, error) {
		dialled = append(dialled, port)
		return nil, os.ErrInvalid
	}
	cfg, _ := parseNetFlags([]string{"--tunnel-port", "4000"})
	if _, err := tunnelDialer(cfg)(); err == nil {
		t.Fatal("the fake vsock dial did not fail")
	}
	if len(dialled) != 1 || dialled[0] != 4000 {
		t.Fatalf("dialled %v, want [4000]", dialled)
	}
}

// After dropping its privileges, the process holds no capability in any set it can use.
func TestDroppingPrivilegesLeavesNoCapability(t *testing.T) {
	if err := dropCapabilities(); err != nil {
		t.Fatalf("drop: %v", err)
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("no /proc/self/status: %v", err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		for _, set := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"} {
			if strings.HasPrefix(line, set) && strings.TrimSpace(strings.TrimPrefix(line, set)) != "0000000000000000" {
				t.Errorf("%s", line)
			}
		}
	}
}

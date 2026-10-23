// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
)

const (
	// tunAddress is the TUN device's own address. It is a host address with no connected route, so the only route
	// that reaches the device is the one in routeTable.
	tunAddress = "198.18.0.1/32"
	tunMTU     = 1500
	// routeTable holds the default route through the TUN device. Only a rule for locally generated traffic selects
	// it, so a packet that Docker forwards from a bridge finds no route and goes nowhere.
	routeTable = 100
	// rulePriority is after the main table (32766), so the loopback and bridge routes there win.
	rulePriority = 32767
	defaultReady = "/run/outerlayer-net.ready"
)

// dialTunnel opens a connection to the runner's tunnel. The host links the vsock port to the tunnel's socket.
var dialTunnel = dialHost

func writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o644)
}

// tunSysctls lists the kernel settings the device needs, as path and value. IPv6 stays off because the stack has no
// IPv6, and a link-local address would let the kernel start neighbour discovery. The reverse path filter stays off
// because replies come back from addresses the route table does not list.
func tunSysctls(name string) [][2]string {
	return [][2]string{
		{filepath.Join("/proc/sys/net/ipv6/conf", name, "disable_ipv6"), "1"},
		{filepath.Join("/proc/sys/net/ipv4/conf", name, "rp_filter"), "0"},
	}
}

// tunAddr is the device's own address.
func tunAddr() *netlink.Addr {
	prefix := netip.MustParsePrefix(tunAddress)
	return &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), 32)}}
}

// tunRoute is the default route through the device, in its own table.
func tunRoute(linkIndex int) *netlink.Route {
	return &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Scope:     netlink.SCOPE_LINK,
		Table:     routeTable,
	}
}

// tunRule selects the device's table for traffic that a local program generates. Traffic that arrives on another
// interface, such as a Docker bridge, never matches.
func tunRule() *netlink.Rule {
	rule := netlink.NewRule()
	rule.IifName = "lo"
	rule.Table = routeTable
	rule.Priority = rulePriority
	return rule
}

// setupTunDevice gives the device its address, brings it up and routes the guest's own traffic through it.
func setupTunDevice(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find %s: %w", name, err)
	}
	for _, setting := range tunSysctls(name) {
		if err := writeSysctl(setting[0], setting[1]); err != nil {
			return fmt.Errorf("set %s: %w", setting[0], err)
		}
	}
	if err := netlink.LinkSetMTU(link, tunMTU); err != nil {
		return fmt.Errorf("set the MTU of %s: %w", name, err)
	}
	if err := netlink.AddrAdd(link, tunAddr()); err != nil {
		return fmt.Errorf("add %s to %s: %w", tunAddress, name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring %s up: %w", name, err)
	}
	if err := netlink.RouteAdd(tunRoute(link.Attrs().Index)); err != nil {
		return fmt.Errorf("add the default route through %s: %w", name, err)
	}
	if err := netlink.RuleAdd(tunRule()); err != nil {
		return fmt.Errorf("add the rule for local traffic: %w", err)
	}
	return nil
}

// netConfig holds the options of the net command.
type netConfig struct {
	tun, dns, ready, hosts string
	tunnelPort             uint32
}

// parseNetFlags reads the options of the net command. The second result is 0 for a good command line and otherwise
// the exit status.
func parseNetFlags(args []string) (netConfig, int) {
	fs := flag.NewFlagSet("net", flag.ContinueOnError)
	tunName := fs.String("tun", "tun0", "name of the TUN device to create")
	dnsAddr := fs.String("dns", "127.0.0.53:53", "address of the DNS server")
	tunnelPort := fs.Uint("tunnel-port", 3128, "vsock port of the runner's tunnel")
	ready := fs.String("ready", defaultReady, "file to create once the route and the DNS server are up")
	hosts := fs.String("hosts", "/etc/hosts", "hosts file whose names keep their own address")
	if err := fs.Parse(args); err != nil {
		return netConfig{}, 2
	}
	if *tunnelPort == 0 || *tunnelPort > 65535 {
		fmt.Fprintln(os.Stderr, "net: --tunnel-port must be a port")
		return netConfig{}, 2
	}
	return netConfig{tun: *tunName, dns: *dnsAddr, ready: *ready, hosts: *hosts, tunnelPort: uint32(*tunnelPort)}, 0
}

// writeReady creates the ready file in one step, so a reader never finds it half written.
func writeReady(path string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("ready\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func runNet(args []string) int {
	cfg, status := parseNetFlags(args)
	if status != 0 {
		return status
	}
	tunName, dnsAddr, hosts := &cfg.tun, &cfg.dns, &cfg.hosts
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "net: "+format+"\n", a...)
		return 1
	}

	names := newNameMap(loadLocalNames(*hosts), 0)
	pc, err := net.ListenPacket("udp4", *dnsAddr)
	if err != nil {
		return fail("listen on udp %s: %v", *dnsAddr, err)
	}
	tl, err := net.Listen("tcp4", *dnsAddr)
	if err != nil {
		return fail("listen on tcp %s: %v", *dnsAddr, err)
	}

	fd, err := tun.Open(*tunName)
	if err != nil {
		return fail("open %s: %v", *tunName, err)
	}
	closed := make(chan struct{})
	var closeOnce sync.Once
	link, err := fdbased.New(&fdbased.Options{
		FDs:        []int{fd},
		MTU:        tunMTU,
		ClosedFunc: func(tcpip.Error) { closeOnce.Do(func() { close(closed) }) },
	})
	if err != nil {
		return fail("attach to %s: %v", *tunName, err)
	}
	port := cfg.tunnelPort
	ns, err := newNetStack(link, names, func() (net.Conn, error) { return dialTunnel(port) })
	if err != nil {
		return fail("%v", err)
	}
	if err := setupTunDevice(*tunName); err != nil {
		return fail("%v", err)
	}
	go serveDNSUDP(pc, names)
	go serveDNSTCP(tl, names)

	// The file appears only after the route and the name server work, so a build step never starts without them.
	if err := writeReady(cfg.ready); err != nil {
		return fail("%v", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-stop:
		fmt.Fprintf(os.Stderr, "net: stopping; %d packets that were not TCP over IPv4 were dropped\n", ns.Dropped())
		return 0
	case <-closed:
		return fail("%s was closed", *tunName)
	}
}

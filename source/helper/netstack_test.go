// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// rig joins the helper's stack to a second stack that plays the guest kernel: a program in the guest dials
// through the second stack, and the packets cross a pair of channel endpoints as they cross a TUN device.
type rig struct {
	t      *testing.T
	ns     *netStack
	client *stack.Stack
	names  *nameMap
	dials  atomic.Int32
	// closed counts the Close calls on the helper's end of its tunnel connections.
	closed atomic.Int32
	// tunnel receives the far end of each connection the helper opens to the tunnel.
	tunnel chan net.Conn
	// near receives the helper's end of each connection to the tunnel.
	near chan net.Conn
}

// closeCounter counts the Close calls on a connection.
type closeCounter struct {
	net.Conn
	n *atomic.Int32
}

func (c *closeCounter) Close() error { c.n.Add(1); return c.Conn.Close() }

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, names: newNameMap(nil, 0), tunnel: make(chan net.Conn, 16), near: make(chan net.Conn, 16)}
	serverEP := channel.New(256, 1500, "")
	clientEP := channel.New(256, 1500, "")
	ns, err := newNetStack(serverEP, r.names, func() (net.Conn, error) {
		r.dials.Add(1)
		near, far := net.Pipe()
		r.tunnel <- far
		r.near <- near
		return &closeCounter{Conn: near, n: &r.closed}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r.ns = ns
	t.Cleanup(ns.Close)

	r.client = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if e := r.client.CreateNIC(1, clientEP); e != nil {
		t.Fatal(e)
	}
	addr := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}), PrefixLen: 32}
	if e := r.client.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr}, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	r.client.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pump := func(from, to *channel.Endpoint) {
		for {
			pkt := from.ReadContext(ctx)
			if pkt == nil {
				return
			}
			buf := pkt.ToBuffer()
			to.InjectInbound(pkt.NetworkProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buf}))
			pkt.DecRef()
		}
	}
	go pump(serverEP, clientEP)
	go pump(clientEP, serverEP)
	return r
}

func (r *rig) dial(addr string, port uint16) (*gonet.TCPConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a := netip.MustParseAddr(addr).As4()
	return gonet.DialContextTCP(ctx, r.client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(a), Port: port}, ipv4.ProtocolNumber)
}

func (r *rig) assign(name string) string {
	r.t.Helper()
	addr, err := r.names.assign(name)
	if err != nil {
		r.t.Fatal(err)
	}
	return addr.String()
}

// nextTunnel returns the tunnel's end of the next connection, with the request line and headers it received.
func (r *rig) nextTunnel() (net.Conn, *bufio.Reader, string) {
	r.t.Helper()
	select {
	case far := <-r.tunnel:
		_ = far.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(far)
		var head strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				r.t.Fatalf("reading the CONNECT request: %v (%q)", err, head.String())
			}
			head.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		return far, br, head.String()
	case <-time.After(5 * time.Second):
		r.t.Fatal("the helper opened no connection to the tunnel")
		return nil, nil, ""
	}
}

// waitClosed waits until the helper has closed its end of n tunnel connections.
func (r *rig) waitClosed(n int32) {
	r.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for r.closed.Load() < n {
		if time.Now().After(deadline) {
			r.t.Fatalf("the helper closed %d tunnel connections, want %d", r.closed.Load(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// proves AC-1533-08
func TestStackMapsAddressToName(t *testing.T) {
	r := newRig(t)
	addr := r.assign("api.example.org")

	type result struct {
		conn *gonet.TCPConn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := r.dial(addr, 443)
		done <- result{c, err}
	}()
	far, br, head := r.nextTunnel()
	defer far.Close()
	if want := "CONNECT api.example.org:443 HTTP/1.1\r\nHost: api.example.org:443\r\n\r\n"; head != want {
		t.Fatalf("the tunnel received %q, want %q", head, want)
	}
	// The program's handshake does not finish before the tunnel answers.
	select {
	case res := <-done:
		t.Fatalf("the connection completed before the tunnel answered: %v", res.err)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := far.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\nSSH-2.0-test\r\n")); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("dial: %v", res.err)
	}
	defer res.conn.Close()

	// Bytes the tunnel sent after its headers reach the program first.
	_ = res.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(res.conn).ReadString('\n')
	if err != nil || line != "SSH-2.0-test\r\n" {
		t.Fatalf("read %q, %v", line, err)
	}
	if _, err := res.conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "hello" {
		t.Fatalf("the tunnel read %q, %v", got, err)
	}
}

func TestStackSendsALiteralAddressAsTheLiteral(t *testing.T) {
	r := newRig(t)
	go func() { _, _ = r.dial("1.1.1.1", 22) }()
	far, _, head := r.nextTunnel()
	defer far.Close()
	if want := "CONNECT 1.1.1.1:22 HTTP/1.1\r\nHost: 1.1.1.1:22\r\n\r\n"; head != want {
		t.Fatalf("the tunnel received %q, want %q", head, want)
	}
}

func TestStackSendsASyntheticAddressItNeverHandedOutAsTheLiteral(t *testing.T) {
	r := newRig(t)
	go func() { _, _ = r.dial("198.19.7.7", 443) }()
	far, _, head := r.nextTunnel()
	defer far.Close()
	if !strings.HasPrefix(head, "CONNECT 198.19.7.7:443 HTTP/1.1\r\n") {
		t.Fatalf("the tunnel received %q", head)
	}
}

func TestStackResetsAConnectionTheTunnelRefuses(t *testing.T) {
	r := newRig(t)
	addr := r.assign("blocked.example.org")
	errc := make(chan error, 1)
	go func() {
		_, err := r.dial(addr, 443)
		errc <- err
	}()
	far, _, _ := r.nextTunnel()
	defer far.Close()
	if _, err := far.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("want a refused connection, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the program's connection was not reset")
	}
	r.waitClosed(1)
}

func TestStackResetsAConnectionWhenTheTunnelIsUnreachable(t *testing.T) {
	r := newRig(t)
	addr := r.assign("down.example.org")
	go func() {
		far := <-r.tunnel
		far.Close()
	}()
	errc := make(chan error, 1)
	go func() {
		_, err := r.dial(addr, 443)
		errc <- err
	}()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("the connection succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the program's connection was not reset")
	}
	r.waitClosed(1)
}

// proves AC-1533-07
func TestStackDropsUDPAndOpensNoConnection(t *testing.T) {
	r := newRig(t)
	raddr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), Port: 53}
	laddr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}), Port: 40000}
	conn, err := gonet.DialUDP(r.client, &laddr, &raddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := buildQuery(t, "example.org.", dnsmessage.TypeA)
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if n, err := conn.Read(make([]byte, 512)); err == nil {
		t.Fatalf("got a %d byte reply", n)
	}
	if r.dials.Load() != 0 {
		t.Fatalf("the helper opened %d connections to the tunnel", r.dials.Load())
	}
	if r.ns.Dropped() == 0 {
		t.Fatal("the filter counted no dropped packet")
	}
}

func TestOnlyTCPOverIPv4ReachesTheStack(t *testing.T) {
	build := func(proto tcpip.TransportProtocolNumber) *stack.PacketBuffer {
		ip := header.IPv4(make([]byte, header.IPv4MinimumSize+8))
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(ip)), TTL: 64, Protocol: uint8(proto), SrcAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}), DstAddr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1})})
		return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(ip)})
	}
	cases := []struct {
		name  string
		proto tcpip.TransportProtocolNumber
		want  bool
	}{{"tcp", tcp.ProtocolNumber, true}, {"udp", udp.ProtocolNumber, false}, {"icmp", header.ICMPv4ProtocolNumber, false}, {"sctp", 132, false}}
	for _, c := range cases {
		if got := carriesTCP(ipv4.ProtocolNumber, build(c.proto)); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	if carriesTCP(header.IPv6ProtocolNumber, build(tcp.ProtocolNumber)) {
		t.Error("IPv6 reaches the stack")
	}
	// A header with no payload is a whole packet, and a shorter one is not.
	bare := header.IPv4(make([]byte, header.IPv4MinimumSize))
	bare.Encode(&header.IPv4Fields{TotalLength: header.IPv4MinimumSize, TTL: 64, Protocol: uint8(tcp.ProtocolNumber), SrcAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}), DstAddr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1})})
	if !carriesTCP(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bare)})) {
		t.Error("a TCP header with no payload was dropped")
	}
	if carriesTCP(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bare[:header.IPv4MinimumSize-1])})) {
		t.Error("a truncated header reached the stack")
	}
}

// A packet that is not TCP over IPv4 is counted once and goes no further.
func TestTheFilterCountsEachDroppedPacketOnce(t *testing.T) {
	r := newRig(t)
	ip := header.IPv4(make([]byte, header.IPv4MinimumSize+8))
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(ip)), TTL: 64, Protocol: uint8(udp.ProtocolNumber), SrcAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}), DstAddr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1})})
	before := r.ns.Dropped()
	r.ns.filter.DeliverNetworkPacket(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(ip)}))
	if got := r.ns.Dropped() - before; got != 1 {
		t.Fatalf("one dropped packet counted %d", got)
	}
}

func TestTheStackKeepsSACKAndSizesItsBuffers(t *testing.T) {
	r := newRig(t)
	var sack tcpip.TCPSACKEnabled
	if err := r.ns.s.TransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil || !bool(sack) {
		t.Errorf("SACK is %v, %v", sack, err)
	}
	var moderate tcpip.TCPModerateReceiveBufferOption
	if err := r.ns.s.TransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil || !bool(moderate) {
		t.Errorf("receive buffer moderation is %v, %v", moderate, err)
	}
	var receive tcpip.TCPReceiveBufferSizeRangeOption
	if err := r.ns.s.TransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil || receive.Max != 4<<20 {
		t.Errorf("receive buffer range is %+v, %v", receive, err)
	}
	var send tcpip.TCPSendBufferSizeRangeOption
	if err := r.ns.s.TransportProtocolOption(tcp.ProtocolNumber, &send); err != nil || send.Max != 4<<20 {
		t.Errorf("send buffer range is %+v, %v", send, err)
	}
}

func TestTheStackWaitsLongerForTheTunnelThanTheTunnelWaitsToConnect(t *testing.T) {
	if tunnelReplyTimeout <= tunnelConnectTimeout {
		t.Fatalf("the stack gives up after %v, before the tunnel's own %v connect limit, so the tunnel's refusal is never logged", tunnelReplyTimeout, tunnelConnectTimeout)
	}
}

func TestReadTunnelReply(t *testing.T) {
	cases := []struct {
		name, reply string
		status      int
		ok          bool
	}{
		{"ok", "HTTP/1.1 200 Connection Established\r\nA: b\r\n\r\n", 200, true},
		{"http 1.0", "HTTP/1.0 403 Forbidden\r\n\r\n", 403, true},
		{"headers cut off by EOF", "HTTP/1.1 200 OK\r\nA: b\r\n", 0, false},
		{"status line cut off by EOF", "HTTP/1.1 200 OK", 0, false},
		{"status line with no code", "HTTP/1.1\r\n\r\n", 0, false},
		{"a code that is not a number", "HTTP/1.1 abc OK\r\n\r\n", 0, false},
		{"another protocol version", "HTTP/2.0 200 OK\r\n\r\n", 0, false},
		{"not HTTP", "SSH-2.0-x\r\n\r\n", 0, false},
		{"many short headers", "HTTP/1.1 200 OK\r\n" + strings.Repeat("A: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n", 300) + "\r\n", 0, false},
		{"headers too long", "HTTP/1.1 200 OK\r\nA: " + strings.Repeat("x", tunnelReplyLimit) + "\r\n\r\n", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, err := readTunnelReply(bufio.NewReaderSize(strings.NewReader(c.reply), tunnelReplyLimit))
			if (err == nil) != c.ok || status != c.status {
				t.Fatalf("got %d, %v", status, err)
			}
		})
	}
}

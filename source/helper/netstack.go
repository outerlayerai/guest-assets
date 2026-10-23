// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// maxInFlightDials is the most connections that wait for the tunnel's answer at one time. A connection past it
	// is reset at once.
	maxInFlightDials = 1024
	// tunnelReplyLimit is the most bytes of reply headers the stack reads from the tunnel.
	tunnelReplyLimit = 8192
	// tunnelConnectTimeout is how long the tunnel itself waits to open a connection (CONNECT_TIMEOUT_MS in
	// tunnel.ts).
	tunnelConnectTimeout = 30 * time.Second
	// tunnelReplyTimeout is how long the stack waits for the tunnel's answer to a CONNECT request. It starts before
	// the tunnel resolves the name, so it must outlast the tunnel's own timeout: the tunnel then answers 502 and
	// logs the refusal before the stack gives up.
	tunnelReplyTimeout = tunnelConnectTimeout + 15*time.Second
	nicID              = 1
)

// nameLookup maps a synthetic address back to the name it was handed out for.
type nameLookup interface {
	nameFor(netip.Addr) (string, bool)
}

// dialFunc opens a connection to the runner's tunnel.
type dialFunc func() (net.Conn, error)

// netStack ends every TCP connection that reaches the TUN device and opens one connection to the tunnel for each.
// It has no other way out: UDP, ICMP and IPv6 are dropped before the stack sees them.
type netStack struct {
	s       *stack.Stack
	names   nameLookup
	dial    dialFunc
	gate    chan struct{}
	dropped atomic.Uint64
	filter  *tcpFilter
}

// tcpFilter passes only TCP over IPv4 to the stack. A stack that sees an ICMP echo request answers it for any
// address, which would make a ping succeed when no host was reached.
type tcpFilter struct {
	nested.Endpoint
	dropped *atomic.Uint64
}

func (f *tcpFilter) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if !carriesTCP(protocol, pkt) {
		f.dropped.Add(1)
		return
	}
	f.Endpoint.DeliverNetworkPacket(protocol, pkt)
}

// carriesTCP reports whether a packet is an IPv4 packet that holds TCP.
func carriesTCP(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) bool {
	if protocol != ipv4.ProtocolNumber {
		return false
	}
	h, ok := pkt.Data().PullUp(header.IPv4MinimumSize)
	if !ok {
		return false
	}
	return header.IPv4(h).TransportProtocol() == tcp.ProtocolNumber
}

func newNetStack(link stack.LinkEndpoint, names nameLookup, dial dialFunc) (*netStack, error) {
	ns := &netStack{names: names, dial: dial, gate: make(chan struct{}, maxInFlightDials)}
	ns.filter = &tcpFilter{dropped: &ns.dropped}
	ns.filter.Init(link, ns.filter)
	ns.s = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := ns.s.CreateNIC(nicID, ns.filter); err != nil {
		return nil, fmt.Errorf("create the NIC: %v", err)
	}
	// The stack answers for any address, whatever address the program connected to.
	if err := ns.s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %v", err)
	}
	if err := ns.s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %v", err)
	}
	ns.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	sack := tcpip.TCPSACKEnabled(true)
	if err := ns.s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("enable SACK: %v", err)
	}
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	if err := ns.s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		return nil, fmt.Errorf("moderate the receive buffer: %v", err)
	}
	receive := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 212 << 10, Max: 4 << 20}
	if err := ns.s.SetTransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		return nil, fmt.Errorf("size the receive buffer: %v", err)
	}
	send := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 212 << 10, Max: 4 << 20}
	if err := ns.s.SetTransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		return nil, fmt.Errorf("size the send buffer: %v", err)
	}
	forwarder := tcp.NewForwarder(ns.s, 0, 2*maxInFlightDials, ns.handle)
	ns.s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
	return ns, nil
}

// Close stops the stack.
func (ns *netStack) Close() {
	ns.s.Close()
	ns.s.Wait()
}

// Dropped is the number of packets that were not TCP over IPv4 and so never reached the stack.
func (ns *netStack) Dropped() uint64 { return ns.dropped.Load() }

// targetOf names where a program connected to: the name a synthetic address was handed out for, or else the address.
func (ns *netStack) targetOf(addr tcpip.Address, port uint16) (string, string) {
	a, ok := netip.AddrFromSlice(addr.AsSlice())
	if !ok {
		return "", ""
	}
	host := a.String()
	if syntheticPrefix.Contains(a) {
		if name, found := ns.names.nameFor(a); found {
			host = name
		}
	}
	return host, net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func (ns *netStack) handle(r *tcp.ForwarderRequest) {
	id := r.ID()
	host, hostPort := ns.targetOf(id.LocalAddress, id.LocalPort)
	if host == "" {
		r.Complete(true)
		return
	}
	select {
	case ns.gate <- struct{}{}:
	default:
		logf("too many connections wait for the tunnel; resetting %s", hostPort)
		r.Complete(true)
		return
	}
	go ns.forward(r, hostPort)
}

// forward asks the tunnel to connect and completes the program's handshake only when the tunnel agrees. On any
// other answer the program's connection is reset.
func (ns *netStack) forward(r *tcp.ForwarderRequest, hostPort string) {
	released := false
	release := func() {
		if !released {
			released = true
			<-ns.gate
		}
	}
	defer release()

	up, err := ns.dial()
	if err != nil {
		logf("cannot reach the tunnel for %s: %v", hostPort, err)
		r.Complete(true)
		return
	}
	_ = up.SetDeadline(time.Now().Add(tunnelReplyTimeout))
	if _, err := fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort); err != nil {
		logf("cannot send the request for %s to the tunnel: %v", hostPort, err)
		up.Close()
		r.Complete(true)
		return
	}
	br := bufio.NewReaderSize(up, tunnelReplyLimit)
	status, err := readTunnelReply(br)
	if err != nil || status != 200 {
		if err != nil {
			logf("no usable answer from the tunnel for %s: %v", hostPort, err)
		} else {
			logf("the tunnel refused %s with status %d", hostPort, status)
		}
		up.Close()
		r.Complete(true)
		return
	}
	_ = up.SetDeadline(time.Time{})
	release()

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		logf("cannot accept the connection to %s: %v", hostPort, tcpErr)
		up.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	proxy(&programConn{TCPConn: gonet.NewTCPConn(&wq, ep), ep: ep}, &bufferedConn{Conn: up, r: br})
}

// readTunnelReply reads the status line and headers of the tunnel's answer, and returns the status. Bytes after the
// headers stay in the reader.
func readTunnelReply(br *bufio.Reader) (int, error) {
	total := 0
	status := 0
	for first := true; ; first = false {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return 0, err
		}
		total += len(line)
		if total > tunnelReplyLimit {
			return 0, errors.New("the tunnel's reply headers are too long")
		}
		if first {
			fields := strings.Fields(string(line))
			if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/1.") {
				return 0, errors.New("the tunnel's reply is not an HTTP status line")
			}
			status, err = strconv.Atoi(fields[1])
			if err != nil {
				return 0, err
			}
			continue
		}
		if len(strings.TrimRight(string(line), "\r\n")) == 0 {
			return status, nil
		}
	}
}

// bufferedConn reads through the reader that already holds bytes the tunnel sent after its headers.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// programConn is the program's side of a connection. Abort ends it with a reset.
type programConn struct {
	*gonet.TCPConn
	ep tcpip.Endpoint
}

func (c *programConn) Abort() {
	// A close with a linger time of zero sends a reset and not a FIN.
	c.ep.SocketOptions().SetLinger(tcpip.LingerOption{Enabled: true, Timeout: 0})
	_ = c.TCPConn.Close()
}

const (
	// maxLogLines is the most lines the helper writes in one logWindow. The tunnel limits its own refusal lines the
	// same way, so a program that connects in a loop cannot fill the build log.
	maxLogLines = 10
	logWindow   = 10 * time.Second
)

// logLimiter lets a fixed number of lines through in each window and counts the rest.
type logLimiter struct {
	mu      sync.Mutex
	start   time.Time
	lines   int
	dropped int
}

// allow reports whether a line may be written at now. The second result is the number of lines dropped in the window
// that just ended, when this call starts a new one.
func (l *logLimiter) allow(now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	report := 0
	if l.start.IsZero() || now.Sub(l.start) >= logWindow {
		report = l.dropped
		l.start, l.lines, l.dropped = now, 0, 0
	}
	if l.lines >= maxLogLines {
		l.dropped++
		return false, report
	}
	l.lines++
	return true, report
}

var logGate logLimiter

// logf writes one line to the helper's standard error, which reaches the build log. Past maxLogLines in a window it
// drops lines, and the first line of the next window says how many.
func logf(format string, a ...any) { logGate.printf("net", format, a...) }

// printf writes one line that starts with prefix to the helper's standard error, when the limiter allows it.
func (l *logLimiter) printf(prefix, format string, a ...any) {
	ok, dropped := l.allow(time.Now())
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "%s: %d log lines were dropped in the last %d seconds\n", prefix, dropped, int(logWindow/time.Second))
	}
	if ok {
		fmt.Fprintf(os.Stderr, "%s: %s\n", prefix, fmt.Sprintf(format, a...))
	}
}

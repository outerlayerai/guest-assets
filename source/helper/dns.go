// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The DNS server never asks another server. It gives every name a fixed
// address in a range reserved for benchmarking, and the network stack maps the
// address back to the name when a program connects to it. The tunnel then
// resolves the name itself, so no query leaves the guest.

var (
	syntheticBase = netip.MustParseAddr("198.18.0.0")
	// syntheticSize is the number of addresses in 198.18.0.0/15.
	syntheticSize = 1 << 17
	// The first two addresses are the network address and the tunnel device's
	// own address, and the last is the broadcast address. None is handed out.
	syntheticReservedLow  = 2
	syntheticReservedHigh = 1
	syntheticPrefix       = netip.MustParsePrefix("198.18.0.0/15")
)

const (
	// answerTTL is how long a program may keep an answer. The map never changes an answer, so a day is safe.
	answerTTL = 24 * 60 * 60
	// maxNameLength is the longest name in text form, without the trailing dot.
	maxNameLength  = 253
	maxLabelLength = 63
	// retryPause is the wait after a failed read or accept, so a persistent fault cannot fill the log.
	retryPause = 100 * time.Millisecond
)

var (
	errBadName = errors.New("not a valid host name")
	errMapFull = errors.New("the synthetic address range is used up")
)

// nameMap holds the address handed out for each name.
type nameMap struct {
	mu     sync.Mutex
	byName map[string]netip.Addr
	byAddr map[netip.Addr]string
	local  map[string]netip.Addr
	next   int
	limit  int
	// fullLogged is set once the full map has been reported, so a program cannot flood the log.
	fullLogged atomic.Bool
}

// newNameMap makes an empty map. `local` names get their own address and never a synthetic one. A `limit` of 0
// means every address in the range that is not reserved.
func newNameMap(local map[string]netip.Addr, limit int) *nameMap {
	max := syntheticSize - syntheticReservedLow - syntheticReservedHigh
	if limit <= 0 || limit > max {
		limit = max
	}
	if local == nil {
		local = map[string]netip.Addr{}
	}
	return &nameMap{byName: map[string]netip.Addr{}, byAddr: map[netip.Addr]string{}, local: local, next: syntheticReservedLow, limit: limit}
}

// assign returns the address of a name, handing out the next free one the first time.
func (m *nameMap) assign(name string) (netip.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if addr, ok := m.byName[name]; ok {
		return addr, nil
	}
	if len(m.byName) >= m.limit {
		return netip.Addr{}, errMapFull
	}
	base := syntheticBase.As4()
	n := binary.BigEndian.Uint32(base[:]) + uint32(m.next)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	addr := netip.AddrFrom4(b)
	m.next++
	m.byName[name] = addr
	m.byAddr[addr] = name
	return addr, nil
}

// nameFor returns the name an address was handed out for.
func (m *nameMap) nameFor(addr netip.Addr) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name, ok := m.byAddr[addr]
	return name, ok
}

// normalizeName checks a name from a query and returns it in lower case, without its trailing dot. Only letters,
// digits, hyphens and underscores are accepted, so no byte that could change a request line (a space, a colon, a
// carriage return or a line feed) ever reaches the tunnel.
func normalizeName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(raw, "."))
	if name == "" || len(name) > maxNameLength {
		return "", errBadName
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > maxLabelLength {
			return "", errBadName
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return "", errBadName
			}
		}
	}
	return name, nil
}

// addressFor returns the address a name resolves to in the guest.
func (m *nameMap) addressFor(name string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(name); err == nil && addr.Is4() {
		// A literal address answers with itself, so the tunnel sees the literal and applies its rules to it.
		return addr, nil
	}
	if addr, ok := m.local[name]; ok {
		return addr, nil
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return netip.MustParseAddr("127.0.0.1"), nil
	}
	return m.assign(name)
}

// answer returns the reply to a DNS query, or nil when the message is not one to reply to.
func (m *nameMap) answer(query []byte) []byte {
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil || header.Response {
		return nil
	}
	reply := dnsmessage.Message{Header: dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true, OpCode: header.OpCode}}
	finish := func(code dnsmessage.RCode) []byte {
		reply.Header.RCode = code
		out, err := reply.Pack()
		if err != nil {
			return nil
		}
		return out
	}
	if header.OpCode != 0 {
		return finish(dnsmessage.RCodeNotImplemented)
	}
	questions, err := p.AllQuestions()
	if err != nil || len(questions) != 1 {
		return finish(dnsmessage.RCodeFormatError)
	}
	q := questions[0]
	reply.Questions = questions
	name, err := normalizeName(q.Name.String())
	if err != nil {
		return finish(dnsmessage.RCodeFormatError)
	}
	if q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET {
		// No record of another type is ever given: AAAA keeps programs on IPv4, and the rest have no meaning here.
		return finish(dnsmessage.RCodeSuccess)
	}
	addr, err := m.addressFor(name)
	if err != nil {
		if m.fullLogged.CompareAndSwap(false, true) {
			logf("the DNS server has no address left for %s: %v", name, err)
		}
		return finish(dnsmessage.RCodeServerFailure)
	}
	reply.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: answerTTL},
		Body:   &dnsmessage.AResource{A: addr.As4()},
	}}
	return finish(dnsmessage.RCodeSuccess)
}

// serveDNSUDP answers queries until the socket closes.
func serveDNSUDP(pc net.PacketConn, m *nameMap) {
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logf("dns: read a query: %v", err)
			time.Sleep(retryPause)
			continue
		}
		if out := m.answer(buf[:n]); out != nil {
			_, _ = pc.WriteTo(out, from)
		}
	}
}

// serveDNSTCP answers queries sent over TCP until the listener closes.
func serveDNSTCP(l net.Listener, m *nameMap) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logf("dns: accept a connection: %v", err)
			time.Sleep(retryPause)
			continue
		}
		go func() {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var length [2]byte
				if _, err := io.ReadFull(br, length[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(br, msg); err != nil {
					return
				}
				out := m.answer(msg)
				if out == nil {
					return
				}
				frame := binary.BigEndian.AppendUint16(nil, uint16(len(out)))
				if _, err := c.Write(append(frame, out...)); err != nil {
					return
				}
			}
		}()
	}
}

// loadLocalNames reads the names in a hosts file and adds the machine's own name. These names keep the address the
// file gives them, so a program that looks one up does not reach the tunnel.
func loadLocalNames(hostsPath string) map[string]netip.Addr {
	local := map[string]netip.Addr{}
	if data, err := os.ReadFile(hostsPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			addr, err := netip.ParseAddr(fields[0])
			if err != nil || !addr.Is4() {
				continue
			}
			for _, name := range fields[1:] {
				if normal, err := normalizeName(name); err == nil {
					if _, taken := local[normal]; !taken {
						local[normal] = addr
					}
				}
			}
		}
	}
	if host, err := os.Hostname(); err == nil {
		if normal, err := normalizeName(host); err == nil {
			if _, taken := local[normal]; !taken {
				local[normal] = netip.MustParseAddr("127.0.0.1")
			}
		}
	}
	return local
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// A tunnel answer that is not 200 resets the program's connection, whatever the status class.
func TestStackResetsOnAnyTunnelStatusButOK(t *testing.T) {
	for _, status := range []string{"204 No Content", "302 Found", "101 Switching Protocols"} {
		t.Run(status, func(t *testing.T) {
			r := newRig(t)
			addr := r.assign("odd.example.org")
			errc := make(chan error, 1)
			go func() {
				c, err := r.dial(addr, 443)
				if c != nil {
					defer c.Close()
				}
				errc <- err
			}()
			far, _, _ := r.nextTunnel()
			defer far.Close()
			if _, err := far.Write([]byte("HTTP/1.1 " + status + "\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-errc:
				if err == nil {
					t.Fatalf("status %q was accepted as a connected tunnel", status)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no answer")
			}
		})
	}
}

// Past maxInFlightDials unanswered dials, the next connection is reset at once and not left to wait.
func TestStackResetsAConnectionPastTheDialLimit(t *testing.T) {
	r := newRig(t)
	held := make(chan struct{})
	go func() {
		for far := range r.tunnel {
			go func() { <-held; far.Close() }()
		}
	}()
	t.Cleanup(func() { close(held) })
	addr := r.assign("many.example.org")
	for i := 0; i < maxInFlightDials; i++ {
		go func() {
			c, err := r.dial(addr, 443)
			if err == nil {
				c.Close()
			}
		}()
	}
	deadline := time.Now().Add(60 * time.Second)
	for r.dials.Load() < maxInFlightDials {
		if time.Now().After(deadline) {
			t.Fatalf("only %d dials reached the tunnel", r.dials.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	start := time.Now()
	c, err := r.dial(addr, 443)
	if c != nil {
		c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "refused") || time.Since(start) > 4*time.Second {
		t.Fatalf("want a prompt refusal, got %v after %v", err, time.Since(start))
	}
}

// The host's own name from the hosts file and the machine hostname keep their local address.
func TestLoadLocalNamesReadsHostsFileAndHostname(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(p, []byte("10.1.2.3 db.internal # c\n::1 v6only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadLocalNames(p)
	if got["db.internal"] != netip.MustParseAddr("10.1.2.3") {
		t.Errorf("hosts entry missing: %v", got)
	}
	if _, bad := got["v6only"]; bad {
		t.Error("an IPv6 entry was kept")
	}
	host, _ := os.Hostname()
	if h := strings.ToLower(strings.TrimSuffix(host, ".")); h != "" {
		if got[h] != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("hostname %q not mapped: %v", h, got)
		}
	}
}

// watchStderr collects what the helper writes to its standard error until the test ends.
func watchStderr(t *testing.T) func() string {
	t.Helper()
	logGate = logLimiter{}
	old := os.Stderr
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wr
	var mu sync.Mutex
	var got strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := rd.Read(buf)
			mu.Lock()
			got.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		os.Stderr = old
		wr.Close()
		<-done
		rd.Close()
	})
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return got.String()
	}
}

// waitLogged waits for the helper to write text to its standard error.
func waitLogged(t *testing.T, read func() string, text string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(read(), text) {
		if time.Now().After(deadline) {
			t.Fatalf("the helper's log lacks %q: %q", text, read())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAFullNameMapIsLoggedOnce(t *testing.T) {
	read := watchStderr(t)
	m := newNameMap(nil, 1)
	m.answer(buildQuery(t, "a.example.org.", dnsmessage.TypeA))
	m.answer(buildQuery(t, "b.example.org.", dnsmessage.TypeA))
	m.answer(buildQuery(t, "c.example.org.", dnsmessage.TypeA))
	waitLogged(t, read, "b.example.org")
	if n := strings.Count(read(), "no address left"); n != 1 {
		t.Fatalf("a full map was logged %d times: %q", n, read())
	}
}

func TestARefusalFromTheTunnelIsLogged(t *testing.T) {
	read := watchStderr(t)
	r := newRig(t)
	addr := r.assign("blocked.example.org")
	go func() { _, _ = r.dial(addr, 443) }()
	far, _, _ := r.nextTunnel()
	defer far.Close()
	_, _ = far.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	waitLogged(t, read, "the tunnel refused blocked.example.org:443 with status 403")
}

func TestAnUnreachableTunnelIsLogged(t *testing.T) {
	read := watchStderr(t)
	r := newRig(t)
	addr := r.assign("down.example.org")
	go func() { (<-r.tunnel).Close() }()
	go func() { _, _ = r.dial(addr, 443) }()
	waitLogged(t, read, "down.example.org:443")
}

func TestAFailedDialToTheTunnelIsLogged(t *testing.T) {
	read := watchStderr(t)
	r := newRig(t)
	r.ns.dial = func() (net.Conn, error) { return nil, io.ErrClosedPipe }
	addr := r.assign("nowhere.example.org")
	go func() { _, _ = r.dial(addr, 443) }()
	waitLogged(t, read, "cannot reach the tunnel for nowhere.example.org:443")
}

func TestAConnectionPastTheDialLimitIsLogged(t *testing.T) {
	read := watchStderr(t)
	r := newRig(t)
	for i := 0; i < maxInFlightDials; i++ {
		r.ns.gate <- struct{}{}
	}
	addr := r.assign("many.example.org")
	go func() { _, _ = r.dial(addr, 443) }()
	waitLogged(t, read, "too many connections wait for the tunnel; resetting many.example.org:443")
}

// A tunnel that fails after the handshake resets the program's connection. A clean end of stream would look like a
// complete answer.
func TestAFailedTunnelAfterTheHandshakeResetsTheProgram(t *testing.T) {
	r := newRig(t)
	addr := r.assign("flaky.example.org")
	type result struct {
		conn *gonet.TCPConn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := r.dial(addr, 443)
		done <- result{c, err}
	}()
	far, _, _ := r.nextTunnel()
	if _, err := far.Write([]byte("HTTP/1.1 200 OK\r\n\r\npart")); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	defer res.conn.Close()
	got := make([]byte, 4)
	_ = res.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(res.conn, got); err != nil || string(got) != "part" {
		t.Fatalf("read %q, %v", got, err)
	}
	// Make the helper's next read from the tunnel fail with an error that is not an end of stream.
	_ = (<-r.near).SetReadDeadline(time.Now().Add(-time.Second))
	defer far.Close()
	_, err := res.conn.Read(make([]byte, 1))
	if err == nil || err == io.EOF {
		t.Fatalf("the program read %v, want a reset", err)
	}
}

func TestManyRefusedConnectionsWriteAtMostTheCapOfLogLines(t *testing.T) {
	read := watchStderr(t)
	r := newRig(t)
	go func() {
		for range r.near {
		}
	}()
	go func() {
		for far := range r.tunnel {
			go func() {
				defer far.Close()
				br := bufio.NewReader(far)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = far.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			}()
		}
	}()
	addr := r.assign("blocked.example.org")
	const attempts = 60
	for i := 0; i < attempts; i++ {
		if c, err := r.dial(addr, 443); err == nil {
			c.Close()
		}
	}
	r.waitClosed(attempts)
	waitLogged(t, read, "the tunnel refused")
	if n := strings.Count(read(), "\n"); n > 10 {
		t.Fatalf("%d refused connections wrote %d log lines, want at most 10", attempts, n)
	}
}

func TestTheLimiterCountsWhatItDropsAndReportsItInTheNextWindow(t *testing.T) {
	var l logLimiter
	now := time.Unix(1000, 0)
	for i := 0; i < maxLogLines; i++ {
		if ok, report := l.allow(now); !ok || report != 0 {
			t.Fatalf("line %d: %v, %d", i, ok, report)
		}
	}
	for i := 0; i < 5; i++ {
		if ok, _ := l.allow(now.Add(time.Second)); ok {
			t.Fatal("a line past the cap was written")
		}
	}
	if ok, report := l.allow(now.Add(logWindow - time.Nanosecond)); ok || report != 0 {
		t.Fatalf("just inside the window: %v, %d", ok, report)
	}
	if ok, report := l.allow(now.Add(logWindow)); !ok || report != 6 {
		t.Fatalf("new window: %v, %d dropped", ok, report)
	}
}

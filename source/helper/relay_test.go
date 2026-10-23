// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const connectRequest = "CONNECT registry.yarnpkg.com:443 HTTP/1.1\r\nHost: registry.yarnpkg.com:443\r\n\r\n"

// startRelay runs the relay's accept loop on a loopback port with dial and gate, and returns the address a client
// connects to.
func startRelay(t *testing.T, dial func() (net.Conn, error), gate chan struct{}) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go relayAccept(l, dial, 3128, gate)
	return l.Addr().String()
}

// sendConnect connects a client to the relay at addr and sends it a CONNECT request.
func sendConnect(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := io.WriteString(c, connectRequest); err != nil {
		t.Fatal(err)
	}
	return c
}

// statusLine is the first line of what the relay sent.
func statusLine(got string) string {
	line, _, _ := strings.Cut(got, "\r\n")
	return line
}

// startTunnel stands in for the runner's tunnel and returns a connection to it. The tunnel answers one CONNECT with
// 200, then sends back in upper case what follows the request, once the client has ended its side.
func startTunnel(t *testing.T) net.Conn {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		s, err := l.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		br := bufio.NewReader(s)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(s, "HTTP/1.1 200 Connection Established\r\n\r\n")
		rest, _ := io.ReadAll(br)
		_, _ = s.Write(bytes.ToUpper(rest))
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// tcpPair returns both ends of a loopback TCP connection: the relay's end, then the client's.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	relayEnd, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relayEnd.Close() })
	return relayEnd, client
}

// readToEnd reads what the client receives until the stream ends, and fails the test when the stream ends with an
// error, such as a reset, or does not end.
func readToEnd(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("the client's read ended with %v after %q, want a clean end of stream", err, got)
	}
	return string(got)
}

func TestTheRelayCarriesAConnectionWhoseFirstTwoDialsTimedOut(t *testing.T) {
	h := &fakeHost{answer: failsFirst(2, unix.ETIMEDOUT, 0), conn: startTunnel(t)}
	d := h.dialer()
	d.pause = time.Millisecond
	addr := startRelay(t, func() (net.Conn, error) { return d.dial(3128) }, make(chan struct{}, maxInFlightDials))

	c := sendConnect(t, addr)
	if _, err := io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	if got, want := readToEnd(t, c), "HTTP/1.1 200 Connection Established\r\n\r\nPING"; got != want {
		t.Fatalf("the client read %q, want %q", got, want)
	}
	if n := h.attempts(); n != 3 {
		t.Fatalf("the relay's dial made %d attempts, want 3", n)
	}
}

// A client of the tunnel, such as yarn, reports a reset as "tunneling socket could not be established, cause=read
// ECONNRESET". The relay answers it 502 instead, and ends the stream with a FIN.
func TestTheRelayAnswersACONNECTItCannotCarryWith502AndEndsWithoutAReset(t *testing.T) {
	h := &fakeHost{answer: alwaysFails(unix.ETIMEDOUT)}
	d := h.dialer()
	d.timeout, d.pause = 200*time.Millisecond, 10*time.Millisecond
	addr := startRelay(t, func() (net.Conn, error) { return d.dial(3128) }, make(chan struct{}, maxInFlightDials))

	got := readToEnd(t, sendConnect(t, addr))
	if statusLine(got) != "HTTP/1.1 502 Bad Gateway" {
		t.Fatalf("the relay answered %q, want a 502 status line", got)
	}
	if !strings.Contains(got, "vsock port 3128") {
		t.Fatalf("the relay's answer %q does not name the port it could not reach", got)
	}
	if n := h.attempts(); n < 2 {
		t.Fatalf("the relay's dial made %d attempts before it gave up, want more than one", n)
	}
}

func TestTheRelayEndsAClientThatSentNoHTTPRequestWithoutAnAnswerOrAReset(t *testing.T) {
	relayEnd, client := tcpPair(t)
	if _, err := io.WriteString(client, "SSH-2.0-OpenSSH_9.6\r\n"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	go refuse(relayEnd, 5*time.Second, "unreachable")
	if got := readToEnd(t, client); got != "" {
		t.Fatalf("the relay answered %q to a client that sent no HTTP request", got)
	}
	// The relay ends its side once it has read the client's first line, and does not wait for the client to close.
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("the stream ended %v after the relay refused it, want at once", waited)
	}
}

// A client that is still sending when the relay answers, such as one whose request has a body, is read and not reset.
// The body is larger than the two sockets' buffers hold, so it is all written only when the relay reads it.
func TestTheRelayKeepsReadingAClientThatIsStillSendingWhenItAnswers(t *testing.T) {
	relayEnd, client := tcpPair(t)
	go refuse(relayEnd, 5*time.Second, "unreachable")
	if _, err := io.WriteString(client, "POST http://example.org/upload HTTP/1.1\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	status, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || status != "HTTP/1.1 502 Bad Gateway\r\n" {
		t.Fatalf("the relay answered %q, %v, want a 502 status line", status, err)
	}
	_ = client.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write(make([]byte, 32<<20)); err != nil {
		t.Fatalf("writing the rest of the request failed with %v, want the relay to read it", err)
	}
}

// Past the gate's capacity, a connection is refused at once and no dial starts for it. A dial that ends frees its
// place.
func TestTheRelayRefusesAConnectionPastItsDialLimitUntilADialEnds(t *testing.T) {
	release := make(chan struct{})
	var dials atomic.Int32
	dial := func() (net.Conn, error) {
		if dials.Add(1) == 1 {
			<-release
		}
		return nil, unix.ECONNRESET
	}
	addr := startRelay(t, dial, make(chan struct{}, 1))

	first := sendConnect(t, addr)
	deadline := time.Now().Add(5 * time.Second)
	for dials.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the relay did not dial for the first connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := readToEnd(t, sendConnect(t, addr)); statusLine(got) != "HTTP/1.1 502 Bad Gateway" {
		t.Fatalf("the relay answered %q past its limit, want a 502 status line", got)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("the relay dialed %d times, want no dial for the connection past its limit", n)
	}

	close(release)
	readToEnd(t, first)
	readToEnd(t, sendConnect(t, addr))
	if n := dials.Load(); n != 2 {
		t.Fatalf("the relay dialed %d times, want a dial for a connection after the first dial ended", n)
	}
}

func TestTheRelayEndsASilentClientOnceItsWaitIsOver(t *testing.T) {
	relayEnd, client := tcpPair(t)
	done := make(chan struct{})
	go func() {
		refuse(relayEnd, 100*time.Millisecond, "unreachable")
		close(done)
	}()
	if got := readToEnd(t, client); got != "" {
		t.Fatalf("the relay answered %q to a client that sent nothing", got)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay still held the connection after its wait")
	}
}

func TestOnlyAnHTTPRequestLineGetsAnAnswer(t *testing.T) {
	for line, want := range map[string]bool{
		"CONNECT registry.npmjs.org:443 HTTP/1.1\r\n": true,
		"GET http://example.org/ HTTP/1.0\r\n":        true,
		"SSH-2.0-OpenSSH_9.6\r\n":                     false,
		"CONNECT registry.npmjs.org:443\r\n":          false,
		"PING host:1 SMTP/1.0\r\n":                    false,
	} {
		if got := isHTTPRequestLine([]byte(line)); got != want {
			t.Errorf("isHTTPRequestLine(%q) = %v, want %v", line, got, want)
		}
	}
}

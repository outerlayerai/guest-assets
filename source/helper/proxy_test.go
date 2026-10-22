// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// endRecorder is the program's side of a proxy: it records whether it was ended cleanly, reset or closed.
type endRecorder struct {
	net.Conn
	cleanEnd atomic.Bool
	aborted  atomic.Bool
	closed   atomic.Bool
}

func (c *endRecorder) Read(b []byte) (int, error) {
	time.Sleep(50 * time.Millisecond)
	return 0, errors.New("program done")
}
func (c *endRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (c *endRecorder) CloseWrite() error           { c.cleanEnd.Store(true); return nil }
func (c *endRecorder) Abort()                      { c.aborted.Store(true) }
func (c *endRecorder) Close() error                { c.closed.Store(true); return nil }

// brokenTunnel delivers some bytes, then fails the way a reset connection fails.
type brokenTunnel struct {
	net.Conn
	sent bool
}

func (c *brokenTunnel) Read(b []byte) (int, error) {
	if !c.sent {
		c.sent = true
		return copy(b, "part"), nil
	}
	return 0, errors.New("read: connection reset by peer")
}
func (c *brokenTunnel) Write(b []byte) (int, error) { return len(b), nil }
func (c *brokenTunnel) Close() error                { return nil }

func TestAFailedTunnelReadResetsTheProgramAndIsNotACleanEnd(t *testing.T) {
	prog := &endRecorder{}
	proxy(prog, &brokenTunnel{})
	if prog.cleanEnd.Load() {
		t.Fatal("the program saw a clean end of stream after the tunnel connection failed with an error")
	}
	if !prog.aborted.Load() {
		t.Fatal("the program's connection was not reset")
	}
}

func TestAFailedCopyClosesADestinationThatCannotBeReset(t *testing.T) {
	prog := &endRecorder{}
	// Hide Abort behind a type that does not have it.
	proxy(struct {
		net.Conn
		closeWriter
	}{prog, prog}, &brokenTunnel{})
	if prog.cleanEnd.Load() {
		t.Fatal("a failed copy ended the stream cleanly")
	}
	if !prog.closed.Load() {
		t.Fatal("a failed copy left the destination open")
	}
}

// A copy that ends at EOF half-closes the destination and does not reset it.
func TestACleanEndOfStreamHalfClosesTheDestination(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	done := make(chan struct{})
	go func() { proxy(a1, b1); close(done) }()
	_ = b2.Close() // the far side of b ends cleanly
	buf := make([]byte, 1)
	_ = a2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := a2.Read(buf); err == nil {
		t.Fatal("read data from a closed stream")
	}
	_ = a2.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the proxy did not finish")
	}
}

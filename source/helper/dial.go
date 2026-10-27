// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// hostDialTimeout is the most time one dial to the host takes over all its attempts. It matches the tunnel's own
	// connect timeout, so a program waits no longer for the host than the tunnel waits for a server.
	hostDialTimeout = tunnelConnectTimeout
	// hostDialPause is the wait before the second attempt. Each later wait is twice the one before it, up to
	// hostDialMaxPause.
	hostDialPause    = 50 * time.Millisecond
	hostDialMaxPause = time.Second
)

// hostDialer opens connections to the host over vsock. The host can be slow to answer a connect, and a signal can end
// the wait early. A failed attempt sent no bytes, so the dialer makes another one until its time is spent.
type hostDialer struct {
	// connect makes one attempt, which waits at most timeout for the host to answer.
	connect func(port uint32, timeout time.Duration) (net.Conn, error)
	// timeout is the most time one dial takes over all its attempts.
	timeout time.Duration
	// pause is the wait before the second attempt, and maxPause is the longest wait between two attempts.
	pause, maxPause time.Duration
	// logf, when set, reports a dial that needed more than one attempt.
	logf func(format string, a ...any)
	// retry, when set, decides which failed attempts are made again. It is retryableDialError when unset.
	retry func(error) bool
}

// dialGate limits the dialer's log lines, as logGate limits the network stack's.
var dialGate logLimiter

// hostVsock is the dialer that the relay, the network stack and the lease watchdog reach the host with.
var hostVsock = hostDialer{
	connect:  connectHost,
	timeout:  hostDialTimeout,
	pause:    hostDialPause,
	maxPause: hostDialMaxPause,
	logf:     func(format string, a ...any) { dialGate.printf("vsock", format, a...) },
}

// dialHost connects to the host's vsock port.
func dialHost(port uint32) (net.Conn, error) { return hostVsock.dial(port) }

// newRelayDialer returns the dialer that reaches the build's relay at addr over TCP. The helper uses it when it runs
// beside a container build instead of inside a microVM. The relay can start after the helper, so a refused connect is
// made again until the dialer's time is spent.
func newRelayDialer(addr string) hostDialer {
	return hostDialer{
		connect:  func(_ uint32, timeout time.Duration) (net.Conn, error) { return net.DialTimeout("tcp", addr, timeout) },
		timeout:  hostDialTimeout,
		pause:    hostDialPause,
		maxPause: hostDialMaxPause,
		logf:     func(format string, a ...any) { dialGate.printf("relay", format, a...) },
		retry:    retryableRelayError,
	}
}

// retryableRelayError reports whether a connect to the relay can succeed when it is made again: any error that a
// vsock connect may retry, and a refusal, which means the relay does not listen yet.
func retryableRelayError(err error) bool {
	return retryableDialError(err) || errors.Is(err, unix.ECONNREFUSED)
}

// connectHost makes one attempt to connect to the host's vsock port.
func connectHost(port uint32, timeout time.Duration) (net.Conn, error) {
	c, err := dialVsock(hostCID, port, timeout)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// dial connects to the host's vsock port. An attempt that timed out, was interrupted by a signal or was reset by the
// host is made again after a pause, until d.timeout has passed since the first attempt. Each attempt waits the whole
// time left. Firecracker connects to the host's socket for every request it receives, even one the guest has given up
// on, so shorter attempts would only add host connections while the host is slow.
func (d hostDialer) dial(port uint32) (net.Conn, error) {
	start := time.Now()
	deadline := start.Add(d.timeout)
	pause := d.pause
	retryable := d.retry
	if retryable == nil {
		retryable = retryableDialError
	}
	var first error
	for attempt := 1; ; attempt++ {
		c, err := d.connect(port, time.Until(deadline))
		if err == nil {
			if first != nil && d.logf != nil {
				d.logf("reached host port %d on attempt %d after %v; the first attempt failed: %v", port, attempt, time.Since(start).Round(time.Millisecond), first)
			}
			return c, nil
		}
		if first == nil {
			first = err
		}
		if !retryable(err) || time.Until(deadline) <= pause {
			if attempt == 1 {
				return nil, err
			}
			return nil, fmt.Errorf("%w (%d attempts in %v)", err, attempt, time.Since(start).Round(time.Millisecond))
		}
		time.Sleep(pause)
		pause = min(2*pause, d.maxPause)
	}
}

// retryableDialError reports whether a connect that failed with err can succeed when it is made again: the host did
// not answer in time, a signal interrupted the wait, or the host reset the connection before it opened. The kernel
// never restarts an interrupted vsock connect by itself.
func retryableDialError(err error) bool {
	return errors.Is(err, unix.ETIMEDOUT) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.ECONNRESET)
}

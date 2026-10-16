// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bufio"
	"context"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

// leaseRedial is how long the guest waits before it connects again to the
// runner's lease stream.
const leaseRedial = time.Second

// maxLeaseMillis keeps a number that is a whole number of milliseconds from
// overflowing a duration.
const maxLeaseMillis = math.MaxInt64 / int64(time.Millisecond)

// leasePortFromCmdline returns the vsock port that `outerlayer.lease=<port>` on
// the kernel command line names. A guest with no such flag has been told
// nothing about a lease and never powers itself off.
func leasePortFromCmdline(cmdline string) (uint32, bool) {
	for _, field := range strings.Fields(cmdline) {
		value, ok := strings.CutPrefix(field, "outerlayer.lease=")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(value, 10, 32)
		if err != nil || port == 0 {
			return 0, false
		}
		return uint32(port), true
	}
	return 0, false
}

// parseTimeLeft reads one line of the lease stream: the milliseconds left on
// the build's lease, as a whole number of 0 or more. Any other line is not a
// number, and the guest ignores it.
func parseTimeLeft(line string) (time.Duration, bool) {
	line = strings.TrimSuffix(line, "\r")
	if line == "" {
		return 0, false
	}
	for _, r := range line {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	ms, err := strconv.ParseInt(line, 10, 64)
	if err != nil {
		return 0, false
	}
	return time.Duration(min(ms, maxLeaseMillis)) * time.Millisecond, true
}

// runLeaseWatchdog powers the guest off when the build's lease runs out.
//
// The runner sends the milliseconds left on the lease, once when the stream
// opens and again after each renewal. The guest counts them down on its
// monotonic clock, which measures elapsed time and needs no sync with the
// host: the deadline is late by the time the message took to arrive, and is
// never early. A line that is not a number is ignored, and the guest keeps its
// deadline. A dropped stream also keeps it, and the guest connects again every
// second. A guest that has been told nothing has no deadline.
func runLeaseWatchdog(ctx context.Context, dial func() (net.Conn, error), powerOff func()) {
	updates := make(chan time.Duration)
	go func() {
		for ctx.Err() == nil {
			if conn, err := dial(); err == nil {
				readTimeLeft(ctx, conn, func(left time.Duration) {
					select {
					case updates <- left:
					case <-ctx.Done():
					}
				})
			}
			select {
			case <-time.After(leaseRedial):
			case <-ctx.Done():
				return
			}
		}
	}()
	var timer *time.Timer
	var expired <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case left := <-updates:
			if timer == nil {
				timer = time.NewTimer(left)
				expired = timer.C
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(left)
			}
		case <-expired:
			powerOff()
			return
		case <-ctx.Done():
			return
		}
	}
}

// readTimeLeft calls onLeft for each valid line of the stream, in order, so
// two lines read together leave the last number in force. It returns when the
// stream ends.
func readTimeLeft(ctx context.Context, conn net.Conn, onLeft func(time.Duration)) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 256), 4096)
	for scanner.Scan() {
		if left, ok := parseTimeLeft(scanner.Text()); ok {
			onLeft(left)
		}
	}
}

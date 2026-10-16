// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// leaseRig runs the watchdog against dialled pipes. Each dial hands the test the runner's end of a new stream.
type leaseRig struct {
	streams    chan net.Conn
	poweredOff atomic.Bool
	dials      atomic.Int32
	// refuse makes every further dial fail, as when the runner's socket is gone.
	refuse atomic.Bool
}

func startLease(t *testing.T) *leaseRig {
	t.Helper()
	r := &leaseRig{streams: make(chan net.Conn, 16)}
	dial := func() (net.Conn, error) {
		r.dials.Add(1)
		if r.refuse.Load() {
			return nil, errors.New("connection refused")
		}
		guest, runner := net.Pipe()
		r.streams <- runner
		return guest, nil
	}
	go runLeaseWatchdog(t.Context(), dial, func() { r.poweredOff.Store(true) })
	return r
}

func (r *leaseRig) next(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-r.streams:
		return c
	case <-time.After(time.Minute):
		t.Fatal("the guest did not open a lease stream")
		return nil
	}
}

func send(t *testing.T, c net.Conn, text string) {
	t.Helper()
	if _, err := c.Write([]byte(text)); err != nil {
		t.Fatalf("write %q: %v", text, err)
	}
}

// AC-1291-07
func TestGuestPowersOffWhenTheTimeLeftItWasToldHasPassed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		stream := r.next(t)
		send(t, stream, "60000\n")
		time.Sleep(59*time.Second + 900*time.Millisecond)
		synctest.Wait()
		if r.poweredOff.Load() {
			t.Fatal("the guest powered off before the time it was told had passed")
		}
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if !r.poweredOff.Load() {
			t.Fatal("the guest did not power off once the time it was told had passed")
		}
	})
}

// AC-1291-08
func TestGuestToldNothingNeverPowersOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		stream := r.next(t)
		time.Sleep(time.Hour)
		synctest.Wait()
		if r.poweredOff.Load() {
			t.Fatal("a guest told nothing about its lease powered off")
		}
		stream.Close()
		time.Sleep(time.Hour)
		synctest.Wait()
		if r.poweredOff.Load() {
			t.Fatal("a guest told nothing, whose stream dropped, powered off")
		}
	})
}

func TestGuestWithNoLeasePortRunsNoWatchdog(t *testing.T) {
	if port, ok := leasePortFromCmdline("console=ttyS0 root=/dev/vda outerlayer.relay=3126,3127"); ok {
		t.Fatalf("a command line with no lease port gave port %d", port)
	}
	port, ok := leasePortFromCmdline("console=ttyS0 outerlayer.lease=3125 outerlayer.relay=3126")
	if !ok || port != 3125 {
		t.Fatalf("got %d, %v, want 3125", port, ok)
	}
	if _, ok := leasePortFromCmdline("outerlayer.lease=abc"); ok {
		t.Fatal("a lease port that is not a number was accepted")
	}
}

// AC-1291-09
func TestGuestWhoseStreamDroppedKeepsRunningPastTheOldDeadlineWhenANewerTimeArrives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		first := r.next(t)
		send(t, first, "60000\n")
		time.Sleep(10 * time.Second)
		first.Close()
		// The guest dials again every second while the stream is down.
		second := r.next(t)
		send(t, second, "120000\n")
		time.Sleep(70 * time.Second)
		synctest.Wait()
		if r.poweredOff.Load() {
			t.Fatal("the guest powered off at its old deadline although a newer time arrived")
		}
		time.Sleep(60 * time.Second)
		synctest.Wait()
		if !r.poweredOff.Load() {
			t.Fatal("the guest did not power off at the newer deadline")
		}
	})
}

func TestGuestKeepsItsDeadlineWhileItsStreamIsDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		first := r.next(t)
		send(t, first, "30000\n")
		first.Close()
		time.Sleep(31 * time.Second)
		synctest.Wait()
		if !r.poweredOff.Load() {
			t.Fatal("a dropped stream cleared the guest's deadline")
		}
	})
}

func TestGuestDialsAgainEverySecondWhileItsStreamIsDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		first := r.next(t)
		r.refuse.Store(true)
		first.Close()
		before := r.dials.Load()
		time.Sleep(5500 * time.Millisecond)
		synctest.Wait()
		if got := r.dials.Load() - before; got != 5 {
			t.Fatalf("the guest dialled %d times in 5.5 seconds, want 5", got)
		}
	})
}

// AC-1291-10
func TestGuestKeepsItsDeadlineWhenAStreamSendsALineThatIsNotAWholeNumber(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		stream := r.next(t)
		send(t, stream, "60000\n")
		for _, junk := range []string{"abc\n", "-5\n", "1.5\n", "\n", "99999999999999999999999999\n", "1e9\n", "+5\n"} {
			send(t, stream, junk)
		}
		time.Sleep(59*time.Second + 900*time.Millisecond)
		synctest.Wait()
		if r.poweredOff.Load() {
			t.Fatal("the guest powered off early: a line that is not a number moved its deadline")
		}
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if !r.poweredOff.Load() {
			t.Fatal("the guest did not power off at its first deadline: a junk line moved it later")
		}
	})
}

func TestGuestUsesTheLastNumberOfTwoLinesReadTogether(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		stream := r.next(t)
		send(t, stream, "300000\n20000\n")
		time.Sleep(21 * time.Second)
		synctest.Wait()
		if !r.poweredOff.Load() {
			t.Fatal("the guest did not use the last of two numbers read together")
		}
	})
}

func TestGuestToldZeroPowersOffAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		stream := r.next(t)
		send(t, stream, "0\n")
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if !r.poweredOff.Load() {
			t.Fatal("a lease with no time left did not power the guest off")
		}
	})
}

// initWatchdogRig starts the init wiring with a fake kernel command line, and records each dial and each power-off.
type initWatchdogRig struct {
	started    bool
	dials      atomic.Int32
	lastPort   atomic.Uint32
	poweredOff atomic.Bool
}

func startInitWatchdog(t *testing.T, cmdline string) *initWatchdogRig {
	t.Helper()
	r := &initWatchdogRig{}
	r.started = startLeaseWatchdog(
		t.Context(),
		func() ([]byte, error) { return []byte(cmdline), nil },
		func(port uint32) (net.Conn, error) {
			r.dials.Add(1)
			r.lastPort.Store(port)
			return nil, errors.New("connection refused")
		},
		func() { r.poweredOff.Store(true) },
	)
	return r
}

func TestGuestWithNoLeasePortOnItsCommandLineStartsNoWatchdog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startInitWatchdog(t, "console=ttyS0 root=/dev/vda outerlayer.relay=3126,3127")
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		if r.started || r.dials.Load() != 0 || r.poweredOff.Load() {
			t.Fatalf("a guest with no lease port started a watchdog (started %v, dials %d, powered off %v)", r.started, r.dials.Load(), r.poweredOff.Load())
		}
	})
}

func TestGuestWithALeasePortOnItsCommandLineDialsThatPort(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startInitWatchdog(t, "console=ttyS0 outerlayer.lease=3125")
		synctest.Wait()
		if !r.started {
			t.Fatal("a guest with a lease port started no watchdog")
		}
		if got := r.lastPort.Load(); got != 3125 {
			t.Fatalf("the watchdog dialled port %d, want 3125", got)
		}
		// Told nothing, the watchdog never powers off, however long it waits.
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		if r.poweredOff.Load() {
			t.Fatal("a watchdog that was told nothing powered the guest off")
		}
	})
}

func TestGuestWhoseCommandLineCannotBeReadStartsNoWatchdog(t *testing.T) {
	started := startLeaseWatchdog(t.Context(),
		func() ([]byte, error) { return nil, errors.New("no /proc") },
		func(uint32) (net.Conn, error) { return nil, errors.New("unreachable") },
		func() {})
	if started {
		t.Fatal("a guest that cannot read its command line started a watchdog")
	}
}

func TestLeasePortZeroIsNotAPort(t *testing.T) {
	if port, ok := leasePortFromCmdline("outerlayer.lease=0"); ok {
		t.Fatalf("lease port 0 was accepted as %d", port)
	}
}

func TestGuestReadsANumberThatEndsInACarriageReturn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		stream := r.next(t)
		send(t, stream, "20000\r\n")
		time.Sleep(21 * time.Second)
		synctest.Wait()
		if !r.poweredOff.Load() {
			t.Fatal("a number that ends in a carriage return was not read")
		}
	})
}

func TestGuestToldTheLargestNumberItCanParseDoesNotPowerOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		stream := r.next(t)
		send(t, stream, "9223372036854775807\n")
		time.Sleep(24 * time.Hour)
		synctest.Wait()
		if r.poweredOff.Load() {
			t.Fatal("a number too large for a duration powered the guest off")
		}
	})
}

func TestGuestReadsADigitNineAndKeepsReadingAfterALongJunkLine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startLease(t)
		stream := r.next(t)
		send(t, stream, strings.Repeat("x", 3000)+"\n9000\n")
		time.Sleep(9*time.Second + 100*time.Millisecond)
		synctest.Wait()
		if !r.poweredOff.Load() {
			t.Fatal("the number after a long junk line was not read")
		}
	})
}

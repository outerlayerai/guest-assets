// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
)

// fakeHost stands in for the host's end of a vsock connect. Its answer function decides each attempt, numbered from
// 1: how much time the attempt takes, and the error it fails with, or nil when it gets conn. The host records the
// timeout and the start time of each attempt.
type fakeHost struct {
	answer   func(attempt int, timeout time.Duration) (time.Duration, error)
	conn     net.Conn
	mu       sync.Mutex
	timeouts []time.Duration
	starts   []time.Time
}

func (h *fakeHost) connect(port uint32, timeout time.Duration) (net.Conn, error) {
	h.mu.Lock()
	h.timeouts = append(h.timeouts, timeout)
	h.starts = append(h.starts, time.Now())
	attempt := len(h.timeouts)
	h.mu.Unlock()
	takes, err := h.answer(attempt, timeout)
	time.Sleep(takes)
	if err != nil {
		return nil, err
	}
	return h.conn, nil
}

func (h *fakeHost) attempts() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.timeouts)
}

// dialer is the helper's own dialer, with the fake host in place of vsock and no log.
func (h *fakeHost) dialer() hostDialer {
	d := hostVsock
	d.connect = h.connect
	d.logf = nil
	return d
}

// failsFirst fails each of the first n attempts with err after takes, and gives a connection at once to the attempts
// after them.
func failsFirst(n int, err error, takes time.Duration) func(int, time.Duration) (time.Duration, error) {
	return func(attempt int, _ time.Duration) (time.Duration, error) {
		if attempt <= n {
			return takes, err
		}
		return 0, nil
	}
}

// kernelDefaultWait is how long the kernel waits for the host to answer a connect when no timeout is set on the socket.
const kernelDefaultWait = 2 * time.Second

// alwaysFails answers every attempt at once with err.
func alwaysFails(err error) func(int, time.Duration) (time.Duration, error) {
	return func(int, time.Duration) (time.Duration, error) { return 0, err }
}

// mustCarry fails the test unless bytes written to c reach far.
func mustCarry(t *testing.T, c, far net.Conn) {
	t.Helper()
	go func() { _, _ = c.Write([]byte("ping")) }()
	got := make([]byte, 4)
	if _, err := io.ReadFull(far, got); err != nil || string(got) != "ping" {
		t.Fatalf("the host read %q, %v through the dialled connection", got, err)
	}
}

// The kernel waits two seconds for the host to answer a connect, unless the socket asks for another time. Opening a
// vsock socket needs a kernel with vsock, outside Docker's default seccomp profile, so the test skips elsewhere.
func TestAVsockSocketAsksTheKernelToWaitTheTimeGiven(t *testing.T) {
	for _, tc := range []struct {
		timeout  time.Duration
		min, max time.Duration
	}{
		{hostDialTimeout, hostDialTimeout, hostDialTimeout},
		// A zero would give the kernel's default, so the socket asks for the shortest wait, one clock tick.
		{0, time.Microsecond, 10 * time.Millisecond},
	} {
		fd, err := vsockSocket(tc.timeout)
		if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPERM) {
			t.Skipf("this host cannot open a vsock socket: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
		tv, err := unix.GetsockoptTimeval(fd, unix.AF_VSOCK, unix.SO_VM_SOCKETS_CONNECT_TIMEOUT)
		unix.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		if got := time.Duration(tv.Nano()); got < tc.min || got > tc.max {
			t.Errorf("a socket opened with a timeout of %v waits %v, want between %v and %v", tc.timeout, got, tc.min, tc.max)
		}
	}
}

func TestADialIsMadeAgainWhenTheHostTimesOutASignalInterruptsOrTheHostResets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		errno unix.Errno
		takes time.Duration
	}{
		// An attempt times out with time left when the kernel keeps its own wait, as it did before the helper set one.
		{"ETIMEDOUT", unix.ETIMEDOUT, kernelDefaultWait},
		{"EINTR", unix.EINTR, 0},
		{"ECONNRESET", unix.ECONNRESET, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				guest, host := net.Pipe()
				defer host.Close()
				h := &fakeHost{answer: failsFirst(2, tc.errno, tc.takes), conn: guest}
				c, err := h.dialer().dial(3128)
				if err != nil {
					t.Fatalf("the dial failed: %v", err)
				}
				defer c.Close()
				if n := h.attempts(); n != 3 {
					t.Fatalf("the dial made %d attempts, want 3", n)
				}
				mustCarry(t, c, host)
			})
		})
	}
}

func TestADialFailsAtOnceOnAnErrorThatAnotherAttemptCannotFix(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := &fakeHost{answer: alwaysFails(unix.EAFNOSUPPORT)}
		start := time.Now()
		_, err := h.dialer().dial(3128)
		if !errors.Is(err, unix.EAFNOSUPPORT) {
			t.Fatalf("the dial failed with %v, want %v", err, unix.EAFNOSUPPORT)
		}
		if n := h.attempts(); n != 1 {
			t.Fatalf("the dial made %d attempts, want 1", n)
		}
		if waited := time.Since(start); waited != 0 {
			t.Fatalf("the dial waited %v before it failed", waited)
		}
	})
}

func TestEachAttemptWaitsForTheHostNoLongerThanTheTimeLeft(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		guest, host := net.Pipe()
		defer host.Close()
		// A signal ends the first attempt after ten seconds.
		h := &fakeHost{conn: guest, answer: func(attempt int, _ time.Duration) (time.Duration, error) {
			if attempt == 1 {
				return 10 * time.Second, unix.EINTR
			}
			return 0, nil
		}}
		c, err := h.dialer().dial(3128)
		if err != nil {
			t.Fatalf("the dial failed: %v", err)
		}
		c.Close()
		want := []time.Duration{hostDialTimeout, hostDialTimeout - 10*time.Second - hostDialPause}
		if !slices.Equal(h.timeouts, want) {
			t.Fatalf("the attempts were given %v to wait, want %v", h.timeouts, want)
		}
	})
}

// With the connect timeout set, the kernel ends an attempt that gets no answer once the whole timeout has passed.
func TestAnAttemptThatWaitsOutTheWholeTimeEndsTheDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := &fakeHost{answer: func(_ int, timeout time.Duration) (time.Duration, error) { return timeout, unix.ETIMEDOUT }}
		start := time.Now()
		_, err := h.dialer().dial(3128)
		if !errors.Is(err, unix.ETIMEDOUT) {
			t.Fatalf("the dial failed with %v, want %v", err, unix.ETIMEDOUT)
		}
		if n := h.attempts(); n != 1 {
			t.Fatalf("the dial made %d attempts, want 1", n)
		}
		if waited := time.Since(start); waited != hostDialTimeout {
			t.Fatalf("the dial gave up after %v, want %v", waited, hostDialTimeout)
		}
	})
}

func TestADialThatKeepsFailingGivesUpWhenItsTimeIsSpent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := &fakeHost{answer: alwaysFails(unix.ECONNRESET)}
		start := time.Now()
		_, err := h.dialer().dial(3128)
		waited := time.Since(start)
		if !errors.Is(err, unix.ECONNRESET) {
			t.Fatalf("the dial failed with %v, want %v", err, unix.ECONNRESET)
		}
		if waited > hostDialTimeout || waited < hostDialTimeout-hostDialMaxPause {
			t.Fatalf("the dial gave up after %v, want between %v and %v", waited, hostDialTimeout-hostDialMaxPause, hostDialTimeout)
		}
		if want := fmt.Sprintf("(%d attempts in ", h.attempts()); !strings.Contains(err.Error(), want) {
			t.Fatalf("the error %q does not say how many attempts were made", err)
		}
	})
}

func TestThePausesBetweenAttemptsDoubleUpToTheLongestPause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := &fakeHost{answer: alwaysFails(unix.ECONNRESET)}
		_, _ = h.dialer().dial(3128)
		var gaps []time.Duration
		for i := 1; i < len(h.starts); i++ {
			gaps = append(gaps, h.starts[i].Sub(h.starts[i-1]))
		}
		if len(gaps) == 0 || gaps[0] != hostDialPause {
			t.Fatalf("the pauses were %v, want the first to be %v", gaps, hostDialPause)
		}
		for i := 1; i < len(gaps); i++ {
			if want := min(2*gaps[i-1], hostDialMaxPause); gaps[i] != want {
				t.Fatalf("the pauses were %v, want pause %d to be %v", gaps, i+1, want)
			}
		}
		if last := gaps[len(gaps)-1]; last != hostDialMaxPause {
			t.Fatalf("the pauses were %v, want them to reach %v", gaps, hostDialMaxPause)
		}
	})
}

func TestOnlyADialThatNeededMoreThanOneAttemptIsLogged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var lines []string
		logf := func(format string, a ...any) { lines = append(lines, fmt.Sprintf(format, a...)) }
		guest, host := net.Pipe()
		defer host.Close()
		defer guest.Close()

		d := (&fakeHost{answer: failsFirst(0, nil, 0), conn: guest}).dialer()
		d.logf = logf
		if _, err := d.dial(3128); err != nil {
			t.Fatalf("the dial failed: %v", err)
		}
		if len(lines) != 0 {
			t.Fatalf("a dial that worked on its first attempt logged %q", lines)
		}

		d = (&fakeHost{answer: failsFirst(2, unix.ETIMEDOUT, kernelDefaultWait), conn: guest}).dialer()
		d.logf = logf
		if _, err := d.dial(3128); err != nil {
			t.Fatalf("the dial failed: %v", err)
		}
		if len(lines) != 1 {
			t.Fatalf("a dial that worked on its third attempt logged %q, want one line", lines)
		}
		for _, want := range []string{"port 3128", "attempt 3", unix.ETIMEDOUT.Error()} {
			if !strings.Contains(lines[0], want) {
				t.Fatalf("the line %q does not say %q", lines[0], want)
			}
		}
	})
}

func TestTheNetworkStackReachesTheTunnelThroughTheHostDialer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		saved := hostVsock
		defer func() { hostVsock = saved }()
		guest, host := net.Pipe()
		defer host.Close()
		h := &fakeHost{answer: failsFirst(1, unix.ETIMEDOUT, kernelDefaultWait), conn: guest}
		hostVsock.connect = h.connect
		hostVsock.logf = nil
		c, err := dialTunnel(3128)
		if err != nil {
			t.Fatalf("the tunnel dial failed: %v", err)
		}
		defer c.Close()
		if n := h.attempts(); n != 2 {
			t.Fatalf("the tunnel dial made %d attempts, want 2", n)
		}
		mustCarry(t, c, host)
	})
}

// Every connection from the guest to the host goes through hostVsock, which makes another attempt when the host is
// slow to answer. Code that used vsockSocket, dialVsock or connectHost directly would make one attempt, and fail on
// the host's first slow answer.
func TestEveryConnectionToTheHostGoesThroughTheHostDialer(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	users := map[string][]string{"vsockSocket": nil, "dialVsock": nil, "connectHost": nil}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			owner := declName(decl)
			var declared *ast.Ident
			if fn, ok := decl.(*ast.FuncDecl); ok {
				declared = fn.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id != declared {
					if _, watched := users[id.Name]; watched {
						users[id.Name] = append(users[id.Name], owner)
					}
				}
				return true
			})
		}
	}
	want := map[string][]string{"vsockSocket": {"dialVsock"}, "dialVsock": {"connectHost"}, "connectHost": {"hostVsock"}}
	for name, got := range users {
		if !slices.Equal(got, want[name]) {
			t.Errorf("%s is used by %v, want only by %v", name, got, want[name])
		}
	}
}

// declName names a top-level declaration: a function by its name, a method by its type and name, and anything else
// by the names it declares.
func declName(decl ast.Decl) string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv != nil && len(d.Recv.List) == 1 {
			return fmt.Sprintf("%s.%s", typeName(d.Recv.List[0].Type), d.Name.Name)
		}
		return d.Name.Name
	case *ast.GenDecl:
		var names []string
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.ValueSpec:
				for _, n := range s.Names {
					names = append(names, n.Name)
				}
			case *ast.TypeSpec:
				names = append(names, s.Name.Name)
			}
		}
		return strings.Join(names, ",")
	}
	return "?"
}

func typeName(e ast.Expr) string {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

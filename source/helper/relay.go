// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// hostCID is the well-known vsock address of the host.
const hostCID = unix.VMADDR_CID_HOST

type vsockAddr struct {
	cid, port uint32
}

func (vsockAddr) Network() string  { return "vsock" }
func (a vsockAddr) String() string { return fmt.Sprintf("%d:%d", a.cid, a.port) }

// vsockConn is a net.Conn over an AF_VSOCK stream socket. The standard
// library cannot wrap vsock descriptors, so reads and writes go through a
// pollable os.File.
type vsockConn struct {
	f      *os.File
	fd     int
	local  vsockAddr
	remote vsockAddr
}

func newVsockConn(fd int) (*vsockConn, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	c := &vsockConn{fd: fd, f: os.NewFile(uintptr(fd), "vsock")}
	if sa, err := unix.Getsockname(fd); err == nil {
		if vm, ok := sa.(*unix.SockaddrVM); ok {
			c.local = vsockAddr{vm.CID, vm.Port}
		}
	}
	if sa, err := unix.Getpeername(fd); err == nil {
		if vm, ok := sa.(*unix.SockaddrVM); ok {
			c.remote = vsockAddr{vm.CID, vm.Port}
		}
	}
	return c, nil
}

func (c *vsockConn) Read(b []byte) (int, error)  { return c.f.Read(b) }
func (c *vsockConn) Write(b []byte) (int, error) { return c.f.Write(b) }
func (c *vsockConn) Close() error                { return c.f.Close() }
func (c *vsockConn) LocalAddr() net.Addr         { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr        { return c.remote }

func (c *vsockConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }

// CloseWrite sends FIN to the peer while keeping the read side open.
func (c *vsockConn) CloseWrite() error { return unix.Shutdown(c.fd, unix.SHUT_WR) }

// peerCID returns the CID of the remote end as reported by the kernel.
func (c *vsockConn) peerCID() (uint32, error) {
	sa, err := unix.Getpeername(c.fd)
	if err != nil {
		return 0, err
	}
	vm, ok := sa.(*unix.SockaddrVM)
	if !ok {
		return 0, errors.New("peer is not a vsock address")
	}
	return vm.CID, nil
}

// dialVsock connects to the given CID and port.
func dialVsock(cid, port uint32) (*vsockConn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return newVsockConn(fd)
}

type vsockListener struct {
	f    *os.File
	port uint32
}

// listenVsock listens on a vsock port for any CID.
func listenVsock(port uint32) (*vsockListener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Listen(fd, 128); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &vsockListener{f: os.NewFile(uintptr(fd), "vsock-listener"), port: port}, nil
}

func (l *vsockListener) Accept() (net.Conn, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	nfd := -1
	var accErr error
	err = rc.Read(func(fd uintptr) bool {
		nfd, _, accErr = unix.Accept4(int(fd), unix.SOCK_CLOEXEC)
		return accErr != unix.EAGAIN
	})
	if err != nil {
		return nil, err
	}
	if accErr != nil {
		return nil, accErr
	}
	return newVsockConn(nfd)
}

func (l *vsockListener) Close() error { return l.f.Close() }
func (l *vsockListener) Addr() net.Addr {
	return vsockAddr{cid: unix.VMADDR_CID_ANY, port: l.port}
}

// vsockPeerAllowed accepts only the host.
func vsockPeerAllowed(c net.Conn) bool {
	vc, ok := c.(*vsockConn)
	if !ok {
		return false
	}
	cid, err := vc.peerCID()
	return err == nil && cid == hostCID
}

func runExecAgent(args []string) int {
	fs := flag.NewFlagSet("exec-agent", flag.ContinueOnError)
	port := fs.Uint("port", 1024, "vsock port to listen on")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	l, err := listenVsock(uint32(*port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "exec-agent: listen on vsock port %d: %v\n", *port, err)
		return 1
	}
	a := newAgent()
	a.PeerAllowed = vsockPeerAllowed
	if err := a.Serve(l); err != nil {
		fmt.Fprintf(os.Stderr, "exec-agent: %v\n", err)
		return 1
	}
	return 0
}

type portList []uint16

func (p *portList) String() string { return fmt.Sprint([]uint16(*p)) }
func (p *portList) Set(v string) error {
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("invalid port %q", v)
	}
	*p = append(*p, uint16(n))
	return nil
}

func runRelay(args []string) int {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	var ports portList
	fs.Var(&ports, "forward", "TCP port on 127.0.0.1 to forward to the same vsock port on the host (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "relay: at least one --forward PORT is required")
		return 2
	}
	var listeners []net.Listener
	for _, p := range ports {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p))))
		if err != nil {
			fmt.Fprintf(os.Stderr, "relay: listen on 127.0.0.1:%d: %v\n", p, err)
			return 1
		}
		listeners = append(listeners, l)
	}
	var wg sync.WaitGroup
	for i, l := range listeners {
		wg.Add(1)
		go func(l net.Listener, port uint16) {
			defer wg.Done()
			relayAccept(l, func() (net.Conn, error) { return dialVsock(hostCID, uint32(port)) }, port)
		}(l, uint16(ports[i]))
	}
	wg.Wait()
	return 1
}

func relayAccept(l net.Listener, dial func() (net.Conn, error), port uint16) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "relay: accept on port %d: %v\n", port, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go func() {
			up, err := dial()
			if err != nil {
				fmt.Fprintf(os.Stderr, "relay: dial host vsock port %d: %v\n", port, err)
				c.Close()
				return
			}
			proxy(c, up)
		}()
	}
}

type closeWriter interface{ CloseWrite() error }

// aborter is a connection that can end with a reset instead of a clean end.
type aborter interface{ Abort() }

// proxy copies both directions and half-closes the write side of the
// destination when a source reaches EOF. A copy that fails for any other
// reason ends the destination with a reset when it can, so the program never
// reads a failure as a clean end of the stream. Both connections close once
// both directions finish.
func proxy(a, b net.Conn) {
	var wg sync.WaitGroup
	copyDir := func(dst, src net.Conn) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			if ab, ok := dst.(aborter); ok {
				ab.Abort()
			} else {
				_ = dst.Close()
			}
			return
		}
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go copyDir(a, b)
	go copyDir(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

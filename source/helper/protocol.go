// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame types of the exec protocol. The host sends Request, Stdin and Kill;
// the guest sends Stdout, Stderr and Exit.
const (
	TypeRequest byte = 1
	TypeStdin   byte = 2
	TypeStdout  byte = 3
	TypeStderr  byte = 4
	TypeExit    byte = 5
	TypeKill    byte = 6
)

const (
	// MaxPayload bounds a single frame so a peer cannot force a huge allocation.
	MaxPayload = 16 << 20
	// MaxChunk bounds the output bytes the guest puts in one frame.
	MaxChunk  = 64 << 10
	headerLen = 5
)

var ErrFrameTooLarge = errors.New("frame payload exceeds 16 MiB")

// Frame is one decoded protocol frame.
type Frame struct {
	Type    byte
	Payload []byte
}

// Request is the JSON payload of the first frame on a connection. Field order
// is the wire key order.
type Request struct {
	Argv []string          `json:"argv"`
	User string            `json:"user"`
	Cwd  string            `json:"cwd"`
	Env  map[string]string `json:"env"`
}

// EncodeFrame returns the wire form: type, 4-byte big-endian length, payload.
func EncodeFrame(typ byte, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, headerLen+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:headerLen], uint32(len(payload)))
	copy(buf[headerLen:], payload)
	return buf, nil
}

// WriteFrame writes one frame with a single Write call.
func WriteFrame(w io.Writer, typ byte, payload []byte) error {
	buf, err := EncodeFrame(typ, payload)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// ReadFrame reads one frame. An oversize length is rejected before any
// payload is read.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxPayload {
		return Frame{}, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, fmt.Errorf("short frame payload: %w", err)
	}
	return Frame{Type: hdr[0], Payload: payload}, nil
}

// EncodeExit encodes an exit status as a big-endian int32.
func EncodeExit(status int32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(status))
	return b[:]
}

// DecodeExit decodes an Exit payload.
func DecodeExit(p []byte) (int32, error) {
	if len(p) != 4 {
		return 0, fmt.Errorf("exit payload is %d bytes, want 4", len(p))
	}
	return int32(binary.BigEndian.Uint32(p)), nil
}

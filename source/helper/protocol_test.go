// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte{0xab}, MaxChunk)} {
		wire, err := EncodeFrame(TypeStdin, payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) != 5+len(payload) || wire[0] != TypeStdin {
			t.Fatalf("bad wire header: len=%d type=%d", len(wire), wire[0])
		}
		f, err := ReadFrame(bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if f.Type != TypeStdin || !bytes.Equal(f.Payload, payload) {
			t.Fatalf("round trip mismatch for %d bytes", len(payload))
		}
	}
}

func TestEncodeRejectsOversize(t *testing.T) {
	if _, err := EncodeFrame(TypeStdin, make([]byte, MaxPayload+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
	if _, err := EncodeFrame(TypeStdin, make([]byte, MaxPayload)); err != nil {
		t.Fatalf("exactly 16 MiB must be accepted: %v", err)
	}
}

func TestReadRejectsOversizeBeforeReadingPayload(t *testing.T) {
	// Header claims 16 MiB + 1 and no payload follows; the length alone must fail.
	hdr := []byte{TypeStdin, 0x01, 0x00, 0x00, 0x01}
	if _, err := ReadFrame(bytes.NewReader(hdr)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
}

func TestReadTruncated(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader([]byte{TypeStdout, 0, 0, 0, 4, 'a'})); err == nil {
		t.Fatal("truncated payload must fail")
	}
	if _, err := ReadFrame(bytes.NewReader(nil)); err == nil {
		t.Fatal("empty input must fail")
	}
}

func TestExitCodec(t *testing.T) {
	for _, v := range []int32{0, 3, 137, -1} {
		got, err := DecodeExit(EncodeExit(v))
		if err != nil || got != v {
			t.Fatalf("exit %d round trip: got %d, %v", v, got, err)
		}
	}
	if _, err := DecodeExit([]byte{0, 0, 1}); err == nil {
		t.Fatal("short exit payload must fail")
	}
}

type goldenFile struct {
	Frames []struct {
		Name       string `json:"name"`
		Type       byte   `json:"type"`
		PayloadHex string `json:"payload_hex"`
		WireHex    string `json:"wire_hex"`
	} `json:"frames"`
}

func TestGoldenFrames(t *testing.T) {
	raw, err := os.ReadFile("testdata/frames.json")
	if err != nil {
		t.Fatal(err)
	}
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, fr := range g.Frames {
		seen[fr.Name] = true
		payload, err := hex.DecodeString(fr.PayloadHex)
		if err != nil {
			t.Fatalf("%s: payload_hex: %v", fr.Name, err)
		}
		wantWire, err := hex.DecodeString(fr.WireHex)
		if err != nil {
			t.Fatalf("%s: wire_hex: %v", fr.Name, err)
		}
		gotWire, err := EncodeFrame(fr.Type, payload)
		if err != nil || !bytes.Equal(gotWire, wantWire) {
			t.Errorf("%s: encoded %x, want %x (%v)", fr.Name, gotWire, wantWire, err)
		}
		dec, err := ReadFrame(bytes.NewReader(wantWire))
		if err != nil || dec.Type != fr.Type || !bytes.Equal(dec.Payload, payload) {
			t.Errorf("%s: decode mismatch (%v)", fr.Name, err)
		}
	}
	for _, name := range []string{"request", "stdin", "stdin_eof", "stdout", "stderr", "exit_0", "exit_3", "exit_negative", "kill"} {
		if !seen[name] {
			t.Errorf("golden file lacks %q", name)
		}
	}
}

func TestGoldenRequestMatchesMarshal(t *testing.T) {
	raw, _ := os.ReadFile("testdata/frames.json")
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	for _, fr := range g.Frames {
		if fr.Name != "request" {
			continue
		}
		got, err := json.Marshal(Request{Argv: []string{"id", "-u", "dev"}, User: "dev", Cwd: "/build/work", Env: map[string]string{"A": "b"}})
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != fr.PayloadHex {
			t.Fatalf("marshalled request %s differs from golden payload", got)
		}
		return
	}
	t.Fatal("no request frame")
}

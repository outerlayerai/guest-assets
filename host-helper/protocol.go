// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

//go:build linux

package main

// ProtocolVersion is the version of the request and reply format. The runner
// asks for it with "hello" and keeps working with the versions it knows.
const ProtocolVersion = 1

// Operations a request can name.
const (
	OpHello = "hello"
	OpStart = "start"
	OpStop  = "stop"
	OpState = "state"
	OpList  = "list"
)

// Kinds of microVM a start can name. The kind changes nothing about the
// confinement: a check microVM gets a user and a unit of its own like a build.
const (
	KindBuild = "build"
	KindCheck = "check"
)

// Refusal codes. A refusal carries one of these and a reason a person can read.
const (
	CodeBadRequest     = "bad-request"
	CodeNotRunner      = "not-runner"
	CodeBadBuild       = "bad-build"
	CodeOutsideBuilds  = "outside-builds-root"
	CodeBadFile        = "bad-file"
	CodeHashMismatch   = "hash-mismatch"
	CodeAlreadyRunning = "already-running"
	CodeNoUser         = "no-free-user"
	CodeSystemd        = "systemd-failed"
	CodeInternal       = "internal"
)

// Request is one JSON object on a connection. It names a build id and never a
// path, a user or a limit: the helper works those out itself.
type Request struct {
	V     int    `json:"v"`
	Op    string `json:"op"`
	Build string `json:"build,omitempty"`
	Kind  string `json:"kind,omitempty"`
}

// Reply answers one request.
type Reply struct {
	Status      string   `json:"status"`
	Code        string   `json:"code,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Protocol    int      `json:"protocol,omitempty"`
	Firecracker string   `json:"firecracker,omitempty"`
	Unit        string   `json:"unit,omitempty"`
	Chroot      string   `json:"chroot,omitempty"`
	Vsock       string   `json:"vsock,omitempty"`
	Active      *bool    `json:"active,omitempty"`
	OOMKills    *int     `json:"oomKills,omitempty"`
	Builds      []string `json:"builds,omitempty"`
}

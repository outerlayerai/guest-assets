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
	// OpRelink points a running build's jail at the runner's sockets as they are now, as a runner that starts again
	// needs. A helper from before this operation refuses it as bad-request.
	OpRelink = "relink"
	// OpDiscard gives the free blocks of a stopped builder microVM's cache disk back to the host. A helper from before
	// this operation refuses it as bad-request.
	OpDiscard = "discard"
	// OpCopy copies a build's disk to one new file in the build's directory, as the runner saves a state. A helper from
	// before this operation refuses it as bad-request.
	OpCopy = "copy"
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
	CodeNotRunning     = "not-running"
	CodeNoUser         = "no-free-user"
	CodeSystemd        = "systemd-failed"
	CodeInternal       = "internal"
)

// Limits on the time limit a start request names, in minutes. The upper bound
// is the longest runner.timeLimitMinutes the runner accepts.
const (
	MinTimeLimitMinutes = 1
	MaxTimeLimitMinutes = 1320
)

// Request is one JSON object on a connection. It names a build id, a kind and
// the runner's time limit, and never a path or a user: the helper works those
// out itself. A start request with no time limit gets a unit with no runtime
// limit.
type Request struct {
	V                int    `json:"v"`
	Op               string `json:"op"`
	Build            string `json:"build,omitempty"`
	Kind             string `json:"kind,omitempty"`
	TimeLimitMinutes int    `json:"timeLimitMinutes,omitempty"`
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
	FreedBytes  *int64   `json:"freedBytes,omitempty"`
	// CopiedBytes is the allocated size of the file a copy wrote.
	CopiedBytes *int64 `json:"copiedBytes,omitempty"`
}

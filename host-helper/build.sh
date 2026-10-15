#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Magu Studios, Inc.
#
# Builds the root helper reproducibly:
#   outerlayer-host-helper-x86_64  static root helper that starts each microVM
#                                  build under Firecracker's jailer
#
# Usage: packages/cli/host-helper/build.sh <out-dir>
#
# The helper is built in a container from an image pinned by digest, with
# fixed paths and build identities, so the same inputs give the same bytes.
# The sha256 line printed at the end is what packages/cli/src/runner/image/pins.ts
# pins as HOST_HELPER_SHA256. The image below is also the one the helper's Go
# tests run in when `go` is not installed (see host-helper-go.integration.test.ts).
set -euo pipefail

GO_IMAGE="golang:1.27.1@sha256:e0174e51e81218523251d85d248a90d24c3d5e81543b4f07a5d66229397db190"

# `build.sh --print-go-image` prints the pinned image and exits.
if [ "${1:-}" = "--print-go-image" ]; then
  echo "$GO_IMAGE"
  exit 0
fi

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <out-dir>" >&2
  exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$1"
out="$(cd "$1" && pwd)"

# The module has no root-only tests: the privileged calls are faked, and the file checks run on a temporary directory.
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GOFLAGS=-mod=readonly \
  -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
  -v "$here:/src:ro" -v "$out:/out" -w /src \
  "$GO_IMAGE" \
  sh -euc '
    go test ./...
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/outerlayer-host-helper-x86_64 .
  '

cd "$out"
sha256sum outerlayer-host-helper-x86_64

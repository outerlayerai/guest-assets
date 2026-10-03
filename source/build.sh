#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Magu Studios, Inc.
#
# Builds the guest artefacts reproducibly:
#   outerlayer-guest-x86_64  static guest helper (init, exec agent, relay)
#   vmlinux-x86_64           Firecracker guest kernel
#
# Usage: packages/cli/guest/build.sh <out-dir>
#
# Each artefact is built in a container from an image pinned by digest, with
# fixed paths, timestamps and build identities, so the same inputs give the
# same bytes. The sha256 lines printed at the end are what
# packages/cli/src/runner/image/pins.ts pins.
set -euo pipefail

GO_IMAGE="golang:1.27.1@sha256:e0174e51e81218523251d85d248a90d24c3d5e81543b4f07a5d66229397db190"
KERNEL_IMAGE="gcc:12.2.0@sha256:a3e091325c0af43bc9c1c576ddd155351d5b16438124421188bb4b4fcacc1452"
# The kernel image is Debian 11, whose live mirrors drop superseded package
# versions. A snapshot.debian.org timestamp serves the same build tools on
# every run, so the kernel's bytes do not drift with the mirror.
DEBIAN_SNAPSHOT="20260701T000000Z"

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <out-dir>" >&2
  exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$1"
out="$(cd "$1" && pwd)"

kernel_field() {
  sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$here/kernel/kernel.json"
}
kernel_url="$(kernel_field url)"
kernel_sha256="$(kernel_field sha256)"
kernel_version="$(kernel_field version)"
if [ -z "$kernel_url" ] || [ -z "$kernel_sha256" ] || [ -z "$kernel_version" ]; then
  echo "kernel/kernel.json must define version, url and sha256" >&2
  exit 1
fi

# Helper: unit tests first, then a static build with no build id or VCS stamp.
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GOFLAGS=-mod=readonly \
  -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
  -v "$here/helper:/src:ro" -v "$out:/out" -w /src \
  "$GO_IMAGE" \
  sh -euc '
    go test ./...
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/outerlayer-guest-x86_64 .
  '

# Kernel: build in a fixed directory so embedded paths do not vary.
docker run --rm \
  -e KERNEL_URL="$kernel_url" \
  -e KERNEL_SHA256="$kernel_sha256" \
  -e DEBIAN_SNAPSHOT="$DEBIAN_SNAPSHOT" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -v "$here/kernel/config-x86_64:/config-x86_64:ro" -v "$out:/out" \
  "$KERNEL_IMAGE" \
  bash -euo pipefail -c '
    rm -f /etc/apt/sources.list.d/*
    snapshot="http://snapshot.debian.org/archive"
    {
      echo "deb [check-valid-until=no] $snapshot/debian/$DEBIAN_SNAPSHOT bullseye main"
      echo "deb [check-valid-until=no] $snapshot/debian/$DEBIAN_SNAPSHOT bullseye-updates main"
      echo "deb [check-valid-until=no] $snapshot/debian-security/$DEBIAN_SNAPSHOT bullseye-security main"
    } > /etc/apt/sources.list
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends bc flex bison libelf-dev libssl-dev xz-utils perl >/dev/null

    mkdir -p /build
    curl -fsSL -o /build/linux.tar.xz "$KERNEL_URL"
    echo "$KERNEL_SHA256  /build/linux.tar.xz" | sha256sum -c -
    mkdir /build/linux
    tar -xf /build/linux.tar.xz -C /build/linux --strip-components=1
    cd /build/linux

    cp /config-x86_64 .config
    # Toolchain-derived symbols are regenerated from the compiler in use.
    toolchain_re="^CONFIG_(CC_VERSION_TEXT|GCC_VERSION|AS_VERSION|LD_VERSION|PAHOLE_VERSION)="
    grep -Ev "$toolchain_re" .config > /tmp/config.before
    make olddefconfig
    grep -Ev "$toolchain_re" .config > /tmp/config.after
    if ! diff -u /tmp/config.before /tmp/config.after; then
      echo "kernel/config-x86_64 is not a fixed point of make olddefconfig" >&2
      exit 1
    fi

    export KBUILD_BUILD_TIMESTAMP="Thu Jan  1 00:00:00 UTC 1970"
    export KBUILD_BUILD_USER=outerlayer
    export KBUILD_BUILD_HOST=outerlayer
    export KBUILD_BUILD_VERSION=1
    export SOURCE_DATE_EPOCH=0
    make -j"$(nproc)" vmlinux
    install -m 0755 vmlinux /out/vmlinux-x86_64
    chown "$HOST_UID:$HOST_GID" /out/vmlinux-x86_64
  '

cd "$out"
sha256sum vmlinux-x86_64 outerlayer-guest-x86_64

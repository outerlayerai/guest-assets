#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Magu Studios, Inc.
#
# Builds the builder microVM's root disk, builder-rootfs-x86_64.ext4, without Docker: the host must not run the
# recipe code that the builder exists to contain, and the disk is made on a machine that has no Docker.
#
# Usage: packages/cli/builder-disk/build.sh <out-dir> <guest-helper>
#
# <guest-helper> is the published outerlayer-guest-x86_64, the builder's PID 1. The disk holds BuildKit and a Docker
# engine, the devcontainer CLI, Node, the converter's tools (`mke2fs`, `tar`) and init.sh as /opt/outerlayer/builder-init.
# The file system is made from a pinned Debian snapshot with `mmdebstrap --mode=unshare`, which needs no root and no
# Docker, written as a tarball and packed with `mke2fs -d` in a user namespace, so every file keeps its owner. The last line prints the sha256 that
# packages/cli/src/runner/image/pins.ts pins as BUILDER_DISK_SHA256.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <out-dir> <guest-helper>" >&2
  exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$1"
out="$(cd "$1" && pwd)"
helper="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
# shellcheck source=pins.env
. "$here/pins.env"

for name in NODE DOCKER BUILDX DEVCONTAINER_CLI; do
  eval "sha=\${${name}_SHA256}"
  if [ -z "$sha" ]; then
    echo "pins.env holds no ${name}_SHA256; set it from the upstream release before you build the disk" >&2
    exit 1
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() { # url sha256 file
  curl -fsSL -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - >&2
}

fetch "$NODE_URL" "$NODE_SHA256" "$work/node.tar.xz"
fetch "$DOCKER_URL" "$DOCKER_SHA256" "$work/docker.tgz"
fetch "$BUILDX_URL" "$BUILDX_SHA256" "$work/buildx"
fetch "$DEVCONTAINER_CLI_URL" "$DEVCONTAINER_CLI_SHA256" "$work/devcontainer-cli.tgz"

# The Debian snapshot gives the same packages on every run, and SOURCE_DATE_EPOCH at the snapshot's time makes
# mmdebstrap's own files reproducible. Unshare mode runs as subordinate ids, so the tree comes out as a tarball, which
# records root as each file's owner. A directory would hold files owned by the subordinate ids.
snapshot_epoch="$(date -u -d "$(echo "$DEBIAN_SNAPSHOT" | sed -E 's/^(....)(..)(..)T(..)(..)(..)Z$/\1-\2-\3 \4:\5:\6/')" +%s)"
SOURCE_DATE_EPOCH="$snapshot_epoch" mmdebstrap --mode=unshare --variant=minbase \
  --include=ca-certificates,e2fsprogs,tar,xz-utils,iproute2,iptables,procps,util-linux,git,coreutils,findutils,sed,gawk \
  "$DEBIAN_SUITE" "$work/tree.tar" "http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/"

disk="$out/builder-rootfs-x86_64.ext4"
rm -f "$disk"
# The tree is unpacked and packed in a user namespace where this account is root and the subordinate ids map to the
# rest, so every file in the disk keeps the owner the tarball records. The tree is removed in the same namespace,
# since this account cannot remove files the subordinate ids own.
export work here helper disk
unshare --map-auto --map-root-user -- bash -euo pipefail -c '
tree="$work/tree"
mkdir "$tree"
tar -xf "$work/tree.tar" -C "$tree"
install -d "$tree/opt/node" "$tree/opt/outerlayer/bin" "$tree/opt/devcontainers-cli" "$tree/cache" "$tree/work" "$tree/out" "$tree/usr/local/lib/docker/cli-plugins"
tar -xJf "$work/node.tar.xz" -C "$tree/opt/node" --strip-components=1 --no-same-owner
tar -xzf "$work/docker.tgz" -C "$work" --no-same-owner
install -m 0755 "$work"/docker/* "$tree/usr/local/bin/"
install -m 0755 "$work/buildx" "$tree/usr/local/lib/docker/cli-plugins/docker-buildx"
tar -xzf "$work/devcontainer-cli.tgz" -C "$tree/opt/devcontainers-cli" --strip-components=1 --no-same-owner
ln -s /opt/node/bin/node "$tree/usr/local/bin/node"
ln -s /opt/devcontainers-cli/devcontainer.js "$tree/usr/local/bin/devcontainer"
install -m 0755 "$helper" "$tree/opt/outerlayer/bin/outerlayer-guest"
install -m 0755 "$here/init.sh" "$tree/opt/outerlayer/builder-init"

# Fixed times, and a size from file sizes rather than the host file system blocks, so the same inputs give the same
# bytes on any host.
find "$tree" -exec touch -h -d "@0" {} +
size_kb=$(( $(du -s --apparent-size -k "$tree" | cut -f1) * 5 / 4 + 131072 ))
truncate -s "${size_kb}K" "$disk"
SOURCE_DATE_EPOCH=0 mke2fs -q -F -t ext4 -m 0 -U 00000000-0000-0000-0000-000000000000 -E hash_seed=00000000-0000-0000-0000-000000000000 -d "$tree" "$disk"
rm -rf "$tree"
'
echo "builder-rootfs-x86_64.ext4 sha256 $(sha256sum "$disk" | cut -d' ' -f1)"

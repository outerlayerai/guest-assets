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

# mke2fs before 1.47.1 stamps the current time into the disk and each inode, and picks a random directory hash seed,
# whatever SOURCE_DATE_EPOCH and -E hash_seed say. Such a disk differs on every build, so it is refused here.
e2fs_version="$(mke2fs -V 2>&1 | sed -n 's/^mke2fs \([0-9.]*\).*/\1/p')"
if [ "$(printf '%s\n' "$e2fs_version" 1.47.1 | sort -V | head -1)" != 1.47.1 ]; then
  echo "mke2fs ${e2fs_version:-of unknown version} cannot make a reproducible disk; use e2fsprogs 1.47.1 or later" >&2
  exit 1
fi

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
# records root as each file's owner. A directory would hold files owned by the subordinate ids. Debian's signing keys
# come from the host's debian-archive-keyring package, so apt checks every package it fetches.
snapshot_epoch="$(date -u -d "$(echo "$DEBIAN_SNAPSHOT" | sed -E 's/^(....)(..)(..)T(..)(..)(..)Z$/\1-\2-\3 \4:\5:\6/')" +%s)"
SOURCE_DATE_EPOCH="$snapshot_epoch" mmdebstrap --mode=unshare --variant=minbase \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  --include=ca-certificates,e2fsprogs,tar,xz-utils,iproute2,iptables,procps,util-linux,git,coreutils,findutils,sed,gawk \
  "$DEBIAN_SUITE" "$work/tree.tar" "http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/"
echo "debian tarball sha256 $(sha256sum "$work/tree.tar" | cut -d" " -f1)" >&2

disk="$out/builder-rootfs-x86_64.ext4"
rm -f "$disk"
# The tree is unpacked and packed in a user namespace where this account is root and the subordinate ids map to the
# rest, so every file in the disk keeps the owner the tarball records. The tree is a tmpfs
# that goes away with the namespace, since this account cannot remove files the subordinate ids own.
export work here helper disk BUILDER_DISK_DIAG
unshare --map-auto --map-root-user --mount -- bash -euo pipefail -c '
tree="$work/tree"
mkdir "$tree"
# A tmpfs lists a directory in the order its entries were made, and mke2fs -d adds files in listing order. A disk
# file system lists them in hash order, which differs from host to host, so the tree is built in memory.
mount -t tmpfs -o size=4g tmpfs "$tree"
# Device files are left out: a user namespace cannot make them, and the guest helper mounts devtmpfs at /dev.
tar -xf "$work/tree.tar" -C "$tree" --exclude="./dev/*"
# mmdebstrap copies the host'"'"'s hostname and resolv.conf into the tree. The builder'"'"'s init sets both at boot, so the
# disk holds the same values on every host.
printf "outerlayer-builder\n" > "$tree/etc/hostname"
printf "# This microVM has no network device. Names are resolved by the runner'"'"'s proxy.\n" > "$tree/etc/resolv.conf"
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

# Fixed times, a fixed directory hash seed, and a size from file sizes rather than the host file system blocks, so the same inputs give the same
# bytes on any host. The seed is not all zeros: mke2fs reads an all-zero seed as unset and picks a random one.
find "$tree" -exec touch -h -d "@0" {} +
size_kb=$(( $(du -s --apparent-size -k "$tree" | cut -f1) * 5 / 4 + 131072 ))
truncate -s "${size_kb}K" "$disk"
SOURCE_DATE_EPOCH=0 mke2fs -q -F -t ext4 -m 0 -U 00000000-0000-0000-0000-000000000000 -E hash_seed=00000000-0000-0000-0000-000000000001 -d "$tree" "$disk"
if [ -n "${BUILDER_DISK_DIAG:-}" ]; then
  (cd "$tree" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) > "$BUILDER_DISK_DIAG/contents.txt"
  tar -tvf "$work/tree.tar" --full-time > "$BUILDER_DISK_DIAG/tarball-list.txt"
fi
echo "tree manifest sha256 $(cd "$tree" && find . -printf "%p %m %U %G %s %l\n" | LC_ALL=C sort | sha256sum | cut -d" " -f1)" >&2
umount "$tree"
'
echo "builder-rootfs-x86_64.ext4 sha256 $(sha256sum "$disk" | cut -d' ' -f1)"

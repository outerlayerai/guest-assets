#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Magu Studios, Inc.
#
# The builder microVM's init. The guest helper (PID 1) has mounted the kernel's file systems and /run, and runs this
# program in place of the build's `vm-init`. The root disk is read-only, so everything the build writes goes to the
# cache disk (/dev/vdb) or to /run and /tmp, which are memory.
#
# The microVM has no network device. The relay below carries loopback connections on the tunnel's port over vsock to the
# runner's tunnel, which is the only way out. The runner unpacks the repository into /work, runs the build script with
# the exec agent, and reads /out/rootfs.ext4 back.
set -eu

mount -t tmpfs -o mode=1777 tmpfs /tmp
# The disk is the repository's layer cache and holds nothing that cannot be rebuilt. A disk that does not mount, for
# example one a killed builder left damaged, is made again so that it does not fail every later build.
if ! mount -t ext4 /dev/vdb /cache; then
  mke2fs -q -F -t ext4 -m 0 /dev/vdb
  mount -t ext4 /dev/vdb /cache
fi
# Docker's data under /cache/docker stays, as the layer cache. What the last builder left in /work and /out is not kept.
rm -rf /cache/work /cache/out /cache/rootfs
# A disk that is nearly full is emptied once the last build's output is gone: a build that fills it fails, and so would the next one.
set -- $(df -P /cache | tail -n 1)
full=${5%\%}
if [ "$full" -ge 90 ]; then
  rm -rf /cache/docker
fi
mkdir -p /cache/work/repo /cache/work/tools /cache/work/recipe /cache/out /run/builder
mount --bind /cache/work /work
mount --bind /cache/out /out

hostname outerlayer-builder
printf '127.0.0.1 localhost\n::1 localhost\n' > /run/builder/hosts
mount --bind /run/builder/hosts /etc/hosts
printf '# This microVM has no network device. Names are resolved by the runner'"'"'s proxy.\n' > /run/builder/resolv.conf
mount --bind /run/builder/resolv.conf /etc/resolv.conf

/opt/outerlayer/bin/outerlayer-guest relay --forward 3128 &
exec /opt/outerlayer/bin/outerlayer-guest exec-agent --port 1024

# OuterLayer guest assets

The guest kernel and guest helper that OuterLayer microVM builds boot, and
the root helper that starts those microVMs under Firecracker's jailer.

A runner with `builtin:vm` hooks runs each build in a Firecracker microVM.
The first time it needs them, it downloads two files from this repository's
releases:

- `vmlinux-x86_64`: a Linux 6.1 kernel built from `source/kernel/`.
- `outerlayer-guest-x86_64`: a static helper built from `source/helper/`. It
  is the microVM's init, runs the build's commands, and relays its
  connections to the runner over vsock.

`outerlayer runner install --service` downloads a third file:

- `outerlayer-host-helper-x86_64`: a static root helper built from
  `host-helper/`. It runs as root and starts each microVM build under
  Firecracker's jailer, as a user made for that build.

The CLI checks each file against a sha256 it pins. A guest file that differs
fails the build before any microVM starts. A root helper that differs is not
installed.

## How a release is made

`source/` is a copy of `packages/cli/guest/` in the OuterLayer repository.
`host-helper/` is a copy of `packages/cli/host-helper/`. `SHA256SUMS` holds
the hashes the CLI pins.

Pushing a tag `guest-<version>` runs `.github/workflows/publish.yml`. It:

1. builds the kernel and the guest helper with `source/build.sh`, and the
   root helper with `host-helper/build.sh`, which runs the root helper's
   tests first;
2. fails unless all three files match `SHA256SUMS`;
3. publishes a release with the three files, the kernel config, the Linux
   source the kernel was built from, the source of both helpers, and
   `SHA256SUMS`;
4. records a signed build provenance attestation for the three files.

A CLI release names the release it reads each file from. The guest files and
the root helper can come from different releases.

Releases are immutable once published.

## Building it yourself

`source/build.sh` builds the kernel and the guest helper. `host-helper/build.sh`
builds the root helper. Both build in containers pinned by digest, with fixed
paths, timestamps and package versions, so the same inputs give the same
bytes. They need Docker on Linux x86_64.

```sh
bash source/build.sh out
bash host-helper/build.sh out
(cd out && sha256sum -c ../SHA256SUMS)
```

To check a published release's provenance:

```sh
gh attestation verify vmlinux-x86_64 --repo outerlayerai/guest-assets
```

## Licenses

- The guest helper, the root helper and the build scripts are Apache-2.0.
  See `LICENSE`.
- The kernel is Linux, licensed GPL-2.0. Each release carries the exact
  Linux source tarball and kernel config it was built from.

## The builder disk

A runner with `builtin:vm` hooks builds a repository's image in a builder
microVM, so no step of the repository's recipe runs on the host. The
builder microVM boots the guest kernel above with a fourth file as its root
disk:

- `builder-rootfs-x86_64.ext4`: a Debian file system built from
  `builder-disk/`. It holds BuildKit, a Docker engine, the devcontainer CLI,
  Node, the guest helper and the builder's init.

`builder-disk/` is a copy of `packages/cli/builder-disk/` in the OuterLayer
repository. `builder-disk/pins.env` pins every download by sha256, and the
Debian packages come from a fixed snapshot, so the same inputs give the same
disk. `SHA256-builder` holds the hash the CLI pins as `BUILDER_DISK_SHA256`.

Pushing a tag `builder-<version>` runs `.github/workflows/publish-builder.yml`.
It builds the disk twice and fails unless both builds match each other and
`SHA256-builder`. Then it publishes a release with the disk, its source and
`SHA256-builder`, and records a signed build provenance attestation for the
disk. A pull request that changes `builder-disk/` runs the same two builds
and shows the disk's hash in the job summary.

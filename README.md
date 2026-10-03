# OuterLayer guest assets

The guest kernel and guest helper that OuterLayer microVM builds boot.

A runner with `builtin:vm` hooks runs each build in a Firecracker microVM.
The first time it needs them, it downloads two files from this repository's
releases:

- `vmlinux-x86_64`: a Linux 6.1 kernel built from `source/kernel/`.
- `outerlayer-guest-x86_64`: a static helper built from `source/helper/`. It
  is the microVM's init, runs the build's commands, and relays its
  connections to the runner over vsock.

The runner checks each file against a sha256 pinned in the `outerlayer` CLI.
A file that differs fails the build before any microVM starts.

## How a release is made

`source/` is a copy of `packages/cli/guest/` in the OuterLayer repository.
`SHA256SUMS` holds the hashes the CLI pins.

Pushing a tag `guest-<version>` runs `.github/workflows/publish.yml`. It:

1. builds both files with `source/build.sh`;
2. fails unless they match `SHA256SUMS`;
3. publishes a release with the two files, the kernel config, the Linux
   source the kernel was built from, the helper's source, and `SHA256SUMS`;
4. records a signed build provenance attestation for both files.

Releases are immutable once published.

## Building it yourself

`source/build.sh` builds both files in containers pinned by digest, with
fixed paths, timestamps and package versions, so the same inputs give the
same bytes. It needs Docker on Linux x86_64.

```sh
bash source/build.sh out
(cd out && sha256sum -c ../SHA256SUMS)
```

To check a published release's provenance:

```sh
gh attestation verify vmlinux-x86_64 --repo outerlayerai/guest-assets
```

## Licenses

- The guest helper and the build script are Apache-2.0. See `LICENSE`.
- The kernel is Linux, licensed GPL-2.0. Each release carries the exact
  Linux source tarball and kernel config it was built from.

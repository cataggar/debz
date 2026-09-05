# debz

An embeddable Debian-family package manager library and CLI written in Zig.

## Install

```sh
ghr install cataggar/debz@v0.2.0
```

Release binaries are fully static Linux x64 or arm64 executables with Zig
0.16.0's reviewed musl snapshot and source-built libsolv, liblzma, and libzstd
included. Gzip and xz binary archives are covered by GitHub provenance
attestations.

### GitHub Actions

Install one exact release with the first-party setup action:

```yaml
- id: debz
  uses: cataggar/debz/actions/setup@<reviewed-commit-sha>
  with:
    debz-version: v0.3.0
- run: '"${{ steps.debz.outputs.debz-path }}" version'
```

The action verifies the GitHub asset digest plus either GitHub/Sigstore release
provenance or an explicitly supplied trusted SHA-256, extracts without host
archive tools, and revalidates exact cache hits. See
[`actions/setup/README.md`](actions/setup/README.md) for pinning, permissions,
trust, cache, platform, and container details.

## Build

```sh
zig build
zig build test
zig build run -- --help
zig build -Dversion=0.3.0
zig build install --prefix "$PWD/install-root"
zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe \
  release-install --prefix "$PWD/release-root"
```

## Add a system repository

Repository descriptors are installed through the separate repository-management
surface:

```sh
sudo debz repo add \
  --url https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
```

The target defaults to `/`; `--root PATH` selects an isolated image root.
Repository add is noninteractive, refreshes by default, and never invokes apt.
Use `--sha256` to pin the descriptor or `--no-refresh` to defer the final
metadata refresh. See
[`doc/repository-management.md`](doc/repository-management.md).

## Install SymCrypt on Ubuntu 24.04

For the Microsoft Noble repository, the supported system workflow is:

```sh
sudo debz repo add \
  --url https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
sudo debz install symcrypt-openssl
```

The second command resolves and installs both `symcrypt-openssl` and its
declared `symcrypt` dependency. `sudo debz install symcrypt` installs only the
core package closure. System product commands default to `/`,
`/var/cache/debz`, `/var/lib/debz`, `/var/lib/debz/locks`, the target dpkg
architecture, and the active repository configuration published by
`repo add`. A durable exact lock is published before dpkg and its path, plus
the retained provenance/recovery paths, is reported in human and JSON output.

The packages provide system-wide SymCrypt and the OpenSSL integration. They do
not replace `zig-symcrypt` pinned build inputs: the Microsoft packages provide
SymCrypt 103.11.0, no static archives, and no `libsymcrypt_plus.a`.

`-Dversion` must be a SemVer value and defaults to the package version in `build.zig.zon`. An ordinary install places the target-selected CLI in `bin/`, documentation under `share/doc/debz/`, and schemas under `share/debz/`. The dedicated static-musl `release-install` graph additionally installs reviewed release runtime metadata.

See [`doc/README.md`](doc/README.md) for the CLI, library, JSON, security, and implementation reference. Licensed under [Apache-2.0](LICENSE).

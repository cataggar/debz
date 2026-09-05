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

Prepare the complete package closure from a reviewed exact lock without
installing it:

```yaml
- uses: cataggar/debz/actions/download@<reviewed-commit-sha>
  id: packages
  with:
    lock-input: .github/debz/noble-amd64.lock.json
    config: .github/debz/noble.json
    keyring: .github/debz/ubuntu-archive-keyring.gpg
    architecture: amd64
```

The download action caches only verified `packages-v1/objects`. Exact and
compatible-prefix restores are always revalidated by `debz`; repository
metadata, credentials, keyrings, roots, dpkg state, and transaction journals
are excluded. A cache hit is not installed state. See
[`actions/download/README.md`](actions/download/README.md) for the complete
input/output, offline, repair, and trust contract.

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

`-Dversion` must be a SemVer value and defaults to the package version in `build.zig.zon`. An ordinary install places the target-selected CLI in `bin/`, documentation under `share/doc/debz/`, and schemas under `share/debz/`. The dedicated static-musl `release-install` graph additionally installs reviewed release runtime metadata.

See [`doc/README.md`](doc/README.md) for the CLI, library, JSON, security, and implementation reference. Licensed under [Apache-2.0](LICENSE).

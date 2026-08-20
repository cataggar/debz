# debz

An embeddable Debian-family package manager library and CLI written in Zig.

## Install

Install a published Linux x64 or arm64 release with `ghr install cataggar/debz@v0.1.0`. The dynamically linked binary requires glibc; liblzma and libzstd are included as source-built static libraries. Gzip and xz archives include checksums and SPDX SBOMs and are covered by GitHub provenance attestations. Artifacts and checksum files are unsigned.

## Build

```sh
zig build
zig build test
zig build run -- --help
zig build -Dversion=0.1.0
zig build install --prefix "$PWD/release-root"
```

`-Dversion` must be a SemVer value and defaults to the package version in `build.zig.zon`. A complete install places the CLI in `bin/`, documentation under `share/doc/debz/`, and schemas plus runtime dependency metadata under `share/debz/`.

See [`doc/README.md`](doc/README.md) for the CLI, library, JSON, security, and implementation reference. Licensed under [Apache-2.0](LICENSE).

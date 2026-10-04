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

## Build

This source compatibility branch requires Zig 0.17.0 (Linux 5.10+ or
macOS 15+). It retains the exact package acquisition, offline closure, lock,
and deadline behavior of `4d3fc47`; released binaries and package inputs are
not republished or refreshed. C declarations use the exact GitHub
`cataggar/translate-c` revision recorded in `build.zig.zon`.
CI on this compatibility branch is manual-only; neither CI nor release
publication is dispatched as part of the source port.

```sh
zig build
zig build test
zig build run -- --help
zig build -Dversion=0.3.0
zig build install --prefix "$PWD/install-root"
zig build -Dtarget=x86_64-linux-musl -Doptimize=safe \
  release-install --prefix "$PWD/release-root"
```

`-Dversion` must be a SemVer value and defaults to the package version in `build.zig.zon`. An ordinary install places the target-selected CLI in `bin/`, documentation under `share/doc/debz/`, and schemas under `share/debz/`. The dedicated static-musl `release-install` graph additionally installs reviewed release runtime metadata.

See [`doc/README.md`](doc/README.md) for the CLI, library, JSON, security, and implementation reference. Licensed under [Apache-2.0](LICENSE).

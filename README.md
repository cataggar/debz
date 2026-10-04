# debz

An embeddable Debian-family package manager library and CLI written in Zig.

## Install

```sh
ghr install cataggar/debz@v0.2.0
```

Release binaries are fully static Linux x64 or arm64 executables with Zig
0.17.0's reviewed musl snapshot and source-built libsolv, liblzma, and libzstd
included. Gzip and xz binary archives are covered by GitHub provenance
attestations.

## Build

Use Zig 0.17.0. The `zig016-miz-compat` branch preserves the miz-pinned
embedded API and implementation rather than importing unrelated changes from
newer main. C bindings are generated with the audited `translate_c` revision
`62d06a5d3e93c82727544e8113e4762a315ca0ed`; the native solver and compression
libraries remain source-built and in-process.

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

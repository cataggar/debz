# debz

An embeddable Debian-family package manager library and CLI written in Zig.

## Install

Install the latest published Linux x64 or arm64 release with `ghr install cataggar/debz@v0.1.0`. Release binaries are fully static executables with Zig 0.16.0's reviewed musl snapshot and source-built libsolv, liblzma, and libzstd included. Gzip and xz archives include checksums and SPDX SBOMs and are covered by GitHub provenance attestations. Artifacts and checksum files are unsigned.

## Build

This source compatibility branch requires Zig 0.17.0 (Linux 5.10+ or
macOS 15+). It retains the exact package acquisition, offline closure, lock,
and deadline behavior of the vmiz-pinned debz 0.2 generation `9cabfc0`;
released binaries and package inputs are
not republished or refreshed. C declarations use the exact GitHub
`cataggar/translate-c` revision recorded in `build.zig.zon`.
CI on this compatibility branch is manual-only; neither CI nor release
publication is dispatched as part of the source port.
The compiler migration reuses the changes from
[PR #383](https://github.com/cataggar/debz/pull/383), without importing the
later package-management features, CLI changes, or unbounded-deadline policy
of the debz 0.3 generation. Native ARM and macOS runtime checks remain
consumer/platform gates.
Both local `zig build test -j2` graphs (default and `-Doptimize=safe`) pass
39/39 steps and 249/249 tests. Actual static safe-mode CLI builds pass for
`x86_64-linux-musl` and `aarch64-linux-musl`; the native CLI still reports
version 0.2.0 through its original `--version` command.

```sh
zig build
zig build test
zig build run -- --help
zig build -Dversion=0.2.0
zig build install --prefix "$PWD/install-root"
zig build -Dtarget=x86_64-linux-musl -Doptimize=safe \
  release-install --prefix "$PWD/release-root"
```

`-Dversion` must be a SemVer value and defaults to the package version in `build.zig.zon`. An ordinary install places the target-selected CLI in `bin/`, documentation under `share/doc/debz/`, and schemas under `share/debz/`. The dedicated static-musl `release-install` graph additionally installs reviewed release runtime metadata.

See [`doc/README.md`](doc/README.md) for the CLI, library, JSON, security, and implementation reference. Licensed under [Apache-2.0](LICENSE).

# Release installation

`zig build install --prefix <path>` preserves the target-selected ordinary
install tree:

- `bin/debz`
- `share/doc/debz/README.md`, `LICENSE`, and `THIRD_PARTY_NOTICES`
- `share/doc/debz/doc/*.md` and linked schema copies
- `share/debz/schema/*.json`

`zig build release-install --prefix <path>` is the dedicated static-musl
packaging graph. It includes the ordinary tree plus
`share/debz/runtime-dependencies.json`. GNU and other ordinary target installs
do not receive that release-only manifest and therefore do not claim the
static-musl runtime model; attempting `release-install` for a non-Linux-musl
target fails. Documentation, notices, metadata, and schemas are installed with
mode `0644`; the built CLI is installed with mode `0755`.

The release version defaults to the `build.zig.zon` package version. Override
it with a valid SemVer value such as `-Dversion=0.1.0-rc.1`. The same value is
available as `debz.version` to Zig consumers and is printed verbatim by
`debz --version`.

Published Linux x64 and arm64 release binaries are fully static executables.
They include MIT-licensed musl from the exact Zig 0.16.0 toolchain snapshot
`1.2.5+zig.0.16.0.24fdd5b7a4c1`, BSD-licensed libsolv and libzstd, and
0BSD-licensed liblzma, with no target-system shared-library requirement. The
musl identifier records the upstream 1.2.5 baseline plus the exact modified Zig
toolchain revision; it does not claim an unmodified upstream musl release.
Machine-readable details and reviewed exact versions are in the release-only
`share/debz/runtime-dependencies.json`.

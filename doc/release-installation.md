# Release installation

`zig build install --prefix <path>` installs the complete release tree:

- `bin/debz`
- `share/doc/debz/README.md`, `LICENSE`, and `THIRD_PARTY_NOTICES`
- `share/doc/debz/doc/*.md` and linked schema copies
- `share/debz/schema/*.json`
- `share/debz/runtime-dependencies.json`

`zig build release-install --prefix <path>` is an equivalent named step for
packaging tools. Documentation, notices, metadata, and schemas are installed
with mode `0644`; the built CLI is installed with mode `0755`.

The release version defaults to the `build.zig.zon` package version. Override
it with a valid SemVer value such as `-Dversion=0.1.0-rc.1`. The same value is
available as `debz.version` to Zig consumers and is printed verbatim by
`debz --version`.

Linux release binaries are not fully static. They dynamically require the
target glibc ABI, liblzma, and libzstd. BSD-licensed libsolv is included as a
static archive. Machine-readable details and reviewed version bounds are in
`share/debz/runtime-dependencies.json`.

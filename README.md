# debz

`debz` is an in-development, embeddable Debian-family package manager and CLI written in Zig. It will own repository configuration, verified metadata acquisition, dependency solving, downloads, transaction planning, and diagnostics while using `dpkg` as the transaction backend.

The project currently exposes typed configuration and request APIs, a CLI command vocabulary, a bounded parser/AST for Debian binary package relations, and a bounded validator for Debian binary package outer archives.

`debz.deb_archive.parse` validates the outer `ar` structure, required members, `debian-binary` version marker, supported compression suffixes, and configured archive/member/count limits. It returns borrowed member byte ranges and metadata without copying, decompressing, or unpacking files. Validation of the compressed streams and inner tar archives is separate follow-up work; callers must not treat outer-archive validation alone as package-content validation.

`debz.dpkg_status` parses only caller-supplied status bytes or explicit paths. It preserves source diagnostics and models package identity, exact Debian versions, installation states, package flags, dependency relations, and installed size without implicitly reading the host dpkg database.

## Dependency solver

The public `SolverContext` adapter owns an empty libsolv pool and solver while keeping libsolv C types out of the debz API. Debian repository parsing and dependency semantics are not implemented yet.

The pinned libsolv Zig build currently leaves `LIBSOLVEXT_FEATURE_DEBIAN` disabled and does not compile `ext/repo_deb.c`. Enabling and validating Debian semantics is follow-up work; this initial integration intentionally does not carry a broad libsolv fork.

## Requirements

- Zig 0.16.0 or newer

## Build and test

```sh
zig build
zig build test
zig build run -- --help
```

## License

Apache-2.0.

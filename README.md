# debz

`debz` is an in-development, embeddable Debian-family package manager and CLI written in Zig. It will own repository configuration, verified metadata acquisition, dependency solving, downloads, transaction planning, and diagnostics while using `dpkg` as the transaction backend.

The project currently exposes typed configuration and request APIs, a CLI command vocabulary, a bounded parser/AST for Debian binary package relations, and a bounded validator for Debian binary package outer archives.

`debz.deb_archive.parse` validates the outer `ar` structure, required members, `debian-binary` version marker, supported compression suffixes, and configured archive/member/count limits. It returns borrowed member byte ranges and metadata without copying, decompressing, or unpacking files. Validation of the compressed streams and inner tar archives is separate follow-up work; callers must not treat outer-archive validation alone as package-content validation.

`debz.dpkg_status` parses only caller-supplied status bytes or explicit paths. It preserves source diagnostics and models package identity, exact Debian versions, installation states, package flags, dependency relations, and installed size without implicitly reading the host dpkg database.

## Dependency solver

The public `SolverContext` adapter owns an empty libsolv pool and solver while keeping libsolv C types out of the debz API. The pinned libsolv core is built with Debian EVR and dependency semantics. The current adapter does not load repositories, so libsolvext, repository loaders, compression backends, tools, conda, and multi-distribution semantics are explicitly disabled.

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

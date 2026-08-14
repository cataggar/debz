# debz

`debz` is an in-development, embeddable Debian-family package manager and CLI written in Zig. It will own repository configuration, verified metadata acquisition, dependency solving, downloads, transaction planning, and diagnostics while using `dpkg` as the transaction backend.

The project currently exposes typed configuration and request APIs, a CLI command vocabulary, and a bounded parser/AST for Debian binary package relations. The relation parser preserves source spans and version text while parsing dependency groups, alternatives, package architecture qualifiers, and version predicates. It does not yet modify packages or repositories.

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

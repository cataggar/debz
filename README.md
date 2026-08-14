# debz

`debz` is an in-development, embeddable Debian-family package manager and CLI written in Zig. It will own repository configuration, verified metadata acquisition, dependency solving, downloads, transaction planning, and diagnostics while using `dpkg` as the transaction backend.

The project currently exposes typed configuration and request APIs, a CLI command vocabulary, bounded parsers for DEB822, Debian versions, binary package relations, control records and repository `Release` metadata, typed repository source configuration, and a bounded validator for Debian binary package outer archives. The control-record model validates required identity fields and typed scalar values, preserves unknown fields and source spans, and keeps relation policy decisions separate from syntax parsing.

`debz.deb_archive.parse` validates the outer `ar` structure, required members, `debian-binary` version marker, supported compression suffixes, and configured archive/member/count limits. It returns borrowed member byte ranges and metadata without copying, decompressing, or unpacking files. Validation of the compressed streams and inner tar archives is separate follow-up work; callers must not treat outer-archive validation alone as package-content validation.

`debz.dpkg_status` parses only caller-supplied status bytes or explicit paths. It preserves source diagnostics and models package identity, exact Debian versions, installation states, package flags, dependency relations, and installed size without implicitly reading the host dpkg database.

Repository sources can be supplied explicitly as canonical `.sources` stanzas or legacy `deb`/`deb-src` lines; parsing never consults host APT configuration. Parsed sources preserve spans, enforce caller-configurable bounds, and receive deterministic IDs from their normalized declared values. The project does not yet modify packages or repositories.

`debz.release_metadata` parses caller-supplied `Release` bytes into typed identity, timestamp, architecture, component, by-hash, and SHA-256 index data. It validates normalized relative index paths and bounded checksum rows. Timestamps retain their declared civil time and UTC offset; expiration and other clock policy remain caller decisions. MD5, SHA-1, and unknown fields are never promoted into trusted checksum records.

`debz.metadata_cache` provides an explicit-root, versioned verified-metadata cache. Objects are addressed by SHA-256, repository/snapshot manifests are atomically published only after size and digest verification, cache-only reads reverify referenced bytes, and bounded garbage collection preserves manifest references. It does not perform network refreshes or use ambient host cache directories.

`debz.repository_acquisition` fetches bounded bytes from explicit `file:`, HTTP, or HTTPS URIs. Callers provide proxy, credential, redirect, retry, deadline, clock, and size policies; production HTTPS verifies certificates and hostnames, while injectable transport and file seams support hermetic tests. Provenance contains only redacted effective URIs.

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

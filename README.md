# debz

## Deterministic transaction planning

`debz.planTransaction` is the public typed planning API. It accepts authenticated
repository snapshots, parsed dpkg state, explicit package policy, architecture,
request, solver policy, and limits. The returned plan owns its data and can be
serialized with `canonicalJson`; schema version 1 is documented in
`schema/transaction-plan-v1.json`.

Planning only computes actions. It does **not** download package archives,
modify the filesystem, or execute dpkg.

`debz` is an in-development, embeddable Debian-family package manager and CLI written in Zig. It will own repository configuration, verified metadata acquisition, dependency solving, downloads, transaction planning, and diagnostics while using `dpkg` as the transaction backend.

The project currently exposes typed configuration and request APIs, a CLI command vocabulary, bounded parsers for DEB822, Debian versions, binary package relations, control records and repository `Release` metadata, typed repository source configuration, and a bounded validator for Debian binary package outer archives. The control-record model validates required identity fields and typed scalar values, preserves unknown fields and source spans, and keeps relation policy decisions separate from syntax parsing.

`debz.deb_archive.parse` validates the outer `ar` structure, required members, `debian-binary` version marker, supported compression suffixes, and configured archive/member/count limits. It returns borrowed member byte ranges and metadata without copying, decompressing, or unpacking files. Validation of the compressed streams and inner tar archives is separate follow-up work; callers must not treat outer-archive validation alone as package-content validation.

`debz.dpkg_status` parses only caller-supplied status bytes or explicit paths. It preserves source diagnostics and models package identity, exact Debian versions, installation states, package flags, dependency relations, and installed size without implicitly reading the host dpkg database.

Repository sources can be supplied explicitly as canonical `.sources` stanzas or legacy `deb`/`deb-src` lines; parsing never consults host APT configuration. Parsed sources preserve spans, enforce caller-configurable bounds, and receive deterministic IDs from their normalized declared values. The project does not yet modify packages or repositories.

`debz.release_metadata` parses caller-supplied `Release` bytes into typed identity, timestamp, architecture, component, by-hash, and SHA-256 index data. It validates normalized relative index paths and bounded checksum rows. Timestamps retain their declared civil time and UTC offset; expiration and other clock policy remain caller decisions. MD5, SHA-1, and unknown fields are never promoted into trusted checksum records.

`debz.metadata_cache` provides an explicit-root, versioned verified-metadata cache. Objects are addressed by SHA-256, repository/snapshot manifests are atomically published only after size and digest verification, cache-only reads reverify referenced bytes, and bounded garbage collection preserves manifest references. It does not perform network refreshes or use ambient host cache directories.

`debz.repository_acquisition` fetches bounded bytes from explicit `file:`, HTTP, or HTTPS URIs. Callers provide proxy, credential, redirect, retry, deadline, clock, and size policies; production HTTPS verifies certificates and hostnames, while injectable transport and file seams support hermetic tests. Provenance contains only redacted effective URIs.

`debz.metadata_decompression` provides allocator-owned, bounded decompression
for gzip, xz, and zstd repository metadata. Callers must explicitly select the
format or derive it from a trusted selected filename; content magic is never
used as a fallback. Compressed size, decompressed size, decoder memory, and an
optional expected decompressed size are checked before a result is returned.
gzip and zstd use Zig's standard library. xz uses the system liblzma streaming
API with a caller-bounded memory limit and full integrity checking.

`debz.repository_refresh` composes bounded acquisition, `Release` and
`Packages` parsing, SHA-256/size checks, Acquire-By-Hash, bounded
decompression, and atomic cache publication into a complete snapshot refresh.
Plain `Release` acquisition is explicitly `unauthenticated` and its result is
not solver-eligible. `refreshAuthenticated` acquires and strictly parses either
clearsigned `InRelease` or detached `Release` plus `Release.gpg`, then verifies
the exact OpenPGP signed bytes before parsing trusted fields. Callers must
provide explicit keyring bytes or paths, accepted primary fingerprints, and a
verification time; ambient GnuPG configuration, keyrings, homes, and network
key discovery are never consulted. Authenticated cache-only loads reverify the
stored envelope and signatures under the current caller policy. Only the
distinct `AuthenticatedResult` type can be converted with
`SolverRepositoryInput.fromRefresh`. See
[`docs/authenticated-refresh.md`](docs/authenticated-refresh.md).

`debz.openpgp_verifier` provides the separate, in-process repository-signature
boundary. It accepts only caller-supplied signed bytes, binary OpenPGP signature
packets, and explicit keyring bytes or paths. The current documented profile is
OpenPGP v4 RSA and legacy Ed25519 with SHA-256/SHA-512, matching current Debian
and Ubuntu archive signing. Parsing and policy are bounded, issuer hints never replace
cryptographic verification, and accepted/rejected outcomes retain deterministic
per-signature diagnostics. It performs no network lookup, process spawning, or
ambient keyring/home-directory access. See
[`docs/openpgp-verifier.md`](docs/openpgp-verifier.md) for the exact profile and
backend/license decision.

## Dependency solver

The public `SolverContext` adapter owns a Debian-configured libsolv pool while
keeping all libsolv C types and IDs private. It imports explicitly identified
and prioritized typed `Packages` indexes only when their solver-eligibility is
marked as verified (or explicitly trusted test data). Imported package origins
are retained as debz-owned identities for future diagnostics and planning.
Dependencies, pre-dependencies, alternatives, version predicates, provides,
conflicts, breaks, replaces, and separately represented recommends are mapped;
unsupported qualifiers fail with typed errors. Transaction planning is not yet
part of this API.

## Requirements

- Zig 0.16.0 or newer
- liblzma development headers and library

## Build and test

```sh
zig build
zig build test
zig build run -- --help
```

## License

Apache-2.0.

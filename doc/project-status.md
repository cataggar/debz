# Project status and API overview

`debz` is an in-development, embeddable Debian-family package manager and CLI written in Zig. It owns repository configuration, verified metadata acquisition, dependency solving, downloads, transaction planning, diagnostics, and an install-root-aware `dpkg` execution boundary.

Required PR tests now exercise deterministic signed Debian stable and Ubuntu
26.04 fixture repositories and disposable dpkg roots on native amd64 and arm64.
Scheduled/manual lanes add foreign-architecture roots; see
[Hermetic integration roots](integration-roots.md).

## Deterministic transaction planning

`debz.planTransaction` is the public typed planning API. It accepts authenticated repository snapshots, parsed dpkg state, explicit package policy, architecture, request, solver policy, and limits. The returned plan owns its data and can be serialized with `canonicalJson`; canonical schema version 2 is documented in [`schema/transaction-plan-v2.json`](../schema/transaction-plan-v2.json), while [version 1](../schema/transaction-plan-v1.json) remains published for compatibility with previously serialized plans.

Planning only computes actions. It does **not** download package archives, modify the filesystem, or execute dpkg.

## Transaction execution

`debz.executeTransaction` consumes an owned plan plus exact cached artifact
paths, revalidates every archive immediately before unpack, and executes only
the plan's ordered actions. It uses explicit root/admin paths, bounded debz and
dpkg locks, direct argv execution, a fixed environment, explicit conffile and
typed force policy, deferred/final trigger processing, and structured
interruption/failure provenance. See [Dpkg transaction executor](transaction-executor.md).

`debz.recoverTransaction` resumes journaled work under the same lock and policy
bindings. Successful execution and recovery perform exact installed-state
verification before atomically publishing transaction provenance; unhealthy or
different dpkg state fails closed.

Archive-producing plan actions retain a typed `selected_origin` that can be
matched back to the authenticated repository record by the package acquisition
API.

## Typed metadata and archives

The project exposes typed configuration and request APIs, a CLI command vocabulary, and bounded parsers for DEB822, Debian versions, binary package relations, control records, repository `Release` metadata, repository source configuration, and Debian binary package outer archives.

The control-record model validates required identity fields and typed scalar values, preserves unknown fields and source spans, and keeps relation policy decisions separate from syntax parsing.

`debz.deb_archive.parse` validates the outer `ar` structure, required members,
`debian-binary` version marker, supported compression suffixes, and configured
archive, member, and count limits. `debz.deb_payload.validate` then verifies the
authenticated identity, bounded compressed streams, inner control and data tar
archives, canonical paths and links, control identity, conffiles, and payload
inventory before an archive reaches the executor. See
[Debian payload validation](deb-payload-validation.md).

`debz.dpkg_status` parses only caller-supplied status bytes or explicit paths. It preserves source diagnostics and models package identity, exact Debian versions, installation states, package flags, dependency relations, and installed size without implicitly reading the host dpkg database.

Repository sources can be supplied explicitly as canonical `.sources` stanzas or legacy `deb` and `deb-src` lines; parsing never consults host APT configuration. Parsed sources preserve spans, enforce caller-configurable bounds, and receive deterministic IDs from normalized declared values.

`debz.release_metadata` parses caller-supplied `Release` bytes into typed identity, timestamp, architecture, component, by-hash, and SHA-256 index data. It validates normalized relative index paths and bounded checksum rows. Timestamps retain their declared civil time and UTC offset; expiration and other clock policy remain caller decisions. MD5, SHA-1, and unknown fields are never promoted into trusted checksum records.

## Repository metadata

`debz.repository_acquisition` fetches bounded bytes from explicit `file:`, HTTP, or HTTPS URIs. Callers provide proxy, credential, redirect, retry, deadline, clock, and size policies; production HTTPS verifies certificates and hostnames, while injectable transport and file seams support hermetic tests. Provenance contains only redacted effective URIs.

`debz.metadata_decompression` provides allocator-owned, bounded decompression for gzip, xz, and zstd repository metadata. Callers must explicitly select the format or derive it from a trusted selected filename; content magic is never used as a fallback. Compressed size, decompressed size, decoder memory, and an optional expected decompressed size are checked before a result is returned. gzip and zstd use Zig's standard library. xz uses the system liblzma streaming API with a caller-bounded memory limit and full integrity checking.

`debz.metadata_cache` provides an explicit-root, versioned verified-metadata cache. Objects are addressed by SHA-256, repository and snapshot manifests are atomically published only after size and digest verification, cache-only reads reverify referenced bytes, and bounded garbage collection preserves manifest references. It does not perform network refreshes or use ambient host cache directories.

`debz.repository_refresh` composes bounded acquisition, `Release` and `Packages` parsing, SHA-256 and size checks, Acquire-By-Hash, bounded decompression, and atomic cache publication into a complete snapshot refresh. Plain `Release` acquisition is explicitly unauthenticated and its result is not solver-eligible. Authenticated refresh and its security policy are documented in [Authenticated repository refresh](authenticated-refresh.md).

## OpenPGP security boundary

`debz.openpgp_verifier` is a separate in-process repository-signature boundary. It accepts only caller-supplied signed bytes, binary OpenPGP signature packets, and explicit keyring bytes or paths. It performs no network lookup, process spawning, or ambient keyring or home-directory access. The exact supported algorithms, parser limits, failure behavior, and backend/license decision are documented in [OpenPGP verification boundary](openpgp-verifier.md).

## Verified package acquisition

`debz.package_acquisition` accepts authenticated solver-selected records,
checks declared size and SHA-256 before atomic publication to an explicit-root
content-addressed cache, and returns owned verified handles with redacted
provenance. Online, cache-only, transaction download, and download-only
workflows use the same checks. Locking coordinates publication, repair, staging
cleanup, and deterministic bounded garbage collection. It does not parse
payloads or execute transactions. See
[Verified package acquisition](package-acquisition.md).

## Package-family image builder

`debz.package_family_backend` is the stable Ubuntu/Debian image-builder
boundary. Its non-mutating `resolve_lock` operation may create an initial exact
lock from authenticated metadata and a deterministic plan. Create, customize,
update, and recovery continue to require that reviewed lock as input. The
manual native-architecture real-snapshot matrix exercises this sequence for
Ubuntu 26.04 `ubuntu-minimal`; see
[zvmi Debian-family backend](zvmi-package-family.md).

## Dependency solver

The public `SolverContext` adapter owns a Debian-configured libsolv pool while keeping all libsolv C types and IDs private. It imports explicitly identified and prioritized typed `Packages` indexes only when their solver eligibility is marked as verified or explicitly trusted test data. Imported package origins are retained as debz-owned identities for diagnostics and planning.

Dependencies, pre-dependencies, alternatives, version predicates, provides, conflicts, breaks, replaces, and separately represented recommends are mapped. Unsupported qualifiers fail with typed errors.

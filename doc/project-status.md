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

`debz.runMaintainerScript` is the audited native maintainer-script runner used
by the native transaction engine. It validates and rejects unsafe scripts,
arguments, and roots before any process exists, executes the script inside the
selected root with a chroot-equivalent child setup, a fixed allowlisted
environment, `/dev/null` stdin, bounded output, an explicit timeout and
cancellation, and process-group termination, and reports exactly distinguishable
outcomes with provenance-grade evidence. See
[Audited maintainer-script runner](maintainer-script-runner.md).

Archive-producing plan actions retain a typed `selected_origin` that can be
matched back to the authenticated repository record by the package acquisition
API.

`debz.native_program` compiles the reviewed native transaction authorization,
the plan's ordered lifecycle, the consumed installed-database generation, and
the validated archives into one deterministic pre-mutation program with a
stable digest. Steps are dense, phased, typed, and dependency-ordered; they
carry preflight assertions, artifact revalidation, filesystem and database
intents, exact maintainer-script calls with failure and unwind semantics,
conffile decisions, trigger work, and final verification and provenance
requirements. Compilation is pure and either returns a complete program or one
typed diagnostic, and `transaction_engine.authorizeProgram` requires a matching
program before native execution. See
[Native transaction program v1](native-transaction-program.md).

`debz.root_fs` is the traversal-safe filesystem layer for the native
transaction engine. It anchors bounded, typed, root-relative operations to an
already opened root descriptor, never resolves a component through a symbolic
link, refuses absolute, traversing, and control-byte paths before any syscall,
creates only exclusively, and replaces existing paths only through fsynced
staged publication. See [Root-anchored filesystem primitives](root-filesystem.md).

`debz.root_operation` is the single mutation gate for a selected root. One root
mutation lock and one durable, versioned active-attempt record in the root's
`var/lib/debz` namespace are shared by repository bootstrap and package
transactions, so two debz operations can never mutate one root at once. The
record binds the attempt identity, root identity, backend, operation surface,
authorization/program/plan/request/policy/exact-lock digests, package-database
base generation, artifact evidence, architectures, durable phase and step,
sticky mutation evidence, and provenance publication state. Transitions are
monotonic, idempotent, and compare-and-set, an interrupted attempt is
classified as safely abandoned before mutation or recovery required, and the
active intent is cleared only after provenance is published. The
command-oriented executor bridge is resolved from the executor's own
transaction state rather than a command count, so a first command that timed
out, hit the deadline, or failed to spawn leaves recovery evidence instead of
clearing a root nobody can prove was untouched. Repository bootstrap binds its
attempt to a stable request digest before acquisition, so a rerun of the same
request adopts its own evidence and finishes it while an unrelated operation,
descriptor, or request is still refused. See
[Root-scoped operation coordination](root-operation.md).

## Typed metadata and archives

The project exposes typed configuration and request APIs, a CLI command vocabulary, and bounded parsers for DEB822, Debian versions, binary package relations, control records, repository `Release` metadata, repository source configuration, and Debian binary package outer archives.

The control-record model validates required identity fields and typed scalar values, preserves unknown fields and source spans, and keeps relation policy decisions separate from syntax parsing.

`debz.deb_archive.parse` validates the outer `ar` structure, required members,
`debian-binary` version marker, supported compression suffixes, recognized
bounded debsigs members, canonical ordering, and configured archive, member,
signature, and count limits. `debz.deb_payload.validate` then verifies the
authenticated identity, bounded compressed streams, inner control and data tar
archives, canonical paths and links, control identity, conffiles, and payload
inventory before an archive reaches the executor. The separate
`debz.deb_payload.inspectLocal` path derives identity from control metadata and
can enforce a narrow repository-descriptor profile. See
[Debian payload validation](deb-payload-validation.md).

`debz.dpkg_status` parses only caller-supplied status bytes or explicit paths. It preserves source diagnostics and models package identity, exact Debian versions, installation states, package flags, dependency relations, and installed size without implicitly reading the host dpkg database.

Repository sources can be supplied explicitly as canonical `.sources` stanzas or legacy `deb` and `deb-src` lines; parsing never consults host APT configuration. Parsed sources preserve spans, enforce caller-configurable bounds, and receive deterministic IDs from normalized declared values.

`debz.target_apt_config` provides an explicit, injectable target-root import
boundary for APT sources, binary OpenPGP keyrings, and dpkg-native architecture
state. Its production filesystem adapter is traversal-safe and no-follow;
logical `Signed-By` values remain root-independent while verifier inputs use
the imported bytes. Imports produce the canonical, digest-bound
[`apt-config-snapshot-v1`](../schema/apt-config-snapshot-v1.json) manifest. See
[Target-root APT configuration snapshots](target-apt-config.md).

`debz.repository_api` is the separate versioned repository-management
boundary. Its production `add` backend acquires a trusted descriptor `.deb`,
authenticates its static repositories and payload keyrings before mutation,
solves dependencies with installed-state-first behavior, persists exact-lock
and resumable state evidence, executes through the transaction executor, and
verifies/imports/refreshes the resulting target configuration. The standalone
`debz repo add --url URL` command wires this backend with `/` as its intentional
default root and `--root` for isolated images. See
[Repository management API](repository-management.md).

`debz.release_metadata` parses caller-supplied `Release` bytes into typed identity, timestamp, architecture, component, by-hash, and SHA-256 index data. It validates normalized relative index paths and bounded checksum rows. Timestamps retain their declared civil time and UTC offset; expiration and other clock policy remain caller decisions. MD5, SHA-1, and unknown fields are never promoted into trusted checksum records.

## Repository metadata

`debz.repository_acquisition` fetches bounded bytes from explicit `file:`, HTTP, or HTTPS URIs. Callers provide proxy, credential, redirect, retry, deadline, clock, and size policies; production HTTPS verifies certificates and hostnames, while injectable transport and file seams support hermetic tests. Provenance contains only redacted effective URIs.

`debz.local_artifact` applies HTTPS-or-explicit-SHA-256 initial trust to
standalone artifact acquisition and publishes verified complete bytes through
the existing package CAS. It does not imply repository authentication or
cryptographic verification of embedded package signatures.

`debz.metadata_decompression` provides allocator-owned, bounded decompression for gzip, xz, and zstd repository metadata. Callers must explicitly select the format or derive it from a trusted selected filename; content magic is never used as a fallback. Compressed size, decompressed size, decoder memory, and an optional expected decompressed size are checked before a result is returned. gzip uses Zig's standard library. xz and zstd use source-built static liblzma and libzstd streaming APIs with caller-bounded memory and full integrity checking.

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

`debz.package_cache_workflow` adds the non-installing exact-lock cache
boundary used by `actions/download`. It deterministically fingerprints
canonical v1 locks and acceptance policy, authenticates current repository
evidence, verifies/downloads every closure object, payload-validates cache hits
and downloads alike, and performs bounded retained-closure cleanup under one
writer lock. Its public JSON schemas and offline limitations are documented in
[GitHub Actions](github-actions.md) and
[Exact closure locks and transaction provenance](exact-locks-and-provenance.md).

`actions/install` composes the exact setup and package-cache boundaries with a
normal `debz install --cache-only` transaction. It denies host `/`, requires
explicit mutation/noninteractive/conffile policy, preserves recovery state,
and publishes installation outputs only after the canonical combined
transaction result is reopened no-follow and matched to the lock. Cache-only
repository replay is read-only so an explicitly elevated install does not
replace an unprivileged runner's authenticated metadata with root-owned files.

`debz.package_cache_archive` is the cache-service transport boundary. It
exports and imports a canonical path-free binary stream containing sorted
digest, size, and package-byte records plus an archive digest. It has no path,
link, owner, mode, or special-file representation; imports enforce object,
expanded-byte, ordering, duplicate, digest, and exact-lock size limits before
CAS publication.

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

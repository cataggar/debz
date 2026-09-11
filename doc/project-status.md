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

`debz.native_unpack` implements roadmap item 10's unpack and ownership work:
10a's descriptive planner and 10b's private data-only materialization adapter.
The planner rebuilds bounded archive models from authenticated
bytes, imports the supplied package-database snapshot itself, and produces an
immutable ordered filesystem description plus a
`package_database_changes.Plan`. It models package identity by name and
architecture, exact ownership and `Replaces`, `Multi-Arch: same`, hard links,
merged-`/usr`, obsolete paths, and the reserved dpkg namespace. Conffiles,
removal, and purge remain handoffs in the default item-10b path. Item 11 adds
opt-in script-free conffile staging/configuration and removal/purge phases,
including both policies, old/dist artifacts, obsolete/remove-on-upgrade state,
and globally planned batch removal. Scripts, triggers, selection changes,
package disappearance, shared roots, and unsupported filesystem/database
features still hand off. No apply, journal, recovery, or release entry point is exported.
Native backend selection remains `BackendUnavailable` before mutation. The
private adapter composes the existing lock, journal, and mutation engine;
`test-native-materialization` compares real install, upgrade, downgrade,
reinstall, and repeated unpack results with dpkg on disposable roots. Native
amd64/arm64 CI runs that gate and `test-native-conffiles` in Debug and ReleaseSafe.
The latter compares each unpack/configure/remove/purge phase against dpkg,
including preservation of local and co-owned contents. Zero timestamps on
newly materialized directories are explicitly refused, not approximated.
Production execution, recovery, and provenance integration remain later
roadmap work. See
[Native unpack and file ownership](native-unpack.md) and
[Native conffile and removal acceptance](native-conffiles.md).

Item 12 adds private compiled lifecycle execution using the actual audited
chroot script runner under one root-operation attempt. It models exact old/new
script arguments and configured-version evidence, known failures and
compensating calls, bootstrap payload materialization, Pre-Depends barriers,
and deterministic configure groups. In-flight script evidence blocks re-entry
when an outcome was not durably recorded. `test-native-lifecycle` compares
script traces, payload visibility, and resulting package/filesystem state with
real dpkg, including failures and dependency/bootstrap cases. Production native
selection remains unavailable. See [Native lifecycle execution](native-lifecycle.md).

Item 13 extends that private lifecycle with named/file trigger registration,
await/noawait activation, explicit deferral, and trigger-only processing.
Compiled trigger authority binds unchanged handlers and dynamic callers
without fake archive actions; final evidence includes actual pending/awaited
states. Deferred dynamic activation uses an explicitly authorized transition
from the bound base closure, not an expected state copied from observed
status. A private native helper records script-driven activation without
invoking dpkg-trigger in candidate execution. `test-native-triggers` covers
ordering, coalescing, failures, and cycles against real dpkg, with native
amd64/arm64 Debug and ReleaseSafe CI wiring. Unknown triggered-script outcomes
retain invocation/authority evidence and block re-entry. The helper is not
installed in releases, and production native remains unavailable. See
[Native trigger execution](native-triggers.md).

Item 14 adds private native-step journaling, persisted execution inputs, and
recovery/provenance orchestration. Recovery consumes the original compiled
authority without caller archives or recompilation, delegates primitive repair
to the root-mutation layer, and never reruns an unknowable script invocation.
Exact recorded outcomes and trigger continuation can advance once; terminal
provenance must be durable before the active operation is cleared.
Managed-state checkpoints reject drift after completed phases, and immutable
per-attempt receipts retain detailed execution evidence after workspace cleanup.
`test-native-recovery` exercises actual process crashes and repeated recovery
against independent root/trace/provenance assertions. Production native
selection remains unavailable. See
[Native recovery and provenance](native-recovery.md).

Item 15b's `debz.native_preparation` foundation binds actual solver plans and
exact-lock v2 documents to native authorization and compiled programs without
fixture request hashes or command-shaped reports. It preserves authenticated
origins and the complete installed/residual closure, and the private interpreter
accepts its mixed install/remove and install/purge programs. Production
execution/recovery ownership, helper deployment, and CLI integration remain
incomplete; native selection is still unavailable and legacy remains default.

`debz.root_fs` is the traversal-safe filesystem layer for the native
transaction engine. It anchors bounded, typed, root-relative operations to an
already opened root descriptor, never resolves a component through a symbolic
link, refuses absolute, traversing, and control-byte paths before any syscall,
creates only exclusively, and replaces existing paths only through fsynced
staged publication. See [Root-anchored filesystem primitives](root-filesystem.md).

`debz.root_mutation` is the crash-safe native mutation layer. It resolves a
caller's ordered typed intents against the current root into exact preconditions
and desired states, publishes them as a versioned durable journal plus a
hash-chained write-ahead progress log before the first target byte changes, and
then walks explicit durability boundaries - staged, backup captured, published,
metadata applied, parent synced, verified, completed - comparing observed state
to the recorded expectation at every one. Metadata is published as ownership,
then mode, then modification time, because Linux drops set-user-ID,
set-group-ID, and `security.capability` on every `chown` of a non-directory; the
mode is rewritten even when it already matches whenever an ownership change
could have cleared a bit it keeps. Because neither that sequence nor directory
creation is atomic, each step also states the exact closed set of intermediate
states the transaction itself could have produced from its last durable
boundary, and accepts nothing outside it, so a half-applied boundary is finished
or undone deterministically while an external modification is still refused.
A plan may touch one path more than once, and the second step's precondition is
then the first step's desired state, which can carry no inode; the verified
boundary of the producing step therefore binds the device, inode, and link count
it published inside the same chained progress record, and every dependent
precondition, directory re-creation, and backup attribution resolves that bound
entry instead of a zero. A precondition nothing has bound yet is proof the step
never ran, and a structurally identical entry on a different inode is an
external replacement rather than the recorded state.
Root-local staging and backups live in
a private `var/lib/debz/mutation` workspace, are created exclusively so a planted
entry can never be followed, and are released only after the whole transaction
verifies, so recovery can always restore the recorded old state without
re-supplying content. Preflight refuses special files, symbolic-link components,
path aliases, ancestor conflicts, hard-link ambiguity, non-empty directory
transitions, cross-device targets, capacity and overflow, content that does
not hash to the authorized digest, and an in-place ownership change that would
silently destroy a file capability. Appending a progress boundary is a
compare-and-set against the last complete record read at a proven offset: a
trailing run shorter than one record is a torn write and is truncated and
`fsync`ed before the append, while a whole extra record is a stale or foreign
history and is refused. Recovery either restores the old state,
finishes releasing a verified transaction, or publishes a durable typed recovery
requirement that blocks every further mutation. `lowerDatabasePlan` is the typed
adapter that consumes `package_database_changes.Plan` in its own status-old,
info, arch, triggers, status ordering with its generation binding, and
`bindArchive` re-proves the archive artifact and application digests immediately
before content is staged. Maintainer scripts, triggers, package ownership, and
unpack semantics are deliberately outside this layer and are documented as an
explicit handoff. See [Crash-safe root mutation layer](root-mutation.md).

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
clearing a root nobody can prove was untouched, and a bridge inherited from an
earlier run is never discharged by this run's own no-start evidence.
Repository bootstrap binds its attempt to a stable request digest before
acquisition, so a rerun of the same request adopts its own evidence and
finishes it while an unrelated operation, descriptor, or request is still
refused; a record that already published its provenance is settled, so the
rerun reserves a new attempt over it rather than executing under it. A package
transaction whose completion was interrupted before its provenance was
published is discharged by `debz recover` through
`debz.root_operation_completion`, a versioned statement in the same namespace
that binds the completed record and says whether its detailed transaction
provenance was already present, recovered, or interrupted, without running the
transaction engine again and without restating any command, script, or package
outcome. See [Root-scoped operation coordination](root-operation.md).

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

`debz.archive_application.prepare` builds the native application model on top of
that validation. It exposes normalized payload entries with mode, ownership,
mtime, bounded content, digests, and link identity, verified `md5sums`,
lifecycle scripts, conffile and trigger declarations, the control relationships
that authorize placement, an explicit supported/unsupported feature
classification, and a deterministic application digest that
`archive_application.revalidate` must reproduce immediately before application.
It writes no target file and implements no package-database or lifecycle
semantics. See [Native archive application model](archive-application-model.md).

`debz.dpkg_status` parses only caller-supplied status bytes or explicit paths. It preserves source diagnostics and models package identity, exact Debian versions, installation states, package flags, dependency relations, and installed size without implicitly reading the host dpkg database.

`debz.package_database` imports a caller-captured `var/lib/dpkg` generation
into a bounded typed model covering status, status-old, updates fragments,
architectures, ownership lists, checksums, conffiles, triggers, maintainer
scripts, diversions, and statoverrides. It retains unknown status fields and
record order, republishes every surface through canonical writers, and hashes
the consumed generation as authorization evidence.
`debz.package_database_changes` compiles typed edits into one deterministic,
validated publication plan of file intents. Neither module performs filesystem
IO; durable publication belongs to `debz.root_mutation`, which consumes the
plan through a typed adapter. See [Native package database](package-database.md).

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

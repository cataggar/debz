# Native transaction engine v1 compatibility contract

Status: design and differential-test contract. The production implementation is
not complete and the existing dpkg executor remains authoritative until every
cutover gate in this document passes.

## Scope

The v1 native engine consumes ordinary Debian binary packages and updates an
explicit Debian-family install root without invoking `dpkg` or `dpkg-deb`.
Repository authentication, dependency solving, acquisition, and exact closure
selection remain outside this boundary.

V1 targets the pinned Debian stable and Ubuntu integration closures on native
amd64 and arm64. Support is defined by this document and the versioned
`test/native-transaction/corpus-v1.json` scenario contract, not by whatever an
installed host tool happens to accept.

The engine must complete preflight before the first mutation. Preflight reads
and validates the complete package database, all selected archives, the exact
transaction lock, policy, compiled lifecycle program, and every filesystem
feature needed by the transaction. An unsupported or ambiguous feature is a
typed failure and may not select the legacy executor automatically.

## Package archive profile

V1 accepts the following package representation:

- Debian format 2.0 `ar` archives with `debian-binary`, one `control.tar`
  member, and one `data.tar` member in canonical order;
- uncompressed, gzip, xz, and zstd control and data members;
- POSIX USTAR and GNU base headers, including bounded GNU long-name and
  long-link records;
- regular files, directories, symbolic links, and backward hard links;
- numeric uid/gid, permission and special mode bits, modification time, and
  bounded USTAR owner/group names;
- `control`, `conffiles`, `md5sums`, `triggers`, and the `preinst`, `postinst`,
  `prerm`, and `postrm` maintainer scripts;
- dependency, Pre-Dependency, Breaks, Conflicts, Replaces, Provides,
  Essential, Protected, and Multi-Arch control fields needed to validate the
  authorized plan and filesystem replacement rules.

Absolute or traversing paths, escaping or forward hard links, unsafe symlink
descendants, duplicate destinations, devices, FIFOs, sockets, sparse files,
and unknown file types are rejected before mutation. PAX headers, archive
xattrs, ACLs, and labels are not in the v1 archive profile. The real-snapshot
feature inventory is a cutover gate: encountering one of these features
requires an explicit contract revision and implementation, not approximation.
Metadata created by a maintainer script remains a recorded script side effect
and is compared by the differential harness.

Every regular payload file named by `md5sums` must match before execution. A
missing checksum file is supported because Debian packages do not universally
require one; malformed, duplicate, mismatched, or out-of-inventory entries are
rejected.

## Package database profile

All paths below are relative to the selected root. Reads and writes use
root-anchored, traversal-safe descriptors and never follow an unvalidated
database path component.

| Path | V1 behavior |
|---|---|
| `var/lib/dpkg/status` | Parse every field, retain unknown fields, and atomically publish compatible package states and conffile digests. |
| `var/lib/dpkg/status-old` | Retain the immediately preceding complete status generation when publishing a new one. |
| `var/lib/dpkg/updates/` | Empty is accepted. Nonempty update fragments are treated as interrupted database publication and require explicit native recovery before another mutation. |
| `var/lib/dpkg/info/*.list` | Parse bounded absolute package paths, build the ownership index, and publish the exact final owned path set. |
| `var/lib/dpkg/info/*.md5sums` | Parse and publish lowercase MD5 plus canonical relative payload paths. |
| `var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm}` | Validate regular no-follow files and preserve or replace them according to lifecycle state. |
| `var/lib/dpkg/info/*.triggers` | Parse and publish the package trigger declarations. |
| `var/lib/dpkg/triggers/File` and `Unincorp` | Parse and publish interests, activations, awaiting packages, and pending work. Lock files are never package state. |
| `var/lib/dpkg/arch` | Preserve a validated unique foreign-architecture list. Native architecture comes from the authorized request and must agree with healthy installed state. |
| `var/lib/dpkg/diversions` | Parse and honor complete three-line diversion records. Malformed records fail preflight. Script-created changes are re-read and validated after the script boundary. |
| `var/lib/dpkg/statoverride` | Parse and honor bounded owner, group, mode, and path records. Malformed records fail preflight. Script-created changes are re-read and validated after the script boundary. |
| `var/lib/dpkg/alternatives/` | Preserve bounded regular-file records managed by package scripts and include their exact bytes in differential state. |
| `var/lib/dpkg/parts/` | Empty is accepted. Nonempty records are retained and classified during feature inventory before mutation. |
| `var/lib/dpkg/available` | Preserve as non-authoritative compatibility data; the native engine does not use it for solving or authorization. |

Package information filenames must follow dpkg's package and architecture
qualification rules. Unknown regular files under `info` and unknown
well-formed status fields are retained. Unknown database directories, links,
special files, malformed names, duplicate identities, and inconsistent
ownership fail before mutation.

The engine hashes the complete consumed database generation while holding the
root operation and dpkg-compatible locks. Any external change between
preflight and mutation invalidates the authorization.

## Package states and lifecycle

V1 supports install, unpack, configure, upgrade, downgrade, reinstall, remove,
purge, and explicit recovery. It models all dpkg status states used by those
operations:

`not-installed`, `config-files`, `half-installed`, `unpacked`,
`half-configured`, `triggers-awaited`, `triggers-pending`, and `installed`,
including the `reinstreq` error flag.

The native program compiler expands the reviewed solver plan into deterministic
state transitions before mutation and publishes them as the durable
[native transaction program v1](native-transaction-program.md) document. The
compiled program includes:

- Essential bootstrap materialization needed to make script interpreters and
  runtime dependencies available in a fresh root;
- Pre-Depends configuration barriers;
- deterministic dependency and cycle configuration order;
- old and new maintainer-script calls with exact operation arguments;
- conffile decisions and package-owned path mutations;
- deferred trigger activation and final trigger processing.

Upgrade error unwind calls are part of the compatibility matrix. A script
failure records the exact script identity, arguments, environment, exit or
signal outcome, bounded stdout/stderr, package state, and recovery requirement.
The engine never reports partial success.

## Maintainer-script policy

Scripts remain child processes. They execute directly from the selected root:

- alternate roots use a chroot-equivalent child setup and working directory
  `/`; host-root execution requires the existing explicit host-root policy;
- stdin is `/dev/null`; no shell command string is constructed;
- the environment is replaced with the documented locale, PATH, frontend,
  package identity, architecture, root, and maintainer-script variables;
- output, runtime, cancellation, descendants, and termination are bounded;
- the interpreter and every executable path resolve inside the selected root;
- exact argv, environment, output digests, and termination are provenance.

The audited runner implementing this policy is documented in
[Audited maintainer-script runner](maintainer-script-runner.md).

Arbitrary script side effects cannot be generically rolled back. A crash while
a script may have been running produces durable `script_outcome_unknown`
evidence and blocks another mutation. Recovery may continue automatically only
when the journal proves that the script did not start or records its exact
completed outcome.

## Conffiles

The selected noninteractive policy is authorization input:

- `keep_existing` preserves a locally modified file and publishes the package
  version using compatible `.dpkg-dist` behavior;
- `use_package_version` installs the package version and preserves a locally
  modified predecessor using compatible `.dpkg-old` behavior.

Unmodified conffiles update without a conflict artifact. Remove retains
conffiles and their status metadata; purge removes them and the package status
record. V1 also covers newly introduced, renamed, removed, obsolete, missing,
and `remove-on-upgrade` conffiles. Every decision and before/after digest is
recorded.

## Triggers

V1 supports `interest`, `interest-await`, `interest-noawait`, `activate`,
`activate-await`, and `activate-noawait`, including file activation, deferred
processing, `triggers-awaited`, `triggers-pending`, explicit `postinst
triggered` calls, failure retention, and deterministic no-progress detection.
Trigger work remains deferred during package unpack/configure and is processed
after the planned package lifecycle unless recovery resumes a pending set.

## Durability and concurrency

One root-scoped operation lock and active-attempt record coordinates repository
bootstrap and package transactions. Lock order is root operation, repository
state when applicable, debz transaction, dpkg frontend compatibility, then dpkg
database compatibility.

Before mutation, the engine durably publishes the exact plan, transaction lock,
policy, artifact and database generation evidence, compiled native program,
attempt identifier, and root identity. Each filesystem, database, script, and
trigger step has a checksummed write-ahead intent and a durable completion
record. File and database publication fsyncs content and parent directories.

Recovery yields exactly one of:

1. proof that no mutation occurred;
2. deterministic completion of an idempotent step and continued recovery;
3. a durable typed recovery requirement that prevents another mutation.

Successful, failed, interrupted, and recovered provenance is published before
the active attempt can be cleared.

## Differential comparison

Reference and native executions run against separate disposable roots created
from identical fixture bytes. The semantic comparator records:

- path type, regular-file SHA-256, link target and hardlink relationship;
- mode, uid, gid, stable file/link mtime, device identity where representable,
  and xattrs; directory mtimes are excluded because child publication changes
  them independently of package semantics;
- complete normalized status and status-old paragraphs;
- normalized ownership lists, md5sums, trigger files, architecture,
  diversions, statoverride, update fragments, and remaining info files;
- exact maintainer-script and trigger traces;
- process outcome and typed package-state result.

Lock files and debz-private journals are excluded from root equivalence and are
validated separately. Ordering is normalized only where the dpkg format treats
it as semantically irrelevant; content, metadata, state, and script order are
never discarded.

`python3 tools/native-differential.py capture` produces a bounded canonical
snapshot. `compare` reports stable JSON paths for mismatches.

## Production cutover gates

The native backend may become the default only when all of the following pass:

- every scenario in `corpus-v1.json` on amd64 and arm64;
- pinned Debian stable and Ubuntu real-snapshot closure installation,
  database import, query compatibility, update, removal, and purge;
- crash injection at every journaled transition;
- malformed database, archive, journal, and unsupported-feature fuzzing;
- exact-lock, final-state, and provenance validation;
- a production-source audit proving there is no `dpkg` or `dpkg-deb`
  invocation, including architecture discovery;
- removal of the legacy production executor and recovery-specific allowances.

Reference `dpkg` remains permitted only in differential test tooling after
cutover.

## Incremental backend boundary

`transaction_engine` owns explicit backend selection. `legacy_dpkg` remains
the default while native work is incomplete. Library backends may inject a
native executor for development, but selecting `native` without one returns a
typed unavailable result before repository acquisition, journal access,
database access, or root mutation. Selection never falls back to
`legacy_dpkg`.

## Native transaction authorization

Native execution is authorized, never implied. `debz.native_authorization`
version 1 is the canonical contract described in
[exact locks and provenance](exact-locks-and-provenance.md), and
`transaction_engine.executeAuthorized` requires one bound to the exact request
before it selects a backend. The authorization pins the backend, the exact
closure lock v2 generation, request/solver-policy/executor-policy/plan digests,
the install root and its identity, the target and foreign architectures, the
conffile and force policy, every ordered action with its authenticated artifact
evidence, and the exact intended final closure. Legacy locks and legacy
execution are never authorized by this contract.

Native execution additionally requires the compiled program the authorization
was expanded into. `transaction_engine.authorizeProgram` binds the program to
the authorization, the request, the reviewed policy, and every artifact, and
optionally to an independently recorded program digest, before
`executeAuthorizedProgram` may select a backend. Because no native executor is
registered, a correct program still cannot start a native transaction; the
typed unavailable result is returned and selection never falls back.

The plan layer represents `purge` as a distinct action kind and ordered phase so
authorizations can express complete removal. The legacy `dpkg` executor rejects
purge actions in preflight before any mutation, so present legacy behavior is
unchanged; only the native engine will execute them.

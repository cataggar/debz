# Repository management API

`debz.repository_api` is a stable API separate from product API v1. Version 1
defines the `add` operation; CLI parsing is intentionally outside this
boundary. Callers provide an absolute target root, descriptor URL, optional
SHA-256, optional target architecture, `no_refresh`, and bounded cache, state,
network, and operation-wide resource policy. The production implementation is
`debz.ProductionRepositoryBackend`.

## CLI

The standalone binary wires the typed backend directly:

```sh
sudo debz repo add \
  --url https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
```

`--url` is required. `--root` defaults to `/`; alternate roots use the same
logical `/var/cache/debz` and `/var/lib/debz` defaults beneath the selected
root. `--architecture` overrides target dpkg architecture discovery,
`--sha256` pins descriptor bytes, `--no-refresh` skips only the final refresh,
and `--json` emits canonical
[`repository-operation-result-v1`](../schema/repository-operation-result-v1.json).
Explicit logical cache/state paths, proxy policy, timeouts, retry/redirect
bounds, byte limits, lock wait, and aggregate repository/action/metadata/
package/cache budgets map directly to the v1 request fields; see
`debz repo add --help` for spellings.

`--transaction-backend legacy_dpkg|native` selects the production backend for
this invocation; omission preserves `legacy_dpkg`. Selection is separate from
the unchanged repository API v1 request and is passed directly to
`ProductionRepositoryBackend.transaction_backend`. Duplicate, missing, and
unknown selections are usage errors.

Native repository bootstrap is not yet activated. Explicit `native` selection
returns exit 3 with `transaction_backend_unavailable` before root access,
operation-state creation, acquisition, or execution. It never falls back to
dpkg, even when the root contains a completed legacy repository operation.
The existing command-report executor cannot stand in for native typed
preparation, receipts, or recovery. Core product and native system-profile
support do not imply that repository bootstrap uses those contracts yet.

The native preparation layer now supports the explicit `locked_packages`
policy used by operation-scoped locks. It retains unrelated healthy packages
from captured database evidence in the complete native final-state proof,
without manufacturing artifact origins for them. This is a prerequisite for
repository bootstrap, not activation of its execution or recovery path; see
[production preparation](native-transaction-program.md#production-preparation).

Repository evidence binding also takes the selected backend explicitly,
snapshotted once per invocation before acquisition callbacks.
Native operation-directory identities, root-caller request/policy digests,
and exact-lock executable-request/solver-policy digests use separate native
domains. Legacy identities remain byte-for-byte compatible, with no history
migration. Both backends retain the same root-operation exclusion and
repository advisory-lock location; separate history does not permit
concurrent mutation or adoption of another backend's unresolved attempt.
These bindings do not activate native execution or make legacy journals and
provenance acceptable native completion evidence.

`debz repo add` is the authorization to mutate the selected root. It does not
accept or require `--assume-yes`, `--allow-host-root`,
`--import-target-apt-config`, `--install-root`, `--refresh`, or a separate
noninteractive flag. It never prompts, checks TTY state, reads stdin, invokes
apt, or consults environment proxy/netrc/credential helpers. Help flags take
precedence over malformed or incomplete command arguments.

Human output reports descriptor identity and truthful installed/refreshed
state. JSON output is the canonical typed result, including diagnostics and
evidence paths. A post-install import or refresh failure exits nonzero while
retaining `installed=true`; no output claims rollback. Observable descriptor
URLs redact the complete query and never persist URI user information.

The canonical result schema is
[`repository-operation-result-v1`](../schema/repository-operation-result-v1.json).
It records acquisition, structural validation, authenticated repository
preflight, planning, installation, import, and refresh state. Nonzero results
retain truthful installed/refreshed evidence and typed diagnostics; incomplete
work cannot be serialized as success. `repository_api.decode` accepts only
bounded, canonical, digest-valid documents. Results returned by the production
backend own their strings with the caller-supplied allocator; call
`Result.deinit` when finished. Decoded documents return `OwnedResult`, which
likewise requires `deinit`.

## Native caller integration

`repository_backend.prepareNative` is the lower-level preparation boundary,
not the repository-add executor. It takes the repository request, an already
held native `repository_bootstrap.add` attempt, the genuine v2 lock and
executable plan, and already acquired archive bytes. It shares
`repository_api.validateRequest` with normal dispatch, then requires matching
root, architecture, complete original request, executor policy, and native
lock request/policy bindings. Existing caller plan, lock, authorization,
program, database-generation, and artifact bindings cannot be replaced.

Before creating a native repository operation namespace, the root guard
reuses the core product's native root admission rules. Literal `/` is refused,
and a physical host-root alias requires the exact authority issued by
`live_root.runProjected`. `Backend.root_projection` may borrow that opaque
authority for the current trusted callback at `live_root.logical_root_path`;
it is not an API request option, serialized permission, or host-root flag.

Only native coordinators receive this authority. It is validated before
namespace creation and again around root-lock acquisition, before publishing
a record. Native preparation and cleanup retain the coordinator's original
scope checks. A different path, descriptor, process, or mount namespace cannot
inherit the callback's authority. If scope is lost, cleanup retains the
original reservation rather than abandoning it without authority. A fresh
supervised callback can adopt the same request and sticky program evidence.
Legacy root admission and coordination do not inherit native projection
authority.

This supplies the repository caller's root-authority contract; it neither
starts a private runner nor enables repository CLI native execution. Helper
deployment, execution/receipt integration, and outer completion still require
the complete lifecycle described below.

Native repository reservations resolve target and foreign architectures using
metadata-only `target_apt_config.inspectArchitecture`, borrowing the guard's
pinned root. An explicit override or an installed `dpkg` status entry supplies
the native architecture; the dpkg executable is never called. Without either,
native architecture is unavailable rather than inferred from the host.
The original API request is not rewritten with the discovered architecture.

Clean reservations, including unstarted adopted reservations, are rechecked
under the root-operation lock before work can proceed. Architecture drift
refuses without rebinding the caller. Recovery-bearing callers retain their
original architecture even if current status is incomplete; locked admission
still rejects different requests and surfaces. Native before/after snapshots
disable process fallback and require the same native and foreign architecture
closure. Cleanup abandons a native reservation only after independently
excluding active native evidence, not from its pre-mutation state alone.
Legacy discovery, fallback, and caller identities are unchanged.

Native preparation accepts a canonical leading native-architecture line in
dpkg architecture metadata while retaining the foreign bytes and their file
mode for strict database import. Foreign membership is compared as a set
against the canonical caller record; input order is not authority. Duplicate,
malformed, and unsafe foreign metadata still refuses without changing the
caller. Raw foreign ordering remains part of the imported database evidence.

`prepareNativeFromCache` connects the held repository caller and genuine v2
lock to the existing package CAS and real native preparation. Before loading
any object, it validates caller/request/policy authority, declared closure
budgets, sticky evidence, absence of active execution, and the canonical lock.
Every object is read through the CAS's no-follow, exact-size, SHA-256-verified
reader; a cache hit is transport, not a replacement for native payload and
origin validation. Missing or corrupt objects fail without network acquisition,
repair, or legacy fallback. Local, mixed-origin, and empty closures use the
same path.

The caller must supply all still-retained package buffers, including an
acquired descriptor, as `retained_archives`. Their actual lengths plus the
complete newly loaded closure must fit `maximum_retained_package_bytes`
before any archive allocation. The closure separately fits
`maximum_total_package_bytes`, the request's per-package/cache limits, and the
opened CAS's object limit. Retained buffers are neither reused nor transferred:
the returned `NativeCachedPreparation` owns its archives and preparation result
until `deinit`, independently of cache eviction or the caller's buffers.
All partially loaded archives are released on failure.

The cache adapter requires the existing absolute operation `Deadline` and
checks it before work, around object reads, and after native preparation.
It does not reset the timeout or claim to interrupt a single read or CPU-bound
preparation. Expiry and lock loss discard the result without changing caller
authority. `executeNativeFromCache` passes that same absolute deadline into
native execution rather than starting a new timeout. Repository CLI activation
still requires the complete caller-owned lifecycle below.

Native caller request digests cover every cache, state, network, and aggregate
resource field; native caller policy digests also bind the actual repository
executor policy. Legacy caller and executable-lock identities remain
byte-for-byte unchanged. A newly constructed lock for changed limits does not
authorize those limits under an earlier native caller.

Preparation bounds action/repository counts and all simultaneously retained
archive bytes, including total, retained-memory, per-package, and cache-object
limits. The runtime captures the actual database and validates archive
identities/origins under the caller's lock using `locked_packages` policy.
It preserves unrelated healthy package identities and holds. Existing native
host-root/projection restrictions and database trust checks are unchanged.

The result is an owned native preparation/diagnostic or `unchanged`. Active
native evidence refuses before preparation, including before an unchanged
result. `unchanged` describes the package plan, not a completed repository add
or permission to clear ownership. Preparation never executes packages,
publishes mutation intent, releases the caller, or acknowledges completion.
Acquisition, the cumulative operation deadline, helper/execution integration,
native receipt retention, persisted recovery, and durable outer completion
remain caller responsibilities. The repository CLI native gate remains in
place until that complete lifecycle is integrated.

### Typed package execution and recovery

`executeNativeFromCache` consumes `NativeCachePreparationRequest`, prepares the
complete verified CAS closure, and calls the actual trusted-helper native
runtime under the original repository attempt and deadline. The adapter owns
all loaded archive bytes through execution and releases them afterward,
including on failure. Native execution persists its recovery inputs before
package mutation; recovery does not depend on this temporary archive bundle.

`NativeExecutionResult` distinguishes `unchanged`, an independently owned
preparation `diagnostic`, and an owned native `execution` report. Unchanged and
diagnostic outcomes never deploy a helper, execute scripts, or fabricate a
receipt. Execution reports preserve native `succeeded`, `failed`,
`recovery_required`, and `refused` outcomes; terminal success or failure carries
a genuine native receipt. Call `deinit` on the result. Operational errors
propagate and must not be interpreted as proof that mutation never started.
Pre-mutation helper refusal may leave sticky program evidence on the original
caller without starting package mutation.

`recoverNative` accepts only the original repository request, its held attempt,
and a fresh invocation's absolute deadline. It authenticates the repository
operation, root, original request/policy and any explicit architecture before
invoking bounded native recovery. It accepts no replacement plan, lock,
archive, cache, helper or repository acquisition input. Completed native
receipts are adopted without replaying scripts; incomplete safe work resumes
from persisted native inputs. Changed caller requests and policies refuse.

These adapters neither acknowledge native receipts nor complete, clear,
abandon or release the repository caller. Package completion is not repository
bootstrap completion: descriptor import, metadata refresh, immutable outer
receipt retention and durable outer completion must precede acknowledgment
and root cleanup. The public repository CLI gate remains unchanged.

### Retaining native package receipts

`retainNativeReceipt` takes the original repository request, held native
attempt, expected terminal receipt digest and the invocation's existing
absolute deadline. It independently reads and authenticates the runtime's
terminal evidence instead of trusting supplied receipt bytes. Both successful
and known-failure package receipts retain their exact native schema, digest
and outcome; nonterminal or missing evidence refuses.

The returned `NativeRetainedReceipt` owns its logical path and native receipt;
call `deinit` when finished. Native operation-local receipts use
`native-transaction-provenance-v1.json`, never the legacy
`transaction-result-v2.json`. The backend-specific operation-directory
identity and original request determine the destination, including custom
state paths. Legacy paths and state schemas are unchanged.

Publication is no-follow, private, durable and non-overwriting. Ancestor
directory entries are synced, and retry accepts only identical bytes, retaining
the existing inode and finishing any interrupted file/directory sync. Existing
foreign, corrupt or non-regular evidence is not repaired. Caller exclusion,
projection authority and the shared deadline are revalidated before publication.
Once the receipt is published, durability finishes without relabeling that
publication as a timeout.

Once outer state binds a retained receipt, use `readRetainedNativeReceipt`.
It requires the same original caller and exact runtime receipt, checks existing
bytes without writing, and refuses missing retention rather than recreating it.
This is caller-owned readback, not historical bootstrap proof or a current
database verifier. Neither API marks packages installed, acknowledges native
execution, completes repository bootstrap, or releases root ownership. Durable
outer installed/import/refresh state and completion remain future integration;
the repository native CLI gate stays closed.

### Verifying live native package state

`verifyNativePackageState` takes the same `NativeReceiptRequest`, but verifies
more than retained receipt bytes. It requires the current held original caller,
the exact operation-local receipt, complete retained authorization/program and
execution evidence, terminal progress and outcome, consistent active evidence,
and the current native package database. It accepts no replacement plan, lock
or archive and performs no package recovery.

The owned `NativePackageState` result distinguishes `succeeded` from `failed`;
call `deinit` when finished. Success proves the authorized final package closure
and recorded database. Known failure proves its actual terminal failure and
recorded database, not that the requested closure was installed. Missing,
unknown, inconsistent or drifted evidence refuses without rewriting state or
replaying scripts. Plain receipt retention/readback remains intentionally
separate and does not acquire these stronger live-state semantics.

The lower `native_transaction_result.verifyCallerSuccess` and
`verifyCallerFailure` entry points use the already-held original native attempt
and expected receipt digest. They share native evidence, progress and database
verification with settled and owner-bound result verification, but do not
require or fabricate an outer completion, a deferred owner or another lock.
The repository adapter additionally authenticates the original repository
request, checks retained bytes and enforces its shared deadline and projection
scope before returning.

Package database proof does not replace descriptor-file, import or refresh
verification. Neither result publishes outer installed/failure state, completes
bootstrap, acknowledges native execution or releases ownership. Durable outer
state/completion and repository dispatch remain integration work; native CLI
activation stays gated.

## Descriptor and repository trust

The MVP descriptor is a Debian binary package. Unpinned acquisition requires
HTTPS certificate and hostname verification on every redirect hop; a downgrade
and later re-upgrade is rejected. HTTP and `file:` require the expected
SHA-256. Observable URLs remove credentials, fragments, and complete query
values. Embedded debsigs members may be inventoried but do not authenticate the
descriptor.

Before dpkg runs, the package is structurally validated with the
repository-descriptor profile. Every enabled `.list` or `.sources` payload must
be static, root-relative, and declare `Signed-By`; every referenced keyring
must be a regular payload file. Keyring bytes are parsed and used to
authenticate a dry refresh of the new repositories. Dynamic repository
material and authentication-bypassing `Trusted: yes`/`trusted=yes`
declarations fail before target mutation. Explicit false values remain valid.

Architecture comes only from an explicit request or target-root dpkg
configuration. Host `uname`, host APT configuration, environment proxies,
netrc, prompts, and TTY input are not used.

The CLI default `/` is intentionally safe only because it enters this typed
operation, whose executor policy enables host-root mutation for repository add
alone. Product API v1 and every generic product command continue to reject
host root. An alternate `--root` resolves source files, keyrings, architecture,
cache, state, locks, and evidence only within that root; it never falls back
to `/`.

## Planning and mutation boundary

The descriptor package is a verified local-artifact solver origin. Installed
packages satisfy dependencies first. Existing imported target repositories are
refreshed only if the installed-only attempt lacks a dependency candidate, and
only authenticated or stale-authenticated complete snapshots are solver
eligible. Repository dependencies use verified acquisition; the descriptor
uses its existing CAS object.

The exact canonical executable plan and an exact-lock v2 file are atomically
persisted before dpkg and passed to both execution and recovery. The plan is
reloaded byte-canonically on resume rather than regenerated from the
potentially incomplete current dpkg state. Lock construction uses only the
persisted action origin, digest, and size plus the authenticated snapshot
evidence bound to those actions; transient solver pointers and record indexes
are never recovery inputs. The lock records the
descriptor and every repository-selected package in the mutation closure;
already-installed dependency satisfiers are retained from target state rather
than assigned invented artifact origins, and binds the complete request,
authenticated repository snapshots, local artifacts, and executable plan.
Its policy digest explicitly binds repository-add's `locked_packages`
verification scope. Under that scope every locked mutation package must have
the exact installed identity, plan origin, digest, size, and completed journal
artifact digest, while unrelated healthy packages already present on the
target are allowed to remain or change. The executor's default full-closure
exact-lock semantics remain unchanged for product operations. The executor uses a fixed
noninteractive, keep-existing-conffile policy. Only this typed backend may opt
into host-root execution, and only when the requested root is `/`; product API
v1 continues to deny host-root execution for every operation.

After dpkg, the backend verifies descriptor package identity and exact static
source/keyring bytes, imports the resulting target APT configuration, writes
its manifest, refreshes only new or changed descriptor repositories unless
`no_refresh`, and publishes transaction provenance v2 through the
lock-validating execution/recovery constructors. Missing or mismatched executor
lock digests cannot be replaced by caller-supplied provenance fields.

Operation-wide limits bound normalized repositories, solver actions,
authenticated metadata bytes, total package bytes, retained package memory,
cache growth, and elapsed time. Metadata objects and per-repository/aggregate
manifests reserve their actual cache growth before publication; retained
snapshot and aggregate-manifest memory is likewise reserved before it becomes
an accepted result. One absolute monotonic deadline starts before the repository operation lock is
acquired and is propagated through
descriptor/repository/package acquisition, dpkg execution, and recovery.
The repository lock wait is capped by both its configured wait and remaining
operation time; expiry after or during that wait prevents all acquisition and
mutation work. Every later transport, lock wait, and process timeout is
likewise capped by the remaining operation time, and expiry cancels a running dpkg process. Package bodies are
validated after CAS
publication and released before the next package; the executor retains only
CAS paths and immutable provenance.

## State, idempotence, and recovery

Every completed phase atomically updates
[`repository-add-state-v1`](../schema/repository-add-state-v1.json) under the
selected state root. Each operation directory is keyed by the backend-specific
SHA-256 identity of the descriptor URL, optional expected digest, and
`no_refresh`, so identical requests under one backend resume the same evidence
while distinct descriptors or backends have separate histories. Existing
legacy directory names are unchanged. Exact-lock request and policy validation
also require the selected backend, even though both use the v2 lock schema.
Decoding is bounded, canonical, and digest checked. A repository-root advisory lock
serializes add operations even though their evidence directories are separate.

An identical installed package and managed-file set resumes import or refresh
without invoking dpkg. When no matching recovery journal exists, that shortcut
also rereads dpkg state and requires every package in the persisted
operation-scoped lock to have its exact version and architecture, while
preserving the invariant that every unrelated installed package is healthy.
The persisted lock and successful provenance establish historical artifact
origins; current dpkg state establishes only package identities and health. A
different version, artifact digest, divergent managed file, missing locked
package, or unhealthy package fails with recovery required before mutation. A
post-dpkg import or refresh failure
returns nonzero with `installed=true`, preserves lock/provenance/state
evidence, and makes no rollback claim. Missing or inconsistent durable
evidence produces `recovery_required` rather than a success-shaped result.
State write/fsync failures after mutation return progress-aware nonzero results
with `installed=true` and every known evidence path. Resume validates
the persisted plan, request, local artifacts, repository snapshots, lock,
provenance, manifest, managed files, and dpkg state rather than
requiring stale state path fields; durable `refreshed=true` history is
monotonic. If dpkg completed before provenance/state publication, provenance
is reconstructed only from the original plan, lock, report/journal, and
authenticated evidence.

Once validated descriptor state exists, resume first reads the exact persisted
digest and size from CAS. A missing or corrupt object may be reacquired only at
that digest and size; an originally unpinned HTTPS descriptor also retains its
all-HTTPS transport requirement and original trust evidence. Changed transport
content is rejected. Shared transaction journals are decoded before selecting
recovery: only an exact plan/root/executor-policy/lock match is recovered,
mismatched incomplete journals block, and unrelated completed archives are
ignored so a normal execution can publish its own journal safely.

All root and logical-path fields use one schema-aligned grammar: valid UTF-8,
canonical absolute components, no backslashes, C0/DEL controls, dot
components, duplicate separators, or trailing separator.

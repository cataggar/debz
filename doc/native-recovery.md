# Native recovery and provenance

Items 14 and 15b provide durable execution boundaries around the compiled native
lifecycle, including the experimental caller-owned `debz.native_runtime` API.
Core product/CLI native execution and persisted-input recovery are experimental;
this does not enable a product cutover or change legacy recovery.

Reference acceptance uses the same
[pinned private dpkg option](native-lifecycle.md#independent-reference-acceptance)
as lifecycle acceptance, including both CI architectures and optimization modes.
Named statoverride coverage is never skipped for an older host dpkg.

## Durable execution authority

Before package mutation, native execution persists the exact authorization,
compiled program, required archive and installed-script bytes, initial
database/trigger evidence, and a native execution intent. The intent binds
attempt, root, request, policy, exact lock, artifact and database generation
digests, stored paths, and limits. Recovery consumes these persisted inputs
without caller archives, repository access, re-solving, or recompilation.

The native progress document preserves a logical append-only sequence and
hash chain, atomically replacing its canonical JSON file on each append.
Records describe native phases and invocation outcomes,
not a list of dpkg commands. Native phase completion must become durable
before its corresponding root-mutation journal and backups can be released.
Progress reads and appends use the deallocating execution allocator, not the
long-lived lifecycle scratch arena: each append decodes and re-encodes the
entire growing history, and those temporary allocations must be reclaimed
before the next phase or script launch.
Unpack trigger discovery similarly frees each database snapshot after copying
only the trigger events needed for later phases; route-settlement reconciliation
and trigger-event publication use temporary allocation scopes.
The CLI supplies its deallocating process allocator for native execution;
its argument-parsing arena cannot reclaim phase-local allocations.

Filesystem and database repair delegates to the existing
[root mutation layer](root-mutation.md). Missing, corrupt, mismatched, or
externally changed evidence cannot become an absent journal or an implicitly
successful step.

Bounded managed-state checkpoints preserve exact path content, metadata and
directory membership at completed phases and known script outcomes. Recovery
checks these durable expectations before continuing; a completed phase marker
alone cannot authorize resuming over externally changed payload.

An alternatives-aware script adds a stable pre-script checkpoint before its
in-flight marker. That checkpoint covers the active record directories, every
record, selector, generic link, provider chain and target authorized by the
literal command set, plus the pinned root-local tool. A normally returned
script is recaptured and its exact post-state becomes the script checkpoint.
If execution reaches in-flight without a durable outcome, or any record/link
identity differs from the authorized checkpoint, recovery stops before root
mutation repair and never reruns or synthesizes an alternatives operation.
This uses the existing versioned execution-progress, script-outcome,
managed-state, root-mutation, completion, and provenance documents; no wire
schema is widened, and older evidence retains its original meaning.

Statoverride resolution is frozen for the original invocation. Alongside the
original override database, recovery stores the exact account-file bytes and
modes actually required for named identities. These use bounded database-kind
blobs keyed `statoverride-passwd` and `statoverride-group`, with exact logical
paths `etc/passwd` and `etc/group`; they are not dpkg database-generation
members. Existing intent v1 supports these inputs without a schema change.
Recovery validates their role, presence, bounds and digest and never substitutes
current account files. Numeric-only records require no identity blobs.
Managed observations separately track current override/account state across
known script outcomes, so legitimate script changes can resume using the
original resolution while subsequent external drift still blocks mutation.
An initially empty override set also stays empty throughout recovery.

Diversion inputs remain genuine database-generation blobs. Managed checkpoints
also observe the live diversion database, including initial absence, and the
actual filesystem destinations. Known script updates may advance observed
state; later external byte, metadata or destination drift blocks continuation.
Diverted conffiles retained on purge are observed despite having no removal
intent.

`native-diversion-cache-v1.json` binds the invocation's genuinely loaded bytes
and file identity separately from the latest observed live identity and digest.
Its canonical base64 payload preserves exact input bytes, not a reconstructed
database. The private file is itself a managed observation and a retained
`diversion_cache` evidence member, bound to the original execution intent.
Recovery restores cached routes while pinning the matching current file;
valid in-place edits do not silently become atomic reloads. Cache byte, mode,
identity and deletion drift blocks continuation before mutation-journal replay.
Malformed live input remains refused. Known script outcomes are not rerun.

Each unpack also freezes its effective cache before payload work in a managed
`native-unpack-diversion-v1-<program-step>.json` input. Initial checkpoints
observe every planned per-step path as absent. The canonical envelope binds the
original execution intent and exact unpack step to the original
`native-diversion-cache-v1` document, including its loaded/observed distinction.
Re-entry uses these historical inputs for unpack routing and file-trigger
selection rather than the invocation's later cache. This prevents a later
postinst replacement from retargeting an earlier unpack during recovery.

Retained `unpack_diversion_cache` evidence keeps its input anchor: filesystem,
original unpack step, substep zero and ordinal zero, independently of later
journal phase numbering. Completed-result verification checks the original program step,
managed bytes and envelope binding; pending cleanup checks surviving files and
rejects unbound extra names. Cleanup validates all cache inputs before removing
any of them. The same all-before-any cleanup rule applies to
route-settlement inputs, and an orphan route-settlement name remains active
recovery evidence rather than becoming a clean-root operation input. Older
executions without initial per-step observations never gain retrospectively
reconstructed input files.

The optional `backups` array extends this envelope without changing legacy
canonical bytes. Omission selects the original cache-only phase protocol;
an empty array selects the new protocol with no ordinary backups. Records are
sorted and unique, reject backup/source collisions and contradictory inode
metadata, and bind physical/logical names, original identity/content/metadata,
and the recreated symlink timestamp. The envelope is bounded to 128 MiB;
the nested cache bound is unchanged.

New inputs also bind `deferred_removals: true` with an explicit backup array.
Omission preserves the original lowering order, including backup-capable
executions recorded before deferred removal was supported. Explicit false/null
or a flag without backup inputs is refused; recovery never upgrades persisted
inputs to a different ordering.

New inputs additionally bind a `settlement` recipe before backup or payload
mutation. Its presence selects a separate successful post-script journal;
omission preserves all earlier phase identities and canonical bytes. The
recipe carries the original unpack/database evidence, ordered removals,
directory metadata and exact incoming database publication. Binary control
bytes use canonical lowercase hex with independent content hashes. The recipe
is bounded to 200,000 unique paths and 64 MiB of decoded content within the
unchanged 128 MiB outer envelope. Null, unbound, malformed or contradictory
recipes are refused.
Managed checkpoints permit an observed absent unpack input to become a regular
file only at its original unpack anchor. Once bound, its bytes, identity and
metadata cannot be changed or adopted by later script or journal checkpoints,
even through same-byte replacement.

`native-unpack-route-settlement-v1.json` is a separate capability for the
reviewed #192 route-aware phases. It binds the original v1 unpack-input digest,
package identity, logical and publication paths, a direct post-script route or
an authenticated `native-diversion-cache-v1` digest, settlement-write
associations, trigger origin, previous/resulting ownership,
backup/conffile expectations, and any proven merged-`/usr` rewrites needed to
compare logical cache routes with canonical publication paths. Its codec is
canonical and bounded before collection or output allocation, and pure
lowering verifies the original publication cache and v1 settlement recipe
before producing route-adjusted intents. The document is not embedded in or
inferred from v1 evidence: existing v1 bytes, phase selection and recovery
meaning remain unchanged.

The successful-settlement lowering/execution path consumes an
explicit contract and a separately authenticated refreshed effective cache. It
does not mint cache authority from live bytes. It derives
new route-bound database/phase evidence, binds newly selected destinations
before mutation, authenticates retained backup identity/content/metadata,
preserves changed-route backups and stranded conffile staging, cleans
unchanged-route backups, and carries the prior conffile digest into the
rewritten resulting status. Same-inode and cached-activation decisions report
live-observation changes separately from effective-route changes. The executor
requires the held operation and stable managed recovery state and uses generic
journals; it never rewrites the live diversion database.

Ordinary v1 and legacy envelopes do not gain a route contract. Activation is
limited to recovery-managed installed-package `postrm upgrade` after its exact
outcome is durable; all other script kinds, phases and arguments retain the
old-postrm guard.

Outcome-aware lowering now covers successful failed-upgrade unwind,
double-postrm rollback and a later postinst failure. The rollback recipe leaves
the generic payload journal authoritative for old database restoration, then
describes only the reference partial state: retained incoming publication
routes, previous-only obsolete paths, stranded conffile staging, authenticated
changed-route backups and original-route triggers. Successful and
postinst-failure paths use the same route-adjusted late settlement.

A route contract is write-once at the unpack filesystem anchor; an exact retry
may finish the same managed checkpoint but cannot replace its bytes. It is
retained as separate indexed provenance evidence. Recovery verifies the
publication input/cache, current authenticated post-script cache, exact script
outcome and progress, lowered destinations and directory observations, backup
identity/content/metadata, conffile staging and digest, settlement recipe and
the actual journal. The cache-refresh-before-checkpoint window is admitted only
when the completed script outcome and managed route input authenticate the
new cache, whose stable regular-file observation must retain private mode and a
single link before and after checkpointing; unknown outcomes still return
before any journal repair. Drift at any input or artifact refuses further
mutation. Existing intent-owned artifact blobs, not caller archive paths,
supply any recovery publication, and repeated completed recovery retains
equivalent evidence.

For nonempty inventories, journalled backup creation precedes payload
publication and the status-old copy. Old postrm and its immediate failure/unwind
callbacks remain inside that payload journal. Success commits payload before
the recipe's separate removal/control/status journal, then proceeds to backup
cleanup. A committed payload is consumed without replanning staged conffiles
or republishing payload; settlement rollback retries only its bound late work.
A failed late phase remains recovery-required, not a claimed rollback of the
already-committed payload. Stable managed observations outside that late journal
are checked before replay, including exact non-journal directory membership.
Known old-postrm rollback
instead runs diverted-payload settlement, then cleanup retaining diverted
backups, before remaining compensation callbacks. A completed rollback resumes
only from matching original script outcomes; missing or unknown outcomes never
authorize script replay as completed settlement. Auxiliary publication has its
own crash boundaries and does not replace the existing database-publication seam.
Actual caller-owned recovery covers interruption inside and around these phases,
with original archives removed, immutable repeated completion, and backup/source
drift refusals.

If recovery begins before the old postrm invocation, it reconstructs the route
blueprint from the intent-owned incoming archive model and authenticated
initial package database. If it begins after a known outcome but before route
checkpointing, it requires the route name to have been bound absent by the
initial managed snapshot, authenticates a contract published before the cache
transition, and validates the private refreshed cache before opening any
settlement journal. A crash after durable contract publication but before
cache publication reconstructs the exact cache transition from the managed
pre-script cache and that contract. Older snapshots without the absent route
slot cannot acquire the capability retrospectively.
Committed settlement and cleanup phases consume their recorded journal rather
than requiring already-consumed backup preconditions again. Archive eviction,
marker-cleared recovery and repeated terminal completion retain the original
script, program, intent, result and provenance bindings.

After the generic engine verifies rollback, a new managed checkpoint may accept
only journal-authorized identity effects: regular-inode ctime changes caused by
hard links, and recreated symlink/directory inode/ctime changes at recorded paths.
Regular identities are matched by both device and inode. Bytes, type, mode,
owner, mtime, link count and other observations stay exact; unrelated drift and
regular-inode replacement still block continuation. Legacy executions retain
their previous strict checkpoint behavior.

Backup-capable unpack journals may also recover an original old-postrm, unwind,
or pre-rollback compensation whose known outcome was captured before the generic
journal settled. Admission requires the original compiler authorization, the
latest script action, its exact outcome, and a post-invocation managed snapshot
whose progress head names that invocation's in-flight record. This also covers
the active-marker-cleared and script-completed windows. A newer invocation,
pre-invocation snapshot, mismatched evidence, or spawned unresolved outcome
cannot authorize rollback.

The generic journal still chooses and verifies rollback; native recovery does
not force partially staged work forward. Reconciliation keeps original
preimages for journal-owned paths and recorded script effects elsewhere,
including same-byte atomic diversion replacement and its cache update.
Journal-only paths use the journal's original preimages. Recovery interrupted
during or immediately after rollback can resume with original archives absent;
completed scripts are not replayed. Payload may be re-materialized for unfinished
callbacks, so this is not a blanket no-payload-republication guarantee. The
no-republication boundary begins only after the payload journal commits.
Unrelated content, metadata and identity drift remains refused. Legacy inputs
conservatively refuse changed directory membership. With bound deferred-removal
inputs, a completed known script may be followed by further journalled mutation
before interruption. Recovery reconstructs a managed directory's recorded
membership only for journal-owned child paths; all other names and kinds must
match the original snapshot. The generic engine still validates those paths'
actual intermediate states. This does not authorize arbitrary membership changes
or changed-route settlement.

Changes during old postrm still block resumed mutation before journal replay
unless the exact route-settlement capability described above is present and
valid. This includes fresh-process callbacks outside the original in-memory
frame and identical atomic replacements that activate previously ignored
in-place edits.
Older executions without cache evidence retain their atomic-update guards;
they never reconstruct an effective cache from changed live bytes.
An older checkpoint without diversion observations can resume only while the
diversion database is absent; a present unobserved database blocks continuation.
Existing intent, progress and managed-state schemas are unchanged. The cache
and per-unpack evidence do not substitute or rewrite the live diversion database.

## Script and trigger continuation

Each invocation has a durable identity distinct from every other invocation,
including repeated identical triggered calls and compensation scripts.

The interpreter passes execution-local recovery state, action identities,
phase/script counters, and in-progress mutation steps explicitly through
materialization, script callbacks, trigger work, and completion. There is no
thread-local ambient execution to inherit or clear when another transaction
runs on the same thread. Distinct executions still require their own
caller-owned attempts and root locks; this does not permit concurrent mutation
of one root or change persisted action identities.

| Boundary | Recovery meaning |
| --- | --- |
| `script_prepared` | Launcher entry was not yet authorized; the script may start once. |
| `script_in_flight` without an outcome | `script_outcome_unknown`; preserve evidence and block mutation. |
| Exact recorded launcher outcome | Consume the original outcome once, without rerunning the script. |
| Continuation checkpoint | Follow the recorded compiler branch and native phase state. |

A recorded `not_started` result is an outcome governed by the original
failure/continuation policy, not permission to invent a retry. Missing trace
output is never proof that a child did not start. Exact script source/version,
bytes, arguments, environment, output and termination evidence remain bound.

Unknown-script classification takes precedence over low-level repair. For
example, an old postrm can have an unknown outcome while an unpack mutation
journal is still active; recovery must not silently roll that payload back
before recognizing the unresolved invocation.

Known failures resume only their compiled compensation branch. Trigger
continuation preserves authenticated activations, handler scheduling and cycle
signatures, and the independently derived deferred final-state expectation.
Neither a completed handler nor its queued activation may be duplicated.

Package-state no-ops are checkpointed as observed state, so recovery can consume
them even after later trigger work changes the package to pending or awaited.
Already-completed configuration/state phases are consumed before rebuilding
obsolete intermediate states; managed-state verification still runs first.
Absent-postinst handlers journal only their database transition, never a
fabricated script outcome. Restart continues the remaining handler database
phases without reusing completed phase identities.

## Provenance and completion

### Private v1 operation ownership

Detailed native provenance binds the original execution and progress head to
phase results, script outcomes, trigger work, verification, recovery history,
and terminal outcome. Publication occurs under the same outer root lock:

1. Persist terminal progress and mark the attempt complete with provenance owed.
2. Publish detailed native provenance and the root-operation completion statement.
3. Record provenance publication, then clear the active intent.
4. Clean the recovery workspace idempotently.

Receipts under `var/lib/debz/native-receipts-v1/<attempt_id>/` survive workspace
cleanup. They retain authorization, program, intent, progress, managed state,
trigger events, and exact script outcomes including captured output. Unresolved
script and mutation evidence is retained when present. Provenance enumerates
each receipt's path, byte digest, semantic digest, size, and invocation identity.
Raw archive payloads need not remain after terminal completion.

`final_state_kind = package_database_closure_v1` identifies the final status,
architecture and trigger-database closure digest; it is distinct from the full
database-generation digest. Recovery without an execution intent still takes
the outer lock and must reject newer active or orphaned work instead of
substituting an older terminal receipt.

A crash during completion must reuse verified durable evidence, not replace a
terminal receipt with a conflicting success. A crash after clearing the active
record must not leave stale workspace state that permanently blocks the next
operation. Unresolved mutation or script evidence remains a typed recovery
requirement rather than a successful transaction.

### Caller-owned production request and completion

`debz.native_execution_request` defines the canonical
[`native-execution-request-v1`](../schema/native-execution-request-v1.json)
document. It separately binds the caller's attempt, operation, request and
policy to the native program's solver request/policy, executor policy, actual
solver plan, authorization, lock, artifacts, initial database and script policy.
Root path, physical inode, architecture and runtime options are also bound.
The request has its own domain-separated semantic digest and canonical bytes
with a trailing newline.

The existing intent v1 stores this document as a separately byte-hashed request
blob. Its native request hash continues to mean the solver/lock request, not the
hash of this new document. No fields or hash domains are added to existing
intent, program, progress or provenance documents. Private fixture requests
remain readable but cannot authorize caller-owned recovery.

The typed adapter persists this mapping before package mutation and
reproduces application models from exact program-bound archive bytes. Supplied
archives are matched by digest rather than caller ordering. Recovery loads the
original database and archives, without re-solving or accepting replacement
caller inputs, under the original caller-owned root attempt.

Native package completion publishes terminal native progress and provenance
without completing, clearing or releasing the outer operation. The immutable
receipt bundle includes the production request as `execution_request`
evidence. Repository/configuration work can continue while the outer operation
remains pending. Repeated native recovery consumes that terminal receipt,
rather than rerunning scripts or mistaking later outer database changes for
unfinished package work.

Only explicit acknowledgment of the exact native receipt digest under the
original caller's held lock removes active native recovery evidence. Cleanup
can be retried from immutable retained intent/progress even after some active
files have been removed. The caller separately owns its completion statement,
provenance discharge and root-attempt release. Unresolved native work cannot
be acknowledged as completed.

### Isolated helper request v2

[`native-execution-request-v2`](../schema/native-execution-request-v2.json)
wraps the unchanged v1 execution mapping together with a helper source path,
target path, byte digest and size. It has a separate v2 digest domain; existing
v1 requests and receipts keep their original bytes and remain readable.

`debz.native_helper` makes the statically linked native trigger helper available
as a build-bound embedded payload. The helper-aware runtime stages
verified bytes under the content-addressed
`var/lib/debz/native-helper-cache-v1/` directory, with read/execute-only
permissions, and requires a successful namespace setup probe before package
mutation. Existing cache entries are verified, never overwritten. The cache is
not active recovery evidence and can be reused after acknowledgment.

Every script invocation pins the source and current target again and mounts the
helper only inside that script's private mount namespace. The invocation digest
binds the helper identity. Recovery requires the persisted v2 binding, the exact
trusted helper bytes and a successful probe; it cannot silently downgrade to
helper-free execution or repair a changed source from caller input. Completed
receipts retain the helper binary and are independently readable after active
cleanup.

Seeded roots still require an existing regular `usr/bin/dpkg-trigger` before
package mutation. No placeholder is created, and no existing target is
overwritten. Plans that remove the target's owning package, omit the target
from its replacement archive, or replace it with a non-regular entry are also
refused.

### Absent dpkg database bootstrap

For a caller-owned native install into a selected root with **no**
`var/lib/dpkg` entry, read-only preparation models an empty `status` and an
`info/format` marker without writing either. Its compiled database-generation
assertion uses a domain-separated **absent-database digest**, distinct from
every initialized empty status generation. That digest is bound by the native
program, execution request, caller's root-operation record, and durable native
execution intent. An existing dpkg directory with missing status, missing
required directories, or unimportable contents is never classified as absent;
it is refused instead of repaired.

Only after the bound execution intent and progress exist does a typed
root-mutation plan create `var/lib/dpkg`, `info`, `updates`, `triggers`, empty
`alternatives` and `parts` directories, empty `status`, and `info/format`
(`1\n`). Every target has a require-absent precondition. The version-2
bootstrap-plan digest binds the ordered path and kind of all eight targets as
well as the program, absent generation, and format marker; recovery requires
the matching eight-step journal and checks exact paths, modes, ownership,
file digests, and the new directories' initial emptiness before replay
completion. An older six-step bootstrap journal is not silently reinterpreted
or replayed as the new plan. Foreign occupants before the bootstrap
checkpoint, or contradictory journal evidence, block recovery rather than
being overwritten.

Once published, ordinary database capture and import take over. Archives may
list only the **exact, already-existing** structural directories
`var/lib/dpkg`, `info`, `updates`, `alternatives`, and `parts`: these directory
claims record ownership but never create or change database paths or metadata.
Other database children, alternate spellings, and non-directory claims remain
reserved. Existing healthy roots never use the absent-database digest or
initialization plan; roots missing either new optional directory are not
repaired by ordinary import, and an archive claim of a missing directory is
refused.

This database initializer is separate from the package-owned trigger-helper
bootstrap below. Neither the runner nor a shell gate seeds the dpkg database.

### Authenticated fresh-root helper bootstrap

Legacy [`native-execution-request-v3`](../schema/native-execution-request-v3.json)
and the authority-bound
[`native-execution-request-v4`](../schema/native-execution-request-v4.json)
are the only missing-target exception. V4 envelopes the unchanged execution
mapping and binds authorization v2, program v2, and exact-lock v3. It is
available only for an empty,
settled dpkg database and an exact transaction whose authenticated `dpkg`
archive contains one regular `usr/bin/dpkg-trigger`. No differently named
package may inherit this authority. The bootstrap binding records the caller
attempt and root identity/inode, fixed private uid/gid, plan, authorization,
program and exact lock, owner package/version/architecture and final state,
complete archive identity, size, artifact index and application digest, and the target's
exact payload digest, size, mode, uid and gid. Wrong, absent, ambiguous,
non-regular or misordered owners fail before payload mutation. Final
verification requires that the bound `dpkg` generation is the target's sole
database owner.

The compiled program must publish that target in its ordinary
`materialize_bootstrap_payload` step before any maintainer script or deferred
trigger work. The package payload and later database ownership are therefore
the only authority for the final path. Bootstrap helper bytes never occupy the
package-visible target.

After the journaled payload step completes, recovery verifies the exact target
and publishes the embedded helper at
`var/lib/debz/native-recovery-v1/helper-<attempt>.bin`. This private file is
bound to the request's helper digest and size, owned by uid/gid 0, mode `0500`,
confined beneath the no-follow recovery workspace, and removed
before that workspace is acknowledged and cleaned. The normal per-script
private mount namespace overlays it on the now package-owned target and masks
the source path with a noexec view of the original authenticated target. A
maintainer script therefore cannot execute or copy the staged helper by its
attempt-derived name.

Source publication and the namespace probe have separate durable progress
actions in `native-execution-progress-v2` for legacy authority and
`native-execution-progress-v4` for all-digest authority. Non-bootstrap
all-digest execution uses progress v3. Legacy request v1/v2 executions keep
their original progress-v1 schema and action vocabulary; helper actions are
accepted only when the retained request is the exact bound bootstrap. A
crash before source publication may publish it once; an exact
already-published source may be adopted. A crash before probe launch may
launch it once, and a recorded successful outcome may be completed without
relaunch. An in-flight probe with no outcome is immutable unknown evidence and
blocks recovery. Target, source, archive, request or ownership drift likewise
blocks before repair. Root-mutation recovery remains responsible for an
authenticated interrupted target publication, after which the target is
rechecked before helper publication.

Receipts retain the exact helper bytes and v3 request before the attempt-scoped
source is removed. A root-owned attempt-derived cleanup marker is synced before
source deletion and again after deletion; recovery accepts only the exact
prepared/completed state and removes the marker with the normal workspace.
Archive-cache eviction does not affect recovery because the original archive
bytes are already retained by the execution intent. Repeated recovery, terminal
completion and acknowledgment consume the same immutable evidence; they never
re-solve, accept caller replacement bytes, invoke `dpkg`/`dpkg-deb`, or
downgrade to the legacy backend.

This closes only the private trigger-helper bootstrap. It does not inject
`update-alternatives` or any other host executable. A script that may invoke
`update-alternatives` remains behind the existing pinned-tool gate: the exact
root-owned executable must already have been published from authenticated
package payload, with the admitted architecture digest, mode and ownership.
Absence or mismatch fails closed before that script. The fresh-root snapshot
workflow must therefore obtain the tool from its authenticated `dpkg` archive;
seeding it from the runner would not satisfy this gate.

### Experimental typed runtime API

`debz.native_runtime` exposes `execute`, `recover`, `recoverWithDeadline`, `readCompletion`, and
`acknowledge` without exposing fixture controls or a command-shaped executor.
It supports Linux non-host roots. The caller must retain a live, locked native
`root_operation.Attempt` and its coordinator throughout each call. The runtime
reopens the canonical named root without following symlinks and matches its
device/inode against the held root before work; host roots, lost locks,
legacy attempts, and mismatched root descriptors are refused.

`execute` accepts an optional absolute `transaction_executor.Deadline` in its
request. Repository callers can pass the same deadline used for acquisition
and cache preparation: it is not reset at a native phase or script boundary.
`recoverWithDeadline` applies a fresh invocation's absolute budget to persisted
recovery; plain `recover` and requests without a deadline keep their existing
behavior.

`Runtime.ExecuteRequest.external_mechanics` and
`recoverWithExternalMechanics` narrowly inject the external helper namespace
probe for hermetic integration. The runtime reaches that hook only after it has
staged and authenticated the bundled helper binding and validated the persisted
request, authorization, program, and recovery intent. The hook cannot replace
those bytes or documents; ordinary callers use the production probe by default.

This is a transient execution constraint, not a changed script policy or
persisted clock. Program, authorization, invocation-policy and recovery hashes
remain unchanged. The runtime checks expiry before helper work and execution
intent, at native program/filesystem/database/script boundaries, and before
terminal publication. Helper probes and running scripts poll cancellation;
root mutation uses its existing per-step deadline and rollback machinery.
For deadline handling, staging recovery inputs and publishing their intent
form one bounded boundary: once started, they finish before the next expiry
check rather than deliberately leaving a partial recovery workspace.
Synchronous reads, hashing, validation and individual filesystem calls are
cooperative boundaries, not interruptible hard real-time operations.

Expiry before execution intent is a refusal. Once execution intent or mutation
exists, it retains recovery authority and reports `deadline_exceeded` without
inventing a terminal receipt or releasing the caller. Rollback, durable phase
checkpoints and recording a stopped child's actual outcome may finish after
expiry so recovery remains truthful. Once terminal publication begins, that
durable publication also finishes rather than fabricating a timed-out
completion. A new recovery budget can resume safe persisted phases, but it
does not authorize replaying an unknown or deadline-cancelled script.

Prepare with `native_runtime.scriptPolicy()` and supply the owned preparation
plus immutable archive byte slices to `execute`. Inputs are borrowed for the
call and must not be changed concurrently. Authorization/program integrity,
caller binding, archive bytes, and locked database state are revalidated.
The runtime always uses the bundled trusted helper and persists a v4 request
binding authorization v2, program v2, and exact-lock v3.
It accepts neither caller helper bytes nor helper-free execution.

```zig
var report = try debz.native_runtime.execute(allocator, .{
    .attempt = &attempt,
    .prepared = &prepared,
    .archives = archive_bytes,
    .operation = .install,
});
defer report.deinit();
```

Reports distinguish `succeeded`, `failed`, `recovery_required`, and `refused`.
Success or terminal failure requires an independently owned native provenance
receipt in `report.receipt`; `report.deinit()` releases that receipt. Diagnostic
text is static, and results do not invent dpkg argv or command exit reports.
Unsupported work does not hand off to a legacy backend. Refusals with active
native evidence or an already-mutated caller operation become recovery
requirements, not proof that nothing happened. Errors propagate; callers must
retain the original attempt and evidence rather than infer rollback or clear
state from a failed call.

`recover(allocator, &attempt)` accepts no new archives, plan, policy, or helper.
Both unfinished recovery and terminal receipt adoption require the original
helper binding to match this build's bundled helper. Use the original build
for outstanding work if the bundled helper changes. Private v1 helper-free
recovery remains compatible through its private adapters, but cannot be
adopted through this API.

`readCompletion` returns a separately owned terminal receipt without mutation.
Terminal recovery and acknowledgment validate retained helper bytes, so they
do not require the current helper cache or target to exist and do not probe a
namespace or rerun scripts. After durably accepting the receipt in its own
operation workflow, the caller passes the exact `digest_sha256` to
`acknowledge(allocator, &attempt, digest)`. Repeated acknowledgment and terminal
recovery after active cleanup are supported. The caller still owns outer
completion, provenance, and lock release.

`prepare(allocator, request)` captures full database, installed script/conffile,
archive, origin, and trigger evidence under the caller's held attempt. Its
result owns a prepared program or diagnostic, or explicitly reports an
unchanged validated closure without creating an executable authorization.
It accepts no fixture configuration. `canAbandon` checks both the caller state
and native active/terminal evidence before permitting pre-mutation abandonment;
the outer record's pre-mutation flag alone is insufficient. The shared
`hasActiveEvidence(allocator, root)` inspection, used under the caller's held
root lock, also recognizes orphan programs, workspaces, progress, script/trigger
evidence, and mutation journals. Completed retained provenance is not active
execution evidence.

Core product/CLI planning, download, execution, and recovery use these typed
contracts. Native mutation requires a reviewed v3 lock and a supported non-host
root. Native recovery accepts no new repository or lock inputs and reads only
the original persisted execution evidence. Terminal success and known failure
bind `root-operation-completion-v2.json` to the exact native provenance-v2
receipt (while legacy execution remains readable through v1), publish
the outer provenance transition, acknowledge native evidence, and finally clear
the caller's active record. Every boundary is restartable. Generic acquisition
cannot reclaim a native program-bound attempt in either the pre-intent or
pending-acknowledgment window, and an orphan native intent blocks other engines.
Empty v3 closures represent last-package removal or purge,
with explicit action authorization and retained configuration modeled separately.
Remaining consumer integration and full pinned parity remain roadmap work.
Legacy stays default, and there is no fallback.

Typed product results additionally return `native_completion` only when a
terminal native report reaches the end of this completion path. The by-value
evidence binds the original operation, outcome, attempt, lock, caller hashes,
receipt, completion and program. Ordinary cleanup returns `cleared`; an
outer-owned result is `retained` even when its released marker awaits
finalization. An interrupted path, unchanged closure or no-work recovery does
not borrow an older receipt to manufacture this evidence. Generic command JSON
continues to omit native metadata. Consumers can bind a particular returned
completion during read-only family verification; see
[the package-family contract](zvmi-package-family.md#binding-a-particular-returned-completion).

The internal batch workflow uses the same native receipt and completion
protocol. Its recovery request must match the original operation,
canonical selectors, and request policy before any abandonment or replay.
Actual-process coverage includes signed-repository batch install/remove,
unchanged closures, known failure, all five receipt/completion crash boundaries,
and refusal of mismatched requests or replacement recovery inputs.

An outer-owned workflow can reserve a pre-mutation attempt and later execute
that exact request. Unchanged or refused pre-mutation attempts retain an
abandoned owner marker. Normal owned success acknowledges native evidence
before clearing the root record, leaving a released owner marker for explicit
outer finalization. A released marker is not silently consumed by a new native
acquisition; a recovery interrupted before record clearing finishes the release
without moving the owner backward to pending.

With deferred recovery, completion first publishes a pending owner marker,
then the root provenance transition. Both marker digests bind the native
completion document directly; native provenance does not use the legacy
command-journal wrapper digest. The completed root record and native evidence
remain until the outer caller durably retains the exact completion token.
Owned known failures also use pending acknowledgment while preserving their
terminal failure outcome and exit 7. Unknown outcomes remain blocked.

Acknowledgment uses the caller's existing rank-0 lock, validates receipt-backed
completion against the original request, and preserves authenticated exact v3
review ownership. Native cleanup precedes marker acknowledgment and root-record
clearing. Independently retained owner evidence supports retries after native
cleanup, marker acknowledgment, record clearing, and marker clearing; none of
these retries accesses replacement repositories or replays package scripts.
Damaged completion or receipt evidence and orphan active evidence refuse cleanup.
Physical host-root denial also applies to acknowledgment and finalization.

Clean reconciliation is an internal exclusion-only handoff for an outer caller
that has already authenticated its state and evidence. It requires a retained
exact owner token, an absent root record/marker, and no active native evidence
under the same root lock. Pre-mutation claims bind the outer state, profile,
lock digest, and semantic request; post-mutation claims bind the original
execute request and the outer caller's lock/evidence digests. Both preserve
reviewed v3 ownership and require explicit exact-owner finalization. A claim
does not verify package closure or manufacture a native completion receipt.
It accepts no replacement recovery inputs or cache/state access. Actual-process
coverage interrupts claim publication and finalization while retaining the
outer token independently of the candidate root. Consumer-specific public
integration remains gated.

## Independent acceptance

`tools/test-native-recovery.py` runs native execution in real guarded chroots
and terminates the actual fixture process at selected durable boundaries,
without ordinary unwinding. The harness requires the reserved crash exit code,
not a normal report pretending that a crash occurred. Script-return faults
occur after the child is reaped, avoiding orphan fixture processes.

Recovery receives no caller archives; the original supplied archives are
removed after interruption. Recovered package state, status-old, filesystem
effects and exact traces are compared with real dpkg. Separate assertions bind
provenance to the original root, attempt, authorization and program, require
terminal publication before clearing, and prove repeated recovery does not
rerun work or replace the terminal receipt.

Known inert metadata (`config`, `templates`, `shlibs`, `symbols`) participates in complete
database-generation and retained-blob evidence as raw bytes, including binary
contents and safe non-default modes. Config additionally binds executable mode
and root ownership. Its authenticated archive/database evidence reconstructs
pre-unpack staging after archive eviction, while completed publication remains
immutable and does not restage it. Actual caller-owned core recovery covers
install, upgrade, removal and purge with file triggers and original archives
evicted. It preserves original metadata for restoration and refuses byte,
mode, ownership, or deletion drift without changing package state or the
helper. Unknown preinst outcomes retain exact `tmp.ci/config`; unknown postinst
outcomes retain the published info member and no staged config.

In a bootstrap closure with multiple config-bearing archives, `tmp.ci/config`
is owned by only one package at a time. Each bootstrap program step records
staging as its native database substep 0, payload/control publication as
filesystem substep 1, and exact-slot removal as database substep 2. Removal
uses the caller's existing authorized root-operation intent and its own typed
root-mutation journal; the next package cannot stage until that phase completes.
After a crash during staging, publication, or removal, mutation recovery
settles the active journal first. Replaying an already-cleared step requires
completed publication and removal progress and verifies its installed config
against the authenticated archive; it neither restages nor removes a later
package's slot. A not-yet-cleared step still requires its own exact staged
config; missing, foreign or changed bytes/mode/ownership remain refusals.
This serialization does not move or invoke config scripts or change configure
callback ordering.

Case-only package leaf names require a root-mutation
`assert_case_sensitive` step immediately before each publication. The guard
binds an existing, unchanged witness and exact parent directory into the
journal. The engine rechecks it before the no-replace publication and before
rollback classifies either spelling. A crash before or after either rename
restores the old state when the directory still proves case-sensitive; lost
proof or an externally replaced directory becomes `recovery_required` instead
of treating the other spelling as a foreign entry and guessing at cleanup.

Caller-owned core cases also cover conffile purge and fresh/upgraded
configuration retry, including partial database publication, prepared/recorded
postrm and postinst outcomes, failed purge and its subsequent trigger work,
including immediate/deferred file and helper activations, and unknown outcomes.
Original archives are evicted. Read-only settled conffiles are included in
managed observations before publication and retained
through interrupted phase recovery; their drift refuses without mutation.
Successful and failed receipts/completions remain unchanged on a later clean
core recovery call, which truthfully reports no active work.

The bounded families cover preparation, filesystem/database publication,
provably unstarted and recorded script outcomes, unknown script outcomes
(including the old-postrm/unpack overlap), failure compensation, dynamic
trigger continuation, completion windows, and changed intent/progress/artifact
or managed-root evidence, including drift after a completed phase and stale
receipts with newer unresolved work. Existing exhaustive primitive crash coverage is
reused rather than duplicated as a cross-product.

Caller-owned fixtures additionally crash at preparation, filesystem publication,
recorded script outcomes and native provenance publication. They preserve
distinct caller hashes, exercise known failure compensation, leave outer
completion pending until acknowledgment, and reject a rehashed request that
substitutes caller policy. Mixed genuine production-preparation units cover
install/remove and install/purge, including repeated recovery after outer
database work and interrupted acknowledgment cleanup.

Helper-aware cases retain the original package-owned helper bytes and inode
through execution, crashes and acknowledgment, including dynamic trigger
processing. The oracle recomputes every helper-bound invocation digest from
retained request, program and script evidence. Missing targets, changed helper
bytes and attempted helper-free recovery are refused.

Cumulative-deadline cases exercise public helper-bound execution and recovery,
including expired startup without a helper target, two scripts sharing one
absolute budget, a durably cancelled child that cannot be replayed, and
expired/fresh recovery using only persisted inputs. These run in the default
amd64/arm64 recovery workload; `-Dnative-deadline-only=true` selects them for a
focused local run. Native-unpack units additionally expire during filesystem
rollback and after a database phase while preserving original caller authority.

Repository projection cases run genuine preparation under the real supervised
root callback. They cover missing/foreign authority before namespace creation,
fresh-callback adoption of bound callers, scope loss after lock acquisition,
and retained ownership when cleanup loses scope. They also preserve the
ordinary backend admission gate and legacy behavior. These cases
join the default recovery workload; `-Dnative-repository-projection-only=true`
selects them with the existing read-only projection cases.

Typed repository execution cases use the verified CAS adapter in actual
supervised root callbacks. They exercise successful and failed scripts,
deadline interruption after intent, fresh persisted-only recovery after CAS
eviction, stable repeated receipts and traces, missing helpers, unchanged
closures and owned preparation diagnostics. Original caller ownership remains
pending through package and import/refresh callbacks; package completion does
not discharge repository bootstrap. Genuine
terminal receipts are retained in backend-distinct operation-local files and
read back in fresh callbacks. Cases cover expired publication, interrupted
rename/sync convergence, refusal to repair corrupt or missing bound retention,
unchanged caller and receipt identities, and scope loss between live proof and
retention/readback followed by fresh legitimate adoption. Repository units
cover every publication boundary, no-follow storage and allocation cleanup. The
default recovery workload includes these cases; use
`-Dnative-repository-execution-only=true` for the focused family.

Live repository package-state verification additionally exercises shared native
authorization, progress, active-evidence and current-database checks under the
original caller, without an outer completion or replacement lock. Real cases
reject healthy-package database drift, unknown active evidence, canonical but
inconsistent receipt progress metadata, opposite terminal outcomes, late expiry
and scope loss after verification. Both success and known-failure paths cover
allocation cleanup. Restored evidence and fresh legitimate callbacks verify
without replay, acknowledgment or ownership changes. Existing settled and
owner-bound verification remains covered by the core recovery family.

Repository package checkpoints reuse the original persisted locked state, plan
and v3 lock after package execution or fresh recovery with no CAS inputs. Real
cases bind successful/failed native outcomes to durable generic repository state,
refuse changed or missing inputs and leaf symlinks, expire before rename, detect
input replacement during publication, converge after interrupted rename and
refuse to repair missing already-bound receipts. Fresh callbacks preserve the
checkpoint inode, script trace and original caller; namespace loss before
accepting a checkpoint refuses. State-model units additionally preserve an
installed descriptor on known package failure, later diagnostics and allocation
cleanup. These remain part of the same repository execution family.

The descriptor fixture also includes genuine static sources and signing keys.
After CAS eviction, new supervised callbacks obtain the descriptor solely from
the receipt-bound native intent blob, verify installed material, durably import
the target manifest and perform authenticated refresh. Coverage includes
changed material evidence, missing original blobs/files, expiry and input or
configuration replacement before rename, interruptions after manifest and state
rename, refresh deadline/authentication failure, missing or corrupt bound
manifests, real namespace revocation and fresh legitimate adoption. No-refresh
recovery creates no metadata cache, known package failure performs no import,
and repeated refreshed checkpoints issue no refresh requests. Selected
allocation failures preserve owned cleanup and checkpoint identity. The external
oracle checks original bindings, imported source/keyring digests, truthful phase
flags and private manifest/state permissions; caller ownership, helper identity
and script traces remain unchanged throughout those stages.

Final supervised callbacks exercise actual repository completion for refreshed
success, original no-refresh success and known package failure. They interrupt
terminal state, completed caller, local/shared completion publication,
provenance publication, acknowledgment and root clear. Fresh callbacks adopt
the original caller even after partial or completed native cleanup, without
replaying scripts or reacquiring descriptor bytes. Coverage rejects incomplete
refresh and outstanding diagnostics, changed request/policy, caller removal
during lock acquisition, missing/corrupt/different bound completion, leaf
symlinks, downgraded terminal state, missing/changed manifests, pinned-manifest
replacement before completion rename, deadline expiry and namespace revocation.
Selected allocation failures release owned results without replacing published
evidence. Same-held-caller retries preserve state/completion identity and keep
the lock after explicit root clear. The independent oracle checks canonical
completion and discharge digests, original caller/receipt bindings, truthful
success/failure, matching private local/shared completion, absence of active
native inputs, and unchanged helper and script evidence.

The same runner additionally exercises the joined native repository resume
adapter in separate success, known-failure, interrupted-intent and clean-caller
cases. It checks original state/plan/lock refusal before package recovery,
caller/policy and deadline refusal, genuine pending reports without fabricated
receipts, refresh interruption under the shared deadline, and fresh adoption
after completion/provenance and acknowledgment interruptions. The original
package CAS is already empty. Exhaustive original-input loading allocation
failures and selected full-pipeline failures preserve owned cleanup, while
repeated completion stays stable. After root clear, a clean held caller verifies
the latest matching historical success, original no-refresh success or known
failure without adopting the old execution identity. Clean callers without
advanced evidence return not-started, not unchanged bootstrap.
The existing external completion, receipt, helper and script oracle applies to
both the component and joined-pipeline cases; private-process limits are unchanged.

Historical cases exercise missing/symlinked inputs, corrupt or differing
local/shared completion and receipt, changed original state/plan/lock, discharge
and caller/policy/architecture/outcome mismatches, changed installed source,
keyring, manifest and an unrelated held package. Active native evidence and
deferred/review ownership refuse. Pin replacement, deadline expiry and projection
loss are checked around package verification, with legitimate fresh scoped
readback afterward. Selected whole-history allocation failures release ownership
of their results without modifying the caller. The independent oracle compares
eight historical files' bytes/inodes with a pre-read snapshot and checks that the
new caller has no execution program or mutation evidence. Operation-scoped lock
units preserve strict full-closure behavior for other native consumers.

Two additional private-root cases start with an already-installed descriptor
and genuine descriptor-bound v3 lock, then complete bootstrap with and without
refresh. They require actual no-execution preparation, retain the original
archive and dedicated no-execution evidence, and exercise interruptions through
import/refresh, terminal state, caller abandonment and root clear. Same-held
and fresh callbacks converge without native receipts, programs, helpers,
maintainer scripts or mutated-caller completion documents.

The cases also cover refresh failure, missing/symlinked/replaced inputs,
unavailable bound archives even when identical bytes are offered, corrupt
no-execution proof, changed installed material and unrelated held-package state,
competing native/deferred ownership, deadline/projection loss and selected
allocation failures. The oracle validates the no-execution schema and canonical
digest, original proof publisher and current unexecuted caller, descriptor/lock/
plan binding, unchanged dpkg status and absence of native execution artifacts.

The same family exercises `Backend.nativeInterface()` through the public
repository request/result API inside genuine projected callbacks. Fresh changed
and held unchanged descriptors, each with refresh and no-refresh, cover actual
acquisition/planning rather than pre-staged executable inputs. Further cases
cover known script failure, interruption after native intent, locked-state
publication and caller completion, revoked projection authority, post-install
refresh failure and acquisition deadline expiry. Fresh callback retries and
historical readback run after descriptor CAS eviction, with descriptor transport
disabled once native inputs are retained. A forbidden legacy process hook
ensures the typed path does not use command execution. The independent oracle
validates canonical API results, native versus no-execution evidence, preserved
holds, exact script traces and helper bytes/inodes, and final caller cleanup.
The same workload additionally invokes the actual `debz repo add
--transaction-backend native --root /` CLI from disposable roots. Signed local
bootstrap and descriptor repositories exercise fresh success, no-refresh,
held no-execution completion, known script failure, persisted refresh recovery
and historical readback after removing the incoming descriptor archive. A
loopback HTTP fixture also exercises real threaded acquisition in the fresh
child I/O context, query redaction and descriptor-free historical readback.
Each initial, recovery and historical CLI invocation enters its own disposable
PID/mount namespace while reusing the same retained root. The outer 120-second
fixture timeout is unchanged; the child watchdog allows the request's original
deadline and bounded teardown to finish instead of killing a valid invocation
at an unrelated shorter limit. Per-invocation timings and timeout-state
diagnostics identify the exact failing lifecycle stage.
Catchable interruption preserves unknown script outcomes and never replays
the script; separate cases exercise the projection lock's cumulative deadline and catchable interruption,
unsafe runtime directories and expiry during real package work. The roots
contain neither dpkg nor dpkg-deb, and the oracle checks canonical results,
native/no-execution evidence, root ownership, exact script traces, helper
bytes/inodes and absence of leaked projections. Transport units cover invalid,
truncated, oversized, noncanonical and failed-child result refusal.

```sh
zig build test-native-recovery -j2
zig build test-native-recovery -Doptimize=ReleaseSafe -j2
zig build test-native-recovery -Dnative-deadline-only=true -j2
zig build test-native-recovery -Dnative-repository-projection-only=true -j2
zig build test-native-recovery -Dnative-repository-execution-only=true -j2
zig build test-native-recovery -Dnative-repository-cli-only=true -j2
```

The native Linux amd64/arm64 runner requires the existing dpkg/chroot fixture
prerequisites and passwordless sudo. Only fixture execution is elevated.
Artifacts stay under the worktree's `.tmp`; `--workspace` retains a new direct
child there. `test-native-recovery-unit` runs focused journal/provenance units,
and the default unit target includes the independent oracle regressions.

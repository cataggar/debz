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
The CLI supplies its deallocating process allocator to native preparation,
execution and recovery while keeping API result ownership in its
argument-parsing arena. The latter cannot reclaim phase-local allocations.

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
The reviewed amd64 `stonking` snapshot admits an additional exact executable
digest for `dpkg` 1.23.7ubuntu2. The older dpkg 1.22.22 pins remain intact;
the new pin does not authorize arm64, another executable digest, or a wider
script command grammar. The exact `less` 668-1build1 amd64 preinst has one
script-digest-bound exception for its literal `--quiet --remove pager /bin/less`
line. Only a new-package `preinst install` can use it: that line is in the
unreachable `upgrade` branch, and every alternatives group remains immutable.
The same authenticated archive's exact postinst admits only its literal
`--quiet --install` of `pager` with the `pager.1.gz` slave, on a new
`less:amd64` 668-1build1 `postinst` with arguments `["configure", ""]`.
This reachable command is not inert: typed transition validation must account
for the registered provider. The exact snapshot-tool check, pre/post capture,
immutable provider/tool inputs, and recovery-on-unknown-outcome still apply;
other scripts using `--quiet` fail closed. See the
[alternatives reference](dpkg-alternatives-reference.md#native-admission).
The corresponding `README.dpkg-new` conffile staged before `dpkg` configuration
is accepted only with the exact pinned README bytes and metadata and is
included in the pre-script managed-path observation; other staging entries
remain refused.

The signed `bash` 5.3-3ubuntu1 amd64 postinst has a separate allowance bound
to its exact script digest for one literal priority-10 `builtins.7.gz`
install followed by `|| true`. Only a new-package `postinst configure` with
exactly `["configure", ""]` and the snapshot amd64 tool is admitted. The
shell may mask that tool's nonzero exit, but native code neither invents a
script outcome nor swallows another failure: the complete script runs and
its actual outcome is journaled. Normal return permits only an unchanged
group or the typed install transition, with immutable inputs and unmentioned
groups unchanged; unknown or malformed state still requires recovery.

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

`zig build test-native-recovery-zig` runs the additional Zig-owned scriptless
core completion-crash and helper-bound deadline acceptance in guarded roots.
`zig build test-native-recovery-zig-scriptless` separately runs the six
scriptless-trigger recovery cases: previously installed or newly installed
handlers, both sides of trigger completion, and postinst-presence drift.
Each case uses a real exit-86 child and an archive-evicted fresh recovery.
The Zig consumer checks the persisted handler's absent postinst hash, pending
status before completion, drift refusal without package mutation, exact
reference-root parity, retained scripted-trigger receipt count, and immutable
recovery repeats. This target runs in both modes on both CI architectures;
other Python recovery matrices and both Python gates remain required.
`zig build test-native-recovery-zig-statoverride` runs all 17 named
statoverride crash/recovery variants in fresh guarded roots, including
install, upgrade, remove and purge, failed postinst, script-replaced account
and override files, a newly created override database, and six independent
identity, stored-blob and owner drifts. The Zig runner checks exact persisted
account/group bytes, archive-evicted core recovery, unchanged helper inode and
bytes, pinned-dpkg filesystem/database/script parity or refusal without
package mutation, terminal completion, and immutable repeated receipts.
Both optimization modes are required on both CI architectures; these
variants do not retire either Python recovery gate.
`zig build test-native-recovery-zig-literal` runs all five literal-backslash
path crash/recovery variants: first install at filesystem publication and
trigger outcome, upgrade with a locally edited conffile, and conffile or
staged-script drift. The Zig consumer requires real exit 86, archive eviction,
pinned-dpkg root parity or drift refusal without mutation, an unchanged
package-owned helper, retained literal trigger/path authority, bound outer
completion, and immutable repeated recovery. Both CI modes and
architectures run this target; other Python recovery matrices remain required.
`zig build test-native-recovery-zig-metadata` covers all eleven retained
metadata recovery variants in real guarded roots: install, upgrade, remove,
purge, and seven independent bytes/mode/ownership/deletion drifts of the
installed `config` and `symbols` members. It requires the original archived
member bytes in the retained intent for upgrade and remove, pinned-dpkg
root/script/database parity for successful recovery, drift refusal without
mutation, unchanged package-owned helper identity, bound completion, and
immutable replay after archive eviction. CI runs Debug and ReleaseSafe on
both architectures while the remaining Python recovery gate stays required.
`zig build test-native-recovery-zig-conffile` executes all twenty lifecycle
crash/recovery cases for configured or failed-configure packages and removal
through purge. The matrix includes deferred and in-script trigger activation,
failed postrm, database publication, an in-flight script-return refusal, and
conffile drift. Each successful case requires a real exit 86, evicted
archives, exact pinned-dpkg root/database/trace parity, bound receipt and
outer completion, unchanged package-owned helper, and immutable repeat;
unknown or drifted inputs refuse recovery without package mutation. Both
architectures run Debug and ReleaseSafe. Other recovery scenarios still
require the Python gates.
`zig build test-native-recovery-helper-zig` runs the separate, bounded
CRASH/HELPER real-process acceptance; both targets honor
`-Dnative-reference-dpkg=...`. The helper target selects a valid crash seam
that is *not* reached by a scriptless install and rejects its actual exit 0,
requires real exit 86 without a report, and rejects a stale success report
left at the report path before a real exit-86 child. It refuses invalid
acknowledgment, helper ownership and replacement recovery archives before
writing a request. Script-bearing installs crash at intent, script-outcome,
provenance, and in-flight script-return boundaries. The caller removes the
archive, then a fresh child consumes only persisted inputs. For successful
cases, the Zig consumer decodes the original typed helper request, binds
the distinct caller/program hash domains and retained request/helper/script
bytes to the actual provenance, recomputes helper-mounted invocation digests,
compares exact script arguments with the real in-root trace, and compares
root/database/trace snapshots to pinned dpkg. Repeats and caller acknowledgment
cannot replay work or rewrite provenance; the package-owned helper retains
its inode and bytes. Downgraded helper ownership, changed cached helper bytes,
and a missing persisted request block recovery without package mutation.
In-flight unknown script recovery and a new purge remain blocked and preserve
the script-produced payload and trace, the actual archive's staged
`tmp.ci/config`, and the absence of a prematurely published `info/*.config`.
A completed helper-bound receipt can also be recovered twice while **both**
the deployed helper and cached source are temporarily absent, retaining its
original claim, receipt and complete root inventory before acknowledgment.
An absent package-owned helper target refuses before mutation or placeholder
creation; both repeat recoveries remain fail-closed. A genuinely unbound
caller request with a changed policy and recomputed request/intent digests
still refuses twice against its original root claim without changing the
complete root inventory. A real `after_active_clear` crash permits a new
upgrade matched to pinned dpkg, but the old receipt does not mask either a
newer active legacy script or an orphaned script on repeated recoveries.
The comparator rejects a deliberately duplicated real trace, and the
snapshot guard rejects a deliberate rollback
of that real script-produced payload; neither mutation is accepted as a
recovered state. The unprivileged Zig unit oracle additionally rejects
changed script arguments, helper digest/policy and duplicated trace lines.
After #231, failed-postinst crashes at `after_failure_outcome` and
`after_script_failure_state` retain the pending root claim and known script
exit. The latter also persists the failed script and same-step database
transition to half-configured before the crash. Fresh helper-bound recovery
returns `script_failed`, verifies the retained trace and failed provenance
against pinned dpkg, and repeats and acknowledges without replay or receipt
replacement.
These controlled negative mutations are private-root/oracle checks, not claims
that the native runtime emitted a success report on a crash or attempted a
rollback. This slice does not cover rollback-clock integration, consumer
parity suites, family/repository transport, or every helper bootstrap seam.
The required Zig core/workflows CI shard runs this helper target alongside
core, FAMILY, repository, rollback-clock and signed-parity Zig acceptance against its
SHA-256-pinned dpkg on both architectures in Debug and ReleaseSafe without
removing or weakening either Python gate.
The two Python recovery gates remain mandatory until the complete
amd64/arm64 Debug/ReleaseSafe matrix reaches end-to-end parity.

### `exercise()` real-process case ledger (separate from workflow parity)

This ledger tracks the **named scenarios** in
`tools/test-native-recovery.py::exercise`, not the separately completed
`exercise_workflows` selector. `test-native-recovery-helper-zig` is a required
Debug/ReleaseSafe CI target on amd64 and arm64; its pinned-dpkg comparison is
executed for successful install/recovery and the post-clear follow-on upgrade.
`covered` below means a bounded real driver invocation with a checked
observation, not a fixture-only, schema-unit or production-only assertion.
The shared ordinary runner exercises real exit 86 without a completion
report, evicts the original archive before a fresh persisted-only recovery,
matches installed/failed package and trace state to pinned dpkg, verifies
the original intent/transport or typed caller request and retained receipt,
then checks immutable repeat and caller acknowledgment where applicable.

| Python scenario | Zig execution and observation | Status |
| --- | --- | --- |
| `typed-runtime-completed-install` | `native_recovery_helper.zig::completedWithoutLiveHelper`: installed receipt and bound evidence; two terminal recoveries with both helper paths absent preserve claim, receipt and complete root inventory; acknowledgment and pinned dpkg match. | Covered. |
| `isolated-helper-{after_execution_intent,after_script_outcome,after_provenance}` | `native_recovery_helper.zig::caseRun`: real exit 86, archive eviction, typed request/proof, helper inode/bytes, repeat recovery/acknowledgment and pinned dpkg state. | Covered. |
| `isolated-helper-target-absent` | `native_recovery_helper.zig::missingPackageOwnedHelper`: first refusal `NativeHelperBootstrapOwnerMissing` with `mutation_started:false`, no helper/cache/intent/placeholder; two repeat recoveries refuse `FileNotFound`, preserving claim and complete root inventory. | Covered. |
| `isolated-helper-changed-{downgrade,bytes}` | `native_recovery_helper.zig::caseRun` (`helper-intent` downgrade; `helper-source-drift`): `NativeHelperBindingRequired` or `HelperDigestMismatch`, package snapshot unchanged; helper target inode/bytes checked. | Covered. |
| `caller-changed-request` | `native_recovery_helper.zig::rehashedCallerPolicy`: real **non-isolated** caller crash, original v1 request rehashed after changing caller policy, intent resealed and typed-decode validated; two `RecoveryRequestBindingMismatch` refusals preserve original claim and complete root inventory. | Covered. |
| `typed-runtime-unknown-script` | `native_recovery_helper.zig::caseRun` (`helper-unknown-script`): executed preinst return-before-outcome, retained produced payload, trace, actual staged config bytes and absent published config through repeated blocked operations. | Covered. |
| `after_active_clear` | `native_recovery_helper.zig::afterActiveClearLegacyEvidence`: real crash/recover, pinned-dpkg-matched follow-on upgrade and verified earlier proof; newer legacy active-script and orphaned-script evidence refuse twice without changing package state or masking the old receipt. | Covered. |
| `caller-{after_execution_intent,during_filesystem_publication,after_script_outcome,after_provenance}` | `native_recovery_helper.zig::recoveredOrdinary`: four real non-isolated caller-owned crashes, typed v1 request/proof, pinned dpkg, immutable repeat and explicit acknowledgment. | Covered: all four. |
| `typed-runtime-known-failure`, `caller-known-failure` | `recoveredOrdinary`: actual failing preinst at `after_failure_outcome` in each distinct helper-bound/non-isolated mode; pinned-dpkg failed snapshot, retained failed receipt, repeat and caller acknowledgment. | Covered: both. |
| Generic unowned `after_execution_intent`, `during_filesystem_publication`, `during_database_publication`, `after_script_prepared`, `after_script_outcome`, `after_provenance` | `recoveredOrdinary`: six real non-core unowned crashes, original archived transport blob, pinned dpkg, terminal evidence and immutable repeat. | Covered: all six; `after_active_clear` covered separately above. |
| `known-failure-compensation` | `recoveredOrdinary`: real ordinary failing preinst/compensation crash; pinned-dpkg failure state, retained failed receipt and immutable repeat. | Covered. |
| `unknown-script`, `unknown-upgrade-postrm` | `native_recovery_helper.zig::blockedUnknown`: real ordinary preinst/installed old-package postrm exit 86, evicted archive, preserved in-flight script and original claim, `script_outcome_unknown` refusal twice, blocked purge; pinned dpkg seeds the upgrade's old package. The active claim may advance its generation on refusal; all other root paths/modes/bytes, script and helper identity are compared. | Covered: both. |
| `known-trigger-outcome`, `isolated-helper-trigger-outcome` | `native_recovery_helper.zig::triggerOutcome`: two real `after_trigger_outcome` exit-86 cases with pinned-dpkg package/trigger parity, typed/unowned original evidence, retained receipt event order `automatic/source/debz-a` then `dynamic/recovery-a/debz-b`, immutable repeat and isolated-caller acknowledgment. | Covered: both. |
| `changed-{intent,progress,artifact,managed-root,completed-phase}` | `native_recovery_helper.zig::corruptedOrdinary`: five real ordinary exit-86 crashes and original archive eviction; truncates intent, appends progress corruption, changes retained artifact bytes, or replaces managed payload (ordinary filesystem / postinst-prepared phase). Two recoveries and a new purge refuse, preserving immutable package and helper state; only the active claim's progress fields (generation/state/phase/step/timestamp/digest) may advance, while its sticky authority remains exact. The four scriptless cases correctly preserve **absent** active-script evidence, while the postinst-only case preserves its prepared script. | Covered: all five. |

All **32 named `exercise()` scenarios** in this ledger now have bounded
real-process Zig executions in the required helper target, including the
cases added before this slice. This does **not** claim parity for any other
Python recovery selector: both mandatory Python gates and the existing Zig
core, workflow, repository and family targets remain in CI. Exact digest
inventory and audit mutations protect the new executed cases. The ordinary
`after_provenance` test initially exposed `CompletionChanged`: a completed
record already had a receipt before crash, then published provenance advanced
its record generation. The production finalizer now reuses that **exact**
existing completion only after validating its sticky record binding, the
single-generation provenance transition, the digest binding to that receipt,
and unchanged transaction/journal/discharge evidence. Different attempts,
unbound claims, or changed receipts still use the fail-closed publication
path; no authority is inferred from a stale or merely same-attempt receipt.
The shared private-root program installer streams Debug executables in bounded
chunks rather than imposing a 192 MiB whole-file limit. This keeps the x64
repository CLI case executable without weakening its interpreter and library
bootstrap checks.

### Numbered diversion recovery migration

`zig build test-native-recovery-zig-diversions -Dnative-reference-dpkg=...`
runs a **separate** Zig acceptance executable in Debug or ReleaseSafe. Each
declared number corresponds to the same numbered tuple, in source order, of
`exercise_diversion_recovery` in `tools/test-native-recovery.py`; a run reports
the exact executed/declaration count, fails on a missing selector, and does
not substitute a fixture/schema or a lifecycle-only test for a crash case.
The declared and executed set is **all 100 Python tuples, 001–100**; the
compile-time ordering check rejects omissions and duplicates. CI requires
the entire set in **both**
optimization modes on amd64 and arm64, with the SHA-256-pinned private dpkg;
`-Dnative-zig-recovery-diversion-case=N` selects a single number for
diagnostics only. The full Python recovery gate and its diversion-only
selector remain required.

These cases install a package-owned `dpkg-trigger` helper, execute package
scripts and triggers in real guarded roots, run the pinned dpkg on the
reference root, demand a real exit 86 and absent crash report, remove the
supplied archives, and start recovery in a new native
process with **no** replacement archives/packages. They cover diversion
database creation, in-place and atomic replacements, `dpkg-divert`, install,
upgrade, remove and purge, postinst trigger continuation, unknown/failed
script outcomes, mid-unpack route changes, backup-probing old postrm and
route/settlement windows. Successful continuation compares filesystem, dpkg
database and script/trigger trace snapshots, preserves the helper's bytes
and inode, validates the original attempt/program/provenance and retained
diversion evidence against the
guarded root, and proves immutable repeated completion. Cache bytes/mode/
deletion, retained unpack cache, old backup bytes/mode/deletion/source,
old-postrm route/cache/payload, directory-member and late settlement-input
drift must refuse without package mutation; unknown outcomes remain blocked
on repeat. Backup probes inspect real restored hardlink and symlink identity,
mode, clock and old payload during the old postrm. The final 28 migrated tuples
specifically force either two failed postrm invocations, a one-failure
old-postrm unwind, a second real exit-86 recovery process *during or after*
known unpack rollback, or the genuine settlement-rollback injection. The
failure cases compare restored symlink timestamps within the invocation
clock to pinned dpkg and to the retained unpack-backup evidence; success
cases check route-settlement bindings and, when an unpack payload already
committed, require its inode/bytes/mtime and staged conffile contents to
survive recovery. There are **no unexecuted tuples in this Python function**.
This local parity result does **not** retire either Python gate: complete
amd64/arm64 Debug/ReleaseSafe CI and the other recovery groups still require
their own executed parity.

For the core/deadline target,
`-Dnative-zig-recovery-core-only=true` and
`-Dnative-zig-recovery-deadline-only=true` select its two workloads; the
existing `-Dnative-reference-dpkg=...` selects the verified private reference.
It checks real process exit 86 without a report (including interrupted
filesystem/database journals and outer completion windows), archive eviction,
fresh persisted-only recovery, exact dpkg package state, receipt/completion
bindings, immutable repeats, zero-budget refusal, cumulative script
cancellation and unknown-outcome refusal. Its core selector also executes
a failed preinst at `after_failure_outcome` and an in-flight script return at
`after_script_return_before_outcome`: the former requires pinned-dpkg failed
root/trace parity and bound failed completion after archive eviction; the
latter refuses recovery without package mutation or losing the original
claim; an actual FAMILY recovery also refuses to reclassify the unknown
outcome, while read-only FAMILY inspection reports the unchanged active
operation. Both require an unchanged package-owned helper and immutable repeats.
This focused workload does not
replace the Python `test-native-recovery` build/CI gate or its lifecycle,
trigger and repository coverage.

### Fresh package-owned helper bootstrap (#215)

`zig build test-native-recovery-zig-bootstrap
-Dnative-reference-dpkg=/absolute/path/to/pinned/dpkg -j2` exercises
`exercise_fresh_helper_bootstrap` on **real disposable private roots**.
`-Dnative-zig-bootstrap-case=ambient-source` (or a case name below) selects
one case. The explicit reference must pass the pinned dpkg 1.22.22 hash and
version checks; the host dpkg is not a fallback. A generated essential `dpkg`
archive supplies a package-owned `usr/bin/dpkg-trigger` absent from each new
root. Real lifecycle children crash with exit 86 and no report at the chosen
boundary; recovery runs in fresh bounded children **after the archive is
deleted**, using the retained intent and its digest-checked persisted request.
Every child has a 120-second external timeout, kill grace and 125-second
awake ceiling; failed roots and bounded logs are retained for diagnosis.
Successful cases check helper source/probe progress, package-owned target
bytes, absent non-fixture dpkg binaries, original successful provenance,
immutable replay, cleanup and attempt-bound completion, then compare actual
filesystem, dpkg database and trace snapshots with the pinned reference
before and after acknowledgment. Refusals check the exact
`recovery_required` detail twice, stable original intent/request bytes,
absence of completion and unchanged package-state snapshots. The ambient
source test plants bytes of the **compiled native trigger-helper**, not the
host's `/usr/bin/dpkg-trigger`; both ambient tests require
`MutationEvidenceRequired`. The operation checkpoint legitimately advances
its generation/step on refusal and is not asserted byte-identical.

| Python fresh-helper case / Zig `-Dnative-zig-bootstrap-case` | Executed outcome and evidence |
| --- | --- |
| `after_execution_intent` | Fresh-source publication, completed recovery, pinned dpkg parity, cleanup |
| `during_filesystem_publication` | Interrupted filesystem publication, same completion/parity |
| `during_database_publication` | Interrupted database publication, same completion/parity |
| `after_helper_source_prepared` | Private source prepared, same completion/parity |
| `during_helper_source_publication` | Interrupted source publication, same completion/parity |
| `after_helper_source_publication` | Published source, same completion/parity |
| `after_helper_probe_prepared` | Prepared probe, same completion/parity |
| `after_helper_probe_outcome` | Retained probe outcome, same completion/parity |
| `after_helper_probe_completed` | Completed probe, same completion/parity |
| `after_provenance` | Published provenance, same completion/parity |
| `after_helper_probe_in_flight` | Unknown probe outcome; repeated `native_helper_outcome_unknown` refusal |
| `after_helper_probe_return_before_outcome` | Probe returned without recorded outcome; same refusal |
| `ambient-target` | Preexisting target blocks publication; repeated `MutationEvidenceRequired` refusal |
| `ambient-source` | Preexisting genuine helper source blocks publication; same refusal |
| `cleanup-after_helper_cleanup_prepared` | Recovery then acknowledgment interrupted before cleanup; retry removes source, pinned parity |
| `cleanup-during_helper_cleanup` | Interrupted cleanup publication; acknowledgment retry and pinned parity |
| `cleanup-after_helper_cleanup_completed` | Completed cleanup interrupted before acknowledgment; retry and pinned parity |
| `script-after_script_prepared` | Real postinst resumes to completed script and pinned parity |
| `script-after_script_outcome` | Retained postinst outcome resumes to completed script and pinned parity |
| `script-after_script_return_before_outcome` | Unrecorded script outcome; repeated `script_outcome_unknown` refusal, no replay |

This is executed coverage of all 20 cases in that **one Python method**,
not the entire recovery suite. `--fresh-helper-only`, both Python entry
points, and their CI gates remain unchanged. The new Zig target runs in the
required Zig core/workflows recovery shard on amd64 and arm64 in Debug and ReleaseSafe;
the security audit rejects removal of either CI command and detects a
bootstrap-source digest-inventory mutation. It does not exercise #231's
known-failure/trigger seams, unrelated helper-bound scripts, or the remaining
Python recovery methods. There is no production-authority blocker for these
20 bootstrap cases.

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

### Zig-owned repository transport slice (#215, partial migration)

`zig build test-native-recovery-zig-repository
-Dnative-repository-projection-only=true -j2` runs the repository-only
acceptance in a private PID/mount namespace (the runner and generated fixture
live under this worktree's `.tmp`). The execution-only selector runs typed
execution plus CLI, and the CLI-only selector runs CLI alone, matching the
existing Python selector hierarchy. Without a selector the Zig repository
target runs all three. The existing `test-native-recovery` target continues
to run **both Python recovery entry points** and now also the Zig repository
process acceptance when its selector includes repository cases; no Python
gate has been removed. Unprivileged Zig transport negatives also run under
the repository target and the standard `zig build test` target. A pinned
`-Dnative-reference-dpkg=...` is forwarded without changing its existing
meaning. For a local Python installation lacking the signed fixture
generator's documented `cryptography` requirement, supply
`-Dnative-repository-fixture-python=/absolute/path/to/python`; this option
selects **fixture generation only**, not the acceptance runner. For a
focused CLI run, combine `-Dnative-repository-cli-only=true` with
`-Dnative-zig-repository-case=known_failure` (or another case in the table
below); the default still runs all cases.

Executed Zig-owned private-root acceptance now covers the repository
projection; all **11** normal/resumed typed execution cases; both additional
held-unchanged bootstrap modes; and all **11** three-pass public-backend
dispatch cases (25 projected backend cases total). The Zig consumer checks
real completion markers, cleared caller/intent, no leaked system-root
projection or package CAS input, exact retained-versus-reported receipts,
partial versus installed dpkg status, unchanged database bytes, and canonical
digest-checked dispatch results. The **public `debz repo add` binary** also
runs all twelve Python CLI case variants in fresh disposable roots, using
a generated signed descriptor,
actual isolated child processes, and a loopback HTTP server for `network`.
Each three-pass case deletes the incoming descriptor after its first call,
then verifies recovery and an immutable replay; the one-pass refusals use
the same private-root entry. The consumer decodes and canonically checks
each actual API result, reads operation checkpoints and retained native
provenance, verifies evidence hashes and unchanged no-receipt evidence,
checks dpkg status/trace, original trigger helper bytes and inode, and
projection cleanup. The network case checks signed-repository request
accounting and redaction in the request log and in retained root files.
Descriptor deletion is an original-input eviction test; the native
content-addressed cache legitimately retains acquired package objects.
The child's explicit 60,000 ms deadline is passed unchanged, and its own
watchdog is 65 seconds, within the unchanged outer 120-second timeout.
Invalid step `-1`/`3` and unbounded 115,000 ms deadline produce
`InvalidRepositoryInvocation`/`UnboundedRepositoryWatchdog` **before the
CLI child**, with no new `cli-N.json` output. All six incompatible
projection-mode pairs, host-root rejection for all three transports,
incorrect marker, PID and UID are checked before entering/mounting; focused
transport tests also assert a host-root refusal leaves no process log.

The transport methods now exercised by Zig (Python remains mandatory pending
full parity) are:

| Python `test_` method | Zig execution or exact refusal |
| --- | --- |
| `projection_requires_private_disposable_root_before_mounting` | Entry checks PID 1, UID 0, exact worktree-root shape and marker before either private mount; `DisposableRootAndPrivatePidNamespaceRequired` |
| `projection_fixture_modes_cannot_be_combined` | All six workflow/repository-projection/repository-execution/repository-CLI pairs; `ProjectionFixturesMutuallyExclusive` before a child |
| `repository_projection_uses_its_own_guarded_entry` | Distinct Zig `--inside projection` entry and real production `DEBZ_NATIVE_REPOSITORY_PROJECTION_FIXTURE=1` callback |
| `repository_projection_refuses_host_root_before_entering` | Host `/` refused before launch; no process log |
| `repository_execution_uses_its_own_guarded_entry` | Distinct Zig `--inside execution` entry and real production `DEBZ_NATIVE_REPOSITORY_EXECUTION_FIXTURE=1` callbacks |
| `repository_execution_refuses_host_root_before_entering` | Host `/` refused before launch; no process log |
| `repository_cli_keeps_the_existing_projection_timeout` | Separate Zig `--inside cli` entry, outer 120-second timeout with bounded kill/125-second awake ceiling |
| `repository_cli_runs_one_invocation_with_watchdog_after_its_deadline` | Actual single public CLI process at step 1 with 60,000 ms deadline and 65-second watchdog; only `cli-1.json` emitted |
| `repository_cli_rejects_invalid_invocation_or_unbounded_watchdog_before_spawn` | Steps `-1` and `3` / deadline 115,000 ms yield exact Zig diagnostic, no `cli-0/1/2.json` |

| Python `repository_cli_cases` variant | Executed Zig result / evidence consumer |
| --- | --- |
| `success` | Signed native install, three calls, success/no-change replay, complete checkpoint and verified native receipt |
| `no_refresh` | Same, refreshed phase skipped and checkpoint `no_refresh` true |
| `unchanged` | Preinstalled held package, unchanged bytes, no script or completion, no-receipt digest, three calls |
| `unchanged_no_refresh` | Held unchanged plus skipped refresh, no-receipt evidence and three calls |
| `known_failure` | Real failing postinst, three transaction failures, half-configured dpkg status, failed checkpoint and retained failure provenance |
| `refresh_failure` | Script-marker-gated Release removal, `refresh_failed`/post-install result, restored Release, recovery and replay |
| `signal` | SIGTERM after actual script marker, retained caller, three recovery statuses and `script_outcome_unknown` without replaying scripts |
| `lock_wait` | Held real flock, 75 ms deadline, `resource_limit_exceeded`, elapsed <3 s, unchanged status |
| `lock_signal` | SIGTERM only after `/proc/<pid>/fd` proves lock wait, `recovery_required`, elapsed <3 s, no caller |
| `unsafe_runtime` | World-writable runtime refused with `transaction_backend_unavailable` and `UnsafeRuntimeDirectory`, unchanged status |
| `deadline` | Real blocked postinst, 3000 ms deadline, `resource_limit_exceeded`, elapsed <8 s |
| `network` | Real signed HTTP acquisition, query-secret not retained, one descriptor request, both repository paths visited and three-call replay |

This is **not** a claim of full #215 or upstream parity: the shared
`exercise_projection` workflow, family execution and native crash/helper
methods are outside this repository-only slice. Repository `repo add`
only installs the descriptor: its failed postinst has no rollback symlink
clock. A separate failed-upgrade acceptance below exercises that clock
without attributing it to the repository CLI. Python recovery gates and
amd64/arm64 CI parity remain required. The repository `known_failure` CLI
row does **not** exercise or claim #231's failed-postinst crash seams or
unconfigured trigger listeners.

### Real failed-upgrade rollback clock (#215)

`zig build test-native-recovery-zig-rollback-clock
-Dnative-reference-dpkg=/absolute/path/to/pinned/dpkg -j2` runs a separate
real-process, disposable-root native upgrade and a hash/version-verified
dpkg 1.22.22 reference. Without that explicit pinned path, the target
refuses to run; the host dpkg is never silently substituted. Both roots
start with the same installed version 1 and a failure marker for the old
`postrm upgrade` and incoming `postrm failed-upgrade`. A version 2 upgrade
fails through the actual callbacks and restores version 1's `current`
symlink. The test retains bounded **before and after** native/reference
snapshots and the two process logs on failure. It requires both after-failure
symlink mtimes to be newly created inside the measured operation interval,
normalizes the actual snapshots with `normalizeRollbackTimes(require_clock =
true)`, and compares the complete normalized dpkg/filesystem/trace images.
Mutating a copy of the real native after-snapshot to either original pre-upgrade
mtime or timestamps immediately before/after the measured interval must
yield `UnexpectedRollbackSymlinkTimestamp`. The shared Python gates remain.

| Python `test_` method | Executed Zig consumer / remaining boundary |
| --- | --- |
| `backup_failure_clock_rejects_original_or_arbitrary_timestamps` | Real failed private-root native upgrade versus pinned dpkg; complete normalized snapshot equality, recreated symlink clock and original/arbitrary negative mutations of the captured snapshot. This does **not** cover the Python diversion-specific rollback-crash/recovery variants or #231 seams. |

### Recovery rollback-crash and deadline transport (#215)

`zig build test-native-recovery-zig-final-gaps
-Dnative-reference-dpkg=/absolute/path/to/pinned/dpkg -j2` (also with
`-Doptimize=ReleaseSafe`) runs `test/native_recovery_final_gaps.zig` as a
separate privileged, bounded (120-second child plus kill grace) Zig acceptance
consumer. The reference is digest/version-pinned dpkg 1.22.22, not an
unverified host fallback. Its private roots are marked and guarded; pre-spawn
refusals use a nonexistent driver, demand the precise Zig diagnostic and no
request directory, and compare the untouched private-root snapshot. A real
non-core helper-bound caller, rather than a fixture-only report, exercises
both positive recovery paths. CI requires the unfiltered target in Debug
and ReleaseSafe on amd64 and arm64. The two Python recovery gates remain.

| Python `test_` method | Executed Zig transport / scope |
| --- | --- |
| `recovery_still_refuses_host_root_before_spawn` | Host `/` recovery fails `NotDisposableRoot` before creating a request or launching the sentinel driver. Earlier `HostRootNotSupported` unit coverage alone was not an equivalent transport refusal. |
| `rollback_crash_seam_cannot_replace_recovery_inputs_or_core_completion` | All four invalid operation/caller/core/seam combinations fail `RollbackCrashRequiresRecoveringCaller` before request/spawn. Additionally, a real failed version-2 upgrade crashes after its script-failure outcome (exit **86**, no normal report); with its archive deleted, a helper-bound recovery crashes at `during_known_unpack_rollback` (exit **86**, no report or core completion). The original intent and caller attempt/request/policy bindings survive; the recovery request has empty archives/packages and `core_product=false`. A fresh helper-bound recovery returns `script_failed`, matches the pinned dpkg failed-upgrade root including script trace and a bounded rollback symlink clock, and is separately acknowledged without replacing its failed receipt. This simple package path does **not** claim diversion-specific rollback or #231 interrupted script-failure parity. |
| `execution_deadline_requires_typed_helper_bound_caller` | Unowned, no-helper, negative, and core-product deadline requests each fail `DeadlineRequiresHelperBoundCaller` before request/spawn. |
| `execution_deadline_preserves_zero_in_private_fixture` | After a real exit-86 execution-intent crash and archive eviction, the helper-bound recovery request contains integer `deadline_after_ms: 0` (not null or omitted), with no core-completion crash; its real `recovery_required` / `deadline_exceeded` report leaves the complete package-root snapshot and original intent/operation bytes unchanged. A fresh nonzero-deadline recovery matches pinned dpkg, binds its succeeded receipt to the attempt, then acknowledges without replacing that receipt. |

### Recovery unit oracle migration inventory (#215)

`zig build test-native-recovery-zig-unit` runs the unprivileged Zig-owned
receipt, progress, script-output, handler-schema and reusable comparative
negatives without a chroot or a crash.
It also runs as part of `test-native-recovery`; the Python oracle remains
mandatory. This inventory distinguishes a production Zig test from an assertion
about the Python fixture transport; the latter is **not** counted as ported.
The focused `test-native-recovery-unit` step also runs the existing root
completion-store idempotence and symlink refusals
(`root_operation_completion.test.store publishes atomically and idempotently`,
`...store refuses a symbolic link at the document path`): identical repeated
completion does not rewrite the receipt; changed same-attempt completion fails
with `CompletionChanged` and cannot replace it.
Names in the following tables are methods of `tools/test_native_recovery.py`;
`test_` is omitted from the left column.

| Python oracle (`test_` + name) | Zig-owned coverage / exact refusal |
| --- | --- |
| `unpack_backup_evidence_distinguishes_legacy_and_canonical_preimages` | `native_unpack.test.unpack backup inputs distinguish legacy and bound backup phases`, `...retain symlink clocks and reject malformed preimages`: `InvalidUnpackBackup`, `InvalidUnpackDiversionCache` |
| `settlement_recipe_binds_binary_bytes_final_status_and_phase_protocol` | `native_unpack.test.post-script recipe retains binary control and original evidence`, `...refuses malformed or unbound late intents`: `InvalidUnpackSettlement`, `InvalidUnpackDiversionCache` |
| `cached_diversion_evidence_keeps_loaded_and_observed_bytes_distinct` | `recovery-unit.diversion cache rejects mismatched loaded bytes and observed identities` exercises the production cache encoder/decoder: changed live digest on the same inode is allowed; changed loaded digest, observed inode, missing observation or changed cached bytes return `InvalidDiversionCache` |
| `cached_diversion_evidence_distinguishes_absent_and_empty` | Same production cache test round-trips absent and empty separately and rejects an absent observation with empty cached bytes |
| `program_package_paths_do_not_broaden_root_authority` | `recovery-unit.literal package paths never grant root authority` uses the package-path and authority-path validators on the same literal backslash path and all seven invalid Python inputs |
| `recovery_still_refuses_host_root_before_spawn` | `native_transaction_result.test.owned verification preserves exact owners and never provisions locks`: `HostRootNotSupported` before lock acquisition; real Zig transport pre-spawn counterpart is above |
| `recovery_has_no_caller_work_or_fault` / `recovery_request_does_not_reauthorize_an_archive` | `native family recovery rejects replacement inputs and execution policy before filesystem work`: `invalid_request` without package mutation |
| `empty_exact_lock_v2_schema_preserves_required_bindings` | `recovery-unit.empty v2 closure requires every typed binding and refuses legacy schema` checks the exact canonical digest, all five omitted typed fields, and the v1 reader's `EmptyClosure` refusal after removing v2-only fields |
| `provenance_is_bound_to_original_execution` | `native_transaction_result.test.owned verification preserves exact owners and never provisions locks`: `OwnershipMismatch`, `ExactIdentityMismatch` |
| `caller_binding_preserves_outer_operation_and_hash_domains` | `native_execution_request.test.canonical ownership mapping survives allocation failures`: caller request/policy hashes distinct from program request/solver hashes |
| `report_cannot_point_outside_native_namespace` | `recovery-unit.report path is bound before reading provenance` rejects the three forged **report** paths, an arbitrary in-namespace path and a wrong version with `UnboundRecoveryProof` before I/O. Separately, receipt *evidence-file* paths return `InvalidEvidence`. |
| `report_cannot_follow_a_provenance_symlink` | The report-path oracle refuses the arbitrary in-namespace `proof.json` symlink path before I/O; production `native_provenance.read` ignores that path and refuses symlinks at either fixed versioned document path with `NotRegularFile`. Retained-evidence symlinks are also refused. |
| `native_document_reads_are_bounded_and_objects_only` | `recovery-unit.unknown receipt fields outcome schema and unsafe paths fail closed`: `UnexpectedToken`; `native_provenance.test.canonical byte decoding preserves outcomes and allocation failures`: `DocumentTooLarge` |
| `canonical_self_digest_cannot_hide_changed_receipt` | `native_provenance.test.digest binds terminal evidence`, `...canonical byte decoding preserves outcomes and allocation failures`: `DigestMismatch` |
| `digest_summary_cannot_replace_missing_detailed_evidence` | `recovery-unit.retained evidence rejects missing duplicate cross-attempt and altered bytes`: `InvalidEvidence` |
| `receipt_rejects_changed_bytes_and_cross_attempt_paths` | Same test: `EvidenceChanged`, `InvalidEvidence` for duplicate or foreign attempt |
| `progress_requires_exact_retained_outcomes` | `recovery-unit.script progress refuses duplicate or unknown outcomes without changing retained history`: `InvalidProgress`; `native_transaction_result.test.retained script outcomes bind every exact progress invocation`: `EvidenceMissing`, `EvidenceMismatch`, `InvalidRecoveryProgress` |
| `bootstrap_progress_uses_its_v2_record_domain` | `recovery-unit.bootstrap progress hashes records in its v2 domain`: real digest differs from v1; `native_recovery.test.helper publication probe and unknown outcome transitions are exact` rejects invalid helper transitions |
| `retained_output_supports_separate_and_combined_capture` | `recovery-unit.script output binds split and combined capture to exact bytes and accounting`: `InvalidScriptOutcome` for digest, accounting or mixed-mode drift |
| `handler_schemas_require_explicit_absence_or_a_real_digest` | `recovery-unit.handler schemas require explicit absent postinst or lowercase digest`: both real handler `$defs` retain required `postinst_sha256`, nullable script hash and mandatory lowercase `declarations_sha256`; malformed or weakened schemas return `InvalidHandlerSchema`, omitted, empty, invalid or null digests return `InvalidTriggerHandler` |

The following is the **complete 56-method inventory**, in Python source order.
`U` means a focused Zig unit/production API assertion (some production tests
run in `zig build test` or `test-native-recovery-unit`, not in the standalone
`test-native-recovery-zig-unit` target). `A` means an existing executed Zig
transport/acceptance target; it must run in both modes on both architectures
before any parity claim. The FAMILY rows describe the executed target, not a claim that its remaining
workflow gaps have closed. Neither a fixture
constant nor a mocked Python subprocess counts as an executed transport.

| # | Python method (`test_` omitted) | Zig status | Concrete assertion/consumer |
| ---: | --- | --- | --- |
| 1 | `unpack_backup_evidence_distinguishes_legacy_and_canonical_preimages` | U | `native_unpack.test.unpack backup inputs distinguish legacy and bound backup phases`; rejects malformed/duplicated backups |
| 2 | `backup_failure_clock_rejects_original_or_arbitrary_timestamps` | U+A | `recovery-unit.rollback comparison accepts only the failure-clock interval`; `native_recovery_rollback_clock.normalize` checks real failed-upgrade snapshots and rejects original/out-of-interval times |
| 3 | `settlement_recipe_binds_binary_bytes_final_status_and_phase_protocol` | U | `native_unpack.test.post-script recipe retains binary control and original evidence` and `...refuses malformed or unbound late intents` |
| 4 | `cached_diversion_evidence_keeps_loaded_and_observed_bytes_distinct` | U | `recovery-unit.diversion cache rejects mismatched loaded bytes and observed identities` checks all four semantic mutations through production encode/decode; changed observed digest with stable identity is valid |
| 5 | `cached_diversion_evidence_distinguishes_absent_and_empty` | U | Same unit test round-trips both cases and refuses empty bytes without an observation |
| 6 | `consumer_parity_requires_every_suite_case_and_actual_consumer` | A | `native_recovery_parity` executes two signed suites × 14 cases through core, FAMILY and pinned dpkg; `validateConsumerParity` rejects missing, duplicate, false or unbound rows |
| 7 | `consumer_parity_keeps_policy_noop_failure_and_suite_cases` | A | Same 28 executed cases cover recommends, held no-op, failure, conffiles, trigger, architectures and literal paths |
| 8 | `program_package_paths_do_not_broaden_root_authority` | U | `recovery-unit.literal package paths never grant root authority` proves one literal package path is invalid as an authority path and rejects all seven malformed examples |
| 9 | `handler_schemas_require_explicit_absence_or_a_real_digest` | U | `recovery-unit.handler schemas require explicit absent postinst or lowercase digest`; reads both real definitions and refuses missing/empty/bad digests |
| 10 | `recovery_still_refuses_host_root_before_spawn` | U+A | `native_transaction_result.test.owned verification preserves exact owners and never provisions locks`; `native_recovery_final_gaps.preSpawnRefusals` checks no request or child |
| 11 | `family_verification_preserves_expected_request_without_execution_flags` | A (FAMILY) | `native_recovery_family.transport` preserves verification request, read-only outcome, absent execution flags/evidence, bounded child |
| 12 | `native_completion_capture_is_separate_from_command_report` | A (FAMILY) | FAMILY `workflow` writes distinct report/evidence paths; `completed` checks actual lock, receipt and completion bindings |
| 13 | `family_execution_preserves_request_and_separate_evidence` | A (FAMILY) | FAMILY `transport` and `archiveExecution` run real inspect/recover/create/customize/update requests with separate evidence and pinned-dpkg comparison |
| 14 | `family_execution_refuses_host_root_before_spawn` | A (FAMILY) | `refusals` rejects `/` before creating a request directory or invoking a nonexistent driver |
| 15 | `family_update_planning_preserves_explicit_method_and_request` | A (FAMILY) | `planning` runs actual selected and upgrade-all `resolve_lock` methods, then archive-backed execution |
| 16 | `family_update_planning_requires_family_request_before_spawn` | A (FAMILY) | `refusals` returns `FamilyRequestRequired` before directory creation/spawn |
| 17 | `diagnostic_inspection_retains_partial_package_states_without_success_proof` | U+A (FAMILY) | `validateDiagnosticInspection` consumes actual FAMILY partial/active-root inspection; no install or completion authority |
| 18 | `diagnostic_inspection_refuses_completion_or_authoritative_relabelling` | U+A (FAMILY) | `native_recovery_family.transport` mutates driver-produced report/evidence and requires `InvalidDiagnosticInspection` |
| 19 | `family_verification_still_refuses_host_root_before_spawn` | A (FAMILY) | `refusals` rejects `/` before request/spawn, also for verification |
| 20 | `projection_requires_private_disposable_root_before_mounting` | A (repository) | `native_recovery_repository.privateRoot` checks marker, disposable root, PID 1 and UID 0 before mount/chroot |
| 21 | `recovery_has_no_caller_work_or_fault` | U | `package_family_backend.test.native family recovery rejects replacement inputs and execution policy before filesystem work` |
| 22 | `rollback_crash_seam_cannot_replace_recovery_inputs_or_core_completion` | A (final-gaps) | `preSpawnRefusals` rejects all four invalid selectors before child; `rollbackSeam` retains original intent/caller and recovers from real exit 86 |
| 23 | `projection_fixture_modes_cannot_be_combined` | A (repository) | `selectMode` rejects all six pairings before subprocess |
| 24 | `repository_projection_uses_its_own_guarded_entry` | A (repository) | `.projection` executes guarded `--inside projection`, not workflow or execution |
| 25 | `repository_cli_keeps_the_existing_projection_timeout` | A (repository) | `.cli` uses bounded 120-second child with 125-second process limit |
| 26 | `repository_cli_runs_one_invocation_with_watchdog_after_its_deadline` | A (repository) | `cliCase` launches real step 1 at 60-second deadline, computes 65-second watchdog, and requires only `cli-1.json` |
| 27 | `repository_cli_rejects_invalid_invocation_or_unbounded_watchdog_before_spawn` | A (repository) | `cliCase` refuses steps −1/3 and 115-second deadline with no result/child |
| 28 | `repository_projection_refuses_host_root_before_entering` | A (repository) | `privateRoot` and `projected` refuse `/` before entering namespace |
| 29 | `repository_execution_uses_its_own_guarded_entry` | A (repository) | `.execution` launches distinct guarded mode, with real projection/execution cases |
| 30 | `repository_execution_refuses_host_root_before_entering` | A (repository) | `projected` refuses `/` before executing `.execution` mode |
| 31 | `execution_deadline_requires_typed_helper_bound_caller` | A (final-gaps) | `preSpawnRefusals` rejects unowned, helperless, negative and core-product deadlines before child |
| 32 | `execution_deadline_preserves_zero_in_private_fixture` | A (final-gaps) | `deadlineZero` serializes zero, observes actual expiry and unchanged authority, then completes fresh recovery against pinned dpkg |
| 33 | `ignored_crash_selector_cannot_pass_as_a_crash` | A (crash/helper) | `crashTransport` detects real exit 0 for an ignored selector as `CrashSelectorIgnored` |
| 34 | `crash_uses_actual_process_exit_without_normal_report` | A (crash/helper) | `crashTransport`/`caseRun` require actual exit 86 and absence of completion report |
| 35 | `crash_with_a_success_report_is_rejected` | A (crash/helper) | `crashTransport` rejects a planted stale success report after exit 86 |
| 36 | `recovery_request_does_not_reauthorize_an_archive` | U+A | Family production recovery refuses replacement inputs; `final_gaps.rollbackSeam` verifies no archives/packages in actual fresh request |
| 37 | `native_acknowledgment_requires_recovering_caller` | A (crash/helper) | `negativeTransport` refuses unowned/install acknowledgment; `caseRun` verifies owned acknowledgment/immutable proof |
| 38 | `isolated_helper_requires_caller_ownership` | A (crash/helper) | `negativeTransport` refuses unowned helper; owned helper/recovery runs in `caseRun` |
| 39 | `empty_exact_lock_v2_schema_preserves_required_bindings` | U | `recovery-unit.empty v2 closure requires every typed binding and refuses legacy schema` confirms the canonical digest, five missing-field refusals, version separation and v1's refusal of an empty unauthenticated closure |
| 40 | `isolated_invocation_evidence_cannot_be_omitted` | A (crash/helper) | `caseRun` decodes actual helper request, validates receipt/helper bytes and recomputed invocations, refuses removed/altered source |
| 41 | `helper_request_schema_supports_jsonschema_without_referencing` | U (Zig runtime); Python-tool compatibility | `recovery-unit.helper request schemas resolve v1 program policy and reject missing bindings` checks the real v1 `$id`, both external v2/v3 `$ref`s and all three typed persisted decoders; each refuses missing or uppercase embedded `script_policy_sha256`. The Python method also re-imports `tools/test-native-recovery.py` with `referencing` blocked, then checks local `jsonschema.RefResolver` and registry validation of v1/v2/v3 without a network connection. That import-path fallback belongs only to the Python acceptance tool, not to a Zig runtime contract |
| 42 | `provenance_is_bound_to_original_execution` | U | `native_transaction_result.test.owned verification preserves exact owners and never provisions locks` refuses changed owners/identities |
| 43 | `caller_binding_preserves_outer_operation_and_hash_domains` | U | `native_execution_request.test.canonical ownership mapping survives allocation failures` preserves outer caller and distinct request/policy domains |
| 44 | `report_cannot_point_outside_native_namespace` | U+A | `recovery-unit.report path is bound before reading provenance` refuses absolute, traversal, near-prefix, arbitrary in-namespace and wrong-version **report** paths with `UnboundRecoveryProof`; real Zig consumers require the fixed versioned path before reading. Receipt *evidence-file* path refusal is distinct. |
| 45 | `report_cannot_follow_a_provenance_symlink` | U+A | The unit creates an arbitrary in-namespace symlink and checks that the report path is rejected before I/O; fixed-path production `native_provenance.read` returns `NotRegularFile` for symlinks at both v1/v2 document paths. Real Zig report consumers use the same fixed-path binder. |
| 46 | `claimed_recovery_cannot_hide_duplicate_script_invocation` | A (crash/helper) | `helper-outcome` appends duplicate to a real recovered trace; `foundation.compare` returns `NativeDpkgMismatch` |
| 47 | `caller_archive_is_removed_before_recovery` | A (crash/helper) | `caseRun` removes and confirms input archive absent before fresh recovery |
| 48 | `unknown_script_cannot_be_hidden_by_rolling_back_payload` | A (crash/helper) | `helper-unknown-script` checks unchanged root and rejects deliberate rollback with `BlockedRecoveryMutatedPackageState` |
| 49 | `native_document_reads_are_bounded_and_objects_only` | U | `native_provenance.test.canonical byte decoding preserves outcomes and allocation failures` refuses oversized receipt; unit decoder rejects non-object |
| 50 | `canonical_self_digest_cannot_hide_changed_receipt` | U | `native_provenance.test.digest binds terminal evidence` and `native_authorization.test.canonical document binds program artifacts and final closure` both reject tampering |
| 51 | `digest_summary_cannot_replace_missing_detailed_evidence` | U | `recovery-unit.retained evidence rejects missing duplicate cross-attempt and altered bytes` refuses missing entries |
| 52 | `receipt_rejects_changed_bytes_and_cross_attempt_paths` | U | Same test refuses changed bytes and foreign-attempt or duplicate paths |
| 53 | `progress_requires_exact_retained_outcomes` | U | `recovery-unit.script progress refuses duplicate or unknown outcomes without changing retained history`; transaction-result proof binds retained outcomes |
| 54 | `bootstrap_progress_uses_its_v2_record_domain` | U | `recovery-unit.bootstrap progress hashes records in its v2 domain` recomputes the real record digest, distinguishes v1; production helper publication tests invalid transitions |
| 55 | `receipt_arguments_must_match_the_actual_script_trace` | U+A | `verifyProof` checks actual trace/helper digest; unit oracle refuses forged arguments |
| 56 | `retained_output_supports_separate_and_combined_capture` | U | `recovery-unit.script output binds split and combined capture to exact bytes and accounting` |

There are 56 names: all have Zig assertions for the portable behavior, while
#41 additionally tests a **Python-tool compatibility branch**. The only
`referencing`/`Registry`/`RefResolver` implementation in `tools/*.py` is in
`tools/test-native-recovery.py`, whose sole Python importer is
`tools/test_native_recovery.py`. The signed Zig FAMILY, parity and repository
targets instead invoke `tools/generate-integration-repository.py`, which
imports `generate-openpgp-fixtures.py` and `cryptography`, not the recovery
acceptance module or `jsonschema`. Remaining required Python schema checks
(`dpkg-oracle-evidence.py`, `test_vendor_state_capture.py`,
`test_dpkg_config_reference.py`, `test_dpkg_alternatives_reference.py`,
`test_dpkg_oracle_evidence.py`) call `jsonschema.Draft202012Validator`
directly on self-contained schemas; none imports the recovery fallback or
resolves an external `$ref`. Once both Python
recovery entry points are retired, no remaining Python consumer needs this
fallback. Replacing a removed Python interpreter import branch with Zig would
be a fixture-only substitute, not executed behavior; the actual cross-file
v1/v2/v3 request refusal remains in the Zig unit target. The table records
*coverage*, not approval of gate retirement without both CI matrices.
Former methods #44 and #45 tested a different Python-tool reader:
`tools/test-native-recovery.py::provenance` passed a report-supplied path to
`namespace_path`, which rejected escapes and arbitrary symlinks before
opening it. Production Zig does **not** consume a report path to find a
receipt: `native_provenance.read` tries only the fixed v2 then v1 paths and
`native_provenance.documentPath` derives the output path from the validated
document version. No production arbitrary-path reader should be added.
Some Zig acceptance consumers had used the untrusted report path to read
test evidence, so they now call the shared report-path oracle and read only
its fixed-path return value. The new unit case injects every Python escape
path and an actual arbitrary in-namespace symlink, while the existing unit
case exercises symlinks at both production document paths. This preserves
the refusal boundary without mistaking a receipt evidence-file path test
for a report-path test or claiming identical Python and Zig reader APIs.
The standalone Zig unit target remains required in both modes in the
Debug row of the `native-recovery` CI job. Both `tools/test_native_recovery.py` and
`tools/test-native-recovery.py` remain required until the integrated
Debug/ReleaseSafe, amd64/arm64 matrix proves equivalence.

| Python oracle (`test_` + name) | Executed Zig CRASH/HELPER counterpart |
| --- | --- |
| `ignored_crash_selector_cannot_pass_as_a_crash` | `crashTransport`: real scriptless install ignores `after_script_outcome`; Zig transport returns `CrashSelectorIgnored` for exit 0, rather than accepting its report |
| `crash_uses_actual_process_exit_without_normal_report` | `crashTransport` and `caseRun`: real exit 86 at intent, script outcome, provenance and unknown script return; no completion report |
| `crash_with_a_success_report_is_rejected` | `crashTransport`: stale planted success report plus actual exit 86 returns `CrashProducedCompletionReport`; no claim of a child-produced success report |
| `native_acknowledgment_requires_recovering_caller` | `negativeTransport`: invalid install/unowned recovery acknowledgment rejected before request/spawn; `caseRun` runs owned acknowledgment, verifies attempt, cleanup and immutable proof |
| `isolated_helper_requires_caller_ownership` | `negativeTransport`: unowned isolated helper rejected before request/spawn; `caseRun` exercises owned helper and refused recovery downgrade |
| `isolated_invocation_evidence_cannot_be_omitted` | `caseRun` decodes original typed helper request, verifies retained receipt/request/helper bytes, recomputes every executed script's helper-mounted invocation and refuses missing original request or altered helper source without package mutation |
| `claimed_recovery_cannot_hide_duplicate_script_invocation` | `helper-outcome`: real recovered trace/dpkg parity, then duplicated trace rejected by actual `foundation.compare` (`NativeDpkgMismatch`) |
| `caller_archive_is_removed_before_recovery` | All `caseRun` executions delete and verify archive absent before launching fresh recovery |
| `unknown_script_cannot_be_hidden_by_rolling_back_payload` | `helper-unknown-script`: real preinst changes existing payload, exits 86 before outcome, recovery/purge preserve exact root; deliberate payload rollback rejected by snapshot consumer (`BlockedRecoveryMutatedPackageState`) |
| `receipt_arguments_must_match_the_actual_script_trace` | `verifyProof` validates real retained script outcomes against the actual trace and recomputed helper invocation; deliberate argument forgery rejected by `ScriptTraceMismatch` and `ScriptHelperBindingMismatch` in acceptance and unit oracle |

### Signed consumer-parity transport slice (#215)

`zig build test-native-recovery-zig-parity -j2` and the same command with
`-Doptimize=ReleaseSafe` run `test/native_recovery_parity.zig` as the real
privileged consumer, with the optional pinned reference
`-Dnative-reference-dpkg=/absolute/path/to/dpkg`. The fixture generator
requires Python `cryptography`; when it is not in `/usr/bin/python3`, use
`-Dnative-zig-recovery-parity-fixture-python=/absolute/path/to/python`.
`-Dnative-zig-recovery-parity-case=debian-stable/pre-depends` selects a
**single debugging case**, not the 28-row acceptance gate. The unfiltered
target is required in CI on amd64 and arm64 in Debug and ReleaseSafe.
Local execution against digest-pinned dpkg 1.22.22 has passed on **arm64**
in both modes with #231 integrated; amd64 still requires CI validation.
Both Python recovery gates and their signed consumer
transport remain required.

| Python method (`test_` omitted) | Executed Zig acceptance |
| --- | --- |
| `consumer_parity_requires_every_suite_case_and_actual_consumer` | Uses the existing Zig oracle's **two signed suites × 14 cases**, not hand-constructed success rows. For each case, runs the public `debz` core CLI, the actual FAMILY workflow driver and pinned/private-root dpkg phases against three guarded roots. Validates the two real v3 exact-lock documents and byte identity; compares dpkg status, installed files, metadata and script/trigger traces; checks core/FAMILY exit, changed flag, each selected package's exact version/architecture/action and failure diagnostic, helper bytes/inode, settled receipt and completion bindings, and read-only core and FAMILY proofs on successful mutations. Each row's `matched` value derives from observed lock, root and helper comparisons, then `validateConsumerParity` rejects omitted, duplicate or mismatched rows. |
| `consumer_parity_keeps_policy_noop_failure_and_suite_cases` | In **each** suite: pre-depends (two dpkg phases), versioned virtual provider, dependency cycle, recommends off/on, multiarch package, literal paths, retained metadata, suite trigger version, upgrade-all, held no-op, conffile keep/replace with a real older package and user edit, and known failed postinst (CLI exit **7**, FAMILY `transaction`, dpkg exit **1**, failed receipt and `transaction_failed`/`backend_failed` diagnostics). Checks no provenance/completion for the held no-op. These are 28 executed case observations, not fixture-only matrix assertions. |

The known-script-failure case here is an ordinary failed postinst, **not**
#231's interrupted failed-script restart or awaited/no-await unpacked-listener
reference. Repository CLI and projection transport are also out of scope.

The FAMILY, repository, and final-gaps transports above remain independently
required acceptance targets. Row 41's Python-only `referencing` fallback stays
in the unchanged Python gate until retirement; its request-schema behavior
already has executed Zig coverage. No Python recovery gate is removed here.

### FAMILY request/result transport slice (#215)

`zig build test-native-recovery-zig-family -j2` and
`zig build test-native-recovery-zig-family -Doptimize=ReleaseSafe -j2`
run `test/native_recovery_family.zig` as root against the **real external
native workflow driver**. The suite uses `native_test_foundation.Fixture` in a
disposable, marked worktree-local root. It bounds each child to 120 seconds
with a two-second kill grace and a 125-second process deadline, retains
bounded logs on failure, and compares root snapshots and the host dpkg status
before/after. The optional `-Dnative-reference-dpkg=...` is forwarded to the
fixture and used for executed state comparisons. The existing
`tools/generate-integration-repository.py` is invoked **only to build**
worktree-local signed metadata and matching `.deb` archives; the test runner,
all assertions and all FAMILY invocations are Zig-owned. The fixture builder
needs Python `cryptography` as do the existing Python gates; environments where
the system Python lacks it can select a dependency-equipped interpreter with
`-Dnative-zig-recovery-family-fixture-python=/absolute/path/to/python`.
`-Dnative-zig-recovery-family-executed-only=true` selects just the
archive-backed and active-inspection scenarios for focused runs.
The existing Python oracle and privileged acceptance gates remain unchanged.
This is a separate target, not a replacement for their repository, crash or
helper selectors. The following table records the **original transport/unit
baseline**; its third column is historical, not the current acceptance-gap
inventory. The current case-by-case `exercise_workflows` inventory follows.

| Python method (`test_` omitted) | Zig FAMILY transport exercised at baseline | Gap at baseline |
| --- | --- | --- |
| `family_verification_preserves_expected_request_without_execution_flags` | The missing-lock case returns `verified:false` / `FileNotFound` without execution flags or evidence. Archive-backed create and customize pass read-only verification both without and with their returned completion; their exact summary bytes match. Create verifies equivalently as customize; its completion is rejected against the **separate actual customize attempt**. On completed create, individually changing **each of seven returned digest/identifier fields**, the outcome, settlement or operation fails with the corresponding exact completion error; changing package, operation, conffile or recommends fails with `NativeFamilyRequestMismatch`. Corrupting the retained receipt, completion, status or input lock and adding an unsettled root operation all refuse verification without further mutation; restored evidence verifies again. Selected and upgrade-all updates pass returned-completion verification. | Python additionally rejects `allow_downgrade` and `foreign_architectures` policy changes, cross-attempt completion from a separately **recovered** transaction and verifies the public CLI's broader result negatives. |
| `native_completion_capture_is_separate_from_command_report` | The ordinary signed-repository plan emits separate report and evidence documents with null completion/install. Mutating FAMILY create/customize, both updates and failed customize/update emit separate reports and **non-null** completion evidence. Successful completion's seven returned identifiers/digests match the actual lock, receipt and root completion; failed completion's digest and outcome match its actual retained failed receipt. | The complete Python failed-script returned-evidence digest matrix is still required. |
| `family_execution_preserves_request_and_separate_evidence` | Actual private-root `inspect` and `recover`, then archive-backed `create`, `customize`, selected `update` and upgrade-all `update` preserve request root, architecture, selector and input-lock path across the driver transport. Each mutation produces a distinct result/evidence pair and a bound completed receipt. The corresponding root state is compared with a pinned-dpkg install of the matching archives. | Only the selected fixture operations are compared, **not** the full signed consumer-parity matrix or failure/restart cases. |
| `family_execution_refuses_host_root_before_spawn` | Host `/` is rejected with `NotDisposableRoot` / `"disposable fixture root"` before even creating the request directory; a nonexistent driver proves spawn was not reached. Root mismatches are also refused. | None for this transport guard. |
| `family_update_planning_preserves_explicit_method_and_request` | Both selected `alpha:amd64=1` and upgrade-all `resolve_lock` requests run the *actual* update-planning method with the existing signed local batch repository; the unflagged upgrade-all request returns `invalid_request` without a lock. Separately, signed archive plans for host architecture feed executed selected and upgrade-all updates and pinned-dpkg comparisons. An install-mode lock, wrong operation/selector/recommends refuse update without mutation; the update lock has a different bound request digest. A repeated real plan/update changes nothing and retains the original receipt and dpkg parity. | Interrupted update recovery after eviction of the cache and input lock remains Python-only. |
| `family-native-install` failed customize and `family-update-failure` | Distinct signed `fail-script` installs, including an upgrade from a pinned-dpkg-seeded scriptless `0.1-1`, really fail in the driver and pinned dpkg. The failed provenance, completion outcome, transaction diagnostic and evidence digests are checked; failed and relabeled-as-success verification refuse, and clean FAMILY recovery leaves receipt, root and reference-dpkg comparison unchanged. | The original scenario's entire combined create/customize/inspect timeline is still Python-only. |
| `family-missing-helper` | A genuine signed `scenario-main` plan in a private root with seeded `essential-core` but no `/usr/bin/dpkg-trigger` refuses execution, reports a helper diagnostic, produces no completion/receipt or placeholder, and preserves status bytes. | Inspection of this exact missing-helper root remains Python-only (other Zig inspection scenarios are executed). |
| `family_update_planning_requires_family_request_before_spawn` | Missing FAMILY request returns `FamilyRequestRequired` / `"requires a family request"` before directory creation or spawn, using a nonexistent driver. | None for this transport guard. |
| `diagnostic_inspection_retains_partial_package_states_without_success_proof` | Actual FAMILY `inspect` reads a marked root containing `hold ok installed`, `install reinstreq half-configured` and `deinstall ok config-files`. Separately, a real bounded native child exits at `after_execution_intent`; FAMILY inspection of that **genuinely active** root returns the persisted operation state and `native_active_evidence:true`. Both driver-produced reports and evidence pass `validateDiagnosticInspection`, contain no invented install/completion/authority, and leave the root snapshot unchanged. | Active inspection here is a seed for diagnostics, **not** proof of crash completion, failed-script replay or #231 trigger parity. |
| `diagnostic_inspection_refuses_completion_or_authoritative_relabelling` | The Zig consumer mutates the **driver-produced** report/evidence, not a hand-written success fixture, and requires `InvalidDiagnosticInspection` for changed, invented lock/provenance, relabelled operation, invented install/completion, false diagnostic flag and wrong root. | None for the listed report/evidence negatives; Python acceptance remains required. |
| `family_verification_still_refuses_host_root_before_spawn` | Host `/` is refused before a request directory or child exists, with the same exact diagnostic and nonexistent driver. | None for this transport guard. |

The embedded batch repository remains **planning-only**: its published
package digests do not materialize executable archives. All claimed completed
transactions above instead use the separately generated signed repository
whose published digests match its available archives. This focused slice is
not, by itself, the full signed-suite parity matrix; the separate executed
parity target above now supplies that matrix. The unit inventory above
records the prior baseline and no Python method or gate is retired.

#### `exercise_workflows` scenario inventory (Python lines 2782–4136)

The FAMILY Zig target is already mandatory in the amd64/arm64 native-recovery
CI job in **both Debug and ReleaseSafe** with pinned reference dpkg; the
security audit and its CI-command removal mutation test enforce both exact
commands. The extended target now also executes the *ordinary workflow*
against signed archives: two interrupted FAMILY create/update chains with
cache and input-lock eviction, a multi-selector install → upgrade-all no-op →
remove batch, a reserved/retained externally owned install and exact
finalization, all four pre/post-mutation reconciliation claim/finalization
crash combinations, and five ordinary completion-crash recoveries. Every
executed install/remove/upgrade/recovery sequence checks durable lock,
receipt and completion bindings and its resulting private root against
pinned reference dpkg; owned verification checks read-only root snapshots.
The transport checks exit **86** and absence of report/evidence for crashed
children, and bounds each spawned child to 120 seconds plus kill grace.
This extends the already-required focused target rather than adding a second
target that runs the same signed repository twice. The Python gates and
selectors are **not** removed. A shared primitive elsewhere in Zig is not
counted as parity for an unexecuted Python workflow scenario:

`test/native_recovery_projected_workflows.zig` is invoked from that required
target. It runs the real driver inside bounded private mount/PID namespaces,
checks a marked disposable root and PID 1 before chroot, mounts an isolated
`/proc`, and checks the root projection mount is cleared after every child.
Against the signed archives and pinned dpkg it executes **success, recovered
and failed** plan/reserve/execute/recover chains, with withheld-projection
refusal, real exit-86 receipt interruption for recovered/failed, matching
root-scoped receipts and lock/completion bindings, owner verification and
wrong-lock proof refusal, v1→v2 transfer, publish/authorized/foreign/clear
review states, active-review acknowledgment refusal, and repeated final
acknowledgment without package replay. Each variant also executes the real
wrong backend/schema/version/digest/outcome and altered policy/selector/arch
verification refusals, damaged lock/receipt/status refusals, generation-2/3
interrupted review acknowledgment, generation-4 stale owner refusal,
generation-5 interrupted and generation-6 prepared acknowledged review
where applicable, and generation-7/8 cleared-review marker-crash convergence
with damaged completion/orphan intent and retained evidence. The projected
driver's dynamic libraries are installed in both private roots, so pinned
dpkg comparisons include the same non-package fixture dependencies.

| Python scenario | Executed Zig checks and remaining gaps |
| --- | --- |
| `family-completed-verification` | **Executed:** `allow_downgrade`/`foreign_architectures` and the other caller-request refusals, create mutation matrix, create/customize semantic equivalence, two-attempt completion refusal, document corruption, real failure-state refusal and clean recovery. The full serialized successful return summary is rechecked by a real verification after **each** create refusal, with an unchanged complete-root byte/metadata inventory. Signed failed-customize execution binds all seven returned-completion fields to its actual lock, receipt and completion. The signed create/customize root continues into failed customize, clean recovery and failed-package inspection with pinned dpkg. Separately, a **single ordinary signed plan/install → successful FAMILY verification with and without returned completion → all seven digest/identifier, outcome, settlement, operation and six caller-request refusals → four damaged-evidence and unsettled-operation refusals → final byte-exact successful summary → ordinary failed plan/install → three FAMILY failure-proof refusals → clean ordinary recovery** runs on one private pinned-dpkg-matched root, binding all seven returned fields on both transactions. No named Python check remains in this row. |
| `family-recovered-verification` | **Executed:** real **ordinary signed install** `after_native_receipt` crash, pending verification refusal, all five forbidden FAMILY recovery fields with unchanged original root-operation bytes **and complete root byte/metadata inventory**, cache/lock eviction, real FAMILY recovery and completed original-request verification, foreign completed attempt refusal, reference-dpkg parity. All seven returned completion digests bind the actual lock/receipt/completion; successful serialized summaries are equal across with-/without-result recovery verifications and remain equal after the foreign refusal, with immutable complete-root evidence. No named Python check remains in this row. |
| `family-native-install` | **Executed:** initial read-only full-root inspection, real signed create → inspection while a **nonblocking exclusive root lock remains held** → real signed customize → failed signed customize → byte-exact clean no-op recovery → failed-package inspection on the same root, with pinned-dpkg comparisons after each transaction. Additional separate-root failed returned-evidence verification remains covered in `family-update-failure`/`family-completed-verification`. No named Python check remains in this row. |
| `family-missing-helper` | **Executed:** inspection of the actual precise missing-helper root before planning (only essential-core installed), signed plan, refusal and immutable status. No named Python check remains in this row. |
| `family-update-selected`, `family-update-all` | **Executed:** install-lock rejection, update binding refusals, selected/all update, complete seven-field returned completion digests, exact successful verification's 24-field v2 schema inventory and bindings to lock/receipt/completion, byte-equal with-/without-returned-completion summaries, wrong-install proof refusal and unchanged complete-root bytes/metadata, pinned-dpkg parity and unchanged second updates. No named Python check remains in this row. |
| `family-update-recovery` | **Executed:** selected **ordinary signed `upgrade`** interrupted at `after_native_receipt`, cache and original input-lock eviction, FAMILY recovery without replay, all seven completion evidence digests, byte-equal repeat successful return summaries and immutable complete-root evidence during refusal and proof, pinned-dpkg parity. No named Python cache-byte inventory exists beyond asserted absence of unused inputs, which Zig also checks. No named Python check remains in this row. |
| `family-update-failure` | **Executed:** signed failed upgrade with all seven returned-completion digests bound to the real lock/receipt/completion, native failure/recoverable diagnostic and exact pinned-dpkg state, failed-result and relabeled-success refusal with immutable complete-root evidence, followed by clean no-op recovery. No named Python check remains unexecuted in this case; both Python gates remain for other recovery selectors. |
| `workflow-batch` | **Executed:** signed three-item version-3 lock with exact package set, reverse-selector ordinary install, unchanged `upgrade_all`, two-selector remove; each changed transaction binds real receipt/completion/lock and compares against pinned dpkg. The required target also runs the actual public `transaction-result` capabilities and verify commands against the **same signed roots**, checks canonical output and complete required 13-/24-field schema inventories with all known literals and lock/receipt/completion/owner-state bindings, unchanged namespace bytes/metadata, and refuses wrong architecture, a separately canonicalized valid wrong lock, unsettled record and damaged program/receipt/completion/database; successful proof repeats after all refusals and after removal. No named Python check remains in this row; the no-op upgrade-all intentionally overwrites the original install lock, and Python does not issue public proof against that overwritten lock. |
| `workflow-known-failure` | **Executed:** ordinary multi-selector plan/failed execute/recover, failed bound receipt/completion and **byte-exact complete** pinned-dpkg comparison, including `status-old`, status, files, info and trace. The reference is a single real pinned `dpkg --abort-after=1 --install fail-script base-dep scenario-main` invocation: unpack all three, configure the failing package first, abort rather than configure the others. This reproduces native's single failed transaction without advancing `status-old` through a second dpkg call. The public CLI refuses both the terminal failed receipt and its no-op recovery without changing namespace evidence. |
| `workflow-after_native_receipt`, `after_completed_record`, `after_owed_provenance_document`, `after_provenance_published`, `after_native_acknowledged` | **Executed:** all five ordinary signed batch crash/recover chains, matching pending root records, immutable root snapshots through completion, repeated no-op recoveries, original lock/receipt/completion bindings and pinned-dpkg parity. Each recovered root also passes the **actual public CLI** `transaction-result verify` with a canonical 24-field successful result and unchanged evidence. After-receipt non-owner deferral, wrong operation/selector/recommends/conffile, and replacement lock/source/keyring/force recovery options produce the same distinct refusal statuses as Python; each preserves exact pending record and namespace bytes/metadata. No named Python check remains in this row. |
| `workflow-owned-success`; `workflow-finalize-*` (three boundaries) | **Executed:** real reserve with exact `root_attempt_id`, foreign selector refusal preserving pending record, reverse-selector owned execution, retained evidence, FAMILY recovery refusal, read-only released owner verification, wrong state and bound-as-released refusal; wrong operation/selector/policy and unfinished record, active intent/script/progress/staging and damaged receipt/completion refusals, each with complete immutable namespace inventory. The public CLI refuses retained ownership but verifies after repeated finalization with reference-dpkg parity. All three dedicated terminal-publication crashes refuse actual CLI verification while the owner remains and verify successfully after repeated finalization; terminal-record-clear replaces the owner with the distinct first root's released-attempt marker and refuses read-only proof with immutable namespace evidence, then restores the original marker before repeated finalization and dpkg comparison. No named Python whole-root inventory exists at terminal interruption; its trigger snapshots and marker checks are covered. No named Python check remains in this row. |
| `workflow-owned-abandon-*` (two outcomes); `workflow-owned-*` (five execution/acknowledgment pairs); `workflow-owned-known-failure` | **Executed:** both genuine abandonments preserve root/reference-dpkg state and finalize the abandoned owner. All five distinct signed execution/acknowledgment crash pairs bind pending owner, original lock/receipt/completion, reject foreign owner recovery and acknowledgment, prove immutable read-only pending verification, and converge without package replay against pinned dpkg. The first pending-owner pair additionally refuses bound-as-pending and wrong operation/selector/recommends; damages real intent/progress/authorization/program/triggers/managed/completion/receipt, and creates each unresolved script/trigger-authority/foreign-outcome/staging artifact to refuse proof; removal of progress still permits the legitimate partial-acknowledgment proof. Wrong-operation and damaged-receipt acknowledgment refuse without changing record or owner; every proof compares the exact namespace byte/metadata inventory before/after. The actual public CLI refuses pending proof in all five, including after the first native-acknowledgment crash, and verifies after finalization. The failed owned receipt also executes unpublished-proof refusal, honest failed proof, mismatched-success/request and changed-database/intent rejection, acknowledgment crash, **byte-exact single-invocation pinned-dpkg failure parity including `status-old`**, and real public CLI failure refusals through final acknowledgment. No named Python whole-root inventory exists at intermediate steps; its trigger snapshots and namespace inventories are covered. No named Python check remains in this row. |
| `workflow-reconciliation-*` (four pre/post-mutation claim pairs) | **Executed:** all four genuine claim and ownership-finalization crash combinations. The real signed no-op lock digest binds each pre/post claim; before either pre-publication marker appears, a changed operation/selector claim is rejected without altering the pending proof bytes or complete namespace inventory. Expected marker state/bytes persist through repeat refusal, repeated finalization removes the owner without introducing receipt, completion, operation or intent; unchanged roots compare with pinned dpkg. No named Python check remains in this row; further exclusion/authority mutations would extend beyond `exercise_workflows`. |
| `workflow-projected-*` (success/recovered/failed) | **Executed:** all three actual PID-/mount-isolated signed variants, real receipt interruption/recovery in two, withheld-projection refusal preserves status and has neither operation nor owner, successful review transfer copies the generated **version-2 owner evidence**, review publish/authorized/foreign/clear, full wrong backend/schema/version/digest/outcome/request-policy/selector/architecture and damaged lock/receipt/status verification refusals, generation-2/3/4 review and acknowledgment crashes, recovered/failed generation-5/6 prepared acknowledged review, generation-7/8 prepared cleared review with pre/post marker-clear crashes and damaged completion/orphan intent refusals, and pinned-dpkg comparisons. Every genuinely read-only verification compares a bounded, recursive **byte-exact hex inventory** of all namespace files plus path, inode, mode, size, and mtime; published/authorized/foreign/cleared review operations additionally check full namespace-byte equality at the appropriate pre-/post-publication boundaries. Damaged completion and orphan intent at generation-7 assert unchanged complete namespace-byte/metadata inventories during each refusal. The previously listed staged/foreign owner-evidence replacement *across all generations* is not a Python `exercise_workflows` operation: Python transfers the owner once in the success branch, checks a foreign **review** without replacing the owner, and retains stale ownership through later generations; Zig executes those same operations. No named Python check remains in this row; repository projection acceptance is a different entry point. |

The prior split-timeline gap in `family-completed-verification` now runs on
one signed ordinary-install root through all successful-result refusals, the
failed second install and clean recovery. The five recovered ordinary roots
also execute the public CLI proof that Python's `assert_completion` invokes.
No named `exercise_workflows` check remains unexecuted in this case ledger;
this does **not** retire either Python recovery acceptance gate or establish
parity for the other Python recovery entry points and selectors inventoried
above.

#### Upstream #231 compatibility boundary

This integration includes #231 (`4ef6188`). The CRASH/HELPER target above
executes its two failed-postinst crash/restart seams with pinned-dpkg state
comparison; the FAMILY target's `after_execution_intent` child only seeds
diagnostic inspection and is not a failed-script scenario. #231 also added
pinned-dpkg trigger reference cases for both awaited and no-await activation:
an unpacked listener must stay unpacked, without a pending trigger, after
the source postinst fails. The Zig trigger suite now runs both as
**reference-only** pinned-dpkg cases; the native program compiler refuses
this unconfigured-listener program, so this is not a native parity claim.
The `--native-script-failure-only` Python selector and both Python recovery
gates remain required. The Zig trigger gates keep these two reference-only
cases on both architectures and in both optimization modes.

### Recovery entry-point selector reconciliation (#215; Python gates retained)

This is an inventory of **executed processes**, not of unit tests or fixture
constants. Each Zig target below is required by one of the two
`native-recovery-zig-*` CI shards in Debug and ReleaseSafe on amd64/arm64;
`-Dnative-reference-dpkg=...` selects pinned
dpkg 1.22.22. "Executed" means that the named case reaches the driver or
public binary in a disposable root; **partial** means that some Python
assertions about the resulting evidence are still not checked by Zig.
Neither `tools/test-native-recovery.py` nor `tools/test_native_recovery.py`
may be removed on the strength of the matching names alone.

| Python selector and complete case inventory | Required Zig target / actual observation | Status |
| --- | --- | --- |
| `exercise()` — its 32 named cases (each name and crash/negative in the [`exercise()` case ledger](#exercise-real-process-case-ledger-separate-from-workflow-parity)) | `test-native-recovery-helper-zig`; real exit-86 children, original evidence/receipt, pinned dpkg and immutable refusals/completions | Executed; see the 32-row ledger. |
| `exercise_deadlines`: `deadline-before-execution`; `deadline-script-cumulative`; `deadline-persisted-recovery` | `test-native-recovery-zig`, `deadlineStartup`, `deadlineCancellation`, `deadlinePersisted`. The first and third now use real scriptful archives; the cumulative case executes both scripts, retains the exact inert `metadata_contents("1")["config"]` bytes without running it, checks both output digests/accounting and original helper invocation hashes, then refuses unknown-outcome recovery. Persisted success compares to pinned dpkg and acknowledges the original caller. | Executed for these three boundaries. |
| `exercise_script_failure_state`: unowned `postinst-failure-after_failure_outcome`, `postinst-failure-after_script_failure_state` | `test-native-recovery-helper-zig`, `knownFailure`: **unowned** actual failed postinst, durably applied half-configured state on the second seam, archive eviction, pinned-dpkg failure parity and repeated recovery/acknowledgment. These are not the separate helper-owned failures in `caseRun`. | Executed: both. |
| `exercise_core`: `core-after_native_receipt`, `core-after_completed_record`, `core-after_owed_provenance_document`, `core-after_provenance_published`, `core-after_native_acknowledged`; `core-known-failure`; `core-unknown-script` | `test-native-recovery-zig`, `coreCases` and `coreScriptOutcomes`: all five completion crashes now use scriptful archives, evict the archive, compare to pinned dpkg, validate the typed receipt and every retained evidence digest, original caller request, output and helper-bound script invocation, and check completion/no repeated work. Known preinst failure compares to dpkg; unknown script return refuses in both core and FAMILY and remains inspectable. | Executed: all seven; core target additionally runs three initial journal/provenance windows. |
| `exercise_diversion_recovery`: exact Python tuple numbers **001–100** | `test-native-recovery-zig-diversions`, `cases[0..100]` and `runCase`; each explicit `Case.number` is ordered/unique at compile time, runs a crash child and the matching recovery/refusal against pinned dpkg. See [numbered diversion inventory](#numbered-diversion-recovery-migration) for the windows and drift groups. | Executed: 100/100; number maps one-to-one to the Python tuple in source order. |
| `exercise_statoverride_recovery`: install at `after_execution_intent`, `during_filesystem_publication`, `after_script_outcome`, `after_failure_outcome`; upgrade at `during_filesystem_publication`, `after_script_outcome`; remove at `after_script_outcome`; purge at `after_script_prepared`; install-{account,override,created} at `after_script_outcome`; drift `passwd-blob`, `group-blob-missing`, `passwd`, `group`, `statoverride`, `owner` at their respective Python windows | `test-native-recovery-zig-statoverride`, 17 ordered `cases` + `runCase`; real helper-bound/core crashes, pinned dpkg, retained original passwd/group blobs, immutable drift refusal, unchanged helper inode/bytes. | Executed: 17/17. |
| `exercise_conffile_lifecycle_recovery`: purge at `after_execution_intent`, `during_database_publication`, `after_script_prepared`, `after_script_outcome`, `after_failure_outcome` (failed), `after_trigger_outcome` (failed), `after_script_return_before_outcome`, `after_script_prepared` (drift); purge-deferred at failed `after_failure_outcome`; purge-helper at failed `after_failure_outcome`, `after_trigger_outcome`; purge-helper-deferred at failed `after_failure_outcome`; configure at `after_script_prepared`, `during_database_publication`, `during_database_publication` (drift), `after_script_outcome`, `after_script_prepared` (drift); configure-upgrade at `after_script_prepared`, `after_script_outcome`, `during_database_publication` | `test-native-recovery-zig-conffile`, 20 explicit `cases` + `runCase`; each runs a real crash, checks modified conffile, known failure/unknown outcome or drift, and successful pinned-dpkg recovery with retained completion. | Executed: 20/20. |
| `exercise_metadata_recovery`: install/during-filesystem; upgrade/after-trigger; remove/after-script; purge/after-script; install/after-trigger drift in `symbols` bytes, mode, absence or `config` bytes, mode, owner, absence | `test-native-recovery-zig-metadata`, 11 ordered `cases` + `runCase`; script/helper-bound crashes, immutable seven drift refusals, original retained metadata and pinned dpkg. | Executed: 11/11. |
| `exercise_literal_path_recovery`: v1/during-filesystem, v1/after-trigger, v2/after-trigger, v1/after-trigger conffile drift, v2/after-trigger staged-script drift | `test-native-recovery-zig-literal`, five `cases` + `runCase`; escaped path and trigger evidence, genuine crash/refusal and pinned-dpkg successful recovery. | Executed: 5/5. |
| `exercise_scriptless_recovery`: `{installed,new}` × `{before_scriptless_trigger_completion,after_scriptless_trigger_completion,before_scriptless_trigger_completion + postinst-presence drift}` | `test-native-recovery-zig-scriptless`, six calls to `runCase`; real scriptless/no-handler and scripted listener, absence of invented script, pending state, reference dpkg and changed-presence refusals. | Executed: 6/6. |
| `exercise_consumer_parity`: `{debian-stable,ubuntu-26.04}` × `{pre-depends,virtual-provides,dependency-cycle,without-recommends,with-recommends,multiarch-package,literal-package-paths,retained-metadata,suite-trigger,upgrade-all,held-unchanged,conffile-keep,conffile-replace,known-script-failure}` | `test-native-recovery-zig-parity`, `parity_suites × parity_cases` + `execute`: 28 signed real public core/FAMILY plans and executions, byte-equal exact locks, pinned-dpkg snapshot parity and installed helper identity. For each of the 26 changed cases, both receipts run `native_recovery_parity_evidence.verify`: canonical provenance and all retained-byte digests, typed manifest/document digests, caller request and program/authorization bindings, progress/outcome and managed histories, isolated helper and script output/invocation/expected environment, successful script trace, typed diversion-cache and unpack-cache bindings, and independent bounded capture of actual dpkg files for both final generation and distinct final closure digests. Failed scripts must retain nonzero exit evidence; the failed-script fixture does not promise a trace line. Both held cases instead require no receipt/completion and an unchanged entire root. | Executed per receipt on arm64 with pinned dpkg; 28/28 signed cases, 52 changed receipts and four held roots. Python gate retained. |
| `exercise_workflows`: each named signed create/customize/update/recover/inspect/batch/owner/verification/review case in the [workflow scenario inventory](#exercise_workflows-scenario-inventory-python-lines-27824136) | `test-native-recovery-zig-family` (`native_recovery_family` and `native_recovery_projected_workflows`); signed driver/reference children and projected owner reviews. | Executed at the named-scenario level per the workflow ledger; Python gate retained. |
| `exercise_repository_cli` / `repository_cli_cases`: `success`, `no_refresh`, `unchanged`, `unchanged_no_refresh`, `known_failure`, `refresh_failure`, `signal`, `lock_wait`, `lock_signal`, `unsafe_runtime`, `deadline`, `network` | `test-native-recovery-zig-repository`, `cliScenario` and `verifyCliScenario`: twelve supervised public CLI processes in disposable projections, canonical typed result decoding, three-call replay or bounded one-call refusal, real lock/signal/HTTP and helper/stale-root checks. | Executed: 12/12; CLI success and refusal shapes checked. |
| `exercise_projection`: one read-only root with *both* `native_transaction_result.test.projected root external fixture` and `apt_system_orchestrator.test.projected native dispatch external fixture` | `test-native-recovery-zig-family`, `readOnlyProjection`: private PID/mount child runs the **actual test executable** with `DEBZ_NATIVE_PROJECTION_FIXTURE=1`, requires both named tests to report OK, byte-identical root evidence, empty lock and no leaked projection mount. The three signed projected workflows are separate cases, not proxies for this row. | Executed: 1/1. |
| `exercise_repository_projection`: scoped caller preparation/adoption and cleanup | `test-native-recovery-zig-repository`, `projectionCase`: real private projected root, exact completion marker, lock-only namespace, absence of installed list and unchanged held bytes. | Executed: 1/1. |
| `exercise_repository_execution`: execution `{success,known_failure,interrupted,missing_helper,unchanged,diagnostic,expired}`; resume `{success,known_failure,interrupted,unchanged}`; held unchanged `{refresh,no-refresh}`; dispatch `{success,no_refresh,unchanged,unchanged_no_refresh,known_failure,interrupted,completion_interrupted,locked_interrupted,scope_lost,refresh_failure,expired}` | `test-native-recovery-zig-repository`, `executionCase` (11), `unchangedCases` (2), `dispatchCases` (11): real private projected caller/backend children and original-input eviction. The six terminal execution/resume receipts now validate original locked checkpoint against typed final checkpoint, managed files against typed manifest and live bytes, caller completion record/generation and independently recomputed discharge, byte-identical private-mode completion copies, retained-document and actual database digests, exactly two source-bound script outcomes and isolated helper invocations, helper bytes/inode, and resumed caller/history identity (eight original inode/byte witnesses for success). Five nonterminal cases explicitly refuse all receipt/helper/repository artifacts and preserve the held path. Both no-receipt unchanged cases validate original vs publisher caller identity, checkpoint/manifest, held database, exact lock and descriptor archive/link digests; all eleven dispatch cases decode canonical result/checkpoint/provenance or unchanged evidence, hold state, non-success initial interruption, repeated result and unchanged helper identity. | Executed per named scenario and evidence shape: 11 + 2 + 11. The projected Zig fixture has its own pinned **amd64** target architecture even when the outer runner validates the pinned arm64 dpkg environment; do not mistake this synthetic projection for an arm64 dpkg differential. Python gate retained. |
| `exercise_fresh_helper_bootstrap`: recoverable `{after_execution_intent,during_filesystem_publication,during_database_publication,after_helper_source_prepared,during_helper_source_publication,after_helper_source_publication,after_helper_probe_prepared,after_helper_probe_outcome,after_helper_probe_completed,after_provenance}`; unknown `{after_helper_probe_in_flight,after_helper_probe_return_before_outcome}`; `ambient-target`, `ambient-source`; cleanup `{after_helper_cleanup_prepared,during_helper_cleanup,after_helper_cleanup_completed}`; scripted `{after_script_prepared,after_script_outcome,after_script_return_before_outcome}` | `test-native-recovery-zig-bootstrap`, explicit `recoverable`, `unknown_probe`, `cleanup`, `script_known` loops and `blocked` script case: real package-owned helper bootstrap, exit 86, eviction, fresh recovery, pinned dpkg and two immutable refusals for unknown/ambient cases. | Executed: 20/20. |

**Repository architecture scope:** Python `exercise_repository_projection`
and `exercise_repository_execution` create the outer private root with the
host architecture, just as `native_recovery_repository.makeRoot` does. Both
then run the same embedded repository backend fixture, which stages its
own `amd64` dpkg status and `arch` file. Neither Python selector compares that
execution root with reference dpkg. Python's CLI selector uses the host
architecture for the signed descriptor and repository, and uses pinned dpkg
only to seed the held/unchanged cases; it does not compare a changed CLI
transaction against dpkg. Zig `cliScenario` follows those same host-architecture
and reference-seed paths. Separately, the required FAMILY target's
`native_recovery_projected_workflows.caseRun` executes signed projected
transactions using host-architecture archives and compares their complete
private-root state with pinned dpkg. It is a real arm64 projected differential
on arm64, but **not** a repository-backend differential. Adding an arm64
repository-backend/dpkg differential would extend, not migrate, these Python
selectors; do not count the synthetic repository fixture as one.

The repository CLI network-evidence check reads every byte of regular files
in bounded chunks, retaining the secret-prefix overlap across reads rather
than imposing a 2 MiB artifact limit. Its Zig regression places the marker
across a chunk boundary both near the start and beyond 2 MiB; the same
scanner runs after each real CLI invocation in both required build modes.

**Remaining before Python gate retirement:** no named entry-point scenario
in this ledger has an outstanding evidence-shape item. Keep both Python
gates: this ledger accounts for the named selector observations, not an
approval to remove independent acceptance or the separate #231 reference-only
unconfigured-listener cases. `test_native_recovery.py` also has the Python-only
`referencing`-absent schema import path (method 41 in the unit ledger), for
which Zig's schema reader is not an equivalent test. Keep both gates through
integrated amd64/arm64 Debug/ReleaseSafe acceptance and a separate decision
about preserving that Python-specific validation.

# Native recovery and provenance

Items 14 and 15b provide durable execution boundaries around the compiled native
lifecycle, including the experimental caller-owned `debz.native_runtime` API.
Core product/CLI native execution and persisted-input recovery are experimental;
this does not enable a product cutover or change legacy recovery.

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

Filesystem and database repair delegates to the existing
[root mutation layer](root-mutation.md). Missing, corrupt, mismatched, or
externally changed evidence cannot become an absent journal or an implicitly
successful step.

Bounded managed-state checkpoints preserve exact path content, metadata and
directory membership at completed phases and known script outcomes. Recovery
checks these durable expectations before continuing; a completed phase marker
alone cannot authorize resuming over externally changed payload.

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

An absent `usr/bin/dpkg-trigger` target is explicitly refused before package
mutation. No placeholder is created, and no existing target is overwritten.
Plans that remove the target's owning package, omit the target from its
replacement archive, or replace it with a non-regular entry are also refused.
Fresh-root target creation is outside this increment.

### Experimental typed runtime API

`debz.native_runtime` exposes `execute`, `recover`, `readCompletion`, and
`acknowledge` without exposing fixture controls or a command-shaped executor.
It supports Linux non-host roots. The caller must retain a live, locked native
`root_operation.Attempt` and its coordinator throughout each call. The runtime
reopens the canonical named root without following symlinks and matches its
device/inode against the held root before work; host roots, lost locks,
legacy attempts, and mismatched root descriptors are refused.

Prepare with `native_runtime.scriptPolicy()` and supply the owned preparation
plus immutable archive byte slices to `execute`. Inputs are borrowed for the
call and must not be changed concurrently. Authorization/program integrity,
caller binding, archive bytes, and locked database state are revalidated.
The runtime always uses the bundled trusted helper and persists a v2 request.
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
the outer record's pre-mutation flag alone is insufficient.

Core product/CLI planning, download, execution, and recovery use these typed
contracts. Native mutation requires a reviewed v2 lock and a supported non-host
root. Native recovery accepts no new repository or lock inputs and reads only
the original persisted execution evidence. Terminal success and known failure
bind `root-operation-completion-v1.json` to the exact native receipt, publish
the outer provenance transition, acknowledge native evidence, and finally clear
the caller's active record. Every boundary is restartable. Generic acquisition
cannot reclaim a native program-bound attempt in either the pre-intent or
pending-acknowledgment window, and an orphan native intent blocks other engines.
Empty v2 closures now represent last-package removal or purge,
with explicit action authorization and retained configuration modeled separately.
Remaining consumer integration and full pinned parity remain roadmap work.
Legacy stays default, and there is no fallback.

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

```sh
zig build test-native-recovery -j2
zig build test-native-recovery -Doptimize=ReleaseSafe -j2
```

The native Linux amd64/arm64 runner requires the existing dpkg/chroot fixture
prerequisites and passwordless sudo. Only fixture execution is elevated.
Artifacts stay under the worktree's `.tmp`; `--workspace` retains a new direct
child there. `test-native-recovery-unit` runs focused journal/provenance units,
and the default unit target includes the independent oracle regressions.

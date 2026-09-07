# Root-scoped operation coordination

`src/root_operation.zig` implements the single mutation gate every debz
operation passes through before it changes a selected root. Repository
bootstrap (`debz repo add`) and package transactions (`install`, `remove`,
`upgrade`, `upgrade-all`, `reinstall`, `recover`) share one root mutation lock
and one durable active-attempt record, so two debz operations can never mutate
one root at the same time and an interrupted operation is always classified as
either *safely abandoned before mutation* or *recovery required*.

This module owns coordination only. It never writes a package database, never
applies an archive, and never runs a maintainer script.

## Namespace

Everything lives under the selected root's own bookkeeping directory, reached
only through [`root_fs`](root-filesystem.md):

| Root-relative path | Purpose |
| --- | --- |
| `var/lib/debz/` | shared namespace, provisioned with `createDirectoryPath` |
| `var/lib/debz/root-operation.lock` | the fixed root mutation lock |
| `var/lib/debz/root-operation-v1.json` | the versioned active-attempt record |
| `var/lib/debz/root-operation-completion-v1.json` | the versioned completion provenance statement recovery publishes for an interrupted completion |

Every component is resolved one at a time without following a symbolic link.
A symlinked `var/lib/debz` fails closed with `error.NamespaceUnavailable`
instead of writing outside the root. The record is published atomically through
a private staging entry, `fsync`ed, renamed over the destination, and the
destination directory is `fsync`ed, so a successful publication survives power
loss. Clearing the record removes it and `fsync`s the namespace.

The record and the completion statement are created with mode `0600`. They
contain digests and state, never secrets.

## Lock order

`root_operation.Rank` defines the total order for every lock any debz mutation
of a root can take. Locks are acquired in increasing rank and released in
decreasing rank, so no two call paths can deadlock.

| Rank | Lock | Owner |
| --- | --- | --- |
| 0 | `<root>/var/lib/debz/root-operation.lock` | `root_operation.Coordinator` |
| 1 | `<state>/repository/repo-add.lock` | repository backend |
| 2 | package cache writer lock | package cache workflow |
| 3 | transaction journal and state locks | product backend |
| 4 | `<root>/var/lib/debz/transaction.lock`, `<root>/var/lib/dpkg/lock-frontend`, `<root>/var/lib/dpkg/lock` | transaction executor |

Rank 0 is always taken first and held through provenance publication and the
clearing of the active intent. Locks the coordinator does not own are declared
to it with `Attempt.enterRank`/`Attempt.exitRank`, which refuse an
out-of-order acquisition with `error.LockOrderViolation`. Rank 0 is never
re-entered, because the attempt already holds it.

The production adapter (`SystemLockBackend`) opens the lock file through
`root_fs` — every prefix component resolved without following a symbolic link,
the leaf opened `O_NOFOLLOW` — and then takes a Linux open-file-description
write lock (`F_OFD_SETLK`, `F_WRLCK`). OFD locks conflict with dpkg's POSIX
record locks while remaining scoped to the descriptor, so independent threads
in one embedding process serialize exactly like separate processes. Acquisition
is bounded by `wait_ms`, polls a cancellation interface, and reports
`error.LockTimeout`, `error.LockCanceled`, `error.LockUnavailable`, or
`error.LockFailed`. Tests inject `TestLockBackend`, which distinguishes roots by
inode so two spellings of one root serialize just as they do in production.

## Record schema

`schema/root-operation-record-v1.json` is the canonical schema; the module is
the normative implementation. The record binds:

- the attempt identifier (32 random bytes from the platform CSPRNG) and a
  strictly increasing `generation`;
- the selected root: canonical absolute `install_root` plus
  `root_identity_sha256`, computed with the same `transaction_recovery.rootIdentity`
  function every other durable debz document uses, so a root has exactly one
  identity everywhere;
- the transaction `backend`, the mutation `surface`
  (`package_transaction` or `repository_bootstrap`), and the exact `operation`;
- the lifecycle: `state`, `phase`, monotonic `step`, sticky `mutation_started`,
  `outcome`, and provenance publication state;
- reviewed evidence: `request_sha256`, `policy_sha256`, and the write-once
  `plan_sha256`, `authorization_sha256`, `program_sha256`, `exact_lock`
  binding, `database_generation_sha256` (the package-database base generation),
  and `artifact_evidence_sha256` (the artifact/application evidence digest);
- the target and foreign architectures, canonically sorted and deduplicated;
- `reserved_unix` and `updated_unix` as evidence only.

Encoding is a fixed canonical JSON byte sequence covered by `digest_sha256`.
Decoding is bounded (`maximum_document_bytes` = 64 KiB) and strict: unknown
fields, missing fields, an unsupported schema or version, a mismatched root
identity or record digest, and any byte sequence that is not the exact
canonical encoding are all rejected. A corrupt, truncated, oversized,
symlinked, or non-regular record is an error, never an absent record, so a
damaged root fails closed instead of permitting a second mutation.

### Timestamps and budgets

Timestamps are recorded but never used to decide anything. No attempt expires,
and no lock is ever stolen because its holder looks old. Budgets are
deliberately absent from the record: a durable deadline would let a crash
during a long transaction turn into an automatic unlock.

## State machine

```
reserved ──► preflight ──► mutation_pending ──► mutating ──► verifying ──► completed
    │           │                │                  │            │            ▲
    │           │                │                  ▼            ▼            │
    └───────────┴────────────────┴──────────► recovery_required ◄─┘            │
                                                    │                          │
                                                    ▼                          │
                                                recovering ────────────────────┘
```

| State | Meaning |
| --- | --- |
| `reserved` | reserved before any mutation; nothing was touched |
| `preflight` | authorization and preflight evidence bound; still nothing touched |
| `mutation_pending` | control handed to an engine that may mutate; a witness is required |
| `mutating` | mutation is durably known to have started |
| `verifying` | mutation finished, verification in progress |
| `recovery_required` | durable failure after mutation |
| `recovering` | recovery in progress |
| `completed` | finished; provenance is owed unless nothing was mutated |

`Phase` records which boundary the attempt stopped at: `reserved`,
`authorization`, `preflight`, `mutation`, `script`, `trigger`, `database`,
`verification`, `provenance`. Each state admits an explicit set of phases;
anything else is rejected.

Rules enforced on every durable write:

- the state transition must appear in the explicit edge table, so nothing ever
  moves back to a pre-mutation state once mutation evidence exists;
- `generation` and `step` strictly increase, so evidence is monotonic;
- replaying the exact published boundary (same state, phase, explicit step,
  mutation flag, outcome, and provenance) is an idempotent success, which is
  what a caller does after crashing between publishing a boundary and acting on
  it;
- evidence digests are write-once, so an attempt cannot be rebound to a
  different authorization, program, plan, lock, database generation, or
  artifact set;
- the write is compare-and-set against the record currently on disk: the
  attempt identifier, generation, and digest must all match what this writer
  last published, so a stale writer that resumed from an older view is rejected
  with `error.StaleAttempt` instead of overwriting newer evidence;
- the root mutation lock must still be held; a lost lock fails with
  `error.LockLost` rather than publishing a boundary.

### Abandoned before mutation versus recovery required

`reserved` and `preflight` are durable proof that nothing was mutated. A caller
that gives up there calls `abandonIfPreMutation`, which completes the attempt
as `abandoned_before_mutation` with `provenance = not_required` and clears the
record. Both product and repository wiring do this automatically when they
return early, so an ordinary usage or planning failure never leaves a root
blocked.

Everything from `mutation_pending` onwards is recovery evidence. A later
mutation attempt is refused with `error.RecoveryRequired`; only an explicit
recovery (`Intent.recovery`) or a rerun of the very same operation
(`Intent.same_operation`) may adopt the record and finish it.

### Intents

`Intent` says what the caller wants to do with whatever the root already
carries. Every intent takes the same rank-0 lock first, so the choice only
decides how existing evidence is treated.

| Intent | Existing evidence | Used by |
| --- | --- | --- |
| `mutation` | blocks; recovery evidence is refused with `error.RecoveryRequired`, an owed provenance with `error.ProvenancePending` | package transactions |
| `same_operation` | adopted when the record binds exactly this operation, otherwise treated as `mutation` and refused with `error.AttemptMismatch` when it carries evidence | repository bootstrap |
| `recovery` | adopted unconditionally; a root with no record gets a fresh pre-mutation bridge | `debz recover` |

`same_operation` compares the backend, the mutation surface and exact
operation, the request digest, the policy digest, the target architecture, the
foreign-architecture set, and the write-once evidence digests. The root
identity is compared before any of them, for every intent. A record that
matches on all of these is the caller's own interrupted attempt, so adopting it
continues one operation rather than starting a second; anything else is a
different operation and may neither adopt nor overwrite the evidence. When the
mismatched record is durably settled — proven pre-mutation, or completed with
its provenance discharged — the plain `mutation` rules apply instead, so an
unrelated leftover that proves nothing was touched never locks a root out.

Adoption keeps the original attempt identifier and generation sequence, so the
compare-and-set still rejects a stale writer that resumed from an older view.

### Settled records are never adopted

A record that is `completed` with its provenance obligation discharged —
`clearable` — is durable evidence that an operation is *over*. No intent
adopts it, not even a rerun of exactly the same request and not an explicit
recovery. Continuing under it would run a second mutation with no reserved
attempt, no executor bridge, and a terminal outcome already published: a crash
mid-rerun would leave durable evidence claiming the opposite of what happened,
and `clear` would remove the record on the way out.

`acquire` therefore settles it before any adoption decision, with the same rule
every intent already uses for a resolved leftover:

- `existing = reclaim_resolved` reclaims it into a fresh attempt — a new
  attempt identifier, `generation + 1`, `reserved` (or `preflight` for a
  recovery), outcome and provenance pending, no mutation evidence;
- `existing = fail` reports it as `error.ResolvedAttemptPresent` rather than
  silently continuing under it.

A `completed` record that still owes its provenance is *not* settled: it is
adopted by a matching `same_operation` rerun, which publishes the owed
provenance and clears it, and refused with `error.AttemptMismatch` when the
rerun binds a different operation.

### The command-oriented executor bridge

The current production executor drives `dpkg` commands, so the moment control
is handed to it the backend can no longer prove that nothing was mutated —
but assuming that a mutation happened would falsely block roots that were
never touched. `mutation_pending` is the explicit bridge for exactly this:

- it is published before the executor takes any target lock;
- it never counts as safely abandoned, so an interrupted attempt still blocks
  the next mutation;
- it is resolved only by an explicit `Witness`. `proved_not_started` requires
  evidence that no command ran and completes the attempt as
  `abandoned_before_mutation`; `mutation_observed` moves to `mutating` and sets
  the sticky mutation flag.

### A witness only speaks for its own hand-over

`proved_not_started` is evidence about the hand-over the *observing* invocation
performed. A rerun or a recovery can adopt a record that is already at
`mutation_pending`, and that bridge belongs to an earlier run which handed
control to `dpkg` and never came back. Nothing this run's executor reports can
speak for it: this run's expired deadline, refused preflight, unavailable lock,
or undecodable journal all report `not_started` with no commands, which is
exactly the shape of a report that proves nothing ran.

`Attempt` therefore tracks where its bridge came from, as process state rather
than durable evidence — no record can carry across a crash the fact of who
performed the hand-over:

| `BridgeOrigin` | Set when | `proved_not_started` is |
| --- | --- | --- |
| `none` | the record carries no bridge | not applicable; `witness` refuses outside `mutation_pending` |
| `published_here` | this invocation advanced into `mutation_pending` | applied as reported |
| `inherited` | the adopted record already sat at `mutation_pending` | coerced to `mutation_observed` |

The coercion lives in `Attempt.witness`, which returns the witness it actually
applied, so an observation site that faithfully passes the witness its own
executor justified still cannot discharge another run's hand-over. Both guards
branch on the returned witness, never on the reported one. Re-publishing an
inherited bridge does not make it this run's; only advancing into
`mutation_pending` from another state does.

The result is conservative in the safe direction: an inherited bridge resolves
as observed mutation, the attempt keeps its mutation evidence, and the guard's
failure path leaves it `recovery_required` with its provenance still owed. A
bridge this invocation published itself is unaffected, so a transaction that
really failed before any spawn still releases the root.

### Deriving the witness

A command count is never that evidence on its own. The executor appends a
command's provenance only *after* the command completed and the operation
deadline was re-checked, so a first command that timed out, hit the deadline,
lost its lock, or failed to spawn returns zero commands while `dpkg` may
already have unpacked, configured, or removed something. A success-shaped
report is no better: a plan the executor drove to `complete` can still report
no commands.

`observedMutation(state, commands)` is therefore the only supported
derivation, and `reportWitness`/`recoveryReportWitness` are the only two call
shapes:

| Executor evidence | Witness |
| --- | --- |
| any completed command | `mutation_observed` |
| no command, `transaction_state = not_started` | `proved_not_started` |
| no command, any other `transaction_state` | `mutation_observed` |

The executor sets `transaction_state` to `in_progress` and persists the
command boundary *before* the first spawn, and a recovery publishes the decoded
journal's state before its own first command, so `not_started` with no commands
is the one case that really proves nothing was handed over. Everything else is
classified conservatively, which can only block a root that was not touched —
never clear one that was. `transaction_executor.test.an unfinished first
command reports started evidence without commands` pins that contract.

A recovery report carries a transaction state only *after* the journal has been
decoded, so `recoveryReportWitness` classifies two failures ahead of the state:

| Recovery failure | Witness | Why |
| --- | --- | --- |
| `journal_io` | `mutation_observed` | the journal could not be read at all, so its state is unknown |
| `journal_corrupt` | `mutation_observed` | a journal exists and is durable evidence a transaction reached this root |
| `journal_missing` | from the state | no journal was ever found, which really is proof nothing started |

Everything else keeps the state-based classification: a decoded journal has
already published its own state into the report.

When the executor returns no report at all — an error propagated out of the
engine — the attempt simply stays at `mutation_pending`. It is not
`provenPreMutation` and not `clearable`, so neither guard's `deinit` clears it
and the next mutation is refused until it is explicitly recovered.

## Provenance before clearing

`clear` refuses while the attempt is unfinished or while `provenance` is
`pending`. An attempt that mutated the root must therefore publish its
provenance digest first. `provenanceDigest` binds the attempt identifier, root
identity, request digest, plan digest, outcome, the published provenance
document digest when one exists, and whether the transaction journal was
archived. A crash between completing and publishing leaves a `completed`
record with provenance owed, which the next mutation reports as
`error.ProvenancePending`.

## Discharging an interrupted completion

The window between the terminal `completed` record and the cleared active
intent is the only part of a mutation whose interruption blocks a root that is
otherwise healthy. The transaction is over: dpkg finished, the executor
archived its journal, and the record says so — but the record still owes
provenance, so every later mutation is refused.

The obligation cannot be discharged by running the transaction engine again.
Re-running `dpkg` would be a second mutation rather than a recovery, and the
legacy journal can no longer answer for the finished transaction at all: a
rerun asks the archived journal about a plan it was never written for, so the
executor reports a failure that could never discharge anything. Before
`root_operation_completion` existed, `debz recover` did exactly that, its
`RecoveryReport` never succeeded, `finish` was never reached, and the only way
back was deleting the record by hand.

`src/root_operation_completion.zig` owns the durable statement that discharges
it, published at `var/lib/debz/root-operation-completion-v1.json` through the
same root-anchored, atomic, no-follow, `fsync`ed publication the record uses.
Republishing an identical statement rewrites nothing, so a recovery that is
itself interrupted converges on exactly one document.

`schema/root-operation-completion-v1.json` is the canonical schema. The
statement binds:

- the attempt identifier, and the `record_generation` and `record_digest_sha256`
  of the active record observed under the root mutation lock;
- the selected root, `root_identity_sha256`, `backend`, `surface`, and
  `operation` of the completed attempt;
- its terminal `phase`, `step`, sticky `mutation_started`, and `outcome`;
- every evidence digest the record carried: `request_sha256`, `policy_sha256`,
  `plan_sha256`, `authorization_sha256`, `program_sha256`, the `exact_lock`
  binding, `database_generation_sha256`, and `artifact_evidence_sha256`;
- the target and foreign architectures and the record's timestamps;
- `transaction_provenance`: whether the detailed document was
  `already_present` (found and verified), `recovered` (rebuilt from durable
  evidence before this statement), or `unavailable` (never published, because
  the crash window interrupted publication), with the bound document's schema
  and digest whenever one exists;
- `journal`: whether the transaction journal is `archived`, `active`, `absent`,
  or `unreadable`, with the digest of the bytes that were read;
- `discharge`: the surface, operation, and request digest of the command that
  discharged the obligation, kept separate from the completed attempt's own
  request so a reader can never mistake the recovering command for the command
  that mutated the root.

Encoding, digesting, and decoding follow the record's rules exactly: one
canonical byte sequence covered by `digest_sha256`, bounded at 64 KiB, strict
about unknown or missing fields, and fail-closed on a foreign root identity, a
mismatched digest, or any non-canonical byte sequence. `create` refuses to
describe an attempt that is not `completed`, that never mutated, whose outcome
is `pending` or `abandoned_before_mutation`, or whose evidence contradicts
itself — an `unavailable` detailed provenance with a document digest, an
`archived` journal without one, or a discharge operation that is not a real
operation of its surface. Details are bounded printable ASCII, so a damaged
root cannot smuggle control bytes into a diagnostic.

Nothing else is restated. The statement never repeats or reconstructs a
command, script, package, or verification outcome: an `unavailable` detailed
provenance says only that the transaction completion was durably witnessed and
that its detailed publication was interrupted.

The statement's digest is what `publishProvenance` binds, so a discharged
attempt is always traceable to it. A normal, uninterrupted completion is
unaffected: it publishes its own provenance digest and clears the intent
without ever writing this document.

## Integration

### Package transactions

`production_backend.withRepositories` reserves the root at rank 0 before
repository loading, refresh, acquisition, journal writes, and the executor.
The selected transaction backend is validated before that, so an unavailable
native selection still fails before any root access. Non-mutating operations —
`refresh`, `download`, `plan`, `list-installed`, `list-available`, `info`,
`provides`, `why`, `clean` — never reserve the root and stay usable while
another attempt holds it.

Boundaries published for one product mutation:

1. `reserved` when the attempt is taken;
2. `preflight` once the reviewed plan digest and exact-lock binding exist;
3. `mutation_pending` immediately before the executor call;
4. `mutating` or `abandoned_before_mutation`, decided by the witness the
   executor's own transaction state justifies;
5. `verifying`, then `completed` with the outcome;
6. provenance published, then the active intent cleared.

A failure after mutation stays at `recovery_required`. `debz recover` takes the
attempt with `Intent.recovery`, which adopts existing evidence instead of
blocking, and reserves a bridge record when a legacy root has none. A recovery
that adopts a record already at `mutation_pending` inherits that bridge: its
own report — a journal it could not find a state for, a lock it could not take,
a deadline that expired — never discharges it, so the record stays
`recovery_required` with its provenance owed.

A recovery that adopts a `completed` record whose provenance is still `pending`
resolves it before any repository, network, journal, or executor work, because
that attempt's transaction is already over. It refuses immediately unless the
record binds this backend and the `package_transaction` surface — a repository
bootstrap's owed provenance is finished by rerunning that bootstrap, never by a
package recovery. Then it reads back what survived under the explicit state
path:

| Evidence at `<state>/transaction-result.json` | Result |
| --- | --- |
| absent | `transaction_provenance: unavailable`, discharge proceeds |
| present, canonical, and bound to this attempt's plan, exact lock, architecture, and outcome | `transaction_provenance: already_present` with its digest bound |
| present but unreadable, non-canonical, digest-mismatched, a symbolic link, or a directory | blocking failure naming the document to inspect |
| present, valid, but bound to a different plan or exact lock | blocking failure naming the document to inspect |

A blocked discharge publishes nothing and clears nothing, so the interrupted
attempt's evidence and the unexplained document both survive for an operator to
look at, and the next mutation is still refused. Once the obstruction is gone
the same `debz recover` finishes the job, so no debz-owned record ever has to
be deleted by hand.

On success the statement is published first, the record transitions to
`published` bound to its digest, and only then is the active intent cleared —
the same provenance-before-clearing order an uninterrupted completion follows.
The journal evidence decides the `journal_archived` flag in the provenance
digest instead of assuming it, and `dpkg` is never run to discharge provenance.
The recovery intent the crashed run never removed is deleted afterwards,
because the transaction it described is over; a state directory that refuses
that removal is reported in the result rather than allowed to re-block a root
whose obligation is already discharged.

A mutating rerun does not discharge the obligation: it is refused with
`error.ProvenancePending`, whose diagnostic names `debz recover`. A rerun could
only either re-execute a transaction that already completed or clear an
obligation without publishing anything, and both are worse than staying
blocked with an actionable message.

### Repository bootstrap

`repository_backend.executeAdd` reserves the root at rank 0 immediately after
the transaction backend is selected and before the repository operation lock at
rank 1. It publishes `preflight` once the target snapshot is validated, enters
the bridge before the executor block, resolves it from the executor's own
transaction state, and publishes provenance bound to the
`transaction-result-v2.json` document digest before clearing the active intent.
The idempotent re-run path, which verifies an already-installed descriptor
without mutating, ends as `abandoned_before_mutation` and clears normally.

Repository bootstrap is resumable by construction: its own durable operation
state already replays acquisition, planning, install, import, and refresh. The
root attempt is bound to the same request digest *before* anything is acquired
and is taken with `Intent.same_operation`, so a rerun of exactly this request
adopts its own evidence and finishes it. Without that, every post-executor
failure — provenance publication, the `installed` checkpoint, installed
verification, the manifest, the `imported` checkpoint, the final refresh —
left the record at `verifying` and the rerun opened a generic mutation intent
that its own evidence refused, so the root could never be finished by debz
again.

The guard therefore resumes from whichever boundary the adopted record stopped
at:

| Adopted state | Before the executor | On success |
| --- | --- | --- |
| `reserved`, `preflight` | publish `mutation_pending` | `completed` as `abandoned_before_mutation` when nothing ran |
| `mutation_pending` | keep the inherited bridge | witness `mutation_observed`, then `verifying` and `completed` |
| `mutating`, `verifying` | `beginRecovery` walks the exact recovery edges | `verifying`, then `completed` as `succeeded` |
| `recovery_required`, `recovering` | `beginRecovery` | `recovering`, then `completed` as `recovered` |
| `completed` owing provenance | nothing is owed but provenance | provenance published, then cleared |

A `completed` record whose provenance is already published is settled instead
of adopted: the rerun reserves its own attempt over it, so a crash during the
rerun leaves evidence of the rerun rather than of the operation it replaced.

Mutation evidence is never cleared to make a rerun possible: an unresolved
attempt that belongs to a different descriptor, architecture, policy, request,
or package operation is still refused, and the record it could not adopt is
left exactly as it was published. Neither is it cleared by a rerun that failed
before its own first command: the bridge it adopted belongs to the run that
handed control over, so it resolves as observed mutation.

## Deferred to later native-engine work

- Native mutation, package-database writes, and archive application are not
  performed here; the record only binds their digests.
- Per-step native program progress is represented by `phase` plus `step`; the
  native engine will bind program step sequences once it exists.
- The legacy journal remains the command-level recovery authority. This module
  brackets it conservatively rather than reinterpreting it.

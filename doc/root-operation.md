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

Every component is resolved one at a time without following a symbolic link.
A symlinked `var/lib/debz` fails closed with `error.NamespaceUnavailable`
instead of writing outside the root. The record is published atomically through
a private staging entry, `fsync`ed, renamed over the destination, and the
destination directory is `fsync`ed, so a successful publication survives power
loss. Clearing the record removes it and `fsync`s the namespace.

The record is created with mode `0600`. It contains digests and state, never
secrets.

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
recovery (`Intent.recovery`) may adopt the record and finish it.

### The command-oriented executor bridge

The current production executor drives `dpkg` commands, so the moment control
is handed to it the backend can no longer prove that nothing was mutated —
but assuming that a mutation happened would falsely block roots that were
never touched. `mutation_pending` is the explicit bridge for exactly this:

- it is published before the executor takes any target lock;
- it never counts as safely abandoned, so an interrupted attempt still blocks
  the next mutation;
- it is resolved only by an explicit `Witness`. `proved_not_started` requires
  evidence that no command ran (the executor reported zero commands) and
  completes the attempt as `abandoned_before_mutation`; `mutation_observed`
  moves to `mutating` and sets the sticky mutation flag.

## Provenance before clearing

`clear` refuses while the attempt is unfinished or while `provenance` is
`pending`. An attempt that mutated the root must therefore publish its
provenance digest first. `provenanceDigest` binds the attempt identifier, root
identity, request digest, plan digest, outcome, the published provenance
document digest when one exists, and whether the transaction journal was
archived. A crash between completing and publishing leaves a `completed`
record with provenance owed, which the next mutation reports as
`error.ProvenancePending`.

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
4. `mutating` or `abandoned_before_mutation`, decided by whether the executor
   reported any command;
5. `verifying`, then `completed` with the outcome;
6. provenance published, then the active intent cleared.

A failure after mutation stays at `recovery_required`. `debz recover` takes the
attempt with `Intent.recovery`, which adopts existing evidence instead of
blocking, and reserves a bridge record when a legacy root has none.

### Repository bootstrap

`repository_backend.executeAdd` reserves the root at rank 0 immediately after
the transaction backend is selected and before the repository operation lock at
rank 1. It publishes `preflight` once the target snapshot is validated, enters
the bridge before the executor block, resolves it from the executor's command
evidence, and publishes provenance bound to the `transaction-result-v2.json`
document digest before clearing the active intent. The idempotent re-run path,
which verifies an already-installed descriptor without mutating, ends as
`abandoned_before_mutation` and clears normally.

## Deferred to later native-engine work

- Native mutation, package-database writes, and archive application are not
  performed here; the record only binds their digests.
- Per-step native program progress is represented by `phase` plus `step`; the
  native engine will bind program step sequences once it exists.
- The legacy journal remains the command-level recovery authority. This module
  brackets it conservatively rather than reinterpreting it.

# Native recovery and provenance

Item 14 adds a private durable execution boundary around the compiled native
lifecycle. Production native selection remains unavailable; this does not
enable a CLI or product cutover and does not change legacy recovery.

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

```sh
zig build test-native-recovery -j2
zig build test-native-recovery -Doptimize=ReleaseSafe -j2
```

The native Linux amd64/arm64 runner requires the existing dpkg/chroot fixture
prerequisites and passwordless sudo. Only fixture execution is elevated.
Artifacts stay under the worktree's `.tmp`; `--workspace` retains a new direct
child there. `test-native-recovery-unit` runs focused journal/provenance units,
and the default unit target includes the independent oracle regressions.

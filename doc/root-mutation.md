# Crash-safe root mutation layer

`src/root_mutation.zig` is the only place the native transaction engine changes
bytes in a selected root. A caller states a complete, ordered set of typed
intents; preflight resolves each one against the current root into an exact
precondition and an exact desired state; the result is published as a versioned
durable journal plus a chained write-ahead progress log; and only then does the
first target byte change.

The layer is deliberately reversible. A backup is captured before a target is
replaced or removed, and it is released only after the whole transaction
verifies. Recovery therefore either restores the recorded old state, finishes
releasing a transaction that already verified, or publishes a durable typed
recovery requirement. It never guesses, and an unresolved journal refuses every
further mutation of that root.

This module runs no maintainer script, processes no trigger, decides no package
ownership, and implements no unpack semantics. Those slices compose the
primitives documented here.

## Namespace

Everything lives under the root's own bookkeeping directory, shared with
[`root_operation`](root-operation.md) and reached only through
[`root_fs`](root-filesystem.md):

| Root-relative path | Purpose |
| --- | --- |
| `var/lib/debz/root-mutation-v1.json` | the versioned durable journal, written once per transaction |
| `var/lib/debz/root-mutation-v1.log` | the append-only, hash-chained progress log |
| `var/lib/debz/mutation/staging/` | new content, materialized before publication |
| `var/lib/debz/mutation/backup/` | hard links preserving replaced or removed content |

The workspace directories are `0700` and the journal and log are `0600`. Every
staging and backup entry is created exclusively, so an entry planted by an
attacker fails the creation instead of being followed or written through. Names
are derived from the step index alone, so they cannot collide with each other.
A plan that names any path inside `var/lib/debz` is refused during preflight
(`path_collision`), so a transaction can never corrupt its own recovery
evidence.

## Journal

The journal is canonically serialized JSON validated by
[`root-mutation-journal-v1`](../schema/root-mutation-journal-v1.json). Decoding
is strict and bounded: unknown fields, missing fields, an unsupported schema, a
step whose recorded shape contradicts its kind, a mismatched step or document
digest, and any byte sequence that is not the exact canonical encoding are all
rejected. `digest_sha256` covers the whole document with its own field removed,
and `steps_sha256` covers the ordered intents alone so a caller can bind a plan
to provenance without serializing the journal.

The journal binds:

- the root-operation attempt id, the record generation at publication, and that
  record's digest;
- the install root and the root identity digest;
- the authorization, native program, plan, exact-lock, package-database
  generation, package-database publication plan, and artifact evidence digests;
- the filesystem device every mutated path and the workspace share;
- the staging byte total and the configured budget;
- the exact ordered mutation intents.

`open` accepts only the attempt the journal names. A different attempt id is
`error.AttemptMismatch`, a different root identity is `error.RootMismatch`, and
a record older than the generation the journal was published under, or the same
generation with a different digest, is `error.StaleAttempt`.

## Intents and preflight

Preflight computes every intent completely before the first mutation. For each
target it records the expected old kind, content digest, mode, uid, gid,
modification time, link identity, inode, and link count — or explicit absence —
plus the desired new state, the overwrite or removal policy, the staging and
backup names, and the steps it depends on.

| Step kind | Publishes |
| --- | --- |
| `publish_file` | regular-file content supplied by the caller |
| `copy_file` | regular-file content copied from another path before that path is republished |
| `publish_symlink` | a symbolic link with an exact target |
| `publish_hard_link` | a hard link to an existing regular file in the same root |
| `create_directory` | a directory with an exact mode and ownership |
| `set_metadata` | a new mode, ownership, or modification time on an existing path |
| `remove_path` | removal of a regular file, hard link, or symbolic link |
| `remove_directory` | removal of an empty directory |

Preflight refuses, before anything can change:

| Diagnostic | Refusal |
| --- | --- |
| `invalid_path` | absolute, traversing, empty, control-byte, over-long, or over-deep path |
| `path_collision` | a target or source inside `var/lib/debz` |
| `symbolic_link_component` | any prefix component that is a symbolic link |
| `unsupported_kind` | a device, socket, FIFO, or unknown kind on a target |
| `ancestor_conflict` | an ancestor the plan turns into a file, a link, or nothing |
| `path_alias` | two distinct targets that resolve to one inode |
| `hard_link_ambiguous` | a link to itself, or a link whose source the plan republishes later |
| `hard_link_source_invalid` | a link source that is absent or is not a regular file |
| `directory_not_empty` | removing or replacing a directory that still has entries |
| `target_present` / `target_absent` | an overwrite or removal policy the root contradicts |
| `cross_device` | a target whose filesystem differs from the workspace |
| `capacity_exceeded` / `numeric_overflow` / `step_limit` | bounded resource accounting |
| `content_digest_mismatch` | content that does not hash to the digest the caller authorized |
| `metadata_unsupported` | a mode change on a symbolic link, or a mode outside `07777` |

A directory's modification time is derived from its own entries, so a later
step in the same plan would invalidate it as soon as it published a child. It
is normalized to zero for directories and is neither published nor asserted,
rather than being written and then quietly ignored.

Cross-device targets are refused because publication and restoration are
atomic renames between the workspace and the target directory, and a rename
cannot cross a filesystem boundary. Splitting a transaction per filesystem is
the caller's decision, not something this layer approximates.

## Write-ahead protocol

The journal is written once. Every boundary after that is a fixed-shape
progress record appended at the exact offset the caller proved durable and
`fsync`ed:

```
<sequence:016x> <scope> <index:08x> <boundary:24> <chain:064x>\n
```

Each record chains onto its predecessor, and the first chains onto the journal
digest, so a log can never be replayed against a different journal, a record
cannot be reordered or replayed, and a torn trailing write is discarded rather
than trusted. Appending is a compare-and-set: the writer reads the log's
durable tail and refuses with `error.StaleWriter` unless the file length and
the last record's sequence and chain digest are exactly the ones it holds, so a
writer whose view has been overtaken can never fork the history.

Transaction stages are `prepared`, `applying`, `rolling_back`, `verified`,
`completing`, `completed`, `releasing_rollback`, `rolled_back`, and
`recovery_required`. Releasing after a verified application and releasing after
a full restoration are separate stages, so an interruption during the release
still states which of the two states the root holds. Step boundaries are
`prepared`, `staged`, `backup_captured`, `published`, `metadata_applied`,
`parent_synced`, `verified`, `completed`, and `reverted`. A step publishes only
the boundaries its kind can reach.

Application of one step:

1. **staged** — the new content is created exclusively in the staging area,
   written, `fsync`ed, given its exact final mode, ownership, and modification
   time, and the staging directory is `fsync`ed. Content is re-hashed against
   the step's recorded digest immediately before it is written, so a substituted
   or unavailable payload never reaches the staging area.
2. **backup captured** — the replaceable regular-file content is hard-linked
   into the backup area and the backup directory is `fsync`ed. A symbolic link
   and a directory carry no content beyond what the journal already records, so
   they need no physical backup.
3. **published** — the target is compared to its recorded precondition and then
   taken over with a single atomic rename. A transition a rename cannot express
   (a directory becoming a file, link, or hard link, or a non-directory becoming
   a directory) removes the old entry first; the recorded expectation and
   desired state still differ in exactly one way, so the step stays resumable.
4. **metadata applied** — `create_directory` and `set_metadata` write their mode,
   ownership, and timestamp and `fsync` the affected inode. Only components that
   actually differ are written.
5. **parent synced** — the destination directory is `fsync`ed.
6. **verified** — the target is observed again and compared to the desired state
   exactly, including the content digest and link target.

Every boundary is idempotent. A retry compares the observed state to the
recorded expectation and to the recorded desired state; anything else is
`external_modification` and never a guess.

## Recovery

The recorded stage decides the direction:

| Stage | Direction | Root holds |
| --- | --- | --- |
| `prepared`, `applying`, `rolling_back` | restore the recorded old state | old state after recovery |
| `verified`, `completing`, `completed` | finish releasing the workspace | new state |
| `releasing_rollback`, `rolled_back` | finish releasing the workspace | old state |
| `recovery_required` | refuse | ambiguous |

Rollback is always possible because backups are released only after the whole
transaction verifies, so recovery never needs the original content re-supplied
and never depends on the process that started the transaction. Each step is
undone in reverse order and re-observed afterwards; a step whose target matches
neither the recorded old state nor the recorded new state publishes
`recovery_required` durably, tells the root-operation attempt through
`Attempt.requireRecovery`, and refuses every further mutation until an operator
resolves it. `clear` is refused unless the stage is `completed` or
`rolled_back`.

A `set_metadata` step proves its recorded precondition before it changes an
inode, because unlike a publication it never takes the target name over and
would otherwise stamp the plan's mode, ownership, and timestamp onto whatever
entry now occupies the name.

A cancellation or an expired deadline is observed at a step boundary, turns the
transaction around, and leaves a cleanly restored root plus the durable
evidence of why.

## Package database publication

`lowerDatabasePlan` is the typed adapter from
[`package_database_changes.Plan`](package-database.md) to mutation intents. The
plan's own ordering is the durable contract: `status-old` is captured first,
then every `info` file, then `arch`, then `triggers/File` and
`triggers/Unincorp`, and `status` last, so a crash before the final publication
leaves the previous generation intact. The adapter preserves that order exactly,
joins every path under the database directory, and refuses a plan whose first
write is not the `status-old` copy or whose last write is not the `status`
replacement (`database_plan_mismatch`). It performs no cross-module cast:
`replace` becomes a file publication with the plan's own digest as the
authorized content digest, `copy` becomes a copy step bound to the source
digest, and `remove` becomes a removal that tolerates an already absent target.

`databaseEvidence` binds the journal to the consumed generation digest and the
publication plan digest, and ownership of the published files is supplied
explicitly by the caller rather than assumed.

## Archive binding

`bindArchive` re-proves, immediately before content is staged, that the
in-memory archive bytes still carry the authenticated size and digest recorded
at acquisition and that the model still reproduces the exact authorized
application digest. Every archive-backed step records that binding, and the
engine re-hashes the exact bytes against the step's content digest at the
staging boundary. `archiveFileIntent` is a typed conversion of one modeled
archive entry into the intent that publishes it; which paths a package may own,
how conflicting ownership is resolved, conffile decisions, and the unpack
lifecycle stay with the package layer.

## What is deliberately not journalled

Arbitrary maintainer-script side effects are not rollbackable, so they are never
recorded as if they were. The journal covers only the filesystem and
package-database mutations this layer performs itself. Script and trigger work
remains an explicit handoff: the caller journals the filesystem and database
phases here, and records script and trigger outcomes through
[`root_operation`](root-operation.md) provenance.

## Testing

`zig build test-root-mutation` runs the layer's own suite. It injects a
simulated power loss at every syscall and durability boundary of every
primitive and proves that the resulting root is exactly the old state, exactly
the new state, or a durable recovery requirement; the harness fails if an
injected fault never fires. It also covers disk-full, short-write, `fsync`,
`rename`, `unlink`, and `link` failures, external modification and symbolic-link
swaps between preflight and publication, corrupt, truncated, torn, replayed, and
unknown-schema journals and logs, stale and mismatched attempts, a lost root
lock, cancellation, restart recovery through a freshly opened engine, database
publication and rollback against a real `var/lib/dpkg` generation, and
allocation failure at every allocation of preflight, decode, and replay. Every
test uses a disposable alternate root.

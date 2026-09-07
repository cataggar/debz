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
| `var/lib/debz/root-mutation-v2.log` | the append-only, hash-chained progress log |
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
| `invalid_encoding` | a path, source, or link target that is not valid UTF-8 |
| `path_collision` | a target or source inside `var/lib/debz` |
| `symbolic_link_component` | any prefix component that is a symbolic link |
| `unsupported_kind` | a device, socket, FIFO, or unknown kind on a target |
| `ancestor_conflict` | an ancestor the plan turns into a file, a link, or nothing |
| `path_alias` | two distinct modeled paths, targets or sources, that resolve to one inode |
| `hard_link_ambiguous` | a link to itself, or a link whose source the plan republishes later |
| `hard_link_source_invalid` | a link source that is absent or is not a regular file |
| `directory_not_empty` | removing or replacing a directory that still has entries |
| `target_present` / `target_absent` | an overwrite or removal policy the root contradicts |
| `cross_device` | a target whose filesystem differs from the workspace |
| `capacity_exceeded` / `numeric_overflow` / `step_limit` | bounded resource accounting |
| `content_digest_mismatch` | content that does not hash to the digest the caller authorized |
| `metadata_unsupported` | a mode change on a symbolic link, a mode outside `07777`, or an in-place ownership change on a non-directory carrying `security.capability` |

### Text the journal can carry

The journal is a canonical JSON document, and a JSON string carries text, not
bytes: `std.json` refuses a string whose bytes are not valid UTF-8, and so does
this module's decoder, which reads every document back through it. Text that is
not valid UTF-8 therefore has no journal spelling at all.

Nothing below this layer supplies that guarantee. The path grammar in
`root_fs.Path` bounds a path's shape — no absolute, traversing, empty,
control-byte, over-long, or over-deep spelling — but every byte at or above
`0x80` passes it, the payload grammar accepts the same bytes, and a symbolic
link the root already holds may point at any of them, because a Debian archive
and a POSIX filesystem both treat a name as an opaque byte string. Publishing
one would write a journal that the very next read — `prepare`'s own decode, or
recovery's after a crash — refuses as corrupt: a transaction whose workspace is
already durable and whose recovery evidence cannot be parsed.

So every string the document will carry is proven encodable before anything
durable exists, and the refusal is `invalid_encoding`, a preflight diagnostic
naming the exact input, never a decode failure discovered after publication.
Preflight proves each target path, each `copy_file` and `publish_hard_link`
source, each symbolic-link literal, and the target of every symbolic link it
observes on the root. `prepare` proves the assembled document once more —
install root, exact-lock schema, and every step string of the plan it was
handed — before the attempt record advances and before the journal is written,
and reports the same typed diagnostic through `Options.refusal`. The store
proves it once more at the write itself, so no path into it can publish a
document the decoder would refuse. A refused call leaves no journal, no
progress log, and no workspace entry.

The strings that reach the document from elsewhere are already proven by their
own validators: `install_root` by `absolute_path.canonical`, which validates
UTF-8; the exact-lock schema by `root_operation.create`, which refuses a
binding whose schema is empty, over-long, or not UTF-8; database paths by
`package_database.validRelativePath`; and staging and backup names, which are
derived from a step index and are always eight hexadecimal digits. The
adapters do not widen this: a database plan path, a database directory, an
archive path, an archive link literal, and an archive hard-link target are all
lowered into ordinary intents and meet the same refusal.

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
<sequence:016x> <scope> <index:08x> <boundary:24> <device:016x> <inode:016x> <links:016x> <chain:064x>\n
```

Each record chains onto its predecessor, and the first chains onto the journal
digest, so a log can never be replayed against a different journal, and a
record cannot be reordered or replayed.

The three identity columns are the entry a boundary bound to the state it
published — the containing device, the inode number, and that inode's link
count at the moment the boundary observed it. They are part of the chained
preimage rather than a comment beside it, so an edited, spliced, or relocated
identity breaks the chain. A journal states the shape of a state the plan will
produce; only a boundary can state which inode it landed on, and [several
steps on one path](#several-steps-on-one-path) depend on exactly that.

The columns are as wide as the values they carry, so a record that binds an
entry is exactly as long as one that binds nothing and a torn tail stays
exactly as detectable. Replay refuses evidence the journal contradicts, which
the chain alone cannot catch because a forger recomputes it:

| Record | Result |
| --- | --- |
| a bound inode on a journal-scoped record, or on any step boundary other than `verified` | `error.ProgressCorrupt` |
| a bound inode on a step whose desired state is an absence | `error.ProgressCorrupt` |
| a bound inode on a device other than the one the journal pinned | `error.ProgressCorrupt` |
| a bound inode with no links, or a device or link count with no inode | `error.ProgressCorrupt` |

The writer validates the record it is about to append by the same rules, so it
can never publish evidence its own replay would refuse.

Appending is a compare-and-set. The writer reads the **last complete record at
exactly `accepted_bytes - one record`**, never at whatever the physical end
happens to be, and refuses with `error.StaleWriter` unless that record's
sequence and chain digest are exactly the ones it holds. Reading at a proven
offset is what makes a torn tail survivable: a window taken from the physical
end after a half-completed append is a slice of two different records and
decodes as garbage.

The physical length is then compared to the accepted prefix:

| Physical length | Meaning | Result |
| --- | --- | --- |
| shorter than the accepted prefix | a different history | `error.StaleWriter` |
| exactly the accepted prefix | nothing is owed | append |
| up to one byte short of a whole record past it | a torn trailing write | truncate to the accepted prefix, `fsync`, then append |
| one whole record or more past it | another writer's append, a replay, or a foreign record | `error.StaleWriter` |

Only bytes past the compared record can be discarded, and only when there are
fewer of them than one record — a shape no complete record can have. A whole
extra record is never repaired away, because it is evidence that this writer's
view is stale rather than evidence of a torn write. The repair is `fsync`ed
before the append, so power loss during the repair leaves either the same torn
tail or the truncated prefix, and both replay to the same accepted prefix.

Replay applies the mirror rule: a trailing run shorter than one record was
never durable and is dropped, while a complete record that fails to decode,
chains onto the wrong predecessor, or carries the wrong sequence is
`error.ProgressCorrupt` and leaves the journal unresolved.

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
4. **metadata applied** — `create_directory` and `set_metadata` write their
   ownership, mode, and timestamp in that exact order and `fsync` the affected
   inode. Only components that actually differ are written, with one deliberate
   exception described below.
5. **parent synced** — the destination directory is `fsync`ed.
6. **verified** — the target is observed again and compared to the desired state
   exactly, including the content digest and link target. The entry that
   comparison proved is bound in the very record that publishes the boundary,
   so the state and the inode it landed on become durable together.

## Metadata order and privileged bits

Applying metadata is three syscalls, and their order is part of the durable
contract:

1. **ownership**, 2. **mode**, 3. **modification time**.

Linux clears the set-user-ID bit of a non-directory on every `chown`, and the
set-group-ID bit of a group-executable one, whatever the caller's privilege and
even when the ownership does not actually change. Writing the mode first would
publish `04755` as `0755`, fail verification, and then wedge rollback on a state
neither side recorded. Ownership therefore goes first, and the mode is
additionally rewritten whenever an ownership change was issued and the desired
mode keeps a bit that a `chown` can clear — even though the mode already
matches — so the final `chmod` is never skipped. The timestamp goes last,
because `chmod` and `chown` update `ctime` alone and a later repair of either
must not disturb a timestamp that is already correct.

A `chown` of a non-directory also drops its `security.capability` attribute.
This layer does not model extended attributes and could not restore one, so a
`set_metadata` intent that would change the ownership of a non-directory
carrying that attribute is refused during preflight (`metadata_unsupported`)
and re-checked immediately before the `chown`. Publication steps are
unaffected: they replace the inode outright, the old inode with its attributes
is held in the backup area until the transaction verifies, and the newly staged
inode never had any.

Each of the three writes is a separate crash-injection boundary
(`metadata_chown`, `metadata_chmod`, `metadata_utimens`), so power loss between
any two of them is a modeled, injectable state rather than an unknown one.

## Reachable intermediate states

Neither metadata application nor directory creation is atomic, so power loss
can leave a target in a state that is neither the recorded old state nor the
recorded new one. Refusing every such state would wedge a transaction on its
own half-finished work; adopting whatever is found would silently accept an
external change. This layer does neither: for each step it states the exact,
closed set of states the transaction itself could have produced from its last
durable boundary, and accepts nothing else.

Every member of that set keeps the identity the recorded states share — kind,
content digest, link target, and, wherever an inode survives the transition,
the bound inode, the plan's device, and a link count the transaction can
account for — so an entry an external writer replaced, truncated, retargeted,
or linked is still `external_modification` and still becomes
`recovery_required`.

| Step shape | States the transaction itself can have left | Window |
| --- | --- | --- |
| `set_metadata`, and `create_directory` on an existing directory | the bound inode with the ordered metadata chain below | the step's metadata boundary |
| `create_directory` over nothing or over a non-directory | an **empty** directory whose mode and ownership are whatever `mkdir` produced under the caller's umask and the parent's set-group-ID bit | the step's publication and metadata boundaries |
| a transition that crosses the directory boundary in either direction | the path momentarily **empty**, between the removal and the creation that replaces it | the step's publication boundary, and the whole restoration |
| while restoring: a recorded directory | an **empty** directory it re-created from the journal, on a different inode from the bound one or where the journal records that this step already removed the recorded one | the restoration |
| while restoring: a recorded symbolic link | the exact recorded target on a fresh inode whose timestamp has not been written back yet | the restoration |

### Several steps on one path

A plan may touch one path more than once — a file published and then re-moded,
a documentation directory two packages both ship. Preflight models each path
once, so the second step's recorded precondition is exactly the first step's
recorded desired state, and refusing such a plan would refuse the most ordinary
shape there is.

A desired state carries no inode, because no plan can predict one. Treating
that zero as "any inode" would admit an entry an outside writer substituted and
would break the directory and link-count reasoning that depends on knowing
which inode is which; treating it as "no inode" would wedge every interrupted
metadata write on a path a plan touches twice. Neither is necessary: the
producing step's verified boundary bound the entry it published, so a
precondition the plan produced resolves to that bound inode.

| Precondition | Resolves to |
| --- | --- |
| an absence | nothing to bind |
| a state preflight observed | the inode preflight observed |
| a state an earlier step produces, once that step verified | the inode that step's verified boundary bound |
| a state an earlier step produces, before that step verified | nothing, and the step provably has not run |
| a state observed where the platform reports no inode number | the degenerate zero, which is the structural comparison such a platform has always had |

The last row keeps a platform without inode numbers exactly as strict as it was
and no stricter: zero matches only zero, so an entry whose inode *is* reported
is still refused, and a directory is never accepted as a re-creation on the
strength of being "different from nothing".

The row before it is a proof, not a fallback. The forward pass reaches a step
only after every earlier step verified, and a verified boundary binds its entry
in the same record that publishes it, so an unbound precondition means the step
never started. A crash before that record therefore cannot let a dependent step
advance. During a rollback such a step is skipped rather than restored over —
its own reversal is nothing, and the path is owed the state the producing step
gives back on its own turn — and the skip additionally requires the step to
still be at its prepared boundary and to sit past the point the forward pass
can have reached, so a platform that reports no inodes fails closed instead.

The bound inode is then what the recorded old state is compared against.
An entry of the same kind holding the same bytes with the same metadata is not
the recorded entry when it is a different inode, which is exactly what an
external replacement looks like, so a substitution made after the producing
step verified is `recovery_required` in both directions rather than a
precondition the next step happily writes onto.

A binding is evidence about what this transaction published, not about what is
at the path now, so it survives that step's own restoration: the backup and
staging links the plan took on that inode are still links on it until the
workspace is released, and the [link-count model](#link-counts-the-transaction-changes-itself)
attributes them by that inode alone.

### The window an intermediate is accepted in

A state is only this transaction's own work if this transaction could have been
making it at the moment it was observed, so every row above is bounded by the
journal rather than by shape alone. The engine accepts an intermediate only
while the boundary that produces it is open: every earlier boundary of that
step is durable, the boundary itself is not, and the transaction has durably
reached a stage in which it mutates the root at all. A step past the point the
forward pass can have reached has done nothing, and a step that published the
boundary has finished it.

A momentarily empty name is the sharpest case. `mkdir` cannot take a name a
non-directory holds and a directory cannot be renamed over, so a transition
that crosses the directory boundary — in either direction — removes what is
there before it creates what replaces it. That is the only reason this layer
ever leaves a name empty, and it is symmetric: the forward pass removes the
recorded old entry before publishing the new one and the restoration removes
the new entry before putting the recorded old one back, so `regular →
directory`, `symlink → directory`, and `directory → regular` are all resumable
forwards from the unlink and backwards from the `rmdir`. An absence anywhere
else — on a step whose publication removes nothing, such as a metadata step or
a directory creation that found its directory already there, or on a step that
has not yet published the boundary before its own publication — is somebody
else's removal and stays `external_modification`.

Where a transition has no durable boundary between the start of the step and
its removal, as when a symbolic link is replaced by a directory and there is no
content to back up, the window opens with the step itself. Nothing foreign is
adopted there: the only state accepted is absence, the plan authorized removing
exactly that entry, and the recorded old symbolic link is restorable from the
journal either way.

The metadata chain from a state `from` toward a state `to` is exactly the
prefixes of the ordered writes: `from` itself; ownership applied with the
privileged bits still present or already cleared; the mode rewritten; and
finally the timestamp. It is at most a handful of combinations, and it is
closed: once the transaction has turned around, an interrupted restoration is
reachable from wherever the forward pass stopped, and walking the same ordered
writes back to the recorded old metadata from every member adds nothing new,
because every restored state already carries the recorded ownership and so can
issue no further `chown`.

The chain is one member of the set rather than the whole of it, so a state it
refuses is still offered to the rest. That matters wherever the bound number
survives a re-creation: a symbolic link restored from the journal onto a reused
inode number holds the recorded target with its timestamp still owed, which is
the recorded old state part way through being republished and not a metadata
combination any in-place write could have produced.

A directory is only accepted as the transaction's own creation while it is
still empty, which is exactly the condition under which removing it restores
the recorded absence; a directory that has gained an entry is refused and
becomes `recovery_required`. While restoring, a re-created directory is
recognized by evidence that the entry the bound inode named is no longer at
the path: either the directory carries a *different* inode, or the journal
itself records that this step already replaced the recorded directory, or is
inside the publication boundary that removes it. Both are the same statement,
and the second is the one a filesystem that reuses inode numbers needs —
`ext4` hands a just-freed number straight back out, so the directory a
restoration re-creates a moment after removing the file that replaced it very
often carries the recorded number again, and requiring a difference would wedge
an ordinary rollback on the transaction's own work. It reaches no further: it
is admitted only on a step whose own transition crosses the directory boundary
and therefore re-creates one, and only while the directory is still empty.
Either way an inode must actually be bound: a recorded directory nothing bound
an inode to admits no directory at all, because "different from nothing" would
accept any empty directory an outside writer left at the path. Every accepted
intermediate is resolved by finishing or undoing the boundary that produced it
— the writer recomputes the components that still differ from what it observes
— never by adopting it as the new truth. Verification at the end of the step is
still an exact comparison with the desired state.

Every boundary is idempotent. A retry compares the observed state to the
recorded expectation, to the recorded desired state, and to that step's closed
reachable set; anything else is `external_modification` and never a guess.

### Link counts the transaction changes itself

A link count is part of an inode's identity: it is what refuses an entry that
gained or lost a hard link behind the transaction's back. The transaction moves
link counts itself, though, and demanding the recorded count back would wedge
recovery on its own work. Every direct subdirectory it creates or removes moves
the containing directory's count by one through the subdirectory's own `..`,
and every hard link it stages, publishes, or holds as a backup adds one to the
inode it links.

Neither is a guess. The plan names the entries that do it and the progress log
says how far each of them got, so the engine computes the exact set of counts
this transaction can have produced on the bound inode and refuses everything
outside it. The set is a closed interval, because each contributing entry moves
the count by exactly one and does so independently:

| Contribution | Delta | Live from | Live until |
| --- | --- | --- | --- |
| a direct subdirectory this plan creates | +1 | that step's publication boundary | that step is recorded reverted |
| a direct subdirectory this plan removes | −1 | that step's publication boundary | that step is recorded reverted |
| a hard link this plan stages from the inode | +1 | that step's staging boundary | that step is reverted **and** the workspace is released |
| a backup this plan captures of the inode | +1 | that step's backup boundary | the workspace is released |

Each contribution is *certain* when its boundary is durable, *possible* when
the step is inside that boundary, and absent otherwise; a possible contribution
widens the interval by one instead of moving it. Rollback is modeled the way it
actually runs — in reverse index order — so while a step is being restored every
later step has already given its links back and every earlier one still holds
them. Workspace links outlive the step that made them, because staging and
backup entries are released only after the whole transaction resolves.

A backup counts only against the inode it actually preserves, and so does a
hard link. Both name whatever the path they were taken from was holding at the
moment they were taken, resolved exactly the way a precondition is — by the
boundary that bound it — so a link or backup taken after some intervening step
of the same plan republished that path is attributed to the inode that step
published and never to the one under examination, and one whose own
precondition nothing has bound yet is attributed to nothing at all.

The baseline is the count the boundary that bound the inode observed, so a
contribution taken *before* that boundary is already inside it: what is open
for those is whether the link has since been given back, not whether it was
ever made. Counting such a link twice would move the whole interval up by one
and admit exactly one outside hard link.

The bound count itself always stays admissible: it is the count a boundary
actually observed, and a filesystem that does not maintain directory link
counts reports it unchanged however many subdirectories a plan makes.
Everything else is checked against the interval, so an outside hard link on a
file this plan is re-moding, or an outside subdirectory in a directory this
plan is re-moding, is one link past what the transaction can account for and
becomes `recovery_required`. The count is only ever consulted after the bound
inode number itself matched, so it never admits a different inode wearing the
recorded identity.

What the model cannot derive, preflight refuses before anything is mutated. A
journal records paths, not the inodes two paths may share, so a link staged
from one name for an inode whose other name the plan also touches would change
a count nothing in the journal accounts for. Every path the plan models —
targets and the sources of copies and hard links alike — is therefore
registered by inode, and a second name for an inode the plan already models is
`path_alias` at preflight rather than a wedged recovery afterwards.

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
neither the recorded old state, nor the recorded new state, nor that step's
closed set of reachable intermediate states publishes `recovery_required`
durably, tells the root-operation attempt through `Attempt.requireRecovery`,
and refuses every further mutation until an operator resolves it. A step whose
precondition an earlier step of the same plan owes and no boundary ever bound
is skipped instead: it provably never ran, and the path is restored by that
earlier step's own reversal further down the same reverse pass. `clear` is
refused unless the stage is `completed` or `rolled_back`.

Every step that writes metadata onto the inode it finds — a `set_metadata`
step, and a `create_directory` step at its metadata boundary — proves its
recorded precondition first, because unlike a publication it never takes the
target name over and would otherwise stamp the plan's mode, ownership, and
timestamp onto whatever entry now occupies the name. The precondition it
accepts is the recorded old state on the inode bound to it, the recorded new
state, or one of that step's own reachable intermediates: the ordered metadata
combinations on the bound inode, or the still-empty directory its own
publication boundary created. Never an unrelated mode, ownership, or timestamp;
never a different inode carrying the recorded metadata; and never a directory
that already holds entries this transaction did not put there.

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
primitive — including each of the three metadata syscalls separately — and
proves that the resulting root is exactly the old state, exactly the new state,
or a durable recovery requirement; the harness fails if an injected fault never
fires. The whole boundary matrix is also run underneath a set-group-ID parent
directory with a real second group, so `mkdir` and the staging area publish
ownership that matches neither recorded state and every self-created
intermediate has to be recognized rather than refused. Publication and
`set_metadata` are proven end to end for `04755` and `02755` across a real
ownership change, in both directions, with the exact mode, uid, and gid
asserted after application and after rollback; the ordering contract itself is
additionally proven without needing a second group, because a `chown` clears
the bits even when it does not change the owner.

The write-ahead log is torn deliberately at every length from one byte to one
byte short of a whole record, on transactions that recover backwards and
forwards, and each case must replay to the last complete record, repair the
file, reach a terminal stage, report the same stage through `inspect`, and
clear. A whole extra record, a whole record plus a torn one, two whole
records, and a replayed copy of the durable tail must all stay corrupt or
stale rather than being repaired away, a stale writer must still be refused
when the tail is torn, and power loss during the repair itself must leave the
same torn tail for the next pass.

A transition that crosses the directory boundary is interrupted at each of its
own boundaries — before the unlink, between the unlink and the `mkdir`, before
the metadata, and before the parent sync — for a recorded regular file and for
a recorded symbolic link, and each interruption is proven both ways: resumed
forward with `apply`, which must finish the transition, and resolved backwards
with `recover`, which must put the recorded file or link back. A target that
disappears before the step could have removed anything, one that disappears on
a step whose publication removes nothing, and a directory removed after this
transaction created it must all stay `external_modification`.

Link counts the transaction changes itself are proven end to end and as a
model: a metadata step whose inode a later step hard-links, and one whose
directory the plan fills with a subdirectory, must both survive a partially
applied or partially restored metadata boundary, while one extra hard link or
one extra subdirectory that this plan does not account for must still become
`recovery_required`. The reachable interval itself is enumerated directly
across staging, publication, backup capture, reverse-order rollback, and the
workspace release, on both sides of the boundary that bound the count, and a
backup taken across an intervening replacement of the same path must be
attributed to the inode it actually preserves.

Several steps on one path are proven at every boundary the second step passes
through, including each metadata syscall on its own, twice per boundary: a
resumed forward pass must finish the transaction, and a fresh process must roll
it back to the exact recorded entries, inode included. Rollback is additionally
interrupted inside each restoration boundary of such a chain and resumed. A
repeated directory step on a populated directory must re-mode the directory
that is there, and two packages shipping the same documentation directory must
produce a satisfied second step rather than a refusal. An outside writer that
substitutes a same-kind, same-content, same-metadata inode after the producing
step verified must be `recovery_required` in both directions, and a step whose
producing step never verified must be skipped rather than restored over.

The write-ahead format is proven column by column: a bound identity round trips
at every width, a record that binds an entry is exactly as long as one that
does not, and a forged record that chains correctly but binds an entry on a
stage record, on an unverified boundary, on a removal, on another device, or
without a link count is `error.ProgressCorrupt` — as is editing a bound
identity without rebuilding the chain. The checked-in fuzz corpus carries a
complete log of the new format and is compared byte for byte against the
canonical encoding, so a format change is a failing test rather than a corpus
that quietly stops parsing.

Text the document cannot carry is proven adversarially for every field kind
and every way UTF-8 can be malformed: an isolated continuation byte, overlong
two- and three-byte encodings, both ends of the surrogate range, the first code
point above U+10FFFF, a lead byte no code point uses, and a sequence truncated
at every width. Each one is driven through a target path of every intent kind,
a copy source, a hard link source, a symbolic-link literal, a symbolic link the
root itself holds, a lowered database path, a caller-chosen database directory,
an archive path, an archive link literal, an archive hard-link target, an
exact-lock schema, and a plan step assembled outside preflight, and each must
be `invalid_encoding` with no journal, no log, and no workspace entry left
behind. Valid non-ASCII text at every sequence width must do the opposite: plan,
publish, round trip through the canonical document byte for byte, and resolve
to an entry under the root. The checked-in journal corpus is spelled the same
way, so a mutated seed lands inside a multibyte sequence.

The suite also covers disk-full, short-write, `fsync`, `rename`, `unlink`, and
`link` failures, external modification and symbolic-link swaps between
preflight and publication, an external mode change and an inode substitution
that must never be mistaken for the transaction's own intermediate state,
corrupt, truncated, torn, replayed, and unknown-schema journals and logs, stale
and mismatched attempts, a lost root lock, cancellation, restart recovery
through a freshly opened engine, database publication and rollback against a
real `var/lib/dpkg` generation, and allocation failure at every allocation of
preflight, decode, replay, and reopening. Every test uses a disposable
alternate root.

The scenarios that need a second group or a privileged caller report
`SkipZigTest` where the environment cannot provide one; the ordering contract,
the reachable-state model, and the whole write-ahead log suite run everywhere.

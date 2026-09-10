# Native package database

`debz.package_database` and `debz.package_database_changes` implement the
native, bounded, typed model of the Debian package database under
`var/lib/dpkg` required by roadmap item 7 of the
[native transaction engine v1 contract](native-transaction-engine-v1.md).

The layer does two things and nothing else:

1. import one captured database generation into an owned typed model, or fail
   closed with an exact typed diagnostic; and
2. compile typed edits into one deterministic, fully serialized publication
   plan bound to that exact generation.

Neither module opens, reads, or writes a file. Callers supply a captured
`Snapshot` in which every consumed file - `status`, `status-old`, `arch`,
`diversions`, `statoverride`, shared and named trigger files, every `info` entry, and every
`updates` fragment - carries the bytes plus the entry kind and mode the reader
observed. The returned `Plan` is a complete list of file intents that owns its
own bytes, so a caller mutating or freeing its buffers afterwards cannot change
what the plan publishes. Durable
publication - root-anchored no-follow descriptors, staging, fsync, atomic
rename, parent-directory fsync, `updates/` journalling, and crash recovery -
belongs to the root-filesystem and mutation layers. Attempting a partial
multi-file live-root transaction here would be unsafe, so this layer refuses to
do it. Unpack rules, lifecycle sequencing, conffile decisions, and trigger
processing are also out of scope; they consume this model.

## Covered surfaces

All paths are relative to `var/lib/dpkg` inside the selected root.

| Path | Behavior |
|---|---|
| `status` | Every field parsed; unknown well-formed fields and field order retained verbatim; identity, version, state, flags, and conffile digests typed. |
| `status-old` | Parsed and bounded; retained as previous-generation evidence (digest, size, record count). |
| `updates/` | Empty accepted. Nonempty is interrupted publication: `require_empty` fails import, `import_for_recovery` types the fragments as recovery evidence. Planning always refuses. |
| `arch` | Unique validated foreign architectures. The native architecture comes from the authorized request and may not be listed. |
| `info/format` | Must be format `1` when present. |
| `info/*.list` | Bounded canonical absolute paths, including dpkg's `/.` root entry; duplicates rejected; ownership index published. |
| `info/*.md5sums` | Lowercase MD5 plus canonical relative as-shipped payload paths. Partial `Replaces` may leave entries that are no longer in the live `.list`, as dpkg does. |
| `info/*.conffiles` | Declared conffiles, each of which must appear in the package's status `Conffiles`. |
| `info/*.triggers` | `interest`, `interest-await`, `interest-noawait`, `activate`, `activate-await`, and `activate-noawait` declarations. |
| `info/*.{preinst,postinst,prerm,postrm}` | Regular executable files with safe modes; size, mode, and SHA-256 recorded. |
| `info/*` (other) | Retained as opaque evidence (owner, mode, size, SHA-256). Names must still be package qualified. |
| `triggers/File` | File-trigger interests with `package` or `package/noawait` listeners. |
| `triggers/<name>` | Named interests with the same listener grammar; each bounded regular file contributes generation evidence. |
| `triggers/Unincorp` | Deferred activations with ordered awaiting-package tokens and explicit `-` no-await markers. |
| `diversions` | Complete three-line records typed; malformed records fail. |
| `statoverride` | Bounded user, group, mode, and path records typed; malformed records fail. |

Co-installed `Multi-Arch: same` instances normally require one version. A
bounded unpack transaction may temporarily contain an `unpacked` incoming
version beside an installed sibling's previous version; fully installed
siblings with differing versions remain invalid.

Info file names must be `package.suffix` or `package:architecture.suffix` and
must resolve to exactly one status record. Unqualified names that match more
than one instance are ambiguous and rejected rather than guessed.

The shared `triggers/Lock` is synchronization infrastructure, not a named
interest file or consumed database generation. `File` and `Unincorp` retain
their dedicated formats. Other trigger-directory entries must satisfy the
named-interest path, grammar, kind, mode, and size bounds; they are not silently
ignored.

## Validation

Import rejects, before any change can be planned:

- non-DEB822 status syntax, duplicate fields, and bound violations;
- invalid package names, architectures, versions, states, flags, priorities,
  `Multi-Arch` values, installed sizes, and conffile records;
- repeated field names and field values that would not survive canonical
  serialization unchanged: newlines, carriage returns, NUL, other C0 controls,
  `DEL`, and leading whitespace on a field's first line. Tabs inside a value
  and indented continuation lines remain ordinary content;
- repeated `Package`/`Architecture` identities and co-installed instances that
  are not `Multi-Arch: same` at one identical version;
- architectures that are neither native, `all`, nor listed in `arch`;
- ownership lists with traversing, relative, duplicated, control-character,
  unterminated, or over-long entries;
- checksums with a bad separator, uppercase hex, absolute paths, duplicates, or
  paths outside the package inventory;
- conffiles absent from the ownership list and declared conffiles absent from
  the status record;
- states that must own an ownership list but do not, and `not-installed`
  records that still own one;
- `triggers-awaited` or `triggers-pending` states without the matching status
  field, and trigger fields that contradict the state;
- file or named interests that the owning package does not declare, trigger
  records naming unknown packages, and malformed trigger grammar;
- database entries that are not regular files, setuid, setgid, or
  world-writable modes, and non-executable maintainer scripts, for top-level
  files, `info` entries, and `updates` fragments alike;
- nonempty `updates/`, unsupported `info/format`, malformed diversions and
  statoverrides, and any file exceeding a configured bound.

Every diagnostic carries the surface, code, database-relative path or info
entry name, package, and line. Diagnostics borrow the caller's snapshot, as
does the imported database, so the snapshot must outlive both.

## Normalization

Ordering and spelling are preserved wherever dpkg treats them as significant:
status record order, field order, unknown fields, ownership order, checksum
order, and trigger order all round-trip byte for byte. Only two documented
normalizations exist, and both are format-level rather than semantic:
continuation lines are republished with dpkg's single leading space, and a
field with an empty first value line is republished as `Name:` without trailing
whitespace. Canonical writers exist for every modeled surface, so a healthy
imported generation re-serializes to identical bytes.

## Generation evidence

`packageDatabaseGeneration` hashes the complete consumed generation: every
present file path, entry kind, mode, size, and content digest, sorted by path
under a versioned domain separator. Because kind and mode are captured rather
than assumed, a root whose file was replaced by a symbolic link or whose mode
changed produces a different generation even when the bytes are identical. `verifyPackageDatabaseGeneration` compares
a freshly captured snapshot against an imported database and reports
`external_generation_change`, so an authorization can never survive an external
database change between preflight and mutation.

## Staged change sets

`planPackageDatabaseChanges` compiles typed changes into a `Plan`:

- `put_package` publishes a complete record plus every modeled info file it
  owns. A `null` component means the file must not exist afterwards; it never
  means "keep whatever is there".
- `set_state` republishes only the `Status` field of an existing record.
- `put_file_list`, `put_md5sums`, `put_trigger_declarations`, and `remove_info`
  edit a single info surface.
- `remove_package` purges the record and every info file the package owns.
- `set_trigger_state` republishes the shared and named trigger surfaces,
  including explicit removals of obsolete named files.
- `set_foreign_architectures` republishes the architecture surface.

The resulting model is validated with exactly the same rules import uses, so a
plan can never publish a database that would fail to import. Trigger state,
foreign architectures, ownership, checksums, conffiles, and declarations are
validated once, in that shared model validation, rather than separately per
entry point. Every produced file is then checked
against the importer's own bounds before a plan is returned. Planning fails
closed on unknown packages, more than one change per subject, impossible state
transitions, unsafe or non-executable scripts, invalid paths, checksums outside
the accepted checksum grammar, bound violations, interrupted publication in
`updates/`, and any
diversion or statoverride that covers a package or path being changed. Mutating
diversions and statoverrides is not supported in v1.

A change that would move a package's info files between the `name` and
`name:architecture` spellings also fails closed when the package still owns
retained unmodeled info files, because their bytes are not part of the model
and renaming them would orphan or discard them.

Because a status field value comes from the caller in a staged record, it is
validated as serializable before it can reach the model or a writer: a value
containing a newline could otherwise close the paragraph and append forged
package records to the published status file. The produced `status` document is
additionally re-parsed with the importer's DEB822 limits and must contain
exactly the intended number of package records. Status files are bounded that
way rather than by the line bound used for `info` and trigger files, so any
status that imports - including fields far longer than one database line - can
always be republished.

Write order is deterministic: `status-old` is copied from the current `status`
first, then info files sorted by path, then `arch` and the shared/named trigger
surfaces, and finally `status`, which publishes the new generation
last. Each intent carries its exact bytes, SHA-256, and mode; `copy` intents
carry the expected source digest instead of bytes. The plan digest binds the
base generation and every ordered intent, and `base_status` plus
`resulting_status` identify the exact previous and next status generations.

## Deferred integration

The following are deliberately outside this pure database model:

- capturing a `Snapshot` through root-anchored, no-follow descriptors, and
  applying a `Plan` durably with staging, fsync, and atomic rename;
- lifecycle, unpack, conffile, and trigger semantics that decide which changes
  to stage;
- mutation of `diversions` and `statoverride`, which currently fail closed when
  they cover a changed package or path.

## Cost

Import, validation, and planning are linear in the number of database entries.
Membership and uniqueness questions - ownership lookups, checksum inventory
membership, duplicate paths, conffiles, checksums, declarations, interests,
deferred activations, architectures, and package identities - all use bounded
reusable hash indexes rather than repeated scans, and diversion or statoverride
coverage is indexed once per plan instead of per changed package.

## Tests

`src/package_database.zig` and `src/package_database_changes.zig` carry the
suite: healthy-root import of every surface, byte-exact canonical writer
round-trips, unknown-field preservation, multiarch consistency, conffiles,
triggers, and maintainer scripts, the malformed and corrupt matrix,
interrupted-publication and external-generation evidence, deterministic plan
ordering and digests, purge, state transitions, and fail-closed change sets.
Plans are applied to an in-memory root and re-imported, so every planned
generation is proven importable.

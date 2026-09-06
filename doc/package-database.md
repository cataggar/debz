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
`Snapshot`, and the returned `Plan` is a complete list of file intents. Durable
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
| `info/*.md5sums` | Lowercase MD5 plus canonical relative payload paths, each of which must be owned by the package. |
| `info/*.conffiles` | Declared conffiles, each of which must appear in the package's status `Conffiles`. |
| `info/*.triggers` | `interest`, `interest-await`, `interest-noawait`, `activate`, `activate-await`, and `activate-noawait` declarations. |
| `info/*.{preinst,postinst,prerm,postrm}` | Regular executable files with safe modes; size, mode, and SHA-256 recorded. |
| `info/*` (other) | Retained as opaque evidence (owner, mode, size, SHA-256). Names must still be package qualified. |
| `triggers/File` | File-trigger interests, including dpkg's `/`-prefixed noawait spelling. |
| `triggers/Unincorp` | Deferred activations and their awaiting packages. |
| `diversions` | Complete three-line records typed; malformed records fail. |
| `statoverride` | Bounded user, group, mode, and path records typed; malformed records fail. |

Info file names must be `package.suffix` or `package:architecture.suffix` and
must resolve to exactly one status record. Unqualified names that match more
than one instance are ambiguous and rejected rather than guessed.

## Validation

Import rejects, before any change can be planned:

- non-DEB822 status syntax, duplicate fields, and bound violations;
- invalid package names, architectures, versions, states, flags, priorities,
  `Multi-Arch` values, installed sizes, and conffile records;
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
- file-trigger interests that the owning package does not declare, trigger
  records naming unknown packages, and malformed trigger grammar;
- database entries that are not regular files, setuid, setgid, or
  world-writable modes, and non-executable maintainer scripts;
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
under a versioned domain separator. `verifyPackageDatabaseGeneration` compares
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
- `set_trigger_state` and `set_foreign_architectures` republish the shared
  trigger and architecture surfaces.

The resulting model is validated with exactly the same rules import uses, so a
plan can never publish a database that would fail to import. Planning fails
closed on unknown packages, more than one change per subject, impossible state
transitions, unsafe or non-executable scripts, invalid paths, checksums outside
the inventory, bound violations, interrupted publication in `updates/`, and any
diversion or statoverride that covers a package or path being changed. Mutating
diversions and statoverrides is not supported in v1.

A change that would move a package's info files between the `name` and
`name:architecture` spellings also fails closed when the package still owns
retained unmodeled info files, because their bytes are not part of the model
and renaming them would orphan or discard them.

Write order is deterministic: `status-old` is copied from the current `status`
first, then info files sorted by path, then `arch`, `triggers/File`,
`triggers/Unincorp`, and finally `status`, which publishes the new generation
last. Each intent carries its exact bytes, SHA-256, and mode; `copy` intents
carry the expected source digest instead of bytes. The plan digest binds the
base generation and every ordered intent, and `base_status` plus
`resulting_status` identify the exact previous and next status generations.

## Deferred integration

The following are intentionally not implemented here and are tracked by later
roadmap items:

- capturing a `Snapshot` through root-anchored, no-follow descriptors, and
  applying a `Plan` durably with staging, fsync, and atomic rename;
- lifecycle, unpack, conffile, and trigger semantics that decide which changes
  to stage;
- mutation of `diversions` and `statoverride`, which currently fail closed when
  they cover a changed package or path.

## Tests

`src/package_database.zig` and `src/package_database_changes.zig` carry the
suite: healthy-root import of every surface, byte-exact canonical writer
round-trips, unknown-field preservation, multiarch consistency, conffiles,
triggers, and maintainer scripts, the malformed and corrupt matrix,
interrupted-publication and external-generation evidence, deterministic plan
ordering and digests, purge, state transitions, and fail-closed change sets.
Plans are applied to an in-memory root and re-imported, so every planned
generation is proven importable.

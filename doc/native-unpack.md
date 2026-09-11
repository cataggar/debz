# Native unpack planning and data-only materialization

Roadmap item 10a is a planning slice only. It does not execute an unpack, write a
journal, mutate an install root, recover an interrupted operation, or release
cleanup state. Experimental core native execution is a separate item-15b
integration described in [Native recovery and provenance](native-recovery.md).

Item 10b adds a private data-only materialization adapter and an executable
reference-`dpkg` comparison for install, upgrade, downgrade, and reinstall.
The planner itself remains descriptive; actual execution and its bounded
acceptance gate are described below.

Item 11 adds an explicit opt-in conffile-unpack capability and private
script-free configure/remove/purge adapters. The default item-10b path retains
its existing conffile and removal handoffs. The phase contract and real-dpkg
matrix are described in [Native conffile and removal acceptance](native-conffiles.md).

The implementation is `src/native_unpack.zig`. Its exported surface is limited
to immutable descriptive types and side-effect-free helpers:

- `Plan`, `PackagePlan`, `PlannedPath`, `FilesystemChange`, `Removal`, and
  `Displacement` describe the reviewed outcome;
- `Handoff`, `DeferredItem`, `Diagnostic`, and their enums describe why later
  lifecycle or integration work is required;
- `Ownership`, `OwnedEntry`, `indexOwnership`, and `relativeListPath` provide
  the bounded ownership index used by the planner;
- `planDigest` provides the deterministic digest of an already-built plan; and
- `fuzzOwnership` is a side-effect-free fuzz boundary.

There is deliberately no public `plan`, `apply`, `execute`, `recover`,
`release`, database-capture, journal-writer, or root-operation capability. The
private planner is exercised by executable Zig unit and fuzz fixtures so later
roadmap items can integrate it only after they supply the missing execution
and recovery authority.

## Inputs revalidated by the private planner

The planner consumes a compiled native transaction program, exact archive
bytes, one complete package-database snapshot, and read-only observations from
a disposable or otherwise isolated root.

The caller must keep that root stable for the planning pass. Pinned observations
detect the changes described below, but do not provide an atomic whole-root
snapshot or isolation from an equally privileged concurrent writer. A plan
digest identifies descriptive evidence; it is not execution authority. The
10b adapter requires its fixture root to remain isolated from planning through
publication. Later production integration must supply and enforce the
execution lock/isolation contract before mutation.

Archive callers provide bytes, not an application inventory. For every program
artifact, the planner:

1. checks package name, version, architecture, declared size, and SHA-256;
2. rebuilds the bounded `archive_application.Model` from the bytes;
3. verifies the model's deterministic application digest against the program;
   and
4. copies every returned fact into plan-owned storage, then destroys the
   rebuilt model before returning.

The package database is likewise supplied as snapshot bytes, not as a
caller-built `package_database.Database`. The planner imports the snapshot
itself, checks its generation and package count against the program, rejects
pending update fragments, and builds ownership from the imported `info/*.list`
records. The resulting `package_database_changes.Plan` is data only; the private 10b
adapter separately lowers it into root-mutation intents.

All scans have explicit limits: distinct packages and artifacts, aggregate
archive/model bytes, paths, filesystem changes, removals, work units, deferred
items, case aliases and case-index bytes, trigger-index bytes, archive parsing,
database import, and database-change planning. Compressed bytes and distinct
inputs are checked before rebuilding;
the archive parser applies its own per-input limits; one live-budget allocator
is passed through decompression, control parsing, relationship AST
construction, model arrays, strings, provenance, and the per-model path and
hard-link indexes, so peak model memory cannot exceed the transaction bound
during construction; and planner-owned paths/changes are charged before
append. Limit exhaustion is a refusal, never a partial plan.

## Deterministic plan

A successful plan contains two independent descriptive halves:

- `filesystem` is ordered as obsolete removals deepest first, directories
  parents first, and payload files/links in archive order; and
- `database` is the final `package_database_changes.Plan`, including status,
  `.list`, `md5sums`, architecture, and other modeled database writes.

A `FilesystemChange` identifies an artifact and archive entry or describes a
link/directory/removal. It carries no root handle, file descriptor, callback,
lock, journal, or executable function. Regular-file payload bytes remain bound
by artifact, archive-entry index, and digest instead of being exposed as an
untrusted write primitive.

Every returned string and nested record is copied into the plan's own arena.
The imported database, rebuilt archive models, source program, snapshot bytes,
and temporary ownership index may all be destroyed immediately after planning.

The ownership checklist is explicit:

- the plan arena owns every filesystem path/source/target, package identity,
  version, stem, configured version, planned/archive/absolute path, previous
  symlink target, removal, list entry, checksum path, resolution identity,
  alias and its pinned inode evidence, case alias, displacement,
  retained-directory path/evidence, and pending-configuration identity;
- `package_database_changes.Plan` owns its database paths and bytes in its own
  arena;
- `Handoff` owns every deferred-item string and `Refusal` owns every top-level
  and nested database diagnostic string; and
- no returned field borrows an archive model, ownership rewrite, program, or
  snapshot.

`planDigest` covers program and authorization digests, aliases, ordered
filesystem changes, package identities, operations, metadata, content digests,
link targets and sources, ownership resolutions, removals, displacement
records, lists, checksums, and the final database-plan digest. Equal reviewed
inputs produce equal plan digests across processes and architectures.
The digest encoding is field-tagged and length-delimited and covers complete
previous-root observations, presence bits, publish/synthesized/alias decisions,
case aliases, removals with their exact prior state, retained-directory
evidence, displacements, and database writes. Allocation peak, compared-byte,
path-count, and work-unit telemetry is intentionally excluded: allocator/ABI
behavior may change those counters without changing the reviewed plan.
Handoffs and refusals carry corresponding digests over every diagnostic or
deferred-item field.

An upgrade records the version most recently configured. A previously
installed package contributes its installed version; an already-unpacked
package preserves its explicit scalar `Config-Version`. An absent field means
the package has never been configured, including repeated unconfigured unpack,
and remains absent. A malformed field is handed off rather than fabricated.

## Package identity and ownership

Package identity is always `(name, architecture)`. This prevents a foreign
architecture from being mistaken for the package generation being upgraded.
The ownership index is sorted by canonical root-relative path and owner index;
exact-owner queries are binary searches and descendant checks are bounded
forward scans.

For each claimed path, the planner records one disposition:

- `create` for an absent unowned path;
- `replace_unowned` for dpkg-compatible replacement of an unowned entry;
- `replace_same_package` for an earlier generation of the same identity;
- `replace_replaces` when the incoming package's exact, version-qualified
  `Replaces` authorizes the current owner;
- `replace_retired` when every current owner drops the path in the same
  authorized transaction;
- `share_directory` for legitimate directory co-ownership; or
- `share_multi_arch` for a `Multi-Arch: same` sibling with byte-identical
  effective content and metadata.

Every co-owner is evaluated before any displacement is recorded. A foreign
owner without an applicable `Replaces` or valid share is an ownership conflict,
even when another owner was authorized. `Replaces` fields containing
alternatives, architecture restrictions, or build profiles are invalid for
this slice and authorize nothing. Forced overwrite is handed off.

Installed `Multi-Arch: same` sharing requires both the database checksum and a
bounded no-follow read of the actual root object to match the payload's SHA-256
and effective mode, owner, group, and timestamp. A valid existing object
produces no physical change. Fresh sibling payloads are compared against each
other and produce exactly one physical file description. Coordinated sibling
upgrades are pre-indexed as one final claimant set, so agreeing v2 payloads
replace a shared v1 object exactly once regardless of program order. Symlink
targets and effective metadata participate in the same comparison. Hard-link
claims additionally bind the normalized regular source, group size, and
per-path role through an order-independent linear group commitment. A regular
source and hard-link member are not interchangeable merely because their bytes
match. Existing groups require simultaneously
pinned destination/source descriptors with equal device and inode and the
exact expected link count. The destination is read twice positionally while
both descriptors remain open, and both complete root-relative chains are
revalidated before return; no digest or change time from an earlier descriptor
open authorizes the share. Topology ambiguity, a same-sized content race, or an
external link is refused. The returned hard-link path carries both destination
and source `PreviousState`, and the semantic digest binds their identical
device/inode evidence.

All transaction claimants are validated even when an unchanged installed
`Multi-Arch: same` sibling remains. Once that sibling proves the exact desired
object and topology, it dominates publication: acted siblings update ownership
only and no redundant payload replacement is described.

When `Replaces` transfers a path, the plan records a `Displacement` and rewrites
only the surviving holder's `.list`, filtering that original ordered spelling
in place so `/.` and every unaffected alias spelling remain intact. Its
`.md5sums` remains the as-shipped manifest, matching dpkg's partial-displacement
behavior; it is not a live
ownership index. Incoming package publication still writes that package's new
manifest. If the holder would retain no real file, package-disappearance
lifecycle work is handed off rather than leaving a ghost record.

Installed checksum lookup is bound to the exact live `OwnedEntry.listed`
spelling. A stale `lib/x` checksum cannot override the checksum for a live
`usr/lib/x` entry after merged-`/usr` normalization; a relevant ambiguous or
missing exact checksum fails closed while unrelated stale manifest entries are
preserved.

Obsolete paths are decided only after every final transaction claimant is
known. A later claimant cancels another package's drop, every obsolete
directory that is a prefix of a final claim survives only when the coherent
root observation proves it is actually a directory, all retiring co-owners
produce one physical removal, and disappearance is evaluated from the final
ownership graph rather than program order. A retiring regular or symlink
ancestor is removed and replaced by a synthesized directory before its final
descendant; a different package may claim an exact path its acted owner
retires without an unrelated `Replaces`.

Every installed conffile is indexed independently of `info/*.list`, including
`config-files` records and `obsolete`/`remove-on-upgrade` entries. Merged-`/usr`
normalization is applied to the index. Any final claim, displacement, removal,
or ancestor transition touching one produces a conffile handoff before a
filesystem intent is built.

## Paths, aliases, and transitions

Archive and database paths use the existing bounded `root_fs.Path` grammar.
The planner additionally reserves `var/lib/dpkg` and every descendant from
payload claims; package data can never describe a write into the database it
is being planned against.

The fixed merged-`/usr` alias table covers `bin`, `sbin`, and the supported
`lib*` spellings. Only a root-observed link to the exact `usr/<name>` target
authorizes normalization. A foreign link is an alias escape. The original
archive spelling and normalized canonical path are both retained in the plan.

Directory claims may be co-owned. An existing directory is an ownership-list
update only: its administrator-selected metadata is not described as a write.
A newly published archive directory carries its archive modification time;
synthesized parents carry an explicit unspecified timestamp. When several
packages first create one shared directory, the earliest authorized program
claim supplies its physical metadata even though package output remains
canonically ordered. Replacing a directory with a non-directory is allowed
only after a bounded no-follow traversal proves the actual directory empty;
the ownership database is never treated as a complete view of its contents.
Synthesized parents are deterministic and emitted parent before child.

Each rebuilt model has one bounded path index. Regular content metadata,
SHA-256, and MD5 are resolved once, and every hard link reuses that effective
record. Chain/cycle/depth checks remain explicit even though the current
archive validator permits only an earlier regular target.

Item 10a has no authenticated casefold capability, so it indexes every prefix
of every final claim, synthesized ancestor, installed ownership path,
conffile, merged alias, and reserved database path. Distinct ASCII-folded
spellings, all non-ASCII payload/ownership spellings, and case-insensitive
variants of `var/lib/dpkg` are refused. Typed prefix requirements also reject
an exact non-directory where another final path requires a directory. Host
lookup behavior is never used as proof of target-root case semantics.
Folded keys are produced in bounded scratch storage, looked up before
allocation, and retained only once in planner-owned temporary memory. Repeated
shared prefixes therefore consume fixed case-index memory rather than growing
the returned plan arena.

Every root lookup error is a typed refusal; only a successful lookup returning
`null` means absence. A directory over a symbolic link is refused rather than
destructively replaced. Regular files are opened no-follow and read through a
pinned descriptor; metadata and bytes are accepted only when device, inode,
link count, size, mode, ownership, modification time, and change time are
stable and the pinned parent still names that inode. Linux symbolic links use
an `O_PATH|O_NOFOLLOW` descriptor plus `readlinkat(fd, "")` with the same
before/after proof. Directories are likewise pinned and name-revalidated before
and after a bounded listing; sorted member name/kind evidence is retained in
claimed paths, removals, or retained-directory records and covered by the plan
digest. Every pinned file, link, and directory also retains the selected root
and complete validated path, then re-resolves the entire no-follow chain before
and after observation; renaming an ancestor cannot leave a detached subtree
mistaken for the selected root.

One coherent directory observation is cached per canonical transaction path
for the planning pass, so thousands of claimants do not enumerate the same
directory repeatedly. Its metadata/change identity is revalidated through the
full root chain at the final lowering boundary immediately before return.
Directory entries and names are charged only on the initial bounded
observation.

Root comparisons have a transaction-wide byte budget. File digests
are never cached across descriptor opens, so inode reuse or coarse change-time
resolution cannot turn an ABA replacement into trusted old content.

Trigger planning first indexes package names to all `(name, architecture)`
identities and affected paths to every ancestor. Relevant per-trigger identity
sets are hash-based, globally work- and memory-budgeted, and stop immediately
at the deferred-item limit; irrelevant interests never expand package sets.

Obsolete removal accepts only coherently observed regular files, symbolic
links, and directories. FIFOs, sockets, devices, and unknown kinds are typed
refusals rather than generic unlink descriptions.

## Typed handoffs

With the default item-10b capability, the planner returns one complete
`Handoff` when the transaction needs work
owned by later roadmap items. Handoff items are deduplicated and deterministically
digested. Covered features include:

- conffiles and conffile decisions;
- maintainer scripts and configure barriers;
- trigger declarations, activations, pending trigger state, and triggers
  interested in removed or published paths;
- package removal and purge;
- package disappearance;
- held-selection changes;
- malformed prior `Config-Version` evidence for an unpacked upgrade;
- diversions, stat overrides, alternatives, and unmodeled package metadata;
- unmodeled `var/lib/dpkg` namespace entries;
- shared-root interoperability; and
- filesystem features a supplied observation cannot model safely.

A handoff is not a partial plan and has no mutation effect. In particular, a
conffile is never silently treated as ordinary payload, and a shared root is
never claimed safe merely because the caller requested native execution.

## Production availability

`transaction_engine.select(.native, ...)` always returns
`BackendUnavailable`, including when a generic executor is injected. The
legacy backend remains the default and selection never falls back after native
was requested.

The public `debz` additions are descriptive native-unpack aliases only. Apt,
product, repository, completion, and root-operation APIs remain unchanged.
The existing mutation engine additionally supports final nonzero directory
timestamps and ordered hard-link group replacement. These changes do not
enable a native production executor. Lifecycle, recovery/provenance
integration, experimental integration, and production cutover remain items
11–16.

## Data-only materialization acceptance (item 10b)

`zig build test-native-materialization` runs an internal native test driver
against actual `.deb` bytes and compares the resulting disposable root with
reference `dpkg --unpack`. The driver is not a production CLI/backend entry
point. It composes the planner with the existing root-operation and
root-mutation layer rather than interpreting plan fields in Python or copying
the reference result.

The private adapter reimports the root database, binds the archive bytes again,
uses the actual system root-operation lock, and lowers payload and database
changes into one existing mutation-engine plan. Database capture is no-follow
and limited to 256 MiB of aggregate live allocation, in addition to per-file
and entry-count limits. Archive models and database content remain owned
through apply. Successful application verifies payload and database state
before retiring the journal and active attempt; rolled-back operations retire
only resolved evidence, and recovery-required results retain it. The shared
lock inode and empty bookkeeping directories remain in place for subsequent
operations. Unexpected preparation failures retain the active attempt rather
than assuming every partial journal write was cleaned up.

Explicit archive-directory timestamps are published after child operations.
A newly materialized directory with timestamp zero is explicitly refused
before mutation because the current mutation journal uses zero to mean an
unasserted directory timestamp. The adapter does not silently substitute the
current time. This limitation, conffiles, scripts, triggers, and the other
typed handoffs remain outside its supported data-only subset.

The independent runner, `tools/test-native-materialization.py`, builds ordinary
packages with `dpkg-deb`. Their ownership matches the test user, so reference
unpack can use `--force-not-root` without host privilege. Every candidate and
reference root has an explicit disposable-root marker, its own dpkg database,
and a bounded temporary workspace. Native execution never invokes dpkg; only
the reference runner and initial healthy-root setup do so.

The required cases are fresh install, upgrade, downgrade, and reinstall from
real installed dpkg states, plus four consecutive native unpack operations on
one root. The fixture includes changed and obsolete content, a hard-link
group, a symbolic link, permission changes, and an empty archive directory.
The existing semantic comparator checks path kinds, bytes, ownership, modes,
file/link timestamps, hard-link groups, status and status-old, ownership
lists, checksum manifests, architecture, and trigger state. It excludes debz's
bookkeeping and ordinary directory timestamps, whose values depend on child
publication; the runner additionally checks the empty archive directory's
timestamp exactly. Conffile and maintainer-script cases must hand off without
changing payload/database state or leaving active mutation evidence. The
zero-directory-timestamp refusal is exercised the same way, and the repeated
sequence must retain the same shared lock inode.

Both native amd64 and arm64 CI jobs run this target in Debug and ReleaseSafe.
`--oracle-only` validates fixture/reference consistency during development; it
does not run native execution and cannot establish native parity. An absent or
skipped native driver cannot pass acceptance without a structured outcome
report and a matching resulting root.

This is an isolated data-only integration boundary, not proof of production
cutover, arbitrary maintainer-script safety, or an atomic snapshot in the
presence of another privileged writer. Native backend selection remains
unavailable. Later integration must supply the production authorization,
isolation, recovery, and provenance contracts.

The opt-in item-11 fixture contract and phase-by-phase conffile/remove/purge
oracle are documented in [Native conffile and removal acceptance](native-conffiles.md).
That path does not change the default item-10b conffile handoff or enable a
production native executor.

## Validation

`zig build test-native-unpack` covers authenticated archive rebuilds, database
re-import, deterministic plans, regular files/directories/symbolic links/hard
links, exact `Replaces`, displaced ownership publication, `Multi-Arch: same`,
merged-`/usr`, the reserved dpkg namespace, and every handoff category above.
The ownership parser has corpus-backed fuzz coverage. The checked-in JSON lists
planning-only scenarios for external differential runners; it is an inventory,
not evidence that those labels were executed. Gate-critical semantics are
asserted by `native_unpack.test.*` Zig fixtures, including pinned
file/link/directory and ancestor-chain substitution, stable-read races, inode
recreation, conffile collisions, exact listed checksums, hard-link topology,
final-prefix retirement, 100,000-package trigger indexes, 120,000 repeated
case prefixes, 200,000-entry hard-link indexes, and 4,096 claimants sharing a
3,000-entry directory.

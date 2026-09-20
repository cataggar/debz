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

## Statoverride metadata

The private resolver honors bounded `var/lib/dpkg/statoverride` records.
Numeric `#<decimal-id>` identities need no account lookup; named identities
resolve only through the selected root's bounded, no-follow `etc/passwd` and
`etc/group` files, never host NSS. Missing or ambiguous names, invalid IDs,
overflow and the chown no-change sentinel are refusals before scripts.

Lookup uses the archive's original root-relative spelling, including literal
backslashes, before merged-/usr alias resolution. Overrides supply owner,
group and mode for files and newly created directories. Existing directory
metadata is retained. Symlinks receive owner/group changes, not mode changes.
The final archive member of a hard-link group determines shared inode metadata:
its override wins, or its absence restores the regular source's defaults.
Conffile policy still preserves existing live metadata where required.

Lifecycle execution freezes this interpretation before its first script,
including when no overrides exist. Script-written account or override changes
are observed as current state but do not alter that invocation's resolution;
the next invocation resolves afresh. Recovery retains the original inputs as
described in [Native recovery](native-recovery.md).

Native database plans explicitly preserve the override file without rewriting
it, including remove and purge. Active `config` scripts, alternatives and other
unsupported vendor state remain guarded.

## Diversion routing

The bounded diversion index separates logical package names from filesystem
destinations. A local `:` record or another package's record redirects the exact
source path; the literal unqualified owning package is exempt. An
architecture-qualified record owner is not an exemption for that package's
unqualified name. Diversions do not rewrite descendants by prefix.

Routing precedes proven merged-/usr normalization. Ownership observations,
hard-link sources, replacements and removals use the resolved destination;
ownership lists, checksums and conffile declarations retain the archive's
logical spelling. Symlink targets remain literal. Statoverrides continue to
match the original source name, not the diversion destination.

Existing destination parents and explicitly supplied directories are honored.
Missing destination parents, an absent diverted source directory needed by
children, conflicting endpoints, canonical claim collisions and reserved
database/private destinations refuse rather than synthesizing a different
successful result. Ambiguous same-package alias ownership remains guarded.
Logical directory ownership and retained ancestors are kept distinct from
physical co-ownership when removing merged-/usr paths.

The native database planner opts into preserving diversion records; it does not
rewrite them. Maintainer scripts may atomically replace the database, including
through genuine `dpkg-divert`. Later phases re-read and validate that state.
Valid in-place edits retain the invocation's previously loaded records, matching
dpkg's inode-aware cache. The loaded descriptor stays pinned; an atomic
replacement or a newly created file reloads the effective records. A subsequent
invocation starts from the current file. Live records are still validated:
malformed or unsupported edits require recovery even when dpkg would continue
using its old cache. The cache never replaces the genuine live database.
Changes during an upgrade's old-postrm callback are also guarded, including
after a fresh-process resume of the interrupted unpack. They require dpkg's
previous-route trigger and retained `.dpkg-tmp` behavior, tracked in
[#192](https://github.com/cataggar/debz/issues/192). This also blocks an atomic
replacement that activates earlier in-place edits without changing live bytes.

File-trigger routing keeps an owned snapshot of the cache used by each unpack.
Recovery-enabled executions persist that snapshot, bound to the original
intent and program step, so later script updates cannot retarget an earlier
publication during re-entry. This is a foundation for the full #192
previous-route, retained-backup and partial-rollback semantics; it does not
remove the mid-unpack guard.

### Visible unpack backups

New unpack inputs also bind the ordinary-file backup inventory before any
backup mutation. Each existing publishing regular file gets a `.dpkg-tmp`
hard link to its original inode; original hard-link groups use a single
canonical source. Symlink backups are recreated with the old target/ownership
and a persisted invocation-clock timestamp. Conffile staging, new paths and
directories do not acquire these ordinary backups. Source/backup collisions
are refused, and original paths and backup destinations are managed observations.

Separate root-mutation journals create backups, publish payload/database state,
and clean up. Only the payload phase runs old postrm. Successful unwind
continues ordinary publication and cleanup. If old postrm and its failed-upgrade
unwind fail, verified generic rollback is followed by a native settlement phase:
incoming diverted files and introduced paths survive, old diverted backups
remain, and diverted conffiles retain old live bytes plus incoming `.dpkg-new`.
Selected diverted hard-link members remain linked to one another, not to
restored nondiverted old members. Restored nondiverted symlinks use their bound
backup timestamps. Compensation order, old installed control/status state and
original-route file triggers remain observable, including the original failed
result after recovery.

This partial rollback is required even when diversion records never change.
It applies to a recorded old-postrm failure, not an arbitrary filesystem error.

Known old-postrm and unwind outcomes can now resume while the payload journal
is still active, including after the script marker is cleared and across an
interrupted recovery rollback. The original outcome and post-invocation
checkpoint remain mandatory; completed scripts are never re-executed.
Recovery preserves recorded non-journal effects without enabling changed-route
unpack behavior. See [native recovery](native-recovery.md) for the admission
rules and conservative directory-membership boundary.

New unpack inputs bind deferred obsolete removal. Payload-replacement
prerequisites and conffile-specific staging keep their original ordering.
Other obsolete removals remain deepest-first but follow the status-old copy
where old postrm runs, before incoming control publication. Old postrm and its
failure/unwind callbacks therefore observe the old obsolete files. Directory
metadata is reapplied after deferred removal where the plan publishes it.
The original plan remains descriptive; its execution ordering is selected by
the immutable per-unpack protocol field, not inferred from live state.
The current protocol binds a binary-safe late-settlement recipe before any
backup or payload mutation. Successful payload/status-old publication commits
first, with old postrm and immediate failure/unwind callbacks still inside that
journal. A separate immutable journal then removes obsolete paths and publishes
incoming control/status bytes before backup cleanup. Recovery consumes committed
payload without replanning existing `.dpkg-new` files; late rollback retries
only the bound settlement. Failure there remains recovery-required rather than
claiming the whole unpack rolled back. Older inputs retain their original
combined journal and phase numbering.
Recovery covers interruption after actual obsolete removal, including a second
interruption during or after rollback, without replaying completed scripts.
Rerouting removals after changed diversion records remains guarded under #192.
Fresh-process recovery consumes committed payload and authenticated completed
script outcomes without republishing that payload or rerunning those scripts.
An unfinished payload may still be re-materialized after verified rollback for
unfinished callbacks. Mid-unpack route changes remain guarded pending the full
settlement/recovery work in #192.

For focused development, `-Dnative-diversions-only=true` selects just the
diversion profiles in the existing lifecycle, trigger and recovery build
targets. Their default workloads and CI still run all profiles.

### Mid-unpack reference specification

`tools/native_diversion_settlement_oracle.py` codifies 24 pinned-dpkg upgrade
profiles and 16 subsequent successful invocations. The default
`test-native-triggers` workload runs this specification in addition to its
native parity cases, on both CI architectures. Every specification result is
explicitly labeled **reference-only**: the mid-unpack native guard remains,
and passing this corpus does not establish native execution or recovery parity.

The oracle requires old postrm to observe real `.dpkg-tmp` backups before
settlement. Regular backups retain the original inode, mode, owner and
timestamp; recreated symlink times are bounded by the actual invocation, not
discarded from comparison. Final observations compare all fixture payload and
side-file paths, exact bytes and metadata, hard-link groups, logical installed
lists, installed script/checksum/declaration bytes, package state, recorded
conffile digest, compensation order and file-trigger routes. In particular,
failed-upgrade compensation must preserve the reference's partial rollback:
version 1 can remain recorded while the old diverted destination contains
version-2 payload and a version-1 backup. Obsolete and introduced paths,
stranded conffile staging, unchanged/in-place/atomic cache updates, creation,
removal, empty databases and package exemption are covered.

A subsequent invocation reloads current routes without deleting old-route
artifacts. Missing conffile destinations under the keep-existing policy can
produce a new-route `.dpkg-dist` while old-route `.dpkg-new` remains; these are
asserted rather than normalized. Use the existing runner to exercise only the
reference specification:

```sh
reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"
sudo -n env PYTHONDONTWRITEBYTECODE=1 python3 tools/test-native-triggers.py \
  --oracle-only --diversion-settlement-reference-only \
  --reference-dpkg "$reference_dpkg"
```

This selector refuses native executable/helper arguments. The full #192
runtime and fresh-process recovery implementation remains a separate
requirement; legacy remains the default.

### Route-settlement contract

The first #192 implementation increment defines a separate
`native-unpack-route-settlement-v1` evidence contract rather than extending
`native-unpack-diversion-v1`. This preserves every existing v1 omission,
canonical byte sequence and protocol selection. The new document is bound to
the execution intent, unpack program step and exact v1 parent digest, and uses
the existing bounded package/path rules. It also records the sorted, proven
merged-`/usr` rewrites used by the original plan, so lowering can compare
logical diversion-cache routes with canonical publication paths without
consulting mutable live aliases.

Each sorted route record names the logical package path, the route used for
payload publication, and either the exact post-script route or an authenticated
diversion-cache digest. It explicitly associates deferred removal/metadata
writes with the publication or post-script route and records the file-trigger
source, previous/resulting package ownership, `.dpkg-tmp` disposition, conffile
staging disposition and exact recorded conffile MD5 expectation. Validation
rejects duplicate routes, settlement indices, physical claims, trigger aliases,
conflicting cache references and side-file collisions. JSON route and
association counts are stopped while parsing, string tokens are bounded before
copying, and the exact encoded size is checked before output allocation.

Pure lowering checks that the parent v1 cache actually selected every recorded
publication route, resolves authenticated cache references, verifies associated
v1 settlement-write kinds and source paths, and emits only data: adjusted
mutation intents, absolute trigger names and derived backup/conffile paths. It
does not read or mutate the root, publish evidence, select a journal protocol,
or change recovery. Production still rejects old-postrm diversion changes with
`UnsupportedMidUnpackDiversionUpdate`; a later #192 increment must integrate
the contract only after the corresponding success and recovery semantics exist.

The second inactive increment adds a separate successful-old-`postrm` lowering
mode and an internal executor, but ordinary lifecycle execution still cannot
select either one. The lowering accepts only a separately authenticated cache
document; it does not turn live bytes into authority. Route changes are decided
from effective records rather than the live diversion file digest alone, while
live-observation changes are reported independently so an identity transition
cannot be omitted from later evidence. This preserves cached routes for valid
same-inode edits while recognizing same-byte atomic activation of a previously
ignored edit.

Successful lowering binds newly selected destinations as absent before any
mutation, reroutes associated obsolete removals with an absent-safe removal
that still rejects an unexpected occupant, retains publication-route
`.dpkg-tmp` backups only when the effective route changed, authenticates their
identity/content/metadata, and emits cleanup for unchanged effective routes.
Trigger paths remain those selected for publication. A route-changing conffile keeps its publication-route
`.dpkg-new` and rewrites only the authenticated package's recorded status MD5
to the prior digest carried by the contract. The rewritten status, original
database recipe and route contract derive new phase/database evidence.

The internal executor requires the existing held operation and recovery
runtime, then uses the generic mutation journal, stable managed-state
validation and pre-mutation path checkpointing.
It does not synthesize or publish a diversion database. It is intentionally
unreachable from normal requests: no ordinary execution emits this capability
and the existing mid-unpack guard remains.

The third inactive increment extends the same lowering across successful
failed-upgrade unwind, double-postrm rollback and later postinst failure. A
rollback does not publish the incoming late database recipe: the verified
payload journal restores the old status/list/control generation first, then
only contract-described changed publication routes are retained. The route
description distinguishes restored previous-only paths, orphaned incoming
payload and stranded conffile staging; changed-route backups remain
authenticated and are not consumed by ordinary cleanup. Original publication
routes remain the trigger authority.

The route contract is a write-once managed input at its unpack anchor. An exact
retry can finish an interrupted checkpoint without changing the contract.
Fresh-process recovery can authenticate the narrow interruption after the
postrm cache document is durably refreshed but before its script checkpoint,
but requires its private mode, single-link identity and exact bytes before
recording that transition. Later settlement and cleanup recovery
re-lowers the contract, checks completed script outcomes and progress, and
matches the actual mutation journal before generic repair. Missing/unknown
outcomes, changed caches or contract, destination occupants, backup or staging
drift and unrelated directory membership still refuse before further
mutation. Caller archives are not consulted: the existing intent-owned
artifact copies remain recovery authority.

Completed provenance retains the route contract as indexed evidence alongside
the publication cache. Repeated completion therefore verifies the same
immutable bytes. This remains inactive infrastructure only; production
activation and the ordinary execution guard are unchanged.

The 15-profile success-lowering corpus covers successful old-`postrm`
transitions. The 24-profile reference set has 16 overall successful upgrades;
`unwind-success/regular` is the additional successful outcome, but its old
`postrm` fails and therefore remains part of the guarded unwind path.

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

Incoming `.list` files include `/.` only when the payload archive declares its
root directory. An archive without that entry does not acquire root ownership;
an empty payload without a root entry publishes an empty list. Synthesized
parent directories likewise do not become package-owned paths.

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
Publication uses the logical archive spelling, including for aliased paths.

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
- alternatives and unmodeled package metadata;
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

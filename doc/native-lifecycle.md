# Native lifecycle execution

The item-12 lifecycle acceptance boundary composes the native program compiler,
data/conffile materialization, package database, root-operation coordinator, and
audited maintainer-script runner. Core native execution now uses this boundary
experimentally; the legacy backend remains the default.
[Trigger execution](native-triggers.md) and
[durable native recovery](native-recovery.md) extend this private boundary.
The experimental [typed runtime API](native-recovery.md#experimental-typed-runtime-api)
provides caller-owned execution of prepared programs and core product/CLI
integration. Other consumers remain a separate milestone.

## Execution contract

The lifecycle consumes a compiled native program, not scenario names or
hand-written script invocations. One root-operation attempt holds the real root
lock across payload changes, database publications, scripts, and compensating
calls. The consumed database generation is rechecked under that lock, and the
complete resulting package closure is checked before completion. Script
identities bind the installed or incoming script bytes and their actual owning
version, and
`SystemMaintainerScriptLauncher` applies the existing root, environment, argv,
timeout, output, and descendant policies.

The pinned-dpkg [root import acceptance](../test/native_root_import.zig)
starts with an already installed, configured package in two independently
seeded disposable roots. It compares the prestate and an additional native
install against pinned dpkg, including status and status-old, owned info files,
conffiles, active alternatives, diversions, statoverrides, file triggers,
script traces, and the complete filesystem/database snapshot. The native
invocation uses durable recovery-backed receipts: its initial/final database
generations, script outcomes, and retained evidence are verified after success.
Independent copies with corrupt or duplicate status, an update fragment,
unclassified top-level metadata, and unsafe modes must refuse before mutation.
Test-only edits to status and an installed script *after compilation* must
refuse on the locked database-generation check; the only change left in each
root is the injected edit. Each refused copy has no active mutation evidence.
Use `zig build test-native-root-import -Dnative-reference-dpkg=/absolute/path/to/verified/dpkg -j2`
in Debug and ReleaseSafe. This test requires root for guarded chroot fixtures
and rejects an unpinned reference. CI runs it in both modes on amd64 and arm64
in the required `native-recovery-zig-workflows` shard, which gates
`Build and test`; the security audit rejects a missing, skipped, duplicated,
unpinned or relocated invocation. This bounded fixture-level parity does not
replace the signed-root gates in the migration acceptance plan.

Arguments preserve empty strings. In particular, a package that has never been
configured receives `postinst configure ""`; the unpacked package's `Version`
is not a substitute for its last configured version. Upgrade preinst and the
incoming failed-upgrade/abort-upgrade scripts include both old and new versions
where dpkg does.

Known inert control members (`config`, `templates`, `shlibs`, `symbols`) are installed
with their exact bytes and safe modes, replaced or retired on upgrade,
reinstall and downgrade, and removed on successful removal/purge. Old upgrade
`postrm` sees the new payload but the original installed control metadata;
new control publication follows that callback. Removal retains metadata through
`postrm remove`, retiring it only on successful settlement. Failed removal
restores original metadata along with the original package record.
Lifecycle fixtures compare these observations with dpkg for unqualified,
architecture-qualified and changing info stems, compensation, failures and
configure/purge retries with and without conffiles. Existing admission guards
for otherwise unsupported half-installed states remain unchanged.
Config additionally requires executable mode and root ownership. It is staged
at `var/lib/dpkg/tmp.ci/config` before pre-unpack callbacks, published before
the incoming postinst, retained after postinst failure for configure retry,
restored on upgrade unwind, and removed before purge postrm. Native execution
never calls it or invokes apt, debconf, or frontend behavior. No other
active/unknown metadata support is implied.

Bootstrap extraction can publish several packages' control files before any
configure callback. Its single dpkg staging slot is serialized: each package's
authenticated config is staged, published unchanged to its installed `info/`
member with that package's payload, then removed with `tmp.ci/` through a
separate authorized, journaled native phase before the next bootstrap package
stages its config. Later postinst callbacks use the installed member, not the
shared staging slot. Recovery does not stage a completed package again:
completed publication and cleanup progress must be present and the installed
member must still match the authenticated bytes and metadata. An occupied slot
without the expected owner, or missing/changed control evidence, is refused;
the same rules for ordinary healthy-root unpack remain in force.

The separate [amd64 and arm64 direct-dpkg config reference](integration-roots.md)
closes the dpkg side of that boundary for the seven pinned vendor `*.config`
identities on both admitted architectures. Pinned dpkg 1.22.22 never invokes
config during install, reinstall, upgrade,
configure retry, remove, purge, compensation, or interrupted-operation retry.
It stages incoming config for the pre-unpack callbacks, publishes it before
the incoming postinst, keeps it through remove postrm, and deletes it only
after successful remove settlement. Failed/interrupted removal keeps it;
failed upgrade rollback restores the old bytes; purge postrm sees it absent.
Native lifecycle execution now implements that bounded state contract and the
native/dpkg differential covers the seven pinned package identities at their
exact observed sizes on both admitted architectures plus general bounded config
members. Debconf or another frontend invoking config is a different contract.
Arm64 admission is backed by its executed canonical oracle observation, not by
architecture-independent parsing.

The authenticated `keyboard-configuration:all` 1.248ubuntu3 fresh-install
preinst is a narrower debconf exception, not permission to execute `config`
members. Pinned dpkg 1.22.22 registers the archive's templates before this
preinst calls `db_get keyboard-configuration/toggle`. In the native root the
frontend instead found no adjacent templates beside the private staged script,
so that call exited 10. A disposable chroot reproduced exit 10 at the native
path and exit 0 when the **exact signed** 576415-byte templates member was
placed beside that script. Native stages that member only for the matching
package, version, architecture, preinst digest and `install` argument, after
proving its dependent bootstrap step, signed installed copy and journaled
publication. The separate journaled template stage runs **at preinst**, even
when bootstrap already staged the package's other scripts: stage-once
short-circuiting had omitted this later sibling in the first new signed
175-package replay. A preexisting sibling requires authenticated recovery,
the stage's progress action and matching bytes/metadata. The existing
bootstrap-staged config still receives its original digest/mode/owner check
before the template stage; foreign or altered siblings are refused. Script
exit and postrm compensation remain authoritative, not ignored.

The signed `iproute2:amd64` 6.19.0-1ubuntu2 postinst is a second, distinct
debconf template placement case. Its `configure ""` branch calls
`db_get iproute2/setcaps` after sourcing `confmodule`; the private staged
script exited 10 with no output, whereas pinned dpkg 1.22.22 configured
the installed-info script in a disposable diagnostic copy. In separately
copied roots, the private path exited 10 without its templates and 0 with
the exact signed 15912-byte sibling and dpkg's maintainer-script environment.
Only the exact postinst digest, package/version/amd64 identity, source and
arguments can stage this archive member. The same authorized program must
prove the dependent bootstrap preinst, completed unpack and unpacked state;
the installed postinst, templates and config retain their signed integrity,
and a collision requires journaled recovery. The stage uses the ordinary
cleanup path, not a blanket debconf or config-script permission.

If a fresh preinst fails after its package was already bootstrapped, the
payload and database ownership are real and cannot be erased by writing an
unowned `not-installed` record. For an exact bootstrap-to-preinst-to-unpack
dependency and complete publication journal, native instead retains its
package list and signed files and durably marks it `install reinstreq
half-installed`. That is a **conservative failed state**, not byte-for-byte
dpkg rollback parity, and it does not turn the failed script into success.
Other already-present packages remain refused. The pinned-dpkg lifecycle
fixture checks the nonzero preinst and compensating postrm plus durable native
failure state independently.

Alternatives use a separate active-state boundary. Opaque package
`.alternatives` members follow ordinary retained-metadata replacement,
failure, removal, and purge behavior, while direct dpkg never interprets them.
For a script that contains literal direct `update-alternatives` command lines,
with at most a literal `case` label before the command and a shell terminator
after it, native
execution verifies the architecture-pinned root-local tool, captures and
checkpoints the complete pre-script record/link/target state, and limits
post-script changes to the discovered groups and master/slave topology.
Unmentioned groups and all provider/tool inputs must remain identity-exact.
A normal return is captured and checkpointed before outcome settlement; a
signal, injected unknown outcome, malformed/partial topology, or external
drift marks recovery required and is never repaired by rerunning the script.
Comments, wrappers, extra shell tokens, dynamic command construction and
unsupported options remain rejected before spawn. Independently, every fresh
native operation validates all existing active groups and orphan selector
state while the operation is still pre-mutation, so a malformed root cannot be
partially unpacked before this refusal. See the
[pinned alternatives contract](dpkg-alternatives-reference.md).

Statoverrides use file-backed target-root identities and are resolved before
scripts. Preinst retains that resolution for its unpack. A successful
non-preinst script refreshes changed override database bytes for later phases,
using the target root's account files; a later invocation resolves anew.
Recovery checkpoints live targets only for records created or changed by those
scripts, leaving unchanged administrator overrides outside this added scope.
Missing identities refuse before lifecycle mutation. See the
[metadata contract](native-unpack.md#statoverride-metadata) for directory,
symlink, hard-link and exact-path behavior.

Diversions use package-dependent logical/physical routing. Normal atomic
`dpkg-divert` updates are observed at subsequent phase boundaries; in-place
edits retain the invocation's cached routes rather than becoming a fresh map.
Malformed live edits remain refused, and the next invocation reads current
records independently.
Updates during an in-progress unpack's installed-package old `postrm upgrade`
use the route-settlement capability only after the exact script outcome,
refreshed cache and route/backup evidence are durably bound. Other callbacks,
arguments, legacy evidence and unsupported route changes remain explicitly
blocked.
File-trigger matching uses the diversion destination spelling, including when
that spelling resolves through a merged-/usr alias. Each unpack retains its own
effective cache for that matching, including across recovery after later script
updates. See
[diversion routing](native-unpack.md#diversion-routing).
An exact archive directory claim at a proven merged-/usr alias can share an
installed owner's alias path without replacing the symlink or publishing
directory metadata, provided its canonical target is an existing directory.
An archive symlink claim can also share that path only when its target bytes
exactly match the observed alias. The symlink's identity and target are checked
against a non-mutating filesystem journal step before publication and during
recovery; foreign links and different targets remain refused.

Old postrm now observes journalled `.dpkg-tmp` backups of replaced ordinary
files: regular backups retain original inodes and hard-link groups, while
symlink backups are recreated at a bound invocation-clock time. Successful
unwind removes them after publication. Known failed upgrade can retain incoming
diverted payload and old diverted backups while restoring old status/control
records, even with an unchanged diversion database. Native/dpkg profiles cover
regular files, symlinks, both hard-link positions, introduced files and conffiles.
Fresh-process recovery preserves this failed result without repeating completed
scripts, and completes or defers file triggers according to the original policy.
For authenticated route changes it also preserves the original publication
route as trigger authority across success, unwind, rollback and later postinst
failure.

A direct purge of an installed package compiles as one journaled
remove-then-purge program in dpkg's order: `prerm remove`, file removal,
`postrm remove`, then the purge half. Like dpkg's `removal_bulk`, remove and
purge of a package with neither conffiles nor a postrm both go straight to
not-installed, without an intermediate `config-files` record or purge
settlement ([#326](https://github.com/cataggar/debz/issues/326)).

File removal deletes every installed maintainer script except `postrm`. A
removal or purge that still runs an installed script therefore stages the
package's installed scripts in a journaled phase before any `info/`
deletion. With a `prerm`, that staging already happens at `prerm remove`.
Without one, the file-removal step stages first, so a package that ships a
`postrm` but no `prerm` runs `postrm remove` (and `postrm purge`) exactly as
dpkg does, instead of refusing with `target_absent`
([#328](https://github.com/cataggar/debz/issues/328)).

Purge deletes conffile bytes and recognized side files before `postrm purge`,
while leaving the original control records visible to that script. A known
outcome then settles the conffile records; final directory/info removal follows
only on success. A failed postrm retains residual directories and its script
for retry. Files recreated by postrm are not deleted by subsequent settlement.
Removal ownership lists retain nonshared directories that could not be removed.
Diverted conffiles are an explicit exception: dpkg leaves the diverted live
file and its side files on purge while retiring the package's logical records.
The administrator's source path is not overwritten or removed.

Configuration retry from `half-configured` does not repeat conffile decisions.
Recorded digests must still match the bound archive, but administrator edits,
deletions and existing side files remain untouched under either policy.
`Config-Version` survives a failed upgraded postinst and is cleared only after
successful configuration, preserving the next invocation's last-configured
argument. Unpacked packages still require matching staged `.dpkg-new` bytes.

Known script failures follow the compiled failure transitions and compensation
ordering. Restoring managed package files is not permission to roll back
arbitrary script side effects. Before any script can run, durable evidence must
identify the invocation as in flight. An outcome that was not durably observed
blocks further mutation rather than retrying the script, declaring success, or
falling back to legacy execution.

Already-absent remove/purge is a narrow fixture exception: authorization v1
cannot represent an absent-package action. Under the same real root lock, this
path can only rotate status-old bookkeeping after confirming the selected
packages are absent. It cannot run scripts, change package data, bypass active
recovery evidence, or claim to have executed a compiled package lifecycle.

### Caller-owned operation boundary

The interpreter can also borrow an existing native root-operation attempt.
`native_operation.bind` checks the held root descriptor, backend, architecture,
and canonical program, then adds write-once authorization, program, actual
solver-plan, exact-lock, database-generation, and artifact evidence. It does not
replace the caller's operation, request hash, policy hash, or attempt identity.
Native phase journals consume those exact bindings rather than substituting
the program digest for the caller's solver-plan digest.

A borrowed interpreter neither acquires a second root lock nor releases the
caller's lock. Preflight refusal leaves abandonment to the caller; successful
package work leaves the outer attempt mutating and unfinished so subsequent
repository/configuration work can still run. Only the outer owner may publish
its completion/provenance and clear its record. A pending legacy executor
bridge cannot be treated as native authority.

The private v1 owned execution/recovery path retains its original binding for
compatibility. Its fixture request cannot describe the separate caller hash
domains, so borrowing it as a production recovery request is explicitly
refused before mutation. The separate typed
[production request and recovery boundary](native-recovery.md#caller-owned-production-request-and-completion)
persists both hash domains, resumes original inputs, and publishes native
terminal evidence without completing the caller. Cleanup requires explicit
receipt acknowledgment. On seeded roots, the helper-aware variant embeds and
stages trusted helper bytes, probes namespace capability before package
mutation, and records the isolated helper binding in a v2 request. Missing
targets are refused without creating placeholders unless a v3 fresh-root
request proves an empty settled database and the exact authenticated owner
archive. In that case the normal bootstrap payload step publishes the final
package bytes first; only then may an attempt-scoped private helper source be
journaled, probed and mounted for later scripts. Final verification requires
the bound package database record to own the target. `debz.native_runtime` now
exposes the trusted-helper-only typed execution/recovery/acknowledgment path;
fixture controls remain private.
Core product/CLI execution/recovery binds native receipts to outer completion
before acknowledgment and cleanup. Other consumers remain independently gated.

## Independent reference acceptance

Run on native Linux amd64 or arm64 with `dpkg`, `dpkg-deb`, `ldd`, `/bin/sh`, and
passwordless `sudo`. Named statoverride comparisons require dpkg 1.22.16 or
newer, when target-root passwd/group lookup was introduced. Older references
fail before the workload rather than skipping named-identity coverage.

```sh
zig build test-native-lifecycle -j2
zig build test-native-lifecycle -Doptimize=ReleaseSafe -j2
```

The Zig acceptance and unprivileged oracle regressions use
`test-native-lifecycle-zig` and `test-native-lifecycle-zig-unit`. The Zig
lifecycle fixtures now compare real dpkg with native execution for all
maintainer-script failure/unwind paths, dependency barriers and bootstrap,
retained/vendor metadata, conffile retry and purge, statoverrides,
alternatives, literal paths, diversions and unsafe refusals. Every successful
or known-failure phase compares complete filesystem, database, status and
length-prefixed script traces; interrupted operations instead check durable
recovery evidence and unchanged re-entry snapshots. The pinned reference
option also supplies and independently verifies `update-alternatives` for
that scenario; without a pinned reference, only that scenario is skipped.
`-Dnative-diversions-only=true` selects diversion scenarios.
`-Dnative-statoverrides-only=true` selects the statoverride metadata and
genuine-tool lifecycle scenarios, including named-account creation, chrony-like
script-created files and a shipped directory, guarded reinstall, a payload
upgrade with byte-stable maintainer scripts, and remove/purge. The genuine
diversion cases also cover postinst and prerm `--rename` moves and 210
`prerm remove` additions owned by `coreutils-switch`.
Both suites assert exact database and `-old` bytes. Use
`-Dnative-reference-dpkg=/absolute/path/to/pinned/dpkg` for artifact-bound
reference evidence; an unpinned host run is separate compatibility evidence.

`test-native-lifecycle-zig-oracle` executes the standalone `--oracle-only`
selector against two guarded roots with the same selected dpkg, independently
running ordered reference groups and comparing each phase's exit and exact
snapshot. `--workspace` retains a *new direct child* of this worktree's
`.tmp`; existing or out-of-tree paths refuse before execution. In
oracle-only mode native-specific refusals are not mislabelled reference parity.
Zig unit tests execute valid and rejected compensation examples against the
published `scriptFailure` schema closure (including actual count, digest, and
rollback bounds). This bounded validator fails closed on unsupported keywords
or references; it does not purport to implement the entire Draft 2020-12
vocabulary. The `test-native-lifecycle` build target now runs this Zig
acceptance, not Python; its Python unit gate has been removed. CI requires
native and both-reference selectors on amd64 and arm64 in Debug and
ReleaseSafe. All four former Python lifecycle/trigger test entry points are
absent. `tools/native-lifecycle-fixtures.py` is an import-only module for
the separate dpkg-config reference and action integration
fixtures; it has no lifecycle acceptance CLI.
Trigger acceptance has a separate reference-only
unconfigured-listener boundary; see [trigger execution](native-triggers.md#independent-acceptance).

The eleven former `tools/test_native_lifecycle.py` unit-method counterparts are
individually exercised by `test-native-lifecycle-zig-unit`:

| Python `test_` method | Executed Zig assertion |
| --- | --- |
| `reference_refuses_host_and_unguarded_roots_before_spawn` | `native_lifecycle_support` root guard and acceptance pre-spawn refusal |
| `fixture_scripts_record_exact_arguments_and_visible_payload` | lifecycle fixture script byte and `/bin/sh -n` test |
| `backup_probe_uses_real_inode_and_metadata_observations_before_failure` | `native_lifecycle_diversions` backup-probe script syntax and byte test |
| `script_and_bootstrap_payload_are_part_of_real_archive_source` | built essential archive's executable source, md5sums and scripts |
| `bootstrap_fixture_can_use_uncompressed_archive_without_runtime_fallback` | actual archive `data.tar` member and two-root bootstrap execution |
| `published_schema_accepts_and_bounds_compensations` | `native_failure_schema_validation` valid/invalid published failure examples |
| `empty_argument_and_payload_differences_cannot_be_normalized_away` | `native_lifecycle_support` trace/payload mutations |
| `rollback_clock_exception_is_path_type_and_time_bounded` | `native_lifecycle_support` named-link type and clock bounds |
| `nonrollback_metadata_is_still_exact` | `native_lifecycle_support` ordinary mtime and metadata mutations |
| `native_request_preserves_reviewed_order_and_fault_boundary` | native request JSON ordered-actions/fault assertion |
| `success_report_cannot_hide_wrong_state` | applied-report/wrong-root snapshot rejection |

CI uses hash-pinned Debian dpkg 1.22.22 for both architectures. On Ubuntu 24.04
or another compatible Linux host with an older dpkg, prepare that reference
without root privileges:

```sh
reference_dpkg="$(python3 tools/prepare-native-dpkg.py --architecture amd64)"
zig build test-dpkg-config-reference test-native-lifecycle test-native-recovery \
  -Dnative-reference-dpkg="$reference_dpkg" \
  -Dnative-reference-architecture=amd64 -j2
```

The helper verifies architecture-specific archive and executable SHA-256 pins,
extracts into `.cache/native-dpkg-reference/`, and validates the executable on
each reuse. It never installs a package, rewrites host accounts, changes host
dpkg, or repairs a tampered cache. The Debian binary requires glibc 2.38 or
newer and the usual dpkg runtime libraries. Direct fixture drivers accept
`--reference-dpkg PATH`; the build option forwards it explicitly through
`sudo` to the config oracle and all five native reference runners. The selected
binary is used only for reference commands. The config oracle uses its bounded
deterministic Python archive builder; the other native fixtures still use host
`dpkg-deb` where documented. The package-owned reference trigger helper remains
unchanged, and fixture/script `PATH` does not gain the private prefix.

Only the fixture runner is elevated; Zig compilation is not. Roots, packages,
requests, snapshots, and logs are created under the worktree's `.tmp` directory.
Every root must have the existing disposable materialization guard. Reference
commands use explicit argv and a validated alternate root; maintainer scripts
run in actual chroots, never with `--force-script-chrootless`. The harness also
checks that host dpkg status is unchanged.

The 27-sequence reference matrix covers fresh install, upgrade, downgrade, reinstall,
remove/purge and repeated operations, upgrading an unconfigured package,
configure retry, failures of all four maintainer-script kinds, missing cleanup
scripts, and failed upgrade/removal compensating calls. It compares exact script identities, argument
counts and length-prefixed arguments (including empties), and payload bytes
visible at each script invocation. Filesystem metadata/content, ownership,
hardlinks, package status and status-old, info records, and script bytes are
compared independently of the native outcome report.

The retained-metadata matrix includes executable root-owned config members. It
checks live and `tmp.ci` identities at every maintainer-script callback,
postinst failure/configure retry, upgrade unwind, failed remove/purge, and
successful settlement. A separate config-only cohort covers all seven pinned
vendor package names and sizes, and ambient `tmp.ci` files, directories,
symlinks, or occupants refuse before mutation.
The essential-bootstrap preinst-failure case runs an actual nonzero preinst
and `abort-install` against pinned dpkg and, independently, checks that native
durably reports `script_failed`, retains its claimed bootstrap payload and
info list, publishes the conservative half-installed state and cleans its
operation journal. A second, independently fresh synthetic root interrupts
after executing that failing preinst but **before** recording its exit: its
script stays in flight, the unpacked owner remains claimed, and a retry
returns recovery required without rerunning the script or changing the root.
An additional config-and-templates-bearing bootstrap fixture exercises signed
staging/cleanup and the same known-failure state.

Advanced fixtures exercise:

- **Statoverrides:** numeric/named identities, new/existing directories,
  conffiles, symlinks, hard links, literal paths and merged-/usr spellings;
  invocation-frozen account/override changes; fresh resolution on reinstall;
  administrator conffile metadata under both policies; and pre-script refusals.
- **Pre-Depends:** a reviewed configure barrier runs the provider's postinst
  before the consumer's preinst; the consumer script independently requires
  that ordering. The reference uses the corresponding separate dpkg command
  groups, including their real status-old semantics.
- **Dependency cycles:** mutually dependent packages require both payloads
  before configuration, and their actual configure traces must match dpkg.
- **Essential bootstrap:** the native root initially has no `/bin/sh`. The
  bootstrap archive really contains the interpreter and its libraries, which
  native execution must materialize before scripts can run. The reference
  extracts that same archive before invoking dpkg, matching a bootstrap stage.
  This fixture uses a real uncompressed archive, without a fixture-specific
  decompressor or rewritten archive provenance.
- **Unknown script outcome:** interruptions after real preinst and old-postrm
  execution, before recording their outcomes, must retain both the
  program-bound recovery record and the exact in-flight script identity,
  bytes digest, and arguments. Neither another lifecycle nor absent-package
  purge may change those records or the complete root/trace.
- **Unexpected final state:** a real postinst changes an unselected package's
  recorded version. Final verification must block completion and retain
  recovery evidence rather than accepting the changed database as its own
  expected result.

### Install-side differential inventory (#266)

These are executed fixture cases, not corpus labels or program-only checks.
`test-native-lifecycle-zig` uses independently initialized, guarded roots,
the hash-pinned dpkg reference and exact `status`/`status-old`, `info`,
filesystem and length-prefixed script-trace snapshots. The signed consumer
cases additionally compare core and FAMILY to pinned dpkg on distinct roots,
using identical authenticated v3 locks. This signed parity cohort publishes
SHA-256, SHA-512 and Size for each archive; the Zig runner independently rehashes both
digests and checks the declared byte count for every locked repository archive.
The pinned reference's executable SHA-256 and version remain checked before
each run.

| Boundary | Executed evidence and result |
| --- | --- |
| Fresh install, unpack/configure and configure retry | `fresh-install`, `script-upgrade-unconfigured`, `fresh-postinst-failure/configure`, and signed `pre-depends` and `known-script-failure`: real dpkg/native roots and exact script/data/database captures match. |
| Nonzero scripts and dependency failure | `fresh-preinst-failure`, `fresh-postinst-failure`, `pre-depends-provider-{preinst,postinst}-failure`: provider failure stops before the consumer preinst on both roots, with exact exit outcome, status, files and trace equality. Signed `pre-depends-known-failure` runs in both Debian-stable and Ubuntu-26.04 suites: public CLI exits 7, FAMILY reports `transaction`, dpkg exits 1, and failed roots/receipts match. |
| Conffile conflict decisions | `script-conffile-{keep_existing,use_package_version}`, `conffile-configure-retry-*` and signed `conffile-{keep,replace}`: edited conffiles, `.dpkg-*` companions, statuses and script trace are compared under both policies. |
| `Pre-Depends` barrier and dependency cycle | `script-pre-depends-barrier`, `script-dependency-cycle`, signed `pre-depends` and `dependency-cycle`: script order/arguments and final root captures match. |
| Competing ownership | `replaces-competing-file-owner` matches dpkg's displacement and installed database. In `unreplaced-competing-file-owner`, dpkg exits 1 with the actual path/owner diagnostic; native refuses `ownership_conflict` before mutation, clears its preflight operation record and runs no script. This unsupported failure is **not** claimed as dpkg-root parity. |
| FIFO payloads | `fifo-payload` builds real FIFO-bearing archives with `dpkg-deb` (tar typeflag `6`) and runs install → upgrade → downgrade → remove → purge: a FIFO whose mode changes from `0640` to set-group-ID `02660`, a FIFO that becomes a regular file and back, a FIFO that becomes a symbolic link and back, and an obsolete FIFO removed on upgrade. `fifo-payload-statoverride` seeds a `statoverride` record for the FIFO and runs install → upgrade → remove → purge. In `fifo-payload-replaces` a package that `Replaces:` the owner takes over one FIFO as a FIFO and another as a regular file; the displaced owner is removed and purged, then the replacer is purged directly. Every phase compares the whole root (kind, mode, owner, mtime), `status`, `info/*.list`/`*.md5sums`, exit status, and script trace with pinned dpkg 1.22.22 exactly. |
| In-archive symlink chains ([#342](https://github.com/cataggar/debz/issues/342)) | `symlink-chain` builds real archives with `dpkg-deb`, which writes symlinks last and sorted by name, and runs install → upgrade → downgrade → remove → purge. The archive holds the libcurl3t64-gnutls `libchain.so.3 -> libchain.so.4 -> libchain.so.4.8.0` order with the head first, a tail-first head, a head-first three-hop chain through a parent-relative hop, a tail-first chain to a directory through an absolute hop, and an absolute head entering another chain. The upgrade retargets the middle hop and drops a head. `symlink-chain-cross-package` installs a package linking into another package's chain, then purges the owner and leaves the link dangling. `symlink-chain-replaces` takes over a chain hop with `Replaces:`. Each phase compares the whole root, including literal link bytes, plus `status`, `info/*.list`/`*.md5sums`, exit status and script trace with pinned dpkg 1.22.22 exactly. In `symlink-chain-unreplaced`, shipping that hop without `Replaces:` makes dpkg exit 1 with `trying to overwrite`, and native refuses `ownership_conflict` before mutation. `symlink-chain-cycle` (a three-symlink cycle) and `symlink-chain-escape` (a chain whose last hop leaves the root) are refused before mutation as `archive_payload_conflicting_path` and `archive_payload_unsafe_link`. pinned dpkg installs both, and these deliberate divergences are **not** claimed as parity. |
| Unknown script return | `script-outcome-unknown` and `core-unknown-script-return` retain in-flight script identity/recovery ownership and refuse a second mutation; the known nonzero outcome above has dpkg parity. A pinned dpkg *post-return/pre-outcome-record* root is not a comparable dpkg terminal state, so unknown-outcome roots are not represented as parity matches; the transition inventory remains [#267](https://github.com/cataggar/debz/issues/267). |

FIFO publication is journaled like every other node
([root mutation](root-mutation.md#fifos-288)); its crash recovery is proven by
the FIFO real-child cases of `test-native-recovery-zig-mutation-boundaries`
([native recovery](native-recovery.md)).

The native application admission path accepts FIFO-bearing archives
([archive model](archive-application-model.md#fifo-payloads-288)), while
non-application validators keep refusing them before dpkg execution. The signed
`fifo-closure` case of `test-native-recovery-zig-parity` runs in both
the Debian-stable and Ubuntu-26.04 suites. It publishes a signed repository
with two generations of a FIFO package. Version 1.0-1 ships four FIFOs, a
regular file and a symbolic link that later become FIFOs, and a conffile.
Version 2.0-1 re-modes one FIFO to set-group-ID `02660`, turns another into a
regular file, drops one, adds one in a new directory, and keeps one under a
seeded `statoverride` record (`#42420 #42421 0620`). For each generation, the
public CLI resolves a signed exact lock with `plan --lock-output`, and the
test checks every locked package's pool bytes (size, SHA-256, SHA-512) and the
FIFO inventory. The CLI then runs `install --lock-input` natively. The
production remove workflow resolves a remove lock, which the public CLI
executes with `remove --lock-input`. The native lifecycle driver runs purge,
because no public command purges. After every step, pinned dpkg 1.22.22 runs
the same operation on an independent root, and the two roots must match in
kind, mode, ownership, mtime, content, `status`, `statoverride`, `info/*.list`
and `*.md5sums`. Each install, upgrade and remove receipt must bind its exact
lock and pass retained-evidence verification. Install and upgrade must also
pass `transaction-result verify`. The package-owned helper must be unchanged. Each architecture proves this for its
own runner (linux-x64 and linux-arm64 in CI).

### Upstream repository descriptor (#341)

`native_lifecycle_repository_descriptor.zig` runs the unmodified upstream
`packages-microsoft-prod` `1.2-ubuntu24.04` descriptor, with its real
`preinst`, `postinst` and `prerm`. The checked-in archive's SHA-256 is
verified first. `microsoft-repository-descriptor` installs it with a stub
`ca-certificates` dependency, then deletes the apt source and reinstalls. On
reinstall, the upstream `preinst` deletes the keyring, dpkg keeps the deleted
conffiles deleted, and the `postinst` restores both from the
`usr/share/doc/packages-microsoft-prod/` copies. The scenario then removes
and purges the package. `microsoft-repository-descriptor-imported` seeds both
roots with pinned dpkg instead, so native first imports dpkg's verbatim
`./`-prefixed `md5sums`. Every phase compares the complete root, database and
script trace with pinned dpkg. The `info/*.md5sums` comparison keeps each
listed spelling. The installed source, keyring and documentation copies must
equal the reviewed bytes. On both roots, `info/packages-microsoft-prod.md5sums`
must equal the shipped control member's pinned SHA-256 after every install and
reinstall. Pinned `dpkg --verify` must report the same result and exit status
on both roots. It must be clean after each install. It must also flag the same
`copyright` file after an identical edit on both sides. On the imported root,
native is also interrupted during reinstall at `during_filesystem_publication`
and during removal at `after_script_outcome`. `recover` must complete each
operation exactly as pinned dpkg does. The restored files' wall-clock mtimes
are the only normalization. `test-native-lifecycle-zig`
includes both cases. To run only them, use `--repository-descriptor-only` in
place of `--removal-only` in the focused command below.

### Removal and trigger failure inventory (#264)

`test-native-lifecycle-zig` runs `native_lifecycle_removal.zig`; its
`--removal-only` selector isolates these new Zig cases. Every paired phase
uses separately prepared guarded roots and the pinned dpkg reference.
The root comparison includes file content/metadata/links, ownership,
`status`/`status-old`, `info`, trigger records and full script traces.
The removal-specific assertions also require the exact invocation sequence,
arguments, payload observation, residual conffile status and info records.
Reference commands exit exactly 0 on success and 1 on failure; native
reports `applied` or the corresponding typed script failure, not merely an
absent callback.

| Boundary | Executable evidence |
| --- | --- |
| Same-version reinstall, upgrade/downgrade ownership, remove versus purge | `removal-residue-reinstall-versions`: reinstall an installed edited-conffile package, upgrade/downgrade payload ownership and links, then remove (retained edited conffile and `deinstall ok config-files`, retained `.list`/`.postrm`) and purge (no status stanza or residual conffile/info). Each phase matches the reference root. |
| Same-version reinstall **after remove** | `removal-config-files-same-version-reinstall`: the same authenticated archive reinstalls into both original `deinstall ok config-files` roots. Exact exit, `install ok installed` status, retained administrator-edited conffile, scripts, info, file ownership/metadata and trace match pinned dpkg. Unlike an installed-to-installed reinstall, the new preinst receives `install 1 1`, no old prerm/postrm runs, and postinst receives `configure 1`. The compiler requires an exact configured-version proof and the database permits the bounded `config-files` to `unpacked` transition, not a jump straight to installed. |
| Failed and interrupted reinstall from `config-files` | `removal-config-files-reinstall-preinst-failure`: dpkg and native run preinst `install 1 1`, then postrm `abort-install 1 1`, retain the edited conffile and original `.list`/`.postrm`, and publish `install ok config-files`; a same-root retry succeeds after removing the failure marker. `removal-config-files-reinstall-unknown-preinst` retains the original `deinstall ok config-files` owner and a program-bound, in-flight preinst record; recovery, reinstall and purge re-entry cannot replace that owner or evidence. These interrupted roots are **not** claimed equivalent to a terminal dpkg root. Invalid `Config-Version`, a purge selection and `half-installed` remain pre-mutation refusals. |
| Prerm failure and successful retry | `removal-failure-prerm`: actual `prerm remove` exits 23 and invokes `postinst abort-remove`; both roots match, then the failure marker is removed and a **same-root** remove/purge succeeds with matching state. |
| Postrm remove failure and bounded retry | `removal-failure-postrm`: the failed `postrm remove` and `deinstall ok half-installed` match. Only a known nonzero exit from the installed `postrm remove` under the mutation lock publishes a root-local failure record; neither prerm failure nor purge postrm failure mints retry proof. The record binds the original attempt/program/lock, root inode, database generation, installed evidence and postrm digest; only a newly authorized same-root remove may stage the remaining postrm and settle residual metadata. The retry retains the edited conffile, residual info and `deinstall ok config-files` with exact dpkg parity. Missing or modified proof, including changed conffile bytes, is refused before mutation; the proof is checked again under the new root-operation lock. Recovery rechecks the retained proof against its durable program before resuming an early interruption; unknown script returns remain blocked. The proof is cleared only after final-state verification. |
| Interrupted postrm retry | `removal-failure-postrm-interrupted-retry`: after the first known failure, the second invocation executes only postrm once. An injected after-return/before-outcome-record interruption retains the new attempt's operation and in-flight script identities; remove, purge and recovery cannot claim a second mutation or erase the owner's journal. This unknown return is not presented as dpkg terminal parity. |
| Early retry crash and recovery | `removal-failure-postrm-early-recovery`: a crash after the retry intent is published but before file settlement leaves the first failed callback intact. Explicit recovery resumes the bound retry with only one further postrm invocation, clears the marker and matches dpkg's complete root and trace. The changed-root variant edits the conffile after the crash and verifies that recovery refuses without replay or mutation. |
| Purge postrm failure and successful retry | `removal-failure-purge-postrm`: conffile bytes are gone *before* the failing purge callback, while `purge ok config-files` and `.postrm` remain; retrying the same root completes purge on both sides. |
| Unknown removal callback outcome | `removal-prerm-outcome-unknown`: a real `prerm remove` executes once, but the native after-return/before-record fault retains the in-flight script hash, arguments and program-bound recovery ownership. Remove, purge and explicit recovery attempts cannot mutate the root or replace evidence. The reference terminal remove is **not** claimed equivalent to this in-flight state. |
| Direct purge of an installed package | `direct-purge-{scriptless,scriptless-conffile,scripts,scripts-conffile,no-postrm}`: one `purge` from `install ok installed` matches pinned `dpkg --purge`, with exact callbacks `prerm remove`, `postrm remove`, `postrm purge` (only `prerm remove` without a postrm, none without scripts). The edited conffile is deleted, and no status stanza, conffile, payload or info residue remains. A package with neither conffiles nor a postrm goes straight to not-installed, as in dpkg ([#326](https://github.com/cataggar/debz/issues/326)). |
| Interrupted direct purge | `direct-purge-recovery-*` crashes on existing boundaries: after the recorded `prerm remove` outcome (with and without a postrm), after the recorded `postrm remove` outcome at the remove-to-purge transition (`after_removal_postrm_outcome`), during the removal half's file removal (`mutation_target_remove`) and during its database publication. Purge re-entry is refused without mutation. Explicit recovery then finishes the same program through purge and matches the complete root and trace of the terminal dpkg purge. After an unrecorded `postrm remove` return (`after_removal_postrm_return_before_outcome`), the edited conffile is retained, and recovery (`script_outcome_unknown`), remove and purge stay blocked without mutation. That root is **not** claimed as dpkg parity. |
| Remove and purge of a postrm-only package | `postrm-only-{no-prerm,no-prerm-conffile,only-postrm,only-postrm-conffile}-{remove,purge}`: a package that ships a `postrm` but no `prerm` (with or without `preinst`/`postinst`, with or without an edited conffile). `remove` runs exactly `postrm remove` and publishes `deinstall ok config-files` with the retained `.postrm` (and edited conffile); the follow-up `purge` runs exactly `postrm purge`. A direct `purge` runs `postrm remove`, then `postrm purge`. Every phase matches pinned dpkg, and no status stanza, conffile, payload or info residue remains after purge ([#328](https://github.com/cataggar/debz/issues/328)). |
| Interrupted postrm-only removal | `postrm-only-{remove,purge}-recovery-*`: a crash during the journaled staging publication (`during_database_publication`) leaves the payload and every `info/` script present. After staging, a crash at the first file removal (`mutation_target_remove`) and after the recorded `postrm remove` outcome (`after_removal_postrm_outcome`) leave every installed script staged. Re-entry is refused without mutation, and explicit recovery finishes the same remove or purge program with the complete root and trace of the terminal dpkg operation, without rerunning `postrm remove`. After an unrecorded `postrm remove` return (`after_removal_postrm_return_before_outcome`), recovery (`script_outcome_unknown`), remove and purge stay blocked without mutation; that root is **not** claimed as dpkg parity. |
| Trigger incorporation, awaited/noawait, deferred callback failure | `removal-interest-{await,noawait}-deferred-callback-failure` in `native_trigger_removal.zig`: `postrm remove` activates a named trigger; the deferred queue, failing `postinst triggered`, half-configured listener and subsequent explicit configure/purge match pinned dpkg, including actual callback counts and arguments. Existing `existing-unincorporated-queue`, `file-trigger-lifecycle`, `self-cycle-no-progress` and `two-package-cycle` compare queued work and the full no-progress terminal states; the latter now require a real callback with the expected trigger argument (dpkg may stop after one callback). |
| **Awaited activation** from postrm removal | `removal-activate-await-refusal` (historical fixture name): both roots retain the source in `config-files`, publish the receiver as `triggers-pending` with an incorporated, empty queue, then match after receiver callback and source purge. The real postrm executes once. Four interruption boundaries retain the bound owner, lock and program; an unrecorded postrm return blocks re-entry, while known outcomes recover without rerunning postrm. See [#301](https://github.com/cataggar/debz/issues/301). |

For a focused local run of the new lifecycle family:

```sh
reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"
zig build build-native-acceptance-zig -j2
sudo -n env TMPDIR="$PWD/.tmp" XDG_CACHE_HOME="$PWD/.cache" \
  zig-out/bin/native-lifecycle-zig-acceptance \
  zig-out/bin/native-lifecycle-fixture-driver --removal-only \
  --reference-dpkg "$reference_dpkg"
```

Add `--oracle-only` and omit the driver to compare two pinned-dpkg roots.
The standard `test-native-lifecycle-zig` and
`test-native-recovery-zig-parity` targets keep these cases in the full gate;
the focused selector never counts as that gate. No unsupported result is
retried against a failed root as if fresh.

Two clock exceptions are bounded and retain raw snapshots. During
double-postrm upgrade failure, only an explicitly selected recreated symlink
may have its original mtime or a timestamp inside the measured operation
interval; its kind, target, mode and owner remain exact. The pinned
`update-alternatives` scenario normalizes its timestamped log prefix and
permits its named links, database entries and log to retain creation times
from earlier phases of that scenario. Other payload mtimes and contents are
not normalized.

`zig build test-native-lifecycle-zig-oracle -Dnative-reference-dpkg="$reference_dpkg"`
exercises two real dpkg roots to establish fixture consistency. It is not
native parity evidence.
`--workspace` can retain diagnostics in a new directory directly under this
worktree's `.tmp`; ordinary runs clean up their temporary roots.

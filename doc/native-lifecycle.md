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

Statoverrides use file-backed target-root identities and are resolved once
before scripts, not separately at unpack and configure. A preinst or postinst
may change the account or override files, but the same invocation keeps its
original resolved metadata, matching dpkg. A later invocation uses the new
state. Missing identities refuse before lifecycle mutation. See the
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
receipt acknowledgment. The helper-aware variant embeds and stages trusted
helper bytes, probes namespace capability before package mutation, and records
the isolated helper binding in a v2 request. Missing targets are refused without
creating placeholders. `debz.native_runtime` now exposes the trusted-helper-only
typed execution/recovery/acknowledgment path; fixture controls remain private.
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

There is one narrow metadata normalization beyond the shared differential
oracle: during double-postrm upgrade failure, dpkg recreates a rollback symlink
at wall-clock time. Only that explicitly selected symlink may have its original
mtime or a timestamp inside the measured operation interval. Its kind, target,
mode, owner, and every other file remain compared; raw snapshots retain the
observed times. Ordinary payload mtimes are not normalized.

`tools/test-native-lifecycle.py --oracle-only`, run as root, exercises two real
dpkg roots to establish fixture consistency. It is not native parity evidence.
`--workspace` can retain diagnostics in a new directory directly under this
worktree's `.tmp`; ordinary runs clean up their temporary roots.

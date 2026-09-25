# Hermetic Debian-family integration roots

`zig build test-integration` builds a small deterministic repository, signs its
`InRelease` with the existing synthetic test-only OpenPGP key, and drives the
production CLI against disposable cache, state, and dpkg roots under
`.zig-cache/`. It never invokes apt against the host and never uses the host
dpkg database. Generated repositories are bounded to 8 MiB and contain no
network-derived input.

## Local prerequisites

- Zig 0.16.0 and liblzma development files;
- Python 3 with `cryptography`;
- `dpkg` for full/native lanes; native execution also requires Linux private
  mount-namespace privileges (use `DEBZ_INTEGRATION_SUDO=1` when needed).

Run one profile:

```sh
DEBZ_INTEGRATION_SUITE=debian-stable \
DEBZ_INTEGRATION_ARCH=amd64 \
DEBZ_INTEGRATION_MODE=smoke \
zig build test-integration
```

Accepted suites are `debian-stable` and `ubuntu-26.04`; architectures are
`amd64` and `arm64`; modes are `smoke`, `native`, and `full`. Full mode requires `dpkg`
and fails rather than skipping transaction assertions.
Refresh, planning, verified downloads, cache replay, payload validation, policy,
and reproducibility remain mandatory on every host. No qemu or foreign
executable is used. Foreign packages contain inert data only.
The native root's script-free helper fixture is reference-installed with
`dpkg --force-architecture` so foreign rows can seed its genuine package-owned
target. This is scoped to the disposable fixture root, not production native
admission or the host architecture database.

The core native planning lane resolves a real v3 lock, compares its repository
and package evidence with the legacy closure, verifies its independent digest
and backend-bound policy, and exercises cold download and cache-only replay.
It rejects v1 input and changed policy. A missing helper target refuses native
execution without changing package state or leaving an active root record.
The focused `native` mode and full lane use a real package-owned helper target
to exercise native install, exact-lock reinstall, no-op upgrade, retained-package
closure, receipt/evidence hashes, receipt-bound outer completion, and recovery
without repositories or cache/state access. A scripted package also exercises
automatically derived trigger authority, private helper invocation, coalesced
activation, and the final triggered postinst trace. This does not claim full
native transaction parity.

`zig build test-native-recovery` also compares the native public core CLI,
native package-family adapter, and reference dpkg across both signed fixture
suites. Its 28-row matrix covers Pre-Depends, versioned Provides, dependency
cycles, Recommends on/off, a Multi-Arch package, literal Linux package paths,
known inert control metadata, suite-specific trigger metadata,
upgrade-all, held unchanged updates, both conffile policies, and known script
failure. Plans must be identical for identical installed inputs; execution
compares payloads, package/trigger databases and script traces, then independently
checks retained native evidence and receipt-bound completion. The fixtures seed
a real package-owned helper target and require its bytes and inode to survive.
No-op results must not invent completion or provenance.

For a focused run, use
`zig build test-native-recovery -Dnative-consumer-parity-only=true -j2`.
It includes crash/restart cases around scriptless handler settlement, with
mixed scripted/scriptless handlers and original archives evicted before
recovery. Literal-path install/upgrade cases also cover filesystem publication,
completed file-trigger handlers, retained evidence, and refusal after a literal
conffile or retained old script changes during interruption. Upgrade recovery
compares staged old scripts with the original bound database, not the newly
installed version's metadata. The lifecycle runner separately compares literal
files, directories, hard links, symlinks and conffiles through install, upgrade,
reinstall, removal and purge with both conffile policies.
Known inert metadata additionally covers install/upgrade/remove/purge recovery,
binary retained blobs, exact modes and drift refusal. Lifecycle coverage checks
old/new control visibility, obsolete-member retirement, Multi-Arch stem changes
and failure/purge-retry behavior against dpkg.
The full required recovery jobs run this coverage in Debug and
ReleaseSafe on matching amd64 and arm64 runners. This is hermetic consumer
parity, not real vendor-snapshot acceptance or native-only production cutover.

## Support claims

The suite names identify fixture contracts, not downloaded vendor root
filesystems. Their signed repository identities and suite-marker versions
differ, so Debian and Ubuntu rows cannot collapse to aliases. PR CI requires
all four suite/architecture combinations in full mode on native amd64 and arm64
runners, including mandatory dpkg-root transactions. Scheduled/manual CI adds
foreign arm64 roots on amd64.

The repository exercises dependencies and Pre-Depends, alternatives,
versioned virtual Provides, Conflicts/Breaks/Replaces, Recommends policy,
Essential and Protected metadata, Multi-Arch, cycles, conffiles, triggers, and
a deliberately failing maintainer script. Full mode also injects cache
corruption. Transaction interruption, lock loss/contention, exact lock
verification, held-package policy, timeout, recovery-state transitions, and
atomic provenance publication use the production executor/recovery seams and
their mandatory Zig tests; they do not require unsafe process killing in a
black-box shell test.

Repository generation is byte-reproducible: fixed archive metadata, package
ordering, signing key, signature time, Release timestamps, and compressed
members produce identical repository and provenance digests. The Release
validity window is fixed from 2024 through 2037. CI retains full-lane root,
cache, state, and provenance artifacts for seven days.

The real-snapshot candidate is selected explicitly with
`--transaction-backend native`; omission can never route this acceptance
through the default legacy executor. The opt-in `ubuntu-real-snapshot` job in
the existing manual `.github/workflows/ci.yml` dispatch runs on
`ubuntu-24.04` amd64 and `ubuntu-24.04-arm` arm64 against
`https://snapshot.ubuntu.com/ubuntu/20260923T000000Z`, suite `stonking`,
component `main`, and the explicit Ubuntu archive keyring. Inputs remain fixed to that reviewed snapshot until its signed validity
window requires a fresh reviewed pin.
Local runs may explicitly set `DEBZ_REAL_SNAPSHOT_KEYRING` to an absolute,
regular, non-symlink Ubuntu archive keyring instead of installing trust material
on the host. The authenticated lock must identify the reviewed Ubuntu 2018
archive signer `F6ECB3762474EDA9D21B7022871920D1991BC93C`. Workspaces must be new;
an existing root is never reused or reset by this script.

The native side begins with only an existing empty directory: no dpkg
database, helper placeholder, package state, merged-/usr links, or private
debz namespace is pre-created. It authenticates metadata, resolves a genuine
v3 lock, and can bootstrap the private trigger helper only from the exact
authenticated `dpkg` archive and final owner evidence. Candidate commands are
optionally exec-traced and fail if they launch `dpkg` or `dpkg-deb`.
The isolated oracle is the architecture-pinned dpkg 1.22.22 payload prepared
under `.cache`; its executable and receipt are reverified before reference
execution. Python is transport for that reference artifact, not the
comparison authority. The reference step independently verifies each
authenticated lock archive against its SHA512 CAS identity, initializes only
the separate oracle's dpkg database, stages exact-lock interpreter/tool
payloads for the chroot, attempts to install the closure with the pinned dpkg,
and captures its root only on success. The candidate root is never seeded from
the reference. The pinned dpkg reference probes prerequisite and configuration
readiness before each package phase, without `--force-depends`; at a stall,
it lets dpkg configure a dependency cycle together, accepting only deferred
dependency failures and checking the resulting database state. Maintainer
scripts see `/proc` mounted only in a private mount namespace, which is gone
before capture. A fresh amd64 rehearsal configured all 175 packages, processed
pending triggers, and captured the healthy reference root. The reference-only
`dev/null` chroot device is excluded from both bounded captures only when no
package claims it; no package payload path is excluded.
`test/real-snapshot-comparator.zig` is the equality authority for the bounded
filesystem and normalized dpkg
status/info/trigger/diversion/statoverride/alternatives sections. It compares
package-owned regular-file timestamps and every payload digest. It ignores
clock-derived timestamps on unowned files and symlinks and the contents of
three explicitly unowned runtime products (`etc/machine-id`,
`var/cache/ldconfig/aux-cache`, `var/log/alternatives.log`); their presence,
size, mode, ownership, and captured hashes remain recorded, and a package
claim on any of those three paths fails comparison. Two independent healthy
amd64 dpkg roots compared successfully under these rules. Missing
either capture or any mismatch fails the manual job; the always-run cleanup
retains available diagnostics even after earlier failure.

This gate is not a completed parity claim until both architecture captures
compare successfully. The previously pinned `resolute` release is frozen with
an InRelease dated 2026-04-23 and expired under the finite policy. The newly
pinned `stonking` release advertises Date 2026-09-22 and Valid-Until
2026-10-06; repository authentication must verify those signed fields
before planning. The repository config explicitly selects
`allow_missing_valid_until_with_max_age_seconds` with the unchanged 31-day
maximum. That policy is part of normalized repository identity, authenticated
snapshot provenance, and exact-lock identity. Current exact-lock v3 and
acquisition contracts support the SHA512-only Release, Packages, and archive
identities published by `stonking`; no fabricated SHA256 or historical-time
replay is allowed. Full install/reinstall/upgrade/remove/purge, crash/restart,
archive-evicted recovery, and passing native/reference comparisons still
require executed evidence from both architectures.

The authenticated amd64 offline replay now publishes `libpam-runtime`'s
`PAM.7.gz` file and `pam.7.gz` symlink as two distinct entries in their
existing case-sensitive directory. Each publication has a journal-bound,
read-only exact-parent witness and atomic no-replace semantics. A real
casefold-ext4 Zig regression refuses the same pair before mutation; Zig
crash tests restore both spellings across the two publications. Later
packages may retain the installed pair only when its one untouched owner
and two distinct on-disk inodes are observed again. The replay proceeded
past the remaining unpack steps but stopped during configuration step 665:
the `init-system-helpers` postinst launcher recorded `setup_failed` at
`fork` (`ENOMEM`), followed by `recovery_required: invalid_transition`.
This interrupted root is retained, not reused. Neither an amd64 completed
closure nor an arm64 native/reference comparison has passed yet; the manual
parity gate remains fail-closed.

A subsequent fresh-root replay was stopped at step 566 when the installer
reached over 31 GiB resident memory. Progress journal reads and appends were
using a lifecycle-long scratch arena, accumulating whole-history temporary
allocations across steps. An initial progress-allocator-only rerun still grew
past 14 GiB by step 530; unpack trigger discovery also retained temporary
whole-database snapshots and route-settlement allocations across packages.
A second rerun with scoped trigger snapshots also reached 14 GiB: the CLI
still passed its process-lifetime argument arena to the native backend, so
deferred frees could not return memory. Native CLI execution now uses the
deallocating process allocator for native runtime phases, retaining the
command arena for API results; transient progress and trigger work is scoped
separately. A fresh-root replay then passed step 665: the
`init-system-helpers` postinst exited successfully. Its sampled peak resident
memory stayed below 566 MiB through step 708, where `mawk`'s postinst stopped
before launch with `InvalidAlternativesTool`. That interrupted root is
retained, not reused; neither completed closure nor native/reference parity
has been established.

A subsequent authenticated fresh-root replay with the exact amd64
`dpkg` 1.23.7ubuntu2 `update-alternatives` pin and staged
`README.dpkg-new` guard passed step 708: `mawk`'s postinst exited
successfully. It reached step 822, where `base-files`' preinst also
exited successfully, then refused its unpack with
`recovery_required: ownership_conflict`. The incoming archive claims
`/lib -> usr/lib`, but the already-installed `ubuntu-pro-client` lists
`/lib` as an owned directory on the same merged-/usr root. The
sampled peak resident memory was 872.4 MiB. This interrupted root is
retained, not reused. An exact, journal-guarded sharing rule for a
byte-identical structural alias claim addresses that refusal, but it
still requires a new replay on the rebased combined code.

That new authenticated replay passed the former step-823 ownership
refusal: `base-files` unpack published its exact archive payload, and
configuration proceeded to step 852. Its postinst then exited 1 with
`chown: invalid user: 'root:root'`. The fresh root has no
`etc/passwd` or `etc/group` yet; this transaction schedules
`base-passwd`'s unpack after this configuration barrier. Sampled peak
resident memory stayed below 883 MiB. This interrupted root is
retained, not reused. A completed closure and native/reference parity
still require a correctly ordered fresh-root replay.

With the local fresh-root account ordering and exact `less` preinst gate, a new
authenticated 175-package amd64 root completed `base-passwd.postinst` at
step 830, `base-files.postinst` at step 862, and `less.preinst install` at
step 878 (each with a persisted zero-exit outcome). It then refused
`less.postinst configure` at step 888 before launch with
`InvalidAlternativesScript`. The authenticated `less` archive's postinst
SHA-256 is
`a33a1e6ef5a22e63a66e42853fc0bcff3107b4653d7b5cea891354a5f28db6c4`;
its literal `--quiet --install` command is reviewed in the
[alternatives reference](dpkg-alternatives-reference.md#native-admission).
This failed root remains untouched. Authorization of the exact script
requires another new authenticated root to identify any subsequent blocker;
none of these intermediate successes establishes complete parity.

A separate fresh-root replay, using a newly authenticated 175-package SHA-512
lock, the reviewed archive signer, and a longer bounded install window,
persisted a zero-exit `less.postinst configure` outcome at step 888. Its
`pager` record selects `/usr/bin/less` at priority 77 with the
`pager.1.gz` slave, and the generic and selector links target the expected
paths. Execution continued until step 976, where `bash` 5.3-3ubuntu1
`postinst` (SHA-256
`e9afaa3227a21e68002bd60a88e054d8f98d2d0e548d1d690c9bba5c3c9577ff`)
was prepared but refused **before launch** with `InvalidAlternativesScript`.
That authenticated script uses a multiline `update-alternatives --install`
for `builtins.7.gz`, followed by `|| true`; this shell wrapper is outside the
reviewed literal-command grammar. Neither interrupted root is reused; the
new refusal does not establish full amd64 native/reference parity.

The signed `bash` archive and exact script bytes are now reviewed separately
in the [alternatives reference](dpkg-alternatives-reference.md#native-admission).
The exception binds one command and its `|| true` tail to that script,
`bash:amd64` 5.3-3ubuntu1, new-package `postinst configure` arguments
`["configure", ""]`, and the snapshot tool. It does not disable
script-outcome checks or permit general shell wrappers. A **new** authenticated
root is required to determine whether execution passes step 976; the
interrupted step-976 root cannot be resumed as a fresh trial.

That new authenticated 175-package amd64 root persisted a zero-exit
`bash.postinst configure` outcome at step 976. Its `builtins.7.gz`
alternatives record selected `/usr/share/man/man7/bash-builtins.7.gz` in auto
mode at priority 10, with the expected generic and selector symlinks.
Execution reached step 1026 and launched `netcat-openbsd` 1.238-1
`postinst` (SHA-256
`81abc862db99e322e5d6cda436769bc21b9394ce287ea35d057761b6313cb6ef`),
but refused the resulting alternatives transition with
`AlternativesStateChanged` before persisting a script outcome. Its signed
script registers `nc` with three slaves. The command lists `netcat` before
`nc.1.gz`, while the resulting record puts `nc.1.gz` first; the native typed
registration had preserved command order. A disposable pinned-dpkg 1.22.22
install of the **exact signed script**, plus a separate snapshot-tool probe,
reproduced the interrupted root's 221-byte `nc` record (SHA-256
`2d38af8c8cc5565fd092c8e7b09cb8517eb5347616141b3e7d92034386671c4e`)
and all eight links. Both tool versions sort slaves bytewise by name and
retain each older candidate's slave targets by name when adding a slave.
Native registration now models that sorted record without waiving strict
before/after transition checks or admitting additional scripts. This
interrupted root is retained and not reused; only a **new** authenticated
root can show whether step 1026 now settles. Complete amd64 install and
native/reference parity remain unproven.

The new fresh amd64 root at
`.real-snapshot/amd64-netcat-fresh-long-2` used a newly resolved lock (file
SHA-256 `da34756c986eab0ae3744c3021f2d1e1609e81333af3ba52481d1c48924e75c8`),
the reviewed archive signer, and 175 independently reverified SHA-512 package
objects. Its `netcat-openbsd.postinst configure` at step 1026 **ran and
persisted exit 0**, with the pinned 221-byte `nc` record and all eight
generic/selector links. It continued through step 1062, then refused
**before launch** at step 1065 with `InvalidAlternativesScript` for
`procps:amd64` 2:4.0.6-3ubuntu1 `postinst configure` (signed script SHA-256
`7c2ba424ad233bd238474b9d6e565a719fbd6902fd75f617bc3e6e915084c9d3`,
arguments `["configure", ""]`). That script builds several `--install`
commands inside a parameterized `check_alternatives` function. No procps
script outcome was persisted; the failed root is retained for recovery and
must not be reused as a fresh run. A separate earlier fresh workspace
(`amd64-netcat-fresh-long-1`) was abandoned before package execution after
using inconsistent planning/install deadlines, which made its exact-lock
repository unavailable; it was never retried. The step-1065 refusal is the
next distinct blocker, **not** complete closure or native/reference parity.

The signed `procps` archive and exact configure branch are reviewed in the
[alternatives reference](dpkg-alternatives-reference.md#native-admission).
Pinned dpkg 1.22.22 configured the signed script without alternatives changes
in a disposable copy of the failed root because all four `.procps` providers
were absent. An isolated provider-present control registered `uptime`, so
native authorization is restricted to this specific digest, package, version,
new-script configure arguments, snapshot amd64 tool, and a checkpointed
**absence** of each provider; all existing alternatives groups are immutable.
The step-1065 interrupted root remains untouched. Only another **new**
authenticated root can establish whether this refusal is resolved; that
subsequent run is recorded below.

The new root `.real-snapshot/amd64-procps-fresh-long-1` resolved another
signed 175-package SHA-512 lock (file SHA-256
`6b92c0dbb16a73145368e9d1b5b66feade6cf94efafdeeed001b79d25339e7e5`)
with the reviewed Ubuntu archive signer; all 175 objects were reverified.
Its `procps.postinst configure` at step 1065 **ran and persisted exit 0**,
and all four guarded alternatives groups remained absent. The next refusal
is **before launch** at step 1145, `sudo-rs:amd64` 0.2.14-1ubuntu2
`postinst configure` (SHA-256
`a7c37986e0ad87565b1639a0131f7b382aac7e637c20a606d8258f314737ea17`)
with `PartialAlternativesState`. Its proposed `sudo` alternatives group
does not yet exist, but the `sudoedit` slave's generic link
`/usr/bin/sudoedit` is already a `sudo` package-owned symlink to `sudo.ws`.
No step-1145 script outcome was persisted; the last stable action is
step 1145, substep 0. The root is retained and must **not** be reused as a
fresh trial. This is the next distinct blocker, not a completed closure or
native/reference parity result.

The signed `sudo-rs` postinst and pinned dpkg 1.22.22 were probed in
**disposable copies** of that root. Both `/usr/bin/sudoedit -> sudo.ws` and
`/usr/share/man/man8/sudoedit.8.gz -> sudo.ws.8.gz` are exact signed
`sudo` package-owned symlinks; the `sudo` alternatives record and selectors
are absent. Pinned dpkg configures `sudo-rs` successfully, replacing both
links and registering the six-slave priority-50 group. Its `set_perms`
calls change only the ctimes of the setuid cargo `sudo` and `su` binaries.
The [alternatives reference](dpkg-alternatives-reference.md#native-admission)
records the exact archives, script, record digest, narrow structural-link
exception, scoped ctime checks, and unchanged failure/recovery boundary.
The interrupted procps-root was not retried or modified.

A separate **new** root,
`.real-snapshot/amd64-sudo-rs-fresh-long-1`, authenticated the reviewed
Ubuntu signer, reverified all 175 signed SHA-512 package objects, and used
one consistent 10,800,000-ms refresh/plan/download/install deadline. It
resolved a new lock (file SHA-256
`07f096da1a1fa614dc73e1797ff0b8cab917a59ce9d6dba400f64473ca24420a`).
It persisted exit 0 for less.postinst step 888, bash.postinst step 976,
netcat-openbsd.postinst step 1026, procps.postinst step 1065, and the exact
sudo-rs.postinst step 1145. The resulting 464-byte priority-50 `sudo`
record has SHA-256
`4f50d77a8e6f76e51745762486caec36324433ea7b09aac48274624c70e46da6`,
identical to pinned dpkg; both package-owned `sudoedit` generic symlinks
were replaced by links into `/etc/alternatives`. This evidence establishes
the step-1145 transition only, not complete native/reference parity.
The same run subsequently returned `native recovery_required: case_alias`
during the **unpack** of `libpam-runtime:all` 1.7.0-5ubuntu4 at step 1173
(archive SHA-512
`3f957eea17e67a3ac263667d62c2f292c684fb28b6bb282ec60cf01559bfaf960528695c3e674e7e350830bb9ed35eb31612d920f505e05b78cc48cd06ea2edf`).
The signed archive contains both
`usr/share/man/man7/PAM.7.gz` (regular) and
`usr/share/man/man7/pam.7.gz -> PAM.7.gz` (symlink). Its last stable
managed action is the preceding database step 1172, substep 0; the
step-1173 root is interrupted, retained for recovery, and **must not** be
reused as a fresh installation. Step 498 had already materialized the same
signed artifact 89 and application digest
`b75ab6b532a2b24afb44cb73d94f9968bc09ab27e730f8f506ed80f550e14a10`;
the retained database marks `libpam-runtime` unpacked and assigns both
spellings to it. The retained root has separate regular-file and symlink
inodes under the modeled parent. In a separate disposable chroot, pinned
dpkg 1.22.22 unpacked that authenticated archive twice, retaining both
distinct spellings and their matching package ownership. The native planner
now admits **only** this bounded bootstrap-to-dependent-re-unpack transition
when both children still exactly match the signed content, link target and
metadata, with the same sole owner and distinct inodes. It deduplicates
repeated folded-pair sightings without admitting a third spelling; journaled
parent/witness guards still precede each replacement and recovery.

A **different fresh** amd64 root,
`.real-snapshot/amd64-case-alias-late-fresh-long-3`, authenticated the same
reviewed signer and separately rehashed all 175 SHA-512 package CAS objects.
Its exact-lock file SHA-256 is
`591146847e5659dbcc26cef3c3d9bffc7bdb4b40513f3474c0278dea26a34149`.
With one 10,800,000-ms deadline for refresh, plan, download and install,
all five durable substeps of `libpam-runtime` unpack step **1173** completed.
The two PAM man-page entries still have distinct inodes (regular
`1375536106`, symlink `1384285199`); the file's SHA-256 remains
`29b81aafe87370274266fdc7c008ef09b799bd712f46c58b1e6c846cc46f6530`.
The same root subsequently persisted `libpam-runtime.postinst` exit 0
at step 1215 and its installed state at step 1216. The **next distinct
blocker** is step 1217: authenticated `keyboard-configuration:all`
1.248ubuntu3 preinst SHA-256
`2633dc09bf75db633726ab7e2fff9d8a29fe06f53e3c5915f9221ffef57a8703`
launched with `install`, exited 10 without output, and its `abort-install`
postrm exited 0. The executor returned
`native recovery_required: package_already_present` after the unwind. This
root's last durable action is step 1217 database substep 0; step 1218 did not
run. It is interrupted and retained for diagnosis/recovery, **not** reusable
as a fresh installation. Neither full amd64 closure nor arm64/reference
parity has passed.

The exact authenticated keyboard archive (SHA-512
`e69402c6d44c6715e165868b1824da00485403b8157b18235945627fead82710e812c7d4b350e5a3d89444816e769ac5dc883886f905e446aecca123bb7b72db`)
and pinned dpkg 1.22.22 were examined in an isolated disposable root with
independently verified signed bootstrap tools. Pinned dpkg's unpack completed
the keyboard preinst and registered `keyboard-configuration/toggle`; the
single-package oracle used `--force-depends` **only** to isolate the preinst
from packages missing in that oracle, not as a claim about full-closure
dependency parity. In controlled chroot probes against the earlier native
debconf database, the private preinst path without adjacent templates exited
10; the installed-info path and the private path with the exact signed
templates sibling both exited 0. The only staged addition is that authenticated
templates member, tied to its exact preinst and bootstrapped installed owner;
no arbitrary debconf frontend/config execution is admitted.

A newly resolved and independently SHA-512-rehashed 175-package root,
`.real-snapshot/amd64-keyboard-fresh-long-1`, confirmed the **first** staging
attempt did not solve step 1217: the package's scripts had already been staged
by its early bootstrap, so the later preinst staging call returned early and
did not add its adjacent templates. Its preinst again exited 10; abort-install
postrm exited 0. The failure-settlement database published
`install reinstreq half-installed` with the package files still claimed, but
the operation subsequently returned `native recovery_required:
invalid_transition`. The retained trigger event includes
`keyboard-configuration:all` activating `libc-upgrade` for `systemd`, which
remains `unpacked`; its transition to `triggers-pending` is forbidden by the
existing database state contract. Do not relax that transition to force a
terminal failure receipt: this root is **interrupted**, not a fresh retry or
a demonstration of full trigger-bearing failure parity. The corrected implementation
stages the signed templates in a distinct journaled preinst phase even when
other scripts were staged at bootstrap.

A second independently planned, downloaded and SHA-512-rehashed **new**
175-package root, `.real-snapshot/amd64-keyboard-fresh-long-2`, used the
corrected template stage and completed the exact keyboard preinst at step
1217 with exit 0 and zero output
(`native-script-outcome-v1-script-1217-0-0.json`). Its keyboard status was
`install ok installed`. This is **not** a full-root success: step 1230
`iproute2:amd64` 6.19.0-1ubuntu2 postinst SHA-256
`bb5318e85da2497d1b2b6fcdf2d612bd02ec54bc5d9f86005506d8e91bb79d3a`
with `["configure", ""]` exited 10, zero output; the journal recorded
`script completed failed` and the subsequent database action completed, but
the operation returned `native recovery_required: invalid_transition`.
The installed script has that exact hash, sources `confmodule` and calls
`db_get iproute2/setcaps`; an installed `iproute2.templates` file exists.
The precise cause of exit 10 and the secondary transition are not yet proven.
Preserve this interrupted root; investigate that distinct script failure and
secondary transition separately, not by replaying this root as fresh.

After rebuilding the final ReleaseSafe candidate with the bootstrap-staged
config integrity check restored, a **third** newly refreshed, planned,
downloaded and independently SHA-512-rehashed 175-package root,
`.real-snapshot/amd64-keyboard-fresh-long-3`, reproduced the result. Its
signed lock matches the second root, and `evidence/identity.txt` records the
final binary. Step 1217 again completed the exact keyboard preinst with exit
0, zero output and `install ok installed` status; step 1230 again recorded
the same `iproute2` postinst exit 10 and zero output, followed by a completed
failure-state database action and `native recovery_required:
invalid_transition`. Its `evidence/create.json`, script outcome files and
execution journal are retained. This third root is **also interrupted**, not
proof of completed amd64 installation; neither interrupted root is a fresh
retry target.

The `iproute2` archive was independently rehashed against the third signed
lock (SHA-512
`56ec4c51d91cbcea3a1270ee13eb0ff79c92bb2cba844af4efac3e6601e21392ab53167c8b51694054e5dd93d0d27cf90178cb9999c18d98aefc556306be7e34`).
Its exact postinst and root-owned 15912-byte templates member match the
installed info copies; the templates SHA-256 is
`33e0ed65a34dbb3a951613c64ac9a71b268eaa2b3827cdd6378875e54112bf46`.
Separate disposable *diagnostic copies*, never used as fresh authenticated
roots, isolated the frontend: private postinst without adjacent templates
exited 10/zero output; with that exact sibling and dpkg's script environment
it exited 0/zero output. Pinned dpkg 1.22.22 configured the installed-info
copy with exit 0 in the diagnostic copy. These probes identify the cause of
the script refusal, not a successful native closure.

The separate `invalid_transition` followed a completed journaled
`iproute2` `half-configured` failure-state publication. Its unincorporated
`libc-upgrade` event named `systemd`, still `install ok unpacked`;
the serial branch lacked #231's previously proven guard against scheduling
an unconfigured trigger listener. That guard is restored without changing
the typed transition table. Pinned dpkg failed-postinst reference fixtures
confirm awaited and no-await activations leave an unpacked listener unchanged.
Only a **new** independently authenticated root can establish the next
native execution boundary.

Two **new** roots, `.real-snapshot/amd64-iproute-fresh-long-1` and
`.real-snapshot/amd64-iproute-fresh-long-2`, each refreshed, planned,
downloaded and independently rehashed all 175 SHA-512 archive objects under
the reviewed Ubuntu signer. Both completed keyboard preinst step 1217
and the exact `iproute2` postinst step 1230 with exit 0 and zero output;
`iproute2` reached `install ok installed`. The second root used the final
formatted ReleaseSafe binary recorded in `evidence/identity.txt`; its
signed lock fingerprint and CAS rehash are retained separately from the first.
This is **not** a completed 175-package installation. Both roots next refused
before script launch at step 1243: `util-linux:amd64` 2.41.3-3ubuntu2
postinst SHA-256
`31f01940fe6aa22a9b35b54029eb5e4dd4ea5146dd2bacdb495d0d37eb210fc9`
with `["configure", ""]` hit `InvalidAlternativesScript`. The final journal
has only a `script prepared` action for that step, no script outcome.
The signed script contains an `OS=linux` guard and a multi-line
`update-alternatives --install` of the `pager` group with its manpage slave;
its exact archive SHA-512, control-member bytes, and installed script digest
were independently checked. The non-command `command -v update-alternatives`
guard is what the literal-command parser refused. Pinned dpkg 1.22.22,
using the snapshot-pinned alternatives tool, configured the script in a
disposable copy after re-unpacking the signed archive; its pager record and
selectors matched a separate direct pinned-`update-alternatives` 1.22.22
probe byte-for-byte. The [alternatives
reference](dpkg-alternatives-reference.md#native-admission) documents the
exact identity, branch, resulting record, and narrow script/tool admission.
Both interrupted roots and their durable claims are retained; neither is
reusable as a fresh root, and neither proves full amd64 parity.

A different **new** root,
`.real-snapshot/amd64-util-linux-fresh-long-2`, refreshed the reviewed
`stonking` snapshot, resolved an independent 175-package SHA-512 lock
(file SHA-256
`6f56ebfd7a787ea006ed08be9215ad9b50522f377349883f3a08fbcd94d15275`),
and separately rehashed all 175 downloaded CAS objects. Its exact signed
`util-linux.postinst` at step 1243 **launched**, persisted an exit-0
outcome, and reached `install ok installed`. The 154-byte `pager` record
has SHA-256
`efb067c8704b11530e836705a78bbfdacbe298b9d13df3a01e1f84ca794747a9`,
identical to both pinned reference probes; both selector links still point
to `/usr/bin/less` and its manpage. This proves only that transition,
not the entire root.

The next distinct refusal is **before script launch** at step 1292:
`console-setup-linux:all` 1.248ubuntu3 new-package `postinst` SHA-256
`5ab31be5894edd94864e54a95d2cbebd46b2b934bffa76a764fc5a52f2915e6a`,
arguments `["configure", ""]`, returned `InvalidAlternativesScript`.
The archive was rehashed against the same signed lock (SHA-512
`b5ad0ebf1b9a526b5af67422b720b29b4e2738ebd945871223bef8241e59b47558f51a31e9638b8e5ce84ea1b42334682f86f9c3d62de224e7c55caa7a5e0f14`);
its installed and archive scripts match. After `CONFIGDIR=/etc/console-setup`,
the script contains two `update-alternatives --install /etc/vtrgb vtrgb
"$CONFIGDIR/vtrgb"` (priority 50) and `"$CONFIGDIR/vtrgb.vga"` (priority 20)
commands, outside the literal grammar. The final journal entry is only
`script prepared` at step 1292 and no outcome file exists. This root is
interrupted, retained for recovery, and **must not** be reused as fresh.
The earlier `.real-snapshot/amd64-util-linux-fresh-long-1` stopped after
authenticated refresh because a diagnostic invocation used an unsupported
`resolve-lock` command; it never planned or executed a package.

The signed console-setup archive, installed postinst, two signed `vtrgb`
provider files, and exact package ownership list were separately verified
against the lock and retained root. In disposable **copies** of that root,
pinned dpkg 1.22.22 re-unpacked and configured the archive, while pinned
`update-alternatives` 1.22.22 executed the corresponding two literal
registrations independently. Both produced the same 78-byte record
(SHA-256 `1fe9c0439ed1d49f6e06fad9d0a4ece1fba6826116f5cf26ba98e313c36570d3`)
and `/etc/vtrgb` selector chain, selecting priority-50
`/etc/console-setup/vtrgb`. Native admission is bound to the exact signed
postinst, fresh `console-setup-linux:all` identity, amd64 configure
arguments, snapshot tool, signed providers, and an absent `vtrgb` group.
The [alternatives reference](dpkg-alternatives-reference.md#native-admission)
describes the fail-closed authority and success-state requirements. The
interrupted predecessor root remains untouched; only another new signed
root can show whether step 1292 now succeeds.

That **new** root,
`.real-snapshot/amd64-console-setup-fresh-long-1`, resolved a separate
175-package authenticated amd64 lock (file SHA-256
`02d84b6867204a7a4c28402f30909bb42dd60f3df411f8db918555d1da03a3d6`)
and independently rehashed all 175 downloaded SHA-512 archives. Its exact
`console-setup-linux.postinst` at step 1292 **launched** with
`["configure", ""]`, durably exited 0, and reached `install ok installed`.
The resulting 78-byte `vtrgb` record has SHA-256
`1fe9c0439ed1d49f6e06fad9d0a4ece1fba6826116f5cf26ba98e313c36570d3`,
byte-identical to pinned dpkg and pinned `update-alternatives`; the generic
and selector links resolve to the signed priority-50 `vtrgb` provider.

This is **not** a completed install. During deferred trigger processing
at step 1428, libc-bin, debianutils and libselinux1 triggered postinst
callbacks persisted exit 0. The next callback, ordinal 3, was only
`prepared`; no outcome exists. `procps:amd64` 2:4.0.6-3ubuntu1 has
`Triggers-Pending: /usr/lib/sysctl.d` and a bound postinst SHA-256
`7c2ba424ad233bd238474b9d6e565a719fbd6902fd75f617bc3e6e915084c9d3`.
Its exact script exits the `triggered` branch before any alternatives
command, but the existing snapshot procps authorization admits only
`["configure", ""]`. The attempted
`["triggered", "/usr/lib/sysctl.d"]` callback therefore refused **before
launch** with `InvalidAlternativesScriptAuthority`; no other pending
postinst contains an alternatives command. The root and all its durable
trigger claims are retained for recovery, **never** reused as fresh.

In a disposable **copy** of that interrupted root, pinned dpkg 1.22.22
processed only the exact pending procps trigger with exit 0 and left every
alternatives record and selector unchanged. The signed callback exits its
triggered branch before alternatives commands; `/proc/sys` was absent,
so its conditional `sysctl` action was unreachable. Native admission now
requires the exact compiled handler, `["triggered", "/usr/lib/sysctl.d"]`,
snapshot tool, all four absent `.procps` providers, absent `/proc/sys`,
and immutable alternatives checkpoints. A new, independently authenticated
root `.real-snapshot/amd64-procps-trigger-fresh-long-1` authenticated the
reviewed signer, independently SHA-512-rehashed all 175 archives against
its newly resolved lock (file SHA-256
`c518a6a265e68857a603c9e47c807cab2bf0db2728451a495e37b5bcb03a4243`),
and persisted the exact procps trigger at step 1428, ordinal 3, with
`["triggered", "/usr/lib/sysctl.d"]`, exit 0 and zero output bytes. Its
script journal records `outcome exited` and `completed succeeded`, followed
by a completed database transition; `procps` ended `install ok installed`.
The snapshot `vtrgb` record remained byte-identical to pinned dpkg.

**This is not a successful install**: earlier in the same new root,
`console-setup:all` 1.248ubuntu3 `postinst configure` at step 1297
(script SHA-256
`e64fb42e4d5e120dfdb889b00aa747ee00ef6c31bf8edcd3230de33f1823d19d`)
actually exited **10**, with zero output bytes. Its journal records
`completed failed`, and the package remains `install ok half-configured`.
The transaction processed its deferred trigger callbacks, including procps,
then published a terminal **failed** receipt (`install` exit 7,
`failed_after_mutation`). The root is retained as a failed transaction,
never reused as fresh. The console-setup exit is the next separate
authenticated blocker; its cause and pinned-dpkg parity are not established
by this procps admission.

The historical legacy capture workflow ran
`tools/capture-vendor-state.py` against the explicitly named staged reference
root. The architecture-tagged [v1 JSON
schema](../schema/vendor-state-inventory-v1.json) inventories every
`var/lib/dpkg/info` member by classification and bounded metadata/hash,
including `*.config`, `*.alternatives`, and all unclassified members. It also
inventories bounded regular records under `var/lib/dpkg/alternatives` and the
root-confined filesystem paths and symlink chains referenced by alternatives
state. Outside `etc/alternatives`, `etc` targets must be package-owned according
to captured dpkg ownership lists, while an unowned alternatives link must point
into `etc/alternatives`. Descriptor-rooted, no-follow traversal rejects races,
hard links, special files, cycles, undeclared link targets, traversal, sensitive
or ambient installation namespaces, malformed text, and every count, path,
integer, or byte-limit overflow. The capture records no file contents,
hostname, timestamp, environment, or absolute workspace path.

The reviewed amd64 and arm64 captures from workflow run
[`35500920816`](https://github.com/cataggar/debz/actions/runs/35500920816) at
commit `193887f0e45dc35a25768f8e58daa98318daddc9` are pinned under
`tools/fixtures/vendor-state/`. `index-v1.json` binds the immutable snapshot,
workflow run and jobs, source commit, downloaded artifact sizes and SHA-256
digests, manifest sizes and SHA-256 digests, capture schema version, and
inventory totals. Tests revalidate the manifests against the schema and
capture classifier, require canonical ordering and bounded totals, inspect
every recorded path, and reject credential patterns or ambient host
namespaces.

Each pinned architecture has 829 control members, 14 alternatives database
records, 189 requested linked paths, and 190 linked entries. The control
inventory includes seven `*.config` members and no `*.alternatives` or
unclassified members. Both architectures have the same classification counts,
alternatives records, requested paths, and linked-path topology; their
architecture-qualified control paths pair exactly, while expected package
metadata and ten linked executable hashes differ. These references document observed vendor state. Native alternatives admission
uses the separately executed oracle because the inventory alone lacks record
bytes and mutation causality; unclassified vendor metadata remains guarded.
The lane is manual because of bandwidth, but release
acceptance requires dispatching it successfully; it does not replace
deterministic PR CI.

The deterministic [vendor-state reference
specification](../schema/vendor-state-reference-v1.json) is committed as
`tools/fixtures/vendor-state/reference-v1.json`. It is derived only from the
two reviewed manifests and their index:

```sh
python3 tools/derive-vendor-state-reference.py \
  --index tools/fixtures/vendor-state/index-v1.json \
  --check tools/fixtures/vendor-state/reference-v1.json
```

The reference binds index SHA-256
`682bff167a4bc2386ceb78fb554be0adbe6fbfab16f4eab77aff3b63af04dd34`
and manifest SHA-256 values
`9ae81ea204a2cf608860451a41d477068a11ab77e8762e61e53d95bc0a70570b`
(amd64) and
`90698d5a1eae643dfc68a0acbb38cca48b98b297453fdc5d1a10509c792fa16c`
(arm64). The canonical reference SHA-256 is
`73228f959a335956c58d48712c891ccc372082dfc4f78f4405c18a37f98efe08`.
Regeneration validates every source digest, the fixed capture limits, canonical
ordering, count/byte/path bound, classification, requested-path resolution,
symlink target, public-path privacy boundary, and terminal linked identity
before emitting canonical JSON.

The paired reference accounts for every item in each manifest. Of the 829
control members, 664 are already-supported typed package-database or lifecycle
state, 158 are bounded inert `templates`/`shlibs`/`symbols`, and the seven
debconf `*.config` scripts are the input to the separate direct-dpkg reference
oracle. There are
zero package `*.alternatives` and zero unclassified members. The 14
alternatives records produce 72 current relationships (14 masters and 58
slaves), 189 complete requested-path resolutions, and all 190 linked entries:
145 symlinks and 45 regular files, including the inert
`etc/alternatives/README`. Each group records the observed record identity,
declared paths, master/slave selectors, selected target topology, and linked
path kind, metadata, target or digest. Package/provider ownership,
auto-versus-manual selection, priorities, candidate registration rows, and
mutation causality are explicitly `not-captured` or
`reference-execution-required`; none is inferred from names or hashes.

Cross-architecture pairing records all 422 architecture-qualified control
paths and the exact 275 control-content differences: 140 checksums, one
conffiles member, 28 maintainer scripts, 94 ownership lists, nine retained
metadata members, and three trigger members. Alternatives records and topology
are identical. Exactly ten regular linked targets differ in size and SHA-256.
Difference entries index the authoritative per-architecture facts above rather
than duplicating them in the generated fixture.

The [direct-dpkg config reference
schema](../schema/dpkg-config-reference-v1.json) and canonical
`tools/fixtures/vendor-state/dpkg-config-reference-v1.json` bind dpkg 1.22.22
and both executable/archive pins, the index, both manifests, the derived
reference digest, and all seven package/config identities. The seven vendor
facts and the pinned dpkg package are available for amd64 and arm64, and the
v1 lifecycle observation is executed and published for both. The common
amd64 observation is stored once; 78 sorted JSON-pointer replacements
reconstruct the exact arm64 result. Those differences are 45 architecture
fields plus six sizes and 27 SHA-256 values derived from
architecture-qualified package/status/info bytes. Commands, exits, traces,
maintainer-script environments, config non-execution, package states, journal
semantics, and frontend exclusion are otherwise identical.

The elevated `tools/dpkg-config-reference.py` runner invokes only the pinned
dpkg binary against guarded disposable roots. Its deterministic Python
archive builder does not invoke host `dpkg-deb`; generated package archives,
control members, and installed info members are digest-, size-, mode-, uid-,
and gid-bound in the observation. The runner requires the exact benign
`/etc/dpkg/dpkg.cfg` shipped by the pinned package, rejects global config
fragments and the fresh fixture user's `.dpkg.cfg`, and rejects any apt,
debconf, or `dpkg-preconfigure` path or environment. The command line overrides
the configured log into each disposable root and asserts that the host dpkg
status and log are unchanged. It generates exact-size
adversarial config members for all seven identities plus instrumented
lifecycle packages, bounds every path, archive, info member, trace,
environment, fd probe, update fragment, log, timeout, and process, and rejects
traversing, symlink, and special-file control fixtures.

```sh
reference_dpkg="$(python3 tools/prepare-native-dpkg.py --architecture amd64)"
zig build test-dpkg-config-reference \
  -Dnative-reference-dpkg="$reference_dpkg" \
  -Dnative-reference-architecture=amd64 -j2
```

On amd64 and arm64, direct dpkg never executes `config`: nonzero scripts and a script with a
missing interpreter are installed and replaced without affecting command
success. Incoming bytes are visible at `tmp.ci/config` to old `prerm`, incoming
`preinst`, and old `postrm`; the installed info member remains the old version
through those calls and changes before new `postinst`. Successful removal
keeps the member through `prerm remove` and `postrm remove`, then deletes it;
`postrm purge` sees it absent. Failed postinst retains the incoming member,
failed or interrupted remove retains the installed member, failed upgrade
rollback restores the old member, and retries settle without invoking config.
The interruption rows additionally bind committed status versus the latest
bounded `updates/` fragment.

This closes the config direct-dpkg behavior question for the pinned amd64 and
arm64 tools, not debconf frontend behavior. Native lifecycle execution
reproduces the byte/mode/ownership publication, rollback, removal, and
non-execution contract for bounded root-owned config members. Arm64 admission
is based on the executed, canonical architecture-specific observation rather
than architecture-independent parser coverage. Current opaque-info and
unsupported-archive-metadata guards remain unchanged.

The remaining alternatives reference requirement is closed separately by the
[pinned dpkg/update-alternatives oracle](dpkg-alternatives-reference.md).
Its canonical schema and fixture bind dpkg/update-alternatives 1.22.22, both
architecture-specific executable pins, the reviewed 14 groups, 189 requested
paths and linked topology, and native amd64/arm64 executions. The external-tool rows
cover exact record bytes, auto/manual mode, priorities and ties, master/slave
shape, missing providers, malformed and non-regular records, root escapes,
symlink/cycle attacks, and database/link partial states. Direct-dpkg rows cover
opaque `.alternatives` info members plus maintainer-script-driven install,
reinstall, upgrade, remove, purge, multiple providers, script failure/unwind,
interruption, and recovery. Dpkg never interprets the member or invokes the
tool implicitly. Exact arm64 architecture-derived differences are stored as a compact patch
over the amd64 baseline; external `update-alternatives` behavior is identical.
The native parser/oracle replay and lifecycle boundary now admit exactly this
pinned set while preserving fail-closed guards for evidence not represented by
the oracle.

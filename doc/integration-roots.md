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
Both reference and candidate captures use the installed
`zig-out/bin/native-differential capture` with the same `dev/null` exclusion
and bounds. Its output retains the typed v1 snapshot format consumed by
`test/real-snapshot-comparator.zig`.
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

The next authenticated amd64 replay passed the former step-823 ownership
refusal: `base-files` unpack published its exact archive payload, and
configuration reached step 852. Its postinst durably exited 1 with
`chown: invalid user: 'root:root'`; the package's `half-configured` status
was also durably applied. The fresh root has no `etc/passwd` or `etc/group`
yet because this transaction schedules `base-passwd`'s unpack after this
configuration barrier. Failure-trigger settlement then tried to promote an
unpacked listener directly to `triggers-pending`, returned
`recovery_required: invalid_transition`, and left the root claim pending.
A separate reference probe confirms dpkg incorporates awaited and no-await
activations without scheduling an unpacked listener after a known failing
postinst. Native settlement now applies that eligibility check and tests
crashes before and after the failed status publication. Sampled peak resident
memory stayed below 883 MiB. This interrupted root is retained, not reused;
its account-ordering failure is addressed by the fresh-root replay below,
which does not establish a completed closure or native/reference parity.

A new authenticated amd64 replay with fresh-root account ordering
configured `base-passwd` at step 830 and `base-files` at step 862; both
postinst outcomes exited 0. It then refused the authenticated
`less` 668-1build1 preinst at step 878 with
`InvalidAlternativesScript`, before launching that script. This
interrupted root is retained, not reused. The successful account setup
does not establish a completed closure or native/reference parity.

With the merged fresh-root account ordering and exact `less` preinst gate, a new
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
required another new authenticated root to identify any subsequent blocker;
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
root was required to determine whether execution passes step 976; the
interrupted step-976 root was not resumed as a fresh trial.

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

A further **new** authenticated 175-package amd64 root on final #235 squash
plus the bash change (recorded source `aa7ab6ed6d399266a016140780ef309380bf1a08`,
ReleaseSafe binary SHA-256
`6a753f12343319423f4045e9053966fbd72ee5d17c8a6622d457242e2921ab0a`)
began without dpkg database, helpers, or package state. It independently
persisted zero-exit account setup at steps 830 and 862, both `less` scripts at
878 and 888, and the signed `bash.postinst configure ""` at 976. The
priority-10 `builtins.7.gz` record and links agree with the earlier trial.
At step 1026, `netcat-openbsd.postinst` was launched, but
`AlternativesStateChanged` prevented persisting its script outcome;
`create.json` exited 8. An ignored local runner copy increased only the
bounded `create` timeout from 30 to 90 minutes. The root is retained read-only;
it does not establish complete install or native/reference parity.

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

A separate **new** authenticated 175-package amd64 root on final #237 squash
plus this netcat change (recorded source
`55779e7a89f41ab50abf3b1c3c429ec7d4353c6d`, ReleaseSafe executable
SHA-256 `bbe6d9e8c2cf6f47c0ae1a8f4aad68028168f749204dce083323f7ce2ec562ea`)
began without dpkg database, helpers, or package state. It independently
persisted a zero-exit signed `netcat-openbsd.postinst configure ""` outcome at
step 1026. The resulting 221-byte `nc` record has the pinned SHA-256
`2d38af8c8cc5565fd092c8e7b09cb8517eb5347616141b3e7d92034386671c4e`;
all eight selector and generic links match. At step 1065,
`procps.postinst` was prepared but refused **before launch** with
`InvalidAlternativesScript`, leaving no procps script outcome; `create.json`
exited 8. An ignored runner copy extended only the bounded `create` timeout
from 30 to 90 minutes. The root is retained read-only, not reused as a fresh
trial; complete install and native/reference parity remain unproven.

A second new authenticated combined-tree root on final #238 squash plus netcat
(recorded source `4394bf85214ac25d366f420ff41ca7c75d6b8c12`,
ReleaseSafe executable SHA-256
`91bf4bffdf388a6347e3360079ba9992db8761ffe64f2c81683db63b4f9c981f`)
started without dpkg state or helper seeding. It independently persisted
zero-exit `netcat-openbsd.postinst configure ""` at step 1026; its 221-byte
`nc` record again matched the pinned digest and all eight links matched the
reference. `procps.postinst` at step 1065 was prepared but refused **before
launch**, with no procps script outcome and `create.json` exit 8. The ignored
runner copy changed only the bounded `create` timeout from 30 to 90 minutes
and was removed afterward. This root also remains read-only, not a completed
install or a native/reference parity result.

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

A separate **new** authenticated 175-package amd64 root on final #240
squash plus procps (recorded source `3651cc92b65905535e8f2fb8ef8e5a3a88fb647f`,
ReleaseSafe executable SHA-256
`dbb1f24eb3e79a426641016168e5546930ee2698559b497859e33b6d0e15cccd`)
started without dpkg database, helper placeholders, or package state. It
independently persisted a zero-exit signed `procps.postinst configure ""`
outcome at step 1065. All four `.procps` providers and their alternatives
groups remained absent. `sudo-rs.postinst` at step 1145 was prepared but
refused **before launch** with `PartialAlternativesState`: the `sudo` group
is absent while the `sudoedit` generic link already belongs to the `sudo`
package and targets `sudo.ws`. No sudo-rs script outcome was persisted;
`create.json` exited 8. An ignored local runner copy changed only the
bounded `create` timeout from 30 to 90 minutes and was removed afterward.
The interrupted root remains read-only; this does not prove complete install
or native/reference parity.

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
reused as a fresh installation. No case-alias rule was changed here.

After #241 squash `b24f3816e13c3897bdd3892963f31dde9b4e2de9`, another
**new** root, `.real-snapshot/amd64-sudo-rs-combined-241-fresh-1`, ran the
combined source `8df430db0be9a3042dc9a4cfa83ba18c01c57510`
(ReleaseSafe executable SHA-256
`828d92b967cd1ecc36c873dbd9309c3f7f4ba6c56c981bca7182d2bcb2bb8ae1`).
Its recorded prestate had no dpkg database, helper placeholders, or package
state. The pinned Ubuntu signer authenticated its 175-package amd64 lock
(file SHA-256
`07f096da1a1fa614dc73e1797ff0b8cab917a59ce9d6dba400f64473ca24420a`);
all 175 cached archives were independently rehashed against their signed
SHA-512 identities. An untracked runner copy used the same bounded
10,800,000-ms deadline throughout and a 90-minute `create` timeout; it was
removed afterward. The exact signed `sudo-rs.postinst configure ""` at step
1145 **spawned and persisted exit 0**. Its 464-byte `sudo` record matched
the pinned dpkg SHA-256
`4f50d77a8e6f76e51745762486caec36324433ea7b09aac48274624c70e46da6`,
and both `sudoedit` links point into `/etc/alternatives`. The same run then
exited 8 with `native recovery_required: case_alias` before the signed
`libpam-runtime:all` unpack at step 1173; database step 1172 is the last
stable action. The interrupted root is retained, **not** reusable as a fresh
trial. This establishes only the step-1145 transition, not full
native/reference parity.

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

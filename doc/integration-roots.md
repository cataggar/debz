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
Local candidate installation must run as UID 0: the private helper workspace
is root-owned and a user-owned workspace fails its sealed bootstrap preflight.
Availability of `sudo` alone does not elevate the acceptance runner.

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
readiness before each package phase, without `--force-depends`. The earlier
reference runner configured dependency cycles together, processed pending
triggers and captured a healthy 175-package amd64 root, but used unrestricted
procfs with the host PID view. That rehearsal does **not** establish parity
with the native invocation-scoped proc environment and must not be replayed
as a full privileged comparison.

The bounded reference-only launcher in
`tools/real-snapshot-reference-launcher.zig` now accepts only single-package
unpack/configure operations and their dry-run probes. It pins the exact dpkg
executable, SHA512 archive/size and, for an amd64 configure requiring proc,
the signed systemd, udev or sudo postinst SHA256/size and package selector.
It runs pinned dpkg as chrooted PID 1 in private mount and PID namespaces,
with a file-only read-only archive mount and private mount propagation.
Only exact systemd configure receives the kernel's actual boot ID in a
read-only mask of `/proc/sys`; exact udev/sudo configure receive read-only
PID-only procfs without `/proc/sys`; all other operations receive no procfs.
The launcher verifies PID 1's root, retains only `CAP_CHOWN`,
`CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`, `CAP_SETGID`, `CAP_SETUID`
and `CAP_SETFCAP` for dpkg's filesystem/account work, and drops all other
supported capabilities from its bounding, effective, permitted and
inheritable sets (including the second 32-bit capability word). It clears
and verifies ambient capabilities, sets no-new-privileges, and denies module
loading and subsequent namespace/chroot changes in seccomp. An unknown
capability beyond the two-word kernel interface, or failure to drop/verify
any capability, aborts before dpkg launch. The reference uses the kernel's
8-byte capability header (`pid` at offset 4): Zig 0.16's
`linux.cap_user_header_t` instead pads its `usize pid` to offset 8 on
64-bit hosts, which made even unprivileged capget probes fail unpredictably.
It closes host descriptors on
exec and reports setup failure separately from dpkg's exit. The driver checks
root-owned, non-writable ancestry and mode-0700 workspaces before root
mutation; host-side status and snapshot reads refuse symlink ancestors.
Inherited stdin must be read-only `/dev/null`; stdout and stderr must be
root-owned, non-writable-by-others, write-only append regular files, with
the dry-run transport reopening only its protected scratch output as such a
writer. The launcher checks all three descriptors before any root access
and again in the child before exec; every other inherited descriptor is
close-on-exec. Exact proc-configure profiles recheck the installed package's
status (`install ok unpacked`), amd64 architecture, pinned version and signed
postinst bytes within the chroot before mounting proc or launching dpkg.
These offline checks are not a privileged isolation proof.

`zig build test-real-snapshot-reference-protected` is a separate, mandatory
(never skipped) ReleaseSafe proof target for a **protected** native runner.
It requires `-Dreference-protected-{launcher,dpkg,root-template,workspace,archive,archive-sha512,archive-size,architecture}`
with absolute paths. The checkout containing the proof program, the launcher,
the pinned dpkg 1.22.22 executable, the independently prepared root template,
the archive and a **new empty** workspace must have root-owned non-writable
ancestry. The template and workspace must be mode 0700; the template starts
with an empty dpkg status, empty `/proc` and an empty regular
`/.debz-reference-archive`. Obtain the archive hash and byte count from an
independently authenticated lock, and prepare the template's loader/tools from
independently verified inputs (runtime binding of the full signed closure is
still #263). Run the target as UID/GID 0 on the matching native architecture,
with separately disposable roots per case and a new workspace per run. The
target executes real pinned-dpkg no-act/unpack with an inherited directory fd,
then rejects altered archive identity/size, a readable stdout, a symlinked
root/archive and writable ancestry. It records actual process exits and stderr per
case, checks an unpacked dpkg database entry, and inspects surviving
root-associated processes and mountpoints after each operation. It fails
instead of passing or skipping when protected inputs are unavailable. This
small gate does **not** exercise the exact signed proc profiles, prove runtime
library binding, establish that arbitrary descendants cannot escape, or
resolve the shared host-network decision (#278); it must not be presented as
full protected confinement or root parity until the remaining privileged
negative probes and independent root evidence execute.

PID 1 now refuses supervisor-pipe EOF (including the death-before-`prctl`
window), not just unexpected bytes; its installed seccomp policy also refuses
every Linux `CLONE_NEW*` namespace flag after setup, including `NEWNET`,
without changing the inherited network namespace. This is independent of
the native script host's policy (#257) and does not settle #278.
The launcher independently bounds probe operations to 45 seconds and mutating
operations to 110 seconds; an expired deadline kills and reaps namespace PID 1
before returning a distinct error. The outer Python driver retains its
60/120-second timeouts and captures operation errors separately. A Zig test
actually kills and reaps a hung child, but that unprivileged test is not a
substitute for a protected pinned-dpkg descendant-teardown observation.

This reference-only capability reduction is deliberately **stricter** than
the existing native script runner, which currently drops `CAP_SYS_ADMIN`
but not `CAP_SYS_MODULE` or all high-numbered capabilities. If a signed
script needs a capability outside the reference allowlist, the reference
must refuse rather than borrow the native authority. Such a refusal is
not proof of a package-state mismatch or permission to expand the
reference allowlist: native hardening and any resulting behavior change
need a separate decision and equivalent protected script proofs. Native's
existing capability syscall also uses the padded Zig header; its correction
needs independent review in the native worktree, not a silent change to this
reference-only delta. The
shared host network view described below also remains under review.

The native exact systemd mode (`src/maintainer_script.zig`) and reference
mode both clone **mount and PID**, not network, namespaces; mount a fresh
`ro,nosuid,nodev,noexec,hidepid=2` procfs; and cover `/proc/sys` with a
read-only boot-ID-only mask before executing a script. Native udev/sudo and
the reference use the separate `subset=pid` mode without `/proc/sys`.
Both chroot their PID 1; the reference verifies `/proc/1/root` against its
pinned root. This matches the native proc **mount flags and mask**, not a
proof that the resulting script environment is safe or identical: native
executes the signed script as PID 1, while reference executes pinned dpkg
as PID 1 and the script as its child.

Without a separate network namespace, `/proc/net` resolves to
`/proc/self/net` and reports the task's network namespace (see Linux
[`proc_pid_net(5)`](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html)
and [`network_namespaces(7)`](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)).
Masking `/proc/sys` does not hide that network view, and hiding the top-level
`/proc/net` alone would leave per-PID `/proc/1/net` to assess. Native and
reference both inherit the host network namespace under the reviewed modes;
equivalent exposure is **not** evidence of harmless exposure. A proposed
reference-only refusal for `/proc/net` was removed because it would make
the reference proc mode narrower than the already approved native mode;
neither mode now adds a network namespace or a proc-network mask. These
shared network surfaces need separate native-and-reference hardening review,
including per-PID views under udev/sudo's PID-only procfs, not a unilateral
reference change.
Neither a private PID namespace nor a read-only proc mount isolates network
syscalls or proves the retained network capabilities harmless.

A disposable **unprivileged** user+network-namespace probe on this host
changed the visible `/proc/self/net/dev` interface count from three to one.
Thus adding `CLONE_NEWNET` to the reference alone cannot be called
behavior-preserving, even if it avoids host network visibility. Any private
network view would require an explicit reviewed contract for native and
reference, equivalent pinned-dpkg/signed-script results, and runner-capability
proof. Existing host sysfs mounts can also retain an old network view; do
not substitute a host bind mount or assume hiding `/proc/net` removes every
network surface. The shared view reflects the approved native profile but
does not establish full parity or resolve future network hardening. The
signed-lock bindings of dpkg's in-root dynamic loader and runtime libraries
remain unverified;
no privileged reference run is authorized on this delta.

This is **not yet an executable full parity gate**: the closed launcher
refuses `--configure --pending`, `--triggers-only --pending` and **also**
single-package trigger actions. A disposable unprivileged dpkg 1.22.22
two-listener fixture shows `--no-triggers --triggers-only listener-a` runs
only A and leaves B pending; `--no-triggers --configure seed` runs only
seed. Without `--no-triggers`, configuring seed also runs an unrelated
pending listener. Even with `--no-triggers`, configuring a selector that is
itself triggers-pending executes its `triggered` postinst, so the driver must
check its exact unpacked status and version before any configure. A selected
listener's attempted recursive dpkg call failed visibly on the frontend
lock, but a selected fixture postinst directly executed B's postinst
*despite* `--no-triggers`; B remained triggers-pending in dpkg's database.
Thus selector isolation applies only to dpkg's own scheduler, not to commands
inside an authorized maintainer script. These disposable fixtures do not
authorize arbitrary signed scripts.
`tools/test_real_snapshot_reference_triggers.py` requires an explicitly
selected, SHA256-checked pinned dpkg fixture and never runs as root.

A safe later single-listener operation would have to bind the selected
listener's **triggered** script bytes to the exact authenticated archive,
verify the pinned installed script, status/trigger queue and version again
in the launcher before exec, establish that no other script is invoked, and
compare per-listener ordering and state with pinned dpkg. The current
launcher has only `configure`/`probe_configure` and an exact
`["configure", ""]` proc profile for systemd/udev/sudo, not a `triggered`
profile for any of them. The Python command builder refuses all trigger
verbs, including attempts to reuse those configure-only profiles. Until
these distinct identities and closure ordering are proved, finalization
refuses rather than silently changing `--pending` behavior. Privileged
namespace/archive-mount, death/timeout cleanup and
exact result equivalence still require independently protected small-root
proof and review before any 175-package comparison. The current CI checkout
and cleanup are not root-owned protected ancestry; arm64 signed script
profiles are unproved. Running the manual full-reference step there must
fail closed until the runner's staging and cleanup contract is redesigned.
The reference-only
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

Step 498 had already materialized the same
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

After #242 squash `c35c3387ac6568ee0a023c0428bdbe5eaf5882cc`,
another **new** amd64 root,
`.real-snapshot/amd64-case-alias-after-242-fresh-1`, ran the combined source
`2a18571d6e08231d6f32abb5aba631b9597950af` (ReleaseSafe executable
SHA-256
`8a96b8002c18506c942a6fd8ec0432887e1c09b041c18959cdb1f5691be4516a`).
Its prestate had no dpkg database, helper placeholders, or package state.
The reviewed Ubuntu signer authenticated the 175-package amd64 exact lock
(file SHA-256
`591146847e5659dbcc26cef3c3d9bffc7bdb4b40513f3474c0278dea26a34149`);
all 175 archive objects were independently rehashed against their signed
SHA-512 identities. An untracked local runner copy kept a bounded 90-minute
`create` timeout and the same 10,800,000-ms deadline across refresh, plan,
download, and install; it was removed afterward. All five substeps of the
signed `libpam-runtime:all` unpack at step **1173** completed. Its
`PAM.7.gz` regular file and `pam.7.gz -> PAM.7.gz` symlink remain distinct
inodes (respectively `288649674` and `328353104`), both owned by
`libpam-runtime`; the regular file's SHA-256 is
`29b81aafe87370274266fdc7c008ef09b799bd712f46c58b1e6c846cc46f6530`.
The signed `libpam-runtime.postinst configure ""` then persisted exit 0
at step 1215, and the package reached installed state at step 1216.
The next refusal is the signed `keyboard-configuration:all` preinst at step
1217: `install` exited 10 with no output; its `abort-install` postrm exited
0. Install returned `native recovery_required: package_already_present`
with last durable database action step 1217, substep 0. This interrupted
root is retained, **never** reused as a fresh trial. It proves the
step-1173 transition, not completed closure or native/reference parity.

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

On the combined final #243 squash `7e03fa21bf55e966d4d0868cf05bba0353968644`
and rebased keyboard change `a1dd73d1217cec5fdb34b5817e6b8d4a020b4cec`,
a **new, elevated, unseeded** amd64 root,
`.real-snapshot/amd64-keyboard-rebased-signed-2`, used ReleaseSafe executable
SHA-256 `896463686f5efd99f2c082f767ef2b33e66a05a0f5b5e2df39ed81e6c6efe377`.
The signed `stonking` lock digest was
`3e7c89c8b70515b67e118db407530fff7bab538fc5fed46ebd57c4722ffb4c0d`;
its reviewed signer was `f6ecb3762474eda9d21b7022871920d1991bc93c`.
All 175 downloaded archives (67,976,788 bytes) were independently rehashed
and size-checked against their SHA-512-primary signed lock identities.
The exact installed keyboard preinst SHA-256
`2633dc09bf75db633726ab7e2fff9d8a29fe06f53e3c5915f9221ffef57a8703`
ran with `["install"]` at step **1217**, exited **0**, and emitted no output.
Its authenticated adjacent templates member SHA-256 was
`4fd265213c939f2b74618c997a3695b30ca9a0b9ee5439dcda4d1f0cc9d01328`;
the retained keyboard status is `install ok installed`.
The next signed script failure was `iproute2:amd64` postinst step **1230**,
SHA-256 `bb5318e85da2497d1b2b6fcdf2d612bd02ec54bc5d9f86005506d8e91bb79d3a`,
with `["configure", ""]`: it exited **10** without output, and the journal
recorded a failed script and applied database state (`half-configured`).
Unlike the earlier local roots, execution continued into deferred trigger
step **1428**, then stopped with `InvalidAlternativesScriptAuthority` after
three completed trigger invocations and a fourth prepared action.
The operation is `recovery_required`, **not** a completed installation or a
native/reference comparison. The first post-rebase trial was not reused
after a non-elevated helper-bootstrap preflight refusal; neither
interrupted root is a fresh retry target. The later iproute2 and alternatives
failures require separate investigation, not broader keyboard admission.

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

The earlier `invalid_transition` followed a completed journaled `iproute2`
`half-configured` failure-state publication. Its unincorporated `libc-upgrade`
event named `systemd`, still `install ok unpacked`; the old serial branch
lacked #231's previously proven guard against scheduling an unconfigured
trigger listener. Final main already retains that guard and Zig reference
regressions; this change does not add a second guard or relax the typed
transition table. Only a **new** independently authenticated root on the
combined #245 tree can establish the next native execution boundary.

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

A **new**, empty, elevated amd64 root on final #245 squash
`93bda9b00723f04d0b4d6ac6658708b6cb5952a7` plus rebased iproute
change `042b0176b242a85f6e1d0fff707717b328da32f3`,
`.real-snapshot/amd64-iproute-rebased-signed-1`, used the ReleaseSafe binary
SHA-256 `0872869b17441b72c3306a9a56ee5dd859ce16bce4a67f882a85235acf5ee35d`.
The reviewed signer was `f6ecb3762474eda9d21b7022871920d1991bc93c`;
the authenticated `stonking` lock digest was
`04d152c28b5e02652dcd00b5d62ac770488c32439948899c994a0583b2b3fe98`.
All 175 downloaded SHA-512-primary archive objects (67,976,788 bytes) were
independently rehashed and size-checked against that lock. The exact signed
`iproute2:amd64` postinst SHA-256
`bb5318e85da2497d1b2b6fcdf2d612bd02ec54bc5d9f86005506d8e91bb79d3a`
spawned at step **1230** with `["configure", ""]`, exited **0**, and produced
no output; installed `iproute2.templates` matches its signed SHA-256
`33e0ed65a34dbb3a951613c64ac9a71b268eaa2b3827cdd6378875e54112bf46`.
The retained iproute2 status is `install ok installed`. The next refusal
is the signed `util-linux:amd64` postinst SHA-256
`31f01940fe6aa22a9b35b54029eb5e4dd4ea5146dd2bacdb495d0d37eb210fc9`
at step **1243**, `["configure", ""]`: `InvalidAlternativesScript`
before launch, with only `script prepared` in the journal and **no** script
outcome. The overall operation remains `recovery_required`. Preserve this
interrupted root; it is not a retry target or proof of full snapshot parity.
Util-linux admission is a separate signed-authority problem.

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

On the final #246 squash `e77f6641227e8f4552ad22cfd987142def8dfdfb`
plus rebased util-linux change `73b008c6f8a649f9bbc8ef46708a149c41a882dc`,
a **new, empty, elevated** amd64 root,
`.real-snapshot/amd64-util-linux-rebased-signed-1`, used ReleaseSafe binary
SHA-256 `49c9c3f875a0fe233164b6f925e87696ed7b80bde1de9a16861628f790aecb8c`.
The reviewed signer was `f6ecb3762474eda9d21b7022871920d1991bc93c`;
the independent authenticated `stonking` lock digest was
`fa0952903605b2e94a2f1630aacda471c5db1b79ac1af90f792651ab7d45f636`.
All 175 downloaded SHA-512-primary archives (67,976,788 bytes) were
independently rehashed and size-checked against that lock. The exact signed
`util-linux:amd64` postinst SHA-256
`31f01940fe6aa22a9b35b54029eb5e4dd4ea5146dd2bacdb495d0d37eb210fc9`
**spawned** at step **1243** with `["configure", ""]`, persisted exit **0**
and 297 output bytes, and left util-linux `install ok installed`. The
154-byte root-owned `pager` record SHA-256
`efb067c8704b11530e836705a78bbfdacbe298b9d13df3a01e1f84ca794747a9`
is byte-identical to the prior pinned dpkg/tool reference record; both
selector links still choose `/usr/bin/less` and its manpage. The next
refusal is the signed `console-setup-linux:all` postinst step **1292**,
SHA-256 `5ab31be5894edd94864e54a95d2cbebd46b2b934bffa76a764fc5a52f2915e6a`,
with `["configure", ""]`: `InvalidAlternativesScript` **before launch**,
only `script prepared` in the journal and no outcome file. The operation
remains `recovery_required`; preserve the interrupted root, not a fresh
retry or proof of full snapshot parity.

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

On final #247 squash `94e21f7e2c602649abd7aa7447aa79a54b97a408`
plus rebased console source `2c534a042d4550e730b40ff97cb7d192f1ea8263`,
a **different new**, empty, elevated amd64 root,
`.real-snapshot/amd64-console-setup-247-combined-signed-1`, used ReleaseSafe
binary SHA-256 `489d31526aa888d158d98743bf5d57f3dd8ee07a602b73df6689e614105dafe1`.
The reviewed signer was `f6ecb3762474eda9d21b7022871920d1991bc93c`;
the authenticated `stonking` lock file SHA-256 was
`02d84b6867204a7a4c28402f30909bb42dd60f3df411f8db918555d1da03a3d6`.
All **175** downloaded SHA-512-primary archive objects (67,976,788
bytes) were independently rehashed, size-checked against the lock, and
matched against the exact CAS object set; the report is
`evidence/cas-rehash.tsv`. The signed
`console-setup-linux:all` postinst SHA-256
`5ab31be5894edd94864e54a95d2cbebd46b2b934bffa76a764fc5a52f2915e6a`
**spawned** at step **1292** with `["configure", ""]`, durably exited **0**
with 1,038 output bytes, and left its package `install ok installed`.
The root-owned, 78-byte `vtrgb` record SHA-256
`1fe9c0439ed1d49f6e06fad9d0a4ece1fba6826116f5cf26ba98e313c36570d3`
is byte-identical to both pinned dpkg and pinned update-alternatives
reference records. The generic `/etc/vtrgb` link targets
`/etc/alternatives/vtrgb`, whose selector targets the signed priority-50
`/etc/console-setup/vtrgb` provider.

This is **not** a completed install. The separate `console-setup:all`
postinst at step 1297 exited 10 and left it `install ok half-configured`;
its recorded failure did not become a successful configuration. During
deferred trigger processing at step 1428, libc-bin,
debianutils, and libselinux1 callbacks spawned and persisted exit 0.
The next callback, ordinal 3, has only a `prepared` record and **no**
outcome; native install exited 8 with `InvalidAlternativesScriptAuthority`.
`procps:amd64` remains `triggers-pending` for `/usr/lib/sysctl.d`; its
installed postinst SHA-256
`7c2ba424ad233bd238474b9d6e565a719fbd6902fd75f617bc3e6e915084c9d3`
has a separately bound configure-only admission, not authorization for
`["triggered", "/usr/lib/sysctl.d"]`. That callback refused before launch.
Preserve this interrupted root for recovery; it is never a fresh retry or
proof of full native/reference snapshot parity.

A separate, earlier diagnostic root from the **unmerged local
procps-trigger branch** had also persisted this same signed
`console-setup:all` postinst's exit 10 and half-configured state. Its
subsequent trigger admission and terminal failed receipt are **not** part
of this console-only change. The signed `console-setup` archive
(108150 bytes, SHA-512
`2ea052bd7c02091ce7afea7262e2340fdaeb9f362af79e4a1b42265ad98ace237b10770275970f89c81acf2c57bc2cc50234c2357adb167e84041c1c5479a330`)
was independently rehashed and its control members compared with the installed
copies in the retained root. On disposable **copies** only, pinned dpkg
1.22.22 `--configure console-setup:all` exited 0 after running the installed
`info/console-setup.config` (SHA-256
`9a7ae3220597dbd88f86f01784a47d9181c6d571a30080ccab2c77eaad0314e8`),
which registered `console-setup/codesetcode=guess`; the signed postinst then
exited 0. Running that postinst directly from `info/` also exited 0. Running
the **same signed postinst** without sidecars from dpkg's `tmp.ci/` path in a
separate copy reproduced exit 10: debconf reported `GET
console-setup/codesetcode` -> `10 ... doesn't exist`. The original root
lacked that question, and that staged path has no adjacent templates; removing
only the installed config in another copy did **not** reproduce the failure.
The installed templates (174753 bytes, SHA-256
`dbddc3ff45db9d1417abff0f21eef1aba5fbd1f1bc0cdb15eba4e3f86f2e1b81`)
are necessary to match debconf's signed input. The exact
archive/script/package/amd64/`["configure", ""]` exception selects `info/`
only after confirming the original staged candidate and all three installed
control files are unchanged root-owned regular files. Other scripts and all
failure/recovery outcomes remain unchanged. The earlier failed root is
retained, **never** retried as a fresh installation.

The following three local console-postinst trials also precede #248's final
squash and include the unpublished trigger change; none proves the outcome
on final main plus this console-only delta. A first new authenticated root,
`.real-snapshot/amd64-console-postinst-fresh-long-1`, rehashed all 175
archives but was stopped at step 659 before its standard runner's 30-minute
timeout; it never reached this postinst and is retained as an interrupted
root, never reused. A second **independently authenticated** root,
`.real-snapshot/amd64-console-postinst-fresh-long-2`, verified the same Ubuntu
signer and separately rehashed 175 SHA-512 archive objects against a new lock
(file SHA-256
`0bb4f952343052efc85f61d2344358ce24742f140afe13e80f1e941d3d0dc9c0`).
It stopped before launching step 1297 with
`InvalidConsoleSetupPostinstControl` (exit 8), having completed unpack and
left `console-setup` unpacked. The initial guard mistakenly expected the
staged postinst under `var/lib/dpkg/tmp.ci/`; native actually stages it under
`var/lib/debz-lifecycle-scripts/`. The staged file, installed postinst,
config, and templates in that retained root all have the exact signed bytes
and root-owned metadata. In a disposable **copy** of this second root,
execution of the exact native private staged postinst reproduced exit 10 and
debconf's missing-`codesetcode` response. The guard is now bound to the
actual private stage path; the second root remains interrupted and cannot
prove success or be reused as fresh.

The third **new** local diagnostic root,
`.real-snapshot/amd64-console-postinst-fresh-long-3`,
independently authenticated that signer, resolved its own 175-package lock
(the immutable snapshot yields the same lock file SHA-256
`0bb4f952343052efc85f61d2344358ce24742f140afe13e80f1e941d3d0dc9c0`),
and separately rehashed all 175 SHA-512 CAS objects. Its ReleaseSafe
candidate has SHA-256
`779b486a1a5b36f67c213cb7a454bff2e6ec19ce69b121142d1db4e65b44a9ad`.
The terminal receipt archives the exact signed `console-setup:all`
`postinst ["configure", ""]` at step 1297 (SHA-256
`e64fb42e4d5e120dfdb889b00aa747ee00ef6c31bf8edcd3230de33f1823d19d`):
it spawned, exited **0** with zero output bytes, and reached `install ok
installed`. Debconf recorded `console-setup/codesetcode=guess`, the installed
postinst/config/templates still match their signed metadata, and the earlier
`vtrgb` alternatives record remains byte-identical to pinned dpkg. This
proves this console-setup correction, **not** full 175-package parity.

In that local root, the next distinct failure is at step 1328: signed
`systemd:amd64` 261.2-1ubuntu2 `postinst ["configure", ""]` (SHA-256
`39df51226d6dd8456a388d3315e7d02b446dcec9944515a109933c65c8c1b412`)
launched and exited **1** with 1702 stderr bytes. Its retained outcome
reports that `/proc/` is not mounted and is required for `systemd-tmpfiles`;
`systemd` remains `install ok half-configured`. The deferred trigger callbacks
later exited 0, but the transaction published a terminal
`failed_after_mutation` receipt (CLI exit 7). This failed root is retained;
neither it nor the earlier interrupted roots are reusable as fresh. The
systemd environment and pinned-reference parity require a separate
investigation, not an inferred success or a broadened console authorization.

On final #248 squash `6e0c6b06a0deba3622079687952cb536a7d971f0`
plus the **console-only** rebased source
`56b037992af04b622c8dd151565beab7c3843612`, a different new,
empty, elevated amd64 root,
`.real-snapshot/amd64-console-postinst-248-combined-signed-1`, used
ReleaseSafe binary SHA-256
`67a230ded926b4766affa9475fdd1c5c590d9ee1d19d10786acd7efccbb41f17`.
The reviewed Ubuntu signer was
`f6ecb3762474eda9d21b7022871920d1991bc93c`; its authenticated
175-package `stonking` lock file SHA-256 was
`0bb4f952343052efc85f61d2344358ce24742f140afe13e80f1e941d3d0dc9c0`.
All 175 downloaded SHA-512-primary archives (67,976,788 bytes) were
independently rehashed, size-checked against the lock and matched
against the exact object set in `evidence/cas-rehash.tsv`.

The exact signed `console-setup:all` postinst SHA-256
`e64fb42e4d5e120dfdb889b00aa747ee00ef6c31bf8edcd3230de33f1823d19d`
**spawned** at step **1297** with `["configure", ""]`, durably exited
**0** with zero output bytes, and left `console-setup` `install ok
installed`. Debconf recorded `console-setup/codesetcode=guess`; the
installed postinst, config and templates were byte-identical to the
pinned dpkg 1.22.22 reference, and the 78-byte `vtrgb` record remained
byte-identical to its pinned reference (SHA-256
`1fe9c0439ed1d49f6e06fad9d0a4ece1fba6826116f5cf26ba98e313c36570d3`).
The **first later signed failure** was `systemd:amd64` 261.2-1ubuntu2
postinst SHA-256
`39df51226d6dd8456a388d3315e7d02b446dcec9944515a109933c65c8c1b412`
at step **1328**: it spawned, exited **1** with 1,702 stderr bytes,
reported that `/proc/` was not mounted but required for
`systemd-tmpfiles`, and left systemd `install ok half-configured`.
Deferred processing later reached the separately unauthorized procps
trigger at step 1428 ordinal 3, which refused **before launch** with
`InvalidAlternativesScriptAuthority`; the install command exited **8**
and requires recovery, not a successful transaction receipt. Neither
later issue is admitted by this console-only delta. The interrupted root
is retained, never retried as fresh, and proves no full snapshot parity.

The subsequent isolated systemd-proc investigation reproduced the exit 1 with
no `/proc` under pinned dpkg 1.22.22 and reproduced five `%b` boot-ID failures
with a private `subset=pid` procfs. Separate disposable copies of the
diagnostic root (which inherits some prior failure effects, and is **not** a
fresh-root parity proof) then used a private PID/mount namespace with a
root-owned `/proc`, full **read-only** procfs and an immediate tmpfs mask of
all `/proc/sys` except a read-only copy of the actual kernel boot ID. The
chrooted PID 1 had only standard descriptors; `CAP_SYS_ADMIN` was removed and
`no_new_privs` set before either signed script launched. Pinned dpkg 1.22.22
configured signed systemd to `install ok installed` (exit 0), and the same
postinst digest with the native runner's exact replacement environment
separately exited 0. Those early pinned comparisons ran from writable
checkout ancestry and are provisional. For a repeatable pinned comparison,
run `tools/real-snapshot-systemd-proc-reference.sh` only from a root-owned
checkout beneath root-owned, non-group/world-writable ancestors, with a
verified source and a new proof destination under its root-owned mode-0700
`.real-snapshot` directory. The harness refuses a shared writable checkout
or proof path before copying or chrooting, since an unprivileged writer could
otherwise swap a previously checked root. A separate Zig signed-root runner
test also exited 0 with no mount retained outside its invocation. None of
these diagnostic copies establishes a successful new 175-package
authenticated replay. An initial new-root trial was deliberately stopped
before systemd to enforce close-on-exec on all inherited descriptors; its
interrupted root is not reusable. A second **new** 175-archive authenticated
amd64 root,
`amd64-systemd-proc-fresh-long-2`, used the reviewed signer and final sealed
launcher (binary SHA-256
`ddc5ef4db8c05ad8f995c393a464e16ed6e6c1bfd2c45bfb437ce87efe41ceed`).
It persisted zero-exit `console-setup` at step 1297, but **refused systemd
before launch** at step 1328: `invalid_snapshot_proc`, with a durable
`spawned=false` script outcome and no retained `/proc/sys`. The retained
invocation SHA-256
`7ec5bdf0304f05c008b053e1cbddd1ef8f0c85` independently matches the
*staged* private `systemd.postinst` pathname plus the pinned helper and
boot-ID evidence; it does not match the installed dpkg-info pathname. Native
script selection had preferred this staged copy during configure, while the
scoped proc admission correctly required the installed path. The exact
signed `systemd` configure path now verifies both aliases against the signed
SHA-256 and executes the installed path, as pinned dpkg does. Neither
interrupted root is reused.

An independently authenticated third 175-package amd64 root,
`amd64-systemd-proc-fresh-long-3`, used the same pinned snapshot and signer
with ReleaseSafe binary SHA-256
`da698f05b1e6b6cb1c8d7f115d4740d8795ff8b9bd4aaca6d4a361d2a6afbc47`.
Its durable receipt records signed `systemd:amd64` `261.2-1ubuntu2`
postinst SHA-256
`39df51226d6dd8456a388d3315e7d02b446dcec9944515a109933c65c8c1b412`
at step 1328 with `["configure", ""]`, `spawned=true`, exit 0 and 748
bytes of captured output. `systemd` is `install ok installed`, and no
`/proc/sys` remains in the host-visible root. The **next** signed script,
`chrony:amd64` `4.8-4ubuntu2` postinst SHA-256
`bb241b43aefd9b8f6822b75a91a4b9eabf15ac75d6505584b58046910a209935`,
exited 10 at step 1344 with `["configure", ""]` and zero output.
`chrony` remains half-configured; the operation recorded
`failed_after_mutation` (exit 7), and the deferred procps trigger was not
reached in this root. This interrupted root cannot be reused as fresh; the
chrony failure requires independent investigation, not another systemd
exception or a claim of completed native/reference parity.

On final #249 squash `6300f3913f78d246ed286377fa35d8ac6efc6097`
plus only the isolated systemd-proc delta (combined source
`1c78761305642d2844de8967cf1e516d416c7780`), a separate root-owned
checkout at `/var/lib/debz-systemd-reference-249/checkout` first repeated
the pinned dpkg **1.22.22** comparison. Its root-owned mode-0700
`.real-snapshot` contains an independently copied, checked half-configured
diagnostic source with empty `/proc`, a separately pinned reference binary,
and a new disposable proof root. The protected harness exited **0**,
recorded `systemd` `install ok installed`, and left no `/proc/sys` in the
proof root. The earlier writable-checkout reference remains provisional;
neither reference copy is a new native installation trial.

The genuinely **new**, empty, elevated amd64 workspace
`.real-snapshot/amd64-systemd-249-combined-signed-1` authenticated the
reviewed Ubuntu signer
`f6ecb3762474eda9d21b7022871920d1991bc93c` and keyring SHA-256
`655e378ede8af51ed5f2ffe3669b38f124593abc1aa769c2cc76ef5986a2f835`.
Its 175-package immutable `stonking` lock SHA-256 was
`655cb3f7ab9b8e1ef1e7868710eaf81d3dd6023486e6aee1f6b11767b57b6f81`;
all 175 downloaded SHA-512-primary CAS archives (67,976,788 bytes) were
independently rehashed and size-checked against that signed lock, with an
exact object-set match (`evidence/cas-rehash.tsv` SHA-256
`5a3b8d0d146264631f88ed39cb79bcc8960225b4526d67a1a7c6bdfad2db0487`).
The ReleaseSafe candidate SHA-256 was
`9d3228b0b19c421ec1fb9b1d141cc31e0ef4c697ac1001f99f2f953827b2c1c4`.
The retained signed `systemd:amd64` postinst SHA-256
`39df51226d6dd8456a388d3315e7d02b446dcec9944515a109933c65c8c1b412`
**spawned** at step **1328** with `["configure", ""]`, durably exited **0**
with 748 captured output bytes, and step **1329** durably recorded
`installed`. No `/proc/sys` remains in the host-visible root.

The **first later signed script failure** was `chrony:amd64` postinst
SHA-256 `bb241b43aefd9b8f6822b75a91a4b9eabf15ac75d6505584b58046910a209935`
at step **1344**, which spawned, exited **10** with zero output, and remained
half-configured. Deferred trigger processing later reached the **separately
unauthorized** procps callback at step **1428** ordinal 3, refused before
launch with `InvalidAlternativesScriptAuthority`, and caused install exit
**8** with recovery required, not a successful completion receipt. Systemd
ended `triggers-pending` after the later activations, despite its durable
installed configure transition; do not misreport the final status as
`installed`. This interrupted root is retained read-only, never retried as
fresh, and proves neither the chrony/procps fixes nor full snapshot parity.

Hosted arm64 Debug exposed a kernel capability-header ABI mismatch: Zig's
`linux.cap_user_header_t` places its machine-width PID at offset 8, but
`capget`/`capset` require a 32-bit PID at offset 4. Padding supplied an
invalid PID (`ESRCH`) during the private proc privilege drop. The signed
systemd-only runner now uses the exact 8-byte kernel header through those
two raw syscalls, retains the capability-drop checks, and tests the ABI
directly. The prior ReleaseSafe root is not substituted for testing this
changed binary.

At ABI-corrected source `692c85a8bc3ac57653db7acc65e9687403c4d177`,
the protected root-owned checkout was fast-forwarded to the same commit and
the hardened pinned dpkg 1.22.22 harness configured a **new** disposable
proof (`proof-systemd-dpkg-abi-2`) from its protected diagnostic source:
exit **0**, `install ok installed`, no retained `/proc/sys`. A genuinely
**new** authenticated amd64 workspace,
`.real-snapshot/amd64-systemd-249-abi-signed-2`, used ReleaseSafe binary
SHA-256 `564ab245ec411811e8f1292af84e6e9b79a455169a0ee41ee21f85cde9fcb04c`
and the same reviewed signer, keyring, immutable 175-package lock and
independently verified 67,976,788 archive bytes. Its signed systemd
postinst again spawned and durably exited **0** with 748 output bytes at
step **1328**; step **1329** applied `installed`, with no `/proc/sys`
remaining. The **first subsequent signed failure** was chrony postinst
step **1344** (exit **10**, half-configured), followed by the independent
procps trigger prelaunch refusal at step **1428** ordinal 3; the operation
ended with recovery-required exit **8** and systemd `triggers-pending`.
This second interrupted root is retained read-only and does not prove a
successful installation or full native/reference parity.

The authenticated `chrony:amd64` archive is SHA-512
`5265963d95267643abec7fbadb5c76ae39a1a940e2b12a48d685c6859bcf44fa318c0f48c509b3c19811cc877b450a92c9fcad5a3212e7b78f441234d54cdcd9`
(333,804 bytes). Its exact postinst, config, and templates have SHA-256
`bb241b43aefd9b8f6822b75a91a4b9eabf15ac75d6505584b58046910a209935`,
`77661a87b10380b637663d35d01f334c99887ba0dfb625f0c3cc14d995dd83f0`,
and `1f0ffe9e66ddc6593446ef924cf6dc80a445b161f0e1876ffac417f0a32841cf`.
The failed root has no debconf row for
`chrony/configure_ubuntu_pools_in_sourcesd`; its retained invocation digest
selects the private staged `chrony.postinst`, which lacks adjacent config
and templates. In separate disposable copies of that interrupted root with
empty `/proc` and the native replacement environment, the exact signed
staged path exited 10 with zero output and left the question absent; the
byte-identical installed dpkg-info path exited 0 and registered the signed
boolean default `true`. Pinned dpkg **1.22.22**
(`0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5`)
also configured chrony successfully from another disposable copy with
empty `/proc`. This distinguishes the adjacent-control lookup from service
or proc-mount behavior; the diagnostic copies are not fresh parity evidence.

These root-privileged comparisons ran beneath a shared writable checkout
with a user-owned `.real-snapshot`, before the protected-ancestry reference
harness in local `aaabc66`. Their observed results diagnose the path-dependent
script behavior, but do **not** satisfy that harness's race-resistant
source/proof-root requirement. The historical fresh native replay below
also used the shared checkout; its authenticated archive and recorded script outcomes do
not establish a hostile-writer-resistant root-path proof. Repeat privileged
reference and native proof in a protected checkout after the required serial
rebase before asserting parity against adversarial path swaps.

Only the exact authenticated new-package chrony postinst configure action
may select the installed dpkg-info path, after pinning the archive identity
and verifying both staged and installed scripts plus the installed config
and templates as exact root-owned signed control files. No exit is masked,
and no general debconf, service, or `/proc` authority is added. At this
point, a protected **new** authenticated root still had to prove step 1344
and identify the next blocker.

A **new** independently authenticated 175-package amd64 root,
`amd64-chrony-fresh-long-1`, used the reviewed signer
`F6ECB3762474EDA9D21B7022871920D1991BC93C` and ReleaseSafe binary
SHA-256 `9b2286d4c0c73531440cec7121fc1a6899252f4968ade28e3142d962f5726278`.
It persisted signed systemd postinst step 1328 exit 0, then the exact
signed chrony postinst step 1344 with `["configure", ""]`, `spawned=true`,
**exit 0**, and 846 bytes of captured output. `chrony` is now `install ok
installed`; debconf registered the signed boolean default `true`, and
`/proc/sys` is still absent outside the invocation. The **first subsequent
failure** is signed `udev:amd64` `261.2-1ubuntu2` postinst SHA-256
`861ba57cdb3f94bae94af237b9284b01bceb956ee69bb09d3b54e381567336ee`:
it exited 1 at step 1357 with 349 stderr bytes stating that `/proc/` is
required for `systemd-tmpfiles`. The native operation recorded
`failed_after_mutation` (exit 7); the deferred procps trigger did not run.
This interrupted root cannot be reused as fresh. Diagnosing udev's
separate proc requirement must not infer authority from chrony's path fix,
and this run does not establish complete native/reference parity.

On final #250 squash `b833d79ea5c57fd17a61cde1ca61a3d9a0e273ae`
plus the chrony-only source at `278857f3c82af364aaeee974a65458dc303d724a`,
the pinned dpkg comparison was repeated from root-owned
`/var/lib/debz-chrony-reference-250/checkout` with a mode-0700
`.real-snapshot`. The protected
`tools/real-snapshot-chrony-reference.sh` rejects writable ancestry and
changed chrony controls before copying an independently retained,
half-configured diagnostic source into a **new** proof root. The pinned dpkg
**1.22.22** receipt verified; `--no-triggers --configure chrony` exited
**0**, left `chrony` `install ok installed`, and registered
`chrony/configure_ubuntu_pools_in_sourcesd` with value `true`. The source
remained half-configured, and the proof has no retained `/proc/sys`. This is
a protected **diagnostic comparison**, not a fresh native installation or
authorization for udev.

The **genuinely new**, empty authenticated amd64 workspace
`/var/lib/debz-chrony-reference-250/checkout/.real-snapshot/amd64-chrony-250-protected-signed-1`
used that same protected checkout and root-owned candidate. The reviewed
signer was `f6ecb3762474eda9d21b7022871920d1991bc93c`, the keyring
SHA-256 was
`655e378ede8af51ed5f2ffe3669b38f124593abc1aa769c2cc76ef5986a2f835`,
and the ReleaseSafe binary SHA-256 was
`0cd7ae62568d10e1cc8875a9d5912dd71cfc646f56c2155936dad0a3e32ce85c`.
The immutable 175-package lock SHA-256 was
`938a76de43cd1af9d8d286ec35f149845520aa216eb3ce417b7a89827604f3e7`;
all 175 downloaded SHA-512-primary CAS objects (67,976,788 bytes) were
independently rehashed and size-checked against its **exact** object set,
recorded in `evidence/cas-rehash.tsv` (SHA-256
`4b0501bcb7f26f2be2dfead5176a38e01643b08ee295d2f8cd2c2ff2e4191d54`).
The protected runner retained only the two reviewed bounded timeout
substitutions, with SHA-256
`cfa860317c8844ed0aba0503b3db7b36594327099c141cc4a0d4b4d80884f666`.

The exact signed `chrony:amd64` postinst SHA-256
`bb241b43aefd9b8f6822b75a91a4b9eabf15ac75d6505584b58046910a209935`
**spawned** at step **1344**, ran `["configure", ""]`, and durably exited
**0** with 846 output bytes. Step **1345** completed its `installed`
transition with result `applied`; final `chrony` status remains
`install ok installed` and debconf records the signed boolean value
`true`. No `/proc/sys` remains in the host-visible root. The **first
subsequent signed script failure** was `udev:amd64` postinst SHA-256
`861ba57cdb3f94bae94af237b9284b01bceb956ee69bb09d3b54e381567336ee`
at step **1357**: it spawned, exited **1**, and emitted 349 stderr bytes
requiring `/proc/` for `systemd-tmpfiles`; `udev` is half-configured.
Later, the separately unauthorized procps deferred trigger at step **1428**
ordinal 3 refused before launch with
`InvalidAlternativesScriptAuthority`, leaving recovery required (install
exit **8**). The interrupted native root is retained read-only and is
never retried as a fresh run. This proves chrony's bounded configure path,
not udev authority, successful completion, or full snapshot parity.

A separate protected, proof-only amd64 run at combined local commit `89675bd`
used a root-owned checkout beneath `/root` and a root-owned, mode-0700
`.real-snapshot`. Its **new** 175-package signed lock identified signer
`F6ECB3762474EDA9D21B7022871920D1991BC93C`; all 175 downloaded archives
were independently rehashed against their locked SHA-512 digests. In
`amd64-udev-proof-new-3`, a traced exec stop copied the root **before** the
exact signed staged udev postinst SHA-256
`861ba57cdb3f94bae94af237b9284b01bceb956ee69bb09d3b54e381567336ee`
ran with `["configure", ""]`. Its durable lifecycle record identified
step 1357 as `in_flight`; `/proc` was empty. The source run deliberately
stopped with exit 88 and is interrupted, not a completed installation or
a reusable fresh root.

Six independent disposable copies of that protected prestate compared
pinned dpkg 1.22.22 and the signed script under no `/proc` and a private
PID+mount namespace with `ro,nosuid,nodev,noexec,hidepid=2,subset=pid`
procfs, chrooted PID 1, no `/proc/sys`, dropped `CAP_SYS_ADMIN`, and
no-new-privileges. Native records udev as `installed` before its postinst;
to make `dpkg --configure udev` execute, **four copies only** changed its
dpkg status to `half-configured`, identically for the reference and direct
script cases. Two direct-script copies preserved the actual `installed`
prestate. With no `/proc`, dpkg and both direct-script cases failed with
the same tmpfiles requirement (script exit 1); with restricted procfs,
dpkg and both direct-script cases exited 0 with identical script stderr.
Both successful environments registered `input:995`, `sgx:994`,
`clock:993`, `kvm:992`, and `render:991`; `/etc/group`, the generated
root-owned mode-0444 hwdb, `/dev`, and service-helper content and metadata
matched the pinned reference. All nine signed static-node permission
targets were absent before and after, so this proof establishes **no**
permission or ownership change for existing device nodes. Each private
`/proc` mount was gone afterward. The udev callback required no boot ID
or other `/proc/sys` entry in this prestate, but this **does not** authorize
udev to use systemd's exact-script proc mechanism or prove a completed
175-package replay. Protected checkout provisioning and namespace/mount
capabilities remain unproven on CI arm64 and WSL.

The separately authorized udev implementation at protected source snapshot
`38ddbca3bdcd67418cad5ea61c1903699130afa7` admits only that signed
new-package `udev:amd64` `261.2-1ubuntu2` postinst with
`["configure", ""]`, from its verified installed dpkg-info path. Its
PID-only private procfs has no `/proc/sys` or boot ID; the signed script,
required tools and sidecars, path resolution, root and empty mountpoint are
pinned before launch. Systemd's separate boot-ID view is unchanged. In
protected disposable pre-udev copies, pinned dpkg 1.22.22 and the signed
script each exited 1 without `/proc` and 0 with the PID-only view. Three
additional **regular files**, not host devices, started root:root mode 0600
at `/dev/kvm`, `/dev/fuse`, and `/dev/snd/seq`. Both pinned dpkg and the
signed script changed them to root:kvm (GID 992) mode 0660, root:root
mode 0666, and root:audio (GID 29) mode 0660, respectively. The direct
script comparison also retained the native `installed` prestate; only the
disposable dpkg comparison set udev to `half-configured` so that dpkg would
execute it. No real device node was exposed or altered.

A **new**, independent 175-package amd64 root,
`amd64-udev-proc-fresh-long-3`, ran under the protected root-owned checkout
and mode-0700 `.real-snapshot`. It reauthenticated signer
`F6ECB3762474EDA9D21B7022871920D1991BC93C` and all 175 signed-lock
archive SHA-512 identities (67,976,788 download bytes), using the
ReleaseSafe binary SHA-256
`8cf3fee176ead7323076acaa83951acf3c44e66ac60c99959705b0082d0042c2`.
The durable outcome for the signed udev postinst at step 1357 records
`spawned=true`, `exit_code=0`, 182 stderr bytes and zero stdout bytes;
the progress ledger marks it **completed/succeeded**. Udev is `install ok
installed`, the five expected groups have GIDs 995 through 991, and the
root-owned mode-0444 `/usr/lib/udev/hwdb.bin` was generated. `/proc` was
empty and no private mount survived the callback.

The installation did **not** complete. Its first subsequent blocker was
`sudo:amd64` `1.9.17p2-7ubuntu3` postinst at step 1376, SHA-256
`e766407bf70ad03d8006de9f3f8700f7ed22b532d8e299ac88e522e2c80a2cb8`:
the action remained **prepared**, without a sudo script outcome or launch.
The ReleaseSafe process aborted (exit 134) inside
`native_alternatives.capture` while preparing the alternatives boundary;
the stack reports `OwnedRecord.deinit` through the parsed-record `errdefer`.
The underlying capture error has not been established. `create.json` is
empty because the process aborted; this interrupted root is **not** reusable
as a fresh root or proof of full native/reference parity. Earlier
`amd64-udev-proc-fresh-long-{1,2}` runs were also stopped before udev while
tightening provider and path guards; neither was reused.

On final #251 squash `06e84cbb155c300cd11ba6ab44a3be72775babda`
plus the isolated udev source at `b5053574751eff4bcc5b90117f68edeb668594cd`,
a root-owned checkout at `/var/lib/debz-udev-reference-251/checkout`
repeated the pinned dpkg **1.22.22** comparison from a mode-0700
`.real-snapshot`. The diagnostic source is an independently copied,
half-configured udev root from the protected failed chrony run; it is
**not** retried as a fresh native installation. The checkout-local
`tools/real-snapshot-udev-reference.sh` rejects writable ancestry and
changed signed controls, verifies the pinned executable and receipt, and
copies the diagnostic source into a **new** disposable proof root. Pinned
dpkg runs from `/usr/local/sbin` without replacing the signed Ubuntu
`/usr/bin/dpkg` used by the postinst. Its private PID and mount namespace
exposes only `ro,nosuid,nodev,noexec,hidepid=2,subset=pid` procfs, with
no `/proc/sys`; `CAP_SYS_ADMIN` is dropped before configure. The pinned
`--no-triggers --configure udev` exited **0**, left udev `install ok
installed`, and generated root-owned mode-0444
`/usr/lib/udev/hwdb.bin` (13,735,371 bytes). The source remained
half-configured; neither private `/proc` nor `/proc/sys` survived in the
proof root. This is a protected **diagnostic comparison**, not new-root
evidence or authority for any other signed script.

The **genuinely new** authenticated amd64 workspace
`/var/lib/debz-udev-reference-251/checkout/.real-snapshot/amd64-udev-251-protected-signed-1`
used that same protected checkout and an empty root. Its reviewed signer
was `f6ecb3762474eda9d21b7022871920d1991bc93c`, keyring SHA-256
`655e378ede8af51ed5f2ffe3669b38f124593abc1aa769c2cc76ef5986a2f835`,
and ReleaseSafe candidate SHA-256
`0646ef35175e782efc3ecd82052e5efd4db74a7cfc1283535a5775ccd9e5991a`.
The immutable 175-package lock SHA-256 was
`811baa788bdd44c8d9cf517b117c7270353885b45813d85399cb2944e947327c`;
all 175 downloaded SHA-512-primary CAS objects (67,976,788 bytes) were
independently size-checked and rehashed against its **exact** object set,
recorded in `evidence/cas-rehash.tsv` (SHA-256
`4b0501bcb7f26f2be2dfead5176a38e01643b08ee295d2f8cd2c2ff2e4191d54`).
The protected runner's two bounded timeout substitutions have SHA-256
`cfa860317c8844ed0aba0503b3db7b36594327099c141cc4a0d4b4d80884f666`.

The exact signed `udev:amd64` postinst SHA-256
`861ba57cdb3f94bae94af237b9284b01bceb956ee69bb09d3b54e381567336ee`
**spawned** at step **1357** with `["configure", ""]` and durably exited
**0** (182 stderr bytes, no stdout). Step **1358** completed its
`installed` transition with result `applied`; final udev status remains
`install ok installed`. The generated root-owned mode-0444
`/usr/lib/udev/hwdb.bin` is 13,735,371 bytes with SHA-256
`d9800b3cbbe2f7b120c04fc83042f7538c858b615907cf71b913c0b0ad395e10`,
byte-identical to the new protected pinned-dpkg proof. No `/proc/sys` or
private `/proc` mount remained. Protected root-owned Debug and ReleaseSafe
Zig namespace runs each executed **40/40** tests, including signed udev,
both private proc views and teardown, without skips.

The **first later blocker** is `sudo:amd64` `1.9.17p2-7ubuntu3`
postinst at step **1376**: its action is only `prepared`, with **no
postinst launch or outcome**. The ReleaseSafe process aborted (exit
**134**, `General protection exception`) in
`native_alternatives.capture`, through `OwnedRecord.deinit` on the
parsed-record `errdefer`, before the sudo script boundary was admitted.
`create.json` is empty; the underlying capture error remains unknown.
The source and proof copies and this interrupted native root are retained
read-only, never retried as a fresh root. Neither sudo capture nor any
other signed script is authorized here, and full native/reference parity
is **not** established.

The separate protected sudo investigation used root-owned checkout
`/root/debz-issue-86-sudo-alternatives` with a mode-0700
`.real-snapshot`. Its source was an **independent** authenticated pre-udev
copy, not the aborted `amd64-udev-proc-fresh-long-3` root. After matching
all 14 alternatives records, selectors, signed sudo files and the two
sudo-owned links against the read-only aborted evidence, disposable copies
recreated just those signed payload links. Pinned dpkg 1.22.22 and the
signed sudo postinst each exited 1 without `/proc`, leaving the group
untouched; under equivalent private PID-only procfs with no `/proc/sys`,
both exited 0 and produced the reference-exact 658-byte `sudo` group
with repaired generic links. A third signed-script disposable copy with
sudo's actual native `installed` prestate produced the same exit 0 and
record. The original process abort was caused by
a parsed-record cleanup after ownership transfer on the strict capture
refusal; the narrowly bound sudo repair instead requires a typed
before/after alternatives transition and separately pinned PID-only
namespace. This protected comparison alone does not prove the 175-package
install or authorize other scripts.

A **new** protected amd64 175-package root,
`/root/debz-issue-86-sudo-alternatives/.real-snapshot/amd64-sudo-alt-fresh-long-1`,
started without a dpkg database and independently reauthenticated signer
`F6ECB3762474EDA9D21B7022871920D1991BC93C` plus all 175
signed-lock SHA-512 archive identities (67,976,788 bytes). It used the
root-owned ReleaseSafe binary SHA-256
`280635b4083bd3868a6045f4805a71fc5cfa86b63333b7fb7ad7d68e13fcc94e`
from protected production-code snapshot
`96c05241ad077ffea28f6a8867e35d6a1cbc9afa`. The signed udev postinst
again completed step 1357 with exit 0. The exact signed `sudo:amd64`
`1.9.17p2-7ubuntu3` postinst at step 1376 then **launched**, durably
recorded `spawned=true`, exit **0**, and completed successfully. Sudo is
`install ok installed`; the six-slave 658-byte `sudo` alternatives record
has reference SHA-256
`c583a377d2d7bc241422c91f43738f8e278e159e8e3bb2aa53d5bdeaf782e845`,
and both package-owned `sudoedit` links now point into `/etc/alternatives`.
`/proc` is empty after the script and the private mount is gone.

The **first subsequent refusal** is signed `python3:amd64` `3.14.7-3`
new-package preinst `["install"]` at step 1383, SHA-256
`115f972bfeb85d083537b4d7fc59261979c6a2511d85b84407c7d7da38c9a85f`.
Its `update-alternatives --auto /usr/bin/python3 >/dev/null 2>&1 || true`
line is outside the admitted command grammar: `InvalidAlternativesScript`
left the action **prepared**, with no python3 script outcome or launch.
The native operation returned `recovery_required` (exit 8), not a complete
installation. This root is interrupted and must **never** be reused as
fresh; python3 requires a separate exact signed-script investigation.
This earlier local run predates the final #252 squash and the sourced
`dpkg-error.sh` pin. It is retained only as diagnostic evidence, not as
the combined-tree fresh-root publication proof.

On the final #252 squash `c73669e6cf4a36de25937f3063fbc0585f58f288`
plus the isolated sudo-only source `898d81ebee16c2cf879a669e525043f330e0d8d2`,
the root-owned checkout `/var/lib/debz-sudo-reference-252/checkout` repeated
the pinned dpkg **1.22.22** comparison from its mode-0700 `.real-snapshot`.
`tools/real-snapshot-sudo-reference.sh` rejected writable ancestry and
changed signed controls before copying an independent authenticated
pre-sudo diagnostic source. Only the two literal sudo-owned payload links
were restored in the **new disposable proof copy**, not in the source or
the native installation. Pinned dpkg configured sudo with private
`ro,nosuid,nodev,noexec,hidepid=2,subset=pid` procfs, no `/proc/sys`, and
`CAP_SYS_ADMIN` dropped. It exited **0**, left sudo `install ok installed`
and generated the reference-exact 658-byte record (SHA-256
`c583a377d2d7bc241422c91f43738f8e278e159e8e3bb2aa53d5bdeaf782e845`).
The protected signed-script Debug and ReleaseSafe tests produced
byte-identical records; each ran **46/46** mandatory namespace tests and
the altered, missing, redirected and post-binding-drift fragment refusals.
The source is unchanged and no private proc mount survived in the proof.

A **genuinely new**, empty amd64 root at
`/var/lib/debz-sudo-reference-252/checkout/.real-snapshot/amd64-sudo-252-protected-signed-1`
independently authenticated signer
`f6ecb3762474eda9d21b7022871920d1991bc93c`, keyring SHA-256
`655e378ede8af51ed5f2ffe3669b38f124593abc1aa769c2cc76ef5986a2f835`,
and ReleaseSafe binary SHA-256
`5a90838763721b07343212d5d62fcfd8fa32c92d1577550e84473ea930734e4b`.
Its signed 175-package lock has SHA-256
`cd8bdea91cf657c2c6b209d2d1e55dc35a7d251e088151ac380371eee20244e6`;
all 175 SHA-512 CAS objects (67,976,788 bytes) were independently
size-checked and rehashed against the **exact** object set. The sorted
`evidence/cas-rehash.tsv` has SHA-256
`4b0501bcb7f26f2be2dfead5176a38e01643b08ee295d2f8cd2c2ff2e4191d54`.

The exact signed `sudo:amd64` postinst SHA-256
`e766407bf70ad03d8006de9f3f8700f7ed22b532d8e299ac88e522e2c80a2cb8`
**spawned** at step **1376** with `["configure", ""]`, durably exited
**0** (zero stdout, 126 stderr bytes), and completed `succeeded`.
Step **1377** applied the installed transition: sudo is `install ok
installed`. Its root-owned mode-0644 six-slave record is 658 bytes and
byte-identical to the protected pinned-dpkg proof; both `sudoedit` links
point into `/etc/alternatives`. The authenticated 3,228-byte sourced
`dpkg-error.sh` fragment retained SHA-256
`d4d4fd7712da692dbb21a10795f7e62046c90b506338768b5a93cf9f1897f528`.
The private `/proc` disappeared, and `/proc/sys` was not retained.

The **first subsequent refusal** was signed `python3:amd64` preinst at
step **1383**: only `prepared` is durable, with **no python3 launch or
script outcome**. `create.json` reports `recovery_required` (exit **8**,
`InvalidAlternativesScript`), not a successful installation. This root
is interrupted and is retained for read-only evidence, never reused as
a fresh trial. Neither python3 admission nor full native/reference
parity follows from sudo's successful step.

A separately protected checkout
`/root/debz-issue-86-python3-preinst` (root-owned, mode 0700, with
root-owned mode-0700 `.real-snapshot`) compared the authenticated
`python3:amd64` `3.14.7-3` preinst against pinned dpkg 1.22.22.
The disposable source was the independent authenticated pre-udev copy
previously used for sudo proof, **not** the failed step-1383 root. Its
signed script, link, package lists and alternatives tool matched the
read-only failed-root prestate; the 14 records and 76 selectors matched
their documented fingerprints. The signed python3 and python3-minimal
archives independently matched the lock's SHA-512 digests.
Both pinned and snapshot `update-alternatives --root <disposable-root>
--auto /usr/bin/python3` returned 2 before touching the root, rejecting
the slash-containing alternative name. The exact signed preinst
`["install"]` on one protected copy exited 0. Pinned dpkg 1.22.22 on
another copy, after fixture-only removal and purge of the already
unpacked python3 package, ran the archive's preinst with exactly
`( install )` and unpacked successfully. Both copies retained all 14
record bytes, all 76 selector links, the signed python3-minimal link and
the absent HTML target. Both wrote the same 96-byte error text into
the root's initially empty, regular `/dev/null`; its SHA-256 is
`3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc`.
This is a *bounded* proof for the install-only branch, not evidence for
python3 upgrades or a completed 175-package install.

A first **new**, protected 175-package root,
`/root/debz-issue-86-python3-preinst/.real-snapshot/amd64-python3-preinst-fresh-long-1`,
reauthenticated Ubuntu signer `F6ECB3762474EDA9D21B7022871920D1991BC93C`
and rehashed all 175 lock archives (67,976,788 bytes; lock SHA-256
`4442a57e27f993cfafa20b9f62339605c0b02f9253be675de7c01d28607c4ffc`).
It reached step 1383 but refused **before launch** with
`InvalidPython3PreinstControl`: its empty, root-owned regular `/dev/null`
had mode **0644**, whereas the initial proof copy and the older refused
root had mode 0600. The action remained `prepared`, with no script outcome;
this failed root is retained for read-only evidence, never resumed or
used as fresh input. A read-only regression against that root verifies
the corrected guard, but does not execute its pending action.

Separate new disposable copies of the independent authenticated prestate
changed **only** that file mode to 0644. The exact signed script
`["install"]` and pinned dpkg 1.22.22 unpack of the signed archive both
exited 0, kept that file at 0644 and wrote the identical 96-byte
diagnostic. The script copy retained all 14 records byte-for-byte and
all 76 selectors; the pinned-dpkg copy also retained those records and
selectors (its fixture-only python3 purge ran before the no-force unpack).
The native guard admits **only** the independently proved 0600 and 0644
root-owned regular-file modes, with the same exact empty-file prestate
and post-exit bytes. Modes 0640 and 0666 remain negative test cases;
this does not accept arbitrary writable files or a real device.

A **second** new, root-owned mode-0700 root/cache/state from an
earlier local branch **also containing unpublished procps-trigger admission**,
`/root/debz-issue-86-python3-preinst/.real-snapshot/amd64-python3-preinst-fresh-long-2`,
independently refreshed authenticated metadata from signer
`F6ECB3762474EDA9D21B7022871920D1991BC93C` and downloaded and
rehash-verified **175/175** SHA-512 archives (67,976,788 bytes; exact
lock SHA-256
`4442a57e27f993cfafa20b9f62339605c0b02f9253be675de7c01d28607c4ffc`).
It used the protected ReleaseSafe executable SHA-256
`9a0c3641daa87f832233b0e6913f2cbf7a25a0fda9fed47aa91ee4cde163fa61`.
Signed python3 preinst step **1383** durably recorded `spawned=true`,
exit **0**, zero output, and a completed `succeeded` action; python3
became `install ok installed`. Its exact 96-byte `/dev/null` witness
was verified before that outcome persisted; later scripts wrote to the
same regular file, so its final contents are not that witness.

The **next distinct blocker** is *after* all recorded script and
deferred-trigger callbacks: seven step-1428 trigger outcomes recorded
exit 0, including `libglib2.0-0t64:amd64` `2.90.0-1` callback ordinal 4
for `/usr/lib/x86_64-linux-gnu/gio/modules` and
`/usr/share/glib-2.0/schemas`. Despite that successful callback,
`libglib2.0-0t64` ends `install ok triggers-awaited` with
`Triggers-Awaited: libglib2.0-0t64` (its own awaited schema trigger).
Following completed database step 1431, final verification returned
`final_closure_mismatch`; the install ended `recovery_required`, exit
**8** on that local combined branch. This is not a prediction for final main
plus python3 alone; no complete 175-package parity is established. This second
interrupted root is retained for evidence and must never be reused as
fresh or resumed by this investigation.

On final #253 sudo squash `c7e9b55631d4c415a43dd9b2ca49819266d3c7ec`
plus **only** python3, a new protected checkout
`/var/lib/debz-python3-reference-253/checkout` at python3-only source
`ac240570ef6d6555c1a10bf5092b783eff2881d0` used root-owned
mode-0700 `.real-snapshot` and a separate empty native root. Pinned dpkg
1.22.22 and signed preinst comparisons on *independent protected
diagnostic copies*, in both empty regular `/dev/null` modes 0600 and
0644, returned exit 0, retained all 14 alternatives records and 76
selectors, and produced the same exact 96-byte output. Those copies
were never used as a new native installation. The first new native
workspace `amd64-python3-253-protected-signed-1` stopped during
acquisition-only evidence checks: the download itself returned 0 but
emitted one `error=NameServerFailure` retry, which the strict diagnostic
runner rejected. Its root remained empty, with no install or script
outcome, and was **not** reused.

The independently refreshed **second** workspace,
`.real-snapshot/amd64-python3-253-protected-signed-2`, reauthenticated
Ubuntu signer `f6ecb3762474eda9d21b7022871920d1991bc93c`. Its
175-package lock SHA-256 was
`b1019563797b699ae30b07b625166f42624ccb056f06e0f62d62e6ec0b060bc5`;
all **175/175** SHA-512 archive objects (67,976,788 bytes) independently
matched their signed digests and sizes, with an exact object set and
`evidence/cas-rehash.tsv` SHA-256
`0e3f2a55adb3d91d60b216f9af8c61c5785e05ab8266b4f0fee220464558a7c1`.
The ReleaseSafe binary SHA-256 was
`e25deea6be146c5c112167c8ec5293b2e6cee50daf708140ae0973d5010a0265`.
The exact signed python3:amd64 `3.14.7-3` preinst SHA-256
`115f972bfeb85d083537b4d7fc59261979c6a2511d85b84407c7d7da38c9a85f`
**spawned** at step **1383** with `["install"]`, durably exited **0**
with zero output, and completed `succeeded`; `python3` ended `install
ok installed`. The diagnostic `/dev/null` witness is checked *at the
preinst outcome*, not inferred from its final contents after later
scripts. No `/proc/sys` was left visible.

The first subsequent refusal was deferred callback ordinal **3** at
step **1428**, **prepared only**, with no spawn or outcome; the three
preceding callbacks completed successfully. `procps:amd64` remained
`triggers-pending` for `/usr/lib/sysctl.d`; its exact signed postinst
SHA-256 `7c2ba424ad233bd238474b9d6e565a719fbd6902fd75f617bc3e6e915084c9d3`
has configure-only admission on this branch, not an authorized
`["triggered", "/usr/lib/sysctl.d"]` callback. `create.json` recorded
`InvalidAlternativesScriptAuthority` and exit **8**. The earlier
`final_closure_mismatch` result belongs only to the separate unpublished
trigger-admission branch. No full install/parity claim follows from
python3's success; this root is retained read-only, never reused.

An earlier, independently authenticated procps-trigger proof followed
the interrupted console-setup-linux root described above:

In a disposable **copy** of the earlier procps-refused root, pinned dpkg 1.22.22
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
never reused as fresh. The console-setup failure was addressed by the
subsequent exact signed script-path admission; its pinned-dpkg parity does
not follow from the procps trigger proof.

On final #254 python3 squash
`0e17210b0f2c15ce8cba7f029892911aa887887f` plus **only** the
procps-trigger delta, a new root-owned checkout
`/var/lib/debz-procps-reference-254/checkout` (mode-0700
`.real-snapshot`) created an empty
`.real-snapshot/amd64-procps-254-protected-signed-1/root`, cache and
state. Its authenticated `stonking` amd64 lock SHA-256 was
`67eaaf9146202f75d1ff63e9a0ce81cc3e001efcb667777a7f471c73c01724a2`,
signed by `f6ecb3762474eda9d21b7022871920d1991bc93c`.
All **175/175** SHA-512 archive objects (67,976,788 bytes) matched
their signed identities, declared sizes and exact cache object set;
`evidence/cas-rehash.tsv` SHA-256 was
`0e3f2a55adb3d91d60b216f9af8c61c5785e05ab8266b4f0fee220464558a7c1`.
The ReleaseSafe executable SHA-256 was
`936df94bb4f5a03a2d17ad42381535b5548e6f9fffa68f110926f51abe6fd425`.
Signed `python3` preinst step 1383 again exited 0. The exact
signed procps postinst SHA-256
`7c2ba424ad233bd238474b9d6e565a719fbd6902fd75f617bc3e6e915084c9d3`
then **spawned** for deferred trigger step **1428**, ordinal **3**,
with `["triggered", "/usr/lib/sysctl.d"]`, durably exited **0** with
zero output, and completed `succeeded`; `procps` ended `install ok
installed`. The reference-exact 78-byte `vtrgb` record retained SHA-256
`1fe9c0439ed1d49f6e06fad9d0a4ece1fba6826116f5cf26ba98e313c36570d3`;
the private `/proc` mount left no `/proc/sys`.

This is **not** a successful complete install or pinned-reference
parity proof. All seven deferred callbacks exited 0, including the
signed `libglib2.0-0t64` callback at ordinal 4, but that package
remained self `triggers-awaited` for its own schema trigger.
Following completed database step 1431, final verification refused
with `final_closure_mismatch`; `create.json` recorded exit **8**.
The glib self-file-trigger settlement is a separate, unpublished
change. This interrupted root is retained read-only and is never
resumed as a fresh installation.

Pinned dpkg 1.22.22 independently isolated that closure mismatch in
root-owned disposable copies of the earlier authenticated prestate,
**not** in the interrupted root. The signed glib archive's two empty
file-interest directories did not activate their own listener during a
no-force first install, or during a same-version re-unpack after its
interest was already registered. Separate directory-only and
regular-file probe packages did activate the same schema interest and
the latter's awaited edge was cleared by the successful pinned callback.
The narrowly corrected native path excludes a matching source/listener
only while emitting automatic **file** events; it keeps other listeners
and leaves explicit and dynamic trigger activations unchanged. New-root
verification of this correction is separate from the failed root above.

An earlier independent **new**, empty, root-owned mode-0700 root/cache/state
from the local procps-and-glib branch before #255's final squash,
`/root/debz-issue-86-glib-self-trigger/.real-snapshot/amd64-glib-self-fresh-long-1`,
used the protected local-branch ReleaseSafe binary SHA-256
`fe0ca285dad63711b1f9c0df9d81e01c0a2f402f36bcc3f7be29e4edc151219a`.
It independently refreshed authenticated metadata for signer
`F6ECB3762474EDA9D21B7022871920D1991BC93C`, planned a new
175-package lock (file SHA-256
`345431196138c0c7da03dfa3706f664c5ec8bef36f33c8c48cd2810d34d13d94`),
downloaded and independently SHA-512-rehashed all **175/175** archives
(67,976,788 bytes), and installed without retrying either interrupted
predecessor root. The native install returned exit **0** with receipt
SHA-256 `d1504d5ebff4ff1d46f7cd35a74b90bcbcae3f4df3538ded140f832ec642b5d9`.
Separate `transaction-result verify` reported `succeeded`,
`final_verification_status: exact_match`, `receipt_evidence: exact_match`,
and `root_operation_status: cleared`. All 175 dpkg status entries are
`install ok installed`, including glib; `triggers/Unincorp` is empty.
The sealed receipt has 81 activation events, **zero** automatic file
events addressed to their own source, no glib self listener, and five
successful step-1428 triggered callbacks. Glib's only source event is
the independent `ldconfig` activation, whose listener is `libc-bin`.

This proves the previously failing native final closure **on that local
branch**, not yet on final #255 plus this glib-only delta, and agrees with
the separately observed pinned dpkg 1.22.22 glib self-interest behavior.
It does **not** establish complete filesystem/reference parity or arm64
parity: no equivalent full pinned-reference root and bounded differential
capture were compared for this new signed lock. The bounded native capture
is retained as `evidence/native.snapshot.json` for that later comparison.
The older full-reference
harness mounts an unrestricted procfs in a private mount namespace and
is not an equivalent invocation-scoped proc view for the signed systemd
and udev scripts; do not treat it as an isolated proof for this run.

On final #255 squash `bef1f15a42791b1ba1e55a6bef220e9d82979436`
plus only the glib self-file-trigger change, a separate, genuinely new
root-owned checkout
`/var/lib/debz-glib-reference-255/checkout` with mode-0700
`.real-snapshot` created
`.real-snapshot/amd64-glib-255-protected-signed-1` from an empty root,
cache and state. Its ReleaseSafe executable SHA-256 was
`9f8bc04254dba33a14c8391ca07d1f3a86e66e8720a0df97d9c3e0fca5748030`;
its protected keyring SHA-256 was
`655e378ede8af51ed5f2ffe3669b38f124593abc1aa769c2cc76ef5986a2f835`.
Fresh authenticated metadata signed by
`f6ecb3762474eda9d21b7022871920d1991bc93c` produced a 175-package
`stonking` amd64 lock (file SHA-256
`188993c0e7f09da540bf4e49544f244a0c0e934621942c4f9903c8c114047129`).
Independent SHA-512 rehashing checked all **175/175** signed archive
objects, their exact cache-object set and declared sizes (67,976,788
bytes); `evidence/cas-rehash.tsv` SHA-256 was
`0e3f2a55adb3d91d60b216f9af8c61c5785e05ab8266b4f0fee220464558a7c1`.

Native `install` returned exit **0** with sealed receipt SHA-256
`fc24d39ca96bcdba878883b64b15e1c17f334b5673d4c4495d407fe259f79d15`.
Separate **read-only** native `transaction-result verify` reported
`succeeded`, `final_verification_status: exact_match`,
`receipt_evidence: exact_match` and `root_operation_status: cleared`;
all 175 packages, including glib and procps, are `install ok installed`,
and `triggers/Unincorp` is empty. The sealed receipt contains 81
activation events, no automatic file events addressed to their own
source and no glib self listener. Glib's sole source event addresses
`ldconfig` to `libc-bin`. The five deferred step-1428 callbacks include
the exact signed procps postinst at ordinal 3, spawned with
`["triggered", "/usr/lib/sysctl.d"]`, exit **0** and zero output; glib
has no self callback. This is completed **native amd64 closure** on
final #255 plus the glib-only delta, not full pinned-dpkg filesystem
parity or arm64 parity.

The longer disposable acceptance wrapper stopped **after** the successful
native installation because its separate verifier command incorrectly
passed the legacy-only `--state-path` option to the native verifier. Its
`create-summary.stderr` records that refusal and its later update/no-op
checks did not run. The correct documented native verifier omits
`--state-path`; its successful, separate result is retained as
`evidence/create-native-summary.json`. The completed root is retained
read-only, not retried as a new installation. A full pinned-reference
root and bounded differential capture for this exact lock have **not**
been compared; the manual two-architecture parity gate remains open.

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

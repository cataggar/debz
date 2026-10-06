# Audited maintainer-script runner

`debz.maintainer_script` runs exactly one Debian maintainer script for the
native transaction engine. It never invokes `dpkg` or `dpkg-deb`, never builds a
shell command string, and never inherits ambient process state. It implements
the maintainer-script policy of the
[native transaction engine v1 contract](native-transaction-engine-v1.md); the
package lifecycle that decides *which* script runs, in which order, is not part
of this module.

## Request contract

`MaintainerScriptRequest` is fully explicit:

- `root` is the absolute canonical path of the selected root;
- `identity` carries the package, version, architecture, script `kind`
  (`preinst`, `postinst`, `prerm`, `postrm`), the root-relative `script_path`,
  and the SHA-256 of the exact script bytes the caller already validated;
- `arguments` are the exact maintainer-script arguments without `argv[0]`;
- `variables` are additional maintainer-script variables from a closed
  allowlist (`DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT`, `DPKG_RUNNING_VERSION`);
- `policy` selects host-root permission, capture mode, descendant policy,
  bounded limits, and the allowed script directories.

`debz.runMaintainerScript(allocator, request, dependencies)` returns an
arena-owned `MaintainerScriptReport` that the caller releases with `deinit()`.
`debz.validateMaintainerScriptRequest(request)` exposes the same validation
without executing anything.

## Rejection before spawn

Every request is validated before any process exists. A rejected request is
reported as the exact `outcome = .{ .rejected = reason }` rather than an untyped
error, so the lifecycle can record why nothing ran. Rejections cover a
non-absolute or non-canonical root, host root without explicit policy, a script
path that is absolute, non-canonical, or contains `..`, a script that lives
outside the allowed script directories (`var/lib/dpkg/info` and
`var/lib/dpkg/tmp.ci` by default), a script file name that does not match the
requested kind, an invalid package, version or architecture, an invalid empty,
non-printable, oversized, or option-shaped argument, too many arguments, an
invalid or duplicated variable, and an invalid timeout, output limit, or script
directory.

The only accepted empty argument is the second argument of `postinst
configure ""`, which represents a package that has never been successfully
configured. It is preserved in argv and the invocation evidence, not omitted.

## Execution policy

A spawned script runs with:

- **Root isolation.** An alternate root is entered with a chroot-equivalent
  child setup (`chdir(root)` then `chroot(".")`) and working directory `/`, so
  the interpreter and every executable path resolve inside the selected root.
  Host-root execution requires `policy.allow_host_root`.
- **Fixed environment.** The environment is replaced by a deterministic sorted
  allowlist: `DEBIAN_FRONTEND=noninteractive`, `DPKG_ADMINDIR`, `DPKG_COLORS`,
  `DPKG_MAINTSCRIPT_ARCH`, `DPKG_MAINTSCRIPT_NAME`, `DPKG_MAINTSCRIPT_PACKAGE`,
  `DPKG_ROOT` (empty, because the child already runs inside the root), `HOME`,
  `LANG=C`, `LC_ALL=C`, and `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, plus the
  allowlisted request variables. No proxy, credential, or configuration value
  is inherited.
- **dpkg's umask.** The child sets `umask(022)` immediately before `execve`,
  as dpkg's `dpkg_program_init` does for its whole process, so files and
  directories a script creates never inherit the caller's umask. debz's own
  payload and dpkg-database writes set explicit modes, so they do not depend on
  the umask either.
- **No shell.** The script is executed with `execve` on an absolute in-root
  path and an exact argv; no `sh -c` string is ever constructed.
- **Child capability gate.** After any helper/proc mounts and chroot, but
  before `execve`, every native script child applies the same closed
  filesystem/account capability and syscall policy described below. Failed
  setup never executes the script.
- **Stdin.** Standard input is `/dev/null`, so scripts cannot block on input.
- **Standard descriptors.** Every descriptor the child still needs is first
  moved above the standard range, so installing stdin, stdout, and stderr is
  always a real `dup2` that clears CLOEXEC. A runner invoked with fd 0, 1, or 2
  already closed therefore still hands the script the intended streams instead
  of losing them at `execve`.
- **Descriptor seal.** Immediately before `execve`, every descriptor above the
  standard streams is marked close-on-exec for every maintainer script, not only
  signed proc-view scripts. Inherited host sockets, directory handles, helper
  preparation descriptors, and test leak descriptors therefore cannot become
  script authority. If the kernel rejects the seal, the script does not launch.
- **Private network namespace.** Every script is cloned into a fresh network
  namespace before any script byte runs. The child brings up only loopback; it
  receives no non-loopback interface, route, host TCP listener, or host
  abstract UNIX socket authority. Ordinary socket creation and loopback bind or
  self-connect inside the private namespace remain available. Failure to create
  the namespace is a typed, non-spawned `network_namespace` setup failure; the
  runner never falls back to host networking. Failure to bring up loopback after
  the child exists is a typed `network_setup` failure.
- **Bounded output.** Combined or separate stdout/stderr capture is bounded by
  `limits.maximum_output_bytes`; exceeding it is the distinct
  `output_limit_exceeded` outcome, not a truncated success.
- **Bounded runtime and cancellation.** The wall-clock budget is
  `limits.timeout_ms`; an injected `Cancellation` is polled at
  `limits.poll_interval_ms`. Supervision continues until the child is observed
  to have exited, so a script that closes or redirects its own stdout and
  stderr is still bounded by the deadline and the cancellation token rather
  than being waited on indefinitely.
- **Process-tree termination.** The child creates its own session and process
  group. Timeout, cancellation, and the output limit terminate it with
  `SIGTERM`, then escalate to `SIGKILL` after `limits.termination_grace_ms`.
  `descendants = .terminate` signals the whole process group and always issues
  one final group-wide `SIGKILL` sweep before the reap, so any descendant that
  is still in the group is removed; `descendants = .detach` signals only the
  script itself and leaves survivors running, preserving dpkg's daemon
  behavior.
- **Signal ordering.** Exit is observed with a non-destructive `waitid`
  (`WNOWAIT`) probe, so the leader stays an unreaped zombie and its pid — and
  therefore its process-group id — cannot be recycled while the runner is still
  signalling. Every `SIGTERM`/`SIGKILL`, including the final descendant sweep,
  is issued before the reap, and the reap is always the last operation.

## Network authority inventory and contract

Before the #278 contract, the ordinary native launcher used `fork()` and the
signed proc-view launcher used new mount/PID namespaces without `CLONE_NEWNET`.
Dropping `CAP_NET_ADMIN` did not remove ordinary host-network authority: a
host-root script could observe the host network namespace through `/proc/net`,
connect to a host loopback listener owned by a bounded test, bind host-network
loopback sockets, connect to a host abstract UNIX socket, and inherit any
non-CLOEXEC socket fd. The signed systemd broad-proc view also exposed
`/proc/net` for that shared namespace; the signed udev and sudo `subset=pid`
proc views did not expose `/proc/net`, but their sockets still used the host
network namespace.

The reviewed contract is now loopback-only private networking for every native
maintainer script. `/proc/net`, when present in the selected root or the signed
systemd proc view, describes the child's private namespace and contains only
loopback state; the signed udev and sudo proc views keep their existing
PID-only shape and still do not expose `/proc/net`. No signed maintainer script
in the real 20261001 closure is authorized to use host connectivity; the exact
systemd, udev, and sudo admissions need their current proc and file grants, but
no network peer, interface, route, or inherited socket fd.

## Private helper exposure

Experimental native integration can supply an optional `HelperMount` in a
runner request. Its source and existing target are pinned regular files in the
same root; initialization checks the bounded source bytes against the trusted
helper digest. The binding must remain alive throughout one invocation.

The child unshares its mount namespace, disables mount propagation, reopens the
paths without symlinks in the new namespace, and matches their pinned inode
identities. It then mounts the helper over the target using descriptor-based
mount operations. The helper view is read-only, nosuid, nodev and executable.
In the same private namespace, the source path is covered by a read-only,
nosuid, nodev, noexec view of the original package target, so the script cannot
invoke or copy the private helper through its staging name.
Both normal command lookup and absolute invocation paths see that helper, but
the package-owned target bytes and the parent's mount namespace are unchanged.
Alternate-root execution still enters the verified root before executing the
script. The fixed environment and `PATH` do not change.

`SystemLauncher.probeHelper` exercises the same mount and root setup without
executing a script. The production adapter must require an exited-zero probe
before package mutation. This requires Linux mount-namespace privileges
(`CAP_SYS_ADMIN`) and working `openat2`, `open_tree`, `mount_setattr`, and
`move_mount` support; setup failures retain their exact errno rather than
falling back to an unmodified helper. `Report.helper` identifies the source,
target and helper digest, which are also bound into invocation evidence.
Requests without a helper retain their existing execution and digest contract.

The experimental `debz.native_runtime` API supplies build-bound helper bytes through
`debz.native_helper`, records seeded-root deployment in a v2 execution request,
and requires the probe before package mutation. It refuses absent targets
without creating placeholders except for the authenticated v3 fresh-root
protocol: the owning archive's exact target is first published by the normal
journaled package payload step, then an attempt-scoped private source is
published and probed. Helper-aware recovery revalidates the original binding;
it never falls back to a package-owned executable or treats bootstrap bytes as
the final target. See
[native recovery and helper deployment](native-recovery.md#isolated-helper-request-v2).

The privileged `test-native-helper-namespace` target requires the positive
mount path, proves named and absolute helper execution, rejects writes through
the mount, preserves the original target, and proves alternate-root isolation.

## Exact signed systemd postinst proc view

The native lifecycle policy permits a separate, invocation-scoped view only
for `systemd:amd64` `261.2-1ubuntu2`, new-package `postinst
["configure", ""]`, signed script SHA-256
`d9df6a03ccb6b557c16ac1c674557a66c1db290f3c6d3cadbef335e0ce74e31d`
at `var/lib/dpkg/info/systemd.postinst`. The lifecycle rechecks its bytes and
pins the root-owned, mode-0755 *empty* `/proc` directory. The runner verifies
the exact 4,942-byte script again and obtains the kernel's current boot ID
from one host proc file, never by binding the host proc tree. Wrong identity,
script bytes, arguments, path, mountpoint, or `detach` descendant policy cannot
request this view; other invocations retain the previous launcher.
The native lifecycle may still hold a private staged
`var/lib/debz-lifecycle-scripts/systemd.postinst` copy at configure time.
For this one signed action, it resolves the installed path from the package
database, verifies **both** permitted copies against the signed script digest,
and executes only the installed dpkg-info path, matching pinned dpkg. An
unexpected alias or changed copy refuses before launch; there is no generic
script-path redirection.

Only this child is cloned into new mount, PID, and network namespaces. Namespace
PID 1 enters the same pinned chroot before mounting anything: its own root is
the selected root, not a supervisor's host root. With private propagation, it
mounts a fresh read-only, nosuid, nodev, noexec procfs with `hidepid=2`,
*immediately* covers its entire `/proc/sys` with a private tmpfs, publishes a
single read-only copy of the actual kernel boot ID at
`/proc/sys/kernel/random/boot_id`, then remounts the mask read-only. No
maintainer script runs between the first mount and the completed mask; the
other sysctl entries remain absent. Before `execve`, the child applies the
closed script capability and syscall policy below, including the removal of
`CAP_SYS_ADMIN` and `no_new_privs`; it cannot unmount the mask. The shared
descriptor seal prevents inherited host-root or socket fds from reaching the
script. A parent-death signal is established before setup with a control-pipe
check for the clone/race window. The script receives only its normal standard
streams, not root, socket, or host-proc descriptors. Namespace PID 1 exit kills all descendants, even those
that leave its process group, so the private mounts disappear before another
script or the deferred procps trigger can run. A setup failure is a typed
non-spawned `snapshot_proc` outcome, never a successful script exit. Helper overlay
setup retains its own existing `root_isolation` stage and failure claim.

The opt-in uses a distinct v3 policy domain and exact invocation digest
extension containing the SHA-256 of the kernel boot ID. Every policy domain,
including default v2 requests, also binds the `private-network-loopback-v1`
and `script-capability-seccomp-v1` contract tokens. Native program and
script-outcome recovery retain their existing program-policy and
unknown-outcome claims. Synthetic positive
and negative namespace tests run in the privileged
`test-native-helper-namespace` target; the signed postinst test additionally
requires an explicitly supplied disposable
`DEBZ_REQUIRE_SIGNED_SYSTEMD_PROC_ROOT`.
The parent needs namespace/mount privileges (`CAP_SYS_ADMIN`), and the child
needs `CAP_SYS_CHROOT` and `CAP_SETPCAP` to enter the pinned root and drop its
remount authority; `openat2`, `statx`, and `close_range(CLOEXEC)` must work.
The capability syscall header uses the kernel's 8-byte layout with its
32-bit PID at offset 4; Zig's `linux.cap_user_header_t` instead pads a
machine-width PID to offset 8, which can send an uninitialized PID and yield
`ESRCH` in Debug builds. The scoped runner checks the exact header layout
and verifies both 32-bit capability words and the bounding and ambient sets
after dropping them. These
requirements passed on the local Linux 6.18.31 privileged runner. Missing
support refuses the exact invocation without a proc or mount fallback.
Workflow-dispatch CI run
[`36322419073`](https://github.com/cataggar/debz/actions/runs/36322419073)
at ABI-corrected source `692c85a8bc3ac57653db7acc65e9687403c4d177`
also executed the mandatory privileged namespace step on hosted amd64 and
arm64, in both Debug and ReleaseSafe; the 33-test target includes PID 1
mount/mask/teardown and parent-crash regressions, not a capability skip.
WSL capability availability remains unverified.

## Exact signed udev postinst PID-only proc view

The separate udev admission is limited to `udev:amd64` `261.2-1ubuntu2`,
new-package `postinst ["configure", ""]`, signed SHA-256
`b7892e975bcce896c4938c2219a244fa03863d5eff37cd2eb66d2b8540f14606`.
Only the root-owned, mode-0755, 2,533-byte installed dpkg-info script may
execute. The staged new-package copy, if present, must match its signed
digest; unexpected aliases refuse. The runner pins the mode-0700 root,
empty root-owned `/proc` mountpoint, installed script, exact `/bin`-to-`usr/bin`
and `sh`-to-`dash`
link, and signed tool and sidecar bytes needed by the script (including
`systemd-tmpfiles`, `systemd-sysusers`, `systemd-hwdb`, dpkg and both udev
configuration files). The higher-priority `/etc`, `/run`, and
`/usr/local/lib` names that could shadow either sidecar must be absent.
Higher-priority `/usr/sbin` names for the exact `/usr/bin` commands must
also be absent, so the script cannot silently resolve a different provider.
Replaced, differently owned or multiply linked inputs refuse before
launch. This does not admit udev triggers, other
scripts, other architectures, or other package versions.

The child reuses the isolated PID-1/chroot/network boundary, descriptor seal,
private mount propagation, closed capability and syscall policy,
supervision and teardown described above, but mounts a fresh
`ro,nosuid,nodev,noexec,hidepid=2,subset=pid` procfs. It never mounts
the broader procfs or creates a boot-ID mask: `/proc/sys` and its boot-ID
path must both be absent before exec. PID 1's proc-visible root must
match the pinned fixture. The script cannot remount proc after
mount authority is dropped, and a failed setup records the existing typed
non-spawned `snapshot_proc` outcome. The policy previously had its own v3 digest
domain and now uses v4 with the capability gate; its original v3
domain pins the exact provider paths and hashes; systemd's boot-ID
boot-ID admission and its one-file `/proc/sys` representation remain
separate. This environment passed protected amd64 pinned-dpkg and
signed-script comparisons; it does not authorize a broader proc view
or establish arm64/WSL namespace support.

## Exact signed sudo postinst PID-only proc view

Only the authenticated new-package `sudo:amd64` `1.9.17p2-7ubuntu3`
`postinst ["configure", ""]`, SHA-256
`fd4c65932ab3ab7ce90c3633c42b8ee7a36af2c8292142d6e0cd134dda4c6383`,
can select the separately bound sudo view. The staged script must match the
root-owned 1,927-byte installed dpkg-info script; the root is mode 0700 and
its root-owned `/proc` mountpoint is an empty real directory. The pinned
tools include `dash`, dpkg and its helper's sourced
`/usr/share/dpkg/sh/dpkg-error.sh` fragment, the snapshot `update-alternatives`,
`systemd-tmpfiles`, and the exact GNU `rm`, `chown`, and `chmod` symlink
targets. Their `/usr/sbin` shadows, higher-priority `sudo.conf` tmpfiles
overrides, changed `/bin`, `/sbin`, shell or GNU command aliases, and changed
signed `sudo.conf`, `sudo.list`, or `sudo.ws` providers refuse before launch.
The corresponding program pins both authenticated `sudo` and `sudo-rs`
archives and the two exact root-owned, single-link `sudoedit` symlinks
restored by sudo unpack.

The namespace helper uses the same fresh, private
`ro,nosuid,nodev,noexec,hidepid=2,subset=pid` procfs as the udev mode,
without granting either script the other's identity. PID 1 and its
descendants stay in the same pinned chroot; `/proc/sys` and boot ID are
absent, inherited host-root and socket descriptors are sealed, and mount and
kernel authority are dropped before the script runs. Setup failure records a
typed non-spawned result; exit, deadline, crash and recovery preserve ordinary
durable outcomes and private mount teardown. The invocation uses a separate v5
policy domain with the capability gate and private-network token; systemd and
udev are separately bumped to v3 and v4. This is no grant to sudo triggers,
other scripts or package versions, and does not establish CI arm64 or WSL
namespace capability.
From the root-owned protected checkout on final #252 squash plus sudo-only
source `898d81e`, the Debug and ReleaseSafe privileged suites each ran
46/46 tests, including the signed sudo script and four distinct sourced
fragment refusals. Pinned dpkg 1.22.22 and the isolated signed-script
runs produced byte-identical sudo alternatives records; a separate new
authenticated root persisted sudo step 1376 exit 0 and installed. The
next refusal was python3 preinst at step 1383, before its script launched.
This local proof does not substitute for hosted arm64 namespace coverage
or authorize python3.

## Pre-cutover child capability gate (#257)

The **native** launcher now applies this gate to ordinary scripts and to the
three separately authorized, unchanged systemd boot-ID, udev PID-only and
sudo PID-only proc views. It runs only *after* required helper overlays, root
entry and proc mounts/masking; no child runs between mounting and restriction.
No new script digest, root identity, helper, proc entry or host-root admission
is authorized. The pinned reference runner remains a separate policy; this
change is not a native-only cutover or a claim of reference parity.

The closed list of potentially usable capabilities is `CAP_CHOWN` (signed
sudo's `chown` and account/file ownership), `CAP_DAC_OVERRIDE` (root-owned
file updates), `CAP_FOWNER` (ownership/permission repairs), `CAP_FSETID`
(file modes), `CAP_SETGID` and `CAP_SETUID` (signed udev
`systemd-sysusers` and ordinary account changes), and `CAP_SETFCAP`
(account/file capability metadata). No `CAP_MKNOD`, `CAP_SYS_CHROOT`,
`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, `CAP_NET_RAW`,
`CAP_BPF` or `CAP_CHECKPOINT_RESTORE` survives a privileged parent.
This list permits only capabilities the parent already held; it never grants
any. In the child, `capget` uses the 8-byte v3 kernel header (32-bit PID at
offset 4), `capset` masks **both** 32-bit effective, permitted and inheritable
words, and a readback verifies them. Every supported capability outside the
list is dropped from the bounding set and read back; all ambient capabilities
are cleared and individually checked, and `no_new_privs` is verified.
A parent without *any* usable or inheritable capability cannot drop its
bounding set; that case is accepted only after verifying all six current
capability words are zero and `no_new_privs` is set, so neither setuid
executables nor file capabilities can promote it. A partially privileged
parent that cannot drop its bounding set fails closed.

After the capset readback, a mandatory arch-checked seccomp filter rejects
mount/unmount, namespace entry/creation, pivot/chroot, new mount API,
open-by-handle, device creation, module loading, reboot/kexec, swap and
kernel BPF/perf/userfault/ptrace/write-foreign-process syscalls with `EPERM`;
it rejects namespace-flavored `clone`, and returns `ENOSYS` for `clone3` so
ordinary libc forks can use the filtered `clone` path. Wrong-architecture and
x32 syscall aliases kill the child. Missing capset, bounding, ambient, NNP,
or seccomp support refuses the script with a typed non-successful
`capability_policy` setup outcome (the existing `snapshot_proc` setup stage
applies to its three scoped modes). This syscall denylist supplements, rather
than replaces, the capability bounding contract.

The policy changes the on-disk script policy and invocation evidence: default
policy v1 becomes v2; systemd v2 becomes v3, udev v3 becomes v4 and sudo v4
becomes v5, each with an additional `script-capability-seccomp-v1` marker.
Preexisting durable programs/receipts must not be reinterpreted using the new
contract; prepare new policy-bound programs. Debug and ReleaseSafe
`test-maintainer-script`, privileged `test-native-helper-namespace`, and
`security-audit` exercise the new boundary. The privileged Zig probe checks
denied mount/namespace/module operations with a fully capable parent, both
capability words and readbacks, and permitted ownership, file-mode and
UID/GID changes on a disposable test file; it never attempts a real host
mutation.

### Non-skipped signed replay prerequisite

The ordinary required CI matrix (`build-and-test-workload`, native lifecycle
and recovery shards, and required disposable roots) builds **repository-local
signed synthetic packages**, not the exact snapshot systemd, udev or sudo
scripts. `test-native-helper-namespace` also runs the three signed tests
without roots, so those individual tests are reported as **SKIP**. Its
other passing results are capability/proc probe coverage, **not**
signed-script parity.
`ubuntu-real-snapshot` is an opt-in `workflow_dispatch` job (`run_native_real_snapshot
= true`) on amd64 and arm64, currently ReleaseSafe only. It performs a fresh,
authenticated snapshot install, but does not publish independently reusable
**pre-script** roots or run the three direct-script tests in Debug and
ReleaseSafe. A failed/interrupted install cannot be retried as fresh.

On an **amd64** runner, prepare three *independent*, protected, root-owned,
mode-0700 disposable copies from authenticated snapshot prestates, with
empty root-owned `/proc` directories and the exact pinned signed inputs.
The systemd copy must be before its configure; the udev copy must include
the signed sidecars and the expected regular-file `/dev` test targets; the
sudo copy must retain the pre-repair alternatives record and signed links.
The three `Snapshot*Proc.init` bindings revalidate exact bytes, owners,
paths and proc mountpoints before execution. Do not pass the historical
interrupted sources to the test, use the same copy for two variants, or
copy from a writable checkout as protected evidence. On each **new** set
of copies (Debug and ReleaseSafe separately), run:

```sh
zig build test-native-signed-proc -Doptimize=Debug -j2 \
  -Dsigned-systemd-proc-root=/root/protected/fixture/debug-systemd-before \
  -Dsigned-udev-proc-root=/root/protected/fixture/debug-udev-before \
  -Dsigned-sudo-proc-root=/root/protected/fixture/debug-sudo-before
```

Use `-Doptimize=ReleaseSafe` and *different fresh prestate copies* for
the ReleaseSafe run. The build target rejects missing, relative, duplicate
or wrong-architecture root paths and runs only the three positive signed
tests as root with `DEBZ_REQUIRE_SIGNED_PROC_ROOTS=1`; a missing environment
binding is an error, not a skip. Check each outcome and the retained root
bytes against a **separate** pinned-dpkg proof copy. From the root of a
**root-owned, non-group-writable checkout** with root-owned mode-0700
`.real-snapshot`, where `PINNED_DPKG`, all three `PRE_*` sources and
the new `*_PROOF` destinations are beneath that `.real-snapshot`, run
before mutating the native replay copies:

```sh
sudo -n tools/real-snapshot-systemd-proc-reference.sh \
  "$PINNED_DPKG" "$PRE_SYSTEMD" "$SYSTEMD_PROOF"
sudo -n tools/real-snapshot-udev-reference.sh \
  "$PINNED_DPKG" "$PRE_UDEV" "$UDEV_PROOF"
sudo -n tools/real-snapshot-sudo-reference.sh \
  "$PINNED_DPKG" "$PRE_SUDO" "$SUDO_PROOF"
```

The proof harnesses drop capabilities with the closure's `setpriv`, so
each proof source (never a native replay copy) needs `usr/bin/setpriv`
from the pinned util-linux; see below.

#### Generated signed prestates

`tools/real-snapshot-signed-proc-prestates.sh PINNED_DPKG WORKSPACE`
manufactures the three before-script sources. Run it **as root on amd64**
from the protected checkout root, after
`tools/real-snapshot-signed-proc-bindings.sh` has authenticated the pinned
closure into the same `WORKSPACE`. It reuses that closure and does not
fetch anything. It:

- verifies the pinned dpkg 1.22.22 binary and receipt, and the
  exact systemd and udev (261.2-1ubuntu2), sudo (1.9.17p2-7ubuntu3),
  sudo-rs (0.2.14-1ubuntu2) and util-linux versions. It binds the lock to
  the authenticated `stonking` Release (SHA-256 `0b2bb351…`, signer
  `f6ecb376…`) and to the sorted 175-package closure of name, version,
  architecture, SHA-512 and size (`7773e7c4…`). It does not bind the lock
  document digest, which also covers the local keyring path. It then
  rehashes every locked archive by size and SHA-512;
- bootstraps the same unregistered tool root as
  `tools/real-snapshot-reference.sh`, then lets **pinned dpkg** install the
  closure in the reviewed order with
  `tools/real-snapshot-reference-order.py --prestate`. Non-target packages
  are configured in explicit batches, so no target is configured
  implicitly. Before systemd and udev are configured, the order tool binds
  each unchanged signed postinst `noexec`: dpkg records `half-configured`
  without running the script, and the root is copied at that point. sudo
  is copied while `unpacked`, after sudo-rs registered its alternatives;
- checks each copy: root-owned mode 0700, an empty `proc`, the dpkg
  status, the signed postinst and `usr/bin/dpkg` bytes, and no `setpriv`.

It then applies three reviewed normalizations:

- pinned dpkg writes `sudo.list` in extraction order, with symbolic links
  last. The signed sudo binding pins the C-sorted list, so the script sorts
  it and requires the pinned digest (2376 bytes, `92f90d6a…`). This proves
  that only the order changed.
- udev's static-node permissions only adjust existing paths. `dev/kvm`,
  `dev/fuse` and `dev/snd/seq` are created as empty **regular files**,
  `root:root` 0600, never as device nodes, as in the recorded pinned proof.
- util-linux is not yet unpacked in these states. The script therefore
  extracts only its `usr/bin/setpriv` (SHA-256 `9e0d70d2…`) into
  `WORKSPACE/reference-tools` for the pinned-dpkg proof sources.

The prestates are disposable fixtures, not native installation results.
The build tree is removed; `WORKSPACE/prestate-build/evidence` keeps the
reference order logs.

`tools/real-snapshot-signed-proc-compare.py TARGET NATIVE PROOF REPORT`
inventories a replayed native root and its pinned-dpkg proof. It records
type, owner, mode, size, link count, link target, device number and SHA-256
for every entry, requires `proc` to be empty and refuses mount crossings.
The native test runs only the signed postinst, while the proof runs
`dpkg --configure`, so a few differences are expected. Each is accepted
only by an exact rule, derived from the first hosted amd64 reports and
covered by `tools/test_real_snapshot_signed_proc_compare.py`:

- **proof harness files:** `usr/bin/setpriv` (only in the proof, SHA-256
  `9e0d70d2…`) and pinned dpkg (`0a20f601…`). For udev and sudo that is
  proof-only `usr/local/sbin/dpkg`; for systemd it replaces the snapshot
  `usr/bin/dpkg` (`6587ef9e…`). Also `run/mount`, the empty root-owned
  0700 directory that the chrooted `mount -t proc` (libmount) creates;
- **dpkg bookkeeping:** `var/log/dpkg.log` exists only in the proof and
  may record only its configure of the target. In `status` only the
  target stanza may change: `unpacked` or `half-configured` becomes
  `installed`, `Config-Version` may equal only `Version`, and each
  `newconffile` hash becomes the MD5 of the proof's installed conffile.
  The proof's `status-old` must equal the native (unconfigured) `status`;
- **new conffiles:** each `newconffile` in the target's native status
  (sudo's `/etc/sudo.conf` and `/etc/sudo_logsrvd.conf`) stays
  `NAME.dpkg-new` natively and must be byte- and metadata-identical to the
  proof's installed `NAME`. dpkg installs new conffiles before the
  postinst; the native test replays the postinst alone;
- **nondeterminism:** systemd's `etc/machine-id` may differ only in
  content, and each copy must be one lowercase 32-hex-digit line;
  `var/log/alternatives.log` may differ only in its `update-alternatives
  YYYY-MM-DD HH:MM:SS:` stamps.

Any other difference, or an unreadable or changed file, fails.

#### Hosted protected amd64 replay

The CI job **Signed proc replay in protected amd64 roots**
(`signed-proc-protected-replay`) runs on hosted `ubuntu-24.04` x86_64 for
every push and pull request. Debug and ReleaseSafe each run on their own
runner with fresh roots, within 35 minutes. Each run:

1. runs the prestate and binding scripts from the runner-owned checkout
   and requires both to refuse the writable ancestry. It also requires
   `test-native-signed-proc` to reject missing and relative roots;
2. stages the reviewed commit (`git archive HEAD`), the verified Zig 0.16.0
   installation, the pinned dpkg prefix and the pinned
   `ubuntu-archive-keyring.gpg` (ubuntu-keyring 2023.11.28.1) beneath
   `/srv/debz-protected/signed-proc`. Every staged entry and every
   ancestor must be `root:root` and not group- or world-writable; the
   runner's own `/usr/share` is writable, so the keyring is copied and pinned;
3. as root, builds `debz`, authenticates the closure with the binding
   script and generates the prestates;
4. copies each prestate twice: once as a native root and once as a proof
   source with `setpriv`. The sudo proof harness restores the two signed
   `sudoedit` payload links (`-> sudo.ws`, `-> sudo.ws.8.gz`) before
   configure. The job applies the same two links to the native sudo root, so
   both start in the same state. The prestate itself keeps the
   `/etc/alternatives` links that sudo-rs registered. It runs the three
   pinned-dpkg proof harnesses on the proof sources, and runs
   `test-native-signed-proc` on the native roots. It requires `All 4 tests passed.`, with each of the three signed
   replays reported `OK`; the fourth is the root module's reference test.
   A skip therefore fails the job;
5. runs the comparison unit tests, compares each native root with its
   proof, and fails on any unexpected difference. It then executes the signed
   binding refusal fixtures from the same workspace. Only the three positive
   replays may skip there, because step 4 ran them;
6. always copies bounded evidence (logs, the lock, `prestates.tsv`,
   reference order logs, comparison reports, the proofs' `dpkg.log` and
   both sudo `alternatives.log` files) into the
   `signed-proc-protected-replay-*` artifact. It fails if a mount under
   the staged path survives, then removes the staged path.

The job is **not** part of the `Build and test` aggregate. The pinned
`stonking` snapshot Release is `Valid-Until: Tue, 06 Oct 2026 22:41:59 UTC`.
After that date, authentication fails closed. The #262 repin also changes
the signed identities that these bindings pin. Make the job required only
after that repin, with refreshed pins and a green run in both modes.
`tools/security-audit.py` (`check ci-signed-proc`) and
`test/security-policy.zig` keep its runner, modes, timeout, staging,
refusals and no-skip assertions fixed.

#### Signed binding refusal fixtures

The udev and sudo refusal and changed-after-binding tests read
`DEBZ_REQUIRE_SIGNED_{UDEV,SUDO}_PROC_*_ROOT` variables and **return
without assertions** when those are unset, so the ordinary suite counts
them as passes without evidence. To execute them with the exact signed
bytes on either native architecture, build a fresh set of root-owned
binding roots per optimization mode from the protected checkout root
(including its root-owned `.real-snapshot` and a root-owned `debz` build):

```sh
sudo -n tools/real-snapshot-signed-proc-bindings.sh \
  zig-out/bin/debz .real-snapshot/debug-bindings
sudo -n env -i PATH="$PROTECTED_ZIG_DIR:/usr/sbin:/usr/bin:/sbin:/bin" \
  HOME=/root DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE=1 \
  $(sudo -n cat .real-snapshot/debug-bindings/bindings.env) \
  zig build test-maintainer-script -Doptimize=Debug -j2
```

The script plans and downloads the authenticated amd64 `ubuntu-minimal`
closure from the pinned `stonking` snapshot, rehashes every locked
archive by size and SHA-512, extracts each pinned input from its single
providing archive, and writes 6 udev and 9 sudo variants: one valid
binding for each changed-after-binding test and one mutation per refusal.
The Zig bindings, not the script, compare exact bytes, owners, modes and
links. These roots contain only the signed inputs. They **cannot** run a
script and do not satisfy `test-native-signed-proc`. The changed variants
are mutated by their tests; do not reuse a set.

To replay **ordinary** signed lifecycle fixtures on either native
architecture, the existing CI uses
`zig build test-native-lifecycle-zig -Dnative-reference-dpkg=PATH
-Doptimize=Debug -j2` and its ReleaseSafe variant; `PATH` is prepared
with `python3 tools/prepare-native-dpkg.py --architecture amd64` or
`--architecture arm64` in that runner's worktree. These fixtures prove
script execution and pinned-dpkg parity for the selected native architecture
but **cannot** substitute for exact Ubuntu signed systemd/udev/sudo bytes.
Those three native proc identities and their pinned sidecars are deliberately
**amd64-only** in the current admission; no arm64 signed proc replay is
possible without a separately reviewed arm64 identity/profile and protected
arm64 inputs. In the authenticated arm64 `ubuntu-minimal` closure of the
same snapshot, all three postinst scripts and the ten pinned interpreted,
data or file-list inputs are byte-identical to amd64; the 12 pinned ELF
inputs differ. Do not weaken the amd64 identity checks or use emulation as
native-arm64 proof. The opt-in snapshot job may be invoked with:

```sh
gh workflow run ci.yml --repo cataggar/debz \
  --ref copilot/issue-257-fleet-capabilities \
  -f run_native_real_snapshot=true \
  -f ubuntu_snapshot_uri=https://snapshot.ubuntu.com/ubuntu/20260923T000000Z \
  -f ubuntu_snapshot_suite=stonking
```

This dispatch can provide fresh-root ReleaseSafe observations but does
**not** satisfy the direct signed prestate replay gate. That gate is the
hosted protected amd64 replay job described above; a skipped or non-zero
script outcome there remains an explicit blocker.
The shared network boundary still belongs to #278.

**Separate network boundary (#278):** dropping `CAP_NET_ADMIN` and
`CAP_NET_RAW` does *not* disable ordinary socket or host-network access.
The current `/proc/net` view and inherited socket/namespace boundary must
be investigated and decided **for both** engines in #278. Do not infer host
network isolation from this gate, silently adjust one signed proc view, or
authorize any new network connectivity on this evidence.

## Exact signed python3 preinst inert alternatives call

The separate new-package `python3:amd64` `3.14.7-3`
`preinst ["install"]` (signed SHA-256
`115f972bfeb85d083537b4d7fc59261979c6a2511d85b84407c7d7da38c9a85f`)
does not receive proc, mount, or general shell authority. The exact
installed and any staged script must match, as must authenticated python3
and python3-minimal archives, their dpkg ownership lists, the
`/usr/bin/python3 -> python3.14` link, signed `dash` and GNU `rm` bytes,
their aliases, the snapshot-pinned alternatives tool, and the root-owned
mode-0700 fixture root. `/proc` must be empty, `/usr/sbin` tool shadows
and the HTML cleanup target absent, and `/dev/null` must be a root-owned,
mode-0600 or mode-0644, empty regular file. Both modes were separately
proved against pinned dpkg 1.22.22 and the signed script in protected
disposable roots; 0640 and 0666 refuse. Other tool, root, alias,
script, argument, package, or architecture identities refuse before launch.

On this branch, the tool rejects the script's literal
`--auto /usr/bin/python3` operand before alternatives state changes.
The signed script still runs **unmodified**, including its `|| true`,
`[ -L ... ]` and `rm -rf` lines; the existing launcher records its real
exit, limits and output. All 14 alternatives groups remain immutable.
Successful completion additionally requires the 96-byte
snapshot-tool diagnostic to have been redirected into `/dev/null`
with SHA-256
`3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc`.
A different exit or redirected witness cannot be converted into success;
post-launch proof failure requires durable recovery. The managed checkpoint
includes that one changed file. This does not admit `--auto` with an
absolute name elsewhere or the signed script's upgrade branch.

## Outcome taxonomy

`MaintainerScriptOutcome` keeps every result exactly distinguishable:
`exited` (with the code), `signaled` (with the signal), `timed_out`,
`cancelled`, `output_limit_exceeded`, `setup_failed` (with the exact stage —
`pipe`, `stdin_device`, `fork`, `session`, `standard_streams`,
`root_isolation`, `working_directory`, `execute`, `launcher`, `wait` — and the
operating-system error number; `snapshot_proc` and `capability_policy` both
represent non-executed child setup failures), and `rejected`. `Outcome.spawned()` states
whether a child process actually existed, which separates pre-fork setup
failures from in-child failures. `Report.succeeded()` is true only for exit
code 0.

## Provenance evidence

The report records the script identity, isolation, absolute in-root program
path, complete argv, the exact environment, capture and descendant policy,
bounded output, `terminated_process_group` (the still-running script had to be
terminated), `escalated_to_kill`, `issued_descendant_sweep` (the final
group-wide `SIGKILL` sweep was issued under the `terminate` policy, including
after a clean exit), and domain-separated length-prefixed SHA-256 digests of the script, argv,
environment, policy, invocation, stdout, stderr, and combined output. The
invocation digest binds root, isolation, program, argv, environment, and limits
into one value suitable for later transaction provenance. Supervision flags are
deliberately exact about what is observable: `issued_descendant_sweep` records
that the sweep signal was delivered to the process group, never that a
descendant existed, because a group-wide `kill` cannot distinguish an empty
group from a killed survivor. Evidence digests cover the request and the
output, so renaming or extending these flags does not change any digest.

## Injection seam and tests

`MaintainerScriptLauncher` is the audited child boundary. Production uses
`SystemMaintainerScriptLauncher`; hermetic tests substitute a recording launcher
to exercise validation, the environment allowlist, invocation and evidence
binding, the outcome taxonomy, and launcher failure mapping without spawning
anything. Real-execution tests run the system launcher against fixture scripts
in a temporary directory under explicit host-root policy and cover the
sanitized child environment, `/dev/null` stdin, bounded and combined capture,
signals, timeout with descendant-tree termination, cancellation, the output
limit, timeout and cancellation of a script that closed its own captured
streams, and — from a forked helper whose own fd 0, 1, and 2 are closed — the
correct installation of the child's standard descriptors. Termination ordering
is checked deterministically through a recording process-group seam that
asserts the reap is the last operation and that the detach policy never signals
descendants. Sweep evidence is tested on both seams: a clean exit under the
`terminate` policy reports `issued_descendant_sweep` without reporting
termination, an actually terminated tree reports both, the `detach` policy
reports neither, and a rejected request reports neither because no process ever
existed.

The strongest alternate-root test this repository's infrastructure supports
asserts the chroot boundary directly: unprivileged runners observe
`setup_failed{ .root_isolation, EPERM }`, while a privileged runner observes an
`execute` failure for an interpreter that exists only outside the root, which
proves the isolation took effect. A host-root positive control runs in the same
test, so the assertion never degrades into a skip.

`tools/security-audit.py` pins the native child-process boundary
(`linux.fork`, `linux.execve`, `linux.chroot`) to this module, so no other
production source can spawn a child outside the audited policy.

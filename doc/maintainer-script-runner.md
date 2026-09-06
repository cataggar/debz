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
requested kind, an invalid package, version or architecture, an empty,
non-printable, oversized, or option-shaped argument, too many arguments, an
invalid or duplicated variable, and an invalid timeout, output limit, or script
directory.

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
- **No shell.** The script is executed with `execve` on an absolute in-root
  path and an exact argv; no `sh -c` string is ever constructed.
- **Stdin.** Standard input is `/dev/null`, so scripts cannot block on input.
- **Standard descriptors.** Every descriptor the child still needs is first
  moved above the standard range, so installing stdin, stdout, and stderr is
  always a real `dup2` that clears CLOEXEC. A runner invoked with fd 0, 1, or 2
  already closed therefore still hands the script the intended streams instead
  of losing them at `execve`.
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
  `descendants = .terminate` signals and finally sweeps the whole process
  group; `descendants = .detach` signals only the script itself and leaves
  survivors running, preserving dpkg's daemon behavior.
- **Signal ordering.** Exit is observed with a non-destructive `waitid`
  (`WNOWAIT`) probe, so the leader stays an unreaped zombie and its pid — and
  therefore its process-group id — cannot be recycled while the runner is still
  signalling. Every `SIGTERM`/`SIGKILL`, including the final descendant sweep,
  is issued before the reap, and the reap is always the last operation.

## Outcome taxonomy

`MaintainerScriptOutcome` keeps every result exactly distinguishable:
`exited` (with the code), `signaled` (with the signal), `timed_out`,
`cancelled`, `output_limit_exceeded`, `setup_failed` (with the exact stage —
`pipe`, `stdin_device`, `fork`, `session`, `standard_streams`,
`root_isolation`, `working_directory`, `execute`, `launcher`, `wait` — and the
operating-system error number), and `rejected`. `Outcome.spawned()` states
whether a child process actually existed, which separates pre-fork setup
failures from in-child failures. `Report.succeeded()` is true only for exit
code 0.

## Provenance evidence

The report records the script identity, isolation, absolute in-root program
path, complete argv, the exact environment, capture and descendant policy,
bounded output, `terminated_process_group` (the still-running script had to be
terminated), `escalated_to_kill`, `swept_descendants` (a group-wide `SIGKILL`
sweep removed survivors under the `terminate` policy), and
domain-separated length-prefixed SHA-256 digests of the script, argv,
environment, policy, invocation, stdout, stderr, and combined output. The
invocation digest binds root, isolation, program, argv, environment, and limits
into one value suitable for later transaction provenance.

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
descendants.

The strongest alternate-root test this repository's infrastructure supports
asserts the chroot boundary directly: unprivileged runners observe
`setup_failed{ .root_isolation, EPERM }`, while a privileged runner observes an
`execute` failure for an interpreter that exists only outside the root, which
proves the isolation took effect. A host-root positive control runs in the same
test, so the assertion never degrades into a skip.

`tools/security-audit.py` pins the native child-process boundary
(`linux.fork`, `linux.execve`, `linux.chroot`) to this module, so no other
production source can spawn a child outside the audited policy.

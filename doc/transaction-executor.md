# Dpkg transaction executor

`debz.executeTransaction` executes an owned schema-v2 solver plan against one
explicit absolute install root. Host root (`/`) is denied unless
`RiskPolicy.allow_host_root` is explicitly enabled. The production filesystem
adapter rejects symlinks in every root and artifact-path component.

Before mutation, the executor validates the complete action/ordering shape,
identities, artifact mappings, paths, conffile policy, and typed force policy.
It then acquires, in fixed order, the debz transaction lock,
`var/lib/dpkg/lock-frontend`, and `var/lib/dpkg/lock`, using bounded waits.
The production adapter uses POSIX record locks compatible with dpkg.
Timeout identifies the blocking path and no dpkg process is started. The
database lock is released after this bounded probe so dpkg can own it; debz
retains its transaction lock and the frontend lock, with
`DPKG_FRONTEND_LOCKED=true`, across the transaction.

Each cached archive is reread immediately before its unpack command. Size,
SHA-256, outer archive, payload paths, control identity, requested identity,
scripts, and conffiles are revalidated with `deb_payload.validate`.

Processes are invoked directly as `/usr/bin/dpkg`; no shell or command string
is used. Every invocation replaces the environment with the fixed audited set
`DEBIAN_FRONTEND`, `DPKG_COLORS`, `DPKG_FRONTEND_LOCKED`, `HOME`, `LC_ALL`,
and `PATH`. The fixed locale is `C`. Dpkg receives both `--root` and
`--admindir`.

Callers must select one noninteractive conffile policy:

- `keep_existing` uses `--force-confold`.
- `use_package_version` uses `--force-confnew`.

No general dpkg force option is enabled by default. Supported exceptions are a
typed `ForceRisk` list and therefore appear in command provenance.

The executor follows `ordered_actions` exactly, including planner-linearized
cycles. Configure commands defer triggers with `--no-triggers`; one final
`--configure --pending` command processes them deterministically. Planning
refuses unhealthy pre-existing dpkg states, so this does not widen execution
to unrelated pending packages.

Failures include phase, package identity, exit status or signal, bounded dpkg
diagnostics, completed-command count, plan digest, and command/artifact
digests. Cancellation and lock loss stop at command boundaries. A report is
successful only after every ordered command and final trigger command exits
zero. Recovery and post-state verification are intentionally deferred to #28.

`FileSystem`, `LockManager`, `ProcessRunner`, and `Cancellation` are injectable
for hermetic tests. `SystemFileSystem`, `SystemLockManager`, and
`SystemProcessRunner` provide production adapters.

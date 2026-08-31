# Dpkg transaction executor

`debz.executeTransaction` executes an owned schema-v2 or schema-v3 solver plan against one
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

Each cached archive is reread immediately before its bootstrap-extract or unpack command. Size,
SHA-256, outer archive, payload paths, control identity, requested identity,
scripts, and conffiles are revalidated with `deb_payload.validate` for
repository packages or `deb_payload.inspectLocal` for tagged local artifacts.
Every install-like action requires an exact SHA-256 and size. Origin checks
branch explicitly between authenticated repository identity and local artifact
ID, acquisition URL, trust mode, digest, size, and control identity.
An exact-lock-v2 local package is always replayed from its locked artifact when
dpkg status alone is the only installed-state evidence. Final execution and
recovery verification require a completed unpack journal entry with that
artifact digest and an exact plan-origin/size match; matching dpkg identity
alone is insufficient.

`Policy.exact_lock_verification` defaults to `full_closure`, preserving the
existing rule that every installed package must appear in the exact lock.
The explicit `locked_packages` policy is available for operation locks that
contain every non-remove plan action rather than a complete target manifest.
It still rejects a missing or wrong locked identity and requires each locked
repository or local origin, digest, size, and completed unpack digest to match;
only unrelated healthy package identities are outside that verification scope.
The selected scope is part of the executor policy digest and therefore the
recovery journal and transaction provenance binding.

Schema-v2 recovery journals retain the released plan-digest algorithm so
interrupted repository-only transactions remain recoverable after an upgrade.
For schema-v3 plans, the recovery journal's plan digest additionally binds the
complete tagged origin of every archive-producing action, including the union
tag, artifact ID, SHA-256, size, package identity, acquisition URL, trust mode,
and solver priority.

For a new root, the authenticated closure containing absent Essential packages
receives a deterministic `/usr/bin/dpkg-deb --extract` bootstrap phase before
normal dpkg processing. This runs no maintainer scripts and makes Essential
packages plus their omitted or explicit runtime prerequisites available for the
first pre-installation and configuration scripts; every archive is subsequently
unpacked by dpkg so ownership and database state remain authoritative.
Before dpkg runs, legacy top-level directories created by safe archive
extraction are merged into their `usr` targets without overwriting any existing
entry, then restored to exact merged-usr links. Authenticated `base-passwd`
master files, when present, seed the new root's initial passwd and group
databases before maintainer scripts run. Wrong links, path collisions, and
unsupported entries fail closed.

Processes are invoked directly as `/usr/bin/dpkg-deb` or `/usr/bin/dpkg`; no
shell or command string is used. Every invocation replaces the environment with the fixed audited set
`DEBIAN_FRONTEND`, `DPKG_COLORS`, `DPKG_FRONTEND_LOCKED`, `HOME`, `LC_ALL`,
and `PATH`. The fixed locale is `C`. Dpkg receives both `--root` and
`--admindir`. Standard output and error diagnostics are captured concurrently,
combined in fixed stdout-then-stderr order under independent bounds, and every child has a
configurable nonzero deadline (five minutes by default); expiry terminates and
reaps the child and produces a structured `process_timeout` failure. Production
cancellation is observed while a command is running and likewise terminates and
reaps the child before returning an interruption report.

Callers must select one noninteractive conffile policy:

- `keep_existing` uses `--force-confold`.
- `use_package_version` uses `--force-confnew`.

No general dpkg force option is enabled by default. Supported exceptions are a
typed `ForceRisk` list and therefore appear in command provenance.

The executor follows `ordered_actions` exactly, including planner-linearized
cycles and Essential bootstrap extraction. It unpacks in libsolv's
Pre-Depends-aware order and inserts `dpkg --configure --pending` barriers before
packages with Pre-Depends and after the final unpack, allowing dpkg to configure
normal dependency cycles in its native order. A barrier omits dpkg's
single-error abort limit: when dependency cycles leave a nonzero result, the
executor proceeds only if a bounded status reread proves a strict increase in
fully configured packages. No-progress and maintainer-script failures remain
structured transaction failures. Remove, unpack, and configure
commands defer triggers with `--no-triggers`; one final
`--triggers-only --pending` command processes them deterministically without
configuring unrelated pending packages.

Failures include phase, exact package identity, exit status or signal, bounded dpkg
diagnostics, completed-command count, plan digest, and command/artifact
digests. Root safety and lock ownership are rechecked at command boundaries. A report is
successful only after every ordered command makes its required state transition,
the final trigger command exits zero, and exact post-state verification passes.
Recovery and post-state verification are intentionally deferred to #28.

`FileSystem`, `LockManager`, `ProcessRunner`, and `Cancellation` are injectable
for hermetic tests. `SystemFileSystem`, `SystemLockManager`, and
`SystemProcessRunner` provide production adapters.

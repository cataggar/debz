# Native lifecycle execution

The item-12 lifecycle acceptance boundary composes the native program compiler,
data/conffile materialization, package database, root-operation coordinator, and
audited maintainer-script runner. It is private: production native selection
remains unavailable and the legacy backend remains the default.
[Trigger execution](native-triggers.md) and
[durable native recovery](native-recovery.md) extend this private boundary.
Production integration remains a separate milestone.

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

## Independent reference acceptance

Run on native Linux amd64 or arm64 with `dpkg`, `dpkg-deb`, `ldd`, `/bin/sh`, and
passwordless `sudo`:

```sh
zig build test-native-lifecycle -j2
zig build test-native-lifecycle -Doptimize=ReleaseSafe -j2
```

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

Advanced fixtures exercise:

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

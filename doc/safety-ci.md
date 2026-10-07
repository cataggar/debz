# Safety CI, fuzzing and audits

`zig build fuzz` runs every checked-in deterministic corpus plus 256
deterministic mutations per corpus seed. The bound is configurable:

```sh
zig build fuzz -Dfuzz-cases=10000
zig build fuzz -Dfuzz-cases=100000   # longer local campaign
```

CI runs 128 mutation cases per seed on pull requests and 5,000 on the
scheduled campaign. x64 runs the longer campaign; x64 and arm64 run all
deterministic corpora and Debug/ReleaseSafe builds and tests. A failing
deterministic mutation logs its seed and case indexes for exact replay.

Required build workloads run as five disjoint jobs. Each job runs for both
architectures and both optimization modes, so there are 20 rows, and each row
has a 45-minute limit. The former single workload job had a 90-minute limit
and took 34–90 minutes per row. It timed out on x64 ReleaseSafe at 90.1
minutes. `zig build test` now depends only on five partition steps. Every
former `test` member belongs to exactly one partition, and every former
workload command runs in exactly one job:

| Required job | Commands (`-j2 --summary all`; pinned dpkg where marked) |
| --- | --- |
| `build-and-test-workload` (core) | install; `test-workload-core` (unit, CLI, help-flag, consumer, snapshot comparator, apt acceptance unit and repository-add tests); ReleaseSafe `run -- --help` and download action fixture |
| `build-and-test-workload-production` | `test-workload-production` (package family, production backend, required security and customize tests); pinned `test-native-triggers-zig` and `test-native-diversion-settlement-zig` |
| `build-and-test-workload-apt-system` | `test-workload-apt-system` (system profile, apt system API/CLI/command/state/orchestrator and required orchestrator security tests); installed-CLI `test-apt-system-acceptance` in both modes; Debug privileged `test-apt-system` |
| `build-and-test-workload-native` | `test-workload-native` (native alternatives, snapshot, differential, fixture, conffile, dpkg reference/evidence, SHA-512, trigger queue, lifecycle/trigger/settlement unit and recovery unit tests); pinned `test-native-materialization`, `test-native-conffiles`, `test-native-differential` and `test-native-lifecycle-zig`; `test-native-helper-namespace` |
| `build-and-test-workload-release` | `test-workload-release` (apt schema, native-only rehearsal and the real-snapshot repin harness); `fuzz`; Debug `test-release`; pinned lifecycle/trigger reference oracles; standalone Zig workspace selectors |

Manual CI dispatches have a boolean `run_full_matrix` input, defaulting to
`true`. Explicitly setting it to `false` skips all five workload jobs, all six
native recovery jobs, the `Build and test` aggregators, and `integration-full`.
Push, pull-request, and scheduled coverage is unchanged. Full-run aggregators
still require every shard to succeed: failure, cancellation, or an unexpected
skip cannot pass. An opted-out dispatch intentionally skips the aggregators
and is **not** evidence that the full matrix passed. Action checks, security
audit, release checks, fuzzing, and `integration-required` still run.

The security audit enforces this inventory in three ways:

- `build.zig` must bind the aggregate `test` step to exactly the five
  partitions, and every former member to exactly one of them.
- The workload jobs together must run every former Zig target exactly once.
- CI must run each partition once and must never run the aggregate
  `zig build test`.

Mutation tests reject every moved, dropped or duplicated partition member or
target. A few small unit prerequisites of the pinned compare and oracle
targets still run as build dependencies inside the job that owns each target:
the lifecycle, trigger and settlement unit runs, each under a minute. No CI
command runs twice.

The prepared Zig-only recovery transition has three required jobs on each
architecture, each bounded to 35 minutes. The `native-recovery-zig-*` jobs
run their targets in **both** modes with pinned dpkg and signed fixture
dependencies; the core/repository shard also runs the standalone Zig unit
target in Debug and ReleaseSafe:

| Required job | Zig targets (prefix `test-native-recovery-` unless shown) |
| --- | --- |
| `native-recovery-zig-workflows` | `zig`, `zig-repository`, `helper-zig`, `zig-bootstrap`, `zig-parity`, `zig-rollback-clock`, `test-native-root-import` |
| `native-recovery-zig-family` | `zig-family` |
| `native-recovery-zig-scenarios` | `zig-scriptless`, `zig-statoverride`, `zig-literal`, `zig-metadata`, `zig-conffile`, `zig-final-gaps`, `zig-diversions` |

On two x64 hosted runners the old serial job received a shutdown signal
after about 40–42 minutes, after both Python modes and the core Zig target
passed but before the FAMILY target completed. The Python modes alone took
about 34 minutes on the second run; moving only the Zig targets would leave
too little runner margin. The first split still lost its x64 core/workflows
runner after about 21 minutes during FAMILY, so FAMILY runs in its own shard.
Sharding both legacy modes and Zig targets preserves every pre-retirement
CI command exactly once per mode and architecture on the published parent,
which still requires both Python gates. Only this prepared transition removes
its legacy job. Its `Build and test` checks require all 20 workload rows and
all three Zig recovery shards on each architecture; failure, cancellation,
or a skipped row of any shard cannot make either architecture's aggregate
pass. The audit also rejects any recovery command duplicated outside its
assigned shard. The hosted runner budget remains a measured risk until both
the pre-retirement and post-retirement matrices complete in CI.
The published four-job recovery graph uses 14 verified Zig installations;
this prepared three-job graph requires exactly 13 in both security and
release workflow policy audits.

Ordinary CI and release builds obtain Zig 0.16.0 from `cataggar/zig` through the
commit-pinned `ghr` v0.8.1 install action, verify the release with its pinned
minisign key and GitHub attestations, and check `zig version` before use. The
action cache contains only the exact installed tool and `ghr` transaction state;
it does not restore Zig's local or global build caches, preserving the previous
no-build-cache policy.

The dispatch-only native snapshot job instead shares the small protected
proof's root-owned bootstrap: the same size/SHA-256/minisign-pinned Zig and
verified library tree, package-derived Ubuntu keyring and pinned dpkg. It
stages a new `native-ci-RUN-ATTEMPT-ARCH` tree on each architecture; the small
proof retains a distinct `ci-RUN-ATTEMPT-ARCH` tree. No proof workspace is
reused. The native wrapper requires protected reviewed keyring bytes, without
an ambient image fallback; the full reference wrapper invokes the explicit
absolute protected `DEBZ_ZIG` with its protected `lib`, without extending its
fixed PATH. The 20 ordinary ghr-install jobs include the separate signed proc
replay, but not the protected native snapshot job; both protected consumers are
checked separately. Bounded diagnostics/export and named descendant cleanup
run on failure, without returning ownership of protected inputs to the runner.
Successful setup or small-proof results do not claim full wrapper/parity
completion; hosted native success must reach the reference step.

The CI workflow has a top-level concurrency group keyed by the workflow name,
event name, and either the pull request number, the pushed ref, or the unique
manual/scheduled run id. Newer pushes to the same pull request or to `main`
cancel their superseded run, while `workflow_dispatch` and `schedule` runs use
non-cancelling groups that cannot collide with push or pull-request traffic.
Release, provenance, and attestation workflows remain separate so a tag
publication or attestation is never cancelled by development CI churn.

The same tests are native `std.testing.fuzz` targets with seed corpora, so
coverage-guided runs can use `zig build fuzz --fuzz=<cases>` on Zig toolchains
where the built-in fuzzer is available. CI uses the deterministic runner
because Zig 0.16.0's built-in Linux test runner currently fails to compile in
fuzz instrumentation mode due to its internal stack-trace type mismatch; this
is an explicit toolchain limitation, not a green substitute sanitizer gate.

Targets cover DEB822, Debian versions and relations, sources, control/status,
Release/Packages, signed envelopes and OpenPGP packets, gzip/xz/zstd
decompression, ar/deb/tar payloads, the native archive application model, exact
locks, native transaction authorizations and programs, provenance JSON and
journals, the root mutation journal with its write-ahead progress log, and
the native ownership index built from `info/*.list` bytes, plus canonical
active alternatives records.
Harnesses call production bounded APIs directly and never shell out.

GitHub Actions lanes reproduce all three JavaScript bundles, audit their locked
dependencies, run native x64/arm64 package preparation and alternate-root
installation, exercise cold, compatible-prefix, exact-hit/fresh-root, offline,
and same-root semantics, and run the non-mutating action in a bare Ubuntu
container without installing Python, curl, `gh`, or APT tooling there.
Post-release smoke runs the complete setup/download/install composition on
both native architectures with explicit `sudo -n`. Hermetic signed-repository
integration tests cover corruption, explicit repair, offline metadata
requirements, moving repository failure, retained-closure GC, hostile
tar-shaped cache blobs, relocation, executable-replacement attempts,
maintainer-script failure, and explicit recovery.

For snapshot-focused validation without repeating the standard matrix:

```sh
gh workflow run ci.yml --ref main \
  -f run_full_matrix=false \
  -f run_native_real_snapshot=true \
  -f run_protected_reference=true
```

The snapshot, protected-reference, and ARM64 dpkg oracle lanes remain
independently selected by their existing inputs. Omitting `run_full_matrix`
or setting it to `true` retains full manual coverage, including
`integration-full`.

The manual `ubuntu-real-snapshot` CI job is an opt-in two-row amd64/arm64
gate selected by the `run_native_real_snapshot` dispatch input. It builds the
production candidate and Zig comparator, prepares the hash-pinned dpkg oracle
outside the candidate path, verifies the lock's cached archives, installs
them into a separate oracle root only if dpkg's dependency checks permit it,
and requires both captures to compare. Direct alphabetical lock order
currently fails the reference's `Pre-Depends` checks; this gate is not yet
passing real-package parity.
The previous full-reference harness mounted unrestricted procfs and is
retired; its healthy historical oracle root is not a private-PID parity
proof. The bounded replacement refuses shared/unprotected checkouts,
unknown or multi-package/pending script operations, and unsupported arm64
script profiles. Hosted checkout staging, mode-0700 root-owned workspace
and cleanup, small protected namespace tests, arm64 signed profiles and
more than the current 90-minute job budget require separate review before
re-enabling the full opt-in reference run. No retained failed root may be
reused as a fresh proof.
The opt-in `test-real-snapshot-reference-protected` Zig build target requires
explicit root-owned protected fixture paths and a fresh proof workspace; it
returns a failure, not a skip, without them;
`tools/real-snapshot-reference-protected-stage.sh` stages them. Its
pinned-dpkg operations, refusals, confined escape probe (including
detached-descendant teardown) and amd64 signed proc profiles are not a
substitute for runtime binding (#263) or the network decision (#278).
The `protected-reference` job runs that target on hosted amd64 and arm64
runners only on the weekly schedule or a `workflow_dispatch` with
`run_protected_reference: true`. Under `sudo -n` it clones the exact commit
from a root-owned bare repository into a new mode-0700 tree under
`/srv/debz-protected`. It verifies the pinned Zig with minisign, tightens and
records the `zig-pkg` modes, and runs seven fail-closed negatives before the
proof. Bounded evidence is always uploaded, and the tree is always removed.
`tools/security-audit.py` and `test/security-policy.zig` keep the job opt-in,
`sudo -n`-only and unskippable; see "Hosted protected reference job" in
[integration roots](integration-roots.md).
Missing or unequal captures fail the job. The gate proves the candidate root has no pre-existing
dpkg/helper/package state, selects `native` explicitly, and exec-traces
candidate commands to reject `dpkg`, `dpkg-deb`, `dpkg-divert` or
`dpkg-statoverride`, including failed commands. The only exception is a
maintainer script that `debz` started running the root's own tool as it would
under dpkg. The call must be a plain `execve` of the filename `/usr/bin/dpkg`,
`/usr/bin/dpkg-divert` or `/usr/bin/dpkg-statoverride`, with `argv[0]` the
tool's bare name or that filename. A dpkg call needs an action of
`--compare-versions`, `--validate-version`, `--print-architecture`, `-s`, `-L`
or `-l`; a `dpkg-divert` or `dpkg-statoverride` call must match one of the
exact argument shapes that the closure's scripts use on a fresh install, such
as DEP17 `--no-rename` diversions, `--truename`, `--list` and chrony's
`--update --add`. No call may pass a `--root`, `--admindir`, `--instdir` or
`--force*` option. The tool must also match its reviewed per-architecture
`1.23.7ubuntu1` digest, with no `PATH` shadow. Each allowed call is logged
with its script and PID lineage. These calls hand no transaction step to
dpkg: dpkg would run the same scripts the same way, the diversion and
statoverride tools only edit their own databases (and, for `--update`, the
named path's owner and mode), and `debz` still performs every unpack,
configuration and status update.
`execveat`, `dpkg-deb`, `--rename` and every other dpkg-tool exec still fail
with exit 90; see "Native exec audit" in
[integration roots](integration-roots.md).
Evidence members are capped at 128 MiB and the artifact at 512 MiB before
upload. Bounded, recognized acquisition retry diagnostics remain in the
evidence; unexpected candidate stderr still fails the gate. Repository
freshness remains authoritative and repository-specific: the acceptance
config pins the frozen `resolute` Release SHA-256
`596ee4cea058f74d59e2180532c89904e306d90725d42162eda82c01d4370834` and
requires both `resolute-updates` and `resolute-security` witnesses from the
same snapshot. The unchanged 31-day maximum applies only to those witnesses
when they omit `Valid-Until`; no CI clock exception, hostname inference, or
unbounded immutable exemption exists.

`zig build security-audit` is network-free and rejects:

- ambient APT/GnuPG/proxy/environment access and shell construction;
- unpinned GitHub Actions or dependencies outside the reviewed allowlist;
- unpinned external actions in composite action manifests;
- missing required CI architecture/mode coverage or aggregate failure propagation;
- missing dependency notices or GPL/LGPL/AGPL production dependencies;
- expired recorded vulnerability/license reviews or source pins that differ
  from the reviewed libsolv, liblzma, and libzstd inputs;
- stale local documentation paths;
- credential markers in tracked files, except the exact documented synthetic
  fixture-key generator;
- tracked build, coverage or generated binary artifacts.

The required audit step runs Zig-owned policy mutations and offline snapshot
workflow tests alongside the production Python audit utility. It does not
download or execute the live snapshot; see the
[test inventory](tooling-test-inventory.md) for the preserved negative cases.
It needs no passwordless sudo. The same CI job then runs
`zig build test-real-snapshot-reference-launcher-root`, which proves the
reference launcher's capability transition as real root through `sudo -n`
and fails with `CapabilityProbeRequiresRoot`, rather than skipping, without
that authority; the audit refuses a missing, conditional or
`continue-on-error` step and any audit dependency on it.
Digest cutover drift is reviewed in `security/digest-inventory-v1.tsv`, a
sorted TSV with one line per file that has findings, and in
`security/digest-semantic-allowlist-v1.tsv`, a sorted TSV with one line per
reviewed allowlist entry/path membership. After rebasing a change that adds,
edits, or removes SHA256-shaped findings, run `zig build write-digest-inventory`
and review the per-file and per-membership line diffs before running
`zig build security-audit`. The command updates counts and hashes only for
existing allowlist memberships; new member paths require an explicit JSON
policy edit.

Zig's Debug and ReleaseSafe modes provide bounds, overflow and safety checks.
The repository does not claim a C sanitizer gate: libsolv and libzstd are
built by separately pinned packages and liblzma by the repository-local Zig
build module, but toggling a root Zig flag is not presented as sanitizer
coverage for those C dependencies.

The network-free dependency gate validates exact pins, licenses, notices,
review evidence and expiry. It does not claim to discover advisories published
after the recorded review; that review must be refreshed before its expiry.

Concurrency, fault injection, symlink/path traversal, cleanup and atomic
publication cases live beside the cache, acquisition, refresh, payload,
executor and recovery implementations and run in the full test suite.

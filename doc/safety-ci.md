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
| `build-and-test-workload-release` | `test-workload-release` (apt schema and native-only rehearsal); `fuzz`; Debug `test-release`; pinned lifecycle/trigger reference oracles; standalone Zig workspace selectors |

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

Every CI and release build obtains Zig 0.16.0 from `cataggar/zig` through the
commit-pinned `ghr` v0.8.1 install action, verifies the release with its pinned
minisign key and GitHub attestations, and checks `zig version` before use. The
action cache contains only the exact installed tool and `ghr` transaction state;
it does not restore Zig's local or global build caches, preserving the previous
no-build-cache policy.

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

The manual `ubuntu-real-snapshot` CI job is an opt-in two-row amd64/arm64
gate selected by the `run_native_real_snapshot` dispatch input. It builds the
production candidate and Zig comparator, prepares the hash-pinned dpkg oracle
outside the candidate path, verifies the lock's cached archives, installs
them into a separate oracle root only if dpkg's dependency checks permit it,
and requires both captures to compare. Direct alphabetical lock order
currently fails the reference's `Pre-Depends` checks; this gate is not yet
passing real-package parity.
Missing or unequal captures fail the job. The gate proves the candidate root has no pre-existing
dpkg/helper/package state, selects `native` explicitly, and exec-traces
candidate commands to reject `dpkg` or `dpkg-deb`, including failed commands.
Evidence members are capped at 128 MiB and the artifact at 512 MiB before
upload. Bounded, recognized acquisition retry diagnostics remain in the
evidence; unexpected candidate stderr still fails the gate. Repository
freshness remains authoritative and repository-specific: the acceptance
config explicitly binds the unchanged 31-day maximum for a
missing `Valid-Until`. The gate pins the signed `stonking`
`https://snapshot.ubuntu.com/ubuntu/20261001T000000Z` snapshot, signed by
`F6ECB3762474EDA9D21B7022871920D1991BC93C` with Date Wed, 30 Sep 2026
20:37:08 UTC and Valid-Until Wed, 14 Oct 2026 20:37:08 UTC, instead of
overriding the clock for frozen
`resolute`; no CI clock exception, hostname inference, or unbounded immutable
exemption exists.

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
Digest cutover drift is reviewed in `security/digest-inventory-v1.tsv`, a
sorted TSV with one line per file that has findings. After rebasing a change
that adds, edits, or removes SHA256-shaped findings, run
`zig build write-digest-inventory` and review the per-file line diff before
running `zig build security-audit`.

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

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

Required build workloads use separate architecture and optimization-mode jobs,
each retaining the 60-minute limit. Every combination runs the complete build,
test, fuzz, native differential, and private helper namespace targets with
`-j2` and timing summaries. Debug jobs also run release packaging and privileged
orchestration; ReleaseSafe jobs run installed-CLI facade acceptance and the
download action fixture. Native crash recovery remains a separate required
workload in both modes on both architectures. The existing `Build and test`
checks require all four build jobs and both recovery jobs to succeed; failure,
cancellation, or a skipped workload cannot make the aggregate pass.

Every CI and release build obtains Zig 0.16.0 from `cataggar/zig` through the
commit-pinned `ghr` v0.8.1 install action, verifies the release with its pinned
minisign key and GitHub attestations, and checks `zig version` before use. The
action cache contains only the exact installed tool and `ghr` transaction state;
it does not restore Zig's local or global build caches, preserving the previous
no-build-cache policy.

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
missing `Valid-Until`. The gate pins a currently valid signed `stonking`
snapshot instead of overriding the clock for frozen `resolute`; no CI clock
exception, hostname inference, or unbounded immutable exemption exists.

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

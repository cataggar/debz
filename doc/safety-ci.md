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

The same tests are native `std.testing.fuzz` targets with seed corpora, so
coverage-guided runs can use `zig build fuzz --fuzz=<cases>` on Zig toolchains
where the built-in fuzzer is available. CI uses the deterministic runner
because Zig 0.16.0's built-in Linux test runner currently fails to compile in
fuzz instrumentation mode due to its internal stack-trace type mismatch; this
is an explicit toolchain limitation, not a green substitute sanitizer gate.

Targets cover DEB822, Debian versions and relations, sources, control/status,
Release/Packages, signed envelopes and OpenPGP packets, gzip/xz/zstd
decompression, ar/deb/tar payloads, exact locks, provenance JSON and journals.
Harnesses call production bounded APIs directly and never shell out.

`zig build security-audit` is network-free and rejects:

- ambient APT/GnuPG/proxy/environment access and shell construction;
- unpinned GitHub Actions or dependencies outside the reviewed allowlist;
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

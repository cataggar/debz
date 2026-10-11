# Release packaging

Copyright 2026 debz contributors. SPDX-License-Identifier: Apache-2.0.

`tools/release.py` is an independently authored, network-free release packager
and validator. Its tag parsing, four-asset plan, complete static ELF validation
and canonical GNU tar encoder run in the installed Zig `debz-release` helper,
with `PATH=/no-host-interpreters` and no Python fallback. Compression and strict
container decoding also run in this helper: gzip uses Zig's best-level deflate
encoder with the original zero timestamp and stable header; XZ uses a separate
encoder build from the already pinned upstream sources. The product retains its
decoder-only library. Decoder CRC, completeness, trailing-data, input, output
and memory limits are enforced before returning a tar payload.

`DEBZ_RELEASE` selects the helper in a custom build prefix. Tar member reading
also runs natively, preserving GNU long names and signed epochs while checking
checksums, bounds, names, order, ownership, modes and timestamp equality. Audit
and smoke use the returned original member bytes; they no longer open or decode
the archive with Python. Python still adapts member metadata, validates runtime
and policy inputs, and orchestrates packaging, publication and smoke execution.
This bounded port does not complete Python retirement.

Release inputs are rejected when
they contain links, generated artifacts, cache paths, common secret formats,
missing notices, unsafe names, or ELF binaries that are not fully static for
the declared architecture.

The install prefix must contain:

* `bin/debz`
* `share/doc/debz/LICENSE`
* `share/doc/debz/THIRD_PARTY_NOTICES`
* identical `share/debz/` and `share/doc/debz/` copies of
  `digest-cutover-policy.json`, `digest-inventory-v1.tsv`,
  `digest-semantic-allowlist-v1.tsv`, and `legacy-cutover-policy.json`
* `share/debz/runtime-dependencies.json`

Typical CI usage:

```sh
zig build build-release-tool
python3 tools/release.py version v0.3.0 --expect zon=0.3.0 --expect binary=0.3.0
python3 tools/release.py dry-run --tag v0.3.0
python3 tools/release.py binary --tag v0.3.0 --platform linux-x64 \
  --prefix zig-out --epoch "$SOURCE_DATE_EPOCH" --output dist
python3 tools/release.py audit --tag v0.3.0 \
  --platform linux-x64 --archive dist/debz-0.3.0-linux-x64.tar.xz --smoke
python3 tools/release.py verify --tag v0.3.0 --assets dist \
  --policy security/dependency-policy.json --smoke
```

CI builds this host-native helper before every actual release consumer. Each
release job first verifies main ancestry, then installs the exactly pinned,
version-checked Zig compiler before compiling the helper. The publication and
dry-run verifier jobs have their own compiler installation and helper build;
they do not assume an artifact or a helper left over from another job.

Run the Zig-owned tooling tests with `zig build test-release` (or
`zig build test-release -Doptimize=ReleaseSafe`). The
[test inventory](tooling-test-inventory.md) maps the former Python cases to
their Zig assertions. Packaging the same inputs twice in one controlled
build environment produces byte-identical gzip and xz assets. Portable audit
does not assume that different deflate, liblzma, or Python implementations emit identical
compressed bytes: it validates container integrity and canonical stable headers,
then compares the decompressed tar payload with the canonical tar encoding.
The native gzip producer can differ byte-for-byte from the former zlib encoder;
existing immutable archives are neither recompressed nor reinterpreted.
Names, ordering, timestamps, ownership and modes remain strictly enforced. Each
release contains exactly four binary archives: gzip and xz for Linux x64 and
Linux arm64. Verification rejects every extra regular file, including checksum
or SPDX sidecars, release manifests, and custom source archives. Binary audit
re-reads `bin/debz` and the installed runtime manifest from each archive, then
checks ELF architecture and parses ELF program headers to reject `PT_INTERP`,
every `DT_NEEDED` entry, and malformed layouts even when section headers are
absent. `PT_DYNAMIC` file and virtual ranges must resolve uniquely and
consistently through the same file-backed `PT_LOAD`, preventing a decoy file
offset from hiding the dynamic table actually visible to the loader.

The first-party [`actions/setup`](../actions/setup/README.md) action selects
the exact gzip archive for its normalized runner target. Gzip is the action
format because Node provides in-process decompression; the action does not
depend on a target container's tar or xz tools. The release workflow verifies
the checked-in action against the newly published tag on both native release
architectures after attestations and publication complete.

The same post-publication matrix then creates a hermetic signed repository and
exact lock and runs [`actions/download`](../actions/download/README.md) with
caching disabled. This proves the just-published CLI implements the
`package-cache-v3` legacy contract and prepares the complete closure on both native
architectures without treating setup or package cache state as installation.

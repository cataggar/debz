# Release packaging

Copyright 2026 debz contributors. SPDX-License-Identifier: Apache-2.0.

The installed Zig `debz-release` is the complete, network-free release packager
and validator. Tag parsing, four-asset planning, installed dependency/license
and policy checks, bounded prefix scanning, atomic publication, complete static
ELF validation, canonical GNU tar encoding, archive audit and native smoke all
run in this executable, without a host interpreter or Python fallback.
Compression and strict container decoding are native: gzip uses Zig's best-level deflate
encoder with the original zero timestamp and stable header; XZ uses a separate
encoder build from the already pinned upstream sources. The product retains its
decoder-only library. Decoder CRC, completeness, trailing-data, input, output
and memory limits are enforced before returning a tar payload.

Build/test consumers bind the executable in the selected install prefix,
including `--prefix` builds. Tar member reading preserves GNU long names and signed epochs while checking
checksums, bounds, names, order, ownership, modes and timestamp equality. Audit
and smoke use the original member bytes. The prefix scanner pins no-follow
directories and stable regular files, limits the complete tree to 4,096 entries,
128 directory levels and 256 MiB of file data, and rechecks pins before atomic
publication. Output ancestry and preexisting aliases are checked without
following links; staged files are private, uniquely named and durably renamed.
Smoke creates a private owned extraction beside the archive, preserves original
file/directory modes and nanosecond epochs, runs only matching-host binaries
with `PATH=/no-host-interpreters` and a 60-second timeout, and cleans up on failure.
Foreign binaries are audited, never executed.

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
zig-out/bin/debz-release version v0.3.0 --zon build.zig.zon --expect binary=0.3.0
zig-out/bin/debz-release dry-run --tag v0.3.0
zig-out/bin/debz-release binary --tag v0.3.0 --platform linux-x64 \
  --prefix zig-out --epoch "$SOURCE_DATE_EPOCH" --output dist
zig-out/bin/debz-release audit --tag v0.3.0 \
  --platform linux-x64 --archive dist/debz-0.3.0-linux-x64.tar.xz --smoke
zig-out/bin/debz-release verify --tag v0.3.0 --assets dist \
  --policy security/dependency-policy.json --smoke
```

CI builds this host-native helper before every actual release consumer. Each
release job first verifies main ancestry, then installs the exactly pinned,
version-checked Zig compiler before compiling the helper. The publication and
dry-run verifier jobs have their own compiler installation and helper build;
they do not assume an artifact or a helper left over from another job.

Run the bounded native core and actual packaging consumer tests with
`zig build test-release-consumers -j2` in Debug and ReleaseSafe. This selector
does not rebuild every normal GNU-installed tool. Full installation-layout
qualification remains `zig build test-release` (or
`zig build test-release -Doptimize=ReleaseSafe`). The
[test inventory](tooling-test-inventory.md) maps the former Python cases to
their Zig assertions. Packaging the same inputs twice in one controlled
build environment produces byte-identical gzip and xz assets. Portable audit
does not assume that different deflate or liblzma implementations emit identical
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

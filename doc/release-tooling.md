# Release packaging

Copyright 2026 debz contributors. SPDX-License-Identifier: Apache-2.0.

`tools/release.py` is an independently authored, network-free release packager
and validator using Python's standard library. Release inputs are rejected when
they contain links, generated artifacts, cache paths, common secret formats,
missing notices, unsafe names, or ELF binaries that are not fully static for
the declared architecture.

The install prefix must contain:

* `bin/debz`
* `share/doc/debz/LICENSE`
* `share/doc/debz/THIRD_PARTY_NOTICES`
* `share/debz/runtime-dependencies.json`

Typical CI usage:

```sh
python3 tools/release.py version v0.3.0 --expect zon=0.3.0 --expect binary=0.3.0
python3 tools/release.py dry-run --tag v0.3.0
python3 tools/release.py binary --tag v0.3.0 --platform linux-x64 \
  --prefix zig-out --epoch "$SOURCE_DATE_EPOCH" --output dist
python3 tools/release.py audit --tag v0.3.0 \
  --platform linux-x64 --archive dist/debz-0.3.0-linux-x64.tar.xz --smoke
python3 tools/release.py verify --tag v0.3.0 --assets dist \
  --policy security/dependency-policy.json --smoke
```

Run the tooling tests with `python3 -m unittest tools/test_release.py` or
`zig build test-release`. Packaging the same inputs twice in one controlled
build environment produces byte-identical gzip and xz assets. Portable audit
does not assume that different zlib, liblzma, or Python versions emit identical
compressed bytes: it validates container integrity and canonical stable headers,
then compares the decompressed tar payload with the canonical tar encoding.
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

# Debian 13 stable signed-input readiness (issue #261)

**Eligible signed input, not an acceptance closure.** The pinned Debian
`trixie` snapshot has an authenticatable, still-fresh Release and parseable
`main` indexes. It publishes **SHA256 only** for the selected indexes and
**every** package archive. The #261 owner decision accepts those signed SHA256
Release/Packages entries (plus size) as the authenticated archive binding. An
exact v3 lock marks such a repository
`"archive_binding":"signed_sha256_derived_sha512"`. It records each archive's
locally computed SHA512 only in `derived_archive_identity`, with provenance
`derived_from_signed_sha256`, and only after the bytes matched the signed
SHA256 ([exact locks](exact-locks-and-provenance.md)). A derived SHA512 is
never presented as signed, and the Ubuntu `stonking` closure is not a
substitute for Debian. No Debian package was resolved, downloaded into CAS,
installed, or claimed supported in this session.

## Reviewed source, trust, and freshness

The immutable URI is
`https://snapshot.debian.org/archive/debian/20260928T000000Z`, suite
`trixie`, component `main`. The signed Release identifies `Origin: Debian`,
`Suite: stable`, `Codename: trixie`, version `13.7`, and Date
`Sat, 12 Sep 2026 07:55:41 UTC`. Its `InRelease` SHA256 is
`0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675`.
It has **no** `Valid-Until`. The source explicitly chooses
`allow_missing_valid_until_with_max_age_seconds` with the existing maximum
`2678400` (31 days); without a newly signed Release, the pin expires after
**2026-10-13 07:55:41 UTC**. Do not override the clock or increase this bound.
The signed Release publishes SHA256 index identities, but no SHA512 section.

The only `Signed-By` key is Debian's **13/trixie stable release** signing
key, published at `https://ftp-master.debian.org/keys/release-13.asc`;
the separately published [Debian signing-key inventory](https://ftp-master.debian.org/keys.html)
lists its primary fingerprint
`41587F7DB8C774BCCF131416762F67A0B2C39DE4`.
The pinned armored SHA256 is
`4d097bb93f83d731f475c5b92a0c2fcf108cfce1d4932792fca72d00b48d198b`;
its decoded binary SHA256 is
`abced156a22aa8683b228299ac35c1ea51515eef900cec0e562f56716dfe3915`.
The binary is byte-equal to
`usr/share/keyrings/debian-archive-trixie-stable.pgp` from Debian's
`debian-archive-keyring_2025.1_all.deb` (download SHA256
`9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac`).
The preflight checks the source-key bytes **and** the independently reviewed
primary fingerprint before passing that one explicit key to debz; it never
trusts host APT/GnuPG state. Debian's InRelease contains three signature
packets in one armor block; verification accepts the reviewed stable signer,
not an unrelated valid signature from another key.

`tools/fixtures/debian-stable-readiness-v1.json` pins both actual index
identities from this signed Release:

| Native architecture | `main/binary-*/Packages.xz` SHA256 | Exact compressed bytes | Authenticated package stanzas | Published archive SHA512 |
| --- | --- | ---: | ---: | ---: |
| amd64 | `7778d3e3f303b7ddb8ce0fe7c8d57473a076c6bf2e8f241f75421d2396352498` | 9,678,380 | 68,825 | 0 |
| arm64 | `be16b37b2f740f066ea93d35d56f04f94d63693e5a3eb421b052bf86fae75bcd` | 9,614,192 | 68,196 | 0 |

These checksum and package-field counts describe *published vendor metadata*,
not downloaded `.deb` archives or CAS objects. Both indexes were independently
fetched and byte-matched to their signed SHA256/size entries; **only arm64**
also underwent matching-architecture debz authenticated refresh in this
session. The amd64 checksum inspection performed on arm64 is **not** an
amd64 native signed-refresh run.

## Reproduce the read-only preflight

From a fresh checkout with Zig 0.16.0 and Python 3:

```sh
zig build -Doptimize=ReleaseSafe -j2
python3 tools/debian-stable-readiness.py \
  --debz "$PWD/zig-out/bin/debz" \
  --architecture arm64 \
  --workspace "$PWD/.tmp/debian-261-readiness-arm64-1"
```

Use `--architecture amd64` only on an x86_64 runner and give each attempt a
new direct child of this checkout's `.tmp`. For this snapshot the preflight
exits **0** with status `eligible_signed_sha256_derived_sha512` and
`archive_binding: "signed_sha256_derived_sha512"`. A repository whose signed
index and every record publish SHA512 reports `eligible_signed_sha512`
(`published_digests`). A repository that publishes SHA512 only partially exits
**3** with `refused_partial_published_sha512`, because one repository cannot
mix signed-SHA512 and SHA256-bound archives. Exit **2** covers:

- authentication failures;
- index checksum failures, including a substituted record SHA256, which
  changes the signed index identity;
- a missing or malformed record SHA256;
- bounded missing-expiry freshness failures.

A mismatched native architecture is rejected before network access and
workspace creation. The helper never invokes `plan`, `download`, or any
mutating debz transaction, and never publishes a lock.

The exact generated deb822 source bytes are:

```text
Types: deb
URIs: https://snapshot.debian.org/archive/debian/20260928T000000Z
Suites: trixie
Components: main
Architectures: <native amd64 or arm64>
Signed-By: <checkout>/.tmp/debian-261-trixie-release-13.gpg
```

The newline-terminated JSON configuration has exactly `source_path`
(absolute workspace `debian.sources`), `priority: 500`,
`default_release: "trixie"`, `immutable: true`, and
`freshness: {"mode":"allow_missing_valid_until_with_max_age_seconds",
"maximum_release_age_seconds":2678400}` (serialized without spaces).
`evidence/refresh.json`, `evidence/refresh.stderr`, and
`evidence/readiness.json` retain actual verification status, architecture,
source/config/program/key bytes hashes, Release/index identities, the bounded
record and digest counts, and explicit `root_mutated: false` /
`exact_lock_published: false`. The helper checks that the empty root remains
empty before issuing either assertion. The shared pinned `Signed-By` path
keeps repository identity constant for independent runs in one checkout;
the per-workspace config digest naturally differs because `source_path`
contains the workspace. Cross-machine byte-identical lock comparisons will
require the same reviewed absolute `Signed-By` path (it is part of
repository identity) once bound Debian locks are produced. The read-only
preflight config deliberately omits `archive_binding`, so its recorded
repository identity stays valid. A lock-producing run adds
`"archive_binding":"signed_sha256_derived_sha512"` to the same config,
which is an additional repository identity input.

Before the #261 decision, two fresh, independent **native arm64** ReleaseSafe
preflights returned `refresh.exit_status=0`. They retained the same Release
and `be16b37b...` index hashes and all 68,196 SHA256-only package records,
then exited 3 without altering either root. An authenticated cache-only
refresh reverified the retained multi-signature snapshot. That bounded
[pre-decision arm64 evidence](../tools/fixtures/debian-stable-readiness-arm64-evidence-v1.json)
remains a historical refusal ledger.

After the decision, two more fresh, independent native arm64 ReleaseSafe
preflights of the signed-SHA256 binding change produced the same repository
identity `7fe912e2...`. They reverified the same Release, the index, and the
signed SHA256 of all 68,196 records, and found no published SHA512. Both
exited 0 with `eligible_signed_sha256_derived_sha512` and left the root
empty. The
[post-decision arm64 evidence](../tools/fixtures/debian-stable-readiness-arm64-evidence-v2.json)
retains:

- executable, source, and config byte hashes;
- the repository identity and the binding status;
- the explicit absence of any lock, CAS, and root mutation.

No amd64 native runner was available here, so amd64 has **not**
independently refreshed. Both ledgers are input evidence, not signed-root
acceptance or externally attested workflow artifacts.

## Prioritized closure blockers and next steps

1. **Resolved, input provenance:** the #261 decision accepts this snapshot's
   signed SHA256 archive entries. Exact-lock v3 records that authority
   explicitly with the `signed_sha256_derived_sha512` binding. Library
   binding (`bindSignedSha256Repositories`) and every consumer (acquisition,
   cache hit, tagged CAS import, native unpack) verify the signed SHA256
   before the derived SHA512 and refuse any mismatch. Do not synthesize
   signed SHA512 values, backdate verification, or switch to Ubuntu.
2. **Resolved, product lock publication:** the opt-in is the per-repository
   `--config` setting `"archive_binding":"signed_sha256_derived_sha512"`
   (no CLI flag). For an opted-in repository, native `plan`/`download
   --lock-output` and package-family `resolve_lock` do three things before
   publishing anything: acquire every locked archive, verify its size and
   signed SHA256, and bind the derived SHA512 through the library above.
   Only the admitted bound lock is written, and a mismatch writes none.
   Native engine / exact-lock v3 consumers enforce
   `sha512_identity_required` by default. An unbound SHA256-only lock is
   refused and is not an acceptance artifact. Legacy consumers are
   unchanged. Hermetic Zig and integration lanes prove this with a
   Debian-shaped signed-SHA256 repository. The real snapshot still needs
   step 3.
3. **P1, native evidence:** run independently on native amd64 and arm64
   with one normalized keyring path and fresh roots/caches. Repeat
   signed refresh, resolve a representative closure, and bind complete
   v3 identities with the explicit derived-SHA512 provenance. Then acquire
   every exact-size, signed-SHA256 archive into CAS and compare
   byte-identical locks and CAS inventory. This session has **no** accepted
   package set, lock, CAS inventory, or signed archive payload. Its vendor
   integration closure is therefore empty by policy, not a claimed
   supported empty Debian install.
4. **P1, native feature gap inventory:** only after (2)–(3), inspect the
   actual selected `.deb` control/data members **before any mutation**:
   - exact package and script versions;
   - invoked script arguments and tools;
   - conffiles;
   - trigger interests/activations;
   - diversions, accounts, and system features;
   - explicitly unsupported native cases.

   The current metadata-only reconnaissance does not mark any speculative
   script gap fixed or supported.
5. **P2, parity:** native/reference fresh-root execution and full equality
   are later issues; no result here may satisfy that gate.

The actual `librust-winapi-dev` arm64 package record contains a 75,639-byte
`Provides` with over 1,600 groups. The repository parser's bounded
Packages-specific relation limits now admit this real signed metadata
without changing the smaller general-purpose relation parser limits;
synthetic Zig regressions preserve an explicit lower caller-supplied cap.
That indexing fix and multi-signature InRelease revalidation are
**prerequisites**, not evidence that a Debian closure has been selected.

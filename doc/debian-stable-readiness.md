# Debian 13 stable signed-input readiness (issue #261)

**Authenticated Debian input locks and a native gap list, not an install.**
The pinned Debian `trixie` snapshot has an authenticatable, still-fresh
Release and parseable `main` indexes. It publishes **SHA256 only** for the
selected indexes and **every** package archive. The #261 owner decision
accepts those signed SHA256 Release/Packages entries (plus size) as the
authenticated archive binding. An exact v3 lock marks such a repository
`"archive_binding":"signed_sha256_derived_sha512"`. It records each archive's
locally computed SHA512 only in `derived_archive_identity`, with provenance
`derived_from_signed_sha256`, and only after the bytes matched the signed
SHA256 ([exact locks](exact-locks-and-provenance.md)). A derived SHA512 is
never presented as signed, and the Ubuntu `stonking` closure is not a
substitute for Debian.

The [recorded closure evidence](#reproducible-bound-closure-locks) holds
byte-identical bound locks for Debian's minbase (`apt`) and default init
(`systemd-sysv`) closures on **amd64 and arm64**. Each came from two
independent clean runs. The evidence also records every archive's size,
signed SHA256, derived SHA512 and CAS object. A
[pre-mutation inventory](#pre-mutation-feature-inventory-and-prioritized-native-gaps)
of the 78-package closure per architecture yields the prioritized native gap
list. No Debian package was installed, executed or claimed supported.

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

This read-only preflight runs a matching-architecture refresh, so use
`--architecture amd64` only on an x86_64 runner. The
[closure tool](#reproducible-bound-closure-locks) below needs no native
execution and resolves both architectures on either host. Give each attempt a
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
contains the workspace. Repository identity includes the absolute
`Signed-By` path, so the closure tool uses Debian's canonical keyring path
to keep locks byte-identical across machines. The read-only
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

## Issue #261 steps

1. **Resolved, input provenance:** the #261 decision accepts this snapshot's
   signed SHA256 archive entries. Exact-lock v3 records that authority
   explicitly with the `signed_sha256_derived_sha512` binding. Library
   binding (`bindSignedSha256Repositories`) and every consumer (acquisition,
   cache hit, tagged CAS import, native unpack) verify the signed SHA256
   before the derived SHA512 and refuse any mismatch. Do not synthesize
   signed SHA512 values, backdate verification, or switch to Ubuntu.
2. **Resolved, product lock publication:** the opt-in is the per-repository
   `--config` setting `"archive_binding":"signed_sha256_derived_sha512"`, or
   the equivalent source declaration (`X-Debz-Archive-Binding:` /
   `debz-archive-binding=`) that target-APT import and repository-add
   descriptors carry (no CLI flag). For an opted-in repository, native
   `plan`/`download --lock-output`, package-family `resolve_lock`, and native
   repository-add operation locks do three things before publishing
   anything: acquire every locked archive, verify its size and
   signed SHA256, and bind the derived SHA512 through the library above.
   Only the admitted bound lock is written, and a mismatch writes none.
   Native engine / exact-lock v3 consumers enforce
   `sha512_identity_required` by default, including transaction-result
   verification and orchestrator lock re-reads before recovery. An unbound
   SHA256-only lock is refused and is not an acceptance artifact. A
   repository archive relabelled as a local artifact is refused by origin
   binding. Legacy consumers are
   unchanged. Hermetic Zig and integration lanes prove this with a
   Debian-shaped signed-SHA256 repository.
3. **Resolved, reproducible authenticated locks:** amd64 and arm64 bound
   locks and CAS evidence for the real snapshot, byte-identical across two
   clean runs each; see
   [reproducible bound closure locks](#reproducible-bound-closure-locks).
4. **Resolved, pre-mutation feature inventory:** see the
   [inventory and prioritized native gaps](#pre-mutation-feature-inventory-and-prioritized-native-gaps).
5. **Remaining, native execution and parity:** see
   [what remains](#what-remains-for-native-execution).

The actual `librust-winapi-dev` arm64 package record contains a 75,639-byte
`Provides` with over 1,600 groups. The repository parser's bounded
Packages-specific relation limits now admit this real signed metadata
without changing the smaller general-purpose relation parser limits;
synthetic Zig regressions preserve an explicit lower caller-supplied cap.
That indexing fix and multi-signature InRelease revalidation are
**prerequisites**, not evidence that a Debian closure has been selected.

## Reproducible bound closure locks

`tools/debian-stable-closure.py` resolves, locks, downloads and inventories
one architecture per run. It never installs or executes package content, so
both architectures run on either host. This evidence was recorded on aarch64
with `--architecture amd64` and `--architecture arm64`.

**Keyring.** Repository identity hashes the `Signed-By` path, so the tool
requires Debian's own path,
`/usr/share/keyrings/debian-archive-trixie-stable.pgp`. Every path component
must be root-owned, must not be group- or other-writable, and must not be a
symlink. The file must be byte-equal to the reviewed key (binary SHA256
`abced156…`), which the tool fetches afresh and checks against the
fingerprint. Debian hosts get the file from `debian-archive-keyring`.
Elsewhere, install the reviewed bytes, for example:
`sudo install -D -m 0644 -o root -g root <reviewed-key> /usr/share/keyrings/debian-archive-trixie-stable.pgp`.

**Commands.**

```sh
zig build -Doptimize=ReleaseSafe -j4
zig build test-debian-closure-inventory -Doptimize=ReleaseSafe -j4
for arch in amd64 arm64; do
  for n in 1 2; do
    python3 tools/debian-stable-closure.py run \
      --debz "$PWD/zig-out/bin/debz" \
      --inventory "$PWD/zig-out/bin/debian-closure-inventory" \
      --architecture "$arch" \
      --workspace "$PWD/.tmp/debian-261-closure-$arch-$n"
  done
  python3 tools/debian-stable-closure.py compare \
    ".tmp/debian-261-closure-$arch-1" ".tmp/debian-261-closure-$arch-2"
done
python3 tools/debian-stable-closure.py record \
  --amd64 .tmp/debian-261-closure-amd64-1 .tmp/debian-261-closure-amd64-2 \
  --arm64 .tmp/debian-261-closure-arm64-1 .tmp/debian-261-closure-arm64-2 \
  --program-version 0.3.0 --source-commit <commit> --recorded-on <date>
python3 tools/debian-stable-closure.py check
```

Each `run` creates a new workspace with empty `root`, `cache` and `state`
directories. It writes these exact `debian.sources` bytes (SHA256
`0ff1ed7a…` for amd64, `95f54700…` for arm64, both bound in the evidence):

```text
Types: deb
URIs: https://snapshot.debian.org/archive/debian/20260928T000000Z
Suites: trixie
Components: main
Architectures: <amd64 or arm64>
Signed-By: /usr/share/keyrings/debian-archive-trixie-stable.pgp
```

It also writes a newline-terminated `debian.json` config. The config holds
the preflight fields above plus
`"archive_binding":"signed_sha256_derived_sha512"`, serialized without
spaces; that field is the opt-in, and no CLI flag is involved. Its
`source_path` names the workspace, so the config digest differs per run,
but repository identity and locks do not. The tool then runs debz with
`--config`, `--keyring`, `--architecture` and `--json`:

1. `refresh`;
2. for each request, a native `plan --lock-output`;
3. a second native `plan --lock-input … --lock-output …`, which must
   reproduce identical lock bytes;
4. a native `download --lock-input`.

Only debz retry lines may appear on stderr. The tool then does the following:

- checks that the root is still empty;
- independently refetches the pinned InRelease and `Packages.xz`, and matches
  every locked package to its signed Debian record (Filename under `pool/`,
  Size and SHA256);
- reviews each lock fail-closed. It requires:
  - v3, exactly one repository, signed only by the Debian key;
  - the binding and the pinned index identity;
  - no local artifacts;
  - a SHA256-only primary identity plus SHA512 provenance
    `derived_from_signed_sha256`;
  - exactly one requested package;
  - at most 128 packages and 64 MiB per lock;
- rehashes every cached archive (size, SHA256 and derived SHA512); the
  cache's object directory must hold exactly the union of both locks;
- runs the native inventory.

`compare` requires identical run summaries, and identical bytes for both
locks, the CAS evidence and the inventory. `record` writes the
[committed evidence](../tools/fixtures/debian-stable-closure-v1/evidence.json),
the four locks and both inventories. `check` and the security-audit unit
tests revalidate them offline.

**Recorded results.** Recorded on 2026-09-30 with a ReleaseSafe debz 0.3.0
build of `7fc3960` (SHA256
`6aca15f0ef7747954ee186ca7a38bf77af83f22490583b5278ddb48d9d3bb540`), using two
clean runs per architecture. `policy_sha256`
`2f5d0d954dfe682bcc36acd6d636f4bc3d52a819156b6623b6a1d2339ed38d57` and the
`request_sha256` values are the same for both architectures:

- `apt`: `b999effaa1e7a9423a9c192c063823f8470ae67d4ecd6dfb604f6aa8f3ffce6b`
- `systemd-sysv`: `5f49cb0a386e27c7f4e9c77de5916e43f832f2848e428382f0947548a14aed97`

| Architecture | Request | Packages | Archive bytes | Lock file SHA256 | Lock `digest_sha256` |
| --- | --- | ---: | ---: | --- | --- |
| amd64 | `apt` | 73 | 31,793,892 | `72e36e01e0148691382c0f8877f982bb3d075a4bf112020c0685ea4a794339b5` | `1de068531d57382c89ef40e6b33be062e9dd73ff41cb118def8fa153755797f9` |
| amd64 | `systemd-sysv` | 69 | 32,462,832 | `115ad16d61ad4545da210e2675680de75cb01a058606f33dc1f94836939394f7` | `c45486fc240ffcf6dba1ff54a1073269795bb1e2ddf6f813973a256c11bd193c` |
| arm64 | `apt` | 73 | 30,499,520 | `f32bd3faded815e44cb25f6f4f66170279c234f2c341978bc911d4231cb38f7e` | `fb2321a81cc14faf15f34cb23528ad0b3e98f7e3d89e6e93d66b0739c633894c` |
| arm64 | `systemd-sysv` | 69 | 31,119,116 | `b1df06f6b80967f18f8f8575674f3d8ead22a65d5ae47834edbb321290b2321c` | `5392c08048e2290d95c0f1bdd2c41fc56c1add0eacc5ac2ab8decd3bd8b73b16` |

| Architecture | Repository identity | CAS objects | CAS bytes | CAS evidence SHA256 | Inventory SHA256 |
| --- | --- | ---: | ---: | --- | --- |
| amd64 | `c8cec41705612dba684f249dc277c1f39d9a2137134155dedd528837a4e497c2` | 78 | 37,313,912 | `279028c4f10a0b5024df65b0cc135b2d4fa5eded8f678196ca9bef42d11600a0` | `0e6a5d82ca5f939efde1ec4d8ddb49e3ff255e79143c623221cc0788b6c7e2cf` |
| arm64 | `663e2a215ff393b6840f6e66c12fb62f80e2b0aa057143ba0bed0ca6a0714f9b` | 78 | 35,611,916 | `73dc70968393094f29eaa9ca0cca597cd21bd529b6feaefdaedc3f6b9f539cf3` | `2f83186a7afd23799ae7f4b71fda49dd34dace74e15fee34226c6573752be38f` |

**Freshness handling.** The pinned Release has no `Valid-Until`. Its
reviewed bounded policy expires at **2026-10-13T07:55:41Z**:

- After that time, `run` refuses before any network access or workspace
  creation, and debz `refresh` refuses on its own.
- The committed evidence remains an offline-verifiable, dated record; it
  keeps both `recorded_on` and `expires_at`. `check` never consults the
  clock.
- To reproduce after expiry, review a newer snapshot pin (Release, signer
  and both indexes) in `tools/fixtures/debian-stable-readiness-v1.json`,
  then rerun and re-record.
- Never override the clock or lengthen the bound.

**Fail-closed tests.**

- `tools/test_debian_stable_closure.py` refuses:
  - tampered committed evidence;
  - Ubuntu signers;
  - stripped or relabelled bindings;
  - forged derived provenance;
  - a SHA512 primary identity;
  - local artifacts;
  - foreign architectures;
  - out-of-bound locks;
  - Ubuntu or mismatched archives that are absent from, or differ from, the
    signed Debian index;
  - unsafe keyrings;
  - expired pins, before any network access.
- `tools/test_debian_stable_readiness.py` refuses an expired Release and a
  substituted Ubuntu Release (`Origin`, `Suite` or `Codename`), even when
  its digest has been repinned.
- `zig build test-debian-closure-inventory`:
  - decodes the committed locks canonically as signed-SHA256 bound under
    `sha512_identity_required`;
  - refuses them after Ubuntu signer substitution, binding stripping,
    relabelling the derived SHA512 as signed, or an architecture relabel;
  - refuses tampered, truncated and forged-SHA512 archives before inventory.
- The debz `repository_refresh` tests independently refuse expired and
  future-dated Releases.

## Pre-mutation feature inventory and prioritized native gaps

`debian-closure-inventory` (`test/debian-closure-inventory.zig`) reads only
the bound cached archives, after rechecking size, signed SHA256 and derived
SHA512. For each archive it runs the native pre-mutation archive model
(`archive_application.prepare`, the same admission that a native install
uses). It records:

- control facts, conffiles, triggers and metadata members;
- maintainer scripts: hash, interpreter, invoked tools and arguments from a
  static token scan, and the `update-alternatives` authority gate;
- payload kinds, setuid/setgid files and non-root owners;
- system paths: systemd units, sysusers, tmpfiles, init scripts, udev, PAM
  and cron.

Nothing is unpacked into a root and no script runs.
`tools/capture-vendor-state.py` inventories an *installed* Ubuntu root, so
it cannot run before mutation. The gap categories reuse its vocabulary.

Findings are identical for both architectures unless noted:

- **Admission:** 78 packages (22 Essential). The native model admits all
  78. There are no FIFOs, character or block devices, PAX or unknown
  members, and no unsupported control members.
- **Payload:** amd64 has 4,033 regular files, 2,343 directories, 351 symlinks
  and 1 hard link; arm64 has 4,033, 2,341, 346 and 1.
- **Scripts:** 24 `postinst`, 17 `postrm`, 10 `preinst`, 12 `prerm` and 1
  `config`.
- **Conffiles:** 64, none remove-on-upgrade.
- **Triggers:** 41 `activate-noawait` and 1 `interest-await` (libc-bin
  `ldconfig`). There are 8 `interest-noawait` on amd64 and 9 on arm64, where
  `base-files` also watches `/usr/lib64`.
- **Diversions:** `dpkg-divert` in base-files, dash, gzip,
  init-system-helpers, libc6, libreadline8t64 and systemd-sysv.
- **Statoverrides:** no `dpkg-statoverride` calls. The only non-root owner
  is `unix_chkpwd` (`0:42`, setgid); `mount`, `umount` and `su` are setuid.
- **Accounts:** `update-passwd` (base-passwd); `adduser` and `getent`
  (apt); `systemd-sysusers` with three `sysusers.d` files (systemd);
  `pam-auth-update` (libpam-modules and libpam-runtime).
- **System features:**
  - files: 263 systemd units, 18 `tmpfiles.d` files, 4 udev rules, 6 PAM
    files and 2 cron files, but no init scripts;
  - service tools: `systemd-machine-id-setup`, `deb-systemd-helper`,
    `deb-systemd-invoke`, `invoke-rc.d` and `start-stop-daemon`;
  - `/etc/shells` updates via `add-shell` and `update-shells`.
- **Solver:** for `awk`, the solver picks `gawk`, not `mawk`, in both
  closures; gawk's `update-alternatives` use is a P1 gap.

The prioritized gap list below is derived from the committed inventories.
`check` recomputes it.

| Priority | Gap | Packages | Native status |
| --- | --- | --- | --- |
| P0 | archive admission rejected | none | — |
| P1 | `update-alternatives` script authority | bash, debianutils, gawk, tar, util-linux | only exact Ubuntu script and dpkg tool digests carry authority; native lifecycle refuses before launch |
| P1 | debconf frontend | base-passwd, dash, debconf, libc6, libpam-modules, libpam-runtime, libpam0g | no Debian debconf database/frontend authority |
| P1 | kernel filesystem (`/proc`) | libc6 `preinst` | the runner provides no `/proc` or `/sys` |
| P2 | accounts | apt, base-passwd, libpam-modules, libpam-runtime, systemd | mutations outside the dpkg database; unobserved for Debian |
| P2 | service manager | apt, dpkg, libc6, libpam-modules-bin, libpam0g, libselinux1, systemd, util-linux | chroot without a running manager; unobserved |
| P2 | environment probes | apt, base-files, base-passwd, dpkg, libc6, libpam-modules-bin, libpam0g, systemd, util-linux | native runner result unobserved |
| P2 | system registry (`/etc/shells`) | dash, debianutils | unobserved |
| P3 | dpkg database helpers | 16 packages | modeled natively; no Debian parity evidence |
| P3 | `ldconfig` | libc-bin | ordinary in-root command; no parity evidence |
| P3 | trigger declarations | 45 packages | modeled; processing parity unobserved |
| P4 | ownership and mode | base-files, base-passwd, libpam-modules-bin, mount, util-linux | supported metadata; review against statoverrides |

The priorities mean:

- **P1:** a native Debian install stops before or at the affected script.
- **P2:** side effects whose native result must still be observed.
- **P3 and P4:** modeled, but without Debian parity evidence.

## What remains for native execution

Nothing above needed amd64 execution, because lock resolution, download,
CAS and inventory never run package code. The following work does need
native execution, on hosted CI (an x86_64 runner for amd64, an arm64 runner
for arm64):

1. A native fresh-root install from these locks that exercises the P1 and P2
   rows.
2. Reference (dpkg/APT) versus native parity for the same locks.

These are tracked in #271 (amd64) and #273 (arm64). The committed,
bounded locks (at most 128 packages and 64 MiB each) and their CAS and
inventory evidence are the baseline input for those runs. Nothing here
satisfies their gate.

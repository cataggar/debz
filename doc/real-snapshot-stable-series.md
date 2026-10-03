# Real-snapshot reference on a stable series (design for #330)

Status: **reviewed on #330** (see [review decisions](#review-decisions)).
PR A implements the `frozen_release_with_witnesses` freshness policy; the repin
tool (PR B) and the migration (PR C) are not implemented yet. The
current pin stays the Ubuntu development series `stonking` at
`https://snapshot.ubuntu.com/ubuntu/20261001T000000Z` until the migration
described in [question 5](#5-migration-order) lands.

This document answers the five design questions on #330 with measured data:

1. [Series choice](#1-series-choice)
2. [Freshness without a clock override](#2-freshness-without-a-clock-override)
3. [Churn](#3-churn)
4. [Repin tooling and runbook](#4-repin-tool-and-runbook)
5. [Migration order](#5-migration-order)

## Recommendation

- **Series:** Ubuntu 26.04 `resolute` with `resolute-updates` and
  `resolute-security`, `main`, on amd64 and arm64. All come from one URI,
  `https://snapshot.ubuntu.com/ubuntu/<T>`, and one signer, `F6ECB376…93C`.
  The request stays `ubuntu-minimal`. Debian `trixie` stays a separate #261/#289
  lane.
- **Freshness:** a new per-pocket policy,
  `frozen_release_with_witnesses`. A frozen release pocket is admitted only
  when both of the following hold:
  - its signed Release bytes equal a reviewed pinned digest;
  - every named witness pocket in the same snapshot, signed by the same key,
    passes its own ordinary freshness check at the real verification time.

  The pocket's own age is never compared with the clock, and nothing is
  evaluated at a historical time. A resolute pin then stays admissible for
  about 31 days after the snapshot timestamp. The current stonking pin lasts
  14 days, and a trixie pin that includes its 7-day `-updates`/`-security`
  pockets lasts at most 7 days.
- **Churn:** over three consecutive two-week windows, the resolute
  `ubuntu-minimal` closure (177 packages) changed 33, 17 and 6 versions, and
  reviewed identities changed 5, 0 and 1 times. Every reviewed SRU kept its
  maintainer scripts byte-identical, or changed only debhelper version
  comments. Stonking changed 18, 33 (+1/−2) and 36 versions, and 5, 6 and 5
  reviewed identities, including upstream jumps and semantic script changes.
- **Tooling:** `tools/real-snapshot-repin.py` and a reviewed pin manifest. All
  authentication goes through `debz` itself. Admissions bind exact bytes, so
  a repin that leaves those bytes unchanged needs no re-review.
- **Order:**
  1. freshness policy and repin tool, in parallel;
  2. one migration PR;
  3. then #287's prestates, #262's arm64 admissions and #270 on resolute.

  No reviewed evidence is generated twice.

## Method and data

The data was collected on 2026-10-01 (about 07:50Z) on an aarch64 host:

- A ReleaseSafe `debz` was built from `e7a6cae` and run with the commands
  `refresh` and `plan --transaction-backend native`, using the system keyring
  `/usr/share/keyrings/ubuntu-archive-keyring.gpg`.
- InRelease files and the `main` `Packages.xz` indexes were fetched for these
  snapshots:
  - 20260820T000000Z
  - 20260903T000000Z
  - 20260917T000000Z
  - 20260923T000000Z
  - 20261001T000000Z

  Each index was checked against the strongest digest its InRelease lists.
- Closures were computed with a throwaway resolver, which is not committed.
  It follows `Pre-Depends`/`Depends` from `ubuntu-minimal` plus
  `Essential: yes`, and the highest version across pockets wins. The resolver
  is calibrated against `debz`:
  - It reproduces `debz plan`'s 175-package stonking 20261001 lock exactly
    (names and versions) on amd64 and arm64.
  - It reproduces the 21 version changes that #331 recorded for stonking
    20260923 → 20261001.
- Maintainer scripts were compared for 42 package versions of the 18 reviewed
  packages listed in question 3, on amd64 and arm64. Each `.deb` was checked
  against its Packages SHA-512, or SHA-256 where that is the only digest
  listed. Then `control.tar` was extracted and the members were hashed.

### Ubuntu pockets

| Pocket @ 20261001T000000Z | Signed `Date` | `Valid-Until` | Release hash fields | Signer |
|---|---|---|---|---|
| `resolute` (26.04) | Thu, 23 Apr 2026 17:07:15 UTC | none | MD5Sum, SHA1, SHA256 | `F6ECB3762474EDA9D21B7022871920D1991BC93C` |
| `resolute-updates` | Wed, 30 Sep 2026 20:38:20 UTC | none | MD5Sum, SHA1, SHA256 | same |
| `resolute-security` | Wed, 30 Sep 2026 21:10:36 UTC | none | MD5Sum, SHA1, SHA256 | same |
| `stonking` (26.10) | Wed, 30 Sep 2026 23:37:07 UTC | Wed, 14 Oct 2026 23:37:07 UTC | SHA512 | same |

Facts that the design depends on:

- **The `resolute` InRelease is byte-identical in all five snapshots.**
  - InRelease SHA-256: `45f95ce276cdba3e…`.
  - Signed-cleartext SHA-256, which is what exact locks record as
    `release_sha256`:
    `596ee4cea058f74d59e2180532c89904e306d90725d42162eda82c01d4370834`.
  - The stonking cleartext digest computed the same way matches `debz`'s own
    lock value, `8042c13e…`.
- **No resolute pocket carries `Valid-Until`.**
  - `-updates` and `-security` were published 1.4 to 9.0 hours before every
    sampled snapshot timestamp.
  - All Ubuntu pockets carry exactly one signature: RSA/SHA-512 from the
    2018 archive key `F6ECB376…`.
- **arm64 is in the same archive.**
  - Every resolute InRelease lists `amd64 amd64v3 arm64 armhf i386 ppc64el
    riscv64 s390x`.
  - The arm64 indexes at `/ubuntu/<T>/dists/resolute*/main/binary-arm64/`
    hash-verify.
  - `https://snapshot.ubuntu.com/ubuntu-ports/…` returns HTTP 401, and
    `/ubuntu/latest/` returns 404.
  - On both architectures the closure has the same 177 names and versions.
- **The resolute Release files list no SHA-512.**
  - Exact locks will therefore record `index_identity.primary == "sha256"`.
    `review_lock` in `tools/real-snapshot-acceptance.sh` currently requires
    `sha512`.
  - Packages entries do carry SHA-512, with these exceptions:
    - 96 of 6,486 amd64 entries in the release pocket;
    - 5 `libtiff` entries in `-updates` and in `-security`.
  - At 20261001, all 177 closure packages have SHA-512, so archive identity
    stays SHA-512 primary.
  - At 20260820, `sudo-rs 0.2.13-0ubuntu1` (release pocket) had only SHA-256.
    The repin tool must detect this case (see question 4).
- **`debz refresh` with the current 31-day bounded policy:**
  - `resolute-updates` and `resolute-security` authenticate on amd64 and
    arm64.
  - `resolute` fails on both architectures with `ReleaseExpired` (exit 4).
    `refreshAuthenticated` runs OpenPGP verification before
    `validateRelease`, so the signature was accepted and only the freshness
    check refused.
- **The dpkg in resolute is `1.23.7ubuntu1`** (release pocket, unchanged since
  release).
  - `usr/bin/dpkg`: amd64 322,728 bytes, SHA-256 `972003a1…6517`; arm64
    330,816 bytes, `6c03c9fa…692f`.
  - `usr/bin/update-alternatives`: amd64 `023e1c2e…ed45`; arm64
    `dae71fcd…7807`.
  - The same extraction reproduces #322's stonking `1.23.7ubuntu2` pins (amd64
    `6587ef9e…739f`, arm64 `d622099d…d4b4`) and the `3e5fbdcf…` amd64
    `update-alternatives` digest in `doc/dpkg-alternatives-reference.md`.

### Hazard: snapshot timestamps in the future are mutable

snapshot.ubuntu.com resolves a timestamp to the archive state *at the time of
the request* until that timestamp has passed. A future timestamp is served
with `cache-control: max-age=31536000` like any other.

#331 authenticated stonking `20261001T000000Z` on 2026-09-30, about 20:53Z.
That was before 00:00Z, and #331 merged at 23:12Z. #331 recorded InRelease
SHA-256 `33cd7da8…`. #331 and five docs on main record `Date` 20:37:08 and
`Valid-Until` 2026-10-14 20:37:08. The five docs are:

- `doc/dpkg-alternatives-reference.md`
- `doc/integration-roots.md`
- `doc/native-recovery.md`
- `doc/project-status.md`
- `doc/safety-ci.md`

The same URL now serves different bytes:

- InRelease SHA-256 `ee4ca502…`;
- `Date` 23:37:07;
- `Valid-Until` 23:37:07.

PR A corrected the five docs to these values after re-fetching the same bytes
on 2026-10-01, after `T` had passed.

`review_lock` does not pin `release_sha256`, so the dispatch lane still
passes. However, the docs are inaccurate, and any evidence that binds the old
`release_sha256` (such as #287's prestates) would refuse. Rules that follow:

- A pin must bind each pocket's Release digest.
- The repin tool must refuse a timestamp less than 24 hours in the past.
- The tool must re-fetch before it finishes and require identical bytes.

### Debian pockets (from #330 and snapshot.debian.org at 20261001T000000Z)

| Pocket | `Version` | `Date` | `Valid-Until` | Signers |
|---|---|---|---|---|
| `trixie` | 13.7 | 2026-09-12 07:55:41 | none | archive keys `4cb50190…e131`, `b8e5f131…2265`, plus stable release key `41587f7d…9de4` |
| `trixie-updates` | 13-updates | 2026-09-30 20:12:08 | 2026-10-07 (7 days) | archive keys only |
| `trixie-security` (debian-security archive) | 13 | 2026-09-30 22:42:41 | 2026-10-07 (7 days) | `b0cab926…c7a8`, `89c87ace…ba95` |

Other Debian facts:

- trixie's `dpkg` is **1.22.22**. Its archives are byte-identical to the
  pinned reference archives in `tools/prepare-native-dpkg.py` (amd64
  `3e800c6d…`, arm64 `1142468e…`).
- None of the Debian Release files list SHA-512, so #289 binds signed SHA-256
  with a derived SHA-512.

## 1. Series choice

| | Ubuntu `resolute` (recommended) | Debian `trixie` | Ubuntu `stonking` (today) |
|---|---|---|---|
| Release-pocket expiry | none, frozen since 2026-04-23 | none, frozen per point release (about every 2 months) | 14-day `Valid-Until` |
| Admissible pin lifetime under the proposed policy | about 31 days (`-updates`/`-security` `Date` + 31 days; 30.6–30.9 days after `T` in all five samples) | at most 7 days with any witness or security pocket (their `Valid-Until`) | 13.7–14.0 days |
| Signers | one key for all pockets | three key sets; security uses its own keys and archive | one key |
| arm64 | same URI and closure; existing `ubuntu-24.04-arm` runner | same archive; security in a second archive | same as resolute |
| Frozen-pocket re-review | never during 26.04's life | at each point release | n/a |
| dpkg in the snapshot | 1.23.7ubuntu1 (needs a #322-style executable pin) | 1.22.22, identical to the pinned reference | 1.23.7ubuntu2 (#322) |
| `ubuntu-minimal`-style closure | 177 packages, `ubuntu-minimal` | different package family (#289: `apt` 73, `systemd-sysv` 69) | 175 packages |
| Reviewed-identity churn per two weeks | 5, 0, 1 | not measured; point releases are not mechanical | 5, 6, 5 |

**Recommendation: resolute.** It is the only candidate that yields a
pin lifetime of several weeks with security pockets included. It keeps one
signer and one URI on both architectures, and its frozen pocket never
needs re-review during the series' life. Moving from stonking is also cheaper
than moving to Debian, because the reviewed package names stay the same (see
[question 3](#3-churn)).

trixie's one real advantage is that its dpkg equals the pinned 1.22.22
reference byte for byte. That does not outweigh weekly repins and the
three-key-set witness problem the owner described on #330.

**dpkg references:**

- Pinned dpkg 1.22.22 remains the series-independent lifecycle, recovery and
  alternatives oracle. `tools/prepare-native-dpkg.py` downloads it from
  `deb.debian.org`, so it is unaffected by this move.
- The real-snapshot reference scripts use the snapshot's own dpkg. They pin
  `usr/bin/dpkg` 1.23.7ubuntu1 per architecture (digests above), replacing
  #322's stonking `1.23.7ubuntu2` pin in the same migration PR.
- dpkg changes in resolute only through an SRU, which the repin tool reports.

Debian keeps its own lane (#261/#289). It can adopt the same frozen-pocket
policy, with `trixie-updates` as a witness signed by the shared archive keys
(see below). Its pins would then last 7 days instead of dying on the fixed
date 2026-10-13.

## 2. Freshness without a clock override

### What freshness protects

The current policy (`require_valid_until`, or
`allow_missing_valid_until_with_max_age_seconds` of at most 31 days) protects
against two things:

- **freeze/replay attacks:** an old signed Release is served to withhold
  updates;
- **indefinitely aging pins:** an immutable snapshot URL keeps installing
  outdated packages long after it was taken.

A frozen release pocket is not a replay risk if it is exactly the reviewed
bytes, because nothing newer exists for that suite. Updates reach a stable
series only through `-updates` and `-security`. So an installation stays
current exactly when those pockets are fresh.

### Policy: `frozen_release_with_witnesses`

A repository R configured with this policy is admitted at verification time
`now` only if every condition below holds. `now` is the same clock the
refresh already uses: `RefreshPolicy` plus the injectable `Clock`, with no
override.

1. **Pinned bytes.** R's signed Release cleartext digest (the value recorded
   as `Provenance.release_digest` and lock `release_sha256`) equals the
   configured, algorithm-tagged `frozen_release_digest`. Otherwise refusal is
   `ReleaseFrozenDigestMismatch`. The pin is new content authority over index
   metadata, so it is a `content_digest.Value`, never a raw 32-byte field, and
   every wire form names its algorithm (`sha256:<hex>`). SHA-256 is the only
   accepted algorithm for now, because Release files publish only SHA-256. A Debian point release or an Ubuntu
   re-publication therefore always needs a reviewed repin.
2. **Really frozen.** R's Release has no `Valid-Until`
   (`ReleaseFrozenValidUntilPresent`). Its `Date` still obeys the existing
   future-skew bound. Development-series and pre-release Releases have
   `Valid-Until`, so they can never use this mode.
3. **Named witnesses.** The policy lists one or more witness suites
   (`Policy.freshness_witnesses`; `witness_suites` in configuration). Each
   suite must resolve, in the same normalized
   configuration, to exactly one enabled repository W, and W must meet all of
   these conditions:
   - It has the same `uri` (so the same snapshot timestamp), `component`,
     `architecture` and `signed_by` as R.
   - Its own freshness is **not** frozen, so witnesses cannot chain.
   - It is not stale under `allow_stale_authenticated`.

   An unresolvable witness is a normalization diagnostic
   (`invalid_freshness_witness`). It is never discovered at refresh time.
4. **Witness freshness.** Each W passes its own policy at the same `now`: for
   example, Ubuntu `allow_missing_valid_until_with_max_age_seconds` = 2678400,
   or Debian `require_valid_until`. A witness failure fails R with
   `ReleaseFrozenWitnessUnavailable`, and the witness's own error is reported
   for W.
5. **Same signer.** At least one primary fingerprint has a `valid`
   signature on both R's and W's Release, and that fingerprint is in the
   accepted set of both (`ReleaseFrozenWitnessSignerMismatch`).
   - Ubuntu: `F6ECB376…` on every pocket.
   - Debian: archive keys `4cb50190…`/`b8e5f131…` on `trixie` and
     `trixie-updates`. Configuration must therefore accept them on `trixie`,
     not only `41587f7d…`.
6. **Same origin, not older.** W's `Origin` and `Label` equal R's, and W's
   signed `Date` ≥ R's (`ReleaseFrozenWitnessOriginMismatch` and
   `ReleaseFrozenWitnessOlder`). `trixie-security`
   (`Label: Debian-Security`, different URI and keys) can therefore never be
   a witness for `trixie`. It is configured as an ordinary
   `require_valid_until` repository.
7. **Admission deadline.** R's admission deadline is the minimum of its
   witnesses' deadlines:
   - `Valid-Until` plus grace, or
   - `Date` + maximum age.

   It is recorded, and later cache-only loads and lock replays recompute it
   at their own `now`.

**Example deadlines.** For resolute at `20261001T000000Z`, R's deadline is
2026-10-31T20:38:20Z:

- `-updates` deadline: 2026-09-30 20:38:20 + 31 days;
- `-security` deadline: 21:10:36 + 31 days.

A trixie pin witnessed by `trixie-updates` expires at that pocket's
`Valid-Until`, 2026-10-07T20:12:08Z.

No step evaluates R's `Date` against `now` beyond the existing future-skew
check. No step substitutes a historical time. Expiry comes only from fresh,
same-key, same-snapshot pockets that carry every update the frozen pocket
lacks.

### Configuration shape

Freshness is a per-document `Policy` field today, and `Suites: a b c` expands
into independent repositories that share one policy. Per-pocket freshness
therefore uses one `--config` document per pocket. `loadRepositoryDocuments`
already accepts many. The release document becomes:

```json
{
  "source_path": "/…/resolute.sources",
  "priority": 500,
  "default_release": "resolute",
  "immutable": true,
  "freshness": {
    "mode": "frozen_release_with_witnesses",
    "frozen_release_digest": "sha256:596ee4cea058f74d59e2180532c89904e306d90725d42162eda82c01d4370834",
    "witness_suites": ["resolute-updates", "resolute-security"]
  }
}
```

`resolute-updates` and `resolute-security` keep
`{"mode": "allow_missing_valid_until_with_max_age_seconds",
"maximum_release_age_seconds": 2678400}`. Any unknown field, empty witness
list, duplicate witness, untagged digest, digest with an algorithm other than
`sha256`, or digest that is not 64 lowercase hex characters is
`InvalidRepositoryConfig`. A self-reference or unresolved witness is the
normalization diagnostic `invalid_freshness_witness`.
`maximum_release_age_seconds` may be
omitted; it must be absent or `null` for `require_valid_until` and the frozen
mode, and the frozen fields are refused for every other mode.

### Identity binding

The design binds the policy into every identity layer, following the
precedent set when the bounded missing-`Valid-Until` exception was added:

| Layer | What changes |
|---|---|
| Normalized repository identity | `repository_policy.repositoryId` hashes the tag, the tagged `frozen_release_digest` text and the sorted witness suites. `configurationId` uses a new domain, `debz-multi-repository-configuration-v3`, only when a frozen repository is present, so v1/v2 identities of existing configurations are unchanged. `appendCanonical` emits `# X-Debz-Expiry-Policy: frozen_release_with_witnesses`, `# X-Debz-Frozen-Release-Digest: sha256:…` and `# X-Debz-Freshness-Witnesses: …`. Conflict equality (`expiryPoliciesEqual`, `runtimeMatches`) compares all three. |
| Snapshot provenance | `PolicyDecisions` gains the tagged `release_digest`, the witness decisions (each witness's repository id, snapshot digest, signed `Date`, deadline and the matched fingerprint) and `admission_deadline_unix`. `snapshotDigest` hashes them under a new domain, `debz-authenticated-repository-snapshot-v4`, only for frozen repositories, so every existing digest and lock stays byte-identical. Frozen repositories store `SnapshotManifest`/`encodeSnapshot` as `debz-repository-snapshot-v5` in a new cache namespace, `repository-refresh-v5`; every other repository keeps v4 bytes and the v4 namespace. |
| Exact lock | `schema/exact-closure-lock-v3.json` does not change. A lock binds the policy through `Repository.id` (repository identity) and `Repository.snapshot_sha256` (snapshot digest v4, which includes the witnesses' snapshot digests). This holds even when a witness contributes no package and so cannot appear in the lock (`error.UnusedRepository`). `doc/exact-locks-and-provenance.md` documents snapshot digest v4. An explicit `freshness` member in a future lock v4 is deferred until other v4 changes justify a new lock schema. |
| Aggregate manifest | The `refreshAll` writer emits `debz-multi-repository-manifest-v2` only when a frozen repository is present, recording each frozen repository's admission deadline and witness repository IDs. Other manifests keep their v1 bytes. |

### Files and structs that change

- **`src/repository_refresh.zig`**
  - Add `ExpiryPolicy.frozen_release_with_witnesses: FrozenRelease`, holding
    `release_digest: content_digest.Value`, plus `validFrozenReleaseDigest`
    (SHA-256 only, non-zero), `parseFrozenReleaseDigest` and
    `taggedDigestText`. Snapshot manifest v5 stores the algorithm byte before
    the digest bytes. Only the witness snapshot digests are raw 32-byte
    domain-separated controls; `src/repository_refresh.zig` joins the
    `raw-control-and-compatibility-fields` semantic allowlist for them.
  - Update `validExpiryPolicy`, `expiryPolicyMaxAge` (returns `null`) and
    `expiryPoliciesEqual`.
  - Add `RefreshPolicy.frozen_witnesses: []const WitnessEvidence`. If it is
    empty for a frozen policy, refresh fails with
    `ReleaseFrozenWitnessUnavailable`, so `refreshAuthenticated` can never
    admit a frozen pocket alone.
  - Add a frozen branch in `validateRelease`, plus eight new `Release*`
    errors: the six above, `ReleaseFrozenWitnessTargetMismatch` and
    `ReleaseFrozenWitnessChanged`.
  - Update `PolicyDecisions`, `snapshotDigest`, `SnapshotManifest`,
    `encodeSnapshot`, `snapshot_magic` and `snapshot_id`.
  - Make the cache-only reload re-evaluate the witnesses.
- **`src/repository_policy.zig`**
  - Add `freshness_witnesses` to `Policy` and to `NormalizedRepository`.
  - Validate witnesses in `normalize`, with
    `DiagnosticCode.invalid_freshness_witness`.
  - Update `repositoryId`, `configurationId` and `appendCanonical`.
  - In `refreshAll`, refresh witnesses first, build `WitnessEvidence` from
    their `AuthenticatedResult`s, and fail the frozen repository if any
    witness failed or is stale.
  - Add `PublishedRepositoryState.frozen` (admission deadline and witness
    repository IDs).
  - Emit aggregate manifest v2 only when a frozen repository is present.
- **`src/production_backend.zig`**
  - Add the new mode to `ConfigFreshnessMode`.
  - Add `ConfigFreshness.frozen_release_digest` (`sha256:<hex>`) and
    `.witness_suites`.
  - Update `configuredFreshness` and `loadRepositoryDocuments`.
  - Extend the test "production repository config freshness is finite and
    explicit".
- **`src/target_apt_config.zig` and `schema/apt-config-snapshot-v2.json`**
  - The schema is unchanged in phase 1. Target-root APT configuration cannot
    express the frozen mode: `parseFreshness` keeps refusing unknown modes, and
    source policies and manifests refuse it explicitly.
  - Supporting the mode in target-root configuration later requires
    `apt-config-snapshot-v3`.
- **`tools/real-snapshot-acceptance.sh`, `test/real-snapshot-policy.zig` and
  `.github/workflows/ci.yml`**
  - Write three config documents.
  - In `review_lock`, accept `index_identity.primary == "sha256"` only for
    repositories whose signed Release lists no SHA-512, and still require
    SHA-512 archive identities and the single reviewed signer.
  - Pin the URI from the manifest (see question 4).
- **Docs:**
  - `doc/authenticated-refresh.md`
  - `doc/multi-repository-policy.md`
  - `doc/exact-locks-and-provenance.md`
  - `doc/target-apt-config.md` (the refusal)
  - `doc/integration-roots.md`
  - `doc/safety-ci.md`

**Tests (Zig).** All use the existing synthetic signed-Release fixtures and an
injected clock set to the real verification time of each scenario.

`repository_refresh` cases:

- a frozen pocket is admitted with fresh witnesses;
- it is refused for each of the following:
  - an expired witness;
  - a missing witness;
  - a witness signed only by another key;
  - a witness from another URI;
  - a witness that is older than the frozen pocket;
  - a present `Valid-Until`;
  - a digest mismatch;
- the cache-only reload re-evaluates after a witness expires;
- the snapshot digest changes when a witness's digest changes and is
  unchanged for non-frozen repositories.

`repository_policy` cases:

- identity and canonical-output inputs;
- unresolved witnesses, chained witnesses and disabled witnesses;
- v1/v2 configuration identities stay stable.

`production_backend` covers the configuration parsing cases.

### Alternatives rejected

- **Raise the maximum age** (for example to 365 days). This weakens freeze
  protection for every pocket and only moves the cliff: resolute would die on
  2027-04-23 regardless of repins.
- **A CI clock override, or verifying at the snapshot timestamp.** Both are
  explicitly out of scope on #330, and they would let a stale pin pass
  forever.
- **Pinned digest without witnesses.** A frozen pocket configured alone would
  never expire and would carry no security updates.
- **Witnesses without a pinned digest.** For Debian, any superseded
  `trixie` point-release Release (none of which has `Valid-Until`) could be
  replayed next to a fresh `trixie-updates`.

## 3. Churn

### Closure churn (`ubuntu-minimal`, amd64; arm64 is identical)

| Window | resolute: changed versions (of 177) | reviewed identities changed | stonking: changed versions (of 175–176) | reviewed identities changed |
|---|---|---|---|---|
| 08-20 → 09-03 | 33 | 5: console-setup, console-setup-linux, keyboard-configuration (1.237ubuntu3 → .1), sudo-rs (0.2.13-0ubuntu1 → .2), util-linux (2.41.3-3ubuntu2 → .2) | 18 | 5: bash, sudo, sudo-rs (0.2.13 → 0.2.14), systemd and udev (259.5 → 261.2) |
| 09-03 → 09-17 | 17 | 0 | 33, +1/−2 | 6: chrony, console-setup, console-setup-linux, keyboard-configuration, procps (4.0.4 → 4.0.6), python3 (3.14.3 → 3.14.7) |
| 09-17 → 10-01 | 6: libexpat1, libglib2.0-0t64, libssl3t64, openssl-provider-legacy, sudo, ubuntu-minimal | 1: sudo 1.9.17p2-1ubuntu3 → 3.1 | 36 | 5: dpkg, sudo-rs, systemd, udev, util-linux (2.41.3 → 2.42.2) |
| 08-20 → 10-01 (6 weeks) | 51 | 6 | 64, +1/−2 | 13 |

Notes on the table:

- "Reviewed identities" here are the 18 packages whose scripts, archives,
  tools or versions are pinned in the tree today:
  - bash, chrony, console-setup, console-setup-linux, dash, dpkg,
    init-system-helpers, iproute2, keyboard-configuration;
  - less, netcat-openbsd, procps, python3, sudo, sudo-rs, systemd, udev,
    util-linux.
- At 20261001 the resolute closure came from these pockets: 107 packages
  from the release pocket, 55 from `-security` and 15 from `-updates`.
- Every resolute change is an SRU or security suffix (`ubuntuX.Y`). Stonking
  also takes new upstream versions.

### Script bytes behind those versions

| Version change | Control members |
|---|---|
| resolute sudo, sudo-rs, util-linux (SRUs above) | **all byte-identical** |
| resolute console-setup, console-setup-linux, keyboard-configuration (1.237ubuntu3 → .1) | only `# Automatically added by dh_*/13.28ubuntu1` → `13.31ubuntu1` comment lines |
| stonking systemd, udev (261.2-1ubuntu1 → 2) | all byte-identical |
| stonking sudo-rs (0.2.14-1ubuntu2 → 4) | debhelper comments only (matches #331's review) |
| stonking dpkg (1.23.7ubuntu1 → 2) | `postrm` semantic; others comments only |
| stonking util-linux (2.41.3-3ubuntu2 → 2.42.2-1ubuntu2) | `postinst`/`postrm` semantic (the `DPKG_ROOT` guard noted on #331) |

Across all 32 architecture-specific package versions examined, the control
members are **byte-identical on amd64 and arm64**. The archive SHA-512 differs
in all 31 that list one.

### How admissions bind

Admissions and fixtures bind the **exact bytes that run**:

- a maintainer script: package, member, SHA-256 and size;
- a tool input: path, size, mode and SHA-256, as `snapshot_*_inputs` already
  do.

The version and the per-architecture archive SHA-512 are **provenance** in
the pin manifest. They are never the admission key, and the snapshot URI or
Release digest is never part of an admission. Consequences:

- A repin whose bound bytes are unchanged is "provenance-only". The tool
  updates the manifest mechanically and no re-review is needed. Over six weeks
  this covered 3 of the 6 resolute reviewed-version changes.
- Any change to bound bytes, including a debhelper comment, is a reviewed
  change. The tool shows the diff and classifies it, but the classification
  is advisory only.
- One script review covers amd64 and arm64 (useful for #262). Tool inputs
  stay per architecture because the binaries differ.
- Fixture files drop the version from their names
  (`src/fixtures/ubuntu-resolute-sudo-rs.postinst`), so provenance-only repins
  do not rename files or churn `security/digest-inventory-v1.tsv`.
- Version-bound logic that really depends on version stays explicitly
  version-keyed, and the manifest marks it `version_bound: true`. An example
  is the `native_unpack` proc-admission versions, if a review decides the
  version matters.

### One-time migration cost from stonking to resolute

Compared at 20261001, the 18 reviewed packages contain 75 control members:

- 34 are byte-identical;
- 12 differ only in debhelper comments;
- 29 differ semantically, in these packages:
  - systemd, udev, sudo (#287's proc admissions);
  - bash, procps, util-linux, keyboard-configuration, console-setup, chrony;
  - the dpkg `postrm`.

For the 9 committed `src/fixtures/ubuntu-stonking-*` scripts:

- 4 are identical (both `less` scripts, `netcat-openbsd` postinst and
  `python3` preinst);
- 2 differ only in comments (`console-setup-linux`, `sudo-rs`);
- 3 change semantically:
  - `bash`: `$(…)` → backticks;
  - `util-linux`: no `DPKG_ROOT` guard;
  - `procps`: the resolute postinst has **no** `update-alternatives` block,
    which removes one alternatives admission.

These differences are reviewed once, in the migration PR.

## 4. Repin tool and runbook

### Tool

`tools/real-snapshot-repin.py` uses only the Python standard library, like
`tools/prepare-native-dpkg.py` and #289's `tools/debian-stable-closure.py`.
Its subcommands (`probe`, `diff`, `record`, `check`) follow the latter's
`run`/`compare`/`record`/`check` pattern, so the Debian lane can adopt it
through a second series profile.

It never implements OpenPGP or Release policy itself:

- It drives a ReleaseSafe `debz` built from the checkout (`refresh`, `plan
  --transaction-backend native --lock-output`, `download --lock-input`) in a
  fresh workspace under `.tmp/`.
- It reads `control.tar` members only from CAS objects that `debz download`
  has already verified.

**Inputs:**

- `--series ubuntu-resolute`, which defines:
  - the URI root;
  - the pockets and witness relation;
  - `main`;
  - amd64 and arm64;
  - the keyring path and reviewed signer;
  - the request `ubuntu-minimal`.
- `--timestamp T`. The default is the newest settled day:
  `floor_day(now − 24 h)`.
- `--debz PATH`
- `--manifest tools/fixtures/real-snapshot/pin-v1.json`
- Optional `--pr N…`, to scan open PRs.

**`probe` checks.** Any failure exits nonzero before any lock is written:

1. `T` is at least 24 hours in the past (`now − T ≥ 86400 s`) and not older
   than the current pin.
2. For each pocket, the tool fetches the Release twice: once at the start and
   once after planning. The bytes must be identical. This catches the
   mutable-timestamp hazard.
3. `debz refresh` authenticates every pocket under the configured policies at
   the real clock.
4. Each pocket's signed `Date` is ≤ `T`. Witness `Date`s are within 48 hours
   of `T`, which flags a stale snapshot service.
5. The signer equals the manifest's reviewed signer, and the frozen pocket's
   `release_sha256` equals the manifest value. A change requires an explicit
   `--accept-frozen-release` review entry.
6. Every closure package has a signed SHA-512 archive identity. For example,
   the 20260820 `sudo-rs` entry would fail.

**Outputs:**

- `.tmp/real-snapshot-repin/<T>/report.json`, plus a Markdown summary for the
  PR body:
  - per pocket: URI, suite, `Date`, `Valid-Until` or `none`, signer
    fingerprints, InRelease SHA-256/SHA-512, cleartext `release_sha256`, the
    hash fields present, index identities, and the computed admission
    deadline;
  - per architecture: the exact lock, closure digest, package count and
    source-pocket counts.
- `diff` adds, per architecture, the changed, added and removed closure
  packages against the manifest. For every manifest identity it gives one
  of these statuses:
  - `unchanged`;
  - `provenance-only`: the version or archive changed but the bound bytes did
    not;
  - `changed`: the bound bytes differ, with a unified diff and an advisory
    classification;
  - `missing`: the package left the closure.
- With `--pr N`, the tool scans `gh pr diff N` for strings the manifest
  pins, such as:
  - the URI;
  - Release digests;
  - closure digests;
  - versions and file digests (#287's `release_sha256`, closure hash,
    `setpriv` digest).

  It lists which PR identities would go stale.
- `record` rewrites the manifest:
  - It applies `unchanged` and `provenance-only` entries automatically.
  - It **refuses** to write a `changed` or `missing` identity unless the
    operator passes `--reviewed <identity-id>=<PR-or-issue>` for exactly that
    identity. That review reference is stored with the new bytes, so every
    re-review is visible in the PR diff.
- `check` (network) recomputes and exits nonzero if any identity differs from
  the manifest. Failures are reviewed identities that changed without
  re-review.

**Pin manifest.** `tools/fixtures/real-snapshot/pin-v1.json` is the single
source of truth for:

- the URI, pockets, freshness policies, `release_sha256` values, signer and
  admission deadline;
- per-architecture closure digests;
- identity records, each with these fields: `id`, `kind`
  (`script` | `tool_file` | `archive` | `prestate`), `package`,
  `architectures`, `member`/`path`, `sha256`, `size`, `mode`,
  boolean `version_bound`, `provenance` (version, archive SHA-512 per
  architecture), `consumers` (files and constants) and `review`.

**Offline enforcement (Zig).** `test/real-snapshot-policy.zig` gains a
manifest cross-check in normal CI. It fails in these cases:

- an in-tree pin is absent from the manifest or differs from it. In-tree pins
  are:
  - fixture file SHA-256s;
  - `snapshot_*_sha256` constants in `src/native_alternatives.zig`;
  - `native_unpack.zig` admissions;
  - `maintainer_script.zig` tool inputs;
  - reference-script digests;
  - the acceptance URI;
- a manifest identity has no consumer.

`test/real-snapshot-repin.zig` runs the tool against synthetic signed fixtures
(from `tools/generate-openpgp-fixtures.py`) and covers:

- a recent `T` is refused;
- a Release that changes between fetches is refused;
- a frozen digest change without review is refused;
- an unreviewed `changed` identity is refused;
- a missing SHA-512 is refused;
- a provenance-only update is accepted;
- the PR scan output.

### Runbook (to be expanded in this document when the tool lands)

1. Build ReleaseSafe `debz` at the current `main`.
2. Run `tools/real-snapshot-repin.py probe` and read the report. Note the new
   admission deadline.
3. Run `diff --pr <open real-snapshot PRs>`.
4. For each `changed` identity:
   - review the diff;
   - update the fixture, admission or tool constant;
   - rerun `record --reviewed id=#PR`.

   For a frozen-pocket change (Debian point release), review the Release
   delta and pass `--accept-frozen-release`.
5. Run `check`, then the targeted Debug and ReleaseSafe tests, then
   `zig build write-digest-inventory` and `zig build security-audit`.
6. Open the repin PR with the generated summary, then dispatch
   `ubuntu-real-snapshot` on amd64 and arm64.
7. **Cadence:** monthly. Start when fewer than 10 days remain before the
   admission deadline. For resolute that is about day 21 of 31.

## 5. Migration order

The goal is to review each piece of real-snapshot evidence once, on resolute,
and never regenerate it on stonking first. The pinned stonking snapshot
expires on 2026-10-14. Only the manual `ubuntu-real-snapshot` dispatch lane
depends on it: `test/real-snapshot-policy.zig` uses fixed offline inputs.

1. **#320 (Microsoft 14-day profile) first, if it is still open.** It edits
   `doc/authenticated-refresh.md` and the repository backend that the
   freshness PR also touches. Its reviewed-profile pattern is compatible with
   this policy.
2. **PR A: frozen-release freshness policy.** It contains code, Zig tests and
   docs on synthetic fixtures, plus the stonking timestamp correction described
   in the hazard section above; it makes no fixture, admission or CI
   real-snapshot change.
3. **PR B: repin tool, manifest and runbook.** It runs in parallel with PR A.
   - The manifest is first recorded for the *current* stonking pin, and the
     offline cross-check proves it covers every in-tree pin.
   - The tool is exercised once against stonking: the provenance-only and
     `changed` paths, and the timestamp hazard above.
4. **#322 (#259)** landed on stonking as 85774a7. Its bounds and
   audit are not tied to a series. PR C replaces its `1.23.7ubuntu2` pin with
   `1.23.7ubuntu1`, and the stonking value is deleted rather than kept.
5. **PR C: migration to resolute, after A and B.** Using the tool's `diff`:
   - switch the acceptance script, `ci.yml` dispatch inputs and
     `real-snapshot-policy.zig` to the resolute triple and the manifest;
   - re-review the 29 semantic and 12 comment-only control members;
   - rename the fixtures to `ubuntu-resolute-<package>.<member>`;
   - update the `native_unpack` and `native_alternatives` admissions, the
     `maintainer_script` tool inputs, the reference scripts and the dpkg pin;
   - delete every stonking identity;
   - update `doc/integration-roots.md`, `doc/safety-ci.md`,
     `doc/dpkg-alternatives-reference.md`, `doc/native-recovery.md` and
     `doc/project-status.md` for the resolute migration; the stale stonking
     20:37:08 timestamp correction is part of PR A;
   - exercise the tool once, from stonking to resolute;
   - authenticate on amd64 and arm64 through the dispatch lane.
6. **#257 / #287.** Do not regenerate its signed systemd/udev/sudo proc
   prestates on stonking 20261001. The capability gate can land on synthetic
   evidence; its real-snapshot prestates are generated once, on resolute,
   after PR C. systemd, udev and sudo all change semantically between the
   series, so stonking prestates would be thrown away.
7. **#258 / #291.** The protected pinned-1.22.22 launcher is not tied to a
   series and can land at any time. Any real-snapshot evidence it adds comes
   after PR C.
8. **#262 (arm64 admissions)** after PR C. Byte-identical scripts mean that
   amd64 reviews carry over, and only the per-architecture tool inputs and
   archive provenance are new.
9. **#268 (protected CI staging)** can run in parallel. It is
   infrastructure.
10. **#270 (arm64 native vs dpkg)** comes last, after #262, #258, #263, #265
    and #268, on resolute.
11. **#261 / #289 (Debian)** stays a separate lane. After PR A it can switch
    `trixie` to `frozen_release_with_witnesses`, with `trixie-updates` as the
    witness and the archive keys accepted. It can use PR B's tool through a
    `debian-trixie` profile. That removes the 2026-10-13 cliff in exchange
    for weekly repins.

## Open questions for review

1. Should every listed witness be required (proposed), or is it enough for
   any one of them to be fresh? Requiring all of them is stricter and costs
   nothing on Ubuntu.
2. Should the Ubuntu witnesses keep the 31-day cap, or use the 14-day
   reviewed age from #320? 14 days would bring back roughly the cadence of
   stonking.
3. Should bytes-first admissions (question 3) be a separate refactor PR
   before PR C, or part of it?
4. Is an explicit lock-v4 `freshness` member wanted now, or is the deferral
   acceptable? The deferral follows the snapshot-digest precedent.

### Review decisions

The coordinator answered the open questions on #330:

1. Every listed witness must pass.
2. Witnesses without `Valid-Until` keep the 31-day bound.
3. Exact-byte admission binding is its own PR, before PR C.
4. Lock v4 is deferred.

# Real-snapshot repin tool and runbook

`tools/real-snapshot-repin.py` moves the reviewed real-snapshot pins from one
snapshot.ubuntu.com timestamp to a newer one. Unchanged bytes move
automatically, and every reviewed identity whose bytes changed has to be
reviewed again. The tool implements the repin design from #330. It uses only
the Python standard library.

## Trust boundary

The tool never authenticates repository metadata itself:

- `probe` drives a `debz` binary (`refresh`, `plan --transaction-backend
  native --lock-output` and `download --lock-input`) in a fresh workspace with
  no host APT configuration.
- The tool fetches each pocket's `InRelease` itself only to record its bytes.
  It then binds those bytes to the cleartext `release_sha256` that `debz`
  wrote into an exact lock after authenticating the Release. A pocket that
  `debz` did not authenticate in some lock is refused.
- Package members are read only from CAS objects that `debz download`
  verified. The tool hashes each object again against the lock's SHA-512
  archive identity and declared size before opening it.
- `check` reads only the checkout. It runs offline in normal CI.

## Pin manifest

`tools/fixtures/real-snapshot/pin-v1.json`
(`io.github.cataggar.debz.real-snapshot-pin.v1`) is the single source of truth
for the real-snapshot pins:

| Field | Content |
| --- | --- |
| `series` | The reviewed series profile: URI root, component, architectures, keyring, signer fingerprint, request, and pockets with their roles (`bounded`, `frozen`, `witness`). It must equal the built-in profile. |
| `snapshot` | `pending` (timestamp only) or `probed`: per pocket the `Date`, `Valid-Until`, hash fields, signers, InRelease SHA-256/SHA-512, cleartext `release_sha256`, deadline and per-architecture `binding`; the admission deadline; and the per-architecture closure digest, package counts and versions. A frozen pocket also carries the review reference that accepted its Release. |
| `uri_consumers` | Files that must name exactly the pinned snapshot URI and no other snapshot timestamp. |
| `identities` | One record per reviewed byte identity: `id`, `kind` (`script`, `tool_file`, `archive`, `prestate`), `package`, `architectures`, `path`, tagged `digest` (`sha512:` for archives, `sha256:` for members), `size`, `mode`, boolean `version_bound`, `provenance`, `consumers` and `review`. Prestate identities also list `derived_from`. |
| `excluded` | Digest literals in the scanned sources that are not snapshot pins, each with a reason. |

A consumer is a file that pins the identity in one of three forms:

- `hex`: the file contains the hexadecimal digest.
- `zig_bytes`: the named Zig byte-array constant equals the digest.
- `fixture`: the file's own bytes are the identity.

Admissions are exact-byte-bound by default: a package version change is
`provenance-only` when the reviewed member bytes, size and mode are unchanged.
The `version_bound` flag is reserved for reviewed cases where version-keyed
logic is itself part of the admission; only then must a consumer name the
provenance version.

The committed manifest starts `pending` at the current pin, `20261001T000000Z`.
It holds every reviewed identity, but no probe results yet. The tool refuses
to probe a timestamp less than 24 hours old, so the first `record` runs in the
first repin after that day has settled.

## Commands

### `probe`

```sh
python3 tools/real-snapshot-repin.py probe --series ubuntu-stonking \
    [--timestamp 20261015T000000Z] --debz zig-out/bin/debz \
    [--manifest PATH] [--workspace DIR] [--accept-frozen-release]
```

Inputs:

- `--series` names a built-in profile: `ubuntu-stonking` (one bounded pocket)
  or `ubuntu-resolute` (frozen `resolute` plus the `resolute-updates` and
  `resolute-security` witnesses). Both profiles cover `main` on amd64 and
  arm64, use `/usr/share/keyrings/ubuntu-archive-keyring.gpg` with the
  reviewed signer `f6ecb3762474eda9d21b7022871920d1991bc93c`, and request
  `ubuntu-minimal`. `--profile PATH` may add a non-built-in profile for
  tests; it cannot replace a built-in one.
- `--timestamp` defaults to the newest settled day, `floor_day(now − 24 h)`.
- `--debz` is the `debz` executable. Use a ReleaseSafe build of the commit
  being repinned. A frozen series needs a `debz` that implements the
  `frozen_release_with_witnesses` freshness policy (#330).

The probe refuses, with exit status 2, when any of these checks fails:

1. `T` is less than 24 hours old, or older than the current pin.
2. A pocket's `Release` names another suite.
3. The frozen pocket's cleartext `release_sha256` differs from the
   manifest's, and `--accept-frozen-release` was not passed. This check runs
   before `debz` does.
4. `debz refresh` does not authenticate every pocket under the configured
   freshness policies at the real clock. Bounded and witness pockets use
   `allow_missing_valid_until_with_max_age_seconds` with the 31-day bound.
   The frozen pocket uses `frozen_release_with_witnesses`, pinned to the
   probed digest.
5. Refresh omits a pocket's typed repository evidence, reports a signer other
   than the reviewed signer, or its tagged Release digest differs from the
   fetched bytes. This is checked before any planning/download, including for
   quiet pockets. Frozen decisions must name exactly the configured witnesses
   in normalized policy order, with their own refresh snapshot digests, signed
   Dates, calculated deadlines and reviewed primary signer. Each contributing
   lock must agree with refresh's Release/snapshot/signer identity. Refresh must
   report fresh authentication, not stale-cache admission.
6. A closure package, or a package that a manifest identity needs, has no
   signed SHA-512 archive identity.
7. A second fetch of any `InRelease`, made after all planning and
   downloading, returns different bytes. That means the snapshot is not
   settled.
8. A pocket `Date` is after `T`, a witness `Date` is more than 48 hours
   before `T`, a frozen pocket carries `Valid-Until`, or a frozen pocket has
   no witness.

Outputs, under `--workspace` (default `.tmp/real-snapshot-repin/<T>`):

- `report.json` (`io.github.cataggar.debz.real-snapshot-repin-report.v1`):
  the pockets with their per-architecture `binding`, `debz` repository ids and
  full public `repository_evidence` (including frozen witness decisions),
  admission deadline, per-architecture closures (lock, lock digest, closure
  digest, package and pocket counts, packages), packages that could not be
  planned, and the observed value of every manifest identity.
- `summary.md`: a Markdown summary for the pull request body. It lists every
  pocket that contributes no locked package.
- `locks/`, `members/` and `debz-<arch>.jsonl`, the `debz` call log.

Each pocket's `binding`, per architecture, is one of:

- `exact_lock`: an exact lock from the closure plan or from an identity's
  plan names the repository, and its `release_sha256` equals the Release the
  tool fetched.
- `refresh_identity`: the pocket contributes no locked package, for example a
  quiet `-security` pocket, but its fetched Release is bound to public refresh
  evidence. Frozen witnesses are bound regardless of lock contribution.
- `refresh_only`: **historical evidence only**, produced before refresh exposed
  repository identity. It is never emitted by a new probe. Existing reports and
  manifests retain this honest limitation rather than being silently promoted.
  `record` requires complete matching public repository evidence before it will
  accept `refresh_identity`; a label edit alone is refused.

### `diff`

```sh
python3 tools/real-snapshot-repin.py diff --report DIR/report.json \
    [--pr N ...] [--pr-diff-file PATH ...]
```

`diff` writes `diff.json` and `diff.md` next to the report and prints the
Markdown. Every manifest identity gets a status:

- `unchanged`: same bytes and same provenance.
- `provenance-only`: the version or archive changed, but the bound bytes did
  not and the identity is not explicitly `version_bound`.
- `changed`: the bound bytes, size or mode differ, an explicitly
  `version_bound` identity's version moved, or a prestate's source packages
  changed version.
  Script and tool-file identities get an advisory: "comments or whitespace
  only", "behavioral change; review every hunk", or "no in-tree bytes to
  compare; review the new member". When the in-tree fixture exists, a script
  identity also gets a unified diff in `diff.json`.
- `missing`: the package is neither in the closure nor plannable for an
  architecture.

The diff also lists the changed, added and removed closure packages for each
architecture, and the frozen Release change, if any. `--pr N` scans `gh pr
diff N`, and `--pr-diff-file` scans a saved diff. Each lists the added lines
that pin a manifest value (URI, timestamp, Release, InRelease, closure,
identity or archive digest) and marks the pins this repin makes stale.

### `record`

```sh
python3 tools/real-snapshot-repin.py record --report DIR/report.json \
    [--reviewed ID=#PR ...] [--accept-frozen-release #PR]
```

`record` rewrites the manifest from the report:

- `unchanged` and `provenance-only` identities are applied automatically.
- It refuses unless `--reviewed ID=REF` names exactly the `changed` and
  `missing` identities. A changed identity without a review fails with
  "reviewed identities changed without re-review". A review for an identity
  that did not change also fails. The reference (`#N` or `owner/repo#N`) is
  stored as that identity's `review`.
- It refuses a changed frozen Release without `--accept-frozen-release REF`,
  and refuses that flag when the frozen Release did not change.
- It refuses a report from another series or older than the current pin.
- Exact-byte-bound identities keep their consumer paths when only provenance
  changes. When an explicitly `version_bound` identity moves to a new version,
  `fixture` consumer paths that embed the old version (without its epoch) are
  renamed in the manifest. Rename those files in the same commit.

`record` changes only the manifest. The repin commit updates the fixtures,
admissions, constants and URIs itself, then runs `check`.

### `check`

```sh
python3 tools/real-snapshot-repin.py check
```

`check` is offline. It exits 1 and lists every failure when:

- the manifest series differs from its built-in profile;
- a URI consumer does not name the pinned snapshot URI, or names another
  snapshot timestamp;
- an identity consumer does not pin the identity's digest, an explicitly
  version-bound consumer does not name the provenance version, or a fixture's
  bytes differ;
- a fixture under `src/fixtures/ubuntu-*` is not a manifest consumer;
- a digest literal is not a manifest identity or an exclusion, or an
  admission disagrees with its identity on path, size or mode. The scan
  covers `snapshot_*_sha256` constants, `.sha256` admission entries and
  quoted digest literals in `src/maintainer_script.zig`,
  `src/native_alternatives.zig` and `src/native_unpack.zig`, plus digest
  literals in `tools/real-snapshot-*.sh`.
- the protected pinned-dpkg stage's frozen suite, witness suites or frozen
  Release digest drift from the manifest, or the protected launcher's
  proc-profile `script_bindings` drift from the manifest identities for the
  staged `systemd`, `udev` and `sudo` postinsts.

`test/real-snapshot-policy.zig` runs `check` in `zig build security-audit`
and also verifies that it refuses a manifest with a mutated identity.

## Runbook

1. Build ReleaseSafe `debz` at the current `main`:
   `zig build -Doptimize=ReleaseSafe -j4`.
2. Probe the newest settled day:
   `python3 tools/real-snapshot-repin.py probe --series ubuntu-stonking --debz zig-out/bin/debz`.
   Read `summary.md` and note the new admission deadline.
3. Run `diff --report .tmp/real-snapshot-repin/<T>/report.json --pr N` for
   every open real-snapshot pull request.
4. For each `changed` or `missing` identity:
   - review the unified diff and the advisory;
   - update the fixture, admission, tool constant or reference script;
   - pass `--reviewed ID=#PR` to `record`.

   For a frozen series, a changed frozen Release (a point release) is
   reviewed as a Release delta. Pass `--accept-frozen-release` to `probe`
   and `--accept-frozen-release #PR` to `record`.
5. Run `record`, then update the URI consumers and rename the moved fixture
   files.
6. Run `check`, then the targeted Debug and ReleaseSafe tests, then
   `zig build write-digest-inventory` and `zig build security-audit`.
7. Open the repin pull request with `summary.md` and `diff.md`, and list the
   other pull requests that `diff` reported stale. Dispatch
   `ubuntu-real-snapshot` on amd64 and arm64.

**Cadence:** monthly. Start when fewer than 10 days remain before the
admission deadline (about day 21 of the 31-day bound).

## Tests

- `zig build test-real-snapshot-repin` (`test/real-snapshot-repin.zig`, in
  the release workload) runs the tool against the `debz` from the same
  build. Its synthetic `file://` snapshots are signed by a deterministic
  Ed25519 test key, and the tests use no network. They cover:
  - probe, diff, record and check across a reviewed change: a recent `T` is
    refused, a partial review is refused, provenance-only updates are
    applied, a fixture path is renamed, a stale tree fails `check`, and an
    older `T` is refused;
  - a missing SHA-512 archive identity;
  - an `InRelease` republished between the two fetches;
  - an unreviewed signer;
  - an unreviewed frozen Release, which is refused before `debz` runs;
  - a pocket whose packages are all shadowed by another pocket, and an empty
    pocket. Each is reported as `refresh_identity` on the architectures where it
    contributes nothing, without any extra `debz` plan, and `record` keeps
    that binding. Contributing Release/snapshot identities match exact locks;
    frozen witnesses include an empty security pocket on both architectures.
- `tools/test_real_snapshot_repin.py` unit-tests the tool's pure logic in
  `zig build security-audit`: timestamps, Release parsing, date and deadline
  rules, manifest and binding validation, statuses, `record` refusals and
  renames, pocket binding, and package member extraction.

## Historical evidence is not a new probe

Older committed evidence may still contain `refresh_only`, including the
resolute arm64 security pocket. The implementation fixes future observations;
it does not retroactively authenticate those fetched bytes. Replacing such a
binding requires a reviewed report from the new binary's public refresh
evidence, using the existing repin procedure. Do not fabricate a contributing
package, inspect private metadata-cache manifests as a substitute, or describe
an offline manifest `check` as a new live probe. Live native/protected acceptance
gates remain separate from these synthetic, network-free tests.

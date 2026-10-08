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
  It binds every pocket's cleartext Release digest to `debz refresh` public
  repository evidence, including quiet pockets absent from any lock. Frozen
  witness decisions must agree with their own refresh items, and contributing
  exact locks must agree with refresh's Release/snapshot/signer identity.
  Missing or mismatched public evidence is refused before planning/download.
- Package members are read only from CAS objects that `debz download`
  verified. The tool hashes each object again against the lock's SHA-512
  archive identity and declared size before opening it.
- `check` reads only the checkout. It runs offline in normal CI.
  It re-derives supported prestates from retained original archive bytes;
  it does not authenticate new metadata, contact the snapshot service, renew
  freshness, or treat a saved successful report as a fresh probe.

## Pin manifest

`tools/fixtures/real-snapshot/pin-v1.json`
(`io.github.cataggar.debz.real-snapshot-pin.v1`) is the single source of truth
for the real-snapshot pins:

| Field | Content |
| --- | --- |
| `series` | The reviewed series profile: URI root, component, architectures, keyring, signer fingerprint, request, and pockets with their roles (`bounded`, `frozen`, `witness`). It must equal the built-in profile. |
| `snapshot` | `pending` (timestamp only) or `probed`: per pocket the `Date`, `Valid-Until`, hash fields, signers, InRelease SHA-256/SHA-512, cleartext `release_sha256`, deadline and per-architecture `binding`; the admission deadline; and the per-architecture closure digest, package counts and versions. A frozen pocket also carries the review reference that accepted its Release. |
| `uri_consumers` | Files that must name exactly the pinned snapshot URI and no other snapshot timestamp. |
| `coordinate_consumers` | Optional typed bindings from snapshot URI, frozen suite, witness suites and frozen Release digest to named shell `readonly` assignments. |
| `identities` | One record per reviewed byte identity: `id`, `kind` (`script`, `tool_file`, `archive`, `prestate`), `package`, `architectures`, `path`, tagged `digest` (`sha512:` for archives, `sha256:` for members), `size`, `mode`, boolean `version_bound`, `provenance`, `consumers` and `review`. Prestate identities also list `derived_from`. |
| `prestate_evidence` | Repository-relative source-evidence ZIP, required by `check` for archive-derivable prestates and URL-bound artifacts. Retains original verified `.deb`, InRelease and Packages bytes, original authenticated exact locks and the probe report, not a second list of expected derived digests. |
| `excluded` | Digest literals in the scanned sources that are not snapshot pins, each with a reason. |

A consumer is a file that pins the identity in one of four forms:

- `hex`: the file contains the hexadecimal digest.
- `zig_bytes`: the named Zig byte-array constant equals the digest.
- `fixture`: the file's own bytes are the identity.
- `shell`: `bindings` maps typed coordinates (`digest`, `digest_size`, `url`,
  `version`, `size`, `member`) to named literal `readonly` assignments.
  The digest (or combined digest/size tuple) is mandatory. Comments containing
  correct values cannot rescue a wrong assignment. Duplicate or nonliteral
  assignments fail closed. An optional identity `artifact` supplies the
  repository-relative `.deb` filename and package architecture; its basename
  must agree with the package and provenance version. The full URL is derived
  from that filename and the pinned snapshot URI.
  For retained URL-bound artifacts, the filename is independently checked
  against the original signed Packages stanza, not merely against another
  editable manifest literal.

The protected keyring registers its actual download URL, deb size, member
path, member size and digests. The URL also binds its package version and
architecture, so the historical stonking URL/size regression cannot pass with
the resolute digest. The native dpkg exec-audit consumers additionally bind
their explicit version and digest/size tuples. Snapshot-coordinate consumers
register the acceptance, protected-stage and signed-proc staging scripts.
The specialized protected stage/launcher coupling checks remain in force.

Admissions are exact-byte-bound by default: a package version change is
`provenance-only` when the reviewed member bytes, size and mode are unchanged.
The `version_bound` flag is reserved for reviewed cases where version-keyed
logic is itself part of the admission; only then must a consumer name the
provenance version.

The committed manifest is `probed` for `ubuntu-resolute` at
`20261001T000000Z`: it records the frozen Release, both witnesses, and
177-package closures on amd64 and arm64. Its admission deadline is
2026-10-31 20:38:20 UTC; renewal requires a reviewed repin, not a clock
override. Committed quiet-pocket `refresh_only` bindings remain
[historical evidence](#historical-evidence-is-not-a-new-probe) until a real
probe using the new public refresh output proves their identity.
The tool refuses to probe a timestamp less than 24 hours old and compares
two fetches of each InRelease before recording the result.

## Commands

### `probe`

```sh
python3 tools/real-snapshot-repin.py probe --series ubuntu-resolute \
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

For supported prestates and URL-bound artifacts, `record` also exports
`prestate_evidence` from the report workspace's verified CAS objects and
original exact locks, InRelease and signed Packages index bytes. Artifact
coordinates come from those indices, not guessed pool paths. Missing source
bytes, altered locks or inconsistent archive controls refuse recording; a
report alone is insufficient. The
repin commit updates the fixtures, admissions, constants and URIs itself,
then runs `check`.

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
- a typed shell consumer's named URL, version, size, member or digest/size
  tuple differs, or a snapshot-coordinate consumer's suite/witness
  coordinates differ;
- retained source evidence is missing, stale, malformed or inconsistent
  with its original authenticated lock and current snapshot, or re-derived
  `.list`/`.triggers` digest, size or mode differs from the manifest;
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

### Offline source-evidence boundary

The retained source bundle comes from `probe`'s authenticated download path.
`check` verifies each original archive's SHA-512 and declared size against
its retained lock, verifies package/version/architecture from its control
tar, checks the lock's repository/signer/Release against the retained probe
lineage and current snapshot, validates the original InRelease/Packages
hash chain and signed package filename/size/SHA-512, and re-runs the same archive extraction and
dpkg ownership-list derivation used by `probe`. Editing both the manifest and
its code consumers to a stale derived digest still fails against those
independent source bytes. Stored report observations are not used as derived
byte verdicts. This is retained, reviewed authentication evidence, not
offline re-verification of OpenPGP signatures or a new live probe.

Adding an architecture requires its original archive bytes, not just an
unchanged derived member. The retained v1 bundle authenticates the arm64
Python package coordinates through its original lock and signed index but
does not contain the arm64 `python3` or `python3-minimal` archives. Their
expanded list-prestate coverage therefore fails closed until those exact
original archives are retained in a separately generated, versioned bundle.
The existing bundle and historical pocket labels must not be rewritten as
a new successful probe to fill that gap.

The ZIP is read without filesystem extraction. Limits are 64 MiB aggregate
evidence, 256 ZIP entries, 128 MiB decompressed tar and 100,000 tar entries;
duplicate/unsafe paths and unsupported ZIP entry types fail closed.
JSON, lock and source-metadata inputs are limited to 16 MiB before parsing.
Every source-file/ZIP-member read is capped, export enforces the remaining
aggregate budget before reading, and candidate lock enumeration is bounded.
Package tar parsing uses the standard library. Zstd-compressed packages use
Python 3.14's `compression.zstd`, or the existing bounded `zstd` fallback.

This gate covers the archive-derived `python3.list`, `python3-minimal.list`,
`sudo.list`, `console-setup-linux.list` and glib trigger declaration, plus
the keyring deb/member. The two sudo alternatives databases and
`preinst-dev-null` are behavioral outputs, not archive members or ownership
lists. Their reality still requires separately retained protected-run byte
evidence and a reviewed behavioral derivation; this change does not claim
that proof or substitute duplicated manifest constants for it. The
`(probed)` suffix reports the manifest's recorded status, not an action
performed by `check`.

`test/real-snapshot-policy.zig` runs `check` in `zig build security-audit`
and also verifies that it refuses a manifest with a mutated identity.

## Runbook

1. Build ReleaseSafe `debz` at the current `main`:
   `zig build -Doptimize=ReleaseSafe -j4`.
2. Probe the newest settled day:
   `python3 tools/real-snapshot-repin.py probe --series ubuntu-resolute --debz zig-out/bin/debz`.
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

## Ubuntu archive trust-root renewal

The protected reference proof uses a reviewed, package-derived trust root,
not the hosted image's keyring (#355). The current source is the resolute
`ubuntu-keyring_2023.11.28.1build1_all.deb`; its archive is 11,228 bytes and
its `./usr/share/keyrings/ubuntu-archive-keyring.gpg` member is 3,607 bytes.
The authoritative URL, archive SHA-512/size and member SHA-256/size constants
live in `tools/real-snapshot-reference-protected-ci.sh`. Their anti-drift
tokens are in `PROTECTED_REFERENCE_SCRIPT_TOKENS` in
`tools/security-audit.py`. Read those current values when renewing; do not
reuse the older stonking values from the original issue.

Review renewal when Ubuntu announces an archive signing-key addition,
replacement, revocation or expiry, when the authenticated package changes
its key set, or when a required signature no longer validates under the
reviewed root. Check these conditions during the monthly repin review. An
older package version alone does not require rotation if its reviewed keys
still satisfy the authentication policy. Conversely, a pending renewal does
not permit accepting an unknown, expired or revoked signer.

Renewal is a separate trust decision from a snapshot or freshness repin:

1. Select a settled snapshot and record the candidate package's exact URL,
   version, architecture, signed archive identity and size. Authenticate its
   Release, index and package record using the still-accepted trust root,
   then verify the downloaded bytes against that record before opening the
   archive. A digest computed from an unauthenticated download is not a trust
   source. If the existing root cannot authenticate the candidate, stop:
   establish independently trusted Ubuntu key-transition evidence and obtain
   explicit review of that bootstrap before proceeding.
2. In a new private review directory, independently re-derive both identities
   from the authenticated package, rather than copying the staging constants.
   With `package` naming those verified bytes and `review` naming that new
   directory:

   ```sh
   wc -c < "$package"
   sha512sum "$package"
   dpkg-deb --field "$package" Package Version Architecture
   dpkg-deb --fsys-tarfile "$package" |
     tar -xOf - ./usr/share/keyrings/ubuntu-archive-keyring.gpg \
       > "$review/ubuntu-archive-keyring.gpg"
   wc -c < "$review/ubuntu-archive-keyring.gpg"
   sha256sum "$review/ubuntu-archive-keyring.gpg"
   mkdir -m 0700 "$review/gnupg"
   gpg --batch --homedir "$review/gnupg" --no-default-keyring \
     --keyring "$review/ubuntu-archive-keyring.gpg" \
     --with-colons --fingerprint --list-keys
   ```

   Retain the authenticated metadata/lock, archive identity, extraction
   command, member bytes, complete fingerprints and expiry/revocation
   information. Compare old and new key sets; document every addition,
   removal and changed validity. Package authentication does not by itself
   authorize accepting every key or replacing the configured signer.
3. Obtain review of the source evidence, both independently derived
   digest/size pairs, key-set delta and intended accepted signer set. Any
   signer-policy change must be explicit in the same review; never silently
   expand the allowlist to make a failed signature pass.
4. Update the protected staging constants and anti-drift tokens together.
   Use the probe/diff/record flow to update manifest identities
   `archive:ubuntu-keyring` and
   `file:ubuntu-keyring/usr/share/keyrings/ubuntu-archive-keyring.gpg`,
   their provenance and every registered consumer, including
   `doc/integration-roots.md`. Review related signer/profile changes
   separately and run offline `check`, then the covering protected-CI
   policy/mutation checks and security audit.
5. Before accepting the renewal, execute the protected reference proof on
   both amd64 and arm64 with the proposed staged root. Retain
   `archive-keyring-path.tsv`, authenticated frozen/witness decisions,
   commit identity and both job outcomes. A skipped job or a successful
   proof under the previous root is not renewal evidence.

A missing or mismatched archive/member, unaccepted signer, expired metadata,
or an unreviewed key transition must fail the build or acceptance run. Never
fall back to the image keyring, change the clock, relax signature checks,
or extend the current witness deadline to conceal a renewal failure.

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

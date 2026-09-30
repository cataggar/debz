# Legacy compatibility and native-only cutover policy

This release remains **legacy-capable**. `legacy_dpkg` stays the default and
continues to execute; this increment does not remove dpkg, change defaults, or
enable fallback. It makes the compatibility boundary explicit so a later
native-only release can delete legacy execution without reinterpreting old
authority.

The machine-readable inventory is
[`security/legacy-cutover-policy.json`](../security/legacy-cutover-policy.json).
The normative Zig classifier and capability-evidence encoder are
`src/legacy_compat.zig`.

## Exact identities

- `system-profile-v1` is always legacy. Its missing backend field means
  `legacy_dpkg`, never native.
- `system-profile-v2` is backend-explicit. The selected backend must match the
  lock, result, active record, package-family surface, repository surface, and
  Actions input before mutation.
- exact-lock v1 is legacy. Exact-lock v2 remains a version-specific historical
  read format. New native product, package-cache, package-family, apt-system,
  and repository operations use exact-lock v3 with complete tagged package
  identities. Historical repository v2 operations must
  supply the separately authenticated backend context. A v2 repository lock
  without that context is refused. There is no conversion, format detection,
  or cross-backend replay.
- transaction-result v1 and v2 are legacy command-execution provenance.
  Native execution uses native transaction provenance and receipt-bound
  completion instead.
- transaction journals v1 and v2 are historical implicit-legacy records.
  Journal v3 records `legacy_dpkg` and the bounded
  `legacy-dpkg-execution-deprecated-v1` capability. Journal v4 additionally
  carries complete package identities for plan-v4/exact-lock-v3 execution.
  All four versions remain legacy and can never authorize native work.
- root-operation and completion v1 carry an explicit backend. An active record
  belongs to that backend until it is recovered and cleared by its owner.

Canonical locks, profiles, results, journals, signatures, and digests are
never rewritten to migrate them. Newly published legacy locks and transaction
results receive a separate
[`legacy-capability-evidence-v1`](../schema/legacy-capability-evidence-v1.json)
sidecar binding the exact artifact bytes. Operation-scoped sidecars also bind
the immutable root identity and attempt ID; plan-only product locks use explicit
null bindings. The sidecar is deprecation evidence, not execution authority and
not a substitute for the artifact's own canonical, signature, digest, backend,
profile, or root-operation verification. Older valid artifacts do not require a
sidecar, and a sidecar can never make invalid or mismatched artifact bytes
valid.

## Active versus completed evidence

Active legacy evidence must be finished with a release in the advertised
legacy-capable range (`>=0.3.0,<0.4.0`). A native backend, or a build declaring
itself native-only, returns a typed pre-mutation refusal:

> Recover this operation with debz >=0.3.0,<0.4.0 before installing a
> native-only release.

Native-only code must not generically abandon, reclaim, clear, or relabel an
active legacy root-operation record, even when that record is pre-mutation or
terminal. Recovery first establishes the legacy record's own terminal state and
publishes any provenance it owes.

Completed historical artifacts may remain readable after cutover only through
their exact version-specific decoder and verifier. Read-only support must
preserve canonical bytes, signature inputs, document digests, repository
snapshot identity, exact package/version/architecture spelling, and recorded
backend. Historical verification never grants mutation authority.

## Opt-in native-only rehearsal

`zig build test-native-only-rehearsal` builds an uninstalled test-only CLI and
exercises typed `native_only` selection
for product and repository CLI backends and transaction-result verification,
plus root-operation/product/repository pre-mutation refusal. An omitted
backend selects native **in the test policy only**; the released CLI, dpkg
executor, and both Actions still default to `legacy_dpkg`. Explicit new legacy
requests refuse with `LegacyCapabilityRequired` and the versioned guidance
above, before creating locks, results, sidecars, or root mutation records.
Native v3 inputs remain backend/profile/capability-bound; completed legacy
results remain independently read-only through exact version-specific
verification. An active legacy root, including a pre-mutation or terminal
unacknowledged record, is not cleared to make room for a second mutation on
either product or repository surfaces.

This is not the native-only release gate: package-family, apt/system, cache,
refresh/clean, and other unexercised selectors remain explicit #284/#280 and
final #283/#274 work. The rehearsal binary rejects those unexercised selectors
instead of advertising success-shaped defaults. No readiness policy or release
default changes here.

## Digest compatibility inventory

The tracked repository digest policy is
[`security/digest-cutover-policy.json`](../security/digest-cutover-policy.json);
the merge-friendly per-file finding inventory is
[`security/digest-inventory-v1.tsv`](../security/digest-inventory-v1.tsv).
Current package, repository-index, artifact, and package-CAS authority must use
`content_digest.Identity`, `Value`, or `Set`, or the equivalent versioned
algorithm-tagged wire form. SHA256-only fields and raw `[32]u8` widths remain
allowlisted only for frozen version-specific compatibility or unrelated
document, policy, signature, state, and transport controls. Each exception has
an exact path, a per-scope classification/rationale in the JSON policy, and a
sorted TSV inventory line with per-kind counts plus the SHA512 of that file's
canonical findings. The audit derives repository and scope totals at run time;
there is no repository-wide `tracked_files` aggregate to repin because every
scoped path is still checked against the classified scope list. Path globs,
malformed, duplicate, unsorted, missing, extra, stale, or unreviewed inventory
lines fail closed. Regenerate the TSV after rebasing with
`zig build write-digest-inventory`. Fixed 64-hex and SHA256 CAS layout
assumptions cannot authorize current content.

## Migration

1. Generate a backend-explicit `system-profile-v2`.
2. Generate and review a native exact-lock v3. Do not translate or resign v1/v2.
3. Run native preparation and execution with matching repository, package
   family, profile, Actions, and backend selection.
4. Retain old profiles, locks, results, and signatures unchanged where audit
   history requires them.
5. Recover every active legacy root before installing a native-only release.

The first-party download and install Actions retain their legacy default in
this release, but publish `backend-capability` as either
`legacy-dpkg-execution-deprecated-v1` or
`native-transaction-execution-v1`. Generated bundles are audited against their
TypeScript sources. This commit regenerates only the current checked-in bundle;
released tag, attestation, and bundle bytes remain immutable historical
artifacts. The cutover increment will remove the legacy input value and change
defaults; this increment deliberately does neither.

## Cutover deletion boundary

The policy inventory separates:

- production legacy command execution and backend selectors to delete;
- mixed orchestration surfaces that must lose legacy execution while retaining
  version-specific historical decoding;
- historical/reference code, including pinned dpkg oracle transport, that may
  remain read-only.

The security audit fails if an inventoried path disappears without policy
review, if a production selector is not classified, if the action bundles omit
capability evidence, or if the policy claims native-only readiness while
cutover blockers remain.

## Opt-in production candidate (#276)

Run `python3 tools/security-audit.py native-only-candidate` only when rehearsing
the **future** cutover. It must fail on this legacy-capable release. The output
names remaining deletion/default tasks by exact source path (#280–#285), not a
claim of #274 readiness. Ordinary `zig build security-audit` continues to
check the shipped legacy-capable policy and tests the candidate's expected
failure and negative mutations; it does not enable native-only defaults.

`security/native-only-production-policy.json` pins reviewed child-process
allowances and source/bundle fingerprints. The candidate scans *all* production
Zig sources and Setup/Download/Install Action TypeScript for direct and
indirect launches, including descriptor-based `execveat`. An unknown launch,
changed/missing allowance, unreadable source, missing inventory path, or stale
fingerprint is a failure, not a skip. The legacy command adapter and the
host-root dpkg architecture probe must disappear; native script execution and
root probes must remain exactly reviewed. The signed sudo post-install
`dpkg-query` input is pinned to that script's exact identity and tool binding,
**not** a general dpkg/dpkg-query basename exception. The exact pinned oracle
paths under `tools/` are reference-only and may not migrate into production.
Journals v1–v4 remain distinct read-only historical decode formats; active
legacy journal publication/replay is a separate cutover blocker.

The #279 CLI/root rehearsal is opt-in, not a changed release mode. The
candidate also pins `build.zig`'s shipped CLI mode, the exact
`src/cli_backend_policy.zig` selector, and the CLI/root operation wiring. The
native-only cutover must remove the legacy new-execution fallback without
removing completed historical verification or enabling the rehearsal as a
success-shaped substitute for changing the shipped default.

After integrating #274, update fingerprints and allowances only with a review
of the changed paths, run this candidate, both Actions' candidate contracts
and bundle reproducibility checks, and the production install/remove/reinstall/
downgrade/failure/recovery exec-trace gates before marking readiness. A
source-only candidate pass is not a runtime process trace or permission to
release.

# Legacy compatibility and native-only cutover policy

This release is **native-only** (`current_release_mode: "native_only"`,
`native_only_cutover_ready: true`). `native` is the shipped default across the
CLI, product, package-family, repository, apt/system, and GitHub Actions
surfaces. New `legacy_dpkg` execution is retired and refused before root or
cache mutation with versioned recovery guidance (`debz >=0.3.0,<0.4.0`), while
historical legacy locks, journals, profiles, and transaction results remain
verifiable read-only through their exact version-specific decoders without
reinterpreting old authority.

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
plus root-operation/product/repository pre-mutation refusal. In the current
`native_only` release line (`current_release_mode: "native_only"`), released CLI
commands, `ProductBackend`, `AptSystemBackend`, `PackageFamilyBackend`,
`RepositoryBackend`, `actions/download`, and `actions/install` all default to
`native_zig` (`native`). `legacy_dpkg` (`legacy`) is accepted only at the outer
parser boundary so it can be deterministically refused with `UnsupportedBackend`
(`LegacyCapabilityRequired`) and the versioned `debz >=0.3.0,<0.4.0` guidance
above before any network, lock, result, sidecar, or root mutation side effect.
Native v3 inputs remain backend/profile/capability-bound; completed legacy
results remain independently read-only through exact version-specific
verification. An active legacy root, including a pre-mutation or terminal
unacknowledged record, is not cleared to make room for a second mutation on
either product or repository surfaces.

Following the completed #280–#285 and #274 cutover work, `native_only` is now
the shipped production mode across all surfaces; the standalone rehearsal
target remains a focused regression gate for the CLI and root-operation
boundary.

## Digest compatibility inventory

The tracked repository digest policy is
[`security/digest-cutover-policy.json`](../security/digest-cutover-policy.json);
the merge-friendly per-file finding inventory is
[`security/digest-inventory-v1.tsv`](../security/digest-inventory-v1.tsv), and
the per-membership semantic allowlist inventory is
[`security/digest-semantic-allowlist-v1.tsv`](../security/digest-semantic-allowlist-v1.tsv).
Current package, repository-index, artifact, and package-CAS authority must use
`content_digest.Identity`, `Value`, or `Set`, or the equivalent versioned
algorithm-tagged wire form. SHA256-only fields and raw `[32]u8` widths remain
allowlisted only for frozen version-specific compatibility or unrelated
document, policy, signature, state, and transport controls. Each exception has
an exact path, a per-scope classification/rationale in the JSON policy, and a
sorted TSV inventory line with per-kind counts plus the SHA512 of that file's
canonical findings. Semantic allowlist membership remains only in the JSON
policy; the allowlist TSV stores one reviewed `(entry id, path)` count and
canonical SHA512 line, so changing findings in different member files merges
cleanly without automatically adding new membership. The audit derives
repository, scope, and semantic totals at run time;
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

### Post-Cutover Default (`native_only` Today)

- Released CLI commands, `actions/download`, and `actions/install` default
  `transaction-backend` to `native` (`native_zig`) and publish
  `backend-capability` as `native-transaction-execution-v1`.
- Explicit `legacy_dpkg` (`legacy`) requests are refused before any network,
  lock, or root mutation side effect (`UnsupportedBackend` /
  `LegacyCapabilityRequired`).
- When an older `legacy_dpkg` active-operation record or command-executor
  bridge witness is encountered on a target root, `native_only` surfaces refuse
  to abandon, clear, or relabel the record and direct the operator to finish or
  recover that operation with a pre-cutover `debz >=0.3.0,<0.4.0` release
  before mutating the root under `native_only`.
- Generated Action bundles are audited against their TypeScript sources, while
  completed historical artifacts and released tag, attestation, and bundle
  bytes remain immutable read-only historical evidence.

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

## Production native-only candidate (#276 / #274)

`zig-out/bin/debz-native-only-candidate native-only-candidate` (and
`zig-out/bin/debz-security-audit native-only-candidate`, which delegates to the
compiled `debz-native-only-candidate` binary) audits the completed native-only
cutover (#280–#285, #274) and must pass with zero findings (`security-audit:
native-only candidate passed`). Ordinary `zig build security-audit` enforces
the native-only cutover policy and tests exact negative mutations via
`tools/native-only-candidate.zig`.

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

The #279 CLI/root rehearsal target remains a separate test binary alongside the
shipped `native_only` CLI mode. The candidate pins `build.zig`'s shipped CLI
mode, the exact `src/cli_backend_policy.zig` selector, and the CLI/root
operation wiring, ensuring that the native-only cutover removes the legacy
new-execution fallback while preserving completed historical verification and
without treating the rehearsal binary as a substitute for the shipped default.

After integrating #274, update fingerprints and allowances only with a review
of the changed paths, run this candidate, both Actions' candidate contracts
and bundle reproducibility checks, and the production install/remove/reinstall/
downgrade/failure/recovery exec-trace gates before marking readiness. A
source-only candidate pass is not a runtime process trace or permission to
release.

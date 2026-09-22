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
  Newly written journal v3 records `legacy_dpkg` and the bounded
  `legacy-dpkg-execution-deprecated-v1` capability. All three versions remain
  legacy and can never authorize native work.
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

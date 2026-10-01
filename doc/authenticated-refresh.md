# Authenticated repository refresh

`repository_refresh.refresh` preserves the plain `Release` path and returns an
untrusted `Result`. It verifies every supported Release-to-index digest
(SHA256 and SHA512) but cannot be
passed to `SolverRepositoryInput.fromRefresh`.

`repository_refresh.refreshAuthenticated` returns `AuthenticatedResult` only
after all of these steps succeed:

1. acquire and strictly parse `InRelease`, or `Release` plus `Release.gpg`;
2. verify the exact canonical-text or detached signed bytes;
3. enforce verification-time policy and, when supplied, the accepted-primary-
   fingerprint allowlist;
4. validate Release identity, Date, Valid-Until, and selected index checksum;
5. boundedly decompress and parse Packages;
6. atomically publish the authenticated snapshot.

`AuthenticationPolicy` requires caller-supplied keyring bytes or explicit
paths, an optional accepted-primary-fingerprint allowlist, and a verification timestamp. An
empty allowlist trusts any valid signing key in the explicit keyrings, matching
the production CLI's `Signed-By` trust model; it never enables an ambient
keyring. The
default multiple-signature policy accepts at least one valid accepted signer
and preserves every per-signature result. `.all` rejects any invalid extra.
An optional `SignatureReporter` receives the complete borrowed result list for
both accepted and rejected verification attempts.

Freshness defaults to `require_valid_until`. A caller may instead explicitly
select `allow_missing_valid_until_with_max_age_seconds`, with a nonzero maximum
of 31 days. That exception is used only when the signed Release omits
`Valid-Until`: the verifier computes signed `Date + maximum age` with checked
arithmetic and rejects the Release after that inclusive boundary. A present
`Valid-Until` remains authoritative, including its existing grace handling,
regardless of the missing-expiry policy. Signed dates may be at most the
configured future skew (currently bounded to 24 hours); overflow and larger
policy values fail closed. The production callers currently use a five-minute
future bound. `repo add` selects the exception automatically only for exact
[reviewed freshness profiles](repository-management.md#reviewed-freshness-profiles).
Currently that is Microsoft's Ubuntu 24.04 feed, with a 14-day maximum.

`frozen_release_with_witnesses` admits a frozen release pocket (one whose
signed Release has no `Valid-Until`, such as Ubuntu `resolute`) without a
clock override and without replaying historical time. It never compares the
frozen pocket's own `Date` with the clock beyond the future-skew bound.
Instead:

1. The Release cleartext SHA-256 must equal the configured
   `release_sha256` (`ReleaseFrozenDigestMismatch`), and the Release must have
   no `Valid-Until` (`ReleaseFrozenValidUntilPresent`).
2. `RefreshPolicy.frozen_witnesses` must name one to four witnesses, built by
   `witnessEvidence` from authenticated results of the same refresh. An empty
   list, a witness that is itself frozen, or an expired witness is
   `ReleaseFrozenWitnessUnavailable`. `refreshAuthenticated` therefore never
   admits a frozen pocket alone, and unauthenticated `refresh` refuses the
   mode.
3. Each witness must have the same URI, component and architecture and a
   different suite (`ReleaseFrozenWitnessTargetMismatch`). At least one primary
   fingerprint must have a `valid` signature on both Releases
   (`ReleaseFrozenWitnessSignerMismatch`). `Origin` and `Label` must be equal
   (`ReleaseFrozenWitnessOriginMismatch`), and the witness's signed `Date` must
   not be older than the frozen pocket's (`ReleaseFrozenWitnessOlder`).
4. Every witness must still be fresh under its own policy at the same `now`:
   `Valid-Until` plus grace, or `Date` plus its maximum age. The admission
   deadline is the earliest witness deadline.

The decisions (pin, admission deadline, and each witness's repository ID,
snapshot digest, signed `Date`, deadline and shared fingerprint) are recorded
in `PolicyDecisions.frozen`. Frozen snapshots use repository snapshot v5 in
the separate `repository-refresh-v5` cache namespace; every other repository
keeps v4 bytes and namespace. A cache-only reload reuses a frozen admission
only with the same witness repository IDs and snapshot digests
(`ReleaseFrozenWitnessChanged` otherwise), revalidates the stored decision, and
re-admits through the witnesses at the current time.

Provenance records the authentication mode, signature digest, verification
time, accepted signature index, primary/signing fingerprints, public-key and
hash algorithm identifiers, and signature creation/expiration. Cache snapshots
bind that evidence, the signed Release digest, signed Date, original freshness
verification time and observed age, configured expiry policy and maximum age,
`Valid-Until` grace, whether the missing-`Valid-Until` exception was exercised,
future-skew policy, and index objects. Cache-only loading rechecks object
integrity, reruns authentication, rejects any changed freshness policy,
revalidates the original decision, and evaluates the signed metadata at the
current time. Changed policy evidence, historically invalid decisions, stale
metadata, or incompatible evidence fails closed. Repository snapshot v4 stores
the algorithm-tagged index digest set and explicit primary selection in
canonical SHA256-then-SHA512 order. It uses a new cache namespace, so older
snapshots are never reinterpreted as tagged identities.

The supported algorithms are exactly those documented in
[`openpgp-verifier.md`](openpgp-verifier.md): OpenPGP v4 RSA (algorithms 1 and
3) and legacy Ed25519 (22), with SHA-256 or SHA-512.

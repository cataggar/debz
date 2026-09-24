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
future bound.

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

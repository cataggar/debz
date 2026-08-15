# Authenticated repository refresh

`repository_refresh.refresh` preserves the plain `Release` path and returns an
untrusted `Result`. It verifies Release-to-index SHA-256 integrity but cannot be
passed to `SolverRepositoryInput.fromRefresh`.

`repository_refresh.refreshAuthenticated` returns `AuthenticatedResult` only
after all of these steps succeed:

1. acquire and strictly parse `InRelease`, or `Release` plus `Release.gpg`;
2. verify the exact canonical-text or detached signed bytes;
3. enforce explicit accepted-primary-fingerprint and verification-time policy;
4. validate Release identity, Date, Valid-Until, and selected index checksum;
5. boundedly decompress and parse Packages;
6. atomically publish the authenticated snapshot.

`AuthenticationPolicy` requires caller-supplied keyring bytes or explicit
paths, accepted primary fingerprints, and a verification timestamp. The
default multiple-signature policy accepts at least one valid accepted signer
and preserves every per-signature result. `.all` rejects any invalid extra.
An optional `SignatureReporter` receives the complete borrowed result list for
both accepted and rejected verification attempts.

Provenance records the authentication mode, signature digest, verification
time, accepted signature index, primary/signing fingerprints, public-key and
hash algorithm identifiers, and signature creation/expiration. Cache snapshots
bind that evidence, the signed Release digest, policy decisions, and index
objects. Cache-only loading rechecks object integrity and reruns authentication
with the current caller policy; missing or incompatible evidence fails closed.

The supported algorithms are exactly those documented in
[`openpgp-verifier.md`](openpgp-verifier.md): OpenPGP v4 RSA (algorithms 1 and
3) and legacy Ed25519 (22), with SHA-256 or SHA-512.

# Authenticated repository refresh

`repository_refresh.refresh` preserves the plain `Release` path and returns an
untrusted `Result`. It verifies Release-to-index SHA-256 integrity but cannot be
passed to `SolverRepositoryInput.fromRefresh`.

`repository_refresh.refreshAuthenticated` returns `AuthenticatedResult` only
after all of these steps succeed:

1. acquire and strictly parse `InRelease`, or `Release` plus `Release.gpg`;
2. verify the exact canonical-text or detached signed bytes;
3. enforce verification-time policy and, when supplied, the accepted-primary-
   fingerprint allowlist;
4. validate Release identity, Date, expiry policy, and selected index checksum;
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

Provenance records the authentication mode, signature digest, verification
time, accepted signature index, primary/signing fingerprints, public-key and
hash algorithm identifiers, and signature creation/expiration. Cache snapshots
bind that evidence, the signed Release digest, policy decisions, and index
objects. Cache-only loading rechecks object integrity and reruns authentication
with the current caller policy; missing or incompatible evidence fails closed.

Moving repositories require `Valid-Until` by default. The only missing-expiry
exception is
`allow_missing_valid_until_with_max_age_seconds`, which must be nonzero and no
greater than 31 days. A signed `Date` remains mandatory, the existing future
date bound remains enforced, and acceptance requires
`verification_clock <= signed Date + configured bound`. If `Valid-Until` is
present it remains authoritative. Snapshot v3 records and replay-validates the
selected policy, configured maximum age, signed date, verification time,
observed age, and whether the exception was exercised.

Gzip decoding uses a bounded retained DEFLATE window so valid long-distance
matches, including Microsoft's single-member `Packages.gz` with original
filename `Packages`, work across output chunks. Header variants, CRC32, ISIZE,
truncation, trailing bytes, concatenated members, and all input/output/memory
limits remain fail-closed.

The supported algorithms are exactly those documented in
[`openpgp-verifier.md`](openpgp-verifier.md): OpenPGP v4 RSA (algorithms 1 and
3) and legacy Ed25519 (22), with SHA-256 or SHA-512.

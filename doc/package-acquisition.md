# Verified package acquisition

`debz.package_acquisition` owns package download and SHA-256 CAS publication.
It does not parse package payloads, execute transactions, invoke `dpkg`, or
infer trust from archive names or paths.

## Trust and ownership

`SelectedPackage.fromSolverSelection` accepts the `selected_origin` attached
to an archive-producing `SolverPlanAction` and its matching
`SolverRepositoryInput` only when the repository came from an authenticated
refresh. It rejects stale indices, changed identities,
repository/priority conflicts, and credential-bearing base URIs. The separate
`fromTrustedTest` constructor is only for hermetic tests.

`acquirePackage` returns an owned `VerifiedPackage`; call `deinit`. Its
provenance borrows package identity strings from the selected Packages index,
so that index must outlive the handle. Package bytes and the redacted resolved
URI are owned by the handle.

## Acquisition policy

Every request explicitly supplies:

- online or cache-only mode and transaction or download-only workflow;
- maximum package bytes;
- connect, read, and overall deadlines;
- redirect and retry bounds;
- direct or explicit proxy configuration;
- a scoped credential provider;
- cache-integrity, corrupt-cache, and locking policy.

No ambient proxy, credential, APT, or cache configuration is consulted.
Repository acquisition retries only connection/reset/timeout/temporary DNS and
read/write transport failures, plus explicitly enabled HTTP 408, 429, and 5xx
statuses. Backoff is caller supplied. Redirects are bounded, cannot change to
unsupported schemes, and credentials are sent only to the original origin.
TLS certificate and hostname verification is performed by Zig's HTTPS client.

## Verification and cache

The declared size and SHA-256 from the authenticated Packages record are
checked before publication. The streaming transport is limited to at most one
byte beyond the declared size, subject to the lower configured package limit.
MD5, SHA-1, filenames, URLs, and pre-existing object paths never establish
trust.

Verified objects use `packages-v1/objects/<lowercase-sha256>`. Publication
writes and syncs private same-filesystem staging, then renames and syncs the
object directory while holding the cache writer lock. Cache hits are reopened,
size checked, and SHA-256 revalidated. Corruption fails closed unless online
repair is explicitly enabled. Cache-only mode performs no acquisition call.
Failed verification and interrupted publication remove staging data.

Handles own their bytes, so garbage collection cannot invalidate active
readers. Writers, repair, staging cleanup, and GC share the explicit cache
lock. `garbageCollect` accepts retained digests and hard directory, scan,
object, and byte limits; names are sorted before deletion for deterministic
results. `cleanupStaging` provides bounded crash recovery.

Errors never contain authorization values. Effective URLs omit user info,
fragments, and query values; cache keys and provenance contain only the
authenticated repository identity and expected SHA-256.

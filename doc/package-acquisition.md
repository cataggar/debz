# Verified package acquisition

`debz.package_acquisition` owns package download and SHA-256 CAS publication.
It does not parse package payloads, execute transactions, invoke `dpkg`, or
infer trust from archive names or paths.

`debz.package_cache_workflow` composes that primitive for a canonical exact
lock. `debz package-cache fingerprint` validates exact-lock v1, architecture,
solver policy, package/count/byte limits, and the running CLI version before
printing a versioned fingerprint, exact cache key, compatible restore prefix,
and the sole externally cacheable path. Filesystem paths, URLs, keyring names,
proxy settings, and credentials do not enter key material.

`debz package-cache prepare` authenticates current repository evidence, requires
the repository ID/snapshot/Release/Packages/signer and every package
name/version/architecture/size/SHA-256 to match the lock, then acquires and
payload-validates the complete closure. It counts current-lock objects as
downloaded or reused, cleans staging, and garbage-collects objects outside the
lock under one bounded writer lock. Incomplete cleanup or lock contention is a
failure. Digest-indexed matching scans authenticated `Packages` records once
and rejects an explicitly bounded record count instead of performing
lock-by-index quadratic work.

Immediately after acquiring the writer lock, preparation performs bounded
staging cleanup before importing a restored opaque archive. It then preflights
every present current-lock object against the lock's size and SHA-256 before
repository I/O. Missing online objects proceed to authenticated acquisition;
missing offline objects and default-policy corruption fail immediately. A
caller-declared exact restore also treats a missing current-lock object as
corruption; partial/miss restores may download it. Payload identity is checked
after the authenticated package record is matched. Successful publication
removes its own staging file, so the workflow does not repeat the initial scan.

## Trust and ownership

`SelectedPackage.fromSolverSelection` accepts the `selected_origin` attached
to an archive-producing `SolverPlanAction` and its matching
`SolverRepositoryInput` only when the repository came from an authenticated
refresh. It rejects stale indices, changed identities,
repository/priority conflicts, and credential-bearing base URIs. The separate
`fromTrustedTest` constructor is only for hermetic tests.

`acquirePackage` returns an owned `VerifiedPackage`; call `deinit`. Package
bytes, package identity strings, and the redacted resolved URI are owned by the
handle, so the selected Packages index need only remain alive for the call.

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
unsupported schemes, cannot downgrade HTTPS or embed credentials, and
credentials are sent only to the original origin. TLS certificate and hostname
verification is performed by Zig's HTTPS client.

The package-cache workflow adds an explicit online-only corruption repair
policy. Without it, a wrong-size, wrong-digest, symlinked, truncated, or
non-regular object fails closed. With repair enabled, the object is deleted and
reacquired only after repository authentication, then size-, SHA-256-, and
payload-validated before publication. Offline mode and repair are mutually
exclusive.

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

Repository refresh in cache-only mode is also read-only: authenticated cached
objects and manifests are verified and returned in memory but are not
republished. An explicitly elevated transaction therefore cannot replace
metadata prepared by an unprivileged Actions process with root-owned files,
and a later warm-cache verification remains usable.

Handles own their bytes, so garbage collection cannot invalidate active
readers. Writers, repair, staging cleanup, and GC share the explicit cache
lock. `garbageCollect` accepts retained digests and hard directory, scan,
object, and byte limits; names are sorted before deletion for deterministic
results. `cleanupStaging` provides bounded crash recovery.

External caches contain one opaque, path-free archive exported from the
verified current-lock objects. The cache service writes that blob only into a
fresh private transfer directory; `debz.package_cache_archive` validates its
framing, canonical digest ordering, object and expanded-byte limits, payload
digests, and current-lock sizes before publishing lowercase-SHA256 objects
under the CAS writer lock. It never interprets tar paths, links, devices, or
special entries. `metadata-v1`, `staging`, `locks`, exact locks, keyrings,
credentials, installation roots, dpkg state, and transaction/recovery records
are outside this boundary.

The opaque v1 stream is `debz-package-cache-archive-v1\n`, a big-endian object
count, then strictly digest-sorted records of 32 raw SHA-256 bytes, an unsigned
64-bit size, and exactly that many package bytes. A final SHA-256 covers all
preceding bytes, and trailing data is rejected. The format intentionally has
no pathname, ownership, mode, link, or special-file fields.

Errors never contain authorization values. Effective URLs omit user info,
fragments, and all query data; cache keys and provenance contain only the
authenticated repository identity and expected SHA-256.

## Local artifacts

`debz.local_artifact.acquire` is a separate initial-trust boundary for
standalone artifacts such as repository-configuration packages. Unpinned
requests require HTTPS. An explicit SHA-256 pin permits HTTPS, HTTP, or a local
`file:` URI; an optional size is also enforced. Successful bytes are hashed as
one complete artifact, published through the same package CAS, and returned
with redacted acquisition provenance and an explicit HTTPS-or-SHA-256 trust
mode. This layer does not treat the artifact as authenticated repository
metadata and does not verify embedded debsigs signatures.

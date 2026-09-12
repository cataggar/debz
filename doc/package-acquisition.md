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

### Native archive contract

The lower-level archive API additionally provides `importNativeFile`,
`exportNativeFile`, and `maximumNativeArchiveBytes` for typed exact-lock v2
closures. These use `debz-package-cache-archive-v2\n` with the same sorted
digest/size records and final checksum. Unlike v1, v2 permits a canonical
zero-object stream for an empty closure. Existing `importFile`, `exportFile`,
and `maximumArchiveBytes` retain their v1 behavior, including rejecting empty
streams; neither reader auto-detects or accepts the other version.

The v2 transport binds object digests and sizes directly from the genuine v2
lock without converting it to v1 or inventing repository origins. Repository
and local-artifact origin evidence stays in the caller's authenticated lock,
not the path-free archive. Transport does not grant origin authority or
validate package installation policy.

Both formats validate the complete envelope and every object before any
matching object is published under the CAS writer lock. Exact restores require
the entire lock closure, including an actually empty archive for an empty
native lock. Partial restores publish only matching objects; unrelated objects
are verified but skipped. Imported objects are reread and rehashed before
publication, and the existing CAS layout remains unchanged.

`package-cache fingerprint` and `package-cache prepare` select these native
contracts only with explicit `--transaction-backend native`; the default
remains `legacy_dpkg` and v1. Native fingerprints/results use separate v2
schemas, fingerprint domains, and restore-key prefixes. Empty closures need
no repository inputs and produce zero verified objects.

Native preparation authenticates repository evidence and validates each
repository payload normally. Local-artifact entries must already be in the
verified CAS or imported archive and pass `deb_payload.inspectLocal` against
the lock's exact identity, size, and digest. Missing local artifacts require
separate explicit acquisition; corrupt local artifacts refuse even under
online repair. Preparation never fetches a lock's redacted provenance URL.
The core native solver-policy domain remains required. The download action
supports explicit native selection with these v2 contracts; other consumer
policy scopes and native install-action integration are separate work.

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

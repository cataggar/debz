# Exact closure locks and transaction provenance

`debz.exact_lock` defines schema version 1 for a complete solved closure. A
package identity includes exact Debian version spelling, architecture,
authenticated repository/snapshot identity, package SHA-256, and declared
size. Entries are sorted by package, architecture, version, and repository.
The document digest covers canonical JSON without its final digest member.

`debz.exact_lock_v2` adds a tagged package origin. Authenticated repository
origins retain repository and snapshot identity. Verified local-artifact
origins instead record an artifact ID, complete archive SHA-256, size, package
identity, redacted acquisition URL, and `pinned_sha256` or `verified_https`
trust mode. Local artifacts never receive fabricated Release, index, signer,
or repository snapshot evidence. V2 creation and replay reject unused or
duplicate evidence and every origin, digest, size, identity, URL, or trust-mode
substitution. Local packages are reinstalled during replay even when dpkg
already reports the locked name, version, and architecture, because dpkg status
does not authoritatively retain archive origin. Final verification additionally
requires the completed journal's local archive digest and the plan's exact
origin, digest, and size evidence. V1 decoding and replay remain unchanged.

Exact-lock v2 keeps its complete-closure meaning by default. The transaction
executor also exposes a separately policy-digested `locked_packages` mode for
repository-add operations whose lock intentionally contains only non-remove
mutation actions. That mode requires every locked package at exact identity and
requires exact plan origin/digest/size plus completed unpack digest evidence,
but does not reject unrelated healthy installed packages. Repository-add binds
the mode in its validated lock policy digest, executor journal policy digest,
and transaction provenance; product full-closure verification is not relaxed.

`dpkg_selection_hold` records dpkg selection intent. It is not an exact-lock
constraint. `SolverPlanInput.exact_lock` separately constrains the complete
final closure. Planning fails if a repository snapshot, version, architecture,
size, digest, or closure member differs. Package acquisition and execution can
receive the corresponding locked package or lock and fail before mutation on
different evidence.

Locks can only be created with the authenticated-metadata trust assertion;
normal production inputs should be built from
`repository_refresh.AuthenticatedResult` and its `snapshotDigest`. Decoding
rejects unknown schema versions, digest tampering, non-canonical JSON,
duplicates, missing repositories, unsafe paths, symlinks, and oversized
documents. V2 validation has explicit repository, artifact, package, signer,
and total-work limits; sorted indexed matching and reference accounting avoid
quadratic artifact/package validation. `ExactClosureLockStore` publishes with
write/fsync/rename/fsync.
The production CLI permits initial lock resolution only on non-mutating
`plan` and `download` operations. The package-family API exposes that path as
`resolve_lock`; all image mutations continue to require the reviewed lock.

`debz.transaction_provenance` defines transaction-result schema version 1. It
binds request and policy digests, architecture, source configuration IDs,
Release/signature/metadata/snapshot evidence and signer fingerprints, plan and
lock digests, package CAS identities, redacted dpkg argv/environment,
journal/recovery boundaries, outcome, and final exact-state/origin evidence.
A successful result requires `exact_match` final verification.
`createTransactionProvenanceFromExecution` and
`createTransactionProvenanceFromRecovery` copy the executor's observed argv,
audited environment, command/artifact digests, policy binding, and lock binding
into the result.

`debz.transaction_provenance_v2` carries the same tagged package origins and
verifies them against an exact-closure-lock v2. Repository evidence is emitted
only for authenticated repository packages; local artifacts carry only their
artifact and acquisition evidence. Execution and recovery provenance reject
target-architecture, request-digest, or solver-policy-digest values that differ
from the exact lock, then serialize those fields from the lock. A successful
result additionally requires non-null installed-state evidence and a
package-origin digest exactly equal to the bound lock digest. Package,
repository, and signer verification is count-bounded and uses sorted/indexed
matching rather than nested scans.

The simple system install creates an exact-lock v2 before dpkg and uses the
policy-digested `locked_packages` verification scope because the lock contains
the complete mutation closure rather than unrelated packages already present
on the system. Acquisition receives the same locked package evidence. The lock
is retained at `INSTALL_ROOT/var/lib/debz/locks/<digest>.json`, copied into the
unique `STATE/transactions/<attempt-id>/` evidence directory, and never
replaced on a digest collision without canonical equality.

Every system mutation also publishes
[`system-operation-lock-v2`](../schema/system-operation-lock-v2.json). This
lock binds the complete action list (including removals), canonical persisted
plan digest, request digest, solver policy, executor policy, and optional v1/v2
package-lock digest. It also binds the canonical install/state roots, unique
attempt identifier, and repository freshness evidence needed to reconstruct
recovery provenance without refreshing. Remove-only operations therefore
retain an authorized zero-archive mutation closure without weakening
exact-lock v1/v2's nonempty package invariants. Mixed install/remove operations
enforce both the complete plan and the archive package lock.

`transaction-result-v3` embeds the complete v2 execution result and adds, for
each repository used by the lock, the signed Release date, optional
`Valid-Until`, verification time, maximum accepted future skew, whether that
skew was exercised, observed age, exact bounded missing-expiry policy, whether
that exception was exercised, selected Packages path, and compression.
System results also bind the unique attempt identifier. Failure provenance is
retained after dpkg has begun; successful recovery atomically replaces it with
a success result before clearing the active intent. Creation and validation enforce required-expiry presence,
noninverted signed intervals, bounded observed age for a missing-expiry
exception, checked future-date bounds, exception consistency,
repository/snapshot correspondence with the embedded execution result,
bounded repository counts, linear sorted-list comparison, and canonical
reserialization.

Credentials in URI user-info, common token/query/header assignments, proxy
variables, and auth paths are redacted before serialization. Persisted
provenance can be bounded and digest-validated with
`TransactionProvenanceStore`. CLI flags are intentionally outside this API
change and remain tracked by issue #23.

Schemas:

- [`schema/exact-closure-lock-v1.json`](../schema/exact-closure-lock-v1.json)
- [`schema/exact-closure-lock-v2.json`](../schema/exact-closure-lock-v2.json)
- [`schema/system-operation-lock-v2.json`](../schema/system-operation-lock-v2.json)
- [`schema/transaction-result-v1.json`](../schema/transaction-result-v1.json)
- [`schema/transaction-result-v2.json`](../schema/transaction-result-v2.json)
- [`schema/transaction-result-v3.json`](../schema/transaction-result-v3.json)

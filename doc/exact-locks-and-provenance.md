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
substitution. V1 decoding and replay remain unchanged.

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
documents. `ExactClosureLockStore` publishes with write/fsync/rename/fsync.
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
artifact and acquisition evidence.

Credentials in URI user-info, common token/query/header assignments, proxy
variables, and auth paths are redacted before serialization. Persisted
provenance can be bounded and digest-validated with
`TransactionProvenanceStore`. CLI flags are intentionally outside this API
change and remain tracked by issue #23.

Schemas:

- [`schema/exact-closure-lock-v1.json`](../schema/exact-closure-lock-v1.json)
- [`schema/exact-closure-lock-v2.json`](../schema/exact-closure-lock-v2.json)
- [`schema/transaction-result-v1.json`](../schema/transaction-result-v1.json)
- [`schema/transaction-result-v2.json`](../schema/transaction-result-v2.json)

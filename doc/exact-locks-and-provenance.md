# Exact closure locks and transaction provenance

`debz.exact_lock` defines schema version 1 for a complete solved closure. A
package identity includes exact Debian version spelling, architecture,
authenticated repository/snapshot identity, package SHA-256, and declared
size. Entries are sorted by package, architecture, version, and repository.
The document digest covers canonical JSON without its final digest member.
V1 is permanently `legacy_dpkg` authority; it is never inferred or translated
as native. Newly generated v1 locks receive a separate capability sidecar that
binds the exact canonical lock bytes without changing their digest or any
historical signature. Current product/package-cache native locks are v3.
Repository operations use v3 for both backends, with backend authority
supplied by the separately authenticated request and policy digests; missing
or mismatched backend context is refused. See
[Legacy compatibility](legacy-compatibility.md).

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

V2 also permits an empty installed-package closure, including removal or purge
of the last installed package. Its repository and local-artifact arrays must
then be empty: the usual unused-evidence rejection still applies. The target
architecture, request and policy digests, canonical encoding, and digest
verification remain mandatory. Existing nonempty locks keep identical bytes
and hashes; older releases reject the newly supported empty v2 locks.

An empty lock does not authorize deleting an installed database. Native
preparation still requires explicit remove/purge actions for every installed
package omitted from the closure, and rejects a missing install artifact or
an unauthorized retained package. A removal can leave residual configuration;
that `config-files` state belongs in the separate native final-state authority,
not the lock's installed-package closure. Purge must remove the residual state.
V1 creation, decoding, and schema are unchanged.

`debz.exact_lock_v3` versions repository and package content identity without
changing any v1/v2 bytes. Repository indexes and package archives carry an
explicit primary algorithm plus the complete supported digest set. Supported
algorithms are exactly lowercase `sha256` and `sha512`; encodings have exact
lengths and canonical order is SHA256 then SHA512. If both are published, both
are retained and verified. SHA512-only repository packages remain valid
without a fabricated SHA256. Unknown algorithms, duplicate/conflicting
entries, a missing primary, wrong case/length, and digest-set substitution are
rejected. Transaction-plan schema v4 serializes the same tagged archive
identity. Local origins bind a typed artifact ID plus the complete archive and
pinned content identities; v2/v3 plan serialization remains byte-for-byte
unchanged.

**Signed SHA256 with a derived SHA512.** Some signed archives, including
Debian stable, publish only SHA256 in both
Release and Packages. For those repositories debz accepts the signed SHA256
entries (plus declared size) as the authenticated archive binding. It records
a SHA512 only as a *derived* identity, bound to the verified SHA256, never as
an independently authenticated one (issue #261). A repository opts in
explicitly and additively:

```json
{"id":"…","index_identity":{…},"archive_binding":"signed_sha256_derived_sha512","signer_fingerprints":[…]}
{"name":"…","archive_identity":{"primary":"sha256","digests":[{"algorithm":"sha256","digest":"…"}]},
 "derived_archive_identity":{"provenance":"derived_from_signed_sha256","algorithm":"sha512","digest":"…"},…}
```

- `archive_identity` still holds exactly the signed digests. The derived value
  lives only in `derived_archive_identity`, with the fixed provenance
  `derived_from_signed_sha256`. Package CAS stays keyed by the signed SHA256
  and never by the derived value.
- Every package of a bound repository must be SHA256-only and must carry the
  derived identity. The following are rejected: a derived identity without the
  repository binding, a missing derived identity, a signed SHA512 in a bound
  repository, local-artifact derived identities, other provenance or binding
  strings, `null` values, and a derived value that duplicates another archive's
  SHA512. So is promoting the derived value into `archive_identity` as a signed
  SHA512 while the repository is bound.
- `bindSignedSha256Repositories` produces bound locks. It checks every
  archive's size and signed SHA256 *before* computing any SHA512; a mismatch
  refuses and derives nothing. Acquisition, cache hits, tagged CAS import, and
  native unpack verify size, then every signed digest, then the derived
  SHA512. A derived mismatch refuses (`DerivedDigestMismatch`) and is never
  published to or repaired in CAS.
- `Lock.archiveAuthentication` reports each package's authority
  (`signed_sha512`, `signed_sha256_derived_sha512`, `signed_sha256_only`, or a
  local variant). `Lock.requireArchiveDigestPolicy(.sha512_identity_required)`
  governs repository archives. It accepts a signed SHA512 or the explicit
  binding, and refuses an unbound signed-SHA256-only repository archive.
  Local artifacts keep the caller-pinned digest set they were admitted with,
  such as a repository-add descriptor pinned by SHA256. Their exact class
  stays visible as `local_artifact_sha256_only` or `local_artifact_sha512`.

Locks that do not opt in, including every Ubuntu signed-SHA512 lock, keep
identical bytes, digests, and meaning. Older decoders reject bound locks as
unknown fields, so a derived SHA512 can never be read as signed.

**Opting in and native enforcement.** The opt-in is a per-repository setting;
there is no CLI flag. It can be given in the `--config` JSON source entry:

```json
{"source_path":"/etc/apt/sources.list.d/debian.sources","archive_binding":"signed_sha256_derived_sha512"}
```

or declared on the source itself, as a DEB822 field or a one-line option:

```text
X-Debz-Archive-Binding: signed_sha256_derived_sha512
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg debz-archive-binding=signed_sha256_derived_sha512] https://deb.debian.org/debian trixie main
```

- `archive_binding` defaults to `published_digests`. Any other token refuses
  the configuration (`configuration_required`). A source declaration accepts
  exactly `published_digests` or `signed_sha256_derived_sha512`; anything else
  is a malformed source (`invalid_archive_binding`), and a repeated one-line
  option is a duplicate option. A declaration that contradicts a non-default
  `--config` setting for the same source refuses the configuration. APT
  ignores both spellings, so the same files stay valid APT sources.
- The binding is repository identity input. Only an opted-in repository adds
  it to the repository ID and to canonical sources
  (`# X-Debz-Archive-Binding: …`), so existing IDs, configuration identities,
  and locks stay byte-identical. The same source declared with and without the
  opt-in is a conflicting repository.
- Because the declaration travels with the source bytes, target-APT
  configuration import (`target-apt-config import`) and repository-add
  descriptors (`.list` or `.sources` payloads) carry it unchanged into the
  managed sources and repository IDs. The target-APT manifest format does not
  change.
- Native lock production (`plan`/`download --lock-output`, package-family
  `resolve_lock`, and native repository-add operation locks) acquires each
  opted-in repository's locked archives through the package cache. With `--offline`/`--cache-only` it reads only the cache.
  Every archive must match its declared size and signed SHA256 before any
  SHA512 is derived. The lock is written only after the bound lock passes
  admission. A tampered or substituted archive refuses with `download_failed`
  and writes no lock.
- Native engine consumers enforce `sha512_identity_required` by default. This
  covers product native lock input and output, native preparation
  (`Runtime.prepare`), the package-family `NativeBackend`, and native locks in
  package-cache workflows. The following are refused:
  - an unbound SHA256-only native lock: `lock_verification_failed` on input,
    `planning_failed` on output, with no lock written;
  - a lock whose repository `archive_binding` differs from the configured one,
    which covers a derived SHA512 relabelled as signed (`lock_verification_failed`);
  - a derived SHA512 that does not match the verified bytes
    (`download_failed`, `DerivedDigestMismatch`).

  The policy governs repository archives. Caller-pinned local artifacts, such
  as a repository-add descriptor pinned by SHA256, stay admissible. Local
  artifacts carry distinct `local_artifact` provenance (artifact ID,
  acquisition URL, trust mode) that only resolves against caller-supplied,
  verified local artifact input. A repository archive relabelled as a local
  artifact therefore refuses: product planning reports `planning_failed`
  ("locked local artifact is unavailable"), and native repository-add
  preparation refuses the plan/lock origin mismatch
  (`AuthorizationArtifactMismatch`). Embedders can relax the default only
  explicitly, through `Backend.native_archive_digest_policy`,
  `NativeBackend.archive_digest_policy`,
  `Runtime.PrepareRequest.archive_digest_policy`,
  `native_transaction_result` `ExpectedCaller`/`OwnedRequest`
  `archive_digest_policy`, or the repository-add
  `NativePreparationRequest`/`NativeCachePreparationRequest` field.
- The policy is re-checked wherever a native exact-lock v3 is consumed after
  planning, so a lock whose binding is stripped or altered after planning
  refuses before any evidence is read:
  - `native_transaction_result` verification of v3 results (`verify`,
    `verifyForCaller`, pending/owned routes, and repository history);
  - the APT/system orchestrator's lock re-reads before download, execution,
    recovery, and acknowledgement (`OperationalVerificationFailure`);
  - native preparation.

  Persisted-only native recovery consumes no lock. It is bound to the admitted
  lock digest through the authorization's exact-lock binding, so a changed
  lock cannot be substituted there either.
- Legacy consumers are unchanged. The legacy backend ignores the binding and
  writes ordinary v1 locks with no binding or derived fields. The only effect
  of opting in is the repository ID change.
- Native repository-add refuses a dependency from a signed-SHA256-only
  repository unless that target repository opts in.

Native execution carries that identity without truncation through explicit
successor documents: authorization v2, program v2, execution request v4,
recovery intent v2, progress v3/v4, transaction result v3, native provenance
v2, and root completion v2. Each successor binds the exact schemas and
versions it consumed. Legacy authorization/program/provenance/completion v1,
request v1-v3, intent v1, progress v1/v2, and transaction-result v1/v2 bytes
and canonical hashes remain readable and unchanged.

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

Authenticated snapshot digest version 3 additionally binds the configured
freshness policy and maximum missing-expiry age, signed Release date,
`Valid-Until` grace, bounded future-skew decision, and whether the
missing-`Valid-Until` exception was exercised, plus the complete
algorithm-tagged index digest set and explicit primary selection. Observation
time and observed
age remain validated cache evidence but are excluded from lock identity, so
independent authenticated refreshes of the same still-valid signed snapshot
under the same policy produce the same digest. Repository and configuration
identities also bind that configured policy. Exact-lock v1/v2
and transaction-result v1/v2 schemas continue to carry the opaque repository
snapshot digest, so their existing evidence path transitively binds the new
freshness facts without a transaction-result v3. Previously serialized locks
remain decodable, but a repository-backed lock carrying the old snapshot
digest fails replay against a newly computed digest and requires reviewed
regeneration; it never silently acquires the exception. Transaction
provenance retains the same fail-closed snapshot comparison.
Authenticated snapshot digest version 4 is used only for
`frozen_release_with_witnesses` repositories. It hashes the version 3 inputs
plus the pinned Release SHA-256, the admission deadline, and each witness's
repository ID, snapshot digest, signed `Date`, deadline and shared signer
fingerprint. A lock therefore binds a frozen pocket's witnesses through
`Repository.snapshot_sha256`, even when a witness contributes no locked
package. Every non-frozen snapshot keeps its version 3 digest, so existing
locks are unchanged; exact-lock v3 does not change.
The production CLI permits initial lock resolution only on non-mutating
`plan` and `download` operations. The package-family API exposes that path as
`resolve_lock`; all image mutations continue to require the reviewed lock.

The core CLI selects genuine v3 planning and download with
`--transaction-backend native`; embedders set
`ProductionBackend.transaction_backend = .native`. Native resolution builds
the tagged closure directly from authenticated repository snapshots, while
native replay refuses v1 input. Its solver-policy digest is SHA-256 of
`debz.product-native-solver-policy-v1\0` followed by the existing 32-byte solver
policy digest. Legacy core resolution/replay keeps its original v1 format and
policy bytes. Core native mutation consumes an explicit reviewed v3 lock and
publishes a native receipt rather than legacy command provenance. Core recovery
consumes persisted inputs without re-resolution or replacement locks, binds outer
completion to that receipt, and acknowledges native evidence before clearing the
caller record. Other consumers remain independently gated.

The separate `debz package-cache` interface supports canonical v1, v2, and v3
locks through explicit version-specific paths.
`fingerprint` rejects unsupported schema versions, noncanonical/tampered
documents, target or solver-policy drift, duplicate object digests, and
resource-limit violations before cache restore. `prepare` reauthenticates all
repository evidence and verifies the complete lock closure independent of
installed state. Exact-lock v3 carries SHA512-only and mixed package identities
through tagged CAS and archive v3; every supported digest is verified before
publication or replay.

The package-cache fingerprint is domain-separated and covers the lock digest,
schema, target and foreign architectures, exact runtime version, package-CAS
layout, opaque cache-archive format, corruption mode, package size/total
bounds, origin mode, and payload validation policy version. Its compatible
restore prefix omits only the exact lock digest. Prefix-restored objects remain
untrusted until complete revalidation. The action reports whether the service
matched the exact key or only the prefix; an exact restore missing any
current-lock object is corruption unless explicit online repair is selected.
The fingerprint result also supplies the CLI-derived maximum opaque archive
size used to bound cache-service downloads before import.

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

`debz.native_authorization` defines the complete contract the native engine
must hold before it mutates a root. Historical schema v1 retains SHA256 package
evidence. Current schema v2 binds exact-lock v3 and the complete canonical
content identity for every archive-producing action without changing v1
bytes. Both versions bind the selected backend, lock generation and digest,
request, solver-policy, executor-policy and plan digests, selected install root
and derived root identity, target and foreign architectures, conffile and force
policy, ordered lifecycle actions, authenticated origins, sizes, and the exact
intended final closure.

For removal, that closure may contain a residual `config-files` record or
omit the package when no residual conffiles or `postrm` remain. The program
compiler checks the authorized choice against installed evidence; authorizing
absence does not permit it to discard conffiles that removal must retain.

Authorization is native-only. Creating one for `legacy_dpkg` is rejected, and
new authorization binds exact-closure-lock v3, so previously serialized v1/v2 locks stay
readable for the legacy backend and can never be silently reinterpreted as
native authorization. `transaction_engine.authorize` requires an authorization
for native execution, rejects an authorization supplied to the legacy backend,
and re-verifies the lock, request, solver-policy, architecture, root, plan,
executor-policy, action, artifact, and origin bindings against the request the
executor would actually run; `executeAuthorized` performs that check before
backend selection, so an unauthorized native transaction never reaches an
executor.

Actions are canonically ordered by a dense sequence, unique per package
identity, and semantically validated: version transitions must match the action
kind, archive evidence is required exactly for archive-producing actions and
must equal the lock's origin and size for that package, and the final closure
must list every retained package once with a non-contradictory state. Purged
packages must be absent from the final closure. Documents are canonically
serialized, digest-bound over payload and final state, parsed with bounded
strict JSON that rejects unknown fields and non-canonical bytes, and can be
persisted through the no-follow `NativeTransactionAuthorizationStore`.

`debz.native_program` compiles one authorization, the reviewed ordered
lifecycle, the consumed installed-database generation, and the validated
archives into the deterministic low-level transaction the engine executes and
recovery replays or refuses. Historical schema v1 remains byte-compatible;
schema v2 carries every artifact's complete supported digest set and binds
authorization v2 plus exact-lock v3. Both versions bind the authorization
digest, database generation and complete installed-state evidence, artifact
origin, size and application digest, maintainer-script environment-policy
identity, intended final closure, and the dense typed dependency-ordered step
graph.
`transaction_engine.authorizeProgram` and `executeAuthorizedProgram` require a
matching program before native execution, and can require an independently
recorded program digest. See
[native transaction programs](native-transaction-program.md).

Credentials in URI user-info, common token/query/header assignments, proxy
variables, and auth paths are redacted before serialization. Persisted
provenance can be bounded and digest-validated with
`TransactionProvenanceStore`. CLI flags are intentionally outside this API
change and remain tracked by issue #23.

Schemas:

- [`schema/exact-closure-lock-v1.json`](../schema/exact-closure-lock-v1.json)
- [`schema/exact-closure-lock-v2.json`](../schema/exact-closure-lock-v2.json)
- [`schema/exact-closure-lock-v3.json`](../schema/exact-closure-lock-v3.json)
- [`schema/package-cache-fingerprint-v1.json`](../schema/package-cache-fingerprint-v1.json)
- [`schema/package-cache-fingerprint-v3.json`](../schema/package-cache-fingerprint-v3.json)
- [`schema/package-cache-fingerprint-v4.json`](../schema/package-cache-fingerprint-v4.json)
- [`schema/package-cache-fingerprint-v5.json`](../schema/package-cache-fingerprint-v5.json)
- [`schema/package-cache-result-v1.json`](../schema/package-cache-result-v1.json)
- [`schema/package-cache-result-v3.json`](../schema/package-cache-result-v3.json)
- [`schema/package-cache-result-v4.json`](../schema/package-cache-result-v4.json)
- [`schema/package-cache-result-v5.json`](../schema/package-cache-result-v5.json)
- [`schema/package-cache-error-v1.json`](../schema/package-cache-error-v1.json)
- [`schema/transaction-result-v1.json`](../schema/transaction-result-v1.json)
- [`schema/transaction-result-v2.json`](../schema/transaction-result-v2.json)
- [`schema/transaction-result-v3.json`](../schema/transaction-result-v3.json)
- [`schema/transaction-result-summary-v1.json`](../schema/transaction-result-summary-v1.json)
- [`schema/native-transaction-authorization-v1.json`](../schema/native-transaction-authorization-v1.json)
- [`schema/native-transaction-authorization-v2.json`](../schema/native-transaction-authorization-v2.json)
- [`schema/native-transaction-program-v1.json`](../schema/native-transaction-program-v1.json)
- [`schema/native-transaction-program-v2.json`](../schema/native-transaction-program-v2.json)
- [`schema/native-transaction-provenance-v2.json`](../schema/native-transaction-provenance-v2.json)

`debz transaction-result verify` is the no-follow read boundary used after an
Actions installation, including when the mutating process ran under explicit
sudo. It verifies canonical transaction-result v1 bytes and digest, successful
exact final state, and complete repository/package evidence against the
supplied canonical lock before emitting the bounded summary schema above.

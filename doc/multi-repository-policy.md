# Immutable multi-repository policy

`debz.repository_policy` is the public orchestration API for an explicitly
declared repository set. It never reads `/etc/apt`, environment proxy
variables, netrc files, credential helpers, host keyrings, or a default cache.

`normalize` accepts any ordered collection of legacy or DEB822
`SourceDocument` values. It expands URI/suite/component/architecture
combinations, applies an explicit native architecture only when requested,
sorts normalized repositories, rejects duplicates, rejects unsupported
exact-path suites and non-`file`/`http`/`https` or credential-bearing URIs,
and returns:

- stable SHA-256 repository and configuration identities;
- typed enablement, priority, release pin, default-release, immutable/snapshot,
  proxy, credential-reference, keyring, and deadline policy;
- canonical, round-trippable DEB822 output in repository-ID order.

Credential references are opaque. Their identifiers and resolved values are
excluded from repository/configuration IDs, generated sources, aggregate
manifests, diagnostics, and cache keys.

`refreshAll` requires one `Runtime` for every enabled repository. A runtime
must repeat the declared proxy, credential, keyring, and deadline references
and supplies the resolved authenticated-refresh policies. Each repository is
refreshed through `repository_refresh.refreshAuthenticated`, so OpenPGP,
Release identity/date/expiry, index checksum, decompression, parsing, and
per-repository cache publication all complete before solver admission.
Disabled repositories are not refreshed.
Extra runtimes that do not identify an enabled repository are rejected.

The default `all_or_nothing` policy publishes no aggregate universe when any
repository fails. `allow_stale_authenticated` may use only that repository's
previous authenticated cache snapshot, marks it stale in provenance, and
never substitutes another mirror. `cache_only` performs no acquisition and
fails on a missing or policy-incompatible snapshot.

Immutable URL and named snapshot repositories are cache-first in online mode:
after their first authenticated publication, the same configuration identity
can only reuse that authenticated generation. Changing immutable content or
authentication policy requires changing the declared immutable identity.

After every enabled repository has a complete trusted generation, `refreshAll`
atomically publishes a deterministic aggregate manifest through the explicit
`metadata_cache.Cache`. It records configuration/repository IDs, Release and
index digests, selected index paths, signer fingerprints, explicit clock time,
immutability identity, and stale decisions. Cache publish locking is controlled
by `aggregate_publish`; per-repository locking remains controlled by each
runtime refresh policy.

`CombinedUniverse` contains authenticated `SolverRepositoryInput` values and a
total-ordered candidate view. Effective priority applies the base priority,
matching suite/component pins, and a default-release floor of 990. Candidates
are ordered by package, architecture, effective priority, Debian version,
repository ID, and record index. `importInto` imports the same deterministic
repository sequence into `SolverContext`.

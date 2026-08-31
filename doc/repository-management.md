# Repository management API

`debz.repository_api` is a stable API separate from product API v1. Version 1
defines the `add` operation; CLI parsing is intentionally outside this
boundary. Callers provide an absolute target root, descriptor URL, optional
SHA-256, optional target architecture, `no_refresh`, and bounded cache, state,
network, and operation-wide resource policy. The production implementation is
`debz.ProductionRepositoryBackend`.

The canonical result schema is
[`repository-operation-result-v1`](../schema/repository-operation-result-v1.json).
It records acquisition, structural validation, authenticated repository
preflight, planning, installation, import, and refresh state. Nonzero results
retain truthful installed/refreshed evidence and typed diagnostics; incomplete
work cannot be serialized as success. `repository_api.decode` accepts only
bounded, canonical, digest-valid documents. Results returned by the production
backend own their strings with the caller-supplied allocator; call
`Result.deinit` when finished. Decoded documents return `OwnedResult`, which
likewise requires `deinit`.

## Descriptor and repository trust

The MVP descriptor is a Debian binary package. Unpinned acquisition requires
HTTPS certificate and hostname verification on every redirect hop; a downgrade
and later re-upgrade is rejected. HTTP and `file:` require the expected
SHA-256. Observable URLs remove credentials, fragments, and complete query
values. Embedded debsigs members may be inventoried but do not authenticate the
descriptor.

Before dpkg runs, the package is structurally validated with the
repository-descriptor profile. Every enabled `.list` or `.sources` payload must
be static, root-relative, and declare `Signed-By`; every referenced keyring
must be a regular payload file. Keyring bytes are parsed and used to
authenticate a dry refresh of the new repositories. Dynamic repository
material and authentication-bypassing `Trusted: yes`/`trusted=yes`
declarations fail before target mutation. Explicit false values remain valid.

Architecture comes only from an explicit request or target-root dpkg
configuration. Host `uname`, host APT configuration, environment proxies,
netrc, prompts, and TTY input are not used.

## Planning and mutation boundary

The descriptor package is a verified local-artifact solver origin. Installed
packages satisfy dependencies first. Existing imported target repositories are
refreshed only if the installed-only attempt lacks a dependency candidate, and
only authenticated or stale-authenticated complete snapshots are solver
eligible. Repository dependencies use verified acquisition; the descriptor
uses its existing CAS object.

An exact-lock v2 file is atomically persisted before dpkg and is passed to both
execution and recovery. It records the
descriptor and every repository-selected package in the mutation closure;
already-installed dependency satisfiers are retained from target state rather
than assigned invented artifact origins. The executor uses a fixed
noninteractive, keep-existing-conffile policy. Only this typed backend may opt
into host-root execution, and only when the requested root is `/`; product API
v1 continues to deny host-root execution for every operation.

After dpkg, the backend verifies descriptor package identity and exact static
source/keyring bytes, imports the resulting target APT configuration, writes
its manifest, refreshes only new or changed descriptor repositories unless
`no_refresh`, and publishes transaction provenance v2 through the
lock-validating execution/recovery constructors. Missing or mismatched executor
lock digests cannot be replaced by caller-supplied provenance fields.

Operation-wide limits bound normalized repositories, solver actions,
authenticated metadata bytes, total package bytes, retained package memory,
cache growth, and elapsed time. Package bodies are validated after CAS
publication and released before the next package; the executor retains only
CAS paths and immutable provenance.

## State, idempotence, and recovery

Every completed phase atomically updates
[`repository-add-state-v1`](../schema/repository-add-state-v1.json) under the
selected state root. Each operation directory is keyed by the SHA-256 identity
of the descriptor URL, optional expected digest, and `no_refresh`, so identical requests
resume the same evidence while distinct descriptors coexist. Decoding is
bounded, canonical, and digest checked. A repository-root advisory lock
serializes add operations even though their evidence directories are separate.

An identical installed package and managed-file set resumes import or refresh
without invoking dpkg. A different version, artifact digest, or divergent
managed file fails before mutation. A post-dpkg import or refresh failure
returns nonzero with `installed=true`, preserves lock/provenance/state
evidence, and makes no rollback claim. Missing or inconsistent durable
evidence produces `recovery_required` rather than a success-shaped result.
State write/fsync failures after mutation return progress-aware nonzero results
with `installed=true` and every known evidence path. Resume validates
persisted lock, provenance, manifest, managed files, and dpkg state rather than
requiring stale state path fields; durable `refreshed=true` history is
monotonic.

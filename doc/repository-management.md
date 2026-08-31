# Repository management API

`debz.repository_api` is a stable API separate from product API v1. Version 1
defines the `add` operation; CLI parsing is intentionally outside this
boundary. Callers provide an absolute target root, descriptor URL, optional
SHA-256, optional target architecture, `no_refresh`, and bounded cache, state,
network, and operation-wide resource policy. The production implementation is
`debz.ProductionRepositoryBackend`.

## CLI

The standalone binary wires the typed backend directly:

```sh
sudo debz repo add \
  --url https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
```

`--url` is required. `--root` defaults to `/`; alternate roots use the same
logical `/var/cache/debz` and `/var/lib/debz` defaults beneath the selected
root. `--architecture` overrides target dpkg architecture discovery,
`--sha256` pins descriptor bytes, `--no-refresh` skips only the final refresh,
and `--json` emits canonical
[`repository-operation-result-v1`](../schema/repository-operation-result-v1.json).
Explicit logical cache/state paths, proxy policy, timeouts, retry/redirect
bounds, byte limits, lock wait, and aggregate repository/action/metadata/
package/cache budgets map directly to the v1 request fields; see
`debz repo add --help` for spellings.

`debz repo add` is the authorization to mutate the selected root. It does not
accept or require `--assume-yes`, `--allow-host-root`,
`--import-target-apt-config`, `--install-root`, `--refresh`, or a separate
noninteractive flag. It never prompts, checks TTY state, reads stdin, invokes
apt, or consults environment proxy/netrc/credential helpers. Help flags take
precedence over malformed or incomplete command arguments.

Human output reports descriptor identity and truthful installed/refreshed
state. JSON output is the canonical typed result, including diagnostics and
evidence paths. A post-install import or refresh failure exits nonzero while
retaining `installed=true`; no output claims rollback. Observable descriptor
URLs redact the complete query and never persist URI user information.

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

The CLI default `/` is intentionally safe only because it enters this typed
operation, whose executor policy enables host-root mutation for repository add
alone. Product API v1 and every generic product command continue to reject
host root. An alternate `--root` resolves source files, keyrings, architecture,
cache, state, locks, and evidence only within that root; it never falls back
to `/`.

## Planning and mutation boundary

The descriptor package is a verified local-artifact solver origin. Installed
packages satisfy dependencies first. Existing imported target repositories are
refreshed only if the installed-only attempt lacks a dependency candidate, and
only authenticated or stale-authenticated complete snapshots are solver
eligible. Repository dependencies use verified acquisition; the descriptor
uses its existing CAS object.

The exact canonical executable plan and an exact-lock v2 file are atomically
persisted before dpkg and passed to both execution and recovery. The plan is
reloaded byte-canonically on resume rather than regenerated from the
potentially incomplete current dpkg state. Lock construction uses only the
persisted action origin, digest, and size plus the authenticated snapshot
evidence bound to those actions; transient solver pointers and record indexes
are never recovery inputs. The lock records the
descriptor and every repository-selected package in the mutation closure;
already-installed dependency satisfiers are retained from target state rather
than assigned invented artifact origins, and binds the complete request,
authenticated repository snapshots, local artifacts, and executable plan.
Its policy digest explicitly binds repository-add's `locked_packages`
verification scope. Under that scope every locked mutation package must have
the exact installed identity, plan origin, digest, size, and completed journal
artifact digest, while unrelated healthy packages already present on the
target are allowed to remain or change. The executor's default full-closure
exact-lock semantics remain unchanged for product operations. The executor uses a fixed
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
cache growth, and elapsed time. Metadata objects and per-repository/aggregate
manifests reserve their actual cache growth before publication; retained
snapshot and aggregate-manifest memory is likewise reserved before it becomes
an accepted result. One absolute monotonic deadline starts before the repository operation lock is
acquired and is propagated through
descriptor/repository/package acquisition, dpkg execution, and recovery.
The repository lock wait is capped by both its configured wait and remaining
operation time; expiry after or during that wait prevents all acquisition and
mutation work. Every later transport, lock wait, and process timeout is
likewise capped by the remaining operation time, and expiry cancels a running dpkg process. Package bodies are
validated after CAS
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
without invoking dpkg. When no matching recovery journal exists, that shortcut
also rereads dpkg state and requires every package in the persisted
operation-scoped lock to have its exact version and architecture, while
preserving the invariant that every unrelated installed package is healthy.
The persisted lock and successful provenance establish historical artifact
origins; current dpkg state establishes only package identities and health. A
different version, artifact digest, divergent managed file, missing locked
package, or unhealthy package fails with recovery required before mutation. A
post-dpkg import or refresh failure
returns nonzero with `installed=true`, preserves lock/provenance/state
evidence, and makes no rollback claim. Missing or inconsistent durable
evidence produces `recovery_required` rather than a success-shaped result.
State write/fsync failures after mutation return progress-aware nonzero results
with `installed=true` and every known evidence path. Resume validates
the persisted plan, request, local artifacts, repository snapshots, lock,
provenance, manifest, managed files, and dpkg state rather than
requiring stale state path fields; durable `refreshed=true` history is
monotonic. If dpkg completed before provenance/state publication, provenance
is reconstructed only from the original plan, lock, report/journal, and
authenticated evidence.

Once validated descriptor state exists, resume first reads the exact persisted
digest and size from CAS. A missing or corrupt object may be reacquired only at
that digest and size; an originally unpinned HTTPS descriptor also retains its
all-HTTPS transport requirement and original trust evidence. Changed transport
content is rejected. Shared transaction journals are decoded before selecting
recovery: only an exact plan/root/executor-policy/lock match is recovered,
mismatched incomplete journals block, and unrelated completed archives are
ignored so a normal execution can publish its own journal safely.

All root and logical-path fields use one schema-aligned grammar: valid UTF-8,
canonical absolute components, no backslashes, C0/DEL controls, dot
components, duplicate separators, or trailing separator.

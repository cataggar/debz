# Download exact-lock packages

`cataggar/debz/actions/download` authenticates the repositories named by a
canonical exact-lock document, restores untrusted candidate package bytes,
and asks `debz` to prepare the lock's complete Debian package closure.

This is a cache/download action, not an installation action. A cache hit never
means that packages are installed, that dpkg state exists, or that a
transaction may be skipped.

## Usage

Pin both first-party actions by full commit SHA. A commit-pinned setup action
needs an explicit CLI release:

```yaml
permissions:
  contents: read
  attestations: read

steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
    with:
      persist-credentials: false

  - uses: cataggar/debz/actions/setup@<full-commit-sha>
    with:
      debz-version: v0.3.0

  - uses: cataggar/debz/actions/download@<full-commit-sha>
    id: packages
    with:
      lock-input: .github/debz/noble-amd64.lock.json
      config: .github/debz/noble.json
      keyring: .github/debz/ubuntu-archive-keyring.gpg
      architecture: amd64
      cache: 'true'

  - run: |
      test "${{ steps.packages.outputs.cache-hit }}" = true \
        || test "${{ steps.packages.outputs.cache-hit }}" = false
      printf 'verified package objects: %s\n' \
        "${{ steps.packages.outputs.cache-path }}"
```

`debz` must already be a regular executable on `PATH`; use
[`actions/setup`](../setup/README.md). The action invokes no `apt`, `dpkg`,
`curl`, `gh`, Python, shell-generated argument string, or caller-provided
command, and the cache path invokes no host tar or extraction utility.
GitHub-hosted Linux runners and compatible container/self-hosted
runners that provide the maintained Node 24 action runtime are supported;
older runners are rejected rather than given a shell/Python fallback.
Pinning the download action selects its orchestration code; pinning
`debz-version` in the setup step separately selects the CLI and fingerprint
implementation. The download action never upgrades or substitutes that CLI.
The default `transaction-backend: legacy_dpkg` requires `package-cache-v1`
(introduced in `debz` 0.3.0). Explicit `transaction-backend: native` requires a
CLI build/release implementing `package-cache-v2`, with native v2 lock,
fingerprint, preparation, and archive support. An older or incompatible CLI
fails before cache restore; neither backend is automatically substituted.
`contents: read` is sufficient for checkout and public repository files;
`attestations: read` is needed by the default setup-action provenance path.
The download action itself calls no GitHub content or attestation API; the
runner-provided cache service token is used only by the bounded cache-v2 client
and exact-version Azure blob dependency in the checked-in bundle.

When this runtime is invoked by [`actions/install`](../install/README.md), the
parent supplies setup's already verified absolute executable through a private
handoff and the download runtime does not search `PATH`. This is not an
additional public action input and cannot weaken standalone setup guidance.

## Inputs

Required and conditional inputs:

| Input | Meaning |
| --- | --- |
| `lock-input` | Canonical exact-closure lock v1 for legacy or v2 for native. Unsupported or mismatched schemas fail instead of being skipped. |
| `architecture` | Native target Debian architecture: `amd64` or `arm64`. This is not inferred from the runner architecture. |
| `source` or `config` | Required for legacy mode and repository-backed native locks. Repeated paths are newline-delimited. |
| `keyring` | Required for legacy mode and repository-backed native locks. Every source must use `Signed-By` and name one of these newline-delimited paths. |

Common optional inputs:

| Input | Default | Meaning |
| --- | --- | --- |
| `transaction-backend` | `legacy_dpkg` | Explicit `legacy_dpkg` or `native`; binds both CLI phases, schema validation, and restore-key version. |
| `foreign-architecture` | empty | Newline-delimited allowed foreign architectures. |
| `default-release` | empty | Explicit release-selection policy. |
| `repository-policy` | `strict-priority` | `strict-priority` or `best-version`; it must match the lock's solver policy. |
| `recommends` | `false` | Must match the lock's solver policy. |
| `allow-downgrade` | `false` | Must match the lock's solver policy. |
| `proxy` | empty | Explicit HTTP(S) proxy without embedded credentials. No ambient proxy is inherited by `debz`. |
| `credential-reference` | empty | Explicit regular file containing authorization material for the declared repository origin. |
| `deadline-ms` | empty | Optional positive repository/package deadline; omission preserves the lock's default policy while the action retains a 15-minute child-process guard. |
| `lock-wait-ms` | `30000` | Bounded wait for the package-CAS writer lock. |
| `cache` | `true` | Enable exact and compatible-prefix GitHub cache restore/save. |
| `cache-root` | `$RUNNER_TEMP/debz-package-cache` | Absolute child of `RUNNER_TEMP`; symbolic-link components are rejected. |
| `offline` / `cache-only` | `false` | Require local authenticated metadata and complete valid objects; never fall back online. |
| `repair-corrupt-cache` | `false` | Online-only explicit repository-object repair. Local artifacts cannot be repaired this way. |

The bounded resource inputs are
`maximum-package-bytes`, `maximum-total-package-bytes`,
`maximum-lock-packages`, `maximum-repository-records`,
`maximum-staging-entries`,
`maximum-gc-directory-entries`, `maximum-gc-objects-scanned`,
`maximum-gc-objects-deleted`, and `maximum-gc-bytes-deleted`. Exceeding any
bound fails the action; incomplete cleanup is never saved.

Relative file inputs are resolved once beneath `GITHUB_WORKSPACE`. Absolute
files are accepted, but every path must resolve to the same regular file
without symbolic-link traversal. The cache root must be below `RUNNER_TEMP`
and cannot contain the lock, source/config, keyring, or credential files.
Each source's `Signed-By` value (or the source referenced by a config file)
must name the same absolute path supplied through `keyring`; debz never searches
ambient trusted-key directories.

### Native closures

Native mode accepts the CLI's separately versioned v2 contracts and
`debz-package-cas-v2-` keys, never v1 responses or restore keys. Empty native
closures need no source/keyring inputs, return zero downloaded/reused objects,
and can still be saved and restored as canonical empty v2 archives. Local-only
closures may also omit repository inputs. The CLI remains responsible for
deciding which repository evidence the lock requires.

Mixed and local-artifact closures retain the CLI's existing authority boundary:
local artifacts must already be available in the verified CAS or imported
archive and pass local payload/identity validation. Missing or corrupt local
artifacts require separate explicit acquisition. Neither the action nor
preparation fetches redacted provenance URLs or treats local artifacts as
repository-authenticated packages. Locks must match the core native
solver-policy domain.

The install action still selects legacy download contracts explicitly. Native
download support does not enable native installation or replace its required
receipt-backed completion integration.

## Outputs

| Output | Meaning |
| --- | --- |
| `cache-hit` | `true` only when the Actions cache service restored the exact primary key. Preparation and verification still ran. |
| `cache-matched-key` | Exact key, compatible prefix key, or empty when no cache was restored. |
| `cache-path` | Absolute verified `packages-v1/objects` directory used by later debz operations. |
| `cache-root` | Parent cache root accepted by `debz --cache-path`, for a later cache-only transaction. |
| `lock-digest` | Canonical exact-lock digest verified and reported by `debz`. |
| `downloaded-count` | Current-lock objects acquired from package transport. |
| `reused-count` | Current-lock objects reopened, size/SHA-256 checked, and payload-validated from the CAS. |

Outputs are emitted only after authenticated repository matching, complete
closure preparation, staging cleanup, and retained-closure garbage collection
succeed. Credentials, proxy authorization, keyring paths, repository paths,
and URLs are never outputs or key material.

## Cache and trust model

The CLI, not YAML or JavaScript, validates the canonical lock and produces the
primary key and bounded restore prefix. The fingerprint covers:

- exact-lock schema and canonical digest;
- native/foreign architecture and Debian package ABI identity;
- the exact running `debz` version and package-CAS layout;
- solver policy already authenticated by the lock;
- corruption mode, package size/total bounds, origin mode, and payload
  validation policy version.

The exact key adds the lock digest. The compatible prefix stops at the safe
sharing boundary, so an older lock may contribute candidate objects. Neither
an exact hit nor a prefix hit is trusted: `debz` reopens every current-lock
object, verifies its regular-file shape, declared size, SHA-256, the lock's
repository or local-artifact evidence, and Debian payload identity before
reporting reuse.
The action passes the restore classification back to the CLI. A missing object
after an exact-key restore is corruption and fails by default; only explicit
online repair may reacquire it. Missing objects are expected after a prefix
restore or cold miss.

The checked-in Node 24 bundle uses the Actions cache v2 service as an opaque
blob store. It never invokes the cache action's tar extraction path. A restored
blob is written only to a fresh private directory below `RUNNER_TEMP`, then
`debz` parses a path-free, length-delimited archive, rejects malformed,
duplicate, out-of-order, oversized, or digest-invalid entries, and imports only
current-lock objects into the CAS under the writer lock. Exact-key archives
must contain exactly the current closure; compatible-prefix archives may
contain a verified subset plus unrelated objects, which are not imported. The
executable is descriptor- and SHA-256-revalidated before and after this
sequence.

The opaque format and cache-service version are path-independent, so the same
entry can be restored into a different safe cache root. Restore keys come only
from the CLI result; JavaScript does not append repository paths, secrets, or
ad hoc policy fragments.

Only objects from `packages-v1/objects` are serialized into the opaque cache
blob. The action never caches:

- repository metadata or freshness state;
- lock/config/source files or keyrings;
- credentials or proxy authorization;
- package staging files or writer locks;
- installation roots, dpkg/alternatives state, journals, provenance, or
  mutable transaction state;
- success markers.

After verification, `debz` removes objects outside the current lock under one
bounded writer lock. Concurrent publishers remain atomic. A concurrent
GitHub cache save for the same immutable key is benign; a verification,
cleanup, or repository error is not.

The GitHub cache is an optimization: an unavailable lookup is treated as a
miss, and an unavailable save does not invalidate an already verified local
CAS. Once the service reports a matching entry, an invalid URL, oversized or
truncated blob, or invalid inner archive fails closed instead of being
downgraded to a miss. Offline mode still fails if restored/local evidence is
incomplete. Cache integration requires the GitHub Actions cache v2 service;
unsupported GHES/cache-service environments run as cache misses.

## Repository and offline behavior

For repository-backed entries, online preparation performs normal signed
repository refresh and requires the
current authenticated repository ID, snapshot, Release digest, Packages
digest, accepted signer, and every package's exact
name/version/architecture/size/SHA-256 to match the lock. A moving repository
that no longer reproduces the lock fails even if every `.deb` object was
restored.

Offline preparation performs no network request. For repository-backed locks,
it succeeds only when the explicit cache root already contains both:

1. authenticated repository metadata sufficient to replay the lock; and
2. every valid package object.

The GitHub cache deliberately stores only item 2. Therefore a fresh runner
with only the Actions cache restored is not, by itself, an offline repository
snapshot. Use an explicit immutable/local repository configuration when
offline reproducibility is required.

Corrupt, truncated, symlinked, wrongly named, wrong-size, wrong-digest, or
payload-invalid objects fail closed. `repair-corrupt-cache: 'true'` is
available only online for repository-backed objects and reacquires through
the same authenticated repository and full validation path. It does not repair
local artifacts by fetching their provenance URLs.

## Handoff to installation

A later installation action or direct CLI invocation must execute the normal
transaction in cache-only mode with the same exact lock, explicit repository
configuration/keyrings, architecture/policy, and `${{ steps.packages.outputs.cache-root }}`.
Do not infer an installed state from `cache-hit`, `reused-count`, or the
presence of files in `cache-path`.
Keep the backend selection consistent: a native download closure must be
consumed by a native-capable transaction caller, not the currently legacy
install action.

## Local integration coverage

With Node 24, locked action dependencies, and a built v2-capable CLI:

```sh
DEBZ_DOWNLOAD_INTEGRATION=1 \
DEBZ_DOWNLOAD_CLI="$PWD/zig-out/bin/debz" \
npm --prefix actions/download test
```

This also exercises a real canonical empty native archive through cold and
exact action restores. To include signed-repository cold/partial/exact
preparation, set `DEBZ_DOWNLOAD_REPOSITORY_FIXTURE` to an absolute fixture
directory containing `fixture.sources`, `repository/fixture-keyring.gpg`,
`base.native.lock.json`, and `scenario.native.lock.json`, as generated by the
CI cache-semantics job. CI additionally exercises the checked-in bundle with
the real Actions cache service and refuses cross-backend locks.

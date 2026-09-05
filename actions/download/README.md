# Download exact-lock packages

`cataggar/debz/actions/download` authenticates the repositories named by a
canonical exact-lock v1 document, restores untrusted candidate package bytes,
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
command. GitHub-hosted Linux runners and compatible container/self-hosted
runners that provide the maintained Node 24 action runtime are supported;
older runners are rejected rather than given a shell/Python fallback.
Pinning the download action selects its orchestration code; pinning
`debz-version` in the setup step separately selects the CLI and fingerprint
implementation. The download action never upgrades or substitutes that CLI.
The executable must implement the `package-cache-v1` capability (introduced in
`debz` 0.3.0); an older or incompatible CLI fails before cache restore.
`contents: read` is sufficient for checkout and public repository files;
`attestations: read` is needed by the default setup-action provenance path.
The download action itself calls no GitHub content or attestation API; the
runner-provided cache service token is used only by the exact-version,
lockfile-integrity-pinned `@actions/cache` client in the checked-in bundle.

## Inputs

Required:

| Input | Meaning |
| --- | --- |
| `lock-input` | Canonical exact-closure lock v1. Unsupported schemas fail instead of being skipped. |
| `architecture` | Native target Debian architecture: `amd64` or `arm64`. This is not inferred from the runner architecture. |
| `source` or `config` | At least one explicit source/config path. Repeated paths are newline-delimited. |
| `keyring` | One or more explicit keyring paths, newline-delimited. Every source must use `Signed-By` and name one of these paths. |

Common optional inputs:

| Input | Default | Meaning |
| --- | --- | --- |
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
| `repair-corrupt-cache` | `false` | Online-only explicit repair. A corrupt object otherwise fails closed. |

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

## Outputs

| Output | Meaning |
| --- | --- |
| `cache-hit` | `true` only when the Actions cache service restored the exact primary key. Preparation and verification still ran. |
| `cache-matched-key` | Exact key, compatible prefix key, or empty when no cache was restored. |
| `cache-path` | Absolute `packages-v1/objects` directory. This is the only path saved by the action. |
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
object, verifies its regular-file shape, declared size, SHA-256, repository
identity/snapshot, and Debian payload identity before reporting reuse.
The action passes the restore classification back to the CLI. A missing object
after an exact-key restore is corruption and fails by default; only explicit
online repair may reacquire it. Missing objects are expected after a prefix
restore or cold miss.

The checked-in Node 24 bundle uses an exact-version, integrity-locked
`@actions/cache` client for the same cache service used by the official cache
action. Restore keys come only from the CLI result; JavaScript does not append
repository paths, secrets, or ad hoc policy fragments. The client archives the
relative `objects` directory from its verified parent, so the cache service's
internal version does not bind a runner-specific absolute path.

Only `packages-v1/objects` is restored and saved. The action never caches:

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

The GitHub cache is an optimization: an unavailable restore is treated as a
miss, and an unavailable save does not invalidate an already verified local
CAS. Offline mode still fails if the restored/local evidence is incomplete.

## Repository and offline behavior

Online preparation performs normal signed repository refresh and requires the
current authenticated repository ID, snapshot, Release digest, Packages
digest, accepted signer, and every package's exact
name/version/architecture/size/SHA-256 to match the lock. A moving repository
that no longer reproduces the lock fails even if every `.deb` object was
restored.

Offline preparation performs no network request. It succeeds only when the
explicit cache root already contains both:

1. authenticated repository metadata sufficient to replay the lock; and
2. every valid package object.

The GitHub cache deliberately stores only item 2. Therefore a fresh runner
with only the Actions cache restored is not, by itself, an offline repository
snapshot. Use an explicit immutable/local repository configuration when
offline reproducibility is required.

Corrupt, truncated, symlinked, wrongly named, wrong-size, wrong-digest, or
payload-invalid objects fail closed. `repair-corrupt-cache: 'true'` is
available only online and reacquires the object through the same authenticated
repository and full validation path.

## Handoff to installation

A later installation action or direct CLI invocation must execute the normal
transaction in cache-only mode with the same exact lock, explicit repository
configuration/keyrings, architecture/policy, and `${{ steps.packages.outputs.cache-root }}`.
Do not infer an installed state from `cache-hit`, `reused-count`, or the
presence of files in `cache-path`.

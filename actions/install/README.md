# Install an exact package closure

`cataggar/debz/actions/install` is the mutating composition of the repository's
verified setup and package-download actions. It obtains one exact `debz`
release, prepares the immutable package CAS for one reviewed exact lock, and
then **always** executes a normal alternate-root installation with
`--cache-only`.

A package cache hit saves transfer only. It never means that a root is
installed and never skips planning, archive revalidation, dpkg
unpack/configure, maintainer scripts, triggers, transaction journaling, or the
final exact-state audit.

## Usage

Pin the action by a reviewed full commit SHA and select an exact compatible CLI
release separately:

```yaml
permissions:
  contents: read
  attestations: read

steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
    with:
      persist-credentials: false

  - id: install
    uses: cataggar/debz/actions/install@<full-commit-sha>
    with:
      debz-version: v0.3.0
      package: scenario-main
      lock-input: .github/debz/noble-amd64.lock.json
      config: .github/debz/noble.json
      keyring: .github/debz/ubuntu-archive-keyring.gpg
      architecture: amd64
      install-root: ${{ runner.temp }}/debz-root
      assume-yes: 'true'
      noninteractive: 'true'
      conffile: keep-existing
      use-sudo: 'true'

  - name: Consume verified result
    env:
      RESULT: ${{ steps.install.outputs.transaction-result }}
      COUNT: ${{ steps.install.outputs.installed-count }}
    run: printf 'verified packages=%s result=%s\n' "$COUNT" "$RESULT"
```

The action revision pins the setup, cache-service, validation, and orchestration
implementation. `debz-version` pins the CLI protocol and package/transaction
implementation. Commit-pinned action use therefore requires an explicit
version. Version 0.3.0 is the minimum supported contract.

## Required inputs

| Input | Contract |
| --- | --- |
| `debz-version` | Exact SemVer release, with or without `v`; no ranges or `latest`. |
| `package` | One selector in the current `name[:architecture][=version]` grammar. It is one argv element, never split or interpreted by a shell. |
| `lock-input` | Reviewed canonical exact-closure lock v1. The action never creates or replaces it. |
| `architecture` | Native `amd64` on Linux X64 or native `arm64` on Linux ARM64. |
| `install-root` | Explicit alternate root. `/`, ambiguous spellings, symbolic-link components, and overlap with cache/state/input files are rejected. |
| `assume-yes` | Must be exactly `'true'`; this is the mutation authorization. |
| `noninteractive` | Must be exactly `'true'`; interactive Actions execution is unsupported. |
| `conffile` | Exactly `keep-existing` or `use-package-version`. |
| `source` and/or `config` | Newline-delimited explicit repository paths; at least one is required. |
| `keyring` | One or more newline-delimited explicit keyring paths. Every source must use `Signed-By` consistently with these paths. |

Relative file, root, and state paths are resolved beneath
`GITHUB_WORKSPACE`. File inputs must already be regular files and may not
traverse symbolic links. `install-root` may be created by the action. The
package cache remains an absolute child of `RUNNER_TEMP`.

## Policy, cache, and setup inputs

The repository and solver inputs are passed unchanged to package preparation
and final installation:

- `foreign-architecture`;
- `default-release`;
- `repository-policy` (`strict-priority`, the default, or `best-version`);
- exact booleans `recommends` and `allow-downgrade`;
- credential-free HTTP(S) `proxy`;
- `credential-reference`, which is a file path and is never logged, cached, or
  emitted;
- positive bounded `deadline-ms` and `lock-wait-ms`.

`force` is a newline-delimited list from this closed set:

- `depends`;
- `depends_version`;
- `break_replaces`;
- `overwrite`;
- `overwrite_dir`;
- `remove_reinstreq`.

Each value becomes one `--force` argv pair. Duplicates and unknown values fail
before setup, network, cache, or mutation activity.

The download runtime is lock-closure based and has no separate package
argument. The final CLI invocation supplies the single selector and rejects it
unless its canonical request digest matches the reviewed lock; the wrapper
does not rewrite or paper over that binding.

Package-cache inputs match [`actions/download`](../download/README.md):
`cache`, `cache-root`, `offline`, `cache-only`,
`repair-corrupt-cache`, and all `maximum-*` resource limits. `cache-only` is an
alias for whole-action offline package preparation; regardless of this input,
the final install always uses CLI `--cache-only`. Online preparation leaves
authenticated metadata only in the ephemeral same-run cache root so that the
final network-disabled transaction can reproduce the lock.

Setup inputs match [`actions/setup`](../setup/README.md): `sha256`, `token`, and
`cli-cache`. The token is used only for release/attestation requests and is
masked before the bundled setup runtime starts. The exact `debz-path` returned
by setup is descriptor- and SHA-256-checked around every later phase and handed
directly to the download runtime; the install action never searches `PATH`
again.

## Roots, privilege, and recovery

`state-path` defaults to a root-specific private directory below
`RUNNER_TEMP`. An explicit state path may be absolute or workspace-relative.
Install root, transaction state, and package cache must be pairwise
non-overlapping. Existing recovery state is preserved and is never
automatically deleted or recovered.

`use-sudo` defaults to `'false'`:

- `false` invokes the verified executable directly. This is appropriate in a
  root container and fails normally if the current user lacks capabilities
  required by dpkg or maintainer scripts.
- `true` requires canonical `/usr/bin/sudo` and successful noninteractive
  execution. The only elevated program is the exact verified `debz` path,
  invoked as `sudo -n -- <debz-path> ...`. The host root remains forbidden.

On failure the CLI exit status is preserved, including usage `2`,
authentication `4`, planning `5`, package/cache `6`, transaction `7`, recovery
`8`, and internal `70`. The action leaves the selected state path intact and
does not publish transaction-shaped outputs. Recovery is an explicit later
`debz recover` operation using the same exact CLI, root, state, lock,
repository, architecture, and policy inputs.

## Verification and outputs

After `debz install` exits successfully, the same executable reopens
`STATE/transaction-result.json` without following symbolic links. It validates
the canonical transaction-result v1 digest and checks:

- successful outcome and `final_verification.status: exact_match`;
- target architecture;
- request, solver-policy, and exact-lock digests;
- authenticated repository evidence;
- every package identity, size, package digest, and CAS digest against the
  lock;
- bounded command and journal evidence.

The action also requires an atomically fresh result file, canonical successful
command-result JSON, empty success diagnostics/stderr, unchanged input file
identities, and unchanged root/cache/state directory identities. Only then are
outputs written.

| Output | Meaning |
| --- | --- |
| `debz-path`, `debz-version`, `target` | Exact verified setup identity. |
| `cli-cache-hit` | Exact verified CLI cache hit. |
| `package-cache-hit` | Exact primary-key package cache hit. Prefix/partial and cold restores are `false`. |
| `package-cache-path` | Verified `packages-v1/objects` directory. |
| `package-cache-root` | Parent passed unchanged to final `--cache-path`. |
| `lock-digest` | Canonical exact-lock digest verified by download and transaction-result validation. |
| `downloaded-count`, `reused-count` | Package preparation counts, not installed-state claims. |
| `transaction-result` | Absolute canonical `STATE/transaction-result.json` path. |
| `provenance` | Alias of `transaction-result`; v1 is one combined result/provenance document. |
| `installed-count` | Package count in the final exact closure, not the number newly changed. |

No output contains credentials, authorization headers, keyring contents, or
repository URLs.

## Cache and offline examples

Disable both optional transfer caches while retaining all verification:

```yaml
- uses: cataggar/debz/actions/install@<full-commit-sha>
  with:
    debz-version: v0.3.0
    package: scenario-main
    lock-input: .github/debz/lock.json
    source: .github/debz/repository.sources
    keyring: .github/debz/archive-keyring.gpg
    architecture: amd64
    install-root: ${{ runner.temp }}/root
    assume-yes: 'true'
    noninteractive: 'true'
    conffile: use-package-version
    cache: 'false'
    cli-cache: 'false'
    use-sudo: 'true'
```

For a root container, omit escalation:

```yaml
container: ubuntu:24.04
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
    with:
      persist-credentials: false
  - uses: cataggar/debz/actions/install@<full-commit-sha>
    with:
      debz-version: v0.3.0
      package: scenario-main
      lock-input: .github/debz/lock.json
      source: .github/debz/repository.sources
      keyring: .github/debz/archive-keyring.gpg
      architecture: amd64
      install-root: ${{ runner.temp }}/root
      assume-yes: 'true'
      noninteractive: 'true'
      conffile: keep-existing
      use-sudo: 'false'
```

`offline: 'true'` forbids all repair and repository/package network transport.
It succeeds only when the selected local cache root already contains both
authenticated metadata/evidence and every verified package object. An Actions
cache hit restores package objects only, so a package-only hit on a fresh
runner is not sufficient offline. Missing, partial, stale, truncated,
symlinked, or digest-invalid evidence fails closed.

## What is never cached

Only the CLI-owned opaque serialization of immutable
`packages-v1/objects` is eligible for the package cache. The action never
caches or restores:

- `install-root` or host `/`;
- dpkg or alternatives databases;
- repository metadata/freshness state;
- transaction state, journals, or results;
- credentials, authorization values, or keyrings;
- an installed/success marker.

Cold preparation downloads and verifies missing objects. A warm exact hit on a
new root reports zero downloads but still runs the full transaction and audit.
A same-root rerun also invokes `debz`; a no-change plan is not a cache
short-circuit.

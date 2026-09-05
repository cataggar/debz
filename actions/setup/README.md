# `debz` setup action

This first-party JavaScript action installs one exact static `debz` release on
Linux x64 or arm64. It downloads no package-manager state and needs no Python,
`pipx`, `curl`, `gh`, APT, or host archive utility.

For a single typed setup, package-cache, and alternate-root transaction
boundary, use [`actions/install`](../install/README.md). That action invokes
this checked-in setup runtime from the same immutable repository revision and
continues to use the exact returned executable path.

## Recommended usage

Pin the action implementation to a reviewed commit and pin the CLI separately:

```yaml
permissions:
  contents: read
  attestations: read

steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
    with:
      persist-credentials: false
  - id: debz
    uses: cataggar/debz/actions/setup@<reviewed-commit-sha>
    with:
      debz-version: v0.3.0
  - run: '"${{ steps.debz.outputs.debz-path }}" version'
```

The action commit controls installer code. `debz-version` independently
selects the exact immutable release. A commit, branch, major tag, range, or
`latest` action ref cannot safely imply a CLI version, so omitting
`debz-version` in those cases fails rather than selecting the latest release.

When using an exact action tag, the CLI version may be coupled to it:

```yaml
- uses: cataggar/debz/actions/setup@v0.3.0
```

Only an exact `vMAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]` action ref is accepted
for this derivation. An explicit `debz-version` always wins.

## Inputs

| Input | Default | Contract |
| --- | --- | --- |
| `debz-version` | derived only from an exact semver action ref | Exact release tag or version, such as `v0.3.0`; no ranges or latest fallback. |
| `sha256` | empty | Independently trusted 64-hex SHA-256 for the selected archive. It must also match GitHub's release-asset digest. |
| `token` | `github.token` on `github.com`, otherwise empty | Used only for GitHub release and attestation API requests. It is never sent to release storage or Sigstore TUF. |
| `cache` | `true` | Restore/save only the exact verified CLI archive and install tree. Must be exactly `true` or `false`. |

## Outputs

| Output | Value |
| --- | --- |
| `debz-path` | Absolute path to the verified executable. Consumers should use this output rather than rediscovering the file. |
| `debz-version` | Canonical exact release tag, for example `v0.3.0`. |
| `target` | `linux-x64` or `linux-arm64`. |
| `cache-hit` | String `true` only for an exact, successfully reverified cache restore; otherwise `false`. |

Only the installation's `bin/` directory is added to `PATH`.

## Verification and trust

The action resolves the release by its exact tag and selects exactly
`debz-<version>-linux-{x64,arm64}.tar.gz`. The asset must be uploaded, nonempty,
bounded in size, and expose a lowercase `sha256:<digest>` through the GitHub
release API. Downloaded bytes always have to match that digest.

One additional trust path is mandatory:

1. **GitHub provenance (default):** the action obtains the Sigstore trusted root
   through TUF and cryptographically verifies a GitHub artifact-attestation
   bundle, its transparency evidence, GitHub OIDC issuer, repository and
   `release.yml` workflow identity, exact tag ref, peeled tag commit, SLSA
   workflow build type, and matching filename/digest subject. Extra subjects in
   the same valid bundle are allowed.
2. **Trusted SHA:** setting `sha256` supplies an out-of-band trust root. The
   value must match both GitHub's asset digest and the downloaded bytes.

Release titles, filenames, cache entries, redirects, and mere attestation API
presence are never trust roots. Provenance/TUF failure is fatal unless the
caller explicitly supplied a matching trusted SHA.

For public releases the GitHub APIs can be used anonymously, with lower rate
limits. The default token needs only:

```yaml
permissions:
  contents: read
  attestations: read
```

The token is not read from `GH_TOKEN`, Git credential helpers, or other ambient
credential configuration. Authorization is stripped before a release-storage
redirect.

## Extraction, installation, and cache

Gzip and tar are decoded in the Node process. Extraction rejects absolute and
parent paths, links, devices, duplicate entries, unexpected top-level or
`bin/` entries, malformed headers, truncated streams, oversized content, and
noncanonical modes/ownership. A staging directory is atomically published
under:

```text
$RUNNER_TEMP/debz-tools/<version>/<target>/<archive-sha256>/
```

The cache key is:

```text
debz-cli-v1-<target>-musl-static-<exact-tag>-<archive-sha256>
```

There are no restore prefixes. On a hit, the archive digest is checked again,
the cached object is treated as the opaque release `.tar.gz` bytes rather than
being extracted by a generic cache client, and the action's bounded safe parser
publishes a fresh install tree. The expected `bin/debz` bytes are then derived
from that authenticated archive, and the complete restored install tree is
compared with it before execution. Corruption fails closed; it does not trigger
an unverified fallback. The post-action repeats verification before uploading
the same raw archive to the GitHub Actions cache v2 service. It never invokes a
PATH-resolved cache archive tool. This cache is independent of the Debian
package content-addressed store used by package download/install workflows.
On a compatible runner where the GitHub Actions cache v2 service is not
available, setup remains correct and reports `cache-hit: false` without saving
a cache.

After installation, `debz version` must return the requested unprefixed SemVer
with no stderr before outputs are written. Published v0.1.x/v0.2.x binaries
predate that command, so those exact releases use their historical
`debz --version` check only after `debz version` fails with the known
unsupported-command status.

## Boundaries and compatibility

- Supported: GitHub-hosted Linux x64/arm64 and compatible Linux runners or
  container jobs able to execute Node 24 actions.
- Unsupported: Windows, macOS, 32-bit architectures, GHES mirrors, arbitrary
  download mirrors, and old self-hosted runners without the Node 24 action
  runtime.
- The action does not inspect or mutate APT sources, dpkg state, package caches,
  proxy settings, Git/`gh` credentials, Python environments, or installation
  roots. Package planning, download, and transactions belong to the separate
  actions that consume `debz-path`.

Any unsupported target, missing or duplicate asset, malformed digest or
archive, trust-policy failure, cache tampering, or version mismatch fails
before success outputs are emitted.

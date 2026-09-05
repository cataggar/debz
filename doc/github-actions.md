# GitHub Actions

[`actions/setup`](../actions/setup/README.md) is the first-party setup boundary
for GitHub workflows. It installs one exact static Linux release, establishes
trust through cryptographically verified GitHub provenance or a caller-supplied
SHA-256, safely extracts under `RUNNER_TEMP`, and exposes a stable
`debz-path` output.

[`actions/download`](../actions/download/README.md) is the first-party
exact-lock package boundary. It consumes the setup action's verified executable
from `PATH`, asks that CLI to produce the deterministic cache fingerprint,
restores only `packages-v1/objects`, authenticates the explicit repository
configuration and keyrings, and prepares every package in the lock.

An exact or partial cache hit supplies only untrusted candidate bytes. Every
current-lock object is reopened and checked for regular-file shape, declared
size, SHA-256, authenticated repository/snapshot identity, and Debian payload
identity before it is counted as reused. The CLI performs bounded staging
cleanup and retained-closure garbage collection before the action saves an
exact cache key.

Neither action installs packages. In particular, `cache-hit: 'true'` does not
represent an installed root or permit a later transaction to skip normal lock,
repository, payload, dpkg, journal, or post-state checks. Repository metadata,
credentials, keyrings, roots, dpkg state, and journals are never included in
the package object cache.

The action README is the normative reference for:

- action-ref and CLI-version pinning;
- supported targets and the Node 24 runner requirement;
- token permissions and anonymous API behavior;
- provenance and explicit-SHA trust modes;
- archive and redirect defenses;
- exact cache keys and cache-hit reverification; and
- inputs, outputs, failure behavior, and examples.

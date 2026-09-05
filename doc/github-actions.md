# GitHub Actions

[`actions/setup`](../actions/setup/README.md) is the first-party setup boundary
for GitHub workflows. It installs one exact static Linux release, establishes
trust through cryptographically verified GitHub provenance or a caller-supplied
SHA-256, safely extracts under `RUNNER_TEMP`, and exposes a stable
`debz-path` output.

Use the action output as the executable input to later package planning,
download, and transaction actions. The setup action does not read or modify
APT, dpkg, package repositories, target roots, or the Debian package
content-addressed store.

The action README is the normative reference for:

- action-ref and CLI-version pinning;
- supported targets and the Node 24 runner requirement;
- token permissions and anonymous API behavior;
- provenance and explicit-SHA trust modes;
- archive and redirect defenses;
- exact cache keys and cache-hit reverification; and
- inputs, outputs, failure behavior, and examples.

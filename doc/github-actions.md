# GitHub Actions

[`actions/setup`](../actions/setup/README.md) is the first-party setup boundary
for GitHub workflows. It installs one exact static Linux release, establishes
trust through cryptographically verified GitHub provenance or a caller-supplied
SHA-256, safely extracts under `RUNNER_TEMP`, and exposes a stable
`debz-path` output.

[`actions/download`](../actions/download/README.md) is the first-party
exact-lock package boundary. It consumes the setup action's verified executable
from `PATH`, asks that CLI to produce the deterministic cache fingerprint,
downloads one opaque cache blob into a private `RUNNER_TEMP` staging directory,
imports only verified package objects through debz, authenticates the explicit
repository configuration and keyrings, and prepares every package in the lock.
It defaults to `transaction-backend: native`, selecting native v3 locks,
v5 fingerprints/preparation results, and tagged archive-v3 keys,
with no version autodetection or fallback. Explicit `legacy_dpkg` is refused
before lock or cache work with `>=0.3.0,<0.4.0` recovery guidance. Native empty and local-only
closures may omit repository inputs; local bytes must already be acquired or
imported, never fetched from redacted provenance URLs.
Native v3 locks must carry a SHA-512 archive identity: a signed SHA512 or, for a
repository whose `--config` opts in with
`"archive_binding":"signed_sha256_derived_sha512"`, a derived SHA512 bound to
its signed SHA256 ([exact locks](exact-locks-and-provenance.md)).
Successful download and install invocations publish `backend-capability` as
`native-transaction-execution-v1`. Generated bundle bytes are checked by the
[cutover policy](legacy-compatibility.md).

[`actions/install`](../actions/install/README.md) composes those exact
boundaries and then performs the mutation. It validates all typed inputs before
setup or cache activity, hands the exact setup executable directly to the
download runtime, and always invokes one normal `debz install --cache-only`
transaction with the same lock, repository/keyring inputs, architecture,
solver policy, cache root, and explicit alternate root.
The install action defaults to `transaction-backend: native` and selects
v5/v3 download contracts and receipt-bound native installation, with a
dedicated CLI capability probe before preparation or mutation. Explicit
`legacy_dpkg` is refused before any work. Changed installs
must match the completing caller's typed receipt/completion identities to a
read-only native verification summary. Verified unchanged native closures emit
`changed: false` and no transaction/provenance path; an old receipt is not
presented as a new execution.

An exact or partial cache hit supplies only untrusted candidate bytes. Every
current-lock object is reopened and checked for regular-file shape, declared
size, SHA-256, the lock's repository or local-artifact evidence, and Debian payload
identity before it is counted as reused. The CLI performs bounded staging
cleanup and retained-closure garbage collection before the action saves an
exact cache key.

The cache service never extracts an archive into the workspace, setup tool
directory, or CAS. Debz owns a path-free, length-delimited opaque format and
rejects malformed framing, excess expansion, duplicates, invalid ordering, and
digest or lock mismatches before importing candidates under the CAS writer
lock. The Node 24 action downloads/uploads that single bounded blob through the
cache v2 and signed Azure endpoints; its service version is independent of
absolute runner paths.

The setup and download actions do not install packages. In particular, a
download `cache-hit: 'true'` does not represent an installed root. The install
action treats it only as a transfer optimization and still performs normal
lock, repository, payload, selected-engine, journal, and post-state checks. Repository
metadata, credentials, keyrings, roots, dpkg state, and journals are never
included in the package object cache.

The action README is the normative reference for:

- action-ref and CLI-version pinning;
- supported targets and the Node 24 runner requirement;
- token permissions and anonymous API behavior;
- provenance and explicit-SHA trust modes;
- archive and redirect defenses;
- exact cache keys and cache-hit reverification; and
- inputs, outputs, failure behavior, and examples.

The install action additionally documents alternate-root confinement,
explicit `sudo -n`, conffile/force policy, recovery-state preservation,
fail-closed offline behavior, legacy canonical transaction-result validation,
and native receipt versus unchanged-closure evidence before success outputs.

## Native-only cutover (#275 / #283 / #274)

The shipped defaults, checked-in bundles and documentation above are now
native-only (`transaction-backend: native`). The `actions-native-only`
security-policy check
(`zig-out/bin/debz-security-audit check actions-native-only <fixture.json>`)
evaluates **each** Action's metadata, TypeScript selector, checked-in bundle,
backend-capability output and native handoff. A fixture is a JSON object with
`"action": "download"` or `"install"` and `"overrides": {}`; missing override
paths are read from the checkout. Against this native-only release, **both**
checks pass with zero findings, and `zig build security-audit` tests negative
mutations against both Actions to prevent legacy regressions.

In the *single* post-parity #283/#274 cutover, change together:

- `actions/{download,install}/action.yml` transaction-backend defaults and
  accepted values, and `actions/{download,install}/src/inputs.ts` selectors,
  early legacy/v1 refusal and versioned active-recovery guidance;
- `actions/download/src/{action,runner}.ts` native v3 lock, v5 fingerprint,
  restore domain, preparation and capability output, plus
  `actions/install/src/{action,runner,subprocess,errors}.ts` native probe,
  nested download handoff, receipt/completion and unchanged result binding;
- both `actions/{download,install}/dist/index.js` bundles, reproducibly built
  from those sources (never copy one Action's bundle alone), their Action
  READMEs, this page, `doc/legacy-compatibility.md`, release examples and
  `security/legacy-cutover-policy.json` generated-contract inventory;
- `tools/security-audit.zig`'s shipped-mode Action/legacy checks and the
  `.github/workflows/{ci,release}.yml` Action, bundle and release gates.

Before claiming readiness, run both normal and candidate Action tests, both
deterministic `npm ... run bundle`/`git diff --exit-code -- actions/{download,install}/dist`
checks, and `zig build security-audit` with the cutover policy changed in the
same PR. #274 remains blocked on the four signed parity gates, #277 and #278;
this rehearsal does not relax any merge or release gate.

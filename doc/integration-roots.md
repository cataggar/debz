# Hermetic Debian-family integration roots

`zig build test-integration` builds a small deterministic repository, signs its
`InRelease` with the existing synthetic test-only OpenPGP key, and drives the
production CLI against disposable cache, state, and dpkg roots under
`.zig-cache/`. It never invokes apt against the host and never uses the host
dpkg database. Generated repositories are bounded to 8 MiB and contain no
network-derived input.

## Local prerequisites

- Zig 0.16.0 and liblzma development files;
- Python 3 with `cryptography`;
- `dpkg` for full/native lanes; native execution also requires Linux private
  mount-namespace privileges (use `DEBZ_INTEGRATION_SUDO=1` when needed).

Run one profile:

```sh
DEBZ_INTEGRATION_SUITE=debian-stable \
DEBZ_INTEGRATION_ARCH=amd64 \
DEBZ_INTEGRATION_MODE=smoke \
zig build test-integration
```

Accepted suites are `debian-stable` and `ubuntu-26.04`; architectures are
`amd64` and `arm64`; modes are `smoke`, `native`, and `full`. Full mode requires `dpkg`
and fails rather than skipping transaction assertions.
Refresh, planning, verified downloads, cache replay, payload validation, policy,
and reproducibility remain mandatory on every host. No qemu or foreign
executable is used. Foreign packages contain inert data only.
The native root's script-free helper fixture is reference-installed with
`dpkg --force-architecture` so foreign rows can seed its genuine package-owned
target. This is scoped to the disposable fixture root, not production native
admission or the host architecture database.

The core native planning lane resolves a real v2 lock, compares its repository
and package evidence with the legacy closure, verifies its independent digest
and backend-bound policy, and exercises cold download and cache-only replay.
It rejects v1 input and changed policy. A missing helper target refuses native
execution without changing package state or leaving an active root record.
The focused `native` mode and full lane use a real package-owned helper target
to exercise native install, exact-lock reinstall, no-op upgrade, retained-package
closure, receipt/evidence hashes, receipt-bound outer completion, and recovery
without repositories or cache/state access. A scripted package also exercises
automatically derived trigger authority, private helper invocation, coalesced
activation, and the final triggered postinst trace. This does not claim full
native transaction parity.

`zig build test-native-recovery` also compares the native public core CLI,
native package-family adapter, and reference dpkg across both signed fixture
suites. Its 28-row matrix covers Pre-Depends, versioned Provides, dependency
cycles, Recommends on/off, a Multi-Arch package, literal Linux package paths,
known inert control metadata, suite-specific trigger metadata,
upgrade-all, held unchanged updates, both conffile policies, and known script
failure. Plans must be identical for identical installed inputs; execution
compares payloads, package/trigger databases and script traces, then independently
checks retained native evidence and receipt-bound completion. The fixtures seed
a real package-owned helper target and require its bytes and inode to survive.
No-op results must not invent completion or provenance.

For a focused run, use
`zig build test-native-recovery -Dnative-consumer-parity-only=true -j2`.
It includes crash/restart cases around scriptless handler settlement, with
mixed scripted/scriptless handlers and original archives evicted before
recovery. Literal-path install/upgrade cases also cover filesystem publication,
completed file-trigger handlers, retained evidence, and refusal after a literal
conffile or retained old script changes during interruption. Upgrade recovery
compares staged old scripts with the original bound database, not the newly
installed version's metadata. The lifecycle runner separately compares literal
files, directories, hard links, symlinks and conffiles through install, upgrade,
reinstall, removal and purge with both conffile policies.
Known inert metadata additionally covers install/upgrade/remove/purge recovery,
binary retained blobs, exact modes and drift refusal. Lifecycle coverage checks
old/new control visibility, obsolete-member retirement, Multi-Arch stem changes
and failure/purge-retry behavior against dpkg.
The full required recovery jobs run this coverage in Debug and
ReleaseSafe on matching amd64 and arm64 runners. This is hermetic consumer
parity, not real vendor-snapshot acceptance or native-only production cutover.

## Support claims

The suite names identify fixture contracts, not downloaded vendor root
filesystems. Their signed repository identities and suite-marker versions
differ, so Debian and Ubuntu rows cannot collapse to aliases. PR CI requires
all four suite/architecture combinations in full mode on native amd64 and arm64
runners, including mandatory dpkg-root transactions. Scheduled/manual CI adds
foreign arm64 roots on amd64.

The repository exercises dependencies and Pre-Depends, alternatives,
versioned virtual Provides, Conflicts/Breaks/Replaces, Recommends policy,
Essential and Protected metadata, Multi-Arch, cycles, conffiles, triggers, and
a deliberately failing maintainer script. Full mode also injects cache
corruption. Transaction interruption, lock loss/contention, exact lock
verification, held-package policy, timeout, recovery-state transitions, and
atomic provenance publication use the production executor/recovery seams and
their mandatory Zig tests; they do not require unsafe process killing in a
black-box shell test.

Repository generation is byte-reproducible: fixed archive metadata, package
ordering, signing key, signature time, Release timestamps, and compressed
members produce identical repository and provenance digests. The Release
validity window is fixed from 2024 through 2037. CI retains full-lane root,
cache, state, and provenance artifacts for seven days.

The mandatory release-acceptance command is the manual `workflow_dispatch`
real-snapshot matrix in `.github/workflows/ci.yml`. It runs natively on
`ubuntu-24.04` amd64 and `ubuntu-24.04-arm` arm64 against
`https://snapshot.ubuntu.com/ubuntu/20260816T000000Z`, suite `resolute`,
component `main`, and the explicit Ubuntu archive keyring. Inputs remain
visible but validation rejects any value other than that reviewed snapshot.
Here "natively" describes the runner architecture: this snapshot lane still
uses the default legacy transaction backend, not native transaction execution.
Local runs may explicitly set `DEBZ_REAL_SNAPSHOT_KEYRING` to an absolute,
regular, non-symlink Ubuntu archive keyring instead of installing trust material
on the host. The authenticated lock must identify the reviewed Ubuntu 2018
archive signer `F6ECB3762474EDA9D21B7022871920D1991BC93C`. Workspaces must be new;
an existing root is never reused or reset by this script.

Each row uses the production CLI to authenticate metadata, resolve and review
an exact `ubuntu-minimal` closure lock without mutating a root, download and
validate every payload, create the dpkg root under that exact lock, reproduce
the install lock, and resolve a separate operation-bound lock for `upgrade-all`.
The pinned update must execute zero dpkg commands and preserve package status.
Its genuine legacy receipt is verified against the update lock, separately
from the verified install receipt; it is not a copy of earlier provenance.
Unlike a native unchanged result, this legacy replay can report `changed: true`
and publish a new receipt despite executing zero commands.
It verifies dpkg health,
provenance, native architecture, failure-before-mutation for a tampered lock,
and the absence of apt processes in the root. Metadata, package, total
download, disk, retry, command, and workflow limits are bounded. Evidence is
retained even on failure while package cache and staged root payloads are
cleaned.

Immediately before that cleanup, the workflow runs
`tools/capture-vendor-state.py` against the explicitly named staged reference
root. The architecture-tagged [v1 JSON
schema](../schema/vendor-state-inventory-v1.json) inventories every
`var/lib/dpkg/info` member by classification and bounded metadata/hash,
including `*.config`, `*.alternatives`, and all unclassified members. It also
inventories bounded regular records under `var/lib/dpkg/alternatives` and the
root-confined filesystem paths and symlink chains referenced by alternatives
state. Outside `etc/alternatives`, `etc` targets must be package-owned according
to captured dpkg ownership lists, while an unowned alternatives link must point
into `etc/alternatives`. Descriptor-rooted, no-follow traversal rejects races,
hard links, special files, cycles, undeclared link targets, traversal, sensitive
or ambient installation namespaces, malformed text, and every count, path,
integer, or byte-limit overflow. The capture records no file contents,
hostname, timestamp, environment, or absolute workspace path.

The reviewed amd64 and arm64 captures from workflow run
[`35500920816`](https://github.com/cataggar/debz/actions/runs/35500920816) at
commit `193887f0e45dc35a25768f8e58daa98318daddc9` are pinned under
`tools/fixtures/vendor-state/`. `index-v1.json` binds the immutable snapshot,
workflow run and jobs, source commit, downloaded artifact sizes and SHA-256
digests, manifest sizes and SHA-256 digests, capture schema version, and
inventory totals. Tests revalidate the manifests against the schema and
capture classifier, require canonical ordering and bounded totals, inspect
every recorded path, and reject credential patterns or ambient host
namespaces.

Each pinned architecture has 829 control members, 14 alternatives database
records, 189 requested linked paths, and 190 linked entries. The control
inventory includes seven `*.config` members and no `*.alternatives` or
unclassified members. Both architectures have the same classification counts,
alternatives records, requested paths, and linked-path topology; their
architecture-qualified control paths pair exactly, while expected package
metadata and ten linked executable hashes differ. These references document
observed vendor state but do not expand native production support: feature
guards for config scripts, alternatives, and unclassified vendor metadata
remain unchanged. The lane is manual because of bandwidth, but release
acceptance requires dispatching it successfully; it does not replace
deterministic PR CI.

The deterministic [vendor-state reference
specification](../schema/vendor-state-reference-v1.json) is committed as
`tools/fixtures/vendor-state/reference-v1.json`. It is derived only from the
two reviewed manifests and their index:

```sh
python3 tools/derive-vendor-state-reference.py \
  --index tools/fixtures/vendor-state/index-v1.json \
  --check tools/fixtures/vendor-state/reference-v1.json
```

The reference binds index SHA-256
`682bff167a4bc2386ceb78fb554be0adbe6fbfab16f4eab77aff3b63af04dd34`
and manifest SHA-256 values
`9ae81ea204a2cf608860451a41d477068a11ab77e8762e61e53d95bc0a70570b`
(amd64) and
`90698d5a1eae643dfc68a0acbb38cca48b98b297453fdc5d1a10509c792fa16c`
(arm64). Regeneration validates every source digest, canonical ordering,
count/byte/path bound, classification, requested-path resolution, symlink
target, and terminal linked identity before emitting canonical JSON.

The paired reference accounts for every item in each manifest. Of the 829
control members, 664 are already-supported typed package-database or lifecycle
state, 158 are bounded inert `templates`/`shlibs`/`symbols`, and the seven
debconf `*.config` scripts require reference-execution evidence. There are
zero package `*.alternatives` and zero unclassified members. The 14
alternatives records produce 72 current relationships (14 masters and 58
slaves), 189 complete requested-path resolutions, and all 190 linked entries:
145 symlinks and 45 regular files, including the inert
`etc/alternatives/README`. Each group records the observed record identity,
declared paths, master/slave selectors, selected target topology, and linked
path kind, metadata, target or digest. Package/provider ownership,
auto-versus-manual selection, priorities, candidate registration rows, and
mutation causality are explicitly `not-captured` or
`reference-execution-required`; none is inferred from names or hashes.

Cross-architecture pairing records all 422 architecture-qualified control
paths and the exact 275 control-content differences: 140 checksums, one
conffiles member, 28 maintainer scripts, 94 ownership lists, nine retained
metadata members, and three trigger members. Alternatives records and topology
are identical. Exactly ten regular linked targets differ in size and SHA-256.
Remaining oracle work is bounded reference execution for config-script
invocation/effects and alternatives record decoding plus install, upgrade,
remove, purge, failure, and recovery mutations. Until that evidence and an
explicit support contract exist, native preflight continues handing off or
rejecting active config/alternatives or unclassified semantics before
mutation.

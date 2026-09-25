# Pinned dpkg/update-alternatives reference

`tools/dpkg-alternatives-reference.py` is an executable reference for dpkg
1.22.22 and its `update-alternatives` 1.22.22 binary. Its reviewed boundary is
now admitted by the native alternatives implementation. Admission remains
limited to the pinned architectures, tool digests, bounded literal script
commands, typed canonical records, and authenticated root topology described
below; all state outside that boundary remains fail-closed.

The 2026-09-23 Ubuntu `stonking` amd64 snapshot has a separate executable
pin for `dpkg` 1.23.7ubuntu2. Its authenticated exact lock names the archive
SHA-512
`e2de124c6741eddc498badd81b0bf0fee0845e617d81e90ca8cb28dba16946cd23a193cc5e67dbc3dc50f3f9b0b6eab31318a9172b69282586d8bdc20fc9f19c`;
the archive's `usr/bin/update-alternatives` has SHA-256
`3e5fbdcf3b36bcfb7af1b406152c3a088acccc27c7b3e42d59ca0527a6259d9d`.
The installed file must still be root-owned, mode 0755, single-linked, and
exactly match that digest. This additional identity does not change the
dpkg 1.22.22 reference observations below or admit an arm64 snapshot tool.
Before `dpkg` is configured on a fresh root, its authenticated alternatives
README conffile can be staged as `etc/alternatives/README.dpkg-new`. Native
capture admits only this spelling and the existing `README` spelling with the
reviewed 100-byte SHA-256, root ownership, mode 0644, and one link. Both
paths remain in the managed script checkpoint; other staged names, unexpected
content, and metadata changes still fail closed.

The canonical result is
`tools/fixtures/vendor-state/dpkg-alternatives-reference-v1.json`, validated by
`schema/dpkg-alternatives-reference-v1.json`. It binds:

- the reviewed vendor index, amd64 and arm64 manifests, and derived reference;
- all 14 pinned group identities, 72 master/slave relationships, 189 requested
  paths, and 190 linked entries;
- the dpkg archives and architecture-specific dpkg and
  `update-alternatives` executable SHA-256 digests;
- deterministic synthetic package identities and archive bytes;
- the task invocation clock and the runtime clock/timestamp classification;
- every executed command, argument, exit, bounded output/log delta, package
  archive, relevant payload, status/journal file, control/info file, record,
  selector, and generic-link effect;
- every count, byte, path, file, process, cleanup, and timeout limit.

The common observation is stored once as the amd64 baseline. The reviewed
arm64 execution is represented by 190 sorted JSON-pointer replacements:
20 architecture fields, 64 architecture-derived encoded database values,
26 architecture-qualified dpkg log values, and their 80 SHA-256 values.
Applying those replacements reconstructs the exact 694,862-byte arm64
observation with SHA-256
`cf2b4f92399c2c19281d62b6ab1ea266cd85887263bc273ac8857fe507deae8f`.
The external `update-alternatives` observation and the dpkg/tool separation
result are byte-identical between architectures.

The reviewed vendor captures do not contain alternatives record bytes,
priorities, providers, ownership, or auto/manual mode. The executable vendor
projection therefore registers one synthetic priority-50 provider for every
pinned group and materializes every requested path. It proves the pinned names
and selected link topology without claiming to reconstruct unavailable vendor
database state.

## Hermetic execution boundary

The runner requires root only for direct dpkg maintainer-script execution. It
uses guarded disposable roots under repository-local `.tmp`, the hash-pinned
private tools under `.cache`, a fixed `C` environment, bounded subprocesses,
and no apt/debconf frontend. The benign host dpkg configuration is digest-bound;
configuration fragments and user configuration are forbidden. External tool
calls always provide `--root` and a root-local log. Maintainer scripts execute
the same pinned `/usr/bin/update-alternatives` inside the disposable chroot,
assert cwd `/`, descriptors 0/1/2 only, and reject frontend variables. Output
is streamed into size-limited files rather than accumulated in memory.
Subprocesses have a 30-second runtime bound, a two-second process-group cleanup
bound, a 64-descriptor limit, and complete process-group termination on
timeout. The copied chroot binary and both selected private binaries are
digest-verified.

Before every run, the oracle inventories the complete host dpkg database plus
host alternatives database, every generic link named by those records, the
selector directory, dpkg configuration, dpkg log, and alternatives log. The
inventory is checked in `finally`, including failed oracle runs, so no host
mutation can be hidden by an observation exception. No ambient host dpkg
executable is used to identify the architecture.

Prepare and run the reference:

```sh
reference_dpkg="$(python3 tools/prepare-native-dpkg.py --architecture amd64)"
zig build test-dpkg-alternatives-reference \
  -Dnative-reference-dpkg="$reference_dpkg" \
  -Dnative-reference-architecture=amd64 -j2
```

The canonical execution covers amd64 and arm64. The arm64 result was captured
by `CI` run `35526836596`, job `106120369829`, from source commit
`f3132ef5fa554b7bbfbfa73a84983632bd08ff68` on `ubuntu-24.04-arm`.
The opt-in `run_arm64_dpkg_oracles` target passes the architecture explicitly,
verifies the downloaded archive and private binaries against the pinned
digests, hides host dpkg configuration and fragments inside a private mount
namespace, executes both references with an empty inherited environment, and
uploads only canonical bounded observations plus their execution-evidence
manifest. The manifest and artifact bindings, invocation clock, exact compact
architecture differences, tool sizes, and receipt digest are retained in the
canonical JSON.

## External `update-alternatives` behavior

For a normal group, the administrative record is a root-owned `0644` regular
file. Its exact line format is:

1. `auto` or `manual`;
2. the master generic link;
3. pairs of slave name and generic slave link, sorted bytewise by slave name
   regardless of command-argument order;
4. a blank line;
5. for each candidate, the candidate path, signed decimal priority, and one
   target line per declared slave;
6. a final blank line.

Candidate rows are stored in bytewise path order. Generic and selector links
are root-owned `0777` symlinks. Generic links target
`/etc/alternatives/<name>`; selectors target the selected provider bytes.
Record bytes, order, sizes, SHA-256, modes, uid/gid, and every symlink target
are in the canonical observation.
When a registration adds a slave, existing candidates retain their targets
by slave **name**, not by their former position in the record; a candidate
without that slave has an empty target line. Both pinned 1.22.22 and snapshot
1.23.7ubuntu2 tools produced the same sorted record in a two-provider probe
that inserted `b-man` between existing `a-man` and `z-man` slaves (record
SHA-256 `0b7c0ad2bb53aaab05bd57d81db15dcee652a89a7e677ba6c8eb5c9dfef746bb`).

Selection behavior is exact:

- the first provider selects automatically;
- registering an equal-priority provider does not displace the current valid
  selection;
- recomputing an equal-priority tie after removing the higher provider selects
  the first stored candidate path;
- `--set` writes `manual` and changes all master/slave selectors;
- later higher-priority registration does not displace a manual selection;
- `--auto` selects the highest priority;
- removing the final candidate or `--remove-all` removes the record, selectors,
  and generic links.

A missing master provider is rejected with exit 2 before registration. A
missing slave target can be recorded and linked. Re-registering the selected
provider with a changed slave set rewrites the group and removes obsolete
slave links. A read-only `--query` warns about a now-missing selected provider
and computes an in-memory fallback but does not persist the pruned record.
The mutating `--auto` prunes missing candidates and removes an empty group.

Empty, truncated, invalid-mode, invalid-priority, and embedded-NUL regular
records have bounded, canonical exit-2 diagnostics. The oracle refuses
oversized, directory, FIFO, and symlink records before invoking the tool.

Raw adversarial rows are retained separately from the safe command wrapper:
1.22.22 accepts a generic path containing `/../` and creates a link outside
the selected root, and it follows a symlink used as `etc/alternatives`. A
self-referential provider is rejected. Replacing an already selected provider
with a symlink back to its generic link creates an indirect cycle; `--query`
warns that the provider is missing and computes an in-memory removal without
persisting the record or links. Normal oracle execution rejects unsafe generic
paths and state-directory symlinks before spawning the tool.

The database and link set are not one atomic filesystem transaction. The
explicitly labeled injected cases block the database temporary, selector
temporary, or generic-link temporary. They make the command exit 2 with no
committed group record, but can strand an
`atomic.dpkg-tmp` selector symlink. The alternatives log still says the link
group was updated. These partial states and diagnostics are canonical and must
not be approximated as an all-or-nothing commit. They are failure models, not
claims that the vendor tool spontaneously produced those failures.

Log timestamps come from local `CLOCK_REALTIME` at one-second precision and
are asserted to fall within the subprocess invocation. Record mtimes use the
filesystem clock at rename; link mtimes are set to the whole-second invocation
time. Those unstable values are classified rather than frozen.

## Direct dpkg behavior and package lifecycle

Direct dpkg does not invoke `update-alternatives` implicitly. A package
`DEBIAN/alternatives` member containing opaque bytes, including NUL and
non-UTF-8 bytes, is copied exactly to
`var/lib/dpkg/info/<package>.alternatives` with its `0640`, root-owned
metadata. It creates no alternatives group. For the scriptless fixture the
member is deleted on remove and no package row or info file remains; purge is
then a no-op.

The scripted fixtures isolate external-tool causality:

- install registers version 1 after unpack and finishes `installed`;
- reinstall runs old `prerm upgrade`, incoming `preinst upgrade`, old
  `postrm upgrade`, then new `postinst configure`, removing and re-registering
  the same provider;
- upgrade performs the same sequence and selects version 2;
- remove unregisters in `prerm`, then leaves only `list` and `postrm` with a
  `config-files` status row;
- purge runs `postrm purge` and removes the final status/info state.

Two packages can register distinct providers for one group. Automatic mode
selects the higher priority, removing that package falls back to the lower
provider, and removing the last provider deletes the group. A separate pair
shipping different bytes at one payload path fails in direct dpkg before the
second package can configure; the first owner's bytes and database row remain
unchanged and no alternatives update is invented.

Failure and recovery boundaries are also external side effects:

- a fresh or upgraded `postinst` that registers and then fails leaves the new
  group selected with package status `half-configured`; `--configure` retries
  and settles it;
- an old upgrade `prerm` failure after unregistering is handled by dpkg's new
  `prerm failed-upgrade` fallback, after which unpack/configuration succeeds
  and the new provider is registered;
- a failing remove `postrm` leaves status `half-installed`, retains the full
  old info set, and leaves the group absent because `prerm` already removed
  it; retry reaches `config-files`;
- killing dpkg after `postinst` registers leaves the group committed while the
  package exists only in the nonempty `updates/` journal as
  `half-configured`; recovery publishes `installed` status and clears the
  journal.

Thus dpkg status/info durability and alternatives durability are separate.
Dpkg only compensates an alternatives update when a maintainer script invoked
during unwind explicitly performs that inverse operation.

## Native admission

`src/native_alternatives.zig` implements the bounded record grammar,
canonical writer, selection transitions, master/slave topology, native-owned
root-mutation settlement, and exact amd64/arm64 tool bindings. Native lifecycle
execution retains opaque package `.alternatives` bytes but interprets active
`var/lib/dpkg/alternatives` records as typed state.

Before a maintainer script containing a literal direct
`update-alternatives` command line runs, the engine verifies the root-local
tool digest, discovers the complete bounded command authority, captures all
existing groups plus authorized new groups, and durably checkpoints database
directories, records, selectors, generic links, provider chains, and target
identities. The admitted shell shape is intentionally narrow: only the direct
tool command, an optional literal `case` label, and an optional terminator are
accepted. After a normal script return it captures again, requires provider
and tool inputs to remain identity-exact, rejects changes to unmentioned
groups or topology outside the command authority, and checkpoints the exact
new state before the script outcome can complete. Unknown outcomes, partial or
malformed state, external drift, comments or wrappers that merely mention the
tool, extra shell tokens, dynamic shell construction, unpinned tools, extra
groups, cycles, traversal, special files, or changed identities require
recovery without repair or replay.

The authenticated `stonking` amd64 `less` 668-1build1 archive (SHA-512
`957502bf7fc7f49b0e146362e9c4bdf094c6c93fcca25dd1a47f47c6f17dec5b525f793c87ea03867411039ebef402a85f702766cd7c46d916beb53c81f0da45`)
ships a 292-byte `preinst` (SHA-256
`c72b2f152d56cae58b8f39efe22e6f0d85d676c4ac3060f40cfe0c463f1f8d94`).
Its sole alternatives command is the literal
`update-alternatives --quiet --remove pager /bin/less` under `upgrade)`.
The snapshot-pinned tool documents `--quiet` as an output option. An isolated
`--root` probe of that exact binary found that removing the sole `/bin/less`
`pager` provider with or without `--quiet` deletes the same record and links;
the executable reference covers the same typed `--remove` transition.
Only these exact script bytes and command are recognized with `--quiet`; no
other wrapper, option, or command receives that authority. Native execution
admits this script only as the **new** `less:amd64` preinst with exactly
`["install"]` on amd64. This branch cannot call the tool, so the existing
`pager` group is immutable across its pre/post checkpoints. The installed
`update-alternatives` binary must match the **snapshot** amd64 pin above
(not merely the older amd64 oracle pin), with root-owned executable metadata.
Upgrade/abort and other identities remain refused rather than relying on the
unreviewed upgrade branch's `dpkg --compare-versions`.

The same authenticated archive ships a 374-byte `postinst` (SHA-256
`a33a1e6ef5a22e63a66e42853fc0bcff3107b4653d7b5cea891354a5f28db6c4`).
Its only alternatives command, in the `configure)` branch, is
`update-alternatives --quiet --install /usr/bin/pager pager /usr/bin/less 77 --slave /usr/share/man/man1/pager.1.gz pager.1.gz /usr/share/man/man1/less.1.gz`.
In a disposable root, the exact snapshot-pinned executable registered an
auto-selected `pager` group at priority 77 with that slave and links; its
record and selectors match the pinned reference's typed `--install` model.
Native admission binds the complete script SHA-256, exactly these literal
tokens (including `--quiet`), the **new** `less:amd64` 668-1build1 postinst,
exactly `["configure", ""]`, and the snapshot amd64 tool digest and metadata.
Unlike the preinst's inert install branch, this configure branch may register
the group, subject to the existing before/after checkpoints, immutable
provider and tool identities, and reachable-transition validation. Other
scripts, options, source identities, arguments, and tool digests remain
refused. The interrupted root that exposed this refusal is not reused; no
full install or native/reference parity is inferred from authorizing it.
A separate authenticated fresh-root replay persisted a zero-exit postinst
outcome and the expected `pager` record and links at step 888, then refused
an unrelated `bash.postinst` `update-alternatives --install ... || true`
script at step 976 before launch.

The same signed amd64 snapshot's `bash` 5.3-3ubuntu1 archive (SHA-512
`05fc4be7d1457e8e853a04c259d73c2c16de18154275612051f0d8efd6d4ec74c23f85b80c6a60c11e217aa4756a6a27650dd03502733b53141ac69c0732d3b4`)
ships a 492-byte `postinst` (SHA-256
`e9afaa3227a21e68002bd60a88e054d8f98d2d0e548d1d690c9bba5c3c9577ff`).
It invokes the literal `update-alternatives --install
/usr/share/man/man7/builtins.7.gz builtins.7.gz
/usr/share/man/man7/bash-builtins.7.gz 10 || true`, split over shell
continuations. In the refused fresh root `/bin/sh` already points to `dash`,
the candidate exists, no `builtins.7.gz` group exists, and `update-menus` is
absent. The maintainer script runs even for other postinst arguments, so
native admission is restricted to the observed **new** `bash:amd64`
`postinst` with exactly `["configure", ""]`.

A disposable chroot probe with the signed script and pinned dpkg 1.22.22
configured a synthetic fixture both when the candidate was present (the
priority-10 auto group was registered) and when it was missing (the tool
reported an error but `|| true` left dpkg exit 0 and no group). The
snapshot-pinned amd64 tool independently returned 0 with the provider and 2
without it, producing the same typed group/absence. Only the complete
authenticated script digest and these exact command tokens allow the
`|| true` tail to be excluded **from operand parsing**. The script itself
still runs unmodified; its actual exit, output, immutable provider/tool
identities, group transitions, managed checkpoints, and unknown-outcome
recovery are not suppressed. No other use of `|| true`, architecture, tool
digest, package, source, or arguments gains authority. This does not prove
full fresh-root parity. A new authenticated root did persist the `bash`
postinst's zero-exit outcome and priority-10 `builtins.7.gz` group at step
976, then stopped after launching `netcat-openbsd.postinst` at step 1026:
its three-slave registration returned a state outside the existing typed
transition model. The interrupted root remains a recovery case, not a
completed parity result.

The authenticated amd64 `netcat-openbsd` 1.238-1 archive (SHA-512
`c4d9b42055c0b9473c40a93205de115c104b79fdd51a9a8c1728d4e09ba1766fbb9bc7375abdea5fb68a0f0be7de338d8e86039f827b0a51852c99f4bb5fbe58`)
ships a 414-byte `postinst` (SHA-256
`81abc862db99e322e5d6cda436769bc21b9394ce287ea35d057761b6313cb6ef`).
With `["configure", ""]`, its literal `--install` registers `/bin/nc`
as group `nc` at priority 50, with slaves in script order `netcat`,
`nc.1.gz`, `netcat.1.gz`. The before-script checkpoint had no `nc` group or
links, but did contain the immutable `/usr/bin/nc.openbsd` provider. A
disposable pinned-dpkg 1.22.22 chroot configured a synthetic package with
the exact authenticated script; the resulting record (SHA-256
`2d38af8c8cc5565fd092c8e7b09cb8517eb5347616141b3e7d92034386671c4e`)
and all eight selector/generic links match the interrupted native root.
The snapshot-pinned tool independently wrote the same bytes and links. Both
sort the slaves as `nc.1.gz`, `netcat`, `netcat.1.gz`, which was the sole
discrepancy with the native typed transition: it had retained script order.
The native writer now sorts slaves by name and maps existing candidate targets
by name; exact transition, provider/tool identity, and durable script-outcome
checks remain in force. This is a normalized record-model correction, not
new script authority or an exception for altered state. The interrupted root
cannot be retried as a fresh root.

In a new authenticated 175-package amd64 root, the exact netcat postinst
persisted an exit-0 outcome at step 1026, and the resulting 221-byte record
and eight links again matched the pinned reference. Installation then refused
**before launching** the unrelated `procps.postinst` at step 1065: its
`check_alternatives` shell function constructs several alternative commands
from variables, outside the reviewed literal-command grammar. That root is
retained for recovery; neither the netcat success nor the later refusal
establishes full installation or native/reference parity.

The next script is the authenticated `procps:amd64` 2:4.0.6-3ubuntu1
`postinst` (3,559 bytes, SHA-256
`7c2ba424ad233bd238474b9d6e565a719fbd6902fd75f617bc3e6e915084c9d3`)
from archive SHA-512
`1e9ae9a5912c64c42dcfa5582f04c4bcda21261f7c98dfc45110e2a413666998b5eedfc9f0e53c794b2f7227762f7dd17976572d4b223aa3669e5c4280e15cbf`.
For `["configure", ""]`, its shell function is called only with the four
literal triples `("uptime", "/usr/bin", "1")`,
`("vmstat", "/usr/bin", "8")`, `("w", "/usr/bin", "1")`, and
`("ps", "/bin", "1")`. Each call tests readability of its corresponding
`<binpath>/<name>.procps` provider **before** its parameterized
`update-alternatives --install` command. None of those four providers exists
in the signed fresh-root checkpoint or the signed package payload. In a
disposable copy of that root, pinned dpkg 1.22.22 configured the **exact
signed** script with exit 0 and no new alternatives group. As a negative
control, staging a readable `uptime.procps` in another disposable copy made
the same pinned dpkg execute the conditional command and create an `uptime`
record; this is not an authorized native transition.

Native admission does **not** parse or execute variable-generated
alternatives operands. Only this script digest, the new
`procps:amd64` postinst, exact version and configure arguments, and the
snapshot amd64 alternatives tool are bound. All four providers must be
absent before launch and remain absent after the script; every existing
alternatives group must remain unchanged and no group can appear or disappear.
Their missing-path facts, tool identity, records, and links stay in the
managed before/after checkpoint. If any provider is present, authorization
fails **before** running the script. Script failures and unknown outcomes
still require the normal recovery path. No other variable expansion, script
branch, architecture, or tool digest gains authority.

The new authenticated amd64 root persisted the exact `procps.postinst`
step-1065 outcome with exit 0 and no `uptime`, `vmstat`, `w`, or `ps`
alternatives group. It later refused **before launching** the unrelated
`sudo-rs.postinst` at step 1145 with `PartialAlternativesState`: the group
`sudo` was absent, but the proposed `sudoedit` slave's generic
`/usr/bin/sudoedit` already existed as a `sudo` package-owned symlink to
`sudo.ws`. This partial-state refusal does not grant authority to replace
that symlink, nor does the earlier procps success establish full parity.
The new failed root is retained for recovery.

External tool execution intentionally retains the oracle's observable
non-atomic failure boundary. When native code itself owns a record/link
transition, the complete database-plus-selector-plus-generic-link intent set is
lowered into the versioned root-mutation journal, with fixed ordering, backups,
parent fsyncs, exact verification, and crash recovery.

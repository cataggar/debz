# Pinned dpkg/update-alternatives reference

`tools/dpkg-alternatives-reference.py` is an executable reference for dpkg
1.22.22 and its `update-alternatives` 1.22.22 binary. Its reviewed boundary is
now admitted by the native alternatives implementation. Admission remains
limited to the pinned architectures, tool digests, bounded literal script
commands, typed canonical records, and authenticated root topology described
below; all state outside that boundary remains fail-closed.

The same `tools/prepare-native-dpkg.py` receipt also binds the sibling
`dpkg-query` 1.22.22 binary for test-only fresh-root and
[imported-then-mutated query parity checks](native-lifecycle.md#read-only-imported-root-query-oracle). That
pin does not admit a production `dpkg-query` dependency or broaden the separate
signed-maintainer-script exception.

The 2026-10-01 Ubuntu `resolute` snapshot, signed by
`F6ECB3762474EDA9D21B7022871920D1991BC93C`, has separate executable
pins for `dpkg` 1.23.7ubuntu1. Its authenticated exact locks name the amd64
archive SHA-512
`3d6a718ca8d51387c3cdfc432dd6fa533976f6d9ab6455b397f1c3cbfec12c1ce3293e00d37009602c309c353a42d25057f021c98d78d5947d8de021fb83400d`
and arm64 archive SHA-512
`824a6a3f33837c16dedb4faff92bd15b0dbe82d27dd9b25403f87ec4572acc6332159a6374558185ca503e18de6f637d2a79e7db9fafaab3ccae4ac77427eee5`.
The archives' `usr/bin/update-alternatives` files are architecture-specific
ELF executables: amd64 SHA-256
`023e1c2eef9f323f6f2c2f53aa22092cd118b1f087349ce133a677f94a03ed45`,
arm64 SHA-256
`dae71fcd81f5373b8f1c19b300d10317dd3d323f577b7e5a45a50301fa217807`.
The installed file must still be root-owned, mode 0755, single-linked, and
exactly match the target architecture's digest. These snapshot identities do not
change the dpkg 1.22.22 reference observations below; the real-snapshot
acceptance wrapper also binds the separate arm64
`dpkg`/`dpkg-divert`/`dpkg-statoverride` identities.
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
- the dpkg archives and architecture-specific dpkg, test-only `dpkg-query`,
  and `update-alternatives` executable SHA-256 digests;
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
1.23.7ubuntu1 tools produced the same sorted record in a two-provider probe
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

The authenticated `resolute` amd64 `less` 668-1build1 archive (SHA-512
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

The byte-identical signed ARM less postinst has a separate native guard for
fresh `less:arm64` 668-1build1 `postinst/new_package` with exactly
`["configure", ""]` and a script action. Its source is not borrowed from amd64:
the retained original ARM archive binds the controls, `/usr/bin/less` and its
manpage; the independent dash, update-alternatives, loader and libc sources,
aliases and unchanged ownership list are checked before and after execution.
Loader cache/preload/hwcaps, shadow tools and nonempty proc remain forbidden.

The mandatory hosted ARM protected target retains the eight preinst roots and
adds native/pinned-dpkg configure roots plus five postinst refusal roots.
It invokes the actual production `maintainer_script.run`/`SystemLauncher` with
the original script and lifecycle policy, checks immutable inputs and the
reachable transition, and compares the full alternatives inventory with a
separate pinned-dpkg configure. Missing coordinates or proof receipts fail;
local unit compilation is not protected acceptance. This bounded callback does
not establish subsequent ARM callbacks, full-root parity or Python-free cutover.

The same signed amd64 snapshot's `bash` 5.3-3ubuntu1 archive (SHA-512
`05fc4be7d1457e8e853a04c259d73c2c16de18154275612051f0d8efd6d4ec74c23f85b80c6a60c11e217aa4756a6a27650dd03502733b53141ac69c0732d3b4`)
ships a 492-byte `postinst` (SHA-256
`72dfde3dbe58a2eb3766ac52a485626b27213cd9b6fa7b14705cde793620343d`).
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
`3dbc0b33e45028e59dca33a1f29e41cba3aebe369b6d67a2e26c40ef8ce383b8`)
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

The signed `sudo-rs:amd64` 0.2.14-1ubuntu4 archive (SHA-512
`61360abddf8f4f8101bed23bd4a8308ae5d3afa33b812d0b7c9443cf8b6671b23ce572568198bfc06eb0a6200d8faf3d10b631d409f9ee17ab084bd3fd835189`)
ships the exact 2,100-byte `postinst` (SHA-256
`8204660f7a77c449041d3639d1075d96e76aeda3050fc0ad7780e9c4cc9a69c0`).
For `["configure", ""]`, it calls `set_perms root root 4755` on both
`/usr/lib/cargo/bin/sudo` and `/usr/lib/cargo/bin/su`, then invokes a literal
`update-alternatives --install /usr/bin/sudo sudo /usr/lib/cargo/bin/sudo 50`
with six literal slaves. The earlier `sudo:amd64` 1.9.17p2-7ubuntu3
archive (SHA-512
`7c7d957235034e0b60e9b83e511a925966fbb52b0f758ea68538cecfecf37e57f75bc4415ebba6202ac744cf8aa257e6be7a225803fa14af58cb7e2c1625484d`)
owns **two** existing generic symlinks:
`/usr/bin/sudoedit -> sudo.ws` and
`/usr/share/man/man8/sudoedit.8.gz -> sudo.ws.8.gz`. The exact signed
`sudo.list` (SHA-256
`39fe94bdbeab0a80b3aaeae4cfa258be578949b791aeb06875ddf9d488387bc8`)
claims both; the proposed `sudo` group, record, selectors, and all other
generic links are absent.

In disposable copies of the interrupted root, receipt-verified pinned dpkg
1.22.22 configured the script successfully: its snapshot-pinned
`update-alternatives` replaced **both** package-owned generic symlinks with
links into `/etc/alternatives`. The new 464-byte `sudo` record (SHA-256
`4f50d77a8e6f76e51745762486caec36324433ea7b09aac48274624c70e46da6`)
registers the `/usr/lib/cargo/bin/sudo` candidate at priority 50 and sorts
all six slaves by name. A separate probe confirmed that the `chown`/`chmod`
calls change only the ctime of `sudo` and `su`; their inode, content, mode
4755, uid/gid, link count, size, and mtime remain unchanged.

Native admission binds the complete script digest, new-package amd64
`sudo-rs` identity, exact configure arguments, snapshot tool, both signed
archive identities, the signed `sudo.list`, and signed `sudo.ws` target
identities. Only the two root-owned `0777`, single-link, exact-target
package-owned generic symlinks may preexist in this **absent** group. The
record, selectors, and other generic links must still be absent; missing
or changed structural links refuse before launch. The only relaxed
immutable-provider facts are the ctimes of the two signed setuid cargo
binaries, and all their other facts remain exact. The original script and
its exit semantics, typed reachable installation, other groups, checkpoints,
and unknown-outcome recovery remain unchanged. The interrupted root was not
reused. A separate newly authenticated 175-package root persisted the exact
signed `sudo-rs.postinst` exit-0 outcome at step 1145; its `sudo` record
matched the 464-byte pinned dpkg reference digest above, and both structural
links became the expected generic links into `/etc/alternatives`. A further
fresh root on final #241 squash plus the sudo-rs change independently
reproduced that exact signed outcome and record; see
[integration roots](integration-roots.md). This is step-1145 evidence, not a
claim of full fresh-root parity: the run later
required recovery on a distinct `libpam-runtime` case-alias unpack at
step 1173, documented in the [integration root
log](integration-roots.md#hermetic-debian-family-integration-roots).
The new failed root is retained for recovery.

The later signed `sudo:amd64` `1.9.17p2-7ubuntu3` postinst (1,927 bytes,
SHA-256
`fd4c65932ab3ab7ce90c3633c42b8ee7a36af2c8292142d6e0cd134dda4c6383`)
encounters a different boundary. Its previously registered 464-byte
priority-50 `sudo-rs` group and selectors still exist, but signed sudo
unpack restores `/usr/bin/sudoedit -> sudo.ws` and
`/usr/share/man/man8/sudoedit.8.gz -> sudo.ws.8.gz`; the record still selects
`/usr/lib/cargo/bin/sudo`. Both links are authenticated sudo-owned,
root-owned mode-0777 single-link symlinks. The before-capture therefore
admits **only these two exact structural links** for the exact new-package
sudo configure script, after pinning the already reviewed sudo and sudo-rs
archive identities and signed sudo provider bytes. Its after-capture uses
the strict ordinary generic-link rules, and the normal transition checker
must prove the literal priority-40 sudo candidate with all six slaves;
other groups and records remain immutable. The former parsed-record
`errdefer` after transfer caused a general-protection exception when a
capture rejected the structural link. Its ownership is now transferred
once, so rejection remains a typed error and never silently succeeds.

Independent root-owned disposable copies of an authenticated pre-udev
capture were aligned **only** by restoring the two exact signed sudo
payload links; the separately aborted step-1376 root was read but never
copied or reused. All 14 alternatives record hashes, selectors, signed
postinst and `sudo.conf` matched the retained pre-sudo evidence. Pinned
dpkg 1.22.22 and the exact signed script both exited 1 with no `/proc`,
before invoking `update-alternatives`, due to `systemd-tmpfiles`. On two
new copies with private chrooted PID 1 and read-only
`nosuid,nodev,noexec,hidepid=2,subset=pid` procfs, `/proc/sys` absent
and `CAP_SYS_ADMIN` dropped, each exited 0. Both installed the same
658-byte `sudo` record, SHA-256
`c583a377d2d7bc241422c91f43738f8e278e159e8e3bb2aa53d5bdeaf782e845`,
retained priority-50 `sudo-rs` as selected, repaired both generic links
into `/etc/alternatives`, and created root-owned mode-0711 `/run/sudo`.
An additional signed-script copy normalized only sudo's status to the
native `installed` prestate and produced the same exit 0, record and links.
Each private mount disappeared on exit. This independently verifies
the state repair and the *separate* exact sudo proc requirement; it is
not evidence for borrowing a host proc or admitting arbitrary commands.
A newly authenticated protected 175-package root subsequently persisted
signed sudo.postinst step 1376 exit 0 and installed status with that exact
record and both repaired generic links. It later refused the unrelated
python3 preinst before launch at step 1383 with `InvalidAlternativesScript`;
the failed root is retained, never reused for a second installation.
These local diagnostic results predate the final #252 squash and the
subsequently pinned sourced `dpkg-error.sh` fragment; they are not the
combined-tree publication proof. `tools/real-snapshot-sudo-reference.sh`
repeats the pinned dpkg 1.22.22 comparison from a root-owned checkout,
mode-0700 fixture directory and independently copied authenticated
pre-sudo diagnostic source. It refuses writable or symlinked ancestry,
changed signed controls and unpinned dpkg, then restores only the two
literal signed sudo payload links in a **new disposable diagnostic copy**,
matching the pre-postinst unpack state. It executes only that copy with
private PID-only procfs and no `/proc/sys`. The diagnostic source is
unchanged and no failed native installation is retried.
On final #252 squash plus sudo-only source `898d81e`, the protected
disposable pinned-dpkg proof exited 0 and installed sudo. Independent
protected Debug and ReleaseSafe signed-script tests generated the same
658-byte record **byte-for-byte** and refused all four altered, missing,
symlinked or post-binding-changed sourced-fragment fixtures. A separate
new authenticated 175-package native root then recorded signed sudo
step 1376 exit 0 and installed with the same record and repaired links;
the first later refusal was python3 preinst step 1383 before launch.
The exact root paths, lock and CAS rehash are in
[integration roots](integration-roots.md#hermetic-debian-family-integration-roots).
This verifies only sudo's signed transition, not full installation parity.

The separate signed `python3:amd64` `3.14.7-3` archive (SHA-512
`616bc16aa40a486075b987804a735a7c9e1873ad151564d057452761e31377b93451f00d2f82fcbccd6b2edd32dbaaeba14e6862a6a5192229a37e66fe61f6aa`)
ships an 856-byte preinst (SHA-256
`115f972bfeb85d083537b4d7fc59261979c6a2511d85b84407c7d7da38c9a85f`).
For exactly `["install"]` its alternatives line is
`update-alternatives --auto /usr/bin/python3 >/dev/null 2>&1 || true`;
the `upgrade)` hooks are unreachable. The `/usr/bin/python3 -> python3.14`
link belongs instead to signed `python3-minimal:amd64` `3.14.7-3` (archive
SHA-512
`e45a8b4d3ee89c9c30f3c2a31af1dfc5600dd4a541f4fcf42abb4946870076ad2dfa3a629699aa204d77db9d17ae58529eee5202cd6e89f8af14a5a9ec9b96a5`).
There is no `python3` alternatives record or selector, and
`/usr/share/doc/python3/html` is absent. Both pinned dpkg 1.22.22 and
snapshot 1.23.7ubuntu1 `update-alternatives`, invoked with `--root` on a
protected disposable root, return **2** with `alternative name
(/usr/bin/python3) must not contain '/' and spaces`, without touching that
root. This is an invalid *name*, not a valid `--auto python3` transition.

Independent protected copies of the authenticated prestate, never of the
interrupted step-1383 root, proved the exact signed script `install` exits
**0** and pinned dpkg 1.22.22 invokes its signed preinst with exactly
`( install )` and unpacks successfully. For the pinned-dpkg probe only,
`--force-depends --purge python3` first removed that package in its own
disposable copy; the subsequent signed-archive unpack used no force option.
The 14 alternatives records and 76 selectors remained byte-for-byte
identical on both copies (record inventory SHA-256
`0c962b7820400c8c06efe34493c58c04925d87a5ee556fe8cc4a4be93d81a99c`).
The signed minimal link and absent HTML path remained unchanged. Since
this fixture's `/dev/null` is a root-owned mode-0600 empty **regular file**
instead of a device, the signed script's redirection produces the same
96-byte diagnostic in both independent copies (SHA-256
`3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc`).
The refused root had the exact empty-file prestate.

A first separately authenticated fresh 175-package root reached
python3 step 1383 and refused before launch: its empty, root-owned
regular `/dev/null` was mode **0644**, not the 0600 of the earlier
proof and refused roots. Its action stayed `prepared`, with no outcome.
Independent protected 0644 disposable copies (never of the interrupted
root) established that the signed script `["install"]` and pinned dpkg
1.22.22 signed-archive unpack both exit 0 and preserve that mode, all
14 alternatives records and all 76 selectors, and yield the same
96-byte diagnostic. The pinned-dpkg copy required fixture-only python3
purge before no-force unpack; the script copy did not. A read-only
guard test also accepts the interrupted root's actual 0644 prestate
without executing its pending script. Only those two proved file modes,
0600 and 0644, are admitted; 0640 and 0666 are explicitly rejected.

Native admission models **no alternatives command** for only this complete
signed script's new-package amd64 `preinst ["install"]`. It binds both signed
archive identities, the installed and any staged script, signed ownership
lists and minimal link, root and doc-directory identities, exact shell/GNU
`rm` aliases and bytes, absent `/usr/sbin` shadows, absent HTML target,
empty `/proc`, empty guarded regular `/dev/null` at mode 0600 or 0644,
and the snapshot-pinned `update-alternatives` binary. All preexisting
groups are immutable across
the normal managed before/after checkpoints. An exit-0 script must also
leave the reference-exact 96-byte diagnostic in `/dev/null` before its
outcome can be persisted; a mismatch requires recovery after mutation,
never a success-shaped fallback. No generic redirect, `|| true`,
absolute-name, or upgrade grammar is added. The script's own exit remains
authoritative.

An earlier newly authenticated protected 175-package root from a local
branch **also containing unpublished procps-trigger admission** used the
corrected ReleaseSafe binary (SHA-256
`9a0c3641daa87f832233b0e6913f2cbf7a25a0fda9fed47aa91ee4cde163fa61`)
durably persisted the exact signed python3 preinst at step 1383 with
`spawned=true`, exit 0, no output and `succeeded`; python3 is installed.
Later scripts changed the `/dev/null` file again, so its *final* bytes
are not evidence for the preinst witness; admission checked its contents
before persisting that signed outcome. All seven deferred trigger scripts
also exited 0, but `libglib2.0-0t64:amd64` remained self
`triggers-awaited` for its schema trigger. Final closure verification
refused with `final_closure_mismatch` (exit 8). This is a later distinct
blocker on that local combined branch, not a prediction for final main plus
python3 alone, completed installation, or authority for trigger changes.

On the final #253 sudo squash plus **only** the python3 delta, a separate
root-owned protected checkout at
`/var/lib/debz-python3-reference-253/checkout` repeated the pinned dpkg
1.22.22 comparison with `tools/real-snapshot-python3-reference.sh`. Its
independently copied pre-sudo diagnostic source, not a fresh native trial,
had the signed 856-byte preinst and root-owned empty regular `/dev/null`.
The reference helper checks protected ancestry, pinned dpkg's receipt,
the SHA-512 python3 archive against the newly signed 175-package lock,
signed installed script and minimal-list bytes, the pinned alternatives
tool and minimal symlink, and a previously absent HTML target. Separate
disposable copies with `/dev/null` modes 0600 and 0644 each showed the
signed script's `install` exit 0 and pinned dpkg's no-force archive
unpack after fixture-only purge. Both retained the same 14 alternatives
records and 76 selectors (combined fingerprint SHA-256
`9f7ace1de86e778a42d5f69175689429211c72e442447c367e79f718443da3be`)
and the same 96-byte diagnostic SHA-256
`3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc`.
The independent reference copies do not establish a fresh native outcome.

The **new** protected native root
`/var/lib/debz-python3-reference-253/checkout/.real-snapshot/amd64-python3-253-protected-signed-2`
used ReleaseSafe binary SHA-256
`e25deea6be146c5c112167c8ec5293b2e6cee50daf708140ae0973d5010a0265`.
The newly authenticated lock SHA-256 was
`b1019563797b699ae30b07b625166f42624ccb056f06e0f62d62e6ec0b060bc5`;
all 175 SHA-512 archive objects (67,976,788 bytes) were independently
size/digest-checked against it, with exact-object-set `cas-rehash.tsv`
SHA-256 `0e3f2a55adb3d91d60b216f9af8c61c5785e05ab8266b4f0fee220464558a7c1`.
The signed python3 preinst at step **1383** ran with `["install"]`,
`spawned=true`, exit **0**, zero output and a durable `succeeded` record;
the package finished `install ok installed`. The first later refusal
was **not** the earlier local branch's final closure mismatch: after three
successful deferred callbacks, ordinal 3 at step **1428** remained
`prepared` with **no script outcome**. The signed configure-only procps
postinst SHA-256
`3dbc0b33e45028e59dca33a1f29e41cba3aebe369b6d67a2e26c40ef8ce383b8`
was pending `/usr/lib/sysctl.d`; its separate `triggered` admission was
not present in #254. Native execution returned `InvalidAlternativesScriptAuthority`
(exit 8). This root is retained for read-only evidence, never resumed as
a fresh trial, and does not establish full snapshot parity.

On #254's final squash plus only this procps-trigger admission, a
separate new root-owned protected 175-package amd64 workspace
`/var/lib/debz-procps-reference-254/checkout/.real-snapshot/amd64-procps-254-protected-signed-1`
authenticated the signer and independently checked every SHA-512
archive and the exact object set. Signed procps postinst step **1428**,
ordinal **3**, spawned with `["triggered", "/usr/lib/sysctl.d"]`,
durably exited **0** with zero output and completed `succeeded`;
procps ended installed. The 78-byte `vtrgb` record retained reference
SHA-256 `1fe9c0439ed1d49f6e06fad9d0a4ece1fba6826116f5cf26ba98e313c36570d3`.
The seven deferred callbacks exited 0, but
`libglib2.0-0t64` remained self `triggers-awaited`: final closure
refused with `final_closure_mismatch`, exit **8**. This independently
authenticated native outcome does not establish pinned-reference
parity or authorize the separate glib settlement; the interrupted
root is never reused.

The signed `util-linux:amd64` 2.41.3-3ubuntu2.2 archive (SHA-512
`271b4df2ee3ee790cdf1791dfffdaf87280a99a4df0bb0bc82c3d3f325484da98c05475961f8eb73410be9079fea05c2a2f4c94375deab6cdcb864b0ce21e7cc`)
ships the exact 2,112-byte `postinst` (SHA-256
`31f01940fe6aa22a9b35b54029eb5e4dd4ea5146dd2bacdb495d0d37eb210fc9`).
It assigns `OS=linux`, tests that constant and `command -v
update-alternatives`, then runs one literal, continued command:
`update-alternatives --install /usr/bin/pager pager /bin/more 50 --slave
/usr/share/man/man1/pager.1.gz pager.1.gz
/usr/share/man/man1/more.1.gz`. The existing `pager` record already selects
the priority-77 `/usr/bin/less` provider with that slave; `/bin/more` and
its manpage are root-owned regular files. The exact snapshot tool has SHA-256
`023e1c2eef9f323f6f2c2f53aa22092cd118b1f087349ce133a677f94a03ed45`.

The interrupted root was **copied only for disposable reference probes**;
its package status was already `install ok installed`, so pinned dpkg 1.22.22
first re-unpacked the separately rehashed signed util-linux archive in its
copy, then configured the exact script. It exited 0 and produced a 154-byte
`pager` record (SHA-256
`efb067c8704b11530e836705a78bbfdacbe298b9d13df3a01e1f84ca794747a9`):
the priority-50 `/bin/more` provider precedes the priority-77 `/usr/bin/less`
provider; both selector links still point to `less` and its manpage. Applying
the exact install command with pinned `update-alternatives` 1.22.22 to an
independent disposable copy produced **identical** record bytes and selectors.
These probes are not fresh native-root executions.

Native recognition skips **only** that literal tool-availability guard for
the complete signed script digest, then parses the continued literal install
using the existing typed grammar. This does not interpret a generic `if`,
shell variable, redirect, or alternative command. Admission is bound to the
new-package `util-linux:amd64` postinst at that exact version, exactly
`["configure", ""]`, and the snapshot amd64 tool identity and metadata.
Both `/bin/more` and its manpage are immutable script inputs. Before/after
capture, the selected less provider, unchanged other groups, typed reachable
registration, outcome journaling, and unknown-outcome recovery remain required.
Altered guards, operands, slaves, arguments, package identity, tool digest,
or resulting record fail closed. The interrupted predecessor roots are not
reused. A different authenticated 175-package root persisted util-linux
postinst exit 0 at step 1243 with the exact 154-byte pinned `pager` record
and both selectors still pointing to `less`. It then refused **before
launching** the unrelated `console-setup-linux.postinst` at step 1292: that
script uses two variable-expanded `update-alternatives --install` candidates.
This admission does not establish full-root parity; the newly interrupted
root is retained for recovery.

The independent fresh-root replay on final #246 plus the rebased util-linux
change reproduced the same 154-byte pinned pager record **byte-for-byte**
and kept both less selectors. Its signed postinst exited 0 at step 1243;
console-setup-linux.postinst was then refused before launch at step 1292.
The complete lock, executable, journal and interrupted-root evidence are
recorded in the [integration roots](integration-roots.md); no full-closure
parity follows from this bounded comparison.

The signed `console-setup-linux:all` 1.248ubuntu3 archive (SHA-512
`511e2f220d1f2afb6c0ae80d9488b6863b884f2db26e54d9cd343ca212c8061e6fbf637131fbd6f93673f3f9d47fe22515b22eca96a1cdf65e9e768fd2bbbb5b`,
6,207,548 bytes) ships the exact 6,448-byte postinst (SHA-256
`6d4e7cc59222fdde22ef49bc1ed1f2c8405c8a537c00af787f3c22a2edee383e`).
Its only alternatives-related assignment is the literal
`CONFIGDIR=/etc/console-setup`; the next two unconditional commands register
`"$CONFIGDIR/vtrgb"` at priority 50 and `"$CONFIGDIR/vtrgb.vga"` at priority
20 in the same `/etc/vtrgb` group. The signed archive owns both root-owned,
0644, single-link provider files: the 158-byte `vtrgb` SHA-256 is
`684cd905549f78e025870dd5c8a3835e49f79f2bb08952eb7424537f6df5fa13`,
and the 155-byte `vtrgb.vga` SHA-256 is
`1018702de86f8c570d097eadda5c2ec807375beb663e3a7afeec2cd1cd3e8f76`.
The exact root-owned `console-setup-linux.list` (41,489 bytes, SHA-256
`7ce7d005cb9f6144ee42373153611b01a1ab8f867f7174e3c0bf105ca2f7790f`)
claims both. Before launch, the record, selector, and generic link are absent;
the installed tool matches the snapshot amd64 digest and executable metadata.

In a disposable copy of the interrupted root, pinned dpkg 1.22.22
re-unpacked the separately rehashed signed archive, then configured the
signed postinst with exit 0. Its snapshot-pinned alternatives tool created
the 78-byte `vtrgb` record (SHA-256
`1fe9c0439ed1d49f6e06fad9d0a4ece1fba6826116f5cf26ba98e313c36570d3`),
selected the priority-50 provider, and linked
`/etc/vtrgb -> /etc/alternatives/vtrgb ->
/etc/console-setup/vtrgb`. An independent copy, given only the two
literal commands with pinned `update-alternatives` 1.22.22, produced
byte-identical record and link targets. These are disposable reference
observations, **not** native fresh-root success.

Native admission does not interpret `CONFIGDIR` or other shell variables.
Only the complete signed script digest maps those two exact command lines
to their literal operands and delegates parsing to the existing bounded
grammar. Admission binds the **new** `console-setup-linux:all` postinst,
version 1.248ubuntu3, target amd64, exact `["configure", ""]`, authenticated
archive identity, both signed providers and ownership list, and the snapshot
amd64 alternatives tool. The `vtrgb` group and generic/selector links must
start absent. Provider bytes, metadata, ownership list, and tool are checked
before launch and remain immutable through the managed checkpoint. A
zero-exit script must produce **both** registrations, in source order, with
the exact typed record and links; a real nonzero exit is not converted to
success and retains the normal bounded failure and recovery path. Other
groups, commands, scripts, variables, preexisting `vtrgb` state, and
unknown outcomes remain fail-closed. The predecessor interrupted root is
never retried as fresh. A new independently authenticated 175-package root
persisted exit 0 for the exact console-setup postinst at step 1292, with
the same 78-byte record and both pinned links. It later refused **before**
the unrelated `procps.postinst triggered /usr/lib/sysctl.d` callback in
deferred trigger processing at step 1428: the existing exact procps
configure-only admission rejects those triggered arguments. No full-root
parity is inferred, and that newly interrupted root remains retained.

After #247 squash `94e21f7e2c602649abd7aa7447aa79a54b97a408`,
another **new**, elevated, signed amd64 root ran the rebased console
admission at source commit `2c534a042d4550e730b40ff97cb7d192f1ea8263`.
The exact postinst at step 1292 spawned, durably exited 0, and left
`console-setup-linux:all` installed. Its 78-byte `vtrgb` record is
byte-identical to **both** pinned references, and its generic and selector
links select `/etc/console-setup/vtrgb`. A later, separate procps triggered
callback refused before launch at step 1428; this root remains interrupted
and supplies no full-closure parity claim. The signed lock, independent
175-archive rehash and next refusal are recorded in the
[integration roots](integration-roots.md).

The same signed `procps` archive's postinst is pending with
`["triggered", "/usr/lib/sysctl.d"]`. That exact branch shifts its arguments,
dispatches `/usr/lib/sysctl.d` to `_update_sysctl`, and exits 0 **before**
the parameterized `check_alternatives` function can run. `_update_sysctl`
cannot invoke `sysctl` when `/proc/sys` is absent. In a disposable copy of
the interrupted root with that path absent, pinned dpkg 1.22.22
`--triggers-only procps:amd64` exited 0, cleared the pending trigger and
left both the alternatives-record inventory (SHA-256
`892dd4d64385f38db6abcdefc197440d1c7cc79441675f2d0072fdf4f435217d`)
and selector inventory (SHA-256
`12b2a9e513aec2ff3a1dd768cdd48ae4f9ab1bafed82df02fd68629bdfd2ebe1`)
unchanged. No `uptime`, `vmstat`, `w`, or `ps` group appeared.

The additional native admission is restricted to a **trigger** action,
the new-package `procps:amd64` 2:4.0.6-3ubuntu1 postinst with the exact
script bytes, bound trigger handler and arguments above, and the snapshot
amd64 `update-alternatives` tool. It still requires all four `.procps`
providers absent and every group immutable; it also refuses an occupied
`/proc/sys` before launch and checkpoints that absence through post-exit
validation. This is not a general trigger or shell-variable allowance:
different triggers, arguments, scripts, actions, handlers, tools, or
observed alternatives mutations fail closed. The script's actual outcome
and unknown-outcome recovery remain unchanged.

An independently authenticated new 175-package root persisted this exact
procps callback at step 1428, ordinal 3, with exit 0 and zero output;
its immutable alternatives checkpoint passed and `procps` reached
`install ok installed`. The overall install nevertheless failed: an earlier
`console-setup:all postinst configure` at step 1297 exited 10 and left that
package half-configured. Its later failed receipt is not a procps or
full-root parity claim. The console-setup failure was addressed separately
in the subsequent signed script-path admission.

External tool execution intentionally retains the oracle's observable
non-atomic failure boundary. When native code itself owns a record/link
transition, the complete database-plus-selector-plus-generic-link intent set is
lowered into the versioned root-mutation journal, with fixed ordering, backups,
parent fsyncs, exact verification, and crash recovery.

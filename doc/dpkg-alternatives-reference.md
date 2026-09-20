# Pinned dpkg/update-alternatives reference

`tools/dpkg-alternatives-reference.py` is an executable reference for dpkg
1.22.22 and its `update-alternatives` 1.22.22 binary. It documents behavior;
it does not admit alternatives to native execution. The existing
archive-member and installed-state guards remain fail-closed.

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

The current canonical execution is amd64 only. Arm64 archive and executable
pins are evidence inputs, not observed behavior. The runner rejects arm64
publication until it is executed natively and reviewed separately.

The `CI` workflow's opt-in `run_arm64_dpkg_oracles` dispatch target performs
that review capture on `ubuntu-24.04-arm`. It passes the architecture
explicitly, verifies the downloaded archive and private binaries against the
pinned digests, executes both references with an empty inherited environment,
and uploads only canonical bounded observations plus their execution-evidence
manifest.

## External `update-alternatives` behavior

For a normal group, the administrative record is a root-owned `0644` regular
file. Its exact line format is:

1. `auto` or `manual`;
2. the master generic link;
3. ordered pairs of slave name and generic slave link;
4. a blank line;
5. for each candidate, the candidate path, signed decimal priority, and one
   target line per declared slave;
6. a final blank line.

Candidate rows are stored in bytewise path order. Generic and selector links
are root-owned `0777` symlinks. Generic links target
`/etc/alternatives/<name>`; selectors target the selected provider bytes.
Record bytes, order, sizes, SHA-256, modes, uid/gid, and every symlink target
are in the canonical observation.

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

## Later native requirements

Before native admission, implementation and review must cover the exact record
grammar and ordering, group-wide link publication, all observed partial
states, auto/manual selection, ties, missing targets, provider and package
lifecycle, opaque `.alternatives` info members, script failure/unwind,
interruption recovery, root confinement, bounded diagnostics, provenance, and
native amd64/arm64 evidence. The canonical JSON contains the full requirement
list. No current production guard is relaxed by this reference.

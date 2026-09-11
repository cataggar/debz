# Native trigger execution

Item 13 extends the private native lifecycle with trigger registration,
activation, deferral, and processing. Experimental core native execution derives
trigger authority from captured database and archive evidence.
[Native recovery and provenance](native-recovery.md) supplies the durable
continuation layer; remaining consumers and cutover are later roadmap work.

## Compatibility boundary

File interests live in `var/lib/dpkg/triggers/File`; named interests live in
individual `var/lib/dpkg/triggers/<name>` files. Their interested-package
records preserve await/noawait semantics. `triggers/Unincorp` is a deferred
activation queue: `-` denotes no-await activation, not a package identity.
Status `Triggers-Pending` and `Triggers-Awaited` fields, their package states,
and the shared registry must remain mutually consistent.

The declared activation policy and each listener's interest policy both
matter. Multiple activations coalesce without losing their ordering.
`postinst triggered` receives exactly two arguments: `triggered` and a single
space-separated trigger-name argument. The name order is observable and is not
arbitrarily sorted. File-trigger matching follows component boundaries and
the package paths affected by unpack/removal.

Trigger-only processing must consume compiled authority without pretending to
reinstall an archive. Deferred completion must retain the real pending and
awaited state rather than claim that every package is installed. Dynamic
script activations are constrained by bound trigger-handler identity and
script evidence; they are not a free-form script-execution capability.

A known failing triggered postinst and a no-progress cycle are distinct from
an unknowable script outcome. Known failures preserve dpkg-compatible package
states and stop the appropriate processing chain. An interruption while a
triggered script's outcome is not durably recorded retains the existing exact
script invocation record and root-operation evidence, blocking subsequent
mutation.

## Deferred final-state authority

`TriggerAuthority.final_mode` distinguishes an `exact` final closure from
`derive_from_activations`. The latter is explicitly authorized only for
deferred completion and binds the base final-state digest and a maximum
activation count. Immediate processing and existing non-trigger execution
retain their exact final-state contract.

Opaque maintainer scripts can activate triggers whose occurrence cannot be
predicted before the script runs. Derived mode therefore binds the exact base
package closure and the permitted transition rule, rather than pretending
that the final trigger fields were known in advance. A pure transition derives
the expected pending/awaited fields from generation-bound initial work and
bounded, validated automatic and helper activation events. Handler/caller
identity, trigger names, await policy, coalescing, and ordering remain
constrained by the compiled authority.

The expected closure is not copied from observed final status. Final
verification compares the actual database against the independently derived
expectation, including exact pending names and awaiting edges. Missing,
extra, or reordered edges and unrelated package identity/version/selection
changes remain mismatches; derived mode is not permission to accept any
pending state.

## Private activation helper

The test-only static helper accepts `--await` or `--no-await`, an optional
`--by-package=PACKAGE` matching the active caller, and one trigger. It uses the
shared native queue implementation, not a second queue parser or a subprocess
delegation. The lifecycle already holds the outer root lock; helper ingress
must not try to reacquire that lock.

`var/lib/debz/native-trigger-authority-v1.json` binds the permitted work to the
active program. The helper also requires the exact in-flight lifecycle
invocation and active operation. Known terminal outcomes clear that helper
authority; unknown invocation outcomes retain it with the other active
evidence. Caller bindings cover every script kind and distinguish installed
and incoming source/version/digest, including old scripts during replacement.
They are separate from the final postinst binding used for trigger handlers.
This is a private invocation boundary, not isolation against
malicious maintainer scripts running as the same UID.

## Independent acceptance

`tools/test-native-triggers.py` uses real packages and guarded disposable
chroots. It compares package status/status-old, every trigger registry/queue
file, info metadata, package filesystem effects, and exact script traces after
each operation. Cases include:

- all await/noawait combinations, both immediate and deferred;
- default aliases, named/file trigger ordering, duplicate activation, and an
  existing Unincorp queue;
- file-trigger install, upgrade, remove, and purge;
- newly installed listeners in both archive orders;
- actual postinst/postrm-driven activation, dynamic activation with deferral,
  a terminating chain, self-cycles, and a two-package no-progress cycle;
- known triggered-postinst failures, interrupted triggered scripts,
  malformed-queue refusal, and unexpected unrelated selection changes during
  deferred execution.

Reference roots use the real `dpkg-trigger`; candidate execution uses a
separately compiled native helper installed at the same in-root path.
Reference-only seeding is separate from candidate execution. The candidate
helper must match its compiled artifact and cannot be the reference binary.
Only this differing harness executable is excluded from filesystem comparison;
all package, queue, registry, status, and trace effects remain compared.

`--oracle-only` compares two real dpkg roots and establishes fixture
consistency, not native parity. Native execution additionally requires the
native lifecycle driver and `--native-helper` artifact. The runner requires
native Linux amd64/arm64, root for real chroot execution, and the existing
dpkg/ldd fixture prerequisites. Artifacts stay under the worktree's `.tmp`;
`--workspace` retains a new directory there for bounded diagnostics.

```sh
zig build test-native-triggers -j2
zig build test-native-triggers -Doptimize=ReleaseSafe -j2
```

`test-native-trigger-helper` runs the shared queue/helper unit coverage;
`native-trigger-helper` builds the private artifact without installing it.
Both the focused parity target and the default unit target include the
independent oracle regressions.

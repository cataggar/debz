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

Removal and purge derive file events from the actual planned filesystem
removals, not merely from ownership lists. Retained conffiles therefore do not
activate removal triggers; later conffile deletion and eligible directory
cleanup do. Events remain durably bound to their original package and program.
Known lifecycle-script failure still processes or defers authorized pending
work before publishing the failed outcome. It neither discards those events
nor converts the original package failure into a successful receipt.
Incorporation checks the listener's current database state: an interested
package that is still unpacked or otherwise not configured does not become
`triggers-pending` or cause its activating package to become
`triggers-awaited`. This matches dpkg's handling of both awaited and
no-await activations after a failed postinst: the activation is evidenced,
the unincorporated queue is drained, and the unconfigured listener remains
unpacked. Missing listeners are refused, not treated as unconfigured.
Failure recovery rechecks that state from the database rather than replaying
or inventing a script outcome.
`zig build test-native-recovery -Dnative-script-failure-only -j2` exercises
known exit, failed status publication, restart, and active-claim retention.
Zig tests cover trigger eligibility and the durable root-operation transition.
The narrow Python acceptance cases remain necessary to launch independent
crashing Zig processes and compare real dpkg scripts inside disposable chroots;
moving that privileged oracle and process orchestration into Zig is tracked
by [#213](https://github.com/cataggar/debz/issues/213) and
[#215](https://github.com/cataggar/debz/issues/215).

Trigger-only processing must consume compiled authority without pretending to
reinstall an archive. Deferred completion must retain the real pending and
awaited state rather than claim that every package is installed. Dynamic
script activations are constrained by bound trigger-handler identity and
script evidence; they are not a free-form script-execution capability.

An interested package need not ship `postinst`. Native authorization, compiled
programs and helper authority represent its observed absence with an explicit
`postinst_sha256: null`, still binding package/version/architecture, source and
declarations. The compiler rejects a mismatch in either direction. Processing
rechecks absence, clears pending/awaited state through the normal database
journal, and creates no script invocation, outcome or substitute script.
This applies to incoming and installed handlers, immediate and deferred work,
and persisted recovery. The package-owned helper target policy is unchanged.

The nullable field is a required, fail-closed extension of the v1 documents:
all-script documents keep their existing bytes and digests. Authorities
containing an absent handler use the domain
`debz-native-trigger-authority-optional-postinst-v1` (NUL terminated) and
presence-tag each handler digest; absence cannot alias a real script digest.
Older readers reject the null form rather than silently omitting a handler.

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

The incremental Zig-owned runner is available through
`test-native-triggers-zig` and `test-native-triggers-zig-unit`. It authenticates
a distinct private helper, compares exact guarded reference/native snapshots
for await/noawait immediate and deferred processing, tests a pre-existing
Unincorp queue, postinst-driven activation and a known triggered-postinst
failure, malformed queue refusal,
and exercises a diverted file-trigger route.
`-Dnative-diversions-only=true` selects the latter; the
`-Dnative-reference-dpkg` pin applies to both implementations. CI runs these
steps alongside the existing Python gates on amd64 and arm64 in Debug and
ReleaseSafe. The Python runner and its independent 24-profile diversion
settlement oracle (including 16 eligible follow-ups) remain mandatory until
Zig reproduces the full trigger matrix and exact settlement observations.
The current Zig runner does **not** establish full trigger/settlement parity.

`test-native-trigger-helper` runs the shared queue/helper unit coverage;
`native-trigger-helper` builds the private artifact without installing it.
Both the focused parity target and the default unit target include the
independent oracle regressions.

The private helper omits debugger metadata by default, including in Debug
builds; Debug code generation and runtime safety checks remain enabled.
This keeps repeatedly authenticated and retained helper evidence compact,
especially on CPUs without accelerated SHA-256. The default bundled artifact
has an 8 MiB regression budget. `-Dnative-helper-debug-info=true` retains the
metadata for helper debugging; use that option consistently when building the
caller and helper because their exact byte/digest binding still applies.

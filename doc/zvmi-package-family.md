# zvmi Debian-family backend

`debz.package_family_backend` is the versioned image-builder boundary for
Ubuntu and Debian roots. Capability discovery is available from the library
and from:

```sh
debz package-family-capabilities
debz package-family-capabilities --transaction-backend native
```

Omission of the backend flag preserves the version-1 legacy capability
document exactly; explicit `legacy_dpkg` returns the same document. Invalid,
duplicate or missing backend selections are usage errors. Help remains
metadata-only and takes precedence over other arguments.

Schema version 1 supports resolve-lock, create, customize, update, inspect, and
recovery for `amd64` and `arm64`, including either architecture as a configured
foreign architecture. Requests must provide absolute root, source/config,
keyring, cache, state, credential-reference, and lock paths. No host APT
configuration, keyring, proxy, cache, or credentials are inherited.

`resolve_lock` is the only operation permitted to omit a lock input. It is
non-mutating, requires a package and lock output, and derives the canonical
closure from authenticated metadata, the supplied root's installed package
database (empty for initial image creation), and deterministic solver policy.
The caller reviews that artifact before create. Every create, customize,
update, or recovery request still
requires a previously reviewed exact-lock input; the backend never performs an
unlocked image mutation. An optional lock output on those operations is an
atomic canonical copy.

Repository metadata is accepted only through debz's authenticated refresh
pipeline. Package archives are digest-checked and payload-validated before the
dpkg executor sees them. Exact-closure lock inputs are canonical and
integrity-protected; unavailable or ambiguous locked artifacts fail closed.
Successful locked transactions write canonical provenance to
`STATE/transaction-result.json`.

`offline` means cache-only and never falls back to the network. Credentials are
passed only by opaque file reference; capability, result, lock, provenance,
and diagnostics contain no credential bytes. The caller owns atomic image/root
staging and must not publish until the result, exact lock, and provenance have
all been verified.

The version-1 release-acceptance lane selects the immutable
`https://snapshot.ubuntu.com/ubuntu/20260816T000000Z` snapshot in a deb822
source, suite `resolute`, component `main`, and uses
`/usr/share/keyrings/ubuntu-archive-keyring.gpg` explicitly. Native amd64 and
arm64 runners exercise the legacy backend, installing `ubuntu-minimal` into
empty staged roots, reproducing the install lock, and resolving a separate
operation-bound update lock. The zero-command update preserves package status;
its genuine legacy receipt is verified against that update lock rather than
presenting the earlier install receipt as new update provenance.

## Native family workflows

The separate `debz.NativePackageFamilyBackend` provides native version-2
`resolve_lock`, `create`, `customize`, `update`, `recover` and `inspect` without
changing the legacy adapter or converting v1 locks.
Requests execute through this library API; capability discovery is metadata
only and does not introduce a package-family execution CLI.
Initialize it with the caller's `std.Io`; it constructs the real native
production backend rather than accepting a command-shaped executor. Use the
existing request fields with
`schema = package_family_backend.native_request_schema` and
`version = package_family_backend.native_schema_version`. Version/backend
mismatches fail before backend work. Root, repository, trust, cache, state,
architecture and reviewed output location remain explicit.

Resolution uses authenticated repository metadata and the supplied root's
installed-state snapshot through the existing native planner, producing a
genuine canonical `exact-closure-lock-v2` with authenticated origin, signer,
snapshot, semantic-request and policy bindings. An empty staged root yields
the initial image closure. Offline resolution uses only already-authenticated
cached metadata and never fetches missing packages or repository files.
Planning does not execute packages, create a native transaction receipt or
advertise legacy provenance. The returned `OwnedResult` contains a version-2
`result`, including an independently owned `lock_path`; call `deinit` on the
owned result after use.

### Update planning and execution

`NativePackageFamilyBackend.resolveUpdateLock(allocator, request)` accepts the
same explicit native v2 `resolve_lock` request shape, with a lock output and
no lock input. A `package` selects a named upgrade (including qualified
architecture/version selectors); omitting it selects upgrade-all. The method
does not accept mutation or recovery requests. Ordinary `execute` with
`resolve_lock` still requires a package and retains install planning semantics.
No new request version or planning-target field is introduced.

Review the emitted v2 lock, then call `execute` with `operation = .update`,
the same package selector (or no package for upgrade-all), the same planning
policy, and that lock as `lock_input`. Install, named-upgrade and upgrade-all
locks have distinct semantic bindings; changing operation, selector or policy
refuses rather than reinterpreting or replacing the reviewed lock. Planning
and authenticated offline replay do not execute packages or acquire root
operation ownership.

Update preserves the core solver's installed-package and hold policies.
Successful changed updates carry the original `upgrade` or `upgrade_all`
completion and pass invocation-specific verification. Genuinely unchanged
updates return `changed = false`, the reviewed lock path, and no new completion
or provenance path. Updates never fabricate install-only `native_install`
evidence, including for unchanged results. A previous latest receipt is not
evidence of that unchanged invocation. Failed updates remain failed, and
persisted-only recovery returns the original update completion rather than
relabelling it as an install.

### Mutation results and recovery

Native create/customize require a reviewed lock and use the same native
install operation. They retain the core planner's behavior: repeated requests
or matching versions do not imply no work, and an explicit install can select
reinstallation. If preparation is genuinely unchanged, the adapter preserves
`changed = false` with typed install evidence and no invented
receipt or provenance path. Mutation still requires the real trusted helper
target in the staged root; a missing target refuses before mutation and is
never replaced with a placeholder.

Changed successes carry the actual core install/completion evidence and pass
invocation-specific completed-success verification before the family reports
success. Known failure and incomplete recovery retain the core's actual
`changed` flag and failed exit status. The owned result's `native_install` and
`native_completion` are by-value companions to the unchanged common result
shape; retain them separately when serializing `result`. A terminal
`provenance_path` identifies the native receipt under the requested root, never
`STATE/transaction-result.json`. This latest-receipt path can change after
another transaction; bind it with the returned evidence, not the path alone.
Post-execution proof failure is recovery-required, preserves the changed flag,
and does not authorize publication. Any raised API error also prevents image
publication.

Native recovery accepts explicit root, architecture/foreign architectures,
cache/state paths and invocation deadline/lock-wait limits, but no package,
source/config/keyring, lock input/output, credential or proxy replacements.
Leave execution-policy fields at their defaults; recovery uses the original
persisted policy, not those fields as overrides. Cache/state paths remain
explicit and syntactically validated, but recovery does not acquire archives
or metadata through them. A terminal recovery returns the original completion
evidence and native provenance, without a replacement lock path. No-work
recovery returns no new provenance and does not turn a prior failed install
into success. Unknown script outcomes remain unresolved without replay;
another outer owner's marker cannot be finalized through this adapter.

Native capability discovery advertises all six operations, exact-lock v2,
native transaction provenance and disposable-or-recoverable roots, with no
apt/dpkg invocation. Selecting native never falls back to the legacy family
adapter, and the ordinary v1 adapter rejects v2 requests.

### Diagnostic inspection

`execute` with `operation = .inspect` returns an owned `native_inspection`
companion, separately from the unchanged common v2 `result`. Retain it
separately if serializing only `result`; all inventory strings and arrays live
until `OwnedResult.deinit`. The companion contains the root, whether the status
file was present, and every parsed package record sorted by name/architecture.
Each package includes its version, architecture, and full typed status:
selection (`want`), error state, and current state. Held, partially configured,
and config-files-only records are not silently filtered out.

Inspection accepts explicit root, architecture/foreign architectures,
cache/state paths and an optional invocation deadline. Cache/state paths are
syntactically validated but not read or created. Repository/config/keyring,
credential/proxy, package filters, lock input/output and nondefault execution
policy are refused. Leave `lock_wait_ms` at its default: inspection does not
acquire or wait for a coordination lock. The deadline is checked between
bounded read/parse stages. Architecture inputs retain request validation;
records report their stored architectures rather than being filtered or
attested against the requested architecture.

The companion always marks `diagnostic_only = true`. It also reports an
observed root operation's backend/operation/state/mutation flag, an observed
deferred-owner state, and whether native active evidence was observed. These
are separate diagnostic observations, **not an atomic database generation or
proof of a healthy, settled or exactly installed root**. A missing status file
is reported explicitly with an empty inventory; absence alone does not prove
a fresh root. Malformed, unreadable or linked status/coordination documents
fail explicitly rather than becoming an empty or clean result. The active
evidence flag only reports recognized pending artifacts, not verification of
their contents.

Fresh and recovery-required roots can be inspected, including while another
caller holds the coordination lock. Root-anchored reads do not follow
symlinks, and literal host roots or unscoped host-root aliases are refused.
Inspection creates no database, namespace, lock, helper, cache or state files,
does not recover or acknowledge anything, and never emits install/completion
evidence, a reviewed lock path or provenance. Concurrent writers can change
the root during or after inspection; successful inspection only means the
diagnostic observations were obtained. It never authorizes image publication
or replaces the completed-success proof below.

## Read-only native completion evidence

`NativePackageFamilyBackend.verifyCompletedSuccess(allocator, original_request)`
verifies a settled successful native transaction against an explicit v2
create/customize/update request. It does **not** execute that request,
recover an incomplete transaction or accept a
known failure as successful installation. Create and customize intentionally
share the product install operation; their family labels are not independently
attested.

The verifier shares the adapter's product-request mapping and validation,
reads the reviewed v2 lock without following symlinks, and uses the existing
native transaction verifier under its fail-fast, non-creating root lock.
Before releasing that lock it compares the mapped operation, semantic caller
request, native solver policy and foreign architectures with the verified
completion. The existing verifier checks root identity, target architecture,
the lock, receipt, retained execution evidence and current package database,
and refuses pending or uncleared execution. It neither acknowledges receipts
nor creates or rewrites root state.

The returned `NativePackageFamilyVerifiedCompletion` owns its summary's root
path and must be released with `deinit`. Its `summary.canonicalJson` produces
the existing native `transaction-result-summary.v2`, not legacy provenance or
a new family execution result. Verification describes the retained completed
transaction: it does not prove that a new unchanged invocation performed work
or reserve the root for subsequent image publication. The image builder still
owns atomic staging and publication.

Semantic caller hashes do not attest acquisition paths, cache/state locations,
credentials, proxies or transport limits. These request fields are validated
but verification performs no repository refresh, archive acquisition or
credential loading. Authenticated content is bound by the reviewed lock and
retained native evidence, not by reusing current transport configuration.
Existing capability and common execution-result schemas remain unchanged;
capabilities identify which native operations are available.

### Binding a particular returned completion

Core native product results expose optional, by-value
`ProductNativeCompletionEvidence` through `Result.native_completion`.
A terminal successful or known-failed execution, including persisted-input
recovery, carries the original product operation, outcome, attempt, lock,
caller request/policy, receipt, completion and program bindings. Recovery's
command operation can be `recover` while the evidence correctly describes the
original `install` or other package operation.

`settlement = cleared` is returned only after ordinary completion,
acknowledgment and root-record cleanup succeed. `retained` means the outer
owner's lifecycle still controls the result, including released owners whose
marker remains; it is not a standalone cleared-root result. Unchanged,
preflight-refused, incomplete and no-work recovery results do not manufacture
terminal evidence. Metadata is not ownership or execution authority and does
not appear in generic `command.v1` JSON; typed consumers must retain it
separately. Existing native-install evidence and all wire schemas are unchanged.

Use `verifyCompletedResultSuccess(allocator, original_request, completion)`
to bind readback to a particular returned `native_completion`. Failed or
retained metadata is refused before filesystem work. The verifier compares
every returned binding with the independently verified native documents while
the root lock remains held. A different attempt, altered binding or relabeled
failure cannot stand in for that result. The older `verifyCompletedSuccess`
continues to describe matching retained history without asserting which
invocation returned it. Both methods are read-only and require genuine
evidence; diagnostic inspection cannot substitute for either proof.

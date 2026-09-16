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
empty staged roots and replaying the same exact lock for update and
reproducibility evidence.

## Native lock resolution

The separate `debz.NativePackageFamilyBackend` provides native version-2
`resolve_lock` without changing the legacy adapter or converting v1 locks.
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

Native capability discovery currently advertises **only `resolve-lock`**,
exact-lock v2, no provenance schema, unavailable recovery and no apt/dpkg
invocation. Native create/customize/update/recover/inspect requests remain
unavailable before filesystem access until their complete family-level
contracts are integrated. Selecting native never falls back to the legacy
family adapter, and the ordinary v1 adapter rejects v2 requests.

## Read-only native completion evidence

`NativePackageFamilyBackend.verifyCompletedSuccess(allocator, original_request)`
verifies a settled successful native transaction against an explicit v2
create/customize/update request. It does **not** execute that request, enable
those operations in `execute`, recover an incomplete transaction or accept a
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
Existing capability and execution-result schemas remain unchanged, including
the native execution, recovery and inspection gates.

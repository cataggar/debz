# Target-root APT configuration snapshots

`debz.target_apt_config` is the explicit compatibility boundary for importing
repository configuration from a selected Debian-family root. It does not run
APT and does not consult process environment, proxy settings, authentication
configuration, netrc, credential helpers, a GnuPG home, or files outside the
selected root.

## Discovery and paths

The importer considers only:

- `/etc/apt/sources.list`;
- regular `.list` and `.sources` files directly beneath
  `/etc/apt/sources.list.d`;
- each absolute logical `Signed-By` path declared by those sources; and
- when a source omits `Signed-By`, `/etc/apt/trusted.gpg` plus regular `.gpg`
  and `.asc` entries directly beneath `/etc/apt/trusted.gpg.d`.

Unrelated directory entries are excluded deterministically and recorded with a
reason. Eligible symlinks, directories, special files, traversing paths, and
malformed sources fail explicitly. The production adapter opens the selected
root, every parent, and every file without following symlinks and resolves file
reads beneath their opened parent. Specific-file classification uses a direct
no-follow path-only open and stat rather than scanning the parent directory.

Source fragments follow APT's basename grammar before extension matching:
ASCII letters, digits, underscore, hyphen, and period only. Names containing
spaces, `@`, Unicode, or other characters are ignored as inputs and recorded
as `unsupported_name` exclusions.

Valid `deb-src`-only declarations, including disabled legacy declarations, stay
covered by the source-file path and digest evidence but are excluded from the
binary refresh configuration. Source material is bounded both per file and in
aggregate before retained copies are made.

Paths remain logical in normalized repositories and in the manifest. For
example, `/usr/share/keyrings/vendor.gpg` is read from
`ROOT/usr/share/keyrings/vendor.gpg`, but the declared path is never rewritten
to include `ROOT`. Repository identities therefore remain stable when
identical roots live at different physical paths. Logical paths use one
schema/runtime grammar: valid UTF-8 absolute paths other than `/`, with no
empty, `.` or `..` component, trailing slash, backslash, control byte, or DEL.

## Trust material

Every imported binary keyring is boundedly parsed before use. The snapshot
records its SHA-256 and sorted supported v4 primary-key fingerprints.
Per-keyring and aggregate retained bytes are bounded. Malformed keyrings,
unusable RSA public parameters, unsupported RSA modulus sizes, and unsupported
public/secret key material fail before a snapshot is returned. ASCII-armored
keyrings are eligible APT inputs but are currently rejected explicitly because
the verifier intentionally supports binary OpenPGP keyrings only.

Candidate keyring paths are deduplicated through a bounded hash index, with the
unique-keyring limit enforced before insertion. Strict inspection applies the
same byte, packet, and key limits cumulatively across all imported keyrings.
Those exact verifier limits are carried into runtime authentication, so every
accepted snapshot remains usable by the runtime verifier.

`Snapshot.runtimeTrust` constructs `openpgp_verifier.Keyring.bytes` values from
the imported bytes. Repeated logical paths contribute only one authentication
keyring, while the original `declared_keyrings` sequence is preserved so
`repository_policy` runtime matching remains bound to the exact normalized
`Signed-By` declaration. Sources without `Signed-By` receive only the enumerated
global keyrings, and the manifest marks global-trust compatibility.

## Typed system product context

`debz.system_product_context` consumes only the
[active record published by a successful repository add](repository-management.md#root-scoped-active-configuration).
It supplies a typed, allocator-owned configuration view, not a new execution
permission or an implicit fallback for product API v1:

```zig
const context = try debz.system_product_context.resolve(allocator, io, .{
    .root = "/srv/owned-image",
});
defer context.deinit();
try context.validate();
const snapshot = context.snapshot();
const defaults = context.options();
```

The request defaults are root `/`, logical cache `/var/cache/debz` and logical
state `/var/lib/debz`. `options()` returns the physical paths under the
selected root, validated native/foreign architectures, noninteractive mode,
and `keep_existing` conffile policy. `locksPath()` selects `<state>/locks`.
It does **not** set `assume_yes`, create directories, select a backend, fill
generic product repository paths, or authorize mutation. `snapshot()` returns
non-owning, deeply read-only facts, including `[]const NormalizedRepository`;
it exposes neither mutable configuration storage nor owning arenas. Detached
value copies cannot change the retained context. Consumers obtain verifier
inputs with `context.runtimeTrust(allocator, repository.id)`, which resolves
only retained repository identities, rather than accepting caller-edited
repository facts. Reopening
its logical key paths against the process host would violate this boundary.

Architecture comes from target installed-dpkg metadata with **no subprocess
fallback, including for `/`**. An explicit architecture override must match
the recorded architecture. Cache/state overrides are canonical logical paths
inside the selected root; a missing alternate-root pointer never imports a
host pointer. Root namespace and device/inode checks reject copied active
records. Reimport rehashes the manifest and every recorded source/keyring,
replays its finite freshness policy, and compares the complete configuration
digest. Added or removed eligible inputs, symlink or unsafe-owner/mode/link
changes, and architecture/configuration drift refuse.

An existing shared root-operation record, deferred owner/review, or native
execution intent returns `RootOperationRecoveryRequired` **before** source
import. `validate()` repeats that check and reopens/revalidates the same root
and active identity; it never adopts, clears or replaces retained work.
Recovery must use the surface that owns `/var/lib/debz/root-operation-v1.json`
and its exact recorded evidence. This read-only check is not a root-lock
reservation: a future mutation consumer still needs the normal root-operation
lock and exact recovery/receipt protocol.

The host's active **configuration** uses `/` identity for either backend.
Normalization from a private projection occurs only after validating its
borrowed `live_root.Projection` authority against the pinned descriptor;
the observed physical device/inode must still match. `resolveProjected`
requires that same authority. Ordinary `resolve` rejects the projection
spelling; no host-root alias or permission is inferred from a path string.
**Execution/recovery records retain their original exact root namespace**,
and this configuration view neither reinterprets nor adopts them. A projected
context must stay within its callback's lifetime; `validate()` rechecks that
borrowed authority too.

This completes configuration/context preparation only. The short SymCrypt
install command, durable auto-lock, evidence-bearing product results and
exact owned retry are not wired to this view yet. In particular, the existing
exact-lock builder refuses retained installed packages with no authenticated
origin in the current repository set (`RetainedPackageUnavailable`); resolving
that healthy-system baseline boundary must not silently drop retained state
or invent archive/signature authority. The reproduced blocker is tracked in
[#407](https://github.com/cataggar/debz/issues/407).

## Architecture and manifest

Callers may provide an explicit native architecture. Otherwise the importer
uses the installed `dpkg` package in the selected root's status database.
Entries in `/var/lib/dpkg/arch` are recorded as foreign architectures rather
than treated as competing native candidates. Only for root `/`, and only when
target state has no native answer, an injected runner may execute the fixed
argv `/usr/bin/dpkg --print-architecture` with an empty environment. Alternate
roots never fall back to the host architecture or `uname`.

`inspectArchitecture` provides the same bounded target-metadata discovery
without importing sources or keyrings. It returns an `OwnedArchitecture`
containing the native architecture and sorted, deduplicated foreign set;
call `deinit` when finished. This read-only entry point always disables the
process runner, even if one is supplied and the logical root is `/`. Missing
target-native evidence therefore requires an explicit override instead of a
dpkg subprocess. Root-adapter checks, malformed-input refusals, and allocation
errors are preserved. The ordinary `snapshot` fallback contract is unchanged.

`zig build test-target-apt-config -j2` discovers both the importer and
`system_product_context` modules explicitly. Its context cases cover deeply
read-only borrowed facts, allocation-failure ownership, retained work, root
identity, immutable-generation drift, and independence from the public
operation manifest. Use `-Doptimize=ReleaseSafe` to repeat the same cases;
compile filters alone do not discover Zig's lazy module imports.

Callers may attach an explicit freshness policy to a discovered source path.
The default requires signed `Valid-Until`; the only alternative allows a
missing field for a nonzero, bounded maximum Release age. Unknown, duplicate,
invalid, or missing source-policy paths fail rather than being ignored. This is
an API-level policy input only; target import does not infer a policy from a
hostname or publish system-specific defaults. `repo add` supplies policies
itself only for exact
[reviewed freshness profiles](repository-management.md#reviewed-freshness-profiles).
It derives them from the imported source and keyring bytes and repeats the
import to confirm those bytes are unchanged.
Target-root configuration has no witness relation, so it refuses
`frozen_release_with_witnesses` in source policies, manifests and
`apt-config-snapshot-v2` documents; supporting it would require a new snapshot
schema.

The canonical `apt-config-snapshot-v2` document records source paths, digests,
and freshness policies; normalized configuration, repository identities, and
per-repository freshness policies; keyring paths, digests and fingerprints;
global compatibility use; deterministic exclusions; native and foreign
architectures; and an aggregate SHA-256. It is emitted when a finite
missing-expiry policy is configured. Strict-only snapshots continue to use
canonical v1 bytes, whose defined semantics require `Valid-Until` for every
source and repository. V1 artifacts remain readable and round-trip as v1 and
can never acquire the finite exception by omission. Both decoders are bounded,
reject unknown fields and noncanonical documents, and verify the aggregate
digest. `Store.writeAtomic` publishes through a no-follow directory handle,
file sync, rename, and directory sync.

A source may declare the per-repository signed-SHA256 archive binding
(`X-Debz-Archive-Binding:` in DEB822 or `debz-archive-binding=` as a one-line
option). Import validates the token, carries the declaration in the source
bytes, normalized repositories, and repository identities, and leaves the
manifest format unchanged ([exact locks](exact-locks-and-provenance.md)).

The module is a foundation for the separately scoped `repo add` workflow. It
does not install descriptors, mutate repository configuration, alter exact
locks or transaction provenance, or add CLI commands.

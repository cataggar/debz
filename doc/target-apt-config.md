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

## Architecture and manifest

Callers may provide an explicit native architecture. Otherwise the importer
uses the installed `dpkg` package in the selected root's status database.
Entries in `/var/lib/dpkg/arch` are recorded as foreign architectures rather
than treated as competing native candidates. Only for root `/`, and only when
target state has no native answer, an injected runner may execute the fixed
argv `/usr/bin/dpkg --print-architecture` with an empty environment. Alternate
roots never fall back to the host architecture or `uname`.

The canonical `apt-config-snapshot-v2` document records source paths and
digests, normalized configuration and repository identities, keyring paths,
digests and fingerprints, global compatibility use, deterministic exclusions,
native and foreign architectures, repository-specific freshness policy, and
an aggregate SHA-256. Decode is bounded,
rejects unknown fields and noncanonical documents, and verifies the aggregate
digest. `loadRecordedSnapshot` reopens only the named source/keyring files under the
selected root and verifies every digest, fingerprint, repository identity, and
freshness decision. `Store.writeAtomic` publishes through a no-follow directory handle,
file sync, rename, and directory sync.

`repo add` retains an operation copy and publishes a well-known active v2 copy
under the selected debz state root. Alternate-root snapshots cannot select or
reuse the host-root active record. Native and foreign architectures in that
record are copied into standalone system planning; active-record replay
reopens and verifies all named source/keyring bytes before they become solver
input. Standalone consumers acquire the shared root operation guard before
that replay and hold it through planning/execution; repository-add acquires the
same guard before its repository and transaction locks.

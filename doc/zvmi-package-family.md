# zvmi Debian-family backend

`debz.package_family_backend` is the versioned image-builder boundary for
Ubuntu and Debian roots. Capability discovery is available from the library
and from:

```sh
debz package-family-capabilities
```

Schema version 1 supports resolve-lock, create, customize, update, inspect, and
recovery for `amd64` and `arm64`, including either architecture as a configured
foreign architecture. Requests must provide absolute root, source/config,
keyring, cache, state, credential-reference, and lock paths. No host APT
configuration, keyring, proxy, cache, or credentials are inherited.

`resolve_lock` is the only operation permitted to omit a lock input. It is
non-mutating, requires a package and lock output, and derives the canonical
closure solely from authenticated metadata, an empty installed package
database, and deterministic solver policy. The caller reviews that artifact
before create. Every create, customize, update, or recovery request still
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

The release-acceptance lane selects the immutable
`https://snapshot.ubuntu.com/ubuntu/20260816T000000Z` snapshot in a deb822
source, suite `resolute`, component `main`, and uses
`/usr/share/keyrings/ubuntu-archive-keyring.gpg` explicitly. Native amd64 and
arm64 runners install `ubuntu-minimal` into empty staged roots and replay the
same exact lock for update and reproducibility evidence.

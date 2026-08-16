# zvmi Debian-family backend

`debz.package_family_backend` is the versioned image-builder boundary for
Ubuntu and Debian roots. Capability discovery is available from the library
and from:

```sh
debz package-family-capabilities
```

Schema version 1 supports create, customize, update, inspect, and recovery for
`amd64` and `arm64`, including either architecture as a configured foreign
architecture. Requests must provide absolute root, source/config, keyring,
cache, state, credential-reference, and lock paths. No host APT configuration,
keyring, proxy, cache, or credentials are inherited.

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

Ubuntu 26.04 core-image builders normally select the immutable snapshot in a
deb822 source, use the vendor archive keyring explicitly, install the
`ubuntu-minimal` metapackage into an empty staged root, and then replay the
same exact lock for updates or reproducibility checks.

# Threat model and safety limits

## Trust boundaries

Untrusted inputs include repository source declarations, HTTP/file responses,
DEB822 records, versions and relations, Release and Packages indexes,
OpenPGP envelopes, packets and keyrings, compressed metadata, `.deb`/ar/tar
bytes, exact locks, transaction provenance, journals, package-cache contents,
and installed-state files. Install roots, cache roots, clocks, proxy settings,
credentials, keyrings and policy are explicit caller inputs; host APT, GnuPG,
proxy and environment configuration is never consulted.

Production parsing, verification, decompression and archive inspection are
in-process and never invoke a shell. `dpkg` is the sole intended production
child-process boundary and is executed with fixed argv/environment policy.

## Security properties

- Every allocating parser has caller-visible byte/count limits. Fuzz harnesses
  use tighter limits (32 KiB input, bounded records/packets/tar entries).
- Decompression limits compressed bytes, output bytes and decoder memory.
- Archive validation rejects absolute/traversing paths, unsafe links,
  extensions, special files, duplicate paths, bombs and incomplete archives.
- Cache and journal publication use explicit roots, no-follow traversal,
  staging, fsync and atomic rename. Lock waits and garbage collection are
  bounded; interrupted state remains non-success evidence.
- Repository and package publication is digest-bound and fail-closed.
- Diagnostics and provenance retain redacted URIs and fixed audited
  environment values; authenticated URLs and supplied credentials are not
  serialized.

Defaults are part of the public API and remain stable within a major version.
Overrides may lower limits or raise them deliberately; callers remain
responsible for selecting values appropriate to their resource budget.

## Residual risks

The OpenPGP implementation intentionally supports a documented subset.
Unsupported algorithms and packets fail closed. libsolv and libzstd are
linked as reviewed, exact-pinned BSD dependencies; liblzma is an exact-pinned
0BSD, single-threaded in-process decoder. None enables repository/network
loaders.
See [Safety CI and fuzzing](safety-ci.md) and
[dependency notices](../THIRD_PARTY_NOTICES).

# Threat model and safety limits

## Trust boundaries

Untrusted inputs include repository source declarations, HTTP/file responses,
DEB822 records, versions and relations, Release and Packages indexes,
OpenPGP envelopes, packets and keyrings, compressed metadata, `.deb`/ar/tar
bytes, exact locks, transaction provenance, journals, package-cache contents,
repository descriptor packages, repository-add operation state, and
installed-state files. Install roots, cache roots, clocks, proxy settings,
credentials, keyrings and policy are explicit caller inputs; host APT, GnuPG,
proxy and environment configuration is never consulted.

`debz repo add` is the one explicit compatibility import boundary: it snapshots
APT sources, referenced keyrings, and dpkg architecture from the selected
target root. This is operation-scoped input, not ambient inheritance. `/` is
enabled only inside the typed repository-add backend; alternate roots never
fall back to host source, keyring, architecture, cache, state, or lock paths.
Generic product operations continue to deny `/`.

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
- Repository descriptors require verified HTTPS or an explicit SHA-256.
  Unpinned transport trust covers the complete redirect chain, not only the
  initial URL.
  Bundled keyrings authenticate only the repositories they name; they never
  authenticate the descriptor package that carried them.
- Repository declarations that set `Trusted`/`trusted` true are rejected before
  authentication or target import.
- Repository-add operations apply aggregate repository, action, metadata,
  package, retained-memory, cache-growth, and elapsed-time budgets in addition
  to per-object parser and transfer limits. The elapsed budget starts before
  the repository operation lock and caps that wait.
- Validated descriptor recovery is pinned to persisted CAS digest and size.
  Missing or corrupt CAS data can only be reacquired at that identity, and
  previously established HTTPS trust cannot be replaced by a weaker redirect
  chain or newly labeled evidence.
- Repository operation journals are integrity-decoded and matched to plan,
  root, executor policy, and exact lock before recovery. Unrelated completed
  archives do not select recovery; mismatched incomplete evidence blocks.
- Diagnostics and provenance retain redacted URIs and fixed audited
  environment values; authenticated URLs and supplied credentials are not
  serialized.
- Repository-add CLI parsing is noninteractive: there are no prompts, stdin or
  TTY branches, consent flags, or apt subprocesses. The direct process boundary
  remains fixed-environment dpkg/dpkg-deb execution.

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

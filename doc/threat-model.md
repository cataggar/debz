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
The typed standalone system-product resolver may authorize `/` only after
loading and revalidating the active root-scoped configuration. Generic product
API calls and alternate-root workflows do not gain ambient host trust.

Production parsing, verification, decompression and archive inspection are
in-process and never invoke a shell. `/usr/bin/dpkg` and `/usr/bin/dpkg-deb`
are the only production child processes started directly by debz. These
fixed-path host tools are trusted dependencies; debz supplies explicit argv
and a replacement environment and bounds captured output and runtime. Debz
never directly invokes a shell, apt, or another ambient package manager; dpkg
may in turn run package maintainer scripts within the package-execution trust
boundary.

## Security properties

- Every allocating parser has caller-visible byte/count limits. Fuzz harnesses
  use tighter limits (32 KiB input, bounded records/packets/tar entries).
- Decompression limits compressed bytes, output bytes and decoder memory.
  Gzip retains a bounded 32 KiB DEFLATE history across output chunks and still
  verifies header structure, CRC32, ISIZE, truncation, and trailing data.
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
- Moving repositories without `Valid-Until` remain rejected by default. A
  repository-specific persisted exception is finite (maximum 31 days), bound
  to signed `Date`, verification time, configuration identity, cache snapshot,
  exact lock, and transaction provenance.
- A system mutation publishes an exact closure lock before the first dpkg
  command. Post-lock failures retain and report lock, provenance, and recovery
  evidence, and retries cannot silently switch transactions.
- The root-scoped system-operation lock is acquired before active
  source/keyring validation by product operations and before repository-add's
  repository/transaction locks. It serializes active configuration use and
  the recovery-intent state machine without lock-order inversion.
- Recovery intents contain no trusted filesystem paths. The root-owned
  operation lock binds canonical install/state roots and a unique attempt;
  plan, package-lock, journal, and provenance paths are derived from it.
  Recovery consumes the persisted canonical plan and freshness evidence, not a
  newly refreshed repository or a plan reconstructed from mutable dpkg state.
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

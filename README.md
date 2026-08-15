# debz

`debz` is an in-development, embeddable Debian-family package manager and CLI written in Zig. It is designed around explicit inputs, bounded parsing, authenticated repository metadata, deterministic dependency solving, verified package acquisition, transaction planning, and install-root-aware execution through `dpkg`.

## Public entry points

- `debz.planTransaction` creates an owned, deterministic transaction plan from authenticated repository snapshots and parsed dpkg state.
- `debz.acquirePackage` downloads or loads an authenticated solver-selected package, verifies its size and SHA-256, and publishes it to an explicit package CAS.
- `debz.repository_policy` normalizes and atomically orchestrates explicitly declared multi-repository policy.
- `debz.executeTransaction` revalidates cached artifacts and executes an owned plan against an explicit install root with bounded locks and structured failure provenance.
- `debz.createExactClosureLock` and `debz.decodeExactClosureLock` create and validate canonical, digest-bound complete solved-closure locks.
- `debz.createTransactionProvenance` records redacted, digest-bound repository, artifact, command, journal, recovery, and final-verification evidence.
- `debz.repository_refresh.refreshAuthenticated` verifies repository signatures and metadata before publishing a solver-eligible snapshot.
- `debz.openpgp_verifier` verifies the project's supported OpenPGP profile without network, process, or ambient keyring access.
- `debz.deb_payload.validate` performs complete bounded `.deb` payload and authenticated identity validation before transaction handoff.
- `debz.SolverContext` imports eligible package indexes into a Debian-configured libsolv pool.
- `debz.dpkg_status`, `debz.source`, and the parser modules expose typed APIs for caller-supplied Debian metadata.

Plan serialization uses canonical schema version 2 in
[`schema/transaction-plan-v2.json`](schema/transaction-plan-v2.json); version 1
remains published for compatibility.

Exact lock and transaction result schemas are documented in
[`doc/exact-locks-and-provenance.md`](doc/exact-locks-and-provenance.md).

See the [documentation index](doc/README.md) and
[solver planning semantics](doc/solver-planning.md) for current capabilities,
security boundaries, authenticated refresh usage, package acquisition and
cache behavior, policy behavior, and API/schema references.

## Requirements

- Zig 0.16.0 or newer
- liblzma development headers and library

## Build and test

```sh
zig build
zig build test
zig build run -- --help
```

## License

[Apache-2.0](LICENSE)

# debz

`debz` is an in-development, embeddable Debian-family package manager and CLI written in Zig. It is designed around explicit inputs, bounded parsing, authenticated repository metadata, deterministic dependency solving, verified package acquisition, and transaction planning while using `dpkg` as the eventual transaction backend. It does not yet modify packages or repositories.

## Public entry points

- `debz.planTransaction` creates an owned, deterministic transaction plan from authenticated repository snapshots and parsed dpkg state.
- `debz.acquirePackage` downloads or loads an authenticated solver-selected package, verifies its size and SHA-256, and publishes it to an explicit package CAS.
- `debz.repository_refresh.refreshAuthenticated` verifies repository signatures and metadata before publishing a solver-eligible snapshot.
- `debz.openpgp_verifier` verifies the project's supported OpenPGP profile without network, process, or ambient keyring access.
- `debz.SolverContext` imports eligible package indexes into a Debian-configured libsolv pool.
- `debz.dpkg_status`, `debz.source`, and the parser modules expose typed APIs for caller-supplied Debian metadata.

See the [documentation index](doc/README.md) for current capabilities, security boundaries, authenticated refresh usage, package acquisition and cache behavior, the supported OpenPGP profile, and API/schema references.

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

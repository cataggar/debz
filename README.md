# debz

An embeddable Debian-family package manager library and CLI written in Zig.

Release binaries are fully static Linux x64 or arm64 executables with Zig
0.17.0's reviewed musl snapshot and source-built libsolv, liblzma, and libzstd
included. Gzip and xz binary archives are covered by GitHub provenance
attestations.

## Quick start

Install the latest release with [ghr](https://cataggar.github.io/ghr/):

```sh
ghr install cataggar/debz
```

Without a tag, ghr installs the latest release:
[https://github.com/cataggar/debz/releases/latest](https://github.com/cataggar/debz/releases/latest).

Check the version and CLI help:

```sh
debz version
debz --help
```

## Documentation

Browse [`doc/README.md`](doc/README.md) for the complete CLI, library, JSON,
security, and implementation reference:

- [GitHub Actions](doc/github-actions.md) — first-party [`actions/setup`](actions/setup/README.md), [`actions/download`](actions/download/README.md), and [`actions/install`](actions/install/README.md) workflows.
- [Repository management](doc/repository-management.md) — `debz repo add` and reviewed freshness profiles.
- [Apt-shaped system facade](doc/apt-system-facade.md) — `debz apt` and `debz recover` profile-bound system interface.
- [Release installation and build](doc/release-installation.md) — building from source, version injection, and static-musl packaging.

## License

[Apache-2.0](LICENSE)

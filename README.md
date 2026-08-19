# debz

An embeddable Debian-family package manager library and CLI written in Zig.

```sh
zig build
zig build test
zig build run -- --help
zig build -Dversion=0.1.0
zig build install --prefix "$PWD/release-root"
```

`-Dversion` must be a SemVer value and defaults to the package version in
`build.zig.zon`. A complete install places the CLI in `bin/`, documentation
under `share/doc/debz/`, and schemas plus runtime dependency metadata under
`share/debz/`.

See [`doc/README.md`](doc/README.md) for the CLI, library, JSON, security, and
implementation reference. Licensed under [Apache-2.0](LICENSE).

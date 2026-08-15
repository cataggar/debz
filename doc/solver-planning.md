# Debian solver and planning semantics

The public planning boundary is debz-owned; libsolv IDs and rules never escape.
Inputs include authenticated repository identities and priorities, exact
installed state and holds, native/foreign architectures, a typed request, and
explicit policy. Candidate order is repository priority, Debian version,
architecture, then repository ID.

Holds, protected and essential packages, downgrades, replacements,
reverse-dependency removals, Recommends, and phased updates are denied unless
their policy permits them. Phased updates are disabled by default.
Deterministic percentage mode uses only caller input, never host identity,
randomness, wall-clock time, or APT configuration.

Relations support `:any`, `:native`, explicit architectures, architecture
restriction lists, and preserved build-profile groups. Binary transactions
evaluate profiles against an explicitly empty active-profile set. `Multi-Arch`
metadata is passed through libsolv's Debian metadata key.

`install_only` identities use libsolv multiversion jobs. Reinstall requires the
exact installed name, version, and architecture in an authenticated repository.
Reverse-dependency removal additionally requires every unrequested identity in
the computed closure to appear in `authorized_removals`.

Schema v2 adds operation mode, requested status, a complete summary, ordered
remove/unpack/configure steps, stable problem IDs, candidate rejection records,
and graph edges. Plan-only and download-only never execute dpkg. Schema v1
remains published for older consumers.

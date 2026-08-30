# Debian solver and planning semantics

The public planning boundary is debz-owned; libsolv IDs and rules never escape.
Inputs include authenticated repository identities and priorities, exact
installed state and holds, native/foreign architectures, a typed request, and
explicit policy. Candidate order is repository priority, Debian version,
architecture, then repository ID.

One strictly verified local artifact may be imported through
`RepositoryInput.fromLocalArtifact` alongside authenticated repositories.
libsolv receives a synthetic container, but the selected `PackageOrigin` and
public plan remain tagged `local_artifact`; the local archive cannot enter
through the trusted-test or repository package-acquisition boundaries.

Holds, protected and essential packages, downgrades, replacements,
reverse-dependency removals, Recommends, and phased updates are denied unless
their policy permits them. Phased updates are disabled by default.
Deterministic percentage mode uses only caller input, never host identity,
randomness, wall-clock time, or APT configuration.

Relations support `:any`, `:native`, explicit architectures, architecture
restriction lists, and preserved build-profile groups. Binary transactions
evaluate profiles against an explicitly empty active-profile set. `Multi-Arch`
metadata is passed through libsolv's Debian metadata key. `Pre-Depends` retains
its prerequisite marker, version relations use Debian EVR ordering, and
`Replaces` becomes a solver obsoletion only where a matching `Conflicts`
relation gives it replacement semantics.

The solver is created only after installed and available repositories are
fully imported, so all libsolv maps and rule ranges cover the final pool.
Available `Essential: yes` packages are included in install closures even when
Debian metadata omits explicit dependencies on them. A named install is
successful only if its selected identity is already installed or appears in
the materialized transaction. Problem diagnostics validate libsolv problem,
learned-rule, rule-range, and solvable IDs before converting them to stable
owned records.

`install_only` identities use libsolv multiversion jobs. Reinstall requires the
exact installed name, version, and architecture in an authenticated repository.
Reverse-dependency removal additionally requires every unrequested identity in
the computed closure to appear in `authorized_removals`.

Schema v2 adds operation mode, requested status, a complete summary, ordered
bootstrap-extract/remove/unpack/configure-pending steps, stable problem IDs,
candidate rejection records, and graph edges. Configure barriers preserve
Pre-Depends while leaving normal dependency-cycle ordering to dpkg. Plan-only
and download-only never execute dpkg. Schema v1 remains published for older
consumers.

Repository-only plans retain canonical schema-v2 output. A plan containing a
local artifact uses schema v3, where every archive-producing action serializes
a tagged `origin` rather than reinterpreting the v2 `repository` field.

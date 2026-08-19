# Releasing

Releases are immutable `vMAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]` tags on commits already merged to `main`. Stable examples use `v0.1.0`; prerelease examples use `v0.2.0-rc.1`. Never move, overwrite, force-push, delete for reuse, or recreate a release tag.

## Operator checklist

1. Confirm the intended version is valid SemVer, matches `build.zig.zon`, and does not already exist: `python3 tools/release.py version v0.1.0 --expect zon=0.1.0`.
2. Confirm the candidate commit is on current `origin/main`: `git fetch origin main --tags && git merge-base --is-ancestor HEAD origin/main && test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"`.
3. Confirm all required CI checks are green, including both native build/test lanes, both `Required release dry-run` lanes, `Required release workflow policy`, required disposable-root integration, security audit, and fuzzing.
4. Run the separate `CI` workflow manually with the pinned immutable Ubuntu snapshot URI and suite selected for the release. Require both native real-snapshot acceptance jobs to pass; normal pull-request CI intentionally does not download real Ubuntu archives.
5. Review `security/dependency-policy.json`, runtime library versions reported by CI, `THIRD_PARTY_NOTICES`, and the exact 26-asset plan from `python3 tools/release.py dry-run --tag v0.1.0`.
6. Create one annotated tag without changing the commit: `git tag -a v0.1.0 -m "debz 0.1.0"`.
7. Push only that tag: `git push origin refs/tags/v0.1.0`.
8. Watch the `Release` workflow through both native packages, the deterministic source comparison, exact manifest verification, gzip and xz provenance attestations, GitHub Release publication, and both post-release `ghr-bin==0.7.0` smoke jobs.
9. Confirm the release is named `debz 0.1.0`, its prerelease flag matches parsed SemVer, all 26 declared archive/checksum/SBOM/manifest assets are present exactly once, and `ghr install cataggar/debz@v0.1.0` succeeds on native x64 and arm64.
10. Verify both archive formats with `gh attestation verify debz-0.1.0-linux-x64.tar.gz --repo cataggar/debz` and `gh attestation verify debz-0.1.0-linux-x64.tar.xz --repo cataggar/debz` after downloading the assets.

The workflow fetches current `origin/main`, rejects a tagged commit outside its ancestry, validates the tag against `build.zig.zon` and the built CLI, embeds the version with `-Dversion`, and builds the complete `ReleaseSafe` install prefix. The merged clean-room tooling creates deterministic gzip and xz archives, checksum sidecars, per-archive SPDX 2.3 SBOMs and checksums, plus the canonical release manifest. Final verification requires exactly 26 regular assets and re-audits archived ELF architecture, dynamic dependencies, runtime metadata, deterministic encoding, checksums, and SBOMs before publication. SHA-256 sidecars and artifacts are unsigned; GitHub attestations cover every binary and source archive.

## Failure and rollback

If any job fails before publication, leave the failed tag unchanged, fix the problem on `main`, complete all gates again, and release a new version. Do not retarget or reuse the failed tag.

If publication succeeds but a smoke job or later investigation finds a defect, do not replace assets, edit provenance, or move the tag. Mark the release as affected in its notes, open a tracking issue, and publish a corrected next patch or prerelease tag after all gates pass. If an artifact must be withdrawn, remove the GitHub Release assets or release entry only as an explicit incident response while preserving the tag and audit record; users must be directed to a new version.

The workflow uses no repository secrets and cannot run on pull requests. A rerun is safe only when no GitHub Release exists for the tag; after publication, diagnose the existing immutable release instead of rerunning publication.

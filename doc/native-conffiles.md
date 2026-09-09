# Native conffile and removal acceptance

`zig build test-native-conffiles` compares the private native fixture driver
with real dpkg on isolated disposable roots. It does not select a production
native backend or execute maintainer scripts. The independent runner is
`tools/test-native-conffiles.py`, sharing the package builder, root guard,
bounded subprocess runner, and semantic comparator used by item 10b.

## Phase contract

| Phase | Reference operation | Required result |
|---|---|---|
| Unpack | `dpkg --unpack` | Ordinary conffiles stage as `.dpkg-new`; the live file is not prematurely replaced. New records use `newconffile`. Existing recorded digests survive until configure. |
| Configure | `dpkg --force-confold/--force-confnew --configure` | Apply the digest-based decision under the selected policy; publish compatible old/dist artifacts and configured database state. |
| Remove | `dpkg --remove` | Delete ordinary owned payload and obsolete info, retain residual conffiles and their database state, and preserve unrelated/shared contents. Packages without residual conffiles or `postrm` lose their status record. |
| Purge | `dpkg --purge` | Remove conffiles, recognized artifacts, and package metadata; remove only eligible empty owned directories. |

`remove-on-upgrade` is unpack-phase work: an unmodified file is deleted, a
modified file is saved as `.dpkg-old`, and an absent file stays absent. Its
recorded digest and flag remain in status. Dpkg deliberately preserves the
administrator's `.dpkg-old` created by remove-on-upgrade even on later purge;
the native fixture must preserve it too. A conffile omitted by the incoming
package is instead marked obsolete and remains owned.

The conffile policy only decides actual conflicts. If the maintainer has not
changed the file, a local edit or deletion is retained under either policy.
Already-packaged bytes require no replacement; an unmodified predecessor
does not require a conflict artifact. The compiler's pure
`native_program.conffileDecision` helper encodes this table.

## Executed fixture matrix

The runner compares roots immediately after every phase, not just after the
whole sequence. Coverage includes both policies on fresh, unchanged, edited,
deleted, and already-packaged files; obsolete and remove-on-upgrade cases;
repeated unpack without configure; downgrade and reinstall; installed and
unpacked removal/purge; repeated no-ops; and local files and co-owned
directories that must survive purge. Batch purge also checks that directories
shared only by the selected retiring packages are removed when empty.

The comparator covers live and staged bytes, path kinds, ownership, modes,
file/link timestamps, hard-link topology, status/status-old, ownership lists,
conffile declarations and records, checksums, architecture, and trigger state.
Ordinary directory timestamps and debz bookkeeping are excluded as in item
10b; where payload remains, the explicit empty archive directory timestamp is
also compared exactly.

Each native invocation must produce a bounded structured outcome report.
Reporting success without producing the reference state cannot pass.
Resolved operations must leave no active operation/mutation journal.
Script-bearing packages, unregistered local conffiles outside v1's observed
evidence, and unsupported conffile link types must hand off before mutation.
Generated staging-name collisions and foreign ownership of conffile artifacts
must also be refused before any mutation.

The fixture request extends the existing materialization driver with
`conffiles: true`, a `keep_existing` or `use_package_version` policy, and
`configure`, `remove`, or `purge` operations. Configure receives the original
archive bytes; remove/purge receive selected `(name, architecture)` package
identities and need no archive. The default item-10b request still defers
conffile work.

Phase preflight checks program/root/database/policy binding and rejects
unsupported package states, malformed configuration-version evidence, scripts,
triggers, diversions, overrides, and opaque metadata. Conffile observations are
bounded and staged bytes are checked against the bound archive with SHA-256.
The final phase digest incorporates the concrete mutation-plan step digest.
Unexpected preparation failures preserve active evidence, and a failed
recovery-state publication is propagated rather than ignored.

Native amd64 and arm64 CI run the target in Debug and ReleaseSafe.
`--oracle-only` checks reference fixture consistency; it does not execute
native code and is not native parity evidence. Production authorization,
lifecycle/script execution, triggers, recovery orchestration, and provenance
integration remain later roadmap work.

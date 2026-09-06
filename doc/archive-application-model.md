# Native archive application model

`debz.archive_application` turns one validated `.deb` into the exact,
application-ready description the native transaction engine needs before it may
mutate an install root. It builds on `deb_archive`, `deb_payload`,
`control_record`, and `relation` instead of invoking `dpkg-deb`, and it never
writes a target file, executes a script, or implements package-database or
lifecycle semantics.

Call `archive_application.prepare` with the artifact bytes and the acquisition
boundary that produced them:

- `.repository` carries the authenticated repository, package identity,
  filename, byte count, and SHA-256 selected by acquisition;
- `.local` carries the standalone-artifact boundary, where optional size,
  digest, and identity expectations still fail closed.

Success returns an owned `Model`; every failure returns a typed `Diagnostic`
that names the stage, code, offset, and the `UnsupportedFeature` classification
the engine refuses to approximate. Call `deinit` on a successful model.

## Modeled application facts

| Surface | Contents |
|---|---|
| `identity`, `facts` | Package, version, architecture, `Essential`, `Protected`, `Important`, `Multi-Arch`, `Priority`, and `Installed-Size`. |
| `relationshipText` / `relationship` | Exact declared text and the parsed AST for `Pre-Depends`, `Depends`, `Recommends`, `Suggests`, `Enhances`, `Conflicts`, `Breaks`, `Replaces`, and `Provides`. |
| `files` | Every payload entry with its normalized archive-root-relative path, kind, permission and special mode bits, numeric uid/gid, USTAR owner/group names, mtime, size, bounded content offsets, SHA-256, verified MD5, canonical link identity, exact symlink bytes, and conffile flag. |
| `root` | Metadata of the conventional `./` archive root record when the archive ships one. |
| `scripts` | `preinst`, `postinst`, `prerm`, `postrm`, and the debconf `config` script with safe name, kind, mode, size, SHA-256, and bounded bytes. |
| `metadata` | `templates`, `shlibs`, and `symbols` retained verbatim with digests and never interpreted. |
| `conffiles` | Declarations including Debian `remove-on-upgrade`, each resolved against the payload. |
| `checksums` | Parsed and verified `md5sums` entries bound to payload file indexes. |
| `triggers` | `interest`, `interest-await`, `interest-noawait`, `activate`, `activate-await`, and `activate-noawait` declarations with await policy and name/path target classification. |
| `features` | The supported features this archive actually uses, for corpus inventory and cutover gates. |
| `digest` | Deterministic SHA-256 of the complete modeled application. |

`fileBytes`, `scriptBytes`, and `metadataBytes` expose only already validated,
bounded content from the decompressed members. Paths are canonical and
root-relative; they are never absolute and never traverse.

## Deterministic application digest

`digest` hashes a length-prefixed, domain-separated encoding of the model:
`debz.archive-application.v1`, the model version, identity, provenance kind,
origin, filename, artifact size and SHA-256, control facts, every relationship
field, the archive root record, both member compressions, and every file,
script, retained metadata member, conffile, checksum, and trigger in archive
order. Identical archive bytes with identical expectations always produce the
same digest, and any modeled metadata change produces a different one. The
future native program compiler binds this digest into the authorized program.

## Artifact binding and pre-application revalidation

The authenticated size, digest, and origin recorded at acquisition stay bound to
the model:

- `Model.verifyArtifactBinding` re-hashes in-memory artifact bytes and compares
  them with the recorded size and SHA-256 in constant time;
- `archive_application.revalidate` re-validates and re-models the artifact
  immediately before application and requires the reproduced digest to equal the
  previously authorized digest.

Callers hold only the authorized digest between review and application, so a
substituted, truncated, or re-signed archive fails closed before mutation.
Origin is part of that binding: the digest covers the provenance kind,
repository, and filename, so revalidating the same bytes under a different
origin or identity expectation cannot reproduce the authorized digest.

## V1 feature classification

Support is explicit. Anything outside the profile is rejected during preflight
with a typed diagnostic instead of being approximated.

Supported:

- Debian 2.0 `ar` containers with `debian-binary`, one control member, and one
  data member, plus recognized debsigs members;
- uncompressed, gzip, xz, and zstd control and data members;
- POSIX USTAR and GNU base headers with bounded GNU long-name and long-link
  records;
- regular files, directories, symbolic links, and backward hard links;
- permission and special mode bits, numeric uid/gid, bounded USTAR owner and
  group names, and modification time;
- the control members `control`, `conffiles`, `md5sums`, `triggers`, `preinst`,
  `postinst`, `prerm`, `postrm`, and `config`;
- `templates`, `shlibs`, and `symbols` as retained, uninterpreted metadata,
  matching dpkg's behavior of copying them into the package information
  directory.

Rejected before mutation, with the classification in parentheses:

- PAX extended and global headers, archive xattrs, ACLs, labels, and malformed
  or dangling GNU extension records (`tar_extension`);
- devices, FIFOs, sockets, sparse entries, and unknown type flags
  (`file_type`);
- mode bits outside the permission and special bits, and malformed owner or
  group metadata (`file_metadata`);
- unrecognized or unsupported compression and trailing compressed data
  (`compression`);
- absolute, traversing, duplicate, conflicting, symlink-mediated, or forward
  link paths (`path_or_link`);
- any control member outside the table above, non-regular control entries,
  setuid or setgid control members (`control_member`);
- a maintainer script that is not executable (`maintainer_script`);
- malformed, duplicate, mismatched, or out-of-inventory `md5sums` entries
  (`checksum_manifest`);
- conffiles that the payload does not ship as regular files, and
  `remove-on-upgrade` conffiles that the payload does ship
  (`conffile_declaration`);
- unknown trigger directives, unsafe trigger names or paths, and duplicate
  trigger targets (`trigger_declaration`);
- identity, request, filename, size, and digest disagreements
  (`identity_binding`);
- every configured count and byte limit (`resource_limit`).

`alternatives` is deliberately not in the supported control-member table. dpkg
acts on that member, so accepting and ignoring it would silently change package
semantics; v1 rejects it and requires an explicit contract revision instead.
The debconf `config` script is modeled and preserved but never executed by v1,
because debconf preconfiguration is a frontend responsibility outside the dpkg
replacement boundary.

A missing `md5sums` member is supported because Debian packages do not
universally ship one, and `dh_md5sums` omits conffiles by default. Every entry
that is present must name a regular payload file, or a hard link to one, and
must match the exact linked bytes.

## Fixture inventory and the v1 support decision

The pinned fixtures currently exercise a deliberately small part of the profile.

| Fixture | Exercised features |
|---|---|
| `src/fixtures/packages-microsoft-prod*.deb` | Uncompressed control and data tars, USTAR headers, archive root record, directories, regular files, root ownership, `control` only. |
| `src/fixtures/deb-payload/*.tar{,.gz,.xz,.zst}` | Uncompressed, gzip, xz, and zstd control and data members. |
| `tools/generate-integration-repository.py` packages | gzip control and data members, `control`, `conffiles`, `triggers` with `interest-noawait` on a path target, an executable `postinst`, dependencies, `Pre-Depends`, `Provides`, `Conflicts`, `Breaks`, `Replaces`, `Essential`, `Protected`, and `Multi-Arch`. |

No pinned fixture ships `md5sums`, symbolic or hard links, setuid or setgid
payload entries, non-root ownership, GNU long names, `remove-on-upgrade`
conffiles, retained metadata members, or `config`. Those paths are therefore
covered by the adversarial and positive unit tests in
`src/archive_application.zig` and by the `archive-application-model`,
`archive-checksum-verification`, and `archive-unsupported-feature` scenarios in
`test/native-transaction/corpus-v1.json`.

The v1 decision is to model the complete supported profile now, keep every
unsupported feature a typed preflight rejection, and treat the real-snapshot
feature inventory as a cutover gate. Encountering a rejected feature in a
required Debian or Ubuntu closure requires a contract revision and an
implementation, never a silent approximation.

## Limits

`Limits` embeds the `deb_payload` limits and adds independent bounds on modeled
payload entries, control members and their bytes, `md5sums` bytes and entries,
and trigger bytes, declarations, and target length. Every limit failure is a
typed `resource_limit` diagnostic.

`archive_application.fuzzOne` is the side-effect-free fuzz boundary; it models
one archive, exercises the binding check and diagnostic classification, and
releases every successful result immediately.

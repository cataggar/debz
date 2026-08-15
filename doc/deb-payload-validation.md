# Debian payload validation

Use `debz.deb_payload.validate` only after acquisition has selected an authenticated repository record. The caller supplies the exact repository, selected and requested package identity, repository filename, byte count, and SHA-256. Validation rejects any disagreement; filenames are diagnostic input and never replace authenticated metadata or the `control` file.

The validator first checks size and SHA-256, validates the outer `ar` archive, and boundedly decompresses plain, gzip, xz, or zstd `control.tar` and `data.tar` members. `Limits` independently bounds archive/member bytes, compressed and decompressed bytes, decoder memory, tar entries, aggregate payload bytes, inventory memory, paths, links, control metadata, and conffile bytes and entries. Every failure returns a typed stage/code and outer or inner byte offset. No partially validated result is returned.

The built-in tar policy requires POSIX USTAR headers and verifies checksums, octal metadata and overflow, content padding, two-block termination, and zero-only trailing records. A single conventional leading `./` is canonicalized. Absolute paths, empty/internal dot components, traversal, backslashes, control bytes, normalization collisions, duplicate/conflicting destinations, forward hardlinks, escaping links, symlink-mediated descendants or link targets, link-ordering attacks, devices, FIFOs, sockets, and unknown special types are rejected. Safe USTAR prefix paths are supported; GNU and PAX extensions are explicitly unsupported and fail closed.

A successful owned `Validation` inventories canonical control/data entries, compression and byte summaries, maintainer script names/modes/sizes, and conffiles (including the `obsolete` qualifier). It never follows host links, touches an install root, executes scripts, or unpacks files. Call `deinit` when finished.

`debz.deb_payload.fuzzOne` is the side-effect-free entry point for fuzzing decompressor, tar, control, identity, and path/link boundaries. Seed it with the deterministic fixtures under `src/fixtures/deb-payload/` and malformed regressions; always use deliberately small limits for bomb campaigns.

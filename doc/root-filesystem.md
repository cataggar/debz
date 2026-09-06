# Root-anchored filesystem primitives

`src/root_fs.zig` implements the traversal-safe filesystem layer required by
the [native transaction engine](native-transaction-engine-v1.md). Every native
database read, archive application, staging, and publication step goes through
this module so that the engine has exactly one audited way to touch a selected
root.

The module implements filesystem primitives only. Package semantics, lifecycle
ordering, conffile decisions, and maintainer scripts are not part of this
boundary.

## Anchoring model

`Root` borrows an already opened root directory descriptor and never closes it.
`openAbsoluteRoot` is available for callers that only have a canonical absolute
path; it opens `/` and then each component with `O_NOFOLLOW`, using the same
absolute grammar as locks, plans, and provenance (`src/absolute_path.zig`).

The root descriptor must be a complete directory descriptor. On Linux, a
descriptor opened without `iterate` is an `O_PATH` handle that cannot be
`fsync`ed or `fchmod`ed, so every directory this module opens requests a real
descriptor.

## Path grammar

`root_fs.Path` accepts only canonical root-relative paths:

- at least one component and no leading `/`;
- no empty, `.`, or `..` component and no trailing slash;
- no NUL or other control byte, and no `\`, which is a separator on Windows and
  never appears in a supported Debian payload path;
- at most 4096 path bytes, 255 component bytes, and 128 components.

`Path.fromAbsolute` converts the canonical absolute spelling used by the dpkg
database and exact locks; `/` has no relative spelling and is rejected.
Validation happens before any syscall, so malformed database or archive input
fails closed without touching the root.

## Resolution and race behavior

Paths are resolved one component at a time from the root descriptor with
symbolic-link following disabled, and `..` never reaches the kernel. A symbolic
link anywhere in a path is a typed failure:

| Situation | Result |
|---|---|
| Symbolic link as an intermediate or directory component | `error.SymbolicLinkComponent` |
| Symbolic link where a regular file is required | `error.NotRegularFile` |
| Non-directory where a directory is required | `error.NotDirectory` |
| Device, socket, FIFO, or unknown kind via `supportedMetadata` | `error.UnsupportedPathKind` |

Linux reports both "component is a symbolic link" and "component is not a
directory" as `ENOTDIR` for `O_DIRECTORY | O_NOFOLLOW`, so the failing
component is classified with a no-follow stat. That classification is only a
diagnostic; traversal has already been refused.

Because no component is ever followed through a link and `..` never appears, a
symlink planted between validation and use cannot redirect an operation outside
the root. Where the operating system supports it, file operations additionally
request `resolve_beneath`. Residual risk: an attacker who can already rename a
real directory of a resolved prefix out of the root can move descriptors this
module holds open, which requires write access to root-owned directories and is
outside the engine's trust boundary.

## Mutation and publication policy

Direct creation is always exclusive. `createRegularFile`, `createDirectory`,
and `createSymbolicLink` fail with `error.PathAlreadyExists` when the name is
in use, including by a symbolic link, so a planted link is never written
through. `createDirectoryPath` creates missing components and proves that each
existing component is a real directory.

Replacing an existing path is possible only through atomic publication:

- `stageFile` creates a private `.debz-stage-*` entry with `0o600` permissions
  in the destination directory. `deinit` removes an uncommitted entry, so an
  interrupted caller never publishes a partial file.
- `commit` applies the exact requested permissions, fsyncs the contents,
  renames the staging entry over the destination, and fsyncs the destination
  directory. `publishFile` and `publishSymbolicLink` wrap that sequence.
- `OverwritePolicy.replace` renames over any existing entry, replacing a
  symbolic link itself rather than its target.
  `OverwritePolicy.fail_if_exists` requires a non-replacing rename; when the
  filesystem cannot perform one, publication fails with
  `error.AtomicPublicationUnsupported` instead of falling back to a racy check.

Permissions are applied explicitly after creation so that the published mode
does not depend on the process umask.

`removeFile` unlinks a name, never a link target; `removeDirectory` removes an
empty directory; `rename` moves within the root under the same explicit
overwrite policy. `syncDirectory` and `syncRoot` provide parent-directory
durability where the platform supports it.

## Testing

`src/root_fs.zig` carries hermetic adversarial tests covering the path grammar,
absolute and traversing input, intermediate and final symbolic links, escaping
link targets, exclusive-creation refusals that leave link targets untouched,
symlink replacement by publication, directory/file transitions, overwrite
policy, staging cleanup, unsupported path kinds, and durability calls. They run
in temporary roots as part of `zig build test`.

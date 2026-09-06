//! Root-anchored, traversal-safe filesystem primitives for the native
//! transaction engine.
//!
//! Every operation is expressed as a validated relative path resolved one
//! component at a time from an already opened root directory descriptor. No
//! component is ever resolved through a symbolic link, `..` never appears in a
//! resolved path, and absolute paths are rejected before any syscall. The
//! resulting descriptors therefore cannot be steered outside the selected root
//! by a symlink planted between validation and use.
//!
//! Residual risk: an attacker who can already rename a real directory that is
//! part of a resolved prefix out of the root can move descriptors this module
//! holds. That requires write access to root-owned directories, which is
//! outside the native engine's trust boundary. Where the operating system
//! supports it, file operations additionally request `resolve_beneath`.
//!
//! Overwriting an existing path is only possible through atomic publication
//! (`stageFile`/`publishFile`/`publishSymbolicLink`), which writes a private
//! staging entry in the destination directory, fsyncs it, and renames it over
//! the destination. Direct creation is always exclusive, so a planted symlink
//! can never be written through.

const std = @import("std");
const builtin = @import("builtin");
const absolute_path = @import("absolute_path.zig");
const package_acquisition = @import("package_acquisition.zig");

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;

/// Bounded path grammar. The limits are deliberately smaller than the kernel's
/// so that malformed database or archive input fails before any syscall.
pub const maximum_path_bytes = 4096;
pub const maximum_component_bytes = 255;
pub const maximum_path_components = 128;
pub const maximum_link_target_bytes = 4095;

const staging_prefix = ".debz-stage-";
const staging_attempts = 8;

pub const PathError = error{
    EmptyPath,
    AbsolutePath,
    TraversingPath,
    EmptyPathComponent,
    InvalidPathByte,
    PathTooLong,
    PathComponentTooLong,
    PathTooDeep,
};

pub const KindError = error{
    NotRegularFile,
    NotDirectory,
    SymbolicLinkComponent,
    UnsupportedPathKind,
};

pub const PublicationError = error{
    AtomicPublicationUnsupported,
    StagingNameExhausted,
    StagedFileClosed,
};

pub const LinkError = error{
    EmptyLinkTarget,
    LinkTargetTooLong,
    InvalidLinkTargetByte,
};

/// A validated root-relative path. The text is borrowed; callers own it for
/// the lifetime of any derived operation.
pub const Path = struct {
    text: []const u8,

    /// Accepts only canonical relative paths: at least one component, no
    /// leading `/`, no empty, `.`, or `..` component, no control byte, and no
    /// `\` (which is a separator on Windows and never appears in a supported
    /// Debian payload path).
    pub fn init(text: []const u8) PathError!Path {
        if (text.len == 0) return error.EmptyPath;
        if (text[0] == '/') return error.AbsolutePath;
        if (text.len > maximum_path_bytes) return error.PathTooLong;
        var components = std.mem.splitScalar(u8, text, '/');
        var count: usize = 0;
        while (components.next()) |component| {
            if (component.len == 0) return error.EmptyPathComponent;
            if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
                return error.TraversingPath;
            if (component.len > maximum_component_bytes) return error.PathComponentTooLong;
            for (component) |byte| {
                if (byte < 0x20 or byte == 0x7f or byte == '\\') return error.InvalidPathByte;
            }
            count += 1;
            if (count > maximum_path_components) return error.PathTooDeep;
        }
        return .{ .text = text };
    }

    /// Accepts the canonical absolute spelling used by locks, plans, and the
    /// dpkg database and converts it to a root-relative path. `/` has no
    /// relative spelling and is rejected.
    pub fn fromAbsolute(text: []const u8) PathError!Path {
        if (text.len == 0) return error.EmptyPath;
        if (text[0] != '/') return error.AbsolutePath;
        if (!absolute_path.nonRoot(text)) return error.TraversingPath;
        return init(text[1..]);
    }

    pub fn basename(self: Path) []const u8 {
        const index = std.mem.lastIndexOfScalar(u8, self.text, '/') orelse return self.text;
        return self.text[index + 1 ..];
    }

    pub fn parent(self: Path) ?Path {
        const index = std.mem.lastIndexOfScalar(u8, self.text, '/') orelse return null;
        return .{ .text = self.text[0..index] };
    }

    pub fn depth(self: Path) usize {
        return std.mem.count(u8, self.text, "/") + 1;
    }

    pub fn eql(self: Path, other: Path) bool {
        return std.mem.eql(u8, self.text, other.text);
    }
};

pub const Metadata = struct {
    kind: File.Kind,
    size: u64,
    permissions: File.Permissions,
    link_count: File.NLink,
    inode: File.INode,
    modified: Io.Timestamp,

    fn fromStat(stat: File.Stat) Metadata {
        return .{
            .kind = stat.kind,
            .size = stat.size,
            .permissions = stat.permissions,
            .link_count = stat.nlink,
            .inode = stat.inode,
            .modified = stat.mtime,
        };
    }

    pub fn isRegularFile(self: Metadata) bool {
        return self.kind == .file;
    }

    pub fn isDirectory(self: Metadata) bool {
        return self.kind == .directory;
    }

    pub fn isSymbolicLink(self: Metadata) bool {
        return self.kind == .sym_link;
    }

    /// The native engine supports only regular files, directories, and
    /// symbolic links. Everything else fails closed before mutation.
    pub fn isSupportedKind(self: Metadata) bool {
        return switch (self.kind) {
            .file, .directory, .sym_link => true,
            else => false,
        };
    }
};

pub const OverwritePolicy = enum {
    /// `error.PathAlreadyExists` when the destination name exists.
    fail_if_exists,
    /// Atomically replaces the destination name, including a symbolic link,
    /// without ever writing through it.
    replace,
};

pub const CreateFileOptions = struct {
    permissions: File.Permissions = default_file_permissions,
    read: bool = false,
};

pub const PublishOptions = struct {
    permissions: File.Permissions = default_file_permissions,
    overwrite: OverwritePolicy = .replace,
    /// Fsyncs the staged contents and the destination directory so that a
    /// successful publication survives power loss.
    durable: bool = true,
};

pub const default_file_permissions: File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o644);
pub const default_directory_permissions: File.Permissions =
    if (builtin.os.tag == .windows) .default_dir else .fromMode(0o755);

/// A resolved destination directory plus the final name. Intermediate
/// components have already been resolved without following symbolic links.
pub const Parent = struct {
    dir: Dir,
    leaf: []const u8,
    owned: bool,

    pub fn close(self: *Parent, io: Io) void {
        if (self.owned) self.dir.close(io);
        self.* = undefined;
    }
};

/// A staged file that becomes visible at its destination only on `commit`.
/// `deinit` removes an uncommitted staging entry, so an interrupted caller
/// never publishes a partial file.
pub const StagedFile = struct {
    io: Io,
    parent: Parent,
    file: File,
    name_buffer: [staging_prefix.len + 16 + 4]u8,
    name_length: usize,
    options: PublishOptions,
    file_open: bool,
    staged: bool,

    pub fn name(self: *const StagedFile) []const u8 {
        return self.name_buffer[0..self.name_length];
    }

    pub fn writeAll(self: *StagedFile, bytes: []const u8) !void {
        if (!self.file_open) return error.StagedFileClosed;
        try self.file.writeStreamingAll(self.io, bytes);
    }

    /// Streaming writer for payload-sized content. It appends at the
    /// descriptor's current offset, so it composes with `writeAll` and with
    /// earlier writers instead of restarting at offset zero. The caller must
    /// flush before `commit`.
    pub fn writer(self: *StagedFile, buffer: []u8) !File.Writer {
        if (!self.file_open) return error.StagedFileClosed;
        return self.file.writerStreaming(self.io, buffer);
    }

    pub fn commit(self: *StagedFile) !void {
        if (!self.file_open) return error.StagedFileClosed;
        if (builtin.os.tag != .windows)
            try self.file.setPermissions(self.io, self.options.permissions);
        if (self.options.durable) try self.file.sync(self.io);
        self.file.close(self.io);
        self.file_open = false;
        switch (self.options.overwrite) {
            .replace => try self.parent.dir.rename(
                self.name(),
                self.parent.dir,
                self.parent.leaf,
                self.io,
            ),
            .fail_if_exists => self.parent.dir.renamePreserve(
                self.name(),
                self.parent.dir,
                self.parent.leaf,
                self.io,
            ) catch |err| switch (err) {
                error.OperationUnsupported => return error.AtomicPublicationUnsupported,
                else => return err,
            },
        }
        self.staged = false;
        if (self.options.durable) try syncDir(self.io, self.parent.dir);
    }

    pub fn deinit(self: *StagedFile) void {
        if (self.file_open) {
            self.file.close(self.io);
            self.file_open = false;
        }
        if (self.staged) {
            self.parent.dir.deleteFile(self.io, self.name()) catch {};
            self.staged = false;
        }
        self.parent.close(self.io);
        self.* = undefined;
    }
};

/// Root-relative filesystem access anchored to an already opened directory.
/// The root descriptor is borrowed; `Root` never closes it. It must be a
/// complete directory descriptor, which on Linux means it was not opened with
/// `O_PATH`; `openAbsoluteRoot` and `Io.Dir.OpenOptions.iterate` produce one.
pub const Root = struct {
    io: Io,
    dir: Dir,

    pub fn init(io: Io, dir: Dir) Root {
        return .{ .io = io, .dir = dir };
    }

    pub fn metadataOfRoot(self: Root) !Metadata {
        return Metadata.fromStat(try self.dir.stat(self.io));
    }

    /// Opens a directory by resolving one component at a time. A symbolic link
    /// anywhere in the path fails with `error.SymbolicLinkComponent`.
    pub fn openDirectory(self: Root, path: Path) !Dir {
        var current: ?Dir = null;
        errdefer if (current) |dir| dir.close(self.io);
        var components = std.mem.splitScalar(u8, path.text, '/');
        while (components.next()) |component| {
            const base = current orelse self.dir;
            const next = try openComponent(self.io, base, component);
            if (current) |dir| dir.close(self.io);
            current = next;
        }
        return current.?;
    }

    /// Resolves everything but the final component. Callers must `close` the
    /// result; it borrows the root descriptor for single-component paths.
    pub fn openParent(self: Root, path: Path) !Parent {
        const index = std.mem.lastIndexOfScalar(u8, path.text, '/') orelse
            return .{ .dir = self.dir, .leaf = path.text, .owned = false };
        const dir = try self.openDirectory(.{ .text = path.text[0..index] });
        return .{ .dir = dir, .leaf = path.text[index + 1 ..], .owned = true };
    }

    /// Creates the final component. Fails with `error.PathAlreadyExists` when
    /// any entry, including a symbolic link, already uses the name.
    pub fn createDirectory(self: Root, path: Path, permissions: File.Permissions) !void {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        try parent.dir.createDir(self.io, parent.leaf, permissions);
        try applyDirectoryPermissions(self.io, parent.dir, parent.leaf, permissions);
    }

    /// Idempotent `createDirectory`. An existing entry must already be a real
    /// directory; a symbolic link to a directory fails closed.
    pub fn ensureDirectory(self: Root, path: Path, permissions: File.Permissions) !void {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        parent.dir.createDir(self.io, parent.leaf, permissions) catch |err| switch (err) {
            error.PathAlreadyExists => {
                var existing = try openComponent(self.io, parent.dir, parent.leaf);
                existing.close(self.io);
                return;
            },
            else => return err,
        };
        try applyDirectoryPermissions(self.io, parent.dir, parent.leaf, permissions);
    }

    /// Creates every missing component and proves that each existing one is a
    /// real directory.
    pub fn createDirectoryPath(self: Root, path: Path, permissions: File.Permissions) !void {
        var current: ?Dir = null;
        defer if (current) |dir| dir.close(self.io);
        var components = std.mem.splitScalar(u8, path.text, '/');
        while (components.next()) |component| {
            const base = current orelse self.dir;
            var created = true;
            base.createDir(self.io, component, permissions) catch |err| switch (err) {
                error.PathAlreadyExists => created = false,
                else => return err,
            };
            const next = try openComponent(self.io, base, component);
            errdefer next.close(self.io);
            if (created and builtin.os.tag != .windows)
                try next.setPermissions(self.io, permissions);
            if (current) |dir| dir.close(self.io);
            current = next;
        }
    }

    /// Opens an existing regular file. Directories, symbolic links, and
    /// special files fail with `error.NotRegularFile`.
    pub fn openRegularFile(self: Root, path: Path) !File {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        return package_acquisition.openRegularFileNoFollow(
            parent.dir,
            self.io,
            parent.leaf,
        ) catch |err| return mapRegularFileError(err);
    }

    /// Reads the whole file when it is at most `maximum_bytes` long and fails
    /// with `error.FileTooLarge` otherwise. The saturating probe limit keeps a
    /// file of exactly `maximum_bytes` readable, because `allocRemaining`
    /// fails once its own limit is reached.
    pub fn readFileAlloc(
        self: Root,
        allocator: std.mem.Allocator,
        path: Path,
        maximum_bytes: usize,
    ) ![]u8 {
        var file = try self.openRegularFile(path);
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        return reader.interface.allocRemaining(allocator, .limited(maximum_bytes +| 1)) catch |err|
            switch (err) {
                error.StreamTooLong => error.FileTooLarge,
                error.ReadFailed => reader.err.?,
                else => |other| other,
            };
    }

    /// Creates a new regular file exclusively. Exclusive creation never
    /// follows a symbolic link, so an existing link fails with
    /// `error.PathAlreadyExists` instead of writing through it. Replacing an
    /// existing path requires `publishFile`.
    pub fn createRegularFile(self: Root, path: Path, options: CreateFileOptions) !File {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        const file = parent.dir.createFile(self.io, parent.leaf, .{
            .exclusive = true,
            .truncate = false,
            .read = options.read,
            .permissions = options.permissions,
            .resolve_beneath = true,
        }) catch |err| return mapLeafError(err);
        errdefer file.close(self.io);
        if (builtin.os.tag != .windows)
            try file.setPermissions(self.io, options.permissions);
        return file;
    }

    /// Metadata for the final component without following it.
    pub fn metadata(self: Root, path: Path) !Metadata {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        const stat = parent.dir.statFile(self.io, parent.leaf, .{
            .follow_symlinks = false,
        }) catch |err| return mapLeafError(err);
        return Metadata.fromStat(stat);
    }

    /// Metadata restricted to the kinds the native engine can act on.
    /// Devices, sockets, FIFOs, and unknown kinds fail closed.
    pub fn supportedMetadata(self: Root, path: Path) !Metadata {
        const info = try self.metadata(path);
        if (!info.isSupportedKind()) return error.UnsupportedPathKind;
        return info;
    }

    /// `null` when the path, or any parent component, does not exist.
    pub fn metadataIfExists(self: Root, path: Path) !?Metadata {
        return self.metadata(path) catch |err| switch (err) {
            error.FileNotFound => null,
            else => err,
        };
    }

    pub fn readSymbolicLink(self: Root, path: Path, buffer: []u8) ![]const u8 {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        const length = parent.dir.readLink(self.io, parent.leaf, buffer) catch |err|
            return mapLeafError(err);
        return buffer[0..length];
    }

    /// Creates a symbolic link. The name must be unused; symbolic-link
    /// creation never follows an existing entry.
    pub fn createSymbolicLink(self: Root, path: Path, target: []const u8) !void {
        try validateLinkTarget(target);
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        parent.dir.symLink(self.io, target, parent.leaf, .{}) catch |err|
            return mapLeafError(err);
    }

    /// Atomically publishes a symbolic link, replacing an existing entry
    /// according to `overwrite` without writing through it.
    pub fn publishSymbolicLink(
        self: Root,
        path: Path,
        target: []const u8,
        options: PublishOptions,
    ) !void {
        try validateLinkTarget(target);
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        var name_buffer: [staging_prefix.len + 16 + 4]u8 = undefined;
        var attempt: usize = 0;
        const staged = while (attempt < staging_attempts) : (attempt += 1) {
            const candidate = stagingName(&name_buffer);
            parent.dir.symLink(self.io, target, candidate, .{}) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => return mapLeafError(err),
            };
            break candidate;
        } else return error.StagingNameExhausted;
        errdefer parent.dir.deleteFile(self.io, staged) catch {};
        switch (options.overwrite) {
            .replace => try parent.dir.rename(staged, parent.dir, parent.leaf, self.io),
            .fail_if_exists => parent.dir.renamePreserve(
                staged,
                parent.dir,
                parent.leaf,
                self.io,
            ) catch |err| switch (err) {
                error.OperationUnsupported => return error.AtomicPublicationUnsupported,
                else => return err,
            },
        }
        if (options.durable) try syncDir(self.io, parent.dir);
    }

    /// Opens a private staging file in the destination directory. The result
    /// must be released with `deinit`, which removes an uncommitted entry.
    pub fn stageFile(self: Root, path: Path, options: PublishOptions) !StagedFile {
        var parent = try self.openParent(path);
        errdefer parent.close(self.io);
        var staged: StagedFile = .{
            .io = self.io,
            .parent = parent,
            .file = undefined,
            .name_buffer = undefined,
            .name_length = 0,
            .options = options,
            .file_open = false,
            .staged = false,
        };
        var attempt: usize = 0;
        while (attempt < staging_attempts) : (attempt += 1) {
            const candidate = stagingName(&staged.name_buffer);
            staged.file = parent.dir.createFile(self.io, candidate, .{
                .exclusive = true,
                .truncate = false,
                .permissions = private_staging_permissions,
                .resolve_beneath = true,
            }) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => return mapLeafError(err),
            };
            staged.name_length = candidate.len;
            staged.file_open = true;
            staged.staged = true;
            return staged;
        }
        return error.StagingNameExhausted;
    }

    /// Writes `bytes` and publishes them atomically at `path`.
    pub fn publishFile(self: Root, path: Path, bytes: []const u8, options: PublishOptions) !void {
        var staged = try self.stageFile(path, options);
        defer staged.deinit();
        try staged.writeAll(bytes);
        try staged.commit();
    }

    /// Removes a non-directory entry. A symbolic link is removed itself, never
    /// its target.
    pub fn removeFile(self: Root, path: Path) !void {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        parent.dir.deleteFile(self.io, parent.leaf) catch |err| return mapLeafError(err);
    }

    /// Removes an empty directory.
    pub fn removeDirectory(self: Root, path: Path) !void {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        parent.dir.deleteDir(self.io, parent.leaf) catch |err| return mapLeafError(err);
    }

    /// Renames within the same root. Neither final component is followed.
    pub fn rename(self: Root, old: Path, new: Path, policy: OverwritePolicy) !void {
        var old_parent = try self.openParent(old);
        defer old_parent.close(self.io);
        var new_parent = try self.openParent(new);
        defer new_parent.close(self.io);
        switch (policy) {
            .replace => try old_parent.dir.rename(
                old_parent.leaf,
                new_parent.dir,
                new_parent.leaf,
                self.io,
            ),
            .fail_if_exists => old_parent.dir.renamePreserve(
                old_parent.leaf,
                new_parent.dir,
                new_parent.leaf,
                self.io,
            ) catch |err| switch (err) {
                error.OperationUnsupported => return error.AtomicPublicationUnsupported,
                else => return err,
            },
        }
    }

    /// Fsyncs a root-relative directory so that entries created or renamed in
    /// it survive power loss.
    pub fn syncDirectory(self: Root, path: Path) !void {
        var dir = try self.openDirectory(path);
        defer dir.close(self.io);
        try syncDir(self.io, dir);
    }

    pub fn syncRoot(self: Root) !void {
        try syncDir(self.io, self.dir);
    }
};

/// A root opened by this module. Used by callers that only have an absolute
/// path; the descriptor is closed by `close`.
pub const OwnedRoot = struct {
    root: Root,

    pub fn close(self: *OwnedRoot) void {
        self.root.dir.close(self.root.io);
        self.* = undefined;
    }
};

/// Opens `path` as a root by walking `/` one component at a time without
/// following symbolic links. `path` must use the canonical absolute grammar
/// shared with locks, plans, and provenance.
pub fn openAbsoluteRoot(io: Io, path: []const u8) !OwnedRoot {
    if (!absolute_path.root(path)) return error.InvalidAbsolutePath;
    var current = try Dir.openDirAbsolute(io, "/", .{
        .follow_symlinks = false,
        .iterate = true,
    });
    errdefer current.close(io);
    if (path.len > 1) {
        var components = std.mem.splitScalar(u8, path[1..], '/');
        while (components.next()) |component| {
            const next = try openComponent(io, current, component);
            current.close(io);
            current = next;
        }
    }
    return .{ .root = .init(io, current) };
}

const private_staging_permissions: File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);

var staging_counter: std.atomic.Value(u64) = .init(0);

fn stagingName(buffer: *[staging_prefix.len + 16 + 4]u8) []const u8 {
    const written = std.fmt.bufPrint(buffer, staging_prefix ++ "{x:0>16}.tmp", .{
        staging_counter.fetchAdd(1, .monotonic),
    }) catch unreachable;
    return written;
}

fn applyDirectoryPermissions(
    io: Io,
    parent: Dir,
    leaf: []const u8,
    permissions: File.Permissions,
) !void {
    if (builtin.os.tag == .windows) return;
    var created = try openComponent(io, parent, leaf);
    defer created.close(io);
    try created.setPermissions(io, permissions);
}

/// Opens exactly one path component as a directory without following it.
/// `iterate` is requested so that the result is a complete directory
/// descriptor usable for iteration, `fsync`, and permission changes rather
/// than a Linux `O_PATH` handle.
fn openComponent(io: Io, base: Dir, component: []const u8) !Dir {
    return base.openDir(io, component, .{
        .follow_symlinks = false,
        .iterate = true,
    }) catch |err| return classifyComponentError(io, base, component, err);
}

/// Distinguishes "this component is a symbolic link" from "this component is
/// not a directory". Linux reports both as `ENOTDIR` for `O_DIRECTORY |
/// O_NOFOLLOW`, so the kind is resolved with a no-follow stat. The result is
/// only a diagnostic; the failure itself already prevented traversal.
fn classifyComponentError(io: Io, base: Dir, component: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.NotDir, error.SymLinkLoop, error.IsDir => {},
        else => return err,
    }
    const stat = base.statFile(io, component, .{ .follow_symlinks = false }) catch
        return if (err == error.SymLinkLoop) error.SymbolicLinkComponent else error.NotDirectory;
    return switch (stat.kind) {
        .sym_link => error.SymbolicLinkComponent,
        .directory => err,
        else => error.NotDirectory,
    };
}

fn syncDir(io: Io, dir: Dir) !void {
    _ = io;
    switch (builtin.os.tag) {
        .linux => if (std.posix.errno(std.os.linux.fsync(dir.handle)) != .SUCCESS)
            return error.Unexpected,
        else => {},
    }
}

fn validateLinkTarget(target: []const u8) LinkError!void {
    if (target.len == 0) return error.EmptyLinkTarget;
    if (target.len > maximum_link_target_bytes) return error.LinkTargetTooLong;
    for (target) |byte| {
        if (byte < 0x20 or byte == 0x7f) return error.InvalidLinkTargetByte;
    }
}

/// The final component of a regular-file open is never followed, so a symbolic
/// link there means the caller did not name a regular file.
fn mapRegularFileError(err: anyerror) anyerror {
    return switch (err) {
        error.SymLinkLoop, error.IsDir => error.NotRegularFile,
        error.NotDir => error.NotDirectory,
        else => err,
    };
}

/// Final-component operations that never follow symbolic links only need the
/// prefix-kind failure normalized.
fn mapLeafError(err: anyerror) anyerror {
    return switch (err) {
        error.NotDir => error.NotDirectory,
        else => err,
    };
}

const testing = std.testing;

fn testRoot(tmp: *std.testing.TmpDir) Root {
    return .init(testing.io, tmp.dir);
}

fn testPath(text: []const u8) !Path {
    return Path.init(text);
}

test "root_fs.test.path grammar rejects absolute, traversing, and control paths" {
    const valid = try Path.init("var/lib/dpkg/status");
    try testing.expectEqualStrings("status", valid.basename());
    try testing.expectEqualStrings("var/lib/dpkg", valid.parent().?.text);
    try testing.expectEqual(@as(usize, 4), valid.depth());

    const single = try Path.init("status");
    try testing.expectEqualStrings("status", single.basename());
    try testing.expect(single.parent() == null);

    try testing.expectError(error.EmptyPath, Path.init(""));
    try testing.expectError(error.AbsolutePath, Path.init("/etc/passwd"));
    try testing.expectError(error.TraversingPath, Path.init(".."));
    try testing.expectError(error.TraversingPath, Path.init("var/../../etc"));
    try testing.expectError(error.TraversingPath, Path.init("./var"));
    try testing.expectError(error.TraversingPath, Path.init("var/./lib"));
    try testing.expectError(error.EmptyPathComponent, Path.init("var//lib"));
    try testing.expectError(error.EmptyPathComponent, Path.init("var/"));
    try testing.expectError(error.InvalidPathByte, Path.init("var/nul\x00byte"));
    try testing.expectError(error.InvalidPathByte, Path.init("var/line\nbreak"));
    try testing.expectError(error.InvalidPathByte, Path.init("var/delete\x7f"));
    try testing.expectError(error.InvalidPathByte, Path.init("var\\lib"));

    const long_component = "a" ** (maximum_component_bytes + 1);
    try testing.expectError(error.PathComponentTooLong, Path.init(long_component));
    const deep = "a/" ** maximum_path_components ++ "a";
    try testing.expectError(error.PathTooDeep, Path.init(deep));
    const long_path = ("ab/" ** ((maximum_path_bytes / 3) + 1)) ++ "a";
    try testing.expectError(error.PathTooLong, Path.init(long_path));
}

test "root_fs.test.absolute spellings convert only when canonical" {
    const converted = try Path.fromAbsolute("/var/lib/dpkg/status");
    try testing.expectEqualStrings("var/lib/dpkg/status", converted.text);
    try testing.expectError(error.AbsolutePath, Path.fromAbsolute("var/lib"));
    try testing.expectError(error.TraversingPath, Path.fromAbsolute("/"));
    try testing.expectError(error.TraversingPath, Path.fromAbsolute("/var/../etc"));
    try testing.expectError(error.TraversingPath, Path.fromAbsolute("/var/lib/"));
}

test "root_fs.test.regular files round trip through root-relative paths" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const path = try testPath("var/lib/dpkg/status");
    try root.createDirectoryPath(path.parent().?, default_directory_permissions);
    try root.publishFile(path, "Package: debz\n", .{});

    const bytes = try root.readFileAlloc(testing.allocator, path, 4096);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("Package: debz\n", bytes);

    const info = try root.metadata(path);
    try testing.expect(info.isRegularFile());
    try testing.expect(info.isSupportedKind());
    try testing.expectEqual(@as(u64, 14), info.size);
    if (builtin.os.tag != .windows)
        try testing.expectEqual(@as(std.posix.mode_t, 0o644), info.permissions.toMode() & 0o7777);
}

test "root_fs.test.reads are bounded by the caller limit" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const path = try testPath("payload");
    const contents = "0123456789";
    try root.publishFile(path, contents, .{});
    try testing.expectError(
        error.FileTooLarge,
        root.readFileAlloc(testing.allocator, path, 4),
    );

    const exact = try root.readFileAlloc(testing.allocator, path, contents.len);
    defer testing.allocator.free(exact);
    try testing.expectEqualStrings(contents, exact);

    const spare = try root.readFileAlloc(testing.allocator, path, contents.len + 1);
    defer testing.allocator.free(spare);
    try testing.expectEqualStrings(contents, spare);

    try testing.expectError(
        error.FileTooLarge,
        root.readFileAlloc(testing.allocator, path, contents.len - 1),
    );

    const empty = try testPath("empty");
    try root.publishFile(empty, "", .{});
    const nothing = try root.readFileAlloc(testing.allocator, empty, 0);
    defer testing.allocator.free(nothing);
    try testing.expectEqualStrings("", nothing);
}

test "root_fs.test.staged writers append at the descriptor offset" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const path = try testPath("var/lib/dpkg/status");
    try root.createDirectoryPath(path.parent().?, default_directory_permissions);
    {
        var staged = try root.stageFile(path, .{});
        defer staged.deinit();
        try staged.writeAll("Package: debz\n");
        {
            var buffer: [8]u8 = undefined;
            var sink = try staged.writer(&buffer);
            try sink.interface.writeAll("Status: install ok installed\n");
            try sink.interface.flush();
        }
        try staged.writeAll("Architecture: amd64\n");
        {
            var buffer: [4]u8 = undefined;
            var sink = try staged.writer(&buffer);
            try sink.interface.writeAll("Version: 0.3.0\n");
            try sink.interface.flush();
        }
        try staged.commit();
        try testing.expectError(error.StagedFileClosed, staged.writer(&.{}));
    }

    const bytes = try root.readFileAlloc(testing.allocator, path, 4096);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        "Package: debz\nStatus: install ok installed\nArchitecture: amd64\nVersion: 0.3.0\n",
        bytes,
    );
    try testing.expectEqual(@as(u64, bytes.len), (try root.metadata(path)).size);
}

test "root_fs.test.final symbolic links are never followed" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.publishFile(try testPath("secret"), "target contents", .{});
    const link = try testPath("link");
    try root.createSymbolicLink(link, "secret");

    try testing.expectError(error.NotRegularFile, root.openRegularFile(link));
    try testing.expectError(
        error.NotRegularFile,
        root.readFileAlloc(testing.allocator, link, 4096),
    );

    const info = try root.metadata(link);
    try testing.expect(info.isSymbolicLink());

    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings("secret", try root.readSymbolicLink(link, &buffer));
}

test "root_fs.test.intermediate symbolic links fail closed" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.createDirectory(try testPath("real"), default_directory_permissions);
    try root.publishFile(try testPath("real/file"), "inside", .{});
    try root.createSymbolicLink(try testPath("alias"), "real");

    try testing.expectError(
        error.SymbolicLinkComponent,
        root.openRegularFile(try testPath("alias/file")),
    );
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.openDirectory(try testPath("alias")),
    );
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.metadata(try testPath("alias/file")),
    );
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.createDirectoryPath(try testPath("alias/nested"), default_directory_permissions),
    );
}

test "root_fs.test.escaping symbolic links cannot leave the root" {
    var outside = testing.tmpDir(.{ .iterate = true });
    defer outside.cleanup();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.createSymbolicLink(try testPath("escape"), "../../..");
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.openDirectory(try testPath("escape")),
    );
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.openRegularFile(try testPath("escape/etc/passwd")),
    );
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.publishFile(try testPath("escape/planted"), "owned", .{}),
    );
}

test "root_fs.test.exclusive creation never writes through a planted symlink" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const victim = try testPath("victim");
    try root.publishFile(victim, "original", .{});
    const planted = try testPath("planted");
    try root.createSymbolicLink(planted, "victim");

    try testing.expectError(
        error.PathAlreadyExists,
        root.createRegularFile(planted, .{}),
    );

    const bytes = try root.readFileAlloc(testing.allocator, victim, 4096);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("original", bytes);

    var file = try root.createRegularFile(try testPath("fresh"), .{});
    defer file.close(testing.io);
    try file.writeStreamingAll(testing.io, "new");
    try testing.expectError(
        error.PathAlreadyExists,
        root.createRegularFile(try testPath("fresh"), .{}),
    );
}

test "root_fs.test.publication replaces a symlink instead of its target" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const victim = try testPath("victim");
    try root.publishFile(victim, "original", .{});
    const planted = try testPath("planted");
    try root.createSymbolicLink(planted, "victim");

    try root.publishFile(planted, "published", .{});

    const replaced = try root.metadata(planted);
    try testing.expect(replaced.isRegularFile());
    const victim_bytes = try root.readFileAlloc(testing.allocator, victim, 4096);
    defer testing.allocator.free(victim_bytes);
    try testing.expectEqualStrings("original", victim_bytes);
    const planted_bytes = try root.readFileAlloc(testing.allocator, planted, 4096);
    defer testing.allocator.free(planted_bytes);
    try testing.expectEqualStrings("published", planted_bytes);
}

test "root_fs.test.publication overwrite policy is explicit" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const path = try testPath("state");
    try root.publishFile(path, "first", .{ .overwrite = .fail_if_exists });
    try testing.expectError(
        error.PathAlreadyExists,
        root.publishFile(path, "second", .{ .overwrite = .fail_if_exists }),
    );
    try root.publishFile(path, "second", .{ .overwrite = .replace });

    const bytes = try root.readFileAlloc(testing.allocator, path, 4096);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("second", bytes);
    try expectNoStagingResidue(&tmp);
}

test "root_fs.test.staged files publish durably and abandon cleanly" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const path = try testPath("var/lib/dpkg/status");
    try root.createDirectoryPath(path.parent().?, default_directory_permissions);
    {
        var staged = try root.stageFile(path, .{ .durable = true });
        defer staged.deinit();
        try staged.writeAll("Package: debz\n");
        try staged.writeAll("Status: install ok installed\n");
        try testing.expect(try root.metadataIfExists(path) == null);
        try staged.commit();
        try testing.expectError(error.StagedFileClosed, staged.writeAll("late"));
    }
    const bytes = try root.readFileAlloc(testing.allocator, path, 4096);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("Package: debz\nStatus: install ok installed\n", bytes);

    {
        var staged = try root.stageFile(try testPath("var/lib/dpkg/abandoned"), .{});
        defer staged.deinit();
        try staged.writeAll("never published");
    }
    try testing.expect(try root.metadataIfExists(try testPath("var/lib/dpkg/abandoned")) == null);
    try expectNoStagingResidue(&tmp);
    try root.syncDirectory(path.parent().?);
    try root.syncRoot();
}

test "root_fs.test.directory creation rejects file and symlink transitions" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.publishFile(try testPath("occupied"), "regular", .{});
    try testing.expectError(
        error.PathAlreadyExists,
        root.createDirectory(try testPath("occupied"), default_directory_permissions),
    );
    try testing.expectError(
        error.NotDirectory,
        root.ensureDirectory(try testPath("occupied"), default_directory_permissions),
    );
    try testing.expectError(
        error.NotDirectory,
        root.createDirectoryPath(try testPath("occupied/child"), default_directory_permissions),
    );

    try root.createDirectory(try testPath("real"), default_directory_permissions);
    try root.createSymbolicLink(try testPath("alias"), "real");
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.ensureDirectory(try testPath("alias"), default_directory_permissions),
    );

    try root.ensureDirectory(try testPath("real"), default_directory_permissions);
    const info = try root.metadata(try testPath("real"));
    try testing.expect(info.isDirectory());
    if (builtin.os.tag != .windows)
        try testing.expectEqual(@as(std.posix.mode_t, 0o755), info.permissions.toMode() & 0o7777);
}

test "root_fs.test.publishing over a directory fails without mutating it" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const directory = try testPath("info");
    try root.createDirectory(directory, default_directory_permissions);
    try root.publishFile(try testPath("info/debz.list"), "/usr/bin/debz\n", .{});

    try testing.expect(std.meta.isError(root.publishFile(directory, "clobber", .{})));
    const info = try root.metadata(directory);
    try testing.expect(info.isDirectory());
    const bytes = try root.readFileAlloc(
        testing.allocator,
        try testPath("info/debz.list"),
        4096,
    );
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("/usr/bin/debz\n", bytes);
    try expectNoStagingResidue(&tmp);
}

test "root_fs.test.removal and rename operate on links, not their targets" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const target = try testPath("target");
    try root.publishFile(target, "kept", .{});
    const link = try testPath("link");
    try root.createSymbolicLink(link, "target");
    try root.removeFile(link);
    try testing.expect(try root.metadataIfExists(link) == null);
    try testing.expect((try root.metadata(target)).isRegularFile());

    try root.createDirectory(try testPath("directory"), default_directory_permissions);
    try testing.expect(std.meta.isError(root.removeFile(try testPath("directory"))));
    try root.publishFile(try testPath("directory/child"), "child", .{});
    try testing.expectError(
        error.DirNotEmpty,
        root.removeDirectory(try testPath("directory")),
    );
    try root.removeFile(try testPath("directory/child"));
    try root.removeDirectory(try testPath("directory"));

    try root.rename(target, try testPath("renamed"), .fail_if_exists);
    try testing.expect(try root.metadataIfExists(target) == null);
    try root.publishFile(try testPath("other"), "other", .{});
    try testing.expectError(
        error.PathAlreadyExists,
        root.rename(try testPath("other"), try testPath("renamed"), .fail_if_exists),
    );
    try root.rename(try testPath("other"), try testPath("renamed"), .replace);
    const bytes = try root.readFileAlloc(testing.allocator, try testPath("renamed"), 4096);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("other", bytes);
}

test "root_fs.test.symbolic link publication is bounded and atomic" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const link = try testPath("alternative");
    try root.publishSymbolicLink(link, "usr/bin/debz", .{});
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings("usr/bin/debz", try root.readSymbolicLink(link, &buffer));
    try root.publishSymbolicLink(link, "usr/bin/other", .{});
    try testing.expectEqualStrings("usr/bin/other", try root.readSymbolicLink(link, &buffer));
    try testing.expectError(
        error.PathAlreadyExists,
        root.publishSymbolicLink(link, "usr/bin/third", .{ .overwrite = .fail_if_exists }),
    );
    try testing.expectError(
        error.PathAlreadyExists,
        root.createSymbolicLink(link, "usr/bin/third"),
    );

    try testing.expectError(
        error.EmptyLinkTarget,
        root.createSymbolicLink(try testPath("empty"), ""),
    );
    try testing.expectError(
        error.InvalidLinkTargetByte,
        root.createSymbolicLink(try testPath("control"), "usr/\x00bin"),
    );
    const long_target = "a" ** (maximum_link_target_bytes + 1);
    try testing.expectError(
        error.LinkTargetTooLong,
        root.createSymbolicLink(try testPath("long"), long_target),
    );
    try expectNoStagingResidue(&tmp);
}

test "root_fs.test.roots open without following absolute path components" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try testing.expectError(
        error.InvalidAbsolutePath,
        openAbsoluteRoot(testing.io, "relative/path"),
    );
    try testing.expectError(
        error.InvalidAbsolutePath,
        openAbsoluteRoot(testing.io, "/srv/../etc"),
    );
    try testing.expectError(
        error.InvalidAbsolutePath,
        openAbsoluteRoot(testing.io, "/srv/roots/"),
    );

    var opened = try openAbsoluteRoot(testing.io, "/");
    defer opened.close();
    try testing.expect((try opened.root.metadataOfRoot()).isDirectory());
}

test "root_fs.test.unsupported path kinds are reported without following them" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.createSymbolicLink(try testPath("dangling"), "missing/target");
    const info = try root.metadata(try testPath("dangling"));
    try testing.expect(info.isSymbolicLink());
    try testing.expect(info.isSupportedKind());
    try testing.expectError(
        error.NotRegularFile,
        root.openRegularFile(try testPath("dangling")),
    );
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.openDirectory(try testPath("dangling")),
    );
    try testing.expect(try root.metadataIfExists(try testPath("missing")) == null);
    try testing.expect(try root.metadataIfExists(try testPath("missing/child")) == null);
}

test "root_fs.test.unsupported path kinds fail closed before mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    const fifo = try testPath("fifo");
    if (std.posix.errno(std.os.linux.mknodat(
        tmp.dir.handle,
        "fifo",
        std.posix.S.IFIFO | 0o600,
        0,
    )) != .SUCCESS) return error.SkipZigTest;

    const info = try root.metadata(fifo);
    try testing.expect(!info.isSupportedKind());
    try testing.expectError(error.UnsupportedPathKind, root.supportedMetadata(fifo));
    try testing.expectError(error.NotRegularFile, root.openRegularFile(fifo));
    try testing.expectError(error.NotDirectory, root.openDirectory(fifo));

    try root.publishFile(try testPath("regular"), "bytes", .{});
    try testing.expect((try root.supportedMetadata(try testPath("regular"))).isRegularFile());
    try root.createDirectory(try testPath("directory"), default_directory_permissions);
    try testing.expect((try root.supportedMetadata(try testPath("directory"))).isDirectory());
    try root.createSymbolicLink(try testPath("link"), "regular");
    try testing.expect((try root.supportedMetadata(try testPath("link"))).isSymbolicLink());
}

fn expectNoStagingResidue(tmp: *std.testing.TmpDir) !void {
    var walker = try tmp.dir.walk(testing.allocator);
    defer walker.deinit();
    while (try walker.next(testing.io)) |entry| {
        if (std.mem.startsWith(u8, entry.basename, staging_prefix))
            return error.StagingResidue;
    }
}

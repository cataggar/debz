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

pub const MetadataError = error{
    /// The platform cannot express the requested ownership or timestamp
    /// change without following the final component.
    NoFollowMetadataUnsupported,
    /// The entry carries a `security.capability` attribute that a change of
    /// ownership would silently destroy, or the attribute could not be read,
    /// so the ownership change is refused instead of made.
    CapabilityAttributePresent,
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

/// The complete no-follow observation of one path the native mutation layer
/// needs to state an exact precondition. `std.Io.File.Stat` deliberately omits
/// ownership and the containing device, so on Linux this is read with a single
/// `statx`; elsewhere it is derived from the portable stat with the
/// unavailable fields reported as zero and `modeled` false.
pub const Entry = struct {
    kind: File.Kind,
    size: u64,
    /// Permission and special mode bits only; the file-type bits are masked
    /// off so a mode never restates the kind.
    mode: u32,
    uid: u32,
    gid: u32,
    /// Identifier of the filesystem holding the entry. Two paths with
    /// different devices can never be linked or atomically renamed onto each
    /// other.
    device: u64,
    inode: u64,
    link_count: u64,
    modified_nanoseconds: i128,
    /// False when the platform could not report ownership and device, so a
    /// caller never mistakes a zero for an observation.
    modeled: bool,

    pub fn isRegularFile(self: Entry) bool {
        return self.kind == .file;
    }

    pub fn isDirectory(self: Entry) bool {
        return self.kind == .directory;
    }

    pub fn isSymbolicLink(self: Entry) bool {
        return self.kind == .sym_link;
    }

    pub fn isSupportedKind(self: Entry) bool {
        return switch (self.kind) {
            .file, .directory, .sym_link => true,
            else => false,
        };
    }
};

pub const CreateFileOptions = struct {
    permissions: File.Permissions = default_file_permissions,
    read: bool = false,
};

/// Exact metadata to publish on an already resolved path without following
/// its final component. A `null` component is left untouched.
pub const MetadataUpdate = struct {
    mode: ?u32 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    modified_nanoseconds: ?i128 = null,
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

    /// Complete no-follow observation of the final component, including
    /// ownership and the containing device.
    pub fn entry(self: Root, path: Path) !Entry {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        return entryAt(self.io, parent.dir, parent.leaf) catch |err| return mapLeafError(err);
    }

    /// `null` when the path, or any parent component, does not exist.
    pub fn entryIfExists(self: Root, path: Path) !?Entry {
        return self.entry(path) catch |err| switch (err) {
            error.FileNotFound => null,
            else => err,
        };
    }

    /// Observation of the root descriptor itself. Its device is the reference
    /// a caller compares staging and backup areas against.
    pub fn rootEntry(self: Root) !Entry {
        return entryAt(self.io, self.dir, "");
    }

    /// Device identifier of an existing directory, resolved without following
    /// any component. Callers use it to refuse cross-device staging before a
    /// rename can fail halfway through a transaction.
    pub fn deviceOfDirectory(self: Root, path: Path) !u64 {
        var dir = try self.openDirectory(path);
        defer dir.close(self.io);
        const observed = try entryAt(self.io, dir, "");
        return observed.device;
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

    /// Creates a hard link at `path` naming the same inode as `existing`.
    /// Neither final component is followed, so a symbolic link is linked as
    /// itself and never as its target, and the name must be unused.
    pub fn createHardLink(self: Root, existing: Path, path: Path) !void {
        var source = try self.openParent(existing);
        defer source.close(self.io);
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        Dir.hardLink(
            source.dir,
            source.leaf,
            parent.dir,
            parent.leaf,
            self.io,
            .{ .follow_symlinks = false },
        ) catch |err| return mapLeafError(err);
    }

    /// Exclusively creates `path`, writes `bytes`, and optionally fsyncs the
    /// contents before closing. Exclusive creation never follows an existing
    /// entry, so a planted symbolic link fails with `error.PathAlreadyExists`
    /// instead of being written through.
    pub fn writeNewFile(
        self: Root,
        path: Path,
        bytes: []const u8,
        options: CreateFileOptions,
        durable: bool,
    ) !void {
        var file = try self.createRegularFile(path, options);
        defer file.close(self.io);
        try file.writeStreamingAll(self.io, bytes);
        if (durable) try file.sync(self.io);
    }

    /// Fsyncs an existing regular file so that content and metadata already
    /// applied to it survive power loss.
    pub fn syncRegularFile(self: Root, path: Path) !void {
        var file = try self.openRegularFile(path);
        defer file.close(self.io);
        try file.sync(self.io);
    }

    /// Byte length of an existing regular file plus a bounded window of its
    /// bytes, read without following the final component. A write-ahead log
    /// uses it to compare its own view against the durable tail before it
    /// appends.
    ///
    /// `size` is always the physical length, which is what proves whether
    /// anything follows the window, and `bytes` is short only when the file
    /// ends inside the window.
    pub const Window = struct {
        size: u64,
        bytes: []const u8,
    };

    /// Reads `buffer.len` bytes starting at exactly `offset`. The offset is
    /// supplied by the caller rather than derived from the physical end, so a
    /// torn trailing write can never shift the window and make a complete
    /// record decode as garbage.
    pub fn readWindowAt(self: Root, path: Path, offset: u64, buffer: []u8) !Window {
        var file = try self.openRegularFile(path);
        defer file.close(self.io);
        const size = (try file.stat(self.io)).size;
        if (offset >= size) return .{ .size = size, .bytes = buffer[0..0] };
        const length: usize = @intCast(@min(size - offset, buffer.len));
        const read = try file.readPositionalAll(self.io, buffer[0..length], offset);
        return .{ .size = size, .bytes = buffer[0..read] };
    }

    /// Byte length of an existing regular file plus its last `buffer.len`
    /// bytes.
    pub fn readTail(self: Root, path: Path, buffer: []u8) !Window {
        var file = try self.openRegularFile(path);
        defer file.close(self.io);
        const size = (try file.stat(self.io)).size;
        const length: usize = @intCast(@min(size, buffer.len));
        const offset = size - length;
        const read = try file.readPositionalAll(self.io, buffer[0..length], offset);
        return .{ .size = size, .bytes = buffer[0..read] };
    }

    /// Discards everything after `length` in an existing regular file and
    /// fsyncs the result. A write-ahead log uses it to repair a trailing
    /// write that was proven never to have completed, so the repair itself is
    /// durable before anything is appended after it.
    pub fn truncateFile(self: Root, path: Path, length: u64, durable: bool) !void {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        var file = parent.dir.openFile(self.io, parent.leaf, .{
            .mode = .write_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        }) catch |err| return mapRegularFileError(err);
        defer file.close(self.io);
        try file.setLength(self.io, length);
        if (durable) try file.sync(self.io);
    }

    /// True when the final component carries a `security.capability`
    /// attribute. Linux drops that attribute together with the set-user-ID
    /// and set-group-ID bits whenever a non-directory is chowned, so a caller
    /// that is about to change ownership in place has to know first.
    ///
    /// An attribute that cannot be read is reported as present, because the
    /// only safe answer to "would this chown destroy a privilege the plan
    /// does not model" is yes.
    pub fn hasCapabilityAttribute(self: Root, path: Path) !bool {
        if (builtin.os.tag != .linux) return false;
        var file = try self.openRegularFile(path);
        defer file.close(self.io);
        const linux = std.os.linux;
        var value: [1]u8 = undefined;
        const result = linux.fgetxattr(file.handle, "security.capability", &value, 0);
        return switch (linux.errno(result)) {
            .SUCCESS => true,
            // No attribute, or a filesystem that cannot store one at all.
            .NODATA, .OPNOTSUPP => false,
            // The buffer is deliberately zero-length, so a stored attribute
            // reports its size rather than being copied out.
            .RANGE => true,
            else => true,
        };
    }

    /// Appends `bytes` at exactly `offset` in an existing regular file and
    /// fsyncs it. The offset is supplied by the caller rather than taken from
    /// the descriptor, so a write-ahead log always lands after the last record
    /// the caller proved durable and never after a torn trailing one.
    pub fn appendAt(
        self: Root,
        path: Path,
        offset: u64,
        bytes: []const u8,
        durable: bool,
    ) !void {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        var file = parent.dir.openFile(self.io, parent.leaf, .{
            .mode = .write_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        }) catch |err| return mapRegularFileError(err);
        defer file.close(self.io);
        try file.writePositionalAll(self.io, bytes, offset);
        if (durable) try file.sync(self.io);
    }

    /// Applies exact metadata to the final component without following it.
    /// Every component is already resolved no-follow, so this can never chmod
    /// or chown a path outside the root through a planted link. Ownership is
    /// written before the mode and the modification time last, so a `chown`
    /// can never silently drop a set-user-ID or set-group-ID bit the caller
    /// asked for.
    pub fn applyMetadata(self: Root, path: Path, update: MetadataUpdate) !void {
        var parent = try self.openParent(path);
        defer parent.close(self.io);
        try applyMetadataAt(self.io, parent.dir, parent.leaf, update);
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

/// `std.posix.errno` is libc's `errno` when libc is linked, which reads the
/// thread-local variable and expects a `-1` return. A raw Linux syscall
/// returns the negated error code instead, so every direct syscall in this
/// file is classified with the linux-specific decoder. Using the wrong one
/// would silently report every failure as success, which for `fsync` would
/// mean claiming durability that was never achieved.
fn syncDir(io: Io, dir: Dir) !void {
    _ = io;
    switch (builtin.os.tag) {
        .linux => switch (std.os.linux.errno(std.os.linux.fsync(dir.handle))) {
            .SUCCESS => {},
            // The filesystem cannot flush a directory. Reporting it is the
            // only honest option: silently succeeding would claim a durability
            // guarantee the publication never got.
            .INVAL, .ROFS => return error.OperationUnsupported,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .DQUOT => return error.DiskQuota,
            else => return error.Unexpected,
        },
        else => {},
    }
}

/// One no-follow observation of `leaf` inside `base`. An empty `leaf` observes
/// `base` itself. On Linux a single `statx` reports ownership and the
/// containing device, which `std.Io.File.Stat` does not carry.
fn entryAt(io: Io, base: Dir, leaf: []const u8) !Entry {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var path_buffer: [maximum_path_bytes + 1]u8 = undefined;
        if (leaf.len > maximum_path_bytes) return error.PathTooLong;
        @memcpy(path_buffer[0..leaf.len], leaf);
        path_buffer[leaf.len] = 0;
        const request: linux.STATX = .{
            .TYPE = true,
            .MODE = true,
            .NLINK = true,
            .UID = true,
            .GID = true,
            .INO = true,
            .SIZE = true,
            .MTIME = true,
        };
        const flags: u32 = linux.AT.NO_AUTOMOUNT | linux.AT.SYMLINK_NOFOLLOW |
            @as(u32, if (leaf.len == 0) linux.AT.EMPTY_PATH else 0);
        var raw = std.mem.zeroes(linux.Statx);
        const path: [*:0]const u8 = @ptrCast(&path_buffer);
        switch (linux.errno(linux.statx(base.handle, path, flags, request, &raw))) {
            .SUCCESS => {},
            .ACCES => return error.AccessDenied,
            .LOOP => return error.SymLinkLoop,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDir,
            .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
        const filled: u32 = @bitCast(raw.mask);
        const wanted: u32 = @bitCast(request);
        if (filled & wanted != wanted) return error.Unexpected;
        return .{
            .kind = statxKind(raw.mode),
            .size = raw.size,
            .mode = @as(u32, raw.mode) & 0o7777,
            .uid = raw.uid,
            .gid = raw.gid,
            .device = (@as(u64, raw.dev_major) << 32) | raw.dev_minor,
            .inode = raw.ino,
            .link_count = raw.nlink,
            .modified_nanoseconds = @as(i128, raw.mtime.sec) * std.time.ns_per_s + raw.mtime.nsec,
            .modeled = true,
        };
    }
    const stat = if (leaf.len == 0)
        try base.stat(io)
    else
        try base.statFile(io, leaf, .{ .follow_symlinks = false });
    return .{
        .kind = stat.kind,
        .size = stat.size,
        .mode = if (builtin.os.tag == .windows) 0 else @intCast(stat.permissions.toMode() & 0o7777),
        .uid = 0,
        .gid = 0,
        .device = 0,
        .inode = stat.inode,
        .link_count = stat.nlink,
        .modified_nanoseconds = stat.mtime.nanoseconds,
        .modeled = false,
    };
}

fn statxKind(mode: u16) File.Kind {
    const S = std.os.linux.S;
    return switch (mode & S.IFMT) {
        S.IFDIR => .directory,
        S.IFCHR => .character_device,
        S.IFBLK => .block_device,
        S.IFREG => .file,
        S.IFIFO => .named_pipe,
        S.IFLNK => .sym_link,
        S.IFSOCK => .unix_domain_socket,
        else => .unknown,
    };
}

/// Applies exact metadata to one already resolved final component in the only
/// order that cannot lose a bit the caller asked for.
///
/// Linux clears the set-user-ID bit of a non-directory on every `chown`, and
/// the set-group-ID bit of a group-executable non-directory, and it drops the
/// `security.capability` attribute with them. It does so regardless of the
/// caller's privilege. A `chmod` issued before the `chown` would therefore be
/// silently undone, so ownership is always written first, the mode second, and
/// the modification time last.
///
/// The modification time is written last because it is the only component a
/// later repair of the mode or ownership must not disturb: `chmod` and `chown`
/// update `ctime` alone, so once `utimensat` has run the entry is exactly what
/// the caller asked for and any retry of the earlier components leaves it that
/// way.
fn applyMetadataAt(io: Io, base: Dir, leaf: []const u8, update: MetadataUpdate) !void {
    if (update.uid != null or update.gid != null) {
        // `std.Io.Dir.setFileOwner` declares an error set narrower than the
        // one its own dispatch can return, so the no-follow change is issued
        // directly. Every component is already resolved without following a
        // link, so this can never reach outside the root.
        if (builtin.os.tag != .linux) return error.NoFollowMetadataUnsupported;
        const linux = std.os.linux;
        var path_buffer: [maximum_path_bytes + 1]u8 = undefined;
        if (leaf.len > maximum_path_bytes) return error.PathTooLong;
        @memcpy(path_buffer[0..leaf.len], leaf);
        path_buffer[leaf.len] = 0;
        const path: [*:0]const u8 = @ptrCast(&path_buffer);
        const uid: std.posix.uid_t = if (update.uid) |value| value else std.math.maxInt(u32);
        const gid: std.posix.gid_t = if (update.gid) |value| value else std.math.maxInt(u32);
        switch (linux.errno(linux.fchownat(
            base.handle,
            path,
            uid,
            gid,
            linux.AT.SYMLINK_NOFOLLOW,
        ))) {
            .SUCCESS => {},
            .ACCES => return error.AccessDenied,
            .PERM => return error.PermissionDenied,
            .LOOP => return error.SymLinkLoop,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDirectory,
            .ROFS => return error.ReadOnlyFileSystem,
            .IO => return error.InputOutput,
            else => return error.Unexpected,
        }
    }
    if (update.mode) |mode| {
        base.setFilePermissions(io, leaf, .fromMode(@intCast(mode)), .{
            .follow_symlinks = false,
        }) catch |err| switch (err) {
            // A symbolic link has no independent mode anywhere the native
            // engine runs, so the caller must not have planned one.
            error.OperationUnsupported => return error.NoFollowMetadataUnsupported,
            else => return mapLeafError(err),
        };
    }
    if (update.modified_nanoseconds) |nanoseconds| {
        // `Io.Timestamp` is 96-bit; a wider value can never be stored, so it
        // is refused rather than truncated into a different timestamp.
        const value = std.math.cast(i96, nanoseconds) orelse
            return error.NoFollowMetadataUnsupported;
        base.setTimestamps(io, leaf, .{
            .follow_symlinks = false,
            .modify_timestamp = .{ .new = .{ .nanoseconds = value } },
        }) catch |err| return mapLeafError(err);
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
    if (std.os.linux.errno(std.os.linux.mknodat(
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

test "root_fs.test.entries report kind, mode, ownership, device, and link identity" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.createDirectoryPath(try testPath("usr/bin"), default_directory_permissions);
    try root.publishFile(try testPath("usr/bin/tool"), "payload", .{});
    try root.createSymbolicLink(try testPath("usr/bin/alias"), "tool");

    const file = try root.entry(try testPath("usr/bin/tool"));
    try testing.expect(file.isRegularFile());
    try testing.expectEqual(@as(u64, 7), file.size);
    try testing.expectEqual(@as(u64, 1), file.link_count);

    const directory = try root.entry(try testPath("usr/bin"));
    try testing.expect(directory.isDirectory());

    const link = try root.entry(try testPath("usr/bin/alias"));
    try testing.expect(link.isSymbolicLink());
    try testing.expect(link.inode != file.inode);

    if (builtin.os.tag == .linux) {
        try testing.expect(file.modeled);
        try testing.expectEqual(@as(u32, 0o644), file.mode);
        try testing.expectEqual(@as(u32, 0o755), directory.mode);
        try testing.expectEqual(std.os.linux.getuid(), file.uid);
        // Everything inside one root shares one filesystem here, which is the
        // precondition the mutation layer's staging area relies on.
        const rooted = try root.rootEntry();
        try testing.expectEqual(rooted.device, file.device);
        try testing.expectEqual(
            rooted.device,
            try root.deviceOfDirectory(try testPath("usr/bin")),
        );
    }

    try testing.expect(try root.entryIfExists(try testPath("usr/bin/missing")) == null);
    try testing.expect(try root.entryIfExists(try testPath("missing/child")) == null);
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.entry(try testPath("usr/bin/alias/child")),
    );
}

test "root_fs.test.hard links never follow the final component" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.publishFile(try testPath("target"), "payload", .{});
    try root.createSymbolicLink(try testPath("link"), "target");
    try root.createHardLink(try testPath("target"), try testPath("clone"));

    const original = try root.entry(try testPath("target"));
    const clone = try root.entry(try testPath("clone"));
    try testing.expectEqual(original.inode, clone.inode);
    try testing.expectEqual(@as(u64, 2), clone.link_count);

    // An existing name is never taken over silently.
    try testing.expectError(
        error.PathAlreadyExists,
        root.createHardLink(try testPath("target"), try testPath("clone")),
    );
    try testing.expectError(
        error.PathAlreadyExists,
        root.createHardLink(try testPath("target"), try testPath("link")),
    );
    // A planted symbolic link in the prefix cannot steer the link out.
    try testing.expectError(
        error.SymbolicLinkComponent,
        root.createHardLink(try testPath("target"), try testPath("link/escape")),
    );
}

test "root_fs.test.metadata updates never follow a planted link" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.publishFile(try testPath("secret"), "sensitive", .{});
    try root.createSymbolicLink(try testPath("planted"), "secret");
    try root.publishFile(try testPath("regular"), "payload", .{});

    try root.applyMetadata(try testPath("regular"), .{
        .mode = 0o600,
        .modified_nanoseconds = 1_234_000_000_000,
    });
    const updated = try root.entry(try testPath("regular"));
    try testing.expectEqual(@as(u32, 0o600), updated.mode);
    try testing.expectEqual(@as(i128, 1_234_000_000_000), updated.modified_nanoseconds);

    // Changing the timestamp of the link changes the link, never its target.
    try root.applyMetadata(try testPath("planted"), .{
        .modified_nanoseconds = 5_000_000_000,
    });
    const secret = try root.entry(try testPath("secret"));
    try testing.expectEqual(@as(u32, 0o644), secret.mode);
    try testing.expect(secret.modified_nanoseconds != 5_000_000_000);
    const planted = try root.entry(try testPath("planted"));
    try testing.expectEqual(@as(i128, 5_000_000_000), planted.modified_nanoseconds);

    // A symbolic link has no independent mode, so a mode change is refused
    // rather than silently applied to the target.
    try testing.expectError(
        error.NoFollowMetadataUnsupported,
        root.applyMetadata(try testPath("planted"), .{ .mode = 0o600 }),
    );
    try testing.expectEqual(@as(u32, 0o644), (try root.entry(try testPath("secret"))).mode);
}

test "root_fs.test.exclusive writes and positional appends stay bounded" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.writeNewFile(try testPath("log"), "first\n", .{}, true);
    try testing.expectError(
        error.PathAlreadyExists,
        root.writeNewFile(try testPath("log"), "again\n", .{}, true),
    );

    try root.appendAt(try testPath("log"), 6, "second\n", true);
    const bytes = try root.readFileAlloc(testing.allocator, try testPath("log"), 4096);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("first\nsecond\n", bytes);

    // A torn trailing record is overwritten by the next append at the offset
    // the caller proved durable.
    try root.appendAt(try testPath("log"), 6, "third\n\n", true);
    const rewritten = try root.readFileAlloc(testing.allocator, try testPath("log"), 4096);
    defer testing.allocator.free(rewritten);
    try testing.expectEqualStrings("first\nthird\n\n", rewritten);

    try root.createSymbolicLink(try testPath("planted"), "log");
    try testing.expectError(
        error.NotRegularFile,
        root.appendAt(try testPath("planted"), 0, "x", true),
    );
    try testing.expectError(
        error.PathAlreadyExists,
        root.writeNewFile(try testPath("planted"), "x", .{}, true),
    );
    try root.syncRegularFile(try testPath("log"));
    try expectNoStagingResidue(&tmp);
}

test "root_fs.test.device identity distinguishes filesystems" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);
    const local = try root.rootEntry();

    // Any real second filesystem proves the identity is a mount property and
    // not a constant. The mutation layer refuses to stage across one, because
    // a rename between filesystems is not atomic.
    var other = openAbsoluteRoot(testing.io, "/dev/shm") catch return error.SkipZigTest;
    defer other.close();
    const remote = try other.root.rootEntry();
    if (remote.device == local.device) return error.SkipZigTest;
    try testing.expect(local.modeled and remote.modeled);
    try testing.expect(local.device != remote.device);
}

test "root_fs.test.ownership is written before a mode that carries privileged bits" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.publishFile(try testPath("tool"), "payload", .{});
    const uid = std.os.linux.getuid();
    const gid = std.os.linux.getgid();

    // Linux clears the set-user-ID bit of a non-directory on every `chown`,
    // and the set-group-ID bit of a group-executable one, whatever the
    // caller's privilege and even when the ownership does not actually
    // change. A mode written before the ownership would therefore be silently
    // downgraded, so the order is part of the contract and is asserted here
    // without needing a second uid or gid.
    for ([_]u32{ 0o4755, 0o2755, 0o6755, 0o1755 }) |mode| {
        try root.applyMetadata(try testPath("tool"), .{
            .mode = mode,
            .uid = uid,
            .gid = gid,
            .modified_nanoseconds = 7_000_000_000,
        });
        const updated = try root.entry(try testPath("tool"));
        try testing.expectEqual(mode, updated.mode);
        try testing.expectEqual(uid, updated.uid);
        try testing.expectEqual(gid, updated.gid);
        try testing.expectEqual(@as(i128, 7_000_000_000), updated.modified_nanoseconds);
    }

    // A directory keeps its set-group-ID bit across a chown, and the same
    // order still publishes exactly what was asked for.
    try root.createDirectory(try testPath("group"), default_directory_permissions);
    try root.applyMetadata(try testPath("group"), .{ .mode = 0o2775, .uid = uid, .gid = gid });
    try testing.expectEqual(@as(u32, 0o2775), (try root.entry(try testPath("group"))).mode);
}

test "root_fs.test.capability attributes are reported before an ownership change" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.publishFile(try testPath("plain"), "payload", .{});
    try testing.expect(!try root.hasCapabilityAttribute(try testPath("plain")));

    // An entry that cannot be opened as a regular file cannot be proven free
    // of a capability attribute, and the caller treats that as present.
    try root.createDirectory(try testPath("dir"), default_directory_permissions);
    try testing.expectError(
        error.NotRegularFile,
        root.hasCapabilityAttribute(try testPath("dir")),
    );
    try testing.expectError(
        error.FileNotFound,
        root.hasCapabilityAttribute(try testPath("missing")),
    );
}

test "root_fs.test.windows read at a proven offset and truncation repairs a tail" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = testRoot(&tmp);

    try root.writeNewFile(try testPath("log"), "aaaa" ++ "bbbb" ++ "cc", .{}, true);
    var buffer: [4]u8 = undefined;

    // The window is taken at exactly the offset the caller proved durable,
    // so a torn trailing write never shifts it.
    const first = try root.readWindowAt(try testPath("log"), 0, &buffer);
    try testing.expectEqual(@as(u64, 10), first.size);
    try testing.expectEqualStrings("aaaa", first.bytes);
    const second = try root.readWindowAt(try testPath("log"), 4, &buffer);
    try testing.expectEqual(@as(u64, 10), second.size);
    try testing.expectEqualStrings("bbbb", second.bytes);
    // A window that runs past the end reports the physical size and the short
    // read, which is how a partial tail is recognized.
    const torn = try root.readWindowAt(try testPath("log"), 8, &buffer);
    try testing.expectEqual(@as(u64, 10), torn.size);
    try testing.expectEqualStrings("cc", torn.bytes);
    const past = try root.readWindowAt(try testPath("log"), 10, &buffer);
    try testing.expectEqual(@as(u64, 10), past.size);
    try testing.expectEqual(@as(usize, 0), past.bytes.len);

    // The tail helper still reads from the physical end.
    const tail = try root.readTail(try testPath("log"), &buffer);
    try testing.expectEqual(@as(u64, 10), tail.size);
    try testing.expectEqualStrings("bbcc", tail.bytes);

    try root.truncateFile(try testPath("log"), 8, true);
    const repaired = try root.readWindowAt(try testPath("log"), 4, &buffer);
    try testing.expectEqual(@as(u64, 8), repaired.size);
    try testing.expectEqualStrings("bbbb", repaired.bytes);

    // Truncation never follows a planted link and never reaches a directory.
    try root.createSymbolicLink(try testPath("planted"), "log");
    try testing.expectError(
        error.NotRegularFile,
        root.truncateFile(try testPath("planted"), 0, true),
    );
}

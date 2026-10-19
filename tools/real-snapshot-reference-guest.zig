//! Guest runtime bindings for protected pinned-dpkg reference operations.
//!
//! The launcher executes the pinned dpkg from an immutable runtime mount, but
//! dpkg then executes guest helpers (dpkg-split, dpkg-deb, tar, rm), maintainer
//! script interpreters, the guest loader and libraries, and late NSS/gconv
//! providers from the reference root itself. Those guest paths cannot be
//! bind-mounted read-only because dpkg legitimately renames and unlinks the
//! very files it owns while unpacking (a mounted inode would turn that into
//! EBUSY). Instead every such path is bound to identities derived from the
//! original signed lock archives and verified, together with required
//! absences, search scopes and the loader cache, immediately before dpkg runs.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const schema_id = "io.github.cataggar.debz.reference-guest.v1";
pub const manifest_name = "guest.json";
pub const cache_path = "/etc/ld.so.cache";
pub const maximum_manifest_bytes = 2 * 1024 * 1024;
pub const maximum_entries = 2048;
pub const maximum_file_bytes = 64 * 1024 * 1024;
pub const maximum_cache_bytes = 8 * 1024 * 1024;

pub const Kind = enum { regular, symlink, directory };

pub const Role = enum {
    alias,
    helper,
    interpreter,
    handler_tool,
    library,
    loader,
    loader_config,
    nss_config,
    nss_provider,
    gconv,
    dpkg_config,
    shadow,
    hwcaps,
};

pub const Identity = struct {
    kind: Kind,
    mode: u32 = 0,
    size: u64 = 0,
    sha256: []const u8 = "",
    target: []const u8 = "",
    /// Null only for the hash-pinned Debian dpkg helpers staged beside the
    /// pinned dpkg; every other identity names its signed lock archive member.
    package: ?[]const u8 = null,
    version: ?[]const u8 = null,
    archive_sha512: ?[]const u8 = null,
    member: ?[]const u8 = null,
};

pub const Entry = struct {
    path: []const u8,
    role: Role,
    required: bool = false,
    /// Empty means the path must be absent.
    allowed: []const Identity = &.{},
};

pub const Scope = struct {
    directory: []const u8,
    /// Every child whose name starts with `prefix` and ends with `suffix`
    /// must be a listed entry.
    prefix: []const u8,
    suffix: []const u8 = "",
};

pub const Manifest = struct {
    schema: []const u8 = schema_id,
    version: u32 = 1,
    architecture: []const u8,
    lock_sha256: []const u8,
    library_directory: []const u8,
    cache: []const u8 = cache_path,
    sonames: []const []const u8,
    cache_prefixes: []const []const u8,
    scopes: []const Scope,
    entries: []const Entry,
};

const OpenHow = extern struct { flags: u64, mode: u64 = 0, resolve: u64 };
// RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH
const resolve_beneath: u64 = 0x02 | 0x04 | 0x08;
const resolve_absolute: u64 = 0x02 | 0x04;

/// Hermetic negative tests exercise every refusal, so only production logs it.
fn refuse(comptime format: []const u8, arguments: anytype) void {
    if (!builtin.is_test) std.log.err(format, arguments);
}

pub fn triplet(architecture: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, architecture, "amd64")) return "x86_64-linux-gnu";
    if (std.mem.eql(u8, architecture, "arm64")) return "aarch64-linux-gnu";
    return null;
}

fn component(part: []const u8) bool {
    if (part.len == 0 or part.len > 255 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
        return false;
    for (part) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '_' and byte != '-' and byte != '+')
            return false;
    }
    return true;
}

pub fn canonicalPath(path: []const u8) bool {
    if (path.len < 2 or path.len > 4096 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| if (!component(part)) return false;
    return true;
}

fn hexadecimal(text: []const u8, size: usize) bool {
    if (text.len != size) return false;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

/// Resolves a symlink literal relative to its canonical parent without
/// touching the filesystem.
pub fn resolveTarget(buffer: []u8, path: []const u8, target: []const u8) ![]const u8 {
    if (target.len == 0 or target.len > 4096 or std.mem.indexOfScalar(u8, target, 0) != null)
        return error.InvalidGuestAlias;
    var stack: [64][]const u8 = undefined;
    var depth: usize = 0;
    if (target[0] != '/') {
        var parents = std.mem.tokenizeScalar(u8, std.fs.path.dirname(path) orelse return error.InvalidGuestAlias, '/');
        while (parents.next()) |part| {
            if (depth == stack.len) return error.InvalidGuestAlias;
            stack[depth] = part;
            depth += 1;
        }
    }
    var parts = std.mem.tokenizeScalar(u8, target, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (depth == 0) return error.InvalidGuestAlias;
            depth -= 1;
            continue;
        }
        if (!component(part) or depth == stack.len) return error.InvalidGuestAlias;
        stack[depth] = part;
        depth += 1;
    }
    if (depth == 0) return error.InvalidGuestAlias;
    var length: usize = 0;
    for (stack[0..depth]) |part| {
        if (length + 1 + part.len > buffer.len) return error.InvalidGuestAlias;
        buffer[length] = '/';
        @memcpy(buffer[length + 1 ..][0..part.len], part);
        length += 1 + part.len;
    }
    return buffer[0..length];
}

fn findEntry(manifest: Manifest, path: []const u8) ?usize {
    for (manifest.entries, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.path, path)) return index;
    }
    return null;
}

pub fn validate(allocator: std.mem.Allocator, manifest: Manifest, architecture: []const u8, lock_sha256: []const u8) !void {
    const expected_triplet = triplet(architecture) orelse return error.UnsupportedGuestArchitecture;
    var library_directory: [64]u8 = undefined;
    const expected_directory = try std.fmt.bufPrint(&library_directory, "/usr/lib/{s}", .{expected_triplet});
    if (!std.mem.eql(u8, manifest.schema, schema_id) or manifest.version != 1 or
        !std.mem.eql(u8, manifest.architecture, architecture) or !hexadecimal(lock_sha256, 64) or
        !std.mem.eql(u8, manifest.lock_sha256, lock_sha256) or
        !std.mem.eql(u8, manifest.library_directory, expected_directory) or
        !std.mem.eql(u8, manifest.cache, cache_path) or
        manifest.entries.len == 0 or manifest.entries.len > maximum_entries or
        manifest.sonames.len == 0 or manifest.sonames.len > 512 or
        manifest.cache_prefixes.len > 8 or manifest.scopes.len > 32)
        return error.InvalidGuestBinding;
    for (manifest.sonames, 0..) |name, index| {
        if (!component(name)) return error.InvalidGuestBinding;
        for (manifest.sonames[0..index]) |previous| {
            if (std.mem.eql(u8, name, previous)) return error.InvalidGuestBinding;
        }
    }
    for (manifest.cache_prefixes) |prefix| if (!component(prefix)) return error.InvalidGuestBinding;
    for (manifest.scopes, 0..) |scope, index| {
        if (!canonicalPath(scope.directory) or (scope.prefix.len != 0 and !component(scope.prefix)) or
            (scope.suffix.len != 0 and !component(scope.suffix)))
            return error.InvalidGuestBinding;
        for (manifest.scopes[0..index]) |previous| {
            if (std.mem.eql(u8, scope.directory, previous.directory) and std.mem.eql(u8, scope.prefix, previous.prefix) and
                std.mem.eql(u8, scope.suffix, previous.suffix))
                return error.InvalidGuestBinding;
        }
    }
    var paths = std.StringHashMap(void).init(allocator);
    defer paths.deinit();
    for (manifest.entries) |entry| {
        if (!canonicalPath(entry.path) or std.mem.eql(u8, entry.path, manifest.cache) or
            entry.allowed.len > 8 or (entry.required and entry.allowed.len == 0))
            return error.InvalidGuestBinding;
        const result = try paths.getOrPut(entry.path);
        if (result.found_existing) return error.DuplicateGuestBinding;
        for (entry.allowed) |identity| {
            switch (identity.kind) {
                .regular => if (identity.mode & ~@as(u32, 0o755) != 0 or identity.mode & 0o400 == 0 or
                    !hexadecimal(identity.sha256, 64) or identity.size > maximum_file_bytes or identity.target.len != 0)
                    return error.InvalidGuestBinding,
                .symlink => if (identity.mode != 0 or identity.size != 0 or identity.sha256.len != 0)
                    return error.InvalidGuestBinding,
                .directory => if (identity.mode & ~@as(u32, 0o755) != 0 or identity.mode & 0o700 != 0o700 or
                    identity.size != 0 or identity.sha256.len != 0 or identity.target.len != 0)
                    return error.InvalidGuestBinding,
            }
            if ((identity.package == null) != (identity.version == null) or
                (identity.package == null) != (identity.archive_sha512 == null) or
                (identity.package == null) != (identity.member == null))
                return error.InvalidGuestBinding;
            if (identity.package) |package| {
                if (package.len == 0 or identity.version.?.len == 0 or !hexadecimal(identity.archive_sha512.?, 128) or
                    identity.member.?.len == 0)
                    return error.InvalidGuestBinding;
            } else if (identity.kind != .regular or entry.role != .helper) {
                return error.UnsignedGuestBinding;
            }
        }
    }
    for (manifest.entries) |entry| {
        for (entry.allowed) |identity| {
            if (identity.kind != .symlink) continue;
            var buffer: [4096]u8 = undefined;
            const resolved = try resolveTarget(&buffer, entry.path, identity.target);
            if (entry.role == .alias) {
                if (std.mem.indexOfScalarPos(u8, entry.path, 1, '/') != null or !std.mem.startsWith(u8, resolved, "/usr/"))
                    return error.InvalidGuestAlias;
            } else if (findEntry(manifest, resolved) == null) {
                return error.UnboundGuestAliasTarget;
            }
        }
    }
}

fn syscall(result: usize) !usize {
    return switch (linux.errno(result)) {
        .SUCCESS => result,
        else => |err| {
            refuse("reference guest syscall refused: {s}", .{@tagName(err)});
            return error.GuestInputRefused;
        },
    };
}

fn stat(fd: i32) !linux.Statx {
    var value: linux.Statx = undefined;
    _ = try syscall(linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &value));
    return value;
}

fn sameNode(left: linux.Statx, right: linux.Statx) bool {
    return left.dev_major == right.dev_major and left.dev_minor == right.dev_minor and left.ino == right.ino;
}

fn same(left: linux.Statx, right: linux.Statx) bool {
    return sameNode(left, right) and left.mode == right.mode and left.uid == right.uid and
        left.gid == right.gid and left.size == right.size and left.nlink == right.nlink and
        left.mtime.sec == right.mtime.sec and left.mtime.nsec == right.mtime.nsec and
        left.ctime.sec == right.ctime.sec and left.ctime.nsec == right.ctime.nsec;
}

fn openat2(directory: i32, path: [*:0]const u8, flags: linux.O, resolve: u64) usize {
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve };
    return linux.syscall4(.openat2, @bitCast(@as(isize, directory)), @intFromPtr(path), @intFromPtr(&how), @sizeOf(OpenHow));
}

const State = struct {
    present: bool = false,
    metadata: linux.Statx = undefined,
};

pub const Bound = struct {
    allocator: std.mem.Allocator,
    parsed: std.json.Parsed(Manifest),
    uid: u32,
    gid: u32,
    root: linux.Statx,
    entries: []State,
    scopes: []State,
    cache: State = .{},

    /// Production guests are owned by root:root.
    pub fn init(
        allocator: std.mem.Allocator,
        source: []const u8,
        root: []const u8,
        architecture: []const u8,
        lock_sha256: []const u8,
    ) !Bound {
        return initOwned(allocator, source, root, architecture, lock_sha256, 0, 0);
    }

    pub fn initOwned(
        allocator: std.mem.Allocator,
        source: []const u8,
        root: []const u8,
        architecture: []const u8,
        lock_sha256: []const u8,
        uid: u32,
        gid: u32,
    ) !Bound {
        if (source.len > maximum_manifest_bytes) return error.InvalidGuestBinding;
        const parsed = std.json.parseFromSlice(Manifest, allocator, source, .{ .allocate = .alloc_always }) catch
            return error.InvalidGuestBinding;
        errdefer parsed.deinit();
        try validate(allocator, parsed.value, architecture, lock_sha256);
        const entries = try allocator.alloc(State, parsed.value.entries.len);
        errdefer allocator.free(entries);
        @memset(entries, .{});
        const scopes = try allocator.alloc(State, parsed.value.scopes.len);
        errdefer allocator.free(scopes);
        @memset(scopes, .{});
        var result: Bound = .{
            .allocator = allocator,
            .parsed = parsed,
            .uid = uid,
            .gid = gid,
            .root = undefined,
            .entries = entries,
            .scopes = scopes,
        };
        const root_fd = try openRoot(allocator, root);
        defer _ = linux.close(root_fd);
        result.root = try stat(root_fd);
        try result.bind(root_fd);
        return result;
    }

    pub fn deinit(self: *Bound) void {
        self.allocator.free(self.entries);
        self.allocator.free(self.scopes);
        self.parsed.deinit();
    }

    pub fn manifest(self: *const Bound) Manifest {
        return self.parsed.value;
    }

    fn bind(self: *Bound, root: i32) !void {
        const record = self.manifest();
        for (record.entries, self.entries) |entry, *state| {
            const node = try self.lookup(root, entry.path) orelse {
                if (entry.required) {
                    refuse("reference guest binding {s} is missing", .{entry.path});
                    return error.MissingGuestBinding;
                }
                continue;
            };
            defer _ = linux.close(node.fd);
            self.match(root, entry, node) catch |err| {
                refuse("reference guest binding {s} refused: {s}", .{ entry.path, @errorName(err) });
                return err;
            };
            state.* = .{ .present = true, .metadata = node.metadata };
        }
        for (record.entries, self.entries) |entry, state| {
            if (!state.present or state.metadata.mode & 0o170000 != 0o120000 or entry.role == .alias) continue;
            var link: [4097]u8 = undefined;
            var buffer: [4096]u8 = undefined;
            const resolved = try resolveTarget(&buffer, entry.path, try self.readLink(root, entry.path, &link));
            const index = findEntry(record, resolved) orelse return error.UnboundGuestAliasTarget;
            if (!self.entries[index].present) {
                refuse("reference guest alias {s} targets missing {s}", .{ entry.path, resolved });
                return error.MissingGuestBinding;
            }
        }
        for (record.scopes, self.scopes) |scope, *state| {
            state.* = try self.scan(root, scope);
        }
        self.cache = try self.bindCache(root);
    }

    const Node = struct { fd: i32, metadata: linux.Statx };

    fn lookup(self: *const Bound, root: i32, path: []const u8) !?Node {
        const relative = try self.allocator.dupeSentinel(u8, path[1..], 0);
        defer self.allocator.free(relative);
        var cursor: usize = 0;
        while (std.mem.indexOfScalarPos(u8, relative, cursor, '/')) |end| : (cursor = end + 1) {
            relative[end] = 0;
            defer relative[end] = '/';
            const result = openat2(root, relative.ptr, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, resolve_beneath);
            switch (linux.errno(result)) {
                .SUCCESS => {},
                .NOENT => return null,
                .NOTDIR, .LOOP, .XDEV => return error.GuestPathChanged,
                else => return error.GuestInputRefused,
            }
            const fd: i32 = @intCast(result);
            defer _ = linux.close(fd);
            const info = try stat(fd);
            if (info.mode & 0o170000 != 0o040000 or info.uid != self.uid or info.gid != self.gid or info.mode & 0o022 != 0)
                return error.UnprotectedGuestDirectory;
        }
        const result = openat2(root, relative.ptr, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, resolve_beneath);
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .NOENT => return null,
            .NOTDIR, .LOOP, .XDEV => return error.GuestPathChanged,
            else => return error.GuestInputRefused,
        }
        const fd: i32 = @intCast(result);
        errdefer _ = linux.close(fd);
        return .{ .fd = fd, .metadata = try stat(fd) };
    }

    fn readLink(self: *const Bound, root: i32, path: []const u8, buffer: *[4097]u8) ![]const u8 {
        const node = try self.lookup(root, path) orelse return error.GuestSourceChanged;
        defer _ = linux.close(node.fd);
        if (node.metadata.mode & 0o170000 != 0o120000) return error.GuestAliasChanged;
        const length = try syscall(linux.readlinkat(node.fd, "", buffer, buffer.len));
        if (length == 0 or length >= buffer.len) return error.GuestAliasChanged;
        return buffer[0..length];
    }

    fn match(self: *const Bound, root: i32, entry: Entry, node: Node) !void {
        const info = node.metadata;
        if (entry.allowed.len == 0) return error.ForbiddenGuestEntry;
        if (info.uid != self.uid or info.gid != self.gid) return error.UnprotectedGuestEntry;
        const kind: Kind = switch (info.mode & 0o170000) {
            0o100000 => .regular,
            0o120000 => .symlink,
            0o040000 => .directory,
            else => return error.UnsupportedGuestEntry,
        };
        if (kind != .symlink and info.mode & 0o022 != 0) return error.UnprotectedGuestEntry;
        if (!hasKind(entry, kind))
            return if (kind == .symlink or hasKind(entry, .symlink)) error.GuestAliasChanged else error.GuestKindChanged;
        switch (kind) {
            .regular => {
                var candidate = false;
                for (entry.allowed) |identity| {
                    if (identity.kind == .regular and identity.size == info.size) candidate = true;
                }
                if (!candidate) return error.GuestDigestChanged;
                const actual = try self.digest(root, entry.path, info);
                var metadata_changed = false;
                for (entry.allowed) |identity| {
                    if (identity.kind != .regular or identity.size != info.size or !std.mem.eql(u8, identity.sha256, &actual))
                        continue;
                    if (identity.mode == info.mode & 0o7777) return;
                    metadata_changed = true;
                }
                return if (metadata_changed) error.GuestMetadataChanged else error.GuestDigestChanged;
            },
            .symlink => {
                var buffer: [4097]u8 = undefined;
                const length = try syscall(linux.readlinkat(node.fd, "", &buffer, buffer.len));
                if (length == 0 or length >= buffer.len) return error.GuestAliasChanged;
                for (entry.allowed) |identity| {
                    if (identity.kind == .symlink and std.mem.eql(u8, identity.target, buffer[0..length])) return;
                }
                return error.GuestAliasChanged;
            },
            .directory => {
                for (entry.allowed) |identity| {
                    if (identity.kind == .directory and identity.mode == info.mode & 0o7777) return;
                }
                return error.GuestMetadataChanged;
            },
        }
    }

    fn hasKind(entry: Entry, kind: Kind) bool {
        for (entry.allowed) |identity| if (identity.kind == kind) return true;
        return false;
    }

    fn digest(self: *const Bound, root: i32, path: []const u8, expected: linux.Statx) ![64]u8 {
        const relative = try self.allocator.dupeSentinel(u8, path[1..], 0);
        defer self.allocator.free(relative);
        const result = openat2(root, relative.ptr, .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .NOCTTY = true,
            .CLOEXEC = true,
        }, resolve_beneath);
        if (linux.errno(result) != .SUCCESS) return error.GuestSourceChanged;
        const fd: i32 = @intCast(result);
        defer _ = linux.close(fd);
        if (!same(expected, try stat(fd))) return error.GuestSourceChanged;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < expected.size) {
            const wanted: usize = @intCast(@min(buffer.len, expected.size - offset));
            const got = try syscall(linux.pread(fd, &buffer, wanted, @intCast(offset)));
            if (got == 0) return error.GuestSourceChanged;
            hash.update(buffer[0..got]);
            offset += got;
        }
        if (!same(expected, try stat(fd))) return error.GuestSourceChanged;
        var value: [32]u8 = undefined;
        hash.final(&value);
        return std.fmt.bytesToHex(value, .lower);
    }

    fn scan(self: *const Bound, root: i32, scope: Scope) !State {
        const node = try self.lookup(root, scope.directory) orelse return .{};
        defer _ = linux.close(node.fd);
        if (node.metadata.mode & 0o170000 != 0o040000 or node.metadata.uid != self.uid or
            node.metadata.gid != self.gid or node.metadata.mode & 0o022 != 0)
            return error.UnprotectedGuestDirectory;
        const relative = try self.allocator.dupeSentinel(u8, scope.directory[1..], 0);
        defer self.allocator.free(relative);
        const result = openat2(root, relative.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, resolve_beneath);
        if (linux.errno(result) != .SUCCESS) return error.GuestSourceChanged;
        const fd: i32 = @intCast(result);
        defer _ = linux.close(fd);
        const before = try stat(fd);
        if (!same(before, node.metadata)) return error.GuestSourceChanged;
        var buffer: [16 * 1024]u8 align(8) = undefined;
        var count: usize = 0;
        while (true) {
            const size = try syscall(linux.getdents64(fd, &buffer, buffer.len));
            if (size == 0) break;
            var offset: usize = 0;
            while (offset < size) {
                if (size - offset < 20) return error.InvalidGuestDirectory;
                const length = std.mem.readInt(u16, buffer[offset + 16 ..][0..2], .little);
                if (length < 20 or length > size - offset) return error.InvalidGuestDirectory;
                const names = buffer[offset + 19 .. offset + length];
                const end = std.mem.indexOfScalar(u8, names, 0) orelse return error.InvalidGuestDirectory;
                const name = names[0..end];
                offset += length;
                if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
                count += 1;
                if (count > 65536) return error.InvalidGuestDirectory;
                if (!std.mem.startsWith(u8, name, scope.prefix) or !std.mem.endsWith(u8, name, scope.suffix)) continue;
                const child = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ scope.directory, name });
                defer self.allocator.free(child);
                if (findEntry(self.manifest(), child) == null) {
                    refuse("reference guest scope {s} contains unbound {s}", .{ scope.directory, name });
                    return error.UnboundGuestEntry;
                }
            }
        }
        if (!same(before, try stat(fd))) return error.GuestSourceChanged;
        return .{ .present = true, .metadata = before };
    }

    fn bindCache(self: *const Bound, root: i32) !State {
        const node = try self.lookup(root, self.manifest().cache) orelse return .{};
        defer _ = linux.close(node.fd);
        const info = node.metadata;
        if (info.mode & 0o170000 != 0o100000 or info.uid != self.uid or info.gid != self.gid or
            info.mode & 0o022 != 0 or info.nlink != 1 or info.size > maximum_cache_bytes)
            return error.UnprotectedGuestCache;
        const relative = try self.allocator.dupeSentinel(u8, self.manifest().cache[1..], 0);
        defer self.allocator.free(relative);
        const result = openat2(root, relative.ptr, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, resolve_beneath);
        if (linux.errno(result) != .SUCCESS) return error.GuestSourceChanged;
        const fd: i32 = @intCast(result);
        defer _ = linux.close(fd);
        if (!same(info, try stat(fd))) return error.GuestSourceChanged;
        const bytes = try self.allocator.alloc(u8, @intCast(info.size));
        defer self.allocator.free(bytes);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const got = try syscall(linux.pread(fd, bytes[offset..].ptr, bytes.len - offset, @intCast(offset)));
            if (got == 0) return error.GuestSourceChanged;
            offset += got;
        }
        if (!same(info, try stat(fd))) return error.GuestSourceChanged;
        try checkCache(self.manifest(), bytes);
        return .{ .present = true, .metadata = info };
    }

    /// Re-resolves every binding beneath `root` ("" or "/" after chroot) and
    /// requires the pinned metadata, presence and absence observed at bind time.
    pub fn verify(self: *const Bound, root: []const u8) !void {
        const root_fd = try openRoot(self.allocator, root);
        defer _ = linux.close(root_fd);
        const current_root = try stat(root_fd);
        if (!sameNode(current_root, self.root) or current_root.uid != self.root.uid or
            current_root.gid != self.root.gid or current_root.mode != self.root.mode)
            return error.GuestSourceChanged;
        const record = self.manifest();
        for (record.entries, self.entries) |entry, state| try self.reverify(root_fd, entry.path, state);
        for (record.scopes, self.scopes) |scope, state| try self.reverify(root_fd, scope.directory, state);
        try self.reverify(root_fd, record.cache, self.cache);
    }

    fn reverify(self: *const Bound, root: i32, path: []const u8, state: State) !void {
        const node = self.lookup(root, path) catch return error.GuestSourceChanged;
        if (node) |value| {
            defer _ = linux.close(value.fd);
            if (!state.present or !same(state.metadata, value.metadata)) {
                refuse("reference guest binding {s} changed after binding", .{path});
                return error.GuestSourceChanged;
            }
        } else if (state.present) {
            refuse("reference guest binding {s} disappeared after binding", .{path});
            return error.GuestSourceChanged;
        }
    }
};

fn openRoot(allocator: std.mem.Allocator, root: []const u8) !i32 {
    const path = try allocator.dupeSentinel(u8, if (root.len == 0) "/" else root, 0);
    defer allocator.free(path);
    if (path[0] != '/') return error.InvalidGuestRoot;
    const result = openat2(linux.AT.FDCWD, path.ptr, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, resolve_absolute);
    if (linux.errno(result) != .SUCCESS) return error.InvalidGuestRoot;
    return @intCast(result);
}

fn cString(bytes: []const u8, offset: u32) ![]const u8 {
    if (offset >= bytes.len) return error.InvalidGuestCache;
    const end = std.mem.indexOfScalarPos(u8, bytes, offset, 0) orelse return error.InvalidGuestCache;
    if (end - offset > 4096) return error.InvalidGuestCache;
    return bytes[offset..end];
}

/// Accepts only the glibc 1.1 cache format. Every entry whose key is a bound
/// soname or carries a late-loading prefix (for example `libnss_`) must name
/// that bound soname at its canonical library directory path.
pub fn checkCache(manifest: Manifest, bytes: []const u8) !void {
    const magic = "glibc-ld.so.cache1.1";
    if (bytes.len < 48 or !std.mem.eql(u8, bytes[0..magic.len], magic)) return error.InvalidGuestCache;
    const count = std.mem.readInt(u32, bytes[20..24], .little);
    const strings = std.mem.readInt(u32, bytes[24..28], .little);
    const endian = bytes[28] & 3;
    if ((endian != 0 and endian != 2) or count > 65536) return error.InvalidGuestCache;
    const table = 48 + @as(usize, count) * 24;
    if (table > bytes.len or strings > bytes.len - table) return error.InvalidGuestCache;
    for (0..count) |index| {
        const entry = bytes[48 + index * 24 ..][0..24];
        const key = try cString(bytes, std.mem.readInt(u32, entry[4..8], .little));
        const value = try cString(bytes, std.mem.readInt(u32, entry[8..12], .little));
        var reviewed = false;
        for (manifest.sonames) |name| {
            if (std.mem.eql(u8, name, key)) reviewed = true;
        }
        var prefixed = false;
        for (manifest.cache_prefixes) |prefix| {
            if (std.mem.startsWith(u8, key, prefix)) prefixed = true;
        }
        if (!reviewed and !prefixed) continue;
        var buffer: [4200]u8 = undefined;
        const normalized = if (std.mem.startsWith(u8, value, "/lib/") or std.mem.startsWith(u8, value, "/lib64/"))
            try std.fmt.bufPrint(&buffer, "/usr{s}", .{value})
        else
            value;
        var expected: [4200]u8 = undefined;
        const canonical = try std.fmt.bufPrint(&expected, "{s}/{s}", .{ manifest.library_directory, key });
        // ldconfig also records the signed loader alias under its trusted directories.
        var alias = false;
        for (manifest.entries) |bound| {
            if (bound.role == .loader and std.mem.eql(u8, bound.path, normalized) and
                std.mem.eql(u8, std.fs.path.basename(bound.path), key)) alias = true;
        }
        if (!reviewed or (!alias and !std.mem.eql(u8, normalized, canonical))) {
            refuse("reference guest loader cache maps {s} to unbound {s}", .{ key, value });
            return error.UnboundGuestCacheEntry;
        }
    }
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    relative: []u8,
    absolute: []u8,
    fd: i32,

    var serial: usize = 0;

    fn init(allocator: std.mem.Allocator) !Fixture {
        const io = std.testing.io;
        serial += 1;
        const relative = try std.fmt.allocPrint(allocator, ".cache/reference-guest-{d}-{d}", .{ linux.getpid(), serial });
        errdefer allocator.free(relative);
        const cwd = std.Io.Dir.cwd();
        cwd.deleteTree(io, relative) catch {};
        try cwd.createDirPath(io, relative);
        var opened = try cwd.openDir(io, relative, .{});
        defer opened.close(io);
        var resolved: [std.fs.max_path_bytes]u8 = undefined;
        const length = try opened.realPath(io, &resolved);
        const absolute = try allocator.dupe(u8, resolved[0..length]);
        errdefer allocator.free(absolute);
        const path = try allocator.dupeSentinel(u8, absolute, 0);
        defer allocator.free(path);
        const fd: i32 = @intCast(try syscall(linux.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0)));
        _ = try syscall(linux.fchmod(fd, 0o755));
        return .{ .allocator = allocator, .relative = relative, .absolute = absolute, .fd = fd };
    }

    fn deinit(self: *Fixture) void {
        _ = linux.close(self.fd);
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.relative) catch {};
        self.allocator.free(self.relative);
        self.allocator.free(self.absolute);
    }

    fn directory(self: *const Fixture, path: []const u8) !void {
        const owned = try self.allocator.dupeSentinel(u8, path, 0);
        defer self.allocator.free(owned);
        var cursor: usize = 0;
        while (true) {
            const end = std.mem.indexOfScalarPos(u8, owned, cursor, '/') orelse owned.len;
            const saved = owned[end];
            owned[end] = 0;
            const result = linux.mkdirat(self.fd, owned.ptr, 0o755);
            if (linux.errno(result) != .SUCCESS and linux.errno(result) != .EXIST) return error.FixtureFailed;
            if (linux.errno(result) == .SUCCESS) {
                const fd: i32 = @intCast(try syscall(linux.openat(self.fd, owned.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0)));
                defer _ = linux.close(fd);
                _ = try syscall(linux.fchmod(fd, 0o755));
            }
            owned[end] = saved;
            if (end == owned.len) break;
            cursor = end + 1;
        }
    }

    fn file(self: *const Fixture, path: []const u8, bytes: []const u8, mode: u32) !void {
        if (std.fs.path.dirname(path)) |parent| try self.directory(parent);
        self.remove(path);
        const owned = try self.allocator.dupeSentinel(u8, path, 0);
        defer self.allocator.free(owned);
        const fd: i32 = @intCast(try syscall(linux.openat(self.fd, owned.ptr, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, 0o600)));
        defer _ = linux.close(fd);
        if (bytes.len != 0 and try syscall(linux.write(fd, bytes.ptr, bytes.len)) != bytes.len) return error.FixtureFailed;
        _ = try syscall(linux.fchmod(fd, mode));
    }

    fn link(self: *const Fixture, path: []const u8, target: []const u8) !void {
        if (std.fs.path.dirname(path)) |parent| try self.directory(parent);
        self.remove(path);
        const owned = try self.allocator.dupeSentinel(u8, path, 0);
        defer self.allocator.free(owned);
        const literal = try self.allocator.dupeSentinel(u8, target, 0);
        defer self.allocator.free(literal);
        _ = try syscall(linux.symlinkat(literal.ptr, self.fd, owned.ptr));
    }

    fn remove(self: *const Fixture, path: []const u8) void {
        const owned = self.allocator.dupeSentinel(u8, path, 0) catch return;
        defer self.allocator.free(owned);
        if (linux.errno(linux.unlinkat(self.fd, owned.ptr, 0)) == .ISDIR)
            _ = linux.unlinkat(self.fd, owned.ptr, linux.AT.REMOVEDIR);
    }
};

const fixture_lock = "1111111111111111111111111111111111111111111111111111111111111111";
const fixture_archive: *const [128]u8 = &@splat('a');
const fixture_files = [_]struct { path: []const u8, bytes: []const u8, mode: u32, role: Role, required: bool }{
    .{ .path = "usr/bin/tar", .bytes = "tar helper", .mode = 0o755, .role = .helper, .required = true },
    .{ .path = "usr/bin/gnurm", .bytes = "gnu rm helper", .mode = 0o755, .role = .helper, .required = false },
    .{ .path = "usr/bin/dpkg-split", .bytes = "split helper", .mode = 0o755, .role = .helper, .required = true },
    .{ .path = "usr/lib/x86_64-linux-gnu/libc.so.6", .bytes = "libc bytes", .mode = 0o644, .role = .library, .required = true },
    .{ .path = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", .bytes = "loader bytes", .mode = 0o755, .role = .loader, .required = true },
    .{ .path = "etc/ld.so.conf.d/libc.conf", .bytes = "/usr/local/lib\n", .mode = 0o644, .role = .loader_config, .required = false },
    .{ .path = "usr/lib/x86_64-linux-gnu/libnss_files.so.2", .bytes = "nss files", .mode = 0o644, .role = .nss_provider, .required = false },
    .{ .path = "etc/nsswitch.conf", .bytes = "passwd: files\n", .mode = 0o644, .role = .nss_config, .required = false },
    .{ .path = "usr/lib/x86_64-linux-gnu/gconv/gconv-modules", .bytes = "module x y z\n", .mode = 0o644, .role = .gconv, .required = false },
};

fn fixtureIdentity(allocator: std.mem.Allocator, bytes: []const u8, mode: u32, member: []const u8) !Identity {
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &value, .{});
    return .{
        .kind = .regular,
        .mode = mode,
        .size = bytes.len,
        .sha256 = try allocator.dupe(u8, &std.fmt.bytesToHex(value, .lower)),
        .package = "fixture",
        .version = "1",
        .archive_sha512 = fixture_archive,
        .member = member,
    };
}

fn fixtureLink(target: []const u8) Identity {
    return .{ .kind = .symlink, .target = target, .package = "fixture", .version = "1", .archive_sha512 = fixture_archive, .member = target };
}

fn fixtureDirectory() Identity {
    return .{ .kind = .directory, .mode = 0o755, .package = "fixture", .version = "1", .archive_sha512 = fixture_archive, .member = "directory" };
}

fn fixtureManifest(arena: std.mem.Allocator) ![]const u8 {
    var entries: std.ArrayList(Entry) = .empty;
    try entries.append(arena, .{ .path = "/bin", .role = .alias, .required = true, .allowed = try arena.dupe(Identity, &.{fixtureLink("usr/bin")}) });
    for (fixture_files) |item| {
        const allowed = try arena.dupe(Identity, &.{try fixtureIdentity(arena, item.bytes, item.mode, item.path)});
        try entries.append(arena, .{ .path = try std.fmt.allocPrint(arena, "/{s}", .{item.path}), .role = item.role, .required = item.required, .allowed = allowed });
    }
    const rm_bytes = fixture_files[1];
    try entries.append(arena, .{ .path = "/usr/bin/rm", .role = .helper, .required = true, .allowed = try arena.dupe(Identity, &.{
        try fixtureIdentity(arena, rm_bytes.bytes, 0o755, "usr/bin/gnurm"),
        fixtureLink("gnurm"),
    }) });
    try entries.append(arena, .{ .path = "/usr/lib64/ld-linux-x86-64.so.2", .role = .loader, .required = true, .allowed = try arena.dupe(Identity, &.{
        fixtureLink("../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    }) });
    try entries.append(arena, .{ .path = "/usr/lib/x86_64-linux-gnu/gconv", .role = .gconv, .allowed = try arena.dupe(Identity, &.{fixtureDirectory()}) });
    try entries.append(arena, .{ .path = "/etc/ld.so.conf.d", .role = .loader_config, .allowed = try arena.dupe(Identity, &.{fixtureDirectory()}) });
    try entries.append(arena, .{ .path = "/etc/dpkg/dpkg.cfg.d", .role = .dpkg_config, .allowed = try arena.dupe(Identity, &.{fixtureDirectory()}) });
    for ([_][]const u8{ "/usr/sbin/tar", "/usr/bin/debsig-verify", "/usr/sbin/debsig-verify", "/usr/lib/libc.so.6" }) |path| {
        try entries.append(arena, .{ .path = path, .role = .shadow });
    }
    try entries.append(arena, .{ .path = "/usr/lib/x86_64-linux-gnu/glibc-hwcaps", .role = .hwcaps });
    const manifest: Manifest = .{
        .architecture = "amd64",
        .lock_sha256 = fixture_lock,
        .library_directory = "/usr/lib/x86_64-linux-gnu",
        .sonames = &.{ "libc.so.6", "ld-linux-x86-64.so.2", "libnss_files.so.2" },
        .cache_prefixes = &.{"libnss_"},
        .scopes = &.{
            .{ .directory = "/usr/lib/x86_64-linux-gnu", .prefix = "libnss_" },
            .{ .directory = "/usr/lib/x86_64-linux-gnu/gconv", .prefix = "" },
            .{ .directory = "/etc/dpkg/dpkg.cfg.d", .prefix = "" },
            .{ .directory = "/etc/ld.so.conf.d", .prefix = "", .suffix = ".conf" },
        },
        .entries = entries.items,
    };
    return std.json.Stringify.valueAlloc(arena, manifest, .{});
}

fn populateFixture(fixture: *const Fixture) !void {
    try fixture.directory("usr/bin");
    try fixture.directory("usr/sbin");
    try fixture.directory("etc/dpkg/dpkg.cfg.d");
    try fixture.link("bin", "usr/bin");
    for (fixture_files) |item| try fixture.file(item.path, item.bytes, item.mode);
    try fixture.link("usr/bin/rm", "gnurm");
    try fixture.link("usr/lib64/ld-linux-x86-64.so.2", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
}

fn fixtureBind(allocator: std.mem.Allocator, fixture: *const Fixture, source: []const u8) !Bound {
    return Bound.initOwned(allocator, source, fixture.absolute, "amd64", fixture_lock, linux.getuid(), linux.getgid());
}

fn cacheFixture(allocator: std.mem.Allocator, pairs: []const [2][]const u8) ![]u8 {
    var strings: std.ArrayList(u8) = .empty;
    defer strings.deinit(allocator);
    const base = 48 + pairs.len * 24;
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, "glibc-ld.so.cache1.1");
    var header: [28]u8 = @splat(0);
    std.mem.writeInt(u32, header[0..4], @intCast(pairs.len), .little);
    header[8] = 2;
    var offsets: std.ArrayList([2]u32) = .empty;
    defer offsets.deinit(allocator);
    for (pairs) |pair| {
        const key: u32 = @intCast(base + strings.items.len);
        try strings.appendSlice(allocator, pair[0]);
        try strings.append(allocator, 0);
        const value: u32 = @intCast(base + strings.items.len);
        try strings.appendSlice(allocator, pair[1]);
        try strings.append(allocator, 0);
        try offsets.append(allocator, .{ key, value });
    }
    std.mem.writeInt(u32, header[4..8], @intCast(strings.items.len), .little);
    try bytes.appendSlice(allocator, &header);
    for (offsets.items) |offset| {
        var entry: [24]u8 = @splat(0);
        std.mem.writeInt(i32, entry[0..4], 0x0303, .little);
        std.mem.writeInt(u32, entry[4..8], offset[0], .little);
        std.mem.writeInt(u32, entry[8..12], offset[1], .little);
        try bytes.appendSlice(allocator, &entry);
    }
    try bytes.appendSlice(allocator, strings.items);
    return bytes.toOwnedSlice(allocator);
}

test "reference guest binds signed helpers, aliases, NSS, gconv, dpkg configuration and absences" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const source = try fixtureManifest(arena);
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try populateFixture(&fixture);
    {
        var bound = try fixtureBind(std.testing.allocator, &fixture, source);
        defer bound.deinit();
        try bound.verify(fixture.absolute);
    }
    // The regular staged rm and a present gnurm are both signed identities.
    try fixture.file("usr/bin/rm", fixture_files[1].bytes, 0o755);
    {
        var bound = try fixtureBind(std.testing.allocator, &fixture, source);
        defer bound.deinit();
    }
    const Case = struct { mutate: *const fn (*const Fixture) anyerror!void, expected: anyerror };
    const cases = [_]Case{
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("usr/bin/tar", "tar trojan", 0o755);
            }
        }.f, .expected = error.GuestDigestChanged },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("usr/bin/tar", "tar helper", 0o750);
            }
        }.f, .expected = error.GuestMetadataChanged },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                item.remove("usr/bin/dpkg-split");
            }
        }.f, .expected = error.MissingGuestBinding },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.link("usr/bin/rm", "tar");
            }
        }.f, .expected = error.GuestAliasChanged },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                item.remove("usr/bin/gnurm");
            }
        }.f, .expected = error.MissingGuestBinding },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("usr/sbin/tar", "tar helper", 0o755);
            }
        }.f, .expected = error.ForbiddenGuestEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("usr/bin/debsig-verify", "#!/bin/sh\n", 0o755);
            }
        }.f, .expected = error.ForbiddenGuestEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("usr/lib/libc.so.6", "libc bytes", 0o644);
            }
        }.f, .expected = error.ForbiddenGuestEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("usr/lib/x86_64-linux-gnu/libnss_db.so.2", "late provider", 0o644);
            }
        }.f, .expected = error.UnboundGuestEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("etc/nsswitch.conf", "passwd: files db\n", 0o644);
            }
        }.f, .expected = error.GuestDigestChanged },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("etc/dpkg/dpkg.cfg.d/injected", "pre-invoke=touch /x\n", 0o644);
            }
        }.f, .expected = error.UnboundGuestEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("usr/lib/x86_64-linux-gnu/gconv/EVIL.so", "module", 0o644);
            }
        }.f, .expected = error.UnboundGuestEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.directory("usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3");
            }
        }.f, .expected = error.ForbiddenGuestEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                item.remove("usr/sbin");
                try item.link("usr/sbin", "bin");
            }
        }.f, .expected = error.GuestPathChanged },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                const bytes = try cacheFixture(item.allocator, &.{.{ "libc.so.6", "/usr/local/lib/libc.so.6" }});
                defer item.allocator.free(bytes);
                try item.file("etc/ld.so.cache", bytes, 0o644);
            }
        }.f, .expected = error.UnboundGuestCacheEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                const bytes = try cacheFixture(item.allocator, &.{.{ "libnss_db.so.2", "/lib/x86_64-linux-gnu/libnss_db.so.2" }});
                defer item.allocator.free(bytes);
                try item.file("etc/ld.so.cache", bytes, 0o644);
            }
        }.f, .expected = error.UnboundGuestCacheEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("etc/ld.so.cache", "ld.so-1.7.0" ++ &@as([40]u8, @splat(0)), 0o644);
            }
        }.f, .expected = error.InvalidGuestCache },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                const bytes = try cacheFixture(item.allocator, &.{.{ "libc.so.6", "/lib64/libc.so.6" }});
                defer item.allocator.free(bytes);
                try item.file("etc/ld.so.cache", bytes, 0o644);
            }
        }.f, .expected = error.UnboundGuestCacheEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.file("etc/ld.so.conf.d/zz-late.conf", "/opt/late\n", 0o644);
            }
        }.f, .expected = error.UnboundGuestEntry },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                try item.link("usr/lib64/ld-linux-x86-64.so.2", "/opt/loader");
            }
        }.f, .expected = error.GuestAliasChanged },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                item.remove("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
            }
        }.f, .expected = error.MissingGuestBinding },
        .{ .mutate = struct {
            fn f(item: *const Fixture) !void {
                item.remove("usr/bin/tar");
                try item.directory("usr/bin/tar");
            }
        }.f, .expected = error.GuestKindChanged },
    };
    for (cases) |case| {
        var each = try Fixture.init(std.testing.allocator);
        defer each.deinit();
        try populateFixture(&each);
        try case.mutate(&each);
        try std.testing.expectError(case.expected, fixtureBind(std.testing.allocator, &each, source));
    }
    {
        var each = try Fixture.init(std.testing.allocator);
        defer each.deinit();
        try populateFixture(&each);
        // A conffile staged by dpkg before configure is outside the `.conf` include glob.
        try each.file("etc/ld.so.conf.d/libc.conf.dpkg-new", "/usr/local/lib\n", 0o644);
        const bytes = try cacheFixture(std.testing.allocator, &.{
            .{ "ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2" },
            .{ "ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" },
            .{ "libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6" },
            .{ "libnss_files.so.2", "/usr/lib/x86_64-linux-gnu/libnss_files.so.2" },
            .{ "libunrelated.so.1", "/usr/local/lib/libunrelated.so.1" },
        });
        defer std.testing.allocator.free(bytes);
        try each.file("etc/ld.so.cache", bytes, 0o644);
        var bound = try fixtureBind(std.testing.allocator, &each, source);
        defer bound.deinit();
        try bound.verify(each.absolute);
    }
}

test "reference guest refuses post-binding changes, appearances and disappearances before execution" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const source = try fixtureManifest(arena_state.allocator());
    const Case = *const fn (*const Fixture) anyerror!void;
    const cases = [_]Case{
        struct {
            fn f(item: *const Fixture) !void {
                try item.file("usr/bin/tar", "tar trojan", 0o755);
            }
        }.f,
        struct {
            fn f(item: *const Fixture) !void {
                try item.file("usr/sbin/tar", "tar helper", 0o755);
            }
        }.f,
        struct {
            fn f(item: *const Fixture) !void {
                item.remove("usr/lib/x86_64-linux-gnu/libnss_files.so.2");
            }
        }.f,
        struct {
            fn f(item: *const Fixture) !void {
                try item.file("etc/dpkg/dpkg.cfg.d/injected", "", 0o644);
            }
        }.f,
        struct {
            fn f(item: *const Fixture) !void {
                const bytes = try cacheFixture(item.allocator, &.{.{ "libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6" }});
                defer item.allocator.free(bytes);
                try item.file("etc/ld.so.cache", bytes, 0o644);
            }
        }.f,
    };
    for (cases) |mutate| {
        var each = try Fixture.init(std.testing.allocator);
        defer each.deinit();
        try populateFixture(&each);
        var bound = try fixtureBind(std.testing.allocator, &each, source);
        defer bound.deinit();
        try bound.verify(each.absolute);
        try mutate(&each);
        try std.testing.expectError(error.GuestSourceChanged, bound.verify(each.absolute));
    }
}

test "reference guest manifest refuses unsigned, ambiguous and dangling bindings" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const identity = try fixtureIdentity(arena, "bytes", 0o755, "usr/bin/tar");
    var unsigned = identity;
    unsigned.package = null;
    unsigned.version = null;
    unsigned.archive_sha512 = null;
    unsigned.member = null;
    const base: Manifest = .{
        .architecture = "amd64",
        .lock_sha256 = fixture_lock,
        .library_directory = "/usr/lib/x86_64-linux-gnu",
        .sonames = &.{"libc.so.6"},
        .cache_prefixes = &.{"libnss_"},
        .scopes = &.{},
        .entries = &.{.{ .path = "/usr/bin/tar", .role = .helper, .required = true, .allowed = &.{identity} }},
    };
    try validate(arena, base, "amd64", fixture_lock);
    try std.testing.expectError(error.InvalidGuestBinding, validate(arena, base, "amd64", &@as([64]u8, @splat('2'))));
    try std.testing.expectError(error.UnsupportedGuestArchitecture, validate(arena, base, "i386", fixture_lock));
    var changed = base;
    changed.library_directory = "/usr/local/lib";
    try std.testing.expectError(error.InvalidGuestBinding, validate(arena, changed, "amd64", fixture_lock));
    changed = base;
    changed.entries = &.{ base.entries[0], base.entries[0] };
    try std.testing.expectError(error.DuplicateGuestBinding, validate(arena, changed, "amd64", fixture_lock));
    changed.entries = &.{.{ .path = "/usr/lib/x86_64-linux-gnu/libc.so.6", .role = .library, .allowed = &.{unsigned} }};
    try std.testing.expectError(error.UnsignedGuestBinding, validate(arena, changed, "amd64", fixture_lock));
    changed.entries = &.{.{ .path = "/usr/bin/sh", .role = .interpreter, .allowed = &.{fixtureLink("dash")} }};
    try std.testing.expectError(error.UnboundGuestAliasTarget, validate(arena, changed, "amd64", fixture_lock));
    changed.entries = &.{.{ .path = "/usr/bin/../tar", .role = .helper, .allowed = &.{identity} }};
    try std.testing.expectError(error.InvalidGuestBinding, validate(arena, changed, "amd64", fixture_lock));
    changed.entries = &.{.{ .path = "/usr/bin/tar", .role = .helper, .required = true }};
    try std.testing.expectError(error.InvalidGuestBinding, validate(arena, changed, "amd64", fixture_lock));
    changed.entries = &.{.{ .path = "/bin", .role = .alias, .allowed = &.{fixtureLink("/etc")} }};
    try std.testing.expectError(error.InvalidGuestAlias, validate(arena, changed, "amd64", fixture_lock));
    var buffer: [4096]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        try resolveTarget(&buffer, "/usr/lib64/ld-linux-x86-64.so.2", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    );
    try std.testing.expectError(error.InvalidGuestAlias, resolveTarget(&buffer, "/bin", "../../.."));
}

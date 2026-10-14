const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const guest = @import("real-snapshot-reference-guest.zig");

pub const schema_id = "io.github.cataggar.debz.reference-runtime.v1";
pub const mountpoint = "/.debz-reference-runtime";
pub const maximum_object_bytes = 16 * 1024 * 1024;

pub const Link = struct {
    path: []const u8,
    target: []const u8,
};

pub const Binding = struct {
    name: []const u8,
    root_path: ?[]const u8,
    sha256: []const u8,
    size: usize,
    mode: u32,
    package: ?[]const u8,
    version: ?[]const u8,
    archive_sha512: ?[]const u8,
};

pub const Manifest = struct {
    schema: []const u8 = schema_id,
    version: u32 = 1,
    architecture: []const u8,
    lock_sha256: []const u8,
    loader: []const u8,
    objects: []const Binding,
    links: []const Link,
};

pub const Pinned = struct {
    fd: i32,
    metadata: linux.Statx,
};

const OpenHow = extern struct { flags: u64, mode: u64 = 0, resolve: u64 = 0x02 | 0x04 };

fn syscall(result: usize) !usize {
    return switch (linux.errno(result)) {
        .SUCCESS => result,
        else => |err| {
            std.log.err("reference runtime syscall refused: {s}", .{@tagName(err)});
            return error.RuntimeInputRefused;
        },
    };
}

pub fn stat(fd: i32) !linux.Statx {
    var value: linux.Statx = undefined;
    _ = try syscall(linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &value));
    return value;
}

pub fn same(left: linux.Statx, right: linux.Statx) bool {
    return left.dev_major == right.dev_major and left.dev_minor == right.dev_minor and
        left.ino == right.ino and left.mode == right.mode and left.uid == right.uid and
        left.gid == right.gid and left.size == right.size and left.nlink == right.nlink and
        left.mtime.sec == right.mtime.sec and left.mtime.nsec == right.mtime.nsec and
        left.ctime.sec == right.ctime.sec and left.ctime.nsec == right.ctime.nsec;
}

fn protectedMetadata(info: linux.Statx, directory: bool) bool {
    return info.uid == 0 and info.gid == 0 and info.mode & 0o022 == 0 and
        info.mode & 0o170000 == (if (directory) @as(u16, 0o040000) else @as(u16, 0o100000));
}

pub fn openProtected(allocator: std.mem.Allocator, path: []const u8, directory: bool) !Pinned {
    if (!absolutePath(path)) return error.InvalidRuntimePath;
    var parent: usize = 1;
    while (std.mem.indexOfScalarPos(u8, path, parent, '/')) |end| {
        const prefix = try allocator.dupeZ(u8, path[0..end]);
        defer allocator.free(prefix);
        const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .DIRECTORY = true };
        const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)) };
        const fd: i32 = @intCast(try syscall(linux.syscall4(
            .openat2,
            @bitCast(@as(isize, linux.AT.FDCWD)),
            @intFromPtr(prefix.ptr),
            @intFromPtr(&how),
            @sizeOf(OpenHow),
        )));
        defer _ = linux.close(fd);
        if (!protectedMetadata(try stat(fd), true)) return error.UnprotectedRuntimeInput;
        parent = end + 1;
    }
    const name = try allocator.dupeZ(u8, path);
    defer allocator.free(name);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .DIRECTORY = directory };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)) };
    const fd: i32 = @intCast(try syscall(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(name.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    errdefer _ = linux.close(fd);
    const info = try stat(fd);
    if (!protectedMetadata(info, directory) or (!directory and info.nlink != 1))
        return error.UnprotectedRuntimeInput;
    return .{ .fd = fd, .metadata = info };
}

pub fn readPinned(allocator: std.mem.Allocator, pinned: Pinned, maximum: usize) ![]u8 {
    if (pinned.metadata.size > maximum) return error.RuntimeInputTooLarge;
    const bytes = try allocator.alloc(u8, @intCast(pinned.metadata.size));
    errdefer allocator.free(bytes);
    var count: usize = 0;
    while (count < bytes.len) {
        const got = try syscall(linux.pread(pinned.fd, bytes[count..].ptr, bytes.len - count, @intCast(count)));
        if (got == 0) return error.RuntimeSourceChanged;
        count += got;
    }
    if (!same(pinned.metadata, try stat(pinned.fd))) return error.RuntimeSourceChanged;
    return bytes;
}

fn readProtected(allocator: std.mem.Allocator, path: []const u8, maximum: usize) ![]u8 {
    const pinned = try openProtected(allocator, path, false);
    defer _ = linux.close(pinned.fd);
    return readPinned(allocator, pinned, maximum);
}

fn digest(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return allocator.dupe(u8, &std.fmt.bytesToHex(hash, .lower));
}

fn writeNew(allocator: std.mem.Allocator, directory: i32, name: []const u8, bytes: []const u8) !void {
    if (!libraryName(name)) return error.InvalidRuntimePath;
    const path = try allocator.dupeZ(u8, name);
    defer allocator.free(path);
    const fd: i32 = @intCast(try syscall(linux.openat(
        directory,
        path.ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true },
        0o500,
    )));
    defer _ = linux.close(fd);
    var count: usize = 0;
    while (count < bytes.len) {
        const written = try syscall(linux.write(fd, bytes[count..].ptr, bytes.len - count));
        if (written == 0) return error.RuntimeWriteFailed;
        count += written;
    }
    _ = try syscall(linux.fsync(fd));
}

pub const Bound = struct {
    allocator: std.mem.Allocator,
    prefix: []const u8,
    root: []const u8,
    parsed: ?std.json.Parsed(Manifest) = null,
    objects: std.ArrayList(Object) = .empty,
    inputs: std.ArrayList(Pinned) = .empty,
    root_files: std.ArrayList(Pinned) = .empty,
    aliases: std.ArrayList(Pinned) = .empty,
    /// Signed guest helper/interpreter/loader/provider bindings recorded beside
    /// binding.json; the launcher binds and verifies them in the guest root.
    guest_source: []const u8 = "",

    pub fn deinit(self: *Bound) void {
        for (self.inputs.items) |input| _ = linux.close(input.fd);
        for (self.root_files.items) |input| _ = linux.close(input.fd);
        for (self.aliases.items) |input| _ = linux.close(input.fd);
        for (self.objects.items) |object| self.allocator.free(object.bytes);
        self.inputs.deinit(self.allocator);
        self.root_files.deinit(self.allocator);
        self.aliases.deinit(self.allocator);
        self.objects.deinit(self.allocator);
        if (self.guest_source.len != 0) self.allocator.free(self.guest_source);
        if (self.parsed) |*value| value.deinit();
    }

    pub fn manifest(self: *const Bound) Manifest {
        return self.parsed.?.value;
    }

    fn readInput(self: *Bound, path: []const u8, maximum: usize) ![]const u8 {
        const pinned = try openProtected(self.allocator, path, false);
        errdefer _ = linux.close(pinned.fd);
        const bytes = try readPinned(self.allocator, pinned, maximum);
        errdefer self.allocator.free(bytes);
        try self.inputs.append(self.allocator, pinned);
        return bytes;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        prefix: []const u8,
        root: []const u8,
        architecture: []const u8,
        dpkg_digest: []const u8,
    ) !Bound {
        var result: Bound = .{ .allocator = allocator, .prefix = prefix, .root = root };
        errdefer result.deinit();
        const directory = try openProtected(allocator, prefix, true);
        result.inputs.append(allocator, directory) catch |err| {
            _ = linux.close(directory.fd);
            return err;
        };
        const path = try std.fmt.allocPrint(allocator, "{s}/binding.json", .{prefix});
        defer allocator.free(path);
        const source = try result.readInput(path, 128 * 1024);
        defer allocator.free(source);
        result.parsed = try std.json.parseFromSlice(Manifest, allocator, source, .{ .allocate = .alloc_always });
        const guest_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, guest.manifest_name });
        defer allocator.free(guest_path);
        result.guest_source = try result.readInput(guest_path, guest.maximum_manifest_bytes);
        const record = result.manifest();
        if (!std.mem.eql(u8, record.schema, schema_id) or record.version != 1 or
            !std.mem.eql(u8, record.architecture, architecture) or
            !hexadecimal(record.lock_sha256, 64) or
            record.objects.len < 2 or record.objects.len > 64 or record.links.len > 64)
            return error.InvalidRuntimeBinding;
        for (record.objects, 0..) |binding, index| {
            if (!libraryName(binding.name) or !hexadecimal(binding.sha256, 64) or
                binding.size == 0 or binding.size > maximum_object_bytes or
                binding.mode & ~@as(u32, 0o755) != 0)
                return error.InvalidRuntimeBinding;
            for (record.objects[0..index]) |previous| {
                if (std.mem.eql(u8, binding.name, previous.name)) return error.DuplicateRuntimeObject;
            }
            if (index == 0) {
                if (!std.mem.eql(u8, binding.name, "dpkg") or binding.root_path != null or
                    binding.package != null or binding.version != null or binding.archive_sha512 != null or
                    !std.mem.eql(u8, binding.sha256, dpkg_digest))
                    return error.UnboundRuntimeExecutable;
            } else {
                const package = for (runtime_libraries) |library| {
                    if (std.mem.eql(u8, binding.name, library.name)) break library.package;
                } else return error.UnreviewedRuntimeLibrary;
                const triplet = if (std.mem.eql(u8, architecture, "amd64"))
                    "/usr/lib/x86_64-linux-gnu/"
                else
                    "/usr/lib/aarch64-linux-gnu/";
                const member = binding.root_path orelse return error.InvalidRuntimeBinding;
                const source_package = binding.package orelse return error.InvalidRuntimeBinding;
                const source_version = binding.version orelse return error.InvalidRuntimeBinding;
                const archive_hash = binding.archive_sha512 orelse return error.InvalidRuntimeBinding;
                if (!absolutePath(member) or !std.mem.startsWith(u8, member, triplet) or
                    !std.mem.eql(u8, source_package, package) or source_version.len == 0 or
                    !hexadecimal(archive_hash, 128))
                    return error.InvalidRuntimeBinding;
            }
            const filename = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, binding.name });
            defer allocator.free(filename);
            const bytes = try result.readInput(filename, maximum_object_bytes);
            errdefer allocator.free(bytes);
            try verifyBytes(allocator, bytes, binding);
            try result.objects.append(allocator, .{ .name = binding.name, .bytes = bytes });
        }
        try validateClosure(allocator, result.objects.items, architecture);
        const executable = try inspectElf(allocator, result.objects.items[0].bytes, architecture);
        defer executable.deinit(allocator);
        if (!std.mem.eql(u8, std.fs.path.basename(executable.interpreter.?), record.loader))
            return error.UnboundRuntimeInterpreter;
        try directoryContents(directory.fd, record.objects);
        for (record.objects[1..]) |binding| {
            const filename = try std.fmt.allocPrint(allocator, "{s}{s}", .{ root, binding.root_path.? });
            defer allocator.free(filename);
            const pinned = try openProtected(allocator, filename, false);
            errdefer _ = linux.close(pinned.fd);
            const bytes = try readPinned(allocator, pinned, maximum_object_bytes);
            defer allocator.free(bytes);
            try verifyBytes(allocator, bytes, binding);
            if (pinned.metadata.mode & 0o7777 != binding.mode) return error.RuntimeMetadataChanged;
            try result.root_files.append(allocator, pinned);
        }
        for (record.links, 0..) |link, index| {
            if (!absolutePath(link.path) or link.target.len == 0 or link.target.len > 4096)
                return error.InvalidRuntimeBinding;
            for (record.links[0..index]) |previous| {
                if (std.mem.eql(u8, link.path, previous.path)) return error.AmbiguousRuntimeLink;
            }
            const pinned = try result.openAlias(root, link);
            errdefer _ = linux.close(pinned.fd);
            try result.aliases.append(allocator, pinned);
        }
        return result;
    }

    fn openAlias(self: *const Bound, root: []const u8, link: Link) !Pinned {
        const dirname = std.fs.path.dirname(link.path).?;
        const parent_path = if (root.len != 0 and std.mem.eql(u8, dirname, "/"))
            try self.allocator.dupe(u8, root)
        else
            try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ root, dirname });
        defer self.allocator.free(parent_path);
        const parent = try openProtected(self.allocator, parent_path, true);
        defer _ = linux.close(parent.fd);
        const name = try self.allocator.dupeZ(u8, std.fs.path.basename(link.path));
        defer self.allocator.free(name);
        const fd: i32 = @intCast(try syscall(linux.openat(
            parent.fd,
            name.ptr,
            .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        )));
        errdefer _ = linux.close(fd);
        const info = try stat(fd);
        if (info.mode & 0o170000 != 0o120000 or info.uid != 0 or info.gid != 0 or info.nlink != 1)
            return error.RuntimeAliasChanged;
        var target: [4097]u8 = undefined;
        const length = try syscall(linux.readlinkat(fd, "", &target, target.len));
        if (!std.mem.eql(u8, target[0..length], link.target)) return error.RuntimeAliasChanged;
        if (!same(info, try stat(fd))) return error.RuntimeSourceChanged;
        return .{ .fd = fd, .metadata = info };
    }

    pub fn verify(self: *const Bound, guest_root: []const u8) !void {
        for (self.inputs.items) |input| {
            if (!same(input.metadata, try stat(input.fd))) return error.RuntimeSourceChanged;
        }
        if (guest_root.len != 0) {
            const current = try openProtected(self.allocator, self.prefix, true);
            defer _ = linux.close(current.fd);
            if (!same(self.inputs.items[0].metadata, current.metadata)) return error.RuntimeSourceChanged;
        }
        for (self.manifest().objects[1..], self.root_files.items) |binding, previous| {
            const filename = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ guest_root, binding.root_path.? });
            defer self.allocator.free(filename);
            const current = try openProtected(self.allocator, filename, false);
            defer _ = linux.close(current.fd);
            if (!same(previous.metadata, try stat(previous.fd)) or !same(previous.metadata, current.metadata))
                return error.RuntimeSourceChanged;
        }
        for (self.manifest().links, self.aliases.items) |link, previous| {
            const current = try self.openAlias(guest_root, link);
            defer _ = linux.close(current.fd);
            if (!same(previous.metadata, try stat(previous.fd)) or !same(previous.metadata, current.metadata))
                return error.RuntimeAliasChanged;
        }
    }
};

fn hexadecimal(text: []const u8, size: usize) bool {
    if (text.len != size) return false;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

fn verifyBytes(allocator: std.mem.Allocator, bytes: []const u8, binding: Binding) !void {
    const actual = try digest(allocator, bytes);
    defer allocator.free(actual);
    if (bytes.len != binding.size or !std.mem.eql(u8, actual, binding.sha256)) {
        std.log.err("reference runtime object {s} changed", .{binding.name});
        return error.RuntimeDigestChanged;
    }
}

fn directoryContents(fd: i32, bindings: []const Binding) !void {
    var buffer: [8192]u8 align(8) = undefined;
    var count: usize = 0;
    while (true) {
        const size = try syscall(linux.getdents64(fd, &buffer, buffer.len));
        if (size == 0) break;
        var offset: usize = 0;
        while (offset < size) {
            if (size - offset < 20) return error.InvalidRuntimeDirectory;
            const length = std.mem.readInt(u16, buffer[offset + 16 ..][0..2], .little);
            if (length < 20 or length > size - offset) return error.InvalidRuntimeDirectory;
            const names = buffer[offset + 19 .. offset + length];
            const end = std.mem.indexOfScalar(u8, names, 0) orelse return error.InvalidRuntimeDirectory;
            const name = names[0..end];
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                if (!std.mem.eql(u8, name, "binding.json") and !std.mem.eql(u8, name, guest.manifest_name)) {
                    const found = for (bindings) |binding| {
                        if (std.mem.eql(u8, name, binding.name)) break true;
                    } else false;
                    if (!found) return error.UnboundRuntimeDirectoryEntry;
                }
                count += 1;
            }
            offset += length;
        }
    }
    if (count != bindings.len + 2) return error.MissingRuntimeObject;
}

pub fn populate(allocator: std.mem.Allocator, fd: i32, objects: []const Object) !void {
    for (objects) |object| try writeNew(allocator, fd, object.name, object.bytes);
    try writeNew(allocator, fd, "preload", "");
    const preload: i32 = @intCast(try syscall(linux.openat(fd, "preload", .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0)));
    defer _ = linux.close(preload);
    _ = try syscall(linux.fchmod(preload, 0o444));
}

const runtime_libraries = [_]struct { name: []const u8, package: []const u8 }{
    .{ .name = "libc.so.6", .package = "libc6" },
    .{ .name = "ld-linux-x86-64.so.2", .package = "libc6" },
    .{ .name = "ld-linux-aarch64.so.1", .package = "libc6" },
    .{ .name = "libmd.so.0", .package = "libmd0" },
    .{ .name = "libz.so.1", .package = "zlib1g" },
    .{ .name = "libbz2.so.1.0", .package = "libbz2-1.0" },
    .{ .name = "liblzma.so.5", .package = "liblzma5" },
    .{ .name = "libzstd.so.1", .package = "libzstd1" },
    .{ .name = "libselinux.so.1", .package = "libselinux1" },
    .{ .name = "libpcre2-8.so.0", .package = "libpcre2-8-0" },
};

const Recorder = struct {
    const debz = @import("debz");
    allocator: std.mem.Allocator,
    architecture: []const u8,
    lock: debz.exact_lock_v3.Lock,
    cache: []const u8,
    payloads: std.StringHashMap(debz.deb_payload.Validation),
    bindings: std.ArrayList(Binding) = .empty,
    objects: std.ArrayList(Object) = .empty,
    links: std.ArrayList(Link) = .empty,

    fn payload(self: *Recorder, name: []const u8) !*const debz.deb_payload.Validation {
        if (self.payloads.getPtr(name)) |found| return found;
        const package = self.lockPackage(name) orelse return error.MissingRuntimePackage;
        const origin = switch (package.origin) {
            .authenticated_repository => |value| value,
            .local_artifact => return error.UnsignedRuntimePackage,
        };
        const archive_hash = package.archive_identity.digests.sha512 orelse
            package.derived_sha512 orelse return error.UnboundRuntimeArchive;
        const path = try std.fmt.allocPrint(self.allocator, "{s}/packages-v2/objects/sha512-{s}", .{
            self.cache, std.fmt.bytesToHex(archive_hash, .lower),
        });
        const bytes = try readProtected(self.allocator, path, 32 * 1024 * 1024);
        try package.verifyArchive(bytes);
        const validation = switch (debz.deb_payload.validate(self.allocator, bytes, .{
            .repository = &origin.repository_id,
            .package = package.name,
            .version = package.version,
            .architecture = package.architecture,
            .requested_package = package.name,
            .filename = package.name,
            .size = package.declared_size,
            .archive_identity = package.archive_identity,
            .require_conventional_filename = false,
        }, .{
            .outer = .{ .max_archive_bytes = 32 * 1024 * 1024, .max_member_bytes = 32 * 1024 * 1024 },
            .max_data_compressed_bytes = 32 * 1024 * 1024,
            .max_data_decompressed_bytes = 128 * 1024 * 1024,
            .max_inventory_bytes_per_tar = 8 * 1024 * 1024,
        })) {
            .validation => |value| value,
            .diagnostic => |value| {
                std.log.err("reference runtime archive {s} refused: {s}/{s}", .{
                    name, @tagName(value.stage), @tagName(value.code),
                });
                return error.RuntimeArchiveRefused;
            },
        };
        try self.payloads.put(package.name, validation);
        return self.payloads.getPtr(package.name).?;
    }

    fn lockPackage(self: *const Recorder, name: []const u8) ?debz.exact_lock_v3.Package {
        return self.lock.findIdentity(name, self.architecture) orelse self.lock.findIdentity(name, "all");
    }

    fn link(self: *Recorder, path: []const u8, target: []const u8) !void {
        for (self.links.items) |previous| {
            if (!std.mem.eql(u8, previous.path, path)) continue;
            if (!std.mem.eql(u8, previous.target, target)) return error.AmbiguousRuntimeLink;
            return;
        }
        try self.links.append(self.allocator, .{ .path = path, .target = target });
    }

    fn sourceLink(self: *Recorder, package: []const u8, path: []const u8) !void {
        const data = try self.payload(package);
        const entry = for (data.data.entries) |candidate| {
            if (std.mem.eql(u8, candidate.path, path)) break candidate;
        } else return error.MissingRuntimeInterpreterAlias;
        if (entry.kind != .symlink or entry.uid != 0 or entry.gid != 0)
            return error.InvalidRuntimeInterpreterAlias;
        try self.link(try std.fmt.allocPrint(self.allocator, "/{s}", .{path}), entry.link_literal.?);
    }

    fn add(self: *Recorder, name: []const u8) !void {
        for (self.objects.items) |previous| {
            if (std.mem.eql(u8, previous.name, name)) return;
        }
        if (self.objects.items.len >= 64) return error.RuntimeClosureTooLarge;
        const package_name = for (runtime_libraries) |library| {
            if (std.mem.eql(u8, library.name, name)) break library.package;
        } else return error.UnreviewedRuntimeLibrary;
        const package = self.lock.findIdentity(package_name, self.architecture) orelse
            return error.MissingRuntimePackage;
        const data = try self.payload(package_name);
        const triplet = if (std.mem.eql(u8, self.architecture, "amd64"))
            "x86_64-linux-gnu"
        else
            "aarch64-linux-gnu";
        var path = try std.fmt.allocPrint(self.allocator, "usr/lib/{s}/{s}", .{ triplet, name });
        var depth: usize = 0;
        while (depth < 16) : (depth += 1) {
            const entry = for (data.data.entries) |candidate| {
                if (std.mem.eql(u8, candidate.path, path)) break candidate;
            } else return error.MissingRuntimeMember;
            if (entry.uid != 0 or entry.gid != 0 or
                (entry.kind != .symlink and entry.mode & 0o022 != 0))
                return error.UnprotectedRuntimeMember;
            if (entry.kind == .symlink) {
                try self.link(try std.fmt.allocPrint(self.allocator, "/{s}", .{path}), entry.link_literal.?);
                path = entry.link_target.?;
                continue;
            }
            if (entry.kind != .regular) return error.UnsupportedRuntimeMember;
            const bytes = try data.regularPayloadBytes(path, maximum_object_bytes);
            try self.objects.append(self.allocator, .{ .name = name, .bytes = bytes });
            try self.bindings.append(self.allocator, .{
                .name = name,
                .root_path = try std.fmt.allocPrint(self.allocator, "/{s}", .{path}),
                .sha256 = try digest(self.allocator, bytes),
                .size = bytes.len,
                .mode = entry.mode,
                .package = package_name,
                .version = package.version,
                .archive_sha512 = try self.allocator.dupe(u8, &std.fmt.bytesToHex(
                    package.archive_identity.digests.sha512 orelse package.derived_sha512.?,
                    .lower,
                )),
            });
            return;
        }
        return error.CyclicRuntimeLink;
    }
};

/// Libraries that guest helpers, interpreters, tools and late providers load,
/// each bound to the single signed package that ships it.
const guest_libraries = [_]struct { name: []const u8, package: []const u8 }{
    .{ .name = "libm.so.6", .package = "libc6" },
    .{ .name = "libresolv.so.2", .package = "libc6" },
    .{ .name = "libacl.so.1", .package = "libacl1" },
    .{ .name = "libattr.so.1", .package = "libattr1" },
    .{ .name = "libtinfo.so.6", .package = "libtinfo6" },
    .{ .name = "libcrypt.so.1", .package = "libcrypt1" },
    .{ .name = "libgcc_s.so.1", .package = "libgcc-s1" },
    .{ .name = "libcrypto.so.3", .package = "libssl3t64" },
    .{ .name = "libgmp.so.10", .package = "libgmp10" },
};

fn guestLibraryPackage(name: []const u8) ?[]const u8 {
    for (runtime_libraries) |library| {
        if (std.mem.eql(u8, library.name, name)) return library.package;
    }
    for (guest_libraries) |library| {
        if (std.mem.eql(u8, library.name, name)) return library.package;
    }
    return null;
}

/// Executables that the guest resolves by PATH or shebang; each is bound with
/// its complete ELF closure. Helpers are required in every reference root.
const guest_executables = [_]struct { package: []const u8, path: []const u8, role: guest.Role, required: bool }{
    .{ .package = "dpkg", .path = "usr/bin/dpkg-deb", .role = .helper, .required = true },
    .{ .package = "dpkg", .path = "usr/bin/dpkg-split", .role = .helper, .required = true },
    .{ .package = "tar", .path = "usr/bin/tar", .role = .helper, .required = true },
    .{ .package = "dash", .path = "usr/bin/sh", .role = .interpreter, .required = false },
    .{ .package = "bash", .path = "usr/bin/bash", .role = .interpreter, .required = false },
    .{ .package = "perl-base", .path = "usr/bin/perl", .role = .interpreter, .required = false },
    .{ .package = "libc-bin", .path = "usr/sbin/ldconfig", .role = .handler_tool, .required = false },
};

const GuestRecorder = struct {
    base: *Recorder,
    triplet: []const u8,
    interpreter: []const u8,
    /// The interpreter beneath its canonical /usr directory (no merged-usr alias).
    loader_path: []const u8,
    entries: std.ArrayList(guest.Entry) = .empty,
    sonames: std.ArrayList([]const u8) = .empty,
    visited: std.StringHashMap(bool),

    const Member = struct { identity: guest.Identity, bytes: ?[]const u8 = null };

    fn find(self: *const GuestRecorder, path: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (std.mem.eql(u8, entry.path, path)) return index;
        }
        return null;
    }

    fn sameIdentity(left: guest.Identity, right: guest.Identity) bool {
        return left.kind == right.kind and left.mode == right.mode and left.size == right.size and
            std.mem.eql(u8, left.sha256, right.sha256) and std.mem.eql(u8, left.target, right.target) and
            std.mem.eql(u8, left.package orelse "", right.package orelse "") and
            std.mem.eql(u8, left.member orelse "", right.member orelse "");
    }

    fn put(self: *GuestRecorder, path: []const u8, role: guest.Role, required: bool, identity: guest.Identity) !void {
        const allocator = self.base.allocator;
        if (!guest.canonicalPath(path)) {
            std.log.err("reference guest path {s} is not canonical", .{path});
            return error.InvalidGuestBinding;
        }
        if (self.find(path)) |index| {
            const entry = &self.entries.items[index];
            if (entry.role != role or entry.allowed.len == 0) return error.AmbiguousGuestBinding;
            entry.required = entry.required or required;
            for (entry.allowed) |previous| {
                if (sameIdentity(previous, identity)) return;
            }
            const allowed = try allocator.alloc(guest.Identity, entry.allowed.len + 1);
            @memcpy(allowed[0..entry.allowed.len], entry.allowed);
            allowed[entry.allowed.len] = identity;
            entry.allowed = allowed;
            return;
        }
        try self.entries.append(allocator, .{
            .path = path,
            .role = role,
            .required = required,
            .allowed = try allocator.dupe(guest.Identity, &.{identity}),
        });
    }

    /// A path that must stay absent unless another binding already owns it.
    fn absent(self: *GuestRecorder, path: []const u8, role: guest.Role) !void {
        if (self.find(path) != null) return;
        try self.entries.append(self.base.allocator, .{ .path = path, .role = role });
    }

    fn member(self: *GuestRecorder, package_name: []const u8, path: []const u8) !Member {
        const allocator = self.base.allocator;
        const data = try self.base.payload(package_name);
        const package = self.base.lockPackage(package_name) orelse return error.MissingRuntimePackage;
        const entry = payloadEntry(data, path) orelse {
            // Hermetic negative tests exercise this refusal; only production logs it.
            if (!builtin.is_test) std.log.err("reference guest member {s}:/{s} is missing", .{ package_name, path });
            return error.MissingGuestMember;
        };
        if (entry.uid != 0 or entry.gid != 0) return error.UnprotectedGuestMember;
        var result: Member = .{ .identity = .{
            .kind = .regular,
            .package = package.name,
            .version = package.version,
            .archive_sha512 = try allocator.dupe(u8, &std.fmt.bytesToHex(
                package.archive_identity.digests.sha512 orelse package.derived_sha512.?,
                .lower,
            )),
            .member = try std.fmt.allocPrint(allocator, "/{s}", .{path}),
        } };
        switch (entry.kind) {
            .regular, .hardlink => {
                const source = if (entry.kind == .hardlink) entry.link_target orelse return error.UnsupportedGuestMember else path;
                const primary = payloadEntry(data, source) orelse return error.MissingGuestMember;
                if (primary.kind != .regular) return error.UnsupportedGuestMember;
                const bytes = try data.regularPayloadBytes(source, guest.maximum_file_bytes);
                result.identity.mode = primary.mode & 0o7777;
                result.identity.size = bytes.len;
                result.identity.sha256 = try digest(allocator, bytes);
                result.bytes = bytes;
            },
            .symlink => {
                result.identity.kind = .symlink;
                result.identity.target = entry.link_literal.?;
            },
            .directory => {
                result.identity.kind = .directory;
                result.identity.mode = entry.mode & 0o7777;
            },
            .fifo => return error.UnsupportedGuestMember,
        }
        return result;
    }

    fn payloadEntry(data: *const Recorder.debz.deb_payload.Validation, path: []const u8) ?Recorder.debz.deb_payload.Entry {
        for (data.data.entries) |candidate| {
            if (std.mem.eql(u8, std.mem.trimEnd(u8, candidate.path, "/"), path)) return candidate;
        }
        return null;
    }

    /// Binds a member and follows its in-package symlink chain to the ELF
    /// file, then binds the loader and every NEEDED library recursively.
    fn chain(self: *GuestRecorder, packages: []const []const u8, start: []const u8, role: guest.Role, required: bool) anyerror!void {
        const allocator = self.base.allocator;
        var path = start;
        var depth: usize = 0;
        while (depth < 16) : (depth += 1) {
            if (self.visited.get(path)) |done| {
                if (done or !required) return;
            }
            try self.visited.put(path, required);
            const found = for (packages) |package_name| {
                const data = try self.base.payload(package_name);
                if (payloadEntry(data, path) != null) break try self.member(package_name, path);
            } else {
                std.log.err("reference guest member /{s} is missing", .{path});
                return error.MissingGuestMember;
            };
            const absolute = try std.fmt.allocPrint(allocator, "/{s}", .{path});
            try self.put(absolute, role, required, found.identity);
            switch (found.identity.kind) {
                .symlink => {
                    var buffer: [4096]u8 = undefined;
                    const resolved = try guest.resolveTarget(&buffer, absolute, found.identity.target);
                    path = try allocator.dupe(u8, resolved[1..]);
                },
                .regular => return self.closure(found.bytes.?, required),
                .directory => return error.UnsupportedGuestMember,
            }
        }
        return error.CyclicGuestLink;
    }

    fn closure(self: *GuestRecorder, bytes: []const u8, required: bool) anyerror!void {
        if (!std.mem.startsWith(u8, bytes, "\x7fELF")) return;
        const elf = try inspectElf(self.base.allocator, bytes, self.base.architecture);
        if (elf.interpreter) |interpreter| {
            if (!std.mem.eql(u8, interpreter, self.interpreter)) {
                std.log.err("reference guest interpreter {s} is unreviewed", .{interpreter});
                return error.UnreviewedGuestInterpreter;
            }
            try self.chain(&.{"libc6"}, self.loader_path, .loader, required);
        }
        for (elf.needed) |name| try self.library(name, required);
    }

    fn library(self: *GuestRecorder, name: []const u8, required: bool) anyerror!void {
        const allocator = self.base.allocator;
        const loader = std.mem.eql(u8, name, std.fs.path.basename(self.interpreter));
        const package_name = guestLibraryPackage(name) orelse {
            std.log.err("reference guest library {s} is unreviewed", .{name});
            return error.UnreviewedGuestLibrary;
        };
        for (self.sonames.items) |previous| {
            if (std.mem.eql(u8, previous, name)) break;
        } else try self.sonames.append(allocator, name);
        const path = try std.fmt.allocPrint(allocator, "usr/lib/{s}/{s}", .{ self.triplet, name });
        try self.chain(&.{package_name}, path, if (loader) .loader else .library, required);
    }

    /// Binds every member of `packages` at or beneath `directory`.
    fn tree(self: *GuestRecorder, packages: []const []const u8, directory: []const u8, role: guest.Role) !void {
        const allocator = self.base.allocator;
        for (packages) |package_name| {
            const data = try self.base.payload(package_name);
            for (data.data.entries) |entry| {
                const path = std.mem.trimEnd(u8, entry.path, "/");
                if (!std.mem.eql(u8, path, directory) and !(std.mem.startsWith(u8, path, directory) and
                    path.len > directory.len and path[directory.len] == '/'))
                    continue;
                const found = try self.member(package_name, path);
                try self.put(try std.fmt.allocPrint(allocator, "/{s}", .{path}), role, false, found.identity);
            }
        }
    }

    /// /etc/nsswitch.conf may only hold a signed provider copy of the bound lock:
    /// libc-bin's is always required; systemd's factory copy is bound exactly
    /// when the lock carries systemd (the protected runtime lock does not). A
    /// locked provider whose member is missing still refuses.
    fn nssConfig(self: *GuestRecorder) !void {
        for ([_]struct { package: []const u8, path: []const u8, required: bool }{
            .{ .package = "libc-bin", .path = "usr/share/libc-bin/nsswitch.conf", .required = true },
            .{ .package = "systemd", .path = "usr/share/factory/etc/nsswitch.conf", .required = false },
        }) |source| {
            if (!source.required and self.base.lockPackage(source.package) == null) continue;
            const found = try self.member(source.package, source.path);
            try self.put("/etc/nsswitch.conf", .nss_config, false, found.identity);
        }
    }
};

/// Derives the guest binding from the original signed lock archives (and the
/// hash-pinned Debian dpkg helpers staged beside the pinned dpkg).
fn recordGuest(recorder: *Recorder, dpkg_path: []const u8, lock_sha256: []const u8, interpreter: []const u8) ![]const u8 {
    const allocator = recorder.allocator;
    const architecture = recorder.architecture;
    const triplet = guest.triplet(architecture) orelse return error.UnsupportedRuntimeArchitecture;
    if (!std.mem.startsWith(u8, interpreter, "/lib/") and !std.mem.startsWith(u8, interpreter, "/lib64/"))
        return error.UnreviewedRuntimeInterpreter;
    var self: GuestRecorder = .{
        .base = recorder,
        .triplet = triplet,
        .interpreter = interpreter,
        .loader_path = try std.fmt.allocPrint(allocator, "usr{s}", .{interpreter}),
        .visited = std.StringHashMap(bool).init(allocator),
    };
    const amd64 = std.mem.eql(u8, architecture, "amd64");
    for ([_][]const u8{ "bin", "sbin", "lib", "lib64" }) |name| {
        if (!amd64 and std.mem.eql(u8, name, "lib64")) continue;
        const found = try self.member("base-files", name);
        try self.put(try std.fmt.allocPrint(allocator, "/{s}", .{name}), .alias, true, found.identity);
    }
    try self.chain(&.{"libc6"}, self.loader_path, .loader, true);
    const pinned = std.fs.path.dirname(dpkg_path) orelse return error.InvalidRuntimePath;
    for ([_][]const u8{ "dpkg-deb", "dpkg-split" }) |helper| {
        const bytes = try readProtected(
            allocator,
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ pinned, helper }),
            maximum_object_bytes,
        );
        try self.put(try std.fmt.allocPrint(allocator, "/usr/bin/{s}", .{helper}), .helper, true, .{
            .kind = .regular,
            .mode = 0o755,
            .size = bytes.len,
            .sha256 = try digest(allocator, bytes),
        });
        try self.closure(bytes, true);
    }
    for (guest_executables) |executable| {
        try self.chain(&.{executable.package}, executable.path, executable.role, executable.required);
    }
    // dpkg removes control extraction directories with rm: the coreutils-from-gnu
    // alias in reference roots, or the GNU rm bytes staged in proof templates.
    const gnurm = try self.member("gnu-coreutils", "usr/bin/gnurm");
    try self.put("/usr/bin/rm", .helper, true, gnurm.identity);
    try self.closure(gnurm.bytes.?, true);
    try self.put("/usr/bin/rm", .helper, true, (try self.member("coreutils-from-gnu", "usr/bin/rm")).identity);
    try self.chain(&.{"gnu-coreutils"}, "usr/bin/gnurm", .helper, false);
    for ((try recorder.payload("dpkg")).data.entries) |entry| {
        const path = std.mem.trimEnd(u8, entry.path, "/");
        if (entry.kind == .directory or !(std.mem.startsWith(u8, path, "usr/bin/") or std.mem.startsWith(u8, path, "usr/sbin/")) or
            self.visited.contains(path))
            continue;
        try self.chain(&.{"dpkg"}, path, .handler_tool, false);
    }
    // Late NSS: configuration, every libc6 provider, and loader-cache search.
    try self.nssConfig();
    const library_directory = try std.fmt.allocPrint(allocator, "usr/lib/{s}", .{triplet});
    for ((try recorder.payload("libc6")).data.entries) |entry| {
        const path = std.mem.trimEnd(u8, entry.path, "/");
        if (!std.mem.startsWith(u8, path, library_directory) or path.len <= library_directory.len + 1 or
            path[library_directory.len] != '/' or !std.mem.startsWith(u8, path[library_directory.len + 1 ..], "libnss_"))
            continue;
        const name = path[library_directory.len + 1 ..];
        if (std.mem.indexOfScalar(u8, name, '/') != null) continue;
        try self.sonames.append(allocator, name);
        try self.chain(&.{"libc6"}, path, .nss_provider, false);
    }
    // Late gconv modules, configuration and cache, all from signed members.
    const gconv = try std.fmt.allocPrint(allocator, "{s}/gconv", .{library_directory});
    try self.tree(&.{ "libc6", "libc-gconv-modules-extra" }, gconv, .gconv);
    // dpkg and loader configuration.
    for ([_][3][]const u8{
        .{ "dpkg", "etc/dpkg/dpkg.cfg", "dpkg_config" },
        .{ "dpkg", "etc/dpkg/dpkg.cfg.d", "dpkg_config" },
        .{ "libc-bin", "etc/ld.so.conf", "loader_config" },
        .{ "libc-bin", "etc/ld.so.conf.d", "loader_config" },
        .{ "libc6", "etc/ld.so.conf.d", "loader_config" },
        .{ "libc-bin", "etc/ld.so.conf.d/libc.conf", "loader_config" },
    }) |source| {
        const found = try self.member(source[0], source[1]);
        try self.put(
            try std.fmt.allocPrint(allocator, "/{s}", .{source[1]}),
            std.meta.stringToEnum(guest.Role, source[2]).?,
            false,
            found.identity,
        );
    }
    const multiarch = try std.fmt.allocPrint(allocator, "etc/ld.so.conf.d/{s}.conf", .{triplet});
    try self.put(try std.fmt.allocPrint(allocator, "/{s}", .{multiarch}), .loader_config, false, (try self.member("libc6", multiarch)).identity);
    // Required absences: HOME configuration, PATH shadows ahead of /usr/bin,
    // signature hooks, hwcaps subdirectories and loader search shadows.
    try self.absent("/.dpkg.cfg", .dpkg_config);
    try self.absent("/usr/bin/debsig-verify", .shadow);
    try self.absent("/usr/sbin/debsig-verify", .shadow);
    const bound_count = self.entries.items.len;
    for (self.entries.items[0..bound_count]) |entry| {
        if (!std.mem.startsWith(u8, entry.path, "/usr/bin/") or entry.allowed.len == 0) continue;
        const shadow = try std.fmt.allocPrint(allocator, "/usr/sbin/{s}", .{entry.path["/usr/bin/".len..]});
        if (guest.canonicalPath(shadow)) try self.absent(shadow, .shadow);
    }
    try self.absent(try std.fmt.allocPrint(allocator, "/{s}/glibc-hwcaps", .{library_directory}), .hwcaps);
    try self.absent("/usr/lib/glibc-hwcaps", .hwcaps);
    for (self.sonames.items) |name| {
        try self.absent(try std.fmt.allocPrint(allocator, "/usr/lib/{s}", .{name}), .shadow);
        if (amd64) try self.absent(try std.fmt.allocPrint(allocator, "/usr/lib64/{s}", .{name}), .shadow);
    }
    const absolute_directory = try std.fmt.allocPrint(allocator, "/{s}", .{library_directory});
    const manifest: guest.Manifest = .{
        .architecture = architecture,
        .lock_sha256 = lock_sha256,
        .library_directory = absolute_directory,
        .sonames = self.sonames.items,
        .cache_prefixes = &.{"libnss_"},
        .scopes = &.{
            .{ .directory = try std.fmt.allocPrint(allocator, "/{s}", .{gconv}), .prefix = "" },
            .{ .directory = try std.fmt.allocPrint(allocator, "/{s}/gconv-modules.d", .{gconv}), .prefix = "" },
            .{ .directory = "/etc/dpkg/dpkg.cfg.d", .prefix = "" },
            .{ .directory = "/etc/ld.so.conf.d", .prefix = "", .suffix = ".conf" },
            .{ .directory = absolute_directory, .prefix = "libnss_" },
            .{ .directory = "/usr/lib", .prefix = "libnss_" },
        },
        .entries = self.entries.items,
    };
    try guest.validate(allocator, manifest, architecture, lock_sha256);
    return std.json.Stringify.valueAlloc(allocator, manifest, .{ .whitespace = .indent_2 });
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const command = args.next() orelse return error.InvalidRuntimeArguments;
    if (std.mem.eql(u8, command, "prove-postbinding")) {
        const architecture = args.next() orelse return error.InvalidRuntimeArguments;
        const prefix = args.next() orelse return error.InvalidRuntimeArguments;
        const root = args.next() orelse return error.InvalidRuntimeArguments;
        const dpkg_hash = args.next() orelse return error.InvalidRuntimeArguments;
        const member = args.next() orelse return error.InvalidRuntimeArguments;
        if (args.next() != null or linux.getuid() != 0 or linux.getgid() != 0)
            return error.InvalidRuntimeArguments;
        var bound = try Bound.init(allocator, prefix, root, architecture, dpkg_hash);
        defer bound.deinit();
        const index = for (bound.manifest().objects, 0..) |binding, index| {
            if (binding.root_path != null and std.mem.eql(u8, binding.name, member)) break index;
        } else return error.InvalidRuntimeArguments;
        const path = try std.fmt.allocPrintSentinel(
            allocator,
            "{s}{s}",
            .{ root, bound.manifest().objects[index].root_path.? },
            0,
        );
        const fd: i32 = @intCast(try syscall(linux.open(path, .{
            .ACCMODE = .RDWR,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, 0)));
        defer _ = linux.close(fd);
        if (!same(bound.root_files.items[index - 1].metadata, try stat(fd)))
            return error.RuntimeSourceChanged;
        var byte: [1]u8 = undefined;
        if (try syscall(linux.pread(fd, &byte, 1, 0)) != 1) return error.RuntimeSourceChanged;
        byte[0] ^= 1;
        if (try syscall(linux.pwrite(fd, &byte, 1, 0)) != 1) return error.RuntimeWriteFailed;
        _ = try syscall(linux.fsync(fd));
        bound.verify(root) catch |err| {
            if (err != error.RuntimeSourceChanged) return err;
            std.log.info("reference runtime post-binding {s}: RuntimeSourceChanged; no dpkg or script executed", .{member});
            return;
        };
        return error.RuntimeDriftNotDetected;
    }
    if (std.mem.eql(u8, command, "prove-guest-postbinding")) {
        const architecture = args.next() orelse return error.InvalidRuntimeArguments;
        const prefix = args.next() orelse return error.InvalidRuntimeArguments;
        const root = args.next() orelse return error.InvalidRuntimeArguments;
        const dpkg_hash = args.next() orelse return error.InvalidRuntimeArguments;
        const path = args.next() orelse return error.InvalidRuntimeArguments;
        if (args.next() != null or linux.getuid() != 0 or linux.getgid() != 0 or !guest.canonicalPath(path))
            return error.InvalidRuntimeArguments;
        var bound = try Bound.init(allocator, prefix, root, architecture, dpkg_hash);
        defer bound.deinit();
        var guest_bound = try guest.Bound.init(allocator, bound.guest_source, root, architecture, bound.manifest().lock_sha256);
        defer guest_bound.deinit();
        const filename = try std.fmt.allocPrintSentinel(allocator, "{s}{s}", .{ root, path }, 0);
        const fd: i32 = @intCast(try syscall(linux.open(filename, .{
            .ACCMODE = .RDWR,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, 0)));
        defer _ = linux.close(fd);
        var byte: [1]u8 = undefined;
        if (try syscall(linux.pread(fd, &byte, 1, 0)) != 1) return error.GuestSourceChanged;
        byte[0] ^= 1;
        if (try syscall(linux.pwrite(fd, &byte, 1, 0)) != 1) return error.RuntimeWriteFailed;
        _ = try syscall(linux.fsync(fd));
        guest_bound.verify(root) catch |err| {
            if (err != error.GuestSourceChanged) return err;
            std.log.info("reference guest post-binding {s}: GuestSourceChanged; no dpkg or script executed", .{path});
            return;
        };
        return error.GuestDriftNotDetected;
    }
    if (!std.mem.eql(u8, command, "record")) return error.InvalidRuntimeArguments;
    const architecture = args.next() orelse return error.InvalidRuntimeArguments;
    const lock_path = args.next() orelse return error.InvalidRuntimeArguments;
    const cache = args.next() orelse return error.InvalidRuntimeArguments;
    const dpkg_path = args.next() orelse return error.InvalidRuntimeArguments;
    const output = args.next() orelse return error.InvalidRuntimeArguments;
    if (args.next() != null or linux.getuid() != 0 or linux.getgid() != 0)
        return error.InvalidRuntimeArguments;
    if (!std.mem.eql(u8, architecture, "amd64") and !std.mem.eql(u8, architecture, "arm64"))
        return error.UnsupportedRuntimeArchitecture;
    const lock_bytes = try readProtected(allocator, lock_path, 16 * 1024 * 1024);
    const debz = @import("debz");
    var decoded = try debz.exact_lock_v3.decode(allocator, lock_bytes, 16 * 1024 * 1024);
    defer decoded.deinit();
    if (!std.mem.eql(u8, decoded.lock.target_architecture, architecture))
        return error.RuntimeArchitectureMismatch;
    try decoded.lock.requireArchiveDigestPolicy(.sha512_identity_required);
    const dpkg_bytes = try readProtected(allocator, dpkg_path, maximum_object_bytes);
    var recorder: Recorder = .{
        .allocator = allocator,
        .architecture = architecture,
        .lock = decoded.lock,
        .cache = cache,
        .payloads = std.StringHashMap(debz.deb_payload.Validation).init(allocator),
    };
    try recorder.objects.append(allocator, .{ .name = "dpkg", .bytes = dpkg_bytes });
    try recorder.bindings.append(allocator, .{
        .name = "dpkg",
        .root_path = null,
        .sha256 = try digest(allocator, dpkg_bytes),
        .size = dpkg_bytes.len,
        .mode = 0o755,
        .package = null,
        .version = null,
        .archive_sha512 = null,
    });
    const executable = try inspectElf(allocator, dpkg_bytes, architecture);
    const interpreter = executable.interpreter orelse return error.MissingRuntimeInterpreter;
    const loader_name = std.fs.path.basename(interpreter);
    const lock_sha256 = try digest(allocator, lock_bytes);
    try recorder.add(loader_name);
    try recorder.link("/lib", "usr/lib");
    if (std.mem.eql(u8, architecture, "amd64")) {
        if (!std.mem.eql(u8, interpreter, "/lib64/ld-linux-x86-64.so.2"))
            return error.UnreviewedRuntimeInterpreter;
        try recorder.link("/lib64", "usr/lib64");
        try recorder.sourceLink("libc6", "usr/lib64/ld-linux-x86-64.so.2");
    } else {
        if (!std.mem.eql(u8, interpreter, "/lib/ld-linux-aarch64.so.1"))
            return error.UnreviewedRuntimeInterpreter;
        try recorder.sourceLink("libc6", "usr/lib/ld-linux-aarch64.so.1");
    }
    var cursor: usize = 0;
    while (cursor < recorder.objects.items.len) : (cursor += 1) {
        const elf = try inspectElf(allocator, recorder.objects.items[cursor].bytes, architecture);
        for (elf.needed) |name| try recorder.add(name);
    }
    try validateClosure(allocator, recorder.objects.items, architecture);
    const guest_json = try recordGuest(&recorder, dpkg_path, lock_sha256, interpreter);
    const manifest: Manifest = .{
        .architecture = architecture,
        .lock_sha256 = lock_sha256,
        .loader = loader_name,
        .objects = recorder.bindings.items,
        .links = recorder.links.items,
    };
    const json = try std.json.Stringify.valueAlloc(allocator, manifest, .{ .whitespace = .indent_2 });
    const parent = try openProtected(allocator, std.fs.path.dirname(output) orelse return error.InvalidRuntimePath, true);
    defer _ = linux.close(parent.fd);
    const basename = std.fs.path.basename(output);
    if (!libraryName(basename)) return error.InvalidRuntimePath;
    const output_name = try allocator.dupeZ(u8, basename);
    _ = try syscall(linux.mkdirat(parent.fd, output_name.ptr, 0o700));
    const directory = try openProtected(allocator, output, true);
    defer _ = linux.close(directory.fd);
    for (recorder.objects.items) |object| try writeNew(allocator, directory.fd, object.name, object.bytes);
    try writeNew(allocator, directory.fd, "binding.json", json);
    try writeNew(allocator, directory.fd, guest.manifest_name, guest_json);
    _ = try syscall(linux.fsync(directory.fd));
}

pub const Elf = struct {
    interpreter: ?[]const u8,
    needed: []const []const u8,

    pub fn deinit(self: Elf, allocator: std.mem.Allocator) void {
        allocator.free(self.needed);
    }
};

const Segment = struct {
    offset: usize,
    address: u64,
    size: usize,
};

fn region(bytes: []const u8, offset: usize, size: usize) ![]const u8 {
    const end = std.math.add(usize, offset, size) catch return error.InvalidRuntimeElf;
    if (end > bytes.len) return error.InvalidRuntimeElf;
    return bytes[offset..end];
}

fn integer(comptime T: type, bytes: []const u8, offset: usize) !T {
    const value = try region(bytes, offset, @sizeOf(T));
    return std.mem.readInt(T, value[0..@sizeOf(T)], .little);
}

fn offsetValue(value: u64) !usize {
    return std.math.cast(usize, value) orelse error.InvalidRuntimeElf;
}

fn libraryName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128 or name[0] == '.') return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and byte != '_' and byte != '-' and byte != '+') return false;
    }
    return true;
}

fn interpreterPath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |part| {
        if (!libraryName(part)) return false;
    }
    return true;
}

fn absolutePath(path: []const u8) bool {
    if (std.mem.eql(u8, path, "/")) return true;
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
        for (part) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and
                byte != '.' and byte != '_' and byte != '-' and byte != '+') return false;
        }
    }
    return true;
}

fn stringAt(table: []const u8, offset: u64) ![]const u8 {
    const start = try offsetValue(offset);
    if (start >= table.len) return error.InvalidRuntimeElf;
    const end = std.mem.indexOfScalarPos(u8, table, start, 0) orelse
        return error.InvalidRuntimeElf;
    return table[start..end];
}

pub fn inspectElf(allocator: std.mem.Allocator, bytes: []const u8, architecture: []const u8) !Elf {
    const machine: u16 = if (std.mem.eql(u8, architecture, "amd64"))
        62
    else if (std.mem.eql(u8, architecture, "arm64"))
        183
    else
        return error.UnsupportedRuntimeArchitecture;
    if (bytes.len < 64 or !std.mem.eql(u8, bytes[0..7], "\x7fELF\x02\x01\x01") or
        (try integer(u16, bytes, 16) != 2 and try integer(u16, bytes, 16) != 3) or
        try integer(u16, bytes, 18) != machine or try integer(u32, bytes, 20) != 1 or
        try integer(u16, bytes, 52) != 64 or try integer(u16, bytes, 54) != 56)
        return error.InvalidRuntimeElf;
    const program_offset = try offsetValue(try integer(u64, bytes, 32));
    const count = try integer(u16, bytes, 56);
    if (count == 0 or count > 128) return error.InvalidRuntimeElf;
    _ = try region(bytes, program_offset, @as(usize, count) * 56);

    var loads: [128]Segment = undefined;
    var load_count: usize = 0;
    var dynamic: ?[]const u8 = null;
    var dynamic_segment: ?Segment = null;
    var interpreter: ?[]const u8 = null;
    for (0..count) |index| {
        const header = program_offset + index * 56;
        const kind = try integer(u32, bytes, header);
        const offset = try offsetValue(try integer(u64, bytes, header + 8));
        const address = try integer(u64, bytes, header + 16);
        const size = try offsetValue(try integer(u64, bytes, header + 32));
        const memory_size = try integer(u64, bytes, header + 40);
        if (size > memory_size) return error.InvalidRuntimeElf;
        const data = try region(bytes, offset, size);
        _ = std.math.add(u64, address, memory_size) catch return error.InvalidRuntimeElf;
        switch (kind) {
            1 => {
                loads[load_count] = .{ .offset = offset, .address = address, .size = size };
                load_count += 1;
            },
            2 => {
                if (dynamic != null or size == 0 or size % 16 != 0)
                    return error.InvalidRuntimeElf;
                dynamic = data;
                dynamic_segment = .{ .offset = offset, .address = address, .size = size };
            },
            3 => {
                if (interpreter != null or data.len < 2 or data.len > 4096 or
                    data[data.len - 1] != 0 or std.mem.indexOfScalar(u8, data[0 .. data.len - 1], 0) != null)
                    return error.InvalidRuntimeElf;
                interpreter = data[0 .. data.len - 1];
                if (!interpreterPath(interpreter.?)) return error.InvalidRuntimeElf;
            },
            else => {},
        }
    }
    if (load_count == 0) return error.InvalidRuntimeElf;
    var names: std.ArrayList([]const u8) = .empty;
    errdefer names.deinit(allocator);
    if (dynamic) |entries| {
        const selected = dynamic_segment.?;
        var mapped = false;
        for (loads[0..load_count]) |load| {
            if (selected.address < load.address) continue;
            const delta = try offsetValue(selected.address - load.address);
            if (delta > load.size or selected.size > load.size - delta) continue;
            if (mapped or load.offset + delta != selected.offset) return error.InvalidRuntimeElf;
            mapped = true;
        }
        if (!mapped) return error.InvalidRuntimeElf;
        var strings_address: ?u64 = null;
        var strings_size: ?usize = null;
        var needed: [64]u64 = undefined;
        var needed_count: usize = 0;
        var terminated = false;
        for (0..entries.len / 16) |index| {
            const tag = try integer(u64, entries, index * 16);
            const value = try integer(u64, entries, index * 16 + 8);
            if (terminated and (tag != 0 or value != 0)) return error.InvalidRuntimeElf;
            switch (tag) {
                0 => terminated = true,
                1 => {
                    if (needed_count == needed.len) return error.InvalidRuntimeElf;
                    needed[needed_count] = value;
                    needed_count += 1;
                },
                5 => {
                    if (strings_address != null) return error.InvalidRuntimeElf;
                    strings_address = value;
                },
                10 => {
                    if (strings_size != null) return error.InvalidRuntimeElf;
                    strings_size = try offsetValue(value);
                },
                // These tags can introduce runtime code outside the enumerated closure.
                15, 29, 0x6ffffefa, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff => return error.UnsupportedRuntimeSearch,
                else => {},
            }
        }
        if (!terminated or (strings_address == null) != (strings_size == null))
            return error.InvalidRuntimeElf;
        if (strings_address) |address| {
            const size = strings_size.?;
            if (size == 0 or size > 1024 * 1024) return error.InvalidRuntimeElf;
            var strings: ?[]const u8 = null;
            for (loads[0..load_count]) |load| {
                if (address < load.address) continue;
                const delta = try offsetValue(address - load.address);
                if (delta > load.size or size > load.size - delta) continue;
                if (strings != null) return error.InvalidRuntimeElf;
                strings = try region(bytes, load.offset + delta, size);
            }
            const table = strings orelse return error.InvalidRuntimeElf;
            for (needed[0..needed_count]) |offset| {
                const name = try stringAt(table, offset);
                if (!libraryName(name)) return error.InvalidRuntimeElf;
                for (names.items) |previous| {
                    if (std.mem.eql(u8, name, previous)) return error.InvalidRuntimeElf;
                }
                try names.append(allocator, name);
            }
        } else if (needed_count != 0) return error.InvalidRuntimeElf;
    }
    return .{ .interpreter = interpreter, .needed = try names.toOwnedSlice(allocator) };
}

pub const Object = struct {
    name: []const u8,
    bytes: []const u8,
};

fn objectIndex(objects: []const Object, name: []const u8) !usize {
    for (objects, 0..) |object, index| {
        if (std.mem.eql(u8, object.name, name)) return index;
    }
    return error.MissingRuntimeLibrary;
}

pub fn validateClosure(allocator: std.mem.Allocator, objects: []const Object, architecture: []const u8) !void {
    if (objects.len < 2 or objects.len > 64 or !std.mem.eql(u8, objects[0].name, "dpkg"))
        return error.InvalidRuntimeClosure;
    for (objects, 0..) |object, index| {
        if (!libraryName(object.name)) return error.InvalidRuntimeClosure;
        for (objects[0..index]) |previous| {
            if (std.mem.eql(u8, object.name, previous.name)) return error.InvalidRuntimeClosure;
        }
    }
    var visited: [64]bool = @splat(false);
    var pending: [64]usize = undefined;
    var count: usize = 1;
    var cursor: usize = 0;
    pending[0] = 0;
    visited[0] = true;
    while (cursor < count) : (cursor += 1) {
        const index = pending[cursor];
        const elf = try inspectElf(allocator, objects[index].bytes, architecture);
        defer elf.deinit(allocator);
        if (index == 0 and elf.interpreter == null) return error.MissingRuntimeInterpreter;
        if (elf.interpreter) |path| {
            const loader = try objectIndex(objects, std.fs.path.basename(path));
            if (!visited[loader]) {
                visited[loader] = true;
                pending[count] = loader;
                count += 1;
            }
            const loader_elf = try inspectElf(allocator, objects[loader].bytes, architecture);
            defer loader_elf.deinit(allocator);
            if (loader_elf.interpreter != null or loader_elf.needed.len != 0)
                return error.InvalidRuntimeInterpreter;
        }
        for (elf.needed) |name| {
            const dependency = try objectIndex(objects, name);
            if (!visited[dependency]) {
                visited[dependency] = true;
                pending[count] = dependency;
                count += 1;
            }
        }
    }
    if (count != objects.len) return error.UnreferencedRuntimeObject;
}

fn fixtureInteger(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

fn elfFixture() [512]u8 {
    var bytes: [512]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    fixtureInteger(u16, &bytes, 16, 3);
    fixtureInteger(u16, &bytes, 18, 62);
    fixtureInteger(u32, &bytes, 20, 1);
    fixtureInteger(u64, &bytes, 32, 64);
    fixtureInteger(u16, &bytes, 52, 64);
    fixtureInteger(u16, &bytes, 54, 56);
    fixtureInteger(u16, &bytes, 56, 2);
    fixtureInteger(u32, &bytes, 64, 1);
    fixtureInteger(u64, &bytes, 80, 0x400000);
    fixtureInteger(u64, &bytes, 96, bytes.len);
    fixtureInteger(u64, &bytes, 104, bytes.len);
    fixtureInteger(u32, &bytes, 120, 2);
    fixtureInteger(u64, &bytes, 128, 176);
    fixtureInteger(u64, &bytes, 136, 0x400000 + 176);
    fixtureInteger(u64, &bytes, 152, 80);
    fixtureInteger(u64, &bytes, 160, 80);
    const strings = "\x00libalpha.so.1\x00libbeta.so.2\x00";
    @memcpy(bytes[320..][0..strings.len], strings);
    fixtureInteger(u64, &bytes, 176, 5);
    fixtureInteger(u64, &bytes, 184, 0x400000 + 320);
    fixtureInteger(u64, &bytes, 192, 10);
    fixtureInteger(u64, &bytes, 200, strings.len);
    fixtureInteger(u64, &bytes, 208, 1);
    fixtureInteger(u64, &bytes, 216, 1);
    fixtureInteger(u64, &bytes, 224, 1);
    fixtureInteger(u64, &bytes, 232, 15);
    return bytes;
}

test "reference runtime ELF enumerates dependencies without executing code on either architecture" {
    var bytes = elfFixture();
    const x64 = try inspectElf(std.testing.allocator, &bytes, "amd64");
    defer x64.deinit(std.testing.allocator);
    try std.testing.expect(x64.interpreter == null);
    try std.testing.expectEqual(@as(usize, 2), x64.needed.len);
    try std.testing.expectEqualStrings("libalpha.so.1", x64.needed[0]);
    try std.testing.expectEqualStrings("libbeta.so.2", x64.needed[1]);
    fixtureInteger(u16, &bytes, 18, 183);
    const arm = try inspectElf(std.testing.allocator, &bytes, "arm64");
    defer arm.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(x64.needed[0], arm.needed[0]);
    try std.testing.expectError(error.InvalidRuntimeElf, inspectElf(std.testing.allocator, &bytes, "amd64"));
}

test "reference runtime ELF refuses malformed mappings and hidden runtime search" {
    for ([_]struct { offset: usize, value: u64, err: anyerror }{
        .{ .offset = 32, .value = std.math.maxInt(u64), .err = error.InvalidRuntimeElf },
        .{ .offset = 104, .value = 1, .err = error.InvalidRuntimeElf },
        .{ .offset = 136, .value = 0x400000 + 177, .err = error.InvalidRuntimeElf },
        .{ .offset = 184, .value = 0x500000, .err = error.InvalidRuntimeElf },
        .{ .offset = 200, .value = 512, .err = error.InvalidRuntimeElf },
        .{ .offset = 216, .value = 500, .err = error.InvalidRuntimeElf },
        .{ .offset = 232, .value = 1, .err = error.InvalidRuntimeElf },
        .{ .offset = 240, .value = 1, .err = error.InvalidRuntimeElf },
        .{ .offset = 224, .value = 29, .err = error.UnsupportedRuntimeSearch },
    }) |mutation| {
        var bytes = elfFixture();
        fixtureInteger(u64, &bytes, mutation.offset, mutation.value);
        try std.testing.expectError(mutation.err, inspectElf(std.testing.allocator, &bytes, "amd64"));
    }

    var bytes = elfFixture();
    bytes[321] = '/';
    try std.testing.expectError(error.InvalidRuntimeElf, inspectElf(std.testing.allocator, &bytes, "amd64"));
}

fn executableFixture() [512]u8 {
    var bytes = elfFixture();
    @memmove(bytes[232..312], bytes[176..256]);
    fixtureInteger(u16, &bytes, 56, 3);
    fixtureInteger(u64, &bytes, 128, 232);
    fixtureInteger(u64, &bytes, 136, 0x400000 + 232);
    @memset(bytes[176..232], 0);
    fixtureInteger(u32, &bytes, 176, 3);
    fixtureInteger(u64, &bytes, 184, 384);
    const path = "/lib64/ld-linux-x86-64.so.2\x00";
    fixtureInteger(u64, &bytes, 208, path.len);
    fixtureInteger(u64, &bytes, 216, path.len);
    @memcpy(bytes[384..][0..path.len], path);
    return bytes;
}

test "reference runtime ELF requires a single canonical terminated interpreter path" {
    var bytes = executableFixture();
    const path = "/lib64/ld-linux-x86-64.so.2\x00";
    const elf = try inspectElf(std.testing.allocator, &bytes, "amd64");
    defer elf.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(path[0 .. path.len - 1], elf.interpreter.?);
    bytes[384] = '.';
    try std.testing.expectError(error.InvalidRuntimeElf, inspectElf(std.testing.allocator, &bytes, "amd64"));
    bytes[384] = '/';
    bytes[384 + path.len - 1] = 'x';
    try std.testing.expectError(error.InvalidRuntimeElf, inspectElf(std.testing.allocator, &bytes, "amd64"));
}

test "reference runtime closure recursively refuses missing, unbound and architecture-swapped code" {
    const program = executableFixture();
    var loader = elfFixture();
    @memset(loader[208..256], 0);
    var alpha = elfFixture();
    fixtureInteger(u64, &alpha, 216, 15);
    @memset(alpha[224..256], 0);
    const beta = loader;
    var objects = [_]Object{
        .{ .name = "dpkg", .bytes = &program },
        .{ .name = "ld-linux-x86-64.so.2", .bytes = &loader },
        .{ .name = "libalpha.so.1", .bytes = &alpha },
        .{ .name = "libbeta.so.2", .bytes = &beta },
    };
    try validateClosure(std.testing.allocator, &objects, "amd64");
    try std.testing.expectError(error.MissingRuntimeLibrary, validateClosure(std.testing.allocator, objects[0..3], "amd64"));
    objects[3].name = "unbound.so";
    try std.testing.expectError(error.MissingRuntimeLibrary, validateClosure(std.testing.allocator, &objects, "amd64"));
    objects[3].name = "libbeta.so.2";
    fixtureInteger(u16, &loader, 18, 183);
    try std.testing.expectError(error.InvalidRuntimeElf, validateClosure(std.testing.allocator, &objects, "amd64"));
    fixtureInteger(u16, &loader, 18, 62);
    fixtureInteger(u64, &loader, 208, 1);
    fixtureInteger(u64, &loader, 216, 1);
    try std.testing.expectError(error.InvalidRuntimeInterpreter, validateClosure(std.testing.allocator, &objects, "amd64"));
}

/// Every package of the hosted protected runtime locks of run 38480672695
/// (staging/runtime.lock.json; amd64 sha256 38189ae3…ecfc, arm64 sha256
/// 52a74d64…7b1d) in lock order: 61 packages and no systemd. ":all" marks the
/// architecture-independent packages; the rest carry the target architecture.
const hosted_protected_runtime_lock = [_][]const u8{
    "base-files",             "base-passwd",              "bash",               "coreutils:all",
    "coreutils-from-gnu:all", "dash",                     "debconf:all",        "debianutils",
    "diffutils",              "dpkg",                     "findutils",          "gawk",
    "gcc-16-base",            "gnu-coreutils",            "grep",               "gzip",
    "hostname",               "init-system-helpers:all",  "libacl1",            "libattr1",
    "libaudit-common:all",    "libaudit1",                "libblkid1",          "libbz2-1.0",
    "libc-bin",               "libc-gconv-modules-extra", "libc6",              "libcap-ng0",
    "libcrypt1",              "libdb5.3t64",              "libdebconfclient0",  "libgcc-s1",
    "libgmp10",               "liblzma5",                 "libmd0",             "libmount1",
    "libmpfr6",               "libpam-modules",           "libpam-modules-bin", "libpam-runtime:all",
    "libpam0g",               "libpcre2-8-0",             "libreadline8t64",    "libselinux1",
    "libsmartcols1",          "libssl3t64",               "libsystemd0",        "libtinfo6",
    "libudev1",               "libuuid1",                 "libzstd1",           "ncurses-base:all",
    "ncurses-bin",            "openssl-provider-legacy",  "perl-base",          "readline-common:all",
    "sed",                    "sysvinit-utils",           "tar",                "util-linux",
    "zlib1g",
};

/// The hosted protected lock shape with `added` packages and without `removed`;
/// each archive identity is a fixture digest that only the lock carries.
fn fixtureLock(a: std.mem.Allocator, architecture: []const u8, added: []const []const u8, removed: ?[]const u8) !Recorder.debz.exact_lock_v3.Lock {
    const Package = Recorder.debz.exact_lock_v3.Package;
    var packages: std.ArrayList(Package) = .empty;
    for ([_][]const []const u8{ &hosted_protected_runtime_lock, added }) |items| {
        for (items) |item| {
            const all = std.mem.endsWith(u8, item, ":all");
            const name = if (all) item[0 .. item.len - ":all".len] else item;
            if (removed != null and std.mem.eql(u8, name, removed.?)) continue;
            var sha512: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash(item, &sha512, .{});
            try packages.append(a, .{
                .name = name,
                .version = "fixture",
                .architecture = if (all) "all" else architecture,
                .origin = .{ .authenticated_repository = .{ .repository_id = @splat('0'), .repository_snapshot_sha256 = @splat(0) } },
                .archive_identity = .{ .digests = .{ .sha512 = sha512 }, .primary = .sha512 },
                .declared_size = 1,
                .retention = .dependency,
                .dpkg_selection_hold = false,
            });
        }
    }
    std.mem.sort(Package, packages.items, {}, struct {
        fn less(_: void, left: Package, right: Package) bool {
            return switch (std.mem.order(u8, left.name, right.name)) {
                .eq => std.mem.order(u8, left.architecture, right.architecture) == .lt,
                else => |order| order == .lt,
            };
        }
    }.less);
    return .{
        .target_architecture = architecture,
        .request_sha256 = @splat(0),
        .policy_sha256 = @splat(0),
        .repositories = &.{},
        .local_artifacts = &.{},
        .packages = packages.items,
        .digest_sha256 = @splat(0),
    };
}

/// A validated payload reduced to one root-owned regular data member.
fn fixturePayload(a: std.mem.Allocator, path: []const u8, bytes: []const u8) !Recorder.debz.deb_payload.Validation {
    const entries = try a.alloc(Recorder.debz.deb_payload.Entry, 1);
    entries[0] = .{
        .path = try a.dupe(u8, path),
        .link_target = null,
        .link_literal = null,
        .kind = .regular,
        .mode = 0o644,
        .uid = 0,
        .gid = 0,
        .owner_name = "root",
        .group_name = "root",
        .mtime = 0,
        .size = bytes.len,
        .header_offset = 0,
        .content_offset = 0,
    };
    var validation: Recorder.debz.deb_payload.Validation = undefined;
    validation.data = undefined;
    validation.data.entries = entries;
    validation.data_bytes = try a.dupe(u8, bytes);
    return validation;
}

test "reference runtime binds exactly the nsswitch.conf providers of the hosted protected runtime lock" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const providers = [_]struct { package: []const u8, path: []const u8, bytes: []const u8 }{
        .{ .package = "libc-bin", .path = "usr/share/libc-bin/nsswitch.conf", .bytes = "passwd: files\n" },
        .{ .package = "systemd", .path = "usr/share/factory/etc/nsswitch.conf", .bytes = "passwd: files systemd\n" },
    };
    for ([_][]const u8{ "amd64", "arm64" }) |architecture| {
        for ([_]struct { added: []const []const u8, removed: ?[]const u8 = null, systemd_member: bool = true, bound: usize = 0, err: ?anyerror = null }{
            // The hosted lock: libc-bin's copy alone; systemd is never loaded.
            .{ .added = &.{}, .bound = 1 },
            // A lock that carries systemd still binds its factory copy too.
            .{ .added = &.{"systemd"}, .bound = 2 },
            // A locked provider without its member refuses; it is never dropped.
            .{ .added = &.{"systemd"}, .systemd_member = false, .err = error.MissingGuestMember },
            // libc-bin's copy is always required.
            .{ .added = &.{}, .removed = "libc-bin", .err = error.MissingRuntimePackage },
        }) |case| {
            var recorder: Recorder = .{
                .allocator = a,
                .architecture = architecture,
                .lock = try fixtureLock(a, architecture, case.added, case.removed),
                .cache = "/nonexistent-reference-runtime-cache",
                .payloads = .init(a),
            };
            for (providers) |provider| {
                if (recorder.lockPackage(provider.package) == null) continue;
                const path = if (case.systemd_member or !std.mem.eql(u8, provider.package, "systemd")) provider.path else "usr/lib/systemd/systemd";
                try recorder.payloads.put(provider.package, try fixturePayload(a, path, provider.bytes));
            }
            var self: GuestRecorder = .{
                .base = &recorder,
                .triplet = guest.triplet(architecture).?,
                .interpreter = "",
                .loader_path = "",
                .visited = .init(a),
            };
            if (case.err) |expected| {
                try std.testing.expectError(expected, self.nssConfig());
                continue;
            }
            try self.nssConfig();
            try std.testing.expectEqual(@as(usize, 1), self.entries.items.len);
            const entry = self.entries.items[0];
            try std.testing.expectEqualStrings("/etc/nsswitch.conf", entry.path);
            try std.testing.expectEqual(guest.Role.nss_config, entry.role);
            try std.testing.expect(!entry.required);
            try std.testing.expectEqual(case.bound, entry.allowed.len);
            for (entry.allowed, providers[0..case.bound]) |identity, provider| {
                const package = recorder.lockPackage(provider.package).?;
                try std.testing.expectEqualStrings(provider.package, identity.package.?);
                try std.testing.expectEqualStrings(package.version, identity.version.?);
                try std.testing.expectEqualStrings(&std.fmt.bytesToHex(package.archive_identity.digests.sha512.?, .lower), identity.archive_sha512.?);
                try std.testing.expectEqualStrings(provider.path, identity.member.?[1..]);
                try std.testing.expectEqualStrings(try digest(a, provider.bytes), identity.sha256);
                try std.testing.expectEqual(@as(u64, provider.bytes.len), identity.size);
            }
        }
    }
}

test {
    _ = guest;
}

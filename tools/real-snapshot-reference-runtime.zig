const std = @import("std");
const linux = std.os.linux;

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

    pub fn deinit(self: *Bound) void {
        for (self.inputs.items) |input| _ = linux.close(input.fd);
        for (self.root_files.items) |input| _ = linux.close(input.fd);
        for (self.aliases.items) |input| _ = linux.close(input.fd);
        for (self.objects.items) |object| self.allocator.free(object.bytes);
        self.inputs.deinit(self.allocator);
        self.root_files.deinit(self.allocator);
        self.aliases.deinit(self.allocator);
        self.objects.deinit(self.allocator);
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
                if (!std.mem.eql(u8, name, "binding.json")) {
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
    if (count != bindings.len + 1) return error.MissingRuntimeObject;
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
        const package = self.lock.findIdentity(name, self.architecture) orelse return error.MissingRuntimePackage;
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
    const manifest: Manifest = .{
        .architecture = architecture,
        .lock_sha256 = try digest(allocator, lock_bytes),
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

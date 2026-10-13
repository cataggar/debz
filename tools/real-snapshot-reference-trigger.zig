const std = @import("std");
const linux = std.os.linux;
const debz = @import("debz");
const runtime = @import("real-snapshot-reference-runtime.zig");

pub const schema = "io.github.cataggar.debz.reference-trigger-authority.v1";
const selected_version = "2.43-2ubuntu2.4";
const postinst_sha256 = "3daa7e3ffd429c1d77287f0fc840a490a607697906d2303452f70578647ce0d4";
const triggers_sha256 = "c3d6b5df131336e54c31dc5687929467de7abea5c5798e3d6a6b2a64ef971fd4";
const nsswitch_sha256 = "eec30745bade42a3f3f792e4d4192e57d2bcfe8e472433b1de426fe39a39cddb";
const archive_pins = [_]struct { architecture: []const u8, size: usize, sha512: []const u8 }{
    .{ .architecture = "amd64", .size = 700954, .sha512 = "350969573c25805e77d2ab180ebb445da1be72266f9aa5a162c2c38ec52f6935a58d7810d5795ba5fad415f5fa12fefe9194ff7e0534e292d1f63a56811e420f" },
    .{ .architecture = "arm64", .size = 597592, .sha512 = "e964f5753787fa44c95c7144507b178b970359b1ea90a732b2f2b6a1831d67ef3bf5b900d57ae682d3481676f8080b6382a130c6e13112a40fb698435ee124cc" },
};

const Input = struct { path: []const u8, pinned: runtime.Pinned, directory: bool = false, metadata_only: bool = false };
const Reader = struct {
    allocator: std.mem.Allocator,
    protected: bool,
    inputs: std.ArrayList(Input) = .empty,
    absences: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *Reader) void {
        for (self.inputs.items) |input| _ = linux.close(input.pinned.fd);
        self.inputs.deinit(self.allocator);
        self.absences.deinit(self.allocator);
    }

    fn open(self: *Reader, path: []const u8, directory: bool) !runtime.Pinned {
        if (self.protected) return runtime.openProtected(self.allocator, path, directory);
        return self.openUnprotected(path, directory);
    }

    fn openMetadata(self: *Reader, path: []const u8, directory: bool) !runtime.Pinned {
        const parent = try runtime.openProtected(self.allocator, std.fs.path.dirname(path) orelse return error.InvalidAuthorityPath, true);
        defer _ = linux.close(parent.fd);
        return self.openUnprotected(path, directory);
    }

    fn openUnprotected(self: *Reader, path: []const u8, directory: bool) !runtime.Pinned {
        if (!std.fs.path.isAbsolute(path)) return error.InvalidAuthorityPath;
        const name = try self.allocator.dupeZ(u8, path);
        defer self.allocator.free(name);
        const how = extern struct { flags: u64, mode: u64 = 0, resolve: u64 = 0x02 | 0x04 }{
            .flags = @as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY, .CLOEXEC = true, .DIRECTORY = directory })),
        };
        const result = linux.syscall4(.openat2, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(name.ptr), @intFromPtr(&how), @sizeOf(@TypeOf(how)));
        if (linux.errno(result) != .SUCCESS) return error.AuthorityPathRefused;
        const fd: i32 = @intCast(result);
        errdefer _ = linux.close(fd);
        const metadata = try runtime.stat(fd);
        if (metadata.mode & 0o170000 != (if (directory) @as(u16, 0o040000) else @as(u16, 0o100000)) or
            (!directory and metadata.nlink != 1)) return error.AuthorityPathRefused;
        return .{ .fd = fd, .metadata = metadata };
    }

    fn read(self: *Reader, path: []const u8, maximum: usize) ![]const u8 {
        const pinned = try self.open(path, false);
        errdefer _ = linux.close(pinned.fd);
        const bytes = try runtime.readPinned(self.allocator, pinned, maximum);
        errdefer self.allocator.free(bytes);
        try self.inputs.append(self.allocator, .{ .path = path, .pinned = pinned });
        return bytes;
    }

    fn exists(self: *Reader, path: []const u8) !bool {
        const name = try self.allocator.dupeZ(u8, path);
        defer self.allocator.free(name);
        const how = extern struct { flags: u64, mode: u64 = 0, resolve: u64 = 0x02 | 0x04 }{
            .flags = @as(u32, @bitCast(linux.O{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true })),
        };
        const result = linux.syscall4(.openat2, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(name.ptr), @intFromPtr(&how), @sizeOf(@TypeOf(how)));
        switch (linux.errno(result)) {
            .NOENT => return false,
            .SUCCESS => {
                _ = linux.close(@intCast(result));
                return true;
            },
            else => return error.AuthorityPathRefused,
        }
    }

    fn optional(self: *Reader, path: []const u8, maximum: usize) !?[]const u8 {
        if (try self.exists(path)) return try self.read(path, maximum);
        try self.absences.append(self.allocator, path);
        return null;
    }

    fn verify(self: *Reader) !void {
        for (self.inputs.items) |input| {
            const current = if (input.metadata_only)
                try self.openMetadata(input.path, input.directory)
            else
                try self.open(input.path, input.directory);
            defer _ = linux.close(current.fd);
            if (!runtime.same(input.pinned.metadata, try runtime.stat(input.pinned.fd)) or
                !runtime.same(input.pinned.metadata, current.metadata)) return error.TriggerAuthoritySourceChanged;
        }
        for (self.absences.items) |path| if (try self.exists(path)) return error.TriggerAuthoritySourceChanged;
    }
};

fn hash(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return allocator.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

fn base64(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
    _ = std.base64.standard.Encoder.encode(encoded, bytes);
    return encoded;
}

fn sameDigest(bytes: []const u8, expected: []const u8) bool {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), expected);
}

fn packagePayload(reader: *Reader, lock: debz.exact_lock_v3.Lock, cache: []const u8, name: []const u8) !debz.deb_payload.Validation {
    const package = lock.findIdentity(name, lock.target_architecture) orelse return error.MissingTriggerAuthorityPackage;
    const origin = switch (package.origin) {
        .authenticated_repository => |value| value,
        .local_artifact => return error.UnsignedTriggerAuthorityPackage,
    };
    const digest = package.archive_identity.digests.sha512 orelse return error.UnboundTriggerAuthorityArchive;
    const path = try std.fmt.allocPrint(reader.allocator, "{s}/packages-v2/objects/sha512-{s}", .{ cache, std.fmt.bytesToHex(digest, .lower) });
    const bytes = try reader.read(path, 32 * 1024 * 1024);
    try package.verifyArchive(bytes);
    return switch (debz.deb_payload.validate(reader.allocator, bytes, .{
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
    })) {
        .validation => |value| value,
        .diagnostic => error.TriggerAuthorityArchiveRefused,
    };
}

fn controlMember(payload: *const debz.deb_payload.Validation, name: []const u8, size: usize, expected: []const u8) ![]const u8 {
    const entry = for (payload.control.entries) |entry| {
        if (std.mem.eql(u8, entry.path, name)) break entry;
    } else return error.MissingTriggerAuthorityControl;
    if (entry.kind != .regular or entry.uid != 0 or entry.gid != 0 or
        entry.mode != (if (std.mem.eql(u8, name, "postinst")) @as(u32, 0o755) else @as(u32, 0o644)) or
        entry.size != size or entry.content_offset > payload.control_bytes.len or size > payload.control_bytes.len - entry.content_offset)
        return error.InvalidTriggerAuthorityControl;
    const bytes = payload.control_bytes[entry.content_offset..][0..size];
    if (!sameDigest(bytes, expected)) return error.ChangedTriggerAuthorityControl;
    return bytes;
}

pub fn verifySelectedArchive(package: debz.exact_lock_v3.Package, architecture: []const u8) !void {
    const pin = for (archive_pins) |pin| {
        if (std.mem.eql(u8, pin.architecture, architecture)) break pin;
    } else return error.UnsupportedTriggerAuthorityArchitecture;
    const digest = package.archive_identity.digests.sha512 orelse return error.UnboundTriggerAuthorityArchive;
    if (!std.mem.eql(u8, package.name, "libc-bin") or !std.mem.eql(u8, package.version, selected_version) or
        !std.mem.eql(u8, package.architecture, architecture) or package.declared_size != pin.size or
        !std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), pin.sha512))
        return error.UnreviewedSelectedTriggerHandler;
    if (package.origin != .authenticated_repository) return error.UnsignedTriggerAuthorityPackage;
}

pub fn parseStatus(allocator: std.mem.Allocator, bytes: []const u8) !debz.deb822.BorrowedDocument {
    var document = switch (try debz.deb822.parseBorrowed(allocator, bytes, .{
        .limits = .{ .max_total_bytes = 16 * 1024 * 1024, .max_paragraphs = 2048, .max_fields_per_paragraph = 128, .max_field_bytes = 1024 * 1024 },
        .duplicate_policy = .reject,
    })) {
        .document => |value| value,
        .failure => return error.InvalidTriggerStatusDatabase,
    };
    errdefer document.deinit();
    for (document.paragraphs, 0..) |paragraph, index| {
        const name = try scalar(paragraph, "Package");
        const architecture = try scalar(paragraph, "Architecture");
        _ = try scalar(paragraph, "Version");
        _ = try scalar(paragraph, "Status");
        for (document.paragraphs[0..index]) |previous| {
            if (std.mem.eql(u8, name, try scalar(previous, "Package")) and
                std.mem.eql(u8, architecture, try scalar(previous, "Architecture"))) return error.AmbiguousTriggerStatusIdentity;
        }
    }
    return document;
}

fn scalar(paragraph: debz.deb822.Paragraph, name: []const u8) ![]const u8 {
    const field = paragraph.get(name) orelse return error.MissingTriggerStatusField;
    if (field.value_lines.len != 1) return error.InvalidTriggerStatusField;
    return std.mem.trim(u8, field.value_lines[0].text, " \t");
}

fn optionalScalar(paragraph: debz.deb822.Paragraph, name: []const u8) ![]const u8 {
    if (paragraph.get(name) == null) return "";
    return scalar(paragraph, name);
}

fn record(document: debz.deb822.BorrowedDocument, name: []const u8, architecture: []const u8) !debz.deb822.Paragraph {
    for (document.paragraphs) |paragraph| {
        if (std.mem.eql(u8, try scalar(paragraph, "Package"), name) and
            std.mem.eql(u8, try scalar(paragraph, "Architecture"), architecture)) return paragraph;
    }
    return error.MissingSelectedTriggerStatus;
}

pub fn verifySelectedStatus(document: debz.deb822.BorrowedDocument, architecture: []const u8, libc6_version: []const u8) !void {
    const selected = try record(document, "libc-bin", architecture);
    if (!std.mem.eql(u8, try scalar(selected, "Version"), selected_version) or
        !std.mem.eql(u8, try scalar(selected, "Status"), "install ok triggers-pending") or
        !std.mem.eql(u8, try scalar(selected, "Triggers-Pending"), "ldconfig") or
        !std.mem.eql(u8, try scalar(selected, "Depends"), "libc6 (>> 2.43), libc6 (<< 2.44)") or
        (try optionalScalar(selected, "Triggers-Awaited")).len != 0)
        return error.MixedSelectedTriggerState;
    const libc6 = try record(document, "libc6", architecture);
    if (!std.mem.eql(u8, try scalar(libc6, "Version"), libc6_version) or
        !std.mem.eql(u8, try scalar(libc6, "Status"), "install ok installed") or
        (try optionalScalar(libc6, "Triggers-Pending")).len != 0 or
        (try optionalScalar(libc6, "Triggers-Awaited")).len != 0)
        return error.UnconfiguredTriggerDependency;
}

fn fieldEqual(left: debz.deb822.Field, right: debz.deb822.Field) bool {
    if (!std.ascii.eqlIgnoreCase(left.name, right.name) or left.value_lines.len != right.value_lines.len) return false;
    for (left.value_lines, right.value_lines) |a, b| if (!std.mem.eql(u8, a.text, b.text)) return false;
    return true;
}

fn stableFields(left: debz.deb822.Paragraph, right: debz.deb822.Paragraph) !void {
    for ([_]debz.deb822.Paragraph{ left, right }, [_]debz.deb822.Paragraph{ right, left }) |from, to| {
        for (from.fields) |field| {
            if (std.ascii.eqlIgnoreCase(field.name, "Status") or std.ascii.eqlIgnoreCase(field.name, "Triggers-Pending") or
                std.ascii.eqlIgnoreCase(field.name, "Triggers-Awaited")) continue;
            if (!fieldEqual(field, (to.get(field.name) orelse return error.TriggerDatabaseChanged).*))
                return error.TriggerDatabaseChanged;
        }
    }
}

fn withoutAwaited(allocator: std.mem.Allocator, value: []const u8, name: []const u8, architecture: []const u8) ![]const u8 {
    const selector = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ name, architecture });
    defer allocator.free(selector);
    var remaining: std.ArrayList(u8) = .empty;
    errdefer remaining.deinit(allocator);
    var tokens = std.mem.tokenizeAny(u8, value, " \t");
    var removed = false;
    while (tokens.next()) |token| {
        if (std.mem.eql(u8, token, name) or std.mem.eql(u8, token, selector)) {
            if (removed) return error.MixedSelectedTriggerState;
            removed = true;
            continue;
        }
        if (remaining.items.len != 0) try remaining.append(allocator, ' ');
        try remaining.appendSlice(allocator, token);
    }
    return remaining.toOwnedSlice(allocator);
}

pub fn verifyTransition(allocator: std.mem.Allocator, before: debz.deb822.BorrowedDocument, after: debz.deb822.BorrowedDocument, architecture: []const u8) !void {
    if (!std.mem.eql(u8, architecture, "amd64") and !std.mem.eql(u8, architecture, "arm64"))
        return error.UnsupportedTriggerAuthorityArchitecture;
    const selected_before = try record(before, "libc-bin", architecture);
    const selected_after = try record(after, "libc-bin", architecture);
    if (!std.mem.eql(u8, try scalar(selected_before, "Status"), "install ok triggers-pending") or
        !std.mem.eql(u8, try scalar(selected_before, "Triggers-Pending"), "ldconfig") or
        !std.mem.eql(u8, try scalar(selected_before, "Version"), selected_version) or
        (try optionalScalar(selected_before, "Triggers-Awaited")).len != 0)
        return error.MixedSelectedTriggerState;
    if (std.mem.eql(u8, try scalar(selected_after, "Status"), try scalar(selected_before, "Status")) and
        std.mem.eql(u8, try optionalScalar(selected_after, "Triggers-Pending"), "ldconfig"))
        return error.CycleNoProgress;
    if (before.paragraphs.len != after.paragraphs.len or
        !std.mem.eql(u8, try scalar(selected_after, "Status"), "install ok installed") or
        (try optionalScalar(selected_after, "Triggers-Pending")).len != 0 or
        (try optionalScalar(selected_after, "Triggers-Awaited")).len != 0)
        return error.TriggerDatabaseChanged;
    for (before.paragraphs) |old| {
        const name = try scalar(old, "Package");
        const arch = try scalar(old, "Architecture");
        const current = try record(after, name, arch);
        try stableFields(old, current);
        if (std.mem.eql(u8, name, "libc-bin") and std.mem.eql(u8, arch, architecture)) continue;
        if (!std.mem.eql(u8, try optionalScalar(old, "Triggers-Pending"), try optionalScalar(current, "Triggers-Pending")))
            return error.ExternalTriggerCallback;
        const awaited = try withoutAwaited(allocator, try optionalScalar(old, "Triggers-Awaited"), "libc-bin", architecture);
        defer allocator.free(awaited);
        if (!std.mem.eql(u8, awaited, try optionalScalar(current, "Triggers-Awaited"))) return error.ExternalTriggerCallback;
        const old_state = try scalar(old, "Status");
        const expected = if (std.mem.eql(u8, old_state, "install ok triggers-awaited") and awaited.len == 0)
            "install ok installed"
        else
            old_state;
        if (!std.mem.eql(u8, expected, try scalar(current, "Status"))) return error.ExternalTriggerCallback;
    }
}

pub fn nssModules(allocator: std.mem.Allocator, bytes: []const u8) ![]const []const u8 {
    if (bytes.len > 64 * 1024 or std.mem.indexOfScalar(u8, bytes, 0) != null) return error.InvalidNssClosureConfiguration;
    var modules: std.ArrayList([]const u8) = .empty;
    errdefer modules.deinit(allocator);
    var services = std.StringHashMap(void).init(allocator);
    defer services.deinit();
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const content = std.mem.trim(u8, line[0 .. std.mem.indexOfScalar(u8, line, '#') orelse line.len], " \t\r");
        if (content.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, content, ':') orelse return error.InvalidNssClosureConfiguration;
        const service = std.mem.trim(u8, content[0..colon], " \t");
        if (service.len == 0 or services.contains(service)) return error.InvalidNssClosureConfiguration;
        for (service) |byte| if (!std.ascii.isLower(byte)) return error.InvalidNssClosureConfiguration;
        try services.put(service, {});
        var tokens = std.mem.tokenizeAny(u8, content[colon + 1 ..], " \t");
        var count: usize = 0;
        while (tokens.next()) |token| {
            // Complex lookup actions need their own reviewed semantics, not a token-presence grant.
            for (token) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '_')
                return error.UnreviewedNssClosureAction;
            if (token.len == 0 or token.len > 64) return error.InvalidNssClosureConfiguration;
            count += 1;
            const found = for (modules.items) |previous| {
                if (std.mem.eql(u8, previous, token)) break true;
            } else false;
            if (!found) try modules.append(allocator, token);
        }
        if (count == 0) return error.InvalidNssClosureConfiguration;
    }
    return modules.toOwnedSlice(allocator);
}

const Member = struct {
    path: []const u8,
    package: []const u8,
    version: []const u8,
    archive_sha512: []const u8,
    sha256: []const u8,
    size: usize,
    mode: u32,
    interpreter: ?[]const u8 = null,
    needed: []const []const u8 = &.{},
};

fn member(allocator: std.mem.Allocator, lock: debz.exact_lock_v3.Lock, payload: *const debz.deb_payload.Validation, path: []const u8, elf: bool) !Member {
    const entry = for (payload.data.entries) |entry| {
        if (std.mem.eql(u8, entry.path, path)) break entry;
    } else return error.MissingTriggerRuntimeMember;
    if (entry.kind != .regular or entry.uid != 0 or entry.gid != 0 or entry.mode & 0o022 != 0)
        return error.UnprotectedTriggerRuntimeMember;
    const bytes = try payload.regularPayloadBytes(path, runtime.maximum_object_bytes);
    const package = lock.findIdentity(payload.package, payload.architecture).?;
    const parsed = if (elf) try runtime.inspectElf(allocator, bytes, lock.target_architecture) else null;
    return .{
        .path = try std.fmt.allocPrint(allocator, "/{s}", .{path}),
        .package = payload.package,
        .version = payload.version,
        .archive_sha512 = try allocator.dupe(u8, &std.fmt.bytesToHex(package.archive_identity.digests.sha512.?, .lower)),
        .sha256 = try hash(allocator, bytes),
        .size = bytes.len,
        .mode = entry.mode,
        .interpreter = if (parsed) |value| value.interpreter else null,
        .needed = if (parsed) |value| value.needed else &.{},
    };
}

fn rootMember(reader: *Reader, root: []const u8, binding: Member) !void {
    const path = try std.fmt.allocPrint(reader.allocator, "{s}{s}", .{ root, binding.path });
    const bytes = try reader.read(path, runtime.maximum_object_bytes);
    const metadata = reader.inputs.items[reader.inputs.items.len - 1].pinned.metadata;
    if (metadata.mode & 0o7777 != binding.mode or bytes.len != binding.size or !sameDigest(bytes, binding.sha256))
        return error.TriggerRuntimeMemberChanged;
}

const DatabaseMember = struct { name: []const u8, sha256: []const u8, size: usize, mode: u32, content_base64: []const u8 };

fn databaseDirectory(reader: *Reader, root: []const u8, directory_name: []const u8, admission: bool) ![]DatabaseMember {
    const path = try std.fmt.allocPrint(reader.allocator, "{s}/var/lib/dpkg/{s}", .{ root, directory_name });
    const directory = try reader.open(path, true);
    try reader.inputs.append(reader.allocator, .{ .path = path, .pinned = directory, .directory = true });
    var entries: std.ArrayList(DatabaseMember) = .empty;
    var total_bytes: usize = 0;
    var buffer: [8192]u8 align(8) = undefined;
    while (true) {
        const result = linux.getdents64(directory.fd, &buffer, buffer.len);
        if (linux.errno(result) != .SUCCESS) return error.InvalidTriggerControlDatabase;
        if (result == 0) break;
        var offset: usize = 0;
        while (offset < result) {
            if (result - offset < 20) return error.InvalidTriggerControlDatabase;
            const length = std.mem.readInt(u16, buffer[offset + 16 ..][0..2], .little);
            if (length < 20 or length > result - offset) return error.InvalidTriggerControlDatabase;
            const names = buffer[offset + 19 .. offset + length];
            const end = std.mem.indexOfScalar(u8, names, 0) orelse return error.InvalidTriggerControlDatabase;
            const name = names[0..end];
            offset += length;
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            if (entries.items.len == 2048 or std.mem.indexOfAny(u8, name, "/\n\r\t") != null or !std.unicode.utf8ValidateSlice(name))
                return error.InvalidTriggerControlDatabase;
            const source = try std.fmt.allocPrint(reader.allocator, "{s}/{s}", .{ path, name });
            const bytes = try reader.read(source, 2 * 1024 * 1024);
            total_bytes += bytes.len;
            if (total_bytes > 2 * 1024 * 1024) return error.TriggerControlDatabaseTooLarge;
            if (admission and std.mem.eql(u8, name, "Unincorp") and bytes.len != 0) return error.UnincorporatedTriggerActivation;
            try entries.append(reader.allocator, .{
                .name = try reader.allocator.dupe(u8, name),
                .sha256 = try hash(reader.allocator, bytes),
                .size = bytes.len,
                .mode = reader.inputs.items[reader.inputs.items.len - 1].pinned.metadata.mode & 0o7777,
                .content_base64 = try base64(reader.allocator, bytes),
            });
        }
    }
    if (!runtime.same(directory.metadata, try runtime.stat(directory.fd))) return error.TriggerAuthoritySourceChanged;
    std.mem.sort(DatabaseMember, entries.items, {}, struct {
        fn less(_: void, a: DatabaseMember, b: DatabaseMember) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.less);
    return entries.toOwnedSlice(reader.allocator);
}

const MutationDatabase = struct {
    path: []const u8,
    present: bool,
    content_base64: ?[]const u8,
    sha256: ?[]const u8,
    mode: ?u32,
};
const LiveMetadata = struct {
    path: []const u8,
    present: bool,
    kind: ?[]const u8 = null,
    mode: ?u32 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
};
const MutationState = struct { databases: [4]MutationDatabase, chrony: [3]LiveMetadata };
const Accounts = struct {
    passwd_base64: ?[]const u8,
    group_base64: ?[]const u8,
    passwd_sha256: ?[]const u8,
    group_sha256: ?[]const u8,
};
const Capture = struct {
    schema: []const u8,
    version: u32,
    state: MutationState,
    accounts: Accounts,
    status_base64: ?[]const u8,
    status_sha256: ?[]const u8,
    trigger_registry: []const DatabaseMember,
    updates: []const DatabaseMember,
    observation_only: bool,
    parity_accepted: bool,
};

fn verifyCapturedBytes(allocator: std.mem.Allocator, encoded: ?[]const u8, digest: ?[]const u8) !void {
    if ((encoded == null) != (digest == null)) return error.InvalidMutatingToolsCapture;
    if (encoded) |source| {
        const decoder = std.base64.standard.Decoder;
        const decoded = try allocator.alloc(u8, decoder.calcSizeForSlice(source) catch return error.InvalidMutatingToolsCapture);
        defer allocator.free(decoded);
        decoder.decode(decoded, source) catch return error.InvalidMutatingToolsCapture;
        if (!sameDigest(decoded, digest.?)) return error.MutatingToolsCaptureDigestChanged;
    }
}

pub fn verifyCapture(allocator: std.mem.Allocator, capture: Capture) !void {
    if (!std.mem.eql(u8, capture.schema, "io.github.cataggar.debz.reference-mutating-tools-state.v1") or
        capture.version != 1 or !capture.observation_only or capture.parity_accepted)
        return error.InvalidMutatingToolsCapture;
    for (capture.state.databases, [_][]const u8{
        "/var/lib/dpkg/diversions", "/var/lib/dpkg/diversions-old", "/var/lib/dpkg/statoverride", "/var/lib/dpkg/statoverride-old",
    }) |binding, path| {
        if (!std.mem.eql(u8, binding.path, path) or binding.present != (binding.content_base64 != null) or
            binding.present != (binding.mode != null)) return error.InvalidMutatingToolsCapture;
        try verifyCapturedBytes(allocator, binding.content_base64, binding.sha256);
    }
    for (capture.state.chrony, [_][]const u8{ "/etc/chrony/chrony.keys", "/var/lib/chrony", "/var/log/chrony" }, 0..) |binding, path, index| {
        if (!std.mem.eql(u8, binding.path, path) or binding.present != (binding.kind != null) or
            binding.present != (binding.mode != null) or binding.present != (binding.uid != null) or binding.present != (binding.gid != null) or
            (binding.present and !std.mem.eql(u8, binding.kind.?, if (index == 0) "file" else "directory")))
            return error.InvalidMutatingToolsCapture;
    }
    try verifyCapturedBytes(allocator, capture.accounts.passwd_base64, capture.accounts.passwd_sha256);
    try verifyCapturedBytes(allocator, capture.accounts.group_base64, capture.accounts.group_sha256);
    try verifyCapturedBytes(allocator, capture.status_base64, capture.status_sha256);
    for ([_][]const DatabaseMember{ capture.trigger_registry, capture.updates }) |directory| {
        for (directory) |binding| try verifyCapturedBytes(allocator, binding.content_base64, binding.sha256);
    }
}

pub fn compareCaptures(allocator: std.mem.Allocator, reference: Capture, native: Capture) !void {
    try verifyCapture(allocator, reference);
    try verifyCapture(allocator, native);
    const left = try std.json.Stringify.valueAlloc(allocator, .{ .state = reference.state, .accounts = reference.accounts }, .{});
    defer allocator.free(left);
    const right = try std.json.Stringify.valueAlloc(allocator, .{ .state = native.state, .accounts = native.accounts }, .{});
    defer allocator.free(right);
    if (!std.mem.eql(u8, left, right)) return error.MutatingToolsStateDiffers;
}

fn captureMutations(init: std.process.Init, root: []const u8) !void {
    const allocator = init.arena.allocator();
    var reader: Reader = .{ .allocator = allocator, .protected = true };
    defer reader.deinit();
    const directory = try reader.open(root, true);
    try reader.inputs.append(allocator, .{ .path = root, .pinned = directory, .directory = true });
    var databases: [4]MutationDatabase = undefined;
    for (&databases, [_][]const u8{ "diversions", "diversions-old", "statoverride", "statoverride-old" }) |*binding, name| {
        const relative = try std.fmt.allocPrint(allocator, "/var/lib/dpkg/{s}", .{name});
        const path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ root, relative });
        const content = try reader.optional(path, 1024 * 1024);
        binding.* = .{
            .path = relative,
            .present = content != null,
            .content_base64 = if (content) |bytes| try base64(allocator, bytes) else null,
            .sha256 = if (content) |bytes| try hash(allocator, bytes) else null,
            .mode = if (content != null) reader.inputs.items[reader.inputs.items.len - 1].pinned.metadata.mode & 0o7777 else null,
        };
    }
    var chrony: [3]LiveMetadata = undefined;
    for (&chrony, [_][]const u8{ "/etc/chrony/chrony.keys", "/var/lib/chrony", "/var/log/chrony" }, 0..) |*binding, relative, index| {
        const path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ root, relative });
        const present = try reader.exists(path);
        binding.* = .{ .path = relative, .present = present };
        if (!present) {
            try reader.absences.append(allocator, path);
            continue;
        }
        const input = try reader.openMetadata(path, index != 0);
        try reader.inputs.append(allocator, .{ .path = path, .pinned = input, .directory = index != 0, .metadata_only = true });
        binding.kind = if (index == 0) "file" else "directory";
        binding.mode = input.metadata.mode & 0o7777;
        binding.uid = input.metadata.uid;
        binding.gid = input.metadata.gid;
    }
    // Account files are observations from this root, not host identities or expected native results.
    const passwd = try reader.optional(try std.fmt.allocPrint(allocator, "{s}/etc/passwd", .{root}), 1024 * 1024);
    const group = try reader.optional(try std.fmt.allocPrint(allocator, "{s}/etc/group", .{root}), 1024 * 1024);
    const status = try reader.optional(try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/status", .{root}), 2 * 1024 * 1024);
    const trigger_registry = try databaseDirectory(&reader, root, "triggers", false);
    const updates = try databaseDirectory(&reader, root, "updates", false);
    var registry_bytes: usize = 0;
    for ([_][]const DatabaseMember{ trigger_registry, updates }) |entries| {
        for (entries) |entry| registry_bytes += entry.size;
    }
    if (registry_bytes > 1024 * 1024) return error.TriggerControlDatabaseTooLarge;
    try reader.verify();
    const output = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = "io.github.cataggar.debz.reference-mutating-tools-state.v1",
        .version = 1,
        .state = .{ .databases = databases, .chrony = chrony },
        .accounts = .{
            .passwd_base64 = if (passwd) |bytes| try base64(allocator, bytes) else null,
            .group_base64 = if (group) |bytes| try base64(allocator, bytes) else null,
            .passwd_sha256 = if (passwd) |bytes| try hash(allocator, bytes) else null,
            .group_sha256 = if (group) |bytes| try hash(allocator, bytes) else null,
        },
        .status_base64 = if (status) |bytes| try base64(allocator, bytes) else null,
        .status_sha256 = if (status) |bytes| try hash(allocator, bytes) else null,
        .trigger_registry = trigger_registry,
        .updates = updates,
        .observation_only = true,
        .parity_accepted = false,
    }, .{});
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
    try std.Io.File.stdout().writeStreamingAll(init.io, "\n");
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const command = args.next() orelse return error.InvalidTriggerAuthorityArguments;
    if (std.mem.eql(u8, command, "compare-mutations")) {
        const reference_path = args.next() orelse return error.InvalidTriggerAuthorityArguments;
        const native_path = args.next() orelse return error.InvalidTriggerAuthorityArguments;
        if (args.next() != null) return error.InvalidTriggerAuthorityArguments;
        var reader: Reader = .{ .allocator = allocator, .protected = false };
        defer reader.deinit();
        var reference = try std.json.parseFromSlice(Capture, allocator, try reader.read(reference_path, 16 * 1024 * 1024), .{});
        defer reference.deinit();
        var native = try std.json.parseFromSlice(Capture, allocator, try reader.read(native_path, 16 * 1024 * 1024), .{});
        defer native.deinit();
        try compareCaptures(allocator, reference.value, native.value);
        try reader.verify();
        try std.Io.File.stdout().writeStreamingAll(init.io, "{\"mutating_tools_equal\":true,\"full_root_parity_accepted\":false}\n");
        return;
    }
    if (std.mem.eql(u8, command, "capture-mutations")) {
        const root = args.next() orelse return error.InvalidTriggerAuthorityArguments;
        if (args.next() != null) return error.InvalidTriggerAuthorityArguments;
        return captureMutations(init, root);
    }
    if (std.mem.eql(u8, command, "verify-transition")) {
        const architecture = args.next() orelse return error.InvalidTriggerAuthorityArguments;
        const before_path = args.next() orelse return error.InvalidTriggerAuthorityArguments;
        const after_path = args.next() orelse return error.InvalidTriggerAuthorityArguments;
        if (args.next() != null) return error.InvalidTriggerAuthorityArguments;
        var reader: Reader = .{ .allocator = allocator, .protected = false };
        defer reader.deinit();
        var before = try parseStatus(allocator, try reader.read(before_path, 16 * 1024 * 1024));
        defer before.deinit();
        var after = try parseStatus(allocator, try reader.read(after_path, 16 * 1024 * 1024));
        defer after.deinit();
        try verifyTransition(allocator, before, after, architecture);
        try reader.verify();
        return;
    }
    const probing = std.mem.eql(u8, command, "probe-trigger-authority");
    if (!probing and !std.mem.eql(u8, command, "inspect-original")) return error.InvalidTriggerAuthorityArguments;
    const architecture = args.next() orelse return error.InvalidTriggerAuthorityArguments;
    const lock_path = args.next() orelse return error.InvalidTriggerAuthorityArguments;
    const cache = args.next() orelse return error.InvalidTriggerAuthorityArguments;
    const root = if (probing) args.next() orelse return error.InvalidTriggerAuthorityArguments else null;
    const selector = if (probing) args.next() orelse return error.InvalidTriggerAuthorityArguments else "libc-bin";
    if (args.next() != null) return error.InvalidTriggerAuthorityArguments;
    const qualified = try std.fmt.allocPrint(allocator, "libc-bin:{s}", .{architecture});
    if (!std.mem.eql(u8, selector, "libc-bin") and !std.mem.eql(u8, selector, qualified))
        return error.UnreviewedSelectedTriggerHandler;
    if (probing and (linux.getuid() != 0 or linux.getgid() != 0)) return error.UnprotectedTriggerAuthority;
    var reader: Reader = .{ .allocator = allocator, .protected = probing };
    defer reader.deinit();
    const lock_bytes = try reader.read(lock_path, 16 * 1024 * 1024);
    var decoded = try debz.exact_lock_v3.decode(allocator, lock_bytes, 16 * 1024 * 1024);
    defer decoded.deinit();
    const lock = decoded.lock;
    if (!std.mem.eql(u8, lock.target_architecture, architecture)) return error.TriggerAuthorityArchitectureMismatch;
    try lock.requireArchiveDigestPolicy(.sha512_identity_required);
    const selected = lock.findIdentity("libc-bin", architecture) orelse return error.MissingTriggerAuthorityPackage;
    try verifySelectedArchive(selected, architecture);
    var libc_bin = try packagePayload(&reader, lock, cache, "libc-bin");
    defer libc_bin.deinit();
    const postinst = try controlMember(&libc_bin, "postinst", 847, postinst_sha256);
    const triggers = try controlMember(&libc_bin, "triggers", 440, triggers_sha256);
    if (!std.mem.eql(u8, libc_bin.relationships.depends orelse "", "libc6 (>> 2.43), libc6 (<< 2.44)"))
        return error.TriggerDependencyGraphChanged;
    var dash = try packagePayload(&reader, lock, cache, "dash");
    defer dash.deinit();
    var libc6 = try packagePayload(&reader, lock, cache, "libc6");
    defer libc6.deinit();
    const triplet = if (std.mem.eql(u8, architecture, "amd64")) "x86_64-linux-gnu" else "aarch64-linux-gnu";
    const libc_path = try std.fmt.allocPrint(allocator, "usr/lib/{s}/libc.so.6", .{triplet});
    const loader_name = if (std.mem.eql(u8, architecture, "amd64")) "ld-linux-x86-64.so.2" else "ld-linux-aarch64.so.1";
    const loader_path = try std.fmt.allocPrint(allocator, "usr/lib/{s}/{s}", .{ triplet, loader_name });
    const bindings = [_]Member{
        try member(allocator, lock, &dash, "usr/bin/dash", true),
        try member(allocator, lock, &libc_bin, "usr/sbin/ldconfig", true),
        try member(allocator, lock, &libc6, libc_path, true),
        try member(allocator, lock, &libc6, loader_path, true),
        try member(allocator, lock, &libc_bin, "usr/share/libc-bin/nsswitch.conf", false),
    };
    if (bindings[1].interpreter != null or bindings[1].needed.len != 0)
        return error.UnreviewedLdconfigRuntime;
    const nsswitch = try libc_bin.regularPayloadBytes("usr/share/libc-bin/nsswitch.conf", 64 * 1024);
    if (!sameDigest(nsswitch, nsswitch_sha256)) return error.UnreviewedNssClosureConfiguration;
    const modules = try nssModules(allocator, nsswitch);
    var status_sha256: ?[]const u8 = null;
    var status_base64: ?[]const u8 = null;
    var database: []DatabaseMember = &.{};
    if (root) |path| {
        const source = try reader.read(try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/status", .{path}), 2 * 1024 * 1024);
        var document = try parseStatus(allocator, source);
        defer document.deinit();
        try verifySelectedStatus(document, architecture, libc6.version);
        status_sha256 = try hash(allocator, source);
        status_base64 = try base64(allocator, source);
        const script = try reader.read(try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/info/libc-bin.postinst", .{path}), 847);
        if (reader.inputs.items[reader.inputs.items.len - 1].pinned.metadata.mode & 0o7777 != 0o755)
            return error.TriggerInstalledControlChanged;
        const activation = try reader.read(try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/info/libc-bin.triggers", .{path}), 440);
        if (reader.inputs.items[reader.inputs.items.len - 1].pinned.metadata.mode & 0o7777 != 0o644)
            return error.TriggerInstalledControlChanged;
        if (!std.mem.eql(u8, postinst, script) or !std.mem.eql(u8, triggers, activation))
            return error.TriggerInstalledControlChanged;
        for ([_][]const u8{ "postinst", "triggers" }) |name| {
            const alternate = try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/info/{s}.{s}", .{ path, qualified, name });
            if (try reader.exists(alternate)) return error.AmbiguousSelectedTriggerControl;
            try reader.absences.append(allocator, alternate);
        }
        for (bindings) |binding| try rootMember(&reader, path, binding);
        const actual_nss = try reader.read(try std.fmt.allocPrint(allocator, "{s}/etc/nsswitch.conf", .{path}), 64 * 1024);
        if (!std.mem.eql(u8, nsswitch, actual_nss)) return error.UnreviewedNssClosureConfiguration;
        database = try databaseDirectory(&reader, path, "triggers", true);
        const updates = try databaseDirectory(&reader, path, "updates", true);
        if (updates.len != 0) return error.UnsettledTriggerStatusUpdates;
    }
    try reader.verify();
    const output = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = schema,
        .version = 1,
        .architecture = architecture,
        .selector = qualified,
        .package_version = selected.version,
        .archive_sha512 = try allocator.dupe(u8, &std.fmt.bytesToHex(selected.archive_identity.digests.sha512.?, .lower)),
        .lock_sha256 = try hash(allocator, lock_bytes),
        .postinst_sha256 = postinst_sha256,
        .postinst_size = 847,
        .triggers_sha256 = triggers_sha256,
        .dependency_graph = libc_bin.relationships.depends,
        .argv = .{ "--no-triggers", "--triggers-only", qualified },
        .postinst_argv = .{ "triggered", "ldconfig" },
        .proc_profile = "none",
        .source_members = bindings,
        .nss_modules = modules,
        .status_sha256 = status_sha256,
        .status_base64 = status_base64,
        .trigger_database = database,
        .execution_authorized = false,
        .outcome = if (probing) "refused" else "source_inspected",
        .reason = "UnboundTriggerRuntime",
        .remaining = .{
            "hosted proof of the bound guest runtime and of the libc-bin single-handler transition at the final head",
            "arm64 pre-handler trigger state (unobserved: no arm64 reference has reached it)",
            "every remaining selected handler, procps /usr/lib/sysctl.d first; --pending stays unauthorized",
        },
    }, .{});
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
    try std.Io.File.stdout().writeStreamingAll(init.io, "\n");
    if (probing) return error.UnboundTriggerRuntime;
}

const before_fixture =
    "Package: libc-bin\nArchitecture: arm64\nVersion: 2.43-2ubuntu2.4\nStatus: install ok triggers-pending\n" ++
    "Depends: libc6 (>> 2.43), libc6 (<< 2.44)\nTriggers-Pending: ldconfig\n\n" ++
    "Package: libc6\nArchitecture: arm64\nVersion: 2.43-2ubuntu2.4\nStatus: install ok installed\n\n" ++
    "Package: seed\nArchitecture: all\nVersion: 1\nStatus: install ok triggers-awaited\nTriggers-Awaited: libc-bin\n\n" ++
    "Package: other\nArchitecture: all\nVersion: 1\nStatus: install ok triggers-pending\nTriggers-Pending: other-trigger\n\n";
const after_fixture =
    "Package: libc-bin\nArchitecture: arm64\nVersion: 2.43-2ubuntu2.4\nStatus: install ok installed\n" ++
    "Depends: libc6 (>> 2.43), libc6 (<< 2.44)\n\n" ++
    "Package: libc6\nArchitecture: arm64\nVersion: 2.43-2ubuntu2.4\nStatus: install ok installed\n\n" ++
    "Package: seed\nArchitecture: all\nVersion: 1\nStatus: install ok installed\n\n" ++
    "Package: other\nArchitecture: all\nVersion: 1\nStatus: install ok triggers-pending\nTriggers-Pending: other-trigger\n\n";

test "selected trigger status binds version architecture dependency and one pending callback" {
    var document = try parseStatus(std.testing.allocator, before_fixture);
    defer document.deinit();
    try verifySelectedStatus(document, "arm64", selected_version);
    try std.testing.expectError(error.MissingSelectedTriggerStatus, verifySelectedStatus(document, "amd64", selected_version));
    try std.testing.expectError(error.UnconfiguredTriggerDependency, verifySelectedStatus(document, "arm64", "2.43-2ubuntu2.5"));
    try std.testing.expectError(error.InvalidTriggerStatusDatabase, parseStatus(std.testing.allocator, "Package: libc-bin\npackage: injected\nArchitecture: arm64\nVersion: 1\nStatus: install ok installed\n"));
    try std.testing.expectError(error.AmbiguousTriggerStatusIdentity, parseStatus(std.testing.allocator, before_fixture ++ before_fixture));
}

test "selected trigger transition preserves independent fields unrelated pending handlers and awaited claims" {
    var before = try parseStatus(std.testing.allocator, before_fixture);
    defer before.deinit();
    var after = try parseStatus(std.testing.allocator, after_fixture);
    defer after.deinit();
    try verifyTransition(std.testing.allocator, before, after, "arm64");
    try std.testing.expectError(error.CycleNoProgress, verifyTransition(std.testing.allocator, before, before, "arm64"));
    const changed = try std.mem.replaceOwned(u8, std.testing.allocator, after_fixture, "Depends: libc6 (>> 2.43), libc6 (<< 2.44)", "Depends: libc6");
    defer std.testing.allocator.free(changed);
    var changed_document = try parseStatus(std.testing.allocator, changed);
    defer changed_document.deinit();
    try std.testing.expectError(error.TriggerDatabaseChanged, verifyTransition(std.testing.allocator, before, changed_document, "arm64"));
    const external = try std.mem.replaceOwned(u8, std.testing.allocator, after_fixture, "Status: install ok triggers-pending\nTriggers-Pending: other-trigger", "Status: install ok installed");
    defer std.testing.allocator.free(external);
    var external_document = try parseStatus(std.testing.allocator, external);
    defer external_document.deinit();
    try std.testing.expectError(error.ExternalTriggerCallback, verifyTransition(std.testing.allocator, before, external_document, "arm64"));
}

test "NSS late modules are explicit obligations never implicitly part of ELF DT_NEEDED" {
    const modules = try nssModules(std.testing.allocator, "passwd: files\ngroup: files\nhosts: files dns\nservices: db files\nnetgroup: nis\n");
    defer std.testing.allocator.free(modules);
    try std.testing.expectEqual(@as(usize, 4), modules.len);
    try std.testing.expectEqualStrings("db", modules[2]);
    try std.testing.expectEqualStrings("nis", modules[3]);
    try std.testing.expectError(error.UnreviewedNssClosureAction, nssModules(std.testing.allocator, "hosts: files [NOTFOUND=return] dns\n"));
    try std.testing.expectError(error.UnreviewedNssClosureAction, nssModules(std.testing.allocator, "passwd: ../../injected\n"));
    try std.testing.expectError(error.InvalidNssClosureConfiguration, nssModules(std.testing.allocator, "passwd: files\npasswd: systemd\n"));
}

test "mutating-tool comparison binds exact backup bytes absent state accounts and live metadata" {
    var reference: Capture = .{
        .schema = "io.github.cataggar.debz.reference-mutating-tools-state.v1",
        .version = 1,
        .state = .{ .databases = undefined, .chrony = undefined },
        .accounts = .{ .passwd_base64 = null, .group_base64 = null, .passwd_sha256 = null, .group_sha256 = null },
        .status_base64 = null,
        .status_sha256 = null,
        .trigger_registry = &.{},
        .updates = &.{},
        .observation_only = true,
        .parity_accepted = false,
    };
    for (&reference.state.databases, [_][]const u8{
        "/var/lib/dpkg/diversions", "/var/lib/dpkg/diversions-old", "/var/lib/dpkg/statoverride", "/var/lib/dpkg/statoverride-old",
    }) |*binding, path| binding.* = .{ .path = path, .present = false, .content_base64 = null, .sha256 = null, .mode = null };
    for (&reference.state.chrony, [_][]const u8{ "/etc/chrony/chrony.keys", "/var/lib/chrony", "/var/log/chrony" }) |*binding, path|
        binding.* = .{ .path = path, .present = false };
    try compareCaptures(std.testing.allocator, reference, reference);
    var native = reference;
    native.state.databases[1] = .{
        .path = "/var/lib/dpkg/diversions-old",
        .present = true,
        .content_base64 = "",
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        .mode = 0o644,
    };
    try std.testing.expectError(error.MutatingToolsStateDiffers, compareCaptures(std.testing.allocator, reference, native));
    native.state.databases[1].content_base64 = "eA==";
    try std.testing.expectError(error.MutatingToolsCaptureDigestChanged, compareCaptures(std.testing.allocator, reference, native));
    native = reference;
    native.state.chrony[1] = .{ .path = "/var/lib/chrony", .present = true, .kind = "directory", .mode = 0o750, .uid = 42420, .gid = 42421 };
    reference = native;
    native.state.chrony[1].mode = 0o755;
    try std.testing.expectError(error.MutatingToolsStateDiffers, compareCaptures(std.testing.allocator, reference, native));
    native = reference;
    native.parity_accepted = true;
    try std.testing.expectError(error.InvalidMutatingToolsCapture, compareCaptures(std.testing.allocator, reference, native));
}

test "authority reader rejects missing symlink replaced and post-binding changed inputs without execution" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const relative = try std.fmt.allocPrint(allocator, ".cache/reference-trigger-reader-{d}", .{linux.getpid()});
    defer allocator.free(relative);
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, relative);
    defer cwd.deleteTree(io, relative) catch {};
    var directory = try cwd.openDir(io, relative, .{});
    defer directory.close(io);
    var resolved: [std.fs.max_path_bytes]u8 = undefined;
    const directory_length = try directory.realPath(io, &resolved);
    const absolute = try std.fmt.allocPrint(allocator, "{s}/source", .{resolved[0..directory_length]});
    defer allocator.free(absolute);
    const source = try std.fmt.allocPrint(allocator, "{s}/source", .{relative});
    defer allocator.free(source);
    {
        var reader: Reader = .{ .allocator = allocator, .protected = false };
        defer reader.deinit();
        try std.testing.expectError(error.AuthorityPathRefused, reader.read(absolute, 16));
        try std.testing.expect((try reader.optional(absolute, 16)) == null);
        try cwd.writeFile(io, .{ .sub_path = source, .data = "original" });
        try std.testing.expectError(error.TriggerAuthoritySourceChanged, reader.verify());
    }
    {
        var reader: Reader = .{ .allocator = allocator, .protected = false };
        defer reader.deinit();
        const bytes = try reader.read(absolute, 16);
        defer allocator.free(bytes);
        try reader.verify();
        try cwd.writeFile(io, .{ .sub_path = source, .data = "modified" });
        try std.testing.expectError(error.TriggerAuthoritySourceChanged, reader.verify());
    }
    {
        var reader: Reader = .{ .allocator = allocator, .protected = false };
        defer reader.deinit();
        const bytes = try reader.read(absolute, 16);
        defer allocator.free(bytes);
        const previous = try std.fmt.allocPrint(allocator, "{s}/previous", .{relative});
        defer allocator.free(previous);
        try cwd.rename(source, cwd, previous, io);
        try cwd.writeFile(io, .{ .sub_path = source, .data = bytes });
        try std.testing.expectError(error.TriggerAuthoritySourceChanged, reader.verify());
        try cwd.deleteFile(io, source);
        try cwd.symLink(io, "previous", source, .{});
        try std.testing.expectError(error.AuthorityPathRefused, reader.read(absolute, 16));
    }
}

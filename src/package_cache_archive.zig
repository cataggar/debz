const std = @import("std");
const exact_lock = @import("exact_lock.zig");
const package_acquisition = @import("package_acquisition.zig");

const File = std.Io.File;

pub const format_id = "debz-package-cache-archive-v1";
pub const magic = format_id ++ "\n";
pub const entry_header_bytes: u64 = 32 + 8;
pub const trailer_bytes: u64 = 32;

pub const Limits = struct {
    maximum_objects: usize,
    maximum_object_bytes: usize,
    maximum_total_object_bytes: u64,
};

pub const ImportPolicy = struct {
    repair_corrupt: bool = false,
    require_exact_closure: bool = false,
};

pub const ImportResult = struct {
    imported: usize,
    reused: usize,
    skipped: usize,
    bytes: u64,
};

pub const ExportResult = struct {
    objects: usize,
    bytes: u64,
    archive_bytes: u64,
    content_sha256: [32]u8,
};

pub const Error = error{
    InvalidArchive,
    InvalidArchiveFile,
    ArchiveTooLarge,
    TooManyObjects,
    ObjectTooLarge,
    TotalObjectBytesExceeded,
    DuplicateObject,
    NonCanonicalOrder,
    TruncatedArchive,
    TrailingArchiveData,
    ArchiveDigestMismatch,
    ObjectDigestMismatch,
    LockObjectMismatch,
    CorruptObject,
    InvalidConfiguration,
};

pub fn maximumArchiveBytes(limits: Limits) Error!u64 {
    if (limits.maximum_objects == 0 or
        limits.maximum_object_bytes == 0 or
        limits.maximum_total_object_bytes == 0)
        return error.InvalidConfiguration;
    const headers = std.math.mul(
        u64,
        @intCast(limits.maximum_objects),
        entry_header_bytes,
    ) catch return error.ArchiveTooLarge;
    var total = std.math.add(
        u64,
        @intCast(magic.len + @sizeOf(u32)),
        headers,
    ) catch return error.ArchiveTooLarge;
    total = std.math.add(u64, total, limits.maximum_total_object_bytes) catch
        return error.ArchiveTooLarge;
    return std.math.add(u64, total, trailer_bytes) catch error.ArchiveTooLarge;
}

pub fn importFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive: File,
    cache: *package_acquisition.Cache,
    lock: exact_lock.Lock,
    limits: Limits,
    policy: ImportPolicy,
    writer_lock: *const package_acquisition.Cache.WriterLock,
) !ImportResult {
    if (writer_lock.cache != cache or writer_lock.file == null or
        cache.limits.maximum_object_bytes != limits.maximum_object_bytes)
        return error.InvalidConfiguration;
    const stat = archive.stat(io) catch return error.InvalidArchiveFile;
    if (stat.kind != .file) return error.InvalidArchiveFile;
    const maximum = try maximumArchiveBytes(limits);
    const minimum: u64 = magic.len + @sizeOf(u32) + trailer_bytes;
    if (stat.size < minimum) return error.TruncatedArchive;
    if (stat.size > maximum) return error.ArchiveTooLarge;

    var offset: u64 = 0;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var magic_buffer: [magic.len]u8 = undefined;
    try readHashed(archive, io, &magic_buffer, &offset, &hasher);
    if (!std.mem.eql(u8, &magic_buffer, magic)) return error.InvalidArchive;
    var count_buffer: [4]u8 = undefined;
    try readHashed(archive, io, &count_buffer, &offset, &hasher);
    const count = std.mem.readInt(u32, &count_buffer, .big);
    if (count == 0 or count > limits.maximum_objects) return error.TooManyObjects;

    var lock_by_digest = std.AutoHashMap([32]u8, usize).init(allocator);
    defer lock_by_digest.deinit();
    for (lock.packages, 0..) |package, index| {
        const entry = try lock_by_digest.getOrPut(package.sha256);
        if (entry.found_existing) return error.DuplicateObject;
        entry.value_ptr.* = index;
    }

    var previous_digest: ?[32]u8 = null;
    var total_bytes: u64 = 0;
    const matches = try allocator.alloc(?struct {
        digest: [32]u8,
        size: u64,
        payload_offset: u64,
    }, lock.packages.len);
    defer allocator.free(matches);
    @memset(matches, null);
    var result: ImportResult = .{
        .imported = 0,
        .reused = 0,
        .skipped = 0,
        .bytes = 0,
    };
    var entry_index: u32 = 0;
    while (entry_index < count) : (entry_index += 1) {
        var digest: [32]u8 = undefined;
        try readHashed(archive, io, &digest, &offset, &hasher);
        if (previous_digest) |previous| {
            const order = std.mem.order(u8, &previous, &digest);
            if (order == .eq) return error.DuplicateObject;
            if (order != .lt) return error.NonCanonicalOrder;
        }
        previous_digest = digest;

        var size_buffer: [8]u8 = undefined;
        try readHashed(archive, io, &size_buffer, &offset, &hasher);
        const size = std.mem.readInt(u64, &size_buffer, .big);
        if (size == 0 or size > limits.maximum_object_bytes) return error.ObjectTooLarge;
        total_bytes = std.math.add(u64, total_bytes, size) catch
            return error.TotalObjectBytesExceeded;
        if (total_bytes > limits.maximum_total_object_bytes)
            return error.TotalObjectBytesExceeded;
        const size_usize = std.math.cast(usize, size) orelse return error.ObjectTooLarge;
        const payload_offset = offset;
        const bytes = try allocator.alloc(u8, size_usize);
        defer allocator.free(bytes);
        try readHashed(archive, io, bytes, &offset, &hasher);
        const actual_digest = package_acquisition.Digest.of(bytes);
        if (!std.mem.eql(u8, &actual_digest.bytes, &digest))
            return error.ObjectDigestMismatch;

        const lock_index = lock_by_digest.get(digest) orelse {
            result.skipped += 1;
            continue;
        };
        const locked = lock.packages[lock_index];
        if (locked.declared_size != size) return error.LockObjectMismatch;
        matches[lock_index] = .{
            .digest = digest,
            .size = size,
            .payload_offset = payload_offset,
        };
    }
    result.bytes = total_bytes;

    var expected_digest: [32]u8 = undefined;
    try readExact(archive, io, &expected_digest, &offset);
    const actual_archive_digest = hasher.finalResult();
    if (!std.mem.eql(u8, &actual_archive_digest, &expected_digest))
        return error.ArchiveDigestMismatch;
    if (offset != stat.size) return error.TrailingArchiveData;
    if (policy.require_exact_closure) {
        if (result.skipped != 0 or count != lock.packages.len)
            return error.LockObjectMismatch;
        for (matches) |match| if (match == null) return error.LockObjectMismatch;
    }

    for (matches) |maybe_match| {
        const match = maybe_match orelse continue;
        const size_usize = std.math.cast(usize, match.size) orelse return error.ObjectTooLarge;
        const bytes = try allocator.alloc(u8, size_usize);
        defer allocator.free(bytes);
        var payload_offset = match.payload_offset;
        try readExact(archive, io, bytes, &payload_offset);
        const actual_digest = package_acquisition.Digest.of(bytes);
        if (!std.mem.eql(u8, &actual_digest.bytes, &match.digest))
            return error.ObjectDigestMismatch;
        const object_digest: package_acquisition.Digest = .{ .bytes = match.digest };
        if (cache.lookup(allocator, object_digest, match.size, .verify_sha256)) |existing| {
            allocator.free(existing);
            result.reused += 1;
        } else |err| switch (err) {
            error.CacheMiss => {
                try cache.publish(
                    allocator,
                    object_digest,
                    match.size,
                    bytes,
                    .{ .held = writer_lock },
                    .{},
                );
                result.imported += 1;
            },
            error.CorruptObject => {
                if (!policy.repair_corrupt) return error.CorruptObject;
                result.skipped += 1;
            },
            else => |other| return other,
        }
    }
    return result;
}

pub fn exportFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    output: File,
    cache: *package_acquisition.Cache,
    lock: exact_lock.Lock,
    limits: Limits,
    writer_lock: *const package_acquisition.Cache.WriterLock,
) !ExportResult {
    if (writer_lock.cache != cache or writer_lock.file == null or
        cache.limits.maximum_object_bytes != limits.maximum_object_bytes or
        lock.packages.len == 0 or lock.packages.len > limits.maximum_objects)
        return error.InvalidConfiguration;
    const output_stat = output.stat(io) catch return error.InvalidArchiveFile;
    if (output_stat.kind != .file or output_stat.size != 0)
        return error.InvalidArchiveFile;

    const order = try allocator.alloc(usize, lock.packages.len);
    defer allocator.free(order);
    for (order, 0..) |*value, index| value.* = index;
    std.mem.sort(usize, order, lock, lessPackageDigest);
    for (order[1..], order[0 .. order.len - 1]) |current, previous|
        if (std.mem.eql(
            u8,
            &lock.packages[current].sha256,
            &lock.packages[previous].sha256,
        )) return error.DuplicateObject;

    var expected_size: u64 = magic.len + @sizeOf(u32) + trailer_bytes;
    var total_bytes: u64 = 0;
    for (lock.packages) |package| {
        if (package.declared_size == 0 or package.declared_size > limits.maximum_object_bytes)
            return error.ObjectTooLarge;
        total_bytes = std.math.add(u64, total_bytes, package.declared_size) catch
            return error.TotalObjectBytesExceeded;
        if (total_bytes > limits.maximum_total_object_bytes)
            return error.TotalObjectBytesExceeded;
        expected_size = std.math.add(
            u64,
            expected_size,
            entry_header_bytes + package.declared_size,
        ) catch return error.ArchiveTooLarge;
    }
    if (expected_size > try maximumArchiveBytes(limits)) return error.ArchiveTooLarge;

    var offset: u64 = 0;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    try writeHashed(output, io, magic, &offset, &hasher);
    var count_buffer: [4]u8 = undefined;
    std.mem.writeInt(u32, &count_buffer, @intCast(lock.packages.len), .big);
    try writeHashed(output, io, &count_buffer, &offset, &hasher);
    for (order) |package_index| {
        const package = lock.packages[package_index];
        try writeHashed(output, io, &package.sha256, &offset, &hasher);
        var size_buffer: [8]u8 = undefined;
        std.mem.writeInt(u64, &size_buffer, package.declared_size, .big);
        try writeHashed(output, io, &size_buffer, &offset, &hasher);
        const digest: package_acquisition.Digest = .{ .bytes = package.sha256 };
        const bytes = try cache.lookup(
            allocator,
            digest,
            package.declared_size,
            .verify_sha256,
        );
        defer allocator.free(bytes);
        try writeHashed(output, io, bytes, &offset, &hasher);
    }
    const content_digest = hasher.finalResult();
    try output.writePositionalAll(io, &content_digest, offset);
    offset += content_digest.len;
    if (offset != expected_size) return error.ArchiveTooLarge;
    try output.sync(io);
    return .{
        .objects = lock.packages.len,
        .bytes = total_bytes,
        .archive_bytes = offset,
        .content_sha256 = content_digest,
    };
}

fn readHashed(
    file: File,
    io: std.Io,
    bytes: []u8,
    offset: *u64,
    hasher: *std.crypto.hash.sha2.Sha256,
) !void {
    try readExact(file, io, bytes, offset);
    hasher.update(bytes);
}

fn readExact(file: File, io: std.Io, bytes: []u8, offset: *u64) !void {
    const read = file.readPositionalAll(io, bytes, offset.*) catch
        return error.InvalidArchiveFile;
    if (read != bytes.len) return error.TruncatedArchive;
    offset.* = std.math.add(u64, offset.*, bytes.len) catch
        return error.ArchiveTooLarge;
}

fn writeHashed(
    file: File,
    io: std.Io,
    bytes: []const u8,
    offset: *u64,
    hasher: *std.crypto.hash.sha2.Sha256,
) !void {
    file.writePositionalAll(io, bytes, offset.*) catch
        return error.InvalidArchiveFile;
    offset.* = std.math.add(u64, offset.*, bytes.len) catch
        return error.ArchiveTooLarge;
    hasher.update(bytes);
}

fn lessPackageDigest(lock: exact_lock.Lock, left: usize, right: usize) bool {
    return std.mem.order(
        u8,
        &lock.packages[left].sha256,
        &lock.packages[right].sha256,
    ) == .lt;
}

fn testLock(
    allocator: std.mem.Allocator,
    objects: []const []const u8,
) !exact_lock.OwnedLock {
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(1);
    const packages = try allocator.alloc(exact_lock.Package, objects.len);
    defer allocator.free(packages);
    for (objects, 0..) |bytes, index| {
        packages[index] = .{
            .name = try std.fmt.allocPrint(allocator, "package-{d}", .{index}),
            .version = "1",
            .architecture = "amd64",
            .repository_id = repository_id,
            .repository_snapshot_sha256 = snapshot,
            .sha256 = package_acquisition.Digest.of(bytes).bytes,
            .declared_size = bytes.len,
            .retention = if (index == 0) .requested else .dependency,
            .dpkg_selection_hold = false,
        };
    }
    defer for (packages) |package| allocator.free(package.name);
    return exact_lock.create(allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(2),
        .policy_sha256 = @splat(3),
        .repositories = &.{.{
            .id = repository_id,
            .snapshot_sha256 = snapshot,
            .release_sha256 = @splat(4),
            .index_sha256 = @splat(5),
            .signer_fingerprints = &.{@splat(6)},
        }},
        .packages = packages,
        .authenticated_metadata = true,
    });
}

test "package_cache_archive.test.roundtrip relocates verified objects between cache roots" {
    const objects = [_][]const u8{ "first object", "second object" };
    var lock = try testLock(std.testing.allocator, &objects);
    defer lock.deinit();
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    var source_cache = try package_acquisition.Cache.initFromDir(
        std.testing.io,
        source_tmp.dir,
        .{ .maximum_object_bytes = 1024 },
    );
    defer source_cache.deinit();
    for (objects) |bytes| try source_cache.publish(
        std.testing.allocator,
        package_acquisition.Digest.of(bytes),
        bytes.len,
        bytes,
        .fail_fast,
        .{},
    );
    var source_writer = try source_cache.acquireWriter(10);
    defer source_writer.release();
    var archive = try source_tmp.dir.createFile(std.testing.io, "cache.archive", .{
        .exclusive = true,
        .read = true,
    });
    defer archive.close(std.testing.io);
    const limits: Limits = .{
        .maximum_objects = 10,
        .maximum_object_bytes = 1024,
        .maximum_total_object_bytes = 4096,
    };
    const exported = try exportFile(
        std.testing.allocator,
        std.testing.io,
        archive,
        &source_cache,
        lock.lock,
        limits,
        &source_writer,
    );
    try std.testing.expectEqual(@as(usize, 2), exported.objects);

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();
    var target_cache = try package_acquisition.Cache.initFromDir(
        std.testing.io,
        target_tmp.dir,
        .{ .maximum_object_bytes = 1024 },
    );
    defer target_cache.deinit();
    var target_writer = try target_cache.acquireWriter(10);
    defer target_writer.release();
    const imported = try importFile(
        std.testing.allocator,
        std.testing.io,
        archive,
        &target_cache,
        lock.lock,
        limits,
        .{},
        &target_writer,
    );
    try std.testing.expectEqual(@as(usize, 2), imported.imported);
    for (objects) |expected| {
        const bytes = try target_cache.lookup(
            std.testing.allocator,
            package_acquisition.Digest.of(expected),
            expected.len,
            .verify_sha256,
        );
        defer std.testing.allocator.free(bytes);
        try std.testing.expectEqualStrings(expected, bytes);
    }
}

test "package_cache_archive.test.tar path link and special entries are never interpreted" {
    const hostile = [_]struct {
        name: []const u8,
        kind: u8,
        link: []const u8,
    }{
        .{ .name = "/absolute/tool/debz", .kind = '0', .link = "" },
        .{ .name = "../../workspace/credential", .kind = '0', .link = "" },
        .{ .name = "symlink", .kind = '2', .link = "../../tool/debz" },
        .{ .name = "hardlink", .kind = '1', .link = "/etc/passwd" },
        .{ .name = "character-device", .kind = '3', .link = "" },
        .{ .name = "fifo", .kind = '6', .link = "" },
    };
    var lock = try testLock(std.testing.allocator, &.{"expected"});
    defer lock.deinit();
    for (hostile) |entry| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var cache = try package_acquisition.Cache.initFromDir(
            std.testing.io,
            tmp.dir,
            .{ .maximum_object_bytes = 1024 },
        );
        defer cache.deinit();
        try tmp.dir.writeFile(std.testing.io, .{
            .sub_path = "victim",
            .data = "unchanged",
        });
        var writer = try cache.acquireWriter(10);
        defer writer.release();
        var archive = try tmp.dir.createFile(std.testing.io, "hostile.tar", .{
            .exclusive = true,
            .read = true,
        });
        defer archive.close(std.testing.io);
        var tar: [1024]u8 = @splat(0);
        @memcpy(tar[0..entry.name.len], entry.name);
        tar[156] = entry.kind;
        @memcpy(tar[157..][0..entry.link.len], entry.link);
        @memcpy(tar[257..263], "ustar\x00");
        try archive.writeStreamingAll(std.testing.io, &tar);
        try std.testing.expectError(error.InvalidArchive, importFile(
            std.testing.allocator,
            std.testing.io,
            archive,
            &cache,
            lock.lock,
            .{
                .maximum_objects = 10,
                .maximum_object_bytes = 1024,
                .maximum_total_object_bytes = 4096,
            },
            .{},
            &writer,
        ));
        try std.testing.expectEqual(
            @as(?u64, null),
            try cache.objectSize(package_acquisition.Digest.of("expected")),
        );
        const victim = try tmp.dir.readFileAlloc(
            std.testing.io,
            "victim",
            std.testing.allocator,
            .limited(16),
        );
        defer std.testing.allocator.free(victim);
        try std.testing.expectEqualStrings("unchanged", victim);
    }
}

test "package_cache_archive.test.corrupt prefix archive imports no object" {
    const object = "verified object";
    var lock = try testLock(std.testing.allocator, &.{object});
    defer lock.deinit();
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    var source_cache = try package_acquisition.Cache.initFromDir(
        std.testing.io,
        source_tmp.dir,
        .{ .maximum_object_bytes = 1024 },
    );
    defer source_cache.deinit();
    try source_cache.publish(
        std.testing.allocator,
        package_acquisition.Digest.of(object),
        object.len,
        object,
        .fail_fast,
        .{},
    );
    var source_writer = try source_cache.acquireWriter(10);
    defer source_writer.release();
    var archive = try source_tmp.dir.createFile(std.testing.io, "cache.archive", .{
        .exclusive = true,
        .read = true,
    });
    defer archive.close(std.testing.io);
    const limits: Limits = .{
        .maximum_objects = 10,
        .maximum_object_bytes = 1024,
        .maximum_total_object_bytes = 4096,
    };
    _ = try exportFile(
        std.testing.allocator,
        std.testing.io,
        archive,
        &source_cache,
        lock.lock,
        limits,
        &source_writer,
    );
    try archive.writePositionalAll(std.testing.io, "X", magic.len + 4 + entry_header_bytes);

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();
    var target_cache = try package_acquisition.Cache.initFromDir(
        std.testing.io,
        target_tmp.dir,
        .{ .maximum_object_bytes = 1024 },
    );
    defer target_cache.deinit();
    var target_writer = try target_cache.acquireWriter(10);
    defer target_writer.release();
    try std.testing.expectError(error.ObjectDigestMismatch, importFile(
        std.testing.allocator,
        std.testing.io,
        archive,
        &target_cache,
        lock.lock,
        limits,
        .{},
        &target_writer,
    ));
    try std.testing.expectEqual(
        @as(?u64, null),
        try target_cache.objectSize(package_acquisition.Digest.of(object)),
    );
}

const TestArchiveEntry = struct {
    digest: [32]u8,
    bytes: []const u8,
};

test "package_cache_archive.test.duplicate and noncanonical objects are rejected" {
    var lock = try testLock(std.testing.allocator, &.{ "a", "b" });
    defer lock.deinit();
    const digest_a = package_acquisition.Digest.of("a").bytes;
    const digest_b = package_acquisition.Digest.of("b").bytes;
    const cases = [_]struct {
        entries: [2]TestArchiveEntry,
        expected: anyerror,
    }{
        .{
            .entries = .{
                .{ .digest = digest_a, .bytes = "a" },
                .{ .digest = digest_a, .bytes = "a" },
            },
            .expected = error.DuplicateObject,
        },
        .{
            .entries = if (std.mem.order(u8, &digest_a, &digest_b) == .gt)
                .{
                    .{ .digest = digest_a, .bytes = "a" },
                    .{ .digest = digest_b, .bytes = "b" },
                }
            else
                .{
                    .{ .digest = digest_b, .bytes = "b" },
                    .{ .digest = digest_a, .bytes = "a" },
                },
            .expected = error.NonCanonicalOrder,
        },
    };
    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var cache = try package_acquisition.Cache.initFromDir(
            std.testing.io,
            tmp.dir,
            .{ .maximum_object_bytes = 1024 },
        );
        defer cache.deinit();
        var writer = try cache.acquireWriter(10);
        defer writer.release();
        var archive = try tmp.dir.createFile(std.testing.io, "cache.archive", .{
            .exclusive = true,
            .read = true,
        });
        defer archive.close(std.testing.io);
        try writeTestArchive(archive, &case.entries);
        try std.testing.expectError(case.expected, importFile(
            std.testing.allocator,
            std.testing.io,
            archive,
            &cache,
            lock.lock,
            .{
                .maximum_objects = 10,
                .maximum_object_bytes = 1024,
                .maximum_total_object_bytes = 4096,
            },
            .{},
            &writer,
        ));
    }
}

test "package_cache_archive.test.object count and expanded bytes are bounded before allocation" {
    var lock = try testLock(std.testing.allocator, &.{"expected"});
    defer lock.deinit();
    const limits: Limits = .{
        .maximum_objects = 1,
        .maximum_object_bytes = 16,
        .maximum_total_object_bytes = 16,
    };
    const cases = [_]struct {
        count: u32,
        size: u64,
        expected: anyerror,
    }{
        .{ .count = 2, .size = 0, .expected = error.TooManyObjects },
        .{ .count = 1, .size = 17, .expected = error.ObjectTooLarge },
    };
    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var cache = try package_acquisition.Cache.initFromDir(
            std.testing.io,
            tmp.dir,
            .{ .maximum_object_bytes = 16 },
        );
        defer cache.deinit();
        var writer = try cache.acquireWriter(10);
        defer writer.release();
        var archive = try tmp.dir.createFile(std.testing.io, "bounded.cache", .{
            .exclusive = true,
            .read = true,
        });
        defer archive.close(std.testing.io);
        var offset: u64 = 0;
        try archive.writePositionalAll(std.testing.io, magic, offset);
        offset += magic.len;
        var count_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &count_bytes, case.count, .big);
        try archive.writePositionalAll(std.testing.io, &count_bytes, offset);
        offset += count_bytes.len;
        if (case.count == 1) {
            const digest: [32]u8 = @splat(1);
            try archive.writePositionalAll(std.testing.io, &digest, offset);
            offset += 32;
            var size_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &size_bytes, case.size, .big);
            try archive.writePositionalAll(std.testing.io, &size_bytes, offset);
            offset += size_bytes.len;
        }
        const minimum = magic.len + @sizeOf(u32) + trailer_bytes;
        if (offset < minimum) {
            const padding = try std.testing.allocator.alloc(u8, @intCast(minimum - offset));
            defer std.testing.allocator.free(padding);
            @memset(padding, 0);
            try archive.writePositionalAll(std.testing.io, padding, offset);
        }
        try std.testing.expectError(case.expected, importFile(
            std.testing.allocator,
            std.testing.io,
            archive,
            &cache,
            lock.lock,
            limits,
            .{},
            &writer,
        ));
    }
}

test "package_cache_archive.test.exact restore requires the complete lock and imports nothing" {
    var lock = try testLock(std.testing.allocator, &.{ "a", "b" });
    defer lock.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try package_acquisition.Cache.initFromDir(
        std.testing.io,
        tmp.dir,
        .{ .maximum_object_bytes = 16 },
    );
    defer cache.deinit();
    var writer = try cache.acquireWriter(10);
    defer writer.release();
    var archive = try tmp.dir.createFile(std.testing.io, "incomplete.cache", .{
        .exclusive = true,
        .read = true,
    });
    defer archive.close(std.testing.io);
    const entry = TestArchiveEntry{
        .digest = package_acquisition.Digest.of("a").bytes,
        .bytes = "a",
    };
    try writeTestArchive(archive, &.{entry});
    try std.testing.expectError(error.LockObjectMismatch, importFile(
        std.testing.allocator,
        std.testing.io,
        archive,
        &cache,
        lock.lock,
        .{
            .maximum_objects = 10,
            .maximum_object_bytes = 16,
            .maximum_total_object_bytes = 32,
        },
        .{ .require_exact_closure = true },
        &writer,
    ));
    try std.testing.expectEqual(
        @as(?u64, null),
        try cache.objectSize(package_acquisition.Digest.of("a")),
    );
}

fn writeTestArchive(
    file: File,
    entries: []const TestArchiveEntry,
) !void {
    var offset: u64 = 0;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    try writeHashed(file, std.testing.io, magic, &offset, &hasher);
    var count_buffer: [4]u8 = undefined;
    std.mem.writeInt(u32, &count_buffer, @intCast(entries.len), .big);
    try writeHashed(file, std.testing.io, &count_buffer, &offset, &hasher);
    for (entries) |entry| {
        try writeHashed(file, std.testing.io, &entry.digest, &offset, &hasher);
        var size_buffer: [8]u8 = undefined;
        std.mem.writeInt(u64, &size_buffer, entry.bytes.len, .big);
        try writeHashed(file, std.testing.io, &size_buffer, &offset, &hasher);
        try writeHashed(file, std.testing.io, entry.bytes, &offset, &hasher);
    }
    const digest = hasher.finalResult();
    try file.writePositionalAll(std.testing.io, &digest, offset);
}

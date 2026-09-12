const std = @import("std");
const exact_lock = @import("exact_lock.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const package_acquisition = @import("package_acquisition.zig");

const File = std.Io.File;

pub const format_id = "debz-package-cache-archive-v1";
pub const magic = format_id ++ "\n";
pub const native_format_id = "debz-package-cache-archive-v2";
pub const native_magic = native_format_id ++ "\n";
pub const entry_header_bytes: u64 = 32 + 8;
pub const trailer_bytes: u64 = 32;

const Version = enum { v1, v2 };

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
    return maximumBytes(.v1, limits);
}

pub fn maximumNativeArchiveBytes(limits: Limits) Error!u64 {
    return maximumBytes(.v2, limits);
}

fn maximumBytes(comptime version: Version, limits: Limits) Error!u64 {
    const header = if (version == .v1) magic else native_magic;
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
        @intCast(header.len + @sizeOf(u32)),
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
    return importVersion(.v1, allocator, io, archive, cache, lock, limits, policy, writer_lock);
}

pub fn importNativeFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive: File,
    cache: *package_acquisition.Cache,
    lock: exact_lock_v2.Lock,
    limits: Limits,
    policy: ImportPolicy,
    writer_lock: *const package_acquisition.Cache.WriterLock,
) !ImportResult {
    return importVersion(.v2, allocator, io, archive, cache, lock, limits, policy, writer_lock);
}

fn importVersion(
    comptime version: Version,
    allocator: std.mem.Allocator,
    io: std.Io,
    archive: File,
    cache: *package_acquisition.Cache,
    lock: if (version == .v1) exact_lock.Lock else exact_lock_v2.Lock,
    limits: Limits,
    policy: ImportPolicy,
    writer_lock: *const package_acquisition.Cache.WriterLock,
) !ImportResult {
    const header = if (version == .v1) magic else native_magic;
    if (writer_lock.cache != cache or writer_lock.file == null or
        cache.limits.maximum_object_bytes != limits.maximum_object_bytes)
        return error.InvalidConfiguration;
    const stat = archive.stat(io) catch return error.InvalidArchiveFile;
    if (stat.kind != .file) return error.InvalidArchiveFile;
    const maximum = try maximumBytes(version, limits);
    const minimum: u64 = header.len + @sizeOf(u32) + trailer_bytes;
    if (stat.size < minimum) return error.TruncatedArchive;
    if (stat.size > maximum) return error.ArchiveTooLarge;

    var offset: u64 = 0;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var magic_buffer: [header.len]u8 = undefined;
    try readHashed(archive, io, &magic_buffer, &offset, &hasher);
    if (!std.mem.eql(u8, &magic_buffer, header)) return error.InvalidArchive;
    var count_buffer: [4]u8 = undefined;
    try readHashed(archive, io, &count_buffer, &offset, &hasher);
    const count = std.mem.readInt(u32, &count_buffer, .big);
    if ((version == .v1 and count == 0) or count > limits.maximum_objects)
        return error.TooManyObjects;

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
    return exportVersion(.v1, allocator, io, output, cache, lock, limits, writer_lock);
}

pub fn exportNativeFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    output: File,
    cache: *package_acquisition.Cache,
    lock: exact_lock_v2.Lock,
    limits: Limits,
    writer_lock: *const package_acquisition.Cache.WriterLock,
) !ExportResult {
    return exportVersion(.v2, allocator, io, output, cache, lock, limits, writer_lock);
}

fn exportVersion(
    comptime version: Version,
    allocator: std.mem.Allocator,
    io: std.Io,
    output: File,
    cache: *package_acquisition.Cache,
    lock: if (version == .v1) exact_lock.Lock else exact_lock_v2.Lock,
    limits: Limits,
    writer_lock: *const package_acquisition.Cache.WriterLock,
) !ExportResult {
    const header = if (version == .v1) magic else native_magic;
    if (writer_lock.cache != cache or writer_lock.file == null or
        cache.limits.maximum_object_bytes != limits.maximum_object_bytes or
        (version == .v1 and lock.packages.len == 0) or lock.packages.len > limits.maximum_objects)
        return error.InvalidConfiguration;
    const output_stat = output.stat(io) catch return error.InvalidArchiveFile;
    if (output_stat.kind != .file or output_stat.size != 0)
        return error.InvalidArchiveFile;

    const order = try allocator.alloc(usize, lock.packages.len);
    defer allocator.free(order);
    for (order, 0..) |*value, index| value.* = index;
    std.mem.sort(usize, order, lock, struct {
        fn less(context: @TypeOf(lock), left: usize, right: usize) bool {
            return std.mem.order(u8, &context.packages[left].sha256, &context.packages[right].sha256) == .lt;
        }
    }.less);
    if (order.len > 1) for (order[1..], order[0 .. order.len - 1]) |current, previous|
        if (std.mem.eql(
            u8,
            &lock.packages[current].sha256,
            &lock.packages[previous].sha256,
        )) return error.DuplicateObject;

    var expected_size: u64 = header.len + @sizeOf(u32) + trailer_bytes;
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
    if (expected_size > try maximumBytes(version, limits)) return error.ArchiveTooLarge;

    var offset: u64 = 0;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    try writeHashed(output, io, header, &offset, &hasher);
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

fn testNativeLock(
    allocator: std.mem.Allocator,
    objects: []const []const u8,
) !exact_lock_v2.OwnedLock {
    const package_origin = @import("package_origin.zig");
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(1);
    const packages = try temporary.alloc(exact_lock_v2.Package, objects.len);
    var artifacts: std.ArrayList(package_origin.LocalArtifactEvidence) = .empty;
    for (objects, 0..) |bytes, index| {
        const name = try std.fmt.allocPrint(temporary, "package-{d}", .{index});
        const digest = package_acquisition.Digest.of(bytes).bytes;
        const origin: exact_lock_v2.PackageOrigin = if (index % 2 == 0)
            .{ .authenticated_repository = .{
                .repository_id = repository_id,
                .repository_snapshot_sha256 = snapshot,
            } }
        else local: {
            const artifact: package_origin.LocalArtifactEvidence = .{
                .artifact_id = package_origin.artifactIdFromSha256(digest),
                .sha256 = digest,
                .size = bytes.len,
                .package = name,
                .version = "1",
                .architecture = "amd64",
                .acquisition_url = "https://example.test/artifact.deb",
                .trust_mode = .verified_https,
            };
            try artifacts.append(temporary, artifact);
            break :local .{ .local_artifact = artifact };
        };
        packages[index] = .{
            .name = name,
            .version = "1",
            .architecture = "amd64",
            .origin = origin,
            .sha256 = digest,
            .declared_size = bytes.len,
            .retention = .requested,
            .dpkg_selection_hold = false,
        };
    }
    return exact_lock_v2.create(allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(2),
        .policy_sha256 = @splat(3),
        .repositories = if (objects.len == 0) &.{} else &.{.{
            .id = repository_id,
            .snapshot_sha256 = snapshot,
            .release_sha256 = @splat(4),
            .index_sha256 = @splat(5),
            .signer_fingerprints = &.{@splat(6)},
        }},
        .local_artifacts = artifacts.items,
        .packages = packages,
        .verified_origins = true,
    });
}

test "package_cache_archive.test.native roundtrip preserves mixed and empty v2 closures" {
    const objects = [_][]const u8{ "first object", "second object" };
    const limits: Limits = .{
        .maximum_objects = 10,
        .maximum_object_bytes = 1024,
        .maximum_total_object_bytes = 4096,
    };
    var legacy = try testLock(std.testing.allocator, &objects);
    defer legacy.deinit();
    for (0..objects.len + 1) |count| {
        var lock = try testNativeLock(std.testing.allocator, objects[0..count]);
        defer lock.deinit();
        const lock_digest = lock.lock.digest_sha256;
        var source_tmp = std.testing.tmpDir(.{});
        defer source_tmp.cleanup();
        var source_cache = try package_acquisition.Cache.initFromDir(
            std.testing.io,
            source_tmp.dir,
            .{ .maximum_object_bytes = limits.maximum_object_bytes },
        );
        defer source_cache.deinit();
        for (objects[0..count]) |bytes| try source_cache.publish(
            std.testing.allocator,
            package_acquisition.Digest.of(bytes),
            bytes.len,
            bytes,
            .fail_fast,
            .{},
        );
        var source_writer = try source_cache.acquireWriter(10);
        defer source_writer.release();
        var archive = try source_tmp.dir.createFile(std.testing.io, "native.archive", .{
            .exclusive = true,
            .read = true,
        });
        defer archive.close(std.testing.io);
        const exported = try exportNativeFile(
            std.testing.allocator,
            std.testing.io,
            archive,
            &source_cache,
            lock.lock,
            limits,
            &source_writer,
        );
        try std.testing.expectEqual(count, exported.objects);
        const encoded = try source_tmp.dir.readFileAlloc(
            std.testing.io,
            "native.archive",
            std.testing.allocator,
            .limited(4096),
        );
        defer std.testing.allocator.free(encoded);
        try std.testing.expect(std.mem.startsWith(u8, encoded, "debz-package-cache-archive-v2\n"));
        try std.testing.expectEqual(@as(u32, @intCast(count)), std.mem.readInt(u32, encoded[native_magic.len..][0..4], .big));
        try std.testing.expectEqual(exported.archive_bytes, encoded.len);
        const digest = package_acquisition.Digest.of(encoded[0 .. encoded.len - trailer_bytes]);
        try std.testing.expectEqualSlices(u8, &digest.bytes, &exported.content_sha256);
        try std.testing.expectEqualSlices(u8, &digest.bytes, encoded[encoded.len - trailer_bytes ..]);
        try std.testing.expect(exported.archive_bytes <= try maximumNativeArchiveBytes(limits));
        if (count == 0) {
            try std.testing.expectEqual(@as(u64, native_magic.len + 4 + trailer_bytes), exported.archive_bytes);
            try std.testing.expectEqual(@as(u64, 0), exported.bytes);
        }
        var target_tmp = std.testing.tmpDir(.{});
        defer target_tmp.cleanup();
        var target_cache = try package_acquisition.Cache.initFromDir(
            std.testing.io,
            target_tmp.dir,
            .{ .maximum_object_bytes = limits.maximum_object_bytes },
        );
        defer target_cache.deinit();
        var target_writer = try target_cache.acquireWriter(10);
        defer target_writer.release();
        try std.testing.expectError(error.InvalidArchive, importFile(
            std.testing.allocator,
            std.testing.io,
            archive,
            &target_cache,
            legacy.lock,
            limits,
            .{},
            &target_writer,
        ));
        if (count != 0) {
            var empty_lock = try testNativeLock(std.testing.allocator, &.{});
            defer empty_lock.deinit();
            try std.testing.expectError(error.LockObjectMismatch, importNativeFile(
                std.testing.allocator,
                std.testing.io,
                archive,
                &target_cache,
                empty_lock.lock,
                limits,
                .{ .require_exact_closure = true },
                &target_writer,
            ));
        }
        const imported = try importNativeFile(
            std.testing.allocator,
            std.testing.io,
            archive,
            &target_cache,
            lock.lock,
            limits,
            .{ .require_exact_closure = true },
            &target_writer,
        );
        try std.testing.expectEqual(count, imported.imported);
        try std.testing.expectEqual(@as(usize, 0), imported.skipped);
        const repeated = try importNativeFile(
            std.testing.allocator,
            std.testing.io,
            archive,
            &target_cache,
            lock.lock,
            limits,
            .{ .require_exact_closure = true },
            &target_writer,
        );
        try std.testing.expectEqual(@as(usize, 0), repeated.imported);
        try std.testing.expectEqual(count, repeated.reused);
        for (objects[0..count]) |expected| {
            const actual = try target_cache.lookup(
                std.testing.allocator,
                package_acquisition.Digest.of(expected),
                expected.len,
                .verify_sha256,
            );
            defer std.testing.allocator.free(actual);
            try std.testing.expectEqualStrings(expected, actual);
        }
        try std.testing.expectEqual(lock_digest, lock.lock.digest_sha256);
        if (count == 2) {
            try std.testing.expect(lock.lock.packages[0].origin == .authenticated_repository);
            try std.testing.expect(lock.lock.packages[1].origin == .local_artifact);
            var subset = try testNativeLock(std.testing.allocator, objects[0..1]);
            defer subset.deinit();
            var partial_tmp = std.testing.tmpDir(.{});
            defer partial_tmp.cleanup();
            var partial_cache = try package_acquisition.Cache.initFromDir(
                std.testing.io,
                partial_tmp.dir,
                .{ .maximum_object_bytes = limits.maximum_object_bytes },
            );
            defer partial_cache.deinit();
            var partial_writer = try partial_cache.acquireWriter(10);
            defer partial_writer.release();
            const partial = try importNativeFile(
                std.testing.allocator,
                std.testing.io,
                archive,
                &partial_cache,
                subset.lock,
                limits,
                .{},
                &partial_writer,
            );
            try std.testing.expectEqual(@as(usize, 1), partial.imported);
            try std.testing.expectEqual(@as(usize, 1), partial.skipped);
            try std.testing.expectEqual(@as(?u64, null), try partial_cache.objectSize(package_acquisition.Digest.of(objects[1])));
        }
    }
}

test "package_cache_archive.test.native import does not autodetect legacy archives" {
    var native_lock = try testNativeLock(std.testing.allocator, &.{"object"});
    defer native_lock.deinit();
    var legacy_lock = try testLock(std.testing.allocator, &.{"object"});
    defer legacy_lock.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try package_acquisition.Cache.initFromDir(std.testing.io, tmp.dir, .{ .maximum_object_bytes = 1024 });
    defer cache.deinit();
    var writer = try cache.acquireWriter(10);
    defer writer.release();
    var archive = try tmp.dir.createFile(std.testing.io, "legacy.archive", .{ .exclusive = true, .read = true });
    defer archive.close(std.testing.io);
    const digest = package_acquisition.Digest.of("object");
    try writeTestArchive(archive, &.{.{ .digest = digest.bytes, .bytes = "object" }});
    const limits: Limits = .{ .maximum_objects = 10, .maximum_object_bytes = 1024, .maximum_total_object_bytes = 4096 };
    try std.testing.expectError(error.InvalidArchive, importNativeFile(
        std.testing.allocator,
        std.testing.io,
        archive,
        &cache,
        native_lock.lock,
        limits,
        .{},
        &writer,
    ));
    try std.testing.expectEqual(@as(?u64, null), try cache.objectSize(digest));
    const imported = try importFile(
        std.testing.allocator,
        std.testing.io,
        archive,
        &cache,
        legacy_lock.lock,
        limits,
        .{},
        &writer,
    );
    try std.testing.expectEqual(@as(usize, 1), imported.imported);
    var empty_lock = try testLock(std.testing.allocator, &.{});
    defer empty_lock.deinit();
    var empty_archive = try tmp.dir.createFile(std.testing.io, "empty.archive", .{ .exclusive = true, .read = true });
    defer empty_archive.close(std.testing.io);
    try std.testing.expectError(error.InvalidConfiguration, exportFile(
        std.testing.allocator,
        std.testing.io,
        empty_archive,
        &cache,
        empty_lock.lock,
        limits,
        &writer,
    ));
    try std.testing.expectEqual(@as(u64, 0), (try empty_archive.stat(std.testing.io)).size);
    try writeTestArchive(empty_archive, &.{});
    try std.testing.expectError(error.TooManyObjects, importFile(
        std.testing.allocator,
        std.testing.io,
        empty_archive,
        &cache,
        empty_lock.lock,
        limits,
        .{},
        &writer,
    ));
}

test "package_cache_archive.test.native invalid closures publish no objects" {
    const objects = [_][]const u8{ "first object", "second object" };
    var lock = try testNativeLock(std.testing.allocator, &objects);
    defer lock.deinit();
    const limits: Limits = .{ .maximum_objects = 10, .maximum_object_bytes = 1024, .maximum_total_object_bytes = 4096 };
    const Fault = enum { empty, missing, extra, duplicate, reversed, trailer, trailing, count, size, released_writer };
    for ([_]Fault{ .empty, .missing, .extra, .duplicate, .reversed, .trailer, .trailing, .count, .size, .released_writer }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var cache = try package_acquisition.Cache.initFromDir(std.testing.io, tmp.dir, .{ .maximum_object_bytes = 1024 });
        defer cache.deinit();
        var writer = try cache.acquireWriter(10);
        defer writer.release();
        var archive = try tmp.dir.createFile(std.testing.io, "native.archive", .{ .exclusive = true, .read = true });
        defer archive.close(std.testing.io);
        var entries = [_]TestArchiveEntry{
            .{ .digest = package_acquisition.Digest.of(objects[0]).bytes, .bytes = objects[0] },
            .{ .digest = package_acquisition.Digest.of(objects[1]).bytes, .bytes = objects[1] },
            .{ .digest = package_acquisition.Digest.of("extra").bytes, .bytes = "extra" },
        };
        const length: usize = switch (fault) {
            .empty => 0,
            .missing => 1,
            .extra => 3,
            else => 2,
        };
        std.mem.sort(TestArchiveEntry, entries[0..length], {}, struct {
            fn less(_: void, left: TestArchiveEntry, right: TestArchiveEntry) bool {
                return std.mem.order(u8, &left.digest, &right.digest) == .lt;
            }
        }.less);
        if (fault == .duplicate) entries[1] = entries[0];
        if (fault == .reversed) std.mem.swap(TestArchiveEntry, &entries[0], &entries[1]);
        try writeTestArchiveVersion(.v2, archive, entries[0..length]);
        if (fault == .trailer) {
            const end = (try archive.stat(std.testing.io)).size;
            var last: [1]u8 = undefined;
            try std.testing.expectEqual(@as(usize, 1), try archive.readPositionalAll(std.testing.io, &last, end - 1));
            last[0] ^= 1;
            try archive.writePositionalAll(std.testing.io, &last, end - 1);
        }
        if (fault == .trailing)
            try archive.writePositionalAll(std.testing.io, "x", (try archive.stat(std.testing.io)).size);
        var actual_limits = limits;
        if (fault == .count) actual_limits.maximum_objects = 1;
        var packages = [_]exact_lock_v2.Package{ lock.lock.packages[0], lock.lock.packages[1] };
        var actual_lock = lock.lock;
        if (fault == .size) {
            packages[0].declared_size += 1;
            actual_lock.packages = &packages;
        }
        if (fault == .released_writer) writer.release();
        const expected = switch (fault) {
            .empty, .missing, .extra, .size => error.LockObjectMismatch,
            .duplicate => error.DuplicateObject,
            .reversed => error.NonCanonicalOrder,
            .trailer => error.ArchiveDigestMismatch,
            .trailing => error.TrailingArchiveData,
            .count => error.TooManyObjects,
            .released_writer => error.InvalidConfiguration,
        };
        try std.testing.expectError(expected, importNativeFile(
            std.testing.allocator,
            std.testing.io,
            archive,
            &cache,
            actual_lock,
            actual_limits,
            .{ .require_exact_closure = true },
            &writer,
        ));
        for (objects) |object|
            try std.testing.expectEqual(@as(?u64, null), try cache.objectSize(package_acquisition.Digest.of(object)));
    }
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
    return writeTestArchiveVersion(.v1, file, entries);
}

fn writeTestArchiveVersion(
    comptime version: Version,
    file: File,
    entries: []const TestArchiveEntry,
) !void {
    const header = if (version == .v1) magic else native_magic;
    var offset: u64 = 0;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    try writeHashed(file, std.testing.io, header, &offset, &hasher);
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

const std = @import("std");
const debz = @import("debz");
const locks = debz.exact_lock_v3;
const fs = debz.root_fs;

fn emptyLock(allocator: std.mem.Allocator, source: []const u8) ![]u8 {
    var original = try locks.decode(allocator, source, locks.maximum_document_bytes);
    defer original.deinit();
    var request: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("native-action-empty-cache", &request, .{});
    var empty = try locks.create(allocator, .{
        .target_architecture = original.lock.target_architecture,
        .request_sha256 = request,
        .policy_sha256 = original.lock.policy_sha256,
        .repositories = &.{},
        .local_artifacts = &.{},
        .packages = &.{},
        .verified_origins = true,
    });
    defer empty.deinit();
    return empty.lock.canonicalJson(allocator);
}

fn generate(io: std.Io, allocator: std.mem.Allocator, source: []const u8, destination: []const u8) !void {
    if (!std.fs.path.isAbsolute(source) or !std.fs.path.isAbsolute(destination))
        return error.AbsoluteFixturePathsRequired;
    var input = try fs.openAbsoluteRoot(io, std.fs.path.dirname(source) orelse return error.InvalidFixturePath);
    defer input.close();
    var file = try input.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(source)));
    defer file.close();
    const observed = try file.observeStableAlloc(allocator, locks.maximum_document_bytes);
    defer allocator.free(observed.bytes);
    if (observed.entry.link_count != 1) return error.HardLinkedFixtureSource;
    const bytes = try emptyLock(allocator, observed.bytes);
    defer allocator.free(bytes);
    var output = try fs.openAbsoluteRoot(io, std.fs.path.dirname(destination) orelse return error.InvalidFixturePath);
    defer output.close();
    try output.root.publishFile(try fs.Path.init(std.fs.path.basename(destination)), bytes, .{
        .permissions = .fromMode(0o644),
        .overwrite = .fail_if_exists,
    });
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const source = args.next() orelse return error.MissingFixtureArgument;
    const destination = args.next() orelse return error.MissingFixtureArgument;
    if (args.next() != null) return error.UnexpectedFixtureArgument;
    try generate(init.io, init.arena.allocator(), source, destination);
}

fn sourceFixture(architecture: []const u8) ![]u8 {
    const repository: locks.Repository = .{
        .id = @splat('a'),
        .snapshot_sha256 = @splat(3),
        .release_sha256 = @splat(4),
        .index_identity = .{ .digests = .{ .sha256 = @splat(5) }, .primary = .sha256 },
        .signer_fingerprints = &.{@splat(6)},
    };
    const identity: debz.content_digest.Identity = .{
        .digests = .{ .sha256 = @splat(7) },
        .primary = .sha256,
    };
    const artifact: debz.package_origin.LocalArtifactEvidenceV2 = .{
        .artifact_id = debz.package_origin.artifactIdFromIdentity(identity),
        .archive_identity = identity,
        .size = 42,
        .package = "fixture-local",
        .version = "1",
        .architecture = "all",
        .acquisition_url = "https://example.test/fixture.deb",
        .trust_mode = .verified_https,
    };
    const packages = [_]locks.Package{
        .{
            .name = "fixture-dependency",
            .version = "2",
            .architecture = architecture,
            .origin = .{ .authenticated_repository = .{
                .repository_id = repository.id,
                .repository_snapshot_sha256 = repository.snapshot_sha256,
            } },
            .archive_identity = .{ .digests = .{ .sha256 = @splat(8) }, .primary = .sha256 },
            .declared_size = 12,
            .retention = .dependency,
            .dpkg_selection_hold = false,
        },
        .{
            .name = artifact.package,
            .version = artifact.version,
            .architecture = artifact.architecture,
            .origin = .{ .local_artifact = artifact },
            .archive_identity = artifact.archive_identity,
            .declared_size = artifact.size,
            .retention = .requested,
            .dpkg_selection_hold = true,
        },
    };
    var original = try locks.create(std.testing.allocator, .{
        .target_architecture = architecture,
        .request_sha256 = [_]u8{1} ** 32,
        .policy_sha256 = [_]u8{2} ** 32,
        .repositories = &.{repository},
        .local_artifacts = &.{artifact},
        .packages = &packages,
        .verified_origins = true,
    });
    defer original.deinit();
    return original.lock.canonicalJson(std.testing.allocator);
}

test "native action empty lock preserves policy and architecture with deterministic canonical identity" {
    for ([_][]const u8{ "amd64", "arm64" }) |architecture| {
        const source = try sourceFixture(architecture);
        defer std.testing.allocator.free(source);
        const bytes = try emptyLock(std.testing.allocator, source);
        defer std.testing.allocator.free(bytes);
        var decoded = try locks.decode(std.testing.allocator, bytes, locks.maximum_document_bytes);
        defer decoded.deinit();
        try std.testing.expectEqualStrings(architecture, decoded.lock.target_architecture);
        try std.testing.expectEqual([_]u8{2} ** 32, decoded.lock.policy_sha256);
        var request: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("native-action-empty-cache", &request, .{});
        try std.testing.expectEqual(request, decoded.lock.request_sha256);
        try std.testing.expectEqual(@as(usize, 0), decoded.lock.repositories.len);
        try std.testing.expectEqual(@as(usize, 0), decoded.lock.local_artifacts.len);
        try std.testing.expectEqual(@as(usize, 0), decoded.lock.packages.len);
        const repeated = try emptyLock(std.testing.allocator, bytes);
        defer std.testing.allocator.free(repeated);
        try std.testing.expectEqualSlices(u8, bytes, repeated);
    }
}

test "native action empty lock refuses noncanonical source serialization" {
    const source = try sourceFixture("amd64");
    defer std.testing.allocator.free(source);
    const changed = try std.fmt.allocPrint(std.testing.allocator, "{s}\n", .{source});
    defer std.testing.allocator.free(changed);
    try std.testing.expectError(error.NonCanonicalDocument, emptyLock(std.testing.allocator, changed));
}

test "native action empty lock refuses changed source identity without publishing or overwriting output" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const parent = try temporary.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(parent);
    const source_path = try std.fs.path.join(std.testing.allocator, &.{ parent, "source.json" });
    defer std.testing.allocator.free(source_path);
    const output_path = try std.fs.path.join(std.testing.allocator, &.{ parent, "empty.json" });
    defer std.testing.allocator.free(output_path);
    const source = try sourceFixture("amd64");
    defer std.testing.allocator.free(source);
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "source.json", .data = source });
    try generate(std.testing.io, std.testing.allocator, source_path, output_path);
    try std.testing.expectError(error.PathAlreadyExists, generate(std.testing.io, std.testing.allocator, source_path, output_path));
    const retained = try temporary.dir.readFileAlloc(std.testing.io, "source.json", std.testing.allocator, .limited(locks.maximum_document_bytes));
    defer std.testing.allocator.free(retained);
    try std.testing.expectEqualSlices(u8, source, retained);
    const marker = std.mem.indexOf(u8, source, "\"request_sha256\":\"").? + "\"request_sha256\":\"".len;
    source[marker] ^= 1;
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "source.json", .data = source });
    try temporary.dir.deleteFile(std.testing.io, "empty.json");
    try std.testing.expectError(error.DigestMismatch, generate(std.testing.io, std.testing.allocator, source_path, output_path));
    try std.testing.expectError(error.FileNotFound, temporary.dir.openFile(std.testing.io, "empty.json", .{}));
}

test "native action empty lock refuses symbolic input and relative coordinates" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const parent = try temporary.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(parent);
    const source_path = try std.fs.path.join(std.testing.allocator, &.{ parent, "linked.json" });
    defer std.testing.allocator.free(source_path);
    const output_path = try std.fs.path.join(std.testing.allocator, &.{ parent, "empty.json" });
    defer std.testing.allocator.free(output_path);
    const source = try sourceFixture("arm64");
    defer std.testing.allocator.free(source);
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "source.json", .data = source });
    try temporary.dir.symLink(std.testing.io, "source.json", "linked.json", .{});
    try std.testing.expectError(error.NotRegularFile, generate(std.testing.io, std.testing.allocator, source_path, output_path));
    try std.testing.expectError(error.AbsoluteFixturePathsRequired, generate(std.testing.io, std.testing.allocator, "source.json", output_path));
    try std.testing.expectError(error.AbsoluteFixturePathsRequired, generate(std.testing.io, std.testing.allocator, source_path, "empty.json"));
}

const std = @import("std");
const content_digest = @import("content_digest.zig");
const package_origin = @import("package_origin.zig");
const solver = @import("solver.zig");

pub const maximum_document_bytes: usize = 16 * 1024 * 1024;

pub const Store = struct {
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,

    pub fn init(io: std.Io, dir: std.Io.Dir, name: []const u8) !Store {
        if (!safeLeaf(name)) return error.InvalidPath;
        return .{ .io = io, .dir = dir, .name = name };
    }

    pub fn read(self: Store, allocator: std.mem.Allocator) !solver.Plan {
        var file = try self.dir.openFile(self.io, self.name, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const source = try reader.interface.allocRemaining(
            allocator,
            .limited(maximum_document_bytes),
        );
        defer allocator.free(source);
        return decode(allocator, source);
    }

    pub fn writeAtomic(
        self: Store,
        allocator: std.mem.Allocator,
        plan: solver.Plan,
    ) !void {
        const bytes = try plan.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
        const stage = ".repository-plan-v4.new";
        self.dir.deleteFile(self.io, stage) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        {
            var file = try self.dir.createFile(self.io, stage, .{
                .exclusive = true,
                .permissions = if (@import("builtin").os.tag == .windows)
                    .default_file
                else
                    .fromMode(0o600),
                .resolve_beneath = true,
            });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, bytes);
            try file.sync(self.io);
        }
        try self.dir.rename(stage, self.dir, self.name, self.io);
        try syncDirectory(self.io, self.dir);
    }
};

pub fn decode(allocator: std.mem.Allocator, source: []const u8) !solver.Plan {
    if (source.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, source, .{
        .allocate = .alloc_always,
        .parse_numbers = false,
    }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidDocument;
    defer parsed.deinit();
    const root = try object(parsed.value);
    const schema_version = try unsigned(u32, root, "schema_version");
    if (schema_version != 3 and schema_version != 4)
        return error.UnsupportedPlanVersion;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const action_values = try array(root, "actions");
    if (action_values.len > 100_000) return error.PlanTooLarge;
    const actions = try owned.alloc(solver.PlanAction, action_values.len);
    for (action_values, 0..) |value, index| {
        const action = try object(value);
        const origin_value = action.get("origin") orelse
            return error.InvalidDocument;
        const origin_v2 = if (schema_version == 4)
            try parseOriginV2(owned, origin_value)
        else
            null;
        const origin: ?solver.PlanOrigin = if (schema_version == 3)
            try parseOrigin(owned, origin_value)
        else if (origin_v2) |value_origin| switch (value_origin) {
            .authenticated_repository => |repository| solver.PlanOrigin{
                .authenticated_repository = repository,
            },
            .local_artifact => null,
        } else null;
        const identity = if (schema_version == 4)
            try optionalDigestIdentity(action.get("archive_identity") orelse
                return error.InvalidDocument)
        else
            null;
        const digest = if (schema_version == 3)
            try optionalHex64(action.get("sha256") orelse
                return error.InvalidDocument)
        else if (identity) |archive_identity|
            if (archive_identity.digests.sha256) |sha256|
                package_origin.artifactIdFromSha256(sha256)
            else
                null
        else
            null;
        const prior = try parsePrior(owned, action.get("prior_installed") orelse
            return error.InvalidDocument);
        actions[index] = .{
            .kind = try enumField(solver.ActionKind, action, "kind"),
            .package = try stringDupe(owned, action, "package"),
            .version = try stringDupe(owned, action, "version"),
            .architecture = try stringDupe(owned, action, "architecture"),
            .repository = if (origin) |value_origin| switch (value_origin) {
                .authenticated_repository => |repository| repository,
                .local_artifact => null,
            } else null,
            .sha256 = digest,
            .archive_identity = identity,
            .package_size = try optionalUnsigned(u64, action, "package_size"),
            .installed_size_delta_bytes = try signed(i128, action, "installed_size_delta_bytes"),
            .source_package = try stringDupe(owned, action, "source_package"),
            .prior_installed = prior,
            .requested = try boolean(action, "requested"),
            .reason = try enumField(solver.ActionReason, action, "reason"),
            .essential = try boolean(action, "essential"),
            .has_pre_depends = try boolean(action, "has_pre_depends"),
            .selected_origin = null,
            .selected_origin_v2 = null,
            .origin = origin,
            .origin_v2 = origin_v2,
        };
    }

    const ordered_values = try array(root, "ordered_actions");
    if (ordered_values.len > 300_000) return error.PlanTooLarge;
    const ordered = try owned.alloc(solver.OrderedAction, ordered_values.len);
    for (ordered_values, 0..) |value, index| {
        const action = try object(value);
        ordered[index] = .{
            .sequence = try unsigned(usize, action, "sequence"),
            .kind = try enumField(solver.OrderedActionKind, action, "kind"),
            .package = try stringDupe(owned, action, "package"),
            .version = try stringDupe(owned, action, "version"),
            .architecture = try stringDupe(owned, action, "architecture"),
        };
    }
    const summary_object = try object(root.get("summary") orelse
        return error.InvalidDocument);
    const plan: solver.Plan = .{
        .schema_version = schema_version,
        .target_architecture = try stringDupe(owned, root, "target_architecture"),
        .mode = try enumField(solver.OperationMode, root, "mode"),
        .actions = actions,
        .ordered_actions = ordered,
        .summary = .{
            .installs = try unsigned(usize, summary_object, "installs"),
            .removals = try unsigned(usize, summary_object, "removals"),
            .upgrades = try unsigned(usize, summary_object, "upgrades"),
            .downgrades = try unsigned(usize, summary_object, "downgrades"),
            .reinstalls = try unsigned(usize, summary_object, "reinstalls"),
            .download_bytes = try unsigned(u64, summary_object, "download_bytes"),
            .installed_size_delta_bytes = try signed(
                i128,
                summary_object,
                "installed_size_delta_bytes",
            ),
        },
        .download_bytes = try unsigned(u64, root, "download_bytes"),
        .installed_size_delta_bytes = try signed(
            i128,
            root,
            "installed_size_delta_bytes",
        ),
        .backing_allocator = allocator,
        .arena = arena,
    };
    const canonical = plan.canonicalJson(allocator) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return plan;
}

fn parseOrigin(
    allocator: std.mem.Allocator,
    value: std.json.Value,
) !?solver.PlanOrigin {
    if (value == .null) return null;
    const origin = try object(value);
    const kind = try string(origin, "type");
    if (std.mem.eql(u8, kind, "authenticated_repository")) {
        return .{ .authenticated_repository = .{
            .id = try lowerHex64(try string(origin, "id")),
            .priority = try signed(i32, origin, "priority"),
        } };
    }
    if (!std.mem.eql(u8, kind, "local_artifact"))
        return error.InvalidDocument;
    const package = try object(origin.get("package") orelse
        return error.InvalidDocument);
    const evidence: package_origin.LocalArtifactEvidence = .{
        .artifact_id = try lowerHex64(try string(origin, "artifact_id")),
        .sha256 = try digest32(try string(origin, "sha256")),
        .size = try unsigned(u64, origin, "size"),
        .package = try stringDupe(allocator, package, "name"),
        .version = try stringDupe(allocator, package, "version"),
        .architecture = try stringDupe(allocator, package, "architecture"),
        .acquisition_url = try stringDupe(allocator, origin, "acquisition_url"),
        .trust_mode = try enumField(
            package_origin.LocalArtifactTrustMode,
            origin,
            "trust_mode",
        ),
    };
    try package_origin.validateLocalArtifact(evidence);
    return .{ .local_artifact = .{
        .evidence = evidence,
        .solver_priority = try signed(i32, origin, "solver_priority"),
    } };
}

fn parseOriginV2(
    allocator: std.mem.Allocator,
    value: std.json.Value,
) !?solver.PlanOriginV2 {
    if (value == .null) return null;
    const origin = try object(value);
    const kind = try string(origin, "type");
    if (std.mem.eql(u8, kind, "authenticated_repository")) {
        return .{ .authenticated_repository = .{
            .id = try lowerHex64(try string(origin, "id")),
            .priority = try signed(i32, origin, "priority"),
        } };
    }
    if (!std.mem.eql(u8, kind, "local_artifact"))
        return error.InvalidDocument;
    const package = try object(origin.get("package") orelse
        return error.InvalidDocument);
    const identity = (try optionalDigestIdentity(
        origin.get("archive_identity") orelse return error.InvalidDocument,
    )) orelse return error.InvalidDigest;
    const evidence: package_origin.LocalArtifactEvidenceV2 = .{
        .artifact_id = try parseDigestValue(
            origin.get("artifact_id") orelse return error.InvalidDocument,
        ),
        .archive_identity = identity,
        .size = try unsigned(u64, origin, "size"),
        .package = try stringDupe(allocator, package, "name"),
        .version = try stringDupe(allocator, package, "version"),
        .architecture = try stringDupe(allocator, package, "architecture"),
        .acquisition_url = try stringDupe(allocator, origin, "acquisition_url"),
        .trust_mode = try enumField(
            package_origin.LocalArtifactTrustModeV2,
            origin,
            "trust_mode",
        ),
    };
    try package_origin.validateLocalArtifactV2(evidence);
    return .{ .local_artifact = .{
        .evidence = evidence,
        .solver_priority = try signed(i32, origin, "solver_priority"),
    } };
}

fn parsePrior(
    allocator: std.mem.Allocator,
    value: std.json.Value,
) !?solver.PriorInstalled {
    if (value == .null) return null;
    const prior = try object(value);
    return .{
        .package = try stringDupe(allocator, prior, "package"),
        .version = try stringDupe(allocator, prior, "version"),
        .architecture = try stringDupe(allocator, prior, "architecture"),
        .installed_size_kib = try optionalUnsigned(u64, prior, "installed_size_kib"),
    };
}

fn object(value: std.json.Value) !std.json.ObjectMap {
    return switch (value) {
        .object => |result| result,
        else => error.InvalidDocument,
    };
}

fn array(map: std.json.ObjectMap, name: []const u8) ![]const std.json.Value {
    const value = map.get(name) orelse return error.InvalidDocument;
    return switch (value) {
        .array => |result| result.items,
        else => error.InvalidDocument,
    };
}

fn string(map: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = map.get(name) orelse return error.InvalidDocument;
    return switch (value) {
        .string => |result| result,
        else => error.InvalidDocument,
    };
}

fn stringDupe(
    allocator: std.mem.Allocator,
    map: std.json.ObjectMap,
    name: []const u8,
) ![]u8 {
    return allocator.dupe(u8, try string(map, name));
}

fn boolean(map: std.json.ObjectMap, name: []const u8) !bool {
    const value = map.get(name) orelse return error.InvalidDocument;
    return switch (value) {
        .bool => |result| result,
        else => error.InvalidDocument,
    };
}

fn enumField(
    comptime T: type,
    map: std.json.ObjectMap,
    name: []const u8,
) !T {
    return std.meta.stringToEnum(T, try string(map, name)) orelse
        error.InvalidDocument;
}

fn signed(
    comptime T: type,
    map: std.json.ObjectMap,
    name: []const u8,
) !T {
    const value = map.get(name) orelse return error.InvalidDocument;
    return switch (value) {
        .number_string => |number| std.fmt.parseInt(T, number, 10) catch
            return error.InvalidDocument,
        else => error.InvalidDocument,
    };
}

fn unsigned(
    comptime T: type,
    map: std.json.ObjectMap,
    name: []const u8,
) !T {
    return signed(T, map, name);
}

fn optionalUnsigned(
    comptime T: type,
    map: std.json.ObjectMap,
    name: []const u8,
) !?T {
    const value = map.get(name) orelse return error.InvalidDocument;
    if (value == .null) return null;
    return switch (value) {
        .number_string => |number| std.fmt.parseInt(T, number, 10) catch
            return error.InvalidDocument,
        else => error.InvalidDocument,
    };
}

fn optionalHex64(value: std.json.Value) !?[64]u8 {
    if (value == .null) return null;
    return try lowerHex64(switch (value) {
        .string => |result| result,
        else => return error.InvalidDocument,
    });
}

fn optionalDigestIdentity(value: std.json.Value) !?content_digest.Identity {
    if (value == .null) return null;
    const identity = try object(value);
    const primary = content_digest.Algorithm.parse(
        try string(identity, "primary"),
    ) catch return error.InvalidDigest;
    const digest_values = try array(identity, "digests");
    if (digest_values.len == 0 or digest_values.len > content_digest.supported_algorithms.len)
        return error.InvalidDigest;
    var digests: content_digest.Set = .{};
    var previous: ?content_digest.Algorithm = null;
    for (digest_values) |digest_value| {
        const digest = try object(digest_value);
        const algorithm = content_digest.Algorithm.parse(
            try string(digest, "algorithm"),
        ) catch return error.InvalidDigest;
        if (previous) |prior| {
            if (@intFromEnum(algorithm) <= @intFromEnum(prior))
                return error.InvalidDigest;
        }
        previous = algorithm;
        const parsed = content_digest.Value.parse(
            algorithm,
            try string(digest, "digest"),
        ) catch return error.InvalidDigest;
        digests.put(parsed) catch return error.InvalidDigest;
    }
    return content_digest.Identity.init(digests, primary) catch
        return error.InvalidDigest;
}

fn parseDigestValue(value: std.json.Value) !content_digest.Value {
    const digest = try object(value);
    const algorithm = content_digest.Algorithm.parse(
        try string(digest, "algorithm"),
    ) catch return error.InvalidDigest;
    return content_digest.Value.parse(
        algorithm,
        try string(digest, "digest"),
    ) catch return error.InvalidDigest;
}

fn lowerHex64(value: []const u8) ![64]u8 {
    if (value.len != 64) return error.InvalidDigest;
    var result: [64]u8 = undefined;
    for (value, 0..) |byte, index| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidDigest;
        result[index] = byte;
    }
    return result;
}

fn digest32(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidDigest;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    return result;
}

fn safeLeaf(name: []const u8) bool {
    return name.len != 0 and
        !std.mem.eql(u8, name, ".") and
        !std.mem.eql(u8, name, "..") and
        std.mem.indexOfScalar(u8, name, '/') == null and
        std.mem.indexOfScalar(u8, name, '\\') == null and
        std.mem.indexOfScalar(u8, name, 0) == null;
}

fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    _ = io;
    switch (@import("builtin").os.tag) {
        .linux => if (std.posix.errno(std.os.linux.fsync(dir.handle)) != .SUCCESS)
            return error.Unexpected,
        else => {},
    }
}

test "repository_plan.test.canonical executable plan round trips exactly" {
    const evidence: package_origin.LocalArtifactEvidence = .{
        .artifact_id = @splat('1'),
        .sha256 = @splat(0x11),
        .size = 12,
        .package = "vendor-repository",
        .version = "1",
        .architecture = "all",
        .acquisition_url = "file:///vendor.deb",
        .trust_mode = .pinned_sha256,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var actions = [_]solver.PlanAction{.{
        .kind = .install,
        .package = "vendor-repository",
        .version = "1",
        .architecture = "all",
        .repository = null,
        .sha256 = package_origin.artifactIdFromSha256(evidence.sha256),
        .package_size = evidence.size,
        .installed_size_delta_bytes = 1,
        .source_package = "vendor-repository",
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
        .selected_origin_v2 = null,
        .origin = .{ .local_artifact = .{
            .evidence = evidence,
            .solver_priority = 1000,
        } },
    }};
    var ordered = [_]solver.OrderedAction{
        .{
            .sequence = 0,
            .kind = .unpack,
            .package = "vendor-repository",
            .version = "1",
            .architecture = "all",
        },
        .{
            .sequence = 1,
            .kind = .configure_pending,
            .package = "vendor-repository",
            .version = "1",
            .architecture = "all",
        },
    };
    const plan: solver.Plan = .{
        .schema_version = 3,
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &actions,
        .ordered_actions = &ordered,
        .summary = .{ .installs = 1, .download_bytes = evidence.size },
        .download_bytes = evidence.size,
        .installed_size_delta_bytes = 1,
        .backing_allocator = std.testing.allocator,
        .arena = &arena,
    };
    const canonical = try plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);
    var decoded = try decode(std.testing.allocator, canonical);
    defer decoded.deinit();
    const replay = try decoded.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(replay);
    try std.testing.expectEqualStrings(canonical, replay);
    const Decode = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var result = try decode(allocator, bytes);
            defer result.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Decode.run, .{canonical});
    const noncanonical = try std.fmt.allocPrint(std.testing.allocator, " {s}", .{canonical});
    defer std.testing.allocator.free(noncanonical);
    try std.testing.expectError(error.NonCanonicalDocument, decode(std.testing.allocator, noncanonical));
}

test "repository_plan.test.full width canonical integers replay exactly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const large_delta: i128 = @as(i128, std.math.maxInt(i64)) + 1;
    const large_download: u64 = @as(u64, std.math.maxInt(i64)) + 1;
    var action = [_]solver.PlanAction{.{
        .kind = .remove,
        .package = "large",
        .version = "1",
        .architecture = "amd64",
        .repository = null,
        .sha256 = null,
        .package_size = null,
        .installed_size_delta_bytes = large_delta,
        .source_package = "large",
        .prior_installed = .{
            .package = "large",
            .version = "1",
            .architecture = "amd64",
            .installed_size_kib = large_download,
        },
        .requested = true,
        .reason = .explicit_request,
        .essential = false,
        .has_pre_depends = false,
        .selected_origin = null,
        .selected_origin_v2 = null,
        .origin = null,
    }};
    var ordered = [_]solver.OrderedAction{.{
        .sequence = 0,
        .kind = .remove,
        .package = "large",
        .version = "1",
        .architecture = "amd64",
    }};
    const plan: solver.Plan = .{
        .schema_version = 3,
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &action,
        .ordered_actions = &ordered,
        .summary = .{
            .removals = 1,
            .download_bytes = large_download,
            .installed_size_delta_bytes = large_delta,
        },
        .download_bytes = large_download,
        .installed_size_delta_bytes = large_delta,
        .backing_allocator = std.testing.allocator,
        .arena = &arena,
    };
    const canonical = try plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);
    var replay = try decode(std.testing.allocator, canonical);
    defer replay.deinit();
    try std.testing.expectEqual(large_download, replay.download_bytes);
    try std.testing.expectEqual(large_delta, replay.installed_size_delta_bytes);
    try std.testing.expectEqual(
        large_download,
        replay.actions[0].prior_installed.?.installed_size_kib.?,
    );
}

test "repository_plan.test.v4 replays complete mixed archive identities" {
    const bytes = "repository-plan-mixed-identity";
    const identity = content_digest.Identity.ofSupported(bytes);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var actions = [_]solver.PlanAction{.{
        .kind = .install,
        .package = "mixed",
        .version = "1",
        .architecture = "amd64",
        .repository = .{ .id = @splat('1'), .priority = 500 },
        .sha256 = package_origin.artifactIdFromSha256(identity.digests.sha256.?),
        .archive_identity = identity,
        .package_size = bytes.len,
        .installed_size_delta_bytes = 1,
        .source_package = "mixed",
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
        .selected_origin_v2 = null,
        .origin = .{ .authenticated_repository = .{
            .id = @splat('1'),
            .priority = 500,
        } },
        .origin_v2 = .{ .authenticated_repository = .{
            .id = @splat('1'),
            .priority = 500,
        } },
    }};
    var ordered = [_]solver.OrderedAction{.{
        .sequence = 0,
        .kind = .unpack,
        .package = "mixed",
        .version = "1",
        .architecture = "amd64",
    }};
    const plan: solver.Plan = .{
        .schema_version = 4,
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &actions,
        .ordered_actions = &ordered,
        .summary = .{ .installs = 1, .download_bytes = bytes.len },
        .download_bytes = bytes.len,
        .installed_size_delta_bytes = 1,
        .backing_allocator = std.testing.allocator,
        .arena = &arena,
    };
    const canonical = try plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);
    var decoded = try decode(std.testing.allocator, canonical);
    defer decoded.deinit();
    try std.testing.expect(content_digest.Identity.eql(
        identity,
        decoded.actions[0].archive_identity.?,
    ));
    const replay = try decoded.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(replay);
    try std.testing.expectEqualStrings(canonical, replay);
}

test "repository_plan.test.v4 SHA512-only local origin replays without SHA256" {
    const identity = try content_digest.Identity.init(
        .{ .sha512 = content_digest.Value.of(
            .sha512,
            "repository-plan-sha512",
        ).sha512 },
        .sha512,
    );
    const evidence: package_origin.LocalArtifactEvidenceV2 = .{
        .artifact_id = package_origin.artifactIdFromIdentity(identity),
        .archive_identity = identity,
        .size = 22,
        .package = "local",
        .version = "1",
        .architecture = "all",
        .acquisition_url = "file:///local.deb",
        .trust_mode = .pinned_content_digest,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var actions = [_]solver.PlanAction{.{
        .kind = .install,
        .package = evidence.package,
        .version = evidence.version,
        .architecture = evidence.architecture,
        .repository = null,
        .sha256 = null,
        .archive_identity = identity,
        .package_size = evidence.size,
        .installed_size_delta_bytes = 1,
        .source_package = evidence.package,
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
        .selected_origin_v2 = null,
        .origin = null,
        .origin_v2 = .{ .local_artifact = .{
            .evidence = evidence,
            .solver_priority = 1000,
        } },
    }};
    var ordered = [_]solver.OrderedAction{.{
        .sequence = 0,
        .kind = .unpack,
        .package = evidence.package,
        .version = evidence.version,
        .architecture = evidence.architecture,
    }};
    const plan: solver.Plan = .{
        .schema_version = 4,
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &actions,
        .ordered_actions = &ordered,
        .summary = .{ .installs = 1, .download_bytes = evidence.size },
        .download_bytes = evidence.size,
        .installed_size_delta_bytes = 1,
        .backing_allocator = std.testing.allocator,
        .arena = &arena,
    };
    const canonical = try plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);
    try std.testing.expect(std.mem.indexOf(u8, canonical, "\"sha256\"") == null);

    var decoded = try decode(std.testing.allocator, canonical);
    defer decoded.deinit();
    const decoded_evidence = decoded.actions[0].origin_v2.?.local_artifact.evidence;
    try std.testing.expect(decoded_evidence.archive_identity.eql(identity));
    try std.testing.expect(decoded_evidence.archive_identity.digests.sha256 == null);
    const replay = try decoded.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(replay);
    try std.testing.expectEqualStrings(canonical, replay);

    const tampered = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        canonical,
        "\"algorithm\":\"sha512\"",
        "\"algorithm\":\"sha999\"",
    );
    defer std.testing.allocator.free(tampered);
    try std.testing.expectError(
        error.InvalidDigest,
        decode(std.testing.allocator, tampered),
    );
}

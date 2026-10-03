const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

const max_reference_bytes = 8 * 1024 * 1024;
const max_admin_bytes = 64 * 1024 * 1024;
const receipt_name = "reference-receipt-v1.json";
const receipt_schema = "https://debz.dev/schema/native-dpkg-reference-receipt-v1";
const reference_version = "1.22.22";
const show_format = "--showformat=${Package} ${Version} ${Architecture} ${Status}\\n";

const QueryResult = struct {
    code: u8,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: QueryResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

const AdminEntry = struct {
    path: []const u8,
    kind: []const u8,
    size: ?u64 = null,
    sha256: ?[64]u8 = null,
};

fn lessAdminEntry(_: void, left: AdminEntry, right: AdminEntry) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

fn expectedDpkgQueryDigest(architecture: []const u8) ![]const u8 {
    if (std.mem.eql(u8, architecture, "amd64"))
        return "095817337215129933918cacae5fd62e86202fe238591bea207a75b73561e8c5";
    if (std.mem.eql(u8, architecture, "arm64"))
        return "a5377f6b04e6d251d013c13a2399cb83db8462bf249949b5d76ae0e22842e83a";
    return error.UnsupportedReferenceArchitecture;
}

fn readRegularAbsolute(allocator: std.mem.Allocator, io: std.Io, absolute: []const u8, maximum: usize) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, absolute, .{
        .follow_symlinks = false,
        .allow_directory = false,
    });
    defer file.close(io);
    if ((try file.stat(io)).size > maximum) return error.ReferenceTooLarge;
    var reader = file.reader(io, &.{});
    const bytes = try reader.interface.allocRemaining(allocator, .limited(maximum + 1));
    errdefer allocator.free(bytes);
    if (bytes.len > maximum) return error.ReferenceTooLarge;
    return bytes;
}

fn jsonString(value: std.json.Value, name: []const u8) ![]const u8 {
    const field = value.object.get(name) orelse return error.InvalidReferenceReceipt;
    if (field != .string) return error.InvalidReferenceReceipt;
    return field.string;
}

fn verifyReceiptBinding(
    allocator: std.mem.Allocator,
    io: std.Io,
    receipt_path: []const u8,
    architecture: []const u8,
    digest_hex: []const u8,
    size: u64,
) !void {
    const raw = try readRegularAbsolute(allocator, io, receipt_path, 4096);
    defer allocator.free(raw);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object or parsed.value.object.count() != 7)
        return error.InvalidReferenceReceipt;
    if (!std.mem.eql(u8, try jsonString(parsed.value, "schema"), receipt_schema) or
        !std.mem.eql(u8, try jsonString(parsed.value, "version"), reference_version) or
        !std.mem.eql(u8, try jsonString(parsed.value, "architecture"), architecture))
        return error.InvalidReferenceReceipt;
    const binding = parsed.value.object.get("dpkg_query") orelse return error.InvalidReferenceReceipt;
    if (binding != .object or binding.object.count() != 2) return error.InvalidReferenceReceipt;
    if (!std.mem.eql(u8, try jsonString(binding, "sha256"), digest_hex))
        return error.ReferenceReceiptMismatch;
    const bound_size = binding.object.get("size") orelse return error.InvalidReferenceReceipt;
    if (bound_size != .integer or bound_size.integer != @as(i64, @intCast(size)))
        return error.ReferenceReceiptMismatch;
}

fn selectReferenceDpkgQuery(allocator: std.mem.Allocator, io: std.Io, dpkg: []const u8, architecture: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(dpkg)) return error.InvalidReferencePath;
    const bin = std.fs.path.dirname(dpkg) orelse return error.InvalidReferencePath;
    const usr = std.fs.path.dirname(bin) orelse return error.InvalidReferencePath;
    const prefix = std.fs.path.dirname(usr) orelse return error.InvalidReferencePath;
    const query = try std.fs.path.join(allocator, &.{ bin, "dpkg-query" });
    errdefer allocator.free(query);
    const digest_hex = try expectedDpkgQueryDigest(architecture);
    const bytes = try readRegularAbsolute(allocator, io, query, max_reference_bytes);
    defer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), digest_hex))
        return error.ReferenceDpkgQueryDigestMismatch;
    var dir = try foundation.openRealDirectory(io, bin);
    defer dir.close(io);
    try dir.access(io, "dpkg-query", .{ .execute = true });
    const receipt = try std.fs.path.join(allocator, &.{ prefix, receipt_name });
    defer allocator.free(receipt);
    try verifyReceiptBinding(allocator, io, receipt, architecture, digest_hex, bytes.len);
    const version = try std.process.run(allocator, io, .{
        .argv = &.{ query, "--version" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer allocator.free(version.stdout);
    defer allocator.free(version.stderr);
    if (version.term != .exited or version.term.exited != 0 or
        std.mem.indexOf(u8, version.stdout, "version " ++ reference_version) == null)
        return error.InvalidReferenceDpkgQueryVersion;
    return query;
}

fn captureAdmin(allocator: std.mem.Allocator, io: std.Io, absolute: []const u8) ![]u8 {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var dir = try foundation.openRealDirectory(io, absolute);
    defer dir.close(io);
    var entries: std.ArrayList(AdminEntry) = .empty;
    var total: u64 = 0;
    var walker = try dir.walk(a);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        const relative = try a.dupe(u8, entry.path);
        switch (entry.kind) {
            .directory => try entries.append(a, .{ .path = relative, .kind = "directory" }),
            .file => {
                var file = try dir.openFile(io, entry.path, .{
                    .follow_symlinks = false,
                    .allow_directory = false,
                });
                defer file.close(io);
                const size = (try file.stat(io)).size;
                total += size;
                if (total > max_admin_bytes) return error.AdminDirTooLarge;
                var reader = file.reader(io, &.{});
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                var buffer: [64 * 1024]u8 = undefined;
                while (true) {
                    const count = reader.interface.readSliceShort(&buffer) catch return reader.err.?;
                    if (count == 0) break;
                    hash.update(buffer[0..count]);
                }
                var digest: [32]u8 = undefined;
                hash.final(&digest);
                try entries.append(a, .{
                    .path = relative,
                    .kind = "regular",
                    .size = size,
                    .sha256 = std.fmt.bytesToHex(digest, .lower),
                });
            },
            else => return error.UnsupportedAdminDirEntry,
        }
    }
    std.mem.sort(AdminEntry, entries.items, {}, lessAdminEntry);
    return std.json.Stringify.valueAlloc(allocator, entries.items, .{ .whitespace = .indent_2 });
}

fn copyAdminDir(case: *support.Scenario, root: []const u8, side: []const u8) ![]u8 {
    const relative = try std.fmt.allocPrint(case.fixture.allocator, "{s}/query-admindirs/{s}", .{ case.name, side });
    defer case.fixture.allocator.free(relative);
    try case.fixture.directory(relative);
    const absolute = try case.fixture.absolute(relative);
    errdefer case.fixture.allocator.free(absolute);
    const source = try std.fmt.allocPrint(case.fixture.allocator, "{s}/var/lib/dpkg/.", .{root});
    defer case.fixture.allocator.free(source);
    const log = try std.fmt.allocPrint(case.fixture.allocator, "{s}/query-admindirs/{s}.copy.log", .{ case.name, side });
    defer case.fixture.allocator.free(log);
    try case.fixture.run(&.{ "cp", "-a", "--no-preserve=ownership", source, absolute }, log, 30);
    return absolute;
}

fn runQuery(
    fixture: *foundation.Fixture,
    dpkg_query: []const u8,
    admindir: []const u8,
    args: []const []const u8,
) !QueryResult {
    const admindir_arg = try std.fmt.allocPrint(fixture.allocator, "--admindir={s}", .{admindir});
    defer fixture.allocator.free(admindir_arg);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(fixture.allocator);
    try argv.appendSlice(fixture.allocator, &.{ "/usr/bin/timeout", "--kill-after=2s", "30s", dpkg_query, admindir_arg });
    try argv.appendSlice(fixture.allocator, args);
    const result = try std.process.run(fixture.allocator, fixture.io, .{
        .argv = argv.items,
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(35), .clock = .awake } },
    });
    errdefer {
        fixture.allocator.free(result.stdout);
        fixture.allocator.free(result.stderr);
    }
    const code = switch (result.term) {
        .exited => |value| value,
        else => return error.DpkgQueryTerminated,
    };
    return .{ .code = code, .stdout = result.stdout, .stderr = result.stderr };
}

fn writeQueryResult(fixture: *foundation.Fixture, destination: []const u8, label: []const u8, side: []const u8, result: QueryResult) !void {
    const prefix = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}.{s}", .{ destination, label, side });
    defer fixture.allocator.free(prefix);
    const code = try std.fmt.allocPrint(fixture.allocator, "{d}\n", .{result.code});
    defer fixture.allocator.free(code);
    const code_path = try support.path(fixture.allocator, prefix, "code");
    defer fixture.allocator.free(code_path);
    const stdout_path = try support.path(fixture.allocator, prefix, "stdout");
    defer fixture.allocator.free(stdout_path);
    const stderr_path = try support.path(fixture.allocator, prefix, "stderr");
    defer fixture.allocator.free(stderr_path);
    try fixture.write(code_path, code, 0o644);
    try fixture.write(stdout_path, result.stdout, 0o644);
    try fixture.write(stderr_path, result.stderr, 0o644);
}

fn compareOneQuery(
    case: *support.Scenario,
    dpkg_query: []const u8,
    left_admin: []const u8,
    right_admin: []const u8,
    destination: []const u8,
    label: []const u8,
    args: []const []const u8,
) !void {
    const left = try runQuery(case.fixture, dpkg_query, left_admin, args);
    defer left.deinit(case.fixture.allocator);
    const right = try runQuery(case.fixture, dpkg_query, right_admin, args);
    defer right.deinit(case.fixture.allocator);
    try writeQueryResult(case.fixture, destination, label, "reference", left);
    try writeQueryResult(case.fixture, destination, label, "native", right);
    if (left.code != right.code or
        !std.mem.eql(u8, left.stdout, right.stdout) or
        !std.mem.eql(u8, left.stderr, right.stderr))
    {
        std.debug.print("dpkg-query mismatch in {s}/{s}: reference={d}, native={d}\n", .{
            case.name, label, left.code, right.code,
        });
        return error.DpkgQueryMismatch;
    }
}

fn compareQueries(case: *support.Scenario, dpkg_query: []const u8, package: []const u8, search_path: []const u8) !void {
    const destination = try std.fmt.allocPrint(case.fixture.allocator, "{s}/query-results", .{case.name});
    defer case.fixture.allocator.free(destination);
    try case.fixture.directory(destination);
    const left_admin = try copyAdminDir(case, case.reference_root, "reference");
    defer case.fixture.allocator.free(left_admin);
    const right_admin = try copyAdminDir(case, case.native_root, "native");
    defer case.fixture.allocator.free(right_admin);
    const left_before = try captureAdmin(case.fixture.allocator, case.fixture.io, left_admin);
    defer case.fixture.allocator.free(left_before);
    const right_before = try captureAdmin(case.fixture.allocator, case.fixture.io, right_admin);
    defer case.fixture.allocator.free(right_before);
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "show-all", &.{ "-W", show_format });
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "show-package", &.{ "-W", show_format, package });
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "status", &.{ "-s", package });
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "list", &.{ "-L", package });
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "search", &.{ "-S", search_path });
    const left_after = try captureAdmin(case.fixture.allocator, case.fixture.io, left_admin);
    defer case.fixture.allocator.free(left_after);
    const right_after = try captureAdmin(case.fixture.allocator, case.fixture.io, right_admin);
    defer case.fixture.allocator.free(right_after);
    if (!std.mem.eql(u8, left_before, left_after) or
        !std.mem.eql(u8, right_before, right_after))
        return error.DpkgQueryMutatedAdminDir;
    std.debug.print("{s}/dpkg-query: native/dpkg query parity passed\n", .{case.name});
}

fn failureMarker(case: *support.Scenario, content: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |label| {
        const relative = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{
            case.name, label, support.failure,
        });
        defer case.fixture.allocator.free(relative);
        try support.fixtureFile(case.fixture, relative, content, 0o644);
    }
}

fn configuredCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, dpkg_query: []const u8, arch: []const u8) !void {
    const name = "dpkg-query-configured";
    const archive = try support.makePackage(fixture, arch, "1", name, "dpkg-query-packages", .{});
    defer fixture.allocator.free(archive);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, false);
    defer case.deinit();
    try case.phase(.{ .operation = "install", .archives = &.{archive}, .packages = &selected }, false);
    try compareQueries(&case, dpkg_query, name, "/usr/share/" ++ name ++ "/data");
}

fn residualConfigCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, dpkg_query: []const u8, arch: []const u8) !void {
    const name = "dpkg-query-residual";
    const conffile = "etc/dpkg-query-residual.conf";
    const archive = try support.makePackage(fixture, arch, "1", name, "dpkg-query-packages", .{
        .conffile_content = "residual configuration\n",
        .conffile_path = conffile,
    });
    defer fixture.allocator.free(archive);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, false);
    defer case.deinit();
    try case.phase(.{ .operation = "install", .archives = &.{archive}, .packages = &selected }, false);
    try case.phase(.{ .operation = "remove", .packages = &selected }, false);
    try compareQueries(&case, dpkg_query, name, "/" ++ conffile);
}

fn purgeCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, dpkg_query: []const u8, arch: []const u8) !void {
    const name = "dpkg-query-purged";
    const conffile = "etc/dpkg-query-purged.conf";
    const archive = try support.makePackage(fixture, arch, "1", name, "dpkg-query-packages", .{
        .conffile_content = "purged configuration\n",
        .conffile_path = conffile,
    });
    defer fixture.allocator.free(archive);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, false);
    defer case.deinit();
    try case.phase(.{ .operation = "install", .archives = &.{archive}, .packages = &selected }, false);
    try case.phase(.{ .operation = "purge", .packages = &selected }, false);
    try compareQueries(&case, dpkg_query, name, "/" ++ conffile);
}

fn halfConfiguredCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, dpkg_query: []const u8, arch: []const u8) !void {
    const name = "dpkg-query-half-configured";
    const archive = try support.makePackage(fixture, arch, "1", name, "dpkg-query-packages", .{});
    defer fixture.allocator.free(archive);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, false);
    defer case.deinit();
    try failureMarker(&case, name ++ "@1:postinst:configure\n");
    try case.phase(.{ .operation = "install", .archives = &.{archive}, .packages = &selected }, true);
    try compareQueries(&case, dpkg_query, name, "/usr/share/" ++ name ++ "/data");
}

fn triggerPendingCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, dpkg_query: []const u8, arch: []const u8) !void {
    const handler_name = "dpkg-query-trigger-handler";
    const source_name = "dpkg-query-trigger-source";
    const trigger = "debz-dpkg-query-trigger";
    const handler = try support.makePackage(fixture, arch, "1", handler_name, "dpkg-query-packages", .{
        .declarations = "interest-noawait " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    const activating = try support.makePackage(fixture, arch, "1", source_name, "dpkg-query-packages", .{
        .declarations = "activate-noawait " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(activating);
    const selected = [_]foundation.PackageIdentity{.{ .name = source_name, .architecture = arch }};
    var case = try support.Scenario.init(fixture, "dpkg-query-trigger-pending", driver, dpkg, arch, false);
    defer case.deinit();
    try case.seed(handler);
    try case.phase(.{
        .operation = "install",
        .archives = &.{activating},
        .packages = &selected,
        .triggers = true,
        .defer_triggers = true,
    }, false);
    try compareQueries(&case, dpkg_query, handler_name, "/usr/share/" ++ handler_name ++ "/data");
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, architecture: []const u8) !void {
    const dpkg_query = try selectReferenceDpkgQuery(fixture.allocator, fixture.io, dpkg, architecture);
    defer fixture.allocator.free(dpkg_query);
    try configuredCase(fixture, driver, dpkg, dpkg_query, architecture);
    try residualConfigCase(fixture, driver, dpkg, dpkg_query, architecture);
    try purgeCase(fixture, driver, dpkg, dpkg_query, architecture);
    try halfConfiguredCase(fixture, driver, dpkg, dpkg_query, architecture);
    try triggerPendingCase(fixture, driver, dpkg, dpkg_query, architecture);
}

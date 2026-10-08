const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const root_fs = @import("debz").root_fs;

const max_reference_bytes = 8 * 1024 * 1024;
const max_admin_bytes = 64 * 1024 * 1024;
const receipt_name = "reference-receipt-v1.json";
const receipt_schema = "https://debz.dev/schema/native-dpkg-reference-receipt-v1";
const reference_version = "1.22.22";
const show_format = "--showformat=${Package} ${Version} ${Architecture} ${Status}\\n";
const imported_conffile_md5 = "483be8ac879757fa5b00778dc337be15";

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
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_ns: i128,
    size: ?u64 = null,
    sha256: ?[64]u8 = null,
};

const QueryExpectation = struct {
    package: []const u8,
    version: ?[]const u8,
    status: ?[]const u8,
    show_all: []const u8,
    search_path: []const u8,
    conffile: ?[]const u8 = null,
    config_version: ?[]const u8 = null,
    residual: bool = false,
    pending: ?[]const u8 = null,
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

fn syntheticReceipt(
    allocator: std.mem.Allocator,
    architecture: []const u8,
    digest_hex: []const u8,
    size: u64,
    include_query: bool,
) ![]u8 {
    if (!include_query) {
        return std.fmt.allocPrint(allocator,
            \\{{
            \\  "architecture": "{s}",
            \\  "archive": {{}},
            \\  "dpkg": {{}},
            \\  "schema": "{s}",
            \\  "update_alternatives": {{}},
            \\  "version": "{s}"
            \\}}
            \\
        , .{ architecture, receipt_schema, reference_version });
    }
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "architecture": "{s}",
        \\  "archive": {{}},
        \\  "dpkg": {{}},
        \\  "dpkg_query": {{
        \\    "sha256": "{s}",
        \\    "size": {d}
        \\  }},
        \\  "schema": "{s}",
        \\  "update_alternatives": {{}},
        \\  "version": "{s}"
        \\}}
        \\
    , .{ architecture, digest_hex, size, receipt_schema, reference_version });
}

fn verifySyntheticReceipt(
    receipt: []const u8,
    architecture: []const u8,
    digest_hex: []const u8,
    size: u64,
) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = receipt_name,
        .data = receipt,
    });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, receipt_name, std.testing.allocator);
    defer std.testing.allocator.free(path);
    try verifyReceiptBinding(std.testing.allocator, std.testing.io, path, architecture, digest_hex, size);
}

test "dpkg-query reference receipt binding validates every bound attribute" {
    const allocator = std.testing.allocator;
    const architecture = "arm64";
    const digest_hex = try expectedDpkgQueryDigest(architecture);
    const size = 199328;
    const valid = try syntheticReceipt(allocator, architecture, digest_hex, size, true);
    defer allocator.free(valid);

    try verifySyntheticReceipt(valid, architecture, digest_hex, size);
    try std.testing.expectError(
        error.InvalidReferenceReceipt,
        verifySyntheticReceipt(valid, "amd64", digest_hex, size),
    );

    var wrong_digest = try allocator.dupe(u8, digest_hex);
    defer allocator.free(wrong_digest);
    wrong_digest[0] = if (wrong_digest[0] == '0') '1' else '0';
    try std.testing.expectError(
        error.ReferenceReceiptMismatch,
        verifySyntheticReceipt(valid, architecture, wrong_digest, size),
    );
    try std.testing.expectError(
        error.ReferenceReceiptMismatch,
        verifySyntheticReceipt(valid, architecture, digest_hex, size + 1),
    );

    const legacy = try syntheticReceipt(allocator, architecture, digest_hex, size, false);
    defer allocator.free(legacy);
    try std.testing.expectError(
        error.InvalidReferenceReceipt,
        verifySyntheticReceipt(legacy, architecture, digest_hex, size),
    );
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
    const root: root_fs.Root = .init(io, dir);
    var entries: std.ArrayList(AdminEntry) = .empty;
    var parent = try foundation.openRealDirectory(io, std.fs.path.dirname(absolute) orelse return error.InvalidReferencePath);
    defer parent.close(io);
    const directory_entry = try (root_fs.Root.init(io, parent)).entry(try root_fs.Path.init(std.fs.path.basename(absolute)));
    try entries.append(a, .{
        .path = ".",
        .kind = "directory",
        .mode = directory_entry.mode,
        .uid = directory_entry.uid,
        .gid = directory_entry.gid,
        .mtime_ns = directory_entry.modified_nanoseconds,
    });
    var total: u64 = 0;
    var walker = try dir.walk(a);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        const relative = try a.dupe(u8, entry.path);
        const metadata = try root.entry(try root_fs.Path.initPackage(entry.path));
        var observed: AdminEntry = .{
            .path = relative,
            .kind = "directory",
            .mode = metadata.mode,
            .uid = metadata.uid,
            .gid = metadata.gid,
            .mtime_ns = metadata.modified_nanoseconds,
        };
        switch (entry.kind) {
            .directory => {},
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
                observed.kind = "regular";
                observed.size = size;
                observed.sha256 = std.fmt.bytesToHex(digest, .lower);
            },
            else => return error.UnsupportedAdminDirEntry,
        }
        try entries.append(a, observed);
    }
    std.mem.sort(AdminEntry, entries.items, {}, lessAdminEntry);
    return std.json.Stringify.valueAlloc(allocator, entries.items, .{ .whitespace = .indent_2 });
}

fn copyAdminDir(fixture: *foundation.Fixture, root: []const u8, relative: []const u8) ![]u8 {
    try fixture.directory(relative);
    const absolute = try fixture.absolute(relative);
    errdefer fixture.allocator.free(absolute);
    const source = try std.fmt.allocPrint(fixture.allocator, "{s}/var/lib/dpkg/.", .{root});
    defer fixture.allocator.free(source);
    const log = try std.fmt.allocPrint(fixture.allocator, "{s}.copy.log", .{relative});
    defer fixture.allocator.free(log);
    try fixture.run(&.{ "cp", "-a", "--no-preserve=ownership", source, absolute }, log, 30);
    return absolute;
}

fn captureQueryRoot(fixture: *foundation.Fixture, root: []const u8) ![]u8 {
    const snapshot = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(snapshot);
    const admin = try std.fs.path.join(fixture.allocator, &.{ root, "var/lib/dpkg" });
    defer fixture.allocator.free(admin);
    const database = try captureAdmin(fixture.allocator, fixture.io, admin);
    defer fixture.allocator.free(database);
    const evidence_path = try std.fs.path.join(fixture.allocator, &.{ root, "var/lib/debz" });
    defer fixture.allocator.free(evidence_path);
    const evidence = if (fixture.dir.statFile(fixture.io, evidence_path[fixture.path.len + 1 ..], .{ .follow_symlinks = false })) |_|
        try captureAdmin(fixture.allocator, fixture.io, evidence_path)
    else |err| switch (err) {
        error.FileNotFound => try fixture.allocator.dupe(u8, "<absent>"),
        else => return err,
    };
    defer fixture.allocator.free(evidence);
    return std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = snapshot,
        .database = database,
        .native_evidence = evidence,
    }, .{});
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
    expectation: ?QueryExpectation,
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
    if (expectation) |expected| {
        expectQuery(case.fixture.allocator, case.architecture, label, right, expected) catch |err| {
            std.debug.print("unexpected dpkg-query state in {s}/{s}; exact outputs retained in {s}\n", .{
                case.name, label, destination,
            });
            return err;
        };
    }
}

fn expectQuery(allocator: std.mem.Allocator, architecture: []const u8, label: []const u8, result: QueryResult, expected: QueryExpectation) !void {
    if (std.mem.eql(u8, label, "show-all")) {
        if (result.code != 0 or result.stderr.len != 0 or !std.mem.eql(u8, result.stdout, expected.show_all))
            return error.UnexpectedQueryState;
        return;
    }
    if (expected.version == null) {
        const diagnostic = if (std.mem.eql(u8, label, "show-package"))
            try std.fmt.allocPrint(allocator, "dpkg-query: no packages found matching {s}\n", .{expected.package})
        else if (std.mem.startsWith(u8, label, "search"))
            try std.fmt.allocPrint(allocator, "dpkg-query: no path found matching pattern {s}\n", .{expected.search_path})
        else if (std.mem.eql(u8, label, "list"))
            try std.fmt.allocPrint(allocator, "dpkg-query: package '{s}' is not installed\n" ++
                "Use dpkg --contents (= dpkg-deb --contents) to list archive files contents.\n", .{expected.package})
        else
            try std.fmt.allocPrint(allocator, "dpkg-query: package '{s}' is not installed and no information is available\n" ++
                "Use dpkg --info (= dpkg-deb --info) to examine archive files.\n", .{expected.package});
        defer allocator.free(diagnostic);
        if (result.code != 1 or result.stdout.len != 0 or !std.mem.eql(u8, result.stderr, diagnostic))
            return error.UnexpectedQueryState;
        return;
    }
    if (result.code != 0 or result.stdout.len == 0 or result.stderr.len != 0)
        return error.UnexpectedQueryState;
    if (std.mem.eql(u8, label, "show-package")) {
        const show = try std.fmt.allocPrint(allocator, "{s} {s} {s} {s}\n", .{
            expected.package, expected.version.?, architecture, expected.status.?,
        });
        defer allocator.free(show);
        if (!std.mem.eql(u8, result.stdout, show)) return error.UnexpectedQueryState;
    } else if (std.mem.eql(u8, label, "status")) {
        const config_version = if (expected.config_version) |version|
            try std.fmt.allocPrint(allocator, "Config-Version: {s}\n", .{version})
        else
            try allocator.dupe(u8, "");
        defer allocator.free(config_version);
        const conffiles = if (expected.conffile) |conffile|
            try std.fmt.allocPrint(allocator, "Conffiles:\n {s} " ++ imported_conffile_md5 ++ "\n", .{conffile})
        else
            try allocator.dupe(u8, "");
        defer allocator.free(conffiles);
        const pending = if (expected.pending) |trigger|
            try std.fmt.allocPrint(allocator, "Triggers-Pending: {s}\n", .{trigger})
        else
            try allocator.dupe(u8, "");
        defer allocator.free(pending);
        const status = try std.fmt.allocPrint(allocator, "Package: {s}\nStatus: {s}\nMaintainer: debz fixture <fixture@example.invalid>\n" ++
            "Architecture: {s}\nVersion: {s}\n{s}{s}Description: native lifecycle fixture\n{s}", .{ expected.package, expected.status.?, architecture, expected.version.?, config_version, conffiles, pending });
        defer allocator.free(status);
        if (!std.mem.eql(u8, result.stdout, status)) return error.UnexpectedQueryState;
    } else if (std.mem.eql(u8, label, "list")) {
        const configuration = if (expected.conffile) |conffile|
            try std.fmt.allocPrint(allocator, "/etc\n{s}\n", .{conffile})
        else
            try allocator.dupe(u8, "");
        defer allocator.free(configuration);
        const list = if (expected.residual)
            try allocator.dupe(u8, configuration)
        else
            try std.fmt.allocPrint(allocator, "/.\n{s}/usr\n/usr/share\n/usr/share/{s}\n/usr/share/{s}/data\n" ++
                "/usr/share/{s}/data.link\n/usr/share/{s}/current\n", .{ configuration, expected.package, expected.package, expected.package, expected.package });
        defer allocator.free(list);
        if (!std.mem.eql(u8, result.stdout, list)) return error.UnexpectedQueryState;
    } else if (std.mem.eql(u8, label, "search")) {
        const owner = try std.fmt.allocPrint(allocator, "{s}: {s}\n", .{ expected.package, expected.search_path });
        defer allocator.free(owner);
        if (!std.mem.eql(u8, result.stdout, owner)) return error.UnexpectedQueryState;
    } else return error.InvalidQueryLabel;
}

fn compareQueriesAt(case: *support.Scenario, dpkg_query: []const u8, package: []const u8, search_path: []const u8, checkpoint: []const u8, expectation: ?QueryExpectation) !void {
    const destination = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}", .{ case.name, checkpoint });
    defer case.fixture.allocator.free(destination);
    try case.fixture.directory(destination);
    const left_root_before = try captureQueryRoot(case.fixture, case.reference_root);
    defer case.fixture.allocator.free(left_root_before);
    const right_root_before = try captureQueryRoot(case.fixture, case.native_root);
    defer case.fixture.allocator.free(right_root_before);
    const left_path = try support.path(case.fixture.allocator, destination, "admindirs/reference");
    defer case.fixture.allocator.free(left_path);
    const right_path = try support.path(case.fixture.allocator, destination, "admindirs/native");
    defer case.fixture.allocator.free(right_path);
    const left_admin = try copyAdminDir(case.fixture, case.reference_root, left_path);
    defer case.fixture.allocator.free(left_admin);
    const right_admin = try copyAdminDir(case.fixture, case.native_root, right_path);
    defer case.fixture.allocator.free(right_admin);
    const left_before = try captureAdmin(case.fixture.allocator, case.fixture.io, left_admin);
    defer case.fixture.allocator.free(left_before);
    const right_before = try captureAdmin(case.fixture.allocator, case.fixture.io, right_admin);
    defer case.fixture.allocator.free(right_before);
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "show-all", &.{ "-W", show_format }, expectation);
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "show-package", &.{ "-W", show_format, package }, expectation);
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "status", &.{ "-s", package }, expectation);
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "list", &.{ "-L", package }, expectation);
    try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "search", &.{ "-S", search_path }, expectation);
    if (expectation) |expected| {
        if (expected.residual) {
            const payload = try std.fmt.allocPrint(case.fixture.allocator, "/usr/share/{s}/data", .{package});
            defer case.fixture.allocator.free(payload);
            try compareOneQuery(case, dpkg_query, left_admin, right_admin, destination, "search-removed-payload", &.{ "-S", payload }, .{
                .package = package,
                .version = null,
                .status = null,
                .show_all = expected.show_all,
                .search_path = payload,
            });
        }
    }
    const left_after = try captureAdmin(case.fixture.allocator, case.fixture.io, left_admin);
    defer case.fixture.allocator.free(left_after);
    const right_after = try captureAdmin(case.fixture.allocator, case.fixture.io, right_admin);
    defer case.fixture.allocator.free(right_after);
    if (!std.mem.eql(u8, left_before, left_after) or
        !std.mem.eql(u8, right_before, right_after))
        return error.DpkgQueryMutatedAdminDir;
    const left_root_after = try captureQueryRoot(case.fixture, case.reference_root);
    defer case.fixture.allocator.free(left_root_after);
    const right_root_after = try captureQueryRoot(case.fixture, case.native_root);
    defer case.fixture.allocator.free(right_root_after);
    if (!std.mem.eql(u8, left_root_before, left_root_after) or
        !std.mem.eql(u8, right_root_before, right_root_after))
        return error.DpkgQueryMutatedRoot;
    std.debug.print("{s}/dpkg-query: native/dpkg query parity passed\n", .{case.name});
}

test "imported query expectations reject empty, stale and falsely successful absent results" {
    const expected: QueryExpectation = .{
        .package = "imported",
        .version = "2",
        .status = "install ok installed",
        .show_all = "imported 2 arm64 install ok installed\n",
        .search_path = "/usr/share/imported/data",
    };
    var empty: [0]u8 = .{};
    const missing: QueryResult = .{ .code = 0, .stdout = &empty, .stderr = &empty };
    try std.testing.expectError(error.UnexpectedQueryState, expectQuery(std.testing.allocator, "arm64", "show-all", missing, expected));
    var stale = "imported 1 arm64 install ok installed\n".*;
    try std.testing.expectError(error.UnexpectedQueryState, expectQuery(std.testing.allocator, "arm64", "show-package", .{
        .code = 0,
        .stdout = &stale,
        .stderr = &empty,
    }, expected));
    var purged = expected;
    purged.version = null;
    purged.status = null;
    try std.testing.expectError(error.UnexpectedQueryState, expectQuery(std.testing.allocator, "arm64", "search", missing, purged));
}

fn compareQueries(case: *support.Scenario, dpkg_query: []const u8, package: []const u8, search_path: []const u8) !void {
    return compareQueriesAt(case, dpkg_query, package, search_path, "query-results", null);
}

pub fn observeRefusedImport(
    fixture: *foundation.Fixture,
    dpkg: []const u8,
    architecture: []const u8,
    root: []const u8,
    label: []const u8,
    expected_show: ?[]const u8,
) !void {
    const query = try selectReferenceDpkgQuery(fixture.allocator, fixture.io, dpkg, architecture);
    defer fixture.allocator.free(query);
    const destination = try std.fmt.allocPrint(fixture.allocator, "{s}-query-observation", .{label});
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    const relative = try support.path(fixture.allocator, destination, "admindir");
    defer fixture.allocator.free(relative);
    const root_before = try captureQueryRoot(fixture, root);
    defer fixture.allocator.free(root_before);
    const admin = try copyAdminDir(fixture, root, relative);
    defer fixture.allocator.free(admin);
    const before = try captureAdmin(fixture.allocator, fixture.io, admin);
    defer fixture.allocator.free(before);
    const result = try runQuery(fixture, query, admin, &.{ "-W", show_format });
    defer result.deinit(fixture.allocator);
    try writeQueryResult(fixture, destination, "show-all", "imported", result);
    if (expected_show) |show| {
        if (result.code != 0 or result.stderr.len != 0 or !std.mem.eql(u8, result.stdout, show))
            return error.UnexpectedQueryState;
    } else if (result.code != 2 or result.stdout.len != 0 or result.stderr.len == 0)
        return error.UnexpectedQueryState;
    const after = try captureAdmin(fixture.allocator, fixture.io, admin);
    defer fixture.allocator.free(after);
    const root_after = try captureQueryRoot(fixture, root);
    defer fixture.allocator.free(root_after);
    if (!std.mem.eql(u8, before, after) or !std.mem.eql(u8, root_before, root_after))
        return error.DpkgQueryMutatedRoot;
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

fn importedBaseline(case: *support.Scenario) !void {
    const destination = try support.path(case.fixture.allocator, case.name, "import-baseline");
    defer case.fixture.allocator.free(destination);
    try case.fixture.directory(destination);
    try support.compare(case.fixture, case.reference_root, case.native_root, destination, case.helper);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const evidence = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/var/lib/debz", .{ case.name, side });
        defer case.fixture.allocator.free(evidence);
        try support.absent(case.fixture, evidence);
    }
}

fn importedLifecycleCases(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, query: []const u8, architecture: []const u8) !void {
    const keeper = "aaa-dpkg-query-imported-keeper";
    const keeper_archive = try support.makePackage(fixture, architecture, "1", keeper, "dpkg-query-imported-packages", .{});
    defer fixture.allocator.free(keeper_archive);
    const keeper_show = try std.fmt.allocPrint(fixture.allocator, keeper ++ " 1 {s} install ok installed\n", .{architecture});
    defer fixture.allocator.free(keeper_show);
    for ([_]struct { name: []const u8, operation: []const u8, version: ?[]const u8, status: ?[]const u8, fails: bool = false }{
        .{ .name = "dpkg-query-imported-configured", .operation = "upgrade", .version = "2", .status = "install ok installed" },
        .{ .name = "dpkg-query-imported-residual", .operation = "remove", .version = "1", .status = "deinstall ok config-files" },
        .{ .name = "dpkg-query-imported-purged", .operation = "purge", .version = null, .status = null },
        .{ .name = "dpkg-query-imported-half-configured", .operation = "upgrade", .version = "2", .status = "install ok half-configured", .fails = true },
    }) |entry| {
        const conffile = try std.fmt.allocPrint(fixture.allocator, "etc/{s}.conf", .{entry.name});
        defer fixture.allocator.free(conffile);
        const spec: support.PackageSpec = .{ .conffile_content = "imported configuration\n", .conffile_path = conffile };
        const first = try support.makePackage(fixture, architecture, "1", entry.name, "dpkg-query-imported-packages", spec);
        defer fixture.allocator.free(first);
        const second = if (std.mem.eql(u8, entry.operation, "upgrade"))
            try support.makePackage(fixture, architecture, "2", entry.name, "dpkg-query-imported-packages", spec)
        else
            null;
        defer if (second) |archive| fixture.allocator.free(archive);
        var case = try support.Scenario.init(fixture, entry.name, driver, dpkg, architecture, false);
        defer case.deinit();
        try case.seed(keeper_archive);
        try case.seed(first);
        try importedBaseline(&case);
        const search = try std.fmt.allocPrint(fixture.allocator, "/{s}", .{conffile});
        defer fixture.allocator.free(search);
        const before_show = try std.fmt.allocPrint(fixture.allocator, "{s}{s} 1 {s} install ok installed\n", .{
            keeper_show, entry.name, architecture,
        });
        defer fixture.allocator.free(before_show);
        try compareQueriesAt(&case, query, entry.name, search, "query-before-mutation", .{
            .package = entry.name,
            .version = "1",
            .status = "install ok installed",
            .show_all = before_show,
            .search_path = search,
            .conffile = search,
        });
        if (entry.fails) {
            const marker = try std.fmt.allocPrint(fixture.allocator, "{s}@2:postinst:configure\n", .{entry.name});
            defer fixture.allocator.free(marker);
            try failureMarker(&case, marker);
        }
        const selected = [_]foundation.PackageIdentity{.{ .name = entry.name, .architecture = architecture }};
        try case.phase(.{
            .operation = entry.operation,
            .archives = if (second) |archive| &.{archive} else &.{},
            .packages = &selected,
        }, entry.fails);
        const after_show = if (entry.version) |version|
            try std.fmt.allocPrint(fixture.allocator, "{s}{s} {s} {s} {s}\n", .{
                keeper_show, entry.name, version, architecture, entry.status.?,
            })
        else
            try fixture.allocator.dupe(u8, keeper_show);
        defer fixture.allocator.free(after_show);
        try compareQueriesAt(&case, query, entry.name, search, "query-after-mutation", .{
            .package = entry.name,
            .version = entry.version,
            .status = entry.status,
            .show_all = after_show,
            .search_path = search,
            .conffile = search,
            .config_version = if (entry.fails or std.mem.eql(u8, entry.operation, "remove")) "1" else null,
            .residual = std.mem.eql(u8, entry.operation, "remove"),
        });
    }
}

fn importedTriggerPendingCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, query: []const u8, architecture: []const u8) !void {
    const handler_name = "dpkg-query-imported-trigger-handler";
    const source_name = "dpkg-query-imported-trigger-source";
    const trigger = "debz-dpkg-query-imported-trigger";
    const handler = try support.makePackage(fixture, architecture, "1", handler_name, "dpkg-query-imported-packages", .{
        .declarations = "interest-noawait " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    const spec: support.PackageSpec = .{ .declarations = "activate-noawait " ++ trigger ++ "\n" };
    const first = try support.makePackage(fixture, architecture, "1", source_name, "dpkg-query-imported-packages", .{});
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, architecture, "2", source_name, "dpkg-query-imported-packages", spec);
    defer fixture.allocator.free(second);
    var case = try support.Scenario.init(fixture, "dpkg-query-imported-trigger-pending", driver, dpkg, architecture, false);
    defer case.deinit();
    try case.seed(handler);
    try case.seed(first);
    try importedBaseline(&case);
    const before_show = try std.fmt.allocPrint(fixture.allocator, handler_name ++ " 1 {s} install ok installed\n" ++ source_name ++ " 1 {s} install ok installed\n", .{ architecture, architecture });
    defer fixture.allocator.free(before_show);
    try compareQueriesAt(&case, query, handler_name, "/usr/share/" ++ handler_name ++ "/data", "query-before-mutation", .{
        .package = handler_name,
        .version = "1",
        .status = "install ok installed",
        .show_all = before_show,
        .search_path = "/usr/share/" ++ handler_name ++ "/data",
    });
    const selected = [_]foundation.PackageIdentity{.{ .name = source_name, .architecture = architecture }};
    try case.phase(.{
        .operation = "upgrade",
        .archives = &.{second},
        .packages = &selected,
        .triggers = true,
        .defer_triggers = true,
    }, false);
    const after_show = try std.fmt.allocPrint(fixture.allocator, handler_name ++ " 1 {s} install ok triggers-pending\n" ++ source_name ++ " 2 {s} install ok installed\n", .{ architecture, architecture });
    defer fixture.allocator.free(after_show);
    for ([_]struct { name: []const u8, version: []const u8, status: []const u8, pending: ?[]const u8 = null, checkpoint: []const u8, path: []const u8 }{
        .{ .name = handler_name, .version = "1", .status = "install ok triggers-pending", .pending = trigger, .checkpoint = "query-pending-handler", .path = "/usr/share/" ++ handler_name ++ "/data" },
        .{ .name = source_name, .version = "2", .status = "install ok installed", .checkpoint = "query-upgraded-source", .path = "/usr/share/" ++ source_name ++ "/data" },
    }) |entry| {
        try compareQueriesAt(&case, query, entry.name, entry.path, entry.checkpoint, .{
            .package = entry.name,
            .version = entry.version,
            .status = entry.status,
            .show_all = after_show,
            .search_path = entry.path,
            .pending = entry.pending,
        });
    }
}

pub fn runImported(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, architecture: []const u8) !void {
    const query = try selectReferenceDpkgQuery(fixture.allocator, fixture.io, dpkg, architecture);
    defer fixture.allocator.free(query);
    try importedLifecycleCases(fixture, driver, dpkg, query, architecture);
    try importedTriggerPendingCase(fixture, driver, dpkg, query, architecture);
}

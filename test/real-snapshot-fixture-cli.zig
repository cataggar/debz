const std = @import("std");

const signer = "f6ecb3762474eda9d21b7022871920d1991bc93c";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.arena.allocator();
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    var arguments: std.ArrayList([]const u8) = .empty;
    while (iterator.next()) |argument| {
        if (arguments.items.len >= 64 or argument.len > 4096) return error.InvalidArguments;
        try arguments.append(allocator, argument);
    }
    const args = arguments.items;
    if (args.len == 0) return error.InvalidArguments;
    const operation = args[0];
    const scenario = init.environ_map.get("SNAPSHOT_TEST_SCENARIO") orelse "";
    const calls = init.environ_map.get("SNAPSHOT_TEST_CALLS") orelse return error.MissingCallLog;
    const line = try std.json.Stringify.valueAlloc(allocator, args, .{});
    var log = try std.Io.Dir.createFileAbsolute(io, calls, .{ .read = true, .truncate = false });
    defer log.close(io);
    const offset = try log.length(io);
    try log.writePositionalAll(io, line, offset);
    try log.writePositionalAll(io, "\n", offset + line.len);

    if ((equals(scenario, "retry-log") or equals(scenario, "unexpected-stderr")) and
        (equals(operation, "refresh") or equals(operation, "download")))
    {
        try std.Io.File.stderr().writeStreamingAll(io, if (equals(scenario, "retry-log"))
            "debz acquisition retry failed_attempt=1/6 delay_ms=2000 http_status=503\n"
        else
            "unexpected acquisition warning\n");
    }
    if (equals(operation, "refresh") and equals(scenario, "freshness-failure")) {
        try std.Io.File.stdout().writeStreamingAll(io,
            \\{"operation":"refresh","exit_status":4,"changed":false,"summary":"ReleaseExpired","diagnostics":[{"id":"repository_authentication_failed","message":"ReleaseExpired"}]}
            ++ "\n");
        std.process.exit(4);
    }

    const input_path = option(args, "--lock-input");
    const lock_data = if (input_path) |path| try read(io, allocator, path) else null;
    var parsed_lock: ?std.json.Parsed(std.json.Value) = if (lock_data) |data|
        try std.json.parseFromSlice(std.json.Value, allocator, data, .{})
    else
        null;
    defer if (parsed_lock) |*parsed| parsed.deinit();
    const digest: ?[]const u8 = if (parsed_lock) |parsed| parsed.value.object.get("digest_sha256").?.string else null;
    if (equals(operation, "plan") and digest != null and std.mem.startsWith(u8, digest.?, "0")) {
        try std.Io.File.stdout().writeStreamingAll(io, "{\"exit_status\":5}\n");
        std.process.exit(5);
    }
    if (equals(operation, "plan")) {
        const intent: []const u8 = if (equals(args[args.len - 1], "ubuntu-minimal")) "install" else "upgrade-all";
        if (option(args, "--lock-output")) |path| {
            if (lock_data) |data| {
                try write(io, path, data);
            } else {
                const arch = option(args, "--architecture") orelse return error.MissingArchitecture;
                const lock = try std.json.Stringify.valueAlloc(allocator, .{
                    .schema = "https://debz.dev/schema/exact-closure-lock-v3",
                    .version = @as(u8, 3),
                    .target_architecture = arch,
                    .packages = [_]struct {
                        name: []const u8,
                        declared_size: u8,
                        archive_identity: struct { primary: []const u8 },
                    }{.{ .name = "ubuntu-minimal", .declared_size = 1, .archive_identity = .{ .primary = "sha512" } }},
                    .repositories = [_]struct {
                        index_identity: struct { primary: []const u8 },
                        signer_fingerprints: [1][]const u8,
                    }{.{
                        .index_identity = .{ .primary = "sha512" },
                        .signer_fingerprints = .{if (equals(scenario, "unreviewed-signer") or
                            (equals(scenario, "unreviewed-update-signer") and equals(intent, "upgrade-all")))
                            "unreviewed"
                        else
                            signer},
                    }},
                    .digest_sha256 = if (equals(intent, "install"))
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    else
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    .fixture_intent = intent,
                }, .{});
                try write(io, path, lock);
            }
        }
    }
    if (equals(operation, "install") or equals(operation, "upgrade-all")) {
        const lock = parsed_lock orelse return error.MissingLock;
        if (!equals(lock.value.object.get("fixture_intent").?.string, operation))
            return error.MismatchedLockIntent;
        const install_root = option(args, "--install-root") orelse return error.MissingRoot;
        const state_path = option(args, "--state-path") orelse return error.MissingState;
        var root = try std.Io.Dir.openDirAbsolute(io, install_root, .{});
        defer root.close(io);
        try root.createDirPath(io, "var/lib/dpkg/info");
        if (equals(operation, "install")) {
            const arch = option(args, "--architecture") orelse return error.MissingArchitecture;
            const status = try std.fmt.allocPrint(allocator,
                "Package: ubuntu-minimal\nStatus: install ok installed\nArchitecture: {s}\nVersion: 1.0\nDescription: offline driver fixture\n\n",
                .{arch});
            try root.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = status });
            try root.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/ubuntu-minimal.list", .data = if (equals(scenario, "owned-excluded-device"))
                "/.\n/usr\n/dev/null\n"
            else
                "/.\n/usr\n" });
        } else if (equals(scenario, "changed-status")) {
            const status = try root.readFileAlloc(io, "var/lib/dpkg/status", allocator, .limited(32 * 1024));
            const changed = try std.mem.replaceOwned(u8, allocator, status, "Version: 1.0", "Version: 2.0");
            try root.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = changed });
        }
        const receipt = try std.json.Stringify.valueAlloc(allocator, .{
            .outcome = "succeeded",
            .commands = if (equals(operation, "install")) &[_][]const u8{"fixture-install"} else &[_][]const u8{},
            .fixture_lock_digest = digest.?,
        }, .{});
        const receipt_path = try std.fmt.allocPrint(allocator, "{s}/transaction-result.json", .{state_path});
        try write(io, receipt_path, receipt);
        if (equals(operation, "install")) {
            try root.createDirPath(io, "var/lib/debz");
            const provenance = try std.json.Stringify.valueAlloc(allocator, .{
                .outcome = "succeeded",
                .fixture_lock_digest = digest.?,
            }, .{});
            try root.writeFile(io, .{ .sub_path = "var/lib/debz/native-transaction-provenance-v2.json", .data = provenance });
            try root.writeFile(io, .{ .sub_path = "var/lib/debz/root-operation-completion-v2.json", .data = provenance });
        }
    }
    if (equals(operation, "transaction-result")) {
        if (args.len < 2 or !equals(args[1], "verify") or digest == null) return error.InvalidVerification;
        const state_path = option(args, "--state-path") orelse return error.MissingState;
        const receipt_path = try std.fmt.allocPrint(allocator, "{s}/transaction-result.json", .{state_path});
        const receipt = try read(io, allocator, receipt_path);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, receipt, .{});
        defer parsed.deinit();
        if (!equals(parsed.value.object.get("fixture_lock_digest").?.string, digest.?))
            return error.MismatchedReceipt;
        try std.Io.File.stdout().writeStreamingAll(io, if (equals(scenario, "failed-verification"))
            "{\"outcome\":\"failed\"}\n"
        else
            "{\"outcome\":\"succeeded\"}\n");
    } else {
        const changed = !equals(operation, "refresh") and !equals(operation, "plan") and
            !equals(operation, "download") and !equals(operation, "upgrade-all");
        try std.Io.File.stdout().writeStreamingAll(io, if (changed)
            "{\"exit_status\":0,\"changed\":true}\n"
        else
            "{\"exit_status\":0,\"changed\":false}\n");
    }
}

fn equals(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn option(args: []const []const u8, name: []const u8) ?[]const u8 {
    for (args, 0..) |arg, index| {
        if (equals(arg, name) and index + 1 < args.len) return args[index + 1];
    }
    return null;
}

fn read(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(512 * 1024));
}

fn write(io: std.Io, path: []const u8, data: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, data);
}

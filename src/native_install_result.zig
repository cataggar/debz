const std = @import("std");
const api = @import("product_api.zig");
const native_recovery = @import("native_recovery.zig");
const native_transaction_result = @import("native_transaction_result.zig");

pub const schema_id = "io.github.cataggar.debz.native-install-result.v1";
pub const capability_schema_id = "io.github.cataggar.debz.native-install-capability.v1";

pub fn capabilitiesJson(allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    std.json.Stringify.value(.{
        .schema = capability_schema_id,
        .api_version = @as(u32, 1),
        .backend = "native",
        .capability = "native-install-v1",
        .result_schema = schema_id,
        .result_api_version = @as(u32, 1),
        .summary_schema = native_transaction_result.schema_id,
        .summary_api_version = native_transaction_result.api_version,
        .receipt_binding = true,
        .unchanged_without_receipt = true,
    }, .{ .whitespace = .minified }, &output.writer) catch return error.OutOfMemory;
    output.writer.writeByte('\n') catch return error.OutOfMemory;
    return output.toOwnedSlice();
}

pub fn canonicalJson(
    allocator: std.mem.Allocator,
    request: api.Request,
    result: api.Result,
) ![]u8 {
    const evidence = result.native_install orelse return error.NativeInstallEvidenceMissing;
    if (request.operation != .install or result.operation != .install or
        result.exit_status != .success or result.diagnostic_count != 0 or
        request.options.lock_input_path == null or evidence.package_count > 100_000 or
        result.changed != (evidence.receipt != null))
        return error.InvalidNativeInstallResult;
    const command = result.canonicalJson(allocator) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
    defer allocator.free(command);
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;
    writer.writeAll("{\"schema\":\"" ++ schema_id ++ "\",\"api_version\":1,\"backend\":\"native\",\"command\":") catch return error.OutOfMemory;
    writer.writeAll(command[0 .. command.len - 1]) catch return error.OutOfMemory;
    writer.writeAll(",\"evidence\":") catch return error.OutOfMemory;
    const Receipt = struct {
        transaction_digest_sha256: []const u8,
        completion_digest_sha256: []const u8,
        program_sha256: []const u8,
    };
    std.json.Stringify.value(.{
        .install_root = request.options.install_root,
        .target_architecture = request.options.architecture,
        .lock_sha256 = @as([]const u8, &native_recovery.hexDigest(evidence.lock_sha256)),
        .caller_request_sha256 = @as([]const u8, &native_recovery.hexDigest(evidence.caller_request_sha256)),
        .caller_policy_sha256 = @as([]const u8, &native_recovery.hexDigest(evidence.caller_policy_sha256)),
        .package_count = evidence.package_count,
        .receipt = if (evidence.receipt) |receipt| @as(?Receipt, .{
            .transaction_digest_sha256 = &native_recovery.hexDigest(receipt.transaction_digest_sha256),
            .completion_digest_sha256 = &native_recovery.hexDigest(receipt.completion_digest_sha256),
            .program_sha256 = &native_recovery.hexDigest(receipt.program_sha256),
        }) else null,
    }, .{ .whitespace = .minified }, writer) catch return error.OutOfMemory;
    writer.writeAll("}\n") catch return error.OutOfMemory;
    return output.toOwnedSlice();
}

const test_request: api.Request = .{
    .operation = .install,
    .packages = &.{"demo"},
    .options = .{
        .install_root = "/root",
        .cache_path = "/cache",
        .state_path = "/state",
        .architecture = "amd64",
        .lock_input_path = "/lock.json",
    },
};

fn testResult(changed: bool) api.Result {
    return .{
        .operation = .install,
        .exit_status = .success,
        .changed = changed,
        .summary = "verified",
        .native_install = .{
            .lock_sha256 = @splat(1),
            .caller_request_sha256 = @splat(2),
            .caller_policy_sha256 = @splat(3),
            .package_count = 4,
            .receipt = if (changed) .{
                .transaction_digest_sha256 = @splat(4),
                .completion_digest_sha256 = @splat(5),
                .program_sha256 = @splat(6),
            } else null,
        },
    };
}

test "native_install_result.test.changed installs bind receipts while unchanged installs do not invent them" {
    for ([_]bool{ false, true }) |changed| {
        const json = try canonicalJson(std.testing.allocator, test_request, testResult(changed));
        defer std.testing.allocator.free(json);
        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
        defer parsed.deinit();
        const receipt = parsed.value.object.get("evidence").?.object.get("receipt").?;
        try std.testing.expectEqual(changed, receipt != .null);
        if (changed) try std.testing.expectEqualStrings("04" ** 32, receipt.object.get("transaction_digest_sha256").?.string);
        var invalid = testResult(changed);
        invalid.changed = !changed;
        try std.testing.expectError(error.InvalidNativeInstallResult, canonicalJson(std.testing.allocator, test_request, invalid));
        const legacy = try testResult(changed).canonicalJson(std.testing.allocator);
        defer std.testing.allocator.free(legacy);
        try std.testing.expect(std.mem.indexOf(u8, legacy, "native_install") == null);
        try std.testing.expect(std.mem.indexOf(u8, legacy, "receipt") == null);
    }
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const capabilities = try capabilitiesJson(allocator);
    defer allocator.free(capabilities);
    const json = try canonicalJson(allocator, test_request, testResult(true));
    defer allocator.free(json);
}

test "native_install_result.test.serializers report allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

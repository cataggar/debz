//! Public native repository boundary. Only result data leaves the projection.
const std = @import("std");
const builtin = @import("builtin");
const api = @import("repository_api.zig");
const backend = @import("repository_backend.zig");
const live_root = @import("live_root.zig");
const transaction_executor = @import("transaction_executor.zig");
const linux = std.os.linux;

pub fn executeNative(allocator: std.mem.Allocator, request: api.Request) !api.Result {
    if (api.validateRequest(request)) |invalid| return invalid;
    if (!std.mem.eql(u8, request.root, "/"))
        return api.failure(
            .unavailable,
            .transaction_backend_unavailable,
            "request",
            "native repository CLI requires --root /; alternate roots are not supported",
        );
    if (builtin.os.tag != .linux)
        return api.failure(.unavailable, .transaction_backend_unavailable, "runner", "native repository execution requires Linux");

    var clock: Clock = .{};
    const started = clock.read() catch |err| return runnerFailure(err);
    const deadline: transaction_executor.Deadline = .{
        .context = &clock,
        .nowMsFn = Clock.now,
        .expires_at_ms = started +| request.network.overall_timeout_ms,
    };
    const fd = openTransport() catch |err| return runnerFailure(err);
    defer _ = linux.close(fd);
    var context: ChildContext = .{ .request = request, .deadline = deadline, .output_fd = fd };
    const outcome = live_root.runProjected(.{
        .context = &context,
        .child = projectedChild,
        .deadline = deadline,
    }) catch |err| return runnerFailure(if (clock.failed) error.ClockUnavailable else err);
    if (clock.failed) return runnerFailure(error.ClockUnavailable);
    if (supervisorFailure(outcome)) |failure| return failure;
    return receiveResult(allocator, fd) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => runnerFailure(err),
    };
}

const Clock = struct {
    failed: bool = false,

    fn read(self: *@This()) !u64 {
        var timestamp: linux.timespec = undefined;
        if (linux.errno(linux.clock_gettime(.MONOTONIC, &timestamp)) != .SUCCESS or
            timestamp.sec < 0 or timestamp.nsec < 0 or timestamp.nsec >= std.time.ns_per_s)
        {
            self.failed = true;
            return error.ClockUnavailable;
        }
        return @as(u64, @intCast(timestamp.sec)) *| std.time.ms_per_s +
            @as(u64, @intCast(timestamp.nsec)) / std.time.ns_per_ms;
    }

    fn now(raw: ?*anyopaque) u64 {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        // Deadline callbacks cannot return errors. Expire, then surface the
        // clock failure at the boundary instead of granting another budget.
        return self.read() catch std.math.maxInt(u64);
    }
};

const ChildContext = struct {
    request: api.Request,
    deadline: transaction_executor.Deadline,
    output_fd: i32,
};

fn projectedChild(raw: ?*anyopaque, projection: *const live_root.Projection) !u8 {
    const context: *ChildContext = @ptrCast(@alignCast(raw.?));
    _ = try context.deadline.remainingMs();
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    // Do not use the parent's allocator or inherited threaded I/O after fork.
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    var production: backend.Backend = .{
        .io = threaded.io(),
        .transaction_backend = .native,
        .root_projection = projection,
        .native_deadline = context.deadline,
    };
    var request = context.request;
    request.root = live_root.logical_root_path;
    var result = try api.execute(arena.allocator(), request, production.nativeInterface());
    defer result.deinit();
    const clock: *Clock = @ptrCast(@alignCast(context.deadline.context.?));
    if (clock.failed) return error.ClockUnavailable;
    const source = try result.canonicalJson(arena.allocator());
    try writeTransport(context.output_fd, source);
    return 0;
}

fn runnerFailure(err: anyerror) api.Result {
    return switch (err) {
        error.UnsupportedPlatform,
        error.NotPrivileged,
        error.UnsafeRuntimeDirectory,
        error.UnsafeLockFile,
        error.UnsafeMountpoint,
        error.ActiveHostMount,
        error.RootReplaced,
        error.RuntimeReplaced,
        error.LockReplaced,
        error.MountpointReplaced,
        error.NamespaceUnavailable,
        => api.failure(.unavailable, .transaction_backend_unavailable, "runner", @errorName(err)),
        error.DeadlineExceeded => api.failure(
            .recovery,
            .resource_limit_exceeded,
            "runner",
            "native invocation deadline exceeded; retry the same request to reconcile retained state",
        ),
        else => api.failure(.recovery, .recovery_required, "runner", @errorName(err)),
    };
}

fn supervisorFailure(outcome: live_root.Result) ?api.Result {
    return switch (outcome) {
        .exited => |code| if (code == 0) null else api.failure(.recovery, .recovery_required, "runner", "native repository child exited without a trusted result"),
        .interrupted => api.failure(.recovery, .recovery_required, "runner", "native repository invocation interrupted; retry the same request"),
        .signaled => api.failure(.recovery, .recovery_required, "runner", "native repository supervisor terminated by signal"),
        .setup_failed => |failure| api.failure(
            if (failure.stage == .callback or failure.stage == .cleanup) .recovery else .unavailable,
            if (failure.stage == .callback or failure.stage == .cleanup) .recovery_required else .transaction_backend_unavailable,
            "runner",
            @tagName(failure.stage),
        ),
    };
}

fn openTransport() !i32 {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const fd = linux.memfd_create("debz-repository-result", linux.MFD.CLOEXEC);
    if (linux.errno(fd) != .SUCCESS) return error.ResultTransportUnavailable;
    return @intCast(fd);
}

fn writeAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (linux.errno(count)) {
            .SUCCESS => {
                if (count == 0) return error.ResultTransportFailed;
                offset += count;
            },
            .INTR => continue,
            else => return error.ResultTransportFailed,
        }
    }
}

fn writeTransport(fd: i32, source: []const u8) !void {
    if (source.len == 0 or source.len > api.maximum_document_bytes) return error.DocumentTooLarge;
    var length: [4]u8 = undefined;
    std.mem.writeInt(u32, &length, @intCast(source.len), .little);
    try writeAll(fd, &length);
    try writeAll(fd, source);
}

fn readExact(fd: i32, buffer: []u8, start: usize) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const count = linux.pread(fd, buffer[offset..].ptr, buffer.len - offset, @intCast(start + offset));
        switch (linux.errno(count)) {
            .SUCCESS => {
                if (count == 0) return error.TruncatedResult;
                offset += count;
            },
            .INTR => continue,
            else => return error.ResultTransportFailed,
        }
    }
}

fn receiveResult(allocator: std.mem.Allocator, fd: i32) !api.Result {
    var length: [4]u8 = undefined;
    try readExact(fd, &length, 0);
    const size = std.mem.readInt(u32, &length, .little);
    if (size == 0 or size > api.maximum_document_bytes) return error.DocumentTooLarge;
    const source = try allocator.alloc(u8, size);
    defer allocator.free(source);
    try readExact(fd, source, length.len);
    var extra: [1]u8 = undefined;
    while (true) {
        const count = linux.pread(fd, &extra, 1, @intCast(length.len + source.len));
        switch (linux.errno(count)) {
            .SUCCESS => if (count != 0) return error.TrailingResultData else break,
            .INTR => continue,
            else => return error.ResultTransportFailed,
        }
    }
    var decoded = try api.decode(allocator, source, api.maximum_document_bytes);
    defer decoded.deinit();
    return api.ownResult(allocator, decoded.result);
}

test "repository_command.test.native public admission refuses root aliases before setup" {
    for ([_][]const u8{ "/target", live_root.logical_root_path, "/missing-native-root" }) |root| {
        var result = try executeNative(std.testing.allocator, .{
            .root = root,
            .descriptor_url = "https://example.test/descriptor.deb",
        });
        defer result.deinit();
        try std.testing.expectEqual(api.ExitStatus.unavailable, result.exit_status);
        try std.testing.expectEqual(api.DiagnosticId.transaction_backend_unavailable, result.diagnostics[0].id);
        try std.testing.expect(result.paths.operation_state == null);
    }
    var invalid = try executeNative(std.testing.allocator, .{ .root = "/", .descriptor_url = "http://example.test/unpinned.deb" });
    defer invalid.deinit();
    try std.testing.expectEqual(api.ExitStatus.usage, invalid.exit_status);
}

test "repository_command.test.canonical transport is owned and allocation safe" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn exercise(allocator: std.mem.Allocator) !void {
            const fd = try openTransport();
            defer _ = linux.close(fd);
            const expected = api.failure(.recovery, .recovery_required, "runner", "retained native state requires recovery");
            const source = try expected.canonicalJson(allocator);
            defer allocator.free(source);
            try writeTransport(fd, source);
            var actual = try receiveResult(allocator, fd);
            defer actual.deinit();
            try std.testing.expectEqualSlices(u8, &expected.digest_sha256, &actual.digest_sha256);
            try std.testing.expect(actual.ownership != null);
        }
    }.exercise, .{});
}

test "repository_command.test.transport refuses missing truncated oversized trailing and noncanonical results" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const source = try api.failure(.recovery, .recovery_required, "runner", "failure").canonicalJson(allocator);
    defer allocator.free(source);
    const noncanonical = try std.fmt.allocPrint(allocator, " {s}", .{source});
    defer allocator.free(noncanonical);
    const corrupt = try allocator.dupe(u8, source);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 3] = if (corrupt[corrupt.len - 3] == '0') '1' else '0';
    for (0..8) |mode| {
        const fd = try openTransport();
        defer _ = linux.close(fd);
        switch (mode) {
            0 => {},
            1 => try writeAll(fd, &.{ 0xff, 0xff, 0xff, 0xff }),
            2 => try writeAll(fd, &.{ 10, 0, 0, 0, '{' }),
            3 => {
                try writeTransport(fd, source);
                try writeAll(fd, "extra");
            },
            4 => try writeTransport(fd, noncanonical),
            5 => try writeTransport(fd, "{}"),
            6 => try writeTransport(fd, corrupt),
            7 => try writeAll(fd, &.{ 0, 0, 0, 0 }),
            else => unreachable,
        }
        const expected = switch (mode) {
            0, 2 => error.TruncatedResult,
            1 => error.DocumentTooLarge,
            3 => error.TrailingResultData,
            4 => error.NonCanonicalDocument,
            5 => error.InvalidDocument,
            6 => error.DigestMismatch,
            7 => error.DocumentTooLarge,
            else => unreachable,
        };
        try std.testing.expectError(expected, receiveResult(allocator, fd));
    }
}

test "repository_command.test.failed supervision never accepts child result data" {
    try std.testing.expect(supervisorFailure(.{ .exited = 0 }) == null);
    for ([_]live_root.Result{
        .{ .exited = 1 },
        .{ .signaled = 9 },
        .{ .interrupted = 15 },
        .{ .setup_failed = .{ .stage = .callback } },
        .{ .setup_failed = .{ .stage = .cleanup } },
        .{ .setup_failed = .{ .stage = .mount_namespace } },
    }) |outcome| {
        const failure = supervisorFailure(outcome).?;
        try std.testing.expect(failure.exit_status != .success);
        try std.testing.expect(!failure.changed and !failure.installed);
    }
    try std.testing.expectEqual(api.ExitStatus.recovery, runnerFailure(error.DeadlineExceeded).exit_status);
}

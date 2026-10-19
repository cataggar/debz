//! Privileged short-profile `debz install <package>`. The host root is read and
//! written only through the authenticated private projection, and only the
//! canonical result document leaves it.
const std = @import("std");
const builtin = @import("builtin");
const api = @import("product_api.zig");
const live_root = @import("live_root.zig");
const production_backend = @import("production_backend.zig");
const repository_refresh = @import("repository_refresh.zig");
const root_operation = @import("root_operation.zig");
const system_install = @import("system_install.zig");
const system_product_context = @import("system_product_context.zig");
const transaction_executor = @import("transaction_executor.zig");
const linux = std.os.linux;

pub const privilege_message = "system install requires root privilege (run with sudo); nothing was changed";

pub const Options = struct {
    /// False in native-only rehearsal builds, which refuse legacy planning.
    legacy_execution_capable: bool = true,
};

pub fn execute(
    allocator: std.mem.Allocator,
    invocation: system_install.Invocation,
    kind: system_install.Kind,
    options: Options,
) !system_install.OwnedResult {
    const package = invocation.package;
    if (builtin.os.tag != .linux)
        return system_install.refusal(allocator, package, .unavailable, .transaction_backend_unavailable, "system install requires Linux; nothing was changed");
    if (linux.geteuid() != 0)
        return system_install.refusal(allocator, package, .unavailable, .transaction_backend_unavailable, privilege_message);
    var clock: Clock = .{};
    const deadline: ?transaction_executor.Deadline = if (invocation.deadline_ms) |budget| .{
        .context = &clock,
        .nowMsFn = Clock.now,
        .expires_at_ms = (clock.read() catch |err| return runnerFailure(allocator, package, err)) +| budget,
    } else null;
    const fd = openTransport() catch |err| return runnerFailure(allocator, package, err);
    defer _ = linux.close(fd);
    var context: ChildContext = .{
        .invocation = invocation,
        .kind = kind,
        .options = options,
        .deadline = deadline,
        .clock = &clock,
        .output_fd = fd,
    };
    const outcome = live_root.runProjected(.{
        .context = &context,
        .child = projectedChild,
        .deadline = deadline,
    }) catch |err| return runnerFailure(allocator, package, if (clock.failed) error.ClockUnavailable else err);
    if (clock.failed) return runnerFailure(allocator, package, error.ClockUnavailable);
    if (supervisorFailure(outcome)) |failure|
        return system_install.refusal(allocator, package, failure.status, failure.id, failure.message);
    return receiveResult(allocator, fd) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => runnerFailure(allocator, package, err),
    };
}

/// Re-verifies the active configuration and refuses other surfaces' owned work.
pub const Revalidation = struct {
    context: *const system_product_context.Context,

    fn check(raw: ?*anyopaque) anyerror!void {
        const self: *Revalidation = @ptrCast(@alignCast(raw.?));
        try self.context.validate();
    }
};

/// What the active configuration authorizes for one run. Disabled
/// repositories authorize nothing, so a lock naming one no longer binds.
pub fn authorityOf(
    allocator: std.mem.Allocator,
    context: *const system_product_context.Context,
    root_path: []const u8,
    revalidation: *Revalidation,
) !system_install.Authority {
    const facts = context.snapshot();
    var repositories: std.ArrayList(system_install.RepositoryAuthority) = .empty;
    errdefer repositories.deinit(allocator);
    for (facts.configuration.repositories) |repository| {
        if (!repository.enabled) continue;
        try repositories.append(allocator, .{
            .id = repository.id.bytes,
            .uri = repository.uri,
            .suite = repository.suite,
            .component = repository.component,
            .freshness = freshnessOf(repository.freshness),
            .archive_binding = repository.archive_binding,
        });
    }
    return .{
        .root_path = root_path,
        .architecture = context.options().architecture,
        .context = .{
            .configuration_sha256 = facts.configuration.identity.bytes,
            .manifest_sha256 = facts.manifest.digest_sha256,
        },
        .repositories = try repositories.toOwnedSlice(allocator),
        .revalidate = .{ .context = revalidation, .function = Revalidation.check },
    };
}

fn freshnessOf(policy: repository_refresh.ExpiryPolicy) system_install.Freshness {
    return switch (policy) {
        .require_valid_until => .{ .policy = .require_valid_until },
        .allow_missing_valid_until_with_max_age_seconds => |seconds| .{
            .policy = .bounded_missing_valid_until,
            .maximum_release_age_seconds = seconds,
        },
        .frozen_release_with_witnesses => .{ .policy = .frozen_release },
    };
}

/// Plans with the production backend against the borrowed active context and
/// publishes only the exact lock the engine names.
pub const ProductionPlanner = struct {
    backend: *production_backend.Backend,
    context: *const system_product_context.Context,

    pub fn interface(self: *ProductionPlanner) system_install.Planner {
        return .{ .context = self, .planFn = plan };
    }

    fn plan(raw: ?*anyopaque, allocator: std.mem.Allocator, request: system_install.PlanRequest) anyerror!system_install.PlanOutcome {
        const self: *ProductionPlanner = @ptrCast(@alignCast(raw.?));
        if (request.backend != self.backend.transaction_backend) return error.PlannerBackendMismatch;
        var options = self.context.options();
        options.lock_output_path = request.lock_output_path;
        options.deadline_ms = request.deadline_ms;
        options.lock_wait_ms = request.lock_wait_ms;
        const result = try self.backend.executeWorkflow(allocator, .{
            .operation = .install,
            .mode = .plan_only,
            .selectors = &.{.{ .name = request.package }},
            .options = options,
        });
        if (result.exit_status == .success) return .published;
        const diagnostics = result.diagnostics[0..result.diagnostic_count];
        return .{ .refused = .{
            .exit_status = result.exit_status,
            .id = if (diagnostics.len != 0) diagnostics[0].id else .planning_failed,
            .message = if (diagnostics.len != 0) diagnostics[0].message else result.summary,
        } };
    }
};

const Failure = struct { status: api.ExitStatus, id: api.ErrorId, message: []const u8 };

const retained_guidance = "any reserved system install attempt is retained; rerun the same command to adopt it";

fn contextFailure(allocator: std.mem.Allocator, package: []const u8, err: anyerror) !system_install.OwnedResult {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.FileNotFound => system_install.refusal(
            allocator,
            package,
            .unavailable,
            .configuration_required,
            system_install.configuration_required_message,
        ),
        error.RootOperationRecoveryRequired => system_install.refusal(
            allocator,
            package,
            .recovery,
            .root_operation_recovery_required,
            "another debz root operation requires recovery before a system install can run; " ++
                "any unfinished system install attempt is retained unchanged; nothing was changed",
        ),
        else => refusalFor(
            allocator,
            package,
            .unavailable,
            .configuration_required,
            "the active repository configuration could not be verified ({s}); nothing was changed",
            err,
        ),
    };
}

fn refusalFor(
    allocator: std.mem.Allocator,
    package: []const u8,
    status: api.ExitStatus,
    id: api.ErrorId,
    comptime format: []const u8,
    err: anyerror,
) !system_install.OwnedResult {
    const message = try std.fmt.allocPrint(allocator, format, .{@errorName(err)});
    defer allocator.free(message);
    return system_install.refusal(allocator, package, status, id, message);
}

fn runnerFailure(allocator: std.mem.Allocator, package: []const u8, err: anyerror) !system_install.OwnedResult {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
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
        error.ResultTransportUnavailable,
        => refusalFor(
            allocator,
            package,
            .unavailable,
            .transaction_backend_unavailable,
            "the private root projection could not be set up ({s}); nothing was changed",
            err,
        ),
        error.DeadlineExceeded => refusalFor(
            allocator,
            package,
            .recovery,
            .root_operation_recovery_required,
            "the system install deadline expired ({s}); " ++ retained_guidance,
            err,
        ),
        else => refusalFor(
            allocator,
            package,
            .recovery,
            .root_operation_recovery_required,
            "the system install supervisor returned no trusted result ({s}); " ++ retained_guidance,
            err,
        ),
    };
}

fn supervisorFailure(outcome: live_root.Result) ?Failure {
    const retained: Failure = .{
        .status = .recovery,
        .id = .root_operation_recovery_required,
        .message = "the system install child returned no trusted result; " ++ retained_guidance,
    };
    return switch (outcome) {
        .exited => |code| if (code == 0) null else retained,
        .interrupted => .{
            .status = .recovery,
            .id = .root_operation_recovery_required,
            .message = "the system install was interrupted; " ++ retained_guidance,
        },
        .signaled => .{
            .status = .recovery,
            .id = .root_operation_recovery_required,
            .message = "the system install supervisor was terminated by a signal; " ++ retained_guidance,
        },
        .setup_failed => |failure| switch (failure.stage) {
            .callback, .cleanup => retained,
            else => .{
                .status = .unavailable,
                .id = .transaction_backend_unavailable,
                .message = "the private root projection could not be set up; nothing was changed",
            },
        },
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
        // Deadline callbacks cannot return errors: expire, then report the clock failure.
        return self.read() catch std.math.maxInt(u64);
    }
};

const ChildContext = struct {
    invocation: system_install.Invocation,
    kind: system_install.Kind,
    options: Options,
    deadline: ?transaction_executor.Deadline,
    clock: *Clock,
    output_fd: i32,
};

fn projectedChild(raw: ?*anyopaque, projection: *const live_root.Projection) !u8 {
    const context: *ChildContext = @ptrCast(@alignCast(raw.?));
    if (context.deadline) |deadline| _ = try deadline.remainingMs();
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    // Do not use the parent's allocator or inherited threaded I/O after fork.
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    var result = try installProjected(arena.allocator(), threaded.io(), projection, context);
    defer result.deinit();
    if (context.clock.failed) return error.ClockUnavailable;
    try writeTransport(context.output_fd, try result.canonicalJson(arena.allocator()));
    return 0;
}

fn installProjected(
    allocator: std.mem.Allocator,
    io: std.Io,
    projection: *const live_root.Projection,
    context: *const ChildContext,
) !system_install.OwnedResult {
    const active = system_product_context.resolveProjected(allocator, io, .{ .root = live_root.logical_root_path }, projection) catch |err|
        return contextFailure(allocator, context.invocation.package, err);
    defer active.deinit();
    var revalidation: Revalidation = .{ .context = active };
    var backend: production_backend.Backend = .{
        .io = io,
        .transaction_backend = context.kind,
        .legacy_execution_capable = context.options.legacy_execution_capable,
        .root_projection = projection,
        .active_context = active,
    };
    var planner: ProductionPlanner = .{ .backend = &backend, .context = active };
    var locks: root_operation.SystemLockBackend = .{ .allocator = allocator, .io = io };
    const engine: system_install.Engine = .{
        .io = io,
        .authority = try authorityOf(allocator, active, live_root.logical_root_path, &revalidation),
        .planner = planner.interface(),
        .locks = locks.interface(),
    };
    return engine.run(allocator, context.invocation, context.kind);
}

fn openTransport() !i32 {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const fd = linux.memfd_create("debz-system-install-result", linux.MFD.CLOEXEC);
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
    if (source.len == 0 or source.len > system_install.maximum_document_bytes) return error.DocumentTooLarge;
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

fn receiveResult(allocator: std.mem.Allocator, fd: i32) !system_install.OwnedResult {
    var length: [4]u8 = undefined;
    try readExact(fd, &length, 0);
    const size = std.mem.readInt(u32, &length, .little);
    if (size == 0 or size > system_install.maximum_document_bytes) return error.DocumentTooLarge;
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
    return system_install.decodeResult(allocator, source);
}

test "system_install_command.test unprivileged invocations refuse before any projection" {
    if (builtin.os.tag != .linux or linux.geteuid() == 0) return error.SkipZigTest;
    var result = try execute(std.testing.allocator, .{ .package = "demo" }, .native, .{});
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, result.exitStatus());
    try std.testing.expectEqualStrings(privilege_message, result.value.summary);
    try std.testing.expect(result.value.attempt_id == null and !result.value.changed);
}

test "system_install_command.test result transport accepts only one exact canonical result" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var expected = try system_install.refusal(allocator, "demo", .recovery, .root_operation_recovery_required, "retained attempt");
    defer expected.deinit();
    const source = try expected.canonicalJson(allocator);
    defer allocator.free(source);
    {
        const fd = try openTransport();
        defer _ = linux.close(fd);
        try writeTransport(fd, source);
        var actual = try receiveResult(allocator, fd);
        defer actual.deinit();
        const round_trip = try actual.canonicalJson(allocator);
        defer allocator.free(round_trip);
        try std.testing.expectEqualStrings(source, round_trip);
    }
    const noncanonical = try std.mem.concat(allocator, u8, &.{ " ", source });
    defer allocator.free(noncanonical);
    for (0..6) |mode| {
        const fd = try openTransport();
        defer _ = linux.close(fd);
        switch (mode) {
            0 => {},
            1 => try writeAll(fd, &.{ 0xff, 0xff, 0xff, 0x7f }),
            2 => try writeAll(fd, &.{ 10, 0, 0, 0, '{' }),
            3 => {
                try writeTransport(fd, source);
                try writeAll(fd, "extra");
            },
            4 => try writeTransport(fd, noncanonical),
            5 => try writeTransport(fd, "{}"),
            else => unreachable,
        }
        const failure = switch (mode) {
            0, 2 => error.TruncatedResult,
            1 => error.DocumentTooLarge,
            3 => error.TrailingResultData,
            4 => error.NonCanonicalResult,
            5 => error.InvalidResult,
            else => unreachable,
        };
        try std.testing.expectError(failure, receiveResult(allocator, fd));
    }
}

test "system_install_command.test failed supervision never accepts child result data" {
    try std.testing.expect(supervisorFailure(.{ .exited = 0 }) == null);
    for ([_]live_root.Result{
        .{ .exited = 1 },
        .{ .signaled = 9 },
        .{ .interrupted = 15 },
        .{ .setup_failed = .{ .stage = .callback } },
        .{ .setup_failed = .{ .stage = .cleanup } },
    }) |outcome| {
        const failure = supervisorFailure(outcome).?;
        try std.testing.expectEqual(api.ExitStatus.recovery, failure.status);
        try std.testing.expect(std.mem.endsWith(u8, failure.message, retained_guidance));
    }
    const setup = supervisorFailure(.{ .setup_failed = .{ .stage = .mount_namespace } }).?;
    try std.testing.expectEqual(api.ExitStatus.unavailable, setup.status);
    var expired = try runnerFailure(std.testing.allocator, "demo", error.DeadlineExceeded);
    defer expired.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, expired.exitStatus());
    try std.testing.expectEqualStrings("the system install deadline expired (DeadlineExceeded); " ++ retained_guidance, expired.value.summary);
    var unprivileged = try runnerFailure(std.testing.allocator, "demo", error.NotPrivileged);
    defer unprivileged.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, unprivileged.exitStatus());
}

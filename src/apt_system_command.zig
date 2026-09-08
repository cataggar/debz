const std = @import("std");
const api = @import("apt_system_api.zig");
const cli = @import("apt_system_cli.zig");
const orchestrator = @import("apt_system_orchestrator.zig");

pub const Engine = struct {
    context: *anyopaque,
    prepareFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        api.Request,
    ) anyerror!orchestrator.PrepareOutcome,
    executeFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        orchestrator.Preparation,
        bool,
    ) anyerror!api.Result,
    prepareRecoveryFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
    ) anyerror!orchestrator.RecoveryPrepareOutcome,
    executeRecoveryFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        orchestrator.RecoveryPreparation,
        bool,
    ) anyerror!api.Result,
    reconcilePreparedErrorFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        orchestrator.Preparation,
    ) anyerror!api.Result,

    pub fn production(engine: *orchestrator.Engine) Engine {
        return .{
            .context = engine,
            .prepareFn = productionPrepare,
            .executeFn = productionExecute,
            .prepareRecoveryFn = productionPrepareRecovery,
            .executeRecoveryFn = productionExecuteRecovery,
            .reconcilePreparedErrorFn = productionReconcilePreparedError,
        };
    }

    fn productionPrepare(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !orchestrator.PrepareOutcome {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.prepare(allocator, request);
    }

    fn productionExecute(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        prepared: orchestrator.Preparation,
        confirmed: bool,
    ) !api.Result {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.execute(allocator, prepared, confirmed);
    }

    fn productionPrepareRecovery(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        profile_path: []const u8,
    ) !orchestrator.RecoveryPrepareOutcome {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.prepareRecovery(allocator, profile_path);
    }

    fn productionExecuteRecovery(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        prepared: orchestrator.RecoveryPreparation,
        confirmed: bool,
    ) !api.Result {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.executeRecovery(allocator, prepared, confirmed);
    }

    fn productionReconcilePreparedError(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        prepared: orchestrator.Preparation,
    ) !api.Result {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.reconcilePreparedError(allocator, prepared);
    }
};

pub const Confirmation = enum {
    confirmed,
    declined,
    unavailable,
};

pub const Terminal = struct {
    context: *anyopaque,
    confirmFn: *const fn (*anyopaque, *std.Io.Writer) anyerror!Confirmation,

    pub fn unavailable() Terminal {
        return .{
            .context = undefined,
            .confirmFn = alwaysUnavailable,
        };
    }

    fn alwaysUnavailable(
        _: *anyopaque,
        _: *std.Io.Writer,
    ) !Confirmation {
        return .unavailable;
    }
};

pub const Streams = struct {
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
};

pub fn runApt(
    allocator: std.mem.Allocator,
    command: cli.ParsedCommand,
    engine: Engine,
    terminal: Terminal,
    streams: Streams,
) !api.ExitStatus {
    var prepared_outcome = engine.prepareFn(
        engine.context,
        allocator,
        command.request,
    ) catch {
        var result = try internalFailure(command.request);
        defer result.deinit();
        try cli.writeResult(
            allocator,
            result,
            command.output,
            streams.stdout,
            streams.stderr,
        );
        return result.exit_status;
    };

    switch (prepared_outcome) {
        .result => |*result| {
            defer result.deinit();
            try cli.writeResult(
                allocator,
                result.*,
                command.output,
                streams.stdout,
                streams.stderr,
            );
            return result.exit_status;
        },
        .ready => |*prepared| {
            defer prepared.deinit();
            const decision = cli.confirmationDecision(command, true);
            if (command.output == .human) {
                try writeReview(prepared.*, null, streams.stdout);
                try streams.stdout.flush();
            }

            const confirmed = switch (decision) {
                .proceed_without_prompt => true,
                .request_tty_confirmation => (terminal.confirmFn(
                    terminal.context,
                    streams.stderr,
                ) catch .unavailable) == .confirmed,
                .return_confirmation_required => false,
                .await_plan => unreachable,
            };
            const items = if (!confirmed and command.output == .json)
                try copyReviewItems(allocator, prepared.review)
            else
                null;
            defer if (items) |value| allocator.free(value);
            var result = if (!confirmed)
                try confirmationResult(
                    prepared.*,
                    null,
                    if (items) |value| value else &.{},
                )
            else
                engine.executeFn(
                    engine.context,
                    allocator,
                    prepared.*,
                    true,
                ) catch try engine.reconcilePreparedErrorFn(
                    engine.context,
                    allocator,
                    prepared.*,
                );
            defer result.deinit();
            try cli.writeResult(
                allocator,
                result,
                command.output,
                streams.stdout,
                streams.stderr,
            );
            return result.exit_status;
        },
    }
}

pub fn runRecovery(
    allocator: std.mem.Allocator,
    profile_path: []const u8,
    output: cli.OutputFormat,
    engine: Engine,
    terminal: Terminal,
    streams: Streams,
) !api.ExitStatus {
    var outcome = engine.prepareRecoveryFn(
        engine.context,
        allocator,
        profile_path,
    ) catch return error.RecoveryPreparationFailed;
    switch (outcome) {
        .result => |*result| {
            defer result.deinit();
            try cli.writeResult(
                allocator,
                result.*,
                output,
                streams.stdout,
                streams.stderr,
            );
            return result.exit_status;
        },
        .ready => |*recovery| {
            defer recovery.deinit();
            if (output == .human) {
                try writeReview(
                    recovery.prepared,
                    recovery.action,
                    streams.stdout,
                );
                try streams.stdout.flush();
            }
            const confirmed = if (output == .json)
                false
            else
                (terminal.confirmFn(
                    terminal.context,
                    streams.stderr,
                ) catch .unavailable) == .confirmed;
            const items = if (!confirmed and output == .json)
                try copyReviewItems(allocator, recovery.prepared.review)
            else
                null;
            defer if (items) |value| allocator.free(value);
            var result = if (confirmed)
                engine.executeRecoveryFn(
                    engine.context,
                    allocator,
                    recovery.*,
                    true,
                ) catch try engine.reconcilePreparedErrorFn(
                    engine.context,
                    allocator,
                    recovery.prepared,
                )
            else
                try confirmationResult(
                    recovery.prepared,
                    recovery.action,
                    if (items) |value| value else &.{},
                );
            defer result.deinit();
            try cli.writeResult(
                allocator,
                result,
                output,
                streams.stdout,
                streams.stderr,
            );
            return result.exit_status;
        },
    }
}

fn writeReview(
    prepared: orchestrator.Preparation,
    action: ?[]const u8,
    writer: *std.Io.Writer,
) !void {
    try writer.writeAll(
        "debz apt: reviewed atomic plan (not apt-compatible)\n",
    );
    try writer.print("Operation: {s}\n", .{
        @tagName(prepared.request.operation),
    });
    if (action) |value| try writer.print("Recovery action: {s}\n", .{value});
    for (prepared.review) |item| {
        try writer.print("Planned package: {s}", .{item.package});
        if (item.version) |version| try writer.print(
            " version={s}",
            .{version},
        );
        if (item.architecture) |architecture| try writer.print(
            " architecture={s}",
            .{architecture},
        );
        if (item.detail) |detail| try writer.print(
            " detail={s}",
            .{detail},
        );
        try writer.writeByte('\n');
    }
    try writer.print("Profile: {s}\nProfile SHA-256: ", .{
        prepared.profile.path,
    });
    try writeHex(writer, &prepared.profile.sha256);
    try writer.writeAll("\nProfile reference evidence SHA-256: ");
    try writeHex(writer, &prepared.profile.reference_evidence_sha256);
    try writer.writeAll("\nRequest SHA-256: ");
    try writeHex(writer, &prepared.request_sha256);
    try writer.print("\nExact lock: {s}\nExact lock SHA-256: ", .{
        prepared.exact_lock.path,
    });
    try writeHex(writer, &prepared.exact_lock.digest_sha256);
    try writer.print("\nActive operation state: {s}\n", .{
        prepared.paths.active_state,
    });
    try writer.writeAll("No package mutation has occurred.\n");
}

fn writeHex(writer: *std.Io.Writer, digest: *const [32]u8) !void {
    const encoded = std.fmt.bytesToHex(digest.*, .lower);
    try writer.writeAll(&encoded);
}

fn confirmationResult(
    prepared: orchestrator.Preparation,
    action: ?[]const u8,
    items: []const api.Item,
) !api.Result {
    var result = try prepared.confirmationResult();
    result.items = items;
    if (action) |value| {
        result.summary = value;
        result.diagnostics[0].message = value;
    }
    return api.complete(result);
}

fn copyReviewItems(
    allocator: std.mem.Allocator,
    review: []const orchestrator.ReviewItem,
) ![]api.Item {
    const items = try allocator.alloc(api.Item, review.len);
    for (review, 0..) |item, index| {
        items[index] = .{
            .package = item.package,
            .version = item.version,
            .architecture = item.architecture,
            .detail = item.detail,
        };
    }
    return items;
}

fn internalFailure(request: api.Request) !api.Result {
    return api.failure(
        request,
        .internal,
        .internal_error,
        "cli",
        "internal apt/system orchestration failure",
    );
}

const TestContext = struct {
    allocator: std.mem.Allocator,
    prepare_count: usize = 0,
    execute_count: usize = 0,
    recovery_prepare_count: usize = 0,
    recovery_execute_count: usize = 0,
    mutation_count: usize = 0,
    last_package_count: usize = 0,
    fail_execute: bool = false,

    fn interface(self: *TestContext) Engine {
        return .{
            .context = self,
            .prepareFn = prepare,
            .executeFn = execute,
            .prepareRecoveryFn = prepareRecovery,
            .executeRecoveryFn = executeRecovery,
            .reconcilePreparedErrorFn = reconcilePreparedError,
        };
    }

    fn prepare(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !orchestrator.PrepareOutcome {
        const self: *TestContext = @ptrCast(@alignCast(context));
        self.prepare_count += 1;
        self.last_package_count = request.packages.len;
        if (!request.operation.mutatesRoot()) {
            const items: []const api.Item = if (request.operation ==
                .list_installed)
                &.{.{
                    .package = "installed",
                    .version = "1",
                    .architecture = "amd64",
                }}
            else
                &.{};
            return .{ .result = try api.complete(.{
                .operation = request.operation,
                .request_sha256 = try request.digest(),
                .profile = .{
                    .path = request.profile_path,
                    .sha256 = @splat(0x21),
                    .reference_evidence_sha256 = @splat(0x22),
                },
                .outcome = .success,
                .exit_status = .success,
                .summary = "read-only result",
                .items = items,
                .diagnostics = undefined,
            }) };
        }
        return .{ .ready = try testPreparation(allocator, request) };
    }

    fn execute(
        context: *anyopaque,
        _: std.mem.Allocator,
        prepared: orchestrator.Preparation,
        confirmed: bool,
    ) !api.Result {
        const self: *TestContext = @ptrCast(@alignCast(context));
        if (!confirmed) return error.UnconfirmedExecution;
        self.execute_count += 1;
        self.mutation_count += 1;
        if (self.fail_execute) return error.InjectedPostMutationFailure;
        return successfulTestResult(prepared);
    }

    fn successfulTestResult(
        prepared: orchestrator.Preparation,
    ) !api.Result {
        return api.complete(.{
            .operation = prepared.request.operation,
            .request_sha256 = prepared.request_sha256,
            .profile = prepared.profile,
            .outcome = .success,
            .exit_status = .success,
            .changed = true,
            .summary = "executed exact reviewed lock",
            .evidence = .{
                .exact_lock = prepared.exact_lock,
                .transaction_result = .{
                    .path = prepared.paths.transaction_result,
                    .schema = "io.github.cataggar.debz.transaction-result.v2",
                    .version = 2,
                    .digest_sha256 = @splat(0x24),
                },
                .root_operation_completion = .{
                    .document = .{
                        .path = prepared.paths.completion,
                        .schema = "io.github.cataggar.debz.execution-completion.v1",
                        .version = 1,
                        .digest_sha256 = @splat(0x25),
                    },
                    .completed_attempt_id = prepared.attempt_id,
                },
            },
            .diagnostics = undefined,
        });
    }

    fn prepareRecovery(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        profile_path: []const u8,
    ) !orchestrator.RecoveryPrepareOutcome {
        const self: *TestContext = @ptrCast(@alignCast(context));
        self.recovery_prepare_count += 1;
        const request: api.Request = .{
            .operation = .install,
            .profile_path = profile_path,
            .packages = &.{"alpha"},
        };
        return .{ .ready = .{
            .prepared = try testPreparation(allocator, request),
            .action = "debz recover --system-profile /profile.json",
        } };
    }

    fn executeRecovery(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        recovery: orchestrator.RecoveryPreparation,
        confirmed: bool,
    ) !api.Result {
        const self: *TestContext = @ptrCast(@alignCast(context));
        self.recovery_execute_count += 1;
        _ = allocator;
        if (!confirmed) return error.UnconfirmedExecution;
        if (self.fail_execute) return error.InjectedRecoveryDurabilityFailure;
        return successfulTestResult(recovery.prepared);
    }

    fn reconcilePreparedError(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        prepared: orchestrator.Preparation,
    ) !api.Result {
        var result = try api.failure(
            prepared.request,
            .recovery,
            .recovery_required,
            "recovery",
            "recovery required; mutation may have occurred; run debz recover --system-profile /profile.json",
        );
        result.changed = true;
        result.profile = prepared.profile;
        result.evidence = .{
            .exact_lock = prepared.exact_lock,
            .active_operation_state = prepared.paths.active_state,
        };
        result = try api.complete(result);
        return api.ownResult(allocator, result);
    }
};

fn testPreparation(
    allocator: std.mem.Allocator,
    request: api.Request,
) !orchestrator.Preparation {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const attempt: [32]u8 = @splat(0x31);
    const paths = try orchestrator.pathsFor(owned, "/state", attempt);
    return .{
        .request = .{
            .operation = request.operation,
            .profile_path = try owned.dupe(u8, request.profile_path),
            .packages = try owned.dupe([]const u8, request.packages),
            .assume_yes = request.assume_yes,
        },
        .request_sha256 = try request.digest(),
        .profile = .{
            .path = try owned.dupe(u8, request.profile_path),
            .sha256 = @splat(0x21),
            .reference_evidence_sha256 = @splat(0x22),
        },
        .profile_state_path = "/state",
        .attempt_id = attempt,
        .paths = paths,
        .exact_lock = .{
            .path = paths.exact_lock,
            .schema = "io.github.cataggar.debz.exact-closure-lock.v2",
            .version = 2,
            .digest_sha256 = @splat(0x23),
        },
        .review = &.{.{
            .package = "alpha",
            .version = "1",
            .architecture = "amd64",
            .detail = "install",
        }},
        .arena = arena,
        .backing_allocator = allocator,
    };
}

const TestTerminal = struct {
    answer: Confirmation,
    call_count: usize = 0,
    stdout: ?*std.Io.Writer.Allocating = null,

    fn interface(self: *TestTerminal) Terminal {
        return .{ .context = self, .confirmFn = confirm };
    }

    fn confirm(
        context: *anyopaque,
        _: *std.Io.Writer,
    ) !Confirmation {
        const self: *TestTerminal = @ptrCast(@alignCast(context));
        self.call_count += 1;
        if (self.stdout) |output| {
            if (std.mem.indexOf(
                u8,
                output.written(),
                "reviewed atomic plan",
            ) == null) return error.PlanNotRendered;
        }
        return self.answer;
    }
};

test "apt_system_command.test.JSON confirmation is one document and never mutates" {
    const parsed = switch (cli.parse(&.{
        "--profile",
        "/profile.json",
        "--json",
        "install",
        "alpha",
    })) {
        .command => |command| command,
        else => return error.UnexpectedParseResult,
    };
    var context: TestContext = .{ .allocator = std.testing.allocator };
    var terminal: TestTerminal = .{ .answer = .confirmed };
    var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout.deinit();
    var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr.deinit();
    const status = try runApt(
        std.testing.allocator,
        parsed,
        context.interface(),
        terminal.interface(),
        .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
    );
    try std.testing.expectEqual(api.ExitStatus.usage, status);
    try std.testing.expectEqual(@as(usize, 1), context.prepare_count);
    try std.testing.expectEqual(@as(usize, 0), context.execute_count);
    try std.testing.expectEqual(@as(usize, 0), terminal.call_count);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(
        u8,
        stdout.written(),
        "\n",
    ));
    try std.testing.expect(std.mem.indexOf(
        u8,
        stdout.written(),
        "\"id\":\"confirmation_required\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stdout.written(),
        "\"items\":[{\"package\":\"alpha\"",
    ) != null);
    try std.testing.expectEqual(@as(usize, 0), stderr.written().len);
}

test "apt_system_command.test.human plan precedes TTY confirmation and exact execution" {
    const parsed = switch (cli.parse(&.{
        "--profile",
        "/profile.json",
        "install",
        "alpha",
    })) {
        .command => |command| command,
        else => return error.UnexpectedParseResult,
    };
    var context: TestContext = .{ .allocator = std.testing.allocator };
    var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout.deinit();
    var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr.deinit();
    var terminal: TestTerminal = .{
        .answer = .confirmed,
        .stdout = &stdout,
    };
    const status = try runApt(
        std.testing.allocator,
        parsed,
        context.interface(),
        terminal.interface(),
        .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
    );
    try std.testing.expectEqual(api.ExitStatus.success, status);
    try std.testing.expectEqual(@as(usize, 1), terminal.call_count);
    try std.testing.expectEqual(@as(usize, 1), context.execute_count);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stdout.written(),
        "executed exact reviewed lock",
    ) != null);
    try std.testing.expectEqual(@as(usize, 0), stderr.written().len);
}

test "apt_system_command.test.non-TTY refuses mutation after rendering review" {
    const parsed = switch (cli.parse(&.{
        "--profile",
        "/profile.json",
        "remove",
        "alpha",
    })) {
        .command => |command| command,
        else => return error.UnexpectedParseResult,
    };
    var context: TestContext = .{ .allocator = std.testing.allocator };
    var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout.deinit();
    var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr.deinit();
    const status = try runApt(
        std.testing.allocator,
        parsed,
        context.interface(),
        Terminal.unavailable(),
        .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
    );
    try std.testing.expectEqual(api.ExitStatus.usage, status);
    try std.testing.expectEqual(@as(usize, 0), context.execute_count);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stdout.written(),
        "reviewed atomic plan",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stderr.written(),
        "confirmation_required",
    ) != null);
}

test "apt_system_command.test.assume-yes executes without terminal access" {
    const parsed = switch (cli.parse(&.{
        "--profile",
        "/profile.json",
        "--json",
        "install",
        "-y",
        "alpha",
        "beta",
    })) {
        .command => |command| command,
        else => return error.UnexpectedParseResult,
    };
    var context: TestContext = .{ .allocator = std.testing.allocator };
    var terminal: TestTerminal = .{ .answer = .declined };
    var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout.deinit();
    var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr.deinit();
    const status = try runApt(
        std.testing.allocator,
        parsed,
        context.interface(),
        terminal.interface(),
        .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
    );
    try std.testing.expectEqual(api.ExitStatus.success, status);
    try std.testing.expectEqual(@as(usize, 1), context.execute_count);
    try std.testing.expectEqual(@as(usize, 2), context.last_package_count);
    try std.testing.expectEqual(@as(usize, 0), terminal.call_count);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(
        u8,
        stdout.written(),
        "\n",
    ));
}

test "apt_system_command.test.update and list route read-only with list result v2" {
    for ([_][]const []const u8{
        &.{ "--profile", "/profile.json", "--json", "update" },
        &.{ "--profile", "/profile.json", "--json", "list", "--installed" },
    }) |arguments| {
        const parsed = switch (cli.parse(arguments)) {
            .command => |command| command,
            else => return error.UnexpectedParseResult,
        };
        var context: TestContext = .{ .allocator = std.testing.allocator };
        var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stdout.deinit();
        var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stderr.deinit();
        const status = try runApt(
            std.testing.allocator,
            parsed,
            context.interface(),
            Terminal.unavailable(),
            .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
        );
        try std.testing.expectEqual(api.ExitStatus.success, status);
        try std.testing.expectEqual(@as(usize, 1), context.prepare_count);
        try std.testing.expectEqual(@as(usize, 0), context.execute_count);
        if (parsed.request.operation == .list_installed) {
            try std.testing.expect(std.mem.indexOf(
                u8,
                stdout.written(),
                "apt-system-result-v2",
            ) != null);
            try std.testing.expect(std.mem.indexOf(
                u8,
                stdout.written(),
                "\"package\":\"installed\"",
            ) != null);
        }
    }
}

test "apt_system_command.test.recovery JSON prepares exact action without prompting" {
    var context: TestContext = .{ .allocator = std.testing.allocator };
    var terminal: TestTerminal = .{ .answer = .confirmed };
    var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout.deinit();
    var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr.deinit();
    const status = try runRecovery(
        std.testing.allocator,
        "/profile.json",
        .json,
        context.interface(),
        terminal.interface(),
        .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
    );
    try std.testing.expectEqual(api.ExitStatus.usage, status);
    try std.testing.expectEqual(@as(usize, 1), context.recovery_prepare_count);
    try std.testing.expectEqual(@as(usize, 0), context.recovery_execute_count);
    try std.testing.expectEqual(@as(usize, 0), terminal.call_count);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stdout.written(),
        "debz recover --system-profile /profile.json",
    ) != null);
}

test "apt_system_command.test.human recovery confirms exact retained action once" {
    var context: TestContext = .{ .allocator = std.testing.allocator };
    var terminal: TestTerminal = .{ .answer = .confirmed };
    var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout.deinit();
    terminal.stdout = &stdout;
    var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr.deinit();
    const status = try runRecovery(
        std.testing.allocator,
        "/profile.json",
        .human,
        context.interface(),
        terminal.interface(),
        .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
    );
    try std.testing.expectEqual(api.ExitStatus.success, status);
    try std.testing.expectEqual(@as(usize, 1), terminal.call_count);
    try std.testing.expectEqual(@as(usize, 1), context.recovery_execute_count);
    try std.testing.expectEqual(@as(usize, 0), context.execute_count);
    try std.testing.expectEqual(@as(usize, 0), context.mutation_count);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stdout.written(),
        "Recovery action: debz recover --system-profile /profile.json",
    ) != null);
}

test "apt_system_command.test.post-mutation execute errors render recovery evidence in human and JSON" {
    for ([_]cli.OutputFormat{ .human, .json }) |output| {
        const arguments: []const []const u8 = if (output == .json)
            &.{
                "--profile",
                "/profile.json",
                "--json",
                "install",
                "-y",
                "alpha",
            }
        else
            &.{
                "--profile",
                "/profile.json",
                "install",
                "-y",
                "alpha",
            };
        const parsed = switch (cli.parse(arguments)) {
            .command => |command| command,
            else => return error.UnexpectedParseResult,
        };
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .fail_execute = true,
        };
        var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stdout.deinit();
        var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stderr.deinit();
        const status = try runApt(
            std.testing.allocator,
            parsed,
            context.interface(),
            Terminal.unavailable(),
            .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
        );
        try std.testing.expectEqual(api.ExitStatus.recovery, status);
        const rendered = if (output == .json)
            stdout.written()
        else
            stderr.written();
        try std.testing.expect(std.mem.indexOf(
            u8,
            rendered,
            "recovery_required",
        ) != null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            rendered,
            if (output == .json)
                "\"active_operation_state\":\"/state/apt/"
            else
                "Active operation state: /state/apt/",
        ) != null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            rendered,
            if (output == .json)
                "\"exact_lock\":{\"path\":\"/state/apt/"
            else
                "Exact lock: /state/apt/",
        ) != null);
        if (output == .json) {
            try std.testing.expect(std.mem.indexOf(
                u8,
                rendered,
                "\"changed\":true",
            ) != null);
            try std.testing.expectEqual(@as(usize, 1), std.mem.count(
                u8,
                rendered,
                "\n",
            ));
        }

        context.fail_execute = false;
        var recovery_terminal: TestTerminal = .{ .answer = .confirmed };
        const recovery_status = try runRecovery(
            std.testing.allocator,
            "/profile.json",
            .human,
            context.interface(),
            recovery_terminal.interface(),
            .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
        );
        try std.testing.expectEqual(
            api.ExitStatus.success,
            recovery_status,
        );
        try std.testing.expectEqual(@as(usize, 1), context.mutation_count);
    }
}

test "apt_system_command.test.recovery execution errors retain recovery-required evidence" {
    var context: TestContext = .{
        .allocator = std.testing.allocator,
        .fail_execute = true,
    };
    var terminal: TestTerminal = .{ .answer = .confirmed };
    var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout.deinit();
    var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr.deinit();
    const status = try runRecovery(
        std.testing.allocator,
        "/profile.json",
        .human,
        context.interface(),
        terminal.interface(),
        .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
    );
    try std.testing.expectEqual(api.ExitStatus.recovery, status);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stderr.written(),
        "mutation may have occurred",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stderr.written(),
        "active-operation-v1.json",
    ) != null);
}

test "apt_system_command.test.required_privileged.production adapter binds concrete composition" {
    var backend: @import("production_backend.zig").Backend = .{
        .io = std.testing.io,
    };
    var composition: orchestrator.ProductionComposition = undefined;
    composition.init(std.testing.allocator, std.testing.io, &backend);
    const concrete = composition.orchestrator();
    const adapter = Engine.production(concrete);
    try std.testing.expectEqual(
        @intFromPtr(concrete),
        @intFromPtr(adapter.context),
    );
    try std.testing.expect(adapter.prepareFn == Engine.productionPrepare);
    try std.testing.expect(
        adapter.prepareRecoveryFn == Engine.productionPrepareRecovery,
    );
}

const std = @import("std");
const api = @import("apt_system_api.zig");
const cli = @import("apt_system_cli.zig");
const orchestrator = @import("apt_system_orchestrator.zig");

pub const EngineError = orchestrator.ExecutionError;
pub const OperationalFailure = orchestrator.OperationalFailure;
pub const ExecutionInvocation = orchestrator.ExecutionInvocation;

pub const Engine = struct {
    context: *anyopaque,
    prepareFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        api.Request,
    ) EngineError!orchestrator.PrepareOutcome,
    executeFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        orchestrator.Preparation,
        bool,
    ) EngineError!ExecutionInvocation,
    prepareRecoveryFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
    ) EngineError!orchestrator.RecoveryPrepareOutcome,
    executeRecoveryFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        orchestrator.RecoveryPreparation,
        bool,
    ) EngineError!ExecutionInvocation,
    reconcilePreparedErrorFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        orchestrator.Preparation,
    ) EngineError!api.Result,

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
    ) EngineError!orchestrator.PrepareOutcome {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.invokePrepare(allocator, request);
    }

    fn productionExecute(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        prepared: orchestrator.Preparation,
        confirmed: bool,
    ) EngineError!ExecutionInvocation {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.invokeExecute(
            allocator,
            prepared,
            confirmed,
        );
    }

    fn productionPrepareRecovery(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        profile_path: []const u8,
    ) EngineError!orchestrator.RecoveryPrepareOutcome {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.invokePrepareRecovery(
            allocator,
            profile_path,
        );
    }

    fn productionExecuteRecovery(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        prepared: orchestrator.RecoveryPreparation,
        confirmed: bool,
    ) EngineError!ExecutionInvocation {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.invokeExecuteRecovery(
            allocator,
            prepared,
            confirmed,
        );
    }

    fn productionReconcilePreparedError(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        prepared: orchestrator.Preparation,
    ) EngineError!api.Result {
        const engine: *orchestrator.Engine = @ptrCast(@alignCast(context));
        return engine.invokeReconcilePreparedError(
            allocator,
            prepared,
        );
    }
};

pub const Confirmation = enum {
    confirmed,
    declined,
    unavailable,
};

pub const ConfirmationPrompt = enum {
    apt_execution,
    recovery,
};

pub const Terminal = struct {
    context: *anyopaque,
    confirmFn: *const fn (
        *anyopaque,
        *std.Io.Writer,
        ConfirmationPrompt,
    ) anyerror!Confirmation,

    pub fn unavailable() Terminal {
        return .{
            .context = undefined,
            .confirmFn = alwaysUnavailable,
        };
    }

    fn alwaysUnavailable(
        _: *anyopaque,
        _: *std.Io.Writer,
        _: ConfirmationPrompt,
    ) !Confirmation {
        return .unavailable;
    }
};

pub const ProductionTerminal = struct {
    io: std.Io,
    const maximum_confirmation_bytes = 64;

    pub fn interface(self: *ProductionTerminal) Terminal {
        return .{
            .context = self,
            .confirmFn = confirm,
        };
    }

    fn confirm(
        context: *anyopaque,
        stderr: *std.Io.Writer,
        prompt: ConfirmationPrompt,
    ) !Confirmation {
        const self: *ProductionTerminal = @ptrCast(@alignCast(context));
        return confirmFiles(
            self.io,
            std.Io.File.stdin(),
            std.Io.File.stdout(),
            std.Io.File.stderr(),
            stderr,
            prompt,
        );
    }

    fn confirmFiles(
        io: std.Io,
        stdin_file: std.Io.File,
        stdout_file: std.Io.File,
        stderr_file: std.Io.File,
        stderr: *std.Io.Writer,
        prompt: ConfirmationPrompt,
    ) !Confirmation {
        if (!try stdin_file.isTty(io) or
            !try stdout_file.isTty(io) or
            !try stderr_file.isTty(io))
            return .unavailable;

        try stderr.writeAll(confirmationPromptText(prompt));
        try stderr.flush();
        var answer: [maximum_confirmation_bytes]u8 = undefined;
        var length: usize = 0;
        var saw_input = false;
        while (true) {
            var byte: [1]u8 = undefined;
            const read = stdin_file.readStreaming(
                io,
                &.{byte[0..]},
            ) catch return .unavailable;
            if (read == 0) {
                if (!saw_input) return .unavailable;
                break;
            }
            if (byte[0] == '\n' or byte[0] == '\r') break;
            saw_input = true;
            if ((byte[0] < 0x20 and byte[0] != '\t') or byte[0] == 0x7f) {
                try stderr.writeByte('\n');
                return .declined;
            }
            if (length == answer.len) {
                try stderr.writeByte('\n');
                return .declined;
            }
            answer[length] = byte[0];
            length += 1;
        }
        try stderr.writeByte('\n');
        const value = std.mem.trim(u8, answer[0..length], " \t");
        if (std.ascii.eqlIgnoreCase(value, "y") or
            std.ascii.eqlIgnoreCase(value, "yes"))
            return .confirmed;
        return .declined;
    }
};

pub fn confirmationPromptText(prompt: ConfirmationPrompt) []const u8 {
    return switch (prompt) {
        .apt_execution => "Proceed with this exact lock? [y/N] ",
        .recovery => "Proceed with this reviewed recovery action? [y/N] ",
    };
}

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
    var prepared_outcome = try engine.prepareFn(
        engine.context,
        allocator,
        command.request,
    );

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
                    .apt_execution,
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
            else result: {
                const invocation = try engine.executeFn(
                    engine.context,
                    allocator,
                    prepared.*,
                    true,
                );
                break :result switch (invocation) {
                    .result => |value| value,
                    .operational_failure => try engine.reconcilePreparedErrorFn(
                        engine.context,
                        allocator,
                        prepared.*,
                    ),
                };
            };
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
    var outcome = try engine.prepareRecoveryFn(
        engine.context,
        allocator,
        profile_path,
    );
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
                try writeRecoveryReview(recovery.*, streams.stdout);
                try streams.stdout.flush();
            }
            if (recovery.mutation_status == .unknown) {
                const cancellation = try engine.executeRecoveryFn(
                    engine.context,
                    allocator,
                    recovery.*,
                    false,
                );
                var cancellation_result = switch (cancellation) {
                    .result => |value| value,
                    .operational_failure => try engine.reconcilePreparedErrorFn(
                        engine.context,
                        allocator,
                        recovery.prepared,
                    ),
                };
                defer cancellation_result.deinit();
                if (cancellation_result.exit_status == .recovery) {
                    try cli.writeResult(
                        allocator,
                        cancellation_result,
                        output,
                        streams.stdout,
                        streams.stderr,
                    );
                    return cancellation_result.exit_status;
                }
                var result = try unknownRecoveryReviewResult(recovery.*);
                defer result.deinit();
                try cli.writeResult(
                    allocator,
                    result,
                    output,
                    streams.stdout,
                    streams.stderr,
                );
                return result.exit_status;
            }
            const confirmed = if (output == .json)
                false
            else
                (terminal.confirmFn(
                    terminal.context,
                    streams.stderr,
                    .recovery,
                ) catch .unavailable) == .confirmed;
            var result = result: {
                const invocation = try engine.executeRecoveryFn(
                    engine.context,
                    allocator,
                    recovery.*,
                    confirmed,
                );
                break :result switch (invocation) {
                    .result => |value| value,
                    .operational_failure => try engine.reconcilePreparedErrorFn(
                        engine.context,
                        allocator,
                        recovery.prepared,
                    ),
                };
            };
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
    _: ?[]const u8,
    writer: *std.Io.Writer,
) !void {
    try writer.writeAll(
        "debz apt: reviewed atomic plan (not apt-compatible)\n",
    );
    try writer.print("Operation: {s}\n", .{
        @tagName(prepared.request.operation),
    });
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

fn writeRecoveryReview(
    recovery: orchestrator.RecoveryPreparation,
    writer: *std.Io.Writer,
) !void {
    const prepared = recovery.prepared;
    try writer.writeAll("debz recover: reviewed retained recovery action\n");
    try writer.print("Original operation: {s}\nRecovery action: {s}\n", .{
        @tagName(prepared.request.operation),
        recovery.action,
    });
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
    switch (recovery.mutation_status) {
        .unchanged => try writer.writeAll(
            "Verified mutation status: no package mutation has occurred. " ++
                "Recovery will finalize the retained pre-mutation operation.\n",
        ),
        .changed => try writer.writeAll(
            "Verified mutation status: package mutation has occurred or may " ++
                "be incomplete. Recovery may make further package changes " ++
                "to converge the retained exact action.\n",
        ),
        .unknown => try writer.writeAll(
            "Verified mutation status: prior package mutation status is " ++
                "unknown. Recovery is blocked until durable evidence is " ++
                "restored or investigated.\n",
        ),
    }
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

fn recoveryConfirmationResult(
    recovery: orchestrator.RecoveryPreparation,
) !api.Result {
    var result = try recovery.prepared.confirmationResult();
    result.changed = recovery.mutation_status == .changed;
    result.summary = recovery.action;
    result.diagnostics[0].message = recovery.action;
    return api.complete(result);
}

fn unknownRecoveryReviewResult(
    recovery: orchestrator.RecoveryPreparation,
) !api.Result {
    const context: api.RecoveryContext = .{
        .profile_path = recovery.prepared.request.profile_path,
        .requested_operation = recovery.prepared.request.operation,
    };
    const summary =
        "prior package mutation status is unknown; recovery is blocked until durable evidence is restored or investigated";
    var result: api.Result = .{
        .operation = .recover,
        .request_sha256 = try api.recoveryRequestDigest(context),
        .outcome = .recovery,
        .exit_status = .recovery,
        .mutation_status = .unknown,
        .recovery_context = context,
        .summary = summary,
        .diagnostics = undefined,
    };
    result.diagnostics[0] = .{
        .id = .recovery_required,
        .outcome = .recovery,
        .phase = "recovery",
        .message = summary,
    };
    result.diagnostic_count = 1;
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

const TestContext = struct {
    allocator: std.mem.Allocator,
    prepare_count: usize = 0,
    execute_count: usize = 0,
    recovery_prepare_count: usize = 0,
    recovery_execute_count: usize = 0,
    mutation_count: usize = 0,
    last_package_count: usize = 0,
    fail_execute: bool = false,
    execute_engine_error: ?EngineError = null,
    operational_failure: ?OperationalFailure = null,
    return_recovery_result: bool = false,
    unknown_reconciliation: bool = false,
    recovery_prepare_unknown: bool = false,
    recovery_mutation_status: orchestrator.VerifiedMutationStatus = .unchanged,
    recovery_cancel_count: usize = 0,
    reconcile_count: usize = 0,

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
    ) EngineError!orchestrator.PrepareOutcome {
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
            return .{ .result = api.complete(.{
                .operation = request.operation,
                .request_sha256 = request.digest() catch |err|
                    return testEngineError(err),
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
            }) catch |err| return testEngineError(err) };
        }
        return .{ .ready = testPreparation(
            allocator,
            request,
        ) catch |err| return testEngineError(err) };
    }

    fn execute(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        prepared: orchestrator.Preparation,
        confirmed: bool,
    ) EngineError!ExecutionInvocation {
        const self: *TestContext = @ptrCast(@alignCast(context));
        if (!confirmed) return error.ContractViolation;
        self.execute_count += 1;
        if (self.execute_engine_error) |err| return err;
        self.mutation_count += 1;
        if (self.operational_failure) |failure|
            return .{ .operational_failure = failure };
        if (self.fail_execute)
            return .{ .operational_failure = .state_io_or_durability };
        if (self.return_recovery_result)
            return .{ .result = recoveryTestResult(
                allocator,
                prepared,
            ) catch |err| return testEngineError(err) };
        return .{ .result = successfulTestResult(
            prepared,
        ) catch |err| return testEngineError(err) };
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
    ) EngineError!orchestrator.RecoveryPrepareOutcome {
        const self: *TestContext = @ptrCast(@alignCast(context));
        self.recovery_prepare_count += 1;
        const request: api.Request = .{
            .operation = .install,
            .profile_path = profile_path,
            .packages = &.{"alpha"},
        };
        if (self.recovery_prepare_unknown)
            return .{ .result = unknownTestResult(
                allocator,
                profile_path,
                null,
            ) catch |err| return testEngineError(err) };
        return .{ .ready = .{
            .prepared = testPreparation(
                allocator,
                request,
            ) catch |err| return testEngineError(err),
            .action = "debz recover --system-profile /profile.json",
            .mutation_status = self.recovery_mutation_status,
        } };
    }

    fn executeRecovery(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        recovery: orchestrator.RecoveryPreparation,
        confirmed: bool,
    ) EngineError!ExecutionInvocation {
        const self: *TestContext = @ptrCast(@alignCast(context));
        if (!confirmed) {
            self.recovery_cancel_count += 1;
            return .{ .result = recoveryConfirmationResult(recovery) catch |err|
                return testEngineError(err) };
        }
        self.recovery_execute_count += 1;
        if (self.execute_engine_error) |err| return err;
        if (self.operational_failure) |failure|
            return .{ .operational_failure = failure };
        if (self.fail_execute)
            return .{ .operational_failure = .state_io_or_durability };
        if (self.return_recovery_result)
            return .{ .result = recoveryTestResult(
                allocator,
                recovery.prepared,
            ) catch |err| return testEngineError(err) };
        return .{ .result = successfulTestResult(
            recovery.prepared,
        ) catch |err| return testEngineError(err) };
    }

    fn reconcilePreparedError(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        prepared: orchestrator.Preparation,
    ) EngineError!api.Result {
        const self: *TestContext = @ptrCast(@alignCast(context));
        self.reconcile_count += 1;
        if (self.unknown_reconciliation)
            return unknownTestResult(
                allocator,
                prepared.request.profile_path,
                prepared.request.operation,
            ) catch |err| return testEngineError(err);
        return recoveryTestResult(
            allocator,
            prepared,
        ) catch |err| return testEngineError(err);
    }

    fn recoveryTestResult(
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

    fn unknownTestResult(
        allocator: std.mem.Allocator,
        profile_path: []const u8,
        requested_operation: ?api.Operation,
    ) !api.Result {
        const context: api.RecoveryContext = .{
            .profile_path = profile_path,
            .requested_operation = requested_operation,
        };
        var result: api.Result = .{
            .operation = .recover,
            .request_sha256 = try api.recoveryRequestDigest(context),
            .outcome = .recovery,
            .exit_status = .recovery,
            .summary = "mutation status unknown; inspect durable recovery state",
            .mutation_status = .unknown,
            .recovery_context = context,
            .diagnostics = undefined,
        };
        result.diagnostics[0] = .{
            .id = .recovery_required,
            .outcome = .recovery,
            .phase = "recovery",
            .message = result.summary,
        };
        result.diagnostic_count = 1;
        result = try api.complete(result);
        return api.ownResult(allocator, result);
    }
};

fn testEngineError(err: anyerror) EngineError {
    return if (err == error.OutOfMemory)
        error.OutOfMemory
    else
        error.InvariantViolation;
}

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
    last_prompt: ?ConfirmationPrompt = null,

    fn interface(self: *TestTerminal) Terminal {
        return .{ .context = self, .confirmFn = confirm };
    }

    fn confirm(
        context: *anyopaque,
        _: *std.Io.Writer,
        prompt: ConfirmationPrompt,
    ) !Confirmation {
        const self: *TestTerminal = @ptrCast(@alignCast(context));
        self.call_count += 1;
        self.last_prompt = prompt;
        if (self.stdout) |output| {
            if (std.mem.indexOf(
                u8,
                output.written(),
                switch (prompt) {
                    .apt_execution => "reviewed atomic plan",
                    .recovery => "reviewed retained recovery action",
                },
            ) == null) return error.PlanNotRendered;
        }
        return self.answer;
    }
};

extern fn posix_openpt(flags: c_int) c_int;
extern fn grantpt(fd: c_int) c_int;
extern fn unlockpt(fd: c_int) c_int;
extern fn ptsname_r(fd: c_int, buffer: [*]u8, length: usize) c_int;

const TestPty = struct {
    master: std.Io.File,
    slave: std.Io.File,

    fn open() !TestPty {
        const flags: c_int = @intCast(@as(u32, @bitCast(std.os.linux.O{
            .ACCMODE = .RDWR,
            .NOCTTY = true,
            .CLOEXEC = true,
        })));
        const master_fd = posix_openpt(flags);
        if (master_fd < 0) return error.PtyOpenFailed;
        errdefer _ = std.os.linux.close(master_fd);
        if (grantpt(master_fd) != 0 or unlockpt(master_fd) != 0)
            return error.PtySetupFailed;
        var path_buffer: [128]u8 = undefined;
        if (ptsname_r(
            master_fd,
            &path_buffer,
            path_buffer.len,
        ) != 0) return error.PtyNameFailed;
        const path = std.mem.sliceTo(&path_buffer, 0);
        const slave_fd = try std.posix.openat(
            std.os.linux.AT.FDCWD,
            path,
            .{
                .ACCMODE = .RDWR,
                .NOCTTY = true,
                .CLOEXEC = true,
            },
            0,
        );
        return .{
            .master = .{
                .handle = master_fd,
                .flags = .{ .nonblocking = false },
            },
            .slave = .{
                .handle = slave_fd,
                .flags = .{ .nonblocking = false },
            },
        };
    }

    fn close(self: *TestPty) void {
        self.master.close(std.testing.io);
        self.slave.close(std.testing.io);
        self.* = undefined;
    }
};

const TestPtyTerminal = struct {
    file: std.Io.File,

    fn interface(self: *TestPtyTerminal) Terminal {
        return .{
            .context = self,
            .confirmFn = confirm,
        };
    }

    fn confirm(
        context: *anyopaque,
        stderr: *std.Io.Writer,
        prompt: ConfirmationPrompt,
    ) !Confirmation {
        const self: *TestPtyTerminal = @ptrCast(@alignCast(context));
        return ProductionTerminal.confirmFiles(
            std.testing.io,
            self.file,
            self.file,
            self.file,
            stderr,
            prompt,
        );
    }
};

test "apt_system_command.test.production recovery prompt uses PTY yes no and EOF semantics" {
    inline for (.{
        .{ "yes\n", Confirmation.confirmed },
        .{ "y\r\n", Confirmation.confirmed },
        .{ "no\n", Confirmation.declined },
        .{ "yes     no\n", Confirmation.declined },
        .{ "yes\x00\n", Confirmation.declined },
    }) |case| {
        var pty = try TestPty.open();
        defer pty.close();
        try pty.master.writeStreamingAll(std.testing.io, case[0]);
        var prompt: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer prompt.deinit();
        const answer = try ProductionTerminal.confirmFiles(
            std.testing.io,
            pty.slave,
            pty.slave,
            pty.slave,
            &prompt.writer,
            .recovery,
        );
        try std.testing.expectEqual(case[1], answer);
        try std.testing.expectEqualStrings(
            "Proceed with this reviewed recovery action? [y/N] \n",
            prompt.written(),
        );
    }

    inline for (.{ ConfirmationPrompt.apt_execution, .recovery }) |kind| {
        var pty = try TestPty.open();
        defer pty.close();
        var overlong: [ProductionTerminal.maximum_confirmation_bytes + 2]u8 =
            undefined;
        @memset(&overlong, ' ');
        @memcpy(overlong[0..3], "yes");
        overlong[overlong.len - 1] = '\n';
        try pty.master.writeStreamingAll(std.testing.io, &overlong);
        const started = std.Io.Clock.awake.now(std.testing.io);
        var prompt: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer prompt.deinit();
        const answer = try ProductionTerminal.confirmFiles(
            std.testing.io,
            pty.slave,
            pty.slave,
            pty.slave,
            &prompt.writer,
            kind,
        );
        try std.testing.expectEqual(Confirmation.declined, answer);
        try std.testing.expect(
            started.durationTo(
                std.Io.Clock.awake.now(std.testing.io),
            ).toMilliseconds() < 1_000,
        );
    }

    {
        var pty = try TestPty.open();
        defer pty.close();
        var exact: [ProductionTerminal.maximum_confirmation_bytes + 1]u8 =
            undefined;
        @memset(exact[0..ProductionTerminal.maximum_confirmation_bytes], ' ');
        @memcpy(exact[0..3], "yes");
        exact[ProductionTerminal.maximum_confirmation_bytes] = '\n';
        try pty.master.writeStreamingAll(std.testing.io, &exact);
        var prompt: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer prompt.deinit();
        try std.testing.expectEqual(
            Confirmation.confirmed,
            try ProductionTerminal.confirmFiles(
                std.testing.io,
                pty.slave,
                pty.slave,
                pty.slave,
                &prompt.writer,
                .recovery,
            ),
        );
    }

    {
        var pty = try TestPty.open();
        try pty.master.writeStreamingAll(std.testing.io, "yes");
        const CloseContext = struct {
            file: std.Io.File,

            fn close(context: @This()) void {
                var delay: std.os.linux.timespec = .{
                    .sec = 0,
                    .nsec = 10_000_000,
                };
                var remaining: std.os.linux.timespec = undefined;
                _ = std.os.linux.nanosleep(&delay, &remaining);
                context.file.close(std.testing.io);
            }
        };
        const closer = try std.Thread.spawn(
            .{},
            CloseContext.close,
            .{CloseContext{ .file = pty.master }},
        );
        var prompt: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer prompt.deinit();
        const answer = try ProductionTerminal.confirmFiles(
            std.testing.io,
            pty.slave,
            pty.slave,
            pty.slave,
            &prompt.writer,
            .recovery,
        );
        closer.join();
        pty.slave.close(std.testing.io);
        try std.testing.expectEqual(Confirmation.unavailable, answer);
    }

    var pty = try TestPty.open();
    pty.master.close(std.testing.io);
    var prompt: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer prompt.deinit();
    const answer = try ProductionTerminal.confirmFiles(
        std.testing.io,
        pty.slave,
        pty.slave,
        pty.slave,
        &prompt.writer,
        .recovery,
    );
    pty.slave.close(std.testing.io);
    try std.testing.expectEqual(Confirmation.unavailable, answer);
    try std.testing.expectEqual(@as(usize, 0), prompt.written().len);
}

test "apt_system_command.test.PTY confirmation parses the complete recovery answer before execution" {
    inline for (.{
        "no\n",
        "yes     no\n",
        "yes\x00\n",
        "yes                                                                 \n",
    }) |input| {
        var pty = try TestPty.open();
        defer pty.close();
        try pty.master.writeStreamingAll(std.testing.io, input);
        var terminal: TestPtyTerminal = .{ .file = pty.slave };
        var context: TestContext = .{ .allocator = std.testing.allocator };
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
        try std.testing.expectEqual(api.ExitStatus.usage, status);
        try std.testing.expectEqual(@as(usize, 0), context.recovery_execute_count);
    }

    inline for (.{ "yes\n", "y\r\n" }) |input| {
        var pty = try TestPty.open();
        defer pty.close();
        try pty.master.writeStreamingAll(std.testing.io, input);
        var terminal: TestPtyTerminal = .{ .file = pty.slave };
        var context: TestContext = .{ .allocator = std.testing.allocator };
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
        try std.testing.expectEqual(api.ExitStatus.success, status);
        try std.testing.expectEqual(@as(usize, 1), context.recovery_execute_count);
        try std.testing.expectEqual(@as(usize, 0), context.recovery_cancel_count);
    }
}

test "apt_system_command.test.PTY confirmation rejects an install yes prefix with a non-yes suffix" {
    const parsed = switch (cli.parse(&.{
        "--profile",
        "/profile.json",
        "install",
        "alpha",
    })) {
        .command => |command| command,
        else => return error.UnexpectedParseResult,
    };
    var pty = try TestPty.open();
    defer pty.close();
    try pty.master.writeStreamingAll(std.testing.io, "yes     no\n");
    var terminal: TestPtyTerminal = .{ .file = pty.slave };
    var context: TestContext = .{ .allocator = std.testing.allocator };
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
    try std.testing.expectEqual(@as(usize, 0), context.execute_count);
}

test "apt_system_command.test.PTY incomplete line cannot confirm before a process deadline" {
    var pty = try TestPty.open();
    const fork_result = std.os.linux.fork();
    switch (std.os.linux.errno(fork_result)) {
        .SUCCESS => {},
        else => {
            pty.close();
            return error.ForkFailed;
        },
    }
    if (fork_result == 0) {
        pty.master.close(std.testing.io);
        var prompt_buffer: [256]u8 = undefined;
        var prompt = std.Io.Writer.fixed(&prompt_buffer);
        const answer = ProductionTerminal.confirmFiles(
            std.testing.io,
            pty.slave,
            pty.slave,
            pty.slave,
            &prompt,
            .recovery,
        ) catch .unavailable;
        pty.slave.close(std.testing.io);
        std.os.linux.exit_group(if (answer == .confirmed) 2 else 0);
    }
    pty.slave.close(std.testing.io);
    try pty.master.writeStreamingAll(
        std.testing.io,
        "yes                                                                 ",
    );
    var delay: std.os.linux.timespec = .{ .sec = 0, .nsec = 20_000_000 };
    var remaining: std.os.linux.timespec = undefined;
    _ = std.os.linux.nanosleep(&delay, &remaining);
    var status: u32 = 0;
    const early = std.os.linux.waitpid(
        @intCast(fork_result),
        &status,
        std.os.linux.W.NOHANG,
    );
    try std.testing.expectEqual(@as(usize, 0), early);
    pty.master.close(std.testing.io);
    while (true) {
        const waited = std.os.linux.waitpid(@intCast(fork_result), &status, 0);
        switch (std.os.linux.errno(waited)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    try std.testing.expect(std.os.linux.W.IFEXITED(status));
    try std.testing.expectEqual(
        @as(u8, 0),
        std.os.linux.W.EXITSTATUS(status),
    );
}

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
        "\"schema\":\"https://debz.dev/schema/apt-system-result-v3\"",
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
    try std.testing.expectEqual(
        ConfirmationPrompt.recovery,
        terminal.last_prompt.?,
    );
    try std.testing.expectEqual(@as(usize, 1), context.recovery_execute_count);
    try std.testing.expectEqual(@as(usize, 0), context.execute_count);
    try std.testing.expectEqual(@as(usize, 0), context.mutation_count);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stdout.written(),
        "Recovery action: debz recover --system-profile /profile.json",
    ) != null);
}

test "apt_system_command.test.recovery review truthfully renders mutation status and declines safely" {
    const cases = [_]struct {
        mutation_status: orchestrator.VerifiedMutationStatus,
        answer: Confirmation,
        expected_status: api.ExitStatus,
        expected_text: []const u8,
        prompts: usize,
        executions: usize,
        cancellations: usize,
    }{
        .{
            .mutation_status = .unchanged,
            .answer = .declined,
            .expected_status = .usage,
            .expected_text = "no package mutation has occurred",
            .prompts = 1,
            .executions = 0,
            .cancellations = 1,
        },
        .{
            .mutation_status = .unchanged,
            .answer = .unavailable,
            .expected_status = .usage,
            .expected_text = "no package mutation has occurred",
            .prompts = 1,
            .executions = 0,
            .cancellations = 1,
        },
        .{
            .mutation_status = .changed,
            .answer = .declined,
            .expected_status = .usage,
            .expected_text = "package mutation has occurred or may be incomplete",
            .prompts = 1,
            .executions = 0,
            .cancellations = 1,
        },
        .{
            .mutation_status = .changed,
            .answer = .unavailable,
            .expected_status = .usage,
            .expected_text = "package mutation has occurred or may be incomplete",
            .prompts = 1,
            .executions = 0,
            .cancellations = 1,
        },
        .{
            .mutation_status = .unknown,
            .answer = .confirmed,
            .expected_status = .recovery,
            .expected_text = "prior package mutation status is unknown",
            .prompts = 0,
            .executions = 0,
            .cancellations = 1,
        },
    };
    for (cases) |case| {
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .recovery_mutation_status = case.mutation_status,
        };
        var terminal: TestTerminal = .{ .answer = case.answer };
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
        try std.testing.expectEqual(case.expected_status, status);
        try std.testing.expectEqual(case.prompts, terminal.call_count);
        try std.testing.expectEqual(
            case.executions,
            context.recovery_execute_count,
        );
        try std.testing.expectEqual(
            case.cancellations,
            context.recovery_cancel_count,
        );
        try std.testing.expect(std.mem.indexOf(
            u8,
            stdout.written(),
            case.expected_text,
        ) != null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            stdout.written(),
            "reviewed atomic plan",
        ) == null);
        if (case.prompts != 0)
            try std.testing.expectEqual(
                ConfirmationPrompt.recovery,
                terminal.last_prompt.?,
            );
    }
}

test "apt_system_command.test.changed recovery confirmation may execute and JSON never prompts" {
    {
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .recovery_mutation_status = .changed,
        };
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
        try std.testing.expectEqual(@as(usize, 1), context.recovery_execute_count);
        try std.testing.expect(std.mem.indexOf(
            u8,
            stdout.written(),
            "Recovery may make further package changes",
        ) != null);
    }
    {
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .recovery_mutation_status = .changed,
        };
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
        try std.testing.expectEqual(@as(usize, 0), terminal.call_count);
        try std.testing.expectEqual(@as(usize, 0), context.recovery_execute_count);
        try std.testing.expectEqual(@as(usize, 1), context.recovery_cancel_count);
        try std.testing.expectEqual(@as(usize, 0), stderr.written().len);
        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, stdout.written(), "\n"),
        );
        try std.testing.expect(std.mem.indexOf(
            u8,
            stdout.written(),
            "\"changed\":true",
        ) != null);
    }
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

test "apt_system_command.test.post-mutation structured results keep recovery exit in human and JSON" {
    for ([_]cli.OutputFormat{ .human, .json }) |output| {
        const arguments: []const []const u8 = if (output == .json)
            &.{ "--profile", "/profile.json", "--json", "install", "-y", "alpha" }
        else
            &.{ "--profile", "/profile.json", "install", "-y", "alpha" };
        const parsed = switch (cli.parse(arguments)) {
            .command => |command| command,
            else => return error.UnexpectedParseResult,
        };
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .return_recovery_result = true,
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
            "debz recover --system-profile /profile.json",
        ) != null);
        if (output == .json) {
            try std.testing.expectEqual(
                @as(usize, 1),
                std.mem.count(u8, rendered, "\n"),
            );
            try std.testing.expectEqual(@as(usize, 0), stderr.written().len);
        }
        context.return_recovery_result = false;
        var terminal: TestTerminal = .{ .answer = .confirmed };
        const recovery_status = try runRecovery(
            std.testing.allocator,
            "/profile.json",
            .human,
            context.interface(),
            terminal.interface(),
            .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
        );
        try std.testing.expectEqual(api.ExitStatus.success, recovery_status);
        try std.testing.expectEqual(@as(usize, 1), context.mutation_count);
    }
}

test "apt_system_command.test.unknown mutation status is truthful and exposes no fabricated evidence" {
    for ([_]cli.OutputFormat{ .human, .json }) |output| {
        const arguments: []const []const u8 = if (output == .json)
            &.{ "--profile", "/profile.json", "--json", "install", "-y", "alpha" }
        else
            &.{ "--profile", "/profile.json", "install", "-y", "alpha" };
        const parsed = switch (cli.parse(arguments)) {
            .command => |command| command,
            else => return error.UnexpectedParseResult,
        };
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .fail_execute = true,
            .unknown_reconciliation = true,
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
        if (output == .json) {
            try std.testing.expect(std.mem.indexOf(
                u8,
                rendered,
                "\"schema\":\"https://debz.dev/schema/apt-system-result-v3\"",
            ) != null);
            try std.testing.expect(std.mem.indexOf(
                u8,
                rendered,
                "\"mutation_status\":\"unknown\"",
            ) != null);
            try std.testing.expect(std.mem.indexOf(
                u8,
                rendered,
                "\"profile\":null",
            ) != null);
            try std.testing.expect(std.mem.indexOf(
                u8,
                rendered,
                "\"active_operation_state\":null",
            ) != null);
        } else {
            try std.testing.expect(std.mem.indexOf(
                u8,
                rendered,
                "Changed: unknown (recovery required)",
            ) != null);
            try std.testing.expect(std.mem.indexOf(
                u8,
                rendered,
                "Profile: none",
            ) != null);
        }
    }
}

test "apt_system_command.test.engine OOM and contract errors bypass reconciliation" {
    const parsed = switch (cli.parse(
        &.{ "--profile", "/profile.json", "install", "-y", "alpha" },
    )) {
        .command => |command| command,
        else => return error.UnexpectedParseResult,
    };
    for ([_]EngineError{
        error.OutOfMemory,
        error.ContractViolation,
        error.InvariantViolation,
    }) |expected| {
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .execute_engine_error = expected,
        };
        var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stdout.deinit();
        var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stderr.deinit();
        try std.testing.expectError(expected, runApt(
            std.testing.allocator,
            parsed,
            context.interface(),
            Terminal.unavailable(),
            .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
        ));
        try std.testing.expectEqual(@as(usize, 0), context.reconcile_count);
        try std.testing.expectEqual(@as(usize, 0), context.mutation_count);
    }
}

test "apt_system_command.test.only tagged operational failures invoke reconciliation" {
    const parsed = switch (cli.parse(
        &.{ "--profile", "/profile.json", "install", "-y", "alpha" },
    )) {
        .command => |command| command,
        else => return error.UnexpectedParseResult,
    };
    for (std.enums.values(OperationalFailure)) |failure| {
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .operational_failure = failure,
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
        try std.testing.expectEqual(@as(usize, 1), context.reconcile_count);
        try std.testing.expectEqual(@as(usize, 1), context.mutation_count);
    }
}

test "apt_system_command.test.recovery engine errors bypass reconciliation" {
    for ([_]EngineError{
        error.OutOfMemory,
        error.ContractViolation,
        error.InvariantViolation,
    }) |expected| {
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .execute_engine_error = expected,
        };
        var terminal: TestTerminal = .{ .answer = .confirmed };
        var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stdout.deinit();
        var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stderr.deinit();
        try std.testing.expectError(expected, runRecovery(
            std.testing.allocator,
            "/profile.json",
            .human,
            context.interface(),
            terminal.interface(),
            .{ .stdout = &stdout.writer, .stderr = &stderr.writer },
        ));
        try std.testing.expectEqual(@as(usize, 0), context.reconcile_count);
    }
}

test "apt_system_command.test.recovery preparation unknown is a structured one-document result" {
    for ([_]cli.OutputFormat{ .human, .json }) |output| {
        var context: TestContext = .{
            .allocator = std.testing.allocator,
            .recovery_prepare_unknown = true,
        };
        var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stdout.deinit();
        var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stderr.deinit();
        const status = try runRecovery(
            std.testing.allocator,
            "/profile.json",
            output,
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
            "mutation status unknown",
        ) != null);
        if (output == .json)
            try std.testing.expectEqual(
                @as(usize, 1),
                std.mem.count(u8, rendered, "\n"),
            );
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

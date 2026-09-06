const std = @import("std");
const transaction_executor = @import("transaction_executor.zig");

pub const Kind = enum {
    legacy_dpkg,
    native,
};

pub const SelectionError = error{
    BackendUnavailable,
};

/// Backend-neutral transaction entry point. The legacy implementation retains
/// its current request and report types until native step provenance lands.
pub const Executor = struct {
    context: *anyopaque,
    executeFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        transaction_executor.Request,
        transaction_executor.Dependencies,
    ) anyerror!transaction_executor.Report,
    recoverFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        transaction_executor.RecoveryRequest,
        transaction_executor.Dependencies,
    ) anyerror!transaction_executor.RecoveryReport,

    pub const legacy_dpkg: Executor = .{
        .context = @ptrCast(@constCast(&legacy_context)),
        .executeFn = executeLegacy,
        .recoverFn = recoverLegacy,
    };
    pub const system = legacy_dpkg;

    pub fn execute(
        self: Executor,
        allocator: std.mem.Allocator,
        request: transaction_executor.Request,
        dependencies: transaction_executor.Dependencies,
    ) !transaction_executor.Report {
        return self.executeFn(self.context, allocator, request, dependencies);
    }

    pub fn recover(
        self: Executor,
        allocator: std.mem.Allocator,
        request: transaction_executor.RecoveryRequest,
        dependencies: transaction_executor.Dependencies,
    ) !transaction_executor.RecoveryReport {
        return self.recoverFn(self.context, allocator, request, dependencies);
    }
};

var legacy_context: u8 = 0;

fn executeLegacy(
    _: *anyopaque,
    allocator: std.mem.Allocator,
    request: transaction_executor.Request,
    dependencies: transaction_executor.Dependencies,
) !transaction_executor.Report {
    return transaction_executor.execute(allocator, request, dependencies);
}

fn recoverLegacy(
    _: *anyopaque,
    allocator: std.mem.Allocator,
    request: transaction_executor.RecoveryRequest,
    dependencies: transaction_executor.Dependencies,
) !transaction_executor.RecoveryReport {
    return transaction_executor.recover(allocator, request, dependencies);
}

/// Selection never falls back. A requested native backend must be present
/// before callers perform acquisition, journal, database, or root mutation.
pub fn select(
    kind: Kind,
    legacy_dpkg: Executor,
    native: ?Executor,
) SelectionError!Executor {
    return switch (kind) {
        .legacy_dpkg => legacy_dpkg,
        .native => native orelse error.BackendUnavailable,
    };
}

const SelectionHarness = struct {
    execute_calls: usize = 0,
    recover_calls: usize = 0,

    fn executor(self: *SelectionHarness) Executor {
        return .{
            .context = self,
            .executeFn = execute,
            .recoverFn = recover,
        };
    }

    fn execute(
        context: *anyopaque,
        _: std.mem.Allocator,
        _: transaction_executor.Request,
        _: transaction_executor.Dependencies,
    ) !transaction_executor.Report {
        const self: *SelectionHarness = @ptrCast(@alignCast(context));
        self.execute_calls += 1;
        return error.TestOnly;
    }

    fn recover(
        context: *anyopaque,
        _: std.mem.Allocator,
        _: transaction_executor.RecoveryRequest,
        _: transaction_executor.Dependencies,
    ) !transaction_executor.RecoveryReport {
        const self: *SelectionHarness = @ptrCast(@alignCast(context));
        self.recover_calls += 1;
        return error.TestOnly;
    }
};

test "transaction_engine.test.selection is explicit and never falls back" {
    var legacy: SelectionHarness = .{};
    var native: SelectionHarness = .{};

    const selected_legacy = try select(.legacy_dpkg, legacy.executor(), null);
    try std.testing.expectEqual(legacy.executor().context, selected_legacy.context);

    const selected_native = try select(.native, legacy.executor(), native.executor());
    try std.testing.expectEqual(native.executor().context, selected_native.context);

    try std.testing.expectError(
        error.BackendUnavailable,
        select(.native, legacy.executor(), null),
    );
    try std.testing.expectEqual(@as(usize, 0), legacy.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), native.execute_calls);
}

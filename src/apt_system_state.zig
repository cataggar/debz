//! Durable active-operation state for apt/system facade API v1.
const std = @import("std");
const api = @import("apt_system_api.zig");

pub const schema_id = "https://debz.dev/schema/apt-system-operation-state-v1";
pub const schema_version: u32 = 1;
pub const maximum_document_bytes: usize = api.maximum_document_bytes;
pub const document_name = "active-operation-v1.json";

pub const Phase = enum {
    reserved,
    profile_loaded,
    authenticated,
    planned,
    downloaded,
    mutating,
    verifying,
    recovery_required,
    recovering,
    completed,
};

pub const Outcome = enum {
    pending,
    succeeded,
    failed_before_mutation,
    failed_after_mutation,
    recovered,
};

pub const State = struct {
    attempt_id: [32]u8,
    generation: u64,
    operation: api.Operation,
    phase: Phase,
    mutation_started: bool,
    outcome: Outcome,
    request_sha256: [32]u8,
    profile: api.ProfileBinding,
    exact_lock: ?api.DocumentBinding = null,
    transaction_result: ?api.DocumentBinding = null,
    root_operation_completion: ?api.CompletionBinding = null,
    updated_unix: i64,
    diagnostic: []const u8 = "",
    digest_sha256: [32]u8 = @splat(0),

    pub fn canonicalJson(
        self: State,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try validate(self);
        if (!std.mem.eql(u8, &self.digest_sha256, &digestPayload(self)))
            return error.DigestMismatch;
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        writeDocument(self, &output.writer) catch return error.OutOfMemory;
        const bytes = try output.toOwnedSlice();
        if (bytes.len > maximum_document_bytes) {
            allocator.free(bytes);
            return error.DocumentTooLarge;
        }
        return bytes;
    }
};

pub const OwnedState = struct {
    state: State,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedState) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn create(
    allocator: std.mem.Allocator,
    input: State,
) !OwnedState {
    try validate(input);
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var state = input;
    state.profile = .{
        .path = try owned.dupe(u8, input.profile.path),
        .sha256 = input.profile.sha256,
        .reference_evidence_sha256 = input.profile.reference_evidence_sha256,
    };
    state.exact_lock = try ownOptionalDocument(owned, input.exact_lock);
    state.transaction_result = try ownOptionalDocument(
        owned,
        input.transaction_result,
    );
    if (input.root_operation_completion) |completion| {
        state.root_operation_completion = .{
            .document = try ownDocument(owned, completion.document),
            .completed_attempt_id = completion.completed_attempt_id,
        };
    }
    state.diagnostic = try owned.dupe(u8, input.diagnostic);
    state.digest_sha256 = digestPayload(state);
    return .{
        .state = state,
        .arena = arena,
        .backing_allocator = allocator,
    };
}

const WireProfile = struct {
    path: []const u8,
    sha256: []const u8,
    reference_evidence_sha256: []const u8,
};

const WireDocument = struct {
    path: []const u8,
    schema: []const u8,
    version: u32,
    digest_sha256: []const u8,
};

const WireCompletion = struct {
    document: WireDocument,
    completed_attempt_id: []const u8,
};

const WireState = struct {
    schema: []const u8,
    version: u32,
    attempt_id: []const u8,
    generation: u64,
    operation: api.Operation,
    phase: Phase,
    mutation_started: bool,
    outcome: Outcome,
    request_sha256: []const u8,
    profile: WireProfile,
    exact_lock: ?WireDocument,
    transaction_result: ?WireDocument,
    root_operation_completion: ?WireCompletion,
    updated_unix: i64,
    diagnostic: []const u8,
    digest_sha256: []const u8,
};

pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !OwnedState {
    if (maximum_bytes == 0 or maximum_bytes > maximum_document_bytes or
        source.len > maximum_bytes)
        return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(WireState, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidDocument,
    };
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, schema_id) or
        wire.version != schema_version)
        return error.UnsupportedSchema;

    var attempt_id: [32]u8 = undefined;
    var request_sha256: [32]u8 = undefined;
    var profile_sha256: [32]u8 = undefined;
    var reference_evidence_sha256: [32]u8 = undefined;
    var digest_sha256: [32]u8 = undefined;
    try parseHex(&attempt_id, wire.attempt_id);
    try parseHex(&request_sha256, wire.request_sha256);
    try parseHex(&profile_sha256, wire.profile.sha256);
    try parseHex(
        &reference_evidence_sha256,
        wire.profile.reference_evidence_sha256,
    );
    try parseHex(&digest_sha256, wire.digest_sha256);
    const exact_lock = if (wire.exact_lock) |value|
        try decodeDocument(value)
    else
        null;
    const transaction_result = if (wire.transaction_result) |value|
        try decodeDocument(value)
    else
        null;
    var completion: ?api.CompletionBinding = null;
    if (wire.root_operation_completion) |value| {
        var completed_attempt_id: [32]u8 = undefined;
        try parseHex(&completed_attempt_id, value.completed_attempt_id);
        completion = .{
            .document = try decodeDocument(value.document),
            .completed_attempt_id = completed_attempt_id,
        };
    }
    const decoded: State = .{
        .attempt_id = attempt_id,
        .generation = wire.generation,
        .operation = wire.operation,
        .phase = wire.phase,
        .mutation_started = wire.mutation_started,
        .outcome = wire.outcome,
        .request_sha256 = request_sha256,
        .profile = .{
            .path = wire.profile.path,
            .sha256 = profile_sha256,
            .reference_evidence_sha256 = reference_evidence_sha256,
        },
        .exact_lock = exact_lock,
        .transaction_result = transaction_result,
        .root_operation_completion = completion,
        .updated_unix = wire.updated_unix,
        .diagnostic = wire.diagnostic,
        .digest_sha256 = digest_sha256,
    };
    try validate(decoded);
    if (!std.mem.eql(u8, &decoded.digest_sha256, &digestPayload(decoded)))
        return error.DigestMismatch;
    var owned = try create(allocator, decoded);
    errdefer owned.deinit();
    const canonical = try owned.state.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return owned;
}

pub const Store = struct {
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    locks: LockBackend,
    write_hooks: WriteHooks = .{},

    pub fn init(
        io: std.Io,
        dir: std.Io.Dir,
        name: []const u8,
        locks: LockBackend,
    ) !Store {
        if (!safeLeaf(name)) return error.InvalidPath;
        return .{ .io = io, .dir = dir, .name = name, .locks = locks };
    }

    pub fn read(
        self: Store,
        allocator: std.mem.Allocator,
        maximum_bytes: usize,
    ) !OwnedState {
        var file = try openRegularNoFollow(self.dir, self.io, self.name);
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const source = try reader.interface.allocRemaining(
            allocator,
            .limited(maximum_bytes),
        );
        defer allocator.free(source);
        return decode(allocator, source, maximum_bytes);
    }

    pub fn initialize(
        self: Store,
        allocator: std.mem.Allocator,
        state: State,
        maximum_bytes: usize,
        wait_ms: u64,
    ) !void {
        if (state.generation != 1 or state.phase != .reserved or
            state.outcome != .pending or state.mutation_started)
            return error.InvalidInitialState;
        const token = try self.locks.acquire(wait_ms);
        defer self.locks.release(token);
        if (!self.locks.held(token)) return error.LockLost;
        if (self.read(allocator, maximum_bytes)) |existing| {
            var value = existing;
            value.deinit();
            return error.StateAlreadyExists;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
        try self.writeAtomicLocked(allocator, state, maximum_bytes, token);
    }

    pub fn compareAndSet(
        self: Store,
        allocator: std.mem.Allocator,
        expected: Expected,
        next: State,
        maximum_bytes: usize,
        wait_ms: u64,
    ) !void {
        const token = try self.locks.acquire(wait_ms);
        defer self.locks.release(token);
        if (!self.locks.held(token)) return error.LockLost;
        var current = try self.read(allocator, maximum_bytes);
        defer current.deinit();
        if (!expected.matches(current.state)) return error.StaleState;
        try validateTransition(current.state, next);
        try self.writeAtomicLocked(allocator, next, maximum_bytes, token);
    }

    pub fn ensureDurable(
        self: Store,
        allocator: std.mem.Allocator,
        expected: Expected,
        maximum_bytes: usize,
        wait_ms: u64,
    ) !void {
        const token = try self.locks.acquire(wait_ms);
        defer self.locks.release(token);
        if (!self.locks.held(token)) return error.LockLost;
        var current = try self.read(allocator, maximum_bytes);
        defer current.deinit();
        if (!expected.matches(current.state)) return error.StaleState;
        var file = try openRegularNoFollow(self.dir, self.io, self.name);
        defer file.close(self.io);
        try file.sync(self.io);
        try self.write_hooks.run(.before_durability_resync);
        try syncDirectory(self.io, self.dir);
    }

    fn writeAtomicLocked(
        self: Store,
        allocator: std.mem.Allocator,
        state: State,
        maximum_bytes: usize,
        token: LockToken,
    ) !void {
        if (!self.locks.held(token)) return error.LockLost;
        if (maximum_bytes == 0 or maximum_bytes > maximum_document_bytes)
            return error.DocumentTooLarge;
        const bytes = try state.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_bytes) return error.DocumentTooLarge;
        var nonce: [8]u8 = undefined;
        try std.Io.randomSecure(self.io, &nonce);
        const value = std.mem.readInt(u64, &nonce, .little);
        var stage_buffer: [64]u8 = undefined;
        const stage = try std.fmt.bufPrint(
            &stage_buffer,
            ".apt-system-state-{x:0>16}.tmp",
            .{value},
        );
        try self.write_hooks.run(.before_stage);
        var renamed = false;
        defer if (!renamed)
            self.dir.deleteFile(self.io, stage) catch {};
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
        if (!self.locks.held(token)) return error.LockLost;
        try self.dir.rename(stage, self.dir, self.name, self.io);
        renamed = true;
        try self.write_hooks.run(.after_rename);
        try syncDirectory(self.io, self.dir);
    }
};

fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    if (@import("builtin").os.tag != .linux) return;
    const fd = try std.posix.openat(dir.handle, ".", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    var sync_file: std.Io.File = .{
        .handle = fd,
        .flags = .{ .nonblocking = false },
    };
    defer sync_file.close(io);
    switch (std.os.linux.errno(std.os.linux.fsync(fd))) {
        .SUCCESS => {},
        .BADF => return error.InvalidDirectoryHandle,
        .INVAL, .ROFS => return error.OperationUnsupported,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .DQUOT => return error.DiskQuota,
        else => return error.Unexpected,
    }
}

pub const Expected = struct {
    attempt_id: [32]u8,
    generation: u64,
    digest_sha256: [32]u8,

    pub fn fromState(state: State) Expected {
        return .{
            .attempt_id = state.attempt_id,
            .generation = state.generation,
            .digest_sha256 = state.digest_sha256,
        };
    }

    fn matches(self: Expected, state: State) bool {
        return self.generation == state.generation and
            std.mem.eql(u8, &self.attempt_id, &state.attempt_id) and
            std.mem.eql(u8, &self.digest_sha256, &state.digest_sha256);
    }
};

pub const LockToken = *anyopaque;

pub const LockBackend = struct {
    context: *anyopaque,
    acquireFn: *const fn (*anyopaque, u64) anyerror!LockToken,
    heldFn: *const fn (*anyopaque, LockToken) bool,
    releaseFn: *const fn (*anyopaque, LockToken) void,

    pub fn acquire(self: LockBackend, wait_ms: u64) !LockToken {
        return self.acquireFn(self.context, wait_ms);
    }

    pub fn held(self: LockBackend, token: LockToken) bool {
        return self.heldFn(self.context, token);
    }

    pub fn release(self: LockBackend, token: LockToken) void {
        self.releaseFn(self.context, token);
    }
};

pub const SystemLockBackend = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8 = "active-operation-v1.lock",
    retry_ms: u64 = 10,

    const Token = struct {
        file: std.Io.File,
        held: bool,
    };

    pub fn interface(self: *SystemLockBackend) LockBackend {
        return .{
            .context = self,
            .acquireFn = acquire,
            .heldFn = held,
            .releaseFn = release,
        };
    }

    fn acquire(context: *anyopaque, wait_ms: u64) !LockToken {
        const self: *SystemLockBackend = @ptrCast(@alignCast(context));
        if (@import("builtin").os.tag != .linux) return error.LockUnavailable;
        const started = std.Io.Clock.awake.now(self.io);
        while (true) {
            const file = try self.openLockFile();
            var record: std.os.linux.Flock = .{
                .type = std.os.linux.F.WRLCK,
                .whence = 0,
                .start = 0,
                .len = 0,
                .pid = 0,
                ._unused = {},
            };
            const code = std.os.linux.errno(std.os.linux.fcntl(
                file.handle,
                std.os.linux.F.OFD_SETLK,
                @intFromPtr(&record),
            ));
            if (code == .SUCCESS) {
                const token = self.allocator.create(Token) catch |err| {
                    file.close(self.io);
                    return err;
                };
                token.* = .{ .file = file, .held = true };
                return @ptrCast(token);
            }
            file.close(self.io);
            if (code != .ACCES and code != .AGAIN) return error.LockFailed;
            const elapsed = started.durationTo(
                std.Io.Clock.awake.now(self.io),
            ).toMilliseconds();
            if (elapsed < 0) return error.LockFailed;
            const waited: u64 = @intCast(elapsed);
            if (waited >= wait_ms) return error.LockTimeout;
            try std.Io.sleep(
                self.io,
                .fromMilliseconds(@intCast(@min(self.retry_ms, wait_ms - waited))),
                .awake,
            );
        }
    }

    fn openLockFile(self: *SystemLockBackend) !std.Io.File {
        if (!safeLeaf(self.name)) return error.InvalidPath;
        var attempt: usize = 0;
        while (attempt < 2) : (attempt += 1) {
            const fd = std.posix.openat(self.dir.handle, self.name, .{
                .ACCMODE = .RDWR,
                .NONBLOCK = true,
                .NOFOLLOW = true,
                .CLOEXEC = true,
            }, 0) catch |err| switch (err) {
                error.FileNotFound => {
                    var created = self.dir.createFile(self.io, self.name, .{
                        .read = true,
                        .truncate = false,
                        .exclusive = true,
                        .permissions = .fromMode(0o600),
                        .resolve_beneath = true,
                    }) catch |create_err| switch (create_err) {
                        error.PathAlreadyExists => continue,
                        else => return create_err,
                    };
                    created.close(self.io);
                    continue;
                },
                else => return err,
            };
            const file: std.Io.File = .{
                .handle = fd,
                .flags = .{ .nonblocking = true },
            };
            errdefer file.close(self.io);
            const stat = try file.stat(self.io);
            if (stat.kind != .file) return error.LockUnavailable;
            return file;
        }
        return error.LockUnavailable;
    }

    fn held(_: *anyopaque, token: LockToken) bool {
        const value: *Token = @ptrCast(@alignCast(token));
        return value.held;
    }

    fn release(context: *anyopaque, token: LockToken) void {
        const self: *SystemLockBackend = @ptrCast(@alignCast(context));
        const value: *Token = @ptrCast(@alignCast(token));
        if (value.held) {
            value.file.close(self.io);
            value.held = false;
        }
        self.allocator.destroy(value);
    }
};

pub const WriteBoundary = enum {
    before_stage,
    after_rename,
    before_durability_resync,
};

pub const WriteHooks = struct {
    context: ?*anyopaque = null,
    runFn: ?*const fn (?*anyopaque, WriteBoundary) anyerror!void = null,

    fn run(self: WriteHooks, boundary: WriteBoundary) !void {
        if (self.runFn) |runFn| try runFn(self.context, boundary);
    }
};

pub fn validate(state: State) !void {
    if (state.generation == 0) return error.InvalidGeneration;
    api.validateProfileBinding(state.profile) catch return error.InvalidProfile;
    api.validateEvidence(.{
        .exact_lock = state.exact_lock,
        .transaction_result = state.transaction_result,
        .root_operation_completion = state.root_operation_completion,
    }) catch return error.InvalidEvidence;
    if (state.root_operation_completion) |completion|
        if (!std.mem.eql(
            u8,
            &completion.completed_attempt_id,
            &state.attempt_id,
        ))
            return error.InvalidCompletionEvidence;
    if (!validDiagnostic(state.diagnostic))
        return error.InvalidDiagnostic;
    if ((state.outcome == .pending) != (state.phase != .completed))
        return error.InvalidOutcome;

    const expected_mutation_started = switch (state.phase) {
        .reserved,
        .profile_loaded,
        .authenticated,
        .planned,
        .downloaded,
        => false,
        .mutating,
        .verifying,
        .recovery_required,
        .recovering,
        => true,
        .completed => if (state.operation.mutatesRoot())
            switch (state.outcome) {
                .pending => return error.InvalidOutcome,
                .failed_before_mutation => false,
                .succeeded, .failed_after_mutation, .recovered => true,
            }
        else switch (state.outcome) {
            .succeeded, .failed_before_mutation => false,
            .pending, .failed_after_mutation, .recovered => return error.InvalidOutcome,
        },
    };
    if (state.mutation_started != expected_mutation_started)
        return error.InvalidMutationState;
    if (!state.operation.mutatesRoot() and state.mutation_started)
        return error.InvalidMutationState;

    if (state.operation.mutatesRoot()) {
        switch (state.phase) {
            .reserved, .profile_loaded, .authenticated => {
                if (state.exact_lock != null) return error.UnexpectedExactLock;
            },
            .planned,
            .downloaded,
            .mutating,
            .verifying,
            .recovery_required,
            .recovering,
            => if (state.exact_lock == null) return error.MissingExactLock,
            .completed => switch (state.outcome) {
                .failed_before_mutation => {
                    if (state.transaction_result != null or
                        state.root_operation_completion != null)
                        return error.UnexpectedTransactionEvidence;
                },
                .succeeded, .recovered, .failed_after_mutation => {
                    if (state.exact_lock == null) return error.MissingExactLock;
                },
                .pending => unreachable,
            },
        }

        switch (state.phase) {
            .reserved,
            .profile_loaded,
            .authenticated,
            .planned,
            .downloaded,
            .mutating,
            => if (state.transaction_result != null)
                return error.UnexpectedTransactionResult,
            .verifying => if (state.transaction_result == null)
                return error.MissingTransactionResult,
            .recovery_required, .recovering => {},
            .completed => if (state.mutation_started and
                state.transaction_result == null)
                return error.MissingTransactionResult,
        }
        if (state.phase == .completed and
            (state.outcome == .succeeded or state.outcome == .recovered))
        {
            if (state.root_operation_completion == null)
                return error.MissingCompletionEvidence;
        } else if (state.root_operation_completion != null) {
            return error.UnexpectedCompletionEvidence;
        }
    } else {
        if (state.exact_lock != null or
            state.transaction_result != null or
            state.root_operation_completion != null)
            return error.UnexpectedTransactionEvidence;
        if (state.outcome == .failed_after_mutation or state.outcome == .recovered)
            return error.InvalidOutcome;
    }

    if (state.outcome == .pending and state.diagnostic.len != 0 and
        state.phase != .recovery_required and state.phase != .recovering)
        return error.InvalidDiagnostic;
    if (state.phase == .recovery_required and state.diagnostic.len == 0)
        return error.InvalidDiagnostic;
    if (state.outcome == .succeeded and state.diagnostic.len != 0)
        return error.InvalidDiagnostic;
    if (state.outcome != .pending and state.outcome != .succeeded and
        state.diagnostic.len == 0)
        return error.InvalidDiagnostic;
}

pub fn validateTransition(current: State, next: State) !void {
    try validate(current);
    try validate(next);
    if (current.phase == .completed) return error.InvalidTransition;
    if (!std.mem.eql(u8, &current.attempt_id, &next.attempt_id) or
        current.operation != next.operation or
        !std.mem.eql(u8, &current.request_sha256, &next.request_sha256) or
        !profileEqual(current.profile, next.profile))
        return error.AttemptMismatch;
    if (next.generation != std.math.add(u64, current.generation, 1) catch
        return error.InvalidGeneration)
        return error.InvalidGeneration;
    if (next.updated_unix < current.updated_unix) return error.InvalidTimestamp;
    if (!canTransition(current.phase, next.phase)) return error.InvalidTransition;
    if (current.mutation_started and !next.mutation_started)
        return error.MutationEvidenceRollback;
    if (!stickyDocument(current.exact_lock, next.exact_lock) or
        !stickyDocument(current.transaction_result, next.transaction_result) or
        !stickyCompletion(
            current.root_operation_completion,
            next.root_operation_completion,
        ))
        return error.EvidenceRollback;
}

fn canTransition(current: Phase, next: Phase) bool {
    if (current == next) return current != .completed;
    return switch (current) {
        .reserved => next == .profile_loaded or next == .completed,
        .profile_loaded => next == .authenticated or next == .completed,
        .authenticated => next == .planned or next == .downloaded or
            next == .completed,
        .planned => next == .downloaded or next == .completed,
        .downloaded => next == .mutating or next == .completed,
        .mutating => next == .verifying or next == .recovery_required,
        .verifying => next == .completed or next == .recovery_required,
        .recovery_required => next == .recovering or next == .verifying,
        .recovering => next == .verifying or next == .recovery_required or
            next == .completed,
        .completed => false,
    };
}

fn profileEqual(left: api.ProfileBinding, right: api.ProfileBinding) bool {
    return std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, &left.sha256, &right.sha256) and
        std.mem.eql(
            u8,
            &left.reference_evidence_sha256,
            &right.reference_evidence_sha256,
        );
}

fn stickyDocument(
    current: ?api.DocumentBinding,
    next: ?api.DocumentBinding,
) bool {
    const existing = current orelse return true;
    const candidate = next orelse return false;
    return documentEqual(existing, candidate);
}

fn documentEqual(
    left: api.DocumentBinding,
    right: api.DocumentBinding,
) bool {
    return std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.schema, right.schema) and
        left.version == right.version and
        std.mem.eql(u8, &left.digest_sha256, &right.digest_sha256);
}

fn stickyCompletion(
    current: ?api.CompletionBinding,
    next: ?api.CompletionBinding,
) bool {
    const existing = current orelse return true;
    const candidate = next orelse return false;
    return documentEqual(existing.document, candidate.document) and
        std.mem.eql(
            u8,
            &existing.completed_attempt_id,
            &candidate.completed_attempt_id,
        );
}

fn validDiagnostic(value: []const u8) bool {
    const maximum = api.maximum_summary_characters;
    const maximum_bytes = std.math.mul(usize, maximum, 4) catch return false;
    if (value.len > maximum_bytes) return false;
    var index: usize = 0;
    var characters: usize = 0;
    while (index < value.len) {
        const sequence_length: usize = std.unicode.utf8ByteSequenceLength(
            value[index],
        ) catch return false;
        if (sequence_length > value.len - index) return false;
        const codepoint = std.unicode.utf8Decode(
            value[index..][0..sequence_length],
        ) catch return false;
        characters += 1;
        if (characters > maximum) return false;
        if (codepoint < 0x20 or codepoint == 0x7f) return false;
        index += sequence_length;
    }
    return true;
}

fn digestPayload(state: State) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(state, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeDocument(state: State, writer: *std.Io.Writer) !void {
    try writePayload(state, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHex(writer, &state.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(state: State, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, schema_id);
    try writer.print(",\"version\":{},\"attempt_id\":", .{schema_version});
    try writeHex(writer, &state.attempt_id);
    try writer.print(",\"generation\":{},\"operation\":", .{state.generation});
    try writeString(writer, @tagName(state.operation));
    try writer.writeAll(",\"phase\":");
    try writeString(writer, @tagName(state.phase));
    try writer.print(",\"mutation_started\":{},\"outcome\":", .{
        state.mutation_started,
    });
    try writeString(writer, @tagName(state.outcome));
    try writer.writeAll(",\"request_sha256\":");
    try writeHex(writer, &state.request_sha256);
    try writer.writeAll(",\"profile\":{\"path\":");
    try writeString(writer, state.profile.path);
    try writer.writeAll(",\"sha256\":");
    try writeHex(writer, &state.profile.sha256);
    try writer.writeAll(",\"reference_evidence_sha256\":");
    try writeHex(writer, &state.profile.reference_evidence_sha256);
    try writer.writeAll("},\"exact_lock\":");
    try writeOptionalDocument(writer, state.exact_lock);
    try writer.writeAll(",\"transaction_result\":");
    try writeOptionalDocument(writer, state.transaction_result);
    try writer.writeAll(",\"root_operation_completion\":");
    if (state.root_operation_completion) |completion| {
        try writer.writeAll("{\"document\":");
        try writeDocumentBinding(writer, completion.document);
        try writer.writeAll(",\"completed_attempt_id\":");
        try writeHex(writer, &completion.completed_attempt_id);
        try writer.writeByte('}');
    } else try writer.writeAll("null");
    try writer.print(",\"updated_unix\":{},\"diagnostic\":", .{state.updated_unix});
    try writeString(writer, state.diagnostic);
    try writer.writeByte('}');
}

fn writeOptionalDocument(
    writer: *std.Io.Writer,
    binding: ?api.DocumentBinding,
) !void {
    if (binding) |value|
        try writeDocumentBinding(writer, value)
    else
        try writer.writeAll("null");
}

fn writeDocumentBinding(
    writer: *std.Io.Writer,
    binding: api.DocumentBinding,
) !void {
    try writer.writeAll("{\"path\":");
    try writeString(writer, binding.path);
    try writer.writeAll(",\"schema\":");
    try writeString(writer, binding.schema);
    try writer.print(",\"version\":{},\"digest_sha256\":", .{binding.version});
    try writeHex(writer, &binding.digest_sha256);
    try writer.writeByte('}');
}

fn writeString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...8, 11, 12, 14...31 => try writer.print("\\u00{x:0>2}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

fn parseHex(output: []u8, value: []const u8) !void {
    if (value.len != output.len * 2) return error.InvalidDigest;
    for (output, 0..) |*byte, index| {
        byte.* = (@as(u8, try nibble(value[index * 2])) << 4) |
            try nibble(value[index * 2 + 1]);
    }
}

fn nibble(value: u8) !u4 {
    return switch (value) {
        '0'...'9' => @intCast(value - '0'),
        'a'...'f' => @intCast(value - 'a' + 10),
        else => error.InvalidDigest,
    };
}

fn decodeDocument(wire: WireDocument) !api.DocumentBinding {
    var digest: [32]u8 = undefined;
    try parseHex(&digest, wire.digest_sha256);
    return .{
        .path = wire.path,
        .schema = wire.schema,
        .version = wire.version,
        .digest_sha256 = digest,
    };
}

fn ownOptionalDocument(
    allocator: std.mem.Allocator,
    binding: ?api.DocumentBinding,
) !?api.DocumentBinding {
    return if (binding) |value| try ownDocument(allocator, value) else null;
}

fn ownDocument(
    allocator: std.mem.Allocator,
    binding: api.DocumentBinding,
) !api.DocumentBinding {
    return .{
        .path = try allocator.dupe(u8, binding.path),
        .schema = try allocator.dupe(u8, binding.schema),
        .version = binding.version,
        .digest_sha256 = binding.digest_sha256,
    };
}

fn safeLeaf(name: []const u8) bool {
    return name.len != 0 and
        !std.mem.eql(u8, name, ".") and
        !std.mem.eql(u8, name, "..") and
        std.mem.indexOfScalar(u8, name, '/') == null and
        std.mem.indexOfScalar(u8, name, '\\') == null and
        std.mem.indexOfScalar(u8, name, 0) == null;
}

fn openRegularNoFollow(
    dir: std.Io.Dir,
    io: std.Io,
    name: []const u8,
) !std.Io.File {
    if (!safeLeaf(name)) return error.InvalidPath;
    const file: std.Io.File = switch (@import("builtin").os.tag) {
        .linux => blk: {
            const fd = try std.posix.openat(dir.handle, name, .{
                .NONBLOCK = true,
                .NOFOLLOW = true,
                .CLOEXEC = true,
            }, 0);
            break :blk .{
                .handle = fd,
                .flags = .{ .nonblocking = true },
            };
        },
        else => try dir.openFile(io, name, .{
            .mode = .read_only,
            .allow_directory = true,
            .follow_symlinks = false,
            .resolve_beneath = true,
        }),
    };
    errdefer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.NotRegularFile;
    return file;
}

const TestLockBackend = struct {
    held_value: bool = false,

    fn interface(self: *TestLockBackend) LockBackend {
        return .{
            .context = self,
            .acquireFn = acquire,
            .heldFn = held,
            .releaseFn = release,
        };
    }

    fn acquire(context: *anyopaque, _: u64) !LockToken {
        const self: *TestLockBackend = @ptrCast(@alignCast(context));
        if (self.held_value) return error.LockTimeout;
        self.held_value = true;
        return @ptrCast(self);
    }

    fn held(context: *anyopaque, token: LockToken) bool {
        const self: *TestLockBackend = @ptrCast(@alignCast(context));
        return self.held_value and token == @as(LockToken, @ptrCast(self));
    }

    fn release(context: *anyopaque, token: LockToken) void {
        const self: *TestLockBackend = @ptrCast(@alignCast(context));
        if (token == @as(LockToken, @ptrCast(self))) self.held_value = false;
    }
};

fn testReservedState(allocator: std.mem.Allocator) !OwnedState {
    return create(allocator, .{
        .attempt_id = @splat(0x11),
        .generation = 1,
        .operation = .install,
        .phase = .reserved,
        .mutation_started = false,
        .outcome = .pending,
        .request_sha256 = @splat(0x22),
        .profile = .{
            .path = "/etc/debz/default.json",
            .sha256 = @splat(0x23),
            .reference_evidence_sha256 = @splat(0x24),
        },
        .updated_unix = 1_800_000_000,
    });
}

fn testCompletedState(allocator: std.mem.Allocator) !OwnedState {
    const lock: api.DocumentBinding = .{
        .path = "/var/lib/debz/apt/exact-lock-v2.json",
        .schema = "https://debz.dev/schema/exact-closure-lock-v2",
        .version = 2,
        .digest_sha256 = @splat(0x33),
    };
    return create(allocator, .{
        .attempt_id = @splat(0x11),
        .generation = 9,
        .operation = .install,
        .phase = .completed,
        .mutation_started = true,
        .outcome = .succeeded,
        .request_sha256 = @splat(0x22),
        .profile = .{
            .path = "/etc/debz/default.json",
            .sha256 = @splat(0x23),
            .reference_evidence_sha256 = @splat(0x24),
        },
        .exact_lock = lock,
        .transaction_result = .{
            .path = "/var/lib/debz/transaction-result.json",
            .schema = "https://debz.dev/schema/transaction-result-v2",
            .version = 2,
            .digest_sha256 = @splat(0x44),
        },
        .root_operation_completion = .{
            .document = .{
                .path = "/var/lib/debz/root-operation-completion-v1.json",
                .schema = "https://debz.dev/schema/root-operation-completion-v1",
                .version = 1,
                .digest_sha256 = @splat(0x55),
            },
            .completed_attempt_id = @splat(0x11),
        },
        .updated_unix = 1_800_000_000,
    });
}

test "apt_system_state.test.completed state round-trips canonically" {
    var state = try testCompletedState(std.testing.allocator);
    defer state.deinit();
    const bytes = try state.state.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var decoded = try decode(
        std.testing.allocator,
        bytes,
        maximum_document_bytes,
    );
    defer decoded.deinit();
    try std.testing.expectEqual(Phase.completed, decoded.state.phase);
    try std.testing.expectEqual(Outcome.succeeded, decoded.state.outcome);
    try std.testing.expect(decoded.state.root_operation_completion != null);
}

test "apt_system_state.test.completed state decoding preserves allocation failures" {
    var state = try testCompletedState(std.testing.allocator);
    defer state.deinit();
    const source = try state.state.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(source);
    const Case = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var decoded = try decode(allocator, bytes, maximum_document_bytes);
            defer decoded.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.run, .{source});
}

test "apt_system_state.test.success cannot omit root completion evidence" {
    var state = try testCompletedState(std.testing.allocator);
    defer state.deinit();
    var incomplete = state.state;
    incomplete.root_operation_completion = null;
    try std.testing.expectError(
        error.MissingCompletionEvidence,
        validate(incomplete),
    );
    var later = state.state;
    later.generation += 1;
    later.updated_unix += 1;
    later.digest_sha256 = @splat(0);
    var recreated = try create(std.testing.allocator, later);
    defer recreated.deinit();
    try std.testing.expectError(
        error.InvalidTransition,
        validateTransition(state.state, recreated.state),
    );
    var wrong_attempt = state.state;
    wrong_attempt.root_operation_completion.?.completed_attempt_id = @splat(0xff);
    try std.testing.expectError(
        error.InvalidCompletionEvidence,
        validate(wrong_attempt),
    );
}

test "apt_system_state.test.phase and mutation evidence are strictly coupled" {
    var reserved = try testReservedState(std.testing.allocator);
    defer reserved.deinit();
    var invalid = reserved.state;
    invalid.phase = .planned;
    invalid.mutation_started = true;
    invalid.exact_lock = .{
        .path = "/var/lib/debz/lock.json",
        .schema = "lock",
        .version = 1,
        .digest_sha256 = @splat(1),
    };
    try std.testing.expectError(error.InvalidMutationState, validate(invalid));

    invalid.phase = .mutating;
    invalid.mutation_started = false;
    try std.testing.expectError(error.InvalidMutationState, validate(invalid));

    invalid.phase = .verifying;
    invalid.mutation_started = true;
    try std.testing.expectError(error.MissingTransactionResult, validate(invalid));

    var update = reserved.state;
    update.operation = .update;
    update.phase = .completed;
    update.outcome = .succeeded;
    update.mutation_started = false;
    update.diagnostic = "";
    try validate(update);
}

test "apt_system_state.test.profile paths are byte-bounded before scanning" {
    var reserved = try testReservedState(std.testing.allocator);
    defer reserved.deinit();
    var state = reserved.state;
    state.profile.path = @as(
        [*]const u8,
        @ptrFromInt(1),
    )[0 .. api.maximum_path_bytes + 1];
    try std.testing.expectError(error.InvalidProfile, validate(state));
}

test "apt_system_state.test.diagnostics reject bounded oversized text" {
    const ascii = try std.testing.allocator.alloc(
        u8,
        api.maximum_summary_characters + 1,
    );
    defer std.testing.allocator.free(ascii);
    @memset(ascii, 'a');
    try std.testing.expect(!validDiagnostic(ascii));

    const unicode = try std.testing.allocator.alloc(
        u8,
        (api.maximum_summary_characters + 1) * 2,
    );
    defer std.testing.allocator.free(unicode);
    for (0..api.maximum_summary_characters + 1) |index| {
        unicode[index * 2] = 0xc3;
        unicode[index * 2 + 1] = 0xa9;
    }
    try std.testing.expect(!validDiagnostic(unicode));

    const over_byte_bound = try std.testing.allocator.alloc(
        u8,
        api.maximum_summary_characters * 4 + 1,
    );
    defer std.testing.allocator.free(over_byte_bound);
    @memset(over_byte_bound, 'a');
    try std.testing.expect(!validDiagnostic(over_byte_bound));
}

test "apt_system_state.test.transitions are monotonic and evidence is sticky" {
    var reserved = try testReservedState(std.testing.allocator);
    defer reserved.deinit();

    var profile_input = reserved.state;
    profile_input.generation += 1;
    profile_input.phase = .profile_loaded;
    profile_input.updated_unix += 1;
    var profile = try create(std.testing.allocator, profile_input);
    defer profile.deinit();
    try validateTransition(reserved.state, profile.state);

    var authenticated_input = profile.state;
    authenticated_input.generation += 1;
    authenticated_input.phase = .authenticated;
    authenticated_input.updated_unix += 1;
    var authenticated = try create(std.testing.allocator, authenticated_input);
    defer authenticated.deinit();
    try validateTransition(profile.state, authenticated.state);

    var planned_input = authenticated.state;
    planned_input.generation += 1;
    planned_input.phase = .planned;
    planned_input.updated_unix += 1;
    planned_input.exact_lock = .{
        .path = "/var/lib/debz/lock.json",
        .schema = "lock",
        .version = 1,
        .digest_sha256 = @splat(0x33),
    };
    var planned = try create(std.testing.allocator, planned_input);
    defer planned.deinit();
    try validateTransition(authenticated.state, planned.state);

    var rollback_input = planned.state;
    rollback_input.generation += 1;
    rollback_input.phase = .downloaded;
    rollback_input.updated_unix += 1;
    rollback_input.exact_lock.?.digest_sha256 = @splat(0xff);
    var rollback = try create(std.testing.allocator, rollback_input);
    defer rollback.deinit();
    try std.testing.expectError(
        error.EvidenceRollback,
        validateTransition(planned.state, rollback.state),
    );

    var mutating_input = planned.state;
    mutating_input.generation += 1;
    mutating_input.phase = .downloaded;
    mutating_input.updated_unix += 1;
    var downloaded = try create(std.testing.allocator, mutating_input);
    defer downloaded.deinit();
    try validateTransition(planned.state, downloaded.state);

    mutating_input = downloaded.state;
    mutating_input.generation += 1;
    mutating_input.phase = .mutating;
    mutating_input.mutation_started = true;
    mutating_input.updated_unix += 1;
    var mutating = try create(std.testing.allocator, mutating_input);
    defer mutating.deinit();
    try validateTransition(downloaded.state, mutating.state);

    var recovery_input = mutating.state;
    recovery_input.generation += 1;
    recovery_input.phase = .recovery_required;
    recovery_input.diagnostic = "recovery required";
    recovery_input.updated_unix += 1;
    var recovery = try create(std.testing.allocator, recovery_input);
    defer recovery.deinit();
    try validateTransition(mutating.state, recovery.state);

    var reconciliation_input = recovery.state;
    reconciliation_input.generation += 1;
    reconciliation_input.phase = .verifying;
    reconciliation_input.diagnostic = "";
    reconciliation_input.transaction_result = .{
        .path = "/var/lib/debz/result.json",
        .schema = "result",
        .version = 1,
        .digest_sha256 = @splat(0x44),
    };
    reconciliation_input.updated_unix += 1;
    var reconciliation = try create(
        std.testing.allocator,
        reconciliation_input,
    );
    defer reconciliation.deinit();
    try validateTransition(recovery.state, reconciliation.state);
}

test "apt_system_state.test.locked compare-and-set rejects concurrent and stale writers" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var locks: TestLockBackend = .{};
    try std.testing.expectError(
        error.InvalidPath,
        Store.init(
            std.testing.io,
            directory.dir,
            "../state.json",
            locks.interface(),
        ),
    );
    const store = try Store.init(
        std.testing.io,
        directory.dir,
        document_name,
        locks.interface(),
    );
    var reserved = try testReservedState(std.testing.allocator);
    defer reserved.deinit();

    const held = try locks.interface().acquire(0);
    try std.testing.expectError(
        error.LockTimeout,
        store.initialize(
            std.testing.allocator,
            reserved.state,
            maximum_document_bytes,
            0,
        ),
    );
    locks.interface().release(held);
    try store.initialize(
        std.testing.allocator,
        reserved.state,
        maximum_document_bytes,
        0,
    );

    var next_input = reserved.state;
    next_input.generation += 1;
    next_input.phase = .profile_loaded;
    next_input.updated_unix += 1;
    var next = try create(std.testing.allocator, next_input);
    defer next.deinit();
    const stale = Expected.fromState(reserved.state);
    try store.compareAndSet(
        std.testing.allocator,
        stale,
        next.state,
        maximum_document_bytes,
        0,
    );
    try std.testing.expectError(
        error.StaleState,
        store.compareAndSet(
            std.testing.allocator,
            stale,
            next.state,
            maximum_document_bytes,
            0,
        ),
    );
    var wrong_digest = Expected.fromState(next.state);
    wrong_digest.digest_sha256 = @splat(0xff);
    var final_input = next.state;
    final_input.generation += 1;
    final_input.phase = .authenticated;
    final_input.updated_unix += 1;
    var final = try create(std.testing.allocator, final_input);
    defer final.deinit();
    try std.testing.expectError(
        error.StaleState,
        store.compareAndSet(
            std.testing.allocator,
            wrong_digest,
            final.state,
            maximum_document_bytes,
            0,
        ),
    );
    var loaded = try store.read(std.testing.allocator, maximum_document_bytes);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u64, 2), loaded.state.generation);
    try std.testing.expectEqual(Phase.profile_loaded, loaded.state.phase);
}

test "apt_system_state.test.post-rename errors preserve published state" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const Hooks = struct {
        fail_after_rename: bool = true,
        fail_resync: bool = false,

        fn run(context: ?*anyopaque, boundary: WriteBoundary) !void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (boundary == .after_rename and self.fail_after_rename) {
                self.fail_after_rename = false;
                return error.InjectedPostRenameFailure;
            }
            if (boundary == .before_durability_resync and self.fail_resync)
                return error.InjectedDurabilityResyncFailure;
        }
    };

    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var locks: TestLockBackend = .{};
    var store = try Store.init(
        std.testing.io,
        directory.dir,
        document_name,
        locks.interface(),
    );
    var reserved = try testReservedState(std.testing.allocator);
    defer reserved.deinit();
    try store.initialize(
        std.testing.allocator,
        reserved.state,
        maximum_document_bytes,
        0,
    );

    var next_input = reserved.state;
    next_input.generation += 1;
    next_input.phase = .profile_loaded;
    next_input.updated_unix += 1;
    var next = try create(std.testing.allocator, next_input);
    defer next.deinit();
    var hooks: Hooks = .{};
    store.write_hooks = .{ .context = &hooks, .runFn = Hooks.run };
    try std.testing.expectError(
        error.InjectedPostRenameFailure,
        store.compareAndSet(
            std.testing.allocator,
            Expected.fromState(reserved.state),
            next.state,
            maximum_document_bytes,
            0,
        ),
    );

    var published = try store.read(
        std.testing.allocator,
        maximum_document_bytes,
    );
    defer published.deinit();
    try std.testing.expectEqual(next.state.generation, published.state.generation);
    try std.testing.expectEqual(next.state.phase, published.state.phase);
    try std.testing.expectEqualSlices(
        u8,
        &next.state.digest_sha256,
        &published.state.digest_sha256,
    );
    hooks.fail_resync = true;
    try std.testing.expectError(
        error.InjectedDurabilityResyncFailure,
        store.ensureDurable(
            std.testing.allocator,
            Expected.fromState(next.state),
            maximum_document_bytes,
            0,
        ),
    );
    hooks.fail_resync = false;
    try store.ensureDurable(
        std.testing.allocator,
        Expected.fromState(next.state),
        maximum_document_bytes,
        0,
    );
}

test "apt_system_state.test.production operation lock serializes writers" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var first: SystemLockBackend = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .dir = directory.dir,
    };
    var second: SystemLockBackend = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .dir = directory.dir,
    };
    const held = try first.interface().acquire(0);
    defer first.interface().release(held);
    try std.testing.expectError(
        error.LockTimeout,
        second.interface().acquire(0),
    );
}

test "apt_system_state.test.schema uses the shared evidence contract" {
    const source = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "schema/apt-system-operation-state-v1.json",
        std.testing.allocator,
        .limited(maximum_document_bytes),
    );
    defer std.testing.allocator.free(source);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, source, .{});
    defer parsed.deinit();
    const properties = parsed.value.object.get("properties").?.object;
    try std.testing.expectEqualStrings(
        schema_id,
        properties.get("schema").?.object.get("const").?.string,
    );
    const phases = properties.get("phase").?.object.get("enum").?.array.items;
    try std.testing.expectEqual(std.meta.fields(Phase).len, phases.len);
    inline for (std.meta.fields(Phase)) |field| {
        var found = false;
        for (phases) |value| {
            if (value == .string and std.mem.eql(u8, field.name, value.string)) {
                found = true;
            }
        }
        try std.testing.expect(found);
    }
}

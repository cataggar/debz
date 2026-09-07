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
        try writeDocument(self, &output.writer);
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
    }) catch return error.InvalidDocument;
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, schema_id) or
        wire.version != schema_version)
        return error.UnsupportedSchema;

    var attempt_id: [32]u8 = undefined;
    var request_sha256: [32]u8 = undefined;
    var profile_sha256: [32]u8 = undefined;
    var digest_sha256: [32]u8 = undefined;
    try parseHex(&attempt_id, wire.attempt_id);
    try parseHex(&request_sha256, wire.request_sha256);
    try parseHex(&profile_sha256, wire.profile.sha256);
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
    write_hooks: WriteHooks = .{},

    pub fn init(io: std.Io, dir: std.Io.Dir, name: []const u8) !Store {
        if (!safeLeaf(name)) return error.InvalidPath;
        return .{ .io = io, .dir = dir, .name = name };
    }

    pub fn read(
        self: Store,
        allocator: std.mem.Allocator,
        maximum_bytes: usize,
    ) !OwnedState {
        var file = try self.dir.openFile(self.io, self.name, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const source = try reader.interface.allocRemaining(
            allocator,
            .limited(maximum_bytes),
        );
        defer allocator.free(source);
        return decode(allocator, source, maximum_bytes);
    }

    pub fn writeAtomic(
        self: Store,
        allocator: std.mem.Allocator,
        state: State,
        maximum_bytes: usize,
    ) !void {
        if (maximum_bytes == 0 or maximum_bytes > maximum_document_bytes)
            return error.DocumentTooLarge;
        const bytes = try state.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_bytes) return error.DocumentTooLarge;
        const stage = ".apt-system-operation-state-v1.tmp";
        self.dir.deleteFile(self.io, stage) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try self.write_hooks.run(.before_stage);
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
        try self.dir.rename(stage, self.dir, self.name, self.io);
        try self.write_hooks.run(.after_rename);
        switch (@import("builtin").os.tag) {
            .linux => if (std.os.linux.errno(std.os.linux.fsync(self.dir.handle)) != .SUCCESS)
                return error.Unexpected,
            else => {},
        }
    }
};

pub const WriteBoundary = enum {
    before_stage,
    after_rename,
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
    if (!validDiagnostic(state.diagnostic))
        return error.InvalidDiagnostic;
    if ((state.outcome == .pending) != (state.phase != .completed))
        return error.InvalidOutcome;
    if (state.mutation_started and !state.operation.mutatesRoot())
        return error.InvalidMutationState;
    if (state.phase == .recovery_required and !state.mutation_started)
        return error.InvalidMutationState;
    if (state.transaction_result != null and !state.mutation_started)
        return error.InvalidTransactionEvidence;
    if (state.root_operation_completion != null and
        (!state.mutation_started or state.phase != .completed))
        return error.InvalidCompletionEvidence;
    if (state.operation.mutatesRoot()) {
        switch (state.phase) {
            .planned,
            .downloaded,
            .mutating,
            .verifying,
            .recovery_required,
            => if (state.exact_lock == null) return error.MissingExactLock,
            .completed => if (state.outcome != .failed_before_mutation and
                state.exact_lock == null) return error.MissingExactLock,
            .reserved, .profile_loaded, .authenticated => {},
        }
        if ((state.phase == .verifying or state.phase == .completed) and
            state.mutation_started and state.transaction_result == null)
            return error.MissingTransactionResult;
        if ((state.outcome == .succeeded or state.outcome == .recovered) and
            state.root_operation_completion == null)
            return error.MissingCompletionEvidence;
    } else if (state.exact_lock != null or
        state.transaction_result != null or
        state.root_operation_completion != null)
        return error.UnexpectedTransactionEvidence;
    if (state.outcome == .failed_before_mutation and state.mutation_started)
        return error.InvalidOutcome;
    if ((state.outcome == .failed_after_mutation or state.outcome == .recovered) and
        !state.mutation_started)
        return error.InvalidOutcome;
    if (state.outcome == .pending and state.diagnostic.len != 0 and
        state.phase != .recovery_required)
        return error.InvalidDiagnostic;
    if (state.phase == .recovery_required and state.diagnostic.len == 0)
        return error.InvalidDiagnostic;
    if (state.outcome != .pending and state.outcome != .succeeded and
        state.diagnostic.len == 0)
        return error.InvalidDiagnostic;
}

fn validDiagnostic(value: []const u8) bool {
    if (value.len > api.maximum_summary_bytes or
        !std.unicode.utf8ValidateSlice(value))
        return false;
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
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
            .completed_attempt_id = @splat(0x66),
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

test "apt_system_state.test.success cannot omit root completion evidence" {
    var state = try testCompletedState(std.testing.allocator);
    defer state.deinit();
    var incomplete = state.state;
    incomplete.root_operation_completion = null;
    try std.testing.expectError(
        error.MissingCompletionEvidence,
        validate(incomplete),
    );
}

test "apt_system_state.test.atomic store rejects unsafe names and persists state" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectError(
        error.InvalidPath,
        Store.init(std.testing.io, directory.dir, "../state.json"),
    );
    const store = try Store.init(std.testing.io, directory.dir, document_name);
    var state = try testCompletedState(std.testing.allocator);
    defer state.deinit();
    try store.writeAtomic(
        std.testing.allocator,
        state.state,
        maximum_document_bytes,
    );
    var loaded = try store.read(std.testing.allocator, maximum_document_bytes);
    defer loaded.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &state.state.digest_sha256,
        &loaded.state.digest_sha256,
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
}

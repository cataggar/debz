//! Offline diagnostics: validate timestamps against the original durable chain.
const std = @import("std");
const debz = @import("debz");
const recovery = debz.native_recovery;
const telemetry = recovery.phase_telemetry;
const fs = debz.root_fs;
const maximum_log_bytes = 256 * 1024 * 1024;
const maximum_invocations = 4096;
const InvocationKey = struct { epoch: [16]u8, invocation: u64 };

const Fields = struct {
    attempt: []const u8,
    process_epoch: []const u8,
    invocation: u64,
    sequence: u64,
    kind: []const u8,
    program_step: u32,
    substep: u16,
    ordinal: u32,
    stage: []const u8,
    result: []const u8,
    elapsed_ns: u64,
    capture_count: u64,
    capture_ns: u64,
    import_count: u64,
    import_ns: u64,
    hash_count: u64,
    hash_ns: u64,
    mutation_count: u64,
    mutation_ns: u64,
    fsync_count: u64,
    fsync_ns: u64,
    progress_serialization_count: u64,
    progress_serialization_ns: u64,
    schema: []const u8,
    version: u32,
    clock: []const u8,
    published: bool,
    progress_version: u32,
    intent_sha256: []const u8,
    progress_sequence: u64,
    progress_record_sha256: []const u8,
    progress_document_sha256: []const u8,
};

const Counter = struct { phase: telemetry.Phase, count: u64 = 0, nanoseconds: u64 = 0 };
const counters_zero = block: {
    var result: [std.enums.values(telemetry.Phase).len]Counter = undefined;
    for (std.enums.values(telemetry.Phase), 0..) |phase, index| result[index] = .{ .phase = phase };
    break :block result;
};
const Invocation = struct {
    attempt: []const u8,
    process_epoch: []const u8,
    invocation: u64,
    next_sequence: u64 = 0,
    elapsed_ns: u64 = 0,
    maximum_record_gap_ns: u64 = 0,
    published_records: usize = 0,
    finished: bool = false,
    counters: @TypeOf(counters_zero) = counters_zero,
};
const Summary = struct {
    schema: []const u8 = "https://debz.dev/schema/native-phase-summary-v1",
    version: u32 = 1,
    diagnostic_only: bool = true,
    clock: []const u8 = "awake",
    log_sha256: [64]u8,
    progress_file_sha256: [64]u8,
    intent_sha256: recovery.Digest,
    progress_head_sha256: recovery.Digest,
    durable_records: usize,
    recovered_phases: u64,
    all_invocations_finished: bool,
    invocations: []const Invocation,
};

fn parseFields(line: []const u8) !Fields {
    var result: Fields = undefined;
    var seen: [std.meta.fields(Fields).len]bool = @splat(false);
    var words = std.mem.tokenizeScalar(u8, line, ' ');
    while (words.next()) |word| {
        const equal = std.mem.indexOfScalar(u8, word, '=') orelse return error.MalformedTelemetry;
        const name = word[0..equal];
        const value = word[equal + 1 ..];
        if (value.len == 0) return error.MalformedTelemetry;
        var recognized = false;
        inline for (std.meta.fields(Fields), 0..) |field, index| {
            if (std.mem.eql(u8, name, field.name)) {
                if (seen[index]) return error.DuplicateTelemetryField;
                seen[index] = true;
                recognized = true;
                @field(result, field.name) = switch (field.type) {
                    []const u8 => value,
                    bool => if (std.mem.eql(u8, value, "true")) true else if (std.mem.eql(u8, value, "false")) false else return error.MalformedTelemetry,
                    else => block: {
                        for (value) |byte| if (!std.ascii.isDigit(byte)) return error.MalformedTelemetry;
                        if (value.len > 1 and value[0] == '0') return error.MalformedTelemetry;
                        break :block std.fmt.parseInt(field.type, value, 10) catch return error.MalformedTelemetry;
                    },
                };
            }
        }
        if (!recognized) return error.UnknownTelemetryField;
    }
    for (seen) |value| if (!value) return error.MissingTelemetryField;
    if (!std.mem.eql(u8, result.schema, telemetry.schema_id) or result.version != 1 or
        !std.mem.eql(u8, result.clock, "awake")) return error.UnsupportedTelemetrySchema;
    try lowerHex(result.attempt, 64);
    try lowerHex(result.process_epoch, 32);
    return result;
}

fn lowerHex(bytes: []const u8, length: usize) !void {
    if (bytes.len != length) return error.MalformedTelemetryDigest;
    for (bytes) |byte| if (!(std.ascii.isDigit(byte) or (byte >= 'a' and byte <= 'f')))
        return error.MalformedTelemetryDigest;
}

fn digest(bytes: []const u8) [64]u8 {
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &value, .{});
    return std.fmt.bytesToHex(value, .lower);
}

fn validateBinding(fields: Fields, progress: recovery.ProgressDocument, index: usize) !void {
    if (index >= progress.records.len) return error.ExtraPublishedRecord;
    const record = progress.records[index];
    if (fields.progress_version != progress.version or fields.progress_sequence != record.sequence or
        !std.mem.eql(u8, fields.intent_sha256, &progress.intent_sha256) or
        !std.mem.eql(u8, fields.progress_record_sha256, &record.digest_sha256) or
        !std.mem.eql(u8, fields.kind, @tagName(record.action.kind)) or
        fields.program_step != record.action.program_step or fields.substep != record.action.substep or
        fields.ordinal != record.action.ordinal or !std.mem.eql(u8, fields.stage, @tagName(record.stage)) or
        !std.mem.eql(u8, fields.result, @tagName(record.result))) return error.ProgressBindingMismatch;
    try lowerHex(fields.progress_document_sha256, 64);
    if (index + 1 == progress.records.len and
        !std.mem.eql(u8, fields.progress_document_sha256, &progress.digest_sha256))
        return error.ProgressBindingMismatch;
}

fn summarize(allocator: std.mem.Allocator, log: []const u8, progress_bytes: []const u8) !Summary {
    if (log.len > maximum_log_bytes) return error.LimitExceeded;
    var progress = try recovery.decodeProgress(allocator, progress_bytes);
    defer progress.deinit();
    var invocations: std.ArrayList(Invocation) = .empty;
    errdefer invocations.deinit(allocator);
    var invocation_index: std.AutoHashMapUnmanaged(InvocationKey, usize) = .empty;
    defer invocation_index.deinit(allocator);
    var published: usize = 0;
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| {
        const prefix = std.mem.indexOf(u8, line, "native_phase ") orelse continue;
        if (prefix != 0 and !std.mem.eql(u8, line[0..prefix], "info: ")) return error.MalformedTelemetry;
        if (line.len > 4096) return error.LimitExceeded;
        const fields = try parseFields(line[prefix + "native_phase ".len ..]);
        if (invocations.items.len != 0 and !std.mem.eql(u8, fields.attempt, invocations.items[0].attempt))
            return error.MixedAttemptTelemetry;
        var key: InvocationKey = .{ .epoch = undefined, .invocation = fields.invocation };
        _ = try std.fmt.hexToBytes(&key.epoch, fields.process_epoch);
        const indexed = try invocation_index.getOrPut(allocator, key);
        if (!indexed.found_existing) {
            if (invocations.items.len >= maximum_invocations) return error.LimitExceeded;
            indexed.value_ptr.* = invocations.items.len;
            try invocations.append(allocator, .{
                .attempt = fields.attempt,
                .process_epoch = fields.process_epoch,
                .invocation = fields.invocation,
            });
        }
        const invocation = &invocations.items[indexed.value_ptr.*];
        if (invocation.finished or fields.sequence != invocation.next_sequence or
            fields.elapsed_ns < invocation.elapsed_ns) return error.NonMonotonicTelemetry;
        invocation.next_sequence = try std.math.add(u64, invocation.next_sequence, 1);
        const gap = fields.elapsed_ns - invocation.elapsed_ns;
        invocation.elapsed_ns = fields.elapsed_ns;
        inline for (std.enums.values(telemetry.Phase), 0..) |phase, index| {
            const count = @field(fields, @tagName(phase) ++ "_count");
            const nanoseconds = @field(fields, @tagName(phase) ++ "_ns");
            const counter = &invocation.counters[index];
            if (count < counter.count or nanoseconds < counter.nanoseconds)
                return error.NonMonotonicTelemetry;
            counter.count = count;
            counter.nanoseconds = nanoseconds;
        }
        if (fields.published) {
            try validateBinding(fields, progress.document, published);
            published += 1;
            invocation.published_records += 1;
            invocation.maximum_record_gap_ns = @max(invocation.maximum_record_gap_ns, gap);
        } else {
            if (!std.mem.eql(u8, fields.kind, "attempt_end") or !std.mem.eql(u8, fields.stage, "finished") or
                !std.mem.eql(u8, fields.result, "none") or fields.program_step != 0 or fields.substep != 0 or
                fields.ordinal != 0 or fields.progress_version != 0 or fields.progress_sequence != 0 or
                !std.mem.eql(u8, fields.intent_sha256, "-") or
                !std.mem.eql(u8, fields.progress_record_sha256, "-") or
                !std.mem.eql(u8, fields.progress_document_sha256, "-"))
                return error.InvalidUnpublishedTelemetry;
            invocation.finished = true;
        }
    }
    if (published == 0 or published != progress.document.records.len) return error.IncompleteProgressTelemetry;
    var all_finished = true;
    for (invocations.items) |invocation| all_finished = all_finished and invocation.finished;
    return .{
        .log_sha256 = digest(log),
        .progress_file_sha256 = digest(progress_bytes),
        .intent_sha256 = progress.document.intent_sha256,
        .progress_head_sha256 = progress.document.head_sha256,
        .durable_records = published,
        .recovered_phases = recovery.summarizeProgress(progress.document).recovered_phase_count,
        .all_invocations_finished = all_finished,
        .invocations = try invocations.toOwnedSlice(allocator),
    };
}

fn read(io: std.Io, allocator: std.mem.Allocator, path: []const u8, maximum: usize) ![]u8 {
    const parent = std.fs.path.dirname(path) orelse return error.AbsoluteEvidencePathRequired;
    var root = try fs.openAbsoluteRoot(io, parent);
    defer root.close();
    var pin = try root.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(path)));
    defer pin.close();
    if ((try pin.metadata()).entry.link_count != 1) return error.HardLinkedTelemetryEvidence;
    return (try pin.observeStableAlloc(allocator, maximum)).bytes;
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const log_path = args.next() orelse return error.MissingTelemetryArguments;
    const progress_path = args.next() orelse return error.MissingTelemetryArguments;
    if (args.next() != null) return error.UnexpectedTelemetryArgument;
    const allocator = init.arena.allocator();
    const log = try read(init.io, allocator, log_path, maximum_log_bytes);
    const progress = try read(init.io, allocator, progress_path, recovery.maximum_progress_bytes);
    const summary = try summarize(allocator, log, progress);
    const bytes = try std.json.Stringify.valueAlloc(allocator, summary, .{ .whitespace = .indent_2 });
    try std.Io.File.stdout().writeStreamingAll(init.io, bytes);
    try std.Io.File.stdout().writeStreamingAll(init.io, "\n");
}

fn exampleLine(allocator: std.mem.Allocator, log: *std.ArrayList(u8), context: *const telemetry.Context, progress: recovery.ProgressDocument, finished: bool) !void {
    const record = progress.records[progress.records.len - 1];
    const fields: Fields = .{
        .attempt = &std.fmt.bytesToHex(context.attempt_id, .lower),
        .process_epoch = &std.fmt.bytesToHex(context.process_epoch, .lower),
        .invocation = context.invocation,
        .sequence = context.sequence - 1,
        .kind = if (finished) "attempt_end" else @tagName(record.action.kind),
        .program_step = if (finished) 0 else record.action.program_step,
        .substep = if (finished) 0 else record.action.substep,
        .ordinal = if (finished) 0 else record.action.ordinal,
        .stage = if (finished) "finished" else @tagName(record.stage),
        .result = if (finished) "none" else @tagName(record.result),
        .elapsed_ns = @intCast(context.started.durationTo(std.Io.Clock.awake.now(std.testing.io)).toNanoseconds()),
        .capture_count = context.measurement(.capture).count,
        .capture_ns = context.measurement(.capture).nanoseconds,
        .import_count = context.measurement(.import).count,
        .import_ns = context.measurement(.import).nanoseconds,
        .hash_count = context.measurement(.hash).count,
        .hash_ns = context.measurement(.hash).nanoseconds,
        .mutation_count = context.measurement(.mutation).count,
        .mutation_ns = context.measurement(.mutation).nanoseconds,
        .fsync_count = context.measurement(.fsync).count,
        .fsync_ns = context.measurement(.fsync).nanoseconds,
        .progress_serialization_count = context.measurement(.progress_serialization).count,
        .progress_serialization_ns = context.measurement(.progress_serialization).nanoseconds,
        .schema = telemetry.schema_id,
        .version = 1,
        .clock = "awake",
        .published = !finished,
        .progress_version = if (finished) 0 else progress.version,
        .intent_sha256 = if (finished) "-" else &progress.intent_sha256,
        .progress_sequence = if (finished) 0 else record.sequence,
        .progress_record_sha256 = if (finished) "-" else &record.digest_sha256,
        .progress_document_sha256 = if (finished) "-" else &progress.digest_sha256,
    };
    try log.appendSlice(allocator, "native_phase");
    inline for (std.meta.fields(Fields)) |field| {
        const value = @field(fields, field.name);
        const rendered = switch (field.type) {
            []const u8 => try std.fmt.allocPrint(allocator, " {s}={s}", .{ field.name, value }),
            bool => try std.fmt.allocPrint(allocator, " {s}={s}", .{ field.name, if (value) "true" else "false" }),
            else => try std.fmt.allocPrint(allocator, " {s}={d}", .{ field.name, value }),
        };
        defer allocator.free(rendered);
        try log.appendSlice(allocator, rendered);
    }
    try log.append(allocator, '\n');
}

fn example(allocator: std.mem.Allocator, restarted: bool, version: u32) !struct { log: []u8, progress: []u8 } {
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    const root = fs.Root.init(std.testing.io, fixture.dir);
    for ([_][]const u8{ "var", "var/lib", debz.root_operation.namespace_path }) |path|
        try root.ensureDirectory(try fs.Path.init(path), fs.default_directory_permissions);
    const intent: recovery.Digest = @splat('1');
    switch (version) {
        1 => try recovery.initializeProgress(allocator, root, intent),
        2 => try recovery.initializeBootstrapProgress(allocator, root, intent),
        3 => try recovery.initializeAuthorityProgress(allocator, root, intent),
        4 => try recovery.initializeAuthorityBootstrapProgress(allocator, root, intent),
        else => unreachable,
    }
    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(allocator);
    var first = telemetry.Context.init(std.testing.io, @splat(2));
    first.attach();
    defer first.detach();
    const action: recovery.Action = .{ .kind = .database, .program_step = 3, .substep = 1, .ordinal = 2 };
    telemetry.start(.capture).end();
    try recovery.appendProgress(allocator, root, intent, action, .prepared, .none, null);
    var prepared = try recovery.readProgress(allocator, root);
    defer prepared.deinit();
    try exampleLine(allocator, &log, &first, prepared.document, false);
    if (restarted) {
        first.detach();
        try exampleLine(allocator, &log, &first, prepared.document, true);
    }
    var resumed = telemetry.Context.init(std.testing.io, @splat(2));
    if (restarted) resumed.attach();
    defer resumed.detach();
    try recovery.appendProgress(allocator, root, intent, action, .completed, if (restarted) .recovered else .applied, null);
    var completed = try recovery.readProgress(allocator, root);
    defer completed.deinit();
    const last = if (restarted) &resumed else &first;
    try exampleLine(allocator, &log, last, completed.document, false);
    last.detach();
    try exampleLine(allocator, &log, last, completed.document, true);
    return .{
        .log = try log.toOwnedSlice(allocator),
        .progress = try root.readFileAlloc(allocator, try fs.Path.init(recovery.progress_path), recovery.maximum_progress_bytes),
    };
}

test "native phase summary binds actual durable records and keeps recovery clocks separate" {
    for ([_]u32{ 1, 2, 3, 4 }) |version| {
        for ([_]bool{ false, true }) |restarted| {
            const allocator = std.testing.allocator;
            const input = try example(allocator, restarted, version);
            defer allocator.free(input.log);
            defer allocator.free(input.progress);
            const report = try summarize(allocator, input.log, input.progress);
            defer allocator.free(report.invocations);
            try std.testing.expectEqual(@as(usize, 2), report.durable_records);
            try std.testing.expectEqual(@as(usize, if (restarted) 2 else 1), report.invocations.len);
            try std.testing.expectEqual(@as(u64, if (restarted) 1 else 0), report.recovered_phases);
            try std.testing.expect(report.all_invocations_finished);
            try std.testing.expectEqual(@as(u64, 1), report.invocations[0].counters[0].count);
            if (restarted) try std.testing.expectEqual(@as(u64, 0), report.invocations[1].counters[0].count);
        }
    }
}

test "native phase summary rejects truncation drift duplicate records and backwards clocks" {
    const allocator = std.testing.allocator;
    const input = try example(allocator, false, 3);
    defer allocator.free(input.log);
    defer allocator.free(input.progress);
    const first_line = std.mem.indexOfScalar(u8, input.log, '\n').? + 1;
    try std.testing.expectError(error.IncompleteProgressTelemetry, summarize(allocator, input.log[0..first_line], input.progress));
    const doubled = try std.mem.concat(allocator, u8, &.{ input.log, input.log });
    defer allocator.free(doubled);
    try std.testing.expectError(error.NonMonotonicTelemetry, summarize(allocator, doubled, input.progress));
    for ([_][]const u8{ "progress_record_sha256=", "intent_sha256=", "program_step=" }) |needle| {
        const changed = try allocator.dupe(u8, input.log);
        defer allocator.free(changed);
        const offset = std.mem.indexOf(u8, changed, needle).? + needle.len;
        changed[offset] = if (changed[offset] == '0') '1' else '0';
        try std.testing.expectError(error.ProgressBindingMismatch, summarize(allocator, changed, input.progress));
    }
    const second_elapsed = std.mem.indexOf(u8, input.log[first_line..], "elapsed_ns=").? + first_line + "elapsed_ns=".len;
    const end_elapsed = std.mem.indexOfScalarPos(u8, input.log, second_elapsed, ' ').?;
    const backwards = try std.mem.concat(allocator, u8, &.{ input.log[0..second_elapsed], "0", input.log[end_elapsed..] });
    defer allocator.free(backwards);
    try std.testing.expectError(error.NonMonotonicTelemetry, summarize(allocator, backwards, input.progress));
    const second_fsync = std.mem.indexOf(u8, input.log[first_line..], "fsync_count=").? + first_line + "fsync_count=".len;
    const end_fsync = std.mem.indexOfScalarPos(u8, input.log, second_fsync, ' ').?;
    const decreased_counter = try std.mem.concat(allocator, u8, &.{ input.log[0..second_fsync], "0", input.log[end_fsync..] });
    defer allocator.free(decreased_counter);
    try std.testing.expectError(error.NonMonotonicTelemetry, summarize(allocator, decreased_counter, input.progress));
    const unknown = try std.mem.concat(allocator, u8, &.{ input.log[0 .. first_line - 1], " unknown=1\n", input.log[first_line..] });
    defer allocator.free(unknown);
    try std.testing.expectError(error.UnknownTelemetryField, summarize(allocator, unknown, input.progress));
}

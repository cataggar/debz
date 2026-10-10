const std = @import("std");
const fs = @import("debz").root_fs;

const maximum_result_bytes = 128 * 1024 * 1024;
const maximum_document_depth = 64;
const Outcome = struct {
    operation: []const u8 = "native",
    exit_status: u8 = 1,
    changed: ?bool = null,
    summary: []const u8 = "native acceptance evidence unavailable",
    diagnostics: []const std.json.Value = &.{},
    stage: ?[]const u8 = null,
    workflow_step_outcome: []const u8,
    wrapper_exit_status: ?u8 = null,
    command_exit_status: ?u8 = null,
    result_exit_status: ?u8 = null,
    result_available: bool = false,
    expected_refusal: bool = false,
};
const Report = struct { outcome: Outcome, collector_exit: u8 };
const stages = .{
    .refresh = "refresh",
    .@"resolve-lock" = "plan",
    .download = "download",
    .create = "install",
    .@"create-summary" = "transaction-result verify",
    .@"reproduce-lock" = "plan",
    .@"resolve-update-lock" = "plan",
    .update = "upgrade-all",
    .@"injected-failure" = "plan",
};

fn operation(stage: []const u8) ![]const u8 {
    inline for (std.meta.fields(@TypeOf(stages))) |entry| {
        if (std.mem.eql(u8, stage, entry.name)) return @field(stages, entry.name);
    }
    return error.InvalidLatestStage;
}

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidResultObject;
    return value.object.get(name) orelse error.MissingResultField;
}

fn string(value: std.json.Value) ![]const u8 {
    return if (value == .string) value.string else error.InvalidResultString;
}

fn exitStatus(value: std.json.Value) !u8 {
    if (value != .number_string or std.mem.indexOfAny(u8, value.number_string, ".eE") != null)
        return error.InvalidExitStatus;
    const status = std.fmt.parseInt(i16, value.number_string, 10) catch return error.InvalidExitStatus;
    if (status < 0 or status > 255) return error.InvalidExitStatus;
    return @intCast(status);
}

fn read(root: *fs.OwnedRoot, allocator: std.mem.Allocator, path: []const u8, maximum: usize) ![]u8 {
    var pin = try root.root.pinRegularFile(try fs.Path.init(path));
    defer pin.close();
    if ((try pin.metadata()).entry.link_count != 1) return error.HardLinkedOutcomeEvidence;
    return (try pin.observeStableAlloc(allocator, maximum)).bytes;
}

fn document(root: *fs.OwnedRoot, allocator: std.mem.Allocator, path: []const u8, maximum: usize) !std.json.Value {
    const bytes = try read(root, allocator, path, maximum);
    var scanner = std.json.Scanner.initCompleteInput(allocator, bytes);
    defer scanner.deinit();
    var depth: usize = 0;
    while (true) {
        switch (try scanner.next()) {
            .object_begin, .array_begin => {
                depth += 1;
                if (depth > maximum_document_depth) return error.OutcomeDepthExceeded;
            },
            .object_end, .array_end => {
                if (depth == 0) return error.InvalidResultObject;
                depth -= 1;
            },
            .end_of_document => break,
            else => {},
        }
    }
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .max_value_len = maximum,
        .parse_numbers = false,
    });
    return parsed.value;
}

fn diagnostic(allocator: std.mem.Allocator, outcome: *Outcome, id: []const u8, message: []const u8) !void {
    var object: std.json.ObjectMap = .empty;
    try object.put(allocator, "id", .{ .string = id });
    try object.put(allocator, "message", .{ .string = message });
    const values = try allocator.alloc(std.json.Value, outcome.diagnostics.len + 1);
    @memcpy(values[0..outcome.diagnostics.len], outcome.diagnostics);
    values[outcome.diagnostics.len] = .{ .object = object };
    outcome.diagnostics = values;
}

fn populate(root: *fs.OwnedRoot, allocator: std.mem.Allocator, outcome: *Outcome) !void {
    const workflow = outcome.workflow_step_outcome;
    var valid_workflow = false;
    for ([_][]const u8{ "success", "failure", "cancelled", "skipped", "unavailable" }) |name|
        valid_workflow = valid_workflow or std.mem.eql(u8, workflow, name);
    if (!valid_workflow) return error.InvalidWorkflowOutcome;
    const marker = try document(root, allocator, "native-stage-v1.json", 4096);
    const stage = try string(try field(marker, "stage"));
    const selected_operation = try operation(stage);
    outcome.stage = stage;
    outcome.operation = selected_operation;
    const command = if (marker == .object) marker.object.get("command_exit_status") else null;
    if (command) |value| {
        if (value != .null) outcome.command_exit_status = try exitStatus(value);
    }
    const wrapper = read(root, allocator, "native-wrapper-exit-status.txt", 32) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (wrapper) |bytes| {
        const text = std.mem.trim(u8, bytes, " \t\r\n\x0b\x0c");
        if (text.len == 0) return error.InvalidWrapperExitStatus;
        for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidWrapperExitStatus;
        outcome.wrapper_exit_status = std.fmt.parseInt(u8, text, 10) catch return error.InvalidWrapperExitStatus;
    }
    const result_path = try std.fmt.allocPrint(allocator, "{s}.json", .{stage});
    const result = try document(root, allocator, result_path, maximum_result_bytes);
    if (std.mem.eql(u8, stage, "create-summary")) {
        if (!std.mem.eql(u8, try string(try field(result, "backend")), "native"))
            return error.InvalidVerificationResult;
        const verdict = try string(try field(result, "outcome"));
        if (!std.mem.eql(u8, verdict, "succeeded") and !std.mem.eql(u8, verdict, "failed"))
            return error.InvalidVerificationResult;
        outcome.changed = false;
        outcome.summary = try std.fmt.allocPrint(allocator, "native transaction-result verification {s}", .{verdict});
    } else {
        const status = try exitStatus(try field(result, "exit_status"));
        const changed = try field(result, "changed");
        if (changed != .bool) return error.InvalidResultChanged;
        const result_operation = try string(try field(result, "operation"));
        if (!std.mem.eql(u8, result_operation, selected_operation)) return error.LatestOperationMismatch;
        const summary = try string(try field(result, "summary"));
        const diagnostics = try field(result, "diagnostics");
        if (diagnostics != .array) return error.InvalidResultDiagnostics;
        outcome.changed = changed.bool;
        outcome.summary = summary;
        outcome.diagnostics = diagnostics.array.items;
        outcome.result_exit_status = status;
    }
    outcome.result_available = true;
    const command_status = outcome.command_exit_status orelse return error.UnrecordedCommandExit;
    const expected_refusal = std.mem.eql(u8, stage, "injected-failure") and
        command_status != 0 and outcome.result_exit_status == 5;
    outcome.expected_refusal = expected_refusal;
    if (std.mem.eql(u8, workflow, "skipped") or std.mem.eql(u8, workflow, "unavailable"))
        return error.UnavailableWorkflowStep;
    if (std.mem.eql(u8, workflow, "success")) {
        if (outcome.wrapper_exit_status != 0 or !expected_refusal) return error.IncompleteSuccessfulWorkflow;
        outcome.exit_status = 0;
        outcome.summary = "native acceptance completed; injected invalid lock was refused as expected";
    } else {
        outcome.exit_status = if (outcome.wrapper_exit_status != null and outcome.wrapper_exit_status.? != 0)
            outcome.wrapper_exit_status.?
        else if (command_status != 0 and !expected_refusal) command_status else 1;
        try diagnostic(allocator, outcome, "native_acceptance_failed", try std.fmt.allocPrint(
            allocator,
            "native workflow step {s}; latest attempted stage {s}",
            .{ workflow, stage },
        ));
    }
}

fn invalid(allocator: std.mem.Allocator, outcome: *Outcome, err: anyerror) !Report {
    const unavailable = switch (err) {
        error.FileNotFound, error.UnrecordedCommandExit, error.UnavailableWorkflowStep => true,
        else => false,
    };
    const kind = if (unavailable) "unavailable" else "invalid";
    const message = @errorName(err);
    outcome.exit_status = if (outcome.wrapper_exit_status != null and outcome.wrapper_exit_status.? != 0)
        outcome.wrapper_exit_status.?
    else if (outcome.command_exit_status != null and outcome.command_exit_status.? != 0)
        outcome.command_exit_status.?
    else
        1;
    outcome.summary = try std.fmt.allocPrint(allocator, "native acceptance evidence {s}: {s}", .{ kind, message });
    try diagnostic(allocator, outcome, try std.fmt.allocPrint(allocator, "native_acceptance_evidence_{s}", .{kind}), message);
    return .{ .outcome = outcome.*, .collector_exit = 1 };
}

fn collect(io: std.Io, allocator: std.mem.Allocator, evidence: []const u8, workflow: []const u8) !Report {
    var outcome: Outcome = .{ .workflow_step_outcome = workflow };
    var root = fs.openAbsoluteRoot(io, evidence) catch |err| return invalid(allocator, &outcome, err);
    defer root.close();
    populate(&root, allocator, &outcome) catch |err| return invalid(allocator, &outcome, err);
    return .{ .outcome = outcome, .collector_exit = 0 };
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const evidence = args.next() orelse return error.MissingOutcomeArguments;
    const workflow = args.next() orelse return error.MissingOutcomeArguments;
    if (args.next() != null) return error.UnexpectedOutcomeArgument;
    const report = try collect(init.io, init.arena.allocator(), evidence, workflow);
    const bytes = try std.json.Stringify.valueAlloc(init.arena.allocator(), report.outcome, .{ .whitespace = .indent_2, .escape_unicode = true });
    try std.Io.File.stdout().writeStreamingAll(init.io, bytes);
    try std.Io.File.stdout().writeStreamingAll(init.io, "\n");
    if (report.collector_exit != 0) std.process.exit(report.collector_exit);
}

const Fixture = struct {
    temporary: std.testing.TmpDir,
    arena: std.heap.ArenaAllocator,
    path: []const u8,

    fn init() !Fixture {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer arena.deinit();
        var temporary = std.testing.tmpDir(.{});
        errdefer temporary.cleanup();
        const path = try temporary.dir.realPathFileAlloc(std.testing.io, ".", arena.allocator());
        return .{ .temporary = temporary, .arena = arena, .path = path };
    }
    fn deinit(self: *Fixture) void {
        self.temporary.cleanup();
        self.arena.deinit();
    }
    fn write(self: *Fixture, path: []const u8, bytes: []const u8) !void {
        try self.temporary.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = bytes });
    }
    fn attempt(self: *Fixture, stage: []const u8, command: ?u8, wrapper: ?u8, result: []const u8) !void {
        const allocator = self.arena.allocator();
        try self.write("native-stage-v1.json", try std.json.Stringify.valueAlloc(allocator, .{ .stage = stage, .command_exit_status = command }, .{}));
        try self.write(try std.fmt.allocPrint(allocator, "{s}.json", .{stage}), result);
        if (wrapper) |status| try self.write("native-wrapper-exit-status.txt", try std.fmt.allocPrint(allocator, "{d}\n", .{status}));
    }
    fn run(self: *Fixture, workflow: []const u8) !Report {
        return collect(std.testing.io, self.arena.allocator(), self.path, workflow);
    }
};

test "native outcome retains failed create diagnostics rather than earlier successful refresh" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.write("refresh.json", "{\"operation\":\"refresh\",\"exit_status\":0,\"changed\":true,\"summary\":\"refresh\",\"diagnostics\":[]}");
    try fixture.attempt("create", 8, 8, "{\"operation\":\"install\",\"exit_status\":8,\"changed\":true,\"summary\":\"original failure\",\"diagnostics\":[{\"id\":\"native_backend_unavailable\",\"message\":\"control_file_mismatch path=dev/null expected=0 observed=20\"}]}");
    const report = try fixture.run("failure");
    try std.testing.expectEqual(@as(u8, 0), report.collector_exit);
    try std.testing.expectEqual(@as(u8, 8), report.outcome.exit_status);
    try std.testing.expectEqualStrings("install", report.outcome.operation);
    try std.testing.expectEqualStrings("create", report.outcome.stage.?);
    try std.testing.expect(report.outcome.changed.?);
    try std.testing.expectEqualStrings("native_backend_unavailable", report.outcome.diagnostics[0].object.get("id").?.string);
}

test "native outcome distinguishes command result, verification and failed postconditions" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for ([_]struct { stage: []const u8, result: []const u8, command: u8, wrapper: u8 }{
        .{ .stage = "update", .result = "{\"operation\":\"upgrade-all\",\"exit_status\":8,\"changed\":false,\"summary\":\"update\",\"diagnostics\":[]}", .command = 8, .wrapper = 8 },
        .{ .stage = "create-summary", .result = "{\"backend\":\"native\",\"outcome\":\"failed\"}", .command = 7, .wrapper = 7 },
        .{ .stage = "update", .result = "{\"operation\":\"upgrade-all\",\"exit_status\":0,\"changed\":false,\"summary\":\"update\",\"diagnostics\":[]}", .command = 0, .wrapper = 90 },
        .{ .stage = "update", .result = "{\"operation\":\"upgrade-all\",\"exit_status\":0,\"changed\":false,\"summary\":\"update\",\"diagnostics\":[]}", .command = 0, .wrapper = 0 },
    }) |case| {
        try fixture.attempt(case.stage, case.command, case.wrapper, case.result);
        const report = try fixture.run("failure");
        try std.testing.expectEqual(@as(u8, 0), report.collector_exit);
        try std.testing.expectEqual(if (case.wrapper == 0) @as(u8, 1) else case.wrapper, report.outcome.exit_status);
        try std.testing.expectEqual(case.command, report.outcome.command_exit_status.?);
        if (std.mem.eql(u8, case.stage, "create-summary")) try std.testing.expectEqual(null, report.outcome.result_exit_status);
    }
}

test "native outcome requires wrapper and workflow completion for expected invalid-lock refusal" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const result = "{\"operation\":\"plan\",\"exit_status\":5,\"changed\":false,\"summary\":\"refused\",\"diagnostics\":[]}";
    try fixture.attempt("injected-failure", 5, 0, result);
    const completed = try fixture.run("success");
    try std.testing.expectEqual(@as(u8, 0), completed.outcome.exit_status);
    try std.testing.expect(completed.outcome.expected_refusal);
    try std.testing.expectEqual(@as(u8, 5), completed.outcome.command_exit_status.?);
    try fixture.attempt("injected-failure", 5, 1, result);
    const failed = try fixture.run("failure");
    try std.testing.expectEqual(@as(u8, 1), failed.outcome.exit_status);
    try std.testing.expect(failed.outcome.expected_refusal);
    for ([_][]const u8{ "success", "skipped", "unavailable" }) |workflow| {
        const refused = try fixture.run(workflow);
        try std.testing.expectEqual(@as(u8, 1), refused.collector_exit);
        try std.testing.expect(refused.outcome.exit_status != 0);
    }
}

test "native outcome refuses missing corrupt unsafe or mismatched latest results without refresh fallback" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.attempt("update", 1, 1, "{}");
    for ([_][]const u8{ "", "{broken", "null", "[]", "{}", "{\"operation\":\"upgrade-all\",\"exit_status\":false,\"changed\":false,\"summary\":\"bad\",\"diagnostics\":[]}", "{\"operation\":\"refresh\",\"exit_status\":1,\"changed\":false,\"summary\":\"wrong\",\"diagnostics\":[]}" }) |bytes| {
        try fixture.write("update.json", bytes);
        const report = try fixture.run("failure");
        try std.testing.expectEqual(@as(u8, 1), report.collector_exit);
        try std.testing.expectEqualStrings("update", report.outcome.stage.?);
        try std.testing.expectEqualStrings("upgrade-all", report.outcome.operation);
        try std.testing.expect(!report.outcome.result_available);
        try std.testing.expectEqualStrings("native_acceptance_evidence_invalid", report.outcome.diagnostics[0].object.get("id").?.string);
    }
    var root = try fs.openAbsoluteRoot(std.testing.io, fixture.path);
    defer root.close();
    try root.root.removeFile(try fs.Path.init("update.json"));
    const missing = try fixture.run("failure");
    try std.testing.expectEqualStrings("native_acceptance_evidence_unavailable", missing.outcome.diagnostics[0].object.get("id").?.string);
    try fixture.write("refresh.json", "{}");
    try root.root.createSymbolicLink(try fs.Path.init("update.json"), "refresh.json");
    const unsafe = try fixture.run("failure");
    try std.testing.expectEqual(@as(u8, 1), unsafe.collector_exit);
    try std.testing.expect(!unsafe.outcome.result_available);
}

test "native outcome marks missing command receipt or stage unavailable and refuses malformed wrapper status" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.attempt("create", null, null, "{\"operation\":\"install\",\"exit_status\":0,\"changed\":false,\"summary\":\"install\",\"diagnostics\":[]}");
    const unrecorded = try fixture.run("cancelled");
    try std.testing.expect(unrecorded.outcome.result_available);
    try std.testing.expectEqualStrings("native_acceptance_evidence_unavailable", unrecorded.outcome.diagnostics[0].object.get("id").?.string);
    try fixture.write("native-wrapper-exit-status.txt", "256\n");
    const malformed = try fixture.run("failure");
    try std.testing.expectEqual(@as(u8, 1), malformed.collector_exit);
    try std.testing.expect(!malformed.outcome.result_available);
    var root = try fs.openAbsoluteRoot(std.testing.io, fixture.path);
    defer root.close();
    try root.root.removeFile(try fs.Path.init("native-stage-v1.json"));
    const missing = try fixture.run("failure");
    try std.testing.expectEqual(null, missing.outcome.stage);
    try std.testing.expectEqualStrings("native", missing.outcome.operation);
}

test "native outcome refuses duplicate fields hardlinks oversized markers and excessive nesting" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const result = "{\"operation\":\"install\",\"exit_status\":0,\"changed\":false,\"summary\":\"install\",\"diagnostics\":[]}";
    try fixture.attempt("create", 0, 0, result);
    try fixture.write("create.json", "{\"operation\":\"install\",\"exit_status\":0,\"exit_status\":8,\"changed\":false,\"summary\":\"install\",\"diagnostics\":[]}");
    const duplicate = try fixture.run("failure");
    try std.testing.expectEqual(@as(u8, 1), duplicate.collector_exit);
    try std.testing.expect(!duplicate.outcome.result_available);
    try fixture.write("create.json", result);
    var root = try fs.openAbsoluteRoot(std.testing.io, fixture.path);
    defer root.close();
    try root.root.createHardLink(try fs.Path.init("create.json"), try fs.Path.init("alias.json"));
    const linked = try fixture.run("failure");
    try std.testing.expectEqualStrings("HardLinkedOutcomeEvidence", linked.outcome.diagnostics[0].object.get("message").?.string);
    try root.root.removeFile(try fs.Path.init("alias.json"));
    try fixture.write("native-stage-v1.json", " " ** 4097);
    const oversized = try fixture.run("failure");
    try std.testing.expectEqual(@as(u8, 1), oversized.collector_exit);
    try std.testing.expectEqual(null, oversized.outcome.stage);
    try fixture.attempt("create", 0, 0, "[" ** 65 ++ "0" ++ "]" ** 65);
    const deep = try fixture.run("failure");
    try std.testing.expectEqualStrings("OutcomeDepthExceeded", deep.outcome.diagnostics[0].object.get("message").?.string);
    try std.testing.expect(!deep.outcome.result_available);
}

test "native outcome preserves numeric diagnostics and refuses noninteger command exits" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.attempt("create", 8, 8, "{\"operation\":\"install\",\"exit_status\":8,\"changed\":true,\"summary\":\"original\",\"diagnostics\":[{\"integer\":184467440737095516160123456789,\"decimal\":1.0,\"scientific\":1e+99}]}");
    const report = try fixture.run("failure");
    try std.testing.expectEqual(@as(u8, 0), report.collector_exit);
    const numeric = report.outcome.diagnostics[0].object;
    try std.testing.expectEqualStrings("184467440737095516160123456789", numeric.get("integer").?.number_string);
    try std.testing.expectEqualStrings("1.0", numeric.get("decimal").?.number_string);
    try std.testing.expectEqualStrings("1e+99", numeric.get("scientific").?.number_string);
    for ([_][]const u8{ "false", "1.0", "1e0", "-1", "256" }) |status| {
        try fixture.write("native-stage-v1.json", try std.fmt.allocPrint(fixture.arena.allocator(), "{{\"stage\":\"create\",\"command_exit_status\":{s}}}", .{status}));
        const invalid_status = try fixture.run("failure");
        try std.testing.expectEqual(@as(u8, 1), invalid_status.collector_exit);
        try std.testing.expectEqualStrings("InvalidExitStatus", invalid_status.outcome.diagnostics[0].object.get("message").?.string);
    }
    try fixture.write("native-stage-v1.json", "{\"stage\":\"create\",\"command_exit_status\":-0}");
    const negative_zero = try fixture.run("failure");
    try std.testing.expectEqual(@as(u8, 0), negative_zero.collector_exit);
    try std.testing.expectEqual(@as(u8, 0), negative_zero.outcome.command_exit_status.?);
}

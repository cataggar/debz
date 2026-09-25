const std = @import("std");

pub const ScriptInvocation = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    kind: []const u8,
    source: []const u8,
    arguments: []const []const u8,
    environment: []const EnvironmentEntry,
    script_sha256: [64]u8,
    invocation_sha256: [64]u8,
};

pub const EnvironmentEntry = @import("debz").native_recovery.EnvironmentEntry;

fn hashText(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, value.len, .little);
    hash.update(&length);
    hash.update(value);
}

pub fn helperInvocationDigest(
    root: []const u8,
    helper_source: []const u8,
    helper_target: []const u8,
    helper_sha256: [64]u8,
    policy_sha256: [64]u8,
    script: ScriptInvocation,
    path: []const u8,
) ![64]u8 {
    var script_hash: [32]u8 = undefined;
    var helper_hash: [32]u8 = undefined;
    var policy_hash: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&script_hash, &script.script_sha256) catch return error.InvalidScriptBinding;
    _ = std.fmt.hexToBytes(&helper_hash, &helper_sha256) catch return error.InvalidScriptBinding;
    _ = std.fmt.hexToBytes(&policy_hash, &policy_sha256) catch return error.InvalidScriptBinding;
    var argv = std.crypto.hash.sha2.Sha256.init(.{});
    argv.update("debz-maintainer-script-argv-v1\x00");
    var absolute_path: [4096]u8 = undefined;
    if (path.len + 1 > absolute_path.len) return error.InvalidScriptBinding;
    absolute_path[0] = '/';
    @memcpy(absolute_path[1 .. path.len + 1], path);
    hashText(&argv, absolute_path[0 .. path.len + 1]);
    for (script.arguments) |argument| hashText(&argv, argument);
    var env = std.crypto.hash.sha2.Sha256.init(.{});
    env.update("debz-maintainer-script-environment-v1\x00");
    for (script.environment) |entry| {
        hashText(&env, entry.key);
        hashText(&env, entry.value);
    }
    var invocation = std.crypto.hash.sha2.Sha256.init(.{});
    invocation.update("debz-maintainer-script-invocation-v1\x00");
    for ([_][]const u8{ root, "chroot", script.package, script.version, script.architecture, script.kind, path }) |value| hashText(&invocation, value);
    invocation.update(&script_hash);
    const argv_hash = argv.finalResult();
    invocation.update(&argv_hash);
    const env_hash = env.finalResult();
    invocation.update(&env_hash);
    invocation.update(&policy_hash);
    invocation.update("debz-maintainer-script-helper-mount-v1\x00");
    hashText(&invocation, helper_source);
    hashText(&invocation, helper_target);
    invocation.update(&helper_hash);
    return std.fmt.bytesToHex(invocation.finalResult(), .lower);
}

pub fn validateHelperInvocation(
    allocator: std.mem.Allocator,
    root: []const u8,
    helper_source: []const u8,
    helper_target: []const u8,
    helper_sha256: [64]u8,
    policy_sha256: [64]u8,
    script: ScriptInvocation,
) !void {
    const staged = if (std.mem.eql(u8, script.source, "new_package")) script.package else try std.fmt.allocPrint(allocator, "{s}:{s}", .{ script.package, script.architecture });
    defer if (!std.mem.eql(u8, script.source, "new_package")) allocator.free(staged);
    for (0..3) |index| {
        const candidate = switch (index) {
            0 => try std.fmt.allocPrint(allocator, "var/lib/debz-lifecycle-scripts/{s}.{s}", .{ staged, script.kind }),
            1 => try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}.{s}", .{ script.package, script.kind }),
            else => try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}:{s}.{s}", .{ script.package, script.architecture, script.kind }),
        };
        defer allocator.free(candidate);
        const digest = try helperInvocationDigest(root, helper_source, helper_target, helper_sha256, policy_sha256, script, candidate);
        if (std.mem.eql(u8, &digest, &script.invocation_sha256)) return;
    }
    return error.ScriptHelperBindingMismatch;
}

pub fn validateScriptTrace(allocator: std.mem.Allocator, trace: []const u8, scripts: []const ScriptInvocation) !void {
    const lines_without_terminator = if (std.mem.endsWith(u8, trace, "\n")) trace[0 .. trace.len - 1] else trace;
    var lines = std.mem.splitScalar(u8, lines_without_terminator, '\n');
    for (scripts) |script| {
        const line = lines.next() orelse return error.ScriptTraceMismatch;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const identity = try std.fmt.allocPrint(allocator, "{s}@{s}:{s}", .{ script.package, script.version, script.kind });
        defer allocator.free(identity);
        for ([_][]const u8{ identity, script.package, script.kind, script.architecture }) |expected|
            if (!std.mem.eql(u8, fields.next() orelse return error.ScriptTraceMismatch, expected))
                return error.ScriptTraceMismatch;
        const count = std.fmt.parseUnsigned(usize, fields.next() orelse return error.ScriptTraceMismatch, 10) catch
            return error.ScriptTraceMismatch;
        if (count != script.arguments.len) return error.ScriptTraceMismatch;
        for (script.arguments) |argument| {
            const encoded = try std.fmt.allocPrint(allocator, "{d}:{s}", .{ argument.len, argument });
            defer allocator.free(encoded);
            if (!std.mem.eql(u8, fields.next() orelse return error.ScriptTraceMismatch, encoded))
                return error.ScriptTraceMismatch;
        }
        if (!std.mem.startsWith(u8, fields.next() orelse return error.ScriptTraceMismatch, "payload=") or
            fields.next() != null) return error.ScriptTraceMismatch;
    }
    if (lines.next() != null or (scripts.len == 0 and trace.len != 0))
        return error.ScriptTraceMismatch;
}

pub const RollbackEntry = struct {
    path: []const u8,
    kind: enum { symlink, regular, directory },
    modified_nanoseconds: i128,
};

pub const RollbackTime = struct {
    path: []const u8,
    original_nanoseconds: ?i128,
};

pub fn normalizeRollbackTimes(
    entries: []RollbackEntry,
    recorded: []const RollbackTime,
    started: i128,
    ended: i128,
    require_clock: bool,
) !void {
    for (recorded) |original| {
        const entry = for (entries) |*item| {
            if (std.mem.eql(u8, item.path, original.path)) break item;
        } else return error.MissingRollbackPath;
        if (entry.kind != .symlink) return error.RollbackChangedSymlinkType;
        const time = entry.modified_nanoseconds;
        if (!(time >= started and time <= ended) and
            (require_clock or original.original_nanoseconds == null or
                time != original.original_nanoseconds.?))
            return error.UnexpectedRollbackSymlinkTimestamp;
        entry.modified_nanoseconds = original.original_nanoseconds orelse 0;
    }
}

pub const parity_suites = [_][]const u8{ "debian-stable", "ubuntu-26.04" };

pub const ParityCase = struct {
    id: []const u8,
    package: ?[]const u8,
    archives: []const []const u8,
    seeds: []const []const u8 = &.{},
    reference_phases: []const []const []const u8 = &.{},
    recommends: bool = false,
    update: bool = false,
    hold: ?[]const u8 = null,
    conffile: ?[]const u8 = null,
    exit_status: u8 = 0,
};

pub const parity_cases = [_]ParityCase{
    .{ .id = "pre-depends", .package = "pre-app", .archives = &.{ "base-dep", "pre-app" }, .reference_phases = &.{ &.{"base-dep"}, &.{"pre-app"} } },
    .{ .id = "virtual-provides", .package = "virtual-consumer", .archives = &.{ "virtual-provider=2.0-1", "virtual-consumer" } },
    .{ .id = "dependency-cycle", .package = "cycle-a", .archives = &.{ "cycle-a", "cycle-b" } },
    .{ .id = "without-recommends", .package = "scenario-main", .archives = &.{ "base-dep", "scenario-main" } },
    .{ .id = "with-recommends", .package = "scenario-main", .archives = &.{ "base-dep", "recommended-addon", "scenario-main" }, .recommends = true },
    .{ .id = "multiarch-package", .package = "multi-lib", .archives = &.{"multi-lib"} },
    .{ .id = "literal-package-paths", .package = "literal-paths-pkg", .archives = &.{"literal-paths-pkg"} },
    .{ .id = "retained-metadata", .package = "retained-metadata-pkg", .archives = &.{"retained-metadata-pkg"} },
    .{ .id = "suite-trigger", .package = "trigger-pkg", .archives = &.{"trigger-pkg"} },
    .{ .id = "upgrade-all", .package = null, .archives = &.{"fixture-upgrade=2.0-1"}, .seeds = &.{"fixture-upgrade"}, .update = true },
    .{ .id = "held-unchanged", .package = null, .archives = &.{}, .seeds = &.{"fixture-upgrade"}, .update = true, .hold = "fixture-upgrade" },
    .{ .id = "conffile-keep", .package = "conffile-pkg", .archives = &.{"conffile-pkg"}, .conffile = "keep_existing" },
    .{ .id = "conffile-replace", .package = "conffile-pkg", .archives = &.{"conffile-pkg"}, .conffile = "use_package_version" },
    .{ .id = "known-script-failure", .package = "fail-script", .archives = &.{"fail-script"}, .exit_status = 7 },
};

pub const ParityRow = struct {
    suite: []const u8,
    case_id: []const u8,
    architecture: []const u8,
    consumers: []const []const u8,
    matched: bool,
};

pub const parity_consumers = [_][]const u8{ "core-cli", "family", "dpkg-reference" };

pub fn validateConsumerParity(rows: []const ParityRow, architecture: []const u8) !void {
    if (rows.len != parity_suites.len * parity_cases.len)
        return error.IncompleteOrDuplicatedConsumerParity;
    for (parity_suites) |suite| for (parity_cases) |case| {
        var seen: usize = 0;
        for (rows) |row|
            if (std.mem.eql(u8, row.suite, suite) and std.mem.eql(u8, row.case_id, case.id)) {
                seen += 1;
            };
        if (seen != 1) return error.IncompleteOrDuplicatedConsumerParity;
    };
    if (!std.mem.eql(u8, architecture, "amd64") and !std.mem.eql(u8, architecture, "arm64"))
        return error.ConsumerParityMismatch;
    for (rows) |row| {
        if (!std.mem.eql(u8, row.architecture, architecture) or
            !row.matched or row.consumers.len != parity_consumers.len)
            return error.ConsumerParityMismatch;
        for (row.consumers, parity_consumers) |observed, expected| {
            if (!std.mem.eql(u8, observed, expected)) return error.ConsumerParityMismatch;
        }
    }
}

fn handlerSchemaField(object: std.json.Value, name: []const u8) !std.json.Value {
    if (object != .object) return error.InvalidHandlerSchema;
    return object.object.get(name) orelse error.InvalidHandlerSchema;
}

fn handlerSchemaText(object: std.json.Value, name: []const u8) ![]const u8 {
    const value = try handlerSchemaField(object, name);
    if (value != .string) return error.InvalidHandlerSchema;
    return value.string;
}

pub fn validateHandlerSchemaDefinition(allocator: std.mem.Allocator, bytes: []const u8, definition: []const u8) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch
        return error.InvalidHandlerSchema;
    defer parsed.deinit();
    const definitions = try handlerSchemaField(parsed.value, "$defs");
    const digest = try handlerSchemaField(definitions, "sha256");
    if (!std.mem.eql(u8, try handlerSchemaText(digest, "pattern"), "^[0-9a-f]{64}$"))
        return error.InvalidHandlerSchema;
    const handler = try handlerSchemaField(definitions, definition);
    const required = try handlerSchemaField(handler, "required");
    const properties = try handlerSchemaField(handler, "properties");
    const additional = try handlerSchemaField(handler, "additionalProperties");
    const names = [_][]const u8{ "package", "source", "postinst_sha256", "declarations_sha256" };
    if (required != .array or required.array.items.len != names.len or
        additional != .bool or additional.bool or properties != .object or
        properties.object.count() != names.len)
        return error.InvalidHandlerSchema;
    for (required.array.items, names) |actual, name| {
        if (actual != .string or !std.mem.eql(u8, actual.string, name))
            return error.InvalidHandlerSchema;
    }
    const postinst = try handlerSchemaField(properties, "postinst_sha256");
    const alternatives = try handlerSchemaField(postinst, "oneOf");
    if (alternatives != .array or alternatives.array.items.len != 2)
        return error.InvalidHandlerSchema;
    if (!std.mem.eql(u8, try handlerSchemaText(alternatives.array.items[0], "$ref"), "#/$defs/sha256") or
        !std.mem.eql(u8, try handlerSchemaText(alternatives.array.items[1], "type"), "null") or
        !std.mem.eql(u8, try handlerSchemaText(try handlerSchemaField(properties, "declarations_sha256"), "$ref"), "#/$defs/sha256"))
        return error.InvalidHandlerSchema;
}

fn validDigest(value: std.json.Value) bool {
    if (value != .string or value.string.len != 64) return false;
    for (value.string) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

pub fn validateHandler(value: std.json.Value) !void {
    if (value != .object or value.object.count() != 4)
        return error.InvalidTriggerHandler;
    const package = value.object.get("package") orelse return error.InvalidTriggerHandler;
    if (package != .object or package.object.count() != 3)
        return error.InvalidTriggerHandler;
    for ([_][]const u8{ "name", "version", "architecture" }) |key| {
        const field = package.object.get(key) orelse return error.InvalidTriggerHandler;
        if (field != .string or field.string.len == 0) return error.InvalidTriggerHandler;
    }
    const source = value.object.get("source") orelse return error.InvalidTriggerHandler;
    if (source != .string or
        (!std.mem.eql(u8, source.string, "installed_package") and !std.mem.eql(u8, source.string, "new_package")))
        return error.InvalidTriggerHandler;
    const script = value.object.get("postinst_sha256") orelse return error.InvalidTriggerHandler;
    if (script != .null and !validDigest(script)) return error.InvalidTriggerHandler;
    if (!validDigest(value.object.get("declarations_sha256") orelse return error.InvalidTriggerHandler))
        return error.InvalidTriggerHandler;
}

fn diagnosticField(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidDiagnosticInspection;
    return value.object.get(name) orelse error.InvalidDiagnosticInspection;
}

fn diagnosticString(value: std.json.Value, name: []const u8) ![]const u8 {
    const field = try diagnosticField(value, name);
    if (field != .string) return error.InvalidDiagnosticInspection;
    return field.string;
}

pub fn validateDiagnosticInspection(report: std.json.Value, evidence: std.json.Value, expected_root: []const u8) !std.json.Value {
    const schema = try diagnosticString(report, "schema");
    if (!std.mem.eql(u8, schema, "io.github.cataggar.debz.package-family.result.v2") or
        (try diagnosticField(report, "version")) != .integer or
        (try diagnosticField(report, "version")).integer != 2 or
        !std.mem.eql(u8, try diagnosticString(report, "operation"), "inspect") or
        !std.meta.eql(try diagnosticField(report, "succeeded"), std.json.Value{ .bool = true }) or
        !std.mem.eql(u8, try diagnosticString(report, "exit_status"), "success") or
        !std.meta.eql(try diagnosticField(report, "changed"), std.json.Value{ .bool = false }) or
        (try diagnosticField(report, "lock_path")) != .null or
        (try diagnosticField(report, "provenance_path")) != .null or
        (try diagnosticField(evidence, "native_install")) != .null or
        (try diagnosticField(evidence, "native_completion")) != .null)
        return error.InvalidDiagnosticInspection;
    const inspection = try diagnosticField(evidence, "native_inspection");
    if (!std.mem.eql(u8, try diagnosticString(inspection, "root"), expected_root) or
        !std.meta.eql(try diagnosticField(inspection, "diagnostic_only"), std.json.Value{ .bool = true }) or
        (try diagnosticField(inspection, "status_database_present")) != .bool or
        (try diagnosticField(inspection, "native_active_evidence")) != .bool)
        return error.InvalidDiagnosticInspection;
    const packages = try diagnosticField(inspection, "packages");
    if (packages != .array) return error.InvalidDiagnosticInspection;
    var previous_name: []const u8 = "";
    var previous_arch: []const u8 = "";
    for (packages.array.items, 0..) |package, index| {
        if (package != .object or package.object.count() != 4)
            return error.InvalidDiagnosticInspection;
        const name = try diagnosticString(package, "name");
        const architecture = try diagnosticString(package, "architecture");
        _ = try diagnosticString(package, "version");
        const status = try diagnosticField(package, "status");
        if (status != .object or status.object.count() != 3)
            return error.InvalidDiagnosticInspection;
        for ([_][]const u8{ "want", "error_state", "current" }) |field|
            _ = try diagnosticString(status, field);
        if (index != 0 and (std.mem.order(u8, previous_name, name) == .gt or
            (std.mem.eql(u8, previous_name, name) and std.mem.order(u8, previous_arch, architecture) != .lt)))
            return error.InvalidDiagnosticInspection;
        previous_name = name;
        previous_arch = architecture;
    }
    return inspection;
}

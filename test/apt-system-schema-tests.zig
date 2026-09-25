const std = @import("std");
const validator = @import("apt-system-schema-validator.zig");

const allocator = std.testing.allocator;
const Store = validator.Store;
const v2_profile =
    \\{"schema":"https://debz.dev/schema/system-profile-v2","version":2,"transaction_backend":"native","repositories":[{"source_path":"/etc/debz/repository.sources"}],"keyring_paths":["/etc/debz/keyring.gpg"],"architecture":"amd64"}
;
const operation_state =
    \\{"schema":"https://debz.dev/schema/apt-system-operation-state-v1","version":1,"attempt_id":"1111111111111111111111111111111111111111111111111111111111111111","generation":2,"operation":"install","phase":"executing","mutation_started":false,"outcome":"pending","request_sha256":"1111111111111111111111111111111111111111111111111111111111111111","profile":null,"exact_lock":null,"transaction_result":null,"root_operation_completion":null,"updated_unix":1800000000,"diagnostic":"","digest_sha256":"6666666666666666666666666666666666666666666666666666666666666666"}
;

fn fixture(path: []const u8) !std.json.Parsed(std.json.Value) {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(1024 * 1024));
    defer allocator.free(bytes);
    return std.json.parseFromSlice(std.json.Value, allocator, bytes, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
    });
}

fn put(object: *std.json.Value, name: []const u8, value: std.json.Value) !void {
    const target = object.object.getPtr(name) orelse return error.MissingField;
    target.* = value;
}

fn add(object: *std.json.Value, arena: std.mem.Allocator, name: []const u8, value: std.json.Value) !void {
    try object.object.put(arena, name, value);
}

fn remove(object: *std.json.Value, name: []const u8) void {
    _ = object.object.swapRemove(name);
}

fn field(object: *std.json.Value, name: []const u8) *std.json.Value {
    return object.object.getPtr(name).?;
}

fn valid(store: *Store, name: []const u8, value: std.json.Value) !void {
    try std.testing.expect(try store.validValue(name, value));
}

fn invalid(store: *Store, name: []const u8, value: std.json.Value) !void {
    try std.testing.expect(!try store.validValue(name, value));
}

fn rejectClosedFields(store: *Store, name: []const u8, document: *std.json.Parsed(std.json.Value), required: []const u8) !void {
    try valid(store, name, document.value);
    const original = try std.json.Stringify.valueAlloc(allocator, document.value, .{});
    defer allocator.free(original);
    const marker = "\"schema\":";
    const offset = std.mem.indexOf(u8, original, marker) orelse return error.InvalidFixture;
    const duplicate = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{
        original[0..offset], marker ++ "\"duplicate\",", original[offset..],
    });
    defer allocator.free(duplicate);
    try std.testing.expectError(error.DuplicateField, store.valid(name, duplicate));
    try add(&document.value, document.arena.allocator(), "unknown_field", .null);
    try invalid(store, name, document.value);
    remove(&document.value, "unknown_field");
    const old = field(&document.value, required).*;
    try put(&document.value, required, .{ .bool = true });
    try invalid(store, name, document.value);
    remove(&document.value, required);
    try invalid(store, name, document.value);
    try add(&document.value, document.arena.allocator(), required, old);
    try valid(store, name, document.value);
}

test "apt schema security manifests select six tests exactly once" {
    const build = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "build.zig", allocator, .limited(256 * 1024));
    defer allocator.free(build);
    for ([_][]const u8{
        ".filters = &.{\"production workflow required_security.\"}",
        ".filters = &.{\"apt_system_orchestrator.test.required_security.\"}",
    }) |selection| try std.testing.expect(std.mem.indexOf(u8, build, selection) != null);

    const cases = .{
        .{ "src/production_backend.zig", .{
            "production workflow required_security.ownership finalization rejects a valid colliding v2 owner",
            "production workflow required_security.restart requires the authenticated exact v2 owner",
        } },
        .{ "src/apt_system_orchestrator.zig", .{
            "apt_system_orchestrator.test.required_security.valid v2 prior collision makes concurrent review publication stale",
            "apt_system_orchestrator.test.required_security.restart authenticates durable lower ownership token before review",
            "apt_system_orchestrator.test.required_security.restart cancellation requires fully verified exact owner",
            "apt_system_orchestrator.test.required_security.recovery transport failure preserves lower token for retry without second mutation",
        } },
    };
    inline for (cases) |case| {
        const source = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, case[0], allocator, .limited(4 * 1024 * 1024));
        defer allocator.free(source);
        inline for (case[1]) |name| {
            const needle = "test \"" ++ name ++ "\"";
            try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, source, needle));
        }
    }
}

test "system profile v1 and v2 backend compatibility and strict paths" {
    var store = try Store.init(allocator);
    defer store.deinit();
    const backend_cases = [_][]const u8{ "legacy_dpkg", "native" };
    for (backend_cases) |backend| {
        var v2 = try std.json.parseFromSlice(std.json.Value, allocator, v2_profile, .{ .allocate = .alloc_always });
        defer v2.deinit();
        try put(&v2.value, "transaction_backend", .{ .string = backend });
        try valid(&store, "system-profile-v2", v2.value);
        try put(&v2.value, "schema", .{ .string = "https://debz.dev/schema/system-profile-v1" });
        try put(&v2.value, "version", .{ .integer = 1 });
        try invalid(&store, "system-profile-v1", v2.value);
        remove(&v2.value, "transaction_backend");
        try valid(&store, "system-profile-v1", v2.value);
        try invalid(&store, "system-profile-v2", v2.value);
    }
    for ([_][]const u8{ "auto", "NATIVE", "" }) |backend| {
        var v2 = try std.json.parseFromSlice(std.json.Value, allocator, v2_profile, .{ .allocate = .alloc_always });
        defer v2.deinit();
        try put(&v2.value, "transaction_backend", .{ .string = backend });
        try invalid(&store, "system-profile-v2", v2.value);
    }
    for ([_][]const u8{ "/", "/a/../b", "/a//b", "/a\\b", "/a/\x1f" }) |path| {
        var v2 = try std.json.parseFromSlice(std.json.Value, allocator, v2_profile, .{ .allocate = .alloc_always });
        defer v2.deinit();
        try add(&v2.value, v2.arena.allocator(), "state_path", .{ .string = path });
        try invalid(&store, "system-profile-v2", v2.value);
    }
    for ([_][]const u8{ "install_root", "cache_path" }) |key| {
        var v2 = try std.json.parseFromSlice(std.json.Value, allocator, v2_profile, .{ .allocate = .alloc_always });
        defer v2.deinit();
        try add(&v2.value, v2.arena.allocator(), key, .{ .string = "/" });
        try invalid(&store, "system-profile-v2", v2.value);
    }
    {
        var v2 = try std.json.parseFromSlice(std.json.Value, allocator, v2_profile, .{ .allocate = .alloc_always });
        defer v2.deinit();
        try put(&v2.value, "transaction_backend", .null);
        try invalid(&store, "system-profile-v2", v2.value);
        try put(&v2.value, "transaction_backend", .{ .string = "native" });
        field(&v2.value, "keyring_paths").array.items[0] = .{ .string = "/a//b" };
        try invalid(&store, "system-profile-v2", v2.value);
        field(&v2.value, "keyring_paths").array.items[0] = .{ .string = "/etc/debz/keyring.gpg" };
        try put(&v2.value, "version", .{ .integer = 1 });
        try invalid(&store, "system-profile-v2", v2.value);
    }
}

test "historical request and v2 schema and document remain compatible" {
    var store = try Store.init(allocator);
    defer store.deinit();
    for ([_]struct { source: []const u8, frozen: []const u8, document: []const u8, name: []const u8, old: []const u8 }{
        .{ .source = "schema/apt-system-request-v1.json", .frozen = "tools/fixtures/apt-system-request-v1-origin-main.schema.json", .document = "tools/fixtures/apt-system-request-v1-origin-main.document.json", .name = "apt-system-request-v1", .old = "frozen-request-v1" },
        .{ .source = "schema/apt-system-result-v2.json", .frozen = "tools/fixtures/apt-system-result-v2-origin-main.schema.json", .document = "tools/fixtures/apt-system-result-v2-origin-main.document.json", .name = "apt-system-result-v2", .old = "frozen-result-v2" },
    }) |case| {
        var source = try fixture(case.source);
        defer source.deinit();
        var frozen = try fixture(case.frozen);
        defer frozen.deinit();
        const normalized_source = try std.json.Stringify.valueAlloc(allocator, source.value, .{});
        defer allocator.free(normalized_source);
        const normalized_frozen = try std.json.Stringify.valueAlloc(allocator, frozen.value, .{});
        defer allocator.free(normalized_frozen);
        try std.testing.expectEqualStrings(normalized_source, normalized_frozen);
        var document = try fixture(case.document);
        defer document.deinit();
        try valid(&store, case.name, document.value);
        try valid(&store, case.old, document.value);
        if (std.mem.eql(u8, case.name, "apt-system-result-v2")) {
            try invalid(&store, "apt-system-result-v3", document.value);
            try add(&document.value, document.arena.allocator(), "mutation_status", .{ .string = "unchanged" });
            try invalid(&store, case.name, document.value);
            try invalid(&store, case.old, document.value);
            try invalid(&store, "apt-system-result-v3", document.value);
        } else {
            for ([_][]const u8{ "+alpha", ".alpha", ":alpha", "=alpha" }) |package| {
                field(&document.value, "packages").array.items[0] = .{ .string = package };
                try valid(&store, case.name, document.value);
                try valid(&store, case.old, document.value);
            }
        }
    }
}

test "result v1 keeps its strict historical shape" {
    var store = try Store.init(allocator);
    defer store.deinit();
    var list = try fixture("tools/fixtures/apt-system-result-v2-origin-main.document.json");
    defer list.deinit();
    remove(&list.value, "items");
    try put(&list.value, "schema", .{ .string = "https://debz.dev/schema/apt-system-result-v1" });
    try put(&list.value, "version", .{ .integer = 1 });
    try valid(&store, "apt-system-result-v1", list.value);
    try invalid(&store, "apt-system-result-v2", list.value);
    try add(&list.value, list.arena.allocator(), "items", .null);
    try invalid(&store, "apt-system-result-v1", list.value);
}

test "canonical v3 confirmation and unknown examples enforce conditional evidence" {
    var store = try Store.init(allocator);
    defer store.deinit();
    var confirmation = try fixture("tools/fixtures/apt-system-result-v3-confirmation.document.json");
    defer confirmation.deinit();
    try valid(&store, "apt-system-result-v3", confirmation.value);
    try invalid(&store, "apt-system-result-v2", confirmation.value);
    const diagnostic = &field(&confirmation.value, "diagnostics").array.items[0];
    try put(diagnostic, "phase", .{ .string = "request" });
    try invalid(&store, "apt-system-result-v3", confirmation.value);
    try put(diagnostic, "phase", .{ .string = "confirmation" });
    var extra = try std.json.parseFromSlice(std.json.Value, allocator,
        \\{"id":"invalid_request","outcome":"usage","phase":"request","message":"extra diagnostic"}
    , .{});
    defer extra.deinit();
    try field(&confirmation.value, "diagnostics").array.append(extra.value);
    try invalid(&store, "apt-system-result-v3", confirmation.value);
    _ = field(&confirmation.value, "diagnostics").array.pop();
    try field(&confirmation.value, "diagnostics").array.append(diagnostic.*);
    try invalid(&store, "apt-system-result-v3", confirmation.value);
    _ = field(&confirmation.value, "diagnostics").array.pop();
    try valid(&store, "apt-system-result-v3", confirmation.value);
    try put(field(&confirmation.value, "evidence"), "active_operation_state", .{ .string = "/state/apt/active-operation-v1.json" });
    try valid(&store, "apt-system-result-v3", confirmation.value);
    remove(&confirmation.value, "items");
    try put(&confirmation.value, "outcome", .{ .string = "success" });
    try put(&confirmation.value, "exit_status", .{ .integer = 0 });
    field(&confirmation.value, "diagnostics").array.clearRetainingCapacity();
    try valid(&store, "apt-system-result-v3", confirmation.value);
    for ([_][]const u8{ "exact_lock", "active_operation_state" }) |missing| {
        const evidence = field(&confirmation.value, "evidence");
        const previous = field(evidence, missing).*;
        try put(evidence, missing, .null);
        try invalid(&store, "apt-system-result-v3", confirmation.value);
        try put(evidence, missing, previous);
    }
    try put(&confirmation.value, "changed", .{ .bool = true });
    try invalid(&store, "apt-system-result-v3", confirmation.value);
    try put(&confirmation.value, "changed", .{ .bool = false });
    try put(field(&confirmation.value, "evidence"), "transaction_result", field(field(&confirmation.value, "evidence"), "exact_lock").*);
    try invalid(&store, "apt-system-result-v3", confirmation.value);
    var unknown = try fixture("tools/fixtures/apt-system-result-v3-unknown.document.json");
    defer unknown.deinit();
    try valid(&store, "apt-system-result-v3", unknown.value);
    try put(field(&unknown.value, "recovery_context"), "requested_operation", .null);
    try valid(&store, "apt-system-result-v3", unknown.value);
    try put(&unknown.value, "profile", field(&confirmation.value, "profile").*);
    try invalid(&store, "apt-system-result-v3", unknown.value);
    try put(&unknown.value, "profile", .null);
    try put(field(&unknown.value, "recovery_context"), "action", .{ .string = "debz recover --system-profile /profile.json" });
    try invalid(&store, "apt-system-result-v3", unknown.value);
    try put(field(&unknown.value, "recovery_context"), "action", .null);
    try put(&field(&unknown.value, "diagnostics").array.items[0], "phase", .{ .string = "state" });
    try invalid(&store, "apt-system-result-v3", unknown.value);
}

test "operation state executing and unchanged cannot claim mutation or lose lock" {
    var store = try Store.init(allocator);
    defer store.deinit();
    var example = try fixture("tools/fixtures/apt-system-result-v3-confirmation.document.json");
    defer example.deinit();
    var state = try std.json.parseFromSlice(std.json.Value, allocator, operation_state, .{ .allocate = .alloc_always });
    defer state.deinit();
    try put(&state.value, "profile", field(&example.value, "profile").*);
    try put(&state.value, "exact_lock", field(field(&example.value, "evidence"), "exact_lock").*);
    try valid(&store, "apt-system-operation-state-v1", state.value);
    try put(&state.value, "operation", .{ .string = "update" });
    try invalid(&store, "apt-system-operation-state-v1", state.value);
    try put(&state.value, "operation", .{ .string = "install" });
    try put(&state.value, "phase", .{ .string = "completed" });
    try put(&state.value, "outcome", .{ .string = "unchanged" });
    try put(&state.value, "generation", .{ .integer = 3 });
    try put(&state.value, "diagnostic", .{ .string = "native transaction has no package changes" });
    try valid(&store, "apt-system-operation-state-v1", state.value);
    try put(&state.value, "mutation_started", .{ .bool = true });
    try invalid(&store, "apt-system-operation-state-v1", state.value);
    try put(&state.value, "mutation_started", .{ .bool = false });
    try put(&state.value, "exact_lock", .null);
    try invalid(&store, "apt-system-operation-state-v1", state.value);
    try put(&state.value, "exact_lock", field(field(&example.value, "evidence"), "exact_lock").*);
    try put(&state.value, "transaction_result", field(&state.value, "exact_lock").*);
    try invalid(&store, "apt-system-operation-state-v1", state.value);
    try put(&state.value, "transaction_result", .null);
    try put(&state.value, "operation", .{ .string = "update" });
    try invalid(&store, "apt-system-operation-state-v1", state.value);
}

test "request and result package contracts distinguish leading punctuation and reject invalid bytes" {
    var store = try Store.init(allocator);
    defer store.deinit();
    var request = try fixture("tools/fixtures/apt-system-request-v1-origin-main.document.json");
    defer request.deinit();
    var result = try fixture("tools/fixtures/apt-system-result-v2-origin-main.document.json");
    defer result.deinit();
    const long = "a" ** 256;
    for ([_][]const u8{ "+", ".", ":", "=", "a", "Z", "0", "a+", "a-", "a.", "a:", "a=", "-", "é", "\x1f", "a/b", "a_", long[0..] }) |name| {
        field(&request.value, "packages").array.items[0] = .{ .string = name };
        try put(&field(&result.value, "items").array.items[0], "package", .{ .string = name });
        const expected_request = !std.mem.eql(u8, name, "-") and !std.mem.eql(u8, name, "é") and
            !std.mem.eql(u8, name, "\x1f") and !std.mem.eql(u8, name, "a/b") and
            !std.mem.eql(u8, name, "a_") and name.len <= 255;
        const expected_result = expected_request and name.len > 0 and std.ascii.isAlphanumeric(name[0]);
        try std.testing.expectEqual(expected_request, try store.validValue("apt-system-request-v1", request.value));
        try std.testing.expectEqual(expected_result, try store.validValue("apt-system-result-v2", result.value));
    }
}

test "missing duplicate unknown and invalid apt fields fail closed" {
    var store = try Store.init(allocator);
    defer store.deinit();
    {
        var profile = try std.json.parseFromSlice(std.json.Value, allocator, v2_profile, .{ .allocate = .alloc_always });
        defer profile.deinit();
        try rejectClosedFields(&store, "system-profile-v2", &profile, "architecture");
        try put(&profile.value, "schema", .{ .string = "https://debz.dev/schema/system-profile-v1" });
        try put(&profile.value, "version", .{ .integer = 1 });
        remove(&profile.value, "transaction_backend");
        try rejectClosedFields(&store, "system-profile-v1", &profile, "architecture");
    }
    for ([_]struct { path: []const u8, schema: []const u8, required: []const u8 }{
        .{ .path = "tools/fixtures/apt-system-request-v1-origin-main.document.json", .schema = "apt-system-request-v1", .required = "packages" },
        .{ .path = "tools/fixtures/apt-system-result-v2-origin-main.document.json", .schema = "apt-system-result-v2", .required = "profile" },
        .{ .path = "tools/fixtures/apt-system-result-v3-confirmation.document.json", .schema = "apt-system-result-v3", .required = "mutation_status" },
        .{ .path = "tools/fixtures/apt-system-request-v1-origin-main.document.json", .schema = "frozen-request-v1", .required = "packages" },
        .{ .path = "tools/fixtures/apt-system-result-v2-origin-main.document.json", .schema = "frozen-result-v2", .required = "profile" },
    }) |case| {
        var doc = try fixture(case.path);
        defer doc.deinit();
        try rejectClosedFields(&store, case.schema, &doc, case.required);
    }
    {
        var result_v1 = try fixture("tools/fixtures/apt-system-result-v2-origin-main.document.json");
        defer result_v1.deinit();
        remove(&result_v1.value, "items");
        try put(&result_v1.value, "schema", .{ .string = "https://debz.dev/schema/apt-system-result-v1" });
        try put(&result_v1.value, "version", .{ .integer = 1 });
        try rejectClosedFields(&store, "apt-system-result-v1", &result_v1, "profile");
    }
    {
        var state = try std.json.parseFromSlice(std.json.Value, allocator, operation_state, .{ .allocate = .alloc_always });
        defer state.deinit();
        var confirmation = try fixture("tools/fixtures/apt-system-result-v3-confirmation.document.json");
        defer confirmation.deinit();
        try put(&state.value, "profile", field(&confirmation.value, "profile").*);
        try put(&state.value, "exact_lock", field(field(&confirmation.value, "evidence"), "exact_lock").*);
        try rejectClosedFields(&store, "apt-system-operation-state-v1", &state, "phase");
    }
    {
        var diagnostic = try std.json.parseFromSlice(std.json.Value, allocator,
            \\{"schema":"io.github.cataggar.debz.apt-system-cli-diagnostic.v1","version":1,"exit_status":2,"id":"unsupported_syntax","topic":"apt","message":"bad option"}
        , .{ .allocate = .alloc_always });
        defer diagnostic.deinit();
        try rejectClosedFields(&store, "apt-system-cli-diagnostic-v1", &diagnostic, "version");
    }
    try std.testing.expectError(error.DuplicateField, store.valid("apt-system-request-v1",
        \\{"schema":"https://debz.dev/schema/apt-system-request-v1","schema":"https://debz.dev/schema/apt-system-request-v1"}
    ));
    {
        var request = try fixture("tools/fixtures/apt-system-request-v1-origin-main.document.json");
        defer request.deinit();
        const packages = field(&request.value, "packages");
        try packages.array.append(packages.array.items[0]);
        try invalid(&store, "apt-system-request-v1", request.value);
    }
    {
        var result = try fixture("tools/fixtures/apt-system-result-v3-confirmation.document.json");
        defer result.deinit();
        try add(field(&result.value, "profile"), result.arena.allocator(), "unexpected", .null);
        try invalid(&store, "apt-system-result-v3", result.value);
        remove(field(&result.value, "profile"), "unexpected");
        remove(field(&result.value, "evidence"), "exact_lock");
        try invalid(&store, "apt-system-result-v3", result.value);
    }
    {
        var profile = try std.json.parseFromSlice(std.json.Value, allocator, v2_profile, .{ .allocate = .alloc_always });
        defer profile.deinit();
        try add(&profile.value.object.getPtr("repositories").?.array.items[0], profile.arena.allocator(), "unexpected", .null);
        try invalid(&store, "system-profile-v2", profile.value);
    }
    const oversized = try allocator.alloc(u8, validator.max_document_bytes + 1);
    defer allocator.free(oversized);
    try std.testing.expectError(error.DocumentTooLarge, store.valid("apt-system-request-v1", oversized));
}

test "integral decimals preserve version, exit, binding and minimum semantics" {
    var store = try Store.init(allocator);
    defer store.deinit();
    const v2_result = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "tools/fixtures/apt-system-result-v2-origin-main.document.json", allocator, .limited(1024 * 1024));
    defer allocator.free(v2_result);
    const v2_decimal = try std.mem.replaceOwned(u8, allocator, v2_result, "\"version\":2,", "\"version\":2.0,");
    defer allocator.free(v2_decimal);
    const v2_decimal_exit = try std.mem.replaceOwned(u8, allocator, v2_decimal, "\"exit_status\":0,", "\"exit_status\":0.0,");
    defer allocator.free(v2_decimal_exit);
    try std.testing.expect(try store.valid("apt-system-result-v2", v2_decimal_exit));
    const bad_exit = try std.mem.replaceOwned(u8, allocator, v2_decimal_exit, "\"exit_status\":0.0,", "\"exit_status\":0.5,");
    defer allocator.free(bad_exit);
    try std.testing.expect(!try store.valid("apt-system-result-v2", bad_exit));
    for ([_][]const u8{ "2.5", "2.00000000000000000001" }) |invalid_version| {
        const replacement = try std.fmt.allocPrint(allocator, "\"version\":{s},", .{invalid_version});
        defer allocator.free(replacement);
        const changed = try std.mem.replaceOwned(u8, allocator, v2_result, "\"version\":2,", replacement);
        defer allocator.free(changed);
        try std.testing.expect(!try store.valid("apt-system-result-v2", changed));
    }
    const profile_decimal = try std.mem.replaceOwned(u8, allocator, v2_profile, "\"version\":2,", "\"version\":2e0,");
    defer allocator.free(profile_decimal);
    try std.testing.expect(try store.valid("system-profile-v2", profile_decimal));
    const request = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "tools/fixtures/apt-system-request-v1-origin-main.document.json", allocator, .limited(1024 * 1024));
    defer allocator.free(request);
    const request_decimal = try std.mem.replaceOwned(u8, allocator, request, "\"api_version\":1,", "\"api_version\":1.0,");
    defer allocator.free(request_decimal);
    try std.testing.expect(try store.valid("apt-system-request-v1", request_decimal));
    const v3 = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "tools/fixtures/apt-system-result-v3-confirmation.document.json", allocator, .limited(1024 * 1024));
    defer allocator.free(v3);
    const good_binding = try std.mem.replaceOwned(u8, allocator, v3, "\"version\":2,", "\"version\":2.0,");
    defer allocator.free(good_binding);
    try std.testing.expect(try store.valid("apt-system-result-v3", good_binding));
    const bad_binding = try std.mem.replaceOwned(u8, allocator, good_binding, "\"version\":2.0,", "\"version\":0.0,");
    defer allocator.free(bad_binding);
    try std.testing.expect(!try store.valid("apt-system-result-v3", bad_binding));
}

test "maximum item count and text length exceed old megabyte cutoff" {
    var store = try Store.init(allocator);
    defer store.deinit();
    const original = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "tools/fixtures/apt-system-result-v2-origin-main.document.json", allocator, .limited(1024 * 1024));
    defer allocator.free(original);
    const marker = "\"items\":[";
    const start = (std.mem.indexOf(u8, original, marker) orelse return error.InvalidFixture) + marker.len;
    const end = std.mem.indexOfPos(u8, original, start, "],\"evidence\"") orelse return error.InvalidFixture;
    var document: std.ArrayList(u8) = .empty;
    defer document.deinit(allocator);
    try document.appendSlice(allocator, original[0..start]);
    for (0..4096) |i| {
        if (i != 0) try document.append(allocator, ',');
        try document.appendSlice(allocator, "{\"package\":\"alpha\",\"version\":\"1\",\"architecture\":\"amd64\",\"detail\":\"");
        try document.appendSlice(allocator, ("A" ** 4096)[0..]);
        try document.appendSlice(allocator, "\"}");
    }
    try document.appendSlice(allocator, original[end..]);
    try std.testing.expect(document.items.len > 16 * 1024 * 1024);
    try std.testing.expect(try store.valid("apt-system-result-v2", document.items));
    const fractional = try std.mem.replaceOwned(u8, allocator, document.items, "\"version\":2,", "\"version\":2.1,");
    defer allocator.free(fractional);
    try std.testing.expect(!try store.valid("apt-system-result-v2", fractional));
}

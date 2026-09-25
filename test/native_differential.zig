const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const options = @import("native_test_options");

const corpus_schema = "https://debz.dev/test/native-transaction-corpus-v1";
const corpus_sha256 = "048c7cee5f3ca2a5a5afe31b6ebc89545806f4fd5e09c643a8c1130e1cabfcf9";
const corpus_cases = 145;
const operations = [_][]const u8{
    "install", "upgrade", "downgrade",        "reinstall",
    "remove",  "purge",   "process_triggers", "recover",
};
const expected_outcomes = [_][]const u8{
    "success",                 "failure",                "recovery-required",
    "failure-before-mutation", "success-after-recovery",
};
const initial_states = [_][]const u8{
    "fresh", "healthy", "locally-modified", "imported", "corrupt",
};

fn readFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8, maximum: usize) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{
        .follow_symlinks = false,
        .allow_directory = false,
    });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(maximum + 1));
}

fn includes(values: []const []const u8, item: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, value, item)) return true;
    return false;
}

fn field(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidCorpusShape;
    return value.object.get(key) orelse error.InvalidCorpusShape;
}

fn text(value: std.json.Value) ![]const u8 {
    return if (value == .string) value.string else error.InvalidCorpusShape;
}

fn identity(value: []const u8) bool {
    if (value.len == 0 or value[0] < 'a' or value[0] > 'z') {
        if (value.len == 0 or value[0] < '0' or value[0] > '9') return false;
    }
    var separator = false;
    for (value) |c| {
        if ((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9')) {
            separator = false;
        } else if (c == '+' or c == '.' or c == '-') {
            if (separator) return false;
            separator = true;
        } else return false;
    }
    return !separator;
}

pub fn validateCorpus(allocator: std.mem.Allocator, document: std.json.Value) !usize {
    if (document != .object or document.object.count() != 4)
        return error.InvalidCorpusShape;
    if (!std.mem.eql(u8, try text(try field(document, "schema")), corpus_schema) or
        (try field(document, "version")) != .integer or
        (try field(document, "version")).integer != 1)
        return error.UnsupportedCorpus;
    const arch = try field(document, "architectures");
    if (arch != .array or arch.array.items.len != 2 or
        !std.mem.eql(u8, try text(arch.array.items[0]), "amd64") or
        !std.mem.eql(u8, try text(arch.array.items[1]), "arm64"))
        return error.InvalidCorpusArchitectures;
    const entries = try field(document, "scenarios");
    if (entries != .array or entries.array.items.len == 0)
        return error.InvalidCorpusScenarios;
    var seen: std.StringHashMap(void) = .init(allocator);
    defer seen.deinit();
    for (entries.array.items) |scenario| {
        if (scenario != .object or scenario.object.count() != 5)
            return error.InvalidScenarioShape;
        const id = try text(try field(scenario, "id"));
        if (!identity(id) or seen.contains(id)) return error.InvalidScenarioIdentity;
        try seen.put(id, {});
        const initial = try text(try field(scenario, "initial"));
        if (!includes(&initial_states, initial)) return error.InvalidInitialState;
        const steps = try field(scenario, "operations");
        if (steps != .array or steps.array.items.len == 0) return error.InvalidScenarioOperations;
        for (steps.array.items) |step| {
            if (!includes(&operations, try text(step))) return error.InvalidScenarioOperations;
        }
        const features = try field(scenario, "features");
        if (features != .array or features.array.items.len == 0)
            return error.InvalidScenarioFeatures;
        var unique: std.StringHashMap(void) = .init(allocator);
        defer unique.deinit();
        for (features.array.items) |feature| {
            const value = try text(feature);
            if (!identity(value) or unique.contains(value)) return error.InvalidScenarioFeatures;
            try unique.put(value, {});
        }
        const expectation = try text(try field(scenario, "expected"));
        if (!includes(&expected_outcomes, expectation)) return error.InvalidScenarioExpectation;
    }
    return entries.array.items.len;
}

fn loadCorpus(allocator: std.mem.Allocator, io: std.Io) !std.json.Parsed(std.json.Value) {
    const raw = try readFile(allocator, io, options.corpus, 512 * 1024);
    defer allocator.free(raw);
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &sha256, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(sha256, .lower), corpus_sha256))
        return error.CorpusInventoryChanged;
    return std.json.parseFromSlice(std.json.Value, allocator, raw, .{ .allocate = .alloc_always });
}

fn findScenario(document: std.json.Value, id: []const u8) !std.json.Value {
    for ((try field(document, "scenarios")).array.items) |item| {
        if (std.mem.eql(u8, try text(try field(item, "id")), id))
            return item;
    }
    return error.MissingRequiredScenario;
}

fn execute(allocator: std.mem.Allocator, io: std.Io, driver: []const u8, reference_path: ?[]const u8, host_dpkg: []const u8) !void {
    var corpus = try loadCorpus(allocator, io);
    defer corpus.deinit();
    const count = try validateCorpus(allocator, corpus.value);
    if (count != corpus_cases) return error.CorpusInventoryChanged;
    const first = try findScenario(corpus.value, "fresh-install");
    if (!std.mem.eql(u8, try text(try field(first, "expected")), "success"))
        return error.CorpusInventoryChanged;
    const upgrade = try findScenario(corpus.value, "upgrade");
    if (!std.mem.eql(u8, try text(try field(upgrade, "expected")), "success"))
        return error.CorpusInventoryChanged;

    const architecture = try foundation.hostArchitecture(allocator, io, host_dpkg);
    const dpkg = try foundation.selectReference(allocator, io, reference_path, architecture, host_dpkg);
    const host_before = try foundation.hostStatusDigest(allocator, io);
    var fixture = try foundation.Fixture.init(allocator, io, options.repository);
    defer fixture.deinit();
    const first_archive = try fixture.makePackage(architecture, "1", .data);
    defer allocator.free(first_archive);
    const second_archive = try fixture.makePackage(architecture, "2", .data);
    defer allocator.free(second_archive);
    const left = try fixture.makeRoot("reference", architecture);
    defer allocator.free(left);
    const right = try fixture.makeRoot("candidate", architecture);
    defer allocator.free(right);
    var executed: usize = 0;
    for ([_]struct { operation: []const u8, archive: []const u8 }{
        .{ .operation = "install", .archive = first_archive },
        .{ .operation = "upgrade", .archive = second_archive },
    }) |step| {
        try fixture.directory(step.operation);
        const log = try std.fmt.allocPrint(allocator, "{s}/reference.log", .{step.operation});
        defer allocator.free(log);
        try foundation.reference(fixture, dpkg, left, step.archive, log, false);
        var result = try foundation.native(&fixture, driver, right, step.archive, architecture, step.operation, step.operation);
        defer result.deinit();
        if (!std.mem.eql(u8, result.value.outcome, "applied")) return error.DifferentialNativeNotApplied;
        try foundation.compare(fixture, left, right, step.operation);
        try foundation.assertDirectoryMtime(io, left, right, foundation.payload ++ "/empty");
        executed += 1;
    }
    const host_after = try foundation.hostStatusDigest(allocator, io);
    if (!std.mem.eql(u8, &host_before, &host_after)) return error.HostDpkgStatusChanged;
    std.debug.print("differential: {d} validated corpus inventory entries; {d} executed native/dpkg comparisons (not {d})\n", .{
        count, executed, count,
    });
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeTestExecutable;
    var reference_path: ?[]const u8 = null;
    if (args.next()) |option| {
        if (!std.mem.eql(u8, option, "--reference-dpkg")) return error.InvalidArguments;
        reference_path = args.next() orelse return error.InvalidArguments;
    }
    if (args.next() != null) return error.InvalidArguments;
    const host_dpkg = try foundation.hostDpkg(allocator, init.io, init.environ_map.get("PATH") orelse "/bin:/usr/bin");
    defer allocator.free(host_dpkg);
    try execute(allocator, init.io, driver, reference_path, host_dpkg);
}

test "corpus is validated as inventory, not as executed cases" {
    var parsed = try loadCorpus(std.testing.allocator, std.testing.io);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, corpus_cases), try validateCorpus(std.testing.allocator, parsed.value));
    const triggered = try findScenario(parsed.value, "trigger-failure");
    try std.testing.expectEqualStrings("failure", try text(try field(triggered, "expected")));
    const pending = try findScenario(parsed.value, "trigger-interest-pending-recorded");
    const steps = try field(pending, "operations");
    try std.testing.expectEqualStrings("process_triggers", try text(steps.array.items[0]));
}

test "corpus validator rejects unsupported, ambiguous and unsafe scenarios" {
    const prefix =
        \\{"schema":"https://debz.dev/test/native-transaction-corpus-v1","version":1,"architectures":["amd64","arm64"],"scenarios":[
    ;
    const valid = prefix ++
        \\{"id":"fresh-install","initial":"fresh","operations":["install"],"features":["regular-file"],"expected":"success"}]}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, valid, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), try validateCorpus(std.testing.allocator, parsed.value));
    const scenario_value = &parsed.value.object.getPtr("scenarios").?.array.items[0];
    try scenario_value.object.put(std.testing.allocator, "typo", .{ .bool = true });
    try std.testing.expectError(error.InvalidScenarioShape, validateCorpus(std.testing.allocator, parsed.value));
    _ = scenario_value.object.swapRemove("typo");
    scenario_value.object.getPtr("id").?.* = .{ .string = "../bad" };
    try std.testing.expectError(error.InvalidScenarioIdentity, validateCorpus(std.testing.allocator, parsed.value));
    scenario_value.object.getPtr("id").?.* = .{ .string = "fresh-install" };
    scenario_value.object.getPtr("features").?.array.items[0] = .{ .string = "link/escape" };
    try std.testing.expectError(error.InvalidScenarioFeatures, validateCorpus(std.testing.allocator, parsed.value));
    scenario_value.object.getPtr("features").?.array.items[0] = .{ .string = "regular-file" };
    parsed.value.object.getPtr("architectures").?.array.items[0] = .{ .string = "arm64" };
    try std.testing.expectError(error.InvalidCorpusArchitectures, validateCorpus(std.testing.allocator, parsed.value));
}

test "Zig canonical differential rejects changed payload and malformed dpkg metadata" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("left", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("right", "amd64");
    defer std.testing.allocator.free(right);
    try fixture.write("left/usr/bin/demo", "reference\n", 0o755);
    try fixture.write("right/usr/bin/demo", "candidate\n", 0o755);
    try std.testing.expectError(error.NativeDpkgMismatch, foundation.compare(fixture, left, right, "comparison"));
    try fixture.write("right/usr/bin/demo", "reference\n", 0o755);
    try fixture.dir.setTimestamps(std.testing.io, "right/usr/bin/demo", .{
        .modify_timestamp = .{ .new = .{ .nanoseconds = (try fixture.dir.statFile(
            std.testing.io,
            "left/usr/bin/demo",
            .{},
        )).mtime.nanoseconds } },
    });
    try foundation.compare(fixture, left, right, "matched");
    try fixture.write("right/var/lib/dpkg/info/demo.list", "../unsafe\n", 0o644);
    try std.testing.expectError(
        error.UnsafePackagePath,
        foundation.capture(std.testing.allocator, std.testing.io, right),
    );
}

test "semantic status, trigger, diversion and statoverride ordering is normalized" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const reference = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(reference);
    const candidate = try fixture.makeRoot("candidate", "amd64");
    defer std.testing.allocator.free(candidate);
    try fixture.write(
        "reference/var/lib/dpkg/status",
        "Package: demo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n",
        0o644,
    );
    try fixture.write(
        "candidate/var/lib/dpkg/status",
        "Version: 1\nArchitecture: amd64\nStatus: install ok installed\nPackage: demo\n\n",
        0o644,
    );
    try fixture.write("reference/var/lib/dpkg/info/demo.list", "/usr/bin/z\n/etc/a\n", 0o644);
    try fixture.write("candidate/var/lib/dpkg/info/demo.list", "/etc/a\n/usr/bin/z\n", 0o644);
    try fixture.write("reference/var/lib/dpkg/triggers/File", "/z demo\n/a demo\n", 0o644);
    try fixture.write("candidate/var/lib/dpkg/triggers/File", "/a demo\n/z demo\n", 0o644);
    try fixture.write(
        "reference/var/lib/dpkg/diversions",
        "/usr/bin/z\n/usr/bin/z.distrib\npackage-z\n/usr/bin/a\n/usr/bin/a.distrib\npackage-a\n",
        0o644,
    );
    try fixture.write(
        "candidate/var/lib/dpkg/diversions",
        "/usr/bin/a\n/usr/bin/a.distrib\npackage-a\n/usr/bin/z\n/usr/bin/z.distrib\npackage-z\n",
        0o644,
    );
    try fixture.write("reference/var/lib/dpkg/statoverride", "root root 4755 /usr/bin/z\nroot root 0755 /usr/bin/a\n", 0o644);
    try fixture.write("candidate/var/lib/dpkg/statoverride", "root root 0755 /usr/bin/a\nroot root 4755 /usr/bin/z\n", 0o644);
    const expected = try foundation.capture(std.testing.allocator, std.testing.io, reference);
    defer std.testing.allocator.free(expected);
    const observed = try foundation.capture(std.testing.allocator, std.testing.io, candidate);
    defer std.testing.allocator.free(observed);
    try std.testing.expectEqualStrings(expected, observed);
}

test "symlinks remain lexical and regular hardlink groups are semantic" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(root);
    try fixture.write("root/usr/lib/demo", "same inode\n", 0o644);
    try std.Io.Dir.hardLink(fixture.dir, "root/usr/lib/demo", fixture.dir, "root/usr/lib/demo-link", std.testing.io, .{});
    try fixture.dir.symLink(std.testing.io, "../../outside", "root/usr/lib/escape", .{});
    try fixture.write("outside", "must not be read\n", 0o644);
    const image = try foundation.capture(std.testing.allocator, std.testing.io, root);
    defer std.testing.allocator.free(image);
    try std.testing.expect(std.mem.indexOf(u8, image, "\"target\": \"../../outside\"") != null);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, image, "\"hardlink_to\": \"usr/lib/demo\""));
    try std.testing.expect(std.mem.indexOf(u8, image, "must not be read") == null);
}

test "filesystem/database limits and truncated or corrupt input fail closed" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(root);
    try fixture.write("root/large", "1234", 0o644);
    try std.testing.expectError(error.FilesystemFileLimit, foundation.captureWithLimits(
        std.testing.allocator,
        std.testing.io,
        root,
        .{ .max_file_bytes = 3 },
    ));
    try fixture.dir.deleteFile(std.testing.io, "root/large");
    for ([_][]const u8{ "one", "two", "three" }) |name| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "root/var/lib/dpkg/info/{s}.list", .{name});
        defer std.testing.allocator.free(path);
        try fixture.write(path, "/one\n", 0o644);
    }

    try std.testing.expectError(error.DatabaseEntryLimit, foundation.captureWithLimits(
        std.testing.allocator,
        std.testing.io,
        root,
        .{ .max_entries = 2 },
    ));
    try fixture.write("root/var/lib/dpkg/info/one.list", "relative/path\n", 0o644);
    try std.testing.expectError(
        error.UnsafePackagePath,
        foundation.capture(std.testing.allocator, std.testing.io, root),
    );
    if (std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"schema\":", .{})) |parsed| {
        var unexpected = parsed;
        unexpected.deinit();
        return error.AcceptedTruncatedSnapshot;
    } else |_| {}
}

test "md5sums rejects uppercase hex but retains lowercase digests" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(root);
    const record = "root/var/lib/dpkg/info/demo.md5sums";
    try fixture.write(record, "D41D8CD98F00B204E9800998ECF8427E  usr/bin/demo\n", 0o644);
    try std.testing.expectError(error.InvalidMd5sums, foundation.capture(std.testing.allocator, std.testing.io, root));
    try fixture.write(record, "d41d8cd98f00b204e9800998ecf8427e  usr/bin/demo\n", 0o644);
    const accepted = try foundation.capture(std.testing.allocator, std.testing.io, root);
    defer std.testing.allocator.free(accepted);
    try std.testing.expect(std.mem.indexOf(u8, accepted, "usr/bin/demo d41d8cd98f00b204e9800998ecf8427e") != null);
}

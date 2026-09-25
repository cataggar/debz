const std = @import("std");
const debz = @import("debz");
const options = @import("native_test_options");
const foundation = @import("native_test_foundation.zig");
const oracle = @import("native_recovery_oracle.zig");

const recovery = debz.native_recovery;
const provenance = debz.native_provenance;
const root_fs = debz.root_fs;
const diversion = debz.native_diversion;
const diversion_cache = debz.native_diversion_cache;
const package_path = debz.package_path;
const absolute_path = debz.absolute_path;
const Digest = recovery.Digest;
const allocator = std.testing.allocator;

test "recovery-unit.script trace and helper invocation bind actual arguments and mount" {
    const script: oracle.ScriptInvocation = .{
        .package = "example",
        .version = "1",
        .architecture = "amd64",
        .kind = "postinst",
        .source = "new_package",
        .arguments = &.{ "configure", "" },
        .environment = &.{.{ .key = "LANG", .value = "C" }},
        .script_sha256 = @splat('a'),
        .invocation_sha256 = @splat('0'),
    };
    var actual = script;
    actual.invocation_sha256 = try oracle.helperInvocationDigest(
        "/fixture",
        "var/lib/debz/helper.bin",
        "usr/bin/dpkg-trigger",
        @splat('b'),
        @splat('c'),
        script,
        "var/lib/debz-lifecycle-scripts/example.postinst",
    );
    try oracle.validateHelperInvocation(
        allocator,
        "/fixture",
        "var/lib/debz/helper.bin",
        "usr/bin/dpkg-trigger",
        @splat('b'),
        @splat('c'),
        actual,
    );
    const trace = "example@1:postinst\texample\tpostinst\tamd64\t2\t9:configure\t0:\tpayload=new\n";
    try oracle.validateScriptTrace(allocator, trace, &.{actual});
    var changed = actual;
    changed.arguments = &.{ "configure", "2" };
    try std.testing.expectError(error.ScriptTraceMismatch, oracle.validateScriptTrace(allocator, trace, &.{changed}));
    try std.testing.expectError(error.ScriptHelperBindingMismatch, oracle.validateHelperInvocation(
        allocator,
        "/fixture",
        "var/lib/debz/helper.bin",
        "usr/bin/dpkg-trigger",
        @splat('d'),
        @splat('c'),
        actual,
    ));
    try std.testing.expectError(error.ScriptHelperBindingMismatch, oracle.validateHelperInvocation(
        allocator,
        "/fixture",
        "var/lib/debz/helper.bin",
        "usr/bin/dpkg-trigger",
        @splat('b'),
        @splat('d'),
        actual,
    ));
    try std.testing.expectError(error.ScriptTraceMismatch, oracle.validateScriptTrace(
        allocator,
        trace ++ trace,
        &.{actual},
    ));
    try std.testing.expectError(error.ScriptTraceMismatch, oracle.validateScriptTrace(
        allocator,
        trace ++ "\n",
        &.{actual},
    ));
}

fn hash(bytes: []const u8) Digest {
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &value, .{});
    return recovery.hexDigest(value);
}

fn hashBytes(bytes: []const u8) [32]u8 {
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &value, .{});
    return value;
}

fn fixture() !foundation.Fixture {
    return foundation.Fixture.init(allocator, std.testing.io, options.repository);
}

test "recovery-unit.diversion cache rejects mismatched loaded bytes and observed identities" {
    const bytes = "/usr/bin/tool\n/usr/bin/tool.original\n:\n";
    const loaded: diversion.Observation = .{ .device = 3, .inode = 4, .sha256 = hashBytes(bytes) };
    var cache = try diversion.CachedRecords.init(allocator, bytes, loaded);
    defer cache.deinit();
    cache.observed = .{ .device = 3, .inode = 4, .sha256 = hashBytes("changed live bytes") };
    const encoded = try diversion_cache.encode(allocator, cache, @splat('0'));
    defer allocator.free(encoded);
    var decoded = try diversion_cache.decode(allocator, encoded, @splat('0'));
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u8, bytes, decoded.cache.bytes.?);
    try std.testing.expectEqualDeep(loaded, decoded.cache.loaded.?);
    try std.testing.expectEqualDeep(cache.observed, decoded.cache.observed);

    var changed = cache;
    changed.loaded = .{ .device = 3, .inode = 4, .sha256 = hashBytes("other cached bytes") };
    try std.testing.expectError(error.InvalidDiversionCache, diversion_cache.encode(allocator, changed, @splat('0')));
    changed = cache;
    changed.observed = .{ .device = 3, .inode = 5, .sha256 = hashBytes("changed live bytes") };
    try std.testing.expectError(error.InvalidDiversionCache, diversion_cache.encode(allocator, changed, @splat('0')));
    changed = cache;
    changed.observed = null;
    try std.testing.expectError(error.InvalidDiversionCache, diversion_cache.encode(allocator, changed, @splat('0')));
    changed = cache;
    changed.bytes = "other cached bytes";
    try std.testing.expectError(error.InvalidDiversionCache, diversion_cache.encode(allocator, changed, @splat('0')));

    var absent = try diversion.CachedRecords.init(allocator, null, null);
    defer absent.deinit();
    const absent_bytes = try diversion_cache.encode(allocator, absent, @splat('0'));
    defer allocator.free(absent_bytes);
    var absent_decoded = try diversion_cache.decode(allocator, absent_bytes, @splat('0'));
    defer absent_decoded.deinit();
    try std.testing.expect(absent_decoded.cache.bytes == null);
    changed = absent;
    changed.bytes = "";
    try std.testing.expectError(error.InvalidDiversionCache, diversion_cache.encode(allocator, changed, @splat('0')));

    var empty = try diversion.CachedRecords.init(allocator, "", .{
        .device = 3,
        .inode = 4,
        .sha256 = hashBytes(""),
    });
    defer empty.deinit();
    const empty_bytes = try diversion_cache.encode(allocator, empty, @splat('0'));
    defer allocator.free(empty_bytes);
    var empty_decoded = try diversion_cache.decode(allocator, empty_bytes, @splat('0'));
    defer empty_decoded.deinit();
    try std.testing.expectEqualStrings("", empty_decoded.cache.bytes.?);
}

test "recovery-unit.literal package paths never grant root authority" {
    const literal = "/usr/lib/systemd/system/system-systemd\\x2dmute.slice";
    try std.testing.expect(package_path.nonRoot(literal));
    try std.testing.expect(!absolute_path.nonRoot(literal));
    for ([_][]const u8{ "", "/", "/literal/../escape", "/literal//file", "/literal/", "/literal\n", "/literal\x00" }) |invalid| {
        try std.testing.expect(!package_path.nonRoot(invalid));
    }
}

test "recovery-unit.empty v2 closure requires every typed binding and refuses legacy schema" {
    const lock_v2 = debz.exact_lock_v2;
    var lock = try lock_v2.create(allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(7),
        .policy_sha256 = @splat(8),
        .repositories = &.{},
        .local_artifacts = &.{},
        .packages = &.{},
        .verified_origins = true,
    });
    defer lock.deinit();
    const canonical = try lock.lock.canonicalJson(allocator);
    defer allocator.free(canonical);
    const digest = std.fmt.bytesToHex(lock.lock.digest_sha256, .lower);
    try std.testing.expectEqualStrings(
        "cd84da2b85532fb27bbcd53a085a4446bd3c25c9b816808d8ce8c9e3c12b60e6",
        &digest,
    );
    for ([_][]const u8{ "target_architecture", "request_sha256", "policy_sha256", "packages", "digest_sha256" }) |field| {
        var value = try std.json.parseFromSlice(std.json.Value, allocator, canonical, .{});
        defer value.deinit();
        try std.testing.expect(value.value.object.swapRemove(field));
        const missing = try std.json.Stringify.valueAlloc(allocator, value.value, .{ .whitespace = .minified });
        defer allocator.free(missing);
        try std.testing.expectError(error.MissingField, lock_v2.decode(allocator, missing, lock_v2.maximum_document_bytes));
    }
    const legacy = try std.mem.replaceOwned(
        u8,
        allocator,
        canonical,
        lock_v2.schema_id,
        "https://debz.dev/schema/exact-closure-lock-v1",
    );
    defer allocator.free(legacy);
    try std.testing.expectError(error.UnsupportedSchema, lock_v2.decode(allocator, legacy, lock_v2.maximum_document_bytes));

    var legacy_value = try std.json.parseFromSlice(std.json.Value, allocator, legacy, .{});
    defer legacy_value.deinit();
    legacy_value.value.object.getPtr("version").?.* = .{ .integer = 1 };
    try std.testing.expect(legacy_value.value.object.swapRemove("local_artifacts"));
    const legacy_empty = try std.json.Stringify.valueAlloc(allocator, legacy_value.value, .{ .whitespace = .minified });
    defer allocator.free(legacy_empty);
    try std.testing.expectError(
        error.EmptyClosure,
        debz.exact_lock.decode(allocator, legacy_empty, debz.exact_lock.maximum_document_bytes),
    );
}

fn manifestDigest(files: []const provenance.EvidenceFile) Digest {
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-retained-evidence-v1\x00") catch unreachable;
    std.json.Stringify.value(files, .{ .whitespace = .minified }, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return provenance.hexDigest(sink.hasher.finalResult());
}

test "recovery-unit.retained evidence rejects missing duplicate cross-attempt and altered bytes" {
    var sandbox = try fixture();
    defer sandbox.deinit();
    const root = root_fs.Root.init(sandbox.io, sandbox.dir);
    var document = provenance.testDocument();
    document.install_root = sandbox.path;
    document.root_identity_sha256 = recovery.hexDigest(debz.transaction_recovery.rootIdentity(sandbox.path));
    var files: [6]provenance.EvidenceFile = undefined;
    @memcpy(&files, document.evidence_files);
    for (&files) |*file| {
        file.sha256 = hash("x");
        try sandbox.write(file.path, "x", 0o600);
    }
    document.evidence_files = &files;
    document.evidence_files_sha256 = manifestDigest(&files);
    provenance.seal(&document);
    try provenance.validate(document);
    try provenance.verifyEvidence(allocator, root, document);
    try provenance.publish(allocator, root, document);
    try provenance.publish(allocator, root, document);
    var stored = (try provenance.read(allocator, root)).?;
    defer stored.deinit();
    try std.testing.expectEqualSlices(u8, &document.digest_sha256, &stored.document.digest_sha256);
    var changed = document;
    changed.detail = "relabelled after completion";
    provenance.seal(&changed);
    try std.testing.expectError(error.ProvenanceChanged, provenance.publish(allocator, root, changed));
    try sandbox.write(files[0].path, "y", 0o600);
    try std.testing.expectError(error.EvidenceChanged, provenance.verifyEvidence(allocator, root, document));
    try sandbox.write(files[0].path, "x", 0o600);

    changed = document;
    changed.evidence_files = &.{};
    changed.evidence_files_sha256 = manifestDigest(&.{});
    provenance.seal(&changed);
    try std.testing.expectError(error.InvalidEvidence, provenance.validate(changed));
    files[1].path = files[0].path;
    changed = document;
    changed.evidence_files_sha256 = manifestDigest(&files);
    provenance.seal(&changed);
    try std.testing.expectError(error.InvalidEvidence, provenance.validate(changed));
    files[1].path = "var/lib/debz/native-receipts-v1/" ++ ("b" ** 64) ++ "/foreign.json";
    changed.evidence_files_sha256 = manifestDigest(&files);
    provenance.seal(&changed);
    try std.testing.expectError(error.InvalidEvidence, provenance.validate(changed));
    const unsafe = try std.fmt.allocPrint(allocator, "{s}/../escape.json", .{document.evidence_root});
    defer allocator.free(unsafe);
    files[1].path = unsafe;
    changed.evidence_files_sha256 = manifestDigest(&files);
    provenance.seal(&changed);
    try std.testing.expectError(error.InvalidEvidence, provenance.validate(changed));
}

test "recovery-unit.retained evidence rejects a symlink instead of following it" {
    var sandbox = try fixture();
    defer sandbox.deinit();
    const root = root_fs.Root.init(sandbox.io, sandbox.dir);
    var document = provenance.testDocument();
    var files: [6]provenance.EvidenceFile = undefined;
    @memcpy(&files, document.evidence_files);
    for (&files) |*file| {
        file.sha256 = hash("x");
        try sandbox.write(file.path, "x", 0o600);
    }
    try sandbox.dir.deleteFile(sandbox.io, files[0].path);
    try sandbox.write("outside.json", "x", 0o600);
    const external = try sandbox.absolute("outside.json");
    defer allocator.free(external);
    try sandbox.dir.symLink(sandbox.io, external, files[0].path, .{});
    document.evidence_files = &files;
    document.evidence_files_sha256 = manifestDigest(&files);
    provenance.seal(&document);
    try std.testing.expectError(error.NotRegularFile, provenance.verifyEvidence(allocator, root, document));
}

test "recovery-unit.provenance reader refuses symlinks at both document paths" {
    var sandbox = try fixture();
    defer sandbox.deinit();
    const root = root_fs.Root.init(sandbox.io, sandbox.dir);
    try sandbox.directory("var/lib/debz");
    try sandbox.write("outside.json", "not a provenance document", 0o600);
    const external = try sandbox.absolute("outside.json");
    defer allocator.free(external);
    for ([_][]const u8{ provenance.document_path, provenance.legacy_document_path }) |path| {
        try sandbox.dir.symLink(sandbox.io, external, path, .{});
        try std.testing.expectError(error.NotRegularFile, provenance.read(allocator, root));
        try sandbox.dir.deleteFile(sandbox.io, path);
    }
    try std.testing.expect((try provenance.read(allocator, root)) == null);
}

test "recovery-unit.unknown receipt fields outcome schema and unsafe paths fail closed" {
    var document = provenance.testDocument();
    try std.testing.expectError(error.UnexpectedToken, provenance.decode(allocator, "[]"));
    const canonical = try document.canonicalJson(allocator);
    defer allocator.free(canonical);
    const unknown = try std.fmt.allocPrint(allocator, "{s},\"unreviewed\":true}}\n", .{canonical[0 .. canonical.len - 2]});
    defer allocator.free(unknown);
    try std.testing.expectError(error.UnknownField, provenance.decode(allocator, unknown));
    const invented = try std.mem.replaceOwned(
        u8,
        allocator,
        canonical,
        "\"outcome\":\"succeeded\"",
        "\"outcome\":\"unreviewed\"",
    );
    defer allocator.free(invented);
    try std.testing.expectError(error.InvalidEnumTag, provenance.decode(allocator, invented));
    document.version = 99;
    provenance.seal(&document);
    try std.testing.expectError(error.InvalidDocument, provenance.validate(document));
    document = provenance.testDocument();
    document.backend = .legacy_dpkg;
    provenance.seal(&document);
    try std.testing.expectError(error.InvalidDocument, provenance.validate(document));
    document = provenance.testDocument();
    document.root_inode += 1;
    try std.testing.expectError(error.DigestMismatch, provenance.validate(document));
    var files: [6]provenance.EvidenceFile = undefined;
    @memcpy(&files, document.evidence_files);
    for ([_][]const u8{ "/etc/passwd", "var/lib/debz-other/proof.json", "var/lib/debz/../../outside" }) |path| {
        files[0].path = path;
        document = provenance.testDocument();
        document.evidence_files = &files;
        document.evidence_files_sha256 = manifestDigest(&files);
        provenance.seal(&document);
        try std.testing.expectError(error.InvalidEvidence, provenance.validate(document));
    }
}

test "recovery-unit.script output binds split and combined capture to exact bytes and accounting" {
    const action: recovery.Action = .{ .kind = .script, .program_step = 1, .substep = 0, .ordinal = 0 };
    const empty = hash("");
    var outcome: recovery.ScriptOutcome = .{
        .intent_sha256 = @splat('a'),
        .action = action,
        .package = "example",
        .package_version = "1",
        .architecture = "amd64",
        .kind = .postinst,
        .source = "new_package",
        .script_sha256 = @splat('b'),
        .arguments = &.{ "configure", "" },
        .environment = &.{},
        .disposition = .exited,
        .exit_code = 0,
        .spawned = true,
        .invocation_sha256 = @splat('c'),
        .stdout_sha256 = hash("out"),
        .stderr_sha256 = hash("err"),
        .combined_sha256 = empty,
        .stdout_hex = "6f7574",
        .stderr_hex = "657272",
        .combined_hex = "",
        .output_bytes = 6,
        .output_limit = 100,
        .terminated_process_group = false,
        .escalated_to_kill = false,
        .issued_descendant_sweep = false,
        .digest_sha256 = @splat('0'),
    };
    recovery.sealScriptOutcome(&outcome);
    try recovery.validateScriptOutcome(outcome);
    outcome.output_bytes = 0;
    recovery.sealScriptOutcome(&outcome);
    try std.testing.expectError(error.InvalidScriptOutcome, recovery.validateScriptOutcome(outcome));
    outcome.output_bytes = 6;
    outcome.stdout_sha256 = @splat('f');
    recovery.sealScriptOutcome(&outcome);
    try std.testing.expectError(error.InvalidScriptOutcome, recovery.validateScriptOutcome(outcome));
    outcome.stdout_sha256 = empty;
    outcome.stderr_sha256 = empty;
    outcome.stdout_hex = "";
    outcome.stderr_hex = "";
    outcome.combined_hex = "6f7574657272";
    outcome.combined_sha256 = hash("outerr");
    recovery.sealScriptOutcome(&outcome);
    try recovery.validateScriptOutcome(outcome);
    outcome.stdout_hex = "6f7574";
    outcome.stdout_sha256 = hash("out");
    recovery.sealScriptOutcome(&outcome);
    try std.testing.expectError(error.InvalidScriptOutcome, recovery.validateScriptOutcome(outcome));
}

test "recovery-unit.script progress refuses duplicate or unknown outcomes without changing retained history" {
    var sandbox = try fixture();
    defer sandbox.deinit();
    const root = root_fs.Root.init(sandbox.io, sandbox.dir);
    try root.createDirectoryPath(
        try root_fs.Path.init(debz.root_operation.namespace_path),
        root_fs.default_directory_permissions,
    );
    const intent: Digest = @splat('a');
    const action: recovery.Action = .{ .kind = .script, .program_step = 1, .substep = 0, .ordinal = 0 };
    try recovery.initializeProgress(allocator, root, intent);
    try recovery.appendProgress(allocator, root, intent, action, .prepared, .none, null);
    try recovery.appendProgress(allocator, root, intent, action, .in_flight, .none, null);
    var progress = try recovery.readProgress(allocator, root);
    defer progress.deinit();
    try std.testing.expectEqual(@as(usize, 2), progress.document.records.len);
    try std.testing.expectError(
        error.InvalidProgress,
        recovery.appendProgress(allocator, root, intent, action, .outcome, .exited, null),
    );
    try recovery.appendProgress(allocator, root, intent, action, .outcome, .exited, @splat('b'));
    try std.testing.expectError(
        error.InvalidProgress,
        recovery.appendProgress(allocator, root, intent, action, .outcome, .exited, @splat('b')),
    );
    try std.testing.expectError(
        error.InvalidProgress,
        recovery.appendProgress(allocator, root, @splat('c'), action, .completed, .succeeded, null),
    );
    var unchanged = try recovery.readProgress(allocator, root);
    defer unchanged.deinit();
    try std.testing.expectEqual(@as(usize, 3), unchanged.document.records.len);
    try std.testing.expectEqual(recovery.Stage.outcome, unchanged.document.records[2].stage);
    try std.testing.expectEqualSlices(u8, &unchanged.document.records[2].digest_sha256, &unchanged.document.head_sha256);
}

test "recovery-unit.bootstrap progress hashes records in its v2 domain" {
    var sandbox = try fixture();
    defer sandbox.deinit();
    const root = root_fs.Root.init(sandbox.io, sandbox.dir);
    try root.createDirectoryPath(
        try root_fs.Path.init(debz.root_operation.namespace_path),
        root_fs.default_directory_permissions,
    );
    const intent: Digest = @splat('a');
    const helper_action: recovery.Action = .{
        .kind = .helper,
        .program_step = 1,
        .substep = recovery.helper_source_substep,
        .ordinal = 0,
    };
    try recovery.initializeBootstrapProgress(allocator, root, intent);
    try recovery.appendProgress(allocator, root, intent, helper_action, .prepared, .none, null);
    var progress = try recovery.readProgress(allocator, root);
    defer progress.deinit();
    try std.testing.expectEqual(@as(u32, 2), progress.document.version);
    try std.testing.expectEqualStrings(recovery.bootstrap_progress_schema_id, progress.document.schema);
    try std.testing.expectEqual(@as(usize, 1), progress.document.records.len);
    var record = progress.document.records[0];
    const actual = record.digest_sha256;
    record.digest_sha256 = @splat('0');
    const bytes = try std.json.Stringify.valueAlloc(allocator, record, .{ .whitespace = .minified });
    defer allocator.free(bytes);
    var v2 = std.crypto.hash.sha2.Sha256.init(.{});
    v2.update("debz-native-execution-progress-record-v2\x00");
    v2.update(bytes);
    try std.testing.expectEqualSlices(u8, &actual, &recovery.hexDigest(v2.finalResult()));
    var v1 = std.crypto.hash.sha2.Sha256.init(.{});
    v1.update("debz-native-execution-progress-record-v1\x00");
    v1.update(bytes);
    try std.testing.expect(!std.mem.eql(u8, &actual, &recovery.hexDigest(v1.finalResult())));
}

test "recovery-unit.rollback comparison accepts only the failure-clock interval" {
    const recorded = [_]oracle.RollbackTime{.{ .path = "usr/share/link", .original_nanoseconds = 100 }};
    var entries = [_]oracle.RollbackEntry{.{ .path = "usr/share/link", .kind = .symlink, .modified_nanoseconds = 150 }};
    try oracle.normalizeRollbackTimes(&entries, &recorded, 125, 175, true);
    try std.testing.expectEqual(@as(i128, 100), entries[0].modified_nanoseconds);
    for ([_]i128{ 100, 124, 176 }) |invalid| {
        entries[0].modified_nanoseconds = invalid;
        try std.testing.expectError(error.UnexpectedRollbackSymlinkTimestamp, oracle.normalizeRollbackTimes(&entries, &recorded, 125, 175, true));
    }
    entries[0].modified_nanoseconds = 150;
    try oracle.normalizeRollbackTimes(&entries, &.{.{ .path = "usr/share/link", .original_nanoseconds = null }}, 125, 175, false);
    try std.testing.expectEqual(@as(i128, 0), entries[0].modified_nanoseconds);
    entries[0].kind = .regular;
    try std.testing.expectError(error.RollbackChangedSymlinkType, oracle.normalizeRollbackTimes(&entries, &recorded, 125, 175, true));
    try std.testing.expectError(error.MissingRollbackPath, oracle.normalizeRollbackTimes(&entries, &.{.{ .path = "absent", .original_nanoseconds = 100 }}, 125, 175, true));
}

test "recovery-unit.consumer parity matrix requires all 28 matched signed-suite cases" {
    const cases = oracle.parity_cases;
    try std.testing.expectEqualStrings("debian-stable", oracle.parity_suites[0]);
    try std.testing.expectEqualStrings("ubuntu-26.04", oracle.parity_suites[1]);
    try std.testing.expectEqual(@as(usize, 14), cases.len);
    try std.testing.expect(cases[4].recommends and !cases[3].recommends);
    try std.testing.expect(cases[10].archives.len == 0 and cases[10].update);
    try std.testing.expectEqualStrings("fixture-upgrade", cases[9].seeds[0]);
    try std.testing.expectEqualStrings("fixture-upgrade", cases[10].seeds[0]);
    try std.testing.expectEqualStrings("base-dep", cases[0].reference_phases[0][0]);
    try std.testing.expectEqualStrings("pre-app", cases[0].reference_phases[1][0]);
    try std.testing.expectEqualStrings("fixture-upgrade", cases[10].hold.?);
    try std.testing.expectEqual(@as(u8, 7), cases[13].exit_status);
    try std.testing.expectEqualStrings("keep_existing", cases[11].conffile.?);
    try std.testing.expectEqualStrings("use_package_version", cases[12].conffile.?);
    try std.testing.expectEqualStrings("trigger-pkg", cases[8].package.?);
    try std.testing.expectEqualStrings("literal-paths-pkg", cases[6].archives[0]);
    try std.testing.expectEqualStrings("retained-metadata-pkg", cases[7].archives[0]);
    var rows: [28]oracle.ParityRow = undefined;
    for (oracle.parity_suites, 0..) |suite, suite_index| {
        for (cases, 0..) |case, index| {
            rows[suite_index * cases.len + index] = .{
                .suite = suite,
                .case_id = case.id,
                .architecture = "amd64",
                .consumers = &oracle.parity_consumers,
                .matched = true,
            };
        }
    }
    try oracle.validateConsumerParity(&rows, "amd64");
    try std.testing.expectError(error.IncompleteOrDuplicatedConsumerParity, oracle.validateConsumerParity(&.{}, "amd64"));
    try std.testing.expectError(error.IncompleteOrDuplicatedConsumerParity, oracle.validateConsumerParity(rows[0 .. rows.len - 1], "amd64"));
    var extra: [29]oracle.ParityRow = undefined;
    @memcpy(extra[0..rows.len], &rows);
    extra[rows.len] = rows[0];
    try std.testing.expectError(error.IncompleteOrDuplicatedConsumerParity, oracle.validateConsumerParity(&extra, "amd64"));
    rows[0].case_id = "unreviewed";
    try std.testing.expectError(error.IncompleteOrDuplicatedConsumerParity, oracle.validateConsumerParity(&rows, "amd64"));
    rows[0] = rows[1];
    try std.testing.expectError(error.IncompleteOrDuplicatedConsumerParity, oracle.validateConsumerParity(&rows, "amd64"));
    rows[0].case_id = cases[0].id;
    rows[0].suite = oracle.parity_suites[0];
    rows[0].architecture = "arm64";
    try std.testing.expectError(error.ConsumerParityMismatch, oracle.validateConsumerParity(&rows, "amd64"));
    rows[0].architecture = "amd64";
    rows[0].consumers = oracle.parity_consumers[1..];
    try std.testing.expectError(error.ConsumerParityMismatch, oracle.validateConsumerParity(&rows, "amd64"));
    rows[0].consumers = &oracle.parity_consumers;
    rows[0].matched = false;
    try std.testing.expectError(error.ConsumerParityMismatch, oracle.validateConsumerParity(&rows, "amd64"));
    rows[0].matched = true;
    try std.testing.expectError(error.ConsumerParityMismatch, oracle.validateConsumerParity(&rows, "other"));
}

test "recovery-unit.handler schemas require explicit absent postinst or lowercase digest" {
    for ([_]struct { schema: []const u8, definition: []const u8 }{
        .{ .schema = "schema/native-transaction-authorization-v1.json", .definition = "triggerHandler" },
        .{ .schema = "schema/native-transaction-program-v1.json", .definition = "triggerHandlerBinding" },
    }) |schema| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, schema.schema, allocator, .limited(4 * 1024 * 1024));
        defer allocator.free(bytes);
        try oracle.validateHandlerSchemaDefinition(allocator, bytes, schema.definition);
        const loosened = try std.mem.replaceOwned(
            u8,
            allocator,
            bytes,
            "\"package\", \"source\", \"postinst_sha256\", \"declarations_sha256\"",
            "\"package\", \"source\", \"declarations_sha256\"",
        );
        defer allocator.free(loosened);
        try std.testing.expect(loosened.len < bytes.len);
        try std.testing.expectError(error.InvalidHandlerSchema, oracle.validateHandlerSchemaDefinition(allocator, loosened, schema.definition));
        try std.testing.expectError(error.InvalidHandlerSchema, oracle.validateHandlerSchemaDefinition(allocator, "[]", schema.definition));
        for ([_][]const u8{
            "{\"package\":{\"name\":\"receiver\",\"version\":\"1\",\"architecture\":\"amd64\"},\"source\":\"installed_package\",\"postinst_sha256\":null,\"declarations_sha256\":\"" ++ ("b" ** 64) ++ "\"}",
            "{\"package\":{\"name\":\"receiver\",\"version\":\"1\",\"architecture\":\"amd64\"},\"source\":\"installed_package\",\"postinst_sha256\":\"" ++ ("a" ** 64) ++ "\",\"declarations_sha256\":\"" ++ ("b" ** 64) ++ "\"}",
        }) |valid| {
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, valid, .{});
            defer parsed.deinit();
            try oracle.validateHandler(parsed.value);
        }
        for ([_][]const u8{
            "{\"package\":{\"name\":\"receiver\",\"version\":\"1\",\"architecture\":\"amd64\"},\"source\":\"installed_package\",\"declarations_sha256\":\"" ++ ("b" ** 64) ++ "\"}",
            "{\"package\":{\"name\":\"receiver\",\"version\":\"1\",\"architecture\":\"amd64\"},\"source\":\"installed_package\",\"postinst_sha256\":\"\",\"declarations_sha256\":\"" ++ ("b" ** 64) ++ "\"}",
            "{\"package\":{\"name\":\"receiver\",\"version\":\"1\",\"architecture\":\"amd64\"},\"source\":\"installed_package\",\"postinst_sha256\":\"not-a-digest\",\"declarations_sha256\":\"" ++ ("b" ** 64) ++ "\"}",
            "{\"package\":{\"name\":\"receiver\",\"version\":\"1\",\"architecture\":\"amd64\"},\"source\":\"installed_package\",\"postinst_sha256\":null,\"declarations_sha256\":null}",
        }) |invalid| {
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, invalid, .{});
            defer parsed.deinit();
            try std.testing.expectError(error.InvalidTriggerHandler, oracle.validateHandler(parsed.value));
        }
    }
}

test "recovery-unit.helper request schemas resolve v1 program policy and reject missing bindings" {
    const request = debz.native_execution_request;
    var program: request.ProgramBinding = undefined;
    inline for (std.meta.fields(request.ProgramBinding)) |field| {
        @field(program, field.name) = @splat('a');
    }
    var document: request.Document = .{
        .install_root = "/fixture",
        .root_identity_sha256 = recovery.hexDigest(debz.transaction_recovery.rootIdentity("/fixture")),
        .root_inode = 1,
        .architecture = "amd64",
        .caller = .{
            .attempt_id = @splat('b'),
            .operation = .{ .repository_bootstrap = .add },
            .request_sha256 = @splat('c'),
            .policy_sha256 = @splat('d'),
        },
        .program = program,
        .operation = .install,
        .policy = .keep_existing,
        .triggers = false,
        .defer_triggers = false,
    };
    request.seal(&document);
    const canonical = try request.encode(allocator, document);
    defer allocator.free(canonical);
    var decoded = try request.decodePersisted(allocator, canonical);
    defer decoded.deinit();
    try std.testing.expectEqual(document.program.script_policy_sha256, decoded.execution().program.script_policy_sha256);
    const without_policy = try std.mem.replaceOwned(
        u8,
        allocator,
        canonical,
        ",\"script_policy_sha256\":\"" ++ ("a" ** 64) ++ "\"",
        "",
    );
    defer allocator.free(without_policy);
    try std.testing.expect(without_policy.len < canonical.len);
    try std.testing.expectError(error.MissingField, request.decodePersisted(allocator, without_policy));

    const v1_bytes = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "schema/native-execution-request-v1.json",
        allocator,
        .limited(4 * 1024 * 1024),
    );
    defer allocator.free(v1_bytes);
    var v1 = try std.json.parseFromSlice(std.json.Value, allocator, v1_bytes, .{});
    defer v1.deinit();
    const program_schema = v1.value.object.get("properties").?.object.get("program").?;
    const required = program_schema.object.get("required").?.array.items;
    try std.testing.expectEqual(@as(usize, std.meta.fields(request.ProgramBinding).len), required.len);
    try std.testing.expect(std.mem.eql(u8, v1.value.object.get("$id").?.string, request.schema_id));
    for ([_]struct { path: []const u8, id: []const u8 }{
        .{ .path = "schema/native-execution-request-v2.json", .id = request.helper_schema_id },
        .{ .path = "schema/native-execution-request-v3.json", .id = request.bootstrap_schema_id },
    }) |wrapper| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wrapper.path, allocator, .limited(4 * 1024 * 1024));
        defer allocator.free(bytes);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        defer parsed.deinit();
        try std.testing.expectEqualStrings(wrapper.id, parsed.value.object.get("$id").?.string);
        const execution = parsed.value.object.get("properties").?.object.get("execution").?;
        try std.testing.expectEqualStrings(request.schema_id, execution.object.get("$ref").?.string);
    }
    inline for (std.meta.fields(request.ProgramBinding)) |field| {
        var found = false;
        for (required) |name| {
            if (std.mem.eql(u8, name.string, field.name)) found = true;
        }
        try std.testing.expect(found);
    }

    const helper = debz.native_helper;
    const isolated = try request.withHelper(document, .{
        .source_path = helper.directory ++ "/" ++ ("e" ** 64) ++ ".bin",
        .target_path = helper.target_path,
        .sha256 = @splat('e'),
        .size = 1,
    });
    const isolated_bytes = try request.encodeWithHelper(allocator, isolated);
    defer allocator.free(isolated_bytes);
    const bootstrap = try request.withBootstrap(document, .{
        .attempt_id = document.caller.attempt_id,
        .root_identity_sha256 = document.root_identity_sha256,
        .root_inode = document.root_inode,
        .root_uid = 0,
        .root_gid = 0,
        .plan_sha256 = document.program.plan_sha256,
        .authorization_sha256 = document.program.authorization_sha256,
        .program_sha256 = document.program.program_sha256,
        .exact_lock_schema = helper.legacy_exact_lock_schema,
        .exact_lock_version = helper.legacy_exact_lock_version,
        .exact_lock_sha256 = document.program.exact_lock_sha256,
        .helper = .{
            .source_path = helper.bootstrap_directory ++ "/helper-" ++ ("b" ** 64) ++ ".bin",
            .target_path = helper.target_path,
            .sha256 = @splat('e'),
            .size = 1,
        },
        .owner = .{
            .package = helper.owner_package,
            .version = "1",
            .architecture = "amd64",
            .final_state = "installed",
            .artifact = 0,
            .archive_sha256 = @splat('c'),
            .archive_size = 1,
            .application_sha256 = @splat('d'),
            .program_step = 1,
        },
        .target = .{
            .sha256 = @splat('f'),
            .size = 1,
            .mode = 0o755,
            .uid = 0,
            .gid = 0,
        },
    });
    const bootstrap_bytes = try request.encodeWithBootstrap(allocator, bootstrap);
    defer allocator.free(bootstrap_bytes);
    for ([_][]const u8{ canonical, isolated_bytes, bootstrap_bytes }) |bytes| {
        var persisted = try request.decodePersisted(allocator, bytes);
        defer persisted.deinit();
        try std.testing.expectEqual(document.program.script_policy_sha256, persisted.execution().program.script_policy_sha256);
        const omitted = try std.mem.replaceOwned(
            u8,
            allocator,
            bytes,
            ",\"script_policy_sha256\":\"" ++ ("a" ** 64) ++ "\"",
            "",
        );
        defer allocator.free(omitted);
        try std.testing.expect(omitted.len < bytes.len);
        try std.testing.expectError(error.MissingField, request.decodePersisted(allocator, omitted));
        const invalid = try std.mem.replaceOwned(
            u8,
            allocator,
            bytes,
            "\"script_policy_sha256\":\"" ++ ("a" ** 64) ++ "\"",
            "\"script_policy_sha256\":\"" ++ ("A" ** 64) ++ "\"",
        );
        defer allocator.free(invalid);
        try std.testing.expectEqual(bytes.len, invalid.len);
        try std.testing.expect(!std.mem.eql(u8, bytes, invalid));
        try std.testing.expectError(error.InvalidExecutionRequest, request.decodePersisted(allocator, invalid));
    }
}

fn refuseDiagnostic(report_bytes: []const u8, evidence_bytes: []const u8) !void {
    var report = try std.json.parseFromSlice(std.json.Value, allocator, report_bytes, .{});
    defer report.deinit();
    var evidence = try std.json.parseFromSlice(std.json.Value, allocator, evidence_bytes, .{});
    defer evidence.deinit();
    try std.testing.expectError(
        error.InvalidDiagnosticInspection,
        oracle.validateDiagnosticInspection(report.value, evidence.value, "/fixture"),
    );
}

test "recovery-unit.diagnostic inspection retains partial states without accepting invented authority" {
    const report =
        \\{"schema":"io.github.cataggar.debz.package-family.result.v2","version":2,"operation":"inspect","succeeded":true,"exit_status":"success","changed":false,"lock_path":null,"provenance_path":null}
    ;
    const evidence =
        \\{"native_install":null,"native_completion":null,"native_inspection":{"root":"/fixture","diagnostic_only":true,"status_database_present":true,"native_active_evidence":true,"observed_operation":{"state":"recovering"},"deferred_owner":null,"packages":[{"name":"partial","version":"1","architecture":"amd64","status":{"want":"install","error_state":"reinst_required","current":"half_configured"}}]}}
    ;
    var parsed_report = try std.json.parseFromSlice(std.json.Value, allocator, report, .{});
    defer parsed_report.deinit();
    var parsed_evidence = try std.json.parseFromSlice(std.json.Value, allocator, evidence, .{});
    defer parsed_evidence.deinit();
    const inspection = try oracle.validateDiagnosticInspection(parsed_report.value, parsed_evidence.value, "/fixture");
    try std.testing.expectEqualStrings("partial", inspection.object.get("packages").?.array.items[0].object.get("name").?.string);
    for ([_]struct { original: []const u8, replacement: []const u8 }{
        .{ .original = "\"changed\":false", .replacement = "\"changed\":true" },
        .{ .original = "\"provenance_path\":null", .replacement = "\"provenance_path\":\"/invented/receipt\"" },
        .{ .original = "\"lock_path\":null", .replacement = "\"lock_path\":\"/invented/lock\"" },
        .{ .original = "\"operation\":\"inspect\"", .replacement = "\"operation\":\"create\"" },
    }) |mutation| {
        const changed = try std.mem.replaceOwned(u8, allocator, report, mutation.original, mutation.replacement);
        defer allocator.free(changed);
        try std.testing.expect(changed.len != report.len);
        try refuseDiagnostic(changed, evidence);
    }
    for ([_]struct { original: []const u8, replacement: []const u8 }{
        .{ .original = "\"native_install\":null", .replacement = "\"native_install\":{}" },
        .{ .original = "\"native_completion\":null", .replacement = "\"native_completion\":{}" },
        .{ .original = "\"diagnostic_only\":true", .replacement = "\"diagnostic_only\":false" },
        .{ .original = "\"root\":\"/fixture\"", .replacement = "\"root\":\"/other-root\"" },
        .{ .original = "\"name\":\"partial\"", .replacement = "\"name\":\"partial\",\"unreviewed\":true" },
        .{ .original = "\"version\":\"1\"", .replacement = "\"version\":null" },
    }) |mutation| {
        const changed = try std.mem.replaceOwned(u8, allocator, evidence, mutation.original, mutation.replacement);
        defer allocator.free(changed);
        try std.testing.expect(changed.len != evidence.len);
        try refuseDiagnostic(report, changed);
    }
}

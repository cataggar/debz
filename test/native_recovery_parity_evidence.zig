const std = @import("std");
const debz = @import("debz");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const oracle = @import("native_recovery_oracle.zig");

const Digest = [64]u8;
const database = debz.package_database;
const Sha256 = std.crypto.hash.sha2.Sha256;
const DocumentFile = debz.native_provenance.EvidenceFile;

fn equal(left: []const u8, right: []const u8) !void {
    if (!std.mem.eql(u8, left, right)) return error.ConsumerReceiptEvidenceMismatch;
}

fn raw(allocator: std.mem.Allocator, root: debz.root_fs.Root, path: []const u8) ![]const u8 {
    return root.readFileAlloc(allocator, try debz.root_fs.Path.init(path), 16 * 1024 * 1024);
}

fn file(allocator: std.mem.Allocator, root: debz.root_fs.Root, name: []const u8) !?database.FileEntry {
    const path = try std.fmt.allocPrint(allocator, "var/lib/dpkg/{s}", .{name});
    const resolved = try debz.root_fs.Path.init(path);
    const entry = (try root.entryIfExists(resolved)) orelse return null;
    if (entry.kind != .file) return error.NonregularConsumerDatabaseFile;
    return .{
        .bytes = try root.readFileAlloc(allocator, resolved, 16 * 1024 * 1024),
        .mode = entry.mode,
    };
}

fn names(allocator: std.mem.Allocator, root: debz.root_fs.Root, comptime directory: []const u8) ![][]const u8 {
    var opened = try root.openDirectory(try debz.root_fs.Path.init("var/lib/dpkg/" ++ directory));
    defer opened.close(root.io);
    var iterator = opened.iterate();
    var collected: std.ArrayList([]const u8) = .empty;
    while (try iterator.next(root.io)) |entry| {
        if (collected.items.len >= 10_000) return error.ConsumerDatabaseEntryLimit;
        if (comptime std.mem.eql(u8, directory, "triggers")) {
            if (std.mem.eql(u8, entry.name, "File") or std.mem.eql(u8, entry.name, "Unincorp") or std.mem.eql(u8, entry.name, "Lock")) continue;
        }
        try collected.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, collected.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.less);
    return collected.items;
}

fn finalDatabase(allocator: std.mem.Allocator, root: debz.root_fs.Root, architecture: []const u8, proof: debz.native_provenance.Document) !void {
    var snapshot: database.Snapshot = .{
        .status = (try file(allocator, root, "status")) orelse return error.MissingConsumerStatus,
        .status_old = try file(allocator, root, "status-old"),
        .arch = try file(allocator, root, "arch"),
        .diversions = try file(allocator, root, "diversions"),
        .statoverride = try file(allocator, root, "statoverride"),
        .triggers_file = try file(allocator, root, "triggers/File"),
        .triggers_unincorp = try file(allocator, root, "triggers/Unincorp"),
    };
    if (snapshot.arch) |entry| {
        const expected = try std.fmt.allocPrint(allocator, "{s}\n", .{architecture});
        if (std.mem.eql(u8, entry.bytes, expected)) snapshot.arch = null;
    }
    var info: std.ArrayList(database.InfoEntry) = .empty;
    for (try names(allocator, root, "info")) |name| {
        const path = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}", .{name});
        const entry = (try root.entryIfExists(try debz.root_fs.Path.init(path))) orelse return error.ConsumerDatabaseChanged;
        const captured = (try file(allocator, root, try std.fmt.allocPrint(allocator, "info/{s}", .{name}))) orelse return error.ConsumerDatabaseChanged;
        try info.append(allocator, .{ .name = name, .bytes = captured.bytes, .mode = captured.mode, .uid = entry.uid, .gid = entry.gid });
    }
    snapshot.info = info.items;
    var updates: std.ArrayList(database.UpdateEntry) = .empty;
    for (try names(allocator, root, "updates")) |name| {
        const captured = (try file(allocator, root, try std.fmt.allocPrint(allocator, "updates/{s}", .{name}))) orelse return error.ConsumerDatabaseChanged;
        try updates.append(allocator, .{ .name = name, .bytes = captured.bytes, .mode = captured.mode });
    }
    snapshot.updates = updates.items;
    var triggers: std.ArrayList(database.NamedTriggerEntry) = .empty;
    for (try names(allocator, root, "triggers")) |name| {
        const captured = (try file(allocator, root, try std.fmt.allocPrint(allocator, "triggers/{s}", .{name}))) orelse return error.ConsumerDatabaseChanged;
        try triggers.append(allocator, .{ .name = name, .bytes = captured.bytes, .mode = captured.mode });
    }
    snapshot.triggers_named = triggers.items;
    const generation = try database.generation(allocator, snapshot);
    try equal(&std.fmt.bytesToHex(generation.sha256, .lower), &proof.final_database_generation_sha256);

    const Closure = struct {
        status: database.FileEntry,
        arch: ?database.FileEntry,
        triggers_file: ?database.FileEntry,
        triggers_unincorp: ?database.FileEntry,
        triggers_named: []const database.NamedTriggerEntry,
    };
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    try sink.writer.writeAll("debz-native-package-database-closure-v1\x00");
    try std.json.Stringify.value(Closure{
        .status = snapshot.status,
        .arch = snapshot.arch,
        .triggers_file = snapshot.triggers_file,
        .triggers_unincorp = snapshot.triggers_unincorp,
        .triggers_named = snapshot.triggers_named,
    }, .{ .whitespace = .minified }, &sink.writer);
    try sink.writer.flush();
    try equal(&std.fmt.bytesToHex(sink.hasher.finalResult(), .lower), &proof.final_state_sha256);
}

fn scriptInvocation(script: debz.native_recovery.ScriptOutcome) oracle.ScriptInvocation {
    return .{
        .package = script.package,
        .version = script.package_version,
        .architecture = script.architecture,
        .kind = @tagName(script.kind),
        .source = script.source,
        .arguments = script.arguments,
        .environment = script.environment,
        .script_sha256 = script.script_sha256,
        .invocation_sha256 = script.invocation_sha256,
    };
}

fn checkOutput(script: debz.native_recovery.ScriptOutcome) !void {
    var total: u64 = 0;
    const Stream = struct { hex: []const u8, digest: Digest };
    const streams = [_]Stream{
        .{ .hex = script.stdout_hex, .digest = script.stdout_sha256 },
        .{ .hex = script.stderr_hex, .digest = script.stderr_sha256 },
        .{ .hex = script.combined_hex, .digest = script.combined_sha256 },
    };
    for (streams) |stream| {
        if (stream.hex.len % 2 != 0) return error.ConsumerScriptOutputMismatch;
        const output = try std.heap.page_allocator.alloc(u8, stream.hex.len / 2);
        defer std.heap.page_allocator.free(output);
        const bytes = try std.fmt.hexToBytes(output, stream.hex);
        var hash: [32]u8 = undefined;
        Sha256.hash(bytes, &hash, .{});
        try equal(&std.fmt.bytesToHex(hash, .lower), &stream.digest);
        total += bytes.len;
    }
    if (script.combined_hex.len != 0 and (script.stdout_hex.len != 0 or script.stderr_hex.len != 0))
        return error.ConsumerScriptOutputMismatch;
    if (total != script.output_bytes or total > script.output_limit) return error.ConsumerScriptOutputMismatch;
}

fn checkEnvironment(script: debz.native_recovery.ScriptOutcome) !void {
    const expected = [_]struct { key: []const u8, value: []const u8 }{
        .{ .key = "DPKG_MAINTSCRIPT_ARCH", .value = script.architecture },
        .{ .key = "DPKG_MAINTSCRIPT_NAME", .value = @tagName(script.kind) },
        .{ .key = "DPKG_MAINTSCRIPT_PACKAGE", .value = script.package },
        .{ .key = "DPKG_ROOT", .value = "" },
        .{ .key = "DPKG_ADMINDIR", .value = "/var/lib/dpkg" },
        .{ .key = "DEBIAN_FRONTEND", .value = "noninteractive" },
        .{ .key = "DPKG_COLORS", .value = "never" },
        .{ .key = "HOME", .value = "/nonexistent" },
        .{ .key = "LANG", .value = "C" },
        .{ .key = "LC_ALL", .value = "C" },
        .{ .key = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" },
    };
    for (script.environment, 0..) |entry, index| {
        if (index > 0 and !std.mem.lessThan(u8, script.environment[index - 1].key, entry.key))
            return error.ConsumerScriptEnvironmentOrder;
    }
    for (expected) |wanted| {
        var found = false;
        for (script.environment) |entry| if (std.mem.eql(u8, entry.key, wanted.key)) {
            try equal(entry.value, wanted.value);
            found = true;
        };
        if (!found) return error.ConsumerScriptEnvironmentMissing;
    }
    if (script.disposition != .exited or script.signal != null or !script.spawned)
        return error.ConsumerScriptDidNotExit;
}

fn manifestDocument(entry: DocumentFile, digest: Digest) !void {
    try equal(&digest, &(entry.document_sha256 orelse return error.MissingConsumerDocumentDigest));
}

fn scriptTrace(allocator: std.mem.Allocator, root: debz.root_fs.Root, scripts: []const oracle.ScriptInvocation) !void {
    if (scripts.len == 0) return;
    const bytes = try raw(allocator, root, support.trace);
    var filtered: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or std.mem.startsWith(u8, line, "metadata:") or
            std.mem.startsWith(u8, line, "conffiles:")) continue;
        try filtered.append(allocator, line);
    }
    if (filtered.items.len < scripts.len) return error.ConsumerScriptTraceMissing;
    var trace: std.Io.Writer.Allocating = .init(allocator);
    defer trace.deinit();
    for (filtered.items[filtered.items.len - scripts.len ..]) |line| {
        try trace.writer.writeAll(line);
        try trace.writer.writeByte('\n');
    }
    try oracle.validateScriptTrace(allocator, trace.written(), scripts);
}

fn managedBinding(managed: debz.native_recovery.ManagedStateDocument, entry: DocumentFile, path: []const u8) !void {
    const snapshot = managed.transient orelse managed.stable orelse return error.MissingConsumerManagedSnapshot;
    for (snapshot.entries) |member| {
        if (!std.mem.eql(u8, member.path, path)) continue;
        if (member.kind != .regular or member.size != entry.size or
            !std.mem.eql(u8, &(member.content_sha256 orelse return error.MissingConsumerCacheDigest), &entry.sha256))
            return error.ConsumerManagedEvidenceMismatch;
        return;
    }
    return error.MissingConsumerManagedEvidence;
}

pub fn verify(fixture: *foundation.Fixture, root_path: []const u8, architecture: []const u8, lock_sha256: []const u8, failed: bool) !void {
    return verifyAt(fixture, root_path, root_path, architecture, lock_sha256, failed, true);
}

pub fn verifyProjected(fixture: *foundation.Fixture, physical_root: []const u8, logical_root: []const u8, architecture: []const u8, lock_sha256: []const u8, failed: bool) !void {
    return verifyAt(fixture, physical_root, logical_root, architecture, lock_sha256, failed, false);
}

fn verifyAt(fixture: *foundation.Fixture, root_path: []const u8, logical_root: []const u8, architecture: []const u8, lock_sha256: []const u8, failed: bool, lifecycle_trace: bool) !void {
    const allocator = fixture.allocator;
    var dir = try foundation.guardedRoot(fixture.io, root_path);
    defer dir.close(fixture.io);
    const root: debz.root_fs.Root = .init(fixture.io, dir);
    const receipt_raw = try raw(allocator, root, debz.native_provenance.document_path);
    var decoded = try debz.native_provenance.decode(allocator, receipt_raw);
    defer decoded.deinit();
    const proof = decoded.document;
    try equal(proof.install_root, logical_root);
    try equal(&proof.exact_lock_sha256, lock_sha256);
    if ((failed and proof.outcome != .failed) or (!failed and proof.outcome != .succeeded))
        return error.ConsumerReceiptOutcomeMismatch;
    const physical = try std.Io.Dir.cwd().statFile(fixture.io, root_path, .{ .follow_symlinks = false });
    if (proof.root_inode != physical.inode) return error.ConsumerRootIdentityChanged;
    try debz.native_provenance.verifyEvidence(allocator, root, proof);

    var intent: ?debz.native_recovery.OwnedIntent = null;
    defer if (intent) |*value| value.deinit();
    var progress: ?debz.native_recovery.OwnedProgress = null;
    defer if (progress) |*value| value.deinit();
    var managed: ?debz.native_recovery.OwnedManagedState = null;
    defer if (managed) |*value| value.deinit();
    var triggers: ?debz.native_recovery.OwnedTriggerEvents = null;
    defer if (triggers) |*value| value.deinit();
    var request: ?debz.native_execution_request.OwnedRequest = null;
    defer if (request) |*value| value.deinit();
    var authorization: ?debz.native_authorization.OwnedAuthorization = null;
    defer if (authorization) |*value| value.deinit();
    var program: ?debz.native_program.OwnedProgram = null;
    defer if (program) |*value| value.deinit();
    var helper_binary: ?debz.native_provenance.EvidenceFile = null;
    var scripts: std.ArrayList(oracle.ScriptInvocation) = .empty;
    var outcomes: std.ArrayList(struct { action: debz.native_recovery.Action, digest: Digest }) = .empty;
    var retained_scripts: std.ArrayList(std.json.Parsed(debz.native_recovery.ScriptOutcome)) = .empty;
    defer for (retained_scripts.items) |*script| script.deinit();
    for (proof.evidence_files) |entry| {
        const bytes = try raw(allocator, root, entry.path);
        switch (entry.kind) {
            .intent => {
                intent = try debz.native_recovery.decodeIntent(allocator, bytes);
                try manifestDocument(entry, intent.?.intent.digest_sha256);
            },
            .progress => {
                progress = try debz.native_recovery.decodeProgress(allocator, bytes);
                try manifestDocument(entry, progress.?.document.digest_sha256);
            },
            .managed_state => {
                managed = try debz.native_recovery.decodeManagedState(allocator, bytes);
                try manifestDocument(entry, managed.?.document.digest_sha256);
            },
            .trigger_events => {
                triggers = try debz.native_recovery.decodeTriggerEvents(allocator, bytes);
                try manifestDocument(entry, triggers.?.document.digest_sha256);
            },
            .execution_request => {
                request = try debz.native_execution_request.decodePersisted(allocator, bytes);
                const digest = switch (request.?) {
                    inline else => |owned| owned.document.digest_sha256,
                };
                try manifestDocument(entry, digest);
            },
            .authorization => {
                authorization = try debz.native_authorization.decode(allocator, bytes, 16 * 1024 * 1024);
                try manifestDocument(entry, std.fmt.bytesToHex(authorization.?.authorization.digest_sha256, .lower));
            },
            .program => {
                program = try debz.native_program.decode(allocator, bytes, 16 * 1024 * 1024);
                try manifestDocument(entry, program.?.program.digest_sha256);
            },
            .helper_binary => helper_binary = entry,
            .script_outcome => {
                var parsed = try std.json.parseFromSlice(debz.native_recovery.ScriptOutcome, allocator, bytes, .{
                    .allocate = .alloc_always, .ignore_unknown_fields = false,
                });
                errdefer parsed.deinit();
                const script = parsed.value;
                try debz.native_recovery.validateScriptOutcome(script);
                var canonical: std.Io.Writer.Allocating = .init(allocator);
                defer canonical.deinit();
                try std.json.Stringify.value(script, .{ .whitespace = .minified }, &canonical.writer);
                try canonical.writer.writeByte('\n');
                try equal(bytes, canonical.written());
                try manifestDocument(entry, script.digest_sha256);
                const bound_action = entry.action orelse return error.MissingConsumerScriptAction;
                if (script.action.kind != bound_action.kind or
                    script.action.program_step != bound_action.program_step or
                    script.action.substep != bound_action.substep or
                    script.action.ordinal != bound_action.ordinal)
                    return error.ConsumerScriptActionMismatch;
                try equal(&script.intent_sha256, &proof.execution_intent_sha256);
                try checkOutput(script);
                try checkEnvironment(script);
                for (outcomes.items) |prior| if (std.meta.eql(prior.action, script.action))
                    return error.DuplicateConsumerScriptOutcome;
                try scripts.append(allocator, scriptInvocation(script));
                try outcomes.append(allocator, .{ .action = script.action, .digest = script.digest_sha256 });
                try retained_scripts.append(allocator, parsed);
            },
            else => {},
        }
    }
    const i = (intent orelse return error.MissingConsumerIntent).intent;
    const p = (progress orelse return error.MissingConsumerProgress).document;
    const m = (managed orelse return error.MissingConsumerManagedState).document;
    const t = (triggers orelse return error.MissingConsumerTriggers).document;
    const r = (request orelse return error.MissingConsumerRequest);
    const a = (authorization orelse return error.MissingConsumerAuthorization).authorization;
    const compiled = (program orelse return error.MissingConsumerProgram).program;
    const caller = r.execution();
    try equal(&proof.attempt_id, &i.attempt_id);
    try equal(&proof.attempt_id, &caller.caller.attempt_id);
    try equal(&proof.execution_intent_sha256, &i.digest_sha256);
    try equal(&proof.root_identity_sha256, &i.root_identity_sha256);
    if (i.root_inode != physical.inode or caller.root_inode != physical.inode) return error.ConsumerRootIdentityChanged;
    try equal(&proof.request_sha256, &caller.caller.request_sha256);
    try equal(&proof.policy_sha256, &caller.caller.policy_sha256);
    try equal(&i.request_sha256, &caller.program.request_sha256);
    try equal(&caller.program.request_sha256, &compiled.request_sha256);
    try equal(&caller.program.solver_policy_sha256, &compiled.solver_policy_sha256);
    try equal(&caller.program.executor_policy_sha256, &compiled.executor_policy_sha256);
    try equal(&caller.program.plan_sha256, &compiled.plan_sha256);
    try equal(&caller.program.script_policy_sha256, &compiled.script_policy_sha256);
    try equal(&caller.program.program_sha256, &compiled.digest_sha256);
    if (std.mem.eql(u8, &caller.caller.request_sha256, &compiled.request_sha256))
        return error.ConsumerCallerRequestNotDistinct;
    try equal(&i.authorization_sha256, &proof.authorization_sha256);
    try equal(&i.program_sha256, &proof.program_sha256);
    try equal(&i.artifact_evidence_sha256, &proof.artifact_evidence_sha256);
    try equal(&i.database_generation_sha256, &proof.initial_database_generation_sha256);
    try equal(&compiled.digest_sha256, &proof.program_sha256);
    try equal(&std.fmt.bytesToHex(a.digest_sha256, .lower), &proof.authorization_sha256);
    if (!compiled.matchesAuthorization(a)) return error.ConsumerAuthorizationMismatch;
    if (!std.meta.eql(proof.operation, caller.caller.operation)) return error.ConsumerCallerOperationMismatch;
    try equal(&p.intent_sha256, &i.digest_sha256);
    try equal(&m.intent_sha256, &i.digest_sha256);
    try equal(&t.intent_sha256, &i.digest_sha256);
    try equal(&p.head_sha256, &proof.progress_head_sha256);
    if (p.records.len != proof.progress_record_count) return error.ConsumerProgressLengthMismatch;
    const summary = debz.native_recovery.summarizeProgress(p);
    try equal(&std.fmt.bytesToHex(summary.script_outcomes_sha256, .lower), &proof.script_outcomes_sha256);
    if (summary.recovered_phase_count != proof.recovered_phase_count) return error.ConsumerRecoveryHistoryMismatch;
    try equal(&t.digest_sha256, &proof.trigger_evidence_sha256);
    if (proof.final_state_kind != .package_database_closure_v1 or
        std.mem.eql(u8, &proof.final_state_sha256, &proof.final_database_generation_sha256))
        return error.ConsumerFinalStateKindMismatch;
    for ([_]?debz.native_recovery.ManagedSnapshot{ m.stable, m.transient }) |optional_snapshot| {
        const snapshot = optional_snapshot orelse continue;
        var seen = false;
        for (m.history) |boundary| if (std.mem.eql(u8, &boundary.snapshot_sha256, &snapshot.digest_sha256)) {
            seen = true;
        };
        if (!seen) return error.ConsumerManagedHistoryMismatch;
    }
    var request_blobs: usize = 0;
    for (i.blobs) |blob| {
        if (blob.kind != .request) continue;
        request_blobs += 1;
        var logical = false;
        for ([_][]const u8{ "v1", "v2", "v3", "v4" }) |version| {
            const expected = try std.fmt.allocPrint(allocator, "request/native-execution-request-{s}.json", .{version});
            if (std.mem.eql(u8, blob.logical_path, expected)) logical = true;
        }
        if (!logical) return error.ConsumerRequestBlobMismatch;
        for (proof.evidence_files) |entry| {
            if (entry.kind != .execution_request) continue;
            if (blob.size != entry.size or !std.mem.eql(u8, &blob.sha256, &entry.sha256))
                return error.ConsumerRequestBlobMismatch;
        }
    }
    if (request_blobs != 1) return error.ConsumerRequestBlobMismatch;
    for (p.records) |record| {
        if ((record.action.kind != .script and record.action.kind != .trigger and record.action.kind != .compensation) or record.stage != .outcome) continue;
        var matched: usize = 0;
        for (outcomes.items) |outcome| if (std.meta.eql(record.action, outcome.action)) {
            try equal(&(record.evidence_sha256 orelse return error.MissingConsumerOutcome), &outcome.digest);
            matched += 1;
        };
        if (matched != 1) return error.ConsumerScriptOutcomeMismatch;
    }
    for (outcomes.items) |outcome| {
        var matched: usize = 0;
        for (p.records) |record| {
            if (std.meta.eql(record.action, outcome.action) and record.stage == .outcome)
                matched += 1;
        }
        if (matched != 1) return error.ConsumerScriptOutcomeMismatch;
    }
    if (p.records.len == 0 or p.records[p.records.len - 1].stage != .terminal)
        return error.ConsumerTerminalProgressMissing;
    var failed_script = false;
    for (retained_scripts.items) |script| if (script.value.exit_code.? != 0) {
        failed_script = true;
    };
    if (failed_script != failed) return error.ConsumerFailureScriptMismatch;
    const helper = r.helper() orelse return error.MissingConsumerHelper;
    const binary = helper_binary orelse return error.MissingConsumerHelperBinary;
    try equal(&helper.sha256, &binary.sha256);
    if (helper.size != binary.size) return error.ConsumerHelperBinaryMismatch;
    for (scripts.items) |script| try oracle.validateHelperInvocation(
        allocator, logical_root, helper.source_path, helper.target_path, helper.sha256,
        caller.program.script_policy_sha256, script,
    );
    if (!failed and lifecycle_trace) try scriptTrace(allocator, root, scripts.items);
    var diversion_count: usize = 0;
    for (proof.evidence_files) |entry| {
        if (entry.kind == .diversion_cache) {
            diversion_count += 1;
            var decoded_cache = try debz.native_diversion_cache.decode(allocator, try raw(allocator, root, entry.path), i.digest_sha256);
            defer decoded_cache.deinit();
            try manifestDocument(entry, decoded_cache.digest_sha256);
            try managedBinding(m, entry, "var/lib/debz/native-diversion-cache-v1.json");
            const snapshot = m.transient orelse m.stable orelse return error.MissingConsumerManagedSnapshot;
            var live_found = false;
            for (snapshot.entries) |member| {
                if (!std.mem.eql(u8, member.path, "var/lib/dpkg/diversions")) continue;
                live_found = true;
                if (decoded_cache.cache.loaded) |_| {
                    const observed = decoded_cache.cache.observed orelse return error.ConsumerDiversionObservationMismatch;
                    if (member.kind != .regular or member.device != observed.device or member.inode != observed.inode or
                        !std.mem.eql(u8, &(member.content_sha256 orelse return error.ConsumerDiversionObservationMismatch),
                            &std.fmt.bytesToHex(observed.sha256, .lower)))
                        return error.ConsumerDiversionObservationMismatch;
                } else if (member.kind != .absent) return error.ConsumerDiversionObservationMismatch;
            }
            if (!live_found) return error.MissingConsumerManagedDiversion;
        } else if (entry.kind == .unpack_diversion_cache) {
            const action = entry.action orelse return error.MissingConsumerCacheAction;
            var decoded_cache = try debz.native_unpack_diversion.decode(allocator, try raw(allocator, root, entry.path), i.digest_sha256, action.program_step);
            defer decoded_cache.deinit();
            try manifestDocument(entry, decoded_cache.digest_sha256);
            const path = try std.fmt.allocPrint(allocator, "var/lib/debz/native-unpack-diversion-v1-{d}.json", .{action.program_step});
            try managedBinding(m, entry, path);
        }
    }
    const snapshot = m.transient orelse m.stable orelse return error.MissingConsumerManagedSnapshot;
    for (snapshot.entries) |member| {
        if (std.mem.eql(u8, member.path, "var/lib/debz/native-diversion-cache-v1.json")) {
            if ((member.kind == .regular) != (diversion_count == 1))
                return error.ConsumerDiversionCacheManifestMismatch;
        }
        const prefix = "var/lib/debz/native-unpack-diversion-v1-";
        if (!std.mem.startsWith(u8, member.path, prefix)) continue;
        var matching: usize = 0;
        for (proof.evidence_files) |entry| {
            if (entry.kind != .unpack_diversion_cache) continue;
            const action = entry.action orelse return error.MissingConsumerCacheAction;
            const expected = try std.fmt.allocPrint(allocator, "{s}{d}.json", .{ prefix, action.program_step });
            if (std.mem.eql(u8, member.path, expected)) matching += 1;
        }
        if ((if (member.kind == .regular) @as(usize, 1) else 0) != matching)
            return error.ConsumerUnpackCacheManifestMismatch;
        if (member.kind == .absent) {
            const digits = std.mem.trimEnd(u8, member.path[prefix.len..], ".json");
            const step = std.fmt.parseUnsigned(u32, digits, 10) catch return error.ConsumerUnpackCachePathMismatch;
            const expected = try std.fmt.allocPrint(allocator, "{s}{d}.json", .{ prefix, step });
            try equal(member.path, expected);
            for (p.records) |record| if (record.action.kind == .filesystem and
                record.action.program_step == step and record.action.substep == 0 and record.action.ordinal == 0)
                return error.ExecutedUnpackLostFrozenCache;
        }
    }
    try finalDatabase(allocator, root, architecture, proof);
}

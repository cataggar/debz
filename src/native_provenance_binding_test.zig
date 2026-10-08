//! Hermetic tamper coverage for issue #269. Each case settles a real
//! caller-owned `native_unpack.Runtime` attempt on a disposable root, then
//! changes or omits exactly one bound component and requires a typed refusal
//! from the public verifier, the acknowledgment boundary, or recovery. No case
//! may return a success-shaped summary or leave a second active operation.
//! `doc/native-recovery.md` maps every #86 acceptance component to these cases.

const std = @import("std");
const builtin = @import("builtin");

const e2e = @import("sha512_transaction_e2e_test.zig");
const content_digest = @import("content_digest.zig");
const exact_lock_v3 = @import("exact_lock_v3.zig");
const metadata_cache = @import("metadata_cache.zig");
const native_preparation = @import("native_preparation.zig");
const native_provenance = @import("native_provenance.zig");
const native_recovery = @import("native_recovery.zig");
const native_transaction_result = @import("native_transaction_result.zig");
const native_unpack = @import("native_unpack.zig");
const repository_acquisition = @import("repository_acquisition.zig");
const repository_refresh = @import("repository_refresh.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const root_operation_completion = @import("root_operation_completion.zig");
const solver = @import("solver.zig");
const transaction_executor = @import("transaction_executor.zig");

const testing = std.testing;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Runtime = native_unpack.Runtime;
const Digest = native_provenance.Digest;

const attempt_id: [32]u8 = @splat(0x69);
const second_attempt_id: [32]u8 = @splat(0x6a);

const Environment = struct {
    allocator: std.mem.Allocator,
    fixture: e2e.SignedRepository,
    transport: e2e.RepositoryTransport,
    metadata_tmp: testing.TmpDir,
    metadata: metadata_cache.Cache,
    refreshed: repository_refresh.AuthenticatedResult,
    plan: solver.Plan,
    lock: exact_lock_v3.OwnedLock,
    root_tmp: testing.TmpDir,
    root: root_fs.Root,
    install_root_buffer: [root_fs.maximum_path_bytes]u8,
    install_root_len: usize,
    locks: root_operation.TestLockBackend,
    coordinator: root_operation.Coordinator,
    mechanics: e2e.HermeticMechanics,
    request_sha256: [32]u8,
    policy: transaction_executor.Policy,
    policy_sha256: [32]u8,

    fn init(self: *Environment, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.fixture = try e2e.SignedRepository.init(allocator);
        errdefer self.fixture.deinit();
        self.transport = .{ .fixture = &self.fixture };
        self.metadata_tmp = testing.tmpDir(.{});
        errdefer self.metadata_tmp.cleanup();
        self.metadata = try metadata_cache.Cache.initFromDir(testing.io, self.metadata_tmp.dir, .{
            .max_object_bytes = 4 * 1024 * 1024,
        });
        errdefer self.metadata.deinit();
        self.refreshed = try repository_refresh.refreshAuthenticated(
            allocator,
            .{
                .id = e2e.repository_id,
                .base_uri = try repository_acquisition.Uri.parse(e2e.base_uri_text),
                .suite = "stable",
                .component = "main",
                .architecture = "amd64",
            },
            .{ .detached_release = .{
                .keyrings = .{ .one = .{ .bytes = self.fixture.keyring } },
                .accepted_primary_fingerprints = &.{self.fixture.fingerprint},
                .verification_time = e2e.verification_time,
            } },
            e2e.acquisitionPolicy(),
            e2e.refreshPolicy(),
            .{
                .acquisition = self.transport.dependencies(),
                .cache = &self.metadata,
                .clock = .{ .context = null, .nowUnixFn = e2e.refreshNow },
                .io = testing.io,
            },
        );
        errdefer self.refreshed.deinit();
        const repository = solver.RepositoryInput.fromRefresh(&self.refreshed, 500);
        var planning = try solver.planTransaction(allocator, .{
            .repositories = &.{repository},
            .installed = .{
                .records = &.{},
                .native_architecture = "amd64",
                .policies = &.{},
                .hold_authority = .explicit_policy,
            },
            .target_architecture = "amd64",
            .request = .{ .install = &.{.{ .name = "demo", .architecture = "amd64" }} },
            .output_schema_version = .v4,
        });
        self.plan = switch (planning) {
            .plan => |value| value,
            .failure => |*failure| {
                failure.deinit();
                return error.TestUnexpectedResult;
            },
        };
        errdefer self.plan.deinit();
        Sha256.hash("install demo", &self.request_sha256, .{});
        self.policy = .{ .conffile = .keep_existing, .exact_lock_verification = .locked_packages };
        self.policy_sha256 = transaction_executor.policyDigest(self.policy);
        const action = self.plan.actions[0];
        self.lock = try e2e.createLock(
            allocator,
            &self.refreshed,
            action,
            action.archive_identity.?,
            self.request_sha256,
            self.policy_sha256,
        );
        errdefer self.lock.deinit();
        self.root_tmp = testing.tmpDir(.{ .iterate = true });
        errdefer self.root_tmp.cleanup();
        self.root = root_fs.Root.init(testing.io, self.root_tmp.dir);
        try e2e.initializeRoot(self.root);
        self.install_root_len = try self.root_tmp.dir.realPath(testing.io, &self.install_root_buffer);
        self.locks = .{ .allocator = allocator };
        errdefer self.locks.deinit();
        self.coordinator = try root_operation.Coordinator.open(
            testing.io,
            self.root,
            self.installRoot(),
            self.locks.interface(),
        );
        self.mechanics = .{};
    }

    fn deinit(self: *Environment) void {
        self.locks.deinit();
        self.root_tmp.cleanup();
        self.lock.deinit();
        self.plan.deinit();
        self.refreshed.deinit();
        self.metadata.deinit();
        self.metadata_tmp.cleanup();
        self.fixture.deinit();
        self.* = undefined;
    }

    fn installRoot(self: *const Environment) []const u8 {
        return self.install_root_buffer[0..self.install_root_len];
    }

    fn external(self: *Environment) Runtime.ExternalMechanics {
        return .{ .context = &self.mechanics, .probe_helper_fn = e2e.HermeticMechanics.probe };
    }

    fn acquire(self: *Environment) !root_operation.Attempt {
        return self.coordinator.acquire(self.allocator, .{
            .backend = .native,
            .operation = .{ .package_transaction = .install },
            .request_sha256 = self.request_sha256,
            .policy_sha256 = self.policy_sha256,
            .target_architecture = "amd64",
            .attempt_id = attempt_id,
        });
    }

    /// Re-enters the durable record the way a restarted caller does after the
    /// process that owned the attempt disappeared.
    fn acquireRecovery(self: *Environment) !root_operation.Attempt {
        var observed = try self.coordinator.inspect(self.allocator) orelse return error.TestUnexpectedResult;
        defer observed.deinit();
        const record = observed.record;
        try testing.expectEqualSlices(u8, &attempt_id, &record.attempt_id);
        return self.coordinator.acquire(self.allocator, .{
            .intent = .recovery,
            .backend = .native,
            .operation = record.operation,
            .request_sha256 = record.request_sha256,
            .policy_sha256 = record.policy_sha256,
            .target_architecture = record.target_architecture,
            .foreign_architectures = record.foreign_architectures,
            .evidence = record.evidence(),
        });
    }

    /// The in-memory lock adapter models exclusion only; production supplies
    /// the persistent lock-file anchor that settled verification requires.
    fn publishLockAnchor(self: *Environment) !void {
        const path = try root_fs.Path.init(root_operation.lock_path);
        if (try self.root.entryIfExists(path) == null)
            try self.root.publishFile(path, "", .{});
    }

    fn verify(self: *Environment) anyerror!native_transaction_result.Summary {
        return native_transaction_result.verify(
            self.allocator,
            self.root,
            self.installRoot(),
            self.lock.lock,
            "amd64",
            self.locks.interface(),
        );
    }

    fn read(self: *Environment, relative: []const u8) ![]u8 {
        return self.root.readFileAlloc(self.allocator, try root_fs.Path.init(relative), 16 * 1024 * 1024);
    }

    fn readOptional(self: *Environment, relative: []const u8) !?[]u8 {
        return self.read(relative) catch |err| switch (err) {
            error.FileNotFound => null,
            else => err,
        };
    }

    /// Replaces bytes while keeping the existing mode, which the database
    /// generation binds alongside content.
    fn write(self: *Environment, relative: []const u8, bytes: []const u8) !void {
        const path = try root_fs.Path.init(relative);
        const existing = try self.root.metadataIfExists(path);
        try self.root.publishFile(path, bytes, .{
            .permissions = if (existing) |value| value.permissions else .fromMode(0o600),
            .durable = false,
        });
    }

    fn remove(self: *Environment, relative: []const u8) !void {
        self.root_tmp.dir.deleteFile(testing.io, relative) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    fn exists(self: *Environment, relative: []const u8) !bool {
        return try self.root.entryIfExists(try root_fs.Path.init(relative)) != null;
    }

    /// No active record, owner, or native execution evidence: any refusal
    /// left the root settled rather than opening a second operation.
    fn expectSettled(self: *Environment) !void {
        try testing.expect(!try self.exists(root_operation.record_path));
        try testing.expect(!try self.exists(root_operation.deferred_ack_path));
        try testing.expect(!try self.exists(native_recovery.intent_path));
        try testing.expect(!try Runtime.hasActiveEvidence(self.allocator, self.root));
    }

    /// A second, unrelated operation cannot start while the first is owed.
    fn expectSecondOperationRefused(self: *Environment) !void {
        var other_request: [32]u8 = undefined;
        Sha256.hash("remove demo", &other_request, .{});
        for ([_]root_operation.Operation{
            .{ .package_transaction = .install },
            .{ .package_transaction = .remove },
        }, [_][32]u8{ self.request_sha256, other_request }) |operation, request| {
            if (self.coordinator.acquire(self.allocator, .{
                .backend = .native,
                .operation = operation,
                .request_sha256 = request,
                .policy_sha256 = self.policy_sha256,
                .target_architecture = "amd64",
                .attempt_id = second_attempt_id,
            })) |second| {
                var owned = second;
                owned.release();
                return error.SecondOperationStarted;
            } else |err| try testing.expectEqual(error.RecoveryRequired, err);
        }
    }
};

const Settled = struct {
    receipt_bytes: []u8,
    completion_bytes: []u8,
    record_bytes: []u8,
    intent_bytes: []u8,
    receipt_digest: Digest,
    completion_digest: [32]u8,
    provenance_digest: [32]u8,
    recovered_phase_count: u64,

    fn deinit(self: *Settled, allocator: std.mem.Allocator) void {
        allocator.free(self.receipt_bytes);
        allocator.free(self.completion_bytes);
        allocator.free(self.record_bytes);
        allocator.free(self.intent_bytes);
        self.* = undefined;
    }
};

const Mode = enum { completed, recovered };

fn prepared(preparation: *native_preparation.ResultWithNoChanges) !*native_preparation.Prepared {
    return switch (preparation.*) {
        .prepared => |*value| value,
        else => error.TestUnexpectedResult,
    };
}

/// Expires the executing process's deadline once package database info is
/// published, so the attempt is lost after mutation has durably started.
const MutationClock = struct {
    root: root_fs.Root,

    fn now(context: ?*anyopaque) u64 {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        const path = root_fs.Path.init(mutation_marker) catch return 1;
        const found = self.root.entryIfExists(path) catch return 1;
        return if (found != null) 1 else 0;
    }
};

const mutation_marker = "var/lib/dpkg/info/demo.list";
const payload_path = "usr/share/sha512-e2e";

/// Loses the executing process mid-mutation: no receipt, no acknowledgment,
/// and the durable record stays owed to recovery.
fn interrupt(env: *Environment) !void {
    const allocator = env.allocator;
    var attempt = try env.acquire();
    defer attempt.release();
    var preparation = try Runtime.prepare(allocator, .{
        .attempt = &attempt,
        .plan = &env.plan,
        .exact_lock = &env.lock.lock,
        .archives = &.{env.fixture.archive},
        .policy = env.policy,
    });
    defer preparation.deinit();
    var clock: MutationClock = .{ .root = env.root };
    var report = try Runtime.execute(allocator, .{
        .attempt = &attempt,
        .prepared = try prepared(&preparation),
        .archives = &.{env.fixture.archive},
        .operation = .install,
        .deadline = .{ .context = &clock, .nowMsFn = MutationClock.now, .expires_at_ms = 1 },
        .external_mechanics = env.external(),
    });
    defer report.deinit();
    try testing.expectEqual(Runtime.Outcome.recovery_required, report.outcome);
    try testing.expect(report.receipt == null);
    try testing.expect(attempt.record().mutation_started);
    try testing.expectEqual(root_operation.State.recovery_required, attempt.record().state);
    try testing.expect(try env.exists(payload_path));
    try testing.expect(try Runtime.readCompletion(allocator, &attempt) == null);
    try testing.expectError(error.RecoveryEvidenceMissing, Runtime.acknowledge(allocator, &attempt, @splat('0')));
    try testing.expect(try Runtime.hasActiveEvidence(allocator, env.root));
}

/// Runs a real caller-owned native install to a settled, verified root. The
/// recovered mode loses the executing process mid-mutation and finishes
/// through a fresh recovery attempt.
fn settle(env: *Environment, mode: Mode) !Settled {
    const allocator = env.allocator;
    if (mode == .recovered) {
        try interrupt(env);
        try env.publishLockAnchor();
        try testing.expectError(error.OperationNotSettled, env.verify());
        try env.expectSecondOperationRefused();
        var attempt = try env.acquireRecovery();
        var held = true;
        defer if (held) attempt.release();
        var recovered = try Runtime.recoverWithExternalMechanics(allocator, &attempt, env.external());
        defer recovered.deinit();
        try testing.expectEqual(Runtime.Outcome.succeeded, recovered.outcome);
        return finish(env, &attempt, &held, recovered.receipt.?.document);
    }
    var attempt = try env.acquire();
    var held = true;
    defer if (held) attempt.release();
    var preparation = try Runtime.prepare(allocator, .{
        .attempt = &attempt,
        .plan = &env.plan,
        .exact_lock = &env.lock.lock,
        .archives = &.{env.fixture.archive},
        .policy = env.policy,
    });
    defer preparation.deinit();
    var report = try Runtime.execute(allocator, .{
        .attempt = &attempt,
        .prepared = try prepared(&preparation),
        .archives = &.{env.fixture.archive},
        .operation = .install,
        .external_mechanics = env.external(),
    });
    defer report.deinit();
    try testing.expectEqual(Runtime.Outcome.succeeded, report.outcome);
    return finish(env, &attempt, &held, report.receipt.?.document);
}

fn finish(
    env: *Environment,
    attempt: *root_operation.Attempt,
    held: *bool,
    receipt: native_provenance.Document,
) !Settled {
    const allocator = env.allocator;
    try testing.expectEqual(native_provenance.Outcome.succeeded, receipt.outcome);
    var current = try Runtime.readCompletion(allocator, attempt) orelse return error.TestUnexpectedResult;
    defer current.deinit();
    try testing.expectEqualSlices(u8, &receipt.digest_sha256, &current.document.digest_sha256);
    switch (attempt.record().state) {
        .mutating => try attempt.advance(allocator, .{ .state = .verifying, .phase = .verification }),
        .recovery_required => try attempt.beginRecovery(allocator, attempt.record().phase),
        .verifying, .recovering => {},
        else => return error.TestUnexpectedResult,
    }
    try attempt.complete(allocator, .succeeded);
    const receipt_digest = native_recovery.parseDigest(receipt.digest_sha256) orelse
        return error.TestUnexpectedResult;
    var completion = try root_operation_completion.create(allocator, .{
        .record = attempt.record(),
        .transaction_provenance = .{
            .status = .already_present,
            .schema = native_provenance.schema_id,
            .version = native_provenance.schema_version,
            .document_sha256 = receipt_digest,
            .detail = "verified terminal native receipt",
        },
        .journal = .{ .status = .absent, .detail = "native receipt binds native phase journals" },
        .discharge = .{
            .surface = .package_transaction,
            .operation = "install",
            .request_sha256 = env.request_sha256,
        },
    });
    defer completion.deinit();
    try root_operation_completion.Store.init(env.root).publish(allocator, completion.document);
    // Production records the historical provenance binding over the published
    // completion digest; neither value may stand in for the receipt digest.
    const provenance_digest = root_operation.provenanceDigest(attempt.record(), .{
        .outcome = .succeeded,
        .document_sha256 = completion.document.digest_sha256,
        .journal_archived = false,
    });
    try attempt.publishProvenance(allocator, provenance_digest);
    try testing.expect(!std.mem.eql(u8, &receipt_digest, &completion.document.digest_sha256));
    try testing.expect(!std.mem.eql(u8, &receipt_digest, &provenance_digest));
    try testing.expect(!std.mem.eql(u8, &completion.document.digest_sha256, &provenance_digest));

    for ([_][32]u8{ completion.document.digest_sha256, provenance_digest }) |substitute|
        try testing.expectError(
            error.InvalidRecoveryProvenance,
            Runtime.acknowledge(allocator, attempt, native_provenance.hexDigest(substitute)),
        );
    var stale = receipt.digest_sha256;
    stale[0] = if (stale[0] == '0') '1' else '0';
    try testing.expectError(error.InvalidRecoveryProvenance, Runtime.acknowledge(allocator, attempt, stale));
    try testing.expect(try Runtime.hasActiveEvidence(allocator, env.root));
    try expectCallerPayloadBound(env, attempt, receipt.digest_sha256);

    const record_bytes = try env.read(root_operation.record_path);
    errdefer allocator.free(record_bytes);
    const intent_bytes = try env.read(native_recovery.intent_path);
    errdefer allocator.free(intent_bytes);
    try Runtime.acknowledge(allocator, attempt, receipt.digest_sha256);
    try testing.expect(!try Runtime.hasActiveEvidence(allocator, env.root));
    try attempt.clear();
    attempt.release();
    held.* = false;
    try env.publishLockAnchor();
    try env.expectSettled();
    const receipt_bytes = try env.read(native_provenance.document_path);
    errdefer allocator.free(receipt_bytes);
    const completion_bytes = try env.read(root_operation_completion.document_path);
    errdefer allocator.free(completion_bytes);
    return .{
        .receipt_bytes = receipt_bytes,
        .completion_bytes = completion_bytes,
        .record_bytes = record_bytes,
        .intent_bytes = intent_bytes,
        .receipt_digest = receipt.digest_sha256,
        .completion_digest = completion.document.digest_sha256,
        .provenance_digest = provenance_digest,
        .recovered_phase_count = receipt.recovered_phase_count,
    };
}

/// The held caller's in-attempt verification binds the live payload before
/// acknowledgment: a changed payload is refused and nothing is acknowledged.
fn expectCallerPayloadBound(env: *Environment, attempt: *root_operation.Attempt, receipt_digest: Digest) !void {
    const allocator = env.allocator;
    {
        var verified = try native_transaction_result.verifyCallerSuccess(allocator, attempt, receipt_digest);
        verified.deinit();
    }
    const original = try env.read(payload_path);
    defer allocator.free(original);
    const changed = try allocator.dupe(u8, original);
    defer allocator.free(changed);
    changed[0] ^= 0x01;
    try env.write(payload_path, changed);
    try testing.expectError(
        error.LivePayloadChanged,
        native_transaction_result.verifyCallerSuccess(allocator, attempt, receipt_digest),
    );
    {
        // The refusal describes the changed path, its recorded bytes and its
        // installed owner, so an operator can restore exactly that.
        var change: ?native_recovery.SettledPayloadChange = null;
        defer if (change) |*value| value.deinit();
        try testing.expectError(
            error.LivePayloadChanged,
            native_transaction_result.verifyCallerSuccessReporting(allocator, attempt, receipt_digest, &change),
        );
        const found = change orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(payload_path, found.path);
        try testing.expectEqual(native_recovery.SettledPayloadChange.Reason.content_changed, found.reason);
        try testing.expectEqual(native_recovery.ManagedKind.regular, found.expected_kind);
        var original_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(original, &original_digest, .{});
        try testing.expectEqualSlices(u8, &native_recovery.hexDigest(original_digest), &found.expected_sha256.?);
        try testing.expectEqual(@as(usize, 1), found.owner_count);
        const owner = found.owner orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings("demo", owner.package);
        try testing.expectEqualStrings("1.0", owner.version);
        try testing.expectEqualStrings("amd64", owner.architecture);
    }
    try testing.expect(try Runtime.hasActiveEvidence(allocator, env.root));
    try testing.expect(try env.exists(root_operation.record_path));
    try env.write(payload_path, original);
    var verified = try native_transaction_result.verifyCallerSuccess(allocator, attempt, receipt_digest);
    verified.deinit();
}

fn flipHex(value: []u8) void {
    value[0] = if (value[0] == '0') '1' else '0';
}

/// Reconstructs the completed record a completion statement binds so a case
/// can publish a statement for a different receipt or record field.
fn recordFrom(outer: root_operation_completion.Document) root_operation.Record {
    return .{
        .attempt_id = outer.attempt_id,
        .generation = outer.record_generation,
        .install_root = outer.install_root,
        .root_identity_sha256 = outer.root_identity_sha256,
        .backend = outer.backend,
        .operation = outer.operation,
        .state = .completed,
        .phase = outer.phase,
        .step = outer.step,
        .mutation_started = outer.mutation_started,
        .outcome = outer.outcome,
        .provenance = .pending,
        .provenance_sha256 = null,
        .authorization_sha256 = outer.authorization_sha256,
        .program_sha256 = outer.program_sha256,
        .plan_sha256 = outer.plan_sha256,
        .exact_lock = outer.exact_lock,
        .database_generation_sha256 = outer.database_generation_sha256,
        .artifact_evidence_sha256 = outer.artifact_evidence_sha256,
        .request_sha256 = outer.request_sha256,
        .policy_sha256 = outer.policy_sha256,
        .target_architecture = outer.target_architecture,
        .foreign_architectures = outer.foreign_architectures,
        .reserved_unix = outer.reserved_unix,
        .updated_unix = outer.updated_unix,
        .digest_sha256 = outer.record_digest_sha256,
    };
}

const Matrix = struct {
    env: *Environment,
    settled: *const Settled,
    cases: usize = 0,
    failures: usize = 0,

    fn receipt(self: *Matrix) !native_provenance.OwnedDocument {
        return native_provenance.decode(self.env.allocator, self.settled.receipt_bytes);
    }

    fn completion(self: *Matrix) !root_operation_completion.OwnedDocument {
        return root_operation_completion.decode(
            self.env.allocator,
            self.settled.completion_bytes,
            root_operation_completion.maximum_document_bytes,
        );
    }

    fn restore(self: *Matrix) !void {
        const env = self.env;
        try env.write(native_provenance.document_path, self.settled.receipt_bytes);
        try env.write(root_operation_completion.document_path, self.settled.completion_bytes);
        try env.remove(root_operation_completion.legacy_document_path);
        try env.remove(root_operation.record_path);
        try env.remove(root_operation.deferred_ack_path);
        try env.remove(native_recovery.intent_path);
        try env.expectSettled();
    }

    fn expectVerified(self: *Matrix) !void {
        const summary = try self.env.verify();
        try testing.expectEqualSlices(
            u8,
            &(native_recovery.parseDigest(self.settled.receipt_digest).?),
            &summary.transaction_digest_sha256,
        );
        try testing.expectEqualSlices(u8, &self.settled.completion_digest, &summary.completion_digest_sha256);
        try testing.expectEqualSlices(u8, &self.env.lock.lock.digest_sha256, &summary.lock_sha256);
        try testing.expectEqual(@as(usize, 1), summary.package_count);
    }

    /// Records a mismatch instead of stopping so one run reports every case.
    fn refused(self: *Matrix, label: []const u8, expected: anyerror, result: anytype) !void {
        self.cases += 1;
        if (result) |_| {
            std.debug.print("{s}: tampered evidence produced a success-shaped result\n", .{label});
            self.failures += 1;
        } else |err| if (err != expected) {
            std.debug.print("{s}: expected {s}, observed {s}\n", .{ label, @errorName(expected), @errorName(err) });
            self.failures += 1;
        }
    }

    fn verifyRefused(self: *Matrix, label: []const u8, expected: anyerror) !void {
        try self.refused(label, expected, self.env.verify());
        try self.restore();
    }

    fn publishCompletion(self: *Matrix, record: root_operation.Record, provenance: root_operation_completion.TransactionProvenance) !void {
        const allocator = self.env.allocator;
        var original = try self.completion();
        defer original.deinit();
        var rebuilt = try root_operation_completion.create(allocator, .{
            .record = record,
            .transaction_provenance = provenance,
            .journal = original.document.journal,
            .discharge = original.document.discharge,
        });
        defer rebuilt.deinit();
        const bytes = try rebuilt.document.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (rebuilt.document.version == root_operation_completion.legacy_schema_version) {
            try self.env.remove(root_operation_completion.document_path);
            try self.env.write(root_operation_completion.legacy_document_path, bytes);
        } else try self.env.write(root_operation_completion.document_path, bytes);
    }

    fn provenanceFor(self: *Matrix, outer: root_operation_completion.Document, receipt_digest: ?[32]u8) root_operation_completion.TransactionProvenance {
        _ = self;
        var provenance = outer.transaction_provenance;
        provenance.document_sha256 = receipt_digest;
        return provenance;
    }

    /// Reseals a changed receipt and republishes a completion that binds its
    /// new digest, so only the changed receipt field can cause the refusal.
    fn receiptCase(self: *Matrix, label: []const u8, expected: anyerror, document: native_provenance.Document) !void {
        const allocator = self.env.allocator;
        var changed = document;
        native_provenance.seal(&changed);
        const bytes = try changed.canonicalJson(allocator);
        defer allocator.free(bytes);
        try self.env.write(native_provenance.document_path, bytes);
        var outer = try self.completion();
        defer outer.deinit();
        try self.publishCompletion(
            recordFrom(outer.document),
            self.provenanceFor(outer.document, native_recovery.parseDigest(changed.digest_sha256).?),
        );
        try self.verifyRefused(label, expected);
    }

    fn completionCase(self: *Matrix, label: []const u8, expected: anyerror, record: root_operation.Record, provenance: root_operation_completion.TransactionProvenance) !void {
        try self.publishCompletion(record, provenance);
        try self.verifyRefused(label, expected);
    }

    fn fileCase(self: *Matrix, label: []const u8, expected: anyerror, relative: []const u8, replacement: ?[]const u8) !void {
        const allocator = self.env.allocator;
        const original = try self.env.readOptional(relative);
        defer if (original) |bytes| allocator.free(bytes);
        const metadata = try self.env.root.metadataIfExists(try root_fs.Path.init(relative));
        if (replacement) |bytes| try self.env.write(relative, bytes) else try self.env.remove(relative);
        try self.refused(label, expected, self.env.verify());
        if (original) |bytes| {
            try self.env.remove(relative);
            try self.env.root.publishFile(try root_fs.Path.init(relative), bytes, .{
                .permissions = metadata.?.permissions,
                .durable = false,
            });
        } else try self.env.remove(relative);
        try self.restore();
    }

    fn finish(self: *Matrix) !void {
        try self.expectVerified();
        if (self.failures != 0) {
            std.debug.print("{d} of {d} provenance tamper cases were not refused as bound\n", .{ self.failures, self.cases });
            return error.UnboundProvenanceComponent;
        }
    }

    /// Replaces the live payload with another kind or mode, then restores
    /// the original bytes and mode.
    fn payloadCase(self: *Matrix, replacement: PayloadReplacement, original: []const u8) !void {
        const env = self.env;
        const path = try root_fs.Path.init(payload_path);
        const metadata = (try env.root.metadataIfExists(path)).?;
        const entry = try env.root.entry(path);
        const copy = try root_fs.Path.init(payload_path ++ ".real");
        try env.remove(payload_path);
        switch (replacement) {
            // The link names identical bytes; only a following reader would
            // accept it.
            .symlink => {
                try env.root.publishFile(copy, original, .{ .permissions = metadata.permissions, .durable = false });
                try env.root.createSymbolicLink(path, "sha512-e2e.real");
            },
            .directory => try env.root.createDirectory(path, root_fs.default_directory_permissions),
            .mode => try env.root.publishFile(path, original, .{
                .permissions = .fromMode(if (entry.mode & 0o7777 == 0o600) 0o640 else 0o600),
                .durable = false,
            }),
        }
        try self.refused(switch (replacement) {
            .symlink => "live payload replaced by symlink",
            .directory => "live payload replaced by directory",
            .mode => "live payload mode",
        }, error.LivePayloadChanged, env.verify());
        switch (replacement) {
            .symlink => {
                try env.remove(payload_path);
                try env.remove(payload_path ++ ".real");
            },
            .directory => try env.root.removeDirectory(path),
            .mode => try env.remove(payload_path),
        }
        try env.root.publishFile(path, original, .{ .permissions = metadata.permissions, .durable = false });
        try self.restore();
    }
};

const PayloadReplacement = enum { symlink, directory, mode };

fn omittedEvidenceError(kind: native_provenance.EvidenceKind) anyerror {
    return switch (kind) {
        .authorization, .program, .intent, .progress, .managed_state, .trigger_events => error.InvalidEvidence,
        else => error.EvidenceMissing,
    };
}

/// Changes or omits every component bound by a settled success and requires
/// the exact typed refusal, then proves the untouched evidence still verifies.
fn tamperSettled(env: *Environment, settled: *const Settled) !void {
    const allocator = env.allocator;
    var matrix: Matrix = .{ .env = env, .settled = settled };
    try matrix.expectVerified();

    {
        // The synthetic record reproduces the published statement exactly, so
        // every rebuilt completion below differs only in its tampered field.
        var outer = try matrix.completion();
        defer outer.deinit();
        var rebuilt = try root_operation_completion.create(allocator, .{
            .record = recordFrom(outer.document),
            .transaction_provenance = outer.document.transaction_provenance,
            .journal = outer.document.journal,
            .discharge = outer.document.discharge,
        });
        defer rebuilt.deinit();
        const bytes = try rebuilt.document.canonicalJson(allocator);
        defer allocator.free(bytes);
        try testing.expectEqualStrings(settled.completion_bytes, bytes);
    }

    // Archive identities, exact lock, request/policy, authorization/program,
    // database generations, final state, progress, scripts, triggers, and
    // attempt/owner identity bound by the receipt.
    inline for (.{
        .{ "exact_lock_sha256", error.EvidenceMismatch },
        .{ "artifact_evidence_sha256", error.EvidenceMismatch },
        .{ "authorization_sha256", error.EvidenceMismatch },
        .{ "program_sha256", error.EvidenceMismatch },
        .{ "request_sha256", error.EvidenceMismatch },
        .{ "policy_sha256", error.EvidenceMismatch },
        .{ "initial_database_generation_sha256", error.EvidenceMismatch },
        .{ "final_database_generation_sha256", error.FinalStateMismatch },
        .{ "final_state_sha256", error.FinalStateMismatch },
        .{ "execution_intent_sha256", error.EvidenceMismatch },
        .{ "progress_head_sha256", error.EvidenceMismatch },
        .{ "script_outcomes_sha256", error.EvidenceMismatch },
        .{ "trigger_evidence_sha256", error.EvidenceMismatch },
        .{ "attempt_id", error.InvalidDocument },
    }) |case| {
        var owned = try matrix.receipt();
        defer owned.deinit();
        var document = owned.document;
        flipHex(&@field(document, case[0]));
        try matrix.receiptCase("receipt." ++ case[0], case[1], document);
    }
    inline for (.{
        .{ "progress_record_count", error.InvalidRecoveryProgress },
        .{ "recovered_phase_count", error.InvalidRecoveryProgress },
        .{ "root_inode", error.InvalidCompletion },
    }) |case| {
        var owned = try matrix.receipt();
        defer owned.deinit();
        var document = owned.document;
        @field(document, case[0]) += 1;
        try matrix.receiptCase("receipt." ++ case[0], case[1], document);
    }
    for ([_]native_provenance.Outcome{ .failed, .recovery_required }) |outcome| {
        var owned = try matrix.receipt();
        defer owned.deinit();
        var document = owned.document;
        document.outcome = outcome;
        try matrix.receiptCase("receipt.outcome", error.TransactionNotSuccessful, document);
    }
    {
        var owned = try matrix.receipt();
        defer owned.deinit();
        var document = owned.document;
        document.operation = .{ .package_transaction = .remove };
        try matrix.receiptCase("receipt.operation", error.InvalidCompletion, document);
    }
    // Baseline-only versions are malformed on this non-baseline receipt.
    inline for (.{
        .{ "exact_lock_version", error.InvalidDocument },
        .{ "progress_version", error.InvalidCompletion },
        .{ "execution_intent_version", error.InvalidCompletion },
        .{ "program_version", error.InvalidDocument },
    }) |case| {
        var owned = try matrix.receipt();
        defer owned.deinit();
        var document = owned.document;
        var authority = document.authority.?;
        @field(authority, case[0]) += 1;
        document.authority = authority;
        try matrix.receiptCase("receipt.authority." ++ case[0], case[1], document);
    }

    // Retained evidence: every entry omitted, re-pointed at a different
    // digest, or changed on disk underneath an unchanged receipt.
    var original = try matrix.receipt();
    defer original.deinit();
    const files = original.document.evidence_files;
    try testing.expect(files.len >= 6);
    for (files, 0..) |omitted, index| {
        const remaining = try allocator.alloc(native_provenance.EvidenceFile, files.len - 1);
        defer allocator.free(remaining);
        @memcpy(remaining[0..index], files[0..index]);
        @memcpy(remaining[index..], files[index + 1 ..]);
        var document = original.document;
        document.evidence_files = remaining;
        document.evidence_files_sha256 = native_provenance.evidenceDigest(remaining);
        const label = try std.fmt.allocPrint(allocator, "receipt.evidence_files[{s}] omitted", .{@tagName(omitted.kind)});
        defer allocator.free(label);
        try matrix.receiptCase(label, omittedEvidenceError(omitted.kind), document);
    }
    for (files, 0..) |changed, index| {
        const altered = try allocator.dupe(native_provenance.EvidenceFile, files);
        defer allocator.free(altered);
        flipHex(&altered[index].sha256);
        var document = original.document;
        document.evidence_files = altered;
        document.evidence_files_sha256 = native_provenance.evidenceDigest(altered);
        const label = try std.fmt.allocPrint(allocator, "receipt.evidence_files[{s}].sha256", .{@tagName(changed.kind)});
        defer allocator.free(label);
        try matrix.receiptCase(label, error.EvidenceChanged, document);
    }
    for (files) |changed| {
        const bytes = try env.read(changed.path);
        defer allocator.free(bytes);
        const altered = try allocator.dupe(u8, bytes);
        defer allocator.free(altered);
        altered[altered.len - 1] ^= 0x01;
        const label = try std.fmt.allocPrint(allocator, "retained {s} bytes", .{@tagName(changed.kind)});
        defer allocator.free(label);
        try matrix.fileCase(label, error.EvidenceChanged, changed.path, altered);
    }

    // Completion v2 fields bound to the attempt record, receipt, and program.
    var outer_owned = try matrix.completion();
    defer outer_owned.deinit();
    const outer = outer_owned.document;
    const base = recordFrom(outer);
    const receipt_digest = native_recovery.parseDigest(settled.receipt_digest).?;
    for ([_]struct { label: []const u8, digest: [32]u8 }{
        .{ .label = "completion.transaction_provenance=completion digest", .digest = settled.completion_digest },
        .{ .label = "completion.transaction_provenance=provenanceDigest", .digest = settled.provenance_digest },
    }) |case|
        try matrix.completionCase(case.label, error.EvidenceMismatch, base, matrix.provenanceFor(outer, case.digest));
    try matrix.completionCase("completion.transaction_provenance unavailable", error.InvalidCompletion, base, .{
        .status = .unavailable,
        .detail = "receipt withheld",
    });
    inline for (.{
        .{ "database_generation_sha256", error.InvalidCompletion },
        .{ "artifact_evidence_sha256", error.InvalidCompletion },
        .{ "authorization_sha256", error.InvalidCompletion },
        .{ "program_sha256", error.InvalidCompletion },
        .{ "plan_sha256", error.InvalidCompletion },
    }) |case| {
        var record = base;
        var digest = @field(record, case[0]).?;
        digest[0] ^= 1;
        @field(record, case[0]) = digest;
        try matrix.completionCase("completion." ++ case[0], case[1], record, matrix.provenanceFor(outer, receipt_digest));
    }
    inline for (.{ "attempt_id", "request_sha256", "policy_sha256" }) |name| {
        var record = base;
        @field(record, name)[0] ^= 1;
        try matrix.completionCase("completion." ++ name, error.EvidenceMismatch, record, matrix.provenanceFor(outer, receipt_digest));
    }
    {
        var record = base;
        var binding = record.exact_lock.?;
        binding.digest_sha256[0] ^= 1;
        record.exact_lock = binding;
        try matrix.completionCase("completion.exact_lock", error.LockEvidenceMismatch, record, matrix.provenanceFor(outer, receipt_digest));
    }
    {
        var record = base;
        record.outcome = .failed_after_mutation;
        try matrix.completionCase("completion.outcome", error.TransactionNotSuccessful, record, matrix.provenanceFor(outer, receipt_digest));
    }
    {
        var record = base;
        record.operation = .{ .package_transaction = .remove };
        try matrix.completionCase("completion.operation", error.InvalidCompletion, record, matrix.provenanceFor(outer, receipt_digest));
    }

    // Live final state: database status, package info, and trigger claims.
    const status = try env.read("var/lib/dpkg/status");
    defer allocator.free(status);
    const installed = "Status: install ok installed\n";
    const at = std.mem.indexOf(u8, status, installed) orelse return error.TestUnexpectedResult;
    const half = try std.mem.concat(allocator, u8, &.{ status[0..at], "Status: install ok half-configured\n", status[at + installed.len ..] });
    defer allocator.free(half);
    try matrix.fileCase("live dpkg status", error.FinalStateMismatch, "var/lib/dpkg/status", half);
    const list = try env.read("var/lib/dpkg/info/demo.list");
    defer allocator.free(list);
    const extended = try std.mem.concat(allocator, u8, &.{ list, "/usr/share/forged\n" });
    defer allocator.free(extended);
    try matrix.fileCase("live dpkg info list", error.FinalStateMismatch, "var/lib/dpkg/info/demo.list", extended);
    try matrix.fileCase("live pending trigger claim", error.FinalStateMismatch, "var/lib/dpkg/triggers/Unincorp", "forged-trigger demo\n");

    // Live managed payload: the final managed snapshot binds each covered
    // path's kind, mode, owner and bytes, not only the database records.
    const payload = try env.read(payload_path);
    defer allocator.free(payload);
    const flipped = try allocator.dupe(u8, payload);
    defer allocator.free(flipped);
    flipped[0] ^= 0x01;
    try matrix.fileCase("live payload bytes", error.LivePayloadChanged, payload_path, flipped);
    const grown = try std.mem.concat(allocator, u8, &.{ payload, "forged\n" });
    defer allocator.free(grown);
    try matrix.fileCase("live payload resized", error.LivePayloadChanged, payload_path, grown);
    try matrix.fileCase("live payload removed", error.LivePayloadChanged, payload_path, null);
    for (std.enums.values(PayloadReplacement)) |replacement|
        try matrix.payloadCase(replacement, payload);
    {
        // Settlement does not claim unrelated members of shared directories.
        const unrelated = "usr/share/administrator-file";
        try env.write(unrelated, "administrator\n");
        try matrix.expectVerified();
        try env.remove(unrelated);
    }
    {
        // Each verify variant shares the live payload binding.
        try env.write(payload_path, flipped);
        var outer_live = try matrix.completion();
        defer outer_live.deinit();
        var receipt_owned = try matrix.receipt();
        defer receipt_owned.deinit();
        try matrix.refused("caller verify of live payload", error.LivePayloadChanged, native_transaction_result.verifyForCaller(
            allocator,
            env.root,
            env.installRoot(),
            env.lock.lock,
            "amd64",
            .{
                .operation = .install,
                .request_sha256 = env.request_sha256,
                .policy_sha256 = env.policy_sha256,
                .foreign_architectures = &.{},
                .completion = try native_transaction_result.describeCompletion(outer_live.document, receipt_owned.document, .cleared),
            },
            env.locks.interface(),
        ));
        try env.write(payload_path, payload);
        try matrix.restore();
    }

    // Settlement and terminal acknowledgment: evidence must be complete and
    // no active record, owner, or native intent may survive acknowledgment.
    try matrix.fileCase("completion missing", error.CompletionMissing, root_operation_completion.document_path, null);
    try matrix.fileCase("receipt missing", error.ReceiptMissing, native_provenance.document_path, null);
    try matrix.fileCase("root-operation record reinstated", error.OperationNotSettled, root_operation.record_path, settled.record_bytes);
    try matrix.fileCase("native intent reinstated", error.OperationNotSettled, native_recovery.intent_path, settled.intent_bytes);
    try matrix.fileCase("deferred owner reinstated", error.OperationNotSettled, root_operation.deferred_ack_path, "{}\n");

    // Caller-supplied authority: archive identity, architecture, conffile
    // choice, operation, and the returned completion evidence.
    {
        const action = env.plan.actions[0];
        var wrong_sha512 = action.archive_identity.?.digests.sha512.?;
        wrong_sha512[0] ^= 0xff;
        var forged = try e2e.createLock(
            allocator,
            &env.refreshed,
            action,
            try content_digest.Identity.init(.{ .sha512 = wrong_sha512 }, .sha512),
            env.request_sha256,
            env.policy_sha256,
        );
        defer forged.deinit();
        try matrix.refused("caller lock archive identity", error.LockEvidenceMismatch, native_transaction_result.verify(
            allocator,
            env.root,
            env.installRoot(),
            forged.lock,
            "amd64",
            env.locks.interface(),
        ));
        try matrix.refused("caller architecture", error.ArchitectureMismatch, native_transaction_result.verify(
            allocator,
            env.root,
            env.installRoot(),
            env.lock.lock,
            "arm64",
            env.locks.interface(),
        ));
    }
    const described = try native_transaction_result.describeCompletion(outer, original.document, .cleared);
    const caller: native_transaction_result.ExpectedCaller = .{
        .operation = .install,
        .request_sha256 = env.request_sha256,
        .policy_sha256 = env.policy_sha256,
        .foreign_architectures = &.{},
        .completion = described,
    };
    _ = try native_transaction_result.verifyForCaller(allocator, env.root, env.installRoot(), env.lock.lock, "amd64", caller, env.locks.interface());
    {
        var wrong = caller;
        wrong.policy_sha256 = transaction_executor.policyDigest(.{
            .conffile = .use_package_version,
            .exact_lock_verification = .locked_packages,
        });
        try matrix.refused("caller conffile choice", error.CallerRequestMismatch, native_transaction_result.verifyForCaller(
            allocator,
            env.root,
            env.installRoot(),
            env.lock.lock,
            "amd64",
            wrong,
            env.locks.interface(),
        ));
        wrong = caller;
        wrong.operation = .remove;
        try matrix.refused("caller operation", error.CallerRequestMismatch, native_transaction_result.verifyForCaller(
            allocator,
            env.root,
            env.installRoot(),
            env.lock.lock,
            "amd64",
            wrong,
            env.locks.interface(),
        ));
        var substituted = described;
        substituted.transaction_digest_sha256 = settled.completion_digest;
        wrong = caller;
        wrong.completion = substituted;
        try matrix.refused("caller completion transaction digest", error.CompletionResultMismatch, native_transaction_result.verifyForCaller(
            allocator,
            env.root,
            env.installRoot(),
            env.lock.lock,
            "amd64",
            wrong,
            env.locks.interface(),
        ));
        var unsettled = original.document;
        unsettled.outcome = .recovery_required;
        try matrix.refused(
            "describe recovery_required receipt",
            error.InvalidNativeCompletionEvidence,
            native_transaction_result.describeCompletion(outer, unsettled, .cleared),
        );
    }
    try matrix.finish();
}

test "native_provenance_binding.test.completed attempt binds every acceptance component" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var env: Environment = undefined;
    try env.init(testing.allocator);
    defer env.deinit();
    var settled = try settle(&env, .completed);
    defer settled.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), settled.recovered_phase_count);
    try tamperSettled(&env, &settled);
}

test "native_provenance_binding.test.recovered attempt binds every acceptance component" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var env: Environment = undefined;
    try env.init(testing.allocator);
    defer env.deinit();
    var settled = try settle(&env, .recovered);
    defer settled.deinit(testing.allocator);
    try testing.expect(settled.recovered_phase_count >= 1);
    var receipt = try native_provenance.decode(testing.allocator, settled.receipt_bytes);
    defer receipt.deinit();
    try testing.expectEqualStrings("recovered", receipt.document.detail);
    try tamperSettled(&env, &settled);
}

test "native_provenance_binding.test.recovery_required attempt keeps typed evidence without success-shaped settlement" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;
    var env: Environment = undefined;
    try env.init(allocator);
    defer env.deinit();
    try interrupt(&env);
    try env.publishLockAnchor();

    // A filesystem decision changed while the attempt was owed to recovery.
    const installed = try env.read(payload_path);
    defer allocator.free(installed);
    try env.write(payload_path, "forged filesystem decision\n");
    var attempt = try env.acquireRecovery();
    var held = true;
    defer if (held) attempt.release();
    {
        var report = try Runtime.recoverWithExternalMechanics(allocator, &attempt, env.external());
        defer report.deinit();
        try testing.expectEqual(Runtime.Outcome.recovery_required, report.outcome);
        try testing.expectEqualStrings("managed_state_changed", report.detail);
        try testing.expect(report.receipt == null);
    }
    try testing.expectEqual(root_operation.State.recovery_required, attempt.record().state);
    const receipt_bytes = try env.read(native_provenance.document_path);
    defer allocator.free(receipt_bytes);
    var receipt = try native_provenance.decode(allocator, receipt_bytes);
    defer receipt.deinit();
    try testing.expectEqual(native_provenance.Outcome.recovery_required, receipt.document.outcome);
    try testing.expectEqualStrings("managed_state_changed", receipt.document.detail);
    try testing.expectEqualSlices(u8, &native_provenance.hexDigest(attempt_id), &receipt.document.attempt_id);
    try native_provenance.verifyEvidence(allocator, env.root, receipt.document);

    // The typed requirement is not terminal evidence: it cannot be read as a
    // completion, acknowledged, or exposed as a caller completion.
    try testing.expect(try Runtime.readCompletion(allocator, &attempt) == null);
    try testing.expectError(
        error.RecoveryEvidenceMissing,
        Runtime.acknowledge(allocator, &attempt, receipt.document.digest_sha256),
    );
    try testing.expectError(
        error.ReceiptMissing,
        native_transaction_result.verifyCallerSuccess(allocator, &attempt, receipt.document.digest_sha256),
    );
    try testing.expectError(
        error.ReceiptMissing,
        native_transaction_result.verifyCallerFailure(allocator, &attempt, receipt.document.digest_sha256),
    );
    try testing.expect(try Runtime.hasActiveEvidence(allocator, env.root));

    // Resealing the requirement as a terminal outcome keeps every retained
    // evidence digest valid, but the retained progress has no terminal
    // provenance record, so neither recovery nor acknowledgment may settle.
    for ([_]native_provenance.Outcome{ .succeeded, .failed }) |outcome| {
        var forged = receipt.document;
        forged.outcome = outcome;
        forged.detail = "recovered";
        native_provenance.seal(&forged);
        const forged_bytes = try forged.canonicalJson(allocator);
        defer allocator.free(forged_bytes);
        try env.write(native_provenance.document_path, forged_bytes);
        try native_provenance.verifyEvidence(allocator, env.root, forged);
        try testing.expectError(error.InvalidRecoveryProvenance, Runtime.readCompletion(allocator, &attempt));
        try testing.expectError(
            error.InvalidRecoveryProvenance,
            Runtime.recoverWithExternalMechanics(allocator, &attempt, env.external()),
        );
        try testing.expectError(
            error.InvalidRecoveryProvenance,
            Runtime.acknowledge(allocator, &attempt, forged.digest_sha256),
        );
        try testing.expectError(
            error.InvalidRecoveryProvenance,
            native_transaction_result.verifyCallerSuccess(allocator, &attempt, forged.digest_sha256),
        );
        try testing.expectError(
            error.InvalidRecoveryProvenance,
            native_transaction_result.verifyCallerFailure(allocator, &attempt, forged.digest_sha256),
        );
        try testing.expect(try Runtime.hasActiveEvidence(allocator, env.root));
        try testing.expectEqual(root_operation.State.recovery_required, attempt.record().state);
    }
    try env.write(native_provenance.document_path, receipt_bytes);

    attempt.release();
    held = false;
    try testing.expectError(error.OperationNotSettled, env.verify());
    try env.expectSecondOperationRefused();

    // The owed attempt still owns the root after a restart: the changed
    // decision is reported again rather than replaced by success.
    attempt = try env.acquireRecovery();
    held = true;
    {
        var report = try Runtime.recoverWithExternalMechanics(allocator, &attempt, env.external());
        defer report.deinit();
        try testing.expectEqual(Runtime.Outcome.recovery_required, report.outcome);
        try testing.expect(report.receipt == null);
    }
    try testing.expect(try Runtime.readCompletion(allocator, &attempt) == null);
    try testing.expect(try Runtime.hasActiveEvidence(allocator, env.root));
}

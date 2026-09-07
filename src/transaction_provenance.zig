const std = @import("std");
const exact_lock = @import("exact_lock.zig");
const transaction_executor = @import("transaction_executor.zig");

pub const schema_id = "https://debz.dev/schema/transaction-result-v1";
pub const schema_version: u32 = 1;
pub const maximum_document_bytes: usize = 32 * 1024 * 1024;

pub const Outcome = enum { succeeded, failed, interrupted, recovery_required };
pub const VerificationStatus = enum { exact_match, mismatch, not_run };

pub const RepositoryEvidence = struct {
    source_config_id: [64]u8,
    snapshot_sha256: [32]u8,
    release_sha256: [32]u8,
    signature_sha256: ?[32]u8,
    metadata_sha256: [32]u8,
    signer_fingerprints: []const [20]u8,
    signature_verified: bool,
};

pub const PackageEvidence = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    repository_id: [64]u8,
    repository_snapshot_sha256: [32]u8,
    package_sha256: [32]u8,
    cas_sha256: [32]u8,
    declared_size: u64,
};

pub const EnvironmentEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const CommandEvidence = struct {
    phase: []const u8,
    package: ?[]const u8,
    argv: []const []const u8,
    environment: []const EnvironmentEntry,
    command_sha256: [32]u8,
    artifact_sha256: ?[32]u8,
};

pub const JournalStep = struct {
    sequence: usize,
    boundary: []const u8,
    state: []const u8,
    command_index: usize,
    recovered: bool,
};

pub const FinalVerification = struct {
    status: VerificationStatus,
    installed_state_sha256: ?[32]u8,
    package_origins_sha256: ?[32]u8,
    detail: []const u8,
};

pub const Input = struct {
    target_architecture: []const u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    executor_policy_sha256: [32]u8,
    plan_sha256: [32]u8,
    lock_sha256: [32]u8,
    repositories: []const RepositoryEvidence,
    packages: []const PackageEvidence,
    commands: []const CommandEvidence,
    journal_steps: []const JournalStep,
    recovery_steps: []const JournalStep = &.{},
    final_verification: FinalVerification,
    outcome: Outcome,
    diagnostic: []const u8 = "",
};

pub const Result = struct {
    target_architecture: []const u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    executor_policy_sha256: [32]u8,
    plan_sha256: [32]u8,
    lock_sha256: [32]u8,
    repositories: []const RepositoryEvidence,
    packages: []const PackageEvidence,
    commands: []const CommandEvidence,
    journal_steps: []const JournalStep,
    recovery_steps: []const JournalStep,
    final_verification: FinalVerification,
    outcome: Outcome,
    diagnostic: []const u8,
    digest_sha256: [32]u8,

    pub fn canonicalJson(self: Result, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        return output.toOwnedSlice();
    }
};

pub const OwnedResult = struct {
    result: Result,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedResult) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const Error = error{
    UnsupportedSchema,
    DocumentTooLarge,
    DigestMismatch,
    NonCanonicalDocument,
    InvalidIdentity,
    DuplicateRepository,
    DuplicatePackage,
    DuplicateSigner,
    DuplicateEnvironmentKey,
    InvalidJournal,
    UnauthenticatedRepository,
    RepositoryEvidenceMismatch,
    MissingPackageEvidence,
    PackageDigestMismatch,
    ContradictoryOutcome,
    InvalidDigest,
    MissingLockDigest,
    LockDigestMismatch,
};

pub const ExecutionInput = struct {
    exact_lock: *const exact_lock.Lock,
    target_architecture: []const u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    repositories: []const RepositoryEvidence,
    packages: []const PackageEvidence,
    journal_steps: []const JournalStep,
    recovery_steps: []const JournalStep = &.{},
    final_verification: FinalVerification,
};

/// Converts the executor's observed argv/environment, artifact digests,
/// journal state, plan/policy/lock bindings, and failure into schema v1.
pub fn createFromExecution(
    allocator: std.mem.Allocator,
    input: ExecutionInput,
    report: transaction_executor.Report,
) !OwnedResult {
    const lock_sha256 = report.lock_sha256 orelse return error.MissingLockDigest;
    if (!std.mem.eql(u8, &lock_sha256, &input.exact_lock.digest_sha256))
        return error.LockDigestMismatch;
    try verifyLockEvidence(input.exact_lock.*, input.repositories, input.packages, null);
    var temporary = std.heap.ArenaAllocator.init(allocator);
    defer temporary.deinit();
    const arena = temporary.allocator();
    const commands = try arena.alloc(CommandEvidence, report.commands.len);
    for (report.commands, 0..) |command, index| {
        const environment = try arena.alloc(EnvironmentEntry, command.environment.len);
        for (command.environment, 0..) |entry, environment_index| environment[environment_index] = .{
            .key = entry.key,
            .value = entry.value,
        };
        commands[index] = .{
            .phase = @tagName(command.phase),
            .package = command.package,
            .argv = command.argv,
            .environment = environment,
            .command_sha256 = command.command_sha256,
            .artifact_sha256 = command.artifact_sha256,
        };
    }

    return create(allocator, .{
        .target_architecture = input.target_architecture,
        .request_sha256 = input.request_sha256,
        .solver_policy_sha256 = input.solver_policy_sha256,
        .executor_policy_sha256 = report.policy_sha256,
        .plan_sha256 = report.plan_sha256,
        .lock_sha256 = lock_sha256,
        .repositories = input.repositories,
        .packages = input.packages,
        .commands = commands,
        .journal_steps = input.journal_steps,
        .recovery_steps = input.recovery_steps,
        .final_verification = input.final_verification,
        .outcome = if (report.succeeded()) .succeeded else switch (report.transaction_state) {
            .interrupted => .interrupted,
            .in_progress, .dpkg_failed, .verification_failed => .recovery_required,
            else => .failed,
        },
        .diagnostic = if (report.failure) |failure| failure.diagnostic else "",
    });
}

pub fn createFromRecovery(
    allocator: std.mem.Allocator,
    input: ExecutionInput,
    report: transaction_executor.RecoveryReport,
) !OwnedResult {
    const lock_sha256 = report.lock_sha256 orelse return error.MissingLockDigest;
    if (!std.mem.eql(u8, &lock_sha256, &input.exact_lock.digest_sha256))
        return error.LockDigestMismatch;
    try verifyLockEvidence(input.exact_lock.*, input.repositories, input.packages, null);
    var temporary = std.heap.ArenaAllocator.init(allocator);
    defer temporary.deinit();
    const arena = temporary.allocator();
    const commands = try arena.alloc(CommandEvidence, report.commands.len);
    for (report.commands, 0..) |command, index| {
        const environment = try arena.alloc(EnvironmentEntry, command.environment.len);
        for (command.environment, 0..) |entry, environment_index| environment[environment_index] = .{
            .key = entry.key,
            .value = entry.value,
        };
        commands[index] = .{
            .phase = @tagName(command.phase),
            .package = command.package,
            .argv = command.argv,
            .environment = environment,
            .command_sha256 = command.command_sha256,
            .artifact_sha256 = command.artifact_sha256,
        };
    }
    return create(allocator, .{
        .target_architecture = input.target_architecture,
        .request_sha256 = input.request_sha256,
        .solver_policy_sha256 = input.solver_policy_sha256,
        .executor_policy_sha256 = report.policy_sha256,
        .plan_sha256 = report.plan_sha256,
        .lock_sha256 = lock_sha256,
        .repositories = input.repositories,
        .packages = input.packages,
        .commands = commands,
        .journal_steps = input.journal_steps,
        .recovery_steps = input.recovery_steps,
        .final_verification = input.final_verification,
        .outcome = if (report.succeeded()) .succeeded else if (report.state == .interrupted) .interrupted else .recovery_required,
        .diagnostic = if (report.failure) |failure| failure.diagnostic else "",
    });
}

pub const ValidatedDocument = struct {
    bytes: []u8,
    digest_sha256: [32]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ValidatedDocument) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn validateDocument(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !ValidatedDocument {
    if (source.len > maximum_bytes or source.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, source, .{
        .allocate = .alloc_always,
        .parse_numbers = true,
    });
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |value| value,
        else => return error.NonCanonicalDocument,
    };
    if (object.count() != 17 or hasJsonWhitespace(source)) return error.NonCanonicalDocument;
    const schema = object.get("schema") orelse return error.UnsupportedSchema;
    const version = object.get("version") orelse return error.UnsupportedSchema;
    if (schema != .string or !std.mem.eql(u8, schema.string, schema_id) or
        version != .integer or version.integer != schema_version)
        return error.UnsupportedSchema;
    const digest_value = object.get("digest_sha256") orelse return error.InvalidDigest;
    if (digest_value != .string) return error.InvalidDigest;
    const expected = try parseDigest(digest_value.string);
    const marker = ",\"digest_sha256\":\"";
    const marker_index = std.mem.lastIndexOf(u8, source, marker) orelse return error.NonCanonicalDocument;
    if (marker_index + marker.len + 64 + 2 != source.len or source[source.len - 2] != '"' or source[source.len - 1] != '}')
        return error.NonCanonicalDocument;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(source[0..marker_index]);
    hash.update("}");
    const actual = hash.finalResult();
    if (!std.mem.eql(u8, &expected, &actual)) return error.DigestMismatch;
    return .{
        .bytes = try allocator.dupe(u8, source),
        .digest_sha256 = expected,
        .allocator = allocator,
    };
}

/// The identity a published transaction result binds, read back from a
/// document that was already validated as canonical and digest-consistent.
///
/// It exists for recovery: a run that finds a result document where its own
/// interrupted attempt would have published one must decide whether that
/// document describes *this* attempt before it is allowed to count as the
/// attempt's detailed provenance. Only fixed-size identity is returned, so a
/// caller never has to keep the parsed document alive.
pub const DocumentBinding = struct {
    digest_sha256: [32]u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    executor_policy_sha256: [32]u8,
    plan_sha256: [32]u8,
    lock_sha256: [32]u8,
    outcome: Outcome,
    final_verification: VerificationStatus,
    architecture_storage: [64]u8,
    architecture_length: u8,

    pub fn architecture(self: *const DocumentBinding) []const u8 {
        return self.architecture_storage[0..self.architecture_length];
    }
};

/// Validates `source` and reads back exactly the identity it binds. Anything
/// that is not a canonical, digest-consistent v1 result document — or that
/// carries an unknown outcome, verification status, or oversized architecture
/// — fails instead of returning a partial binding.
pub fn readBinding(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !DocumentBinding {
    var validated = try validateDocument(allocator, source, maximum_bytes);
    defer validated.deinit();
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, validated.bytes, .{
        .allocate = .alloc_always,
        .parse_numbers = true,
        .duplicate_field_behavior = .@"error",
    });
    defer parsed.deinit();
    const document = switch (parsed.value) {
        .object => |value| value,
        else => return error.NonCanonicalDocument,
    };
    const architecture = try bindingString(document, "target_architecture");
    if (architecture.len == 0 or architecture.len > 64) return error.InvalidIdentity;
    const outcome_text = try bindingString(document, "outcome");
    const outcome = std.meta.stringToEnum(Outcome, outcome_text) orelse
        return error.NonCanonicalDocument;
    const final = switch (document.get("final_verification") orelse
        return error.NonCanonicalDocument) {
        .object => |value| value,
        else => return error.NonCanonicalDocument,
    };
    const status_text = try bindingString(final, "status");
    const status = std.meta.stringToEnum(VerificationStatus, status_text) orelse
        return error.NonCanonicalDocument;
    var binding: DocumentBinding = .{
        .digest_sha256 = validated.digest_sha256,
        .request_sha256 = try bindingDigest(document, "request_sha256"),
        .solver_policy_sha256 = try bindingDigest(document, "solver_policy_sha256"),
        .executor_policy_sha256 = try bindingDigest(document, "executor_policy_sha256"),
        .plan_sha256 = try bindingDigest(document, "plan_sha256"),
        .lock_sha256 = try bindingDigest(document, "lock_sha256"),
        .outcome = outcome,
        .final_verification = status,
        .architecture_storage = @splat(0),
        .architecture_length = @intCast(architecture.len),
    };
    @memcpy(binding.architecture_storage[0..architecture.len], architecture);
    return binding;
}

fn bindingString(object: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = object.get(name) orelse return error.NonCanonicalDocument;
    if (value != .string) return error.NonCanonicalDocument;
    return value.string;
}

fn bindingDigest(object: std.json.ObjectMap, name: []const u8) ![32]u8 {
    return parseDigest(try bindingString(object, name));
}

pub const Store = struct {
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,

    pub fn init(io: std.Io, dir: std.Io.Dir, name: []const u8) !Store {
        if (!safeLeaf(name)) return error.AmbiguousPath;
        return .{ .io = io, .dir = dir, .name = name };
    }

    pub fn read(self: Store, allocator: std.mem.Allocator, maximum_bytes: usize) !ValidatedDocument {
        var file = try self.dir.openFile(self.io, self.name, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const bytes = try reader.interface.allocRemaining(allocator, .limited(maximum_bytes));
        defer allocator.free(bytes);
        return validateDocument(allocator, bytes, maximum_bytes);
    }

    pub fn writeAtomic(self: Store, allocator: std.mem.Allocator, result: Result) !void {
        const bytes = try result.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
        const stage = ".debz-result.new";
        self.dir.deleteFile(self.io, stage) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        {
            var file = try self.dir.createFile(self.io, stage, .{
                .exclusive = true,
                .permissions = if (@import("builtin").os.tag == .windows) .default_file else .fromMode(0o600),
                .resolve_beneath = true,
            });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, bytes);
            try file.sync(self.io);
        }
        try self.dir.rename(stage, self.dir, self.name, self.io);
        switch (@import("builtin").os.tag) {
            .linux => if (std.posix.errno(std.os.linux.fsync(self.dir.handle)) != .SUCCESS)
                return error.Unexpected,
            else => {},
        }
    }
};

pub fn create(allocator: std.mem.Allocator, input: Input) !OwnedResult {
    if (input.target_architecture.len == 0) return error.InvalidIdentity;
    if (input.outcome == .succeeded and input.final_verification.status != .exact_match)
        return error.ContradictoryOutcome;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const repositories = try owned.alloc(RepositoryEvidence, input.repositories.len);
    for (input.repositories, 0..) |repository, index| {
        if (!validRepositoryId(&repository.source_config_id)) return error.InvalidIdentity;
        if (!repository.signature_verified) return error.UnauthenticatedRepository;
        repositories[index] = repository;
        repositories[index].signer_fingerprints = try owned.dupe([20]u8, repository.signer_fingerprints);
        std.mem.sort([20]u8, @constCast(repositories[index].signer_fingerprints), {}, lessFingerprint);
        for (repositories[index].signer_fingerprints, 0..) |fingerprint, signer_index| {
            if (signer_index != 0 and std.mem.eql(
                u8,
                &fingerprint,
                &repositories[index].signer_fingerprints[signer_index - 1],
            )) return error.DuplicateSigner;
        }
    }
    std.mem.sort(RepositoryEvidence, repositories, {}, lessRepository);
    for (repositories, 0..) |repository, index| {
        if (index != 0 and std.mem.eql(
            u8,
            &repository.source_config_id,
            &repositories[index - 1].source_config_id,
        )) return error.DuplicateRepository;
    }

    const packages = try owned.alloc(PackageEvidence, input.packages.len);
    for (input.packages, 0..) |package, index| {
        if (package.name.len == 0 or package.version.len == 0 or package.architecture.len == 0 or
            !validRepositoryId(&package.repository_id))
            return error.InvalidIdentity;
        if (!std.mem.eql(u8, &package.package_sha256, &package.cas_sha256))
            return error.PackageDigestMismatch;
        const repository = findRepositoryEvidence(repositories, package.repository_id) orelse
            return error.RepositoryEvidenceMismatch;
        if (!std.mem.eql(u8, &repository.snapshot_sha256, &package.repository_snapshot_sha256))
            return error.RepositoryEvidenceMismatch;
        packages[index] = package;
        packages[index].name = try owned.dupe(u8, package.name);
        packages[index].version = try owned.dupe(u8, package.version);
        packages[index].architecture = try owned.dupe(u8, package.architecture);
    }
    std.mem.sort(PackageEvidence, packages, {}, lessPackage);
    for (packages, 0..) |package, index| {
        if (index != 0 and samePackageIdentity(package, packages[index - 1]))
            return error.DuplicatePackage;
    }

    const commands = try owned.alloc(CommandEvidence, input.commands.len);
    for (input.commands, 0..) |command, index| {
        const argv = try owned.alloc([]const u8, command.argv.len);
        for (command.argv, 0..) |argument, argument_index|
            argv[argument_index] = try redactAlloc(owned, argument);
        const environment = try owned.alloc(EnvironmentEntry, command.environment.len);
        for (command.environment, 0..) |entry, environment_index| {
            environment[environment_index] = .{
                .key = try owned.dupe(u8, entry.key),
                .value = if (secretName(entry.key)) try owned.dupe(u8, "<redacted>") else try redactAlloc(owned, entry.value),
            };
        }
        std.mem.sort(EnvironmentEntry, environment, {}, lessEnvironment);
        for (environment, 0..) |entry, environment_index| {
            if (environment_index != 0 and std.mem.eql(u8, entry.key, environment[environment_index - 1].key))
                return error.DuplicateEnvironmentKey;
        }
        commands[index] = .{
            .phase = try owned.dupe(u8, command.phase),
            .package = if (command.package) |package| try owned.dupe(u8, package) else null,
            .argv = argv,
            .environment = environment,
            .command_sha256 = command.command_sha256,
            .artifact_sha256 = command.artifact_sha256,
        };
    }

    const journal_steps = try copySteps(owned, input.journal_steps);
    const recovery_steps = try copySteps(owned, input.recovery_steps);
    try validateSteps(journal_steps, commands.len, 0);
    try validateSteps(
        recovery_steps,
        commands.len,
        if (journal_steps.len == 0) 0 else std.math.add(
            usize,
            journal_steps[journal_steps.len - 1].sequence,
            1,
        ) catch return error.InvalidJournal,
    );
    var result: Result = .{
        .target_architecture = try owned.dupe(u8, input.target_architecture),
        .request_sha256 = input.request_sha256,
        .solver_policy_sha256 = input.solver_policy_sha256,
        .executor_policy_sha256 = input.executor_policy_sha256,
        .plan_sha256 = input.plan_sha256,
        .lock_sha256 = input.lock_sha256,
        .repositories = repositories,
        .packages = packages,
        .commands = commands,
        .journal_steps = journal_steps,
        .recovery_steps = recovery_steps,
        .final_verification = .{
            .status = input.final_verification.status,
            .installed_state_sha256 = input.final_verification.installed_state_sha256,
            .package_origins_sha256 = input.final_verification.package_origins_sha256,
            .detail = try redactAlloc(owned, input.final_verification.detail),
        },
        .outcome = input.outcome,
        .diagnostic = try redactAlloc(owned, input.diagnostic),
        .digest_sha256 = undefined,
    };
    result.digest_sha256 = digestPayload(result);
    return .{ .result = result, .arena = arena, .backing_allocator = allocator };
}

/// Credential-free sink for a lock-evidence verification failure. The message
/// names the offending repository (by id prefix) or package and the field that
/// changed, so a mismatch no longer surfaces as only a bare error name. Repo id
/// prefixes, content digests, and package names/versions are all non-secret, so
/// nothing here can leak an authentication token or signing key.
pub const VerifyDiagnostic = struct {
    buffer: [220]u8 = undefined,
    len: usize = 0,

    pub fn message(self: *const VerifyDiagnostic) []const u8 {
        return self.buffer[0..self.len];
    }

    pub fn note(self: *VerifyDiagnostic, comptime fmt: []const u8, args: anytype) void {
        const rendered = std.fmt.bufPrint(&self.buffer, fmt, args) catch {
            self.len = 0;
            return;
        };
        self.len = rendered.len;
    }
};

fn shortId(id: *const [64]u8) []const u8 {
    return id[0..12];
}

/// Verifies that every repository and package recorded in the exact lock is
/// present and unchanged in the runtime provenance evidence.
///
/// The runtime refresh authenticates every configured repository -- for the
/// Ubuntu release that is every suite x component (e.g. 12 repositories) --
/// while the exact lock records only the repositories that actually contributed
/// a package. The locked repositories are therefore verified as a SUBSET of the
/// runtime evidence. Requiring an exact count match falsely rejected the
/// production customize with `RepositoryEvidenceMismatch` whenever a configured
/// component such as `multiverse` shipped no selected package (2 locked vs 12
/// refreshed). Every locked repository must still be present with matching
/// snapshot/release/index digests, signer fingerprints, and a verified
/// signature, so no authenticated artifact can silently change between resolve
/// and customize.
///
/// On mismatch the optional `diagnostic` is filled with a credential-free
/// message naming the offending repository or package and the changed field.
pub fn verifyLockEvidence(
    lock: exact_lock.Lock,
    repositories: []const RepositoryEvidence,
    packages: []const PackageEvidence,
    diagnostic: ?*VerifyDiagnostic,
) Error!void {
    for (lock.repositories) |locked| {
        const repository = findRepositoryEvidence(repositories, locked.id) orelse {
            if (diagnostic) |sink| sink.note(
                "locked repository {s} absent from runtime evidence (runtime authenticated {d} repositories)",
                .{ shortId(&locked.id), repositories.len },
            );
            return error.RepositoryEvidenceMismatch;
        };
        const changed: ?[]const u8 =
            if (!std.mem.eql(u8, &locked.snapshot_sha256, &repository.snapshot_sha256))
                "snapshot digest"
            else if (!std.mem.eql(u8, &locked.release_sha256, &repository.release_sha256))
                "release digest"
            else if (!std.mem.eql(u8, &locked.index_sha256, &repository.metadata_sha256))
                "index digest"
            else if (!sameFingerprints(locked.signer_fingerprints, repository.signer_fingerprints))
                "signer fingerprints"
            else if (!repository.signature_verified)
                "signature verification"
            else
                null;
        if (changed) |field| {
            if (diagnostic) |sink| sink.note(
                "locked repository {s} {s} changed between resolve and customize",
                .{ shortId(&locked.id), field },
            );
            return error.RepositoryEvidenceMismatch;
        }
    }
    if (lock.packages.len != packages.len) {
        if (diagnostic) |sink| sink.note(
            "locked package count {d} does not match runtime evidence {d}",
            .{ lock.packages.len, packages.len },
        );
        return error.MissingPackageEvidence;
    }
    for (lock.packages) |locked| {
        var found = false;
        for (packages) |package| {
            if (!std.mem.eql(u8, locked.name, package.name) or
                !std.mem.eql(u8, locked.version, package.version) or
                !std.mem.eql(u8, locked.architecture, package.architecture))
                continue;
            found = true;
            if (!std.mem.eql(u8, &locked.repository_id, &package.repository_id) or
                !std.mem.eql(u8, &locked.repository_snapshot_sha256, &package.repository_snapshot_sha256) or
                !std.mem.eql(u8, &locked.sha256, &package.package_sha256) or
                locked.declared_size != package.declared_size)
            {
                if (diagnostic) |sink| sink.note(
                    "locked package {s} {s} artifact evidence changed between resolve and customize",
                    .{ locked.name, locked.architecture },
                );
                return error.PackageDigestMismatch;
            }
        }
        if (!found) {
            if (diagnostic) |sink| sink.note(
                "locked package {s} {s} missing from runtime evidence",
                .{ locked.name, locked.architecture },
            );
            return error.MissingPackageEvidence;
        }
    }
}

pub fn redactAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var index: usize = 0;
    while (index < value.len) {
        if (std.mem.startsWith(u8, value[index..], "://")) {
            try output.writer.writeAll("://");
            index += 3;
            const authority_end = std.mem.indexOfAnyPos(u8, value, index, "/?#") orelse value.len;
            const at = std.mem.lastIndexOfScalar(u8, value[index..authority_end], '@');
            if (at) |relative| {
                try output.writer.writeAll("<redacted>@");
                index += relative + 1;
            }
            continue;
        }
        const matched = secretAssignment(value, index);
        if (matched) |assignment| {
            try output.writer.writeAll(value[index..assignment.value_start]);
            try output.writer.writeAll("<redacted>");
            index = assignment.value_end;
            continue;
        }
        try output.writer.writeByte(value[index]);
        index += 1;
    }
    return output.toOwnedSlice();
}

const Assignment = struct { value_start: usize, value_end: usize };

fn secretAssignment(value: []const u8, start: usize) ?Assignment {
    const names = [_][]const u8{ "token=", "access_token=", "auth=", "authorization:", "password=", "proxy_password=", "signed-by=" };
    for (names) |name| {
        if (start + name.len > value.len or !std.ascii.eqlIgnoreCase(value[start .. start + name.len], name)) continue;
        var end = start + name.len;
        while (end < value.len and value[end] != '&' and value[end] != ' ' and value[end] != '\n' and value[end] != '\r')
            end += 1;
        return .{ .value_start = start + name.len, .value_end = end };
    }
    const path_names = [_][]const u8{ "auth-conf=", "auth_config=", "netrc=" };
    for (path_names) |name| {
        if (start + name.len > value.len or !std.ascii.eqlIgnoreCase(value[start .. start + name.len], name)) continue;
        var end = start + name.len;
        while (end < value.len and value[end] != '&' and value[end] != ' ' and value[end] != '\n' and value[end] != '\r')
            end += 1;
        return .{ .value_start = start + name.len, .value_end = end };
    }
    return null;
}

pub fn secretName(name: []const u8) bool {
    const secrets = [_][]const u8{ "authorization", "proxy-authorization", "token", "password", "http_proxy", "https_proxy", "apt_auth_conf" };
    for (secrets) |secret| if (std.ascii.eqlIgnoreCase(name, secret)) return true;
    return false;
}

fn copySteps(allocator: std.mem.Allocator, input: []const JournalStep) ![]JournalStep {
    const result = try allocator.alloc(JournalStep, input.len);
    for (input, 0..) |step, index| result[index] = .{
        .sequence = step.sequence,
        .boundary = try allocator.dupe(u8, step.boundary),
        .state = try allocator.dupe(u8, step.state),
        .command_index = step.command_index,
        .recovered = step.recovered,
    };
    return result;
}

fn validateSteps(steps: []const JournalStep, command_count: usize, first_sequence: usize) Error!void {
    var expected = first_sequence;
    for (steps) |step| {
        if (step.sequence != expected or step.command_index > command_count or
            step.boundary.len == 0 or step.state.len == 0)
            return error.InvalidJournal;
        expected = std.math.add(usize, expected, 1) catch return error.InvalidJournal;
    }
}

fn findRepositoryEvidence(
    repositories: []const RepositoryEvidence,
    id: [64]u8,
) ?RepositoryEvidence {
    for (repositories) |repository| {
        if (std.mem.eql(u8, &repository.source_config_id, &id)) return repository;
    }
    return null;
}

fn sameFingerprints(left: []const [20]u8, right: []const [20]u8) bool {
    if (left.len != right.len) return false;
    for (left) |left_value| {
        var found = false;
        for (right) |right_value| {
            if (std.mem.eql(u8, &left_value, &right_value)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn digestPayload(result: Result) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(result, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeDocument(result: Result, writer: *std.Io.Writer) !void {
    try writePayload(result, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHex(writer, &result.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(result: Result, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, schema_id);
    try writer.print(",\"version\":{},\"target_architecture\":", .{schema_version});
    try writeString(writer, result.target_architecture);
    inline for (.{
        .{ "request_sha256", result.request_sha256 },
        .{ "solver_policy_sha256", result.solver_policy_sha256 },
        .{ "executor_policy_sha256", result.executor_policy_sha256 },
        .{ "plan_sha256", result.plan_sha256 },
        .{ "lock_sha256", result.lock_sha256 },
    }) |field| {
        try writer.print(",\"{s}\":", .{field[0]});
        try writeHex(writer, &field[1]);
    }
    try writer.writeAll(",\"repositories\":[");
    for (result.repositories, 0..) |repository, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"source_config_id\":");
        try writeString(writer, &repository.source_config_id);
        try writer.writeAll(",\"snapshot_sha256\":");
        try writeHex(writer, &repository.snapshot_sha256);
        try writer.writeAll(",\"release_sha256\":");
        try writeHex(writer, &repository.release_sha256);
        try writer.writeAll(",\"signature_sha256\":");
        if (repository.signature_sha256) |digest| try writeHex(writer, &digest) else try writer.writeAll("null");
        try writer.writeAll(",\"metadata_sha256\":");
        try writeHex(writer, &repository.metadata_sha256);
        try writer.writeAll(",\"signer_fingerprints\":[");
        for (repository.signer_fingerprints, 0..) |fingerprint, signer_index| {
            if (signer_index != 0) try writer.writeByte(',');
            try writeHex(writer, &fingerprint);
        }
        try writer.print("],\"signature_verified\":{}}}", .{repository.signature_verified});
    }
    try writer.writeAll("],\"packages\":[");
    for (result.packages, 0..) |package, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try writeString(writer, package.name);
        try writer.writeAll(",\"version\":");
        try writeString(writer, package.version);
        try writer.writeAll(",\"architecture\":");
        try writeString(writer, package.architecture);
        try writer.writeAll(",\"repository_id\":");
        try writeString(writer, &package.repository_id);
        try writer.writeAll(",\"repository_snapshot_sha256\":");
        try writeHex(writer, &package.repository_snapshot_sha256);
        try writer.writeAll(",\"package_sha256\":");
        try writeHex(writer, &package.package_sha256);
        try writer.writeAll(",\"cas_sha256\":");
        try writeHex(writer, &package.cas_sha256);
        try writer.print(",\"declared_size\":{}}}", .{package.declared_size});
    }
    try writer.writeAll("],\"commands\":[");
    for (result.commands, 0..) |command, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"phase\":");
        try writeString(writer, command.phase);
        try writer.writeAll(",\"package\":");
        if (command.package) |package| try writeString(writer, package) else try writer.writeAll("null");
        try writer.writeAll(",\"argv\":[");
        for (command.argv, 0..) |argument, argument_index| {
            if (argument_index != 0) try writer.writeByte(',');
            try writeString(writer, argument);
        }
        try writer.writeAll("],\"environment\":[");
        for (command.environment, 0..) |entry, environment_index| {
            if (environment_index != 0) try writer.writeByte(',');
            try writer.writeAll("{\"key\":");
            try writeString(writer, entry.key);
            try writer.writeAll(",\"value\":");
            try writeString(writer, entry.value);
            try writer.writeByte('}');
        }
        try writer.writeAll("],\"command_sha256\":");
        try writeHex(writer, &command.command_sha256);
        try writer.writeAll(",\"artifact_sha256\":");
        if (command.artifact_sha256) |digest| try writeHex(writer, &digest) else try writer.writeAll("null");
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"journal_steps\":");
    try writeSteps(writer, result.journal_steps);
    try writer.writeAll(",\"recovery_steps\":");
    try writeSteps(writer, result.recovery_steps);
    try writer.writeAll(",\"final_verification\":{\"status\":");
    try writeString(writer, @tagName(result.final_verification.status));
    try writer.writeAll(",\"installed_state_sha256\":");
    if (result.final_verification.installed_state_sha256) |digest| try writeHex(writer, &digest) else try writer.writeAll("null");
    try writer.writeAll(",\"package_origins_sha256\":");
    if (result.final_verification.package_origins_sha256) |digest| try writeHex(writer, &digest) else try writer.writeAll("null");
    try writer.writeAll(",\"detail\":");
    try writeString(writer, result.final_verification.detail);
    try writer.writeAll("},\"outcome\":");
    try writeString(writer, @tagName(result.outcome));
    try writer.writeAll(",\"diagnostic\":");
    try writeString(writer, result.diagnostic);
    try writer.writeByte('}');
}

fn writeSteps(writer: *std.Io.Writer, steps: []const JournalStep) !void {
    try writer.writeByte('[');
    for (steps, 0..) |step, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{{\"sequence\":{},\"boundary\":", .{step.sequence});
        try writeString(writer, step.boundary);
        try writer.writeAll(",\"state\":");
        try writeString(writer, step.state);
        try writer.print(",\"command_index\":{},\"recovered\":{}}}", .{ step.command_index, step.recovered });
    }
    try writer.writeByte(']');
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

fn writeHex(writer: *std.Io.Writer, value: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (value) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

fn validRepositoryId(id: *const [64]u8) bool {
    for (id) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    return true;
}

fn lessRepository(_: void, left: RepositoryEvidence, right: RepositoryEvidence) bool {
    return std.mem.order(u8, &left.source_config_id, &right.source_config_id) == .lt;
}

fn lessPackage(_: void, left: PackageEvidence, right: PackageEvidence) bool {
    const name = std.mem.order(u8, left.name, right.name);
    if (name != .eq) return name == .lt;
    const arch = std.mem.order(u8, left.architecture, right.architecture);
    if (arch != .eq) return arch == .lt;
    return std.mem.order(u8, left.version, right.version) == .lt;
}

fn samePackageIdentity(left: PackageEvidence, right: PackageEvidence) bool {
    return std.mem.eql(u8, left.name, right.name) and
        std.mem.eql(u8, left.architecture, right.architecture);
}

fn lessEnvironment(_: void, left: EnvironmentEntry, right: EnvironmentEntry) bool {
    const key = std.mem.order(u8, left.key, right.key);
    if (key != .eq) return key == .lt;
    return std.mem.order(u8, left.value, right.value) == .lt;
}

fn lessFingerprint(_: void, left: [20]u8, right: [20]u8) bool {
    return std.mem.order(u8, &left, &right) == .lt;
}

fn parseDigest(value: []const u8) Error![32]u8 {
    if (value.len != 64) return error.InvalidDigest;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    return result;
}

fn safeLeaf(name: []const u8) bool {
    return name.len != 0 and
        !std.mem.eql(u8, name, ".") and
        !std.mem.eql(u8, name, "..") and
        std.mem.indexOfScalar(u8, name, '/') == null and
        std.mem.indexOfScalar(u8, name, '\\') == null;
}

fn hasJsonWhitespace(source: []const u8) bool {
    var in_string = false;
    var escaped = false;
    for (source) |byte| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                in_string = false;
            }
        } else if (byte == '"') {
            in_string = true;
        } else if (byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n') {
            return true;
        }
    }
    return false;
}

test "transaction_provenance.test.deterministic provenance recovery and redaction" {
    const repository_id: [64]u8 = @splat('b');
    const repositories = [_]RepositoryEvidence{.{
        .source_config_id = repository_id,
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .signature_sha256 = @splat(3),
        .metadata_sha256 = @splat(4),
        .signer_fingerprints = &.{@splat(5)},
        .signature_verified = true,
    }};
    const packages = [_]PackageEvidence{.{
        .name = "demo",
        .version = "1:2.0-3",
        .architecture = "amd64",
        .repository_id = repository_id,
        .repository_snapshot_sha256 = @splat(1),
        .package_sha256 = @splat(6),
        .cas_sha256 = @splat(6),
        .declared_size = 99,
    }};
    const argv = [_][]const u8{
        "dpkg",
        "https://user:pass@example.invalid/pool/demo.deb?token=secret",
        "--auth-conf=/home/user/private.conf",
    };
    const environment = [_]EnvironmentEntry{.{ .key = "Authorization", .value = "Bearer secret" }};
    const commands = [_]CommandEvidence{.{
        .phase = "unpack",
        .package = "demo",
        .argv = &argv,
        .environment = &environment,
        .command_sha256 = @splat(7),
        .artifact_sha256 = @splat(6),
    }};
    var owned = try create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(8),
        .solver_policy_sha256 = @splat(9),
        .executor_policy_sha256 = @splat(10),
        .plan_sha256 = @splat(11),
        .lock_sha256 = @splat(12),
        .repositories = &repositories,
        .packages = &packages,
        .commands = &commands,
        .journal_steps = &.{.{ .sequence = 0, .boundary = "before_command", .state = "in_progress", .command_index = 0, .recovered = false }},
        .recovery_steps = &.{.{ .sequence = 1, .boundary = "recovering", .state = "complete", .command_index = 1, .recovered = true }},
        .final_verification = .{ .status = .exact_match, .installed_state_sha256 = @splat(13), .package_origins_sha256 = @splat(14), .detail = "ok" },
        .outcome = .succeeded,
        .diagnostic = "proxy_password=hunter2",
    });
    defer owned.deinit();
    const json = try owned.result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "hunter2") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "user:pass") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "/home/user/private.conf") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "recovery_steps") != null);
    var validated = try validateDocument(std.testing.allocator, json, maximum_document_bytes);
    defer validated.deinit();
    try std.testing.expectEqualSlices(u8, &owned.result.digest_sha256, &validated.digest_sha256);
    var tampered = try std.testing.allocator.dupe(u8, json);
    defer std.testing.allocator.free(tampered);
    tampered[std.mem.indexOf(u8, tampered, "\"demo\"").? + 1] = 'x';
    try std.testing.expectError(error.DigestMismatch, validateDocument(std.testing.allocator, tampered, maximum_document_bytes));

    const lock_repositories = [_]exact_lock.Repository{.{
        .id = repository_id,
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .index_sha256 = @splat(4),
        .signer_fingerprints = &.{@splat(5)},
    }};
    const lock_packages = [_]exact_lock.Package{.{
        .name = "demo",
        .version = "1:2.0-3",
        .architecture = "amd64",
        .repository_id = repository_id,
        .repository_snapshot_sha256 = @splat(1),
        .sha256 = @splat(6),
        .declared_size = 99,
        .retention = .requested,
        .dpkg_selection_hold = false,
    }};
    const lock: exact_lock.Lock = .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(8),
        .policy_sha256 = @splat(9),
        .repositories = &lock_repositories,
        .packages = &lock_packages,
        .digest_sha256 = @splat(12),
    };
    try verifyLockEvidence(lock, &repositories, &packages, null);
    var wrong_repository = repositories;
    wrong_repository[0].metadata_sha256 = @splat(15);
    try std.testing.expectError(
        error.RepositoryEvidenceMismatch,
        verifyLockEvidence(lock, &wrong_repository, &packages, null),
    );
}

test "transaction_provenance.test.published result binds a readable identity" {
    const repository_id: [64]u8 = @splat('b');
    const repositories = [_]RepositoryEvidence{.{
        .source_config_id = repository_id,
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .signature_sha256 = @splat(3),
        .metadata_sha256 = @splat(4),
        .signer_fingerprints = &.{@splat(5)},
        .signature_verified = true,
    }};
    const packages = [_]PackageEvidence{.{
        .name = "demo",
        .version = "1",
        .architecture = "amd64",
        .repository_id = repository_id,
        .repository_snapshot_sha256 = @splat(1),
        .package_sha256 = @splat(6),
        .cas_sha256 = @splat(6),
        .declared_size = 99,
    }};
    var owned = try create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(8),
        .solver_policy_sha256 = @splat(9),
        .executor_policy_sha256 = @splat(10),
        .plan_sha256 = @splat(11),
        .lock_sha256 = @splat(12),
        .repositories = &repositories,
        .packages = &packages,
        .commands = &.{},
        .journal_steps = &.{},
        .final_verification = .{
            .status = .exact_match,
            .installed_state_sha256 = @splat(13),
            .package_origins_sha256 = @splat(14),
            .detail = "ok",
        },
        .outcome = .succeeded,
    });
    defer owned.deinit();
    const json = try owned.result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);

    const binding = try readBinding(std.testing.allocator, json, maximum_document_bytes);
    try std.testing.expectEqualStrings("amd64", binding.architecture());
    try std.testing.expectEqual(Outcome.succeeded, binding.outcome);
    try std.testing.expectEqual(VerificationStatus.exact_match, binding.final_verification);
    try std.testing.expectEqualSlices(u8, &owned.result.digest_sha256, &binding.digest_sha256);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(11)), &binding.plan_sha256);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(12)), &binding.lock_sha256);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(8)), &binding.request_sha256);

    var tampered = try std.testing.allocator.dupe(u8, json);
    defer std.testing.allocator.free(tampered);
    tampered[std.mem.indexOf(u8, tampered, "\"outcome\":\"succeeded\"").? + 12] = 'x';
    try std.testing.expectError(
        error.DigestMismatch,
        readBinding(std.testing.allocator, tampered, maximum_document_bytes),
    );
    try std.testing.expectError(
        error.DocumentTooLarge,
        readBinding(std.testing.allocator, json, json.len - 1),
    );
}

test "transaction_provenance.verifyLockEvidence accepts locked repositories as a subset of runtime evidence" {
    // Regression for issue #455: the aarch64/x86 release customize refreshes
    // every configured suite x component (12 repositories) while the exact lock
    // records only the repositories that contributed a package (2). Requiring an
    // exact count match surfaced a bare `backend_failed: RepositoryEvidenceMismatch`
    // (exit 70) the first time customize verified evidence after a resolve. The
    // locked repositories must instead verify as a subset of the runtime evidence.
    const fingerprints = [_][20]u8{@splat(0xAB)};
    var evidence: [12]RepositoryEvidence = undefined;
    for (&evidence, 0..) |*item, index| {
        const tag: u8 = @intCast(index + 1);
        item.* = .{
            .source_config_id = @splat(tag),
            .snapshot_sha256 = @splat(tag),
            .release_sha256 = @splat(tag +% 0x20),
            .signature_sha256 = null,
            .metadata_sha256 = @splat(tag +% 0x40),
            .signer_fingerprints = &fingerprints,
            .signature_verified = true,
        };
    }
    const contributing = [_]usize{ 3, 8 };
    const names = [_][]const u8{ "alpha", "beta" };
    var lock_repositories: [2]exact_lock.Repository = undefined;
    var lock_packages: [2]exact_lock.Package = undefined;
    var package_evidence: [2]PackageEvidence = undefined;
    for (&lock_repositories, &lock_packages, &package_evidence, contributing, names) |*repo, *pkg, *ev, source, name| {
        repo.* = .{
            .id = evidence[source].source_config_id,
            .snapshot_sha256 = evidence[source].snapshot_sha256,
            .release_sha256 = evidence[source].release_sha256,
            .index_sha256 = evidence[source].metadata_sha256,
            .signer_fingerprints = &fingerprints,
        };
        pkg.* = .{
            .name = name,
            .version = "1.0",
            .architecture = "amd64",
            .repository_id = evidence[source].source_config_id,
            .repository_snapshot_sha256 = evidence[source].snapshot_sha256,
            .sha256 = @splat(0xC0),
            .declared_size = 100,
            .retention = .requested,
            .dpkg_selection_hold = false,
        };
        ev.* = .{
            .name = name,
            .version = "1.0",
            .architecture = "amd64",
            .repository_id = evidence[source].source_config_id,
            .repository_snapshot_sha256 = evidence[source].snapshot_sha256,
            .package_sha256 = @splat(0xC0),
            .cas_sha256 = @splat(0xC0),
            .declared_size = 100,
        };
    }
    const lock: exact_lock.Lock = .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &lock_repositories,
        .packages = &lock_packages,
        .digest_sha256 = @splat(3),
    };
    // Before the fix this returned error.RepositoryEvidenceMismatch purely
    // because 2 != 12.
    try verifyLockEvidence(lock, &evidence, &package_evidence, null);
}

test "transaction_provenance.verifyLockEvidence names a missing repository without leaking credentials" {
    const fingerprints = [_][20]u8{@splat(0xAB)};
    const evidence = [_]RepositoryEvidence{.{
        .source_config_id = @splat('a'),
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .signature_sha256 = null,
        .metadata_sha256 = @splat(3),
        .signer_fingerprints = &fingerprints,
        .signature_verified = true,
    }};
    const lock_repositories = [_]exact_lock.Repository{.{
        .id = @splat('z'),
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .index_sha256 = @splat(3),
        .signer_fingerprints = &fingerprints,
    }};
    const lock: exact_lock.Lock = .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &lock_repositories,
        .packages = &.{},
        .digest_sha256 = @splat(3),
    };
    var diagnostic: VerifyDiagnostic = .{};
    try std.testing.expectError(
        error.RepositoryEvidenceMismatch,
        verifyLockEvidence(lock, &evidence, &.{}, &diagnostic),
    );
    const message = diagnostic.message();
    try std.testing.expect(std.mem.indexOf(u8, message, "absent from runtime evidence") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "zzzzzzzzzzzz") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "token") == null);
    try std.testing.expect(std.mem.indexOf(u8, message, "password") == null);
    try std.testing.expect(std.mem.indexOf(u8, message, "signed-by") == null);
}

test "transaction_provenance.verifyLockEvidence names a changed repository digest" {
    const fingerprints = [_][20]u8{@splat(0xAB)};
    const evidence = [_]RepositoryEvidence{.{
        .source_config_id = @splat('a'),
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .signature_sha256 = null,
        .metadata_sha256 = @splat(9),
        .signer_fingerprints = &fingerprints,
        .signature_verified = true,
    }};
    const lock_repositories = [_]exact_lock.Repository{.{
        .id = @splat('a'),
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .index_sha256 = @splat(3),
        .signer_fingerprints = &fingerprints,
    }};
    const lock: exact_lock.Lock = .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &lock_repositories,
        .packages = &.{},
        .digest_sha256 = @splat(3),
    };
    var diagnostic: VerifyDiagnostic = .{};
    try std.testing.expectError(
        error.RepositoryEvidenceMismatch,
        verifyLockEvidence(lock, &evidence, &.{}, &diagnostic),
    );
    try std.testing.expect(std.mem.indexOf(u8, diagnostic.message(), "index digest changed") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic.message(), "aaaaaaaaaaaa") != null);
}

const std = @import("std");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const package_origin = @import("package_origin.zig");
const transaction_executor = @import("transaction_executor.zig");
const v1 = @import("transaction_provenance.zig");

pub const schema_id = "https://debz.dev/schema/transaction-result-v2";
pub const schema_version: u32 = 2;
pub const maximum_document_bytes: usize = 32 * 1024 * 1024;

pub const Outcome = v1.Outcome;
pub const VerificationStatus = v1.VerificationStatus;
pub const RepositoryEvidence = v1.RepositoryEvidence;
pub const EnvironmentEntry = v1.EnvironmentEntry;
pub const CommandEvidence = v1.CommandEvidence;
pub const JournalStep = v1.JournalStep;
pub const FinalVerification = v1.FinalVerification;

pub const PackageEvidence = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    origin: exact_lock_v2.PackageOrigin,
    package_sha256: [32]u8,
    cas_sha256: [32]u8,
    declared_size: u64,
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

    fn testExecutionMetadataBoundToExactLock() !void {
        const digest: [32]u8 = @splat(0x31);
        const artifact: package_origin.LocalArtifactEvidence = .{
            .artifact_id = package_origin.artifactIdFromSha256(digest),
            .sha256 = digest,
            .size = 31,
            .package = "demo",
            .version = "1",
            .architecture = "amd64",
            .acquisition_url = "file:///demo.deb",
            .trust_mode = .pinned_sha256,
        };
        const locked_package: exact_lock_v2.Package = .{
            .name = artifact.package,
            .version = artifact.version,
            .architecture = artifact.architecture,
            .origin = .{ .local_artifact = artifact },
            .sha256 = artifact.sha256,
            .declared_size = artifact.size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        };
        var lock = try exact_lock_v2.create(std.testing.allocator, .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(1),
            .policy_sha256 = @splat(2),
            .repositories = &.{},
            .local_artifacts = &.{artifact},
            .packages = &.{locked_package},
            .verified_origins = true,
        });
        defer lock.deinit();
        const package: PackageEvidence = .{
            .name = artifact.package,
            .version = artifact.version,
            .architecture = artifact.architecture,
            .origin = .{ .local_artifact = artifact },
            .package_sha256 = artifact.sha256,
            .cas_sha256 = artifact.sha256,
            .declared_size = artifact.size,
        };
        const verification: FinalVerification = .{
            .status = .exact_match,
            .installed_state_sha256 = @splat(3),
            .package_origins_sha256 = lock.lock.digest_sha256,
            .detail = "verified",
        };
        const input: ExecutionInput = .{
            .exact_lock = &lock.lock,
            .target_architecture = lock.lock.target_architecture,
            .request_sha256 = lock.lock.request_sha256,
            .solver_policy_sha256 = lock.lock.policy_sha256,
            .repositories = &.{},
            .packages = &.{package},
            .journal_steps = &.{},
            .final_verification = verification,
        };
        const report: transaction_executor.Report = .{
            .allocator = std.testing.allocator,
            .arena = undefined,
            .commands = &.{},
            .plan_sha256 = @splat(4),
            .transaction_state = .complete,
            .root_identity = @splat(5),
            .policy_sha256 = @splat(6),
            .lock_sha256 = lock.lock.digest_sha256,
            .failure = null,
        };
        const recovery_report: transaction_executor.RecoveryReport = .{
            .allocator = std.testing.allocator,
            .arena = undefined,
            .state = .complete,
            .commands = &.{},
            .plan_sha256 = report.plan_sha256,
            .root_identity = report.root_identity,
            .policy_sha256 = report.policy_sha256,
            .lock_sha256 = report.lock_sha256,
            .failure = null,
        };
        var execution = try createFromExecution(std.testing.allocator, input, report);
        defer execution.deinit();
        var recovered = try createFromRecovery(
            std.testing.allocator,
            input,
            recovery_report,
        );
        defer recovered.deinit();
        try std.testing.expectEqualStrings(
            lock.lock.target_architecture,
            execution.result.target_architecture,
        );
        try std.testing.expectEqualSlices(
            u8,
            &lock.lock.request_sha256,
            &recovered.result.request_sha256,
        );

        const Mismatch = enum { architecture, request, policy };
        inline for ([_]Mismatch{ .architecture, .request, .policy }) |kind| {
            var mismatch = input;
            const expected: anyerror = switch (kind) {
                .architecture => blk: {
                    mismatch.target_architecture = "arm64";
                    break :blk error.LockArchitectureMismatch;
                },
                .request => blk: {
                    mismatch.request_sha256 = @splat(0xaa);
                    break :blk error.LockRequestMismatch;
                },
                .policy => blk: {
                    mismatch.solver_policy_sha256 = @splat(0xbb);
                    break :blk error.LockPolicyMismatch;
                },
            };
            try std.testing.expectError(
                expected,
                createFromExecution(std.testing.allocator, mismatch, report),
            );
            try std.testing.expectError(
                expected,
                createFromRecovery(std.testing.allocator, mismatch, recovery_report),
            );
        }
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

pub const Error = v1.Error || package_origin.ValidationError || error{
    UnusedRepository,
    InvalidPackageOrigin,
    PackageOriginMismatch,
    LockArchitectureMismatch,
    LockRequestMismatch,
    LockPolicyMismatch,
};

pub const ExecutionInput = struct {
    exact_lock: *const exact_lock_v2.Lock,
    target_architecture: []const u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    repositories: []const RepositoryEvidence,
    packages: []const PackageEvidence,
    journal_steps: []const JournalStep,
    recovery_steps: []const JournalStep = &.{},
    final_verification: FinalVerification,
};

pub fn createFromExecution(
    allocator: std.mem.Allocator,
    input: ExecutionInput,
    report: transaction_executor.Report,
) !OwnedResult {
    const lock_sha256 = report.lock_sha256 orelse return error.MissingLockDigest;
    if (!std.mem.eql(u8, &lock_sha256, &input.exact_lock.digest_sha256))
        return error.LockDigestMismatch;
    try validateExecutionLockMetadata(input);
    try verifyLockEvidence(input.exact_lock.*, input.repositories, input.packages, null);
    var temporary = std.heap.ArenaAllocator.init(allocator);
    defer temporary.deinit();
    const arena = temporary.allocator();
    const commands = try commandsFromReport(arena, report.commands);
    return create(allocator, .{
        .target_architecture = input.exact_lock.target_architecture,
        .request_sha256 = input.exact_lock.request_sha256,
        .solver_policy_sha256 = input.exact_lock.policy_sha256,
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
    try validateExecutionLockMetadata(input);
    try verifyLockEvidence(input.exact_lock.*, input.repositories, input.packages, null);
    var temporary = std.heap.ArenaAllocator.init(allocator);
    defer temporary.deinit();
    const commands = try commandsFromReport(temporary.allocator(), report.commands);
    return create(allocator, .{
        .target_architecture = input.exact_lock.target_architecture,
        .request_sha256 = input.exact_lock.request_sha256,
        .solver_policy_sha256 = input.exact_lock.policy_sha256,
        .executor_policy_sha256 = report.policy_sha256,
        .plan_sha256 = report.plan_sha256,
        .lock_sha256 = lock_sha256,
        .repositories = input.repositories,
        .packages = input.packages,
        .commands = commands,
        .journal_steps = input.journal_steps,
        .recovery_steps = input.recovery_steps,
        .final_verification = input.final_verification,
        .outcome = if (report.succeeded()) .succeeded else if (report.state == .interrupted)
            .interrupted
        else
            .recovery_required,
        .diagnostic = if (report.failure) |failure| failure.diagnostic else "",
    });
}

fn validateExecutionLockMetadata(input: ExecutionInput) Error!void {
    if (!std.mem.eql(
        u8,
        input.target_architecture,
        input.exact_lock.target_architecture,
    )) return error.LockArchitectureMismatch;
    if (!std.mem.eql(
        u8,
        &input.request_sha256,
        &input.exact_lock.request_sha256,
    )) return error.LockRequestMismatch;
    if (!std.mem.eql(
        u8,
        &input.solver_policy_sha256,
        &input.exact_lock.policy_sha256,
    )) return error.LockPolicyMismatch;
}

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
        if (!validId(&repository.source_config_id)) return error.InvalidIdentity;
        if (!repository.signature_verified or repository.signer_fingerprints.len == 0)
            return error.UnauthenticatedRepository;
        repositories[index] = repository;
        repositories[index].signer_fingerprints = try owned.dupe(
            [20]u8,
            repository.signer_fingerprints,
        );
        std.mem.sort(
            [20]u8,
            @constCast(repositories[index].signer_fingerprints),
            {},
            lessFingerprint,
        );
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
        if (!validIdentity(package.name) or
            !validIdentity(package.version) or
            !validIdentity(package.architecture))
            return error.InvalidIdentity;
        if (!std.mem.eql(u8, &package.package_sha256, &package.cas_sha256))
            return error.PackageDigestMismatch;
        packages[index] = package;
        packages[index].name = try owned.dupe(u8, package.name);
        packages[index].version = try owned.dupe(u8, package.version);
        packages[index].architecture = try owned.dupe(u8, package.architecture);
        switch (package.origin) {
            .authenticated_repository => |origin| {
                const repository = findRepository(repositories, origin.repository_id) orelse
                    return error.RepositoryEvidenceMismatch;
                if (!std.mem.eql(
                    u8,
                    &repository.snapshot_sha256,
                    &origin.repository_snapshot_sha256,
                )) return error.RepositoryEvidenceMismatch;
            },
            .local_artifact => |origin| {
                try package_origin.validateLocalArtifact(origin);
                if (!std.mem.eql(u8, package.name, origin.package) or
                    !std.mem.eql(u8, package.version, origin.version) or
                    !std.mem.eql(u8, package.architecture, origin.architecture) or
                    !std.mem.eql(u8, &package.package_sha256, &origin.sha256) or
                    package.declared_size != origin.size)
                    return error.PackageOriginMismatch;
                packages[index].origin = .{
                    .local_artifact = try dupeLocalArtifact(owned, origin),
                };
            },
        }
    }
    std.mem.sort(PackageEvidence, packages, {}, lessPackage);
    for (packages, 0..) |package, index| {
        if (index != 0 and samePackageIdentity(package, packages[index - 1]))
            return error.DuplicatePackage;
    }
    for (repositories) |repository| {
        var used = false;
        for (packages) |package| switch (package.origin) {
            .authenticated_repository => |origin| if (std.mem.eql(
                u8,
                &repository.source_config_id,
                &origin.repository_id,
            )) {
                used = true;
            },
            .local_artifact => {},
        };
        if (!used) return error.UnusedRepository;
    }

    const commands = try owned.alloc(CommandEvidence, input.commands.len);
    for (input.commands, 0..) |command, index| {
        const argv = try owned.alloc([]const u8, command.argv.len);
        for (command.argv, 0..) |argument, argument_index|
            argv[argument_index] = try v1.redactAlloc(owned, argument);
        const environment = try owned.alloc(EnvironmentEntry, command.environment.len);
        for (command.environment, 0..) |entry, environment_index| {
            environment[environment_index] = .{
                .key = try owned.dupe(u8, entry.key),
                .value = if (v1.secretName(entry.key))
                    try owned.dupe(u8, "<redacted>")
                else
                    try v1.redactAlloc(owned, entry.value),
            };
        }
        std.mem.sort(EnvironmentEntry, environment, {}, lessEnvironment);
        for (environment, 0..) |entry, environment_index| {
            if (environment_index != 0 and
                std.mem.eql(u8, entry.key, environment[environment_index - 1].key))
                return error.DuplicateEnvironmentKey;
        }
        commands[index] = .{
            .phase = try owned.dupe(u8, command.phase),
            .package = if (command.package) |package|
                try owned.dupe(u8, package)
            else
                null,
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
            .detail = try v1.redactAlloc(owned, input.final_verification.detail),
        },
        .outcome = input.outcome,
        .diagnostic = try v1.redactAlloc(owned, input.diagnostic),
        .digest_sha256 = undefined,
    };
    result.digest_sha256 = digestPayload(result);
    return .{ .result = result, .arena = arena, .backing_allocator = allocator };
}

pub const VerifyDiagnostic = v1.VerifyDiagnostic;

pub fn verifyLockEvidence(
    lock: exact_lock_v2.Lock,
    repositories: []const RepositoryEvidence,
    packages: []const PackageEvidence,
    diagnostic: ?*VerifyDiagnostic,
) Error!void {
    for (lock.repositories) |locked| {
        const repository = findRepository(repositories, locked.id) orelse {
            if (diagnostic) |sink| sink.note(
                "locked repository {s} absent from runtime evidence",
                .{locked.id[0..12]},
            );
            return error.RepositoryEvidenceMismatch;
        };
        if (!std.mem.eql(u8, &locked.snapshot_sha256, &repository.snapshot_sha256) or
            !std.mem.eql(u8, &locked.release_sha256, &repository.release_sha256) or
            !std.mem.eql(u8, &locked.index_sha256, &repository.metadata_sha256) or
            !sameFingerprints(locked.signer_fingerprints, repository.signer_fingerprints) or
            !repository.signature_verified)
            return error.RepositoryEvidenceMismatch;
    }
    if (lock.packages.len != packages.len) return error.MissingPackageEvidence;
    for (lock.packages) |locked| {
        var found = false;
        for (packages) |package| {
            if (!std.mem.eql(u8, locked.name, package.name) or
                !std.mem.eql(u8, locked.version, package.version) or
                !std.mem.eql(u8, locked.architecture, package.architecture))
                continue;
            found = true;
            if (!std.mem.eql(u8, &locked.sha256, &package.package_sha256) or
                locked.declared_size != package.declared_size or
                !sameOrigin(locked.origin, package.origin))
                return error.PackageOriginMismatch;
        }
        if (!found) return error.MissingPackageEvidence;
    }
}

pub const ValidatedDocument = v1.ValidatedDocument;

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
    if (object.count() != 17 or hasJsonWhitespace(source))
        return error.NonCanonicalDocument;
    const schema = object.get("schema") orelse return error.UnsupportedSchema;
    const version = object.get("version") orelse return error.UnsupportedSchema;
    if (schema != .string or !std.mem.eql(u8, schema.string, schema_id) or
        version != .integer or version.integer != schema_version)
        return error.UnsupportedSchema;
    const digest_value = object.get("digest_sha256") orelse return error.InvalidDigest;
    if (digest_value != .string) return error.InvalidDigest;
    const expected = try parseDigest(digest_value.string);
    const marker = ",\"digest_sha256\":\"";
    const marker_index = std.mem.lastIndexOf(u8, source, marker) orelse
        return error.NonCanonicalDocument;
    if (marker_index + marker.len + 64 + 2 != source.len or
        source[source.len - 2] != '"' or source[source.len - 1] != '}')
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
        const stage = ".debz-result-v2.new";
        self.dir.deleteFile(self.io, stage) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
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
        switch (@import("builtin").os.tag) {
            .linux => if (std.posix.errno(std.os.linux.fsync(self.dir.handle)) != .SUCCESS)
                return error.Unexpected,
            else => {},
        }
    }
};

fn commandsFromReport(
    allocator: std.mem.Allocator,
    input: []const transaction_executor.CommandProvenance,
) ![]CommandEvidence {
    const commands = try allocator.alloc(CommandEvidence, input.len);
    for (input, 0..) |command, index| {
        const environment = try allocator.alloc(EnvironmentEntry, command.environment.len);
        for (command.environment, 0..) |entry, environment_index|
            environment[environment_index] = .{ .key = entry.key, .value = entry.value };
        commands[index] = .{
            .phase = @tagName(command.phase),
            .package = command.package,
            .argv = command.argv,
            .environment = environment,
            .command_sha256 = command.command_sha256,
            .artifact_sha256 = command.artifact_sha256,
        };
    }
    return commands;
}

fn sameOrigin(left: exact_lock_v2.PackageOrigin, right: exact_lock_v2.PackageOrigin) bool {
    return switch (left) {
        .authenticated_repository => |expected| switch (right) {
            .authenticated_repository => |actual| std.mem.eql(u8, &expected.repository_id, &actual.repository_id) and
                std.mem.eql(
                    u8,
                    &expected.repository_snapshot_sha256,
                    &actual.repository_snapshot_sha256,
                ),
            .local_artifact => false,
        },
        .local_artifact => |expected| switch (right) {
            .authenticated_repository => false,
            .local_artifact => |actual| package_origin.eqlLocalArtifact(expected, actual),
        },
    };
}

fn dupeLocalArtifact(
    allocator: std.mem.Allocator,
    artifact: package_origin.LocalArtifactEvidence,
) !package_origin.LocalArtifactEvidence {
    var result = artifact;
    result.package = try allocator.dupe(u8, artifact.package);
    result.version = try allocator.dupe(u8, artifact.version);
    result.architecture = try allocator.dupe(u8, artifact.architecture);
    result.acquisition_url = try allocator.dupe(u8, artifact.acquisition_url);
    return result;
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
        try writer.writeAll(",\"origin\":");
        try writeOrigin(writer, package.origin);
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

fn writeOrigin(writer: *std.Io.Writer, origin: exact_lock_v2.PackageOrigin) !void {
    switch (origin) {
        .authenticated_repository => |repository| {
            try writer.writeAll("{\"type\":\"authenticated_repository\",\"repository_id\":");
            try writeString(writer, &repository.repository_id);
            try writer.writeAll(",\"repository_snapshot_sha256\":");
            try writeHex(writer, &repository.repository_snapshot_sha256);
            try writer.writeByte('}');
        },
        .local_artifact => |artifact| {
            try writer.writeAll("{\"type\":\"local_artifact\",\"artifact_id\":");
            try writeString(writer, &artifact.artifact_id);
            try writer.writeAll(",\"sha256\":");
            try writeHex(writer, &artifact.sha256);
            try writer.print(",\"size\":{},\"package\":{{\"name\":", .{artifact.size});
            try writeString(writer, artifact.package);
            try writer.writeAll(",\"version\":");
            try writeString(writer, artifact.version);
            try writer.writeAll(",\"architecture\":");
            try writeString(writer, artifact.architecture);
            try writer.writeAll("},\"acquisition_url\":");
            try writeString(writer, artifact.acquisition_url);
            try writer.writeAll(",\"trust_mode\":");
            try writeString(writer, @tagName(artifact.trust_mode));
            try writer.writeByte('}');
        },
    }
}

fn writeSteps(writer: *std.Io.Writer, steps: []const JournalStep) !void {
    try writer.writeByte('[');
    for (steps, 0..) |step, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{{\"sequence\":{},\"boundary\":", .{step.sequence});
        try writeString(writer, step.boundary);
        try writer.writeAll(",\"state\":");
        try writeString(writer, step.state);
        try writer.print(",\"command_index\":{},\"recovered\":{}}}", .{
            step.command_index,
            step.recovered,
        });
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

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

fn parseDigest(value: []const u8) Error![32]u8 {
    if (value.len != 64) return error.InvalidDigest;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    return result;
}

fn findRepository(
    repositories: []const RepositoryEvidence,
    id: [64]u8,
) ?RepositoryEvidence {
    for (repositories) |repository|
        if (std.mem.eql(u8, &repository.source_config_id, &id)) return repository;
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

fn lessRepository(_: void, left: RepositoryEvidence, right: RepositoryEvidence) bool {
    return std.mem.order(u8, &left.source_config_id, &right.source_config_id) == .lt;
}

fn lessPackage(_: void, left: PackageEvidence, right: PackageEvidence) bool {
    const name = std.mem.order(u8, left.name, right.name);
    if (name != .eq) return name == .lt;
    const architecture = std.mem.order(u8, left.architecture, right.architecture);
    if (architecture != .eq) return architecture == .lt;
    return std.mem.order(u8, left.version, right.version) == .lt;
}

fn lessFingerprint(_: void, left: [20]u8, right: [20]u8) bool {
    return std.mem.order(u8, &left, &right) == .lt;
}

fn lessEnvironment(_: void, left: EnvironmentEntry, right: EnvironmentEntry) bool {
    return std.mem.order(u8, left.key, right.key) == .lt;
}

fn samePackageIdentity(left: PackageEvidence, right: PackageEvidence) bool {
    return std.mem.eql(u8, left.name, right.name) and
        std.mem.eql(u8, left.architecture, right.architecture);
}

fn validId(value: *const [64]u8) bool {
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return false;
    }
    return true;
}

fn validIdentity(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| if (byte <= 0x1f or byte == 0x7f) return false;
    return true;
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
        } else if (byte == ' ' or byte == '\n' or byte == '\r' or byte == '\t') {
            return true;
        }
    }
    return false;
}

fn safeLeaf(name: []const u8) bool {
    return name.len != 0 and
        !std.mem.eql(u8, name, ".") and
        !std.mem.eql(u8, name, "..") and
        std.mem.indexOfScalar(u8, name, '/') == null and
        std.mem.indexOfScalar(u8, name, '\\') == null;
}

test "transaction_provenance_v2.test.local artifact evidence has no repository signer fields" {
    const digest: [32]u8 = @splat(0x44);
    const artifact: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(digest),
        .sha256 = digest,
        .size = 44,
        .package = "vendor-repo",
        .version = "1",
        .architecture = "amd64",
        .acquisition_url = "https://example.test/vendor.deb",
        .trust_mode = .verified_https,
    };
    const package: PackageEvidence = .{
        .name = artifact.package,
        .version = artifact.version,
        .architecture = artifact.architecture,
        .origin = .{ .local_artifact = artifact },
        .package_sha256 = artifact.sha256,
        .cas_sha256 = artifact.sha256,
        .declared_size = artifact.size,
    };
    var owned = try create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .solver_policy_sha256 = @splat(2),
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .lock_sha256 = @splat(5),
        .repositories = &.{},
        .packages = &.{package},
        .commands = &.{},
        .journal_steps = &.{},
        .final_verification = .{
            .status = .exact_match,
            .installed_state_sha256 = @splat(6),
            .package_origins_sha256 = @splat(7),
            .detail = "verified",
        },
        .outcome = .succeeded,
    });
    defer owned.deinit();
    const json = try owned.result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"local_artifact\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"signer_fingerprints\"") == null);
    var validated = try validateDocument(std.testing.allocator, json, maximum_document_bytes);
    defer validated.deinit();
    var tampered = try std.testing.allocator.dupe(u8, json);
    defer std.testing.allocator.free(tampered);
    tampered[std.mem.indexOf(u8, tampered, "verified").?] = 'V';
    try std.testing.expectError(
        error.DigestMismatch,
        validateDocument(std.testing.allocator, tampered, maximum_document_bytes),
    );
    const noncanonical = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{ {s}",
        .{json[1..]},
    );
    defer std.testing.allocator.free(noncanonical);
    try std.testing.expectError(
        error.NonCanonicalDocument,
        validateDocument(std.testing.allocator, noncanonical, maximum_document_bytes),
    );

    const locked_package: exact_lock_v2.Package = .{
        .name = artifact.package,
        .version = artifact.version,
        .architecture = artifact.architecture,
        .origin = .{ .local_artifact = artifact },
        .sha256 = artifact.sha256,
        .declared_size = artifact.size,
        .retention = .requested,
        .dpkg_selection_hold = false,
    };
    var lock = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &.{},
        .local_artifacts = &.{artifact},
        .packages = &.{locked_package},
        .verified_origins = true,
    });
    defer lock.deinit();
    const MismatchKind = enum { digest, size, identity, url, trust, substitution };
    inline for ([_]MismatchKind{ .digest, .size, .identity, .url, .trust, .substitution }) |kind| {
        var mismatch = package;
        switch (kind) {
            .digest => {
                mismatch.package_sha256 = @splat(0xaa);
                mismatch.cas_sha256 = mismatch.package_sha256;
            },
            .size => mismatch.declared_size += 1,
            .identity => mismatch.origin.local_artifact.version = "2",
            .url => mismatch.origin.local_artifact.acquisition_url =
                "https://example.test/other.deb",
            .trust => mismatch.origin.local_artifact.trust_mode = .pinned_sha256,
            .substitution => mismatch.origin = .{ .authenticated_repository = .{
                .repository_id = @splat('a'),
                .repository_snapshot_sha256 = @splat(1),
            } },
        }
        try std.testing.expectError(
            error.PackageOriginMismatch,
            verifyLockEvidence(lock.lock, &.{}, &.{mismatch}, null),
        );
    }
}

test "transaction_provenance_v2.test.execution metadata is bound to exact lock" {
    try Result.testExecutionMetadataBoundToExactLock();
}

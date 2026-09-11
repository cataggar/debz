//! Binds native program evidence to an operation owned by a product caller.
//! Caller request and policy hashes retain their original domains. Native
//! request/policy hashes remain covered by the immutable program digest.
const std = @import("std");
const native_program = @import("native_program.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");

fn digest(value: native_program.Digest) ![32]u8 {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, &value) catch return error.InvalidProgramDigest;
    return bytes;
}

fn architecturesMatch(left: []const []const u8, right: []const []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.mem.eql(u8, a, b)) return false;
    return true;
}

fn validateRoot(
    root: root_fs.Root,
    attempt: *const root_operation.Attempt,
    program: native_program.Program,
) !void {
    if (!attempt.locked()) return error.LockLost;
    const supplied = try root.rootEntry();
    const held = try attempt.coordinator.root.rootEntry();
    if (supplied.inode != held.inode or supplied.device != held.device)
        return error.OperationRootMismatch;
    const record = attempt.record();
    if (record.backend != .native) return error.OperationBackendMismatch;
    if (!std.mem.eql(u8, record.install_root, program.install_root) or
        !std.mem.eql(u8, &record.root_identity_sha256, &try digest(program.root_identity_sha256)))
        return error.OperationRootMismatch;
    if (!std.mem.eql(u8, record.target_architecture, program.target_architecture) or
        !architecturesMatch(record.foreign_architectures, program.foreign_architectures))
        return error.OperationArchitectureMismatch;
}

pub fn evidence(program: native_program.Program) !root_operation.Evidence {
    return .{
        .authorization_sha256 = try digest(program.authorization_sha256),
        .program_sha256 = try digest(program.digest_sha256),
        .plan_sha256 = try digest(program.plan_sha256),
        .exact_lock = .{
            .schema = program.exact_lock.schema,
            .version = program.exact_lock.version,
            .digest_sha256 = try digest(program.exact_lock.digest_sha256),
        },
        .database_generation_sha256 = try digest(program.installed_database.generation_sha256),
        .artifact_evidence_sha256 = try digest(program.artifacts_sha256),
    };
}

/// Adds write-once evidence without replacing the caller's request, policy,
/// operation, attempt identity, or lock. A legacy executor bridge is not a
/// native mutation boundary and cannot be adopted here.
pub fn bind(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    program: native_program.Program,
) !void {
    try native_program.validateDocument(program);
    try validateRoot(root, attempt, program);
    const record = attempt.record();
    const state: root_operation.State = switch (record.state) {
        .reserved, .preflight => .preflight,
        .mutating, .recovering => record.state,
        else => return error.OperationNotMutable,
    };
    try attempt.advance(allocator, .{
        .state = state,
        .phase = if (state == .preflight) .preflight else record.phase,
        .evidence = try evidence(program),
    });
}

/// The private v1 interpreter used its program digest as the outer plan
/// digest. Keep that exact binding readable, but production binding above
/// always records the actual solver-plan digest.
pub fn boundPlan(
    root: root_fs.Root,
    attempt: *const root_operation.Attempt,
    program: native_program.Program,
) ![32]u8 {
    try validateRoot(root, attempt, program);
    const expected = try evidence(program);
    const record = attempt.record();
    inline for (.{
        "authorization_sha256",
        "program_sha256",
        "database_generation_sha256",
        "artifact_evidence_sha256",
    }) |field| {
        const actual = @field(record, field) orelse return error.OperationEvidenceMismatch;
        if (!std.mem.eql(u8, &actual, &@field(expected, field).?))
            return error.OperationEvidenceMismatch;
    }
    const lock = record.exact_lock orelse return error.OperationEvidenceMismatch;
    if (!lock.eql(expected.exact_lock.?)) return error.OperationEvidenceMismatch;
    const plan = record.plan_sha256 orelse return error.OperationEvidenceMismatch;
    if (std.mem.eql(u8, &plan, &expected.plan_sha256.?)) return plan;
    if (std.mem.eql(u8, &plan, &expected.program_sha256.?) and
        std.mem.eql(u8, &record.request_sha256, &try digest(program.request_sha256)) and
        std.mem.eql(u8, &record.policy_sha256, &try digest(program.executor_policy_sha256)))
        return plan;
    return error.OperationEvidenceMismatch;
}

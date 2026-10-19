//! Short system-profile install: owned attempts and versioned evidence, never execution permission.
const std = @import("std");
const builtin = @import("builtin");
const api = @import("product_api.zig");
const content_digest = @import("content_digest.zig");
const engine = @import("transaction_engine.zig");
const healthy = @import("healthy_installed_prestate.zig");
const lock_v3 = @import("exact_lock_v3.zig");
const lock_v5 = @import("exact_lock_v5.zig");
const package_database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");

const Sha512 = std.crypto.hash.sha2.Sha512;

pub const Kind = engine.Kind;

/// The execution generation an authorization names. No build provides it yet.
pub const execution_generation_id = "system-install-execution-v1";
pub const state_directory = root_operation.namespace_path ++ "/system-install";
pub const owner_lock_path = state_directory ++ "/owner.lock";
pub const active_path = state_directory ++ "/active-v1.json";
pub const operations_directory = state_directory ++ "/operations";
pub const locks_directory = root_operation.namespace_path ++ "/locks";
pub const maximum_document_bytes: usize = 16 * 1024 * 1024;
pub const maximum_package_name_bytes: usize = 255;
pub const maximum_lock_wait_ms: u64 = 86_400_000;
pub const result_schema_id = schemaId("result");
const status_path = "var/lib/dpkg/status";
const maximum_status_bytes: usize = 64 * 1024 * 1024;
const maximum_diagnostics: usize = 16;
const attempt_bytes = 16;
const lock_prefix = locks_directory ++ "/install-";
const lock_suffix = ".json";

pub const AttemptId = [attempt_bytes * 2]u8;
pub const Sha512Hex = [Sha512.digest_length * 2]u8;
pub const RepositoryHex = @FieldType(lock_v3.Repository, "id");
const Signer = @typeInfo(@FieldType(lock_v3.Repository, "signer_fingerprints")).pointer.child;
pub const SignerHex = [@sizeOf(Signer) * 2]u8;

const directory_permissions: std.Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_dir else .fromMode(0o700);
const file_permissions: std.Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);

fn schemaId(comptime name: []const u8) []const u8 {
    return "https://debz.dev/schema/system-install-" ++ name ++ "-v1";
}

pub const Output = enum { human, json };

pub const Invocation = struct {
    package: []const u8,
    backend: ?Kind = null,
    output: Output = .human,
    deadline_ms: ?u64 = null,
    lock_wait_ms: u64 = 30_000,
};

pub const Usage = struct { output: Output, message: []const u8 };

pub const Route = union(enum) {
    /// Any explicit product_api v1 option keeps the embedding contract unchanged.
    product_api,
    system: Invocation,
    usage: Usage,
};

const Flag = enum { json, assume_yes, noninteractive, transaction_backend, deadline_ms, lock_wait_ms };

fn flagOf(argument: []const u8) ?Flag {
    const spellings = [_]struct { []const u8, Flag }{
        .{ "--json", .json },
        .{ "-y", .assume_yes },
        .{ "--assume-yes", .assume_yes },
        .{ "--noninteractive", .noninteractive },
        .{ "--transaction-backend", .transaction_backend },
        .{ "--deadline-ms", .deadline_ms },
        .{ "--lock-wait-ms", .lock_wait_ms },
    };
    for (spellings) |entry| if (std.mem.eql(u8, argument, entry[0])) return entry[1];
    return null;
}

fn takesValue(flag: Flag) bool {
    return switch (flag) {
        .transaction_backend, .deadline_ms, .lock_wait_ms => true,
        .json, .assume_yes, .noninteractive => false,
    };
}

fn isOption(argument: []const u8) bool {
    return argument.len != 0 and argument[0] == '-';
}

const backend_message = blk: {
    var text: []const u8 = "--transaction-backend must be one of:";
    for (std.enums.values(Kind)) |kind| text = text ++ " " ++ @tagName(kind);
    break :blk text ++ "; nothing was changed";
};

fn usage(output: Output, message: []const u8) Route {
    return .{ .usage = .{ .output = output, .message = message } };
}

fn parseMilliseconds(text: []const u8, minimum: u64, maximum: u64) ?u64 {
    if (text.len == 0) return null;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return null;
    const value = std.fmt.parseUnsigned(u64, text, 10) catch return null;
    if (value < minimum or value > maximum) return null;
    return value;
}

fn validPackage(name: []const u8) bool {
    return name.len <= maximum_package_name_bytes and package_database.validPackageName(name);
}

/// Classifies `debz install` arguments. Only the short system form, one
/// package name plus the options below, is routed to the system profile.
pub fn route(arguments: []const []const u8) Route {
    var positionals: usize = 0;
    var json = false;
    var index: usize = 0;
    while (index < arguments.len) : (index += 1) {
        const argument = arguments[index];
        if (!isOption(argument)) {
            positionals += 1;
            continue;
        }
        const flag = flagOf(argument) orelse return .product_api;
        if (flag == .json) json = true;
        if (takesValue(flag) and index + 1 < arguments.len and !isOption(arguments[index + 1])) index += 1;
    }
    if (positionals == 0) return .product_api;
    const output: Output = if (json) .json else .human;
    var seen: std.EnumSet(Flag) = .empty;
    var invocation: Invocation = .{ .package = "", .output = output };
    var package: ?[]const u8 = null;
    index = 0;
    while (index < arguments.len) : (index += 1) {
        const argument = arguments[index];
        if (!isOption(argument)) {
            if (package != null) return usage(output, "the system profile installs exactly one package; nothing was changed");
            if (!validPackage(argument))
                return usage(output, "invalid package name; the system profile accepts one Debian package name without version, architecture, or release selectors; nothing was changed");
            package = argument;
            continue;
        }
        const flag = flagOf(argument).?;
        if (seen.contains(flag)) return usage(output, "each system install option may be given at most once; nothing was changed");
        seen.insert(flag);
        if (!takesValue(flag)) continue;
        if (index + 1 >= arguments.len or isOption(arguments[index + 1]))
            return usage(output, "--transaction-backend, --deadline-ms, and --lock-wait-ms each require a value; nothing was changed");
        index += 1;
        const value = arguments[index];
        switch (flag) {
            .transaction_backend => invocation.backend = std.meta.stringToEnum(Kind, value) orelse
                return usage(output, backend_message),
            .deadline_ms => invocation.deadline_ms = parseMilliseconds(value, 1, std.math.maxInt(u64)) orelse
                return usage(output, "--deadline-ms must be a positive decimal number of milliseconds; nothing was changed"),
            .lock_wait_ms => invocation.lock_wait_ms = parseMilliseconds(value, 0, maximum_lock_wait_ms) orelse
                return usage(output, "--lock-wait-ms must be a decimal number of milliseconds no greater than 86400000; nothing was changed"),
            .json, .assume_yes, .noninteractive => unreachable,
        }
    }
    invocation.package = package.?;
    return .{ .system = invocation };
}

pub fn commandText(allocator: std.mem.Allocator, package: []const u8, backend: Kind) ![]u8 {
    return std.fmt.allocPrint(allocator, "debz install --transaction-backend {s} {s}", .{ @tagName(backend), package });
}

fn commandMatches(command: []const u8, package: []const u8, backend: Kind) bool {
    const prefix = "debz install --transaction-backend ";
    if (!std.mem.startsWith(u8, command, prefix)) return false;
    const rest = command[prefix.len..];
    const tag = @tagName(backend);
    return rest.len == tag.len + 1 + package.len and std.mem.startsWith(u8, rest, tag) and
        rest[tag.len] == ' ' and std.mem.eql(u8, rest[tag.len + 1 ..], package);
}

/// Binds what was asked (package, backend, root), never the solved closure.
pub fn requestDigest(package: []const u8, backend: Kind, root: []const u8) Sha512Hex {
    var hash = Sha512.init(.{});
    hash.update("debz system install request v1\x00");
    hash.update(package);
    hash.update("\x00");
    hash.update(@tagName(backend));
    hash.update("\x00");
    hash.update(root);
    var digest: [Sha512.digest_length]u8 = undefined;
    hash.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn lockPath(allocator: std.mem.Allocator, attempt_id: AttemptId) ![]u8 {
    return std.mem.concat(allocator, u8, &.{ lock_prefix, &attempt_id, lock_suffix });
}

fn lockPathMatches(path: []const u8, attempt_id: AttemptId) bool {
    return path.len == lock_prefix.len + attempt_id.len + lock_suffix.len and
        std.mem.startsWith(u8, path, lock_prefix) and
        std.mem.eql(u8, path[lock_prefix.len..][0..attempt_id.len], &attempt_id) and
        std.mem.endsWith(u8, path, lock_suffix);
}

fn sha512Hex(bytes: []const u8) Sha512Hex {
    var digest: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn lowerHex(text: []const u8) bool {
    for (text) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    return true;
}

fn upperHex(text: []const u8) bool {
    for (text) |byte| if (!std.ascii.isDigit(byte) and (byte < 'A' or byte > 'F')) return false;
    return true;
}

fn absolute(path: []const u8) bool {
    return path.len != 0 and path[0] == '/';
}

fn header(value: anytype) bool {
    return std.mem.eql(u8, value.schema, @TypeOf(value).schema_id) and value.version == 1;
}

/// Every fixed-width text field is hexadecimal: signer fingerprints are
/// uppercase, every other identity is lowercase.
fn validateText(value: anytype) bool {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.field_names) |field_name| if (!validateText(@field(value, field_name))) return false;
            return true;
        },
        .optional => return if (value) |inner| validateText(inner) else true,
        .array => |info| {
            if (info.child != u8) {
                for (value) |item| if (!validateText(item)) return false;
                return true;
            }
            return if (T == SignerHex) upperHex(&value) else lowerHex(&value);
        },
        .pointer => |info| {
            if (info.size != .slice or info.child == u8) return true;
            for (value) |item| if (!validateText(item)) return false;
            return true;
        },
        else => return true,
    }
}

pub const Profile = struct {
    name: enum { system_default } = .system_default,
    root: []const u8,
    cache_path: []const u8,
    state_path: []const u8,
    locks_path: []const u8,
    evidence_path: []const u8,
    architecture: []const u8,
    conffile: enum { keep_existing } = .keep_existing,
    noninteractive: bool = true,

    fn validate(self: Profile) bool {
        return self.noninteractive and absolute(self.root) and absolute(self.cache_path) and
            absolute(self.state_path) and absolute(self.locks_path) and absolute(self.evidence_path) and
            self.architecture.len != 0;
    }
};

pub const RequestPayload = struct {
    pub const schema_id = schemaId("request");
    schema: []const u8 = schema_id,
    version: u32 = 1,
    attempt_id: AttemptId,
    operation: enum { install } = .install,
    package: []const u8,
    backend: Kind,
    profile: Profile,
    command: []const u8,
    request_sha512: Sha512Hex,

    fn validate(self: RequestPayload) bool {
        const expected = requestDigest(self.package, self.backend, self.profile.root);
        return header(self) and validPackage(self.package) and self.profile.validate() and
            commandMatches(self.command, self.package, self.backend) and
            std.mem.eql(u8, &expected, &self.request_sha512);
    }
};

/// The single owned-attempt pointer. Present exactly while an attempt is unsettled.
pub const ActivePayload = struct {
    pub const schema_id = schemaId("active");
    schema: []const u8 = schema_id,
    version: u32 = 1,
    attempt_id: AttemptId,
    request_sha512: Sha512Hex,
    request_document_sha512: Sha512Hex,
    command: []const u8,

    fn validate(self: ActivePayload) bool {
        return header(self) and self.command.len != 0;
    }
};

pub const Phase = enum { reserved, lock_bound, authorized, executing, recovery_required, terminal };
pub const Outcome = enum {
    rejected,
    refused_before_mutation,
    abandoned_before_mutation,
    completed,
    recovery_required,
    interrupted,
};

pub const LockReference = struct { path: []const u8, document_sha512: Sha512Hex };

pub const Terminal = struct {
    outcome: Outcome,
    changed: bool = false,
    exit_status: u8,
    id: ?api.ErrorId = null,
    message: []const u8,

    fn validate(self: Terminal) bool {
        const status = std.enums.fromInt(api.ExitStatus, self.exit_status) orelse return false;
        if (self.message.len == 0) return false;
        return switch (self.outcome) {
            .completed => status == .success and self.id == null,
            .rejected, .refused_before_mutation, .abandoned_before_mutation => status != .success and
                !self.changed and self.id != null,
            .recovery_required, .interrupted => false,
        };
    }
};

fn allowedTransition(from: Phase, to: Phase) bool {
    return switch (from) {
        .reserved => to == .lock_bound or to == .terminal,
        .lock_bound => to == .authorized or to == .terminal,
        .authorized => to == .executing or to == .terminal,
        .executing => to == .recovery_required or to == .terminal,
        .recovery_required, .terminal => false,
    };
}

/// The replaced-in-place attempt state; each generation chains its predecessor.
pub const ProgressPayload = struct {
    pub const schema_id = schemaId("progress");
    schema: []const u8 = schema_id,
    version: u32 = 1,
    attempt_id: AttemptId,
    generation: u64,
    previous_progress_sha512: ?Sha512Hex = null,
    request_document_sha512: Sha512Hex,
    phase: Phase,
    lock: ?LockReference = null,
    program_document_sha512: ?Sha512Hex = null,
    authorization_document_sha512: ?Sha512Hex = null,
    terminal: ?Terminal = null,
    reason: ?[]const u8 = null,

    fn validate(self: ProgressPayload) bool {
        if (!header(self) or self.generation == 0) return false;
        if ((self.generation == 1) != (self.previous_progress_sha512 == null)) return false;
        if (self.lock) |lock| if (!lockPathMatches(lock.path, self.attempt_id)) return false;
        const has_lock = self.lock != null;
        const has_program = self.program_document_sha512 != null;
        const has_authorization = self.authorization_document_sha512 != null;
        const settled = self.terminal == null and self.reason == null;
        return switch (self.phase) {
            .reserved => !has_lock and !has_program and !has_authorization and settled and self.generation == 1,
            .lock_bound => has_lock and !has_program and !has_authorization and settled,
            .authorized, .executing => has_lock and has_program and has_authorization and settled,
            .recovery_required => has_lock and has_program and has_authorization and self.terminal == null and
                if (self.reason) |reason| reason.len != 0 else false,
            .terminal => if (self.terminal) |terminal| terminal.validate() and self.reason == null and
                (!has_authorization or has_program) and (!has_program or has_lock) else false,
        };
    }
};

pub const ArchiveClass = enum { signed_sha512, signed_sha256_derived_sha512, signed_sha256_only };
pub const PublishedDigest = struct { algorithm: content_digest.Algorithm, value: []const u8 };
const DerivedProvenance = enum { derived_from_signed_sha256 };
comptime {
    std.debug.assert(std.mem.eql(u8, @tagName(DerivedProvenance.derived_from_signed_sha256), lock_v3.derived_sha512_provenance));
}
/// A SHA-512 computed locally from bytes that matched the signed SHA-256; never a signed record.
pub const DerivedDigest = struct {
    value: Sha512Hex,
    provenance: DerivedProvenance = .derived_from_signed_sha256,
};

pub const ArchiveEntry = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    retention: lock_v3.Retention,
    archive_authentication: ArchiveClass,
    repository_id: RepositoryHex,
    published_digests: []const PublishedDigest,
    primary: content_digest.Algorithm,
    derived_sha512: ?DerivedDigest = null,
    dpkg_selection_hold: bool,
    declared_size: u64,

    fn validate(self: ArchiveEntry) bool {
        if (!validPackage(self.package) or self.version.len == 0 or self.architecture.len == 0) return false;
        if (self.published_digests.len == 0 or self.published_digests.len > content_digest.supported_algorithms.len)
            return false;
        var published_sha512 = false;
        var primary_published = false;
        for (self.published_digests, 0..) |published, index| {
            if (index != 0 and @intFromEnum(published.algorithm) <= @intFromEnum(self.published_digests[index - 1].algorithm))
                return false;
            if (published.value.len != published.algorithm.hexLength() or !lowerHex(published.value)) return false;
            if (published.algorithm == .sha512) published_sha512 = true;
            if (published.algorithm == self.primary) primary_published = true;
        }
        if (!primary_published) return false;
        return switch (self.archive_authentication) {
            .signed_sha512 => published_sha512 and self.derived_sha512 == null,
            .signed_sha256_derived_sha512 => !published_sha512 and self.primary == .sha256 and self.derived_sha512 != null,
            .signed_sha256_only => !published_sha512 and self.derived_sha512 == null,
        };
    }
};

pub const Selection = enum { install, hold };
pub const InstalledFact = struct { name: []const u8, version: []const u8, architecture: []const u8, selection: Selection };
pub const InstalledAuthority = enum { healthy_installed_prestate };
pub const InstalledOrigin = enum { installed_package_database };

/// Observed package-database facts. They deliberately carry no archive origin.
pub const InstalledFacts = struct {
    authority: InstalledAuthority = .healthy_installed_prestate,
    origin: InstalledOrigin = .installed_package_database,
    database_sha512: Sha512Hex,
    facts: []const InstalledFact,

    fn validate(self: InstalledFacts) bool {
        return self.facts.len != 0 and sortedFacts(self.facts);
    }
};

fn sortedFacts(facts: []const InstalledFact) bool {
    for (facts, 0..) |fact, index| {
        if (fact.name.len == 0 or fact.version.len == 0 or fact.architecture.len == 0) return false;
        if (index == 0) continue;
        const previous = facts[index - 1];
        const order = std.mem.order(u8, previous.name, fact.name);
        const identity = if (order == .eq) std.mem.order(u8, previous.architecture, fact.architecture) else order;
        if (identity != .lt) return false;
    }
    return true;
}

pub const FreshnessPolicy = enum { require_valid_until, bounded_missing_valid_until, frozen_release };
pub const Freshness = struct {
    policy: FreshnessPolicy,
    maximum_release_age_seconds: ?u64 = null,

    fn validate(self: Freshness) bool {
        if (self.maximum_release_age_seconds) |seconds| return self.policy == .bounded_missing_valid_until and seconds != 0;
        return self.policy != .bounded_missing_valid_until;
    }
};

pub const RepositoryEntry = struct {
    id: RepositoryHex,
    uri: []const u8,
    suite: []const u8,
    component: []const u8,
    archive_binding: lock_v3.ArchiveBinding,
    signers: []const SignerHex,
    freshness: Freshness,

    fn validate(self: RepositoryEntry) bool {
        return self.uri.len != 0 and self.suite.len != 0 and self.component.len != 0 and
            self.signers.len != 0 and self.freshness.validate();
    }
};

fn repositoriesValid(repositories: []const RepositoryEntry) bool {
    for (repositories, 0..) |repository, index| {
        if (!repository.validate()) return false;
        if (index != 0 and std.mem.order(u8, &repositories[index - 1].id, &repository.id) != .lt) return false;
    }
    return true;
}

fn archivesValid(archives: []const ArchiveEntry, repositories: []const RepositoryEntry, backend: ?Kind) bool {
    for (archives, 0..) |archive, index| {
        if (!archive.validate()) return false;
        if (backend) |kind| if (kind == .native and archive.archive_authentication == .signed_sha256_only) return false;
        if (index != 0) {
            const previous = archives[index - 1];
            const order = std.mem.order(u8, previous.package, archive.package);
            const identity = if (order == .eq) std.mem.order(u8, previous.architecture, archive.architecture) else order;
            if (identity != .lt) return false;
        }
        for (repositories) |repository| {
            if (std.mem.eql(u8, &repository.id, &archive.repository_id)) break;
        } else return false;
    }
    return true;
}

/// The exact program one execution generation may run: the lock's archive
/// closure, the healthy installed facts it was planned against, and the
/// repository authority that binds each archive.
pub const ProgramPayload = struct {
    pub const schema_id = schemaId("program");
    schema: []const u8 = schema_id,
    version: u32 = 1,
    attempt_id: AttemptId,
    request_document_sha512: Sha512Hex,
    lock: LockReference,
    backend: Kind,
    target_architecture: []const u8,
    execution_generation: []const u8 = execution_generation_id,
    archives: []const ArchiveEntry,
    installed: InstalledFacts,
    repositories: []const RepositoryEntry,

    fn validate(self: ProgramPayload) bool {
        return header(self) and lockPathMatches(self.lock.path, self.attempt_id) and
            std.mem.eql(u8, self.execution_generation, execution_generation_id) and
            self.target_architecture.len != 0 and self.installed.validate() and
            repositoriesValid(self.repositories) and archivesValid(self.archives, self.repositories, self.backend);
    }
};

/// The install subcommand itself is the authorization for the fixed system profile.
pub const AuthorizationPayload = struct {
    pub const schema_id = schemaId("authorization");
    schema: []const u8 = schema_id,
    version: u32 = 1,
    authority: enum { system_install_invocation } = .system_install_invocation,
    attempt_id: AttemptId,
    command: []const u8,
    request_document_sha512: Sha512Hex,
    program_document_sha512: Sha512Hex,
    lock: LockReference,
    backend: Kind,
    conffile: enum { keep_existing } = .keep_existing,
    noninteractive: bool = true,
    execution_generation: []const u8 = execution_generation_id,

    fn validate(self: AuthorizationPayload) bool {
        return header(self) and self.noninteractive and lockPathMatches(self.lock.path, self.attempt_id) and
            std.mem.eql(u8, self.execution_generation, execution_generation_id) and self.command.len != 0;
    }
};

pub const ReceiptPayload = struct {
    pub const schema_id = schemaId("receipt");
    schema: []const u8 = schema_id,
    version: u32 = 1,
    attempt_id: AttemptId,
    request_document_sha512: Sha512Hex,
    progress_document_sha512: Sha512Hex,
    terminal: Terminal,
    lock: ?LockReference = null,
    program_document_sha512: ?Sha512Hex = null,
    authorization_document_sha512: ?Sha512Hex = null,

    fn validate(self: ReceiptPayload) bool {
        if (self.lock) |lock| if (!lockPathMatches(lock.path, self.attempt_id)) return false;
        return header(self) and self.terminal.validate() and
            (self.authorization_document_sha512 == null or self.program_document_sha512 != null) and
            (self.program_document_sha512 == null or self.lock != null);
    }
};

pub const RecoveryPayload = struct {
    pub const schema_id = schemaId("recovery");
    schema: []const u8 = schema_id,
    version: u32 = 1,
    attempt_id: AttemptId,
    request_document_sha512: Sha512Hex,
    progress_document_sha512: Sha512Hex,
    lock: LockReference,
    program_document_sha512: Sha512Hex,
    authorization_document_sha512: Sha512Hex,
    command: []const u8,
    guidance: []const u8,
    reason: []const u8,

    fn validate(self: RecoveryPayload) bool {
        return header(self) and lockPathMatches(self.lock.path, self.attempt_id) and self.command.len != 0 and
            self.guidance.len != 0 and self.reason.len != 0;
    }
};

pub const DocumentKind = enum { request, progress, lock, program, authorization, receipt, recovery };
pub const DocumentReference = struct { kind: DocumentKind, path: []const u8, document_sha512: Sha512Hex };

pub const InstalledSummary = struct {
    authority: InstalledAuthority = .healthy_installed_prestate,
    origin: InstalledOrigin = .installed_package_database,
    database_sha512: Sha512Hex,
    fact_count: u64,
    held: []const InstalledFact,
};

pub const PlanSummary = struct {
    target_architecture: []const u8,
    archives: []const ArchiveEntry,
    installed: InstalledSummary,
    repositories: []const RepositoryEntry,

    fn validate(self: PlanSummary, backend: ?Kind) bool {
        if (self.installed.fact_count < self.installed.held.len or !sortedFacts(self.installed.held)) return false;
        for (self.installed.held) |fact| if (fact.selection != .hold) return false;
        return self.target_architecture.len != 0 and repositoriesValid(self.repositories) and
            archivesValid(self.archives, self.repositories, backend);
    }
};

pub const Diagnostic = struct { id: api.ErrorId, message: []const u8 };

/// The per-operation result: outcome, exact evidence paths, and the planned actions.
pub const ResultPayload = struct {
    pub const schema_id = result_schema_id;
    schema: []const u8 = schema_id,
    version: u32 = 1,
    operation: enum { install } = .install,
    exit_status: u8,
    outcome: Outcome,
    changed: bool = false,
    package: []const u8,
    summary: []const u8,
    backend: ?Kind = null,
    command: ?[]const u8 = null,
    attempt_id: ?AttemptId = null,
    resumed: bool = false,
    profile: ?Profile = null,
    lock: ?[]const u8 = null,
    evidence_path: ?[]const u8 = null,
    documents: []const DocumentReference = &.{},
    plan: ?PlanSummary = null,
    diagnostics: []const Diagnostic = &.{},

    pub fn validate(self: ResultPayload) bool {
        const status = std.enums.fromInt(api.ExitStatus, self.exit_status) orelse return false;
        if (!header(self) or self.package.len == 0 or self.summary.len == 0) return false;
        if (self.diagnostics.len > maximum_diagnostics) return false;
        if ((status == .success) != (self.outcome == .completed)) return false;
        if (status != .success and self.diagnostics.len == 0) return false;
        if (self.changed and self.outcome != .completed and self.outcome != .recovery_required) return false;
        if (self.resumed and self.attempt_id == null) return false;
        if (self.profile) |profile| if (!profile.validate()) return false;
        if (self.plan) |plan| if (!plan.validate(self.backend)) return false;
        return true;
    }
};

pub const OwnedResult = struct {
    arena: *std.heap.ArenaAllocator,
    value: ResultPayload,

    pub fn deinit(self: *OwnedResult) void {
        const backing = self.arena.child_allocator;
        self.arena.deinit();
        backing.destroy(self.arena);
        self.* = undefined;
    }

    pub fn exitStatus(self: *const OwnedResult) api.ExitStatus {
        return std.enums.fromInt(api.ExitStatus, self.value.exit_status) orelse .internal;
    }

    pub fn canonicalJson(self: *const OwnedResult, allocator: std.mem.Allocator) ![]u8 {
        return encodeValue(allocator, self.value);
    }
};

fn newArena(allocator: std.mem.Allocator) !*std.heap.ArenaAllocator {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = .init(allocator);
    return arena;
}

fn dropArena(arena: *std.heap.ArenaAllocator) void {
    const backing = arena.child_allocator;
    arena.deinit();
    backing.destroy(arena);
}

pub fn decodeResult(allocator: std.mem.Allocator, bytes: []const u8) !OwnedResult {
    if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
    const arena = try newArena(allocator);
    errdefer dropArena(arena);
    const value = std.json.parseFromSliceLeaky(ResultPayload, arena.allocator(), bytes, .{
        .allocate = .alloc_always,
        .max_value_len = maximum_document_bytes,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidResult,
    };
    const canonical = try encodeValue(arena.allocator(), value);
    if (!std.mem.eql(u8, canonical, bytes)) return error.NonCanonicalResult;
    if (!validateText(value) or !value.validate()) return error.InvalidResult;
    return .{ .arena = arena, .value = value };
}

/// Stopped by required recovery (possibly retaining an owned attempt), or rejected outright.
fn refusedOutcome(id: api.ErrorId) Outcome {
    return if (id == .root_operation_recovery_required) .interrupted else .rejected;
}

/// A result for refusals before any attempt exists or when no result was received.
pub fn refusal(
    allocator: std.mem.Allocator,
    package: []const u8,
    status: api.ExitStatus,
    id: api.ErrorId,
    message: []const u8,
) !OwnedResult {
    std.debug.assert(status != .success);
    const arena = try newArena(allocator);
    errdefer dropArena(arena);
    const scratch = arena.allocator();
    const diagnostics = try scratch.alloc(Diagnostic, 1);
    diagnostics[0] = .{ .id = id, .message = try scratch.dupe(u8, message) };
    return .{ .arena = arena, .value = .{
        .exit_status = @intFromEnum(status),
        .outcome = refusedOutcome(id),
        .package = try scratch.dupe(u8, package),
        .summary = diagnostics[0].message,
        .diagnostics = diagnostics,
    } };
}

fn encodeValue(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, value, .{ .emit_null_optional_fields = false });
}

fn Envelope(comptime Payload: type) type {
    return struct { payload: Payload, digest_sha512: Sha512Hex };
}

const Encoded = struct { bytes: []u8, digest: Sha512Hex };

/// `{payload, digest_sha512}` where the digest is SHA-512 of the canonical payload.
fn encodeEnvelope(allocator: std.mem.Allocator, payload: anytype) !Encoded {
    const payload_bytes = try encodeValue(allocator, payload);
    defer allocator.free(payload_bytes);
    const digest = sha512Hex(payload_bytes);
    const bytes = try encodeValue(allocator, Envelope(@TypeOf(payload)){ .payload = payload, .digest_sha512 = digest });
    return .{ .bytes = bytes, .digest = digest };
}

fn Decoded(comptime Payload: type) type {
    return struct { payload: Payload, digest: Sha512Hex };
}

fn decodeEnvelope(comptime Payload: type, allocator: std.mem.Allocator, bytes: []const u8) !Decoded(Payload) {
    if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
    const Header = struct {
        payload: struct { schema: []const u8, version: u32 },
        digest_sha512: []const u8,
    };
    const head = std.json.parseFromSliceLeaky(Header, allocator, bytes, .{
        .ignore_unknown_fields = true,
        .max_value_len = maximum_document_bytes,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidDocument,
    };
    if (!std.mem.eql(u8, head.payload.schema, Payload.schema_id) or head.payload.version != 1)
        return error.UnsupportedSchema;
    const envelope = std.json.parseFromSliceLeaky(Envelope(Payload), allocator, bytes, .{
        .allocate = .alloc_always,
        .max_value_len = maximum_document_bytes,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidDocument,
    };
    const encoded = try encodeEnvelope(allocator, envelope.payload);
    if (!std.mem.eql(u8, &encoded.digest, &envelope.digest_sha512)) return error.DigestMismatch;
    if (!std.mem.eql(u8, encoded.bytes, bytes)) return error.NonCanonicalDocument;
    if (!validateText(envelope.payload) or !envelope.payload.validate()) return error.InvalidDocument;
    return .{ .payload = envelope.payload, .digest = encoded.digest };
}

fn classText(class: ArchiveClass) []const u8 {
    return switch (class) {
        .signed_sha512 => "signed SHA-512 published by the signed index",
        .signed_sha256_derived_sha512 => "signed SHA-256; SHA-512 derived locally from the signed SHA-256 match " ++
            "(derived_from_signed_sha256; not independently signed)",
        .signed_sha256_only => "signed SHA-256 only; no SHA-512 published by the signed index",
    };
}

fn writeFreshness(writer: *std.Io.Writer, freshness: Freshness) !void {
    switch (freshness.policy) {
        .require_valid_until => try writer.writeAll("signed Valid-Until required"),
        .bounded_missing_valid_until => try writer.print(
            "missing Valid-Until accepted for at most {d} s (explicit repository bound)",
            .{freshness.maximum_release_age_seconds.?},
        ),
        .frozen_release => try writer.writeAll("frozen signed Release with witnesses"),
    }
}

/// JSON is the canonical result document on one stdout line; human output
/// goes to stdout only on success.
pub fn render(
    allocator: std.mem.Allocator,
    result: *const ResultPayload,
    output: Output,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !void {
    if (output == .json) {
        const bytes = try encodeValue(allocator, result.*);
        defer allocator.free(bytes);
        try stdout.writeAll(bytes);
        try stdout.writeByte('\n');
        return;
    }
    const writer = if (result.exit_status == 0) stdout else stderr;
    try writer.print("install: {s}\n", .{result.summary});
    if (result.attempt_id) |id| try writer.print("attempt: {s}{s}\n", .{ &id, if (result.resumed) " (resumed)" else "" });
    if (result.backend) |backend| try writer.print("backend: {s}\n", .{@tagName(backend)});
    if (result.lock) |path| try writer.print("exact lock: {s}\n", .{path});
    if (result.evidence_path) |path| try writer.print("evidence: {s}\n", .{path});
    if (result.plan) |plan| {
        try writer.print("actions ({d}):\n", .{plan.archives.len});
        for (plan.archives) |archive| try writer.print("  install {s} {s} [{s}] {s}: {s}\n", .{
            archive.package,
            archive.version,
            archive.architecture,
            @tagName(archive.retention),
            classText(archive.archive_authentication),
        });
        for (plan.repositories) |repository| {
            try writer.print("repository {s} {s} {s}: ", .{ repository.uri, repository.suite, repository.component });
            try writeFreshness(writer, repository.freshness);
            try writer.writeByte('\n');
        }
        try writer.print(
            "installed facts: {d} from the healthy installed package database (no archive origin)\n",
            .{plan.installed.fact_count},
        );
        for (plan.installed.held) |fact|
            try writer.print("  held {s} {s} [{s}] (no archive origin)\n", .{ fact.name, fact.version, fact.architecture });
    }
    for (result.diagnostics) |diagnostic|
        try writer.print("debz[{s}]: {s}\n", .{ @tagName(diagnostic.id), diagnostic.message });
}

pub const RepositoryAuthority = struct {
    id: RepositoryHex,
    uri: []const u8,
    suite: []const u8,
    component: []const u8,
    freshness: Freshness,
    archive_binding: lock_v3.ArchiveBinding,
};

pub const Hook = struct {
    context: ?*anyopaque = null,
    function: *const fn (?*anyopaque) anyerror!void,
};

/// What the active configuration authorizes now. Every bind re-checks the
/// retained exact lock against it, so a lock never outlives its authority.
pub const Authority = struct {
    /// Physical root the planner observed; the healthy evidence root path.
    root_path: []const u8,
    /// The root as the operator names it in commands and evidence paths.
    display_root: []const u8 = "/",
    cache_path: []const u8 = "/var/cache/debz",
    state_path: []const u8 = "/var/lib/debz",
    architecture: []const u8,
    context: lock_v5.ContextBinding,
    repositories: []const RepositoryAuthority,
    /// Re-verifies the active configuration and refuses other surfaces' owned work.
    revalidate: ?Hook = null,

    fn repository(self: *const Authority, id: RepositoryHex) ?RepositoryAuthority {
        for (self.repositories) |candidate| if (std.mem.eql(u8, &candidate.id, &id)) return candidate;
        return null;
    }
};

pub const PlanRequest = struct {
    attempt_id: AttemptId,
    package: []const u8,
    backend: Kind,
    /// Absolute physical path; the planner publishes the exact lock there and nowhere else.
    lock_output_path: []const u8,
    deadline_ms: ?u64,
    lock_wait_ms: u64,
};

pub const Refusal = struct { exit_status: api.ExitStatus, id: api.ErrorId, message: []const u8 };
pub const PlanOutcome = union(enum) { published, refused: Refusal };

/// Plans one request and publishes its exact lock. It runs outside the shared
/// root-operation guard because the production planner takes that guard itself.
pub const Planner = struct {
    context: ?*anyopaque = null,
    planFn: *const fn (?*anyopaque, std.mem.Allocator, PlanRequest) anyerror!PlanOutcome,
};

pub const ExecuteRequest = struct {
    attempt_id: AttemptId,
    backend: Kind,
    lock: *const lock_v5.OwnedLock,
    lock_path: []const u8,
    program_document_sha512: Sha512Hex,
    authorization_document_sha512: Sha512Hex,
};

pub const ExecutionOutcome = union(enum) {
    completed: struct { changed: bool },
    /// Final verification refused before any mutation.
    refused_before_mutation: []const u8,
    /// Mutation may have begun; the attempt becomes sticky recovery.
    failed_after_mutation: []const u8,
};

pub const Executor = struct {
    context: ?*anyopaque = null,
    /// Why this build cannot run the execution generation for a backend, or null.
    unavailableFn: *const fn (?*anyopaque, Kind) ?[]const u8,
    executeFn: *const fn (?*anyopaque, std.mem.Allocator, ExecuteRequest) anyerror!ExecutionOutcome,
};

pub const configuration_required_message =
    "no active repository configuration; run 'sudo debz repo add --url <descriptor>' first; nothing was changed";

pub const pending_execution_message = execution_generation_id ++
    " is not available in this build; nothing was changed; the exact lock is retained";

pub const recovery_guidance = "automatic retry is refused after execution may have begun; operator recovery for " ++
    execution_generation_id ++ " is not available in this build; preserve the evidence under /" ++ state_directory;

fn pendingUnavailable(_: ?*anyopaque, _: Kind) ?[]const u8 {
    return pending_execution_message;
}

fn pendingExecute(_: ?*anyopaque, _: std.mem.Allocator, _: ExecuteRequest) anyerror!ExecutionOutcome {
    return error.ExecutionGenerationUnavailable;
}

/// No build provides the execution generation yet: every authorized attempt
/// is refused before mutation and its exact lock is retained.
pub const pending_executor: Executor = .{ .unavailableFn = pendingUnavailable, .executeFn = pendingExecute };

/// Durable boundaries a test may interrupt to prove exact owned retry.
pub const CrashPoint = enum {
    after_request,
    after_reservation,
    after_lock_publication,
    after_lock_bound,
    after_program,
    after_authorization,
    after_authorized,
    after_executing,
    after_execution,
    after_terminal,
    after_receipt,
};

pub const Observer = struct {
    context: ?*anyopaque = null,
    hitFn: *const fn (?*anyopaque, CrashPoint) anyerror!void,
};

pub const Engine = struct {
    io: std.Io,
    authority: Authority,
    planner: Planner,
    executor: Executor = pending_executor,
    observer: ?Observer = null,
    locks: root_operation.LockBackend,

    /// One system install under the owner lock and the shared root-operation
    /// guard: the unsettled owned attempt is adopted exactly, or refused, before
    /// any new plan. Every failure except allocation is a reported result.
    pub fn run(self: *const Engine, allocator: std.mem.Allocator, invocation: Invocation, kind: Kind) !OwnedResult {
        const arena = try newArena(allocator);
        errdefer dropArena(arena);
        var session: Session = .{ .runner = self, .allocator = arena.allocator(), .invocation = invocation, .kind = kind };
        defer session.close();
        var value = session.run() catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => try session.failedResult(err),
        };
        if (!validateText(value) or !value.validate())
            value = try session.plainResult(.internal, .internal_error, "system install produced an invalid result; the evidence under /" ++
                state_directory ++ " was left as written");
        return .{ .arena = arena, .value = value };
    }
};

const Attempt = struct {
    id: AttemptId,
    request: RequestPayload,
    request_document: Sha512Hex,
    progress: ProgressPayload,
    progress_document: Sha512Hex,
    resumed: bool,
    program_document: ?Sha512Hex = null,
    authorization_document: ?Sha512Hex = null,
    receipt_document: ?Sha512Hex = null,
    recovery_document: ?Sha512Hex = null,
    plan: ?PlanSummary = null,
};

const Change = struct { lock: ?LockReference = null, terminal: ?Terminal = null, reason: ?[]const u8 = null };

fn documentPath(allocator: std.mem.Allocator, id: AttemptId, kind: DocumentKind) ![]u8 {
    if (kind == .lock) return lockPath(allocator, id);
    return std.mem.concat(allocator, u8, &.{ operations_directory, "/", &id, "/", @tagName(kind), "-v1.json" });
}

fn operationPath(allocator: std.mem.Allocator, id: AttemptId) ![]u8 {
    return std.mem.concat(allocator, u8, &.{ operations_directory, "/", &id });
}

fn requestedBy(archive_lock: lock_v3.Lock, evidence: healthy.Evidence, name: []const u8) bool {
    for (archive_lock.packages) |candidate|
        if (candidate.retention == .requested and std.mem.eql(u8, candidate.name, name)) return true;
    for (evidence.observed.packages) |candidate| if (std.mem.eql(u8, candidate.name, name)) return true;
    return false;
}

const Session = struct {
    runner: *const Engine,
    allocator: std.mem.Allocator,
    invocation: Invocation,
    kind: Kind,
    root: ?root_fs.OwnedRoot = null,
    root_uid: u32 = 0,
    identity: ?root_operation.Identity = null,
    owner: ?root_operation.LockToken = null,
    guard: ?root_operation.LockToken = null,
    attempt: ?Attempt = null,
    /// Set while an owned attempt pointer exists; failures then never start new work.
    adoptable: bool = false,

    fn fs(self: *const Session) root_fs.Root {
        return self.root.?.root;
    }

    fn print(self: *const Session, comptime format: []const u8, arguments: anytype) ![]u8 {
        return std.fmt.allocPrint(self.allocator, format, arguments);
    }

    fn close(self: *Session) void {
        self.releaseGuard();
        if (self.owner) |token| self.runner.locks.release(token);
        self.owner = null;
        if (self.root) |*owned| owned.close();
        self.root = null;
    }

    fn run(self: *Session) !ResultPayload {
        try self.openRoot();
        try self.acquireOwner();
        try self.enterGuard();
        try self.ensureSafeDirectory(operations_directory);
        if (try self.adoptAttempt()) |result| return result;
        return self.startAttempt();
    }

    fn openRoot(self: *Session) !void {
        const authority = &self.runner.authority;
        self.root = try root_fs.openAbsoluteRoot(self.runner.io, authority.root_path);
        const top = try self.fs().rootEntry();
        if (!top.modeled or !top.isDirectory()) return error.UnsafeSystemInstallState;
        self.root_uid = top.uid;
        self.identity = .{ .install_root_sha256 = transaction_recovery.rootIdentity(authority.root_path), .inode = top.inode };
        const namespace = try self.fs().entryIfExists(try root_fs.Path.init(root_operation.namespace_path)) orelse
            return error.ConfigurationRequired;
        try self.requireSafeDirectory(namespace);
        try self.ensureSafeDirectory(state_directory);
    }

    fn acquireLock(self: *Session, relative: []const u8) !root_operation.LockToken {
        return self.runner.locks.acquire(.{
            .rank = .root_operation,
            .root = self.fs(),
            .identity = self.identity.?,
            .path = relative,
            .wait_ms = self.invocation.lock_wait_ms,
            .cancellation = transaction_executor.Cancellation.never(),
        });
    }

    /// Serializes system installs; held for the whole run, including planning.
    fn acquireOwner(self: *Session) !void {
        self.owner = self.acquireLock(owner_lock_path) catch |err| switch (err) {
            error.LockTimeout => return error.OwnerLockBusy,
            else => return err,
        };
        try self.requireSafeFile(try self.fs().entry(try root_fs.Path.init(owner_lock_path)));
    }

    /// The shared root-operation guard, held for every state transition.
    fn enterGuard(self: *Session) !void {
        std.debug.assert(self.guard == null);
        self.guard = self.acquireLock(root_operation.lock_path) catch |err| switch (err) {
            error.LockTimeout => return error.RootOperationBusy,
            else => return err,
        };
        try self.requireSafeFile(try self.fs().entry(try root_fs.Path.init(root_operation.lock_path)));
    }

    fn releaseGuard(self: *Session) void {
        if (self.guard) |token| self.runner.locks.release(token);
        self.guard = null;
    }

    /// Exact owned retry: an unsettled attempt is resumed by its own request,
    /// or refuses every other request, before any refresh or replan.
    fn adoptAttempt(self: *Session) !?ResultPayload {
        const pointer_bytes = try self.readOptional(active_path) orelse return null;
        self.adoptable = true;
        const pointer = try decodeEnvelope(ActivePayload, self.allocator, pointer_bytes);
        const id = pointer.payload.attempt_id;
        const request = try decodeEnvelope(RequestPayload, self.allocator, try self.readStable(try documentPath(self.allocator, id, .request)));
        const progress = try decodeEnvelope(ProgressPayload, self.allocator, try self.readStable(try documentPath(self.allocator, id, .progress)));
        if (!std.mem.eql(u8, &request.digest, &pointer.payload.request_document_sha512) or
            !std.mem.eql(u8, &request.payload.attempt_id, &id) or
            !std.mem.eql(u8, &request.payload.request_sha512, &pointer.payload.request_sha512) or
            !std.mem.eql(u8, request.payload.command, pointer.payload.command) or
            !std.mem.eql(u8, &progress.payload.attempt_id, &id) or
            !std.mem.eql(u8, &progress.payload.request_document_sha512, &request.digest))
            return error.AttemptEvidenceMismatch;
        self.attempt = .{
            .id = id,
            .request = request.payload,
            .request_document = request.digest,
            .progress = progress.payload,
            .progress_document = progress.digest,
            .resumed = true,
            .program_document = progress.payload.program_document_sha512,
            .authorization_document = progress.payload.authorization_document_sha512,
        };
        const expected = requestDigest(self.invocation.package, self.kind, self.runner.authority.display_root);
        const same = std.mem.eql(u8, &expected, &request.payload.request_sha512);
        switch (progress.payload.phase) {
            .recovery_required => {
                try self.loadPlan();
                return try self.requireRecovery(progress.payload.reason.?);
            },
            .terminal => {
                try self.settle();
                if (!same) {
                    self.attempt = null;
                    return null;
                }
                try self.loadPlan();
                return try self.attemptResult();
            },
            .reserved, .lock_bound, .authorized, .executing => {},
        }
        if (!same) return try self.blockedResult();
        switch (progress.payload.phase) {
            .executing => {
                try self.loadPlan();
                return try self.requireRecovery("the previous run was interrupted after execution began");
            },
            .reserved => {
                const published = try self.fs().entryIfExists(try root_fs.Path.init(try lockPath(self.allocator, id)));
                return if (published != null) try self.bindLock() else try self.planAndBind();
            },
            .lock_bound, .authorized => return try self.bindLock(),
            .recovery_required, .terminal => unreachable,
        }
    }

    fn blockedResult(self: *Session) !ResultPayload {
        const attempt = &self.attempt.?;
        attempt.resumed = false;
        return self.report(.{
            .outcome = .interrupted,
            .exit_status = @intFromEnum(api.ExitStatus.recovery),
            .id = .root_operation_recovery_required,
            .message = try self.print(
                "unfinished system install attempt {s} owns this root; rerun exactly 'sudo {s}' to adopt it; " ++
                    "this request was not started and nothing was changed",
                .{ &attempt.id, attempt.request.command },
            ),
        });
    }

    fn startAttempt(self: *Session) !ResultPayload {
        // Never start around another surface's owned work or a changed configuration.
        try self.revalidate();
        var random: [attempt_bytes]u8 = undefined;
        try std.Io.randomSecure(self.runner.io, &random);
        const id: AttemptId = std.fmt.bytesToHex(random, .lower);
        try self.fs().createDirectory(try root_fs.Path.init(try operationPath(self.allocator, id)), directory_permissions);
        try self.fs().syncDirectory(try root_fs.Path.init(operations_directory));
        const command = try commandText(self.allocator, self.invocation.package, self.kind);
        const request: RequestPayload = .{
            .attempt_id = id,
            .package = self.invocation.package,
            .backend = self.kind,
            .profile = try self.systemProfile(),
            .command = command,
            .request_sha512 = requestDigest(self.invocation.package, self.kind, self.runner.authority.display_root),
        };
        const request_document = try self.writeOnce(try documentPath(self.allocator, id, .request), request);
        try self.hit(.after_request);
        const progress: ProgressPayload = .{
            .attempt_id = id,
            .generation = 1,
            .request_document_sha512 = request_document,
            .phase = .reserved,
        };
        const progress_document = try self.writeOnce(try documentPath(self.allocator, id, .progress), progress);
        self.attempt = .{
            .id = id,
            .request = request,
            .request_document = request_document,
            .progress = progress,
            .progress_document = progress_document,
            .resumed = false,
        };
        _ = try self.writeOnce(active_path, ActivePayload{
            .attempt_id = id,
            .request_sha512 = request.request_sha512,
            .request_document_sha512 = request_document,
            .command = command,
        });
        self.adoptable = true;
        try self.hit(.after_reservation);
        return self.planAndBind();
    }

    fn planAndBind(self: *Session) !ResultPayload {
        const attempt = &self.attempt.?;
        try self.ensureSafeDirectory(locks_directory);
        const relative = try lockPath(self.allocator, attempt.id);
        const request: PlanRequest = .{
            .attempt_id = attempt.id,
            .package = attempt.request.package,
            .backend = self.kind,
            .lock_output_path = try std.fs.path.join(self.allocator, &.{ self.runner.authority.root_path, relative }),
            .deadline_ms = self.invocation.deadline_ms,
            .lock_wait_ms = self.invocation.lock_wait_ms,
        };
        // The owner lock stays held; the planner takes the shared guard itself.
        self.releaseGuard();
        const planned = self.runner.planner.planFn(self.runner.planner.context, self.allocator, request);
        try self.enterGuard();
        const outcome = planned catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.terminate(.{
                .outcome = .rejected,
                .exit_status = @intFromEnum(api.ExitStatus.internal),
                .id = .internal_error,
                .message = try self.print("planning failed ({s}); nothing was changed", .{@errorName(err)}),
            }, null),
        };
        switch (outcome) {
            .published => {},
            .refused => |refused| return self.terminate(.{
                .outcome = .rejected,
                .exit_status = @intFromEnum(if (refused.exit_status == .success) api.ExitStatus.internal else refused.exit_status),
                .id = refused.id,
                .message = if (std.mem.indexOf(u8, refused.message, "nothing was changed") != null)
                    refused.message
                else
                    try self.print("{s}; nothing was changed", .{refused.message}),
            }, null),
        }
        try self.hit(.after_lock_publication);
        return self.bindLock();
    }

    /// Binds the attempt to its retained exact lock after re-verifying it
    /// against the healthy installed database and the current authority.
    fn bindLock(self: *Session) !ResultPayload {
        const attempt = &self.attempt.?;
        const relative = try lockPath(self.allocator, attempt.id);
        const bytes = self.readStable(relative) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.abandonLock(err, attempt.progress.lock),
        };
        const reference: LockReference = .{ .path = relative, .document_sha512 = sha512Hex(bytes) };
        if (attempt.progress.lock) |recorded| if (!std.mem.eql(u8, &recorded.document_sha512, &reference.document_sha512))
            return self.abandonLock(error.LockDocumentChanged, recorded);
        const owned = lock_v5.decode(self.allocator, bytes) catch |err| return self.abandonLock(err, reference);
        self.verifyLock(&owned) catch |err| return self.abandonLock(err, reference);
        if (attempt.progress.phase == .reserved) {
            try self.advance(.lock_bound, .{ .lock = reference });
            try self.hit(.after_lock_bound);
        }
        const program = self.buildProgram(&owned, reference) catch |err| return self.abandonLock(err, reference);
        const recorded_program = attempt.program_document;
        const program_document = self.writeOnce(try documentPath(self.allocator, attempt.id, .program), program) catch |err| switch (err) {
            error.DocumentConflict, error.InvalidAttemptDocument => return self.abandonLock(error.ProgramEvidenceChanged, reference),
            else => return err,
        };
        if (recorded_program) |recorded| if (!std.mem.eql(u8, &recorded, &program_document))
            return self.abandonLock(error.ProgramEvidenceChanged, reference);
        attempt.program_document = program_document;
        attempt.plan = try self.summarizePlan(program);
        try self.hit(.after_program);
        if (program.archives.len == 0) return self.terminate(.{
            .outcome = .completed,
            .exit_status = @intFromEnum(api.ExitStatus.success),
            .message = try self.print(
                "{s} is already satisfied by the healthy installed package database; nothing was changed",
                .{attempt.request.package},
            ),
        }, reference);
        const recorded_authorization = attempt.authorization_document;
        const authorization_document = self.writeOnce(try documentPath(self.allocator, attempt.id, .authorization), AuthorizationPayload{
            .attempt_id = attempt.id,
            .command = attempt.request.command,
            .request_document_sha512 = attempt.request_document,
            .program_document_sha512 = program_document,
            .lock = reference,
            .backend = self.kind,
        }) catch |err| switch (err) {
            error.DocumentConflict, error.InvalidAttemptDocument => return self.abandonLock(error.AuthorizationEvidenceChanged, reference),
            else => return err,
        };
        if (recorded_authorization) |recorded| if (!std.mem.eql(u8, &recorded, &authorization_document))
            return self.abandonLock(error.AuthorizationEvidenceChanged, reference);
        attempt.authorization_document = authorization_document;
        try self.hit(.after_authorization);
        if (attempt.progress.phase == .lock_bound) {
            try self.advance(.authorized, .{});
            try self.hit(.after_authorized);
        }
        const executor = self.runner.executor;
        const lock_display = try self.displayPath(relative);
        if (executor.unavailableFn(executor.context, self.kind)) |reason| return self.terminate(.{
            .outcome = .refused_before_mutation,
            .exit_status = @intFromEnum(api.ExitStatus.unavailable),
            .id = .transaction_backend_unavailable,
            .message = try self.print("{s} is planned and authorized by exact lock {s}; {s}", .{
                attempt.request.package,
                lock_display,
                reason,
            }),
        }, reference);
        try self.advance(.executing, .{});
        try self.hit(.after_executing);
        const executed = executor.executeFn(executor.context, self.allocator, .{
            .attempt_id = attempt.id,
            .backend = self.kind,
            .lock = &owned,
            .lock_path = lock_display,
            .program_document_sha512 = program_document,
            .authorization_document_sha512 = authorization_document,
        }) catch |err| return self.requireRecovery(try self.print("execution stopped ({s}) after it may have begun", .{@errorName(err)}));
        try self.hit(.after_execution);
        switch (executed) {
            .completed => |done| return self.terminate(.{
                .outcome = .completed,
                .changed = done.changed,
                .exit_status = @intFromEnum(api.ExitStatus.success),
                .message = try self.print("{s} is installed by exact lock {s}", .{ attempt.request.package, lock_display }),
            }, reference),
            .refused_before_mutation => |reason| return self.terminate(.{
                .outcome = .refused_before_mutation,
                .exit_status = @intFromEnum(api.ExitStatus.transaction),
                .id = .transaction_failed,
                .message = try self.print("{s}; nothing was changed", .{reason}),
            }, reference),
            .failed_after_mutation => |reason| return self.requireRecovery(reason),
        }
    }

    fn verifyLock(self: *Session, owned: *const lock_v5.OwnedLock) !void {
        const authority = &self.runner.authority;
        if (owned.backend() != self.kind) return error.LockBackendChanged;
        const bound = owned.context();
        if (!std.mem.eql(u8, &bound.configuration_sha256, &authority.context.configuration_sha256) or
            !std.mem.eql(u8, &bound.manifest_sha256, &authority.context.manifest_sha256))
            return error.ActiveContextChanged;
        const evidence = owned.evidence();
        const archive_lock = owned.archive_lock.lock;
        if (!std.mem.eql(u8, evidence.observed.root_path, authority.root_path)) return error.InstalledRootChanged;
        if (!std.mem.eql(u8, evidence.observed.native_architecture, authority.architecture) or
            !std.mem.eql(u8, archive_lock.target_architecture, authority.architecture))
            return error.ArchitectureChanged;
        const verified = try healthy.verify(
            self.allocator,
            self.runner.io,
            authority.root_path,
            authority.architecture,
            try self.readStatus(),
            evidence,
        );
        verified.deinit();
        // Historical v4/v5 execution fences stay; native admits only signed or
        // authenticated-derived SHA-512 archive identities.
        if (self.kind == .native) try archive_lock.requireArchiveDigestPolicy(.sha512_identity_required);
        if (archive_lock.local_artifacts.len != 0) return error.LocalArtifactUnsupported;
        if (!requestedBy(archive_lock, evidence, self.invocation.package)) return error.RequestedPackageMissing;
        for (archive_lock.repositories) |locked| {
            const current = authority.repository(locked.id) orelse return error.RepositoryAuthorityChanged;
            if (current.archive_binding != locked.archive_binding) return error.RepositoryAuthorityChanged;
        }
        try self.revalidate();
    }

    /// Closes a pre-mutation attempt whose exact lock no longer verifies.
    fn abandonLock(self: *Session, err: anyerror, reference: ?LockReference) !ResultPayload {
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Another surface's owned work: keep this attempt exactly as it is.
            error.RootOperationRecoveryRequired => return error.RootOperationRecoveryRequired,
            else => {},
        }
        if (err == error.Sha512IdentityRequired) return self.terminate(.{
            .outcome = .abandoned_before_mutation,
            .exit_status = @intFromEnum(api.ExitStatus.planning),
            .id = .planning_failed,
            .message = "the native backend requires a signed SHA-512 or an authenticated-derived SHA-512 " ++
                "(signed_sha256_derived_sha512) for every archive; the signed index binds at least one archive " ++
                "by SHA-256 only; nothing was changed",
        }, reference);
        return self.terminate(.{
            .outcome = .abandoned_before_mutation,
            .exit_status = @intFromEnum(api.ExitStatus.planning),
            .id = .lock_verification_failed,
            .message = try self.print(
                "the exact lock no longer verifies ({s}); nothing was changed; rerun to plan a new exact lock",
                .{@errorName(err)},
            ),
        }, reference);
    }

    fn buildProgram(self: *Session, owned: *const lock_v5.OwnedLock, reference: LockReference) !ProgramPayload {
        const attempt = &self.attempt.?;
        const archive_lock = owned.archive_lock.lock;
        const archives = try self.allocator.alloc(ArchiveEntry, archive_lock.packages.len);
        for (archive_lock.packages, archives) |locked, *archive| {
            const repository_id = switch (locked.origin) {
                .authenticated_repository => |origin| origin.repository_id,
                .local_artifact => return error.LocalArtifactUnsupported,
            };
            const class: ArchiveClass = switch (archive_lock.archiveAuthentication(locked)) {
                .signed_sha512 => .signed_sha512,
                .signed_sha256_derived_sha512 => .signed_sha256_derived_sha512,
                .signed_sha256_only => .signed_sha256_only,
                .local_artifact_sha512, .local_artifact_sha256_only => return error.LocalArtifactUnsupported,
            };
            if ((class == .signed_sha256_derived_sha512) != (locked.derived_sha512 != null)) return error.UnboundDerivedDigest;
            var published: std.ArrayList(PublishedDigest) = .empty;
            for (content_digest.supported_algorithms) |algorithm| {
                const digest = locked.archive_identity.digests.get(algorithm) orelse continue;
                var buffer: Sha512Hex = undefined;
                try published.append(self.allocator, .{
                    .algorithm = algorithm,
                    .value = try self.allocator.dupe(u8, digest.hex(&buffer)),
                });
            }
            archive.* = .{
                .package = locked.name,
                .version = locked.version,
                .architecture = locked.architecture,
                .retention = locked.retention,
                .archive_authentication = class,
                .repository_id = repository_id,
                .published_digests = try published.toOwnedSlice(self.allocator),
                .primary = locked.archive_identity.primary,
                .derived_sha512 = if (locked.derived_sha512) |derived| .{ .value = std.fmt.bytesToHex(derived, .lower) } else null,
                .dpkg_selection_hold = locked.dpkg_selection_hold,
                .declared_size = locked.declared_size,
            };
        }
        const evidence = owned.evidence().observed;
        const facts = try self.allocator.alloc(InstalledFact, evidence.packages.len);
        for (evidence.packages, facts) |observed, *fact| fact.* = .{
            .name = observed.name,
            .version = observed.version,
            .architecture = observed.architecture,
            .selection = switch (observed.selection) {
                .install => .install,
                .hold => .hold,
                .unknown, .deinstall, .purge => return error.InstalledFactUnsupported,
            },
        };
        const database = evidence.database_identity.value;
        if (database.len != @sizeOf(Sha512Hex)) return error.InvalidInstalledEvidence;
        var database_sha512: Sha512Hex = undefined;
        @memcpy(&database_sha512, database);
        const repositories = try self.allocator.alloc(RepositoryEntry, archive_lock.repositories.len);
        for (archive_lock.repositories, repositories) |locked, *entry| {
            const current = self.runner.authority.repository(locked.id) orelse return error.RepositoryAuthorityChanged;
            const signers = try self.allocator.alloc(SignerHex, locked.signer_fingerprints.len);
            for (locked.signer_fingerprints, signers) |fingerprint, *signer| signer.* = std.fmt.bytesToHex(fingerprint, .upper);
            entry.* = .{
                .id = locked.id,
                .uri = current.uri,
                .suite = current.suite,
                .component = current.component,
                .archive_binding = locked.archive_binding,
                .signers = signers,
                .freshness = current.freshness,
            };
        }
        return .{
            .attempt_id = attempt.id,
            .request_document_sha512 = attempt.request_document,
            .lock = reference,
            .backend = self.kind,
            .target_architecture = archive_lock.target_architecture,
            .archives = archives,
            .installed = .{ .database_sha512 = database_sha512, .facts = facts },
            .repositories = repositories,
        };
    }

    fn summarizePlan(self: *Session, program: ProgramPayload) !PlanSummary {
        var held: std.ArrayList(InstalledFact) = .empty;
        for (program.installed.facts) |fact| if (fact.selection == .hold) try held.append(self.allocator, fact);
        return .{
            .target_architecture = program.target_architecture,
            .archives = program.archives,
            .installed = .{
                .database_sha512 = program.installed.database_sha512,
                .fact_count = program.installed.facts.len,
                .held = try held.toOwnedSlice(self.allocator),
            },
            .repositories = program.repositories,
        };
    }

    fn loadPlan(self: *Session) !void {
        const attempt = &self.attempt.?;
        const recorded = attempt.progress.program_document_sha512 orelse return;
        const program = try decodeEnvelope(
            ProgramPayload,
            self.allocator,
            try self.readStable(try documentPath(self.allocator, attempt.id, .program)),
        );
        if (!std.mem.eql(u8, &program.digest, &recorded) or !std.mem.eql(u8, &program.payload.attempt_id, &attempt.id))
            return error.AttemptEvidenceMismatch;
        attempt.plan = try self.summarizePlan(program.payload);
    }

    /// Publishes the next progress generation, chained to its predecessor.
    fn advance(self: *Session, phase: Phase, change: Change) !void {
        const attempt = &self.attempt.?;
        const current = attempt.progress;
        if (!allowedTransition(current.phase, phase)) return error.InvalidAttemptTransition;
        const carries_documents = phase != .lock_bound;
        const next: ProgressPayload = .{
            .attempt_id = attempt.id,
            .generation = current.generation + 1,
            .previous_progress_sha512 = attempt.progress_document,
            .request_document_sha512 = attempt.request_document,
            .phase = phase,
            .lock = current.lock orelse change.lock,
            .program_document_sha512 = if (carries_documents) attempt.program_document else null,
            .authorization_document_sha512 = if (carries_documents) attempt.authorization_document else null,
            .terminal = change.terminal,
            .reason = change.reason,
        };
        if (!validateText(next) or !next.validate()) return error.InvalidAttemptTransition;
        const encoded = try encodeEnvelope(self.allocator, next);
        try self.fs().publishFile(try root_fs.Path.init(try documentPath(self.allocator, attempt.id, .progress)), encoded.bytes, .{
            .permissions = file_permissions,
            .overwrite = .replace,
        });
        attempt.progress = next;
        attempt.progress_document = encoded.digest;
    }

    fn terminate(self: *Session, terminal: Terminal, reference: ?LockReference) !ResultPayload {
        try self.advance(.terminal, .{ .lock = reference, .terminal = terminal });
        try self.hit(.after_terminal);
        try self.settle();
        return self.attemptResult();
    }

    /// Writes the receipt, then releases the owned-attempt pointer.
    fn settle(self: *Session) !void {
        const attempt = &self.attempt.?;
        const progress = attempt.progress;
        attempt.receipt_document = try self.writeOnce(try documentPath(self.allocator, attempt.id, .receipt), ReceiptPayload{
            .attempt_id = attempt.id,
            .request_document_sha512 = attempt.request_document,
            .progress_document_sha512 = attempt.progress_document,
            .terminal = progress.terminal.?,
            .lock = progress.lock,
            .program_document_sha512 = progress.program_document_sha512,
            .authorization_document_sha512 = progress.authorization_document_sha512,
        });
        try self.hit(.after_receipt);
        self.fs().removeFile(try root_fs.Path.init(active_path)) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try self.fs().syncDirectory(try root_fs.Path.init(state_directory));
        self.adoptable = false;
    }

    /// Sticky: after execution may have begun no run retries or replans.
    fn requireRecovery(self: *Session, reason: []const u8) !ResultPayload {
        const attempt = &self.attempt.?;
        if (attempt.progress.phase != .recovery_required) try self.advance(.recovery_required, .{ .reason = reason });
        const progress = attempt.progress;
        attempt.recovery_document = try self.writeOnce(try documentPath(self.allocator, attempt.id, .recovery), RecoveryPayload{
            .attempt_id = attempt.id,
            .request_document_sha512 = attempt.request_document,
            .progress_document_sha512 = attempt.progress_document,
            .lock = progress.lock.?,
            .program_document_sha512 = progress.program_document_sha512.?,
            .authorization_document_sha512 = progress.authorization_document_sha512.?,
            .command = attempt.request.command,
            .guidance = recovery_guidance,
            .reason = progress.reason.?,
        });
        return self.report(.{
            .outcome = .recovery_required,
            .changed = true,
            .exit_status = @intFromEnum(api.ExitStatus.recovery),
            .id = .root_operation_recovery_required,
            .message = try self.print("attempt {s} requires operator recovery: {s}; {s}", .{
                &attempt.id,
                progress.reason.?,
                recovery_guidance,
            }),
        });
    }

    fn attemptResult(self: *Session) !ResultPayload {
        return self.report(self.attempt.?.progress.terminal.?);
    }

    fn report(self: *Session, terminal: Terminal) !ResultPayload {
        const attempt = &self.attempt.?;
        const recorded = [_]struct { DocumentKind, ?Sha512Hex }{
            .{ .request, attempt.request_document },
            .{ .progress, attempt.progress_document },
            .{ .lock, if (attempt.progress.lock) |lock| lock.document_sha512 else null },
            .{ .program, attempt.program_document },
            .{ .authorization, attempt.authorization_document },
            .{ .receipt, attempt.receipt_document },
            .{ .recovery, attempt.recovery_document },
        };
        var documents: std.ArrayList(DocumentReference) = .empty;
        for (recorded) |item| {
            const digest = item[1] orelse continue;
            try documents.append(self.allocator, .{
                .kind = item[0],
                .path = try self.displayPath(try documentPath(self.allocator, attempt.id, item[0])),
                .document_sha512 = digest,
            });
        }
        const diagnostics: []const Diagnostic = if (terminal.id) |id| blk: {
            const single = try self.allocator.alloc(Diagnostic, 1);
            single[0] = .{ .id = id, .message = terminal.message };
            break :blk single;
        } else &.{};
        return .{
            .exit_status = terminal.exit_status,
            .outcome = terminal.outcome,
            .changed = terminal.changed,
            .package = self.invocation.package,
            .summary = terminal.message,
            .backend = attempt.request.backend,
            .command = attempt.request.command,
            .attempt_id = attempt.id,
            .resumed = attempt.resumed,
            .profile = attempt.request.profile,
            .lock = if (attempt.progress.lock) |lock| try self.displayPath(lock.path) else null,
            .evidence_path = try self.displayPath(try operationPath(self.allocator, attempt.id)),
            .documents = try documents.toOwnedSlice(self.allocator),
            .plan = attempt.plan,
            .diagnostics = diagnostics,
        };
    }

    fn plainResult(self: *Session, status: api.ExitStatus, id: api.ErrorId, message: []const u8) !ResultPayload {
        const diagnostics = try self.allocator.alloc(Diagnostic, 1);
        diagnostics[0] = .{ .id = id, .message = message };
        return .{
            .exit_status = @intFromEnum(status),
            .outcome = refusedOutcome(id),
            .package = self.invocation.package,
            .summary = message,
            .backend = self.kind,
            .command = try commandText(self.allocator, self.invocation.package, self.kind),
            .diagnostics = diagnostics,
        };
    }

    fn failedResult(self: *Session, err: anyerror) !ResultPayload {
        switch (err) {
            error.ConfigurationRequired => return self.plainResult(.unavailable, .configuration_required, configuration_required_message),
            error.OwnerLockBusy => return self.plainResult(.unavailable, .root_operation_conflict, try self.print(
                "another system install holds {s}; nothing was changed",
                .{try self.displayPath(owner_lock_path)},
            )),
            else => {},
        }
        if (self.adoptable) {
            if (self.attempt != null) {
                const attempt = &self.attempt.?;
                const message = if (err == error.RootOperationRecoveryRequired)
                    try self.print(
                        "another debz root operation requires recovery first; attempt {s} is retained unchanged; " ++
                            "after that recovery, rerun exactly: sudo {s}",
                        .{ &attempt.id, attempt.request.command },
                    )
                else
                    try self.print(
                        "attempt {s} was interrupted ({s}); rerun the same command to adopt it: sudo {s}",
                        .{ &attempt.id, @errorName(err), attempt.request.command },
                    );
                return self.report(.{
                    .outcome = .interrupted,
                    .exit_status = @intFromEnum(api.ExitStatus.recovery),
                    .id = .root_operation_recovery_required,
                    .message = message,
                });
            }
            return self.plainResult(.recovery, .root_operation_recovery_required, try self.print(
                "system install state at {s} could not be adopted ({s}); it was left unchanged",
                .{ try self.displayPath(active_path), @errorName(err) },
            ));
        }
        return switch (err) {
            error.RootOperationBusy => self.plainResult(.unavailable, .root_operation_conflict, try self.print(
                "another debz root operation holds {s}; nothing was changed",
                .{try self.displayPath(root_operation.lock_path)},
            )),
            error.RootOperationRecoveryRequired => self.plainResult(
                .recovery,
                .root_operation_recovery_required,
                "another debz root operation requires recovery before a system install can start; nothing was changed",
            ),
            else => self.plainResult(.unavailable, .transaction_backend_unavailable, try self.print(
                "system install could not start ({s}); nothing was changed",
                .{@errorName(err)},
            )),
        };
    }

    fn displayPath(self: *const Session, relative: []const u8) ![]u8 {
        const display_root = self.runner.authority.display_root;
        if (std.mem.eql(u8, display_root, "/")) return std.mem.concat(self.allocator, u8, &.{ "/", relative });
        return std.mem.concat(self.allocator, u8, &.{ display_root, "/", relative });
    }

    fn systemProfile(self: *const Session) !Profile {
        const authority = &self.runner.authority;
        return .{
            .root = authority.display_root,
            .cache_path = authority.cache_path,
            .state_path = authority.state_path,
            .locks_path = try self.displayPath(locks_directory),
            .evidence_path = try self.displayPath(state_directory),
            .architecture = authority.architecture,
        };
    }

    fn readStable(self: *Session, relative: []const u8) ![]u8 {
        var pinned = try self.fs().pinRegularFile(try root_fs.Path.init(relative));
        defer pinned.close();
        const observed = try pinned.observeStableAlloc(self.allocator, maximum_document_bytes);
        try self.requireSafeFile(observed.entry);
        return observed.bytes;
    }

    fn readOptional(self: *Session, relative: []const u8) !?[]u8 {
        _ = try self.fs().entryIfExists(try root_fs.Path.init(relative)) orelse return null;
        return try self.readStable(relative);
    }

    fn readStatus(self: *Session) ![]u8 {
        var pinned = try self.fs().pinRegularFile(try root_fs.Path.init(status_path));
        defer pinned.close();
        return (try pinned.observeStableAlloc(self.allocator, maximum_status_bytes)).bytes;
    }

    /// Create-once evidence: an existing document must be byte-identical.
    fn writeOnce(self: *Session, relative: []const u8, payload: anytype) !Sha512Hex {
        if (!validateText(payload) or !payload.validate()) return error.InvalidAttemptDocument;
        const encoded = try encodeEnvelope(self.allocator, payload);
        self.fs().publishFile(try root_fs.Path.init(relative), encoded.bytes, .{
            .permissions = file_permissions,
            .overwrite = .fail_if_exists,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => if (!std.mem.eql(u8, try self.readStable(relative), encoded.bytes))
                return error.DocumentConflict,
            else => return err,
        };
        return encoded.digest;
    }

    fn requireSafeFile(self: *const Session, entry: root_fs.Entry) !void {
        if (!entry.modeled or !entry.isRegularFile() or entry.uid != self.root_uid or entry.mode & 0o022 != 0 or
            entry.link_count != 1)
            return error.UnsafeSystemInstallState;
    }

    fn requireSafeDirectory(self: *const Session, entry: root_fs.Entry) !void {
        if (!entry.modeled or !entry.isDirectory() or entry.uid != self.root_uid or entry.mode & 0o022 != 0)
            return error.UnsafeSystemInstallState;
    }

    fn ensureSafeDirectory(self: *Session, relative: []const u8) !void {
        const target = try root_fs.Path.init(relative);
        try self.fs().ensureDirectory(target, directory_permissions);
        try self.requireSafeDirectory(try self.fs().entry(target));
    }

    fn hit(self: *const Session, point: CrashPoint) !void {
        if (self.runner.observer) |observer| try observer.hitFn(observer.context, point);
    }

    fn revalidate(self: *const Session) !void {
        if (self.runner.authority.revalidate) |hook| try hook.function(hook.context);
    }
};

const installed_baseline = @import("installed_baseline.zig");

const test_status =
    "Package: base-files\nStatus: install ok installed\nArchitecture: amd64\nVersion: 13\n\n" ++
    "Package: private-tool\nStatus: hold ok installed\nArchitecture: amd64\nVersion: 2.0-local\n\n";
const test_facts = [_]installed_baseline.Package{
    .{ .name = "base-files", .version = "13", .architecture = "amd64", .selection = .install },
    .{ .name = "private-tool", .version = "2.0-local", .architecture = "amd64", .selection = .hold },
};
const test_context: lock_v5.ContextBinding = .{ .configuration_sha256 = @splat('c'), .manifest_sha256 = @splat(6) };
const test_repository_id: RepositoryHex = @splat('a');
const test_signers = [_]Signer{@splat(5)};

const TestRoot = struct {
    tmp: std.testing.TmpDir,
    path: []u8,

    fn init() !TestRoot {
        var tmp = std.testing.tmpDir(.{ .iterate = true });
        errdefer tmp.cleanup();
        try tmp.dir.setPermissions(std.testing.io, .fromMode(0o755));
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try tmp.dir.realPath(std.testing.io, &path_buffer);
        const root_path = try std.testing.allocator.dupe(u8, path_buffer[0..length]);
        errdefer std.testing.allocator.free(root_path);
        var opened = try root_fs.openAbsoluteRoot(std.testing.io, root_path);
        defer opened.close();
        try opened.root.createDirectoryPath(try root_fs.Path.init("var/lib/dpkg"), .fromMode(0o755));
        try opened.root.createDirectoryPath(try root_fs.Path.init(root_operation.namespace_path), .fromMode(0o755));
        try opened.root.publishFile(try root_fs.Path.init(status_path), test_status, .{ .permissions = .fromMode(0o644) });
        return .{ .tmp = tmp, .path = root_path };
    }

    fn deinit(self: *TestRoot) void {
        std.testing.allocator.free(self.path);
        self.tmp.cleanup();
    }

    fn read(self: *TestRoot, relative_path: []const u8) ![]u8 {
        return self.tmp.dir.readFileAlloc(std.testing.io, relative_path, std.testing.allocator, .limited(maximum_document_bytes));
    }

    fn exists(self: *TestRoot, relative_path: []const u8) bool {
        self.tmp.dir.access(std.testing.io, relative_path, .{}) catch return false;
        return true;
    }

    fn write(self: *TestRoot, relative_path: []const u8, data: []const u8) !void {
        try self.tmp.dir.writeFile(std.testing.io, .{ .sub_path = relative_path, .data = data });
    }
};

const PlanMode = enum { sha256_only, derived, sha512, empty, refuse, fail };

/// Publishes a real v5 lock over the healthy test database, like the
/// production planner, with a chosen archive authentication class.
const FakePlanner = struct {
    mode: PlanMode = .sha256_only,
    root_path: []const u8,
    calls: usize = 0,

    fn plan(context: ?*anyopaque, allocator: std.mem.Allocator, request: PlanRequest) anyerror!PlanOutcome {
        const self: *FakePlanner = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        switch (self.mode) {
            .refuse => return .{ .refused = .{ .exit_status = .planning, .id = .planning_failed, .message = "no installable candidate" } },
            .fail => return error.PlannerExploded,
            .sha256_only, .derived, .sha512, .empty => {},
        }
        try std.testing.expect(std.mem.startsWith(u8, request.lock_output_path, self.root_path));
        const root_relative = request.lock_output_path[self.root_path.len + 1 ..];
        try std.testing.expectEqualStrings(try lockPath(allocator, request.attempt_id), root_relative);
        var opened = try root_fs.openAbsoluteRoot(std.testing.io, self.root_path);
        defer opened.close();
        const status_bytes = try opened.root.dir.readFileAlloc(std.testing.io, status_path, allocator, .limited(maximum_status_bytes));
        const verified = try healthy.capture(allocator, std.testing.io, self.root_path, "amd64", status_bytes, &test_facts);
        defer verified.deinit();
        const repositories = [_]lock_v3.Repository{.{
            .id = test_repository_id,
            .snapshot_sha256 = @splat(3),
            .release_sha256 = @splat(4),
            .index_identity = content_digest.Identity.ofSha256("index"),
            .signer_fingerprints = &test_signers,
            .archive_binding = if (self.mode == .derived) .signed_sha256_derived_sha512 else .published_digests,
        }};
        const derived: [Sha512.digest_length]u8 = @splat(9);
        const packages = [_]lock_v3.Package{.{
            .name = request.package,
            .version = "1.0",
            .architecture = "amd64",
            .origin = .{ .authenticated_repository = .{ .repository_id = test_repository_id, .repository_snapshot_sha256 = @splat(3) } },
            .archive_identity = if (self.mode == .sha512)
                content_digest.Identity.ofSupported("archive")
            else
                content_digest.Identity.ofSha256("archive"),
            .derived_sha512 = if (self.mode == .derived) derived else null,
            .declared_size = 7,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }};
        const empty = self.mode == .empty;
        var archive_lock = try lock_v3.create(allocator, .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(7),
            .policy_sha256 = @splat(8),
            .repositories = if (empty) &.{} else &repositories,
            .local_artifacts = &.{},
            .packages = if (empty) &.{} else &packages,
            .verified_origins = true,
        });
        defer archive_lock.deinit();
        var owned_lock = try lock_v5.create(allocator, request.backend, test_context, archive_lock.lock, verified);
        defer owned_lock.deinit();
        try opened.root.publishFile(try root_fs.Path.init(root_relative), try owned_lock.canonicalJson(allocator), .{
            .permissions = .fromMode(0o600),
            .overwrite = .fail_if_exists,
        });
        return .published;
    }
};

const ExecMode = enum { completed, refused, failed, broken };

const FakeExecutor = struct {
    mode: ExecMode,
    calls: usize = 0,

    fn available(_: ?*anyopaque, _: Kind) ?[]const u8 {
        return null;
    }

    fn execute(context: ?*anyopaque, _: std.mem.Allocator, request: ExecuteRequest) anyerror!ExecutionOutcome {
        const self: *FakeExecutor = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        try std.testing.expect(std.mem.startsWith(u8, request.lock_path, "/" ++ lock_prefix));
        return switch (self.mode) {
            .completed => .{ .completed = .{ .changed = true } },
            .refused => .{ .refused_before_mutation = "final verification refused" },
            .failed => .{ .failed_after_mutation = "the execution generation stopped after mutation began" },
            .broken => error.ExecutorExploded,
        };
    }
};

/// One test root with injectable authority drift, crash points, and executor.
const Harness = struct {
    root: TestRoot,
    planner: FakePlanner,
    executor: ?FakeExecutor = null,
    crash: ?CrashPoint = null,
    repositories: [1]RepositoryAuthority,
    context: lock_v5.ContextBinding = test_context,
    revalidation: ?anyerror = null,
    locks: root_operation.SystemLockBackend,

    fn init() !Harness {
        const test_root = try TestRoot.init();
        return .{
            .root = test_root,
            .planner = .{ .root_path = test_root.path },
            .repositories = .{.{
                .id = test_repository_id,
                .uri = "https://packages.example.test/ubuntu",
                .suite = "noble",
                .component = "main",
                .freshness = .{ .policy = .bounded_missing_valid_until, .maximum_release_age_seconds = 1_209_600 },
                .archive_binding = .published_digests,
            }},
            .locks = .{ .allocator = std.testing.allocator, .io = std.testing.io },
        };
    }

    fn deinit(self: *Harness) void {
        self.root.deinit();
    }

    fn observe(context: ?*anyopaque, point: CrashPoint) anyerror!void {
        const self: *Harness = @ptrCast(@alignCast(context.?));
        const armed = self.crash orelse return;
        if (armed != point) return;
        self.crash = null;
        return error.InjectedCrash;
    }

    fn check(context: ?*anyopaque) anyerror!void {
        const self: *Harness = @ptrCast(@alignCast(context.?));
        if (self.revalidation) |failure| return failure;
    }

    fn run(self: *Harness, package_name: []const u8, kind: Kind) !OwnedResult {
        const runner: Engine = .{
            .io = std.testing.io,
            .authority = .{
                .root_path = self.root.path,
                .architecture = "amd64",
                .context = self.context,
                .repositories = &self.repositories,
                .revalidate = .{ .context = self, .function = check },
            },
            .planner = .{ .context = &self.planner, .planFn = FakePlanner.plan },
            .executor = if (self.executor) |*fake|
                .{ .context = fake, .unavailableFn = FakeExecutor.available, .executeFn = FakeExecutor.execute }
            else
                pending_executor,
            .observer = .{ .context = self, .hitFn = observe },
            .locks = self.locks.interface(),
        };
        return runner.run(std.testing.allocator, .{ .package = package_name, .lock_wait_ms = 0 }, kind);
    }

    fn progress(self: *Harness, arena: std.mem.Allocator, attempt_id: AttemptId) !ProgressPayload {
        const bytes = try self.root.read(try documentPath(arena, attempt_id, .progress));
        defer std.testing.allocator.free(bytes);
        return (try decodeEnvelope(ProgressPayload, arena, bytes)).payload;
    }
};

fn nonNativeKind() Kind {
    for (std.enums.values(Kind)) |candidate| if (candidate != .native) return candidate;
    unreachable;
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

test "system_install.test route accepts only the short system form" {
    for ([_][]const []const u8{
        &.{},
        &.{"--json"},
        &.{ "--root", "/srv", "demo" },
        &.{ "--plan-only", "demo" },
        &.{ "--yes", "demo" },
    }) |arguments| try std.testing.expect(route(arguments) == .product_api);
    const plain = route(&.{"demo"}).system;
    try std.testing.expectEqualStrings("demo", plain.package);
    try std.testing.expectEqual(@as(?Kind, null), plain.backend);
    try std.testing.expectEqual(Output.human, plain.output);
    try std.testing.expectEqual(@as(?u64, null), plain.deadline_ms);
    try std.testing.expectEqual(@as(u64, 30_000), plain.lock_wait_ms);
    const full = route(&.{
        "--json",         "-y", "--noninteractive", "--transaction-backend", "native", "--deadline-ms", "5",
        "--lock-wait-ms", "0",  "demo",
    }).system;
    try std.testing.expectEqual(Output.json, full.output);
    try std.testing.expectEqual(@as(?Kind, .native), full.backend);
    try std.testing.expectEqual(@as(?u64, 5), full.deadline_ms);
    try std.testing.expectEqual(@as(u64, 0), full.lock_wait_ms);
    const refusals = [_]struct { []const []const u8, Output, []const u8 }{
        .{ &.{ "--json", "one", "two" }, .json, "exactly one package" },
        .{ &.{"pkg=1"}, .human, "invalid package name" },
        .{ &.{"demo:amd64"}, .human, "invalid package name" },
        .{ &.{ "--json", "--json", "demo" }, .json, "at most once" },
        .{ &.{ "-y", "--assume-yes", "demo" }, .human, "at most once" },
        .{ &.{ "demo", "--lock-wait-ms" }, .human, "each require a value" },
        .{ &.{ "--transaction-backend", "bogus", "demo" }, .human, "--transaction-backend must be one of:" },
        .{ &.{ "--deadline-ms", "0", "demo" }, .human, "--deadline-ms must be" },
        .{ &.{ "--lock-wait-ms", "86400001", "demo" }, .human, "--lock-wait-ms must be" },
        .{ &.{ "--lock-wait-ms", "+5", "demo" }, .human, "--lock-wait-ms must be" },
    };
    for (refusals) |scenario| {
        switch (route(scenario[0])) {
            .usage => |bad| {
                try std.testing.expectEqual(scenario[1], bad.output);
                try std.testing.expect(contains(bad.message, scenario[2]));
                try std.testing.expect(std.mem.endsWith(u8, bad.message, "nothing was changed"));
            },
            .product_api, .system => return error.TestUnexpectedResult,
        }
    }
    const text_native = try commandText(std.testing.allocator, "demo", .native);
    defer std.testing.allocator.free(text_native);
    try std.testing.expectEqualStrings("debz install --transaction-backend native demo", text_native);
    try std.testing.expect(commandMatches(text_native, "demo", .native));
    try std.testing.expect(!commandMatches(text_native, "demo2", .native));
    try std.testing.expect(!commandMatches(text_native, "demo", nonNativeKind()));
    const digest_root = requestDigest("demo", .native, "/");
    try std.testing.expect(lowerHex(&digest_root));
    try std.testing.expect(!std.mem.eql(u8, &digest_root, &requestDigest("demo", .native, "/srv")));
    try std.testing.expect(!std.mem.eql(u8, &digest_root, &requestDigest("demo", nonNativeKind(), "/")));
    try std.testing.expect(!std.mem.eql(u8, &digest_root, &requestDigest("demo2", .native, "/")));
}

test "system_install.test pending execution records the exact owned chain without changing the database" {
    const kind = nonNativeKind();
    var harness = try Harness.init();
    defer harness.deinit();
    var result = try harness.run("demo", kind);
    defer result.deinit();
    const value = &result.value;
    try std.testing.expectEqual(api.ExitStatus.unavailable, result.exitStatus());
    try std.testing.expectEqual(Outcome.refused_before_mutation, value.outcome);
    try std.testing.expectEqual(api.ErrorId.transaction_backend_unavailable, value.diagnostics[0].id);
    try std.testing.expect(!value.changed and !value.resumed);
    try std.testing.expectEqual(kind, value.backend.?);
    const lock_shown = value.lock.?;
    try std.testing.expect(std.mem.startsWith(u8, lock_shown, "/" ++ lock_prefix));
    try std.testing.expect(std.mem.startsWith(u8, value.summary, "demo is planned and authorized by exact lock "));
    try std.testing.expect(contains(value.summary, lock_shown));
    try std.testing.expect(contains(value.summary, pending_execution_message));
    const shown_profile = value.profile.?;
    try std.testing.expectEqualStrings("/", shown_profile.root);
    try std.testing.expectEqualStrings("/var/lib/debz/locks", shown_profile.locks_path);
    try std.testing.expectEqualStrings("/var/lib/debz/system-install", shown_profile.evidence_path);

    const kinds = [_]DocumentKind{ .request, .progress, .lock, .program, .authorization, .receipt };
    try std.testing.expectEqual(kinds.len, value.documents.len);
    for (kinds, value.documents) |expected_kind, document| {
        try std.testing.expectEqual(expected_kind, document.kind);
        const bytes = try harness.root.read(document.path[1..]);
        defer std.testing.allocator.free(bytes);
        if (document.kind == .lock) try std.testing.expectEqualSlices(u8, &sha512Hex(bytes), &document.document_sha512);
    }
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const scratch_allocator = arena_state.allocator();
    const settled = try harness.progress(scratch_allocator, value.attempt_id.?);
    try std.testing.expectEqual(Phase.terminal, settled.phase);
    try std.testing.expectEqual(@as(u64, 4), settled.generation);
    try std.testing.expectEqual(Outcome.refused_before_mutation, settled.terminal.?.outcome);
    const receipt_bytes = try harness.root.read(value.documents[5].path[1..]);
    defer std.testing.allocator.free(receipt_bytes);
    const receipt = try decodeEnvelope(ReceiptPayload, scratch_allocator, receipt_bytes);
    try std.testing.expectEqualSlices(u8, &value.documents[5].document_sha512, &receipt.digest);
    try std.testing.expectEqualSlices(u8, &value.documents[1].document_sha512, &receipt.payload.progress_document_sha512);
    try std.testing.expect(!harness.root.exists(active_path));
    try std.testing.expect(harness.root.exists(lock_shown[1..]));
    const status_after = try harness.root.read(status_path);
    defer std.testing.allocator.free(status_after);
    try std.testing.expectEqualStrings(test_status, status_after);

    const summary_plan = value.plan.?;
    try std.testing.expectEqual(@as(usize, 1), summary_plan.archives.len);
    const archive_entry = summary_plan.archives[0];
    try std.testing.expectEqual(ArchiveClass.signed_sha256_only, archive_entry.archive_authentication);
    try std.testing.expectEqual(@as(usize, 1), archive_entry.published_digests.len);
    try std.testing.expectEqual(content_digest.Algorithm.sha256, archive_entry.published_digests[0].algorithm);
    try std.testing.expect(archive_entry.derived_sha512 == null);
    try std.testing.expectEqual(@as(u64, 2), summary_plan.installed.fact_count);
    try std.testing.expectEqual(@as(usize, 1), summary_plan.installed.held.len);
    try std.testing.expectEqualStrings("private-tool", summary_plan.installed.held[0].name);
    try std.testing.expectEqual(Selection.hold, summary_plan.installed.held[0].selection);
    try std.testing.expectEqual(@as(?u64, 1_209_600), summary_plan.repositories[0].freshness.maximum_release_age_seconds);
    try std.testing.expect(std.mem.startsWith(u8, &summary_plan.repositories[0].signers[0], "0505"));

    var stdout_buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout_buffer.deinit();
    var stderr_buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr_buffer.deinit();
    try render(std.testing.allocator, value, .human, &stdout_buffer.writer, &stderr_buffer.writer);
    try std.testing.expectEqual(@as(usize, 0), stdout_buffer.written().len);
    for ([_][]const u8{
        "install: demo is planned and authorized by exact lock /var/lib/debz/locks/install-",
        "actions (1):\n  install demo 1.0 [amd64] requested: signed SHA-256 only; no SHA-512 published by the signed index\n",
        "repository https://packages.example.test/ubuntu noble main: missing Valid-Until accepted for at most " ++
            "1209600 s (explicit repository bound)\n",
        "installed facts: 2 from the healthy installed package database (no archive origin)\n" ++
            "  held private-tool 2.0-local [amd64] (no archive origin)\n",
        "debz[transaction_backend_unavailable]: ",
    }) |line| try std.testing.expect(contains(stderr_buffer.written(), line));
    const json_bytes = try result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json_bytes);
    var decoded = try decodeResult(std.testing.allocator, json_bytes);
    defer decoded.deinit();
    try std.testing.expectEqualStrings(value.summary, decoded.value.summary);
    var json_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer json_out.deinit();
    try render(std.testing.allocator, value, .json, &json_out.writer, &stderr_buffer.writer);
    try std.testing.expectEqualStrings(json_bytes, json_out.written()[0 .. json_out.written().len - 1]);
    try std.testing.expect(std.mem.endsWith(u8, json_out.written(), "}\n"));

    var again = try harness.run("demo", kind);
    defer again.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, again.exitStatus());
    try std.testing.expect(!again.value.resumed);
    try std.testing.expect(!std.mem.eql(u8, &value.attempt_id.?, &again.value.attempt_id.?));
    try std.testing.expectEqual(@as(usize, 2), harness.planner.calls);
}

test "system_install.test native admits only signed or authenticated-derived SHA-512 archive identities" {
    const scenarios = [_]struct { PlanMode, api.ExitStatus, ?ArchiveClass, usize }{
        .{ .sha256_only, .planning, null, 0 },
        .{ .derived, .unavailable, .signed_sha256_derived_sha512, 1 },
        .{ .sha512, .unavailable, .signed_sha512, 2 },
    };
    for (scenarios) |scenario| {
        var harness = try Harness.init();
        defer harness.deinit();
        harness.planner.mode = scenario[0];
        if (scenario[0] == .derived) harness.repositories[0].archive_binding = .signed_sha256_derived_sha512;
        var result = try harness.run("demo", .native);
        defer result.deinit();
        try std.testing.expectEqual(scenario[1], result.exitStatus());
        const class = scenario[2] orelse {
            try std.testing.expectEqual(Outcome.abandoned_before_mutation, result.value.outcome);
            try std.testing.expectEqual(api.ErrorId.planning_failed, result.value.diagnostics[0].id);
            try std.testing.expect(contains(result.value.summary, "(signed_sha256_derived_sha512)"));
            try std.testing.expect(result.value.plan == null);
            try std.testing.expect(!harness.root.exists(active_path));
            continue;
        };
        const archive_entry = result.value.plan.?.archives[0];
        try std.testing.expectEqual(class, archive_entry.archive_authentication);
        try std.testing.expectEqual(scenario[3], archive_entry.published_digests.len);
        try std.testing.expectEqual(content_digest.Algorithm.sha256, archive_entry.published_digests[0].algorithm);
        if (class != .signed_sha256_derived_sha512) {
            try std.testing.expect(archive_entry.derived_sha512 == null);
            continue;
        }
        const derived_digest = archive_entry.derived_sha512.?;
        try std.testing.expectEqual(DerivedProvenance.derived_from_signed_sha256, derived_digest.provenance);
        try std.testing.expect(std.mem.startsWith(u8, &derived_digest.value, "0909"));
        try std.testing.expectEqual(
            lock_v3.ArchiveBinding.signed_sha256_derived_sha512,
            result.value.plan.?.repositories[0].archive_binding,
        );
        var stderr_buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stderr_buffer.deinit();
        try render(std.testing.allocator, &result.value, .human, &stderr_buffer.writer, &stderr_buffer.writer);
        try std.testing.expect(contains(stderr_buffer.written(), "signed SHA-256; SHA-512 derived locally from the signed SHA-256 match"));
    }
}

test "system_install.test interrupted attempts resume exactly by their owned request" {
    const kind = nonNativeKind();
    for ([_]CrashPoint{
        .after_reservation,   .after_lock_publication, .after_lock_bound, .after_program,
        .after_authorization, .after_authorized,       .after_terminal,   .after_receipt,
    }) |point| {
        var harness = try Harness.init();
        defer harness.deinit();
        harness.crash = point;
        var first = try harness.run("demo", kind);
        defer first.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, first.exitStatus());
        try std.testing.expectEqual(Outcome.interrupted, first.value.outcome);
        try std.testing.expect(contains(first.value.summary, "(InjectedCrash); rerun the same command to adopt it: sudo debz install"));
        try std.testing.expect(harness.root.exists(active_path));
        var second = try harness.run("demo", kind);
        defer second.deinit();
        try std.testing.expectEqual(api.ExitStatus.unavailable, second.exitStatus());
        try std.testing.expectEqual(Outcome.refused_before_mutation, second.value.outcome);
        try std.testing.expect(second.value.resumed and second.value.plan != null);
        try std.testing.expectEqualSlices(u8, &first.value.attempt_id.?, &second.value.attempt_id.?);
        try std.testing.expectEqual(@as(usize, 1), harness.planner.calls);
        try std.testing.expect(!harness.root.exists(active_path));
    }
}

test "system_install.test an interruption before reservation leaves nothing to adopt" {
    const kind = nonNativeKind();
    var harness = try Harness.init();
    defer harness.deinit();
    harness.crash = .after_request;
    var first = try harness.run("demo", kind);
    defer first.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, first.exitStatus());
    try std.testing.expectEqualStrings("system install could not start (InjectedCrash); nothing was changed", first.value.summary);
    try std.testing.expect(first.value.attempt_id == null and !harness.root.exists(active_path));
    var second = try harness.run("demo", kind);
    defer second.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, second.exitStatus());
    try std.testing.expect(!second.value.resumed);
    try std.testing.expectEqual(@as(usize, 1), harness.planner.calls);
}

test "system_install.test an unsettled attempt refuses every other request until it is adopted" {
    const kind = nonNativeKind();
    var harness = try Harness.init();
    defer harness.deinit();
    harness.crash = .after_lock_bound;
    var first = try harness.run("demo", kind);
    defer first.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, first.exitStatus());
    const owned_id = first.value.attempt_id.?;
    const command_line = try commandText(std.testing.allocator, "demo", kind);
    defer std.testing.allocator.free(command_line);
    const adopt_hint = try std.fmt.allocPrint(std.testing.allocator, "rerun exactly 'sudo {s}' to adopt it", .{command_line});
    defer std.testing.allocator.free(adopt_hint);
    for ([_]struct { []const u8, Kind }{ .{ "other", kind }, .{ "demo", .native } }) |other| {
        var blocked = try harness.run(other[0], other[1]);
        defer blocked.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, blocked.exitStatus());
        try std.testing.expectEqual(Outcome.interrupted, blocked.value.outcome);
        try std.testing.expectEqual(api.ErrorId.root_operation_recovery_required, blocked.value.diagnostics[0].id);
        try std.testing.expect(contains(blocked.value.summary, adopt_hint));
        try std.testing.expect(contains(blocked.value.summary, "this request was not started and nothing was changed"));
        try std.testing.expectEqualSlices(u8, &owned_id, &blocked.value.attempt_id.?);
        try std.testing.expect(!blocked.value.resumed);
        try std.testing.expectEqualStrings(other[0], blocked.value.package);
    }
    var resumed = try harness.run("demo", kind);
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, resumed.exitStatus());
    try std.testing.expect(resumed.value.resumed);
    try std.testing.expectEqualSlices(u8, &owned_id, &resumed.value.attempt_id.?);
    var fresh = try harness.run("other", kind);
    defer fresh.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, fresh.exitStatus());
    try std.testing.expect(!fresh.value.resumed);
    try std.testing.expect(!std.mem.eql(u8, &owned_id, &fresh.value.attempt_id.?));
    try std.testing.expectEqual(@as(usize, 2), harness.planner.calls);
}

test "system_install.test installed database drift abandons the retained lock before mutation" {
    const kind = nonNativeKind();
    var harness = try Harness.init();
    defer harness.deinit();
    harness.crash = .after_authorized;
    var first = try harness.run("demo", kind);
    defer first.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, first.exitStatus());
    try harness.root.write(status_path, test_status ++ "Package: drift\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n");
    var second = try harness.run("demo", kind);
    defer second.deinit();
    try std.testing.expectEqual(api.ExitStatus.planning, second.exitStatus());
    try std.testing.expectEqual(Outcome.abandoned_before_mutation, second.value.outcome);
    try std.testing.expectEqual(api.ErrorId.lock_verification_failed, second.value.diagnostics[0].id);
    try std.testing.expect(second.value.resumed);
    try std.testing.expect(std.mem.startsWith(u8, second.value.summary, "the exact lock no longer verifies ("));
    try std.testing.expect(!harness.root.exists(active_path));
    var third = try harness.run("demo", kind);
    defer third.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, third.exitStatus());
    try std.testing.expect(!third.value.resumed);
    try std.testing.expectEqual(@as(usize, 2), harness.planner.calls);
}

test "system_install.test authority drift abandons the retained lock before mutation" {
    const kind = nonNativeKind();
    const Drift = enum { context, binding, removed, uri };
    for (std.enums.values(Drift)) |drift| {
        var harness = try Harness.init();
        defer harness.deinit();
        harness.crash = if (drift == .uri) .after_program else .after_lock_bound;
        var first = try harness.run("demo", kind);
        defer first.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, first.exitStatus());
        switch (drift) {
            .context => harness.context.manifest_sha256 = @splat(1),
            .binding => harness.repositories[0].archive_binding = .signed_sha256_derived_sha512,
            .removed => harness.repositories[0].id = @splat('b'),
            .uri => harness.repositories[0].uri = "https://mirror.example.test/ubuntu",
        }
        var second = try harness.run("demo", kind);
        defer second.deinit();
        try std.testing.expectEqual(api.ExitStatus.planning, second.exitStatus());
        try std.testing.expectEqual(Outcome.abandoned_before_mutation, second.value.outcome);
        try std.testing.expectEqual(api.ErrorId.lock_verification_failed, second.value.diagnostics[0].id);
        try std.testing.expect(second.value.resumed);
        try std.testing.expect(contains(second.value.summary, switch (drift) {
            .context => "(ActiveContextChanged)",
            .binding, .removed => "(RepositoryAuthorityChanged)",
            .uri => "(ProgramEvidenceChanged)",
        }));
        try std.testing.expectEqual(@as(usize, 1), harness.planner.calls);
    }
}

test "system_install.test another surface's recovery retains the owned attempt unchanged" {
    const kind = nonNativeKind();
    var harness = try Harness.init();
    defer harness.deinit();
    harness.revalidation = error.RootOperationRecoveryRequired;
    var refused_start = try harness.run("demo", kind);
    defer refused_start.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, refused_start.exitStatus());
    try std.testing.expectEqual(api.ErrorId.root_operation_recovery_required, refused_start.value.diagnostics[0].id);
    try std.testing.expect(contains(refused_start.value.summary, "before a system install can start; nothing was changed"));
    try std.testing.expect(refused_start.value.attempt_id == null and !harness.root.exists(active_path));
    try std.testing.expectEqual(@as(usize, 0), harness.planner.calls);

    harness.revalidation = null;
    harness.crash = .after_lock_bound;
    var first = try harness.run("demo", kind);
    defer first.deinit();
    const owned_id = first.value.attempt_id.?;
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const progress_path = try documentPath(arena_state.allocator(), owned_id, .progress);
    const before = try harness.root.read(progress_path);
    defer std.testing.allocator.free(before);
    harness.revalidation = error.RootOperationRecoveryRequired;
    var retained = try harness.run("demo", kind);
    defer retained.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, retained.exitStatus());
    try std.testing.expectEqual(Outcome.interrupted, retained.value.outcome);
    try std.testing.expect(std.mem.startsWith(u8, retained.value.summary, "another debz root operation requires recovery first; attempt "));
    try std.testing.expect(contains(retained.value.summary, " is retained unchanged; after that recovery, rerun exactly: sudo debz install"));
    const after = try harness.root.read(progress_path);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualStrings(before, after);
    try std.testing.expect(harness.root.exists(active_path));
    harness.revalidation = null;
    var resumed = try harness.run("demo", kind);
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, resumed.exitStatus());
    try std.testing.expect(resumed.value.resumed);
    try std.testing.expectEqualSlices(u8, &owned_id, &resumed.value.attempt_id.?);
    try std.testing.expectEqual(@as(usize, 1), harness.planner.calls);
}

test "system_install.test planner refusals and satisfied requests settle without execution" {
    const kind = nonNativeKind();
    const scenarios = [_]struct { PlanMode, []const u8, api.ExitStatus, ?api.ErrorId, []const u8 }{
        .{ .refuse, "demo", .planning, .planning_failed, "no installable candidate; nothing was changed" },
        .{ .fail, "demo", .internal, .internal_error, "planning failed (PlannerExploded); nothing was changed" },
        .{ .empty, "base-files", .success, null, "base-files is already satisfied by the healthy installed package database; nothing was changed" },
    };
    for (scenarios) |scenario| {
        var harness = try Harness.init();
        defer harness.deinit();
        harness.planner.mode = scenario[0];
        var result = try harness.run(scenario[1], kind);
        defer result.deinit();
        try std.testing.expectEqual(scenario[2], result.exitStatus());
        try std.testing.expectEqualStrings(scenario[4], result.value.summary);
        try std.testing.expect(!result.value.changed and !harness.root.exists(active_path));
        try std.testing.expectEqual(DocumentKind.receipt, result.value.documents[result.value.documents.len - 1].kind);
        const failure_id = scenario[3] orelse {
            try std.testing.expectEqual(Outcome.completed, result.value.outcome);
            try std.testing.expectEqual(@as(usize, 0), result.value.plan.?.archives.len);
            try std.testing.expectEqual(@as(usize, 5), result.value.documents.len);
            continue;
        };
        try std.testing.expectEqual(Outcome.rejected, result.value.outcome);
        try std.testing.expectEqual(failure_id, result.value.diagnostics[0].id);
        try std.testing.expect(result.value.lock == null);
        try std.testing.expectEqual(@as(usize, 3), result.value.documents.len);
    }
}

test "system_install.test execution outcomes settle or become sticky recovery" {
    const kind = nonNativeKind();
    const outcomes = [_]struct { ExecMode, api.ExitStatus, Outcome, []const u8 }{
        .{ .completed, .success, .completed, "demo is installed by exact lock /var/lib/debz/locks/install-" },
        .{ .refused, .transaction, .refused_before_mutation, "final verification refused; nothing was changed" },
        .{ .failed, .recovery, .recovery_required, "requires operator recovery: the execution generation stopped after mutation began; " },
        .{ .broken, .recovery, .recovery_required, "requires operator recovery: execution stopped (ExecutorExploded) after it may have begun; " },
    };
    for (outcomes) |scenario| {
        var harness = try Harness.init();
        defer harness.deinit();
        harness.executor = .{ .mode = scenario[0] };
        var result = try harness.run("demo", kind);
        defer result.deinit();
        try std.testing.expectEqual(scenario[1], result.exitStatus());
        try std.testing.expectEqual(scenario[2], result.value.outcome);
        try std.testing.expect(contains(result.value.summary, scenario[3]));
        try std.testing.expectEqual(@as(usize, 1), harness.executor.?.calls);
        const sticky = scenario[2] == .recovery_required;
        try std.testing.expectEqual(sticky, harness.root.exists(active_path));
        try std.testing.expectEqual(sticky or scenario[0] == .completed, result.value.changed);
        if (!sticky) continue;
        try std.testing.expect(std.mem.endsWith(u8, result.value.summary, recovery_guidance));
        try std.testing.expectEqual(DocumentKind.recovery, result.value.documents[result.value.documents.len - 1].kind);
        for ([_][]const u8{ "demo", "other" }) |name| {
            var again = try harness.run(name, kind);
            defer again.deinit();
            try std.testing.expectEqual(api.ExitStatus.recovery, again.exitStatus());
            try std.testing.expectEqualStrings(result.value.summary, again.value.summary);
            try std.testing.expect(again.value.resumed and again.value.changed);
        }
        try std.testing.expectEqual(@as(usize, 1), harness.executor.?.calls);
        try std.testing.expectEqual(@as(usize, 1), harness.planner.calls);
    }
    for ([_]struct { CrashPoint, usize }{ .{ .after_executing, 0 }, .{ .after_execution, 1 } }) |scenario| {
        var harness = try Harness.init();
        defer harness.deinit();
        harness.executor = .{ .mode = .completed };
        harness.crash = scenario[0];
        var first = try harness.run("demo", kind);
        defer first.deinit();
        try std.testing.expectEqual(Outcome.interrupted, first.value.outcome);
        var second = try harness.run("demo", kind);
        defer second.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, second.exitStatus());
        try std.testing.expectEqual(Outcome.recovery_required, second.value.outcome);
        try std.testing.expect(contains(second.value.summary, "the previous run was interrupted after execution began"));
        try std.testing.expectEqual(scenario[1], harness.executor.?.calls);
    }
}

test "system_install.test lock contention refuses before any attempt state" {
    const kind = nonNativeKind();
    var harness = try Harness.init();
    defer harness.deinit();
    var opened = try root_fs.openAbsoluteRoot(std.testing.io, harness.root.path);
    defer opened.close();
    try opened.root.createDirectory(try root_fs.Path.init(state_directory), directory_permissions);
    var other: root_operation.SystemLockBackend = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    const holder = other.interface();
    const root_identity: root_operation.Identity = .{
        .install_root_sha256 = transaction_recovery.rootIdentity(harness.root.path),
        .inode = (try opened.root.rootEntry()).inode,
    };
    for ([_]struct { []const u8, []const u8 }{
        .{ owner_lock_path, "another system install holds /var/lib/debz/system-install/owner.lock; nothing was changed" },
        .{ root_operation.lock_path, "another debz root operation holds /var/lib/debz/root-operation.lock; nothing was changed" },
    }) |scenario| {
        const held_token = try holder.acquire(.{
            .rank = .root_operation,
            .root = opened.root,
            .identity = root_identity,
            .path = scenario[0],
            .wait_ms = 0,
            .cancellation = transaction_executor.Cancellation.never(),
        });
        var busy = harness.run("demo", kind) catch |err| {
            holder.release(held_token);
            return err;
        };
        holder.release(held_token);
        defer busy.deinit();
        try std.testing.expectEqual(api.ExitStatus.unavailable, busy.exitStatus());
        try std.testing.expectEqual(api.ErrorId.root_operation_conflict, busy.value.diagnostics[0].id);
        try std.testing.expectEqualStrings(scenario[1], busy.value.summary);
        try std.testing.expect(!harness.root.exists(active_path));
    }
    try std.testing.expectEqual(@as(usize, 0), harness.planner.calls);
    var result = try harness.run("demo", kind);
    defer result.deinit();
    try std.testing.expectEqual(api.ErrorId.transaction_backend_unavailable, result.value.diagnostics[0].id);
}

test "system_install.test missing or unsafe debz state refuses before any attempt state" {
    var harness = try Harness.init();
    defer harness.deinit();
    try harness.root.tmp.dir.deleteTree(std.testing.io, root_operation.namespace_path);
    var missing = try harness.run("demo", nonNativeKind());
    defer missing.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, missing.exitStatus());
    try std.testing.expectEqual(api.ErrorId.configuration_required, missing.value.diagnostics[0].id);
    try std.testing.expect(!harness.root.exists(root_operation.namespace_path));
    var opened = try root_fs.openAbsoluteRoot(std.testing.io, harness.root.path);
    defer opened.close();
    try opened.root.createDirectory(try root_fs.Path.init(root_operation.namespace_path), .fromMode(0o775));
    var unsafe = try harness.run("demo", nonNativeKind());
    defer unsafe.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, unsafe.exitStatus());
    try std.testing.expectEqualStrings("system install could not start (UnsafeSystemInstallState); nothing was changed", unsafe.value.summary);
    try std.testing.expect(!harness.root.exists(state_directory));
    try std.testing.expectEqual(@as(usize, 0), harness.planner.calls);
}

test "system_install.test tampered attempt evidence and noncanonical results are refused" {
    const kind = nonNativeKind();
    var harness = try Harness.init();
    defer harness.deinit();
    harness.crash = .after_lock_bound;
    var first = try harness.run("demo", kind);
    defer first.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const progress_path = try documentPath(arena_state.allocator(), first.value.attempt_id.?, .progress);
    const original = try harness.root.read(progress_path);
    defer std.testing.allocator.free(original);
    const tampered = try std.mem.replaceOwned(u8, std.testing.allocator, original, "\"lock_bound\"", "\"authorized\"");
    defer std.testing.allocator.free(tampered);
    try std.testing.expect(!std.mem.eql(u8, original, tampered));
    try harness.root.write(progress_path, tampered);
    var refused_adoption = try harness.run("demo", kind);
    defer refused_adoption.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, refused_adoption.exitStatus());
    try std.testing.expect(std.mem.startsWith(
        u8,
        refused_adoption.value.summary,
        "system install state at /var/lib/debz/system-install/active-v1.json could not be adopted (",
    ));
    try std.testing.expect(refused_adoption.value.attempt_id == null);
    const kept = try harness.root.read(progress_path);
    defer std.testing.allocator.free(kept);
    try std.testing.expectEqualStrings(tampered, kept);
    try std.testing.expect(harness.root.exists(active_path));
    try std.testing.expectEqual(@as(usize, 1), harness.planner.calls);

    var valid = try refusal(std.testing.allocator, "demo", .usage, .invalid_request, "invalid package name; nothing was changed");
    defer valid.deinit();
    const canonical_bytes = try valid.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical_bytes);
    var round_trip = try decodeResult(std.testing.allocator, canonical_bytes);
    round_trip.deinit();
    const spaced = try std.mem.concat(std.testing.allocator, u8, &.{ canonical_bytes, " " });
    defer std.testing.allocator.free(spaced);
    try std.testing.expectError(error.NonCanonicalResult, decodeResult(std.testing.allocator, spaced));
    try std.testing.expectError(error.InvalidResult, decodeResult(std.testing.allocator, "{}"));
    const lying = try std.mem.replaceOwned(u8, std.testing.allocator, canonical_bytes, "\"exit_status\":2", "\"exit_status\":0");
    defer std.testing.allocator.free(lying);
    try std.testing.expect(!std.mem.eql(u8, canonical_bytes, lying));
    try std.testing.expectError(error.InvalidResult, decodeResult(std.testing.allocator, lying));
}

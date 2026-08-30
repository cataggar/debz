const std = @import("std");
const solver = @import("solver.zig");
const dpkg_status = @import("dpkg_status.zig");
const exact_lock = @import("exact_lock.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");

pub const journal_version: u32 = 2;
pub const maximum_journal_bytes: usize = 8 * 1024 * 1024;

pub const State = enum {
    not_started,
    in_progress,
    dpkg_failed,
    interrupted,
    verification_failed,
    complete,
};

pub const Boundary = enum { prepared, before_command, after_command, verifying, recovering };

pub const Command = struct {
    phase: []const u8,
    package: ?[]const u8,
    command_sha256: [32]u8,
    artifact_sha256: ?[32]u8,
};

pub const Journal = struct {
    version: u32 = journal_version,
    state: State,
    boundary: Boundary,
    plan_sha256: [32]u8,
    root_identity: [32]u8,
    policy_sha256: [32]u8,
    lock_sha256: ?[32]u8 = null,
    next_command: usize,
    commands: []const Command,
    failure: ?[]const u8 = null,
};

pub const Store = struct {
    context: *anyopaque,
    loadFn: *const fn (*anyopaque, std.mem.Allocator, []const u8) anyerror!?[]u8,
    writeAtomicFn: *const fn (*anyopaque, []const u8, []const u8) anyerror!void,
    archiveAtomicFn: *const fn (*anyopaque, []const u8, []const u8) anyerror!void,

    pub fn load(self: Store, allocator: std.mem.Allocator, root: []const u8) !?[]u8 {
        return self.loadFn(self.context, allocator, root);
    }

    pub fn writeAtomic(self: Store, root: []const u8, bytes: []const u8) !void {
        return self.writeAtomicFn(self.context, root, bytes);
    }

    pub fn archiveAtomic(self: Store, root: []const u8, bytes: []const u8) !void {
        return self.archiveAtomicFn(self.context, root, bytes);
    }
};

pub const StatusReader = struct {
    context: *anyopaque,
    readFn: *const fn (*anyopaque, std.mem.Allocator, []const u8, usize) anyerror![]u8,

    pub fn read(self: StatusReader, allocator: std.mem.Allocator, root: []const u8, maximum: usize) ![]u8 {
        return self.readFn(self.context, allocator, root, maximum);
    }
};

/// Durable journal store rooted at a caller-selected directory. Publication is
/// write, fsync, rename, and directory fsync. Completed journals are retained
/// as `transaction.complete`; active failure evidence is never deleted.
pub const SystemJournalStore = struct {
    io: std.Io,
    dir: std.Io.Dir,
    owns_dir: bool,
    expected_root: []const u8,

    const active_name = "transaction.journal";
    const archive_name = "transaction.complete";
    const stage_name = ".transaction.journal.new";

    pub fn init(io: std.Io, directory_path: []const u8, expected_root: []const u8) !SystemJournalStore {
        const dir = try openOrCreateDirectoryPath(io, directory_path);
        return .{ .io = io, .dir = dir, .owns_dir = true, .expected_root = expected_root };
    }

    pub fn initFromDir(io: std.Io, dir: std.Io.Dir, expected_root: []const u8) SystemJournalStore {
        return .{ .io = io, .dir = dir, .owns_dir = false, .expected_root = expected_root };
    }

    pub fn deinit(self: *SystemJournalStore) void {
        if (self.owns_dir) self.dir.close(self.io);
        self.* = undefined;
    }

    pub fn interface(self: *SystemJournalStore) Store {
        return .{
            .context = self,
            .loadFn = load,
            .writeAtomicFn = writeAtomic,
            .archiveAtomicFn = archiveAtomic,
        };
    }

    fn checkRoot(self: *SystemJournalStore, root: []const u8) !void {
        if (!std.mem.eql(u8, root, self.expected_root)) return error.WrongInstallRoot;
    }

    fn load(context: *anyopaque, allocator: std.mem.Allocator, root: []const u8) !?[]u8 {
        const self: *SystemJournalStore = @ptrCast(@alignCast(context));
        try self.checkRoot(root);
        return readFile(self, allocator, active_name) catch |err| switch (err) {
            error.FileNotFound => readFile(self, allocator, archive_name) catch |archive_err| switch (archive_err) {
                error.FileNotFound => null,
                else => return archive_err,
            },
            else => return err,
        };
    }

    fn writeAtomic(context: *anyopaque, root: []const u8, bytes: []const u8) !void {
        const self: *SystemJournalStore = @ptrCast(@alignCast(context));
        try self.checkRoot(root);
        if (bytes.len > maximum_journal_bytes) return error.JournalTooLarge;
        self.dir.deleteFile(self.io, stage_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        {
            var file = try self.dir.createFile(self.io, stage_name, .{
                .exclusive = true,
                .permissions = if (@import("builtin").os.tag == .windows) .default_file else .fromMode(0o600),
                .resolve_beneath = true,
            });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, bytes);
            try file.sync(self.io);
        }
        try self.dir.rename(stage_name, self.dir, active_name, self.io);
        try syncDirectory(self.io, self.dir);
    }

    fn archiveAtomic(context: *anyopaque, root: []const u8, bytes: []const u8) !void {
        const self: *SystemJournalStore = @ptrCast(@alignCast(context));
        try writeAtomic(context, root, bytes);
        self.dir.deleteFile(self.io, archive_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try self.dir.rename(active_name, self.dir, archive_name, self.io);
        try syncDirectory(self.io, self.dir);
    }

    fn readFile(self: *SystemJournalStore, allocator: std.mem.Allocator, name: []const u8) ![]u8 {
        var file = try self.dir.openFile(self.io, name, .{
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        return reader.interface.allocRemaining(allocator, .limited(maximum_journal_bytes));
    }
};

/// Explicit status-file adapter. It reads only the caller-bound install root;
/// no host dpkg path or environment setting is consulted.
pub const SystemStatusFileReader = struct {
    io: std.Io,
    expected_root: []const u8,

    pub fn interface(self: *SystemStatusFileReader) StatusReader {
        return .{ .context = self, .readFn = read };
    }

    fn read(context: *anyopaque, allocator: std.mem.Allocator, root: []const u8, maximum: usize) ![]u8 {
        const self: *SystemStatusFileReader = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, root, self.expected_root)) return error.WrongInstallRoot;
        var root_dir = try openDirectoryPath(self.io, root);
        defer root_dir.close(self.io);
        var dpkg_dir = try openDirectoryPathFrom(self.io, root_dir, "var/lib/dpkg");
        defer dpkg_dir.close(self.io);
        var file = try dpkg_dir.openFile(self.io, "status", .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        return reader.interface.allocRemaining(allocator, .limited(maximum));
    }
};

fn openOrCreateDirectoryPath(io: std.Io, path: []const u8) !std.Io.Dir {
    var current = if (std.fs.path.isAbsolute(path))
        try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false })
    else
        try std.Io.Dir.cwd().openDir(io, ".", .{ .follow_symlinks = false });
    errdefer current.close(io);
    const components_source = if (std.fs.path.isAbsolute(path)) path[1..] else path;
    var components = std.mem.splitScalar(u8, components_source, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.AmbiguousPath;
        current.createDir(io, component, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const next = try current.openDir(io, component, .{ .follow_symlinks = false });
        current.close(io);
        current = next;
    }
    return current;
}

fn openDirectoryPath(io: std.Io, path: []const u8) !std.Io.Dir {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidAbsolutePath;
    const root = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
    if (path.len == 1) return root;
    return openDirectoryPathFromOwned(io, root, path[1..]);
}

fn openDirectoryPathFrom(io: std.Io, base: std.Io.Dir, path: []const u8) !std.Io.Dir {
    return openDirectoryPathFromOwned(io, try base.openDir(io, ".", .{ .follow_symlinks = false }), path);
}

fn openDirectoryPathFromOwned(io: std.Io, initial: std.Io.Dir, path: []const u8) !std.Io.Dir {
    var current = initial;
    errdefer current.close(io);
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.AmbiguousPath;
        const next = try current.openDir(io, component, .{ .follow_symlinks = false });
        current.close(io);
        current = next;
    }
    return current;
}

fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    _ = io;
    switch (@import("builtin").os.tag) {
        .linux => if (std.posix.errno(std.os.linux.fsync(dir.handle)) != .SUCCESS)
            return error.Unexpected,
        else => {},
    }
}

pub const CrashPoint = enum {
    before_initial_journal,
    after_initial_journal,
    before_command_journal,
    after_command_journal,
    before_verification_journal,
    after_verification_journal,
    before_archive,
};

pub const CrashInjector = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, CrashPoint, usize) anyerror!void,

    pub fn hit(self: CrashInjector, point: CrashPoint, index: usize) !void {
        return self.hitFn(self.context, point, index);
    }

    pub fn none() CrashInjector {
        return .{ .context = @ptrCast(@constCast(&none_context)), .hitFn = noCrash };
    }

    fn noCrash(_: *anyopaque, _: CrashPoint, _: usize) !void {}
};

const none_context: u8 = 0;

pub const VerificationPolicy = struct {
    /// Packages not named by the plan may remain installed, but every package
    /// in the database must be in a healthy final state.
    allow_unrelated_installed: bool = true,
    maximum_status_bytes: usize = 64 * 1024 * 1024,
};

pub const VerificationFailure = enum {
    status_query_failed,
    status_parse_failed,
    unhealthy_package,
    expected_package_missing,
    expected_identity_mismatch,
    removed_package_present,
    unrelated_package,
};

pub const Verification = struct {
    failure: ?VerificationFailure = null,
    package: ?[]const u8 = null,
    expected_version: ?[]const u8 = null,
    observed_version: ?[]const u8 = null,

    pub fn succeeded(self: Verification) bool {
        return self.failure == null;
    }
};

pub fn rootIdentity(root: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-install-root-v1\x00");
    hash.update(root);
    hash.final(&result);
    return result;
}

pub fn policyDigest(
    conffile: []const u8,
    lock_wait_ms: u64,
    process_timeout_ms: u64,
    forces: []const []const u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-executor-policy-v1\x00");
    hash.update(conffile);
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, lock_wait_ms, .little);
    hash.update(&number);
    std.mem.writeInt(u64, &number, process_timeout_ms, .little);
    hash.update(&number);
    for (forces) |force| {
        hash.update(force);
        hash.update("\x00");
    }
    return hash.finalResult();
}

pub fn persist(allocator: std.mem.Allocator, store: Store, root: []const u8, journal: Journal) !void {
    const bytes = try encode(allocator, journal);
    defer allocator.free(bytes);
    try store.writeAtomic(root, bytes);
}

pub fn archive(allocator: std.mem.Allocator, store: Store, root: []const u8, journal: Journal) !void {
    const bytes = try encode(allocator, journal);
    defer allocator.free(bytes);
    try store.archiveAtomic(root, bytes);
}

pub fn encode(allocator: std.mem.Allocator, journal: Journal) ![]u8 {
    var payload: std.Io.Writer.Allocating = .init(allocator);
    defer payload.deinit();
    const writer = &payload.writer;
    try writer.print("DEBZ-TXN\t{d}\nstate\t{s}\nboundary\t{s}\n", .{
        journal.version,
        @tagName(journal.state),
        @tagName(journal.boundary),
    });
    try writeDigest(writer, "plan", journal.plan_sha256);
    try writeDigest(writer, "root", journal.root_identity);
    try writeDigest(writer, "policy", journal.policy_sha256);
    try writer.writeAll("lock\t");
    if (journal.lock_sha256) |digest| try writeRawDigest(writer, digest) else try writer.writeByte('-');
    try writer.writeByte('\n');
    try writer.print("next\t{d}\ncommands\t{d}\n", .{ journal.next_command, journal.commands.len });
    for (journal.commands) |command| {
        try writer.writeAll("command\t");
        try writeHex(writer, command.phase);
        try writer.writeByte('\t');
        if (command.package) |package| try writeHex(writer, package) else try writer.writeByte('-');
        try writer.writeByte('\t');
        try writeRawDigest(writer, command.command_sha256);
        try writer.writeByte('\t');
        if (command.artifact_sha256) |digest| try writeRawDigest(writer, digest) else try writer.writeByte('-');
        try writer.writeByte('\n');
    }
    try writer.writeAll("failure\t");
    if (journal.failure) |failure| try writeHex(writer, failure) else try writer.writeByte('-');
    try writer.writeByte('\n');

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload.written(), &digest, .{});
    try writer.writeAll("checksum\t");
    try writeRawDigest(writer, digest);
    try writer.writeByte('\n');
    return payload.toOwnedSlice();
}

pub const Decoded = struct {
    journal: Journal,
    allocation: []u8,
    commands: []Command,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Decoded) void {
        self.allocator.free(self.commands);
        self.allocator.free(self.allocation);
        self.* = undefined;
    }
};

pub fn decode(allocator: std.mem.Allocator, source: []const u8) !Decoded {
    return decodeBounded(allocator, source, maximum_journal_bytes);
}

pub fn decodeBounded(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !Decoded {
    if (source.len > maximum_bytes or source.len > maximum_journal_bytes)
        return error.JournalTooLarge;
    const checksum_marker = "\nchecksum\t";
    const marker = std.mem.lastIndexOf(u8, source, checksum_marker) orelse return error.MissingChecksum;
    const checksum_start = marker + checksum_marker.len;
    if (checksum_start + 64 + 1 != source.len or source[source.len - 1] != '\n')
        return error.MalformedChecksum;
    const expected = try parseDigest(source[checksum_start .. checksum_start + 64]);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source[0 .. marker + 1], &actual, .{});
    if (!std.mem.eql(u8, &expected, &actual)) return error.ChecksumMismatch;

    const allocation = try allocator.dupe(u8, source[0 .. marker + 1]);
    errdefer allocator.free(allocation);
    var lines = std.mem.splitScalar(u8, allocation, '\n');
    const header = lines.next() orelse return error.MalformedJournal;
    var header_fields = std.mem.splitScalar(u8, header, '\t');
    if (!std.mem.eql(u8, header_fields.next() orelse "", "DEBZ-TXN")) return error.MalformedJournal;
    const version = try std.fmt.parseInt(u32, header_fields.next() orelse return error.MalformedJournal, 10);
    if (version != journal_version) return error.UnsupportedJournalVersion;

    const state = try parseEnumLine(State, lines.next(), "state");
    const boundary = try parseEnumLine(Boundary, lines.next(), "boundary");
    const plan = try parseDigestLine(lines.next(), "plan");
    const root = try parseDigestLine(lines.next(), "root");
    const policy = try parseDigestLine(lines.next(), "policy");
    const lock = try parseOptionalDigestLine(lines.next(), "lock");
    const next = try parseIntLine(lines.next(), "next");
    const count = try parseIntLine(lines.next(), "commands");
    if (count > 300_001 or next > count) return error.ContradictoryJournal;
    const commands = try allocator.alloc(Command, count);
    errdefer allocator.free(commands);
    for (commands) |*command| {
        const line = lines.next() orelse return error.MalformedJournal;
        var fields = std.mem.splitScalar(u8, line, '\t');
        if (!std.mem.eql(u8, fields.next() orelse "", "command")) return error.MalformedJournal;
        command.* = .{
            .phase = try decodeHexInPlace(@constCast(fields.next() orelse return error.MalformedJournal)),
            .package = try optionalHexInPlace(@constCast(fields.next() orelse return error.MalformedJournal)),
            .command_sha256 = try parseDigest(fields.next() orelse return error.MalformedJournal),
            .artifact_sha256 = try optionalDigest(fields.next() orelse return error.MalformedJournal),
        };
        if (fields.next() != null) return error.MalformedJournal;
    }

    const failure_line = lines.next() orelse return error.MalformedJournal;
    var failure_fields = std.mem.splitScalar(u8, failure_line, '\t');
    if (!std.mem.eql(u8, failure_fields.next() orelse "", "failure")) return error.MalformedJournal;
    const failure = try optionalHexInPlace(@constCast(failure_fields.next() orelse return error.MalformedJournal));
    if (failure_fields.next() != null) return error.MalformedJournal;
    if ((state == .complete or state == .not_started or state == .in_progress) and failure != null)
        return error.ContradictoryJournal;
    if ((state == .dpkg_failed or state == .interrupted or state == .verification_failed) and failure == null)
        return error.ContradictoryJournal;
    if (state == .not_started and (boundary != .prepared or next != 0))
        return error.ContradictoryJournal;
    if (lines.next()) |trailing| {
        if (trailing.len != 0 or lines.next() != null) return error.MalformedJournal;
    }

    return .{
        .journal = .{
            .version = version,
            .state = state,
            .boundary = boundary,
            .plan_sha256 = plan,
            .root_identity = root,
            .policy_sha256 = policy,
            .lock_sha256 = lock,
            .next_command = next,
            .commands = commands,
            .failure = failure,
        },
        .allocation = allocation,
        .commands = commands,
        .allocator = allocator,
    };
}

test "transaction_recovery journal decoding is caller bounded" {
    try std.testing.expectError(
        error.JournalTooLarge,
        decodeBounded(std.testing.allocator, "12345", 4),
    );
}

pub fn verify(
    allocator: std.mem.Allocator,
    plan: solver.Plan,
    root: []const u8,
    reader: StatusReader,
    policy: VerificationPolicy,
) !Verification {
    const source = reader.read(allocator, root, policy.maximum_status_bytes) catch
        return .{ .failure = .status_query_failed };
    defer allocator.free(source);
    const parsed = try dpkg_status.parseOwned(allocator, source, .{});
    var database = switch (parsed) {
        .diagnostic => return .{ .failure = .status_parse_failed },
        .database => |value| value,
    };
    defer database.deinit();

    for (database.database.packages) |package| {
        if (package.status.requiresRepair())
            return .{ .failure = .unhealthy_package, .package = package.name.value };
        if (!policy.allow_unrelated_installed and
            findAction(plan.actions, package.name.value, package.architecture.value) == null and
            package.status.isFullyInstalled())
            return .{ .failure = .unrelated_package, .package = package.name.value };
    }

    for (plan.actions) |action| {
        const observed = database.database.find(action.package, action.architecture);
        if (action.kind == .remove) {
            if (observed) |package| {
                if (package.status.isFullyInstalled())
                    return .{ .failure = .removed_package_present, .package = action.package, .observed_version = package.version.spelling.value };
                if (package.status.requiresRepair())
                    return .{ .failure = .unhealthy_package, .package = action.package };
            }
            continue;
        }
        const package = observed orelse
            return .{ .failure = .expected_package_missing, .package = action.package, .expected_version = action.version };
        if (!package.status.isFullyInstalled() or
            !std.mem.eql(u8, package.version.spelling.value, action.version))
            return .{
                .failure = .expected_identity_mismatch,
                .package = action.package,
                .expected_version = action.version,
                .observed_version = package.version.spelling.value,
            };
    }
    return .{};
}

/// Verifies the complete installed closure, not only transaction actions.
/// Exact version spelling and architecture are compared byte-for-byte.
pub fn verifyExactLock(
    allocator: std.mem.Allocator,
    lock: exact_lock.Lock,
    root: []const u8,
    reader: StatusReader,
    maximum_status_bytes: usize,
) !Verification {
    const source = reader.read(allocator, root, maximum_status_bytes) catch
        return .{ .failure = .status_query_failed };
    defer allocator.free(source);
    const parsed = try dpkg_status.parseOwned(allocator, source, .{});
    var database = switch (parsed) {
        .diagnostic => return .{ .failure = .status_parse_failed },
        .database => |value| value,
    };
    defer database.deinit();

    var installed_count: usize = 0;
    for (database.database.packages) |package| {
        if (package.status.requiresRepair())
            return .{ .failure = .unhealthy_package, .package = package.name.value };
        if (!package.status.isFullyInstalled()) continue;
        installed_count += 1;
        const locked = lock.findIdentity(package.name.value, package.architecture.value) orelse
            return .{ .failure = .unrelated_package, .package = package.name.value };
        if (!std.mem.eql(u8, locked.version, package.version.spelling.value))
            return .{
                .failure = .expected_identity_mismatch,
                .package = package.name.value,
                .expected_version = locked.version,
                .observed_version = package.version.spelling.value,
            };
    }
    if (installed_count != lock.packages.len) {
        for (lock.packages) |locked| {
            const package = database.database.find(locked.name, locked.architecture) orelse
                return .{ .failure = .expected_package_missing, .package = locked.name, .expected_version = locked.version };
            if (!package.status.isFullyInstalled())
                return .{ .failure = .expected_package_missing, .package = locked.name, .expected_version = locked.version };
        }
        return .{ .failure = .expected_package_missing };
    }
    return .{};
}

pub fn verifyExactLockV2(
    allocator: std.mem.Allocator,
    lock: exact_lock_v2.Lock,
    root: []const u8,
    reader: StatusReader,
    maximum_status_bytes: usize,
) !Verification {
    const source = reader.read(allocator, root, maximum_status_bytes) catch
        return .{ .failure = .status_query_failed };
    defer allocator.free(source);
    const parsed = try dpkg_status.parseOwned(allocator, source, .{});
    var database = switch (parsed) {
        .diagnostic => return .{ .failure = .status_parse_failed },
        .database => |value| value,
    };
    defer database.deinit();

    var installed_count: usize = 0;
    for (database.database.packages) |package| {
        if (package.status.requiresRepair())
            return .{ .failure = .unhealthy_package, .package = package.name.value };
        if (!package.status.isFullyInstalled()) continue;
        installed_count += 1;
        const locked = lock.findIdentity(package.name.value, package.architecture.value) orelse
            return .{ .failure = .unrelated_package, .package = package.name.value };
        if (!std.mem.eql(u8, locked.version, package.version.spelling.value))
            return .{
                .failure = .expected_identity_mismatch,
                .package = package.name.value,
                .expected_version = locked.version,
                .observed_version = package.version.spelling.value,
            };
    }
    if (installed_count != lock.packages.len) {
        for (lock.packages) |locked| {
            const package = database.database.find(locked.name, locked.architecture) orelse
                return .{ .failure = .expected_package_missing, .package = locked.name, .expected_version = locked.version };
            if (!package.status.isFullyInstalled())
                return .{ .failure = .expected_package_missing, .package = locked.name, .expected_version = locked.version };
        }
        return .{ .failure = .expected_package_missing };
    }
    return .{};
}

fn findAction(actions: []const solver.PlanAction, package: []const u8, architecture: []const u8) ?solver.PlanAction {
    for (actions) |action| {
        if (std.mem.eql(u8, action.package, package) and std.mem.eql(u8, action.architecture, architecture))
            return action;
    }
    return null;
}

const TestStatusReader = struct {
    source: []const u8,

    fn interface(self: *TestStatusReader) StatusReader {
        return .{ .context = self, .readFn = read };
    }

    fn read(context: *anyopaque, allocator: std.mem.Allocator, _: []const u8, maximum: usize) ![]u8 {
        const self: *TestStatusReader = @ptrCast(@alignCast(context));
        if (self.source.len > maximum) return error.StreamTooLong;
        return allocator.dupe(u8, self.source);
    }
};

test "transaction_recovery.test.exact closure verification rejects drift" {
    const repository_id: [64]u8 = @splat('a');
    const package: exact_lock.Package = .{
        .name = "demo",
        .version = "1:2.0-3",
        .architecture = "amd64",
        .repository_id = repository_id,
        .repository_snapshot_sha256 = @splat(1),
        .sha256 = @splat(2),
        .declared_size = 10,
        .retention = .requested,
        .dpkg_selection_hold = false,
    };
    const lock: exact_lock.Lock = .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(0),
        .policy_sha256 = @splat(0),
        .repositories = &.{},
        .packages = &.{package},
        .digest_sha256 = @splat(0),
    };
    var exact: TestStatusReader = .{ .source =
        \\Package: demo
        \\Status: install ok installed
        \\Version: 1:2.0-3
        \\Architecture: amd64
        \\
    };
    try std.testing.expect((try verifyExactLock(std.testing.allocator, lock, "/target", exact.interface(), 4096)).succeeded());
    var drift: TestStatusReader = .{ .source =
        \\Package: demo
        \\Status: install ok installed
        \\Version: 1:2.0-4
        \\Architecture: amd64
        \\
    };
    const mismatch = try verifyExactLock(std.testing.allocator, lock, "/target", drift.interface(), 4096);
    try std.testing.expectEqual(VerificationFailure.expected_identity_mismatch, mismatch.failure.?);
}

fn writeDigest(writer: anytype, name: []const u8, digest: [32]u8) !void {
    try writer.print("{s}\t", .{name});
    try writeRawDigest(writer, digest);
    try writer.writeByte('\n');
}

fn writeRawDigest(writer: anytype, digest: [32]u8) !void {
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{digest}) catch unreachable;
    try writer.writeAll(&hex);
}

fn writeHex(writer: anytype, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 0xf]);
    }
}

fn parseDigest(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.MalformedDigest;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.MalformedDigest;
    return result;
}

fn optionalDigest(value: []const u8) !?[32]u8 {
    if (std.mem.eql(u8, value, "-")) return null;
    return try parseDigest(value);
}

fn parseDigestLine(line: ?[]const u8, name: []const u8) ![32]u8 {
    var fields = std.mem.splitScalar(u8, line orelse return error.MalformedJournal, '\t');
    if (!std.mem.eql(u8, fields.next() orelse "", name)) return error.MalformedJournal;
    const result = try parseDigest(fields.next() orelse return error.MalformedJournal);
    if (fields.next() != null) return error.MalformedJournal;
    return result;
}

fn parseOptionalDigestLine(line: ?[]const u8, name: []const u8) !?[32]u8 {
    var fields = std.mem.splitScalar(u8, line orelse return error.MalformedJournal, '\t');
    if (!std.mem.eql(u8, fields.next() orelse "", name)) return error.MalformedJournal;
    const result = try optionalDigest(fields.next() orelse return error.MalformedJournal);
    if (fields.next() != null) return error.MalformedJournal;
    return result;
}

fn parseIntLine(line: ?[]const u8, name: []const u8) !usize {
    var fields = std.mem.splitScalar(u8, line orelse return error.MalformedJournal, '\t');
    if (!std.mem.eql(u8, fields.next() orelse "", name)) return error.MalformedJournal;
    const result = try std.fmt.parseInt(usize, fields.next() orelse return error.MalformedJournal, 10);
    if (fields.next() != null) return error.MalformedJournal;
    return result;
}

fn parseEnumLine(comptime T: type, line: ?[]const u8, name: []const u8) !T {
    var fields = std.mem.splitScalar(u8, line orelse return error.MalformedJournal, '\t');
    if (!std.mem.eql(u8, fields.next() orelse "", name)) return error.MalformedJournal;
    const result = std.meta.stringToEnum(T, fields.next() orelse return error.MalformedJournal) orelse
        return error.MalformedJournal;
    if (fields.next() != null) return error.MalformedJournal;
    return result;
}

fn optionalHexInPlace(value: []u8) !?[]const u8 {
    if (std.mem.eql(u8, value, "-")) return null;
    return try decodeHexInPlace(value);
}

fn decodeHexInPlace(value: []u8) ![]const u8 {
    if (value.len % 2 != 0) return error.MalformedHex;
    const length = value.len / 2;
    _ = std.fmt.hexToBytes(value[0..length], value) catch return error.MalformedHex;
    return value[0..length];
}

test "transaction_recovery journal integrity and contradictions" {
    const commands = [_]Command{.{
        .phase = "unpack",
        .package = "demo",
        .command_sha256 = @splat(1),
        .artifact_sha256 = @splat(2),
    }};
    const journal: Journal = .{
        .state = .in_progress,
        .boundary = .before_command,
        .plan_sha256 = @splat(3),
        .root_identity = @splat(4),
        .policy_sha256 = @splat(5),
        .next_command = 0,
        .commands = &commands,
    };
    const bytes = try encode(std.testing.allocator, journal);
    defer std.testing.allocator.free(bytes);
    var decoded = try decode(std.testing.allocator, bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(State.in_progress, decoded.journal.state);
    try std.testing.expectEqualStrings("demo", decoded.journal.commands[0].package.?);

    const corrupt = try std.testing.allocator.dupe(u8, bytes);
    defer std.testing.allocator.free(corrupt);
    corrupt[10] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, decode(std.testing.allocator, corrupt));
}

test "transaction_recovery exact verification rejects partial states and permits unrelated healthy packages" {
    const Reader = struct {
        source: []const u8,
        fn read(context: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: usize) ![]u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            return allocator.dupe(u8, self.source);
        }
    };
    var action = [_]solver.PlanAction{.{
        .kind = .install,
        .package = "demo",
        .version = "2",
        .architecture = "amd64",
        .repository = null,
        .sha256 = null,
        .package_size = null,
        .installed_size_delta_bytes = 0,
        .source_package = "demo",
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
    }};
    const plan: solver.Plan = .{
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &action,
        .ordered_actions = &.{},
        .summary = .{},
        .download_bytes = 0,
        .installed_size_delta_bytes = 0,
        .backing_allocator = std.testing.allocator,
        .arena = undefined,
    };
    var healthy: Reader = .{ .source =
        \\Package: demo
        \\Version: 2
        \\Architecture: amd64
        \\Status: install ok installed
        \\
        \\Package: other
        \\Version: 1
        \\Architecture: amd64
        \\Status: install ok installed
        \\
    };
    const ok = try verify(std.testing.allocator, plan, "/target", .{ .context = &healthy, .readFn = Reader.read }, .{});
    try std.testing.expect(ok.succeeded());
    var partial: Reader = .{ .source =
        \\Package: demo
        \\Version: 2
        \\Architecture: amd64
        \\Status: install ok unpacked
        \\
    };
    const bad = try verify(std.testing.allocator, plan, "/target", .{ .context = &partial, .readFn = Reader.read }, .{});
    try std.testing.expectEqual(VerificationFailure.unhealthy_package, bad.failure.?);
}

test "transaction_recovery system journal store atomically archives and reloads completion" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "journal", .default_dir);
    var journal_dir = try tmp.dir.openDir(std.testing.io, "journal", .{ .iterate = true });
    defer journal_dir.close(std.testing.io);
    var store = SystemJournalStore.initFromDir(std.testing.io, journal_dir, "/target");
    const interface = store.interface();
    const journal: Journal = .{
        .state = .complete,
        .boundary = .verifying,
        .plan_sha256 = @splat(1),
        .root_identity = rootIdentity("/target"),
        .policy_sha256 = @splat(2),
        .next_command = 0,
        .commands = &.{},
    };
    try persist(std.testing.allocator, interface, "/target", journal);
    try archive(std.testing.allocator, interface, "/target", journal);
    const bytes = (try interface.load(std.testing.allocator, "/target")).?;
    defer std.testing.allocator.free(bytes);
    var decoded = try decode(std.testing.allocator, bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(State.complete, decoded.journal.state);
    try std.testing.expectError(error.WrongInstallRoot, interface.load(std.testing.allocator, "/other"));
}

test "transaction_recovery production paths reject journal and status symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "safe/root/var/lib/dpkg");
    try tmp.dir.createDirPath(std.testing.io, "outside");
    var status = try tmp.dir.createFile(std.testing.io, "outside/status", .{});
    try status.writeStreamingAll(std.testing.io, "");
    status.close(std.testing.io);
    try tmp.dir.symLink(std.testing.io, "outside", "linked", .{ .is_directory = true });
    try tmp.dir.symLink(std.testing.io, "../../../../outside/status", "safe/root/var/lib/dpkg/status", .{});

    var real_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const real_length = try tmp.dir.realPath(std.testing.io, &real_buffer);
    const root_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/safe/root", .{real_buffer[0..real_length]});
    defer std.testing.allocator.free(root_path);
    var reader: SystemStatusFileReader = .{ .io = std.testing.io, .expected_root = root_path };
    try std.testing.expectError(
        error.SymLinkLoop,
        reader.interface().read(std.testing.allocator, root_path, 1024),
    );

    const linked_journal = try std.fmt.allocPrint(std.testing.allocator, "{s}/linked/journal", .{real_buffer[0..real_length]});
    defer std.testing.allocator.free(linked_journal);
    try std.testing.expectError(
        error.NotDir,
        SystemJournalStore.init(std.testing.io, linked_journal, root_path),
    );
}

//! Audited maintainer-script runner for the native transaction engine.
//!
//! The runner executes one already-validated Debian maintainer script as a
//! child process of the selected root without invoking `dpkg` or `dpkg-deb`
//! and without constructing a shell command. Alternate roots are entered with
//! a chroot-equivalent child setup and working directory `/`; the host root
//! requires the existing explicit host-root policy. Every request is rejected
//! before spawn unless the root, script path, script name, identity,
//! arguments, environment variables, and limits are exactly representable.
//!
//! Package lifecycle ordering, script selection, and filesystem mutation are
//! owned by other native-engine modules. This module owns only the audited
//! child-process boundary and its typed evidence.

const std = @import("std");
const builtin = @import("builtin");
const absolute_path = @import("absolute_path.zig");

pub const Kind = enum {
    preinst,
    postinst,
    prerm,
    postrm,

    pub fn fileName(self: Kind) []const u8 {
        return @tagName(self);
    }
};

pub const Capture = enum {
    /// Separate bounded stdout and stderr pipes.
    separate,
    /// One bounded pipe shared by stdout and stderr, preserving interleaving.
    combined,
};

/// Whether descendants that outlive the script are terminated with the script
/// process group. The bounded native-engine contract terminates them; `detach`
/// preserves dpkg's behavior of leaving a daemon started by a script running.
pub const DescendantPolicy = enum {
    terminate,
    detach,
};

pub const Limits = struct {
    /// Wall-clock budget for the complete script invocation.
    timeout_ms: u64 = 5 * 60 * 1000,
    /// Grace period between the process-group SIGTERM and the SIGKILL escalation.
    termination_grace_ms: u64 = 5_000,
    /// Bounded interval between cancellation, deadline, and readiness checks.
    poll_interval_ms: u32 = 10,
    /// Bounded window used to drain output written before the script exited.
    descendant_drain_ms: u32 = 100,
    /// Total captured bytes across every captured stream.
    maximum_output_bytes: usize = 64 * 1024,
    maximum_arguments: usize = 8,
    maximum_argument_bytes: usize = 512,
};

pub const maximum_output_limit = 1024 * 1024;
pub const maximum_script_path_bytes = 1024;
pub const maximum_variable_bytes = 256;

/// Script directories the runner will execute from. `info` holds installed
/// scripts; `tmp.ci` holds the control members of the package being unpacked.
pub const default_script_directories = [_][]const u8{
    "var/lib/dpkg/info",
    "var/lib/dpkg/tmp.ci",
};

pub const Policy = struct {
    allow_host_root: bool = false,
    capture: Capture = .separate,
    descendants: DescendantPolicy = .terminate,
    limits: Limits = .{},
    script_directories: []const []const u8 = &default_script_directories,
};

pub const Identity = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    kind: Kind,
    /// Root-relative canonical path of the exact validated script file.
    script_path: []const u8,
    /// SHA-256 of the exact script bytes the caller validated before the request.
    script_sha256: [32]u8,
};

/// Additional maintainer-script variables the lifecycle caller may set. The
/// allowlist is closed; no ambient environment value is ever inherited.
pub const VariableName = enum {
    package_refcount,
    running_version,

    pub fn key(self: VariableName) []const u8 {
        return switch (self) {
            .package_refcount => "DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT",
            .running_version => "DPKG_RUNNING_VERSION",
        };
    }
};

pub const Variable = struct {
    name: VariableName,
    value: []const u8,
};

pub const EnvironmentEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const Request = struct {
    /// Absolute canonical path of the selected root.
    root: []const u8,
    identity: Identity,
    /// Exact maintainer-script arguments, without argv[0].
    arguments: []const []const u8 = &.{},
    variables: []const Variable = &.{},
    policy: Policy = .{},
};

pub const Isolation = enum {
    /// Alternate root entered with a chroot-equivalent child setup.
    chroot,
    /// Host root, permitted only by explicit policy.
    host_root,
};

pub const RejectionReason = enum {
    invalid_root,
    host_root_denied,
    invalid_script_path,
    script_directory_denied,
    invalid_script_name,
    invalid_package,
    invalid_version,
    invalid_architecture,
    invalid_argument,
    too_many_arguments,
    invalid_variable,
    duplicate_variable,
    invalid_timeout,
    invalid_output_limit,
    invalid_script_directory,
};

pub const SetupStage = enum {
    /// Output or status pipe creation failed.
    pipe,
    /// `/dev/null` could not be opened for the child's stdin.
    stdin_device,
    fork,
    /// The child could not create its own session and process group.
    session,
    /// Child stdin/stdout/stderr installation failed.
    standard_streams,
    /// chroot-equivalent root entry failed.
    root_isolation,
    working_directory,
    /// `execve` of the script failed.
    execute,
    /// The injected launcher failed before or during the child lifecycle.
    launcher,
    /// The child could not be observed or reaped.
    wait,
};

pub const SetupFailure = struct {
    stage: SetupStage,
    /// Operating-system error number, or 0 when none was reported.
    errno: u32 = 0,
};

/// Outcome of a spawned script. Normal exit, signal, timeout, cancellation,
/// setup failure, and output-limit failure remain exactly distinguishable.
pub const LaunchOutcome = union(enum) {
    exited: u8,
    signaled: u32,
    timed_out,
    cancelled,
    setup_failed: SetupFailure,
    output_limit_exceeded,
};

/// Complete outcome, including requests rejected before any child existed.
pub const Outcome = union(enum) {
    exited: u8,
    signaled: u32,
    timed_out,
    cancelled,
    setup_failed: SetupFailure,
    output_limit_exceeded,
    rejected: RejectionReason,

    pub fn fromLaunch(outcome: LaunchOutcome) Outcome {
        return switch (outcome) {
            .exited => |code| .{ .exited = code },
            .signaled => |signal| .{ .signaled = signal },
            .timed_out => .timed_out,
            .cancelled => .cancelled,
            .setup_failed => |failure| .{ .setup_failed = failure },
            .output_limit_exceeded => .output_limit_exceeded,
        };
    }

    /// Whether a child process was actually created.
    pub fn spawned(self: Outcome) bool {
        return switch (self) {
            .exited, .signaled, .timed_out, .cancelled, .output_limit_exceeded => true,
            .setup_failed => |failure| switch (failure.stage) {
                .root_isolation, .working_directory, .execute, .session, .standard_streams => true,
                .pipe, .stdin_device, .fork, .launcher, .wait => false,
            },
            .rejected => false,
        };
    }
};

pub const Cancellation = struct {
    context: *anyopaque,
    cancelledFn: *const fn (*anyopaque) bool,

    pub fn cancelled(self: Cancellation) bool {
        return self.cancelledFn(self.context);
    }

    pub fn never() Cancellation {
        return .{
            .context = @ptrCast(@constCast(&never_context)),
            .cancelledFn = neverCancelled,
        };
    }

    fn neverCancelled(_: *anyopaque) bool {
        return false;
    }
};

const never_context: u8 = 0;

/// Fully validated child description. Nothing here is derived from ambient
/// process state: the environment is replaced, stdin is `/dev/null`, and the
/// program is an absolute path inside the selected root.
pub const Invocation = struct {
    /// Absolute host path of the selected root.
    root: []const u8,
    isolation: Isolation,
    /// Absolute path of the script as seen from inside the selected root.
    program: []const u8,
    /// Complete argv, including argv[0].
    argv: []const []const u8,
    environment: []const EnvironmentEntry,
    capture: Capture,
    descendants: DescendantPolicy,
    limits: Limits,
    cancellation: Cancellation,
};

pub const Execution = struct {
    outcome: LaunchOutcome,
    stdout: []u8 = &.{},
    stderr: []u8 = &.{},
    combined: []u8 = &.{},
    /// The runner had to terminate the still-running script's process group.
    terminated_process_group: bool = false,
    escalated_to_kill: bool = false,
    /// A final group-wide `SIGKILL` sweep was issued under the `terminate`
    /// descendant policy before the script was reaped. It records that the
    /// sweep was delivered to the process group, not that survivors existed:
    /// whether any descendant was still alive is not observable here.
    issued_descendant_sweep: bool = false,

    pub fn deinit(self: *Execution, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        allocator.free(self.combined);
        self.* = undefined;
    }
};

/// Injection seam for the audited child boundary. Hermetic tests replace it;
/// production uses `SystemLauncher`.
pub const Launcher = struct {
    context: *anyopaque,
    launchFn: *const fn (*anyopaque, std.mem.Allocator, Invocation) anyerror!Execution,

    pub fn launch(
        self: Launcher,
        allocator: std.mem.Allocator,
        invocation: Invocation,
    ) !Execution {
        return self.launchFn(self.context, allocator, invocation);
    }
};

pub const Dependencies = struct {
    launcher: Launcher,
    cancellation: Cancellation = Cancellation.never(),
};

pub const Evidence = struct {
    script_sha256: [32]u8,
    argv_sha256: [32]u8,
    environment_sha256: [32]u8,
    policy_sha256: [32]u8,
    invocation_sha256: [32]u8,
    stdout_sha256: [32]u8,
    stderr_sha256: [32]u8,
    combined_sha256: [32]u8,
};

pub const Report = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    identity: Identity,
    root: []const u8,
    isolation: Isolation,
    program: []const u8,
    argv: []const []const u8,
    environment: []const EnvironmentEntry,
    capture: Capture,
    descendants: DescendantPolicy,
    outcome: Outcome,
    stdout: []const u8,
    stderr: []const u8,
    combined: []const u8,
    output_bytes: usize,
    output_limit: usize,
    terminated_process_group: bool,
    escalated_to_kill: bool,
    /// A group-wide `SIGKILL` sweep was issued under the `terminate`
    /// descendant policy. It never claims that descendants existed.
    issued_descendant_sweep: bool,
    evidence: Evidence,

    pub fn succeeded(self: Report) bool {
        return switch (self.outcome) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    pub fn deinit(self: *Report) void {
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
        self.* = undefined;
    }
};

/// Runs one maintainer script. Rejected requests never spawn a process and are
/// reported with an exact `rejected` outcome instead of an untyped error.
pub fn run(
    allocator: std.mem.Allocator,
    request: Request,
    dependencies: Dependencies,
) !Report {
    const arena_ptr = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena_ptr);
    arena_ptr.* = .init(allocator);
    errdefer arena_ptr.deinit();
    const arena = arena_ptr.allocator();

    // The report outlives the caller's request buffers, so every reported
    // string is owned by the report arena.
    const owned = try cloneRequest(arena, request);
    const isolation: Isolation = if (std.mem.eql(u8, owned.root, "/"))
        .host_root
    else
        .chroot;
    const program = try std.fmt.allocPrint(arena, "/{s}", .{owned.identity.script_path});
    const argv = try buildArgv(arena, program, owned.arguments);
    const environment = try buildEnvironment(arena, owned);
    const evidence_base = digests(owned, isolation, argv, environment);

    if (validate(owned)) |reason| {
        return .{
            .allocator = allocator,
            .arena = arena_ptr,
            .identity = owned.identity,
            .root = owned.root,
            .isolation = isolation,
            .program = program,
            .argv = argv,
            .environment = environment,
            .capture = owned.policy.capture,
            .descendants = owned.policy.descendants,
            .outcome = .{ .rejected = reason },
            .stdout = "",
            .stderr = "",
            .combined = "",
            .output_bytes = 0,
            .output_limit = owned.policy.limits.maximum_output_bytes,
            .terminated_process_group = false,
            .escalated_to_kill = false,
            .issued_descendant_sweep = false,
            .evidence = evidenceWithOutput(evidence_base, "", "", ""),
        };
    }

    var execution = dependencies.launcher.launch(allocator, .{
        .root = owned.root,
        .isolation = isolation,
        .program = program,
        .argv = argv,
        .environment = environment,
        .capture = owned.policy.capture,
        .descendants = owned.policy.descendants,
        .limits = owned.policy.limits,
        .cancellation = dependencies.cancellation,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => Execution{ .outcome = .{ .setup_failed = .{ .stage = .launcher } } },
    };
    defer execution.deinit(allocator);

    const captured_stdout = try arena.dupe(u8, execution.stdout);
    const captured_stderr = try arena.dupe(u8, execution.stderr);
    const captured_combined = try arena.dupe(u8, execution.combined);

    return .{
        .allocator = allocator,
        .arena = arena_ptr,
        .identity = owned.identity,
        .root = owned.root,
        .isolation = isolation,
        .program = program,
        .argv = argv,
        .environment = environment,
        .capture = owned.policy.capture,
        .descendants = owned.policy.descendants,
        .outcome = Outcome.fromLaunch(execution.outcome),
        .stdout = captured_stdout,
        .stderr = captured_stderr,
        .combined = captured_combined,
        .output_bytes = captured_stdout.len + captured_stderr.len + captured_combined.len,
        .output_limit = owned.policy.limits.maximum_output_bytes,
        .terminated_process_group = execution.terminated_process_group,
        .escalated_to_kill = execution.escalated_to_kill,
        .issued_descendant_sweep = execution.issued_descendant_sweep,
        .evidence = evidenceWithOutput(
            evidence_base,
            captured_stdout,
            captured_stderr,
            captured_combined,
        ),
    };
}

/// Returns the exact reason the request may not be spawned, or null.
pub fn validate(request: Request) ?RejectionReason {
    const policy = request.policy;
    if (!absolute_path.root(request.root)) return .invalid_root;
    if (std.mem.eql(u8, request.root, "/") and !policy.allow_host_root) return .host_root_denied;

    if (policy.limits.timeout_ms == 0) return .invalid_timeout;
    if (policy.limits.maximum_output_bytes == 0 or
        policy.limits.maximum_output_bytes > maximum_output_limit)
        return .invalid_output_limit;

    for (policy.script_directories) |directory| {
        if (!validRelativePath(directory)) return .invalid_script_directory;
    }

    const identity = request.identity;
    if (!validPackageName(identity.package)) return .invalid_package;
    if (!validArchitecture(identity.architecture)) return .invalid_architecture;
    if (!validVersion(identity.version)) return .invalid_version;
    if (!validRelativePath(identity.script_path)) return .invalid_script_path;

    const directory = std.fs.path.dirname(identity.script_path) orelse "";
    var directory_allowed = false;
    for (policy.script_directories) |allowed| {
        if (std.mem.eql(u8, allowed, directory)) directory_allowed = true;
    }
    if (!directory_allowed) return .script_directory_denied;
    if (!validScriptName(std.fs.path.basename(identity.script_path), identity))
        return .invalid_script_name;

    if (request.arguments.len > policy.limits.maximum_arguments) return .too_many_arguments;
    for (request.arguments) |argument| {
        if (argument.len == 0 or
            argument.len > policy.limits.maximum_argument_bytes or
            argument[0] == '-' or
            !validText(argument))
            return .invalid_argument;
    }

    var seen: [std.meta.fields(VariableName).len]bool = @splat(false);
    for (request.variables) |variable| {
        if (variable.value.len == 0 or
            variable.value.len > maximum_variable_bytes or
            !validText(variable.value))
            return .invalid_variable;
        const index = @intFromEnum(variable.name);
        if (seen[index]) return .duplicate_variable;
        seen[index] = true;
    }
    return null;
}

pub fn policyDigest(policy: Policy) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-maintainer-script-policy-v1\x00");
    hash.update(if (policy.allow_host_root) "host-root\x00" else "root\x00");
    hashString(&hash, @tagName(policy.capture));
    hashString(&hash, @tagName(policy.descendants));
    hashNumber(&hash, policy.limits.timeout_ms);
    hashNumber(&hash, policy.limits.termination_grace_ms);
    hashNumber(&hash, policy.limits.poll_interval_ms);
    hashNumber(&hash, policy.limits.descendant_drain_ms);
    hashNumber(&hash, policy.limits.maximum_output_bytes);
    hashNumber(&hash, policy.limits.maximum_arguments);
    hashNumber(&hash, policy.limits.maximum_argument_bytes);
    for (policy.script_directories) |directory| hashString(&hash, directory);
    return hash.finalResult();
}

fn cloneRequest(arena: std.mem.Allocator, request: Request) !Request {
    var identity = request.identity;
    identity.package = try arena.dupe(u8, request.identity.package);
    identity.version = try arena.dupe(u8, request.identity.version);
    identity.architecture = try arena.dupe(u8, request.identity.architecture);
    identity.script_path = try arena.dupe(u8, request.identity.script_path);

    const arguments = try arena.alloc([]const u8, request.arguments.len);
    for (request.arguments, arguments) |argument, *slot| slot.* = try arena.dupe(u8, argument);

    const variables = try arena.alloc(Variable, request.variables.len);
    for (request.variables, variables) |variable, *slot| slot.* = .{
        .name = variable.name,
        .value = try arena.dupe(u8, variable.value),
    };

    return .{
        .root = try arena.dupe(u8, request.root),
        .identity = identity,
        .arguments = arguments,
        .variables = variables,
        .policy = request.policy,
    };
}

fn buildArgv(
    arena: std.mem.Allocator,
    program: []const u8,
    arguments: []const []const u8,
) ![]const []const u8 {
    const argv = try arena.alloc([]const u8, arguments.len + 1);
    argv[0] = program;
    for (arguments, argv[1..]) |argument, *slot| slot.* = argument;
    return argv;
}

/// Builds the complete replacement environment. The set is closed, sorted by
/// key, and contains no ambient proxy, credential, or configuration value.
fn buildEnvironment(arena: std.mem.Allocator, request: Request) ![]const EnvironmentEntry {
    var entries: std.ArrayList(EnvironmentEntry) = .empty;
    try entries.appendSlice(arena, &.{
        .{ .key = "DEBIAN_FRONTEND", .value = "noninteractive" },
        .{ .key = "DPKG_ADMINDIR", .value = "/var/lib/dpkg" },
        .{ .key = "DPKG_COLORS", .value = "never" },
        .{ .key = "DPKG_MAINTSCRIPT_ARCH", .value = request.identity.architecture },
        .{ .key = "DPKG_MAINTSCRIPT_NAME", .value = request.identity.kind.fileName() },
        .{ .key = "DPKG_MAINTSCRIPT_PACKAGE", .value = request.identity.package },
        // The child already runs inside the selected root, so the in-root
        // instdir is always "/" and DPKG_ROOT stays empty as dpkg specifies.
        .{ .key = "DPKG_ROOT", .value = "" },
        .{ .key = "HOME", .value = "/nonexistent" },
        .{ .key = "LANG", .value = "C" },
        .{ .key = "LC_ALL", .value = "C" },
        .{ .key = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" },
    });
    for (request.variables) |variable|
        try entries.append(arena, .{ .key = variable.name.key(), .value = variable.value });
    const owned = try entries.toOwnedSlice(arena);
    std.mem.sort(EnvironmentEntry, owned, {}, lessThanKey);
    return owned;
}

fn lessThanKey(_: void, left: EnvironmentEntry, right: EnvironmentEntry) bool {
    return std.mem.lessThan(u8, left.key, right.key);
}

fn digests(
    request: Request,
    isolation: Isolation,
    argv: []const []const u8,
    environment: []const EnvironmentEntry,
) Evidence {
    const argv_sha256 = hashArgv(argv);
    const environment_sha256 = hashEnvironment(environment);
    const policy_sha256 = policyDigest(request.policy);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-maintainer-script-invocation-v1\x00");
    hashString(&hash, request.root);
    hashString(&hash, @tagName(isolation));
    hashString(&hash, request.identity.package);
    hashString(&hash, request.identity.version);
    hashString(&hash, request.identity.architecture);
    hashString(&hash, @tagName(request.identity.kind));
    hashString(&hash, request.identity.script_path);
    hash.update(&request.identity.script_sha256);
    hash.update(&argv_sha256);
    hash.update(&environment_sha256);
    hash.update(&policy_sha256);
    return .{
        .script_sha256 = request.identity.script_sha256,
        .argv_sha256 = argv_sha256,
        .environment_sha256 = environment_sha256,
        .policy_sha256 = policy_sha256,
        .invocation_sha256 = hash.finalResult(),
        .stdout_sha256 = @splat(0),
        .stderr_sha256 = @splat(0),
        .combined_sha256 = @splat(0),
    };
}

fn evidenceWithOutput(
    base: Evidence,
    captured_stdout: []const u8,
    captured_stderr: []const u8,
    captured_combined: []const u8,
) Evidence {
    var evidence = base;
    evidence.stdout_sha256 = hashBytes(captured_stdout);
    evidence.stderr_sha256 = hashBytes(captured_stderr);
    evidence.combined_sha256 = hashBytes(captured_combined);
    return evidence;
}

fn hashArgv(argv: []const []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-maintainer-script-argv-v1\x00");
    for (argv) |argument| hashString(&hash, argument);
    return hash.finalResult();
}

fn hashEnvironment(environment: []const EnvironmentEntry) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-maintainer-script-environment-v1\x00");
    for (environment) |entry| {
        hashString(&hash, entry.key);
        hashString(&hash, entry.value);
    }
    return hash.finalResult();
}

fn hashBytes(value: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(value);
    return hash.finalResult();
}

fn hashString(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, @intCast(value.len), .little);
    hash.update(&length);
    hash.update(value);
}

fn hashNumber(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, value, .little);
    hash.update(&number);
}

fn validRelativePath(path: []const u8) bool {
    if (path.len == 0 or path.len > maximum_script_path_bytes) return false;
    if (path[0] == '/') return false;
    var buffer: [maximum_script_path_bytes + 1]u8 = undefined;
    buffer[0] = '/';
    @memcpy(buffer[1 .. path.len + 1], path);
    return absolute_path.nonRoot(buffer[0 .. path.len + 1]);
}

fn validScriptName(name: []const u8, identity: Identity) bool {
    const kind = identity.kind.fileName();
    if (std.mem.eql(u8, name, kind)) return true;
    if (name.len <= kind.len + 1) return false;
    if (name[name.len - kind.len - 1] != '.') return false;
    if (!std.mem.eql(u8, name[name.len - kind.len ..], kind)) return false;
    const stem = name[0 .. name.len - kind.len - 1];
    if (std.mem.eql(u8, stem, identity.package)) return true;
    if (stem.len <= identity.package.len + 1) return false;
    if (!std.mem.startsWith(u8, stem, identity.package)) return false;
    if (stem[identity.package.len] != ':') return false;
    return std.mem.eql(u8, stem[identity.package.len + 1 ..], identity.architecture);
}

fn validText(value: []const u8) bool {
    if (!std.unicode.utf8ValidateSlice(value)) return false;
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    return true;
}

fn validPackageName(value: []const u8) bool {
    if (value.len < 2 or !lowerAlphaNumeric(value[0])) return false;
    for (value[1..]) |byte| {
        if (!lowerAlphaNumeric(byte) and byte != '+' and byte != '-' and byte != '.') return false;
    }
    return true;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or !lowerAlphaNumeric(value[0])) return false;
    for (value[1..]) |byte| {
        if (!lowerAlphaNumeric(byte) and byte != '-') return false;
    }
    return true;
}

fn validVersion(value: []const u8) bool {
    if (value.len == 0 or value.len > maximum_variable_bytes) return false;
    if (!std.ascii.isAlphanumeric(value[0])) return false;
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '.', '+', '-', ':', '~' => {},
            else => return false,
        }
    }
    return true;
}

fn lowerAlphaNumeric(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or std.ascii.isDigit(byte);
}

/// Production launcher. It forks, enters the selected root with a
/// chroot-equivalent child setup, replaces the environment, binds stdin to
/// `/dev/null`, captures bounded output, and terminates the whole script
/// process group with SIGTERM/SIGKILL escalation and an exact reap.
pub const SystemLauncher = struct {
    pub fn interface(self: *SystemLauncher) Launcher {
        return .{ .context = self, .launchFn = launchInterface };
    }

    fn launchInterface(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        invocation: Invocation,
    ) anyerror!Execution {
        return launch(allocator, invocation);
    }
};

const linux = std.os.linux;

const child_status_bytes = 5;

fn launch(allocator: std.mem.Allocator, invocation: Invocation) !Execution {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    var strings: Strings = try .init(allocator, invocation);
    defer strings.deinit(allocator);

    var output_pipe: [2]i32 = .{ -1, -1 };
    var error_pipe: [2]i32 = .{ -1, -1 };
    var status_pipe: [2]i32 = .{ -1, -1 };
    var null_fd: i32 = -1;
    var opened = false;
    defer if (!opened) {
        closePipe(&output_pipe);
        closePipe(&error_pipe);
        closePipe(&status_pipe);
        closeFd(&null_fd);
    };

    const output = createPipe();
    if (output.errno != 0) return setupFailure(.pipe, output.errno);
    output_pipe = output.fds;
    if (invocation.capture == .separate) {
        const errors = createPipe();
        if (errors.errno != 0) return setupFailure(.pipe, errors.errno);
        error_pipe = errors.fds;
    }
    const status = createPipe();
    if (status.errno != 0) return setupFailure(.pipe, status.errno);
    status_pipe = status.fds;

    const null_device = openNullDevice();
    if (null_device.errno != 0) return setupFailure(.stdin_device, null_device.errno);
    null_fd = null_device.fd;

    const separate = invocation.capture == .separate;
    const child: ChildDescriptor = .{
        .root = strings.root,
        .program = strings.program,
        .argv = strings.argv.ptr,
        .envp = strings.envp.ptr,
        .isolation = invocation.isolation,
        .null_fd = null_fd,
        .output_write = output_pipe[1],
        .error_write = if (separate) error_pipe[1] else output_pipe[1],
        .output_read = output_pipe[0],
        .error_read = if (separate) error_pipe[0] else output_pipe[0],
        .status_write = status_pipe[1],
        .status_read = status_pipe[0],
    };

    const forked = linux.fork();
    switch (linux.errno(forked)) {
        .SUCCESS => {},
        else => |err| return setupFailure(.fork, @intFromEnum(err)),
    }
    const pid: i32 = @intCast(forked);
    if (pid == 0) childMain(child);
    opened = true;

    // Close the race between the parent's group signal and the child's setsid.
    _ = linux.setpgid(pid, pid);
    closeFd(&null_fd);
    closeFd(&output_pipe[1]);
    closeFd(&error_pipe[1]);
    closeFd(&status_pipe[1]);

    return supervise(allocator, invocation, pid, .{
        .output = output_pipe[0],
        .errors = error_pipe[0],
        .status = status_pipe[0],
    });
}

fn setupFailure(stage: SetupStage, errno: u32) Execution {
    return .{ .outcome = .{ .setup_failed = .{ .stage = stage, .errno = errno } } };
}

const Strings = struct {
    root: [:0]u8,
    program: [:0]u8,
    argv: [:null]?[*:0]const u8,
    envp: [:null]?[*:0]const u8,
    argv_storage: [][:0]u8,
    envp_storage: [][:0]u8,

    fn init(allocator: std.mem.Allocator, invocation: Invocation) !Strings {
        const root = try allocator.dupeZ(u8, invocation.root);
        errdefer allocator.free(root);
        const program = try allocator.dupeZ(u8, invocation.program);
        errdefer allocator.free(program);

        const argv_storage = try allocator.alloc([:0]u8, invocation.argv.len);
        errdefer allocator.free(argv_storage);
        var filled_argv: usize = 0;
        errdefer for (argv_storage[0..filled_argv]) |item| allocator.free(item);
        for (invocation.argv, argv_storage) |argument, *slot| {
            slot.* = try allocator.dupeZ(u8, argument);
            filled_argv += 1;
        }

        const envp_storage = try allocator.alloc([:0]u8, invocation.environment.len);
        errdefer allocator.free(envp_storage);
        var filled_envp: usize = 0;
        errdefer for (envp_storage[0..filled_envp]) |item| allocator.free(item);
        for (invocation.environment, envp_storage) |entry, *slot| {
            slot.* = try std.fmt.allocPrintSentinel(
                allocator,
                "{s}={s}",
                .{ entry.key, entry.value },
                0,
            );
            filled_envp += 1;
        }

        const argv = try allocator.allocSentinel(?[*:0]const u8, invocation.argv.len, null);
        errdefer allocator.free(argv);
        for (argv_storage, argv) |item, *slot| slot.* = item.ptr;
        const envp = try allocator.allocSentinel(?[*:0]const u8, invocation.environment.len, null);
        errdefer allocator.free(envp);
        for (envp_storage, envp) |item, *slot| slot.* = item.ptr;

        return .{
            .root = root,
            .program = program,
            .argv = argv,
            .envp = envp,
            .argv_storage = argv_storage,
            .envp_storage = envp_storage,
        };
    }

    fn deinit(self: *Strings, allocator: std.mem.Allocator) void {
        for (self.argv_storage) |item| allocator.free(item);
        for (self.envp_storage) |item| allocator.free(item);
        allocator.free(self.argv_storage);
        allocator.free(self.envp_storage);
        allocator.free(self.argv);
        allocator.free(self.envp);
        allocator.free(self.program);
        allocator.free(self.root);
        self.* = undefined;
    }
};

const ChildDescriptor = struct {
    root: [:0]const u8,
    program: [:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    isolation: Isolation,
    null_fd: i32,
    output_write: i32,
    error_write: i32,
    output_read: i32,
    error_read: i32,
    status_write: i32,
    status_read: i32,
};

/// Child half of the fork. Only async-signal-safe raw syscalls run here; no
/// allocation, no shell, and no ambient environment is consulted.
fn childMain(child: ChildDescriptor) noreturn {
    if (linux.errno(linux.setsid()) != .SUCCESS) {
        const grouped = linux.errno(linux.setpgid(0, 0));
        if (grouped != .SUCCESS) childFail(child.status_write, .session, grouped);
    }

    var streams: ChildStreams = .{
        .input = child.null_fd,
        .output = child.output_write,
        .errors = child.error_write,
        .status = child.status_write,
    };
    // A parent with closed standard descriptors leaves fd 0, 1, or 2 free, so
    // the runner's own pipes can land there. `dup2(fd, fd)` is a no-op that
    // keeps CLOEXEC set, which would silently close the stream at execve, and
    // an aliased source could also be clobbered by an earlier mapping. Lift
    // every still-needed descriptor out of the standard range first.
    if (liftReservedDescriptors(&streams)) |err|
        childFail(child.status_write, .standard_streams, err);

    for ([_][2]i32{
        .{ streams.input, 0 },
        .{ streams.output, 1 },
        .{ streams.errors, 2 },
    }) |mapping| {
        const duplicated = linux.errno(linux.dup2(mapping[0], mapping[1]));
        if (duplicated != .SUCCESS)
            childFail(streams.status, .standard_streams, duplicated);
    }

    for ([_]i32{
        streams.input,
        streams.output,
        streams.errors,
        child.output_read,
        child.error_read,
    }) |fd| {
        if (fd > 2) _ = linux.close(fd);
    }

    var empty = linux.sigemptyset();
    _ = linux.sigprocmask(linux.SIG.SETMASK, &empty, null);
    for ([_]linux.SIG{ .PIPE, .INT, .QUIT, .HUP, .TERM, .CHLD }) |signal| {
        const action: linux.Sigaction = .{
            .handler = .{ .handler = linux.SIG.DFL },
            .mask = empty,
            .flags = 0,
        };
        _ = linux.sigaction(signal, &action, null);
    }

    switch (child.isolation) {
        .chroot => {
            // chdir first so the chroot target and the post-chroot working
            // directory cannot be raced through the inherited cwd.
            const entered = linux.errno(linux.chdir(child.root.ptr));
            if (entered != .SUCCESS) childFail(streams.status, .working_directory, entered);
            const isolated = linux.errno(linux.chroot("."));
            if (isolated != .SUCCESS) childFail(streams.status, .root_isolation, isolated);
        },
        .host_root => {},
    }
    const working = linux.errno(linux.chdir("/"));
    if (working != .SUCCESS) childFail(streams.status, .working_directory, working);

    const executed = linux.errno(linux.execve(child.program.ptr, child.argv, child.envp));
    childFail(streams.status, .execute, executed);
}

const ChildStreams = struct {
    input: i32,
    output: i32,
    errors: i32,
    status: i32,
};

/// Moves every descriptor the child still needs above the standard range so
/// each later `dup2` into 0, 1, and 2 really duplicates the descriptor, which
/// also clears CLOEXEC, instead of aliasing or no-op'ing on it. Returns the
/// exact error when a descriptor cannot be moved.
fn liftReservedDescriptors(streams: *ChildStreams) ?linux.E {
    const slots = [_]*i32{ &streams.input, &streams.output, &streams.errors, &streams.status };
    for (slots) |slot| {
        while (slot.* >= 0 and slot.* < 3) {
            const rc = linux.fcntl(slot.*, linux.F.DUPFD_CLOEXEC, 3);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |err| return err,
            }
            const moved: i32 = @intCast(rc);
            const previous = slot.*;
            // Streams may share one descriptor, so every alias moves together.
            for (slots) |alias| {
                if (alias.* == previous) alias.* = moved;
            }
        }
    }
    return null;
}

fn childFail(status_write: i32, stage: SetupStage, err: linux.E) noreturn {
    var record: [child_status_bytes]u8 = undefined;
    record[0] = @intFromEnum(stage);
    std.mem.writeInt(u32, record[1..5], @intFromEnum(err), .little);
    var written: usize = 0;
    while (written < record.len) {
        const rc = linux.write(status_write, record[written..].ptr, record.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => written += rc,
            .INTR => {},
            else => break,
        }
    }
    linux.exit(127);
}

const ReadEnds = struct {
    output: i32,
    errors: i32,
    status: i32,
};

fn supervise(
    allocator: std.mem.Allocator,
    invocation: Invocation,
    pid: i32,
    ends: ReadEnds,
) !Execution {
    var fds = ends;
    defer closeFd(&fds.output);
    defer closeFd(&fds.errors);
    defer closeFd(&fds.status);

    var primary: std.ArrayList(u8) = .empty;
    defer primary.deinit(allocator);
    var secondary: std.ArrayList(u8) = .empty;
    defer secondary.deinit(allocator);

    var captured: usize = 0;
    var limit_exceeded = false;
    var setup: ?SetupFailure = null;
    var child_exited = false;
    var timed_out = false;
    var cancelled = false;

    const started = monotonicMs();
    var drain_deadline: ?u64 = null;
    var buffer: [4096]u8 = undefined;

    // The loop never ends merely because the captured streams closed: a script
    // that closes or redirects its own stdio keeps running, so the deadline and
    // the cancellation token stay authoritative until the child is observed to
    // have exited.
    while (true) {
        if (invocation.cancellation.cancelled()) {
            cancelled = true;
            break;
        }
        const elapsed = monotonicMs() - started;
        if (elapsed >= invocation.limits.timeout_ms) {
            timed_out = true;
            break;
        }
        if (drain_deadline) |deadline| {
            if (monotonicMs() >= deadline) break;
        }
        const streaming = fds.output >= 0 or fds.errors >= 0 or fds.status >= 0;
        if (child_exited and !streaming) break;

        var poll_fds: [3]linux.pollfd = undefined;
        var slots: [3]*i32 = undefined;
        var count: usize = 0;
        for ([_]*i32{ &fds.output, &fds.errors, &fds.status }) |slot| {
            if (slot.* < 0) continue;
            poll_fds[count] = .{ .fd = slot.*, .events = linux.POLL.IN, .revents = 0 };
            slots[count] = slot;
            count += 1;
        }

        const wait_ms = @min(
            @as(u64, invocation.limits.poll_interval_ms),
            invocation.limits.timeout_ms - elapsed,
        );
        const rc = linux.poll(&poll_fds, count, @intCast(wait_ms));
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => {
                setup = .{ .stage = .wait, .errno = @intFromEnum(linux.errno(rc)) };
                break;
            },
        }

        var progressed = false;
        for (poll_fds[0..count], slots[0..count]) |poll_fd, slot| {
            if (poll_fd.revents == 0) continue;
            progressed = true;
            const read_rc = linux.read(poll_fd.fd, &buffer, buffer.len);
            switch (linux.errno(read_rc)) {
                .SUCCESS => {},
                .INTR, .AGAIN => continue,
                else => {
                    closeFd(slot);
                    continue;
                },
            }
            if (read_rc == 0) {
                closeFd(slot);
                continue;
            }
            const chunk = buffer[0..read_rc];
            if (slot == &fds.status) {
                if (chunk.len >= child_status_bytes) setup = .{
                    .stage = @enumFromInt(chunk[0]),
                    .errno = std.mem.readInt(u32, chunk[1..5], .little),
                };
                continue;
            }
            const sink = if (slot == &fds.errors) &secondary else &primary;
            const remaining = invocation.limits.maximum_output_bytes - captured;
            const accepted = @min(remaining, chunk.len);
            try sink.appendSlice(allocator, chunk[0..accepted]);
            captured += accepted;
            if (accepted < chunk.len) {
                limit_exceeded = true;
                break;
            }
        }
        if (limit_exceeded) break;

        // The exit probe never reaps: the pid stays pinned by its zombie so the
        // process group remains safe to signal during finalization.
        if (!child_exited) child_exited = probeExited(pid);
        // An exited script whose descendants still hold the pipes only gets a
        // bounded drain window before the group is terminated.
        if (child_exited and !progressed and drain_deadline == null)
            drain_deadline = monotonicMs() + invocation.limits.descendant_drain_ms;
    }

    var operations: SystemGroupOperations = .{ .pid = pid };
    const finalized = finalizeGroup(&operations, .{
        .leader_exited = child_exited,
        .sweep = invocation.descendants == .terminate,
        .grace_ms = invocation.limits.termination_grace_ms,
        .poll_ms = group_poll_interval_ms,
    });
    const reaped = finalized.status;
    const terminated = finalized.terminated;
    const escalated = finalized.escalated;
    const issued_sweep = finalized.issued_sweep;

    const outcome: LaunchOutcome = if (setup) |failure|
        .{ .setup_failed = failure }
    else if (cancelled)
        .cancelled
    else if (timed_out)
        .timed_out
    else if (limit_exceeded)
        .output_limit_exceeded
    else if (reaped) |status|
        terminationOf(status)
    else
        .{ .setup_failed = .{ .stage = .wait } };

    var execution: Execution = .{
        .outcome = outcome,
        .terminated_process_group = terminated,
        .escalated_to_kill = escalated,
        .issued_descendant_sweep = issued_sweep,
    };
    switch (invocation.capture) {
        .separate => {
            execution.stdout = try primary.toOwnedSlice(allocator);
            errdefer allocator.free(execution.stdout);
            execution.stderr = try secondary.toOwnedSlice(allocator);
        },
        .combined => execution.combined = try primary.toOwnedSlice(allocator),
    }
    return execution;
}

fn terminationOf(status: u32) LaunchOutcome {
    if (linux.W.IFEXITED(status)) return .{ .exited = linux.W.EXITSTATUS(status) };
    if (linux.W.IFSIGNALED(status)) return .{ .signaled = @intFromEnum(linux.W.TERMSIG(status)) };
    if (linux.W.IFSTOPPED(status)) return .{ .signaled = @intFromEnum(linux.W.STOPSIG(status)) };
    return .{ .signaled = status };
}

const group_poll_interval_ms = 5;

const SignalScope = enum { leader, group };

const TerminationSignal = enum { term, kill };

const Finalization = struct {
    /// Whether the leader was already observed to have exited without reaping.
    leader_exited: bool,
    /// Whether the descendant policy signals the whole process group instead
    /// of the leader alone and issues a final group-wide sweep.
    sweep: bool,
    grace_ms: u64,
    poll_ms: u64,
};

const FinalizeResult = struct {
    status: ?u32 = null,
    terminated: bool = false,
    escalated: bool = false,
    /// The group-wide `SIGKILL` sweep was issued. Survivorship is unknowable:
    /// `kill` on the group cannot distinguish "no descendant was left" from
    /// "descendants were killed", so this only records the attempt.
    issued_sweep: bool = false,
};

/// Ordering-critical shutdown. Every signal is delivered while the leader pid
/// is still pinned by an unreaped child, and the reap is the final operation,
/// so neither a recycled pid nor a recycled process group can ever be
/// signalled by this runner.
fn finalizeGroup(operations: anytype, plan: Finalization) FinalizeResult {
    var result: FinalizeResult = .{};
    var exited = plan.leader_exited;
    const scope: SignalScope = if (plan.sweep) .group else .leader;
    if (!exited) {
        operations.signal(scope, .term);
        result.terminated = true;
        exited = awaitExit(operations, plan);
        if (!exited) {
            operations.signal(scope, .kill);
            result.escalated = true;
            exited = awaitExit(operations, plan);
        }
    }
    if (plan.sweep) {
        // Any survivor is removed before the reap, while the pid is still
        // pinned. The signal is issued unconditionally because a live
        // descendant cannot be observed without racing it; the recorded
        // evidence is therefore the sweep attempt, not a survivor count.
        operations.signal(.group, .kill);
        result.issued_sweep = true;
    }
    result.status = operations.reap(exited);
    return result;
}

fn awaitExit(operations: anytype, plan: Finalization) bool {
    const deadline = operations.now() + plan.grace_ms;
    while (true) {
        if (operations.exited()) return true;
        if (operations.now() >= deadline) return false;
        operations.sleep(plan.poll_ms);
    }
}

const SystemGroupOperations = struct {
    pid: i32,

    fn signal(self: *SystemGroupOperations, scope: SignalScope, number: TerminationSignal) void {
        const target: i32 = switch (scope) {
            .leader => self.pid,
            .group => -self.pid,
        };
        _ = linux.kill(target, switch (number) {
            .term => .TERM,
            .kill => .KILL,
        });
    }

    fn exited(self: *SystemGroupOperations) bool {
        return probeExited(self.pid);
    }

    fn reap(self: *SystemGroupOperations, known_exited: bool) ?u32 {
        return reapChild(self.pid, !known_exited) catch null;
    }

    fn now(_: *SystemGroupOperations) u64 {
        return monotonicMs();
    }

    fn sleep(_: *SystemGroupOperations, milliseconds: u64) void {
        sleepMs(milliseconds);
    }
};

/// Non-destructive exit probe. `WNOWAIT` leaves the zombie in place, so the
/// leader pid keeps its process-group identity reserved until the final reap.
fn probeExited(pid: i32) bool {
    while (true) {
        var info: linux.siginfo_t = std.mem.zeroes(linux.siginfo_t);
        const rc = linux.waitid(
            .PID,
            pid,
            &info,
            linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT,
            null,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => return info.fields.common.first.piduid.pid == pid,
            .INTR => continue,
            // No such child left to wait for: it can no longer be running.
            else => return true,
        }
    }
}

fn reapChild(pid: i32, nohang: bool) !?u32 {
    var status: u32 = 0;
    while (true) {
        const rc = linux.waitpid(pid, &status, if (nohang) linux.W.NOHANG else 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return null;
                return status;
            },
            .INTR => continue,
            .CHILD => return null,
            else => return error.WaitFailed,
        }
    }
}

fn createPipe() struct { fds: [2]i32, errno: u32 } {
    var fds: [2]i32 = undefined;
    const rc = linux.pipe2(&fds, .{ .CLOEXEC = true });
    return switch (linux.errno(rc)) {
        .SUCCESS => .{ .fds = fds, .errno = 0 },
        else => |err| .{ .fds = .{ -1, -1 }, .errno = @intFromEnum(err) },
    };
}

fn openNullDevice() struct { fd: i32, errno: u32 } {
    const rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => .{ .fd = @intCast(rc), .errno = 0 },
        else => |err| .{ .fd = -1, .errno = @intFromEnum(err) },
    };
}

fn closePipe(fds: *[2]i32) void {
    closeFd(&fds[0]);
    closeFd(&fds[1]);
}

fn closeFd(fd: *i32) void {
    if (fd.* < 0) return;
    _ = linux.close(fd.*);
    fd.* = -1;
}

fn monotonicMs() u64 {
    var value: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &value)) != .SUCCESS) return 0;
    return @as(u64, @intCast(value.sec)) * 1000 + @as(u64, @intCast(value.nsec)) / 1_000_000;
}

fn sleepMs(milliseconds: u64) void {
    const request: linux.timespec = .{
        .sec = @intCast(milliseconds / 1000),
        .nsec = @intCast((milliseconds % 1000) * 1_000_000),
    };
    _ = linux.nanosleep(&request, null);
}

const testing = std.testing;

const RecordingLauncher = struct {
    outcome: LaunchOutcome = .{ .exited = 0 },
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    combined: []const u8 = "",
    failure: ?anyerror = null,
    terminated_process_group: bool = false,
    escalated_to_kill: bool = false,
    issued_descendant_sweep: bool = false,
    launches: usize = 0,
    invocation: ?Invocation = null,

    fn interface(self: *RecordingLauncher) Launcher {
        return .{ .context = self, .launchFn = launchRecorded };
    }

    fn launchRecorded(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        invocation: Invocation,
    ) anyerror!Execution {
        const self: *RecordingLauncher = @ptrCast(@alignCast(context));
        self.launches += 1;
        self.invocation = invocation;
        if (self.failure) |err| return err;
        const captured_stdout = try allocator.dupe(u8, self.stdout);
        errdefer allocator.free(captured_stdout);
        const captured_stderr = try allocator.dupe(u8, self.stderr);
        errdefer allocator.free(captured_stderr);
        const captured_combined = try allocator.dupe(u8, self.combined);
        return .{
            .outcome = self.outcome,
            .stdout = captured_stdout,
            .stderr = captured_stderr,
            .combined = captured_combined,
            .terminated_process_group = self.terminated_process_group,
            .escalated_to_kill = self.escalated_to_kill,
            .issued_descendant_sweep = self.issued_descendant_sweep,
        };
    }
};

const CountingCancellation = struct {
    checks: usize = 0,
    cancel_after: usize,

    fn interface(self: *CountingCancellation) Cancellation {
        return .{ .context = self, .cancelledFn = cancelled };
    }

    fn cancelled(context: *anyopaque) bool {
        const self: *CountingCancellation = @ptrCast(@alignCast(context));
        self.checks += 1;
        return self.checks > self.cancel_after;
    }
};

fn testRequest() Request {
    return .{
        .root = "/srv/roots/target",
        .identity = .{
            .package = "demo",
            .version = "1.0-1",
            .architecture = "amd64",
            .kind = .postinst,
            .script_path = "var/lib/dpkg/info/demo.postinst",
            .script_sha256 = @splat(0x11),
        },
        .arguments = &.{ "configure", "0.9-1" },
    };
}

test "maintainer_script.test.unsafe requests are rejected before any spawn" {
    const Case = struct {
        reason: RejectionReason,
        mutate: *const fn (*Request) void,
    };
    const cases = [_]Case{
        .{ .reason = .invalid_root, .mutate = struct {
            fn apply(request: *Request) void {
                request.root = "srv/roots/target";
            }
        }.apply },
        .{ .reason = .invalid_root, .mutate = struct {
            fn apply(request: *Request) void {
                request.root = "/srv/../roots";
            }
        }.apply },
        .{ .reason = .host_root_denied, .mutate = struct {
            fn apply(request: *Request) void {
                request.root = "/";
            }
        }.apply },
        .{ .reason = .invalid_script_path, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "/var/lib/dpkg/info/demo.postinst";
            }
        }.apply },
        .{ .reason = .invalid_script_path, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "var/lib/dpkg/info/../../../etc/demo.postinst";
            }
        }.apply },
        .{ .reason = .script_directory_denied, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "tmp/demo.postinst";
            }
        }.apply },
        .{ .reason = .invalid_script_name, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "var/lib/dpkg/info/other.postinst";
            }
        }.apply },
        .{ .reason = .invalid_script_name, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "var/lib/dpkg/info/demo.prerm";
            }
        }.apply },
        .{ .reason = .invalid_package, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.package = "Demo Package";
            }
        }.apply },
        .{ .reason = .invalid_architecture, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.architecture = "amd64;rm";
            }
        }.apply },
        .{ .reason = .invalid_version, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.version = "1.0 -1";
            }
        }.apply },
        .{ .reason = .invalid_argument, .mutate = struct {
            fn apply(request: *Request) void {
                request.arguments = &.{"--force-all"};
            }
        }.apply },
        .{ .reason = .invalid_argument, .mutate = struct {
            fn apply(request: *Request) void {
                request.arguments = &.{"configure\n--"};
            }
        }.apply },
        .{ .reason = .too_many_arguments, .mutate = struct {
            fn apply(request: *Request) void {
                request.policy.limits.maximum_arguments = 1;
            }
        }.apply },
        .{ .reason = .invalid_variable, .mutate = struct {
            fn apply(request: *Request) void {
                request.variables = &.{.{ .name = .running_version, .value = "1.21\x00" }};
            }
        }.apply },
        .{ .reason = .duplicate_variable, .mutate = struct {
            fn apply(request: *Request) void {
                request.variables = &.{
                    .{ .name = .running_version, .value = "1.21" },
                    .{ .name = .running_version, .value = "1.22" },
                };
            }
        }.apply },
        .{ .reason = .invalid_timeout, .mutate = struct {
            fn apply(request: *Request) void {
                request.policy.limits.timeout_ms = 0;
            }
        }.apply },
        .{ .reason = .invalid_output_limit, .mutate = struct {
            fn apply(request: *Request) void {
                request.policy.limits.maximum_output_bytes = maximum_output_limit + 1;
            }
        }.apply },
        .{ .reason = .invalid_script_directory, .mutate = struct {
            fn apply(request: *Request) void {
                request.policy.script_directories = &.{"/var/lib/dpkg/info"};
            }
        }.apply },
    };

    var launcher: RecordingLauncher = .{};
    for (cases) |case| {
        var request = testRequest();
        case.mutate(&request);
        try testing.expectEqual(case.reason, validate(request).?);
        var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
        defer report.deinit();
        try testing.expectEqual(case.reason, report.outcome.rejected);
        try testing.expect(!report.succeeded());
        try testing.expect(!report.outcome.spawned());
    }
    try testing.expectEqual(@as(usize, 0), launcher.launches);

    const accepted = testRequest();
    try testing.expect(validate(accepted) == null);
}

test "maintainer_script.test.environment is a fixed allowlist without ambient inheritance" {
    var request = testRequest();
    request.variables = &.{
        .{ .name = .running_version, .value = "1.21.22" },
        .{ .name = .package_refcount, .value = "1" },
    };
    var launcher: RecordingLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();

    const expected = [_]EnvironmentEntry{
        .{ .key = "DEBIAN_FRONTEND", .value = "noninteractive" },
        .{ .key = "DPKG_ADMINDIR", .value = "/var/lib/dpkg" },
        .{ .key = "DPKG_COLORS", .value = "never" },
        .{ .key = "DPKG_MAINTSCRIPT_ARCH", .value = "amd64" },
        .{ .key = "DPKG_MAINTSCRIPT_NAME", .value = "postinst" },
        .{ .key = "DPKG_MAINTSCRIPT_PACKAGE", .value = "demo" },
        .{ .key = "DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT", .value = "1" },
        .{ .key = "DPKG_ROOT", .value = "" },
        .{ .key = "DPKG_RUNNING_VERSION", .value = "1.21.22" },
        .{ .key = "HOME", .value = "/nonexistent" },
        .{ .key = "LANG", .value = "C" },
        .{ .key = "LC_ALL", .value = "C" },
        .{ .key = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" },
    };
    try testing.expectEqual(expected.len, report.environment.len);
    for (expected, report.environment) |wanted, actual| {
        try testing.expectEqualStrings(wanted.key, actual.key);
        try testing.expectEqualStrings(wanted.value, actual.value);
    }
}

test "maintainer_script.test.invocation binds the selected root program and evidence" {
    var launcher: RecordingLauncher = .{};
    var report = try run(testing.allocator, testRequest(), .{ .launcher = launcher.interface() });
    defer report.deinit();

    try testing.expectEqual(@as(usize, 1), launcher.launches);
    const invocation = launcher.invocation.?;
    try testing.expectEqual(Isolation.chroot, invocation.isolation);
    try testing.expectEqualStrings("/srv/roots/target", invocation.root);
    try testing.expectEqualStrings("/var/lib/dpkg/info/demo.postinst", invocation.program);
    try testing.expectEqual(@as(usize, 3), invocation.argv.len);
    try testing.expectEqualStrings("/var/lib/dpkg/info/demo.postinst", invocation.argv[0]);
    try testing.expectEqualStrings("configure", invocation.argv[1]);
    try testing.expectEqualStrings("0.9-1", invocation.argv[2]);
    try testing.expectEqual(Capture.separate, invocation.capture);
    try testing.expectEqual(DescendantPolicy.terminate, invocation.descendants);
    try testing.expectEqualStrings("/var/lib/dpkg/info/demo.postinst", report.program);
    try testing.expect(report.succeeded());

    var host = testRequest();
    host.root = "/";
    host.policy.allow_host_root = true;
    var host_report = try run(testing.allocator, host, .{ .launcher = launcher.interface() });
    defer host_report.deinit();
    try testing.expectEqual(Isolation.host_root, host_report.isolation);
    try testing.expect(!std.mem.eql(
        u8,
        &report.evidence.invocation_sha256,
        &host_report.evidence.invocation_sha256,
    ));

    var renamed = testRequest();
    renamed.identity.script_sha256 = @splat(0x22);
    var renamed_report = try run(testing.allocator, renamed, .{ .launcher = launcher.interface() });
    defer renamed_report.deinit();
    try testing.expect(!std.mem.eql(
        u8,
        &report.evidence.invocation_sha256,
        &renamed_report.evidence.invocation_sha256,
    ));
    try testing.expectEqualSlices(
        u8,
        &report.evidence.argv_sha256,
        &renamed_report.evidence.argv_sha256,
    );

    var repeated = try run(testing.allocator, testRequest(), .{ .launcher = launcher.interface() });
    defer repeated.deinit();
    try testing.expectEqualSlices(
        u8,
        &report.evidence.invocation_sha256,
        &repeated.evidence.invocation_sha256,
    );
    try testing.expectEqualSlices(
        u8,
        &policyDigest(.{}),
        &report.evidence.policy_sha256,
    );
}

test "maintainer_script.test.outcomes remain exactly distinguishable" {
    const outcomes = [_]LaunchOutcome{
        .{ .exited = 0 },
        .{ .exited = 1 },
        .{ .signaled = 9 },
        .timed_out,
        .cancelled,
        .output_limit_exceeded,
        .{ .setup_failed = .{ .stage = .root_isolation, .errno = 1 } },
        .{ .setup_failed = .{ .stage = .fork, .errno = 11 } },
    };
    for (outcomes) |outcome| {
        var launcher: RecordingLauncher = .{ .outcome = outcome, .stdout = "out", .stderr = "err" };
        var report = try run(testing.allocator, testRequest(), .{ .launcher = launcher.interface() });
        defer report.deinit();
        try testing.expectEqualStrings(
            @tagName(std.meta.activeTag(outcome)),
            @tagName(std.meta.activeTag(report.outcome)),
        );
        try testing.expectEqualStrings("out", report.stdout);
        try testing.expectEqualStrings("err", report.stderr);
        try testing.expectEqual(@as(usize, 6), report.output_bytes);
        try testing.expectEqualSlices(u8, &hashBytes("out"), &report.evidence.stdout_sha256);
        try testing.expectEqualSlices(u8, &hashBytes("err"), &report.evidence.stderr_sha256);
        switch (outcome) {
            .exited => |code| {
                try testing.expectEqual(code, report.outcome.exited);
                try testing.expectEqual(code == 0, report.succeeded());
            },
            .signaled => |signal| try testing.expectEqual(signal, report.outcome.signaled),
            .setup_failed => |failure| {
                try testing.expectEqual(failure.stage, report.outcome.setup_failed.stage);
                try testing.expectEqual(failure.errno, report.outcome.setup_failed.errno);
                try testing.expectEqual(
                    failure.stage == .root_isolation,
                    report.outcome.spawned(),
                );
            },
            else => try testing.expect(!report.succeeded()),
        }
    }
}

fn environmentValue(environment: []const EnvironmentEntry, key: []const u8) ?[]const u8 {
    for (environment) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry.value;
    }
    return null;
}

test "maintainer_script.test.report owns every reported string" {
    const allocator = testing.allocator;
    const root = try allocator.dupe(u8, "/srv/roots/target");
    const package = try allocator.dupe(u8, "demo");
    const script_path = try allocator.dupe(u8, "var/lib/dpkg/info/demo.postinst");
    const argument = try allocator.dupe(u8, "configure");
    const refcount = try allocator.dupe(u8, "1");

    var request = testRequest();
    request.root = root;
    request.identity.package = package;
    request.identity.script_path = script_path;
    request.arguments = &.{argument};
    request.variables = &.{.{ .name = .package_refcount, .value = refcount }};

    var launcher: RecordingLauncher = .{ .outcome = .{ .exited = 0 } };
    var report = try run(allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();

    allocator.free(root);
    allocator.free(package);
    allocator.free(script_path);
    allocator.free(argument);
    allocator.free(refcount);

    try testing.expectEqualStrings("/srv/roots/target", report.root);
    try testing.expectEqualStrings("demo", report.identity.package);
    try testing.expectEqualStrings("var/lib/dpkg/info/demo.postinst", report.identity.script_path);
    try testing.expectEqualStrings("/var/lib/dpkg/info/demo.postinst", report.argv[0]);
    try testing.expectEqualStrings("configure", report.argv[1]);
    const refcount_value = environmentValue(
        report.environment,
        "DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT",
    ).?;
    try testing.expectEqualStrings("1", refcount_value);
    try testing.expectEqualStrings("demo", environmentValue(report.environment, "DPKG_MAINTSCRIPT_PACKAGE").?);
}

test "maintainer_script.test.sweep evidence records the attempt, not survivors" {
    // A rejected request never spawns, so no signal of any kind was issued.
    var rejecting: RecordingLauncher = .{};
    var rejected_request = testRequest();
    rejected_request.identity.script_path = "etc/demo.postinst";
    var rejected = try run(testing.allocator, rejected_request, .{
        .launcher = rejecting.interface(),
    });
    defer rejected.deinit();
    try testing.expectEqual(@as(usize, 0), rejecting.launches);
    try testing.expect(!rejected.issued_descendant_sweep);
    try testing.expect(!rejected.terminated_process_group);

    // A script that exited on its own still gets the group-wide sweep under the
    // `terminate` policy. The report must say the sweep was issued without
    // claiming a descendant was alive, so termination stays false.
    var swept: RecordingLauncher = .{
        .outcome = .{ .exited = 0 },
        .issued_descendant_sweep = true,
    };
    var clean = try run(testing.allocator, testRequest(), .{ .launcher = swept.interface() });
    defer clean.deinit();
    try testing.expect(clean.succeeded());
    try testing.expect(clean.issued_descendant_sweep);
    try testing.expect(!clean.terminated_process_group);
    try testing.expect(!clean.escalated_to_kill);

    // An actually terminated process group is distinguishable from the sweep.
    var forced: RecordingLauncher = .{
        .outcome = .timed_out,
        .terminated_process_group = true,
        .escalated_to_kill = true,
        .issued_descendant_sweep = true,
    };
    var terminated = try run(testing.allocator, testRequest(), .{ .launcher = forced.interface() });
    defer terminated.deinit();
    try testing.expectEqualStrings("timed_out", @tagName(terminated.outcome));
    try testing.expect(terminated.terminated_process_group);
    try testing.expect(terminated.escalated_to_kill);
    try testing.expect(terminated.issued_descendant_sweep);

    // The `detach` policy never signals the group, so no sweep is issued.
    var detached_launcher: RecordingLauncher = .{ .outcome = .{ .exited = 0 } };
    var detached_request = testRequest();
    detached_request.policy.descendants = .detach;
    var detached = try run(testing.allocator, detached_request, .{
        .launcher = detached_launcher.interface(),
    });
    defer detached.deinit();
    try testing.expectEqual(DescendantPolicy.detach, detached_launcher.invocation.?.descendants);
    try testing.expect(!detached.issued_descendant_sweep);
}

test "maintainer_script.test.launcher failures become typed setup evidence" {
    var failing: RecordingLauncher = .{ .failure = error.AccessDenied };
    var report = try run(testing.allocator, testRequest(), .{ .launcher = failing.interface() });
    defer report.deinit();
    try testing.expectEqual(SetupStage.launcher, report.outcome.setup_failed.stage);
    try testing.expect(!report.outcome.spawned());
    try testing.expect(!report.succeeded());

    var exhausted: RecordingLauncher = .{ .failure = error.OutOfMemory };
    try testing.expectError(
        error.OutOfMemory,
        run(testing.allocator, testRequest(), .{ .launcher = exhausted.interface() }),
    );
}

fn skipUnlessPosixShell() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var shell = std.Io.Dir.openFileAbsolute(testing.io, "/bin/sh", .{ .mode = .read_only }) catch
        return error.SkipZigTest;
    shell.close(testing.io);
}

fn writeExecutableScript(
    directory: *std.testing.TmpDir,
    sub_path: []const u8,
    body: []const u8,
) !void {
    if (std.fs.path.dirname(sub_path)) |parent|
        try directory.dir.createDirPath(testing.io, parent);
    try directory.dir.writeFile(testing.io, .{
        .sub_path = sub_path,
        .data = body,
        .flags = .{ .permissions = .executable_file },
    });
}

fn absoluteTempPath(
    allocator: std.mem.Allocator,
    directory: *std.testing.TmpDir,
    sub_path: []const u8,
) ![]u8 {
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ buffer[0..length], sub_path });
}

/// Hermetic host-root fixture. Host-root execution is the strongest script
/// execution unprivileged CI can perform; the alternate-root chroot contract is
/// exercised separately.
const HostScript = struct {
    absolute: []u8,
    directories: [1][]const u8,

    fn init(
        allocator: std.mem.Allocator,
        directory: *std.testing.TmpDir,
        sub_path: []const u8,
        body: []const u8,
    ) !HostScript {
        try writeExecutableScript(directory, sub_path, body);
        const absolute = try absoluteTempPath(allocator, directory, sub_path);
        errdefer allocator.free(absolute);
        const relative = absolute[1..];
        return .{
            .absolute = absolute,
            .directories = .{std.fs.path.dirname(relative) orelse return error.TestUnexpectedResult},
        };
    }

    fn deinit(self: *HostScript, allocator: std.mem.Allocator) void {
        allocator.free(self.absolute);
        self.* = undefined;
    }

    fn request(self: *const HostScript, arguments: []const []const u8) Request {
        return .{
            .root = "/",
            .identity = .{
                .package = "demo",
                .version = "1.0-1",
                .architecture = "amd64",
                .kind = .postinst,
                .script_path = self.absolute[1..],
                .script_sha256 = @splat(0),
            },
            .arguments = arguments,
            .policy = .{
                .allow_host_root = true,
                .script_directories = &self.directories,
                .limits = .{ .timeout_ms = 20_000, .termination_grace_ms = 500 },
            },
        };
    }
};

test "maintainer_script.test.system launcher captures bounded output from a sanitized child" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\printf 'argument=%s\n' "$1"
        \\printf 'directory=%s\n' "$PWD"
        \\printf 'path=%s\n' "$PATH"
        \\printf 'locale=%s\n' "$LC_ALL"
        \\printf 'frontend=%s\n' "$DEBIAN_FRONTEND"
        \\printf 'package=%s\n' "$DPKG_MAINTSCRIPT_PACKAGE"
        \\printf 'name=%s\n' "$DPKG_MAINTSCRIPT_NAME"
        \\printf 'home=%s\n' "$HOME"
        \\printf 'ambient=[%s]\n' "${DEBZ_AMBIENT_TEST_VALUE-}"
        \\printf 'stdin=[%s]\n' "$(cat)"
        \\printf 'diagnostic\n' >&2
        \\exit 3
        \\
    );
    defer script.deinit(testing.allocator);

    var launcher: SystemLauncher = .{};
    var report = try run(
        testing.allocator,
        script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    );
    defer report.deinit();

    try testing.expectEqual(@as(u8, 3), report.outcome.exited);
    try testing.expect(!report.succeeded());
    try testing.expectEqualStrings("diagnostic\n", report.stderr);
    try testing.expectEqualStrings("", report.combined);
    try testing.expectEqualStrings(
        \\argument=configure
        \\directory=/
        \\path=/usr/sbin:/usr/bin:/sbin:/bin
        \\locale=C
        \\frontend=noninteractive
        \\package=demo
        \\name=postinst
        \\home=/nonexistent
        \\ambient=[]
        \\stdin=[]
        \\
    , report.stdout);
    try testing.expectEqualSlices(u8, &hashBytes(report.stdout), &report.evidence.stdout_sha256);
    try testing.expect(!report.terminated_process_group);
    try testing.expect(!report.escalated_to_kill);
    // The script exited on its own, so nothing was terminated. The sweep is
    // still issued under the `terminate` policy, and the flag reports only
    // that: it never asserts that a descendant survived.
    try testing.expect(report.issued_descendant_sweep);
}

test "maintainer_script.test.system launcher issues no sweep under the detach policy" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\exit 0
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.descendants = .detach;

    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();

    try testing.expectEqual(@as(u8, 0), report.outcome.exited);
    try testing.expect(!report.terminated_process_group);
    try testing.expect(!report.escalated_to_kill);
    try testing.expect(!report.issued_descendant_sweep);
}

test "maintainer_script.test.system launcher reports a script terminated by a signal" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\kill -9 $$
        \\
    );
    defer script.deinit(testing.allocator);

    var launcher: SystemLauncher = .{};
    var report = try run(
        testing.allocator,
        script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    );
    defer report.deinit();

    try testing.expectEqual(@as(u32, 9), report.outcome.signaled);
    try testing.expect(report.outcome.spawned());
    try testing.expect(!report.succeeded());
}

test "maintainer_script.test.system launcher terminates the script process tree on timeout" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\sleep 300 &
        \\echo $! >"$1"
        \\sleep 300
        \\
    );
    defer script.deinit(testing.allocator);
    const pid_path = try absoluteTempPath(testing.allocator, &directory, "descendant.pid");
    defer testing.allocator.free(pid_path);

    var request = script.request(&.{pid_path});
    request.policy.limits.timeout_ms = 500;
    request.policy.limits.termination_grace_ms = 200;

    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();

    try testing.expectEqualStrings("timed_out", @tagName(report.outcome));
    try testing.expect(report.terminated_process_group);
    try testing.expect(report.issued_descendant_sweep);

    const recorded = try directory.dir.readFileAlloc(
        testing.io,
        "descendant.pid",
        testing.allocator,
        .limited(64),
    );
    defer testing.allocator.free(recorded);
    const descendant = try std.fmt.parseInt(
        i32,
        std.mem.trim(u8, recorded, &std.ascii.whitespace),
        10,
    );
    try expectProcessTerminated(descendant);
}

fn expectProcessTerminated(pid: i32) !void {
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        if (linux.errno(linux.kill(pid, @enumFromInt(0))) == .SRCH) return;
        sleepMs(10);
    }
    return error.TestDescendantSurvived;
}

test "maintainer_script.test.system launcher cancels a running script" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\sleep 300
        \\
    );
    defer script.deinit(testing.allocator);

    var cancellation: CountingCancellation = .{ .cancel_after = 3 };
    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, script.request(&.{"configure"}), .{
        .launcher = launcher.interface(),
        .cancellation = cancellation.interface(),
    });
    defer report.deinit();

    try testing.expectEqualStrings("cancelled", @tagName(report.outcome));
    try testing.expect(report.terminated_process_group);
    try testing.expect(!report.succeeded());
}

test "maintainer_script.test.system launcher bounds a script that closed its own streams" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    // Redirecting the captured streams closes every pipe the supervisor holds
    // while the script keeps running, so only the deadline can end the run.
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\exec >/dev/null 2>&1
        \\sleep 300
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.limits.timeout_ms = 500;
    request.policy.limits.termination_grace_ms = 200;

    var launcher: SystemLauncher = .{};
    const started = monotonicMs();
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();

    try testing.expectEqualStrings("timed_out", @tagName(report.outcome));
    try testing.expect(report.terminated_process_group);
    try testing.expect(!report.succeeded());
    try testing.expect(monotonicMs() - started < 20_000);
}

test "maintainer_script.test.system launcher cancels a script that closed its own streams" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\exec >/dev/null 2>&1
        \\sleep 300
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.limits.termination_grace_ms = 200;

    var cancellation: CountingCancellation = .{ .cancel_after = 3 };
    var launcher: SystemLauncher = .{};
    const started = monotonicMs();
    var report = try run(testing.allocator, request, .{
        .launcher = launcher.interface(),
        .cancellation = cancellation.interface(),
    });
    defer report.deinit();

    try testing.expectEqualStrings("cancelled", @tagName(report.outcome));
    try testing.expect(report.terminated_process_group);
    try testing.expect(monotonicMs() - started < 20_000);
}

const TraceEvent = enum {
    term_leader,
    term_group,
    kill_leader,
    kill_group,
    reap,
};

/// Deterministic stand-in for the child process group. It records the exact
/// order of signalling and reaping without depending on pid reuse.
const RecordingGroupOperations = struct {
    events: [8]TraceEvent = undefined,
    count: usize = 0,
    probes: usize = 0,
    /// Number of exit probes answered with "still running".
    running_probes: usize = 0,
    clock: u64 = 0,
    status: u32 = 0,
    reaped_at: ?usize = null,
    blocking_reap: ?bool = null,

    fn signal(self: *RecordingGroupOperations, scope: SignalScope, number: TerminationSignal) void {
        self.record(switch (scope) {
            .leader => switch (number) {
                .term => .term_leader,
                .kill => .kill_leader,
            },
            .group => switch (number) {
                .term => .term_group,
                .kill => .kill_group,
            },
        });
    }

    fn exited(self: *RecordingGroupOperations) bool {
        self.probes += 1;
        return self.probes > self.running_probes;
    }

    fn reap(self: *RecordingGroupOperations, known_exited: bool) ?u32 {
        self.blocking_reap = known_exited;
        self.reaped_at = self.count;
        self.record(.reap);
        return self.status;
    }

    fn now(self: *RecordingGroupOperations) u64 {
        return self.clock;
    }

    fn sleep(self: *RecordingGroupOperations, milliseconds: u64) void {
        self.clock += milliseconds;
    }

    fn record(self: *RecordingGroupOperations, event: TraceEvent) void {
        self.events[self.count] = event;
        self.count += 1;
    }

    fn trace(self: *const RecordingGroupOperations) []const TraceEvent {
        return self.events[0..self.count];
    }
};

fn expectTrace(expected: []const TraceEvent, operations: *const RecordingGroupOperations) !void {
    try testing.expectEqualSlices(TraceEvent, expected, operations.trace());
    // The reap must be the last operation: signalling afterwards could reach a
    // recycled pid or process group.
    try testing.expectEqual(operations.count - 1, operations.reaped_at.?);
}

test "maintainer_script.test.finalization never signals a group after reaping it" {
    const plan: Finalization = .{
        .leader_exited = false,
        .sweep = true,
        .grace_ms = 50,
        .poll_ms = 10,
    };

    var exited_cleanly: RecordingGroupOperations = .{ .status = 0 };
    const clean = finalizeGroup(&exited_cleanly, .{
        .leader_exited = true,
        .sweep = true,
        .grace_ms = plan.grace_ms,
        .poll_ms = plan.poll_ms,
    });
    try expectTrace(&.{ .kill_group, .reap }, &exited_cleanly);
    try testing.expect(!clean.terminated);
    try testing.expect(!clean.escalated);
    try testing.expect(clean.issued_sweep);
    try testing.expectEqual(true, exited_cleanly.blocking_reap.?);

    var detached: RecordingGroupOperations = .{ .status = 0 };
    const kept = finalizeGroup(&detached, .{
        .leader_exited = true,
        .sweep = false,
        .grace_ms = plan.grace_ms,
        .poll_ms = plan.poll_ms,
    });
    try expectTrace(&.{.reap}, &detached);
    try testing.expect(!kept.issued_sweep);

    var polite: RecordingGroupOperations = .{ .running_probes = 2 };
    const terminated = finalizeGroup(&polite, plan);
    try expectTrace(&.{ .term_group, .kill_group, .reap }, &polite);
    try testing.expect(terminated.terminated);
    try testing.expect(!terminated.escalated);
    try testing.expect(terminated.issued_sweep);

    var stubborn: RecordingGroupOperations = .{ .running_probes = 1_000 };
    const escalated = finalizeGroup(&stubborn, plan);
    try expectTrace(&.{ .term_group, .kill_group, .kill_group, .reap }, &stubborn);
    try testing.expect(escalated.terminated);
    try testing.expect(escalated.escalated);
    try testing.expectEqual(false, stubborn.blocking_reap.?);

    var detached_running: RecordingGroupOperations = .{ .running_probes = 1_000 };
    _ = finalizeGroup(&detached_running, .{
        .leader_exited = false,
        .sweep = false,
        .grace_ms = plan.grace_ms,
        .poll_ms = plan.poll_ms,
    });
    // The detach policy must never signal descendants.
    try expectTrace(&.{ .term_leader, .kill_leader, .reap }, &detached_running);
}

test "maintainer_script.test.system launcher fails closed when output exceeds the limit" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\count=0
        \\while [ "$count" -lt 512 ]; do
        \\  printf '0123456789012345678901234567890123456789012345678901234567890123\n'
        \\  count=$((count + 1))
        \\done
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.limits.maximum_output_bytes = 64;

    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();

    try testing.expectEqualStrings("output_limit_exceeded", @tagName(report.outcome));
    try testing.expectEqual(@as(usize, 64), report.output_bytes);
    try testing.expectEqual(@as(usize, 64), report.output_limit);
    try testing.expect(report.terminated_process_group);
}

/// Runs the script with fd 0, 1, and 2 closed and reports the result through
/// `channel`. It runs in a forked child so the test harness keeps its own
/// standard descriptors, and it never returns to the test runner.
fn reportWithoutStandardStreams(script: *const HostScript, channel: [2]i32) noreturn {
    _ = linux.close(channel[0]);
    for ([_]i32{ 0, 1, 2 }) |fd| _ = linux.close(fd);

    var launcher: SystemLauncher = .{};
    const report = run(
        std.heap.page_allocator,
        script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    ) catch linux.exit(91);

    const code: u8 = switch (report.outcome) {
        .exited => |value| value,
        else => 200,
    };
    writeAllRaw(channel[1], &[_]u8{code});
    writeAllRaw(channel[1], report.stdout);
    writeAllRaw(channel[1], "|");
    writeAllRaw(channel[1], report.stderr);
    _ = linux.close(channel[1]);
    linux.exit(0);
}

fn writeAllRaw(fd: i32, bytes: []const u8) void {
    var written: usize = 0;
    while (written < bytes.len) {
        const rc = linux.write(fd, bytes[written..].ptr, bytes.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => written += rc,
            .INTR => {},
            else => return,
        }
    }
}

test "maintainer_script.test.system launcher installs standard streams the parent had closed" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\printf 'stdin=[%s]\n' "$(cat)"
        \\printf 'diagnostic\n' >&2
        \\exit 7
        \\
    );
    defer script.deinit(testing.allocator);

    const created = createPipe();
    try testing.expectEqual(@as(u32, 0), created.errno);
    var channel = created.fds;
    defer closePipe(&channel);

    const forked = linux.fork();
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(forked));
    const pid: i32 = @intCast(forked);
    if (pid == 0) reportWithoutStandardStreams(&script, channel);
    closeFd(&channel[1]);

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(testing.allocator);
    var buffer: [512]u8 = undefined;
    while (true) {
        const rc = linux.read(channel[0], &buffer, buffer.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => break,
        }
        if (rc == 0) break;
        try payload.appendSlice(testing.allocator, buffer[0..rc]);
    }
    const status = (try reapChild(pid, false)).?;
    try testing.expect(linux.W.IFEXITED(status));
    try testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));

    // The script still saw an empty /dev/null stdin and both captured streams,
    // so the runner's pipes were installed on 0, 1, and 2 with CLOEXEC cleared.
    try testing.expect(payload.items.len > 1);
    try testing.expectEqual(@as(u8, 7), payload.items[0]);
    try testing.expectEqualStrings("stdin=[]\n|diagnostic\n", payload.items[1..]);
}

test "maintainer_script.test.system launcher combines interleaved output when requested" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\printf 'out\n'
        \\printf 'err\n' >&2
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.capture = .combined;

    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();

    try testing.expectEqual(@as(u8, 0), report.outcome.exited);
    try testing.expect(report.succeeded());
    try testing.expectEqualStrings("", report.stdout);
    try testing.expectEqualStrings("", report.stderr);
    try testing.expectEqualStrings("out\nerr\n", report.combined);
    try testing.expectEqualSlices(
        u8,
        &hashBytes("out\nerr\n"),
        &report.evidence.combined_sha256,
    );
}

test "maintainer_script.test.system launcher enters the alternate root before executing" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    const script_path = "var/lib/dpkg/info/demo.postinst";
    try writeExecutableScript(&directory, script_path,
        \\#!/bin/sh
        \\exit 0
        \\
    );
    const root = try absoluteTempPath(testing.allocator, &directory, "");
    defer testing.allocator.free(root);
    const trimmed_root = std.mem.trimEnd(u8, root, "/");

    var launcher: SystemLauncher = .{};
    const identity: Identity = .{
        .package = "demo",
        .version = "1.0-1",
        .architecture = "amd64",
        .kind = .postinst,
        .script_path = script_path,
        .script_sha256 = @splat(0),
    };
    var report = try run(testing.allocator, .{
        .root = trimmed_root,
        .identity = identity,
        .arguments = &.{"configure"},
        .policy = .{ .limits = .{ .timeout_ms = 20_000, .termination_grace_ms = 500 } },
    }, .{ .launcher = launcher.interface() });
    defer report.deinit();

    try testing.expectEqual(Isolation.chroot, report.isolation);
    try testing.expect(report.outcome.spawned());
    switch (report.outcome) {
        // Unprivileged CI cannot enter an alternate root; the denial is exact.
        .setup_failed => |failure| switch (failure.stage) {
            .root_isolation => try testing.expectEqual(
                @intFromEnum(linux.E.PERM),
                failure.errno,
            ),
            // A privileged run does enter the root, where the fixture has no
            // interpreter. Reaching this proves the chroot took effect.
            .execute => try testing.expectEqual(
                @intFromEnum(linux.E.NOENT),
                failure.errno,
            ),
            else => return error.TestUnexpectedResult,
        },
        // A privileged root that does contain an interpreter runs the script.
        .exited => |code| try testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }

    // Positive control: the identical script is executable through the host
    // root, so the alternate-root outcome above is isolation, not a bad fixture.
    var host_script: HostScript = .{
        .absolute = try absoluteTempPath(testing.allocator, &directory, script_path),
        .directories = undefined,
    };
    defer host_script.deinit(testing.allocator);
    host_script.directories = .{std.fs.path.dirname(host_script.absolute[1..]).?};
    var host_report = try run(
        testing.allocator,
        host_script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    );
    defer host_report.deinit();
    try testing.expectEqual(Isolation.host_root, host_report.isolation);
    try testing.expectEqual(@as(u8, 0), host_report.outcome.exited);
}

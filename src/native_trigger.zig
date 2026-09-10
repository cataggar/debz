const std = @import("std");
const maintainer_script = @import("maintainer_script.zig");
const package_database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const authority_path = "var/lib/debz/native-trigger-authority-v1.json";
pub const script_record_path = "var/lib/debz/native-lifecycle-script-v1.json";
pub const queue_lock_path = "var/lib/debz/native-trigger-queue.lock";
pub const operation_record_path = "var/lib/debz/root-operation-v1.json";
pub const namespace_path = "var/lib/debz";
pub const maximum_document_bytes: usize = 1024 * 1024;
pub const maximum_queue_bytes: usize = 16 * 1024 * 1024;
pub const maximum_queue_entries: usize = 4096;
pub const maximum_queue_packages: usize = 4096;

pub const ScriptSource = enum { installed_package, new_package };
pub const FinalMode = enum { exact, derive_from_activations };

pub const Handler = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    source: ScriptSource,
    postinst_sha256: [32]u8,
    declarations_sha256: [32]u8,
};

pub const Caller = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    source: ScriptSource,
    kind: maintainer_script.Kind,
    script_sha256: [32]u8,
};

pub const Authority = struct {
    program_sha256: [32]u8,
    attempt_id: [32]u8,
    initial_state_sha256: [32]u8,
    handlers: []const Handler,
    callers: []const Caller,
    allowed_triggers: []const []const u8,
    maximum_invocations: u32,
    final_mode: FinalMode = .exact,
    base_final_state_sha256: ?[32]u8 = null,
    maximum_activations: u32 = 0,
};

pub const OwnedAuthority = struct {
    authority: Authority,
    parsed: std.json.Parsed(WireAuthority),
    allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedAuthority) void {
        self.allocator.free(self.authority.handlers);
        self.allocator.free(self.authority.callers);
        self.parsed.deinit();
        self.* = undefined;
    }
};

const WireIdentity = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
};

const WireHandler = struct {
    package: WireIdentity,
    source: ScriptSource,
    postinst_sha256: []const u8,
    declarations_sha256: []const u8,
};

const WireCaller = struct {
    package: WireIdentity,
    source: ScriptSource,
    kind: maintainer_script.Kind,
    script_sha256: []const u8,
};

const WireAuthority = struct {
    schema: []const u8,
    program_sha256: []const u8,
    attempt_id: []const u8,
    initial_state_sha256: []const u8,
    handlers: []const WireHandler,
    callers: []const WireCaller,
    allowed_triggers: []const []const u8,
    maximum_invocations: u32,
    final_mode: FinalMode,
    base_final_state_sha256: ?[]const u8,
    maximum_activations: u32,
};

const WireScriptRecord = struct {
    schema: []const u8,
    program_sha256: []const u8,
    step: u32,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    kind: []const u8,
    source: ScriptSource,
    script_sha256: []const u8,
    arguments: []const []const u8,
    outcome: []const u8,
    exit_code: ?u8,
};

pub const ActiveScript = struct {
    program_sha256: [32]u8,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    kind: maintainer_script.Kind,
    source: ScriptSource,
    script_sha256: [32]u8,
};

pub const OwnedActiveScript = struct {
    script: ActiveScript,
    parsed: std.json.Parsed(WireScriptRecord),

    pub fn deinit(self: *OwnedActiveScript) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub fn authorityJson(
    allocator: std.mem.Allocator,
    authority: Authority,
) ![]u8 {
    const handlers = try allocator.alloc(WireHandler, authority.handlers.len);
    defer allocator.free(handlers);
    var handler_digests = try allocator.alloc([2][64]u8, authority.handlers.len);
    defer allocator.free(handler_digests);
    for (authority.handlers, 0..) |handler, index| {
        handler_digests[index][0] = hex(handler.postinst_sha256);
        handler_digests[index][1] = hex(handler.declarations_sha256);
        handlers[index] = .{
            .package = .{
                .name = handler.package,
                .version = handler.version,
                .architecture = handler.architecture,
            },
            .source = handler.source,
            .postinst_sha256 = &handler_digests[index][0],
            .declarations_sha256 = &handler_digests[index][1],
        };
    }
    const callers = try allocator.alloc(WireCaller, authority.callers.len);
    defer allocator.free(callers);
    const caller_digests = try allocator.alloc([64]u8, authority.callers.len);
    defer allocator.free(caller_digests);
    for (authority.callers, 0..) |caller, index| {
        caller_digests[index] = hex(caller.script_sha256);
        callers[index] = .{
            .package = .{
                .name = caller.package,
                .version = caller.version,
                .architecture = caller.architecture,
            },
            .source = caller.source,
            .kind = caller.kind,
            .script_sha256 = &caller_digests[index],
        };
    }
    const program = hex(authority.program_sha256);
    const attempt = hex(authority.attempt_id);
    const initial = hex(authority.initial_state_sha256);
    const base = if (authority.base_final_state_sha256) |digest|
        hex(digest)
    else
        null;
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(
        WireAuthority{
            .schema = "https://debz.dev/schema/native-trigger-authority-v1",
            .program_sha256 = &program,
            .attempt_id = &attempt,
            .initial_state_sha256 = &initial,
            .handlers = handlers,
            .callers = callers,
            .allowed_triggers = authority.allowed_triggers,
            .maximum_invocations = authority.maximum_invocations,
            .final_mode = authority.final_mode,
            .base_final_state_sha256 = if (base) |*digest| digest else null,
            .maximum_activations = authority.maximum_activations,
        },
        .{ .whitespace = .minified },
        &output.writer,
    );
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

pub fn decodeAuthority(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedAuthority {
    if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(
        WireAuthority,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false },
    );
    errdefer parsed.deinit();
    if (!std.mem.eql(
        u8,
        parsed.value.schema,
        "https://debz.dev/schema/native-trigger-authority-v1",
    ) or
        parsed.value.maximum_invocations == 0 or
        parsed.value.maximum_invocations > 4096 or
        (parsed.value.final_mode == .derive_from_activations and
            (parsed.value.base_final_state_sha256 == null or
                parsed.value.maximum_activations == 0 or
                parsed.value.maximum_activations > 4096)) or
        (parsed.value.final_mode == .exact and
            (parsed.value.base_final_state_sha256 != null or
                parsed.value.maximum_activations != 0)) or
        parsed.value.handlers.len > 4096 or
        parsed.value.callers.len > 4096 or
        parsed.value.allowed_triggers.len > 4096)
        return error.InvalidAuthority;
    const handlers = try allocator.alloc(Handler, parsed.value.handlers.len);
    errdefer allocator.free(handlers);
    for (parsed.value.handlers, 0..) |handler, index| {
        handlers[index] = .{
            .package = handler.package.name,
            .version = handler.package.version,
            .architecture = handler.package.architecture,
            .source = handler.source,
            .postinst_sha256 = try parseHex(handler.postinst_sha256),
            .declarations_sha256 = try parseHex(handler.declarations_sha256),
        };
    }
    const callers = try allocator.alloc(Caller, parsed.value.callers.len);
    errdefer allocator.free(callers);
    for (parsed.value.callers, 0..) |caller, index| {
        callers[index] = .{
            .package = caller.package.name,
            .version = caller.package.version,
            .architecture = caller.package.architecture,
            .source = caller.source,
            .kind = caller.kind,
            .script_sha256 = try parseHex(caller.script_sha256),
        };
    }
    for (parsed.value.allowed_triggers) |trigger| {
        if (!package_database.validTriggerName(trigger))
            return error.InvalidAuthority;
    }
    return .{
        .authority = .{
            .program_sha256 = try parseHex(parsed.value.program_sha256),
            .attempt_id = try parseHex(parsed.value.attempt_id),
            .initial_state_sha256 = try parseHex(parsed.value.initial_state_sha256),
            .handlers = handlers,
            .callers = callers,
            .allowed_triggers = parsed.value.allowed_triggers,
            .maximum_invocations = parsed.value.maximum_invocations,
            .final_mode = parsed.value.final_mode,
            .base_final_state_sha256 = if (parsed.value.base_final_state_sha256) |value|
                try parseHex(value)
            else
                null,
            .maximum_activations = parsed.value.maximum_activations,
        },
        .parsed = parsed,
        .allocator = allocator,
    };
}

pub fn decodeActiveScript(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedActiveScript {
    if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(
        WireScriptRecord,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false },
    );
    errdefer parsed.deinit();
    if (!std.mem.eql(
        u8,
        parsed.value.schema,
        "https://debz.dev/schema/native-lifecycle-script-v1",
    ) or
        !std.mem.eql(u8, parsed.value.outcome, "in_flight") or
        parsed.value.exit_code != null)
        return error.InvalidScriptRecord;
    const kind = std.meta.stringToEnum(
        maintainer_script.Kind,
        parsed.value.kind,
    ) orelse return error.InvalidScriptRecord;
    return .{
        .script = .{
            .program_sha256 = try parseHex(parsed.value.program_sha256),
            .package = parsed.value.package,
            .version = parsed.value.version,
            .architecture = parsed.value.architecture,
            .kind = kind,
            .source = parsed.value.source,
            .script_sha256 = try parseHex(parsed.value.script_sha256),
        },
        .parsed = parsed,
    };
}

pub fn callerAuthorized(
    authority: Authority,
    script: ActiveScript,
) bool {
    if (!std.mem.eql(
        u8,
        &authority.program_sha256,
        &script.program_sha256,
    )) return false;
    for (authority.callers) |caller| {
        if (std.mem.eql(u8, caller.package, script.package) and
            std.mem.eql(u8, caller.version, script.version) and
            std.mem.eql(u8, caller.architecture, script.architecture) and
            caller.source == script.source and caller.kind == script.kind and
            std.mem.eql(u8, &caller.script_sha256, &script.script_sha256))
            return true;
    }
    return false;
}

pub fn triggerAuthorized(authority: Authority, trigger: []const u8) bool {
    for (authority.allowed_triggers) |allowed| {
        if (std.mem.eql(u8, allowed, trigger)) return true;
    }
    return false;
}

pub fn stateDigest(model: package_database.Model) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("debz-native-trigger-state-v1\x00");
    for (model.triggers.interests) |interest| {
        hashText(&hash, interest.trigger);
        hashText(&hash, interest.package.name);
        hashText(&hash, interest.package.architecture);
        hash.update(&[_]u8{@intFromEnum(interest.await_mode)});
    }
    hash.update(&[_]u8{0xff});
    for (model.triggers.pending) |pending| {
        hashText(&hash, pending.trigger);
        for (pending.packages) |package| {
            hashText(&hash, package.package.name);
            hashText(&hash, package.package.architecture);
        }
        hash.update(&[_]u8{@intFromBool(pending.noawait)});
    }
    hash.update(&[_]u8{0xfe});
    for (model.packages) |package| {
        if (package.triggers_pending.len == 0 and
            package.triggers_awaited.len == 0)
            continue;
        hashText(&hash, package.name);
        hashText(&hash, package.architecture);
        hash.update(&[_]u8{@intFromEnum(package.status.current)});
        for (package.triggers_pending) |trigger| hashText(&hash, trigger);
        hash.update(&[_]u8{0xfd});
        for (package.triggers_awaited) |name| hashText(&hash, name);
        hash.update(&[_]u8{0xfc});
    }
    return hash.finalResult();
}

pub const Queue = struct {
    entries: std.ArrayList(package_database.PendingTrigger) = .empty,
    arena: std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Queue {
        return .{ .arena = .init(allocator), .allocator = allocator };
    }

    pub fn deinit(self: *Queue) void {
        self.entries.deinit(self.allocator);
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn parse(
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) !Queue {
        if (bytes.len > maximum_queue_bytes) return error.QueueLimit;
        var queue = Queue.init(allocator);
        errdefer queue.deinit();
        const owned = queue.arena.allocator();
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (queue.entries.items.len >= maximum_queue_entries)
                return error.QueueLimit;
            for (line) |byte| {
                if (byte <= 0x20 and byte != ' ' or byte >= 0x7f)
                    return error.InvalidQueue;
            }
            var tokens = std.mem.tokenizeScalar(u8, line, ' ');
            const trigger = tokens.next() orelse return error.InvalidQueue;
            if (!package_database.validTriggerName(trigger))
                return error.InvalidQueue;
            var packages: std.ArrayList(package_database.PendingPackage) = .empty;
            defer packages.deinit(allocator);
            var noawait = false;
            while (tokens.next()) |token| {
                if (std.mem.eql(u8, token, "-")) {
                    if (noawait) return error.InvalidQueue;
                    noawait = true;
                    continue;
                }
                if (packages.items.len >= maximum_queue_packages)
                    return error.QueueLimit;
                const colon = std.mem.indexOfScalar(u8, token, ':');
                const name = if (colon) |at| token[0..at] else token;
                const architecture = if (colon) |at| token[at + 1 ..] else "";
                if (name.len == 0 or
                    std.mem.indexOfScalar(u8, name, '/') != null or
                    (colon != null and architecture.len == 0))
                    return error.InvalidQueue;
                for (packages.items) |package| {
                    if (std.mem.eql(u8, package.package.name, name) and
                        std.mem.eql(
                            u8,
                            package.package.architecture,
                            architecture,
                        ))
                        return error.InvalidQueue;
                }
                try packages.append(allocator, .{
                    .package = .{
                        .name = try owned.dupe(u8, name),
                        .architecture = try owned.dupe(u8, architecture),
                    },
                    .await_mode = .awaited,
                });
            }
            if (packages.items.len == 0 and !noawait)
                return error.InvalidQueue;
            for (queue.entries.items) |entry| {
                if (std.mem.eql(u8, entry.trigger, trigger))
                    return error.InvalidQueue;
            }
            try queue.entries.append(allocator, .{
                .trigger = try owned.dupe(u8, trigger),
                .packages = try owned.dupe(
                    package_database.PendingPackage,
                    packages.items,
                ),
                .noawait = noawait,
            });
        }
        return queue;
    }

    pub fn enqueue(
        self: *Queue,
        trigger: []const u8,
        mode: package_database.AwaitMode,
        package: package_database.Identity,
    ) !void {
        const owned = self.arena.allocator();
        for (self.entries.items) |*entry| {
            if (!std.mem.eql(u8, entry.trigger, trigger)) continue;
            if (mode == .noawait) {
                entry.noawait = true;
                return;
            }
            for (entry.packages) |existing| {
                if (package_database.Identity.eql(existing.package, package))
                    return;
            }
            if (entry.packages.len >= maximum_queue_packages)
                return error.QueueLimit;
            const packages = try owned.alloc(
                package_database.PendingPackage,
                entry.packages.len + 1,
            );
            @memcpy(packages[0..entry.packages.len], entry.packages);
            packages[entry.packages.len] = .{
                .package = .{
                    .name = try owned.dupe(u8, package.name),
                    .architecture = try owned.dupe(u8, package.architecture),
                },
                .await_mode = .awaited,
            };
            entry.packages = packages;
            return;
        }
        if (self.entries.items.len >= maximum_queue_entries)
            return error.QueueLimit;
        const packages = if (mode == .awaited) block: {
            const values = try owned.alloc(package_database.PendingPackage, 1);
            values[0] = .{
                .package = .{
                    .name = try owned.dupe(u8, package.name),
                    .architecture = try owned.dupe(u8, package.architecture),
                },
                .await_mode = .awaited,
            };
            break :block values;
        } else &.{};
        try self.entries.append(self.allocator, .{
            .trigger = try owned.dupe(u8, trigger),
            .packages = packages,
            .noawait = mode == .noawait,
        });
    }

    pub fn serialize(self: Queue, allocator: std.mem.Allocator) ![]u8 {
        return package_database.writePendingTriggers(
            allocator,
            self.entries.items,
        );
    }
};

pub const HelperRequest = struct {
    mode: package_database.AwaitMode,
    trigger: []const u8,
    package: []const u8,
    architecture: []const u8,
};

pub const HelperEnvironment = struct {
    package: []const u8,
    architecture: []const u8,
    admindir: []const u8,
};

pub const maximum_helper_arguments: usize = 3;
pub const maximum_helper_argument_bytes: usize = 4096;

pub fn parseHelperInvocation(
    arguments: []const []const u8,
    environment: HelperEnvironment,
) !HelperRequest {
    if (arguments.len == 0 or arguments.len > maximum_helper_arguments)
        return error.InvalidArguments;
    if (environment.package.len == 0 or environment.architecture.len == 0 or
        !std.mem.eql(u8, environment.admindir, "/var/lib/dpkg"))
        return error.InvalidEnvironment;
    var mode: ?package_database.AwaitMode = null;
    var by_package: ?[]const u8 = null;
    var trigger: ?[]const u8 = null;
    for (arguments) |argument| {
        if (argument.len == 0 or argument.len > maximum_helper_argument_bytes)
            return error.InvalidArguments;
        for (argument) |byte| {
            if (byte < 0x20 or byte == 0x7f) return error.InvalidArguments;
        }
        if (std.mem.eql(u8, argument, "--await")) {
            if (mode != null) return error.InvalidArguments;
            mode = .awaited;
        } else if (std.mem.eql(u8, argument, "--no-await")) {
            if (mode != null) return error.InvalidArguments;
            mode = .noawait;
        } else if (std.mem.startsWith(u8, argument, "--by-package=")) {
            if (by_package != null) return error.InvalidArguments;
            by_package = argument["--by-package=".len..];
            if (by_package.?.len == 0 or
                !std.mem.eql(u8, by_package.?, environment.package))
                return error.InvalidArguments;
        } else if (argument[0] == '-') {
            return error.InvalidArguments;
        } else {
            if (trigger != null) return error.InvalidArguments;
            trigger = argument;
        }
    }
    const selected_trigger = trigger orelse return error.InvalidArguments;
    if (!package_database.validTriggerName(selected_trigger))
        return error.InvalidArguments;
    return .{
        .mode = mode orelse .awaited,
        .trigger = selected_trigger,
        .package = environment.package,
        .architecture = environment.architecture,
    };
}

pub const OperationEvidence = struct {
    state: OperationState,
    phase: OperationPhase,
    attempt_id: [32]u8,
    program_sha256: ?[32]u8,
};

pub const OperationState = enum {
    reserved,
    preflight,
    mutation_pending,
    mutating,
    verifying,
    recovery_required,
    recovering,
    completed,
};

pub const OperationPhase = enum {
    reserved,
    authorization,
    preflight,
    mutation,
    script,
    trigger,
    database,
    verification,
    provenance,
};

const WireOperationEvidence = struct {
    schema: []const u8,
    attempt_id: []const u8,
    state: OperationState,
    phase: OperationPhase,
    program_sha256: ?[]const u8,
};

fn decodeOperationEvidence(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OperationEvidence {
    if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(
        WireOperationEvidence,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    if (!std.mem.eql(
        u8,
        parsed.value.schema,
        "https://debz.dev/schema/root-operation-record-v1",
    )) return error.InvalidOperationRecord;
    return .{
        .state = parsed.value.state,
        .phase = parsed.value.phase,
        .attempt_id = try parseHex(parsed.value.attempt_id),
        .program_sha256 = if (parsed.value.program_sha256) |value|
            try parseHex(value)
        else
            null,
    };
}

pub fn authorizeInvocation(
    operation: ?OperationEvidence,
    authority: ?Authority,
    script: ?ActiveScript,
    request: HelperRequest,
) !void {
    const active_operation = operation orelse return error.NoActiveOperation;
    const active_authority = authority orelse return error.NoTriggerAuthority;
    const active_script = script orelse return error.NoActiveScript;
    if (active_operation.state != .mutating or
        active_operation.phase != .script or
        active_operation.program_sha256 == null or
        !std.mem.eql(
            u8,
            &active_operation.program_sha256.?,
            &active_authority.program_sha256,
        ) or
        !std.mem.eql(
            u8,
            &active_operation.attempt_id,
            &active_authority.attempt_id,
        ) or
        !callerAuthorized(active_authority, active_script) or
        !triggerAuthorized(active_authority, request.trigger) or
        !std.mem.eql(u8, request.package, active_script.package) or
        !std.mem.eql(
            u8,
            request.architecture,
            active_script.architecture,
        ))
        return error.UnauthorizedActivation;
}

pub fn runHelper(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: root_fs.Root,
    request: HelperRequest,
) !void {
    const authority_bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(authority_path),
        maximum_document_bytes,
    );
    defer allocator.free(authority_bytes);
    var authority = try decodeAuthority(allocator, authority_bytes);
    defer authority.deinit();
    const script_bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(script_record_path),
        maximum_document_bytes,
    );
    defer allocator.free(script_bytes);
    var script = try decodeActiveScript(allocator, script_bytes);
    defer script.deinit();
    const operation_bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(operation_record_path),
        maximum_document_bytes,
    );
    defer allocator.free(operation_bytes);
    const operation = try decodeOperationEvidence(allocator, operation_bytes);
    try authorizeInvocation(
        operation,
        authority.authority,
        script.script,
        request,
    );

    var lock_file = root.openRegularFile(
        try root_fs.Path.init(queue_lock_path),
    ) catch |err| switch (err) {
        error.FileNotFound => block: {
            var created = false;
            if (root.writeNewFile(
                try root_fs.Path.init(queue_lock_path),
                "",
                .{},
                true,
            )) |_| {
                created = true;
            } else |create_err| switch (create_err) {
                error.PathAlreadyExists => {},
                else => return create_err,
            }
            if (created)
                try root.syncDirectory(
                    try root_fs.Path.init(namespace_path),
                );
            break :block try root.openRegularFile(
                try root_fs.Path.init(queue_lock_path),
            );
        },
        else => return err,
    };
    defer lock_file.close(io);
    if (@import("builtin").os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    if (linux.errno(linux.flock(lock_file.handle, 2)) != .SUCCESS)
        return error.QueueLockFailed;
    defer _ = linux.flock(lock_file.handle, 8);

    const queue_path = try root_fs.Path.init(
        package_database.database_directory ++ "/" ++
            package_database.triggers_unincorp_path,
    );
    const current = root.readFileAlloc(
        allocator,
        queue_path,
        maximum_queue_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => try allocator.dupe(u8, ""),
        else => return err,
    };
    defer allocator.free(current);
    var queue = try Queue.parse(allocator, current);
    defer queue.deinit();
    try queue.enqueue(request.trigger, request.mode, .{
        .name = request.package,
        .architecture = "",
    });
    const bytes = try queue.serialize(allocator);
    defer allocator.free(bytes);
    try root.publishFile(queue_path, bytes, .{ .durable = true });
}

fn hex(bytes: [32]u8) [64]u8 {
    const alphabet = "0123456789abcdef";
    var output: [64]u8 = undefined;
    for (bytes, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

fn parseHex(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidDigest;
    var output: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, value) catch return error.InvalidDigest;
    return output;
}

fn hashText(hash: *Sha256, text: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, text.len, .little);
    hash.update(&length);
    hash.update(text);
}

test "native_trigger queue preserves activation order and noawait marker" {
    var queue = try Queue.parse(
        std.testing.allocator,
        "debz-a source -\ndebz-b -\n",
    );
    defer queue.deinit();
    try queue.enqueue(
        "debz-a",
        .awaited,
        .{ .name = "other", .architecture = "" },
    );
    const bytes = try queue.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings(
        "debz-a source other -\ndebz-b -\n",
        bytes,
    );
}

test "native_trigger authority binds exact dynamic caller evidence" {
    const handlers = [_]Handler{.{
        .package = "receiver",
        .version = "1",
        .architecture = "amd64",
        .source = .installed_package,
        .postinst_sha256 = @splat(0x11),
        .declarations_sha256 = @splat(0x22),
    }};
    const callers = [_]Caller{.{
        .package = "receiver",
        .version = "1",
        .architecture = "amd64",
        .source = .installed_package,
        .kind = .postinst,
        .script_sha256 = @splat(0x11),
    }};
    const authority: Authority = .{
        .program_sha256 = @splat(0x33),
        .attempt_id = @splat(0x44),
        .initial_state_sha256 = @splat(0x55),
        .handlers = &handlers,
        .callers = &callers,
        .allowed_triggers = &.{"debz-trigger"},
        .maximum_invocations = 8,
    };
    const bytes = try authorityJson(std.testing.allocator, authority);
    defer std.testing.allocator.free(bytes);
    var decoded = try decodeAuthority(std.testing.allocator, bytes);
    defer decoded.deinit();
    try std.testing.expect(callerAuthorized(decoded.authority, .{
        .program_sha256 = @splat(0x33),
        .package = "receiver",
        .version = "1",
        .architecture = "amd64",
        .kind = .postinst,
        .source = .installed_package,
        .script_sha256 = @splat(0x11),
    }));
    try std.testing.expect(triggerAuthorized(
        decoded.authority,
        "debz-trigger",
    ));
    var wrong_program: ActiveScript = .{
        .program_sha256 = @splat(0x34),
        .package = "receiver",
        .version = "1",
        .architecture = "amd64",
        .kind = .postinst,
        .source = .installed_package,
        .script_sha256 = @splat(0x11),
    };
    try std.testing.expect(!callerAuthorized(decoded.authority, wrong_program));
    wrong_program.program_sha256 = @splat(0x33);
    wrong_program.version = "2";
    try std.testing.expect(!callerAuthorized(decoded.authority, wrong_program));
}

test "native_trigger malformed queue controls fail closed" {
    try std.testing.expectError(
        error.InvalidQueue,
        Queue.parse(std.testing.allocator, "invalid\x00trigger -\n"),
    );
    try std.testing.expectError(
        error.InvalidQueue,
        Queue.parse(std.testing.allocator, "trigger - -\n"),
    );
}

test "native_trigger helper argv is narrow and bounded" {
    const environment: HelperEnvironment = .{
        .package = "source",
        .architecture = "amd64",
        .admindir = "/var/lib/dpkg",
    };
    const request = try parseHelperInvocation(
        &.{ "--by-package=source", "--no-await", "debz-trigger" },
        environment,
    );
    try std.testing.expectEqual(package_database.AwaitMode.noawait, request.mode);
    try std.testing.expectEqualStrings("debz-trigger", request.trigger);
    try std.testing.expectError(
        error.InvalidArguments,
        parseHelperInvocation(
            &.{ "--await", "--no-await", "debz-trigger" },
            environment,
        ),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseHelperInvocation(
            &.{ "--by-package=other", "debz-trigger" },
            environment,
        ),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseHelperInvocation(
            &.{ "--await", "--by-package=source", "debz-trigger", "extra" },
            environment,
        ),
    );
    var oversized: [maximum_helper_argument_bytes + 1]u8 = @splat('a');
    try std.testing.expectError(
        error.InvalidArguments,
        parseHelperInvocation(&.{&oversized}, environment),
    );
    var bad_environment = environment;
    bad_environment.admindir = "/host/var/lib/dpkg";
    try std.testing.expectError(
        error.InvalidEnvironment,
        parseHelperInvocation(&.{"debz-trigger"}, bad_environment),
    );
}

test "native_trigger invocation authority refuses absent stale and mismatched evidence" {
    const handlers = [_]Handler{.{
        .package = "receiver",
        .version = "1",
        .architecture = "amd64",
        .source = .installed_package,
        .postinst_sha256 = @splat(0x11),
        .declarations_sha256 = @splat(0x22),
    }};
    const callers = [_]Caller{.{
        .package = "receiver",
        .version = "1",
        .architecture = "amd64",
        .source = .installed_package,
        .kind = .postinst,
        .script_sha256 = @splat(0x11),
    }};
    const authority: Authority = .{
        .program_sha256 = @splat(0x33),
        .attempt_id = @splat(0x44),
        .initial_state_sha256 = @splat(0x55),
        .handlers = &handlers,
        .callers = &callers,
        .allowed_triggers = &.{"debz-trigger"},
        .maximum_invocations = 8,
    };
    const script: ActiveScript = .{
        .program_sha256 = @splat(0x33),
        .package = "receiver",
        .version = "1",
        .architecture = "amd64",
        .kind = .postinst,
        .source = .installed_package,
        .script_sha256 = @splat(0x11),
    };
    const request: HelperRequest = .{
        .mode = .noawait,
        .trigger = "debz-trigger",
        .package = "receiver",
        .architecture = "amd64",
    };
    const operation: OperationEvidence = .{
        .state = .mutating,
        .phase = .script,
        .attempt_id = @splat(0x44),
        .program_sha256 = @splat(0x33),
    };
    try authorizeInvocation(operation, authority, script, request);
    try std.testing.expectError(
        error.NoActiveOperation,
        authorizeInvocation(null, authority, script, request),
    );
    try std.testing.expectError(
        error.NoTriggerAuthority,
        authorizeInvocation(operation, null, script, request),
    );
    try std.testing.expectError(
        error.NoActiveScript,
        authorizeInvocation(operation, authority, null, request),
    );
    var stale_operation = operation;
    stale_operation.attempt_id[0] ^= 1;
    try std.testing.expectError(
        error.UnauthorizedActivation,
        authorizeInvocation(stale_operation, authority, script, request),
    );
    var stale_script = script;
    stale_script.script_sha256[0] ^= 1;
    try std.testing.expectError(
        error.UnauthorizedActivation,
        authorizeInvocation(operation, authority, stale_script, request),
    );
    var mismatched_request = request;
    mismatched_request.package = "other";
    try std.testing.expectError(
        error.UnauthorizedActivation,
        authorizeInvocation(operation, authority, script, mismatched_request),
    );
}

test "native_trigger queue entry bound fails before allocation growth" {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    for (0..maximum_queue_entries + 1) |index| {
        const line = try std.fmt.allocPrint(
            std.testing.allocator,
            "trigger-{} -\n",
            .{index},
        );
        defer std.testing.allocator.free(line);
        try bytes.appendSlice(std.testing.allocator, line);
    }
    try std.testing.expectError(
        error.QueueLimit,
        Queue.parse(std.testing.allocator, bytes.items),
    );
}

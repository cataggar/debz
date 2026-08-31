const std = @import("std");
const api = @import("repository_api.zig");

pub const schema_id = "https://debz.dev/schema/repository-add-state-v1";
pub const schema_version: u32 = 1;
pub const maximum_document_bytes: usize = api.maximum_document_bytes;
pub const maximum_files: usize = 4096;

pub const Phase = enum {
    initialized,
    acquired,
    validated,
    preflight_authenticated,
    planned,
    locked,
    installed,
    imported,
    refreshed,
    complete,
    failed,
};

pub const FileEvidence = struct {
    logical_path: []const u8,
    sha256: [32]u8,
    size: u64,
};

pub const Descriptor = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    sha256: [32]u8,
    size: u64,
    effective_url: []const u8,
    trust_mode: api.TrustMode,
};

pub const State = struct {
    root: []const u8,
    architecture: []const u8,
    no_refresh: bool,
    phase: Phase,
    descriptor: ?Descriptor = null,
    managed_files: []const FileEvidence = &.{},
    installed: bool = false,
    refreshed: bool = false,
    exact_lock_path: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
    manifest_path: ?[]const u8 = null,
    diagnostic_id: ?api.DiagnosticId = null,
    diagnostic: []const u8 = "",
    digest_sha256: [32]u8 = @splat(0),

    pub fn canonicalJson(self: State, allocator: std.mem.Allocator) ![]u8 {
        try validate(self);
        if (!std.mem.eql(u8, &self.digest_sha256, &digestPayload(self)))
            return error.DigestMismatch;
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        const bytes = try output.toOwnedSlice();
        if (bytes.len > maximum_document_bytes) {
            allocator.free(bytes);
            return error.DocumentTooLarge;
        }
        return bytes;
    }
};

pub const OwnedState = struct {
    state: State,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedState) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn create(allocator: std.mem.Allocator, input: State) !OwnedState {
    try validate(input);
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var output = input;
    output.root = try owned.dupe(u8, input.root);
    output.architecture = try owned.dupe(u8, input.architecture);
    output.diagnostic = try owned.dupe(u8, input.diagnostic);
    output.exact_lock_path = try dupeOptional(owned, input.exact_lock_path);
    output.provenance_path = try dupeOptional(owned, input.provenance_path);
    output.manifest_path = try dupeOptional(owned, input.manifest_path);
    if (input.descriptor) |descriptor| output.descriptor = .{
        .package = try owned.dupe(u8, descriptor.package),
        .version = try owned.dupe(u8, descriptor.version),
        .architecture = try owned.dupe(u8, descriptor.architecture),
        .sha256 = descriptor.sha256,
        .size = descriptor.size,
        .effective_url = try owned.dupe(u8, descriptor.effective_url),
        .trust_mode = descriptor.trust_mode,
    };
    const files = try owned.alloc(FileEvidence, input.managed_files.len);
    for (input.managed_files, 0..) |file, index| {
        files[index] = file;
        files[index].logical_path = try owned.dupe(u8, file.logical_path);
    }
    output.managed_files = files;
    output.digest_sha256 = digestPayload(output);
    return .{ .state = output, .arena = arena, .backing_allocator = allocator };
}

const WireDescriptor = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    sha256: []const u8,
    size: u64,
    effective_url: []const u8,
    trust_mode: api.TrustMode,
};

const WireFile = struct {
    logical_path: []const u8,
    sha256: []const u8,
    size: u64,
};

const WireState = struct {
    schema: []const u8,
    version: u32,
    root: []const u8,
    architecture: []const u8,
    no_refresh: bool,
    phase: Phase,
    descriptor: ?WireDescriptor,
    managed_files: []const WireFile,
    installed: bool,
    refreshed: bool,
    exact_lock_path: ?[]const u8,
    provenance_path: ?[]const u8,
    manifest_path: ?[]const u8,
    diagnostic_id: ?api.DiagnosticId,
    diagnostic: []const u8,
    digest_sha256: []const u8,
};

pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !OwnedState {
    if (maximum_bytes == 0 or maximum_bytes > maximum_document_bytes or
        source.len > maximum_bytes)
        return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(WireState, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    }) catch return error.InvalidDocument;
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, schema_id) or wire.version != schema_version)
        return error.UnsupportedSchema;
    if (wire.managed_files.len > maximum_files) return error.TooManyFiles;
    var digest: [32]u8 = undefined;
    try parseHex(&digest, wire.digest_sha256);
    var descriptor: ?Descriptor = null;
    if (wire.descriptor) |value| {
        var sha256: [32]u8 = undefined;
        try parseHex(&sha256, value.sha256);
        descriptor = .{
            .package = value.package,
            .version = value.version,
            .architecture = value.architecture,
            .sha256 = sha256,
            .size = value.size,
            .effective_url = value.effective_url,
            .trust_mode = value.trust_mode,
        };
    }
    const files = try allocator.alloc(FileEvidence, wire.managed_files.len);
    defer allocator.free(files);
    for (wire.managed_files, 0..) |file, index| {
        var sha256: [32]u8 = undefined;
        try parseHex(&sha256, file.sha256);
        files[index] = .{
            .logical_path = file.logical_path,
            .sha256 = sha256,
            .size = file.size,
        };
    }
    const decoded_state: State = .{
        .root = wire.root,
        .architecture = wire.architecture,
        .no_refresh = wire.no_refresh,
        .phase = wire.phase,
        .descriptor = descriptor,
        .managed_files = files,
        .installed = wire.installed,
        .refreshed = wire.refreshed,
        .exact_lock_path = wire.exact_lock_path,
        .provenance_path = wire.provenance_path,
        .manifest_path = wire.manifest_path,
        .diagnostic_id = wire.diagnostic_id,
        .diagnostic = wire.diagnostic,
    };
    const calculated_digest = digestPayload(decoded_state);
    if (!std.mem.eql(u8, &calculated_digest, &digest))
        return error.DigestMismatch;
    var owned = try create(allocator, decoded_state);
    errdefer owned.deinit();
    const canonical = try owned.state.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return owned;
}

pub const Store = struct {
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    write_hooks: WriteHooks = .{},

    pub fn init(io: std.Io, dir: std.Io.Dir, name: []const u8) !Store {
        if (!safeLeaf(name)) return error.InvalidPath;
        return .{ .io = io, .dir = dir, .name = name };
    }

    pub fn read(
        self: Store,
        allocator: std.mem.Allocator,
        maximum_bytes: usize,
    ) !OwnedState {
        var file = try self.dir.openFile(self.io, self.name, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const source = try reader.interface.allocRemaining(
            allocator,
            .limited(maximum_bytes),
        );
        defer allocator.free(source);
        return decode(allocator, source, maximum_bytes);
    }

    pub fn writeAtomic(
        self: Store,
        allocator: std.mem.Allocator,
        state: State,
        maximum_bytes: usize,
    ) !void {
        if (maximum_bytes == 0 or maximum_bytes > maximum_document_bytes)
            return error.DocumentTooLarge;
        try self.write_hooks.run(.before_stage);
        const bytes = try state.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_bytes) return error.DocumentTooLarge;
        const stage = ".repo-add-state-v1.tmp";
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
        try self.write_hooks.run(.after_rename);
        switch (@import("builtin").os.tag) {
            .linux => if (std.posix.errno(std.os.linux.fsync(self.dir.handle)) != .SUCCESS)
                return error.Unexpected,
            else => {},
        }
    }
};

pub const WriteBoundary = enum {
    before_stage,
    after_rename,
};

pub const WriteHooks = struct {
    context: ?*anyopaque = null,
    runFn: ?*const fn (?*anyopaque, WriteBoundary) anyerror!void = null,

    fn run(self: WriteHooks, boundary: WriteBoundary) !void {
        if (self.runFn) |runFn| try runFn(self.context, boundary);
    }
};

fn validate(state: State) !void {
    if (!validPath(state.root) or !validIdentity(state.architecture))
        return error.InvalidIdentity;
    if (state.managed_files.len > maximum_files) return error.TooManyFiles;
    if (state.installed and state.descriptor == null) return error.InvalidState;
    if (state.refreshed and !state.installed) return error.InvalidState;
    if ((state.diagnostic_id == null) != (state.diagnostic.len == 0))
        return error.InvalidState;
    switch (state.phase) {
        .initialized, .acquired => {
            if (state.descriptor != null or state.managed_files.len != 0 or
                state.installed or state.refreshed or
                state.exact_lock_path != null or state.provenance_path != null or
                state.manifest_path != null)
                return error.InvalidState;
        },
        .validated, .preflight_authenticated, .planned => {
            if (state.descriptor == null or state.managed_files.len == 0 or
                state.installed or state.refreshed or
                state.exact_lock_path != null or state.provenance_path != null or
                state.manifest_path != null)
                return error.InvalidState;
        },
        .locked => {
            if (state.descriptor == null or state.managed_files.len == 0 or
                state.installed or state.refreshed or
                state.exact_lock_path == null or state.provenance_path != null or
                state.manifest_path != null)
                return error.InvalidState;
        },
        .installed => {
            if (state.descriptor == null or state.managed_files.len == 0 or
                !state.installed or state.refreshed or
                state.exact_lock_path == null or state.manifest_path != null or
                (state.diagnostic_id == null and state.provenance_path == null))
                return error.InvalidState;
        },
        .imported => {
            if (state.descriptor == null or state.managed_files.len == 0 or
                !state.installed or state.refreshed or
                state.exact_lock_path == null or state.provenance_path == null or
                state.manifest_path == null)
                return error.InvalidState;
        },
        .refreshed => {
            if (state.descriptor == null or state.managed_files.len == 0 or
                !state.installed or !state.refreshed or
                state.exact_lock_path == null or state.provenance_path == null or
                state.manifest_path == null)
                return error.InvalidState;
        },
        .complete => {
            if (state.descriptor == null or state.managed_files.len == 0 or
                !state.installed or
                state.exact_lock_path == null or state.provenance_path == null or
                state.manifest_path == null)
                return error.InvalidState;
        },
        .failed => if (state.diagnostic_id == null) return error.InvalidState,
    }
    if (state.descriptor) |descriptor| {
        if (!validIdentity(descriptor.package) or
            !validIdentity(descriptor.version) or
            !validIdentity(descriptor.architecture) or
            descriptor.size == 0 or
            descriptor.effective_url.len == 0)
            return error.InvalidIdentity;
        const uri = std.Uri.parse(descriptor.effective_url) catch return error.InvalidIdentity;
        if (uri.user != null or uri.password != null) return error.InvalidIdentity;
    }
    for (state.managed_files, 0..) |file, index| {
        if (!validPath(file.logical_path)) return error.InvalidPath;
        for (state.managed_files[0..index]) |previous| {
            if (std.mem.eql(u8, previous.logical_path, file.logical_path))
                return error.DuplicateFile;
        }
    }
    inline for (.{
        state.exact_lock_path,
        state.provenance_path,
        state.manifest_path,
    }) |path| if (path) |value| {
        if (!validPath(value)) return error.InvalidPath;
    };
}

fn dupeOptional(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) std.mem.Allocator.Error!?[]const u8 {
    return if (value) |bytes| try allocator.dupe(u8, bytes) else null;
}

fn digestPayload(state: State) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(state, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeDocument(state: State, writer: *std.Io.Writer) !void {
    try writePayload(state, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHex(writer, &state.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(state: State, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, schema_id);
    try writer.print(",\"version\":{},\"root\":", .{schema_version});
    try writeString(writer, state.root);
    try writer.writeAll(",\"architecture\":");
    try writeString(writer, state.architecture);
    try writer.print(",\"no_refresh\":{},\"phase\":", .{state.no_refresh});
    try writeString(writer, @tagName(state.phase));
    try writer.writeAll(",\"descriptor\":");
    if (state.descriptor) |descriptor| {
        try writer.writeAll("{\"package\":");
        try writeString(writer, descriptor.package);
        try writer.writeAll(",\"version\":");
        try writeString(writer, descriptor.version);
        try writer.writeAll(",\"architecture\":");
        try writeString(writer, descriptor.architecture);
        try writer.writeAll(",\"sha256\":");
        try writeHex(writer, &descriptor.sha256);
        try writer.print(",\"size\":{},\"effective_url\":", .{descriptor.size});
        try writeString(writer, descriptor.effective_url);
        try writer.writeAll(",\"trust_mode\":");
        try writeString(writer, @tagName(descriptor.trust_mode));
        try writer.writeByte('}');
    } else try writer.writeAll("null");
    try writer.writeAll(",\"managed_files\":[");
    for (state.managed_files, 0..) |file, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"logical_path\":");
        try writeString(writer, file.logical_path);
        try writer.writeAll(",\"sha256\":");
        try writeHex(writer, &file.sha256);
        try writer.print(",\"size\":{}}}", .{file.size});
    }
    try writer.print("],\"installed\":{},\"refreshed\":{},\"exact_lock_path\":", .{
        state.installed,
        state.refreshed,
    });
    try writeOptionalString(writer, state.exact_lock_path);
    try writer.writeAll(",\"provenance_path\":");
    try writeOptionalString(writer, state.provenance_path);
    try writer.writeAll(",\"manifest_path\":");
    try writeOptionalString(writer, state.manifest_path);
    try writer.writeAll(",\"diagnostic_id\":");
    if (state.diagnostic_id) |id| try writeString(writer, @tagName(id)) else try writer.writeAll("null");
    try writer.writeAll(",\"diagnostic\":");
    try writeString(writer, state.diagnostic);
    try writer.writeByte('}');
}

fn parseHex(output: []u8, value: []const u8) !void {
    if (value.len != output.len * 2) return error.InvalidDigest;
    for (output, 0..) |*byte, index| {
        byte.* = (@as(u8, try nibble(value[index * 2])) << 4) |
            try nibble(value[index * 2 + 1]);
    }
}

fn nibble(value: u8) !u4 {
    return switch (value) {
        '0'...'9' => @intCast(value - '0'),
        'a'...'f' => @intCast(value - 'a' + 10),
        else => error.InvalidDigest,
    };
}

fn validPath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/' or
        std.mem.indexOfScalar(u8, path, 0) != null or
        std.mem.indexOfScalar(u8, path, '\\') != null)
        return false;
    if (path.len == 1) return true;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return false;
    }
    return true;
}

fn validIdentity(value: []const u8) bool {
    if (value.len == 0 or value.len > 4096 or std.mem.indexOfScalar(u8, value, 0) != null)
        return false;
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

fn safeLeaf(name: []const u8) bool {
    return name.len != 0 and
        !std.mem.eql(u8, name, ".") and
        !std.mem.eql(u8, name, "..") and
        std.mem.indexOfScalar(u8, name, '/') == null and
        std.mem.indexOfScalar(u8, name, '\\') == null and
        std.mem.indexOfScalar(u8, name, 0) == null;
}

fn writeOptionalString(writer: *std.Io.Writer, value: ?[]const u8) !void {
    if (value) |bytes| try writeString(writer, bytes) else try writer.writeAll("null");
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

test "repository state round trips canonically and detects tampering" {
    const files = [_]FileEvidence{.{
        .logical_path = "/etc" ++ "/apt/sources.list.d/example.list",
        .sha256 = @splat(2),
        .size = 87,
    }};
    var state = try create(std.testing.allocator, .{
        .root = "/target",
        .architecture = "amd64",
        .no_refresh = false,
        .phase = .installed,
        .descriptor = .{
            .package = "packages-example-prod",
            .version = "1",
            .architecture = "amd64",
            .sha256 = @splat(1),
            .size = 4096,
            .effective_url = "https://packages.example.test/config.deb?REDACTED",
            .trust_mode = .verified_https,
        },
        .managed_files = &files,
        .installed = true,
        .exact_lock_path = "/var/lib/debz/repository/exact-lock-v2.json",
        .provenance_path = "/var/lib/debz/repository/transaction-result-v2.json",
    });
    defer state.deinit();
    const json = try state.state.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    var decoded = try decode(std.testing.allocator, json, maximum_document_bytes);
    defer decoded.deinit();
    try std.testing.expectEqualStrings(
        state.state.descriptor.?.package,
        decoded.state.descriptor.?.package,
    );
    const changed = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        json,
        "\"installed\":true",
        "\"installed\":false",
    );
    defer std.testing.allocator.free(changed);
    try std.testing.expectError(
        error.DigestMismatch,
        decode(std.testing.allocator, changed, maximum_document_bytes),
    );
}

test "repository state preserves installed-but-refresh-failed evidence" {
    const files = [_]FileEvidence{.{
        .logical_path = "/etc" ++ "/apt/sources.list.d/microsoft-prod.list",
        .sha256 = @splat(0x44),
        .size = 128,
    }};
    var state = try create(std.testing.allocator, .{
        .root = "/target",
        .architecture = "amd64",
        .no_refresh = false,
        .phase = .imported,
        .descriptor = .{
            .package = "packages-microsoft-prod",
            .version = "1.1",
            .architecture = "all",
            .sha256 = @splat(0x55),
            .size = 2048,
            .effective_url = "https://packages.microsoft.test/config.deb",
            .trust_mode = .verified_https,
        },
        .managed_files = &files,
        .installed = true,
        .refreshed = false,
        .exact_lock_path = "/var/lib/debz/repository/exact-lock-v2.json",
        .provenance_path = "/var/lib/debz/repository/transaction-result-v2.json",
        .manifest_path = "/var/lib/debz/repository/apt-config-snapshot-v1.json",
        .diagnostic_id = .refresh_failed,
        .diagnostic = "authenticated refresh failed",
    });
    defer state.deinit();
    const json = try state.state.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    var decoded = try decode(std.testing.allocator, json, maximum_document_bytes);
    defer decoded.deinit();
    try std.testing.expect(decoded.state.installed);
    try std.testing.expect(!decoded.state.refreshed);
    try std.testing.expectEqual(api.DiagnosticId.refresh_failed, decoded.state.diagnostic_id.?);
}

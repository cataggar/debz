const std = @import("std");
const native_diversion = @import("native_diversion.zig");
const native_diversion_cache = @import("native_diversion_cache.zig");
const native_recovery = @import("native_recovery.zig");
const root_fs = @import("root_fs.zig");
const root_mutation = @import("root_mutation.zig");

const Digest = native_recovery.Digest;
const schema_name = "https://debz.dev/schema/native-unpack-diversion-v1";
pub const maximum_document_bytes = 128 * 1024 * 1024;
const json_options: std.json.Stringify.Options = .{ .whitespace = .minified, .emit_null_optional_fields = false };

pub const Backup = struct {
    path: []const u8,
    logical_path: []const u8,
    kind: enum { regular, symlink },
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    device: u64,
    inode: u64,
    modified_nanoseconds: i128,
    backup_modified_nanoseconds: i128,
    content_sha256: ?Digest = null,
    link_target: ?[]const u8 = null,

    pub fn backupPath(self: Backup, buffer: []u8) ![]const u8 {
        const path = try std.fmt.bufPrint(buffer, "{s}.dpkg-tmp", .{self.path});
        _ = try root_fs.Path.initPackage(path);
        return path;
    }
};

fn validateBackups(allocator: std.mem.Allocator, backups: []const Backup) !void {
    if (backups.len > native_recovery.maximum_managed_paths)
        return error.InvalidUnpackBackup;
    var previous: ?[]const u8 = null;
    var paths: std.StringHashMapUnmanaged(void) = .empty;
    defer paths.deinit(allocator);
    var identities: std.AutoHashMapUnmanaged(u128, Backup) = .empty;
    defer identities.deinit(allocator);
    for (backups) |backup| {
        _ = root_fs.Path.initPackage(backup.path) catch return error.InvalidUnpackBackup;
        _ = root_fs.Path.initPackage(backup.logical_path) catch return error.InvalidUnpackBackup;
        var path_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        _ = backup.backupPath(&path_buffer) catch return error.InvalidUnpackBackup;
        if (previous) |path| {
            if (!std.mem.lessThan(u8, path, backup.path)) return error.InvalidUnpackBackup;
        }
        previous = backup.path;
        try paths.put(allocator, backup.path, {});
        if (backup.mode > 0o7777 or backup.inode == 0 or
            backup.modified_nanoseconds < root_mutation.minimum_timestamp_nanoseconds or
            backup.modified_nanoseconds > root_mutation.maximum_timestamp_nanoseconds or
            backup.backup_modified_nanoseconds < root_mutation.minimum_timestamp_nanoseconds or
            backup.backup_modified_nanoseconds > root_mutation.maximum_timestamp_nanoseconds)
            return error.InvalidUnpackBackup;
        switch (backup.kind) {
            .regular => {
                const digest = backup.content_sha256 orelse return error.InvalidUnpackBackup;
                for (digest) |byte| if (!(byte >= '0' and byte <= '9') and !(byte >= 'a' and byte <= 'f'))
                    return error.InvalidUnpackBackup;
                if (backup.link_target != null or backup.backup_modified_nanoseconds != backup.modified_nanoseconds)
                    return error.InvalidUnpackBackup;
            },
            .symlink => {
                const target = backup.link_target orelse return error.InvalidUnpackBackup;
                if (backup.content_sha256 != null or backup.mode != 0o777 or
                    target.len == 0 or target.len > root_fs.maximum_link_target_bytes or backup.size != target.len)
                    return error.InvalidUnpackBackup;
                for (target) |byte| if (byte < 0x20 or byte == 0x7f)
                    return error.InvalidUnpackBackup;
            },
        }
        const identity = try identities.getOrPut(allocator, (@as(u128, backup.device) << 64) | backup.inode);
        if (identity.found_existing) {
            const before = identity.value_ptr.*;
            if (backup.kind != before.kind or backup.mode != before.mode or backup.uid != before.uid or backup.gid != before.gid or
                backup.size != before.size or backup.modified_nanoseconds != before.modified_nanoseconds or
                !std.meta.eql(backup.content_sha256, before.content_sha256) or
                !std.mem.eql(u8, backup.link_target orelse "", before.link_target orelse ""))
                return error.InvalidUnpackBackup;
        } else identity.value_ptr.* = backup;
    }
    for (backups) |backup| {
        var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        if (paths.contains(try backup.backupPath(&buffer)))
            return error.InvalidUnpackBackup;
    }
}

const Document = struct {
    schema: []const u8 = schema_name,
    version: u32 = 1,
    intent_sha256: Digest,
    program_step: u32,
    cache_json: []const u8,
    backups: ?[]const Backup = null,
    deferred_removals: ?bool = null,
    digest_sha256: Digest = @splat('0'),
};

pub const Decoded = struct {
    cache: native_diversion.CachedRecords,
    digest_sha256: Digest,
    backups: ?[]const Backup,
    deferred_removals: bool,
    parsed: std.json.Parsed(Document),

    pub fn deinit(self: *Decoded) void {
        self.cache.deinit();
        self.parsed.deinit();
        self.* = undefined;
    }
};

fn documentDigest(document: Document) Digest {
    var payload = document;
    payload.digest_sha256 = @splat('0');
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-unpack-diversion-v1\x00") catch unreachable;
    std.json.Stringify.value(payload, json_options, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return native_recovery.hexDigest(sink.hasher.finalResult());
}

pub fn encode(
    allocator: std.mem.Allocator,
    cache: native_diversion.CachedRecords,
    intent_sha256: Digest,
    program_step: u32,
) ![]u8 {
    return encodeWithBackups(allocator, cache, intent_sha256, program_step, null);
}

pub fn encodeWithBackups(
    allocator: std.mem.Allocator,
    cache: native_diversion.CachedRecords,
    intent_sha256: Digest,
    program_step: u32,
    backups: ?[]const Backup,
) ![]u8 {
    return encodeInputs(allocator, cache, intent_sha256, program_step, backups, null);
}

pub fn encodeWithDeferredRemovals(
    allocator: std.mem.Allocator,
    cache: native_diversion.CachedRecords,
    intent_sha256: Digest,
    program_step: u32,
    backups: []const Backup,
) ![]u8 {
    return encodeInputs(allocator, cache, intent_sha256, program_step, backups, true);
}

fn encodeInputs(
    allocator: std.mem.Allocator,
    cache: native_diversion.CachedRecords,
    intent_sha256: Digest,
    program_step: u32,
    backups: ?[]const Backup,
    deferred_removals: ?bool,
) ![]u8 {
    if (deferred_removals) |enabled|
        if (!enabled or backups == null) return error.InvalidUnpackDiversionCache;
    if (backups) |entries| try validateBackups(allocator, entries);
    const cache_json = try native_diversion_cache.encode(allocator, cache, intent_sha256);
    defer allocator.free(cache_json);
    var document: Document = .{
        .intent_sha256 = intent_sha256,
        .program_step = program_step,
        .cache_json = cache_json,
        .backups = backups,
        .deferred_removals = deferred_removals,
    };
    document.digest_sha256 = documentDigest(document);
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    std.json.Stringify.value(document, json_options, &output.writer) catch
        return error.OutOfMemory;
    if (output.written().len > maximum_document_bytes)
        return error.InvalidUnpackDiversionCache;
    return output.toOwnedSlice();
}

pub fn decode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    intent_sha256: Digest,
    program_step: u32,
) !Decoded {
    if (bytes.len > maximum_document_bytes)
        return error.InvalidUnpackDiversionCache;
    var parsed = try std.json.parseFromSlice(Document, allocator, bytes, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();
    const document = parsed.value;
    if (!std.mem.eql(u8, document.schema, schema_name) or document.version != 1 or
        !std.mem.eql(u8, &document.intent_sha256, &intent_sha256) or
        document.program_step != program_step or
        !std.mem.eql(u8, &document.digest_sha256, &documentDigest(document)))
        return error.InvalidUnpackDiversionCache;
    var decoded = try native_diversion_cache.decode(allocator, document.cache_json, intent_sha256);
    errdefer decoded.deinit();
    const canonical = try encodeInputs(allocator, decoded.cache, intent_sha256, program_step, document.backups, document.deferred_removals);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.InvalidUnpackDiversionCache;
    return .{
        .cache = decoded.cache,
        .digest_sha256 = document.digest_sha256,
        .backups = document.backups,
        .deferred_removals = document.deferred_removals orelse false,
        .parsed = parsed,
    };
}

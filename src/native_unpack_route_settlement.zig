const std = @import("std");
const builtin = @import("builtin");
const deb822 = @import("deb822.zig");
const native_diversion = @import("native_diversion.zig");
const native_diversion_cache = @import("native_diversion_cache.zig");
const native_program = @import("native_program.zig");
const native_recovery = @import("native_recovery.zig");
const native_unpack_diversion = @import("native_unpack_diversion.zig");
const native_unpack_settlement = @import("native_unpack_settlement.zig");
const package_database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");
const root_mutation = @import("root_mutation.zig");
const root_operation = @import("root_operation.zig");

const Digest = native_recovery.Digest;
const schema_name = "https://debz.dev/schema/native-unpack-route-settlement-v1";
const json_options: std.json.Stringify.Options = .{
    .whitespace = .minified,
    .emit_null_optional_fields = false,
};

pub const maximum_document_bytes = 128 * 1024 * 1024;
pub const maximum_routes = (package_database.Limits{}).max_diversions;
pub const maximum_aliases = 7;

fn BoundedSlice(comptime T: type, comptime maximum_items: usize) type {
    return struct {
        items: []const T,

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            source: anytype,
            options: std.json.ParseOptions,
        ) !@This() {
            if (.array_begin != try source.next())
                return error.UnexpectedToken;
            var items: std.ArrayList(T) = .empty;
            errdefer items.deinit(allocator);
            while (true) {
                if (try source.peekNextTokenType() == .array_end) {
                    _ = try source.next();
                    break;
                }
                if (items.items.len >= maximum_items)
                    return error.Overflow;
                try items.append(
                    allocator,
                    try std.json.innerParse(T, allocator, source, options),
                );
            }
            return .{ .items = try items.toOwnedSlice(allocator) };
        }

        pub fn jsonStringify(self: @This(), writer: anytype) !void {
            try writer.write(self.items);
        }
    };
}

pub const Capability = enum {
    postrm_upgrade_route_settlement,
};

pub const Package = struct {
    name: []const u8,
    architecture: []const u8,
};

pub const Alias = struct {
    from: []const u8,
    to: []const u8,
};

pub const CacheReference = struct {
    digest_sha256: Digest,
};

pub const PostScriptRoute = union(enum) {
    path: []const u8,
    cache: CacheReference,
};

pub const RouteSource = enum {
    payload,
    post_script,
};

pub const AssociationKind = enum {
    removal,
    write,
};

pub const Association = struct {
    write_index: u32,
    kind: AssociationKind,
    route: RouteSource,
};

pub const TriggerSource = enum {
    none,
    logical,
    payload,
    post_script,
    logical_and_payload,
    logical_and_post_script,
};

pub const BackupExpectation = enum {
    none,
    discard,
    retain,
};

pub const StagingExpectation = enum {
    absent,
    discard,
    retain,
};

pub const OwnershipExpectation = enum {
    previous,
    resulting,
    previous_and_resulting,
};

pub const ConffileExpectation = struct {
    staging: StagingExpectation,
    recorded_md5: native_program.Md5Digest,
};

pub const Route = struct {
    logical_path: []const u8,
    payload_route: []const u8,
    post_script_route: PostScriptRoute,
    settlement: []const Association,
    trigger_source: TriggerSource,
    ownership: OwnershipExpectation,
    backup: BackupExpectation,
    conffile: ?ConffileExpectation = null,

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !Route {
        const Wire = struct {
            logical_path: []const u8,
            payload_route: []const u8,
            post_script_route: PostScriptRoute,
            settlement: BoundedSlice(
                Association,
                native_unpack_settlement.maximum_writes,
            ),
            trigger_source: TriggerSource,
            ownership: OwnershipExpectation,
            backup: BackupExpectation,
            conffile: ?ConffileExpectation = null,
        };
        const wire = try std.json.innerParse(
            Wire,
            allocator,
            source,
            options,
        );
        return .{
            .logical_path = wire.logical_path,
            .payload_route = wire.payload_route,
            .post_script_route = wire.post_script_route,
            .settlement = wire.settlement.items,
            .trigger_source = wire.trigger_source,
            .ownership = wire.ownership,
            .backup = wire.backup,
            .conffile = wire.conffile,
        };
    }
};

pub const Contract = struct {
    version: u32 = 1,
    capability: Capability = .postrm_upgrade_route_settlement,
    intent_sha256: Digest,
    program_step: u32,
    unpack_input_sha256: Digest,
    package: Package,
    aliases: []const Alias = &.{},
    routes: []const Route,
};

const Document = struct {
    schema: []const u8 = schema_name,
    version: u32,
    capability: Capability,
    intent_sha256: Digest,
    program_step: u32,
    unpack_input_sha256: Digest,
    package: Package,
    aliases: BoundedSlice(Alias, maximum_aliases),
    routes: BoundedSlice(Route, maximum_routes),
    digest_sha256: Digest = @splat('0'),
};

pub const Decoded = struct {
    contract: Contract,
    digest_sha256: Digest,
    parsed: std.json.Parsed(Document),

    pub fn deinit(self: *Decoded) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub const LoweredConffile = struct {
    staging: StagingExpectation,
    staged_path: ?[]const u8,
    recorded_md5: native_program.Md5Digest,
};

pub const LoweredRoute = struct {
    logical_path: []const u8,
    payload_route: []const u8,
    post_script_route: []const u8,
    route_changed: bool,
    trigger_paths: []const []const u8,
    ownership: OwnershipExpectation,
    backup: BackupExpectation,
    backup_path: ?[]const u8,
    conffile: ?LoweredConffile,
};

pub const PathExpectation = enum {
    absent,
    present_regular,
    backup,
};

pub const BoundPath = struct {
    path: []const u8,
    expectation: PathExpectation,
    backup: ?native_unpack_diversion.Backup = null,
};

pub const Lowered = struct {
    intents: []const root_mutation.Intent,
    cleanup_intents: []const root_mutation.Intent,
    routes: []const LoweredRoute,
    bound_paths: []const BoundPath,
    observed_paths: []const []const u8,
    evidence: native_unpack_settlement.DatabaseEvidence,
    phase_sha256: [32]u8,
};

pub const Outcome = enum {
    postrm_succeeded,
    unwind_succeeded,
    rollback,
    postinst_failed,
};

pub const PartialDisposition = enum {
    restore_previous,
    retain_incoming,
    retain_conffile_staging,
};

pub const PartialRoute = struct {
    logical_path: []const u8,
    payload_route: []const u8,
    post_script_route: []const u8,
    disposition: PartialDisposition,
    backup_path: ?[]const u8,
    trigger_paths: []const []const u8,
};

pub const LoweredOutcome = struct {
    outcome: Outcome,
    routes: []const LoweredRoute,
    settlement_intents: []const root_mutation.Intent,
    cleanup_intents: []const root_mutation.Intent,
    partial_routes: []const PartialRoute,
    bound_paths: []const BoundPath,
    observed_paths: []const []const u8,
    evidence: native_unpack_settlement.DatabaseEvidence,
    phase_sha256: [32]u8,
    publish_settlement: bool,
};

fn validateDigest(digest: Digest) !void {
    if (native_recovery.parseDigest(digest) == null)
        return error.InvalidUnpackRouteSettlement;
}

fn validateMd5(digest: native_program.Md5Digest) !void {
    for (digest) |byte| {
        if (!(byte >= '0' and byte <= '9') and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidUnpackRouteSettlement;
    }
}

fn validatePath(path: []const u8) !void {
    _ = root_fs.Path.initPackage(path) catch return error.InvalidUnpackRouteSettlement;
    if (package_database.reservedPayloadPath(path) or root_mutation.withinNamespace(path))
        return error.InvalidUnpackRouteSettlement;
}

fn validateSuffixedPath(path: []const u8, suffix: []const u8) !void {
    if (path.len > root_fs.maximum_path_bytes - suffix.len)
        return error.InvalidUnpackRouteSettlement;
    var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    @memcpy(buffer[0..path.len], path);
    @memcpy(buffer[path.len .. path.len + suffix.len], suffix);
    try validatePath(buffer[0 .. path.len + suffix.len]);
}

fn aliasDestination(source: []const u8) ?[]const u8 {
    inline for (.{
        .{ "bin", "usr/bin" },
        .{ "lib", "usr/lib" },
        .{ "lib32", "usr/lib32" },
        .{ "lib64", "usr/lib64" },
        .{ "libo32", "usr/libo32" },
        .{ "libx32", "usr/libx32" },
        .{ "sbin", "usr/sbin" },
    }) |entry| {
        if (std.mem.eql(u8, source, entry[0]))
            return entry[1];
    }
    return null;
}

fn validateAliases(aliases: []const Alias) !void {
    if (aliases.len > maximum_aliases)
        return error.InvalidUnpackRouteSettlement;
    var previous: ?[]const u8 = null;
    for (aliases) |alias| {
        const expected = aliasDestination(alias.from) orelse
            return error.InvalidUnpackRouteSettlement;
        if (!std.mem.eql(u8, alias.to, expected))
            return error.InvalidUnpackRouteSettlement;
        if (previous) |before|
            if (!std.mem.lessThan(u8, before, alias.from))
                return error.InvalidUnpackRouteSettlement;
        previous = alias.from;
    }
}

const CanonicalPath = struct {
    text: []const u8,
    rewritten: bool,
};

fn canonicalPath(
    aliases: []const Alias,
    path: []const u8,
    buffer: *[root_fs.maximum_path_bytes]u8,
) !CanonicalPath {
    const first = std.mem.sliceTo(path, '/');
    for (aliases) |alias| {
        if (!std.mem.eql(u8, alias.from, first))
            continue;
        const rest = path[first.len..];
        if (rest.len > root_fs.maximum_path_bytes - alias.to.len)
            return error.InvalidUnpackRouteSettlement;
        return .{
            .text = std.fmt.bufPrint(buffer, "{s}{s}", .{
                alias.to,
                rest,
            }) catch return error.InvalidUnpackRouteSettlement,
            .rewritten = true,
        };
    }
    return .{ .text = path, .rewritten = false };
}

fn claimRoutePath(
    allocator: std.mem.Allocator,
    paths: *std.StringHashMapUnmanaged(usize),
    path: []const u8,
    route_index: usize,
) !void {
    const result = try paths.getOrPut(allocator, path);
    if (result.found_existing and result.value_ptr.* != route_index)
        return error.InvalidUnpackRouteSettlement;
    result.value_ptr.* = route_index;
}

fn claimCanonicalRoutePath(
    allocator: std.mem.Allocator,
    aliases: []const Alias,
    owned_paths: *std.ArrayList([]u8),
    paths: *std.StringHashMapUnmanaged(usize),
    path: []const u8,
    route_index: usize,
) !void {
    var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    const canonical = try canonicalPath(aliases, path, &buffer);
    const key = if (canonical.rewritten) block: {
        const owned = try allocator.dupe(u8, canonical.text);
        errdefer allocator.free(owned);
        try owned_paths.append(allocator, owned);
        break :block owned;
    } else canonical.text;
    try claimRoutePath(allocator, paths, key, route_index);
}

fn claimSidePath(
    allocator: std.mem.Allocator,
    paths: *std.StringHashMapUnmanaged(usize),
    path: []const u8,
    route_index: usize,
) !void {
    const result = try paths.getOrPut(allocator, path);
    if (result.found_existing)
        return error.InvalidUnpackRouteSettlement;
    result.value_ptr.* = route_index;
}

fn lessRoute(left: Route, right: Route) bool {
    return std.mem.lessThan(u8, left.logical_path, right.logical_path);
}

fn validateTriggerPath(path: []const u8) !void {
    if (path.len >= (package_database.Limits{}).max_trigger_name_bytes)
        return error.InvalidUnpackRouteSettlement;
}

pub fn validate(allocator: std.mem.Allocator, contract: Contract) !void {
    if (contract.version != 1 or
        contract.capability != .postrm_upgrade_route_settlement or
        contract.routes.len == 0 or
        contract.routes.len > maximum_routes)
        return error.InvalidUnpackRouteSettlement;
    try validateDigest(contract.intent_sha256);
    try validateDigest(contract.unpack_input_sha256);
    try validateAliases(contract.aliases);
    const limits = package_database.Limits{};
    if (contract.package.name.len > limits.max_package_name_bytes or
        contract.package.architecture.len > limits.max_architecture_bytes or
        !package_database.validPackageName(contract.package.name) or
        !package_database.validArchitecture(contract.package.architecture))
        return error.InvalidUnpackRouteSettlement;

    var route_paths: std.StringHashMapUnmanaged(usize) = .empty;
    defer route_paths.deinit(allocator);
    var canonical_paths: std.ArrayList([]u8) = .empty;
    defer {
        for (canonical_paths.items) |path| allocator.free(path);
        canonical_paths.deinit(allocator);
    }
    var associations: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer associations.deinit(allocator);
    var cache_digest: ?Digest = null;
    var previous: ?Route = null;
    for (contract.routes, 0..) |route, route_index| {
        if (previous) |before| {
            if (!lessRoute(before, route))
                return error.InvalidUnpackRouteSettlement;
        }
        previous = route;
        try validatePath(route.logical_path);
        try validatePath(route.payload_route);
        var payload_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        if ((try canonicalPath(
            contract.aliases,
            route.payload_route,
            &payload_buffer,
        )).rewritten)
            return error.InvalidUnpackRouteSettlement;
        try claimCanonicalRoutePath(
            allocator,
            contract.aliases,
            &canonical_paths,
            &route_paths,
            route.logical_path,
            route_index,
        );
        try claimCanonicalRoutePath(
            allocator,
            contract.aliases,
            &canonical_paths,
            &route_paths,
            route.payload_route,
            route_index,
        );
        switch (route.post_script_route) {
            .path => |path| {
                try validatePath(path);
                var post_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
                if ((try canonicalPath(
                    contract.aliases,
                    path,
                    &post_buffer,
                )).rewritten)
                    return error.InvalidUnpackRouteSettlement;
                try claimCanonicalRoutePath(
                    allocator,
                    contract.aliases,
                    &canonical_paths,
                    &route_paths,
                    path,
                    route_index,
                );
            },
            .cache => |reference| {
                try validateDigest(reference.digest_sha256);
                if (cache_digest) |digest| {
                    if (!std.mem.eql(
                        u8,
                        &digest,
                        &reference.digest_sha256,
                    ))
                        return error.InvalidUnpackRouteSettlement;
                } else cache_digest = reference.digest_sha256;
            },
        }
        switch (route.trigger_source) {
            .none => {},
            .logical => try validateTriggerPath(route.logical_path),
            .payload => try validateTriggerPath(route.payload_route),
            .post_script => switch (route.post_script_route) {
                .path => |path| try validateTriggerPath(path),
                .cache => {},
            },
            .logical_and_payload => {
                try validateTriggerPath(route.logical_path);
                try validateTriggerPath(route.payload_route);
                if (std.mem.eql(
                    u8,
                    route.logical_path,
                    route.payload_route,
                ))
                    return error.InvalidUnpackRouteSettlement;
            },
            .logical_and_post_script => {
                try validateTriggerPath(route.logical_path);
                switch (route.post_script_route) {
                    .path => |path| {
                        try validateTriggerPath(path);
                        if (std.mem.eql(u8, route.logical_path, path))
                            return error.InvalidUnpackRouteSettlement;
                    },
                    .cache => {},
                }
            },
        }
        if (route.backup != .none and route.conffile != null)
            return error.InvalidUnpackRouteSettlement;
        if (route.backup != .none)
            try validateSuffixedPath(route.payload_route, ".dpkg-tmp");
        if (route.conffile) |conffile| {
            try validateMd5(conffile.recorded_md5);
            if (conffile.staging != .absent)
                try validateSuffixedPath(route.payload_route, ".dpkg-new");
        }
        var previous_write: ?u32 = null;
        for (route.settlement) |association| {
            if (association.write_index >= native_unpack_settlement.maximum_writes)
                return error.InvalidUnpackRouteSettlement;
            if (previous_write) |before|
                if (association.write_index <= before)
                    return error.InvalidUnpackRouteSettlement;
            previous_write = association.write_index;
            const result = try associations.getOrPut(allocator, association.write_index);
            if (result.found_existing)
                return error.InvalidUnpackRouteSettlement;
        }
    }

    var side_paths: std.ArrayList([]u8) = .empty;
    defer {
        for (side_paths.items) |path| allocator.free(path);
        side_paths.deinit(allocator);
    }
    for (contract.routes, 0..) |route, route_index| {
        const suffix: ?[]const u8 = if (route.backup != .none)
            ".dpkg-tmp"
        else if (route.conffile) |conffile|
            if (conffile.staging != .absent) ".dpkg-new" else null
        else
            null;
        if (suffix) |value| {
            const path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ route.payload_route, value });
            errdefer allocator.free(path);
            if (route_paths.contains(path))
                return error.InvalidUnpackRouteSettlement;
            try claimSidePath(allocator, &route_paths, path, route_index);
            try side_paths.append(allocator, path);
        }
    }
}

fn documentDigest(document: Document) Digest {
    var payload = document;
    payload.digest_sha256 = @splat('0');
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-unpack-route-settlement-v1\x00") catch unreachable;
    std.json.Stringify.value(payload, json_options, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return native_recovery.hexDigest(sink.hasher.finalResult());
}

pub fn contractDigest(contract: Contract) Digest {
    return documentDigest(contractDocument(contract));
}

fn contractDocument(contract: Contract) Document {
    return .{
        .version = contract.version,
        .capability = contract.capability,
        .intent_sha256 = contract.intent_sha256,
        .program_step = contract.program_step,
        .unpack_input_sha256 = contract.unpack_input_sha256,
        .package = contract.package,
        .aliases = .{ .items = contract.aliases },
        .routes = .{ .items = contract.routes },
    };
}

fn documentSize(document: Document) !usize {
    var buffer: [4096]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&buffer);
    std.json.Stringify.value(document, json_options, &counter.writer) catch
        unreachable;
    const size = std.math.cast(usize, counter.fullCount()) orelse
        return error.InvalidUnpackRouteSettlement;
    if (size > maximum_document_bytes)
        return error.InvalidUnpackRouteSettlement;
    return size;
}

pub fn encode(allocator: std.mem.Allocator, contract: Contract) ![]u8 {
    try validate(allocator, contract);
    var document = contractDocument(contract);
    document.digest_sha256 = documentDigest(document);
    var output: std.Io.Writer.Allocating = try .initCapacity(
        allocator,
        try documentSize(document),
    );
    errdefer output.deinit();
    std.json.Stringify.value(document, json_options, &output.writer) catch
        return error.OutOfMemory;
    return output.toOwnedSlice();
}

fn decodeBounded(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    intent_sha256: Digest,
    program_step: u32,
    unpack_input_sha256: ?Digest,
    maximum_bytes: usize,
) !Decoded {
    if (bytes.len > maximum_bytes)
        return error.InvalidUnpackRouteSettlement;
    var parsed = try std.json.parseFromSlice(Document, allocator, bytes, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
        .max_value_len = root_fs.maximum_path_bytes,
    });
    errdefer parsed.deinit();
    const document = parsed.value;
    if (!std.mem.eql(u8, document.schema, schema_name) or
        document.version != 1 or
        document.capability != .postrm_upgrade_route_settlement or
        !std.mem.eql(u8, &document.intent_sha256, &intent_sha256) or
        document.program_step != program_step or
        !std.mem.eql(u8, &document.digest_sha256, &documentDigest(document)))
        return error.InvalidUnpackRouteSettlement;
    if (unpack_input_sha256) |expected|
        if (!std.mem.eql(
            u8,
            &document.unpack_input_sha256,
            &expected,
        ))
            return error.InvalidUnpackRouteSettlement;
    const contract: Contract = .{
        .version = document.version,
        .capability = document.capability,
        .intent_sha256 = document.intent_sha256,
        .program_step = document.program_step,
        .unpack_input_sha256 = document.unpack_input_sha256,
        .package = document.package,
        .aliases = document.aliases.items,
        .routes = document.routes.items,
    };
    try validate(allocator, contract);
    const canonical = try encode(allocator, contract);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.InvalidUnpackRouteSettlement;
    return .{
        .contract = contract,
        .digest_sha256 = document.digest_sha256,
        .parsed = parsed,
    };
}

pub fn decode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    intent_sha256: Digest,
    program_step: u32,
    unpack_input_sha256: Digest,
) !Decoded {
    return decodeBounded(
        allocator,
        bytes,
        intent_sha256,
        program_step,
        unpack_input_sha256,
        maximum_document_bytes,
    );
}

pub fn decodeEvidence(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    intent_sha256: Digest,
    program_step: u32,
) !Decoded {
    return decodeBounded(
        allocator,
        bytes,
        intent_sha256,
        program_step,
        null,
        maximum_document_bytes,
    );
}

fn effectiveRoute(
    route: Route,
    package: Package,
    route_cache: ?*const native_diversion_cache.Decoded,
) ![]const u8 {
    return switch (route.post_script_route) {
        .path => |path| path,
        .cache => |reference| block: {
            const cached = route_cache orelse return error.InvalidUnpackRouteSettlement;
            if (!std.mem.eql(u8, &reference.digest_sha256, &cached.digest_sha256))
                return error.InvalidUnpackRouteSettlement;
            break :block cached.cache.index.physical(route.logical_path, package.name);
        },
    };
}

fn appendTrigger(
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]const u8),
    path: []const u8,
) !void {
    try validateTriggerPath(path);
    for (paths.items) |existing|
        if (std.mem.eql(u8, existing[1..], path))
            return error.InvalidUnpackRouteSettlement;
    const trigger = try std.fmt.allocPrint(allocator, "/{s}", .{path});
    errdefer allocator.free(trigger);
    try paths.append(allocator, trigger);
}

fn backupForRoute(
    backups: []const native_unpack_diversion.Backup,
    route: Route,
) !?native_unpack_diversion.Backup {
    var found: ?native_unpack_diversion.Backup = null;
    for (backups) |backup| {
        if (!std.mem.eql(u8, backup.logical_path, route.logical_path))
            continue;
        if (found != null or !std.mem.eql(u8, backup.path, route.payload_route))
            return error.InvalidUnpackRouteSettlement;
        found = backup;
    }
    return found;
}

fn associationMatches(
    association: Association,
    write: native_unpack_settlement.Write,
) bool {
    return switch (association.kind) {
        .removal => write == .remove or write == .remove_directory,
        .write => write == .metadata,
    };
}

fn appendBoundPath(
    allocator: std.mem.Allocator,
    index: *std.StringHashMapUnmanaged(void),
    paths: *std.ArrayList(BoundPath),
    path: []const u8,
    expectation: PathExpectation,
    backup: ?native_unpack_diversion.Backup,
) !void {
    const result = try index.getOrPut(allocator, path);
    if (result.found_existing)
        return error.InvalidUnpackRouteSettlement;
    try paths.append(allocator, .{
        .path = path,
        .expectation = expectation,
        .backup = backup,
    });
}

fn fieldValue(field: *const deb822.Field) ?[]const u8 {
    if (field.value_lines.len != 1)
        return null;
    return field.value_lines[0].text;
}

fn writeField(writer: *std.Io.Writer, field: deb822.Field) !void {
    if (field.value_lines.len == 0 or field.value_lines[0].text.len == 0) {
        try writer.print("{s}:\n", .{field.name});
    } else {
        try writer.print("{s}: {s}\n", .{
            field.name,
            field.value_lines[0].text,
        });
    }
    for (field.value_lines[@min(1, field.value_lines.len)..]) |line|
        try writer.print(" {s}\n", .{line.text});
}

fn rewriteConffileField(
    writer: *std.Io.Writer,
    field: deb822.Field,
    expected: *const std.StringHashMapUnmanaged(native_program.Md5Digest),
    found: *std.StringHashMapUnmanaged(void),
    allocator: std.mem.Allocator,
) !void {
    if (field.value_lines.len == 0 or field.value_lines[0].text.len != 0)
        return error.InvalidUnpackRouteSettlement;
    try writer.print("{s}:\n", .{field.name});
    for (field.value_lines[1..]) |line| {
        const separator = std.mem.indexOfScalar(u8, line.text, ' ') orelse
            return error.InvalidUnpackRouteSettlement;
        const path = line.text[0..separator];
        const digest_start = separator + 1;
        if (digest_start >= line.text.len)
            return error.InvalidUnpackRouteSettlement;
        const digest_end = std.mem.indexOfScalarPos(
            u8,
            line.text,
            digest_start,
            ' ',
        ) orelse line.text.len;
        if (expected.get(path)) |digest| {
            if (digest_end - digest_start != digest.len)
                return error.InvalidUnpackRouteSettlement;
            for (line.text[digest_start..digest_end]) |byte|
                if (!(byte >= '0' and byte <= '9') and
                    !(byte >= 'a' and byte <= 'f'))
                    return error.InvalidUnpackRouteSettlement;
            if ((try found.getOrPut(allocator, path)).found_existing)
                return error.InvalidUnpackRouteSettlement;
            try writer.print(" {s} {s}{s}\n", .{
                path,
                &digest,
                line.text[digest_end..],
            });
        } else {
            try writer.print(" {s}\n", .{line.text});
        }
    }
}

fn rewriteStatusConffiles(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_records: usize,
    contract: Contract,
) ![]u8 {
    var expected: std.StringHashMapUnmanaged(native_program.Md5Digest) = .empty;
    defer {
        var keys = expected.keyIterator();
        while (keys.next()) |path| allocator.free(path.*);
        expected.deinit(allocator);
    }
    for (contract.routes) |route| {
        const conffile = route.conffile orelse continue;
        const path = try std.fmt.allocPrint(allocator, "/{s}", .{
            route.logical_path,
        });
        const result = expected.getOrPut(allocator, path) catch |err| {
            allocator.free(path);
            return err;
        };
        if (result.found_existing) {
            allocator.free(path);
            return error.InvalidUnpackRouteSettlement;
        }
        result.value_ptr.* = conffile.recorded_md5;
    }
    if (expected.count() == 0)
        return allocator.dupe(u8, bytes);

    const limits = package_database.Limits{};
    const parsed = try deb822.parseBorrowed(allocator, bytes, .{
        .limits = .{
            .max_total_bytes = limits.max_status_bytes,
            .max_paragraphs = limits.max_packages,
            .max_fields_per_paragraph = limits.max_fields_per_package,
            .max_field_bytes = limits.max_field_bytes,
        },
        .duplicate_policy = .reject,
    });
    var document = switch (parsed) {
        .failure => return error.InvalidUnpackRouteSettlement,
        .document => |value| value,
    };
    defer document.deinit();
    if (document.paragraphs.len != expected_records)
        return error.InvalidUnpackRouteSettlement;

    var field_count: usize = 0;
    for (document.paragraphs) |paragraph|
        field_count = std.math.add(
            usize,
            field_count,
            paragraph.fields.len,
        ) catch return error.InvalidUnpackRouteSettlement;
    const maximum_output = std.math.add(
        usize,
        bytes.len,
        field_count,
    ) catch return error.InvalidUnpackRouteSettlement;
    if (maximum_output > limits.max_status_bytes)
        return error.InvalidUnpackRouteSettlement;

    var found: std.StringHashMapUnmanaged(void) = .empty;
    defer found.deinit(allocator);
    var target_count: usize = 0;
    var output: std.Io.Writer.Allocating = try .initCapacity(
        allocator,
        maximum_output,
    );
    errdefer output.deinit();
    for (document.paragraphs) |paragraph| {
        const name = paragraph.get("Package") orelse
            return error.InvalidUnpackRouteSettlement;
        const architecture = paragraph.get("Architecture") orelse
            return error.InvalidUnpackRouteSettlement;
        const target = std.mem.eql(
            u8,
            fieldValue(name) orelse return error.InvalidUnpackRouteSettlement,
            contract.package.name,
        ) and std.mem.eql(
            u8,
            fieldValue(architecture) orelse
                return error.InvalidUnpackRouteSettlement,
            contract.package.architecture,
        );
        if (target) target_count += 1;
        var conffiles_seen = false;
        for (paragraph.fields) |field| {
            if (target and std.ascii.eqlIgnoreCase(field.name, "Conffiles")) {
                if (conffiles_seen)
                    return error.InvalidUnpackRouteSettlement;
                conffiles_seen = true;
                try rewriteConffileField(
                    &output.writer,
                    field,
                    &expected,
                    &found,
                    allocator,
                );
            } else try writeField(&output.writer, field);
        }
        if (target and !conffiles_seen)
            return error.InvalidUnpackRouteSettlement;
        output.writer.writeByte('\n') catch return error.OutOfMemory;
    }
    if (target_count != 1 or found.count() != expected.count())
        return error.InvalidUnpackRouteSettlement;
    const rewritten = try output.toOwnedSlice();
    errdefer allocator.free(rewritten);
    if (try package_database.verifySerializedStatus(
        allocator,
        rewritten,
        expected_records,
        .{},
        .status,
    ) != null)
        return error.InvalidUnpackRouteSettlement;
    return rewritten;
}

const SettlementDigests = struct {
    evidence: [32]u8,
    phase: [32]u8,
};

fn routeSettlementDigests(
    contract: Contract,
    settlement: native_unpack_settlement.Plan,
    resulting_status_sha256: [32]u8,
) !SettlementDigests {
    const contract_digest = native_recovery.parseDigest(
        documentDigest(contractDocument(contract)),
    ) orelse return error.InvalidUnpackRouteSettlement;
    const database_digest = native_recovery.parseDigest(
        settlement.database_plan_sha256,
    ) orelse return error.InvalidUnpackRouteSettlement;
    const unpack_digest = native_recovery.parseDigest(
        settlement.unpack_plan_sha256,
    ) orelse return error.InvalidUnpackRouteSettlement;
    var evidence = std.crypto.hash.sha2.Sha256.init(.{});
    evidence.update("debz-native-route-settlement-database-v1\x00");
    evidence.update(&database_digest);
    evidence.update(&contract_digest);
    evidence.update(&resulting_status_sha256);
    var phase = std.crypto.hash.sha2.Sha256.init(.{});
    phase.update("debz-native-route-settlement-phase-v1\x00");
    phase.update(&unpack_digest);
    phase.update(&contract_digest);
    phase.update(&resulting_status_sha256);
    return .{
        .evidence = evidence.finalResult(),
        .phase = phase.finalResult(),
    };
}

fn lowerInternal(
    allocator: std.mem.Allocator,
    contract: Contract,
    unpack_input: *const native_unpack_diversion.Decoded,
    route_cache: ?*const native_diversion_cache.Decoded,
    successful: bool,
) !Lowered {
    try validate(allocator, contract);
    if (!std.mem.eql(u8, &contract.unpack_input_sha256, &unpack_input.digest_sha256))
        return error.InvalidUnpackRouteSettlement;
    const settlement = unpack_input.settlement orelse
        return error.InvalidUnpackRouteSettlement;
    const backups = unpack_input.backups orelse
        return error.InvalidUnpackRouteSettlement;
    const base_intents = try native_unpack_settlement.lower(allocator, settlement);
    defer allocator.free(base_intents);
    const intents = try allocator.dupe(root_mutation.Intent, base_intents);
    var cleanup_intents: std.ArrayList(root_mutation.Intent) = .empty;
    var bound_paths: std.ArrayList(BoundPath) = .empty;
    var bound_path_index: std.StringHashMapUnmanaged(void) = .empty;
    defer bound_path_index.deinit(allocator);

    const lowered_routes = try allocator.alloc(LoweredRoute, contract.routes.len);
    var physical_routes: std.StringHashMapUnmanaged(usize) = .empty;
    defer physical_routes.deinit(allocator);
    var canonical_paths: std.ArrayList([]u8) = .empty;
    defer {
        for (canonical_paths.items) |path| allocator.free(path);
        canonical_paths.deinit(allocator);
    }
    var payload_routes: std.StringHashMapUnmanaged(usize) = .empty;
    defer payload_routes.deinit(allocator);
    const associated = try allocator.alloc(bool, settlement.writes.len);
    @memset(associated, false);

    for (contract.routes, lowered_routes, 0..) |route, *lowered, route_index| {
        if (successful) switch (route.post_script_route) {
            .cache => {},
            .path => return error.InvalidUnpackRouteSettlement,
        };
        var payload_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        const selected_payload = try canonicalPath(
            contract.aliases,
            unpack_input.cache.index.physical(
                route.logical_path,
                contract.package.name,
            ),
            &payload_buffer,
        );
        if (!std.mem.eql(
            u8,
            selected_payload.text,
            route.payload_route,
        ))
            return error.InvalidUnpackRouteSettlement;
        const raw_post_script_route = try effectiveRoute(
            route,
            contract.package,
            route_cache,
        );
        var post_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        const selected_post_script = try canonicalPath(
            contract.aliases,
            raw_post_script_route,
            &post_buffer,
        );
        try validatePath(selected_post_script.text);
        const post_script_route = try allocator.dupe(
            u8,
            selected_post_script.text,
        );
        const route_changed = !std.mem.eql(
            u8,
            route.payload_route,
            post_script_route,
        );
        try claimCanonicalRoutePath(
            allocator,
            contract.aliases,
            &canonical_paths,
            &physical_routes,
            route.logical_path,
            route_index,
        );
        try claimCanonicalRoutePath(
            allocator,
            contract.aliases,
            &canonical_paths,
            &physical_routes,
            route.payload_route,
            route_index,
        );
        try claimCanonicalRoutePath(
            allocator,
            contract.aliases,
            &canonical_paths,
            &physical_routes,
            post_script_route,
            route_index,
        );
        try payload_routes.put(allocator, route.payload_route, route_index);

        const backup = try backupForRoute(backups, route);
        if ((route.backup == .none) != (backup == null))
            return error.InvalidUnpackRouteSettlement;
        if (successful and backup != null) {
            const expected_backup: BackupExpectation =
                if (route_changed) .retain else .discard;
            if (route.backup != expected_backup)
                return error.InvalidUnpackRouteSettlement;
        }
        const backup_path = if (backup) |entry| block: {
            var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
            break :block try allocator.dupe(u8, try entry.backupPath(&buffer));
        } else null;
        const conffile: ?LoweredConffile = if (route.conffile) |expectation| block: {
            const staged_path = if (expectation.staging == .absent)
                null
            else
                try std.fmt.allocPrint(allocator, "{s}.dpkg-new", .{route.payload_route});
            break :block .{
                .staging = expectation.staging,
                .staged_path = staged_path,
                .recorded_md5 = expectation.recorded_md5,
            };
        } else null;
        if (successful) {
            if (conffile) |expectation| {
                const expected_staging: StagingExpectation =
                    if (route_changed) .retain else .absent;
                if (expectation.staging != expected_staging)
                    return error.InvalidUnpackRouteSettlement;
            }
        }
        if (successful and route_changed) switch (route.trigger_source) {
            .post_script, .logical_and_post_script => return error.InvalidUnpackRouteSettlement,
            else => {},
        };
        if (backup_path) |path|
            try claimSidePath(allocator, &physical_routes, path, route_index);
        if (conffile) |expectation|
            if (expectation.staged_path) |path|
                try claimSidePath(allocator, &physical_routes, path, route_index);
        if (successful and route_changed)
            try appendBoundPath(
                allocator,
                &bound_path_index,
                &bound_paths,
                post_script_route,
                .absent,
                null,
            );
        if (successful) {
            if (backup_path) |path| {
                try appendBoundPath(
                    allocator,
                    &bound_path_index,
                    &bound_paths,
                    path,
                    .backup,
                    backup,
                );
                if (route.backup == .discard)
                    try cleanup_intents.append(allocator, .{ .remove = .{
                        .path = path,
                        .removal = .require_present,
                    } });
            }
        }
        if (successful) {
            if (conffile) |expectation|
                if (expectation.staged_path) |path|
                    try appendBoundPath(
                        allocator,
                        &bound_path_index,
                        &bound_paths,
                        path,
                        .present_regular,
                        null,
                    );
        }

        var triggers: std.ArrayList([]const u8) = .empty;
        switch (route.trigger_source) {
            .none => {},
            .logical => try appendTrigger(allocator, &triggers, route.logical_path),
            .payload => try appendTrigger(allocator, &triggers, route.payload_route),
            .post_script => try appendTrigger(allocator, &triggers, post_script_route),
            .logical_and_payload => {
                try appendTrigger(allocator, &triggers, route.logical_path);
                try appendTrigger(allocator, &triggers, route.payload_route);
            },
            .logical_and_post_script => {
                try appendTrigger(allocator, &triggers, route.logical_path);
                try appendTrigger(allocator, &triggers, post_script_route);
            },
        }
        lowered.* = .{
            .logical_path = route.logical_path,
            .payload_route = route.payload_route,
            .post_script_route = post_script_route,
            .route_changed = route_changed,
            .trigger_paths = try triggers.toOwnedSlice(allocator),
            .ownership = route.ownership,
            .backup = route.backup,
            .backup_path = backup_path,
            .conffile = conffile,
        };

        for (route.settlement) |association| {
            const index = std.math.cast(usize, association.write_index) orelse
                return error.InvalidUnpackRouteSettlement;
            if (index >= settlement.writes.len or associated[index])
                return error.InvalidUnpackRouteSettlement;
            const write = settlement.writes[index];
            if (!associationMatches(association, write) or
                !std.mem.eql(u8, write.path(), route.payload_route))
                return error.InvalidUnpackRouteSettlement;
            const destination = switch (association.route) {
                .payload => route.payload_route,
                .post_script => post_script_route,
            };
            switch (intents[index]) {
                .metadata => |*value| value.path = destination,
                .remove => |*value| {
                    value.path = destination;
                    if (successful and association.route == .post_script and route_changed)
                        value.removal = .require_absent;
                },
                .remove_directory => |*value| {
                    value.path = destination;
                    if (successful and association.route == .post_script and route_changed)
                        value.removal = .require_absent;
                },
                else => return error.InvalidUnpackRouteSettlement,
            }
            if (successful and association.kind == .write and
                association.route == .post_script and route_changed)
                return error.InvalidUnpackRouteSettlement;
            associated[index] = true;
        }
    }

    for (settlement.writes, 0..) |write, index| {
        if (payload_routes.contains(write.path()) and
            (write == .metadata or write == .remove or write == .remove_directory) and
            !associated[index])
            return error.InvalidUnpackRouteSettlement;
    }
    var intent_paths: std.StringHashMapUnmanaged(void) = .empty;
    defer intent_paths.deinit(allocator);
    for (intents) |intent| {
        _ = root_fs.Path.initPackage(intent.path()) catch
            return error.InvalidUnpackRouteSettlement;
        const result = try intent_paths.getOrPut(allocator, intent.path());
        if (result.found_existing)
            return error.InvalidUnpackRouteSettlement;
    }

    const status_index = intents.len - 1;
    if (intents[status_index] != .file or !std.mem.eql(
        u8,
        intents[status_index].file.path,
        package_database.database_directory ++ "/" ++
            package_database.status_path,
    ))
        return error.InvalidUnpackRouteSettlement;
    const status_bytes = if (successful)
        try rewriteStatusConffiles(
            allocator,
            intents[status_index].file.bytes,
            settlement.resulting_status_package_count,
            contract,
        )
    else
        intents[status_index].file.bytes;
    var resulting_status_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        status_bytes,
        &resulting_status_sha256,
        .{},
    );
    intents[status_index].file.bytes = status_bytes;
    intents[status_index].file.expected_sha256 = resulting_status_sha256;
    var evidence = try settlement.evidence();
    evidence.resulting_status = .{
        .sha256 = resulting_status_sha256,
        .size = status_bytes.len,
        .package_count = settlement.resulting_status_package_count,
    };
    const digests: SettlementDigests = if (successful)
        try routeSettlementDigests(
            contract,
            settlement,
            resulting_status_sha256,
        )
    else
        .{
            .evidence = evidence.digest,
            .phase = native_recovery.parseDigest(
                settlement.unpack_plan_sha256,
            ) orelse return error.InvalidUnpackRouteSettlement,
        };
    if (successful) evidence.digest = digests.evidence;
    const observations = try bound_paths.toOwnedSlice(allocator);
    const observed_paths = try allocator.alloc([]const u8, observations.len);
    for (observations, observed_paths) |observation, *path|
        path.* = observation.path;
    return .{
        .intents = intents,
        .cleanup_intents = try cleanup_intents.toOwnedSlice(allocator),
        .routes = lowered_routes,
        .bound_paths = observations,
        .observed_paths = observed_paths,
        .evidence = evidence,
        .phase_sha256 = digests.phase,
    };
}

/// Returned collections and derived paths use `allocator`; borrowed contract
/// and unpack-input strings must outlive the result.
pub fn lower(
    allocator: std.mem.Allocator,
    contract: Contract,
    unpack_input: *const native_unpack_diversion.Decoded,
    route_cache: ?*const native_diversion_cache.Decoded,
) !Lowered {
    return lowerInternal(
        allocator,
        contract,
        unpack_input,
        route_cache,
        false,
    );
}

/// Inactive successful old-postrm lowering. This adds route preconditions,
/// rerouted-removal semantics, backup cleanup and conffile status settlement
/// without activating the production capability.
pub fn lowerSuccess(
    allocator: std.mem.Allocator,
    contract: Contract,
    unpack_input: *const native_unpack_diversion.Decoded,
    route_cache: ?*const native_diversion_cache.Decoded,
) !Lowered {
    return lowerInternal(
        allocator,
        contract,
        unpack_input,
        route_cache,
        true,
    );
}

fn outcomePhaseDigest(
    contract: Contract,
    route_cache: *const native_diversion_cache.Decoded,
    outcome: Outcome,
    base: [32]u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-native-route-settlement-outcome-v1\x00");
    hash.update(&base);
    hash.update(&native_recovery.parseDigest(
        contractDigest(contract),
    ).?);
    hash.update(&native_recovery.parseDigest(
        route_cache.digest_sha256,
    ).?);
    hash.update(@tagName(outcome));
    return hash.finalResult();
}

fn partialDisposition(route: LoweredRoute) PartialDisposition {
    if (route.conffile) |conffile|
        if (conffile.staging == .retain)
            return .retain_conffile_staging;
    return switch (route.ownership) {
        .previous => .restore_previous,
        .resulting, .previous_and_resulting => .retain_incoming,
    };
}

/// Inactive outcome-aware lowering for the complete old-postrm reference
/// boundary. Rollback consumes the same authenticated routes and artifacts
/// but does not publish the incoming late database recipe; the generic payload
/// rollback remains authoritative and only the described partial routes may be
/// re-published afterwards.
pub fn lowerOutcome(
    allocator: std.mem.Allocator,
    contract: Contract,
    unpack_input: *const native_unpack_diversion.Decoded,
    route_cache: *const native_diversion_cache.Decoded,
    outcome: Outcome,
) !LoweredOutcome {
    const lowered = try lowerSuccess(
        allocator,
        contract,
        unpack_input,
        route_cache,
    );
    var changed_routes: usize = 0;
    for (lowered.routes) |route|
        changed_routes += @intFromBool(route.route_changed);
    if (changed_routes == 0 and outcome != .postrm_succeeded)
        return error.InvalidUnpackRouteSettlement;

    const partial_routes = if (outcome == .rollback) block: {
        const routes = try allocator.alloc(PartialRoute, changed_routes);
        var index: usize = 0;
        for (lowered.routes) |route| {
            if (!route.route_changed) continue;
            routes[index] = .{
                .logical_path = route.logical_path,
                .payload_route = route.payload_route,
                .post_script_route = route.post_script_route,
                .disposition = partialDisposition(route),
                .backup_path = route.backup_path,
                .trigger_paths = route.trigger_paths,
            };
            index += 1;
        }
        break :block routes;
    } else &.{};
    const publish_settlement = outcome != .rollback;
    return .{
        .outcome = outcome,
        .routes = lowered.routes,
        .settlement_intents = if (publish_settlement)
            lowered.intents
        else
            &.{},
        .cleanup_intents = lowered.cleanup_intents,
        .partial_routes = partial_routes,
        .bound_paths = lowered.bound_paths,
        .observed_paths = lowered.observed_paths,
        .evidence = lowered.evidence,
        .phase_sha256 = outcomePhaseDigest(
            contract,
            route_cache,
            outcome,
            lowered.phase_sha256,
        ),
        .publish_settlement = publish_settlement,
    };
}

fn verifyRecoveryState(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    program_step: u32,
    outcome: Outcome,
    validate_artifacts: bool,
    cache_checkpointed: bool,
) !void {
    var unpack_path_buffer: [128]u8 = undefined;
    const unpack_path = try native_recovery.unpackDiversionPath(
        program_step,
        &unpack_path_buffer,
    );
    const unpack_bytes = (try native_recovery.readManagedFile(
        allocator,
        root,
        intent_sha256,
        unpack_path,
        native_unpack_diversion.maximum_document_bytes,
    )) orelse return error.InvalidManagedState;
    defer allocator.free(unpack_bytes);
    var unpack_input = try native_unpack_diversion.decode(
        allocator,
        unpack_bytes,
        intent_sha256,
        program_step,
    );
    defer unpack_input.deinit();

    var route_path_buffer: [128]u8 = undefined;
    const route_path = try native_recovery.unpackRouteSettlementPath(
        program_step,
        &route_path_buffer,
    );
    const route_bytes = (try native_recovery.readManagedFile(
        allocator,
        root,
        intent_sha256,
        route_path,
        maximum_document_bytes,
    )) orelse return error.InvalidManagedState;
    defer allocator.free(route_bytes);
    var route = try decode(
        allocator,
        route_bytes,
        intent_sha256,
        program_step,
        unpack_input.digest_sha256,
    );
    defer route.deinit();

    const cache_bytes = if (cache_checkpointed)
        (try native_recovery.readManagedFile(
            allocator,
            root,
            intent_sha256,
            native_recovery.diversion_cache_path,
            native_diversion_cache.maximum_document_bytes,
        )) orelse return error.InvalidManagedState
    else
        try root.readFileAlloc(
            allocator,
            try root_fs.Path.init(native_recovery.diversion_cache_path),
            native_diversion_cache.maximum_document_bytes,
        );
    defer allocator.free(cache_bytes);
    const cache_path = try root_fs.Path.init(
        native_recovery.diversion_cache_path,
    );
    var pinned_cache = root.pinRegularFile(cache_path) catch |err| switch (err) {
        error.FileNotFound,
        error.NotRegularFile,
        error.PathChanged,
        => return error.ManagedStateChanged,
        else => return err,
    };
    defer pinned_cache.close();
    const observed_cache = pinned_cache.observeStableAlloc(
        allocator,
        native_diversion_cache.maximum_document_bytes,
    ) catch |err| switch (err) {
        error.FileTooLarge,
        error.PathChanged,
        => return error.ManagedStateChanged,
        else => return err,
    };
    defer allocator.free(observed_cache.bytes);
    if ((builtin.os.tag != .windows and
        (!observed_cache.entry.modeled or
            observed_cache.entry.mode != 0o600 or
            observed_cache.entry.link_count != 1)) or
        !std.mem.eql(u8, observed_cache.bytes, cache_bytes))
        return error.ManagedStateChanged;
    var route_cache = try native_diversion_cache.decode(
        allocator,
        cache_bytes,
        intent_sha256,
    );
    defer route_cache.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const lowered = try lowerOutcome(
        arena.allocator(),
        route.contract,
        &unpack_input,
        &route_cache,
        outcome,
    );
    if (validate_artifacts)
        try validateBoundPaths(
            allocator,
            root,
            lowered.bound_paths,
        );
}

pub fn verifyManagedRecoveryState(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    program_step: u32,
    outcome: Outcome,
    validate_artifacts: bool,
) !void {
    return verifyRecoveryState(
        allocator,
        root,
        intent_sha256,
        program_step,
        outcome,
        validate_artifacts,
        true,
    );
}

pub fn verifyUncheckpointedCacheTransition(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    program_step: u32,
    validate_artifacts: bool,
) !void {
    return verifyRecoveryState(
        allocator,
        root,
        intent_sha256,
        program_step,
        .postrm_succeeded,
        validate_artifacts,
        false,
    );
}

pub fn validateJournal(
    lowered: LoweredOutcome,
    journal: root_mutation.Journal,
) !void {
    const database_digest = journal.evidence.database_plan_sha256;
    const intents = if (database_digest != null and std.mem.eql(
        u8,
        &database_digest.?,
        &lowered.evidence.digest,
    ))
        lowered.settlement_intents
    else
        lowered.cleanup_intents;
    if (journal.steps.len != intents.len or intents.len == 0)
        return error.InvalidUnpackRouteSettlementJournal;
    for (intents, journal.steps) |intent, step| {
        if (!std.mem.eql(u8, intent.path(), step.path))
            return error.InvalidUnpackRouteSettlementJournal;
        switch (intent) {
            .file => |file| {
                if (step.kind != .publish_file or
                    step.desired != .present or
                    step.desired.present.kind != .regular)
                    return error.InvalidUnpackRouteSettlementJournal;
                const desired = step.desired.present;
                const expected = file.expected_sha256 orelse
                    return error.InvalidUnpackRouteSettlementJournal;
                if (desired.content_sha256 == null or
                    !std.mem.eql(
                        u8,
                        &desired.content_sha256.?,
                        &expected,
                    ) or desired.metadata.mode != file.mode or
                    desired.metadata.uid != file.uid or
                    desired.metadata.gid != file.gid or
                    desired.metadata.modified_nanoseconds !=
                        file.modified_nanoseconds)
                    return error.InvalidUnpackRouteSettlementJournal;
            },
            .metadata => |metadata| {
                if (step.kind != .set_metadata or
                    step.desired != .present)
                    return error.InvalidUnpackRouteSettlementJournal;
                const desired = step.desired.present.metadata;
                if ((metadata.mode != null and
                    desired.mode != metadata.mode.?) or
                    (metadata.uid != null and
                        desired.uid != metadata.uid.?) or
                    (metadata.gid != null and
                        desired.gid != metadata.gid.?) or
                    (metadata.modified_nanoseconds != null and
                        desired.modified_nanoseconds !=
                            metadata.modified_nanoseconds.?))
                    return error.InvalidUnpackRouteSettlementJournal;
            },
            .remove => if (step.kind != .remove_path or
                step.desired != .absent)
                return error.InvalidUnpackRouteSettlementJournal,
            .remove_directory => if (step.kind != .remove_directory or
                step.desired != .absent)
                return error.InvalidUnpackRouteSettlementJournal,
            else => return error.InvalidUnpackRouteSettlementJournal,
        }
    }
}

fn validateBackupPath(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: root_fs.Path,
    backup: native_unpack_diversion.Backup,
) !void {
    switch (backup.kind) {
        .regular => {
            var pinned = root.pinRegularFile(path) catch |err| switch (err) {
                error.FileNotFound => return error.UnpackRouteArtifactMissing,
                error.NotRegularFile, error.PathChanged => return error.UnpackRouteArtifactMismatch,
                else => return err,
            };
            defer pinned.close();
            const maximum = std.math.cast(usize, backup.size) orelse
                return error.UnpackRouteArtifactMismatch;
            const observed = pinned.observeStableAlloc(
                allocator,
                maximum,
            ) catch |err| switch (err) {
                error.FileTooLarge, error.PathChanged => return error.UnpackRouteArtifactMismatch,
                else => return err,
            };
            defer allocator.free(observed.bytes);
            const entry = observed.entry;
            if (!entry.modeled or entry.mode != backup.mode or
                entry.uid != backup.uid or entry.gid != backup.gid or
                entry.size != backup.size or
                entry.modified_nanoseconds != backup.backup_modified_nanoseconds or
                entry.device != backup.device or
                entry.inode != backup.inode)
                return error.UnpackRouteArtifactMismatch;
            const expected = native_recovery.parseDigest(
                backup.content_sha256 orelse
                    return error.UnpackRouteArtifactMismatch,
            ) orelse return error.UnpackRouteArtifactMismatch;
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(observed.bytes, &digest, .{});
            if (!std.mem.eql(u8, &digest, &expected))
                return error.UnpackRouteArtifactMismatch;
        },
        .symlink => {
            var pinned = root.pinSymbolicLink(path) catch |err| switch (err) {
                error.FileNotFound => return error.UnpackRouteArtifactMissing,
                error.NotSymbolicLink, error.PathChanged => return error.UnpackRouteArtifactMismatch,
                else => return err,
            };
            defer pinned.close();
            var buffer: [root_fs.maximum_link_target_bytes]u8 = undefined;
            const observed = pinned.observe(&buffer) catch |err| switch (err) {
                error.FileNotFound, error.NotSymbolicLink, error.PathChanged => return error.UnpackRouteArtifactMismatch,
                else => return err,
            };
            const entry = observed.entry;
            if (!entry.modeled or !entry.isSymbolicLink() or
                entry.mode != backup.mode or entry.uid != backup.uid or
                entry.gid != backup.gid or entry.size != backup.size or
                entry.modified_nanoseconds != backup.backup_modified_nanoseconds)
                return error.UnpackRouteArtifactMismatch;
            if (!std.mem.eql(
                u8,
                observed.target,
                backup.link_target orelse
                    return error.UnpackRouteArtifactMismatch,
            ))
                return error.UnpackRouteArtifactMismatch;
        },
    }
}

pub fn validateBoundPaths(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    paths: []const BoundPath,
) !void {
    for (paths) |path| {
        const resolved = try root_fs.Path.initPackage(path.path);
        const entry = try root.entryIfExists(resolved);
        switch (path.expectation) {
            .absent => if (entry != null)
                return error.UnexpectedUnpackRouteOccupant,
            .present_regular => if (entry == null)
                return error.UnpackRouteArtifactMissing
            else if (!entry.?.isRegularFile())
                return error.UnpackRouteArtifactMismatch,
            .backup => try validateBackupPath(
                allocator,
                root,
                resolved,
                path.backup orelse
                    return error.InvalidUnpackRouteSettlement,
            ),
        }
    }
}

const testing = std.testing;

fn testObservation(bytes: []const u8, inode: u64) native_diversion.Observation {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .device = 7, .inode = inode, .sha256 = digest };
}

fn testSettlement(allocator: std.mem.Allocator) !native_unpack_settlement.Plan {
    const status =
        "Package: demo\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 2\n" ++
        "Conffiles:\n" ++
        " /etc/demo.conf 6d024d5096fe2159f397866c679590b6\n\n";
    var status_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(status, &status_digest, .{});
    return native_unpack_settlement.capture(allocator, &.{
        .{ .remove = .{ .path = "usr/share/demo/obsolete.original" } },
        .{ .file = .{
            .path = "var/lib/dpkg/status",
            .bytes = status,
            .expected_sha256 = status_digest,
        } },
    }, .{
        .base_generation = .{ .sha256 = @splat(0x81), .file_count = 3, .total_bytes = 200 },
        .base_status = .{ .sha256 = @splat(0x82), .size = 100, .package_count = 1 },
        .resulting_status = .{ .sha256 = status_digest, .size = status.len, .package_count = 1 },
        .digest = @splat(0x83),
    }, @splat(0x84));
}

fn testBackup() native_unpack_diversion.Backup {
    return .{
        .path = "usr/share/demo/file.original",
        .logical_path = "usr/share/demo/file",
        .kind = .regular,
        .mode = 0o640,
        .uid = 0,
        .gid = 0,
        .size = 5,
        .device = 7,
        .inode = 11,
        .modified_nanoseconds = 123456789,
        .backup_modified_nanoseconds = 123456789,
        .content_sha256 = @splat('a'),
    };
}

test "native_unpack.test.route settlement contract round trips and lowers without mutation" {
    const intent: Digest = @splat('1');
    const original =
        "/etc/demo.conf\n/etc/demo.conf.original\n:\n" ++
        "/usr/share/demo/file\n/usr/share/demo/file.original\n:\n" ++
        "/usr/share/demo/obsolete\n/usr/share/demo/obsolete.original\n:\n";
    const changed =
        "/etc/demo.conf\n/etc/demo.conf.changed\n:\n" ++
        "/usr/share/demo/file\n/usr/share/demo/file.changed\n:\n" ++
        "/usr/share/demo/obsolete\n/usr/share/demo/obsolete.changed\n:\n";
    var original_cache = try native_diversion.CachedRecords.init(
        testing.allocator,
        original,
        testObservation(original, 9),
    );
    defer original_cache.deinit();
    var post_cache = try native_diversion.CachedRecords.init(
        testing.allocator,
        changed,
        testObservation(changed, 10),
    );
    defer post_cache.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const settlement = try testSettlement(arena.allocator());
    const parent_bytes = try native_unpack_diversion.encodeWithSettlement(
        testing.allocator,
        original_cache,
        intent,
        7,
        &.{testBackup()},
        settlement,
    );
    defer testing.allocator.free(parent_bytes);
    var parent = try native_unpack_diversion.decode(testing.allocator, parent_bytes, intent, 7);
    defer parent.deinit();

    const cache_bytes = try native_diversion_cache.encode(testing.allocator, post_cache, intent);
    defer testing.allocator.free(cache_bytes);
    var cached = try native_diversion_cache.decode(testing.allocator, cache_bytes, intent);
    defer cached.deinit();

    const routes = [_]Route{
        .{
            .logical_path = "etc/demo.conf",
            .payload_route = "etc/demo.conf.original",
            .post_script_route = .{
                .cache = .{ .digest_sha256 = cached.digest_sha256 },
            },
            .settlement = &.{},
            .trigger_source = .payload,
            .ownership = .previous_and_resulting,
            .backup = .none,
            .conffile = .{ .staging = .retain, .recorded_md5 = @splat('b') },
        },
        .{
            .logical_path = "usr/share/demo/file",
            .payload_route = "usr/share/demo/file.original",
            .post_script_route = .{ .cache = .{ .digest_sha256 = cached.digest_sha256 } },
            .settlement = &.{},
            .trigger_source = .payload,
            .ownership = .previous_and_resulting,
            .backup = .retain,
        },
        .{
            .logical_path = "usr/share/demo/obsolete",
            .payload_route = "usr/share/demo/obsolete.original",
            .post_script_route = .{ .cache = .{ .digest_sha256 = cached.digest_sha256 } },
            .settlement = &.{.{
                .write_index = 0,
                .kind = .removal,
                .route = .post_script,
            }},
            .trigger_source = .none,
            .ownership = .previous,
            .backup = .none,
        },
    };
    const contract: Contract = .{
        .intent_sha256 = intent,
        .program_step = 7,
        .unpack_input_sha256 = parent.digest_sha256,
        .package = .{ .name = "demo", .architecture = "amd64" },
        .routes = &routes,
    };
    const bytes = try encode(testing.allocator, contract);
    defer testing.allocator.free(bytes);
    var decoded = try decode(
        testing.allocator,
        bytes,
        intent,
        7,
        parent.digest_sha256,
    );
    defer decoded.deinit();
    var retained = try decodeEvidence(
        testing.allocator,
        bytes,
        intent,
        7,
    );
    defer retained.deinit();
    try testing.expectEqualDeep(
        decoded.digest_sha256,
        retained.digest_sha256,
    );
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        decodeEvidence(testing.allocator, bytes, @splat('2'), 7),
    );
    const repeated = try encode(testing.allocator, decoded.contract);
    defer testing.allocator.free(repeated);
    try testing.expectEqualStrings(bytes, repeated);
    try testing.expect(std.mem.indexOf(u8, bytes, "\"aliases\":[]") != null);

    var rejected_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer rejected_arena.deinit();
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        lower(rejected_arena.allocator(), decoded.contract, &parent, null),
    );
    var wrong_routes = routes;
    wrong_routes[2].settlement = &.{.{
        .write_index = 0,
        .kind = .write,
        .route = .post_script,
    }};
    var wrong_contract = contract;
    wrong_contract.routes = &wrong_routes;
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        lower(rejected_arena.allocator(), wrong_contract, &parent, &cached),
    );

    const lowered = try lower(arena.allocator(), decoded.contract, &parent, &cached);
    try testing.expectEqualStrings(
        "usr/share/demo/obsolete.changed",
        lowered.intents[0].remove.path,
    );
    try testing.expectEqualStrings(
        "/etc/demo.conf.original",
        lowered.routes[0].trigger_paths[0],
    );
    try testing.expectEqualStrings(
        "etc/demo.conf.original.dpkg-new",
        lowered.routes[0].conffile.?.staged_path.?,
    );
    try testing.expectEqualStrings(
        "usr/share/demo/file.original.dpkg-tmp",
        lowered.routes[1].backup_path.?,
    );
    try testing.expectEqualStrings(
        "usr/share/demo/file.changed",
        lowered.routes[1].post_script_route,
    );
    try testing.expectEqual(
        OwnershipExpectation.previous,
        lowered.routes[2].ownership,
    );

    const successful = try lowerSuccess(
        arena.allocator(),
        decoded.contract,
        &parent,
        &cached,
    );
    try testing.expectEqual(
        root_mutation.Removal.require_absent,
        successful.intents[0].remove.removal,
    );
    try testing.expect(std.mem.indexOf(
        u8,
        successful.intents[successful.intents.len - 1].file.bytes,
        "/etc/demo.conf bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ) != null);

    var malformed_routes = routes;
    malformed_routes[1].backup = .discard;
    var malformed = contract;
    malformed.routes = &malformed_routes;
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        lowerSuccess(
            rejected_arena.allocator(),
            malformed,
            &parent,
            &cached,
        ),
    );
    malformed_routes = routes;
    malformed_routes[1].trigger_source = .post_script;
    malformed.routes = &malformed_routes;
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        lowerSuccess(
            rejected_arena.allocator(),
            malformed,
            &parent,
            &cached,
        ),
    );
    malformed_routes = routes;
    malformed_routes[0].post_script_route = .{
        .path = "etc/demo.conf.changed",
    };
    malformed.routes = &malformed_routes;
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        lowerSuccess(
            rejected_arena.allocator(),
            malformed,
            &parent,
            &cached,
        ),
    );
    malformed_routes = routes;
    malformed_routes[0].conffile.?.staging = .absent;
    malformed.routes = &malformed_routes;
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        lowerSuccess(
            rejected_arena.allocator(),
            malformed,
            &parent,
            &cached,
        ),
    );
}

fn testContract(routes: []const Route) Contract {
    return .{
        .intent_sha256 = @splat('1'),
        .program_step = 7,
        .unpack_input_sha256 = @splat('2'),
        .package = .{ .name = "demo", .architecture = "amd64" },
        .routes = routes,
    };
}

fn testRoute(path: []const u8) Route {
    return .{
        .logical_path = path,
        .payload_route = path,
        .post_script_route = .{ .path = path },
        .settlement = &.{},
        .trigger_source = .none,
        .ownership = .previous_and_resulting,
        .backup = .none,
    };
}

test "native_unpack.test.route settlement contract enforces bounds and canonical input" {
    const routes = [_]Route{testRoute("usr/bin/demo")};
    const bytes = try encode(testing.allocator, testContract(&routes));
    defer testing.allocator.free(bytes);
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        decodeBounded(
            testing.allocator,
            bytes,
            @splat('1'),
            7,
            @splat('2'),
            bytes.len - 1,
        ),
    );
    const spaced = try std.fmt.allocPrint(testing.allocator, " {s}", .{bytes});
    defer testing.allocator.free(spaced);
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        decode(testing.allocator, spaced, @splat('1'), 7, @splat('2')),
    );
    const unknown = try std.fmt.allocPrint(
        testing.allocator,
        "{s},\"unknown\":true}}",
        .{bytes[0 .. bytes.len - 1]},
    );
    defer testing.allocator.free(unknown);
    try testing.expectError(
        error.UnknownField,
        decode(testing.allocator, unknown, @splat('1'), 7, @splat('2')),
    );
    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    const architecture = std.mem.indexOf(u8, tampered, "amd64").?;
    tampered[architecture] = 'x';
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        decode(testing.allocator, tampered, @splat('1'), 7, @splat('2')),
    );

    var invalid = testContract(&routes);
    invalid.version = 2;
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, invalid),
    );
    invalid = testContract(&.{});
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, invalid),
    );
    invalid = testContract(&routes);
    invalid.package.name = "D";
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, invalid),
    );
    invalid = testContract(&routes);
    invalid.package.architecture = "Amd64";
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, invalid),
    );
    var invalid_route = testRoute("../escape");
    invalid.routes = &.{invalid_route};
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, invalid),
    );
    invalid_route = testRoute("usr/bin/demo");
    invalid_route.post_script_route = .{ .cache = .{ .digest_sha256 = @splat('G') } };
    invalid.routes = &.{invalid_route};
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, invalid),
    );
    invalid_route = testRoute("etc/demo.conf");
    invalid_route.conffile = .{ .staging = .retain, .recorded_md5 = @splat('G') };
    invalid.routes = &.{invalid_route};
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, invalid),
    );
    invalid_route = testRoute("usr/bin/demo");
    invalid_route.settlement = &.{.{
        .write_index = native_unpack_settlement.maximum_writes,
        .kind = .removal,
        .route = .payload,
    }};
    invalid.routes = &.{invalid_route};
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, invalid),
    );

    const SmallSlice = BoundedSlice(u8, 1);
    try testing.expectError(
        error.Overflow,
        std.json.parseFromSlice(
            SmallSlice,
            testing.allocator,
            "[1,2]",
            .{},
        ),
    );

    const maximum_trigger_path = try testing.allocator.alloc(
        u8,
        root_fs.maximum_path_bytes,
    );
    defer testing.allocator.free(maximum_trigger_path);
    var offset: usize = 0;
    for (0..18) |component| {
        const length: usize = if (component < 15)
            255
        else if (component == 15)
            252
        else
            1;
        @memset(maximum_trigger_path[offset .. offset + length], 'a');
        offset += length;
        if (component != 17) {
            maximum_trigger_path[offset] = '/';
            offset += 1;
        }
    }
    try testing.expectEqual(root_fs.maximum_path_bytes, offset);
    invalid_route = testRoute(maximum_trigger_path);
    invalid_route.trigger_source = .logical;
    invalid.routes = &.{invalid_route};
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, invalid),
    );
}

test "native_unpack.test.success settlement rejects malformed conffile status evidence" {
    var route = testRoute("etc/demo.conf");
    route.conffile = .{
        .staging = .retain,
        .recorded_md5 = @splat('a'),
    };
    const contract = testContract(&.{route});
    const missing_field =
        "Package: demo\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 2\n\n";
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        rewriteStatusConffiles(
            testing.allocator,
            missing_field,
            1,
            contract,
        ),
    );
    const missing_path =
        "Package: demo\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 2\n" ++
        "Conffiles:\n" ++
        " /etc/other.conf 6d024d5096fe2159f397866c679590b6\n\n";
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        rewriteStatusConffiles(
            testing.allocator,
            missing_path,
            1,
            contract,
        ),
    );
    const malformed_digest =
        "Package: demo\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 2\n" ++
        "Conffiles:\n" ++
        " /etc/demo.conf zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n\n";
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        rewriteStatusConffiles(
            testing.allocator,
            malformed_digest,
            1,
            contract,
        ),
    );
}

test "native_unpack.test.route settlement contract rejects duplicate and conflicting claims" {
    var routes = [_]Route{
        testRoute("usr/bin/a"),
        testRoute("usr/bin/a"),
    };
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, testContract(&routes)),
    );

    routes[0] = testRoute("usr/bin/a");
    routes[0].backup = .retain;
    routes[0].conffile = .{
        .staging = .retain,
        .recorded_md5 = @splat('a'),
    };
    routes[1] = testRoute("usr/bin/b");
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, testContract(&routes)),
    );

    routes[1] = testRoute("usr/bin/b");
    routes[1].payload_route = "usr/bin/a";
    routes[1].post_script_route = .{ .path = "usr/bin/b" };
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, testContract(&routes)),
    );

    routes[0] = testRoute("usr/bin/a");
    routes[0].backup = .retain;
    routes[1] = testRoute("usr/bin/a.dpkg-tmp");
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, testContract(&routes)),
    );

    routes[0] = testRoute("usr/bin/a");
    routes[0].settlement = &.{.{
        .write_index = 0,
        .kind = .removal,
        .route = .payload,
    }};
    routes[1] = testRoute("usr/bin/b");
    routes[1].settlement = routes[0].settlement;
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, testContract(&routes)),
    );

    routes[0] = testRoute("usr/bin/a");
    routes[0].trigger_source = .logical_and_payload;
    routes[1] = testRoute("usr/bin/b");
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, testContract(&routes)),
    );

    routes[0] = testRoute("usr/bin/a");
    routes[0].conffile = .{
        .staging = .retain,
        .recorded_md5 = @splat('a'),
    };
    routes[1] = testRoute("usr/bin/a.dpkg-new");
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, testContract(&routes)),
    );

    routes[0] = testRoute("usr/bin/a");
    routes[0].post_script_route = .{
        .cache = .{ .digest_sha256 = @splat('a') },
    };
    routes[1] = testRoute("usr/bin/b");
    routes[1].post_script_route = .{
        .cache = .{ .digest_sha256 = @splat('b') },
    };
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, testContract(&routes)),
    );

    routes[0] = testRoute("bin/a");
    routes[0].payload_route = "usr/bin/a";
    routes[0].post_script_route = .{ .path = "usr/bin/a" };
    routes[1] = testRoute("usr/bin/a");
    routes[1].payload_route = "usr/bin/b";
    routes[1].post_script_route = .{ .path = "usr/bin/b" };
    var alias_contract = testContract(&routes);
    alias_contract.aliases = &.{.{ .from = "bin", .to = "usr/bin" }};
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, alias_contract),
    );

    routes[0] = testRoute("bin/a");
    routes[0].payload_route = "bin/a";
    routes[0].post_script_route = .{ .path = "bin/a" };
    alias_contract.routes = routes[0..1];
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, alias_contract),
    );

    routes[0].payload_route = "usr/bin/a";
    routes[0].post_script_route = .{ .path = "usr/bin/a" };
    alias_contract.aliases = &.{.{ .from = "bin", .to = "usr/sbin" }};
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, alias_contract),
    );

    alias_contract.aliases = &.{
        .{ .from = "lib", .to = "usr/lib" },
        .{ .from = "bin", .to = "usr/bin" },
    };
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        encode(testing.allocator, alias_contract),
    );
}

test "native_unpack.test.route settlement contract lowers proven merged usr routes" {
    const intent: Digest = @splat('1');
    var original_cache = try native_diversion.CachedRecords.init(
        testing.allocator,
        null,
        null,
    );
    defer original_cache.deinit();
    const changed =
        "/bin/demo\n/bin/demo.changed\n:\n";
    var post_cache = try native_diversion.CachedRecords.init(
        testing.allocator,
        changed,
        testObservation(changed, 10),
    );
    defer post_cache.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const settlement = try testSettlement(arena.allocator());
    const parent_bytes = try native_unpack_diversion.encodeWithSettlement(
        testing.allocator,
        original_cache,
        intent,
        7,
        &.{},
        settlement,
    );
    defer testing.allocator.free(parent_bytes);
    var parent = try native_unpack_diversion.decode(
        testing.allocator,
        parent_bytes,
        intent,
        7,
    );
    defer parent.deinit();

    const cache_bytes = try native_diversion_cache.encode(
        testing.allocator,
        post_cache,
        intent,
    );
    defer testing.allocator.free(cache_bytes);
    var cached = try native_diversion_cache.decode(
        testing.allocator,
        cache_bytes,
        intent,
    );
    defer cached.deinit();

    const routes = [_]Route{.{
        .logical_path = "bin/demo",
        .payload_route = "usr/bin/demo",
        .post_script_route = .{
            .cache = .{ .digest_sha256 = cached.digest_sha256 },
        },
        .settlement = &.{},
        .trigger_source = .logical_and_post_script,
        .ownership = .previous_and_resulting,
        .backup = .none,
    }};
    const contract: Contract = .{
        .intent_sha256 = intent,
        .program_step = 7,
        .unpack_input_sha256 = parent.digest_sha256,
        .package = .{ .name = "demo", .architecture = "amd64" },
        .aliases = &.{.{ .from = "bin", .to = "usr/bin" }},
        .routes = &routes,
    };
    const bytes = try encode(testing.allocator, contract);
    defer testing.allocator.free(bytes);
    var decoded = try decode(
        testing.allocator,
        bytes,
        intent,
        7,
        parent.digest_sha256,
    );
    defer decoded.deinit();
    const lowered = try lower(
        arena.allocator(),
        decoded.contract,
        &parent,
        &cached,
    );
    try testing.expectEqualStrings(
        "usr/bin/demo.changed",
        lowered.routes[0].post_script_route,
    );
    try testing.expectEqualStrings(
        "/bin/demo",
        lowered.routes[0].trigger_paths[0],
    );
    try testing.expectEqualStrings(
        "/usr/bin/demo.changed",
        lowered.routes[0].trigger_paths[1],
    );

    const unchanged_cache_bytes = try native_diversion_cache.encode(
        testing.allocator,
        original_cache,
        intent,
    );
    defer testing.allocator.free(unchanged_cache_bytes);
    var unchanged_cache = try native_diversion_cache.decode(
        testing.allocator,
        unchanged_cache_bytes,
        intent,
    );
    defer unchanged_cache.deinit();
    const duplicate_route = [_]Route{.{
        .logical_path = "usr/bin/demo",
        .payload_route = "usr/bin/demo",
        .post_script_route = .{
            .cache = .{ .digest_sha256 = unchanged_cache.digest_sha256 },
        },
        .settlement = &.{},
        .trigger_source = .logical_and_post_script,
        .ownership = .previous_and_resulting,
        .backup = .none,
    }};
    var duplicate_contract = contract;
    duplicate_contract.aliases = &.{};
    duplicate_contract.routes = &duplicate_route;
    try testing.expectError(
        error.InvalidUnpackRouteSettlement,
        lower(
            arena.allocator(),
            duplicate_contract,
            &parent,
            &unchanged_cache,
        ),
    );
}

test "native_unpack.test.route settlement contract leaves v1 evidence unchanged" {
    var cache = try native_diversion.CachedRecords.init(testing.allocator, null, null);
    defer cache.deinit();
    const old = try native_unpack_diversion.encode(
        testing.allocator,
        cache,
        @splat('1'),
        7,
    );
    defer testing.allocator.free(old);
    try testing.expect(std.mem.indexOf(u8, old, "route_settlement") == null);
    var decoded_old = try native_unpack_diversion.decode(
        testing.allocator,
        old,
        @splat('1'),
        7,
    );
    defer decoded_old.deinit();
    const repeated_old = try native_unpack_diversion.encode(
        testing.allocator,
        decoded_old.cache,
        @splat('1'),
        7,
    );
    defer testing.allocator.free(repeated_old);
    try testing.expectEqualStrings(old, repeated_old);

    const routes = [_]Route{testRoute("usr/bin/demo")};
    const current = try encode(testing.allocator, testContract(&routes));
    defer testing.allocator.free(current);
    try testing.expectError(
        error.UnknownField,
        decode(testing.allocator, old, @splat('1'), 7, decoded_old.digest_sha256),
    );
    try testing.expectError(
        error.UnknownField,
        native_unpack_diversion.decode(testing.allocator, current, @splat('1'), 7),
    );
}

const SuccessProfile = struct {
    update: []const u8,
    member: []const u8,
    payload_route: []const u8,
    post_script_route: []const u8,
    backup: BackupExpectation,
    staging: StagingExpectation,
    ownership: OwnershipExpectation,
    trigger_paths: []const []const u8,
    removal_route: ?RouteSource,
    recorded_md5: []const u8,
};

fn successSource(member: []const u8) []const u8 {
    if (std.mem.eql(u8, member, "regular"))
        return "usr/share/diversion-lifecycle/mode";
    if (std.mem.eql(u8, member, "symlink"))
        return "usr/share/diversion-lifecycle/current";
    if (std.mem.eql(u8, member, "hardlink-source"))
        return "usr/share/diversion-lifecycle/data";
    if (std.mem.eql(u8, member, "hardlink-member"))
        return "usr/share/diversion-lifecycle/data.link";
    if (std.mem.eql(u8, member, "conffile"))
        return "etc/debz-native.conf";
    if (std.mem.eql(u8, member, "directory"))
        return "usr/share/diversion-lifecycle";
    if (std.mem.eql(u8, member, "obsolete"))
        return "usr/share/diversion-lifecycle/obsolete";
    if (std.mem.eql(u8, member, "introduced"))
        return "usr/share/diversion-lifecycle/introduced";
    unreachable;
}

fn successDiversionBytes(
    allocator: std.mem.Allocator,
    source: []const u8,
    suffix: []const u8,
    package: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "/{s}\n/{s}{s}\n{s}\n",
        .{ source, source, suffix, package },
    );
}

fn successStatus() []const u8 {
    return "Package: diversion-lifecycle\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 2\n" ++
        "Conffiles:\n" ++
        " /etc/debz-native.conf 6d024d5096fe2159f397866c679590b6\n\n";
}

fn successSettlement(
    allocator: std.mem.Allocator,
    removal_path: ?[]const u8,
) !native_unpack_settlement.Plan {
    const status = successStatus();
    var status_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(status, &status_digest, .{});
    const intents = try allocator.alloc(
        root_mutation.Intent,
        @as(usize, 1) + @intFromBool(removal_path != null),
    );
    var index: usize = 0;
    if (removal_path) |path| {
        intents[index] = .{ .remove = .{ .path = path } };
        index += 1;
    }
    intents[index] = .{ .file = .{
        .path = package_database.database_directory ++ "/" ++
            package_database.status_path,
        .bytes = status,
        .expected_sha256 = status_digest,
    } };
    return native_unpack_settlement.capture(
        allocator,
        intents,
        .{
            .base_generation = .{
                .sha256 = @splat(0x81),
                .file_count = 3,
                .total_bytes = 200,
            },
            .base_status = .{
                .sha256 = @splat(0x82),
                .size = 100,
                .package_count = 1,
            },
            .resulting_status = .{
                .sha256 = status_digest,
                .size = status.len,
                .package_count = 1,
            },
            .digest = @splat(0x83),
        },
        @splat(0x84),
    );
}

fn successBackup(
    profile: SuccessProfile,
    source: []const u8,
) native_unpack_diversion.Backup {
    const symlink = std.mem.eql(u8, profile.member, "symlink");
    return .{
        .path = profile.payload_route,
        .logical_path = source,
        .kind = if (symlink) .symlink else .regular,
        .mode = if (symlink) 0o777 else 0o640,
        .uid = 0,
        .gid = 0,
        .size = if (symlink) 4 else 5,
        .device = 7,
        .inode = 11,
        .modified_nanoseconds = 123456789,
        .backup_modified_nanoseconds = if (symlink)
            223456789
        else
            123456789,
        .content_sha256 = if (symlink) null else @splat('a'),
        .link_target = if (symlink) "data" else null,
    };
}

test "native_unpack.test.effective diversion cache comparison ignores record order" {
    const original =
        "/usr/share/a\n/usr/share/a.original\n:\n" ++
        "/usr/share/b\n/usr/share/b.original\n:\n";
    const reordered =
        "/usr/share/b\n/usr/share/b.original\n:\n" ++
        "/usr/share/a\n/usr/share/a.original\n:\n";
    const changed =
        "/usr/share/b\n/usr/share/b.changed\n:\n" ++
        "/usr/share/a\n/usr/share/a.original\n:\n";
    var cache = try native_diversion.CachedRecords.init(
        testing.allocator,
        original,
        testObservation(original, 9),
    );
    defer cache.deinit();
    const reordered_refresh = try cache.refreshRouteSettlement(
        reordered,
        testObservation(reordered, 10),
    );
    try testing.expect(reordered_refresh.observation_changed);
    try testing.expect(!reordered_refresh.effective_routes_changed);
    try testing.expectEqualStrings(
        "usr/share/b.original",
        cache.index.physical("usr/share/b", "demo"),
    );
    const changed_refresh = try cache.refreshRouteSettlement(
        changed,
        testObservation(changed, 11),
    );
    try testing.expect(changed_refresh.observation_changed);
    try testing.expect(changed_refresh.effective_routes_changed);
    try testing.expectEqualStrings(
        "usr/share/b.changed",
        cache.index.physical("usr/share/b", "demo"),
    );
}

test "native_unpack.test.success route settlement lowers every reference profile" {
    var parsed = try std.json.parseFromSlice(
        []const SuccessProfile,
        testing.allocator,
        @embedFile("fixtures/native-diversion-success-settlement-v1.json"),
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 15), parsed.value.len);

    for (parsed.value) |profile| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const owned = arena.allocator();
        const source = successSource(profile.member);
        const original = try successDiversionBytes(
            owned,
            source,
            ".original",
            ":",
        );
        const changed = try successDiversionBytes(
            owned,
            source,
            ".changed",
            ":",
        );
        const exempt = try successDiversionBytes(
            owned,
            source,
            ".original",
            "diversion-lifecycle",
        );
        const initial_bytes: ?[]const u8 = if (std.mem.eql(
            u8,
            profile.update,
            "create",
        ))
            null
        else
            original;
        const initial_observation = if (initial_bytes) |bytes|
            testObservation(bytes, 9)
        else
            null;
        var cache = try native_diversion.CachedRecords.init(
            testing.allocator,
            initial_bytes,
            initial_observation,
        );
        defer cache.deinit();

        var refresh: native_diversion.RouteSettlementRefresh = undefined;
        if (std.mem.eql(u8, profile.update, "inplace")) {
            refresh = try cache.refreshRouteSettlement(
                changed,
                testObservation(changed, 9),
            );
        } else if (std.mem.eql(u8, profile.update, "cached-activation")) {
            const same_inode = try cache.refreshRouteSettlement(
                changed,
                testObservation(changed, 9),
            );
            try testing.expect(same_inode.observation_changed);
            try testing.expect(!same_inode.effective_routes_changed);
            refresh = try cache.refreshRouteSettlement(
                changed,
                testObservation(changed, 10),
            );
        } else if (std.mem.eql(u8, profile.update, "unchanged")) {
            refresh = try cache.refreshRouteSettlement(
                original,
                testObservation(original, 10),
            );
        } else if (std.mem.eql(u8, profile.update, "empty")) {
            refresh = try cache.refreshRouteSettlement(
                "",
                testObservation("", 10),
            );
        } else if (std.mem.eql(u8, profile.update, "remove")) {
            refresh = try cache.refreshRouteSettlement(null, null);
        } else if (std.mem.eql(u8, profile.update, "exempt")) {
            refresh = try cache.refreshRouteSettlement(
                exempt,
                testObservation(exempt, 10),
            );
        } else {
            refresh = try cache.refreshRouteSettlement(
                changed,
                testObservation(changed, 10),
            );
        }
        try testing.expect(refresh.observation_changed);
        try testing.expectEqual(
            !std.mem.eql(
                u8,
                profile.payload_route,
                profile.post_script_route,
            ),
            refresh.effective_routes_changed,
        );
        try testing.expectEqualStrings(
            profile.post_script_route,
            cache.index.physical(source, "diversion-lifecycle"),
        );
        const intent: Digest = @splat('1');
        const authenticated_bytes = try native_diversion_cache.encode(
            testing.allocator,
            cache,
            intent,
        );
        defer testing.allocator.free(authenticated_bytes);
        var authenticated = try native_diversion_cache.decode(
            testing.allocator,
            authenticated_bytes,
            intent,
        );
        defer authenticated.deinit();

        const settlement = try successSettlement(
            owned,
            if (profile.removal_route != null)
                profile.payload_route
            else
                null,
        );
        const backup_entries: []const native_unpack_diversion.Backup =
            if (profile.backup == .none)
                &.{}
            else
                try owned.dupe(
                    native_unpack_diversion.Backup,
                    &.{successBackup(profile, source)},
                );
        var publication = try native_diversion.CachedRecords.init(
            testing.allocator,
            initial_bytes,
            initial_observation,
        );
        defer publication.deinit();
        const parent_bytes = try native_unpack_diversion.encodeWithSettlement(
            testing.allocator,
            publication,
            intent,
            7,
            backup_entries,
            settlement,
        );
        defer testing.allocator.free(parent_bytes);
        var parent = try native_unpack_diversion.decode(
            testing.allocator,
            parent_bytes,
            intent,
            7,
        );
        defer parent.deinit();

        var md5: native_program.Md5Digest = undefined;
        try testing.expectEqual(md5.len, profile.recorded_md5.len);
        @memcpy(&md5, profile.recorded_md5);
        const associations: []const Association =
            if (profile.removal_route) |route_source|
                try owned.dupe(Association, &.{.{
                    .write_index = 0,
                    .kind = .removal,
                    .route = route_source,
                }})
            else
                &.{};
        const trigger_source: TriggerSource =
            if (profile.trigger_paths.len == 0)
                .none
            else if (profile.trigger_paths.len == 2)
                .logical_and_payload
            else
                .payload;
        const conffile: ?ConffileExpectation =
            if (std.mem.eql(u8, profile.member, "conffile"))
                .{
                    .staging = profile.staging,
                    .recorded_md5 = md5,
                }
            else
                null;
        const routes = [_]Route{.{
            .logical_path = source,
            .payload_route = profile.payload_route,
            .post_script_route = .{ .cache = .{
                .digest_sha256 = authenticated.digest_sha256,
            } },
            .settlement = associations,
            .trigger_source = trigger_source,
            .ownership = profile.ownership,
            .backup = profile.backup,
            .conffile = conffile,
        }};
        const contract: Contract = .{
            .intent_sha256 = intent,
            .program_step = 7,
            .unpack_input_sha256 = parent.digest_sha256,
            .package = .{
                .name = "diversion-lifecycle",
                .architecture = "amd64",
            },
            .routes = &routes,
        };
        const lowered = try lowerSuccess(
            owned,
            contract,
            &parent,
            &authenticated,
        );
        const successful_outcome = try lowerOutcome(
            owned,
            contract,
            &parent,
            &authenticated,
            .postrm_succeeded,
        );
        try testing.expect(successful_outcome.publish_settlement);
        try testing.expectEqual(
            lowered.intents.len,
            successful_outcome.settlement_intents.len,
        );
        try testing.expectEqual(@as(usize, 0), successful_outcome.partial_routes.len);
        try testing.expect(!std.mem.eql(
            u8,
            &lowered.phase_sha256,
            &successful_outcome.phase_sha256,
        ));
        if (std.mem.eql(u8, profile.update, "atomic")) {
            const rolled_back = try lowerOutcome(
                owned,
                contract,
                &parent,
                &authenticated,
                .rollback,
            );
            try testing.expect(!rolled_back.publish_settlement);
            try testing.expectEqual(
                @as(usize, 0),
                rolled_back.settlement_intents.len,
            );
            try testing.expectEqual(
                @as(usize, 1),
                rolled_back.partial_routes.len,
            );
            const expected_disposition: PartialDisposition =
                if (std.mem.eql(u8, profile.member, "conffile"))
                    .retain_conffile_staging
                else if (profile.ownership == .previous)
                    .restore_previous
                else
                    .retain_incoming;
            try testing.expectEqual(
                expected_disposition,
                rolled_back.partial_routes[0].disposition,
            );
            if (std.mem.eql(u8, profile.member, "regular")) {
                const unwound = try lowerOutcome(
                    owned,
                    contract,
                    &parent,
                    &authenticated,
                    .unwind_succeeded,
                );
                try testing.expect(unwound.publish_settlement);
            }
            if (std.mem.eql(u8, profile.member, "regular") or
                std.mem.eql(u8, profile.member, "conffile"))
            {
                const postinst_failed = try lowerOutcome(
                    owned,
                    contract,
                    &parent,
                    &authenticated,
                    .postinst_failed,
                );
                try testing.expect(postinst_failed.publish_settlement);
            }
        }
        try testing.expectEqualStrings(
            profile.post_script_route,
            lowered.routes[0].post_script_route,
        );
        try testing.expectEqual(
            !std.mem.eql(
                u8,
                profile.payload_route,
                profile.post_script_route,
            ),
            lowered.routes[0].route_changed,
        );
        try testing.expectEqual(profile.backup, lowered.routes[0].backup);
        try testing.expectEqual(
            profile.ownership,
            lowered.routes[0].ownership,
        );
        try testing.expectEqual(
            @as(usize, @intFromBool(profile.backup == .discard)),
            lowered.cleanup_intents.len,
        );
        try testing.expectEqual(
            profile.trigger_paths.len,
            lowered.routes[0].trigger_paths.len,
        );
        for (
            profile.trigger_paths,
            lowered.routes[0].trigger_paths,
        ) |expected, actual|
            try testing.expectEqualStrings(expected, actual);
        const expected_bound_paths: usize =
            @as(usize, @intFromBool(lowered.routes[0].route_changed)) +
            @as(usize, @intFromBool(profile.backup != .none)) +
            @as(usize, @intFromBool(profile.staging != .absent));
        try testing.expectEqual(expected_bound_paths, lowered.bound_paths.len);
        try testing.expectEqual(
            lowered.bound_paths.len,
            lowered.observed_paths.len,
        );
        for (lowered.bound_paths, lowered.observed_paths) |bound, observed|
            try testing.expectEqualStrings(bound.path, observed);
        if (lowered.routes[0].route_changed) {
            const bound = lowered.bound_paths[0];
            try testing.expectEqualStrings(profile.post_script_route, bound.path);
            try testing.expectEqual(PathExpectation.absent, bound.expectation);
        }
        if (profile.backup != .none) {
            const expected_backup_path = try std.fmt.allocPrint(
                owned,
                "{s}.dpkg-tmp",
                .{profile.payload_route},
            );
            try testing.expectEqualStrings(
                expected_backup_path,
                lowered.routes[0].backup_path.?,
            );
            const bound = lowered.bound_paths[
                @as(usize, @intFromBool(lowered.routes[0].route_changed))
            ];
            try testing.expectEqualStrings(expected_backup_path, bound.path);
            try testing.expectEqual(PathExpectation.backup, bound.expectation);
            try testing.expect(bound.backup != null);
            if (profile.backup == .discard) {
                try testing.expectEqualStrings(
                    expected_backup_path,
                    lowered.cleanup_intents[0].remove.path,
                );
                try testing.expectEqual(
                    root_mutation.Removal.require_present,
                    lowered.cleanup_intents[0].remove.removal,
                );
            }
        }
        if (profile.staging != .absent) {
            const expected_staged_path = try std.fmt.allocPrint(
                owned,
                "{s}.dpkg-new",
                .{profile.payload_route},
            );
            try testing.expectEqualStrings(
                expected_staged_path,
                lowered.routes[0].conffile.?.staged_path.?,
            );
            const bound = lowered.bound_paths[
                @as(usize, @intFromBool(lowered.routes[0].route_changed)) +
                    @as(usize, @intFromBool(profile.backup != .none))
            ];
            try testing.expectEqualStrings(expected_staged_path, bound.path);
            try testing.expectEqual(
                PathExpectation.present_regular,
                bound.expectation,
            );
        }
        if (profile.removal_route != null) {
            try testing.expectEqualStrings(
                profile.post_script_route,
                lowered.intents[0].remove.path,
            );
            try testing.expectEqual(
                root_mutation.Removal.require_absent,
                lowered.intents[0].remove.removal,
            );
        }
        const status = lowered.intents[lowered.intents.len - 1].file;
        const expected_conffile = try std.fmt.allocPrint(
            owned,
            "/etc/debz-native.conf {s}",
            .{profile.recorded_md5},
        );
        try testing.expect(
            std.mem.indexOf(u8, status.bytes, expected_conffile) != null,
        );
        try testing.expectEqual(status.bytes.len, lowered.evidence.resulting_status.size);
        const expected_sha256 = status.expected_sha256 orelse unreachable;
        try testing.expectEqualSlices(
            u8,
            &expected_sha256,
            &lowered.evidence.resulting_status.sha256,
        );
        const original_evidence = try settlement.evidence();
        try testing.expect(!std.mem.eql(
            u8,
            &original_evidence.digest,
            &lowered.evidence.digest,
        ));
        const original_phase: [32]u8 = @splat(0x84);
        try testing.expect(!std.mem.eql(
            u8,
            &original_phase,
            &lowered.phase_sha256,
        ));
    }
}

test "native_unpack.test.success route settlement rejects unexpected occupants" {
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    const selected = BoundPath{
        .path = "usr/share/demo.changed",
        .expectation = .absent,
    };
    try root.createDirectoryPath(
        try root_fs.Path.init("usr/share"),
        .fromMode(0o755),
    );
    try validateBoundPaths(testing.allocator, root, &.{selected});
    try root.publishFile(
        try root_fs.Path.init(selected.path),
        "unexpected",
        .{ .overwrite = .fail_if_exists },
    );
    try testing.expectError(
        error.UnexpectedUnpackRouteOccupant,
        validateBoundPaths(testing.allocator, root, &.{selected}),
    );
    const retained = BoundPath{
        .path = selected.path,
        .expectation = .present_regular,
    };
    try validateBoundPaths(testing.allocator, root, &.{retained});
    try root.removeFile(try root_fs.Path.init(selected.path));
    try root.createSymbolicLink(
        try root_fs.Path.init(selected.path),
        "elsewhere",
    );
    try testing.expectError(
        error.UnpackRouteArtifactMismatch,
        validateBoundPaths(testing.allocator, root, &.{retained}),
    );
    try testing.expectError(
        error.UnpackRouteArtifactMissing,
        validateBoundPaths(testing.allocator, root, &.{.{
            .path = "usr/share/missing.dpkg-tmp",
            .expectation = .present_regular,
        }}),
    );
}

test "native_unpack.test.success route settlement authenticates retained backups" {
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    try root.createDirectoryPath(
        try root_fs.Path.init("usr/share"),
        .fromMode(0o755),
    );
    const path = try root_fs.Path.init("usr/share/demo.dpkg-tmp");
    try root.publishFile(path, "old\n", .{
        .permissions = .fromMode(0o640),
        .overwrite = .fail_if_exists,
    });
    try root.applyMetadata(path, .{
        .mode = 0o640,
        .modified_nanoseconds = 123456789,
    });
    const entry = try root.entry(path);
    var content_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("old\n", &content_sha256, .{});
    const backup: native_unpack_diversion.Backup = .{
        .path = "usr/share/demo",
        .logical_path = "usr/share/demo",
        .kind = .regular,
        .mode = entry.mode,
        .uid = entry.uid,
        .gid = entry.gid,
        .size = entry.size,
        .device = entry.device,
        .inode = entry.inode,
        .modified_nanoseconds = entry.modified_nanoseconds,
        .backup_modified_nanoseconds = entry.modified_nanoseconds,
        .content_sha256 = native_recovery.hexDigest(content_sha256),
    };
    const bound = BoundPath{
        .path = path.text,
        .expectation = .backup,
        .backup = backup,
    };
    try validateBoundPaths(testing.allocator, root, &.{bound});
    try root.publishFile(path, "old\n", .{ .overwrite = .replace });
    try root.applyMetadata(path, .{
        .mode = backup.mode,
        .uid = backup.uid,
        .gid = backup.gid,
        .modified_nanoseconds = backup.backup_modified_nanoseconds,
    });
    try testing.expectError(
        error.UnpackRouteArtifactMismatch,
        validateBoundPaths(testing.allocator, root, &.{bound}),
    );

    const symlink_path = try root_fs.Path.init(
        "usr/share/current.dpkg-tmp",
    );
    try root.createSymbolicLink(symlink_path, "data");
    try root.applyMetadata(symlink_path, .{
        .modified_nanoseconds = 223456789,
    });
    const symlink_entry = try root.entry(symlink_path);
    const symlink_backup: native_unpack_diversion.Backup = .{
        .path = "usr/share/current",
        .logical_path = "usr/share/current",
        .kind = .symlink,
        .mode = symlink_entry.mode,
        .uid = symlink_entry.uid,
        .gid = symlink_entry.gid,
        .size = symlink_entry.size,
        .device = symlink_entry.device,
        .inode = symlink_entry.inode,
        .modified_nanoseconds = 123456789,
        .backup_modified_nanoseconds = symlink_entry.modified_nanoseconds,
        .link_target = "data",
    };
    const symlink_bound = BoundPath{
        .path = symlink_path.text,
        .expectation = .backup,
        .backup = symlink_backup,
    };
    try validateBoundPaths(testing.allocator, root, &.{symlink_bound});
    try root.removeFile(symlink_path);
    try root.createSymbolicLink(symlink_path, "other");
    try root.applyMetadata(symlink_path, .{
        .modified_nanoseconds = symlink_backup.backup_modified_nanoseconds,
    });
    try testing.expectError(
        error.UnpackRouteArtifactMismatch,
        validateBoundPaths(testing.allocator, root, &.{symlink_bound}),
    );
}

test "native_recovery.test.route settlement evidence survives fresh recovery and rejects drift" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    try root.createDirectoryPath(
        try root_fs.Path.init(root_operation.namespace_path),
        .fromMode(0o755),
    );
    try root.createDirectoryPath(
        try root_fs.Path.init("usr/share/demo"),
        .fromMode(0o755),
    );

    const intent: Digest = @splat('1');
    const program_step: u32 = 7;
    const source = "usr/share/demo/file";
    const original =
        "/usr/share/demo/file\n/usr/share/demo/file.original\n:\n";
    const changed =
        "/usr/share/demo/file\n/usr/share/demo/file.changed\n:\n";
    var publication = try native_diversion.CachedRecords.init(
        testing.allocator,
        original,
        testObservation(original, 9),
    );
    defer publication.deinit();
    var post_script = try native_diversion.CachedRecords.init(
        testing.allocator,
        changed,
        testObservation(changed, 10),
    );
    defer post_script.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const settlement = try successSettlement(arena.allocator(), null);
    const unpack_bytes = try native_unpack_diversion.encodeWithSettlement(
        testing.allocator,
        publication,
        intent,
        program_step,
        &.{},
        settlement,
    );
    defer testing.allocator.free(unpack_bytes);
    var unpack = try native_unpack_diversion.decode(
        testing.allocator,
        unpack_bytes,
        intent,
        program_step,
    );
    defer unpack.deinit();

    const cache_bytes = try native_diversion_cache.encode(
        testing.allocator,
        post_script,
        intent,
    );
    defer testing.allocator.free(cache_bytes);
    const publication_cache_bytes = try native_diversion_cache.encode(
        testing.allocator,
        publication,
        intent,
    );
    defer testing.allocator.free(publication_cache_bytes);
    var cache = try native_diversion_cache.decode(
        testing.allocator,
        cache_bytes,
        intent,
    );
    defer cache.deinit();
    const routes = [_]Route{.{
        .logical_path = source,
        .payload_route = "usr/share/demo/file.original",
        .post_script_route = .{ .cache = .{
            .digest_sha256 = cache.digest_sha256,
        } },
        .settlement = &.{},
        .trigger_source = .payload,
        .ownership = .previous_and_resulting,
        .backup = .none,
    }};
    const contract: Contract = .{
        .intent_sha256 = intent,
        .program_step = program_step,
        .unpack_input_sha256 = unpack.digest_sha256,
        .package = .{ .name = "demo", .architecture = "amd64" },
        .routes = &routes,
    };
    const route_bytes = try encode(testing.allocator, contract);
    defer testing.allocator.free(route_bytes);
    const lowered = try lowerOutcome(
        arena.allocator(),
        contract,
        &unpack,
        &cache,
        .postrm_succeeded,
    );
    try root.createDirectoryPath(
        try root_fs.Path.init(package_database.database_directory),
        .fromMode(0o755),
    );
    const preflight = try root_mutation.preflight(
        testing.allocator,
        root,
        .{ .intents = lowered.settlement_intents },
    );
    var plan = switch (preflight) {
        .plan => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer plan.deinit();
    const journal: root_mutation.Journal = .{
        .attempt_id = @splat(1),
        .attempt_generation = 1,
        .attempt_digest_sha256 = @splat(2),
        .install_root = "/fixture",
        .root_identity_sha256 = @splat(3),
        .evidence = .{
            .database_plan_sha256 = lowered.evidence.digest,
        },
        .device = plan.device,
        .staging_bytes = plan.staging_bytes,
        .budget_bytes = plan.staging_bytes,
        .steps = plan.steps,
        .steps_sha256 = plan.steps_sha256,
        .digest_sha256 = @splat(4),
    };
    try validateJournal(lowered, journal);
    var unrelated = journal;
    unrelated.evidence.database_plan_sha256 = null;
    try testing.expectError(
        error.InvalidUnpackRouteSettlementJournal,
        validateJournal(lowered, unrelated),
    );
    const changed_steps = try testing.allocator.dupe(
        root_mutation.Step,
        plan.steps,
    );
    defer testing.allocator.free(changed_steps);
    changed_steps[0].path = "var/lib/dpkg/unrelated";
    var changed_journal = journal;
    changed_journal.steps = changed_steps;
    try testing.expectError(
        error.InvalidUnpackRouteSettlementJournal,
        validateJournal(lowered, changed_journal),
    );

    try native_recovery.initializeProgress(
        testing.allocator,
        root,
        intent,
    );
    try native_recovery.initializeManagedState(
        testing.allocator,
        root,
        intent,
    );
    const action: native_recovery.Action = .{
        .kind = .filesystem,
        .program_step = program_step,
        .substep = 0,
        .ordinal = 0,
    };
    var unpack_path_buffer: [128]u8 = undefined;
    const unpack_path = try native_recovery.unpackDiversionPath(
        program_step,
        &unpack_path_buffer,
    );
    _ = try native_recovery.updateManagedState(
        testing.allocator,
        root,
        intent,
        action,
        &.{unpack_path},
        false,
    );
    var route_path_buffer: [128]u8 = undefined;
    const route_path = try native_recovery.unpackRouteSettlementPath(
        program_step,
        &route_path_buffer,
    );
    try root.publishFile(
        try root_fs.Path.init(unpack_path),
        unpack_bytes,
        .{},
    );
    try root.publishFile(
        try root_fs.Path.init(route_path),
        route_bytes,
        .{},
    );
    try root.publishFile(
        try root_fs.Path.init(native_recovery.diversion_cache_path),
        publication_cache_bytes,
        .{ .permissions = .fromMode(0o600) },
    );
    _ = try native_recovery.updateManagedState(
        testing.allocator,
        root,
        intent,
        action,
        &.{
            unpack_path,
            route_path,
            native_recovery.diversion_cache_path,
            "usr/share/demo/file.changed",
        },
        false,
    );
    try root.publishFile(
        try root_fs.Path.init(native_recovery.diversion_cache_path),
        cache_bytes,
        .{
            .permissions = .fromMode(0o600),
            .overwrite = .replace,
        },
    );

    try root.publishFile(
        try root_fs.Path.init("caller-archive.deb"),
        "caller owned",
        .{},
    );
    try root.removeFile(try root_fs.Path.init("caller-archive.deb"));
    const recovered_root = root_fs.Root.init(testing.io, temporary.dir);
    try verifyUncheckpointedCacheTransition(
        testing.allocator,
        recovered_root,
        intent,
        program_step,
        true,
    );
    const cache_path = try root_fs.Path.init(
        native_recovery.diversion_cache_path,
    );
    try recovered_root.applyMetadata(cache_path, .{ .mode = 0o640 });
    try testing.expectError(
        error.ManagedStateChanged,
        verifyUncheckpointedCacheTransition(
            testing.allocator,
            recovered_root,
            intent,
            program_step,
            true,
        ),
    );
    try recovered_root.applyMetadata(cache_path, .{ .mode = 0o600 });
    try testing.expectError(
        error.ManagedStateChanged,
        verifyManagedRecoveryState(
            testing.allocator,
            recovered_root,
            intent,
            program_step,
            .postrm_succeeded,
            true,
        ),
    );
    _ = try native_recovery.updateManagedState(
        testing.allocator,
        recovered_root,
        intent,
        .{
            .kind = .script,
            .program_step = program_step + 1,
            .substep = 0,
            .ordinal = 0,
        },
        &.{
            native_recovery.diversion_cache_path,
            "usr/share/demo/file.changed",
        },
        false,
    );
    try verifyManagedRecoveryState(
        testing.allocator,
        recovered_root,
        intent,
        program_step,
        .postrm_succeeded,
        true,
    );
    try verifyManagedRecoveryState(
        testing.allocator,
        recovered_root,
        intent,
        program_step,
        .postrm_succeeded,
        true,
    );

    try recovered_root.publishFile(
        try root_fs.Path.init("usr/share/demo/file.changed"),
        "drift",
        .{},
    );
    try testing.expectError(
        error.UnexpectedUnpackRouteOccupant,
        verifyManagedRecoveryState(
            testing.allocator,
            recovered_root,
            intent,
            program_step,
            .postrm_succeeded,
            true,
        ),
    );
    try recovered_root.removeFile(
        try root_fs.Path.init("usr/share/demo/file.changed"),
    );
    try recovered_root.publishFile(
        try root_fs.Path.init(route_path),
        "{}\n",
        .{ .overwrite = .replace },
    );
    try testing.expectError(
        error.ManagedStateChanged,
        verifyManagedRecoveryState(
            testing.allocator,
            recovered_root,
            intent,
            program_step,
            .postrm_succeeded,
            true,
        ),
    );
}

fn testCodecAllocations(allocator: std.mem.Allocator) !void {
    const routes = [_]Route{testRoute("usr/bin/demo")};
    const contract = testContract(&routes);
    const bytes = try encode(allocator, contract);
    defer allocator.free(bytes);
    var decoded = try decode(
        allocator,
        bytes,
        contract.intent_sha256,
        contract.program_step,
        contract.unpack_input_sha256,
    );
    defer decoded.deinit();
}

test "native_unpack.test.route settlement codec releases partial allocations" {
    try testing.checkAllAllocationFailures(testing.allocator, testCodecAllocations, .{});
}

const std = @import("std");
const native_diversion = @import("native_diversion.zig");
const native_diversion_cache = @import("native_diversion_cache.zig");
const native_program = @import("native_program.zig");
const native_recovery = @import("native_recovery.zig");
const native_unpack_diversion = @import("native_unpack_diversion.zig");
const native_unpack_settlement = @import("native_unpack_settlement.zig");
const package_database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");
const root_mutation = @import("root_mutation.zig");

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
    trigger_paths: []const []const u8,
    ownership: OwnershipExpectation,
    backup: BackupExpectation,
    backup_path: ?[]const u8,
    conffile: ?LoweredConffile,
};

pub const Lowered = struct {
    intents: []const root_mutation.Intent,
    routes: []const LoweredRoute,
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
    var document: Document = .{
        .version = contract.version,
        .capability = contract.capability,
        .intent_sha256 = contract.intent_sha256,
        .program_step = contract.program_step,
        .unpack_input_sha256 = contract.unpack_input_sha256,
        .package = contract.package,
        .aliases = .{ .items = contract.aliases },
        .routes = .{ .items = contract.routes },
    };
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
    unpack_input_sha256: Digest,
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
        !std.mem.eql(u8, &document.unpack_input_sha256, &unpack_input_sha256) or
        !std.mem.eql(u8, &document.digest_sha256, &documentDigest(document)))
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

/// Returned collections and derived paths use `allocator`; borrowed contract
/// and unpack-input strings must outlive the result.
pub fn lower(
    allocator: std.mem.Allocator,
    contract: Contract,
    unpack_input: *const native_unpack_diversion.Decoded,
    route_cache: ?*const native_diversion_cache.Decoded,
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
        if (backup_path) |path|
            try claimSidePath(allocator, &physical_routes, path, route_index);
        if (conffile) |expectation|
            if (expectation.staged_path) |path|
                try claimSidePath(allocator, &physical_routes, path, route_index);

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
                .remove => |*value| value.path = destination,
                .remove_directory => |*value| value.path = destination,
                else => return error.InvalidUnpackRouteSettlement,
            }
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
    return .{ .intents = intents, .routes = lowered_routes };
}

const testing = std.testing;

fn testObservation(bytes: []const u8, inode: u64) native_diversion.Observation {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .device = 7, .inode = inode, .sha256 = digest };
}

fn testSettlement(allocator: std.mem.Allocator) !native_unpack_settlement.Plan {
    const status = "Package: demo\nStatus: install ok unpacked\n\n";
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
            .post_script_route = .{ .path = "etc/demo.conf.changed" },
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

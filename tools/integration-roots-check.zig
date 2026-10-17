const std = @import("std");
const fs = @import("debz").root_fs;

const maximum_json_bytes = 16 * 1024 * 1024;

fn equalValue(left: std.json.Value, right: std.json.Value) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    return switch (left) {
        .string => |text| std.mem.eql(u8, text, right.string),
        .integer => |number| number == right.integer,
        .bool => |boolean| boolean == right.bool,
        .null => true,
        .array => |arr| {
            if (arr.items.len != right.array.items.len) return false;
            for (arr.items, right.array.items) |a, b| {
                if (!equalValue(a, b)) return false;
            }
            return true;
        },
        .object => |obj| {
            if (obj.count() != right.object.count()) return false;
            var it = obj.iterator();
            while (it.next()) |entry| {
                const other = right.object.get(entry.key_ptr.*) orelse return false;
                if (!equalValue(entry.value_ptr.*, other)) return false;
            }
            return true;
        },
        else => false,
    };
}

fn natural(value: std.json.Value) !usize {
    if (value != .integer or value.integer < 0) return error.InvalidSchema;
    return @intCast(value.integer);
}

fn isHexLower(text: []const u8, expected_len: usize) bool {
    if (text.len != expected_len) return false;
    for (text) |ch| {
        if (!std.ascii.isDigit(ch) and (ch < 'a' or ch > 'f')) return false;
    }
    return true;
}

fn isArchToken(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '-') return false;
    }
    return true;
}

fn matchesCasKeyPattern(text: []const u8, prefix: []const u8, has_second_digest: bool) bool {
    if (!std.mem.startsWith(u8, text, prefix)) return false;
    const rest = text[prefix.len..];
    if (has_second_digest) {
        if (rest.len < 1 + 1 + 64 + 1 + 64) return false;
        const tail = rest[rest.len - (1 + 64 + 1 + 64) ..];
        if (tail[0] != '-' or tail[65] != '-') return false;
        if (!isHexLower(tail[1..65], 64) or !isHexLower(tail[66..130], 64)) return false;
        return isArchToken(rest[0 .. rest.len - (1 + 64 + 1 + 64)]);
    } else {
        if (rest.len < 1 + 1 + 64 + 1) return false;
        const tail = rest[rest.len - (1 + 64 + 1) ..];
        if (tail[0] != '-' or tail[65] != '-') return false;
        if (!isHexLower(tail[1..65], 64)) return false;
        return isArchToken(rest[0 .. rest.len - (1 + 64 + 1)]);
    }
}

fn matchesSchemaPattern(pattern: []const u8, text: []const u8) !bool {
    const hex_token = "[0-9a-f]{" ++ "64}";
    if (std.mem.eql(u8, pattern, "^" ++ hex_token ++ "$")) {
        return isHexLower(text, 64);
    } else if (std.mem.eql(u8, pattern, "^debz-package-cas-v5-[A-Za-z0-9-]+-" ++ hex_token ++ "-" ++ hex_token ++ "$")) {
        return matchesCasKeyPattern(text, "debz-package-cas-v5-", true);
    } else if (std.mem.eql(u8, pattern, "^debz-package-cas-v5-[A-Za-z0-9-]+-" ++ hex_token ++ "-$")) {
        return matchesCasKeyPattern(text, "debz-package-cas-v5-", false);
    } else if (std.mem.eql(u8, pattern, "^debz-package-cas-v4-[A-Za-z0-9-]+-" ++ hex_token ++ "-" ++ hex_token ++ "$")) {
        return matchesCasKeyPattern(text, "debz-package-cas-v4-", true);
    } else if (std.mem.eql(u8, pattern, "^debz-package-cas-v4-[A-Za-z0-9-]+-" ++ hex_token ++ "-$")) {
        return matchesCasKeyPattern(text, "debz-package-cas-v4-", false);
    } else if (std.mem.eql(u8, pattern, "^/")) {
        return std.mem.startsWith(u8, text, "/");
    } else if (std.mem.eql(u8, pattern, "/packages-v2/objects$")) {
        return std.mem.endsWith(u8, text, "/packages-v2/objects");
    }
    return error.UnsupportedSchemaPattern;
}

fn schemaAllows(root: std.json.Value, schema: std.json.Value, instance: std.json.Value, depth: usize) anyerror!bool {
    if (depth > 16) return error.SchemaDepthExceeded;
    if (schema != .object) return error.InvalidSchema;
    var fields = schema.object.iterator();
    while (fields.next()) |field| {
        const key = field.key_ptr.*;
        const supported = [_][]const u8{
            "$schema",    "$id",                  "title",     "$defs",     "$ref",    "type",
            "const",      "enum",                 "oneOf",     "pattern",   "minimum", "maximum",
            "minItems",   "maxItems",             "minLength", "maxLength", "items",   "required",
            "properties", "additionalProperties",
        };
        var found = false;
        for (supported) |name| found = found or std.mem.eql(u8, name, key);
        if (!found) return error.UnsupportedSchemaKeyword;
    }
    if (depth == 0) {
        const meta = schema.object.get("$schema") orelse return error.InvalidSchema;
        if (meta != .string or !std.mem.eql(u8, meta.string, "https://json-schema.org/draft/2020-12/schema"))
            return error.InvalidSchema;
    }
    if (schema.object.get("$ref")) |reference| {
        if (reference != .string or !std.mem.startsWith(u8, reference.string, "#/$defs/")) return error.UnsupportedSchemaReference;
        const definitions = root.object.get("$defs") orelse return error.InvalidSchema;
        if (definitions != .object) return error.InvalidSchema;
        const target = definitions.object.get(reference.string["#/$defs/".len..]) orelse return error.InvalidSchema;
        if (!try schemaAllows(root, target, instance, depth + 1)) return false;
    }
    if (schema.object.get("type")) |kind| {
        if (kind != .string) return error.InvalidSchema;
        const matches = if (std.mem.eql(u8, kind.string, "object"))
            instance == .object
        else if (std.mem.eql(u8, kind.string, "array"))
            instance == .array
        else if (std.mem.eql(u8, kind.string, "string"))
            instance == .string
        else if (std.mem.eql(u8, kind.string, "integer"))
            instance == .integer
        else if (std.mem.eql(u8, kind.string, "boolean"))
            instance == .bool
        else if (std.mem.eql(u8, kind.string, "null"))
            instance == .null
        else
            return error.UnsupportedSchemaType;
        if (!matches) return false;
    }
    if (schema.object.get("const")) |expected| if (!equalValue(expected, instance)) return false;
    if (schema.object.get("enum")) |choices| {
        if (choices != .array) return error.InvalidSchema;
        var found = false;
        for (choices.array.items) |choice| found = found or equalValue(choice, instance);
        if (!found) return false;
    }
    if (schema.object.get("oneOf")) |choices| {
        if (choices != .array) return error.InvalidSchema;
        var matches: usize = 0;
        for (choices.array.items) |choice| matches += @intFromBool(try schemaAllows(root, choice, instance, depth + 1));
        if (matches != 1) return false;
    }
    if (schema.object.get("pattern")) |pattern| {
        if (pattern != .string) return error.InvalidSchema;
        if (instance == .string) {
            if (!try matchesSchemaPattern(pattern.string, instance.string)) return false;
        }
    }
    if (instance == .integer) {
        if (schema.object.get("minimum")) |min| {
            if (instance.integer < @as(i64, @intCast(try natural(min)))) return false;
        }
        if (schema.object.get("maximum")) |max| {
            if (instance.integer > @as(i64, @intCast(try natural(max)))) return false;
        }
    }
    if (instance == .string) {
        if (schema.object.get("minLength")) |min| if (instance.string.len < try natural(min)) return false;
        if (schema.object.get("maxLength")) |max| if (instance.string.len > try natural(max)) return false;
    }
    if (instance == .array) {
        if (schema.object.get("minItems")) |min| if (instance.array.items.len < try natural(min)) return false;
        if (schema.object.get("maxItems")) |max| if (instance.array.items.len > try natural(max)) return false;
        if (schema.object.get("items")) |item| {
            for (instance.array.items) |element| if (!try schemaAllows(root, item, element, depth + 1)) return false;
        }
    }
    if (instance == .object) {
        if (schema.object.get("required")) |names| {
            if (names != .array) return error.InvalidSchema;
            for (names.array.items) |name| {
                if (name != .string) return error.InvalidSchema;
                if (!instance.object.contains(name.string)) return false;
            }
        }
        const properties = schema.object.get("properties") orelse .null;
        if (properties != .null and properties != .object) return error.InvalidSchema;
        if (schema.object.get("additionalProperties")) |allowed| {
            if (allowed != .bool) return error.UnsupportedSchemaKeyword;
            if (!allowed.bool) {
                var keys = instance.object.iterator();
                while (keys.next()) |key| if (properties == .null or !properties.object.contains(key.key_ptr.*)) return false;
            }
        }
        if (properties == .object) {
            var keys = properties.object.iterator();
            while (keys.next()) |key| {
                if (instance.object.get(key.key_ptr.*)) |value| {
                    if (!try schemaAllows(root, key.value_ptr.*, value, depth + 1)) return false;
                }
            }
        }
    }
    return true;
}

fn readFileAlloc(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(maximum_json_bytes));
}

fn writeFileAll(io: std.Io, path: []const u8, bytes: []const u8) !void {
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
}

fn parseJsonSlice(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Value {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always });
    return parsed.value;
}

fn parseJsonFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !std.json.Value {
    const bytes = try readFileAlloc(io, allocator, path);
    return parseJsonSlice(allocator, bytes);
}

fn stringifyCompact(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn sha512Hex(bytes: []const u8) [128]u8 {
    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn getString(obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const v = obj.get(key) orelse return error.MissingJsonField;
    if (v != .string) return error.InvalidJsonFieldType;
    return v.string;
}

fn getInt(obj: std.json.ObjectMap, key: []const u8) !i64 {
    const v = obj.get(key) orelse return error.MissingJsonField;
    if (v != .integer) return error.InvalidJsonFieldType;
    return v.integer;
}

fn getBool(obj: std.json.ObjectMap, key: []const u8) !bool {
    const v = obj.get(key) orelse return error.MissingJsonField;
    if (v != .bool) return error.InvalidJsonFieldType;
    return v.bool;
}

fn getObject(obj: std.json.ObjectMap, key: []const u8) !std.json.ObjectMap {
    const v = obj.get(key) orelse return error.MissingJsonField;
    if (v != .object) return error.InvalidJsonFieldType;
    return v.object;
}

fn getArray(obj: std.json.ObjectMap, key: []const u8) ![]std.json.Value {
    const v = obj.get(key) orelse return error.MissingJsonField;
    if (v != .array) return error.InvalidJsonFieldType;
    return v.array.items;
}

fn verifyAndComputeLockDigest(allocator: std.mem.Allocator, lock: *std.json.Value) !void {
    const expected = try getString(lock.object, "digest_sha256");
    const expected_copy = try allocator.dupe(u8, expected);
    if (!lock.object.orderedRemove("digest_sha256")) return error.MissingLockDigest;
    const encoded = try stringifyCompact(allocator, lock.*);
    const actual = sha256Hex(encoded);
    if (!std.mem.eql(u8, &actual, expected_copy)) return error.LockDigestMismatch;
    try lock.object.put(allocator, "digest_sha256", .{ .string = expected_copy });
}

fn checkNativeLock(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 3) return error.InvalidCheckArguments;
    const legacy = try parseJsonFile(io, allocator, args[0]);
    var native = try parseJsonFile(io, allocator, args[1]);
    const cache_dir = args[2];

    if (legacy != .object or native != .object) return error.InvalidLockJson;
    if (!std.mem.eql(u8, try getString(native.object, "schema"), "https://debz.dev/schema/exact-closure-lock-v3"))
        return error.UnexpectedLockSchema;
    if ((try getInt(native.object, "version")) != 3) return error.UnexpectedLockVersion;
    if (!std.mem.eql(u8, try getString(native.object, "request_sha256"), try getString(legacy.object, "request_sha256")))
        return error.RequestDigestMismatch;

    const legacy_policy_hex = try getString(legacy.object, "policy_sha256");
    var legacy_policy_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&legacy_policy_bytes, legacy_policy_hex);
    var policy_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    policy_hasher.update("debz.product-native-solver-policy-v1\x00");
    policy_hasher.update(&legacy_policy_bytes);
    var policy_digest: [32]u8 = undefined;
    policy_hasher.final(&policy_digest);
    const expected_policy = std.fmt.bytesToHex(policy_digest, .lower);
    if (!std.mem.eql(u8, try getString(native.object, "policy_sha256"), &expected_policy))
        return error.PolicyDigestMismatch;

    const native_repos = try getArray(native.object, "repositories");
    const legacy_repos = try getArray(legacy.object, "repositories");
    if (native_repos.len != legacy_repos.len) return error.RepositoryCountMismatch;
    for (native_repos, legacy_repos) |repo_val, prev_val| {
        if (repo_val != .object or prev_val != .object) return error.InvalidRepositoryJson;
        const repo = repo_val.object;
        const prev = prev_val.object;
        for ([_][]const u8{ "id", "snapshot_sha256", "release_sha256", "signer_fingerprints" }) |field| {
            const left = repo.get(field) orelse return error.MissingRepositoryField;
            const right = prev.get(field) orelse return error.MissingRepositoryField;
            if (!equalValue(left, right)) return error.RepositoryFieldMismatch;
        }
        if (repo.contains("archive_binding")) return error.UnexpectedArchiveBinding;
        const index_identity = try getObject(repo, "index_identity");
        if (!std.mem.eql(u8, try getString(index_identity, "primary"), "sha256")) return error.InvalidIndexPrimary;
        const index_digests = try getArray(index_identity, "digests");
        if (index_digests.len != 1 or index_digests[0] != .object) return error.InvalidIndexDigests;
        if (!std.mem.eql(u8, try getString(index_digests[0].object, "algorithm"), "sha256") or
            !std.mem.eql(u8, try getString(index_digests[0].object, "digest"), try getString(prev, "index_sha256")))
            return error.IndexDigestMismatch;
    }

    const local_artifacts = try getArray(native.object, "local_artifacts");
    if (local_artifacts.len != 0) return error.UnexpectedLocalArtifacts;

    const native_packages = try getArray(native.object, "packages");
    const legacy_packages = try getArray(legacy.object, "packages");
    if (native_packages.len != legacy_packages.len) return error.PackageCountMismatch;
    for (native_packages, legacy_packages) |pkg_val, prev_val| {
        if (pkg_val != .object or prev_val != .object) return error.InvalidPackageJson;
        const pkg = pkg_val.object;
        const prev = prev_val.object;
        const origin = try getObject(pkg, "origin");
        if (!std.mem.eql(u8, try getString(origin, "type"), "authenticated_repository"))
            return error.UnexpectedOriginType;
        for ([_][]const u8{ "repository_id", "repository_snapshot_sha256" }) |field| {
            if (!std.mem.eql(u8, try getString(origin, field), try getString(prev, field)))
                return error.OriginFieldMismatch;
        }
        for ([_][]const u8{ "name", "version", "architecture", "declared_size", "retention", "dpkg_selection_hold" }) |field| {
            const left = pkg.get(field) orelse return error.MissingPackageField;
            const right = prev.get(field) orelse return error.MissingPackageField;
            if (!equalValue(left, right)) return error.PackageFieldMismatch;
        }
        if (pkg.contains("derived_archive_identity")) return error.UnexpectedDerivedArchiveIdentity;
        const identity = try getObject(pkg, "archive_identity");
        const primary = try getString(identity, "primary");
        if (!std.mem.eql(u8, primary, "sha512")) return error.UnexpectedArchivePrimary;
        const digests = try getArray(identity, "digests");
        var sha256_digest: ?[]const u8 = null;
        var sha512_digest: ?[]const u8 = null;
        for (digests) |d| {
            if (d != .object) return error.InvalidDigestEntry;
            const alg = try getString(d.object, "algorithm");
            const val = try getString(d.object, "digest");
            if (std.mem.eql(u8, alg, "sha256")) sha256_digest = val else if (std.mem.eql(u8, alg, "sha512")) sha512_digest = val else return error.UnexpectedDigestAlgorithm;
        }
        if (sha256_digest == null or !std.mem.eql(u8, sha256_digest.?, try getString(prev, "sha256")))
            return error.PackageSha256Mismatch;
        if (sha512_digest == null or sha512_digest.?.len != 128)
            return error.PackageSha512Mismatch;
        const object_path = try std.fmt.allocPrint(allocator, "{s}/packages-v2/objects/{s}-{s}", .{ cache_dir, primary, sha512_digest.? });
        const data = try readFileAlloc(io, allocator, object_path);
        const declared_size: usize = @intCast(try getInt(pkg, "declared_size"));
        if (data.len != declared_size) return error.PackageObjectSizeMismatch;
        if (!std.mem.eql(u8, &sha256Hex(data), sha256_digest.?)) return error.PackageObjectSha256Mismatch;
        if (!std.mem.eql(u8, &sha512Hex(data), sha512_digest.?)) return error.PackageObjectSha512Mismatch;
    }
    try verifyAndComputeLockDigest(allocator, &native);
}

fn validateCacheSchema(io: std.Io, allocator: std.mem.Allocator, value: std.json.Value, kind: []const u8, check_v4_rejected: bool) !void {
    const v5_path = try std.fmt.allocPrint(allocator, "schema/package-cache-{s}-v5.json", .{kind});
    const v5_schema = try parseJsonFile(io, allocator, v5_path);
    if (!try schemaAllows(v5_schema, v5_schema, value, 0)) return error.SchemaV5ValidationFailed;
    if (check_v4_rejected) {
        const v4_path = try std.fmt.allocPrint(allocator, "schema/package-cache-{s}-v4.json", .{kind});
        const v4_schema = try parseJsonFile(io, allocator, v4_path);
        if (try schemaAllows(v4_schema, v4_schema, value, 0)) return error.SchemaV4UnexpectedlyAccepted;
    }
}

fn checkNativeCachePrepare(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 5) return error.InvalidCheckArguments;
    const fingerprint = try parseJsonSlice(allocator, args[0]);
    const prepared = try parseJsonSlice(allocator, args[1]);
    const warm = try parseJsonSlice(allocator, args[2]);
    const lock = try parseJsonFile(io, allocator, args[3]);
    const archive = try readFileAlloc(io, allocator, args[4]);

    const lock_digest = try getString(lock.object, "digest_sha256");
    for ([_]struct { val: std.json.Value, kind: []const u8 }{
        .{ .val = fingerprint, .kind = "fingerprint" },
        .{ .val = prepared, .kind = "result" },
        .{ .val = warm, .kind = "result" },
    }) |item| {
        try validateCacheSchema(io, allocator, item.val, item.kind, true);
        if (!std.mem.eql(u8, try getString(item.val.object, "lock_digest"), lock_digest))
            return error.CacheLockDigestMismatch;
    }

    const fp_str = try getString(fingerprint.object, "fingerprint");
    if (!std.mem.eql(u8, try getString(prepared.object, "fingerprint"), fp_str) or
        !std.mem.eql(u8, try getString(warm.object, "fingerprint"), fp_str))
        return error.CacheFingerprintMismatch;

    const package_count: i64 = @intCast((try getArray(lock.object, "packages")).len);
    const prepared_downloaded = try getInt(prepared.object, "downloaded_count");
    const prepared_verified = try getInt(prepared.object, "verified_count");
    const prepared_reused = try getInt(prepared.object, "reused_count");
    const warm_downloaded = try getInt(warm.object, "downloaded_count");
    const warm_reused = try getInt(warm.object, "reused_count");
    if (prepared_downloaded != package_count or prepared_verified != package_count)
        return error.UnexpectedPreparedCount;
    if (prepared_reused != 0 or warm_downloaded != 0)
        return error.UnexpectedWarmOrReusedCount;
    if (warm_reused != prepared_verified)
        return error.WarmReusedCountMismatch;

    const magic = "debz-package-cache-archive-v3\n";
    if (!std.mem.startsWith(u8, archive, magic) or archive.len < magic.len + 4 + 32)
        return error.InvalidCacheArchiveFormat;
    const archive_count = std.mem.readInt(u32, archive[magic.len..][0..4], .big);
    if (archive_count != @as(u32, @intCast(package_count)))
        return error.CacheArchiveCountMismatch;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(archive[0 .. archive.len - 32], &digest, .{});
    if (!std.mem.eql(u8, &digest, archive[archive.len - 32 ..]))
        return error.CacheArchiveDigestMismatch;
}

fn checkNativeCachePartialExact(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 2) return error.InvalidCheckArguments;
    const partial = try parseJsonSlice(allocator, args[0]);
    const exact = try parseJsonSlice(allocator, args[1]);
    if ((try getInt(partial.object, "downloaded_count")) <= 0 or (try getInt(partial.object, "reused_count")) <= 0)
        return error.InvalidPartialCacheCounts;
    if ((try getInt(exact.object, "downloaded_count")) != 0)
        return error.InvalidExactDownloadedCount;
    if ((try getInt(exact.object, "reused_count")) != (try getInt(exact.object, "verified_count")))
        return error.InvalidExactReusedCount;
    if (!std.mem.eql(u8, try getString(partial.object, "fingerprint"), try getString(exact.object, "fingerprint")))
        return error.PartialExactFingerprintMismatch;
}

fn writeCacheFixture(io: std.Io, allocator: std.mem.Allocator, value: *std.json.Value, path: []const u8, name: []const u8) !void {
    _ = value.object.orderedRemove("digest_sha256");
    const req_digest = sha256Hex(name);
    try value.object.put(allocator, "request_sha256", .{ .string = try allocator.dupe(u8, &req_digest) });
    const encoded_without_digest = try stringifyCompact(allocator, value.*);
    const doc_digest = sha256Hex(encoded_without_digest);
    try value.object.put(allocator, "digest_sha256", .{ .string = try allocator.dupe(u8, &doc_digest) });
    const final_bytes = try stringifyCompact(allocator, value.*);
    try writeFileAll(io, path, final_bytes);
}

fn writeNativeCacheFixtures(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 4) return error.InvalidCheckArguments;
    const lock_bytes = try readFileAlloc(io, allocator, args[0]);

    var empty = try parseJsonSlice(allocator, lock_bytes);
    if ((try getInt(empty.object, "version")) != 3) return error.UnexpectedLockVersion;
    try empty.object.put(allocator, "repositories", .{ .array = std.json.Array.init(allocator) });
    try empty.object.put(allocator, "local_artifacts", .{ .array = std.json.Array.init(allocator) });
    try empty.object.put(allocator, "packages", .{ .array = std.json.Array.init(allocator) });
    try writeCacheFixture(io, allocator, &empty, args[1], "native-cache-empty");

    var mixed = try parseJsonSlice(allocator, lock_bytes);
    const packages = mixed.object.getPtr("packages").?.array.items;
    var base_dep_index: ?usize = null;
    for (packages, 0..) |pkg, idx| {
        if (std.mem.eql(u8, try getString(pkg.object, "name"), "base-dep")) {
            base_dep_index = idx;
            break;
        }
    }
    const pkg_idx = base_dep_index orelse return error.MissingBaseDepPackage;
    var pkg_obj = &packages[pkg_idx].object;
    const archive_identity = pkg_obj.get("archive_identity") orelse return error.MissingArchiveIdentity;
    const primary = try getString(archive_identity.object, "primary");
    const digests = try getArray(archive_identity.object, "digests");
    var artifact_id: ?std.json.Value = null;
    for (digests) |d| {
        if (std.mem.eql(u8, try getString(d.object, "algorithm"), primary)) {
            artifact_id = d;
            break;
        }
    }
    if (artifact_id == null) return error.MissingPrimaryDigest;

    var pkg_coord: std.json.ObjectMap = .empty;
    try pkg_coord.put(allocator, "name", .{ .string = try getString(pkg_obj.*, "name") });
    try pkg_coord.put(allocator, "version", .{ .string = try getString(pkg_obj.*, "version") });
    try pkg_coord.put(allocator, "architecture", .{ .string = try getString(pkg_obj.*, "architecture") });

    var artifact_obj: std.json.ObjectMap = .empty;
    try artifact_obj.put(allocator, "artifact_id", artifact_id.?);
    try artifact_obj.put(allocator, "archive_identity", archive_identity);
    try artifact_obj.put(allocator, "size", pkg_obj.get("declared_size").?);
    try artifact_obj.put(allocator, "package", .{ .object = pkg_coord });
    try artifact_obj.put(allocator, "acquisition_url", .{ .string = "file:/unused-native-cache-artifact.deb?REDACTED" });
    try artifact_obj.put(allocator, "trust_mode", .{ .string = "pinned_content_digest" });

    var origin_obj: std.json.ObjectMap = .empty;
    try origin_obj.put(allocator, "type", .{ .string = "local_artifact" });
    var art_it = artifact_obj.iterator();
    while (art_it.next()) |entry| {
        try origin_obj.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
    }
    try pkg_obj.put(allocator, "origin", .{ .object = origin_obj });

    var local_artifacts = std.json.Array.init(allocator);
    try local_artifacts.append(.{ .object = artifact_obj });
    try mixed.object.put(allocator, "local_artifacts", .{ .array = local_artifacts });
    try writeCacheFixture(io, allocator, &mixed, args[2], "native-cache-mixed");

    const mixed_bytes = try readFileAlloc(io, allocator, args[2]);
    var local = try parseJsonSlice(allocator, mixed_bytes);
    try local.object.put(allocator, "repositories", .{ .array = std.json.Array.init(allocator) });
    var single_pkg = std.json.Array.init(allocator);
    try single_pkg.append(local.object.get("packages").?.array.items[pkg_idx]);
    try local.object.put(allocator, "packages", .{ .array = single_pkg });
    try writeCacheFixture(io, allocator, &local, args[3], "native-cache-local");
}

fn checkNativeCacheEmpty(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 5) return error.InvalidCheckArguments;
    const fingerprint = try parseJsonSlice(allocator, args[0]);
    const prepared = try parseJsonSlice(allocator, args[1]);
    const restored = try parseJsonSlice(allocator, args[2]);
    const lock = try parseJsonFile(io, allocator, args[3]);
    const archive = try readFileAlloc(io, allocator, args[4]);

    if ((try getArray(lock.object, "packages")).len != 0 or
        (try getArray(lock.object, "repositories")).len != 0 or
        (try getArray(lock.object, "local_artifacts")).len != 0)
        return error.NonEmptyLockFixture;

    const lock_digest = try getString(lock.object, "digest_sha256");
    for ([_]struct { val: std.json.Value, kind: []const u8 }{
        .{ .val = fingerprint, .kind = "fingerprint" },
        .{ .val = prepared, .kind = "result" },
        .{ .val = restored, .kind = "result" },
    }) |item| {
        try validateCacheSchema(io, allocator, item.val, item.kind, false);
        if (!std.mem.eql(u8, try getString(item.val.object, "lock_digest"), lock_digest))
            return error.CacheLockDigestMismatch;
    }
    if ((try getInt(prepared.object, "verified_count")) != 0 or (try getInt(restored.object, "verified_count")) != 0)
        return error.UnexpectedEmptyVerifiedCount;
    const fp_str = try getString(fingerprint.object, "fingerprint");
    if (!std.mem.eql(u8, try getString(prepared.object, "fingerprint"), fp_str) or
        !std.mem.eql(u8, try getString(restored.object, "fingerprint"), fp_str))
        return error.CacheFingerprintMismatch;

    const body = "debz-package-cache-archive-v3\n\x00\x00\x00\x00";
    var body_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &body_digest, .{});
    if (archive.len != body.len + 32 or
        !std.mem.eql(u8, archive[0..body.len], body) or
        !std.mem.eql(u8, archive[body.len..], &body_digest))
        return error.EmptyArchiveMismatch;
}

fn checkNativeCacheMixedLocal(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 2) return error.InvalidCheckArguments;
    const mixed = try parseJsonSlice(allocator, args[0]);
    const local = try parseJsonSlice(allocator, args[1]);
    for ([_]std.json.Value{ mixed, local }) |val| {
        try validateCacheSchema(io, allocator, val, "result", false);
        if ((try getInt(val.object, "downloaded_count")) != 0) return error.UnexpectedDownloadedCount;
        if ((try getInt(val.object, "reused_count")) != (try getInt(val.object, "verified_count")))
            return error.ReusedVerifiedMismatch;
    }
    if ((try getInt(mixed.object, "verified_count")) != 2) return error.UnexpectedMixedVerifiedCount;
    if ((try getInt(local.object, "verified_count")) != 1) return error.UnexpectedLocalVerifiedCount;
}

fn checkSha256BoundLock(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 4) return error.InvalidCheckArguments;
    const bound_bytes = try readFileAlloc(io, allocator, args[0]);
    var lock = try parseJsonSlice(allocator, bound_bytes);
    const cache_dir = args[1];
    const legacy = try parseJsonFile(io, allocator, args[2]);
    const forged_path = args[3];

    if ((try getInt(lock.object, "version")) != 3) return error.UnexpectedLockVersion;
    const repos = try getArray(lock.object, "repositories");
    const legacy_repos = try getArray(legacy.object, "repositories");
    if (repos.len != 1 or legacy_repos.len != 1) return error.UnexpectedRepositoryCount;
    if (!std.mem.eql(u8, try getString(repos[0].object, "archive_binding"), "signed_sha256_derived_sha512"))
        return error.UnexpectedArchiveBinding;
    if (std.mem.eql(u8, try getString(repos[0].object, "id"), try getString(legacy_repos[0].object, "id")))
        return error.BoundRepositoryIdUnchanged;

    const packages = try getArray(lock.object, "packages");
    const legacy_packages = try getArray(legacy.object, "packages");
    if (packages.len != legacy_packages.len or packages.len == 0) return error.PackageCountMismatch;
    for (packages, legacy_packages) |pkg_val, prev_val| {
        const pkg = pkg_val.object;
        const prev = prev_val.object;
        const identity = try getObject(pkg, "archive_identity");
        const primary = try getString(identity, "primary");
        if (!std.mem.eql(u8, primary, "sha256")) return error.UnexpectedArchivePrimary;
        const digests = try getArray(identity, "digests");
        if (digests.len != 1 or !std.mem.eql(u8, try getString(digests[0].object, "algorithm"), primary))
            return error.InvalidArchiveDigests;
        const signed = try getString(digests[0].object, "digest");
        if (!std.mem.eql(u8, signed, try getString(prev, "sha256"))) return error.PackageSha256Mismatch;
        const derived = try getObject(pkg, "derived_archive_identity");
        if (!std.mem.eql(u8, try getString(derived, "provenance"), "derived_from_signed_sha256") or
            !std.mem.eql(u8, try getString(derived, "algorithm"), "sha512"))
            return error.InvalidDerivedIdentity;
        const derived_digest = try getString(derived, "digest");
        const obj_path = try std.fmt.allocPrint(allocator, "{s}/packages-v2/objects/{s}-{s}", .{ cache_dir, primary, signed });
        const data = try readFileAlloc(io, allocator, obj_path);
        const declared_size: usize = @intCast(try getInt(pkg, "declared_size"));
        if (data.len != declared_size) return error.PackageObjectSizeMismatch;
        if (!std.mem.eql(u8, &sha256Hex(data), signed)) return error.PackageObjectSha256Mismatch;
        if (!std.mem.eql(u8, &sha512Hex(data), derived_digest)) return error.PackageObjectSha512Mismatch;
    }
    try verifyAndComputeLockDigest(allocator, &lock);

    var forged = try parseJsonSlice(allocator, bound_bytes);
    _ = forged.object.orderedRemove("digest_sha256");
    for (forged.object.getPtr("repositories").?.array.items) |*repo| {
        _ = repo.object.orderedRemove("archive_binding");
    }
    for (forged.object.getPtr("packages").?.array.items) |*pkg| {
        _ = pkg.object.orderedRemove("derived_archive_identity");
    }
    const forged_without_digest = try stringifyCompact(allocator, forged);
    const forged_digest = sha256Hex(forged_without_digest);
    try forged.object.put(allocator, "digest_sha256", .{ .string = try allocator.dupe(u8, &forged_digest) });
    try writeFileAll(io, forged_path, try stringifyCompact(allocator, forged));

    const first_identity = try getObject(packages[0].object, "archive_identity");
    const first_primary = try getString(first_identity, "primary");
    const first_digests = try getArray(first_identity, "digests");
    const first_signed = try getString(first_digests[0].object, "digest");
    const out_line = try std.fmt.allocPrint(allocator, "{s}/packages-v2/objects/{s}-{s}\n", .{ cache_dir, first_primary, first_signed });
    try std.Io.File.stdout().writeStreamingAll(io, out_line);
}

fn pathExists(io: std.Io, path: []const u8) bool {
    var root = fs.openAbsoluteRoot(io, "/") catch return false;
    defer root.close();
    const rel = if (std.mem.startsWith(u8, path, "/")) path[1..] else path;
    const entry = root.root.entryIfExists(fs.Path.init(rel) catch return false) catch return false;
    return entry != null;
}

fn isRegularFilePath(io: std.Io, path: []const u8) bool {
    var root = fs.openAbsoluteRoot(io, "/") catch return false;
    defer root.close();
    const rel = if (std.mem.startsWith(u8, path, "/")) path[1..] else path;
    const entry = root.root.entryIfExists(fs.Path.init(rel) catch return false) catch return false;
    return if (entry) |e| e.isRegularFile() else false;
}

fn checkNativeExecution(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 2) return error.InvalidCheckArguments;
    const root = args[0];
    const lock = try parseJsonFile(io, allocator, args[1]);
    const packages = try getArray(lock.object, "packages");
    if (packages.len != 3) return error.UnexpectedExecutionPackageCount;
    var has_base = false;
    var has_essential = false;
    var has_helper = false;
    for (packages) |pkg| {
        const name = try getString(pkg.object, "name");
        if (std.mem.eql(u8, name, "base-dep")) has_base = true else if (std.mem.eql(u8, name, "essential-core")) has_essential = true else if (std.mem.eql(u8, name, "native-helper-target")) has_helper = true;
    }
    if (!has_base or !has_essential or !has_helper) return error.UnexpectedExecutionPackageSet;

    const receipt_path = try std.fmt.allocPrint(allocator, "{s}/var/lib/debz/native-transaction-provenance-v2.json", .{root});
    const completion_path = try std.fmt.allocPrint(allocator, "{s}/var/lib/debz/root-operation-completion-v2.json", .{root});
    const receipt = try parseJsonFile(io, allocator, receipt_path);
    const completion = try parseJsonFile(io, allocator, completion_path);

    if (!std.mem.eql(u8, try getString(receipt.object, "outcome"), "succeeded")) return error.UnexpectedReceiptOutcome;
    if (!std.mem.eql(u8, try getString(receipt.object, "backend"), "native") or
        !std.mem.eql(u8, try getString(completion.object, "backend"), "native"))
        return error.UnexpectedBackend;
    if (!std.mem.eql(u8, try getString(receipt.object, "attempt_id"), try getString(completion.object, "attempt_id")))
        return error.AttemptIdMismatch;
    if (!std.mem.eql(u8, try getString(receipt.object, "install_root"), root))
        return error.InstallRootMismatch;
    if (!std.mem.eql(u8, try getString(receipt.object, "exact_lock_sha256"), try getString(lock.object, "digest_sha256")))
        return error.ExactLockDigestMismatch;

    const tx_prov = try getObject(completion.object, "transaction_provenance");
    if (!std.mem.eql(u8, try getString(tx_prov, "schema"), try getString(receipt.object, "schema")) or
        !std.mem.eql(u8, try getString(tx_prov, "document_sha256"), try getString(receipt.object, "digest_sha256")))
        return error.TransactionProvenanceMismatch;

    const journal = try getObject(completion.object, "journal");
    if (!std.mem.eql(u8, try getString(journal, "status"), "absent")) return error.UnexpectedJournalStatus;

    for (try getArray(receipt.object, "evidence_files")) |ev| {
        const rel = try getString(ev.object, "path");
        const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, std.mem.trimStart(u8, rel, "/") });
        const data = try readFileAlloc(io, allocator, full);
        const expected_size: usize = @intCast(try getInt(ev.object, "size"));
        if (data.len != expected_size) return error.EvidenceFileSizeMismatch;
        if (!std.mem.eql(u8, &sha256Hex(data), try getString(ev.object, "sha256")))
            return error.EvidenceFileDigestMismatch;
    }

    const fixture_file = try std.fmt.allocPrint(allocator, "{s}/usr/share/debz-fixtures/base-dep", .{root});
    if (!isRegularFilePath(io, fixture_file)) return error.MissingBaseDepFixtureFile;
    const trigger_bin = try std.fmt.allocPrint(allocator, "{s}/usr/bin/dpkg-trigger", .{root});
    const trigger_bytes = try readFileAlloc(io, allocator, trigger_bin);
    if (!std.mem.startsWith(u8, trigger_bytes, "native-helper-target="))
        return error.UnexpectedDpkgTriggerPayload;

    for ([_][]const u8{ "root-operation-v1.json", "native-execution-intent-v2.json", "native-recovery-v1" }) |name| {
        const p = try std.fmt.allocPrint(allocator, "{s}/var/lib/debz/{s}", .{ root, name });
        if (pathExists(io, p)) return error.UnexpectedTransientStateFile;
    }
}

fn checkNativeTrigger(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 1) return error.InvalidCheckArguments;
    const root = args[0];
    const trace_path = try std.fmt.allocPrint(allocator, "{s}/native-trigger-trace", .{root});
    const trace = try readFileAlloc(io, allocator, trace_path);
    if (!std.mem.eql(u8, trace, "configure \ntriggered native-fixture\n"))
        return error.UnexpectedTriggerTrace;

    const receipt_path = try std.fmt.allocPrint(allocator, "{s}/var/lib/debz/native-transaction-provenance-v2.json", .{root});
    const receipt = try parseJsonFile(io, allocator, receipt_path);
    if (!std.mem.eql(u8, try getString(receipt.object, "outcome"), "succeeded"))
        return error.UnexpectedReceiptOutcome;

    var auth_rel: ?[]const u8 = null;
    for (try getArray(receipt.object, "evidence_files")) |ev| {
        if (std.mem.eql(u8, try getString(ev.object, "kind"), "authorization")) {
            auth_rel = try getString(ev.object, "path");
            break;
        }
    }
    const auth_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, std.mem.trimStart(u8, auth_rel orelse return error.MissingAuthorizationEvidence, "/") });
    const authorization = try parseJsonFile(io, allocator, auth_path);
    const trigger_authority = try getObject(authorization.object, "trigger_authority");
    const allowed = try getArray(trigger_authority, "allowed_triggers");
    if (allowed.len != 1 or allowed[0] != .string or !std.mem.eql(u8, allowed[0].string, "native-fixture"))
        return error.UnexpectedAllowedTriggers;

    const intent_path = try std.fmt.allocPrint(allocator, "{s}/var/lib/debz/native-execution-intent-v2.json", .{root});
    if (pathExists(io, intent_path)) return error.UnexpectedExecutionIntent;
}

fn checkBoundExecution(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 2) return error.InvalidCheckArguments;
    const root = args[0];
    const lock = try parseJsonFile(io, allocator, args[1]);
    const repos = try getArray(lock.object, "repositories");
    if (repos.len != 1 or !std.mem.eql(u8, try getString(repos[0].object, "archive_binding"), "signed_sha256_derived_sha512"))
        return error.UnexpectedArchiveBinding;
    for (try getArray(lock.object, "packages")) |pkg| {
        const identity = try getObject(pkg.object, "archive_identity");
        if (!std.mem.eql(u8, try getString(identity, "primary"), "sha256")) return error.UnexpectedArchivePrimary;
        const derived = try getObject(pkg.object, "derived_archive_identity");
        if (!std.mem.eql(u8, try getString(derived, "provenance"), "derived_from_signed_sha256"))
            return error.InvalidDerivedIdentity;
    }
    const receipt_path = try std.fmt.allocPrint(allocator, "{s}/var/lib/debz/native-transaction-provenance-v2.json", .{root});
    const receipt = try parseJsonFile(io, allocator, receipt_path);
    if (!std.mem.eql(u8, try getString(receipt.object, "outcome"), "succeeded") or
        !std.mem.eql(u8, try getString(receipt.object, "backend"), "native") or
        !std.mem.eql(u8, try getString(receipt.object, "exact_lock_sha256"), try getString(lock.object, "digest_sha256")))
        return error.BoundReceiptMismatch;

    const fixture_file = try std.fmt.allocPrint(allocator, "{s}/usr/share/debz-fixtures/base-dep", .{root});
    if (!isRegularFilePath(io, fixture_file)) return error.MissingBaseDepFixtureFile;
}

fn writeAbandonedStaging(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 2) return error.InvalidCheckArguments;
    const lock = try parseJsonFile(io, allocator, args[0]);
    const retry_cache = args[1];
    const packages = try getArray(lock.object, "packages");
    if (packages.len == 0) return error.EmptyLockPackages;
    const digest = try getString(packages[0].object, "sha256");
    if (digest.len < 8) return error.InvalidPackageDigest;

    var name_buf: [96]u8 = @splat('_');
    const prefix = try std.fmt.allocPrint(allocator, "package-{s}-0000000000000000.tmp", .{digest[0..8]});
    @memcpy(name_buf[0..prefix.len], prefix);

    const staging_rel = try std.fmt.allocPrint(allocator, "{s}/packages-v2/staging", .{retry_cache});
    try std.Io.Dir.cwd().createDirPath(io, staging_rel);
    const target_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ staging_rel, &name_buf });
    try writeFileAll(io, target_path, "abandoned");
}

fn checkCacheResult(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 2) return error.InvalidCheckArguments;
    const mode = args[0];
    const value = try parseJsonSlice(allocator, args[1]);
    if (value != .object) return error.InvalidResultJson;
    if (std.mem.eql(u8, mode, "cold")) {
        if ((try getInt(value.object, "downloaded_count")) != (try getInt(value.object, "verified_count")) or
            (try getInt(value.object, "reused_count")) != 0)
            return error.ColdCacheResultMismatch;
    } else if (std.mem.eql(u8, mode, "retried")) {
        const staging = try getObject(value.object, "staging");
        if ((try getInt(value.object, "downloaded_count")) != 0 or
            (try getInt(value.object, "reused_count")) != (try getInt(value.object, "verified_count")) or
            (try getInt(staging, "deleted")) < 1)
            return error.RetriedCacheResultMismatch;
    } else if (std.mem.eql(u8, mode, "exact")) {
        if ((try getInt(value.object, "downloaded_count")) != 0 or
            (try getInt(value.object, "reused_count")) != (try getInt(value.object, "verified_count")))
            return error.ExactCacheResultMismatch;
    } else if (std.mem.eql(u8, mode, "partial")) {
        if ((try getInt(value.object, "downloaded_count")) <= 0 or
            (try getInt(value.object, "reused_count")) <= 0)
            return error.PartialCacheResultMismatch;
    } else if (std.mem.eql(u8, mode, "pruned")) {
        const gc = try getObject(value.object, "gc");
        if ((try getInt(gc, "deleted")) <= 0 or !(try getBool(gc, "complete")))
            return error.PrunedCacheResultMismatch;
    } else if (std.mem.eql(u8, mode, "repaired")) {
        if ((try getInt(value.object, "downloaded_count")) != 1 or
            (try getInt(value.object, "reused_count")) + 1 != (try getInt(value.object, "verified_count")))
            return error.RepairedCacheResultMismatch;
    } else return error.UnknownCacheResultMode;
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) return error.MissingCheckSubcommand;
    const subcommand = args[0];
    const rest = args[1..];
    if (std.mem.eql(u8, subcommand, "native-lock")) {
        try checkNativeLock(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "native-cache-prepare")) {
        try checkNativeCachePrepare(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "native-cache-partial-exact")) {
        try checkNativeCachePartialExact(allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "write-native-cache-fixtures")) {
        try writeNativeCacheFixtures(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "native-cache-empty")) {
        try checkNativeCacheEmpty(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "native-cache-mixed-local")) {
        try checkNativeCacheMixedLocal(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "sha256-bound-lock")) {
        try checkSha256BoundLock(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "native-execution")) {
        try checkNativeExecution(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "native-trigger")) {
        try checkNativeTrigger(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "bound-execution")) {
        try checkBoundExecution(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "write-abandoned-staging")) {
        try writeAbandonedStaging(io, allocator, rest);
    } else if (std.mem.eql(u8, subcommand, "cache-result")) {
        try checkCacheResult(allocator, rest);
    } else return error.UnknownCheckSubcommand;
}

test "integration-roots-check validates v5 package-cache schemas and rejects v4" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const digest: [64]u8 = @splat('a');
    const fp_json =
        \\{"schema":"io.github.cataggar.debz.package-cache-fingerprint.v5","api_version":5,"capability":"package-cache-v5","lock_schema":"https://debz.dev/schema/exact-closure-lock-v3","lock_schema_version":3,"lock_digest":"
    ++ &digest ++
        \\","target_architecture":"amd64","abi":"debian-package-archive-v1","debz_version":"0.1.0","cas_layout":"packages-v2","archive_format":"debz-package-cache-archive-v3","payload_policy":"deb-payload-default-limits-v1","origin_mode":"exact-lock-v3-content-identities","acceptance_policy_digest":"
    ++ &digest ++
        \\","fingerprint":"
    ++ &digest ++
        \\","primary_key":"debz-package-cas-v5-amd64-
    ++ &digest ++ "-" ++ &digest ++
        \\","restore_prefix":"debz-package-cas-v5-amd64-
    ++ &digest ++
        \\-","cache_root":"/tmp/cache","cache_path":"/tmp/cache/packages-v2/objects","maximum_archive_bytes":8388608}
    ;
    const fp_val = try parseJsonSlice(allocator, fp_json);
    try validateCacheSchema(std.testing.io, allocator, fp_val, "fingerprint", true);
    try checkCacheResult(allocator, &.{ "cold", "{\"downloaded_count\":2,\"verified_count\":2,\"reused_count\":0}" });
    try std.testing.expectError(
        error.ColdCacheResultMismatch,
        checkCacheResult(allocator, &.{ "cold", "{\"downloaded_count\":1,\"verified_count\":2,\"reused_count\":0}" }),
    );
}

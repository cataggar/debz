const std = @import("std");
const options = @import("native_test_options");

fn equalValue(left: std.json.Value, right: std.json.Value) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    return switch (left) {
        .string => |text| std.mem.eql(u8, text, right.string),
        .integer => |number| number == right.integer,
        .bool => |boolean| boolean == right.bool,
        .null => true,
        else => false,
    };
}

fn natural(value: std.json.Value) !usize {
    if (value != .integer or value.integer < 0) return error.InvalidSchema;
    return @intCast(value.integer);
}

fn schemaAllows(root: std.json.Value, schema: std.json.Value, instance: std.json.Value, depth: usize) anyerror!bool {
    if (depth > 16) return error.SchemaDepthExceeded;
    if (schema != .object) return error.InvalidSchema;
    var fields = schema.object.iterator();
    while (fields.next()) |field| {
        const key = field.key_ptr.*;
        const supported = [_][]const u8{
            "$ref",  "type",     "additionalProperties", "required", "properties", "enum",
            "items", "maxItems", "minimum",              "maximum",  "maxLength",  "minLength",
            "oneOf", "pattern",  "const",
        };
        var found = false;
        for (supported) |name| found = found or std.mem.eql(u8, name, key);
        if (!found) return error.UnsupportedSchemaKeyword;
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
        if (pattern != .string or !std.mem.eql(u8, pattern.string, "^[0-9a-f]{64}$")) return error.UnsupportedSchemaPattern;
        if (instance == .string) {
            if (instance.string.len != 64) return false;
            for (instance.string) |character| {
                if (!std.ascii.isDigit(character) and (character < 'a' or character > 'f')) return false;
            }
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

test "published Draft 2020-12 scriptFailure closure validates compensation instances and bounds" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const filename = try std.fs.path.join(a, &.{ options.repository, "schema/native-transaction-program-v1.json" });
    var file = try std.Io.Dir.openFileAbsolute(std.testing.io, filename, .{ .follow_symlinks = false });
    defer file.close(std.testing.io);
    var reader = file.reader(std.testing.io, &.{});
    const bytes = try reader.interface.allocRemaining(a, .limited(256 * 1024));
    const schema = try std.json.parseFromSlice(std.json.Value, a, bytes, .{ .allocate = .alloc_always });
    var failure_spec = schema.value.object.get("$defs").?.object.get("scriptFailure").?;
    const digest = [_]u8{'a'} ** 64;
    const example = try std.fmt.allocPrint(a,
        \\{{"state":"half_installed","unwind":null,"resume_after_unwind":false,
        \\"compensations":[{{"kind":"postinst","source":"installed_package",
        \\"script_sha256":"{s}","arguments":["abort-upgrade","2"]}}],
        \\"rollback_after_compensations":0,"recovery_required":true}}
    , .{&digest});
    var failure = try std.json.parseFromSlice(std.json.Value, a, example, .{ .allocate = .alloc_always });
    try std.testing.expect(try schemaAllows(schema.value, failure_spec, failure.value, 0));
    const compensation = failure.value.object.get("compensations").?.array.items[0];
    for (0..7) |_| try failure.value.object.getPtr("compensations").?.array.append(compensation);
    try std.testing.expect(try schemaAllows(schema.value, failure_spec, failure.value, 0));
    try failure.value.object.getPtr("compensations").?.array.append(compensation);
    try std.testing.expect(!try schemaAllows(schema.value, failure_spec, failure.value, 0));
    failure.value.object.getPtr("compensations").?.array.items.len = 1;
    try failure.value.object.getPtr("compensations").?.array.items[0].object.put(a, "script_sha256", .{ .string = "not-a-digest" });
    try std.testing.expect(!try schemaAllows(schema.value, failure_spec, failure.value, 0));
    try failure.value.object.getPtr("compensations").?.array.items[0].object.put(a, "script_sha256", .{ .string = &digest });
    failure.value.object.getPtr("rollback_after_compensations").?.* = .{ .integer = 9 };
    try std.testing.expect(!try schemaAllows(schema.value, failure_spec, failure.value, 0));
    failure.value.object.getPtr("rollback_after_compensations").?.* = .{ .integer = 0 };
    try failure_spec.object.getPtr("properties").?.object.getPtr("compensations").?.object.put(a, "unknownKeyword", .{ .bool = true });
    try std.testing.expectError(error.UnsupportedSchemaKeyword, schemaAllows(schema.value, failure_spec, failure.value, 0));
    _ = failure_spec.object.getPtr("properties").?.object.getPtr("compensations").?.object.swapRemove("unknownKeyword");
    try failure.value.object.put(a, "unreviewed_compensation", .{ .bool = true });
    try std.testing.expect(!try schemaAllows(schema.value, failure_spec, failure.value, 0));
}

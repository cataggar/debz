const std = @import("std");

// The registry is deliberately closed: schema documents may refer to these
// repository-owned resources, never to the network or arbitrary filesystem.
const resources = .{
    .{ "system-profile-v1", "schema/system-profile-v1.json" },
    .{ "system-profile-v2", "schema/system-profile-v2.json" },
    .{ "apt-system-request-v1", "schema/apt-system-request-v1.json" },
    .{ "apt-system-result-v1", "schema/apt-system-result-v1.json" },
    .{ "apt-system-result-v2", "schema/apt-system-result-v2.json" },
    .{ "apt-system-result-v3", "schema/apt-system-result-v3.json" },
    .{ "apt-system-cli-diagnostic-v1", "schema/apt-system-cli-diagnostic-v1.json" },
    .{ "apt-system-operation-state-v1", "schema/apt-system-operation-state-v1.json" },
    .{ "frozen-request-v1", "tools/fixtures/apt-system-request-v1-origin-main.schema.json" },
    .{ "frozen-result-v2", "tools/fixtures/apt-system-result-v2-origin-main.schema.json" },
};

// 4,096 result items may each contain 4,096 code points plus other bounded
// fields; JSON escaping can expand each ASCII control code point sixfold.
pub const max_document_bytes = 192 * 1024 * 1024;
const max_schema_depth = 64;
const max_validation_steps = 100_000;

pub const Store = struct {
    allocator: std.mem.Allocator,
    schemas: [resources.len]std.json.Parsed(std.json.Value),
    steps: usize = 0,

    pub fn init(allocator: std.mem.Allocator) !Store {
        return initWithIo(allocator, std.testing.io);
    }

    pub fn initWithIo(allocator: std.mem.Allocator, io: std.Io) !Store {
        var self: Store = .{ .allocator = allocator, .schemas = undefined };
        var loaded: usize = 0;
        errdefer for (self.schemas[0..loaded]) |*schema| schema.deinit();
        inline for (resources, 0..) |resource, i| {
            const bytes = try std.Io.Dir.cwd().readFileAlloc(
                io,
                resource[1],
                allocator,
                .limited(64 * 1024),
            );
            defer allocator.free(bytes);
            self.schemas[i] = try parse(allocator, bytes, 64 * 1024);
            loaded += 1;
            const root = asObject(self.schemas[i].value) orelse return error.InvalidSchema;
            if (!stringEqual(root.get("$schema"), "https://json-schema.org/draft/2020-12/schema"))
                return error.InvalidSchema;
            const id = asString(root.get("$id")) orelse return error.InvalidSchema;
            const expected = if (std.mem.startsWith(u8, resource[0], "frozen-"))
                (if (i == resources.len - 2) "apt-system-request-v1" else "apt-system-result-v2")
            else
                resource[0];
            const expected_id = if (std.mem.eql(u8, resource[0], "apt-system-cli-diagnostic-v1"))
                "https://cataggar.github.io/debz/schema/apt-system-cli-diagnostic-v1.json"
            else
                try std.fmt.allocPrint(allocator, "https://debz.dev/schema/{s}", .{expected});
            defer if (!std.mem.eql(u8, resource[0], "apt-system-cli-diagnostic-v1"))
                allocator.free(expected_id);
            if (!std.mem.eql(u8, id, expected_id))
                return error.InvalidSchema;
        }
        for (self.schemas) |schema| try self.audit(schema.value, schema.value, 0);
        return self;
    }

    pub fn deinit(self: *Store) void {
        for (&self.schemas) |*schema| schema.deinit();
    }

    pub fn valid(self: *Store, schema_name: []const u8, bytes: []const u8) !bool {
        var document = try parseWithNumbers(self.allocator, bytes, max_document_bytes, false);
        defer document.deinit();
        return self.validValue(schema_name, document.value);
    }

    pub fn validValue(self: *Store, schema_name: []const u8, value: std.json.Value) !bool {
        const schema = self.find(schema_name) orelse return error.UnknownSchema;
        self.steps = 0;
        return self.check(value, schema, schema, 0);
    }

    fn find(self: *const Store, name: []const u8) ?std.json.Value {
        inline for (resources, 0..) |resource, i| {
            if (std.mem.eql(u8, name, resource[0])) return self.schemas[i].value;
        }
        return null;
    }

    fn resolve(self: *const Store, origin: std.json.Value, reference: []const u8) !struct {
        root: std.json.Value,
        node: std.json.Value,
    } {
        const hash = std.mem.indexOfScalar(u8, reference, '#') orelse return error.InvalidReference;
        const base = reference[0..hash];
        const root = if (base.len == 0) origin else blk: {
            var name = base;
            if (std.mem.startsWith(u8, name, "https://debz.dev/schema/"))
                name = name["https://debz.dev/schema/".len..];
            if (std.mem.endsWith(u8, name, ".json"))
                name = name[0 .. name.len - ".json".len];
            // Frozen schemas use the same $id as their current counterparts.
            // Explicit relative refs always resolve to the canonical local copy.
            break :blk self.find(name) orelse return error.InvalidReference;
        };
        var node = root;
        const fragment = reference[hash + 1 ..];
        if (fragment.len != 0) {
            if (fragment[0] != '/') return error.InvalidReference;
            var components = std.mem.splitScalar(u8, fragment[1..], '/');
            while (components.next()) |part| {
                if (part.len == 0 or std.mem.indexOfScalar(u8, part, '~') != null)
                    return error.InvalidReference;
                node = switch (node) {
                    .object => |object| object.get(part) orelse return error.InvalidReference,
                    .array => |array| blk: {
                        const index = std.fmt.parseInt(usize, part, 10) catch return error.InvalidReference;
                        if (index >= array.items.len) return error.InvalidReference;
                        break :blk array.items[index];
                    },
                    else => return error.InvalidReference,
                };
            }
        }
        return .{ .root = root, .node = node };
    }

    fn audit(self: *const Store, node: std.json.Value, origin: std.json.Value, depth: usize) anyerror!void {
        if (depth > max_schema_depth) return error.ValidationLimit;
        const schema = asObject(node) orelse return error.InvalidSchema;
        var fields = schema.iterator();
        while (fields.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            const annotations = [_][]const u8{ "$schema", "title", "description", "default", "const", "enum", "type", "required", "additionalProperties", "minItems", "maxItems", "minLength", "maxLength", "minimum", "uniqueItems" };
            var known = false;
            for (annotations) |annotation| {
                if (std.mem.eql(u8, key, annotation)) known = true;
            }
            if (known) continue;
            if (std.mem.eql(u8, key, "$id")) {
                if (depth != 0) return error.InvalidSchema;
            } else if (std.mem.eql(u8, key, "$ref")) {
                _ = try self.resolve(origin, asString(value) orelse return error.InvalidSchema);
            } else if (std.mem.eql(u8, key, "pattern")) {
                _ = try matchPattern(asString(value) orelse return error.InvalidSchema, "");
            } else if (std.mem.eql(u8, key, "properties") or std.mem.eql(u8, key, "$defs")) {
                const children = asObject(value) orelse return error.InvalidSchema;
                var it = children.iterator();
                while (it.next()) |child| try self.audit(child.value_ptr.*, origin, depth + 1);
            } else if (std.mem.eql(u8, key, "allOf") or std.mem.eql(u8, key, "oneOf") or std.mem.eql(u8, key, "anyOf")) {
                for (asArray(value) orelse return error.InvalidSchema) |child| {
                    try self.audit(child, origin, depth + 1);
                }
            } else if (std.mem.eql(u8, key, "items") or std.mem.eql(u8, key, "contains") or
                std.mem.eql(u8, key, "if") or std.mem.eql(u8, key, "then") or
                std.mem.eql(u8, key, "else") or std.mem.eql(u8, key, "not"))
            {
                try self.audit(value, origin, depth + 1);
            } else return error.UnsupportedSchema;
        }
    }

    fn check(self: *Store, value: std.json.Value, rule: std.json.Value, origin: std.json.Value, depth: usize) anyerror!bool {
        if (depth > max_schema_depth or self.steps >= max_validation_steps) return error.ValidationLimit;
        self.steps += 1;
        const schema = asObject(rule) orelse return error.InvalidSchema;

        if (schema.get("$ref")) |ref| {
            const target = try self.resolve(origin, asString(ref) orelse return error.InvalidSchema);
            if (!try self.check(value, target.node, target.root, depth + 1)) return false;
        }
        if (schema.get("type")) |kind| {
            const name = asString(kind) orelse return error.InvalidSchema;
            const matches = if (std.mem.eql(u8, name, "object"))
                value == .object
            else if (std.mem.eql(u8, name, "array"))
                value == .array
            else if (std.mem.eql(u8, name, "string"))
                value == .string
            else if (std.mem.eql(u8, name, "integer"))
                jsonInteger(value)
            else if (std.mem.eql(u8, name, "boolean"))
                value == .bool
            else if (std.mem.eql(u8, name, "null"))
                value == .null
            else
                return error.UnsupportedSchema;
            if (!matches) return false;
        }
        if (schema.get("const")) |constant| {
            if (!equal(value, constant)) return false;
        }
        if (schema.get("enum")) |choices| {
            const items = asArray(choices) orelse return error.InvalidSchema;
            var found = false;
            for (items) |choice| {
                if (equal(value, choice)) found = true;
            }
            if (!found) return false;
        }

        if (value == .object) {
            const object = value.object;
            if (schema.get("required")) |required| {
                for (asArray(required) orelse return error.InvalidSchema) |name| {
                    if (!object.contains(asString(name) orelse return error.InvalidSchema)) return false;
                }
            }
            const properties = if (schema.get("properties")) |p|
                asObject(p) orelse return error.InvalidSchema
            else
                null;
            var it = object.iterator();
            while (it.next()) |entry| {
                const property = if (properties) |p| p.get(entry.key_ptr.*) else null;
                if (property) |child| {
                    if (!try self.check(entry.value_ptr.*, child, origin, depth + 1)) return false;
                } else if (schema.get("additionalProperties")) |allowed| {
                    if (allowed != .bool) return error.UnsupportedSchema;
                    if (!allowed.bool) return false;
                }
            }
        }
        if (value == .array) {
            const items = value.array.items;
            if (try limit(schema, "minItems")) |min| {
                if (items.len < min) return false;
            }
            if (try limit(schema, "maxItems")) |max| {
                if (items.len > max) return false;
            }
            if (schema.get("items")) |item_schema| {
                for (items) |item| {
                    if (!try self.check(item, item_schema, origin, depth + 1)) return false;
                }
            }
            if (schema.get("uniqueItems")) |unique| {
                if (unique != .bool or !unique.bool) return error.UnsupportedSchema;
                for (items, 0..) |item, i| {
                    for (items[0..i]) |earlier| {
                        if (self.steps >= max_validation_steps) return error.ValidationLimit;
                        self.steps += 1;
                        if (equal(item, earlier)) return false;
                    }
                }
            }
            if (schema.get("contains")) |child| {
                var found = false;
                for (items) |item| {
                    if (try self.check(item, child, origin, depth + 1)) found = true;
                }
                if (!found) return false;
            }
        }
        if (value == .string) {
            const size = std.unicode.utf8CountCodepoints(value.string) catch return false;
            if (try limit(schema, "minLength")) |min| {
                if (size < min) return false;
            }
            if (try limit(schema, "maxLength")) |max| {
                if (size > max) return false;
            }
            if (schema.get("pattern")) |pattern| {
                if (!try matchPattern(asString(pattern) orelse return error.InvalidSchema, value.string)) return false;
            }
        }
        if (schema.get("minimum")) |min| {
            if (min != .integer) return error.InvalidSchema;
            if (isNumber(value) and numericCompare(value, min) == .lt) return false;
        }
        if (schema.get("allOf")) |rules| {
            for (asArray(rules) orelse return error.InvalidSchema) |child| {
                if (!try self.check(value, child, origin, depth + 1)) return false;
            }
        }
        if (schema.get("oneOf")) |rules| {
            var count: usize = 0;
            for (asArray(rules) orelse return error.InvalidSchema) |child| {
                if (try self.check(value, child, origin, depth + 1)) count += 1;
            }
            if (count != 1) return false;
        }
        if (schema.get("anyOf")) |rules| {
            var found = false;
            for (asArray(rules) orelse return error.InvalidSchema) |child| {
                if (try self.check(value, child, origin, depth + 1)) found = true;
            }
            if (!found) return false;
        }
        if (schema.get("not")) |child| {
            if (try self.check(value, child, origin, depth + 1)) return false;
        }
        if (schema.get("if")) |condition| {
            const branch = if (try self.check(value, condition, origin, depth + 1)) "then" else "else";
            if (schema.get(branch)) |child| {
                if (!try self.check(value, child, origin, depth + 1)) return false;
            }
        }
        return true;
    }
};

fn parse(allocator: std.mem.Allocator, bytes: []const u8, max: usize) !std.json.Parsed(std.json.Value) {
    return parseWithNumbers(allocator, bytes, max, true);
}

fn parseWithNumbers(allocator: std.mem.Allocator, bytes: []const u8, max: usize, parse_numbers: bool) !std.json.Parsed(std.json.Value) {
    if (bytes.len > max) return error.DocumentTooLarge;
    return std.json.parseFromSlice(std.json.Value, allocator, bytes, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .max_value_len = max,
        .parse_numbers = parse_numbers,
    });
}

fn asObject(value: std.json.Value) ?std.json.ObjectMap {
    return if (value == .object) value.object else null;
}
fn asArray(value: std.json.Value) ?[]std.json.Value {
    return if (value == .array) value.array.items else null;
}
fn asString(value: ?std.json.Value) ?[]const u8 {
    const v = value orelse return null;
    return if (v == .string) v.string else null;
}
fn stringEqual(value: ?std.json.Value, text: []const u8) bool {
    return if (asString(value)) |s| std.mem.eql(u8, s, text) else false;
}
fn limit(schema: std.json.ObjectMap, key: []const u8) !?usize {
    const value = schema.get(key) orelse return null;
    if (value != .integer) return error.InvalidSchema;
    return std.math.cast(usize, value.integer) orelse error.InvalidSchema;
}

const Decimal = struct {
    mantissa: []const u8,
    negative: bool,
    first: usize,
    last: usize,
    total: usize,
    integer_digits: usize,
    exponent: i64,

    fn parse(raw: []const u8) ?Decimal {
        if (raw.len == 0) return null;
        const negative = raw[0] == '-';
        const start: usize = if (negative) 1 else 0;
        const exponent_at = std.mem.indexOfAny(u8, raw, "eE") orelse raw.len;
        const mantissa = raw[start..exponent_at];
        if (mantissa.len == 0) return null;
        const integer_digits = std.mem.indexOfScalar(u8, mantissa, '.') orelse mantissa.len;
        var exponent: i64 = 0;
        if (exponent_at != raw.len) {
            const digits = raw[exponent_at + 1 ..];
            const negative_exponent = digits.len > 0 and digits[0] == '-';
            const parsed = std.fmt.parseInt(i64, digits, 10) catch
                @as(i64, if (negative_exponent) -1_000_000_000 else 1_000_000_000);
            exponent = std.math.clamp(parsed, -1_000_000_000, 1_000_000_000);
        }
        var first: ?usize = null;
        var last: usize = 0;
        var total: usize = 0;
        for (mantissa) |ch| {
            if (ch == '.') continue;
            if (!std.ascii.isDigit(ch)) return null;
            if (ch != '0') {
                if (first == null) first = total;
                last = total;
            }
            total += 1;
        }
        if (total == 0) return null;
        return .{
            .mantissa = mantissa,
            .negative = negative and first != null,
            .first = first orelse total,
            .last = last,
            .total = total,
            .integer_digits = integer_digits,
            .exponent = exponent,
        };
    }

    fn zero(self: Decimal) bool {
        return self.first == self.total;
    }

    fn integer(self: Decimal) bool {
        if (self.zero()) return true;
        const fraction_digits: i64 = @intCast(self.total - self.integer_digits);
        const trailing_zeros: i64 = @intCast(self.total - self.last - 1);
        return self.exponent - fraction_digits + trailing_zeros >= 0;
    }

    fn power(self: Decimal) i64 {
        return self.exponent + @as(i64, @intCast(self.integer_digits)) -
            @as(i64, @intCast(self.first)) - 1;
    }

    const Digits = struct {
        decimal: Decimal,
        cursor: usize = 0,
        seen: usize = 0,

        fn next(self: *Digits) u8 {
            while (self.cursor < self.decimal.mantissa.len) {
                const ch = self.decimal.mantissa[self.cursor];
                self.cursor += 1;
                if (ch == '.') continue;
                const at = self.seen;
                self.seen += 1;
                if (at >= self.decimal.first) return ch;
            }
            return '0';
        }
    };
};

fn isNumber(value: std.json.Value) bool {
    return value == .integer or value == .float or value == .number_string;
}

fn decimal(value: std.json.Value, scratch: *[64]u8) ?Decimal {
    const raw = switch (value) {
        .integer => |n| std.fmt.bufPrint(scratch, "{d}", .{n}) catch return null,
        .float => |n| blk: {
            if (!std.math.isFinite(n)) return null;
            break :blk std.fmt.bufPrint(scratch, "{e}", .{n}) catch return null;
        },
        .number_string => |n| n,
        else => return null,
    };
    return Decimal.parse(raw);
}

fn jsonInteger(value: std.json.Value) bool {
    var scratch: [64]u8 = undefined;
    return if (decimal(value, &scratch)) |d| d.integer() else false;
}

fn numericCompare(a: std.json.Value, b: std.json.Value) std.math.Order {
    var left_scratch: [64]u8 = undefined;
    var right_scratch: [64]u8 = undefined;
    const left = decimal(a, &left_scratch) orelse return .lt;
    const right = decimal(b, &right_scratch) orelse return .gt;
    if (left.zero() and right.zero()) return .eq;
    if (left.negative != right.negative) return if (left.negative) .lt else .gt;
    var order: std.math.Order = if (left.zero())
        .lt
    else if (right.zero())
        .gt
    else
        std.math.order(left.power(), right.power());
    if (order == .eq and !left.zero() and !right.zero()) {
        var a_digits: Decimal.Digits = .{ .decimal = left };
        var b_digits: Decimal.Digits = .{ .decimal = right };
        const count = @max(left.total - left.first, right.total - right.first);
        for (0..count) |_| {
            order = std.math.order(a_digits.next(), b_digits.next());
            if (order != .eq) break;
        }
    }
    return if (left.negative) switch (order) {
        .lt => .gt,
        .gt => .lt,
        .eq => .eq,
    } else order;
}

fn equal(a: std.json.Value, b: std.json.Value) bool {
    if (isNumber(a) and isNumber(b)) return numericCompare(a, b) == .eq;
    if (a != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => a.bool == b.bool,
        .integer => a.integer == b.integer,
        .float => a.float == b.float,
        .number_string => std.mem.eql(u8, a.number_string, b.number_string),
        .string => std.mem.eql(u8, a.string, b.string),
        .array => blk: {
            if (a.array.items.len != b.array.items.len) break :blk false;
            for (a.array.items, b.array.items) |left, right| {
                if (!equal(left, right)) break :blk false;
            }
            break :blk true;
        },
        .object => blk: {
            if (a.object.count() != b.object.count()) break :blk false;
            var it = a.object.iterator();
            while (it.next()) |entry| {
                const other = b.object.get(entry.key_ptr.*) orelse break :blk false;
                if (!equal(entry.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
    };
}

fn matchPattern(pattern: []const u8, text: []const u8) !bool {
    if (std.mem.eql(u8, pattern, "^[0-9a-f]{64}$")) {
        if (text.len != 64) return false;
        for (text) |ch| if (!std.ascii.isDigit(ch) and (ch < 'a' or ch > 'f')) return false;
        return true;
    }
    if (std.mem.eql(u8, pattern, "^(?!-)[A-Za-z0-9+.:=-]+$") or
        std.mem.eql(u8, pattern, "^[A-Za-z0-9][A-Za-z0-9+.:=-]*$"))
    {
        if (text.len == 0) return false;
        const result_name = pattern[1] == '[';
        if ((result_name and !std.ascii.isAlphanumeric(text[0])) or
            (!result_name and text[0] == '-')) return false;
        for (text) |ch| {
            if (!std.ascii.isAlphanumeric(ch) and std.mem.indexOfScalar(u8, "+.:=-", ch) == null) return false;
        }
        return true;
    }
    if (std.mem.eql(u8, pattern, "^[a-z0-9-]+$")) {
        if (text.len == 0) return false;
        for (text) |ch| if (!(ch >= 'a' and ch <= 'z') and !std.ascii.isDigit(ch) and ch != '-') return false;
        return true;
    }
    if (std.mem.eql(u8, pattern, "^debz recover --system-profile /"))
        return std.mem.startsWith(u8, text, "debz recover --system-profile /");
    if (std.mem.eql(u8, pattern, "^https?://(?![^/?#]*@)[^/?#]+(?:[/?#]|$)")) {
        const prefix: usize = if (std.mem.startsWith(u8, text, "https://")) 8 else if (std.mem.startsWith(u8, text, "http://")) 7 else return false;
        var end = prefix;
        while (end < text.len and std.mem.indexOfScalar(u8, "/?#", text[end]) == null) : (end += 1) {
            if (text[end] == '@') return false;
        }
        return end != prefix;
    }
    if (std.mem.eql(u8, pattern, "^(?:/|/(?!\\.{1,2}(?:/|$))[^/\\\\\\u0000-\\u001f\\u007f]+(?:/(?!\\.{1,2}(?:/|$))[^/\\\\\\u0000-\\u001f\\u007f]+)*)$")) {
        if (text.len == 0 or text[0] != '/') return false;
        if (text.len == 1) return true;
        var segments = std.mem.splitScalar(u8, text[1..], '/');
        while (segments.next()) |segment| {
            if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
            for (segment) |ch| if (ch == '\\' or ch < 0x20 or ch == 0x7f) return false;
        }
        return true;
    }
    return error.UnsupportedPattern;
}

test "closed schema registry rejects unknown refs and keywords" {
    var store = try Store.init(std.testing.allocator);
    defer store.deinit();
    try std.testing.expectError(error.UnknownSchema, store.valid("remote", "{}"));
    try std.testing.expect(!try store.valid("apt-system-request-v1", "{}"));
    try std.testing.expectError(error.DuplicateField, store.valid(
        "apt-system-request-v1",
        "{\"version\":1,\"version\":1}",
    ));
    try std.testing.expectError(error.InvalidReference, store.resolve(store.schemas[0].value, "https://evil.invalid/schema#/$defs/path"));
    try std.testing.expectError(error.UnsupportedPattern, matchPattern(".*", "anything"));
    try std.testing.expect(try store.valid("apt-system-cli-diagnostic-v1",
        \\{"schema":"io.github.cataggar.debz.apt-system-cli-diagnostic.v1","version":1,"exit_status":2,"id":"unsupported_syntax","topic":"apt","message":"bad option"}
    ));
    try std.testing.expect(!try store.valid("apt-system-cli-diagnostic-v1",
        \\{"schema":"io.github.cataggar.debz.apt-system-cli-diagnostic.v1","version":1,"exit_status":0,"id":"unsupported_syntax","topic":"apt","message":"bad option"}
    ));
}

test "JSON numeric equivalence is exact across integer decimal and exponent notation" {
    try std.testing.expect(equal(.{ .integer = 2 }, .{ .float = 2.0 }));
    try std.testing.expect(equal(.{ .integer = 2 }, .{ .number_string = "2.0e0" }));
    try std.testing.expect(equal(.{ .number_string = "-0.0" }, .{ .integer = 0 }));
    try std.testing.expect(!equal(.{ .integer = 2 }, .{ .number_string = "2.00000000000000000001" }));
    try std.testing.expect(jsonInteger(.{ .number_string = "1.2e1" }));
    try std.testing.expect(!jsonInteger(.{ .number_string = "1.2e0" }));
    try std.testing.expect(!jsonInteger(.{ .number_string = "2.00000000000000000001" }));
    try std.testing.expect(numericCompare(.{ .number_string = "-1.5" }, .{ .integer = -2 }) == .gt);
    try std.testing.expect(numericCompare(.{ .number_string = "9223372036854775808" }, .{ .integer = 1 }) == .gt);
}

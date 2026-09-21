const std = @import("std");
const debz = @import("debz");
const oracle_options = @import("native_alternatives_oracle_options");

const alternatives = debz.native_alternatives;

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    return value.object.get(name) orelse error.MissingOracleField;
}

fn string(value: std.json.Value) ![]const u8 {
    return switch (value) {
        .string => |text| text,
        else => error.InvalidOracleField,
    };
}

fn integer(value: std.json.Value) !i64 {
    return switch (value) {
        .integer => |number| number,
        else => error.InvalidOracleField,
    };
}

fn decodeBase64(
    allocator: std.mem.Allocator,
    text: []const u8,
) ![]u8 {
    const size = try std.base64.standard.Decoder.calcSizeForSlice(text);
    const result = try allocator.alloc(u8, size);
    errdefer allocator.free(result);
    try std.base64.standard.Decoder.decode(result, text);
    return result;
}

fn parseRecordFact(
    allocator: std.mem.Allocator,
    name: []const u8,
    fact: std.json.Value,
) !alternatives.OwnedRecord {
    const bytes = try decodeBase64(
        allocator,
        try string(try field(fact, "bytes_base64")),
    );
    defer allocator.free(bytes);
    const expected_size = try integer(try field(fact, "size"));
    try std.testing.expectEqual(expected_size, @as(i64, @intCast(bytes.len)));
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &sha256, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        try string(try field(fact, "sha256")),
    );
    try std.testing.expectEqualSlices(u8, &expected, &sha256);
    return alternatives.parse(allocator, name, bytes, .{});
}

fn oraclePath(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, oracle_options.path);
}

fn vendorPath(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, oracle_options.vendor_path);
}

fn hexDigest(text: []const u8) ![32]u8 {
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, text);
    return result;
}

fn jsonBytes(
    allocator: std.mem.Allocator,
    value: std.json.Value,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(
        value,
        .{ .whitespace = .indent_2 },
        &output.writer,
    );
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

fn decodePointerPart(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    var index: usize = 0;
    while (index < encoded.len) : (index += 1) {
        if (encoded[index] != '~') {
            try result.append(allocator, encoded[index]);
            continue;
        }
        if (index + 1 >= encoded.len) return error.InvalidJsonPointer;
        index += 1;
        try result.append(allocator, switch (encoded[index]) {
            '0' => '~',
            '1' => '/',
            else => return error.InvalidJsonPointer,
        });
    }
    return result.toOwnedSlice(allocator);
}

fn replaceJsonPointer(
    allocator: std.mem.Allocator,
    root: *std.json.Value,
    pointer: []const u8,
    replacement: std.json.Value,
) !void {
    if (pointer.len < 2 or pointer[0] != '/')
        return error.InvalidJsonPointer;
    var current = root;
    var parts = std.mem.splitScalar(u8, pointer[1..], '/');
    var encoded = parts.next() orelse return error.InvalidJsonPointer;
    while (true) {
        const part = try decodePointerPart(allocator, encoded);
        defer allocator.free(part);
        const next = parts.next();
        if (next == null) {
            switch (current.*) {
                .object => |*object| {
                    const slot = object.getPtr(part) orelse
                        return error.MissingJsonPointer;
                    slot.* = replacement;
                },
                .array => |*array| {
                    const index = std.fmt.parseInt(
                        usize,
                        part,
                        10,
                    ) catch return error.InvalidJsonPointer;
                    if (index >= array.items.len)
                        return error.MissingJsonPointer;
                    array.items[index] = replacement;
                },
                else => return error.InvalidJsonPointer,
            }
            return;
        }
        current = switch (current.*) {
            .object => |*object| object.getPtr(part) orelse
                return error.MissingJsonPointer,
            .array => |*array| item: {
                const index = std.fmt.parseInt(
                    usize,
                    part,
                    10,
                ) catch return error.InvalidJsonPointer;
                if (index >= array.items.len)
                    return error.MissingJsonPointer;
                break :item &array.items[index];
            },
            else => return error.InvalidJsonPointer,
        };
        encoded = next.?;
    }
}

fn applyArm64Evidence(
    allocator: std.mem.Allocator,
    root: *std.json.Value,
) !std.json.Value {
    const arm64 = try field(
        try field(root.*, "architecture_evidence"),
        "arm64",
    );
    const observed = root.object.getPtr("observed_behavior") orelse
        return error.MissingOracleField;
    const differences = (try field(
        arm64,
        "differences_from_baseline",
    )).array.items;
    for (differences) |difference| {
        try replaceJsonPointer(
            allocator,
            observed,
            try string(try field(difference, "path")),
            try field(difference, "value"),
        );
    }
    const encoded = try jsonBytes(allocator, observed.*);
    defer allocator.free(encoded);
    const observation = try field(arm64, "observation");
    try std.testing.expectEqual(
        try integer(try field(observation, "size")),
        @as(i64, @intCast(encoded.len)),
    );
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    const expected = try hexDigest(
        try string(try field(observation, "sha256")),
    );
    try std.testing.expectEqualSlices(u8, &expected, &digest);
    return observed.*;
}

const ReplayCounts = struct {
    total: usize = 0,
    canonical: usize = 0,
    rejected: usize = 0,
};

fn replayRecordFacts(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    key: ?[]const u8,
    counts: *ReplayCounts,
) !void {
    switch (value) {
        .object => |object| {
            if (key != null and std.mem.eql(u8, key.?, "record") and
                object.get("bytes_base64") != null and
                object.get("sha256") != null and
                object.get("size") != null)
            {
                counts.total += 1;
                const bytes = try decodeBase64(
                    allocator,
                    try string(object.get("bytes_base64").?),
                );
                defer allocator.free(bytes);
                try std.testing.expectEqual(
                    try integer(object.get("size").?),
                    @as(i64, @intCast(bytes.len)),
                );
                var observed: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(bytes, &observed, .{});
                var expected: [32]u8 = undefined;
                _ = try std.fmt.hexToBytes(
                    &expected,
                    try string(object.get("sha256").?),
                );
                try std.testing.expectEqualSlices(u8, &expected, &observed);
                var parsed = alternatives.parse(
                    allocator,
                    "oracle-replay",
                    bytes,
                    .{},
                ) catch {
                    counts.rejected += 1;
                    return;
                };
                defer parsed.deinit();
                const canonical = try alternatives.canonicalBytes(
                    allocator,
                    parsed.record,
                );
                defer allocator.free(canonical);
                try std.testing.expectEqualSlices(u8, bytes, canonical);
                counts.canonical += 1;
                return;
            }
            var iterator = object.iterator();
            while (iterator.next()) |entry|
                try replayRecordFacts(
                    allocator,
                    entry.value_ptr.*,
                    entry.key_ptr.*,
                    counts,
                );
        },
        .array => |array| for (array.items) |item|
            try replayRecordFacts(allocator, item, null, counts),
        else => {},
    }
}

test "native_alternatives.oracle.amd64 arm64 evidence and vendor projection parse exactly" {
    const testing = std.testing;
    const path = try oraclePath(testing.allocator);
    defer testing.allocator.free(path);
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        path,
        testing.allocator,
        .limited(2 * 1024 * 1024),
    );
    defer testing.allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();
    const root = parsed.value;

    const source = try field(root, "source");
    const dpkg = try field(source, "dpkg");
    const architectures = try field(dpkg, "architectures");
    for (alternatives.pinned_tools) |binding| {
        const architecture = architectures.object.get(
            binding.architecture,
        ) orelse return error.MissingOracleArchitecture;
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(
            &expected,
            try string(try field(
                architecture,
                "update_alternatives_sha256",
            )),
        );
        try testing.expectEqualSlices(u8, &binding.sha256, &expected);
    }
    const arm64 = try field(
        try field(root, "architecture_evidence"),
        "arm64",
    );
    try testing.expectEqual(
        @as(i64, 190),
        try integer(try field(arm64, "difference_count")),
    );
    const differences = (try field(
        arm64,
        "differences_from_baseline",
    )).array.items;
    try testing.expectEqual(@as(usize, 190), differences.len);
    var previous_path: ?[]const u8 = null;
    for (differences) |difference| {
        const difference_path = try string(try field(difference, "path"));
        if (previous_path) |previous|
            try testing.expect(std.mem.order(
                u8,
                previous,
                difference_path,
            ) == .lt);
        previous_path = difference_path;
    }
    try testing.expectEqualStrings(
        "cf2b4f92399c2c19281d62b6ab1ea266cd85887263bc273ac8857fe507deae8f",
        try string(try field(
            try field(arm64, "observation"),
            "sha256",
        )),
    );

    const inventory_path = try vendorPath(testing.allocator);
    defer testing.allocator.free(inventory_path);
    const inventory_bytes = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        inventory_path,
        testing.allocator,
        .limited(2 * 1024 * 1024),
    );
    defer testing.allocator.free(inventory_bytes);
    const reference_binding = try field(
        try field(source, "vendor_reference"),
        "reference",
    );
    try testing.expectEqual(
        try integer(try field(reference_binding, "size")),
        @as(i64, @intCast(inventory_bytes.len)),
    );
    var inventory_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        inventory_bytes,
        &inventory_sha256,
        .{},
    );
    const expected_inventory_sha256 = try hexDigest(
        try string(try field(reference_binding, "sha256")),
    );
    try testing.expectEqualSlices(
        u8,
        &expected_inventory_sha256,
        &inventory_sha256,
    );
    var parsed_inventory = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        inventory_bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed_inventory.deinit();
    const inventory_alternatives = try field(
        parsed_inventory.value,
        "alternatives",
    );
    const inventory_canonical = try jsonBytes(
        testing.allocator,
        inventory_alternatives,
    );
    defer testing.allocator.free(inventory_canonical);
    var alternatives_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        inventory_canonical,
        &alternatives_sha256,
        .{},
    );
    const expected_alternatives_sha256 = try hexDigest(
        alternatives.pinned_oracle_sha256,
    );
    try testing.expectEqualSlices(
        u8,
        &expected_alternatives_sha256,
        &alternatives_sha256,
    );
    const inventory_groups = (try field(
        inventory_alternatives,
        "groups",
    )).array.items;
    try testing.expectEqual(
        alternatives.pinned_vendor_group_count,
        inventory_groups.len,
    );
    try testing.expectEqual(
        alternatives.pinned_vendor_requested_path_count,
        (try field(
            inventory_alternatives,
            "requested_paths",
        )).array.items.len,
    );
    try testing.expectEqual(
        alternatives.pinned_vendor_linked_entry_count,
        (try field(
            inventory_alternatives,
            "linked_entries",
        )).array.items.len,
    );

    const projection = try field(
        try field(
            try field(root, "observed_behavior"),
            "external_update_alternatives",
        ),
        "vendor_projection",
    );
    const groups = (try field(projection, "groups")).array.items;
    try testing.expectEqual(
        alternatives.pinned_vendor_group_count,
        groups.len,
    );
    var relationships: usize = 0;
    for (groups, 0..) |group, index| {
        const name = try string(try field(group, "name"));
        try testing.expectEqualStrings(
            alternatives.pinned_vendor_groups[index],
            name,
        );
        var record = try parseRecordFact(
            testing.allocator,
            name,
            try field(group, "record"),
        );
        defer record.deinit();
        relationships += 1 + record.record.slaves.len;
        try testing.expectEqual(alternatives.Mode.auto, record.record.mode);
        try testing.expectEqual(@as(usize, 1), record.record.candidates.len);
        try testing.expectEqual(
            @as(i32, 50),
            record.record.candidates[0].priority,
        );
        const links = try alternatives.selectedLinks(
            testing.allocator,
            record.record,
            record.record.candidates[0].path,
        );
        defer testing.allocator.free(links);
        const selectors = (try field(group, "selectors")).array.items;
        const generics = (try field(group, "generic_links")).array.items;
        try testing.expectEqual(links.len, selectors.len);
        try testing.expectEqual(links.len, generics.len);
        const inventory_group = inventory_groups[index];
        try testing.expectEqualStrings(
            name,
            try string(try field(inventory_group, "name")),
        );
        const inventory_links = (try field(
            inventory_group,
            "links",
        )).array.items;
        try testing.expectEqual(links.len, inventory_links.len);
        for (links, 0..) |link, link_index| {
            const selector = selectors[link_index];
            try testing.expectEqualStrings(
                link.selector_name,
                try string(try field(selector, "name")),
            );
            try testing.expectEqualStrings(
                link.selector_target,
                try string(try field(
                    try field(selector, "fact"),
                    "target",
                )),
            );
            var generic: ?std.json.Value = null;
            for (generics) |candidate_generic| {
                if (std.mem.eql(
                    u8,
                    link.generic_path,
                    try string(try field(candidate_generic, "path")),
                )) {
                    generic = candidate_generic;
                    break;
                }
            }
            const generic_entry = generic orelse
                return error.MissingProjectedGenericLink;
            try testing.expectEqualStrings(
                link.generic_path,
                try string(try field(generic_entry, "path")),
            );
            const expected_generic_target = try std.fmt.allocPrint(
                testing.allocator,
                "/etc/alternatives/{s}",
                .{link.selector_name},
            );
            defer testing.allocator.free(expected_generic_target);
            try testing.expectEqualStrings(
                expected_generic_target,
                try string(try field(
                    try field(generic_entry, "fact"),
                    "target",
                )),
            );
            var inventory_link: ?std.json.Value = null;
            for (inventory_links) |candidate_link| {
                if (std.mem.eql(
                    u8,
                    link.generic_path[1..],
                    try string(try field(candidate_link, "link_path")),
                )) {
                    inventory_link = candidate_link;
                    break;
                }
            }
            const inventory_entry = inventory_link orelse
                return error.MissingInventoryRelationship;
            try testing.expectEqualStrings(
                link.generic_path[1..],
                try string(try field(inventory_entry, "link_path")),
            );
            const inventory_selector = try string(try field(
                inventory_entry,
                "selector_path",
            ));
            try testing.expectEqualStrings(
                link.selector_name,
                inventory_selector[std.mem.lastIndexOfScalar(
                    u8,
                    inventory_selector,
                    '/',
                ).? + 1 ..],
            );
            try testing.expectEqualStrings(
                link.selector_target,
                try string(try field(
                    inventory_entry,
                    "selector_target",
                )),
            );
        }
    }
    try testing.expectEqual(
        alternatives.pinned_vendor_relationship_count,
        relationships,
    );
    try testing.expectEqual(
        @as(i64, @intCast(alternatives.pinned_vendor_requested_path_count)),
        try integer(try field(projection, "requested_path_count")),
    );
    try testing.expectEqual(
        @as(i64, @intCast(alternatives.pinned_vendor_relationship_count)),
        try integer(try field(projection, "relationship_count")),
    );
    const vendor = try field(root, "vendor_projection");
    try testing.expectEqual(
        @as(i64, @intCast(alternatives.pinned_vendor_linked_entry_count)),
        try integer(try field(vendor, "linked_entry_count")),
    );
    try testing.expectEqualStrings(
        alternatives.pinned_oracle_sha256,
        try string(try field(vendor, "alternatives_sha256")),
    );
    try testing.expectEqualStrings(
        alternatives.pinned_vendor_reference_sha256,
        try string(try field(reference_binding, "sha256")),
    );
}

test "native_alternatives.oracle.selection and lifecycle records remain canonical" {
    const testing = std.testing;
    const path = try oraclePath(testing.allocator);
    defer testing.allocator.free(path);
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        path,
        testing.allocator,
        .limited(2 * 1024 * 1024),
    );
    defer testing.allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();
    var replayed: ReplayCounts = .{};
    try replayRecordFacts(
        testing.allocator,
        parsed.value,
        null,
        &replayed,
    );
    try testing.expectEqual(@as(usize, 48), replayed.total);
    try testing.expectEqual(@as(usize, 42), replayed.canonical);
    try testing.expectEqual(@as(usize, 6), replayed.rejected);
    _ = try applyArm64Evidence(
        testing.allocator,
        &parsed.value,
    );
    var arm64_replayed: ReplayCounts = .{};
    try replayRecordFacts(
        testing.allocator,
        parsed.value,
        null,
        &arm64_replayed,
    );
    try testing.expectEqual(replayed.total, arm64_replayed.total);
    try testing.expectEqual(replayed.canonical, arm64_replayed.canonical);
    try testing.expectEqual(replayed.rejected, arm64_replayed.rejected);
    const observed = try field(parsed.value, "observed_behavior");
    const external = try field(observed, "external_update_alternatives");
    const malformed = (try field(
        try field(external, "malformed_records"),
        "regular_record_cases",
    )).array.items;
    try testing.expectEqual(@as(usize, 5), malformed.len);
    for (malformed) |case| {
        const state = try field(case, "state");
        var rejected = false;
        if (parseRecordFact(
            testing.allocator,
            "bad",
            try field(state, "record"),
        )) |record_value| {
            var record = record_value;
            record.deinit();
        } else |_| {
            rejected = true;
        }
        try testing.expect(rejected);
    }
    const attacks = (try field(
        try field(external, "path_and_symlink_attacks"),
        "raw_tool_cases",
    )).array.items;
    var rejected_traversal = false;
    if (parseRecordFact(
        testing.allocator,
        "bad",
        try field(attacks[0], "record"),
    )) |record_value| {
        var record = record_value;
        record.deinit();
    } else |_| {
        rejected_traversal = true;
    }
    try testing.expect(rejected_traversal);
    const steps = (try field(
        try field(external, "selection"),
        "steps",
    )).array.items;
    try testing.expectEqual(@as(usize, 9), steps.len);
    for (steps) |step| {
        const state = try field(step, "state");
        const record_fact = try field(state, "record");
        if (record_fact == .null) continue;
        var record = try parseRecordFact(
            testing.allocator,
            "debz-choice",
            record_fact,
        );
        defer record.deinit();
        const bytes_again = try alternatives.canonicalBytes(
            testing.allocator,
            record.record,
        );
        defer testing.allocator.free(bytes_again);
        try testing.expect(bytes_again.len != 0);
    }

    const direct = try field(observed, "direct_dpkg");
    const lifecycle = try field(direct, "successful_lifecycle");
    const phases = (try field(lifecycle, "phases")).array.items;
    var parsed_records: usize = 0;
    for (phases) |phase| {
        const state = try field(phase, "state");
        const alternatives_state = try field(state, "alternatives");
        const record_fact = try field(alternatives_state, "record");
        if (record_fact == .null) continue;
        var record = try parseRecordFact(
            testing.allocator,
            "debz-alt-lifecycle",
            record_fact,
        );
        defer record.deinit();
        parsed_records += 1;
    }
    try testing.expectEqual(@as(usize, 3), parsed_records);
}

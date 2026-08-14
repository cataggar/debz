const std = @import("std");

pub const ParseError = error{
    EmptyVersion,
    EmptyEpoch,
    InvalidEpochCharacter,
    EmptyUpstreamVersion,
    UpstreamVersionMustStartWithDigit,
    InvalidUpstreamVersionCharacter,
    EmptyDebianRevision,
    InvalidDebianRevisionCharacter,
};

pub const DebianVersion = struct {
    original: []const u8,
    epoch: ?[]const u8,
    upstream: []const u8,
    revision: ?[]const u8,

    pub fn parse(input: []const u8) ParseError!DebianVersion {
        if (input.len == 0) return error.EmptyVersion;

        var remainder = input;
        var epoch: ?[]const u8 = null;
        if (std.mem.indexOfScalar(u8, input, ':')) |colon| {
            const spelling = input[0..colon];
            if (spelling.len == 0) return error.EmptyEpoch;
            for (spelling) |character| {
                if (!std.ascii.isDigit(character)) return error.InvalidEpochCharacter;
            }
            epoch = spelling;
            remainder = input[colon + 1 ..];
        }

        var upstream = remainder;
        var revision: ?[]const u8 = null;
        if (std.mem.lastIndexOfScalar(u8, remainder, '-')) |hyphen| {
            upstream = remainder[0..hyphen];
            const spelling = remainder[hyphen + 1 ..];
            if (spelling.len == 0) return error.EmptyDebianRevision;
            revision = spelling;
        }

        if (upstream.len == 0) return error.EmptyUpstreamVersion;
        if (!std.ascii.isDigit(upstream[0])) {
            return error.UpstreamVersionMustStartWithDigit;
        }
        for (upstream) |character| {
            if (!isUpstreamCharacter(character)) {
                return error.InvalidUpstreamVersionCharacter;
            }
        }
        if (revision) |spelling| {
            for (spelling) |character| {
                if (!isRevisionCharacter(character)) {
                    return error.InvalidDebianRevisionCharacter;
                }
            }
        }

        return .{
            .original = input,
            .epoch = epoch,
            .upstream = upstream,
            .revision = revision,
        };
    }

    pub fn order(left: DebianVersion, right: DebianVersion) std.math.Order {
        const epoch_order = compareDigitRuns(
            left.epoch orelse "0",
            right.epoch orelse "0",
        );
        if (epoch_order != .eq) return epoch_order;

        const upstream_order = comparePart(left.upstream, right.upstream);
        if (upstream_order != .eq) return upstream_order;

        return comparePart(left.revision orelse "0", right.revision orelse "0");
    }

    pub fn eql(left: DebianVersion, right: DebianVersion) bool {
        return left.order(right) == .eq;
    }
};

fn isUpstreamCharacter(character: u8) bool {
    return std.ascii.isAlphanumeric(character) or
        character == '.' or character == '+' or character == '-' or character == '~';
}

fn isRevisionCharacter(character: u8) bool {
    return std.ascii.isAlphanumeric(character) or
        character == '.' or character == '+' or character == '~';
}

fn comparePart(left: []const u8, right: []const u8) std.math.Order {
    var left_index: usize = 0;
    var right_index: usize = 0;

    while (left_index < left.len or right_index < right.len) {
        while ((left_index < left.len and !std.ascii.isDigit(left[left_index])) or
            (right_index < right.len and !std.ascii.isDigit(right[right_index])))
        {
            const left_character = if (left_index < left.len) left[left_index] else 0;
            const right_character = if (right_index < right.len) right[right_index] else 0;
            const left_order = nonDigitOrder(left_character);
            const right_order = nonDigitOrder(right_character);
            if (left_order < right_order) return .lt;
            if (left_order > right_order) return .gt;
            if (left_index < left.len) left_index += 1;
            if (right_index < right.len) right_index += 1;
        }

        const left_start = left_index;
        const right_start = right_index;
        while (left_index < left.len and std.ascii.isDigit(left[left_index])) {
            left_index += 1;
        }
        while (right_index < right.len and std.ascii.isDigit(right[right_index])) {
            right_index += 1;
        }
        const digit_order = compareDigitRuns(
            left[left_start..left_index],
            right[right_start..right_index],
        );
        if (digit_order != .eq) return digit_order;
    }

    return .eq;
}

fn nonDigitOrder(character: u8) u16 {
    if (character == '~') return 0;
    if (character == 0 or std.ascii.isDigit(character)) return 1;
    if (std.ascii.isAlphabetic(character)) return @as(u16, character) + 1;
    return @as(u16, character) + 257;
}

fn compareDigitRuns(left: []const u8, right: []const u8) std.math.Order {
    const left_significant = std.mem.trimStart(u8, left, "0");
    const right_significant = std.mem.trimStart(u8, right, "0");

    if (left_significant.len < right_significant.len) return .lt;
    if (left_significant.len > right_significant.len) return .gt;
    return std.mem.order(u8, left_significant, right_significant);
}

fn expectOrder(left: []const u8, expected: std.math.Order, right: []const u8) !void {
    const parsed_left = try DebianVersion.parse(left);
    const parsed_right = try DebianVersion.parse(right);
    try std.testing.expectEqual(expected, parsed_left.order(parsed_right));
    try std.testing.expectEqual(expected.invert(), parsed_right.order(parsed_left));
}

test "parser preserves spelling and exposes typed components" {
    const parsed = try DebianVersion.parse("0002:1.0~rc1+git-03");

    try std.testing.expectEqualStrings("0002:1.0~rc1+git-03", parsed.original);
    try std.testing.expectEqualStrings("0002", parsed.epoch.?);
    try std.testing.expectEqualStrings("1.0~rc1+git", parsed.upstream);
    try std.testing.expectEqualStrings("03", parsed.revision.?);

    const native = try DebianVersion.parse("1.2-3-4");
    try std.testing.expectEqualStrings("1.2-3", native.upstream);
    try std.testing.expectEqualStrings("4", native.revision.?);

    const omitted = try DebianVersion.parse("1.2");
    try std.testing.expect(omitted.epoch == null);
    try std.testing.expect(omitted.revision == null);
}

test "parser reports precise syntax errors" {
    try std.testing.expectError(error.EmptyVersion, DebianVersion.parse(""));
    try std.testing.expectError(error.EmptyEpoch, DebianVersion.parse(":1"));
    try std.testing.expectError(error.InvalidEpochCharacter, DebianVersion.parse("x:1"));
    try std.testing.expectError(error.EmptyUpstreamVersion, DebianVersion.parse("1:"));
    try std.testing.expectError(error.UpstreamVersionMustStartWithDigit, DebianVersion.parse("x1"));
    try std.testing.expectError(error.InvalidUpstreamVersionCharacter, DebianVersion.parse("1_0"));
    try std.testing.expectError(error.EmptyDebianRevision, DebianVersion.parse("1-"));
    try std.testing.expectError(error.InvalidDebianRevisionCharacter, DebianVersion.parse("1-2_3"));
    try std.testing.expectError(error.InvalidDebianRevisionCharacter, DebianVersion.parse("1-2/3"));
    try std.testing.expectError(error.InvalidUpstreamVersionCharacter, DebianVersion.parse("1:2:3"));
    try std.testing.expectError(error.InvalidUpstreamVersionCharacter, DebianVersion.parse("1/2"));
}

test "epochs compare numerically without overflow" {
    try expectOrder("1:1", .gt, "1");
    try expectOrder("0001:1", .eq, "1:1");
    try expectOrder("999999999999999999999999:1", .gt, "2:9999");
}

test "omitted Debian revision is equivalent to zero" {
    try expectOrder("1.0", .eq, "1.0-0");
    try expectOrder("1.0", .lt, "1.0-1");
    try expectOrder("1.0", .gt, "1.0-0~1");
}

test "tilde sorts before the empty string and all other characters" {
    try expectOrder("1.0~~", .lt, "1.0~");
    try expectOrder("1.0~", .lt, "1.0");
    try expectOrder("1.0~rc1", .lt, "1.0~rc2");
    try expectOrder("1.0~beta1", .lt, "1.0~rc1");
    try expectOrder("1.0-1~exp1", .lt, "1.0-1");
}

test "digit runs compare numerically and ignore leading zeroes" {
    try expectOrder("1.09", .eq, "1.9");
    try expectOrder("1.9", .lt, "1.10");
    try expectOrder("1.0000000000000000000002", .gt, "1.1");
    try expectOrder("1.0a01", .eq, "1.0a1");
}

test "non-digits use Debian letter and punctuation ordering" {
    try expectOrder("1.0A", .lt, "1.0a");
    try expectOrder("1.0Z", .lt, "1.0a");
    try expectOrder("1.0a", .lt, "1.0+");
    try expectOrder("1.0+", .lt, "1.0.");
    try expectOrder("1.0+git", .gt, "1.0");
    try expectOrder("1.0a1", .lt, "1.0a.");
    try expectOrder("1.0a~", .lt, "1.0a1");
}

test "Policy-style version sequence is ordered correctly" {
    const versions = [_][]const u8{
        "1.0~rc1",
        "1.0",
        "1.0-1~bpo1",
        "1.0-1",
        "1.0-1+b1",
        "1.0-2",
        "1:0",
    };
    for (versions[0 .. versions.len - 1], versions[1..]) |left, right| {
        try expectOrder(left, .lt, right);
    }
    try expectOrder("1.0", .eq, "1.0-0");
}

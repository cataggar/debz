const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const debz = @import("debz");

pub fn ManagedStringArrayHashMap(comptime V: type) type {
    return struct {
        allocator: std.mem.Allocator,
        unmanaged: std.StringArrayHashMapUnmanaged(V) = .empty,

        pub const Entry = std.StringArrayHashMapUnmanaged(V).Entry;
        pub const Iterator = std.StringArrayHashMapUnmanaged(V).Iterator;
        pub const GetOrPutResult = std.StringArrayHashMapUnmanaged(V).GetOrPutResult;

        pub fn init(allocator: std.mem.Allocator) @This() {
            return .{ .allocator = allocator };
        }
        pub fn deinit(self: *@This()) void {
            self.unmanaged.deinit(self.allocator);
        }
        pub fn put(self: *@This(), key: []const u8, value: V) !void {
            return self.unmanaged.put(self.allocator, key, value);
        }
        pub fn get(self: @This(), key: []const u8) ?V {
            return self.unmanaged.get(key);
        }
        pub fn getPtr(self: @This(), key: []const u8) ?*V {
            return self.unmanaged.getPtr(key);
        }
        pub fn getOrPut(self: *@This(), key: []const u8) !GetOrPutResult {
            return self.unmanaged.getOrPut(self.allocator, key);
        }
        pub fn contains(self: @This(), key: []const u8) bool {
            return self.unmanaged.contains(key);
        }
        pub fn count(self: @This()) usize {
            return self.unmanaged.count();
        }
        pub fn keys(self: @This()) [][]const u8 {
            return self.unmanaged.keys();
        }
        pub fn values(self: @This()) []V {
            return self.unmanaged.values();
        }
        pub fn iterator(self: @This()) Iterator {
            return self.unmanaged.iterator();
        }
    };
}

pub const ArrayListWriter = struct {
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn writeAll(self: ArrayListWriter, bytes: []const u8) !void {
        try self.list.appendSlice(self.allocator, bytes);
    }
    pub fn writeByte(self: ArrayListWriter, b: u8) !void {
        try self.list.append(self.allocator, b);
    }
    pub fn print(self: ArrayListWriter, comptime fmt: []const u8, args: anytype) !void {
        try self.list.print(self.allocator, fmt, args);
    }
    pub fn writeInt(self: ArrayListWriter, comptime T: type, value: T, endian: std.builtin.Endian) !void {
        var bytes: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
        std.mem.writeInt(T, &bytes, value, endian);
        try self.list.appendSlice(self.allocator, &bytes);
    }
};

pub fn arrayListWriter(list: *std.ArrayList(u8), allocator: std.mem.Allocator) ArrayListWriter {
    return .{ .list = list, .allocator = allocator };
}

pub var global_io: std.Io = if (builtin.is_test) std.testing.io else undefined;

pub fn nowSeconds() i64 {
    return @intCast(@divFloor(std.Io.Clock.real.now(global_io).nanoseconds, std.time.ns_per_s));
}

pub const StatInfo = struct {
    kind: enum { file, directory, sym_link, other },
    size: u64,
    mode: u32,
};

pub fn lstatOrStatFile(path: []const u8, follow_symlinks: bool) !StatInfo {
    var buf: [4096]u8 = undefined;
    if (path.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const path_z: [*:0]const u8 = buf[0..path.len :0];
    var stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const flags: u32 = if (follow_symlinks)
        linux.AT.STATX_SYNC_AS_STAT
    else
        (linux.AT.SYMLINK_NOFOLLOW | linux.AT.STATX_SYNC_AS_STAT);
    const rc = linux.statx(linux.AT.FDCWD, path_z, flags, linux.STATX.BASIC_STATS, &stx);
    return switch (linux.errno(rc)) {
        .SUCCESS => .{
            .kind = switch (stx.mode & linux.S.IFMT) {
                linux.S.IFREG => .file,
                linux.S.IFDIR => .directory,
                linux.S.IFLNK => .sym_link,
                else => .other,
            },
            .size = stx.size,
            .mode = stx.mode,
        },
        .NOENT => error.FileNotFound,
        else => error.Unexpected,
    };
}

pub fn statFileFollow(path: []const u8) !StatInfo {
    return lstatOrStatFile(path, true);
}

pub fn cwdMakePath(path: []const u8) RepinError!void {
    std.Io.Dir.cwd().createDirPath(global_io, path) catch |err| {
        return fail("cannot create directory {s}: {s}", .{ path, @errorName(err) });
    };
}

pub fn cwdRealpathAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().realPathFileAlloc(global_io, path, allocator);
}

pub fn cwdReadFileAlloc(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(global_io, path, allocator, .limited(max_bytes));
}
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const DEFAULT_MANIFEST = "tools/fixtures/real-snapshot/pin-v1.json";
pub const MANIFEST_SCHEMA = "io.github.cataggar.debz.real-snapshot-pin.v1";
pub const REPORT_SCHEMA = "io.github.cataggar.debz.real-snapshot-repin-report.v1";
pub const EVIDENCE_SCHEMA = "io.github.cataggar.debz.real-snapshot-source-evidence.v1";
pub const DEFAULT_EVIDENCE = "tools/fixtures/real-snapshot/prestate-sources-v1.zip";

pub const SETTLE_SECONDS: i64 = 24 * 60 * 60;
pub const WITNESS_WINDOW_SECONDS: i64 = 48 * 60 * 60;
pub const MAXIMUM_RELEASE_AGE_SECONDS: i64 = 31 * 24 * 60 * 60;
pub const DEBZ_DEADLINE_MS = "300000";
pub const DEBZ_LOCK_WAIT_MS = "30000";

pub const MAXIMUM_RELEASE_BYTES_DEFAULT: usize = 16 * 1024 * 1024;
pub const MAXIMUM_ARCHIVE_BYTES_DEFAULT: usize = 512 * 1024 * 1024;
pub const MAXIMUM_MEMBER_BYTES_DEFAULT: usize = 64 * 1024 * 1024;
pub const MAXIMUM_TAR_BYTES_DEFAULT: usize = 128 * 1024 * 1024;
pub const MAXIMUM_TAR_MEMBERS_DEFAULT: usize = 100000;
pub const MAXIMUM_EVIDENCE_BYTES_DEFAULT: usize = 64 * 1024 * 1024;
pub const MAXIMUM_EVIDENCE_FILES_DEFAULT: usize = 256;
pub const FETCH_TIMEOUT_SECONDS: u32 = 120;

pub var maximum_release_bytes: usize = MAXIMUM_RELEASE_BYTES_DEFAULT;
pub var maximum_archive_bytes: usize = MAXIMUM_ARCHIVE_BYTES_DEFAULT;
pub var maximum_member_bytes: usize = MAXIMUM_MEMBER_BYTES_DEFAULT;
pub var maximum_tar_bytes: usize = MAXIMUM_TAR_BYTES_DEFAULT;
pub var maximum_tar_members: usize = MAXIMUM_TAR_MEMBERS_DEFAULT;
pub var maximum_evidence_bytes: usize = MAXIMUM_EVIDENCE_BYTES_DEFAULT;
pub var maximum_evidence_files: usize = MAXIMUM_EVIDENCE_FILES_DEFAULT;

pub const SHA256_HEX: usize = Sha256.digest_length * 2;
pub const SHA512_HEX: usize = Sha512.digest_length * 2;

pub const KINDS = [_][]const u8{ "script", "tool_file", "archive", "prestate" };
pub const ROLES = [_][]const u8{ "bounded", "frozen", "witness" };
pub const BINDINGS = [_][]const u8{ "exact_lock", "refresh_identity", "refresh_only" };
pub const CONSUMER_FORMS = [_][]const u8{ "hex", "zig_bytes", "fixture", "shell" };
pub const IDENTITY_COORDINATES = [_][]const u8{ "digest", "digest_size", "url", "version", "size", "member" };
pub const SNAPSHOT_COORDINATES = [_][]const u8{ "uri", "suite", "witness_suites", "release_sha256" };
pub const STATUSES = [_][]const u8{ "unchanged", "provenance-only", "changed", "missing" };

pub const DEBZ_SNAPSHOT_CONSTANT_SOURCES = [_][]const u8{
    "src/maintainer_script.zig",
    "src/native_alternatives.zig",
    "src/native_unpack.zig",
};
pub const PROTECTED_STAGE_SCRIPT = "tools/real-snapshot-reference-protected-stage.sh";
pub const REFERENCE_LAUNCHER = "tools/real-snapshot-reference-launcher.zig";

pub const RepinError = error{
    RepinFailed,
    OutOfMemory,
};

var last_error_buf: [4096]u8 = undefined;
var last_error_len: usize = 0;

pub fn fail(comptime fmt: []const u8, args: anytype) RepinError {
    const msg = std.fmt.bufPrint(&last_error_buf, fmt, args) catch blk: {
        const fallback = "repin error (message truncated)";
        @memcpy(last_error_buf[0..fallback.len], fallback);
        break :blk last_error_buf[0..fallback.len];
    };
    last_error_len = msg.len;
    return error.RepinFailed;
}

pub fn lastErrorMessage() []const u8 {
    return last_error_buf[0..last_error_len];
}

pub fn clearErrorMessage() void {
    last_error_len = 0;
}

pub fn isLowerHex(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

pub fn isHex64(digest: []const u8) bool {
    return digest.len == 64 and isLowerHex(digest);
}

pub fn isHex128(digest: []const u8) bool {
    return digest.len == 128 and isLowerHex(digest);
}

pub fn isFingerprint(s: []const u8) bool {
    return s.len == 40 and isLowerHex(s);
}

pub fn isShellVarName(s: []const u8) bool {
    if (s.len == 0) return false;
    if (!(std.ascii.isAlphabetic(s[0]) or s[0] == '_')) return false;
    for (s[1..]) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_')) return false;
    }
    return true;
}

pub fn isPackageName(s: []const u8) bool {
    if (s.len == 0) return false;
    const first = s[0];
    if (!((first >= 'a' and first <= 'z') or (first >= '0' and first <= '9'))) return false;
    for (s[1..]) |c| {
        if (!((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '+' or c == '.' or c == '-')) return false;
    }
    return true;
}

pub fn isIdentityId(s: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return false;
    if (colon == 0 or colon + 1 >= s.len) return false;
    for (s[0..colon]) |c| {
        if (!(c >= 'a' and c <= 'z')) return false;
    }
    const rest = s[colon + 1 ..];
    if (!std.ascii.isAlphanumeric(rest[0])) return false;
    for (rest[1..]) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '.' or c == ':' or c == '/' or c == '_' or c == '@' or c == '-')) {
            return false;
        }
    }
    return true;
}

fn isRepoSlugPart(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '.' or c == '-')) return false;
    }
    return true;
}

pub fn isReviewReference(s: []const u8) bool {
    const hash = std.mem.indexOfScalar(u8, s, '#') orelse return false;
    if (hash > 0) {
        const prefix = s[0..hash];
        const slash = std.mem.indexOfScalar(u8, prefix, '/') orelse return false;
        if (std.mem.indexOfScalarPos(u8, prefix, slash + 1, '/') != null) return false;
        if (!isRepoSlugPart(prefix[0..slash]) or !isRepoSlugPart(prefix[slash + 1 ..])) return false;
    }
    const num = s[hash + 1 ..];
    if (num.len == 0 or num[0] < '1' or num[0] > '9') return false;
    for (num[1..]) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

pub fn isTimestampFormat(text: []const u8) bool {
    if (text.len != 16) return false;
    if (text[8] != 'T' or text[15] != 'Z') return false;
    for (text[0..8]) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    for (text[9..15]) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn isLeapYear(year: i64) bool {
    return (@mod(year, 4) == 0 and @mod(year, 100) != 0) or (@mod(year, 400) == 0);
}

fn daysInMonth(year: i64, month: i64) i64 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn daysFromCivil(y: i64, m: i64, d: i64) i64 {
    const yr = if (m <= 2) y - 1 else y;
    const era = @divFloor(if (yr >= 0) yr else yr - 399, 400);
    const yoe = yr - era * 400;
    const doy = @divFloor(153 * (m + (if (m > 2) @as(i64, -3) else 9)) + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

pub fn utcToEpochSeconds(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) ?i64 {
    if (month < 1 or month > 12) return null;
    const max_day = daysInMonth(year, month);
    if (day < 1 or day > max_day) return null;
    if (hour < 0 or hour > 23) return null;
    if (minute < 0 or minute > 59) return null;
    if (second < 0 or second > 60) return null;
    const days = daysFromCivil(year, month, day);
    return days * 86400 + hour * 3600 + minute * 60 + second;
}

pub fn epochSecondsToTimestamp(allocator: std.mem.Allocator, seconds: i64) ![]u8 {
    const z = @divFloor(seconds, 86400) + 719468;
    const era = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    var y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = mp + (if (mp < 10) @as(i64, 3) else -9);
    if (m <= 2) y += 1;
    const rem = @mod(seconds, 86400);
    const hr = @divFloor(rem, 3600);
    const mn = @divFloor(@mod(rem, 3600), 60);
    const sc = @mod(rem, 60);
    return std.fmt.allocPrint(
        allocator,
        "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z",
        .{ @as(u32, @intCast(y)), @as(u32, @intCast(m)), @as(u32, @intCast(d)), @as(u32, @intCast(hr)), @as(u32, @intCast(mn)), @as(u32, @intCast(sc)) },
    );
}

pub fn formatUtcTimestampHuman(allocator: std.mem.Allocator, seconds: i64) ![]u8 {
    const z = @divFloor(seconds, 86400) + 719468;
    const era = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    var y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = mp + (if (mp < 10) @as(i64, 3) else -9);
    if (m <= 2) y += 1;
    const rem = @mod(seconds, 86400);
    const hr = @divFloor(rem, 3600);
    const mn = @divFloor(@mod(rem, 3600), 60);
    const sc = @mod(rem, 60);
    return std.fmt.allocPrint(
        allocator,
        "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC",
        .{ @as(u32, @intCast(y)), @as(u32, @intCast(m)), @as(u32, @intCast(d)), @as(u32, @intCast(hr)), @as(u32, @intCast(mn)), @as(u32, @intCast(sc)) },
    );
}

pub fn timestampSeconds(text: []const u8) RepinError!i64 {
    if (!isTimestampFormat(text)) {
        return fail("snapshot timestamp must be UTC YYYYMMDDTHHMMSSZ: '{s}'", .{text});
    }
    const year = std.fmt.parseInt(i64, text[0..4], 10) catch return fail("invalid snapshot timestamp: '{s}'", .{text});
    const month = std.fmt.parseInt(i64, text[4..6], 10) catch return fail("invalid snapshot timestamp: '{s}'", .{text});
    const day = std.fmt.parseInt(i64, text[6..8], 10) catch return fail("invalid snapshot timestamp: '{s}'", .{text});
    const hour = std.fmt.parseInt(i64, text[9..11], 10) catch return fail("invalid snapshot timestamp: '{s}'", .{text});
    const minute = std.fmt.parseInt(i64, text[11..13], 10) catch return fail("invalid snapshot timestamp: '{s}'", .{text});
    const second = std.fmt.parseInt(i64, text[13..15], 10) catch return fail("invalid snapshot timestamp: '{s}'", .{text});
    return utcToEpochSeconds(year, month, day, hour, minute, second) orelse
        fail("invalid snapshot timestamp: '{s}'", .{text});
}

pub fn defaultTimestamp(allocator: std.mem.Allocator, now: i64) ![]u8 {
    const settled = now - SETTLE_SECONDS;
    const day_start = settled - @mod(settled, 24 * 60 * 60);
    return epochSecondsToTimestamp(allocator, day_start);
}

pub fn validateTimestamp(text: []const u8, now: i64, pinned: ?[]const u8) RepinError!i64 {
    const seconds = try timestampSeconds(text);
    if (now - seconds < SETTLE_SECONDS) {
        return fail(
            "snapshot {s} is less than 24 hours old; snapshot timestamps are mutable until the service has published every pocket for that time",
            .{text},
        );
    }
    if (pinned) |p| {
        const pinned_sec = try timestampSeconds(p);
        if (seconds < pinned_sec) {
            return fail("snapshot {s} is older than the current pin {s}", .{ text, p });
        }
    }
    return seconds;
}

pub fn releaseTime(value: []const u8, field: []const u8) RepinError!i64 {
    if (value.len < 20) return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    if (value[3] != ',' or value[4] != ' ') {
        return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    }
    const dow = value[0..3];
    const valid_dow = std.mem.eql(u8, dow, "Mon") or std.mem.eql(u8, dow, "Tue") or
        std.mem.eql(u8, dow, "Wed") or std.mem.eql(u8, dow, "Thu") or
        std.mem.eql(u8, dow, "Fri") or std.mem.eql(u8, dow, "Sat") or
        std.mem.eql(u8, dow, "Sun");
    if (!valid_dow) return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });

    const rest = value[5..];
    var sp = std.mem.splitScalar(u8, rest, ' ');
    const day_str = sp.next() orelse return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    const mon_str = sp.next() orelse return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    const year_str = sp.next() orelse return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    const time_str = sp.next() orelse return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    const tz_str = sp.next() orelse return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    if (sp.next() != null) return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });

    if (day_str.len == 0 or day_str.len > 2) return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    const is_utc = std.mem.eql(u8, tz_str, "UTC") or std.mem.eql(u8, tz_str, "GMT") or
        std.mem.eql(u8, tz_str, "+0000");
    if (!is_utc) {
        return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    }

    const day = std.fmt.parseInt(i64, day_str, 10) catch return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    const month: i64 = if (std.mem.eql(u8, mon_str, "Jan")) 1 else if (std.mem.eql(u8, mon_str, "Feb")) 2 else if (std.mem.eql(u8, mon_str, "Mar")) 3 else if (std.mem.eql(u8, mon_str, "Apr")) 4 else if (std.mem.eql(u8, mon_str, "May")) 5 else if (std.mem.eql(u8, mon_str, "Jun")) 6 else if (std.mem.eql(u8, mon_str, "Jul")) 7 else if (std.mem.eql(u8, mon_str, "Aug")) 8 else if (std.mem.eql(u8, mon_str, "Sep")) 9 else if (std.mem.eql(u8, mon_str, "Oct")) 10 else if (std.mem.eql(u8, mon_str, "Nov")) 11 else if (std.mem.eql(u8, mon_str, "Dec")) 12 else return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    if (year_str.len != 4) return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    const year = std.fmt.parseInt(i64, year_str, 10) catch return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });

    if (time_str.len != 8 or time_str[2] != ':' or time_str[5] != ':') {
        return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    }
    const hour = std.fmt.parseInt(i64, time_str[0..2], 10) catch return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    const minute = std.fmt.parseInt(i64, time_str[3..5], 10) catch return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
    const second = std.fmt.parseInt(i64, time_str[6..8], 10) catch return fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });

    return utcToEpochSeconds(year, month, day, hour, minute, second) orelse
        fail("Release {s} is not an RFC 2822 UTC time: '{s}'", .{ field, value });
}

pub fn sha256HexLower(data: []const u8) [SHA256_HEX]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn sha512HexLower(data: []const u8) [SHA512_HEX]u8 {
    var digest: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn tagged(allocator: std.mem.Allocator, algorithm: []const u8, data: []const u8) RepinError![]u8 {
    if (std.mem.eql(u8, algorithm, "sha256")) {
        const hex = sha256HexLower(data);
        return std.fmt.allocPrint(allocator, "sha256:{s}", .{&hex});
    } else if (std.mem.eql(u8, algorithm, "sha512")) {
        const hex = sha512HexLower(data);
        return std.fmt.allocPrint(allocator, "sha512:{s}", .{&hex});
    }
    return fail("unsupported digest algorithm: {s}", .{algorithm});
}

pub const ParsedDigest = struct {
    algorithm: []const u8,
    hex: []const u8,
};

pub fn parseTaggedValue(
    value: std.json.Value,
    algorithms: []const []const u8,
) RepinError!ParsedDigest {
    if (value != .string) return fail("digest must be an algorithm-tagged string", .{});
    return parseTaggedStr(value.string, algorithms);
}

pub fn parseTaggedStr(
    text: []const u8,
    algorithms: []const []const u8,
) RepinError!ParsedDigest {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse
        return fail("digest must be an algorithm-tagged string: '{s}'", .{text});
    const algorithm = text[0..colon];
    const hex = text[colon + 1 ..];
    var allowed = false;
    for (algorithms) |a| {
        if (std.mem.eql(u8, a, algorithm)) {
            allowed = true;
            break;
        }
    }
    if (!allowed) {
        return fail("unsupported digest algorithm in '{s}'", .{text});
    }
    const expected_len: usize = if (std.mem.eql(u8, algorithm, "sha256"))
        SHA256_HEX
    else if (std.mem.eql(u8, algorithm, "sha512"))
        SHA512_HEX
    else
        return fail("unsupported digest algorithm in '{s}'", .{text});

    if (hex.len != expected_len or !isLowerHex(hex)) {
        return fail("invalid {s} digest '{s}'", .{ algorithm, text });
    }
    return .{ .algorithm = algorithm, .hex = hex };
}

pub fn lockDigest(allocator: std.mem.Allocator, value: []const u8, algorithm: []const u8) RepinError![]u8 {
    if (std.mem.indexOfScalar(u8, value, ':') != null) {
        _ = try parseTaggedStr(value, &.{algorithm});
        return allocator.dupe(u8, value);
    }
    const tagged_str = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ algorithm, value });
    _ = try parseTaggedStr(tagged_str, &.{algorithm});
    return tagged_str;
}

pub fn sliceContains(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

pub fn cloneJsonValue(allocator: std.mem.Allocator, val: std.json.Value) !std.json.Value {
    return switch (val) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .integer = i },
        .float => |f| .{ .float = f },
        .number_string => |s| .{ .number_string = try allocator.dupe(u8, s) },
        .string => |s| .{ .string = try allocator.dupe(u8, s) },
        .array => |arr| blk: {
            var new_arr = std.json.Array.init(allocator);
            try new_arr.ensureTotalCapacity(arr.items.len);
            for (arr.items) |item| {
                new_arr.appendAssumeCapacity(try cloneJsonValue(allocator, item));
            }
            break :blk .{ .array = new_arr };
        },
        .object => |obj| blk: {
            var new_obj: std.json.ObjectMap = .empty;
            try new_obj.ensureTotalCapacity(allocator, obj.count());
            var it = obj.iterator();
            while (it.next()) |entry| {
                try new_obj.put(
                    allocator,
                    try allocator.dupe(u8, entry.key_ptr.*),
                    try cloneJsonValue(allocator, entry.value_ptr.*),
                );
            }
            break :blk .{ .object = new_obj };
        },
    };
}

pub fn jsonEql(a: std.json.Value, b: std.json.Value) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |av| return b == .bool and av == b.bool,
        .integer => |av| return b == .integer and av == b.integer,
        .float => |av| return b == .float and av == b.float,
        .number_string => |av| return b == .number_string and std.mem.eql(u8, av, b.number_string),
        .string => |av| return b == .string and std.mem.eql(u8, av, b.string),
        .array => |av| {
            if (b != .array) return false;
            if (av.items.len != b.array.items.len) return false;
            for (av.items, b.array.items) |ai, bi| {
                if (!jsonEql(ai, bi)) return false;
            }
            return true;
        },
        .object => |av| {
            if (b != .object) return false;
            if (av.count() != b.object.count()) return false;
            var it = av.iterator();
            while (it.next()) |entry| {
                const bv = b.object.get(entry.key_ptr.*) orelse return false;
                if (!jsonEql(entry.value_ptr.*, bv)) return false;
            }
            return true;
        },
    }
}

pub fn writeJsonStringLiteral(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    var i: usize = 0;
    while (i < s.len) {
        const b = s[i];
        switch (b) {
            '"' => {
                try writer.writeAll("\\\"");
                i += 1;
            },
            '\\' => {
                try writer.writeAll("\\\\");
                i += 1;
            },
            '\x08' => {
                try writer.writeAll("\\b");
                i += 1;
            },
            '\x0c' => {
                try writer.writeAll("\\f");
                i += 1;
            },
            '\n' => {
                try writer.writeAll("\\n");
                i += 1;
            },
            '\r' => {
                try writer.writeAll("\\r");
                i += 1;
            },
            '\t' => {
                try writer.writeAll("\\t");
                i += 1;
            },
            0x00...0x07, 0x0b, 0x0e...0x1f => {
                try writer.print("\\u{x:0>4}", .{b});
                i += 1;
            },
            0x20...0x21, 0x23...0x5b, 0x5d...0x7f => {
                try writer.writeByte(b);
                i += 1;
            },
            else => {
                const seq_len = std.unicode.utf8ByteSequenceLength(b) catch 1;
                if (i + seq_len <= s.len) {
                    const cp = std.unicode.utf8Decode(s[i .. i + seq_len]) catch 0xfffd;
                    if (cp <= 0xffff) {
                        try writer.print("\\u{x:0>4}", .{cp});
                    } else {
                        const adj = cp - 0x10000;
                        const high: u16 = @intCast(0xd800 + (adj >> 10));
                        const low: u16 = @intCast(0xdc00 + (adj & 0x3ff));
                        try writer.print("\\u{x:0>4}\\u{x:0>4}", .{ high, low });
                    }
                    i += seq_len;
                } else {
                    try writer.print("\\u{x:0>4}", .{b});
                    i += 1;
                }
            },
        }
    }
    try writer.writeByte('"');
}

fn writeIndent(writer: anytype, depth: usize) !void {
    for (0..depth) |_| {
        try writer.writeAll("  ");
    }
}

fn writeCanonicalValue(
    allocator: std.mem.Allocator,
    writer: anytype,
    val: std.json.Value,
    depth: usize,
) !void {
    switch (val) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.writeAll(if (b) "true" else "false"),
        .integer => |n| try writer.print("{d}", .{n}),
        .float => |f| try writer.print("{d}", .{f}),
        .number_string => |s| try writer.writeAll(s),
        .string => |s| try writeJsonStringLiteral(writer, s),
        .array => |arr| {
            if (arr.items.len == 0) {
                try writer.writeAll("[]");
                return;
            }
            try writer.writeAll("[\n");
            for (arr.items, 0..) |item, idx| {
                try writeIndent(writer, depth + 1);
                try writeCanonicalValue(allocator, writer, item, depth + 1);
                if (idx + 1 < arr.items.len) try writer.writeByte(',');
                try writer.writeByte('\n');
            }
            try writeIndent(writer, depth);
            try writer.writeByte(']');
        },
        .object => |obj| {
            if (obj.count() == 0) {
                try writer.writeAll("{}");
                return;
            }
            const keys = try allocator.alloc([]const u8, obj.count());
            defer allocator.free(keys);
            var idx: usize = 0;
            var it = obj.iterator();
            while (it.next()) |entry| : (idx += 1) {
                keys[idx] = entry.key_ptr.*;
            }
            std.mem.sort([]const u8, keys, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.lessThan(u8, a, b);
                }
            }.lessThan);
            try writer.writeAll("{\n");
            for (keys, 0..) |k, k_idx| {
                try writeIndent(writer, depth + 1);
                try writeJsonStringLiteral(writer, k);
                try writer.writeAll(": ");
                try writeCanonicalValue(allocator, writer, obj.get(k).?, depth + 1);
                if (k_idx + 1 < keys.len) try writer.writeByte(',');
                try writer.writeByte('\n');
            }
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
    }
}

pub fn canonicalJson(allocator: std.mem.Allocator, document: std.json.Value) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try writeCanonicalValue(allocator, arrayListWriter(&list, allocator), document, 0);
    try list.append(allocator, '\n');
    return list.toOwnedSlice(allocator);
}

pub fn writeJson(allocator: std.mem.Allocator, path: []const u8, document: std.json.Value) !void {
    const rendered = try canonicalJson(allocator, document);
    defer allocator.free(rendered);
    try writeFileBytes(path, rendered);
}

pub fn writeFileBytes(path: []const u8, data: []const u8) RepinError!void {
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) {
            try cwdMakePath(dir);
        }
    }
    std.Io.Dir.cwd().writeFile(global_io, .{ .sub_path = path, .data = data }) catch |err| {
        return fail("cannot write {s}: {s}", .{ path, @errorName(err) });
    };
}

pub fn readFileBounded(
    allocator: std.mem.Allocator,
    path: []const u8,
    max_bytes: usize,
    where: []const u8,
) RepinError![]u8 {
    const stat = statFileFollow(path) catch |err| {
        return fail("cannot read {s} ({s}): {s}", .{ where, path, @errorName(err) });
    };
    if (stat.kind != .file) {
        return fail("{s} ({s}) is not a regular file", .{ where, path });
    }
    if (stat.size > max_bytes) {
        return fail("{s} is too large", .{where});
    }
    const data = cwdReadFileAlloc(allocator, path, max_bytes + 1) catch |err| {
        if (err == error.StreamTooLong) return fail("{s} is too large", .{where});
        return fail("cannot read {s}: {s}", .{ where, @errorName(err) });
    };
    if (data.len > max_bytes) {
        allocator.free(data);
        return fail("{s} is too large", .{where});
    }
    return data;
}

pub fn loadJson(allocator: std.mem.Allocator, path: []const u8) RepinError!std.json.Value {
    const raw = try readFileBounded(allocator, path, maximum_release_bytes, "JSON document");
    return parseJsonObjectBytes(allocator, raw, path);
}

pub fn parseJsonObjectBytes(
    allocator: std.mem.Allocator,
    raw: []const u8,
    where: []const u8,
) RepinError!std.json.Value {
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, allocator, raw, .{}) catch |err| {
        return fail("{s} is invalid JSON: {s}", .{ where, @errorName(err) });
    };
    if (parsed != .object) {
        return fail("{s} must be a JSON object", .{where});
    }
    return parsed;
}

pub fn makeBuiltinProfile(allocator: std.mem.Allocator, name: []const u8) !?std.json.Value {
    if (std.mem.eql(u8, name, "ubuntu-stonking")) {
        var obj: std.json.ObjectMap = .empty;
        try obj.put(allocator, "name", .{ .string = "ubuntu-stonking" });
        try obj.put(allocator, "uri_root", .{ .string = "https://snapshot.ubuntu.com/ubuntu" });
        try obj.put(allocator, "component", .{ .string = "main" });
        var archs = std.json.Array.init(allocator);
        try archs.append(.{ .string = "amd64" });
        try archs.append(.{ .string = "arm64" });
        try obj.put(allocator, "architectures", .{ .array = archs });
        try obj.put(allocator, "keyring", .{ .string = "/usr/share/keyrings/ubuntu-archive-keyring.gpg" });
        try obj.put(allocator, "signer", .{ .string = "f6ecb3762474eda9d21b7022871920d1991bc93c" });
        try obj.put(allocator, "request", .{ .string = "ubuntu-minimal" });
        var pockets = std.json.Array.init(allocator);
        var p0: std.json.ObjectMap = .empty;
        try p0.put(allocator, "suite", .{ .string = "stonking" });
        try p0.put(allocator, "role", .{ .string = "bounded" });
        try pockets.append(.{ .object = p0 });
        try obj.put(allocator, "pockets", .{ .array = pockets });
        return .{ .object = obj };
    } else if (std.mem.eql(u8, name, "ubuntu-resolute")) {
        var obj: std.json.ObjectMap = .empty;
        try obj.put(allocator, "name", .{ .string = "ubuntu-resolute" });
        try obj.put(allocator, "uri_root", .{ .string = "https://snapshot.ubuntu.com/ubuntu" });
        try obj.put(allocator, "component", .{ .string = "main" });
        var archs = std.json.Array.init(allocator);
        try archs.append(.{ .string = "amd64" });
        try archs.append(.{ .string = "arm64" });
        try obj.put(allocator, "architectures", .{ .array = archs });
        try obj.put(allocator, "keyring", .{ .string = "/usr/share/keyrings/ubuntu-archive-keyring.gpg" });
        try obj.put(allocator, "signer", .{ .string = "f6ecb3762474eda9d21b7022871920d1991bc93c" });
        try obj.put(allocator, "request", .{ .string = "ubuntu-minimal" });
        var pockets = std.json.Array.init(allocator);
        const specs = [_]struct { suite: []const u8, role: []const u8 }{
            .{ .suite = "resolute", .role = "frozen" },
            .{ .suite = "resolute-updates", .role = "witness" },
            .{ .suite = "resolute-security", .role = "witness" },
        };
        for (specs) |sp| {
            var p: std.json.ObjectMap = .empty;
            try p.put(allocator, "suite", .{ .string = sp.suite });
            try p.put(allocator, "role", .{ .string = sp.role });
            try pockets.append(.{ .object = p });
        }
        try obj.put(allocator, "pockets", .{ .array = pockets });
        return .{ .object = obj };
    }
    return null;
}

pub fn exactKeys(
    value: std.json.Value,
    required: []const []const u8,
    optional: []const []const u8,
    where: []const u8,
) RepinError!std.json.ObjectMap {
    if (value != .object) {
        return fail("{s} must be an object", .{where});
    }
    const obj = value.object;
    for (required) |req| {
        if (!obj.contains(req)) {
            return fail("{s} is missing ['{s}']", .{ where, req });
        }
    }
    var it = obj.iterator();
    while (it.next()) |entry| {
        const k = entry.key_ptr.*;
        if (!sliceContains(required, k) and !sliceContains(optional, k)) {
            return fail("{s} has unknown ['{s}'] fields", .{ where, k });
        }
    }
    return obj;
}

pub fn validateRelativePath(path_val: std.json.Value, where: []const u8) RepinError![]const u8 {
    if (path_val != .string) return fail("{s} must be repository-relative", .{where});
    return validateRelativePathStr(path_val.string, where);
}

pub fn validateRelativePathStr(path: []const u8, where: []const u8) RepinError![]const u8 {
    if (path.len == 0 or path[0] == '/' or std.mem.indexOfScalar(u8, path, 0) != null or
        std.mem.indexOfScalar(u8, path, '\n') != null or std.mem.indexOfScalar(u8, path, '\r') != null)
    {
        return fail("{s} must be repository-relative", .{where});
    }
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) {
            return fail("{s} must be repository-relative", .{where});
        }
    }
    return path;
}

pub fn validateProfile(allocator: std.mem.Allocator, profile: std.json.Value, where: []const u8) RepinError!std.json.Value {
    const obj = try exactKeys(
        profile,
        &.{ "name", "uri_root", "component", "architectures", "keyring", "signer", "request", "pockets" },
        &.{},
        where,
    );
    const name_val = obj.get("name").?;
    if (name_val != .string or name_val.string.len == 0) {
        return fail("{s}.name is invalid", .{where});
    }
    for (name_val.string) |c| {
        if (!((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-')) {
            return fail("{s}.name is invalid", .{where});
        }
    }
    const uri_val = obj.get("uri_root").?;
    if (uri_val != .string or
        (!std.mem.startsWith(u8, uri_val.string, "https://") and !std.mem.startsWith(u8, uri_val.string, "file://")) or
        std.mem.indexOfAny(u8, uri_val.string, "?#") != null or
        std.mem.endsWith(u8, uri_val.string, "/"))
    {
        return fail("{s}.uri_root must be an https or file URI without a trailing slash", .{where});
    }
    const archs_val = obj.get("architectures").?;
    if (archs_val != .array or archs_val.array.items.len == 0) {
        return fail("{s}.architectures must list distinct amd64/arm64 values", .{where});
    }
    var seen_archs = std.StringHashMap(void).init(allocator);
    defer seen_archs.deinit();
    for (archs_val.array.items) |a| {
        if (a != .string or (!std.mem.eql(u8, a.string, "amd64") and !std.mem.eql(u8, a.string, "arm64")) or seen_archs.contains(a.string)) {
            return fail("{s}.architectures must list distinct amd64/arm64 values", .{where});
        }
        try seen_archs.put(a.string, {});
    }
    const kr_val = obj.get("keyring").?;
    if (kr_val != .string or !std.mem.startsWith(u8, kr_val.string, "/")) {
        return fail("{s}.keyring must be absolute", .{where});
    }
    const signer = obj.get("signer").?;
    if (signer != .string or !isFingerprint(signer.string)) {
        return fail("{s}.signer must be a lowercase v4 fingerprint", .{where});
    }
    for ([_][]const u8{ "component", "request" }) |field| {
        const fv = obj.get(field).?;
        if (fv != .string or !isPackageName(fv.string)) {
            return fail("{s}.{s} is invalid", .{ where, field });
        }
    }
    const pockets_val = obj.get("pockets").?;
    if (pockets_val != .array or pockets_val.array.items.len == 0) {
        return fail("{s}.pockets must be a non-empty list", .{where});
    }
    var seen_suites = std.StringHashMap(void).init(allocator);
    defer seen_suites.deinit();
    var frozen_count: usize = 0;
    var witness_count: usize = 0;
    for (pockets_val.array.items, 0..) |pocket, idx| {
        const p_where = try std.fmt.allocPrint(allocator, "{s}.pockets[{d}]", .{ where, idx });
        const p_obj = try exactKeys(pocket, &.{ "suite", "role" }, &.{}, p_where);
        const suite = p_obj.get("suite").?;
        const role = p_obj.get("role").?;
        if (suite != .string or !isPackageName(suite.string)) {
            return fail("{s}.pockets[{d}].suite is invalid", .{ where, idx });
        }
        if (role != .string or !sliceContains(&ROLES, role.string) or seen_suites.contains(suite.string)) {
            return fail("{s}.pockets[{d}] has an invalid role or duplicate suite", .{ where, idx });
        }
        try seen_suites.put(suite.string, {});
        if (std.mem.eql(u8, role.string, "frozen")) frozen_count += 1;
        if (std.mem.eql(u8, role.string, "witness")) witness_count += 1;
    }
    if (frozen_count > 1 or (frozen_count > 0) != (witness_count > 0)) {
        return fail("{s} must pair exactly one frozen pocket with witness pockets", .{where});
    }
    return profile;
}

pub fn resolveProfile(
    allocator: std.mem.Allocator,
    name: []const u8,
    profile_path: ?[]const u8,
) RepinError!std.json.Value {
    if (profile_path) |p| {
        const loaded = try loadJson(allocator, p);
        const validated = try validateProfile(allocator, loaded, "profile");
        if (!std.mem.eql(u8, validated.object.get("name").?.string, name)) {
            return fail("profile {s} is for {s}, not {s}", .{ p, validated.object.get("name").?.string, name });
        }
        if ((try makeBuiltinProfile(allocator, name)) != null) {
            return fail("{s} is a built-in profile; it cannot be replaced", .{name});
        }
        return validated;
    }
    if (try makeBuiltinProfile(allocator, name)) |builtin_prof| {
        return validateProfile(allocator, builtin_prof, "series");
    }
    return fail("unknown series {s}; pass --profile for a new series", .{name});
}

pub fn validateCoordinateBindings(
    allocator: std.mem.Allocator,
    bindings: std.json.Value,
    coordinates: []const []const u8,
    where: []const u8,
) RepinError!void {
    if (bindings != .object or bindings.object.count() == 0) {
        return fail("{s}: invalid typed coordinate bindings", .{where});
    }
    var seen_vars = std.StringHashMap(void).init(allocator);
    defer seen_vars.deinit();
    var it = bindings.object.iterator();
    while (it.next()) |entry| {
        const coord = entry.key_ptr.*;
        const var_val = entry.value_ptr.*;
        if (!sliceContains(coordinates, coord) or var_val != .string or !isShellVarName(var_val.string) or seen_vars.contains(var_val.string)) {
            return fail("{s}: invalid typed coordinate bindings", .{where});
        }
        try seen_vars.put(var_val.string, {});
    }
}

pub fn validateConsumer(
    allocator: std.mem.Allocator,
    consumer: std.json.Value,
    where: []const u8,
) RepinError!void {
    const obj = try exactKeys(consumer, &.{ "path", "form" }, &.{ "name", "bindings" }, where);
    _ = try validateRelativePath(obj.get("path").?, try std.fmt.allocPrint(allocator, "{s}.path", .{where}));
    const form_val = obj.get("form").?;
    if (form_val != .string or !sliceContains(&CONSUMER_FORMS, form_val.string)) {
        return fail("{s}.form is invalid", .{where});
    }
    const form = form_val.string;
    if (std.mem.eql(u8, form, "zig_bytes") != obj.contains("name")) {
        return fail("{s}: only zig_bytes consumers name a constant", .{where});
    }
    if (obj.get("name")) |n| {
        if (n != .string or n.string.len == 0) return fail("{s}.name is invalid", .{where});
    }
    if (std.mem.eql(u8, form, "shell") != obj.contains("bindings")) {
        return fail("{s}: exactly shell consumers list coordinate bindings", .{where});
    }
    if (std.mem.eql(u8, form, "shell")) {
        const bindings = obj.get("bindings").?;
        try validateCoordinateBindings(allocator, bindings, &IDENTITY_COORDINATES, where);
        if (!bindings.object.contains("digest") and !bindings.object.contains("digest_size")) {
            return fail("{s}: shell consumers must bind their digest", .{where});
        }
    }
}

pub fn validateProvenance(
    allocator: std.mem.Allocator,
    provenance: std.json.Value,
    architectures: []const []const u8,
    where: []const u8,
) RepinError!void {
    if (provenance == .string and std.mem.eql(u8, provenance.string, "pending")) {
        return;
    }
    const p_where = try std.fmt.allocPrint(allocator, "{s}.provenance", .{where});
    const obj = try exactKeys(provenance, &.{ "version", "archives" }, &.{}, p_where);
    const ver = obj.get("version").?;
    if (ver != .string or ver.string.len == 0) {
        return fail("{s}.provenance.version is invalid", .{where});
    }
    const archives = obj.get("archives").?;
    if (archives != .object or archives.object.count() != architectures.len) {
        return fail("{s}.provenance.archives must cover the identity architectures", .{where});
    }
    for (architectures) |arch| {
        const a_val = archives.object.get(arch) orelse
            return fail("{s}.provenance.archives must cover the identity architectures", .{where});
        _ = try parseTaggedValue(a_val, &.{"sha512"});
    }
}

pub fn validateIdentity(
    allocator: std.mem.Allocator,
    identity: std.json.Value,
    index: usize,
) RepinError!std.json.Value {
    const where = try std.fmt.allocPrint(allocator, "identities[{d}]", .{index});
    const obj = try exactKeys(
        identity,
        &.{
            "id",            "kind",       "package",   "architectures", "path", "digest", "size", "mode",
            "version_bound", "provenance", "consumers", "review",
        },
        &.{ "derived_from", "artifact" },
        where,
    );
    const id_val = obj.get("id").?;
    if (id_val != .string or !isIdentityId(id_val.string)) {
        return fail("{s}.id is invalid", .{where});
    }
    const kind_val = obj.get("kind").?;
    if (kind_val != .string or !sliceContains(&KINDS, kind_val.string)) {
        return fail("{s}.kind is invalid", .{where});
    }
    const kind = kind_val.string;
    const pkg_val = obj.get("package").?;
    if (pkg_val != .string or !isPackageName(pkg_val.string)) {
        return fail("{s}.package is invalid", .{where});
    }
    const archs_val = obj.get("architectures").?;
    if (archs_val != .array or archs_val.array.items.len == 0) {
        return fail("{s}.architectures is invalid", .{where});
    }
    var archs_list: [4][]const u8 = undefined;
    var archs_len: usize = 0;
    for (archs_val.array.items) |a| {
        if (a != .string or (!std.mem.eql(u8, a.string, "amd64") and !std.mem.eql(u8, a.string, "arm64")) or
            sliceContains(archs_list[0..archs_len], a.string))
        {
            return fail("{s}.architectures is invalid", .{where});
        }
        archs_list[archs_len] = a.string;
        archs_len += 1;
    }
    const architectures = archs_list[0..archs_len];

    const parsed_digest = try parseTaggedValue(obj.get("digest").?, &.{ "sha256", "sha512" });
    if (std.mem.eql(u8, kind, "archive") != std.mem.eql(u8, parsed_digest.algorithm, "sha512")) {
        return fail("{s}: archives bind SHA-512 and members bind SHA-256", .{where});
    }
    if (std.mem.eql(u8, kind, "archive")) {
        if (obj.get("path").? != .null or obj.get("mode").? != .null) {
            return fail("{s}: an archive identity has no path or mode", .{where});
        }
    } else {
        const path_val = obj.get("path").?;
        if (path_val != .string) return fail("{s}.path is invalid", .{where});
        _ = validateRelativePathStr(path_val.string, where) catch return fail("{s}.path is invalid", .{where});
        const mode_val = obj.get("mode").?;
        if (mode_val == .null and std.mem.eql(u8, kind, "prestate")) {
            // allowed
        } else {
            if (mode_val != .string or (mode_val.string.len != 4 and mode_val.string.len != 5) or mode_val.string[0] != '0') {
                return fail("{s}.mode must be an octal string", .{where});
            }
            for (mode_val.string[1..]) |c| {
                if (c < '0' or c > '7') return fail("{s}.mode must be an octal string", .{where});
            }
        }
    }

    const size_val = obj.get("size").?;
    if (size_val != .integer or size_val.integer < 0) {
        return fail("{s}.size is invalid", .{where});
    }
    if (obj.get("version_bound").? != .bool) {
        return fail("{s}.version_bound must be a boolean", .{where});
    }
    const version_bound = obj.get("version_bound").?.bool;

    const derived = obj.get("derived_from");
    if (std.mem.eql(u8, kind, "prestate") != (derived != null)) {
        return fail("{s}: exactly the prestate identities list derived_from", .{where});
    }
    if (derived) |dv| {
        if (dv != .array) return fail("{s}.derived_from must be a list", .{where});
        for (dv.array.items, 0..) |item, d_idx| {
            const d_where = try std.fmt.allocPrint(allocator, "{s}.derived_from[{d}]", .{ where, d_idx });
            const d_obj = try exactKeys(item, &.{ "package", "version" }, &.{}, d_where);
            const dp = d_obj.get("package").?;
            const dver = d_obj.get("version").?;
            if (dp != .string or !isPackageName(dp.string) or dver != .string or dver.string.len == 0) {
                return fail("{s} is invalid", .{d_where});
            }
        }
    }

    const provenance = obj.get("provenance").?;
    try validateProvenance(allocator, provenance, architectures, where);
    const prov_is_pending = provenance == .string and std.mem.eql(u8, provenance.string, "pending");

    const artifact = obj.get("artifact");
    if (artifact) |art| {
        const a_where = try std.fmt.allocPrint(allocator, "{s}.artifact", .{where});
        const a_obj = try exactKeys(art, &.{ "filename", "architecture" }, &.{}, a_where);
        const filename = try validateRelativePath(a_obj.get("filename").?, try std.fmt.allocPrint(allocator, "{s}.filename", .{a_where}));
        if (prov_is_pending) {
            return fail("{s}.artifact requires recorded provenance", .{where});
        }
        const art_arch_val = a_obj.get("architecture").?;
        if (art_arch_val != .string or (!std.mem.eql(u8, art_arch_val.string, "all") and !sliceContains(architectures, art_arch_val.string))) {
            return fail("{s}.artifact.architecture is invalid", .{where});
        }
        const full_ver = provenance.object.get("version").?.string;
        const ver_no_epoch = if (std.mem.indexOfScalar(u8, full_ver, ':')) |c| full_ver[c + 1 ..] else full_ver;
        const expected_base = try std.fmt.allocPrint(allocator, "{s}_{s}_{s}.deb", .{ pkg_val.string, ver_no_epoch, art_arch_val.string });
        if (!std.mem.eql(u8, std.fs.path.basename(filename), expected_base)) {
            return fail("{s}.artifact.filename disagrees with the package, version or architecture", .{where});
        }
    }

    if (version_bound and prov_is_pending) {
        return fail("{s}.version_bound requires recorded provenance", .{where});
    }

    const consumers_val = obj.get("consumers").?;
    if (consumers_val != .array or consumers_val.array.items.len == 0) {
        return fail("{s} has no consumer", .{where});
    }
    for (consumers_val.array.items, 0..) |c_item, c_idx| {
        const c_where = try std.fmt.allocPrint(allocator, "{s}.consumers[{d}]", .{ where, c_idx });
        try validateConsumer(allocator, c_item, c_where);
        if (std.mem.eql(u8, c_item.object.get("form").?.string, "shell")) {
            const b_obj = c_item.object.get("bindings").?.object;
            if (b_obj.contains("url") and artifact == null) {
                return fail("{s}: URL bindings require artifact coordinates", .{where});
            }
            if (b_obj.contains("version") and prov_is_pending) {
                return fail("{s}: version bindings require recorded provenance", .{where});
            }
            if (b_obj.contains("member") and obj.get("path").? == .null) {
                return fail("{s}: member bindings require a member path", .{where});
            }
        }
    }
    if (artifact != null) {
        var has_complete_shell = false;
        for (consumers_val.array.items) |c_item| {
            if (std.mem.eql(u8, c_item.object.get("form").?.string, "shell")) {
                const b_obj = c_item.object.get("bindings").?.object;
                if (b_obj.contains("url") and b_obj.contains("size") and
                    (std.mem.eql(u8, kind, "archive") or b_obj.contains("member")))
                {
                    has_complete_shell = true;
                    break;
                }
            }
        }
        if (!has_complete_shell) {
            return fail("{s}: artifact requires a complete typed URL/size/member consumer", .{where});
        }
    }

    const rev = obj.get("review").?;
    if (rev != .string or !isReviewReference(rev.string)) {
        return fail("{s}.review must be a PR or issue reference", .{where});
    }
    return identity;
}

pub fn validateSnapshot(
    allocator: std.mem.Allocator,
    snapshot: std.json.Value,
    profile: std.json.Value,
) RepinError!std.json.Value {
    const obj = try exactKeys(
        snapshot,
        &.{ "timestamp", "status" },
        &.{ "pockets", "admission_deadline", "closures" },
        "snapshot",
    );
    const ts_val = obj.get("timestamp").?;
    if (ts_val != .string) return fail("snapshot.timestamp must be a string", .{});
    _ = try timestampSeconds(ts_val.string);
    const status_val = obj.get("status").?;
    if (status_val != .string) return fail("snapshot.status must be pending or probed", .{});
    if (std.mem.eql(u8, status_val.string, "pending")) {
        if (obj.count() != 2) {
            return fail("a pending snapshot records only its timestamp", .{});
        }
        return snapshot;
    }
    if (!std.mem.eql(u8, status_val.string, "probed")) {
        return fail("snapshot.status must be pending or probed", .{});
    }
    _ = try exactKeys(
        snapshot,
        &.{ "timestamp", "status", "pockets", "admission_deadline", "closures" },
        &.{},
        "snapshot",
    );
    const pockets_val = obj.get("pockets").?;
    const prof_pockets = profile.object.get("pockets").?.array.items;
    if (pockets_val != .array or pockets_val.array.items.len != prof_pockets.len) {
        return fail("snapshot.pockets must follow the series pockets", .{});
    }
    for (pockets_val.array.items, prof_pockets, 0..) |pocket, prof_p, idx| {
        if (pocket != .object) return fail("snapshot.pockets must follow the series pockets", .{});
        const s_val = pocket.object.get("suite") orelse return fail("snapshot.pockets must follow the series pockets", .{});
        if (s_val != .string or !std.mem.eql(u8, s_val.string, prof_p.object.get("suite").?.string)) {
            return fail("snapshot.pockets must follow the series pockets", .{});
        }
        const p_where = try std.fmt.allocPrint(allocator, "snapshot.pockets[{d}]", .{idx});
        const p_obj = try exactKeys(
            pocket,
            &.{
                "suite",             "role",        "date",    "valid_until", "release_sha256", "in_release_sha256",
                "in_release_sha512", "hash_fields", "signers", "deadline",    "binding",
            },
            &.{"review"},
            p_where,
        );
        const binding = p_obj.get("binding").?;
        const prof_archs = profile.object.get("architectures").?.array.items;
        if (binding != .object or binding.object.count() != prof_archs.len) {
            return fail("snapshot.pockets[{d}].binding must give every series architecture one of exact_lock, refresh_identity, refresh_only", .{idx});
        }
        for (prof_archs) |pa| {
            const bval = binding.object.get(pa.string) orelse
                return fail("snapshot.pockets[{d}].binding must give every series architecture one of exact_lock, refresh_identity, refresh_only", .{idx});
            if (bval != .string or !sliceContains(&BINDINGS, bval.string)) {
                return fail("snapshot.pockets[{d}].binding must give every series architecture one of exact_lock, refresh_identity, refresh_only", .{idx});
            }
        }
        _ = try parseTaggedValue(p_obj.get("release_sha256").?, &.{"sha256"});
        _ = try parseTaggedValue(p_obj.get("in_release_sha256").?, &.{"sha256"});
        _ = try parseTaggedValue(p_obj.get("in_release_sha512").?, &.{"sha512"});
        const role_val = p_obj.get("role").?;
        if (role_val != .string or !std.mem.eql(u8, role_val.string, prof_p.object.get("role").?.string)) {
            return fail("snapshot.pockets[{d}].role differs from the series", .{idx});
        }
        const signers_val = p_obj.get("signers").?;
        if (signers_val != .array or signers_val.array.items.len != 1 or
            signers_val.array.items[0] != .string or
            !std.mem.eql(u8, signers_val.array.items[0].string, profile.object.get("signer").?.string))
        {
            return fail("snapshot.pockets[{d}] has an unreviewed signer", .{idx});
        }
        if (std.mem.eql(u8, role_val.string, "frozen")) {
            const rev_val = p_obj.get("review") orelse return fail("the frozen pocket must carry the review that accepted its Release", .{});
            if (rev_val != .string or !isReviewReference(rev_val.string)) {
                return fail("the frozen pocket must carry the review that accepted its Release", .{});
            }
        } else if (p_obj.contains("review")) {
            return fail("only the frozen pocket carries a release review", .{});
        }
    }
    if (obj.get("admission_deadline").? != .integer) {
        return fail("snapshot.admission_deadline must be an integer", .{});
    }
    const closures_val = obj.get("closures").?;
    const prof_archs = profile.object.get("architectures").?.array.items;
    if (closures_val != .object or closures_val.object.count() != prof_archs.len) {
        return fail("snapshot.closures must cover the series architectures", .{});
    }
    for (prof_archs) |pa| {
        const arch = pa.string;
        if (!closures_val.object.contains(arch)) {
            return fail("snapshot.closures must cover the series architectures", .{});
        }
        const c_where = try std.fmt.allocPrint(allocator, "snapshot.closures.{s}", .{arch});
        const c_obj = try exactKeys(
            closures_val.object.get(arch).?,
            &.{ "digest", "package_count", "packages", "pockets" },
            &.{},
            c_where,
        );
        _ = try parseTaggedValue(c_obj.get("digest").?, &.{"sha256"});
        const pkgs = c_obj.get("packages").?;
        const pkg_count = c_obj.get("package_count").?;
        if (pkgs != .object or pkg_count != .integer or pkg_count.integer != @as(i64, @intCast(pkgs.object.count()))) {
            return fail("snapshot.closures.{s}.packages does not match package_count", .{arch});
        }
    }
    return snapshot;
}

pub fn validateManifest(allocator: std.mem.Allocator, manifest: std.json.Value) RepinError!std.json.Value {
    const obj = try exactKeys(
        manifest,
        &.{ "schema", "series", "snapshot", "uri_consumers", "identities", "excluded" },
        &.{ "coordinate_consumers", "prestate_evidence" },
        "manifest",
    );
    const schema_val = obj.get("schema").?;
    if (schema_val != .string or !std.mem.eql(u8, schema_val.string, MANIFEST_SCHEMA)) {
        return fail("unsupported manifest schema", .{});
    }
    const profile = try validateProfile(allocator, obj.get("series").?, "series");
    _ = try validateSnapshot(allocator, obj.get("snapshot").?, profile);

    const uri_consumers = obj.get("uri_consumers").?;
    if (uri_consumers != .array) return fail("uri_consumers must be a list of paths", .{});
    for (uri_consumers.array.items) |u_item| {
        if (u_item != .string) return fail("uri_consumers must be a list of paths", .{});
    }

    const identities_val = obj.get("identities").?;
    if (identities_val != .array) return fail("identities must be a list", .{});
    var seen_ids = std.StringHashMap(void).init(allocator);
    defer seen_ids.deinit();
    for (identities_val.array.items, 0..) |id_item, idx| {
        _ = try validateIdentity(allocator, id_item, idx);
        const id_str = id_item.object.get("id").?.string;
        if (seen_ids.contains(id_str)) {
            return fail("duplicate identity {s}", .{id_str});
        }
        try seen_ids.put(id_str, {});
    }

    if (obj.get("coordinate_consumers")) |cc_val| {
        if (cc_val != .array) return fail("coordinate_consumers must be a list", .{});
        for (cc_val.array.items, 0..) |cc_item, idx| {
            const cc_where = try std.fmt.allocPrint(allocator, "coordinate_consumers[{d}]", .{idx});
            const cc_obj = try exactKeys(cc_item, &.{ "path", "bindings" }, &.{}, cc_where);
            _ = try validateRelativePath(cc_obj.get("path").?, try std.fmt.allocPrint(allocator, "{s}.path", .{cc_where}));
            try validateCoordinateBindings(allocator, cc_obj.get("bindings").?, &SNAPSHOT_COORDINATES, cc_where);
        }
    }

    if (obj.get("prestate_evidence")) |pe_val| {
        _ = try validateRelativePath(pe_val, "prestate_evidence");
    }

    const excluded_val = obj.get("excluded").?;
    if (excluded_val != .array) return fail("excluded must be a list", .{});
    for (excluded_val.array.items, 0..) |ex_item, idx| {
        const ex_where = try std.fmt.allocPrint(allocator, "excluded[{d}]", .{idx});
        const ex_obj = try exactKeys(ex_item, &.{ "digest", "reason" }, &.{}, ex_where);
        _ = try parseTaggedValue(ex_obj.get("digest").?, &.{ "sha256", "sha512" });
        const reason = ex_obj.get("reason").?;
        if (reason != .string or reason.string.len < 16) {
            return fail("{s} needs a reason", .{ex_where});
        }
    }
    return manifest;
}

pub fn pinnedTimestamp(manifest: ?std.json.Value, series: []const u8) ?[]const u8 {
    const m = manifest orelse return null;
    if (!std.mem.eql(u8, m.object.get("series").?.object.get("name").?.string, series)) {
        return null;
    }
    return m.object.get("snapshot").?.object.get("timestamp").?.string;
}

pub fn frozenPocket(document: std.json.Value) ?std.json.Value {
    const pockets_val = document.object.get("pockets") orelse return null;
    if (pockets_val != .array) return null;
    for (pockets_val.array.items) |pocket| {
        if (std.mem.eql(u8, pocket.object.get("role").?.string, "frozen")) {
            return pocket;
        }
    }
    return null;
}

pub fn snapshotUri(allocator: std.mem.Allocator, profile: std.json.Value, timestamp: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ profile.object.get("uri_root").?.string, timestamp });
}

// InRelease, Release fields, Pocket dates, and Packages index.

pub fn inReleaseCleartext(allocator: std.mem.Allocator, data: []const u8) RepinError![]u8 {
    if (data.len == 0) {
        return fail("InRelease does not start with a cleartext signature header", .{});
    }
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(allocator);
    var pos: usize = 0;
    while (pos < data.len) {
        const nl = std.mem.indexOfScalarPos(u8, data, pos, '\n');
        const line = if (nl) |idx| data[pos .. idx + 1] else data[pos..];
        pos = if (nl) |idx| idx + 1 else data.len;
        try lines.append(allocator, line);
    }
    if (lines.items.len == 0 or
        !std.mem.eql(u8, std.mem.trimEnd(u8, lines.items[0], "\r\n"), "-----BEGIN PGP SIGNED MESSAGE-----"))
    {
        return fail("InRelease does not start with a cleartext signature header", .{});
    }
    var index: usize = 1;
    while (index < lines.items.len and std.mem.trimEnd(u8, lines.items[index], "\r\n").len != 0) {
        index += 1;
    }
    if (index >= lines.items.len) {
        return fail("InRelease has no blank line after its armor headers", .{});
    }
    index += 1;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    while (index < lines.items.len) : (index += 1) {
        const line = lines.items[index];
        var line_text = std.mem.trimEnd(u8, line, "\r\n");
        if (std.mem.eql(u8, line_text, "-----BEGIN PGP SIGNATURE-----")) {
            return out.toOwnedSlice(allocator);
        }
        if (!std.mem.endsWith(u8, line, "\n")) {
            return fail("InRelease cleartext is truncated", .{});
        }
        const ending = line[line_text.len..];
        if (std.mem.startsWith(u8, line_text, "- ")) {
            line_text = line_text[2..];
        } else if (std.mem.startsWith(u8, line_text, "-")) {
            return fail("InRelease cleartext has an invalid dash escape", .{});
        }
        try out.appendSlice(allocator, line_text);
        try out.appendSlice(allocator, ending);
    }
    return fail("InRelease has no signature block", .{});
}

pub const ReleaseFields = struct {
    suite: ?[]const u8,
    codename: ?[]const u8,
    date: []const u8,
    date_unix: i64,
    valid_until: ?[]const u8,
    valid_until_unix: ?i64,
    hash_fields: [][]const u8,
};

pub fn releaseFields(allocator: std.mem.Allocator, cleartext: []const u8) RepinError!ReleaseFields {
    var fields = ManagedStringArrayHashMap([]const u8).init(allocator);
    defer fields.deinit();
    var hash_fields: std.ArrayList([]const u8) = .empty;

    var current: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, cleartext, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) break;
        if (line[0] == ' ' or line[0] == '\t') {
            if (current == null) {
                return fail("Release continuation line without a field", .{});
            }
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse
            return fail("invalid Release line: '{s}'", .{line});
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (fields.contains(name)) {
            return fail("duplicate Release field {s}", .{name});
        }
        try fields.put(name, value);
        current = name;
        if (sliceContains(&.{ "MD5Sum", "SHA1", "SHA256", "SHA512" }, name)) {
            try hash_fields.append(allocator, try allocator.dupe(u8, name));
        }
    }

    const date_str = fields.get("Date") orelse return fail("Release has no Date", .{});
    const date_unix = try releaseTime(date_str, "Date");

    var valid_until: ?[]const u8 = null;
    var valid_until_unix: ?i64 = null;
    if (fields.get("Valid-Until")) |vu| {
        valid_until = vu;
        valid_until_unix = try releaseTime(vu, "Valid-Until");
    }

    return .{
        .suite = fields.get("Suite"),
        .codename = fields.get("Codename"),
        .date = date_str,
        .date_unix = date_unix,
        .valid_until = valid_until,
        .valid_until_unix = valid_until_unix,
        .hash_fields = try hash_fields.toOwnedSlice(allocator),
    };
}

pub fn pocketDeadline(pocket: std.json.Value) i64 {
    if (pocket.object.get("valid_until_unix")) |vu| {
        if (vu == .integer) return vu.integer;
    }
    return pocket.object.get("date_unix").?.integer + MAXIMUM_RELEASE_AGE_SECONDS;
}

pub fn checkPocketDates(allocator: std.mem.Allocator, pockets: []std.json.Value, snapshot_unix: i64) RepinError!i64 {
    for (pockets) |pocket| {
        const suite = pocket.object.get("suite").?.string;
        const role = pocket.object.get("role").?.string;
        const date_str = pocket.object.get("date").?.string;
        const date_unix = pocket.object.get("date_unix").?.integer;
        const valid_until = pocket.object.get("valid_until") orelse .null;

        if (date_unix > snapshot_unix) {
            return fail("{s} Date {s} is after the snapshot time", .{ suite, date_str });
        }
        if (std.mem.eql(u8, role, "witness") and snapshot_unix - date_unix > WITNESS_WINDOW_SECONDS) {
            return fail(
                "witness {s} Date {s} is more than 48 hours before the snapshot time; the snapshot service may be stale",
                .{ suite, date_str },
            );
        }
        if (std.mem.eql(u8, role, "frozen") and valid_until != .null) {
            return fail("frozen pocket {s} carries Valid-Until", .{suite});
        }
    }

    var witness_deadlines: [16]i64 = undefined;
    var witness_count: usize = 0;
    var has_frozen = false;
    for (pockets) |pocket| {
        const role = pocket.object.get("role").?.string;
        if (std.mem.eql(u8, role, "frozen")) has_frozen = true;
        if (std.mem.eql(u8, role, "witness")) {
            witness_deadlines[witness_count] = pocketDeadline(pocket);
            witness_count += 1;
        }
    }
    if (has_frozen) {
        if (witness_count == 0) {
            return fail("a frozen pocket requires at least one witness pocket", .{});
        }
        var min_w = witness_deadlines[0];
        for (witness_deadlines[1..witness_count]) |w| {
            if (w < min_w) min_w = w;
        }
        for (pockets) |*pocket| {
            if (std.mem.eql(u8, pocket.object.get("role").?.string, "frozen")) {
                try pocket.object.put(allocator, "deadline", .{ .integer = min_w });
            }
        }
    }
    for (pockets) |*pocket| {
        if (!std.mem.eql(u8, pocket.object.get("role").?.string, "frozen")) {
            try pocket.object.put(allocator, "deadline", .{ .integer = pocketDeadline(pocket.*) });
        }
    }

    var min_deadline = pockets[0].object.get("deadline").?.integer;
    for (pockets[1..]) |pocket| {
        const d = pocket.object.get("deadline").?.integer;
        if (d < min_deadline) min_deadline = d;
    }
    return min_deadline;
}

pub fn deb822Fields(allocator: std.mem.Allocator, data: []const u8) RepinError!ManagedStringArrayHashMap([]const u8) {
    var fields = ManagedStringArrayHashMap([]const u8).init(allocator);
    var current: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) break;
        if (line[0] == ' ' or line[0] == '\t') {
            if (current == null) return fail("malformed source control/metadata fields", .{});
            const prev = fields.get(current.?).?;
            try fields.put(current.?, try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ prev, std.mem.trim(u8, line, " \t") }));
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse
            return fail("malformed source control/metadata fields", .{});
        const raw_name = line[0..colon];
        if (raw_name.len == 0) return fail("malformed source control/metadata fields", .{});
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        const lower_name = try allocator.alloc(u8, raw_name.len);
        for (raw_name, 0..) |c, i| lower_name[i] = std.ascii.toLower(c);
        if (fields.contains(lower_name)) {
            return fail("duplicate source control/metadata field {s}", .{raw_name});
        }
        try fields.put(lower_name, try allocator.dupe(u8, value));
        current = lower_name;
    }
    return fields;
}

pub const IndexChecksum = struct {
    digest: []const u8,
    size: i64,
};

pub fn releaseIndexEntries(
    allocator: std.mem.Allocator,
    data: []const u8,
    algorithm: []const u8,
) RepinError!ManagedStringArrayHashMap(IndexChecksum) {
    const cleartext = try inReleaseCleartext(allocator, data);
    var fields = try deb822Fields(allocator, cleartext);
    defer fields.deinit();
    var entries = ManagedStringArrayHashMap(IndexChecksum).init(allocator);
    const block = fields.get(algorithm) orelse return entries;
    var lines = std.mem.splitScalar(u8, block, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        var tok = std.mem.tokenizeAny(u8, line, " \t");
        const digest = tok.next() orelse return fail("malformed source Release index checksum", .{});
        const size_text = tok.next() orelse return fail("malformed source Release index checksum", .{});
        const name = tok.next() orelse return fail("malformed source Release index checksum", .{});
        if (tok.next() != null) return fail("malformed source Release index checksum", .{});
        for (size_text) |c| {
            if (!std.ascii.isDigit(c)) return fail("malformed source Release index checksum", .{});
        }
        const size_val = std.fmt.parseInt(i64, size_text, 10) catch
            return fail("malformed source Release index checksum", .{});
        _ = try parseTaggedStr(try std.fmt.allocPrint(allocator, "{s}:{s}", .{ algorithm, digest }), &.{algorithm});
        _ = try validateRelativePathStr(name, "source Release index path");
        if (entries.contains(name)) {
            return fail("duplicate source Release index checksum", .{});
        }
        try entries.put(try allocator.dupe(u8, name), .{
            .digest = try allocator.dupe(u8, digest),
            .size = size_val,
        });
    }
    return entries;
}

const DecompressCacheEntry = struct {
    valid: bool = false,
    kind: u8 = 0,
    hash: [Sha256.digest_length]u8 = undefined,
    bytes: []u8 = &.{},
};
var decompress_cache: [32]DecompressCacheEntry = @splat(.{});
var decompress_cache_next: usize = 0;

pub fn decompressNamed(
    allocator: std.mem.Allocator,
    name: []const u8,
    data: []const u8,
) RepinError![]u8 {
    const kind: u8 = if (std.mem.endsWith(u8, name, ".gz"))
        1
    else if (std.mem.endsWith(u8, name, ".xz"))
        2
    else if (std.mem.endsWith(u8, name, ".zst"))
        3
    else
        0;
    if (kind == 0) {
        if (data.len > maximum_tar_bytes) {
            return fail("deb {s} is too large", .{name});
        }
        return allocator.dupe(u8, data);
    }
    var h: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &h, .{});
    for (decompress_cache) |ce| {
        if (ce.valid and ce.kind == kind and std.mem.eql(u8, &ce.hash, &h)) {
            return allocator.dupe(u8, ce.bytes);
        }
    }
    const opts: debz.metadata_decompression.Options = .{
        .maximum_compressed_bytes = maximum_tar_bytes,
        .maximum_decompressed_bytes = maximum_tar_bytes,
    };
    const out = (switch (kind) {
        1 => debz.metadata_decompression.decompress(allocator, .gzip, data, opts),
        2 => debz.metadata_decompression.decompress(allocator, .xz, data, opts),
        3 => debz.metadata_decompression.decompress(allocator, .zstd, data, opts),
        else => unreachable,
    }) catch |err| switch (err) {
        error.InputLimitExceeded, error.OutputLimitExceeded => return fail("deb {s} is too large", .{name}),
        else => return fail("cannot decompress {s}: {s}", .{ name, @errorName(err) }),
    };
    if (std.heap.page_allocator.dupe(u8, out)) |cached_copy| {
        const slot = decompress_cache_next % decompress_cache.len;
        decompress_cache_next +%= 1;
        if (decompress_cache[slot].valid) {
            std.heap.page_allocator.free(decompress_cache[slot].bytes);
        }
        decompress_cache[slot] = .{
            .valid = true,
            .kind = kind,
            .hash = h,
            .bytes = cached_copy,
        };
    } else |_| {}
    return out;
}

pub fn sourceArchiveDigest(allocator: std.mem.Allocator, entry: std.json.Value) RepinError![]u8 {
    const identity = entry.object.get("archive_identity") orelse
        return fail("source lock has no unique SHA-512 archive identity", .{});
    if (identity != .object) return fail("source lock has no unique SHA-512 archive identity", .{});
    const primary = identity.object.get("primary") orelse
        return fail("source lock has no unique SHA-512 archive identity", .{});
    const digests = identity.object.get("digests") orelse
        return fail("source lock has no unique SHA-512 archive identity", .{});
    if (primary != .string or !std.mem.eql(u8, primary.string, "sha512") or digests != .array) {
        return fail("source lock has no unique SHA-512 archive identity", .{});
    }
    var found: ?[]const u8 = null;
    for (digests.array.items) |d_item| {
        if (d_item != .object) continue;
        const alg = d_item.object.get("algorithm") orelse continue;
        const dig = d_item.object.get("digest") orelse continue;
        if (alg == .string and std.mem.eql(u8, alg.string, "sha512") and dig == .string) {
            if (found != null) return fail("source lock has no unique SHA-512 archive identity", .{});
            found = dig.string;
        }
    }
    const hex = found orelse return fail("source lock has no unique SHA-512 archive identity", .{});
    const value = try std.fmt.allocPrint(allocator, "sha512:{s}", .{hex});
    _ = try parseTaggedStr(value, &.{"sha512"});
    return value;
}

const CachedSourceIndex = struct {
    valid: bool = false,
    kind: u8 = 0,
    hash: [Sha256.digest_length]u8 = undefined,
    stanzas: []ManagedStringArrayHashMap([]const u8) = &.{},
};
var source_index_cache: [16]CachedSourceIndex = @splat(.{});
var source_index_cache_next: usize = 0;

pub fn sourceIndexPackage(
    allocator: std.mem.Allocator,
    index: []const u8,
    index_path: []const u8,
    entry: std.json.Value,
) RepinError!ManagedStringArrayHashMap([]const u8) {
    const kind: u8 = if (std.mem.endsWith(u8, index_path, ".xz"))
        2
    else if (std.mem.endsWith(u8, index_path, ".gz"))
        1
    else if (std.mem.endsWith(u8, index_path, ".zst"))
        3
    else
        0;
    if (kind == 0 and index.len > maximum_tar_bytes) {
        return fail("source Packages index is too large", .{});
    }
    var h: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(index, &h, .{});

    var cached_stanzas: ?[]ManagedStringArrayHashMap([]const u8) = null;
    for (source_index_cache) |ce| {
        if (ce.valid and ce.kind == kind and std.mem.eql(u8, &ce.hash, &h)) {
            cached_stanzas = ce.stanzas;
            break;
        }
    }

    const stanzas = if (cached_stanzas) |cs| cs else blk: {
        const data = switch (kind) {
            2 => try decompressNamed(allocator, "source.tar.xz", index),
            1 => try decompressNamed(allocator, "source.tar.gz", index),
            3 => try decompressNamed(allocator, "source.tar.zst", index),
            else => index,
        };
        var normalized: std.ArrayList(u8) = .empty;
        defer normalized.deinit(allocator);
        var i: usize = 0;
        while (i < data.len) : (i += 1) {
            if (data[i] == '\r' and i + 1 < data.len and data[i + 1] == '\n') continue;
            try normalized.append(allocator, data[i]);
        }
        const text = normalized.items;
        var parsed_list: std.ArrayList(ManagedStringArrayHashMap([]const u8)) = .empty;
        var pos: usize = 0;
        while (pos < text.len) {
            const sep = std.mem.indexOf(u8, text[pos..], "\n\n");
            const paragraph = if (sep) |s| text[pos .. pos + s] else text[pos..];
            pos = if (sep) |s| pos + s + 2 else text.len;
            const trimmed = std.mem.trim(u8, paragraph, " \t\r\n");
            if (trimmed.len == 0) continue;
            const fields = try deb822Fields(std.heap.page_allocator, trimmed);
            try parsed_list.append(std.heap.page_allocator, fields);
        }
        const owned = try parsed_list.toOwnedSlice(std.heap.page_allocator);
        const slot = source_index_cache_next % source_index_cache.len;
        source_index_cache_next +%= 1;
        source_index_cache[slot] = .{
            .valid = true,
            .kind = kind,
            .hash = h,
            .stanzas = owned,
        };
        break :blk owned;
    };

    const want_name = entry.object.get("name").?.string;
    const want_ver = entry.object.get("version").?.string;
    const want_arch = entry.object.get("architecture").?.string;
    const want_size = entry.object.get("declared_size").?.integer;

    var match_fields: ?ManagedStringArrayHashMap([]const u8) = null;
    var match_count: usize = 0;
    for (stanzas) |fields| {
        const pkg = fields.get("package") orelse "";
        const ver = fields.get("version") orelse "";
        const arch = fields.get("architecture") orelse "";
        if (std.mem.eql(u8, pkg, want_name) and std.mem.eql(u8, ver, want_ver) and std.mem.eql(u8, arch, want_arch)) {
            match_fields = fields;
            match_count += 1;
        }
    }
    if (match_count != 1) {
        return fail("source Packages index must name {s} exactly once", .{want_name});
    }
    var fields = ManagedStringArrayHashMap([]const u8).init(allocator);
    for (match_fields.?.keys(), match_fields.?.values()) |k, v| {
        try fields.put(try allocator.dupe(u8, k), try allocator.dupe(u8, v));
    }
    const archive_dig = try sourceArchiveDigest(allocator, entry);
    const want_sha512 = archive_dig["sha512:".len..];
    const got_sha512 = fields.get("sha512") orelse "";
    const got_size = fields.get("size") orelse "";
    const want_size_str = try std.fmt.allocPrint(allocator, "{d}", .{want_size});
    if (!std.mem.eql(u8, got_sha512, want_sha512) or !std.mem.eql(u8, got_size, want_size_str)) {
        return fail("source Packages index for {s} differs from its authenticated archive lock", .{want_name});
    }
    const filename = fields.get("filename") orelse return fail("source package Filename must be repository-relative", .{});
    _ = try validateRelativePathStr(filename, "source package Filename");
    return fields;
}

// .deb (ar + tar) reading and prestate derivation.

pub fn arMembers(allocator: std.mem.Allocator, data: []const u8) RepinError!ManagedStringArrayHashMap([]const u8) {
    if (!std.mem.startsWith(u8, data, "!<arch>\n")) {
        return fail("file is not an ar archive", .{});
    }
    var offset: usize = 8;
    var members = ManagedStringArrayHashMap([]const u8).init(allocator);
    while (offset < data.len) {
        if (offset + 60 > data.len) {
            return fail("truncated ar header", .{});
        }
        const header = data[offset .. offset + 60];
        if (!std.mem.eql(u8, header[58..60], "`\n")) {
            return fail("invalid ar member header magic", .{});
        }
        var name = std.mem.trimEnd(u8, header[0..16], " ");
        if (std.mem.endsWith(u8, name, "/")) {
            name = name[0 .. name.len - 1];
        }
        const size_str = std.mem.trim(u8, header[48..58], " ");
        const size = std.fmt.parseInt(usize, size_str, 10) catch
            return fail("invalid ar member size", .{});
        offset += 60;
        if (offset + size > data.len or members.contains(name)) {
            return fail("truncated or duplicate ar member {s}", .{name});
        }
        try members.put(try allocator.dupe(u8, name), data[offset .. offset + size]);
        offset += size + (size % 2);
    }
    const deb_bin = members.get("debian-binary") orelse
        return fail("archive is not a Debian 2.0 package", .{});
    if (!std.mem.eql(u8, deb_bin, "2.0\n")) {
        return fail("archive is not a Debian 2.0 package", .{});
    }
    return members;
}

pub fn normalizeTarPath(allocator: std.mem.Allocator, name: []const u8) RepinError![]u8 {
    var trimmed = name;
    while (std.mem.startsWith(u8, trimmed, "./")) {
        trimmed = trimmed[2..];
    }
    trimmed = std.mem.trimStart(u8, trimmed, "/");
    trimmed = std.mem.trimEnd(u8, trimmed, "/");
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(allocator);
    var it = std.mem.splitScalar(u8, trimmed, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            return fail("unsafe tar member path {s}", .{name});
        }
        try parts.append(allocator, part);
    }
    if (parts.items.len == 0) {
        return allocator.dupe(u8, "");
    }
    return std.mem.join(allocator, "/", parts.items);
}

pub fn openDebTar(allocator: std.mem.Allocator, data: []const u8, prefix: []const u8) RepinError![]u8 {
    var members = try arMembers(allocator, data);
    defer members.deinit();
    var matching_name: ?[]const u8 = null;
    for (members.keys()) |k| {
        if (std.mem.startsWith(u8, k, prefix)) {
            if (matching_name != null) {
                return fail("deb is missing unique {s}* member", .{prefix});
            }
            matching_name = k;
        }
    }
    const name = matching_name orelse return fail("deb is missing unique {s}* member", .{prefix});
    const raw_member = members.get(name).?;
    if (std.mem.eql(u8, name, prefix) or
        std.mem.eql(u8, name, try std.fmt.allocPrint(allocator, "{s}.gz", .{prefix})) or
        std.mem.eql(u8, name, try std.fmt.allocPrint(allocator, "{s}.xz", .{prefix})) or
        std.mem.eql(u8, name, try std.fmt.allocPrint(allocator, "{s}.zst", .{prefix})))
    {
        return decompressNamed(allocator, name, raw_member);
    }
    return fail("unsupported deb tar compression {s}", .{name});
}

const TarEntry = struct {
    raw_name: []const u8,
    typeflag: u8,
    mode: u32,
    size: usize,
    linkname: []const u8,
    bytes: []const u8,
};

fn parseTarOctalOrBase256(field: []const u8) RepinError!usize {
    if (field.len > 0 and (field[0] & 0x80) != 0) {
        var acc: usize = 0;
        for (field[1..]) |b| {
            acc = (acc << 8) | @as(usize, b);
        }
        return acc;
    }
    const trimmed = std.mem.trim(u8, field, " \x00");
    if (trimmed.len == 0) return 0;
    return std.fmt.parseInt(usize, trimmed, 8) catch return fail("invalid tar octal field", .{});
}

fn cStrSlice(field: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, field, 0)) |nul| return field[0..nul];
    return field;
}

fn parseTarEntries(allocator: std.mem.Allocator, tar_bytes: []const u8) RepinError![]TarEntry {
    var entries: std.ArrayList(TarEntry) = .empty;
    errdefer entries.deinit(allocator);

    var offset: usize = 0;
    var count: usize = 0;
    var pax_path: ?[]const u8 = null;
    var pax_linkpath: ?[]const u8 = null;
    var pax_size: ?usize = null;
    var gnu_longname: ?[]const u8 = null;
    var gnu_longlink: ?[]const u8 = null;

    while (offset + 512 <= tar_bytes.len) {
        const block = tar_bytes[offset .. offset + 512];
        var all_zero = true;
        for (block) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            offset += 512;
            continue;
        }
        const name_part = cStrSlice(block[0..100]);
        const mode_val: u32 = @intCast(try parseTarOctalOrBase256(block[100..108]));
        const size_hdr = try parseTarOctalOrBase256(block[124..136]);
        const typeflag = if (block[156] == 0) @as(u8, '0') else block[156];
        const link_part = cStrSlice(block[157..257]);
        const magic = block[257..262];
        const prefix_part = if (std.mem.eql(u8, magic, "ustar")) cStrSlice(block[345..500]) else "";

        const size = pax_size orelse size_hdr;
        offset += 512;
        if (offset + size > tar_bytes.len) {
            return fail("truncated tar member", .{});
        }
        const payload = tar_bytes[offset .. offset + size];
        const padded = ((size + 511) / 512) * 512;
        offset += @min(padded, tar_bytes.len - offset);

        if (typeflag == 'x' or typeflag == 'g') {
            var p_pos: usize = 0;
            while (p_pos < payload.len) {
                const sp = std.mem.indexOfScalarPos(u8, payload, p_pos, ' ') orelse break;
                const rec_len = std.fmt.parseInt(usize, payload[p_pos..sp], 10) catch break;
                if (rec_len == 0 or p_pos + rec_len > payload.len) break;
                const rec = std.mem.trimEnd(u8, payload[sp + 1 .. p_pos + rec_len], "\n");
                if (std.mem.indexOfScalar(u8, rec, '=')) |eq| {
                    const k = rec[0..eq];
                    const v = rec[eq + 1 ..];
                    if (std.mem.eql(u8, k, "path")) pax_path = try allocator.dupe(u8, v);
                    if (std.mem.eql(u8, k, "linkpath")) pax_linkpath = try allocator.dupe(u8, v);
                    if (std.mem.eql(u8, k, "size")) pax_size = std.fmt.parseInt(usize, v, 10) catch null;
                }
                p_pos += rec_len;
            }
            continue;
        }
        if (typeflag == 'L') {
            gnu_longname = try allocator.dupe(u8, cStrSlice(payload));
            continue;
        }
        if (typeflag == 'K') {
            gnu_longlink = try allocator.dupe(u8, cStrSlice(payload));
            continue;
        }

        count += 1;
        if (count > maximum_tar_members) {
            return fail("tar archive exceeds entry bound", .{});
        }

        const raw_name = if (pax_path) |p|
            p
        else if (gnu_longname) |l|
            l
        else if (prefix_part.len > 0)
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix_part, name_part })
        else
            try allocator.dupe(u8, name_part);

        const linkname = if (pax_linkpath) |p|
            p
        else if (gnu_longlink) |l|
            l
        else
            try allocator.dupe(u8, link_part);

        pax_path = null;
        pax_linkpath = null;
        pax_size = null;
        gnu_longname = null;
        gnu_longlink = null;

        try entries.append(allocator, .{
            .raw_name = raw_name,
            .typeflag = typeflag,
            .mode = mode_val,
            .size = size,
            .linkname = linkname,
            .bytes = payload,
        });
    }
    return entries.toOwnedSlice(allocator);
}

pub const TarMemberResult = struct {
    bytes: []u8,
    mode: u32,
};

pub fn tarMember(
    allocator: std.mem.Allocator,
    data: []const u8,
    prefix: []const u8,
    member_path: []const u8,
) RepinError!TarMemberResult {
    const target_norm = try normalizeTarPath(allocator, member_path);
    const tar_bytes = try openDebTar(allocator, data, prefix);
    const entries = try parseTarEntries(allocator, tar_bytes);

    var found: ?TarEntry = null;
    for (entries) |entry| {
        const norm = try normalizeTarPath(allocator, entry.raw_name);
        if (std.mem.eql(u8, norm, target_norm)) {
            found = entry;
            break;
        }
    }
    var member = found orelse return fail("{s} has no member {s}", .{ prefix, member_path });
    const mode = member.mode & 0o7777;
    if (member.typeflag == '1') {
        if (std.mem.startsWith(u8, member.linkname, "/")) {
            return fail("tar member {s} has an unsafe hardlink target", .{member_path});
        }
        const link_norm = normalizeTarPath(allocator, member.linkname) catch {
            return fail("tar member {s} has an unsafe hardlink target", .{member_path});
        };
        if (link_norm.len == 0) {
            return fail("tar member {s} has an unsafe hardlink target", .{member_path});
        }
        var target_entry: ?TarEntry = null;
        for (entries) |entry| {
            const norm = try normalizeTarPath(allocator, entry.raw_name);
            if (std.mem.eql(u8, norm, link_norm)) {
                target_entry = entry;
                break;
            }
        }
        member = target_entry orelse return fail("cannot read tar member {s}", .{member_path});
    }
    if (member.typeflag != '0') {
        return fail("cannot read tar member {s}", .{member_path});
    }
    if (member.size > maximum_member_bytes or member.bytes.len > maximum_member_bytes) {
        return fail("tar member {s} is too large", .{member_path});
    }
    if (member.bytes.len != member.size) {
        return fail("truncated tar member {s}", .{member_path});
    }
    return .{
        .bytes = try allocator.dupe(u8, member.bytes),
        .mode = mode,
    };
}

pub fn tarMemberDpkgListPath(allocator: std.mem.Allocator, name: []const u8) RepinError![]u8 {
    if (std.mem.eql(u8, name, "") or std.mem.eql(u8, name, ".")) {
        return allocator.dupe(u8, "/.");
    }
    const stripped = if (std.mem.startsWith(u8, name, "./")) name[2..] else name;
    const trimmed = std.mem.trimEnd(u8, stripped, "/");
    if (trimmed.len == 0 or std.mem.eql(u8, trimmed, ".")) {
        return allocator.dupe(u8, "/.");
    }
    if (!std.mem.startsWith(u8, name, "./")) {
        return fail("data.tar member path {s} is not ./-prefixed", .{name});
    }
    _ = try validateRelativePathStr(trimmed, "data.tar member path");
    return std.fmt.allocPrint(allocator, "/{s}", .{trimmed});
}

const DpkgListCacheEntry = struct {
    valid: bool = false,
    hash: [Sha256.digest_length]u8 = undefined,
    bytes: []u8 = &.{},
};
var dpkg_list_cache: [32]DpkgListCacheEntry = @splat(.{});
var dpkg_list_cache_next: usize = 0;

pub fn dpkgOwnershipList(allocator: std.mem.Allocator, data: []const u8) RepinError![]u8 {
    var h: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &h, .{});
    for (dpkg_list_cache) |ce| {
        if (ce.valid and std.mem.eql(u8, &ce.hash, &h)) {
            return allocator.dupe(u8, ce.bytes);
        }
    }
    const tar_bytes = try openDebTar(allocator, data, "data.tar");
    const entries = try parseTarEntries(allocator, tar_bytes);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (entries) |entry| {
        const line = try tarMemberDpkgListPath(allocator, entry.raw_name);
        try out.print(allocator, "{s}\n", .{line});
    }
    const res = try out.toOwnedSlice(allocator);
    if (std.heap.page_allocator.dupe(u8, res)) |cached_copy| {
        const slot = dpkg_list_cache_next % dpkg_list_cache.len;
        dpkg_list_cache_next +%= 1;
        if (dpkg_list_cache[slot].valid) {
            std.heap.page_allocator.free(dpkg_list_cache[slot].bytes);
        }
        dpkg_list_cache[slot] = .{
            .valid = true,
            .hash = h,
            .bytes = cached_copy,
        };
    } else |_| {}
    return res;
}

pub fn prestateDerivation(allocator: std.mem.Allocator, identity: std.json.Value, arch: []const u8) !?[]const u8 {
    if (!std.mem.eql(u8, identity.object.get("kind").?.string, "prestate")) return null;
    const derived = identity.object.get("derived_from") orelse return null;
    if (derived != .array or derived.array.items.len != 1) return null;
    const pkg = identity.object.get("package").?.string;
    if (!std.mem.eql(u8, derived.array.items[0].object.get("package").?.string, pkg)) return null;

    const path_val = identity.object.get("path").?;
    if (path_val != .string) return null;
    const p = path_val.string;

    const plain_list = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}.list", .{pkg});
    const arch_list = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}:{s}.list", .{ pkg, arch });
    if (std.mem.eql(u8, p, plain_list) or std.mem.eql(u8, p, arch_list)) {
        return "list";
    }
    for ([_][]const u8{ "triggers", "shlibs", "conffiles", "templates" }) |member| {
        const plain_m = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}.{s}", .{ pkg, member });
        const arch_m = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}:{s}.{s}", .{ pkg, arch, member });
        if (std.mem.eql(u8, p, plain_m) or std.mem.eql(u8, p, arch_m)) {
            return member;
        }
    }
    return null;
}

pub fn derivePrestate(
    allocator: std.mem.Allocator,
    identity: std.json.Value,
    arch: []const u8,
    deb_bytes: []const u8,
) RepinError!?TarMemberResult {
    const derivation = try prestateDerivation(allocator, identity, arch) orelse return null;
    if (std.mem.eql(u8, derivation, "list")) {
        return .{
            .bytes = try dpkgOwnershipList(allocator, deb_bytes),
            .mode = 0o644,
        };
    }
    return try tarMember(allocator, deb_bytes, "control.tar", derivation);
}

// Source evidence ZIP, bind-architecture, and bind-member.

pub fn sourceEvidenceIdentities(allocator: std.mem.Allocator, manifest: std.json.Value) ![]std.json.Value {
    var list: std.ArrayList(std.json.Value) = .empty;
    errdefer list.deinit(allocator);
    const all_ids = manifest.object.get("identities").?.array.items;

    for (all_ids) |identity| {
        var include = false;
        for (identity.object.get("architectures").?.array.items) |arch| {
            if ((try prestateDerivation(allocator, identity, arch.string)) != null) {
                include = true;
                break;
            }
        }
        if (!include) {
            for (identity.object.get("consumers").?.array.items) |consumer| {
                if (std.mem.eql(u8, consumer.object.get("form").?.string, "shell")) {
                    if (consumer.object.get("bindings").?.object.contains("url")) {
                        include = true;
                        break;
                    }
                }
            }
        }
        if (include) try list.append(allocator, identity);
    }

    for (all_ids) |identity| {
        if (std.mem.eql(u8, identity.object.get("kind").?.string, "script") and
            identity.object.get("architectures").?.array.items.len > 1)
        {
            var already = false;
            for (list.items) |existing| {
                if (std.mem.eql(u8, existing.object.get("id").?.string, identity.object.get("id").?.string)) {
                    already = true;
                    break;
                }
            }
            if (!already) try list.append(allocator, identity);
        }
    }

    var retained_pairs = std.StringHashMap(void).init(allocator);
    defer retained_pairs.deinit();
    var retained_ids = std.StringHashMap(void).init(allocator);
    defer retained_ids.deinit();

    for (list.items) |identity| {
        try retained_ids.put(identity.object.get("id").?.string, {});
        const pkg = identity.object.get("package").?.string;
        for (identity.object.get("architectures").?.array.items) |arch| {
            try retained_pairs.put(try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ pkg, arch.string }), {});
        }
    }

    for (all_ids) |identity| {
        if (!std.mem.eql(u8, identity.object.get("kind").?.string, "tool_file")) continue;
        if (retained_ids.contains(identity.object.get("id").?.string)) continue;
        const pkg = identity.object.get("package").?.string;
        var all_retained = true;
        for (identity.object.get("architectures").?.array.items) |arch| {
            const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ pkg, arch.string });
            if (!retained_pairs.contains(key)) {
                all_retained = false;
                break;
            }
        }
        if (all_retained) try list.append(allocator, identity);
    }

    return list.toOwnedSlice(allocator);
}

pub fn archivePackageFields(allocator: std.mem.Allocator, data: []const u8) RepinError!ManagedStringArrayHashMap([]const u8) {
    const control = try tarMember(allocator, data, "control.tar", "control");
    const fields = try deb822Fields(allocator, control.bytes);
    var values = ManagedStringArrayHashMap([]const u8).init(allocator);
    for ([_][]const u8{ "Package", "Version", "Architecture" }) |field| {
        var lower_buf: [16]u8 = undefined;
        for (field, 0..) |c, idx| lower_buf[idx] = std.ascii.toLower(c);
        const lower = lower_buf[0..field.len];
        const v = fields.get(lower) orelse
            return fail("source archive has an invalid {s} control field", .{field});
        if (v.len == 0) return fail("source archive has an invalid {s} control field", .{field});
        try values.put(try allocator.dupe(u8, lower), v);
    }
    return values;
}

pub fn authenticatedSourcePackage(
    allocator: std.mem.Allocator,
    report: std.json.Value,
    lock: std.json.Value,
    package: []const u8,
    arch: []const u8,
) RepinError!std.json.Value {
    if (lock != .object) return fail("source lock must be an object", .{});
    const pkgs_val = lock.object.get("packages") orelse return fail("source lock must name {s} exactly once for {s}", .{ package, arch });
    if (pkgs_val != .array) return fail("source lock must name {s} exactly once for {s}", .{ package, arch });

    var found_entry: ?std.json.Value = null;
    for (pkgs_val.array.items) |p_item| {
        if (p_item != .object) continue;
        const n = p_item.object.get("name") orelse continue;
        if (n == .string and std.mem.eql(u8, n.string, package)) {
            if (found_entry != null) {
                return fail("source lock must name {s} exactly once for {s}", .{ package, arch });
            }
            found_entry = p_item;
        }
    }
    const entry = found_entry orelse return fail("source lock must name {s} exactly once for {s}", .{ package, arch });
    const entry_arch = entry.object.get("architecture") orelse return fail("source lock has an unauthenticated or wrong-architecture {s}", .{package});
    const origin = entry.object.get("origin") orelse return fail("source lock has an unauthenticated or wrong-architecture {s}", .{package});
    if (entry_arch != .string or (!std.mem.eql(u8, entry_arch.string, arch) and !std.mem.eql(u8, entry_arch.string, "all")) or
        origin != .object)
    {
        return fail("source lock has an unauthenticated or wrong-architecture {s}", .{package});
    }
    const origin_type = origin.object.get("type") orelse return fail("source lock has an unauthenticated or wrong-architecture {s}", .{package});
    if (origin_type != .string or !std.mem.eql(u8, origin_type.string, "authenticated_repository")) {
        return fail("source lock has an unauthenticated or wrong-architecture {s}", .{package});
    }
    const origin_id_val = origin.object.get("repository_id") orelse return fail("source lock has no unique authenticated repository for {s}", .{package});
    if (origin_id_val != .string) return fail("source lock has no unique authenticated repository for {s}", .{package});
    const origin_id = origin_id_val.string;

    const repos_val = lock.object.get("repositories") orelse return fail("source lock has no unique authenticated repository for {s}", .{package});
    if (repos_val != .array) return fail("source lock has no unique authenticated repository for {s}", .{package});
    var found_repo: ?std.json.Value = null;
    for (repos_val.array.items) |r_item| {
        if (r_item != .object) continue;
        const rid = r_item.object.get("id") orelse continue;
        if (rid == .string and std.mem.eql(u8, rid.string, origin_id)) {
            if (found_repo != null) return fail("source lock has no unique authenticated repository for {s}", .{package});
            found_repo = r_item;
        }
    }
    const repository = found_repo orelse return fail("source lock has no unique authenticated repository for {s}", .{package});

    const repo_ids_arch = report.object.get("repository_ids").?.object.get(arch) orelse
        return fail("source lock repository for {s} was not refreshed", .{package});
    var suite: ?[]const u8 = null;
    var r_it = repo_ids_arch.object.iterator();
    while (r_it.next()) |kv| {
        if (kv.value_ptr.* == .string and std.mem.eql(u8, kv.value_ptr.*.string, origin_id)) {
            suite = kv.key_ptr.*;
            break;
        }
    }
    const matched_suite = suite orelse return fail("source lock repository for {s} was not refreshed", .{package});

    var found_pocket: ?std.json.Value = null;
    for (report.object.get("pockets").?.array.items) |p_item| {
        if (std.mem.eql(u8, p_item.object.get("suite").?.string, matched_suite)) {
            if (found_pocket != null) return fail("source lock repository for {s} was not refreshed", .{package});
            found_pocket = p_item;
        }
    }
    const pocket = found_pocket orelse return fail("source lock repository for {s} was not refreshed", .{package});

    const signers = repository.object.get("signer_fingerprints") orelse
        return fail("source lock repository for {s} differs from the authenticated probe Release", .{package});
    const want_signer = report.object.get("series").?.object.get("signer").?.string;
    if (signers != .array or signers.array.items.len != 1 or signers.array.items[0] != .string or
        !std.mem.eql(u8, signers.array.items[0].string, want_signer))
    {
        return fail("source lock repository for {s} differs from the authenticated probe Release", .{package});
    }
    const repo_rel_val = repository.object.get("release_sha256") orelse
        return fail("source lock repository for {s} differs from the authenticated probe Release", .{package});
    if (repo_rel_val != .string) return fail("source lock repository for {s} differs from the authenticated probe Release", .{package});
    const repo_rel = try lockDigest(allocator, repo_rel_val.string, "sha256");
    if (!std.mem.eql(u8, repo_rel, pocket.object.get("release_sha256").?.string)) {
        return fail("source lock repository for {s} differs from the authenticated probe Release", .{package});
    }

    const origin_snap = origin.object.get("repository_snapshot_sha256") orelse
        return fail("source lock snapshot for {s} differs from its repository", .{package});
    const repo_snap = repository.object.get("snapshot_sha256") orelse
        return fail("source lock snapshot for {s} differs from its repository", .{package});
    if (origin_snap != .string or repo_snap != .string) {
        return fail("source lock snapshot for {s} differs from its repository", .{package});
    }
    _ = try lockDigest(allocator, origin_snap.string, "sha256");
    _ = try lockDigest(allocator, repo_snap.string, "sha256");
    if (!std.mem.eql(u8, origin_snap.string, repo_snap.string)) {
        return fail("source lock snapshot for {s} differs from its repository", .{package});
    }
    return entry;
}

pub fn verifySourceArchive(allocator: std.mem.Allocator, data: []const u8, entry: std.json.Value) RepinError!void {
    const pkg_name = entry.object.get("name").?.string;
    const declared_size = entry.object.get("declared_size").?.integer;
    const got_sha512 = try tagged(allocator, "sha512", data);
    const want_sha512 = try sourceArchiveDigest(allocator, entry);
    if (@as(i64, @intCast(data.len)) != declared_size or !std.mem.eql(u8, got_sha512, want_sha512)) {
        return fail("source archive for {s} disagrees with its authenticated lock digest or size", .{pkg_name});
    }
    const control = try archivePackageFields(allocator, data);
    if (!std.mem.eql(u8, control.get("package").?, pkg_name) or
        !std.mem.eql(u8, control.get("version").?, entry.object.get("version").?.string) or
        !std.mem.eql(u8, control.get("architecture").?, entry.object.get("architecture").?.string))
    {
        return fail("source archive control coordinates for {s} disagree with its authenticated lock", .{pkg_name});
    }
}

pub fn verifySourceMetadata(
    allocator: std.mem.Allocator,
    report: std.json.Value,
    lock: std.json.Value,
    source: std.json.Value,
    entry: std.json.Value,
    release: []const u8,
    index: []const u8,
) RepinError!ManagedStringArrayHashMap([]const u8) {
    const comp = report.object.get("series").?.object.get("component").?.string;
    const arch = source.object.get("architecture").?.string;
    const index_path = source.object.get("index_path").?.string;
    const stem = try std.fmt.allocPrint(allocator, "{s}/binary-{s}/Packages", .{ comp, arch });
    if (!std.mem.eql(u8, index_path, stem) and
        !std.mem.eql(u8, index_path, try std.fmt.allocPrint(allocator, "{s}.xz", .{stem})) and
        !std.mem.eql(u8, index_path, try std.fmt.allocPrint(allocator, "{s}.gz", .{stem})) and
        !std.mem.eql(u8, index_path, try std.fmt.allocPrint(allocator, "{s}.zst", .{stem})))
    {
        return fail("retained source Packages path has the wrong component or architecture", .{});
    }
    const repository_id = entry.object.get("origin").?.object.get("repository_id").?.string;
    var repository: ?std.json.Value = null;
    for (lock.object.get("repositories").?.array.items) |r| {
        if (std.mem.eql(u8, r.object.get("id").?.string, repository_id)) {
            repository = r;
            break;
        }
    }
    var suite: ?[]const u8 = null;
    var r_it = report.object.get("repository_ids").?.object.get(arch).?.object.iterator();
    while (r_it.next()) |kv| {
        if (std.mem.eql(u8, kv.value_ptr.*.string, repository_id)) {
            suite = kv.key_ptr.*;
            break;
        }
    }
    var pocket: ?std.json.Value = null;
    for (report.object.get("pockets").?.array.items) |p| {
        if (std.mem.eql(u8, p.object.get("suite").?.string, suite.?)) {
            pocket = p;
            break;
        }
    }
    const p_obj = pocket.?.object;
    const pkg_name = entry.object.get("name").?.string;
    const rel_sha256 = try tagged(allocator, "sha256", release);
    const rel_sha512 = try tagged(allocator, "sha512", release);
    const clear = try inReleaseCleartext(allocator, release);
    const clear_sha256 = try tagged(allocator, "sha256", clear);
    if (!std.mem.eql(u8, rel_sha256, p_obj.get("in_release_sha256").?.string) or
        !std.mem.eql(u8, rel_sha512, p_obj.get("in_release_sha512").?.string) or
        !std.mem.eql(u8, clear_sha256, p_obj.get("release_sha256").?.string))
    {
        return fail("retained source InRelease for {s} differs from the authenticated probe", .{pkg_name});
    }
    const index_identity = repository.?.object.get("index_identity").?.object;
    const algorithm = index_identity.get("primary").?.string;
    if (!std.mem.eql(u8, algorithm, "sha256") and !std.mem.eql(u8, algorithm, "sha512")) {
        return fail("retained source index needs a signed SHA-256 or SHA-512 identity", .{});
    }
    var found_dig: ?[]const u8 = null;
    var dig_count: usize = 0;
    for (index_identity.get("digests").?.array.items) |d| {
        if (std.mem.eql(u8, d.object.get("algorithm").?.string, algorithm)) {
            found_dig = d.object.get("digest").?.string;
            dig_count += 1;
        }
    }
    const checksums = try releaseIndexEntries(allocator, release, algorithm);
    const checksum = checksums.get(index_path) orelse
        return fail("retained source Packages index for {s} differs from its signed Release/lock", .{pkg_name});
    const actual_hex: []const u8 = if (std.mem.eql(u8, algorithm, "sha256"))
        &(try allocator.dupe(u8, &sha256HexLower(index)))[0..SHA256_HEX].*
    else
        &(try allocator.dupe(u8, &sha512HexLower(index)))[0..SHA512_HEX].*;
    if (dig_count != 1 or !std.mem.eql(u8, checksum.digest, found_dig.?) or
        checksum.size != @as(i64, @intCast(index.len)) or !std.mem.eql(u8, actual_hex, found_dig.?))
    {
        return fail("retained source Packages index for {s} differs from its signed Release/lock", .{pkg_name});
    }
    return sourceIndexPackage(allocator, index, index_path, entry);
}

fn isPathWithinRoot(allocator: std.mem.Allocator, path: []const u8, root: []const u8) bool {
    const real_root = cwdRealpathAlloc(allocator, root) catch return false;
    const real_path = cwdRealpathAlloc(allocator, path) catch return false;
    if (std.mem.eql(u8, real_path, real_root)) return true;
    if (!std.mem.startsWith(u8, real_path, real_root)) return false;
    return real_path.len > real_root.len and real_path[real_root.len] == '/';
}

fn isNotSymlink(path: []const u8) bool {
    const st = lstatOrStatFile(path, false) catch |err| switch (err) {
        error.FileNotFound => return true,
        else => return false,
    };
    return st.kind != .sym_link;
}

pub fn readSourceFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    root: []const u8,
    limit: usize,
    where: []const u8,
) RepinError![]u8 {
    if (!isNotSymlink(path) or !isPathWithinRoot(allocator, path, root)) {
        return fail("{s} is missing or unsafe", .{where});
    }
    const stat = lstatOrStatFile(path, false) catch {
        return fail("{s} is missing or unsafe", .{where});
    };
    if (stat.kind != .file) {
        return fail("{s} is missing or unsafe", .{where});
    }
    if (stat.size > limit) {
        return fail("{s} is too large", .{where});
    }
    const data = cwdReadFileAlloc(allocator, path, limit +| 1) catch |err| switch (err) {
        error.StreamTooLong => return fail("{s} is too large", .{where}),
        else => return fail("cannot read {s}: {s}", .{ where, @errorName(err) }),
    };
    if (data.len > limit) {
        return fail("{s} is too large", .{where});
    }
    return data;
}

pub fn sourceLockPaths(allocator: std.mem.Allocator, directory: []const u8) RepinError![][]const u8 {
    const locks_dir_path = try std.fs.path.join(allocator, &.{ directory, "locks" });
    if (!isNotSymlink(locks_dir_path) or !isPathWithinRoot(allocator, locks_dir_path, directory)) {
        return fail("probe source lock directory is unsafe", .{});
    }
    const stat = lstatOrStatFile(locks_dir_path, false) catch return fail("probe source lock directory is unsafe", .{});
    if (stat.kind != .directory) return fail("probe source lock directory is unsafe", .{});
    var dir = std.Io.Dir.cwd().openDir(global_io, locks_dir_path, .{ .iterate = true }) catch {
        return fail("probe source lock directory is unsafe", .{});
    };
    defer dir.close(global_io);

    var paths: std.ArrayList([]const u8) = .empty;
    var index: usize = 0;
    var it = dir.iterate();
    while (it.next(global_io) catch |err| return fail("cannot read probe source lock directory: {s}", .{@errorName(err)})) |entry| {
        if (index >= maximum_evidence_files) {
            return fail("probe source lock directory exceeds its entry bound", .{});
        }
        index += 1;
        if (std.mem.endsWith(u8, entry.name, ".lock.json")) {
            try paths.append(allocator, try std.fs.path.join(allocator, &.{ locks_dir_path, entry.name }));
        }
    }
    std.mem.sort([]const u8, paths.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    return paths.toOwnedSlice(allocator);
}

pub const ZipEntrySpec = struct {
    name: []const u8,
    data: []const u8,
    compress_type: u16 = 0,
    external_attr: u32 = 0o100644 << 16,
    flags: u16 = 0,
};

pub fn buildZipArchive(allocator: std.mem.Allocator, entries: []const ZipEntrySpec) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var w = arrayListWriter(&out, allocator);

    const Offsets = struct {
        local_offset: u32,
        crc: u32,
    };
    const meta = try allocator.alloc(Offsets, entries.len);
    defer allocator.free(meta);

    // DOS 1980-01-01 00:00:00 -> time = 0, date = (0 << 9) | (1 << 5) | 1 = 0x0021
    const dos_time: u16 = 0;
    const dos_date: u16 = 0x0021;

    for (entries, 0..) |entry, i| {
        const local_offset: u32 = @intCast(out.items.len);
        const crc = std.hash.Crc32.hash(entry.data);
        meta[i] = .{ .local_offset = local_offset, .crc = crc };
        const size32: u32 = @intCast(entry.data.len);
        const name_len: u16 = @intCast(entry.name.len);

        try w.writeInt(u32, 0x04034b50, .little);
        try w.writeInt(u16, 20, .little);
        try w.writeInt(u16, entry.flags, .little);
        try w.writeInt(u16, entry.compress_type, .little);
        try w.writeInt(u16, dos_time, .little);
        try w.writeInt(u16, dos_date, .little);
        try w.writeInt(u32, crc, .little);
        try w.writeInt(u32, size32, .little);
        try w.writeInt(u32, size32, .little);
        try w.writeInt(u16, name_len, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeAll(entry.name);
        try w.writeAll(entry.data);
    }

    const cd_offset: u32 = @intCast(out.items.len);
    for (entries, 0..) |entry, i| {
        const size32: u32 = @intCast(entry.data.len);
        const name_len: u16 = @intCast(entry.name.len);
        try w.writeInt(u32, 0x02014b50, .little);
        try w.writeInt(u16, (3 << 8) | 20, .little);
        try w.writeInt(u16, 20, .little);
        try w.writeInt(u16, entry.flags, .little);
        try w.writeInt(u16, entry.compress_type, .little);
        try w.writeInt(u16, dos_time, .little);
        try w.writeInt(u16, dos_date, .little);
        try w.writeInt(u32, meta[i].crc, .little);
        try w.writeInt(u32, size32, .little);
        try w.writeInt(u32, size32, .little);
        try w.writeInt(u16, name_len, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u32, entry.external_attr, .little);
        try w.writeInt(u32, meta[i].local_offset, .little);
        try w.writeAll(entry.name);
    }
    const cd_size: u32 = @intCast(out.items.len - cd_offset);
    const count16: u16 = @intCast(entries.len);
    try w.writeInt(u32, 0x06054b50, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, count16, .little);
    try w.writeInt(u16, count16, .little);
    try w.writeInt(u32, cd_size, .little);
    try w.writeInt(u32, cd_offset, .little);
    try w.writeInt(u16, 0, .little);

    return out.toOwnedSlice(allocator);
}

pub const ParsedZipEntry = struct {
    filename: []const u8,
    flags: u16,
    compress_type: u16,
    crc32: u32,
    compressed_size: usize,
    file_size: usize,
    external_attr: u32,
    compressed_data: []const u8,

    pub fn isDir(self: ParsedZipEntry) bool {
        return std.mem.endsWith(u8, self.filename, "/");
    }
};

pub fn parseZipEntries(allocator: std.mem.Allocator, data: []const u8) RepinError![]ParsedZipEntry {
    if (data.len < 22) return fail("BadZipFile: truncated ZIP archive", .{});
    const min_eocd_pos = if (data.len > 22 + 65535) data.len - 22 - 65535 else 0;
    var eocd_pos: ?usize = null;
    var pos: usize = data.len - 22;
    while (true) {
        if (std.mem.readInt(u32, data[pos..][0..4], .little) == 0x06054b50) {
            const comment_len = std.mem.readInt(u16, data[pos + 20 ..][0..2], .little);
            if (pos + 22 + comment_len == data.len) {
                eocd_pos = pos;
                break;
            }
        }
        if (pos == min_eocd_pos) break;
        pos -= 1;
    }
    const eocd = eocd_pos orelse return fail("BadZipFile: missing EOCD signature", .{});
    const total_entries = std.mem.readInt(u16, data[eocd + 10 ..][0..2], .little);
    const cd_size = std.mem.readInt(u32, data[eocd + 12 ..][0..4], .little);
    const cd_offset = std.mem.readInt(u32, data[eocd + 16 ..][0..4], .little);
    if (@as(usize, cd_offset) + @as(usize, cd_size) > eocd) {
        return fail("BadZipFile: invalid central directory bounds", .{});
    }

    var entries: std.ArrayList(ParsedZipEntry) = .empty;
    errdefer entries.deinit(allocator);
    var cd_pos: usize = cd_offset;
    for (0..total_entries) |_| {
        if (cd_pos + 46 > eocd) return fail("BadZipFile: truncated central directory entry", .{});
        if (std.mem.readInt(u32, data[cd_pos..][0..4], .little) != 0x02014b50) {
            return fail("BadZipFile: invalid central directory header", .{});
        }
        const flags = std.mem.readInt(u16, data[cd_pos + 8 ..][0..2], .little);
        const compress_type = std.mem.readInt(u16, data[cd_pos + 10 ..][0..2], .little);
        const crc32 = std.mem.readInt(u32, data[cd_pos + 16 ..][0..4], .little);
        const comp_size = std.mem.readInt(u32, data[cd_pos + 20 ..][0..4], .little);
        const uncomp_size = std.mem.readInt(u32, data[cd_pos + 24 ..][0..4], .little);
        const name_len = std.mem.readInt(u16, data[cd_pos + 28 ..][0..2], .little);
        const extra_len = std.mem.readInt(u16, data[cd_pos + 30 ..][0..2], .little);
        const comment_len = std.mem.readInt(u16, data[cd_pos + 32 ..][0..2], .little);
        const external_attr = std.mem.readInt(u32, data[cd_pos + 38 ..][0..4], .little);
        const local_offset = std.mem.readInt(u32, data[cd_pos + 42 ..][0..4], .little);

        const header_end = cd_pos + 46 + name_len + extra_len + comment_len;
        if (header_end > eocd) return fail("BadZipFile: truncated central directory variable fields", .{});
        const filename = data[cd_pos + 46 .. cd_pos + 46 + name_len];
        cd_pos = header_end;

        const loc: usize = local_offset;
        if (loc + 30 > cd_offset) return fail("BadZipFile: invalid local header offset", .{});
        if (std.mem.readInt(u32, data[loc..][0..4], .little) != 0x04034b50) {
            return fail("BadZipFile: invalid local file header signature", .{});
        }
        const loc_name_len = std.mem.readInt(u16, data[loc + 26 ..][0..2], .little);
        const loc_extra_len = std.mem.readInt(u16, data[loc + 28 ..][0..2], .little);
        const data_start = loc + 30 + loc_name_len + loc_extra_len;
        if (data_start + comp_size > cd_offset) {
            return fail("BadZipFile: truncated compressed data", .{});
        }
        try entries.append(allocator, .{
            .filename = filename,
            .flags = flags,
            .compress_type = compress_type,
            .crc32 = crc32,
            .compressed_size = comp_size,
            .file_size = uncomp_size,
            .external_attr = external_attr,
            .compressed_data = data[data_start .. data_start + comp_size],
        });
    }
    return entries.toOwnedSlice(allocator);
}

fn readZipMemberData(
    allocator: std.mem.Allocator,
    entries: []const ParsedZipEntry,
    name: []const u8,
    limit: usize,
) RepinError![]u8 {
    var found: ?ParsedZipEntry = null;
    for (entries) |e| {
        if (std.mem.eql(u8, e.filename, name)) {
            found = e;
            break;
        }
    }
    const entry = found orelse return fail("KeyError: missing ZIP member {s}", .{name});
    if (entry.file_size > limit) {
        return fail("source evidence member {s} is too large", .{name});
    }
    var out: []u8 = undefined;
    if (entry.compress_type == 0) {
        if (entry.compressed_data.len != entry.file_size) {
            return fail("source evidence member {s} is too large or truncated", .{name});
        }
        out = try allocator.dupe(u8, entry.compressed_data);
    } else if (entry.compress_type == 8) {
        var input = std.Io.Reader.fixed(entry.compressed_data);
        const history = try allocator.alloc(u8, std.compress.flate.max_window_len);
        defer allocator.free(history);
        var decoder: std.compress.flate.Decompress = .init(&input, .raw, history);
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);
        var scratch: [16 * 1024]u8 = undefined;
        while (true) {
            var writer = std.Io.Writer.fixed(&scratch);
            const produced = decoder.reader.stream(&writer, .limited(scratch.len)) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return fail("BadZipFile: corrupt deflate stream in {s}", .{name}),
            };
            if (list.items.len + produced > limit) {
                return fail("source evidence member {s} is too large", .{name});
            }
            try list.appendSlice(allocator, scratch[0..produced]);
        }
        out = try list.toOwnedSlice(allocator);
    } else {
        return fail("source evidence ZIP has an unsafe member {s}", .{name});
    }
    if (out.len > limit or out.len != entry.file_size) {
        return fail("source evidence member {s} is too large or truncated", .{name});
    }
    if (std.hash.Crc32.hash(out) != entry.crc32) {
        return fail("BadZipFile: CRC-32 mismatch for {s}", .{name});
    }
    return out;
}

pub fn exportPrestateEvidence(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    report: std.json.Value,
    directory: []const u8,
    root: []const u8,
) RepinError!void {
    var files = ManagedStringArrayHashMap([]const u8).init(allocator);
    defer files.deinit();

    const Helpers = struct {
        fn totalBytes(f: *const ManagedStringArrayHashMap([]const u8)) usize {
            var sum: usize = 0;
            for (f.values()) |v| sum += v.len;
            return sum;
        }
        fn remainingBytes(f: *const ManagedStringArrayHashMap([]const u8)) usize {
            const used = totalBytes(f);
            return if (maximum_evidence_bytes >= used) maximum_evidence_bytes - used else 0;
        }
        fn remember(
            alloc: std.mem.Allocator,
            f: *ManagedStringArrayHashMap([]const u8),
            name: []const u8,
            data: []const u8,
        ) RepinError!void {
            if (!f.contains(name)) {
                if (f.count() >= maximum_evidence_files or data.len > remainingBytes(f)) {
                    return fail("source evidence exceeds its file or byte bound", .{});
                }
                try f.put(try alloc.dupe(u8, name), data);
            }
        }
        fn retain(
            alloc: std.mem.Allocator,
            f: *ManagedStringArrayHashMap([]const u8),
            dir: []const u8,
            relative: []const u8,
            limit: usize,
        ) RepinError![]const u8 {
            _ = try validateRelativePathStr(relative, "probe source metadata path");
            if (f.get(relative)) |existing| return existing;
            const full = try std.fs.path.join(alloc, &.{ dir, relative });
            const where = try std.fmt.allocPrint(alloc, "probe source {s}", .{relative});
            const data = try readSourceFile(alloc, full, dir, @min(limit, remainingBytes(f)), where);
            try remember(alloc, f, relative, data);
            return data;
        }
    };

    _ = try Helpers.retain(allocator, &files, directory, "report.json", maximum_release_bytes);
    const lock_paths = try sourceLockPaths(allocator, directory);

    const ArchPkg = struct {
        arch: []const u8,
        pkg: []const u8,
    };
    var wanted_list: std.ArrayList(ArchPkg) = .empty;
    const ev_ids = try sourceEvidenceIdentities(allocator, manifest);
    for (ev_ids) |identity| {
        const pkg = identity.object.get("package").?.string;
        for (identity.object.get("architectures").?.array.items) |a| {
            var exists = false;
            for (wanted_list.items) |item| {
                if (std.mem.eql(u8, item.arch, a.string) and std.mem.eql(u8, item.pkg, pkg)) {
                    exists = true;
                    break;
                }
            }
            if (!exists) try wanted_list.append(allocator, .{ .arch = a.string, .pkg = pkg });
        }
    }
    std.mem.sort(ArchPkg, wanted_list.items, {}, struct {
        fn less(_: void, a: ArchPkg, b: ArchPkg) bool {
            const cmp = std.mem.order(u8, a.arch, b.arch);
            if (cmp != .eq) return cmp == .lt;
            return std.mem.lessThan(u8, a.pkg, b.pkg);
        }
    }.less);

    var sources_arr = std.json.Array.init(allocator);
    for (wanted_list.items) |wp| {
        const arch = wp.arch;
        const name = wp.pkg;
        var selected_path: ?[]const u8 = null;
        var selected_bytes: ?[]const u8 = null;
        var selected_entry: ?std.json.Value = null;

        for (lock_paths) |lp| {
            const base = std.fs.path.basename(lp);
            if (!std.mem.startsWith(u8, base, arch)) continue;
            const lock_name = try std.fmt.allocPrint(allocator, "locks/{s}", .{base});
            const lock_bytes = files.get(lock_name) orelse
                try readSourceFile(
                    allocator,
                    lp,
                    directory,
                    @min(maximum_release_bytes, Helpers.remainingBytes(&files)),
                    try std.fmt.allocPrint(allocator, "probe source lock {s}", .{base}),
                );
            const lock_doc = parseJsonObjectBytes(
                allocator,
                lock_bytes,
                try std.fmt.allocPrint(allocator, "probe source lock {s}", .{base}),
            ) catch |err| return err;
            const pkgs = lock_doc.object.get("packages") orelse continue;
            if (pkgs != .array) continue;
            var has_pkg = false;
            for (pkgs.array.items) |p_item| {
                if (p_item == .object) {
                    if (p_item.object.get("name")) |n| {
                        if (n == .string and std.mem.eql(u8, n.string, name)) {
                            has_pkg = true;
                            break;
                        }
                    }
                }
            }
            if (has_pkg) {
                selected_entry = try authenticatedSourcePackage(allocator, report, lock_doc, name, arch);
                selected_path = lp;
                selected_bytes = lock_bytes;
                break;
            }
        }
        if (selected_entry == null) {
            return fail("probe has no authenticated source lock for {s} on {s}", .{ name, arch });
        }
        const entry = selected_entry.?;
        const digest = try sourceArchiveDigest(allocator, entry);
        const dash_digest = try std.mem.replaceOwned(u8, allocator, digest, ":", "-");
        const archive_name = try std.fmt.allocPrint(allocator, "archives/{s}.deb", .{dash_digest});
        const cas_source = try std.fs.path.join(allocator, &.{ directory, arch, "cache/packages-v2/objects", dash_digest });
        const lock_base = std.fs.path.basename(selected_path.?);
        const lock_name = try std.fmt.allocPrint(allocator, "locks/{s}", .{lock_base});
        try Helpers.remember(allocator, &files, lock_name, selected_bytes.?);

        const archive_data = files.get(archive_name) orelse
            try readSourceFile(
                allocator,
                cas_source,
                directory,
                Helpers.remainingBytes(&files),
                try std.fmt.allocPrint(allocator, "probe source archive for {s} on {s}", .{ name, arch }),
            );
        try verifySourceArchive(allocator, archive_data, entry);
        try Helpers.remember(allocator, &files, archive_name, archive_data);

        const art_sources_val = report.object.get("artifact_sources") orelse
            return fail("probe has no independently retained signed source metadata for {s} on {s}; run a new probe", .{ name, arch });
        if (art_sources_val != .object) {
            return fail("probe has no independently retained signed source metadata for {s} on {s}; run a new probe", .{ name, arch });
        }
        const arch_sources = art_sources_val.object.get(arch) orelse
            return fail("probe has no independently retained signed source metadata for {s} on {s}; run a new probe", .{ name, arch });
        if (arch_sources != .object) {
            return fail("probe has no independently retained signed source metadata for {s} on {s}; run a new probe", .{ name, arch });
        }
        const metadata = arch_sources.object.get(name) orelse
            return fail("probe has no independently retained signed source metadata for {s} on {s}; run a new probe", .{ name, arch });
        if (metadata != .object) {
            return fail("probe has no independently retained signed source metadata for {s} on {s}; run a new probe", .{ name, arch });
        }
        _ = try exactKeys(metadata, &.{ "index_file", "index_path", "release_file" }, &.{}, "probe source metadata");

        const index_file = metadata.object.get("index_file").?.string;
        const index_path = metadata.object.get("index_path").?.string;
        const release_file = metadata.object.get("release_file").?.string;

        var src_obj: std.json.ObjectMap = .empty;
        try src_obj.put(allocator, "package", .{ .string = name });
        try src_obj.put(allocator, "architecture", .{ .string = arch });
        try src_obj.put(allocator, "archive_file", .{ .string = archive_name });
        try src_obj.put(allocator, "lock_file", .{ .string = lock_name });
        try src_obj.put(allocator, "lock_sha256", .{ .string = try tagged(allocator, "sha256", files.get(lock_name).?) });
        try src_obj.put(allocator, "index_file", .{ .string = index_file });
        try src_obj.put(allocator, "index_path", .{ .string = index_path });
        try src_obj.put(allocator, "release_file", .{ .string = release_file });
        try sources_arr.append(.{ .object = src_obj });

        _ = try Helpers.retain(allocator, &files, directory, index_file, maximum_release_bytes);
        _ = try Helpers.retain(allocator, &files, directory, release_file, maximum_release_bytes);
    }

    var ev_doc: std.json.ObjectMap = .empty;
    try ev_doc.put(allocator, "schema", .{ .string = EVIDENCE_SCHEMA });
    try ev_doc.put(allocator, "report_sha256", .{ .string = try tagged(allocator, "sha256", files.get("report.json").?) });
    try ev_doc.put(allocator, "sources", .{ .array = sources_arr });
    const ev_bytes = try canonicalJson(allocator, .{ .object = ev_doc });
    try Helpers.remember(allocator, &files, "evidence.json", ev_bytes);

    if (files.count() > maximum_evidence_files or Helpers.totalBytes(&files) > maximum_evidence_bytes) {
        return fail("source evidence exceeds its file or byte bound", .{});
    }

    const rel_out = manifest.object.get("prestate_evidence").?.string;
    const out_path = try std.fs.path.join(allocator, &.{ root, rel_out });
    if (!isNotSymlink(out_path)) {
        return fail("source evidence output must stay inside the checkout without a symlink", .{});
    }
    if (std.fs.path.dirname(out_path)) |parent| {
        cwdMakePath(parent) catch |err| {
            return fail("cannot create source evidence parent directory: {s}", .{@errorName(err)});
        };
        if (!isPathWithinRoot(allocator, parent, root)) {
            return fail("source evidence output must stay inside the checkout without a symlink", .{});
        }
    }

    const sorted_names = try allocator.alloc([]const u8, files.count());
    for (files.keys(), 0..) |k, i| sorted_names[i] = k;
    std.mem.sort([]const u8, sorted_names, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);

    const specs = try allocator.alloc(ZipEntrySpec, sorted_names.len);
    for (sorted_names, 0..) |k, i| {
        specs[i] = .{
            .name = k,
            .data = files.get(k).?,
            .compress_type = 0,
            .external_attr = 0o100644 << 16,
        };
    }
    const zip_bytes = try buildZipArchive(allocator, specs);
    const failures = try checkPrestateEvidence(allocator, manifest, zip_bytes);
    if (failures.len > 0) {
        return fail("cannot record source evidence: {s}", .{try std.mem.join(allocator, "; ", failures)});
    }
    writeFileBytes(out_path, zip_bytes) catch |err| {
        return fail("cannot write source evidence: {s}", .{@errorName(err)});
    };
}

pub fn checkPrestateEvidence(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    data: []const u8,
) RepinError![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    if (data.len > maximum_evidence_bytes) {
        return fail("source evidence ZIP is too large", .{});
    }
    const entries = try parseZipEntries(allocator, data);
    var unique_names = std.StringHashMap(void).init(allocator);
    defer unique_names.deinit();
    var total_uncomp: usize = 0;
    for (entries) |entry| {
        try unique_names.put(entry.filename, {});
        total_uncomp +|= entry.file_size;
    }
    if (entries.len > maximum_evidence_files or unique_names.count() != entries.len or total_uncomp > maximum_evidence_bytes) {
        return fail("source evidence ZIP has duplicate entries or exceeds its file or byte bound", .{});
    }
    for (entries) |entry| {
        _ = try validateRelativePathStr(entry.filename, "source evidence ZIP member");
        const mode = entry.external_attr >> 16;
        const file_type = mode & 0o170000;
        if (entry.isDir() or (entry.flags & 1) != 0 or
            (entry.compress_type != 0 and entry.compress_type != 8) or
            (file_type != 0 and file_type != 0o100000))
        {
            return fail("source evidence ZIP has an unsafe member {s}", .{entry.filename});
        }
    }

    const ev_raw = try readZipMemberData(allocator, entries, "evidence.json", maximum_release_bytes);
    const index = try parseJsonObjectBytes(allocator, ev_raw, "source evidence evidence.json");
    _ = try exactKeys(index, &.{ "schema", "report_sha256", "sources" }, &.{}, "source evidence");

    const rep_raw = try readZipMemberData(allocator, entries, "report.json", maximum_release_bytes);
    const rep_sha256 = try tagged(allocator, "sha256", rep_raw);
    if (index.object.get("schema").? != .string or
        !std.mem.eql(u8, index.object.get("schema").?.string, EVIDENCE_SCHEMA) or
        index.object.get("report_sha256").? != .string or
        !std.mem.eql(u8, rep_sha256, index.object.get("report_sha256").?.string))
    {
        return fail("source evidence has an unsupported schema or changed probe report", .{});
    }

    const report = try parseJsonObjectBytes(allocator, rep_raw, "source evidence report.json");
    const rep_schema = report.object.get("schema") orelse return fail("source evidence probe coordinates differ from the current manifest", .{});
    const rep_series = report.object.get("series") orelse return fail("source evidence probe coordinates differ from the current manifest", .{});
    const rep_ts = report.object.get("timestamp") orelse return fail("source evidence probe coordinates differ from the current manifest", .{});
    if (rep_schema != .string or !std.mem.eql(u8, rep_schema.string, REPORT_SCHEMA) or
        !jsonEql(rep_series, manifest.object.get("series").?) or
        rep_ts != .string or !std.mem.eql(u8, rep_ts.string, manifest.object.get("snapshot").?.object.get("timestamp").?.string))
    {
        return fail("source evidence probe coordinates differ from the current manifest", .{});
    }

    var current_pockets = std.StringHashMap(std.json.Value).init(allocator);
    defer current_pockets.deinit();
    if (manifest.object.get("snapshot").?.object.get("pockets")) |mp| {
        if (mp == .array) {
            for (mp.array.items) |p| {
                try current_pockets.put(p.object.get("suite").?.string, p);
            }
        }
    }
    for (report.object.get("pockets").?.array.items) |pocket| {
        const suite = pocket.object.get("suite").?.string;
        const cur = current_pockets.get(suite) orelse
            return fail("source evidence Release for {s} differs from the current manifest", .{suite});
        for ([_][]const u8{ "role", "release_sha256", "in_release_sha256", "in_release_sha512", "signers" }) |k| {
            if (!jsonEql(cur.object.get(k).?, pocket.object.get(k).?)) {
                return fail("source evidence Release for {s} differs from the current manifest", .{suite});
            }
        }
    }

    const sources_val = index.object.get("sources").?;
    if (sources_val != .array) return fail("source evidence sources must be a list", .{});

    const SourceRecord = struct {
        entry: std.json.Value,
        archive_bytes: []const u8,
        fields: ManagedStringArrayHashMap([]const u8),
    };
    var sources = ManagedStringArrayHashMap(SourceRecord).init(allocator);
    defer sources.deinit();
    var used = std.StringHashMap(void).init(allocator);
    defer used.deinit();
    try used.put("evidence.json", {});
    try used.put("report.json", {});

    for (sources_val.array.items) |source| {
        const s_obj = try exactKeys(
            source,
            &.{ "package", "architecture", "archive_file", "lock_file", "lock_sha256", "index_file", "index_path", "release_file" },
            &.{},
            "source evidence source",
        );
        const arch = s_obj.get("architecture").?.string;
        const pkg = s_obj.get("package").?.string;
        const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ arch, pkg });
        if (sources.contains(key)) {
            return fail("source evidence has duplicate package/architecture coordinates", .{});
        }
        _ = try parseTaggedValue(s_obj.get("lock_sha256").?, &.{"sha256"});
        const lock_file = s_obj.get("lock_file").?.string;
        const lock_bytes = try readZipMemberData(allocator, entries, lock_file, maximum_release_bytes);
        if (!std.mem.eql(u8, try tagged(allocator, "sha256", lock_bytes), s_obj.get("lock_sha256").?.string)) {
            return fail("source evidence lock bytes changed", .{});
        }
        const lock_doc = try parseJsonObjectBytes(allocator, lock_bytes, lock_file);
        const entry = try authenticatedSourcePackage(allocator, report, lock_doc, pkg, arch);
        const archive_file = s_obj.get("archive_file").?.string;
        const archive_bytes = try readZipMemberData(allocator, entries, archive_file, maximum_evidence_bytes);
        try verifySourceArchive(allocator, archive_bytes, entry);
        const release_file = s_obj.get("release_file").?.string;
        const index_file = s_obj.get("index_file").?.string;
        const rel_bytes = try readZipMemberData(allocator, entries, release_file, maximum_release_bytes);
        const idx_bytes = try readZipMemberData(allocator, entries, index_file, maximum_release_bytes);
        const fields = try verifySourceMetadata(allocator, report, lock_doc, source, entry, rel_bytes, idx_bytes);
        try sources.put(key, .{
            .entry = entry,
            .archive_bytes = archive_bytes,
            .fields = fields,
        });
        try used.put(lock_file, {});
        try used.put(archive_file, {});
        try used.put(release_file, {});
        try used.put(index_file, {});
    }

    if (used.count() != entries.len) {
        return fail("source evidence ZIP has unreferenced members", .{});
    }

    var needed = std.StringHashMap(void).init(allocator);
    defer needed.deinit();
    const ev_identities = try sourceEvidenceIdentities(allocator, manifest);
    for (ev_identities) |identity| {
        const id_str = identity.object.get("id").?.string;
        const pkg = identity.object.get("package").?.string;
        const kind = identity.object.get("kind").?.string;
        for (identity.object.get("architectures").?.array.items) |arch_val| {
            const arch = arch_val.string;
            const where = try std.fmt.allocPrint(allocator, "{s} independent source evidence ({s})", .{ id_str, arch });
            const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ arch, pkg });
            try needed.put(key, {});
            const rec = sources.get(key) orelse {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} is missing", .{where}));
                continue;
            };
            const prov = identity.object.get("provenance").?;
            const want_archive_dig = try sourceArchiveDigest(allocator, rec.entry);
            if (prov != .object or
                !std.mem.eql(u8, prov.object.get("version").?.string, rec.entry.object.get("version").?.string) or
                !std.mem.eql(u8, prov.object.get("archives").?.object.get(arch).?.string, want_archive_dig))
            {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} disagrees on archive provenance", .{where}));
            }
            if (identity.object.get("derived_from")) |df| {
                for (df.array.items) |dep| {
                    const dep_pkg = dep.object.get("package").?.string;
                    const dep_ver = dep.object.get("version").?.string;
                    const dep_key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ arch, dep_pkg });
                    const dep_rec = sources.get(dep_key);
                    if (dep_rec == null or !std.mem.eql(u8, dep_rec.?.entry.object.get("version").?.string, dep_ver)) {
                        try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} disagrees on derived source {s}", .{ where, dep_pkg }));
                    }
                }
            }
            if (try derivePrestate(allocator, identity, arch, rec.archive_bytes)) |derived| {
                const mode_str = try std.fmt.allocPrint(allocator, "0{o:0>3}", .{derived.mode});
                if (!std.mem.eql(u8, try tagged(allocator, "sha256", derived.bytes), identity.object.get("digest").?.string) or
                    @as(i64, @intCast(derived.bytes.len)) != identity.object.get("size").?.integer or
                    identity.object.get("mode").? != .string or
                    !std.mem.eql(u8, mode_str, identity.object.get("mode").?.string))
                {
                    try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} derived bytes disagree on digest, size or mode", .{where}));
                }
            } else if (std.mem.eql(u8, kind, "archive")) {
                if (!std.mem.eql(u8, identity.object.get("digest").?.string, want_archive_dig) or
                    identity.object.get("size").?.integer != @as(i64, @intCast(rec.archive_bytes.len)))
                {
                    try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} archive digest or size disagrees", .{where}));
                }
            } else {
                const prefix = if (std.mem.eql(u8, kind, "script")) "control.tar" else "data.tar";
                const member = try tarMember(allocator, rec.archive_bytes, prefix, identity.object.get("path").?.string);
                const mode_str = try std.fmt.allocPrint(allocator, "0{o:0>3}", .{member.mode});
                if (!std.mem.eql(u8, try tagged(allocator, "sha256", member.bytes), identity.object.get("digest").?.string) or
                    @as(i64, @intCast(member.bytes.len)) != identity.object.get("size").?.integer or
                    identity.object.get("mode").? != .string or
                    !std.mem.eql(u8, mode_str, identity.object.get("mode").?.string))
                {
                    try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} member bytes disagree on digest, size or mode", .{where}));
                }
            }
            if (identity.object.get("artifact")) |art| {
                const fn_str = rec.fields.get("filename") orelse "";
                const ar_str = rec.fields.get("architecture") orelse "";
                if (!std.mem.eql(u8, art.object.get("filename").?.string, fn_str) or
                    !std.mem.eql(u8, art.object.get("architecture").?.string, ar_str))
                {
                    try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} artifact filename or architecture disagrees", .{where}));
                }
            }
        }
    }

    for (sources.keys()) |k| {
        if (!needed.contains(k)) {
            return fail("source evidence has unneeded package/architecture coordinates", .{});
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn prestateEvidenceFailures(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    root: []const u8,
) ![][]const u8 {
    const ev_ids = try sourceEvidenceIdentities(allocator, manifest);
    if (ev_ids.len == 0) return &.{};
    const rel_val = manifest.object.get("prestate_evidence") orelse {
        const res = try allocator.alloc([]const u8, 1);
        res[0] = "derivable prestates/artifact coordinates have no retained independent source evidence";
        return res;
    };
    const relative = rel_val.string;
    const full = try std.fs.path.join(allocator, &.{ root, relative });
    if (!isNotSymlink(full) or !isPathWithinRoot(allocator, full, root)) {
        const res = try allocator.alloc([]const u8, 1);
        res[0] = try std.fmt.allocPrint(allocator, "independent source evidence {s} is missing, unsafe or too large", .{relative});
        return res;
    }
    const stat = statFileFollow(full) catch {
        const res = try allocator.alloc([]const u8, 1);
        res[0] = try std.fmt.allocPrint(allocator, "independent source evidence {s} is missing, unsafe or too large", .{relative});
        return res;
    };
    if (stat.kind != .file or stat.size > maximum_evidence_bytes) {
        const res = try allocator.alloc([]const u8, 1);
        res[0] = try std.fmt.allocPrint(allocator, "independent source evidence {s} is missing, unsafe or too large", .{relative});
        return res;
    }
    const where = try std.fmt.allocPrint(allocator, "independent source evidence {s}", .{relative});
    const data = readSourceFile(allocator, full, root, maximum_evidence_bytes, where) catch |err| switch (err) {
        error.RepinFailed => {
            const res = try allocator.alloc([]const u8, 1);
            res[0] = try std.fmt.allocPrint(allocator, "independent source evidence {s}: {s}", .{ relative, lastErrorMessage() });
            return res;
        },
        else => return err,
    };
    return checkPrestateEvidence(allocator, manifest, data) catch |err| switch (err) {
        error.RepinFailed => {
            const res = try allocator.alloc([]const u8, 1);
            res[0] = try std.fmt.allocPrint(allocator, "independent source evidence {s}: {s}", .{ relative, lastErrorMessage() });
            return res;
        },
        else => return err,
    };
}

pub const RetainedSourceMemberResult = struct {
    entry: std.json.Value,
    bytes: []u8,
    mode: u32,
};

pub fn retainedSourceMember(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    evidence: []const u8,
    package: []const u8,
    architecture: []const u8,
    prefix: []const u8,
    path: []const u8,
) RepinError!RetainedSourceMemberResult {
    const failures = checkPrestateEvidence(allocator, manifest, evidence) catch |err| switch (err) {
        error.RepinFailed => return fail("binding source evidence refused: {s}", .{lastErrorMessage()}),
        else => return err,
    };
    if (failures.len > 0) {
        return fail("binding source evidence refused: {s}", .{try std.mem.join(allocator, "; ", failures)});
    }
    const entries = try parseZipEntries(allocator, evidence);
    const ev_raw = try readZipMemberData(allocator, entries, "evidence.json", maximum_release_bytes);
    const index = try parseJsonObjectBytes(allocator, ev_raw, "evidence.json");
    var found_source: ?std.json.Value = null;
    for (index.object.get("sources").?.array.items) |src| {
        if (std.mem.eql(u8, src.object.get("architecture").?.string, architecture) and
            std.mem.eql(u8, src.object.get("package").?.string, package))
        {
            if (found_source != null) {
                return fail("binding has no unique independently retained source archive; run a new probe", .{});
            }
            found_source = src;
        }
    }
    const source = found_source orelse
        return fail("binding has no unique independently retained source archive; run a new probe", .{});
    const rep_raw = try readZipMemberData(allocator, entries, "report.json", maximum_release_bytes);
    const report = try parseJsonObjectBytes(allocator, rep_raw, "report.json");
    const lock_raw = try readZipMemberData(allocator, entries, source.object.get("lock_file").?.string, maximum_release_bytes);
    const lock = try parseJsonObjectBytes(allocator, lock_raw, "lock");
    const entry = try authenticatedSourcePackage(allocator, report, lock, package, architecture);
    const archive_data = try readZipMemberData(allocator, entries, source.object.get("archive_file").?.string, maximum_evidence_bytes);
    try verifySourceArchive(allocator, archive_data, entry);
    const member = try tarMember(allocator, archive_data, prefix, path);
    return .{
        .entry = entry,
        .bytes = member.bytes,
        .mode = member.mode,
    };
}

pub fn bindArchitecture(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    identity_id: []const u8,
    architecture: []const u8,
    review: []const u8,
    evidence: []const u8,
    now_opt: ?i64,
) RepinError!std.json.Value {
    _ = try validateManifest(allocator, manifest);
    var found_id: ?std.json.Value = null;
    for (manifest.object.get("identities").?.array.items) |item| {
        if (std.mem.eql(u8, item.object.get("id").?.string, identity_id)) {
            if (found_id != null) return fail("architecture binding requires an existing script identity", .{});
            found_id = item;
        }
    }
    const identity = found_id orelse return fail("architecture binding requires an existing script identity", .{});
    if (!std.mem.eql(u8, identity.object.get("kind").?.string, "script")) {
        return fail("architecture binding requires an existing script identity", .{});
    }
    var in_series = false;
    for (manifest.object.get("series").?.object.get("architectures").?.array.items) |a| {
        if (std.mem.eql(u8, a.string, architecture)) in_series = true;
    }
    var already_in_id = false;
    for (identity.object.get("architectures").?.array.items) |a| {
        if (std.mem.eql(u8, a.string, architecture)) already_in_id = true;
    }
    if (!in_series or already_in_id) {
        return fail("architecture binding requires a new architecture from the series profile", .{});
    }
    if (!isReviewReference(review)) {
        return fail("architecture binding requires a PR or issue review reference", .{});
    }
    const now = now_opt orelse nowSeconds();
    const snap = manifest.object.get("snapshot").?.object;
    if (!std.mem.eql(u8, snap.get("status").?.string, "probed") or
        now >= snap.get("admission_deadline").?.integer)
    {
        return fail("architecture binding requires a currently admissible recorded snapshot", .{});
    }
    const retained = try retainedSourceMember(
        allocator,
        manifest,
        evidence,
        identity.object.get("package").?.string,
        architecture,
        "control.tar",
        identity.object.get("path").?.string,
    );
    const mode_str = try std.fmt.allocPrint(allocator, "0{o:0>3}", .{retained.mode});
    const prov = identity.object.get("provenance").?;
    if (!std.mem.eql(u8, try tagged(allocator, "sha256", retained.bytes), identity.object.get("digest").?.string) or
        @as(i64, @intCast(retained.bytes.len)) != identity.object.get("size").?.integer or
        !std.mem.eql(u8, mode_str, identity.object.get("mode").?.string) or
        prov != .object or
        !std.mem.eql(u8, retained.entry.object.get("version").?.string, prov.object.get("version").?.string))
    {
        return fail("architecture binding differs in script bytes, size, mode or version; record a separate identity", .{});
    }
    const updated = try cloneJsonValue(allocator, manifest);
    for (updated.object.getPtr("identities").?.array.items) |*item| {
        if (std.mem.eql(u8, item.object.get("id").?.string, identity_id)) {
            try item.object.getPtr("architectures").?.array.append(.{ .string = try allocator.dupe(u8, architecture) });
            try item.object.getPtr("provenance").?.object.getPtr("archives").?.object.put(
                allocator,
                try allocator.dupe(u8, architecture),
                .{ .string = try sourceArchiveDigest(allocator, retained.entry) },
            );
            try item.object.put(allocator, "review", .{ .string = try allocator.dupe(u8, review) });
            break;
        }
    }
    _ = try validateManifest(allocator, updated);
    const failures = try checkPrestateEvidence(allocator, updated, evidence);
    if (failures.len > 0) {
        return fail("architecture binding recorded source refused: {s}", .{try std.mem.join(allocator, "; ", failures)});
    }
    return updated;
}

pub fn bindMember(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    archive_id: []const u8,
    path: []const u8,
    consumers: []const []const u8,
    review: []const u8,
    evidence: []const u8,
    now_opt: ?i64,
) RepinError!std.json.Value {
    _ = try validateManifest(allocator, manifest);
    var found_archive: ?std.json.Value = null;
    for (manifest.object.get("identities").?.array.items) |item| {
        if (std.mem.eql(u8, item.object.get("id").?.string, archive_id)) {
            if (found_archive != null) return fail("member binding requires an existing single-architecture archive identity", .{});
            found_archive = item;
        }
    }
    const archive = found_archive orelse return fail("member binding requires an existing single-architecture archive identity", .{});
    if (!std.mem.eql(u8, archive.object.get("kind").?.string, "archive") or
        archive.object.get("architectures").?.array.items.len != 1)
    {
        return fail("member binding requires an existing single-architecture archive identity", .{});
    }
    const prov = archive.object.get("provenance").?;
    if (prov != .object) {
        return fail("member binding requires recorded archive provenance", .{});
    }
    const architecture = archive.object.get("architectures").?.array.items[0].string;
    _ = try validateRelativePathStr(path, "member binding path");

    if (consumers.len == 0) {
        return fail("member binding requires distinct snapshot admission source consumers", .{});
    }
    var seen_cons = std.StringHashMap(void).init(allocator);
    defer seen_cons.deinit();
    for (consumers) |c| {
        if (!sliceContains(&DEBZ_SNAPSHOT_CONSTANT_SOURCES, c) or seen_cons.contains(c)) {
            return fail("member binding requires distinct snapshot admission source consumers", .{});
        }
        try seen_cons.put(c, {});
    }
    if (!isReviewReference(review)) {
        return fail("member binding requires a PR or issue review reference", .{});
    }
    const now = now_opt orelse nowSeconds();
    const snap = manifest.object.get("snapshot").?.object;
    if (!std.mem.eql(u8, snap.get("status").?.string, "probed") or
        now >= snap.get("admission_deadline").?.integer)
    {
        return fail("member binding requires a currently admissible recorded snapshot", .{});
    }
    const pkg = archive.object.get("package").?.string;
    const identity_id = try std.fmt.allocPrint(allocator, "file:{s}/{s}@{s}", .{ pkg, path, architecture });
    for (manifest.object.get("identities").?.array.items) |item| {
        if (std.mem.eql(u8, item.object.get("id").?.string, identity_id)) {
            return fail("member binding identity already exists", .{});
        }
    }
    const retained = try retainedSourceMember(
        allocator,
        manifest,
        evidence,
        pkg,
        architecture,
        "data.tar",
        path,
    );
    const entry_dig = try sourceArchiveDigest(allocator, retained.entry);
    if (!std.mem.eql(u8, archive.object.get("digest").?.string, entry_dig) or
        archive.object.get("size").?.integer != retained.entry.object.get("declared_size").?.integer or
        !std.mem.eql(u8, prov.object.get("version").?.string, retained.entry.object.get("version").?.string))
    {
        return fail("member binding source disagrees with the reviewed archive identity", .{});
    }

    var updated = try cloneJsonValue(allocator, manifest);
    var new_id: std.json.ObjectMap = .empty;
    try new_id.put(allocator, "id", .{ .string = identity_id });
    try new_id.put(allocator, "kind", .{ .string = "tool_file" });
    try new_id.put(allocator, "package", .{ .string = try allocator.dupe(u8, pkg) });
    try new_id.put(allocator, "path", .{ .string = try allocator.dupe(u8, path) });
    var archs_arr = std.json.Array.init(allocator);
    try archs_arr.append(.{ .string = try allocator.dupe(u8, architecture) });
    try new_id.put(allocator, "architectures", .{ .array = archs_arr });
    try new_id.put(allocator, "digest", .{ .string = try tagged(allocator, "sha256", retained.bytes) });
    try new_id.put(allocator, "size", .{ .integer = @intCast(retained.bytes.len) });
    try new_id.put(allocator, "mode", .{ .string = try std.fmt.allocPrint(allocator, "0{o:0>3}", .{retained.mode}) });
    try new_id.put(allocator, "version_bound", .{ .bool = false });
    try new_id.put(allocator, "review", .{ .string = try allocator.dupe(u8, review) });

    var new_prov: std.json.ObjectMap = .empty;
    try new_prov.put(allocator, "version", .{ .string = try allocator.dupe(u8, retained.entry.object.get("version").?.string) });
    var new_archives: std.json.ObjectMap = .empty;
    try new_archives.put(allocator, try allocator.dupe(u8, architecture), .{ .string = entry_dig });
    try new_prov.put(allocator, "archives", .{ .object = new_archives });
    try new_id.put(allocator, "provenance", .{ .object = new_prov });

    var cons_arr = std.json.Array.init(allocator);
    for (consumers) |c| {
        var c_obj: std.json.ObjectMap = .empty;
        try c_obj.put(allocator, "path", .{ .string = try allocator.dupe(u8, c) });
        try c_obj.put(allocator, "form", .{ .string = "hex" });
        try cons_arr.append(.{ .object = c_obj });
    }
    try new_id.put(allocator, "consumers", .{ .array = cons_arr });
    try updated.object.getPtr("identities").?.array.append(.{ .object = new_id });

    _ = try validateManifest(allocator, updated);
    const ev_ids = try sourceEvidenceIdentities(allocator, updated);
    var in_ev = false;
    for (ev_ids) |ev_item| {
        if (std.mem.eql(u8, ev_item.object.get("id").?.string, identity_id)) {
            in_ev = true;
            break;
        }
    }
    if (!in_ev) {
        return fail("member binding requires an archive already retained by the offline source gates", .{});
    }
    const failures = try checkPrestateEvidence(allocator, updated, evidence);
    if (failures.len > 0) {
        return fail("member binding recorded source refused: {s}", .{try std.mem.join(allocator, "; ", failures)});
    }
    return updated;
}

// Check manifest, consumers, shell coordinates, and in-tree pins.

pub fn zigBytesConstant(allocator: std.mem.Allocator, text: []const u8, name: []const u8) !?[]u8 {
    var pos: usize = 0;
    while (pos < text.len) {
        const idx = std.mem.indexOfPos(u8, text, pos, "const ") orelse break;
        if (idx > 0 and (std.ascii.isAlphanumeric(text[idx - 1]) or text[idx - 1] == '_')) {
            pos = idx + 6;
            continue;
        }
        var cur = idx + 6;
        while (cur < text.len and (text[cur] == ' ' or text[cur] == '\t')) cur += 1;
        if (!std.mem.startsWith(u8, text[cur..], name)) {
            pos = cur;
            continue;
        }
        cur += name.len;
        if (cur < text.len and (std.ascii.isAlphanumeric(text[cur]) or text[cur] == '_')) {
            pos = cur;
            continue;
        }
        const eq = std.mem.indexOfScalarPos(u8, text, cur, '=') orelse break;
        if (std.mem.indexOfScalar(u8, text[cur..eq], '\n') != null) {
            pos = cur;
            continue;
        }
        var rhs = std.mem.trimStart(u8, text[eq + 1 ..], " \t\r\n");
        const prefix_32 = "[32]" ++ "u8";
        if (std.mem.startsWith(u8, rhs, prefix_32)) {
            rhs = std.mem.trimStart(u8, rhs[prefix_32.len..], " \t\r\n");
        }
        if (std.mem.startsWith(u8, rhs, ".{")) {
            rhs = rhs[2..];
        } else if (std.mem.startsWith(u8, rhs, "{")) {
            rhs = rhs[1..];
        } else {
            pos = eq + 1;
            continue;
        }
        const close = std.mem.indexOfScalar(u8, rhs, '}') orelse break;
        const body = rhs[0..close];
        var hex_out: std.ArrayList(u8) = .empty;
        defer hex_out.deinit(allocator);
        var byte_count: usize = 0;
        var b_pos: usize = 0;
        while (b_pos + 4 <= body.len) {
            if (body[b_pos] == '0' and body[b_pos + 1] == 'x' and
                std.ascii.isHex(body[b_pos + 2]) and std.ascii.isHex(body[b_pos + 3]))
            {
                try hex_out.append(allocator, std.ascii.toLower(body[b_pos + 2]));
                try hex_out.append(allocator, std.ascii.toLower(body[b_pos + 3]));
                byte_count += 1;
                b_pos += 4;
            } else {
                b_pos += 1;
            }
        }
        if (byte_count == Sha256.digest_length) {
            return try hex_out.toOwnedSlice(allocator);
        }
        return null;
    }
    return null;
}

pub fn shlexSplitPosix(allocator: std.mem.Allocator, input: []const u8) !?[][]const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    errdefer words.deinit(allocator);
    var cur: std.ArrayList(u8) = .empty;
    defer cur.deinit(allocator);
    var in_token = false;
    var quote: u8 = 0;
    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];
        if (quote == '\'') {
            if (c == '\'') {
                quote = 0;
            } else {
                try cur.append(allocator, c);
            }
            i += 1;
            continue;
        }
        if (quote == '"') {
            if (c == '"') {
                quote = 0;
                i += 1;
                continue;
            }
            if (c == '\\') {
                if (i + 1 >= input.len) return null;
                const next = input[i + 1];
                if (next == '$' or next == '`' or next == '"' or next == '\\' or next == '\n') {
                    if (next != '\n') try cur.append(allocator, next);
                    i += 2;
                    continue;
                }
            }
            try cur.append(allocator, c);
            i += 1;
            continue;
        }
        if (c == '#') {
            if (!in_token) {
                while (i < input.len and input[i] != '\n') i += 1;
                continue;
            }
        }
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            if (in_token) {
                try words.append(allocator, try cur.toOwnedSlice(allocator));
                in_token = false;
            }
            i += 1;
            continue;
        }
        if (c == '\'' or c == '"') {
            quote = c;
            in_token = true;
            i += 1;
            continue;
        }
        if (c == '\\') {
            if (i + 1 >= input.len) return null;
            if (input[i + 1] != '\n') {
                in_token = true;
                try cur.append(allocator, input[i + 1]);
            }
            i += 2;
            continue;
        }
        in_token = true;
        try cur.append(allocator, c);
        i += 1;
    }
    if (quote != 0) return null;
    if (in_token) {
        try words.append(allocator, try cur.toOwnedSlice(allocator));
    }
    return try words.toOwnedSlice(allocator);
}

pub fn shellReadonlyScalars(allocator: std.mem.Allocator, text: []const u8) !ManagedStringArrayHashMap(?[]const u8) {
    var values = ManagedStringArrayHashMap(?[]const u8).init(allocator);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimStart(u8, std.mem.trimEnd(u8, raw_line, "\r"), " \t");
        if (!std.mem.startsWith(u8, line, "readonly ")) continue;
        const rest = std.mem.trimStart(u8, line["readonly ".len..], " \t");
        const eq = std.mem.indexOfScalar(u8, rest, '=') orelse continue;
        const name = rest[0..eq];
        if (!isShellVarName(name)) continue;
        if (values.contains(name)) {
            try values.put(name, null);
            continue;
        }
        try values.put(try allocator.dupe(u8, name), null);
        const raw_rhs = std.mem.trim(u8, rest[eq + 1 ..], " \t");
        if (std.mem.startsWith(u8, raw_rhs, "(")) continue;
        const words = (try shlexSplitPosix(allocator, raw_rhs)) orelse continue;
        if (words.len == 1) {
            try values.put(name, words[0]);
        }
    }
    return values;
}

pub fn shellReadonlyArray(allocator: std.mem.Allocator, text: []const u8, var_name: []const u8) !?[][]const u8 {
    var match_body: ?[]const u8 = null;
    var pos: usize = 0;
    while (pos < text.len) {
        const line_end = std.mem.indexOfScalarPos(u8, text, pos, '\n') orelse text.len;
        const line = text[pos..line_end];
        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "readonly ")) {
            const after_ro = std.mem.trimStart(u8, trimmed["readonly ".len..], " \t");
            const prefix = try std.fmt.allocPrint(allocator, "{s}=(", .{var_name});
            if (std.mem.startsWith(u8, after_ro, prefix)) {
                const start_in_text = (text.ptr + text.len) - (after_ro.ptr + after_ro.len) + prefix.len;
                _ = start_in_text;
                const open_offset = (@intFromPtr(after_ro.ptr) - @intFromPtr(text.ptr)) + prefix.len;
                const close = std.mem.indexOfScalarPos(u8, text, open_offset, ')') orelse return null;
                if (match_body != null) return null;
                match_body = text[open_offset..close];
            }
        }
        pos = if (line_end < text.len) line_end + 1 else text.len;
    }
    const body = match_body orelse return null;
    return try shlexSplitPosix(allocator, body);
}

fn countReadonlyDeclarations(allocator: std.mem.Allocator, text: []const u8, var_name: []const u8) !usize {
    var count: usize = 0;
    const target = try std.fmt.allocPrint(allocator, "{s}=", .{var_name});
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const trimmed = std.mem.trimStart(u8, raw_line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "readonly ")) continue;
        const after_ro = std.mem.trimStart(u8, trimmed["readonly ".len..], " \t");
        if (std.mem.startsWith(u8, after_ro, target)) count += 1;
    }
    return count;
}

pub const ExpectedCoord = union(enum) {
    none,
    scalar: []const u8,
    array: []const []const u8,
};

fn formatPyReprStr(allocator: std.mem.Allocator, s: ?[]const u8) ![]u8 {
    if (s == null) return allocator.dupe(u8, "None");
    return std.fmt.allocPrint(allocator, "'{s}'", .{s.?});
}

fn formatPyReprList(allocator: std.mem.Allocator, list_opt: ?[]const []const u8) ![]u8 {
    const list = list_opt orelse return allocator.dupe(u8, "None");
    var out: std.ArrayList(u8) = .empty;
    try out.append(allocator, '[');
    for (list, 0..) |item, i| {
        if (i > 0) try out.appendSlice(allocator, ", ");
        try out.print(allocator, "'{s}'", .{item});
    }
    try out.append(allocator, ']');
    return out.toOwnedSlice(allocator);
}

pub fn shellCoordinateFailures(
    allocator: std.mem.Allocator,
    text: []const u8,
    bindings: std.json.ObjectMap,
    expected: std.StringHashMap(ExpectedCoord),
    where: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const scalars = try shellReadonlyScalars(allocator, text);
    var it = bindings.iterator();
    while (it.next()) |entry| {
        const coordinate = entry.key_ptr.*;
        const name = entry.value_ptr.*.string;
        const wanted = expected.get(coordinate) orelse .none;
        const decls = try countReadonlyDeclarations(allocator, text, name);
        switch (wanted) {
            .none => {
                const actual_str = if (decls == 1) (scalars.get(name) orelse null) else null;
                try failures.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "{s} {s} ({s}) is {s}, expected None", .{
                        where,
                        coordinate,
                        name,
                        try formatPyReprStr(allocator, actual_str),
                    }),
                );
            },
            .scalar => |want_s| {
                const actual_str = if (decls == 1) (scalars.get(name) orelse null) else null;
                if (actual_str == null or !std.mem.eql(u8, actual_str.?, want_s)) {
                    try failures.append(
                        allocator,
                        try std.fmt.allocPrint(allocator, "{s} {s} ({s}) is {s}, expected '{s}'", .{
                            where,
                            coordinate,
                            name,
                            try formatPyReprStr(allocator, actual_str),
                            want_s,
                        }),
                    );
                }
            },
            .array => |want_arr| {
                const actual_arr = if (decls == 1) (try shellReadonlyArray(allocator, text, name)) else null;
                var matches = false;
                if (actual_arr) |arr| {
                    if (arr.len == want_arr.len) {
                        matches = true;
                        for (arr, want_arr) |a, b| {
                            if (!std.mem.eql(u8, a, b)) {
                                matches = false;
                                break;
                            }
                        }
                    }
                }
                if (!matches) {
                    try failures.append(
                        allocator,
                        try std.fmt.allocPrint(allocator, "{s} {s} ({s}) is {s}, expected {s}", .{
                            where,
                            coordinate,
                            name,
                            try formatPyReprList(allocator, actual_arr),
                            try formatPyReprList(allocator, want_arr),
                        }),
                    );
                }
            },
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn consumerFailures(
    allocator: std.mem.Allocator,
    identity: std.json.Value,
    root: []const u8,
    manifest: ?std.json.Value,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const id_str = identity.object.get("id").?.string;
    const digest_str = identity.object.get("digest").?.string;
    const colon = std.mem.indexOfScalar(u8, digest_str, ':').?;
    const hexadecimal = digest_str[colon + 1 ..];
    const size_val = identity.object.get("size").?.integer;
    const prov = identity.object.get("provenance").?;
    const prov_is_obj = prov == .object;

    var version: ?[]const u8 = null;
    if (identity.object.get("version_bound").?.bool and prov_is_obj) {
        const full_ver = prov.object.get("version").?.string;
        version = if (std.mem.indexOfScalar(u8, full_ver, ':')) |c| full_ver[c + 1 ..] else full_ver;
    }
    var version_seen = (version == null);

    for (identity.object.get("consumers").?.array.items) |consumer| {
        const c_path = consumer.object.get("path").?.string;
        const form = consumer.object.get("form").?.string;
        const full_path = try std.fs.path.join(allocator, &.{ root, c_path });
        const where = try std.fmt.allocPrint(allocator, "{s} consumer {s}", .{ id_str, c_path });
        if (!isNotSymlink(full_path)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} does not exist", .{where}));
            continue;
        }
        const stat = statFileFollow(full_path) catch {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} does not exist", .{where}));
            continue;
        };
        if (stat.kind != .file) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} does not exist", .{where}));
            continue;
        }
        const data = cwdReadFileAlloc(allocator, full_path, maximum_archive_bytes) catch {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} does not exist", .{where}));
            continue;
        };
        if (std.mem.eql(u8, form, "fixture")) {
            if (!std.mem.eql(u8, try tagged(allocator, "sha256", data), digest_str) or
                @as(i64, @intCast(data.len)) != size_val)
            {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} bytes do not match {s} ({d} bytes)", .{ where, digest_str, size_val }));
            }
            if (version) |v| {
                if (std.mem.indexOf(u8, c_path, v) == null) {
                    try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} name does not carry version {s}", .{ where, prov.object.get("version").?.string }));
                }
            }
            version_seen = true;
            continue;
        }
        if (std.mem.eql(u8, form, "shell")) {
            var expected = std.StringHashMap(ExpectedCoord).init(allocator);
            try expected.put("digest", .{ .scalar = hexadecimal });
            try expected.put("digest_size", .{ .scalar = try std.fmt.allocPrint(allocator, "{s} {d}", .{ hexadecimal, size_val }) });
            try expected.put("size", .{ .scalar = try std.fmt.allocPrint(allocator, "{d}", .{size_val}) });
            if (prov_is_obj) {
                try expected.put("version", .{ .scalar = prov.object.get("version").?.string });
            } else {
                try expected.put("version", .none);
            }
            const path_val = identity.object.get("path").?;
            if (path_val == .string) {
                try expected.put("member", .{ .scalar = try std.fmt.allocPrint(allocator, "./{s}", .{path_val.string}) });
            } else {
                try expected.put("member", .none);
            }
            if (manifest) |m| {
                if (identity.object.get("artifact")) |art| {
                    const uri = try snapshotUri(allocator, m.object.get("series").?, m.object.get("snapshot").?.object.get("timestamp").?.string);
                    try expected.put("url", .{ .scalar = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ uri, art.object.get("filename").?.string }) });
                }
            }
            const bindings = consumer.object.get("bindings").?.object;
            const sh_fails = try shellCoordinateFailures(allocator, data, bindings, expected, where);
            try failures.appendSlice(allocator, sh_fails);
            if (bindings.contains("version") or bindings.contains("url")) {
                version_seen = true;
            }
            continue;
        }
        if (version) |v| {
            if (std.mem.indexOf(u8, data, v) != null) {
                version_seen = true;
            }
        }
        if (std.mem.eql(u8, form, "hex")) {
            if (std.mem.indexOf(u8, data, hexadecimal) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} does not pin {s}", .{ where, digest_str }));
            }
        } else {
            const cname = consumer.object.get("name").?.string;
            const zc = try zigBytesConstant(allocator, data, cname);
            if (zc == null or !std.mem.eql(u8, zc.?, hexadecimal)) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} constant {s} is not {s}", .{ where, cname, digest_str }));
            }
        }
    }
    if (!version_seen) {
        try failures.append(
            allocator,
            try std.fmt.allocPrint(allocator, "{s} is version-bound but no consumer names {s}", .{ id_str, prov.object.get("version").?.string }),
        );
    }
    return failures.toOwnedSlice(allocator);
}

pub fn snapshotCoordinateFailures(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    root: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const series = manifest.object.get("series").?;
    const snapshot = manifest.object.get("snapshot").?;
    const frozen = frozenPocket(snapshot);

    var frozen_suites: std.ArrayList([]const u8) = .empty;
    var witness_suites: std.ArrayList([]const u8) = .empty;
    for (series.object.get("pockets").?.array.items) |p| {
        const role = p.object.get("role").?.string;
        const suite = p.object.get("suite").?.string;
        if (std.mem.eql(u8, role, "frozen")) try frozen_suites.append(allocator, suite);
        if (std.mem.eql(u8, role, "witness")) try witness_suites.append(allocator, suite);
    }

    var expected = std.StringHashMap(ExpectedCoord).init(allocator);
    try expected.put("uri", .{ .scalar = try snapshotUri(allocator, series, snapshot.object.get("timestamp").?.string) });
    if (frozen_suites.items.len == 1) {
        try expected.put("suite", .{ .scalar = frozen_suites.items[0] });
    } else {
        try expected.put("suite", .none);
    }
    try expected.put("witness_suites", .{ .array = witness_suites.items });
    if (frozen) |fp| {
        const rel = fp.object.get("release_sha256").?.string;
        try expected.put("release_sha256", .{ .scalar = rel["sha256:".len..] });
    } else {
        try expected.put("release_sha256", .none);
    }

    const cc_val = manifest.object.get("coordinate_consumers") orelse return &.{};
    for (cc_val.array.items) |consumer| {
        const c_path = consumer.object.get("path").?.string;
        const full = try std.fs.path.join(allocator, &.{ root, c_path });
        const where = try std.fmt.allocPrint(allocator, "snapshot coordinate consumer {s}", .{c_path});
        if (!isNotSymlink(full)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} does not exist", .{where}));
            continue;
        }
        const stat = statFileFollow(full) catch {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} does not exist", .{where}));
            continue;
        };
        if (stat.kind != .file) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} does not exist", .{where}));
            continue;
        }
        const text = try cwdReadFileAlloc(allocator, full, maximum_release_bytes);
        const sh_fails = try shellCoordinateFailures(allocator, text, consumer.object.get("bindings").?.object, expected, where);
        try failures.appendSlice(allocator, sh_fails);
    }
    return failures.toOwnedSlice(allocator);
}

pub const PinDetail = struct {
    fixture: bool = false,
    unparsed: bool = false,
    size: ?i64 = null,
    path: ?[]const u8 = null,
    mode: ?[]const u8 = null,
    package: ?[]const u8 = null,
    version: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
    archive_size: ?i64 = null,
};

pub const InTreePin = struct {
    location: []const u8,
    hex: []const u8,
    detail: PinDetail,
};

fn extractQuotedFieldAfter(text: []const u8, prefix: []const u8) ?struct { val: []const u8, rest: []const u8 } {
    var s = std.mem.trimStart(u8, text, " \t\r\n");
    if (!std.mem.startsWith(u8, s, prefix)) return null;
    s = std.mem.trimStart(u8, s[prefix.len..], " \t\r\n");
    if (s.len == 0 or s[0] != '"') return null;
    s = s[1..];
    const close = std.mem.indexOfScalar(u8, s, '"') orelse return null;
    return .{ .val = s[0..close], .rest = s[close + 1 ..] };
}

fn extractDigitsAfter(text: []const u8, prefix: []const u8) ?struct { val: []const u8, rest: []const u8 } {
    var s = std.mem.trimStart(u8, text, " \t\r\n");
    if (!std.mem.startsWith(u8, s, prefix)) return null;
    s = std.mem.trimStart(u8, s[prefix.len..], " \t\r\n");
    var end: usize = 0;
    while (end < s.len and std.ascii.isDigit(s[end])) end += 1;
    if (end == 0) return null;
    return .{ .val = s[0..end], .rest = s[end..] };
}

pub fn inTreePins(allocator: std.mem.Allocator, root: []const u8) ![]InTreePin {
    var pins: std.ArrayList(InTreePin) = .empty;

    // 1. src/fixtures/ubuntu-*
    const fixtures_dir_path = try std.fs.path.join(allocator, &.{ root, "src/fixtures" });
    if (std.Io.Dir.cwd().openDir(global_io, fixtures_dir_path, .{ .iterate = true })) |dir_val| {
        var dir = dir_val;
        defer dir.close(global_io);
        var names: std.ArrayList([]const u8) = .empty;
        var it = dir.iterate();
        while (try it.next(global_io)) |entry| {
            if (std.mem.startsWith(u8, entry.name, "ubuntu-")) {
                try names.append(allocator, try allocator.dupe(u8, entry.name));
            }
        }
        std.mem.sort([]const u8, names.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        for (names.items) |fname| {
            const rel = try std.fmt.allocPrint(allocator, "src/fixtures/{s}", .{fname});
            const full = try std.fs.path.join(allocator, &.{ root, rel });
            const data = try cwdReadFileAlloc(allocator, full, maximum_archive_bytes);
            const hex = sha256HexLower(data);
            try pins.append(allocator, .{
                .location = rel,
                .hex = try allocator.dupe(u8, &hex),
                .detail = .{ .fixture = true, .size = @intCast(data.len) },
            });
        }
    } else |_| {}

    // 2. DEBZ_SNAPSHOT_CONSTANT_SOURCES
    for (DEBZ_SNAPSHOT_CONSTANT_SOURCES) |relative| {
        const full = try std.fs.path.join(allocator, &.{ root, relative });
        const stat = statFileFollow(full) catch continue;
        if (stat.kind != .file) continue;
        const text = try cwdReadFileAlloc(allocator, full, maximum_release_bytes);

        // 2a. SNAPSHOT_CONSTANT: ^\s*(?:pub\s+)?const\s+(snapshot_[a-z0-9_]*sha256)\b[^=]*=\s*
        var line_pos: usize = 0;
        while (line_pos < text.len) {
            const nl = std.mem.indexOfScalarPos(u8, text, line_pos, '\n') orelse text.len;
            const line = text[line_pos..nl];
            var s = std.mem.trimStart(u8, line, " \t");
            if (std.mem.startsWith(u8, s, "pub ")) {
                s = std.mem.trimStart(u8, s["pub ".len..], " \t");
            }
            if (std.mem.startsWith(u8, s, "const ")) {
                s = std.mem.trimStart(u8, s["const ".len..], " \t");
                var n_end: usize = 0;
                while (n_end < s.len and ((s[n_end] >= 'a' and s[n_end] <= 'z') or (s[n_end] >= '0' and s[n_end] <= '9') or s[n_end] == '_')) {
                    n_end += 1;
                }
                const cname = s[0..n_end];
                if (std.mem.startsWith(u8, cname, "snapshot_") and std.mem.endsWith(u8, cname, "sha256")) {
                    if (std.mem.indexOfScalar(u8, s[n_end..], '=')) |eq_rel| {
                        const after_eq_in_text = (@intFromPtr(s.ptr) - @intFromPtr(text.ptr)) + n_end + eq_rel + 1;
                        const after_ws = std.mem.trimStart(u8, text[after_eq_in_text..], " \t\r\n");
                        const loc = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ relative, cname });
                        if (try zigBytesConstant(allocator, text, cname)) |val| {
                            try pins.append(allocator, .{ .location = loc, .hex = val, .detail = .{} });
                        } else {
                            var is_quoted_hex = false;
                            if (after_ws.len >= 66 and after_ws[0] == '"') {
                                if (isHex64(after_ws[1..65]) and after_ws[65] == '"') is_quoted_hex = true;
                                if (!is_quoted_hex and after_ws.len >= 130 and isHex128(after_ws[1..129]) and after_ws[129] == '"') is_quoted_hex = true;
                            }
                            var is_digest_literal = false;
                            if (std.mem.startsWith(u8, after_ws, "digestLiteral(")) {
                                const arg = std.mem.trimStart(u8, after_ws["digestLiteral(".len..], " \t\r\n");
                                if (arg.len > 0 and arg[0] == '"') is_digest_literal = true;
                            }
                            if (!is_quoted_hex and !is_digest_literal) {
                                try pins.append(allocator, .{ .location = loc, .hex = "", .detail = .{ .unparsed = true } });
                            }
                        }
                    }
                }
            }
            line_pos = if (nl < text.len) nl + 1 else text.len;
        }

        // 2b. SNAPSHOT_INPUT_ENTRY
        var search_pos: usize = 0;
        while (std.mem.indexOfPos(u8, text, search_pos, ".path = \"")) |idx| {
            search_pos = idx + 9;
            const path_end = std.mem.indexOfScalarPos(u8, text, search_pos, '"') orelse continue;
            const entry_path = text[search_pos..path_end];
            var rest = std.mem.trimStart(u8, text[path_end + 1 ..], " \t\r\n");
            if (!std.mem.startsWith(u8, rest, ",")) continue;
            rest = std.mem.trimStart(u8, rest[1..], " \t\r\n");

            var mode_octal: ?[]const u8 = null;
            if (std.mem.startsWith(u8, rest, ".mode = 0o")) {
                rest = rest[".mode = 0o".len..];
                var m_end: usize = 0;
                while (m_end < rest.len and rest[m_end] >= '0' and rest[m_end] <= '7') m_end += 1;
                if (m_end == 0) continue;
                mode_octal = rest[0..m_end];
                rest = std.mem.trimStart(u8, rest[m_end..], " \t\r\n");
                if (!std.mem.startsWith(u8, rest, ",")) continue;
                rest = std.mem.trimStart(u8, rest[1..], " \t\r\n");
            }
            const sz_res = extractDigitsAfter(rest, ".size =") orelse continue;
            const sz_val = std.fmt.parseInt(i64, sz_res.val, 10) catch continue;
            rest = std.mem.trimStart(u8, sz_res.rest, " \t\r\n");
            if (!std.mem.startsWith(u8, rest, ",")) continue;
            rest = std.mem.trimStart(u8, rest[1..], " \t\r\n");

            if (std.mem.startsWith(u8, rest, ".mode = 0o")) {
                rest = rest[".mode = 0o".len..];
                var m_end: usize = 0;
                while (m_end < rest.len and rest[m_end] >= '0' and rest[m_end] <= '7') m_end += 1;
                if (m_end == 0) continue;
                mode_octal = rest[0..m_end];
                rest = std.mem.trimStart(u8, rest[m_end..], " \t\r\n");
                if (!std.mem.startsWith(u8, rest, ",")) continue;
                rest = std.mem.trimStart(u8, rest[1..], " \t\r\n");
            }
            const sha_res = extractQuotedFieldAfter(rest, ".sha256 =") orelse continue;
            if (!isLowerHex(sha_res.val)) continue;
            try pins.append(allocator, .{
                .location = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ relative, entry_path }),
                .hex = sha_res.val,
                .detail = .{
                    .path = entry_path,
                    .size = sz_val,
                    .mode = if (mode_octal) |m| try std.fmt.allocPrint(allocator, "0{s}", .{m}) else null,
                },
            });
        }

        // 2c. SNAPSHOT_ARCHIVE_ENTRY
        search_pos = 0;
        while (std.mem.indexOfPos(u8, text, search_pos, ".package")) |idx| {
            search_pos = idx + 8;
            var rest = std.mem.trimStart(u8, text[search_pos..], " \t\r\n");
            if (!std.mem.startsWith(u8, rest, "=")) continue;
            rest = std.mem.trimStart(u8, rest[1..], " \t\r\n");
            if (!std.mem.startsWith(u8, rest, ".{")) continue;
            rest = std.mem.trimStart(u8, rest[2..], " \t\r\n");
            const name_res = extractQuotedFieldAfter(rest, ".name =") orelse continue;
            rest = std.mem.trimStart(u8, name_res.rest, " \t\r\n");
            if (!std.mem.startsWith(u8, rest, ",")) continue;
            const ver_res = extractQuotedFieldAfter(rest[1..], ".version =") orelse continue;
            rest = std.mem.trimStart(u8, ver_res.rest, " \t\r\n");
            if (!std.mem.startsWith(u8, rest, ",")) continue;
            const arch_res = extractQuotedFieldAfter(rest[1..], ".architecture =") orelse continue;
            rest = std.mem.trimStart(u8, arch_res.rest, " \t\r\n");
            if (!std.mem.startsWith(u8, rest, "}")) continue;
            rest = std.mem.trimStart(u8, rest[1..], " \t\r\n");
            if (!std.mem.startsWith(u8, rest, ",")) continue;
            const sz_res = extractDigitsAfter(rest[1..], ".size =") orelse continue;
            const sz_val = std.fmt.parseInt(i64, sz_res.val, 10) catch continue;
            rest = std.mem.trimStart(u8, sz_res.rest, " \t\r\n");
            if (!std.mem.startsWith(u8, rest, ",")) continue;
            const sha_res = extractQuotedFieldAfter(rest[1..], ".sha512 =") orelse continue;
            if (!isHex128(sha_res.val)) continue;
            try pins.append(allocator, .{
                .location = try std.fmt.allocPrint(allocator, "{s}:archive:{s}", .{ relative, name_res.val }),
                .hex = sha_res.val,
                .detail = .{
                    .package = name_res.val,
                    .version = ver_res.val,
                    .architecture = arch_res.val,
                    .archive_size = sz_val,
                },
            });
        }

        // 2d. QUOTED_HEX_LITERAL
        var q_pos: usize = 0;
        while (std.mem.indexOfScalarPos(u8, text, q_pos, '"')) |q_idx| {
            const rem = text[q_idx + 1 ..];
            var matched_len: usize = 0;
            if (rem.len >= 129 and rem[128] == '"' and isHex128(rem[0..128])) {
                matched_len = 128;
            } else if (rem.len >= 65 and rem[64] == '"' and isHex64(rem[0..64])) {
                matched_len = 64;
            }
            if (matched_len > 0) {
                var line_no: usize = 1;
                for (text[0..q_idx]) |c| {
                    if (c == '\n') line_no += 1;
                }
                try pins.append(allocator, .{
                    .location = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ relative, line_no }),
                    .hex = rem[0..matched_len],
                    .detail = .{},
                });
                q_pos = q_idx + 1 + matched_len + 1;
            } else {
                q_pos = q_idx + 1;
            }
        }
    }

    // 3. tools/real-snapshot-*.sh
    const tools_dir_path = try std.fs.path.join(allocator, &.{ root, "tools" });
    if (std.Io.Dir.cwd().openDir(global_io, tools_dir_path, .{ .iterate = true })) |dir_val| {
        var dir = dir_val;
        defer dir.close(global_io);
        var sh_names: std.ArrayList([]const u8) = .empty;
        var it = dir.iterate();
        while (try it.next(global_io)) |entry| {
            if (std.mem.startsWith(u8, entry.name, "real-snapshot-") and std.mem.endsWith(u8, entry.name, ".sh")) {
                try sh_names.append(allocator, try allocator.dupe(u8, entry.name));
            }
        }
        std.mem.sort([]const u8, sh_names.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        for (sh_names.items) |sname| {
            const rel = try std.fmt.allocPrint(allocator, "tools/{s}", .{sname});
            const full = try std.fs.path.join(allocator, &.{ root, rel });
            const text = try cwdReadFileAlloc(allocator, full, maximum_release_bytes);
            var i: usize = 0;
            while (i < text.len) {
                const prev_alnum = (i > 0 and std.ascii.isAlphanumeric(text[i - 1]));
                if (!prev_alnum) {
                    var hex_len: usize = 0;
                    while (i + hex_len < text.len and ((text[i + hex_len] >= '0' and text[i + hex_len] <= '9') or (text[i + hex_len] >= 'a' and text[i + hex_len] <= 'f'))) {
                        hex_len += 1;
                    }
                    const next_alnum = (i + hex_len < text.len and std.ascii.isAlphanumeric(text[i + hex_len]));
                    if (!next_alnum and (hex_len == 64 or hex_len == 128)) {
                        var line_no: usize = 1;
                        for (text[0..i]) |c| {
                            if (c == '\n') line_no += 1;
                        }
                        try pins.append(allocator, .{
                            .location = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ rel, line_no }),
                            .hex = text[i .. i + hex_len],
                            .detail = .{},
                        });
                        i += hex_len;
                        continue;
                    }
                    if (hex_len > 0) {
                        i += hex_len;
                        continue;
                    }
                }
                i += 1;
            }
        }
    } else |_| {}

    return pins.toOwnedSlice(allocator);
}

fn isBoundPathForIdentity(allocator: std.mem.Allocator, identity: std.json.Value, path: []const u8) !bool {
    const id_path = identity.object.get("path") orelse return false;
    if (id_path != .string) return false;
    if (std.mem.eql(u8, path, id_path.string)) return true;
    const kind_val = identity.object.get("kind") orelse return false;
    if (kind_val == .string and std.mem.eql(u8, kind_val.string, "script")) {
        const pkg = identity.object.get("package").?.string;
        const alt = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}.{s}", .{ pkg, id_path.string });
        if (std.mem.eql(u8, path, alt)) return true;
    }
    return false;
}

pub fn protectedStageProfileCouplingFailures(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    root: []const u8,
) ![][]const u8 {
    const stage_path = try std.fs.path.join(allocator, &.{ root, PROTECTED_STAGE_SCRIPT });
    const launcher_path = try std.fs.path.join(allocator, &.{ root, REFERENCE_LAUNCHER });
    const stage_exists = blk: {
        _ = statFileFollow(stage_path) catch break :blk false;
        break :blk true;
    };
    const launcher_exists = blk: {
        _ = statFileFollow(launcher_path) catch break :blk false;
        break :blk true;
    };
    if (!stage_exists and !launcher_exists) return &.{};

    var failures: std.ArrayList([]const u8) = .empty;
    if (!stage_exists or !isNotSymlink(stage_path) or (try statFileFollow(stage_path)).kind != .file) {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected profile coupling: {s} does not exist", .{PROTECTED_STAGE_SCRIPT}));
        return failures.toOwnedSlice(allocator);
    }
    if (!launcher_exists or !isNotSymlink(launcher_path) or (try statFileFollow(launcher_path)).kind != .file) {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected profile coupling: {s} does not exist", .{REFERENCE_LAUNCHER}));
        return failures.toOwnedSlice(allocator);
    }
    const stage = try cwdReadFileAlloc(allocator, stage_path, maximum_release_bytes);
    const launcher = try cwdReadFileAlloc(allocator, launcher_path, maximum_release_bytes);

    const series = manifest.object.get("series").?;
    const snapshot = manifest.object.get("snapshot").?;
    var frozen_pockets: std.ArrayList(std.json.Value) = .empty;
    var witness_suites: std.ArrayList([]const u8) = .empty;
    for (series.object.get("pockets").?.array.items) |p| {
        const role = p.object.get("role").?.string;
        if (std.mem.eql(u8, role, "frozen")) try frozen_pockets.append(allocator, p);
        if (std.mem.eql(u8, role, "witness")) try witness_suites.append(allocator, p.object.get("suite").?.string);
    }

    if (frozen_pockets.items.len > 0) {
        if (frozen_pockets.items.len != 1) {
            try failures.append(allocator, "protected stage profile coupling: series must have exactly one frozen pocket");
        } else {
            const frozen_suite = frozen_pockets.items[0].object.get("suite").?.string;
            const scalars = try shellReadonlyScalars(allocator, stage);
            const want_uri = try snapshotUri(allocator, series, snapshot.object.get("timestamp").?.string);
            const got_uri = scalars.get("snapshot_uri") orelse null;
            if (got_uri == null or !std.mem.eql(u8, got_uri.?, want_uri)) {
                try failures.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "protected stage profile coupling: {s} does not pin {s}", .{ PROTECTED_STAGE_SCRIPT, want_uri }),
                );
            }
            const got_suite = scalars.get("snapshot_suite") orelse null;
            if (got_suite == null or !std.mem.eql(u8, got_suite.?, frozen_suite)) {
                try failures.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "protected stage profile coupling: snapshot_suite={s}, expected frozen suite '{s}'", .{
                        try formatPyReprStr(allocator, got_suite),
                        frozen_suite,
                    }),
                );
            }
            const stage_witnesses = try shellReadonlyArray(allocator, stage, "snapshot_witness_suites");
            var w_match = false;
            if (stage_witnesses) |sw| {
                if (sw.len == witness_suites.items.len) {
                    w_match = true;
                    for (sw, witness_suites.items) |a, b| {
                        if (!std.mem.eql(u8, a, b)) {
                            w_match = false;
                            break;
                        }
                    }
                }
            }
            if (!w_match) {
                try failures.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "protected stage profile coupling: snapshot_witness_suites={s}, expected {s}", .{
                        try formatPyReprList(allocator, stage_witnesses),
                        try formatPyReprList(allocator, witness_suites.items),
                    }),
                );
            }
            if (snapshot.object.get("pockets")) |sp_val| {
                for (sp_val.array.items) |p| {
                    if (std.mem.eql(u8, p.object.get("suite").?.string, frozen_suite) and
                        std.mem.eql(u8, p.object.get("role").?.string, "frozen"))
                    {
                        const expected_dig = p.object.get("release_sha256").?.string["sha256:".len..];
                        const got_dig = scalars.get("frozen_release_sha256") orelse null;
                        if (got_dig == null or !std.mem.eql(u8, got_dig.?, expected_dig)) {
                            try failures.append(
                                allocator,
                                try std.fmt.allocPrint(allocator, "protected stage profile coupling: frozen_release_sha256={s}, expected '{s}'", .{
                                    try formatPyReprStr(allocator, got_dig),
                                    expected_dig,
                                }),
                            );
                        }
                        break;
                    }
                }
            }
        }
    }

    const ScriptBinding = struct {
        name: []const u8,
        version: []const u8,
        size: i64,
        digest: []const u8,
    };
    var bindings: std.ArrayList(ScriptBinding) = .empty;
    var b_pos: usize = 0;
    while (std.mem.indexOfPos(u8, launcher, b_pos, ".{")) |idx| {
        b_pos = idx + 2;
        const name_res = extractQuotedFieldAfter(launcher[b_pos..], ".name =") orelse continue;
        if (!isPackageName(name_res.val)) continue;
        var rest = std.mem.trimStart(u8, name_res.rest, " \t\r\n");
        if (!std.mem.startsWith(u8, rest, ",")) continue;
        const ver_res = extractQuotedFieldAfter(rest[1..], ".version =") orelse continue;
        rest = std.mem.trimStart(u8, ver_res.rest, " \t\r\n");
        if (!std.mem.startsWith(u8, rest, ",")) continue;
        const sz_res = extractDigitsAfter(rest[1..], ".size =") orelse continue;
        const sz_val = std.fmt.parseInt(i64, sz_res.val, 10) catch continue;
        rest = std.mem.trimStart(u8, sz_res.rest, " \t\r\n");
        if (!std.mem.startsWith(u8, rest, ",")) continue;
        const dig_res = extractQuotedFieldAfter(rest[1..], ".digest =") orelse continue;
        if (!isHex64(dig_res.val)) continue;
        rest = std.mem.trimStart(u8, dig_res.rest, " \t\r\n");
        if (!std.mem.startsWith(u8, rest, "}")) continue;
        try bindings.append(allocator, .{
            .name = name_res.val,
            .version = ver_res.val,
            .size = sz_val,
            .digest = dig_res.val,
        });
    }
    if (bindings.items.len == 0) {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected stage profile coupling: {s} has no script_bindings", .{REFERENCE_LAUNCHER}));
        return failures.toOwnedSlice(allocator);
    }

    var loop_body: ?[]const u8 = null;
    var stage_lines = std.mem.splitScalar(u8, stage, '\n');
    while (stage_lines.next()) |raw_line| {
        var s = std.mem.trimStart(u8, std.mem.trimEnd(u8, raw_line, "\r"), " \t");
        if (!std.mem.startsWith(u8, s, "for ")) continue;
        s = std.mem.trimStart(u8, s["for ".len..], " \t");
        if (!std.mem.startsWith(u8, s, "profile ")) continue;
        s = std.mem.trimStart(u8, s["profile ".len..], " \t");
        if (!std.mem.startsWith(u8, s, "in ")) continue;
        s = std.mem.trimStart(u8, s["in ".len..], " \t");
        const semi = std.mem.indexOfScalar(u8, s, ';') orelse continue;
        const after_semi = std.mem.trim(u8, s[semi + 1 ..], " \t");
        if (!std.mem.eql(u8, after_semi, "do")) continue;
        loop_body = s[0..semi];
        break;
    }
    if (loop_body == null) {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected stage profile coupling: {s} has no profile staging loop", .{PROTECTED_STAGE_SCRIPT}));
    } else {
        const staged_profiles = (try shlexSplitPosix(allocator, loop_body.?)) orelse &.{};
        const binding_names = try allocator.alloc([]const u8, bindings.items.len);
        for (bindings.items, 0..) |b, i| binding_names[i] = b.name;
        var p_match = (staged_profiles.len == binding_names.len);
        if (p_match) {
            for (staged_profiles, binding_names) |a, b| {
                if (!std.mem.eql(u8, a, b)) {
                    p_match = false;
                    break;
                }
            }
        }
        if (!p_match) {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(allocator, "protected stage profile coupling: staged profiles {s} do not match launcher bindings {s}", .{
                    try formatPyReprList(allocator, staged_profiles),
                    try formatPyReprList(allocator, binding_names),
                }),
            );
        }
    }

    var id_map = std.StringHashMap(std.json.Value).init(allocator);
    defer id_map.deinit();
    for (manifest.object.get("identities").?.array.items) |id_item| {
        try id_map.put(id_item.object.get("id").?.string, id_item);
    }
    for (bindings.items) |b| {
        const identity_id = try std.fmt.allocPrint(allocator, "script:{s}/postinst", .{b.name});
        const identity = id_map.get(identity_id) orelse {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected stage profile coupling: {s} is not a manifest identity", .{identity_id}));
            continue;
        };
        const expected_digest = try std.fmt.allocPrint(allocator, "sha256:{s}", .{b.digest});
        const id_dig = identity.object.get("digest").?.string;
        if (!std.mem.eql(u8, id_dig, expected_digest)) {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(allocator, "protected stage profile coupling: {s} {s} digest {s} disagrees with {s} {s}", .{
                    REFERENCE_LAUNCHER, b.name, expected_digest, identity_id, id_dig,
                }),
            );
        }
        const id_size = identity.object.get("size").?.integer;
        if (id_size != b.size) {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(allocator, "protected stage profile coupling: {s} {s} size {d} disagrees with {s} {d}", .{
                    REFERENCE_LAUNCHER, b.name, b.size, identity_id, id_size,
                }),
            );
        }
        const prov = identity.object.get("provenance").?;
        const ver: ?[]const u8 = if (prov == .object) prov.object.get("version").?.string else null;
        if (ver == null or !std.mem.eql(u8, ver.?, b.version)) {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(allocator, "protected stage profile coupling: {s} {s} version '{s}' disagrees with {s} provenance {s}", .{
                    REFERENCE_LAUNCHER, b.name, b.version, identity_id, try formatPyReprStr(allocator, ver),
                }),
            );
        }
        const archs = identity.object.get("architectures").?.array.items;
        if (archs.len != 1 or !std.mem.eql(u8, archs[0].string, "amd64")) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected stage profile coupling: {s} must be amd64-only", .{identity_id}));
        }
        var has_launcher_hex = false;
        for (identity.object.get("consumers").?.array.items) |c| {
            if (std.mem.eql(u8, c.object.get("form").?.string, "hex") and
                std.mem.eql(u8, c.object.get("path").?.string, REFERENCE_LAUNCHER))
            {
                has_launcher_hex = true;
                break;
            }
        }
        if (!has_launcher_hex) {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(allocator, "protected stage profile coupling: {s} does not register {s} as a hex consumer", .{
                    identity_id, REFERENCE_LAUNCHER,
                }),
            );
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn checkManifest(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    root: []const u8,
    profile_opt: ?std.json.Value,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const series = manifest.object.get("series").?;
    const series_name = series.object.get("name").?.string;
    const expected = profile_opt orelse (try makeBuiltinProfile(allocator, series_name));
    if (expected == null) {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "series {s} is not a built-in profile; pass --profile", .{series_name}));
    } else if (!jsonEql(expected.?, series)) {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "series {s} differs from its reviewed profile", .{series_name}));
    }

    const snapshot = manifest.object.get("snapshot").?;
    const snap_ts = snapshot.object.get("timestamp").?.string;
    const uri = try snapshotUri(allocator, series, snap_ts);

    for (manifest.object.get("uri_consumers").?.array.items) |rel_val| {
        const relative = rel_val.string;
        const full = try std.fs.path.join(allocator, &.{ root, relative });
        const stat = statFileFollow(full) catch {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "URI consumer {s} does not exist", .{relative}));
            continue;
        };
        if (stat.kind != .file) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "URI consumer {s} does not exist", .{relative}));
            continue;
        }
        const text = try cwdReadFileAlloc(allocator, full, maximum_release_bytes);
        if (std.mem.indexOf(u8, text, uri) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "URI consumer {s} does not pin {s}", .{ relative, uri }));
        }
        var other_ts = ManagedStringArrayHashMap(void).init(allocator);
        defer other_ts.deinit();
        const needle = "snapshot.ubuntu.com/ubuntu/";
        var u_pos: usize = 0;
        while (std.mem.indexOfPos(u8, text, u_pos, needle)) |idx| {
            u_pos = idx + needle.len;
            if (u_pos + 16 <= text.len) {
                const cand = text[u_pos .. u_pos + 16];
                if (isTimestampFormat(cand) and !std.mem.eql(u8, cand, snap_ts)) {
                    try other_ts.put(cand, {});
                }
            }
        }
        const sorted_others = try allocator.alloc([]const u8, other_ts.count());
        for (other_ts.keys(), 0..) |k, i| sorted_others[i] = k;
        std.mem.sort([]const u8, sorted_others, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        for (sorted_others) |other| {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "URI consumer {s} pins another snapshot {s}", .{ relative, other }));
        }
    }

    var digests = std.StringHashMap(std.json.Value).init(allocator);
    defer digests.deinit();
    if (snapshot.object.get("pockets")) |pockets_val| {
        for (pockets_val.array.items) |pocket| {
            const suite = pocket.object.get("suite").?.string;
            const rel_hex = pocket.object.get("release_sha256").?.string["sha256:".len..];
            const inrel_hex = pocket.object.get("in_release_sha256").?.string["sha256:".len..];
            var rel_obj: std.json.ObjectMap = .empty;
            try rel_obj.put(allocator, "id", .{ .string = try std.fmt.allocPrint(allocator, "release:{s}", .{suite}) });
            try rel_obj.put(allocator, "path", .null);
            try rel_obj.put(allocator, "size", .null);
            try digests.put(rel_hex, .{ .object = rel_obj });

            var inrel_obj: std.json.ObjectMap = .empty;
            try inrel_obj.put(allocator, "id", .{ .string = try std.fmt.allocPrint(allocator, "in-release:{s}", .{suite}) });
            try inrel_obj.put(allocator, "path", .null);
            try inrel_obj.put(allocator, "size", .null);
            try digests.put(inrel_hex, .{ .object = inrel_obj });
        }
    }
    if (snapshot.object.get("closures")) |closures_val| {
        var c_it = closures_val.object.iterator();
        while (c_it.next()) |kv| {
            const c_hex = kv.value_ptr.*.object.get("digest").?.string["sha256:".len..];
            var c_obj: std.json.ObjectMap = .empty;
            try c_obj.put(allocator, "id", .{ .string = try std.fmt.allocPrint(allocator, "closure:{s}", .{kv.key_ptr.*}) });
            try c_obj.put(allocator, "path", .null);
            try c_obj.put(allocator, "size", .null);
            try digests.put(c_hex, .{ .object = c_obj });
        }
    }
    for (manifest.object.get("identities").?.array.items) |identity| {
        const c_fails = try consumerFailures(allocator, identity, root, manifest);
        try failures.appendSlice(allocator, c_fails);
        const dig_str = identity.object.get("digest").?.string;
        const colon = std.mem.indexOfScalar(u8, dig_str, ':').?;
        const hex = dig_str[colon + 1 ..];
        if (!digests.contains(hex)) {
            try digests.put(hex, identity);
        }
    }

    try failures.appendSlice(allocator, try protectedStageProfileCouplingFailures(allocator, manifest, root));
    try failures.appendSlice(allocator, try snapshotCoordinateFailures(allocator, manifest, root));
    try failures.appendSlice(allocator, try prestateEvidenceFailures(allocator, manifest, root));

    var excluded = std.StringHashMap(void).init(allocator);
    defer excluded.deinit();
    for (manifest.object.get("excluded").?.array.items) |ex_item| {
        const d_str = ex_item.object.get("digest").?.string;
        const colon = std.mem.indexOfScalar(u8, d_str, ':').?;
        try excluded.put(d_str[colon + 1 ..], {});
    }

    var fixture_consumers = std.StringHashMap(void).init(allocator);
    defer fixture_consumers.deinit();
    for (manifest.object.get("identities").?.array.items) |identity| {
        for (identity.object.get("consumers").?.array.items) |consumer| {
            if (std.mem.eql(u8, consumer.object.get("form").?.string, "fixture")) {
                try fixture_consumers.put(consumer.object.get("path").?.string, {});
            }
        }
    }

    const pins = try inTreePins(allocator, root);
    for (pins) |pin| {
        if (pin.detail.unparsed) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "cannot parse the snapshot pin {s}", .{pin.location}));
            continue;
        }
        if (pin.detail.fixture and !fixture_consumers.contains(pin.location)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "fixture {s} is not a manifest identity consumer", .{pin.location}));
            continue;
        }
        if (excluded.contains(pin.hex)) continue;
        const identity = digests.get(pin.hex) orelse {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "in-tree pin {s} {s}... is absent from the manifest", .{ pin.location, pin.hex[0..16] }));
            continue;
        };
        const id_str = identity.object.get("id").?.string;
        if (pin.detail.archive_size) |arch_sz| {
            const kind_val = identity.object.get("kind") orelse .null;
            const pkg_val = identity.object.get("package") orelse .null;
            const size_val = identity.object.get("size") orelse .null;
            const prov_val = identity.object.get("provenance") orelse .null;
            var arch_ok = false;
            if (identity.object.get("architectures")) |archs_val| {
                for (archs_val.array.items) |a| {
                    if (std.mem.eql(u8, a.string, pin.detail.architecture.?)) arch_ok = true;
                }
            }
            if (kind_val != .string or !std.mem.eql(u8, kind_val.string, "archive") or
                pkg_val != .string or !std.mem.eql(u8, pkg_val.string, pin.detail.package.?) or
                size_val != .integer or size_val.integer != arch_sz or
                !arch_ok or prov_val != .object or
                !std.mem.eql(u8, prov_val.object.get("version").?.string, pin.detail.version.?))
            {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "in-tree pin {s} disagrees with {s} on archive version, size or architecture", .{ pin.location, id_str }));
            }
        }
        if (pin.detail.path) |p_path| {
            const path_ok = try isBoundPathForIdentity(allocator, identity, p_path);
            const size_val = identity.object.get("size") orelse .null;
            const size_ok = (size_val == .integer and size_val.integer == pin.detail.size.?);
            var mode_ok = true;
            if (pin.detail.mode) |p_mode| {
                const m_val = identity.object.get("mode") orelse .null;
                if (m_val != .null and (m_val != .string or !std.mem.eql(u8, m_val.string, p_mode))) {
                    mode_ok = false;
                }
            }
            if (!path_ok or !size_ok or !mode_ok) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "in-tree pin {s} disagrees with {s} on path, size or mode", .{ pin.location, id_str }));
            }
        }
    }
    return failures.toOwnedSlice(allocator);
}

// Probe, Diff, Record, and CLI Main.

pub var fetch_override: ?*const fn (allocator: std.mem.Allocator, url: []const u8) RepinError![]u8 = null;

pub fn fetch(allocator: std.mem.Allocator, url: []const u8) RepinError![]u8 {
    if (fetch_override) |override_fn| {
        return override_fn(allocator, url);
    }
    if (std.mem.startsWith(u8, url, "file://")) {
        const path = url["file://".len..];
        const stat = statFileFollow(path) catch |err| {
            return fail("cannot fetch {s}: {s}", .{ url, @errorName(err) });
        };
        if (stat.size > maximum_release_bytes) {
            return fail("{s} is too large", .{url});
        }
        const data = cwdReadFileAlloc(allocator, path, maximum_release_bytes + 1) catch |err| switch (err) {
            error.StreamTooLong => return fail("{s} is too large", .{url}),
            else => return fail("cannot fetch {s}: {s}", .{ url, @errorName(err) }),
        };
        if (data.len > maximum_release_bytes) {
            return fail("{s} is too large", .{url});
        }
        return data;
    }
    const max_str = try std.fmt.allocPrint(allocator, "{d}", .{maximum_release_bytes + 1});
    const res = std.process.run(allocator, global_io, .{
        .argv = &.{
            "curl",
            "-fsSL",
            "--max-time",
            "120",
            "--max-filesize",
            max_str,
            "-A",
            "debz-real-snapshot-repin",
            url,
        },
        .stdout_limit = .limited(maximum_release_bytes + 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch |err| {
        return fail("cannot fetch {s}: {s}", .{ url, @errorName(err) });
    };
    switch (res.term) {
        .exited => |code| if (code != 0) {
            if (code == 63) return fail("{s} is too large", .{url});
            return fail("cannot fetch {s}: curl exit {d}: {s}", .{ url, code, std.mem.trim(u8, res.stderr, " \t\r\n") });
        },
        else => return fail("cannot fetch {s}: curl terminated abnormally", .{url}),
    }
    if (res.stdout.len > maximum_release_bytes) {
        return fail("{s} is too large", .{url});
    }
    return res.stdout;
}

pub fn writeConfigs(
    allocator: std.mem.Allocator,
    directory: []const u8,
    profile: std.json.Value,
    timestamp: []const u8,
    arch: []const u8,
    frozen_digest: ?[]const u8,
) ![][]const u8 {
    try cwdMakePath(directory);
    var witnesses = std.json.Array.init(allocator);
    for (profile.object.get("pockets").?.array.items) |p| {
        if (std.mem.eql(u8, p.object.get("role").?.string, "witness")) {
            try witnesses.append(.{ .string = p.object.get("suite").?.string });
        }
    }
    var configs: std.ArrayList([]const u8) = .empty;
    const uri = try snapshotUri(allocator, profile, timestamp);
    const comp = profile.object.get("component").?.string;
    const kr = profile.object.get("keyring").?.string;

    for (profile.object.get("pockets").?.array.items) |pocket| {
        const suite = pocket.object.get("suite").?.string;
        const role = pocket.object.get("role").?.string;
        const source_path = try std.fs.path.join(allocator, &.{ directory, try std.fmt.allocPrint(allocator, "{s}.sources", .{suite}) });
        const source_text = try std.fmt.allocPrint(
            allocator,
            "Types: deb\nURIs: {s}\nSuites: {s}\nComponents: {s}\nArchitectures: {s}\nSigned-By: {s}\n",
            .{ uri, suite, comp, arch, kr },
        );
        try writeFileBytes(source_path, source_text);

        var freshness: std.json.ObjectMap = .empty;
        if (std.mem.eql(u8, role, "frozen")) {
            try freshness.put(allocator, "mode", .{ .string = "frozen_release_with_witnesses" });
            if (frozen_digest) |fd| {
                try freshness.put(allocator, "frozen_release_digest", .{ .string = fd });
            } else {
                try freshness.put(allocator, "frozen_release_digest", .null);
            }
            try freshness.put(allocator, "witness_suites", .{ .array = witnesses });
        } else {
            try freshness.put(allocator, "mode", .{ .string = "allow_missing_valid_until_with_max_age_seconds" });
            try freshness.put(allocator, "maximum_release_age_seconds", .{ .integer = MAXIMUM_RELEASE_AGE_SECONDS });
        }

        var cfg_obj: std.json.ObjectMap = .empty;
        try cfg_obj.put(allocator, "source_path", .{ .string = source_path });
        try cfg_obj.put(allocator, "priority", .{ .integer = 500 });
        try cfg_obj.put(allocator, "immutable", .{ .bool = true });
        try cfg_obj.put(allocator, "freshness", .{ .object = freshness });
        const config_path = try std.fs.path.join(allocator, &.{ directory, try std.fmt.allocPrint(allocator, "{s}.json", .{suite}) });
        try writeJson(allocator, config_path, .{ .object = cfg_obj });
        try configs.append(allocator, config_path);
    }
    return configs.toOwnedSlice(allocator);
}

pub const PackageSummary = struct {
    version: []const u8,
    architecture: []const u8,
    archive: ?[]const u8,
    pocket: ?[]const u8,
    size: i64,
    lock_package: ?std.json.Value = null,
    artifact: ?std.json.Value = null,
};

pub fn closureDigest(allocator: std.mem.Allocator, packages: ManagedStringArrayHashMap(PackageSummary)) RepinError![]u8 {
    const names = try allocator.alloc([]const u8, packages.count());
    for (packages.keys(), 0..) |k, i| names[i] = k;
    std.mem.sort([]const u8, names, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);

    var lines: std.ArrayList(u8) = .empty;
    for (names) |name| {
        const entry = packages.get(name).?;
        try lines.print(allocator, "{s}\x00{s}\x00{s}\x00{s}\n", .{
            name,
            entry.version,
            entry.architecture,
            entry.archive orelse "None",
        });
    }
    return tagged(allocator, "sha256", lines.items);
}

pub fn lockPackages(
    allocator: std.mem.Allocator,
    lock: std.json.Value,
    repositories: std.StringHashMap([]const u8),
) RepinError!ManagedStringArrayHashMap(PackageSummary) {
    var packages = ManagedStringArrayHashMap(PackageSummary).init(allocator);
    for (lock.object.get("packages").?.array.items) |pkg| {
        const name = pkg.object.get("name").?.string;
        if (packages.contains(name)) {
            return fail("lock lists {s} twice", .{name});
        }
        const identity = pkg.object.get("archive_identity").?.object;
        var sha512_dig: ?[]const u8 = null;
        var sha512_count: usize = 0;
        for (identity.get("digests").?.array.items) |d| {
            if (std.mem.eql(u8, d.object.get("algorithm").?.string, "sha512")) {
                sha512_dig = d.object.get("digest").?.string;
                sha512_count += 1;
            }
        }
        const primary = identity.get("primary") orelse .null;
        const archive = if (primary == .string and std.mem.eql(u8, primary.string, "sha512") and sha512_count == 1)
            try std.fmt.allocPrint(allocator, "sha512:{s}", .{sha512_dig.?})
        else
            null;
        var pocket: ?[]const u8 = null;
        if (pkg.object.get("origin").?.object.get("repository_id")) |rid| {
            if (rid == .string) pocket = repositories.get(rid.string);
        }
        try packages.put(try allocator.dupe(u8, name), .{
            .version = pkg.object.get("version").?.string,
            .architecture = pkg.object.get("architecture").?.string,
            .archive = archive,
            .pocket = pocket,
            .size = pkg.object.get("declared_size").?.integer,
        });
    }
    return packages;
}

pub fn requireSha512(allocator: std.mem.Allocator, packages: ManagedStringArrayHashMap(PackageSummary), arch: []const u8) RepinError!void {
    var missing: std.ArrayList([]const u8) = .empty;
    for (packages.keys()) |name| {
        const entry = packages.get(name).?;
        if (entry.archive == null) {
            try missing.append(allocator, try std.fmt.allocPrint(allocator, "{s} {s}", .{ name, entry.version }));
        }
    }
    if (missing.items.len > 0) {
        std.mem.sort([]const u8, missing.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        return fail("{s} closure packages without a signed SHA-512 archive identity: {s}", .{
            arch,
            try std.mem.join(allocator, ", ", missing.items),
        });
    }
}

pub fn validateRefreshRepository(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    suite: []const u8,
) RepinError!std.json.Value {
    const where = try std.fmt.allocPrint(allocator, "{s} refresh repository", .{suite});
    const obj = try exactKeys(
        value,
        &.{ "release_digest", "snapshot_digest", "signer_fingerprints", "frozen" },
        &.{},
        where,
    );
    _ = try parseTaggedValue(obj.get("release_digest").?, &.{"sha256"});
    _ = try parseTaggedValue(obj.get("snapshot_digest").?, &.{"sha256"});
    const signers = obj.get("signer_fingerprints").?;
    if (signers != .array or signers.array.items.len == 0) {
        return fail("{s} refresh has invalid signer fingerprints", .{suite});
    }
    for (signers.array.items, 0..) |s, idx| {
        if (s != .string or !isFingerprint(s.string)) {
            return fail("{s} refresh has invalid signer fingerprints", .{suite});
        }
        if (idx > 0 and !std.mem.lessThan(u8, signers.array.items[idx - 1].string, s.string)) {
            return fail("{s} refresh has invalid signer fingerprints", .{suite});
        }
    }
    const frozen = obj.get("frozen").?;
    if (frozen != .null) {
        const f_where = try std.fmt.allocPrint(allocator, "{s} frozen decisions", .{suite});
        const f_obj = try exactKeys(
            frozen,
            &.{ "release_digest", "admission_deadline_unix", "witnesses" },
            &.{},
            f_where,
        );
        _ = try parseTaggedValue(f_obj.get("release_digest").?, &.{"sha256"});
        if (f_obj.get("admission_deadline_unix").? != .integer) {
            return fail("{s} frozen admission deadline must be an integer", .{suite});
        }
        const witnesses = f_obj.get("witnesses").?;
        if (witnesses != .array or witnesses.array.items.len < 1 or witnesses.array.items.len > 4) {
            return fail("{s} frozen decisions need one to four witnesses", .{suite});
        }
        const w_where = try std.fmt.allocPrint(allocator, "{s} frozen witness", .{suite});
        for (witnesses.array.items) |w| {
            const w_obj = try exactKeys(
                w,
                &.{ "repository_id", "snapshot_digest", "release_date_unix", "deadline_unix", "primary_fingerprint" },
                &.{},
                w_where,
            );
            const rid = w_obj.get("repository_id").?;
            const pfp = w_obj.get("primary_fingerprint").?;
            if (rid != .string or !isHex64(rid.string) or
                pfp != .string or !isFingerprint(pfp.string) or
                w_obj.get("release_date_unix").? != .integer or
                w_obj.get("deadline_unix").? != .integer)
            {
                return fail("{s} frozen witness has invalid identity or decisions", .{suite});
            }
            _ = try parseTaggedValue(w_obj.get("snapshot_digest").?, &.{"sha256"});
        }
    }
    return value;
}

pub fn bindPockets(
    allocator: std.mem.Allocator,
    pockets: ManagedStringArrayHashMap(std.json.Value),
    locks: []const std.json.Value,
    repositories: ManagedStringArrayHashMap(std.json.Value),
    signer: []const u8,
    arch: []const u8,
) RepinError!std.StringHashMap(void) {
    if (repositories.count() != pockets.count()) {
        return fail("{s} refresh did not authenticate every pocket", .{arch});
    }
    for (pockets.keys()) |suite| {
        if (!repositories.contains(suite)) {
            return fail("{s} refresh did not authenticate every pocket", .{arch});
        }
    }
    var by_id = std.StringHashMap([]const u8).init(allocator);
    defer by_id.deinit();
    for (repositories.keys()) |suite| {
        const repository = repositories.get(suite).?;
        const where = try std.fmt.allocPrint(allocator, "{s} refresh evidence", .{suite});
        const r_obj = try exactKeys(
            repository,
            &.{ "id", "release_digest", "snapshot_digest", "signer_fingerprints", "frozen" },
            &.{},
            where,
        );
        const rid = r_obj.get("id").?;
        if (rid != .string or !isHex64(rid.string)) {
            return fail("{s} refresh has an invalid repository id", .{suite});
        }
        try by_id.put(rid.string, suite);
    }
    if (by_id.count() != repositories.count()) {
        return fail("{s} refresh reported duplicate repository ids", .{arch});
    }

    for (repositories.keys()) |suite| {
        const repository = repositories.get(suite).?;
        var without_id = try cloneJsonValue(allocator, repository);
        _ = without_id.object.swapRemove("id");
        _ = try validateRefreshRepository(allocator, without_id, suite);

        const s_fps = repository.object.get("signer_fingerprints").?.array.items;
        if (s_fps.len != 1 or !std.mem.eql(u8, s_fps[0].string, signer)) {
            var quoted: std.ArrayList([]const u8) = .empty;
            for (s_fps) |fp_val| {
                try quoted.append(allocator, try std.fmt.allocPrint(allocator, "'{s}'", .{fp_val.string}));
            }
            const joined = try std.mem.join(allocator, ", ", quoted.items);
            return fail("{s} is signed by [{s}], not the reviewed signer", .{ suite, joined });
        }
        const pocket = pockets.get(suite).?;
        if (!std.mem.eql(u8, repository.object.get("release_digest").?.string, pocket.object.get("release_sha256").?.string)) {
            return fail("{s} Release fetched by the probe differs from the Release debz authenticated", .{suite});
        }
        const frozen = repository.object.get("frozen").?;
        if (!std.mem.eql(u8, pocket.object.get("role").?.string, "frozen")) {
            if (frozen != .null) {
                return fail("{s} unexpectedly reports frozen decisions", .{suite});
            }
            continue;
        }
        var witness_pockets: std.ArrayList(std.json.Value) = .empty;
        for (pockets.values()) |p_val| {
            if (std.mem.eql(u8, p_val.object.get("role").?.string, "witness")) {
                try witness_pockets.append(allocator, p_val);
            }
        }
        std.mem.sort(std.json.Value, witness_pockets.items, {}, struct {
            fn less(_: void, a: std.json.Value, b: std.json.Value) bool {
                return std.mem.lessThan(u8, a.object.get("suite").?.string, b.object.get("suite").?.string);
            }
        }.less);
        if (frozen == .null or !std.mem.eql(u8, frozen.object.get("release_digest").?.string, pocket.object.get("release_sha256").?.string)) {
            return fail("{s} frozen Release differs from the reviewed pin", .{suite});
        }
        const f_witnesses = frozen.object.get("witnesses").?.array.items;
        if (f_witnesses.len != witness_pockets.items.len) {
            return fail("{s} frozen witnesses differ from configured policy order", .{suite});
        }
        var min_w_deadline: ?i64 = null;
        for (f_witnesses, witness_pockets.items) |decision, w_pocket| {
            const w_suite = w_pocket.object.get("suite").?.string;
            const w_repo = repositories.get(w_suite).?;
            if (!std.mem.eql(u8, decision.object.get("repository_id").?.string, w_repo.object.get("id").?.string)) {
                return fail("{s} frozen witnesses differ from configured policy order", .{suite});
            }
            const date_unix = try releaseTime(w_pocket.object.get("date").?.string, "Date");
            const vu_val = w_pocket.object.get("valid_until") orelse .null;
            const deadline_unix = if (vu_val == .string and vu_val.string.len > 0)
                try releaseTime(vu_val.string, "Valid-Until")
            else
                date_unix + MAXIMUM_RELEASE_AGE_SECONDS;
            const dec_dl = decision.object.get("deadline_unix").?.integer;
            if (!std.mem.eql(u8, decision.object.get("snapshot_digest").?.string, w_repo.object.get("snapshot_digest").?.string) or
                !std.mem.eql(u8, decision.object.get("primary_fingerprint").?.string, signer) or
                decision.object.get("release_date_unix").?.integer != date_unix or
                dec_dl != deadline_unix)
            {
                return fail("{s} frozen witness {s} differs from its authenticated pocket", .{ suite, w_suite });
            }
            min_w_deadline = if (min_w_deadline) |m| @min(m, dec_dl) else dec_dl;
        }
        if (frozen.object.get("admission_deadline_unix").?.integer != min_w_deadline.?) {
            return fail("{s} frozen admission deadline differs from its witnesses", .{suite});
        }
    }

    var bound = std.StringHashMap(void).init(allocator);
    for (locks) |lock| {
        for (lock.object.get("repositories").?.array.items) |repository| {
            const rid = repository.object.get("id").?.string;
            const suite = by_id.get(rid) orelse
                return fail("{s} lock names a repository that refresh did not report", .{arch});
            const evidence = repositories.get(suite).?;
            const lock_rel = try lockDigest(allocator, repository.object.get("release_sha256").?.string, "sha256");
            const lock_snap = try lockDigest(allocator, repository.object.get("snapshot_sha256").?.string, "sha256");
            if (!jsonEql(repository.object.get("signer_fingerprints").?, evidence.object.get("signer_fingerprints").?) or
                !std.mem.eql(u8, lock_rel, evidence.object.get("release_digest").?.string) or
                !std.mem.eql(u8, lock_snap, evidence.object.get("snapshot_digest").?.string))
            {
                return fail("{s} exact lock differs from its authenticated refresh identity", .{suite});
            }
            try bound.put(suite, {});
        }
    }
    return bound;
}

pub var debz_run_override: ?*const fn (
    allocator: std.mem.Allocator,
    debz_self: *const Debz,
    operation: []const u8,
    extra: []const []const u8,
) RepinError!std.json.Value = null;

pub const Debz = struct {
    allocator: std.mem.Allocator,
    executable: []const u8,
    arch: []const u8,
    base: []const u8,
    common: [][]const u8,
    log_path: []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        executable: []const u8,
        workspace: []const u8,
        arch: []const u8,
        configs: []const []const u8,
        keyring: []const u8,
    ) !Debz {
        const base = try std.fs.path.join(allocator, &.{ workspace, arch });
        for ([_][]const u8{ "root", "cache", "state" }) |sub| {
            try cwdMakePath(try std.fs.path.join(allocator, &.{ base, sub }));
        }
        var common: std.ArrayList([]const u8) = .empty;
        try common.appendSlice(allocator, &.{
            "--install-root",
            try std.fs.path.join(allocator, &.{ base, "root" }),
            "--cache-path",
            try std.fs.path.join(allocator, &.{ base, "cache" }),
            "--state-path",
            try std.fs.path.join(allocator, &.{ base, "state" }),
            "--architecture",
            arch,
        });
        for (configs) |cfg| {
            try common.appendSlice(allocator, &.{ "--config", cfg });
        }
        try common.appendSlice(allocator, &.{
            "--keyring",
            keyring,
            "--deadline-ms",
            DEBZ_DEADLINE_MS,
            "--lock-wait-ms",
            DEBZ_LOCK_WAIT_MS,
            "--json",
        });
        return .{
            .allocator = allocator,
            .executable = executable,
            .arch = arch,
            .base = base,
            .common = try common.toOwnedSlice(allocator),
            .log_path = try std.fs.path.join(allocator, &.{ workspace, try std.fmt.allocPrint(allocator, "debz-{s}.jsonl", .{arch}) }),
        };
    }

    pub fn run(self: *const Debz, operation: []const u8, extra: []const []const u8) RepinError!std.json.Value {
        if (debz_run_override) |override_fn| {
            return override_fn(self.allocator, self, operation, extra);
        }
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(self.allocator, self.executable);
        try argv.append(self.allocator, operation);
        try argv.appendSlice(self.allocator, self.common);
        try argv.appendSlice(self.allocator, extra);

        const res = std.process.run(self.allocator, global_io, .{
            .argv = argv.items,
            .stdout_limit = .limited(maximum_release_bytes),
            .stderr_limit = .limited(maximum_release_bytes),
        }) catch |err| {
            return fail("debz {s} failed for {s}: {s}", .{ operation, self.arch, @errorName(err) });
        };
        const returncode: i64 = switch (res.term) {
            .exited => |code| @intCast(code),
            else => -1,
        };

        var log_arr = std.json.Array.init(self.allocator);
        try log_arr.append(.{ .string = operation });
        for (extra) |ex| try log_arr.append(.{ .string = ex });
        var log_obj: std.json.ObjectMap = .empty;
        try log_obj.put(self.allocator, "argv", .{ .array = log_arr });
        try log_obj.put(self.allocator, "exit", .{ .integer = returncode });
        const log_line = try std.fmt.allocPrint(self.allocator, "{f}\n", .{std.json.fmt(std.json.Value{ .object = log_obj }, .{})});
        const existing_log = cwdReadFileAlloc(self.allocator, self.log_path, maximum_release_bytes) catch "";
        const combined_log = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ existing_log, log_line });
        writeFileBytes(self.log_path, combined_log) catch {};

        const parsed_opt: ?std.json.Value = std.json.parseFromSliceLeaky(std.json.Value, self.allocator, res.stdout, .{}) catch null;
        var ok = (returncode == 0 and parsed_opt != null and parsed_opt.? == .object);
        if (ok) {
            const es = parsed_opt.?.object.get("exit_status") orelse .null;
            if (es != .integer or es.integer != 0) ok = false;
        }
        if (!ok) {
            const out_trim = std.mem.trim(u8, res.stdout, " \t\r\n");
            const err_trim = std.mem.trim(u8, res.stderr, " \t\r\n");
            const detail = if (out_trim.len > 0) out_trim else err_trim;
            const capped = detail[0..@min(detail.len, 2000)];
            return fail("debz {s} failed for {s} (exit {d}): {s}", .{ operation, self.arch, returncode, capped });
        }
        return parsed_opt.?;
    }

    pub fn refresh(self: *const Debz, suites: []const []const u8) RepinError!ManagedStringArrayHashMap(std.json.Value) {
        const doc = try self.run("refresh", &.{"--assume-yes"});
        const schema = doc.object.get("schema") orelse .null;
        const api_v = doc.object.get("api_version") orelse .null;
        const op = doc.object.get("operation") orelse .null;
        const es = doc.object.get("exit_status") orelse .null;
        const items = doc.object.get("items") orelse .null;
        if (schema != .string or !std.mem.eql(u8, schema.string, "io.github.cataggar.debz.command.v1") or
            api_v != .integer or api_v.integer != 1 or
            op != .string or !std.mem.eql(u8, op.string, "refresh") or
            es != .integer or es.integer != 0 or
            items != .array)
        {
            return fail("{s} refresh returned an unsupported command result", .{self.arch});
        }
        var repositories = ManagedStringArrayHashMap(std.json.Value).init(self.allocator);
        var unique_ids = std.StringHashMap(void).init(self.allocator);
        defer unique_ids.deinit();

        for (items.array.items) |item| {
            if (item != .object) return fail("{s} refresh reported an unexpected pocket", .{self.arch});
            const ver = item.object.get("version") orelse .null;
            const arch_v = item.object.get("architecture") orelse .null;
            if (ver != .string or !sliceContains(suites, ver.string) or arch_v != .null) {
                return fail("{s} refresh reported an unexpected pocket", .{self.arch});
            }
            const suite = ver.string;
            if (repositories.contains(suite)) {
                return fail("{s} refresh reported {s} twice", .{ self.arch, suite });
            }
            const detail_val = item.object.get("detail") orelse .null;
            const detail = if (detail_val == .string) detail_val.string else "";
            if (detail_val != .string or !std.mem.startsWith(u8, detail, "authenticated") or std.mem.indexOf(u8, detail, "stale") != null) {
                return fail("{s} refresh did not freshly authenticate {s}: {s}", .{ self.arch, suite, detail });
            }
            const rid_val = item.object.get("package") orelse .null;
            if (rid_val != .string or !isHex64(rid_val.string)) {
                return fail("{s} refresh has an invalid repository id", .{suite});
            }
            const ev = try validateRefreshRepository(self.allocator, item.object.get("repository") orelse .null, suite);
            var repo_entry = try cloneJsonValue(self.allocator, ev);
            try repo_entry.object.put(self.allocator, "id", .{ .string = rid_val.string });
            try repositories.put(suite, repo_entry);
            try unique_ids.put(rid_val.string, {});
        }
        if (repositories.count() != suites.len) {
            return fail("{s} refresh did not authenticate every pocket", .{self.arch});
        }
        if (unique_ids.count() != repositories.count()) {
            return fail("{s} refresh reported duplicate repository ids", .{self.arch});
        }
        return repositories;
    }

    pub fn plan(self: *const Debz, package: []const u8, lock_path: []const u8) RepinError!std.json.Value {
        _ = try self.run("plan", &.{ "--transaction-backend", "native", "--lock-output", lock_path, package });
        return loadJson(self.allocator, lock_path);
    }

    pub fn download(self: *const Debz, package: []const u8, lock_path: []const u8) RepinError!void {
        _ = try self.run("download", &.{ "--transaction-backend", "native", "--lock-input", lock_path, package });
    }

    pub fn archive(self: *const Debz, package: std.json.Value) RepinError![]u8 {
        const pkg_name = package.object.get("name").?.string;
        const pkg_ver = package.object.get("version").?.string;
        const identity = package.object.get("archive_identity").?.object;
        const primary = identity.get("primary") orelse .null;
        if (primary != .string or !std.mem.eql(u8, primary.string, "sha512")) {
            return fail("{s} {s} has no SHA-512 archive identity", .{ pkg_name, pkg_ver });
        }
        var found: ?[]const u8 = null;
        var count: usize = 0;
        for (identity.get("digests").?.array.items) |d| {
            if (std.mem.eql(u8, d.object.get("algorithm").?.string, "sha512")) {
                found = d.object.get("digest").?.string;
                count += 1;
            }
        }
        if (count != 1) {
            return fail("{s} has an ambiguous SHA-512 archive identity", .{pkg_name});
        }
        const obj_path = try std.fs.path.join(self.allocator, &.{
            self.base,
            "cache",
            "packages-v2",
            "objects",
            try std.fmt.allocPrint(self.allocator, "sha512-{s}", .{found.?}),
        });
        const data = try readFileBounded(self.allocator, obj_path, maximum_archive_bytes, pkg_name);
        const actual_hex = sha512HexLower(data);
        if (@as(i64, @intCast(data.len)) != package.object.get("declared_size").?.integer or
            !std.mem.eql(u8, &actual_hex, found.?))
        {
            return fail("verified CAS object for {s} no longer matches its lock", .{pkg_name});
        }
        return data;
    }
};

pub fn retainSourceMetadata(
    allocator: std.mem.Allocator,
    profile: std.json.Value,
    timestamp: []const u8,
    first: std.StringHashMap([]const u8),
    packages: *ManagedStringArrayHashMap(PackageSummary),
    locks: []const std.json.Value,
    arch: []const u8,
    workspace: []const u8,
    identities: []const std.json.Value,
) RepinError!std.json.Value {
    var wanted_map = std.StringHashMap(void).init(allocator);
    defer wanted_map.deinit();
    for (identities) |identity| {
        for (identity.object.get("architectures").?.array.items) |a| {
            if (std.mem.eql(u8, a.string, arch)) {
                try wanted_map.put(identity.object.get("package").?.string, {});
            }
        }
    }
    const wanted = try allocator.alloc([]const u8, wanted_map.count());
    var w_idx: usize = 0;
    var w_it = wanted_map.keyIterator();
    while (w_it.next()) |k| : (w_idx += 1) wanted[w_idx] = k.*;
    std.mem.sort([]const u8, wanted, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);

    var sources: std.json.ObjectMap = .empty;
    var indexes = std.StringHashMap([]const u8).init(allocator);
    defer indexes.deinit();
    const comp = profile.object.get("component").?.string;
    const uri = try snapshotUri(allocator, profile, timestamp);

    for (wanted) |name| {
        const pkg_ptr = packages.getPtr(name) orelse continue;
        const entry = pkg_ptr.lock_package.?;
        const repository_id = entry.object.get("origin").?.object.get("repository_id").?.string;
        var repository: ?std.json.Value = null;
        outer: for (locks) |lock| {
            for (lock.object.get("repositories").?.array.items) |r| {
                if (std.mem.eql(u8, r.object.get("id").?.string, repository_id)) {
                    repository = r;
                    break :outer;
                }
            }
        }
        const index_identity = repository.?.object.get("index_identity").?.object;
        const algorithm = index_identity.get("primary").?.string;
        if (!std.mem.eql(u8, algorithm, "sha256") and !std.mem.eql(u8, algorithm, "sha512")) {
            return fail("source index needs a signed SHA-256 or SHA-512 identity", .{});
        }
        var found_dig: ?[]const u8 = null;
        var dig_count: usize = 0;
        for (index_identity.get("digests").?.array.items) |d| {
            if (std.mem.eql(u8, d.object.get("algorithm").?.string, algorithm)) {
                found_dig = d.object.get("digest").?.string;
                dig_count += 1;
            }
        }
        if (dig_count != 1) {
            return fail("source index has an ambiguous signed identity", .{});
        }
        const suite = pkg_ptr.pocket.?;
        const release = first.get(suite).?;
        const checksums = try releaseIndexEntries(allocator, release, algorithm);
        const stem = try std.fmt.allocPrint(allocator, "{s}/binary-{s}/Packages", .{ comp, arch });
        var matched_path: ?[]const u8 = null;
        var match_count: usize = 0;
        for (checksums.keys()) |c_path| {
            const c_val = checksums.get(c_path).?;
            if ((std.mem.eql(u8, c_path, stem) or
                std.mem.eql(u8, c_path, try std.fmt.allocPrint(allocator, "{s}.xz", .{stem})) or
                std.mem.eql(u8, c_path, try std.fmt.allocPrint(allocator, "{s}.gz", .{stem})) or
                std.mem.eql(u8, c_path, try std.fmt.allocPrint(allocator, "{s}.zst", .{stem}))) and
                std.mem.eql(u8, c_val.digest, found_dig.?))
            {
                matched_path = c_path;
                match_count += 1;
            }
        }
        if (match_count != 1) {
            return fail("source Release has no unique authenticated Packages index for {s}", .{name});
        }
        const index_path = matched_path.?;
        const base_idx = std.fs.path.basename(index_path);
        const rel_idx = try std.fmt.allocPrint(allocator, "indexes/{s}-{s}-{s}", .{ arch, suite, base_idx });
        const rel_release = try std.fmt.allocPrint(allocator, "releases/{s}.InRelease", .{suite});

        if (!indexes.contains(suite)) {
            const idx_url = try std.fmt.allocPrint(allocator, "{s}/dists/{s}/{s}", .{ uri, suite, index_path });
            const index_bytes = try fetch(allocator, idx_url);
            const expected_cs = checksums.get(index_path).?;
            const actual_hex: []const u8 = if (std.mem.eql(u8, algorithm, "sha256"))
                try allocator.dupe(u8, &sha256HexLower(index_bytes))
            else
                try allocator.dupe(u8, &sha512HexLower(index_bytes));
            if (@as(i64, @intCast(index_bytes.len)) != expected_cs.size or !std.mem.eql(u8, actual_hex, expected_cs.digest)) {
                return fail("source Packages index for {s} differs from its authenticated Release", .{suite});
            }
            try indexes.put(suite, index_bytes);
            try writeFileBytes(try std.fs.path.join(allocator, &.{ workspace, rel_idx }), index_bytes);
            try writeFileBytes(try std.fs.path.join(allocator, &.{ workspace, rel_release }), release);
        }
        const fields = try sourceIndexPackage(allocator, indexes.get(suite).?, index_path, entry);
        var art_obj: std.json.ObjectMap = .empty;
        try art_obj.put(allocator, "filename", .{ .string = fields.get("filename").? });
        try art_obj.put(allocator, "architecture", .{ .string = fields.get("architecture").? });
        pkg_ptr.artifact = .{ .object = art_obj };

        var src_meta: std.json.ObjectMap = .empty;
        try src_meta.put(allocator, "index_file", .{ .string = rel_idx });
        try src_meta.put(allocator, "index_path", .{ .string = index_path });
        try src_meta.put(allocator, "release_file", .{ .string = rel_release });
        try sources.put(allocator, name, .{ .object = src_meta });
    }
    return .{ .object = sources };
}

pub fn observeIdentity(
    allocator: std.mem.Allocator,
    identity: std.json.Value,
    arch: []const u8,
    packages: ManagedStringArrayHashMap(PackageSummary),
    debz_runner: *const Debz,
    members_dir: []const u8,
) RepinError!std.json.Value {
    const pkg_name = identity.object.get("package").?.string;
    const entry = packages.get(pkg_name) orelse return .null;
    var observed: std.json.ObjectMap = .empty;
    try observed.put(allocator, "version", .{ .string = entry.version });
    try observed.put(allocator, "archive", .{ .string = entry.archive.? });
    var derived_versions: std.json.ObjectMap = .empty;

    if (entry.artifact) |art| {
        try observed.put(allocator, "artifact", art);
    }
    const kind = identity.object.get("kind").?.string;
    if (std.mem.eql(u8, kind, "archive")) {
        try observed.put(allocator, "derived_versions", .{ .object = derived_versions });
        try observed.put(allocator, "digest", .{ .string = entry.archive.? });
        try observed.put(allocator, "size", .{ .integer = entry.size });
        try observed.put(allocator, "mode", .null);
        return .{ .object = observed };
    }
    if (std.mem.eql(u8, kind, "prestate")) {
        for (identity.object.get("derived_from").?.array.items) |item| {
            const dep_pkg = item.object.get("package").?.string;
            if (packages.get(dep_pkg)) |dep_entry| {
                try derived_versions.put(allocator, dep_pkg, .{ .string = dep_entry.version });
            } else {
                try derived_versions.put(allocator, dep_pkg, .null);
            }
        }
        try observed.put(allocator, "derived_versions", .{ .object = derived_versions });
        if ((try prestateDerivation(allocator, identity, arch)) != null) {
            const deb_bytes = try debz_runner.archive(entry.lock_package.?);
            const derived = (try derivePrestate(allocator, identity, arch, deb_bytes)).?;
            try observed.put(allocator, "digest", .{ .string = try tagged(allocator, "sha256", derived.bytes) });
            try observed.put(allocator, "size", .{ .integer = @intCast(derived.bytes.len) });
            try observed.put(allocator, "mode", .{ .string = try std.fmt.allocPrint(allocator, "0{o:0>3}", .{derived.mode}) });
            return .{ .object = observed };
        }
        try observed.put(allocator, "digest", .null);
        try observed.put(allocator, "size", .null);
        try observed.put(allocator, "mode", .null);
        return .{ .object = observed };
    }

    try observed.put(allocator, "derived_versions", .{ .object = derived_versions });
    const deb_bytes = try debz_runner.archive(entry.lock_package.?);
    const prefix = if (std.mem.eql(u8, kind, "script")) "control.tar" else "data.tar";
    const member = try tarMember(allocator, deb_bytes, prefix, identity.object.get("path").?.string);

    const id_str = identity.object.get("id").?.string;
    var sanitized = try allocator.alloc(u8, id_str.len);
    for (id_str, 0..) |c, i| {
        sanitized[i] = if (std.ascii.isAlphanumeric(c) or c == '+' or c == '.' or c == '-') c else '_';
    }
    const member_name = try std.fmt.allocPrint(allocator, "{s}@{s}", .{ sanitized, arch });
    try writeFileBytes(try std.fs.path.join(allocator, &.{ members_dir, member_name }), member.bytes);

    try observed.put(allocator, "digest", .{ .string = try tagged(allocator, "sha256", member.bytes) });
    try observed.put(allocator, "size", .{ .integer = @intCast(member.bytes.len) });
    const mode_str = if (member.mode >= 0o1000)
        try std.fmt.allocPrint(allocator, "0{o}", .{member.mode})
    else
        try std.fmt.allocPrint(allocator, "0{o:0>3}", .{member.mode});
    try observed.put(allocator, "mode", .{ .string = mode_str });
    try observed.put(allocator, "member_file", .{ .string = try std.fmt.allocPrint(allocator, "members/{s}", .{member_name}) });
    return .{ .object = observed };
}

pub fn unboundPockets(allocator: std.mem.Allocator, pockets: []const std.json.Value) ![][]const u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    for (pockets) |pocket| {
        const binding = pocket.object.get("binding").?.object;
        var archs: std.ArrayList([]const u8) = .empty;
        var it = binding.iterator();
        while (it.next()) |kv| {
            if (std.mem.eql(u8, kv.value_ptr.*.string, "refresh_only")) {
                try archs.append(allocator, kv.key_ptr.*);
            }
        }
        if (archs.items.len > 0) {
            const role_str = pocket.object.get("role").?.string;
            const role = if (std.mem.eql(u8, role_str, "witness"))
                "witness of the frozen pocket"
            else
                try std.fmt.allocPrint(allocator, "{s} pocket", .{role_str});
            try lines.append(
                allocator,
                try std.fmt.allocPrint(allocator, "- `{s}` ({s}) on {s}", .{
                    pocket.object.get("suite").?.string,
                    role,
                    try std.mem.join(allocator, ", ", archs.items),
                }),
            );
        }
    }
    return lines.toOwnedSlice(allocator);
}

pub fn reportSummary(allocator: std.mem.Allocator, report: std.json.Value) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var w = arrayListWriter(&out, allocator);
    const series_name = report.object.get("series").?.object.get("name").?.string;
    const ts = report.object.get("timestamp").?.string;
    const uri = report.object.get("uri").?.string;
    const deadline = report.object.get("admission_deadline").?.integer;
    const human_dl = try formatUtcTimestampHuman(allocator, deadline);
    const debz_sha = report.object.get("debz_sha256").?.string;

    try w.print(
        "## Real-snapshot probe: `{s}` at `{s}`\n\n" ++
            "- URI: `{s}`\n" ++
            "- Admission deadline: {d} ({s})\n" ++
            "- debz: `{s}`\n\n" ++
            "| Pocket | Role | Date | Valid-Until | Hash fields | Release (cleartext) | Deadline | Binding |\n" ++
            "|---|---|---|---|---|---|---|---|\n",
        .{ series_name, ts, uri, deadline, human_dl, debz_sha },
    );
    const pockets = report.object.get("pockets").?.array.items;
    for (pockets) |pocket| {
        const p_obj = pocket.object;
        var bind_parts: std.ArrayList([]const u8) = .empty;
        var b_it = p_obj.get("binding").?.object.iterator();
        while (b_it.next()) |kv| {
            try bind_parts.append(allocator, try std.fmt.allocPrint(allocator, "{s}: {s}", .{ kv.key_ptr.*, kv.value_ptr.*.string }));
        }
        var hf_parts: std.ArrayList([]const u8) = .empty;
        for (p_obj.get("hash_fields").?.array.items) |hf| {
            try hf_parts.append(allocator, hf.string);
        }
        const vu_val = p_obj.get("valid_until") orelse .null;
        const vu_str = if (vu_val == .string and vu_val.string.len > 0) vu_val.string else "none";
        try w.print(
            "| `{s}` | {s} | {s} | {s} | {s} | `{s}` | {d} | {s} |\n",
            .{
                p_obj.get("suite").?.string,
                p_obj.get("role").?.string,
                p_obj.get("date").?.string,
                vu_str,
                try std.mem.join(allocator, ", ", hf_parts.items),
                p_obj.get("release_sha256").?.string,
                p_obj.get("deadline").?.integer,
                try std.mem.join(allocator, ", ", bind_parts.items),
            },
        );
    }
    try w.writeAll("\n| Architecture | Packages | Pockets | Closure digest |\n|---|---|---|---|\n");
    var c_it = report.object.get("closures").?.object.iterator();
    while (c_it.next()) |kv| {
        const arch = kv.key_ptr.*;
        const closure = kv.value_ptr.*.object;
        var p_parts: std.ArrayList([]const u8) = .empty;
        var p_it = closure.get("pockets").?.object.iterator();
        while (p_it.next()) |pkv| {
            try p_parts.append(allocator, try std.fmt.allocPrint(allocator, "{s}: {d}", .{ pkv.key_ptr.*, pkv.value_ptr.*.integer }));
        }
        try w.print(
            "| {s} | {d} | {s} | `{s}` |\n",
            .{
                arch,
                closure.get("package_count").?.integer,
                try std.mem.join(allocator, ", ", p_parts.items),
                closure.get("digest").?.string,
            },
        );
    }
    const unbound = try unboundPockets(allocator, pockets);
    if (unbound.len > 0) {
        try w.writeAll(
            "\nPockets that contribute no locked package. `debz refresh` authenticated them, but debz emits " ++
                "no Release digest for a repository outside an exact lock, so their fetched Release is recorded " ++
                "without that cross-check:\n\n",
        );
        for (unbound) |line| {
            try w.print("{s}\n", .{line});
        }
    }
    var quiet: std.ArrayList([]const u8) = .empty;
    for (pockets) |p| {
        const p_obj = p.object;
        var q_archs: std.ArrayList([]const u8) = .empty;
        var b_it = p_obj.get("binding").?.object.iterator();
        while (b_it.next()) |kv| {
            if (std.mem.eql(u8, kv.value_ptr.*.string, "refresh_identity")) {
                try q_archs.append(allocator, kv.key_ptr.*);
            }
        }
        if (q_archs.items.len > 0) {
            try quiet.append(
                allocator,
                try std.fmt.allocPrint(allocator, "- `{s}` on {s}", .{
                    p_obj.get("suite").?.string,
                    try std.mem.join(allocator, ", ", q_archs.items),
                }),
            );
        }
    }
    if (quiet.items.len > 0) {
        try w.writeAll(
            "\nPockets that contribute no locked package. Their fetched Release is bound to " ++
                "`debz refresh` repository evidence (no fabricated lock contribution):\n\n",
        );
        for (quiet.items) |line| {
            try w.print("{s}\n", .{line});
        }
    }
    return out.toOwnedSlice(allocator);
}

pub const ProbeArgs = struct {
    series: []const u8,
    timestamp: ?[]const u8 = null,
    debz_path: []const u8,
    manifest: []const u8 = DEFAULT_MANIFEST,
    profile: ?[]const u8 = null,
    workspace: ?[]const u8 = null,
    accept_frozen_release: bool = false,
};

pub fn probe(allocator: std.mem.Allocator, args: ProbeArgs, now_opt: ?i64) anyerror!u8 {
    const now = now_opt orelse nowSeconds();
    const manifest_exists = blk: {
        _ = statFileFollow(args.manifest) catch break :blk false;
        break :blk true;
    };
    const manifest: ?std.json.Value = if (manifest_exists)
        try validateManifest(allocator, try loadJson(allocator, args.manifest))
    else
        null;
    const profile = try resolveProfile(allocator, args.series, args.profile);
    const timestamp = args.timestamp orelse try defaultTimestamp(allocator, now);
    const snapshot_seconds = try validateTimestamp(timestamp, now, pinnedTimestamp(manifest, profile.object.get("name").?.string));

    const debz_stat = statFileFollow(args.debz_path) catch {
        return fail("--debz {s} is not an executable file", .{args.debz_path});
    };
    if (debz_stat.kind != .file or (debz_stat.mode & 0o111) == 0) {
        return fail("--debz {s} is not an executable file", .{args.debz_path});
    }
    const debz_real = cwdRealpathAlloc(allocator, args.debz_path) catch {
        return fail("--debz {s} is not an executable file", .{args.debz_path});
    };

    const workspace = args.workspace orelse try std.fs.path.join(allocator, &.{ ".tmp", "real-snapshot-repin", timestamp });
    if (statFileFollow(workspace)) |_| {
        return fail("workspace {s} already exists; probes start from a fresh workspace", .{workspace});
    } else |_| {}

    const uri = try snapshotUri(allocator, profile, timestamp);
    var first = std.StringHashMap([]const u8).init(allocator);
    var pockets = ManagedStringArrayHashMap(std.json.Value).init(allocator);
    var suites_list: std.ArrayList([]const u8) = .empty;

    for (profile.object.get("pockets").?.array.items) |p_spec| {
        const suite = p_spec.object.get("suite").?.string;
        const role = p_spec.object.get("role").?.string;
        try suites_list.append(allocator, suite);
        const inrel_url = try std.fmt.allocPrint(allocator, "{s}/dists/{s}/InRelease", .{ uri, suite });
        const data = try fetch(allocator, inrel_url);
        try first.put(suite, data);
        const cleartext = try inReleaseCleartext(allocator, data);
        const fields = try releaseFields(allocator, cleartext);
        const match_suite = (fields.suite != null and std.mem.eql(u8, fields.suite.?, suite)) or
            (fields.codename != null and std.mem.eql(u8, fields.codename.?, suite));
        if (!match_suite) {
            return fail("{s} Release names suite {s}", .{ suite, fields.suite orelse "None" });
        }
        var p_obj: std.json.ObjectMap = .empty;
        try p_obj.put(allocator, "suite", .{ .string = suite });
        try p_obj.put(allocator, "role", .{ .string = role });
        try p_obj.put(allocator, "date", .{ .string = fields.date });
        try p_obj.put(allocator, "date_unix", .{ .integer = fields.date_unix });
        try p_obj.put(allocator, "valid_until", if (fields.valid_until) |vu| .{ .string = vu } else .null);
        try p_obj.put(allocator, "valid_until_unix", if (fields.valid_until_unix) |vuu| .{ .integer = vuu } else .null);
        var hf_arr = std.json.Array.init(allocator);
        for (fields.hash_fields) |hf| try hf_arr.append(.{ .string = hf });
        try p_obj.put(allocator, "hash_fields", .{ .array = hf_arr });
        try p_obj.put(allocator, "in_release_sha256", .{ .string = try tagged(allocator, "sha256", data) });
        try p_obj.put(allocator, "in_release_sha512", .{ .string = try tagged(allocator, "sha512", data) });
        try p_obj.put(allocator, "release_sha256", .{ .string = try tagged(allocator, "sha256", cleartext) });
        var signers_arr = std.json.Array.init(allocator);
        try signers_arr.append(.{ .string = profile.object.get("signer").?.string });
        try p_obj.put(allocator, "signers", .{ .array = signers_arr });
        try p_obj.put(allocator, "binding", .{ .object = std.json.ObjectMap.empty });
        try pockets.put(suite, .{ .object = p_obj });
    }

    var frozen: ?std.json.Value = null;
    for (pockets.values()) |pv| {
        if (std.mem.eql(u8, pv.object.get("role").?.string, "frozen")) {
            frozen = pv;
            break;
        }
    }
    var frozen_change = false;
    if (frozen) |fp| {
        const pinned: ?std.json.Value = if (manifest != null and
            std.mem.eql(u8, manifest.?.object.get("series").?.object.get("name").?.string, profile.object.get("name").?.string))
            frozenPocket(manifest.?.object.get("snapshot").?)
        else
            null;
        if (pinned == null or !std.mem.eql(u8, pinned.?.object.get("release_sha256").?.string, fp.object.get("release_sha256").?.string)) {
            frozen_change = true;
            if (!args.accept_frozen_release) {
                return fail(
                    "frozen pocket {s} Release {s} differs from the reviewed manifest value; review the Release delta and pass --accept-frozen-release",
                    .{ fp.object.get("suite").?.string, fp.object.get("release_sha256").?.string },
                );
            }
        }
    }

    cwdMakePath(workspace) catch |err| return fail("cannot create workspace: {s}", .{@errorName(err)});
    const members_dir = try std.fs.path.join(allocator, &.{ workspace, "members" });
    cwdMakePath(members_dir) catch |err| return fail("cannot create members dir: {s}", .{@errorName(err)});
    const locks_dir = try std.fs.path.join(allocator, &.{ workspace, "locks" });
    cwdMakePath(locks_dir) catch |err| return fail("cannot create locks dir: {s}", .{@errorName(err)});

    var closures: std.json.ObjectMap = .empty;
    var identities: std.json.ObjectMap = .empty;
    var repository_ids: std.json.ObjectMap = .empty;
    var repository_evidence: std.json.ObjectMap = .empty;
    var unavailable: std.json.ObjectMap = .empty;
    var artifact_sources: std.json.ObjectMap = .empty;
    const manifest_identities = if (manifest) |m| m.object.get("identities").?.array.items else &[_]std.json.Value{};

    for (profile.object.get("architectures").?.array.items) |arch_val| {
        const arch = arch_val.string;
        const cfg_dir = try std.fs.path.join(allocator, &.{ workspace, "config", arch });
        const configs = try writeConfigs(
            allocator,
            cfg_dir,
            profile,
            timestamp,
            arch,
            if (frozen) |fp| fp.object.get("release_sha256").?.string else null,
        );
        const debz_runner = try Debz.init(allocator, debz_real, workspace, arch, configs, profile.object.get("keyring").?.string);
        const refreshed = try debz_runner.refresh(suites_list.items);
        _ = try bindPockets(allocator, pockets, &.{}, refreshed, profile.object.get("signer").?.string, arch);

        var refresh_ids_obj: std.json.ObjectMap = .empty;
        var refresh_ev_obj: std.json.ObjectMap = .empty;
        var by_id = std.StringHashMap([]const u8).init(allocator);
        for (refreshed.keys()) |suite| {
            const val = refreshed.get(suite).?;
            const rid = val.object.get("id").?.string;
            try refresh_ids_obj.put(allocator, suite, .{ .string = rid });
            try refresh_ev_obj.put(allocator, suite, val);
            try by_id.put(rid, suite);
        }
        try repository_ids.put(allocator, arch, .{ .object = refresh_ids_obj });
        try repository_evidence.put(allocator, arch, .{ .object = refresh_ev_obj });

        const closure_lock_path = try std.fs.path.join(allocator, &.{ locks_dir, try std.fmt.allocPrint(allocator, "{s}.lock.json", .{arch}) });
        const req = profile.object.get("request").?.string;
        const closure_lock = try debz_runner.plan(req, closure_lock_path);
        try debz_runner.download(req, closure_lock_path);

        var locks: std.ArrayList(std.json.Value) = .empty;
        try locks.append(allocator, closure_lock);

        var packages = try lockPackages(allocator, closure_lock, by_id);
        var lock_entries = std.StringHashMap(std.json.Value).init(allocator);
        for (closure_lock.object.get("packages").?.array.items) |pkg| {
            try lock_entries.put(pkg.object.get("name").?.string, pkg);
        }
        try requireSha512(allocator, packages, arch);

        var closure_packages = ManagedStringArrayHashMap(PackageSummary).init(allocator);
        for (packages.keys()) |k| {
            try closure_packages.put(k, packages.get(k).?);
        }

        for (manifest_identities) |identity| {
            var has_arch = false;
            for (identity.object.get("architectures").?.array.items) |a| {
                if (std.mem.eql(u8, a.string, arch)) has_arch = true;
            }
            if (!has_arch) continue;

            var names: std.ArrayList([]const u8) = .empty;
            try names.append(allocator, identity.object.get("package").?.string);
            if (identity.object.get("derived_from")) |df| {
                for (df.array.items) |item| {
                    try names.append(allocator, item.object.get("package").?.string);
                }
            }
            for (names.items) |name| {
                if (packages.contains(name)) continue;
                const lock_path = try std.fs.path.join(allocator, &.{ locks_dir, try std.fmt.allocPrint(allocator, "{s}-{s}.lock.json", .{ arch, name }) });
                const extra = debz_runner.plan(name, lock_path) catch |err| switch (err) {
                    error.RepinFailed => {
                        if (!unavailable.contains(arch)) {
                            try unavailable.put(allocator, arch, .{ .object = std.json.ObjectMap.empty });
                        }
                        const msg = lastErrorMessage();
                        try unavailable.getPtr(arch).?.object.put(allocator, name, .{ .string = try allocator.dupe(u8, msg[0..@min(msg.len, 500)]) });
                        continue;
                    },
                    else => return err,
                };
                try debz_runner.download(name, lock_path);
                try locks.append(allocator, extra);
                const extra_packages = try lockPackages(allocator, extra, by_id);
                try requireSha512(allocator, extra_packages, arch);
                for (extra.object.get("packages").?.array.items) |pkg| {
                    const pn = pkg.object.get("name").?.string;
                    if (!lock_entries.contains(pn)) try lock_entries.put(pn, pkg);
                }
                for (extra_packages.keys()) |pn| {
                    if (!packages.contains(pn)) {
                        try packages.put(pn, extra_packages.get(pn).?);
                    }
                }
            }
        }

        const bound = try bindPockets(allocator, pockets, locks.items, refreshed, profile.object.get("signer").?.string, arch);
        for (pockets.keys()) |suite| {
            const p_ptr = pockets.getPtr(suite).?;
            try p_ptr.object.getPtr("binding").?.object.put(
                allocator,
                arch,
                .{ .string = if (bound.contains(suite)) "exact_lock" else "refresh_identity" },
            );
        }
        for (packages.keys()) |name| {
            const p_ptr = packages.getPtr(name).?;
            p_ptr.lock_package = lock_entries.get(name);
        }

        const ev_ids = if (manifest) |m| try sourceEvidenceIdentities(allocator, m) else &[_]std.json.Value{};
        try artifact_sources.put(
            allocator,
            arch,
            try retainSourceMetadata(allocator, profile, timestamp, first, &packages, locks.items, arch, workspace, ev_ids),
        );

        for (manifest_identities) |identity| {
            var has_arch = false;
            for (identity.object.get("architectures").?.array.items) |a| {
                if (std.mem.eql(u8, a.string, arch)) has_arch = true;
            }
            if (has_arch) {
                const id_str = identity.object.get("id").?.string;
                if (!identities.contains(id_str)) {
                    try identities.put(allocator, id_str, .{ .object = std.json.ObjectMap.empty });
                }
                const obs = try observeIdentity(allocator, identity, arch, packages, &debz_runner, members_dir);
                try identities.getPtr(id_str).?.object.put(allocator, arch, obs);
            }
        }

        var counts = std.StringHashMap(i64).init(allocator);
        for (closure_packages.values()) |entry| {
            const p_suite = entry.pocket.?;
            try counts.put(p_suite, (counts.get(p_suite) orelse 0) + 1);
        }
        const sorted_count_keys = try allocator.alloc([]const u8, counts.count());
        var ck_idx: usize = 0;
        var ck_it = counts.keyIterator();
        while (ck_it.next()) |k| : (ck_idx += 1) sorted_count_keys[ck_idx] = k.*;
        std.mem.sort([]const u8, sorted_count_keys, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        var counts_obj: std.json.ObjectMap = .empty;
        for (sorted_count_keys) |ck| {
            try counts_obj.put(allocator, ck, .{ .integer = counts.get(ck).? });
        }

        const sorted_pkg_names = try allocator.alloc([]const u8, closure_packages.count());
        for (closure_packages.keys(), 0..) |k, i| sorted_pkg_names[i] = k;
        std.mem.sort([]const u8, sorted_pkg_names, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        var pkgs_obj: std.json.ObjectMap = .empty;
        for (sorted_pkg_names) |pn| {
            const entry = closure_packages.get(pn).?;
            var po: std.json.ObjectMap = .empty;
            try po.put(allocator, "version", .{ .string = entry.version });
            try po.put(allocator, "architecture", .{ .string = entry.architecture });
            try po.put(allocator, "archive", if (entry.archive) |a| .{ .string = a } else .null);
            try po.put(allocator, "pocket", if (entry.pocket) |p| .{ .string = p } else .null);
            try pkgs_obj.put(allocator, pn, .{ .object = po });
        }

        const lock_raw = try readFileBounded(allocator, closure_lock_path, maximum_release_bytes, closure_lock_path);
        var c_entry: std.json.ObjectMap = .empty;
        try c_entry.put(allocator, "lock", .{ .string = try std.fmt.allocPrint(allocator, "locks/{s}.lock.json", .{arch}) });
        try c_entry.put(allocator, "lock_sha256", .{ .string = try tagged(allocator, "sha256", lock_raw) });
        try c_entry.put(allocator, "digest", .{ .string = try closureDigest(allocator, closure_packages) });
        try c_entry.put(allocator, "package_count", .{ .integer = @intCast(closure_packages.count()) });
        try c_entry.put(allocator, "pockets", .{ .object = counts_obj });
        try c_entry.put(allocator, "packages", .{ .object = pkgs_obj });
        try closures.put(allocator, arch, .{ .object = c_entry });
    }

    for (suites_list.items) |suite| {
        const inrel_url = try std.fmt.allocPrint(allocator, "{s}/dists/{s}/InRelease", .{ uri, suite });
        const second_data = try fetch(allocator, inrel_url);
        if (!std.mem.eql(u8, second_data, first.get(suite).?)) {
            return fail("{s} InRelease changed between the first and second fetch; the snapshot is not settled", .{suite});
        }
    }

    var ordered = try allocator.alloc(std.json.Value, suites_list.items.len);
    for (suites_list.items, 0..) |suite, i| {
        ordered[i] = pockets.get(suite).?;
    }
    const deadline = try checkPocketDates(allocator, ordered, snapshot_seconds);
    var ordered_arr = std.json.Array.init(allocator);
    for (ordered) |o| try ordered_arr.append(o);

    const debz_bytes = try readFileBounded(allocator, debz_real, maximum_archive_bytes, debz_real);
    var report: std.json.ObjectMap = .empty;
    try report.put(allocator, "schema", .{ .string = REPORT_SCHEMA });
    try report.put(allocator, "series", profile);
    try report.put(allocator, "timestamp", .{ .string = timestamp });
    try report.put(allocator, "uri", .{ .string = uri });
    try report.put(allocator, "probed_at", .{ .integer = now });
    try report.put(allocator, "debz_sha256", .{ .string = try tagged(allocator, "sha256", debz_bytes) });
    try report.put(allocator, "frozen_release_change", .{ .bool = frozen_change });
    try report.put(allocator, "pockets", .{ .array = ordered_arr });
    try report.put(allocator, "repository_ids", .{ .object = repository_ids });
    try report.put(allocator, "repository_evidence", .{ .object = repository_evidence });
    try report.put(allocator, "admission_deadline", .{ .integer = deadline });
    try report.put(allocator, "closures", .{ .object = closures });
    try report.put(allocator, "unavailable", .{ .object = unavailable });
    try report.put(allocator, "identities", .{ .object = identities });
    try report.put(allocator, "artifact_sources", .{ .object = artifact_sources });

    const report_val = std.json.Value{ .object = report };
    const report_path = try std.fs.path.join(allocator, &.{ workspace, "report.json" });
    try writeJson(allocator, report_path, report_val);
    const summary_path = try std.fs.path.join(allocator, &.{ workspace, "summary.md" });
    try writeFileBytes(summary_path, try reportSummary(allocator, report_val));

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(global_io, &stdout_buf);
    try stdout_writer.interface.print("probe passed: {s}\n", .{report_path});
    try stdout_writer.interface.flush();
    return 0;
}

// Diff, Record, and CLI Main.

pub fn validateReportPocketEvidence(allocator: std.mem.Allocator, report: std.json.Value) RepinError!void {
    const has_repo_ev = report.object.contains("repository_evidence");
    var any_refresh_id = false;
    for (report.object.get("pockets").?.array.items) |p| {
        var b_it = p.object.get("binding").?.object.iterator();
        while (b_it.next()) |kv| {
            if (std.mem.eql(u8, kv.value_ptr.*.string, "refresh_identity")) {
                any_refresh_id = true;
            }
        }
    }
    if (!has_repo_ev and !any_refresh_id) return;

    const evidence = report.object.get("repository_evidence") orelse
        return fail("report repository evidence must cover every architecture", .{});
    const archs = report.object.get("series").?.object.get("architectures").?.array.items;
    if (evidence != .object or evidence.object.count() != archs.len) {
        return fail("report repository evidence must cover every architecture", .{});
    }
    for (archs) |a| {
        if (!evidence.object.contains(a.string)) {
            return fail("report repository evidence must cover every architecture", .{});
        }
    }
    var pockets = ManagedStringArrayHashMap(std.json.Value).init(allocator);
    for (report.object.get("pockets").?.array.items) |p| {
        try pockets.put(p.object.get("suite").?.string, p);
    }
    var ev_it = evidence.object.iterator();
    while (ev_it.next()) |kv| {
        const arch = kv.key_ptr.*;
        const repos_val = kv.value_ptr.*;
        if (repos_val != .object) {
            return fail("{s} report repository evidence must be an object", .{arch});
        }
        var repos_map = ManagedStringArrayHashMap(std.json.Value).init(allocator);
        var r_it = repos_val.object.iterator();
        while (r_it.next()) |rkv| {
            try repos_map.put(rkv.key_ptr.*, rkv.value_ptr.*);
        }
        _ = try bindPockets(allocator, pockets, &.{}, repos_map, report.object.get("series").?.object.get("signer").?.string, arch);

        const rep_ids_val = report.object.get("repository_ids") orelse
            return fail("{s} report repository ids differ from authenticated evidence", .{arch});
        if (rep_ids_val != .object) {
            return fail("{s} report repository ids differ from authenticated evidence", .{arch});
        }
        const arch_ids = rep_ids_val.object.get(arch) orelse
            return fail("{s} report repository ids differ from authenticated evidence", .{arch});
        if (arch_ids != .object or arch_ids.object.count() != repos_map.count()) {
            return fail("{s} report repository ids differ from authenticated evidence", .{arch});
        }
        for (repos_map.keys()) |s| {
            const want_id = repos_map.get(s).?.object.get("id").?.string;
            const got_id = arch_ids.object.get(s) orelse
                return fail("{s} report repository ids differ from authenticated evidence", .{arch});
            if (got_id != .string or !std.mem.eql(u8, got_id.string, want_id)) {
                return fail("{s} report repository ids differ from authenticated evidence", .{arch});
            }
        }
    }
}

pub fn loadReport(allocator: std.mem.Allocator, path: []const u8) RepinError!std.json.Value {
    const report = try loadJson(allocator, path);
    const schema = report.object.get("schema") orelse .null;
    if (schema != .string or !std.mem.eql(u8, schema.string, REPORT_SCHEMA)) {
        return fail("{s} is not a repin probe report", .{path});
    }
    _ = try validateProfile(allocator, report.object.get("series").?, "report.series");
    try validateReportPocketEvidence(allocator, report);
    return report;
}

pub const IdentityStatusResult = struct {
    status: []const u8,
    reasons: [][]const u8,
};

pub fn identityStatus(
    allocator: std.mem.Allocator,
    identity: std.json.Value,
    observed: std.json.Value,
) !IdentityStatusResult {
    var reasons: std.ArrayList([]const u8) = .empty;
    var status: []const u8 = "unchanged";
    const pkg = identity.object.get("package").?.string;
    const kind = identity.object.get("kind").?.string;
    const id_dig = identity.object.get("digest").?.string;
    const id_size = identity.object.get("size").?.integer;
    const id_mode = identity.object.get("mode").?;

    for (identity.object.get("architectures").?.array.items) |arch_val| {
        const arch = arch_val.string;
        const val_opt = if (observed == .object) observed.object.get(arch) else null;
        if (val_opt == null or val_opt.? == .null) {
            var r = try allocator.alloc([]const u8, 1);
            r[0] = try std.fmt.allocPrint(allocator, "{s} is not in the {s} snapshot", .{ pkg, arch });
            return .{ .status = "missing", .reasons = r };
        }
        const value = val_opt.?.object;
        if (std.mem.eql(u8, kind, "prestate")) {
            var stale: std.ArrayList([]const u8) = .empty;
            const dv = value.get("derived_versions").?.object;
            for (identity.object.get("derived_from").?.array.items) |item| {
                const dp = item.object.get("package").?.string;
                const dver = item.object.get("version").?.string;
                const got_v = dv.get(dp) orelse .null;
                const got_str = if (got_v == .string) got_v.string else "None";
                if (got_v != .string or !std.mem.eql(u8, got_str, dver)) {
                    try stale.append(allocator, try std.fmt.allocPrint(allocator, "{s} {s} -> {s}", .{ dp, dver, got_str }));
                }
            }
            if (stale.items.len > 0) {
                var r = try allocator.alloc([]const u8, 1);
                r[0] = try std.fmt.allocPrint(allocator, "{s}: derived state depends on changed packages: {s}", .{
                    arch,
                    try std.mem.join(allocator, ", ", stale.items),
                });
                return .{ .status = "changed", .reasons = r };
            }
            const v_dig = value.get("digest") orelse .null;
            if (v_dig != .null) {
                const v_size = value.get("size") orelse .null;
                const v_mode = value.get("mode") orelse .null;
                if (!std.mem.eql(u8, v_dig.string, id_dig) or
                    v_size != .integer or v_size.integer != id_size or
                    !jsonEql(v_mode, id_mode))
                {
                    var r = try allocator.alloc([]const u8, 1);
                    r[0] = try std.fmt.allocPrint(allocator, "{s}: derived prestate changed: {s} -> {s}", .{ arch, id_dig, v_dig.string });
                    return .{ .status = "changed", .reasons = r };
                }
            }
        } else {
            const v_dig = value.get("digest").?.string;
            const v_size = value.get("size").?.integer;
            const v_mode = value.get("mode").?;
            if (!std.mem.eql(u8, v_dig, id_dig) or v_size != id_size or !jsonEql(v_mode, id_mode)) {
                var r = try allocator.alloc([]const u8, 1);
                r[0] = try std.fmt.allocPrint(allocator, "{s}: bound bytes changed: {s} -> {s}", .{ arch, id_dig, v_dig });
                return .{ .status = "changed", .reasons = r };
            }
        }

        const prov = identity.object.get("provenance").?;
        const prov_pending = (prov == .string and std.mem.eql(u8, prov.string, "pending"));
        const obs_ver = value.get("version").?.string;
        const obs_arch = value.get("archive").?.string;
        if (identity.object.get("version_bound").?.bool and !prov_pending and
            !std.mem.eql(u8, obs_ver, prov.object.get("version").?.string))
        {
            var r = try allocator.alloc([]const u8, 1);
            r[0] = try std.fmt.allocPrint(allocator, "{s}: version-bound identity moved from {s} to {s}", .{
                arch,
                prov.object.get("version").?.string,
                obs_ver,
            });
            return .{ .status = "changed", .reasons = r };
        }
        if (prov_pending) {
            try reasons.append(allocator, try std.fmt.allocPrint(allocator, "{s}: records first provenance", .{arch}));
            status = "provenance-only";
        } else {
            const old_arch_val = prov.object.get("archives").?.object.get(arch) orelse .null;
            const old_arch_str = if (old_arch_val == .string) old_arch_val.string else "None";
            if (!std.mem.eql(u8, old_arch_str, obs_arch) or !std.mem.eql(u8, prov.object.get("version").?.string, obs_ver)) {
                try reasons.append(allocator, try std.fmt.allocPrint(allocator, "{s}: archive {s} -> {s}", .{ arch, old_arch_str, obs_arch }));
                status = "provenance-only";
            }
        }
    }
    return .{ .status = status, .reasons = try reasons.toOwnedSlice(allocator) };
}

fn normalizedCodeLines(allocator: std.mem.Allocator, data: []const u8) ![][]const u8 {
    var result: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw_line| {
        const stripped = std.mem.trim(u8, raw_line, " \t\r");
        if (stripped.len == 0 or stripped[0] == '#') continue;
        var words: std.ArrayList([]const u8) = .empty;
        var tok = std.mem.tokenizeAny(u8, stripped, " \t\r");
        while (tok.next()) |w| try words.append(allocator, w);
        try result.append(allocator, try std.mem.join(allocator, " ", words.items));
    }
    return result.toOwnedSlice(allocator);
}

pub fn advisory(allocator: std.mem.Allocator, old_opt: ?[]const u8, new_opt: ?[]const u8) ![]const u8 {
    const old_bytes = old_opt orelse return "no in-tree bytes to compare; review the new member";
    const new_bytes = new_opt orelse return "no in-tree bytes to compare; review the new member";
    const old_code = try normalizedCodeLines(allocator, old_bytes);
    const new_code = try normalizedCodeLines(allocator, new_bytes);
    if (old_code.len == new_code.len) {
        var same = true;
        for (old_code, new_code) |a, b| {
            if (!std.mem.eql(u8, a, b)) {
                same = false;
                break;
            }
        }
        if (same) return "comments or whitespace only";
    }
    return "behavioral change; review every hunk";
}

pub fn fixtureBytes(allocator: std.mem.Allocator, identity: std.json.Value, root: []const u8) ?[]u8 {
    for (identity.object.get("consumers").?.array.items) |consumer| {
        if (std.mem.eql(u8, consumer.object.get("form").?.string, "fixture")) {
            const full = std.fs.path.join(allocator, &.{ root, consumer.object.get("path").?.string }) catch return null;
            return cwdReadFileAlloc(allocator, full, maximum_member_bytes) catch null;
        }
    }
    return null;
}

pub fn simpleUnifiedDiff(
    allocator: std.mem.Allocator,
    old_text: []const u8,
    new_text: []const u8,
    fromfile: []const u8,
    tofile: []const u8,
) ![]u8 {
    if (std.mem.eql(u8, old_text, new_text)) return allocator.dupe(u8, "");
    var old_lines: std.ArrayList([]const u8) = .empty;
    var p: usize = 0;
    while (p < old_text.len) {
        const nl = std.mem.indexOfScalarPos(u8, old_text, p, '\n');
        const line = if (nl) |idx| old_text[p .. idx + 1] else old_text[p..];
        p = if (nl) |idx| idx + 1 else old_text.len;
        try old_lines.append(allocator, line);
    }
    var new_lines: std.ArrayList([]const u8) = .empty;
    p = 0;
    while (p < new_text.len) {
        const nl = std.mem.indexOfScalarPos(u8, new_text, p, '\n');
        const line = if (nl) |idx| new_text[p .. idx + 1] else new_text[p..];
        p = if (nl) |idx| idx + 1 else new_text.len;
        try new_lines.append(allocator, line);
    }

    var prefix_len: usize = 0;
    while (prefix_len < old_lines.items.len and prefix_len < new_lines.items.len and
        std.mem.eql(u8, old_lines.items[prefix_len], new_lines.items[prefix_len]))
    {
        prefix_len += 1;
    }
    var suffix_len: usize = 0;
    while (suffix_len < (old_lines.items.len - prefix_len) and
        suffix_len < (new_lines.items.len - prefix_len) and
        std.mem.eql(
            u8,
            old_lines.items[old_lines.items.len - 1 - suffix_len],
            new_lines.items[new_lines.items.len - 1 - suffix_len],
        ))
    {
        suffix_len += 1;
    }

    const ctx_start = if (prefix_len > 3) prefix_len - 3 else 0;
    const old_chg_end = old_lines.items.len - suffix_len;
    const new_chg_end = new_lines.items.len - suffix_len;
    const old_ctx_end = @min(old_lines.items.len, old_chg_end + 3);
    const new_ctx_end = @min(new_lines.items.len, new_chg_end + 3);

    var out: std.ArrayList(u8) = .empty;
    var w = arrayListWriter(&out, allocator);
    try w.print("--- {s}\n+++ {s}\n@@ -{d},{d} +{d},{d} @@\n", .{
        fromfile,
        tofile,
        ctx_start + 1,
        old_ctx_end - ctx_start,
        ctx_start + 1,
        new_ctx_end - ctx_start,
    });
    for (old_lines.items[ctx_start..prefix_len]) |l| {
        try w.print(" {s}", .{l});
        if (!std.mem.endsWith(u8, l, "\n")) try w.writeByte('\n');
    }
    for (old_lines.items[prefix_len..old_chg_end]) |l| {
        try w.print("-{s}", .{l});
        if (!std.mem.endsWith(u8, l, "\n")) try w.writeByte('\n');
    }
    for (new_lines.items[prefix_len..new_chg_end]) |l| {
        try w.print("+{s}", .{l});
        if (!std.mem.endsWith(u8, l, "\n")) try w.writeByte('\n');
    }
    for (old_lines.items[old_chg_end..old_ctx_end]) |l| {
        try w.print(" {s}", .{l});
        if (!std.mem.endsWith(u8, l, "\n")) try w.writeByte('\n');
    }
    return out.toOwnedSlice(allocator);
}

pub fn computeDiff(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    report: std.json.Value,
    report_directory: []const u8,
    root: []const u8,
    allow_series_migration: bool,
) RepinError!std.json.Value {
    const series_differs = !jsonEql(manifest.object.get("series").?, report.object.get("series").?);
    if (series_differs and !allow_series_migration) {
        return fail("the report and manifest describe different series profiles", .{});
    }
    var comparison_manifest = manifest;
    if (series_differs) {
        comparison_manifest = try cloneJsonValue(allocator, manifest);
        try comparison_manifest.object.put(allocator, "series", try cloneJsonValue(allocator, report.object.get("series").?));
        var pend_snap: std.json.ObjectMap = .empty;
        try pend_snap.put(allocator, "timestamp", report.object.get("timestamp").?);
        try pend_snap.put(allocator, "status", .{ .string = "pending" });
        try comparison_manifest.object.put(allocator, "snapshot", .{ .object = pend_snap });
    }

    var statuses = std.json.Array.init(allocator);
    const reported = report.object.get("identities").?.object;
    for (comparison_manifest.object.get("identities").?.array.items) |identity| {
        const id_str = identity.object.get("id").?.string;
        const kind = identity.object.get("kind").?.string;
        const observed = reported.get(id_str) orelse std.json.Value{ .object = std.json.ObjectMap.empty };
        const st = try identityStatus(allocator, identity, observed);

        var entry: std.json.ObjectMap = .empty;
        try entry.put(allocator, "id", .{ .string = id_str });
        try entry.put(allocator, "status", .{ .string = st.status });
        var r_arr = std.json.Array.init(allocator);
        for (st.reasons) |r| try r_arr.append(.{ .string = r });
        try entry.put(allocator, "reasons", .{ .array = r_arr });

        if (std.mem.eql(u8, st.status, "changed") and (std.mem.eql(u8, kind, "script") or std.mem.eql(u8, kind, "tool_file"))) {
            const arch0 = identity.object.get("architectures").?.array.items[0].string;
            const val_opt = if (observed == .object) observed.object.get(arch0) else null;
            var new_bytes: ?[]u8 = null;
            if (val_opt != null and val_opt.? == .object) {
                if (val_opt.?.object.get("member_file")) |mf| {
                    if (mf == .string) {
                        const mf_path = try std.fs.path.join(allocator, &.{ report_directory, mf.string });
                        new_bytes = cwdReadFileAlloc(allocator, mf_path, maximum_member_bytes) catch null;
                    }
                }
            }
            const old_bytes = fixtureBytes(allocator, identity, root);
            try entry.put(allocator, "advisory", .{ .string = try advisory(allocator, old_bytes, new_bytes) });
            if (old_bytes != null and new_bytes != null and std.mem.eql(u8, kind, "script")) {
                const udiff = try simpleUnifiedDiff(
                    allocator,
                    old_bytes.?,
                    new_bytes.?,
                    try std.fmt.allocPrint(allocator, "pinned/{s}", .{id_str}),
                    try std.fmt.allocPrint(allocator, "{s}/{s}", .{ report.object.get("timestamp").?.string, id_str }),
                );
                try entry.put(allocator, "unified_diff", .{ .string = udiff });
            }
        }
        try statuses.append(.{ .object = entry });
    }

    var closures: std.json.ObjectMap = .empty;
    const old_closures_opt = comparison_manifest.object.get("snapshot").?.object.get("closures");
    var c_it = report.object.get("closures").?.object.iterator();
    while (c_it.next()) |kv| {
        const arch = kv.key_ptr.*;
        const closure = kv.value_ptr.*.object;
        var old_pkgs = std.StringHashMap([]const u8).init(allocator);
        if (old_closures_opt) |oc| {
            if (oc == .object) {
                if (oc.object.get(arch)) |arch_oc| {
                    if (arch_oc.object.get("packages")) |op| {
                        var op_it = op.object.iterator();
                        while (op_it.next()) |pkv| {
                            try old_pkgs.put(pkv.key_ptr.*, pkv.value_ptr.*.string);
                        }
                    }
                }
            }
        }
        var new_pkgs = std.StringHashMap([]const u8).init(allocator);
        var np_it = closure.get("packages").?.object.iterator();
        while (np_it.next()) |pkv| {
            try new_pkgs.put(pkv.key_ptr.*, pkv.value_ptr.*.object.get("version").?.string);
        }

        var added: std.ArrayList([]const u8) = .empty;
        var removed: std.ArrayList([]const u8) = .empty;
        var changed: std.ArrayList([]const u8) = .empty;

        var n_it = new_pkgs.iterator();
        while (n_it.next()) |nkv| {
            const name = nkv.key_ptr.*;
            const nver = nkv.value_ptr.*;
            if (old_pkgs.get(name)) |over| {
                if (!std.mem.eql(u8, over, nver)) {
                    try changed.append(allocator, try std.fmt.allocPrint(allocator, "{s} {s} -> {s}", .{ name, over, nver }));
                }
            } else {
                try added.append(allocator, try std.fmt.allocPrint(allocator, "{s} {s}", .{ name, nver }));
            }
        }
        var o_it = old_pkgs.iterator();
        while (o_it.next()) |okv| {
            if (!new_pkgs.contains(okv.key_ptr.*)) {
                try removed.append(allocator, try std.fmt.allocPrint(allocator, "{s} {s}", .{ okv.key_ptr.*, okv.value_ptr.* }));
            }
        }
        const Sorter = struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        };
        std.mem.sort([]const u8, added.items, {}, Sorter.less);
        std.mem.sort([]const u8, removed.items, {}, Sorter.less);
        std.mem.sort([]const u8, changed.items, {}, Sorter.less);

        var added_arr = std.json.Array.init(allocator);
        for (added.items) |s| try added_arr.append(.{ .string = s });
        var removed_arr = std.json.Array.init(allocator);
        for (removed.items) |s| try removed_arr.append(.{ .string = s });
        var changed_arr = std.json.Array.init(allocator);
        for (changed.items) |s| try changed_arr.append(.{ .string = s });

        var arch_diff: std.json.ObjectMap = .empty;
        try arch_diff.put(allocator, "added", .{ .array = added_arr });
        try arch_diff.put(allocator, "removed", .{ .array = removed_arr });
        try arch_diff.put(allocator, "changed", .{ .array = changed_arr });
        try closures.put(allocator, arch, .{ .object = arch_diff });
    }

    const pinned_frozen = frozenPocket(comparison_manifest.object.get("snapshot").?);
    const reported_frozen = frozenPocket(report);
    var frozen_rel_val: std.json.Value = .null;
    if (reported_frozen) |rf| {
        var fr_obj: std.json.ObjectMap = .empty;
        try fr_obj.put(allocator, "pinned", if (pinned_frozen) |pf| pf.object.get("release_sha256").? else .null);
        try fr_obj.put(allocator, "probed", rf.object.get("release_sha256").?);
        frozen_rel_val = .{ .object = fr_obj };
    }

    var diff_obj: std.json.ObjectMap = .empty;
    try diff_obj.put(allocator, "series", report.object.get("series").?.object.get("name").?);
    try diff_obj.put(allocator, "from", manifest.object.get("snapshot").?.object.get("timestamp").?);
    try diff_obj.put(allocator, "to", report.object.get("timestamp").?);
    try diff_obj.put(
        allocator,
        "series_migration",
        if (series_differs) manifest.object.get("series").?.object.get("name").? else .null,
    );
    try diff_obj.put(allocator, "frozen_release", frozen_rel_val);
    try diff_obj.put(allocator, "closures", .{ .object = closures });
    try diff_obj.put(allocator, "identities", .{ .array = statuses });
    return .{ .object = diff_obj };
}

pub fn pinnedStrings(allocator: std.mem.Allocator, manifest: std.json.Value) !ManagedStringArrayHashMap([]const u8) {
    var strings = ManagedStringArrayHashMap([]const u8).init(allocator);
    const series = manifest.object.get("series").?;
    const snapshot = manifest.object.get("snapshot").?;
    const ts = snapshot.object.get("timestamp").?.string;
    try strings.put(try snapshotUri(allocator, series, ts), "uri");
    try strings.put(ts, "timestamp");
    if (snapshot.object.get("pockets")) |pockets| {
        for (pockets.array.items) |pocket| {
            const suite = pocket.object.get("suite").?.string;
            try strings.put(
                pocket.object.get("release_sha256").?.string["sha256:".len..],
                try std.fmt.allocPrint(allocator, "release:{s}", .{suite}),
            );
            try strings.put(
                pocket.object.get("in_release_sha256").?.string["sha256:".len..],
                try std.fmt.allocPrint(allocator, "in-release:{s}", .{suite}),
            );
        }
    }
    if (snapshot.object.get("closures")) |closures| {
        var c_it = closures.object.iterator();
        while (c_it.next()) |kv| {
            try strings.put(
                kv.value_ptr.*.object.get("digest").?.string["sha256:".len..],
                try std.fmt.allocPrint(allocator, "closure:{s}", .{kv.key_ptr.*}),
            );
        }
    }
    for (manifest.object.get("identities").?.array.items) |identity| {
        const id_str = identity.object.get("id").?.string;
        const dig = identity.object.get("digest").?.string;
        const colon = std.mem.indexOfScalar(u8, dig, ':').?;
        try strings.put(dig[colon + 1 ..], try std.fmt.allocPrint(allocator, "identity:{s}", .{id_str}));
        const prov = identity.object.get("provenance").?;
        if (prov == .object) {
            var a_it = prov.object.get("archives").?.object.iterator();
            while (a_it.next()) |akv| {
                const a_str = akv.value_ptr.*.string;
                const a_colon = std.mem.indexOfScalar(u8, a_str, ':').?;
                try strings.put(
                    a_str[a_colon + 1 ..],
                    try std.fmt.allocPrint(allocator, "archive:{s}@{s}", .{ id_str, akv.key_ptr.* }),
                );
            }
        }
    }
    return strings;
}

pub fn scanPrDiff(
    allocator: std.mem.Allocator,
    text: []const u8,
    manifest: std.json.Value,
    changed: std.StringHashMap(void),
) ![]std.json.Value {
    const strings = try pinnedStrings(allocator, manifest);
    var findings: std.ArrayList(std.json.Value) = .empty;
    var path: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (std.mem.startsWith(u8, line, "+++ ")) {
            path = if (std.mem.startsWith(u8, line, "+++ b/")) line[6..] else line[4..];
            continue;
        }
        if (!std.mem.startsWith(u8, line, "+") or std.mem.startsWith(u8, line, "+++")) {
            continue;
        }
        for (strings.keys()) |val| {
            if (std.mem.indexOf(u8, line, val) != null) {
                const label = strings.get(val).?;
                var f_obj: std.json.ObjectMap = .empty;
                try f_obj.put(allocator, "path", if (path) |p| .{ .string = p } else .null);
                try f_obj.put(allocator, "pin", .{ .string = label });
                try f_obj.put(allocator, "stale", .{ .bool = changed.contains(label) });
                const trimmed = std.mem.trim(u8, line[1..], " \t\r\n");
                try f_obj.put(allocator, "line", .{ .string = trimmed[0..@min(trimmed.len, 200)] });
                try findings.append(allocator, .{ .object = f_obj });
            }
        }
    }
    return findings.toOwnedSlice(allocator);
}

pub fn changedLabels(
    allocator: std.mem.Allocator,
    diff: std.json.Value,
    manifest: std.json.Value,
    report: std.json.Value,
) !std.StringHashMap(void) {
    var labels = std.StringHashMap(void).init(allocator);
    const snapshot = manifest.object.get("snapshot").?;
    if (!std.mem.eql(u8, snapshot.object.get("timestamp").?.string, report.object.get("timestamp").?.string)) {
        try labels.put("uri", {});
        try labels.put("timestamp", {});
    }
    if (snapshot.object.get("pockets")) |pockets| {
        for (pockets.array.items) |pocket| {
            const suite = pocket.object.get("suite").?.string;
            var new_p: ?std.json.Value = null;
            for (report.object.get("pockets").?.array.items) |rp| {
                if (std.mem.eql(u8, rp.object.get("suite").?.string, suite)) {
                    new_p = rp;
                    break;
                }
            }
            if (new_p == null or !std.mem.eql(u8, new_p.?.object.get("release_sha256").?.string, pocket.object.get("release_sha256").?.string)) {
                try labels.put(try std.fmt.allocPrint(allocator, "release:{s}", .{suite}), {});
            }
            if (new_p == null or !std.mem.eql(u8, new_p.?.object.get("in_release_sha256").?.string, pocket.object.get("in_release_sha256").?.string)) {
                try labels.put(try std.fmt.allocPrint(allocator, "in-release:{s}", .{suite}), {});
            }
        }
    }
    if (snapshot.object.get("closures")) |closures| {
        var c_it = closures.object.iterator();
        while (c_it.next()) |kv| {
            const arch = kv.key_ptr.*;
            const old_dig = kv.value_ptr.*.object.get("digest").?.string;
            const rep_arch = report.object.get("closures").?.object.get(arch);
            const new_dig = if (rep_arch) |ra| ra.object.get("digest").?.string else "";
            if (!std.mem.eql(u8, old_dig, new_dig)) {
                try labels.put(try std.fmt.allocPrint(allocator, "closure:{s}", .{arch}), {});
            }
        }
    }
    for (diff.object.get("identities").?.array.items) |entry| {
        const st = entry.object.get("status").?.string;
        const id_str = entry.object.get("id").?.string;
        if (std.mem.eql(u8, st, "changed") or std.mem.eql(u8, st, "missing")) {
            try labels.put(try std.fmt.allocPrint(allocator, "identity:{s}", .{id_str}), {});
        }
        if (!std.mem.eql(u8, st, "unchanged")) {
            for ([_][]const u8{ "amd64", "arm64" }) |arch| {
                try labels.put(try std.fmt.allocPrint(allocator, "archive:{s}@{s}", .{ id_str, arch }), {});
            }
        }
    }
    return labels;
}

pub fn diffSummary(allocator: std.mem.Allocator, diff: std.json.Value, findings: []const std.json.Value) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var w = arrayListWriter(&out, allocator);
    try w.print(
        "## Real-snapshot diff: `{s}` `{s}` -> `{s}`\n\n",
        .{
            diff.object.get("series").?.string,
            diff.object.get("from").?.string,
            diff.object.get("to").?.string,
        },
    );
    const frozen = diff.object.get("frozen_release").?;
    if (frozen != .null) {
        const pinned = frozen.object.get("pinned").?;
        const probed = frozen.object.get("probed").?;
        const state = if (jsonEql(pinned, probed)) "unchanged" else "CHANGED (needs --accept-frozen-release)";
        try w.print("- Frozen release: {s}: `{s}`\n", .{ state, probed.string });
    }
    var c_it = diff.object.get("closures").?.object.iterator();
    while (c_it.next()) |kv| {
        const arch = kv.key_ptr.*;
        const closure = kv.value_ptr.*.object;
        const chg = closure.get("changed").?.array.items;
        const add = closure.get("added").?.array.items;
        const rem = closure.get("removed").?.array.items;
        try w.print(
            "- {s}: {d} changed, {d} added, {d} removed closure packages\n",
            .{ arch, chg.len, add.len, rem.len },
        );
        for ([_][]const u8{ "changed", "added", "removed" }) |key| {
            for (closure.get(key).?.array.items) |item| {
                try w.print("  - {s}: {s}\n", .{ key, item.string });
            }
        }
    }
    try w.writeAll("\n| Identity | Status | Detail |\n|---|---|---|\n");
    for (diff.object.get("identities").?.array.items) |entry| {
        const e_obj = entry.object;
        var reasons_list: std.ArrayList([]const u8) = .empty;
        for (e_obj.get("reasons").?.array.items) |r| try reasons_list.append(allocator, r.string);
        var detail = try std.mem.join(allocator, "; ", reasons_list.items);
        if (e_obj.get("advisory")) |adv| {
            detail = try std.fmt.allocPrint(allocator, "{s} ({s})", .{ detail, adv.string });
        }
        try w.print("| `{s}` | {s} | {s} |\n", .{
            e_obj.get("id").?.string,
            e_obj.get("status").?.string,
            detail,
        });
    }
    if (findings.len > 0) {
        try w.writeAll("\n| PR file | Pin | Stale |\n|---|---|---|\n");
        for (findings) |f| {
            const fo = f.object;
            const p_val = fo.get("path").?;
            const p_str = if (p_val == .string) p_val.string else "None";
            try w.print("| `{s}` | `{s}` | {s} |\n", .{
                p_str,
                fo.get("pin").?.string,
                if (fo.get("stale").?.bool) "yes" else "no",
            });
        }
    }
    return out.toOwnedSlice(allocator);
}

pub fn parseReviews(allocator: std.mem.Allocator, values: []const []const u8) RepinError!ManagedStringArrayHashMap([]const u8) {
    var reviews = ManagedStringArrayHashMap([]const u8).init(allocator);
    for (values) |val| {
        const eq = std.mem.indexOfScalar(u8, val, '=') orelse
            return fail("--reviewed must be IDENTITY=REFERENCE: '{s}'", .{val});
        const identity = val[0..eq];
        const reference = val[eq + 1 ..];
        if (!isReviewReference(reference)) {
            return fail("--reviewed {s} needs a PR or issue reference such as #330", .{identity});
        }
        if (reviews.contains(identity)) {
            return fail("--reviewed {s} is repeated", .{identity});
        }
        try reviews.put(identity, reference);
    }
    return reviews;
}

pub fn migratedFixturePath(allocator: std.mem.Allocator, identity: std.json.Value, series_name: []const u8) RepinError![]u8 {
    const path_val = identity.object.get("path") orelse .null;
    const raw_path = if (path_val == .string) path_val.string else "";
    const member = try std.mem.replaceOwned(u8, allocator, raw_path, "/", "-");
    if (member.len == 0) {
        return fail("{s} fixture consumer cannot be renamed without a member path", .{identity.object.get("id").?.string});
    }
    return std.fmt.allocPrint(allocator, "src/fixtures/{s}-{s}.{s}", .{
        series_name,
        identity.object.get("package").?.string,
        member,
    });
}

pub fn refreshExclusionReasons(allocator: std.mem.Allocator, manifest: *std.json.Value) !void {
    const ex_val = manifest.object.getPtr("excluded") orelse return;
    if (ex_val.* != .array) return;
    for (ex_val.array.items) |*item| {
        if (item.* != .object) continue;
        const dig_val = item.object.get("digest") orelse continue;
        if (dig_val != .string) continue;
        const d = dig_val.string;
        if (std.mem.eql(u8, d, "sha256:0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5")) {
            try item.object.put(allocator, "reason", .{ .string = try allocator.dupe(u8, "pinned dpkg 1.22.22 private Debian reference prepared by tools/prepare-native-dpkg.py; external oracle, not the resolute snapshot dpkg pin") });
        } else if (std.mem.eql(u8, d, "sha256:b02b581c6a7f85679f32efe18c9aaeb05316847fa90d3d3fda30b57defab9b13")) {
            try item.object.put(allocator, "reason", .{ .string = try allocator.dupe(u8, "update-alternatives from the pinned dpkg 1.22.22 private Debian reference (amd64); external oracle, not the resolute snapshot dpkg pin") });
        } else if (std.mem.eql(u8, d, "sha256:35616ec58ba58f3fb8b4820bdf893c47a842d56684b3335ba6ebf6df86b27cc5")) {
            try item.object.put(allocator, "reason", .{ .string = try allocator.dupe(u8, "update-alternatives from the pinned dpkg 1.22.22 private Debian reference (arm64); external oracle, not the resolute snapshot dpkg pin") });
        }
    }
}

pub fn recordManifest(
    allocator: std.mem.Allocator,
    manifest: std.json.Value,
    report: std.json.Value,
    diff: std.json.Value,
    reviews: ManagedStringArrayHashMap([]const u8),
    accept_frozen: ?[]const u8,
    allow_series_migration: bool,
) RepinError!std.json.Value {
    try validateReportPocketEvidence(allocator, report);
    const rep_series_name = report.object.get("series").?.object.get("name").?.string;
    const man_series_name = manifest.object.get("series").?.object.get("name").?.string;
    const series_migration = !std.mem.eql(u8, rep_series_name, man_series_name);
    if (series_migration and !allow_series_migration) {
        return fail("the report is for a different series", .{});
    }
    const rep_ts = report.object.get("timestamp").?.string;
    const man_ts = manifest.object.get("snapshot").?.object.get("timestamp").?.string;
    if ((try timestampSeconds(rep_ts)) < (try timestampSeconds(man_ts))) {
        return fail("the report snapshot {s} is older than the current pin", .{rep_ts});
    }

    var required = std.StringHashMap(void).init(allocator);
    for (diff.object.get("identities").?.array.items) |entry| {
        const st = entry.object.get("status").?.string;
        if (std.mem.eql(u8, st, "changed") or std.mem.eql(u8, st, "missing")) {
            try required.put(entry.object.get("id").?.string, {});
        }
    }
    var unreviewed: std.ArrayList([]const u8) = .empty;
    var req_it = required.keyIterator();
    while (req_it.next()) |k| {
        if (!reviews.contains(k.*)) try unreviewed.append(allocator, k.*);
    }
    const Sorter = struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    };
    if (unreviewed.items.len > 0) {
        std.mem.sort([]const u8, unreviewed.items, {}, Sorter.less);
        return fail("reviewed identities changed without re-review: {s}; pass --reviewed ID=#PR for each after reviewing it", .{
            try std.mem.join(allocator, ", ", unreviewed.items),
        });
    }
    var unexpected: std.ArrayList([]const u8) = .empty;
    for (reviews.keys()) |k| {
        if (!required.contains(k)) try unexpected.append(allocator, k);
    }
    if (unexpected.items.len > 0) {
        std.mem.sort([]const u8, unexpected.items, {}, Sorter.less);
        return fail("--reviewed names identities that did not change: {s}", .{
            try std.mem.join(allocator, ", ", unexpected.items),
        });
    }

    const frozen = diff.object.get("frozen_release").?;
    const frozen_changed = (frozen != .null and !jsonEql(frozen.object.get("pinned").?, frozen.object.get("probed").?));
    if (frozen_changed and accept_frozen == null) {
        return fail("the frozen release changed; review the Release delta and pass --accept-frozen-release #PR", .{});
    }
    if (accept_frozen != null and !frozen_changed) {
        return fail("--accept-frozen-release was passed but the frozen release did not change", .{});
    }
    if (accept_frozen) |af| {
        if (!isReviewReference(af)) {
            return fail("--accept-frozen-release needs a PR or issue reference", .{});
        }
    }

    var updated = try cloneJsonValue(allocator, manifest);
    if (series_migration) {
        try updated.object.put(allocator, "series", try cloneJsonValue(allocator, report.object.get("series").?));
    }
    const previous_frozen = frozenPocket(manifest.object.get("snapshot").?);
    var pockets_arr = std.json.Array.init(allocator);
    for (report.object.get("pockets").?.array.items) |pocket| {
        var entry: std.json.ObjectMap = .empty;
        for ([_][]const u8{
            "suite",             "role",        "date",    "valid_until", "release_sha256", "in_release_sha256",
            "in_release_sha512", "hash_fields", "signers", "deadline",    "binding",
        }) |k| {
            try entry.put(allocator, k, try cloneJsonValue(allocator, pocket.object.get(k).?));
        }
        if (std.mem.eql(u8, pocket.object.get("role").?.string, "frozen")) {
            const rev_str = if (frozen_changed) accept_frozen.? else previous_frozen.?.object.get("review").?.string;
            try entry.put(allocator, "review", .{ .string = try allocator.dupe(u8, rev_str) });
        }
        try pockets_arr.append(.{ .object = entry });
    }

    var snap_closures: std.json.ObjectMap = .empty;
    var rc_it = report.object.get("closures").?.object.iterator();
    while (rc_it.next()) |kv| {
        const arch = kv.key_ptr.*;
        const closure = kv.value_ptr.*.object;
        var pkgs_map: std.json.ObjectMap = .empty;
        var p_it = closure.get("packages").?.object.iterator();
        while (p_it.next()) |pkv| {
            try pkgs_map.put(
                allocator,
                try allocator.dupe(u8, pkv.key_ptr.*),
                .{ .string = try allocator.dupe(u8, pkv.value_ptr.*.object.get("version").?.string) },
            );
        }
        var sc_entry: std.json.ObjectMap = .empty;
        try sc_entry.put(allocator, "digest", try cloneJsonValue(allocator, closure.get("digest").?));
        try sc_entry.put(allocator, "package_count", try cloneJsonValue(allocator, closure.get("package_count").?));
        try sc_entry.put(allocator, "pockets", try cloneJsonValue(allocator, closure.get("pockets").?));
        try sc_entry.put(allocator, "packages", .{ .object = pkgs_map });
        try snap_closures.put(allocator, try allocator.dupe(u8, arch), .{ .object = sc_entry });
    }

    var new_snap: std.json.ObjectMap = .empty;
    try new_snap.put(allocator, "timestamp", .{ .string = try allocator.dupe(u8, rep_ts) });
    try new_snap.put(allocator, "status", .{ .string = "probed" });
    try new_snap.put(allocator, "pockets", .{ .array = pockets_arr });
    try new_snap.put(allocator, "admission_deadline", report.object.get("admission_deadline").?);
    try new_snap.put(allocator, "closures", .{ .object = snap_closures });
    try updated.object.put(allocator, "snapshot", .{ .object = new_snap });

    var new_identities = std.json.Array.init(allocator);
    const man_ids = manifest.object.get("identities").?.array.items;
    const diff_ids = diff.object.get("identities").?.array.items;
    for (man_ids, diff_ids) |identity, d_entry| {
        const st = d_entry.object.get("status").?.string;
        if (std.mem.eql(u8, st, "missing")) continue;
        const id_str = identity.object.get("id").?.string;
        const kind = identity.object.get("kind").?.string;
        const observed = report.object.get("identities").?.object.get(id_str).?.object;
        const arch0 = identity.object.get("architectures").?.array.items[0].string;
        const first_obs = observed.get(arch0).?.object;

        var new_id = try cloneJsonValue(allocator, identity);
        const f_dig = first_obs.get("digest") orelse .null;
        if (!std.mem.eql(u8, kind, "prestate") or f_dig != .null) {
            try new_id.object.put(allocator, "digest", try cloneJsonValue(allocator, f_dig));
            try new_id.object.put(allocator, "size", try cloneJsonValue(allocator, first_obs.get("size").?));
            try new_id.object.put(allocator, "mode", try cloneJsonValue(allocator, first_obs.get("mode").?));
        }
        if (series_migration) {
            for (new_id.object.getPtr("consumers").?.array.items) |*consumer| {
                if (std.mem.eql(u8, consumer.object.get("form").?.string, "fixture") and
                    std.mem.startsWith(u8, consumer.object.get("path").?.string, "src/fixtures/ubuntu-"))
                {
                    try consumer.object.put(allocator, "path", .{ .string = try migratedFixturePath(allocator, identity, rep_series_name) });
                }
            }
        }
        const prov = identity.object.get("provenance").?;
        if (identity.object.get("version_bound").?.bool and prov == .object) {
            const old_full = prov.object.get("version").?.string;
            const old_name = if (std.mem.indexOfScalar(u8, old_full, ':')) |c| old_full[c + 1 ..] else old_full;
            const new_full = first_obs.get("version").?.string;
            const new_name = if (std.mem.indexOfScalar(u8, new_full, ':')) |c| new_full[c + 1 ..] else new_full;
            if (!std.mem.eql(u8, old_name, new_name)) {
                for (new_id.object.getPtr("consumers").?.array.items) |*consumer| {
                    if (std.mem.eql(u8, consumer.object.get("form").?.string, "fixture")) {
                        const cur_p = consumer.object.get("path").?.string;
                        try consumer.object.put(allocator, "path", .{ .string = try std.mem.replaceOwned(u8, allocator, cur_p, old_name, new_name) });
                    }
                }
            }
        }

        var new_archives: std.json.ObjectMap = .empty;
        for (identity.object.get("architectures").?.array.items) |a| {
            try new_archives.put(
                allocator,
                try allocator.dupe(u8, a.string),
                try cloneJsonValue(allocator, observed.get(a.string).?.object.get("archive").?),
            );
        }
        var new_prov: std.json.ObjectMap = .empty;
        try new_prov.put(allocator, "version", try cloneJsonValue(allocator, first_obs.get("version").?));
        try new_prov.put(allocator, "archives", .{ .object = new_archives });
        try new_id.object.put(allocator, "provenance", .{ .object = new_prov });

        if (new_id.object.contains("artifact")) {
            const f_art = first_obs.get("artifact") orelse
                return fail("{s} report has no independently observed artifact coordinates", .{id_str});
            try new_id.object.put(allocator, "artifact", try cloneJsonValue(allocator, f_art));
        }
        if (std.mem.eql(u8, kind, "prestate")) {
            var new_df = std.json.Array.init(allocator);
            const dv = first_obs.get("derived_versions").?.object;
            for (identity.object.get("derived_from").?.array.items) |item| {
                const dp = item.object.get("package").?.string;
                var df_item: std.json.ObjectMap = .empty;
                try df_item.put(allocator, "package", .{ .string = try allocator.dupe(u8, dp) });
                try df_item.put(allocator, "version", try cloneJsonValue(allocator, dv.get(dp).?));
                try new_df.append(.{ .object = df_item });
            }
            try new_id.object.put(allocator, "derived_from", .{ .array = new_df });
        }
        if (std.mem.eql(u8, st, "changed")) {
            try new_id.object.put(allocator, "review", .{ .string = try allocator.dupe(u8, reviews.get(id_str).?) });
        }
        try new_identities.append(new_id);
    }
    try updated.object.put(allocator, "identities", .{ .array = new_identities });
    try refreshExclusionReasons(allocator, &updated);
    return validateManifest(allocator, updated);
}

fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\usage: real-snapshot-repin {probe,diff,record,bind-architecture,bind-member,check} ...
        \\
        \\Probe, diff, record and check the reviewed real-snapshot pin manifest.
        \\
    );
}

pub fn runCli(allocator: std.mem.Allocator, argv: []const []const u8) anyerror!u8 {
    if (argv.len == 0) {
        return fail("a subcommand is required (probe, diff, record, bind-architecture, bind-member, check)", .{});
    }
    const cmd = argv[0];
    if (std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "--help")) {
        var buf: [1024]u8 = undefined;
        var w = std.Io.File.stdout().writer(global_io, &buf);
        printUsage(&w.interface) catch {};
        w.interface.flush() catch {};
        return 0;
    }

    if (std.mem.eql(u8, cmd, "probe")) {
        var series: ?[]const u8 = null;
        var timestamp: ?[]const u8 = null;
        var debz_path: ?[]const u8 = null;
        var manifest: []const u8 = DEFAULT_MANIFEST;
        var profile: ?[]const u8 = null;
        var workspace: ?[]const u8 = null;
        var accept_frozen = false;

        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            const arg = argv[i];
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                return 0;
            } else if (std.mem.eql(u8, arg, "--series")) {
                i += 1;
                if (i >= argv.len) return fail("--series requires a value", .{});
                series = argv[i];
            } else if (std.mem.eql(u8, arg, "--timestamp")) {
                i += 1;
                if (i >= argv.len) return fail("--timestamp requires a value", .{});
                timestamp = argv[i];
            } else if (std.mem.eql(u8, arg, "--debz")) {
                i += 1;
                if (i >= argv.len) return fail("--debz requires a value", .{});
                debz_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--manifest")) {
                i += 1;
                if (i >= argv.len) return fail("--manifest requires a value", .{});
                manifest = argv[i];
            } else if (std.mem.eql(u8, arg, "--profile")) {
                i += 1;
                if (i >= argv.len) return fail("--profile requires a value", .{});
                profile = argv[i];
            } else if (std.mem.eql(u8, arg, "--workspace")) {
                i += 1;
                if (i >= argv.len) return fail("--workspace requires a value", .{});
                workspace = argv[i];
            } else if (std.mem.eql(u8, arg, "--accept-frozen-release")) {
                accept_frozen = true;
            } else {
                return fail("unrecognized probe argument: {s}", .{arg});
            }
        }
        if (series == null or debz_path == null) {
            return fail("probe requires --series and --debz", .{});
        }
        return probe(allocator, .{
            .series = series.?,
            .timestamp = timestamp,
            .debz_path = debz_path.?,
            .manifest = manifest,
            .profile = profile,
            .workspace = workspace,
            .accept_frozen_release = accept_frozen,
        }, null);
    }

    if (std.mem.eql(u8, cmd, "diff")) {
        var report_path: ?[]const u8 = null;
        var manifest_path: []const u8 = DEFAULT_MANIFEST;
        var pr_numbers: std.ArrayList([]const u8) = .empty;
        var pr_diff_files: std.ArrayList([]const u8) = .empty;
        var root_path: []const u8 = ".";
        var allow_migration = false;

        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            const arg = argv[i];
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                return 0;
            } else if (std.mem.eql(u8, arg, "--report")) {
                i += 1;
                if (i >= argv.len) return fail("--report requires a value", .{});
                report_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--manifest")) {
                i += 1;
                if (i >= argv.len) return fail("--manifest requires a value", .{});
                manifest_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--pr")) {
                i += 1;
                if (i >= argv.len) return fail("--pr requires a value", .{});
                try pr_numbers.append(allocator, argv[i]);
            } else if (std.mem.eql(u8, arg, "--pr-diff-file")) {
                i += 1;
                if (i >= argv.len) return fail("--pr-diff-file requires a value", .{});
                try pr_diff_files.append(allocator, argv[i]);
            } else if (std.mem.eql(u8, arg, "--root")) {
                i += 1;
                if (i >= argv.len) return fail("--root requires a value", .{});
                root_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--allow-series-migration")) {
                allow_migration = true;
            } else {
                return fail("unrecognized diff argument: {s}", .{arg});
            }
        }
        const rep_p = report_path orelse return fail("diff requires --report", .{});
        const manifest = try validateManifest(allocator, try loadJson(allocator, manifest_path));
        const report = try loadReport(allocator, rep_p);
        const rep_dir = std.fs.path.dirname(rep_p) orelse ".";
        var diff = try computeDiff(allocator, manifest, report, rep_dir, root_path, allow_migration);

        var findings_arr = std.json.Array.init(allocator);
        const labels = try changedLabels(allocator, diff, manifest, report);

        for (pr_numbers.items) |pr_num| {
            const res = std.process.run(allocator, global_io, .{
                .argv = &.{ "gh", "pr", "diff", pr_num },
                .stdout_limit = .limited(maximum_release_bytes),
                .stderr_limit = .limited(64 * 1024),
            }) catch |err| return fail("gh pr diff {s} failed: {s}", .{ pr_num, @errorName(err) });
            switch (res.term) {
                .exited => |code| if (code != 0) {
                    return fail("gh pr diff {s} failed: {s}", .{ pr_num, std.mem.trim(u8, res.stderr, " \t\r\n") });
                },
                else => return fail("gh pr diff {s} failed", .{pr_num}),
            }
            const scanned = try scanPrDiff(allocator, res.stdout, manifest, labels);
            for (scanned) |f| {
                var fo = f;
                try fo.object.put(allocator, "pr", .{ .string = try std.fmt.allocPrint(allocator, "#{s}", .{pr_num}) });
                try findings_arr.append(fo);
            }
        }
        for (pr_diff_files.items) |df_path| {
            const text = try readFileBounded(allocator, df_path, maximum_release_bytes, df_path);
            const scanned = try scanPrDiff(allocator, text, manifest, labels);
            for (scanned) |f| {
                var fo = f;
                try fo.object.put(allocator, "pr", .{ .string = df_path });
                try findings_arr.append(fo);
            }
        }
        try diff.object.put(allocator, "pr_findings", .{ .array = findings_arr });
        try writeJson(allocator, try std.fs.path.join(allocator, &.{ rep_dir, "diff.json" }), diff);
        const summary = try diffSummary(allocator, diff, findings_arr.items);
        try writeFileBytes(try std.fs.path.join(allocator, &.{ rep_dir, "diff.md" }), summary);

        var out_buf: [4096]u8 = undefined;
        var out_w = std.Io.File.stdout().writer(global_io, &out_buf);
        try out_w.interface.writeAll(summary);
        try out_w.interface.flush();
        return 0;
    }

    if (std.mem.eql(u8, cmd, "record")) {
        var report_path: ?[]const u8 = null;
        var manifest_path: []const u8 = DEFAULT_MANIFEST;
        var reviewed_list: std.ArrayList([]const u8) = .empty;
        var accept_frozen: ?[]const u8 = null;
        var root_path: []const u8 = ".";
        var allow_migration = false;

        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            const arg = argv[i];
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                return 0;
            } else if (std.mem.eql(u8, arg, "--report")) {
                i += 1;
                if (i >= argv.len) return fail("--report requires a value", .{});
                report_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--manifest")) {
                i += 1;
                if (i >= argv.len) return fail("--manifest requires a value", .{});
                manifest_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--reviewed")) {
                i += 1;
                if (i >= argv.len) return fail("--reviewed requires a value", .{});
                try reviewed_list.append(allocator, argv[i]);
            } else if (std.mem.eql(u8, arg, "--accept-frozen-release")) {
                i += 1;
                if (i >= argv.len) return fail("--accept-frozen-release requires a value", .{});
                accept_frozen = argv[i];
            } else if (std.mem.eql(u8, arg, "--root")) {
                i += 1;
                if (i >= argv.len) return fail("--root requires a value", .{});
                root_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--allow-series-migration")) {
                allow_migration = true;
            } else {
                return fail("unrecognized record argument: {s}", .{arg});
            }
        }
        const rep_p = report_path orelse return fail("record requires --report", .{});
        const manifest = try validateManifest(allocator, try loadJson(allocator, manifest_path));
        const report = try loadReport(allocator, rep_p);
        const rep_dir = std.fs.path.dirname(rep_p) orelse ".";
        const diff = try computeDiff(allocator, manifest, report, rep_dir, root_path, allow_migration);
        var updated = try recordManifest(
            allocator,
            manifest,
            report,
            diff,
            try parseReviews(allocator, reviewed_list.items),
            accept_frozen,
            allow_migration,
        );
        const ev_ids = try sourceEvidenceIdentities(allocator, updated);
        if (ev_ids.len > 0) {
            if (!updated.object.contains("prestate_evidence")) {
                try updated.object.put(allocator, "prestate_evidence", .{ .string = DEFAULT_EVIDENCE });
            }
            try exportPrestateEvidence(allocator, updated, report, rep_dir, root_path);
        }
        try writeJson(allocator, manifest_path, updated);

        var parts: std.ArrayList([]const u8) = .empty;
        for (STATUSES) |st| {
            var count: usize = 0;
            for (diff.object.get("identities").?.array.items) |entry| {
                if (std.mem.eql(u8, entry.object.get("status").?.string, st)) count += 1;
            }
            try parts.append(allocator, try std.fmt.allocPrint(allocator, "{d} {s}", .{ count, st }));
        }
        var out_buf: [4096]u8 = undefined;
        var out_w = std.Io.File.stdout().writer(global_io, &out_buf);
        try out_w.interface.print("recorded {s}: {s}\n", .{
            report.object.get("timestamp").?.string,
            try std.mem.join(allocator, ", ", parts.items),
        });
        try out_w.interface.flush();
        return 0;
    }

    if (std.mem.eql(u8, cmd, "bind-architecture")) {
        var identity_id: ?[]const u8 = null;
        var architecture: ?[]const u8 = null;
        var reviewed: ?[]const u8 = null;
        var manifest_path: []const u8 = DEFAULT_MANIFEST;
        var root_path: []const u8 = ".";

        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            const arg = argv[i];
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                return 0;
            } else if (std.mem.eql(u8, arg, "--identity")) {
                i += 1;
                if (i >= argv.len) return fail("--identity requires a value", .{});
                identity_id = argv[i];
            } else if (std.mem.eql(u8, arg, "--architecture")) {
                i += 1;
                if (i >= argv.len) return fail("--architecture requires a value", .{});
                architecture = argv[i];
            } else if (std.mem.eql(u8, arg, "--reviewed")) {
                i += 1;
                if (i >= argv.len) return fail("--reviewed requires a value", .{});
                reviewed = argv[i];
            } else if (std.mem.eql(u8, arg, "--manifest")) {
                i += 1;
                if (i >= argv.len) return fail("--manifest requires a value", .{});
                manifest_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--root")) {
                i += 1;
                if (i >= argv.len) return fail("--root requires a value", .{});
                root_path = argv[i];
            } else {
                return fail("unrecognized bind-architecture argument: {s}", .{arg});
            }
        }
        if (identity_id == null or architecture == null or reviewed == null) {
            return fail("bind-architecture requires --identity, --architecture and --reviewed", .{});
        }
        const manifest = try validateManifest(allocator, try loadJson(allocator, manifest_path));
        const pe = manifest.object.get("prestate_evidence") orelse
            return fail("architecture binding requires independently retained source evidence", .{});
        const ev_path = try std.fs.path.join(allocator, &.{ root_path, pe.string });
        const evidence = try readSourceFile(allocator, ev_path, root_path, maximum_evidence_bytes, "architecture binding source evidence");
        const updated = try bindArchitecture(allocator, manifest, identity_id.?, architecture.?, reviewed.?, evidence, null);
        try writeJson(allocator, manifest_path, updated);

        var out_buf: [4096]u8 = undefined;
        var out_w = std.Io.File.stdout().writer(global_io, &out_buf);
        try out_w.interface.print(
            "recorded original {s} source binding for {s}; script execution admission is unchanged\n",
            .{ architecture.?, identity_id.? },
        );
        try out_w.interface.flush();
        return 0;
    }

    if (std.mem.eql(u8, cmd, "bind-member")) {
        var archive_id: ?[]const u8 = null;
        var member: ?[]const u8 = null;
        var consumers: std.ArrayList([]const u8) = .empty;
        var reviewed: ?[]const u8 = null;
        var manifest_path: []const u8 = DEFAULT_MANIFEST;
        var root_path: []const u8 = ".";

        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            const arg = argv[i];
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                return 0;
            } else if (std.mem.eql(u8, arg, "--archive-identity")) {
                i += 1;
                if (i >= argv.len) return fail("--archive-identity requires a value", .{});
                archive_id = argv[i];
            } else if (std.mem.eql(u8, arg, "--member")) {
                i += 1;
                if (i >= argv.len) return fail("--member requires a value", .{});
                member = argv[i];
            } else if (std.mem.eql(u8, arg, "--consumer")) {
                i += 1;
                if (i >= argv.len) return fail("--consumer requires a value", .{});
                try consumers.append(allocator, argv[i]);
            } else if (std.mem.eql(u8, arg, "--reviewed")) {
                i += 1;
                if (i >= argv.len) return fail("--reviewed requires a value", .{});
                reviewed = argv[i];
            } else if (std.mem.eql(u8, arg, "--manifest")) {
                i += 1;
                if (i >= argv.len) return fail("--manifest requires a value", .{});
                manifest_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--root")) {
                i += 1;
                if (i >= argv.len) return fail("--root requires a value", .{});
                root_path = argv[i];
            } else {
                return fail("unrecognized bind-member argument: {s}", .{arg});
            }
        }
        if (archive_id == null or member == null or consumers.items.len == 0 or reviewed == null) {
            return fail("bind-member requires --archive-identity, --member, --consumer and --reviewed", .{});
        }
        const manifest = try validateManifest(allocator, try loadJson(allocator, manifest_path));
        const pe = manifest.object.get("prestate_evidence") orelse
            return fail("member binding requires independently retained source evidence", .{});
        const ev_path = try std.fs.path.join(allocator, &.{ root_path, pe.string });
        const evidence = try readSourceFile(allocator, ev_path, root_path, maximum_evidence_bytes, "member binding source evidence");
        const updated = try bindMember(allocator, manifest, archive_id.?, member.?, consumers.items, reviewed.?, evidence, null);
        try writeJson(allocator, manifest_path, updated);

        var out_buf: [4096]u8 = undefined;
        var out_w = std.Io.File.stdout().writer(global_io, &out_buf);
        try out_w.interface.print(
            "recorded original {s} from {s}; no live probe or execution proof claimed\n",
            .{ member.?, archive_id.? },
        );
        try out_w.interface.flush();
        return 0;
    }

    if (std.mem.eql(u8, cmd, "check")) {
        var manifest_path: []const u8 = DEFAULT_MANIFEST;
        var root_path: []const u8 = ".";
        var profile_path: ?[]const u8 = null;

        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            const arg = argv[i];
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                return 0;
            } else if (std.mem.eql(u8, arg, "--manifest")) {
                i += 1;
                if (i >= argv.len) return fail("--manifest requires a value", .{});
                manifest_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--root")) {
                i += 1;
                if (i >= argv.len) return fail("--root requires a value", .{});
                root_path = argv[i];
            } else if (std.mem.eql(u8, arg, "--profile")) {
                i += 1;
                if (i >= argv.len) return fail("--profile requires a value", .{});
                profile_path = argv[i];
            } else {
                return fail("unrecognized check argument: {s}", .{arg});
            }
        }
        const manifest = try validateManifest(allocator, try loadJson(allocator, manifest_path));
        const profile = if (profile_path) |pp|
            try validateProfile(allocator, try loadJson(allocator, pp), "profile")
        else
            null;
        const failures = try checkManifest(allocator, manifest, root_path, profile);
        if (failures.len > 0) {
            var err_buf: [4096]u8 = undefined;
            var err_w = std.Io.File.stderr().writer(global_io, &err_buf);
            for (failures) |failure| {
                try err_w.interface.print("check: {s}\n", .{failure});
            }
            try err_w.interface.flush();
            return 1;
        }
        const status = manifest.object.get("snapshot").?.object.get("status").?.string;
        var out_buf: [4096]u8 = undefined;
        var out_w = std.Io.File.stdout().writer(global_io, &out_buf);
        try out_w.interface.print(
            "check passed: {d} identities for {s} {s} ({s})\n",
            .{
                manifest.object.get("identities").?.array.items.len,
                manifest.object.get("series").?.object.get("name").?.string,
                manifest.object.get("snapshot").?.object.get("timestamp").?.string,
                status,
            },
        );
        const ev_ids = try sourceEvidenceIdentities(allocator, manifest);
        if (ev_ids.len > 0) {
            try out_w.interface.print(
                "offline retained source evidence: {d} byte identities verified; no live probe\n",
                .{ev_ids.len},
            );
        }
        try out_w.interface.flush();
        return 0;
    }

    return fail("unknown command: {s}", .{cmd});
}

pub fn main(init: std.process.Init) u8 {
    global_io = init.io;
    const allocator = init.arena.allocator();
    var argv_list: std.ArrayList([]const u8) = .empty;
    var args_it = init.minimal.args.iterateAllocator(allocator) catch {
        std.debug.print("real-snapshot-repin: out of memory\n", .{});
        return 2;
    };
    _ = args_it.next();
    while (args_it.next()) |arg| {
        argv_list.append(allocator, arg) catch {
            std.debug.print("real-snapshot-repin: out of memory\n", .{});
            return 2;
        };
    }
    const code = runCli(allocator, argv_list.items) catch |err| switch (err) {
        error.RepinFailed => {
            std.debug.print("real-snapshot-repin: {s}\n", .{lastErrorMessage()});
            return 2;
        },
        else => {
            std.debug.print("real-snapshot-repin: {s}\n", .{@errorName(err)});
            return 2;
        },
    };
    return code;
}

// ============================================================================
// Part 5: Unit Tests
// ============================================================================

const testing = std.testing;

const TEST_DAY: i64 = 86400;
const TEST_T0 = "20260920T000000Z";
const TEST_T1 = "20260927T000000Z";
const TEST_SIGNER = "0123456789abcdef0123456789abcdef01234567";
const TEST_SCRIPT = "#!/bin/sh\nset -e\n# configure\ntrue\n";
const TEST_TOOL = "\x7fELF synthetic tool\n";

fn repeatChar(comptime c: u8, comptime n: usize) *const [n]u8 {
    const arr: [n]u8 = @splat(c);
    return &arr;
}

fn testTmpRoot(allocator: std.mem.Allocator, tmp: *testing.TmpDir) ![]u8 {
    return tmp.dir.realPathFileAlloc(global_io, ".", allocator);
}

fn expectRepinFailsContaining(err_or_val: anytype, needle: []const u8) !void {
    if (err_or_val) |_| {
        std.debug.print("Expected error.RepinFailed containing '{s}', but succeeded\n", .{needle});
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.RepinFailed => {
            const msg = lastErrorMessage();
            if (std.mem.indexOf(u8, msg, needle) == null) {
                std.debug.print("Expected '{s}' in '{s}'\n", .{ needle, msg });
                return error.TestUnexpectedResult;
            }
        },
        else => return err,
    }
}

fn expectAnyContains(items: []const []const u8, needle: []const u8) !void {
    for (items) |item| {
        if (std.mem.indexOf(u8, item, needle) != null) return;
    }
    std.debug.print("Expected any item to contain '{s}', got {d} items:\n", .{ needle, items.len });
    for (items) |item| std.debug.print("  - {s}\n", .{item});
    return error.TestUnexpectedResult;
}

fn parseJsonTest(allocator: std.mem.Allocator, raw: []const u8) !std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, allocator, raw, .{});
}

fn testTaggedSha256(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    return tagged(allocator, "sha256", data);
}

fn testTaggedSha512(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    return tagged(allocator, "sha512", data);
}

fn testProfile(allocator: std.mem.Allocator) !std.json.Value {
    return parseJsonTest(allocator,
        \\{
        \\  "name": "synthetic",
        \\  "uri_root": "file:///synthetic/snapshot",
        \\  "component": "main",
        \\  "architectures": ["amd64"],
        \\  "keyring": "/synthetic/keyring.gpg",
        \\  "signer": "0123456789abcdef0123456789abcdef01234567",
        \\  "request": "synthetic-minimal",
        \\  "pockets": [{"suite": "stable", "role": "bounded"}]
        \\}
    );
}

fn testIdentity(allocator: std.mem.Allocator) !std.json.Value {
    const dig = try testTaggedSha256(allocator, TEST_SCRIPT);
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "id", .{ .string = "script:alpha/postinst" });
    try obj.put(allocator, "kind", .{ .string = "script" });
    try obj.put(allocator, "package", .{ .string = "alpha" });
    var archs = std.json.Array.init(allocator);
    try archs.append(.{ .string = "amd64" });
    try obj.put(allocator, "architectures", .{ .array = archs });
    try obj.put(allocator, "path", .{ .string = "postinst" });
    try obj.put(allocator, "digest", .{ .string = dig });
    try obj.put(allocator, "size", .{ .integer = @intCast(TEST_SCRIPT.len) });
    try obj.put(allocator, "mode", .{ .string = "0755" });
    try obj.put(allocator, "version_bound", .{ .bool = false });
    try obj.put(allocator, "provenance", .{ .string = "pending" });
    var cons = std.json.Array.init(allocator);
    var c0: std.json.ObjectMap = .empty;
    try c0.put(allocator, "path", .{ .string = "pins.txt" });
    try c0.put(allocator, "form", .{ .string = "hex" });
    try cons.append(.{ .object = c0 });
    try obj.put(allocator, "consumers", .{ .array = cons });
    try obj.put(allocator, "review", .{ .string = "#1" });
    return .{ .object = obj };
}

fn testManifest(allocator: std.mem.Allocator) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "schema", .{ .string = MANIFEST_SCHEMA });
    try obj.put(allocator, "series", try testProfile(allocator));
    var snap: std.json.ObjectMap = .empty;
    try snap.put(allocator, "timestamp", .{ .string = TEST_T0 });
    try snap.put(allocator, "status", .{ .string = "pending" });
    try obj.put(allocator, "snapshot", .{ .object = snap });
    try obj.put(allocator, "uri_consumers", .{ .array = std.json.Array.init(allocator) });
    var ids = std.json.Array.init(allocator);
    try ids.append(try testIdentity(allocator));
    try obj.put(allocator, "identities", .{ .array = ids });
    try obj.put(allocator, "excluded", .{ .array = std.json.Array.init(allocator) });
    return .{ .object = obj };
}

fn testObserved(
    allocator: std.mem.Allocator,
    digest_opt: ?[]const u8,
    size_opt: ?i64,
    mode: []const u8,
    version: []const u8,
    archive_opt: ?[]const u8,
) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "version", .{ .string = version });
    try obj.put(allocator, "archive", .{ .string = archive_opt orelse try testTaggedSha512(allocator, version) });
    try obj.put(allocator, "derived_versions", .{ .object = std.json.ObjectMap.empty });
    try obj.put(allocator, "digest", .{ .string = digest_opt orelse try testTaggedSha256(allocator, TEST_SCRIPT) });
    try obj.put(allocator, "size", .{ .integer = size_opt orelse @as(i64, @intCast(TEST_SCRIPT.len)) });
    try obj.put(allocator, "mode", .{ .string = mode });
    return .{ .object = obj };
}

fn testPocket(
    allocator: std.mem.Allocator,
    suite: []const u8,
    role: []const u8,
    release: []const u8,
    binding: []const u8,
) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    var b_obj: std.json.ObjectMap = .empty;
    try b_obj.put(allocator, "amd64", .{ .string = binding });
    try obj.put(allocator, "binding", .{ .object = b_obj });
    try obj.put(allocator, "suite", .{ .string = suite });
    try obj.put(allocator, "role", .{ .string = role });
    try obj.put(allocator, "date", .{ .string = "Sun, 26 Sep 2026 23:00:00 UTC" });
    const t1_sec = try timestampSeconds(TEST_T1);
    try obj.put(allocator, "date_unix", .{ .integer = t1_sec - 3600 });
    try obj.put(allocator, "valid_until", .null);
    try obj.put(allocator, "valid_until_unix", .null);
    var hf = std.json.Array.init(allocator);
    try hf.append(.{ .string = "SHA256" });
    try hf.append(.{ .string = "SHA512" });
    try obj.put(allocator, "hash_fields", .{ .array = hf });
    const in_rel = try std.fmt.allocPrint(allocator, "in{s}", .{release});
    try obj.put(allocator, "in_release_sha256", .{ .string = try testTaggedSha256(allocator, in_rel) });
    try obj.put(allocator, "in_release_sha512", .{ .string = try testTaggedSha512(allocator, in_rel) });
    try obj.put(allocator, "release_sha256", .{ .string = try testTaggedSha256(allocator, release) });
    var signers = std.json.Array.init(allocator);
    try signers.append(.{ .string = TEST_SIGNER });
    try obj.put(allocator, "signers", .{ .array = signers });
    try obj.put(allocator, "deadline", .{ .integer = t1_sec + 30 * TEST_DAY });
    return .{ .object = obj };
}

fn testReport(
    allocator: std.mem.Allocator,
    identities: std.json.Value,
    pockets_opt: ?[]const std.json.Value,
    timestamp: []const u8,
) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "schema", .{ .string = REPORT_SCHEMA });
    var series = try testProfile(allocator);
    var p_arr = std.json.Array.init(allocator);
    if (pockets_opt) |p_slice| {
        var sp_arr = std.json.Array.init(allocator);
        for (p_slice) |p| {
            try p_arr.append(try cloneJsonValue(allocator, p));
            var sp: std.json.ObjectMap = .empty;
            try sp.put(allocator, "suite", .{ .string = p.object.get("suite").?.string });
            try sp.put(allocator, "role", .{ .string = p.object.get("role").?.string });
            try sp_arr.append(.{ .object = sp });
        }
        try series.object.put(allocator, "pockets", .{ .array = sp_arr });
    } else {
        try p_arr.append(try testPocket(allocator, "stable", "bounded", "release", "exact_lock"));
    }
    try obj.put(allocator, "series", series);
    try obj.put(allocator, "timestamp", .{ .string = timestamp });
    try obj.put(allocator, "pockets", .{ .array = p_arr });
    try obj.put(allocator, "admission_deadline", .{ .integer = (try timestampSeconds(timestamp)) + 30 * TEST_DAY });

    var pkg_map = ManagedStringArrayHashMap(PackageSummary).init(allocator);
    var alpha_pkg: std.json.ObjectMap = .empty;
    try alpha_pkg.put(allocator, "version", .{ .string = "1.0" });
    try alpha_pkg.put(allocator, "architecture", .{ .string = "amd64" });
    try alpha_pkg.put(allocator, "archive", .{ .string = try testTaggedSha512(allocator, "1.0") });
    try alpha_pkg.put(allocator, "pocket", .{ .string = "stable" });
    try pkg_map.put("alpha", .{
        .version = "1.0",
        .architecture = "amd64",
        .archive = try testTaggedSha512(allocator, "1.0"),
        .pocket = "stable",
        .size = 1,
    });

    var pkgs_json: std.json.ObjectMap = .empty;
    try pkgs_json.put(allocator, "alpha", .{ .object = alpha_pkg });
    var p_counts: std.json.ObjectMap = .empty;
    try p_counts.put(allocator, "stable", .{ .integer = 1 });
    var amd64_c: std.json.ObjectMap = .empty;
    try amd64_c.put(allocator, "digest", .{ .string = try closureDigest(allocator, pkg_map) });
    try amd64_c.put(allocator, "package_count", .{ .integer = 1 });
    try amd64_c.put(allocator, "pockets", .{ .object = p_counts });
    try amd64_c.put(allocator, "packages", .{ .object = pkgs_json });
    var closures: std.json.ObjectMap = .empty;
    try closures.put(allocator, "amd64", .{ .object = amd64_c });
    try obj.put(allocator, "closures", .{ .object = closures });
    try obj.put(allocator, "identities", identities);
    return .{ .object = obj };
}

fn makeSyntheticDeb(
    allocator: std.mem.Allocator,
    ctrl_entries: []const struct { name: []const u8, body: []const u8, mode: u32 = 0o644 },
    data_entries: []const struct { name: []const u8, body: []const u8, mode: u32 = 0o644, typeflag: u8 = '0', linkname: []const u8 = "" },
) ![]u8 {
    const buildTar = struct {
        fn writeHeader(w: anytype, name: []const u8, size: usize, mode: u32, typeflag: u8, linkname: []const u8) !void {
            var hdr: [512]u8 = @splat(0);
            const full_name = if (std.mem.startsWith(u8, name, "./") or std.mem.startsWith(u8, name, "/") or std.mem.startsWith(u8, name, ".."))
                name
            else
                name;
            @memcpy(hdr[0..full_name.len], full_name);
            _ = try std.fmt.bufPrint(hdr[100..107], "{o:0>7}", .{mode});
            _ = try std.fmt.bufPrint(hdr[108..115], "{o:0>7}", .{@as(u32, 0)});
            _ = try std.fmt.bufPrint(hdr[116..123], "{o:0>7}", .{@as(u32, 0)});
            _ = try std.fmt.bufPrint(hdr[124..135], "{o:0>11}", .{size});
            _ = try std.fmt.bufPrint(hdr[136..147], "{o:0>11}", .{@as(u32, 0)});
            @memset(hdr[148..156], ' ');
            hdr[156] = typeflag;
            if (linkname.len > 0) @memcpy(hdr[157 .. 157 + linkname.len], linkname);
            @memcpy(hdr[257..263], "ustar\x00");
            @memcpy(hdr[263..265], "00");
            var sum: u32 = 0;
            for (hdr) |b| sum += b;
            _ = try std.fmt.bufPrint(hdr[148..154], "{o:0>6}", .{sum});
            hdr[154] = 0;
            try w.writeAll(&hdr);
        }
        fn writeMember(w: anytype, name: []const u8, body: []const u8, mode: u32, typeflag: u8, linkname: []const u8) !void {
            const actual_body = if (typeflag == '0') body else "";
            try writeHeader(w, name, actual_body.len, mode, typeflag, linkname);
            if (actual_body.len > 0) {
                try w.writeAll(actual_body);
                const rem = actual_body.len % 512;
                if (rem != 0) {
                    const pad: [512]u8 = @splat(0);
                    try w.writeAll(pad[0 .. 512 - rem]);
                }
            }
        }
    };

    var ctrl_tar: std.ArrayList(u8) = .empty;
    const cw = arrayListWriter(&ctrl_tar, allocator);
    for (ctrl_entries) |ce| {
        const nm = if (std.mem.startsWith(u8, ce.name, "./")) ce.name else try std.fmt.allocPrint(allocator, "./{s}", .{ce.name});
        try buildTar.writeMember(cw, nm, ce.body, ce.mode, '0', "");
    }
    const zero_eof: [1024]u8 = @splat(0);
    try cw.writeAll(&zero_eof);

    var data_tar: std.ArrayList(u8) = .empty;
    const dw = arrayListWriter(&data_tar, allocator);
    for (data_entries) |de| {
        const nm = if (std.mem.startsWith(u8, de.name, "./") or std.mem.startsWith(u8, de.name, "/") or std.mem.startsWith(u8, de.name, ".."))
            de.name
        else
            try std.fmt.allocPrint(allocator, "./{s}", .{de.name});
        const tf: u8 = if (de.typeflag != '0') de.typeflag else if (std.mem.endsWith(u8, de.name, "/") or std.mem.eql(u8, de.name, ".")) '5' else '0';
        try buildTar.writeMember(dw, nm, de.body, de.mode, tf, de.linkname);
    }
    try dw.writeAll(&zero_eof);

    var ar_buf: std.ArrayList(u8) = .empty;
    const aw = arrayListWriter(&ar_buf, allocator);
    try aw.writeAll("!<arch>\n");
    const addAr = struct {
        fn call(w: anytype, name: []const u8, body: []const u8) !void {
            var hdr: [60]u8 = @splat(' ');
            @memcpy(hdr[0..name.len], name);
            _ = try std.fmt.bufPrint(hdr[16..28], "{d:<12}", .{@as(u32, 0)});
            _ = try std.fmt.bufPrint(hdr[28..34], "{d:<6}", .{@as(u32, 0)});
            _ = try std.fmt.bufPrint(hdr[34..40], "{d:<6}", .{@as(u32, 0)});
            _ = try std.fmt.bufPrint(hdr[40..48], "{d:<8}", .{@as(u32, 100644)});
            _ = try std.fmt.bufPrint(hdr[48..58], "{d:<10}", .{body.len});
            hdr[58] = '`';
            hdr[59] = '\n';
            try w.writeAll(&hdr);
            try w.writeAll(body);
            if (body.len % 2 == 1) try w.writeByte('\n');
        }
    }.call;
    try addAr(aw, "debian-binary", "2.0\n");
    try addAr(aw, "control.tar", ctrl_tar.items);
    try addAr(aw, "data.tar", data_tar.items);
    return ar_buf.toOwnedSlice(allocator);
}

test "TimeTests: recent snapshot, older snapshot, malformed timestamps, and default timestamp" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const t1 = try timestampSeconds(TEST_T1);
    const now = t1 + TEST_DAY - 1;
    try expectRepinFailsContaining(validateTimestamp(TEST_T1, now, null), "less than 24 hours old");
    try testing.expectEqual(t1, try validateTimestamp(TEST_T1, now + 1, null));

    const now2 = t1 + 10 * TEST_DAY;
    try expectRepinFailsContaining(validateTimestamp(TEST_T0, now2, TEST_T1), "older than the current pin");
    _ = try validateTimestamp(TEST_T1, now2, TEST_T1);

    for ([_][]const u8{ "20260927", "20260927T000000", "20261332T000000Z", "2026-09-27T00:00:00Z" }) |bad| {
        if (timestampSeconds(bad)) |_| return error.TestUnexpectedResult else |err| try testing.expectEqual(error.RepinFailed, err);
    }

    const now3 = try timestampSeconds("20260928T153000Z");
    const def_ts = try defaultTimestamp(alloc, now3);
    try testing.expectEqualStrings(TEST_T1, def_ts);
    _ = try validateTimestamp(def_ts, now3, null);
}

test "ReleaseTests: cleartext dash escapes, malformed cleartext, and release fields" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const data =
        "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA512\r\n\r\n" ++
        "Suite: stable\r\n- -escaped\r\nDate: x\r\n" ++
        "-----BEGIN PGP SIGNATURE-----\r\n\r\nwgA=\r\n-----END PGP SIGNATURE-----\r\n";
    try testing.expectEqualStrings("Suite: stable\r\n-escaped\r\nDate: x\r\n", try inReleaseCleartext(alloc, data));

    const header = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n";
    try expectRepinFailsContaining(inReleaseCleartext(alloc, "Suite: stable\n"), "cleartext signature header");
    try expectRepinFailsContaining(inReleaseCleartext(alloc, header ++ "Suite: stable\n"), "no signature block");
    try expectRepinFailsContaining(inReleaseCleartext(alloc, header ++ "-bad\n-----BEGIN PGP SIGNATURE-----\n"), "invalid dash escape");
    try expectRepinFailsContaining(inReleaseCleartext(alloc, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n"), "no blank line");

    const fields = try releaseFields(
        alloc,
        "Origin: Ubuntu\nSuite: stable\nCodename: stable\nDate: Sun, 26 Sep 2026 23:00:00 UTC\n" ++
            "Valid-Until: Sun, 03 Oct 2026 23:00:00 UTC\nSHA256:\n abc 1 main/Packages\n",
    );
    const t1 = try timestampSeconds(TEST_T1);
    try testing.expectEqual(t1 - 3600, fields.date_unix);
    try testing.expectEqual(t1 - 3600 + 7 * TEST_DAY, fields.valid_until_unix.?);
    try testing.expectEqual(@as(usize, 1), fields.hash_fields.len);
    try testing.expectEqualStrings("SHA256", fields.hash_fields[0]);

    try expectRepinFailsContaining(releaseFields(alloc, "Suite: stable\nDate: Sun, 26 Sep 2026 23:00:00 +0200\n"), "RFC 2822 UTC");
    try expectRepinFailsContaining(releaseFields(alloc, "Suite: stable\n"), "no Date");
    try expectRepinFailsContaining(releaseFields(alloc, "Date: Sun, 26 Sep 2026 23:00:00 UTC\nDate: Sun, 26 Sep 2026 23:00:00 UTC\n"), "duplicate");
}

test "DateTests: frozen deadline, future date, stale witness, frozen valid_until, and missing witness" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const snap = try timestampSeconds(TEST_T1);
    const makePockets = struct {
        fn call(a: std.mem.Allocator, s: i64) ![3]std.json.Value {
            var p0: std.json.ObjectMap = .empty;
            try p0.put(a, "suite", .{ .string = "r" });
            try p0.put(a, "role", .{ .string = "frozen" });
            try p0.put(a, "date", .{ .string = "f" });
            try p0.put(a, "date_unix", .{ .integer = s - 180 * TEST_DAY });
            try p0.put(a, "valid_until", .null);
            try p0.put(a, "valid_until_unix", .null);

            var p1: std.json.ObjectMap = .empty;
            try p1.put(a, "suite", .{ .string = "r-updates" });
            try p1.put(a, "role", .{ .string = "witness" });
            try p1.put(a, "date", .{ .string = "u" });
            try p1.put(a, "date_unix", .{ .integer = s - 3600 });
            try p1.put(a, "valid_until", .null);
            try p1.put(a, "valid_until_unix", .null);

            var p2: std.json.ObjectMap = .empty;
            try p2.put(a, "suite", .{ .string = "r-security" });
            try p2.put(a, "role", .{ .string = "witness" });
            try p2.put(a, "date", .{ .string = "s" });
            try p2.put(a, "date_unix", .{ .integer = s - 7200 });
            try p2.put(a, "valid_until", .{ .string = "v" });
            try p2.put(a, "valid_until_unix", .{ .integer = s + 5 * TEST_DAY });

            return .{ .{ .object = p0 }, .{ .object = p1 }, .{ .object = p2 } };
        }
    }.call;

    var pockets = try makePockets(alloc, snap);
    const deadline = try checkPocketDates(alloc, &pockets, snap);
    try testing.expectEqual(snap + 5 * TEST_DAY, pockets[0].object.get("deadline").?.integer);
    try testing.expectEqual(snap - 3600 + MAXIMUM_RELEASE_AGE_SECONDS, pockets[1].object.get("deadline").?.integer);
    try testing.expectEqual(snap + 5 * TEST_DAY, deadline);

    var p_future = try makePockets(alloc, snap);
    try p_future[1].object.put(alloc, "date_unix", .{ .integer = snap + 1 });
    try expectRepinFailsContaining(checkPocketDates(alloc, &p_future, snap), "after the snapshot time");

    var p_stale = try makePockets(alloc, snap);
    try p_stale[2].object.put(alloc, "date_unix", .{ .integer = snap - WITNESS_WINDOW_SECONDS - 1 });
    try expectRepinFailsContaining(checkPocketDates(alloc, &p_stale, snap), "more than 48 hours");

    var p_fvu = try makePockets(alloc, snap);
    try p_fvu[0].object.put(alloc, "valid_until", .{ .string = "x" });
    try expectRepinFailsContaining(checkPocketDates(alloc, &p_fvu, snap), "frozen pocket r carries Valid-Until");

    var p_nowit = try makePockets(alloc, snap);
    try expectRepinFailsContaining(checkPocketDates(alloc, p_nowit[0..1], snap), "requires at least one witness");
}

test "ManifestTests: strict fields, built-in profiles, and committed manifest check" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    _ = try validateManifest(alloc, try testManifest(alloc));

    // Unknown field
    var m1 = try testManifest(alloc);
    try m1.object.put(alloc, "extra", .{ .integer = 1 });
    try expectRepinFailsContaining(validateManifest(alloc, m1), "unknown");

    // Untagged digest
    var m2 = try testManifest(alloc);
    const script_hex = sha256HexLower(TEST_SCRIPT);
    try m2.object.getPtr("identities").?.array.items[0].object.put(alloc, "digest", .{ .string = &script_hex });
    try expectRepinFailsContaining(validateManifest(alloc, m2), "algorithm-tagged");

    // Wrong digest algorithm for script member
    var m3 = try testManifest(alloc);
    try m3.object.getPtr("identities").?.array.items[0].object.put(alloc, "digest", .{ .string = try testTaggedSha512(alloc, TEST_SCRIPT) });
    try expectRepinFailsContaining(validateManifest(alloc, m3), "members bind SHA-256");

    // version_bound requires recorded provenance
    var m4 = try testManifest(alloc);
    try m4.object.getPtr("identities").?.array.items[0].object.put(alloc, "version_bound", .{ .bool = true });
    try expectRepinFailsContaining(validateManifest(alloc, m4), "version_bound requires recorded provenance");

    // Built-in profiles cannot be replaced
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testTmpRoot(alloc, &tmp);
    const p_path = try std.fs.path.join(alloc, &.{ root, "profile.json" });
    var rep_prof = try testProfile(alloc);
    try rep_prof.object.put(alloc, "name", .{ .string = "ubuntu-stonking" });
    try writeJson(alloc, p_path, rep_prof);
    try expectRepinFailsContaining(resolveProfile(alloc, "ubuntu-stonking", p_path), "cannot be replaced");
    const res_prof = try resolveProfile(alloc, "ubuntu-resolute", null);
    try testing.expectEqualStrings("frozen", res_prof.object.get("pockets").?.array.items[0].object.get("role").?.string);

    // Committed manifest checks against the tree
    const committed = try validateManifest(alloc, try loadJson(alloc, DEFAULT_MANIFEST));
    const failures = try checkManifest(alloc, committed, ".", null);
    try testing.expectEqual(@as(usize, 0), failures.len);
}

test "StatusTests and LockPackageTests" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const base = try testIdentity(alloc);
    var obs_map: std.json.ObjectMap = .empty;
    try obs_map.put(alloc, "amd64", try testObserved(alloc, null, null, "0755", "1.0", null));
    try testing.expectEqualStrings("provenance-only", (try identityStatus(alloc, base, .{ .object = obs_map })).status);

    var recorded = try cloneJsonValue(alloc, base);
    try recorded.object.put(alloc, "provenance", try parseJsonTest(
        alloc,
        try std.fmt.allocPrint(alloc, "{{\"version\":\"1.0\",\"archives\":{{\"amd64\":\"{s}\"}}}}", .{try testTaggedSha512(alloc, "1.0")}),
    ));
    try testing.expectEqualStrings("unchanged", (try identityStatus(alloc, recorded, .{ .object = obs_map })).status);

    var obs_rebuilt: std.json.ObjectMap = .empty;
    try obs_rebuilt.put(alloc, "amd64", try testObserved(alloc, null, null, "0755", "1.0", try testTaggedSha512(alloc, "rebuild")));
    try testing.expectEqualStrings("provenance-only", (try identityStatus(alloc, recorded, .{ .object = obs_rebuilt })).status);

    var obs_changed: std.json.ObjectMap = .empty;
    try obs_changed.put(alloc, "amd64", try testObserved(alloc, try testTaggedSha256(alloc, "x"), null, "0755", "1.0", null));
    try testing.expectEqualStrings("changed", (try identityStatus(alloc, recorded, .{ .object = obs_changed })).status);

    var version_bound = try cloneJsonValue(alloc, recorded);
    try version_bound.object.put(alloc, "version_bound", .{ .bool = true });
    var obs_v11: std.json.ObjectMap = .empty;
    try obs_v11.put(alloc, "amd64", try testObserved(alloc, null, null, "0755", "1.1", null));
    const st_vb = try identityStatus(alloc, version_bound, .{ .object = obs_v11 });
    try testing.expectEqualStrings("changed", st_vb.status);
    try expectAnyContains(st_vb.reasons, "version-bound identity moved");

    try testing.expectEqualStrings(
        "comments or whitespace only",
        try advisory(alloc, TEST_SCRIPT, "#!/bin/sh\nset -e\n# configured  \ntrue\n"),
    );
    try testing.expectEqualStrings(
        "behavioral change; review every hunk",
        try advisory(alloc, TEST_SCRIPT, "#!/bin/sh\nset -e\n# configure\nfalse\n"),
    );

    // LockPackageTests
    const lock = try parseJsonTest(alloc,
        \\{
        \\  "packages": [
        \\    {
        \\      "name": "alpha", "version": "1.0", "architecture": "amd64", "declared_size": 1,
        \\      "origin": {"repository_id": "repo"},
        \\      "archive_identity": {"primary": "sha512", "digests": [{"algorithm": "sha512", "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}
        \\    },
        \\    {
        \\      "name": "beta", "version": "1.0", "architecture": "amd64", "declared_size": 1,
        \\      "origin": {"repository_id": "repo"},
        \\      "archive_identity": {"primary": "sha256", "digests": [{"algorithm": "sha256", "digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}
        \\    }
        \\  ]
        \\}
    );
    var pockets_by_id = std.StringHashMap([]const u8).init(alloc);
    try pockets_by_id.put("repo", "stable");
    const packages = try lockPackages(alloc, lock, pockets_by_id);
    try expectRepinFailsContaining(
        requireSha512(alloc, packages, "amd64"),
        "amd64 closure packages without a signed SHA-512 archive identity: beta 1.0",
    );
}

test "RecordTests: provenance, changed review, version bound, series migration, and frozen release acceptance" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const value = try testManifest(alloc);
    var ids_obj: std.json.ObjectMap = .empty;
    var amd64_obs: std.json.ObjectMap = .empty;
    try amd64_obs.put(alloc, "amd64", try testObserved(alloc, null, null, "0755", "1.0", null));
    try ids_obj.put(alloc, "script:alpha/postinst", .{ .object = amd64_obs });
    const rep = try testReport(alloc, .{ .object = ids_obj }, null, TEST_T1);
    const diff = try computeDiff(alloc, value, rep, ".", ".", false);
    const empty_reviews = ManagedStringArrayHashMap([]const u8).init(alloc);
    const updated = try recordManifest(alloc, value, rep, diff, empty_reviews, null, false);
    try testing.expectEqualStrings("probed", updated.object.get("snapshot").?.object.get("status").?.string);

    // Changed identity requires review
    const changed_script = "#!/bin/sh\nexit 1\n";
    var ids_changed: std.json.ObjectMap = .empty;
    var amd64_changed: std.json.ObjectMap = .empty;
    try amd64_changed.put(
        alloc,
        "amd64",
        try testObserved(alloc, try testTaggedSha256(alloc, changed_script), @intCast(changed_script.len), "0755", "1.0", null),
    );
    try ids_changed.put(alloc, "script:alpha/postinst", .{ .object = amd64_changed });
    const rep_changed = try testReport(alloc, .{ .object = ids_changed }, null, TEST_T1);
    const diff_changed = try computeDiff(alloc, value, rep_changed, ".", ".", false);
    try expectRepinFailsContaining(
        recordManifest(alloc, value, rep_changed, diff_changed, empty_reviews, null, false),
        "changed without re-review: script:alpha/postinst",
    );
    const ok_reviews = try parseReviews(alloc, &.{"script:alpha/postinst=cataggar/debz#2"});
    const updated_changed = try recordManifest(alloc, value, rep_changed, diff_changed, ok_reviews, null, false);
    try testing.expectEqualStrings(
        try testTaggedSha256(alloc, changed_script),
        updated_changed.object.get("identities").?.array.items[0].object.get("digest").?.string,
    );

    // Frozen release change requires acceptance
    const p_frozen = try testPocket(alloc, "r", "frozen", "frozen-1", "exact_lock");
    const p_witness = try testPocket(alloc, "r-updates", "witness", "updates", "exact_lock");
    var m_frozen = try testManifest(alloc);
    try m_frozen.object.getPtr("series").?.object.put(
        alloc,
        "pockets",
        (try parseJsonTest(alloc, "[{\"suite\":\"r\",\"role\":\"frozen\"},{\"suite\":\"r-updates\",\"role\":\"witness\"}]")),
    );
    const rep_frozen = try testReport(alloc, .{ .object = ids_obj }, &.{ p_frozen, p_witness }, TEST_T1);
    const diff_frozen = try computeDiff(alloc, m_frozen, rep_frozen, ".", ".", false);
    try expectRepinFailsContaining(
        recordManifest(alloc, m_frozen, rep_frozen, diff_frozen, empty_reviews, null, false),
        "frozen release changed",
    );
    const first_frozen = try recordManifest(alloc, m_frozen, rep_frozen, diff_frozen, empty_reviews, "#330", false);
    try testing.expectEqualStrings("#330", first_frozen.object.get("snapshot").?.object.get("pockets").?.array.items[0].object.get("review").?.string);
}

test "CheckTests and CoordinateTests" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testTmpRoot(alloc, &tmp);

    try writeFileBytes(try std.fs.path.join(alloc, &.{ root, "src/fixtures/ubuntu-synthetic-alpha-1.0.postinst" }), TEST_SCRIPT);
    var sha_bytes: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(TEST_SCRIPT, &sha_bytes, .{});
    var zb_parts: std.ArrayList([]const u8) = .empty;
    for (sha_bytes) |b| try zb_parts.append(alloc, try std.fmt.allocPrint(alloc, "0x{x:0>2}", .{b}));
    const zig_bytes = try std.mem.join(alloc, ", ", zb_parts.items);
    const tool_hex = sha256HexLower(TEST_TOOL);
    const script_hex = sha256HexLower(TEST_SCRIPT);

    const ms_src = try std.fmt.allocPrint(
        alloc,
        "const snapshot_alpha_sha256 = [32]" ++ "u8{{ {s} }};\n" ++
            "const inputs = .{{ .{{ .path = \"usr/bin/beta\", .size = {d}, .mode = 0o755, .sha256 = \"{s}\" }} }};\n// alpha 1.0\n",
        .{ zig_bytes, TEST_TOOL.len, tool_hex },
    );
    try writeFileBytes(try std.fs.path.join(alloc, &.{ root, "src/maintainer_script.zig" }), ms_src);
    try writeFileBytes(
        try std.fs.path.join(alloc, &.{ root, "tools/real-snapshot-synthetic.sh" }),
        try std.fmt.allocPrint(alloc, "uri=file:///synthetic/snapshot/{s}\nalpha={s}\n", .{ TEST_T0, script_hex }),
    );

    var m = try testManifest(alloc);
    try m.object.put(alloc, "uri_consumers", try parseJsonTest(alloc, "[\"tools/real-snapshot-synthetic.sh\"]"));
    var id0 = try testIdentity(alloc);
    try id0.object.put(alloc, "consumers", try parseJsonTest(alloc,
        \\[
        \\  {"path": "src/fixtures/ubuntu-synthetic-alpha-1.0.postinst", "form": "fixture"},
        \\  {"path": "src/maintainer_script.zig", "form": "zig_bytes", "name": "snapshot_alpha_sha256"},
        \\  {"path": "tools/real-snapshot-synthetic.sh", "form": "hex"}
        \\]
    ));
    var id1 = try testIdentity(alloc);
    try id1.object.put(alloc, "id", .{ .string = "file:beta/usr/bin/beta" });
    try id1.object.put(alloc, "kind", .{ .string = "tool_file" });
    try id1.object.put(alloc, "package", .{ .string = "beta" });
    try id1.object.put(alloc, "path", .{ .string = "usr/bin/beta" });
    try id1.object.put(alloc, "digest", .{ .string = try testTaggedSha256(alloc, TEST_TOOL) });
    try id1.object.put(alloc, "size", .{ .integer = @intCast(TEST_TOOL.len) });
    try id1.object.put(alloc, "consumers", try parseJsonTest(alloc, "[{\"path\": \"src/maintainer_script.zig\", \"form\": \"hex\"}]"));
    var ids = std.json.Array.init(alloc);
    try ids.append(id0);
    try ids.append(id1);
    try m.object.put(alloc, "identities", .{ .array = ids });
    _ = try validateManifest(alloc, m);

    const f_ok = try checkManifest(alloc, m, root, m.object.get("series").?);
    try testing.expectEqual(@as(usize, 0), f_ok.len);

    // Mutate fixture
    try writeFileBytes(try std.fs.path.join(alloc, &.{ root, "src/fixtures/ubuntu-synthetic-alpha-1.0.postinst" }), TEST_SCRIPT ++ "\n");
    const f_mut = try checkManifest(alloc, m, root, m.object.get("series").?);
    try expectAnyContains(f_mut, "bytes do not match");
}

test "PackageTests: tar_member, hardlinks, dpkg_ownership_list, and malformed ar" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const d = try makeSyntheticDeb(
        alloc,
        &.{.{ .name = "postinst", .body = TEST_SCRIPT, .mode = 0o755 }},
        &.{
            .{ .name = ".", .body = "", .mode = 0o755, .typeflag = '5' },
            .{ .name = "usr", .body = "", .mode = 0o755, .typeflag = '5' },
            .{ .name = "usr/bin/beta", .body = TEST_TOOL, .mode = 0o4755 },
            .{ .name = "usr/share/doc/beta/", .body = "", .mode = 0o755, .typeflag = '5' },
        },
    );
    const m_post = try tarMember(alloc, d, "control.tar", "postinst");
    try testing.expectEqualStrings(TEST_SCRIPT, m_post.bytes);
    try testing.expectEqual(@as(u32, 0o755), m_post.mode);

    const m_beta = try tarMember(alloc, d, "data.tar", "usr/bin/beta");
    try testing.expectEqualStrings(TEST_TOOL, m_beta.bytes);
    try testing.expectEqual(@as(u32, 0o4755), m_beta.mode);

    try expectRepinFailsContaining(tarMember(alloc, d, "data.tar", "usr/bin/gamma"), "has no member");

    const list_bytes = try dpkgOwnershipList(alloc, d);
    try testing.expectEqualStrings("/.\n/usr\n/usr/bin/beta\n/usr/share/doc/beta\n", list_bytes);

    try expectRepinFailsContaining(arMembers(alloc, "not a deb"), "not an ar archive");
    try expectRepinFailsContaining(arMembers(alloc, d[0 .. d.len - 40]), "truncated or duplicate");
}

test "ArchitectureBindingTests, MemberBindingTests, and SourceEvidenceTests against committed evidence" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var manifest = try loadJson(alloc, DEFAULT_MANIFEST);
    const evidence = try readSourceFile(alloc, manifest.object.get("prestate_evidence").?.string, ".", maximum_evidence_bytes, "committed source evidence");
    const now = manifest.object.get("snapshot").?.object.get("admission_deadline").?.integer - 1;

    // 1. ArchitectureBindingTests: remove arm64 from script:less/postinst and rebind from evidence
    for (manifest.object.getPtr("identities").?.array.items) |*item| {
        if (std.mem.eql(u8, item.object.get("id").?.string, "script:less/postinst")) {
            var archs = std.json.Array.init(alloc);
            try archs.append(.{ .string = "amd64" });
            try item.object.put(alloc, "architectures", .{ .array = archs });
            _ = item.object.getPtr("provenance").?.object.getPtr("archives").?.object.swapRemove("arm64");
        }
    }
    const rebound = try bindArchitecture(alloc, manifest, "script:less/postinst", "arm64", "#393", evidence, now);
    const ev_failures = try checkPrestateEvidence(alloc, rebound, evidence);
    try testing.expectEqual(@as(usize, 0), ev_failures.len);

    // 2. MemberBindingTests: remove file:less/* and rebind usr/bin/less from archive:less@arm64
    var filtered_ids = std.json.Array.init(alloc);
    for (rebound.object.get("identities").?.array.items) |item| {
        if (!std.mem.startsWith(u8, item.object.get("id").?.string, "file:less/")) {
            try filtered_ids.append(item);
        }
    }
    var m_for_member = try cloneJsonValue(alloc, rebound);
    try m_for_member.object.put(alloc, "identities", .{ .array = filtered_ids });
    const member_bound = try bindMember(
        alloc,
        m_for_member,
        "archive:less@arm64",
        "usr/bin/less",
        &.{"src/native_unpack.zig"},
        "#393",
        evidence,
        now,
    );
    try testing.expectEqual(@as(usize, 0), (try checkPrestateEvidence(alloc, member_bound, evidence)).len);
    try expectRepinFailsContaining(
        bindMember(alloc, member_bound, "archive:less@arm64", "usr/bin/less", &.{"src/native_unpack.zig"}, "#393", evidence, now),
        "already exists",
    );
}

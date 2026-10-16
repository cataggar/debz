//! Offline strace execve/execveat lineage, argument-shape, and root-identity
//! auditor for the real-snapshot native acceptance lane.
const std = @import("std");
const linux = std.os.linux;

const maximum_trace_bytes = 256 * 1024 * 1024;
const maximum_status_bytes = 64 * 1024 * 1024;
const maximum_lineage_depth = 4096;
const maximum_symlink_hops = 40;
const maximum_printed_refusals = 200;

const Tool = enum(usize) {
    dpkg = 0,
    dpkg_divert = 1,
    dpkg_statoverride = 2,

    const all = [_]Tool{ .dpkg, .dpkg_divert, .dpkg_statoverride };

    fn name(self: Tool) []const u8 {
        return switch (self) {
            .dpkg => "dpkg",
            .dpkg_divert => "dpkg-divert",
            .dpkg_statoverride => "dpkg-statoverride",
        };
    }

    fn recordName(self: Tool) []const u8 {
        return switch (self) {
            .dpkg => "script_dpkg",
            .dpkg_divert => "script_dpkg_divert",
            .dpkg_statoverride => "script_dpkg_statoverride",
        };
    }

    fn fromName(raw: []const u8) ?Tool {
        for (all) |tool| {
            if (std.mem.eql(u8, raw, tool.name())) return tool;
        }
        return null;
    }

    fn fromPath(path: []const u8) ?Tool {
        const prefix = "/usr/bin/";
        if (!std.mem.startsWith(u8, path, prefix)) return null;
        return fromName(path[prefix.len..]);
    }
};

const dpkg_actions = [_][]const u8{
    "--compare-versions",
    "--validate-version",
    "--print-architecture",
    "-s",
    "-L",
    "-l",
};

const refused_options = [_][]const u8{
    "--root",
    "--admindir",
    "--instdir",
    "--force",
};

const shadow_directories = [_][]const u8{
    "usr/local/sbin",
    "usr/local/bin",
    "usr/sbin",
    "sbin",
};

const fresh_divert_shapes = [_][]const []const u8{
    &.{ "--quiet", "--package", "NAME", "--add", "--no-rename", "--divert", "MERGED", "PATH" },
    &.{ "--quiet", "--package", "NAME", "--remove", "--no-rename", "--divert", "MERGED", "PATH" },
    &.{ "--quiet", "--add", "--no-rename", "--package", "NAME", "--divert", "MERGED", "PATH" },
    &.{ "--quiet", "--add", "--no-rename", "--divert", "MERGED", "PATH" },
    &.{ "--package", "NAME", "--no-rename", "--divert", "MERGED", "--add", "PATH" },
    &.{ "--package", "NAME", "--no-rename", "--divert", "MERGED", "PATH" },
    &.{ "--no-rename", "--divert", "MERGED", "--add", "PATH" },
    &.{ "--no-rename", "--divert", "MERGED", "--remove", "PATH" },
    &.{ "--package", "NAME", "--divert", "BACKUP", "--no-rename", "--remove", "PATH" },
    &.{ "--truename", "PATH" },
    &.{ "--listpackage", "PATH" },
};

const fresh_statoverride_shapes = [_][]const []const u8{
    &.{ "--list", "PATH" },
    &.{ "--update", "--add", "ACCOUNT", "ACCOUNT", "MODE", "PATH" },
};

const ScriptAction = enum {
    preinst,
    postinst,
    prerm,
    postrm,
};

const LifecyclePhaseRule = enum {
    upgrade_or_remove,
    prerm_remove,
    postinst_or_postrm_cleanup,
    postinst_upgrade,
    statoverride_remove,
};

const LifecycleShape = struct {
    words: []const []const u8,
    rule: LifecyclePhaseRule,
};

const lifecycle_divert_shapes = [_]LifecycleShape{
    .{
        .words = &.{ "--rename", "--package", "NAME", "--divert", "MERGED", "--remove", "PATH" },
        .rule = .upgrade_or_remove,
    },
    .{
        .words = &.{ "--package", "NAME", "--rename", "--remove", "PATH" },
        .rule = .upgrade_or_remove,
    },
    .{
        .words = &.{ "--package", "NAME", "--no-rename", "--remove", "PATH" },
        .rule = .upgrade_or_remove,
    },
    .{
        .words = &.{ "--package", "NAME", "--divert", "BACKUP", "--rename", "--remove", "PATH" },
        .rule = .postinst_or_postrm_cleanup,
    },
    .{
        .words = &.{ "--package", "NAME", "--divert", "BACKUP", "--no-rename", "--add", "PATH" },
        .rule = .prerm_remove,
    },
    .{
        .words = &.{ "--quiet", "--local", "--remove", "--no-rename", "PATH" },
        .rule = .postinst_upgrade,
    },
    .{
        .words = &.{ "--list", "PATH" },
        .rule = .postinst_upgrade,
    },
};

const lifecycle_statoverride_shapes = [_]LifecycleShape{
    .{
        .words = &.{ "--remove", "PATH" },
        .rule = .statoverride_remove,
    },
};

const IdentityPin = struct {
    digest: []const u8,
    size: u64,
};

const ParsedIdentities = [Tool.all.len]IdentityPin;

fn parseIdentities(raw: []const u8) ?ParsedIdentities {
    var result: ParsedIdentities = undefined;
    var seen: [Tool.all.len]bool = @splat(false);
    var count: usize = 0;
    var words = std.mem.tokenizeAny(u8, raw, " \t\n\r");
    while (words.next()) |word| {
        count += 1;
        const eq = std.mem.indexOfScalar(u8, word, '=') orelse return null;
        const tool_name = word[0..eq];
        const value = word[eq + 1 ..];
        const colon = std.mem.indexOfScalar(u8, value, ':') orelse return null;
        const digest = value[0..colon];
        const size_text = value[colon + 1 ..];
        if (digest.len == 0 or size_text.len == 0) return null;
        const tool = Tool.fromName(tool_name) orelse return null;
        const idx = @intFromEnum(tool);
        if (seen[idx]) return null;
        for (size_text) |ch| {
            if (!std.ascii.isDigit(ch)) return null;
        }
        const size = std.fmt.parseInt(u64, size_text, 10) catch return null;
        seen[idx] = true;
        result[idx] = .{ .digest = digest, .size = size };
    }
    if (count != Tool.all.len) return null;
    for (seen) |present| {
        if (!present) return null;
    }
    return result;
}

const CString = struct {
    value: []const u8,
    next_index: usize,
    truncated: bool,
};

fn parseCString(allocator: std.mem.Allocator, text: []const u8, start: usize) !CString {
    if (start >= text.len or text[start] != '"') return error.InvalidCString;
    var out: std.ArrayList(u8) = .empty;
    var index = start + 1;
    while (index < text.len) {
        const ch = text[index];
        if (ch == '"') {
            index += 1;
            const truncated = std.mem.startsWith(u8, text[index..], "...");
            return .{
                .value = try out.toOwnedSlice(allocator),
                .next_index = index + (if (truncated) @as(usize, 3) else 0),
                .truncated = truncated,
            };
        }
        if (ch != '\\') {
            try out.append(allocator, ch);
            index += 1;
            continue;
        }
        if (index + 1 >= text.len) return error.UnterminatedCString;
        const esc = text[index + 1];
        const mapped: ?u8 = switch (esc) {
            'n' => 10,
            't' => 9,
            'r' => 13,
            'v' => 11,
            'f' => 12,
            'a' => 7,
            'b' => 8,
            '\\' => 92,
            '"' => 34,
            '\'' => 39,
            else => null,
        };
        if (mapped) |byte| {
            try out.append(allocator, byte);
            index += 2;
            continue;
        }
        if (esc == 'x') {
            if (index + 4 > text.len) return error.InvalidHexEscape;
            const hex = text[index + 2 .. index + 4];
            if (!std.ascii.isHex(hex[0]) or !std.ascii.isHex(hex[1])) return error.InvalidHexEscape;
            const byte = try std.fmt.parseInt(u8, hex, 16);
            try out.append(allocator, byte);
            index += 4;
            continue;
        }
        if (esc >= '0' and esc <= '7') {
            var end = index + 1;
            const limit = @min(text.len, index + 4);
            while (end < limit and text[end] >= '0' and text[end] <= '7') : (end += 1) {}
            const oct = try std.fmt.parseInt(u16, text[index + 1 .. end], 8);
            try out.append(allocator, @truncate(oct));
            index = end;
            continue;
        }
        return error.UnknownEscape;
    }
    return error.UnterminatedCString;
}

const ParsedExecve = struct {
    path: []const u8,
    argv: []const []const u8,
    result: []const u8,
    truncated: bool,
};

fn parseExecveTail(tail: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, tail, ", ")) return null;
    var index: usize = 2;
    if (std.mem.startsWith(u8, tail[index..], "NULL")) {
        index += 4;
    } else if (std.mem.startsWith(u8, tail[index..], "0x")) {
        index += 2;
        const hex_start = index;
        while (index < tail.len and ((tail[index] >= '0' and tail[index] <= '9') or (tail[index] >= 'a' and tail[index] <= 'f'))) : (index += 1) {}
        if (index == hex_start) return null;
    } else {
        return null;
    }
    if (std.mem.startsWith(u8, tail[index..], " /* ")) {
        index += 4;
        const digits_start = index;
        while (index < tail.len and std.ascii.isDigit(tail[index])) : (index += 1) {}
        if (index == digits_start) return null;
        if (!std.mem.startsWith(u8, tail[index..], " var")) return null;
        index += 4;
        if (index < tail.len and tail[index] == 's') index += 1;
        if (!std.mem.startsWith(u8, tail[index..], " */")) return null;
        index += 3;
    }
    if (std.mem.eql(u8, tail[index..], " <unfinished>")) return "?";
    if (index >= tail.len or tail[index] != ')') return null;
    index += 1;
    while (index < tail.len and std.ascii.isWhitespace(tail[index])) : (index += 1) {}
    if (index >= tail.len or tail[index] != '=') return null;
    index += 1;
    while (index < tail.len and std.ascii.isWhitespace(tail[index])) : (index += 1) {}
    if (index >= tail.len) return null;
    if (tail[index] == '0' or tail[index] == '?') {
        const token = tail[index .. index + 1];
        index += 1;
        if (index == tail.len or tail[index] == ' ') return token;
        return null;
    }
    if (std.mem.startsWith(u8, tail[index..], "-1 ")) {
        const token_start = index;
        index += 3;
        const code_start = index;
        while (index < tail.len and (std.ascii.isUpper(tail[index]) or std.ascii.isDigit(tail[index]))) : (index += 1) {}
        if (index == code_start) return null;
        const token = tail[token_start..index];
        if (index == tail.len or tail[index] == ' ') return token;
        return null;
    }
    return null;
}

fn parseExecve(allocator: std.mem.Allocator, text: []const u8) ?ParsedExecve {
    if (!std.mem.startsWith(u8, text, "execve(\"")) return null;
    const path_parsed = parseCString(allocator, text, "execve(".len) catch return null;
    var index = path_parsed.next_index;
    var truncated = path_parsed.truncated;
    if (!std.mem.startsWith(u8, text[index..], ", [")) return null;
    index += 3;
    var argv: std.ArrayList([]const u8) = .empty;
    if (std.mem.startsWith(u8, text[index..], "]")) {
        index += 1;
    } else {
        while (true) {
            if (std.mem.startsWith(u8, text[index..], "...")) {
                truncated = true;
                index += 3;
            } else if (index < text.len and text[index] == '"') {
                const arg_parsed = parseCString(allocator, text, index) catch return null;
                argv.append(allocator, arg_parsed.value) catch return null;
                index = arg_parsed.next_index;
                truncated = truncated or arg_parsed.truncated;
            } else {
                return null;
            }
            if (std.mem.startsWith(u8, text[index..], ", ")) {
                index += 2;
            } else if (std.mem.startsWith(u8, text[index..], "]")) {
                index += 1;
                break;
            } else {
                return null;
            }
        }
    }
    const result = parseExecveTail(text[index..]) orelse return null;
    return .{
        .path = path_parsed.value,
        .argv = argv.toOwnedSlice(allocator) catch return null,
        .result = result,
        .truncated = truncated,
    };
}

fn isDpkgBinaryName(name: []const u8) bool {
    return std.mem.eql(u8, name, "dpkg") or
        std.mem.eql(u8, name, "dpkg-deb") or
        std.mem.eql(u8, name, "dpkg-divert") or
        std.mem.eql(u8, name, "dpkg-statoverride");
}

fn isQuotedDpkgPath(quoted_body: []const u8) bool {
    const base = if (std.mem.lastIndexOfScalar(u8, quoted_body, '/')) |slash|
        quoted_body[slash + 1 ..]
    else
        quoted_body;
    return isDpkgBinaryName(base);
}

fn isDpkgExecCandidate(raw: []const u8) bool {
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, raw, pos, "execve(\"")) |idx| {
        const start = idx + "execve(\"".len;
        if (std.mem.indexOfScalarPos(u8, raw, start, '"')) |end| {
            if (isQuotedDpkgPath(raw[start..end])) return true;
        }
        pos = idx + 1;
    }
    pos = 0;
    while (std.mem.indexOfPos(u8, raw, pos, "execveat(")) |idx| {
        const after = idx + "execveat(".len;
        if (std.mem.indexOfScalarPos(u8, raw, after, ',')) |comma| {
            if (comma > after and std.mem.startsWith(u8, raw[comma..], ", \"")) {
                const path_start = comma + 3;
                if (std.mem.indexOfScalarPos(u8, raw, path_start, '"')) |path_end| {
                    if (isQuotedDpkgPath(raw[path_start..path_end])) return true;
                }
            }
            const first_arg = raw[after..comma];
            if (std.mem.indexOf(u8, first_arg, "</")) |lt| {
                const desc_path_start = lt + 1;
                if (std.mem.indexOfScalarPos(u8, first_arg, desc_path_start, '>')) |gt| {
                    if (gt == first_arg.len - 1 and std.mem.startsWith(u8, raw[comma..], ", \"\"")) {
                        const desc_path = first_arg[desc_path_start..gt];
                        if (std.mem.lastIndexOfScalar(u8, desc_path, '/')) |slash| {
                            if (isDpkgBinaryName(desc_path[slash + 1 ..])) return true;
                        }
                    }
                }
            }
        }
        pos = idx + 1;
    }
    return false;
}

const LineMatch = struct {
    pid: u64,
    rest: []const u8,
};

fn matchLine(raw: []const u8) ?LineMatch {
    var i: usize = 0;
    while (i < raw.len and std.ascii.isDigit(raw[i])) : (i += 1) {}
    if (i == 0 or i >= raw.len or raw[i] != ' ') return null;
    const pid = std.fmt.parseInt(u64, raw[0..i], 10) catch return null;
    while (i < raw.len and raw[i] == ' ') : (i += 1) {}
    return .{ .pid = pid, .rest = raw[i..] };
}

fn matchSuperseded(rest: []const u8) ?u64 {
    const prefix = "+++ superseded by execve in pid ";
    const suffix = " +++";
    if (!std.mem.startsWith(u8, rest, prefix) or !std.mem.endsWith(u8, rest, suffix)) return null;
    if (rest.len <= prefix.len + suffix.len) return null;
    const digits = rest[prefix.len .. rest.len - suffix.len];
    for (digits) |ch| {
        if (!std.ascii.isDigit(ch)) return null;
    }
    return std.fmt.parseInt(u64, digits, 10) catch null;
}

const ResumedMatch = struct {
    call: []const u8,
    tail: []const u8,
};

fn isCallChar(ch: u8) bool {
    return (ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '_';
}

fn matchResumed(rest: []const u8) ?ResumedMatch {
    const prefix = "<... ";
    const mid = " resumed>";
    if (!std.mem.startsWith(u8, rest, prefix)) return null;
    var i: usize = prefix.len;
    while (i < rest.len and isCallChar(rest[i])) : (i += 1) {}
    if (i == prefix.len) return null;
    if (!std.mem.startsWith(u8, rest[i..], mid)) return null;
    return .{
        .call = rest[prefix.len..i],
        .tail = rest[i + mid.len ..],
    };
}

fn matchCallName(rest: []const u8) []const u8 {
    var i: usize = 0;
    while (i < rest.len and isCallChar(rest[i])) : (i += 1) {}
    if (i > 0 and i < rest.len and rest[i] == '(') return rest[0..i];
    return "";
}

fn matchChildPid(text: []const u8) ?u64 {
    var end = text.len;
    while (end > 0 and std.ascii.isWhitespace(text[end - 1])) : (end -= 1) {}
    var pos: usize = 0;
    while (std.mem.indexOfScalarPos(u8, text[0..end], pos, ')')) |rparen| {
        var i = rparen + 1;
        while (i < end and std.ascii.isWhitespace(text[i])) : (i += 1) {}
        if (i < end and text[i] == '=') {
            i += 1;
            while (i < end and std.ascii.isWhitespace(text[i])) : (i += 1) {}
            const d1_start = i;
            while (i < end and std.ascii.isDigit(text[i])) : (i += 1) {}
            if (i > d1_start) {
                const first_pid = std.fmt.parseInt(u64, text[d1_start..i], 10) catch null;
                if (first_pid) |pid1| {
                    if (i == end) return pid1;
                    var j = i;
                    while (j < end and std.ascii.isWhitespace(text[j])) : (j += 1) {}
                    if (std.mem.startsWith(u8, text[j..end], "/* ")) {
                        j += 3;
                        const d2_start = j;
                        while (j < end and std.ascii.isDigit(text[j])) : (j += 1) {}
                        if (j > d2_start and std.mem.eql(u8, text[j..end], " in strace's PID NS */")) {
                            if (std.fmt.parseInt(u64, text[d2_start..j], 10)) |pid2| return pid2 else |_| {}
                        }
                    }
                }
            }
        }
        pos = rparen + 1;
    }
    return null;
}

fn parseScriptAction(path: []const u8) ?ScriptAction {
    const prefixes = [_][]const u8{
        "/var/lib/debz-lifecycle-scripts/",
        "/var/lib/dpkg/info/",
    };
    const tail = blk: {
        for (prefixes) |prefix| {
            if (std.mem.startsWith(u8, path, prefix)) break :blk path[prefix.len..];
        }
        return null;
    };
    const dot = std.mem.lastIndexOfScalar(u8, tail, '.') orelse return null;
    const action_text = tail[dot + 1 ..];
    const action: ScriptAction = if (std.mem.eql(u8, action_text, "preinst"))
        .preinst
    else if (std.mem.eql(u8, action_text, "postinst"))
        .postinst
    else if (std.mem.eql(u8, action_text, "prerm"))
        .prerm
    else if (std.mem.eql(u8, action_text, "postrm"))
        .postrm
    else
        return null;

    const stem = tail[0..dot];
    const pkg_part, const arch_part = if (std.mem.indexOfScalar(u8, stem, ':')) |colon|
        .{ stem[0..colon], stem[colon + 1 ..] }
    else
        .{ stem, null };

    if (pkg_part.len == 0) return null;
    if (!std.ascii.isLower(pkg_part[0]) and !std.ascii.isDigit(pkg_part[0])) return null;
    for (pkg_part[1..]) |ch| {
        if (!std.ascii.isLower(ch) and !std.ascii.isDigit(ch) and ch != '+' and ch != '.' and ch != '-') return null;
    }
    if (arch_part) |arch| {
        if (arch.len == 0) return null;
        for (arch) |ch| {
            if (!std.ascii.isLower(ch) and !std.ascii.isDigit(ch) and ch != '-') return null;
        }
    }
    return action;
}

const ScriptContext = struct {
    path: []const u8,
    pid: u64,
    action: ScriptAction,
    argv: []const []const u8,
};

fn isPackageName(value: []const u8) bool {
    if (value.len < 2) return false;
    if (!std.ascii.isLower(value[0]) and !std.ascii.isDigit(value[0])) return false;
    for (value[1..]) |ch| {
        if (!std.ascii.isLower(ch) and !std.ascii.isDigit(ch) and ch != '+' and ch != '.' and ch != '-') return false;
    }
    return true;
}

fn isAccountName(value: []const u8) bool {
    if (value.len == 0) return false;
    if (!std.ascii.isLower(value[0]) and value[0] != '_') return false;
    for (value[1..]) |ch| {
        if (!std.ascii.isLower(ch) and !std.ascii.isDigit(ch) and ch != '_' and ch != '-') return false;
    }
    return true;
}

fn isModeOperand(value: []const u8) bool {
    if (value.len != 4 or value[0] != '0') return false;
    for (value[1..]) |ch| {
        if (ch < '0' or ch > '7') return false;
    }
    return true;
}

fn isReviewedPath(value: []const u8) bool {
    if (value.len < 2 or value[0] != '/') return false;
    var parts = std.mem.splitScalar(u8, value[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
        for (part) |ch| {
            if (ch < '!' or ch > '~' or ch == '/') return false;
        }
    }
    return true;
}

fn matchesOperand(word: []const u8, value: []const u8, target: []const u8) bool {
    if (std.mem.eql(u8, word, "MERGED")) {
        const suffix = ".usr-is-merged";
        if (std.mem.startsWith(u8, value, target) and std.mem.eql(u8, value[target.len..], suffix)) {
            return true;
        }
        if (std.mem.count(u8, target, "/") == 1 and target.len > 1) {
            if (std.mem.startsWith(u8, value, "/.") and
                value.len == 2 + (target.len - 1) + suffix.len and
                std.mem.eql(u8, value[2 .. 2 + target.len - 1], target[1..]) and
                std.mem.eql(u8, value[2 + target.len - 1 ..], suffix))
            {
                return true;
            }
        }
        return false;
    }
    if (std.mem.eql(u8, word, "BACKUP")) {
        const suffix = ".remove-bak";
        return std.mem.startsWith(u8, value, target) and std.mem.eql(u8, value[target.len..], suffix);
    }
    if (std.mem.eql(u8, word, "PATH")) return isReviewedPath(value);
    if (std.mem.eql(u8, word, "NAME")) return isPackageName(value);
    if (std.mem.eql(u8, word, "ACCOUNT")) return isAccountName(value);
    if (std.mem.eql(u8, word, "MODE")) return isModeOperand(value);
    return false;
}

fn matchesShapeWords(shape: []const []const u8, values: []const []const u8) bool {
    if (shape.len != values.len or values.len == 0) return false;
    const target = values[values.len - 1];
    for (shape, values) |word, value| {
        if (std.mem.startsWith(u8, word, "--")) {
            if (!std.mem.eql(u8, word, value)) return false;
        } else if (!matchesOperand(word, value, target)) {
            return false;
        }
    }
    return true;
}

fn scriptMatchesLifecycleRule(script: ?ScriptContext, rule: LifecyclePhaseRule) bool {
    const ctx = script orelse return false;
    const phase = if (ctx.argv.len >= 2) ctx.argv[1] else "";
    const arg2 = if (ctx.argv.len >= 3) ctx.argv[2] else "";
    return switch (rule) {
        .upgrade_or_remove => switch (ctx.action) {
            .preinst => std.mem.eql(u8, phase, "upgrade"),
            .postinst => std.mem.eql(u8, phase, "configure") and arg2.len > 0,
            .prerm => std.mem.eql(u8, phase, "remove") or std.mem.eql(u8, phase, "upgrade") or std.mem.eql(u8, phase, "deconfigure"),
            .postrm => std.mem.eql(u8, phase, "remove") or std.mem.eql(u8, phase, "purge") or std.mem.eql(u8, phase, "upgrade") or std.mem.eql(u8, phase, "abort-install") or std.mem.eql(u8, phase, "abort-upgrade") or std.mem.eql(u8, phase, "disappear"),
        },
        .prerm_remove => ctx.action == .prerm and (std.mem.eql(u8, phase, "remove") or std.mem.eql(u8, phase, "upgrade") or std.mem.eql(u8, phase, "deconfigure")),
        .postinst_or_postrm_cleanup => switch (ctx.action) {
            .postinst => std.mem.eql(u8, phase, "configure"),
            .postrm => std.mem.eql(u8, phase, "remove") or std.mem.eql(u8, phase, "abort-install") or std.mem.eql(u8, phase, "abort-upgrade") or std.mem.eql(u8, phase, "disappear"),
            else => false,
        },
        .postinst_upgrade => ctx.action == .postinst and std.mem.eql(u8, phase, "configure") and arg2.len > 0,
        .statoverride_remove => switch (ctx.action) {
            .postrm => std.mem.eql(u8, phase, "purge") or std.mem.eql(u8, phase, "remove"),
            .postinst => std.mem.eql(u8, phase, "configure") and arg2.len > 0,
            else => false,
        },
    };
}

fn isReviewedShape(tool: Tool, values: []const []const u8, lifecycle_mode: bool, script: ?ScriptContext) bool {
    const fresh_shapes = switch (tool) {
        .dpkg => return false,
        .dpkg_divert => &fresh_divert_shapes,
        .dpkg_statoverride => &fresh_statoverride_shapes,
    };
    for (fresh_shapes) |shape| {
        if (matchesShapeWords(shape, values)) return true;
    }
    if (!lifecycle_mode) return false;
    const extra_shapes = switch (tool) {
        .dpkg => return false,
        .dpkg_divert => &lifecycle_divert_shapes,
        .dpkg_statoverride => &lifecycle_statoverride_shapes,
    };
    for (extra_shapes) |entry| {
        if (matchesShapeWords(entry.words, values) and scriptMatchesLifecycleRule(script, entry.rule)) {
            return true;
        }
    }
    return false;
}

const Event = struct {
    seq: usize,
    pid: u64,
    text: []const u8,
};

const PendingEvent = struct {
    seq: usize,
    prefix: []const u8,
    call: []const u8,
};

const ParentLink = struct {
    pid: u64,
    seq: usize,
};

const ExecEntry = struct {
    seq: usize,
    parsed: ?ParsedExecve,
};

const LineageResult = struct {
    script: ?ScriptContext,
    lineage: []const u64,
    ambiguous: bool,
};

const TraceState = struct {
    allocator: std.mem.Allocator,
    candidate: []const u8,
    lifecycle_mode: bool,
    root_pid: ?u64 = null,
    events: std.AutoHashMapUnmanaged(usize, Event) = .empty,
    parents: std.AutoHashMapUnmanaged(u64, ParentLink) = .empty,
    poisoned: std.AutoHashMapUnmanaged(u64, void) = .empty,
    execs: std.AutoHashMapUnmanaged(u64, std.ArrayList(ExecEntry)) = .empty,

    fn lineageState(self: *const TraceState, pid: u64, seq: usize) !LineageResult {
        var chain: std.ArrayList(ParentLink) = .empty;
        var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
        var cur_pid = pid;
        var cur_seq = seq;
        while (true) {
            if (seen.contains(cur_pid) or chain.items.len > maximum_lineage_depth) {
                var rev: std.ArrayList(u64) = .empty;
                var idx = chain.items.len;
                while (idx > 0) {
                    idx -= 1;
                    try rev.append(self.allocator, chain.items[idx].pid);
                }
                return .{
                    .script = null,
                    .lineage = try rev.toOwnedSlice(self.allocator),
                    .ambiguous = true,
                };
            }
            try seen.put(self.allocator, cur_pid, {});
            try chain.append(self.allocator, .{ .pid = cur_pid, .seq = cur_seq });
            const parent = self.parents.get(cur_pid) orelse break;
            cur_pid = parent.pid;
            cur_seq = parent.seq;
        }
        var lineage: std.ArrayList(u64) = .empty;
        var idx = chain.items.len;
        while (idx > 0) {
            idx -= 1;
            try lineage.append(self.allocator, chain.items[idx].pid);
        }
        const lineage_slice = try lineage.toOwnedSlice(self.allocator);
        if (self.root_pid == null or chain.items[chain.items.len - 1].pid != self.root_pid.?) {
            return .{
                .script = null,
                .lineage = lineage_slice,
                .ambiguous = false,
            };
        }
        var script: ?ScriptContext = null;
        var ambiguous = false;
        var debz_active = false;
        idx = chain.items.len;
        while (idx > 0) {
            idx -= 1;
            const item = chain.items[idx];
            ambiguous = ambiguous or self.poisoned.contains(item.pid);
            if (self.execs.get(item.pid)) |list| {
                for (list.items) |entry| {
                    if (entry.seq >= item.seq) break;
                    const parsed = entry.parsed orelse {
                        debz_active = false;
                        continue;
                    };
                    if (!std.mem.eql(u8, parsed.result, "0")) continue;
                    if (script == null and debz_active and !parsed.truncated) {
                        if (parseScriptAction(parsed.path)) |action| {
                            script = .{
                                .path = parsed.path,
                                .pid = item.pid,
                                .action = action,
                                .argv = parsed.argv,
                            };
                        }
                    }
                    debz_active = std.mem.eql(u8, parsed.path, self.candidate);
                }
            }
        }
        return .{
            .script = script,
            .lineage = lineage_slice,
            .ambiguous = ambiguous,
        };
    }
};

const CandidateRecord = struct {
    line: usize,
    pid: ?u64,
    argv: []const []const u8,
    path: ?[]const u8,
    script: ?ScriptContext,
    lineage: []const u64,
    reason: ?[]const u8,
};

fn hasRefusedOption(values: []const []const u8) bool {
    for (values) |value| {
        for (refused_options) |opt| {
            if (std.mem.startsWith(u8, value, opt)) return true;
        }
    }
    return false;
}

fn hasOptionBeforeSeparator(values: []const []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value, "--")) break;
        if (std.mem.startsWith(u8, value, "-")) return true;
    }
    return false;
}

fn isAllowedDpkgAction(action: []const u8) bool {
    for (dpkg_actions) |allowed| {
        if (std.mem.eql(u8, action, allowed)) return true;
    }
    return false;
}

fn evaluateCandidate(state: *const TraceState, seq: usize) !CandidateRecord {
    const event = state.events.get(seq) orelse return .{
        .line = seq + 1,
        .pid = null,
        .argv = &.{},
        .path = null,
        .script = null,
        .lineage = &.{},
        .reason = "unparsed",
    };
    const pid = event.pid;
    const text = event.text;
    if (!std.mem.startsWith(u8, text, "execve(")) {
        return .{
            .line = seq + 1,
            .pid = pid,
            .argv = &.{},
            .path = null,
            .script = null,
            .lineage = &.{},
            .reason = if (std.mem.startsWith(u8, text, "execveat(")) "execveat" else "unparsed",
        };
    }
    const parsed: ?ParsedExecve = blk: {
        if (state.execs.get(pid)) |list| {
            for (list.items) |entry| {
                if (entry.seq == seq) break :blk entry.parsed;
            }
        }
        break :blk null;
    };
    const exec_info = parsed orelse return .{
        .line = seq + 1,
        .pid = pid,
        .argv = &.{},
        .path = null,
        .script = null,
        .lineage = &.{},
        .reason = "unparsed",
    };
    const lin = try state.lineageState(pid, seq);
    const tool = Tool.fromPath(exec_info.path);
    const reason: ?[]const u8 = if (exec_info.truncated)
        "truncated"
    else if (tool == null)
        "path"
    else if (!std.mem.eql(u8, exec_info.result, "0"))
        "exec-result"
    else if (exec_info.argv.len == 0 or (!std.mem.eql(u8, exec_info.argv[0], tool.?.name()) and !std.mem.eql(u8, exec_info.argv[0], exec_info.path)))
        "argv0"
    else if (tool.? == .dpkg and (exec_info.argv.len < 2 or !isAllowedDpkgAction(exec_info.argv[1])))
        "action"
    else if (hasRefusedOption(exec_info.argv[if (tool.? == .dpkg) @min(exec_info.argv.len, 2) else @min(exec_info.argv.len, 1)..]))
        "option"
    else if (tool.? == .dpkg and hasOptionBeforeSeparator(exec_info.argv[@min(exec_info.argv.len, 2)..]))
        "option"
    else if (tool.? != .dpkg and !isReviewedShape(tool.?, exec_info.argv[1..], state.lifecycle_mode, lin.script))
        "shape"
    else if (lin.ambiguous)
        "ambiguous-lineage"
    else if (lin.script == null)
        "not-script-descended"
    else
        null;

    return .{
        .line = seq + 1,
        .pid = pid,
        .argv = exec_info.argv,
        .path = exec_info.path,
        .script = lin.script,
        .lineage = lin.lineage,
        .reason = reason,
    };
}

const OpenBeneathError = error{
    NotRegular,
    Unreadable,
};

fn openRootDir(root_path: []const u8) OpenBeneathError!linux.fd_t {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (root_path.len == 0 or root_path.len >= path_buf.len) return error.Unreadable;
    @memcpy(path_buf[0..root_path.len], root_path);
    path_buf[root_path.len] = 0;
    const rc = linux.open(
        @ptrCast(&path_buf),
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.Unreadable,
    };
}

fn openPartNoFollow(dir_fd: linux.fd_t, part: []const u8, directory: bool) OpenBeneathError!linux.fd_t {
    var buf: [std.fs.max_name_bytes + 1]u8 = undefined;
    if (part.len == 0 or part.len >= buf.len) return error.Unreadable;
    @memcpy(buf[0..part.len], part);
    buf[part.len] = 0;
    const flags: linux.O = if (directory)
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }
    else
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true };
    const rc = linux.openat(dir_fd, @ptrCast(&buf), flags, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .LOOP, .NOTDIR => error.NotRegular,
        else => error.Unreadable,
    };
}

fn openBeneathNoFollow(root_path: []const u8, relative: []const u8) OpenBeneathError!linux.fd_t {
    var current = try openRootDir(root_path);
    errdefer _ = linux.close(current);
    var parts = std.mem.splitScalar(u8, relative, '/');
    while (parts.next()) |part| {
        const is_last = parts.rest().len == 0;
        const child = try openPartNoFollow(current, part, !is_last);
        _ = linux.close(current);
        current = child;
    }
    return current;
}

fn existsBeneath(allocator: std.mem.Allocator, root_path: []const u8, relative: []const u8) OpenBeneathError!bool {
    const root_fd = try openRootDir(root_path);
    defer _ = linux.close(root_fd);

    var todo: std.ArrayList([]const u8) = .empty;
    var raw_parts = std.mem.splitScalar(u8, relative, '/');
    while (raw_parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        todo.append(allocator, part) catch return error.Unreadable;
    }
    var done: std.ArrayList([]const u8) = .empty;
    var links: usize = 0;

    while (todo.items.len > 0) {
        const part = todo.orderedRemove(0);
        if (std.mem.eql(u8, part, "..")) {
            if (done.items.len > 0) _ = done.pop();
            continue;
        }
        var rel_buf: [std.fs.max_path_bytes]u8 = undefined;
        var pos: usize = 0;
        for (done.items) |dir_part| {
            if (pos + dir_part.len + 1 >= rel_buf.len) return error.Unreadable;
            @memcpy(rel_buf[pos .. pos + dir_part.len], dir_part);
            pos += dir_part.len;
            rel_buf[pos] = '/';
            pos += 1;
        }
        if (pos + part.len >= rel_buf.len) return error.Unreadable;
        @memcpy(rel_buf[pos .. pos + part.len], part);
        pos += part.len;
        rel_buf[pos] = 0;

        var stx: linux.Statx = undefined;
        const rc = linux.statx(
            root_fd,
            @ptrCast(&rel_buf),
            linux.AT.SYMLINK_NOFOLLOW,
            .{ .TYPE = true, .MODE = true },
            &stx,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOENT, .NOTDIR => return false,
            else => return error.Unreadable,
        }
        if (todo.items.len == 0) return true;
        const file_type = stx.mode & linux.S.IFMT;
        if (file_type == linux.S.IFLNK) {
            links += 1;
            if (links > maximum_symlink_hops) return error.Unreadable;
            var link_buf: [std.fs.max_path_bytes]u8 = undefined;
            const link_rc = linux.readlinkat(root_fd, @ptrCast(&rel_buf), &link_buf, link_buf.len);
            switch (linux.errno(link_rc)) {
                .SUCCESS => {},
                else => return error.Unreadable,
            }
            const target = allocator.dupe(u8, link_buf[0..@intCast(link_rc)]) catch return error.Unreadable;
            if (std.mem.startsWith(u8, target, "/")) {
                done.clearRetainingCapacity();
            }
            var new_todo: std.ArrayList([]const u8) = .empty;
            var target_parts = std.mem.splitScalar(u8, target, '/');
            while (target_parts.next()) |item| {
                if (item.len == 0 or std.mem.eql(u8, item, ".")) continue;
                new_todo.append(allocator, item) catch return error.Unreadable;
            }
            new_todo.appendSlice(allocator, todo.items) catch return error.Unreadable;
            todo = new_todo;
        } else if (file_type == linux.S.IFDIR) {
            done.append(allocator, part) catch return error.Unreadable;
        } else {
            return false;
        }
    }
    return true;
}

fn readFdBounded(allocator: std.mem.Allocator, fd: linux.fd_t, max_bytes: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, &buf, buf.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => return error.Unreadable,
        }
        const n: usize = @intCast(rc);
        if (n == 0) break;
        if (out.items.len + n > max_bytes) return error.TooLarge;
        try out.appendSlice(allocator, buf[0..n]);
    }
    return out.toOwnedSlice(allocator);
}

fn verifyDpkgStatus(status: []const u8, expected_version: []const u8, expected_arch: []const u8) bool {
    var pos: usize = 0;
    while (pos <= status.len) {
        const next_sep = std.mem.indexOfPos(u8, status, pos, "\n\n");
        const stanza = if (next_sep) |end| status[pos..end] else status[pos..];
        var pkg: ?[]const u8 = null;
        var ver: ?[]const u8 = null;
        var arch: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, stanza, '\n');
        while (lines.next()) |line| {
            if (line.len == 0 or line[0] == ' ') continue;
            if (std.mem.indexOf(u8, line, ": ")) |sep| {
                const key = line[0..sep];
                const val = line[sep + 2 ..];
                if (std.mem.eql(u8, key, "Package")) {
                    pkg = val;
                } else if (std.mem.eql(u8, key, "Version")) {
                    ver = val;
                } else if (std.mem.eql(u8, key, "Architecture")) {
                    arch = val;
                }
            }
        }
        if (pkg != null and std.mem.eql(u8, pkg.?, "dpkg")) {
            return ver != null and arch != null and
                std.mem.eql(u8, ver.?, expected_version) and
                std.mem.eql(u8, arch.?, expected_arch);
        }
        if (next_sep) |end| {
            pos = end + 2;
        } else {
            break;
        }
    }
    return false;
}

fn identityRefusal(
    allocator: std.mem.Allocator,
    root_path: []const u8,
    architecture: []const u8,
    version: []const u8,
    tool: Tool,
    pin: IdentityPin,
) !?[]const u8 {
    const tool_name = tool.name();
    const rel_bin = try std.fmt.allocPrint(allocator, "usr/bin/{s}", .{tool_name});
    const fd = openBeneathNoFollow(root_path, rel_bin) catch |err| switch (err) {
        error.NotRegular => return try std.fmt.allocPrint(allocator, "{s}-identity:not-regular", .{tool_name}),
        error.Unreadable => return try std.fmt.allocPrint(allocator, "{s}-identity:unreadable", .{tool_name}),
    };
    defer _ = linux.close(fd);

    var empty_path = [_:0]u8{0};
    var stx: linux.Statx = undefined;
    const st_rc = linux.statx(
        fd,
        &empty_path,
        linux.AT.EMPTY_PATH,
        .{ .TYPE = true, .MODE = true, .SIZE = true },
        &stx,
    );
    if (linux.errno(st_rc) != .SUCCESS) {
        return try std.fmt.allocPrint(allocator, "{s}-identity:unreadable", .{tool_name});
    }
    if ((stx.mode & linux.S.IFMT) != linux.S.IFREG) {
        return try std.fmt.allocPrint(allocator, "{s}-identity:not-regular", .{tool_name});
    }

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const r_rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(r_rc) != .SUCCESS) {
            return try std.fmt.allocPrint(allocator, "{s}-identity:unreadable", .{tool_name});
        }
        const n: usize = @intCast(r_rc);
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }
    var digest_bytes: [32]u8 = undefined;
    hasher.final(&digest_bytes);
    const hex_digest = std.fmt.bytesToHex(digest_bytes, .lower);
    if (stx.size != pin.size or !std.mem.eql(u8, &hex_digest, pin.digest)) {
        return try std.fmt.allocPrint(allocator, "{s}-identity:digest", .{tool_name});
    }

    for (shadow_directories) |dir| {
        const shadow_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, tool_name });
        const exists = existsBeneath(allocator, root_path, shadow_rel) catch {
            return try std.fmt.allocPrint(allocator, "{s}-identity:unreadable", .{tool_name});
        };
        if (exists) {
            return try std.fmt.allocPrint(allocator, "{s}-identity:shadow:/{s}/{s}", .{ tool_name, dir, tool_name });
        }
    }

    const status_fd = openBeneathNoFollow(root_path, "var/lib/dpkg/status") catch {
        return try std.fmt.allocPrint(allocator, "{s}-identity:unreadable", .{tool_name});
    };
    defer _ = linux.close(status_fd);
    const status_bytes = readFdBounded(allocator, status_fd, maximum_status_bytes) catch |err| switch (err) {
        error.TooLarge => return try std.fmt.allocPrint(allocator, "{s}-identity:status", .{tool_name}),
        else => return try std.fmt.allocPrint(allocator, "{s}-identity:unreadable", .{tool_name}),
    };
    if (!verifyDpkgStatus(status_bytes, version, architecture)) {
        return try std.fmt.allocPrint(allocator, "{s}-identity:version", .{tool_name});
    }
    return null;
}

fn writeJsonAsciiString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |ch| {
        switch (ch) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            0x08 => try writer.writeAll("\\b"),
            0x0c => try writer.writeAll("\\f"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (ch < 0x20 or ch >= 0x7f) {
                    try writer.print("\\u{x:0>4}", .{@as(u16, ch)});
                } else {
                    try writer.writeByte(ch);
                }
            },
        }
    }
    try writer.writeByte('"');
}

fn writeJsonOptionalString(writer: anytype, value: ?[]const u8) !void {
    if (value) |s| {
        try writeJsonAsciiString(writer, s);
    } else {
        try writer.writeAll("null");
    }
}

fn writeJsonStringSlice(writer: anytype, values: []const []const u8) !void {
    try writer.writeByte('[');
    for (values, 0..) |item, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writeJsonAsciiString(writer, item);
    }
    try writer.writeByte(']');
}

fn writeLineage(writer: anytype, lineage: []const u64) !void {
    for (lineage, 0..) |pid, idx| {
        if (idx > 0) try writer.writeByte('>');
        try writer.print("{d}", .{pid});
    }
}

const AuditOutcome = struct {
    stdout: []const u8,
    exit_code: u8,
};

fn auditTraceBytes(
    allocator: std.mem.Allocator,
    trace_bytes: []const u8,
    root_path: []const u8,
    architecture: []const u8,
    candidate: []const u8,
    version: []const u8,
    identities: ParsedIdentities,
    lifecycle_mode: bool,
) !AuditOutcome {
    var state: TraceState = .{
        .allocator = allocator,
        .candidate = candidate,
        .lifecycle_mode = lifecycle_mode,
    };
    var candidates: std.ArrayList(usize) = .empty;
    var pending: std.AutoHashMapUnmanaged(u64, PendingEvent) = .empty;
    var pending_order: std.ArrayList(u64) = .empty;

    const unfinished_suffix = " <unfinished ...>";
    var lines = std.mem.splitScalar(u8, trace_bytes, '\n');
    var seq: usize = 0;
    while (lines.next()) |raw| : (seq += 1) {
        if (raw.len == 0) continue;
        if (isDpkgExecCandidate(raw)) {
            try candidates.append(allocator, seq);
        }
        const matched = matchLine(raw) orelse continue;
        const pid = matched.pid;
        const rest = matched.rest;
        if (state.root_pid == null) state.root_pid = pid;
        if (matchSuperseded(rest)) |other_pid| {
            try state.poisoned.put(allocator, pid, {});
            try state.poisoned.put(allocator, other_pid, {});
            continue;
        }
        if (matchResumed(rest)) |resumed| {
            if (pending.fetchRemove(pid)) |kv| {
                if (std.mem.eql(u8, kv.value.call, resumed.call)) {
                    const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ kv.value.prefix, resumed.tail });
                    try state.events.put(allocator, kv.value.seq, .{
                        .seq = kv.value.seq,
                        .pid = pid,
                        .text = combined,
                    });
                }
            }
            continue;
        }
        const call = matchCallName(rest);
        if (std.mem.endsWith(u8, rest, unfinished_suffix)) {
            if (!pending.contains(pid)) try pending_order.append(allocator, pid);
            try pending.put(allocator, pid, .{
                .seq = seq,
                .prefix = rest[0 .. rest.len - unfinished_suffix.len],
                .call = call,
            });
        } else {
            try state.events.put(allocator, seq, .{
                .seq = seq,
                .pid = pid,
                .text = rest,
            });
        }
    }
    for (pending_order.items) |pid| {
        if (pending.get(pid)) |entry| {
            const combined = try std.fmt.allocPrint(allocator, "{s} <unfinished>", .{entry.prefix});
            try state.events.put(allocator, entry.seq, .{
                .seq = entry.seq,
                .pid = pid,
                .text = combined,
            });
        }
    }

    var sorted_seqs: std.ArrayList(usize) = .empty;
    var ev_it = state.events.keyIterator();
    while (ev_it.next()) |key| {
        try sorted_seqs.append(allocator, key.*);
    }
    std.mem.sort(usize, sorted_seqs.items, {}, std.sort.asc(usize));

    for (sorted_seqs.items) |ev_seq| {
        const ev = state.events.get(ev_seq).?;
        const call = matchCallName(ev.text);
        if (std.mem.eql(u8, call, "clone") or
            std.mem.eql(u8, call, "clone3") or
            std.mem.eql(u8, call, "fork") or
            std.mem.eql(u8, call, "vfork"))
        {
            if (matchChildPid(ev.text)) |child_pid| {
                if (state.parents.contains(child_pid) or (state.root_pid != null and child_pid == state.root_pid.?)) {
                    try state.poisoned.put(allocator, child_pid, {});
                }
                try state.parents.put(allocator, child_pid, .{ .pid = ev.pid, .seq = ev_seq });
            }
        } else if (std.mem.eql(u8, call, "execve")) {
            const gop = try state.execs.getOrPut(allocator, ev.pid);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(allocator, .{
                .seq = ev_seq,
                .parsed = parseExecve(allocator, ev.text),
            });
        }
    }

    var allowed_by_tool: [Tool.all.len]std.ArrayList(CandidateRecord) = @splat(.empty);
    var refused: std.ArrayList(CandidateRecord) = .empty;

    for (candidates.items) |cand_seq| {
        const record = try evaluateCandidate(&state, cand_seq);
        if (record.reason != null) {
            try refused.append(allocator, record);
        } else {
            const tool = Tool.fromPath(record.path.?).?;
            try allowed_by_tool[@intFromEnum(tool)].append(allocator, record);
        }
    }

    for (Tool.all) |tool| {
        const idx = @intFromEnum(tool);
        if (allowed_by_tool[idx].items.len == 0) continue;
        if (try identityRefusal(allocator, root_path, architecture, version, tool, identities[idx])) |reason| {
            for (allowed_by_tool[idx].items) |item| {
                var refused_item = item;
                refused_item.reason = reason;
                try refused.append(allocator, refused_item);
            }
            allowed_by_tool[idx].clearRetainingCapacity();
        }
    }

    var allowed_all: std.ArrayList(CandidateRecord) = .empty;
    for (Tool.all) |tool| {
        try allowed_all.appendSlice(allocator, allowed_by_tool[@intFromEnum(tool)].items);
    }
    const RecordSort = struct {
        fn lessThan(_: void, a: CandidateRecord, b: CandidateRecord) bool {
            return a.line < b.line;
        }
    };
    std.mem.sort(CandidateRecord, allowed_all.items, {}, RecordSort.lessThan);
    std.mem.sort(CandidateRecord, refused.items, {}, RecordSort.lessThan);

    var out: std.Io.Writer.Allocating = .init(allocator);
    for (allowed_all.items) |record| {
        const tool = Tool.fromPath(record.path.?).?;
        const script = record.script.?;
        try out.writer.print("{s}_exec line={d} pid={d} script={s} script_pid={d} lineage=", .{
            tool.recordName(),
            record.line,
            record.pid.?,
            script.path,
            script.pid,
        });
        try writeLineage(&out.writer, record.lineage);
        try out.writer.writeAll(" argv=");
        try writeJsonStringSlice(&out.writer, record.argv);
        try out.writer.writeByte('\n');
    }
    const printed_refusals = @min(refused.items.len, maximum_printed_refusals);
    for (refused.items[0..printed_refusals]) |record| {
        try out.writer.print("forbidden_exec reason={s} line={d} pid=", .{
            record.reason.?,
            record.line,
        });
        if (record.pid) |pid| {
            try out.writer.print("{d}", .{pid});
        } else {
            try out.writer.writeAll("None");
        }
        try out.writer.writeAll(" path=");
        try writeJsonOptionalString(&out.writer, record.path);
        if (record.script) |script| {
            try out.writer.print(" script={s} script_pid={d} lineage=", .{ script.path, script.pid });
        } else {
            try out.writer.writeAll(" script=- script_pid=- lineage=");
        }
        try writeLineage(&out.writer, record.lineage);
        try out.writer.writeAll(" argv=");
        try writeJsonStringSlice(&out.writer, record.argv);
        try out.writer.writeByte('\n');
    }
    if (refused.items.len > maximum_printed_refusals) {
        try out.writer.print("forbidden_exec_records_omitted={d}\n", .{refused.items.len - maximum_printed_refusals});
    }
    for (Tool.all) |tool| {
        const idx = @intFromEnum(tool);
        if (allowed_by_tool[idx].items.len > 0) {
            const pin = identities[idx];
            try out.writer.print("{s}_identity version={s} architecture={s} size={d} digest={s}\n", .{
                tool.recordName(),
                version,
                architecture,
                pin.size,
                pin.digest,
            });
        }
    }
    for (Tool.all) |tool| {
        const idx = @intFromEnum(tool);
        try out.writer.print("allowed_{s}_exec={d}\n", .{
            tool.recordName(),
            allowed_by_tool[idx].items.len,
        });
    }
    try out.writer.print("forbidden_dpkg_exec={s}\n", .{if (refused.items.len > 0) "true" else "false"});
    return .{
        .stdout = out.written(),
        .exit_code = if (refused.items.len > 0) 90 else 0,
    };
}

fn failStderr(io: std.Io, code: u8, comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch "exec audit error\n";
    std.Io.File.stderr().writeStreamingAll(io, msg) catch {};
    std.process.exit(code);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args_it = init.minimal.args.iterate();
    const prog = args_it.next() orelse "debz-exec-audit";
    var positional: [7][]const u8 = undefined;
    var count: usize = 0;
    while (args_it.next()) |arg| {
        if (count >= positional.len) {
            failStderr(init.io, 2, "usage: {s} [--lifecycle] TRACE ROOT ARCHITECTURE CANDIDATE VERSION IDENTITIES\n", .{prog});
        }
        positional[count] = arg;
        count += 1;
    }
    var lifecycle_mode = false;
    var offset: usize = 0;
    if (count == 7 and std.mem.eql(u8, positional[0], "--lifecycle")) {
        lifecycle_mode = true;
        offset = 1;
    } else if (count != 6) {
        failStderr(init.io, 2, "usage: {s} [--lifecycle] TRACE ROOT ARCHITECTURE CANDIDATE VERSION IDENTITIES\n", .{prog});
    }
    const trace_path = positional[offset + 0];
    const root_path = positional[offset + 1];
    const architecture = positional[offset + 2];
    const candidate = positional[offset + 3];
    const version = positional[offset + 4];
    const raw_identities = positional[offset + 5];

    const identities = parseIdentities(raw_identities) orelse {
        failStderr(init.io, 91, "reviewed script tool identities are incomplete\n", .{});
    };

    const trace_bytes = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        trace_path,
        allocator,
        .limited(maximum_trace_bytes),
    ) catch |err| {
        failStderr(init.io, 91, "exec trace unreadable: {s}\n", .{@errorName(err)});
    };

    const outcome = try auditTraceBytes(
        allocator,
        trace_bytes,
        root_path,
        architecture,
        candidate,
        version,
        identities,
        lifecycle_mode,
    );
    try std.Io.File.stdout().writeStreamingAll(init.io, outcome.stdout);
    if (outcome.exit_code != 0) std.process.exit(outcome.exit_code);
}

const TestFixture = struct {
    temporary: std.testing.TmpDir,
    arena: std.heap.ArenaAllocator,
    root_path: []const u8,
    identities: ParsedIdentities,

    const dpkg_bytes = "fixture dpkg binary\n";
    const divert_bytes = "fixture dpkg-divert binary\n";
    const statoverride_bytes = "fixture dpkg-statoverride binary\n";
    const version = "1.23.7ubuntu2";
    const arch = "amd64";
    const candidate = "/opt/debz/bin/debz";

    fn hexOf(comptime bytes: []const u8) [64]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        return std.fmt.bytesToHex(digest, .lower);
    }

    fn init() !TestFixture {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer arena.deinit();
        var temporary = std.testing.tmpDir(.{});
        errdefer temporary.cleanup();
        const allocator = arena.allocator();
        try temporary.dir.createDirPath(std.testing.io, "usr/bin");
        try temporary.dir.createDirPath(std.testing.io, "usr/sbin");
        try temporary.dir.createDirPath(std.testing.io, "usr/local/bin");
        try temporary.dir.createDirPath(std.testing.io, "var/lib/dpkg");
        try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "usr/bin/dpkg", .data = dpkg_bytes });
        try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "usr/bin/dpkg-divert", .data = divert_bytes });
        try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "usr/bin/dpkg-statoverride", .data = statoverride_bytes });
        try temporary.dir.writeFile(std.testing.io, .{
            .sub_path = "var/lib/dpkg/status",
            .data = "Package: dpkg\nStatus: install ok installed\nVersion: " ++ version ++ "\nArchitecture: " ++ arch ++ "\n\n",
        });
        const root_path = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
        const dpkg_hex = try allocator.dupe(u8, &hexOf(dpkg_bytes));
        const divert_hex = try allocator.dupe(u8, &hexOf(divert_bytes));
        const statoverride_hex = try allocator.dupe(u8, &hexOf(statoverride_bytes));
        const raw = try std.fmt.allocPrint(allocator, "dpkg={s}:{d} dpkg-divert={s}:{d} dpkg-statoverride={s}:{d}", .{
            dpkg_hex,         dpkg_bytes.len,
            divert_hex,       divert_bytes.len,
            statoverride_hex, statoverride_bytes.len,
        });
        return .{
            .temporary = temporary,
            .arena = arena,
            .root_path = root_path,
            .identities = parseIdentities(raw).?,
        };
    }

    fn deinit(self: *TestFixture) void {
        self.temporary.cleanup();
        self.arena.deinit();
    }

    fn audit(self: *TestFixture, trace: []const u8, lifecycle_mode: bool) !AuditOutcome {
        return auditTraceBytes(
            self.arena.allocator(),
            trace,
            self.root_path,
            arch,
            candidate,
            version,
            self.identities,
            lifecycle_mode,
        );
    }
};

test "exec audit parses C strings, unfinished/resumed lines, and fresh-install shapes" {
    var f = try TestFixture.init();
    defer f.deinit();
    const trace =
        \\700 execve("/opt/debz/bin/debz", ["debz", "install"], 0x7ffd0 /* 4 vars */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/chrony.postinst", ["/var/lib/debz-lifecycle-scripts/chrony.postinst", "configure", ""], 0x7ffd1 /* 1 var */) = 0
        \\702 vfork( <unfinished ...>
        \\703 execve("/usr/bin/dpkg-statoverride", ["dpkg-statoverride", "--update", "--add", "root", "_chrony", "0640", "/etc/chrony/chrony.keys"], 0x7ffd2 /* 2 vars */ <unfinished ...>
        \\702 <... vfork resumed>) = 703
        \\703 <... execve resumed>) = 0
        \\
    ;
    const outcome = try f.audit(trace, false);
    try std.testing.expectEqual(@as(u8, 0), outcome.exit_code);
    try std.testing.expect(std.mem.startsWith(
        u8,
        outcome.stdout,
        "script_dpkg_statoverride_exec line=5 pid=703 script=/var/lib/debz-lifecycle-scripts/chrony.postinst script_pid=702 lineage=700>702>703 argv=[\"dpkg-statoverride\",\"--update\",\"--add\",\"root\",\"_chrony\",\"0640\",\"/etc/chrony/chrony.keys\"]\n",
    ));
    try std.testing.expect(std.mem.endsWith(
        u8,
        outcome.stdout,
        "allowed_script_dpkg_exec=0\nallowed_script_dpkg_divert_exec=0\nallowed_script_dpkg_statoverride_exec=1\nforbidden_dpkg_exec=false\n",
    ));
}

test "exec audit admits upgrade, remove and purge shapes only in lifecycle mode and matching script phase" {
    var f = try TestFixture.init();
    defer f.deinit();
    const cases = [_]struct {
        script_path: []const u8,
        script_argv: []const u8,
        wrong_argv: []const u8,
        tool_path: []const u8,
        tool_argv: []const u8,
    }{
        .{
            .script_path = "/var/lib/debz-lifecycle-scripts/gzip.preinst",
            .script_argv = "\"/var/lib/debz-lifecycle-scripts/gzip.preinst\", \"upgrade\", \"1.12-1\"",
            .wrong_argv = "\"/var/lib/debz-lifecycle-scripts/gzip.preinst\", \"install\"",
            .tool_path = "/usr/bin/dpkg-divert",
            .tool_argv = "\"dpkg-divert\", \"--rename\", \"--package\", \"zutils\", \"--divert\", \"/usr/bin/zcat.usr-is-merged\", \"--remove\", \"/usr/bin/zcat\"",
        },
        .{
            .script_path = "/var/lib/debz-lifecycle-scripts/dash.prerm",
            .script_argv = "\"/var/lib/debz-lifecycle-scripts/dash.prerm\", \"remove\"",
            .wrong_argv = "\"/var/lib/debz-lifecycle-scripts/dash.prerm\", \"failed-upgrade\", \"0.5\"",
            .tool_path = "/usr/bin/dpkg-divert",
            .tool_argv = "\"dpkg-divert\", \"--package\", \"dash\", \"--rename\", \"--remove\", \"/bin/sh\"",
        },
        .{
            .script_path = "/var/lib/debz-lifecycle-scripts/dash.postinst",
            .script_argv = "\"/var/lib/debz-lifecycle-scripts/dash.postinst\", \"configure\", \"0.5.12-6\"",
            .wrong_argv = "\"/var/lib/debz-lifecycle-scripts/dash.postinst\", \"configure\", \"\"",
            .tool_path = "/usr/bin/dpkg-divert",
            .tool_argv = "\"dpkg-divert\", \"--package\", \"dash\", \"--no-rename\", \"--remove\", \"/bin/sh\"",
        },
        .{
            .script_path = "/var/lib/debz-lifecycle-scripts/coreutils-from-gnu.postinst",
            .script_argv = "\"/var/lib/debz-lifecycle-scripts/coreutils-from-gnu.postinst\", \"configure\", \"0.0.0\"",
            .wrong_argv = "\"/var/lib/debz-lifecycle-scripts/coreutils-from-gnu.postinst\", \"triggered\", \"/usr/bin\"",
            .tool_path = "/usr/bin/dpkg-divert",
            .tool_argv = "\"dpkg-divert\", \"--package\", \"coreutils-switch\", \"--divert\", \"/usr/bin/cat.remove-bak\", \"--rename\", \"--remove\", \"/usr/bin/cat\"",
        },
        .{
            .script_path = "/var/lib/debz-lifecycle-scripts/coreutils-switch.prerm",
            .script_argv = "\"/var/lib/debz-lifecycle-scripts/coreutils-switch.prerm\", \"remove\"",
            .wrong_argv = "\"/var/lib/debz-lifecycle-scripts/coreutils-switch.prerm\", \"failed-upgrade\", \"0.0.0\"",
            .tool_path = "/usr/bin/dpkg-divert",
            .tool_argv = "\"dpkg-divert\", \"--package\", \"coreutils-switch\", \"--divert\", \"/usr/bin/cat.remove-bak\", \"--no-rename\", \"--add\", \"/usr/bin/cat\"",
        },
        .{
            .script_path = "/var/lib/debz-lifecycle-scripts/init-system-helpers.postinst",
            .script_argv = "\"/var/lib/debz-lifecycle-scripts/init-system-helpers.postinst\", \"configure\", \"1.66\"",
            .wrong_argv = "\"/var/lib/debz-lifecycle-scripts/init-system-helpers.postinst\", \"configure\", \"\"",
            .tool_path = "/usr/bin/dpkg-divert",
            .tool_argv = "\"dpkg-divert\", \"--quiet\", \"--local\", \"--remove\", \"--no-rename\", \"/etc/os-release\"",
        },
        .{
            .script_path = "/var/lib/debz-lifecycle-scripts/init-system-helpers.postinst",
            .script_argv = "\"/var/lib/debz-lifecycle-scripts/init-system-helpers.postinst\", \"configure\", \"1.66\"",
            .wrong_argv = "\"/var/lib/debz-lifecycle-scripts/init-system-helpers.postinst\", \"configure\", \"\"",
            .tool_path = "/usr/bin/dpkg-divert",
            .tool_argv = "\"dpkg-divert\", \"--list\", \"/etc/os-release\"",
        },
        .{
            .script_path = "/var/lib/debz-lifecycle-scripts/chrony.postrm",
            .script_argv = "\"/var/lib/debz-lifecycle-scripts/chrony.postrm\", \"purge\"",
            .wrong_argv = "\"/var/lib/debz-lifecycle-scripts/chrony.postrm\", \"abort-install\"",
            .tool_path = "/usr/bin/dpkg-statoverride",
            .tool_argv = "\"dpkg-statoverride\", \"--remove\", \"/var/lib/chrony\"",
        },
    };
    const allocator = f.arena.allocator();
    for (cases) |case| {
        const valid_trace = try std.fmt.allocPrint(allocator,
            \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
            \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
            \\702 execve("{s}", [{s}], 0x1 /* 1 var */) = 0
            \\702 vfork() = 703
            \\703 execve("{s}", [{s}], 0x1 /* 1 var */) = 0
            \\
        , .{ case.script_path, case.script_argv, case.tool_path, case.tool_argv });

        // Refused in default fresh-install mode.
        const fresh = try f.audit(valid_trace, false);
        try std.testing.expectEqual(@as(u8, 90), fresh.exit_code);
        try std.testing.expect(std.mem.startsWith(u8, fresh.stdout, "forbidden_exec reason=shape "));

        // Admitted in lifecycle mode with matching script phase.
        const lifecycle = try f.audit(valid_trace, true);
        try std.testing.expectEqual(@as(u8, 0), lifecycle.exit_code);
        try std.testing.expect(std.mem.endsWith(u8, lifecycle.stdout, "forbidden_dpkg_exec=false\n"));

        // Refused even in lifecycle mode when script phase does not match.
        const wrong_phase_trace = try std.fmt.allocPrint(allocator,
            \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
            \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
            \\702 execve("{s}", [{s}], 0x1 /* 1 var */) = 0
            \\702 vfork() = 703
            \\703 execve("{s}", [{s}], 0x1 /* 1 var */) = 0
            \\
        , .{ case.script_path, case.wrong_argv, case.tool_path, case.tool_argv });
        const wrong_phase = try f.audit(wrong_phase_trace, true);
        try std.testing.expectEqual(@as(u8, 90), wrong_phase.exit_code);
        try std.testing.expect(std.mem.startsWith(u8, wrong_phase.stdout, "forbidden_exec reason=shape "));
    }
}

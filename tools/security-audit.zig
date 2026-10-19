const std = @import("std");

pub const DIGEST_POLICY_SCHEMA = "https://debz.dev/security/digest-cutover-policy-v3";
pub const DIGEST_POLICY_VERSION: i64 = 3;
pub const DIGEST_POLICY_PATH = "security/digest-cutover-policy.json";
pub const DIGEST_INVENTORY_PATH = "security/digest-inventory-v1.tsv";
pub const DIGEST_INVENTORY_FORMAT = "tsv-v1";
pub const DIGEST_SEMANTIC_ALLOWLIST_PATH = "security/digest-semantic-allowlist-v1.tsv";
pub const DIGEST_SEMANTIC_ALLOWLIST_FORMAT = "tsv-v1";

pub const DIGEST_SCOPE_ROOTS = [_][]const u8{
    ".github",
    "actions",
    "build",
    "doc",
    "fuzz",
    "schema",
    "security",
    "src",
    "test",
    "tools",
};

pub const DIGEST_TOP_LEVEL_FILES = [_][]const u8{
    "README.md",
    "build.zig",
    "build.zig.zon",
};

pub const DIGEST_FINDING_KINDS = [_][]const u8{
    "cas_layout",
    "digest_version",
    "fixed_64_hex",
    "raw_32_byte",
    "sha256_token",
};

pub const DIGEST_POLICY_EXCLUDED_FINDINGS = [_][]const u8{
    DIGEST_POLICY_PATH,
    DIGEST_INVENTORY_PATH,
    DIGEST_SEMANTIC_ALLOWLIST_PATH,
    "tools/security-audit.zig",
};

pub const DIGEST_INVENTORY_COLUMNS = [_][]const u8{
    "path",
    "scope",
    "cas_layout",
    "digest_version",
    "fixed_64_hex",
    "raw_32_byte",
    "sha256_token",
    "sha512",
};

pub const DIGEST_SEMANTIC_ALLOWLIST_COLUMNS = [_][]const u8{
    "id",
    "path",
    "count",
    "sha512",
};

pub const REMOVED_TEST_ENTRY_POINTS = [_][]const u8{
    "tools/test_release.py",
    "tools/test_security_audit.py",
    "tools/test_real_snapshot_acceptance.py",
    "tools/test_debian_stable_closure.py",
    "tools/test_real_snapshot_reference_triggers.py",
    "tools/native-lifecycle-fixtures.py",
    "tools/native-differential.py",
    "tools/native_only_candidate.py",
    "tools/native-materialization-fixtures.py",
};

pub const DigestFinding = struct {
    context: []const u8,
    kind: []const u8,
    path: []const u8,
    token: []const u8,

    pub fn lessThan(_: void, a: DigestFinding, b: DigestFinding) bool {
        if (!std.mem.eql(u8, a.path, b.path)) return std.mem.lessThan(u8, a.path, b.path);
        if (!std.mem.eql(u8, a.kind, b.kind)) return std.mem.lessThan(u8, a.kind, b.kind);
        if (!std.mem.eql(u8, a.context, b.context)) return std.mem.lessThan(u8, a.context, b.context);
        return std.mem.lessThan(u8, a.token, b.token);
    }
};

pub const DigestCandidate = struct {
    context: []const u8,
    kind: []const u8,
    path: []const u8,
    selector: []const u8,

    pub fn lessThan(_: void, a: DigestCandidate, b: DigestCandidate) bool {
        if (!std.mem.eql(u8, a.kind, b.kind)) return std.mem.lessThan(u8, a.kind, b.kind);
        if (!std.mem.eql(u8, a.path, b.path)) return std.mem.lessThan(u8, a.path, b.path);
        if (!std.mem.eql(u8, a.selector, b.selector)) return std.mem.lessThan(u8, a.selector, b.selector);
        return std.mem.lessThan(u8, a.context, b.context);
    }
};

pub const DigestInventoryRecord = struct {
    path: []const u8,
    scope: []const u8,
    counts: [DIGEST_FINDING_KINDS.len]usize,
    sha512: [128]u8,

    pub fn eql(a: DigestInventoryRecord, b: DigestInventoryRecord) bool {
        return std.mem.eql(u8, a.path, b.path) and
            std.mem.eql(u8, a.scope, b.scope) and
            std.mem.eql(usize, &a.counts, &b.counts) and
            std.mem.eql(u8, &a.sha512, &b.sha512);
    }
};

pub const SemanticAllowlistRecord = struct {
    id: []const u8,
    path: []const u8,
    count: usize,
    sha512: [128]u8,

    pub fn eql(a: SemanticAllowlistRecord, b: SemanticAllowlistRecord) bool {
        return std.mem.eql(u8, a.id, b.id) and
            std.mem.eql(u8, a.path, b.path) and
            a.count == b.count and
            std.mem.eql(u8, &a.sha512, &b.sha512);
    }
};

pub const AuditContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    failures: std.ArrayList([]const u8) = .empty,
    server_mode: bool = false,
    server_file_cache: std.StringHashMapUnmanaged([]const u8) = .empty,
    server_digest_texts_cache: ?std.StringArrayHashMapUnmanaged([]const u8) = null,
    server_findings_cache: std.StringHashMapUnmanaged([]const DigestFinding) = .empty,
    server_candidates_cache: std.StringHashMapUnmanaged([]const DigestCandidate) = .empty,
    cache_allocator: std.mem.Allocator,

    pub fn fail(self: *AuditContext, message: []const u8) !void {
        try self.failures.append(self.allocator, try self.allocator.dupe(u8, message));
    }

    pub fn failFmt(self: *AuditContext, comptime fmt: []const u8, args: anytype) !void {
        try self.failures.append(self.allocator, try std.fmt.allocPrint(self.allocator, fmt, args));
    }

    pub fn pathJoin(self: *AuditContext, relative: []const u8) ![]u8 {
        if (std.mem.startsWith(u8, relative, "/")) return self.allocator.dupe(u8, relative);
        if (std.mem.eql(u8, self.root, ".")) return self.allocator.dupe(u8, relative);
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.root, relative });
    }

    pub fn absPath(self: *AuditContext, relative: []const u8) ![]u8 {
        return self.pathJoin(relative);
    }

    pub fn isRegularFile(self: *AuditContext, relative: []const u8) bool {
        if (self.isSymlink(relative)) return false;
        const full = self.pathJoin(relative) catch return false;
        const stat = std.Io.Dir.cwd().statFile(self.io, full, .{}) catch return false;
        return stat.kind == .file;
    }

    pub fn isNonEmptyRegularFile(self: *AuditContext, relative: []const u8) bool {
        if (self.isSymlink(relative)) return false;
        const full = self.pathJoin(relative) catch return false;
        const stat = std.Io.Dir.cwd().statFile(self.io, full, .{}) catch return false;
        return stat.kind == .file and stat.size > 0;
    }

    pub fn isSymlink(self: *AuditContext, relative: []const u8) bool {
        const full = self.pathJoin(relative) catch return false;
        var link_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        _ = std.Io.Dir.cwd().readLink(self.io, full, &link_buf) catch return false;
        return true;
    }

    pub fn isDir(self: *AuditContext, relative: []const u8) bool {
        if (self.isSymlink(relative)) return false;
        const full = self.pathJoin(relative) catch return false;
        const stat = std.Io.Dir.cwd().statFile(self.io, full, .{}) catch return false;
        return stat.kind == .directory;
    }

    pub fn isDirectory(self: *AuditContext, relative: []const u8) bool {
        return self.isDir(relative);
    }

    pub fn pathExists(self: *AuditContext, relative: []const u8) bool {
        if (self.isSymlink(relative)) return true;
        const full = self.pathJoin(relative) catch return false;
        _ = std.Io.Dir.cwd().statFile(self.io, full, .{}) catch return false;
        return true;
    }

    pub fn fileSize(self: *AuditContext, relative: []const u8) ?u64 {
        const full = self.pathJoin(relative) catch return null;
        const stat = std.Io.Dir.cwd().statFile(self.io, full, .{}) catch return null;
        if (stat.kind != .file) return null;
        return stat.size;
    }

    pub fn readBytes(self: *AuditContext, relative: []const u8) ![]u8 {
        const full = try self.pathJoin(relative);
        return std.Io.Dir.cwd().readFileAlloc(self.io, full, self.allocator, .limited(64 * 1024 * 1024));
    }

    pub fn readText(self: *AuditContext, relative: []const u8) ![]u8 {
        if (self.server_mode) {
            if (self.server_file_cache.get(relative)) |cached| return self.allocator.dupe(u8, cached);
        }
        const raw = try self.readBytes(relative);
        if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidUtf8;
        const text = try normalizeNewlines(self.allocator, raw);
        if (self.server_mode) {
            const key = try self.cache_allocator.dupe(u8, relative);
            const val = try self.cache_allocator.dupe(u8, text);
            try self.server_file_cache.put(self.cache_allocator, key, val);
        }
        return text;
    }

    pub fn serverReadText(self: *AuditContext, relative: []const u8) ![]const u8 {
        if (!self.server_mode) return self.readText(relative);
        if (self.server_file_cache.get(relative)) |cached| return cached;
        const full = try std.fmt.allocPrint(self.cache_allocator, "{s}/{s}", .{ self.root, relative });
        const raw = try std.Io.Dir.cwd().readFileAlloc(self.io, full, self.cache_allocator, .limited(64 * 1024 * 1024));
        if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidUtf8;
        const text = try normalizeNewlines(self.cache_allocator, raw);
        const key = try self.cache_allocator.dupe(u8, relative);
        try self.server_file_cache.put(self.cache_allocator, key, text);
        return text;
    }

    pub fn baseDigestTexts(self: *AuditContext) !std.StringArrayHashMapUnmanaged([]const u8) {
        if (self.server_mode) {
            if (self.server_digest_texts_cache) |cached| {
                var copy: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
                var it = cached.iterator();
                while (it.next()) |entry| {
                    try copy.put(self.allocator, entry.key_ptr.*, entry.value_ptr.*);
                }
                return copy;
            }
        }
        const tracked = try trackedFiles(self);
        const files = try repositoryDigestFiles(self, tracked);
        const max_bytes: usize = 16 * 1024 * 1024;
        if (files.len > 1024) return error.Overflow;
        for (files) |rel| {
            if (self.isSymlink(rel)) return error.Overflow;
        }
        const texts = try trackedDigestTexts(self, files, max_bytes);
        if (self.server_mode) {
            var cache_copy: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
            var it = texts.iterator();
            while (it.next()) |entry| {
                try cache_copy.put(
                    self.cache_allocator,
                    try self.cache_allocator.dupe(u8, entry.key_ptr.*),
                    try self.cache_allocator.dupe(u8, entry.value_ptr.*),
                );
            }
            self.server_digest_texts_cache = cache_copy;
        }
        return texts;
    }

    pub fn globWorkflowFiles(self: *AuditContext) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        const wf_abs = try self.absPath(".github/workflows");
        var dir = std.Io.Dir.openDirAbsolute(self.io, wf_abs, .{ .iterate = true }) catch return list.toOwnedSlice(self.allocator);
        defer dir.close(self.io);
        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".yml") or std.mem.endsWith(u8, entry.name, ".yaml")) {
                try list.append(self.allocator, try std.fmt.allocPrint(self.allocator, ".github/workflows/{s}", .{entry.name}));
            }
        }
        std.mem.sort([]const u8, list.items, {}, lessThanSlices);
        return list.toOwnedSlice(self.allocator);
    }

    pub fn globActionManifests(self: *AuditContext) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        const actions_abs = try self.absPath("actions");
        var dir = std.Io.Dir.openDirAbsolute(self.io, actions_abs, .{ .iterate = true }) catch return list.toOwnedSlice(self.allocator);
        defer dir.close(self.io);
        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .directory) continue;
            for ([_][]const u8{ "action.yml", "action.yaml" }) |fname| {
                const rel = try std.fmt.allocPrint(self.allocator, "actions/{s}/{s}", .{ entry.name, fname });
                if (self.isRegularFile(rel)) {
                    try list.append(self.allocator, rel);
                }
            }
        }
        std.mem.sort([]const u8, list.items, {}, lessThanSlices);
        return list.toOwnedSlice(self.allocator);
    }

    pub fn concatDirectoryFiles(self: *AuditContext, rel_dir: []const u8, suffix: []const u8) ![]const u8 {
        var names: std.ArrayList([]const u8) = .empty;
        const abs = try self.absPath(rel_dir);
        var dir = try std.Io.Dir.openDirAbsolute(self.io, abs, .{ .iterate = true });
        defer dir.close(self.io);
        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, suffix)) {
                try names.append(self.allocator, try self.allocator.dupe(u8, entry.name));
            }
        }
        std.mem.sort([]const u8, names.items, {}, lessThanSlices);
        var out: std.ArrayList(u8) = .empty;
        for (names.items, 0..) |name, i| {
            if (i > 0) try out.append(self.allocator, '\n');
            const rel = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ rel_dir, name });
            try out.appendSlice(self.allocator, try self.readText(rel));
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn hasTrackedFilesUnder(self: *AuditContext, rel_prefix: []const u8) !bool {
        const res = try std.process.run(self.allocator, self.io, .{
            .argv = &.{ "git", "ls-files", rel_prefix },
            .cwd = .{ .path = self.root },
        });
        if (res.term != .exited or res.term.exited != 0) return error.GitLsFilesFailed;
        return std.mem.trim(u8, res.stdout, " \t\r\n").len > 0;
    }

    pub fn walkCutoverMarkerFiles(self: *AuditContext) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        try self.walkDirMatching("src", &.{".zig"}, &.{ "dist", "node_modules" }, &list);
        try self.walkDirMatching("actions", &.{ ".ts", ".yml" }, &.{ "dist", "node_modules" }, &list);
        std.mem.sort([]const u8, list.items, {}, lessThanSlices);
        return list.toOwnedSlice(self.allocator);
    }

    pub fn walkMarkdownFiles(self: *AuditContext) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        const excluded = [_][]const u8{
            ".cache",
            ".git",
            ".real-snapshot",
            ".tmp",
            ".tools",
            ".zig-cache",
            "lib",
            "node_modules",
            "zig-out",
            "zig-pkg",
        };
        try self.walkDirMatching(".", &.{".md"}, &excluded, &list);
        std.mem.sort([]const u8, list.items, {}, lessThanSlices);
        return list.toOwnedSlice(self.allocator);
    }

    fn walkDirMatching(
        self: *AuditContext,
        rel_dir: []const u8,
        suffixes: []const []const u8,
        excluded_parts: []const []const u8,
        out: *std.ArrayList([]const u8),
    ) !void {
        const abs = if (std.mem.eql(u8, rel_dir, ".")) self.root else try self.absPath(rel_dir);
        var dir = std.Io.Dir.openDirAbsolute(self.io, abs, .{ .iterate = true }) catch return;
        defer dir.close(self.io);
        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (sliceContainsString(excluded_parts, entry.name)) continue;
            const child_rel = if (std.mem.eql(u8, rel_dir, "."))
                try self.allocator.dupe(u8, entry.name)
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ rel_dir, entry.name });
            if (entry.kind == .directory) {
                try self.walkDirMatching(child_rel, suffixes, excluded_parts, out);
            } else if (entry.kind == .file) {
                for (suffixes) |sfx| {
                    if (std.mem.endsWith(u8, entry.name, sfx)) {
                        try out.append(self.allocator, child_rel);
                        break;
                    }
                }
            }
        }
    }
};

pub fn normalizeNewlines(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (std.mem.indexOfScalar(u8, input, '\r') == null) {
        return allocator.dupe(u8, input);
    }
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(allocator, input.len);
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        if (input[i] == '\r') {
            try out.append(allocator, '\n');
            if (i + 1 < input.len and input[i + 1] == '\n') i += 1;
        } else {
            try out.append(allocator, input[i]);
        }
    }
    return out.toOwnedSlice(allocator);
}

pub fn sliceContainsStr(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

pub fn isExcludedFindingPath(relative: []const u8) bool {
    return sliceContainsStr(&DIGEST_POLICY_EXCLUDED_FINDINGS, relative);
}

pub fn isWordChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_';
}

pub fn isAlphaUnder(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
}

pub fn isSlugChar(c: u8) bool {
    return isWordChar(c) or c == '-';
}

pub fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

pub fn isSpace(c: u8) bool {
    return switch (c) {
        ' ', '\t', '\r', '\n', 0x0b, 0x0c => true,
        else => false,
    };
}

pub fn isWordBoundary(s: []const u8, pos: usize) bool {
    const before = pos > 0 and isWordChar(s[pos - 1]);
    const after = pos < s.len and isWordChar(s[pos]);
    return before != after;
}

pub fn asciiLowerAlloc(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| {
        out[i] = std.ascii.toLower(c);
    }
    return out;
}

pub inline fn startsWithAt(s: []const u8, pos: usize, prefix: []const u8) bool {
    if (prefix.len == 0) return pos <= s.len;
    if (pos + prefix.len > s.len or s[pos] != prefix[0]) return false;
    return std.mem.eql(u8, s[pos .. pos + prefix.len], prefix);
}

pub fn normalizedLine(allocator: std.mem.Allocator, line: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    const n = line.len;
    var in_space = true;
    while (i < n) {
        const c = line[i];
        if (c == ' ' or (c >= '\t' and c <= '\r') or (c >= 0x1c and c <= 0x1f)) {
            in_space = true;
            i += 1;
            continue;
        }
        if (c == 0xc2 and i + 1 < n and (line[i + 1] == 0xa0 or line[i + 1] == 0x85)) {
            in_space = true;
            i += 2;
            continue;
        }
        if (in_space and out.items.len > 0) {
            try out.append(allocator, ' ');
        }
        in_space = false;
        try out.append(allocator, c);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

pub inline fn fastIndexOfScalarPos(slice: []const u8, start_index: usize, value: u8) ?usize {
    return std.mem.indexOfScalarPos(u8, slice, start_index, value);
}

pub inline fn fastIndexOfPos(haystack: []const u8, start_index: usize, needle: []const u8) ?usize {
    if (needle.len == 0) return start_index;
    if (haystack.len < needle.len or start_index > haystack.len - needle.len) return null;
    const first = needle[0];
    if (needle.len == 1) return std.mem.indexOfScalarPos(u8, haystack, start_index, first);
    const second = needle[1];
    const search_end = haystack.len - needle.len + 1;
    const tail = needle[2..];
    var i = start_index;
    while (std.mem.indexOfScalarPos(u8, haystack[0..search_end], i, first)) |idx| {
        if (haystack[idx + 1] == second and startsWithAt(haystack, idx + 2, tail)) return idx;
        i = idx + 1;
    }
    return null;
}

pub inline fn fastIndexOf(haystack: []const u8, needle: []const u8) ?usize {
    return fastIndexOfPos(haystack, 0, needle);
}

pub fn triggerMask(comptime s: []const u8) u64 {
    comptime {
        var m: u64 = 0;
        for (0..s.len - 1) |i| {
            const h: u6 = (@as(u6, @truncate(s[i])) *% 31) +% @as(u6, @truncate(s[i + 1]));
            m |= (@as(u64, 1) << h);
        }
        return m;
    }
}

pub inline fn mightContain(mask: u64, comptime s: []const u8) bool {
    const req = comptime triggerMask(s);
    return (mask & req) == req;
}

pub fn asciiLowerWithMask(allocator: std.mem.Allocator, s: []const u8, out_mask: *u64) ![]u8 {
    const out = try allocator.alloc(u8, s.len);
    var m: u64 = 0;
    if (s.len > 0) {
        var prev: u8 = if (s[0] >= 'A' and s[0] <= 'Z') s[0] + 32 else s[0];
        out[0] = prev;
        for (s[1..], 1..) |c, idx| {
            const lc: u8 = if (c >= 'A' and c <= 'Z') c + 32 else c;
            out[idx] = lc;
            const h: u6 = (@as(u6, @truncate(prev)) *% 31) +% @as(u6, @truncate(lc));
            m |= (@as(u64, 1) << h);
            prev = lc;
        }
    }
    out_mask.* = m;
    return out;
}

pub fn nextCasWordPos(low: []const u8, start: usize) ?usize {
    var pos = start;
    while (fastIndexOfPos(low, pos, "cas")) |found| {
        if (isWordBoundary(low, found) and isWordBoundary(low, found + 3)) return found;
        pos = found + 3;
    }
    return null;
}

pub fn scanSha256Token(allocator: std.mem.Allocator, line: []const u8, low: []const u8, mask: u64) !std.ArrayList([]const u8) {
    var out: std.ArrayList([]const u8) = .empty;
    const m_sha = comptime (triggerMask("sha256") & triggerMask("sha-256") & triggerMask("sha_256"));
    if ((mask & m_sha) != m_sha) return out;
    if ((!mightContain(mask, "sha256") or fastIndexOf(low, "sha256") == null) and
        (!mightContain(mask, "sha-256") or fastIndexOf(low, "sha-256") == null) and
        (!mightContain(mask, "sha_256") or fastIndexOf(low, "sha_256") == null))
    {
        return out;
    }
    const n = line.len;
    var i: usize = 0;
    while (i < n) {
        const next_sha = fastIndexOfPos(low, i, "sha") orelse break;
        var word_start = next_sha;
        while (word_start > i and isWordChar(line[word_start - 1])) : (word_start -= 1) {}
        if (word_start > i) {
            i = word_start;
        }
        if (startsWithAt(low, i, "sha-256")) {
            try out.append(allocator, line[i .. i + 7]);
            i += 7;
            continue;
        }
        if (startsWithAt(low, i, "sha256")) {
            try out.append(allocator, line[i .. i + 6]);
            i += 6;
            continue;
        }
        if ((i == 0 or !isWordChar(line[i - 1])) and isAlphaUnder(line[i])) {
            var end = i + 1;
            while (end < n and isWordChar(line[end])) : (end += 1) {}
            const sub = low[i + 1 .. end];
            if (fastIndexOf(sub, "sha_256") != null or fastIndexOf(sub, "sha256") != null) {
                try out.append(allocator, line[i..end]);
                i = end;
                continue;
            }
        }
        i = next_sha + 1;
    }
    return out;
}

pub fn scanRaw32Byte(allocator: std.mem.Allocator, line: []const u8, mask: u64) !std.ArrayList([]const u8) {
    var out: std.ArrayList([]const u8) = .empty;
    if (!mightContain(mask, "32") or !mightContain(mask, "u8")) return out;
    if (fastIndexOf(line, "32") == null) return out;
    const n = line.len;
    var i: usize = 0;
    while (i < n) {
        const bracket = fastIndexOfScalarPos(line, i, '[') orelse break;
        i = bracket;
        var j = i + 1;
        while (j < n and isSpace(line[j])) : (j += 1) {}
        if (startsWithAt(line, j, "32")) {
            j += 2;
            while (j < n and isSpace(line[j])) : (j += 1) {}
            if (j < n and line[j] == ']') {
                j += 1;
                var k = j;
                if (startsWithAt(line, k, "const") and k + 5 < n and isSpace(line[k + 5])) {
                    k += 5;
                    while (k < n and isSpace(line[k])) : (k += 1) {}
                }
                if (startsWithAt(line, k, "u8")) {
                    try out.append(allocator, line[i .. k + 2]);
                    i = k + 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    return out;
}

inline fn matchOp64(low: []const u8, pos: usize) ?usize {
    const n = low.len;
    if (pos >= n) return null;
    switch (low[pos]) {
        '=', '!', '<', '>' => {},
        else => return null,
    }
    const ops = [_][]const u8{ "==", "!=", "<=", ">=", "<", ">" };
    for (ops) |op| {
        if (startsWithAt(low, pos, op)) {
            var j = pos + op.len;
            while (j < n and isSpace(low[j])) : (j += 1) {}
            if (startsWithAt(low, j, "64")) return j + 2;
        }
    }
    return null;
}

pub fn scanFixed64Hex(allocator: std.mem.Allocator, line: []const u8, low: []const u8, mask: u64) !std.ArrayList([]const u8) {
    var out: std.ArrayList([]const u8) = .empty;
    if (!mightContain(mask, "64")) return out;
    var next_64 = fastIndexOfPos(low, 0, "64") orelse return out;
    const n = line.len;
    var i: usize = 0;
    const kws = [_][]const u8{ "hex", "digest", "sha256", "artifact_id", "cache_key" };
    const kws5 = [_][]const u8{ "artifact_id", "sha256_hex", "cache_key" };
    while (i < n) {
        if (i > next_64) {
            next_64 = fastIndexOfPos(low, i, "64") orelse break;
        }
        if (next_64 > i + 96) {
            i = next_64 - 96;
            continue;
        }
        switch (low[i]) {
            '^', '{', 'h', 'd', 's', 'a', 'c', '=', '!', '<', '>' => {},
            else => {
                i += 1;
                continue;
            },
        }
        if (startsWithAt(low, i, "^[0-9a-f]{64}$")) {
            try out.append(allocator, line[i .. i + 14]);
            i += 14;
            continue;
        }
        if (startsWithAt(low, i, "{64}")) {
            try out.append(allocator, line[i .. i + 4]);
            i += 4;
            continue;
        }
        var matched_b3: ?usize = null;
        for (kws) |kw| {
            if (startsWithAt(low, i, kw)) {
                const after_kw = i + kw.len;
                const max_d = @min(@as(usize, 64), n - after_kw);
                var d: usize = max_d + 1;
                while (d > 0) {
                    d -= 1;
                    if (matchOp64(low, after_kw + d)) |end_pos| {
                        matched_b3 = end_pos;
                        break;
                    }
                }
                if (matched_b3 != null) break;
            }
        }
        if (matched_b3) |end_pos| {
            try out.append(allocator, line[i..end_pos]);
            i = end_pos;
            continue;
        }
        if (matchOp64(low, i)) |end_op64| {
            var matched_b4: ?usize = null;
            const max_d = @min(@as(usize, 64), n - end_op64);
            var d: usize = max_d + 1;
            while (d > 0) {
                d -= 1;
                const pos = end_op64 + d;
                for (kws) |kw| {
                    if (startsWithAt(low, pos, kw)) {
                        matched_b4 = pos + kw.len;
                        break;
                    }
                }
                if (matched_b4 != null) break;
            }
            if (matched_b4) |end_pos| {
                try out.append(allocator, line[i..end_pos]);
                i = end_pos;
                continue;
            }
        }
        var matched_b5: ?usize = null;
        for (kws5) |kw| {
            if (startsWithAt(low, i, kw)) {
                var j = i + kw.len;
                while (j < n and isSpace(low[j])) : (j += 1) {}
                if (j < n and low[j] == ':') {
                    j += 1;
                    while (j < n and isSpace(low[j])) : (j += 1) {}
                    if (startsWithAt(low, j, "[64]u8")) {
                        matched_b5 = j + 6;
                        break;
                    }
                }
            }
        }
        if (matched_b5) |end_pos| {
            try out.append(allocator, line[i..end_pos]);
            i = end_pos;
            continue;
        }
        i += 1;
    }
    return out;
}

pub fn scanCasLayout(allocator: std.mem.Allocator, line: []const u8, low: []const u8, mask: u64) !std.ArrayList([]const u8) {
    var out: std.ArrayList([]const u8) = .empty;
    const any_mask = mightContain(mask, "cas") or
        mightContain(mask, "packages-v") or
        mightContain(mask, "metadata-v") or
        mightContain(mask, "objects/<") or
        mightContain(mask, "staging/<") or
        mightContain(mask, "locks/<") or
        mightContain(mask, "cachekey") or
        mightContain(mask, "cache_key") or
        mightContain(mask, "sha256-");
    if (!any_mask) return out;
    var next_cas_word: ?usize = if (mightContain(mask, "cas")) nextCasWordPos(low, 0) else null;
    const has_cas_word = next_cas_word != null;
    var active_triggers: [8][]const u8 = undefined;
    var active_len: usize = 0;
    inline for ([_][]const u8{ "packages-v", "metadata-v", "objects/<", "staging/<", "locks/<", "cachekey", "cache_key", "sha256-" }) |t| {
        if (mightContain(mask, t) and fastIndexOf(low, t) != null) {
            active_triggers[active_len] = t;
            active_len += 1;
        }
    }
    if (!has_cas_word and active_len == 0) return out;
    const n = line.len;
    var i: usize = 0;
    var next_other: ?usize = null;
    var next_other_valid = false;
    const cas_kws = [_][]const u8{ "digest", "identity", "layout", "path", "key" };
    while (i < n) {
        if (next_cas_word) |cw| {
            if (i > cw) next_cas_word = nextCasWordPos(low, i);
        }
        if (active_len > 0 and (!next_other_valid or (next_other != null and i > next_other.?))) {
            var min_pos: ?usize = null;
            for (active_triggers[0..active_len]) |t| {
                if (fastIndexOfPos(low, i, t)) |pos| {
                    if (min_pos == null or pos < min_pos.?) min_pos = pos;
                }
            }
            next_other = min_pos;
            next_other_valid = true;
        }
        const earliest_other = next_other orelse n;
        const earliest_cas = if (next_cas_word) |cw| cw -| 95 else n;
        const earliest = @min(earliest_other, earliest_cas);
        if (earliest >= n) break;
        if (earliest > i) {
            i = earliest;
            continue;
        }
        switch (low[i]) {
            'p', 'm', 'o', 's', 'l', 'c' => {},
            'd', 'i', 'k' => {
                if (!has_cas_word) {
                    i += 1;
                    continue;
                }
            },
            else => {
                i += 1;
                continue;
            },
        }
        var matched: ?usize = null;
        for ([_][]const u8{ "packages-v", "metadata-v" }) |pfx| {
            if (startsWithAt(low, i, pfx)) {
                var j = i + pfx.len;
                if (j < n and isDigit(low[j])) {
                    while (j < n and isDigit(low[j])) : (j += 1) {}
                    matched = j;
                    break;
                }
            }
        }
        if (matched) |end_pos| {
            try out.append(allocator, line[i..end_pos]);
            i = end_pos;
            continue;
        }
        for ([_][]const u8{ "objects/<", "staging/<", "locks/<" }) |pfx| {
            if (startsWithAt(low, i, pfx)) {
                if (fastIndexOfScalarPos(low, i + pfx.len, '>')) |gt| {
                    const inner = low[i + pfx.len .. gt];
                    if (fastIndexOf(inner, "digest") != null or
                        fastIndexOf(inner, "identity") != null or
                        fastIndexOf(inner, "sha256") != null)
                    {
                        matched = gt + 1;
                    }
                }
                break;
            }
        }
        if (matched) |end_pos| {
            try out.append(allocator, line[i..end_pos]);
            i = end_pos;
            continue;
        }
        if (isWordBoundary(low, i)) {
            for ([_][]const u8{ "cachekey", "cache_key" }) |kw| {
                if (startsWithAt(low, i, kw) and isWordBoundary(low, i + kw.len)) {
                    matched = i + kw.len;
                    break;
                }
            }
        }
        if (matched) |end_pos| {
            try out.append(allocator, line[i..end_pos]);
            i = end_pos;
            continue;
        }
        if (startsWithAt(low, i, "sha256-")) {
            try out.append(allocator, line[i .. i + 7]);
            i += 7;
            continue;
        }
        if (has_cas_word and isWordBoundary(low, i) and startsWithAt(low, i, "cas") and isWordBoundary(low, i + 3)) {
            const after_cas = i + 3;
            const max_d = @min(@as(usize, 80), n - after_cas);
            var d: usize = max_d + 1;
            while (d > 0) {
                d -= 1;
                const pos = after_cas + d;
                if (isWordBoundary(low, pos)) {
                    for (cas_kws) |kw| {
                        if (startsWithAt(low, pos, kw) and isWordBoundary(low, pos + kw.len)) {
                            matched = pos + kw.len;
                            break;
                        }
                    }
                }
                if (matched != null) break;
            }
            if (matched) |end_pos| {
                try out.append(allocator, line[i..end_pos]);
                i = end_pos;
                continue;
            }
        }
        if (has_cas_word and isWordBoundary(low, i)) {
            for (cas_kws) |kw| {
                if (startsWithAt(low, i, kw) and isWordBoundary(low, i + kw.len)) {
                    const after_kw = i + kw.len;
                    const max_d = @min(@as(usize, 80), n - after_kw);
                    if (next_cas_word != null and next_cas_word.? >= after_kw and next_cas_word.? <= after_kw + max_d) {
                        var d: usize = max_d + 1;
                        while (d > 0) {
                            d -= 1;
                            const pos = after_kw + d;
                            if (isWordBoundary(low, pos) and startsWithAt(low, pos, "cas") and isWordBoundary(low, pos + 3)) {
                                matched = pos + 3;
                                break;
                            }
                        }
                    }
                    if (matched != null) break;
                }
            }
            if (matched) |end_pos| {
                try out.append(allocator, line[i..end_pos]);
                i = end_pos;
                continue;
            }
        }
        i += 1;
    }
    return out;
}

fn matchVersionOrVnum(low: []const u8, pos: usize) ?usize {
    const n = low.len;
    if (startsWithAt(low, pos, "version")) return pos + 7;
    if (pos + 1 < n and low[pos] == 'v' and isDigit(low[pos + 1])) {
        var j = pos + 2;
        while (j < n and isDigit(low[j])) : (j += 1) {}
        return j;
    }
    return null;
}

fn matchVnum(low: []const u8, pos: usize) ?usize {
    const n = low.len;
    if (pos + 1 < n and low[pos] == 'v' and isDigit(low[pos + 1])) {
        var j = pos + 2;
        while (j < n and isDigit(low[j])) : (j += 1) {}
        return j;
    }
    return null;
}

pub fn scanDigestVersion(allocator: std.mem.Allocator, line: []const u8, low: []const u8, mask: u64) !std.ArrayList([]const u8) {
    var out: std.ArrayList([]const u8) = .empty;
    const has_v = mightContain(mask, "v0") or mightContain(mask, "v1") or mightContain(mask, "v2") or
        mightContain(mask, "v3") or mightContain(mask, "v4") or mightContain(mask, "v5") or
        mightContain(mask, "v6") or mightContain(mask, "v7") or mightContain(mask, "v8") or
        mightContain(mask, "v9") or mightContain(mask, "ve");
    if (!has_v) return out;
    const triggers = [_][]const u8{ "digest", "identity", "checksum", "hash", "schema", "format", "namespace" };
    var any_trigger = false;
    inline for (triggers) |t| {
        if (mightContain(mask, t) and fastIndexOf(low, t) != null) {
            any_trigger = true;
            break;
        }
    }
    if (!any_trigger) return out;
    const n = line.len;
    const kws1 = [_][]const u8{ "digest", "identity", "checksum", "hash" };
    const kws3 = [_][]const u8{ "schema", "format", "namespace" };
    var search_from: usize = 0;
    while (search_from < n) {
        const v_pos = fastIndexOfScalarPos(low, search_from, 'v') orelse break;
        if (v_pos + 1 >= n or !(low[v_pos + 1] == 'e' or isDigit(low[v_pos + 1]))) {
            search_from = v_pos + 1;
            continue;
        }
        var slug_start = v_pos;
        while (slug_start > search_from and isSlugChar(low[slug_start - 1])) : (slug_start -= 1) {}
        var end_slug = v_pos + 2;
        while (end_slug < n and isSlugChar(low[end_slug])) : (end_slug += 1) {}
        search_from = end_slug;
        const slug = low[slug_start..end_slug];
        var slug_has_trigger = false;
        if (slug.len >= 5) {
            for (triggers) |t| {
                if (fastIndexOf(slug, t) != null) {
                    slug_has_trigger = true;
                    break;
                }
            }
        }
        if (!slug_has_trigger) continue;
        var i = slug_start;
        while (i < end_slug) {
            switch (low[i]) {
                'd', 'i', 'c', 'h', 'v', 's', 'f', 'n' => {},
                else => {
                    i += 1;
                    continue;
                },
            }
            var matched: ?usize = null;
            for (kws1) |kw| {
                if (startsWithAt(low, i, kw)) {
                    const after_kw = i + kw.len;
                    var p = end_slug + 1;
                    while (p > after_kw) {
                        p -= 1;
                        if (matchVersionOrVnum(low, p)) |end_v| {
                            matched = end_v;
                            break;
                        }
                    }
                    if (matched != null) break;
                }
            }
            if (matched) |end_pos| {
                try out.append(allocator, line[i..end_pos]);
                i = end_pos;
                continue;
            }
            var b2_starts: [2]usize = undefined;
            var b2_len: usize = 0;
            if (startsWithAt(low, i, "version")) {
                b2_starts[b2_len] = i + 7;
                b2_len += 1;
            }
            if (i + 1 < end_slug and low[i] == 'v' and isDigit(low[i + 1])) {
                b2_starts[b2_len] = i + 2;
                b2_len += 1;
            }
            for (b2_starts[0..b2_len]) |after_v| {
                var p = end_slug + 1;
                while (p > after_v) {
                    p -= 1;
                    for (kws1) |kw| {
                        if (startsWithAt(low, p, kw)) {
                            matched = p + kw.len;
                            break;
                        }
                    }
                    if (matched != null) break;
                }
                if (matched != null) break;
            }
            if (matched) |end_pos| {
                try out.append(allocator, line[i..end_pos]);
                i = end_pos;
                continue;
            }
            for (kws3) |kw| {
                if (startsWithAt(low, i, kw)) {
                    const after_kw = i + kw.len;
                    var p = end_slug + 1;
                    while (p > after_kw) {
                        p -= 1;
                        if (matchVnum(low, p)) |end_v| {
                            matched = end_v;
                            break;
                        }
                    }
                    if (matched != null) break;
                }
            }
            if (matched) |end_pos| {
                try out.append(allocator, line[i..end_pos]);
                i = end_pos;
                continue;
            }
            i += 1;
        }
    }
    return out;
}

pub fn scanRaw32Field(line: []const u8, low: []const u8, mask: u64) ?[]const u8 {
    if (!mightContain(mask, "32") or !mightContain(mask, "u8")) return null;
    if (fastIndexOf(low, "32") == null) return null;
    const n = line.len;
    var i: usize = 0;
    while (i < n and isSpace(line[i])) : (i += 1) {}
    if (startsWithAt(low, i, "pub") and i + 3 < n and isSpace(line[i + 3])) {
        i += 3;
        while (i < n and isSpace(line[i])) : (i += 1) {}
    }
    if (i >= n or !isAlphaUnder(line[i])) return null;
    const name_start = i;
    while (i < n and isWordChar(line[i])) : (i += 1) {}
    const name = line[name_start..i];
    const name_low = low[name_start..i];
    const kws = [_][]const u8{ "sha256", "digest", "hash", "checksum", "identity" };
    var kw_match = false;
    for (kws) |kw| {
        if (std.mem.eql(u8, name_low, kw) or fastIndexOf(name_low[1..], kw) != null) {
            kw_match = true;
            break;
        }
    }
    if (!kw_match) return null;
    while (i < n and isSpace(line[i])) : (i += 1) {}
    if (i >= n or line[i] != ':') return null;
    i += 1;
    while (i < n and isSpace(line[i])) : (i += 1) {}
    if (i < n and line[i] == '?') i += 1;
    if (i >= n or line[i] != '[') return null;
    i += 1;
    while (i < n and isSpace(line[i])) : (i += 1) {}
    if (!startsWithAt(low, i, "32")) return null;
    i += 2;
    while (i < n and isSpace(line[i])) : (i += 1) {}
    if (i >= n or line[i] != ']') return null;
    i += 1;
    if (!startsWithAt(low, i, "u8") or !isWordBoundary(low, i + 2)) return null;
    return name;
}

pub fn scanFixedSha256Cas(allocator: std.mem.Allocator, line: []const u8, low: []const u8, mask: u64) !std.ArrayList([]const u8) {
    var out: std.ArrayList([]const u8) = .empty;
    var active_triggers: [4][]const u8 = undefined;
    var active_len: usize = 0;
    inline for ([_][]const u8{ "sha256", "cache_key", "packages-v1", "metadata-v1" }) |t| {
        if (mightContain(mask, t) and fastIndexOf(low, t) != null) {
            active_triggers[active_len] = t;
            active_len += 1;
        }
    }
    if (active_len == 0) return out;
    const n = line.len;
    var i: usize = 0;
    var next_trigger: usize = 0;
    var next_valid = false;
    while (i < n) {
        if (!next_valid or i > next_trigger) {
            var min_pos: ?usize = null;
            for (active_triggers[0..active_len]) |t| {
                if (fastIndexOfPos(low, i, t)) |pos| {
                    if (min_pos == null or pos < min_pos.?) min_pos = pos;
                }
            }
            next_trigger = min_pos orelse break;
            next_valid = true;
        }
        if (next_trigger > i + 10) {
            i = next_trigger - 10;
            continue;
        }
        switch (low[i]) {
            'o', 's', 'l', 'c', 'p', 'm' => {},
            else => {
                i += 1;
                continue;
            },
        }
        var matched: ?usize = null;
        for ([_][]const u8{ "objects", "staging", "locks" }) |pfx| {
            if (startsWithAt(low, i, pfx) and i + pfx.len < n and (low[i + pfx.len] == '/' or low[i + pfx.len] == '\\')) {
                var j = i + pfx.len + 1;
                if (startsWithAt(low, j, "${")) {
                    j += 2;
                } else if (j < n and (low[j] == '{' or low[j] == '<')) {
                    j += 1;
                }
                if (startsWithAt(low, j, "sha256")) {
                    j += 6;
                    if (startsWithAt(low, j, "_hex")) j += 4;
                    matched = j;
                    break;
                }
            }
        }
        if (matched) |end_pos| {
            try out.append(allocator, line[i..end_pos]);
            i = end_pos;
            continue;
        }
        if (startsWithAt(low, i, "sha256")) {
            var j = i + 6;
            if (startsWithAt(low, j, "_hex")) j += 4;
            while (j < n and isSpace(low[j])) : (j += 1) {}
            if (j < n and low[j] == '[') {
                j += 1;
                while (j < n and isSpace(low[j])) : (j += 1) {}
                if (j < n and low[j] == '0') {
                    j += 1;
                    while (j < n and isSpace(low[j])) : (j += 1) {}
                    if (startsWithAt(low, j, "..")) {
                        j += 2;
                        while (j < n and isSpace(low[j])) : (j += 1) {}
                        var ok = false;
                        if (startsWithAt(low, j, "64")) {
                            j += 2;
                            ok = true;
                        } else if (startsWithAt(low, j, "2")) {
                            j += 1;
                            ok = true;
                        }
                        if (ok) {
                            while (j < n and isSpace(low[j])) : (j += 1) {}
                            if (j < n and low[j] == ']') matched = j + 1;
                        }
                    }
                }
            }
        }
        if (matched) |end_pos| {
            try out.append(allocator, line[i..end_pos]);
            i = end_pos;
            continue;
        }
        if (startsWithAt(low, i, "cache_key")) {
            var j = i + 9;
            while (j < n and isSpace(low[j])) : (j += 1) {}
            if (j < n and low[j] == ':') {
                j += 1;
                while (j < n and isSpace(low[j])) : (j += 1) {}
                for ([_][]const u8{ "[64]u8", "[65]u8", "[71]u8" }) |tail| {
                    if (startsWithAt(low, j, tail)) {
                        matched = j + tail.len;
                        break;
                    }
                }
            }
        }
        if (matched) |end_pos| {
            try out.append(allocator, line[i..end_pos]);
            i = end_pos;
            continue;
        }
        if (startsWithAt(low, i, "packages-v1") or startsWithAt(low, i, "metadata-v1")) {
            try out.append(allocator, line[i .. i + 11]);
            i += 11;
            continue;
        }
        i += 1;
    }
    return out;
}

pub fn hasAuthorityField(selector: []const u8) bool {
    var buf: [256]u8 = undefined;
    const low = if (selector.len <= buf.len) blk: {
        for (selector, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        break :blk buf[0..selector.len];
    } else return false;
    const patterns = [_][]const u8{
        "package_sha256",  "package_digest",
        "cas_sha256",      "index_sha256",
        "archive_sha256",  "archive_digest",
        "artifact_sha256", "artifact_digest",
    };
    for (patterns) |p| {
        if (std.mem.indexOf(u8, low, p) != null) return true;
    }
    return false;
}

pub fn appendJsonAsciiString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try out.ensureUnusedCapacity(allocator, s.len + 2);
    try out.append(allocator, '"');
    var i: usize = 0;
    while (i < s.len) {
        const start = i;
        while (i < s.len) : (i += 1) {
            const b = s[i];
            if (b < 0x20 or b > 0x7f or b == '"' or b == '\\') break;
        }
        if (i > start) {
            try out.appendSlice(allocator, s[start..i]);
            if (i == s.len) break;
        }
        const cp_len = try std.unicode.utf8ByteSequenceLength(s[i]);
        const cp = try std.unicode.utf8Decode(s[i .. i + cp_len]);
        i += cp_len;
        switch (cp) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            0x08 => try out.appendSlice(allocator, "\\b"),
            0x0c => try out.appendSlice(allocator, "\\f"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (cp >= 0x20 and cp <= 0x7f) {
                    try out.append(allocator, @intCast(cp));
                } else if (cp <= 0xffff) {
                    var buf: [6]u8 = undefined;
                    _ = try std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{cp});
                    try out.appendSlice(allocator, &buf);
                } else {
                    const adj = cp - 0x10000;
                    const high: u16 = @intCast(0xd800 + (adj >> 10));
                    const low_s: u16 = @intCast(0xdc00 + (adj & 0x3ff));
                    var buf: [12]u8 = undefined;
                    _ = try std.fmt.bufPrint(&buf, "\\u{x:0>4}\\u{x:0>4}", .{ high, low_s });
                    try out.appendSlice(allocator, &buf);
                }
            },
        }
    }
    try out.append(allocator, '"');
}

pub fn appendCanonicalJsonValue(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: std.json.Value) !void {
    switch (value) {
        .null => try out.appendSlice(allocator, "null"),
        .bool => |b| try out.appendSlice(allocator, if (b) "true" else "false"),
        .integer => |n| {
            const s = try std.fmt.allocPrint(allocator, "{d}", .{n});
            try out.appendSlice(allocator, s);
        },
        .float => |f| {
            const s = try std.fmt.allocPrint(allocator, "{d}", .{f});
            try out.appendSlice(allocator, s);
        },
        .number_string => |s| try out.appendSlice(allocator, s),
        .string => |s| try appendJsonAsciiString(out, allocator, s),
        .array => |arr| {
            try out.append(allocator, '[');
            for (arr.items, 0..) |item, i| {
                if (i > 0) try out.append(allocator, ',');
                try appendCanonicalJsonValue(out, allocator, item);
            }
            try out.append(allocator, ']');
        },
        .object => |obj| {
            const keys = try allocator.alloc([]const u8, obj.count());
            for (obj.keys(), 0..) |k, i| keys[i] = k;
            std.mem.sort([]const u8, keys, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.lessThan(u8, a, b);
                }
            }.lessThan);
            try out.append(allocator, '{');
            for (keys, 0..) |k, i| {
                if (i > 0) try out.append(allocator, ',');
                try appendJsonAsciiString(out, allocator, k);
                try out.append(allocator, ':');
                try appendCanonicalJsonValue(out, allocator, obj.get(k).?);
            }
            try out.append(allocator, '}');
        },
    }
}

pub fn canonicalSha512Findings(allocator: std.mem.Allocator, findings: []const DigestFinding) ![128]u8 {
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    hasher.update("[");
    var last_context_ptr: ?[*]const u8 = null;
    var last_context_len: usize = 0;
    var cached_context_json: []const u8 = &.{};
    var tmp: std.ArrayList(u8) = .empty;
    for (findings, 0..) |f, i| {
        if (i > 0) hasher.update(",");
        hasher.update("{\"context\":");
        if (last_context_ptr == null or last_context_ptr.? != f.context.ptr or last_context_len != f.context.len) {
            var ctx_buf: std.ArrayList(u8) = .empty;
            try appendJsonAsciiString(&ctx_buf, allocator, f.context);
            cached_context_json = try ctx_buf.toOwnedSlice(allocator);
            last_context_ptr = f.context.ptr;
            last_context_len = f.context.len;
        }
        hasher.update(cached_context_json);
        tmp.clearRetainingCapacity();
        try tmp.appendSlice(allocator, ",\"kind\":");
        try appendJsonAsciiString(&tmp, allocator, f.kind);
        try tmp.appendSlice(allocator, ",\"path\":");
        try appendJsonAsciiString(&tmp, allocator, f.path);
        try tmp.appendSlice(allocator, ",\"token\":");
        try appendJsonAsciiString(&tmp, allocator, f.token);
        try tmp.append(allocator, '}');
        hasher.update(tmp.items);
    }
    hasher.update("]");
    var digest: [64]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn canonicalSha512Candidates(allocator: std.mem.Allocator, candidates: []const DigestCandidate) ![128]u8 {
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    hasher.update("[");
    var last_context_ptr: ?[*]const u8 = null;
    var last_context_len: usize = 0;
    var cached_context_json: []const u8 = &.{};
    var tmp: std.ArrayList(u8) = .empty;
    for (candidates, 0..) |c, i| {
        if (i > 0) hasher.update(",");
        hasher.update("{\"context\":");
        if (last_context_ptr == null or last_context_ptr.? != c.context.ptr or last_context_len != c.context.len) {
            var ctx_buf: std.ArrayList(u8) = .empty;
            try appendJsonAsciiString(&ctx_buf, allocator, c.context);
            cached_context_json = try ctx_buf.toOwnedSlice(allocator);
            last_context_ptr = c.context.ptr;
            last_context_len = c.context.len;
        }
        hasher.update(cached_context_json);
        tmp.clearRetainingCapacity();
        try tmp.appendSlice(allocator, ",\"kind\":");
        try appendJsonAsciiString(&tmp, allocator, c.kind);
        try tmp.appendSlice(allocator, ",\"path\":");
        try appendJsonAsciiString(&tmp, allocator, c.path);
        try tmp.appendSlice(allocator, ",\"selector\":");
        try appendJsonAsciiString(&tmp, allocator, c.selector);
        try tmp.append(allocator, '}');
        hasher.update(tmp.items);
    }
    hasher.update("]");
    var digest: [64]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn schemaSha256Candidates(allocator: std.mem.Allocator, relative: []const u8, text: []const u8) !std.ArrayList(DigestCandidate) {
    var candidates: std.ArrayList(DigestCandidate) = .empty;
    if (!std.mem.startsWith(u8, relative, "schema/") or !std.mem.endsWith(u8, relative, ".json")) {
        return candidates;
    }
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch return candidates;
    const Walk = struct {
        fn walk(alloc: std.mem.Allocator, rel: []const u8, val: std.json.Value, pointer: []const u8, out: *std.ArrayList(DigestCandidate)) !void {
            switch (val) {
                .object => |obj| {
                    if (obj.get("properties")) |props_val| {
                        if (props_val == .object) {
                            var it = props_val.object.iterator();
                            while (it.next()) |entry| {
                                const name = entry.key_ptr.*;
                                var enc: std.ArrayList(u8) = .empty;
                                try appendCanonicalJsonValue(&enc, alloc, entry.value_ptr.*);
                                const encoded = try enc.toOwnedSlice(alloc);
                                const low_name = try asciiLowerAlloc(alloc, name);
                                if (std.mem.indexOf(u8, low_name, "sha256") != null or
                                    std.mem.indexOf(u8, encoded, "#/$defs/sha256") != null)
                                {
                                    try out.append(alloc, .{
                                        .context = encoded,
                                        .kind = "schema_sha256_field",
                                        .path = rel,
                                        .selector = try std.fmt.allocPrint(alloc, "{s}/properties/{s}", .{ pointer, name }),
                                    });
                                }
                            }
                        }
                    }
                    var it = obj.iterator();
                    while (it.next()) |entry| {
                        const child_ptr = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ pointer, entry.key_ptr.* });
                        try walk(alloc, rel, entry.value_ptr.*, child_ptr, out);
                    }
                },
                .array => |arr| {
                    for (arr.items, 0..) |child, idx| {
                        const child_ptr = try std.fmt.allocPrint(alloc, "{s}/{d}", .{ pointer, idx });
                        try walk(alloc, rel, child, child_ptr, out);
                    }
                },
                else => {},
            }
        }
    };
    try Walk.walk(allocator, relative, parsed.value, "", &candidates);
    return candidates;
}

pub const LineSpan = struct { start: usize, end: usize };

pub fn collectTriggerLines(
    allocator: std.mem.Allocator,
    text: []const u8,
    file_low: []const u8,
    triggers: []const []const u8,
) ![]LineSpan {
    var spans: std.ArrayList(LineSpan) = .empty;
    for (triggers) |t| {
        var pos: usize = 0;
        while (pos < file_low.len) {
            const hit = fastIndexOfPos(file_low, pos, t) orelse break;
            var line_start = hit;
            while (line_start > 0 and text[line_start - 1] != '\n') : (line_start -= 1) {}
            var line_end = hit + t.len;
            while (line_end < text.len and text[line_end] != '\n') : (line_end += 1) {}
            if (line_end > line_start) {
                try spans.append(allocator, .{ .start = line_start, .end = line_end });
            }
            pos = if (line_end < file_low.len) line_end + 1 else file_low.len;
        }
    }
    if (spans.items.len <= 1) return spans.toOwnedSlice(allocator);
    std.mem.sort(LineSpan, spans.items, {}, struct {
        fn lessThan(_: void, a: LineSpan, b: LineSpan) bool {
            return a.start < b.start;
        }
    }.lessThan);
    var write_idx: usize = 1;
    for (spans.items[1..]) |sp| {
        if (sp.start != spans.items[write_idx - 1].start) {
            spans.items[write_idx] = sp;
            write_idx += 1;
        }
    }
    spans.items.len = write_idx;
    return spans.toOwnedSlice(allocator);
}

pub fn digestFindingsForFile(ctx: *AuditContext, relative: []const u8, text: []const u8) ![]const DigestFinding {
    if (isExcludedFindingPath(relative)) return &.{};
    const cache_key = try std.fmt.allocPrint(ctx.allocator, "{s}\x00{x}\x00{d}", .{ relative, std.hash.Wyhash.hash(0, text), text.len });
    if (ctx.server_findings_cache.get(cache_key)) |cached| return cached;
    const alloc = if (ctx.server_findings_cache.count() < 2048) ctx.cache_allocator else ctx.allocator;
    const rel_owned = if (alloc.ptr == ctx.cache_allocator.ptr) try alloc.dupe(u8, relative) else relative;
    var list: std.ArrayList(DigestFinding) = .empty;
    const file_low = try asciiLowerAlloc(ctx.allocator, text);
    const triggers = [_][]const u8{
        "packages-v", "metadata-v", "objects/<", "staging/<", "locks/<",
        "cachekey",   "cache_key",  "sha256-",   "cas",       "digest",
        "identity",   "checksum",   "hash",      "schema",    "format",
        "namespace",  "64",         "32",        "sha256",    "sha-256",
        "sha_256",
    };
    const spans = try collectTriggerLines(ctx.allocator, text, file_low, &triggers);
    const all_mask: u64 = ~@as(u64, 0);
    for (spans) |sp| {
        const raw_line = text[sp.start..sp.end];
        const low = file_low[sp.start..sp.end];
        const cas = try scanCasLayout(ctx.allocator, raw_line, low, all_mask);
        const ver = try scanDigestVersion(ctx.allocator, raw_line, low, all_mask);
        const hex = try scanFixed64Hex(ctx.allocator, raw_line, low, all_mask);
        const r32 = try scanRaw32Byte(ctx.allocator, raw_line, all_mask);
        const sha = try scanSha256Token(ctx.allocator, raw_line, low, all_mask);
        if (cas.items.len == 0 and ver.items.len == 0 and hex.items.len == 0 and r32.items.len == 0 and sha.items.len == 0) continue;
        const norm = try normalizedLine(alloc, raw_line);
        for ([_]struct { kind: []const u8, items: []const []const u8 }{
            .{ .kind = "cas_layout", .items = cas.items },
            .{ .kind = "digest_version", .items = ver.items },
            .{ .kind = "fixed_64_hex", .items = hex.items },
            .{ .kind = "raw_32_byte", .items = r32.items },
            .{ .kind = "sha256_token", .items = sha.items },
        }) |group| {
            for (group.items) |tok| {
                try list.append(alloc, .{
                    .context = norm,
                    .kind = group.kind,
                    .path = rel_owned,
                    .token = try alloc.dupe(u8, tok),
                });
            }
        }
    }
    const result = try list.toOwnedSlice(alloc);
    if (ctx.server_findings_cache.count() < 2048) {
        try ctx.server_findings_cache.put(ctx.cache_allocator, try ctx.cache_allocator.dupe(u8, cache_key), result);
    }
    return result;
}

pub fn digestFindings(ctx: *AuditContext, texts: std.StringArrayHashMapUnmanaged([]const u8)) ![]DigestFinding {
    var list: std.ArrayList(DigestFinding) = .empty;
    for (texts.keys(), texts.values()) |rel, text| {
        const file_findings = try digestFindingsForFile(ctx, rel, text);
        try list.appendSlice(ctx.allocator, file_findings);
    }
    std.mem.sort(DigestFinding, list.items, {}, DigestFinding.lessThan);
    return list.toOwnedSlice(ctx.allocator);
}

pub fn digestSemanticCandidatesForFile(ctx: *AuditContext, relative: []const u8, text: []const u8) ![]const DigestCandidate {
    if (isExcludedFindingPath(relative)) return &.{};
    const cache_key = try std.fmt.allocPrint(ctx.allocator, "{s}\x00{x}\x00{d}", .{ relative, std.hash.Wyhash.hash(0, text), text.len });
    if (ctx.server_candidates_cache.get(cache_key)) |cached| return cached;
    const alloc = if (ctx.server_candidates_cache.count() < 2048) ctx.cache_allocator else ctx.allocator;
    const rel_owned = if (alloc.ptr == ctx.cache_allocator.ptr) try alloc.dupe(u8, relative) else relative;
    var list: std.ArrayList(DigestCandidate) = .empty;
    const file_low = try asciiLowerAlloc(ctx.allocator, text);
    const triggers = [_][]const u8{
        "32", "64", "sha256", "cache_key", "packages-v1", "metadata-v1",
    };
    const spans = try collectTriggerLines(ctx.allocator, text, file_low, &triggers);
    const all_mask: u64 = ~@as(u64, 0);
    for (spans) |sp| {
        const raw_line = text[sp.start..sp.end];
        const low = file_low[sp.start..sp.end];
        const r32_field = scanRaw32Field(raw_line, low, all_mask);
        const hex = try scanFixed64Hex(ctx.allocator, raw_line, low, all_mask);
        const cas = try scanFixedSha256Cas(ctx.allocator, raw_line, low, all_mask);
        if (r32_field == null and hex.items.len == 0 and cas.items.len == 0) continue;
        const norm = try normalizedLine(alloc, raw_line);
        if (r32_field) |field_name| {
            try list.append(alloc, .{
                .context = norm,
                .kind = "raw_32_byte_field",
                .path = rel_owned,
                .selector = try alloc.dupe(u8, field_name),
            });
        }
        for (hex.items) |sel| {
            try list.append(alloc, .{
                .context = norm,
                .kind = "fixed_64_hex_assumption",
                .path = rel_owned,
                .selector = try alloc.dupe(u8, sel),
            });
        }
        for (cas.items) |sel| {
            try list.append(alloc, .{
                .context = norm,
                .kind = "fixed_sha256_cas",
                .path = rel_owned,
                .selector = try alloc.dupe(u8, sel),
            });
        }
    }
    const schema_cands = try schemaSha256Candidates(alloc, rel_owned, text);
    try list.appendSlice(alloc, schema_cands.items);
    const result = try list.toOwnedSlice(alloc);
    if (ctx.server_candidates_cache.count() < 2048) {
        try ctx.server_candidates_cache.put(ctx.cache_allocator, try ctx.cache_allocator.dupe(u8, cache_key), result);
    }
    return result;
}

pub fn digestSemanticCandidates(ctx: *AuditContext, texts: std.StringArrayHashMapUnmanaged([]const u8)) ![]DigestCandidate {
    var list: std.ArrayList(DigestCandidate) = .empty;
    for (texts.keys(), texts.values()) |rel, text| {
        const file_cands = try digestSemanticCandidatesForFile(ctx, rel, text);
        try list.appendSlice(ctx.allocator, file_cands);
    }
    std.mem.sort(DigestCandidate, list.items, {}, DigestCandidate.lessThan);
    return list.toOwnedSlice(ctx.allocator);
}

pub fn trackedFiles(ctx: *AuditContext) ![][]const u8 {
    const res = try std.process.run(ctx.allocator, ctx.io, .{
        .argv = &.{ "git", "ls-files", "-z" },
        .cwd = .{ .path = ctx.root },
        .stdout_limit = .limited(16 * 1024 * 1024),
    });
    if (res.term != .exited or res.term.exited != 0) return error.GitLsFilesFailed;
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, res.stdout, 0);
    while (it.next()) |item| {
        if (item.len == 0) continue;
        if (ctx.pathExists(item) or ctx.isSymlink(item) or !sliceContainsStr(&REMOVED_TEST_ENTRY_POINTS, item)) {
            try out.append(ctx.allocator, item);
        }
    }
    return out.toOwnedSlice(ctx.allocator);
}

pub fn untrackedFiles(ctx: *AuditContext) ![][]const u8 {
    const res = try std.process.run(ctx.allocator, ctx.io, .{
        .argv = &.{ "git", "ls-files", "--others", "--exclude-standard", "-z" },
        .cwd = .{ .path = ctx.root },
        .stdout_limit = .limited(16 * 1024 * 1024),
    });
    if (res.term != .exited or res.term.exited != 0) return error.GitLsFilesFailed;
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, res.stdout, 0);
    while (it.next()) |item| {
        if (item.len == 0) continue;
        try out.append(ctx.allocator, item);
    }
    return out.toOwnedSlice(ctx.allocator);
}

pub fn repositoryDigestFiles(ctx: *AuditContext, files: []const []const u8) ![][]const u8 {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var out: std.ArrayList([]const u8) = .empty;
    for (files) |f| {
        if (!(try seen.getOrPut(ctx.allocator, f)).found_existing) {
            try out.append(ctx.allocator, f);
        }
    }
    const untracked = try untrackedFiles(ctx);
    for (untracked) |f| {
        if (!(try seen.getOrPut(ctx.allocator, f)).found_existing) {
            try out.append(ctx.allocator, f);
        }
    }
    for ([_][]const u8{ DIGEST_POLICY_PATH, DIGEST_INVENTORY_PATH, DIGEST_SEMANTIC_ALLOWLIST_PATH }) |req| {
        if (ctx.isRegularFile(req) and !ctx.isSymlink(req)) {
            if (!(try seen.getOrPut(ctx.allocator, req)).found_existing) {
                try out.append(ctx.allocator, req);
            }
        } else if (ctx.isRegularFile(req)) {
            if (!(try seen.getOrPut(ctx.allocator, req)).found_existing) {
                try out.append(ctx.allocator, req);
            }
        }
    }
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    return out.toOwnedSlice(ctx.allocator);
}

pub fn digestRelevantPath(relative: []const u8) bool {
    if (sliceContainsStr(&DIGEST_TOP_LEVEL_FILES, relative)) return true;
    const slash = std.mem.indexOfScalar(u8, relative, '/') orelse return false;
    const first_part = relative[0..slash];
    if (!sliceContainsStr(&DIGEST_SCOPE_ROOTS, first_part)) return false;
    var it = std.mem.splitScalar(u8, relative, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, "__pycache__") or std.mem.eql(u8, part, "node_modules")) return false;
    }
    if (std.mem.endsWith(u8, relative, ".pyc") or std.mem.endsWith(u8, relative, ".pyo")) return false;
    return true;
}

pub fn trackedDigestTexts(
    ctx: *AuditContext,
    files: []const []const u8,
    maximum_text_bytes: ?usize,
) !std.StringArrayHashMapUnmanaged([]const u8) {
    var texts: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    const digest_files = try repositoryDigestFiles(ctx, files);
    for (digest_files) |relative| {
        if (!digestRelevantPath(relative)) continue;
        const full = try ctx.pathJoin(relative);
        const data = std.Io.Dir.cwd().readFileAlloc(ctx.io, full, ctx.allocator, .limited(64 * 1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound, error.IsDir, error.AccessDenied => continue,
            error.StreamTooLong => {
                if (maximum_text_bytes != null) return error.Overflow;
                continue;
            },
            else => continue,
        };
        if (!std.unicode.utf8ValidateSlice(data)) continue;
        if (maximum_text_bytes) |m| {
            if (data.len > m) return error.Overflow;
        }
        const text = try normalizeNewlines(ctx.allocator, data);
        try texts.put(ctx.allocator, relative, text);
    }
    return texts;
}

pub fn serverBaseDigestTexts(ctx: *AuditContext) !std.StringArrayHashMapUnmanaged([]const u8) {
    if (!ctx.server_mode) {
        const files = try repositoryDigestFiles(ctx, try trackedFiles(ctx));
        if (files.len > 1024) return error.Overflow;
        for (files) |f| {
            if (ctx.isSymlink(f)) return error.Overflow;
        }
        return trackedDigestTexts(ctx, files, 16 * 1024 * 1024);
    }
    if (ctx.server_digest_texts_cache == null) {
        const files = try repositoryDigestFiles(ctx, try trackedFiles(ctx));
        if (files.len > 1024) return error.Overflow;
        for (files) |f| {
            if (ctx.isSymlink(f)) return error.Overflow;
        }
        const local_texts = try trackedDigestTexts(ctx, files, 16 * 1024 * 1024);
        var cached: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
        for (local_texts.keys(), local_texts.values()) |k, v| {
            try cached.put(ctx.cache_allocator, try ctx.cache_allocator.dupe(u8, k), try ctx.cache_allocator.dupe(u8, v));
        }
        ctx.server_digest_texts_cache = cached;
    }
    var copy: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    const base = ctx.server_digest_texts_cache.?;
    for (base.keys(), base.values()) |k, v| {
        try copy.put(ctx.allocator, k, v);
    }
    return copy;
}

pub fn digestScope(relative: []const u8) []const u8 {
    if (sliceContainsStr(&DIGEST_TOP_LEVEL_FILES, relative)) return "build";
    if (std.mem.indexOfScalar(u8, relative, '/')) |slash| return relative[0..slash];
    return relative;
}

pub fn exactPolicyPath(value: []const u8) bool {
    if (value.len == 0 or value[0] == '/' or value[value.len - 1] == '/') return false;
    for (value) |c| {
        if (c == '*' or c == '?' or c == '[' or c == ']' or c == '{' or c == '}') return false;
    }
    var it = std.mem.splitScalar(u8, value, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

pub fn isLowerHex(s: []const u8, expected_len: usize) bool {
    if (s.len != expected_len) return false;
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

pub fn parseNonNegativeCount(s: []const u8) ?usize {
    if (s.len == 0) return null;
    if (std.mem.eql(u8, s, "0")) return 0;
    if (s[0] == '0') return null;
    for (s) |c| {
        if (!isDigit(c)) return null;
    }
    return std.fmt.parseInt(usize, s, 10) catch null;
}

pub fn digestInventoryRecordMap(
    ctx: *AuditContext,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) !std.StringArrayHashMapUnmanaged(DigestInventoryRecord) {
    var records: std.StringArrayHashMapUnmanaged(DigestInventoryRecord) = .empty;
    const all_findings = try digestFindings(ctx, texts);
    var i: usize = 0;
    while (i < all_findings.len) {
        const path = all_findings[i].path;
        var j = i + 1;
        while (j < all_findings.len and std.mem.eql(u8, all_findings[j].path, path)) : (j += 1) {}
        const path_findings = all_findings[i..j];
        var counts: [DIGEST_FINDING_KINDS.len]usize = @splat(0);
        for (path_findings) |f| {
            for (DIGEST_FINDING_KINDS, 0..) |kind, k_idx| {
                if (std.mem.eql(u8, f.kind, kind)) {
                    counts[k_idx] += 1;
                    break;
                }
            }
        }
        try records.put(ctx.allocator, path, .{
            .path = path,
            .scope = digestScope(path),
            .counts = counts,
            .sha512 = try canonicalSha512Findings(ctx.allocator, path_findings),
        });
        i = j;
    }
    return records;
}

pub fn digestInventoryLine(allocator: std.mem.Allocator, rec: DigestInventoryRecord) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}\t{s}\t{d}\t{d}\t{d}\t{d}\t{d}\t{s}",
        .{ rec.path, rec.scope, rec.counts[0], rec.counts[1], rec.counts[2], rec.counts[3], rec.counts[4], rec.sha512 },
    );
}

pub fn renderDigestInventory(
    ctx: *AuditContext,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![]u8 {
    const records = try digestInventoryRecordMap(ctx, texts);
    var out: std.ArrayList(u8) = .empty;
    for (records.values()) |rec| {
        const line = try digestInventoryLine(ctx.allocator, rec);
        try out.appendSlice(ctx.allocator, line);
        try out.append(ctx.allocator, '\n');
    }
    return out.toOwnedSlice(ctx.allocator);
}

pub fn parseDigestInventory(
    allocator: std.mem.Allocator,
    text: []const u8,
    failures: *std.ArrayList([]const u8),
) !std.StringArrayHashMapUnmanaged(DigestInventoryRecord) {
    var records: std.StringArrayHashMapUnmanaged(DigestInventoryRecord) = .empty;
    var paths: std.ArrayList([]const u8) = .empty;
    if (text.len > 0 and text[text.len - 1] != '\n') {
        try failures.append(allocator, try allocator.dupe(u8, "digest inventory is not line-oriented"));
    }
    const trimmed = if (text.len > 0 and text[text.len - 1] == '\n') text[0 .. text.len - 1] else text;
    if (trimmed.len == 0) return records;
    var line_it = std.mem.splitScalar(u8, trimmed, '\n');
    var line_number: usize = 0;
    while (line_it.next()) |raw_line| {
        line_number += 1;
        const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r') raw_line[0 .. raw_line.len - 1] else raw_line;
        var fields: [DIGEST_INVENTORY_COLUMNS.len][]const u8 = undefined;
        var f_idx: usize = 0;
        var f_it = std.mem.splitScalar(u8, line, '\t');
        var too_many = false;
        while (f_it.next()) |field| {
            if (f_idx >= DIGEST_INVENTORY_COLUMNS.len) {
                too_many = true;
                break;
            }
            fields[f_idx] = field;
            f_idx += 1;
        }
        if (too_many or f_idx != DIGEST_INVENTORY_COLUMNS.len) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest inventory line {d} is malformed", .{line_number}));
            continue;
        }
        const path = fields[0];
        const scope = fields[1];
        const sha512 = fields[7];
        if (!exactPolicyPath(path) or !digestRelevantPath(path)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest inventory line {d} has an invalid path", .{line_number}));
            continue;
        }
        if (!std.mem.eql(u8, scope, digestScope(path))) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest inventory line {d} has an invalid scope", .{line_number}));
            continue;
        }
        if (!isLowerHex(sha512, 128)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest inventory line {d} has an invalid sha512", .{line_number}));
            continue;
        }
        var counts: [DIGEST_FINDING_KINDS.len]usize = undefined;
        var bad_count = false;
        for (0..DIGEST_FINDING_KINDS.len) |k_idx| {
            if (parseNonNegativeCount(fields[2 + k_idx])) |c| {
                counts[k_idx] = c;
            } else {
                bad_count = true;
                break;
            }
        }
        if (bad_count) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest inventory line {d} has an invalid count", .{line_number}));
            continue;
        }
        if (records.contains(path)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest inventory contains a duplicate record: {s}", .{path}));
        }
        try paths.append(allocator, path);
        var sha_arr: [128]u8 = undefined;
        @memcpy(&sha_arr, sha512);
        try records.put(allocator, path, .{
            .path = path,
            .scope = scope,
            .counts = counts,
            .sha512 = sha_arr,
        });
    }
    for (1..paths.items.len) |idx| {
        if (std.mem.order(u8, paths.items[idx - 1], paths.items[idx]) == .gt) {
            try failures.append(allocator, try allocator.dupe(u8, "digest inventory records are not sorted"));
            break;
        }
    }
    return records;
}

pub fn jsonStr(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return if (val == .string) val.string else null;
}

pub fn jsonInt(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const val = obj.get(key) orelse return null;
    return if (val == .integer) val.integer else null;
}

pub fn jsonBool(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const val = obj.get(key) orelse return null;
    return if (val == .bool) val.bool else null;
}

pub fn jsonObj(obj: std.json.ObjectMap, key: []const u8) ?std.json.ObjectMap {
    const val = obj.get(key) orelse return null;
    return if (val == .object) val.object else null;
}

pub fn jsonArr(obj: std.json.ObjectMap, key: []const u8) ?[]const std.json.Value {
    const val = obj.get(key) orelse return null;
    return if (val == .array) val.array.items else null;
}

pub fn jsonStrArrayEql(arr: []const std.json.Value, expected: []const []const u8) bool {
    if (arr.len != expected.len) return false;
    for (arr, expected) |v, exp| {
        if (v != .string or !std.mem.eql(u8, v.string, exp)) return false;
    }
    return true;
}

pub fn digestPolicyIdentityFailure(policy: std.json.ObjectMap) ?[]const u8 {
    const schema = jsonStr(policy, "schema") orelse return "digest cutover policy identity changed";
    const version = jsonInt(policy, "version") orelse return "digest cutover policy identity changed";
    const alg = jsonStr(policy, "fingerprint_algorithm") orelse return "digest cutover policy identity changed";
    if (!std.mem.eql(u8, schema, DIGEST_POLICY_SCHEMA) or version != DIGEST_POLICY_VERSION or !std.mem.eql(u8, alg, "sha512")) {
        return "digest cutover policy identity changed";
    }
    return null;
}

pub fn digestInventoryFailures(
    ctx: *AuditContext,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
    policy: std.json.ObjectMap,
    inventory_text: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    if (digestPolicyIdentityFailure(policy)) |msg| {
        try failures.append(ctx.allocator, try ctx.allocator.dupe(u8, msg));
        return failures.toOwnedSlice(ctx.allocator);
    }
    const inventory = jsonObj(policy, "inventory") orelse {
        try failures.append(ctx.allocator, try ctx.allocator.dupe(u8, "digest policy inventory is missing"));
        return failures.toOwnedSlice(ctx.allocator);
    };
    const inv_file = jsonStr(inventory, "file") orelse "";
    const inv_fmt = jsonStr(inventory, "format") orelse "";
    const inv_cols = jsonArr(inventory, "columns") orelse &.{};
    if (!std.mem.eql(u8, inv_file, DIGEST_INVENTORY_PATH) or
        !std.mem.eql(u8, inv_fmt, DIGEST_INVENTORY_FORMAT) or
        !jsonStrArrayEql(inv_cols, &DIGEST_INVENTORY_COLUMNS))
    {
        try failures.append(ctx.allocator, try ctx.allocator.dupe(u8, "digest policy inventory metadata changed"));
    }
    const classifications = jsonArr(inventory, "classifications") orelse {
        try failures.append(ctx.allocator, try ctx.allocator.dupe(u8, "digest policy classifications are missing"));
        return failures.toOwnedSlice(ctx.allocator);
    };
    var actual_scopes: std.StringHashMapUnmanaged(void) = .empty;
    for (texts.keys()) |path| {
        try actual_scopes.put(ctx.allocator, digestScope(path), {});
    }
    var seen_scopes: std.StringHashMapUnmanaged(void) = .empty;
    for (classifications) |entry_val| {
        if (entry_val != .object) {
            try failures.append(ctx.allocator, try ctx.allocator.dupe(u8, "digest policy contains a malformed classification"));
            continue;
        }
        const entry = entry_val.object;
        const scope = jsonStr(entry, "scope") orelse "";
        const classification = jsonStr(entry, "classification") orelse "";
        const rationale = jsonStr(entry, "rationale") orelse "";
        const trimmed_rationale = std.mem.trim(u8, rationale, " \t\r\n");
        if (scope.len == 0 or !actual_scopes.contains(scope) or seen_scopes.contains(scope) or
            classification.len == 0 or trimmed_rationale.len < 40)
        {
            try failures.append(ctx.allocator, try ctx.allocator.dupe(u8, "digest policy contains an invalid or duplicate classification"));
            continue;
        }
        try seen_scopes.put(ctx.allocator, scope, {});
    }
    if (seen_scopes.count() != actual_scopes.count()) {
        try failures.append(ctx.allocator, try ctx.allocator.dupe(u8, "digest policy does not classify every tracked audit scope"));
    }
    const expected_records = try parseDigestInventory(ctx.allocator, inventory_text, &failures);
    const actual_records = try digestInventoryRecordMap(ctx, texts);

    var missing_paths: std.ArrayList([]const u8) = .empty;
    for (actual_records.keys()) |path| {
        if (!expected_records.contains(path)) try missing_paths.append(ctx.allocator, path);
    }
    std.mem.sort([]const u8, missing_paths.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    for (missing_paths.items) |path| {
        try failures.append(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "digest inventory is missing a record: {s}", .{path}));
    }

    var extra_paths: std.ArrayList([]const u8) = .empty;
    for (expected_records.keys()) |path| {
        if (!actual_records.contains(path)) try extra_paths.append(ctx.allocator, path);
    }
    std.mem.sort([]const u8, extra_paths.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    for (extra_paths.items) |path| {
        try failures.append(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "digest inventory contains an unexpected record: {s}", .{path}));
    }

    var common_paths: std.ArrayList([]const u8) = .empty;
    for (actual_records.keys()) |path| {
        if (expected_records.contains(path)) try common_paths.append(ctx.allocator, path);
    }
    std.mem.sort([]const u8, common_paths.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    for (common_paths.items) |path| {
        const exp = expected_records.get(path).?;
        const act = actual_records.get(path).?;
        if (!exp.eql(act)) {
            const line = try digestInventoryLine(ctx.allocator, act);
            try failures.append(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "digest inventory record changed: {s} ({s})", .{ path, line }));
        }
    }
    return failures.toOwnedSlice(ctx.allocator);
}

pub fn semanticAllowlistLine(allocator: std.mem.Allocator, rec: SemanticAllowlistRecord) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}\t{s}\t{d}\t{s}", .{ rec.id, rec.path, rec.count, rec.sha512 });
}

pub fn parseSemanticAllowlistInventory(
    allocator: std.mem.Allocator,
    text: []const u8,
    failures: *std.ArrayList([]const u8),
) !std.StringArrayHashMapUnmanaged(SemanticAllowlistRecord) {
    var records: std.StringArrayHashMapUnmanaged(SemanticAllowlistRecord) = .empty;
    const KeyPair = struct { id: []const u8, path: []const u8 };
    var keys: std.ArrayList(KeyPair) = .empty;
    if (text.len > 0 and text[text.len - 1] != '\n') {
        try failures.append(allocator, try allocator.dupe(u8, "digest semantic allowlist inventory is not line-oriented"));
    }
    const trimmed = if (text.len > 0 and text[text.len - 1] == '\n') text[0 .. text.len - 1] else text;
    if (trimmed.len == 0) return records;
    var line_it = std.mem.splitScalar(u8, trimmed, '\n');
    var line_number: usize = 0;
    while (line_it.next()) |raw_line| {
        line_number += 1;
        const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r') raw_line[0 .. raw_line.len - 1] else raw_line;
        var fields: [DIGEST_SEMANTIC_ALLOWLIST_COLUMNS.len][]const u8 = undefined;
        var f_idx: usize = 0;
        var f_it = std.mem.splitScalar(u8, line, '\t');
        var too_many = false;
        while (f_it.next()) |field| {
            if (f_idx >= DIGEST_SEMANTIC_ALLOWLIST_COLUMNS.len) {
                too_many = true;
                break;
            }
            fields[f_idx] = field;
            f_idx += 1;
        }
        if (too_many or f_idx != DIGEST_SEMANTIC_ALLOWLIST_COLUMNS.len) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest semantic allowlist line {d} is malformed", .{line_number}));
            continue;
        }
        const id = fields[0];
        const path = fields[1];
        const count_text = fields[2];
        const sha512 = fields[3];
        var bad_id = id.len == 0;
        for (id) |c| {
            if (isSpace(c)) bad_id = true;
        }
        if (bad_id) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest semantic allowlist line {d} has an invalid id", .{line_number}));
            continue;
        }
        if (!exactPolicyPath(path) or !digestRelevantPath(path)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest semantic allowlist line {d} has an invalid path", .{line_number}));
            continue;
        }
        const count = parseNonNegativeCount(count_text) orelse {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest semantic allowlist line {d} has an invalid count", .{line_number}));
            continue;
        };
        if (!isLowerHex(sha512, 128)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest semantic allowlist line {d} has an invalid sha512", .{line_number}));
            continue;
        }
        const map_key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ id, path });
        if (records.contains(map_key)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest semantic allowlist contains a duplicate record: {s}:{s}", .{ id, path }));
        }
        try keys.append(allocator, .{ .id = id, .path = path });
        var sha_arr: [128]u8 = undefined;
        @memcpy(&sha_arr, sha512);
        try records.put(allocator, map_key, .{
            .id = id,
            .path = path,
            .count = count,
            .sha512 = sha_arr,
        });
    }
    for (1..keys.items.len) |idx| {
        const a = keys.items[idx - 1];
        const b = keys.items[idx];
        const id_cmp = std.mem.order(u8, a.id, b.id);
        if (id_cmp == .gt or (id_cmp == .eq and std.mem.order(u8, a.path, b.path) == .gt)) {
            try failures.append(allocator, try allocator.dupe(u8, "digest semantic allowlist records are not sorted"));
            break;
        }
    }
    return records;
}

pub fn renderSemanticAllowlistInventory(
    allocator: std.mem.Allocator,
    candidates: []const DigestCandidate,
    policy: std.json.ObjectMap,
) ![]u8 {
    const entries = jsonArr(policy, "semantic_allowlist") orelse &.{};
    var list: std.ArrayList(SemanticAllowlistRecord) = .empty;
    var seen: std.StringHashMapUnmanaged(usize) = .empty;
    for (entries) |entry_val| {
        if (entry_val != .object) continue;
        const entry = entry_val.object;
        const id = jsonStr(entry, "id") orelse continue;
        const kind = jsonStr(entry, "kind") orelse continue;
        const paths = jsonArr(entry, "paths") orelse continue;
        for (paths) |p_val| {
            if (p_val != .string) continue;
            const path = p_val.string;
            var selected: std.ArrayList(DigestCandidate) = .empty;
            for (candidates) |c| {
                if (std.mem.eql(u8, c.kind, kind) and std.mem.eql(u8, c.path, path)) {
                    try selected.append(allocator, c);
                }
            }
            const rec = SemanticAllowlistRecord{
                .id = id,
                .path = path,
                .count = selected.items.len,
                .sha512 = try canonicalSha512Candidates(allocator, selected.items),
            };
            const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ id, path });
            if (seen.get(key)) |existing_idx| {
                list.items[existing_idx] = rec;
            } else {
                try seen.put(allocator, key, list.items.len);
                try list.append(allocator, rec);
            }
        }
    }
    std.mem.sort(SemanticAllowlistRecord, list.items, {}, struct {
        fn lessThan(_: void, a: SemanticAllowlistRecord, b: SemanticAllowlistRecord) bool {
            if (!std.mem.eql(u8, a.id, b.id)) return std.mem.lessThan(u8, a.id, b.id);
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lessThan);
    var out: std.ArrayList(u8) = .empty;
    for (list.items) |rec| {
        const line = try semanticAllowlistLine(allocator, rec);
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

pub fn semanticAllowlistFailures(
    allocator: std.mem.Allocator,
    candidates: []const DigestCandidate,
    policy: std.json.ObjectMap,
    inventory_text: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const entries = jsonArr(policy, "semantic_allowlist") orelse {
        try failures.append(allocator, try allocator.dupe(u8, "digest semantic allowlist is missing"));
        return failures.toOwnedSlice(allocator);
    };
    if (entries.len == 0) {
        try failures.append(allocator, try allocator.dupe(u8, "digest semantic allowlist is missing"));
        return failures.toOwnedSlice(allocator);
    }
    const metadata_opt = jsonObj(policy, "semantic_allowlist_inventory");
    if (metadata_opt == null or
        !std.mem.eql(u8, jsonStr(metadata_opt.?, "file") orelse "", DIGEST_SEMANTIC_ALLOWLIST_PATH) or
        !std.mem.eql(u8, jsonStr(metadata_opt.?, "format") orelse "", DIGEST_SEMANTIC_ALLOWLIST_FORMAT) or
        !jsonStrArrayEql(jsonArr(metadata_opt.?, "columns") orelse &.{}, &DIGEST_SEMANTIC_ALLOWLIST_COLUMNS))
    {
        try failures.append(allocator, try allocator.dupe(u8, "digest semantic allowlist inventory metadata changed"));
    }
    const expected_records = try parseSemanticAllowlistInventory(allocator, inventory_text, &failures);
    var actual_records: std.StringArrayHashMapUnmanaged(SemanticAllowlistRecord) = .empty;
    const covered = try allocator.alloc(bool, candidates.len);
    @memset(covered, false);
    var seen_ids: std.StringHashMapUnmanaged(void) = .empty;
    const allowed_classes = [_][]const u8{
        "fixed_control_and_versioned_compatibility",
        "fixed_control_protocol",
        "generated_external_protocol",
        "historical_versioned_compatibility",
        "typed_identity_internal",
    };

    for (entries) |entry_val| {
        if (entry_val != .object) {
            try failures.append(allocator, try allocator.dupe(u8, "digest semantic allowlist contains a malformed entry"));
            continue;
        }
        const entry = entry_val.object;
        const id = jsonStr(entry, "id") orelse "";
        const kind = jsonStr(entry, "kind") orelse "";
        const classification = jsonStr(entry, "classification") orelse "";
        const rationale = jsonStr(entry, "rationale") orelse "";
        const paths_val = jsonArr(entry, "paths") orelse &.{};
        var paths: std.ArrayList([]const u8) = .empty;
        var paths_valid = paths_val.len > 0;
        for (paths_val) |pv| {
            if (pv != .string or !exactPolicyPath(pv.string)) {
                paths_valid = false;
                break;
            }
            try paths.append(allocator, pv.string);
        }
        if (paths_valid) {
            for (1..paths.items.len) |idx| {
                if (std.mem.order(u8, paths.items[idx - 1], paths.items[idx]) != .lt) {
                    paths_valid = false;
                    break;
                }
            }
        }
        const trimmed_rationale = std.mem.trim(u8, rationale, " \t\r\n");
        if (id.len == 0 or seen_ids.contains(id) or kind.len == 0 or
            !sliceContainsStr(&allowed_classes, classification) or
            trimmed_rationale.len < 40 or !paths_valid or
            entry.contains("count") or entry.contains("sha512"))
        {
            try failures.append(allocator, try allocator.dupe(u8, "digest semantic allowlist contains an invalid or overbroad entry"));
            continue;
        }
        try seen_ids.put(allocator, id, {});
        var selected_indices: std.ArrayList(usize) = .empty;
        var matched_paths: std.StringHashMapUnmanaged(void) = .empty;
        for (candidates, 0..) |c, c_idx| {
            if (std.mem.eql(u8, c.kind, kind) and sliceContainsStr(paths.items, c.path)) {
                try selected_indices.append(allocator, c_idx);
                try matched_paths.put(allocator, c.path, {});
            }
        }
        if (selected_indices.items.len == 0 or matched_paths.count() != paths.items.len) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest semantic allowlist changed: {s}", .{id}));
            continue;
        }
        for (paths.items) |path| {
            var path_selected: std.ArrayList(DigestCandidate) = .empty;
            for (selected_indices.items) |c_idx| {
                if (std.mem.eql(u8, candidates[c_idx].path, path)) {
                    try path_selected.append(allocator, candidates[c_idx]);
                }
            }
            const map_key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ id, path });
            try actual_records.put(allocator, map_key, .{
                .id = id,
                .path = path,
                .count = path_selected.items.len,
                .sha512 = try canonicalSha512Candidates(allocator, path_selected.items),
            });
        }
        for (selected_indices.items) |c_idx| {
            const c = candidates[c_idx];
            if (covered[c_idx]) {
                try failures.append(allocator, try std.fmt.allocPrint(
                    allocator,
                    "digest semantic candidate is multiply classified: {s}:{s}",
                    .{ c.path, c.selector },
                ));
            }
            covered[c_idx] = true;
        }
        if (!std.mem.eql(u8, classification, "historical_versioned_compatibility")) {
            for (selected_indices.items) |c_idx| {
                const c = candidates[c_idx];
                if ((std.mem.eql(u8, c.kind, "raw_32_byte_field") or std.mem.eql(u8, c.kind, "schema_sha256_field")) and
                    hasAuthorityField(c.selector))
                {
                    try failures.append(allocator, try std.fmt.allocPrint(
                        allocator,
                        "{s}:{s}: SHA256-only package/repository/artifact authority is forbidden",
                        .{ c.path, c.selector },
                    ));
                }
                if (std.mem.eql(u8, c.kind, "fixed_sha256_cas")) {
                    try failures.append(allocator, try std.fmt.allocPrint(
                        allocator,
                        "{s}:{s}: fixed SHA256 CAS layout is forbidden",
                        .{ c.path, c.selector },
                    ));
                }
            }
        }
    }

    var missing_keys: std.ArrayList([]const u8) = .empty;
    for (actual_records.keys()) |k| {
        if (!expected_records.contains(k)) try missing_keys.append(allocator, k);
    }
    std.mem.sort([]const u8, missing_keys.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    for (missing_keys.items) |k| {
        const rec = actual_records.get(k).?;
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest semantic allowlist is missing a record: {s}:{s}", .{ rec.id, rec.path }));
    }

    var extra_keys: std.ArrayList([]const u8) = .empty;
    for (expected_records.keys()) |k| {
        if (!actual_records.contains(k)) try extra_keys.append(allocator, k);
    }
    std.mem.sort([]const u8, extra_keys.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    for (extra_keys.items) |k| {
        const rec = expected_records.get(k).?;
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "digest semantic allowlist contains an unexpected record: {s}:{s}", .{ rec.id, rec.path }));
    }

    var common_keys: std.ArrayList([]const u8) = .empty;
    for (actual_records.keys()) |k| {
        if (expected_records.contains(k)) try common_keys.append(allocator, k);
    }
    std.mem.sort([]const u8, common_keys.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    for (common_keys.items) |k| {
        const exp = expected_records.get(k).?;
        const act = actual_records.get(k).?;
        if (!exp.eql(act)) {
            const line = try semanticAllowlistLine(allocator, act);
            try failures.append(allocator, try std.fmt.allocPrint(
                allocator,
                "digest semantic allowlist record changed: {s}:{s} ({s})",
                .{ act.id, act.path, line },
            ));
        }
    }

    for (candidates, 0..) |c, idx| {
        if (!covered[idx]) {
            const kind_spaces = try std.mem.replaceOwned(u8, allocator, c.kind, "_", " ");
            try failures.append(allocator, try std.fmt.allocPrint(
                allocator,
                "{s}:{s}: unreviewed {s}",
                .{ c.path, c.selector, kind_spaces },
            ));
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn typedDigestAuthorityFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const SourceReq = struct { path: []const u8, tokens: []const []const u8 };
    const source_reqs = [_]SourceReq{
        .{
            .path = "src/content_digest.zig",
            .tokens = &.{
                "pub const Value = union(Algorithm)",
                "pub const Set = struct",
                "pub const Identity = struct",
                "pub const JsonValue = struct",
                "pub const JsonIdentity = struct",
                "pub fn cacheKey(self: Identity",
            },
        },
        .{
            .path = "src/exact_lock_v3.zig",
            .tokens = &.{
                "index_identity: content_digest.Identity",
                "archive_identity: content_digest.Identity",
            },
        },
        .{
            .path = "src/package_acquisition.zig",
            .tokens = &.{
                "pub const namespace = \"packages-v2\"",
                "pub const Digest = content_digest.Identity",
                "digest.cacheKey(&name_buffer)",
            },
        },
        .{
            .path = "src/package_origin.zig",
            .tokens = &.{
                "artifact_id: content_digest.Value",
                "archive_identity: content_digest.Identity",
            },
        },
        .{
            .path = "src/repository_refresh.zig",
            .tokens = &.{
                "index_identity: content_digest.Identity",
            },
        },
    };
    for (source_reqs) |req| {
        const text = texts.get(req.path) orelse {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: versioned typed digest authority implementation changed", .{req.path}));
            continue;
        };
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, text, tok) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: versioned typed digest authority implementation changed", .{req.path}));
                break;
            }
        }
    }

    const SchemaReq = struct {
        path: []const u8,
        archive_identity: usize,
        artifact_id: usize,
        index_identity: usize,
    };
    const schema_reqs = [_]SchemaReq{
        .{ .path = "schema/exact-closure-lock-v3.json", .archive_identity = 3, .artifact_id = 2, .index_identity = 1 },
        .{ .path = "schema/native-transaction-authorization-v2.json", .archive_identity = 2, .artifact_id = 1, .index_identity = 0 },
        .{ .path = "schema/native-transaction-program-v2.json", .archive_identity = 3, .artifact_id = 1, .index_identity = 0 },
        .{ .path = "schema/transaction-plan-v4.json", .archive_identity = 2, .artifact_id = 1, .index_identity = 0 },
        .{ .path = "schema/transaction-result-v3.json", .archive_identity = 1, .artifact_id = 1, .index_identity = 0 },
    };

    for (schema_reqs) |req| {
        const text = texts.get(req.path) orelse {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: current typed digest schema is missing", .{req.path}));
            continue;
        };
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: current typed digest schema is invalid JSON", .{req.path}));
            continue;
        };
        var counts = struct {
            archive_identity: usize = 0,
            artifact_id: usize = 0,
            index_identity: usize = 0,
        }{};
        const Walk = struct {
            fn walk(
                alloc: std.mem.Allocator,
                rel: []const u8,
                val: std.json.Value,
                c: anytype,
                fails: *std.ArrayList([]const u8),
            ) !void {
                switch (val) {
                    .object => |obj| {
                        if (obj.get("properties")) |props| {
                            if (props == .object) {
                                var it = props.object.iterator();
                                while (it.next()) |entry| {
                                    const name = entry.key_ptr.*;
                                    var is_target = false;
                                    if (std.mem.eql(u8, name, "archive_identity")) {
                                        c.archive_identity += 1;
                                        is_target = true;
                                    } else if (std.mem.eql(u8, name, "artifact_id")) {
                                        c.artifact_id += 1;
                                        is_target = true;
                                    } else if (std.mem.eql(u8, name, "index_identity")) {
                                        c.index_identity += 1;
                                        is_target = true;
                                    }
                                    if (is_target) {
                                        var enc: std.ArrayList(u8) = .empty;
                                        try appendCanonicalJsonValue(&enc, alloc, entry.value_ptr.*);
                                        const expected_ref = if (std.mem.eql(u8, name, "artifact_id")) "#/$defs/digest" else "#/$defs/digestIdentity";
                                        if (std.mem.indexOf(u8, enc.items, expected_ref) == null) {
                                            try fails.append(alloc, try std.fmt.allocPrint(alloc, "{s}:{s}: current authority is not algorithm-tagged", .{ rel, name }));
                                        }
                                    }
                                }
                            }
                        }
                        for (obj.values()) |child| try walk(alloc, rel, child, c, fails);
                    },
                    .array => |arr| {
                        for (arr.items) |child| try walk(alloc, rel, child, c, fails);
                    },
                    else => {},
                }
            }
        };
        try Walk.walk(allocator, req.path, parsed.value, &counts, &failures);
        if (counts.archive_identity != req.archive_identity or
            counts.artifact_id != req.artifact_id or
            counts.index_identity != req.index_identity)
        {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: typed package/repository/artifact authority fields changed", .{req.path}));
        }
        for ([_][]const u8{
            "package_sha256", "package_digest", "cas_sha256",
            "index_sha256",   "archive_sha256", "archive_digest",
        }) |forbidden| {
            const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{forbidden});
            if (std.mem.indexOf(u8, text, quoted) != null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}:{s}: current schema reintroduced SHA256-only authority", .{ req.path, forbidden }));
            }
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn digestCutoverFailures(
    ctx: *AuditContext,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
    policy: std.json.ObjectMap,
    inventory_text: []const u8,
    semantic_inventory_text: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for (try digestInventoryFailures(ctx, texts, policy, inventory_text)) |f| try failures.append(ctx.allocator, f);
    const cands = try digestSemanticCandidates(ctx, texts);
    for (try semanticAllowlistFailures(ctx.allocator, cands, policy, semantic_inventory_text)) |f| try failures.append(ctx.allocator, f);
    for (try typedDigestAuthorityFailures(ctx.allocator, texts)) |f| try failures.append(ctx.allocator, f);
    return failures.toOwnedSlice(ctx.allocator);
}

pub fn auditDigestCutover(ctx: *AuditContext, files: []const []const u8) !void {
    if (!ctx.isRegularFile(DIGEST_POLICY_PATH)) return ctx.fail("digest cutover policy is missing");
    if (!ctx.isRegularFile(DIGEST_INVENTORY_PATH)) return ctx.fail("digest inventory is missing");
    if (!ctx.isRegularFile(DIGEST_SEMANTIC_ALLOWLIST_PATH)) return ctx.fail("digest semantic allowlist inventory is missing");
    const policy_raw = ctx.readText(DIGEST_POLICY_PATH) catch return ctx.fail("digest cutover policy is invalid JSON");
    const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, policy_raw, .{}) catch return ctx.fail("digest cutover policy is invalid JSON");
    if (parsed.value != .object) return ctx.fail("digest cutover policy is invalid JSON");
    const policy = parsed.value.object;
    if (digestPolicyIdentityFailure(policy)) |msg| return ctx.fail(msg);

    const scope_obj = jsonObj(policy, "scope") orelse return ctx.fail("digest cutover policy scope or self-exclusion changed");
    const expected_rationale =
        "The repository manifest includes tracked and non-ignored untracked " ++
        "files so pre-commit audit results remain stable after commit. The " ++
        "policy, per-file inventory, semantic allowlist inventory, and " ++
        "audit/canary implementation are excluded from token findings to " ++
        "avoid recursive self-classification; they do not define repository " ++
        "digest authority.";
    const excluded_arr = jsonArr(scope_obj, "excluded_finding_paths") orelse &.{};
    if (scope_obj.count() != 4 or
        !jsonStrArrayEql(jsonArr(scope_obj, "roots") orelse &.{}, &DIGEST_SCOPE_ROOTS) or
        !jsonStrArrayEql(jsonArr(scope_obj, "top_level_files") orelse &.{}, &DIGEST_TOP_LEVEL_FILES) or
        !jsonStrArrayEql(excluded_arr, &DIGEST_POLICY_EXCLUDED_FINDINGS) or
        !std.mem.eql(u8, jsonStr(scope_obj, "exclusion_rationale") orelse "", expected_rationale))
    {
        return ctx.fail("digest cutover policy scope or self-exclusion changed");
    }

    const auth_obj = jsonObj(policy, "authority_policy") orelse return ctx.fail("digest cutover authority policy changed");
    if (auth_obj.count() != 6 or
        !std.mem.eql(
            u8,
            jsonStr(auth_obj, "current_package_repository_artifact_authority") orelse "",
            "content_digest.Identity, content_digest.Value, content_digest.Set, or their versioned algorithm-tagged serialized forms",
        ) or
        !std.mem.eql(u8, jsonStr(auth_obj, "sha256_only_authority") orelse "", "forbidden") or
        !std.mem.eql(u8, jsonStr(auth_obj, "raw_32_byte_authority") orelse "", "forbidden") or
        !std.mem.eql(u8, jsonStr(auth_obj, "fixed_64_hex_authority") orelse "", "forbidden") or
        !std.mem.eql(u8, jsonStr(auth_obj, "fixed_sha256_cas_layout") orelse "", "forbidden") or
        !std.mem.eql(
            u8,
            jsonStr(auth_obj, "historical_and_control_exception_rule") orelse "",
            "exact-path, exact-fingerprint, version-specific or frozen-control classification with a non-empty rationale",
        ))
    {
        return ctx.fail("digest cutover authority policy changed");
    }

    const texts = try trackedDigestTexts(ctx, files, null);
    const inventory_text = ctx.readText(DIGEST_INVENTORY_PATH) catch return ctx.fail("digest inventory is not UTF-8");
    const semantic_inventory_text = ctx.readText(DIGEST_SEMANTIC_ALLOWLIST_PATH) catch return ctx.fail("digest semantic allowlist inventory is not UTF-8");
    for (try digestCutoverFailures(ctx, texts, policy, inventory_text, semantic_inventory_text)) |msg| {
        try ctx.fail(msg);
    }
}

pub fn formatNormalizedPolicyJson(allocator: std.mem.Allocator, policy: std.json.ObjectMap) ![]u8 {
    // Reconstruct normalized policy with indent=2 matching Python json.dumps(normalized_policy, indent=2) + "\n"
    var norm: std.json.ObjectMap = .empty;
    for (policy.keys(), policy.values()) |k, v| {
        try norm.put(allocator, k, v);
    }
    try norm.put(allocator, "schema", .{ .string = DIGEST_POLICY_SCHEMA });
    try norm.put(allocator, "version", .{ .integer = DIGEST_POLICY_VERSION });
    try norm.put(allocator, "fingerprint_algorithm", .{ .string = "sha512" });

    var scope: std.json.ObjectMap = .empty;
    var roots_arr = std.json.Array.init(allocator);
    for (DIGEST_SCOPE_ROOTS) |r| try roots_arr.append(.{ .string = r });
    try scope.put(allocator, "roots", .{ .array = roots_arr });
    var top_arr = std.json.Array.init(allocator);
    for (DIGEST_TOP_LEVEL_FILES) |f| try top_arr.append(.{ .string = f });
    try scope.put(allocator, "top_level_files", .{ .array = top_arr });
    var excl_arr = std.json.Array.init(allocator);
    for (DIGEST_POLICY_EXCLUDED_FINDINGS) |f| try excl_arr.append(.{ .string = f });
    try scope.put(allocator, "excluded_finding_paths", .{ .array = excl_arr });
    try scope.put(allocator, "exclusion_rationale", .{
        .string = "The repository manifest includes tracked and non-ignored untracked " ++
            "files so pre-commit audit results remain stable after commit. The " ++
            "policy, per-file inventory, semantic allowlist inventory, and " ++
            "audit/canary implementation are excluded from token findings to " ++
            "avoid recursive self-classification; they do not define repository " ++
            "digest authority.",
    });
    try norm.put(allocator, "scope", .{ .object = scope });

    var inv: std.json.ObjectMap = .empty;
    try inv.put(allocator, "file", .{ .string = DIGEST_INVENTORY_PATH });
    try inv.put(allocator, "format", .{ .string = DIGEST_INVENTORY_FORMAT });
    var inv_cols = std.json.Array.init(allocator);
    for (DIGEST_INVENTORY_COLUMNS) |c| try inv_cols.append(.{ .string = c });
    try inv.put(allocator, "columns", .{ .array = inv_cols });
    var norm_classes = std.json.Array.init(allocator);
    if (jsonObj(policy, "inventory")) |orig_inv| {
        if (jsonArr(orig_inv, "classifications")) |classes| {
            for (classes) |c_val| {
                var c_obj: std.json.ObjectMap = .empty;
                if (c_val == .object) {
                    try c_obj.put(allocator, "scope", c_val.object.get("scope") orelse .null);
                    try c_obj.put(allocator, "classification", c_val.object.get("classification") orelse .null);
                    try c_obj.put(allocator, "rationale", c_val.object.get("rationale") orelse .null);
                }
                try norm_classes.append(.{ .object = c_obj });
            }
        }
    }
    try inv.put(allocator, "classifications", .{ .array = norm_classes });
    try norm.put(allocator, "inventory", .{ .object = inv });

    var sem_inv: std.json.ObjectMap = .empty;
    try sem_inv.put(allocator, "file", .{ .string = DIGEST_SEMANTIC_ALLOWLIST_PATH });
    try sem_inv.put(allocator, "format", .{ .string = DIGEST_SEMANTIC_ALLOWLIST_FORMAT });
    var sem_cols = std.json.Array.init(allocator);
    for (DIGEST_SEMANTIC_ALLOWLIST_COLUMNS) |c| try sem_cols.append(.{ .string = c });
    try sem_inv.put(allocator, "columns", .{ .array = sem_cols });
    try norm.put(allocator, "semantic_allowlist_inventory", .{ .object = sem_inv });

    var norm_sem = std.json.Array.init(allocator);
    if (jsonArr(policy, "semantic_allowlist")) |sem_entries| {
        for (sem_entries) |s_val| {
            var s_obj: std.json.ObjectMap = .empty;
            if (s_val == .object) {
                try s_obj.put(allocator, "id", s_val.object.get("id") orelse .null);
                try s_obj.put(allocator, "kind", s_val.object.get("kind") orelse .null);
                try s_obj.put(allocator, "classification", s_val.object.get("classification") orelse .null);
                try s_obj.put(allocator, "rationale", s_val.object.get("rationale") orelse .null);
                try s_obj.put(allocator, "paths", s_val.object.get("paths") orelse .null);
            }
            try norm_sem.append(.{ .object = s_obj });
        }
    }
    try norm.put(allocator, "semantic_allowlist", .{ .array = norm_sem });

    const Pretty = struct {
        fn writeValue(out: *std.ArrayList(u8), alloc: std.mem.Allocator, val: std.json.Value, indent: usize) !void {
            switch (val) {
                .null => try out.appendSlice(alloc, "null"),
                .bool => |b| try out.appendSlice(alloc, if (b) "true" else "false"),
                .integer => |n| try out.appendSlice(alloc, try std.fmt.allocPrint(alloc, "{d}", .{n})),
                .float => |f| try out.appendSlice(alloc, try std.fmt.allocPrint(alloc, "{d}", .{f})),
                .number_string => |s| try out.appendSlice(alloc, s),
                .string => |s| try appendJsonAsciiString(out, alloc, s),
                .array => |arr| {
                    if (arr.items.len == 0) {
                        try out.appendSlice(alloc, "[]");
                        return;
                    }
                    try out.appendSlice(alloc, "[\n");
                    for (arr.items, 0..) |item, idx| {
                        try out.appendNTimes(alloc, ' ', indent + 2);
                        try writeValue(out, alloc, item, indent + 2);
                        if (idx + 1 < arr.items.len) try out.append(alloc, ',');
                        try out.append(alloc, '\n');
                    }
                    try out.appendNTimes(alloc, ' ', indent);
                    try out.append(alloc, ']');
                },
                .object => |obj| {
                    if (obj.count() == 0) {
                        try out.appendSlice(alloc, "{}");
                        return;
                    }
                    try out.appendSlice(alloc, "{\n");
                    for (obj.keys(), obj.values(), 0..) |k, v, idx| {
                        try out.appendNTimes(alloc, ' ', indent + 2);
                        try appendJsonAsciiString(out, alloc, k);
                        try out.appendSlice(alloc, ": ");
                        try writeValue(out, alloc, v, indent + 2);
                        if (idx + 1 < obj.count()) try out.append(alloc, ',');
                        try out.append(alloc, '\n');
                    }
                    try out.appendNTimes(alloc, ' ', indent);
                    try out.append(alloc, '}');
                },
            }
        }
    };
    var out: std.ArrayList(u8) = .empty;
    try Pretty.writeValue(&out, allocator, .{ .object = norm }, 0);
    try out.append(allocator, '\n');
    return out.toOwnedSlice(allocator);
}

pub fn writeDigestInventory(ctx: *AuditContext, check: bool, stdout_buf: *std.ArrayList(u8), stderr_buf: *std.ArrayList(u8)) !u8 {
    const original_policy = ctx.readText(DIGEST_POLICY_PATH) catch {
        try stderr_buf.appendSlice(ctx.allocator, "security-audit: digest cutover policy is missing\n");
        return 2;
    };
    const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, original_policy, .{}) catch {
        try stderr_buf.appendSlice(ctx.allocator, "security-audit: digest cutover policy is invalid JSON\n");
        return 2;
    };
    if (parsed.value != .object) {
        try stderr_buf.appendSlice(ctx.allocator, "security-audit: digest cutover policy is malformed\n");
        return 2;
    }
    const texts = try trackedDigestTexts(ctx, try trackedFiles(ctx), null);
    const inventory_text = try renderDigestInventory(ctx, texts);
    const policy_text = try formatNormalizedPolicyJson(ctx.allocator, parsed.value.object);
    const norm_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, policy_text, .{});
    const semantic_inventory_text = try renderSemanticAllowlistInventory(
        ctx.allocator,
        try digestSemanticCandidates(ctx, texts),
        norm_parsed.value.object,
    );
    const original_inventory = ctx.readText(DIGEST_INVENTORY_PATH) catch "";
    const original_semantic = ctx.readText(DIGEST_SEMANTIC_ALLOWLIST_PATH) catch "";
    const changed = !std.mem.eql(u8, policy_text, original_policy) or
        !std.mem.eql(u8, inventory_text, original_inventory) or
        !std.mem.eql(u8, semantic_inventory_text, original_semantic);
    const failures = try digestCutoverFailures(
        ctx,
        texts,
        norm_parsed.value.object,
        inventory_text,
        semantic_inventory_text,
    );
    if (check) {
        try stdout_buf.appendSlice(ctx.allocator, if (changed) "stale\n" else "unchanged\n");
        for (failures) |f| {
            try stdout_buf.appendSlice(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "remaining: {s}\n", .{f}));
        }
        return if (changed or failures.len > 0) 1 else 0;
    }
    try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = try ctx.pathJoin(DIGEST_POLICY_PATH), .data = policy_text });
    try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = try ctx.pathJoin(DIGEST_INVENTORY_PATH), .data = inventory_text });
    try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = try ctx.pathJoin(DIGEST_SEMANTIC_ALLOWLIST_PATH), .data = semantic_inventory_text });
    try stdout_buf.appendSlice(ctx.allocator, if (changed) "rewritten\n" else "unchanged\n");
    for (failures) |f| {
        try stdout_buf.appendSlice(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "remaining: {s}\n", .{f}));
    }
    return if (failures.len > 0) 1 else 0;
}

fn syntheticDigestInventoryPolicy(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
    omit_scope: ?[]const u8,
    old_schema: bool,
) !std.json.ObjectMap {
    var scopes_set: std.StringHashMapUnmanaged(void) = .empty;
    var scopes: std.ArrayList([]const u8) = .empty;
    for (texts.keys()) |path| {
        const s = digestScope(path);
        if (!(try scopes_set.getOrPut(allocator, s)).found_existing) {
            try scopes.append(allocator, s);
        }
    }
    std.mem.sort([]const u8, scopes.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    var classes = std.json.Array.init(allocator);
    for (scopes.items) |s| {
        if (omit_scope) |om| {
            if (std.mem.eql(u8, s, om)) continue;
        }
        var c_obj: std.json.ObjectMap = .empty;
        try c_obj.put(allocator, "scope", .{ .string = s });
        try c_obj.put(allocator, "classification", .{ .string = "synthetic_test_scope" });
        try c_obj.put(allocator, "rationale", .{
            .string = try std.fmt.allocPrint(
                allocator,
                "Synthetic digest inventory test classification for {s}; this rationale is intentionally long enough for policy checks.",
                .{s},
            ),
        });
        try classes.append(.{ .object = c_obj });
    }
    var inv: std.json.ObjectMap = .empty;
    try inv.put(allocator, "file", .{ .string = DIGEST_INVENTORY_PATH });
    try inv.put(allocator, "format", .{ .string = DIGEST_INVENTORY_FORMAT });
    var cols = std.json.Array.init(allocator);
    for (DIGEST_INVENTORY_COLUMNS) |c| try cols.append(.{ .string = c });
    try inv.put(allocator, "columns", .{ .array = cols });
    try inv.put(allocator, "classifications", .{ .array = classes });

    var policy: std.json.ObjectMap = .empty;
    try policy.put(allocator, "schema", .{
        .string = if (old_schema) "https://debz.dev/security/digest-cutover-policy-v2" else DIGEST_POLICY_SCHEMA,
    });
    try policy.put(allocator, "version", .{ .integer = if (old_schema) 2 else DIGEST_POLICY_VERSION });
    try policy.put(allocator, "fingerprint_algorithm", .{ .string = "sha512" });
    try policy.put(allocator, "inventory", .{ .object = inv });
    return policy;
}

fn digestInventoryLineForPath(inventory_text: []const u8, path: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, inventory_text, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, path) and line.len > path.len and line[path.len] == '\t') {
            return line;
        }
    }
    return null;
}

fn replaceDigestInventoryField(
    allocator: std.mem.Allocator,
    inventory_text: []const u8,
    path: []const u8,
    field_idx: usize,
    replacement_val: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    const trimmed = if (inventory_text.len > 0 and inventory_text[inventory_text.len - 1] == '\n')
        inventory_text[0 .. inventory_text.len - 1]
    else
        inventory_text;
    var it = std.mem.splitScalar(u8, trimmed, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, path) and line.len > path.len and line[path.len] == '\t') {
            var f_it = std.mem.splitScalar(u8, line, '\t');
            var idx: usize = 0;
            while (f_it.next()) |f| : (idx += 1) {
                if (idx > 0) try out.append(allocator, '\t');
                try out.appendSlice(allocator, if (idx == field_idx) replacement_val else f);
            }
        } else {
            try out.appendSlice(allocator, line);
        }
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

pub fn digestInventorySyntheticFailures(ctx: *AuditContext, case_name: []const u8) ![][]const u8 {
    var texts: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    try texts.put(ctx.allocator, "doc/digest-synthetic.md", "Documentation sha256 compatibility marker.\n");
    try texts.put(ctx.allocator, "doc/empty-digest-synthetic.md", "Plain documentation without findings.\n");
    try texts.put(
        ctx.allocator,
        "src/digest_synthetic.zig",
        "pub const package_sha256 = \"sha256\";\npub const digest_bytes: [32]u8 = undefined;\n",
    );
    try texts.put(ctx.allocator, "tools/digest_synthetic.py", "sha256 = 'fixture'\n");

    var policy = try syntheticDigestInventoryPolicy(ctx.allocator, texts, null, false);
    var inventory_text: []const u8 = try renderDigestInventory(ctx, texts);
    const zero_sha512_arr: [128]u8 = @splat('0');
    const zero_sha512: []const u8 = &zero_sha512_arr;

    if (std.mem.eql(u8, case_name, "valid")) {
        // unchanged
    } else if (std.mem.eql(u8, case_name, "added")) {
        const orig = texts.get("src/digest_synthetic.zig").?;
        try texts.put(ctx.allocator, "src/digest_synthetic.zig", try std.fmt.allocPrint(ctx.allocator, "{s}\n// added sha256 canary\n", .{orig}));
    } else if (std.mem.eql(u8, case_name, "removed")) {
        const orig = texts.get("src/digest_synthetic.zig").?;
        const idx = std.mem.indexOf(u8, orig, "sha256").?;
        try texts.put(ctx.allocator, "src/digest_synthetic.zig", try std.fmt.allocPrint(ctx.allocator, "{s}sha-512{s}", .{ orig[0..idx], orig[idx + 6 ..] }));
    } else if (std.mem.eql(u8, case_name, "edited")) {
        const orig = texts.get("src/digest_synthetic.zig").?;
        const idx = std.mem.indexOf(u8, orig, "package_sha256").?;
        try texts.put(
            ctx.allocator,
            "src/digest_synthetic.zig",
            try std.fmt.allocPrint(ctx.allocator, "{s}package_sha256_changed{s}", .{ orig[0..idx], orig[idx + "package_sha256".len ..] }),
        );
    } else if (std.mem.eql(u8, case_name, "missing-record")) {
        const line = digestInventoryLineForPath(inventory_text, "src/digest_synthetic.zig") orelse return error.InvalidCase;
        const target = try std.fmt.allocPrint(ctx.allocator, "{s}\n", .{line});
        inventory_text = try std.mem.replaceOwned(u8, ctx.allocator, inventory_text, target, "");
    } else if (std.mem.eql(u8, case_name, "extra-missing-file")) {
        inventory_text = try std.fmt.allocPrint(
            ctx.allocator,
            "{s}tools/zzzz_digest_inventory_canary.py\ttools\t0\t0\t0\t0\t1\t{s}\n",
            .{ inventory_text, zero_sha512 },
        );
    } else if (std.mem.eql(u8, case_name, "extra-no-findings")) {
        const first_nl = std.mem.indexOfScalar(u8, inventory_text, '\n').?;
        inventory_text = try std.fmt.allocPrint(
            ctx.allocator,
            "{s}\ndoc/empty-digest-synthetic.md\tdoc\t0\t0\t0\t0\t0\t{s}\n{s}",
            .{ inventory_text[0..first_nl], zero_sha512, inventory_text[first_nl + 1 ..] },
        );
    } else if (std.mem.eql(u8, case_name, "unsorted")) {
        const nl1 = std.mem.indexOfScalar(u8, inventory_text, '\n').?;
        const nl2 = std.mem.indexOfScalarPos(u8, inventory_text, nl1 + 1, '\n').?;
        inventory_text = try std.fmt.allocPrint(
            ctx.allocator,
            "{s}\n{s}\n{s}",
            .{ inventory_text[nl1 + 1 .. nl2], inventory_text[0..nl1], inventory_text[nl2 + 1 ..] },
        );
    } else if (std.mem.eql(u8, case_name, "duplicate")) {
        const nl1 = std.mem.indexOfScalar(u8, inventory_text, '\n').?;
        inventory_text = try std.fmt.allocPrint(ctx.allocator, "{s}{s}\n", .{ inventory_text, inventory_text[0..nl1] });
    } else if (std.mem.eql(u8, case_name, "malformed")) {
        inventory_text = try std.fmt.allocPrint(ctx.allocator, "{s}malformed\n", .{inventory_text});
    } else if (std.mem.eql(u8, case_name, "absolute-path")) {
        inventory_text = try replaceDigestInventoryField(ctx.allocator, inventory_text, "src/digest_synthetic.zig", 0, "/absolute");
    } else if (std.mem.eql(u8, case_name, "parent-path")) {
        inventory_text = try replaceDigestInventoryField(ctx.allocator, inventory_text, "src/digest_synthetic.zig", 0, "../escape");
    } else if (std.mem.eql(u8, case_name, "glob-path")) {
        inventory_text = try replaceDigestInventoryField(ctx.allocator, inventory_text, "src/digest_synthetic.zig", 0, "src/*.zig");
    } else if (std.mem.eql(u8, case_name, "outside-scope-path")) {
        inventory_text = try replaceDigestInventoryField(ctx.allocator, inventory_text, "src/digest_synthetic.zig", 0, "LICENSE");
    } else if (std.mem.eql(u8, case_name, "invalid-scope")) {
        inventory_text = try replaceDigestInventoryField(ctx.allocator, inventory_text, "src/digest_synthetic.zig", 1, "tools");
    } else if (std.mem.eql(u8, case_name, "old-schema")) {
        policy = try syntheticDigestInventoryPolicy(ctx.allocator, texts, null, true);
    } else if (std.mem.eql(u8, case_name, "unclassified-scope")) {
        policy = try syntheticDigestInventoryPolicy(ctx.allocator, texts, "src", false);
    } else {
        return error.UnknownSyntheticCase;
    }

    return digestInventoryFailures(ctx, texts, policy, inventory_text);
}

pub fn semanticAllowlistSyntheticFailures(allocator: std.mem.Allocator, case_name: []const u8) ![][]const u8 {
    var sem_inv: std.json.ObjectMap = .empty;
    try sem_inv.put(allocator, "file", .{ .string = DIGEST_SEMANTIC_ALLOWLIST_PATH });
    try sem_inv.put(allocator, "format", .{ .string = DIGEST_SEMANTIC_ALLOWLIST_FORMAT });
    var cols = std.json.Array.init(allocator);
    for (DIGEST_SEMANTIC_ALLOWLIST_COLUMNS) |c| try cols.append(.{ .string = c });
    try sem_inv.put(allocator, "columns", .{ .array = cols });

    var entry: std.json.ObjectMap = .empty;
    try entry.put(allocator, "id", .{ .string = "synthetic-raw-controls" });
    try entry.put(allocator, "kind", .{ .string = "raw_32_byte_field" });
    try entry.put(allocator, "classification", .{ .string = "fixed_control_protocol" });
    try entry.put(allocator, "rationale", .{
        .string = "Synthetic semantic allowlist control fields are reviewed test-only controls and not package authority.",
    });
    var paths = std.json.Array.init(allocator);
    try paths.append(.{ .string = "src/member.zig" });
    try paths.append(.{ .string = "tools/member.py" });
    try entry.put(allocator, "paths", .{ .array = paths });

    var sem_arr = std.json.Array.init(allocator);
    try sem_arr.append(.{ .object = entry });

    var policy: std.json.ObjectMap = .empty;
    try policy.put(allocator, "semantic_allowlist_inventory", .{ .object = sem_inv });
    try policy.put(allocator, "semantic_allowlist", .{ .array = sem_arr });

    var candidates: std.ArrayList(DigestCandidate) = .empty;
    try candidates.append(allocator, .{
        .context = "control_bytes: [32]u8",
        .kind = "raw_32_byte_field",
        .path = "src/member.zig",
        .selector = "control_bytes",
    });
    try candidates.append(allocator, .{
        .context = "other_control: [32]u8",
        .kind = "raw_32_byte_field",
        .path = "tools/member.py",
        .selector = "other_control",
    });

    var inventory_text: []const u8 = try renderSemanticAllowlistInventory(allocator, candidates.items, policy);
    const nl1 = std.mem.indexOfScalar(u8, inventory_text, '\n').?;
    const first = inventory_text[0..nl1];
    const zero_sha512_arr: [128]u8 = @splat('0');
    const zero_sha512: []const u8 = &zero_sha512_arr;

    if (std.mem.eql(u8, case_name, "valid")) {
        // unchanged
    } else if (std.mem.eql(u8, case_name, "missing")) {
        inventory_text = inventory_text[nl1 + 1 ..];
    } else if (std.mem.eql(u8, case_name, "extra")) {
        inventory_text = try std.fmt.allocPrint(
            allocator,
            "{s}synthetic-raw-controls\tsrc/not-member.zig\t1\t{s}\n",
            .{ inventory_text, zero_sha512 },
        );
    } else if (std.mem.eql(u8, case_name, "unsorted")) {
        const nl2 = std.mem.indexOfScalarPos(u8, inventory_text, nl1 + 1, '\n').?;
        const second = inventory_text[nl1 + 1 .. nl2];
        inventory_text = try std.fmt.allocPrint(allocator, "{s}\n{s}\n", .{ second, first });
    } else if (std.mem.eql(u8, case_name, "duplicate")) {
        inventory_text = try std.fmt.allocPrint(allocator, "{s}{s}\n", .{ inventory_text, first });
    } else if (std.mem.eql(u8, case_name, "malformed")) {
        inventory_text = try std.fmt.allocPrint(allocator, "{s}malformed\n", .{inventory_text});
    } else if (std.mem.eql(u8, case_name, "non-member-candidate")) {
        try candidates.append(allocator, .{
            .context = "new_control: [32]u8",
            .kind = "raw_32_byte_field",
            .path = "src/not_member.zig",
            .selector = "new_control",
        });
    } else if (std.mem.eql(u8, case_name, "member-without-candidates")) {
        candidates.items.len = 1;
    } else if (std.mem.eql(u8, case_name, "changed-count")) {
        var f_it = std.mem.splitScalar(u8, first, '\t');
        const f0 = f_it.next().?;
        const f1 = f_it.next().?;
        const f2 = f_it.next().?;
        const f3 = f_it.next().?;
        const c_num = (try std.fmt.parseInt(usize, f2, 10)) + 1;
        inventory_text = try std.fmt.allocPrint(
            allocator,
            "{s}\t{s}\t{d}\t{s}{s}",
            .{ f0, f1, c_num, f3, inventory_text[nl1..] },
        );
    } else if (std.mem.eql(u8, case_name, "changed-sha512")) {
        var f_it = std.mem.splitScalar(u8, first, '\t');
        const f0 = f_it.next().?;
        const f1 = f_it.next().?;
        const f2 = f_it.next().?;
        inventory_text = try std.fmt.allocPrint(
            allocator,
            "{s}\t{s}\t{s}\t{s}{s}",
            .{ f0, f1, f2, zero_sha512, inventory_text[nl1..] },
        );
    } else if (std.mem.eql(u8, case_name, "missing-entry")) {
        inventory_text = try std.fmt.allocPrint(
            allocator,
            "{s}missing-entry\tsrc/member.zig\t1\t{s}\n",
            .{ inventory_text, zero_sha512 },
        );
    } else {
        return error.UnknownSyntheticCase;
    }

    return semanticAllowlistFailures(allocator, candidates.items, policy, inventory_text);
}

pub fn dependencyOptions(allocator: std.mem.Allocator, build: []const u8, dependency: []const u8) !?std.StringHashMapUnmanaged([]const u8) {
    var blocks: std.ArrayList([]const u8) = .empty;
    var pos: usize = 0;
    const prefix = "b.dependency(";
    while (std.mem.indexOfPos(u8, build, pos, prefix)) |idx| {
        pos = idx + prefix.len;
        if (idx > 0 and isWordChar(build[idx - 1])) continue;
        var j = pos;
        while (j < build.len and isSpace(build[j])) : (j += 1) {}
        if (j >= build.len or build[j] != '"') continue;
        j += 1;
        if (!startsWithAt(build, j, dependency)) continue;
        j += dependency.len;
        if (j >= build.len or build[j] != '"') continue;
        j += 1;
        while (j < build.len and isSpace(build[j])) : (j += 1) {}
        if (j >= build.len or build[j] != ',') continue;
        j += 1;
        while (j < build.len and isSpace(build[j])) : (j += 1) {}
        if (!startsWithAt(build, j, ".{")) continue;
        j += 2;
        const close_brace = std.mem.indexOfScalarPos(u8, build, j, '}') orelse continue;
        var after_brace = close_brace + 1;
        while (after_brace < build.len and isSpace(build[after_brace])) : (after_brace += 1) {}
        if (after_brace >= build.len or build[after_brace] != ')') continue;
        try blocks.append(allocator, build[j..close_brace]);
    }
    if (blocks.items.len != 1) return null;
    var options: std.StringHashMapUnmanaged([]const u8) = .empty;
    var line_it = std.mem.splitScalar(u8, blocks.items[0], '\n');
    while (line_it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] != '.') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        var name = std.mem.trim(u8, line[1..eq], " \t");
        if (std.mem.startsWith(u8, name, "@\"") and std.mem.endsWith(u8, name, "\"") and name.len >= 3) {
            name = name[2 .. name.len - 1];
        } else {
            if (name.len == 0 or !((name[0] >= 'a' and name[0] <= 'z') or (name[0] >= 'A' and name[0] <= 'Z'))) continue;
            var valid_name = true;
            for (name) |c| {
                if (!isSlugChar(c)) valid_name = false;
            }
            if (!valid_name) continue;
        }
        var value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (std.mem.endsWith(u8, value, ",")) {
            value = std.mem.trimEnd(u8, value[0 .. value.len - 1], " \t");
        }
        if (value.len == 0 or std.mem.indexOfScalar(u8, value, ',') != null) continue;
        if ((try options.getOrPut(allocator, name)).found_existing) return null;
        try options.put(allocator, name, value);
    }
    return options;
}

pub const OptionPair = struct { name: []const u8, value: []const u8 };

pub fn dependencyOptionFailures(
    allocator: std.mem.Allocator,
    build: []const u8,
    dependency: []const u8,
    expected: []const OptionPair,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const options = (try dependencyOptions(allocator, build, dependency)) orelse {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: build dependency options are missing or ambiguous", .{dependency}));
        return failures.toOwnedSlice(allocator);
    };
    for (expected) |exp| {
        const actual = options.get(exp.name) orelse "";
        if (!std.mem.eql(u8, actual, exp.value)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: build option .{s} must be {s}", .{ dependency, exp.name, exp.value }));
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn runtimeMetadataFailures(
    allocator: std.mem.Allocator,
    runtime_val: std.json.Value,
    dependencies: std.StringArrayHashMapUnmanaged(std.json.ObjectMap),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const fail_msg = "Linux runtime metadata does not exactly identify fully static musl release binaries";
    if (runtime_val != .object) {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    }
    const runtime = runtime_val.object;
    if (runtime.count() != 3 or
        (jsonInt(runtime, "schema_version") orelse -1) != 1 or
        !std.mem.eql(u8, jsonStr(runtime, "package") orelse "", "debz"))
    {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    }
    const lrr = jsonObj(runtime, "linux_release_runtime") orelse {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    };
    if (lrr.count() != 5 or
        !std.mem.eql(u8, jsonStr(lrr, "binary_kind") orelse "", "fully_static") or
        !(jsonBool(lrr, "fully_static") orelse false))
    {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    }
    const sys_libs = jsonArr(lrr, "system_libraries") orelse {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    };
    if (sys_libs.len != 0) {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    }
    const libc_obj = jsonObj(lrr, "libc") orelse {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    };
    if (libc_obj.count() != 3 or
        !std.mem.eql(u8, jsonStr(libc_obj, "implementation") orelse "", "musl") or
        !std.mem.eql(u8, jsonStr(libc_obj, "linkage") orelse "", "static") or
        !std.mem.eql(
            u8,
            jsonStr(libc_obj, "expectation") orelse "",
            "musl and all required libraries are statically linked; no target-system shared libraries are required.",
        ))
    {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    }
    const inc_libs = jsonArr(lrr, "included_libraries") orelse {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    };
    var dep_names: std.ArrayList([]const u8) = .empty;
    for (dependencies.keys()) |k| try dep_names.append(allocator, k);
    std.mem.sort([]const u8, dep_names.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    if (inc_libs.len != dep_names.items.len) {
        try failures.append(allocator, try allocator.dupe(u8, fail_msg));
        return failures.toOwnedSlice(allocator);
    }
    for (inc_libs, dep_names.items) |lib_val, dep_name| {
        if (lib_val != .object or lib_val.object.count() != 4) {
            try failures.append(allocator, try allocator.dupe(u8, fail_msg));
            return failures.toOwnedSlice(allocator);
        }
        const lib = lib_val.object;
        const dep = dependencies.get(dep_name).?;
        if (!std.mem.eql(u8, jsonStr(lib, "name") orelse "", dep_name) or
            !std.mem.eql(u8, jsonStr(lib, "version") orelse "", jsonStr(dep, "version") orelse "") or
            !std.mem.eql(u8, jsonStr(lib, "linkage") orelse "", jsonStr(dep, "runtime_linkage") orelse "") or
            !std.mem.eql(u8, jsonStr(lib, "license") orelse "", jsonStr(dep, "license") orelse ""))
        {
            try failures.append(allocator, try allocator.dupe(u8, fail_msg));
            return failures.toOwnedSlice(allocator);
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn countSubstring(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;
    var count: usize = 0;
    var pos: usize = 0;
    while (fastIndexOfPos(haystack, pos, needle)) |idx| {
        count += 1;
        pos = idx + needle.len;
    }
    return count;
}

pub fn releaseInstallMetadataFailures(allocator: std.mem.Allocator, build: []const u8) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const source = "\"security/runtime-dependencies.json\"";
    if (countSubstring(build, source) != 1) {
        try failures.append(allocator, try allocator.dupe(u8, "runtime metadata install source is missing or ambiguous"));
    }
    const regular_start = std.mem.indexOf(u8, build, "const regular_files =");
    const regular_end = if (regular_start) |s| std.mem.indexOfPos(u8, build, s, "\n    };") else null;
    if (regular_start == null or regular_end == null or
        std.mem.indexOf(u8, build[regular_start.?..regular_end.?], source) != null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "ordinary install graph contains static-musl runtime metadata"));
    }
    const required = [_][]const u8{
        "const runtime_metadata = b.addInstallFile(",
        "b.path(\"security/runtime-dependencies.json\")",
        "\"share/debz/runtime-dependencies.json\"",
        "target.result.abi != .musl",
        "release-install requires a Linux musl target",
        "release_install.dependOn(&runtime_metadata_mode.step);",
    };
    for (required) |item| {
        if (std.mem.indexOf(u8, build, item) == null) {
            try failures.append(allocator, try allocator.dupe(u8, "release-install graph does not install static-musl runtime metadata"));
            break;
        }
    }
    return failures.toOwnedSlice(allocator);
}

fn lineNumberAt(text: []const u8, offset: usize) usize {
    return std.mem.count(u8, text[0..offset], "\n") + 1;
}

fn lineTextAt(text: []const u8, offset: usize) []const u8 {
    const start = if (std.mem.lastIndexOfScalar(u8, text[0..offset], '\n')) |nl| nl + 1 else 0;
    const end = std.mem.indexOfScalarPos(u8, text, offset, '\n') orelse text.len;
    return text[start..end];
}

pub fn walkRelativeZigFiles(ctx: *AuditContext, sub_dir: []const u8) ![][]const u8 {
    const full = try ctx.pathJoin(sub_dir);
    var dir = std.Io.Dir.cwd().openDir(ctx.io, full, .{ .iterate = true }) catch return &.{};
    defer dir.close(ctx.io);
    var walker = try dir.walk(ctx.allocator);
    defer walker.deinit();
    var out: std.ArrayList([]const u8) = .empty;
    while (try walker.next(ctx.io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;
        try out.append(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "{s}/{s}", .{ sub_dir, entry.path }));
    }
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    return out.toOwnedSlice(ctx.allocator);
}

pub fn auditProductionSources(ctx: *AuditContext) !void {
    const target_apt_paths = [_][]const u8{
        "const sources_list_path = \"/etc/apt/sources.list\";",
        "const sources_directory_path = \"/etc/apt/sources.list.d\";",
        "const global_keyring_path = \"/etc/apt/trusted.gpg\";",
        "const global_keyring_directory_path = \"/etc/apt/trusted.gpg.d\";",
    };
    const reviewed_profile_paths = [_][]const u8{
        ".source_path = \"/etc/apt/sources.list.d/microsoft-prod.list\",",
    };

    var process_calls: std.ArrayList([]const u8) = .empty;
    var child_calls: std.ArrayList([]const u8) = .empty;
    var namespace_calls: std.ArrayList([]const u8) = .empty;
    var capability_calls: std.ArrayList([]const u8) = .empty;

    const src_files = try walkRelativeZigFiles(ctx, "src");
    for (src_files) |relative| {
        const text = try ctx.readText(relative);
        const low = try asciiLowerAlloc(ctx.allocator, text);
        var first_test = std.mem.indexOf(u8, text, "\ntest \"");
        if (std.mem.eql(u8, relative, "src/target_apt_config.zig")) {
            if (std.mem.indexOf(u8, text, "\nconst test_fixture =")) |fs| {
                first_test = fs;
            }
        }

        // Check forbidden patterns:
        // 1. \b(?:getEnvVarOwned|getEnvMap)\b
        for ([_][]const u8{ "getenvvarowned", "getenvmap" }) |kw| {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, low, pos, kw)) |idx| {
                pos = idx + kw.len;
                if (isWordBoundary(low, idx) and isWordBoundary(low, idx + kw.len)) {
                    try ctx.failFmt("{s}:{d}: forbidden ambient environment access", .{ relative, lineNumberAt(text, idx) });
                }
            }
        }
        // 2. (?:"|\b)(?:sh|bash)(?:"|\b)\s*,\s*"-c"
        for ([_][]const u8{ "sh", "bash" }) |sh_kw| {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, low, pos, sh_kw)) |idx| {
                pos = idx + sh_kw.len;
                const before_ok = (idx > 0 and low[idx - 1] == '"') or isWordBoundary(low, idx);
                const end_kw = idx + sh_kw.len;
                if (!before_ok) continue;
                var j = end_kw;
                if (j < low.len and low[j] == '"') {
                    j += 1;
                } else if (!isWordBoundary(low, end_kw)) {
                    continue;
                }
                while (j < low.len and isSpace(low[j])) : (j += 1) {}
                if (j >= low.len or low[j] != ',') continue;
                j += 1;
                while (j < low.len and isSpace(low[j])) : (j += 1) {}
                if (startsWithAt(low, j, "\"-c\"")) {
                    try ctx.failFmt("{s}:{d}: forbidden shell command construction", .{ relative, lineNumberAt(text, idx) });
                }
            }
        }
        // 3. \b(?:system|popen)\s*\(
        for ([_][]const u8{ "system", "popen" }) |sys_kw| {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, low, pos, sys_kw)) |idx| {
                pos = idx + sys_kw.len;
                if (!isWordBoundary(low, idx) or !isWordBoundary(low, idx + sys_kw.len)) continue;
                var j = idx + sys_kw.len;
                while (j < low.len and isSpace(low[j])) : (j += 1) {}
                if (j < low.len and low[j] == '(') {
                    try ctx.failFmt("{s}:{d}: forbidden shell/process string execution", .{ relative, lineNumberAt(text, idx) });
                }
            }
        }
        // 4. /etc/apt(?:/|$)
        {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, low, pos, "/etc/apt")) |idx| {
                const end_idx = idx + "/etc/apt".len;
                pos = end_idx;
                var matched_val: ?[]const u8 = null;
                if (end_idx < low.len and low[end_idx] == '/') {
                    matched_val = text[idx .. end_idx + 1];
                } else if (end_idx == low.len or low[end_idx] == '\n') {
                    matched_val = text[idx..end_idx];
                }
                if (matched_val) |val| {
                    const lt = lineTextAt(text, idx);
                    const lt_stripped = std.mem.trim(u8, lt, " \t\r");
                    if (std.mem.eql(u8, relative, "src/repository_policy.zig") and
                        std.mem.eql(u8, val, "/etc/apt/") and
                        std.mem.indexOf(u8, lt, "&.{\"/etc/apt/trusted.gpg\"}") != null and
                        first_test != null and idx > first_test.?)
                    {
                        continue;
                    }
                    if (std.mem.eql(u8, relative, "src/target_apt_config.zig") and
                        (sliceContainsStr(&target_apt_paths, lt_stripped) or (first_test != null and idx > first_test.?)))
                    {
                        continue;
                    }
                    if (std.mem.eql(u8, relative, "src/reviewed_repository_profile.zig") and
                        sliceContainsStr(&reviewed_profile_paths, lt_stripped))
                    {
                        continue;
                    }
                    try ctx.failFmt("{s}:{d}: forbidden ambient APT configuration", .{ relative, lineNumberAt(text, idx) });
                }
            }
        }
        // 5. /var/lib/apt(?:/|$)
        {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, low, pos, "/var/lib/apt")) |idx| {
                const end_idx = idx + "/var/lib/apt".len;
                pos = end_idx;
                if ((end_idx < low.len and low[end_idx] == '/') or end_idx == low.len or low[end_idx] == '\n') {
                    try ctx.failFmt("{s}:{d}: forbidden ambient APT state", .{ relative, lineNumberAt(text, idx) });
                }
            }
        }
        // 6. \bGNUPGHOME\b
        {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, low, pos, "gnupghome")) |idx| {
                pos = idx + "gnupghome".len;
                if (isWordBoundary(low, idx) and isWordBoundary(low, idx + "gnupghome".len)) {
                    try ctx.failFmt("{s}:{d}: forbidden ambient GnuPG home", .{ relative, lineNumberAt(text, idx) });
                }
            }
        }

        // std.process.run\s*\(
        {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, text, pos, "std.process.run")) |idx| {
                pos = idx + "std.process.run".len;
                if (!isWordBoundary(text, idx)) continue;
                var j = pos;
                while (j < text.len and isSpace(text[j])) : (j += 1) {}
                if (j >= text.len or text[j] != '(') continue;
                if (std.mem.eql(u8, relative, "src/production_backend.zig")) {
                    const fs = std.mem.indexOf(u8, text, "\ntest \"production native baseline signed batch receipt zero-op replay and owned process crash\"");
                    const fe = if (fs) |s| std.mem.indexOfPos(u8, text, s + 1, "\ntest \"") else null;
                    if (fs != null and fe != null and fs.? < idx and idx < fe.? and
                        countSubstring(text, "std.process.run(") == 1 and
                        std.mem.indexOf(u8, text[fs.?..fe.?], ".argv = &.{\"/proc/self/exe\"}") != null and
                        std.mem.indexOf(u8, text[fs.?..fe.?], "CompletionPoint.after_native_receipt") != null)
                    {
                        continue;
                    }
                }
                try process_calls.append(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "{s}:{d}", .{ relative, lineNumberAt(text, idx) }));
            }
        }

        // linux.(?:fork|clone2|execve|chroot)\s*\(
        for ([_][]const u8{ "linux.fork", "linux.clone2", "linux.execve", "linux.chroot" }) |fn_name| {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, text, pos, fn_name)) |idx| {
                pos = idx + fn_name.len;
                if (!isWordBoundary(text, idx)) continue;
                var j = pos;
                while (j < text.len and isSpace(text[j])) : (j += 1) {}
                if (j >= text.len or text[j] != '(') continue;
                const matched_str = text[idx .. j + 1];
                if (std.mem.eql(u8, relative, "src/native_unpack.zig") and std.mem.eql(u8, matched_str, "linux.fork(")) {
                    const hs = std.mem.indexOf(u8, text, "fn testFreshDatabaseInstall(");
                    const he = if (hs) |s| std.mem.indexOfPos(u8, text, s, "\ntest \"native_unpack.test.caller-owned install initializes an absent database\"") else null;
                    if (hs != null and he != null and hs.? < idx and idx < he.? and countSubstring(text, "linux.fork(") == 1) {
                        continue;
                    }
                }
                if ((std.mem.eql(u8, relative, "src/apt_system_command.zig") or
                    std.mem.eql(u8, relative, "src/apt_system_orchestrator.zig") or
                    std.mem.eql(u8, relative, "src/production_backend.zig")) and
                    first_test != null and idx > first_test.? and std.mem.eql(u8, matched_str, "linux.fork("))
                {
                    continue;
                }
                try child_calls.append(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "{s}:{d}", .{ relative, lineNumberAt(text, idx) }));
            }
        }

        // linux.(?:clone2|unshare|setns|mount|move_mount|umount2)\s*\(
        for ([_][]const u8{ "linux.clone2", "linux.unshare", "linux.setns", "linux.mount", "linux.move_mount", "linux.umount2" }) |fn_name| {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, text, pos, fn_name)) |idx| {
                pos = idx + fn_name.len;
                if (!isWordBoundary(text, idx)) continue;
                var j = pos;
                while (j < text.len and isSpace(text[j])) : (j += 1) {}
                if (j >= text.len or text[j] != '(') continue;
                if (std.mem.eql(u8, relative, "src/apt_system_orchestrator.zig") and first_test != null and idx > first_test.?) {
                    continue;
                }
                try namespace_calls.append(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "{s}:{d}", .{ relative, lineNumberAt(text, idx) }));
            }
        }

        // linux.(?:capget|capset|prctl)\s*\( | linux.syscall2\s*\(\s*\.(?:capget|capset)\s*,
        for ([_][]const u8{ "linux.capget", "linux.capset", "linux.prctl" }) |fn_name| {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, text, pos, fn_name)) |idx| {
                pos = idx + fn_name.len;
                if (!isWordBoundary(text, idx)) continue;
                var j = pos;
                while (j < text.len and isSpace(text[j])) : (j += 1) {}
                if (j >= text.len or text[j] != '(') continue;
                try capability_calls.append(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "{s}:{d}", .{ relative, lineNumberAt(text, idx) }));
            }
        }
        {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, text, pos, "linux.syscall2")) |idx| {
                pos = idx + "linux.syscall2".len;
                if (!isWordBoundary(text, idx)) continue;
                var j = pos;
                while (j < text.len and isSpace(text[j])) : (j += 1) {}
                if (j >= text.len or text[j] != '(') continue;
                j += 1;
                while (j < text.len and isSpace(text[j])) : (j += 1) {}
                for ([_][]const u8{ ".capget", ".capset" }) |cap_op| {
                    if (startsWithAt(text, j, cap_op)) {
                        var k = j + cap_op.len;
                        while (k < text.len and isSpace(text[k])) : (k += 1) {}
                        if (k < text.len and text[k] == ',') {
                            try capability_calls.append(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "{s}:{d}", .{ relative, lineNumberAt(text, idx) }));
                        }
                    }
                }
            }
        }
    }

    var process_paths: std.ArrayList([]const u8) = .empty;
    for (process_calls.items) |call| {
        const colon = std.mem.lastIndexOfScalar(u8, call, ':').?;
        try process_paths.append(ctx.allocator, call[0..colon]);
    }
    std.mem.sort([]const u8, process_paths.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    if (process_paths.items.len != 2 or
        !std.mem.eql(u8, process_paths.items[0], "src/target_apt_config.zig") or
        !std.mem.eql(u8, process_paths.items[1], "src/transaction_executor.zig"))
    {
        try ctx.fail("production process boundary changed");
    }

    for (child_calls.items) |call| {
        const colon = std.mem.lastIndexOfScalar(u8, call, ':').?;
        const p = call[0..colon];
        if (!std.mem.eql(u8, p, "src/live_root.zig") and !std.mem.eql(u8, p, "src/maintainer_script.zig")) {
            try ctx.fail("native child-process boundary changed");
            break;
        }
    }
    for (namespace_calls.items) |call| {
        const colon = std.mem.lastIndexOfScalar(u8, call, ':').?;
        const p = call[0..colon];
        if (!std.mem.eql(u8, p, "src/live_root.zig") and !std.mem.eql(u8, p, "src/maintainer_script.zig")) {
            try ctx.fail("native namespace boundary changed");
            break;
        }
    }
    for (capability_calls.items) |call| {
        const colon = std.mem.lastIndexOfScalar(u8, call, ':').?;
        const p = call[0..colon];
        if (!std.mem.eql(u8, p, "src/maintainer_script.zig")) {
            try ctx.fail("native capability boundary changed");
            break;
        }
    }

    const runner = try ctx.readText("src/maintainer_script.zig");
    for ([_][]const u8{
        "const clone_flags = linux.CLONE.NEWNET |",
        "linux.CLONE.NEWNS | linux.CLONE.NEWPID",
        "fn setupPrivateLoopback() linux.E",
        "\"private-network-loopback-v1\\x00\"",
        "fn sealInheritedDescriptors() linux.E",
        "linux.PR.SET_PDEATHSIG",
        "linux.PR.CAPBSET_DROP",
        "linux.PR.SET_NO_NEW_PRIVS",
        "linux.syscall2(\n        .capget,",
        "linux.syscall2(\n        .capset,",
        "@offsetOf(KernelCapabilityHeader, \"pid\")",
        "linux.MS.REMOUNT | proc_mount_flags",
        "linux.syscall3(\n        .close_range,",
        "snapshotUdevIdentity(identity, invocation.argv[1..])",
        "snapshotSudoIdentity(identity, invocation.argv[1..])",
        "\"hidepid=2,subset=pid\"",
        "\"/proc/sys/kernel/random/boot_id\"",
        "\"etc/tmpfiles.d/static-nodes-permissions.conf\"",
        "\"etc/tmpfiles.d/sudo.conf\"",
        "\"etc/sysusers.d/debian-udev.conf\"",
        "\"usr/sbin/systemd-tmpfiles\"",
        "\"usr/sbin/update-alternatives\"",
        "\"usr/bin/gnuchmod\"",
        "\"usr/share/dpkg/sh/dpkg-error.sh\"",
        "\"d4d4fd7712da692dbb21a10795f7e62046c90b506338768b5a93cf9f1897f528\"",
        "return restrictScriptPrivileges(failure_stage, true);",
        "const restricted = restrictScriptPrivileges(null, false);",
        "childFail(streams.status, .capability_policy, restricted);",
        "maskScriptCapabilities(&data);",
        "scriptCapabilityAllowed(capability)",
        "linux.PR.CAP_AMBIENT",
        "linux.SECCOMP.SET_MODE_FILTER",
        "linux.SECCOMP.RET.KILL_PROCESS",
        "linux.CLONE.NEWNET",
        "if (count == 64) return .RANGE;",
        "if (required) return error.SignedProcRootRequired;",
        "return error.SkipZigTest;",
    }) |required| {
        if (std.mem.indexOf(u8, runner, required) == null) {
            try ctx.failFmt("reviewed exact-script proc isolation changed: {s}", .{required});
        }
    }

    const build = try ctx.readText("build.zig");
    for ([_][]const u8{
        "\"test-native-signed-proc\"",
        "\"DEBZ_REQUIRE_SIGNED_PROC_ROOTS=1\"",
        "\"signed-systemd-proc-root\"",
        "\"signed-udev-proc-root\"",
        "\"signed-sudo-proc-root\"",
        "signed_proc_run.addArtifactArg(signed_proc_tests);",
    }) |required| {
        if (std.mem.indexOf(u8, build, required) == null) {
            try ctx.failFmt("required signed proc fixture gate changed: {s}", .{required});
        }
    }

    const alternatives = try ctx.readText("src/native_alternatives.zig");
    const unpack = try ctx.readText("src/native_unpack.zig");
    for ([_][]const u8{
        "matchesStructuralLink(fact, authority.structural_links)",
        "parsed_records.append(allocator, parsed) catch |err|",
        ".structural_links = if (snapshot_sudo_postinst and",
        "verifySnapshotSudoStructuralOwner(allocator, root, program)",
        "verifySnapshotSudoPostinstPaths(",
        ".snapshot_sudo_proc = true",
    }) |required| {
        if (std.mem.indexOf(u8, alternatives, required) == null and std.mem.indexOf(u8, unpack, required) == null) {
            try ctx.failFmt("reviewed signed sudo alternatives admission changed: {s}", .{required});
        }
    }
    for ([_][]const u8{
        "if (matchesSnapshotPython3Preinst(bytes)) {",
        ".paths = &.{\"dev/null\"}",
        "\"/usr/share/doc/python3/html\"",
    }) |required| {
        if (std.mem.indexOf(u8, alternatives, required) == null) {
            try ctx.failFmt("reviewed signed python3 inert script grammar changed: {s}", .{required});
        }
    }
    for ([_][]const u8{
        "snapshotPython3PreinstIsBound(",
        "snapshotPython3PreinstIsInert(",
        "verifySnapshotPython3PreinstPaths(",
        "verifySnapshotPython3PreinstInputs(allocator, root, program)",
        "verifySnapshotPython3NullOutput(allocator, root)",
        "observed.entry.mode != 0o600 and observed.entry.mode != 0o644",
        "verifySnapshotPython3NullInput(allocator, root, program)",
        "if (!std.mem.eql(u8, architecture, \"amd64\"))",
        "try verifySnapshotPython3PreinstArtifacts(program.artifacts, \"amd64\");",
        "for (snapshot_python3_minimal_null_sources) |binding| try verifySignedDebconfControlFile(",
        "const snapshot_python3_minimal_null_input = SignedDebconfControlFile{\n" ++
            "    .path = \"dev/null\",\n    .size = 20,\n    .mode = 0o644,\n" ++
            "    .sha256 = \"e212fd644ebc9508a5494c1d69e26c62e23b5695d797588603dd870af154751e\",",
        "const snapshot_python3_minimal_postinst = SignedDebconfControlFile{\n" ++
            "    .path = \"var/lib/dpkg/info/python3-minimal.postinst\",\n" ++
            "    .size = 117,\n    .mode = 0o755,\n" ++
            "    .sha256 = \"be10656c9edf975f5dfe48fe5819172e905e14dcd4ff372af5d8b45b26168edd\",",
        "        .path = \"usr/bin/py3compile\",\n        .size = 13312,\n" ++
            "        .mode = 0o755,\n" ++
            "        .sha256 = \"a94b6fd8fb7f801f564da4dbb3e2d646b54713b58349d725c650885a5a0c6ccc\",",
        "        .size = 0,\n        .mode = @intCast(entry.mode),\n" ++
            "        .sha256 = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",",
        "root,\n        96,\n        \"3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc\"",
        "\"usr/sbin/rm\"",
    }) |required| {
        if (std.mem.indexOf(u8, unpack, required) == null) {
            try ctx.failFmt("reviewed signed python3 root and output proof changed: {s}", .{required});
        }
    }
    for ([_][]const u8{
        "fn appendAutomaticFileTriggerEvent(",
        "std.mem.eql(u8, interest.package.name, source.name)",
        "interest.package.architecture.len == 0 and",
        "std.mem.eql(u8, source.architecture, native_architecture)",
        "try eligible.append(allocator, interest);",
        "const FileTriggerPathEvents = struct",
        "while (cursor) |component| : (cursor = std.fs.path.dirname(component)) {",
        "if (self.work > (Limits{}).max_work) return error.TriggerWorkLimit;",
        "const trigger = self.paths.get(component) orelse continue;",
        "if ((try self.noted.getOrPut(self.allocator, trigger)).found_existing) continue;",
        "try appendAutomaticFileTriggerEvent(sink.allocator, sink.events, sink.source, architecture, trigger, self.interests);",
        "for (model.files) |file| {\n        try file_events.activate(.{",
        "}, architecture, diversions.physical(file.path, model.facts.package));",
        "try file_events.activate(sink, model.native_architecture, names.get(physical) orelse physical);",
        "persistRuntimeTriggerEvents(&resumed, testing.allocator, root, &.{forged})",
    }) |required| {
        if (std.mem.indexOf(u8, unpack, required) == null) {
            try ctx.failFmt("reviewed automatic file-trigger self-interest boundary changed: {s}", .{required});
        }
    }
    for ([_][]const u8{
        "const arm64 = std.mem.eql(u8, architecture, \"arm64\") and\n" ++
            "        std.mem.eql(u8, package.architecture, \"arm64\");",
        "if ((!amd64 and !arm64) or",
        "const SnapshotAlternativesArm64Artifact = struct {",
        "const snapshot_less_arm64_artifacts = [_]SnapshotAlternativesArm64Artifact{",
        "const snapshot_less_arm64_controls = [_]SignedDebconfControlFile{",
        "const snapshot_less_arm64_postinst_controls = [_]SignedDebconfControlFile{",
        "if ((less_inert or snapshot_postinst) and std.mem.eql(u8, architecture, \"arm64\")) {",
        "if (action_kind != .script or !std.mem.eql(u8, program.target_architecture, \"arm64\"))",
        "try verifySnapshotLessArm64Inputs(allocator, root, program.artifacts, program.target_architecture, kind);",
        "try bindSnapshotLessArm64ImmutableInputs(&script, kind);",
        "stat.uid != 0 or stat.gid != 0 or stat.mode != 0o40700)",
        "\"etc/ld.so.preload\",",
        "const snapshot_less_arm64_absent = snapshot_loader_arm64_absent ++ [_][]const u8{\"etc/ld.so.cache\"};",
        "var contents = try proc.observeAlloc(allocator, 0, 0);",
        "entry.mode != 0o777 or entry.uid != 0 or entry.gid != 0 or",
        "try attempt.requireRecovery(allocator, .script);",
    }) |required| {
        if (std.mem.indexOf(u8, unpack, required) == null) {
            try ctx.failFmt("reviewed exact arm64 less callback boundary changed: {s}", .{required});
        }
    }
    for ([_][]const u8{
        "if (snapshot_bash_postinst and std.mem.eql(u8, architecture, \"arm64\")) {",
        "bash_cache_fact = try verifySnapshotBashArm64Inputs(allocator, root, program.artifacts, program.target_architecture);",
        "native_alternatives.matchesSnapshotBashPostinst(script_bytes))\n" ++
            "            _ = verifySnapshotBashArm64Inputs(",
        "const snapshot_bash_arm64_artifacts = [_]SnapshotAlternativesArm64Artifact{",
        "const snapshot_bash_arm64_controls = [_]SignedDebconfControlFile{",
        ".path = \"var/lib/dpkg/info/libtinfo6:arm64.list\"",
        "\"usr/bin/update-menus\",\n    \"usr/sbin/update-menus\",",
    }) |required| {
        if (std.mem.indexOf(u8, unpack, required) == null) {
            try ctx.failFmt("reviewed exact arm64 bash callback boundary changed: {s}", .{required});
        }
    }
    for ([_][]const u8{
        "if (snapshot_util_linux_postinst and std.mem.eql(u8, architecture, \"arm64\")) {",
        "bash_cache_fact = try verifySnapshotUtilLinuxArm64Inputs(allocator, root, program.artifacts, program.target_architecture);",
        "native_alternatives.matchesSnapshotUtilLinuxPostinst(script_bytes))\n" ++
            "            _ = verifySnapshotUtilLinuxArm64Inputs(",
        "const snapshot_util_linux_arm64_artifacts = [_]SnapshotAlternativesArm64Artifact{",
        "const snapshot_util_linux_arm64_controls = [_]SignedDebconfControlFile{",
        "const snapshot_util_linux_arm64_perl: SignedDebconfControlFile = .{",
        "const snapshot_util_linux_arm64_fstrim_created_paths = [_][]const u8{",
        "verifySnapshotUtilLinuxArm64PostOutput(\n                        allocator,\n                        root,\n                        alternatives_after.?,",
    }) |required| {
        if (std.mem.indexOf(u8, unpack, required) == null) {
            try ctx.failFmt("reviewed exact arm64 util-linux callback boundary changed: {s}", .{required});
        }
    }

    const less_reference = try ctx.readText("tools/real-snapshot-less-reference.sh");
    for ([_][]const u8{
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_SOURCE_ROOT=\"$source_root\"",
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_PREINST_ROOT=\"$source_root\"",
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_SCRIPT_AFTER=\"$script_root\"",
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_DPKG_AFTER=\"$dpkg_root\"",
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_SCRIPT_ROOT=\"$bad_script\"",
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_MODE_ROOT=\"$bad_mode\"",
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_TOOL_ROOT=\"$bad_tool\"",
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_ALIAS_ROOT=\"$bad_alias\"",
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_PRESTATE_ROOT=\"$bad_prestate\"",
        "\"$zig\" build test-native-unpack -Doptimize=ReleaseSafe -j2 --summary all",
        "unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private --",
        "/bin/sh /var/lib/debz-lifecycle-scripts/less.preinst install",
    }) |required| {
        if (std.mem.indexOf(u8, less_reference, required) == null) {
            try ctx.failFmt("protected arm64 less activated proof wiring changed: {s}", .{required});
        }
    }
    const chk_idx = std.mem.indexOf(u8, less_reference, "\ncheck_source_inputs\n");
    const cp_idx = std.mem.indexOf(u8, less_reference, "cp -a --reflink=auto");
    if (chk_idx == null or cp_idx == null or chk_idx.? > cp_idx.?) {
        try ctx.fail("protected arm64 less source guard must run before fixture copies/mutations");
    }

    const less_fixtures = try ctx.readText("tools/real-snapshot-stage.zig");
    for ([_][]const u8{
        "const parent_fd = try reference_paths.openBeneath(root_fd, parent, true);",
        ".ACCMODE = .RDWR,\n        .NOFOLLOW = true,\n        .NONBLOCK = true,\n        .CLOEXEC = true,",
        "const metadata = try rawFstat(descriptor);",
        "(metadata.mode & linux.S.IFMT) != linux.S.IFREG or\n        metadata.nlink != 1",
        "_ = try regularMetadata(descriptor);\n    _ = try syscall(linux.ftruncate(descriptor, 0));",
        ".ACCMODE = .WRONLY,\n        .CREAT = true,\n        .EXCL = true,\n        .NOFOLLOW = true,\n        .CLOEXEC = true,",
        "try reference_paths.protected(root, true)",
    }) |required| {
        if (std.mem.indexOf(u8, less_fixtures, required) == null) {
            try ctx.failFmt("protected arm64 less no-follow fixture mutation boundary changed: {s}", .{required});
        }
    }
    if (std.mem.indexOf(u8, less_fixtures, ".TRUNC = true") != null) {
        try ctx.fail("protected arm64 less fixture must check opened metadata before truncation");
    }

    const live_root = try ctx.readText("src/live_root.zig");
    if (std.mem.indexOf(u8, live_root, "linux.syscall3(\n        .open_tree,") == null) {
        try ctx.fail("live-root detached open_tree boundary changed");
    }
    if (std.mem.indexOf(u8, live_root, "linux.syscall5(\n        .mount_setattr,") == null) {
        try ctx.fail("live-root detached propagation boundary changed");
    }
}

pub fn liblzmaDecoderConfigurationFailures(allocator: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const split_idx = std.mem.indexOf(u8, text, "\npub fn addStaticEncoderLibrary(") orelse text.len;
    const production = text[0..split_idx];
    if (std.mem.indexOf(u8, production, "stream_decoder_mt.c") != null or
        std.mem.indexOf(u8, production, "encoder.c") != null or
        std.mem.indexOf(u8, production, "\"HAVE_ENCODERS\"") != null or
        std.mem.indexOf(u8, production, "\"HAVE_DECODERS\"") == null or
        std.mem.indexOf(u8, production, "\"HAVE_CHECK_SHA256\"") == null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "repository-local liblzma build is not the reviewed single-threaded decoder configuration"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn auditDependencies(ctx: *AuditContext) !void {
    const policy_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText("security/dependency-policy.json"), .{});
    const runtime_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText("security/runtime-dependencies.json"), .{});
    const policy = policy_parsed.value.object;

    const epoch_secs: u64 = @intCast(@max(0, @divFloor(std.Io.Clock.real.now(ctx.io).nanoseconds, std.time.ns_per_s)));
    const epoch_day = (std.time.epoch.EpochSeconds{ .secs = epoch_secs }).getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const today = try std.fmt.allocPrint(ctx.allocator, "{d:0>4}-{d:0>2}-{d:0>2}", .{ year_day.year, month_day.month.numeric(), month_day.day_index + 1 });

    const reviewed_on = jsonStr(policy, "reviewed_on") orelse "";
    const review_expires = jsonStr(policy, "review_expires") orelse "";
    if (std.mem.order(u8, reviewed_on, today) == .gt) {
        try ctx.fail("dependency review date is in the future");
    }
    if (std.mem.order(u8, today, review_expires) == .gt) {
        try ctx.fail("dependency vulnerability/license review has expired");
    }

    var allowed_licenses: std.ArrayList([]const u8) = .empty;
    for (jsonArr(policy, "allowed_production_licenses") orelse &.{}) |lic| {
        if (lic == .string) try allowed_licenses.append(ctx.allocator, lic.string);
    }

    var dependencies: std.StringArrayHashMapUnmanaged(std.json.ObjectMap) = .empty;
    for (jsonArr(policy, "production_dependencies") orelse &.{}) |item| {
        if (item == .object) {
            if (jsonStr(item.object, "name")) |n| {
                try dependencies.put(ctx.allocator, n, item.object);
            }
        }
    }
    if (dependencies.count() != 4 or
        !dependencies.contains("libsolv") or
        !dependencies.contains("liblzma") or
        !dependencies.contains("libzstd") or
        !dependencies.contains("musl"))
    {
        try ctx.fail("dependency policy does not exactly enumerate production dependencies");
    }

    for (dependencies.keys(), dependencies.values()) |dep_name, dep| {
        const lic = jsonStr(dep, "license") orelse "";
        if (!sliceContainsStr(allowed_licenses.items, lic)) {
            try ctx.failFmt("{s}: license is outside the production allowlist", .{dep_name});
        }
        const rt_link = jsonStr(dep, "runtime_linkage") orelse "";
        if (rt_link.len == 0) {
            try ctx.failFmt("{s}: runtime linkage is missing", .{dep_name});
        }
        const vuln_sources = jsonArr(dep, "vulnerability_sources") orelse &.{};
        var sources_ok = vuln_sources.len > 0;
        for (vuln_sources) |vs| {
            if (vs != .string or !std.mem.startsWith(u8, vs.string, "https://")) sources_ok = false;
        }
        if (!sources_ok) {
            try ctx.failFmt("{s}: vulnerability review sources are missing", .{dep_name});
        }
        const review = jsonObj(dep, "vulnerability_review");
        const rev_on = if (review) |r| jsonStr(r, "reviewed_on") orelse "" else "";
        if (!std.mem.eql(u8, rev_on, reviewed_on)) {
            try ctx.failFmt("{s}: vulnerability review evidence is stale", .{dep_name});
        }
        const rev_res = if (review) |r| jsonStr(r, "result") orelse "" else "";
        if (!std.mem.eql(u8, rev_res, "no_known_unresolved_advisories") and !std.mem.eql(u8, rev_res, "reviewed_exceptions")) {
            try ctx.failFmt("{s}: vulnerability review result is missing", .{dep_name});
        }
        if (std.mem.eql(u8, rev_res, "reviewed_exceptions")) {
            const excs = jsonArr(dep, "reviewed_exceptions") orelse &.{};
            if (excs.len == 0) {
                try ctx.failFmt("{s}: vulnerability exceptions are not enumerated", .{dep_name});
            }
        }
    }

    if (dependencies.get("musl")) |musl| {
        if (!std.mem.eql(u8, jsonStr(musl, "source") orelse "", "https://codeberg.org/ziglang/zig/src/tag/0.17.0/lib/libc/musl") or
            !std.mem.eql(u8, jsonStr(musl, "upstream_version") orelse "", "1.2.5") or
            !std.mem.eql(u8, jsonStr(musl, "zig_musl_baseline_commit") orelse "", "0098e650fbceae74c8c468716c0810476f72ec47") or
            !std.mem.eql(u8, jsonStr(musl, "toolchain_version") orelse "", "0.17.0") or
            !std.mem.eql(u8, jsonStr(musl, "toolchain_commit") orelse "", "7647adab80dd088f4de3610fd245915a912eb6ad") or
            !std.mem.eql(u8, jsonStr(musl, "toolchain_source_archive") orelse "", "https://ziglang.org/download/0.17.0/zig-0.17.0.tar.xz") or
            !std.mem.eql(u8, jsonStr(musl, "toolchain_source_sha256") orelse "", "b6c7f1728f043700d6529bac980800792f824256a9d2f1839b3d62beed0b8abd") or
            !std.mem.eql(u8, jsonStr(musl, "version") orelse "", "1.2.5+zig.0.17.0.7647adab80dd") or
            !std.mem.eql(u8, jsonStr(musl, "license") orelse "", "MIT") or
            !std.mem.eql(u8, jsonStr(musl, "runtime_linkage") orelse "", "static_libc_in_debz"))
        {
            try ctx.fail("musl provenance differs from the reviewed Zig 0.17.0 toolchain snapshot");
        }
        const excs = jsonArr(musl, "reviewed_exceptions") orelse &.{};
        var exc_map: std.StringHashMapUnmanaged([]const u8) = .empty;
        var any_missing_rat = false;
        for (excs) |item| {
            if (item != .object) {
                any_missing_rat = true;
                continue;
            }
            const id = jsonStr(item.object, "id") orelse "";
            const disp = jsonStr(item.object, "disposition") orelse "";
            const rat = jsonStr(item.object, "rationale") orelse "";
            if (rat.len == 0) any_missing_rat = true;
            if (id.len > 0) try exc_map.put(ctx.allocator, id, disp);
        }
        if (exc_map.count() != 3 or
            !std.mem.eql(u8, exc_map.get("CVE-2025-26519") orelse "", "patched_in_toolchain") or
            !std.mem.eql(u8, exc_map.get("CVE-2026-40200") orelse "", "not_affected") or
            !std.mem.eql(u8, exc_map.get("CVE-2026-6042") orelse "", "not_linked"))
        {
            try ctx.fail("musl vulnerability review exceptions are incomplete");
        }
        if (any_missing_rat) {
            try ctx.fail("musl vulnerability review exceptions lack rationale");
        }
    }

    const zon = try ctx.readText("build.zig.zon");
    const ZonDep = struct { url: []const u8, hash: []const u8 };
    var found_zon: std.StringHashMapUnmanaged(ZonDep) = .empty;
    {
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, zon, pos, ".url")) |u_idx| {
            pos = u_idx + 4;
            // Find preceding `.name = .{`
            const before = zon[0..u_idx];
            const brace = std.mem.lastIndexOf(u8, before, ".{") orelse continue;
            if (std.mem.trim(u8, before[brace + 2 ..], " \t\r\n").len != 0) continue;
            const eq = std.mem.lastIndexOfScalar(u8, before[0..brace], '=') orelse continue;
            if (std.mem.trim(u8, before[eq + 1 .. brace], " \t\r\n").len != 0) continue;
            const dot = std.mem.lastIndexOfScalar(u8, before[0..eq], '.') orelse continue;
            const dep_name = std.mem.trim(u8, before[dot + 1 .. eq], " \t\r\n");
            const u_q1 = std.mem.indexOfScalarPos(u8, zon, u_idx + 4, '"') orelse continue;
            const u_q2 = std.mem.indexOfScalarPos(u8, zon, u_q1 + 1, '"') orelse continue;
            const url = zon[u_q1 + 1 .. u_q2];
            const h_idx = std.mem.indexOfPos(u8, zon, u_q2 + 1, ".hash") orelse continue;
            const h_q1 = std.mem.indexOfScalarPos(u8, zon, h_idx + 5, '"') orelse continue;
            const h_q2 = std.mem.indexOfScalarPos(u8, zon, h_q1 + 1, '"') orelse continue;
            const hash = zon[h_q1 + 1 .. h_q2];
            try found_zon.put(ctx.allocator, dep_name, .{ .url = url, .hash = hash });
            pos = h_q2 + 1;
        }
    }
    const ExpectedPin = struct {
        manifest_name: []const u8,
        url: []const u8,
        digest: []const u8,
        policy_name: []const u8,
        commit: []const u8,
    };
    const expected_pins = [_]ExpectedPin{
        .{
            .manifest_name = "libsolv",
            .url = "git+https://github.com/cataggar/libsolv.git#e190ef1433e5df60a2238b01438927eb76c285f5",
            .digest = "libsolv-0.7.39-PoNzeg2EIACYnSAYc3_WneVukScmmV-vyo_5guzBzqdO",
            .policy_name = "libsolv",
            .commit = "e190ef1433e5df60a2238b01438927eb76c285f5",
        },
        .{
            .manifest_name = "xz",
            .url = "https://github.com/tukaani-project/xz/archive/4b73f2ec19a99ef465282fbce633e8deb33691b3.tar.gz",
            .digest = "N-V-__8AAPy-ZQDvb3F10PKDTFyFXk7kwDjstLisczD0n9Fs",
            .policy_name = "liblzma",
            .commit = "4b73f2ec19a99ef465282fbce633e8deb33691b3",
        },
        .{
            .manifest_name = "zstd",
            .url = "https://github.com/cataggar/zstd/archive/71502da18ccdacac0c2049c033dedbbf25a40b93.tar.gz",
            .digest = "zstd-1.6.0-Nyx42nbYOwBGNLCV3_VPmuHUh7voiJK2Dqm6OBEBfiod",
            .policy_name = "libzstd",
            .commit = "71502da18ccdacac0c2049c033dedbbf25a40b93",
        },
    };
    var zon_ok = found_zon.count() == expected_pins.len;
    for (expected_pins) |ep| {
        if (found_zon.get(ep.manifest_name)) |z| {
            if (!std.mem.eql(u8, z.url, ep.url) or !std.mem.eql(u8, z.hash, ep.digest)) zon_ok = false;
        } else {
            zon_ok = false;
        }
        if (dependencies.get(ep.policy_name)) |dep| {
            if (!std.mem.eql(u8, jsonStr(dep, "commit") orelse "", ep.commit) or
                !std.mem.eql(u8, jsonStr(dep, "zig_hash") orelse "", ep.digest) or
                std.mem.indexOf(u8, ep.url, ep.commit) == null)
            {
                try ctx.failFmt("{s}: manifest pin differs from dependency policy", .{ep.policy_name});
            }
        }
    }
    if (!zon_ok) {
        try ctx.fail("build.zig.zon dependencies differ from reviewed exact pins");
    }

    const build = try ctx.readText("build.zig");
    const zon_ver = blk: {
        const idx = std.mem.indexOf(u8, zon, ".version") orelse break :blk null;
        const q1 = std.mem.indexOfScalarPos(u8, zon, idx + 8, '"') orelse break :blk null;
        const q2 = std.mem.indexOfScalarPos(u8, zon, q1 + 1, '"') orelse break :blk null;
        break :blk zon[q1 + 1 .. q2];
    };
    const build_ver = blk: {
        const idx = std.mem.indexOf(u8, build, "const package_version") orelse break :blk null;
        const q1 = std.mem.indexOfScalarPos(u8, build, idx + 21, '"') orelse break :blk null;
        const q2 = std.mem.indexOfScalarPos(u8, build, q1 + 1, '"') orelse break :blk null;
        break :blk build[q1 + 1 .. q2];
    };
    if (zon_ver == null or build_ver == null or !std.mem.eql(u8, zon_ver.?, build_ver.?)) {
        try ctx.fail("default build version differs from build.zig.zon");
    }
    if (std.mem.indexOf(u8, build, "linkSystemLibrary(\"") != null) {
        try ctx.fail("unreviewed system libraries");
    }
    for (try runtimeMetadataFailures(ctx.allocator, runtime_parsed.value, dependencies)) |msg| try ctx.fail(msg);
    for (try releaseInstallMetadataFailures(ctx.allocator, build)) |msg| try ctx.fail(msg);
    if (std.mem.indexOf(u8, build, "const target = b.standardTargetOptions(.{});") == null) {
        try ctx.fail("ordinary builds must preserve standard target option propagation");
    }
    for (try dependencyOptionFailures(ctx.allocator, build, "libsolv", &.{.{ .name = "shared", .value = "false" }})) |msg| try ctx.fail(msg);
    for (try dependencyOptionFailures(ctx.allocator, build, "zstd", &.{
        .{ .name = "target", .value = "target" },
        .{ .name = "optimize", .value = "optimize" },
        .{ .name = "shared", .value = "false" },
        .{ .name = "tools", .value = "false" },
        .{ .name = "multithread", .value = "false" },
    })) |msg| try ctx.fail(msg);
    if (std.mem.indexOf(u8, build, "debz.link_libc = true") == null or
        std.mem.indexOf(u8, build, "b.dependency(\"xz\"") == null or
        std.mem.indexOf(u8, build, "liblzma_build.addStaticLibrary") == null or
        std.mem.indexOf(u8, build, "debz.linkLibrary(liblzma)") == null or
        std.mem.indexOf(u8, build, "debz.linkLibrary(zstd)") == null)
    {
        try ctx.fail("build linkage differs from documented runtime dependency model");
    }
    for (try liblzmaDecoderConfigurationFailures(ctx.allocator, try ctx.readText("build/liblzma.zig"))) |msg| try ctx.fail(msg);

    const notices = try ctx.readText("THIRD_PARTY_NOTICES");
    for ([_][]const u8{
        "libsolv",
        "BSD-3-Clause",
        "XZ Utils liblzma",
        "Zstandard libzstd",
        "0BSD",
        "musl libc",
        "1.2.5+zig.0.17.0.7647adab80dd",
        "b6c7f1728f043700d6529bac980800792f824256a9d2f1839b3d62beed0b8abd",
        "MIT",
    }) |req| {
        if (std.mem.indexOf(u8, notices, req) == null) {
            try ctx.failFmt("THIRD_PARTY_NOTICES is missing '{s}'", .{req});
        }
    }
    const split_notices = std.mem.indexOf(u8, notices, "OpenPGP fixture") orelse notices.len;
    const prod_notices = notices[0..split_notices];
    for ([_][]const u8{ "GPL", "LGPL", "AGPL" }) |gpl| {
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, prod_notices, pos, gpl)) |idx| {
            pos = idx + gpl.len;
            if (isWordBoundary(prod_notices, idx) and
                ((idx + gpl.len < prod_notices.len and prod_notices[idx + gpl.len] == '-') or isWordBoundary(prod_notices, idx + gpl.len)))
            {
                try ctx.fail("GPL/LGPL/AGPL production dependency is not permitted");
                break;
            }
        }
    }
}

pub fn extractYamlTopJob(text: []const u8, job_header: []const u8) ?[]const u8 {
    var start_pos: ?usize = null;
    if (std.mem.startsWith(u8, text, job_header)) {
        start_pos = job_header.len;
    } else {
        var search_from: usize = 0;
        while (std.mem.indexOfPos(u8, text, search_from, job_header)) |idx| {
            if (idx > 0 and text[idx - 1] == '\n') {
                start_pos = idx + job_header.len;
                break;
            }
            search_from = idx + 1;
        }
    }
    const body_start = start_pos orelse return null;
    var pos = body_start;
    while (pos < text.len) {
        const nl = std.mem.indexOfScalarPos(u8, text, pos, '\n') orelse return text[body_start..];
        const next_line_start = nl + 1;
        if (next_line_start + 3 <= text.len and
            text[next_line_start] == ' ' and
            text[next_line_start + 1] == ' ' and
            !isSpace(text[next_line_start + 2]))
        {
            return text[body_start..next_line_start];
        }
        pos = next_line_start;
    }
    return text[body_start..];
}

pub fn auditReleaseTargets(ctx: *AuditContext) !void {
    const release = try ctx.readText(".github/workflows/release.yml");
    const ci = try ctx.readText(".github/workflows/ci.yml");
    const JobSpec = struct { label: []const u8, body: ?[]const u8 };
    const jobs = [_]JobSpec{
        .{ .label = "release.yml binaries", .body = extractYamlTopJob(release, "  binaries:\n") },
        .{ .label = "ci.yml release-dry-run", .body = extractYamlTopJob(ci, "  release-dry-run:\n") },
    };
    for (jobs) |job| {
        const body = job.body orelse {
            try ctx.failFmt("{s}: release job is missing", .{job.label});
            continue;
        };
        for ([_][]const u8{ "x86_64-linux-musl", "aarch64-linux-musl" }) |target| {
            const needle = try std.fmt.allocPrint(ctx.allocator, "target: {s}", .{target});
            if (countSubstring(body, needle) != 1) {
                try ctx.failFmt("{s}: release matrix must contain exactly one {s} target", .{ job.label, target });
            }
        }
        for ([_][]const u8{ "x86_64-linux-gnu", "aarch64-linux-gnu" }) |target| {
            const needle = try std.fmt.allocPrint(ctx.allocator, "target: {s}", .{target});
            if (std.mem.indexOf(u8, body, needle) != null) {
                try ctx.failFmt("{s}: release matrix retains dynamic GNU target {s}", .{ job.label, target });
            }
        }
    }
}

pub fn workflowFailureHandlingFailures(allocator: std.mem.Allocator, text: []const u8, label: []const u8) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    var allowed_continue: usize = 0;

    var lines: std.ArrayList([]const u8) = .empty;
    var line_it = std.mem.splitScalar(u8, text, '\n');
    while (line_it.next()) |l| try lines.append(allocator, l);

    var idx: usize = 0;
    while (idx < lines.items.len) {
        const line = lines.items[idx];
        const trimmed_left = std.mem.trimStart(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed_left, "- ") and std.mem.indexOf(u8, trimmed_left, "name:") != null) {
            const after_dash = std.mem.trimStart(u8, trimmed_left[1..], " \t");
            if (std.mem.startsWith(u8, after_dash, "name:")) {
                const name = std.mem.trim(u8, after_dash["name:".len..], " \t\r");
                var body_end = idx + 1;
                while (body_end < lines.items.len) : (body_end += 1) {
                    const bl = lines.items[body_end];
                    if (bl.len < 8) break;
                    var eight_spaces = true;
                    for (bl[0..8]) |c| {
                        if (c != ' ') eight_spaces = false;
                    }
                    if (!eight_spaces) break;
                }
                var has_continue = false;
                var body_buf: std.ArrayList(u8) = .empty;
                for (lines.items[idx + 1 .. body_end]) |bl| {
                    try body_buf.appendSlice(allocator, bl);
                    try body_buf.append(allocator, '\n');
                    const bl_trim = std.mem.trim(u8, bl, " \t\r");
                    if (std.mem.eql(u8, bl_trim, "continue-on-error: true")) {
                        has_continue = true;
                    }
                }
                if (has_continue) {
                    const is_corrupt = std.mem.eql(u8, name, "Reject corrupt package object");
                    const is_offline = std.mem.eql(u8, name, "Reject package-only offline restore");
                    const is_native_neg = std.mem.eql(u8, name, "Refuse legacy lock in native action");
                    const is_legacy_neg = std.mem.eql(u8, name, "Refuse native lock in default legacy action");
                    if (!is_corrupt and !is_offline and !is_native_neg and !is_legacy_neg) {
                        try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: workflow hides a failing command", .{label}));
                    }
                    if (is_native_neg or is_legacy_neg) {
                        const step_id = if (is_native_neg) "native-foreign-lock" else "legacy-foreign-lock";
                        const prefix = if (is_native_neg) "NATIVE" else "LEGACY";
                        const id_tok = try std.fmt.allocPrint(allocator, "id: {s}", .{step_id});
                        const req1 = "Validate explicit backend refusal";
                        const req2 = try std.fmt.allocPrint(allocator, "{s}_OUTCOME: ${{{{ steps.{s}.outcome }}}}", .{ prefix, step_id });
                        const req3 = try std.fmt.allocPrint(allocator, "{s}_PATH: ${{{{ steps.{s}.outputs.cache-path }}}}", .{ prefix, step_id });
                        const req4 = try std.fmt.allocPrint(allocator, "test \"${s}_OUTCOME\" = failure", .{prefix});
                        const req5 = try std.fmt.allocPrint(allocator, "test -z \"${s}_PATH\"", .{prefix});
                        if (std.mem.indexOf(u8, body_buf.items, id_tok) == null or
                            std.mem.indexOf(u8, body_buf.items, "uses: ./actions/download") == null or
                            std.mem.indexOf(u8, text, req1) == null or
                            std.mem.indexOf(u8, text, req2) == null or
                            std.mem.indexOf(u8, text, req3) == null or
                            std.mem.indexOf(u8, text, req4) == null or
                            std.mem.indexOf(u8, text, req5) == null)
                        {
                            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: native backend refusal coverage lacks bound outcome assertions", .{label}));
                        }
                    }
                    allowed_continue += 1;
                }
                idx = body_end;
                continue;
            }
        }
        idx += 1;
    }

    if (countSubstring(text, "continue-on-error: true") != allowed_continue) {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: workflow has an unaudited continue-on-error", .{label}));
    }
    if (allowed_continue > 0 and
        (std.mem.indexOf(u8, text, "Validate corrupt-object failure") == null or
        std.mem.indexOf(u8, text, "Validate offline metadata failure") == null or
        std.mem.indexOf(u8, text, "test \"$OUTCOME\" = failure") == null))
    {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: expected-failure action coverage lacks outcome assertions", .{label}));
    }
    return failures.toOwnedSlice(allocator);
}

pub const DIVERSION_CASE_SHARDS = [_][2]usize{
    .{ 1, 25 },
    .{ 26, 50 },
    .{ 51, 75 },
    .{ 76, 100 },
};

pub const RecoveryZigShard = struct {
    name: []const u8,
    display_name: []const u8,
    step_name: []const u8,
    targets: []const []const u8,
};

pub const RECOVERY_ZIG_SHARDS = [_]RecoveryZigShard{
    .{
        .name = "native-recovery-zig-workflows",
        .display_name = "Native crash recovery Zig core (${{ matrix.name }})",
        .step_name = "Exercise Zig core recovery",
        .targets = &.{"test-native-recovery-zig"},
    },
    .{
        .name = "native-recovery-zig-repository",
        .display_name = "Native crash recovery Zig repository (${{ matrix.name }})",
        .step_name = "Exercise Zig repository recovery",
        .targets = &.{"test-native-recovery-zig-repository"},
    },
    .{
        .name = "native-recovery-zig-helper",
        .display_name = "Native crash recovery Zig helper, bootstrap, parity and rollback (${{ matrix.name }})",
        .step_name = "Exercise Zig helper, bootstrap, parity and rollback recovery",
        .targets = &.{
            "test-native-recovery-helper-zig",
            "test-native-recovery-zig-bootstrap",
            "test-native-recovery-zig-parity",
            "test-native-recovery-zig-rollback-clock",
        },
    },
    .{
        .name = "native-recovery-zig-family",
        .display_name = "Native crash recovery Zig signed FAMILY (${{ matrix.name }})",
        .step_name = "Exercise Zig signed FAMILY recovery",
        .targets = &.{"test-native-recovery-zig-family"},
    },
    .{
        .name = "native-recovery-zig-scenarios",
        .display_name = "Native crash recovery Zig scenario matrices (${{ matrix.name }})",
        .step_name = "Exercise Zig recovery scenario and mutation matrices",
        .targets = &.{
            "test-native-recovery-zig-scriptless",
            "test-native-recovery-zig-statoverride",
            "test-native-recovery-zig-literal",
            "test-native-recovery-zig-metadata",
            "test-native-recovery-zig-publication",
            "test-native-recovery-zig-conffile",
            "test-native-recovery-zig-final-gaps",
            "test-native-recovery-zig-mutation-boundaries",
        },
    },
    .{
        .name = "native-recovery-zig-diversions",
        .display_name = "Native crash recovery Zig diversion shard (${{ matrix.name }} / ${{ matrix.shard }})",
        .step_name = "Exercise counted Zig diversion recovery shard",
        .targets = &.{"test-native-recovery-zig-diversions"},
    },
};

pub const ROOT_IMPORT_STEP = "Compare pinned-dpkg root import and copied-root refusals";
pub const ROOT_IMPORT_COMMANDS = [_][]const u8{
    "mkdir -p .tmp",
    "zig build build-native-dpkg-reference -j2",
    "reference_dpkg=\"$(zig-out/bin/debz-native-dpkg-reference)\"",
    "zig build test-native-root-import -Dnative-reference-dpkg=\"$reference_dpkg\" -j2 --summary all",
    "zig build test-native-root-import -Dnative-reference-dpkg=\"$reference_dpkg\" -Doptimize=ReleaseSafe -j2 --summary all",
};

pub const WORKLOAD_TIMEOUT_MINUTES: usize = 45;

pub const WorkloadPartition = struct {
    variable: []const u8,
    step_name: []const u8,
    members: []const []const u8,
};

pub const WORKLOAD_PARTITIONS = [_]WorkloadPartition{
    .{
        .variable = "workload_core",
        .step_name = "test-workload-core",
        .members = &.{
            "run_tests",
            "native_action_empty_lock_tests",
            "baseline_fixture_tests",
            "disposable_runtime_tests",
            "integration_archive_tests",
            "integration_signing_tests",
            "integration_repository_tests",
            "openpgp_fixture_tests",
            "run_repository_cli_tests",
            "cli_tests",
            "no_args_help",
            "positional_help",
            "removed_version_flag",
            "consumer_tests",
            "run_real_snapshot_comparator_tests",
            "run_reference_runtime_tests",
            "run_reference_paths_tests",
            "run_reference_order_tests",
            "run_reference_protected_tests",
            "run_vendor_snapshot_tools_tests",
            "run_reference_stage_tests",
            "run_script_network_probe_tests",
            "run_http_fixture_tests",
            "run_debian_closure_inventory_tests",
            "debian_readiness_tests",
            "debian_closure_tests",
            "reference_triggers_tests",
            "run_apt_acceptance_unit_tests",
            "repository_add_tests",
        },
    },
    .{
        .variable = "workload_production",
        .step_name = "test-workload-production",
        .members = &.{
            "run_package_family_tests",
            "run_production_backend_tests",
            "run_required_production_security_tests",
            "run_production_customize_tests",
        },
    },
    .{
        .variable = "workload_apt_system",
        .step_name = "test-workload-apt-system",
        .members = &.{
            "run_system_profile_tests",
            "run_apt_system_api_tests",
            "run_apt_system_cli_tests",
            "run_apt_system_command_tests",
            "run_apt_system_state_tests",
            "run_apt_system_orchestrator_tests",
            "run_required_orchestrator_security_tests",
        },
    },
    .{
        .variable = "workload_native",
        .step_name = "test-workload-native",
        .members = &.{
            "native_dpkg_tests",
            "run_healthy_prestate_tests",
            "run_native_program_corpus_tests",
            "native_outcome_tests",
            "run_native_phase_summary_tests",
            "run_exec_audit_tests",
            "run_native_alternatives_tests",
            "run_native_alternatives_oracle_tests",
            "run_native_snapshot_tests",
            "run_native_differential_zig_tests",
            "run_native_fixture_tests",
            "run_native_conffile_zig_tests",
            "dpkg_config_reference_tests",
            "dpkg_alternatives_reference_tests",
            "dpkg_oracle_evidence_tests",
            "signed_proc_compare_tests",
            "run_sha512_e2e_tests",
            "run_native_trigger_queue_tests",
            "run_lifecycle_zig_tests",
            "run_trigger_zig_tests",
            "run_settlement_tests",
            "run_recovery_unit_tests",
            "run_native_recovery_tests",
            "phase_telemetry_step",
            "run_repository_recovery_unit",
            "run_package_cache_archive_tests",
        },
    },
    .{
        .variable = "workload_release",
        .step_name = "test-workload-release",
        .members = &.{
            "run_apt_schema_tests",
            "native_only_rehearsal",
            "run_snapshot_repin_tests",
            "release_tool_tests",
            "run_release_policy_tests",
            "run_release_workflow_policy_tests",
            "run_native_only_candidate_tests",
        },
    },
};

pub const WORKLOAD_HELP_BINDING = "addHelpFlagTests(b, workload_core, cli, case.args, case.usage);";

pub fn countWordOccurrences(text: []const u8, word: []const u8) usize {
    var count: usize = 0;
    var pos: usize = 0;
    while (fastIndexOfPos(text, pos, word)) |idx| {
        pos = idx + word.len;
        if (isWordBoundary(text, idx) and isWordBoundary(text, idx + word.len)) {
            count += 1;
        }
    }
    return count;
}

pub fn workloadPartitionFailures(allocator: std.mem.Allocator, build: []const u8) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    if (countSubstring(build, "const test_step = b.step(\"test\", ") != 1) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: aggregate test step must be declared exactly once"));
    }
    var aggregate: std.ArrayList([]const u8) = .empty;
    var line_it = std.mem.splitScalar(u8, build, '\n');
    while (line_it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t");
        if (std.mem.startsWith(u8, line, "test_step.dependOn(") and std.mem.endsWith(u8, line, ");")) {
            try aggregate.append(allocator, line["test_step.dependOn(".len .. line.len - 2]);
        }
    }
    var agg_ok = aggregate.items.len == WORKLOAD_PARTITIONS.len and
        countWordOccurrences(build, "test_step") == 1 + WORKLOAD_PARTITIONS.len;
    if (agg_ok) {
        for (aggregate.items, WORKLOAD_PARTITIONS) |act, wp| {
            if (!std.mem.eql(u8, act, wp.variable)) agg_ok = false;
        }
    }
    if (!agg_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: aggregate test step must depend only on every workload partition"));
    }

    var expected_pairs: std.ArrayList([]const u8) = .empty;
    for (WORKLOAD_PARTITIONS) |wp| {
        const decl = try std.fmt.allocPrint(allocator, "const {s} = b.step(\"{s}\", ", .{ wp.variable, wp.step_name });
        const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{wp.step_name});
        if (countSubstring(build, decl) != 1 or countSubstring(build, quoted) != 1) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: workload partition {s} must be declared exactly once", .{wp.step_name}));
        }
        const refs = countWordOccurrences(build, wp.variable);
        const exp_refs = 2 + wp.members.len + @as(usize, if (std.mem.eql(u8, wp.variable, "workload_core")) 1 else 0);
        if (refs != exp_refs) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: workload partition {s} has an unreviewed binding", .{wp.step_name}));
        }
        for (wp.members) |m| {
            try expected_pairs.append(allocator, try std.fmt.allocPrint(allocator, "{s}:{s}", .{ wp.variable, m }));
        }
    }

    var actual_pairs: std.ArrayList([]const u8) = .empty;
    var actual_members_set: std.StringHashMapUnmanaged(void) = .empty;
    var duplicate_member = false;
    var line_it2 = std.mem.splitScalar(u8, build, '\n');
    while (line_it2.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t");
        if (!std.mem.startsWith(u8, line, "workload_") or !std.mem.endsWith(u8, line, ");")) continue;
        const dot_dep = std.mem.indexOf(u8, line, ".dependOn(") orelse continue;
        const w_var = line[0..dot_dep];
        var valid_w = w_var.len > "workload_".len;
        for (w_var["workload_".len..]) |c| {
            if (!((c >= 'a' and c <= 'z') or c == '_')) valid_w = false;
        }
        if (!valid_w) continue;
        var arg = line[dot_dep + ".dependOn(".len .. line.len - 2];
        if (std.mem.startsWith(u8, arg, "&")) arg = arg[1..];
        if (std.mem.endsWith(u8, arg, ".step")) arg = arg[0 .. arg.len - 5];
        if (arg.len == 0 or !isAlphaUnder(arg[0])) continue;
        var valid_arg = true;
        for (arg) |c| {
            if (!isWordChar(c)) valid_arg = false;
        }
        if (!valid_arg) continue;
        try actual_pairs.append(allocator, try std.fmt.allocPrint(allocator, "{s}:{s}", .{ w_var, arg }));
        if ((try actual_members_set.getOrPut(allocator, arg)).found_existing) {
            duplicate_member = true;
        }
    }
    const strLess = struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan;
    std.mem.sort([]const u8, expected_pairs.items, {}, strLess);
    std.mem.sort([]const u8, actual_pairs.items, {}, strLess);
    var pairs_match = !duplicate_member and expected_pairs.items.len == actual_pairs.items.len;
    if (pairs_match) {
        for (expected_pairs.items, actual_pairs.items) |e, a| {
            if (!std.mem.eql(u8, e, a)) pairs_match = false;
        }
    }
    if (!pairs_match) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: every former test member must run in exactly one workload partition"));
    }
    if (countSubstring(build, WORKLOAD_HELP_BINDING) != 1 or countSubstring(build, "addHelpFlagTests(") != 2) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: CLI help flag tests must run only in the core workload partition"));
    }
    return failures.toOwnedSlice(allocator);
}

pub const WORKLOAD_MATRIX =
    "      fail-fast: false\n" ++
    "      matrix:\n" ++
    "        name: [linux-x64, linux-arm64]\n" ++
    "        optimize: [Debug, ReleaseSafe]\n" ++
    "        include:\n" ++
    "          - os: ubuntu-24.04\n" ++
    "            name: linux-x64\n" ++
    "            architecture: amd64\n" ++
    "          - os: ubuntu-24.04-arm\n" ++
    "            name: linux-arm64\n" ++
    "            architecture: arm64\n";

pub const WORKLOAD_SETUP_STEPS = [_][]const u8{
    "Install Zig via ghr",
    "Validate Zig version",
    "Install metadata decompression dependency",
};

pub const WORKLOAD_SETUP_LINES = [_][]const u8{
    "          persist-credentials: false",
    "        uses: cataggar/ghr/actions/install@c4be68b52d67d7acd2a7fe6c1e5f126e1754176e # v0.8.1",
    "          ghr-version: v0.8.1",
    "            cataggar/zig@v0.17.0",
    "            RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U",
    "        run: test \"$(zig version)\" = 0.17.0",
    "            sudo apt-get install --yes --no-install-recommends liblzma-dev libzstd-dev",
};

pub const WORKLOAD_RUNS_ON = "    runs-on: ${{ matrix.os }}";
pub const WORKLOAD_CORE_RUNS_ON =
    "    runs-on: ${{ (github.event_name != 'pull_request' || " ++
    "github.event.pull_request.head.repo.full_name == github.repository) && " ++
    "fromJSON(format('[\"self-hosted\",\"Linux\",\"{0}\",\"ubuntu2604\"]', " ++
    "matrix.os == 'ubuntu-24.04-arm' && 'ARM64' || 'X64')) || matrix.os }}";

pub const RootlessJobSpec = struct { name: []const u8, key: ?[]const u8 };
pub const ROOTLESS_ROOT_JOBS = [_]RootlessJobSpec{
    .{ .name = "install-action-native", .key = "runner" },
    .{ .name = "build-and-test-workload-production", .key = "os" },
    .{ .name = "build-and-test-workload-apt-system", .key = "os" },
    .{ .name = "build-and-test-workload-native", .key = "os" },
    .{ .name = "build-and-test-workload-release", .key = "os" },
    .{ .name = "native-recovery-zig-workflows", .key = "os" },
    .{ .name = "native-recovery-zig-repository", .key = "os" },
    .{ .name = "native-recovery-zig-helper", .key = "os" },
    .{ .name = "native-recovery-zig-family", .key = "os" },
    .{ .name = "native-recovery-zig-scenarios", .key = "os" },
    .{ .name = "native-recovery-zig-diversions", .key = "os" },
    .{ .name = "security-audit", .key = null },
    .{ .name = "integration-required", .key = "runner" },
};

pub const ROOTLESS_ROOT_GATE =
    "(github.event_name != 'pull_request' || " ++
    "github.event.pull_request.head.repo.full_name == github.repository)";

pub const ROOTLESS_ROOT_CONTAINER =
    "    container:\n" ++
    "      image: ubuntu:24.04\n" ++
    "      options: --privileged --init\n" ++
    "    defaults:\n" ++
    "      run:\n" ++
    "        shell: bash /usr/local/bin/as-runner {0}\n";

pub const ROOTLESS_ROOT_BOOTSTRAP =
    "      - name: Bootstrap the hosted-runner-like root container\n" ++
    "        shell: bash\n" ++
    "        run: |\n" ++
    "          set -euo pipefail\n" ++
    "          export DEBIAN_FRONTEND=noninteractive\n" ++
    "          # The minimized image's dpkg config excludes /usr/share/man, so the\n" ++
    "          # reference dpkg would skip man-page alternative links debz installs.\n" ++
    "          rm -f /etc/dpkg/dpkg.cfg.d/excludes\n" ++
    "          apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 update\n" ++
    "          apt-get -o Acquire::Retries=3 install --yes --no-install-recommends \\\n" ++
    "            binutils bzip2 ca-certificates curl file git gnupg jq pkg-config \\\n" ++
    "            sudo unzip xz-utils zstd\n" ++
    "          ! command -v python3\n" ++
    "          ! command -v python\n" ++
    "          # Steps run as the hosted image's unprivileged user with passwordless\n" ++
    "          # sudo, because some tools refuse to run as root.\n" ++
    "          useradd --create-home --uid 1001 --shell /bin/bash runner\n" ++
    "          printf 'runner ALL=(ALL:ALL) NOPASSWD: ALL\\n' >/etc/sudoers.d/runner\n" ++
    "          chmod 0440 /etc/sudoers.d/runner\n" ++
    "          cat >/usr/local/bin/as-runner <<'EOF'\n" ++
    "          #!/bin/bash\n" ++
    "          # Run one step script as runner with the hosted default shell. The\n" ++
    "          # runner writes the script and file-command files as container root.\n" ++
    "          set -eu\n" ++
    "          chmod a+r -- \"$1\"\n" ++
    "          chmod a+x -- \"$(dirname -- \"$1\")\"\n" ++
    "          for f in \"${GITHUB_ENV-}\" \"${GITHUB_PATH-}\" \"${GITHUB_OUTPUT-}\" \\\n" ++
    "            \"${GITHUB_STEP_SUMMARY-}\" \"${GITHUB_STATE-}\"; do\n" ++
    "            if [ -n \"$f\" ] && [ -e \"$f\" ]; then\n" ++
    "              chmod a+rw -- \"$f\"\n" ++
    "              chmod a+x -- \"$(dirname -- \"$f\")\"\n" ++
    "            fi\n" ++
    "          done\n" ++
    "          exec runuser -u runner -- env PATH=\"$PATH\" bash -e \"$1\"\n" ++
    "          EOF\n" ++
    "          chmod 0755 /usr/local/bin/as-runner\n" ++
    "          id\n" ++
    "          grep -E '^(CapEff|NoNewPrivs|Seccomp):' /proc/self/status\n" ++
    "          nproc\n" ++
    "          free -g\n";

pub const ROOTLESS_ROOT_HANDOFF =
    "      - name: Hand the checkout to the runner user\n" ++
    "        shell: bash\n" ++
    "        run: chown -R runner:runner \"$GITHUB_WORKSPACE\"\n";

pub const ROOTLESS_ROOT_FOREIGN_TOKENS = [_][]const u8{
    "podman",
    "--privileged",
    "as-runner",
    "/etc/sudoers.d/",
};

pub const CiJobSection = struct {
    name: []const u8,
    body: []const u8,
    header_start: usize,
    body_end: usize,
};

pub fn parseCiJobSections(allocator: std.mem.Allocator, text: []const u8) ![]CiJobSection {
    var headers: std.ArrayList(struct { name: []const u8, header_start: usize, body_start: usize }) = .empty;
    var pos: usize = 0;
    while (pos < text.len) {
        const nl = std.mem.indexOfScalarPos(u8, text, pos, '\n') orelse text.len;
        const line = text[pos..nl];
        if (nl < text.len and line.len >= 4 and line[0] == ' ' and line[1] == ' ' and
            (line[2] >= 'a' and line[2] <= 'z') and line[line.len - 1] == ':')
        {
            const name = line[2 .. line.len - 1];
            var valid = true;
            for (name) |c| {
                if (!((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-')) valid = false;
            }
            if (valid) {
                try headers.append(allocator, .{ .name = name, .header_start = pos, .body_start = nl + 1 });
            }
        }
        pos = nl + 1;
    }
    var out: std.ArrayList(CiJobSection) = .empty;
    for (headers.items, 0..) |h, i| {
        const body_end = if (i + 1 < headers.items.len) headers.items[i + 1].header_start else text.len;
        try out.append(allocator, .{
            .name = h.name,
            .body = text[h.body_start..body_end],
            .header_start = h.header_start,
            .body_end = body_end,
        });
    }
    return out.toOwnedSlice(allocator);
}

pub fn parseCiJobsMap(allocator: std.mem.Allocator, text: []const u8) !std.StringArrayHashMapUnmanaged([]const u8) {
    var map: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    for (try parseCiJobSections(allocator, text)) |sec| {
        try map.put(allocator, sec.name, sec.body);
    }
    return map;
}

pub fn rootlessRootRunsOn(allocator: std.mem.Allocator, key: ?[]const u8) !struct { rootless: []const u8, hosted: []const u8 } {
    if (key) |k| {
        return .{
            .rootless = try std.fmt.allocPrint(
                allocator,
                "    runs-on: ${{{{ {s} && fromJSON(format('[\"self-hosted\",\"Linux\",\"{{0}}\",\"ubuntu2604\",\"podman\"]', matrix.{s} == 'ubuntu-24.04-arm' && 'ARM64' || 'X64')) || matrix.{s} }}}}",
                .{ ROOTLESS_ROOT_GATE, k, k },
            ),
            .hosted = try std.fmt.allocPrint(allocator, "    runs-on: ${{{{ matrix.{s} }}}}", .{k}),
        };
    }
    return .{
        .rootless = try std.fmt.allocPrint(
            allocator,
            "    runs-on: ${{{{ {s} && fromJSON('[\"self-hosted\",\"Linux\",\"X64\",\"ubuntu2604\",\"podman\"]') || 'ubuntu-24.04' }}}}",
            .{ROOTLESS_ROOT_GATE},
        ),
        .hosted = "    runs-on: ubuntu-24.04",
    };
}

fn matchRootlessCheckoutEnd(steps: []const u8, start: usize) ?usize {
    const p1 = "      - uses: actions/checkout@";
    if (!startsWithAt(steps, start, p1)) return null;
    const sha_start = start + p1.len;
    if (sha_start + 40 > steps.len) return null;
    if (!isLowerHex(steps[sha_start .. sha_start + 40], 40)) return null;
    const v_prefix = " # v";
    if (!startsWithAt(steps, sha_start + 40, v_prefix)) return null;
    const nl1 = std.mem.indexOfScalarPos(u8, steps, sha_start + 40 + v_prefix.len, '\n') orelse return null;
    if (nl1 == sha_start + 40 + v_prefix.len) return null;
    const tail = "        with:\n          persist-credentials: false\n";
    if (!startsWithAt(steps, nl1 + 1, tail)) return null;
    return nl1 + 1 + tail.len;
}

fn replaceFirstOwned(allocator: std.mem.Allocator, text: []const u8, needle: []const u8, replacement: []const u8) ![]u8 {
    const idx = std.mem.indexOf(u8, text, needle) orelse return allocator.dupe(u8, text);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(allocator, text[0..idx]);
    try out.appendSlice(allocator, replacement);
    try out.appendSlice(allocator, text[idx + needle.len ..]);
    return out.toOwnedSlice(allocator);
}

pub fn rootlessRootCiFailures(allocator: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const jobs = try parseCiJobsMap(allocator, text);

    for (ROOTLESS_ROOT_JOBS) |spec| {
        const body = jobs.get(spec.name) orelse "";
        const ro = try rootlessRootRunsOn(allocator, spec.key);
        const steps = if (std.mem.indexOf(u8, body, "    steps:\n")) |idx| body[idx + "    steps:\n".len ..] else "";
        const checkout_end = if (std.mem.startsWith(u8, steps, ROOTLESS_ROOT_BOOTSTRAP))
            matchRootlessCheckoutEnd(steps, ROOTLESS_ROOT_BOOTSTRAP.len)
        else
            null;
        const rest = if (std.mem.startsWith(u8, steps, ROOTLESS_ROOT_BOOTSTRAP))
            try replaceFirstOwned(allocator, steps[ROOTLESS_ROOT_BOOTSTRAP.len..], ROOTLESS_ROOT_HANDOFF, "")
        else
            "";

        const container_block = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ ro.rootless, ROOTLESS_ROOT_CONTAINER });
        var container_count: usize = 0;
        {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, body, pos, container_block)) |idx| {
                pos = idx + container_block.len;
                if (pos + 5 <= body.len and std.mem.eql(u8, body[pos .. pos + 4], "    ") and
                    body[pos + 4] >= 'a' and body[pos + 4] <= 'z')
                {
                    container_count += 1;
                }
            }
        }

        var runs_on_lines: std.ArrayList([]const u8) = .empty;
        var container_keys: std.ArrayList([]const u8) = .empty;
        {
            var l_it = std.mem.splitScalar(u8, body, '\n');
            while (l_it.next()) |line| {
                if (std.mem.startsWith(u8, line, "    runs-on:")) {
                    try runs_on_lines.append(allocator, line);
                }
                if (std.mem.startsWith(u8, line, "    container:") or
                    std.mem.startsWith(u8, line, "    defaults:") or
                    std.mem.startsWith(u8, line, "    services:"))
                {
                    try container_keys.append(allocator, line);
                }
            }
        }
        var rest_has_shell = false;
        {
            var l_it = std.mem.splitScalar(u8, rest, '\n');
            while (l_it.next()) |line| {
                if (std.mem.startsWith(u8, line, "        shell:")) rest_has_shell = true;
            }
        }

        if (runs_on_lines.items.len != 1 or
            !std.mem.eql(u8, runs_on_lines.items[0], ro.rootless) or
            container_count != 1 or
            container_keys.items.len != 2 or
            !std.mem.eql(u8, container_keys.items[0], "    container:") or
            !std.mem.eql(u8, container_keys.items[1], "    defaults:") or
            countSubstring(body, "    steps:\n") != 1 or
            checkout_end == null or
            !startsWithAt(steps, checkout_end.?, ROOTLESS_ROOT_HANDOFF) or
            rest_has_shell)
        {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(allocator, "ci.yml: {s} must run as the hosted runner user in the reviewed rootless root container", .{spec.name}),
            );
        }
    }

    for (jobs.keys(), jobs.values()) |name, body| {
        var is_rootless = false;
        for (ROOTLESS_ROOT_JOBS) |spec| {
            if (std.mem.eql(u8, spec.name, name)) is_rootless = true;
        }
        if (!is_rootless) {
            var has_foreign = false;
            for (ROOTLESS_ROOT_FOREIGN_TOKENS) |tok| {
                if (std.mem.indexOf(u8, body, tok) != null) has_foreign = true;
            }
            if (has_foreign) {
                try failures.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "ci.yml: {s} must not use the rootless root container or its runner label", .{name}),
                );
            }
        }
    }
    if (countSubstring(text, ROOTLESS_ROOT_CONTAINER) != ROOTLESS_ROOT_JOBS.len or
        countSubstring(text, ROOTLESS_ROOT_BOOTSTRAP) != ROOTLESS_ROOT_JOBS.len or
        countSubstring(text, ROOTLESS_ROOT_HANDOFF) != ROOTLESS_ROOT_JOBS.len)
    {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: rootless root container scaffolding must appear only in its reviewed jobs"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn rootlessRootHostedView(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    if ((try rootlessRootCiFailures(allocator, text)).len > 0) return text;
    const sections = try parseCiJobSections(allocator, text);
    if (sections.len == 0) return text;
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(allocator, text[0..sections[0].header_start]);
    for (sections) |sec| {
        var body = sec.body;
        for (ROOTLESS_ROOT_JOBS) |spec| {
            if (std.mem.eql(u8, spec.name, sec.name)) {
                const ro = try rootlessRootRunsOn(allocator, spec.key);
                const from1 = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ ro.rootless, ROOTLESS_ROOT_CONTAINER });
                const to1 = try std.fmt.allocPrint(allocator, "{s}\n", .{ro.hosted});
                body = try replaceFirstOwned(allocator, body, from1, to1);
                const from2 = "    steps:\n" ++ ROOTLESS_ROOT_BOOTSTRAP;
                body = try replaceFirstOwned(allocator, body, from2, "    steps:\n");
                body = try replaceFirstOwned(allocator, body, ROOTLESS_ROOT_HANDOFF, "");
                break;
            }
        }
        try out.appendSlice(allocator, try std.fmt.allocPrint(allocator, "  {s}:\n{s}", .{ sec.name, body }));
    }
    return out.toOwnedSlice(allocator);
}

pub const WORKLOAD_DEBUG = "${{ matrix.optimize == 'Debug' }}";
pub const WORKLOAD_RELEASESAFE = "${{ matrix.optimize == 'ReleaseSafe' }}";
pub const WORKLOAD_PREPARE_DPKG = "reference_dpkg=\"$(zig-out/bin/debz-native-dpkg-reference)\"";
pub const WORKLOAD_BUILD_DPKG = "zig build build-native-dpkg-reference -j2";
pub const WORKLOAD_DPKG_MODE = "-Dnative-reference-dpkg=\"$reference_dpkg\" -Doptimize=\"$OPTIMIZE\" -j2 --summary all";
pub const WORKLOAD_MODE = "-Doptimize=\"$OPTIMIZE\" -j2 --summary all";

pub const WORKLOAD_SELECTOR_COMMANDS = [_][]const u8{
    WORKLOAD_BUILD_DPKG,
    WORKLOAD_PREPARE_DPKG,
    "zig build build-native-acceptance-zig " ++ WORKLOAD_MODE,
    "lifecycle=\"$PWD/.tmp/zig-lifecycle-workspace-$OPTIMIZE\"",
    "trigger=\"$PWD/.tmp/zig-trigger-workspace-$OPTIMIZE\"",
    "sudo -n env TMPDIR=\"$PWD/.tmp\" XDG_CACHE_HOME=\"$PWD/.cache\" " ++
        "zig-out/bin/native-lifecycle-zig-acceptance --oracle-only --diversions-only " ++
        "--reference-dpkg \"$reference_dpkg\" --workspace \"$lifecycle\"",
    "sudo -n env TMPDIR=\"$PWD/.tmp\" XDG_CACHE_HOME=\"$PWD/.cache\" " ++
        "zig-out/bin/native-trigger-zig-acceptance --oracle-only --diversion-settlement-reference-only " ++
        "--reference-dpkg \"$reference_dpkg\" --workspace \"$trigger\"",
    "test -d \"$lifecycle\" && test -d \"$trigger\"",
    "if sudo -n env TMPDIR=\"$PWD/.tmp\" XDG_CACHE_HOME=\"$PWD/.cache\" " ++
        "zig-out/bin/native-trigger-zig-acceptance --oracle-only --diversion-settlement-reference-only " ++
        "--diversions-only --reference-dpkg \"$reference_dpkg\" " ++
        "2>\"$PWD/.tmp/zig-invalid-selector.log\"; then exit 1; fi",
    "grep -Fxq 'error: InvalidSettlementSelection' \"$PWD/.tmp/zig-invalid-selector.log\"",
    "if sudo -n env TMPDIR=\"$PWD/.tmp\" XDG_CACHE_HOME=\"$PWD/.cache\" " ++
        "zig-out/bin/native-lifecycle-zig-acceptance --oracle-only " ++
        "--reference-dpkg \"$reference_dpkg\" --workspace \"$lifecycle\" " ++
        "2>\"$PWD/.tmp/zig-existing-workspace.log\"; then exit 1; fi",
    "grep -Fxq 'error: PathAlreadyExists' \"$PWD/.tmp/zig-existing-workspace.log\"",
};

pub const WorkloadStepExpectation = struct {
    name: []const u8,
    condition: ?[]const u8,
    commands: ?[]const []const u8,
    required: []const []const u8,
};

pub const WorkloadJobExpectation = struct {
    name: []const u8,
    label: []const u8,
    steps: []const WorkloadStepExpectation,
};

pub const WORKLOAD_JOBS = [_]WorkloadJobExpectation{
    .{
        .name = "build-and-test-workload",
        .label = "core",
        .steps = &.{
            .{
                .name = "Build and test workload core",
                .condition = null,
                .commands = &.{
                    "zig build " ++ WORKLOAD_MODE,
                    "zig build test-workload-core " ++ WORKLOAD_MODE,
                },
                .required = &.{},
            },
            .{
                .name = "Check ReleaseSafe CLI help",
                .condition = WORKLOAD_RELEASESAFE,
                .commands = &.{"zig build -Doptimize=ReleaseSafe -j2 run -- --help"},
                .required = &.{},
            },
            .{
                .name = "Prepare native download action fixture",
                .condition = WORKLOAD_RELEASESAFE,
                .commands = null,
                .required = &.{
                    "        id: download-fixture",
                    "          \"$PWD/zig-out/bin/debz-integration-repository\" \\",
                    "          zig-out/bin/debz plan \\",
                    "          printf '%s\\n' \"$PWD/zig-out/bin\" >>\"$GITHUB_PATH\"",
                },
            },
            .{
                .name = "Prepare native exact-lock package closure",
                .condition = WORKLOAD_RELEASESAFE,
                .commands = null,
                .required = &.{
                    "        id: download",
                    "        uses: ./actions/download",
                    "          lock-input: ${{ steps.download-fixture.outputs.lock }}",
                    "          cache: 'false'",
                },
            },
            .{
                .name = "Validate native download action outputs",
                .condition = WORKLOAD_RELEASESAFE,
                .commands = &.{
                    "test \"$CACHE_HIT\" = false",
                    "test -d \"$CACHE_PATH\"",
                    "test \"$DOWNLOADED\" -gt 0",
                    "test \"$REUSED\" -eq 0",
                },
                .required = &.{},
            },
        },
    },
    .{
        .name = "build-and-test-workload-production",
        .label = "production",
        .steps = &.{
            .{
                .name = "Build and test workload production",
                .condition = null,
                .commands = &.{"zig build test-workload-production " ++ WORKLOAD_MODE},
                .required = &.{},
            },
            .{
                .name = "Compare native triggers and diversion settlement with dpkg",
                .condition = null,
                .commands = &.{
                    "mkdir -p .tmp",
                    WORKLOAD_BUILD_DPKG,
                    WORKLOAD_PREPARE_DPKG,
                    "zig build test-native-triggers-zig test-native-diversion-settlement-zig " ++ WORKLOAD_DPKG_MODE,
                },
                .required = &.{},
            },
        },
    },
    .{
        .name = "build-and-test-workload-apt-system",
        .label = "apt system",
        .steps = &.{
            .{
                .name = "Build and test workload apt system",
                .condition = null,
                .commands = &.{"zig build test-workload-apt-system " ++ WORKLOAD_MODE},
                .required = &.{},
            },
            .{
                .name = "Run required real apt facade acceptance",
                .condition = null,
                .commands = &.{
                    "sudo env PATH=\"$PATH\" TMPDIR=\"$PWD/.zig-cache\" " ++
                        "ZIG_GLOBAL_CACHE_DIR=\"$PWD/.zig-cache/apt-system-acceptance-global\" " ++
                        "ZIG_LOCAL_CACHE_DIR=\"$PWD/.zig-cache/apt-system-acceptance-local\" " ++
                        "\"$(command -v zig)\" build test-apt-system-acceptance " ++ WORKLOAD_MODE,
                },
                .required = &.{},
            },
            .{
                .name = "Normalize apt facade acceptance diagnostics",
                .condition = "${{ always() }}",
                .commands = &.{
                    "sudo chown -R \"$USER:$USER\" .zig-cache/apt-system-acceptance-global " ++
                        ".zig-cache/apt-system-acceptance-local 2>/dev/null || true",
                },
                .required = &.{},
            },
            .{
                .name = "Run required privileged orchestration crash suite",
                .condition = WORKLOAD_DEBUG,
                .commands = &.{
                    "sudo rm -rf /run/debz",
                    "sudo env ZIG_GLOBAL_CACHE_DIR=\"$PWD/.zig-global-cache-orchestration-required\" " ++
                        "ZIG_LOCAL_CACHE_DIR=\"$PWD/.zig-cache-orchestration-required\" " ++
                        "\"$(command -v zig)\" build test-apt-system " ++
                        "-Drequire-privileged-orchestration-tests=true -j2 --summary all",
                },
                .required = &.{},
            },
            .{
                .name = "Normalize privileged orchestration diagnostics",
                .condition = "${{ always() && matrix.optimize == 'Debug' }}",
                .commands = &.{
                    "sudo chown -R \"$USER:$USER\" .zig-cache-orchestration-required " ++
                        ".zig-global-cache-orchestration-required 2>/dev/null || true",
                    "sudo rm -rf /run/debz",
                },
                .required = &.{},
            },
        },
    },
    .{
        .name = "build-and-test-workload-native",
        .label = "native",
        .steps = &.{
            .{
                .name = "Build and test workload native",
                .condition = null,
                .commands = &.{"zig build test-workload-native " ++ WORKLOAD_MODE},
                .required = &.{},
            },
            .{
                .name = "Compare native materialization, conffiles, differential, and lifecycle with dpkg",
                .condition = null,
                .commands = &.{
                    "mkdir -p .tmp",
                    WORKLOAD_BUILD_DPKG,
                    WORKLOAD_PREPARE_DPKG,
                    "zig build test-native-materialization test-native-conffiles test-native-differential " ++ WORKLOAD_DPKG_MODE,
                    "zig build test-native-lifecycle-zig " ++ WORKLOAD_DPKG_MODE,
                },
                .required = &.{},
            },
            .{
                .name = "Require private native helper namespaces",
                .condition = null,
                .commands = &.{"zig build test-native-helper-namespace " ++ WORKLOAD_MODE},
                .required = &.{},
            },
        },
    },
    .{
        .name = "build-and-test-workload-release",
        .label = "release",
        .steps = &.{
            .{
                .name = "Build and test workload release",
                .condition = null,
                .commands = &.{
                    "zig build test-workload-release " ++ WORKLOAD_MODE,
                    "zig build fuzz " ++ WORKLOAD_MODE,
                },
                .required = &.{},
            },
            .{
                .name = "Test release packaging",
                .condition = WORKLOAD_DEBUG,
                .commands = &.{"zig build test-release -j2 --summary all"},
                .required = &.{},
            },
            .{
                .name = "Run pinned dpkg lifecycle and trigger reference oracles",
                .condition = null,
                .commands = &.{
                    "mkdir -p .tmp",
                    WORKLOAD_BUILD_DPKG,
                    WORKLOAD_PREPARE_DPKG,
                    "zig build test-native-lifecycle-zig-oracle test-native-triggers-zig-oracle " ++
                        "test-native-triggers-zig-settlement-reference " ++ WORKLOAD_DPKG_MODE,
                },
                .required = &.{},
            },
            .{
                .name = "Exercise standalone Zig workspace selectors and fail-closed combinations",
                .condition = null,
                .commands = &WORKLOAD_SELECTOR_COMMANDS,
                .required = &.{},
            },
        },
    },
};

pub const WORKLOAD_ZIG_TARGETS = [_][]const u8{
    "install",
    "run",
    "test-release",
    "fuzz",
    "build-native-acceptance-zig",
    "test-native-materialization",
    "test-native-conffiles",
    "test-native-differential",
    "test-native-lifecycle-zig",
    "test-native-triggers-zig",
    "test-native-diversion-settlement-zig",
    "test-native-lifecycle-zig-oracle",
    "test-native-triggers-zig-oracle",
    "test-native-triggers-zig-settlement-reference",
    "test-native-helper-namespace",
    "test-apt-system-acceptance",
    "test-apt-system",
    "build-native-dpkg-reference",
    "build-native-dpkg-reference",
    "build-native-dpkg-reference",
    "build-native-dpkg-reference",
    "test-workload-core",
    "test-workload-production",
    "test-workload-apt-system",
    "test-workload-native",
    "test-workload-release",
};

pub const WORKLOAD_RESULTS = [_][2][]const u8{
    .{ "BUILD_RESULT", "build-and-test-workload" },
    .{ "BUILD_PRODUCTION_RESULT", "build-and-test-workload-production" },
    .{ "BUILD_APT_SYSTEM_RESULT", "build-and-test-workload-apt-system" },
    .{ "BUILD_NATIVE_RESULT", "build-and-test-workload-native" },
    .{ "BUILD_RELEASE_RESULT", "build-and-test-workload-release" },
};

pub const CI_FULL_MATRIX_INPUT =
    "      run_full_matrix:\n" ++
    "        description: \"Run the standard build/test matrix (off for snapshot-only validation)\"\n" ++
    "        required: true\n" ++
    "        type: boolean\n" ++
    "        default: true\n";
pub const CI_FULL_MATRIX_CONDITION = "github.event_name != 'workflow_dispatch' || inputs.run_full_matrix";
pub const CI_RECOVERY_COHORT_INPUT =
    "      run_native_recovery_cohort:\n" ++
    "        description: \"Run only the hosted native recovery cohort: six recovery shards and the native workload (amd64 and arm64, Debug and ReleaseSafe)\"\n" ++
    "        required: true\n" ++
    "        type: boolean\n" ++
    "        default: false\n";
pub const CI_RECOVERY_COHORT_CONDITION = CI_FULL_MATRIX_CONDITION ++ " || inputs.run_native_recovery_cohort";
pub const CI_BUILD_AGGREGATE_CONDITION = "${{ always() && (" ++ CI_FULL_MATRIX_CONDITION ++ ") }}";
pub const CI_FULL_INTEGRATION_CONDITION =
    "github.event_name == 'schedule' || " ++
    "(github.event_name == 'workflow_dispatch' && inputs.run_full_matrix)";

pub fn extractDispatchInputsBlock(text: []const u8) ?[]const u8 {
    const header = "  workflow_dispatch:\n    inputs:\n";
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, header)) |idx| {
        pos = idx + header.len;
        if (idx > 0 and text[idx - 1] != '\n') continue;
        var end = pos;
        while (end < text.len) {
            const nl = std.mem.indexOfScalarPos(u8, text, end, '\n') orelse break;
            const line = text[end..nl];
            if (line.len < 6 or !std.mem.eql(u8, line[0..6], "      ")) break;
            end = nl + 1;
        }
        return text[pos..end];
    }
    return null;
}

pub fn dispatchInputExact(block: []const u8, expected: []const u8) bool {
    const idx = std.mem.indexOf(u8, block, expected) orelse return false;
    if (countSubstring(block, expected) != 1) return false;
    const after = block[idx + expected.len ..];
    if (after.len == 0) return true;
    return after.len >= 7 and std.mem.eql(u8, after[0..6], "      ") and after[6] >= 'a' and after[6] <= 'z';
}

fn countTrimmedKeyLines(text: []const u8, exact_line: []const u8, key_suffix: []const u8) struct { total_key_lines: usize, exact_matches: usize } {
    var total_key_lines: usize = 0;
    var exact_matches: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const trimmed_left = std.mem.trimStart(u8, line, " ");
        if (std.mem.startsWith(u8, trimmed_left, key_suffix)) {
            total_key_lines += 1;
            if (std.mem.eql(u8, line, exact_line)) exact_matches += 1;
        }
    }
    return .{ .total_key_lines = total_key_lines, .exact_matches = exact_matches };
}

pub fn ciDispatchMatrixFailures(
    allocator: std.mem.Allocator,
    text: []const u8,
    jobs: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const dispatch = extractDispatchInputsBlock(text);
    const rfm_lines = blk: {
        var count: usize = 0;
        var exact: usize = 0;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "      run_full_matrix:")) {
                count += 1;
                if (std.mem.eql(u8, line, "      run_full_matrix:")) exact += 1;
            }
        }
        break :blk (count == 1 and exact == 1);
    };
    if (dispatch == null or countSubstring(dispatch.?, CI_FULL_MATRIX_INPUT) != 1 or !rfm_lines) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: run_full_matrix must be a required boolean dispatch input defaulting to true"));
    }
    const rrc = countTrimmedKeyLines(text, "      run_native_recovery_cohort:", "run_native_recovery_cohort:");
    if (dispatch == null or
        !dispatchInputExact(dispatch.?, CI_RECOVERY_COHORT_INPUT) or
        rrc.total_key_lines != 1 or
        rrc.exact_matches != 1 or
        countSubstring(text, "inputs.run_native_recovery_cohort") != 1 + RECOVERY_ZIG_SHARDS.len)
    {
        try failures.append(
            allocator,
            try allocator.dupe(
                u8,
                "ci.yml: run_native_recovery_cohort must be a required boolean dispatch input defaulting to false" ++
                    " that gates only the hosted native workload and recovery shards",
            ),
        );
    }

    const CondPair = struct { name: []const u8, cond: []const u8 };
    var conds: std.ArrayList(CondPair) = .empty;
    for (WORKLOAD_JOBS) |wj| {
        const cond = if (std.mem.eql(u8, wj.name, "build-and-test-workload-native"))
            CI_RECOVERY_COHORT_CONDITION
        else
            CI_FULL_MATRIX_CONDITION;
        try conds.append(allocator, .{ .name = wj.name, .cond = cond });
    }
    for (RECOVERY_ZIG_SHARDS) |sh| {
        try conds.append(allocator, .{ .name = sh.name, .cond = CI_RECOVERY_COHORT_CONDITION });
    }
    try conds.append(allocator, .{ .name = "build-and-test", .cond = CI_BUILD_AGGREGATE_CONDITION });
    try conds.append(allocator, .{ .name = "integration-full", .cond = CI_FULL_INTEGRATION_CONDITION });

    for (conds.items) |cp| {
        const body = jobs.get(cp.name) orelse "";
        const exp_line = try std.fmt.allocPrint(allocator, "    if: {s}", .{cp.cond});
        var if_count: usize = 0;
        var exact_if: usize = 0;
        var it = std.mem.splitScalar(u8, body, '\n');
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "    if:")) {
                if_count += 1;
                if (std.mem.eql(u8, line, exp_line)) exact_if += 1;
            }
        }
        if (if_count != 1 or exact_if != 1) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "ci.yml: {s} must retain its exact dispatch matrix condition", .{cp.name}));
        }
    }
    if (jobs.get("integration-required")) |ir_body| {
        var has_if = false;
        var it = std.mem.splitScalar(u8, ir_body, '\n');
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "    if:")) has_if = true;
        }
        if (has_if) {
            try failures.append(allocator, try allocator.dupe(u8, "ci.yml: required integration roots must remain unconditional"));
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn workflowLogicalCommands(allocator: std.mem.Allocator, step: []const u8) !?[][]const u8 {
    var single: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, step, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "        run: ") and !std.mem.startsWith(u8, line, "        run: |")) {
            const cmd = std.mem.trim(u8, line["        run: ".len..], " \t\r");
            if (cmd.len > 0) try single.append(allocator, cmd);
        }
    }
    if (single.items.len > 0) {
        if (single.items.len == 1 and std.mem.indexOf(u8, step, "        run: |\n") == null) {
            return try single.toOwnedSlice(allocator);
        }
        return null;
    }
    const marker = "        run: |\n";
    const m_idx = std.mem.indexOf(u8, step, marker) orelse return null;
    if (countSubstring(step, marker) != 1) return null;
    const script = step[m_idx + marker.len ..];
    var commands: std.ArrayList([]const u8) = .empty;
    var pending: std.ArrayList(u8) = .empty;
    var s_it = std.mem.splitScalar(u8, script, '\n');
    while (s_it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or (pending.items.len == 0 and line[0] == '#')) continue;
        if (pending.items.len > 0) {
            try pending.append(allocator, ' ');
        }
        try pending.appendSlice(allocator, line);
        if (pending.items.len > 0 and pending.items[pending.items.len - 1] == '\\') {
            pending.items.len -= 1;
            while (pending.items.len > 0 and isSpace(pending.items[pending.items.len - 1])) {
                pending.items.len -= 1;
            }
            continue;
        }
        try commands.append(allocator, try allocator.dupe(u8, std.mem.trim(u8, pending.items, " \t")));
        pending.clearRetainingCapacity();
    }
    if (pending.items.len > 0) {
        try commands.append(allocator, try allocator.dupe(u8, std.mem.trim(u8, pending.items, " \t")));
    }
    return try commands.toOwnedSlice(allocator);
}

pub fn workloadZigTargets(allocator: std.mem.Allocator, command: []const u8) !?[][]const u8 {
    var rest_opt: ?[]const u8 = null;
    for ([_][]const u8{ "zig build", "\"$(command -v zig)\" build" }) |pat| {
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, command, pos, pat)) |idx| {
            pos = idx + pat.len;
            const before_ok = idx == 0 or isSpace(command[idx - 1]);
            const after_ok = pos == command.len or isSpace(command[pos]);
            if (before_ok and after_ok) {
                rest_opt = command[pos..];
                break;
            }
        }
        if (rest_opt != null) break;
    }
    const rest = rest_opt orelse return null;
    var targets: std.ArrayList([]const u8) = .empty;
    var tok_it = std.mem.tokenizeAny(u8, rest, " \t\r\n");
    while (tok_it.next()) |token| {
        if (std.mem.eql(u8, token, "--")) break;
        if (std.mem.eql(u8, token, "--summary") or
            std.mem.eql(u8, token, "--prefix") or
            std.mem.eql(u8, token, "--cache-dir") or
            std.mem.eql(u8, token, "--global-cache-dir") or
            std.mem.eql(u8, token, "--build-file") or
            std.mem.eql(u8, token, "-p"))
        {
            _ = tok_it.next();
        } else if (!std.mem.startsWith(u8, token, "-")) {
            try targets.append(allocator, try allocator.dupe(u8, token));
        }
    }
    if (targets.items.len == 0) {
        try targets.append(allocator, "install");
    }
    return try targets.toOwnedSlice(allocator);
}

pub fn workflowZigInvocations(allocator: std.mem.Allocator, text: []const u8) ![][][]const u8 {
    var invocations: std.ArrayList([][]const u8) = .empty;
    var pending: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (pending.items.len == 0 and std.mem.startsWith(u8, line, "#")) continue;
        if (pending.items.len > 0) {
            if (line.len > 0) {
                try pending.append(allocator, ' ');
                try pending.appendSlice(allocator, line);
            }
        } else {
            try pending.appendSlice(allocator, line);
        }
        const cur = std.mem.trim(u8, pending.items, " \t");
        if (cur.len > 0 and cur[cur.len - 1] == '\\') {
            const trimmed = std.mem.trimEnd(u8, cur[0 .. cur.len - 1], " \t");
            if (trimmed.ptr != pending.items.ptr) {
                std.mem.copyForwards(u8, pending.items[0..trimmed.len], trimmed);
            }
            pending.items.len = trimmed.len;
            continue;
        }
        if (try workloadZigTargets(allocator, cur)) |t| {
            try invocations.append(allocator, t);
        }
        pending.clearRetainingCapacity();
    }
    return invocations.toOwnedSlice(allocator);
}

pub const JobStep = struct { name: []const u8, body: []const u8 };

pub fn parseJobSteps(allocator: std.mem.Allocator, body: []const u8) ![]JobStep {
    var out: std.ArrayList(JobStep) = .empty;
    var pos: usize = 0;
    while (pos < body.len) {
        const nl = std.mem.indexOfScalarPos(u8, body, pos, '\n') orelse body.len;
        const line = body[pos..nl];
        if (nl < body.len and std.mem.startsWith(u8, line, "      - name: ")) {
            const step_name = line["      - name: ".len..];
            const body_start = nl + 1;
            var scan = body_start;
            var body_end = body.len;
            while (scan < body.len) {
                const snl = std.mem.indexOfScalarPos(u8, body, scan, '\n') orelse body.len;
                const sline = body[scan..snl];
                if (std.mem.startsWith(u8, sline, "      - ")) {
                    body_end = scan;
                    break;
                }
                scan = snl + 1;
            }
            try out.append(allocator, .{ .name = step_name, .body = body[body_start..body_end] });
            pos = body_end;
            continue;
        }
        pos = nl + 1;
    }
    return out.toOwnedSlice(allocator);
}

fn lineInLines(haystack: []const u8, target_line: []const u8) bool {
    var it = std.mem.splitScalar(u8, haystack, '\n');
    while (it.next()) |line| {
        if (std.mem.eql(u8, line, target_line)) return true;
    }
    return false;
}

pub fn workloadCiFailures(
    allocator: std.mem.Allocator,
    jobs: std.StringArrayHashMapUnmanaged([]const u8),
    text: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    var shared_setup: ?[]const u8 = null;
    var inventory: std.ArrayList([]const u8) = .empty;

    for (WORKLOAD_JOBS) |wj| {
        const body = jobs.get(wj.name) orelse "";
        const steps_idx = std.mem.indexOf(u8, body, "    steps:\n");
        const header = if (steps_idx) |idx| body[0..idx] else body;
        const exp_name_line = try std.fmt.allocPrint(
            allocator,
            "    name: Build and test workload {s} (${{{{ matrix.name }}}}, ${{{{ matrix.optimize }}}})",
            .{wj.label},
        );
        const exp_runs_on = if (std.mem.eql(u8, wj.label, "core")) WORKLOAD_CORE_RUNS_ON else WORKLOAD_RUNS_ON;
        const exp_timeout = try std.fmt.allocPrint(allocator, "    timeout-minutes: {d}", .{WORKLOAD_TIMEOUT_MINUTES});

        var runs_on_cnt: usize = 0;
        var runs_on_ok = false;
        var timeout_cnt: usize = 0;
        var timeout_ok = false;
        var has_needs_or_coe = false;
        {
            var it = std.mem.splitScalar(u8, body, '\n');
            while (it.next()) |line| {
                if (std.mem.startsWith(u8, line, "    runs-on:")) {
                    runs_on_cnt += 1;
                    if (std.mem.eql(u8, line, exp_runs_on)) runs_on_ok = true;
                }
                if (std.mem.startsWith(u8, line, "    timeout-minutes:")) {
                    timeout_cnt += 1;
                    if (std.mem.eql(u8, line, exp_timeout)) timeout_ok = true;
                }
                if (std.mem.startsWith(u8, line, "    needs:") or std.mem.startsWith(u8, line, "    continue-on-error:")) {
                    has_needs_or_coe = true;
                }
            }
        }
        const strat_idx = std.mem.indexOf(u8, header, "    strategy:\n");
        const env_idx = if (strat_idx) |si| std.mem.indexOfPos(u8, header, si + "    strategy:\n".len, "    env:\n") else null;
        const matrix_part = if (strat_idx != null and env_idx != null)
            header[strat_idx.? + "    strategy:\n".len .. env_idx.?]
        else
            "";
        const env_part = if (env_idx) |ei| header[ei + "    env:\n".len ..] else "";

        if (!lineInLines(body, exp_name_line) or
            runs_on_cnt != 1 or !runs_on_ok or
            timeout_cnt != 1 or !timeout_ok or
            countSubstring(header, "    strategy:\n") != 1 or
            countSubstring(body, "    steps:\n") != 1 or
            !std.mem.eql(u8, matrix_part, WORKLOAD_MATRIX) or
            !std.mem.eql(u8, env_part, "      OPTIMIZE: ${{ matrix.optimize }}\n") or
            has_needs_or_coe or
            std.mem.indexOf(u8, body, "continue-on-error:") != null)
        {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(
                    allocator,
                    "ci.yml: {s} must require both architectures and optimization modes within {d} minutes",
                    .{ wj.name, WORKLOAD_TIMEOUT_MINUTES },
                ),
            );
        }

        const first_step_header = try std.fmt.allocPrint(allocator, "      - name: {s}\n", .{wj.steps[0].name});
        const after_steps = if (steps_idx) |idx| body[idx + "    steps:\n".len ..] else body;
        const setup = if (std.mem.indexOf(u8, after_steps, first_step_header)) |f_idx| after_steps[0..f_idx] else after_steps;
        if (shared_setup == null) shared_setup = setup;
        var setup_ok = std.mem.eql(u8, setup, shared_setup.?) and
            std.mem.startsWith(u8, setup, "      - uses: actions/checkout@");
        for (WORKLOAD_SETUP_STEPS) |ss| {
            const ss_hdr = try std.fmt.allocPrint(allocator, "      - name: {s}\n", .{ss});
            if (std.mem.indexOf(u8, setup, ss_hdr) == null) setup_ok = false;
        }
        for (WORKLOAD_SETUP_LINES) |sl| {
            if (!lineInLines(setup, sl)) setup_ok = false;
        }
        {
            var it = std.mem.splitScalar(u8, setup, '\n');
            while (it.next()) |line| {
                if (std.mem.startsWith(u8, line, "        if:")) setup_ok = false;
            }
        }
        if (!setup_ok) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "ci.yml: {s} must retain pinned Zig and metadata dependencies", .{wj.name}));
        }

        const parsed_steps = try parseJobSteps(allocator, body);
        var step_names_ok = parsed_steps.len == WORKLOAD_SETUP_STEPS.len + wj.steps.len;
        if (step_names_ok) {
            for (WORKLOAD_SETUP_STEPS, 0..) |ss, i| {
                if (!std.mem.eql(u8, parsed_steps[i].name, ss)) step_names_ok = false;
            }
            for (wj.steps, 0..) |ws, i| {
                if (!std.mem.eql(u8, parsed_steps[WORKLOAD_SETUP_STEPS.len + i].name, ws.name)) step_names_ok = false;
            }
        }
        if (!step_names_ok) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "ci.yml: {s} has a missing, reordered or unreviewed workload step", .{wj.name}));
        }

        var actual_steps_map: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
        for (parsed_steps) |ps| {
            try actual_steps_map.put(allocator, ps.name, ps.body);
        }
        for (wj.steps) |ws| {
            const step_body = actual_steps_map.get(ws.name) orelse "";
            var conds: std.ArrayList([]const u8) = .empty;
            var l_it = std.mem.splitScalar(u8, step_body, '\n');
            while (l_it.next()) |line| {
                if (std.mem.startsWith(u8, line, "        if: ")) {
                    try conds.append(allocator, line["        if: ".len..]);
                }
            }
            const cond_ok = if (ws.condition) |exp_c|
                (conds.items.len == 1 and std.mem.eql(u8, conds.items[0], exp_c))
            else
                (conds.items.len == 0);
            const actual_cmds = try workflowLogicalCommands(allocator, step_body);
            var cmds_ok = true;
            if (ws.commands) |exp_cmds| {
                if (actual_cmds) |ac| {
                    if (ac.len != exp_cmds.len) {
                        cmds_ok = false;
                    } else {
                        for (ac, exp_cmds) |a, e| {
                            if (!std.mem.eql(u8, a, e)) cmds_ok = false;
                        }
                    }
                } else {
                    cmds_ok = false;
                }
            } else if (actual_cmds) |ac| {
                for (ac) |cmd| {
                    if ((try workloadZigTargets(allocator, cmd)) != null) cmds_ok = false;
                }
            }
            var req_ok = true;
            for (ws.required) |req_l| {
                if (!lineInLines(step_body, req_l)) req_ok = false;
            }
            if (!cond_ok or !cmds_ok or !req_ok) {
                const mode = if (ws.condition) |c|
                    (if (std.mem.eql(u8, c, WORKLOAD_DEBUG)) "Debug" else if (std.mem.eql(u8, c, WORKLOAD_RELEASESAFE)) "ReleaseSafe" else "every mode")
                else
                    "every mode";
                try failures.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "ci.yml: {s} must execute {s} exactly as reviewed in {s}", .{ wj.name, ws.name, mode }),
                );
            }
        }
        for (actual_steps_map.values()) |step_body| {
            if (try workflowLogicalCommands(allocator, step_body)) |cmds| {
                for (cmds) |cmd| {
                    if (try workloadZigTargets(allocator, cmd)) |ts| {
                        for (ts) |t| try inventory.append(allocator, t);
                    }
                }
            }
        }
    }

    const sorted_inv = try allocator.dupe([]const u8, inventory.items);
    const sorted_exp = try allocator.dupe([]const u8, &WORKLOAD_ZIG_TARGETS);
    const strLess = struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan;
    std.mem.sort([]const u8, sorted_inv, {}, strLess);
    std.mem.sort([]const u8, sorted_exp, {}, strLess);
    var inv_ok = sorted_inv.len == sorted_exp.len;
    if (inv_ok) {
        for (sorted_inv, sorted_exp) |a, e| {
            if (!std.mem.eql(u8, a, e)) inv_ok = false;
        }
    }
    if (!inv_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: every former build workload target must execute exactly once across the workload jobs"));
    }

    var all_inv_targets: std.ArrayList([]const u8) = .empty;
    for (try workflowZigInvocations(allocator, text)) |ts| {
        for (ts) |t| try all_inv_targets.append(allocator, t);
    }
    for (WORKLOAD_PARTITIONS) |wp| {
        var cnt: usize = 0;
        for (all_inv_targets.items) |t| {
            if (std.mem.eql(u8, t, wp.step_name)) cnt += 1;
        }
        if (cnt != 1) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "ci.yml: workload partition {s} must execute exactly once", .{wp.step_name}));
        }
    }
    if (sliceContainsStr(all_inv_targets.items, "test")) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: aggregate zig build test must not duplicate the workload partitions"));
    }
    return failures.toOwnedSlice(allocator);
}

pub const REFERENCE_ROOT_STEP =
    "      - name: Prove root reference capability transition\n" ++
    "        run: zig build test-real-snapshot-reference-launcher-root --summary all\n";

pub fn referenceLauncherRootWiringFailures(
    allocator: std.mem.Allocator,
    ci_raw: []const u8,
    build: []const u8,
    launcher: []const u8,
    root_test: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const ci = try rootlessRootHostedView(allocator, ci_raw);
    const jobs = try parseCiJobsMap(allocator, ci);
    const job = jobs.get("security-audit") orelse "";

    const step_hdr = "      - name: Prove root reference capability transition\n";
    var step_match: ?[]const u8 = null;
    {
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, job, pos, step_hdr)) |idx| {
            pos = idx + step_hdr.len;
            if (idx > 0 and job[idx - 1] != '\n') continue;
            var scan = pos;
            var end = job.len;
            while (scan < job.len) {
                const nl = std.mem.indexOfScalarPos(u8, job, scan, '\n') orelse job.len;
                const line = job[scan..nl];
                if (std.mem.startsWith(u8, line, "      - ") or line.len == 0) {
                    end = scan;
                    break;
                }
                scan = nl + 1;
            }
            step_match = job[idx..end];
            break;
        }
    }
    var has_bad_key = false;
    {
        var it = std.mem.splitScalar(u8, job, '\n');
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "    if:") or
                std.mem.startsWith(u8, line, "    continue-on-error:") or
                std.mem.startsWith(u8, line, "    strategy:"))
            {
                has_bad_key = true;
            }
        }
    }
    if (!lineInLines(job, "    name: Security and dependency policy") or
        !lineInLines(job, "    runs-on: ubuntu-24.04") or
        !lineInLines(job, "        run: zig build security-audit") or
        has_bad_key or
        std.mem.indexOf(u8, job, "continue-on-error:") != null or
        step_match == null or
        !std.mem.eql(u8, step_match.?, REFERENCE_ROOT_STEP) or
        countSubstring(ci, "test-real-snapshot-reference-launcher-root") != 1)
    {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: the security job must unconditionally prove the root reference capability transition"));
    }

    for ([_][]const u8{
        "const run_reference_launcher_tests = b.addRunArtifact(reference_launcher_tests);",
        "audit_step.dependOn(&run_reference_launcher_tests.step);",
        "b.path(\"tools/real-snapshot-reference-launcher-root-test.zig\")",
        "const run_reference_launcher_root_tests = b.addSystemCommand(&.{ \"sudo\", \"-n\", \"--\" });",
        "run_reference_launcher_root_tests.addArtifactArg(reference_launcher_root_tests);",
        "b.step(\"test-real-snapshot-reference-launcher-root\", ",
        ".dependOn(&run_reference_launcher_root_tests.step);",
    }) |token| {
        if (countSubstring(build, token) != 1) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: root reference capability step lost {s}", .{token}));
        }
    }
    if (std.mem.indexOf(u8, build, "audit_step.dependOn(&run_reference_launcher_root_tests.step)") != null) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: security-audit must not require passwordless sudo"));
    }
    for ([_][]const u8{
        "pub fn capabilityTransitionProbe() !void {",
        "if (linux.geteuid() != 0 or linux.getuid() != 0) linux.exit(14);",
        "if (linux.W.EXITSTATUS(status) == 14) return error.CapabilityProbeRequiresRoot;",
        "test \"reference capability transition fails closed without root authority\" {\n    try unprivilegedTransitionProbe();\n}",
        "if (restrictReferencePrivileges() != .PERM) linux.exit(4);",
    }) |token| {
        if (countSubstring(launcher, token) != 1) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "reference launcher: root capability refusal lost {s}", .{token}));
        }
    }
    var has_unshare_newuser = false;
    {
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, launcher, pos, ".unshare,")) |idx| {
            pos = idx + ".unshare,".len;
            var j = pos;
            while (j < launcher.len and isSpace(launcher[j])) : (j += 1) {}
            if (startsWithAt(launcher, j, "linux.CLONE.NEWUSER")) has_unshare_newuser = true;
        }
    }
    if (std.mem.indexOf(u8, launcher, "SkipZigTest") != null or
        countSubstring(launcher, "capabilityTransitionProbe(") != 1 or
        has_unshare_newuser)
    {
        try failures.append(
            allocator,
            try allocator.dupe(u8, "reference launcher: the capability transition must run only in the root step, never skip or use a user namespace"),
        );
    }

    const expected_root_test =
        "const launcher = @import(\"real-snapshot-reference-launcher.zig\");\n\n" ++
        "test \"reference capability transition clears ambient and high bounding privileges as root\" {\n" ++
        "    try launcher.capabilityTransitionProbe();\n}\n";
    var code_buf: std.ArrayList(u8) = .empty;
    var rt_it = std.mem.splitScalar(u8, root_test, '\n');
    var first = true;
    while (rt_it.next()) |line| {
        if (std.mem.startsWith(u8, line, "//!")) continue;
        if (!first) try code_buf.append(allocator, '\n');
        first = false;
        try code_buf.appendSlice(allocator, line);
    }
    const trimmed_code = try std.fmt.allocPrint(allocator, "{s}\n", .{std.mem.trim(u8, code_buf.items, " \t\r\n")});
    if (!std.mem.eql(u8, trimmed_code, expected_root_test)) {
        try failures.append(allocator, try allocator.dupe(u8, "reference launcher root test: must run the capability transition without conditions or skips"));
    }
    return failures.toOwnedSlice(allocator);
}

pub const PROTECTED_REFERENCE_PATHS = [_][]const u8{
    ".github/workflows/ci.yml",
    "build.zig",
    "tools/real-snapshot-reference-protected-ci.sh",
    "tools/real-snapshot-reference-protected-stage.sh",
    "tools/real-snapshot-reference-protected.zig",
    "tools/real-snapshot-reference-escape-probe.zig",
    "tools/real-snapshot-reference-launcher.zig",
    "tools/real-snapshot-reference-guest.zig",
    "tools/real-snapshot-reference-order.zig",
    "src/private_network.zig",
    "src/fixtures/script_network_probe.zig",
    "src/maintainer_script.zig",
    "tools/real-snapshot-protected-native-ci.sh",
    "tools/real-snapshot-acceptance.sh",
    "tools/real-snapshot-reference.sh",
    "tools/real-snapshot-reference-paths.zig",
    "tools/real-snapshot-native-outcome.zig",
    "tools/native-phase-summary.zig",
    "tools/real-snapshot-exec-audit.zig",
    "tools/native-database-performance-hosted.sh",
    "tools/real-snapshot-python3-protected-stage.sh",
    "tools/real-snapshot-python3-reference.sh",
    "tools/real-snapshot-signed-proc-bindings.sh",
    "tools/real-snapshot-signed-proc-prestates.sh",
    "src/native_unpack.zig",
    "src/native_alternatives.zig",
    "tools/real-snapshot-less-protected-stage.sh",
    "tools/real-snapshot-bash-protected-stage.sh",
    "tools/real-snapshot-less-reference.sh",
    "tools/real-snapshot-stage.zig",
    "tools/prepare-native-dpkg.zig",
};

pub const PROTECTED_REFERENCE_INPUT =
    "      run_protected_reference:\n" ++
    "        description: \"Stage root-owned inputs and run the protected pinned-dpkg reference proof on amd64 and arm64\"\n" ++
    "        required: true\n" ++
    "        type: boolean\n" ++
    "        default: false\n";

pub const PROTECTED_REFERENCE_HEADER =
    "  protected-reference:\n" ++
    "    if: github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.run_protected_reference)\n" ++
    "    name: Protected pinned-dpkg reference (${{ matrix.architecture }})\n" ++
    "    runs-on: ${{ matrix.runner }}\n" ++
    "    # Root-run staging: Zig download and package fetch 5, debz build 15,\n" ++
    "    # snapshot staging 15, preflight refusals 5 and the proof 45 (its own\n" ++
    "    # timeout), plus amd64 Python staging/replay 40 and Zig guards 10,\n" ++
    "    # leaving 5 for evidence, upload and cleanup.\n" ++
    "    timeout-minutes: 140\n" ++
    "    strategy:\n" ++
    "      fail-fast: false\n" ++
    "      matrix:\n" ++
    "        include:\n" ++
    "          - architecture: amd64\n" ++
    "            runner: ubuntu-24.04\n" ++
    "          - architecture: arm64\n" ++
    "            runner: ubuntu-24.04-arm\n" ++
    "    env:\n" ++
    "      ARCHITECTURE: ${{ matrix.architecture }}\n" ++
    "      PROTECTED_TREE: /srv/debz-protected/ci-${{ github.run_id }}-${{ github.run_attempt }}-${{ matrix.architecture }}\n" ++
    "    steps:\n" ++
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n" ++
    "        with:\n" ++
    "          persist-credentials: false\n";

pub const PROTECTED_REFERENCE_BOOTSTRAP =
    "      - name: Stage the reviewed commit in a root-owned tree and run the protected proof\n" ++
    "        timeout-minutes: 130\n" ++
    "        run: |\n" ++
    "          test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"\n" ++
    "          test -z \"$(git status --porcelain)\"\n" ++
    "          bundle=\"$RUNNER_TEMP/debz-protected-$ARCHITECTURE.bundle\"\n" ++
    "          git bundle create \"$bundle\" HEAD\n" ++
    "          sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n" ++
    "            GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \\\n" ++
    "            bash -euo pipefail -c '\n" ++
    "            tree=$1 architecture=$2 expected=$3 bundle=$4\n" ++
    "            [[ $tree =~ ^/srv/debz-protected/ci-[0-9]+-[0-9]+-(amd64|arm64)$ ]]\n" ++
    "            [[ ${BASH_REMATCH[1]} == \"$architecture\" && $expected =~ ^[0-9a-f]{40}$ ]]\n" ++
    "            umask 022\n" ++
    "            [[ -e /srv/debz-protected ]] || mkdir -m 0755 /srv/debz-protected\n" ++
    "            for ancestor in / /srv /srv/debz-protected; do\n" ++
    "              [[ -d $ancestor && ! -L $ancestor && $(stat -c %u:%g \"$ancestor\") == 0:0 ]]\n" ++
    "              (( ($(stat -c 0%a \"$ancestor\") & 022) == 0 ))\n" ++
    "            done\n" ++
    "            mkdir -m 0700 -- \"$tree\"\n" ++
    "            install -o root -g root -m 0600 -- \"$bundle\" \"$tree/debz.bundle\"\n" ++
    "            git init --quiet --bare \"$tree/bare.git\"\n" ++
    "            printf \"%s\\n\" \"$expected\" >\"$tree/bare.git/shallow\"\n" ++
    "            git --git-dir=\"$tree/bare.git\" bundle verify \"$tree/debz.bundle\"\n" ++
    "            git --git-dir=\"$tree/bare.git\" fetch --quiet \"$tree/debz.bundle\" HEAD:refs/heads/protected\n" ++
    "            test \"$(git --git-dir=\"$tree/bare.git\" rev-parse refs/heads/protected)\" = \"$expected\"\n" ++
    "            git --git-dir=\"$tree/bare.git\" symbolic-ref HEAD refs/heads/protected\n" ++
    "            git --git-dir=\"$tree/bare.git\" fsck --full --no-dangling\n" ++
    "            git clone --quiet --no-hardlinks \"file://$tree/bare.git\" \"$tree/checkout\"\n" ++
    "            test \"$(git -C \"$tree/checkout\" rev-parse HEAD)\" = \"$expected\"\n" ++
    "            exec bash \"$tree/checkout/tools/real-snapshot-reference-protected-ci.sh\" \"$tree\" \"$architecture\" \"$expected\"\n" ++
    "            ' protected-bootstrap \"$PROTECTED_TREE\" \"$ARCHITECTURE\" \"$GITHUB_SHA\" \"$bundle\"\n";

pub const PROTECTED_REFERENCE_COPY =
    "      - name: Copy bounded protected evidence\n" ++
    "        if: always()\n" ++
    "        run: |\n" ++
    "          output=\"$RUNNER_TEMP/protected-reference-$ARCHITECTURE\"\n" ++
    "          mkdir -p \"$output\"\n" ++
    "          sudo -n test -d \"$PROTECTED_TREE/upload\"\n" ++
    "          sudo -n tar -C \"$PROTECTED_TREE/upload\" -cf - . >\"$RUNNER_TEMP/protected-evidence.tar\"\n" ++
    "          tar --no-same-owner --no-same-permissions -C \"$output\" -xf \"$RUNNER_TEMP/protected-evidence.tar\"\n" ++
    "          test -s \"$output/result.txt\"\n" ++
    "          cat \"$output/result.txt\"\n";

pub const PROTECTED_REFERENCE_UPLOAD =
    "      - name: Upload protected reference evidence\n" ++
    "        if: always()\n" ++
    "        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2\n" ++
    "        with:\n" ++
    "          name: protected-reference-${{ matrix.architecture }}\n" ++
    "          path: ${{ runner.temp }}/protected-reference-${{ matrix.architecture }}/\n" ++
    "          if-no-files-found: error\n" ++
    "          retention-days: 14\n";

pub const PROTECTED_REFERENCE_CLEANUP =
    "      - name: Kill protected descendants and remove the named tree\n" ++
    "        if: always()\n" ++
    "        run: |\n" ++
    "          sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C bash -euo pipefail -c '\n" ++
    "            tree=$1\n" ++
    "            [[ $tree =~ ^/srv/debz-protected/ci-[0-9]+-[0-9]+-(amd64|arm64)$ ]]\n" ++
    "            [[ -e $tree || -L $tree ]] || exit 0\n" ++
    "            [[ -d $tree && ! -L $tree ]]\n" ++
    "            for attempt in 1 2 3 4 5; do\n" ++
    "              victims=()\n" ++
    "              for process in /proc/[0-9]*; do\n" ++
    "                root=$(readlink \"$process/root\" 2>/dev/null) || continue\n" ++
    "                cwd=$(readlink \"$process/cwd\" 2>/dev/null) || cwd=\n" ++
    "                case \"$root/ $cwd/\" in\n" ++
    "                  *\"$tree/\"*) victims+=(\"${process#/proc/}\") ;;\n" ++
    "                esac\n" ++
    "              done\n" ++
    "              (( ${#victims[@]} )) || break\n" ++
    "              echo \"killing protected descendants: ${victims[*]}\"\n" ++
    "              kill -KILL \"${victims[@]}\" 2>/dev/null || true\n" ++
    "              sleep 1\n" ++
    "            done\n" ++
    "            (( ${#victims[@]} == 0 ))\n" ++
    "            if grep -F \" $tree\" /proc/self/mountinfo; then\n" ++
    "              echo \"mounts remain beneath $tree\" >&2\n" ++
    "              exit 1\n" ++
    "            fi\n" ++
    "            rm -rf --one-file-system -- \"$tree\"\n" ++
    "            test ! -e \"$tree\"\n" ++
    "            ' protected-cleanup \"$PROTECTED_TREE\"\n";

pub const NATIVE_DATABASE_PAIR_INPUT_NAMES = [_][]const u8{
    "run_native_database_pairs",
    "native_database_comparison",
    "native_database_control_sha",
    "native_database_architectures",
    "native_database_modes",
    "native_database_series",
};

pub const NATIVE_DATABASE_PAIR_INPUTS =
    "      run_native_database_pairs:\n" ++
    "        description: \"Run matched native database-performance A/B pairs, one pair per disposable hosted runner\"\n" ++
    "        required: true\n" ++
    "        type: boolean\n" ++
    "        default: false\n" ++
    "      native_database_comparison:\n" ++
    "        description: \"Matched-pair comparison: capture (published control A, candidate B) or overhead (candidate off/on)\"\n" ++
    "        required: true\n" ++
    "        type: choice\n" ++
    "        default: capture\n" ++
    "        options: [capture, overhead]\n" ++
    "      native_database_control_sha:\n" ++
    "        description: \"Published measurement-only control commit for capture pairs (empty for overhead)\"\n" ++
    "        required: false\n" ++
    "        type: string\n" ++
    "        default: \"\"\n" ++
    "      native_database_architectures:\n" ++
    "        description: \"Matched-pair architectures (JSON list)\"\n" ++
    "        required: true\n" ++
    "        type: choice\n" ++
    "        default: '[\"amd64\",\"arm64\"]'\n" ++
    "        options:\n" ++
    "          - '[\"amd64\",\"arm64\"]'\n" ++
    "          - '[\"amd64\"]'\n" ++
    "          - '[\"arm64\"]'\n" ++
    "      native_database_modes:\n" ++
    "        description: \"Matched-pair build modes (JSON list)\"\n" ++
    "        required: true\n" ++
    "        type: choice\n" ++
    "        default: '[\"Debug\",\"ReleaseSafe\"]'\n" ++
    "        options:\n" ++
    "          - '[\"Debug\",\"ReleaseSafe\"]'\n" ++
    "          - '[\"Debug\"]'\n" ++
    "          - '[\"ReleaseSafe\"]'\n" ++
    "      native_database_series:\n" ++
    "        description: \"Reviewed interleaved sample-order series (JSON list)\"\n" ++
    "        required: true\n" ++
    "        type: choice\n" ++
    "        default: '[\"1-AB\",\"2-BA\",\"3-AB\"]'\n" ++
    "        options:\n" ++
    "          - '[\"1-AB\",\"2-BA\",\"3-AB\"]'\n" ++
    "          - '[\"1-AB\"]'\n" ++
    "          - '[\"2-BA\"]'\n" ++
    "          - '[\"3-AB\"]'\n";

pub const NATIVE_DATABASE_PAIR_JOB =
    "  native-database-pair:\n" ++
    "    if: github.event_name == 'workflow_dispatch' && inputs.run_native_database_pairs\n" ++
    "    name: Native database pair (${{ inputs.native_database_comparison }}, ${{ matrix.architecture }}, ${{ matrix.optimize }}, ${{ matrix.pair }})\n" ++
    "    runs-on: ${{ matrix.architecture == 'arm64' && 'ubuntu-24.04-arm' || 'ubuntu-24.04' }}\n" ++
    "    # Prerequisites, bundles and bootstrap 20, both protected slots 300, and\n" ++
    "    # evidence copy plus named-tree cleanup 20, leaving 20 for checkout,\n" ++
    "    # input validation and upload within the hosted six-hour job limit.\n" ++
    "    timeout-minutes: 360\n" ++
    "    strategy:\n" ++
    "      fail-fast: false\n" ++
    "      matrix:\n" ++
    "        architecture: ${{ fromJSON(inputs.native_database_architectures) }}\n" ++
    "        optimize: ${{ fromJSON(inputs.native_database_modes) }}\n" ++
    "        pair: ${{ fromJSON(inputs.native_database_series) }}\n" ++
    "    env:\n" ++
    "      ARCHITECTURE: ${{ matrix.architecture }}\n" ++
    "      OPTIMIZE: ${{ matrix.optimize }}\n" ++
    "      PAIR: ${{ matrix.pair }}\n" ++
    "      COMPARISON: ${{ inputs.native_database_comparison }}\n" ++
    "      CONTROL_INPUT: ${{ inputs.native_database_control_sha }}\n" ++
    "      ORCHESTRATOR: /srv/debz-protected/native-ci-${{ github.run_id }}-${{ github.run_attempt }}0-${{ matrix.architecture }}\n" ++
    "    steps:\n" ++
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n" ++
    "        with:\n" ++
    "          fetch-depth: 0\n" ++
    "          persist-credentials: false\n" ++
    "      - name: Validate matched-pair inputs\n" ++
    "        env:\n" ++
    "          SNAPSHOT_URI: ${{ inputs.ubuntu_snapshot_uri }}\n" ++
    "          SNAPSHOT_SUITE: ${{ inputs.ubuntu_snapshot_suite }}\n" ++
    "        run: |\n" ++
    "          set -euo pipefail\n" ++
    "          test \"$RUNNER_ENVIRONMENT\" = github-hosted\n" ++
    "          case \"$ARCHITECTURE/$RUNNER_ARCH\" in amd64/X64|arm64/ARM64) ;; *) exit 1 ;; esac\n" ++
    "          case \"$PAIR\" in 1-AB|2-BA|3-AB) ;; *) exit 1 ;; esac\n" ++
    "          bash tools/native-database-performance-hosted.sh --validate-values \\\n" ++
    "            \"$ARCHITECTURE\" \"$OPTIMIZE\" \"$COMPARISON\" \"${PAIR#*-}\" \"${PAIR%-*}\"\n" ++
    "          tools/real-snapshot-acceptance.sh --validate-values \\\n" ++
    "            \"$SNAPSHOT_URI\" \"$SNAPSHOT_SUITE\" \"$ARCHITECTURE\"\n" ++
    "          if [ \"$COMPARISON\" = capture ]; then\n" ++
    "            [[ $CONTROL_INPUT =~ ^[0-9a-f]{40}$ && $CONTROL_INPUT != \"$GITHUB_SHA\" ]]\n" ++
    "          else\n" ++
    "            [[ -z $CONTROL_INPUT || $CONTROL_INPUT == \"$GITHUB_SHA\" ]]\n" ++
    "          fi\n" ++
    "      - name: Install test runner prerequisites\n" ++
    "        timeout-minutes: 10\n" ++
    "        run: |\n" ++
    "          sudo -n apt-get update\n" ++
    "          sudo -n apt-get install --yes --no-install-recommends \\\n" ++
    "            dpkg jq liblzma-dev libzstd-dev strace\n" ++
    "      - name: Bundle exact candidate and published control histories\n" ++
    "        timeout-minutes: 5\n" ++
    "        run: |\n" ++
    "          set -euo pipefail\n" ++
    "          test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"\n" ++
    "          test -z \"$(git status --porcelain)\"\n" ++
    "          test ! -e \"$(git rev-parse --git-path shallow)\"\n" ++
    "          git bundle create \"$RUNNER_TEMP/native-database-candidate.bundle\" HEAD\n" ++
    "          if [ \"$COMPARISON\" = capture ]; then\n" ++
    "            control_git=\"$RUNNER_TEMP/native-database-control.git\"\n" ++
    "            git init --quiet --bare \"$control_git\"\n" ++
    "            git --git-dir=\"$control_git\" fetch --quiet --no-tags \"$PWD\" HEAD:refs/heads/candidate\n" ++
    "            git --git-dir=\"$control_git\" fetch --quiet --no-tags \\\n" ++
    "              \"$GITHUB_SERVER_URL/$GITHUB_REPOSITORY\" \"+$CONTROL_INPUT:refs/heads/control\"\n" ++
    "            test \"$(git --git-dir=\"$control_git\" rev-parse refs/heads/control)\" = \"$CONTROL_INPUT\"\n" ++
    "            test ! -e \"$control_git/shallow\"\n" ++
    "            git --git-dir=\"$control_git\" symbolic-ref HEAD refs/heads/control\n" ++
    "            git --git-dir=\"$control_git\" bundle create \"$RUNNER_TEMP/native-database-control.bundle\" HEAD\n" ++
    "          fi\n" ++
    "      - name: Stage protected orchestration checkout and pair bundles\n" ++
    "        timeout-minutes: 5\n" ++
    "        run: |\n" ++
    "          set -euo pipefail\n" ++
    "          control_bundle=\n" ++
    "          if [ \"$COMPARISON\" = capture ]; then\n" ++
    "            control_bundle=\"$RUNNER_TEMP/native-database-control.bundle\"\n" ++
    "          fi\n" ++
    "          sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n" ++
    "            GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \\\n" ++
    "            bash -euo pipefail -c '\n" ++
    "            tree=$1 architecture=$2 expected=$3 candidate_bundle=$4 control_bundle=$5\n" ++
    "            [[ $tree =~ ^/srv/debz-protected/native-ci-[0-9]+-[0-9]+0-(amd64|arm64)$ ]]\n" ++
    "            [[ ${BASH_REMATCH[1]} == \"$architecture\" && $expected =~ ^[0-9a-f]{40}$ ]]\n" ++
    "            umask 022\n" ++
    "            [[ -e /srv/debz-protected ]] || mkdir -m 0755 /srv/debz-protected\n" ++
    "            for ancestor in / /srv /srv/debz-protected; do\n" ++
    "              [[ -d $ancestor && ! -L $ancestor && $(stat -c %u:%g \"$ancestor\") == 0:0 ]]\n" ++
    "              (( ($(stat -c 0%a \"$ancestor\") & 022) == 0 ))\n" ++
    "            done\n" ++
    "            mkdir -m 0700 -- \"$tree\"\n" ++
    "            install -o root -g root -m 0600 -- \"$candidate_bundle\" \"$tree/candidate.bundle\"\n" ++
    "            if [[ -n $control_bundle ]]; then\n" ++
    "              install -o root -g root -m 0600 -- \"$control_bundle\" \"$tree/control.bundle\"\n" ++
    "            fi\n" ++
    "            git init --quiet --bare \"$tree/bare.git\"\n" ++
    "            git --git-dir=\"$tree/bare.git\" bundle verify \"$tree/candidate.bundle\"\n" ++
    "            git --git-dir=\"$tree/bare.git\" fetch --quiet \"$tree/candidate.bundle\" HEAD:refs/heads/protected\n" ++
    "            test \"$(git --git-dir=\"$tree/bare.git\" rev-parse refs/heads/protected)\" = \"$expected\"\n" ++
    "            git --git-dir=\"$tree/bare.git\" symbolic-ref HEAD refs/heads/protected\n" ++
    "            git --git-dir=\"$tree/bare.git\" fsck --full --no-dangling\n" ++
    "            git clone --quiet --no-hardlinks \"file://$tree/bare.git\" \"$tree/checkout\"\n" ++
    "            test \"$(git -C \"$tree/checkout\" rev-parse HEAD)\" = \"$expected\"\n" ++
    "            ' native-database-pair-bootstrap \"$ORCHESTRATOR\" \"$ARCHITECTURE\" \"$GITHUB_SHA\" \\\n" ++
    "            \"$RUNNER_TEMP/native-database-candidate.bundle\" \"$control_bundle\"\n" ++
    "      - name: Run one matched pair on this runner\n" ++
    "        id: pair\n" ++
    "        timeout-minutes: 300\n" ++
    "        env:\n" ++
    "          SNAPSHOT_URI: ${{ inputs.ubuntu_snapshot_uri }}\n" ++
    "          SNAPSHOT_SUITE: ${{ inputs.ubuntu_snapshot_suite }}\n" ++
    "        run: |\n" ++
    "          set -euo pipefail\n" ++
    "          control=\"$GITHUB_SHA\"\n" ++
    "          control_bundle=\"$ORCHESTRATOR/candidate.bundle\"\n" ++
    "          if [ \"$COMPARISON\" = capture ]; then\n" ++
    "            control=\"$CONTROL_INPUT\"\n" ++
    "            control_bundle=\"$ORCHESTRATOR/control.bundle\"\n" ++
    "          fi\n" ++
    "          sudo -n env -i -C \"$ORCHESTRATOR/checkout\" PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n" ++
    "            GITHUB_ACTIONS=\"$GITHUB_ACTIONS\" RUNNER_ENVIRONMENT=\"$RUNNER_ENVIRONMENT\" \\\n" ++
    "            GITHUB_SHA=\"$GITHUB_SHA\" GITHUB_RUN_ID=\"$GITHUB_RUN_ID\" \\\n" ++
    "            GITHUB_RUN_ATTEMPT=\"$GITHUB_RUN_ATTEMPT\" GITHUB_JOB=\"$GITHUB_JOB\" \\\n" ++
    "            GITHUB_WORKFLOW=\"$GITHUB_WORKFLOW\" RUNNER_NAME=\"$RUNNER_NAME\" \\\n" ++
    "            bash \"$ORCHESTRATOR/checkout/tools/native-database-performance-hosted.sh\" \\\n" ++
    "            \"$ORCHESTRATOR\" \"$ARCHITECTURE\" \"$OPTIMIZE\" \"$COMPARISON\" \"${PAIR#*-}\" \"${PAIR%-*}\" \\\n" ++
    "            \"$GITHUB_SHA\" \"$control\" \"$ORCHESTRATOR/candidate.bundle\" \"$control_bundle\" \\\n" ++
    "            \"$SNAPSHOT_URI\" \"$SNAPSHOT_SUITE\"\n" ++
    "      - name: Copy bounded paired evidence\n" ++
    "        if: always()\n" ++
    "        timeout-minutes: 10\n" ++
    "        env:\n" ++
    "          PAIR_OUTCOME: ${{ steps.pair.outcome }}\n" ++
    "        run: |\n" ++
    "          set -euo pipefail\n" ++
    "          case \"$PAIR\" in 1-AB|2-BA|3-AB) ;; *) exit 1 ;; esac\n" ++
    "          sample=${PAIR%-*}\n" ++
    "          bash tools/native-database-performance-hosted.sh --validate-values \\\n" ++
    "            \"$ARCHITECTURE\" \"$OPTIMIZE\" \"$COMPARISON\" \"${PAIR#*-}\" \"$sample\"\n" ++
    "          output=\"$PWD/.native-database-pair/evidence\"\n" ++
    "          mkdir -p \"$output\"\n" ++
    "          printf 'pair_step_outcome=%s\\n' \"$PAIR_OUTCOME\" >\"$output/pair-step.txt\"\n" ++
    "          df -Pk / >\"$output/runner-disk.txt\"\n" ++
    "          status=0\n" ++
    "          copy() {\n" ++
    "            local source=$1 destination=$2 limit=$3 bytes\n" ++
    "            read -r bytes _ < <(sudo -n du -sb \"$source\") &&\n" ++
    "              test \"$bytes\" -le \"$limit\" &&\n" ++
    "              mkdir -p \"$destination\" &&\n" ++
    "              sudo -n tar -C \"$source\" -cf - . >\"$RUNNER_TEMP/native-database-evidence.tar\" &&\n" ++
    "              tar --no-same-owner --no-same-permissions -C \"$destination\" -xf \"$RUNNER_TEMP/native-database-evidence.tar\"\n" ++
    "          }\n" ++
    "          pair=\"$ORCHESTRATOR/pair-$sample-$COMPARISON-$OPTIMIZE\"\n" ++
    "          if sudo -n test -d \"$pair\"; then\n" ++
    "            copy \"$pair\" \"$output/${pair##*/}\" $((256 * 1024 * 1024)) || status=1\n" ++
    "          else\n" ++
    "            printf 'pair_evidence=unavailable\\nreason=bootstrap-or-pair-validation-failed\\n' >\"$output/pair-collection-failure.txt\"\n" ++
    "          fi\n" ++
    "          for index in 1 2; do\n" ++
    "            slot=\"/srv/debz-protected/native-ci-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT}${sample}${index}-$ARCHITECTURE\"\n" ++
    "            letter=A\n" ++
    "            if [ \"$index\" = 2 ]; then letter=B; fi\n" ++
    "            record=\"$output/${pair##*/}/slot-$letter.txt\"\n" ++
    "            if [ -f \"$record\" ] && ! grep -Fxq \"tree=$slot\" \"$record\"; then\n" ++
    "              status=1\n" ++
    "            fi\n" ++
    "            mkdir -p \"$output/${slot##*/}\"\n" ++
    "            if sudo -n test -d \"$slot/native-upload\"; then\n" ++
    "              copy \"$slot/native-upload\" \"$output/${slot##*/}/native-upload\" $((512 * 1024 * 1024)) || status=1\n" ++
    "            elif sudo -n test -d \"$slot\"; then\n" ++
    "              printf 'native_evidence=unavailable\\nreason=slot-staging-or-export-failed\\n' >\"$output/${slot##*/}/collection-failure.txt\"\n" ++
    "              if sudo -n test -d \"$slot/upload\"; then\n" ++
    "                copy \"$slot/upload\" \"$output/${slot##*/}/staging\" $((512 * 1024 * 1024)) || status=1\n" ++
    "              fi\n" ++
    "            else\n" ++
    "              printf 'native_evidence=unavailable\\nreason=slot-tree-absent\\n' >\"$output/${slot##*/}/collection-failure.txt\"\n" ++
    "            fi\n" ++
    "          done\n" ++
    "          if [ -f \"$output/${pair##*/}/pair-result.txt\" ]; then\n" ++
    "            cat \"$output/${pair##*/}/pair-result.txt\" >>\"$GITHUB_STEP_SUMMARY\"\n" ++
    "          fi\n" ++
    "          exit \"$status\"\n" ++
    "      - name: Kill pair descendants and remove only the named trees\n" ++
    "        if: always()\n" ++
    "        timeout-minutes: 10\n" ++
    "        run: |\n" ++
    "          set -euo pipefail\n" ++
    "          output=\"$PWD/.native-database-pair/evidence\"\n" ++
    "          mkdir -p \"$output\"\n" ++
    "          case \"$PAIR\" in 1-AB|2-BA|3-AB) ;; *) exit 1 ;; esac\n" ++
    "          sample=${PAIR%-*}\n" ++
    "          status=0\n" ++
    "          for tree in \"$ORCHESTRATOR\" \\\n" ++
    "            \"/srv/debz-protected/native-ci-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT}${sample}1-$ARCHITECTURE\" \\\n" ++
    "            \"/srv/debz-protected/native-ci-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT}${sample}2-$ARCHITECTURE\"; do\n" ++
    "            sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C bash -euo pipefail -c '\n" ++
    "              tree=$1\n" ++
    "              [[ $tree =~ ^/srv/debz-protected/native-ci-[0-9]+-[0-9]+-(amd64|arm64)$ ]]\n" ++
    "              [[ -e $tree || -L $tree ]] || exit 0\n" ++
    "              [[ -d $tree && ! -L $tree && $(stat -c %u:%g \"$tree\") == 0:0 ]]\n" ++
    "              for attempt in 1 2 3 4 5; do\n" ++
    "                victims=()\n" ++
    "                for process in /proc/[0-9]*; do\n" ++
    "                  root=$(readlink \"$process/root\" 2>/dev/null) || continue\n" ++
    "                  cwd=$(readlink \"$process/cwd\" 2>/dev/null) || cwd=\n" ++
    "                  case \"$root/ $cwd/\" in\n" ++
    "                    *\"$tree/\"*) victims+=(\"${process#/proc/}\") ;;\n" ++
    "                  esac\n" ++
    "                done\n" ++
    "                (( ${#victims[@]} )) || break\n" ++
    "                echo \"killing named native descendants: ${victims[*]}\"\n" ++
    "                kill -KILL \"${victims[@]}\" 2>/dev/null || true\n" ++
    "                sleep 1\n" ++
    "              done\n" ++
    "              (( ${#victims[@]} == 0 ))\n" ++
    "              if grep -F \" $tree\" /proc/self/mountinfo; then\n" ++
    "                echo \"mounts remain beneath $tree\" >&2\n" ++
    "                exit 1\n" ++
    "              fi\n" ++
    "              rm -rf --one-file-system -- \"$tree\"\n" ++
    "              test ! -e \"$tree\"\n" ++
    "              ' native-database-pair-cleanup \"$tree\" >>\"$output/cleanup-result.txt\" 2>&1 || status=1\n" ++
    "          done\n" ++
    "          printf 'cleanup_status=%s\\n' \"$status\" >>\"$output/cleanup-result.txt\"\n" ++
    "          (\n" ++
    "            cd \"$output\"\n" ++
    "            find . -type f ! -name SHA256SUMS -print0 \\\n" ++
    "              | sort -z \\\n" ++
    "              | xargs -0 -r sha256sum >SHA256SUMS\n" ++
    "          )\n" ++
    "          exit \"$status\"\n" ++
    "      - name: Upload matched-pair evidence\n" ++
    "        if: always()\n" ++
    "        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2\n" ++
    "        with:\n" ++
    "          name: native-database-pair-${{ inputs.native_database_comparison }}-${{ matrix.architecture }}-${{ matrix.optimize }}-${{ matrix.pair }}\n" ++
    "          path: .native-database-pair/evidence/\n" ++
    "          if-no-files-found: error\n" ++
    "          retention-days: 14\n";

pub const PROTECTED_REFERENCE_SCRIPT_TOKENS = [_][]const u8{
    "set -euo pipefail",
    "if [[ ${1:-} == --check-keyring && $# == 2 ]]; then",
    "verify-keyring \"$2\" \"$archive_keyring_size\" \"$archive_keyring_sha256\"",
    "if [[ ${1:-} == --stage-native ]]; then",
    "  mode=native-staging\n",
    "[[ $mode == proof ]] || prefix=native-ci",
    "if [[ $mode == native-staging ]]; then\n  stage_native_inputs\n",
    "step native-outcome-build 0 \"\" \"${zenv[@]}\" \"$zig\" build build-native-outcome test-native-outcome \\\n" ++
        "    build-native-phase-summary test-native-phase-summary build-exec-audit test-exec-audit \\\n" ++
        "    -Doptimize=\"$native_optimize\" -j2",
    "native_optimize=ReleaseSafe\nif [[ $mode == native-staging ]]; then\n" ++
        "  native_optimize=${DEBZ_NATIVE_SNAPSHOT_OPTIMIZE:-ReleaseSafe}\n" ++
        "  [[ $native_optimize == Debug || $native_optimize == ReleaseSafe ]]",
    "\"$checkout/zig-out/bin/debz-native-dpkg-reference\" --architecture \"$architecture\" \\\n" ++
        "    --receipt-from-archive \"$tree/reference-dpkg.deb\" --prefix \"$tree/reference-dpkg\"",
    "step zig-library-check 0 \"\" \"$reference_paths\" toolchain \"$zig\"",
    "readonly zig_public_key=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U",
    "readonly archive_keyring_deb_url=https://snapshot.ubuntu.com/ubuntu/20261001T000000Z/pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1build1_all.deb",
    "readonly archive_keyring_deb_sha512=80446b4521a3cc100d797a7ed03532f4358c028f1c0c110e00cfc6e1db3b2795e2f98f92a4077baea0cee3c82b292f9eeb20f7f1dc06ce28b6b46e661b1fad35",
    "readonly archive_keyring_deb_size=11228",
    "readonly archive_keyring_member=./usr/share/keyrings/ubuntu-archive-keyring.gpg",
    "readonly archive_keyring_sha256=80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31",
    "readonly archive_keyring_size=3607",
    "    zig_sha256=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026\n    zig_size=57332648\n",
    "    zig_sha256=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8\n    zig_size=52877280\n",
    "[[ $tree =~ ^/srv/debz-protected/$prefix-[0-9]+-[0-9]+-(amd64|arm64)$ && ${BASH_REMATCH[1]} == \"$architecture\" &&",
    "[[ $(realpath -- \"${BASH_SOURCE[0]}\") == \"$checkout/tools/real-snapshot-reference-protected-ci.sh\" ]] || {",
    "test \"$(git -C \"$checkout\" rev-parse HEAD)\" = \"$commit\"",
    "trap collect EXIT",
    "download_zig_release()",
    "[[ $(stat -c '%u:%g:%a:%s:%h' \"$downloads/$zig_name.tar.xz\") == \"0:0:600:$zig_size:1\" ]]",
    "[[ $(sha256sum \"$downloads/$zig_name.tar.xz\") == \"$zig_sha256  $downloads/$zig_name.tar.xz\" ]]",
    "extract_zig_release()",
    "tar --no-same-owner --no-same-permissions -C \"$tree/zig\" -xf \"$downloads/$zig_name.tar.xz\"",
    "chmod -R go-w \"$tree/zig\"",
    "step zig-verify 0 \"\" \"$reference_paths\" verify-minisign --public-key \"$zig_public_key\" \\",
    "[[ ! -e zig-pkg && ! -L zig-pkg ]]",
    "chmod -R go-w zig-pkg \"$tree/zig-global\"",
    "step zig-pkg-verify 0 \"\" \"$reference_paths\" packages \\",
    "stage_verified_archive_keyring()",
    "printf 'path\\trole\\tuid:gid:mode:size\\talgorithm\\tdigest\\n'",
    "curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \\\n" ++
        "      --max-time 300 --user-agent debz-protected-reference/1 \\",
    "\"$reference_paths\" stage-keyring \\",
    "\"$package\" \"$archive_keyring_deb_sha512\" \"$archive_keyring_deb_size\" \\",
    "\"$archive_keyring_member\" \"$target\" \"$archive_keyring_sha256\" \\",
    "\"$archive_keyring_size\" \"$evidence/archive-keyring-path.tsv\"",
    "staged_archive_keyring=\nstage_verified_archive_keyring\nreadonly staged_archive_keyring",
    "step stage 0 \"\" \"${zenv[@]}\" \"DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring\"",
    "step tree-final 0 \"\" \"$reference_paths\" tree \"$tree\"",
    "mutable=$negatives/mutable-ancestor\n[[ ! -e \"$mutable\" && ! -L \"$mutable\" ]]\ninstall -d -o root -g root -m 0777 \"$mutable\"",
    "negative mutable-ancestor \"writable or non-root ancestor\" \\",
    "negative swapped-dpkg \"reference dpkg executable is not the pinned architecture artifact\" \\",
    "negative swapped-archive \"authenticated archive SHA512 differs\" \\",
    "negative wrong-architecture \"reference dpkg executable is not the pinned architecture artifact\" \\",
    "negative unbound-profile-scripts \"profile scripts\" \\",
    "step negative-reused-workspace refused \"must be new and empty\"",
    "step negative-swapped-keyring refused '\"summary\":\"WrongSigningKey\"' swapped_keyring_stage",
    "    echo \"negative-$name launched before refusing\" >&2",
    "step proof 0 \"executed without skips\" timeout --signal=TERM --kill-after=60s 45m \\",
    "\"${zenv[@]}\" \"$zig\" build test-real-snapshot-reference-protected \"${proof_arguments[@]}\" \\",
    "[[ ${#proof_arguments[@]} == 15 ]]",
};

pub const SourceTokenList = struct { path: []const u8, tokens: []const []const u8 };
pub const PROTECTED_REFERENCE_SOURCE_TOKENS = [_]SourceTokenList{
    .{
        .path = "tools/real-snapshot-bash-protected-stage.sh",
        .tokens = &.{
            "$(id -u) == 0 && $(id -g) == 0 && $(uname -m) == aarch64",
            "\"$workspace\" == \"$checkout/.real-snapshot/bash-arm64\"",
            "\"$checkout/zig-out/bin/debz-reference-paths\" toolchain \"$zig\" >/dev/null",
            "--check-keyring \"$DEBZ_REAL_SNAPSHOT_KEYRING\"",
            "bash tools/real-snapshot-reference-protected-stage.sh --arm64-bash-source",
            "zig-out/bin/debz-reference-stage prepare-bash",
            "zig-out/bin/debz-reference-stage seal-bash",
            "--force-depends --no-triggers --unpack /var/lib/dpkg/producer-libtinfo6.deb /var/lib/dpkg/producer-bash.deb",
            "--force-depends --no-triggers --configure bash",
            "'5.3-2ubuntu1 arm64 install ok installed'",
            "\"$zig\" build test-real-snapshot-arm64-bash-source-protected",
            "grep -Fx \"signed arm64 bash source guard executed without skips\"",
            "zig-out/bin/debz-reference-stage bash-mutate-negatives \"$workspace\"",
            "/var/lib/dpkg/producer-ldconfig -i -X -C /etc/ld.so.cache -f /dev/null /usr/lib/aarch64-linux-gnu",
            "zig-out/bin/debz-reference-stage prepare-util-linux",
            "zig-out/bin/debz-reference-stage seal-util-linux",
            "zig-out/bin/debz-reference-stage util-linux-mutate-negatives \"$util_workspace\"",
            "bytes <= 8 * 1024 * 1024 * 1024",
        },
    },
    .{
        .path = "tools/prepare-native-dpkg.zig",
        .tokens = &.{
            "            .exclusive = true,",
            "try self.root.publishFile(try absolute(path), bytes, .{",
            "            .overwrite = .fail_if_exists,",
            "try cleanupStaging(parent.root, self.allocator, stage, stage_entry);",
        },
    },
    .{
        .path = "tools/real-snapshot-less-protected-stage.sh",
        .tokens = &.{
            "$(id -u) == 0 && $(id -g) == 0 && $(uname -m) == aarch64",
            "\"$workspace\" == \"$checkout/.real-snapshot/less-arm64\"",
            "\"$checkout/zig-out/bin/debz-reference-paths\" toolchain \"$zig\" >/dev/null",
            "--check-keyring \"$DEBZ_REAL_SNAPSHOT_KEYRING\"",
            "bash tools/real-snapshot-reference-protected-stage.sh --arm64-less-source",
            "zig-out/bin/debz-reference-stage prepare",
            "\"$workspace/evidence/less.lock.json\" \"$workspace/evidence/dash.lock.json\" \"$workspace/evidence/util-linux.lock.json\"",
            "zig-out/bin/debz-reference-stage seal",
            "--force-depends --no-triggers --unpack /var/lib/dpkg/producer-less.deb",
            "bash tools/real-snapshot-less-reference.sh",
            "bytes <= 8 * 1024 * 1024 * 1024",
        },
    },
    .{
        .path = "tools/real-snapshot-less-reference.sh",
        .tokens = &.{
            "for file in \"$pinned\" \"$lock\" \"$less_lock\" \"$dash_lock\" \"$archive\" \"$zig\";",
            "for path in \"$pinned\" \"$source_root\" \"$lock\" \"$less_lock\" \"$dash_lock\" \"$archive\" \"$script_root\" \"$dpkg_root\";",
            "require_lock_artifact less 668-1build1 171138 \"$digest\" \"$less_lock\"",
            "\ncheck_source_inputs\n",
            "zig-out/bin/debz-reference-stage less-mutate-negatives \\\n  \"$bad_script\" \"$bad_mode\" \"$bad_tool\" \"$bad_alias\" \"$bad_prestate\"",
            "zig-out/bin/debz-reference-stage less-stage-dpkg \"$dpkg_root\" \"$pinned\" \"$archive\"",
            "zig-out/bin/debz-reference-stage less-stage-dpkg \"$post_dpkg\" \"$pinned\" \"$archive\"",
        },
    },
    .{
        .path = "tools/real-snapshot-stage.zig",
        .tokens = &.{
            "pub fn openParentDescriptor(root: []const u8, relative: []const u8) !ParentDescriptor {",
            "const parent_fd = try reference_paths.openBeneath(root_fd, parent, true);",
            "pub fn replaceContents(descriptor: i32, contents: []const u8) !void {",
            "_ = try regularMetadata(descriptor);\n    _ = try syscall(linux.ftruncate(descriptor, 0));",
            ".ACCMODE = .WRONLY,\n        .CREAT = true,\n        .EXCL = true,\n        .NOFOLLOW = true,\n        .CLOEXEC = true,",
            "pub fn mutateNegativeRoots(allocator: std.mem.Allocator, roots: []const []const u8, kind: []const u8) !void {",
            "try replaceSymlink(bad_alias, \"usr/lib/aarch64-linux-gnu/libtinfo.so.6\", \"libtinfo.so.6.6\", \"foreign-tinfo\");",
            "try createExclusive(bad_prestate, \"usr/bin/update-menus\", \"#!/bin/sh\\nexit 0\\n\", 0o755);",
            "\"/lib/aarch64-linux-gnu/libc.so.6\",\n        \"/bad/aarch64-linux-gnu/libc.so.6\",",
            "pub fn preparePythonEmpty(allocator: std.mem.Allocator, root: []const u8) !void {",
            "pub const maximum_capture_bytes: usize = 16 * 1024 * 1024;",
            "return error.PythonReferenceCaptureExceedsByteLimit;",
            "const content = try readRegular(allocator, root, pin.relative, 2048);",
            "return error.SignedPythonListPathSetChanged;",
            "(metadata.mode & linux.S.IFMT) == linux.S.IFCHR and metadata.rdev_major == 1 and metadata.rdev_minor == 3;",
            "try createExclusive(root, \"dev/null\", \"\", 0o600);",
            "try createExclusive(shadow, \"usr/sbin/update-alternatives\", \"shadow\\n\", 0o644);",
            "try stageDpkgReference(allocator, paths[0], paths[1], paths[2], \"var/lib/dpkg/python3-probe.deb\");",
            "const descriptor = try openRegularDescriptor(postinst, \"var/lib/dpkg/info/python3-minimal.postinst\");",
            "pub fn verifyLockArchive(",
            "if (origin_type != .string or !std.mem.eql(u8, origin_type.string, \"authenticated_repository\"))",
            "return error.SourceArchiveDiffersFromProductionAuthority;",
            "for (source_artifacts) |pin| {",
            "f3d538070be0217eec1c5e747f0b6ed05b08b22a006001dafac6c87747ab46e9055fb8bf1985aed2d4010f57d597108dbff22ed73f92959703fffa57ec84e0e8",
            "c4a44690b1541936c4c85956f8e5bef0c915ce05afe6618230b70f4906803f8710b314b9093b451787b995bcd7b25a3947f51c8efa03dbda16c7eac720f93c6e",
            "824a6a3f33837c16dedb4faff92bd15b0dbe82d27dd9b25403f87ec4572acc6332159a6374558185ca503e18de6f637d2a79e7db9fafaab3ccae4ac77427eee5",
            "865127bc2d7d9218e2a3482b7e0b5ae3649c31bcac82d0437a7231c798f56a1939f0f18fc664111a7c446eef6f9864176c040ad78b7aac1a6a3afe4d4b9cbeb7",
            "pub fn prepareSource(",
            "pub fn prepareUtilLinux(",
            "pub fn sealLess(allocator: std.mem.Allocator, root: []const u8) !void {",
            "const content = try readRegular(allocator, root, \"var/lib/dpkg/info/less.list\", 2048);",
            "return error.SignedLessOwnershipPathSetChanged;",
            "try createExclusive(root, \"var/lib/debz-lifecycle-scripts/less.preinst\", preinst, 0o755);",
            "try createExclusive(root, \"var/lib/debz-lifecycle-scripts/less.postinst\", script, 0o755);",
            "return error.SignedLessPostinstChanged;",
            "pub fn sealBash(allocator: std.mem.Allocator, root: []const u8) !void {",
            "return error.SignedBashOwnershipPathSetChanged;",
            "return error.SignedBashPostinstChanged;",
            "try createExclusive(root, \"var/lib/debz-lifecycle-scripts/bash.postinst\", script, 0o755);",
            "return error.SignedLdconfigCacheProducerChanged;",
            "pub fn sealUtilLinux(allocator: std.mem.Allocator, root: []const u8) !void {",
        },
    },
    .{
        .path = "tools/real-snapshot-protected-native-ci.sh",
        .tokens = &.{
            "export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root",
            "unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH ZIG_LIB_DIR",
            "\"$checkout/zig-out/bin/debz-reference-paths\" protected \"$tree/native-inputs.args\"",
            "\"$checkout/zig-out/bin/debz-reference-paths\" protected \"$tree/native-optimize.txt\"",
            "export DEBZ_NATIVE_SNAPSHOT_OPTIMIZE=${optimize[0]}",
            "\"$checkout/zig-out/bin/debz-native-outcome\"",
            "\"$checkout/zig-out/bin/debz-exec-audit\"",
            "[[ ${#inputs[@]} == 3 ]]",
            "export DEBZ_ZIG=${inputs[0]} REFERENCE_DPKG=${inputs[1]} DEBZ_REAL_SNAPSHOT_KEYRING=${inputs[2]}",
            "exec bash \"$checkout/tools/real-snapshot-acceptance.sh\" \"$checkout/zig-out/bin/debz\"",
            "exec bash tools/real-snapshot-reference.sh \"$REFERENCE_DPKG\"",
            "timeout --signal=TERM --kill-after=30s 5m zig-out/bin/debz-vendor-snapshot-tools capture",
            "if [[ -d \"$work/root/var/lib/dpkg/info\" ]]; then",
            "reference_snapshot_present=%s\\nnative_snapshot_present=%s",
            "PATH=/no-host-interpreters zig-out/bin/debz-native-outcome \"$evidence\" \"${NATIVE_STEP_OUTCOME:-unavailable}\" \\",
            ">\"$evidence/acceptance-outcome-v1.json\" || outcome_status=$?",
            "\"$checkout/zig-out/bin/debz-reference-paths\" capture-coordination \"$work/root\" \"$evidence\" \\",
            ">\"$evidence/native-coordination-capture.log\" 2>&1 || coordination_status=$?",
            "\"$checkout/zig-out/bin/debz-reference-paths\" export-evidence \"$evidence\" \"$upload\"",
            "(( capture_status == 0 && differential_status == 0 && forbidden_exec_status == 0 && outcome_status == 0 && copy_status == 0 && coordination_status == 0 ))",
        },
    },
    .{
        .path = "tools/real-snapshot-acceptance.sh",
        .tokens = &.{
            "readonly keyring=${DEBZ_REAL_SNAPSHOT_KEYRING:-}",
            "--check-keyring \"$keyring\" >/dev/null",
            "PATH=/no-host-interpreters zig-out/bin/debz-exec-audit \"$@\" || status=$?",
            "\"$repository_root/zig-out/bin/debz-reference-paths\" protected --directory \\\n  \"$repository_root\" \"$repository_root/.real-snapshot\"",
            "\"$debz\" \"$repository_root/zig-out/bin/debz-exec-audit\"",
            "\"$repository_root/zig-out/bin/debz-reference-paths\" \\",
            "local wrapper_status=$?",
            "printf '%s\\n' \"$wrapper_status\" >\"$evidence/native-wrapper-exit-status.txt\"",
            "printf '{\"stage\":\"%s\",\"command_exit_status\":null}\\n' \"$name\" >\"$evidence/native-stage-v1.json\"",
            "printf '{\"stage\":\"%s\",\"command_exit_status\":%s}\\n' \"$name\" \"$status\" >\"$evidence/native-stage-v1.json\"",
        },
    },
    .{
        .path = "tools/real-snapshot-exec-audit.zig",
        .tokens = &.{
            "const maximum_trace_bytes = 256 * 1024 * 1024;",
            "const maximum_status_bytes = 64 * 1024 * 1024;",
            "const fresh_divert_shapes = [_][]const []const u8{",
            "const lifecycle_divert_shapes = [_]LifecycleShape{",
            "fn openBeneathNoFollow(root_path: []const u8, relative: []const u8) OpenBeneathError!linux.fd_t {",
            "fn existsBeneath(allocator: std.mem.Allocator, root_path: []const u8, relative: []const u8) OpenBeneathError!bool {",
        },
    },
    .{
        .path = "tools/real-snapshot-native-outcome.zig",
        .tokens = &.{
            "const maximum_result_bytes = 128 * 1024 * 1024;",
            "if (depth > maximum_document_depth) return error.OutcomeDepthExceeded;",
            "document(root, allocator, \"native-stage-v1.json\", 4096)",
            "document(root, allocator, result_path, maximum_result_bytes)",
            "read(root, allocator, \"native-wrapper-exit-status.txt\", 32)",
            "if (outcome.wrapper_exit_status != 0 or !expected_refusal)",
            "outcome.command_exit_status orelse return error.UnrecordedCommandExit",
            "try root.root.pinRegularFile(try fs.Path.init(path))",
            "pin.observeStableAlloc(allocator, maximum)",
            "\"native_acceptance_evidence_{s}\"",
            ".collector_exit = 1",
        },
    },
    .{
        .path = "tools/real-snapshot-python3-protected-stage.sh",
        .tokens = &.{
            "$(id -u) == 0 && $(id -g) == 0 && $(uname -m) == x86_64",
            "\"$workspace\" == \"$checkout/.real-snapshot/python3-amd64\"",
            "\"$checkout/zig-out/bin/debz-reference-paths\" toolchain \"$zig\" >/dev/null",
            "--check-keyring \"$DEBZ_REAL_SNAPSHOT_KEYRING\"",
            "bash tools/real-snapshot-signed-proc-bindings.sh \"$debz\" \"$workspace\"",
            "bash tools/real-snapshot-signed-proc-prestates.sh --python3 \"$pinned\" \"$workspace\"",
            "fixture empty \"$before\"",
            "fixture mode \"$before_0644\" 0644",
            "fixture capture \"$workspace\" \"evidence/replay-$mode.txt\" \"evidence/replay-$mode.stderr\"",
            "fixture basic \"$workspace/bad-html\" \"$workspace/bad-link\" \"$workspace/bad-shadow\"",
            "\"$checkout/zig-out/bin/debz-reference-stage\" create-exclusive-stdin \\\n    \"$workspace\" \"evidence/python3-reference.args\" 0600 16384",
            "for mode in 0600 0644; do",
            "bash tools/real-snapshot-python3-reference.sh \"$pinned\" \"$input\" \"$lock\" \"$archive\"",
            "\"-Dpython3-reference-root-py3compile=$after-py3compile-before\"",
            "\"-Dpython3-reference-after-py3compile=$after-py3compile-after\"",
            "\"-Dpython3-reference-bad-minimal-compiler=$after-py3compile-bad-compiler\"",
            "\"-Dpython3-reference-inputs-proof=$evidence/inputs-proof.txt\"",
            "\"-Dpython3-reference-alternatives-proof=$evidence/alternatives-proof.txt\"",
            "bytes <= 16 * 1024 * 1024 * 1024",
        },
    },
    .{
        .path = "tools/real-snapshot-python3-reference.sh",
        .tokens = &.{
            "unset ZIG_LIB_DIR",
            "--zig-lib-dir \"$(dirname -- \"$zig\")/lib\"",
            "fixture preflight \"$source_root\"",
            "\"$zig\" build test-real-snapshot-python3-source-protected",
            "\"-Dpython3-source-root=$source_root\" \"-Dpython3-source-proof=$source_proof\"",
            "grep -Fx \"signed Python source guard executed before fixture mutation\" \"$source_proof\"",
            "fixture dpkg \"$dpkg_root\" \"$pinned\" \"$archive\"",
            "fixture dpkg \"$py3compile_dpkg\" \"$pinned\" \"$archive\"",
            "fixture mode \"$py3compile_before\" 0644",
            "fixture strict \"$py3compile_bad_hash\" \"$py3compile_bad_mode\"",
            "require_protected_file \"$source_root/dev/null\"",
            "0:0:600:0:1",
            "0:0:644:0:1",
            "0:0:644:20:1",
            "[[ $(stat -c '%u:%g:%a:%s:%h' \"$py3compile_after/dev/null\") == 0:0:644:96:1 ]]",
            "e212fd644ebc9508a5494c1d69e26c62e23b5695d797588603dd870af154751e",
            "[[ $(sha256sum \"$py3compile_after/dev/null\" | cut -d' ' -f1) == \\\n" ++
                "  3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc ]]",
        },
    },
    .{
        .path = "tools/real-snapshot-signed-proc-prestates.sh",
        .tokens = &.{
            "if [[ ${1:-} == --python3 ]]; then",
            "require_protected_file \"$snapshot/evidence/refresh.json\"",
            "--slurpfile refreshed \"$snapshot/evidence/refresh.json\"",
            "([$frozen.witnesses[].repository_id] | sort) ==",
            ".repository.snapshot_digest == (\"sha256:\" + $repository.snapshot_sha256)",
            ".repository.release_digest == (\"sha256:\" + $repository.release_sha256)",
            "--zig-lib-dir \"$(dirname -- \"$zig\")/lib\"",
            "build-reference-runtime build-reference-order",
            "require_protected_file \"$tools/runtime-tool/bin/debz-reference-order\"",
            "--prestate \"python3:amd64=unpacked:$prestates/python3\"",
            "protected Python pre-configure source captured; no full reference completion claimed",
            "actual_record=$(LC_ALL=C sort -- \"$prestates/prestates.tsv\")",
            "[[ $actual_record == \"$expected_record\" ]]",
            "signed prestate record differs from exact requested selectors/statuses/destinations",
            "readonly setpriv_sha256=86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993",
            "  require_control \"$target\" \"usr/bin/setpriv:47576:755:$setpriv_sha256\"",
            "list=$prestates/sudo/var/lib/dpkg/info/sudo.list",
            "var/lib/dpkg/info/sudo.list:2376:644:39fe94bdbeab0a80b3aaeae4cfa258be578949b791aeb06875ddf9d488387bc8",
        },
    },
    .{
        .path = "src/native_unpack.zig",
        .tokens = &.{
            "std.c.getenv(\"DEBZ_REQUIRE_SIGNED_PYTHON3_INPUTS_PROOF\")",
            "signed Python empty0600/0644 and amd64 20/96 input/output guards executed without skips",
        },
    },
    .{
        .path = "src/native_alternatives.zig",
        .tokens = &.{
            "std.c.getenv(\"DEBZ_REQUIRE_SIGNED_PYTHON3_ALTERNATIVES_PROOF\")",
            "signed Python alternatives records and selectors executed without skips",
        },
    },
    .{
        .path = "tools/real-snapshot-reference-launcher.zig",
        .tokens = &.{
            "const reference_namespaces = linux.CLONE.NEWNS | linux.CLONE.NEWPID | linux.CLONE.NEWNET;",
            "const clone_result = linux.clone2(\n        reference_namespaces | @intFromEnum(linux.SIG.CHLD)",
            "const network_ready = private_network.setupLoopback();",
            "if (network_ready != .SUCCESS) fail(status, 15, network_ready);",
            "if (failure[0] == 15) return error.ReferenceNetworkSetupFailed;",
            "if (linux.errno(result) != .SUCCESS) return error.ReferenceNamespaceUnavailable;",
            "if (private_network.setupLoopback() != .PERM) linux.exit(16);",
            "if ((options.verb == .break_kbd_cycle) != (options.kbd_archives != null))",
            "!std.mem.eql(u8, options.selector.?, \"kbd:amd64\")",
            "for (paths, kbd_cycle) |path, binding| {",
            "if (child.options.verb == .break_kbd_cycle)\n        verifyCycle(.kbd)",
            ".kbd => .{ \"kbd\", \"kbd:amd64\" },",
            ".break_kbd_cycle => &.{ common[0], common[1], common[2], common[3], common[4], \"--no-triggers\", \"--force-depends\", \"--configure\", \"kbd:amd64\", null },",
            "if ((options.verb == .triggers_only) != (options.trigger_archive != null))",
            "const binding = triggerBindingFor(selector) orelse return error.InvalidTriggerHandler;",
            "if (child.options.verb == .triggers_only)\n        verifyTriggerHandler(child.options.selector.?)",
            ".triggers_only => &.{ common[0], common[1], common[2], common[3], common[4], \"--no-triggers\", \"--triggers-only\", selector, null },",
        },
    },
    .{
        .path = "tools/real-snapshot-reference-order.zig",
        .tokens = &.{
            "pub fn verifyBaseCycle(",
            "pub fn breakBaseCycle(",
            "pub fn verifyOpensslCycle(",
            "pub fn configureOpensslCycle(",
            "pub fn verifyKbdCycle(",
            "pub fn breakKbdCycle(",
            "pub fn verifyTriggerHandlers(",
            "pub fn processTriggers(",
            "pub fn stagePendingRuntime(",
            "pub fn launcherCommand(",
            "fn execBreakBaseCycle(",
            "fn execConfigureOpensslCycle(",
            "fn execBreakKbdCycle(",
            "fn execProcessTriggers(",
            "fn proveBaseCycle(",
            "fn capturePrestate(",
            "fn install(",
            "pub fn scheduleConserved(",
            "var lines = std.mem.splitAny(u8, data, \"\\r\\n\");",
        },
    },
    .{
        .path = "src/private_network.zig",
        .tokens = &.{
            "pub fn setupLoopback() linux.E {",
            "request.ifru.flags.UP = true;",
            "if (applied != .SUCCESS) return applied;",
            "if (!request.ifru.flags.UP or !request.ifru.flags.LOOPBACK) return .NODEV;",
        },
    },
    .{
        .path = "src/maintainer_script.zig",
        .tokens = &.{"return @import(\"private_network.zig\").setupLoopback();"},
    },
    .{
        .path = "tools/real-snapshot-reference.sh",
        .tokens = &.{
            "unset ZIG_LIB_DIR",
            "zig=${DEBZ_ZIG:-$(command -v zig || true)}",
            "\"$repository_root/zig-out/bin/debz-reference-paths\" toolchain \"$zig\" >/dev/null",
            "\"$zig\" build-exe -O ReleaseSafe -lc --dep private_network",
            "-Mroot=tools/real-snapshot-reference-launcher.zig -Mprivate_network=src/private_network.zig",
            "--zig-lib-dir \"$(dirname -- \"$zig\")/lib\"",
            "\"$zig\" build build-reference-runtime build-reference-order -Doptimize=ReleaseSafe",
            "\"$workspace/runtime-tool/bin/debz-reference-order\" \\\n  --report-only --architecture \"$architecture\"",
        },
    },
    .{
        .path = "tools/real-snapshot-reference-paths.zig",
        .tokens = &.{
            "pub fn openProtected(path: []const u8, directory: bool) !i32 {",
            "pub fn verifyKeyring(path: []const u8, size: usize, expected_digest: []const u8) ![64]u8 {",
            "if (meta.size != size or observed != size or !std.mem.eql(u8, &actual_hex, expected_digest))",
            "pub fn toolchain(allocator: std.mem.Allocator, path: []const u8) ![]u8 {",
            "if (!isWithinPath(target, library)) return error.ToolchainSymlinkEscapes;",
            "pub fn verifyMinisign(",
            "try ed25519Verify(key, &prehash_digest, file_sig);",
            "try ed25519Verify(key, global_message, global_signature);",
            "pub fn stageArchiveKeyring(",
            "const debian_binary = parseArMember(deb_bytes, \"debian-binary\") catch |err| {",
            "const data_archive = parseArMember(deb_bytes, \"data.tar.zst\") catch |err| {",
            "const data_tar = zstdDecompressBounded(allocator, data_archive, keyring_decompressed_limit) catch |err| {",
            "const keyring = extractTarMember(data_tar, member, expected_keyring_size) catch |err| {",
            "requireRootOwnedKeyringFile(allocator, evidence_path, \"downloaded-package\", deb_path, package_stat, 0o600) catch |err| {",
            "try requireRootOwnedKeyringFile(allocator, evidence_path, \"staged-keyring\", target, target_stat, 0o644);",
            "pub fn treeFailures(allocator: std.mem.Allocator, output: *std.ArrayList(u8), tree: []const u8) ![][]u8 {",
            "pub fn packageFailures(",
            "\"protected tree must be mode 0700: {s}\",",
            "\"group/other-writable entry: {s}\",",
            "((entry.meta.mode & linux.S.IFMT) != linux.S.IFLNK and (entry.meta.mode & (writable_mask | special_mask)) != 0))",
            "pub fn captureCoordination(allocator: std.mem.Allocator, root: []const u8, evidence: []const u8) !void {",
            "try openBeneathOptional(rfd, \"var/lib/debz\", true)",
            "if ((before.mode & linux.S.IFMT) != linux.S.IFREG or before.nlink != 1 or before.size > 128 * 1024 * 1024)",
            "if (coordination_bytes > 512 * 1024 * 1024) return error.CoordinationEvidenceExceedsLimit;",
            "pub fn exportEvidence(allocator: std.mem.Allocator, source: []const u8, target: []const u8) !void {",
            "if ((entry.meta.mode & linux.S.IFMT) != linux.S.IFREG or entry.meta.size > 128 * 1024 * 1024) {",
            "if (total > 512 * 1024 * 1024) {",
        },
    },
    .{
        .path = "build.zig",
        .tokens = &.{
            "b.step(\"test-real-snapshot-python3-source-protected\",",
            "run_python3_source_tests.has_side_effects = true;",
            "run_python3_source_tests.setEnvironmentVariable(\"DEBZ_REQUIRE_SIGNED_PYTHON3_SOURCE_ROOT\", b.option([]const u8, \"python3-source-root\", \"Required protected Python source\") orelse \"\");",
            "run_python3_source_tests.setEnvironmentVariable(\"DEBZ_REQUIRE_SIGNED_PYTHON3_SOURCE_PROOF\", b.option([]const u8, \"python3-source-proof\", \"Exclusive pre-mutation Python source proof\") orelse \"\");",
            "b.step(\"test-real-snapshot-python3-protected\",",
            "run_python3_reference_tests.has_side_effects = true;",
            "run_python3_alternatives_tests.has_side_effects = true;",
            "python3_reference_step.dependOn(&run_python3_reference_tests.step);",
            "python3_reference_step.dependOn(&run_python3_alternatives_tests.step);",
            "\"native_unpack.test.protected signed python3 inputs and redirected tool witness are exact\"",
            "\"native_alternatives.test.protected signed python3 preinst preserves all records and selectors\"",
            "for (python3_coordinates, &python3_values)",
            "for (python3_coordinates, python3_values)",
            "\"Required protected Python proof coordinate\") orelse \"\"",
            "b.fmt(\"DEBZ_REQUIRE_SIGNED_PYTHON3_{s}\", .{coordinate.environment}),\n            value.*,",
            "        \"--profile-scripts\",\n        b.option([]const u8, \"reference-protected-profile-scripts\", ",
            "b.step(\"test-real-snapshot-reference-protected\", ",
        },
    },
    .{
        .path = "tools/real-snapshot-reference-protected-stage.sh",
        .tokens = &.{
            "  packages=(less dash util-linux)",
            "if [[ $purpose == arm64-bash ]]; then packages=(bash dash util-linux libc-bin init-system-helpers perl-base less); fi",
            "  for package in \"${packages[@]}\"; do",
            "    authenticated_lock \"$package_lock\"",
            "\"$native_reference\" --architecture \"$architecture\" \\\n" ++
                "  --receipt-from-archive \"$workspace/build/dpkg.deb\" --prefix \"$dpkg_prefix\"",
            "require_protected_file \"$native_reference\"",
            "--architecture \"$architecture\" --verify-only \"$dpkg_prefix/usr/bin/dpkg\"",
            "  for profile in systemd udev sudo; do\n",
            "  printf -- '-Dreference-protected-profile-scripts=%s\\n' \"$profiles\"\n",
            "staging path is not root-owned and protected: $current (uid:gid:mode=$metadata; expected 0:0 with no group/world write bits)",
            "staging file is not root-owned and protected: $1 (uid:gid:mode=$metadata; expected 0:0 with no group/world write bits)",
        },
    },
    .{
        .path = "tools/real-snapshot-reference-protected.zig",
        .tokens = &.{
            "pub fn openNetworkControl(",
            "if (control.exit_code != 0 or !std.mem.eql(u8, control.stdout, expected)) {",
            "else if (std.mem.eql(u8, flag, \"--profile-scripts\")) {",
            "var scripts = try profileScripts(allocator, args.profile_scripts, args.architecture);",
            "const profiles = try proveProfiles(allocator, args, &scripts);",
            ".{ .profile = \"systemd\", .checks = &.{ \"proc-read-only\", \"proc-sys-masked\", \"proc-boot-id\" } },",
            ".{ .profile = \"udev\", .checks = &.{\"proc-pid-only\"} },",
            ".{ .profile = \"sudo\", .checks = &.{\"proc-pid-only\"} },",
            "if (!std.mem.eql(u8, boot_detail.get(\"boot_id\") orelse \"\", host_boot_id)) {",
            "try requireRefusal(res.status, res.stderr, neg.expected);",
        },
    },
    .{
        .path = "tools/real-snapshot-reference-escape-probe.zig",
        .tokens = &.{
            "try network_probe.observe(",
            "report(\"private-network\", false, \"error={s}\"",
            "if (confined) {\n        networkControl(profile) catch |err|",
            "const pid_one_root = statIdentity(\"/proc/1/root\", 0);",
            "report(\"proc-root\", same_root, ",
            "report(\"proc-boot-id\", ",
            "report(\"proc-pid-only\", ",
            "report(\"proc-sys-masked\", ",
            "\"subset=pid\"",
        },
    },
};

fn hasUnflaggedSudo(text: []const u8) bool {
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, "sudo ")) |idx| {
        pos = idx + 5;
        if (!isWordBoundary(text, idx)) continue;
        if (!startsWithAt(text, pos, "-n ")) return true;
    }
    return false;
}

fn partitionAfterAndBefore(text: []const u8, after_marker: []const u8, before_marker: []const u8) []const u8 {
    const idx = std.mem.indexOf(u8, text, after_marker) orelse return "";
    const tail = text[idx + after_marker.len ..];
    const end = std.mem.indexOf(u8, tail, before_marker) orelse return tail;
    return tail[0..end];
}

pub fn nativeDatabasePairCiFailures(allocator: std.mem.Allocator, ci: []const u8) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const dispatch = extractDispatchInputsBlock(ci);
    var inputs_ok = dispatch != null and dispatchInputExact(dispatch.?, NATIVE_DATABASE_PAIR_INPUTS);
    if (inputs_ok) {
        for (NATIVE_DATABASE_PAIR_INPUT_NAMES) |name| {
            const exact_line = try std.fmt.allocPrint(allocator, "      {s}:", .{name});
            const key_suf = try std.fmt.allocPrint(allocator, "{s}:", .{name});
            const c = countTrimmedKeyLines(ci, exact_line, key_suf);
            if (c.total_key_lines != 1 or c.exact_matches != 1) inputs_ok = false;
        }
    }
    if (!inputs_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: the native database pair inputs must remain exact dispatch-only selectors"));
    }

    const sections = try parseCiJobSections(allocator, ci);
    var ndp_cnt: usize = 0;
    var job: []const u8 = "";
    for (sections) |sec| {
        if (std.mem.eql(u8, sec.name, "native-database-pair")) {
            ndp_cnt += 1;
            job = sec.body;
        }
    }
    const last_three_ok = sections.len >= 3 and
        std.mem.eql(u8, sections[sections.len - 3].name, "ubuntu-real-snapshot") and
        std.mem.eql(u8, sections[sections.len - 2].name, "native-database-pair") and
        std.mem.eql(u8, sections[sections.len - 1].name, "protected-reference");
    if (ndp_cnt != 1 or !last_three_ok) {
        try failures.append(
            allocator,
            try allocator.dupe(u8, "ci.yml: the native database pair job must sit between the native snapshot and protected reference jobs"),
        );
    }

    const trimmed_job = std.mem.trimEnd(u8, job, "\n");
    const full_job = try std.fmt.allocPrint(allocator, "  native-database-pair:\n{s}\n", .{trimmed_job});
    if (!std.mem.eql(u8, full_job, NATIVE_DATABASE_PAIR_JOB)) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: the native database pair job must keep its exact hosted matched-pair wiring"));
    }

    var ro_cnt: usize = 0;
    var ro_ok = false;
    {
        var it = std.mem.splitScalar(u8, job, '\n');
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "    runs-on:")) {
                ro_cnt += 1;
                if (std.mem.eql(u8, line, "    runs-on: ${{ matrix.architecture == 'arm64' && 'ubuntu-24.04-arm' || 'ubuntu-24.04' }}")) {
                    ro_ok = true;
                }
            }
        }
    }
    if (std.mem.indexOf(u8, job, "self-hosted") != null or
        std.mem.indexOf(u8, job, "continue-on-error") != null or
        std.mem.indexOf(u8, job, "cataggar/ghr") != null or
        std.mem.indexOf(u8, job, "chown") != null or
        hasUnflaggedSudo(job) or
        ro_cnt != 1 or !ro_ok)
    {
        try failures.append(
            allocator,
            try allocator.dupe(
                u8,
                "ci.yml: the native database pair job must stay GitHub-hosted without hidden failures," ++
                    " unprotected tools or ownership transfer",
            ),
        );
    }

    var driver_ok = countSubstring(ci, "native-database-performance-hosted.sh") == countSubstring(job, "native-database-performance-hosted.sh");
    for (NATIVE_DATABASE_PAIR_INPUT_NAMES) |name| {
        const ref = try std.fmt.allocPrint(allocator, "inputs.{s}", .{name});
        if (countSubstring(ci, ref) != countSubstring(job, ref)) driver_ok = false;
    }
    if (!driver_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: the native database pair driver and inputs must be used only by the matched-pair job"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn protectedReferenceCiFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const python_alternatives = partitionAfterAndBefore(
        texts.get("src/native_alternatives.zig") orelse "",
        "test \"native_alternatives.test.protected signed python3 preinst preserves all records and selectors\" {",
        "\ntest \"",
    );
    for ([_][]const u8{
        "\"DEBZ_REQUIRE_SIGNED_PYTHON3_PREINST_ROOT_0644\", \"DEBZ_REQUIRE_SIGNED_PYTHON3_PREINST_AFTER_0644\"",
        "try testing.expect(listed.names.len != 0);",
        "try testing.expectEqualDeep(listed.names, listed_after.names);",
        "try validateScriptTransition(testing.allocator, before, same, script, authority);",
        "try validateScriptTransition(testing.allocator, after, after_same, script, authority);",
        "try testing.expectEqualDeep(old_group.record, new_group.record);",
        "try testing.expectEqualDeep(old_group.links, new_group.links);",
        "try testing.expectEqualDeep(old_group.missing_master_targets, new_group.missing_master_targets);",
        "try testing.expectEqual(old_group.facts.len, new_group.facts.len);",
        "try testing.expect(testClonedEntryFactEqual(left, right));",
        "try testing.expectEqualSlices(u8, old_record, new_record);",
        "errdefer std.debug.print(",
        "protected Python alternatives: coordinate={s} phase={s} group={s} error={s}",
    }) |token| {
        if (std.mem.indexOf(u8, python_alternatives, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected Python alternatives must preserve complete inventories in both modes: {s}", .{token}));
        }
    }

    const PathCount = struct { path: []const u8, count: usize };
    for ([_]PathCount{
        .{ .path = "tools/real-snapshot-less-protected-stage.sh", .count = 1 },
        .{ .path = "tools/real-snapshot-less-reference.sh", .count = 3 },
        .{ .path = "tools/real-snapshot-bash-protected-stage.sh", .count = 5 },
    }) |pc| {
        const p_text = texts.get(pc.path) orelse "";
        const start_tok = "timeout --signal=TERM --kill-after=5s 120s \\\n";
        const end_tok = "\n  '\n";
        var cmds: std.ArrayList([]const u8) = .empty;
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, p_text, pos, start_tok)) |s_idx| {
            const e_idx = std.mem.indexOfPos(u8, p_text, s_idx + start_tok.len, end_tok) orelse break;
            const end_pos = e_idx + end_tok.len;
            try cmds.append(allocator, p_text[s_idx..end_pos]);
            pos = end_pos;
        }
        var ok = cmds.items.len == pc.count;
        for (cmds.items) |cmd| {
            const env_idx = std.mem.indexOf(u8, cmd, "/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C");
            const chroot_idx = std.mem.indexOf(u8, cmd, "chroot ");
            if (env_idx == null or chroot_idx == null or env_idx.? > chroot_idx.? or
                std.mem.indexOf(u8, cmd[chroot_idx.? + "chroot ".len ..], "env -i") != null or
                std.mem.indexOf(u8, cmd, "--bounding-set=-sys_admin --no-new-privs") == null)
            {
                ok = false;
            }
        }
        if (!ok) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected less environment must be sanitized before chroot without guest env: {s}", .{pc.path}));
        }
    }

    const arm_ci = texts.get("tools/real-snapshot-reference-protected-ci.sh") orelse "";
    const arm_body = partitionAfterAndBefore(
        arm_ci,
        "elif [[ $architecture == arm64 ]]; then\n  less_workspace=",
        "\n# The protected proof on the staged new empty workspace",
    );
    for ([_][]const u8{
        "$checkout/.real-snapshot/less-arm64",
        "step arm64-less-stage 0 \"fifteen replay roots staged\" timeout --signal=TERM --kill-after=60s 30m",
        "bash tools/real-snapshot-less-protected-stage.sh \"$zig\" \"$checkout/zig-out/bin/debz\" \"$less_workspace\"",
        "step arm64-less-guards 0 \"\" timeout --signal=TERM --kill-after=60s 10m",
        "\"$zig\" build test-real-snapshot-arm64-less-protected",
        "\"-Darm64-less-reference-bad-prestate=$less_workspace/script-after-bad-prestate\"",
        "\"$less_workspace/evidence/less-source-proof.txt\"",
        "\"$less_workspace/evidence/less-replay-proof.txt\"",
        "step arm64-less-postinst 0 \"\" timeout --signal=TERM --kill-after=60s 10m",
        "\"$zig\" build test-real-snapshot-arm64-less-postinst-protected",
        "\"-Darm64-less-postinst-bad-prestate=$less_workspace/script-after-postinst-bad-prestate\"",
        "\"$less_workspace/evidence/less-postinst-proof.txt\"",
        "grep -Fx \"signed arm64 less native postinst and independent pinned dpkg agree without skips\"",
        "grep -F \" $less_workspace\" /proc/self/mountinfo",
        "rm -rf --one-file-system -- \"$less_workspace\"",
        "$checkout/.real-snapshot/bash-arm64",
        "step arm64-bash-stage 0 \"nine replay roots staged\" timeout --signal=TERM --kill-after=60s 30m",
        "step arm64-bash-postinst 0 \"\" timeout --signal=TERM --kill-after=60s 10m",
        "\"$zig\" build test-real-snapshot-arm64-bash-postinst-protected",
        "\"-Darm64-bash-postinst-dpkg-root=$bash_workspace/dpkg-after\"",
        "\"-Darm64-bash-postinst-bad-prestate=$bash_workspace/bad-prestate\"",
        "\"-Darm64-bash-postinst-bad-cache=$bash_workspace/bad-cache\"",
        "grep -Fx \"signed arm64 bash native postinst and independent pinned dpkg agree without skips\"",
        "step arm64-util-linux-postinst 0 \"\" timeout --signal=TERM --kill-after=60s 10m",
        "\"$zig\" build test-real-snapshot-arm64-util-linux-postinst-protected",
        "\"-Darm64-util-linux-postinst-dpkg-root=$bash_workspace/util-linux/dpkg-after\"",
        "\"-Darm64-util-linux-postinst-bad-prestate=$bash_workspace/util-linux/bad-prestate\"",
        "\"-Darm64-util-linux-postinst-bad-cache=$bash_workspace/util-linux/bad-cache\"",
        "grep -Fx \"signed arm64 util-linux native postinst and independent pinned dpkg agree without skips\"",
        "grep -F \" $bash_workspace\" /proc/self/mountinfo",
        "rm -rf --one-file-system -- \"$bash_workspace\"",
    }) |token| {
        if (std.mem.indexOf(u8, arm_body, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected arm64 less activation lost {s}", .{token}));
        }
    }
    if (std.mem.indexOf(u8, arm_body, "|| true") != null or std.mem.indexOf(u8, arm_body, "SkipZigTest") != null) {
        try failures.append(allocator, try allocator.dupe(u8, "protected arm64 less activation must not skip or swallow errors"));
    }

    const arm_build = texts.get("build.zig") orelse "";
    for ([_][]const u8{
        "b.step(\"test-real-snapshot-arm64-less-protected\",",
        "run_arm64_less_tests.has_side_effects = true;",
        "\"Required protected ARM less proof coordinate\") orelse \"\"",
        "setEnvironmentVariable(\"DEBZ_REQUIRE_SIGNED_ARM64_LESS_SOURCE_ROOT\", value)",
        "b.step(\"test-real-snapshot-arm64-less-postinst-protected\",",
        "run_arm64_less_postinst_tests.has_side_effects = true;",
        "DEBZ_REQUIRE_SIGNED_ARM64_LESS_POSTINST_{s}",
        "b.step(\"test-real-snapshot-arm64-bash-source-protected\",",
        "run_arm64_bash_source_tests.has_side_effects = true;",
        "b.step(\"test-real-snapshot-arm64-bash-postinst-protected\",",
        "run_arm64_bash_postinst_tests.has_side_effects = true;",
        "DEBZ_REQUIRE_SIGNED_ARM64_BASH_POSTINST_{s}",
        "b.step(\"test-real-snapshot-arm64-util-linux-postinst-protected\",",
        "run_arm64_util_linux_postinst_tests.has_side_effects = true;",
        "DEBZ_REQUIRE_SIGNED_ARM64_UTIL_LINUX_POSTINST_{s}",
    }) |token| {
        if (std.mem.indexOf(u8, arm_build, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected arm64 less build lost {s}", .{token}));
        }
    }

    const unpack = texts.get("src/native_unpack.zig") orelse "";
    const TestCheck = struct { name: []const u8, calls: []const []const u8 };
    for ([_]TestCheck{
        .{
            .name = "source is validated before fixture mutation",
            .calls = &.{
                "try verifySnapshotLessArm64Inputs(testing.allocator, root.root, &artifacts, \"arm64\", .preinst);",
                "try verifySnapshotLessArm64Inputs(testing.allocator, root.root, &artifacts, \"arm64\", .postinst);",
                "DEBZ_REQUIRE_SIGNED_ARM64_LESS_SOURCE_PROOF",
            },
        },
        .{
            .name = "inert input and replay roots are exact",
            .calls = &.{
                "prepareAlternativesScriptBoundary(",
                "try testing.expectEqualDeep(before.record, after.record);",
                "try testing.expectError(error.InvalidAlternativesScriptAuthority, verifySnapshotLessArm64Inputs(",
                "DEBZ_REQUIRE_SIGNED_ARM64_LESS_REPLAY_PROOF",
            },
        },
        .{
            .name = "postinst runs natively and matches pinned dpkg",
            .calls = &.{
                "maintainer_script.SystemLauncher",
                "maintainer_script.run(testing.allocator,",
                "try testing.expect(report.succeeded());",
                ".policy = lifecycleInvocationPolicy(false, false, false)",
                "try verifySnapshotLessArm64Inputs(testing.allocator, native.root, &artifacts, \"arm64\", .postinst);",
                "native_alternatives.validateScriptInputs(",
                "native_alternatives.validateScriptTransition(",
                "try testing.expectEqualDeep(actual.record, expected.record);",
                "try testing.expectEqualStrings(\"/usr/bin/less\", actual.selected);",
                "DEBZ_REQUIRE_SIGNED_ARM64_LESS_POSTINST_BAD_PRESTATE_ROOT",
                "DEBZ_REQUIRE_SIGNED_ARM64_LESS_POSTINST_PROOF",
            },
        },
    }) |tc| {
        const hdr = try std.fmt.allocPrint(allocator, "test \"native_unpack.test.protected signed arm64 less {s}\" {{", .{tc.name});
        const body = partitionAfterAndBefore(unpack, hdr, "\n}\n");
        for (tc.calls) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected arm64 less test body lost {s}", .{token}));
            }
        }
        for ([_][]const u8{ ".exclusive = true", "try proof.writeStreamingAll(" }) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected arm64 less test body lost {s}", .{token}));
            }
        }
    }

    for ([_]TestCheck{
        .{
            .name = "source is validated before fixture mutation",
            .calls = &.{
                "try verifySnapshotBashArm64Inputs(testing.allocator, root.root, &artifacts, \"arm64\");",
                "DEBZ_REQUIRE_SIGNED_ARM64_BASH_SOURCE_PROOF",
            },
        },
        .{
            .name = "postinst runs natively and matches pinned dpkg",
            .calls = &.{
                "maintainer_script.SystemLauncher",
                "maintainer_script.run(testing.allocator,",
                "try testing.expect(report.succeeded());",
                ".policy = lifecycleInvocationPolicy(false, false, false)",
                "try verifySnapshotBashArm64Inputs(testing.allocator, native.root, &artifacts, \"arm64\");",
                "native_alternatives.validateScriptInputs(",
                "native_alternatives.validateScriptTransition(",
                "try testing.expectEqualDeep(actual.record, expected.record);",
                "try testing.expectEqualStrings(\"/usr/share/man/man7/bash-builtins.7.gz\", actual.selected);",
                "try testing.expectEqualDeep(actual.links, expected.links);",
                "try testing.expectEqualDeep(actual.missing_master_targets, expected.missing_master_targets);",
                "try expectAlternativesReplayFactEqual(actual.record_fact, expected.record_fact);",
                "try expectAlternativesReplayFactEqual(left, right);",
                "DEBZ_REQUIRE_SIGNED_ARM64_BASH_POSTINST_BAD_PRESTATE_ROOT",
                "DEBZ_REQUIRE_SIGNED_ARM64_BASH_POSTINST_BAD_CACHE_ROOT",
                "DEBZ_REQUIRE_SIGNED_ARM64_BASH_POSTINST_PROOF",
            },
        },
    }) |tc| {
        const hdr = try std.fmt.allocPrint(allocator, "test \"native_unpack.test.protected signed arm64 bash {s}\" {{", .{tc.name});
        const body = partitionAfterAndBefore(unpack, hdr, "\n}\n");
        for (tc.calls) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected arm64 bash test body lost {s}", .{token}));
            }
        }
        for ([_][]const u8{ ".exclusive = true", "try proof.writeStreamingAll(" }) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected arm64 bash test body lost {s}", .{token}));
            }
        }
    }

    for ([_][]const u8{
        "if (snapshot_bash_postinst and std.mem.eql(u8, architecture, \"arm64\")) {",
        "bash_cache_fact = try verifySnapshotBashArm64Inputs(allocator, root, program.artifacts, program.target_architecture);",
        "native_alternatives.matchesSnapshotBashPostinst(script_bytes))\n" ++
            "            _ = verifySnapshotBashArm64Inputs(",
        "try verifySnapshotBashArm64CacheInput(allocator, root);",
        "targets[script.immutable_targets.len] = \"/etc/ld.so.cache\";",
        "if (!std.meta.eql(observed, expected_cache)) return error.AlternativesInputChanged;",
        "if (snapshot_util_linux_postinst and std.mem.eql(u8, architecture, \"arm64\")) {",
        "bash_cache_fact = try verifySnapshotUtilLinuxArm64Inputs(allocator, root, program.artifacts, program.target_architecture);",
        "native_alternatives.matchesSnapshotUtilLinuxPostinst(script_bytes))\n" ++
            "            _ = verifySnapshotUtilLinuxArm64Inputs(",
        "try verifySnapshotUtilLinuxArm64CacheInput(allocator, root);",
        "verifySnapshotUtilLinuxArm64PostOutput(\n                        allocator,\n                        root,\n                        alternatives_after.?,",
    }) |token| {
        if (std.mem.indexOf(u8, unpack, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected arm64 bash production input revalidation lost {s}", .{token}));
        }
    }

    const util_postinst_body = partitionAfterAndBefore(
        unpack,
        "test \"native_unpack.test.protected signed arm64 util-linux postinst runs natively and matches pinned dpkg\" {",
        "\n}\n",
    );
    for ([_][]const u8{
        "maintainer_script.SystemLauncher",
        "maintainer_script.run(testing.allocator,",
        "try testing.expect(report.succeeded());",
        ".policy = lifecycleInvocationPolicy(false, false, false)",
        "try verifySnapshotUtilLinuxArm64Inputs(testing.allocator, native.root, &artifacts, \"arm64\");",
        "try verifySnapshotUtilLinuxArm64PostOutput(testing.allocator, native.root, after);",
        "try verifySnapshotUtilLinuxArm64PostOutput(testing.allocator, reference.root, oracle);",
        "native_alternatives.validateScriptInputs(",
        "native_alternatives.validateScriptTransition(",
        "try testing.expectEqualDeep(actual.record, expected.record);",
        "try testing.expectEqualStrings(\"/usr/bin/less\", actual.selected);",
        "try testing.expectEqualDeep(actual.links, expected.links);",
        "try testing.expectEqualDeep(actual.missing_master_targets, expected.missing_master_targets);",
        "try expectAlternativesReplayFactEqual(actual.record_fact, expected.record_fact);",
        "try expectAlternativesReplayFactEqual(left, right);",
        "DEBZ_REQUIRE_SIGNED_ARM64_UTIL_LINUX_POSTINST_BAD_PRESTATE_ROOT",
        "DEBZ_REQUIRE_SIGNED_ARM64_UTIL_LINUX_POSTINST_BAD_CACHE_ROOT",
        "DEBZ_REQUIRE_SIGNED_ARM64_UTIL_LINUX_POSTINST_PROOF",
        ".exclusive = true",
        "try proof.writeStreamingAll(",
    }) |token| {
        if (std.mem.indexOf(u8, util_postinst_body, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected arm64 util-linux test body lost {s}", .{token}));
        }
    }

    const bash_stage = texts.get("tools/real-snapshot-bash-protected-stage.sh") orelse "";
    const source_guard = std.mem.indexOf(u8, bash_stage, "\"$zig\" build test-real-snapshot-arm64-bash-source-protected");
    const copies = std.mem.indexOf(u8, bash_stage, "for name in native dpkg-after bad-script");
    if (source_guard == null or copies == null or source_guard.? > copies.?) {
        try failures.append(allocator, try allocator.dupe(u8, "protected bash source guard must execute before copies/mutations"));
    }
    const util_source_guard = std.mem.indexOf(u8, bash_stage, "\"$zig\" build test-real-snapshot-arm64-util-linux-source-protected");
    if (util_source_guard == null or copies == null or util_source_guard.? > copies.?) {
        try failures.append(allocator, try allocator.dupe(u8, "protected ARM util-linux original source guard must execute before copies/mutations"));
    }

    for ([_]SourceTokenList{
        .{
            .path = "tools/real-snapshot-stage.zig",
            .tokens = &.{
                ".name = \"util-linux\",\n        .version = \"2.41.3-3ubuntu2.2\",\n        .declared_size = 1055344,\n        .sha512 = \"adfe77778337bbf3d72b60d2c1f0089821b561876c792104bbe62a8429120d7cdbc665d537993954e2a0312a996a06d3259f7ebcb080b7ad18c64805fdbbdfad\",",
                "try copyExclusive(allocator, root, \"var/lib/dpkg/producer-util-linux.deb\", util_linux_deb, 0o644);",
                "try copyExclusive(allocator, root, \"var/lib/dpkg/producer-util-linux.lock.json\", util_linux_lock_path, 0o644);",
            },
        },
        .{
            .path = "tools/real-snapshot-bash-protected-stage.sh",
            .tokens = &.{
                "\"-Darm64-util-linux-source-root=$source\"",
                "\"-Darm64-util-linux-source-postinst=$workspace/evidence/util-linux-original-native.postinst\"",
                "\"-Darm64-util-linux-source-proof=$workspace/evidence/util-linux-source-proof.txt\"",
                "grep -Fx \"signed arm64 util-linux original archive source validated without callback admission or skips\"",
                "/usr/bin/dpkg-deb --ctrl-tarfile \"$source/var/lib/dpkg/producer-util-linux.deb\"",
                "cmp \"$workspace/evidence/util-linux-original-native.postinst\" \"$workspace/evidence/util-linux-original-dpkg.postinst\"",
            },
        },
        .{
            .path = "build.zig",
            .tokens = &.{
                "b.step(\"test-real-snapshot-arm64-util-linux-source-protected\",",
                "run_arm64_util_linux_source_tests.has_side_effects = true;",
                "DEBZ_REQUIRE_SIGNED_ARM64_UTIL_LINUX_SOURCE_{s}",
            },
        },
        .{
            .path = "src/native_unpack.zig",
            .tokens = &.{
                "lock.archiveAuthentication(package) != .signed_sha512",
                "lock.findRepository(origin.repository_id) orelse",
                "var model = try snapshotUtilLinuxArm64SourceModel(testing.allocator, lock.lock, observation.bytes);",
                "try exact_lock_v3.decode(testing.allocator, lock_observation.bytes, exact_lock_v3.maximum_document_bytes)",
                "try postinst.writeStreamingAll(testing.io, model.scriptBytes(model.script(.postinst).?.*));",
                "DEBZ_REQUIRE_SIGNED_ARM64_UTIL_LINUX_SOURCE_PROOF",
            },
        },
    }) |stl| {
        const p_txt = texts.get(stl.path) orelse "";
        for (stl.tokens) |token| {
            if (std.mem.indexOf(u8, p_txt, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected ARM util-linux original source binding lost {s}", .{token}));
            }
        }
    }

    const less_reference = texts.get("tools/real-snapshot-less-reference.sh") orelse "";
    for ([_][]const u8{
        "zig-out/bin/debz-reference-stage less-mutate-negatives --kind postinst",
        "--force-depends --no-triggers --configure less",
        "'668-1build1 arm64 install ok installed'",
    }) |token| {
        if (std.mem.indexOf(u8, less_reference, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected arm64 less independent configure lost {s}", .{token}));
        }
    }

    const python_body = partitionAfterAndBefore(
        arm_ci,
        "if [[ $architecture == amd64 ]]; then\n  python3_workspace=",
        "\n# The protected proof on the staged new empty workspace",
    );
    for ([_][]const u8{
        "$checkout/.real-snapshot/python3-amd64",
        "step python3-stage 0 \"all 18 root coordinates staged\" timeout --signal=TERM --kill-after=60s 40m",
        "\"DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring\"",
        "bash tools/real-snapshot-python3-protected-stage.sh \"$zig\" \"$checkout/zig-out/bin/debz\"",
        "[[ ${#python3_arguments[@]} == 20 ]]",
        "step python3-guards 0 \"\" timeout --signal=TERM --kill-after=60s 10m",
        "\"$zig\" build test-real-snapshot-python3-protected \"${python3_arguments[@]}\"",
        "-Doptimize=ReleaseSafe -j2 --summary all",
        "\"$python3_workspace/evidence/inputs-proof.txt\"",
        "\"$python3_workspace/evidence/alternatives-proof.txt\"",
        "grep -F \" $python3_workspace\" /proc/self/mountinfo",
        "rm -rf --one-file-system -- \"$python3_workspace\"",
    }) |token| {
        if (std.mem.indexOf(u8, python_body, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected amd64 Python activation lost {s}", .{token}));
        }
    }
    if (std.mem.indexOf(u8, python_body, "|| true") != null or
        std.mem.indexOf(u8, python_body, "SkipZigTest") != null or
        std.mem.indexOf(u8, python_body, "test-integration-arm64") != null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "protected Python activation must not skip, swallow errors or activate ARM397"));
    }

    const PyTestCheck = struct { path: []const u8, name: []const u8, tokens: []const []const u8 };
    for ([_]PyTestCheck{
        .{
            .path = "src/native_unpack.zig",
            .name = "native_unpack.test.protected signed python3 source is validated before fixture mutation",
            .tokens = &.{
                "try verifySnapshotPython3PreinstInputs(testing.allocator, root.root, &program);",
                "std.c.getenv(\"DEBZ_REQUIRE_SIGNED_PYTHON3_SOURCE_PROOF\")",
                ".exclusive = true",
                "try proof.writeStreamingAll(",
            },
        },
        .{
            .path = "src/native_unpack.zig",
            .name = "native_unpack.test.protected signed python3 inputs and redirected tool witness are exact",
            .tokens = &.{
                "try verifySnapshotPython3PreinstInputs(testing.allocator, before.root, &program);",
                "try verifySnapshotPython3PreinstInputs(testing.allocator, before_0644.root, &program);",
                "try verifySnapshotPython3PreinstInputs(testing.allocator, before_py3compile.root, &program);",
                "try verifySnapshotPython3NullOutput(testing.allocator, after.root);",
                "try verifySnapshotPython3NullOutput(testing.allocator, after_0644.root);",
                "try verifySnapshotPython3NullOutput(testing.allocator, after_py3compile.root);",
                "error.DirectoryTooLarge",
                "std.c.getenv(\"DEBZ_REQUIRE_SIGNED_PYTHON3_INPUTS_PROOF\")",
                ".exclusive = true",
                "try proof.writeStreamingAll(",
            },
        },
        .{
            .path = "src/native_alternatives.zig",
            .name = "native_alternatives.test.protected signed python3 preinst preserves all records and selectors",
            .tokens = &.{
                "try validateScriptInputs(",
                "try validateScriptTransition(",
                "try testing.expectEqualSlices(u8, old_record, new_record);",
                "std.c.getenv(\"DEBZ_REQUIRE_SIGNED_PYTHON3_ALTERNATIVES_PROOF\")",
                ".exclusive = true",
                "try proof.writeStreamingAll(",
            },
        },
    }) |ptc| {
        const hdr = try std.fmt.allocPrint(allocator, "test \"{s}\" {{", .{ptc.name});
        const body = partitionAfterAndBefore(texts.get(ptc.path) orelse "", hdr, "\ntest \"");
        for (ptc.tokens) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: protected Python test body lost {s}", .{ ptc.path, token }));
            }
        }
    }

    const python_reference = texts.get("tools/real-snapshot-python3-reference.sh") orelse "";
    const guard = "grep -Fx \"signed Python source guard executed before fixture mutation\" \"$source_proof\"";
    const g_idx = std.mem.indexOf(u8, python_reference, guard);
    const cp_idx = std.mem.indexOf(u8, python_reference, "cp -a --reflink=auto");
    if (g_idx == null or cp_idx == null or g_idx.? > cp_idx.?) {
        try failures.append(allocator, try allocator.dupe(u8, "protected Python source guard must execute before copies/mutations"));
    }

    const fixtures = texts.get("tools/real-snapshot-stage.zig") orelse "";
    if (std.mem.indexOf(u8, fixtures, ".TRUNC = true") != null) {
        try failures.append(allocator, try allocator.dupe(u8, "shared reference mutations must inspect the descriptor before truncation"));
    }
    for ([_][]const u8{ "sealLess", "preparePythonEmpty" }) |fn_name| {
        const hdr = try std.fmt.allocPrint(allocator, "pub fn {s}(", .{fn_name});
        const body = partitionAfterAndBefore(fixtures, hdr, "\npub fn ");
        var has_forbidden_call = body.len == 0;
        for ([_][]const u8{
            "sorted",
            "sort",
            "overwrite_regular",
            "overwriteRegular",
            "replace_contents",
            "replaceContents",
            "ftruncate",
            "writeAllFd",
            "write",
            "write_bytes",
            "write_text",
        }) |call_name| {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, body, pos, call_name)) |idx| {
                pos = idx + call_name.len;
                if (!isWordBoundary(body, idx)) continue;
                var j = pos;
                while (j < body.len and isSpace(body[j])) : (j += 1) {}
                if (j < body.len and body[j] == '(') has_forbidden_call = true;
            }
        }
        if (has_forbidden_call) {
            try failures.append(allocator, try allocator.dupe(u8, "tools/real-snapshot-stage.zig: fixture lists must retain authenticated original bytes without rewriting"));
        }
    }

    const sudo_list = partitionAfterAndBefore(
        texts.get("tools/real-snapshot-signed-proc-prestates.sh") orelse "",
        "list=$prestates/sudo/var/lib/dpkg/info/sudo.list\n",
        "# The pre-sudo record",
    );
    var sudo_bad = sudo_list.len == 0 or std.mem.indexOfScalar(u8, sudo_list, '>') != null;
    for ([_][]const u8{ "sort", "chmod", "mv", "cp", "install", "tee", "dd" }) |w| {
        if (countWordOccurrences(sudo_list, w) > 0) sudo_bad = true;
    }
    if (sudo_bad) {
        try failures.append(allocator, try allocator.dupe(u8, "signed sudo fixture list must retain authenticated original bytes without rewriting"));
    }

    const binding_list = partitionAfterAndBefore(
        texts.get("tools/real-snapshot-signed-proc-bindings.sh") orelse "",
        "awk -F'\\t' '$1 == \"sudo\" { print \"/\" $2 }' \"$listing\" | sed 's#^/$#/.#'",
        "\ncopy_input()",
    );
    if (binding_list.len == 0 or
        countWordOccurrences(binding_list, "sort") > 0 or
        std.mem.indexOf(u8, binding_list, ">\"$source_root/var/lib/dpkg/info/sudo.list\"") == null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "signed sudo binding list must retain authenticated archive member order"));
    }

    const reference = texts.get("tools/prepare-native-dpkg.zig") orelse "";
    const producer = partitionAfterAndBefore(reference, "pub fn receiptFromArchive(", "\n    fn fixture(");
    for ([_][]const u8{
        "try fs.openAbsoluteRoot(self.io, prefix)",
        "try self.read(archive, maximum_bytes, true)",
        "if (!std.mem.eql(u8, &hash(raw), self.expected.archive))",
        "try self.read(path, maximum_bytes, true)",
        "if (!std.mem.eql(u8, &hash(bytes), toolDigest(self.expected, tool)))",
        "try self.archiveMetadata(archive)",
        "try self.writeReceipt(prefix, raw.len)",
        "self.allocator.free(try self.verifyReceipt(receipt))",
    }) |token| {
        if (std.mem.indexOf(u8, producer, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected extracted reference receipt producer lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "self.root.pinRegularFile(try absolute(path))",
        "pin.observeAlloc(self.allocator, maximum)",
        "observed.entry.link_count != 1",
        "observed.entry.uid != std.os.linux.geteuid()",
        "observed.entry.gid != std.os.linux.getegid()",
        "observed.entry.mode & 0o022 != 0",
        "cleanupStaging(parent.root, self.allocator, stage, stage_entry)",
    }) |token| {
        if (std.mem.indexOf(u8, reference, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native pinned-dpkg reference lost {s}", .{token}));
        }
    }
    if (texts.contains("tools/prepare-native-dpkg.py")) {
        try failures.append(allocator, try allocator.dupe(u8, "retired Python pinned-dpkg preparation helper remains"));
    }

    const ci = texts.get(".github/workflows/ci.yml") orelse "";
    const jobs = try parseCiJobsMap(allocator, ci);
    for (try nativeDatabasePairCiFailures(allocator, ci)) |msg| try failures.append(allocator, msg);

    const native_job = jobs.get("ubuntu-real-snapshot") orelse "";
    for ([_][]const u8{
        "    if: github.event_name == 'workflow_dispatch' && inputs.run_native_real_snapshot\n",
        "    timeout-minutes: 320\n",
        "      max-parallel: 1\n",
        "          - architecture: amd64\n            runner: ubuntu-24.04\n",
        "          - architecture: arm64\n            runner: ubuntu-24.04-arm\n",
        "      PROTECTED_TREE: /srv/debz-protected/native-ci-${{ github.run_id }}-${{ github.run_attempt }}-${{ matrix.architecture }}\n",
        "          test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"\n          test -z \"$(git status --porcelain)\"\n",
        "          sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n" ++
            "            GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \\\n",
        "            mkdir -m 0700 -- \"$tree\"\n",
        "            git --git-dir=\"$tree/bare.git\" fsck --full --no-dangling\n",
        "            test \"$(git -C \"$tree/checkout\" rev-parse HEAD)\" = \"$expected\"\n",
        "            exec bash \"$tree/checkout/tools/real-snapshot-reference-protected-ci.sh\" --stage-native \"$tree\" \"$architecture\" \"$expected\"\n",
        "      - name: Create and replay exact native Ubuntu root\n        id: native\n        timeout-minutes: 220\n",
        "            native \"$PROTECTED_TREE\" \"$ARCHITECTURE\" \"$GITHUB_SHA\" \"$SNAPSHOT_URI\" \"$SNAPSHOT_SUITE\"\n",
        "      - name: Install exact closure with pinned dpkg reference\n        timeout-minutes: 50\n        run: |\n",
        "            reference \"$PROTECTED_TREE\" \"$ARCHITECTURE\" \"$GITHUB_SHA\"\n",
        "      - name: Collect bounded protected native diagnostics\n        if: always()\n        timeout-minutes: 15\n" ++
            "        env:\n          NATIVE_STEP_OUTCOME: ${{ steps.native.outcome }}\n",
        "            NATIVE_STEP_OUTCOME=\"$NATIVE_STEP_OUTCOME\" \\\n",
        "            collect \"$PROTECTED_TREE\" \"$ARCHITECTURE\" \"$GITHUB_SHA\"\n",
        "      - name: Copy bounded native evidence\n        if: always()\n",
        "            sudo -n tar -C \"$PROTECTED_TREE/native-upload\" -cf - . >\"$PWD/.native-evidence.tar\"\n",
        "      - name: Kill native descendants and remove only the named tree\n        if: always()\n        timeout-minutes: 3\n",
        "              kill -KILL \"${victims[@]}\" 2>/dev/null || true\n",
        "            rm -rf --one-file-system -- \"$tree\"\n",
        "      - name: Upload real acceptance evidence\n        if: always()\n",
        "          path: .real-snapshot/${{ matrix.architecture }}/evidence/\n",
        "          if-no-files-found: error\n          retention-days: 14\n",
    }) |token| {
        if (countSubstring(native_job, token) != 1) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native snapshot CI lost protected wiring: {s}", .{std.mem.trim(u8, token, " \t\r\n")}));
        }
    }
    if (std.mem.indexOf(u8, native_job, "continue-on-error") != null or
        std.mem.indexOf(u8, native_job, "cataggar/ghr") != null or
        std.mem.indexOf(u8, native_job, "chown") != null or
        hasUnflaggedSudo(native_job))
    {
        try failures.append(allocator, try allocator.dupe(u8, "native snapshot CI must retain protected tools and failures without ownership transfer"));
    }

    const job_opt = jobs.get("protected-reference");
    const on_part = if (std.mem.indexOf(u8, ci, "\nconcurrency:\n")) |idx| ci[0..idx] else ci;
    if (countSubstring(ci, PROTECTED_REFERENCE_INPUT) != 1 or
        countSubstring(ci, "run_protected_reference") != 2 or
        std.mem.indexOf(u8, on_part, "  schedule:\n    - cron: \"23 3 * * 1\"\n") == null or
        !lineInLines(on_part, "  workflow_dispatch:"))
    {
        try failures.append(
            allocator,
            try allocator.dupe(u8, "ci.yml: the protected reference job must run only on the weekly schedule or an explicit dispatch input"),
        );
    }
    if (job_opt == null) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: the protected reference job is missing"));
    }
    const job = job_opt orelse "";
    const after_steps = if (std.mem.indexOf(u8, job, "    steps:\n")) |idx| job[idx + "    steps:\n".len ..] else "";
    var actual_steps: std.ArrayList([]const u8) = .empty;
    {
        var pos: usize = 0;
        while (pos < after_steps.len) {
            const nl = std.mem.indexOfScalarPos(u8, after_steps, pos, '\n') orelse after_steps.len;
            const line = after_steps[pos..nl];
            if (std.mem.startsWith(u8, line, "      - ")) {
                const start = pos;
                var scan = nl + 1;
                var end = after_steps.len;
                while (scan < after_steps.len) {
                    const snl = std.mem.indexOfScalarPos(u8, after_steps, scan, '\n') orelse after_steps.len;
                    if (std.mem.startsWith(u8, after_steps[scan..snl], "      - ")) {
                        end = scan;
                        break;
                    }
                    scan = snl + 1;
                }
                try actual_steps.append(allocator, after_steps[start..end]);
                pos = end;
                continue;
            }
            pos = nl + 1;
        }
    }
    const expected_steps = [_][]const u8{
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n" ++
            "        with:\n          persist-credentials: false\n",
        PROTECTED_REFERENCE_BOOTSTRAP,
        PROTECTED_REFERENCE_COPY,
        PROTECTED_REFERENCE_UPLOAD,
        PROTECTED_REFERENCE_CLEANUP,
    };
    var steps_ok = countSubstring(ci, "\n" ++ PROTECTED_REFERENCE_HEADER) == 1 and
        actual_steps.items.len == expected_steps.len;
    if (steps_ok) {
        for (actual_steps.items, expected_steps) |a, e| {
            if (!std.mem.eql(u8, a, e)) steps_ok = false;
        }
    }
    if (!steps_ok) {
        try failures.append(
            allocator,
            try allocator.dupe(u8, "ci.yml: the protected reference job must keep its exact root bootstrap, evidence copy, upload and cleanup"),
        );
    }
    if (std.mem.indexOf(u8, job, "continue-on-error") != null or
        std.mem.indexOf(u8, job, "cataggar/ghr") != null or
        hasUnflaggedSudo(job))
    {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: the protected reference job must not hide failures or use unprotected tools"));
    }

    const script = texts.get("tools/real-snapshot-reference-protected-ci.sh") orelse "";
    for (PROTECTED_REFERENCE_SCRIPT_TOKENS) |token| {
        if (countSubstring(script, token) != 1) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "protected reference CI script lost {s}", .{std.mem.trim(u8, token, " \t\r\n")}));
        }
    }
    var script_has_skip = std.mem.indexOf(u8, script, "SkipTest") != null or std.mem.indexOf(u8, script, "--skip") != null;
    {
        var it = std.mem.splitScalar(u8, script, '\n');
        while (it.next()) |line| {
            const trimmed = std.mem.trimStart(u8, line, " \t");
            if (std.mem.startsWith(u8, trimmed, "exit 0") and isWordBoundary(trimmed, 6)) {
                script_has_skip = true;
            }
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, line, pos, "||")) |idx| {
                pos = idx + 2;
                var j = pos;
                while (j < line.len and isSpace(line[j])) : (j += 1) {}
                if (startsWithAt(line, j, "true") and isWordBoundary(line, j + 4)) {
                    script_has_skip = true;
                }
            }
        }
    }
    if (script_has_skip or countSubstring(script, "\"$reference_paths\" tree \"$tree\"") != 5) {
        try failures.append(allocator, try allocator.dupe(u8, "protected reference CI script must not skip and must check the tree at every stage"));
    }

    for (PROTECTED_REFERENCE_SOURCE_TOKENS) |stl| {
        const p_txt = texts.get(stl.path) orelse "";
        for (stl.tokens) |token| {
            if (countSubstring(p_txt, token) != 1) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: protected reference wiring lost {s}", .{ stl.path, std.mem.trim(u8, token, " \t\r\n") }));
            }
        }
    }

    const harness = texts.get("tools/real-snapshot-reference-protected.zig") orelse "";
    if (std.mem.indexOf(u8, harness, "SkipZigTest") != null or
        std.mem.indexOf(u8, harness, "SkipTest") != null or
        std.mem.indexOf(u8, harness, "skipTest") != null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "protected reference proof must not skip"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn recoveryZigCommands(allocator: std.mem.Allocator, targets: []const []const u8, sharded: bool) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    const shard_opt = if (sharded) " -Dnative-zig-recovery-diversion-shard=\"${{ matrix.shard }}\"" else "";
    for (targets) |target| {
        for ([_][]const u8{ "", " -Doptimize=ReleaseSafe" }) |mode| {
            try out.append(
                allocator,
                try std.fmt.allocPrint(
                    allocator,
                    "zig build {s}{s} -Dnative-reference-dpkg=\"$reference_dpkg\"{s} -j2 --summary all",
                    .{ target, shard_opt, mode },
                ),
            );
        }
    }
    return out.toOwnedSlice(allocator);
}

pub fn nativeRecoveryCiFailures(allocator: std.mem.Allocator, text_raw: []const u8) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for (try rootlessRootCiFailures(allocator, text_raw)) |msg| try failures.append(allocator, msg);
    const text = try rootlessRootHostedView(allocator, text_raw);
    const jobs = try parseCiJobsMap(allocator, text);
    for (try ciDispatchMatrixFailures(allocator, text, jobs)) |msg| try failures.append(allocator, msg);
    for (try workloadCiFailures(allocator, jobs, text)) |msg| try failures.append(allocator, msg);

    const architectures =
        "          - os: ubuntu-24.04\n" ++
        "            name: linux-x64\n" ++
        "          - os: ubuntu-24.04-arm\n" ++
        "            name: linux-arm64\n";
    var div_arch_buf: std.ArrayList(u8) = .empty;
    for ([_][2][]const u8{ .{ "ubuntu-24.04", "linux-x64" }, .{ "ubuntu-24.04-arm", "linux-arm64" } }) |oa| {
        for (1..DIVERSION_CASE_SHARDS.len + 1) |shard| {
            try div_arch_buf.appendSlice(
                allocator,
                try std.fmt.allocPrint(
                    allocator,
                    "          - os: {s}\n            name: {s}\n            shard: {d}\n",
                    .{ oa[0], oa[1], shard },
                ),
            );
        }
    }
    const diversion_architectures = try div_arch_buf.toOwnedSlice(allocator);

    var has_dup_agg = jobs.contains("native-recovery");
    {
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            const trimmed = std.mem.trimStart(u8, line, " \t");
            if (trimmed.len < line.len and std.mem.startsWith(u8, trimmed, "zig build test-native-recovery")) {
                const rest = trimmed["zig build test-native-recovery".len..];
                if (rest.len == 0 or isSpace(rest[0])) has_dup_agg = true;
            }
        }
    }
    if (has_dup_agg) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: retired recovery job or duplicate complete aggregate is present"));
    }

    var expected_commands: std.ArrayList([]const u8) = .empty;
    var shared_setup: ?[]const u8 = null;

    for (RECOVERY_ZIG_SHARDS) |sh| {
        const RecStep = struct { name: []const u8, commands: []const []const u8 };
        var exp_steps: std.ArrayList(RecStep) = .empty;
        if (std.mem.eql(u8, sh.name, "native-recovery-zig-workflows")) {
            try exp_steps.append(allocator, .{
                .name = "Exercise Zig recovery units in both modes",
                .commands = &.{
                    "mkdir -p .tmp",
                    "zig build test-native-recovery-zig-unit -j2 --summary all",
                    "zig build test-native-recovery-zig-unit -Doptimize=ReleaseSafe -j2 --summary all",
                },
            });
        }
        var main_cmds: std.ArrayList([]const u8) = .empty;
        if (std.mem.eql(u8, sh.name, "native-recovery-zig-workflows") or
            std.mem.eql(u8, sh.name, "native-recovery-zig-repository") or
            std.mem.eql(u8, sh.name, "native-recovery-zig-helper") or
            std.mem.eql(u8, sh.name, "native-recovery-zig-family"))
        {
            try main_cmds.append(allocator, "mkdir -p .tmp");
        }
        try main_cmds.append(allocator, "zig build build-native-dpkg-reference -j2");
        try main_cmds.append(allocator, "reference_dpkg=\"$(zig-out/bin/debz-native-dpkg-reference)\"");
        for (try recoveryZigCommands(allocator, sh.targets, std.mem.eql(u8, sh.name, "native-recovery-zig-diversions"))) |c| {
            try main_cmds.append(allocator, c);
        }
        try exp_steps.append(allocator, .{ .name = sh.step_name, .commands = try main_cmds.toOwnedSlice(allocator) });
        if (std.mem.eql(u8, sh.name, "native-recovery-zig-workflows")) {
            try exp_steps.append(allocator, .{ .name = ROOT_IMPORT_STEP, .commands = &ROOT_IMPORT_COMMANDS });
        }

        const matrix_rows = if (std.mem.eql(u8, sh.name, "native-recovery-zig-diversions")) diversion_architectures else architectures;
        const body = jobs.get(sh.name) orelse "";
        const timeout_minutes: usize = if (std.mem.eql(u8, sh.name, "native-recovery-zig-scenarios") or
            std.mem.eql(u8, sh.name, "native-recovery-zig-diversions")) 75 else 35;
        const strategy = try std.fmt.allocPrint(
            allocator,
            "      fail-fast: false\n      matrix:\n        include:\n{s}",
            .{matrix_rows},
        );
        const exp_name_line = try std.fmt.allocPrint(allocator, "    name: {s}", .{sh.display_name});
        const exp_timeout_line = try std.fmt.allocPrint(allocator, "    timeout-minutes: {d}", .{timeout_minutes});
        var timeout_cnt: usize = 0;
        var timeout_ok = false;
        {
            var it = std.mem.splitScalar(u8, body, '\n');
            while (it.next()) |line| {
                if (std.mem.startsWith(u8, line, "    timeout-minutes:")) {
                    timeout_cnt += 1;
                    if (std.mem.eql(u8, line, exp_timeout_line)) timeout_ok = true;
                }
            }
        }
        const strat_idx = std.mem.indexOf(u8, body, "    strategy:\n");
        const steps_idx = std.mem.indexOf(u8, body, "    steps:\n");
        const strat_part = if (strat_idx != null and steps_idx != null and strat_idx.? < steps_idx.?)
            body[strat_idx.? + "    strategy:\n".len .. steps_idx.?]
        else
            "";

        if (!lineInLines(body, exp_name_line) or
            !lineInLines(body, "    runs-on: ${{ matrix.os }}") or
            timeout_cnt != 1 or !timeout_ok or
            countSubstring(body, "    strategy:\n") != 1 or
            countSubstring(body, "    steps:\n") != 1 or
            !std.mem.eql(u8, strat_part, strategy) or
            std.mem.indexOf(u8, body, "continue-on-error:") != null)
        {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(
                    allocator,
                    "ci.yml: {s} must require every reviewed architecture and mode within {d} minutes",
                    .{ sh.name, timeout_minutes },
                ),
            );
        }

        const parsed_steps = try parseJobSteps(allocator, body);
        var steps_map: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
        for (parsed_steps) |ps| try steps_map.put(allocator, ps.name, ps.body);

        const first_hdr = try std.fmt.allocPrint(allocator, "      - name: {s}\n", .{exp_steps.items[0].name});
        const after_steps = if (steps_idx) |si| body[si + "    steps:\n".len ..] else body;
        const setup = if (std.mem.indexOf(u8, after_steps, first_hdr)) |fi| after_steps[0..fi] else after_steps;
        if (shared_setup == null) shared_setup = setup;
        var setup_has_if = false;
        {
            var it = std.mem.splitScalar(u8, setup, '\n');
            while (it.next()) |line| {
                if (std.mem.startsWith(u8, line, "        if:")) setup_has_if = true;
            }
        }
        if (!std.mem.eql(u8, setup, shared_setup.?) or
            std.mem.indexOf(u8, setup, "      - name: Install Zig via ghr\n") == null or
            std.mem.indexOf(u8, setup, "      - name: Validate Zig version\n") == null or
            std.mem.indexOf(u8, setup, "      - name: Install metadata decompression and signed fixture dependencies\n") == null or
            std.mem.indexOf(u8, setup, "liblzma-dev libzstd-dev") == null or
            std.mem.indexOf(u8, setup, "python3") != null or
            setup_has_if)
        {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "ci.yml: {s} must retain pinned Zig and signed fixture dependencies", .{sh.name}));
        }

        if (steps_map.count() != exp_steps.items.len + 3) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "ci.yml: {s} has an unreviewed recovery step", .{sh.name}));
        }

        for (exp_steps.items) |es| {
            const step_body = steps_map.get(es.name) orelse "";
            var has_if = false;
            {
                var it = std.mem.splitScalar(u8, step_body, '\n');
                while (it.next()) |line| {
                    if (std.mem.startsWith(u8, line, "        if:")) has_if = true;
                }
            }
            var actual: std.ArrayList([]const u8) = .empty;
            if (std.mem.indexOf(u8, step_body, "        run: |\n")) |r_idx| {
                var r_it = std.mem.splitScalar(u8, step_body[r_idx + "        run: |\n".len ..], '\n');
                while (r_it.next()) |rl| {
                    const tr = std.mem.trim(u8, rl, " \t\r");
                    if (tr.len > 0) try actual.append(allocator, tr);
                }
            }
            var cmds_eq = actual.items.len == es.commands.len;
            if (cmds_eq) {
                for (actual.items, es.commands) |a, e| {
                    if (!std.mem.eql(u8, a, e)) cmds_eq = false;
                }
            }
            if (has_if or !cmds_eq) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "ci.yml: {s} must execute {s} without skips or missing commands", .{ sh.name, es.name }));
            }
            for (es.commands) |c| try expected_commands.append(allocator, c);
        }

        var actual_rec_cmds: std.ArrayList([]const u8) = .empty;
        {
            var it = std.mem.splitScalar(u8, body, '\n');
            while (it.next()) |line| {
                const pref = "          zig build test-native-recovery";
                if (std.mem.startsWith(u8, line, pref) and line.len > pref.len) {
                    try actual_rec_cmds.append(allocator, line[10..]);
                }
            }
        }
        var req_rec_cmds: std.ArrayList([]const u8) = .empty;
        for (exp_steps.items) |es| {
            for (es.commands) |c| {
                if (std.mem.startsWith(u8, c, "zig build test-native-recovery")) {
                    try req_rec_cmds.append(allocator, c);
                }
            }
        }
        var rec_eq = actual_rec_cmds.items.len == req_rec_cmds.items.len;
        if (rec_eq) {
            for (actual_rec_cmds.items, req_rec_cmds.items) |a, e| {
                if (!std.mem.eql(u8, a, e)) rec_eq = false;
            }
        }
        if (!rec_eq) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "ci.yml: {s} must execute every recovery target exactly once per mode", .{sh.name}));
        }
    }

    var inv_cmds: std.ArrayList([]const u8) = .empty;
    var inv_set: std.StringHashMapUnmanaged(void) = .empty;
    var inv_dup = false;
    for (expected_commands.items) |c| {
        if (std.mem.startsWith(u8, c, "zig build test-native-recovery")) {
            try inv_cmds.append(allocator, c);
            if ((try inv_set.getOrPut(allocator, c)).found_existing) inv_dup = true;
        }
    }
    if (inv_cmds.items.len != 34 or inv_dup) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: recovery command inventory contains duplicate targets"));
    }

    var text_rec_cmds: std.ArrayList([]const u8) = .empty;
    var text_root_imp: std.ArrayList([]const u8) = .empty;
    {
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            const tr = std.mem.trimStart(u8, line, " \t");
            if (tr.len < line.len) {
                if (std.mem.startsWith(u8, tr, "zig build test-native-recovery") and tr.len > "zig build test-native-recovery".len) {
                    try text_rec_cmds.append(allocator, tr);
                }
                if (std.mem.startsWith(u8, tr, "zig build test-native-root-import")) {
                    try text_root_imp.append(allocator, tr);
                }
            }
        }
    }
    const strLess = struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan;
    std.mem.sort([]const u8, text_rec_cmds.items, {}, strLess);
    std.mem.sort([]const u8, inv_cmds.items, {}, strLess);
    var all_rec_eq = text_rec_cmds.items.len == inv_cmds.items.len;
    if (all_rec_eq) {
        for (text_rec_cmds.items, inv_cmds.items) |a, e| {
            if (!std.mem.eql(u8, a, e)) all_rec_eq = false;
        }
    }
    if (!all_rec_eq) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: recovery targets must execute only in the six required Zig shards"));
    }

    if (text_root_imp.items.len != 2 or
        !std.mem.eql(u8, text_root_imp.items[0], ROOT_IMPORT_COMMANDS[3]) or
        !std.mem.eql(u8, text_root_imp.items[1], ROOT_IMPORT_COMMANDS[4]))
    {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: pinned-dpkg root import must run once per mode only in the required core shard"));
    }

    const gate = jobs.get("build-and-test") orelse "";
    const gate_steps = try parseJobSteps(allocator, gate);
    var gate_step_body: []const u8 = "";
    for (gate_steps) |gs| {
        if (std.mem.eql(u8, gs.name, "Require every build and native recovery shard")) {
            gate_step_body = gs.body;
        }
    }
    var required_results: std.ArrayList([]const u8) = .empty;
    for (WORKLOAD_RESULTS) |wr| {
        try required_results.append(allocator, try std.fmt.allocPrint(allocator, "test \"${s}\" = success", .{wr[0]}));
    }
    try required_results.appendSlice(allocator, &.{
        "test \"$RECOVERY_WORKFLOWS_RESULT\" = success",
        "test \"$RECOVERY_REPOSITORY_RESULT\" = success",
        "test \"$RECOVERY_HELPER_RESULT\" = success",
        "test \"$RECOVERY_FAMILY_RESULT\" = success",
        "test \"$RECOVERY_SCENARIOS_RESULT\" = success",
        "test \"$RECOVERY_DIVERSIONS_RESULT\" = success",
    });

    var gate_ok = lineInLines(gate, "    name: Build and test (${{ matrix.name }})") and
        lineInLines(gate, "    needs: [build-and-test-workload, build-and-test-workload-production, build-and-test-workload-apt-system, build-and-test-workload-native, build-and-test-workload-release, native-recovery-zig-workflows, native-recovery-zig-repository, native-recovery-zig-helper, native-recovery-zig-family, native-recovery-zig-scenarios, native-recovery-zig-diversions]") and
        lineInLines(gate, "    if: " ++ CI_BUILD_AGGREGATE_CONDITION) and
        lineInLines(gate, "      fail-fast: false") and
        lineInLines(gate, "        name: [linux-x64, linux-arm64]");
    for (WORKLOAD_RESULTS) |wr| {
        const l1 = try std.fmt.allocPrint(allocator, "          {s}: ${{{{ needs.{s}.result }}}}", .{ wr[0], wr[1] });
        const l2 = try std.fmt.allocPrint(allocator, "          test \"${s}\" = success", .{wr[0]});
        if (!lineInLines(gate, l1) or !lineInLines(gate, l2)) gate_ok = false;
    }
    for ([_][]const u8{
        "          RECOVERY_WORKFLOWS_RESULT: ${{ needs.native-recovery-zig-workflows.result }}",
        "          RECOVERY_REPOSITORY_RESULT: ${{ needs.native-recovery-zig-repository.result }}",
        "          RECOVERY_HELPER_RESULT: ${{ needs.native-recovery-zig-helper.result }}",
        "          RECOVERY_FAMILY_RESULT: ${{ needs.native-recovery-zig-family.result }}",
        "          RECOVERY_SCENARIOS_RESULT: ${{ needs.native-recovery-zig-scenarios.result }}",
        "          RECOVERY_DIVERSIONS_RESULT: ${{ needs.native-recovery-zig-diversions.result }}",
        "          test \"$RECOVERY_WORKFLOWS_RESULT\" = success",
        "          test \"$RECOVERY_REPOSITORY_RESULT\" = success",
        "          test \"$RECOVERY_HELPER_RESULT\" = success",
        "          test \"$RECOVERY_FAMILY_RESULT\" = success",
        "          test \"$RECOVERY_SCENARIOS_RESULT\" = success",
        "          test \"$RECOVERY_DIVERSIONS_RESULT\" = success",
    }) |req_l| {
        if (!lineInLines(gate, req_l)) gate_ok = false;
    }
    if (std.mem.indexOf(u8, gate, "continue-on-error:") != null or gate_steps.len != 1) gate_ok = false;
    var needs_cnt: usize = 0;
    {
        var it = std.mem.splitScalar(u8, gate, '\n');
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "        if:")) gate_ok = false;
            if (std.mem.startsWith(u8, line, "    needs:")) needs_cnt += 1;
        }
    }
    if (needs_cnt != 1 or countSubstring(gate_step_body, "        run: |\n") != 1) {
        gate_ok = false;
    } else if (std.mem.indexOf(u8, gate_step_body, "        run: |\n")) |r_idx| {
        var act_lines: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, gate_step_body[r_idx + "        run: |\n".len ..], '\n');
        while (it.next()) |rl| {
            const tr = std.mem.trim(u8, rl, " \t\r");
            if (tr.len > 0) try act_lines.append(allocator, tr);
        }
        if (act_lines.items.len != required_results.items.len) {
            gate_ok = false;
        } else {
            for (act_lines.items, required_results.items) |a, e| {
                if (!std.mem.eql(u8, a, e)) gate_ok = false;
            }
        }
    }
    if (!gate_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: existing required build checks must reject any incomplete workload"));
    }
    return failures.toOwnedSlice(allocator);
}

pub const SIGNED_PROC_CI_INPUT =
    "      run_signed_proc_replay:\n" ++
    "        description: \"Run hosted amd64 signed proc replay in protected roots (Debug and ReleaseSafe)\"\n" ++
    "        required: true\n" ++
    "        type: boolean\n" ++
    "        default: false\n";
pub const SIGNED_PROC_CI_CONDITION = "    if: github.event_name == 'workflow_dispatch' && inputs.run_signed_proc_replay";
pub const SIGNED_PROC_CI_JOB = [_][]const u8{
    SIGNED_PROC_CI_CONDITION,
    "    name: Signed proc replay in protected amd64 roots (${{ matrix.optimize }})",
    "    runs-on: ubuntu-24.04",
    "    timeout-minutes: 35",
    "      fail-fast: false",
    "        optimize: [Debug, ReleaseSafe]",
    "      OPTIMIZE: ${{ matrix.optimize }}",
    "      PROTECTED: /srv/debz-protected/signed-proc",
    "      UBUNTU_ARCHIVE_KEYRING_SHA256: 80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31",
};

pub const SignedProcStepSpec = struct { name: []const u8, required: []const []const u8 };
pub const SIGNED_PROC_CI_STEPS = [_]SignedProcStepSpec{
    .{ .name = "Install Zig via ghr", .required = &.{} },
    .{ .name = "Validate Zig version", .required = &.{"        run: test \"$(zig version)\" = 0.17.0"} },
    .{
        .name = "Bind the reviewed commit to a hosted amd64 runner",
        .required = &.{
            "          test \"$RUNNER_ARCH\" = X64",
            "          test \"$(uname -m)\" = x86_64",
            "          test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"",
            "          test ! -e \"$PROTECTED\" && test ! -L \"$PROTECTED\"",
        },
    },
    .{ .name = "Install metadata decompression dependency", .required = &.{} },
    .{
        .name = "Prepare pinned dpkg as the runner user",
        .required = &.{
            "          zig build build-native-dpkg-reference -j2",
            "          reference_dpkg=\"$(zig-out/bin/debz-native-dpkg-reference --architecture amd64)\"",
            "          test \"$reference_dpkg\" = \"$PWD/.cache/native-dpkg-reference/1.22.22/amd64/usr/bin/dpkg\"",
        },
    },
    .{
        .name = "Refuse unprotected and incomplete signed replay inputs",
        .required = &.{
            "          set -euo pipefail",
            "          grep -Fq 'prestate path is writable by an unprivileged user' .tmp/unprotected-prestates.log",
            "          grep -Fq 'fixture path is writable by an unprivileged user' .tmp/unprotected-bindings.log",
            "          grep -Fq 'signed proc replay requires -Dsigned-systemd-proc-root' .tmp/missing-roots.log",
            "          grep -Fq 'three distinct absolute disposable root paths' .tmp/relative-roots.log",
        },
    },
    .{
        .name = "Stage the reviewed commit, Zig and pinned dpkg under root-owned ancestry",
        .required = &.{
            "          set -euo pipefail",
            "          git -c tar.umask=0022 archive --format=tar -o .tmp/protected-checkout.tar HEAD",
            "          sudo -n tar -C \"$PROTECTED/checkout\" --no-same-owner -xf \"$PROTECTED/checkout.tar\"",
            "          sudo -n install -o root -g root -m 0644 /usr/share/keyrings/ubuntu-archive-keyring.gpg \\",
            "            <<<\"$UBUNTU_ARCHIVE_KEYRING_SHA256  $PROTECTED/keyrings/ubuntu-archive-keyring.gpg\"",
            "          sudo -n chmod -R go-w \"$PROTECTED\"",
            "          sudo -n find \"$PROTECTED\" -xdev \\( ! -uid 0 -o ! -gid 0 -o -perm /022 \\) ! -type l \\",
            "          test ! -s .tmp/protected-writable.txt",
            "          for path in / /srv /srv/debz-protected \"$PROTECTED\"; do",
            "            test \"$(stat -c '%u:%g' \"$path\")\" = 0:0",
            "            test $(( 8#$(stat -c '%a' \"$path\") & 022 )) -eq 0",
            "          sudo -n cmp -- \"$zig_binary\" \"$PROTECTED/zig/zig\"",
            "            zig build --build-file \"$PROTECTED/checkout/build.zig\" build-native-dpkg-reference \\",
            "            \"$PROTECTED/checkout/zig-out/bin/debz-native-dpkg-reference\" --architecture amd64 \\",
            "            --verify-only \"$PROTECTED/checkout/.real-snapshot/pinned-dpkg/usr/bin/dpkg\"",
        },
    },
    .{
        .name = "Build the protected snapshot client",
        .required = &.{
            "        working-directory: ${{ env.PROTECTED }}/checkout",
            "            zig build -Doptimize=Debug -j2 --summary all",
        },
    },
    .{
        .name = "Authenticate the snapshot closure and stage signed bindings",
        .required = &.{
            "        timeout-minutes: 20",
            "        working-directory: ${{ env.PROTECTED }}/checkout",
            "            DEBZ_REAL_SNAPSHOT_KEYRING=\"$PROTECTED/keyrings/ubuntu-archive-keyring.gpg\" \\",
            "            tools/real-snapshot-signed-proc-bindings.sh \"$PWD/zig-out/bin/debz\" \\",
            "            \"$PWD/.real-snapshot/ws\"",
        },
    },
    .{
        .name = "Generate fresh signed pinned-dpkg prestates",
        .required = &.{
            "        timeout-minutes: 12",
            "        working-directory: ${{ env.PROTECTED }}/checkout",
            "            DEBZ_ZIG=\"$PROTECTED/zig/zig\" \\",
            "            tools/real-snapshot-signed-proc-prestates.sh \\",
            "            \"$PWD/.real-snapshot/pinned-dpkg/usr/bin/dpkg\" \"$PWD/.real-snapshot/ws\"",
            "          sudo -n test -s \"$PWD/.real-snapshot/ws/prestate-build/evidence/base-cycle-proof/comparison.json\"",
            "          sudo -n test -s \"$PWD/.real-snapshot/ws/prestate-build/evidence/openssl-cycle-after.json\"",
        },
    },
    .{
        .name = "Run pinned dpkg proofs on separate prestate copies",
        .required = &.{
            "        working-directory: ${{ env.PROTECTED }}/checkout",
            "                cp -a -- \"$ws/prestates/$target\" \"$ws/native/$target\"",
            "                cp -a -- \"$ws/prestates/$target\" \"$ws/proof-sources/$target\"",
            "              ln -sfn -- sudo.ws \"$ws/native/sudo/usr/bin/sudoedit\"",
            "              ln -sfn -- sudo.ws.8.gz \"$ws/native/sudo/usr/share/man/man8/sudoedit.8.gz\"",
            "              test \"$(readlink -- \"$ws/native/sudo/usr/bin/sudoedit\")\" = sudo.ws",
            "              test \"$(readlink -- \"$ws/native/sudo/usr/share/man/man8/sudoedit.8.gz\")\" = sudo.ws.8.gz",
            "              tools/real-snapshot-systemd-proc-reference.sh \"$pinned\" \\",
            "                \"$ws/proof-sources/systemd\" \"$ws/proofs/systemd\"",
            "              tools/real-snapshot-udev-reference.sh \"$pinned\" \\",
            "                \"$ws/proof-sources/udev\" \"$ws/proofs/udev\"",
            "              tools/real-snapshot-sudo-reference.sh \"$pinned\" \\",
            "                \"$ws/proof-sources/sudo\" \"$ws/proofs/sudo\"",
        },
    },
    .{
        .name = "Replay signed systemd, udev and sudo postinsts natively without skips",
        .required = &.{
            "        working-directory: ${{ env.PROTECTED }}/checkout",
            "          set -euo pipefail",
            "            zig build test-native-signed-proc -Doptimize=\"$OPTIMIZE\" -j2 --summary all \\",
            "              -Dsigned-systemd-proc-root=\"$ws/native/systemd\" \\",
            "              -Dsigned-udev-proc-root=\"$ws/native/udev\" \\",
            "              -Dsigned-sudo-proc-root=\"$ws/native/sudo\" \\",
            "          test \"${status:-0}\" -eq 0",
            "          grep -Fxq 'All 4 tests passed.' \"$GITHUB_WORKSPACE/.tmp/signed-proc-replay.log\"",
            "          for name in 'systemd postinst uses scoped masked proc' \\",
            "            'udev postinst uses only PID proc and applies static permissions' \\",
            "            'sudo postinst repairs only pinned alternatives with PID-only proc'; do",
            "            grep -Fq \"maintainer_script.test.signed $name...OK\" \"$GITHUB_WORKSPACE/.tmp/signed-proc-replay.log\"",
            "          for target in systemd udev; do",
            "            sudo -n cat \"$PROTECTED/checkout/.tmp/signed-network-$target.proof\" >\"$proof\"",
            "            grep -Fxq \"domain=$target\" \"$proof\"",
            "            grep -Fxq 'DEBZ_HOST_NETWORK_PROOF tcp=reachable abstract_unix=reachable inherited_fd=open' \"$proof\"",
            "            case \"$target\" in",
            "              systemd) proc_net=private ;;",
            "              udev) proc_net=absent ;;",
            "              *) exit 1 ;;",
            "            grep -Fxq \"DEBZ_SIGNED_NETWORK_PROOF proc_net=$proc_net interfaces=lo default_route=false host_tcp=denied abstract_unix=denied inherited_fd=sealed loopback=ok\" \"$proof\"",
        },
    },
    .{
        .name = "Compare native replays with pinned dpkg proofs",
        .required = &.{
            "        working-directory: ${{ env.PROTECTED }}/checkout",
            "          sudo -n env -i PATH=\"$PROTECTED/zig:/usr/sbin:/usr/bin:/sbin:/bin\" HOME=/root \\",
            "            ZIG_GLOBAL_CACHE_DIR=\"$PROTECTED/zig-global-cache\" \\",
            "            zig build build-signed-proc-compare test-signed-proc-compare \\",
            "              -Doptimize=\"$OPTIMIZE\" -j2 --summary all",
            "              for target in systemd udev sudo; do",
            "                PATH=/no-host-interpreters \"$1/zig-out/bin/debz-signed-proc-compare\" \"$target\" \\",
            "                  \"$ws/native/$target\" \"$ws/proofs/$target\" \"$ws/compare/$target.json\"",
        },
    },
    .{
        .name = "Execute signed binding refusal fixtures",
        .required = &.{
            "        working-directory: ${{ env.PROTECTED }}/checkout",
            "          set -euo pipefail",
            "            DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE=1 \\",
            "            sh \"$PWD/.real-snapshot/ws/bindings.env\" \"$OPTIMIZE\" \\",
            "          test \"${status:-0}\" -eq 0",
            "          grep -Eq '^[1-9][0-9]* passed; 3 skipped; 0 failed\\.$' " ++
                "\"$GITHUB_WORKSPACE/.tmp/signed-bindings.log\"",
        },
    },
    .{
        .name = "Exercise named cleanup with a live bounded cache writer",
        .required = &.{
            "          set -euo pipefail",
            "              [[ \"$tree\" == /srv/debz-protected/signed-proc && -d \"$tree\" && ! -L \"$tree\" ]]",
            "              timeout --signal=TERM --kill-after=5s 60s bash -c '\"'\"'",
            "                while :; do printf . >> cleanup-cache-writer; sleep 0.01; done",
            "              kill -0 \"$pid\"",
            "          [[ \"$writer_pid\" =~ ^[1-9][0-9]*$ ]]",
        },
    },
    .{
        .name = "Copy bounded evidence and remove named protected roots",
        .required = &.{
            "        if: ${{ always() }}",
            "          set -euo pipefail",
            "            timeout --signal=TERM --kill-after=5s 30s bash -euo pipefail -c '",
            "              [[ \"$tree\" == /srv/debz-protected/signed-proc ]]",
            "              [[ -d \"$tree\" && ! -L \"$tree\" && $(stat -c %u:%g \"$tree\") == 0:0 ]]",
            "              for attempt in 1 2 3 4 5 6; do",
            "                for process in /proc/[0-9]*; do",
            "                  root=$(readlink \"$process/root\" 2>/dev/null) || continue",
            "                  cwd=$(readlink \"$process/cwd\" 2>/dev/null) || cwd=",
            "                    *\"$tree/\"*) signed_victims+=(\"${process#/proc/}\") ;;",
            "                if (( attempt == 6 )); then",
            "                  echo \"protected descendants survived bounded shutdown: ${signed_victims[*]}\" >&2",
            "                kill -KILL \"${signed_victims[@]}\" 2>/dev/null || true",
            "                sleep 1",
            "            ' signed-cleanup \"$PROTECTED\" >.tmp/signed-proc-stop.log 2>&1 || stop_status=$?",
            "          test \"${stop_status:-0}\" -eq 0",
            "          if grep -F \"$PROTECTED\" .tmp/signed-proc-mounts.txt; then",
            "          sudo -n rm -rf --one-file-system -- \"$PROTECTED\"",
            "          test ! -e \"$PROTECTED\"",
            "            grep -Eq \"(^| )$writer_pid( |$)\" .tmp/signed-proc-stop.log",
            "              >\"$evidence/signed-cleanup-writer-proof.txt\"",
            "                snapshot/evidence/refresh.json snapshot/evidence/refresh.stderr \\",
            "                snapshot/evidence/plan.json snapshot/evidence/plan.stderr \\",
            "                snapshot/evidence/download.json snapshot/evidence/download.stderr \\",
            "                prestate-build/evidence/base-cycle-before.json \\",
            "                prestate-build/evidence/base-cycle-after.json \\",
            "                prestate-build/evidence/openssl-cycle-before.json \\",
            "                prestate-build/evidence/openssl-cycle-after.json \\",
            "                prestate-build/evidence/openssl-cycle-refusals.json \\",
            "                prestate-build/evidence/reference-no-progress.json \\",
            "                prestate-build/evidence/base-cycle-proof/comparison.json \\",
            "                native/systemd/var/log/dpkg.log native/udev/var/log/dpkg.log \\",
            "                native/sudo/var/log/dpkg.log \\",
            "                native/systemd/var/lib/dpkg/status native/udev/var/lib/dpkg/status \\",
            "                native/sudo/var/lib/dpkg/status \\",
            "                native/systemd/var/lib/dpkg/status-old native/udev/var/lib/dpkg/status-old \\",
            "                native/sudo/var/lib/dpkg/status-old \\",
            "                proofs/systemd/var/lib/dpkg/status proofs/udev/var/lib/dpkg/status \\",
            "                proofs/sudo/var/lib/dpkg/status \\",
            "                proofs/systemd/var/lib/dpkg/status-old proofs/udev/var/lib/dpkg/status-old \\",
            "                proofs/sudo/var/lib/dpkg/status-old \\",
            "                native/udev/etc/group proofs/udev/etc/group \\",
        },
    },
    .{
        .name = "Upload bounded signed replay evidence",
        .required = &.{
            "        if: ${{ always() }}",
            "          if-no-files-found: error",
        },
    },
};

pub fn signedProcCiFailures(allocator: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const dispatch = extractDispatchInputsBlock(text);
    const jobs = try parseCiJobsMap(allocator, text);
    const body = jobs.get("signed-proc-protected-replay") orelse "";

    const rspr = countTrimmedKeyLines(text, "      run_signed_proc_replay:", "run_signed_proc_replay:");
    var job_ok = dispatch != null and
        dispatchInputExact(dispatch.?, SIGNED_PROC_CI_INPUT) and
        rspr.total_key_lines == 1 and
        rspr.exact_matches == 1 and
        countSubstring(text, "inputs.run_signed_proc_replay") == 1 and
        std.mem.indexOf(u8, body, "continue-on-error") == null;
    for (SIGNED_PROC_CI_JOB) |req_l| {
        if (!lineInLines(body, req_l)) job_ok = false;
    }
    var if_cnt: usize = 0;
    {
        var it = std.mem.splitScalar(u8, body, '\n');
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "    if:")) {
                if_cnt += 1;
                if (!std.mem.eql(u8, line, SIGNED_PROC_CI_CONDITION)) job_ok = false;
            }
            if (std.mem.startsWith(u8, line, "    needs:") or
                std.mem.startsWith(u8, line, "    continue-on-error:") or
                std.mem.startsWith(u8, line, "        include:") or
                std.mem.startsWith(u8, line, "        exclude:"))
            {
                job_ok = false;
            }
        }
    }
    if (if_cnt != 1 or !job_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: signed proc replay job must run both modes on hosted amd64 within 35 minutes"));
    }

    const steps = try parseJobSteps(allocator, body);
    var seq_ok = steps.len == SIGNED_PROC_CI_STEPS.len;
    if (seq_ok) {
        for (steps, SIGNED_PROC_CI_STEPS) |s, exp| {
            if (!std.mem.eql(u8, s.name, exp.name)) seq_ok = false;
        }
    }
    if (!seq_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: signed proc replay steps changed from the reviewed sequence"));
    }

    var cleanup: []const u8 = "";
    for (steps) |s| {
        if (std.mem.eql(u8, s.name, "Copy bounded evidence and remove named protected roots")) {
            cleanup = s.body;
        }
    }
    const cleanup_order = [_][]const u8{
        "' signed-cleanup \"$PROTECTED\" >.tmp/signed-proc-stop.log",
        "test \"${stop_status:-0}\" -eq 0",
        "cp .tmp/*.log \"$evidence/\"",
        "sudo -n rm -rf --one-file-system -- \"$PROTECTED\"",
        "test ! -e \"$PROTECTED\"",
    };
    var order_ok = true;
    var prev_pos: ?usize = null;
    for (cleanup_order) |tok| {
        if (std.mem.indexOf(u8, cleanup, tok)) |idx| {
            if (prev_pos != null and idx <= prev_pos.?) order_ok = false;
            prev_pos = idx;
        } else {
            order_ok = false;
        }
    }
    if (!order_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: signed proc replay must stop protected writers before evidence copy and named-tree removal"));
    }

    for (steps) |s| {
        var req: []const []const u8 = &.{};
        for (SIGNED_PROC_CI_STEPS) |exp| {
            if (std.mem.eql(u8, exp.name, s.name)) req = exp.required;
        }
        var step_ok = true;
        for (req) |r_line| {
            if (!lineInLines(s.body, r_line)) step_ok = false;
        }
        var conds: std.ArrayList([]const u8) = .empty;
        var timeouts: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, s.body, '\n');
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "        if:")) {
                try conds.append(allocator, line);
            }
            const t_pref = "        timeout-minutes: ";
            if (std.mem.startsWith(u8, line, t_pref) and line.len > t_pref.len) {
                const rest = line[t_pref.len..];
                var all_digits = true;
                for (rest) |c| {
                    if (c < '0' or c > '9') all_digits = false;
                }
                if (all_digits) try timeouts.append(allocator, rest);
            }
        }
        if (conds.items.len > 1 or
            (conds.items.len == 1 and (!std.mem.eql(u8, conds.items[0], "        if: ${{ always() }}") or !sliceContainsStr(req, "        if: ${{ always() }}"))))
        {
            step_ok = false;
        }
        for (timeouts.items) |tm| {
            const val = std.fmt.parseInt(usize, tm, 10) catch 0;
            if (val < 1 or val > 25) step_ok = false;
        }
        if (std.mem.eql(u8, s.name, "Authenticate the snapshot closure and stage signed bindings") and
            (timeouts.items.len != 1 or !std.mem.eql(u8, timeouts.items[0], "20")))
        {
            step_ok = false;
        }
        if (std.mem.eql(u8, s.name, "Generate fresh signed pinned-dpkg prestates") and
            (timeouts.items.len != 1 or !std.mem.eql(u8, timeouts.items[0], "12")))
        {
            step_ok = false;
        }
        if (!step_ok) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "ci.yml: signed proc replay step changed: {s}", .{s.name}));
        }
    }
    if (std.mem.indexOf(u8, body, "--report-only") != null or
        std.mem.indexOf(u8, body, "DEBZ_REQUIRE_SIGNED_PROC_ROOTS=0") != null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: signed proc replay comparison and roots must fail closed"));
    }
    return failures.toOwnedSlice(allocator);
}

// ============================================================================
// Part 4: Native Wiring Validators (Part B)
// ============================================================================

pub const REFERENCE_ROOT_PATHS = [_][]const u8{
    ".github/workflows/ci.yml",
    "build.zig",
    "tools/real-snapshot-reference-launcher.zig",
    "tools/real-snapshot-reference-launcher-root-test.zig",
};

pub fn partitionAfter(text: []const u8, sep: []const u8) []const u8 {
    if (std.mem.indexOf(u8, text, sep)) |idx| return text[idx + sep.len ..];
    return "";
}

pub fn partitionBefore(text: []const u8, sep: []const u8) []const u8 {
    if (std.mem.indexOf(u8, text, sep)) |idx| return text[0..idx];
    return text;
}

pub fn splitAfterOrWhole(text: []const u8, sep: []const u8) []const u8 {
    if (std.mem.indexOf(u8, text, sep)) |idx| return text[idx + sep.len ..];
    return text;
}

pub fn splitAfterAndBefore(text: []const u8, start_sep: []const u8, end_sep: []const u8) []const u8 {
    return partitionBefore(splitAfterOrWhole(text, start_sep), end_sep);
}

pub fn collapseWhitespaceAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var in_space = false;
    for (text) |c| {
        if (isSpace(c)) {
            if (!in_space) {
                try out.append(allocator, ' ');
                in_space = true;
            }
        } else {
            try out.append(allocator, c);
            in_space = false;
        }
    }
    return out.toOwnedSlice(allocator);
}

fn extractLowerSnakeWords(allocator: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < text.len) {
        if ((text[i] >= 'a' and text[i] <= 'z') or text[i] == '_') {
            const start = i;
            while (i < text.len and ((text[i] >= 'a' and text[i] <= 'z') or text[i] == '_')) : (i += 1) {}
            try words.append(allocator, text[start..i]);
        } else {
            i += 1;
        }
    }
    return words.toOwnedSlice(allocator);
}

fn stringSlicesEqual(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x, y)) return false;
    }
    return true;
}

pub const REPORT_PATH_ORACLE_FILES = [_][]const u8{
    "test/native_recovery_oracle.zig",
    "test/native_recovery_unit.zig",
    "test/native_recovery_acceptance.zig",
    "test/native_recovery_scriptless.zig",
    "test/native_recovery_conffile.zig",
    "test/native_recovery_literal.zig",
    "test/native_recovery_metadata.zig",
    "test/native_recovery_statoverride.zig",
};

pub fn nativeReportPathWiringFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const TokenCount = struct { token: []const u8, count: usize };
    const ReqEntry = struct { path: []const u8, tokens: []const TokenCount };
    const required = [_]ReqEntry{
        .{
            .path = "test/native_recovery_oracle.zig",
            .tokens = &.{
                .{ .token = "pub fn reportProvenancePath(reported: []const u8, expected: []const u8) ![]const u8 {", .count = 1 },
                .{ .token = "if (!std.mem.eql(u8, reported, expected)) return error.UnboundRecoveryProof;", .count = 1 },
                .{ .token = "return expected;", .count = 1 },
            },
        },
        .{
            .path = "test/native_recovery_acceptance.zig",
            .tokens = &.{
                .{ .token = "_ = try oracle.reportProvenancePath(report.provenance_path orelse return error.MissingReportBinding, provenance_path);", .count = 1 },
            },
        },
        .{
            .path = "test/native_recovery_scriptless.zig",
            .tokens = &.{
                .{ .token = "pub fn reportProvenancePath(reported: ?[]const u8) ![]const u8 {", .count = 1 },
                .{ .token = "return oracle.reportProvenancePath(reported orelse return error.MissingRecoveryProof, provenance_path);", .count = 1 },
                .{ .token = "const proof_path = try reportProvenancePath(report.value.provenance_path);", .count = 1 },
            },
        },
        .{
            .path = "test/native_recovery_conffile.zig",
            .tokens = &.{
                .{ .token = "const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);", .count = 2 },
            },
        },
        .{
            .path = "test/native_recovery_literal.zig",
            .tokens = &.{
                .{ .token = "const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);", .count = 1 },
            },
        },
        .{
            .path = "test/native_recovery_metadata.zig",
            .tokens = &.{
                .{ .token = "const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);", .count = 1 },
            },
        },
        .{
            .path = "test/native_recovery_statoverride.zig",
            .tokens = &.{
                .{ .token = "const proof_path = try process.reportProvenancePath(report.value.provenance_path);", .count = 1 },
            },
        },
    };
    for (required) |req| {
        const source = texts.get(req.path) orelse "";
        for (req.tokens) |tc| {
            if (countSubstring(source, tc.token) < tc.count) {
                try failures.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "{s}: report provenance path is no longer bound before reading: {s}", .{ req.path, tc.token }),
                );
            }
        }
    }
    const unit = texts.get("test/native_recovery_unit.zig") orelse "";
    const case = partitionAfterAndBefore(
        unit,
        "test \"recovery-unit.report path is bound before reading provenance\" {",
        "\ntest \"",
    );
    for ([_][]const u8{
        "\"/etc/passwd\"",
        "\"var/lib/debz/../../outside\"",
        "\"var/lib/debz-other/proof.json\"",
        "\"var/lib/debz/proof.json\"",
        "provenance.document_path",
        "error.UnboundRecoveryProof",
        "try sandbox.dir.symLink(sandbox.io, external, \"var/lib/debz/proof.json\", .{});",
        "try std.testing.expect((try provenance.read(allocator, root)) == null);",
    }) |token| {
        if (std.mem.indexOf(u8, case, token) == null) {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(allocator, "test/native_recovery_unit.zig: missing report-path refusal: {s}", .{token}),
            );
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeRecoveryGateWiringFailures(
    allocator: std.mem.Allocator,
    build: []const u8,
    helper: []const u8,
    family: []const u8,
    projected: []const u8,
    repository: []const u8,
    diversions: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "tools/test-native-recovery.py", "tools/test_native_recovery.py" }) |path| {
        const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{path});
        if (std.mem.indexOf(u8, build, quoted) != null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: retired Python recovery gate was restored: {s}", .{path}));
        }
    }
    const start = "const native_recovery = b.step(\"test-native-recovery\",";
    const graph = partitionAfterAndBefore(
        build,
        start,
        "    if (b.option(\n        []const u8,\n        \"native-reference-architecture\"",
    );
    if (graph.len == 0) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: complete Zig recovery gate is missing"));
        return failures.toOwnedSlice(allocator);
    }

    const expected_selectors = [_][]const u8{
        "native_core_only",
        "native_deadline_only",
        "native_script_failure_only",
        "repository_projection_only",
        "repository_execution_only",
        "repository_cli_only",
        "native_parity_only",
        "native_helper_only",
        "native_diversions_only",
    };
    var selectors_ok = false;
    if (std.mem.indexOf(u8, graph, "const selectors = [_]bool{")) |sel_start| {
        const after_sel = graph[sel_start + "const selectors = [_]bool{".len ..];
        if (std.mem.indexOf(u8, after_sel, "};")) |sel_end| {
            const words = try extractLowerSnakeWords(allocator, after_sel[0..sel_end]);
            selectors_ok = stringSlicesEqual(words, &expected_selectors);
        }
    }
    if (!selectors_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: nine public recovery workload selectors must remain exclusive"));
    }

    for ([_][]const u8{
        "native_recovery.dependOn(&run_native_recovery_tests.step);",
        "native_recovery.dependOn(&run_recovery_unit_tests.step);",
        "native_recovery.dependOn(&run_repository_recovery_unit.step);",
        "if (selected > 1 or focused)",
        "focused Zig case options cannot narrow the complete test-native-recovery gate",
        "zig_core_only or zig_deadline_only or family_executed_only or",
        "parity_case != null or bootstrap_case != null or repository_case != null or",
        "diversion_case != null or route_case != null or diversion_shard != null or mutation_boundary_case != null",
        "b.option([]const u8, \"native-zig-recovery-diversion-shard\",",
        "recovery_diversions.addArgs(&.{ \"--shard\", shard });",
        "if (native_core_only or zig_core_only) recovery_zig.addArg(\"--core-only\");",
        "if (native_deadline_only or zig_deadline_only) recovery_zig.addArg(\"--deadline-only\");",
        "if (native_script_failure_only or native_core_only) recovery_helper.addArg(\"--script-failure-only\");",
        "if (repository_projection_only) recovery_family.addArg(\"--projection-only\");",
        "if (repository_projection_only) repository_recovery.addArg(\"--projection-only\");",
        "if (repository_execution_only) repository_recovery.addArg(\"--execution-only\");",
        "if (repository_cli_only) repository_recovery.addArg(\"--cli-only\");",
        "recovery_family.addArtifactArg(native_trigger_helper);",
        "recovery_family.addArtifactArg(cli);",
        "recovery_bootstrap.addArtifactArg(native_trigger_helper);",
        "repository_recovery.addArtifactArg(cli);",
        "const repository_fixture_parent = b.addSystemCommand(&.{ \"mkdir\", \"-p\", pathFromRoot(b, \".tmp\") });",
        "run_repository_recovery_unit.step.dependOn(&repository_fixture_parent.step);",
        "repository_recovery.step.dependOn(&repository_fixture_parent.step);",
        "recovery_parity.addArtifactArg(cli);",
        "recovery_parity.addArtifactArg(native_trigger_helper);",
        "}) |runner| runner.addArgs(&.{ \"--reference-dpkg\", path });",
    }) |token| {
        if (std.mem.indexOf(u8, graph, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: complete Zig recovery gate lost {s}", .{token}));
        }
    }

    const branch = partitionAfterAndBefore(
        graph,
        "if (selected > 1 or focused) {",
        "    if (b.option([]const u8, \"native-reference-dpkg\"",
    );
    for ([_][]const u8{
        "if (native_deadline_only) {\n            native_recovery.dependOn(&recovery_zig.step);",
        "if (native_script_failure_only) {\n            native_recovery.dependOn(&recovery_helper.step);",
        "if (native_helper_only) {\n            native_recovery.dependOn(&recovery_bootstrap.step);",
        "if (native_diversions_only) {\n            native_recovery.dependOn(&recovery_diversions.step);",
        "if (repository_projection_only) {\n            native_recovery.dependOn(&recovery_family.step);\n            native_recovery.dependOn(&repository_recovery.step);",
        "if (repository_execution_only or repository_cli_only) {\n            native_recovery.dependOn(&repository_recovery.step);",
    }) |token| {
        if (std.mem.indexOf(u8, branch, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: recovery selector graph lost {s}", .{token}));
        }
    }

    const expected_arrays = [_][]const []const u8{
        &.{
            "recovery_parity",     "recovery_diversions", "statoverride_recovery", "conffile_recovery",
            "metadata_recovery",   "literal_recovery",    "scriptless_recovery",   "publication_recovery",
        },
        &.{
            "recovery_zig",          "recovery_helper",   "recovery_bootstrap",  "recovery_family",
            "recovery_diversions",   "statoverride_recovery", "conffile_recovery", "metadata_recovery",
            "literal_recovery",      "mutation_boundaries", "publication_recovery",
        },
        &.{
            "recovery_zig",          "recovery_family",       "recovery_parity",       "recovery_helper",
            "final_gaps",            "recovery_bootstrap",    "repository_recovery",   "rollback_clock",
            "scriptless_recovery",   "statoverride_recovery", "literal_recovery",      "metadata_recovery",
            "conffile_recovery",     "recovery_diversions",   "mutation_boundaries",   "publication_recovery",
        },
    };
    var found_arrays: std.ArrayList([][]const u8) = .empty;
    {
        const arr_prefix = "for ([_]*std.Build.Step.Run{";
        const arr_suffix = "}) |runner| native_recovery.dependOn(&runner.step);";
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, branch, pos, arr_prefix)) |p_idx| {
            const inner_start = p_idx + arr_prefix.len;
            pos = inner_start;
            if (std.mem.indexOfPos(u8, branch, inner_start, "})")) |close_idx| {
                if (startsWithAt(branch, close_idx, arr_suffix)) {
                    try found_arrays.append(allocator, try extractLowerSnakeWords(allocator, branch[inner_start..close_idx]));
                    pos = close_idx + arr_suffix.len;
                }
            }
        }
    }
    var arrays_ok = found_arrays.items.len == expected_arrays.len;
    if (arrays_ok) {
        for (found_arrays.items, expected_arrays) |act, exp| {
            if (!stringSlicesEqual(act, exp)) arrays_ok = false;
        }
    }
    if (!arrays_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: parity, core, or default recovery workload lost an executed runner"));
    }

    const pinned = partitionAfter(graph, "if (b.option([]const u8, \"native-reference-dpkg\",");
    var pinned_ok = false;
    {
        const pin_prefix = "for ([_]*std.Build.Step.Run{";
        const pin_suffix = "}) |runner| runner.addArgs(&.{ \"--reference-dpkg\", path });";
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, pinned, pos, pin_prefix)) |p_idx| {
            const inner_start = p_idx + pin_prefix.len;
            pos = inner_start;
            if (std.mem.indexOfPos(u8, pinned, inner_start, "})")) |close_idx| {
                if (startsWithAt(pinned, close_idx, pin_suffix)) {
                    const words = try extractLowerSnakeWords(allocator, pinned[inner_start..close_idx]);
                    pinned_ok = stringSlicesEqual(words, expected_arrays[2]);
                    break;
                }
            }
        }
    }
    if (!pinned_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: pinned dpkg must reach every default recovery acceptance runner"));
    }

    const shard_block = partitionAfterAndBefore(diversions, "const case_shards = [_]CaseShard{", "\n};");
    var actual_shards: std.ArrayList([2]usize) = .empty;
    {
        const sh_pref = ".{ .first = ";
        const sh_mid = ", .last = ";
        const sh_suf = " },";
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, shard_block, pos, sh_pref)) |s_idx| {
            const d1_start = s_idx + sh_pref.len;
            var d1_end = d1_start;
            while (d1_end < shard_block.len and shard_block[d1_end] >= '0' and shard_block[d1_end] <= '9') : (d1_end += 1) {}
            pos = d1_end;
            if (d1_end > d1_start and startsWithAt(shard_block, d1_end, sh_mid)) {
                const d2_start = d1_end + sh_mid.len;
                var d2_end = d2_start;
                while (d2_end < shard_block.len and shard_block[d2_end] >= '0' and shard_block[d2_end] <= '9') : (d2_end += 1) {}
                if (d2_end > d2_start and startsWithAt(shard_block, d2_end, sh_suf)) {
                    const first = std.fmt.parseInt(usize, shard_block[d1_start..d1_end], 10) catch 0;
                    const last = std.fmt.parseInt(usize, shard_block[d2_start..d2_end], 10) catch 0;
                    try actual_shards.append(allocator, .{ first, last });
                    pos = d2_end + sh_suf.len;
                }
            }
        }
    }
    var shards_ok = actual_shards.items.len == DIVERSION_CASE_SHARDS.len;
    if (shards_ok) {
        for (actual_shards.items, DIVERSION_CASE_SHARDS) |a, e| {
            if (a[0] != e[0] or a[1] != e[1]) shards_ok = false;
        }
    }
    if (!shards_ok) {
        try failures.append(allocator, try allocator.dupe(u8, "test/native_recovery_diversions.zig: numbered shard partitions must cover 001-100 exactly once"));
    }

    for ([_][]const u8{
        "if (cases.len != 100) @compileError(",
        "if (c.number <= previous or c.number > 100) @compileError(",
        "if (shard.first != next or shard.last < shard.first or shard.last > cases.len)",
        "if (next != cases.len + 1) @compileError(",
        "if (route_cases.len != 2) @compileError(",
        ".{ .name = \"cache-refresh\", .crash = \"after_upgrade_postrm_cache_refresh\" },",
        ".{ .name = \"route-checkpoint\", .crash = \"after_upgrade_postrm_route_checkpoint\" },",
        "if (selected != null or selected_route != null or selected_shard != null) return error.DuplicateCase;",
        "if (selected_shard.? == 0 or selected_shard.? > case_shards.len) return error.InvalidDiversionShard;",
        "const shard = if (selected_shard) |number| case_shards[number - 1] else null;",
        "if (c.number < bounds.first or c.number > bounds.last) continue;",
        "if (executed != expected_cases)",
        "const run_routes = selected == null and (selected_shard == null or selected_shard.? == case_shards.len);",
        "if (run_routes) for (route_cases) |c| {",
        "if (route_executed != (if (!run_routes)",
        "try lifecycle.assertHostUnchanged(a, init.io, reference.before);",
    }) |token| {
        if (std.mem.indexOf(u8, diversions, token) == null) {
            try failures.append(
                allocator,
                try std.fmt.allocPrint(allocator, "test/native_recovery_diversions.zig: required numbered or named shard behavior lost {s}", .{token}),
            );
        }
    }

    if (std.mem.indexOf(u8, build, "native_fixture_options.addOptionPath(\"integration_repository\", integration_repository.getEmittedBin());") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: signed recovery lost its native repository producer"));
    }
    if (std.mem.indexOf(u8, graph, "fixture-python") != null) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: retired signed fixture interpreter option was restored"));
    }

    const SourceTokens = struct { source: []const u8, tokens: []const []const u8 };
    for ([_]SourceTokens{
        .{ .source = helper, .tokens = &.{ "if (script_failure_only) {", "\"after_failure_outcome\", \"after_script_failure_state\"" } },
        .{ .source = family, .tokens = &.{ "if (projection_only) {", "try projected.runReadOnly(&fixture, self orelse return error.MissingSelf, driver, reference.architecture);" } },
        .{ .source = projected, .tokens = &.{"try readOnlyProjection(fixture, runner, driver, arch);"} },
        .{
            .source = repository,
            .tokens = &.{
                "const selected = try selectMode(false, projection_only, execution_only, cli_only);",
                "selected == null or selected == .projection or selected == .execution or selected == .cli",
            },
        },
    }) |st| {
        for (st.tokens) |token| {
            if (std.mem.indexOf(u8, st.source, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "Zig recovery selector lost an executed case: {s}", .{token}));
            }
        }
    }

    const script_branch = partitionAfterAndBefore(helper, "if (script_failure_only) {", "\n    try crashTransport(");
    if (std.mem.indexOf(u8, script_branch, "try knownScriptFailures(&fixture, driver, reference.executable, reference.architecture);") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "Zig recovery script-failure selector lost both unowned postinst crashes"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeCoreCompletionWiringFailures(
    allocator: std.mem.Allocator,
    build: []const u8,
    helper: []const u8,
    support: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{
        "recovery_helper.addArtifactArg(recovery_helper_executable);",
        "recovery_helper.addArtifactArg(native_lifecycle_tests);",
        "b.step(\"test-native-recovery-helper-zig\",",
    }) |token| {
        if (std.mem.indexOf(u8, build, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: required core completion target lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "try completedWithoutLiveHelper(&fixture, driver, reference.executable, reference.architecture);",
        "try missingPackageOwnedHelper(&fixture, driver, reference.architecture);",
        "try rehashedCallerPolicy(&fixture, driver, reference.architecture);",
        "try afterActiveClearLegacyEvidence(&fixture, driver, reference.executable, reference.architecture);",
        "\"NativeHelperBootstrapOwnerMissing\"",
        "\"RecoveryRequestBindingMismatch\"",
        "\"after_active_clear\"",
        "try sealJsonDigest(fixture, &persisted.value, \"debz-native-execution-request-v1\\x00\");",
        "debz.native_recovery.sealIntent(&altered_intent);",
        "const orphaned = try projected.rootInventory(fixture, root, false);",
        "try std.testing.expectEqualSlices(u8, orphaned, try projected.rootInventory(fixture, root, false));",
        "try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, directory), old_proof.document);",
        ".config_content = config,",
        "const config = \"#!/bin/sh\\n# config:1\\nprintf '%s\\\\n' 'config:1' >> /config-invoked\\nexit 97\\n\";",
    }) |token| {
        if (std.mem.indexOf(u8, helper, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: required executed core completion lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "config_content: ?[]const u8 = null,",
        "try fixture.write(config, configuration, 0o755);",
    }) |token| {
        if (std.mem.indexOf(u8, support, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_lifecycle_support.zig: real staged config fixture lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "try std.testing.expectEqualSlices(u8, before, try projected.rootInventory(fixture, root, true));",
        "try same(try bytes(fixture, root, \"var/lib/dpkg/tmp.ci/config\", 64 * 1024), config);",
        "try missing(fixture, root, \"var/lib/dpkg/info/\" ++ foundation.package ++ \".config\");",
        "try missing(fixture, root, \"config-invoked\");",
    }) |token| {
        if (countSubstring(helper, token) != 3) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: executed core checks lost {s}", .{token}));
        }
    }
    const caller_case = splitAfterAndBefore(helper, "fn rehashedCallerPolicy(", "\nfn afterActiveClearLegacyEvidence(");
    if (countSubstring(caller_case, ".isolated_helper = false,") != 2) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_helper.zig: rehashed caller refusal must run without isolated helper"));
    }
    const ordinary = splitAfterAndBefore(helper, "fn recoveredOrdinary(", "\n}\n");
    for ([_][]const u8{
        "if (try invoke(fixture, driver, root, arch, crash_output, .{",
        "try fixture.dir.deleteFile(fixture.io, archive_relative);",
        "const request = try originalRequestFor(fixture, root, intent.intent, case.isolated_helper, case.caller_owned, archive);",
        "if (reference_exit != (if (case.known_preinst_failure)",
        "try foundation.compare(fixture.*, expected, root, comparison);",
        "try verifyProofFor(fixture, root, repeated.value, intent.intent, request, proof_outcome, true, case.isolated_helper, case.caller_owned);",
        "try std.testing.expectEqualSlices(u8, root_before, try projected.rootInventory(fixture, root, case.caller_owned));",
        "try sameHelper(fixture, root, helper_before);",
        ".acknowledge = true,",
    }) |token| {
        if (std.mem.indexOf(u8, ordinary, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: ordinary real-process parity lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "try foundation.compare(fixture.*, expected, root, comparison);",
        "try sameHelper(fixture, root, helper_before);",
    }) |token| {
        if (countSubstring(ordinary, token) != 2) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: ordinary first/last checks lost {s}", .{token}));
        }
    }
    const main_body = splitAfterOrWhole(helper, "pub fn main(");
    if (countSubstring(main_body, "try recoveredOrdinary(") != 5) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_helper.zig: ordinary caller, failure and crash matrices not all executed"));
    }
    for ([_][]const u8{
        "\"after_execution_intent\", \"during_filesystem_publication\",\n        \"after_script_outcome\",   \"after_provenance\",",
        "\"typed-runtime-known-failure\" else \"caller-known-failure\"",
        "\"after_execution_intent\", \"during_filesystem_publication\", \"during_database_publication\",\n        \"after_script_prepared\",  \"after_script_outcome\",          \"after_provenance\",",
        ".name = \"known-failure-compensation\",",
    }) |token| {
        if (std.mem.indexOf(u8, main_body, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: ordinary executed matrix lost {s}", .{token}));
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeExerciseFinalWiringFailures(
    allocator: std.mem.Allocator,
    helper: []const u8,
    support: []const u8,
    unpack: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const main_body = splitAfterOrWhole(helper, "pub fn main(");
    for ([_][]const u8{
        "try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, false);",
        "try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, true);",
        "try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, false);",
        "try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, true);",
        "try noInterestOutcome(&fixture, driver, reference.executable, reference.architecture, false);",
        "try noInterestOutcome(&fixture, driver, reference.executable, reference.architecture, true);",
        "for ([_]Corruption{ .intent, .progress, .artifact, .managed_root, .completed_phase }) |which|",
        "try corruptedOrdinary(&fixture, driver, reference.architecture, which);",
    }) |token| {
        if (std.mem.indexOf(u8, main_body, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: final exercise matrix lost {s}", .{token}));
        }
    }
    if (std.mem.indexOf(u8, helper, "if (!claim.value.object.swapRemove(changing)) return error.InvalidRootClaim;") == null or
        std.mem.indexOf(u8, helper, "\"generation\", \"state\", \"phase\", \"step\", \"updated_unix\", \"digest_sha256\"") == null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_helper.zig: sticky root claim normalization lost"));
    }

    const BlockTokens = struct { start: []const u8, end: []const u8, tokens: []const []const u8 };
    for ([_]BlockTokens{
        .{
            .start = "fn blockedUnknown(",
            .end = "\nfn triggerOutcome(",
            .tokens = &.{
                "if (try invoke(fixture, driver, scenario.native_root, arch,",
                "\"after_upgrade_postrm_return_before_outcome\" else \"after_script_return_before_outcome\"",
                "try same(try text(script.value, \"outcome\"), \"in_flight\");",
                "try verifyProofFor(fixture, scenario.native_root, refused.value, intent.intent, request, .recovery_required, false, false, false);",
                "try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, scenario.native_root));",
                "try same(try stickyActiveClaim(fixture, scenario.native_root), original_claim);",
                "try unchanged(fixture, scenario.native_root, package_before);",
                "try sameHelper(fixture, scenario.native_root, original_helper);",
            },
        },
        .{
            .start = "fn triggerOutcome(",
            .end = "\nfn noInterestOutcome(",
            .tokens = &.{
                "\"after_trigger_outcome\"",
                "try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);",
                "if (events.value.events.len != 2) return error.IncorrectTriggerEventCount;",
                "observed[0].origin != .automatic or observed[1].origin != .dynamic",
                "try same(observed[0].trigger, \"debz-a\");",
                "try same(observed[1].trigger, \"debz-b\");",
                ".acknowledge = true,",
            },
        },
        .{
            .start = "fn noInterestOutcome(",
            .end = "\nconst Corruption =",
            .tokens = &.{
                "\"after_script_outcome\"",
                ".activations = &.{ \"debz-unwatched\", \"/usr/share/debz-unwatched/child\" },",
                ".activation_await = true,",
                "\"debz-unwatched \"",
                "std.mem.indexOf(u8, line, \"debz-trigger-source\") == null",
                "std.mem.indexOf(u8, status, \"Triggers-Awaited:\") != null or",
                "std.mem.indexOf(u8, status, \"Triggers-Pending:\") != null",
                ".acknowledge = true,",
            },
        },
        .{
            .start = "fn corruptedOrdinary(",
            .end = "\nfn caseRun(",
            .tokens = &.{
                ".no_scripts = corruption != .completed_phase,",
                ".scripts = .{ .only_postinst = corruption == .completed_phase },",
                "if (artifact != null) return error.DuplicateRetainedArtifact;",
                "raw[0] = 'X';",
                "\"corrupt\\n\"",
                "\"external replacement\\n\"",
                "try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, root));",
                "try same(try stickyActiveClaim(fixture, root), original_claim);",
                "try unchanged(fixture, root, package_before);",
                "try sameHelper(fixture, root, helper_before);",
            },
        },
    }) |bt| {
        const body = splitAfterAndBefore(helper, bt.start, bt.end);
        for (bt.tokens) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: final real-process case lost {s}", .{token}));
            }
        }
        if (std.mem.eql(u8, bt.start, "fn blockedUnknown(") or std.mem.eql(u8, bt.start, "fn corruptedOrdinary(")) {
            const root_expr = if (std.mem.eql(u8, bt.start, "fn blockedUnknown(")) "scenario.native_root" else "root";
            const sticky = try std.fmt.allocPrint(allocator, "try same(try stickyActiveClaim(fixture, {s}), original_claim);", .{root_expr});
            if (countSubstring(body, sticky) != 3) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: initial, repeat and blocked sticky claim checks lost {s}", .{sticky}));
            }
        }
    }

    for ([_][]const u8{
        "only_postinst: bool = false,",
        "if (options.only_postinst and !std.mem.eql(u8, kind, \"postinst\")) continue;",
    }) |token| {
        if (std.mem.indexOf(u8, support, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_lifecycle_support.zig: postinst-only corruption fixture lost {s}", .{token}));
        }
    }

    if (std.mem.indexOf(u8, unpack, "var preexisting = try completion_store.read(allocator);") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "native_unpack.zig: proof-bound completion must read the original receipt"));
    }
    const production = splitAfterAndBefore(
        unpack,
        "var preexisting = try completion_store.read(allocator);",
        "if (record.provenance == .pending)",
    );
    for ([_][]const u8{
        "previous.bindsRecord(record)",
        "record.provenance == .published",
        "record.generation - previous.record_generation != 1",
        "record.provenance_sha256 == null",
        "root_operation.provenanceDigest(record, .{",
        ".document_sha256 = previous.digest_sha256,",
        "!std.mem.eql(u8, &record.provenance_sha256.?, &published_digest)",
        "!std.mem.eql(u8, prior_evidence, current_evidence)",
        "if (!retained_completion) try completion_store.publish(allocator, statement.document);",
    }) |token| {
        if (std.mem.indexOf(u8, production, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_unpack.zig: proof-bound post-provenance completion lost {s}", .{token}));
        }
    }

    const completion_read = splitAfterAndBefore(unpack, "fn readProductionCompletion(", "\nfn ");
    for ([_][]const u8{
        "nativeAction(.provenance, std.math.maxInt(u32), 0, 0),\n    ) orelse return error.InvalidRecoveryProvenance;",
        "if (terminal.stage != .terminal or switch (receipt.document.outcome) {",
        ".succeeded => terminal.result != .succeeded and terminal.result != .recovered,",
        ".failed => terminal.result != .failed,",
        ".recovery_required => true,\n    }) return error.InvalidRecoveryProvenance;",
    }) |token| {
        if (std.mem.indexOf(u8, completion_read, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_unpack.zig: terminal receipt must bind retained terminal provenance progress lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "if (!std.mem.eql(u8, &retained_progress.document.head_sha256, &receipt.document.progress_head_sha256) or\n" ++
            "        retained_progress.document.records.len != receipt.document.progress_record_count)\n" ++
            "        return error.InvalidRecoveryProgress;",
        "try native_provenance.verifyScriptOutcomes(receipt.document, retained_progress.document);",
    }) |token| {
        if (std.mem.indexOf(u8, completion_read, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_unpack.zig: terminal receipt must bind retained script outcomes lost {s}", .{token}));
        }
    }
    if (std.mem.indexOf(u8, splitAfterAndBefore(unpack, "fn callerOwnedLifecycleFixture(", "\nfn "), ") catch |err| return .{ .outcome = .refused, .detail = @errorName(err) };") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "native_unpack.zig: caller lifecycle verification must report typed refusals"));
    }
    for ([_][]const u8{
        "try completedScriptComponents(&fixture, driver, reference.executable, reference.architecture);",
        ".name = \"caller-script-components-recovered\",\n" ++
            "        .crash = \"after_script_outcome\",\n" ++
            "        .caller_owned = true,\n" ++
            "        .isolated_helper = true,\n" ++
            "        .script_components = true,",
    }) |token| {
        if (std.mem.indexOf(u8, main_body, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: completed and recovered script component matrices lost {s}", .{token}));
        }
    }
    if (std.mem.indexOf(u8, splitAfterAndBefore(helper, "\nfn recoveredOrdinary(", "\n}\n"), "try callerScriptComponents(fixture, driver, root, arch, case.name, true);") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_helper.zig: recovered attempts lost the script component matrix"));
    }
    if (std.mem.indexOf(u8, splitAfterAndBefore(helper, "\nfn completedScriptComponents(", "\nfn "), "try callerScriptComponents(fixture, driver, root, arch, name, false);") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_helper.zig: completed attempts lost the script component matrix"));
    }
    const scripts = splitAfterAndBefore(helper, "\nfn callerScriptComponents(", "\nfn ");
    for ([_][]const u8{
        "if (recovered != (receipt.document.recovered_phase_count != 0)) return error.UnexpectedRecoveredPhaseCount;",
        "\"changed-script_outcome-{d}\"",
        "\"EvidenceChanged\"",
        "\"deleted-script_outcome-{d}\"",
        "\"FileNotFound\"",
        "if (scripts < 2) return error.MissingRetainedScriptOutcome;",
        "for (std.enums.values(ScriptReceiptTamper)) |tamper| {",
        "break :omitted \"EvidenceMissing\";",
        "break :duplicated \"InvalidRecoveryProgress\";",
        "break :rebound \"EvidenceMismatch\";",
        "break :reindexed \"EvidenceMissing\";",
        "break :summary \"EvidenceMismatch\";",
        "break :phases \"InvalidRecoveryProgress\";",
        "break :head \"InvalidRecoveryProgress\";",
        "forged.evidence_files_sha256 = provenance.evidenceDigest(forged.evidence_files);",
    }) |token| {
        if (std.mem.indexOf(u8, scripts, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: script component tamper matrix lost {s}", .{token}));
        }
    }
    const refused = splitAfterAndBefore(helper, "\nfn scriptComponentRefused(", "\nfn ");
    for ([_][]const u8{
        "        .caller_verification = expected_receipt,\n    }), \"refused\", expected_error);",
        "        .acknowledge = true,\n    }), \"recovery_required\", expected_error);",
    }) |token| {
        if (std.mem.indexOf(u8, refused, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_helper.zig: script component refusal lost {s}", .{token}));
        }
    }
    if (countSubstring(refused, "try held.owed(fixture, root, receipt);") != 2) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_helper.zig: script component refusals must leave the attempt owed after verification and recovery"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeEntryPointShapeFailures(
    allocator: std.mem.Allocator,
    core: []const u8,
    projected: []const u8,
    ci: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{
        "const archive = try support.makePackage(fixture, arch, \"1\", foundation.package, packages, .{});",
        "const archive = try support.makePackage(fixture, arch, \"1\", foundation.package, \"deadline-startup/packages\", .{});",
        "const archive = try support.makePackage(fixture, arch, \"1\", foundation.package, \"deadline-persisted/packages\", .{});",
        "try support.scripts(fixture, source, foundation.package, \"1\");",
        "try rootAbsent(fixture, root, \"config-invoked\");",
        "try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, guarded), typed_proof.document);",
        "var request = try debz.native_execution_request.decodePersisted(fixture.allocator, request_bytes);",
        "if (scripts == 0) return error.MissingCoreScriptOutcome;",
        "try debz.native_recovery.validateScriptOutcome(outcome.value);",
        "try oracle.validateHelperInvocation(fixture.allocator, root, helper.source_path, helper.target_path, helper.sha256,",
        "try oracle.validateScriptTrace(fixture.allocator, trace, &invocations);",
        "if (!std.mem.eql(u8, before, try evidenceInventory(fixture, root, true)))",
    }) |token| {
        const source = if (std.mem.indexOf(u8, token, "evidenceInventory") != null) projected else core;
        const is_doubled = std.mem.endsWith(u8, token, "foundation.package, packages, .{});") or
            std.mem.endsWith(u8, token, "var request = try debz.native_execution_request.decodePersisted(fixture.allocator, request_bytes);") or
            std.mem.endsWith(u8, token, "try debz.native_recovery.validateScriptOutcome(outcome.value);") or
            std.mem.endsWith(u8, token, "try oracle.validateHelperInvocation(fixture.allocator, root, helper.source_path, helper.target_path, helper.sha256,");
        const needed: usize = if (is_doubled) 2 else 1;
        if (countSubstring(source, token) < needed) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "Zig recovery entry point: required executed shape check lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "try readOnlyProjection(fixture, runner, driver, arch);",
        "DEBZ_NATIVE_PROJECTION_FIXTURE=1",
        "native_transaction_result.test.projected root external fixture...OK",
        "apt_system_orchestrator.test.projected native dispatch external fixture...OK",
    }) |token| {
        if (std.mem.indexOf(u8, projected, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "projected recovery entry point: read-only child lost {s}", .{token}));
        }
    }
    for (try recoveryZigCommands(allocator, &.{"test-native-recovery-zig"}, false)) |command| {
        const expected_line = try std.fmt.allocPrint(allocator, "          {s}", .{command});
        var matches: usize = 0;
        var it = std.mem.splitScalar(u8, ci, '\n');
        while (it.next()) |line| {
            if (std.mem.eql(u8, line, expected_line)) matches += 1;
        }
        if (matches != 1) {
            try failures.append(allocator, try allocator.dupe(u8, "ci.yml: both sharded core recovery entry-point modes must execute exactly once"));
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeConsumerReceiptWiringFailures(
    allocator: std.mem.Allocator,
    parity: []const u8,
    evidence: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{
        "const retained = @import(\"native_recovery_parity_evidence.zig\");",
        "try retained.verify(fixture, root, arch, digest, case.exit_status != 0);",
        "try support.absent(fixture, try relative(fixture, root, completion_path));",
        "return error.HeldConsumerMutatedRoot;",
        "try verifyFifoLock(fixture, signed.repository, lock.lock, version, fifos);",
        "try fifoReceipt(fixture, scenario.native_root, arch, lock_relative);",
        "try support.compare(fixture, scenario.reference_root, scenario.native_root, remove_compare, true);",
        "try fifoReceipt(fixture, scenario.native_root, arch, remove_relative);",
        "try scenario.phase(.{ .operation = \"purge\", .packages = &selected }, false);",
        "if (fifo_closures != oracle.parity_suites.len) return error.MissingSignedFifoClosure;",
    }) |token| {
        if (std.mem.indexOf(u8, parity, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_parity.zig: required per-case receipt check lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "try debz.native_provenance.verifyEvidence(allocator, root, proof);",
        "try manifestDocument(entry, intent.?.intent.digest_sha256);",
        "try manifestDocument(entry, progress.?.document.digest_sha256);",
        "try manifestDocument(entry, managed.?.document.digest_sha256);",
        "try manifestDocument(entry, triggers.?.document.digest_sha256);",
        "try manifestDocument(entry, script.digest_sha256);",
        "try equal(&proof.request_sha256, &caller.caller.request_sha256);",
        "try oracle.validateHelperInvocation(",
        "try scriptTrace(allocator, root, scripts.items);",
        "try finalDatabase(allocator, root, architecture, proof);",
        "const generation = try database.generation(allocator, snapshot);",
        "try equal(&std.fmt.bytesToHex(sink.hasher.finalResult(), .lower), &proof.final_state_sha256);",
    }) |token| {
        if (std.mem.indexOf(u8, evidence, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_parity_evidence.zig: required retained evidence check lost {s}", .{token}));
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeRepositoryEvidenceWiringFailures(
    allocator: std.mem.Allocator,
    source: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{
        "try terminalEvidence(fixture, root, relative, case, resuming, logical, retained_bytes, helper_before.?);",
        "try parity_evidence.verifyProjected(fixture, root, debz.live_root.logical_root_path, state.state.architecture,",
        "try managedFiles(fixture, root, state.state, manifest.manifest);",
        "completion.discharge.request_sha256, &expected_discharge",
        "try oracle.validateHelperInvocation(",
        "if (script_count != 2) return error.MissingRepositoryScripts;",
        "if (preserved.value.len != 8) return error.RepositoryHistoryEvidenceChanged;",
        "try unchangedBindings(fixture, root, state.state, abandoned.record, publisher.record);",
        "try unchangedEvidence(fixture, bytes);",
        "try checkpointAt(fixture, root, checkpoint);",
        "try checkHelper(fixture, root, original_helper orelse return error.MissingRepositoryHelper);",
        "lock.lock.packages.len != 1 or !lock.lock.packages[0].dpkg_selection_hold",
        "if (first.exit_status == .success) return error.RepositoryDispatchIgnoredInterruption;",
        "try scanQuerySecret(fixture.io, fixture.dir, path);",
        "const count = reader.interface.readSliceShort(buffer[overlap .. overlap + 64 * 1024]) catch return reader.err.?;",
        "if (std.mem.indexOf(u8, buffer[0 .. overlap + count], secret) != null)",
        "std.mem.copyForwards(u8, buffer[0..next_overlap], buffer[end - next_overlap .. end]);",
        "if (scanned != before.size or before.size != after.size or before.inode != after.inode)",
        "test \"repository network evidence scans large files and split secrets\"",
        "for ([_]usize{ 64 * 1024 - 7, 2 * 1024 * 1024 + 64 * 1024 - 7 }) |offset|",
        "try std.testing.expectError(error.NetworkFixtureLeakedCredential, assertNoQuerySecret(&fixture, root));",
    }) |token| {
        if (std.mem.indexOf(u8, source, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_repository.zig: required executed repository evidence lost {s}", .{token}));
        }
    }
    const deadline_case = partitionAfterAndBefore(source, "fn cliScenario(", "\nfn cliCase(");
    for ([_][]const u8{
        "else if (std.mem.eql(u8, case, \"deadline\")) \"15000\" else \"60000\"",
        "(std.mem.eql(u8, case, \"deadline\") and elapsed >= 20000)",
    }) |token| {
        if (std.mem.indexOf(u8, deadline_case, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_repository.zig: bounded blocked-postinst deadline lost {s}", .{token}));
        }
    }
    const diagnostic = partitionAfterAndBefore(source, "fn verifyCliScenario(", "\nfn cliScenario(");
    for ([_][]const u8{
        "if (first.diagnostic_count == 0 or first.diagnostics[0].id != .resource_limit_exceeded)",
        "std.debug.print(\"repository CLI {s}: exit={s}, diagnostic={s}; expected resource limit\\n\", .{",
        "return error.InvalidRepositoryDeadlineDiagnostic;",
    }) |token| {
        if (std.mem.indexOf(u8, diagnostic, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_repository.zig: deadline refusal diagnostic lost {s}", .{token}));
        }
    }
    if (std.mem.indexOf(u8, source, "try std.testing.expectEqual(@as(u64, 20), try cliWatchdog(&.{ \"--deadline-ms\", \"15000\" }, 0, \"deadline\"));") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_repository.zig: deadline watchdog regression lost"));
    }
    for ([_][]const u8{
        "const limit_seconds: i64 = if (std.mem.eql(u8, name, \"repository-execution-success\")) 240 else 120;",
        "const progress_ceiling_factor = 2;",
        "const ceiling_seconds = if (progress_watched) limit_seconds * progress_ceiling_factor else limit_seconds;",
        "if (stalled_ms == null and elapsed >= deadline_ms and deadline_ms < ceiling_seconds * 1000) {",
        "previous = snapshotProcessTree(fixture, name, log, pid, deadline_ms, elapsed, host_before, previous);",
        "const timed_out = stalled_ms != null or term == .exited and term.exited == 124 or wall_ms >= ceiling_seconds * 1000;",
        "reportRunner(init.io, allocator);",
        "test \"repository watchdog bounds time between fixture passes by a fixed ceiling\"",
        "test \"repository watchdog samples a blocked child tree and host CPU\"",
    }) |token| {
        if (std.mem.indexOf(u8, source, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_repository.zig: bounded progress watchdog or its diagnostics lost {s}", .{token}));
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeWorkflowAcceptanceWiringFailures(
    allocator: std.mem.Allocator,
    build: []const u8,
    family: []const u8,
    projected: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{
        "recovery_family.addArtifactArg(recovery_family_executable);",
        "recovery_family.addArg(\"--self\");",
        "recovery_family.addArtifactArg(native_lifecycle_tests);",
        "recovery_family.addArg(\"--cli\");",
        "recovery_family.addArtifactArg(cli);",
    }) |token| {
        if (std.mem.indexOf(u8, build, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: required signed workflow acceptance lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "if (std.mem.eql(u8, driver, \"--inside-projected\"))",
        "return projected.inside(init, allocator, root);",
        "try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);",
        "try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, true);",
        "try ordinaryFamilyTimeline(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try verificationRefusals(fixture, driver, request, returned, original_summary, \"executed\");",
        "try verificationRefusals(fixture, driver, original, first_completion, summary, name);",
        "const no_result_path = try support.path(fixture.allocator, name, \"verify-first-without-result\");",
        "const equivalent_path = try support.path(fixture.allocator, name, \"verify-create-as-customize\");",
        "try assertFamilySummary(fixture, driver, original, first_completion, summary, try support.path(fixture.allocator, name, \"verify-final\"));",
        "try batchWorkflow(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        "try ownedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ordinaryKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try publicVerify(fixture, cli, scenario.native_root, lock, arch, \"executed/workflow-batch/verify-after-refusals\", true);",
        "try reconciliation(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try ordinaryRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        "try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, \"verify-public-recovered\"), true);",
        "try ownedRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedFinalizationBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try projected.run(&fixture, self orelse return error.MissingSelf, driver, reference.executable, reference.architecture);",
        "try assertFamilySummary(fixture, driver, request, completion, summary, try support.path(fixture.allocator, prefix, \"refuse-unsettled-verified-again\"));",
        "const root_before = try projected.rootInventory(fixture, request.root, true);",
        "const pending_evidence = try projected.rootInventory(fixture, scenario.native_root, true);",
        "const before_evidence = try projected.rootInventory(fixture, update.native_root, true);",
        "\"executed/{s}-verify-without-result\"",
        "\"executed/{s}-verify-as-install\"",
        "const failed_evidence = try projected.rootInventory(fixture, scenario.native_root, true);",
        ".force = invocation.force,",
        "\"wrong-conffile\"",
        "\"{s}/replacement-{s}\"",
        "\"changed-request\"",
        "\"verify-damaged-{s}\"",
        "\"verify-unresolved-{s}\"",
        "\"verify-partial-acknowledgment\"",
        "\"acknowledge-damaged-receipt\"",
        "\"verify-public-owner-retained\"",
        "\"verify-terminal-foreign-attempt\"",
        "\"verify-public-pending\"",
        "\"verify-public-native-acknowledged\"",
        "\"verify-public-pending-failure\"",
        "\"verify-public-failed-acknowledgment\"",
        "\"verify-public-final-failure\"",
        "\"verify-success-as-failure\"",
        "\"verify-pending-as-released\"",
        "\"executed/workflow-owned-success/verify-finalized-as-released\"",
        "try inspectInstalledFamily(fixture, driver, scenario.native_root, arch, \"executed/inspect-initial\", \"essential-core\", true, false);",
        "\"executed/inspect-while-root-lock-held\"",
        "\"executed/inspect-failed-same-root\"",
        "\"executed/missing-helper-inspection\"",
        "const reference_failure = \"executed/same-root-failure-reference\";",
        "linux.flock(holder.handle, 2 | 4)",
        "\"verify-before-execution\"",
        "\"verify-failed-result\"",
        "\"verify-relabeled-failure\"",
        "\"verify-failed-without-result\"",
        "\"ordinary-to-FAMILY same-root timeline: signed success, full verification refusals, failed install and clean recovery matched pinned dpkg",
        "\"semantic request\") == null",
        "try std.testing.expectEqual(@as(i64, 3), (try field(update_lock_document.value, \"version\")).integer);",
        "try std.testing.expectEqual(@as(usize, 24), parsed.value.object.count());",
        "try std.testing.expectEqual(@as(usize, 13), capability.value.object.count());",
        "try std.testing.expectEqual(@as(usize, 24), verified.report.value.object.count());",
        "try std.testing.expectEqual(@as(i64, 3), (try field(install_lock.value, \"version\")).integer);",
    }) |token| {
        if (std.mem.indexOf(u8, family, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_family.zig: required signed workflow acceptance lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "const source = try fixture.absolute(\"executed/workflow.sources\");\n    const keyring = try fixture.absolute(\"executed/repository/fixture-keyring.gpg\");\n    var phase_arena: std.heap.ArenaAllocator = .init(init.gpa);",
        "fixture.allocator = phase_arena.allocator();",
        "defer fixture.allocator = allocator;",
        "const lock = try persistent_allocator.dupe(u8, try fixture.absolute(\"executed/lock.json\"));",
        "first_completion = try std.json.parseFromSlice(std.json.Value, persistent_allocator,",
        "    for ([_]bool{ true, false }) |selected| {\n        _ = phase_arena.reset(.free_all);",
    }) |token| {
        if (std.mem.indexOf(u8, family, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_family.zig: bounded signed workflow allocation lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "try refusals(&fixture, reference.architecture);",
        "try transport(&fixture, driver, reference.architecture);",
        "try planning(&fixture, driver);",
        "try activeInspection(&fixture, driver, reference.architecture);",
        "try archiveExecution(&fixture, allocator, &phase_arena, driver, helper orelse return error.MissingHelper, reference.executable, reference.architecture, source, keyring);",
        "try ordinaryFamilyTimeline(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try batchWorkflow(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        "try ownedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try reconciliation(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try ordinaryRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        "try ordinaryKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedAbandon(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try ownedRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedFinalizationBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try projected.run(&fixture, self orelse return error.MissingSelf, driver, reference.executable, reference.architecture);",
        "try missingHelper(&fixture, driver, reference.executable, reference.architecture);",
        "try failedTransaction(&fixture, driver, reference.executable, reference.architecture, false);",
    }) |token| {
        const opt1 = try std.fmt.allocPrint(allocator, "{s}\n    _ = phase_arena.reset(.free_all);", .{token});
        const opt2 = try std.fmt.allocPrint(allocator, "{s}\n        _ = phase_arena.reset(.free_all);", .{token});
        if (std.mem.indexOf(u8, family, opt1) == null and std.mem.indexOf(u8, family, opt2) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_family.zig: scenario allocations retained after {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "    }\n    _ = phase_arena.reset(.free_all);\n    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);",
        "try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);\n    _ = phase_arena.reset(.free_all);\n    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, true);",
    }) |token| {
        if (std.mem.indexOf(u8, family, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_family.zig: interrupted signed workflow allocations retained after {s}", .{token}));
        }
    }
    if (countSubstring(family, "try referenceSingleFailure(fixture, reference, scenario.reference_root, arch, name)") != 2) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_family.zig: both failed workflows require single-invocation pinned dpkg parity"));
    }
    if (countSubstring(family, "\"verify-public-finalized\"") != 2) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_family.zig: pending recovery and terminal-owner finalization require public CLI proof"));
    }
    if (countSubstring(family, "try support.compare(fixture, scenario.reference_root, scenario.native_root, \"executed/same-root-failure-comparison\", true);") != 2) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_family.zig: same-root failed customize must preserve pinned dpkg parity through recovery"));
    }
    for ([_][]const u8{
        "for ([_][]const u8{ \"success\", \"recovered\", \"failed\" }) |outcome|",
        "\"/usr/bin/unshare\", \"--mount\", \"--pid\", \"--fork\"",
        "if (linux.errno(linux.execve(\"/fixture/native-test\", &argv, envp.ptr)) != .SUCCESS)",
        ".prepare_acknowledged_review = .{ .lock_sha256 = lock_digest, .generation = 6 },",
        ".prepare_cleared_review = .{ .lock_sha256 = lock_digest, .receipt_sha256 = receipt_digest, .generation = 8 },",
        "const evidence_before = if (step.verification) |check|",
        "const review_baseline = try evidenceInventory(fixture, scenario.native_root, false);",
        "return inventory(fixture, root, \".\", include_metadata);",
        "const damaged_state = try evidenceInventory(fixture, scenario.native_root, true);",
        "const orphan_state = try evidenceInventory(fixture, scenario.native_root, true);",
        "try std.testing.expectEqual(@as(i64, 2), (try field(owner_v2.value, \"version\")).integer);",
        "try support.absent(fixture, withheld_operation);",
    }) |token| {
        if (std.mem.indexOf(u8, projected, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_projected_workflows.zig: private projected workflow execution lost {s}", .{token}));
        }
    }
    if (countSubstring(projected, "\"/usr/bin/unshare\", \"--mount\", \"--pid\", \"--fork\"") != 2) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_projected_workflows.zig: read-only and signed workflow children both require private PID/mount projections"));
    }
    const components = splitAfterAndBefore(family, "\nfn ownedComponents(", "\nfn ");
    for ([_][]const u8{
        "const retained_kinds = [_]provenance.EvidenceKind{ .authorization, .program, .execution_request, .intent, .progress, .managed_state, .trigger_events, .script_outcome };",
        "if (!observed_kinds.contains(kind) and (kind != .script_outcome or check.scripts))",
        "\"retained-{s}-{d}\"",
        "\"EvidenceChanged\"",
        "outcome_other_terminal,\n        outcome_recovery_required,",
        "final_database_generation,\n        final_state,",
        "if (check.outcome == .failed) \"TransactionNotFailed\" else \"TransactionNotSuccessful\"",
        "else => \"EvidenceMismatch\",",
        ".expected_error = \"ReceiptMissing\"",
        ".expected_error = \"CompletionMissing\"",
        ".expected_error = \"OwnershipMismatch\"",
        "\"live-payload-bytes\", selected, lock, check, \"LivePayloadChanged\"",
        "\"live-payload-removed\", selected, lock, check, \"LivePayloadChanged\"",
        "\"administrator-conffile-edit\", selected, lock, check",
        "\"receipt-script_outcome-duplicated\" else \"receipt-script_outcome-omitted\"",
    }) |token| {
        if (std.mem.indexOf(u8, components, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_family.zig: owned component tamper matrix lost {s}", .{token}));
        }
    }
    for ([_][]const u8{
        "        .state = \"released\",\n        .outcome = .succeeded,\n        .scripts = false,",
        "        .state = \"released\",\n        .outcome = .succeeded,\n        .scripts = true,",
        "        .state = \"pending\",\n        .outcome = .failed,\n        .scripts = true,",
    }) |token| {
        if (std.mem.indexOf(u8, family, "    try ownedComponents(fixture, driver, &scenario, arch, name, selected, lock, .{\n        .owner_evidence = ") == null or
            std.mem.indexOf(u8, family, token) == null)
        {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_recovery_family.zig: owned success and failed attempts require component tamper coverage lost {s}", .{token}));
        }
    }
    if (countSubstring(family, "    try ownedComponents(fixture, driver, &scenario, arch, name, selected, lock, .{") != 3) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_family.zig: owned success, scripted success and failed attempts all require the component tamper matrix"));
    }
    if (std.mem.indexOf(u8, family, "    try ownedScriptedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "native_recovery_family.zig: owned scripted success no longer runs"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeProvenanceBindingWiringFailures(
    allocator: std.mem.Allocator,
    build: []const u8,
    e2e: []const u8,
    binding: []const u8,
    transaction: []const u8,
    repository: []const u8,
    recovery: []const u8,
    unpack: []const u8,
    production: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    if (std.mem.indexOf(u8, build, "            \"native_provenance_binding.test.\",\n        },\n    });\n    const run_sha512_e2e_tests = b.addRunArtifact(sha512_e2e_tests);") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: hermetic native provenance binding tests lost their sha512 e2e filter"));
    }
    if (std.mem.indexOf(u8, build, "    workload_native.dependOn(&run_sha512_e2e_tests.step);") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: hermetic native provenance binding tests lost required test wiring"));
    }
    if (std.mem.indexOf(u8, e2e, "test {\n    _ = @import(\"native_provenance_binding_test.zig\");\n}") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "sha512_transaction_e2e_test.zig: hermetic native provenance binding tests are no longer imported"));
    }
    for ([_][]const u8{
        "test \"native_provenance_binding.test.completed attempt binds every acceptance component\" {",
        "test \"native_provenance_binding.test.recovered attempt binds every acceptance component\" {",
        "test \"native_provenance_binding.test.recovery_required attempt keeps typed evidence without success-shaped settlement\" {",
        "try testing.expect(settled.recovered_phase_count >= 1);",
        "for ([_]native_provenance.Outcome{ .succeeded, .failed }) |outcome| {",
        "\"receipt.evidence_files[{s}] omitted\"",
        "\"retained {s} bytes\"",
        "\"completion.transaction_provenance=provenanceDigest\"",
        "\"live pending trigger claim\"",
        "\"deferred owner reinstated\"",
        "try testing.expect(!std.mem.eql(u8, &receipt_digest, &provenance_digest));",
        "\"live payload bytes\", error.LivePayloadChanged",
        "\"live payload removed\", error.LivePayloadChanged",
        "for (std.enums.values(PayloadReplacement)) |replacement|",
        "\"caller verify of live payload\", error.LivePayloadChanged",
        "try expectCallerPayloadBound(env, attempt, receipt.digest_sha256);",
        "native_transaction_result.verifyCallerSuccessReporting(allocator, attempt, receipt_digest, &change),",
        "try testing.expectEqualStrings(\"demo\", owner.package);",
        "try testing.expectEqualStrings(\"1.0\", owner.version);",
    }) |token| {
        if (std.mem.indexOf(u8, binding, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_provenance_binding_test.zig: component tamper coverage lost {s}", .{token}));
        }
    }
    for ([_][]const u8{ "try tamperSettled(&env, &settled);", "try env.expectSecondOperationRefused();" }) |token| {
        if (countSubstring(binding, token) != 2) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_provenance_binding_test.zig: completed/recovered and recovery_required coverage requires two {s}", .{token}));
        }
    }
    const state = splitAfterAndBefore(transaction, "\nfn verifyStateEvidence(", "\nfn ");
    for ([_][]const u8{
        "        &route_conffiles,\n    );",
        "    _ = try native_runtime.verifySettledPayload(\n        allocator,\n        root,\n        program.program,\n        managed.document,\n        route_conffiles.items,\n        payload_change,\n    );\n}",
    }) |token| {
        if (std.mem.indexOf(u8, state, token) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_transaction_result.zig: settled verification must bind the live managed payload lost {s}", .{token}));
        }
    }
    const caller = splitAfterAndBefore(transaction, "\nfn verifyCaller(", "\nfn ");
    if (std.mem.indexOf(u8, caller, "        null,\n        payload_change,\n    );\n    try verifyPendingEvidence(allocator, root, proof);") == null) {
        try failures.append(allocator, try allocator.dupe(u8, "native_transaction_result.zig: held caller verification must describe a changed live payload"));
    }

    const RecCheck = struct { start: []const u8, end: []const u8, tokens: []const []const u8, message: []const u8 };
    for ([_]RecCheck{
        .{
            .start = "\npub fn verifySettledManagedStateReporting(",
            .end = "\n}\n",
            .tokens = &.{"            if (change) |out| out.* = SettledPayloadChange.init(allocator, expected, reason) catch null;"},
            .message = "native_recovery.zig: a changed live payload must be described",
        },
        .{
            .start = "\ntest \"native_recovery.test.settled managed state binds live payload kind, mode and bytes\" {",
            .end = "\n}\n",
            .tokens = &.{
                "try testing.expectEqual(expected.reason, found.reason);",
                "try testing.expectEqualSlices(u8, &hexDigest(bytes_digest), &found.expected_sha256.?);",
                "try testing.expectEqual(found.reason, parsed.value.reason);",
            },
            .message = "native_recovery.zig: live payload change description coverage lost",
        },
    }) |rc| {
        const body = splitAfterAndBefore(recovery, rc.start, rc.end);
        for (rc.tokens) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s} {s}", .{ rc.message, token }));
            }
        }
    }

    const UnpackCheck = struct { start: []const u8, tokens: []const []const u8 };
    for ([_]UnpackCheck{
        .{
            .start = "\n    pub fn verifySettledPayload(",
            .tokens = &.{"                describeSettledPayloadOwner(allocator, root, program.target_architecture, found) catch {};"},
        },
        .{
            .start = "\n    fn describeSettledPayloadOwner(",
            .tokens = &.{
                "        const owners = ownership.ownersOf(change.path);",
                "        if (owners.len != 1) return;",
            },
        },
    }) |uc| {
        const body = splitAfterAndBefore(unpack, uc.start, "\n    }\n");
        for (uc.tokens) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(allocator, try std.fmt.allocPrint(allocator, "native_unpack.zig: a changed live payload must name its installed owner lost {s}", .{token}));
            }
        }
    }

    const ProdCheck = struct { start: []const u8, end: []const u8, tokens: []const []const u8 };
    for ([_]ProdCheck{
        .{
            .start = "\n    fn recoverNative(",
            .end = "\n    fn ",
            .tokens = &.{"                .add => return repositoryOwnedRecovery(.recover, attempt.record(), repository_recovery_resume),"},
        },
        .{
            .start = "\nfn repositoryOwnedRecovery(",
            .end = "\nfn ",
            .tokens = &.{
                "        .surface = .repository_bootstrap,",
                "        .resume_path = .rerun_same_repository_add,",
            },
        },
        .{
            .start = "\ntest \"production native recovery names the repository bootstrap that owns a held attempt\" {",
            .end = "\n}\n",
            .tokens = &.{
                "try std.testing.expectEqual(api.RecoveryOwner.Surface.repository_bootstrap, owner.surface);",
                "try std.testing.expectEqual(api.RecoveryOwner.ResumePath.rerun_same_repository_add, owner.resume_path);",
                "try std.testing.expectEqualStrings(before, after);",
            },
        },
    }) |pc| {
        const body = splitAfterAndBefore(production, pc.start, pc.end);
        for (pc.tokens) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "production_backend.zig: recovery of a repository-owned attempt must name its surface and resume path lost {s}", .{token}),
                );
            }
        }
    }

    for ([_]UnpackCheck{
        .{
            .start = "\nfn nativeRepositoryCheckpointLoaded(",
            .tokens = &.{
                "    var package_state = verifyNativePackageStateReporting(allocator, input, &payload_change) catch |err| {",
                "        if (err == error.LivePayloadChanged)\n            return refuseNativeLivePayload(allocator, input, observer, stage, original, err, if (payload_change) |*change| change else null);",
            },
        },
        .{
            .start = "\nfn refuseNativeLivePayload(",
            .tokens = &.{
                "    if (retained.receipt.document.outcome != .succeeded or !nativeStageImports(stage, prior.phase)) return cause;",
                "    publication.persist(allocator, current.state, original.paths) catch |err| return err;",
                "    const detail: ?[]u8 = if (payload_change) |change| (change.diagnostic(allocator) catch null) else null;",
                "    return publication.failMessage(allocator, &current, original.paths, .installed_verification_failed, cause, detail orelse @errorName(cause));",
            },
        },
        .{
            .start = "\nfn testProjectedNativeImport(",
            .tokens = &.{
                "try std.testing.expectError(error.LivePayloadChanged, importAndRefreshNative(allocator, input, reporting));",
                "try std.testing.expectEqual(api.DiagnosticId.installed_verification_failed, reported.diagnostics[0].id);",
                "try expectLivePayloadDiagnostic(allocator, reported.diagnostics[0].message, state.state.managed_files[0], state.state.descriptor.?);",
                "try std.testing.expectError(error.LivePayloadChanged, completeNative(allocator, input));",
                "try std.testing.expectEqual(root_operation.ProvenanceState.pending, attempt.record().provenance);",
                "try std.testing.expectEqual(api.DiagnosticId.installed_verification_failed, failed.state.diagnostic_id.?);",
                "try expectLivePayloadDiagnostic(allocator, failed.state.diagnostic, state.state.managed_files[0], state.state.descriptor.?);",
            },
        },
        .{
            .start = "\nfn expectLivePayloadDiagnostic(",
            .tokens = &.{
                "    var parsed = try native_recovery.parseSettledPayloadDiagnostic(allocator, message);",
                "    try std.testing.expectEqualStrings(removed.logical_path[1..], fields.path);",
                "    try std.testing.expectEqualStrings(&expected_sha256, fields.expected_sha256.?);",
                "    try std.testing.expectEqualStrings(descriptor.package, fields.package.?);",
                "    try std.testing.expectEqualStrings(descriptor.version, fields.version.?);",
            },
        },
    }) |rc| {
        const body = splitAfterAndBefore(repository, rc.start, "\nfn ");
        for (rc.tokens) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "repository_backend.zig: repository add must record a changed live payload as installed_verification_failed lost {s}", .{token}),
                );
            }
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub const GHR_ZIG_INSTALL =
    "      - name: Install Zig via ghr\n" ++
    "        uses: cataggar/ghr/actions/install@c4be68b52d67d7acd2a7fe6c1e5f126e1754176e # v0.8.1\n" ++
    "        env:\n" ++
    "          GH_TOKEN: ${{ github.token }}\n" ++
    "        with:\n" ++
    "          ghr-version: v0.8.1\n" ++
    "          tools: >-\n" ++
    "            cataggar/zig@v0.17.0\n" ++
    "            RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U\n" ++
    "      - name: Validate Zig version\n" ++
    "        run: test \"$(zig version)\" = 0.17.0\n";

pub const CI_CONCURRENCY =
    "concurrency:\n" ++
    "  group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.event.pull_request.number || github.event_name == 'push' && github.ref || github.run_id }}\n" ++
    "  cancel-in-progress: ${{ github.event_name == 'push' || github.event_name == 'pull_request' }}\n";

pub fn ciConcurrencyFailures(allocator: std.mem.Allocator, text: []const u8, label: []const u8) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    if (countSubstring(text, CI_CONCURRENCY) != 1) {
        try failures.append(
            allocator,
            try std.fmt.allocPrint(allocator, "{s}: CI concurrency must exactly isolate push, pull_request, schedule, and workflow_dispatch runs", .{label}),
        );
    }
    const target_seq = "\n\n" ++ CI_CONCURRENCY ++ "\npermissions:\n";
    var top_level_ok = false;
    if (std.mem.indexOf(u8, text, target_seq)) |seq_idx| {
        const before = text[0..seq_idx];
        if (std.mem.startsWith(u8, before, "on:\n") or std.mem.indexOf(u8, before, "\non:\n") != null) {
            top_level_ok = true;
        }
    }
    if (!top_level_ok) {
        try failures.append(
            allocator,
            try std.fmt.allocPrint(allocator, "{s}: CI concurrency must be a top-level workflow policy before permissions", .{label}),
        );
    }
    return failures.toOwnedSlice(allocator);
}

pub fn ghrZigWorkflowFailures(
    allocator: std.mem.Allocator,
    text: []const u8,
    label: []const u8,
    expected_count: usize,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    if (std.mem.indexOf(u8, text, "mlugg/setup-zig") != null or std.mem.indexOf(u8, text, "use-cache:") != null) {
        try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: obsolete setup-zig installation or cache input remains", .{label}));
    }
    const count = countSubstring(text, GHR_ZIG_INSTALL);
    if (count != expected_count) {
        try failures.append(
            allocator,
            try std.fmt.allocPrint(allocator, "{s}: expected {d} exact verified ghr Zig install blocks, found {d}", .{ label, expected_count, count }),
        );
    }
    return failures.toOwnedSlice(allocator);
}

pub const CLI_SMOKE_PATHS = [_][]const u8{ "build.zig", "test/cli-smoke.zig", "tools/test-cli.sh" };

pub fn nativeCliSmokeFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_]SourceTokenList{
        .{
            .path = "build.zig",
            .tokens = &.{
                "cli_smoke_options.addOptionPath(\"debz\", cli.getEmittedBin());",
                "cli_smoke_options.addOption([]const u8, \"version\", version);",
                "b.path(\"test/cli-smoke.zig\")",
                "const cli_tests = b.addRunArtifact(b.addTest(",
                "cli_tests.setCwd(b.path(\".\"));",
                "workload_core.dependOn(&cli_tests.step);",
            },
        },
        .{
            .path = "test/cli-smoke.zig",
            .tokens = &.{
                "try environment.put(\"PATH\", \"/no-host-interpreters\");",
                ".environ_map = &self.environment,",
                "options.debz",
                "options.version",
                "case.argv.len + 8000",
                "try f.run(argv, 5);",
                "try absent(result.stdout, dangerous);",
                "try booleanField(value, \"invokes_dpkg\", false);",
                "try booleanField(install_value, \"receipt_binding\", true);",
                "try booleanField(install_value, \"unchanged_without_receipt\", true);",
                "\"root/var/lib/debz/root-operation-v1.json\"",
            },
        },
    }) |req| {
        const txt = texts.get(req.path) orelse "";
        var missing = false;
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: native CLI-smoke authority, privacy or execution contract is missing", .{req.path}));
        }
    }
    if (texts.contains("tools/test-cli.sh") or std.mem.indexOf(u8, texts.get("build.zig") orelse "", "tools/test-cli.sh") != null) {
        try failures.append(allocator, try allocator.dupe(u8, "tools/test-cli.sh: retired shell/Python CLI-smoke driver was restored"));
    }
    return failures.toOwnedSlice(allocator);
}

pub const ACTION_EMPTY_LOCK_PATHS = [_][]const u8{
    ".github/workflows/ci.yml",
    "build.zig",
    "tools/native-action-empty-lock.zig",
};

pub const DEBIAN_READINESS_PATHS = [_][]const u8{
    "build.zig",
    "tools/debian-stable-readiness.zig",
    "tools/debian-stable-readiness.py",
    "tools/test_debian_stable_readiness.py",
    "tools/debian-stable-closure.zig",
    "tools/debian-stable-closure.py",
    "tools/test_debian_stable_closure.py",
};

pub const NATIVE_RELEASE_CORE_PATHS = [_][]const u8{
    "build.zig",
    "build/liblzma.zig",
    "tools/release.zig",
    "tools/release.py",
    "tools/release-workflow-policy.zig",
    "tools/release-workflow-policy.py",
    "tools/test_release_workflow_policy.py",
    ".github/workflows/ci.yml",
    "test/release-tooling.zig",
    "tools/test-release-install.sh",
};

pub fn nativeReleaseCoreFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_]SourceTokenList{
        .{
            .path = "build.zig",
            .tokens = &.{
                "b.path(\"tools/release.zig\")",
                "b.getInstallStep().dependOn(&install_release_tool.step);",
                "workload_release.dependOn(&release_tool_tests.step);",
                "b.path(\"tools/release-workflow-policy.zig\")",
                "b.getInstallStep().dependOn(&install_release_workflow_policy.step);",
                "workload_release.dependOn(&run_release_workflow_policy_tests.step);",
                "audit_step.dependOn(&run_release_workflow_policy_tests.step);",
                "run_release_workflow_policy_tests.step.dependOn(&install_release_tool.step);",
                "run_release_workflow_policy_tests.step.dependOn(&install_release_workflow_policy.step);",
                "release_test_options.addOption([]const u8, \"executable\", getInstallPath(b, .bin, \"debz-release\"));",
                "release_policy_tests.root_module.addOptions(\"release_test_options\", release_test_options);",
                "run_release_policy_tests.step.dependOn(&install_release_tool.step);",
                "const liblzma = liblzma_build.addStaticLibrary(b, xz_dependency, target, optimize);",
                "const release_liblzma = liblzma_build.addStaticEncoderLibrary(b, xz_dependency, target, optimize);",
                "release_tool_module.linkLibrary(release_liblzma);",
            },
        },
        .{
            .path = "tools/release-workflow-policy.zig",
            .tokens = &.{
                "pub fn auditReleaseCoreBootstrap(",
                "pub fn auditZigInstallation(",
                "pub fn auditCiConcurrency(",
                "pub fn auditGhrSmoke(",
                "pub fn auditRepository(",
                "try cleaned.put(\"PATH\", \"/no-host-interpreters\");",
                ".argv = &.{ release_tool_path, \"dry-run\", \"--tag\", \"v0.1.0\" },",
            },
        },
        .{
            .path = ".github/workflows/ci.yml",
            .tokens = &.{
                "zig build build-release-workflow-policy -j2",
                "PATH=/no-host-interpreters zig-out/bin/debz-release-workflow-policy",
            },
        },
        .{
            .path = "build/liblzma.zig",
            .tokens = &.{
                "pub fn addStaticEncoderLibrary(",
                "const library = addStaticLibrary(b, xz, target, optimize);",
                "\"src/liblzma/rangecoder/price_table.c\",",
                "\"HAVE_ENCODER_LZMA1\"",
                "\"HAVE_ENCODER_LZMA2\"",
            },
        },
        .{
            .path = "tools/release.zig",
            .tokens = &.{
                "pub fn parseTag(",
                "pub fn validateStaticElf(",
                "pub fn buildTar(",
                "try validateStaticElf(allocator, binary, platform);",
                "try buildTar(allocator, entries, epoch)",
                "if (machine != platform.machine())",
                "if (file_mapping.? != virtual_mapping.?)",
                "if (value.offset - load.file_start != value.address - load.virtual_start)",
                "if (tag == 1)",
                "if (!terminated)",
                "if (terminated and tag != 0)",
                "tarHeader(\"././@LongLink\", 0, 0, name.len + 1, 'L', true)",
                "const padding = (10240 - output.items.len % 10240) % 10240;",
                "return compressTarLevel(allocator, input, format, 9);",
                "std.compress.flate.Compress.init(&writer, history, .gzip, if (level == 1) .fastest else .best)",
                "output[8] = if (level == 1) 4 else 2;",
                "output[9] = 255;",
                "c.lzma_easy_encoder(&stream, level, c.LZMA_CHECK_CRC64)",
                "if (produced > maximum_compressed_bytes - output.items.len)",
                "if (input[3] != 0)",
                "if (!std.mem.allEqual(u8, input[4..8], 0))",
                "debz.metadata_decompression.decompress(allocator, format, input",
                "const tar = try decompressedTar(allocator, input, args[3]);",
                "const entries = try readTar(allocator, tar);",
                "if (checksum != try tarValue(header[148..156]))",
                "if (signed_size < 0 or signed_size > tar.len - start)",
                "if ((try seen.getOrPut(name)).found_existing)",
                "if (mtime != first)",
            },
        },
    }) |req| {
        const txt = texts.get(req.path) orelse "";
        var missing = false;
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: native release tag, plan, ELF or GNU tar binding is missing", .{req.path}));
        }
    }

    if (texts.contains("tools/release.py") or
        texts.contains("tools/release-workflow-policy.py") or
        texts.contains("tools/test_release_workflow_policy.py") or
        std.mem.indexOf(u8, texts.get(".github/workflows/ci.yml") orelse "", "tools/release-workflow-policy.py") != null or
        std.mem.indexOf(u8, texts.get("build.zig") orelse "", "tools/test_release_workflow_policy.py") != null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "tools/release.py: retired Python release implementation was restored"));
    }

    const build = texts.get("build.zig") orelse "";
    const release_module = partitionAfterAndBefore(build, "\nfn addReleaseToolModule(", "\n}\n");
    if (std.mem.indexOf(u8, build, ".root_module = addReleaseToolModule(b, target, .ReleaseSafe, debz, xz_dependency),") == null or
        std.mem.indexOf(u8, release_module, ".optimize = optimize,") == null or
        std.mem.indexOf(u8, release_module, "liblzma_build.addStaticEncoderLibrary(b, xz_dependency, target, optimize);") == null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "build.zig: installed release packager and its XZ encoder must always be ReleaseSafe"));
    }

    const native = texts.get("tools/release.zig") orelse "";
    const member_body = partitionAfterAndBefore(native, "fn readTar(", "pub fn validateStaticElf(");
    var member_missing = false;
    for ([_][]const u8{
        "if (checksum != try tarValue(header[148..156]))",
        "if (signed_size < 0 or signed_size > tar.len - start)",
        "if ((try seen.getOrPut(name)).found_existing)",
        "if (mtime != first)",
    }) |tok| {
        if (std.mem.indexOf(u8, member_body, tok) == null) member_missing = true;
    }
    if (member_missing) {
        try failures.append(allocator, try allocator.dupe(u8, "tools/release.zig: actual tar member validation body binding is missing"));
    }

    const smoke_body = partitionAfterAndBefore(native, "fn smoke(", "const Options");
    const extraction_body = partitionAfterAndBefore(smoke_body, "const root = fs.Root.init(context.io, extraction);", "var index = archive.entries.len;");
    const timestamp_body = partitionAfterAndBefore(smoke_body, "if (entry.bytes != null) {", "} else {");
    var smoke_missing = std.mem.indexOf(u8, timestamp_body, "try file.setTimestamps(context.io") == null;
    for ([_][]const u8{
        "for (archive.entries) |entry|",
        "try root.createRegularFile(path",
        "try file.writeStreamingAll(context.io, bytes);",
    }) |tok| {
        if (std.mem.indexOf(u8, extraction_body, tok) == null) smoke_missing = true;
    }
    if (smoke_missing) {
        try failures.append(allocator, try allocator.dupe(u8, "tools/release.zig: actual smoke extraction and file timestamp body binding is missing"));
    }

    const BlockTokens = struct { start: []const u8, end: []const u8, tokens: []const []const u8 };
    for ([_]BlockTokens{
        .{
            .start = "fn orchestration(",
            .end = "fn execute(",
            .tokens = &.{
                "try scanner.directory(try context.path(prefix)",
                "try validateBinary(context, scanner.entries.items, root_name, platform, dependencies);",
                "const tar = try buildTar(allocator, scanner.entries.items, epoch);",
                "try publish(context, &scanner, paths[number], bytes[number]);",
                "const archive = try auditArchive(context, archive_path, version, platform, dependencies);",
                "if (options.smoke and platform == hostPlatform())",
                "format == .@\"tar.gz\"",
            },
        },
        .{
            .start = "fn auditArchive(",
            .end = "fn outputSafe(",
            .tokens = &.{
                "const tar = try decompressedTar(context.allocator, compressed, name);",
                "readTar(context.allocator, tar)",
                "try validatePayload(entry.name, bytes)",
                "try buildTar(context.allocator, files.items, entries[0].mtime)",
                "try validateBinary(context, files.items, root, platform, dependencies);",
            },
        },
        .{
            .start = "fn validateBinary(",
            .end = "const AuditedArchive",
            .tokens = &.{
                "try validatePolicies(context.allocator, entries, root);",
                "try validateStaticElf(context.allocator, try findFile(entries, root, \"bin/debz\"), platform);",
                "try validateRuntime(context.allocator, try findFile(entries, root, \"share/debz/runtime-dependencies.json\"), dependencies);",
            },
        },
        .{
            .start = "const Scanner = struct",
            .end = "fn validateBinary(",
            .tokens = &.{
                "self.context.root.pinDirectory(path)",
                "try file.observeStableAlloc(self.context.allocator, maximum_tar_bytes - self.total)",
                "if (self.count > maximum_entries)",
                "if (depth > 128)",
                "try validatePayload(name, observed.bytes);",
                "for (self.files.items) |*pin| _ = try pin.metadata();",
                "for (self.directories.items) |*pin| _ = try pin.metadata();",
            },
        },
        .{
            .start = "fn publish(",
            .end = "fn hostPlatform(",
            .tokens = &.{
                "try outputSafe(self.context, self.path);",
                "try self.scanner.unchanged();",
                "try self.directory.?.metadata();",
                "try context.root.stageFile(path",
                ".durable = true",
                "try staged.commit();",
            },
        },
        .{
            .start = "fn smoke(",
            .end = "const Options",
            .tokens = &.{
                "for (archive.entries) |entry|",
                "try root.createRegularFile(path",
                "entry.mtime) * std.time.ns_per_s",
                "try file.setTimestamps(context.io",
                "try cleaned.put(\"PATH\", \"/no-host-interpreters\");",
                "std.process.run(context.allocator, context.io",
                ".raw = .fromSeconds(60)",
                "parent.deleteTree(context.io, directory_name)",
            },
        },
    }) |bt| {
        const body = partitionAfterAndBefore(native, bt.start, bt.end);
        var missing = false;
        for (bt.tokens) |tok| {
            if (std.mem.indexOf(u8, body, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "tools/release.zig: actual native release consumer body binding is missing: {s}", .{bt.start}));
        }
    }

    const consumer = texts.get("test/release-tooling.zig") orelse "";
    for ([_][2][]const u8{
        .{ "fn release(", "fn releaseFile(" },
        .{ "fn releaseFile(", "fn packageOk(" },
    }) |se| {
        const body = partitionAfterAndBefore(consumer, se[0], se[1]);
        var missing = false;
        for ([_][]const u8{
            "argv[0] = @import(\"release_test_options\").executable;",
            "try environment.put(\"PATH\", \"/no-host-interpreters\");",
            ".environ_map = &environment,",
        }) |tok| {
            if (std.mem.indexOf(u8, body, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try allocator.dupe(u8, "test/release-tooling.zig: actual native installed release handoff is missing"));
        }
    }
    if (std.mem.indexOf(u8, consumer, "python3") != null or std.mem.indexOf(u8, consumer, "tools/release.py") != null) {
        try failures.append(allocator, try allocator.dupe(u8, "test/release-tooling.zig: retired interpreter release consumer was restored"));
    }

    const layout = texts.get("tools/test-release-install.sh") orelse "";
    if (std.mem.indexOf(u8, layout, "PATH=/no-host-interpreters \"$release_tool\" check-runtime") == null or
        std.mem.indexOf(u8, layout, "--manifest \"$release_prefix/share/debz/runtime-dependencies.json\"") == null or
        std.mem.indexOf(u8, layout, "python3") != null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "tools/test-release-install.sh: actual native runtime check is missing"));
    }

    const reader_command = partitionAfterAndBefore(native, "if (std.mem.eql(u8, args[1], \"read-archive\")) {", "const compress = ");
    if (std.mem.indexOf(u8, reader_command, "const tar = try decompressedTar(allocator, input, args[3]);") == null or
        std.mem.indexOf(u8, reader_command, "const entries = try readTar(allocator, tar);") == null or
        std.mem.indexOf(u8, reader_command, "std.Io.File.stdout().writeStreamingAll") == null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "tools/release.zig: actual native archive reader command binding is missing"));
    }
    for (try liblzmaDecoderConfigurationFailures(allocator, texts.get("build/liblzma.zig") orelse "")) |msg| {
        try failures.append(allocator, msg);
    }
    return failures.toOwnedSlice(allocator);
}

fn hasBinaryRefreshInstallRoot(text: []const u8) bool {
    const p1 = "binary,";
    const p2 = "\"refresh\",";
    const p3 = "\"--install-root\",";
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, p1)) |idx| {
        pos = idx + p1.len;
        if (!isWordBoundary(text, idx)) continue;
        var j = pos;
        if (j >= text.len or !isSpace(text[j])) continue;
        while (j < text.len and isSpace(text[j])) : (j += 1) {}
        if (!startsWithAt(text, j, p2)) continue;
        j += p2.len;
        if (j >= text.len or !isSpace(text[j])) continue;
        while (j < text.len and isSpace(text[j])) : (j += 1) {}
        if (startsWithAt(text, j, p3)) return true;
    }
    return false;
}

pub fn nativeDebianReadinessFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_]SourceTokenList{
        .{
            .path = "build.zig",
            .tokens = &.{
                "b.path(\"tools/debian-stable-readiness.zig\")",
                "b.getInstallStep().dependOn(&install_debian_readiness.step);",
                "workload_core.dependOn(&debian_readiness_tests.step);",
                "b.path(\"tools/debian-stable-closure.zig\")",
                "b.getInstallStep().dependOn(&install_debian_closure.step);",
                "workload_core.dependOn(&debian_closure_tests.step);",
                "debian_closure_tests.setEnvironmentVariable(\"DEBZ_DEBIAN_STABLE_READINESS\", getInstallPath(b, .bin, \"debz-debian-stable-readiness\"));",
                "debian_closure_tests.setEnvironmentVariable(\"DEBZ_DEBIAN_STABLE_CLOSURE\", getInstallPath(b, .bin, \"debz-debian-stable-closure\"));",
                "debian_closure_tests.step.dependOn(&install_debian_readiness.step);",
                "debian_closure_tests.step.dependOn(&install_debian_closure.step);",
            },
        },
        .{
            .path = "tools/debian-stable-readiness.zig",
            .tokens = &.{
                "@embedFile(\"fixtures/debian-stable-readiness-v1.json\")",
                "return error.SignerArmorDigestChanged;",
                "return error.SignerBinaryDigestChanged;",
                "return error.SignerFingerprintChanged;",
                "return error.InReleaseDigestChanged;",
                "return error.ReleaseNotFresh;",
                "if (!std.mem.eql(u8, &digest, index.index_sha256) or entry.size != index.index_size)\n            return error.SignedIndexIdentityChanged;",
                "if (compressed.len != index.index_size or\n        !std.mem.eql(u8, &hash(std.crypto.hash.sha2.Sha256, compressed), index.index_sha256))\n        return error.SignedIndexIdentityChanged;",
                "return error.MalformedPublishedSha256;",
                "return error.AuthenticatedRefreshRefused;",
                "return error.ReadOnlyRefreshMutatedRoot;",
                ".require_https = true,",
                ".maximum_decompressed_bytes = maximum_packages_bytes,",
                "if (now != null or published != null or index_identity != null) return error.InvalidReadinessArguments;",
                ".exclusive = true,",
            },
        },
        .{
            .path = "tools/debian-stable-closure.zig",
            .tokens = &.{
                "DEBZ_DEBIAN_STABLE_READINESS",
                "try env.put(\"PATH\", \"/no-host-interpreters\");",
                "_ = try readinessIndexCounts(io, allocator, readiness, compressed, index);",
                "const key = try nativeReadiness(io, allocator, readiness, &.{\"--check-key\"}, try readinessFetch(io, allocator, readiness, \"key\", null));",
                "_ = try nativeReadiness(io, allocator, readiness, &.{ \"--check-release\", \"--architecture\", opts.architecture, \"--now\", now_text }, armored);",
                "try readinessFetch(io, allocator, readiness, \"index\", opts.architecture)",
            },
        },
    }) |req| {
        const txt = texts.get(req.path) orelse "";
        var missing = false;
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: required native Debian readiness or actual consumer binding is missing", .{req.path}));
        }
    }
    if (!hasBinaryRefreshInstallRoot(texts.get("tools/debian-stable-readiness.zig") orelse "")) {
        try failures.append(allocator, try allocator.dupe(u8, "tools/debian-stable-readiness.zig: actual debz read-only refresh invocation is missing"));
    }
    for ([_][]const u8{
        "tools/debian-stable-readiness.py",
        "tools/test_debian_stable_readiness.py",
        "tools/debian-stable-closure.py",
        "tools/test_debian_stable_closure.py",
    }) |path| {
        if (texts.contains(path)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: retired Python Debian readiness implementation or imported test was restored", .{path}));
        }
    }
    if (std.mem.indexOf(u8, texts.get("tools/debian-stable-closure.zig") orelse "", "debian-stable-readiness.py") != null) {
        try failures.append(allocator, try allocator.dupe(u8, "Debian closure must not import the retired Python readiness implementation"));
    }
    return failures.toOwnedSlice(allocator);
}

pub const INTEGRATION_REPOSITORY_PATHS = [_][]const u8{
    "build.zig",
    "tools/generate-integration-repository.zig",
    "tools/generate-integration-repository.py",
    "tools/test-integration-roots.sh",
    "tools/test-repository-add.sh",
    "test/native_recovery_parity.zig",
    "test/native_recovery_family.zig",
    "test/native_recovery_repository.zig",
    "test/apt-system-acceptance.zig",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    "actions/install/__tests__/integration.test.ts",
};

pub const INTEGRATION_ARCHIVE_PATHS = INTEGRATION_REPOSITORY_PATHS ++ [_][]const u8{"tools/integration-archive.zig"};

pub fn nativeIntegrationRepositoryFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_]SourceTokenList{
        .{
            .path = "build.zig",
            .tokens = &.{
                "b.path(\"tools/generate-integration-repository.zig\")",
                "b.getInstallStep().dependOn(&install_integration_repository.step);",
                "workload_core.dependOn(&integration_repository_tests.step);",
                "integration_tests.addArtifactArg(integration_repository);",
                "repository_add_tests.addArtifactArg(integration_repository);",
                "native_fixture_options.addOptionPath(\"integration_repository\", integration_repository.getEmittedBin());",
                "apt_acceptance_fixture_options.addOptionPath(\"integration_repository\", integration_repository.getEmittedBin());",
            },
        },
        .{
            .path = "tools/generate-integration-repository.zig",
            .tokens = &.{
                "archive.encode(io, allocator, workspace",
                "try archive.extraControl(allocator, bytes)",
                "try signing.sign(allocator, release)",
                "try pin.observeStableAlloc(allocator, maximum_bytes)",
                "if (bytes.len > maximum_bytes - self.size) return error.FixtureRepositoryTooLarge;",
                "if (seen.contains(key)) return error.DuplicateExtraPackageIdentity;",
                "if (!std.meta.eql(original, try parent.root.entryIfExists(output))) return error.FixtureDestinationChanged;",
                "if (point == .before_rename) try self.check();",
                "try environment.put(\"PATH\", \"/no-host-interpreters\");",
                "@import(\"integration-roots-check.zig\").run(init.io, allocator, arguments.items[1..])",
            },
        },
        .{
            .path = "actions/install/__tests__/integration.test.ts",
            .tokens = &.{
                "const repositoryGenerator = path.join(path.dirname(sourceCli), 'debz-integration-repository');",
                "['--output', repository, '--suite', 'debian-stable', '--architecture', architecture]",
                "{ env: { PATH: '/no-host-interpreters' }, timeout: 60_000, maxBuffer: 1024 * 1024 }",
                "repositoryGenerator, '--check-roots', 'bootstrap-install-action'",
                "['--check-roots', 'check-install-action-results', path.resolve(actionPath, '../..'), observations]",
            },
        },
        .{
            .path = "tools/test-integration-roots.sh",
            .tokens = &.{
                "*) repository_generator=\"$PWD/$repository_generator\" ;;",
                "if [ ! -x \"$repository_generator\" ]; then",
                "\"$repository_generator\" \\",
                "\"$repository_generator\" --check-roots native-lock",
                "\"$repository_generator\" --check-roots cache-result",
            },
        },
        .{
            .path = "tools/test-repository-add.sh",
            .tokens = &.{
                "*) repository_generator=\"$PWD/$repository_generator\" ;;",
                "if [ ! -x \"$repository_generator\" ]; then",
                "\"$repository_generator\" \\",
            },
        },
        .{
            .path = "test/native_recovery_parity.zig",
            .tokens = &.{
                "std.fs.path.resolve(fixture.allocator, &.{ options.repository, options.integration_repository })",
                "generator, \"--output\"",
            },
        },
        .{
            .path = "test/native_recovery_family.zig",
            .tokens = &.{
                "std.fs.path.resolve(fixture.allocator, &.{ options.repository, options.integration_repository })",
                "generator, \"--output\"",
            },
        },
        .{
            .path = "test/native_recovery_repository.zig",
            .tokens = &.{
                "std.fs.path.resolve(fixture.allocator, &.{ options.repository, options.integration_repository })",
                "generator, \"--output\"",
            },
        },
        .{
            .path = "test/apt-system-acceptance.zig",
            .tokens = &.{
                "realPathFileAlloc(self.io, @import(\"apt_acceptance_fixture_options\").integration_repository, self.arena)",
                "generator, \"--output\"",
            },
        },
        .{
            .path = ".github/workflows/ci.yml",
            .tokens = &.{
                "zig build build-integration-repository -Doptimize=ReleaseSafe -j2 --summary all",
                "\"$PWD/zig-out/bin/debz-integration-repository\" \\",
            },
        },
        .{
            .path = ".github/workflows/release.yml",
            .tokens = &.{
                "zig build build-integration-repository -Doptimize=ReleaseSafe -j2 --summary all",
                "\"$PWD/zig-out/bin/debz-integration-repository\" \\",
            },
        },
    }) |req| {
        const collapsed = try collapseWhitespaceAlloc(allocator, texts.get(req.path) orelse "");
        var missing = false;
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, collapsed, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: required native repository producer or real consumer wiring is missing", .{req.path}));
        }
    }

    if (texts.contains("tools/generate-integration-repository.py")) {
        try failures.append(allocator, try allocator.dupe(u8, "retired Python integration repository producer was restored"));
    }
    const producer = texts.get("tools/generate-integration-repository.zig") orelse "";
    for ([_][]const u8{ "buildDeb", "descriptor" }) |func_name| {
        const hdr = try std.fmt.allocPrint(allocator, "fn {s}(", .{func_name});
        const body = partitionAfterAndBefore(producer, hdr, "\nfn ");
        if (std.mem.indexOf(u8, body, "archive.encode(io, allocator, workspace") == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "native repository {s} must reuse the original native archive encoder", .{func_name}));
        }
    }
    for (INTEGRATION_REPOSITORY_PATHS[3..]) |path| {
        const txt = texts.get(path) orelse "";
        if (std.mem.indexOf(u8, txt, "generate-integration-repository.py") != null or
            std.mem.indexOf(u8, txt, "--fixture-python") != null or
            std.mem.indexOf(u8, txt, "DEBZ_INTEGRATION_ARCHIVE") != null or
            std.mem.indexOf(u8, txt, "DEBZ_INTEGRATION_SIGNING") != null)
        {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: retired Python repository or helper adapter was restored", .{path}));
        }
    }
    const roots_sh = texts.get("tools/test-integration-roots.sh") orelse "";
    if (countWordOccurrences(roots_sh, "python") > 0 or
        countWordOccurrences(roots_sh, "python3") > 0 or
        std.mem.indexOf(u8, roots_sh, "jsonschema") != null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "tools/test-integration-roots.sh: retired Python integration-root check was restored"));
    }
    const install_test = texts.get("actions/install/__tests__/integration.test.ts") orelse "";
    if (countWordOccurrences(install_test, "python") > 0 or
        countWordOccurrences(install_test, "python3") > 0 or
        std.mem.indexOf(u8, install_test, "PYTHONDONTWRITEBYTECODE") != null or
        std.mem.indexOf(u8, install_test, "jsonschema") != null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "actions/install/__tests__/integration.test.ts: retired Python install-action bootstrap or validator was restored"));
    }

    const ci = texts.get(".github/workflows/ci.yml") orelse "";
    const container = partitionAfterAndBefore(ci, "  download-action-container-fixture:", "\n  download-action-container:");
    const b_idx = std.mem.indexOf(u8, container, "zig build build-integration-repository ");
    const g_idx = std.mem.indexOf(u8, container, "\"$PWD/zig-out/bin/debz-integration-repository\"");
    if (b_idx == null or g_idx == null or b_idx.? >= g_idx.?) {
        try failures.append(allocator, try allocator.dupe(u8, "container fixture must build its native-host repository producer before generation"));
    }

    const ci_jobs = try parseCiJobsMap(allocator, ci);
    const JobCount = struct { name: []const u8, count: usize };
    for ([_]JobCount{
        .{ .name = "install-action-native", .count = 1 },
        .{ .name = "download-action-cache", .count = 2 },
        .{ .name = "download-action-container-fixture", .count = 1 },
        .{ .name = "build-and-test-workload", .count = 1 },
    }) |jc| {
        const body = ci_jobs.get(jc.name) orelse "";
        if (countSubstring(body, "\"$PWD/zig-out/bin/debz-integration-repository\" \\") != jc.count) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: every native repository fixture invocation must remain wired", .{jc.name}));
        }
    }

    const release_yml = texts.get(".github/workflows/release.yml") orelse "";
    for (try ghrZigWorkflowFailures(allocator, release_yml, "release.yml", 3)) |msg| {
        try failures.append(allocator, msg);
    }
    const rel_jobs = try parseCiJobsMap(allocator, release_yml);
    const smoke_job = rel_jobs.get("smoke") orelse "";
    const inst_idx = std.mem.indexOf(u8, smoke_job, GHR_ZIG_INSTALL);
    const rel_build_idx = std.mem.indexOf(u8, smoke_job, "zig build build-integration-repository ");
    if (inst_idx == null or rel_build_idx == null or inst_idx.? + GHR_ZIG_INSTALL.len > rel_build_idx.?) {
        try failures.append(allocator, try allocator.dupe(u8, "release fixture must install the verified native compiler before building its producer"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeIntegrationArchiveFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for (try nativeIntegrationRepositoryFailures(allocator, texts)) |msg| {
        try failures.append(allocator, msg);
    }
    const build = texts.get("build.zig") orelse "";
    const helper = texts.get("tools/integration-archive.zig") orelse "";
    for ([_][]const u8{
        "b.getInstallStep().dependOn(&install_integration_archive.step);",
        "workload_core.dependOn(&integration_archive_tests.step);",
    }) |token| {
        if (std.mem.indexOf(u8, build, token) == null) {
            try failures.append(allocator, try allocator.dupe(u8, "build.zig: native integration archive build or test was lost"));
        }
    }
    for ([_][]const u8{
        "try root.root.pinRegularFile(try fs.Path.init(\"request.json\"))",
        ".argv = &.{ \"/usr/bin/gzip\", \"-n\", \"-9\", \"-c\", absolute }",
        "std.mem.writeInt(u32, result.stdout[4..8], epoch, .little)",
        "result.stdout[9] = 255;",
        "std.hash.Crc32.hash(raw)",
        "return error.IntegrationScratchExists;",
        "debz.deb_payload.inspectControlAlloc(allocator, bytes",
        "try pin.observeStableAlloc(allocator, maximum_bytes)",
        "return error.ExtraControlRepositoryFields;",
    }) |token| {
        if (std.mem.indexOf(u8, helper, token) == null) {
            try failures.append(allocator, try allocator.dupe(u8, "tools/integration-archive.zig: native archive or control-only parser contract was lost"));
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub const DISPOSABLE_RUNTIME_PATHS = [_][]const u8{
    "build.zig",
    "tools/disposable-root-runtime.zig",
    "tools/disposable_root_runtime.py",
    "tools/dpkg-config-reference.zig",
    "tools/test-integration-roots.sh",
    "tools/dpkg-alternatives-reference.zig",
    ".github/workflows/ci.yml",
    "tools/run-dpkg-oracle-isolated.sh",
};

pub fn nativeDisposableRuntimeFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_]SourceTokenList{
        .{
            .path = DISPOSABLE_RUNTIME_PATHS[0],
            .tokens = &.{
                "b.path(\"tools/disposable-root-runtime.zig\")",
                "b.getInstallStep().dependOn(&install_disposable_runtime.step);",
                "integration_tests.step.dependOn(&install_disposable_runtime.step);",
                "integration_tests.addArtifactArg(disposable_runtime);",
                "dpkg_config_reference.step.dependOn(&install_disposable_runtime.step);",
                "dpkg_alternatives_reference.step.dependOn(&install_disposable_runtime.step);",
                "dpkg_alternatives_reference_tests.step.dependOn(&install_disposable_runtime.step);",
                "dpkg_alternatives_reference_tests.setEnvironmentVariable(\"DEBZ_DISPOSABLE_RUNTIME\", getInstallPath(b, .bin, \"debz-disposable-runtime\"));",
                "audit_tests.step.dependOn(&install_disposable_runtime.step);",
                "audit_tests.setEnvironmentVariable(\"DEBZ_DISPOSABLE_RUNTIME\", getInstallPath(b, .bin, \"debz-disposable-runtime\"));",
                "b.fmt(\"DEBZ_DISPOSABLE_RUNTIME={s}\", .{getInstallPath(b, .bin, \"debz-disposable-runtime\")}),",
                "workload_core.dependOn(&disposable_runtime_tests.step);",
                "disposable_runtime_test_options.addOptionPath(\"executable\", disposable_runtime.getEmittedBin());",
            },
        },
        .{
            .path = DISPOSABLE_RUNTIME_PATHS[1],
            .tokens = &.{
                "try pin.observeStableAlloc(self.allocator, self.file_limit)",
                "std.mem.eql(u8, argument, \"--max-file-bytes\")",
                "try context.input.check(context.root);",
                "try context.input.checkParent(context.root, context.directory.?);",
                "if (entry.link_count != 1) return error.HardLinkedFixtureDestination;",
            },
        },
        .{
            .path = DISPOSABLE_RUNTIME_PATHS[3],
            .tokens = &.{
                "\"DEBZ_DISPOSABLE_RUNTIME\"",
                "\"zig-out/bin/debz-disposable-runtime\"",
                "try argv.appendSlice(self.allocator, &.{ self.disposable_runtime, root, source, destination });",
            },
        },
        .{
            .path = DISPOSABLE_RUNTIME_PATHS[5],
            .tokens = &.{
                "_ = try validateAbsolutePath(destination);",
                "const limit_str = try std.fmt.allocPrint(self.allocator, \"{d}\", .{Limits.maximum_archive_bytes});",
                "\"--max-file-bytes\"",
            },
        },
        .{
            .path = DISPOSABLE_RUNTIME_PATHS[6],
            .tokens = &.{
                "          zig build build-disposable-runtime test-disposable-runtime -Doptimize=ReleaseSafe -j2 --summary all",
            },
        },
        .{
            .path = DISPOSABLE_RUNTIME_PATHS[7],
            .tokens = &.{
                "DEBZ_DISPOSABLE_RUNTIME=\"$repository/zig-out/bin/debz-disposable-runtime\"",
                "if [ ! -x \"$DEBZ_DISPOSABLE_RUNTIME\" ]; then",
                "export DEBZ_DISPOSABLE_RUNTIME",
            },
        },
        .{
            .path = DISPOSABLE_RUNTIME_PATHS[4],
            .tokens = &.{
                "runtime=${2:-\"$PWD/zig-out/bin/debz-disposable-runtime\"}",
                "$privileged \"$runtime\" \"$native_root\" /bin/sh /bin/sh",
            },
        },
    }) |req| {
        const txt = texts.get(req.path) orelse "";
        var missing = false;
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: native disposable runtime contract is missing", .{req.path}));
        }
    }
    if (texts.contains(DISPOSABLE_RUNTIME_PATHS[2])) {
        try failures.append(allocator, try allocator.dupe(u8, "retired Python disposable runtime implementation was restored"));
    }
    var has_py_consumer = false;
    for (DISPOSABLE_RUNTIME_PATHS[3..]) |path| {
        if (std.mem.indexOf(u8, texts.get(path) orelse "", "disposable_root_runtime.py") != null) has_py_consumer = true;
    }
    if (has_py_consumer) {
        try failures.append(allocator, try allocator.dupe(u8, "retired Python disposable runtime consumer was restored"));
    }
    if (std.mem.indexOf(u8, texts.get(DISPOSABLE_RUNTIME_PATHS[5]) orelse "", "shutil.copy2") != null) {
        try failures.append(allocator, try allocator.dupe(u8, "retired Python alternatives runtime copier was restored"));
    }
    return failures.toOwnedSlice(allocator);
}

pub const BASELINE_FIXTURE_PATHS = [_][]const u8{
    "build.zig",
    "tools/generate-native-baseline-fixture.zig",
    "tools/generate-native-baseline-fixture.py",
    "tools/fixture-openpgp.zig",
};

pub fn nativeBaselineFixtureFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_]SourceTokenList{
        .{
            .path = BASELINE_FIXTURE_PATHS[0],
            .tokens = &.{
                "b.path(\"tools/generate-native-baseline-fixture.zig\")",
                "b.step(\"generate-native-baseline-fixture\",",
                "baseline_fixture_smoke.setEnvironmentVariable(\"PATH\", \"/no-host-interpreters\");",
                "baseline_fixture_test_options.addOptionPathDirectory(\"generated\", generated_baseline_fixture);",
                "workload_core.dependOn(&baseline_fixture_tests.step);",
            },
        },
        .{
            .path = BASELINE_FIXTURE_PATHS[1],
            .tokens = &.{
                "const pgp = @import(\"fixture-openpgp.zig\");",
                "try targets[index].check();",
                "if (point == .before_rename) try self.check();",
                "if (entry.link_count != 1) return error.HardLinkedFixtureDestination;",
                "try std.testing.expectEqualSlices(u8, expected, generated);",
            },
        },
        .{
            .path = BASELINE_FIXTURE_PATHS[3],
            .tokens = &.{
                "modulus.powWithEncodedExponent(message, &rsa.exponent, .big)",
            },
        },
    }) |req| {
        const txt = texts.get(req.path) orelse "";
        var missing = false;
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: native signed baseline fixture contract is missing", .{req.path}));
        }
    }
    if (texts.contains(BASELINE_FIXTURE_PATHS[2]) or std.mem.indexOf(u8, texts.get("build.zig") orelse "", BASELINE_FIXTURE_PATHS[2]) != null) {
        try failures.append(allocator, try allocator.dupe(u8, "retired Python baseline fixture generator was restored"));
    }
    return failures.toOwnedSlice(allocator);
}

pub const OPENPGP_FIXTURE_PATHS = [_][]const u8{
    "build.zig",
    "tools/generate-openpgp-fixtures.zig",
    "tools/generate-openpgp-fixtures.py",
    "tools/fixture-openpgp.zig",
    "tools/generate-integration-repository.py",
};

pub fn nativeOpenpgpFixtureFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_]SourceTokenList{
        .{
            .path = OPENPGP_FIXTURE_PATHS[0],
            .tokens = &.{
                "b.path(\"tools/generate-openpgp-fixtures.zig\")",
                "b.step(\"generate-openpgp-fixtures\",",
                "openpgp_fixture_smoke.setEnvironmentVariable(\"PATH\", \"/no-host-interpreters\");",
                "openpgp_fixture_test_options.addOptionPath(\"generated\", generated_openpgp_fixture);",
                "workload_core.dependOn(&openpgp_fixture_tests.step);",
            },
        },
        .{
            .path = OPENPGP_FIXTURE_PATHS[1],
            .tokens = &.{
                "const pgp = @import(\"fixture-openpgp.zig\");",
                "const original = @import(\"debz\").test_fixtures.openpgp;",
                "try std.testing.expectEqualSlices(u8, &@field(original, field_name), @field(actual, field_name));",
                "try std.testing.expectEqualSlices(u8, expected, generated);",
                "try target.check();",
                "if (point == .before_rename) try self.check();",
                "if (entry.link_count != 1) return error.HardLinkedFixtureDestination;",
            },
        },
        .{
            .path = OPENPGP_FIXTURE_PATHS[3],
            .tokens = &.{
                "modulus.powWithEncodedExponent(message, &rsa.exponent, .big)",
                "pair.sign(digest, null)",
            },
        },
    }) |req| {
        const txt = texts.get(req.path) orelse "";
        var missing = false;
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: native OpenPGP fixture contract is missing", .{req.path}));
        }
    }
    if (texts.contains(OPENPGP_FIXTURE_PATHS[2])) {
        try failures.append(allocator, try allocator.dupe(u8, "retired Python OpenPGP signer was restored"));
    }
    return failures.toOwnedSlice(allocator);
}

pub const INTEGRATION_SIGNING_PATHS = INTEGRATION_REPOSITORY_PATHS ++ [_][]const u8{
    "tools/integration-signing.zig",
    "tools/requirements-openpgp-fixtures.txt",
};

pub fn nativeIntegrationSigningFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for (try nativeIntegrationRepositoryFailures(allocator, texts)) |msg| {
        try failures.append(allocator, msg);
    }
    for ([_]SourceTokenList{
        .{
            .path = "build.zig",
            .tokens = &.{
                "b.path(\"tools/integration-signing.zig\")",
                "b.getInstallStep().dependOn(&install_integration_signing.step);",
                "workload_core.dependOn(&integration_signing_tests.step);",
                "integration_signing_test_options.addOptionPath(\"executable\", integration_signing.getEmittedBin());",
            },
        },
        .{
            .path = "tools/integration-signing.zig",
            .tokens = &.{
                "const pgp = @import(\"fixture-openpgp.zig\");",
                "try pin.observeStableAlloc(allocator, maximum_bytes)",
                "try pgp.subpacket(allocator, 32, try pgp.packetBody(primary_binding))",
                "try pgp.clearsign(allocator, .subkey, subkey_fingerprint, release, .{})",
                "try environment.put(\"PATH\", \"/no-host-interpreters\");",
                "3907b432b4746fcd56702acccbf4bfb0308a99b07331c1fa11d7998865796b14",
                "9cc9b4c7976ea7cdafa5097ad8f2777122b5644479e9828f3c7ae63d81ee4d9f",
            },
        },
    }) |req| {
        const txt = texts.get(req.path) orelse "";
        var missing = false;
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: native integration signing contract is missing", .{req.path}));
        }
    }
    if (texts.contains("tools/requirements-openpgp-fixtures.txt")) {
        try failures.append(allocator, try allocator.dupe(u8, "retired integration cryptography dependency was restored"));
    }
    const gen_repo = texts.get("tools/generate-integration-repository.zig") orelse "";
    if (std.mem.indexOf(u8, gen_repo, "cryptography") != null or
        std.mem.indexOf(u8, gen_repo, "generate-openpgp-fixtures.py") != null or
        std.mem.indexOf(u8, gen_repo, "load_openpgp_fixture_module") != null)
    {
        try failures.append(allocator, try allocator.dupe(u8, "retired Python integration signing consumer was restored"));
    }
    const workflow = texts.get(".github/workflows/ci.yml") orelse "";
    if (std.mem.indexOf(u8, workflow, "python3-cryptography") != null or std.mem.indexOf(u8, workflow, "import cryptography") != null) {
        try failures.append(allocator, try allocator.dupe(u8, "retired CI fixture cryptography dependency was restored"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeActionEmptyLockFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    const ci = texts.get(ACTION_EMPTY_LOCK_PATHS[0]) orelse "";
    const ci_jobs = try parseCiJobsMap(allocator, ci);
    const body = ci_jobs.get("download-action-cache") orelse "";

    for ([_]SourceTokenList{
        .{
            .path = ACTION_EMPTY_LOCK_PATHS[0],
            .tokens = &.{
                "zig build build-native-action-empty-lock test-native-action-empty-lock",
                "PATH=/no-host-interpreters zig-out/bin/debz-native-action-empty-lock",
                "\"$workspace/base.native.lock.json\" \"$workspace/empty.native.lock.json\"",
            },
        },
        .{
            .path = ACTION_EMPTY_LOCK_PATHS[1],
            .tokens = &.{
                "b.step(\"build-native-action-empty-lock\",",
                "b.step(\"test-native-action-empty-lock\",",
                "workload_core.dependOn(&native_action_empty_lock_tests.step);",
            },
        },
        .{
            .path = ACTION_EMPTY_LOCK_PATHS[2],
            .tokens = &.{
                "try locks.decode(allocator, source, locks.maximum_document_bytes)",
                "Sha256.hash(\"native-action-empty-cache\",",
                ".target_architecture = original.lock.target_architecture",
                ".policy_sha256 = original.lock.policy_sha256",
                ".repositories = &.{},",
                ".local_artifacts = &.{},",
                ".packages = &.{},",
                "return empty.lock.canonicalJson(allocator);",
                "try input.root.pinRegularFile(",
                "try file.observeStableAlloc(allocator, locks.maximum_document_bytes)",
                "if (observed.entry.link_count != 1) return error.HardLinkedFixtureSource;",
                ".overwrite = .fail_if_exists,",
            },
        },
    }) |req| {
        const txt = if (std.mem.eql(u8, req.path, ACTION_EMPTY_LOCK_PATHS[0])) body else (texts.get(req.path) orelse "");
        var missing = false;
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) missing = true;
        }
        if (missing) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: native empty action-lock generation contract is missing", .{req.path}));
        }
    }
    var has_py_empty_lock = std.mem.indexOf(u8, body, "native-action-empty-cache") != null;
    {
        var it = std.mem.splitScalar(u8, body, '\n');
        while (it.next()) |line| {
            if (std.mem.indexOf(u8, line, "python")) |p_idx| {
                if (std.mem.indexOfPos(u8, line, p_idx, "empty.native.lock") != null) has_py_empty_lock = true;
            }
        }
    }
    if (has_py_empty_lock) {
        try failures.append(allocator, try allocator.dupe(u8, "ci.yml: retired inline Python action-lock generator was restored"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeLifecycleMigrationFailures(
    allocator: std.mem.Allocator,
    build: []const u8,
    trigger: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{
        "tools/test-native-lifecycle.py",
        "tools/test_native_lifecycle.py",
        "tools/test-native-triggers.py",
        "tools/test_native_triggers.py",
    }) |entrypoint| {
        const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{entrypoint});
        if (std.mem.indexOf(u8, build, quoted) != null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: retired Python acceptance gate was restored: {s}", .{entrypoint}));
        }
    }
    for ([_][]const u8{
        "const native_lifecycle_step = b.step(\"test-native-lifecycle\",",
        "const native_triggers_step = b.step(\"test-native-triggers\",",
        "native_lifecycle_step.dependOn(&lifecycle_zig.step);",
        "native_triggers_step.dependOn(&trigger_zig.step);",
        "native_triggers_step.dependOn(&run_native_trigger_queue_tests.step);",
        "lifecycle_zig.addArtifactArg(native_lifecycle_tests);",
        "trigger_zig.addArtifactArg(native_lifecycle_tests);",
        "trigger_zig.addArg(\"--native-helper\");",
        "trigger_zig.addArtifactArg(native_trigger_helper);",
        "workload_native.dependOn(&run_lifecycle_zig_tests.step);",
        "workload_native.dependOn(&run_trigger_zig_tests.step);",
        "workload_native.dependOn(&run_settlement_tests.step);",
        "b.step(\"test-native-lifecycle-zig-oracle\",",
        "b.step(\"test-native-triggers-zig-oracle\",",
        "b.step(\"test-native-triggers-zig-settlement-reference\",",
        "settlement_oracle_zig.addArgs(&.{ \"--oracle-only\", \"--diversion-settlement-reference-only\" });",
        "settlement_unit_step.dependOn(&run_settlement_lowering_tests.step);",
    }) |binding| {
        if (std.mem.indexOf(u8, build, binding) == null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "build.zig: missing required lifecycle/trigger gate binding: {s}", .{binding}));
        }
    }

    const body = partitionAfterAndBefore(trigger, "fn failedPostinstUnconfiguredListener(", "\nfn refuseMalformedQueue(");
    var body_bad = body.len == 0 or
        countSubstring(body, "support.reference(fixture, dpkg, root") != 2 or
        countSubstring(body, "activation-returned") != 2 or
        std.mem.indexOf(u8, body, "support.native(") != null;
    for ([_][]const u8{
        "for ([_]bool{ false, true }) |awaiting|",
        ".no_scripts = true",
        "Status: install ok unpacked",
        "Status: install ok half-configured",
        "Triggers-Pending:",
        "Triggers-Awaited:",
        "queue.len != 0",
        "exit 1",
    }) |val| {
        if (std.mem.indexOf(u8, body, val) == null) body_bad = true;
    }
    if (body_bad) {
        try failures.append(
            allocator,
            try allocator.dupe(u8, "native_trigger_acceptance.zig: keep both failed-postinst unconfigured-listener cases as reference-only observations"),
        );
    }
    if (std.mem.indexOf(u8, trigger, "failedPostinstUnconfiguredListener(&fixture, reference.executable, reference.architecture)") == null) {
        try failures.append(
            allocator,
            try allocator.dupe(u8, "native_trigger_acceptance.zig: invoke both unconfigured-listener references in the required trigger suite"),
        );
    }

    const refusal = partitionAfterAndBefore(trigger, "fn refuseUnconfiguredListenerProgram(", "\nfn interruptedTriggerHandler(");
    var refusal_bad = refusal.len == 0 or
        countSubstring(refusal, "foundation.captureRealRoot(") != 2 or
        std.mem.indexOf(u8, trigger, "refuseUnconfiguredListenerProgram(&fixture, native_driver, selected, reference.executable, reference.architecture)") == null;
    for ([_][]const u8{
        "for ([_]bool{ false, true }) |awaiting|",
        "case.seedWith(handler, false)",
        "report.value.detail, \"program_compile_rejected\"",
        "support.assertNoActiveEvidence(",
    }) |val| {
        if (std.mem.indexOf(u8, refusal, val) == null) refusal_bad = true;
    }
    if (refusal_bad) {
        try failures.append(
            allocator,
            try allocator.dupe(u8, "native_trigger_acceptance.zig: both unsupported listener programs must refuse before mutation and leave no active authority"),
        );
    }

    var iso_bad = false;
    for ([_][]const u8{
        "if (oracle_only == (driver != null) or (helper != null) != (driver != null))",
        "if (settlement_reference_only and (!oracle_only or diversions_only))",
        "if (fixture.oracle_only) return;",
        "settlement.run(&fixture, native_driver, reference.executable, selected, reference.architecture)",
    }) |tok| {
        if (std.mem.indexOf(u8, trigger, tok) == null) iso_bad = true;
    }
    if (iso_bad) {
        try failures.append(allocator, try allocator.dupe(u8, "native_trigger_acceptance.zig: selector or helper reference isolation removed"));
    }
    return failures.toOwnedSlice(allocator);
}

pub fn nativeLifecycleFixtureFailures(
    allocator: std.mem.Allocator,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{
        "tools/test-native-lifecycle.py",
        "tools/test_native_lifecycle.py",
        "tools/test-native-triggers.py",
        "tools/test_native_triggers.py",
        "tools/test-native-recovery.py",
        "tools/test_native_recovery.py",
        "tools/native-trigger-fixtures.py",
        "tools/native_diversion_settlement_oracle.py",
        "tools/test_real_snapshot_reference_triggers.py",
        "tools/native-lifecycle-fixtures.py",
        "tools/native-differential.py",
        "tools/native_only_candidate.py",
        "tools/native-materialization-fixtures.py",
        "tools/dpkg-config-reference.py",
        "tools/test_dpkg_config_reference.py",
        "tools/dpkg-alternatives-reference.py",
        "tools/test_dpkg_alternatives_reference.py",
    }) |relative| {
        if (texts.contains(relative)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: retired Python test entry point still exists", .{relative}));
        }
    }
    for ([_][2][]const u8{
        .{ "tools/dpkg-config-reference.zig", "native-materialization-fixtures.py" },
        .{ "actions/install/__tests__/integration.test.ts", "native-materialization-fixtures.py" },
    }) |cf| {
        if (std.mem.indexOf(u8, texts.get(cf[0]) orelse "", cf[1]) != null) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: retired fixture import was restored: {s}", .{ cf[0], cf[1] }));
        }
    }
    return failures.toOwnedSlice(allocator);
}

pub fn actionPinFailures(
    allocator: std.mem.Allocator,
    text: []const u8,
    label: []const u8,
) ![][]const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, "uses:")) |idx| {
        pos = idx + "uses:".len;
        var j = pos;
        while (j < text.len and isSpace(text[j])) : (j += 1) {}
        const name_start = j;
        while (j < text.len and text[j] != '@' and !isSpace(text[j])) : (j += 1) {}
        if (j == name_start or j >= text.len or text[j] != '@') continue;
        const name = text[name_start..j];
        j += 1;
        const rev_start = j;
        while (j < text.len and !isSpace(text[j]) and text[j] != '#') : (j += 1) {}
        if (j == rev_start) continue;
        const revision = text[rev_start..j];
        pos = j;
        if (!isLowerHexLen(revision, 40)) {
            try failures.append(allocator, try std.fmt.allocPrint(allocator, "{s}: {s} is not commit-pinned", .{ label, name }));
        }
    }
    return failures.toOwnedSlice(allocator);
}

fn hasPullRequestTargetLine(text: []const u8) bool {
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trimStart(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "pull_request_target")) continue;
        const rest = std.mem.trimStart(u8, trimmed["pull_request_target".len..], " \t\r");
        if (std.mem.startsWith(u8, rest, ":")) return true;
    }
    return false;
}

fn hasSecretsExpression(text: []const u8) bool {
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, "${{")) |idx| {
        pos = idx + 3;
        var j = pos;
        while (j < text.len and isSpace(text[j])) : (j += 1) {}
        if (startsWithAt(text, j, "secrets.")) return true;
    }
    return false;
}

fn hasTopLevelReadPermissions(text: []const u8) bool {
    var lines: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        lines.append(std.heap.page_allocator, std.mem.trimEnd(u8, line, " \t\r")) catch return false;
    }
    defer lines.deinit(std.heap.page_allocator);
    if (lines.items.len < 3) return false;
    var i: usize = 0;
    while (i + 2 < lines.items.len) : (i += 1) {
        if (!std.mem.eql(u8, lines.items[i], "permissions:")) continue;
        const l1 = lines.items[i + 1];
        const l2 = lines.items[i + 2];
        if (!std.mem.startsWith(u8, l1, "  contents:")) continue;
        const r1 = std.mem.trimStart(u8, l1["  contents:".len..], " \t");
        if (!std.mem.eql(u8, r1, "read")) continue;
        if (!std.mem.startsWith(u8, l2, "  attestations:")) continue;
        const r2 = std.mem.trimStart(u8, l2["  attestations:".len..], " \t");
        if (std.mem.eql(u8, r2, "read")) return true;
    }
    return false;
}

fn hasValidCheckoutBlocks(text: []const u8) bool {
    var lines: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        lines.append(std.heap.page_allocator, std.mem.trimEnd(u8, line, "\r")) catch return false;
    }
    defer lines.deinit(std.heap.page_allocator);

    var count: usize = 0;
    var i: usize = 0;
    while (i < lines.items.len) : (i += 1) {
        const line = lines.items[i];
        var j: usize = 0;
        while (j < line.len and (line[j] == ' ' or line[j] == '\t')) : (j += 1) {}
        if (j >= line.len or line[j] != '-') continue;
        j += 1;
        if (j >= line.len or (line[j] != ' ' and line[j] != '\t')) continue;
        while (j < line.len and (line[j] == ' ' or line[j] == '\t')) : (j += 1) {}
        if (!startsWithAt(line, j, "uses:")) continue;
        j += "uses:".len;
        while (j < line.len and (line[j] == ' ' or line[j] == '\t')) : (j += 1) {}
        if (!startsWithAt(line, j, "actions/checkout@")) continue;

        count += 1;
        var has_persist_false = false;
        var k = i + 1;
        while (k < lines.items.len) : (k += 1) {
            const bline = lines.items[k];
            if (!std.mem.startsWith(u8, bline, "        ")) break;
            const trimmed = std.mem.trim(u8, bline, " \t");
            if (std.mem.startsWith(u8, trimmed, "persist-credentials:")) {
                const val = std.mem.trim(u8, trimmed["persist-credentials:".len..], " \t");
                if (std.mem.eql(u8, val, "false")) has_persist_false = true;
            }
        }
        if (!has_persist_false) return false;
    }
    return count > 0;
}

fn loadExistingTextMap(ctx: *AuditContext, paths: []const []const u8) !std.StringArrayHashMapUnmanaged([]const u8) {
    var map: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    for (paths) |rel| {
        if (ctx.isRegularFile(rel)) {
            try map.put(ctx.allocator, rel, try ctx.readText(rel));
        }
    }
    return map;
}

pub fn auditCiPins(ctx: *AuditContext) !void {
    for (try nativeReleaseCoreFailures(ctx.allocator, try loadExistingTextMap(ctx, &NATIVE_RELEASE_CORE_PATHS))) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeDebianReadinessFailures(ctx.allocator, try loadExistingTextMap(ctx, &DEBIAN_READINESS_PATHS))) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeIntegrationSigningFailures(ctx.allocator, try loadExistingTextMap(ctx, &INTEGRATION_SIGNING_PATHS))) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeIntegrationArchiveFailures(ctx.allocator, try loadExistingTextMap(ctx, &INTEGRATION_ARCHIVE_PATHS))) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeDisposableRuntimeFailures(ctx.allocator, try loadExistingTextMap(ctx, &DISPOSABLE_RUNTIME_PATHS))) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeOpenpgpFixtureFailures(ctx.allocator, try loadExistingTextMap(ctx, &OPENPGP_FIXTURE_PATHS))) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeBaselineFixtureFailures(ctx.allocator, try loadExistingTextMap(ctx, &BASELINE_FIXTURE_PATHS))) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeCliSmokeFailures(ctx.allocator, try loadExistingTextMap(ctx, &CLI_SMOKE_PATHS))) |msg| {
        try ctx.fail(msg);
    }
    {
        var empty_lock_map: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
        for (ACTION_EMPTY_LOCK_PATHS) |rel| {
            try empty_lock_map.put(ctx.allocator, rel, try ctx.readText(rel));
        }
        for (try nativeActionEmptyLockFailures(ctx.allocator, empty_lock_map)) |msg| {
            try ctx.fail(msg);
        }
    }
    for (try nativeExerciseFinalWiringFailures(
        ctx.allocator,
        try ctx.readText("test/native_recovery_helper.zig"),
        try ctx.readText("test/native_lifecycle_support.zig"),
        try ctx.readText("src/native_unpack.zig"),
    )) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeCoreCompletionWiringFailures(
        ctx.allocator,
        try ctx.readText("build.zig"),
        try ctx.readText("test/native_recovery_helper.zig"),
        try ctx.readText("test/native_lifecycle_support.zig"),
    )) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeEntryPointShapeFailures(
        ctx.allocator,
        try ctx.readText("test/native_recovery_acceptance.zig"),
        try ctx.readText("test/native_recovery_projected_workflows.zig"),
        try ctx.readText(".github/workflows/ci.yml"),
    )) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeConsumerReceiptWiringFailures(
        ctx.allocator,
        try ctx.readText("test/native_recovery_parity.zig"),
        try ctx.readText("test/native_recovery_parity_evidence.zig"),
    )) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeRepositoryEvidenceWiringFailures(
        ctx.allocator,
        try ctx.readText("test/native_recovery_repository.zig"),
    )) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeWorkflowAcceptanceWiringFailures(
        ctx.allocator,
        try ctx.readText("build.zig"),
        try ctx.readText("test/native_recovery_family.zig"),
        try ctx.readText("test/native_recovery_projected_workflows.zig"),
    )) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeProvenanceBindingWiringFailures(
        ctx.allocator,
        try ctx.readText("build.zig"),
        try ctx.readText("src/sha512_transaction_e2e_test.zig"),
        try ctx.readText("src/native_provenance_binding_test.zig"),
        try ctx.readText("src/native_transaction_result.zig"),
        try ctx.readText("src/repository_backend.zig"),
        try ctx.readText("src/native_recovery.zig"),
        try ctx.readText("src/native_unpack.zig"),
        try ctx.readText("src/production_backend.zig"),
    )) |msg| {
        try ctx.fail(msg);
    }
    {
        var report_map: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
        for (REPORT_PATH_ORACLE_FILES) |rel| {
            try report_map.put(ctx.allocator, rel, try ctx.readText(rel));
        }
        for (try nativeReportPathWiringFailures(ctx.allocator, report_map)) |msg| {
            try ctx.fail(msg);
        }
    }
    for (try nativeRecoveryGateWiringFailures(
        ctx.allocator,
        try ctx.readText("build.zig"),
        try ctx.readText("test/native_recovery_helper.zig"),
        try ctx.readText("test/native_recovery_family.zig"),
        try ctx.readText("test/native_recovery_projected_workflows.zig"),
        try ctx.readText("test/native_recovery_repository.zig"),
        try ctx.readText("test/native_recovery_diversions.zig"),
    )) |msg| {
        try ctx.fail(msg);
    }
    for (try nativeLifecycleMigrationFailures(
        ctx.allocator,
        try ctx.readText("build.zig"),
        try ctx.readText("test/native_trigger_acceptance.zig"),
    )) |msg| {
        try ctx.fail(msg);
    }
    for (try workloadPartitionFailures(ctx.allocator, try ctx.readText("build.zig"))) |msg| {
        try ctx.fail(msg);
    }
    {
        const fixture_paths = [_][]const u8{
            "tools/test-native-lifecycle.py",
            "tools/test_native_lifecycle.py",
            "tools/test-native-triggers.py",
            "tools/test_native_triggers.py",
            "tools/test-native-recovery.py",
            "tools/test_native_recovery.py",
            "tools/native-trigger-fixtures.py",
            "tools/native_diversion_settlement_oracle.py",
            "tools/test_real_snapshot_reference_triggers.py",
            "tools/native-lifecycle-fixtures.py",
            "tools/native-differential.py",
            "tools/native_only_candidate.py",
            "tools/native-materialization-fixtures.py",
            "tools/dpkg-config-reference.py",
            "tools/test_dpkg_config_reference.py",
            "tools/dpkg-alternatives-reference.py",
            "tools/test_dpkg_alternatives_reference.py",
            "tools/dpkg-config-reference.zig",
            "actions/install/__tests__/integration.test.ts",
        };
        var fixture_texts = try loadExistingTextMap(ctx, &fixture_paths);
        for (fixture_paths[0..17]) |rel| {
            if (ctx.isSymlink(rel) or ctx.isDirectory(rel)) {
                try fixture_texts.put(ctx.allocator, rel, "");
            }
        }
        for (try nativeLifecycleFixtureFailures(ctx.allocator, fixture_texts)) |msg| {
            try ctx.fail(msg);
        }
    }

    const workflows = try ctx.globWorkflowFiles();
    for (workflows) |relative| {
        const text = try ctx.readText(relative);
        const name = std.fs.path.basename(relative);
        if (hasPullRequestTargetLine(text)) {
            try ctx.failFmt("{s}: pull_request_target executes untrusted changes with base privileges", .{relative});
        }
        if (hasSecretsExpression(text)) {
            try ctx.failFmt("{s}: workflow exposes repository secrets", .{relative});
        }
        for (try workflowFailureHandlingFailures(ctx.allocator, text, relative)) |msg| {
            try ctx.fail(msg);
        }
        if (std.mem.eql(u8, name, "ci.yml")) {
            for (try ciConcurrencyFailures(ctx.allocator, text, relative)) |msg| {
                try ctx.fail(msg);
            }
            for (try nativeRecoveryCiFailures(ctx.allocator, text)) |msg| {
                try ctx.fail(msg);
            }
            for (try referenceLauncherRootWiringFailures(
                ctx.allocator,
                if (ctx.isRegularFile(REFERENCE_ROOT_PATHS[0])) try ctx.readText(REFERENCE_ROOT_PATHS[0]) else "",
                if (ctx.isRegularFile(REFERENCE_ROOT_PATHS[1])) try ctx.readText(REFERENCE_ROOT_PATHS[1]) else "",
                if (ctx.isRegularFile(REFERENCE_ROOT_PATHS[2])) try ctx.readText(REFERENCE_ROOT_PATHS[2]) else "",
                if (ctx.isRegularFile(REFERENCE_ROOT_PATHS[3])) try ctx.readText(REFERENCE_ROOT_PATHS[3]) else "",
            )) |msg| {
                try ctx.fail(msg);
            }
            for (try protectedReferenceCiFailures(ctx.allocator, try loadExistingTextMap(ctx, &PROTECTED_REFERENCE_PATHS))) |msg| {
                try ctx.fail(msg);
            }
            for (try signedProcCiFailures(ctx.allocator, text)) |msg| {
                try ctx.fail(msg);
            }
        }
        const expected_ghr: ?usize = if (std.mem.eql(u8, name, "ci.yml")) 23 else if (std.mem.eql(u8, name, "release.yml")) 3 else null;
        if (expected_ghr) |exp| {
            for (try ghrZigWorkflowFailures(ctx.allocator, text, relative, exp)) |msg| {
                try ctx.fail(msg);
            }
        }
        if (!hasTopLevelReadPermissions(text)) {
            try ctx.failFmt("{s}: top-level permissions must be contents and attestations read", .{relative});
        }
        if (!hasValidCheckoutBlocks(text)) {
            try ctx.failFmt("{s}: every checkout must disable persisted credentials", .{relative});
        }
        var line_it = std.mem.splitScalar(u8, text, '\n');
        var line_number: usize = 1;
        while (line_it.next()) |line| : (line_number += 1) {
            const stripped = std.mem.trim(u8, line, " \t\r");
            if (std.mem.indexOf(u8, stripped, " | ") != null and !std.mem.startsWith(u8, stripped, "#")) {
                try ctx.failFmt("{s}:{d}: shell pipeline requires an explicit pipefail wrapper", .{ relative, line_number });
            }
        }
        for (try actionPinFailures(ctx.allocator, text, relative)) |msg| {
            try ctx.fail(msg);
        }
    }
}

pub fn auditCompositeActionPins(ctx: *AuditContext) !void {
    const manifests = try ctx.globActionManifests();
    for (manifests) |relative| {
        const text = try ctx.readText(relative);
        var is_composite = false;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (std.mem.startsWith(u8, trimmed, "using:")) {
                const val = std.mem.trim(u8, trimmed["using:".len..], " \t\r");
                if (std.mem.eql(u8, val, "composite")) is_composite = true;
            }
        }
        if (!is_composite) continue;
        for (try actionPinFailures(ctx.allocator, text, relative)) |msg| {
            try ctx.fail(msg);
        }
    }
}

pub fn auditSetupActionDependencies(ctx: *AuditContext) !void {
    const package_path = "actions/setup/package.json";
    const lock_path = "actions/setup/package-lock.json";
    const notices_path = "actions/setup/THIRD_PARTY_NOTICES.md";
    if (!ctx.isRegularFile(package_path) or !ctx.isRegularFile(lock_path) or !ctx.isRegularFile(notices_path)) {
        try ctx.fail("setup action dependency manifests or notices are missing");
        return;
    }
    const package_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText(package_path), .{});
    const lock_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText(lock_path), .{});
    const expected_runtime = [_][]const u8{
        "@actions/core",
        "@sigstore/bundle",
        "@sigstore/protobuf-specs",
        "@sigstore/tuf",
        "@sigstore/verify",
        "semver",
        "undici",
    };
    const deps_val = if (package_parsed.value == .object) package_parsed.value.object.get("dependencies") else null;
    if (deps_val == null or deps_val.? != .object or !jsonObjectKeysEqual(deps_val.?.object, &expected_runtime)) {
        try ctx.fail("setup action runtime dependencies differ from the reviewed allowlist");
    }
    const allowed_licenses = [_][]const u8{
        "0BSD",
        "Apache-2.0",
        "(Apache-2.0 AND BSD-3-Clause)",
        "BlueOak-1.0.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "MIT",
    };
    const packages_val = if (lock_parsed.value == .object) lock_parsed.value.object.get("packages") else null;
    if (packages_val == null or packages_val.? != .object) {
        try ctx.fail("setup action lockfile packages table is missing");
        return;
    }
    var pkg_it = packages_val.?.object.iterator();
    while (pkg_it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (name.len == 0) continue;
        if (entry.value_ptr.* != .object) {
            try ctx.failFmt("setup action lock entry is malformed: {s}", .{name});
            continue;
        }
        const meta = entry.value_ptr.*.object;
        const lic = getJsonString(meta, "license") orelse "";
        if (!sliceContainsString(&allowed_licenses, lic)) {
            try ctx.failFmt("setup action dependency has an unreviewed license: {s}", .{name});
        }
        if (isJsonTruthy(meta.get("hasInstallScript"))) {
            try ctx.failFmt("setup action dependency has an install script: {s}", .{name});
        }
        const resolved = getJsonString(meta, "resolved") orelse "";
        if (!std.mem.startsWith(u8, resolved, "https://registry.npmjs.org/")) {
            try ctx.failFmt("setup action dependency is not resolved from the npm registry: {s}", .{name});
        }
        const integrity = getJsonString(meta, "integrity") orelse "";
        if (!std.mem.startsWith(u8, integrity, "sha512-")) {
            try ctx.failFmt("setup action dependency lacks SHA-512 lock integrity: {s}", .{name});
        }
    }

    const notices = try ctx.readText(notices_path);
    for (expected_runtime) |name| {
        if (std.mem.indexOf(u8, notices, name) == null) {
            try ctx.failFmt("setup action notices omit direct dependency {s}", .{name});
        }
    }
    for ([_][]const u8{ "dist/main/licenses.txt", "dist/post/licenses.txt" }) |rel| {
        const full = try std.fmt.allocPrint(ctx.allocator, "actions/setup/{s}", .{rel});
        if (!ctx.isNonEmptyRegularFile(full)) {
            try ctx.failFmt("setup action bundled licenses are missing: {s}", .{full});
        }
    }
}

fn isPinnedSemver(version: []const u8) bool {
    var i: usize = 0;
    inline for (0..3) |part| {
        const start = i;
        while (i < version.len and std.ascii.isDigit(version[i])) : (i += 1) {}
        if (i == start) return false;
        if (part < 2) {
            if (i >= version.len or version[i] != '.') return false;
            i += 1;
        }
    }
    if (i == version.len) return true;
    if (version[i] != '-') return false;
    i += 1;
    if (i == version.len) return false;
    while (i < version.len) : (i += 1) {
        const c = version[i];
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-') return false;
    }
    return true;
}

fn isJsonTruthy(val: ?std.json.Value) bool {
    if (val == null) return false;
    return switch (val.?) {
        .null => false,
        .bool => |b| b,
        .integer => |n| n != 0,
        .float => |f| f != 0,
        .number_string => |s| s.len > 0,
        .string => |s| s.len > 0,
        .array => |a| a.items.len > 0,
        .object => |o| o.count() > 0,
    };
}

fn jsonStringMapEquals(a: ?std.json.Value, b: ?std.json.Value) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    if (a.? != .object or b.? != .object) return false;
    if (a.?.object.count() != b.?.object.count()) return false;
    var it = a.?.object.iterator();
    while (it.next()) |entry| {
        const b_val = b.?.object.get(entry.key_ptr.*) orelse return false;
        if (entry.value_ptr.* != .string or b_val != .string) return false;
        if (!std.mem.eql(u8, entry.value_ptr.*.string, b_val.string)) return false;
    }
    return true;
}

pub fn auditDownloadAction(ctx: *AuditContext) !void {
    const required = [_][]const u8{
        "actions/download/action.yml",
        "actions/download/package.json",
        "actions/download/package-lock.json",
        "actions/download/THIRD_PARTY_NOTICES.md",
        "actions/download/dist/index.js",
        "actions/download/dist/package.json",
        "actions/download/dist/licenses.txt",
    };
    var any_missing = false;
    for (required) |rel| {
        if (!ctx.isRegularFile(rel)) any_missing = true;
        if (!ctx.isNonEmptyRegularFile(rel)) {
            try ctx.failFmt("download action file is missing or empty: {s}", .{rel});
        }
    }
    if (any_missing) return;

    const manifest = try ctx.readText("actions/download/action.yml");
    for ([_][]const u8{
        "using: node24",
        "main: dist/index.js",
        "lock-input:",
        "architecture:",
        "keyring:",
        "cache-hit:",
        "cache-matched-key:",
        "downloaded-count:",
        "reused-count:",
        "backend-capability:",
        "maximum-repository-records:",
    }) |token| {
        if (std.mem.indexOf(u8, manifest, token) == null) {
            try ctx.failFmt("download action metadata is missing policy token: {s}", .{token});
        }
    }
    for ([_][]const u8{ "install-root:", "state-path:", "\n  args:" }) |forbidden| {
        if (std.mem.indexOf(u8, manifest, forbidden) != null) {
            try ctx.failFmt("download action exposes forbidden transaction input: {s}", .{std.mem.trim(u8, forbidden, " \t\r\n")});
        }
    }

    for ([_]SourceTokenList{
        .{
            .path = "src/inputs.ts",
            .tokens = &.{
                "cache-root must be an absolute child of RUNNER_TEMP",
                "must not traverse a symbolic link",
                "must be outside cache-root",
            },
        },
        .{
            .path = "src/runner.ts",
            .tokens = &.{
                "execFile(",
                "LANG: 'C'",
                "LC_ALL: 'C'",
                "package-cache",
                "fingerprint",
                "prepare",
                "--restored-cache",
                "--archive-input",
                "--archive-output",
                "outside the CLI-provided restore prefix",
            },
        },
        .{
            .path = "src/cache.ts",
            .tokens = &.{
                "debz-package-cache-opaque-archive-v1",
                "GetCacheEntryDownloadURL",
                "BlockBlobClient",
                "downloadToFile(",
                "uploadFile(",
                "createTransferArea(",
                "matched cache blob could not be safely staged",
            },
        },
        .{
            .path = "src/action.ts",
            .tokens = &.{
                "fingerprintCache(",
                "requires the maintained Node 24 runtime",
                "delete process.env.DEBZ_DOWNLOAD_CREDENTIAL_REFERENCE",
                "delete process.env['INPUT_CREDENTIAL-REFERENCE']",
                "delete process.env.DEBZ_DOWNLOAD_EXECUTABLE",
                "verifyExecutableIdentity(executableIdentity)",
                "cache.save(exportArchive, fingerprint.primary_key, archiveLimit)",
                "core.setOutput('cache-hit'",
                "core.setOutput('downloaded-count'",
                "core.setOutput(\n    'backend-capability'",
                "legacy-dpkg-execution-deprecated-v1",
            },
        },
    }) |req| {
        const full = try std.fmt.allocPrint(ctx.allocator, "actions/download/{s}", .{req.path});
        if (!ctx.isRegularFile(full)) {
            try ctx.failFmt("download action source is missing: {s}", .{full});
            continue;
        }
        const txt = try ctx.readText(full);
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) {
                try ctx.failFmt("download action {s} is missing policy token: {s}", .{ req.path, tok });
            }
        }
    }

    const source_text = try ctx.concatDirectoryFiles("actions/download/src", ".ts");
    for ([_][]const u8{
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        ".npmrc",
        "@actions/cache",
        "extractTar(",
        "createTar(",
        "process.chdir(",
    }) |forbidden| {
        if (std.mem.indexOf(u8, source_text, forbidden) != null) {
            try ctx.failFmt("download action source reads forbidden ambient input: {s}", .{forbidden});
        }
    }

    const action_source = try ctx.readText("actions/download/src/action.ts");
    const prepare_idx = std.mem.indexOf(u8, action_source, "const prepared = await prepareCache(");
    const save_idx = std.mem.indexOf(u8, action_source, "await cache.save(");
    const cleanup_idx = std.mem.indexOf(u8, action_source, "await transfer?.cleanup()");
    const output_idx = std.mem.indexOf(u8, action_source, "core.setOutput('cache-hit'");
    if (prepare_idx == null or save_idx == null or cleanup_idx == null or output_idx == null or
        !(prepare_idx.? < save_idx.? and save_idx.? < cleanup_idx.? and cleanup_idx.? < output_idx.?))
    {
        try ctx.fail("download action must prepare, save, clean staging, and only then publish outputs");
    }

    const package_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText("actions/download/package.json"), .{});
    const lock_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText("actions/download/package-lock.json"), .{});
    const pkg_obj = package_parsed.value.object;
    const lock_obj = lock_parsed.value.object;
    const deps = pkg_obj.get("dependencies");
    var deps_ok = false;
    if (deps != null and deps.? == .object and deps.?.object.count() == 2) {
        const c_ver = getJsonString(deps.?.object, "@actions/core") orelse "";
        const b_ver = getJsonString(deps.?.object, "@azure/storage-blob") orelse "";
        deps_ok = std.mem.eql(u8, c_ver, "3.0.1") and std.mem.eql(u8, b_ver, "12.31.0");
    }
    if (!deps_ok) {
        try ctx.fail("download action runtime dependencies differ from the reviewed allowlist");
    }
    for ([_][]const u8{ "dependencies", "devDependencies" }) |group| {
        const values = pkg_obj.get(group);
        if (values == null or values.? != .object or values.?.object.count() == 0) {
            try ctx.failFmt("download action {s} are missing", .{group});
            continue;
        }
        var it = values.?.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* != .string or !isPinnedSemver(entry.value_ptr.*.string)) {
                const ver_repr = if (entry.value_ptr.* == .string) entry.value_ptr.*.string else "";
                try ctx.failFmt("download action dependency {s} is not exactly pinned: '{s}'", .{ entry.key_ptr.*, ver_repr });
            }
        }
    }
    if ((getJsonInt(lock_obj, "lockfileVersion") orelse 0) != 3) {
        try ctx.fail("download action package-lock.json must use lockfileVersion 3");
    }
    const packages_val = lock_obj.get("packages");
    const root_pkg = if (packages_val != null and packages_val.? == .object) packages_val.?.object.get("") else null;
    if (root_pkg == null or root_pkg.? != .object) {
        try ctx.fail("download action lockfile has no root package");
    } else {
        for ([_][]const u8{ "dependencies", "devDependencies" }) |group| {
            if (!jsonStringMapEquals(root_pkg.?.object.get(group), pkg_obj.get(group))) {
                try ctx.failFmt("download action lockfile {s} differ from package.json", .{group});
            }
        }
    }
    const allowed_licenses = [_][]const u8{
        "0BSD",
        "Apache-2.0",
        "(Apache-2.0 AND BSD-3-Clause)",
        "ISC",
        "MIT",
    };
    if (packages_val != null and packages_val.? == .object) {
        var pkg_it = packages_val.?.object.iterator();
        while (pkg_it.next()) |entry| {
            const name = entry.key_ptr.*;
            if (name.len == 0) continue;
            if (entry.value_ptr.* != .object) {
                try ctx.failFmt("download action lock entry is malformed: {s}", .{name});
                continue;
            }
            const meta = entry.value_ptr.*.object;
            if (!sliceContainsString(&allowed_licenses, getJsonString(meta, "license") orelse "")) {
                try ctx.failFmt("download action dependency has an unreviewed license: {s}", .{name});
            }
            if (isJsonTruthy(meta.get("hasInstallScript"))) {
                try ctx.failFmt("download action dependency has an install script: {s}", .{name});
            }
            if (!std.mem.startsWith(u8, getJsonString(meta, "resolved") orelse "", "https://registry.npmjs.org/")) {
                try ctx.failFmt("download action dependency is not resolved from the npm registry: {s}", .{name});
            }
            if (!std.mem.startsWith(u8, getJsonString(meta, "integrity") orelse "", "sha512-")) {
                try ctx.failFmt("download action dependency lacks SHA-512 lock integrity: {s}", .{name});
            }
        }
    }

    const notices = try ctx.readText("actions/download/THIRD_PARTY_NOTICES.md");
    for ([_][]const u8{ "@actions/core", "@azure/storage-blob" }) |name| {
        if (std.mem.indexOf(u8, notices, name) == null) {
            try ctx.failFmt("download action notices omit direct dependency {s}", .{name});
        }
    }
    if (try ctx.hasTrackedFilesUnder("actions/download/node_modules")) {
        try ctx.fail("download action node_modules must not be tracked");
    }

    const archive_path = "src/package_cache_archive.zig";
    if (!ctx.isRegularFile(archive_path)) {
        try ctx.fail("CLI-owned package cache archive implementation is missing");
    } else {
        const archive = try ctx.readText(archive_path);
        for ([_][]const u8{
            "pub const format_id = \"debz-package-cache-archive-v1\"",
            "error.NonCanonicalOrder",
            "error.DuplicateObject",
            "error.ArchiveDigestMismatch",
            "maximum_total_object_bytes",
            "cache.publish(",
        }) |token| {
            if (std.mem.indexOf(u8, archive, token) == null) {
                try ctx.failFmt("package cache archive is missing policy token: {s}", .{token});
            }
        }
    }
}

pub fn auditInstallAction(ctx: *AuditContext) !void {
    const required = [_][]const u8{
        "actions/install/action.yml",
        "actions/install/package.json",
        "actions/install/package-lock.json",
        "actions/install/THIRD_PARTY_NOTICES.md",
        "actions/install/dist/index.js",
        "actions/install/dist/package.json",
        "actions/install/dist/licenses.txt",
    };
    var any_missing = false;
    for (required) |rel| {
        if (!ctx.isRegularFile(rel)) any_missing = true;
        if (!ctx.isNonEmptyRegularFile(rel)) {
            try ctx.failFmt("install action file is missing or empty: {s}", .{rel});
        }
    }
    if (any_missing) return;

    const manifest = try ctx.readText("actions/install/action.yml");
    for ([_][]const u8{
        "using: node24",
        "main: dist/index.js",
        "package:",
        "lock-input:",
        "install-root:",
        "assume-yes:",
        "noninteractive:",
        "conffile:",
        "use-sudo:",
        "package-cache-hit:",
        "transaction-result:",
        "installed-count:",
        "backend-capability:",
    }) |token| {
        if (std.mem.indexOf(u8, manifest, token) == null) {
            try ctx.failFmt("install action metadata is missing policy token: {s}", .{token});
        }
    }
    for ([_][]const u8{ "\n  args:", "status-path:", "allow-host-root:" }) |forbidden| {
        if (std.mem.indexOf(u8, manifest, forbidden) != null) {
            try ctx.failFmt("install action exposes forbidden input: {s}", .{std.mem.trim(u8, forbidden, " \t\r\n")});
        }
    }

    for ([_]SourceTokenList{
        .{
            .path = "src/inputs.ts",
            .tokens = &.{
                "assume-yes must be exactly 'true'",
                "install-root must not be the host root",
                "must not overlap",
                "must not traverse a symbolic link",
                "architecture must match the native",
            },
        },
        .{
            .path = "src/subprocess.ts",
            .tokens = &.{
                "setup', 'dist', 'main', 'index.js",
                "download', 'dist', 'index.js",
                "DEBZ_DOWNLOAD_EXECUTABLE",
                "['-n', '--', executable",
                "spawn(",
            },
        },
        .{
            .path = "src/runner.ts",
            .tokens = &.{
                "'--cache-only'",
                "'transaction-result'",
                "'verify'",
                "lock_evidence",
            },
        },
        .{
            .path = "src/action.ts",
            .tokens = &.{
                "const download = await composition.download",
                "buildInstallArguments(inputs)",
                "requireFreshResult",
                "validateTransactionSummary",
                "await composition.saveSetupCache()",
                "io.setOutput('transaction-result'",
                "io.setOutput(\n    'backend-capability'",
                "legacy-dpkg-execution-deprecated-v1",
            },
        },
    }) |req| {
        const full = try std.fmt.allocPrint(ctx.allocator, "actions/install/{s}", .{req.path});
        if (!ctx.isRegularFile(full)) {
            try ctx.failFmt("install action source is missing: {s}", .{full});
            continue;
        }
        const txt = try ctx.readText(full);
        for (req.tokens) |tok| {
            if (std.mem.indexOf(u8, txt, tok) == null) {
                try ctx.failFmt("install action {s} is missing policy token: {s}", .{ req.path, tok });
            }
        }
    }

    const source_text = try ctx.concatDirectoryFiles("actions/install/src", ".ts");
    for ([_][]const u8{
        "shell: true",
        "execFile(",
        "eval(",
        "status-path",
        "allow-host-root",
        "HTTP_PROXY",
        "HTTPS_PROXY",
    }) |forbidden| {
        if (std.mem.indexOf(u8, source_text, forbidden) != null) {
            try ctx.failFmt("install action source contains forbidden mechanism: {s}", .{forbidden});
        }
    }

    const action_source = try ctx.readText("actions/install/src/action.ts");
    const dl_idx = std.mem.indexOf(u8, action_source, "const download = await composition.download");
    const inst_idx = std.mem.indexOf(u8, action_source, "buildInstallArguments(inputs)");
    const sum_idx = std.mem.indexOf(u8, action_source, "validateTransactionSummary(");
    const out_idx = std.mem.indexOf(u8, action_source, "io.setOutput('transaction-result'");
    if (dl_idx == null or inst_idx == null or sum_idx == null or out_idx == null or
        !(dl_idx.? < inst_idx.? and inst_idx.? < sum_idx.? and sum_idx.? < out_idx.?))
    {
        try ctx.fail("install action must download, always install, verify the result, and only then publish outputs");
    }

    const package_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText("actions/install/package.json"), .{});
    const lock_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText("actions/install/package-lock.json"), .{});
    const pkg_obj = package_parsed.value.object;
    const lock_obj = lock_parsed.value.object;
    const deps = pkg_obj.get("dependencies");
    var deps_ok = false;
    if (deps != null and deps.? == .object and deps.?.object.count() == 1) {
        const c_ver = getJsonString(deps.?.object, "@actions/core") orelse "";
        deps_ok = std.mem.eql(u8, c_ver, "3.0.1");
    }
    if (!deps_ok) {
        try ctx.fail("install action runtime dependencies differ from the reviewed allowlist");
    }
    for ([_][]const u8{ "dependencies", "devDependencies" }) |group| {
        const values = pkg_obj.get(group);
        if (values == null or values.? != .object or values.?.object.count() == 0) {
            try ctx.failFmt("install action {s} are missing", .{group});
            continue;
        }
        var it = values.?.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* != .string or !isPinnedSemver(entry.value_ptr.*.string)) {
                const ver_repr = if (entry.value_ptr.* == .string) entry.value_ptr.*.string else "";
                try ctx.failFmt("install action dependency {s} is not exactly pinned: '{s}'", .{ entry.key_ptr.*, ver_repr });
            }
        }
    }
    if ((getJsonInt(lock_obj, "lockfileVersion") orelse 0) != 3) {
        try ctx.fail("install action package-lock.json must use lockfileVersion 3");
    }
    const packages_val = lock_obj.get("packages");
    const root_pkg = if (packages_val != null and packages_val.? == .object) packages_val.?.object.get("") else null;
    if (root_pkg == null or root_pkg.? != .object) {
        try ctx.fail("install action lockfile has no root package");
    } else {
        for ([_][]const u8{ "dependencies", "devDependencies" }) |group| {
            if (!jsonStringMapEquals(root_pkg.?.object.get(group), pkg_obj.get(group))) {
                try ctx.failFmt("install action lockfile {s} differ from package.json", .{group});
            }
        }
    }
    const allowed_licenses = [_][]const u8{ "0BSD", "Apache-2.0", "ISC", "MIT" };
    if (packages_val != null and packages_val.? == .object) {
        var pkg_it = packages_val.?.object.iterator();
        while (pkg_it.next()) |entry| {
            const name = entry.key_ptr.*;
            if (name.len == 0) continue;
            if (entry.value_ptr.* != .object) {
                try ctx.failFmt("install action lock entry is malformed: {s}", .{name});
                continue;
            }
            const meta = entry.value_ptr.*.object;
            if (!sliceContainsString(&allowed_licenses, getJsonString(meta, "license") orelse "")) {
                try ctx.failFmt("install action dependency has an unreviewed license: {s}", .{name});
            }
            if (isJsonTruthy(meta.get("hasInstallScript"))) {
                try ctx.failFmt("install action dependency has an install script: {s}", .{name});
            }
            if (!std.mem.startsWith(u8, getJsonString(meta, "resolved") orelse "", "https://registry.npmjs.org/")) {
                try ctx.failFmt("install action dependency is not resolved from the npm registry: {s}", .{name});
            }
            if (!std.mem.startsWith(u8, getJsonString(meta, "integrity") orelse "", "sha512-")) {
                try ctx.failFmt("install action dependency lacks SHA-512 lock integrity: {s}", .{name});
            }
        }
    }
    const notices = try ctx.readText("actions/install/THIRD_PARTY_NOTICES.md");
    if (std.mem.indexOf(u8, notices, "@actions/core") == null) {
        try ctx.fail("install action notices omit direct dependency @actions/core");
    }
    if (try ctx.hasTrackedFilesUnder("actions/install/node_modules")) {
        try ctx.fail("install action node_modules must not be tracked");
    }
    if (!ctx.isRegularFile("schema/transaction-result-summary-v1.json")) {
        try ctx.fail("transaction-result summary schema is missing");
    }
}

fn hasLegacyMarker(text: []const u8) bool {
    for ([_][]const u8{
        "legacy_dpkg",
        "legacy-dpkg-execution",
        "legacy-capability",
        "\"/usr/bin/dpkg\"",
        "exact-closure-lock-v1",
        "transaction-result-v1",
        "system-profile-v1",
        "package-cache-fingerprint.v1",
        "package-cache-result.v1",
        "package-family.capabilities.v1",
        "package-family.request.v1",
        "package-family.result.v1",
    }) |sub| {
        if (std.mem.indexOf(u8, text, sub) != null) return true;
    }
    if (countWordOccurrences(text, "dpkg-query") > 0) return true;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, ".{")) |idx| {
        pos = idx + 2;
        var j = pos;
        while (j < text.len and isSpace(text[j])) : (j += 1) {}
        if (startsWithAt(text, j, "\"dpkg\"")) return true;
    }
    return false;
}

pub fn auditLegacyCutoverPolicy(ctx: *AuditContext) !void {
    const policy_path = "security/legacy-cutover-policy.json";
    const schema_path = "schema/legacy-compatibility-policy-v1.json";
    if (!ctx.isRegularFile(policy_path) or !ctx.isRegularFile(schema_path)) {
        try ctx.fail("legacy cutover policy or schema is missing");
        return;
    }
    const parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText(policy_path), .{});
    const policy = parsed.value.object;
    if (!std.mem.eql(u8, getJsonString(policy, "schema") orelse "", "https://debz.dev/schema/legacy-compatibility-policy-v1") or
        (getJsonInt(policy, "version") orelse 0) != 1 or
        (getJsonInt(policy, "issue") orelse 0) != 86 or
        !std.mem.eql(u8, getJsonString(policy, "current_release_mode") orelse "", "legacy_capable"))
    {
        try ctx.fail("legacy cutover policy identity or current release mode changed");
    }
    const blockers = policy.get("cutover_blockers");
    const ready = policy.get("native_only_cutover_ready");
    if (ready == null or ready.? != .bool or ready.?.bool != false or blockers == null or blockers.? != .array or blockers.?.array.items.len == 0) {
        try ctx.fail("legacy cutover policy cannot claim native-only readiness while blockers remain");
    }
    const required_invariants = [_][]const u8{
        "legacy_is_never_native_authority",
        "active_legacy_requires_legacy_capable_recovery",
        "native_only_must_not_clear_active_legacy",
        "completed_history_is_read_only",
        "historical_bytes_are_never_rewritten",
        "no_fallback_after_native_mutation",
        "no_success_shaped_default",
        "single_root_operation_namespace",
    };
    const inv_val = policy.get("invariants");
    var inv_ok = false;
    if (inv_val != null and inv_val.? == .object and inv_val.?.object.count() == required_invariants.len) {
        inv_ok = true;
        for (required_invariants) |req| {
            const v = inv_val.?.object.get(req);
            if (v == null or v.? != .bool or !v.?.bool) inv_ok = false;
        }
    }
    if (!inv_ok) {
        try ctx.fail("legacy cutover invariants are incomplete or not fail-closed");
    }

    const ReqArtifact = struct {
        schema: []const u8,
        versions: []const i64,
        backend: []const u8,
    };
    const required_artifacts = [_]ReqArtifact{
        .{ .schema = "https://debz.dev/schema/system-profile-v1", .versions = &.{1}, .backend = "legacy_dpkg" },
        .{ .schema = "https://debz.dev/schema/system-profile-v2", .versions = &.{2}, .backend = "explicit" },
        .{ .schema = "https://debz.dev/schema/exact-closure-lock-v1", .versions = &.{1}, .backend = "legacy_dpkg" },
        .{ .schema = "https://debz.dev/schema/exact-closure-lock-v2", .versions = &.{2}, .backend = "explicit_context" },
        .{ .schema = "https://debz.dev/schema/transaction-result-v1", .versions = &.{1}, .backend = "legacy_dpkg" },
        .{ .schema = "https://debz.dev/schema/transaction-result-v2", .versions = &.{2}, .backend = "legacy_dpkg" },
        .{ .schema = "io.github.cataggar.debz.transaction-result-summary.v1", .versions = &.{1}, .backend = "legacy_dpkg" },
        .{ .schema = "io.github.cataggar.debz.transaction-result-summary.v2", .versions = &.{2}, .backend = "native" },
        .{ .schema = "io.github.cataggar.debz.transaction-result-capability.v1", .versions = &.{1}, .backend = "native" },
        .{ .schema = "debz:transaction-journal", .versions = &.{ 1, 2, 3, 4 }, .backend = "legacy_dpkg" },
        .{ .schema = "https://debz.dev/schema/root-operation-record-v1", .versions = &.{1}, .backend = "explicit" },
        .{ .schema = "https://debz.dev/schema/root-operation-completion-v1", .versions = &.{1}, .backend = "explicit" },
        .{ .schema = "https://debz.dev/schema/apt-system-operation-state-v1", .versions = &.{1}, .backend = "explicit_context" },
        .{ .schema = "https://debz.dev/schema/apt-system-result-v1", .versions = &.{1}, .backend = "explicit_context" },
        .{ .schema = "https://debz.dev/schema/apt-system-result-v2", .versions = &.{2}, .backend = "explicit_context" },
        .{ .schema = "https://debz.dev/schema/apt-system-result-v3", .versions = &.{3}, .backend = "explicit_context" },
        .{ .schema = "https://debz.dev/schema/apt-system-execution-completion-v1", .versions = &.{1}, .backend = "native" },
        .{ .schema = "io.github.cataggar.debz.command.v1", .versions = &.{1}, .backend = "explicit" },
        .{ .schema = "https://debz.dev/schema/repository-add-state-v1", .versions = &.{1}, .backend = "explicit" },
        .{ .schema = "https://debz.dev/schema/repository-operation-result-v1", .versions = &.{1}, .backend = "explicit" },
        .{ .schema = "io.github.cataggar.debz.package-cache-fingerprint.v1", .versions = &.{1}, .backend = "legacy_dpkg" },
        .{ .schema = "io.github.cataggar.debz.package-cache-fingerprint.v2", .versions = &.{2}, .backend = "native" },
        .{ .schema = "io.github.cataggar.debz.package-cache-result.v1", .versions = &.{1}, .backend = "legacy_dpkg" },
        .{ .schema = "io.github.cataggar.debz.package-cache-result.v2", .versions = &.{2}, .backend = "native" },
        .{ .schema = "io.github.cataggar.debz.package-cache-error.v1", .versions = &.{1}, .backend = "explicit" },
        .{ .schema = "io.github.cataggar.debz.package-family.capabilities.v1", .versions = &.{1}, .backend = "legacy_dpkg" },
        .{ .schema = "io.github.cataggar.debz.package-family.capabilities.v2", .versions = &.{2}, .backend = "native" },
        .{ .schema = "io.github.cataggar.debz.package-family.request.v1", .versions = &.{1}, .backend = "legacy_dpkg" },
        .{ .schema = "io.github.cataggar.debz.package-family.request.v2", .versions = &.{2}, .backend = "native" },
        .{ .schema = "io.github.cataggar.debz.package-family.result.v1", .versions = &.{1}, .backend = "legacy_dpkg" },
        .{ .schema = "io.github.cataggar.debz.package-family.result.v2", .versions = &.{2}, .backend = "native" },
        .{ .schema = "https://debz.dev/schema/native-transaction-provenance-v1", .versions = &.{1}, .backend = "native" },
        .{ .schema = "io.github.cataggar.debz.native-install-capability.v1", .versions = &.{1}, .backend = "native" },
        .{ .schema = "io.github.cataggar.debz.native-install-result.v1", .versions = &.{1}, .backend = "native" },
        .{ .schema = "https://debz.dev/schema/native-repository-unchanged-v1", .versions = &.{1}, .backend = "native" },
        .{ .schema = "https://debz.dev/schema/legacy-capability-evidence-v1", .versions = &.{1}, .backend = "legacy_dpkg_non_authoritative" },
    };

    const artifacts_val = policy.get("artifact_policy");
    var seen_artifacts: std.StringHashMapUnmanaged(struct { versions: []const i64, backend: []const u8 }) = .empty;
    if (artifacts_val == null or artifacts_val.? != .array) {
        try ctx.fail("legacy artifact inventory is missing");
    } else {
        for (artifacts_val.?.array.items) |item| {
            if (item != .object) {
                try ctx.fail("legacy artifact inventory contains a malformed entry");
                continue;
            }
            const s = getJsonString(item.object, "schema");
            const v = item.object.get("versions");
            const b = getJsonString(item.object, "backend");
            if (s == null or b == null or v == null or v.? != .array) {
                try ctx.fail("legacy artifact inventory contains an invalid identity tuple");
                continue;
            }
            var vers: std.ArrayList(i64) = .empty;
            var all_int = true;
            for (v.?.array.items) |vi| {
                if (vi != .integer) {
                    all_int = false;
                    break;
                }
                try vers.append(ctx.allocator, vi.integer);
            }
            if (!all_int) {
                try ctx.fail("legacy artifact inventory contains an invalid identity tuple");
                continue;
            }
            if (seen_artifacts.contains(s.?)) {
                try ctx.failFmt("legacy artifact identity is multiply classified: {s}", .{s.?});
                continue;
            }
            try seen_artifacts.put(ctx.allocator, s.?, .{ .versions = try vers.toOwnedSlice(ctx.allocator), .backend = b.? });
        }
    }
    var artifacts_match = seen_artifacts.count() == required_artifacts.len;
    if (artifacts_match) {
        for (required_artifacts) |req| {
            const actual = seen_artifacts.get(req.schema) orelse {
                artifacts_match = false;
                break;
            };
            if (!std.mem.eql(i64, actual.versions, req.versions) or !std.mem.eql(u8, actual.backend, req.backend)) {
                artifacts_match = false;
                break;
            }
        }
    }
    if (!artifacts_match) {
        try ctx.fail("legacy artifact version/backend inventory is incomplete or ambiguous");
    }

    const classifier = try ctx.readText("src/legacy_compat.zig");
    for (required_artifacts) |req| {
        if (std.mem.indexOf(u8, classifier, req.schema) == null) {
            try ctx.failFmt("normative Zig classifier omits policy artifact: {s}", .{req.schema});
        }
    }

    var classified: std.StringHashMapUnmanaged(void) = .empty;
    for ([_][]const u8{
        "production_execution_paths",
        "compatibility_guard_paths",
        "historical_reference_paths",
        "test_reference_paths",
    }) |section| {
        const entries = policy.get(section);
        if (entries == null or entries.? != .array or entries.?.array.items.len == 0) {
            try ctx.failFmt("legacy cutover policy has no {s}", .{section});
            continue;
        }
        for (entries.?.array.items) |entry| {
            if (entry != .object or getJsonString(entry.object, "path") == null) {
                try ctx.failFmt("legacy cutover policy contains malformed {s} entry", .{section});
                continue;
            }
            const rel = getJsonString(entry.object, "path").?;
            if (classified.contains(rel)) {
                try ctx.failFmt("legacy cutover path is multiply classified: {s}", .{rel});
            }
            try classified.put(ctx.allocator, rel, {});
            if (!ctx.isRegularFile(rel)) {
                try ctx.failFmt("legacy cutover inventory path is missing: {s}", .{rel});
            }
            if (std.mem.eql(u8, section, "historical_reference_paths") or std.mem.eql(u8, section, "test_reference_paths")) {
                const ret = entry.object.get("retain_after_cutover");
                if (ret == null or ret.? != .bool or !ret.?.bool) {
                    try ctx.failFmt("legacy retained path lacks explicit retention: {s}", .{rel});
                }
            } else if (getJsonString(entry.object, "cutover") == null) {
                try ctx.failFmt("legacy executable/guard path lacks a cutover disposition: {s}", .{rel});
            }
        }
    }

    const required_selectors = [_][]const u8{
        "src/transaction_engine.zig",
        "src/production_backend.zig",
        "src/repository_backend.zig",
        "src/package_family_backend.zig",
        "src/package_cache_workflow.zig",
        "src/system_profile.zig",
        "src/main.zig",
        "src/repository_cli.zig",
        "src/apt_system_orchestrator.zig",
        "src/target_apt_config.zig",
        "actions/download/src/inputs.ts",
        "actions/download/src/action.ts",
        "actions/download/src/runner.ts",
        "actions/download/action.yml",
        "actions/install/src/inputs.ts",
        "actions/install/src/action.ts",
        "actions/install/src/errors.ts",
        "actions/install/action.yml",
    };
    var prod_paths: std.StringHashMapUnmanaged(void) = .empty;
    if (policy.get("production_execution_paths")) |p_entries| {
        if (p_entries == .array) {
            for (p_entries.array.items) |entry| {
                if (entry == .object) {
                    if (getJsonString(entry.object, "path")) |p| {
                        try prod_paths.put(ctx.allocator, p, {});
                    }
                }
            }
        }
    }
    var missing_selectors: std.ArrayList([]const u8) = .empty;
    for (required_selectors) |sel| {
        if (!prod_paths.contains(sel)) try missing_selectors.append(ctx.allocator, sel);
    }
    if (missing_selectors.items.len > 0) {
        std.mem.sort([]const u8, missing_selectors.items, {}, lessThanSlices);
        try ctx.failFmt("legacy cutover policy omits production selectors: {s}", .{try formatPythonStringList(ctx.allocator, missing_selectors.items)});
    }
    for (required_selectors) |rel| {
        const text = try ctx.readText(rel);
        if (std.mem.indexOf(u8, text, "legacy_dpkg") == null and std.mem.indexOf(u8, text, "dpkg") == null) {
            try ctx.failFmt("legacy production selector lost its auditable identity: {s}", .{rel});
        }
    }

    const candidate_files = try ctx.walkCutoverMarkerFiles();
    var unclassified: std.ArrayList([]const u8) = .empty;
    for (candidate_files) |rel| {
        const text = try ctx.readText(rel);
        if (hasLegacyMarker(text) and !classified.contains(rel)) {
            try unclassified.append(ctx.allocator, rel);
        }
    }
    if (unclassified.items.len > 0) {
        std.mem.sort([]const u8, unclassified.items, {}, lessThanSlices);
        try ctx.failFmt("legacy cutover policy has unclassified production/test paths: {s}", .{try formatPythonStringList(ctx.allocator, unclassified.items)});
    }

    const contracts = policy.get("generated_contracts");
    if (contracts == null or contracts.? != .array or contracts.?.array.items.len != 2) {
        try ctx.fail("legacy cutover generated Actions inventory is incomplete");
    } else {
        for (contracts.?.array.items) |contract| {
            if (contract != .object) {
                try ctx.fail("legacy cutover generated Actions contract is malformed");
                continue;
            }
            const rel = getJsonString(contract.object, "path") orelse "";
            const req_ev = getJsonString(contract.object, "required_evidence") orelse "";
            if (!std.mem.eql(u8, req_ev, "backend-capability") or rel.len == 0 or !ctx.isRegularFile(rel)) {
                try ctx.fail("legacy cutover generated Actions contract is malformed");
                continue;
            }
            const bundle = try ctx.readText(rel);
            for ([_][]const u8{
                "backend-capability",
                "legacy-dpkg-execution-deprecated-v1",
                "native-transaction-execution-v1",
                "Recover this operation with debz >=0.3.0,<0.4.0 before installing a native-only release.",
            }) |token| {
                if (std.mem.indexOf(u8, bundle, token) == null) {
                    try ctx.failFmt("{s} lacks cutover capability evidence: {s}", .{ rel, token });
                }
            }
        }
    }
}

fn formatPythonStringList(allocator: std.mem.Allocator, items: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(allocator, '[');
    for (items, 0..) |item, i| {
        if (i > 0) try out.appendSlice(allocator, ", ");
        try out.append(allocator, '\'');
        try out.appendSlice(allocator, item);
        try out.append(allocator, '\'');
    }
    try out.append(allocator, ']');
    return out.toOwnedSlice(allocator);
}

pub fn auditDocs(ctx: *AuditContext) !void {
    if (ctx.pathExists("docs")) {
        try ctx.fail("stale docs/ directory exists; documentation belongs under doc/");
    }
    const md_files = try ctx.walkMarkdownFiles();
    for (md_files) |rel| {
        const text = try ctx.readText(rel);
        const parent_rel = std.fs.path.dirname(rel) orelse ".";
        var pos: usize = 0;
        while (pos < text.len) {
            const open_br = std.mem.indexOfScalarPos(u8, text, pos, '[') orelse break;
            var j = open_br + 1;
            while (j < text.len and text[j] != ']') : (j += 1) {}
            if (j == open_br + 1 or j + 1 >= text.len or text[j + 1] != '(') {
                pos = open_br + 1;
                continue;
            }
            const target_start = j + 2;
            var k = target_start;
            while (k < text.len and text[k] != ')') : (k += 1) {}
            if (k == target_start or k >= text.len) {
                pos = open_br + 1;
                continue;
            }
            const raw_target = text[target_start..k];
            pos = k + 1;

            const target = partitionBefore(raw_target, "#");
            if (target.len == 0 or std.mem.indexOf(u8, target, "://") != null or std.mem.startsWith(u8, target, "mailto:")) {
                continue;
            }
            const resolved = if (std.mem.startsWith(u8, target, "/"))
                try std.fs.path.resolve(ctx.allocator, &.{target})
            else
                try std.fs.path.resolve(ctx.allocator, &.{ ctx.root, parent_rel, target });

            const in_root = std.mem.eql(u8, resolved, ctx.root) or
                (std.mem.startsWith(u8, resolved, ctx.root) and resolved.len > ctx.root.len and resolved[ctx.root.len] == '/');
            if (!in_root) {
                try ctx.failFmt("{s}: link escapes repository: {s}", .{ rel, target });
            } else {
                _ = std.Io.Dir.cwd().statFile(ctx.io, resolved, .{}) catch {
                    try ctx.failFmt("{s}: stale local link: {s}", .{ rel, target });
                };
            }
        }
    }
}

fn hasSecretPrivateKey(data: []const u8) bool {
    const prefix = "-----BEGIN ";
    const suffix = "PRIVATE KEY-----";
    var pos: usize = 0;
    while (fastIndexOfPos(data, pos, prefix)) |idx| {
        pos = idx + prefix.len;
        for ([_][]const u8{ "", "RSA ", "EC ", "OPENSSH " }) |mid| {
            if (startsWithAt(data, pos, mid) and startsWithAt(data, pos + mid.len, suffix)) return true;
        }
    }
    return false;
}

fn hasSecretOpenPgpPrivateKey(data: []const u8) bool {
    const prefix = "-----BEGIN PGP ";
    const suffix = "PRIVATE KEY BLOCK-----";
    var pos: usize = 0;
    while (fastIndexOfPos(data, pos, prefix)) |idx| {
        pos = idx + prefix.len;
        if (startsWithAt(data, pos, suffix)) return true;
    }
    return false;
}

fn isBearerTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '~' or c == '+' or c == '/' or c == '=' or c == '-';
}

fn hasSecretBearer(data: []const u8) bool {
    const auth = "authorization";
    const bearer = "bearer";
    if (data.len < auth.len + 1 + bearer.len + 13) return false;
    var pos: usize = auth.len;
    while (fastIndexOfScalarPos(data, pos, ':')) |colon_idx| {
        pos = colon_idx + 1;
        var auth_end = colon_idx;
        while (auth_end > 0 and isSpace(data[auth_end - 1])) : (auth_end -= 1) {}
        if (auth_end < auth.len) continue;
        if (!std.ascii.eqlIgnoreCase(data[auth_end - auth.len .. auth_end], auth)) continue;
        var j = colon_idx + 1;
        while (j < data.len and isSpace(data[j])) : (j += 1) {}
        if (j + bearer.len > data.len or !std.ascii.eqlIgnoreCase(data[j .. j + bearer.len], bearer)) continue;
        j += bearer.len;
        if (j >= data.len or !isSpace(data[j])) continue;
        while (j < data.len and isSpace(data[j])) : (j += 1) {}
        const tok_start = j;
        while (j < data.len and isBearerTokenChar(data[j])) : (j += 1) {}
        if (j - tok_start >= 12) return true;
    }
    return false;
}

fn hasSecretAwsKey(data: []const u8) bool {
    var pos: usize = 0;
    while (fastIndexOfPos(data, pos, "AKIA")) |idx| {
        pos = idx + 4;
        if (pos + 16 > data.len) break;
        var ok = true;
        for (data[pos .. pos + 16]) |c| {
            if (!std.ascii.isDigit(c) and !(c >= 'A' and c <= 'Z')) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

fn hasSecretGithubToken(data: []const u8) bool {
    var pos: usize = 0;
    while (fastIndexOfPos(data, pos, "gh")) |idx| {
        pos = idx + 2;
        if (pos + 38 > data.len) break;
        const kind = data[pos];
        if (kind != 'p' and kind != 'o' and kind != 'u' and kind != 's' and kind != 'r') continue;
        if (data[pos + 1] != '_') continue;
        var j = pos + 2;
        while (j < data.len and std.ascii.isAlphanumeric(data[j])) : (j += 1) {}
        if (j - (pos + 2) >= 36) return true;
    }
    return false;
}

pub fn auditSecretsAndArtifacts(ctx: *AuditContext, files: []const []const u8) !void {
    const generated_roots = [_][]const u8{ "zig-out", ".zig-cache", "zig-pkg" };
    const generated_suffixes = [_][]const u8{ ".o", ".a", ".so", ".dll", ".dylib", ".exe", ".profraw" };
    for (files) |rel| {
        if (hasPathComponent(rel, "__pycache__") or
            std.ascii.endsWithIgnoreCase(rel, ".pyc") or
            std.ascii.endsWithIgnoreCase(rel, ".pyo"))
        {
            continue;
        }
        var in_gen_root = false;
        for (generated_roots) |gr| {
            if (hasPathComponent(rel, gr)) in_gen_root = true;
        }
        if (in_gen_root) {
            try ctx.failFmt("tracked generated artifact: {s}", .{rel});
        }
        const ext = std.fs.path.extension(rel);
        for (generated_suffixes) |gs| {
            if (std.ascii.eqlIgnoreCase(ext, gs)) {
                try ctx.failFmt("tracked generated binary artifact: {s}", .{rel});
                break;
            }
        }
        const data = ctx.readBytes(rel) catch continue;
        if (hasSecretPrivateKey(data)) {
            try ctx.failFmt("{s}: possible private key", .{rel});
        }
        if (hasSecretOpenPgpPrivateKey(data)) {
            try ctx.failFmt("{s}: possible OpenPGP private key", .{rel});
        }
        if (hasSecretBearer(data)) {
            try ctx.failFmt("{s}: possible bearer credential", .{rel});
        }
        if (hasSecretAwsKey(data)) {
            try ctx.failFmt("{s}: possible AWS access key", .{rel});
        }
        if (hasSecretGithubToken(data)) {
            try ctx.failFmt("{s}: possible GitHub token", .{rel});
        }
    }
}

fn isLowerHexLen(s: []const u8, expected_len: usize) bool {
    return isLowerHex(s, expected_len);
}

fn getJsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    return jsonStr(obj, key);
}

fn getJsonInt(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    return jsonInt(obj, key);
}

fn sliceContainsString(haystack: []const []const u8, needle: []const u8) bool {
    return sliceContainsStr(haystack, needle);
}

fn lessThanSlices(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn jsonObjectKeysEqual(obj: std.json.ObjectMap, expected: []const []const u8) bool {
    if (obj.count() != expected.len) return false;
    for (expected) |k| {
        if (!obj.contains(k)) return false;
    }
    return true;
}

fn hasPathComponent(path: []const u8, part: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |comp| {
        if (std.mem.eql(u8, comp, part)) return true;
    }
    return false;
}

fn normalizeNewlinesAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return normalizeNewlines(allocator, input);
}

fn readBoundedRegularInput(io: std.Io, allocator: std.mem.Allocator, input_path: []const u8, limit: usize) ![]const u8 {
    const flags: std.os.linux.O = .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    };
    const path_z = try std.fmt.allocPrintSentinel(allocator, "{s}", .{input_path}, 0);
    const rc = std.os.linux.openat(std.os.linux.AT.FDCWD, path_z.ptr, flags, 0);
    if (std.os.linux.errno(rc) != .SUCCESS) return error.InvalidCheckInput;
    var file: std.Io.File = .{ .handle = @intCast(rc), .flags = .{ .nonblocking = true } };
    defer file.close(io);
    const st = file.stat(io) catch return error.InvalidCheckInput;
    if (st.kind != .file) return error.InvalidCheckInput;
    var buf = try allocator.alloc(u8, limit + 1);
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.os.linux.read(file.handle, buf[total..].ptr, buf.len - total);
        if (std.os.linux.errno(n) != .SUCCESS) return error.InvalidCheckInput;
        if (n == 0) break;
        total += n;
    }
    if (total > limit) return error.InvalidCheckInput;
    const data = buf[0..total];
    if (!std.unicode.utf8ValidateSlice(data)) return error.InvalidCheckInput;
    return normalizeNewlinesAlloc(allocator, data);
}

fn resolveNativeOnlyCandidateExecutable(allocator: std.mem.Allocator, root: []const u8, environ_map: *const std.process.Environ.Map) ![]const u8 {
    if (environ_map.get("DEBZ_NATIVE_ONLY_CANDIDATE")) |env_exe| {
        if (env_exe.len > 0) return allocator.dupe(u8, env_exe);
    }
    return std.fs.path.join(allocator, &.{ root, "zig-out/bin/debz-native-only-candidate" });
}

fn validateFixtureWalk(
    io: std.Io,
    allocator: std.mem.Allocator,
    root: []const u8,
    rel_dir: []const u8,
    depth: usize,
    max_depth: usize,
    count: *usize,
    max_count: usize,
    skip_git: bool,
    check_symlinks_and_size: bool,
) !void {
    if (depth > max_depth) return error.ExceedsTraversalBounds;
    const abs = if (rel_dir.len == 0) root else try std.fs.path.join(allocator, &.{ root, rel_dir });
    var dir = try std.Io.Dir.openDirAbsolute(io, abs, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (skip_git and std.mem.eql(u8, entry.name, ".git") and entry.kind == .directory) continue;
        count.* += 1;
        if (count.* > max_count) return error.ExceedsTraversalBounds;
        if (check_symlinks_and_size and entry.kind == .sym_link) return error.ContainsSymlink;
        const child_rel = if (rel_dir.len == 0)
            try allocator.dupe(u8, entry.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rel_dir, entry.name });
        if (entry.kind == .directory) {
            try validateFixtureWalk(io, allocator, root, child_rel, depth + 1, max_depth, count, max_count, skip_git, check_symlinks_and_size);
        } else if (check_symlinks_and_size and entry.kind == .file) {
            const child_abs = try std.fs.path.join(allocator, &.{ root, child_rel });
            var f = try std.Io.Dir.openFileAbsolute(io, child_abs, .{});
            defer f.close(io);
            const st = try f.stat(io);
            if (st.size > 1024 * 1024) return error.FileTooLarge;
        }
    }
}

pub fn checkPolicyInput(
    ctx: *AuditContext,
    environ_map: *const std.process.Environ.Map,
    kind: []const u8,
    input_path: []const u8,
    stdout_buf: *std.ArrayList(u8),
    stderr_buf: *std.ArrayList(u8),
) !u8 {
    const limit: usize = if (std.mem.eql(u8, kind, "native-final") or
        std.mem.eql(u8, kind, "native-only-candidate") or
        std.mem.eql(u8, kind, "native-provenance"))
        2 * 1024 * 1024
    else
        1024 * 1024;

    const text = readBoundedRegularInput(ctx.io, ctx.allocator, input_path, limit) catch {
        try stderr_buf.appendSlice(
            ctx.allocator,
            try std.fmt.allocPrint(ctx.allocator, "security-audit: check input must be a regular file of at most {d} MiB\n", .{limit / (1024 * 1024)}),
        );
        return 2;
    };

    var failures: [][]const u8 = &.{};
    if (std.mem.eql(u8, kind, "action-pin")) {
        failures = try actionPinFailures(ctx.allocator, text, "action.yml");
    } else if (std.mem.eql(u8, kind, "native-only-candidate") or std.mem.eql(u8, kind, "actions-native-only")) {
        const exe = try resolveNativeOnlyCandidateExecutable(ctx.allocator, ctx.root, environ_map);
        var child_env = std.process.Environ.Map.init(ctx.allocator);
        try child_env.put("PATH", "/no-host-interpreters");
        const res = try std.process.run(ctx.allocator, ctx.io, .{
            .argv = &.{ exe, "--root", ctx.root, "check", kind, input_path },
            .environ_map = &child_env,
        });
        try stdout_buf.appendSlice(ctx.allocator, res.stdout);
        try stderr_buf.appendSlice(ctx.allocator, res.stderr);
        return switch (res.term) {
            .exited => |c| c,
            else => 1,
        };
    } else if (std.mem.eql(u8, kind, "ghr-ci")) {
        failures = try ghrZigWorkflowFailures(ctx.allocator, text, "ci.yml", 23);
    } else if (std.mem.eql(u8, kind, "ghr-release")) {
        failures = try ghrZigWorkflowFailures(ctx.allocator, text, "release.yml", 3);
    } else if (std.mem.eql(u8, kind, "workflow-failure")) {
        failures = try workflowFailureHandlingFailures(ctx.allocator, text, "ci.yml");
    } else if (std.mem.eql(u8, kind, "ci-concurrency")) {
        failures = try ciConcurrencyFailures(ctx.allocator, text, "ci.yml");
    } else if (std.mem.eql(u8, kind, "ci-recovery")) {
        failures = try nativeRecoveryCiFailures(ctx.allocator, text);
    } else if (std.mem.eql(u8, kind, "ci-rootless")) {
        failures = try rootlessRootCiFailures(ctx.allocator, text);
    } else if (std.mem.eql(u8, kind, "workload-build")) {
        failures = try workloadPartitionFailures(ctx.allocator, text);
    } else if (std.mem.eql(u8, kind, "ci-signed-proc")) {
        failures = try signedProcCiFailures(ctx.allocator, text);
    } else if ( getNativeSourcesForKind(kind)) |paths| {
        const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, text, .{}) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid native wiring input\n");
            return 2;
        };
        if (parsed.value != .object or parsed.value.object.count() != 2) {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid native wiring input\n");
            return 2;
        }
        const f_path_val = parsed.value.object.get("path") orelse {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid native wiring input\n");
            return 2;
        };
        const f_text_val = parsed.value.object.get("text") orelse {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid native wiring input\n");
            return 2;
        };
        if (f_path_val != .string or !sliceContainsString(paths, f_path_val.string) or
            (f_text_val != .null and f_text_val != .string))
        {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid native wiring input\n");
            return 2;
        }
        var texts = try loadExistingTextMap(ctx, paths);
        if (f_text_val == .null) {
            _ = texts.orderedRemove(f_path_val.string);
        } else {
            try texts.put(ctx.allocator, f_path_val.string, f_text_val.string);
        }
        failures = try dispatchNativeKindFailures(ctx.allocator, kind, paths, texts);
    } else if (std.mem.eql(u8, kind, "release-install-metadata")) {
        failures = try releaseInstallMetadataFailures(ctx.allocator, text);
    } else if (std.mem.eql(u8, kind, "dependency-zstd")) {
        failures = try dependencyOptionFailures(ctx.allocator, text, "zstd", &.{
            .{ .name = "target", .value = "target" },
            .{ .name = "optimize", .value = "optimize" },
            .{ .name = "shared", .value = "false" },
            .{ .name = "tools", .value = "false" },
            .{ .name = "multithread", .value = "false" },
        });
    } else if (std.mem.eql(u8, kind, "runtime-metadata")) {
        const dep_policy_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText("security/dependency-policy.json"), .{});
        const metadata_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, text, .{});
        var dependencies: std.StringArrayHashMapUnmanaged(std.json.ObjectMap) = .empty;
        for (jsonArr(dep_policy_parsed.value.object, "production_dependencies") orelse &.{}) |item| {
            if (item == .object) {
                if (jsonStr(item.object, "name")) |n| {
                    try dependencies.put(ctx.allocator, n, item.object);
                }
            }
        }
        failures = try runtimeMetadataFailures(ctx.allocator, metadata_parsed.value, dependencies);
    } else if (std.mem.eql(u8, kind, "digest-semantic")) {
        const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, text, .{}) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid digest semantic input\n");
            return 2;
        };
        if (parsed.value != .object or parsed.value.object.count() != 2 or
            getJsonString(parsed.value.object, "path") == null or
            getJsonString(parsed.value.object, "text") == null)
        {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid digest semantic input\n");
            return 2;
        }
        const policy_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, try ctx.readText(DIGEST_POLICY_PATH), .{});
        var texts = ctx.baseDigestTexts() catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: digest check input exceeds repository bounds\n");
            return 2;
        };
        try texts.put(ctx.allocator, getJsonString(parsed.value.object, "path").?, getJsonString(parsed.value.object, "text").?);
        const candidates = try digestSemanticCandidates(ctx, texts);
        failures = try semanticAllowlistFailures(
            ctx.allocator,
            candidates,
            policy_parsed.value.object,
            try ctx.readText(DIGEST_SEMANTIC_ALLOWLIST_PATH),
        );
    } else if (std.mem.eql(u8, kind, "digest-inventory")) {
        const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, text, .{}) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid digest inventory input\n");
            return 2;
        };
        if (!isValidDigestInventoryInput(parsed.value)) {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid digest inventory input\n");
            return 2;
        }
        const obj = parsed.value.object;
        const policy_text = getJsonString(obj, "policy") orelse try ctx.readText(DIGEST_POLICY_PATH);
        const inventory_text = getJsonString(obj, "inventory") orelse try ctx.readText(DIGEST_INVENTORY_PATH);
        const policy_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, policy_text, .{});
        var texts = ctx.baseDigestTexts() catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: digest check input exceeds repository bounds\n");
            return 2;
        };
        const target_path = getJsonString(obj, "path").?;
        const existing = texts.get(target_path) orelse {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: digest inventory path is not audited\n");
            return 2;
        };
        if (getJsonString(obj, "append")) |app| {
            try texts.put(ctx.allocator, target_path, try std.fmt.allocPrint(ctx.allocator, "{s}{s}", .{ existing, app }));
        } else {
            try texts.put(ctx.allocator, target_path, getJsonString(obj, "text").?);
        }
        failures = try digestInventoryFailures(ctx, texts, policy_parsed.value.object, inventory_text);
    } else if (std.mem.eql(u8, kind, "digest-inventory-synthetic")) {
        const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, text, .{}) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid digest inventory synthetic input\n");
            return 2;
        };
        if (parsed.value != .object or parsed.value.object.count() != 1 or getJsonString(parsed.value.object, "case") == null) {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid digest inventory synthetic input\n");
            return 2;
        }
        const case_name = getJsonString(parsed.value.object, "case").?;
        failures = digestInventorySyntheticFailures(ctx, case_name) catch {
            try stderr_buf.appendSlice(
                ctx.allocator,
                try std.fmt.allocPrint(ctx.allocator, "security-audit: unknown synthetic digest inventory case: {s}\n", .{case_name}),
            );
            return 2;
        };
    } else if (std.mem.eql(u8, kind, "digest-semantic-allowlist-synthetic")) {
        const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, text, .{}) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid digest semantic allowlist synthetic input\n");
            return 2;
        };
        if (parsed.value != .object or parsed.value.object.count() != 1 or getJsonString(parsed.value.object, "case") == null) {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid digest semantic allowlist synthetic input\n");
            return 2;
        }
        const case_name = getJsonString(parsed.value.object, "case").?;
        failures = semanticAllowlistSyntheticFailures(ctx.allocator, case_name) catch {
            try stderr_buf.appendSlice(
                ctx.allocator,
                try std.fmt.allocPrint(ctx.allocator, "security-audit: unknown synthetic semantic allowlist case: {s}\n", .{case_name}),
            );
            return 2;
        };
    } else if (std.mem.eql(u8, kind, "digest-allowlist")) {
        const policy_parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, text, .{});
        const texts = try ctx.baseDigestTexts();
        const candidates = try digestSemanticCandidates(ctx, texts);
        failures = try semanticAllowlistFailures(
            ctx.allocator,
            candidates,
            policy_parsed.value.object,
            try ctx.readText(DIGEST_SEMANTIC_ALLOWLIST_PATH),
        );
    } else if (std.mem.eql(u8, kind, "digest-untracked")) {
        const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, text, .{}) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid untracked fixture\n");
            return 2;
        };
        if (parsed.value != .object or parsed.value.object.count() != 1 or getJsonString(parsed.value.object, "root") == null) {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid untracked fixture\n");
            return 2;
        }
        const fixture_root = std.Io.Dir.cwd().realPathFileAlloc(ctx.io, getJsonString(parsed.value.object, "root").?, ctx.allocator) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: untracked fixture must be in the repository test cache\n");
            return 2;
        };
        const cache_tmp = try std.fs.path.join(ctx.allocator, &.{ ctx.root, ".zig-cache/tmp" });
        if (!std.mem.startsWith(u8, fixture_root, cache_tmp) or
            (fixture_root.len > cache_tmp.len and fixture_root[cache_tmp.len] != '/'))
        {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: untracked fixture must be in the repository test cache\n");
            return 2;
        }
        var sub_ctx: AuditContext = .{ .io = ctx.io, .allocator = ctx.allocator, .cache_allocator = ctx.cache_allocator, .root = fixture_root };
        if (!sub_ctx.isDirectory(".git")) {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: untracked fixture needs its own Git root\n");
            return 2;
        }
        var count: usize = 0;
        validateFixtureWalk(ctx.io, ctx.allocator, fixture_root, "", 0, 8, &count, 128, true, false) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: untracked fixture exceeds traversal bounds\n");
            return 2;
        };
        const paths = try repositoryDigestFiles(&sub_ctx, &.{});
        if (paths.len > 128) {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: untracked fixture exceeds file bounds\n");
            return 2;
        }
        for (paths, 0..) |p, idx| {
            if (idx > 0) try stdout_buf.append(ctx.allocator, '\n');
            try stdout_buf.appendSlice(ctx.allocator, p);
        }
        try stdout_buf.append(ctx.allocator, '\n');
        failures = &.{};
    } else if (std.mem.eql(u8, kind, "docs-links")) {
        const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, text, .{}) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid docs fixture\n");
            return 2;
        };
        if (parsed.value != .object or parsed.value.object.count() != 1 or getJsonString(parsed.value.object, "root") == null) {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: invalid docs fixture\n");
            return 2;
        }
        const fixture_root = std.Io.Dir.cwd().realPathFileAlloc(ctx.io, getJsonString(parsed.value.object, "root").?, ctx.allocator) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: docs fixture must be in the repository test cache\n");
            return 2;
        };
        const cache_tmp = try std.fs.path.join(ctx.allocator, &.{ ctx.root, ".zig-cache/tmp" });
        if (!std.mem.startsWith(u8, fixture_root, cache_tmp) or
            (fixture_root.len > cache_tmp.len and fixture_root[cache_tmp.len] != '/'))
        {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: docs fixture must be in the repository test cache\n");
            return 2;
        }
        var root_dir = std.Io.Dir.openDirAbsolute(ctx.io, fixture_root, .{}) catch {
            try stderr_buf.appendSlice(ctx.allocator, "security-audit: docs fixture root is not a directory\n");
            return 2;
        };
        root_dir.close(ctx.io);
        var count: usize = 0;
        validateFixtureWalk(ctx.io, ctx.allocator, fixture_root, "", 0, 16, &count, 256, false, true) catch |err| {
            switch (err) {
                error.ContainsSymlink => try stderr_buf.appendSlice(ctx.allocator, "security-audit: docs fixture contains a symlink\n"),
                error.FileTooLarge => try stderr_buf.appendSlice(ctx.allocator, "security-audit: docs fixture file is too large\n"),
                else => try stderr_buf.appendSlice(ctx.allocator, "security-audit: docs fixture exceeds traversal bounds\n"),
            }
            return 2;
        };
        var sub_ctx: AuditContext = .{ .io = ctx.io, .allocator = ctx.allocator, .cache_allocator = ctx.cache_allocator, .root = fixture_root };
        try auditDocs(&sub_ctx);
        failures = try sub_ctx.failures.toOwnedSlice(ctx.allocator);
    } else {
        try stderr_buf.appendSlice(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "security-audit: unknown check kind: {s}\n", .{kind}));
        return 2;
    }

    for (failures) |failure| {
        try stderr_buf.appendSlice(ctx.allocator, try std.fmt.allocPrint(ctx.allocator, "security-audit: {s}\n", .{failure}));
    }
    return if (failures.len > 0) 1 else 0;
}

fn isValidDigestInventoryInput(val: std.json.Value) bool {
    if (val != .object) return false;
    const obj = val.object;
    if (getJsonString(obj, "path") == null) return false;
    const has_append = obj.contains("append");
    const has_text = obj.contains("text");
    if (has_append == has_text) return false;
    if (has_append) {
        const a = getJsonString(obj, "append") orelse return false;
        if (a.len > 4096) return false;
    }
    if (has_text and getJsonString(obj, "text") == null) return false;
    if (obj.contains("policy") and getJsonString(obj, "policy") == null) return false;
    if (obj.contains("inventory") and getJsonString(obj, "inventory") == null) return false;
    const allowed = [_][]const u8{ "path", "append", "text", "policy", "inventory" };
    var it = obj.iterator();
    while (it.next()) |entry| {
        if (!sliceContainsString(&allowed, entry.key_ptr.*)) return false;
    }
    return true;
}

fn getNativeSourcesForKind(kind: []const u8) ?[]const []const u8 {
    if (std.mem.eql(u8, kind, "native-core")) return &.{ "build.zig", "test/native_recovery_helper.zig", "test/native_lifecycle_support.zig" };
    if (std.mem.eql(u8, kind, "native-final")) return &.{ "test/native_recovery_helper.zig", "test/native_lifecycle_support.zig", "src/native_unpack.zig" };
    if (std.mem.eql(u8, kind, "native-entry")) return &.{ "test/native_recovery_acceptance.zig", "test/native_recovery_projected_workflows.zig", ".github/workflows/ci.yml" };
    if (std.mem.eql(u8, kind, "native-consumer")) return &.{ "test/native_recovery_parity.zig", "test/native_recovery_parity_evidence.zig" };
    if (std.mem.eql(u8, kind, "native-repository")) return &.{"test/native_recovery_repository.zig"};
    if (std.mem.eql(u8, kind, "native-workflow")) return &.{ "build.zig", "test/native_recovery_family.zig", "test/native_recovery_projected_workflows.zig" };
    if (std.mem.eql(u8, kind, "native-report")) return &REPORT_PATH_ORACLE_FILES;
    if (std.mem.eql(u8, kind, "native-lifecycle")) return &.{ "build.zig", "test/native_trigger_acceptance.zig" };
    if (std.mem.eql(u8, kind, "native-provenance")) return &.{
        "build.zig",
        "src/sha512_transaction_e2e_test.zig",
        "src/native_provenance_binding_test.zig",
        "src/native_transaction_result.zig",
        "src/repository_backend.zig",
        "src/native_recovery.zig",
        "src/native_unpack.zig",
        "src/production_backend.zig",
    };
    if (std.mem.eql(u8, kind, "reference-root")) return &REFERENCE_ROOT_PATHS;
    if (std.mem.eql(u8, kind, "protected-reference")) return &PROTECTED_REFERENCE_PATHS;
    if (std.mem.eql(u8, kind, "native-cli-smoke")) return &CLI_SMOKE_PATHS;
    if (std.mem.eql(u8, kind, "native-action-empty-lock")) return &ACTION_EMPTY_LOCK_PATHS;
    if (std.mem.eql(u8, kind, "native-debian-readiness")) return &DEBIAN_READINESS_PATHS;
    if (std.mem.eql(u8, kind, "native-release-core")) return &NATIVE_RELEASE_CORE_PATHS;
    if (std.mem.eql(u8, kind, "native-integration-archive")) return &INTEGRATION_ARCHIVE_PATHS;
    if (std.mem.eql(u8, kind, "native-baseline-fixture")) return &BASELINE_FIXTURE_PATHS;
    if (std.mem.eql(u8, kind, "native-disposable-runtime")) return &DISPOSABLE_RUNTIME_PATHS;
    if (std.mem.eql(u8, kind, "native-openpgp-fixtures")) return &OPENPGP_FIXTURE_PATHS;
    if (std.mem.eql(u8, kind, "native-integration-signing")) return &INTEGRATION_SIGNING_PATHS;
    if (std.mem.eql(u8, kind, "native-gate")) return &.{
        "build.zig",
        "test/native_recovery_helper.zig",
        "test/native_recovery_family.zig",
        "test/native_recovery_projected_workflows.zig",
        "test/native_recovery_repository.zig",
        "test/native_recovery_diversions.zig",
    };
    if (std.mem.eql(u8, kind, "native-fixtures")) return &.{
        "tools/native-materialization-fixtures.py",
        "tools/native-lifecycle-fixtures.py",
        "tools/native-trigger-fixtures.py",
        "tools/native_diversion_settlement_oracle.py",
        "tools/test_real_snapshot_reference_triggers.py",
        "tools/native-differential.py",
        "tools/native_only_candidate.py",
        "tools/dpkg-config-reference.py",
        "tools/test_dpkg_config_reference.py",
        "tools/dpkg-alternatives-reference.py",
        "tools/test_dpkg_alternatives_reference.py",
        "tools/dpkg-config-reference.zig",
        "actions/install/__tests__/integration.test.ts",
        "tools/test-native-lifecycle.py",
        "tools/test_native_lifecycle.py",
        "tools/test-native-triggers.py",
        "tools/test_native_triggers.py",
        "tools/test-native-recovery.py",
        "tools/test_native_recovery.py",
    };
    return null;
}

fn dispatchNativeKindFailures(
    allocator: std.mem.Allocator,
    kind: []const u8,
    paths: []const []const u8,
    texts: std.StringArrayHashMapUnmanaged([]const u8),
) ![][]const u8 {
    if (std.mem.eql(u8, kind, "native-core")) {
        return nativeCoreCompletionWiringFailures(allocator, texts.get(paths[0]) orelse "", texts.get(paths[1]) orelse "", texts.get(paths[2]) orelse "");
    }
    if (std.mem.eql(u8, kind, "native-final")) {
        return nativeExerciseFinalWiringFailures(allocator, texts.get(paths[0]) orelse "", texts.get(paths[1]) orelse "", texts.get(paths[2]) orelse "");
    }
    if (std.mem.eql(u8, kind, "native-entry")) {
        return nativeEntryPointShapeFailures(allocator, texts.get(paths[0]) orelse "", texts.get(paths[1]) orelse "", texts.get(paths[2]) orelse "");
    }
    if (std.mem.eql(u8, kind, "native-consumer")) {
        return nativeConsumerReceiptWiringFailures(allocator, texts.get(paths[0]) orelse "", texts.get(paths[1]) orelse "");
    }
    if (std.mem.eql(u8, kind, "native-repository")) {
        return nativeRepositoryEvidenceWiringFailures(allocator, texts.get(paths[0]) orelse "");
    }
    if (std.mem.eql(u8, kind, "native-workflow")) {
        return nativeWorkflowAcceptanceWiringFailures(allocator, texts.get(paths[0]) orelse "", texts.get(paths[1]) orelse "", texts.get(paths[2]) orelse "");
    }
    if (std.mem.eql(u8, kind, "native-report")) {
        return nativeReportPathWiringFailures(allocator, texts);
    }
    if (std.mem.eql(u8, kind, "native-lifecycle")) {
        return nativeLifecycleMigrationFailures(allocator, texts.get(paths[0]) orelse "", texts.get(paths[1]) orelse "");
    }
    if (std.mem.eql(u8, kind, "native-gate")) {
        return nativeRecoveryGateWiringFailures(
            allocator,
            texts.get(paths[0]) orelse "",
            texts.get(paths[1]) orelse "",
            texts.get(paths[2]) orelse "",
            texts.get(paths[3]) orelse "",
            texts.get(paths[4]) orelse "",
            texts.get(paths[5]) orelse "",
        );
    }
    if (std.mem.eql(u8, kind, "native-provenance")) {
        return nativeProvenanceBindingWiringFailures(
            allocator,
            texts.get(paths[0]) orelse "",
            texts.get(paths[1]) orelse "",
            texts.get(paths[2]) orelse "",
            texts.get(paths[3]) orelse "",
            texts.get(paths[4]) orelse "",
            texts.get(paths[5]) orelse "",
            texts.get(paths[6]) orelse "",
            texts.get(paths[7]) orelse "",
        );
    }
    if (std.mem.eql(u8, kind, "reference-root")) {
        return referenceLauncherRootWiringFailures(
            allocator,
            texts.get(paths[0]) orelse "",
            texts.get(paths[1]) orelse "",
            texts.get(paths[2]) orelse "",
            texts.get(paths[3]) orelse "",
        );
    }
    if (std.mem.eql(u8, kind, "protected-reference")) return protectedReferenceCiFailures(allocator, texts);
    if (std.mem.eql(u8, kind, "native-cli-smoke")) return nativeCliSmokeFailures(allocator, texts);
    if (std.mem.eql(u8, kind, "native-action-empty-lock")) return nativeActionEmptyLockFailures(allocator, texts);
    if (std.mem.eql(u8, kind, "native-debian-readiness")) return nativeDebianReadinessFailures(allocator, texts);
    if (std.mem.eql(u8, kind, "native-release-core")) return nativeReleaseCoreFailures(allocator, texts);
    if (std.mem.eql(u8, kind, "native-integration-archive")) return nativeIntegrationArchiveFailures(allocator, texts);
    if (std.mem.eql(u8, kind, "native-baseline-fixture")) return nativeBaselineFixtureFailures(allocator, texts);
    if (std.mem.eql(u8, kind, "native-disposable-runtime")) return nativeDisposableRuntimeFailures(allocator, texts);
    if (std.mem.eql(u8, kind, "native-openpgp-fixtures")) return nativeOpenpgpFixtureFailures(allocator, texts);
    if (std.mem.eql(u8, kind, "native-integration-signing")) return nativeIntegrationSigningFailures(allocator, texts);
    return nativeLifecycleFixtureFailures(allocator, texts);
}

pub fn runCheckServer(ctx: *AuditContext, environ_map: *const std.process.Environ.Map) !u8 {
    ctx.server_mode = true;
    var stdin_file = std.Io.File.stdin();
    var stdout_file = std.Io.File.stdout();
    var line_buf: std.ArrayList(u8) = .empty;
    var byte: [1]u8 = undefined;
    var reader = stdin_file.reader(ctx.io, &.{});
    while (true) {
        line_buf.clearRetainingCapacity();
        var eof = false;
        while (true) {
            reader.interface.readSliceAll(&byte) catch |err| switch (err) {
                error.EndOfStream => {
                    eof = true;
                    break;
                },
                else => return err,
            };
            if (byte[0] == '\n') break;
            try line_buf.append(ctx.allocator, byte[0]);
        }
        if (eof and line_buf.items.len == 0) break;
        const line = std.mem.trimEnd(u8, line_buf.items, "\r\n");
        if (line.len == 0) continue;

        var parts = std.mem.splitScalar(u8, line, '\t');
        const kind = parts.next() orelse continue;
        const input_path = parts.next() orelse continue;
        const output_path = parts.next() orelse continue;

        var req_arena = std.heap.ArenaAllocator.init(ctx.allocator);
        defer req_arena.deinit();
        const saved_alloc = ctx.allocator;
        ctx.allocator = req_arena.allocator();
        defer ctx.allocator = saved_alloc;

        var out_buf: std.ArrayList(u8) = .empty;
        var err_buf: std.ArrayList(u8) = .empty;
        const code = try checkPolicyInput(ctx, environ_map, kind, input_path, &out_buf, &err_buf);
        const resp_json = try std.json.Stringify.valueAlloc(ctx.allocator, .{
            .code = code,
            .stdout = out_buf.items,
            .stderr = err_buf.items,
        }, .{});
        var out_file = try std.Io.Dir.createFileAbsolute(ctx.io, output_path, .{ .truncate = true });
        try out_file.writeStreamingAll(ctx.io, resp_json);
        out_file.close(ctx.io);
        try stdout_file.writeStreamingAll(ctx.io, "ok\n");
    }
    return 0;
}

pub fn runAuditMain(ctx: *AuditContext) !u8 {
    const files = try trackedFiles(ctx);
    try auditDigestCutover(ctx, files);
    try auditProductionSources(ctx);
    try auditDependencies(ctx);
    try auditReleaseTargets(ctx);
    try auditCiPins(ctx);
    try auditCompositeActionPins(ctx);
    try auditSetupActionDependencies(ctx);
    try auditDownloadAction(ctx);
    try auditInstallAction(ctx);
    try auditLegacyCutoverPolicy(ctx);
    try auditDocs(ctx);
    try auditSecretsAndArtifacts(ctx, files);
    if (ctx.failures.items.len > 0) {
        var stderr_file = std.Io.File.stderr();
        for (ctx.failures.items) |failure| {
            const line = try std.fmt.allocPrint(ctx.allocator, "security-audit: {s}\n", .{failure});
            try stderr_file.writeStreamingAll(ctx.io, line);
        }
        return 1;
    }
    try std.Io.File.stdout().writeStreamingAll(ctx.io, "security-audit: all gates passed\n");
    return 0;
}

pub fn main(init: std.process.Init) !u8 {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    var args_list: std.ArrayList([]const u8) = .empty;
    var args_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    while (args_it.next()) |arg| {
        try args_list.append(allocator, arg);
    }
    const raw_args = args_list.items;

    var root: []const u8 = try std.Io.Dir.cwd().realPathFileAlloc(init.io, ".", allocator);
    var filtered_args: std.ArrayList([]const u8) = .empty;
    var idx: usize = 1;
    while (idx < raw_args.len) : (idx += 1) {
        if (std.mem.eql(u8, raw_args[idx], "--root") and idx + 1 < raw_args.len) {
            root = try std.Io.Dir.cwd().realPathFileAlloc(init.io, raw_args[idx + 1], allocator);
            idx += 1;
        } else {
            try filtered_args.append(allocator, raw_args[idx]);
        }
    }
    const args = filtered_args.items;

    var ctx: AuditContext = .{
        .io = init.io,
        .allocator = allocator,
        .cache_allocator = allocator,
        .root = root,
    };

    if (args.len == 1 and std.mem.eql(u8, args[0], "--write-digest-inventory")) {
        var out_buf: std.ArrayList(u8) = .empty;
        var err_buf: std.ArrayList(u8) = .empty;
        const code = try writeDigestInventory(&ctx, false, &out_buf, &err_buf);
        if (out_buf.items.len > 0) try std.Io.File.stdout().writeStreamingAll(init.io, out_buf.items);
        if (err_buf.items.len > 0) try std.Io.File.stderr().writeStreamingAll(init.io, err_buf.items);
        return code;
    }
    if (args.len == 1 and std.mem.eql(u8, args[0], "--check-digest-inventory")) {
        var out_buf: std.ArrayList(u8) = .empty;
        var err_buf: std.ArrayList(u8) = .empty;
        const code = try writeDigestInventory(&ctx, true, &out_buf, &err_buf);
        if (out_buf.items.len > 0) try std.Io.File.stdout().writeStreamingAll(init.io, out_buf.items);
        if (err_buf.items.len > 0) try std.Io.File.stderr().writeStreamingAll(init.io, err_buf.items);
        return code;
    }
    if (args.len == 1 and std.mem.eql(u8, args[0], "--check-server")) {
        return runCheckServer(&ctx, init.environ_map);
    }
    if (args.len == 3 and std.mem.eql(u8, args[0], "check")) {
        var out_buf: std.ArrayList(u8) = .empty;
        var err_buf: std.ArrayList(u8) = .empty;
        const code = try checkPolicyInput(&ctx, init.environ_map, args[1], args[2], &out_buf, &err_buf);
        if (out_buf.items.len > 0) try std.Io.File.stdout().writeStreamingAll(init.io, out_buf.items);
        if (err_buf.items.len > 0) try std.Io.File.stderr().writeStreamingAll(init.io, err_buf.items);
        return code;
    }
    if (args.len == 1 and std.mem.eql(u8, args[0], "native-only-candidate")) {
        const exe = try resolveNativeOnlyCandidateExecutable(allocator, root, init.environ_map);
        var child_env = std.process.Environ.Map.init(allocator);
        try child_env.put("PATH", "/no-host-interpreters");
        const res = try std.process.run(allocator, init.io, .{
            .argv = &.{ exe, "--root", root, "native-only-candidate" },
            .environ_map = &child_env,
        });
        if (res.stdout.len > 0) try std.Io.File.stdout().writeStreamingAll(init.io, res.stdout);
        if (res.stderr.len > 0) try std.Io.File.stderr().writeStreamingAll(init.io, res.stderr);
        return switch (res.term) {
            .exited => |c| c,
            else => 1,
        };
    }
    if (args.len == 0) {
        return runAuditMain(&ctx);
    }
    try std.Io.File.stderr().writeStreamingAll(init.io, "security-audit: invalid command-line arguments\n");
    return 2;
}



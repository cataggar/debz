//! Network-free policy audit and unit tests for release and CI workflows.
const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const maximum_file_bytes = 16 * 1024 * 1024;

pub const ghr_zig_install =
    \\      - name: Install Zig via ghr
    \\        uses: cataggar/ghr/actions/install@c4be68b52d67d7acd2a7fe6c1e5f126e1754176e # v0.8.1
    \\        env:
    \\          GH_TOKEN: ${{ github.token }}
    \\        with:
    \\          ghr-version: v0.8.1
    \\          tools: >-
    \\            cataggar/zig@v0.17.0
    \\            RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
    \\      - name: Validate Zig version
    \\        run: test "$(zig version)" = 0.17.0
    \\
;

pub const ghr_standalone_setup =
    \\      - name: Install verified standalone ghr
    \\        id: ghr
    \\        uses: cataggar/ghr/actions/setup@c4be68b52d67d7acd2a7fe6c1e5f126e1754176e # v0.8.1
    \\        with:
    \\          ghr-version: v0.8.1
    \\
;

pub const ci_concurrency =
    \\concurrency:
    \\  group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.event.pull_request.number || github.event_name == 'push' && github.ref || github.run_id }}
    \\  cancel-in-progress: ${{ github.event_name == 'push' || github.event_name == 'pull_request' }}
    \\
;

pub const ci_ghr_zig_jobs = [_][]const u8{
    "install-action-native",
    "download-action-cache",
    "download-action-container-fixture",
    "build-and-test-workload",
    "build-and-test-workload-production",
    "build-and-test-workload-apt-system",
    "build-and-test-workload-native",
    "build-and-test-workload-release",
    "native-recovery-zig-workflows",
    "native-recovery-zig-repository",
    "native-recovery-zig-helper",
    "native-recovery-zig-family",
    "native-recovery-zig-scenarios",
    "native-recovery-zig-diversions",
    "arm64-dpkg-oracles",
    "signed-proc-protected-replay",
    "security-audit",
    "release-dry-run",
    "release-dry-run-verify",
    "release-policy",
    "fuzz",
    "integration-required",
    "integration-full",
};

pub const release_ghr_zig_jobs = [_][]const u8{
    "binaries",
    "release",
    "smoke",
};

pub const Failures = struct {
    allocator: std.mem.Allocator,
    list: std.ArrayList([]const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) Failures {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Failures) void {
        self.list.deinit(self.allocator);
    }

    pub fn clear(self: *Failures) void {
        self.list.clearRetainingCapacity();
    }

    pub fn append(self: *Failures, message: []const u8) !void {
        try self.list.append(self.allocator, try self.allocator.dupe(u8, message));
    }

    pub fn print(self: *Failures, comptime fmt: []const u8, args: anytype) !void {
        try self.list.append(self.allocator, try std.fmt.allocPrint(self.allocator, fmt, args));
    }

    pub fn items(self: *const Failures) []const []const u8 {
        return self.list.items;
    }
};

fn countSubstr(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;
    var count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, pos, needle)) |idx| {
        count += 1;
        pos = idx + needle.len;
    }
    return count;
}

fn containsLineBlock(text: []const u8, block: []const u8) bool {
    const trimmed = std.mem.trimEnd(u8, block, "\n");
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, trimmed)) |idx| {
        const at_line_start = (idx == 0 or text[idx - 1] == '\n');
        const end = idx + trimmed.len;
        const at_line_end = (end == text.len or text[end] == '\n');
        if (at_line_start and at_line_end) return true;
        pos = idx + 1;
    }
    return false;
}

fn isJobHeaderLine(line: []const u8) bool {
    if (line.len < 4 or !std.mem.startsWith(u8, line, "  ") or line[line.len - 1] != ':') return false;
    if (!std.ascii.isLower(line[2])) return false;
    for (line[3 .. line.len - 1]) |c| {
        if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
    }
    return true;
}

pub const JobSpan = struct {
    name: []const u8,
    full: []const u8,
    body: []const u8,
};

pub fn findJob(text: []const u8, target_name: []const u8, stop_any_two_space: bool) ?JobSpan {
    var pos: usize = 0;
    while (pos < text.len) {
        const nl = std.mem.indexOfScalarPos(u8, text, pos, '\n');
        const line_end = nl orelse text.len;
        const line = text[pos..line_end];
        if (nl != null and line.len == target_name.len + 3 and
            std.mem.startsWith(u8, line, "  ") and
            std.mem.eql(u8, line[2 .. line.len - 1], target_name) and
            line[line.len - 1] == ':')
        {
            const body_start = line_end + 1;
            var scan = body_start;
            while (scan < text.len) {
                const next_nl = std.mem.indexOfScalarPos(u8, text, scan, '\n');
                const next_end = next_nl orelse text.len;
                const next_line = text[scan..next_end];
                if (stop_any_two_space) {
                    if (next_line.len >= 3 and std.mem.startsWith(u8, next_line, "  ") and !std.ascii.isWhitespace(next_line[2])) {
                        return .{ .name = target_name, .full = text[pos..scan], .body = text[body_start..scan] };
                    }
                } else {
                    if (next_nl != null and isJobHeaderLine(next_line)) {
                        return .{ .name = target_name, .full = text[pos..scan], .body = text[body_start..scan] };
                    }
                }
                scan = if (next_nl) |n| n + 1 else text.len;
            }
            return .{ .name = target_name, .full = text[pos..text.len], .body = text[body_start..text.len] };
        }
        pos = if (nl) |n| n + 1 else text.len;
    }
    return null;
}

fn collectJobs(allocator: std.mem.Allocator, text: []const u8) !std.ArrayList(JobSpan) {
    var jobs: std.ArrayList(JobSpan) = .empty;
    const marker = "\njobs:\n";
    const jobs_idx = std.mem.indexOf(u8, text, marker) orelse return jobs;
    const section = text[jobs_idx + marker.len ..];

    var pos: usize = 0;
    while (pos < section.len) {
        const nl = std.mem.indexOfScalarPos(u8, section, pos, '\n');
        const line_end = nl orelse section.len;
        const line = section[pos..line_end];
        if (nl != null and isJobHeaderLine(line)) {
            const name = line[2 .. line.len - 1];
            const body_start = line_end + 1;
            var scan = body_start;
            while (scan < section.len) {
                const next_nl = std.mem.indexOfScalarPos(u8, section, scan, '\n');
                const next_end = next_nl orelse section.len;
                const next_line = section[scan..next_end];
                if (next_nl != null and isJobHeaderLine(next_line)) break;
                scan = if (next_nl) |n| n + 1 else section.len;
            }
            try jobs.append(allocator, .{
                .name = name,
                .full = section[pos..scan],
                .body = section[body_start..scan],
            });
            pos = scan;
            continue;
        }
        pos = if (nl) |n| n + 1 else section.len;
    }
    return jobs;
}

fn lessThanSlice(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn slicesEqual(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x, y)) return false;
    }
    return true;
}

pub fn auditReleaseCoreBootstrap(failures: *Failures, ci: []const u8, release: []const u8) !void {
    const ci_names = [_][]const u8{ "release-dry-run", "release-dry-run-verify", "release-policy" };
    for ([_]struct { label: []const u8, text: []const u8, names: []const []const u8 }{
        .{ .label = "ci.yml", .text = ci, .names = &ci_names },
        .{ .label = "release.yml", .text = release, .names = &release_ghr_zig_jobs },
    }) |group| {
        for (group.names) |name| {
            const body = if (findJob(group.text, name, false)) |span| span.body else "";
            const install = std.mem.indexOf(u8, body, ghr_zig_install);
            const build = std.mem.indexOf(u8, body, "zig build build-release-tool -j2");
            var ok = false;
            if (install != null and build != null and
                build.? >= install.? + ghr_zig_install.len and
                countSubstr(body, "zig build build-release-tool -j2") == 1)
            {
                if (std.mem.eql(u8, name, "release-policy")) {
                    const policy_build = std.mem.indexOf(u8, body, "zig build build-release-workflow-policy -j2");
                    const consumer = std.mem.indexOf(u8, body, "PATH=/no-host-interpreters zig-out/bin/debz-release-workflow-policy");
                    if (policy_build != null and consumer != null and
                        policy_build.? > build.? and consumer.? > policy_build.? and
                        countSubstr(body, "zig build build-release-workflow-policy -j2") == 1)
                    {
                        ok = true;
                    }
                } else {
                    const consumer = std.mem.indexOf(u8, body, "zig-out/bin/debz-release");
                    if (consumer != null and consumer.? > build.?) {
                        ok = true;
                    }
                }
            }
            if (!ok) {
                try failures.print("{s} {s}: native release consumers must follow one verified compiler install and helper build", .{ group.label, name });
            }
            if (std.mem.eql(u8, group.label, "release.yml")) {
                const ancestry = std.mem.indexOf(u8, body, "git merge-base --is-ancestor \"$GITHUB_SHA\" refs/remotes/origin/main");
                if (ancestry == null or install == null or ancestry.? >= install.?) {
                    try failures.print("{s} {s}: main ancestry must be verified before compiling release tooling", .{ group.label, name });
                }
            }
        }
    }
}

fn isHex40(s: []const u8) bool {
    if (s.len != 40) return false;
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

pub fn auditActions(failures: *Failures, text: []const u8, workflow_name: []const u8) !void {
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, "uses:")) |idx| {
        var cur = idx + "uses:".len;
        while (cur < text.len and std.ascii.isWhitespace(text[cur])) : (cur += 1) {}
        const token_start = cur;
        while (cur < text.len and !std.ascii.isWhitespace(text[cur]) and text[cur] != '#') : (cur += 1) {}
        const token = text[token_start..cur];
        if (std.mem.indexOfScalar(u8, token, '@')) |at| {
            const action = token[0..at];
            const revision = token[at + 1 ..];
            if (action.len > 0 and revision.len > 0 and !isHex40(revision)) {
                try failures.print("{s}: {s} is not pinned to a full commit", .{ workflow_name, action });
            }
        }
        pos = cur;
    }

    var checkout_count: usize = 0;
    var all_disable_creds = true;
    var line_pos: usize = 0;
    while (line_pos < text.len) {
        const nl = std.mem.indexOfScalarPos(u8, text, line_pos, '\n');
        const line_end = nl orelse text.len;
        const line = text[line_pos..line_end];
        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "-")) {
            const after_dash = std.mem.trimStart(u8, trimmed[1..], " \t");
            if (trimmed.len > 1 and (trimmed[1] == ' ' or trimmed[1] == '\t') and
                std.mem.startsWith(u8, after_dash, "uses:"))
            {
                const after_uses = std.mem.trimStart(u8, after_dash["uses:".len..], " \t");
                if (std.mem.startsWith(u8, after_uses, "actions/checkout@")) {
                    checkout_count += 1;
                    const body_start = if (nl) |n| n + 1 else text.len;
                    var scan = body_start;
                    while (scan < text.len) {
                        const next_nl = std.mem.indexOfScalarPos(u8, text, scan, '\n');
                        const next_end = next_nl orelse text.len;
                        const next_line = text[scan..next_end];
                        if (!std.mem.startsWith(u8, next_line, "        ")) break;
                        scan = if (next_nl) |n| n + 1 else text.len;
                    }
                    const block = text[body_start..scan];
                    if (std.mem.indexOf(u8, block, "persist-credentials: false") == null) {
                        all_disable_creds = false;
                    }
                }
            }
        }
        line_pos = if (nl) |n| n + 1 else text.len;
    }
    if (checkout_count == 0 or !all_disable_creds) {
        try failures.print("{s}: every checkout must disable persisted credentials", .{workflow_name});
    }
}

fn checkJobInventory(
    allocator: std.mem.Allocator,
    text: []const u8,
    expected_jobs: []const []const u8,
) !bool {
    var jobs = try collectJobs(allocator, text);
    defer jobs.deinit(allocator);

    var unique_names = std.StringHashMap(void).init(allocator);
    defer unique_names.deinit();
    var installed: std.ArrayList([]const u8) = .empty;
    defer installed.deinit(allocator);

    for (jobs.items) |job| {
        if ((try unique_names.getOrPut(job.name)).found_existing) return false;
        const n = countSubstr(job.body, ghr_zig_install);
        for (0..n) |_| {
            try installed.append(allocator, job.name);
        }
    }
    const expected_sorted = try allocator.dupe([]const u8, expected_jobs);
    defer allocator.free(expected_sorted);
    std.mem.sort([]const u8, expected_sorted, {}, lessThanSlice);
    std.mem.sort([]const u8, installed.items, {}, lessThanSlice);
    return slicesEqual(installed.items, expected_sorted);
}

pub fn auditZigInstallation(failures: *Failures, ci: []const u8, release: []const u8) !void {
    for ([_]struct { label: []const u8, text: []const u8, expected_count: usize }{
        .{ .label = "ci.yml", .text = ci, .expected_count = ci_ghr_zig_jobs.len },
        .{ .label = "release.yml", .text = release, .expected_count = release_ghr_zig_jobs.len },
    }) |item| {
        if (std.mem.indexOf(u8, item.text, "mlugg/setup-zig") != null or
            std.mem.indexOf(u8, item.text, "use-cache:") != null)
        {
            try failures.print("{s}: obsolete setup-zig installation or cache input remains", .{item.label});
        }
        const count = countSubstr(item.text, ghr_zig_install);
        if (count != item.expected_count) {
            try failures.print("{s}: expected {d} exact verified ghr Zig install blocks, found {d}", .{ item.label, item.expected_count, count });
        }
        if (countSubstr(item.text, "uses: cataggar/ghr/actions/install@") != item.expected_count) {
            try failures.print("{s}: unverified or duplicate ghr Zig installer use", .{item.label});
        }
    }
    if (!try checkJobInventory(failures.allocator, ci, &ci_ghr_zig_jobs)) {
        try failures.append("ci.yml: exact verified ghr Zig installs must match the reviewed CI job inventory");
    }
    if (!try checkJobInventory(failures.allocator, release, &release_ghr_zig_jobs)) {
        try failures.append("release.yml: exact verified ghr Zig installs must match the reviewed release job inventory");
    }
}

pub fn auditCiConcurrency(failures: *Failures, ci: []const u8) !void {
    if (countSubstr(ci, ci_concurrency) != 1) {
        try failures.append("ci.yml: workflow concurrency must exactly isolate push, pull_request, schedule, and workflow_dispatch runs");
    }
    const on_idx = if (std.mem.startsWith(u8, ci, "on:\n"))
        @as(?usize, 0)
    else if (std.mem.indexOf(u8, ci, "\non:\n")) |idx|
        idx + 1
    else
        null;
    const expected_block = "\n\n" ++ ci_concurrency ++ "\npermissions:\n";
    const block_idx = std.mem.indexOf(u8, ci, expected_block);
    if (on_idx == null or block_idx == null or block_idx.? < on_idx.?) {
        try failures.append("ci.yml: workflow concurrency must be a top-level policy before permissions");
    }
}

fn isWordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn isWordOrDash(c: u8) bool {
    return isWordChar(c) or c == '-';
}

fn hasRetiredPythonGhrBootstrap(text: []const u8) bool {
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, "ghr-bin")) |idx| {
        const before_ok = (idx == 0 or !isWordOrDash(text[idx - 1]));
        const end = idx + "ghr-bin".len;
        const after_ok = (end == text.len or !isWordOrDash(text[end]));
        if (before_ok and after_ok) return true;
        pos = idx + 1;
    }
    for ([_][]const u8{ "python3-pip", "python3-venv" }) |pkg| {
        var p: usize = 0;
        while (std.mem.indexOfPos(u8, text, p, pkg)) |idx| {
            const before_ok = (idx == 0 or !isWordChar(text[idx - 1]));
            const end = idx + pkg.len;
            const after_ok = (end == text.len or !isWordChar(text[end]));
            if (before_ok and after_ok) return true;
            p = idx + 1;
        }
    }
    for ([_][]const u8{ "python3", "python" }) |py| {
        var p: usize = 0;
        while (std.mem.indexOfPos(u8, text, p, py)) |idx| {
            const before_ok = (idx == 0 or !isWordChar(text[idx - 1]));
            var cur = idx + py.len;
            if (before_ok and cur < text.len and std.ascii.isWhitespace(text[cur])) {
                while (cur < text.len and std.ascii.isWhitespace(text[cur])) : (cur += 1) {}
                if (std.mem.startsWith(u8, text[cur..], "-m") and cur + 2 < text.len and std.ascii.isWhitespace(text[cur + 2])) {
                    cur += 2;
                    while (cur < text.len and std.ascii.isWhitespace(text[cur])) : (cur += 1) {}
                    for ([_][]const u8{ "pip", "venv" }) |mod| {
                        if (std.mem.startsWith(u8, text[cur..], mod)) {
                            const mod_end = cur + mod.len;
                            if (mod_end == text.len or !isWordChar(text[mod_end])) return true;
                        }
                    }
                }
            }
            p = idx + 1;
        }
    }
    return false;
}

fn findStandaloneGhrSetupStep(body: []const u8) ?[]const u8 {
    const header = "      - name: Install verified standalone ghr\n";
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, body, pos, header)) |idx| {
        if (idx == 0 or body[idx - 1] == '\n') {
            const after = idx + header.len;
            if (std.mem.indexOfPos(u8, body, after, "\n      - name:")) |next_step| {
                return body[idx .. next_step + 1];
            }
            return body[idx..body.len];
        }
        pos = idx + 1;
    }
    return null;
}

pub fn auditGhrSmoke(failures: *Failures, ci: []const u8, release: []const u8) !void {
    const required_tokens = [_][]const u8{
        "GHR_PATH: ${{ steps.ghr.outputs.ghr-path }}",
        "GHR_VERSION: ${{ steps.ghr.outputs.ghr-version }}",
        "GHR_TOOL_DIR: ${{ runner.temp }}/debz-release-ghr-tools",
        "GHR_BIN_DIR: ${{ runner.temp }}/debz-release-ghr-bin",
        "GHR_CACHE_DIR: ${{ runner.temp }}/debz-release-ghr-cache",
        "test -x \"$GHR_PATH\"",
        "test \"$GHR_VERSION\" = v0.8.1",
        "test \"$(PATH=/no-host-interpreters \"$GHR_PATH\" version)\" = 0.8.1",
        "PATH=/no-host-interpreters \"$GHR_PATH\" install \"cataggar/debz@v$VERSION\"",
        "bin_dir=$(PATH=/no-host-interpreters \"$GHR_PATH\" path bin)",
        "test \"$bin_dir\" = \"$GHR_BIN_DIR\"",
        "test -x \"$bin_dir/debz\"",
        "test \"$(PATH=/no-host-interpreters \"$bin_dir/debz\" version)\" = \"$VERSION\"",
        "PATH=/no-host-interpreters \"$bin_dir/debz\" --help",
        "PATH=/no-host-interpreters \"$bin_dir/debz\" list-installed",
        "jq --exit-status '.exit_status == 0'",
    };
    for ([_]struct { label: []const u8, text: []const u8, job_name: []const u8 }{
        .{ .label = "ci.yml", .text = ci, .job_name = "release-dry-run" },
        .{ .label = "release.yml", .text = release, .job_name = "smoke" },
    }) |item| {
        const body = if (findJob(item.text, item.job_name, true)) |span| span.body else "";
        const setup = findStandaloneGhrSetupStep(body);
        const expected_trimmed = std.mem.trimEnd(u8, ghr_standalone_setup, " \t\r\n");
        if (countSubstr(item.text, ghr_standalone_setup) != 1 or
            countSubstr(body, ghr_standalone_setup) != 1 or
            countSubstr(item.text, "uses: cataggar/ghr/actions/setup@") != 1 or
            setup == null or
            !std.mem.eql(u8, std.mem.trimEnd(u8, setup.?, " \t\r\n"), expected_trimmed))
        {
            try failures.print("{s}: exact verified standalone ghr setup must remain in {s}", .{ item.label, item.job_name });
        }
        for (required_tokens) |token| {
            if (std.mem.indexOf(u8, body, token) == null) {
                try failures.print("{s}: standalone ghr release smoke lost {s}", .{ item.label, token });
            }
        }
        if (hasRetiredPythonGhrBootstrap(item.text)) {
            try failures.print("{s}: retired Python ghr bootstrap was restored", .{item.label});
        }
    }
}

fn isExactSemver(version: []const u8) bool {
    const dash = std.mem.indexOfScalar(u8, version, '-');
    const core = version[0 .. dash orelse version.len];
    var parts = std.mem.splitScalar(u8, core, '.');
    for (0..3) |_| {
        const part = parts.next() orelse return false;
        if (part.len == 0) return false;
        for (part) |c| if (!std.ascii.isDigit(c)) return false;
    }
    if (parts.next() != null) return false;
    if (dash) |d| {
        const suffix = version[d + 1 ..];
        if (suffix.len == 0) return false;
        for (suffix) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-') return false;
        }
    }
    return true;
}

fn jsonObjectEquals(a: ?std.json.Value, b: ?std.json.Value) bool {
    if (a == null or b == null) return false;
    if (a.? != .object or b.? != .object) return false;
    const obj_a = a.?.object;
    const obj_b = b.?.object;
    if (obj_a.count() != obj_b.count()) return false;
    var it = obj_a.iterator();
    while (it.next()) |entry| {
        const val_b = obj_b.get(entry.key_ptr.*) orelse return false;
        if (entry.value_ptr.* != .string or val_b != .string) return false;
        if (!std.mem.eql(u8, entry.value_ptr.*.string, val_b.string)) return false;
    }
    return true;
}

fn readNonEmptyRegularFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    relative: []const u8,
) ?[]u8 {
    const stat = root_dir.statFile(io, relative, .{}) catch return null;
    if (stat.kind != .file or stat.size == 0) return null;
    return root_dir.readFileAlloc(io, relative, allocator, .limited(maximum_file_bytes)) catch null;
}

fn checkRequiredFiles(
    io: std.Io,
    root_dir: std.Io.Dir,
    failures: *Failures,
    label: []const u8,
    files: []const []const u8,
) !void {
    for (files) |relative| {
        const stat = root_dir.statFile(io, relative, .{}) catch {
            try failures.print("{s} action file is missing or empty: {s}", .{ label, relative });
            continue;
        };
        if (stat.kind != .file or stat.size == 0) {
            try failures.print("{s} action file is missing or empty: {s}", .{ label, relative });
        }
    }
}

fn auditActionPackageAndLock(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    failures: *Failures,
    label: []const u8,
    package_rel: []const u8,
    lock_rel: []const u8,
    check_download_deps: bool,
) !void {
    const pkg_bytes = readNonEmptyRegularFile(allocator, io, root_dir, package_rel) orelse return;
    const lock_bytes = readNonEmptyRegularFile(allocator, io, root_dir, lock_rel) orelse return;

    const pkg_parsed = try std.json.parseFromSlice(std.json.Value, allocator, pkg_bytes, .{});
    defer pkg_parsed.deinit();
    const lock_parsed = try std.json.parseFromSlice(std.json.Value, allocator, lock_bytes, .{});
    defer lock_parsed.deinit();

    if (pkg_parsed.value != .object or lock_parsed.value != .object) return;
    const pkg_obj = pkg_parsed.value.object;
    const lock_obj = lock_parsed.value.object;

    if (check_download_deps) {
        var deps_ok = false;
        if (pkg_obj.get("dependencies")) |deps_val| {
            if (deps_val == .object and deps_val.object.count() == 2) {
                const core = deps_val.object.get("@actions/core");
                const blob = deps_val.object.get("@azure/storage-blob");
                if (core != null and core.? == .string and std.mem.eql(u8, core.?.string, "3.0.1") and
                    blob != null and blob.? == .string and std.mem.eql(u8, blob.?.string, "12.31.0"))
                {
                    deps_ok = true;
                }
            }
        }
        if (!deps_ok) {
            try failures.append("download action runtime dependencies differ from policy");
        }
    }

    for ([_][]const u8{ "dependencies", "devDependencies" }) |group| {
        const deps_val = pkg_obj.get(group) orelse {
            try failures.print("{s} action {s} are missing", .{ label, group });
            continue;
        };
        if (deps_val != .object or deps_val.object.count() == 0) {
            try failures.print("{s} action {s} are missing", .{ label, group });
            continue;
        }
        var it = deps_val.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* != .string or !isExactSemver(entry.value_ptr.*.string)) {
                try failures.print("{s} action dependency {s} is not exactly pinned: {any}", .{ label, entry.key_ptr.*, entry.value_ptr.* });
            }
        }
    }

    const lf_ver = lock_obj.get("lockfileVersion");
    if (lf_ver == null or lf_ver.? != .integer or lf_ver.?.integer != 3) {
        try failures.print("{s} action package-lock.json must use lockfileVersion 3", .{label});
    }

    const packages_val = lock_obj.get("packages");
    const root_pkg = if (packages_val != null and packages_val.? == .object) packages_val.?.object.get("") else null;
    if (root_pkg == null or root_pkg.? != .object) {
        try failures.print("{s} action lockfile has no root package", .{label});
    } else {
        for ([_][]const u8{ "dependencies", "devDependencies" }) |group| {
            if (!jsonObjectEquals(root_pkg.?.object.get(group), pkg_obj.get(group))) {
                try failures.print("{s} action lockfile {s} differ from package.json", .{ label, group });
            }
        }
    }
}

fn checkNodeModulesUntracked(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    root_path: []const u8,
    failures: *Failures,
    label: []const u8,
    node_modules_rel: []const u8,
) !void {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "/usr/bin/git", "ls-files", node_modules_rel },
        .cwd = .{ .path = root_path },
        .environ_map = environ_map,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    if (result.term != .exited or result.term.exited != 0 or
        std.mem.trim(u8, result.stdout, " \t\r\n").len != 0)
    {
        try failures.print("{s} action node_modules must not be tracked", .{label});
    }
}

pub fn auditSetupAction(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    root_dir: std.Io.Dir,
    root_path: []const u8,
    failures: *Failures,
    ci: []const u8,
    release: []const u8,
) !void {
    const required_files = [_][]const u8{
        "actions/setup/action.yml",
        "actions/setup/package.json",
        "actions/setup/package-lock.json",
        "actions/setup/dist/main/index.js",
        "actions/setup/dist/main/package.json",
        "actions/setup/dist/main/licenses.txt",
        "actions/setup/dist/post/index.js",
        "actions/setup/dist/post/package.json",
        "actions/setup/dist/post/licenses.txt",
    };
    try checkRequiredFiles(io, root_dir, failures, "setup", &required_files);

    if (readNonEmptyRegularFile(allocator, io, root_dir, "actions/setup/action.yml")) |action| {
        for ([_][]const u8{
            "using: node24",
            "main: dist/main/index.js",
            "post: dist/post/index.js",
            "post-if: success()",
            "debz-version:",
            "sha256:",
            "token:",
            "cache:",
            "debz-path:",
            "target:",
            "cache-hit:",
        }) |token| {
            if (std.mem.indexOf(u8, action, token) == null) {
                try failures.print("setup action metadata is missing policy token: {s}", .{token});
            }
        }
    }

    for ([_]struct { relative: []const u8, tokens: []const []const u8 }{
        .{
            .relative = "src/action.ts",
            .tokens = &.{
                "delete process.env.INPUT_TOKEN",
                "verifyInstallation(",
                "io.setOutput('debz-path'",
            },
        },
        .{
            .relative = "src/cache.ts",
            .tokens = &.{
                "restore_keys: []",
                "'x-ms-blob-type': 'BlockBlob'",
                "exact cache archive size mismatch",
            },
        },
        .{
            .relative = "src/post.ts",
            .tokens = &.{
                "delete process.env.INPUT_TOKEN",
                "verifyCachedInstallation(",
                "sha256Bytes(archive)",
            },
        },
    }) |source_spec| {
        const full_rel = try std.fmt.allocPrint(allocator, "actions/setup/{s}", .{source_spec.relative});
        const source = readNonEmptyRegularFile(allocator, io, root_dir, full_rel) orelse {
            try failures.print("setup action source is missing: actions/setup/{s}", .{source_spec.relative});
            continue;
        };
        for (source_spec.tokens) |token| {
            if (std.mem.indexOf(u8, source, token) == null) {
                try failures.print("setup action {s} is missing policy token: {s}", .{ source_spec.relative, token });
            }
        }
    }

    try auditActionPackageAndLock(
        allocator,
        io,
        root_dir,
        failures,
        "setup",
        "actions/setup/package.json",
        "actions/setup/package-lock.json",
        false,
    );
    try checkNodeModulesUntracked(allocator, io, environ_map, root_path, failures, "setup", "actions/setup/node_modules");

    for ([_][]const u8{
        "Setup action unit and bundle checks",
        "npm --prefix actions/setup ci",
        "npm --prefix actions/setup audit --audit-level=high",
        "npm --prefix actions/setup test",
        "npm --prefix actions/setup run bundle",
        "git diff --exit-code -- actions/setup/dist",
        "Setup action native (${{ matrix.target }})",
        "Setup action in bare Ubuntu container",
        "uses: ./actions/setup",
        "debz-version: v0.2.0",
        "sha256: ${{ matrix.digest }}",
    }) |token| {
        if (std.mem.indexOf(u8, ci, token) == null) {
            try failures.print("CI setup action coverage is missing policy token: {s}", .{token});
        }
    }
    for ([_][]const u8{
        "Install exact release with the first-party setup action",
        "uses: ./actions/setup",
        "debz-version: ${{ github.ref_name }}",
        "test \"$(\"$DEBZ_PATH\" version)\" = \"$VERSION\"",
        "\"$DEBZ_PATH\" --help",
    }) |token| {
        if (std.mem.indexOf(u8, release, token) == null) {
            try failures.print("release setup smoke is missing policy token: {s}", .{token});
        }
    }
    const smoke_span = findJob(release, "smoke", true);
    if (smoke_span == null or !containsLineBlock(smoke_span.?.body,
        \\    permissions:
        \\      contents: read
        \\      attestations: read
    )) {
        try failures.append("release setup smoke must have contents and attestations read permissions");
    }
    if (!containsLineBlock(ci,
        \\permissions:
        \\  contents: read
        \\  attestations: read
    )) {
        try failures.append("CI setup jobs require top-level attestations: read permission");
    }
}

pub fn auditDownloadAction(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    root_dir: std.Io.Dir,
    root_path: []const u8,
    failures: *Failures,
    ci: []const u8,
    release: []const u8,
) !void {
    const required_files = [_][]const u8{
        "actions/download/action.yml",
        "actions/download/package.json",
        "actions/download/package-lock.json",
        "actions/download/THIRD_PARTY_NOTICES.md",
        "actions/download/dist/index.js",
        "actions/download/dist/package.json",
        "actions/download/dist/licenses.txt",
        "src/package_cache_archive.zig",
    };
    try checkRequiredFiles(io, root_dir, failures, "download", &required_files);

    if (readNonEmptyRegularFile(allocator, io, root_dir, "actions/download/action.yml")) |manifest| {
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, manifest, pos, "uses:")) |idx| {
            var cur = idx + "uses:".len;
            while (cur < manifest.len and std.ascii.isWhitespace(manifest[cur])) : (cur += 1) {}
            const token_start = cur;
            while (cur < manifest.len and !std.ascii.isWhitespace(manifest[cur]) and manifest[cur] != '#') : (cur += 1) {}
            const token = manifest[token_start..cur];
            if (std.mem.indexOfScalar(u8, token, '@')) |at| {
                const action = token[0..at];
                const revision = token[at + 1 ..];
                if (action.len > 0 and revision.len > 0 and !isHex40(revision)) {
                    try failures.print("download action dependency {s} is not commit-pinned", .{action});
                }
            }
            pos = cur;
        }
        for ([_][]const u8{
            "using: node24",
            "main: dist/index.js",
            "cache-hit:",
            "cache-matched-key:",
            "cache-path:",
            "cache-root:",
            "lock-digest:",
            "downloaded-count:",
            "reused-count:",
        }) |token| {
            if (std.mem.indexOf(u8, manifest, token) == null) {
                try failures.print("download action metadata is missing policy token: {s}", .{token});
            }
        }
    }

    try auditActionPackageAndLock(
        allocator,
        io,
        root_dir,
        failures,
        "download",
        "actions/download/package.json",
        "actions/download/package-lock.json",
        true,
    );
    try checkNodeModulesUntracked(allocator, io, environ_map, root_path, failures, "download", "actions/download/node_modules");

    for ([_][]const u8{
        "Download action unit and bundle checks",
        "npm --prefix actions/download ci",
        "npm --prefix actions/download audit --audit-level=high",
        "npm --prefix actions/download test",
        "npm --prefix actions/download run bundle",
        "git diff --exit-code -- actions/download/dist",
        "Download action cache semantics",
        "uses: ./actions/download",
        "cache-matched-key",
        "downloaded-count",
        "reused-count",
        "Reject corrupt package object",
        "Reject package-only offline restore",
        "test \"$OUTCOME\" = failure",
    }) |token| {
        if (std.mem.indexOf(u8, ci, token) == null) {
            try failures.print("CI download action coverage is missing policy token: {s}", .{token});
        }
    }
    for ([_][]const u8{
        "Prepare release smoke package closure",
        "uses: ./actions/download",
        "cache: 'false'",
        "downloaded-count",
        "reused-count",
    }) |token| {
        if (std.mem.indexOf(u8, release, token) == null) {
            try failures.print("release download smoke is missing policy token: {s}", .{token});
        }
    }
}

pub fn auditInstallAction(
    io: std.Io,
    root_dir: std.Io.Dir,
    failures: *Failures,
    ci: []const u8,
    release: []const u8,
) !void {
    const required_files = [_][]const u8{
        "actions/install/action.yml",
        "actions/install/package.json",
        "actions/install/package-lock.json",
        "actions/install/THIRD_PARTY_NOTICES.md",
        "actions/install/dist/index.js",
        "actions/install/dist/package.json",
        "actions/install/dist/licenses.txt",
        "schema/transaction-result-summary-v1.json",
    };
    try checkRequiredFiles(io, root_dir, failures, "install", &required_files);

    for ([_][]const u8{
        "Install action unit and bundle checks",
        "npm --prefix actions/install ci",
        "npm --prefix actions/install audit --audit-level=high",
        "npm --prefix actions/install test",
        "npm --prefix actions/install run bundle",
        "git diff --exit-code -- actions/install/dist",
        "Install action native transaction (${{ matrix.architecture }})",
        "Exercise cold, warm, offline, and same-root installs",
    }) |token| {
        if (std.mem.indexOf(u8, ci, token) == null) {
            try failures.print("CI install action coverage is missing policy token: {s}", .{token});
        }
    }
    for ([_][]const u8{
        "Install exact release into a cold alternate root",
        "Install exact cache hit into a different fresh root",
        "uses: ./actions/install",
        "package-cache-hit",
        "installed-count",
        "test \"$WARM_CACHE_HIT\" = true",
        "test \"$WARM_DOWNLOADED\" -eq 0",
    }) |token| {
        if (std.mem.indexOf(u8, release, token) == null) {
            try failures.print("release install smoke is missing policy token: {s}", .{token});
        }
    }
}

pub fn auditReleaseWorkflowCore(
    failures: *Failures,
    ci: []const u8,
    release: []const u8,
) !void {
    if (!containsLineBlock(release,
        \\on:
        \\  push:
        \\    tags:
        \\      - 'v*'
    )) {
        try failures.append("trigger must be only v* tag pushes");
    }
    if (containsLineBlock(release, "  pull_request:") or
        containsLineBlock(release, "  workflow_dispatch:") or
        containsLineBlock(release, "  schedule:"))
    {
        try failures.append("release workflow has a non-tag trigger");
    }
    if (!containsLineBlock(release,
        \\permissions:
        \\  contents: read
        \\  attestations: read
    )) {
        try failures.append("top-level permissions must be contents and attestations read");
    }
    const release_job = findJob(release, "release", true);
    if (release_job == null or std.mem.indexOf(u8, release_job.?.body,
        \\    permissions:
        \\      contents: write
        \\      id-token: write
        \\      attestations: write
    ) == null) {
        try failures.append("release job must hold publication permissions");
    }

    for ([_][]const u8{
        "ubuntu-24.04",
        "ubuntu-24.04-arm",
        "fetch-depth: 0",
        "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main",
        "git merge-base --is-ancestor \"$GITHUB_SHA\" refs/remotes/origin/main",
        "zig-out/bin/debz-release version \"$GITHUB_REF_NAME\" --zon build.zig.zon",
        "--expect \"binary=$(release-root/bin/debz version)\"",
        "-Doptimize=ReleaseSafe",
        "-Dversion=\"$VERSION\"",
        "zig-out/bin/debz-release binary",
        "zig-out/bin/debz-release audit",
        "zig-out/bin/debz-release verify",
        "--assets release-assets --smoke",
        "subject-path: release-assets/*.tar.gz",
        "subject-path: release-assets/*.tar.xz",
        "release-assets-${{ matrix.platform }}",
        "merge-multiple: true",
        "ghr install cataggar/debz@v$VERSION",
        "'```sh'",
        "--generate-notes",
        "--fail-on-no-commits",
        "--verify-tag",
        "release-assets/debz-$VERSION-linux-x64.tar.gz",
        "release-assets/debz-$VERSION-linux-x64.tar.xz",
        "release-assets/debz-$VERSION-linux-arm64.tar.gz",
        "release-assets/debz-$VERSION-linux-arm64.tar.xz",
    }) |token| {
        if (std.mem.indexOf(u8, release, token) == null) {
            try failures.print("release workflow is missing policy token: {s}", .{token});
        }
    }
    for ([_][]const u8{
        "zig-out/bin/debz-release binary",
        "zig-out/bin/debz-release audit",
        "zig-out/bin/debz-release verify",
        "Required release dry-run exact verification",
    }) |token| {
        if (std.mem.indexOf(u8, ci, token) == null) {
            try failures.print("CI release dry-run is missing policy token: {s}", .{token});
        }
    }

    for ([_]struct { label: []const u8, span: ?JobSpan }{
        .{ .label = "release.yml binaries", .span = findJob(release, "binaries", true) },
        .{ .label = "ci.yml release-dry-run", .span = findJob(ci, "release-dry-run", true) },
    }) |item| {
        if (item.span == null) {
            try failures.print("{s}: release job is missing", .{item.label});
            continue;
        }
        const text = item.span.?.body;
        for ([_][]const u8{ "x86_64-linux-musl", "aarch64-linux-musl" }) |target| {
            const needle = try std.fmt.allocPrint(failures.allocator, "target: {s}", .{target});
            if (countSubstr(text, needle) != 1) {
                try failures.print("{s}: release matrix must contain exactly one {s} target", .{ item.label, target });
            }
        }
        for ([_][]const u8{ "x86_64-linux-gnu", "aarch64-linux-gnu" }) |target| {
            const needle = try std.fmt.allocPrint(failures.allocator, "target: {s}", .{target});
            if (std.mem.indexOf(u8, text, needle) != null) {
                try failures.print("{s}: release matrix retains dynamic GNU target {s}", .{ item.label, target });
            }
        }
    }

    if (countSubstr(release, "actions/attest-build-provenance@") != 2) {
        try failures.append("release workflow must separately attest gzip and xz archives");
    }
    if (std.mem.indexOf(u8, release, "${{ secrets.") != null) {
        try failures.append("release workflow must not reference repository secrets");
    }
    if (std.mem.indexOf(u8, release, "timeout-minutes:") == null or
        std.mem.indexOf(u8, release, "concurrency:") == null)
    {
        try failures.append("release workflow requires timeouts and concurrency");
    }
    for ([_][]const u8{
        ".sha256",
        ".spdx",
        "-release-manifest.json",
        "-source.tar",
        "tools/release.py source",
        "tools/release.py manifest",
        "release-assets-source",
        "tools/release-workflow-policy.py",
        "tools/test_release_workflow_policy.py",
    }) |forbidden| {
        if (std.mem.indexOf(u8, release, forbidden) != null or
            std.mem.indexOf(u8, ci, forbidden) != null)
        {
            try failures.print("forbidden release asset or command remains: {s}", .{forbidden});
        }
    }
    for ([_][]const u8{
        "validate-tag",
        "package-binary",
        "package-source",
        "verify-assets",
        "audit-runtime",
    }) |obsolete| {
        if (std.mem.indexOf(u8, release, obsolete) != null or
            std.mem.indexOf(u8, ci, obsolete) != null)
        {
            try failures.print("obsolete release tool command remains: {s}", .{obsolete});
        }
    }
}

pub fn auditRepository(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    root_path: []const u8,
    release_tool_path: []const u8,
    failures: *Failures,
) !void {
    var root_dir = try std.Io.Dir.cwd().openDir(io, root_path, .{});
    defer root_dir.close(io);

    const release = try root_dir.readFileAlloc(io, ".github/workflows/release.yml", allocator, .limited(maximum_file_bytes));
    const ci = try root_dir.readFileAlloc(io, ".github/workflows/ci.yml", allocator, .limited(maximum_file_bytes));

    try auditReleaseWorkflowCore(failures, ci, release);
    try auditActions(failures, release, "release.yml");
    try auditActions(failures, ci, "ci.yml");
    try auditCiConcurrency(failures, ci);
    try auditZigInstallation(failures, ci, release);
    try auditReleaseCoreBootstrap(failures, ci, release);
    try auditGhrSmoke(failures, ci, release);
    try auditSetupAction(allocator, io, environ_map, root_dir, root_path, failures, ci, release);
    try auditDownloadAction(allocator, io, environ_map, root_dir, root_path, failures, ci, release);
    try auditInstallAction(io, root_dir, failures, ci, release);

    for ([_][]const u8{
        "tools/release-assets.json",
        "tools/release-dry-run.sh",
        "tools/release-workflow-policy.py",
        "tools/test_release_workflow_policy.py",
    }) |obsolete_file| {
        if (root_dir.statFile(io, obsolete_file, .{})) |_| {
            try failures.append("obsolete static release assets or dry-run implementation remains");
            break;
        } else |_| {}
    }

    var cleaned = try environ_map.clone(allocator);
    defer cleaned.deinit();
    try cleaned.put("PATH", "/no-host-interpreters");

    const run_res = std.process.run(allocator, io, .{
        .argv = &.{ release_tool_path, "dry-run", "--tag", "v0.1.0" },
        .cwd = .{ .path = root_path },
        .environ_map = &cleaned,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    }) catch {
        try failures.append("release plan must declare exactly four binary archives");
        return;
    };
    if (run_res.term != .exited or run_res.term.exited != 0) {
        try failures.append("release plan must declare exactly four binary archives");
        return;
    }

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, run_res.stdout, .{}) catch {
        try failures.append("release plan must declare exactly four binary archives");
        return;
    };
    defer parsed.deinit();

    const expected_assets = [_][]const u8{
        "debz-0.1.0-linux-x64.tar.gz",
        "debz-0.1.0-linux-x64.tar.xz",
        "debz-0.1.0-linux-arm64.tar.gz",
        "debz-0.1.0-linux-arm64.tar.xz",
    };
    var assets_ok = false;
    if (parsed.value == .object) {
        if (parsed.value.object.get("assets")) |assets_val| {
            if (assets_val == .array and assets_val.array.items.len == expected_assets.len) {
                assets_ok = true;
                for (expected_assets) |expected| {
                    var found = false;
                    for (assets_val.array.items) |item| {
                        if (item == .string and std.mem.eql(u8, item.string, expected)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        assets_ok = false;
                        break;
                    }
                }
            }
        }
    }
    if (!assets_ok) {
        try failures.append("release plan must declare exactly four binary archives");
    }
}

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    var root_path: []const u8 = ".";
    var release_tool_override: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try std.Io.File.stdout().writeStreamingAll(
                init.io,
                "usage: debz-release-workflow-policy [--root DIR] [--release-tool PATH]\n",
            );
            return 0;
        } else if (std.mem.eql(u8, arg, "--root")) {
            if (i + 1 >= args.len) {
                try std.Io.File.stderr().writeStreamingAll(init.io, "release policy: --root requires a value\n");
                return 2;
            }
            root_path = args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--release-tool")) {
            if (i + 1 >= args.len) {
                try std.Io.File.stderr().writeStreamingAll(init.io, "release policy: --release-tool requires a value\n");
                return 2;
            }
            release_tool_override = args[i + 1];
            i += 2;
        } else {
            try std.Io.File.stderr().writeStreamingAll(
                init.io,
                try std.fmt.allocPrint(allocator, "release policy: unknown argument: {s}\n", .{arg}),
            );
            return 2;
        }
    }

    const release_tool = release_tool_override orelse
        init.environ_map.get("DEBZ_RELEASE") orelse
        try std.fmt.allocPrint(allocator, "{s}/zig-out/bin/debz-release", .{std.mem.trimEnd(u8, root_path, "/")});

    var failures = Failures.init(allocator);
    defer failures.deinit();

    try auditRepository(allocator, init.io, init.environ_map, root_path, release_tool, &failures);
    if (failures.items().len != 0) {
        for (failures.items()) |failure| {
            try std.Io.File.stderr().writeStreamingAll(
                init.io,
                try std.fmt.allocPrint(allocator, "release policy: {s}\n", .{failure}),
            );
        }
        return 1;
    }
    try std.Io.File.stdout().writeStreamingAll(init.io, "release workflow policy audit passed\n");
    return 0;
}

const TestFixture = struct {
    arena: std.heap.ArenaAllocator,
    ci: []const u8,
    release: []const u8,

    fn init() !TestFixture {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        errdefer arena.deinit();
        const alloc = arena.allocator();
        const ci = try std.Io.Dir.cwd().readFileAlloc(testing.io, ".github/workflows/ci.yml", alloc, .limited(maximum_file_bytes));
        const release = try std.Io.Dir.cwd().readFileAlloc(testing.io, ".github/workflows/release.yml", alloc, .limited(maximum_file_bytes));
        return .{ .arena = arena, .ci = ci, .release = release };
    }

    fn deinit(self: *TestFixture) void {
        self.arena.deinit();
    }

    fn replaceFirst(self: *TestFixture, haystack: []const u8, needle: []const u8, replacement: []const u8) ![]const u8 {
        const alloc = self.arena.allocator();
        const idx = std.mem.indexOf(u8, haystack, needle) orelse return error.NeedleNotFound;
        return std.mem.concat(alloc, u8, &.{ haystack[0..idx], replacement, haystack[idx + needle.len ..] });
    }

    fn jobFull(self: *TestFixture, name: []const u8) ![]const u8 {
        const marker = "\njobs:\n";
        const idx = std.mem.indexOf(u8, self.ci, marker) orelse return error.MissingJobsSection;
        const span = findJob(self.ci[idx + marker.len ..], name, false) orelse return error.JobNotFound;
        return span.full;
    }

    fn hasFailureContaining(failures: *const Failures, needle: []const u8) bool {
        for (failures.items()) |msg| {
            if (std.mem.indexOf(u8, msg, needle) != null) return true;
        }
        return false;
    }
};

test "reviewed jobs have one exact verified install each" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    try testing.expectEqual(@as(usize, 23), ci_ghr_zig_jobs.len);

    var failures = Failures.init(fx.arena.allocator());
    try auditZigInstallation(&failures, fx.ci, fx.release);
    try testing.expectEqual(@as(usize, 0), failures.items().len);
}

test "balanced move between new jobs still fails" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    const repository = try fx.jobFull("native-recovery-zig-repository");
    const helper = try fx.jobFull("native-recovery-zig-helper");
    const repo_without = try fx.replaceFirst(repository, ghr_zig_install, "");
    const helper_with = try std.mem.concat(fx.arena.allocator(), u8, &.{ helper, ghr_zig_install });
    const step1 = try fx.replaceFirst(fx.ci, repository, repo_without);
    const changed = try fx.replaceFirst(step1, helper, helper_with);

    try testing.expectEqual(@as(usize, 23), countSubstr(changed, ghr_zig_install));
    var failures = Failures.init(fx.arena.allocator());
    try auditZigInstallation(&failures, changed, fx.release);
    try testing.expect(TestFixture.hasFailureContaining(&failures, "reviewed CI job inventory"));
}

test "balanced move out of diversion shard still fails" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    const diversions = try fx.jobFull("native-recovery-zig-diversions");
    const helper = try fx.jobFull("native-recovery-zig-helper");
    const div_without = try fx.replaceFirst(diversions, ghr_zig_install, "");
    const helper_with = try std.mem.concat(fx.arena.allocator(), u8, &.{ helper, ghr_zig_install });
    const step1 = try fx.replaceFirst(fx.ci, diversions, div_without);
    const changed = try fx.replaceFirst(step1, helper, helper_with);

    try testing.expectEqual(@as(usize, 23), countSubstr(changed, ghr_zig_install));
    var failures = Failures.init(fx.arena.allocator());
    try auditZigInstallation(&failures, changed, fx.release);
    try testing.expect(TestFixture.hasFailureContaining(&failures, "reviewed CI job inventory"));
}

test "balanced move between workload jobs still fails" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    const jobs = [_][]const u8{
        "build-and-test-workload",
        "build-and-test-workload-production",
        "build-and-test-workload-apt-system",
        "build-and-test-workload-native",
        "build-and-test-workload-release",
    };
    for (jobs, 0..) |source, idx| {
        const target = jobs[(idx + 1) % jobs.len];
        const moved_from = try fx.jobFull(source);
        const moved_to = try fx.jobFull(target);
        const from_without = try fx.replaceFirst(moved_from, ghr_zig_install, "");
        const to_with = try std.mem.concat(fx.arena.allocator(), u8, &.{ moved_to, ghr_zig_install });
        const step1 = try fx.replaceFirst(fx.ci, moved_from, from_without);
        const changed = try fx.replaceFirst(step1, moved_to, to_with);

        try testing.expectEqual(@as(usize, 23), countSubstr(changed, ghr_zig_install));
        var failures = Failures.init(fx.arena.allocator());
        try auditZigInstallation(&failures, changed, fx.release);
        try testing.expect(TestFixture.hasFailureContaining(&failures, "reviewed CI job inventory"));
    }
}

test "balanced move out of native oracle evidence job still fails" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    const oracle = try fx.jobFull("arm64-dpkg-oracles");
    const helper = try fx.jobFull("native-recovery-zig-helper");
    const oracle_without = try fx.replaceFirst(oracle, ghr_zig_install, "");
    const helper_with = try std.mem.concat(fx.arena.allocator(), u8, &.{ helper, ghr_zig_install });
    const step1 = try fx.replaceFirst(fx.ci, oracle, oracle_without);
    const changed = try fx.replaceFirst(step1, helper, helper_with);

    try testing.expectEqual(@as(usize, 23), countSubstr(changed, ghr_zig_install));
    var failures = Failures.init(fx.arena.allocator());
    try auditZigInstallation(&failures, changed, fx.release);
    try testing.expect(TestFixture.hasFailureContaining(&failures, "reviewed CI job inventory"));
}

test "unverified or duplicate install refuses" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    const changed = try fx.replaceFirst(fx.ci, "ghr-version: v0.8.1", "ghr-version: v0.8.0");
    var failures = Failures.init(fx.arena.allocator());
    try auditZigInstallation(&failures, changed, fx.release);
    try testing.expect(TestFixture.hasFailureContaining(&failures, "exact verified ghr Zig install blocks"));

    failures.clear();
    const extra = try std.mem.concat(fx.arena.allocator(), u8, &.{ fx.ci, "\nuses: cataggar/ghr/actions/install@deadbeef\n" });
    try auditZigInstallation(&failures, extra, fx.release);
    try testing.expect(TestFixture.hasFailureContaining(&failures, "unverified or duplicate ghr Zig installer use"));
}

test "release install remains exact and balanced move out of release fixture job still fails" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    const missing = try fx.replaceFirst(fx.release, ghr_zig_install, "");
    var failures = Failures.init(fx.arena.allocator());
    try auditZigInstallation(&failures, fx.ci, missing);
    try testing.expect(TestFixture.hasFailureContaining(&failures, "release.yml: expected 3 exact verified ghr Zig install blocks"));

    failures.clear();
    const smoke_idx = std.mem.indexOf(u8, fx.release, "\n  smoke:\n") orelse return error.MissingSmokeJob;
    const smoke_tail = fx.release[smoke_idx + "\n  smoke:\n".len ..];
    const smoke_without = try fx.replaceFirst(smoke_tail, ghr_zig_install, "");
    const step1 = try fx.replaceFirst(fx.release, smoke_tail, smoke_without);
    const moved = try fx.replaceFirst(step1, "\n  smoke:\n", ghr_zig_install ++ "\n  smoke:\n");
    try testing.expectEqual(@as(usize, 3), countSubstr(moved, ghr_zig_install));
    try auditZigInstallation(&failures, fx.ci, moved);
    try testing.expect(TestFixture.hasFailureContaining(&failures, "reviewed release job inventory"));
}

test "native release build and consumers follow verified compiler and main ancestry" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    var failures = Failures.init(fx.arena.allocator());
    try auditReleaseCoreBootstrap(&failures, fx.ci, fx.release);
    try testing.expectEqual(@as(usize, 0), failures.items().len);

    for ([_][]const u8{ "release-dry-run", "release-dry-run-verify", "release-policy" }) |job_name| {
        const body = try fx.jobFull(job_name);
        const without_build = try fx.replaceFirst(body, "          zig build build-release-tool -j2\n", "");
        const premature = try fx.replaceFirst(
            without_build,
            ghr_zig_install,
            "      - name: Premature helper build\n        run: zig build build-release-tool -j2\n" ++ ghr_zig_install,
        );
        const mutated_ci = try fx.replaceFirst(fx.ci, body, premature);
        failures.clear();
        try auditReleaseCoreBootstrap(&failures, mutated_ci, fx.release);
        try testing.expect(TestFixture.hasFailureContaining(&failures, "verified compiler install"));
    }

    for (release_ghr_zig_jobs) |job_name| {
        const span = findJob(fx.release, job_name, false) orelse return error.JobNotFound;
        const mutated_job = try fx.replaceFirst(
            span.full,
            "git merge-base --is-ancestor \"$GITHUB_SHA\" refs/remotes/origin/main",
            "true",
        );
        const mutated_release = try fx.replaceFirst(fx.release, span.full, mutated_job);
        failures.clear();
        try auditReleaseCoreBootstrap(&failures, fx.ci, mutated_release);
        try testing.expect(TestFixture.hasFailureContaining(&failures, "main ancestry"));
    }
}

test "ci concurrency remains exact" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    var failures = Failures.init(fx.arena.allocator());
    try auditCiConcurrency(&failures, fx.ci);
    try testing.expectEqual(@as(usize, 0), failures.items().len);

    const without = try fx.replaceFirst(fx.ci, ci_concurrency ++ "\n", "");
    failures.clear();
    try auditCiConcurrency(&failures, without);
    try testing.expect(TestFixture.hasFailureContaining(&failures, "workflow concurrency"));

    const weakened = try fx.replaceFirst(
        fx.ci,
        "cancel-in-progress: ${{ github.event_name == 'push' || github.event_name == 'pull_request' }}",
        "cancel-in-progress: false",
    );
    failures.clear();
    try auditCiConcurrency(&failures, weakened);
    try testing.expect(TestFixture.hasFailureContaining(&failures, "workflow concurrency"));
}

test "both native smoke consumers use the verified standalone bootstrap and refuse python restore" {
    var fx = try TestFixture.init();
    defer fx.deinit();
    var failures = Failures.init(fx.arena.allocator());
    try auditGhrSmoke(&failures, fx.ci, fx.release);
    try testing.expectEqual(@as(usize, 0), failures.items().len);

    const ghr_v_latest = try fx.replaceFirst(ghr_standalone_setup, "v0.8.1", "latest");
    const ghr_extra_sha = try std.mem.concat(fx.arena.allocator(), u8, &.{ ghr_standalone_setup, "          sha256: unreviewed\n" });

    for ([_]usize{ 0, 1 }) |workflow_index| {
        const original = if (workflow_index == 0) fx.ci else fx.release;
        const mutations = [_][]const u8{
            try fx.replaceFirst(original, ghr_standalone_setup, ""),
            try fx.replaceFirst(original, ghr_standalone_setup, ghr_v_latest),
            try fx.replaceFirst(original, ghr_standalone_setup, ghr_extra_sha),
            try fx.replaceFirst(original, "          PATH=/no-host-interpreters \"$GHR_PATH\" install \"cataggar/debz@v$VERSION\"\n", ""),
            try fx.replaceFirst(original, "          test \"$(PATH=/no-host-interpreters \"$GHR_PATH\" version)\" = 0.8.1\n", ""),
            try fx.replaceFirst(original, "          GHR_BIN_DIR: ${{ runner.temp }}/debz-release-ghr-bin\n", ""),
            try fx.replaceFirst(original, "          test \"$bin_dir\" = \"$GHR_BIN_DIR\"\n", ""),
            try std.mem.concat(fx.arena.allocator(), u8, &.{
                try fx.replaceFirst(original, ghr_standalone_setup, ""),
                "\n  unrelated-ghr:\n    steps:\n",
                ghr_standalone_setup,
            }),
            try std.mem.concat(fx.arena.allocator(), u8, &.{ original, "\n# python3 -m venv .zig-cache/ghr\n" }),
            try std.mem.concat(fx.arena.allocator(), u8, &.{ original, "\n# pip install ghr-bin==0.7.0\n" }),
        };
        for (mutations) |mutated| {
            failures.clear();
            const ci_arg = if (workflow_index == 0) mutated else fx.ci;
            const rel_arg = if (workflow_index == 1) mutated else fx.release;
            try auditGhrSmoke(&failures, ci_arg, rel_arg);
            try testing.expect(failures.items().len > 0);
        }
    }
}

test "complete release workflow policy CLI passes on repository without host interpreters" {
    const opts = @import("release_workflow_policy_options");
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("PATH", "/no-host-interpreters");
    try env.put("DEBZ_RELEASE", opts.release_executable);

    const res = try std.process.run(testing.allocator, testing.io, .{
        .argv = &.{ opts.executable, "--root", opts.repository, "--release-tool", opts.release_executable },
        .environ_map = &env,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer testing.allocator.free(res.stdout);
    defer testing.allocator.free(res.stderr);
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("debz-release-workflow-policy failed:\nstdout: {s}\nstderr: {s}\n", .{ res.stdout, res.stderr });
    }
    try testing.expect(res.term == .exited and res.term.exited == 0);
    try testing.expect(std.mem.indexOf(u8, res.stdout, "release workflow policy audit passed") != null);
}

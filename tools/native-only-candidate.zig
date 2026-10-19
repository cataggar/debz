//! Opt-in source/process inventory and Actions contract auditor for #274/#276; never a shipped-mode gate.
const std = @import("std");
const testing = std.testing;

const maximum_source_bytes = 16 * 1024 * 1024;
const inventory_path = "security/native-only-production-policy.json";
const legacy_policy_path = "security/legacy-cutover-policy.json";

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

fn lessThanString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn isWordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn isJsIdentStart(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '_' or c == '$';
}

fn isJsIdentChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '$';
}

fn isHex128Lower(text: []const u8) bool {
    if (text.len != 128) return false;
    for (text) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

pub fn isSafeRelativePath(relative: []const u8) bool {
    if (relative.len == 0 or relative[0] == '/' or relative[relative.len - 1] == '/') return false;
    var it = std.mem.splitScalar(u8, relative, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn indexOfTokenSeq(haystack: []const u8, tokens: []const []const u8) ?usize {
    if (tokens.len == 0) return 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, pos, tokens[0])) |start| {
        var cur = start + tokens[0].len;
        var matched = true;
        for (tokens[1..]) |tok| {
            while (cur < haystack.len and std.ascii.isWhitespace(haystack[cur])) : (cur += 1) {}
            if (!std.mem.startsWith(u8, haystack[cur..], tok)) {
                matched = false;
                break;
            }
            cur += tok.len;
        }
        if (matched) return start;
        pos = start + 1;
    }
    return null;
}

fn containsTokenSeq(haystack: []const u8, tokens: []const []const u8) bool {
    return indexOfTokenSeq(haystack, tokens) != null;
}

fn hasIndentedDefaultLegacyDpkg(text: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0 or !std.ascii.isWhitespace(line[0])) continue;
        const trimmed = std.mem.trim(u8, line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "default:")) continue;
        const rest = std.mem.trimStart(u8, trimmed["default:".len..], " \t");
        if (std.mem.eql(u8, rest, "legacy_dpkg")) return true;
    }
    return false;
}

const CutoverRoute = struct {
    path: []const u8,
    task: []const u8,
};

const cutover_routes = [_]CutoverRoute{
    .{ .path = "src/transaction_executor.zig", .task = "remove legacy dpkg/dpkg-deb executor (#281)" },
    .{ .path = "src/exact_lock.zig", .task = "stop creating exact-lock v1; retain decode/verify (#282)" },
    .{ .path = "src/transaction_provenance.zig", .task = "stop creating legacy result v1; retain verification (#282)" },
    .{ .path = "src/transaction_provenance_v2.zig", .task = "stop creating repository legacy result v2; retain verification (#282)" },
    .{ .path = "src/transaction_recovery.zig", .task = "remove active legacy journal v4 publication/replay; retain v1-v4 decode (#285)" },
    .{ .path = "src/transaction_engine.zig", .task = "remove legacy executor selection (#281)" },
    .{ .path = "src/production_backend.zig", .task = "remove product legacy route/default (#284)" },
    .{ .path = "src/repository_backend.zig", .task = "remove repository legacy route/default (#280)" },
    .{ .path = "src/package_family_backend.zig", .task = "remove package-family legacy route/default (#284)" },
    .{ .path = "src/package_cache_workflow.zig", .task = "stop creating legacy cache v1 contracts; retain historical verification (#282)" },
    .{ .path = "src/transaction_result_summary.zig", .task = "stop creating legacy result summary v1; retain historical verification (#282)" },
    .{ .path = "src/system_profile.zig", .task = "stop executing profile v1/default; retain exact-byte decoder (#282)" },
    .{ .path = "src/main.zig", .task = "remove CLI legacy selection/default and rehearsal-only runtime mode (#283)" },
    .{ .path = "src/repository_cli.zig", .task = "remove repository CLI legacy default (#280/#283)" },
    .{ .path = "src/apt_system_orchestrator.zig", .task = "remove apt/root legacy profile execution (#280)" },
    .{ .path = "src/target_apt_config.zig", .task = "replace host-root dpkg architecture probe (#280)" },
    .{ .path = "actions/download/src/inputs.ts", .task = "remove download Action legacy input/default (#283)" },
    .{ .path = "actions/download/src/action.ts", .task = "remove download Action legacy dispatch (#283)" },
    .{ .path = "actions/download/src/runner.ts", .task = "remove download Action legacy execution contract (#283)" },
    .{ .path = "actions/download/action.yml", .task = "change download Action shipped default (#283)" },
    .{ .path = "actions/install/src/inputs.ts", .task = "remove install Action legacy input/default (#283)" },
    .{ .path = "actions/install/src/action.ts", .task = "remove install Action legacy dispatch (#283)" },
    .{ .path = "actions/install/src/subprocess.ts", .task = "remove nested download legacy handoff (#283)" },
    .{ .path = "actions/install/src/errors.ts", .task = "remove install Action legacy error default (#283)" },
    .{ .path = "actions/install/src/runner.ts", .task = "remove install Action legacy execution verifier; retain historical-only verifier if needed (#283)" },
    .{ .path = "actions/install/action.yml", .task = "change install Action shipped default (#283)" },
};

const guard_cutover_routes = [_]CutoverRoute{
    .{
        .path = "src/cli_backend_policy.zig",
        .task = "remove new-execution CLI legacy fallback; retain completed historical verification (#283)",
    },
    .{
        .path = "src/root_operation.zig",
        .task = "remove root-operation active legacy publication default; retain historical decoder and typed refusal (#279/#285)",
    },
};

const expected_guard_paths = [_][]const u8{
    "src/active_repository_config.zig",
    "src/cli_backend_policy.zig",
    "src/exact_lock_v2.zig",
    "src/exact_lock_v3.zig",
    "src/exact_lock_v4.zig",
    "src/installed_baseline.zig",
    "src/installed_baseline_component.zig",
    "src/legacy_compat.zig",
    "src/maintainer_script.zig",
    "src/native_authorization.zig",
    "src/native_baseline_contract.zig",
    "src/native_execution_request.zig",
    "src/native_program.zig",
    "src/native_transaction_result.zig",
    "src/native_unpack.zig",
    "src/root_operation.zig",
    "src/root_operation_completion.zig",
    "src/system_product_context.zig",
};

const expected_reference_paths = [_][]const u8{
    "test/native_differential_cli.zig",
    "tools/debian-stable-readiness.zig",
    "tools/prepare-native-dpkg.zig",
};

const expected_contract_paths = [_][]const u8{
    "actions/download/dist/index.js",
    "actions/install/dist/index.js",
};

const OperatorSpec = struct {
    path: []const u8,
    operators: []const []const u8,
};

const native_operator_specs = [_]OperatorSpec{
    .{ .path = "actions/download/src/runner.ts", .operators = &.{"execFile"} },
    .{ .path = "actions/install/src/subprocess.ts", .operators = &.{"spawn"} },
    .{ .path = "actions/setup/src/runner.ts", .operators = &.{"execFileAsync"} },
    .{ .path = "src/live_root.zig", .operators = &.{"linux.fork"} },
    .{ .path = "src/maintainer_script.zig", .operators = &.{ "linux.clone2", "linux.execve", "linux.fork" } },
};

const legacy_operator_specs = [_]OperatorSpec{
    .{ .path = "src/target_apt_config.zig", .operators = &.{"std.process.run"} },
};

fn matchesCutoverRoute(path: []const u8, prod: []const u8) bool {
    if (std.mem.eql(u8, path, "src/transaction_executor.zig")) {
        return (containsTokenSeq(prod, &.{ "pub fn execute", "(" }) and
            !containsTokenSeq(prod, &.{ "return", "error.LegacyTransactionExecutionRetired", ";" })) or
            containsTokenSeq(prod, &.{ "fn buildArgv", "(" });
    }
    if (std.mem.eql(u8, path, "src/exact_lock.zig")) {
        return containsTokenSeq(prod, &.{ "pub fn create", "(" });
    }
    if (std.mem.eql(u8, path, "src/transaction_provenance.zig") or
        std.mem.eql(u8, path, "src/transaction_provenance_v2.zig"))
    {
        return containsTokenSeq(prod, &.{ "pub fn createFromExecution", "(" }) or
            containsTokenSeq(prod, &.{ "pub fn createFromRecovery", "(" });
    }
    if (std.mem.eql(u8, path, "src/transaction_recovery.zig")) {
        return containsTokenSeq(prod, &.{ "pub fn persist", "(" }) or
            containsTokenSeq(prod, &.{ "pub fn archive", "(" }) or
            containsTokenSeq(prod, &.{ "pub fn encode", "(" });
    }
    if (std.mem.eql(u8, path, "src/transaction_engine.zig")) {
        return containsTokenSeq(prod, &.{ ".legacy_dpkg", "=>", "legacy_dpkg" });
    }
    if (std.mem.eql(u8, path, "src/production_backend.zig") or
        std.mem.eql(u8, path, "src/repository_backend.zig"))
    {
        return containsTokenSeq(prod, &.{ "transaction_backend:", "transaction_engine.Kind", "=", ".legacy_dpkg" });
    }
    if (std.mem.eql(u8, path, "src/package_family_backend.zig")) {
        return containsTokenSeq(prod, &.{ "if", "(arguments.len", "==", "0)", "return", ".legacy_dpkg" });
    }
    if (std.mem.eql(u8, path, "src/package_cache_workflow.zig")) {
        return containsTokenSeq(prod, &.{ "pub fn createFingerprint", "(" }) or
            containsTokenSeq(prod, &.{ "pub fn prepare", "(" });
    }
    if (std.mem.eql(u8, path, "src/transaction_result_summary.zig")) {
        return containsTokenSeq(prod, &.{ "pub fn canonicalJson", "(" });
    }
    if (std.mem.eql(u8, path, "src/system_profile.zig")) {
        return containsTokenSeq(prod, &.{ "transaction_backend:", "TransactionBackend", "=", ".legacy_dpkg" });
    }
    if (std.mem.eql(u8, path, "src/main.zig")) {
        return containsTokenSeq(prod, &.{ "var transaction_backend:", "debz.transaction_engine.Kind", "=", ".legacy_dpkg" }) or
            containsTokenSeq(prod, &.{ "return if", "(native_only_rehearsal)", ".native_only", "else", ".legacy_capable" });
    }
    if (std.mem.eql(u8, path, "src/repository_cli.zig")) {
        return containsTokenSeq(prod, &.{ "transaction_backend:", "debz.transaction_engine.Kind", "=", ".legacy_dpkg" });
    }
    if (std.mem.eql(u8, path, "src/apt_system_orchestrator.zig")) {
        return containsTokenSeq(prod, &.{ "transaction_backend:", "system_profile.TransactionBackend", "=", ".legacy_dpkg" }) or
            containsTokenSeq(prod, &.{ ".legacy_capable", ",", "switch", "(loaded.profile.transaction_backend)" });
    }
    if (std.mem.eql(u8, path, "src/target_apt_config.zig")) {
        return containsTokenSeq(prod, &.{ "const argv", "=", "[_][]const u8{", "\"/usr/bin/dpkg\",", "\"--print-architecture\"", "}" });
    }
    if (std.mem.eql(u8, path, "actions/download/src/inputs.ts") or
        std.mem.eql(u8, path, "actions/install/src/inputs.ts"))
    {
        return containsTokenSeq(prod, &.{ "??", "'legacy_dpkg'" }) or
            containsTokenSeq(prod, &.{ "||", "'legacy_dpkg'" });
    }
    if (std.mem.eql(u8, path, "actions/download/src/action.ts") or
        std.mem.eql(u8, path, "actions/install/src/action.ts") or
        std.mem.eql(u8, path, "actions/install/src/subprocess.ts"))
    {
        return containsTokenSeq(prod, &.{ "inputs.transactionBackend", "===", "'legacy_dpkg'" });
    }
    if (std.mem.eql(u8, path, "actions/download/src/runner.ts")) {
        return containsTokenSeq(prod, &.{ "legacy_dpkg:", "{" });
    }
    if (std.mem.eql(u8, path, "actions/download/action.yml") or
        std.mem.eql(u8, path, "actions/install/action.yml"))
    {
        return hasIndentedDefaultLegacyDpkg(prod);
    }
    if (std.mem.eql(u8, path, "actions/install/src/errors.ts")) {
        return containsTokenSeq(prod, &.{ "=", "'legacy_dpkg'" });
    }
    if (std.mem.eql(u8, path, "actions/install/src/runner.ts")) {
        return std.mem.indexOf(u8, prod, "'io.github.cataggar.debz.transaction-result-summary.v1'") != null;
    }
    return false;
}

fn matchesGuardCutoverRoute(path: []const u8, prod: []const u8) bool {
    if (std.mem.eql(u8, path, "src/cli_backend_policy.zig")) {
        return containsTokenSeq(prod, &.{ ".legacy_capable", "=>", "debz.transaction_engine.Kind.legacy_dpkg" });
    }
    if (std.mem.eql(u8, path, "src/root_operation.zig")) {
        return containsTokenSeq(prod, &.{ "legacy_execution_capable:", "bool", "=", "true" });
    }
    return false;
}

pub fn productionPart(relative: []const u8, text: []const u8) []const u8 {
    if (!std.mem.endsWith(u8, relative, ".zig")) return text;
    var test_start: ?usize = null;
    var pos: usize = 0;
    while (pos < text.len) {
        if ((pos == 0 or text[pos - 1] == '\n') and std.mem.startsWith(u8, text[pos..], "test")) {
            var cur = pos + "test".len;
            if (cur < text.len and std.ascii.isWhitespace(text[cur])) {
                while (cur < text.len and std.ascii.isWhitespace(text[cur])) : (cur += 1) {}
                if (cur < text.len and text[cur] == '"') {
                    test_start = pos;
                    break;
                }
            }
        }
        if (std.mem.indexOfScalarPos(u8, text, pos, '\n')) |nl| {
            pos = nl + 1;
        } else break;
    }
    if (std.mem.eql(u8, relative, "src/native_unpack.zig")) {
        if (std.mem.indexOf(u8, text, "\nfn testFreshDatabaseInstall(")) |helper| {
            if (test_start == null or helper < test_start.?) {
                return text[0..helper];
            }
        }
    }
    return if (test_start) |idx| text[0..idx] else text;
}

const LaunchMatch = struct {
    end: usize,
    kind: []const u8,
};

fn matchZigLaunchAt(prod: []const u8, start: usize) ?LaunchMatch {
    const rem = prod[start..];
    switch (rem[0]) {
        's' => if (!std.mem.startsWith(u8, rem, "std.") and !std.mem.startsWith(u8, rem, "system")) return null,
        'l' => if (!std.mem.startsWith(u8, rem, "linux.")) return null,
        'p' => if (!std.mem.startsWith(u8, rem, "po")) return null,
        'e' => if (!std.mem.startsWith(u8, rem, "execv")) return null,
        '@' => if (!std.mem.startsWith(u8, rem, "@field")) return null,
        else => return null,
    }
    if (start > 0 and isWordChar(prod[start - 1])) return null;

    if (std.mem.startsWith(u8, rem, "std.process.")) {
        const after_prefix = start + "std.process.".len;
        for ([_][]const u8{ "ChildProcess", "Child", "run" }) |member| {
            if (std.mem.startsWith(u8, prod[after_prefix..], member)) {
                const member_end = after_prefix + member.len;
                if (member_end < prod.len and isWordChar(prod[member_end])) continue;
                var cur = member_end;
                while (cur < prod.len and std.ascii.isWhitespace(prod[cur])) : (cur += 1) {}
                if (cur < prod.len and (prod[cur] == '(' or prod[cur] == '.' or prod[cur] == '{')) {
                    const kind = switch (prod[cur]) {
                        '.' => "std.process.",
                        else => if (std.mem.eql(u8, member, "run"))
                            "std.process.run"
                        else if (std.mem.eql(u8, member, "ChildProcess"))
                            "std.process.ChildProcess"
                        else
                            "std.process.Child",
                    };
                    return .{ .end = cur + 1, .kind = kind };
                }
            }
        }
    }

    const linux_prefix_len: ?usize = if (std.mem.startsWith(u8, rem, "std.os.linux."))
        "std.os.linux.".len
    else if (std.mem.startsWith(u8, rem, "linux."))
        "linux.".len
    else
        null;

    if (linux_prefix_len) |plen| {
        const after_prefix = start + plen;
        for ([_]struct { name: []const u8, kind: []const u8 }{
            .{ .name = "execveat", .kind = "linux.execveat" },
            .{ .name = "execve", .kind = "linux.execve" },
            .{ .name = "clone2", .kind = "linux.clone2" },
            .{ .name = "fork", .kind = "linux.fork" },
        }) |op| {
            if (std.mem.startsWith(u8, prod[after_prefix..], op.name)) {
                const op_end = after_prefix + op.name.len;
                if (op_end < prod.len and isWordChar(prod[op_end])) continue;
                var cur = op_end;
                while (cur < prod.len and std.ascii.isWhitespace(prod[cur])) : (cur += 1) {}
                if (cur < prod.len and prod[cur] == '(') {
                    return .{ .end = cur + 1, .kind = op.kind };
                }
            }
        }
        if (std.mem.startsWith(u8, prod[after_prefix..], "syscall")) {
            var cur = after_prefix + "syscall".len;
            while (cur < prod.len and std.ascii.isDigit(prod[cur])) : (cur += 1) {}
            if (cur >= prod.len or !isWordChar(prod[cur])) {
                while (cur < prod.len and std.ascii.isWhitespace(prod[cur])) : (cur += 1) {}
                if (cur < prod.len and prod[cur] == '(') {
                    cur += 1;
                    while (cur < prod.len and std.ascii.isWhitespace(prod[cur])) : (cur += 1) {}
                    if (cur < prod.len and prod[cur] == '.') {
                        cur += 1;
                        for ([_]struct { name: []const u8, kind: []const u8 }{
                            .{ .name = "execveat", .kind = "syscall.execveat" },
                            .{ .name = "execve", .kind = "syscall.execve" },
                        }) |sys_op| {
                            if (std.mem.startsWith(u8, prod[cur..], sys_op.name)) {
                                const sys_end = cur + sys_op.name.len;
                                if (sys_end < prod.len and isWordChar(prod[sys_end])) continue;
                                var comma = sys_end;
                                while (comma < prod.len and std.ascii.isWhitespace(prod[comma])) : (comma += 1) {}
                                if (comma < prod.len and prod[comma] == ',') {
                                    return .{ .end = comma + 1, .kind = sys_op.kind };
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    for ([_][]const u8{ "posix_spawn", "execveat", "execvp", "execve", "execv", "system", "popen" }) |func| {
        if (std.mem.startsWith(u8, rem, func)) {
            const func_end = start + func.len;
            if (func_end < prod.len and isWordChar(prod[func_end])) continue;
            var cur = func_end;
            while (cur < prod.len and std.ascii.isWhitespace(prod[cur])) : (cur += 1) {}
            if (cur < prod.len and prod[cur] == '(') {
                return .{ .end = cur + 1, .kind = func };
            }
        }
    }

    if (std.mem.startsWith(u8, rem, "@field")) {
        const after_field = start + "@field".len;
        if (after_field >= prod.len or !isWordChar(prod[after_field])) {
            var cur = after_field;
            while (cur < prod.len and std.ascii.isWhitespace(prod[cur])) : (cur += 1) {}
            if (cur < prod.len and prod[cur] == '(') {
                var scan = cur + 1;
                while (scan < prod.len and prod[scan] != ';' and prod[scan] != '\n') : (scan += 1) {
                    if (std.mem.startsWith(u8, prod[scan..], "\"execveat\"") or
                        std.mem.startsWith(u8, prod[scan..], "'execveat'"))
                    {
                        return .{ .end = scan + "\"execveat\"".len, .kind = "@field" };
                    }
                }
            }
        }
    }

    return null;
}

fn matchTsLaunchAt(prod: []const u8, start: usize) ?LaunchMatch {
    const rem = prod[start..];
    switch (rem[0]) {
        's' => if (!std.mem.startsWith(u8, rem, "spawn")) return null,
        'e' => if (!std.mem.startsWith(u8, rem, "exec")) return null,
        'f' => if (!std.mem.startsWith(u8, rem, "fork")) return null,
        else => return null,
    }
    if (start > 0 and isWordChar(prod[start - 1])) return null;
    for ([_][]const u8{ "spawnSync", "spawn", "execFileAsync", "execFile", "execSync", "fork" }) |func| {
        if (std.mem.startsWith(u8, rem, func)) {
            const func_end = start + func.len;
            if (func_end < prod.len and isWordChar(prod[func_end])) continue;
            var cur = func_end;
            while (cur < prod.len and std.ascii.isWhitespace(prod[cur])) : (cur += 1) {}
            if (cur < prod.len and prod[cur] == '(') {
                return .{ .end = cur + 1, .kind = func };
            }
        }
    }
    return null;
}

pub fn launchSites(
    allocator: std.mem.Allocator,
    relative: []const u8,
    text: []const u8,
) !std.StringHashMap(usize) {
    var sites = std.StringHashMap(usize).init(allocator);
    const prod = productionPart(relative, text);
    const is_zig = std.mem.endsWith(u8, relative, ".zig");

    var i: usize = 0;
    while (i < prod.len) {
        const matched = if (is_zig) matchZigLaunchAt(prod, i) else matchTsLaunchAt(prod, i);
        if (matched) |m| {
            const line_start = if (std.mem.lastIndexOfScalar(u8, prod[0..i], '\n')) |nl| nl + 1 else 0;
            const prefix = std.mem.trimStart(u8, prod[line_start..i], " \t\r\n");
            if (!std.mem.startsWith(u8, prefix, "//") and
                !std.mem.startsWith(u8, prefix, "*") and
                !std.mem.startsWith(u8, prefix, "\\\\"))
            {
                const gop = try sites.getOrPut(m.kind);
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* += 1;
            }
            i = m.end;
        } else {
            i += 1;
        }
    }
    return sites;
}

fn hasTransactionBackendNativeDefault(manifest: []const u8) bool {
    const header = "  transaction-backend:\n";
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, manifest, pos, header)) |idx| {
        if (idx == 0 or manifest[idx - 1] == '\n') {
            var cur = idx + header.len;
            while (cur < manifest.len) {
                const line_end = std.mem.indexOfScalarPos(u8, manifest, cur, '\n') orelse manifest.len;
                const line = std.mem.trimEnd(u8, manifest[cur..line_end], "\r");
                if (!std.mem.startsWith(u8, line, "    ")) break;
                if (std.mem.eql(u8, line, "    default: native")) return true;
                if (line_end >= manifest.len) break;
                cur = line_end + 1;
            }
        }
        pos = idx + 1;
    }
    return false;
}

fn hasBundleNativeDefaultAndGuard(bundle: []const u8) bool {
    var count: usize = 0;
    var all_native = true;
    var has_guarded_native = false;

    var i: usize = 0;
    while (i < bundle.len) : (i += 1) {
        if (bundle[i] != 'o' and bundle[i] != 'e') continue;
        const prefix_len: usize = if (std.mem.startsWith(u8, bundle[i..], "optionalScalar("))
            "optionalScalar(".len
        else if (std.mem.startsWith(u8, bundle[i..], "exactScalar("))
            "exactScalar(".len
        else
            continue;

        const args_start = i + prefix_len;
        const close_paren = std.mem.indexOfScalarPos(u8, bundle, args_start, ')') orelse continue;
        const inside = bundle[args_start..close_paren];
        if (!std.mem.endsWith(u8, inside, "\"TRANSACTION_BACKEND\"")) continue;

        var cur = close_paren + 1;
        while (cur < bundle.len and std.ascii.isWhitespace(bundle[cur])) : (cur += 1) {}
        if (std.mem.startsWith(u8, bundle[cur..], "??")) {
            cur += 2;
        } else if (std.mem.startsWith(u8, bundle[cur..], "||")) {
            cur += 2;
        } else continue;

        if (cur >= bundle.len or bundle[cur] != '"') continue;
        const val_start = cur + 1;
        const val_end = std.mem.indexOfScalarPos(u8, bundle, val_start, '"') orelse continue;
        if (val_end == val_start) continue;
        const default_val = bundle[val_start..val_end];
        count += 1;
        if (!std.mem.eql(u8, default_val, "native")) {
            all_native = false;
            continue;
        }

        const after_quote = val_end + 1;
        if (std.mem.startsWith(u8, bundle[after_quote..], ";if(")) {
            var ident = after_quote + ";if(".len;
            if (ident < bundle.len and isJsIdentStart(bundle[ident])) {
                ident += 1;
                while (ident < bundle.len and isJsIdentChar(bundle[ident])) : (ident += 1) {}
                if (std.mem.startsWith(u8, bundle[ident..], "!==\"native\")")) {
                    has_guarded_native = true;
                }
            }
        }
    }

    return count == 1 and all_native and has_guarded_native;
}

pub fn actionsNativeOnlyCandidateFailures(
    failures: *Failures,
    action: []const u8,
    texts: *const std.StringHashMap([]const u8),
) !void {
    const allocator = failures.allocator;
    const base = try std.fmt.allocPrint(allocator, "actions/{s}/", .{action});
    const manifest = texts.get(try std.fmt.allocPrint(allocator, "{s}action.yml", .{base})).?;
    const inputs = texts.get(try std.fmt.allocPrint(allocator, "{s}src/inputs.ts", .{base})).?;
    const runtime = texts.get(try std.fmt.allocPrint(allocator, "{s}src/action.ts", .{base})).?;
    const bundle = texts.get(try std.fmt.allocPrint(allocator, "{s}dist/index.js", .{base})).?;
    const runner = texts.get(try std.fmt.allocPrint(allocator, "{s}src/runner.ts", .{base})).?;

    if (!hasTransactionBackendNativeDefault(manifest)) {
        try failures.print("{s} action.yml: candidate transaction-backend default must be native", .{action});
    }
    if (std.mem.indexOf(u8, manifest, "backend-capability:") == null) {
        try failures.print("{s} action.yml: candidate must publish backend-capability", .{action});
    }

    const selects_native =
        containsTokenSeq(inputs, &.{ "optionalScalar(", "environment,", "'TRANSACTION_BACKEND'", ")", "??", "'native'" }) or
        containsTokenSeq(inputs, &.{ "optionalScalar(", "environment,", "'TRANSACTION_BACKEND'", ")", "||", "'native'" }) or
        containsTokenSeq(inputs, &.{ "exactScalar(", "environment,", "'TRANSACTION_BACKEND'", ")", "??", "'native'" }) or
        containsTokenSeq(inputs, &.{ "exactScalar(", "environment,", "'TRANSACTION_BACKEND'", ")", "||", "'native'" });
    if (!selects_native) {
        try failures.print("{s} inputs.ts: candidate omitted backend must select native", .{action});
    }

    const guard_idx = indexOfTokenSeq(inputs, &.{ "if", "(", "transactionBackend", "!==", "'native'", ")" });
    const lock_idx = std.mem.indexOf(u8, inputs, "const lockInput =");
    if (guard_idx == null or lock_idx == null or guard_idx.? > lock_idx.?) {
        try failures.print("{s} inputs.ts: candidate must refuse legacy before reading lock or preparing roots/cache", .{action});
    }
    if (std.mem.indexOf(u8, inputs, ">=0.3.0,<0.4.0") == null) {
        try failures.print("{s} inputs.ts: candidate legacy refusal needs versioned recovery guidance", .{action});
    }
    if (!hasBundleNativeDefaultAndGuard(bundle)) {
        try failures.print("{s} dist/index.js: checked-in bundle is stale or accepts legacy", .{action});
    }
    if (std.mem.indexOf(u8, runtime, "backend-capability") == null or
        std.mem.indexOf(u8, runtime, "native-transaction-execution-v1") == null)
    {
        try failures.print("{s} action.ts: native backend-capability output is missing", .{action});
    }

    const action_guard = std.mem.indexOf(u8, runtime, "if (inputs.transactionBackend !== 'native')");
    const first_work = std.mem.indexOf(
        u8,
        runtime,
        if (std.mem.eql(u8, action, "download")) "const executable = await findDebz()" else "const protectedFiles =",
    );
    if (action_guard == null or first_work == null or action_guard.? > first_work.?) {
        try failures.print("{s} action.ts: candidate must reject a forged legacy input before work", .{action});
    }
    if (std.mem.indexOf(u8, bundle, "backend-capability") == null or
        std.mem.indexOf(u8, bundle, "native-transaction-execution-v1") == null)
    {
        try failures.print("{s} dist/index.js: native backend-capability evidence is missing", .{action});
    }

    if (std.mem.eql(u8, action, "download")) {
        for ([_][]const u8{
            "exact-closure-lock-v3",
            "package-cache-v5",
            "debz-package-cas-v5-",
            "validateFingerprint(expected, inputs, version)",
            "validatePrepare(",
        }) |token| {
            if (std.mem.indexOf(u8, runner, token) == null) {
                try failures.print("download runner.ts: native lock/fingerprint/cache contract is missing: {s}", .{token});
            }
        }
        const fp_idx = std.mem.indexOf(u8, runtime, "fingerprintCache(");
        const restore_idx = std.mem.indexOf(u8, runtime, "cache.restore(");
        const fp_pos: isize = if (fp_idx) |v| @intCast(v) else -1;
        const restore_pos: isize = if (restore_idx) |v| @intCast(v) else -1;
        if (fp_pos > restore_pos or std.mem.indexOf(u8, runtime, "restoredCacheState(") == null) {
            try failures.append("download action.ts: fingerprint must bind cache restore before preparation");
        }
    } else {
        const child = texts.get(try std.fmt.allocPrint(allocator, "{s}src/subprocess.ts", .{base})).?;
        if (std.mem.indexOf(u8, child, "DEBZ_DOWNLOAD_TRANSACTION_BACKEND: this.inputs.transactionBackend") == null) {
            try failures.append("install subprocess.ts: selected backend is not handed to download");
        }
        if (std.mem.indexOf(u8, child, "requiredOutput(outputs, 'backend-capability')") == null or
            std.mem.indexOf(u8, child, "backendCapability !== expectedBackendCapability") == null or
            !containsTokenSeq(child, &.{ "const expectedBackendCapability", "=", "'native-transaction-execution-v1'" }))
        {
            try failures.append("install subprocess.ts: missing or foreign download capability must refuse");
        }
        if (std.mem.indexOf(u8, child, "debz-package-cas-v5-") == null or
            std.mem.indexOf(u8, child, "lockDigest") == null)
        {
            try failures.append("install subprocess.ts: native cache key and lock digest handoff is missing");
        }
        const probe = std.mem.indexOf(u8, runtime, "buildNativeCapabilityArguments()");
        const download = std.mem.indexOf(u8, runtime, "const download = await composition.download");
        if (probe == null or download == null or probe.? > download.?) {
            try failures.append("install action.ts: native CLI capability must precede download");
        }
        for ([_][]const u8{
            "validateNativeInstallResult(",
            "validateTransactionSummary(",
            "nativeResult.changed",
            "download.lockDigest",
            "outputs.changed",
        }) |token| {
            if (std.mem.indexOf(u8, runtime, token) == null) {
                try failures.print("install action.ts: native receipt/completion/unchanged binding is missing: {s}", .{token});
            }
        }
        if (std.mem.indexOf(u8, runner, "receipt_evidence") == null or
            std.mem.indexOf(u8, runner, "completion_digest_sha256") == null)
        {
            try failures.append("install runner.ts: verified native receipt/completion binding is missing");
        }
    }
}

fn readExactSource(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    relative: []const u8,
    overrides: *const std.StringHashMap(?[]const u8),
    texts: *std.StringHashMap([]const u8),
    failures: *Failures,
) !?[]const u8 {
    if (texts.get(relative)) |existing| return existing;
    if (!isSafeRelativePath(relative)) {
        try failures.print("{s}: missing/unreadable candidate inventory path (unsafe inventory path)", .{relative});
        return null;
    }
    if (overrides.get(relative)) |override_opt| {
        if (override_opt) |val| {
            try texts.put(relative, val);
            return val;
        }
        try failures.print("{s}: missing/unreadable candidate inventory path (missing)", .{relative});
        return null;
    }
    var file = root_dir.openFile(io, relative, .{ .follow_symlinks = false }) catch |err| {
        try failures.print("{s}: missing/unreadable candidate inventory path ({s})", .{ relative, @errorName(err) });
        return null;
    };
    defer file.close(io);
    const st = file.stat(io) catch |err| {
        try failures.print("{s}: missing/unreadable candidate inventory path ({s})", .{ relative, @errorName(err) });
        return null;
    };
    if (st.kind != .file) {
        try failures.print("{s}: missing/unreadable candidate inventory path (not a regular file)", .{relative});
        return null;
    }
    if (st.size > maximum_source_bytes) {
        try failures.print("{s}: missing/unreadable candidate inventory path (exceeds 16 MiB)", .{relative});
        return null;
    }
    const bytes = root_dir.readFileAlloc(io, relative, allocator, .limited(maximum_source_bytes)) catch |err| {
        try failures.print("{s}: missing/unreadable candidate inventory path ({s})", .{ relative, @errorName(err) });
        return null;
    };
    if (!std.unicode.utf8ValidateSlice(bytes)) {
        try failures.print("{s}: missing/unreadable candidate inventory path (invalid UTF-8)", .{relative});
        return null;
    }
    try texts.put(relative, bytes);
    return bytes;
}

fn collectSectionPaths(
    section: []const std.json.Value,
    out_set: *std.StringHashMap(void),
) !bool {
    for (section) |entry| {
        if (entry != .object) return false;
        const path_val = entry.object.get("path") orelse return false;
        if (path_val != .string or !isSafeRelativePath(path_val.string)) return false;
        try out_set.put(path_val.string, {});
    }
    return true;
}

fn setEqualsSlice(set: *const std.StringHashMap(void), expected: []const []const u8) bool {
    if (set.count() != expected.len) return false;
    for (expected) |item| {
        if (!set.contains(item)) return false;
    }
    return true;
}

fn collectFilesByExtension(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    rel_dir: []const u8,
    ext: []const u8,
    out: *std.ArrayList([]const u8),
) !void {
    var dir = root_dir.openDir(io, rel_dir, .{ .iterate = true, .follow_symlinks = false }) catch return;
    defer dir.close(io);
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        const child_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rel_dir, entry.name });
        switch (entry.kind) {
            .directory => try collectFilesByExtension(allocator, io, root_dir, child_rel, ext, out),
            .file => if (std.mem.endsWith(u8, entry.name, ext)) {
                try out.append(allocator, child_rel);
            },
            else => {},
        }
    }
}

pub fn candidateFailures(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    overrides: *const std.StringHashMap(?[]const u8),
    failures: *Failures,
) !void {
    var texts = std.StringHashMap([]const u8).init(allocator);

    const policy_raw = try readExactSource(allocator, io, root_dir, legacy_policy_path, overrides, &texts, failures);
    const inventory_raw = try readExactSource(allocator, io, root_dir, inventory_path, overrides, &texts, failures);
    if (policy_raw == null or inventory_raw == null) {
        try failures.append("candidate inventory is malformed: missing policy or inventory");
        return;
    }

    const policy_parsed = std.json.parseFromSlice(std.json.Value, allocator, policy_raw.?, .{}) catch |err| {
        try failures.print("candidate inventory is malformed: {s}", .{@errorName(err)});
        return;
    };
    defer policy_parsed.deinit();

    const inventory_parsed = std.json.parseFromSlice(std.json.Value, allocator, inventory_raw.?, .{}) catch |err| {
        try failures.print("candidate inventory is malformed: {s}", .{@errorName(err)});
        return;
    };
    defer inventory_parsed.deinit();

    if (policy_parsed.value != .object or inventory_parsed.value != .object) {
        try failures.append("candidate inventories must be objects");
        return;
    }
    const policy = policy_parsed.value.object;
    const inventory = inventory_parsed.value.object;

    const schema_val = inventory.get("schema");
    const issue_val = inventory.get("issue");
    if (schema_val == null or schema_val.? != .string or
        !std.mem.eql(u8, schema_val.?.string, "https://debz.dev/schema/native-only-production-candidate-v1") or
        issue_val == null or issue_val.? != .integer or issue_val.?.integer != 276)
    {
        try failures.print("{s}: candidate identity changed", .{inventory_path});
    }

    const cli_build_val = inventory.get("cli_build_path");
    if (cli_build_val == null or cli_build_val.? != .string or !std.mem.eql(u8, cli_build_val.?.string, "build.zig")) {
        try failures.print("{s}: missing exact CLI release build-mode path", .{inventory_path});
    }

    const removed_val = inventory.get("removed_production_paths") orelse {
        try failures.print("{s}: missing/malformed cutover deletion inventory", .{inventory_path});
        return;
    };
    if (removed_val != .array) {
        try failures.print("{s}: missing/malformed cutover deletion inventory", .{inventory_path});
        return;
    }
    var removed_paths = std.StringHashMap(void).init(allocator);
    for (removed_val.array.items) |item| {
        if (item != .string) {
            try failures.print("{s}: missing/malformed cutover deletion inventory", .{inventory_path});
            return;
        }
        const gop = try removed_paths.getOrPut(item.string);
        if (gop.found_existing) {
            try failures.print("{s}: missing/malformed cutover deletion inventory", .{inventory_path});
            return;
        }
    }

    const production_val = policy.get("production_execution_paths");
    const guards_val = policy.get("compatibility_guard_paths");
    const references_val = policy.get("historical_reference_paths");
    const contracts_val = policy.get("generated_contracts");
    if (production_val == null or production_val.? != .array or
        guards_val == null or guards_val.? != .array or
        references_val == null or references_val.? != .array or
        contracts_val == null or contracts_val.? != .array)
    {
        try failures.print("{s}: missing production/guard/reference/generated path inventory", .{legacy_policy_path});
        return;
    }

    const production = production_val.?.array.items;
    const guards = guards_val.?.array.items;
    const references = references_val.?.array.items;
    const contracts = contracts_val.?.array.items;

    var production_paths = std.StringHashMap(void).init(allocator);
    var guard_paths = std.StringHashMap(void).init(allocator);
    var reference_paths = std.StringHashMap(void).init(allocator);
    var contract_paths = std.StringHashMap(void).init(allocator);

    if (!(try collectSectionPaths(production, &production_paths)) or
        !(try collectSectionPaths(guards, &guard_paths)) or
        !(try collectSectionPaths(references, &reference_paths)) or
        !(try collectSectionPaths(contracts, &contract_paths)))
    {
        try failures.print("{s}: malformed or unsafe candidate path classification", .{legacy_policy_path});
        return;
    }

    var all_classified = std.StringHashMap(void).init(allocator);
    for ([_]*const std.StringHashMap(void){ &production_paths, &guard_paths, &reference_paths, &contract_paths }) |set| {
        var it = set.keyIterator();
        while (it.next()) |k| try all_classified.put(k.*, {});
    }
    const total_section_len = production.len + guards.len + references.len + contracts.len;
    if (total_section_len != all_classified.count()) {
        try failures.print("{s}: duplicate/multiply classified candidate path", .{legacy_policy_path});
    }

    var prod_plus_removed = std.StringHashMap(void).init(allocator);
    var has_prod_removed_overlap = false;
    {
        var it = production_paths.keyIterator();
        while (it.next()) |k| {
            if (removed_paths.contains(k.*)) has_prod_removed_overlap = true;
            try prod_plus_removed.put(k.*, {});
        }
        var rit = removed_paths.keyIterator();
        while (rit.next()) |k| try prod_plus_removed.put(k.*, {});
    }
    var prod_routes_match = !has_prod_removed_overlap and prod_plus_removed.count() == cutover_routes.len;
    if (prod_routes_match) {
        for (cutover_routes) |route| {
            if (!prod_plus_removed.contains(route.path)) {
                prod_routes_match = false;
                break;
            }
        }
    }
    if (!prod_routes_match) {
        try failures.print("{s}: missing/unreviewed candidate production path classification", .{legacy_policy_path});
    }

    {
        var removed_list: std.ArrayList([]const u8) = .empty;
        var rit = removed_paths.keyIterator();
        while (rit.next()) |k| try removed_list.append(allocator, k.*);
        std.sort.heap([]const u8, removed_list.items, {}, lessThanString);
        for (removed_list.items) |path| {
            if (root_dir.statFile(io, path, .{ .follow_symlinks = false })) |_| {
                try failures.print("{s}: declared deleted but production path still exists", .{path});
            } else |_| {}
        }
    }

    const guards_ok = setEqualsSlice(&guard_paths, &expected_guard_paths);
    if (!guards_ok) {
        try failures.print("{s}: missing/unreviewed compatibility guard paths", .{legacy_policy_path});
    }
    const references_ok = setEqualsSlice(&reference_paths, &expected_reference_paths);
    if (!references_ok) {
        try failures.print("{s}: reference-only paths must be exact, not a dpkg basename allowance", .{legacy_policy_path});
    }
    const contracts_ok = setEqualsSlice(&contract_paths, &expected_contract_paths);
    if (!contracts_ok) {
        try failures.print("{s}: missing or unclassified generated Actions bundle", .{legacy_policy_path});
    }

    var disposition_ok = true;
    for ([_][]const std.json.Value{ production, guards }) |section| {
        for (section) |entry| {
            const role = entry.object.get("role");
            const cutover = entry.object.get("cutover");
            if (role == null or role.? != .string or role.?.string.len == 0 or
                cutover == null or cutover.? != .string or cutover.?.string.len == 0)
            {
                disposition_ok = false;
            }
        }
    }
    for (references) |entry| {
        const retain = entry.object.get("retain_after_cutover");
        if (retain == null or retain.? != .bool or !retain.?.bool) disposition_ok = false;
    }
    for (contracts) |entry| {
        const evidence = entry.object.get("required_evidence");
        if (evidence == null or evidence.? != .string or !std.mem.eql(u8, evidence.?.string, "backend-capability")) {
            disposition_ok = false;
        }
    }
    if (!disposition_ok) {
        try failures.print("{s}: missing disposition or generated-contract evidence", .{legacy_policy_path});
    }

    var journal_ok = false;
    if (policy.get("artifact_policy")) |ap_val| {
        if (ap_val == .array) {
            var journal_matches: usize = 0;
            for (ap_val.array.items) |entry| {
                if (entry != .object) continue;
                const s = entry.object.get("schema") orelse continue;
                if (s != .string or !std.mem.eql(u8, s.string, "debz:transaction-journal")) continue;
                journal_matches += 1;
                const versions = entry.object.get("versions");
                const backend = entry.object.get("backend");
                const new_exec = entry.object.get("new_execution");
                if (versions != null and versions.? == .array and versions.?.array.items.len == 4 and
                    versions.?.array.items[0] == .integer and versions.?.array.items[0].integer == 1 and
                    versions.?.array.items[1] == .integer and versions.?.array.items[1].integer == 2 and
                    versions.?.array.items[2] == .integer and versions.?.array.items[2].integer == 3 and
                    versions.?.array.items[3] == .integer and versions.?.array.items[3].integer == 4 and
                    backend != null and backend.? == .string and std.mem.eql(u8, backend.?.string, "legacy_dpkg") and
                    new_exec != null and new_exec.? == .string and std.mem.eql(u8, new_exec.?.string, "version_4_only"))
                {
                    journal_ok = true;
                }
            }
            if (journal_matches != 1) journal_ok = false;
        }
    }
    if (!journal_ok) {
        try failures.print("{s}: journal v1-v4 historical legacy decoding is unclassified", .{legacy_policy_path});
    }

    if (!prod_routes_match or !guards_ok or !references_ok or !contracts_ok) {
        return;
    }

    const allowances_val = inventory.get("launch_allowances");
    const fingerprints_val = inventory.get("reviewed_fingerprints");
    if (allowances_val == null or allowances_val.? != .object or
        fingerprints_val == null or fingerprints_val.? != .object)
    {
        try failures.print("{s}: missing launch allowances or reviewed fingerprints", .{inventory_path});
        return;
    }
    const allowances = allowances_val.?.object;
    const fingerprints = fingerprints_val.?.object;

    var allowance_paths_ok = true;
    for (native_operator_specs) |spec| {
        if (!allowances.contains(spec.path)) allowance_paths_ok = false;
    }
    {
        var ait = allowances.iterator();
        while (ait.next()) |entry| {
            var known = false;
            for (native_operator_specs) |spec| {
                if (std.mem.eql(u8, spec.path, entry.key_ptr.*)) known = true;
            }
            for (legacy_operator_specs) |spec| {
                if (std.mem.eql(u8, spec.path, entry.key_ptr.*)) known = true;
            }
            if (!known) allowance_paths_ok = false;
        }
    }
    if (!allowance_paths_ok) {
        try failures.print("{s}: missing/unknown child-process allowance paths", .{inventory_path});
    }

    for ([_][]const OperatorSpec{ &native_operator_specs, &legacy_operator_specs }) |specs| {
        for (specs) |spec| {
            if (allowances.get(spec.path)) |allow_entry| {
                var ops_match = allow_entry == .object and allow_entry.object.count() == spec.operators.len;
                if (ops_match) {
                    for (spec.operators) |op| {
                        if (!allow_entry.object.contains(op)) {
                            ops_match = false;
                            break;
                        }
                    }
                }
                if (!ops_match) {
                    try failures.print(
                        "{s}: unreviewed child-process operator; no indirect execveat or dpkg basename allowance",
                        .{spec.path},
                    );
                }
            }
        }
    }

    var required_hashes = std.StringHashMap(void).init(allocator);
    {
        var it = all_classified.keyIterator();
        while (it.next()) |k| try required_hashes.put(k.*, {});
    }
    try required_hashes.put("src/live_root.zig", {});
    try required_hashes.put("actions/setup/src/runner.ts", {});
    try required_hashes.put("build.zig", {});

    var fingerprints_match_required = fingerprints.count() == required_hashes.count();
    if (fingerprints_match_required) {
        var fit = fingerprints.iterator();
        while (fit.next()) |entry| {
            if (!required_hashes.contains(entry.key_ptr.*)) {
                fingerprints_match_required = false;
                break;
            }
        }
    }
    if (!fingerprints_match_required) {
        try failures.print("{s}: missing/stale fingerprint path classification", .{inventory_path});
    }

    var allowed_override_paths = std.StringHashMap(void).init(allocator);
    {
        var it = required_hashes.keyIterator();
        while (it.next()) |k| try allowed_override_paths.put(k.*, {});
    }
    try allowed_override_paths.put(legacy_policy_path, {});
    try allowed_override_paths.put(inventory_path, {});

    {
        var oit = overrides.keyIterator();
        while (oit.next()) |k| {
            if (!allowed_override_paths.contains(k.*)) {
                try failures.print("candidate fixture has unknown override path: {s}", .{k.*});
                break;
            }
        }
    }

    var to_load_set = std.StringHashMap(void).init(allocator);
    {
        var it = all_classified.keyIterator();
        while (it.next()) |k| try to_load_set.put(k.*, {});
        var ait = allowances.iterator();
        while (ait.next()) |entry| try to_load_set.put(entry.key_ptr.*, {});
        var fit = fingerprints.iterator();
        while (fit.next()) |entry| try to_load_set.put(entry.key_ptr.*, {});
    }
    var to_load_list: std.ArrayList([]const u8) = .empty;
    {
        var it = to_load_set.keyIterator();
        while (it.next()) |k| try to_load_list.append(allocator, k.*);
    }
    std.sort.heap([]const u8, to_load_list.items, {}, lessThanString);
    for (to_load_list.items) |relative| {
        _ = try readExactSource(allocator, io, root_dir, relative, overrides, &texts, failures);
    }

    var fp_keys: std.ArrayList([]const u8) = .empty;
    {
        var fit = fingerprints.iterator();
        while (fit.next()) |entry| try fp_keys.append(allocator, entry.key_ptr.*);
    }
    std.sort.heap([]const u8, fp_keys.items, {}, lessThanString);
    for (fp_keys.items) |relative| {
        const expected_val = fingerprints.get(relative).?;
        if (expected_val != .string or !isHex128Lower(expected_val.string)) {
            try failures.print("{s}: missing fingerprint for {s}", .{ inventory_path, relative });
        } else if (texts.get(relative)) |content| {
            var digest: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash(content, &digest, .{});
            const actual_hex = std.fmt.bytesToHex(digest, .lower);
            if (!std.mem.eql(u8, &actual_hex, expected_val.string)) {
                try failures.print("{s}: stale reviewed inventory fingerprint; re-review this exact path", .{relative});
            }
        }
    }

    var exception_ok = false;
    if (inventory.get("signed_script_exception")) |exc_val| {
        if (exc_val == .object and exc_val.object.count() == 4) {
            const p = exc_val.object.get("path");
            const id = exc_val.object.get("identity");
            const sc = exc_val.object.get("script");
            const tl = exc_val.object.get("tool");
            if (p != null and p.? == .string and std.mem.eql(u8, p.?.string, "src/maintainer_script.zig") and
                id != null and id.? == .string and std.mem.eql(u8, id.?.string, "snapshotSudoIdentity") and
                sc != null and sc.? == .string and std.mem.eql(u8, sc.?.string, "var/lib/dpkg/info/sudo.postinst") and
                tl != null and tl.? == .string and std.mem.eql(u8, tl.?.string, "usr/bin/dpkg-query"))
            {
                exception_ok = true;
            }
        }
    }
    if (!exception_ok) {
        try failures.print("{s}: signed sudo dpkg-query exception must be exact", .{inventory_path});
    }

    const runner_src = texts.get("src/maintainer_script.zig") orelse "";
    for ([_][]const u8{
        "fn snapshotSudoIdentity(",
        "\"var/lib/dpkg/info/sudo.postinst\"",
        "snapshotSudoIdentity(identity, invocation.argv[1..])",
        ".{ .path = \"usr/bin/dpkg-query\", .size = 142160, .mode = 0o755,",
        "linux.execve(child.program.ptr, child.argv, child.envp)",
    }) |token| {
        if (std.mem.indexOf(u8, runner_src, token) == null) {
            try failures.append("src/maintainer_script.zig: signed sudo query exception lost exact identity/tool/exec binding");
            break;
        }
    }

    var scoped: std.ArrayList([]const u8) = .empty;
    try collectFilesByExtension(allocator, io, root_dir, "src", ".zig", &scoped);
    std.sort.heap([]const u8, scoped.items, {}, lessThanString);
    for ([_][]const u8{ "setup", "download", "install" }) |action| {
        var action_files: std.ArrayList([]const u8) = .empty;
        const action_src = try std.fmt.allocPrint(allocator, "actions/{s}/src", .{action});
        try collectFilesByExtension(allocator, io, root_dir, action_src, ".ts", &action_files);
        std.sort.heap([]const u8, action_files.items, {}, lessThanString);
        try scoped.appendSlice(allocator, action_files.items);
    }

    var seen_launches = std.StringHashMap(void).init(allocator);
    for (scoped.items) |relative| {
        const text = (try readExactSource(allocator, io, root_dir, relative, overrides, &texts, failures)) orelse continue;
        var found = try launchSites(allocator, relative, text);
        defer found.deinit();

        if (allowances.get(relative)) |expected_val| {
            try seen_launches.put(relative, {});
            var valid_allowance = expected_val == .object and expected_val.object.count() > 0;
            if (valid_allowance) {
                var eit = expected_val.object.iterator();
                while (eit.next()) |kv| {
                    if (kv.value_ptr.* != .integer or kv.value_ptr.*.integer < 1) {
                        valid_allowance = false;
                        break;
                    }
                }
            }
            if (!valid_allowance) {
                try failures.print("{s}: invalid/missing child-process allowance for {s}", .{ inventory_path, relative });
            } else {
                var counts_equal = found.count() == expected_val.object.count();
                if (counts_equal) {
                    var eit = expected_val.object.iterator();
                    while (eit.next()) |kv| {
                        const actual_count = found.get(kv.key_ptr.*) orelse {
                            counts_equal = false;
                            break;
                        };
                        if (actual_count != @as(usize, @intCast(kv.value_ptr.*.integer))) {
                            counts_equal = false;
                            break;
                        }
                    }
                }
                if (!counts_equal) {
                    try failures.print("{s}: unreviewed/stale child-process allowance", .{relative});
                }
            }
        } else if (found.count() > 0) {
            try failures.print("{s}: unreviewed production child-process launch", .{relative});
        }
    }

    {
        var missing_launches: std.ArrayList([]const u8) = .empty;
        var ait = allowances.iterator();
        while (ait.next()) |entry| {
            if (!seen_launches.contains(entry.key_ptr.*)) {
                try missing_launches.append(allocator, entry.key_ptr.*);
            }
        }
        std.sort.heap([]const u8, missing_launches.items, {}, lessThanString);
        for (missing_launches.items) |relative| {
            try failures.print("{s}: missing production child-process allowance path", .{relative});
        }
    }

    for ([_][]const u8{ "src/transaction_executor.zig", "src/target_apt_config.zig" }) |relative| {
        if (allowances.contains(relative)) {
            if (texts.get(relative)) |text| {
                var found = try launchSites(allocator, relative, text);
                defer found.deinit();
                if (found.count() > 0) {
                    try failures.print("{s}: legacy production dpkg/dpkg-deb command adapter remains (#281/#280)", .{relative});
                }
            }
        }
    }

    const executor_prod = productionPart("src/transaction_executor.zig", texts.get("src/transaction_executor.zig") orelse "");
    if (indexOfTokenSeq(executor_prod, &.{ "pub fn recover", "(" })) |recover_idx| {
        if (indexOfTokenSeq(executor_prod[recover_idx..], &.{ "dependencies.process.run", "(" }) != null) {
            try failures.append("src/transaction_executor.zig: active legacy journal recovery still launches dpkg (#285)");
        }
    }

    for (cutover_routes) |route| {
        if (texts.get(route.path)) |text| {
            if (matchesCutoverRoute(route.path, productionPart(route.path, text))) {
                try failures.print("{s}: candidate cutover task: {s}", .{ route.path, route.task });
            }
        }
    }
    for (guard_cutover_routes) |route| {
        if (texts.get(route.path)) |text| {
            if (matchesGuardCutoverRoute(route.path, productionPart(route.path, text))) {
                try failures.print("{s}: candidate cutover task: {s}", .{ route.path, route.task });
            }
        }
    }

    const build_src = texts.get("build.zig") orelse "";
    if (containsTokenSeq(build_src, &.{ "release_cli_options.addOption(", "bool", ",", "\"native_only\"", ",", "false", ")" })) {
        try failures.append("build.zig: candidate cutover task: change CLI shipped native-only mode, not only rehearsal (#283)");
    }

    for ([_][]const u8{ "download", "install" }) |action| {
        const subpaths: []const []const u8 = if (std.mem.eql(u8, action, "install"))
            &.{ "action.yml", "src/inputs.ts", "src/action.ts", "src/runner.ts", "dist/index.js", "src/subprocess.ts" }
        else
            &.{ "action.yml", "src/inputs.ts", "src/action.ts", "src/runner.ts", "dist/index.js" };
        var all_present = true;
        for (subpaths) |sub| {
            const p = try std.fmt.allocPrint(allocator, "actions/{s}/{s}", .{ action, sub });
            if (!texts.contains(p)) {
                all_present = false;
                break;
            }
        }
        if (all_present) {
            try actionsNativeOnlyCandidateFailures(failures, action, &texts);
        }
    }
}

fn readBoundedRegularInput(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    limit: usize,
) ![]const u8 {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    const st = try file.stat(io);
    if (st.kind != .file or st.size > limit) return error.InvalidCheckInput;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(limit));
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidCheckInput;
    return bytes;
}

fn runCheckCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    kind: []const u8,
    input_path: []const u8,
) !u8 {
    const limit: usize = if (std.mem.eql(u8, kind, "native-only-candidate"))
        2 * 1024 * 1024
    else if (std.mem.eql(u8, kind, "actions-native-only"))
        1024 * 1024
    else {
        try std.Io.File.stderr().writeStreamingAll(
            io,
            try std.fmt.allocPrint(allocator, "security-audit: unknown check kind: {s}\n", .{kind}),
        );
        return 2;
    };

    const text = readBoundedRegularInput(allocator, io, input_path, limit) catch {
        try std.Io.File.stderr().writeStreamingAll(
            io,
            try std.fmt.allocPrint(
                allocator,
                "security-audit: check input must be a regular file of at most {d} MiB\n",
                .{limit / (1024 * 1024)},
            ),
        );
        return 2;
    };

    var failures = Failures.init(allocator);
    defer failures.deinit();

    if (std.mem.eql(u8, kind, "native-only-candidate")) {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid native-only candidate fixture\n");
            return 2;
        };
        defer parsed.deinit();
        if (parsed.value != .object or parsed.value.object.count() != 1) {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid native-only candidate fixture\n");
            return 2;
        }
        const overrides_val = parsed.value.object.get("overrides") orelse {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid native-only candidate fixture\n");
            return 2;
        };
        if (overrides_val != .object) {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid native-only candidate fixture\n");
            return 2;
        }
        var overrides = std.StringHashMap(?[]const u8).init(allocator);
        var oit = overrides_val.object.iterator();
        while (oit.next()) |kv| {
            switch (kv.value_ptr.*) {
                .null => try overrides.put(kv.key_ptr.*, null),
                .string => |s| try overrides.put(kv.key_ptr.*, s),
                else => {
                    try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid native-only candidate fixture\n");
                    return 2;
                },
            }
        }
        try candidateFailures(allocator, io, root_dir, &overrides, &failures);
    } else {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid Actions native-only candidate fixture\n");
            return 2;
        };
        defer parsed.deinit();
        if (parsed.value != .object or parsed.value.object.count() != 2) {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid Actions native-only candidate fixture\n");
            return 2;
        }
        const action_val = parsed.value.object.get("action") orelse {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid Actions native-only candidate fixture\n");
            return 2;
        };
        const overrides_val = parsed.value.object.get("overrides") orelse {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid Actions native-only candidate fixture\n");
            return 2;
        };
        if (action_val != .string or overrides_val != .object) {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid Actions native-only candidate fixture\n");
            return 2;
        }
        const action = action_val.string;
        if (!std.mem.eql(u8, action, "download") and !std.mem.eql(u8, action, "install")) {
            try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid Actions native-only candidate fixture\n");
            return 2;
        }
        const subpaths: []const []const u8 = if (std.mem.eql(u8, action, "install"))
            &.{ "action.yml", "src/inputs.ts", "src/action.ts", "src/runner.ts", "dist/index.js", "src/subprocess.ts" }
        else
            &.{ "action.yml", "src/inputs.ts", "src/action.ts", "src/runner.ts", "dist/index.js" };

        var allowed = std.StringHashMap(void).init(allocator);
        for (subpaths) |sub| {
            try allowed.put(try std.fmt.allocPrint(allocator, "actions/{s}/{s}", .{ action, sub }), {});
        }
        var oit = overrides_val.object.iterator();
        while (oit.next()) |kv| {
            if (!allowed.contains(kv.key_ptr.*) or kv.value_ptr.* != .string) {
                try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid Actions native-only candidate fixture\n");
                return 2;
            }
        }
        var texts = std.StringHashMap([]const u8).init(allocator);
        var ait = allowed.keyIterator();
        while (ait.next()) |path_ptr| {
            const path = path_ptr.*;
            if (overrides_val.object.get(path)) |ov| {
                try texts.put(path, ov.string);
            } else {
                const file_bytes = root_dir.readFileAlloc(io, path, allocator, .limited(maximum_source_bytes)) catch {
                    try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid Actions native-only candidate fixture\n");
                    return 2;
                };
                if (!std.unicode.utf8ValidateSlice(file_bytes)) {
                    try std.Io.File.stderr().writeStreamingAll(io, "security-audit: invalid Actions native-only candidate fixture\n");
                    return 2;
                }
                try texts.put(path, file_bytes);
            }
        }
        try actionsNativeOnlyCandidateFailures(&failures, action, &texts);
    }

    for (failures.items()) |failure| {
        try std.Io.File.stderr().writeStreamingAll(
            io,
            try std.fmt.allocPrint(allocator, "security-audit: {s}\n", .{failure}),
        );
    }
    return if (failures.items().len != 0) 1 else 0;
}

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    var root_path: []const u8 = ".";
    var positional: std.ArrayList([]const u8) = .empty;

    var i: usize = 1;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try std.Io.File.stdout().writeStreamingAll(
                init.io,
                "usage: debz-native-only-candidate [--root DIR] [native-only-candidate | check <native-only-candidate|actions-native-only> <PATH>]\n",
            );
            return 0;
        } else if (std.mem.eql(u8, arg, "--root")) {
            if (i + 1 >= args.len) {
                try std.Io.File.stderr().writeStreamingAll(init.io, "security-audit: --root requires a value\n");
                return 2;
            }
            root_path = args[i + 1];
            i += 2;
        } else {
            try positional.append(allocator, arg);
            i += 1;
        }
    }

    var root_dir = try std.Io.Dir.cwd().openDir(init.io, root_path, .{});
    defer root_dir.close(init.io);

    if (positional.items.len == 0 or
        (positional.items.len == 1 and std.mem.eql(u8, positional.items[0], "native-only-candidate")))
    {
        var overrides = std.StringHashMap(?[]const u8).init(allocator);
        var failures = Failures.init(allocator);
        defer failures.deinit();
        try candidateFailures(allocator, init.io, root_dir, &overrides, &failures);
        for (failures.items()) |failure| {
            try std.Io.File.stderr().writeStreamingAll(
                init.io,
                try std.fmt.allocPrint(allocator, "security-audit: {s}\n", .{failure}),
            );
        }
        if (failures.items().len != 0) return 1;
        try std.Io.File.stdout().writeStreamingAll(init.io, "security-audit: native-only candidate passed\n");
        return 0;
    }

    if (positional.items.len == 3 and std.mem.eql(u8, positional.items[0], "check")) {
        return runCheckCommand(allocator, init.io, root_dir, positional.items[1], positional.items[2]);
    }

    try std.Io.File.stderr().writeStreamingAll(init.io, "security-audit: invalid arguments\n");
    return 2;
}

fn hasFailureContaining(failures: *const Failures, needle: []const u8) bool {
    for (failures.items()) |msg| {
        if (std.mem.indexOf(u8, msg, needle) != null) return true;
    }
    return false;
}

test "launchSites detects direct and indirect Zig and TypeScript child-process launches" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const zig_src =
        \\const std = @import("std");
        \\pub fn run() void {
        \\    // std.process.run(commented);
        \\    _ = std.process.run(a, b, c);
        \\    _ = linux.fork();
        \\    _ = std.os.linux.syscall5(.execveat, fd, path, argv, envp, flags);
        \\    _ = @field(linux, "execveat")(fd, path, argv, envp, flags);
        \\}
        \\test "ignored test block" {
        \\    _ = std.process.run(a, b, c);
        \\}
    ;
    const zig_sites = try launchSites(alloc, "src/example.zig", zig_src);
    try testing.expectEqual(@as(?usize, 1), zig_sites.get("std.process.run"));
    try testing.expectEqual(@as(?usize, 1), zig_sites.get("linux.fork"));
    try testing.expectEqual(@as(?usize, 1), zig_sites.get("syscall.execveat"));
    try testing.expectEqual(@as(?usize, 1), zig_sites.get("@field"));

    const ts_src =
        \\// spawn(commented)
        \\export function run() {
        \\  spawn('debz', []);
        \\  execFileAsync('debz', []);
        \\}
    ;
    const ts_sites = try launchSites(alloc, "actions/install/src/example.ts", ts_src);
    try testing.expectEqual(@as(?usize, 1), ts_sites.get("spawn"));
    try testing.expectEqual(@as(?usize, 1), ts_sites.get("execFileAsync"));
}

test "candidateFailures and CLI refuse shipped legacy routes without host interpreters" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var root_dir = try std.Io.Dir.cwd().openDir(testing.io, ".", .{});
    defer root_dir.close(testing.io);

    var overrides = std.StringHashMap(?[]const u8).init(alloc);
    var failures = Failures.init(alloc);
    try candidateFailures(alloc, testing.io, root_dir, &overrides, &failures);

    for ([_][]const u8{
        "src/main.zig: candidate cutover task: remove CLI legacy selection/default",
        "src/cli_backend_policy.zig: candidate cutover task: remove new-execution CLI legacy fallback",
        "build.zig: candidate cutover task: change CLI shipped native-only mode",
        "src/target_apt_config.zig: legacy production dpkg/dpkg-deb command adapter remains",
        "src/transaction_executor.zig: active legacy journal recovery still launches dpkg",
        "download dist/index.js: checked-in bundle is stale or accepts legacy",
        "install dist/index.js: checked-in bundle is stale or accepts legacy",
    }) |expected| {
        try testing.expect(hasFailureContaining(&failures, expected));
    }
    try testing.expect(!hasFailureContaining(
        &failures,
        "src/transaction_executor.zig: legacy production dpkg/dpkg-deb command adapter remains",
    ));
    try testing.expect(!hasFailureContaining(
        &failures,
        "src/transaction_executor.zig: candidate cutover task: remove legacy dpkg/dpkg-deb executor (#281)",
    ));
    try testing.expect(!hasFailureContaining(
        &failures,
        "src/transaction_engine.zig: candidate cutover task: remove legacy executor selection (#281)",
    ));

    const options = @import("native_only_candidate_options");
    var env = std.process.Environ.Map.init(alloc);
    try env.put("PATH", "/no-host-interpreters");
    const res = try std.process.run(alloc, testing.io, .{
        .argv = &.{ options.executable, "native-only-candidate" },
        .environ_map = &env,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    try testing.expect(res.term == .exited and res.term.exited == 1);
    try testing.expect(std.mem.indexOf(u8, res.stderr, "security-audit: src/main.zig: candidate cutover task:") != null);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_len = try tmp.dir.realPath(testing.io, &path_buf);
    const tmp_root = try alloc.dupe(u8, path_buf[0..tmp_len]);

    const actions_input_path = try std.fmt.allocPrint(alloc, "{s}/actions-input.json", .{tmp_root});
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "actions-input.json",
        .data = "{\"action\":\"download\",\"overrides\":{}}",
    });
    const actions_res = try std.process.run(alloc, testing.io, .{
        .argv = &.{ options.executable, "check", "actions-native-only", actions_input_path },
        .environ_map = &env,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    try testing.expect(actions_res.term == .exited and actions_res.term.exited == 1);
    try testing.expect(std.mem.indexOf(u8, actions_res.stderr, "download action.yml: candidate transaction-backend default must be native") != null);

    const candidate_input_path = try std.fmt.allocPrint(alloc, "{s}/candidate-input.json", .{tmp_root});
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "candidate-input.json",
        .data = "{\"overrides\":{\"tools/unreviewed-dpkg-oracle.py\":\"dpkg-query\"}}",
    });
    const candidate_res = try std.process.run(alloc, testing.io, .{
        .argv = &.{ options.executable, "check", "native-only-candidate", candidate_input_path },
        .environ_map = &env,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    try testing.expect(candidate_res.term == .exited and candidate_res.term.exited == 1);
    try testing.expect(std.mem.indexOf(u8, candidate_res.stderr, "candidate fixture has unknown override path: tools/unreviewed-dpkg-oracle.py") != null);
}

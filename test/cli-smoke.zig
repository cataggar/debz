const std = @import("std");
const testing = std.testing;
const support = @import("tooling-test-support.zig");
const options = @import("cli_smoke_options");

const Fixture = struct {
    work: support.Work,
    arena: std.heap.ArenaAllocator,
    environment: std.process.Environ.Map,
    executable: []const u8,
    root: []const u8,
    cache: []const u8,
    state: []const u8,
    status: []const u8,

    fn init() !Fixture {
        var work = try support.Work.init();
        errdefer work.deinit();
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        errdefer arena.deinit();
        const allocator = arena.allocator();
        var environment = std.process.Environ.Map.init(testing.allocator);
        errdefer environment.deinit();
        try environment.put("PATH", "/no-host-interpreters");
        try environment.put("HOME", work.root);
        try environment.put("XDG_CACHE_HOME", work.root);
        try environment.put("LC_ALL", "C");
        try work.directory.dir.createDirPath(support.io, "root/var/lib/dpkg");
        try work.directory.dir.createDirPath(support.io, "state");
        const executable = try std.Io.Dir.cwd().realPathFileAlloc(support.io, options.debz, allocator);
        const root = try std.fs.path.join(allocator, &.{ work.root, "root" });
        const cache = try std.fs.path.join(allocator, &.{ work.root, "cache" });
        const state = try std.fs.path.join(allocator, &.{ work.root, "state" });
        const status = try std.Io.Dir.cwd().realPathFileAlloc(support.io, "src/fixtures/dpkg-status/installed.status", allocator);
        return .{
            .work = work,
            .arena = arena,
            .environment = environment,
            .executable = executable,
            .root = root,
            .cache = cache,
            .state = state,
            .status = status,
        };
    }

    fn deinit(self: *Fixture) void {
        self.environment.deinit();
        self.arena.deinit();
        self.work.deinit();
    }

    fn run(self: *Fixture, arguments: []const []const u8, seconds: u32) !support.Result {
        const allocator = self.arena.allocator();
        const argv = try allocator.alloc([]const u8, arguments.len + 1);
        argv[0] = self.executable;
        @memcpy(argv[1..], arguments);
        const result = try std.process.run(testing.allocator, support.io, .{
            .argv = argv,
            .cwd = .{ .path = self.work.root },
            .environ_map = &self.environment,
            .stdout_limit = .limited(256 * 1024),
            .stderr_limit = .limited(256 * 1024),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(seconds), .clock = .awake } },
        });
        return .{
            .code = switch (result.term) {
                .exited => |code| code,
                else => {
                    testing.allocator.free(result.stdout);
                    testing.allocator.free(result.stderr);
                    return error.CliSmokeAbnormalTermination;
                },
            },
            .stdout = result.stdout,
            .stderr = result.stderr,
        };
    }

    fn words(self: *Fixture, arguments: []const u8) !support.Result {
        var argv: std.ArrayList([]const u8) = .empty;
        const allocator = self.arena.allocator();
        var tokens = std.mem.tokenizeScalar(u8, arguments, ' ');
        while (tokens.next()) |token| {
            if (std.mem.eql(u8, token, "$common") or std.mem.eql(u8, token, "$read_common")) {
                try argv.appendSlice(allocator, &.{
                    "--install-root", self.root,  "--cache-path",   self.cache,
                    "--state-path",   self.state, "--architecture", "amd64",
                    "--json",
                });
                if (std.mem.eql(u8, token, "$read_common"))
                    try argv.appendSlice(allocator, &.{ "--status-path", self.status });
            } else {
                const argument = if (std.mem.eql(u8, token, "$root")) self.root else if (std.mem.eql(u8, token, "$cache")) self.cache else if (std.mem.eql(u8, token, "$state")) self.state else if (std.mem.eql(u8, token, "$status")) self.status else token;
                try argv.append(allocator, argument);
            }
        }
        return self.run(argv.items, 30);
    }

    fn check(self: *Fixture, arguments: []const u8, code: u8, stdout: ?[]const u8, stderr: ?[]const u8) !support.Result {
        const result = try self.words(arguments);
        errdefer result.deinit();
        if (result.code != code) {
            std.debug.print("CLI smoke '{s}': expected {d}, got {d}\nstdout: {s}\nstderr: {s}\n", .{
                arguments, code, result.code, result.stdout, result.stderr,
            });
            return error.UnexpectedCliSmokeStatus;
        }
        if (stdout) |text| try support.contains(result.stdout, text);
        if (stderr) |text| try support.contains(result.stderr, text);
        return result;
    }
};

fn empty(bytes: []const u8) !void {
    try testing.expectEqual(@as(usize, 0), bytes.len);
}

fn absent(bytes: []const u8, text: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, bytes, text) == null);
}

fn document(fixture: *Fixture, bytes: []const u8) !std.json.Value {
    return (try std.json.parseFromSlice(std.json.Value, fixture.arena.allocator(), bytes, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
    })).value;
}

fn stringField(value: std.json.Value, name: []const u8, expected: []const u8) !void {
    const field = value.object.get(name) orelse return error.MissingCapabilityField;
    try testing.expectEqualStrings(expected, field.string);
}

fn integerField(value: std.json.Value, name: []const u8, expected: i64) !void {
    const field = value.object.get(name) orelse return error.MissingCapabilityField;
    try testing.expectEqual(expected, field.integer);
}

fn booleanField(value: std.json.Value, name: []const u8, expected: bool) !void {
    const field = value.object.get(name) orelse return error.MissingCapabilityField;
    try testing.expectEqual(expected, field.bool);
}

fn oneLine(bytes: []const u8) !void {
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, bytes, "\n"));
    try testing.expect(std.mem.endsWith(u8, bytes, "\n"));
}

test "CLI smoke help version and package-family capability contracts" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{ "-h", "--help" }) |arguments| {
        const result = try f.check(arguments, 0, "debz <command> [options] [packages...]", null);
        defer result.deinit();
        try empty(result.stderr);
    }
    const version = try f.check("version", 0, null, null);
    defer version.deinit();
    try testing.expectEqualStrings(options.version, std.mem.trimEnd(u8, version.stdout, "\n"));

    const original = try f.check("package-family-capabilities", 0, null, null);
    defer original.deinit();
    const legacy = try f.check("package-family-capabilities --transaction-backend legacy_dpkg", 0, null, null);
    defer legacy.deinit();
    try testing.expectEqualSlices(u8, original.stdout, legacy.stdout);
    const legacy_value = try document(&f, original.stdout);
    try integerField(legacy_value, "version", 1);
    try testing.expect(std.mem.endsWith(u8, legacy_value.object.get("exact_lock_schema").?.string, "exact-closure-lock-v1"));

    const native = try f.check("package-family-capabilities --transaction-backend native", 0, null, null);
    defer native.deinit();
    try empty(native.stderr);
    const value = try document(&f, native.stdout);
    try integerField(value, "version", 2);
    try stringField(value, "transaction_backend", "native");
    const operations = value.object.get("operations").?.array.items;
    const expected = [_][]const u8{ "resolve-lock", "create", "customize", "update", "recover", "inspect" };
    try testing.expectEqual(expected.len, operations.len);
    for (operations, expected) |operation, name| try testing.expectEqualStrings(name, operation.string);
    try testing.expect(std.mem.endsWith(u8, value.object.get("exact_lock_schema").?.string, "exact-closure-lock-v3"));
    try testing.expect(std.mem.endsWith(u8, value.object.get("provenance_schema").?.string, "native-transaction-provenance-v2"));
    try stringField(value, "recovery", "disposable_or_recoverable");
    try booleanField(value, "invokes_apt", false);
    try booleanField(value, "invokes_dpkg", false);
    for ([_][]const u8{
        "package-family-capabilities --transaction-backend",
        "package-family-capabilities --transaction-backend invalid",
        "package-family-capabilities --transaction-backend native --transaction-backend legacy_dpkg",
        "package-family-capabilities --unknown",
        "package-family-capabilities native",
    }) |arguments| {
        const result = try f.check(arguments, 2, null, "invalid package-family capability options");
        defer result.deinit();
        try empty(result.stdout);
    }
    const help = try f.check("package-family-capabilities --transaction-backend invalid --help", 0, "--transaction-backend legacy_dpkg|native", null);
    defer help.deinit();
    try empty(help.stderr);
}

test "CLI smoke apt and recovery help is decisive private and bounded across 8000 ignored operands" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{
        "apt",                                     "apt --help",                       "apt update --help ignored-secret",
        "apt install --bad --help ignored-secret", "apt remove --help ignored-secret", "apt upgrade --help ignored-secret",
        "apt list --help ignored-secret",
    }) |arguments| {
        const result = try f.check(arguments, 0, "debz apt", null);
        defer result.deinit();
        try empty(result.stderr);
        try absent(result.stdout, "ignored-secret");
    }
    const dangerous = "--credential=decisive-help-secret";
    for ([_]struct { argv: []const []const u8, usage: []const u8 }{
        .{ .argv = &.{ "apt", "update", "--help", dangerous }, .usage = "debz apt update" },
        .{ .argv = &.{ "recover", "--system-profile", "/profile.json", "--help", dangerous }, .usage = "debz recover --system-profile PATH" },
    }) |case| {
        const argv = try f.arena.allocator().alloc([]const u8, case.argv.len + 8000);
        @memcpy(argv[0..case.argv.len], case.argv);
        @memset(argv[case.argv.len..], "ignored");
        const result = try f.run(argv, 5);
        defer result.deinit();
        try result.ok();
        try support.contains(result.stdout, case.usage);
        try absent(result.stdout, dangerous);
        try empty(result.stderr);
    }
    const recovery = try f.check("recover --system-profile /missing-profile.json --help ignored-secret", 0, "apt-system operation", null);
    defer recovery.deinit();
    try empty(recovery.stderr);
    try absent(recovery.stdout, "ignored-secret");
}

test "CLI smoke apt and profile errors preserve JSON status privacy and output channels" {
    var f = try Fixture.init();
    defer f.deinit();
    const extra = try f.check("apt --json update extra", 2, "apt-system-cli-diagnostic.v1", null);
    defer extra.deinit();
    try empty(extra.stderr);
    try oneLine(extra.stdout);
    for ([_][]const u8{
        "apt update --json",                                 "apt --profile --json update",
        "apt --misplaced-json-control-secret --json update", "recover --system-profile --json",
    }) |arguments| {
        const result = try f.check(arguments, 2, null, "usage error");
        defer result.deinit();
        try empty(result.stdout);
        try absent(result.stderr, "misplaced-json-control-secret");
    }
    for ([_][]const u8{
        "apt --profile /missing-profile.json --json install --rejected-cli-secret",
        "apt --profile /missing-profile.json --json list --available",
        "apt --profile /missing-profile.json --json upgrade extra",
        "apt --profile /missing-profile.json --json update --json",
    }) |arguments| {
        const result = try f.check(arguments, 2, "apt-system-cli-diagnostic.v1", null);
        defer result.deinit();
        try empty(result.stderr);
        try oneLine(result.stdout);
        try absent(result.stdout, "rejected-cli-secret");
    }
    for ([_][]const u8{
        "apt --profile /missing-profile.json --json update",
        "apt --json --profile /missing-profile.json install -y alpha beta",
        "apt --profile /missing-profile.json --json remove -y alpha beta",
        "apt --profile /missing-profile.json --json upgrade -y",
        "apt --profile /missing-profile.json --json list --installed",
    }) |arguments| {
        const result = try f.check(arguments, 3, "apt-system-result-v", null);
        defer result.deinit();
        try empty(result.stderr);
        try oneLine(result.stdout);
        try support.contains(result.stdout, "\"id\":\"profile_invalid\"");
    }
    const relative = try f.check("recover --json --system-profile relative", 2, "invalid_profile_path", null);
    defer relative.deinit();
    try empty(relative.stderr);
    try oneLine(relative.stdout);
}

test "CLI smoke removed commands and transaction-result capability exact JSON contracts" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_]struct { arguments: []const u8, code: u8 = 2, diagnostic: []const u8 }{
        .{ .arguments = "--version", .diagnostic = "unknown command '--version'" },
        .{ .arguments = "repo", .diagnostic = "missing command for 'debz repo'" },
        .{ .arguments = "repo unknown", .diagnostic = "unknown repository command 'unknown'" },
        .{ .arguments = "package-cache unknown", .diagnostic = "unknown package-cache command 'unknown'" },
        .{ .arguments = "transaction-result verify --state-path relative --lock-input /missing --architecture amd64 --json", .diagnostic = "invalid explicit path or architecture" },
        .{ .arguments = "transaction-result verify --state-path $state --lock-input /missing --architecture amd64 --json", .code = 7, .diagnostic = "transaction result verification failed" },
    }) |case| {
        const result = try f.check(case.arguments, case.code, null, case.diagnostic);
        defer result.deinit();
    }
    const transaction = try f.check("transaction-result capabilities --transaction-backend native --json", 0, null, null);
    defer transaction.deinit();
    try oneLine(transaction.stdout);
    const value = try document(&f, transaction.stdout);
    try stringField(value, "schema", "io.github.cataggar.debz.transaction-result-capability.v1");
    try stringField(value, "backend", "native");
    try stringField(value, "capability", "native-transaction-result-v1");
    try stringField(value, "summary_schema", "io.github.cataggar.debz.transaction-result-summary.v2");
    try integerField(value, "summary_api_version", 2);
    try integerField(value, "lock_schema_version", 3);
    try booleanField(value, "read_only", true);
    const install = try f.check("transaction-result capabilities --transaction-backend native --for-install --json", 0, null, null);
    defer install.deinit();
    const install_value = try document(&f, install.stdout);
    const canonical = try std.json.Stringify.valueAlloc(f.arena.allocator(), install_value, .{});
    try testing.expectEqualStrings(try std.fmt.allocPrint(f.arena.allocator(), "{s}\n", .{canonical}), install.stdout);
    try stringField(install_value, "schema", "io.github.cataggar.debz.native-install-capability.v1");
    try stringField(install_value, "capability", "native-install-v1");
    try stringField(install_value, "result_schema", "io.github.cataggar.debz.native-install-result.v1");
    try booleanField(install_value, "receipt_binding", true);
    try booleanField(install_value, "unchanged_without_receipt", true);
    for ([_][]const u8{
        "transaction-result capabilities --json",
        "transaction-result capabilities --for-install --json",
        "transaction-result capabilities --transaction-backend native --for-install --for-install --json",
        "transaction-result verify --transaction-backend native --for-install --json",
        "transaction-result capabilities --transaction-backend native --install-root /unused --json",
        "transaction-result verify --transaction-backend other --json",
        "transaction-result verify --transaction-backend native --transaction-backend native --json",
        "transaction-result verify --transaction-backend native --state-path $state --lock-input /missing --architecture amd64 --json",
        "transaction-result verify --transaction-backend native --lock-input /missing --architecture amd64 --json",
        "transaction-result verify --transaction-backend native --install-root relative --lock-input /missing --architecture amd64 --json",
        "transaction-result verify --install-root /unused --lock-input /missing --architecture amd64 --json",
    }) |arguments| {
        const result = try f.check(arguments, 2, null, null);
        defer result.deinit();
        try empty(result.stdout);
    }
}

test "CLI smoke native-result cache and repository input refusals happen before work" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{
        "install --json --native-result",
        "install --json --transaction-backend native --native-result",
        "install --json --transaction-backend native --native-result --native-result --lock-input /missing",
        "plan --json --transaction-backend native --native-result --lock-input /missing",
        "install --json --transaction-backend legacy_dpkg --native-result --lock-input /missing",
    }) |arguments| {
        const result = try f.check(arguments, 2, "\"id\":\"invalid_request\"", null);
        defer result.deinit();
    }
    for ([_][]const u8{
        "package-cache fingerprint --json --lock-input relative --cache-path $cache --architecture amd64",
        "package-cache fingerprint --json --lock-input /missing --cache-path $cache --architecture amd64 --offline",
        "package-cache fingerprint --json --lock-input /missing --cache-path $cache --architecture amd64 --archive-input /archive",
        "package-cache fingerprint --json --transaction-backend other --lock-input /missing --cache-path $cache --architecture amd64",
        "package-cache fingerprint --json --transaction-backend native --transaction-backend native --lock-input /missing --cache-path $cache --architecture amd64",
        "package-cache prepare --json --transaction-backend native --transaction-backend legacy_dpkg --lock-input /missing --cache-path $cache --architecture amd64",
        "package-cache prepare --json --lock-input /missing --cache-path $cache --architecture amd64 --repair-corrupt-cache --offline",
        "package-cache prepare --json --lock-input /missing --cache-path $cache --architecture amd64 --restored-cache exact",
        "package-cache prepare --json --lock-input /missing --cache-path $cache --architecture amd64",
    }) |arguments| {
        const result = try f.check(arguments, 2, "\"schema\":\"io.github.cataggar.debz.package-cache-error.v1\"", null);
        defer result.deinit();
        try empty(result.stderr);
        try support.contains(result.stdout, "\"id\":\"invalid_request\"");
    }
    for ([_][]const u8{
        "repo add --json",
        "repo add --json --url https://one.invalid/config.deb --url https://two.invalid/config.deb",
        "repo add --json --url https://packages.invalid/config.deb --sha256 malformed",
        "repo add --json --url https://packages.invalid/config.deb --redirect-limit 65536",
        "repo add --json --url https://packages.invalid/config.deb --transaction-backend other",
        "repo add --json --url https://packages.invalid/config.deb --transaction-backend",
        "repo add --json --url https://packages.invalid/config.deb --transaction-backend native --transaction-backend legacy_dpkg",
        "repo add --json --url https://packages.invalid/config.deb --deadline-ms 0",
        "repo add --json --url https://packages.invalid/config.deb --root relative",
        "repo add --json --url https://packages.invalid/config.deb -- --operand",
        "repo add --json --url https://packages.invalid/config.deb --refresh",
        "repo add --json --url https://packages.invalid/config.deb --install-root /",
        "repo add --json --url https://packages.invalid/config.deb --import-target-apt-config",
        "repo add --json --url https://packages.invalid/config.deb --allow-host-root",
        "repo add --json --url https://packages.invalid/config.deb --assume-yes",
    }) |arguments| {
        const result = try f.check(arguments, 2, "\"operation\":\"add\"", null);
        defer result.deinit();
        try empty(result.stderr);
        try support.contains(result.stdout, "\"exit_status\":2");
        try testing.expect(std.mem.indexOf(u8, result.stdout, "\"id\":\"invalid_request\"") != null or
            std.mem.indexOf(u8, result.stdout, "\"id\":\"invalid_digest\"") != null or
            std.mem.indexOf(u8, result.stdout, "\"id\":\"invalid_root\"") != null);
    }
    const credential_arguments = try std.fmt.allocPrint(f.arena.allocator(), "repo add --json --url {s}://{s}/config.deb?token={s}", .{
        "https", "user:credential@packages.invalid", "fixture-query-secret",
    });
    const credentials = try f.check(credential_arguments, 2, "\"id\":\"credential_bearing_url\"", null);
    defer credentials.deinit();
    try empty(credentials.stderr);
    try absent(credentials.stdout, "fixture-query-secret");
    try absent(credentials.stdout, "user:credential");
    const relative = try f.check("repo add --url https://packages.invalid/config.deb --root relative", 2, null, "repo add: root must be a canonical absolute path");
    defer relative.deinit();
    try empty(relative.stdout);
    try support.contains(relative.stderr, "debz[invalid_root] (request): root must be a canonical absolute path");
}

test "CLI smoke explicit-root queries native configuration recovery and confirmation contracts" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_]struct { arguments: []const u8, operation: []const u8 }{
        .{ .arguments = "list-installed $read_common", .operation = "\"operation\":\"list-installed\"" },
        .{ .arguments = "why $read_common debz", .operation = "\"operation\":\"why\"" },
    }) |case| {
        const result = try f.check(case.arguments, 0, case.operation, null);
        defer result.deinit();
        try empty(result.stderr);
        try support.contains(result.stdout, "\"exit_status\":0");
        if (std.mem.startsWith(u8, case.arguments, "list-installed"))
            try support.contains(result.stdout, "\"package\":\"debz\"");
    }
    for ([_][]const u8{
        "plan $common --transaction-backend native demo",
        "download $common --transaction-backend native demo",
        "install demo $common --transaction-backend native --assume-yes --conffile keep-existing",
        "remove demo $common --transaction-backend native --assume-yes --conffile keep-existing",
        "reinstall demo $common --transaction-backend native --assume-yes --conffile keep-existing",
        "upgrade demo $common --transaction-backend native --assume-yes --conffile keep-existing",
        "upgrade-all $common --transaction-backend native --assume-yes --conffile keep-existing",
    }) |arguments| {
        const result = try f.check(arguments, 2, "\"id\":\"configuration_required\"", null);
        defer result.deinit();
        try empty(result.stderr);
    }
    const recovery = try f.check("recover $common --transaction-backend native --assume-yes --conffile keep-existing", 0, "\"exit_status\":0", null);
    defer recovery.deinit();
    try empty(recovery.stderr);
    try support.contains(recovery.stdout, "\"changed\":false");
    try testing.expectError(error.FileNotFound, f.work.directory.dir.access(support.io, "root/var/lib/debz/root-operation-v1.json", .{}));
    for ([_][]const u8{
        "plan --json demo --transaction-backend unknown $common",
        "plan --json demo --transaction-backend native --transaction-backend legacy_dpkg $common",
        "plan --json demo --transaction-backend $common",
        "list-installed --json --transaction-backend native $common",
    }) |arguments| {
        const result = try f.check(arguments, 2, "\"id\":\"invalid_request\"", null);
        defer result.deinit();
        try empty(result.stderr);
    }
    for ([_][]const u8{ "refresh $common --assume-yes", "list-available $common" }) |arguments| {
        const result = try f.check(arguments, 2, "\"id\":\"configuration_required\"", null);
        defer result.deinit();
        try empty(result.stderr);
        try absent(result.stdout, "\"exit_status\":3");
    }
    const confirmation = try f.check("install $common demo", 2, "\"id\":\"confirmation_required\"", null);
    defer confirmation.deinit();
    try empty(confirmation.stderr);
    const clean = try f.check("clean $common --assume-yes", 0, "\"operation\":\"clean\"", null);
    defer clean.deinit();
    try empty(clean.stderr);
    try support.contains(clean.stdout, "\"exit_status\":0");
    for ([_][]const u8{
        "list-installed --json --install-root $root --install-root $root --cache-path $cache --state-path $state --architecture amd64",
        "install --json --install-root $root --cache-path $cache --state-path $state --architecture amd64 --assume-yes one two",
        "clean --json --install-root $root --cache-path $cache --state-path $state --status-path $status --architecture amd64 --assume-yes",
        "clean --json --install-root / --cache-path / --state-path / --architecture amd64 --assume-yes",
    }) |arguments| {
        const result = try f.check(arguments, 2, "\"id\":\"invalid_request\"", null);
        defer result.deinit();
        try empty(result.stderr);
        try support.contains(result.stdout, "\"exit_status\":2");
    }
}

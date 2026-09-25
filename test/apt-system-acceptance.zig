const std = @import("std");
const linux = std.os.linux;
const File = std.Io.File;
const schema_validator = @import("apt-system-schema-validator.zig");

const max_file = schema_validator.max_document_bytes;
const max_output = schema_validator.max_document_bytes;
const diagnostics = [_][]const u8{
    "transaction.journal",
    "root-operation-v1.json",
    "root-operation-completion-v1.json",
    "root-operation-completion-v2.json",
    "root-operation-deferred-ack-v1.json",
    "native-transaction-provenance-v1.json",
    "native-transaction-provenance-v2.json",
    "apt/active-operation-v1.json",
};
const Backend = enum { legacy_dpkg, native };

extern "c" fn openpty(*c_int, *c_int, ?[*]u8, ?*anyopaque, ?*anyopaque) c_int;
extern "c" fn getcwd([*]u8, usize) ?[*]u8;
extern "c" fn poll([*]PollFd, c_ulong, c_int) c_int;
extern "c" fn read(c_int, [*]u8, usize) isize;
extern "c" fn write(c_int, [*]const u8, usize) isize;
extern "c" fn close(c_int) c_int;
extern "c" fn clock_gettime(c_int, *Timespec) c_int;
const PollFd = extern struct { fd: c_int, events: c_short, revents: c_short };
const Timespec = extern struct { tv_sec: isize, tv_nsec: isize };

const Runner = struct {
    arena: std.mem.Allocator,
    io: std.Io,
    cwd: []const u8,
    root: []const u8 = "",
    backend: Backend = .legacy_dpkg,
    mountinfo: []const u8 = "",
    schema_store: ?schema_validator.Store = null,
    output_limit: usize = max_output,

    fn path(self: *Runner, suffix: []const u8) ![]const u8 {
        try check(self.root.len > 1 and self.root[0] == '/', "disposable root missing");
        try check(suffix.len != 0 and suffix[0] == '/' and std.mem.indexOf(u8, suffix, "..") == null and
            std.mem.indexOfScalar(u8, suffix, '\\') == null, "unsafe fixture path");
        return std.fmt.allocPrint(self.arena, "{s}{s}", .{ self.root, suffix });
    }

    fn readFile(self: *Runner, name: []const u8) ![]const u8 {
        return std.Io.Dir.cwd().readFileAlloc(self.io, name, self.arena, .limited(max_file));
    }

    fn readRoot(self: *Runner, name: []const u8) ![]const u8 {
        return self.readFile(try self.path(name));
    }

    fn writeRoot(self: *Runner, name: []const u8, bytes: []const u8) !void {
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = try self.path(name), .data = bytes });
    }

    fn exists(self: *Runner, name: []const u8) bool {
        std.Io.Dir.cwd().access(self.io, self.path(name) catch return false, .{}) catch return false;
        return true;
    }

    fn mkDir(self: *Runner, name: []const u8) !void {
        try std.Io.Dir.cwd().createDirPath(self.io, try self.path(name));
    }

    fn run(self: *Runner, argv: []const []const u8, seconds: i64, environment: ?*const std.process.Environ.Map) !std.process.RunResult {
        const result = std.process.run(self.arena, self.io, .{
            .argv = argv,
            .environ_map = environment,
            .stdout_limit = .limited(self.output_limit),
            .stderr_limit = .limited(64 * 1024),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(seconds), .clock = .awake } },
        }) catch |err| {
            if (!@import("builtin").is_test)
                std.log.err("command {s} failed: {s}", .{ argv[0], @errorName(err) });
            return err;
        };
        return result;
    }

    fn command(self: *Runner, argv: []const []const u8, seconds: i64, environment: ?*const std.process.Environ.Map) ![]const u8 {
        const result = try self.run(argv, seconds, environment);
        if (result.term != .exited or result.term.exited != 0) {
            std.log.err("{s} failed: {any}; stdout={s}; stderr={s}", .{
                argv[0], result.term, result.stdout, result.stderr,
            });
            return error.CommandFailed;
        }
        return result.stdout;
    }

    fn isolatedEnv(self: *Runner) !std.process.Environ.Map {
        var env = std.process.Environ.Map.init(self.arena);
        try env.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        try env.put("LANG", "C");
        try env.put("APT_CONFIG", "/etc/apt/apt.conf");
        try env.put("http_proxy", "http://invalid-ambient-proxy.invalid:9");
        try env.put("https_proxy", "http://invalid-ambient-proxy.invalid:9");
        return env;
    }

    fn evidenceOnFailure(self: *Runner) void {
        for (diagnostics) |name| {
            const evidence = std.fmt.allocPrint(self.arena, "/var/lib/debz/{s}", .{name}) catch continue;
            const bytes = self.readRoot(evidence) catch continue;
            std.log.err("{s}: {s}", .{ name, bytes[0..@min(bytes.len, 4096)] });
        }
    }

    fn cli(self: *Runner, expected: u8, args: []const []const u8) !std.json.Value {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(self.arena, &.{ "chroot", self.root, "/usr/bin/debz" });
        try argv.appendSlice(self.arena, args);
        var env = try self.isolatedEnv();
        defer env.deinit();
        const result = self.run(argv.items, 60, &env) catch |err| {
            self.evidenceOnFailure();
            return err;
        };
        const current_mountinfo = try self.readFile("/proc/self/mountinfo");
        try check(std.mem.eql(u8, self.mountinfo, current_mountinfo), "live-root mount changed");
        if (result.term != .exited or result.term.exited != expected or result.stderr.len != 0 or
            std.mem.count(u8, result.stdout, "\n") != 1)
        {
            std.log.err("apt command {any}: expected exit {d}, got {any}; stdout={s}; stderr={s}", .{
                args, expected, result.term, result.stdout, result.stderr,
            });
            self.evidenceOnFailure();
            return error.CliMismatch;
        }
        const parsed = std.json.parseFromSlice(std.json.Value, self.arena, result.stdout, .{
            .allocate = .alloc_always,
            .duplicate_field_behavior = .@"error",
        }) catch |err| {
            std.log.err("invalid JSON from {any}: {s}", .{ args, @errorName(err) });
            return err;
        };
        const identity = text(value(parsed.value, "schema"));
        const schema_name: []const u8 = if (std.mem.eql(u8, identity, "https://debz.dev/schema/apt-system-result-v1"))
            "apt-system-result-v1"
        else if (std.mem.eql(u8, identity, "https://debz.dev/schema/apt-system-result-v2"))
            "apt-system-result-v2"
        else if (std.mem.eql(u8, identity, "https://debz.dev/schema/apt-system-result-v3"))
            "apt-system-result-v3"
        else if (std.mem.eql(u8, identity, "io.github.cataggar.debz.apt-system-cli-diagnostic.v1"))
            "apt-system-cli-diagnostic-v1"
        else if (std.mem.eql(u8, args[0], "transaction-result"))
            ""
        else
            return error.UnexpectedResultSchema;
        if (schema_name.len != 0) {
            const store = if (self.schema_store) |*s| s else return error.SchemaStoreMissing;
            if (!try store.valid(schema_name, result.stdout)) {
                std.log.err("CLI output violates {s}: {s}", .{ schema_name, result.stdout });
                self.evidenceOnFailure();
                return error.InvalidResultSchema;
            }
        }
        if (!std.mem.eql(u8, args[0], "transaction-result"))
            try check(number(value(parsed.value, "exit_status")) == expected, "CLI exit status differs from result");
        return parsed.value;
    }

    fn apt(self: *Runner, expected: u8, args: []const []const u8) !std.json.Value {
        var all: std.ArrayList([]const u8) = .empty;
        try all.append(self.arena, "apt");
        if (self.backend == .native)
            try all.appendSlice(self.arena, &.{ "--profile", "/etc/debz/native-v2.json" });
        try all.append(self.arena, "--json");
        try all.appendSlice(self.arena, args);
        return self.cli(expected, all.items);
    }

    fn confirmRecovery(self: *Runner, expected: u8) !void {
        var master: c_int = undefined;
        var slave: c_int = undefined;
        if (openpty(&master, &slave, null, null, null) != 0) return error.PtyUnavailable;
        defer _ = close(master);
        var slave_open = true;
        defer {
            if (slave_open) _ = close(slave);
        }
        var env = try self.isolatedEnv();
        defer env.deinit();
        const tty = File{ .handle = slave, .flags = .{ .nonblocking = false } };
        var child = try std.process.spawn(self.io, .{
            .argv = &.{ "chroot", self.root, "/usr/bin/debz", "recover", "--system-profile", "/etc/debz/native-v2.json" },
            .environ_map = &env,
            .stdin = .{ .file = tty },
            .stdout = .{ .file = tty },
            .stderr = .{ .file = tty },
        });
        defer child.kill(self.io);
        _ = close(slave);
        slave_open = false;
        var output: std.ArrayList(u8) = .empty;
        const deadline = try currentMs() + 60_000;
        var confirmed = false;
        while (true) {
            const remaining = deadline - try currentMs();
            if (remaining <= 0) return error.RecoveryConfirmationTimeout;
            var descriptor = [1]PollFd{.{ .fd = master, .events = 1, .revents = 0 }};
            const ready = poll(&descriptor, 1, @intCast(@min(remaining, 1000)));
            if (ready < 0) return error.PtyPollFailed;
            if (ready == 0) continue;
            var buffer: [4096]u8 = undefined;
            const length = read(master, &buffer, buffer.len);
            if (length <= 0) break;
            try output.appendSlice(self.arena, buffer[0..@intCast(length)]);
            if (output.items.len > 65536) return error.RecoveryOutputTooLarge;
            if (!confirmed and std.mem.indexOf(u8, output.items, "Proceed with this reviewed recovery action? [y/N]") != null) {
                if (write(master, "y\n", 2) != 2) return error.RecoveryConfirmationFailed;
                confirmed = true;
            }
        }
        const term = try child.wait(self.io);
        if (!confirmed or term != .exited or term.exited != expected) {
            std.log.err("TTY recovery: confirmed={any}, exit={any}, output={s}", .{
                confirmed, term, output.items,
            });
            self.evidenceOnFailure();
            return error.RecoveryConfirmationFailed;
        }
        try check(std.mem.eql(u8, self.mountinfo, try self.readFile("/proc/self/mountinfo")), "TTY recovery changed live mounts");
    }

    fn copyBinary(self: *Runner, source: []const u8, destination: []const u8, depth: usize) !void {
        try check(depth < 16, "fixture interpreter recursion");
        const target = try self.path(destination);
        std.Io.Dir.cwd().access(self.io, target, .{}) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        if (self.exists(destination)) return;
        const parent = std.fs.path.dirname(target) orelse return error.InvalidFixture;
        try std.Io.Dir.cwd().createDirPath(self.io, parent);
        _ = try self.command(&.{ "cp", "-L", "-p", "--", source, target }, 10, null);
        var executable = try std.Io.Dir.openFileAbsolute(self.io, source, .{ .mode = .read_only });
        defer executable.close(self.io);
        var header: [256]u8 = undefined;
        const size = try executable.readPositionalAll(self.io, &header, 0);
        if (size >= 3 and std.mem.startsWith(u8, header[0..size], "#!")) {
            const line = header[2 .. std.mem.indexOfScalar(u8, header[0..size], '\n') orelse size];
            const trimmed = std.mem.trim(u8, line, " \t\r");
            const end = std.mem.indexOfAny(u8, trimmed, " \t") orelse trimmed.len;
            const interpreter = trimmed[0..end];
            try check(interpreter.len != 0 and interpreter[0] == '/', "non-absolute fixture interpreter");
            try self.copyBinary(interpreter, interpreter, depth + 1);
            return;
        }
        const linked = try self.run(&.{ "ldd", source }, 10, null);
        const libs = try std.fmt.allocPrint(self.arena, "{s}\n{s}", .{ linked.stdout, linked.stderr });
        const static = std.mem.indexOf(u8, libs, "not a dynamic executable") != null or
            std.mem.indexOf(u8, libs, "statically linked") != null;
        if (linked.term != .exited or (linked.term.exited != 0 and !static) or
            std.mem.indexOf(u8, libs, "=> not found") != null)
        {
            std.log.err("cannot inspect fixture libraries {s}: {s}", .{ source, libs });
            return error.InvalidFixture;
        }
        if (static) return;
        var lines = std.mem.splitScalar(u8, libs, '\n');
        while (lines.next()) |line| {
            var words = std.mem.tokenizeAny(u8, line, " \t");
            while (words.next()) |word| {
                if (word.len == 0 or word[0] != '/' or std.mem.indexOf(u8, word, "..") != null) continue;
                if (!std.mem.startsWith(u8, word, "/lib") and !std.mem.startsWith(u8, word, "/usr/lib"))
                    return error.InvalidFixture;
                const library = try self.path(word);
                try std.Io.Dir.cwd().createDirPath(self.io, std.fs.path.dirname(library).?);
                _ = try self.command(&.{ "cp", "-L", "--", word, library }, 10, null);
            }
        }
    }

    fn prepareRoot(self: *Runner, binary: []const u8) !void {
        const arch = std.mem.trim(u8, try self.command(&.{ "dpkg", "--print-architecture" }, 10, null), " \r\n");
        try check(std.mem.eql(u8, arch, "amd64") or std.mem.eql(u8, arch, "arm64"), "unsupported fixture architecture");
        for ([_][]const u8{
            "/etc/debz",              "/etc/apt",      "/var/lib/dpkg/info", "/var/lib/dpkg/updates",
            "/var/lib/dpkg/triggers", "/var/lib/debz", "/var/cache/debz",    "/usr/share/debz",
            "/usr/sbin",              "/usr/lib",      "/usr/lib64",         "/proc",
            "/run",                   "/tmp",          "/dev",               "/root",
        }) |directory| try self.mkDir(directory);
        for ([_]struct { []const u8, []const u8 }{
            .{ binary, "/usr/bin/debz" },
            .{ "/usr/bin/dpkg", "/usr/bin/dpkg" },
            .{ "/usr/bin/dpkg-deb", "/usr/bin/dpkg-deb" },
            .{ "/usr/bin/dpkg-split", "/usr/bin/dpkg-split" },
            .{ "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger" },
            .{ "/usr/bin/tar", "/usr/bin/tar" },
            .{ "/bin/sh", "/bin/sh" },
        }) |entry| try self.copyBinary(entry[0], entry[1], 0);
        for ([_][]const u8{ "ldconfig", "start-stop-daemon", "rm", "diff" }) |name| {
            var source: ?[]const u8 = null;
            for ([_][]const u8{ "/usr/sbin", "/sbin", "/usr/bin", "/bin" }) |folder| {
                const candidate = try std.fmt.allocPrint(self.arena, "{s}/{s}", .{ folder, name });
                std.Io.Dir.cwd().access(self.io, candidate, .{}) catch continue;
                source = candidate;
                break;
            }
            try check(source != null, "missing required dpkg fixture helper");
            try self.copyBinary(source.?, try std.fmt.allocPrint(self.arena, "/usr/sbin/{s}", .{name}), 0);
        }
        try std.Io.Dir.cwd().symLink(self.io, "tar", try self.path("/usr/bin/gtar"), .{});
        try self.writeRoot("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n");
        try self.writeRoot("/etc/group", "root:x:0:\n");
        try self.writeRoot("/etc/os-release", "ID=debian\nNAME=\"debz disposable fixture\"\n");
        try self.writeRoot("/var/lib/dpkg/status", "");
        for ([_]struct { []const u8, []const u8 }{
            .{ "null", "3" }, .{ "zero", "5" }, .{ "random", "8" }, .{ "urandom", "9" },
        }) |device| {
            const location = try self.path(try std.fmt.allocPrint(self.arena, "/dev/{s}", .{device[0]}));
            _ = try self.command(&.{ "mknod", "-m", "666", location, "c", "1", device[1] }, 10, null);
        }
        _ = try self.command(&.{ "python3", "tools/generate-integration-repository.py", "--output", try self.path("/repository"), "--suite", "debian-stable", "--architecture", arch }, 120, null);
        try self.writeRoot("/etc/debz/fixture.sources", try std.fmt.allocPrint(self.arena, "Types: deb\nURIs: file:///repository\nSuites: debian-stable\nComponents: main\nArchitectures: {s}\nSigned-By: /repository/fixture-keyring.gpg\n", .{arch}));
        try self.writeRoot("/etc/debz/default.json", try profile(self.arena, arch, .legacy_dpkg, true));
        try self.writeRoot("/etc/apt/sources.list", "invalid ambient apt source\n");
        try self.writeRoot("/etc/apt/apt.conf", "invalid ambient apt configuration\n");
    }
};

fn check(condition: bool, context: []const u8) !void {
    if (!condition) {
        if (!@import("builtin").is_test)
            std.log.err("apt acceptance assertion failed: {s}", .{context});
        return error.AcceptanceMismatch;
    }
}

fn value(object: std.json.Value, name: []const u8) std.json.Value {
    return if (object == .object) object.object.get(name) orelse .null else .null;
}
fn text(v: std.json.Value) []const u8 {
    return if (v == .string) v.string else "";
}
fn number(v: std.json.Value) i64 {
    return if (v == .integer) v.integer else -1;
}
fn boolean(v: std.json.Value) bool {
    return v == .bool and v.bool;
}
fn eq(v: std.json.Value, expected: []const u8) bool {
    return std.mem.eql(u8, text(v), expected);
}
fn equalValue(a: std.json.Value, b: std.json.Value) bool {
    if (a != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => a.bool == b.bool,
        .integer => a.integer == b.integer,
        .string => std.mem.eql(u8, a.string, b.string),
        .array => blk: {
            if (a.array.items.len != b.array.items.len) break :blk false;
            for (a.array.items, b.array.items) |left, right| if (!equalValue(left, right)) break :blk false;
            break :blk true;
        },
        .object => blk: {
            if (a.object.count() != b.object.count()) break :blk false;
            var it = a.object.iterator();
            while (it.next()) |entry| {
                if (!equalValue(entry.value_ptr.*, b.object.get(entry.key_ptr.*) orelse break :blk false))
                    break :blk false;
            }
            break :blk true;
        },
        else => false,
    };
}
fn profile(arena: std.mem.Allocator, arch: []const u8, backend: Backend, v1: bool) ![]const u8 {
    const schema = if (v1) "system-profile-v1" else "system-profile-v2";
    const prefix = try std.fmt.allocPrint(arena, "{{\"schema\":\"https://debz.dev/schema/{s}\",\"version\":{d},", .{ schema, @as(u8, if (v1) 1 else 2) });
    defer arena.free(prefix);
    const backend_field = if (v1) "" else switch (backend) {
        .native => "\"transaction_backend\":\"native\",",
        .legacy_dpkg => "\"transaction_backend\":\"legacy_dpkg\",",
    };
    return std.fmt.allocPrint(arena, "{s}{s}\"repositories\":[{{\"source_path\":\"/etc/debz/fixture.sources\"}}],\"keyring_paths\":[\"/repository/fixture-keyring.gpg\"],\"architecture\":\"{s}\",\"repository_policy\":\"strict_priority\",\"default_conffile\":\"keep_existing\"}}", .{ prefix, backend_field, arch });
}

fn parseFile(runner: *Runner, name: []const u8) !std.json.Value {
    const bytes = try runner.readRoot(name);
    const parsed = try std.json.parseFromSlice(std.json.Value, runner.arena, bytes, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
    });
    return parsed.value;
}

fn currentMs() !i64 {
    var stamp: Timespec = undefined;
    if (clock_gettime(1, &stamp) != 0) return error.ClockFailed;
    return @as(i64, @intCast(stamp.tv_sec)) * 1000 + @divTrunc(@as(i64, @intCast(stamp.tv_nsec)), 1_000_000);
}

fn hostStatusExists(io: std.Io) bool {
    std.Io.Dir.cwd().access(io, "/var/lib/dpkg/status", .{}) catch return false;
    return true;
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    var binary: ?[]const u8 = null;
    var inside_path: ?[]const u8 = null;
    var backend: ?Backend = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--inside")) {
            if (inside_path != null) return error.InvalidArguments;
            inside_path = args.next() orelse return error.InvalidArguments;
        } else if (std.mem.eql(u8, arg, "--transaction-backend")) {
            if (backend != null) return error.InvalidArguments;
            const name = args.next() orelse return error.InvalidArguments;
            backend = std.meta.stringToEnum(Backend, name) orelse return error.InvalidArguments;
        } else {
            if (binary != null or std.mem.startsWith(u8, arg, "-")) return error.InvalidArguments;
            binary = arg;
        }
    }
    if (linux.getuid() != 0) {
        std.log.err("required apt-system acceptance needs root and Linux mount/PID/network namespaces", .{});
        return error.RootRequired;
    }
    var cwd_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (getcwd(&cwd_buffer, cwd_buffer.len) == null) return error.InvalidWorkingDirectory;
    const cwd = try arena.dupe(u8, std.mem.sliceTo(&cwd_buffer, 0));
    var runner: Runner = .{ .arena = arena, .io = init.io, .cwd = cwd };
    if (inside_path) |root| {
        if (backend == null or binary != null) return error.InvalidArguments;
        const canonical = try std.Io.Dir.realPathFileAbsoluteAlloc(init.io, root, arena);
        const parent = std.fs.path.dirname(canonical) orelse return error.UnsafeRoot;
        const cache = std.fs.path.dirname(parent) orelse return error.UnsafeRoot;
        const expected_cache = try std.fmt.allocPrint(arena, "{s}/.zig-cache", .{cwd});
        const workspace_name = std.fs.path.basename(parent);
        const workspace_prefix = "apt-system-acceptance-";
        if (linux.getpid() != 1 or !std.mem.eql(u8, std.fs.path.basename(canonical), "root") or
            !std.mem.eql(u8, cache, expected_cache) or
            !std.mem.startsWith(u8, workspace_name, workspace_prefix) or
            workspace_name.len == workspace_prefix.len)
            return error.UnsafeRoot;
        for (workspace_name[workspace_prefix.len..]) |character| {
            if (!std.ascii.isDigit(character)) return error.UnsafeRoot;
        }
        runner.root = canonical;
        runner.backend = backend.?;
        return inside(&runner);
    }
    if (binary == null) return error.InvalidArguments;
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(init.io, binary.?, arena);
    try std.Io.Dir.cwd().createDirPath(init.io, ".zig-cache");
    var cache = try std.Io.Dir.cwd().openDir(init.io, ".zig-cache", .{ .iterate = true, .follow_symlinks = false });
    defer cache.close(init.io);
    const had_status = hostStatusExists(init.io);
    const host_status = runner.readFile("/var/lib/dpkg/status") catch |err| switch (err) {
        error.FileNotFound => "",
        else => return err,
    };
    var before: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(host_status, &before, .{});
    defer {
        const after = runner.readFile("/var/lib/dpkg/status") catch "";
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(after, &digest, .{});
        if (had_status != hostStatusExists(init.io) or !std.mem.eql(u8, &before, &digest))
            std.log.err("HOST DPKG STATUS CHANGED", .{});
    }
    const executable = try std.process.executablePathAlloc(init.io, arena);
    const selected = if (backend) |b| &[_]Backend{b} else &[_]Backend{ .legacy_dpkg, .native };
    for (selected) |chosen| {
        const name = try std.fmt.allocPrint(arena, "apt-system-acceptance-{d}", .{linux.getpid()});
        try cache.createDir(init.io, name, File.Permissions.fromMode(0o700));
        defer cache.deleteTree(init.io, name) catch |err| std.log.err("disposable root cleanup failed: {s}", .{@errorName(err)});
        runner.root = try std.fmt.allocPrint(arena, "{s}/.zig-cache/{s}/root", .{ cwd, name });
        try std.Io.Dir.cwd().createDir(init.io, runner.root, .default_dir);
        try runner.prepareRoot(cli);
        const result = try runner.run(&.{ "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=SIGKILL", "--propagation", "private", executable, "--inside", runner.root, "--transaction-backend", @tagName(chosen) }, 180, null);
        if (result.term != .exited or result.term.exited != 0) {
            std.log.err("isolated apt acceptance ({s}) failed: {any}; stdout={s}; stderr={s}", .{
                @tagName(chosen), result.term, result.stdout, result.stderr,
            });
            runner.evidenceOnFailure();
            return error.IsolatedAcceptanceFailed;
        }
        std.log.info("apt-system acceptance ({s}): {s}", .{ @tagName(chosen), result.stdout });
    }
    const after = runner.readFile("/var/lib/dpkg/status") catch "";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(after, &digest, .{});
    try check(had_status == hostStatusExists(init.io) and
        std.mem.eql(u8, &before, &digest), "host dpkg status changed");
}

fn inside(runner: *Runner) !void {
    _ = try runner.command(&.{ "mount", "--bind", runner.root, runner.root }, 10, null);
    _ = try runner.command(&.{ "mount", "-t", "proc", "proc", try runner.path("/proc") }, 10, null);
    runner.schema_store = try schema_validator.Store.initWithIo(runner.arena, runner.io);
    defer if (runner.schema_store) |*store| store.deinit();
    try insideScenarios(runner);
}

fn entries(runner: *Runner, name: []const u8) !usize {
    var dir = try std.Io.Dir.openDirAbsolute(runner.io, try runner.path(name), .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(runner.io);
    var iterator = dir.iterate();
    var count: usize = 0;
    while (try iterator.next(runner.io)) |_| count += 1;
    return count;
}

fn resultsCount(runner: *Runner) !usize {
    const base = "/var/lib/debz/apt/operations";
    var dir = std.Io.Dir.openDirAbsolute(runner.io, try runner.path(base), .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return 0,
        else => return err,
    };
    defer dir.close(runner.io);
    var iterator = dir.iterate();
    var count: usize = 0;
    while (try iterator.next(runner.io)) |entry| {
        if (entry.kind != .directory) continue;
        const candidate = try std.fmt.allocPrint(runner.arena, "{s}/{s}/transaction-result.json", .{ base, entry.name });
        if (runner.exists(candidate)) count += 1;
    }
    return count;
}

fn unchangedRoot(runner: *Runner, status: []const u8) !void {
    try check(std.mem.eql(u8, status, try runner.readRoot("/var/lib/dpkg/status")), "invalid request changed dpkg status");
    try check(try entries(runner, "/var/lib/debz") == 0, "invalid request created state");
    try check(try entries(runner, "/var/cache/debz") == 0, "invalid request created cache");
    try check(!runner.exists("/run/debz"), "invalid request created runtime state");
}

fn expectNames(items: std.json.Value, field: []const u8, names: []const []const u8) !void {
    try check(items == .array, "expected item array");
    try check(items.array.items.len == names.len, "unexpected item count");
    for (names, 0..) |name, i| {
        for (names[0..i]) |earlier| try check(!std.mem.eql(u8, name, earlier), "duplicate expected fixture package");
        var found: usize = 0;
        for (items.array.items) |item| {
            if (eq(value(item, field), name)) found += 1;
        }
        try check(found == 1, "missing or duplicate package");
    }
}

fn rootBinding(runner: *Runner, evidence: std.json.Value, key: []const u8) !std.json.Value {
    var binding = value(evidence, key);
    try check(binding == .object, "missing evidence binding");
    if (std.mem.eql(u8, key, "root_operation_completion"))
        binding = value(binding, "document");
    try check(binding == .object, "invalid evidence binding");
    const path = text(value(binding, "path"));
    try check(path.len > 1 and runner.exists(path), "evidence document missing in disposable root");
    return binding;
}

fn insideScenarios(runner: *Runner) !void {
    var packages = try std.Io.Dir.openDirAbsolute(runner.io, try runner.path("/repository/pool/main"), .{ .iterate = true, .follow_symlinks = false });
    defer packages.close(runner.io);
    var iterator = packages.iterate();
    var essential: ?[]const u8 = null;
    while (try iterator.next(runner.io)) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "essential-core_") or
            !std.mem.endsWith(u8, entry.name, ".deb")) continue;
        try check(essential == null, "ambiguous essential fixture archive");
        essential = try runner.arena.dupe(u8, entry.name);
    }
    try check(essential != null, "essential fixture archive missing");
    var env = try runner.isolatedEnv();
    defer env.deinit();
    const archive = try std.fmt.allocPrint(runner.arena, "/repository/pool/main/{s}", .{essential.?});
    _ = try runner.command(&.{ "chroot", runner.root, "/usr/bin/dpkg", "--install", archive }, 60, &env);
    if (runner.backend == .native) {
        for ([_][]const u8{ "dpkg", "dpkg-deb", "dpkg-split" }) |name| {
            const source = try runner.path(try std.fmt.allocPrint(runner.arena, "/usr/bin/{s}", .{name}));
            const dest = try std.fmt.allocPrint(runner.arena, "{s}.disabled", .{source});
            try std.Io.Dir.renameAbsolute(source, dest, runner.io);
        }
    }
    const trigger = try runner.readRoot("/usr/bin/dpkg-trigger");
    var trigger_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(trigger, &trigger_sha, .{});
    const initial_status = try runner.readRoot("/var/lib/dpkg/status");
    runner.mountinfo = try runner.readFile("/proc/self/mountinfo");

    for ([_][]const []const u8{
        &.{ "install", "--unsupported", "base-dep" },
        &.{ "install", "base-dep", "base-dep" },
    }) |args| {
        _ = try runner.apt(2, args);
        try unchangedRoot(runner, initial_status);
    }
    const arch = text(value(try parseFile(runner, "/etc/debz/default.json"), "architecture"));
    try check(std.mem.eql(u8, arch, "amd64") or std.mem.eql(u8, arch, "arm64"), "invalid fixture architecture");
    try runner.writeRoot("/etc/debz/native-v2.json", try profile(runner.arena, arch, .native, false));
    const native_profile = try profile(runner.arena, arch, .native, false);
    const invalid_profile = try std.mem.replaceOwned(u8, runner.arena, native_profile, "\"transaction_backend\":\"native\"", "\"transaction_backend\":\"unsupported\"");
    try check(!std.mem.eql(u8, invalid_profile, native_profile), "invalid profile fixture was not generated");
    try runner.writeRoot("/etc/debz/invalid-v2.json", invalid_profile);
    for ([_]struct { u8, []const []const u8 }{
        .{ 3, &.{ "apt", "--profile", "/etc/debz/invalid-v2.json", "--json", "update" } },
        .{ 3, &.{ "apt", "--profile", "/etc/debz/invalid-v2.json", "--json", "install", "-y", "base-dep" } },
        .{ 3, &.{ "apt", "--profile", "/etc/debz/invalid-v2.json", "--json", "list", "--installed" } },
        .{ 8, &.{ "recover", "--system-profile", "/etc/debz/invalid-v2.json", "--json" } },
    }) |case| {
        const rejected = try runner.cli(case[0], case[1]);
        try check(!boolean(value(rejected, "changed")), "invalid profile changed the root");
        if (case[0] == 8) {
            try check(eq(value(rejected, "mutation_status"), "unknown"), "invalid recovery status");
            const ds = value(rejected, "diagnostics");
            try check(ds == .array and ds.array.items.len > 0 and
                eq(value(ds.array.items[0], "id"), "recovery_required"), "invalid recovery diagnostic");
        }
        try unchangedRoot(runner, initial_status);
    }

    _ = try runner.apt(0, &.{"update"});
    const reviewed = try runner.apt(2, &.{ "install", "base-dep", "alt-a" });
    const review_diagnostics = value(reviewed, "diagnostics");
    try check(review_diagnostics == .array and review_diagnostics.array.items.len > 0 and
        eq(value(review_diagnostics.array.items[0], "id"), "confirmation_required"), "missing review diagnostic");
    try expectNames(value(reviewed, "items"), "package", &.{ "base-dep", "alt-a" });
    try check(std.mem.eql(u8, initial_status, try runner.readRoot("/var/lib/dpkg/status")), "review changed dpkg status");
    const previous_results = try resultsCount(runner);
    const result = try runner.apt(0, &.{ "install", "-y", "base-dep", "alt-a" });
    try check(boolean(value(result, "changed")) and eq(value(result, "outcome"), "success"), "install did not succeed");
    const evidence = value(result, "evidence");
    const lock_binding = try rootBinding(runner, evidence, "exact_lock");
    const reviewed_lock = value(value(reviewed, "evidence"), "exact_lock");
    try check(equalValue(value(lock_binding, "digest_sha256"), value(reviewed_lock, "digest_sha256")), "review and installed closure differ");
    try check(try resultsCount(runner) == previous_results + 1, "install receipt history missing");
    const lock = try parseFile(runner, text(value(lock_binding, "path")));
    try check(number(value(lock, "version")) == (if (runner.backend == .native) @as(i64, 3) else 1), "wrong lock version");
    if (runner.backend == .native) {
        try check(eq(value(lock, "schema"), "https://debz.dev/schema/exact-closure-lock-v3"), "native lock schema");
        const repositories = value(lock, "repositories");
        try check(repositories == .array and repositories.array.items.len > 0, "missing lock repositories");
        for (repositories.array.items) |repository| try check(value(repository, "index_identity") != .null, "missing index identity");
    }
    const locked = value(lock, "packages");
    try expectNames(locked, "name", &.{ "base-dep", "alt-a", "essential-core" });
    var requested: usize = 0;
    for (locked.array.items) |package| {
        if (runner.backend == .native)
            try check(value(package, "archive_identity") != .null, "missing native archive identity");
        if (eq(value(package, "retention"), "requested")) {
            try check(eq(value(package, "name"), "base-dep") or eq(value(package, "name"), "alt-a"), "unexpected requested lock member");
            requested += 1;
        }
    }
    try check(requested == 2, "wrong requested closure");
    const receipt_binding = try rootBinding(runner, evidence, "transaction_result");
    const completion_binding = try rootBinding(runner, evidence, "root_operation_completion");
    const completion = try parseFile(runner, text(value(completion_binding, "path")));
    try check(equalValue(value(completion, "exact_lock"), value(evidence, "exact_lock")) and
        equalValue(value(completion, "transaction_result"), value(evidence, "transaction_result")) and
        equalValue(value(completion, "request_sha256"), value(result, "request_sha256")), "completion evidence does not bind request");
    if (runner.backend == .native) {
        const receipt = try parseFile(runner, text(value(receipt_binding, "path")));
        try check(eq(value(receipt, "schema"), "https://debz.dev/schema/native-transaction-provenance-v2") and
            eq(value(receipt, "outcome"), "succeeded") and
            equalValue(value(receipt, "exact_lock_sha256"), value(lock_binding, "digest_sha256")) and
            equalValue(value(receipt, "digest_sha256"), value(receipt_binding, "digest_sha256")), "invalid native transaction receipt");
    } else {
        const receipt_dir = std.fs.path.dirname(text(value(receipt_binding, "path"))) orelse return error.InvalidEvidence;
        const verification = try runner.cli(0, &.{
            "transaction-result", "verify",                          "--state-path",   receipt_dir,
            "--lock-input",       text(value(lock_binding, "path")), "--architecture", text(value(lock, "target_architecture")),
            "--json",
        });
        try check(equalValue(value(verification, "lock_sha256"), value(lock_binding, "digest_sha256")) and
            equalValue(value(verification, "transaction_digest_sha256"), value(receipt_binding, "digest_sha256")) and
            number(value(verification, "package_count")) == 3, "legacy receipt verification failed");
    }
    for ([_][]const u8{ "base-dep", "alt-a" }) |name| {
        try check(runner.exists(try std.fmt.allocPrint(runner.arena, "/usr/share/debz-fixtures/{s}", .{name})), "installed payload missing");
    }
    try insideRemaining(runner, arch, trigger_sha);
}

fn insideRemaining(runner: *Runner, arch: []const u8, trigger_sha: [32]u8) !void {
    const installed = try runner.apt(0, &.{ "list", "--installed" });
    try check(number(value(installed, "version")) == 2, "installed list is not result v2");
    try expectNames(value(installed, "items"), "package", &.{ "base-dep", "alt-a", "essential-core" });
    try runner.writeRoot("/etc/debz/legacy-v2.json", try profile(runner.arena, arch, .legacy_dpkg, false));
    const explicit_legacy = try runner.cli(0, &.{ "apt", "--profile", "/etc/debz/legacy-v2.json", "--json", "list", "--installed" });
    try check(equalValue(value(explicit_legacy, "items"), value(installed, "items")) and
        !equalValue(value(value(explicit_legacy, "profile"), "sha256"), value(value(installed, "profile"), "sha256")), "explicit legacy backend changed installed list or profile binding");

    _ = try runner.apt(0, &.{ "install", "-y", "fixture-upgrade=1.0-1" });
    const upgraded = try runner.apt(0, &.{ "upgrade", "-y" });
    try check(boolean(value(upgraded, "changed")), "upgrade did not change root");
    const payload = try runner.readRoot("/usr/share/debz-fixtures/fixture-upgrade");
    try check(std.mem.startsWith(u8, payload, "fixture-upgrade=2.0-1:"), "upgrade payload missing");
    if (runner.backend == .native) {
        const lower = try parseFile(runner, "/var/lib/debz/root-operation-completion-v2.json");
        const discharge = value(lower, "discharge");
        try check(eq(value(lower, "operation"), "upgrade_all") and
            eq(value(discharge, "operation"), "upgrade_all") and
            equalValue(value(discharge, "request_sha256"), value(lower, "request_sha256")), "native upgrade completion lost discharge");
        const before_unchanged = try runner.readRoot("/var/lib/dpkg/status");
        const receipts_before = try resultsCount(runner);
        const unchanged = try runner.apt(0, &.{ "upgrade", "-y" });
        const evidence = value(unchanged, "evidence");
        try check(number(value(unchanged, "version")) == 3 and !boolean(value(unchanged, "changed")) and
            value(evidence, "transaction_result") == .null and
            value(evidence, "root_operation_completion") == .null, "unchanged upgrade fabricated receipt");
        const active = "/var/lib/debz/apt/active-operation-v1.json";
        try check(!runner.exists(active), "unchanged upgrade left active operation");
        const unchanged_path = text(value(evidence, "active_operation_state"));
        try check(unchanged_path.len > 1, "unchanged upgrade lost durable history");
        const unchanged_bytes = try runner.readRoot(unchanged_path);
        const unchanged_state = try parseFile(runner, unchanged_path);
        try check(eq(value(unchanged_state, "outcome"), "unchanged") and
            !boolean(value(unchanged_state, "mutation_started")), "unchanged history claims mutation");
        try runner.writeRoot(active, unchanged_bytes);
        const reviewed = try runner.cli(2, &.{ "recover", "--system-profile", "/etc/debz/native-v2.json", "--json" });
        try check(!boolean(value(reviewed, "changed")) and
            std.mem.eql(u8, unchanged_bytes, try runner.readRoot(active)), "unchanged recovery review modified durable state");
        try runner.confirmRecovery(0);
        try check(!runner.exists(active) and
            std.mem.eql(u8, unchanged_bytes, try runner.readRoot(unchanged_path)) and
            std.mem.eql(u8, before_unchanged, try runner.readRoot("/var/lib/dpkg/status")) and
            try resultsCount(runner) == receipts_before, "unchanged recovery mutated history or dpkg status");
    }
    const reinstalled = try runner.apt(0, &.{ "install", "-y", "fixture-upgrade=2.0-1" });
    const reinstall_evidence = value(reinstalled, "evidence");
    try check(boolean(value(reinstalled, "changed")) and
        value(reinstall_evidence, "transaction_result") != .null and
        value(reinstall_evidence, "root_operation_completion") != .null and
        !runner.exists("/var/lib/debz/apt/active-operation-v1.json"), "same-version reinstall did not complete");
    const removed = try runner.apt(0, &.{ "remove", "-y", "base-dep", "alt-a", "fixture-upgrade" });
    try check(boolean(value(removed, "changed")), "batch removal did not change root");
    const remaining = try runner.apt(0, &.{ "list", "--installed" });
    try expectNames(value(remaining, "items"), "package", &.{"essential-core"});
    for ([_][]const u8{ "base-dep", "alt-a", "fixture-upgrade" }) |name| {
        try check(!runner.exists(try std.fmt.allocPrint(runner.arena, "/usr/share/debz-fixtures/{s}", .{name})), "removed package retained payload");
    }
    const before_rejection = try runner.readRoot("/var/lib/dpkg/status");
    const rejected = try runner.apt(5, &.{ "install", "-y", "base-dep", "nonexistent-fixture-package" });
    try check(!boolean(value(rejected, "changed")) and
        std.mem.eql(u8, before_rejection, try runner.readRoot("/var/lib/dpkg/status")) and
        !runner.exists("/usr/share/debz-fixtures/base-dep"), "atomic planning rejection changed root");

    if (runner.backend == .native) {
        const failure = try runner.apt(7, &.{ "install", "-y", "fail-script" });
        const failure_diagnostics = value(failure, "diagnostics");
        const evidence = value(failure, "evidence");
        try check(boolean(value(failure, "changed")) and
            failure_diagnostics == .array and failure_diagnostics.array.items.len > 0 and
            eq(value(failure_diagnostics.array.items[0], "id"), "transaction_failed") and
            value(evidence, "root_operation_completion") == .null, "failed script did not record transaction failure");
        const receipt_binding = try rootBinding(runner, evidence, "transaction_result");
        const receipt_path = text(value(receipt_binding, "path"));
        const receipt = try parseFile(runner, receipt_path);
        try check(eq(value(receipt, "outcome"), "failed"), "failed-script receipt omitted failure");
        const active = "/var/lib/debz/apt/active-operation-v1.json";
        try check(!runner.exists(active), "failed script left active state");
        const receipt_dir = std.fs.path.dirname(receipt_path) orelse return error.InvalidEvidence;
        const final_path = try std.fmt.allocPrint(runner.arena, "{s}/state-v1.json", .{receipt_dir});
        const final_bytes = try runner.readRoot(final_path);
        try runner.writeRoot(active, final_bytes);
        const recovery = try runner.cli(2, &.{ "recover", "--system-profile", "/etc/debz/native-v2.json", "--json" });
        try check(boolean(value(recovery, "changed")) and
            std.mem.eql(u8, final_bytes, try runner.readRoot(active)), "failed-script recovery review altered state");
        try runner.confirmRecovery(7);
        try check(!runner.exists(active) and
            std.mem.eql(u8, final_bytes, try runner.readRoot(final_path)), "failed-script recovery changed final history");
        const trigger = try runner.readRoot("/usr/bin/dpkg-trigger");
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(trigger, &digest, .{});
        try check(std.mem.eql(u8, &trigger_sha, &digest), "real dpkg-trigger helper was modified");
    }
    std.log.info("apt-system ({s}) install/remove, exact-lock evidence, recovery, ambient isolation and mounts passed", .{@tagName(runner.backend)});
}

test "apt acceptance guards paths and compares complete package sets" {
    var runner: Runner = .{
        .arena = std.testing.allocator,
        .io = std.testing.io,
        .cwd = "/worktree",
        .root = "/worktree/.zig-cache/apt-system-acceptance-123/root",
    };
    try std.testing.expectError(error.AcceptanceMismatch, runner.path("/../host"));
    try std.testing.expectError(error.AcceptanceMismatch, runner.path("relative"));
    const safe = try runner.path("/etc/debz/default.json");
    defer std.testing.allocator.free(safe);
    try std.testing.expectEqualStrings(
        "/worktree/.zig-cache/apt-system-acceptance-123/root/etc/debz/default.json",
        safe,
    );
    const profile_bytes = try profile(std.testing.allocator, "arm64", .native, false);
    defer std.testing.allocator.free(profile_bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, profile_bytes, .{});
    defer parsed.deinit();
    try std.testing.expect(eq(value(parsed.value, "transaction_backend"), "native"));
    try std.testing.expect(number(value(parsed.value, "version")) == 2);
    var list = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\[{"package":"alpha"},{"package":"beta"}]
    , .{});
    defer list.deinit();
    try expectNames(list.value, "package", &.{ "beta", "alpha" });
    try std.testing.expectError(error.AcceptanceMismatch, expectNames(list.value, "package", &.{ "alpha", "alpha" }));
    try std.testing.expectError(error.AcceptanceMismatch, expectNames(list.value, "package", &.{"alpha"}));
}

test "apt acceptance stages a real shell and its runtime in the worktree" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cwd_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (getcwd(&cwd_buffer, cwd_buffer.len) == null) return error.InvalidWorkingDirectory;
    const cwd = std.mem.sliceTo(&cwd_buffer, 0);
    const name = try std.fmt.allocPrint(arena.allocator(), "apt-system-acceptance-unit-{d}", .{linux.getpid()});
    try std.Io.Dir.cwd().createDirPath(std.testing.io, ".zig-cache");
    var cache = try std.Io.Dir.cwd().openDir(std.testing.io, ".zig-cache", .{ .follow_symlinks = false });
    defer cache.close(std.testing.io);
    try cache.createDir(std.testing.io, name, File.Permissions.fromMode(0o700));
    defer cache.deleteTree(std.testing.io, name) catch @panic("fixture cleanup failed");
    var runner: Runner = .{
        .arena = arena.allocator(),
        .io = std.testing.io,
        .cwd = cwd,
        .root = try std.fmt.allocPrint(arena.allocator(), "{s}/.zig-cache/{s}", .{ cwd, name }),
    };
    try runner.copyBinary("/bin/sh", "/bin/sh", 0);
    try std.testing.expect(runner.exists("/bin/sh"));
    const source = try runner.readFile("/bin/sh");
    const copied = try runner.readRoot("/bin/sh");
    try std.testing.expectEqualSlices(u8, source, copied);
}

test "apt acceptance captures schema-sized stdout but kills oversized subprocesses" {
    var runner: Runner = .{
        .arena = std.testing.allocator,
        .io = std.testing.io,
        .cwd = ".",
    };
    const captured = try runner.run(&.{ "python3", "-c", "import sys; sys.stdout.buffer.write(b'A' * (1024 * 1024 + 1))" }, 10, null);
    defer std.testing.allocator.free(captured.stdout);
    defer std.testing.allocator.free(captured.stderr);
    try std.testing.expectEqual(@as(usize, 1024 * 1024 + 1), captured.stdout.len);
    runner.output_limit = 16;
    try std.testing.expectError(error.StreamTooLong, runner.run(
        &.{ "printf", "abcdefghijklmnopqrstuvwxyz" },
        10,
        null,
    ));
}

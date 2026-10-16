const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const default_pinned_dpkg_path = "/nonexistent/pinned-dpkg";
pub const expected_x86_64_sha256 = "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5";
pub const expected_aarch64_sha256 = "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79";
pub const required_version_marker = "version 1.22.22";
const max_binary_bytes: usize = 32 * 1024 * 1024;
const max_output_bytes: usize = 1024 * 1024;

fn makePath(io: std.Io, path: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, path);
}

fn writeFileMode(io: std.Io, path: []const u8, bytes: []const u8, mode: std.posix.mode_t) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = true,
        .permissions = .fromMode(mode),
    });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn readFileAlloc(io: std.Io, allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_bytes));
}

fn deleteTree(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, path) catch {};
}

pub const VerifyError = error{
    MustNotRunAsRoot,
    InvalidPinnedDpkgFixture,
    UnsupportedArchitecture,
    PinnedDpkgSha256Mismatch,
    UnexpectedPinnedDpkgVersion,
    OutOfMemory,
};

pub const VerifyOptions = struct {
    simulate_root: bool = false,
    architecture_override: ?[]const u8 = null,
    expected_sha256_override: ?[]const u8 = null,
};

pub fn errorDiagnostic(err: VerifyError) []const u8 {
    return switch (err) {
        error.MustNotRunAsRoot => "trigger scheduling fixture must not run as root",
        error.InvalidPinnedDpkgFixture => "set DEBZ_PINNED_DPKG_FIXTURE to verified dpkg 1.22.22",
        error.UnsupportedArchitecture => "no native pinned dpkg trigger fixture for this architecture",
        error.PinnedDpkgSha256Mismatch => "pinned dpkg fixture SHA256 differs",
        error.UnexpectedPinnedDpkgVersion => "unexpected pinned dpkg version",
        error.OutOfMemory => "out of memory",
    };
}

pub fn hostArchitectureName() []const u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => "x86_64",
        .aarch64 => "aarch64",
        else => @tagName(builtin.cpu.arch),
    };
}

pub fn expectedSha256ForArchitecture(architecture: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, architecture, "x86_64")) return expected_x86_64_sha256;
    if (std.mem.eql(u8, architecture, "aarch64")) return expected_aarch64_sha256;
    return null;
}

pub fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn verifyPinnedDpkg(allocator: std.mem.Allocator, pinned_dpkg_path: []const u8) VerifyError!void {
    return verifyPinnedDpkgWithOptions(allocator, pinned_dpkg_path, .{});
}

pub fn verifyPinnedDpkgWithOptions(
    allocator: std.mem.Allocator,
    pinned_dpkg_path: []const u8,
    options: VerifyOptions,
) VerifyError!void {
    if (options.simulate_root or linux.geteuid() == 0) {
        return error.MustNotRunAsRoot;
    }
    if (!std.fs.path.isAbsolute(pinned_dpkg_path)) {
        return error.InvalidPinnedDpkgFixture;
    }

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var file = std.Io.Dir.cwd().openFile(io, pinned_dpkg_path, .{
        .mode = .read_only,
        .follow_symlinks = false,
    }) catch return error.InvalidPinnedDpkgFixture;
    defer file.close(io);

    const stat = file.stat(io) catch return error.InvalidPinnedDpkgFixture;
    if (stat.kind != .file or stat.size == 0 or stat.size > max_binary_bytes) {
        return error.InvalidPinnedDpkgFixture;
    }

    const architecture = options.architecture_override orelse hostArchitectureName();
    const expected_sha256 = options.expected_sha256_override orelse
        (expectedSha256ForArchitecture(architecture) orelse return error.UnsupportedArchitecture);

    var reader_buffer: [16 * 1024]u8 = undefined;
    var file_reader = file.reader(io, &reader_buffer);
    const bytes = file_reader.interface.allocRemaining(allocator, .limited(max_binary_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPinnedDpkgFixture,
    };
    defer allocator.free(bytes);

    const actual_sha256 = sha256Hex(bytes);
    if (!std.mem.eql(u8, &actual_sha256, expected_sha256)) {
        return error.PinnedDpkgSha256Mismatch;
    }

    const version_run = std.process.run(allocator, io, .{
        .argv = &.{ pinned_dpkg_path, "--version" },
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(max_output_bytes),
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.UnexpectedPinnedDpkgVersion,
    };
    defer allocator.free(version_run.stdout);
    defer allocator.free(version_run.stderr);

    switch (version_run.term) {
        .exited => |code| if (code != 0) return error.UnexpectedPinnedDpkgVersion,
        else => return error.UnexpectedPinnedDpkgVersion,
    }
    if (std.mem.indexOf(u8, version_run.stdout, required_version_marker) == null) {
        return error.UnexpectedPinnedDpkgVersion;
    }
}

const PackageMode = struct {
    cascade: bool = false,
    nested: bool = false,
    direct: bool = false,
};

const FixtureWorkspace = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    pinned_dpkg: []const u8,
    workspace: []const u8,
    root: []const u8,
    admindir: []const u8,
    log: []const u8,
    dpkg_log: []const u8,
    nested_log: []const u8,

    fn init(allocator: std.mem.Allocator, io: std.Io, pinned_dpkg: []const u8, base_dir: []const u8, case_name: []const u8) !FixtureWorkspace {
        const workspace = try std.fs.path.join(allocator, &.{ base_dir, case_name });
        const root = try std.fs.path.join(allocator, &.{ workspace, "root" });
        const admindir = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg" });
        const info_dir = try std.fs.path.join(allocator, &.{ admindir, "info" });
        const updates_dir = try std.fs.path.join(allocator, &.{ admindir, "updates" });
        const triggers_dir = try std.fs.path.join(allocator, &.{ admindir, "triggers" });
        const status_path = try std.fs.path.join(allocator, &.{ admindir, "status" });
        const log = try std.fs.path.join(allocator, &.{ workspace, "scripts.log" });
        const dpkg_log = try std.fs.path.join(allocator, &.{ workspace, "dpkg.log" });
        const nested_log = try std.fs.path.join(allocator, &.{ workspace, "nested.log" });

        try makePath(io, info_dir);
        try makePath(io, updates_dir);
        try makePath(io, triggers_dir);
        try writeFileMode(io, status_path, "", 0o644);

        return .{
            .allocator = allocator,
            .io = io,
            .pinned_dpkg = pinned_dpkg,
            .workspace = workspace,
            .root = root,
            .admindir = admindir,
            .log = log,
            .dpkg_log = dpkg_log,
            .nested_log = nested_log,
        };
    }

    fn dpkg(self: *const FixtureWorkspace, extra_args: []const []const u8, check: bool) !std.process.RunResult {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(self.allocator, &.{
            self.pinned_dpkg,
            try std.fmt.allocPrint(self.allocator, "--root={s}", .{self.root}),
            "--force-not-root",
            "--force-bad-path",
            "--force-confold",
            "--force-script-chrootless",
            try std.fmt.allocPrint(self.allocator, "--log={s}", .{self.dpkg_log}),
        });
        try argv.appendSlice(self.allocator, extra_args);

        var env = std.process.Environ.Map.init(self.allocator);
        defer env.deinit();
        try env.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        try env.put("LC_ALL", "C");
        try env.put("DEBIAN_FRONTEND", "noninteractive");

        const result = try std.process.run(self.allocator, self.io, .{
            .argv = argv.items,
            .environ_map = &env,
            .stdout_limit = .limited(max_output_bytes),
            .stderr_limit = .limited(max_output_bytes),
        });
        if (check) {
            switch (result.term) {
                .exited => |code| if (code != 0) return error.PinnedDpkgCommandFailed,
                else => return error.PinnedDpkgCommandFailed,
            }
        }
        return result;
    }

    fn buildPackage(self: *const FixtureWorkspace, name: []const u8, mode: PackageMode) ![]const u8 {
        const source = try std.fs.path.join(self.allocator, &.{ self.workspace, name });
        const control_dir = try std.fs.path.join(self.allocator, &.{ source, "DEBIAN" });
        try makePath(self.io, control_dir);
        try chmodPath(self.io, control_dir, 0o755);

        const control_path = try std.fs.path.join(self.allocator, &.{ control_dir, "control" });
        const control_text = try std.fmt.allocPrint(
            self.allocator,
            "Package: {s}\nVersion: 1\nArchitecture: all\n" ++
                "Maintainer: Proof <nobody@example.invalid>\n" ++
                "Description: disposable unprivileged trigger fixture\n",
            .{name},
        );
        try writeFileMode(self.io, control_path, control_text, 0o644);

        const triggers_path = try std.fs.path.join(self.allocator, &.{ control_dir, "triggers" });
        const triggers_text = try std.fmt.allocPrint(self.allocator, "interest-noawait named-{s}\n", .{name});
        try writeFileMode(self.io, triggers_path, triggers_text, 0o644);

        var postinst_buf: std.ArrayList(u8) = .empty;
        try postinst_buf.appendSlice(self.allocator, try std.fmt.allocPrint(
            self.allocator,
            "#!/bin/sh\n" ++
                "[ \"$DPKG_ADMINDIR\" = '{s}' ] || exit 77\n" ++
                "printf '%s\\t%s\\n' '{s}' \"$1\" >> '{s}'\n",
            .{ self.admindir, name, self.log },
        ));
        if (mode.cascade) {
            try postinst_buf.appendSlice(self.allocator, try std.fmt.allocPrint(
                self.allocator,
                "if [ \"$1\" = triggered ]; then " ++
                    "dpkg-trigger --admindir='{s}' --no-await named-listener-b; fi\n",
                .{self.admindir},
            ));
        }
        if (mode.nested) {
            try postinst_buf.appendSlice(self.allocator, try std.fmt.allocPrint(
                self.allocator,
                "if [ \"$1\" = triggered ]; then " ++
                    "'{s}' --root='{s}' --force-not-root " ++
                    "--force-bad-path --force-confold --force-script-chrootless " ++
                    "--log='{s}' --no-triggers --triggers-only listener-b; fi\n",
                .{ self.pinned_dpkg, self.root, self.nested_log },
            ));
        }
        if (mode.direct) {
            const listener_b_postinst = try std.fs.path.join(self.allocator, &.{ self.admindir, "info/listener-b.postinst" });
            try postinst_buf.appendSlice(self.allocator, try std.fmt.allocPrint(
                self.allocator,
                "if [ \"$1\" = triggered ]; then " ++
                    "'{s}' triggered named-listener-b; fi\n",
                .{listener_b_postinst},
            ));
        }

        const postinst_path = try std.fs.path.join(self.allocator, &.{ control_dir, "postinst" });
        try writeFileMode(self.io, postinst_path, postinst_buf.items, 0o755);
        try chmodPath(self.io, postinst_path, 0o755);

        const share_dir = try std.fs.path.join(self.allocator, &.{ source, "usr/share" });
        try makePath(self.io, share_dir);
        const payload_path = try std.fs.path.join(self.allocator, &.{ share_dir, name });
        try writeFileMode(self.io, payload_path, name, 0o644);

        const archive = try std.fs.path.join(
            self.allocator,
            &.{ self.workspace, try std.fmt.allocPrint(self.allocator, "{s}.deb", .{name}) },
        );
        const built = try std.process.run(self.allocator, self.io, .{
            .argv = &.{ "dpkg-deb", "--build", source, archive },
            .stdout_limit = .limited(max_output_bytes),
            .stderr_limit = .limited(max_output_bytes),
        });
        switch (built.term) {
            .exited => |code| if (code != 0) return error.DpkgDebBuildFailed,
            else => return error.DpkgDebBuildFailed,
        }
        return archive;
    }

    fn setupTwoPending(self: *const FixtureWorkspace, mode: PackageMode) !void {
        for ([_][]const u8{ "listener-a", "listener-b" }) |name| {
            const is_a = std.mem.eql(u8, name, "listener-a");
            const archive = try self.buildPackage(name, .{
                .cascade = mode.cascade and is_a,
                .nested = mode.nested and is_a,
                .direct = mode.direct and is_a,
            });
            _ = try self.dpkg(&.{ "--no-triggers", "--unpack", archive }, true);
            _ = try self.dpkg(&.{ "--no-triggers", "--configure", name }, true);
        }
        try writeFileMode(self.io, self.log, "", 0o644);
        for ([_][]const u8{ "listener-a", "listener-b" }) |name| {
            const admindir_arg = try std.fmt.allocPrint(self.allocator, "--admindir={s}", .{self.admindir});
            const trigger_name = try std.fmt.allocPrint(self.allocator, "named-{s}", .{name});
            const trig = try std.process.run(self.allocator, self.io, .{
                .argv = &.{ "dpkg-trigger", admindir_arg, "--no-await", trigger_name },
                .stdout_limit = .limited(max_output_bytes),
                .stderr_limit = .limited(max_output_bytes),
            });
            switch (trig.term) {
                .exited => |code| if (code != 0) return error.DpkgTriggerFailed,
                else => return error.DpkgTriggerFailed,
            }
        }
        const seed_archive = try self.buildPackage("seed", .{});
        _ = try self.dpkg(&.{ "--no-triggers", "--unpack", seed_archive }, true);
    }

    fn readStatus(self: *const FixtureWorkspace) ![]const u8 {
        const status_path = try std.fs.path.join(self.allocator, &.{ self.admindir, "status" });
        return readFileAlloc(self.io, self.allocator, status_path, max_output_bytes);
    }

    fn readLog(self: *const FixtureWorkspace) ![]const u8 {
        return readFileAlloc(self.io, self.allocator, self.log, max_output_bytes);
    }
};

fn chmodPath(io: std.Io, path: []const u8, mode: std.posix.mode_t) !void {
    if (std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only })) |file| {
        defer file.close(io);
        try file.setPermissions(io, .fromMode(mode));
        return;
    } else |_| {}
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);
    try dir.setPermissions(io, .fromMode(mode));
}

pub fn testExplicitSelectorDoesNotRunOtherPendingScript(
    allocator: std.mem.Allocator,
    io: std.Io,
    pinned_dpkg: []const u8,
    base_dir: []const u8,
) !void {
    const fx = try FixtureWorkspace.init(allocator, io, pinned_dpkg, base_dir, "case-1-explicit-selector");
    try fx.setupTwoPending(.{});
    const status_before = try fx.readStatus();
    if (std.mem.indexOf(u8, status_before, "Triggers-Pending: named-listener-a") == null) return error.UnexpectedTriggerStatus;
    if (std.mem.indexOf(u8, status_before, "Triggers-Pending: named-listener-b") == null) return error.UnexpectedTriggerStatus;

    const result = try fx.dpkg(&.{ "--no-triggers", "--triggers-only", "listener-a" }, false);
    switch (result.term) {
        .exited => |code| if (code != 0) return error.UnexpectedDpkgExit,
        else => return error.UnexpectedDpkgExit,
    }
    const log_text = try fx.readLog();
    if (!std.mem.eql(u8, log_text, "listener-a\ttriggered\n")) return error.UnexpectedScriptLog;
    const status_after = try fx.readStatus();
    if (std.mem.indexOf(u8, status_after, "Triggers-Pending: named-listener-b") == null) return error.UnexpectedTriggerStatus;
}

pub fn testNamedTriggerOnlyDoesNotDrainOtherPendingListener(
    allocator: std.mem.Allocator,
    io: std.Io,
    pinned_dpkg: []const u8,
    base_dir: []const u8,
) !void {
    const fx = try FixtureWorkspace.init(allocator, io, pinned_dpkg, base_dir, "case-2-named-trigger-only");
    try fx.setupTwoPending(.{ .cascade = true });
    const result = try fx.dpkg(&.{ "--triggers-only", "listener-a" }, true);
    switch (result.term) {
        .exited => |code| if (code != 0) return error.UnexpectedDpkgExit,
        else => return error.UnexpectedDpkgExit,
    }
    const log_text = try fx.readLog();
    if (!std.mem.eql(u8, log_text, "listener-a\ttriggered\n")) return error.UnexpectedScriptLog;
    const status_after = try fx.readStatus();
    if (std.mem.indexOf(u8, status_after, "Triggers-Pending: named-listener-b") == null) return error.UnexpectedTriggerStatus;
}

pub fn testRecursiveDpkgCannotProcessOtherListenerWhileLocked(
    allocator: std.mem.Allocator,
    io: std.Io,
    pinned_dpkg: []const u8,
    base_dir: []const u8,
) !void {
    const fx = try FixtureWorkspace.init(allocator, io, pinned_dpkg, base_dir, "case-3-recursive-locked");
    try fx.setupTwoPending(.{ .nested = true });
    const result = try fx.dpkg(&.{ "--no-triggers", "--triggers-only", "listener-a" }, false);
    switch (result.term) {
        .exited => |code| if (code == 0) return error.ExpectedLockedDpkgFailure,
        else => {},
    }
    if (std.mem.indexOf(u8, result.stderr, "frontend lock was locked") == null) return error.MissingFrontendLockDiagnostic;
    const log_text = try fx.readLog();
    if (!std.mem.eql(u8, log_text, "listener-a\ttriggered\n")) return error.UnexpectedScriptLog;
}

pub fn testSelectedScriptCanLaunchOtherPostinstOutsideDpkgScheduler(
    allocator: std.mem.Allocator,
    io: std.Io,
    pinned_dpkg: []const u8,
    base_dir: []const u8,
) !void {
    const fx = try FixtureWorkspace.init(allocator, io, pinned_dpkg, base_dir, "case-4-direct-postinst");
    try fx.setupTwoPending(.{ .direct = true });
    _ = try fx.dpkg(&.{ "--no-triggers", "--triggers-only", "listener-a" }, true);
    const log_text = try fx.readLog();
    if (!std.mem.eql(u8, log_text, "listener-a\ttriggered\nlistener-b\ttriggered\n")) return error.UnexpectedScriptLog;
    const status_after = try fx.readStatus();
    if (std.mem.indexOf(u8, status_after, "Triggers-Pending: named-listener-b") == null) return error.UnexpectedTriggerStatus;
}

pub fn testConfigureRequiresNoTriggersToIsolateOtherScripts(
    allocator: std.mem.Allocator,
    io: std.Io,
    pinned_dpkg: []const u8,
    base_dir: []const u8,
) !void {
    const fx = try FixtureWorkspace.init(allocator, io, pinned_dpkg, base_dir, "case-5-configure-no-triggers");
    try fx.setupTwoPending(.{});
    _ = try fx.dpkg(&.{ "--no-triggers", "--configure", "seed" }, true);
    const log_text = try fx.readLog();
    if (!std.mem.eql(u8, log_text, "seed\tconfigure\n")) return error.UnexpectedScriptLog;
    const status_after = try fx.readStatus();
    if (std.mem.indexOf(u8, status_after, "Triggers-Pending: named-listener-a") == null) return error.UnexpectedTriggerStatus;
    if (std.mem.indexOf(u8, status_after, "Triggers-Pending: named-listener-b") == null) return error.UnexpectedTriggerStatus;
}

pub fn testDefaultConfigureMayProcessUnselectedTriggerScripts(
    allocator: std.mem.Allocator,
    io: std.Io,
    pinned_dpkg: []const u8,
    base_dir: []const u8,
) !void {
    const fx = try FixtureWorkspace.init(allocator, io, pinned_dpkg, base_dir, "case-6-default-configure");
    try fx.setupTwoPending(.{});
    _ = try fx.dpkg(&.{ "--configure", "seed" }, true);
    const log_text = try fx.readLog();
    if (std.mem.indexOf(u8, log_text, "listener-b\ttriggered\n") == null) return error.UnexpectedScriptLog;
}

pub fn testConfiguringAPendingSelectorRunsItsTriggeredScript(
    allocator: std.mem.Allocator,
    io: std.Io,
    pinned_dpkg: []const u8,
    base_dir: []const u8,
) !void {
    const fx = try FixtureWorkspace.init(allocator, io, pinned_dpkg, base_dir, "case-7-configure-pending-selector");
    try fx.setupTwoPending(.{});
    _ = try fx.dpkg(&.{ "--no-triggers", "--configure", "listener-a" }, true);
    const log_text = try fx.readLog();
    if (!std.mem.eql(u8, log_text, "listener-a\ttriggered\n")) return error.UnexpectedScriptLog;
    const status_after = try fx.readStatus();
    if (std.mem.indexOf(u8, status_after, "Triggers-Pending: named-listener-b") == null) return error.UnexpectedTriggerStatus;
}

pub fn runAllTriggerTests(allocator: std.mem.Allocator, pinned_dpkg: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work_allocator = arena.allocator();

    var threaded: std.Io.Threaded = .init(work_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const suffix = std.fmt.bytesToHex(random_bytes, .lower);
    const base_dir = try std.fs.path.join(
        work_allocator,
        &.{ "/tmp", try std.fmt.allocPrint(work_allocator, "debz-trigger-proof-{s}", .{suffix}) },
    );
    try makePath(io, base_dir);
    defer deleteTree(io, base_dir);

    try testExplicitSelectorDoesNotRunOtherPendingScript(work_allocator, io, pinned_dpkg, base_dir);
    try testNamedTriggerOnlyDoesNotDrainOtherPendingListener(work_allocator, io, pinned_dpkg, base_dir);
    try testRecursiveDpkgCannotProcessOtherListenerWhileLocked(work_allocator, io, pinned_dpkg, base_dir);
    try testSelectedScriptCanLaunchOtherPostinstOutsideDpkgScheduler(work_allocator, io, pinned_dpkg, base_dir);
    try testConfigureRequiresNoTriggersToIsolateOtherScripts(work_allocator, io, pinned_dpkg, base_dir);
    try testDefaultConfigureMayProcessUnselectedTriggerScripts(work_allocator, io, pinned_dpkg, base_dir);
    try testConfiguringAPendingSelectorRunsItsTriggeredScript(work_allocator, io, pinned_dpkg, base_dir);
}

pub const CliAction = union(enum) {
    help,
    run: []const u8,
};

pub fn parseCliArgs(args: []const []const u8, env_pinned_dpkg: ?[]const u8) !CliAction {
    var pinned_dpkg: []const u8 = env_pinned_dpkg orelse default_pinned_dpkg_path;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return .help;
        } else if (std.mem.eql(u8, arg, "--pinned-dpkg")) {
            index += 1;
            if (index >= args.len) return error.MissingPinnedDpkgValue;
            pinned_dpkg = args[index];
        } else {
            return error.UnknownArgument;
        }
    }
    return .{ .run = pinned_dpkg };
}

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const raw_args = try init.minimal.args.toSlice(allocator);
    const args = if (raw_args.len > 0) raw_args[1..] else raw_args[0..0];
    const env_pinned = init.environ_map.get("DEBZ_PINNED_DPKG_FIXTURE");

    const action = parseCliArgs(args, env_pinned) catch |err| {
        var stderr_buf: [512]u8 = undefined;
        var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buf);
        const stderr = &stderr_writer.interface;
        try stderr.print("error: {s}\n", .{@errorName(err)});
        try stderr.flush();
        std.process.exit(1);
    };

    switch (action) {
        .help => {
            var stdout_buf: [512]u8 = undefined;
            var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buf);
            const stdout = &stdout_writer.interface;
            try stdout.writeAll("Usage: debz-real-snapshot-reference-triggers [--pinned-dpkg <path>]\n");
            try stdout.flush();
        },
        .run => |pinned_dpkg| {
            verifyPinnedDpkg(allocator, pinned_dpkg) catch |err| {
                var stderr_buf: [512]u8 = undefined;
                var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buf);
                const stderr = &stderr_writer.interface;
                try stderr.print("error: {s}\n", .{errorDiagnostic(err)});
                try stderr.flush();
                std.process.exit(1);
            };
            runAllTriggerTests(allocator, pinned_dpkg) catch |err| {
                var stderr_buf: [512]u8 = undefined;
                var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buf);
                const stderr = &stderr_writer.interface;
                try stderr.print("error: {s}\n", .{@errorName(err)});
                try stderr.flush();
                std.process.exit(1);
            };
            var stdout_buf: [512]u8 = undefined;
            var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buf);
            const stdout = &stdout_writer.interface;
            try stdout.writeAll("Verified 7 pinned-dpkg trigger scheduling cases.\n");
            try stdout.flush();
        },
    }
}

test "verifyPinnedDpkg refuses root, missing, relative, symlink, directory, unsupported arch, sha256 mismatch, and bad version" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try std.testing.expectError(
        error.MustNotRunAsRoot,
        verifyPinnedDpkgWithOptions(allocator, "/bin/sh", .{ .simulate_root = true }),
    );
    try std.testing.expectEqualStrings(
        "trigger scheduling fixture must not run as root",
        errorDiagnostic(error.MustNotRunAsRoot),
    );

    if (linux.geteuid() == 0) return;

    try std.testing.expectError(
        error.InvalidPinnedDpkgFixture,
        verifyPinnedDpkgWithOptions(allocator, "relative/pinned-dpkg", .{}),
    );
    try std.testing.expectError(
        error.InvalidPinnedDpkgFixture,
        verifyPinnedDpkgWithOptions(allocator, default_pinned_dpkg_path, .{}),
    );
    try std.testing.expectEqualStrings(
        "set DEBZ_PINNED_DPKG_FIXTURE to verified dpkg 1.22.22",
        errorDiagnostic(error.InvalidPinnedDpkgFixture),
    );

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    try std.testing.expectError(
        error.InvalidPinnedDpkgFixture,
        verifyPinnedDpkgWithOptions(allocator, root, .{}),
    );

    const fake_dpkg = try std.fs.path.join(allocator, &.{ root, "fake-dpkg" });
    const script =
        "#!/bin/sh\n" ++
        "echo \"Debian 'dpkg' package management program version 1.22.22 (amd64).\"\n";
    try writeFileMode(io, fake_dpkg, script, 0o755);
    try chmodPath(io, fake_dpkg, 0o755);

    const symlink_dpkg = try std.fs.path.join(allocator, &.{ root, "symlink-dpkg" });
    try tmp.dir.symLink(io, "fake-dpkg", "symlink-dpkg", .{});
    try std.testing.expectError(
        error.InvalidPinnedDpkgFixture,
        verifyPinnedDpkgWithOptions(allocator, symlink_dpkg, .{}),
    );

    try std.testing.expectError(
        error.UnsupportedArchitecture,
        verifyPinnedDpkgWithOptions(allocator, fake_dpkg, .{ .architecture_override = "riscv64" }),
    );
    try std.testing.expectEqualStrings(
        "no native pinned dpkg trigger fixture for this architecture",
        errorDiagnostic(error.UnsupportedArchitecture),
    );

    try std.testing.expectError(
        error.PinnedDpkgSha256Mismatch,
        verifyPinnedDpkgWithOptions(allocator, fake_dpkg, .{ .architecture_override = "x86_64" }),
    );
    try std.testing.expectEqualStrings(
        "pinned dpkg fixture SHA256 differs",
        errorDiagnostic(error.PinnedDpkgSha256Mismatch),
    );

    const fake_hash = sha256Hex(script);
    try verifyPinnedDpkgWithOptions(allocator, fake_dpkg, .{
        .expected_sha256_override = &fake_hash,
    });

    const bad_version_dpkg = try std.fs.path.join(allocator, &.{ root, "bad-version-dpkg" });
    const bad_script =
        "#!/bin/sh\n" ++
        "echo \"Debian 'dpkg' package management program version 1.21.0 (amd64).\"\n";
    try writeFileMode(io, bad_version_dpkg, bad_script, 0o755);
    try chmodPath(io, bad_version_dpkg, 0o755);
    const bad_hash = sha256Hex(bad_script);
    try std.testing.expectError(
        error.UnexpectedPinnedDpkgVersion,
        verifyPinnedDpkgWithOptions(allocator, bad_version_dpkg, .{
            .expected_sha256_override = &bad_hash,
        }),
    );
    try std.testing.expectEqualStrings(
        "unexpected pinned dpkg version",
        errorDiagnostic(error.UnexpectedPinnedDpkgVersion),
    );
}

test "parseCliArgs handles defaults, explicit --pinned-dpkg, --help, and unknown flags" {
    const default_action = try parseCliArgs(&.{}, null);
    try std.testing.expectEqualStrings(default_pinned_dpkg_path, default_action.run);

    const env_action = try parseCliArgs(&.{}, "/custom/env/dpkg");
    try std.testing.expectEqualStrings("/custom/env/dpkg", env_action.run);

    const flag_action = try parseCliArgs(&.{ "--pinned-dpkg", "/custom/flag/dpkg" }, "/custom/env/dpkg");
    try std.testing.expectEqualStrings("/custom/flag/dpkg", flag_action.run);

    const help_action = try parseCliArgs(&.{"--help"}, null);
    try std.testing.expect(help_action == .help);

    try std.testing.expectError(error.MissingPinnedDpkgValue, parseCliArgs(&.{"--pinned-dpkg"}, null));
    try std.testing.expectError(error.UnknownArgument, parseCliArgs(&.{"--bogus"}, null));
}

test "all seven unprivileged trigger scheduling scenarios hold against verified dpkg fixture" {
    if (linux.geteuid() == 0) return;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    const wrapper_dpkg = try std.fs.path.join(allocator, &.{ root, "verified-dpkg-wrapper" });
    const wrapper_script =
        "#!/bin/sh\n" ++
        "if [ \"$1\" = \"--version\" ]; then\n" ++
        "  echo \"Debian 'dpkg' package management program version 1.22.22\"\n" ++
        "  exit 0\n" ++
        "fi\n" ++
        "exec /usr/bin/dpkg \"$@\"\n";
    try writeFileMode(io, wrapper_dpkg, wrapper_script, 0o755);
    try chmodPath(io, wrapper_dpkg, 0o755);

    const wrapper_hash = sha256Hex(wrapper_script);
    try verifyPinnedDpkgWithOptions(allocator, wrapper_dpkg, .{
        .expected_sha256_override = &wrapper_hash,
    });
    try runAllTriggerTests(allocator, wrapper_dpkg);
}

//! Regression coverage for the aarch64 Ubuntu customize failure (issue #455).
//!
//! An authenticated Ubuntu root ships var/lib/dpkg but never var/lib/debz, so
//! acquiring the debz transaction lock walked into a missing parent directory
//! and surfaced a bare `backend_failed: FileNotFound` (exit 7) the first time a
//! package was customized after a multi-hour resolve. The same failure path
//! leaked every working buffer withRepositories had allocated. These tests
//! drive the public product backend end to end so the lock provisioning, the
//! structured diagnostics, and the leak-free failure path all stay fixed.
//!
//! This file is the root of its own test binary (see build.zig's
//! `test-production-customize` step, mirroring the fuzz target wiring) and
//! reaches the backend exclusively through the public `debz` package. That
//! deliberately keeps production_backend.zig's dormant, bit-rotted historical
//! test block out of the graph so this incident fix does not have to revive it.

const std = @import("std");
const debz = @import("debz");
const api = debz.product_api;
const transaction_executor = debz.transaction_executor;
const fixture = debz.test_fixtures.openpgp;

const removable_status =
    \\Package: removable
    \\Status: install ok installed
    \\Priority: optional
    \\Architecture: amd64
    \\Version: 1
    \\
;

const Fixture = struct {
    directory: std.testing.TmpDir,
    source_path: []u8,
    keyring_path: []u8,
    install_root: []u8,
    cache_path: []u8,
    state_path: []u8,

    fn deinit(self: *Fixture) void {
        std.testing.allocator.free(self.source_path);
        std.testing.allocator.free(self.keyring_path);
        std.testing.allocator.free(self.install_root);
        std.testing.allocator.free(self.cache_path);
        std.testing.allocator.free(self.state_path);
        self.directory.cleanup();
    }

    fn options(
        self: Fixture,
        source_paths: []const []const u8,
        keyring_paths: []const []const u8,
    ) api.CommonOptions {
        return .{
            .install_root = self.install_root,
            .source_paths = source_paths,
            .keyring_paths = keyring_paths,
            .cache_path = self.cache_path,
            .state_path = self.state_path,
            .architecture = "amd64",
            .assume_yes = true,
        };
    }
};

// Stages an authenticated single-repository root exactly like an official
// Ubuntu image: var/lib/dpkg exists but var/lib/debz is deliberately absent so
// the production transaction lock adapter must provision its own state
// directory before it can lock.
fn stageRoot() !Fixture {
    var directory = std.testing.tmpDir(.{});
    errdefer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "repo/dists/stable/main/binary-amd64");
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.createDirPath(std.testing.io, "state");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "repo/dists/stable/InRelease",
        .data = &fixture.repository_in_release,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "repo/dists/stable/main/binary-amd64/Packages",
        .data = &fixture.repository_packages,
    });
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "keyring.gpg", .data = &fixture.keyring });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = removable_status,
    });

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const root = real_buffer[0..real_length];
    const keyring_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/keyring.gpg", .{root});
    errdefer std.testing.allocator.free(keyring_path);
    const repository_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/repo", .{root});
    defer std.testing.allocator.free(repository_path);
    const source_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "deb [arch=amd64 signed-by={s}] file://{s} stable main\n",
        .{ keyring_path, repository_path },
    );
    defer std.testing.allocator.free(source_bytes);
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "sources.list", .data = source_bytes });
    return .{
        .directory = directory,
        .source_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sources.list", .{root}),
        .keyring_path = keyring_path,
        .install_root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{root}),
        .cache_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/cache", .{root}),
        .state_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state", .{root}),
    };
}

// Mirrors the production dpkg contract closely enough to succeed: a remove
// empties the recorded status so the backend observes the package gone.
const SuccessfulProcess = struct {
    io: std.Io,
    dir: std.Io.Dir,

    fn interface(self: *SuccessfulProcess) transaction_executor.ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(context: *anyopaque, invocation: transaction_executor.Invocation) !transaction_executor.ProcessResult {
        const self: *SuccessfulProcess = @ptrCast(@alignCast(context));
        if (invocation.phase == .remove) try self.dir.writeFile(self.io, .{
            .sub_path = "root/var/lib/dpkg/status",
            .data = "",
        });
        return .{ .termination = .{ .exited = 0 } };
    }
};

// Fails the first dpkg command so the executor returns a transaction failure
// report, exercising withRepositories' error path.
const FailingProcess = struct {
    fn interface(self: *FailingProcess) transaction_executor.ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(_: *anyopaque, _: transaction_executor.Invocation) !transaction_executor.ProcessResult {
        return .{ .termination = .{ .exited = 1 } };
    }
};

test "production customize provisions a missing var/lib/debz lock root" {
    var staged = try stageRoot();
    defer staged.deinit();

    // The successful-remove path returns caller-owned summary/items whose
    // ownership is intentionally arena-managed by the embedder (main.zig and
    // vmiz wrap the call in an arena). Mirror that here so this behavioural
    // reproduction is not entangled with the caller-ownership question, which
    // the failure test below covers with the leak-checked allocator.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    // The staged root intentionally lacks var/lib/debz. Before the lock adapter
    // provisioned its own state directory, acquiring the transaction lock here
    // failed with FileNotFound (exit 7) — the exact aarch64 customize regression.
    const result = try api.execute(arena.allocator(), .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = staged.options(&source_paths, &keyring_paths),
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expect(result.changed);
    var provisioned = try staged.directory.dir.openDir(
        std.testing.io,
        "root/var/lib/debz",
        .{ .follow_symlinks = false },
    );
    provisioned.close(std.testing.io);
}

test "production customize failure reports structured diagnostics without leaking" {
    var staged = try stageRoot();
    defer staged.deinit();

    var process = FailingProcess{};
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const result = try api.execute(std.testing.allocator, .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = staged.options(&source_paths, &keyring_paths),
    }, backend.interface());
    // The failure path allocates planning policies, plan-request selectors, and
    // the returned message; std.testing.allocator fails if any working buffer
    // leaks (the aarch64 customize regression leaked all of them). The returned
    // diagnostic is owned by the caller here.
    defer std.testing.allocator.free(result.summary);
    try std.testing.expectEqual(api.ExitStatus.transaction, result.exit_status);
    // The bare "FileNotFound" of the incident is replaced by a structured,
    // credential-free diagnostic that names the failing stage and dpkg phase.
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "transaction failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "code=") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "phase=") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "package=removable") != null);
}

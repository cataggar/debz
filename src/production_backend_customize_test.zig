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
//! The same build later failed after dpkg had already succeeded, because
//! execution provenance described every refreshed repository while the exact
//! lock only records the ones a package came from. That binding is covered here
//! too, since it only breaks when the sources out-number the closure.
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

// The baseline for the provenance test: every installed package has to have a
// repository origin before an exact lock can be resolved at all.
const repository_status =
    \\Package: hello
    \\Status: install ok installed
    \\Priority: optional
    \\Architecture: amd64
    \\Version: 1.0-1
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

test "a root with no dpkg database has nothing installed" {
    var staged = try stageRoot();
    defer staged.deinit();

    // A root being bootstrapped has no dpkg database yet. Reproduce that by
    // removing the staged one: this is the state vmiz's fresh-root build leaves
    // behind after it wipes the exported cloud root, and resolving against it
    // failed with a bare FileNotFound that named nothing.
    try staged.directory.dir.deleteFile(std.testing.io, "root/var/lib/dpkg/status");

    var process = FailingProcess{};
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const result = try api.execute(std.testing.allocator, .{
        .operation = .list_installed,
        .packages = &.{},
        .options = staged.options(&source_paths, &keyring_paths),
    }, backend.interface());
    defer std.testing.allocator.free(result.items);
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    // Nothing installed, rather than an error about the absence.
    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "a root that does not exist is still an error, not an empty one" {
    var staged = try stageRoot();
    defer staged.deinit();

    // The absent database is only a fact about packages when the root it would
    // live in is really there. Deleting the root entirely is a misconfigured
    // path, and reporting that as "nothing installed" would let a typo plan a
    // full install into somewhere that does not exist.
    try staged.directory.dir.deleteTree(std.testing.io, "root");

    var process = FailingProcess{};
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const result = try api.execute(std.testing.allocator, .{
        .operation = .list_installed,
        .packages = &.{},
        .options = staged.options(&source_paths, &keyring_paths),
    }, backend.interface());
    // Refused as a configuration problem rather than answered as an empty root.
    // This summary is the static error name, not an allocated diagnostic, so
    // unlike the transaction-failure path below there is nothing to free.
    try std.testing.expectEqual(api.ExitStatus.usage, result.exit_status);
    try std.testing.expectEqual(@as(usize, 0), result.items.len);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "FileNotFound") != null);
}

// Stages a second authenticated repository that resolves and refreshes exactly
// like the first one but never wins a package, and replaces the staged status
// with a baseline the repositories can actually account for. Ubuntu's real
// sources fan out into a repository per component and pocket, so a build
// routinely refreshes many more repositories than its closure draws from.
fn addSpareRepository(staged: Fixture) !void {
    const root = std.fs.path.dirname(staged.keyring_path).?;
    try staged.directory.dir.createDirPath(std.testing.io, "spare/dists/stable/main/binary-amd64");
    try staged.directory.dir.writeFile(std.testing.io, .{
        .sub_path = "spare/dists/stable/InRelease",
        .data = &fixture.repository_in_release,
    });
    try staged.directory.dir.writeFile(std.testing.io, .{
        .sub_path = "spare/dists/stable/main/binary-amd64/Packages",
        .data = &fixture.repository_packages,
    });
    try staged.directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = repository_status,
    });
    const source_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "deb [arch=amd64 signed-by={s}] file://{s}/repo stable main\n" ++
            "deb [arch=amd64 signed-by={s}] file://{s}/spare stable main\n",
        .{ staged.keyring_path, root, staged.keyring_path, root },
    );
    defer std.testing.allocator.free(source_bytes);
    try staged.directory.dir.writeFile(std.testing.io, .{
        .sub_path = "sources.list",
        .data = source_bytes,
    });
}

test "provenance repositories follow the lock, not every refreshed repository" {
    var staged = try stageRoot();
    defer staged.deinit();
    try addSpareRepository(staged);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const root = std.fs.path.dirname(staged.keyring_path).?;
    const lock_path = try std.fmt.allocPrint(arena.allocator(), "{s}/exact-lock.json", .{root});
    var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};

    // Resolve the lock the way vmiz does, as a separate non-mutating pass.
    var resolve_options = staged.options(&source_paths, &keyring_paths);
    resolve_options.lock_output_path = lock_path;
    const resolved = try api.execute(arena.allocator(), .{
        .operation = .plan,
        .packages = &.{},
        .options = resolve_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, resolved.exit_status);

    // Replay that lock through a mutating pass, which is the only path that
    // writes execution provenance. The exact lock refuses to record a
    // repository no package came from, so a build whose sources out-number its
    // closure produced more repository evidence than the lock held, and
    // provenance rejected its own transaction with RepositoryEvidenceMismatch
    // after dpkg had already succeeded.
    var replay_options = staged.options(&source_paths, &keyring_paths);
    replay_options.lock_input_path = lock_path;
    const replayed = try api.execute(arena.allocator(), .{
        .operation = .upgrade_all,
        .packages = &.{},
        .options = replay_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, replayed.exit_status);

    const provenance_bytes = try staged.directory.dir.readFileAlloc(
        std.testing.io,
        "state/transaction-result.json",
        std.testing.allocator,
        .limited(debz.transaction_provenance.maximum_document_bytes),
    );
    defer std.testing.allocator.free(provenance_bytes);
    var validated = try debz.transaction_provenance.validateDocument(
        std.testing.allocator,
        provenance_bytes,
        debz.transaction_provenance.maximum_document_bytes,
    );
    defer validated.deinit();
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        provenance_bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();
    // Both repositories authenticated and refreshed; only the one the closure
    // drew from is evidence, so the record stays bound one-to-one to the lock.
    try std.testing.expectEqual(
        @as(usize, 1),
        parsed.value.object.get("repositories").?.array.items.len,
    );
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

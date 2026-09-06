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
    invocations: usize = 0,

    fn interface(self: *SuccessfulProcess) transaction_executor.ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(context: *anyopaque, invocation: transaction_executor.Invocation) !transaction_executor.ProcessResult {
        const self: *SuccessfulProcess = @ptrCast(@alignCast(context));
        self.invocations += 1;
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

// Reproduces every way the very first dpkg command can end without the
// executor being able to append its provenance. In all of them `dpkg` was
// already handed control, so the report is indistinguishable from an untouched
// root through a command count alone.
const UnfinishedFirstCommand = struct {
    error_value: anyerror,
    invocations: usize = 0,

    fn interface(self: *UnfinishedFirstCommand) transaction_executor.ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(
        context: *anyopaque,
        _: transaction_executor.Invocation,
    ) !transaction_executor.ProcessResult {
        const self: *UnfinishedFirstCommand = @ptrCast(@alignCast(context));
        self.invocations += 1;
        return self.error_value;
    }
};

// Reads the durable root-operation record straight out of the selected root,
// exactly as the next debz invocation would.
fn readRootAttempt(install_root: []const u8) !?debz.root_operation.OwnedRecord {
    var owned = try debz.root_fs.openAbsoluteRoot(std.testing.io, install_root);
    defer owned.close();
    const store = debz.root_operation.Store.init(owned.root);
    return store.read(std.testing.allocator);
}

test "an unfinished first dpkg command leaves recovery evidence instead of clearing the root" {
    // The executor records a command only after it completed, so a first
    // command that timed out or failed to spawn reports zero commands while
    // dpkg may already have unpacked, configured, or removed something.
    // Resolving the root-operation bridge from that count cleared the active
    // intent and let the next mutation run on a root nobody could prove was
    // intact.
    for ([_]anyerror{ error.Timeout, error.AccessDenied }) |injected| {
        var staged = try stageRoot();
        defer staged.deinit();

        var process = UnfinishedFirstCommand{ .error_value = injected };
        var backend: debz.ProductionBackend = .{
            .io = std.testing.io,
            .now_unix = fixture.created + 30,
            .process_runner = process.interface(),
        };
        const source_paths = [_][]const u8{staged.source_path};
        const keyring_paths = [_][]const u8{staged.keyring_path};
        const request: api.Request = .{
            .operation = .remove,
            .packages = &.{"removable"},
            .options = staged.options(&source_paths, &keyring_paths),
        };
        const result = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        defer std.testing.allocator.free(result.summary);
        try std.testing.expectEqual(api.ExitStatus.transaction, result.exit_status);
        // dpkg really was started, which is precisely what the command count
        // cannot say.
        try std.testing.expectEqual(@as(usize, 1), process.invocations);

        var record = (try readRootAttempt(staged.install_root)).?;
        defer record.deinit();
        // The attempt is durable recovery evidence, not an abandoned one.
        try std.testing.expectEqual(
            debz.root_operation.State.recovery_required,
            record.record.state,
        );
        try std.testing.expect(record.record.mutation_started);
        try std.testing.expect(record.record.state.blocksMutation());

        // A second mutation of the same root is refused until it is recovered.
        const blocked = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        try std.testing.expectEqual(api.ExitStatus.recovery, blocked.exit_status);
        try std.testing.expect(std.mem.indexOf(
            u8,
            blocked.summary,
            "requires recovery",
        ) != null);

        // Non-mutating operations stay usable while the root is blocked. The
        // query path returns caller-owned, arena-managed items exactly like
        // the embedder uses them.
        var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer query_arena.deinit();
        var query_options = staged.options(&source_paths, &keyring_paths);
        query_options.lock_wait_ms = 0;
        const listed = try api.execute(query_arena.allocator(), .{
            .operation = .list_installed,
            .packages = &.{},
            .options = query_options,
        }, backend.interface());
        try std.testing.expectEqual(api.ExitStatus.success, listed.exit_status);
    }
}

// Holds one of the executor's own target locks so the transaction fails during
// pre-spawn validation, which is the only shape of failure that really proves
// no command was ever handed to dpkg.
test "a transaction that fails before any spawn clears the root attempt" {
    var staged = try stageRoot();
    defer staged.deinit();

    var manager = transaction_executor.SystemLockManager{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const lock_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/var/lib/debz/transaction.lock",
        .{staged.install_root},
    );
    defer std.testing.allocator.free(lock_path);
    const locks = manager.interface();
    // Contend with the executor's first target lock so the transaction fails
    // in pre-spawn validation without ever reaching a dpkg invocation.
    var token: ?transaction_executor.LockToken = try locks.acquire(lock_path, 1_000);
    defer if (token) |value| locks.release(value);

    var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    var options = staged.options(&source_paths, &keyring_paths);
    options.lock_wait_ms = 25;
    const request: api.Request = .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = options,
    };
    const result = try api.execute(std.testing.allocator, request, backend.interface());
    defer std.testing.allocator.free(result.summary);
    try std.testing.expectEqual(api.ExitStatus.transaction, result.exit_status);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "code=lock_timeout") != null);
    try std.testing.expectEqual(@as(usize, 0), process.invocations);

    // Nothing was handed to dpkg, so the root is released rather than blocked.
    try std.testing.expect((try readRootAttempt(staged.install_root)) == null);

    locks.release(token.?);
    token = null;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const retried = try api.execute(arena.allocator(), request, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, retried.exit_status);
    try std.testing.expect((try readRootAttempt(staged.install_root)) == null);
}

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

fn writeBlockingRootAttempt(
    dir: std.Io.Dir,
    install_root: []const u8,
    operation: debz.root_operation.Operation,
    state: debz.root_operation.State,
) !void {
    const root: debz.root_fs.Root = .init(std.testing.io, dir);
    const store = debz.root_operation.Store.init(root);
    try store.ensureNamespace();
    var record = try debz.root_operation.create(std.testing.allocator, .{
        .attempt_id = @splat(0x5a),
        .generation = 1,
        .install_root = install_root,
        .backend = .legacy_dpkg,
        .operation = operation,
        .state = state,
        .phase = if (state == .mutation_pending) .mutation else .mutation,
        .step = 3,
        .mutation_started = state != .mutation_pending,
        .outcome = .pending,
        .provenance = .pending,
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_000,
    });
    defer record.deinit();
    try store.writeAtomic(std.testing.allocator, record.record);
}

test "production package mutation is refused while a repository attempt is unresolved" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.createDirPath(std.testing.io, "state");
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "keyring.gpg", .data = "" });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "",
    });

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const base = real_buffer[0..real_length];
    const install_root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{base});
    defer std.testing.allocator.free(install_root);
    const keyring_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/keyring.gpg", .{base});
    defer std.testing.allocator.free(keyring_path);
    const source_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sources.list", .{base});
    defer std.testing.allocator.free(source_path);
    const cache_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/cache", .{base});
    defer std.testing.allocator.free(cache_path);
    const state_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state", .{base});
    defer std.testing.allocator.free(state_path);
    const source_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "deb [arch=amd64 signed-by={s}] file://{s}/repo stable main\n",
        .{ keyring_path, base },
    );
    defer std.testing.allocator.free(source_bytes);
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "sources.list",
        .data = source_bytes,
    });

    var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    // A repository bootstrap that mutated this root and never completed is the
    // same durable evidence a package transaction would have left.
    try writeBlockingRootAttempt(
        root_dir,
        install_root,
        .{ .repository_bootstrap = .add },
        .mutating,
    );

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var backend: debz.ProductionBackend = .{ .io = std.testing.io, .now_unix = 1_700_000_000 };
    const options: api.CommonOptions = .{
        .install_root = install_root,
        .source_paths = &.{source_path},
        .keyring_paths = &.{keyring_path},
        .cache_path = cache_path,
        .state_path = state_path,
        .architecture = "amd64",
        .assume_yes = true,
    };
    const blocked = try api.execute(arena.allocator(), .{
        .operation = .install,
        .packages = &.{"anything"},
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.recovery, blocked.exit_status);
    try std.testing.expectEqual(
        api.ErrorId.root_operation_recovery_required,
        blocked.diagnostics[0].id,
    );

    // Non-mutating operations stay usable while the root attempt is unresolved.
    const listed = try api.execute(arena.allocator(), .{
        .operation = .list_installed,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, listed.exit_status);
}

test "production mutation clears its root attempt and leaves no active intent" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
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
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "keyring.gpg",
        .data = &fixture.keyring,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data =
        \\Package: removable
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1
        \\
        ,
    });

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const base = real_buffer[0..real_length];
    const source_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sources.list", .{base});
    defer std.testing.allocator.free(source_path);
    const keyring_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/keyring.gpg", .{base});
    defer std.testing.allocator.free(keyring_path);
    const repository_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/repo", .{base});
    defer std.testing.allocator.free(repository_path);
    const source_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "deb [arch=amd64 signed-by={s}] file://{s} stable main\n",
        .{ keyring_path, repository_path },
    );
    defer std.testing.allocator.free(source_bytes);
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "sources.list",
        .data = source_bytes,
    });
    const install_root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{base});
    defer std.testing.allocator.free(install_root);
    const cache_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/cache", .{base});
    defer std.testing.allocator.free(cache_path);
    const state_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state", .{base});
    defer std.testing.allocator.free(state_path);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var fake = SuccessfulProcess{ .io = std.testing.io, .dir = directory.dir };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = fake.interface(),
    };
    const result = try api.execute(arena.allocator(), .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = .{
            .install_root = install_root,
            .source_paths = &.{source_path},
            .keyring_paths = &.{keyring_path},
            .cache_path = cache_path,
            .state_path = state_path,
            .architecture = "amd64",
            .assume_yes = true,
        },
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);

    var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    const root: debz.root_fs.Root = .init(std.testing.io, root_dir);
    const store = debz.root_operation.Store.init(root);
    // Provenance was published and the active intent was cleared, so the next
    // mutation is free to start.
    try std.testing.expect((try store.read(std.testing.allocator)) == null);
    const lock_metadata = try root.metadata(try debz.root_fs.Path.init(debz.root_operation.lock_path));
    try std.testing.expect(lock_metadata.isRegularFile());
}

test "production recovery on an untouched root never strands the root attempt" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.createDirPath(std.testing.io, "state");
    try directory.dir.createDirPath(std.testing.io, "cache");
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "keyring.gpg", .data = "" });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "",
    });

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const base = real_buffer[0..real_length];
    const install_root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{base});
    defer std.testing.allocator.free(install_root);
    const keyring_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/keyring.gpg", .{base});
    defer std.testing.allocator.free(keyring_path);
    const source_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sources.list", .{base});
    defer std.testing.allocator.free(source_path);
    const cache_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/cache", .{base});
    defer std.testing.allocator.free(cache_path);
    const state_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state", .{base});
    defer std.testing.allocator.free(state_path);
    const source_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "deb [arch=amd64 signed-by={s}] file://{s}/missing-repo stable main\n",
        .{ keyring_path, base },
    );
    defer std.testing.allocator.free(source_bytes);
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "sources.list",
        .data = source_bytes,
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var backend: debz.ProductionBackend = .{ .io = std.testing.io, .now_unix = 1_700_000_000 };
    const options: api.CommonOptions = .{
        .install_root = install_root,
        .source_paths = &.{source_path},
        .keyring_paths = &.{keyring_path},
        .cache_path = cache_path,
        .state_path = state_path,
        .architecture = "amd64",
        .assume_yes = true,
    };
    // `recover` reserves the root before it discovers there is nothing to
    // recover. The attempt is pre-mutation, so giving up must release it.
    const recovered = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expect(recovered.exit_status != api.ExitStatus.success);

    var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    const store = debz.root_operation.Store.init(.init(std.testing.io, root_dir));
    try std.testing.expect((try store.read(std.testing.allocator)) == null);

    // The root is still usable: the next mutation fails for its own reason,
    // never because a stranded attempt blocks it.
    const next = try api.execute(arena.allocator(), .{
        .operation = .install,
        .packages = &.{"anything"},
        .options = options,
    }, backend.interface());
    try std.testing.expect(next.diagnostics[0].id != api.ErrorId.root_operation_recovery_required);
    try std.testing.expect(next.diagnostics[0].id != api.ErrorId.root_operation_conflict);
    try std.testing.expect((try store.read(std.testing.allocator)) == null);
}

test "production recovery adopts durable mutation evidence instead of failing closed" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
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
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "keyring.gpg",
        .data = &fixture.keyring,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = removable_status,
    });

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const base = real_buffer[0..real_length];
    const install_root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{base});
    defer std.testing.allocator.free(install_root);
    const keyring_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/keyring.gpg", .{base});
    defer std.testing.allocator.free(keyring_path);
    const source_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sources.list", .{base});
    defer std.testing.allocator.free(source_path);
    const cache_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/cache", .{base});
    defer std.testing.allocator.free(cache_path);
    const state_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state", .{base});
    defer std.testing.allocator.free(state_path);
    const source_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "deb [arch=amd64 signed-by={s}] file://{s}/repo stable main\n",
        .{ keyring_path, base },
    );
    defer std.testing.allocator.free(source_bytes);
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "sources.list",
        .data = source_bytes,
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var backend: debz.ProductionBackend = .{ .io = std.testing.io, .now_unix = fixture.created + 30 };
    const options: api.CommonOptions = .{
        .install_root = install_root,
        .source_paths = &.{source_path},
        .keyring_paths = &.{keyring_path},
        .cache_path = cache_path,
        .state_path = state_path,
        .architecture = "amd64",
        .assume_yes = true,
    };
    // Populate the metadata cache so the cache-only recovery refresh succeeds
    // and the flow reaches the executor bridge.
    const refreshed = try api.execute(arena.allocator(), .{
        .operation = .refresh,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, refreshed.exit_status);

    var state_dir = try directory.dir.openDir(std.testing.io, "state", .{ .iterate = true });
    defer state_dir.close(std.testing.io);
    try state_dir.writeFile(std.testing.io, .{
        .sub_path = "recovery-request.json",
        .data = "{\"operation\":\"remove\",\"packages\":[\"removable\"]," ++
            "\"recommends\":false,\"allow_downgrade\":false," ++
            "\"repository_policy\":\"strict_priority\",\"conffile\":\"unspecified\"," ++
            "\"force\":[],\"lock_wait_ms\":1000}\n",
    });

    var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    try writeBlockingRootAttempt(
        root_dir,
        install_root,
        .{ .package_transaction = .install },
        .mutating,
    );

    const store = debz.root_operation.Store.init(.init(std.testing.io, root_dir));
    // A plain mutation is refused while the evidence stands.
    const blocked = try api.execute(arena.allocator(), .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(
        api.ErrorId.root_operation_recovery_required,
        blocked.diagnostics[0].id,
    );

    // Recovery is the one intent allowed to adopt that evidence. It must reach
    // the executor instead of failing closed on its own record.
    const recovered = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    // Recovery must reach the executor, which then reports the missing
    // journal. Anything root-operation-shaped here means the coordinator
    // refused its own adopted evidence.
    try std.testing.expectEqual(api.ErrorId.recovery_failed, recovered.diagnostics[0].id);
    try std.testing.expect(
        recovered.diagnostics[0].id != api.ErrorId.root_operation_recovery_required,
    );
    try std.testing.expect(recovered.diagnostics[0].id != api.ErrorId.internal_error);
    try std.testing.expect(
        recovered.diagnostics[0].id != api.ErrorId.root_operation_conflict,
    );

    // No journal exists, so recovery fails and the durable evidence survives.
    var observed = (try store.read(std.testing.allocator)).?;
    defer observed.deinit();
    try std.testing.expect(observed.record.mutation_started);
    try std.testing.expect(observed.record.state.blocksMutation());
}

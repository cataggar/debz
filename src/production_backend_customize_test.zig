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

// A recovery adopts whatever the root already carries, so a record an earlier
// run left at the executor bridge becomes this run's record. That run handed
// control to dpkg and never came back; nothing this run observes is evidence
// about it. A recovery that finds no journal, or cannot decode the one it
// finds, reports `not_started` with no commands — the exact shape of a report
// that proves nothing ran — and resolving the inherited bridge from it cleared
// the only durable evidence blocking the root.
test "recovery never discharges a bridge inherited from an earlier run" {
    const Journal = enum { missing, corrupt };
    for (std.enums.values(Journal)) |journal| {
        var staged = try stageRoot();
        defer staged.deinit();
        errdefer std.debug.print("journal: {t}\n", .{journal});

        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var backend: debz.ProductionBackend = .{
            .io = std.testing.io,
            .now_unix = fixture.created + 30,
        };
        const source_paths = [_][]const u8{staged.source_path};
        const keyring_paths = [_][]const u8{staged.keyring_path};
        const options = staged.options(&source_paths, &keyring_paths);

        // The recovery refresh is cache-only, so the cache has to exist before
        // the flow can reach the executor at all.
        const refreshed = try api.execute(arena.allocator(), .{
            .operation = .refresh,
            .options = options,
        }, backend.interface());
        try std.testing.expectEqual(api.ExitStatus.success, refreshed.exit_status);

        try staged.directory.dir.writeFile(std.testing.io, .{
            .sub_path = "state/recovery-request.json",
            .data = "{\"operation\":\"remove\",\"packages\":[\"removable\"]," ++
                "\"recommends\":false,\"allow_downgrade\":false," ++
                "\"repository_policy\":\"strict_priority\",\"conffile\":\"unspecified\"," ++
                "\"force\":[],\"lock_wait_ms\":1000}\n",
        });
        // A journal that exists and cannot be decoded is durable evidence that
        // a transaction already reached this root, which is precisely what the
        // recovery report cannot say once decoding failed.
        if (journal == .corrupt) try staged.directory.dir.writeFile(std.testing.io, .{
            .sub_path = "state/transaction.journal",
            .data = "{\"schema\":",
        });

        var root_dir = try staged.directory.dir.openDir(
            std.testing.io,
            "root",
            .{ .iterate = true },
        );
        defer root_dir.close(std.testing.io);
        // The interrupted run stopped at the hand-over with no witness.
        try writeBlockingRootAttempt(
            root_dir,
            staged.install_root,
            .{ .package_transaction = .install },
            .mutation_pending,
        );

        const recovered = try api.execute(arena.allocator(), .{
            .operation = .recover,
            .options = options,
        }, backend.interface());
        // The recovery reached the executor and failed on the journal rather
        // than being refused by its own adopted record.
        try std.testing.expectEqual(api.ErrorId.recovery_failed, recovered.diagnostics[0].id);

        // The inherited hand-over is still unresolved: the record blocks, it
        // carries mutation evidence, and its provenance obligation was not
        // waived by completing it as abandoned.
        var observed = (try readRootAttempt(staged.install_root)).?;
        defer observed.deinit();
        try std.testing.expectEqual(
            debz.root_operation.State.recovery_required,
            observed.record.state,
        );
        try std.testing.expect(observed.record.state.blocksMutation());
        try std.testing.expect(observed.record.mutation_started);
        try std.testing.expectEqual(
            debz.root_operation.ProvenanceState.pending,
            observed.record.provenance,
        );
        try std.testing.expectEqual(
            debz.root_operation.Outcome.pending,
            observed.record.outcome,
        );
        try std.testing.expect(!observed.record.clearable());

        // The next mutation of this root is still refused.
        const blocked = try api.execute(arena.allocator(), .{
            .operation = .remove,
            .packages = &.{"removable"},
            .options = options,
        }, backend.interface());
        try std.testing.expectEqual(api.ExitStatus.recovery, blocked.exit_status);
        try std.testing.expectEqual(
            api.ErrorId.root_operation_recovery_required,
            blocked.diagnostics[0].id,
        );
    }
}

// The window between a product transaction's terminal `completed` record and
// its cleared active intent is the one part of a mutation a crash can leave
// blocking a root that is otherwise healthy. The transaction is over — dpkg
// finished, the executor archived its journal, and the record says so — but
// the record still owes provenance, so every later mutation is refused.
//
// Recovery used to run the command-oriented executor first, which asked the
// archived journal about a plan it was never written for and failed. The
// failure could not discharge the obligation, so the root stayed blocked
// forever and only deleting the record by hand brought it back. These tests
// drive each crash and failure point in that window through the public product
// API and require recovery to publish the provenance it owes, explain what the
// crash interrupted, and clear the intent — or to stay blocked with a
// diagnostic that names the document to inspect.

// Reproduces a process death at one durable completion boundary.
const CrashAt = struct {
    point: debz.ProductCompletionPoint,
    hits: usize = 0,

    fn interface(self: *CrashAt) debz.ProductCompletionCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, point: debz.ProductCompletionPoint) !void {
        const self: *CrashAt = @ptrCast(@alignCast(context));
        if (point != self.point) return;
        self.hits += 1;
        return error.SimulatedCrash;
    }
};

fn readCompletionStatement(
    install_root: []const u8,
) !?debz.root_operation_completion.OwnedDocument {
    var owned = try debz.root_fs.openAbsoluteRoot(std.testing.io, install_root);
    defer owned.close();
    const store = debz.root_operation_completion.Store.init(owned.root);
    return store.read(std.testing.allocator);
}

// Publishes the exact durable record a crash inside the completion window
// leaves behind: the attempt is over and its outcome is known, but the
// provenance it owes was never published.
// `recorded_root` is what the record claims about the root it belongs to; `dir`
// is the root it is published into. Passing a different spelling reproduces the
// record a moved or copied root leaves behind.
fn writeOwedProvenanceAttempt(
    dir: std.Io.Dir,
    recorded_root: []const u8,
    operation: debz.root_operation.Operation,
) !void {
    const root: debz.root_fs.Root = .init(std.testing.io, dir);
    const store = debz.root_operation.Store.init(root);
    try store.ensureNamespace();
    var record = try debz.root_operation.create(std.testing.allocator, .{
        .attempt_id = @splat(0x5b),
        .generation = 4,
        .install_root = recorded_root,
        .backend = .legacy_dpkg,
        .operation = operation,
        .state = .completed,
        .phase = .provenance,
        .step = 5,
        .mutation_started = true,
        .outcome = .succeeded,
        .provenance = .pending,
        .evidence = .{ .plan_sha256 = @splat(0x33) },
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_000,
    });
    defer record.deinit();
    try store.writeAtomic(std.testing.allocator, record.record);
}

// Turns the recovery intent into a directory once dpkg has run, so removing it
// fails exactly the way a damaged or read-only state directory does — after
// the completed record is already durable.
const IntentBlockingProcess = struct {
    io: std.Io,
    dir: std.Io.Dir,
    invocations: usize = 0,

    fn interface(self: *IntentBlockingProcess) transaction_executor.ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(
        context: *anyopaque,
        invocation: transaction_executor.Invocation,
    ) !transaction_executor.ProcessResult {
        const self: *IntentBlockingProcess = @ptrCast(@alignCast(context));
        self.invocations += 1;
        if (invocation.phase == .remove) {
            try self.dir.writeFile(self.io, .{
                .sub_path = "root/var/lib/dpkg/status",
                .data = "",
            });
            self.dir.deleteFile(self.io, "state/recovery-request.json") catch {};
            try self.dir.createDirPath(self.io, "state/recovery-request.json");
        }
        return .{ .termination = .{ .exited = 0 } };
    }
};

// A canonical, digest-consistent transaction result that belongs to some other
// transaction. It is exactly what an unrelated earlier run leaves at the
// product provenance path, and it must never be accepted as this attempt's
// detailed provenance.
fn writeForeignTransactionResult(staged: Fixture) !void {
    var owned = try debz.transaction_provenance.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(0xa1),
        .solver_policy_sha256 = @splat(0xa2),
        .executor_policy_sha256 = @splat(0xa3),
        .plan_sha256 = @splat(0xa4),
        .lock_sha256 = @splat(0xa5),
        .repositories = &.{},
        .packages = &.{},
        .commands = &.{},
        .journal_steps = &.{},
        .final_verification = .{
            .status = .exact_match,
            .installed_state_sha256 = @splat(0xa6),
            .package_origins_sha256 = @splat(0xa7),
            .detail = "unrelated transaction",
        },
        .outcome = .succeeded,
    });
    defer owned.deinit();
    const bytes = try owned.result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try staged.directory.dir.writeFile(std.testing.io, .{
        .sub_path = "state/transaction-result.json",
        .data = bytes,
    });
}

test "recovery discharges a completion interrupted before its provenance" {
    var staged = try stageRoot();
    defer staged.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var crash = CrashAt{ .point = .after_completed_record };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
        .completion_crash = crash.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const options = staged.options(&source_paths, &keyring_paths);

    const interrupted = try api.execute(arena.allocator(), .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
    try std.testing.expectEqual(@as(usize, 1), crash.hits);
    try std.testing.expect(process.invocations != 0);

    // The transaction finished and said so; only its provenance is missing.
    var stranded = (try readRootAttempt(staged.install_root)).?;
    defer stranded.deinit();
    try std.testing.expectEqual(debz.root_operation.State.completed, stranded.record.state);
    try std.testing.expectEqual(
        debz.root_operation.Outcome.succeeded,
        stranded.record.outcome,
    );
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.pending,
        stranded.record.provenance,
    );
    try std.testing.expect(!stranded.record.clearable());

    // The dead process cannot crash again.
    backend.completion_crash = null;

    // A second mutation is refused, and the diagnostic names the command that
    // resolves it instead of leaving the operator to delete a record.
    const blocked = try api.execute(arena.allocator(), .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.recovery, blocked.exit_status);
    try std.testing.expectEqual(
        api.ErrorId.root_operation_recovery_required,
        blocked.diagnostics[0].id,
    );
    try std.testing.expect(std.mem.indexOf(u8, blocked.summary, "debz recover") != null);

    // Recovery discharges the obligation without asking dpkg to do anything
    // again: the mutation is over and was durably witnessed.
    const before_recovery = process.invocations;
    const recovered = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
    try std.testing.expect(recovered.changed);
    try std.testing.expectEqual(before_recovery, process.invocations);
    try std.testing.expect(std.mem.indexOf(
        u8,
        recovered.summary,
        "detailed transaction provenance was interrupted",
    ) != null);
    try std.testing.expectEqual(@as(usize, 1), recovered.items.len);
    try std.testing.expect(std.mem.indexOf(
        u8,
        recovered.items[0].detail.?,
        "transaction_provenance=unavailable",
    ) != null);
    // The recovery intent the crashed run never removed described a
    // transaction that is now definitively over.
    try std.testing.expect(std.mem.indexOf(
        u8,
        recovered.items[0].detail.?,
        "recovery_intent=removed",
    ) != null);
    try std.testing.expectError(
        error.FileNotFound,
        staged.directory.dir.statFile(std.testing.io, "state/recovery-request.json", .{}),
    );

    // The published statement says exactly what was witnessed and what the
    // crash window interrupted; nothing about the transaction is invented.
    var statement = (try readCompletionStatement(staged.install_root)).?;
    defer statement.deinit();
    try std.testing.expect(statement.document.bindsRecord(stranded.record));
    try std.testing.expectEqual(
        debz.root_operation_completion.TransactionProvenanceStatus.unavailable,
        statement.document.transaction_provenance.status,
    );
    try std.testing.expectEqual(
        debz.root_operation_completion.JournalStatus.archived,
        statement.document.journal.status,
    );
    try std.testing.expectEqual(
        debz.root_operation.Outcome.succeeded,
        statement.document.outcome,
    );
    try std.testing.expectEqualStrings("recover", statement.document.discharge.operation);
    try std.testing.expect(!std.mem.eql(
        u8,
        &statement.document.request_sha256,
        &statement.document.discharge.request_sha256,
    ));

    // The active intent is gone, so the root is usable again.
    try std.testing.expect((try readRootAttempt(staged.install_root)) == null);
    const unblocked = try api.execute(arena.allocator(), .{
        .operation = .upgrade_all,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, unblocked.exit_status);

    // Recovery is idempotent: nothing is owed the second time, and the
    // statement it published is left exactly as it was.
    const again = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expect(again.exit_status != api.ExitStatus.internal);
    var republished = (try readCompletionStatement(staged.install_root)).?;
    defer republished.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &statement.document.digest_sha256,
        &republished.document.digest_sha256,
    );
}

test "recovery verifies transaction provenance that survived the crash window" {
    var staged = try stageRoot();
    defer staged.deinit();
    // An exact lock can only be resolved when every installed package has a
    // repository origin, and only a locked transaction publishes the detailed
    // provenance document this test is about.
    try staged.directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = repository_status,
    });
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const base = std.fs.path.dirname(staged.keyring_path).?;
    const lock_path = try std.fmt.allocPrint(arena.allocator(), "{s}/exact-lock.json", .{base});
    var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};

    var resolve_options = staged.options(&source_paths, &keyring_paths);
    resolve_options.lock_output_path = lock_path;
    const resolved = try api.execute(arena.allocator(), .{
        .operation = .plan,
        .options = resolve_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, resolved.exit_status);

    var locked_options = staged.options(&source_paths, &keyring_paths);
    locked_options.lock_input_path = lock_path;

    // The crash lands after the detailed provenance document is durable but
    // before the record is allowed to bind it.
    var crash = CrashAt{ .point = .after_transaction_provenance };
    backend.completion_crash = crash.interface();
    const interrupted = try api.execute(arena.allocator(), .{
        .operation = .upgrade_all,
        .options = locked_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
    try std.testing.expectEqual(@as(usize, 1), crash.hits);
    backend.completion_crash = null;

    var stranded = (try readRootAttempt(staged.install_root)).?;
    defer stranded.deinit();
    try std.testing.expectEqual(debz.root_operation.State.completed, stranded.record.state);
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.pending,
        stranded.record.provenance,
    );

    const published = try staged.directory.dir.readFileAlloc(
        std.testing.io,
        "state/transaction-result.json",
        std.testing.allocator,
        .limited(debz.transaction_provenance.maximum_document_bytes),
    );
    defer std.testing.allocator.free(published);
    const binding = try debz.transaction_provenance.readBinding(
        std.testing.allocator,
        published,
        debz.transaction_provenance.maximum_document_bytes,
    );

    // A document that belongs to a different transaction is never adopted as
    // this attempt's provenance, and the record survives the refusal intact.
    try writeForeignTransactionResult(staged);
    const refused = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = locked_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.recovery, refused.exit_status);
    try std.testing.expectEqual(
        api.ErrorId.root_operation_recovery_required,
        refused.diagnostics[0].id,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        refused.summary,
        "does not describe the interrupted transaction",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, refused.summary, "transaction-result.json") != null);
    try std.testing.expect((try readCompletionStatement(staged.install_root)) == null);
    var still_owed = (try readRootAttempt(staged.install_root)).?;
    defer still_owed.deinit();
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.pending,
        still_owed.record.provenance,
    );

    // With the attempt's own document back in place, recovery verifies it and
    // binds it into the statement rather than claiming it was lost.
    try staged.directory.dir.writeFile(std.testing.io, .{
        .sub_path = "state/transaction-result.json",
        .data = published,
    });
    const recovered = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = locked_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
    try std.testing.expect(std.mem.indexOf(
        u8,
        recovered.summary,
        "published transaction provenance verified",
    ) != null);

    var statement = (try readCompletionStatement(staged.install_root)).?;
    defer statement.deinit();
    try std.testing.expectEqual(
        debz.root_operation_completion.TransactionProvenanceStatus.already_present,
        statement.document.transaction_provenance.status,
    );
    try std.testing.expectEqualSlices(
        u8,
        &binding.digest_sha256,
        &statement.document.transaction_provenance.document_sha256.?,
    );
    try std.testing.expectEqualStrings(
        debz.transaction_provenance.schema_id,
        statement.document.transaction_provenance.schema,
    );
    try std.testing.expect(statement.document.exact_lock != null);
    try std.testing.expect((try readRootAttempt(staged.install_root)) == null);
}

test "recovery refuses unreadable transaction provenance and never deletes it" {
    const Damage = enum { corrupt, symbolic_link, directory };
    for (std.enums.values(Damage)) |damage| {
        var staged = try stageRoot();
        defer staged.deinit();
        errdefer std.debug.print("damage: {t}\n", .{damage});
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
        var crash = CrashAt{ .point = .after_completed_record };
        var backend: debz.ProductionBackend = .{
            .io = std.testing.io,
            .now_unix = fixture.created + 30,
            .process_runner = process.interface(),
            .completion_crash = crash.interface(),
        };
        const source_paths = [_][]const u8{staged.source_path};
        const keyring_paths = [_][]const u8{staged.keyring_path};
        const options = staged.options(&source_paths, &keyring_paths);
        const interrupted = try api.execute(arena.allocator(), .{
            .operation = .remove,
            .packages = &.{"removable"},
            .options = options,
        }, backend.interface());
        try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
        backend.completion_crash = null;

        switch (damage) {
            .corrupt => try staged.directory.dir.writeFile(std.testing.io, .{
                .sub_path = "state/transaction-result.json",
                .data = "{\"schema\":\"https://debz.dev/schema/transaction-result-v1\"",
            }),
            .symbolic_link => {
                try staged.directory.dir.writeFile(std.testing.io, .{
                    .sub_path = "state/elsewhere.json",
                    .data = "{}",
                });
                try staged.directory.dir.symLink(
                    std.testing.io,
                    "elsewhere.json",
                    "state/transaction-result.json",
                    .{},
                );
            },
            .directory => try staged.directory.dir.createDirPath(
                std.testing.io,
                "state/transaction-result.json",
            ),
        }

        const refused = try api.execute(arena.allocator(), .{
            .operation = .recover,
            .options = options,
        }, backend.interface());
        try std.testing.expectEqual(api.ExitStatus.recovery, refused.exit_status);
        try std.testing.expectEqual(
            api.ErrorId.root_operation_recovery_required,
            refused.diagnostics[0].id,
        );
        try std.testing.expect(std.mem.indexOf(
            u8,
            refused.summary,
            "inspect it before recovering this root",
        ) != null);

        // Nothing was published and nothing was cleared: the evidence at the
        // provenance path is left for an operator to look at.
        try std.testing.expect((try readCompletionStatement(staged.install_root)) == null);
        var owed = (try readRootAttempt(staged.install_root)).?;
        defer owed.deinit();
        try std.testing.expectEqual(
            debz.root_operation.ProvenanceState.pending,
            owed.record.provenance,
        );
        const blocked = try api.execute(arena.allocator(), .{
            .operation = .upgrade_all,
            .options = options,
        }, backend.interface());
        try std.testing.expectEqual(api.ExitStatus.recovery, blocked.exit_status);

        // Once the damaged document is gone the same command finishes the job,
        // so no debz-owned record ever has to be deleted by hand.
        switch (damage) {
            .corrupt, .symbolic_link => try staged.directory.dir.deleteFile(
                std.testing.io,
                "state/transaction-result.json",
            ),
            .directory => try staged.directory.dir.deleteTree(
                std.testing.io,
                "state/transaction-result.json",
            ),
        }
        const recovered = try api.execute(arena.allocator(), .{
            .operation = .recover,
            .options = options,
        }, backend.interface());
        try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
        try std.testing.expect((try readRootAttempt(staged.install_root)) == null);
        var published = (try readCompletionStatement(staged.install_root)).?;
        published.deinit();
    }
}

test "a completion that cannot delete its recovery intent is still recoverable" {
    var staged = try stageRoot();
    defer staged.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var process = IntentBlockingProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const options = staged.options(&source_paths, &keyring_paths);

    const interrupted = try api.execute(arena.allocator(), .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
    try std.testing.expect(process.invocations != 0);

    var stranded = (try readRootAttempt(staged.install_root)).?;
    defer stranded.deinit();
    try std.testing.expectEqual(debz.root_operation.State.completed, stranded.record.state);
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.pending,
        stranded.record.provenance,
    );

    const recovered = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
    try std.testing.expect((try readRootAttempt(staged.install_root)) == null);
    var statement = (try readCompletionStatement(staged.install_root)).?;
    defer statement.deinit();
    try std.testing.expect(statement.document.bindsRecord(stranded.record));
    // The intent still cannot be removed, and saying so is better than letting
    // a damaged state directory re-block a discharged root.
    try std.testing.expect(std.mem.indexOf(
        u8,
        recovered.items[0].detail.?,
        "recovery_intent=retained",
    ) != null);

    // The state directory the crashed run damaged is repaired by the operator;
    // the root itself was never left blocked.
    try staged.directory.dir.deleteTree(std.testing.io, "state/recovery-request.json");
    const unblocked = try api.execute(arena.allocator(), .{
        .operation = .upgrade_all,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, unblocked.exit_status);
}

test "a completion whose provenance publication fails is recoverable once the path is clear" {
    var staged = try stageRoot();
    defer staged.deinit();
    try staged.directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = repository_status,
    });
    // The publication renames its staged document onto this name, so a
    // directory there fails the write the way a full or broken filesystem
    // does — after the transaction has already completed.
    try staged.directory.dir.createDirPath(std.testing.io, "state/transaction-result.json");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const base = std.fs.path.dirname(staged.keyring_path).?;
    const lock_path = try std.fmt.allocPrint(arena.allocator(), "{s}/exact-lock.json", .{base});
    var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    var resolve_options = staged.options(&source_paths, &keyring_paths);
    resolve_options.lock_output_path = lock_path;
    const resolved = try api.execute(arena.allocator(), .{
        .operation = .plan,
        .options = resolve_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, resolved.exit_status);

    var locked_options = staged.options(&source_paths, &keyring_paths);
    locked_options.lock_input_path = lock_path;
    const interrupted = try api.execute(arena.allocator(), .{
        .operation = .upgrade_all,
        .options = locked_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);

    var stranded = (try readRootAttempt(staged.install_root)).?;
    defer stranded.deinit();
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.pending,
        stranded.record.provenance,
    );

    // The obstruction is still there, so recovery refuses rather than
    // pretending the attempt owes nothing.
    const refused = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = locked_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.recovery, refused.exit_status);
    var still_owed = (try readRootAttempt(staged.install_root)).?;
    still_owed.deinit();

    try staged.directory.dir.deleteTree(std.testing.io, "state/transaction-result.json");
    const recovered = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = locked_options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
    var statement = (try readCompletionStatement(staged.install_root)).?;
    defer statement.deinit();
    // The detailed document really was never published, and the statement says
    // exactly that instead of claiming it exists.
    try std.testing.expectEqual(
        debz.root_operation_completion.TransactionProvenanceStatus.unavailable,
        statement.document.transaction_provenance.status,
    );
    try std.testing.expect((try readRootAttempt(staged.install_root)) == null);
}

test "a crash between the completion statement and the record republishes the same statement" {
    var staged = try stageRoot();
    defer staged.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var crash = CrashAt{ .point = .after_completed_record };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
        .completion_crash = crash.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const options = staged.options(&source_paths, &keyring_paths);
    const interrupted = try api.execute(arena.allocator(), .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);

    // The recovery itself now dies between publishing the statement and
    // binding it to the record.
    var statement_crash = CrashAt{ .point = .after_owed_provenance_document };
    backend.completion_crash = statement_crash.interface();
    const half_done = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.internal, half_done.exit_status);
    try std.testing.expectEqual(@as(usize, 1), statement_crash.hits);
    var first = (try readCompletionStatement(staged.install_root)).?;
    defer first.deinit();
    var owed = (try readRootAttempt(staged.install_root)).?;
    defer owed.deinit();
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.pending,
        owed.record.provenance,
    );

    // Retrying converges on exactly the same statement and then finishes.
    backend.completion_crash = null;
    const recovered = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
    var second = (try readCompletionStatement(staged.install_root)).?;
    defer second.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &first.document.digest_sha256,
        &second.document.digest_sha256,
    );
    try std.testing.expect((try readRootAttempt(staged.install_root)) == null);
}

test "a crash after the provenance transition leaves a settled record, not a blocked root" {
    var staged = try stageRoot();
    defer staged.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var crash = CrashAt{ .point = .after_provenance_published };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
        .completion_crash = crash.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const options = staged.options(&source_paths, &keyring_paths);
    const interrupted = try api.execute(arena.allocator(), .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
    try std.testing.expectEqual(@as(usize, 1), crash.hits);
    backend.completion_crash = null;

    // The record is settled: its provenance is published, so it is proof of a
    // finished operation rather than an obligation.
    var settled = (try readRootAttempt(staged.install_root)).?;
    defer settled.deinit();
    try std.testing.expectEqual(debz.root_operation.State.completed, settled.record.state);
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.published,
        settled.record.provenance,
    );
    try std.testing.expect(settled.record.clearable());

    // The next mutation reclaims it instead of being refused, and leaves the
    // root with no active intent at all.
    const unblocked = try api.execute(arena.allocator(), .{
        .operation = .upgrade_all,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, unblocked.exit_status);
    try std.testing.expect((try readRootAttempt(staged.install_root)) == null);
}

test "product recovery never discharges a repository bootstrap's owed provenance" {
    var staged = try stageRoot();
    defer staged.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var root_dir = try staged.directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    try writeOwedProvenanceAttempt(
        root_dir,
        staged.install_root,
        .{ .repository_bootstrap = .add },
    );

    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const options = staged.options(&source_paths, &keyring_paths);
    const refused = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.recovery, refused.exit_status);
    try std.testing.expectEqual(
        api.ErrorId.root_operation_recovery_required,
        refused.diagnostics[0].id,
    );
    try std.testing.expect(std.mem.indexOf(u8, refused.summary, "repo add") != null);

    // The bootstrap's evidence is left exactly as it was published, and no
    // package-transaction statement was written over it.
    try std.testing.expect((try readCompletionStatement(staged.install_root)) == null);
    var preserved = (try readRootAttempt(staged.install_root)).?;
    defer preserved.deinit();
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.pending,
        preserved.record.provenance,
    );
    try std.testing.expectEqual(
        debz.root_operation.Surface.repository_bootstrap,
        std.meta.activeTag(preserved.record.operation),
    );
}

test "a completion statement that cannot be published leaves the root blocked" {
    var staged = try stageRoot();
    defer staged.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var process = SuccessfulProcess{ .io = std.testing.io, .dir = staged.directory.dir };
    var crash = CrashAt{ .point = .after_completed_record };
    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = process.interface(),
        .completion_crash = crash.interface(),
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const options = staged.options(&source_paths, &keyring_paths);
    const interrupted = try api.execute(arena.allocator(), .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
    backend.completion_crash = null;

    // The statement is published inside the root, so a directory in its place
    // is an I/O failure the recovery must report rather than work around: the
    // obligation may never be cleared without a statement behind it.
    try staged.directory.dir.createDirPath(
        std.testing.io,
        "root/var/lib/debz/root-operation-completion-v1.json",
    );
    const refused = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.recovery, refused.exit_status);
    try std.testing.expect(std.mem.indexOf(
        u8,
        refused.summary,
        "root-operation completion provenance could not be published",
    ) != null);
    var owed = (try readRootAttempt(staged.install_root)).?;
    defer owed.deinit();
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.pending,
        owed.record.provenance,
    );

    try staged.directory.dir.deleteTree(
        std.testing.io,
        "root/var/lib/debz/root-operation-completion-v1.json",
    );
    const recovered = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
    try std.testing.expect((try readRootAttempt(staged.install_root)) == null);
    var statement = (try readCompletionStatement(staged.install_root)).?;
    statement.deinit();
}

test "product recovery never discharges an attempt recorded for another root" {
    var staged = try stageRoot();
    defer staged.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const other_root = try std.fmt.allocPrint(
        arena.allocator(),
        "{s}-copied",
        .{staged.install_root},
    );
    var root_dir = try staged.directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    try writeOwedProvenanceAttempt(
        root_dir,
        other_root,
        .{ .package_transaction = .install },
    );

    var backend: debz.ProductionBackend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
    };
    const source_paths = [_][]const u8{staged.source_path};
    const keyring_paths = [_][]const u8{staged.keyring_path};
    const options = staged.options(&source_paths, &keyring_paths);
    const refused = try api.execute(arena.allocator(), .{
        .operation = .recover,
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.recovery, refused.exit_status);
    try std.testing.expectEqual(
        api.ErrorId.root_operation_recovery_required,
        refused.diagnostics[0].id,
    );
    try std.testing.expect(std.mem.indexOf(u8, refused.summary, "different root") != null);

    // Nothing about another root's attempt is ever published into this one.
    try std.testing.expect((try readCompletionStatement(staged.install_root)) == null);
    var preserved = (try readRootAttempt(staged.install_root)).?;
    defer preserved.deinit();
    try std.testing.expectEqualStrings(other_root, preserved.record.install_root);
    try std.testing.expectEqual(
        debz.root_operation.ProvenanceState.pending,
        preserved.record.provenance,
    );
}

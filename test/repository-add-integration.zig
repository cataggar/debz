const std = @import("std");
const debz = @import("debz");
const repository_cli = @import("repository_cli");

const api = debz.repository_api;
const transaction_executor = debz.transaction_executor;

const SimulatedDpkg = struct {
    io: std.Io,
    root: []const u8,
    source: []const u8,
    keyring: []const u8,
    calls: usize = 0,
    descriptor_calls: usize = 0,
    dependency_calls: usize = 0,

    fn interface(self: *SimulatedDpkg) transaction_executor.ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(
        context: *anyopaque,
        invocation: transaction_executor.Invocation,
    ) !transaction_executor.ProcessResult {
        const self: *SimulatedDpkg = @ptrCast(@alignCast(context));
        if (invocation.argv.len == 0 or
            (!std.mem.eql(u8, invocation.argv[0], "/usr/bin/dpkg") and
                !std.mem.eql(u8, invocation.argv[0], "/usr/bin/dpkg-deb")))
            return error.UnexpectedProcess;
        for (invocation.argv) |argument| {
            if (std.mem.indexOf(u8, argument, "apt") != null)
                return error.AptInvocationForbidden;
        }
        if (invocation.environment.len != transaction_executor.audited_environment.len)
            return error.UnexpectedEnvironment;
        for (invocation.environment, transaction_executor.audited_environment) |actual, expected| {
            if (!std.mem.eql(u8, actual.key, expected.key) or
                !std.mem.eql(u8, actual.value, expected.value))
                return error.UnexpectedEnvironment;
        }

        self.calls += 1;
        if (invocation.package) |package| {
            if (std.mem.eql(u8, package, "packages-microsoft-prod")) {
                self.descriptor_calls += 1;
                try self.installDescriptor();
            } else if (std.mem.eql(u8, package, "ca-certificates")) {
                self.dependency_calls += 1;
            }
        }
        try self.writeInstalledStatus();
        return .{ .termination = .{ .exited = 0 } };
    }

    fn installDescriptor(self: *SimulatedDpkg) !void {
        var root = try std.Io.Dir.cwd().openDir(self.io, self.root, .{});
        defer root.close(self.io);
        try root.createDirPath(self.io, "etc/apt/sources.list.d");
        try root.createDirPath(self.io, "usr/share/keyrings");
        try root.writeFile(self.io, .{
            .sub_path = "etc/apt/sources.list.d/microsoft-prod.list",
            .data = self.source,
        });
        try root.writeFile(self.io, .{
            .sub_path = "usr/share/keyrings/microsoft-prod.gpg",
            .data = self.keyring,
        });
    }

    fn writeInstalledStatus(self: *SimulatedDpkg) !void {
        var root = try std.Io.Dir.cwd().openDir(self.io, self.root, .{});
        defer root.close(self.io);
        try root.createDirPath(self.io, "var/lib/dpkg");
        try root.writeFile(self.io, .{
            .sub_path = "var/lib/dpkg/status",
            .data = "Package: ca-certificates\n" ++
                "Status: install ok installed\n" ++
                "Architecture: all\n" ++
                "Version: 20240203\n\n" ++
                "Package: essential-core\n" ++
                "Status: install ok installed\n" ++
                "Architecture: amd64\n" ++
                "Version: 1.0-1\n\n" ++
                "Package: packages-microsoft-prod\n" ++
                "Status: install ok installed\n" ++
                "Architecture: all\n" ++
                "Version: 1.2-fixture\n",
        });
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const source_path = args.next() orelse return error.MissingSourcePath;
    const keyring_path = args.next() orelse return error.MissingKeyringPath;
    var cli_arguments: std.ArrayList([]const u8) = .empty;
    while (args.next()) |argument| try cli_arguments.append(allocator, argument);
    const parsed = try repository_cli.parseAdd(cli_arguments.items);
    try expect(parsed.output == .json);
    try expect(!std.mem.eql(u8, parsed.request.root, "/"));

    const source = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        source_path,
        allocator,
        .limited(1024 * 1024),
    );
    const keyring = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        keyring_path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
    var simulated_dpkg: SimulatedDpkg = .{
        .io = init.io,
        .root = parsed.request.root,
        .source = source,
        .keyring = keyring,
    };
    var backend: debz.ProductionRepositoryBackend = .{
        .io = init.io,
        .process_runner = simulated_dpkg.interface(),
    };

    var first = try api.execute(allocator, parsed.request, backend.interface());
    defer first.deinit();
    if (first.exit_status != .success) {
        const failure_json = try first.canonicalJson(allocator);
        std.debug.print("{s}\n", .{failure_json});
    }
    try expect(first.exit_status == .success);
    try expect(first.changed);
    try expect(first.installed);
    try expect(first.refreshed == !parsed.request.no_refresh);
    const expected_refresh_phase: api.PhaseState =
        if (parsed.request.no_refresh) .skipped else .complete;
    try expect(first.refreshed_phase == expected_refresh_phase);
    try expect(first.descriptor != null);
    try expect(std.mem.indexOf(u8, first.descriptor.?.effective_url, "?REDACTED") != null);
    try expect(std.mem.indexOf(u8, first.descriptor.?.effective_url, "fixture-query-secret") == null);
    try expect(simulated_dpkg.calls != 0);
    try expect(simulated_dpkg.descriptor_calls != 0);
    try expect(simulated_dpkg.dependency_calls != 0);
    try verifyEvidence(allocator, init.io, parsed.request.root, first);
    const calls_after_first = simulated_dpkg.calls;

    const first_json = try first.canonicalJson(allocator);
    var decoded_first = try api.decode(allocator, first_json, api.maximum_document_bytes);
    defer decoded_first.deinit();
    const human = try first.humanSummary(allocator);

    var second = try api.execute(allocator, parsed.request, backend.interface());
    defer second.deinit();
    try expect(second.exit_status == .success);
    try expect(!second.changed);
    try expect(second.installed);
    try expect(second.refreshed == !parsed.request.no_refresh);
    try expectEqual(calls_after_first, simulated_dpkg.calls);
    const second_json = try second.canonicalJson(allocator);
    var decoded_second = try api.decode(allocator, second_json, api.maximum_document_bytes);
    defer decoded_second.deinit();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_file.interface;
    try stdout.print("FIRST={s}\nSECOND={s}\nHUMAN={s}\nDPKG_CALLS={}\n", .{
        first_json,
        second_json,
        human,
        simulated_dpkg.calls,
    });
    try stdout.flush();
}

fn verifyEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    result: api.Result,
) !void {
    const lock = try readEvidence(
        allocator,
        io,
        root,
        result.paths.exact_lock orelse return error.MissingLock,
    );
    try expect(std.mem.indexOf(u8, lock, "\"local_artifact\"") != null);
    try expect(std.mem.indexOf(u8, lock, "\"authenticated_repository\"") != null);
    try expect(std.mem.indexOf(u8, lock, "packages-microsoft-prod") != null);
    try expect(std.mem.indexOf(u8, lock, "ca-certificates") != null);
    try expect(std.mem.indexOf(u8, lock, "fixture-query-secret") == null);

    const provenance = try readEvidence(
        allocator,
        io,
        root,
        result.paths.provenance orelse return error.MissingProvenance,
    );
    try expect(std.mem.indexOf(u8, provenance, "/usr/bin/dpkg") != null);
    try expect(std.mem.indexOf(u8, provenance, "\"commands\"") != null);
    try expect(std.mem.indexOf(u8, provenance, "fixture-query-secret") == null);

    const manifest = try readEvidence(
        allocator,
        io,
        root,
        result.paths.target_manifest orelse return error.MissingManifest,
    );
    try expect(std.mem.indexOf(u8, manifest, "/etc/apt/sources.list.d/microsoft-prod.list") != null);
    try expect(std.mem.indexOf(u8, manifest, "/usr/share/keyrings/microsoft-prod.gpg") != null);
    try expect(std.mem.indexOf(u8, manifest, "\"primary_fingerprints\"") != null);

    const state = try readEvidence(
        allocator,
        io,
        root,
        result.paths.operation_state orelse return error.MissingState,
    );
    try expect(std.mem.indexOf(u8, state, "\"phase\":\"complete\"") != null);
}

fn readEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    logical: []const u8,
) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "{s}{s}", .{
        if (std.mem.eql(u8, root, "/")) "" else root,
        logical,
    });
    return std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
}

fn expect(condition: bool) !void {
    if (!condition) return error.IntegrationAssertionFailed;
}

fn expectEqual(expected: usize, actual: usize) !void {
    if (expected != actual) return error.IntegrationAssertionFailed;
}

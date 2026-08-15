const std = @import("std");
const debz = @import("debz");
const api = debz.product_api;

const usage =
    \\Usage: debz <command> [options] [packages...]
    \\
    \\Commands:
    \\  refresh install remove upgrade upgrade-all reinstall download plan
    \\  list-installed list-available info provides why clean recover
    \\
    \\Required common options:
    \\  --install-root PATH --cache-path PATH --state-path PATH --architecture ARCH
    \\
    \\Explicit input and policy options:
    \\  --source PATH --config PATH --keyring PATH --default-release SUITE
    \\  --repository-policy strict-priority|best-version
    \\  --proxy URI --credential-reference ID
    \\  --lock-input PATH --lock-output PATH --json --offline --cache-only
    \\  --recommends --allow-downgrade --deadline-ms N --lock-wait-ms N
    \\  --assume-yes --noninteractive
    \\  --conffile keep-existing|use-package-version --force POLICY
    \\
    \\No host APT configuration, keyrings, proxy, or credentials are inherited.
    \\
;

const CliError = error{ InvalidArguments, MissingValue, InvalidNumber, OutOfMemory };

const Parsed = struct {
    request: api.Request,
    help: bool = false,
};

pub fn main(init: std.process.Init) !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stderr_buffer: [4096]u8 = undefined;
    var stdout_file = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    var stderr_file = std.Io.File.stderr().writer(init.io, &stderr_buffer);
    const stdout = &stdout_file.interface;
    const stderr = &stderr_file.interface;
    defer stdout.flush() catch {};
    defer stderr.flush() catch {};

    var args = init.minimal.args.iterate();
    _ = args.next();
    const command = args.next() orelse {
        try stdout.writeAll(usage);
        return;
    };
    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        try stdout.writeAll(usage);
        return;
    }
    if (std.mem.eql(u8, command, "--version")) {
        try stdout.print("debz {s} (API v{d})\n", .{ debz.version, api.api_version });
        return;
    }
    const operation = debz.parseOperation(command) orelse {
        try stderr.print("debz: unknown command '{s}'\n", .{command});
        try stderr.writeAll(usage);
        try stderr.flush();
        std.process.exit(@intFromEnum(api.ExitStatus.usage));
    };
    const parsed = parse(init.arena.allocator(), operation, &args) catch |err| {
        try stderr.print("debz: {s}\n", .{@errorName(err)});
        try stderr.print("Try 'debz {s} --help'.\n", .{command});
        try stderr.flush();
        std.process.exit(@intFromEnum(api.ExitStatus.usage));
    };
    if (parsed.help) {
        try stdout.print("Usage: debz {s} [common options] [packages...]\n\n{s}", .{
            operation.spelling(), usage,
        });
        return;
    }

    var backend_context: u8 = 0;
    const result = api.execute(init.arena.allocator(), parsed.request, .{
        .context = &backend_context,
        .executeFn = unavailableBackend,
    }) catch {
        const internal = api.failure(operation, .internal, .internal_error, "internal execution error");
        try render(init.arena.allocator(), stdout, stderr, parsed.request.options.output, internal);
        try stdout.flush();
        try stderr.flush();
        std.process.exit(@intFromEnum(internal.exit_status));
    };
    try render(init.arena.allocator(), stdout, stderr, parsed.request.options.output, result);
    if (result.exit_status != .success) {
        try stdout.flush();
        try stderr.flush();
        std.process.exit(@intFromEnum(result.exit_status));
    }
}

fn parse(
    allocator: std.mem.Allocator,
    operation: api.Operation,
    args: *std.process.Args.Iterator,
) CliError!Parsed {
    var packages: std.ArrayList([]const u8) = .empty;
    var sources: std.ArrayList([]const u8) = .empty;
    var configs: std.ArrayList([]const u8) = .empty;
    var keyrings: std.ArrayList([]const u8) = .empty;
    var forces: std.ArrayList(api.ForcePolicy) = .empty;
    var options: api.CommonOptions = .{
        .install_root = "",
        .cache_path = "",
        .state_path = "",
        .architecture = "",
    };

    while (args.next()) |argument| {
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h"))
            return .{ .request = .{ .operation = operation, .options = options }, .help = true };
        if (!std.mem.startsWith(u8, argument, "--")) {
            try packages.append(allocator, argument);
            continue;
        }
        if (std.mem.eql(u8, argument, "--json")) options.output = .json else if (std.mem.eql(u8, argument, "--offline")) options.offline = true else if (std.mem.eql(u8, argument, "--cache-only")) {
            options.cache_only = true;
            options.offline = true;
        } else if (std.mem.eql(u8, argument, "--recommends")) options.recommends = true else if (std.mem.eql(u8, argument, "--allow-downgrade")) options.allow_downgrade = true else if (std.mem.eql(u8, argument, "--assume-yes") or std.mem.eql(u8, argument, "-y")) options.assume_yes = true else if (std.mem.eql(u8, argument, "--noninteractive")) options.noninteractive = true else if (std.mem.eql(u8, argument, "--install-root")) options.install_root = try next(args) else if (std.mem.eql(u8, argument, "--cache-path")) options.cache_path = try next(args) else if (std.mem.eql(u8, argument, "--state-path")) options.state_path = try next(args) else if (std.mem.eql(u8, argument, "--architecture")) options.architecture = try next(args) else if (std.mem.eql(u8, argument, "--default-release")) options.default_release = try next(args) else if (std.mem.eql(u8, argument, "--proxy")) options.proxy = try next(args) else if (std.mem.eql(u8, argument, "--credential-reference")) options.credential_reference = try next(args) else if (std.mem.eql(u8, argument, "--lock-input")) options.lock_input_path = try next(args) else if (std.mem.eql(u8, argument, "--lock-output")) options.lock_output_path = try next(args) else if (std.mem.eql(u8, argument, "--source")) try sources.append(allocator, try next(args)) else if (std.mem.eql(u8, argument, "--config")) try configs.append(allocator, try next(args)) else if (std.mem.eql(u8, argument, "--keyring")) try keyrings.append(allocator, try next(args)) else if (std.mem.eql(u8, argument, "--deadline-ms")) options.deadline_ms = try number(try next(args)) else if (std.mem.eql(u8, argument, "--lock-wait-ms")) options.lock_wait_ms = try number(try next(args)) else if (std.mem.eql(u8, argument, "--repository-policy")) {
            const value = try next(args);
            options.repository_policy = if (std.mem.eql(u8, value, "strict-priority"))
                .strict_priority
            else if (std.mem.eql(u8, value, "best-version"))
                .best_version
            else
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, argument, "--conffile")) {
            const value = try next(args);
            options.conffile = if (std.mem.eql(u8, value, "keep-existing"))
                .keep_existing
            else if (std.mem.eql(u8, value, "use-package-version"))
                .use_package_version
            else
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, argument, "--force")) {
            const value = try next(args);
            try forces.append(allocator, std.meta.stringToEnum(api.ForcePolicy, value) orelse
                return error.InvalidArguments);
        } else return error.InvalidArguments;
    }
    options.source_paths = try sources.toOwnedSlice(allocator);
    options.config_paths = try configs.toOwnedSlice(allocator);
    options.keyring_paths = try keyrings.toOwnedSlice(allocator);
    options.force = try forces.toOwnedSlice(allocator);
    return .{ .request = .{
        .operation = operation,
        .packages = try packages.toOwnedSlice(allocator),
        .options = options,
    } };
}

fn next(args: *std.process.Args.Iterator) CliError![]const u8 {
    return args.next() orelse error.MissingValue;
}

fn number(value: []const u8) CliError!u64 {
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidNumber;
}

fn unavailableBackend(_: *anyopaque, _: std.mem.Allocator, request: api.Request) !api.Result {
    return api.failure(
        request.operation,
        .unavailable,
        .configuration_required,
        "no operation backend is configured; use the embeddable API with explicit authenticated snapshots and transaction dependencies",
    );
}

fn render(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    format: api.OutputFormat,
    result: api.Result,
) !void {
    if (format == .json) {
        const json = try result.canonicalJson(allocator);
        try stdout.writeAll(json);
        return;
    }
    const writer = if (result.exit_status == .success) stdout else stderr;
    try writer.print("{s}: {s}\n", .{ result.operation.spelling(), result.summary });
    for (result.items) |item| {
        try writer.print("{s}", .{item.package});
        if (item.version) |value| try writer.print(" {s}", .{value});
        if (item.architecture) |value| try writer.print(" [{s}]", .{value});
        if (item.detail) |value| try writer.print(": {s}", .{value});
        try writer.writeByte('\n');
    }
    for (result.diagnostics[0..result.diagnostic_count]) |diagnostic|
        try writer.print("debz[{s}]: {s}\n", .{ @tagName(diagnostic.id), diagnostic.message });
}

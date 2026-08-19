const std = @import("std");
const debz = @import("debz");
const api = debz.product_api;

const usage =
    \\Usage: debz <command> [options] [packages...]
    \\
    \\Commands:
    \\  refresh install remove upgrade upgrade-all reinstall download plan
    \\  list-installed list-available info provides why clean recover
    \\  package-family-capabilities
    \\
    \\Required common options:
    \\  --install-root PATH --cache-path PATH --state-path PATH --architecture ARCH
    \\
    \\Explicit input and policy options:
    \\  --source PATH --config PATH --keyring PATH --status-path PATH
    \\  --foreign-architecture ARCH
    \\  --default-release SUITE
    \\  --repository-policy strict-priority|best-version
    \\  --proxy URI --credential-reference PATH
    \\  --lock-input PATH --lock-output PATH --json --offline --cache-only
    \\  --recommends --allow-downgrade --deadline-ms N --lock-wait-ms N
    \\  --assume-yes --noninteractive
    \\  --conffile keep-existing|use-package-version --force POLICY
    \\
    \\No host APT configuration, keyrings, proxy, or credentials are inherited.
    \\
;

const CliError = error{ InvalidArguments, MissingValue, InvalidNumber, OutOfMemory };
const SingleOption = enum {
    install_root,
    cache_path,
    state_path,
    status_path,
    architecture,
    default_release,
    proxy,
    credential_reference,
    lock_input,
    lock_output,
    deadline,
    lock_wait,
    repository_policy,
    conffile,
};

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
        try stdout.print("{s}\n", .{debz.version});
        return;
    }
    if (std.mem.eql(u8, command, "package-family-capabilities")) {
        const json = try debz.packageFamilyCapabilities().canonicalJson(init.arena.allocator());
        try stdout.writeAll(json);
        try stdout.writeByte('\n');
        return;
    }
    const operation = debz.parseOperation(command) orelse {
        try stderr.print("debz: unknown command '{s}'\n", .{command});
        try stderr.writeAll(usage);
        try stderr.flush();
        std.process.exit(@intFromEnum(api.ExitStatus.usage));
    };
    var requested_output: api.OutputFormat = .human;
    const parsed = parse(init.arena.allocator(), operation, &args, &requested_output) catch |err| {
        if (requested_output == .json) {
            const invalid = api.failure(operation, .usage, .invalid_request, @errorName(err));
            try render(init.arena.allocator(), stdout, stderr, .json, invalid);
        } else {
            try stderr.print("debz: {s}\n", .{@errorName(err)});
            try stderr.print("Try 'debz {s} --help'.\n", .{command});
        }
        try stdout.flush();
        try stderr.flush();
        std.process.exit(@intFromEnum(api.ExitStatus.usage));
    };
    if (parsed.help) {
        try stdout.print("Usage: debz {s} [common options] [packages...]\n\n{s}", .{
            operation.spelling(), usage,
        });
        return;
    }

    var backend_context: debz.ProductionBackend = .{ .io = init.io };
    const result = api.execute(init.arena.allocator(), parsed.request, .{
        .context = &backend_context,
        .executeFn = debz.ProductionBackend.executeOpaque,
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
    requested_output: *api.OutputFormat,
) CliError!Parsed {
    var packages: std.ArrayList([]const u8) = .empty;
    var sources: std.ArrayList([]const u8) = .empty;
    var configs: std.ArrayList([]const u8) = .empty;
    var keyrings: std.ArrayList([]const u8) = .empty;
    var foreign_architectures: std.ArrayList([]const u8) = .empty;
    var forces: std.ArrayList(api.ForcePolicy) = .empty;
    var seen: std.EnumSet(SingleOption) = .initEmpty();
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
        if (std.mem.eql(u8, argument, "--json")) {
            options.output = .json;
            requested_output.* = .json;
        } else if (std.mem.eql(u8, argument, "--offline")) options.offline = true else if (std.mem.eql(u8, argument, "--cache-only")) {
            options.cache_only = true;
            options.offline = true;
        } else if (std.mem.eql(u8, argument, "--recommends")) options.recommends = true else if (std.mem.eql(u8, argument, "--allow-downgrade")) options.allow_downgrade = true else if (std.mem.eql(u8, argument, "--assume-yes") or std.mem.eql(u8, argument, "-y")) options.assume_yes = true else if (std.mem.eql(u8, argument, "--noninteractive")) options.noninteractive = true else if (std.mem.eql(u8, argument, "--install-root")) {
            try setOnce(&seen, .install_root);
            options.install_root = try next(args);
        } else if (std.mem.eql(u8, argument, "--cache-path")) {
            try setOnce(&seen, .cache_path);
            options.cache_path = try next(args);
        } else if (std.mem.eql(u8, argument, "--state-path")) {
            try setOnce(&seen, .state_path);
            options.state_path = try next(args);
        } else if (std.mem.eql(u8, argument, "--status-path")) {
            try setOnce(&seen, .status_path);
            options.status_path = try next(args);
        } else if (std.mem.eql(u8, argument, "--architecture")) {
            try setOnce(&seen, .architecture);
            options.architecture = try next(args);
        } else if (std.mem.eql(u8, argument, "--foreign-architecture")) {
            try foreign_architectures.append(allocator, try next(args));
        } else if (std.mem.eql(u8, argument, "--default-release")) {
            try setOnce(&seen, .default_release);
            options.default_release = try next(args);
        } else if (std.mem.eql(u8, argument, "--proxy")) {
            try setOnce(&seen, .proxy);
            options.proxy = try next(args);
        } else if (std.mem.eql(u8, argument, "--credential-reference")) {
            try setOnce(&seen, .credential_reference);
            options.credential_reference = try next(args);
        } else if (std.mem.eql(u8, argument, "--lock-input")) {
            try setOnce(&seen, .lock_input);
            options.lock_input_path = try next(args);
        } else if (std.mem.eql(u8, argument, "--lock-output")) {
            try setOnce(&seen, .lock_output);
            options.lock_output_path = try next(args);
        } else if (std.mem.eql(u8, argument, "--source")) try sources.append(allocator, try next(args)) else if (std.mem.eql(u8, argument, "--config")) try configs.append(allocator, try next(args)) else if (std.mem.eql(u8, argument, "--keyring")) try keyrings.append(allocator, try next(args)) else if (std.mem.eql(u8, argument, "--deadline-ms")) {
            try setOnce(&seen, .deadline);
            options.deadline_ms = try number(try next(args));
        } else if (std.mem.eql(u8, argument, "--lock-wait-ms")) {
            try setOnce(&seen, .lock_wait);
            options.lock_wait_ms = try number(try next(args));
        } else if (std.mem.eql(u8, argument, "--repository-policy")) {
            try setOnce(&seen, .repository_policy);
            const value = try next(args);
            options.repository_policy = if (std.mem.eql(u8, value, "strict-priority"))
                .strict_priority
            else if (std.mem.eql(u8, value, "best-version"))
                .best_version
            else
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, argument, "--conffile")) {
            try setOnce(&seen, .conffile);
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
    options.foreign_architectures = try foreign_architectures.toOwnedSlice(allocator);
    options.force = try forces.toOwnedSlice(allocator);
    return .{ .request = .{
        .operation = operation,
        .packages = try packages.toOwnedSlice(allocator),
        .options = options,
    } };
}

fn setOnce(seen: *std.EnumSet(SingleOption), option: SingleOption) CliError!void {
    if (seen.contains(option)) return error.InvalidArguments;
    seen.insert(option);
}

fn next(args: *std.process.Args.Iterator) CliError![]const u8 {
    return args.next() orelse error.MissingValue;
}

fn number(value: []const u8) CliError!u64 {
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidNumber;
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

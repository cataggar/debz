const std = @import("std");
const debz = @import("debz");
const api = debz.product_api;

const root_help =
    \\debz - deterministic Debian package operations
    \\
    \\Usage:
    \\  debz <command> [options] [packages...]
    \\
    \\Commands:
    \\  refresh                      Refresh authenticated repository metadata
    \\  install                      Install one package
    \\  remove                       Remove one package
    \\  upgrade                      Upgrade installed packages or named packages
    \\  upgrade-all                  Upgrade every eligible installed package
    \\  reinstall                    Reinstall one package
    \\  download                     Download one package without installing it
    \\  plan                         Plan a transaction for zero or one package
    \\  list-installed               List installed packages
    \\  list-available               List available packages
    \\  info                         Show information for one or more packages
    \\  provides                     Find providers for one or more capabilities
    \\  why                          Explain why one or more packages are installed
    \\  clean                        Clean cached package artifacts
    \\  recover                      Recover an interrupted transaction
    \\  package-family-capabilities  Print package-family capabilities as JSON
    \\  version                      Print the version and exit
    \\
    \\Options:
    \\  -h, --help                   Show this help
    \\
    \\Run 'debz <command> --help' for command-specific help.
    \\No host APT configuration, keyrings, proxy, or credentials are inherited.
    \\
;

const required_options_help =
    \\Required options:
    \\  --install-root PATH --cache-path PATH --state-path PATH --architecture ARCH
    \\
;

const repository_options_help =
    \\Repository options:
    \\  --source PATH --config PATH --keyring PATH
    \\  --foreign-architecture ARCH --default-release SUITE
    \\  --repository-policy strict-priority|best-version --offline --cache-only
    \\  --proxy URI --credential-reference PATH
    \\
;

const status_option_help =
    \\Installed-state option:
    \\  --status-path PATH            Read installed state from PATH
    \\
;

const lock_options_help =
    \\Exact-lock options:
    \\  --lock-input PATH --lock-output PATH
    \\
;

const resolution_options_help =
    \\Resolution options:
    \\  --recommends --allow-downgrade
    \\
;

const mutation_options_help =
    \\Mutation options:
    \\  --assume-yes                   Confirm the requested mutation
    \\
;

const transaction_options_help =
    \\Transaction options:
    \\  --noninteractive
    \\  --conffile keep-existing|use-package-version
    \\  --force POLICY
    \\
;

const common_options_help =
    \\Common options:
    \\  --json --deadline-ms N --lock-wait-ms N
    \\  -h, --help                    Show this help
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

const HelpTopic = union(enum) {
    root,
    operation: api.Operation,
    package_family_capabilities,
    version,
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

    {
        var help_args = init.minimal.args.iterate();
        _ = help_args.next();
        if (help_args.next()) |command| {
            if (detectHelpTopic(command, &help_args)) |topic| {
                try printHelpTopic(topic, stdout);
                return;
            }
        }
    }

    var args = init.minimal.args.iterate();
    _ = args.next();
    const command = args.next() orelse {
        try stdout.writeAll(root_help);
        return;
    };
    if (std.mem.eql(u8, command, "version")) {
        if (args.next()) |argument| {
            try stderr.print("debz: unexpected argument '{s}' for 'debz version'\n", .{argument});
            try stderr.flush();
            std.process.exit(@intFromEnum(api.ExitStatus.usage));
        }
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
        try stderr.writeAll(root_help);
        try stderr.flush();
        std.process.exit(@intFromEnum(api.ExitStatus.usage));
    };
    var requested_output: api.OutputFormat = .human;
    const request = parse(init.arena.allocator(), operation, &args, &requested_output) catch |err| {
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

    var backend_context: debz.ProductionBackend = .{ .io = init.io };
    const result = api.execute(init.arena.allocator(), request, .{
        .context = &backend_context,
        .executeFn = debz.ProductionBackend.executeOpaque,
    }) catch {
        const internal = api.failure(operation, .internal, .internal_error, "internal execution error");
        try render(init.arena.allocator(), stdout, stderr, request.options.output, internal);
        try stdout.flush();
        try stderr.flush();
        std.process.exit(@intFromEnum(internal.exit_status));
    };
    try render(init.arena.allocator(), stdout, stderr, request.options.output, result);
    if (result.exit_status != .success) {
        try stdout.flush();
        try stderr.flush();
        std.process.exit(@intFromEnum(result.exit_status));
    }
}

fn detectHelpTopic(command: []const u8, args: *std.process.Args.Iterator) ?HelpTopic {
    if (isHelpFlag(command)) return .root;

    var has_help = false;
    while (args.next()) |argument| {
        if (isHelpFlag(argument)) has_help = true;
    }
    if (!has_help) return null;

    if (debz.parseOperation(command)) |operation| return .{ .operation = operation };
    if (std.mem.eql(u8, command, "package-family-capabilities"))
        return .package_family_capabilities;
    if (std.mem.eql(u8, command, "version")) return .version;
    return null;
}

fn isHelpFlag(argument: []const u8) bool {
    return std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h");
}

fn printHelpTopic(topic: HelpTopic, stdout: *std.Io.Writer) !void {
    switch (topic) {
        .root => try stdout.writeAll(root_help),
        .operation => |operation| try printOperationHelp(stdout, operation),
        .package_family_capabilities => try stdout.writeAll(
            \\debz package-family-capabilities - print package-family capabilities as JSON
            \\
            \\Usage:
            \\  debz package-family-capabilities
            \\
            \\Options:
            \\  -h, --help  Show this help
            \\
        ),
        .version => try stdout.writeAll(
            \\debz version - print the debz version
            \\
            \\Usage:
            \\  debz version
            \\
            \\Options:
            \\  -h, --help  Show this help
            \\
        ),
    }
}

fn printOperationHelp(stdout: *std.Io.Writer, operation: api.Operation) !void {
    try stdout.print(
        \\debz {s} - {s}
        \\
        \\Usage:
        \\  debz {s} [options]{s}
        \\
        \\
    , .{
        operation.spelling(),
        operationDescription(operation),
        operation.spelling(),
        operationOperands(operation),
    });
    try stdout.writeAll(required_options_help);
    if (usesRepositories(operation)) try stdout.writeAll(repository_options_help);
    if (!operation.mutates()) try stdout.writeAll(status_option_help);
    if (supportsExactLocks(operation)) try stdout.writeAll(lock_options_help);
    if (usesResolution(operation)) try stdout.writeAll(resolution_options_help);
    if (operation.mutates()) try stdout.writeAll(mutation_options_help);
    if (usesTransactions(operation)) try stdout.writeAll(transaction_options_help);
    try stdout.writeAll(common_options_help);
}

fn operationDescription(operation: api.Operation) []const u8 {
    return switch (operation) {
        .refresh => "refresh authenticated repository metadata",
        .install => "install one package",
        .remove => "remove one package",
        .upgrade => "upgrade installed packages or named packages",
        .upgrade_all => "upgrade every eligible installed package",
        .reinstall => "reinstall one package",
        .download => "download one package without installing it",
        .plan => "plan a transaction for zero or one package",
        .list_installed => "list installed packages",
        .list_available => "list available packages",
        .info => "show information for one or more packages",
        .provides => "find providers for one or more capabilities",
        .why => "explain why one or more packages are installed",
        .clean => "clean cached package artifacts",
        .recover => "recover an interrupted transaction",
    };
}

fn operationOperands(operation: api.Operation) []const u8 {
    return switch (operation) {
        .install, .remove, .reinstall, .download => " <package>",
        .info, .why => " <package>...",
        .provides => " <capability>...",
        .plan => " [package]",
        .upgrade => " [package...]",
        .refresh, .upgrade_all, .list_installed, .list_available, .clean, .recover => "",
    };
}

fn usesRepositories(operation: api.Operation) bool {
    return switch (operation) {
        .list_installed, .why, .clean => false,
        else => true,
    };
}

fn supportsExactLocks(operation: api.Operation) bool {
    return switch (operation) {
        .install, .remove, .upgrade, .upgrade_all, .reinstall, .download, .plan, .recover => true,
        else => false,
    };
}

fn usesResolution(operation: api.Operation) bool {
    return switch (operation) {
        .install, .remove, .upgrade, .upgrade_all, .reinstall, .download, .plan => true,
        else => false,
    };
}

fn usesTransactions(operation: api.Operation) bool {
    return operation.mutates() and operation != .refresh and operation != .clean;
}

fn parse(
    allocator: std.mem.Allocator,
    operation: api.Operation,
    args: *std.process.Args.Iterator,
    requested_output: *api.OutputFormat,
) CliError!api.Request {
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
    return .{
        .operation = operation,
        .packages = try packages.toOwnedSlice(allocator),
        .options = options,
    };
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

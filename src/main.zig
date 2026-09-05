const std = @import("std");
const debz = @import("debz");
const repository_cli = @import("repository_cli");
const api = debz.product_api;
const repository_api = debz.repository_api;

const root_help =
    \\debz - deterministic Debian package operations
    \\
    \\Usage:
    \\  debz <command> [options] [packages...]
    \\
    \\Commands:
    \\  repo                         Manage repository descriptors
    \\  package-cache                Prepare an exact-lock package CAS
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

const repository_help =
    \\debz repo - manage repository descriptors
    \\
    \\Usage:
    \\  debz repo <command> [options]
    \\
    \\Commands:
    \\  add                          Acquire, install, import, and refresh a descriptor
    \\
    \\Options:
    \\  -h, --help                   Show this help
    \\
    \\Run 'debz repo add --help' for command-specific help.
    \\Repository operations are noninteractive and inherit no host APT, proxy,
    \\credential, keyring, or architecture configuration.
    \\
;

const repository_add_help =
    \\debz repo add - acquire and activate a repository descriptor
    \\
    \\Usage:
    \\  debz repo add --url URL [options]
    \\
    \\Required options:
    \\  --url URL                    Repository descriptor URL
    \\
    \\Target options:
    \\  --root PATH                  Target root (default: /)
    \\  --architecture ARCH          Override target dpkg architecture
    \\  --cache-path PATH            Logical cache path inside the target root
    \\  --state-path PATH            Logical state path inside the target root
    \\  --sha256 DIGEST              Expected descriptor SHA-256
    \\  --no-refresh                 Install and import without final refresh
    \\
    \\Network options:
    \\  --proxy URI
    \\  --connect-timeout-ms N --read-timeout-ms N --deadline-ms N
    \\  --redirect-limit N --retry-attempts N --retry-backoff-ms N
    \\  --maximum-descriptor-bytes N --maximum-package-bytes N
    \\  --maximum-release-bytes N --maximum-compressed-index-bytes N
    \\  --maximum-decompressed-index-bytes N --maximum-decoder-memory N
    \\
    \\Resource options:
    \\  --maximum-cache-object-bytes N --lock-wait-ms N
    \\  --maximum-operation-state-bytes N --maximum-repositories N
    \\  --maximum-actions N --maximum-total-metadata-bytes N
    \\  --maximum-total-package-bytes N --maximum-retained-package-bytes N
    \\  --maximum-cache-growth-bytes N
    \\
    \\Output options:
    \\  --json                       Write canonical repository result JSON
    \\  -h, --help                   Show this help
    \\
    \\The operation is authorization to mutate the selected root. It never
    \\prompts, reads stdin, invokes apt, or imports configuration outside that root.
    \\
;

const package_cache_help =
    \\debz package-cache - fingerprint or prepare an exact-lock package CAS
    \\
    \\Usage:
    \\  debz package-cache <command> [options]
    \\
    \\Commands:
    \\  fingerprint                  Validate a lock and print its cache keys
    \\  prepare                      Authenticate and prepare the complete lock closure
    \\
    \\Options:
    \\  -h, --help                   Show this help
    \\
    \\The cache contract is versioned and CLI-owned. Only packages-v1/objects
    \\is suitable for an external cache; metadata, locks, and staging are not.
    \\
;

const package_cache_fingerprint_help =
    \\debz package-cache fingerprint - print a deterministic exact-lock cache fingerprint
    \\
    \\Usage:
    \\  debz package-cache fingerprint --lock-input PATH --cache-path PATH --architecture ARCH [options]
    \\
    \\Policy options:
    \\  --foreign-architecture ARCH --repository-policy strict-priority|best-version
    \\  --recommends --allow-downgrade --repair-corrupt-cache
    \\
    \\Resource options:
    \\  --maximum-package-bytes N --maximum-total-package-bytes N
    \\  --maximum-lock-packages N
    \\
    \\Output options:
    \\  --json                       Write package-cache fingerprint JSON
    \\  -h, --help                   Show this help
    \\
;

const package_cache_prepare_help =
    \\debz package-cache prepare - verify and prepare a complete exact-lock closure
    \\
    \\Usage:
    \\  debz package-cache prepare --lock-input PATH --cache-path PATH --architecture ARCH [options]
    \\
    \\Repository options:
    \\  --source PATH --config PATH --keyring PATH
    \\  --foreign-architecture ARCH --default-release SUITE
    \\  --repository-policy strict-priority|best-version --offline --cache-only
    \\  --proxy URI --credential-reference PATH
    \\
    \\Policy options:
    \\  --recommends --allow-downgrade --repair-corrupt-cache
    \\  --restored-cache none|partial|exact
    \\  --archive-input PATH --archive-output PATH
    \\  --deadline-ms N --lock-wait-ms N
    \\
    \\Resource options:
    \\  --maximum-package-bytes N --maximum-total-package-bytes N
    \\  --maximum-lock-packages N --maximum-repository-records N
    \\  --maximum-staging-entries N
    \\  --maximum-gc-directory-entries N --maximum-gc-objects-scanned N
    \\  --maximum-gc-objects-deleted N --maximum-gc-bytes-deleted N
    \\
    \\Output options:
    \\  --json                       Write package-cache result JSON
    \\  -h, --help                   Show this help
    \\
    \\Repository metadata is authenticated normally but is not part of the
    \\externally cacheable object path. Offline mode never falls back online.
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
    repository,
    repository_add,
    package_cache,
    package_cache_fingerprint,
    package_cache_prepare,
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
    if (std.mem.eql(u8, command, "repo")) {
        try runRepository(
            init,
            &args,
            stdout,
            stderr,
        );
        return;
    }
    if (std.mem.eql(u8, command, "package-cache")) {
        try runPackageCache(init, &args, stdout, stderr);
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

    if (std.mem.eql(u8, command, "repo")) {
        const subcommand = args.next() orelse return null;
        var has_help = isHelpFlag(subcommand);
        while (args.next()) |argument| {
            if (isHelpFlag(argument)) has_help = true;
        }
        if (!has_help) return null;
        if (isHelpFlag(subcommand)) return .repository;
        if (std.mem.eql(u8, subcommand, "add")) return .repository_add;
        return null;
    }

    if (std.mem.eql(u8, command, "package-cache")) {
        const subcommand = args.next() orelse return null;
        var has_help = isHelpFlag(subcommand);
        while (args.next()) |argument| {
            if (isHelpFlag(argument)) has_help = true;
        }
        if (!has_help) return null;
        if (isHelpFlag(subcommand)) return .package_cache;
        if (std.mem.eql(u8, subcommand, "fingerprint")) return .package_cache_fingerprint;
        if (std.mem.eql(u8, subcommand, "prepare")) return .package_cache_prepare;
        return null;
    }

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
        .repository => try stdout.writeAll(repository_help),
        .repository_add => try stdout.writeAll(repository_add_help),
        .package_cache => try stdout.writeAll(package_cache_help),
        .package_cache_fingerprint => try stdout.writeAll(package_cache_fingerprint_help),
        .package_cache_prepare => try stdout.writeAll(package_cache_prepare_help),
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

const PackageCacheOperation = enum { fingerprint, prepare };

const PackageCacheSingleOption = enum {
    lock_input,
    cache_path,
    architecture,
    default_release,
    repository_policy,
    proxy,
    credential_reference,
    deadline,
    lock_wait,
    maximum_package_bytes,
    maximum_total_package_bytes,
    maximum_lock_packages,
    maximum_repository_records,
    maximum_staging_entries,
    maximum_gc_directory_entries,
    maximum_gc_objects_scanned,
    maximum_gc_objects_deleted,
    maximum_gc_bytes_deleted,
    restored_cache,
    archive_input,
    archive_output,
};

fn runPackageCache(
    init: std.process.Init,
    args: *std.process.Args.Iterator,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !void {
    const subcommand = args.next() orelse {
        try stderr.writeAll("debz: missing command for 'debz package-cache'\n");
        try stderr.writeAll(package_cache_help);
        try stderr.flush();
        std.process.exit(@intFromEnum(api.ExitStatus.usage));
    };
    const operation: PackageCacheOperation = if (std.mem.eql(u8, subcommand, "fingerprint"))
        .fingerprint
    else if (std.mem.eql(u8, subcommand, "prepare"))
        .prepare
    else {
        try stderr.print("debz: unknown package-cache command '{s}'\n", .{subcommand});
        try stderr.writeAll(package_cache_help);
        try stderr.flush();
        std.process.exit(@intFromEnum(api.ExitStatus.usage));
    };

    var requested_json = false;
    const request = parsePackageCache(
        init.arena.allocator(),
        operation,
        args,
        &requested_json,
    ) catch |err| {
        try renderPackageCacheError(
            init.arena.allocator(),
            stdout,
            stderr,
            operation,
            requested_json,
            @intFromEnum(api.ExitStatus.usage),
            "invalid_request",
            @errorName(err),
        );
        try stdout.flush();
        try stderr.flush();
        std.process.exit(@intFromEnum(api.ExitStatus.usage));
    };

    var backend: debz.ProductionBackend = .{ .io = init.io };
    switch (operation) {
        .fingerprint => {
            var result = backend.packageCacheFingerprint(
                init.arena.allocator(),
                request,
                debz.version,
            ) catch |err| {
                const failure = packageCacheFailure(err);
                try renderPackageCacheError(
                    init.arena.allocator(),
                    stdout,
                    stderr,
                    operation,
                    requested_json,
                    failure.status,
                    failure.id,
                    @errorName(err),
                );
                try stdout.flush();
                try stderr.flush();
                std.process.exit(failure.status);
            };
            defer result.deinit();
            if (requested_json) {
                const json = try result.canonicalJson(init.arena.allocator());
                try stdout.writeAll(json);
            } else {
                try stdout.print(
                    "package-cache fingerprint: key={s}; restore-prefix={s}; lock={s}\n",
                    .{ result.primary_key, result.restore_prefix, &result.lock_digest },
                );
            }
        },
        .prepare => {
            var result = backend.packageCachePrepare(
                init.arena.allocator(),
                request,
                debz.version,
            ) catch |err| {
                const failure = packageCacheFailure(err);
                try renderPackageCacheError(
                    init.arena.allocator(),
                    stdout,
                    stderr,
                    operation,
                    requested_json,
                    failure.status,
                    failure.id,
                    @errorName(err),
                );
                try stdout.flush();
                try stderr.flush();
                std.process.exit(failure.status);
            };
            defer result.deinit();
            if (requested_json) {
                const json = try result.canonicalJson(init.arena.allocator());
                try stdout.writeAll(json);
            } else {
                try stdout.print(
                    "package-cache prepare: downloaded={d}; reused={d}; path={s}\n",
                    .{ result.downloaded_count, result.reused_count, result.cache_path },
                );
            }
        },
    }
}

fn parsePackageCache(
    allocator: std.mem.Allocator,
    operation: PackageCacheOperation,
    args: *std.process.Args.Iterator,
    requested_json: *bool,
) CliError!debz.package_cache_workflow.Request {
    var sources: std.ArrayList([]const u8) = .empty;
    var configs: std.ArrayList([]const u8) = .empty;
    var keyrings: std.ArrayList([]const u8) = .empty;
    var foreign_architectures: std.ArrayList([]const u8) = .empty;
    var seen: std.EnumSet(PackageCacheSingleOption) = .initEmpty();
    var request: debz.package_cache_workflow.Request = .{
        .lock_input_path = "",
        .cache_root = "",
        .architecture = "",
    };

    while (args.next()) |argument| {
        if (!std.mem.startsWith(u8, argument, "--")) return error.InvalidArguments;
        if (std.mem.eql(u8, argument, "--json")) {
            requested_json.* = true;
        } else if (std.mem.eql(u8, argument, "--lock-input")) {
            try setPackageCacheOnce(&seen, .lock_input);
            request.lock_input_path = try next(args);
        } else if (std.mem.eql(u8, argument, "--cache-path")) {
            try setPackageCacheOnce(&seen, .cache_path);
            request.cache_root = try next(args);
        } else if (std.mem.eql(u8, argument, "--architecture")) {
            try setPackageCacheOnce(&seen, .architecture);
            request.architecture = try next(args);
        } else if (std.mem.eql(u8, argument, "--foreign-architecture")) {
            try foreign_architectures.append(allocator, try next(args));
        } else if (std.mem.eql(u8, argument, "--source")) {
            try sources.append(allocator, try next(args));
        } else if (std.mem.eql(u8, argument, "--config")) {
            try configs.append(allocator, try next(args));
        } else if (std.mem.eql(u8, argument, "--keyring")) {
            try keyrings.append(allocator, try next(args));
        } else if (std.mem.eql(u8, argument, "--default-release")) {
            try setPackageCacheOnce(&seen, .default_release);
            request.default_release = try next(args);
        } else if (std.mem.eql(u8, argument, "--repository-policy")) {
            try setPackageCacheOnce(&seen, .repository_policy);
            const value = try next(args);
            request.repository_policy = if (std.mem.eql(u8, value, "strict-priority"))
                .strict_priority
            else if (std.mem.eql(u8, value, "best-version"))
                .best_version
            else
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, argument, "--proxy")) {
            try setPackageCacheOnce(&seen, .proxy);
            request.proxy = try next(args);
        } else if (std.mem.eql(u8, argument, "--credential-reference")) {
            try setPackageCacheOnce(&seen, .credential_reference);
            request.credential_reference = try next(args);
        } else if (std.mem.eql(u8, argument, "--offline") or
            std.mem.eql(u8, argument, "--cache-only"))
        {
            request.offline = true;
        } else if (std.mem.eql(u8, argument, "--repair-corrupt-cache")) {
            request.corrupt_cache = .repair_online;
        } else if (std.mem.eql(u8, argument, "--restored-cache")) {
            try setPackageCacheOnce(&seen, .restored_cache);
            const value = try next(args);
            request.restored_cache = if (std.mem.eql(u8, value, "none"))
                .none
            else if (std.mem.eql(u8, value, "partial"))
                .partial
            else if (std.mem.eql(u8, value, "exact"))
                .exact
            else
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, argument, "--archive-input")) {
            try setPackageCacheOnce(&seen, .archive_input);
            request.archive_input_path = try next(args);
        } else if (std.mem.eql(u8, argument, "--archive-output")) {
            try setPackageCacheOnce(&seen, .archive_output);
            request.archive_output_path = try next(args);
        } else if (std.mem.eql(u8, argument, "--recommends")) {
            request.recommends = true;
        } else if (std.mem.eql(u8, argument, "--allow-downgrade")) {
            request.allow_downgrade = true;
        } else if (std.mem.eql(u8, argument, "--deadline-ms")) {
            try setPackageCacheOnce(&seen, .deadline);
            request.deadline_ms = try number(try next(args));
        } else if (std.mem.eql(u8, argument, "--lock-wait-ms")) {
            try setPackageCacheOnce(&seen, .lock_wait);
            request.lock_wait_ms = try number(try next(args));
        } else if (std.mem.eql(u8, argument, "--maximum-package-bytes")) {
            try setPackageCacheOnce(&seen, .maximum_package_bytes);
            request.limits.maximum_package_bytes = try packageCacheUsize(try next(args));
        } else if (std.mem.eql(u8, argument, "--maximum-total-package-bytes")) {
            try setPackageCacheOnce(&seen, .maximum_total_package_bytes);
            request.limits.maximum_total_package_bytes = try number(try next(args));
        } else if (std.mem.eql(u8, argument, "--maximum-lock-packages")) {
            try setPackageCacheOnce(&seen, .maximum_lock_packages);
            request.limits.maximum_lock_packages = try packageCacheUsize(try next(args));
        } else if (std.mem.eql(u8, argument, "--maximum-repository-records")) {
            try setPackageCacheOnce(&seen, .maximum_repository_records);
            request.limits.maximum_repository_records = try packageCacheUsize(try next(args));
        } else if (std.mem.eql(u8, argument, "--maximum-staging-entries")) {
            try setPackageCacheOnce(&seen, .maximum_staging_entries);
            request.limits.maximum_staging_entries = try packageCacheUsize(try next(args));
        } else if (std.mem.eql(u8, argument, "--maximum-gc-directory-entries")) {
            try setPackageCacheOnce(&seen, .maximum_gc_directory_entries);
            request.limits.maximum_gc_directory_entries = try packageCacheUsize(try next(args));
        } else if (std.mem.eql(u8, argument, "--maximum-gc-objects-scanned")) {
            try setPackageCacheOnce(&seen, .maximum_gc_objects_scanned);
            request.limits.maximum_gc_objects_scanned = try packageCacheUsize(try next(args));
        } else if (std.mem.eql(u8, argument, "--maximum-gc-objects-deleted")) {
            try setPackageCacheOnce(&seen, .maximum_gc_objects_deleted);
            request.limits.maximum_gc_objects_deleted = try packageCacheUsize(try next(args));
        } else if (std.mem.eql(u8, argument, "--maximum-gc-bytes-deleted")) {
            try setPackageCacheOnce(&seen, .maximum_gc_bytes_deleted);
            request.limits.maximum_gc_bytes_deleted = try number(try next(args));
        } else {
            return error.InvalidArguments;
        }
    }

    request.source_paths = try sources.toOwnedSlice(allocator);
    request.config_paths = try configs.toOwnedSlice(allocator);
    request.keyring_paths = try keyrings.toOwnedSlice(allocator);
    request.foreign_architectures = try foreign_architectures.toOwnedSlice(allocator);
    if (operation == .fingerprint and
        (request.source_paths.len != 0 or request.config_paths.len != 0 or
            request.keyring_paths.len != 0 or request.default_release != null or
            request.proxy != null or request.credential_reference != null or
            request.offline or request.deadline_ms != null or
            seen.contains(.lock_wait) or
            seen.contains(.maximum_repository_records) or
            seen.contains(.maximum_staging_entries) or
            seen.contains(.maximum_gc_directory_entries) or
            seen.contains(.maximum_gc_objects_scanned) or
            seen.contains(.maximum_gc_objects_deleted) or
            seen.contains(.maximum_gc_bytes_deleted) or
            request.archive_input_path != null or
            request.archive_output_path != null or
            request.restored_cache != .none))
        return error.InvalidArguments;
    return request;
}

fn setPackageCacheOnce(
    seen: *std.EnumSet(PackageCacheSingleOption),
    option: PackageCacheSingleOption,
) CliError!void {
    if (seen.contains(option)) return error.InvalidArguments;
    seen.insert(option);
}

fn packageCacheUsize(value: []const u8) CliError!usize {
    const parsed = try number(value);
    return std.math.cast(usize, parsed) orelse error.InvalidNumber;
}

const PackageCacheFailure = struct {
    status: u8,
    id: []const u8,
};

fn packageCacheFailure(err: anyerror) PackageCacheFailure {
    return switch (err) {
        error.InvalidRequest,
        error.InvalidArchitecture,
        error.ArchitectureMismatch,
        error.UnsupportedPackageArchitecture,
        error.LockPolicyMismatch,
        error.TooManyPackages,
        error.TooManyRepositoryRecords,
        error.PackageTooLarge,
        error.TotalPackageBytesExceeded,
        error.DuplicatePackageDigest,
        error.InvalidAbsolutePath,
        error.InvalidRepositoryConfig,
        error.InvalidCredentialFile,
        error.InvalidCredentialScope,
        error.CredentialBearingProxy,
        error.CredentialBearingBaseUri,
        error.InvalidBaseUri,
        error.InvalidConfiguration,
        error.UnsupportedScheme,
        error.InvalidFileUri,
        error.NonLocalFileAuthority,
        error.AmbiguousFilePath,
        error.FileNotFound,
        error.SymLinkLoop,
        error.NotDir,
        error.NotRegularFile,
        error.AccessDenied,
        error.PathAlreadyExists,
        => .{ .status = @intFromEnum(api.ExitStatus.usage), .id = "invalid_request" },
        error.UnsupportedLockSchema => .{
            .status = @intFromEnum(api.ExitStatus.planning),
            .id = "unsupported_lock_schema",
        },
        error.InvalidExactLock => .{
            .status = @intFromEnum(api.ExitStatus.planning),
            .id = "invalid_lock",
        },
        error.MissingRepository,
        error.RepositoryEvidenceMismatch,
        error.MissingPackage,
        error.AmbiguousPackage,
        error.PackageEvidenceMismatch,
        error.LockPackageMismatch,
        => .{ .status = @intFromEnum(api.ExitStatus.planning), .id = "lock_evidence_mismatch" },
        error.RepositoryAuthenticationFailed,
        error.NoValidAcceptedSignature,
        error.WrongSigningKey,
        error.InvalidSignature,
        error.MalformedKeyring,
        error.NoKeyrings,
        => .{ .status = @intFromEnum(api.ExitStatus.authentication), .id = "repository_authentication_failed" },
        error.OfflineRepositoryEvidenceMissing,
        error.CacheMiss,
        => .{ .status = @intFromEnum(api.ExitStatus.download), .id = "offline_cache_miss" },
        error.CorruptObject => .{
            .status = @intFromEnum(api.ExitStatus.download),
            .id = "corrupt_cache_object",
        },
        error.InvalidArchive,
        error.InvalidArchiveFile,
        error.ArchiveTooLarge,
        error.TooManyObjects,
        error.ObjectTooLarge,
        error.TotalObjectBytesExceeded,
        error.DuplicateObject,
        error.NonCanonicalOrder,
        error.TruncatedArchive,
        error.TrailingArchiveData,
        error.ArchiveDigestMismatch,
        error.ObjectDigestMismatch,
        error.LockObjectMismatch,
        => .{
            .status = @intFromEnum(api.ExitStatus.download),
            .id = "corrupt_cache_archive",
        },
        error.InvalidPackagePayload => .{
            .status = @intFromEnum(api.ExitStatus.download),
            .id = "payload_validation_failed",
        },
        error.SizeMismatch,
        error.DigestMismatch,
        error.ResponseTooLarge,
        error.RedirectLimitExceeded,
        error.MissingRedirectLocation,
        error.InvalidRedirect,
        error.NotFound,
        error.HttpStatus,
        error.OverallDeadlineExceeded,
        error.InsecureTransport,
        error.ConnectionResetByPeer,
        error.ConnectionTimedOut,
        => .{
            .status = @intFromEnum(api.ExitStatus.download),
            .id = "package_download_failed",
        },
        error.LockBusy => .{
            .status = @intFromEnum(api.ExitStatus.unavailable),
            .id = "cache_lock_busy",
        },
        error.CleanupIncomplete => .{
            .status = @intFromEnum(api.ExitStatus.unavailable),
            .id = "staging_cleanup_incomplete",
        },
        error.GarbageCollectionIncomplete => .{
            .status = @intFromEnum(api.ExitStatus.unavailable),
            .id = "garbage_collection_incomplete",
        },
        else => .{ .status = @intFromEnum(api.ExitStatus.internal), .id = "internal_error" },
    };
}

fn renderPackageCacheError(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    operation: PackageCacheOperation,
    json: bool,
    status: u8,
    id: []const u8,
    message: []const u8,
) !void {
    if (json) {
        const output = try debz.package_cache_workflow.errorJson(
            allocator,
            @tagName(operation),
            status,
            id,
            message,
        );
        try stdout.writeAll(output);
    } else {
        try stderr.print("debz[package-cache:{s}:{s}]: {s}\n", .{
            @tagName(operation),
            id,
            message,
        });
    }
}

fn runRepository(
    init: std.process.Init,
    args: *std.process.Args.Iterator,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !void {
    const subcommand = args.next() orelse {
        try stderr.writeAll("debz: missing command for 'debz repo'\n");
        try stderr.writeAll(repository_help);
        try stderr.flush();
        std.process.exit(@intFromEnum(repository_api.ExitStatus.usage));
    };
    if (!std.mem.eql(u8, subcommand, "add")) {
        try stderr.print("debz: unknown repository command '{s}'\n", .{subcommand});
        try stderr.writeAll(repository_help);
        try stderr.flush();
        std.process.exit(@intFromEnum(repository_api.ExitStatus.usage));
    }

    var arguments: std.ArrayList([]const u8) = .empty;
    while (args.next()) |argument| try arguments.append(init.arena.allocator(), argument);
    const parsed = repository_cli.parseAdd(arguments.items) catch |err| {
        const output = requestedRepositoryOutput(arguments.items);
        if (output == .json) {
            const invalid = repository_api.failure(
                .usage,
                if (err == error.InvalidDigest) .invalid_digest else .invalid_request,
                "request",
                @errorName(err),
            );
            try renderRepository(init.arena.allocator(), stdout, stderr, output, invalid);
        } else {
            try stderr.print("debz: {s}\n", .{@errorName(err)});
            try stderr.writeAll("Try 'debz repo add --help'.\n");
        }
        try stdout.flush();
        try stderr.flush();
        std.process.exit(@intFromEnum(repository_api.ExitStatus.usage));
    };

    var backend_context: debz.ProductionRepositoryBackend = .{ .io = init.io };
    var result = repository_api.execute(
        init.arena.allocator(),
        parsed.request,
        backend_context.interface(),
    ) catch {
        const internal = repository_api.failure(
            .internal,
            .internal_error,
            "internal",
            "internal execution error",
        );
        try renderRepository(
            init.arena.allocator(),
            stdout,
            stderr,
            parsed.output,
            internal,
        );
        try stdout.flush();
        try stderr.flush();
        std.process.exit(@intFromEnum(internal.exit_status));
    };
    defer result.deinit();
    try renderRepository(
        init.arena.allocator(),
        stdout,
        stderr,
        parsed.output,
        result,
    );
    if (result.exit_status != .success) {
        try stdout.flush();
        try stderr.flush();
        std.process.exit(@intFromEnum(result.exit_status));
    }
}

fn requestedRepositoryOutput(arguments: []const []const u8) repository_cli.OutputFormat {
    for (arguments) |argument| {
        if (std.mem.eql(u8, argument, "--json")) return .json;
    }
    return .human;
}

fn renderRepository(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    format: repository_cli.OutputFormat,
    result: repository_api.Result,
) !void {
    if (format == .json) {
        const json = try result.canonicalJson(allocator);
        try stdout.writeAll(json);
        return;
    }
    const writer = if (result.exit_status == .success) stdout else stderr;
    const summary = try result.humanSummary(allocator);
    defer allocator.free(summary);
    try writer.print("repo add: {s}", .{summary});
    if (result.descriptor == null and result.installed_phase != .pending) {
        try writer.print(
            "; installed={s}; refreshed={s}",
            .{
                if (result.installed) "yes" else "no",
                if (result.refreshed) "yes" else "no",
            },
        );
    }
    try writer.writeByte('\n');
    for (result.diagnostics[0..result.diagnostic_count]) |diagnostic| {
        if (diagnostic.phase) |phase| {
            try writer.print(
                "debz[{s}] ({s}): {s}\n",
                .{ @tagName(diagnostic.id), phase, diagnostic.message },
            );
        } else {
            try writer.print(
                "debz[{s}]: {s}\n",
                .{ @tagName(diagnostic.id), diagnostic.message },
            );
        }
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

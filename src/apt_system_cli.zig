//! Pure CLI contract for the deliberately limited `debz apt` facade.
//!
//! This module performs no filesystem, profile, repository, root, mount,
//! environment, terminal, or backend I/O. It is intentionally not wired into
//! `main.zig`; later integration can consume the typed request and confirmation
//! decision defined here.
const std = @import("std");
const api = @import("apt_system_api.zig");
const system_profile = @import("system_profile.zig");

pub const maximum_arguments: usize = api.maximum_packages + 5;
pub const maximum_argument_bytes: usize = system_profile.maximum_path_bytes;

pub const OutputFormat = enum {
    human,
    json,
};

pub const HelpTopic = enum {
    apt,
    update,
    install,
    remove,
    upgrade,
    list,
};

pub const UsageDiagnosticId = enum {
    too_many_arguments,
    argument_too_long,
    missing_command,
    unknown_command,
    unknown_option,
    duplicate_option,
    missing_option_value,
    invalid_profile_path,
    passthrough_not_supported,
    missing_package,
    invalid_package,
    duplicate_package,
    package_looks_like_option,
    extra_operand,
    missing_installed_option,
    unsupported_list_option,
    mixed_list_options,
    misplaced_facade_option,
};

pub const UsageFailure = struct {
    id: UsageDiagnosticId,
    topic: HelpTopic,
    argument: ?[]const u8 = null,
};

pub const ParsedCommand = struct {
    request: api.Request,
    request_sha256: [32]u8,
    output: OutputFormat,
};

pub const ParseResult = union(enum) {
    help: HelpTopic,
    command: ParsedCommand,
    failure: UsageFailure,
};

pub const ConfirmationDecision = enum {
    proceed_without_prompt,
    await_plan,
    request_tty_confirmation,
    return_confirmation_required,
};

const apt_help =
    \\debz apt - deliberately limited apt-shaped system facade
    \\
    \\Usage:
    \\  debz apt [--profile PATH] [--json] <command>
    \\
    \\Commands:
    \\  update
    \\  install [-y] PACKAGE...
    \\  remove [-y] PACKAGE...
    \\  upgrade [-y]
    \\  list --installed
    \\
    \\Facade options:
    \\  --profile PATH  Use PATH (default: /etc/debz/default.json)
    \\  --json          Emit one canonical apt-system result object
    \\  -h, --help      Show help
    \\
    \\--profile and --json are accepted only here: after 'apt' and before the
    \\command. This interface is apt-shaped, not apt-compatible. It does not
    \\inherit APT configuration, proxies, credentials, or keyrings, and it has
    \\no apt-get alias or '--' passthrough.
    \\
;

const update_help =
    \\debz apt update - refresh authenticated metadata
    \\
    \\Usage:
    \\  debz apt [--profile PATH] [--json] update
    \\
    \\This is an apt-shaped command, not an apt-compatible command.
    \\
;

const install_help =
    \\debz apt install - plan one atomic package installation
    \\
    \\Usage:
    \\  debz apt [--profile PATH] [--json] install [-y] PACKAGE...
    \\
    \\-y is the only command option and must precede every package. Without -y,
    \\human integration may request TTY confirmation only after a plan exists.
    \\JSON integration must never prompt.
    \\
;

const remove_help =
    \\debz apt remove - plan one atomic package removal
    \\
    \\Usage:
    \\  debz apt [--profile PATH] [--json] remove [-y] PACKAGE...
    \\
    \\-y is the only command option and must precede every package. Without -y,
    \\human integration may request TTY confirmation only after a plan exists.
    \\JSON integration must never prompt.
    \\
;

const upgrade_help =
    \\debz apt upgrade - plan one atomic installed-package upgrade
    \\
    \\Usage:
    \\  debz apt [--profile PATH] [--json] upgrade [-y]
    \\
    \\-y is the only command option. Without -y, human integration may request
    \\TTY confirmation only after a plan exists. JSON integration never prompts.
    \\
;

const list_help =
    \\debz apt list - list installed packages
    \\
    \\Usage:
    \\  debz apt [--profile PATH] [--json] list --installed
    \\
    \\--installed is required and is the only accepted list option.
    \\
;

pub fn helpText(topic: HelpTopic) []const u8 {
    return switch (topic) {
        .apt => apt_help,
        .update => update_help,
        .install => install_help,
        .remove => remove_help,
        .upgrade => upgrade_help,
        .list => list_help,
    };
}

pub fn parse(arguments: []const []const u8) ParseResult {
    if (arguments.len > maximum_arguments) {
        return failure(.too_many_arguments, .apt, null);
    }
    if (detectHelp(arguments)) |topic| return .{ .help = topic };
    for (arguments) |argument| {
        if (argument.len > maximum_argument_bytes) {
            return failure(.argument_too_long, .apt, null);
        }
    }
    if (arguments.len == 0) return .{ .help = .apt };

    var profile_path: []const u8 = system_profile.default_profile_path;
    var output: OutputFormat = .human;
    var seen_profile = false;
    var seen_json = false;
    var index: usize = 0;
    while (index < arguments.len) {
        const argument = arguments[index];
        if (std.mem.eql(u8, argument, "--profile")) {
            if (seen_profile) {
                return failure(.duplicate_option, .apt, argument);
            }
            seen_profile = true;
            index += 1;
            if (index >= arguments.len) {
                return failure(.missing_option_value, .apt, "--profile");
            }
            profile_path = arguments[index];
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, argument, "--json")) {
            if (seen_json) return failure(.duplicate_option, .apt, argument);
            seen_json = true;
            output = .json;
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, argument, "--")) {
            return failure(.passthrough_not_supported, .apt, argument);
        }
        if (startsWithDash(argument)) {
            return failure(.unknown_option, .apt, argument);
        }
        break;
    }
    if (index >= arguments.len) {
        return failure(.missing_command, .apt, null);
    }

    const command = arguments[index];
    index += 1;
    const topic = commandTopic(command) orelse {
        return failure(.unknown_command, .apt, command);
    };
    const trailing = arguments[index..];
    const request: api.Request = switch (topic) {
        .update => parseUpdate(profile_path, output, trailing) catch |err|
            return parseFailure(err, topic),
        .install => parseMutation(
            .install,
            profile_path,
            output,
            trailing,
        ) catch |err| return parseFailure(err, topic),
        .remove => parseMutation(
            .remove,
            profile_path,
            output,
            trailing,
        ) catch |err| return parseFailure(err, topic),
        .upgrade => parseUpgrade(profile_path, output, trailing) catch |err|
            return parseFailure(err, topic),
        .list => parseList(profile_path, output, trailing) catch |err|
            return parseFailure(err, topic),
        .apt => unreachable,
    };
    api.validateRequest(request) catch |err| {
        return validationFailure(err, topic);
    };
    const request_sha256 = request.digest() catch |err| {
        return validationFailure(err, topic);
    };
    return .{ .command = .{
        .request = request,
        .request_sha256 = request_sha256,
        .output = output,
    } };
}

const CommandParseError = error{
    DuplicateOption,
    PassthroughNotSupported,
    MissingPackage,
    InvalidPackage,
    PackageLooksLikeOption,
    ExtraOperand,
    MissingInstalledOption,
    UnsupportedListOption,
    MixedListOptions,
    MisplacedFacadeOption,
};

fn parseUpdate(
    profile_path: []const u8,
    _: OutputFormat,
    arguments: []const []const u8,
) CommandParseError!api.Request {
    if (arguments.len != 0) return classifyExtra(arguments[0], false);
    return .{ .operation = .update, .profile_path = profile_path };
}

fn parseMutation(
    operation: api.Operation,
    profile_path: []const u8,
    _: OutputFormat,
    arguments: []const []const u8,
) CommandParseError!api.Request {
    var assume_yes = false;
    var package_index: usize = 0;
    if (arguments.len != 0 and std.mem.eql(u8, arguments[0], "-y")) {
        assume_yes = true;
        package_index = 1;
    }
    const packages = arguments[package_index..];
    if (packages.len == 0) return error.MissingPackage;
    if (packages.len > api.maximum_packages) return error.InvalidPackage;
    for (packages) |package| {
        if (isFacadeOption(package)) return error.MisplacedFacadeOption;
        if (std.mem.eql(u8, package, "--")) {
            return error.PassthroughNotSupported;
        }
        if (std.mem.eql(u8, package, "-y")) return error.DuplicateOption;
        if (package.len > 255) return error.InvalidPackage;
        if (startsWithDash(package)) return error.PackageLooksLikeOption;
    }
    return .{
        .operation = operation,
        .profile_path = profile_path,
        .packages = packages,
        .assume_yes = assume_yes,
    };
}

fn parseUpgrade(
    profile_path: []const u8,
    _: OutputFormat,
    arguments: []const []const u8,
) CommandParseError!api.Request {
    var assume_yes = false;
    if (arguments.len != 0) {
        if (std.mem.eql(u8, arguments[0], "-y")) {
            assume_yes = true;
            if (arguments.len > 1) {
                if (std.mem.eql(u8, arguments[1], "-y"))
                    return error.DuplicateOption;
                return classifyExtra(arguments[1], false);
            }
        } else return classifyExtra(arguments[0], false);
    }
    return .{
        .operation = .upgrade,
        .profile_path = profile_path,
        .assume_yes = assume_yes,
    };
}

fn parseList(
    profile_path: []const u8,
    _: OutputFormat,
    arguments: []const []const u8,
) CommandParseError!api.Request {
    if (arguments.len == 0) return error.MissingInstalledOption;
    if (!std.mem.eql(u8, arguments[0], "--installed")) {
        if (std.mem.eql(u8, arguments[0], "--"))
            return error.PassthroughNotSupported;
        if (isFacadeOption(arguments[0])) return error.MisplacedFacadeOption;
        if (startsWithDash(arguments[0])) return error.UnsupportedListOption;
        return error.MissingInstalledOption;
    }
    if (arguments.len > 1) {
        const extra = arguments[1];
        if (std.mem.eql(u8, extra, "--installed"))
            return error.DuplicateOption;
        if (std.mem.eql(u8, extra, "--"))
            return error.PassthroughNotSupported;
        if (isFacadeOption(extra)) return error.MisplacedFacadeOption;
        if (startsWithDash(extra)) return error.MixedListOptions;
        return error.ExtraOperand;
    }
    return .{ .operation = .list_installed, .profile_path = profile_path };
}

fn classifyExtra(
    argument: []const u8,
    list_mode: bool,
) CommandParseError {
    if (std.mem.eql(u8, argument, "--"))
        return error.PassthroughNotSupported;
    if (isFacadeOption(argument)) return error.MisplacedFacadeOption;
    if (startsWithDash(argument)) {
        if (list_mode) return error.MixedListOptions;
        return error.PackageLooksLikeOption;
    }
    return error.ExtraOperand;
}

fn parseFailure(err: CommandParseError, topic: HelpTopic) ParseResult {
    const id: UsageDiagnosticId = switch (err) {
        error.DuplicateOption => .duplicate_option,
        error.PassthroughNotSupported => .passthrough_not_supported,
        error.MissingPackage => .missing_package,
        error.InvalidPackage => .invalid_package,
        error.PackageLooksLikeOption => .package_looks_like_option,
        error.ExtraOperand => .extra_operand,
        error.MissingInstalledOption => .missing_installed_option,
        error.UnsupportedListOption => .unsupported_list_option,
        error.MixedListOptions => .mixed_list_options,
        error.MisplacedFacadeOption => .misplaced_facade_option,
    };
    return failure(id, topic, null);
}

fn validationFailure(err: anyerror, topic: HelpTopic) ParseResult {
    const id: UsageDiagnosticId = switch (err) {
        error.InvalidProfilePath => .invalid_profile_path,
        error.InvalidPackageCount => .missing_package,
        error.InvalidPackage => .invalid_package,
        error.DuplicatePackage => .duplicate_package,
        else => .invalid_package,
    };
    return failure(id, topic, null);
}

fn failure(
    id: UsageDiagnosticId,
    topic: HelpTopic,
    argument: ?[]const u8,
) ParseResult {
    return .{ .failure = .{
        .id = id,
        .topic = topic,
        .argument = argument,
    } };
}

fn detectHelp(arguments: []const []const u8) ?HelpTopic {
    var has_help = false;
    for (arguments) |argument| {
        if (std.mem.eql(u8, argument, "-h") or
            std.mem.eql(u8, argument, "--help"))
        {
            has_help = true;
        }
    }
    if (!has_help) return null;

    var index: usize = 0;
    while (index < arguments.len) {
        const argument = arguments[index];
        if (std.mem.eql(u8, argument, "--profile")) {
            index += @min(@as(usize, 2), arguments.len - index);
            continue;
        }
        if (std.mem.eql(u8, argument, "--json")) {
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, argument, "-h") or
            std.mem.eql(u8, argument, "--help"))
        {
            return .apt;
        }
        if (startsWithDash(argument)) return .apt;
        return commandTopic(argument);
    }
    return .apt;
}

fn commandTopic(command: []const u8) ?HelpTopic {
    if (std.mem.eql(u8, command, "update")) return .update;
    if (std.mem.eql(u8, command, "install")) return .install;
    if (std.mem.eql(u8, command, "remove")) return .remove;
    if (std.mem.eql(u8, command, "upgrade")) return .upgrade;
    if (std.mem.eql(u8, command, "list")) return .list;
    return null;
}

fn startsWithDash(argument: []const u8) bool {
    return argument.len != 0 and argument[0] == '-';
}

fn isFacadeOption(argument: []const u8) bool {
    return std.mem.eql(u8, argument, "--profile") or
        std.mem.eql(u8, argument, "--json");
}

pub fn confirmationDecision(
    command: ParsedCommand,
    plan_exists: bool,
) ConfirmationDecision {
    if (!command.request.operation.mutatesRoot() or
        command.request.assume_yes)
    {
        return .proceed_without_prompt;
    }
    if (!plan_exists) return .await_plan;
    return switch (command.output) {
        .human => .request_tty_confirmation,
        .json => .return_confirmation_required,
    };
}

pub fn confirmationRequiredResult(command: ParsedCommand) !api.Result {
    if (confirmationDecision(command, true) != .return_confirmation_required)
        return error.ConfirmationNotRequired;
    return api.failure(
        command.request,
        .usage,
        .confirmation_required,
        "confirmation",
        "confirmation is required; JSON mode never prompts",
    );
}

pub fn writeUsageFailure(
    writer: *std.Io.Writer,
    usage_failure: UsageFailure,
) !void {
    try writer.print(
        "debz apt: usage error [{s}]: {s}",
        .{
            @tagName(usage_failure.id),
            diagnosticMessage(usage_failure.id),
        },
    );
    if (usage_failure.argument) |argument| {
        try writer.print(" ('{s}')", .{argument});
    }
    try writer.writeByte('\n');
    try writer.writeAll(helpText(usage_failure.topic));
}

fn diagnosticMessage(id: UsageDiagnosticId) []const u8 {
    return switch (id) {
        .too_many_arguments => "too many arguments",
        .argument_too_long => "argument exceeds the bounded CLI limit",
        .missing_command => "missing apt command",
        .unknown_command => "unknown apt command",
        .unknown_option => "unknown facade option",
        .duplicate_option => "duplicate singleton option",
        .missing_option_value => "missing option value",
        .invalid_profile_path => "profile path must be a bounded absolute non-root path",
        .passthrough_not_supported => "'--' passthrough is not supported",
        .missing_package => "at least one package is required",
        .invalid_package => "invalid or excessive package token",
        .duplicate_package => "duplicate package token",
        .package_looks_like_option => "package tokens must not begin with '-'",
        .extra_operand => "unexpected extra operand",
        .missing_installed_option => "list requires exactly --installed",
        .unsupported_list_option => "unsupported list option",
        .mixed_list_options => "--installed cannot be mixed with other list options",
        .misplaced_facade_option => "--profile and --json must precede the command",
    };
}

pub fn writeResult(
    allocator: std.mem.Allocator,
    result: api.Result,
    output: OutputFormat,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !void {
    switch (output) {
        .json => {
            const document = try result.canonicalJson(allocator);
            defer allocator.free(document);
            try stdout.writeAll(document);
            try stdout.writeByte('\n');
        },
        .human => {
            try api.validateCompleteResult(result);
            const writer = if (result.outcome == .success) stdout else stderr;
            try writeHumanResult(result, writer);
        },
    }
}

fn writeHumanResult(result: api.Result, writer: *std.Io.Writer) !void {
    try writer.writeAll(
        "debz apt: apt-shaped system result (not apt-compatible)\n",
    );
    try writer.print(
        "Operation: {s}\nOutcome: {s}\nExit status: {}\nChanged: {s}\n",
        .{
            @tagName(result.operation),
            @tagName(result.outcome),
            @intFromEnum(result.exit_status),
            if (result.changed) "yes" else "no",
        },
    );
    try writer.print("Plan/change details: {s}\n", .{result.summary});
    try writer.writeAll("Request SHA-256: ");
    try writeHex(writer, &result.request_sha256);
    try writer.writeByte('\n');
    if (result.profile) |profile| {
        try writer.print("Profile: {s}\nProfile SHA-256: ", .{profile.path});
        try writeHex(writer, &profile.sha256);
        try writer.writeAll("\nProfile reference evidence SHA-256: ");
        try writeHex(writer, &profile.reference_evidence_sha256);
        try writer.writeByte('\n');
    } else {
        try writer.writeAll("Profile: none\n");
    }
    try writeDocument("Exact lock", result.evidence.exact_lock, writer);
    try writeDocument(
        "Transaction result",
        result.evidence.transaction_result,
        writer,
    );
    if (result.evidence.root_operation_completion) |completion| {
        try writeDocument(
            "Root operation completion",
            completion.document,
            writer,
        );
        try writer.writeAll("Completed attempt ID: ");
        try writeHex(writer, &completion.completed_attempt_id);
        try writer.writeByte('\n');
    } else {
        try writer.writeAll("Root operation completion: none\n");
    }
    if (result.evidence.active_operation_state) |path| {
        try writer.print("Active operation state: {s}\n", .{path});
    } else {
        try writer.writeAll("Active operation state: none\n");
    }
    for (result.diagnostics[0..result.diagnostic_count]) |diagnostic| {
        try writer.print(
            "Diagnostic [{s}] ({s})",
            .{ @tagName(diagnostic.id), @tagName(diagnostic.outcome) },
        );
        if (diagnostic.phase) |phase| try writer.print(" phase={s}", .{phase});
        try writer.print(": {s}\n", .{diagnostic.message});
    }
    try writer.writeAll("Result SHA-256: ");
    try writeHex(writer, &result.digest_sha256);
    try writer.writeByte('\n');
}

fn writeDocument(
    label: []const u8,
    binding: ?api.DocumentBinding,
    writer: *std.Io.Writer,
) !void {
    if (binding) |document| {
        try writer.print(
            "{s}: {s}\n{s} schema: {s} v{}\n{s} SHA-256: ",
            .{
                label,
                document.path,
                label,
                document.schema,
                document.version,
                label,
            },
        );
        try writeHex(writer, &document.digest_sha256);
        try writer.writeByte('\n');
    } else {
        try writer.print("{s}: none\n", .{label});
    }
}

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
}

fn expectCommand(
    arguments: []const []const u8,
    operation: api.Operation,
    output: OutputFormat,
    assume_yes: bool,
    packages: []const []const u8,
) !ParsedCommand {
    const result = parse(arguments);
    const command = switch (result) {
        .command => |value| value,
        else => return error.ExpectedCommand,
    };
    try std.testing.expectEqual(operation, command.request.operation);
    try std.testing.expectEqual(output, command.output);
    try std.testing.expectEqual(assume_yes, command.request.assume_yes);
    try std.testing.expectEqual(packages.len, command.request.packages.len);
    for (packages, command.request.packages) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
    const expected_digest = try command.request.digest();
    try std.testing.expectEqualSlices(
        u8,
        &expected_digest,
        &command.request_sha256,
    );
    return command;
}

fn expectFailure(
    arguments: []const []const u8,
    expected: UsageDiagnosticId,
) !void {
    const result = parse(arguments);
    switch (result) {
        .failure => |value| try std.testing.expectEqual(expected, value.id),
        else => return error.ExpectedFailure,
    }
}

test "apt_system_cli.test.valid grammar table produces typed API requests" {
    const cases = [_]struct {
        arguments: []const []const u8,
        operation: api.Operation,
        output: OutputFormat = .human,
        assume_yes: bool = false,
        packages: []const []const u8 = &.{},
        profile: []const u8 = system_profile.default_profile_path,
    }{
        .{ .arguments = &.{"update"}, .operation = .update },
        .{
            .arguments = &.{ "install", "curl" },
            .operation = .install,
            .packages = &.{"curl"},
        },
        .{
            .arguments = &.{ "install", "-y", "curl", "ca-certificates" },
            .operation = .install,
            .assume_yes = true,
            .packages = &.{ "curl", "ca-certificates" },
        },
        .{
            .arguments = &.{ "remove", "curl" },
            .operation = .remove,
            .packages = &.{"curl"},
        },
        .{
            .arguments = &.{ "remove", "-y", "curl", "wget" },
            .operation = .remove,
            .assume_yes = true,
            .packages = &.{ "curl", "wget" },
        },
        .{ .arguments = &.{"upgrade"}, .operation = .upgrade },
        .{
            .arguments = &.{ "upgrade", "-y" },
            .operation = .upgrade,
            .assume_yes = true,
        },
        .{ .arguments = &.{ "list", "--installed" }, .operation = .list_installed },
        .{
            .arguments = &.{ "--profile", "/etc/debz/reviewed.json", "--json", "update" },
            .operation = .update,
            .output = .json,
            .profile = "/etc/debz/reviewed.json",
        },
        .{
            .arguments = &.{ "--json", "--profile", "/etc/debz/reviewed.json", "install", "-y", "zlib1g:amd64=1.2.13+dfsg-1" },
            .operation = .install,
            .output = .json,
            .assume_yes = true,
            .packages = &.{"zlib1g:amd64=1.2.13+dfsg-1"},
            .profile = "/etc/debz/reviewed.json",
        },
    };
    for (cases) |case| {
        const command = try expectCommand(
            case.arguments,
            case.operation,
            case.output,
            case.assume_yes,
            case.packages,
        );
        try std.testing.expectEqualStrings(
            case.profile,
            command.request.profile_path,
        );
    }
}

test "apt_system_cli.test.invalid grammar table is strict and typed" {
    const cases = [_]struct {
        arguments: []const []const u8,
        diagnostic: UsageDiagnosticId,
    }{
        .{ .arguments = &.{"apt-get"}, .diagnostic = .unknown_command },
        .{ .arguments = &.{"dist-upgrade"}, .diagnostic = .unknown_command },
        .{ .arguments = &.{"full-upgrade"}, .diagnostic = .unknown_command },
        .{ .arguments = &.{"list-installed"}, .diagnostic = .unknown_command },
        .{ .arguments = &.{ "--unknown", "update" }, .diagnostic = .unknown_option },
        .{ .arguments = &.{ "--json", "--json", "update" }, .diagnostic = .duplicate_option },
        .{ .arguments = &.{ "--profile", "/a", "--profile", "/b", "update" }, .diagnostic = .duplicate_option },
        .{ .arguments = &.{"--profile"}, .diagnostic = .missing_option_value },
        .{ .arguments = &.{ "--profile", "relative", "update" }, .diagnostic = .invalid_profile_path },
        .{ .arguments = &.{"--"}, .diagnostic = .passthrough_not_supported },
        .{ .arguments = &.{ "update", "--" }, .diagnostic = .passthrough_not_supported },
        .{ .arguments = &.{ "update", "-y" }, .diagnostic = .package_looks_like_option },
        .{ .arguments = &.{ "update", "extra" }, .diagnostic = .extra_operand },
        .{ .arguments = &.{"install"}, .diagnostic = .missing_package },
        .{ .arguments = &.{ "install", "-y" }, .diagnostic = .missing_package },
        .{ .arguments = &.{ "install", "--assume-yes", "curl" }, .diagnostic = .package_looks_like_option },
        .{ .arguments = &.{ "install", "curl", "-y" }, .diagnostic = .duplicate_option },
        .{ .arguments = &.{ "install", "curl", "--json" }, .diagnostic = .misplaced_facade_option },
        .{ .arguments = &.{ "install", "curl", "--", "wget" }, .diagnostic = .passthrough_not_supported },
        .{ .arguments = &.{ "install", "curl", "curl" }, .diagnostic = .duplicate_package },
        .{ .arguments = &.{ "install", "bad/name" }, .diagnostic = .invalid_package },
        .{ .arguments = &.{"remove"}, .diagnostic = .missing_package },
        .{ .arguments = &.{ "upgrade", "-y", "-y" }, .diagnostic = .duplicate_option },
        .{ .arguments = &.{ "upgrade", "curl" }, .diagnostic = .extra_operand },
        .{ .arguments = &.{ "upgrade", "--json" }, .diagnostic = .misplaced_facade_option },
        .{ .arguments = &.{"list"}, .diagnostic = .missing_installed_option },
        .{ .arguments = &.{ "list", "--upgradable" }, .diagnostic = .unsupported_list_option },
        .{ .arguments = &.{ "list", "--installed", "--upgradable" }, .diagnostic = .mixed_list_options },
        .{ .arguments = &.{ "list", "--installed", "--installed" }, .diagnostic = .duplicate_option },
        .{ .arguments = &.{ "list", "--installed", "curl" }, .diagnostic = .extra_operand },
        .{ .arguments = &.{ "list", "--installed", "--profile" }, .diagnostic = .misplaced_facade_option },
        .{ .arguments = &.{ "list", "--" }, .diagnostic = .passthrough_not_supported },
    };
    for (cases) |case| try expectFailure(case.arguments, case.diagnostic);
}

test "apt_system_cli.test.help wins for root and valid commands before parsing" {
    const cases = [_]struct {
        arguments: []const []const u8,
        topic: HelpTopic,
    }{
        .{ .arguments = &.{}, .topic = .apt },
        .{ .arguments = &.{"--help"}, .topic = .apt },
        .{ .arguments = &.{ "-h", "--unknown" }, .topic = .apt },
        .{ .arguments = &.{ "--unknown", "--help" }, .topic = .apt },
        .{ .arguments = &.{ "--", "--help" }, .topic = .apt },
        .{ .arguments = &.{ "--profile", "--help" }, .topic = .apt },
        .{ .arguments = &.{ "update", "--unknown", "--help" }, .topic = .update },
        .{ .arguments = &.{ "install", "curl", "--bad", "-h" }, .topic = .install },
        .{ .arguments = &.{ "remove", "--profile", "--help" }, .topic = .remove },
        .{ .arguments = &.{ "upgrade", "-y", "extra", "--help" }, .topic = .upgrade },
        .{ .arguments = &.{ "list", "--installed", "--upgradable", "-h" }, .topic = .list },
        .{ .arguments = &.{ "--json", "install", "--help", "bad/name" }, .topic = .install },
    };
    for (cases) |case| {
        const result = parse(case.arguments);
        switch (result) {
            .help => |topic| try std.testing.expectEqual(case.topic, topic),
            else => return error.ExpectedHelp,
        }
    }
    try expectFailure(
        &.{ "unknown-command", "--help" },
        .unknown_command,
    );
}

test "apt_system_cli.test.parser rejects bounds before traversing rejected input" {
    const inaccessible_arguments = @as(
        [*]const []const u8,
        @ptrFromInt(@alignOf([]const u8)),
    )[0 .. maximum_arguments + 1];
    switch (parse(inaccessible_arguments)) {
        .failure => |value| try std.testing.expectEqual(
            UsageDiagnosticId.too_many_arguments,
            value.id,
        ),
        else => return error.ExpectedFailure,
    }

    const inaccessible_package = @as(
        [*]const u8,
        @ptrFromInt(1),
    )[0..256];
    try expectFailure(
        &.{ "install", inaccessible_package },
        .invalid_package,
    );

    var package_storage: [api.maximum_packages][8]u8 = undefined;
    var maximum: [api.maximum_packages + 1][]const u8 = undefined;
    maximum[0] = "install";
    for (package_storage[0..], 0..) |*storage, index| {
        maximum[index + 1] = try std.fmt.bufPrint(
            storage,
            "p{}",
            .{index},
        );
    }
    const accepted = parse(&maximum);
    switch (accepted) {
        .command => |command| try std.testing.expectEqual(
            api.maximum_packages,
            command.request.packages.len,
        ),
        else => return error.ExpectedCommand,
    }

    var packages: [api.maximum_packages + 2][]const u8 = undefined;
    packages[0] = "install";
    for (packages[1..]) |*package| package.* = "p";
    try expectFailure(&packages, .invalid_package);
}

test "apt_system_cli.test.usage failures render one typed stderr diagnostic" {
    const parsed = parse(&.{ "list", "--installed", "--upgradable" });
    const usage_failure = switch (parsed) {
        .failure => |value| value,
        else => return error.ExpectedFailure,
    };
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeUsageFailure(&output.writer, usage_failure);
    try std.testing.expectEqualStrings(
        "debz apt: usage error [mixed_list_options]: --installed cannot be mixed with other list options\n" ++
            list_help,
        output.written(),
    );
}

fn fixtureResult(request: api.Request) !api.Result {
    return api.complete(.{
        .operation = request.operation,
        .request_sha256 = try request.digest(),
        .profile = .{
            .path = request.profile_path,
            .sha256 = @splat(0x11),
            .reference_evidence_sha256 = @splat(0x22),
        },
        .outcome = .success,
        .exit_status = .success,
        .changed = true,
        .summary = "install curl; install ca-certificates",
        .evidence = .{
            .exact_lock = .{
                .path = "/var/lib/debz/exact-lock.json",
                .schema = "https://debz.dev/schema/exact-lock-v2",
                .version = 2,
                .digest_sha256 = @splat(0x33),
            },
            .transaction_result = .{
                .path = "/var/lib/debz/transaction-result.json",
                .schema = "https://debz.dev/schema/transaction-result-v2",
                .version = 2,
                .digest_sha256 = @splat(0x44),
            },
            .root_operation_completion = .{
                .document = .{
                    .path = "/var/lib/debz/root-completion.json",
                    .schema = "https://debz.dev/schema/root-operation-completion-v1",
                    .version = 1,
                    .digest_sha256 = @splat(0x55),
                },
                .completed_attempt_id = @splat(0x66),
            },
            .active_operation_state = "/var/lib/debz/active-operation.json",
        },
    });
}

test "apt_system_cli.test.human rendering is stable complete and routed by outcome" {
    const command = try expectCommand(
        &.{ "install", "-y", "curl", "ca-certificates" },
        .install,
        .human,
        true,
        &.{ "curl", "ca-certificates" },
    );
    const result = try fixtureResult(command.request);
    var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout.deinit();
    var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr.deinit();
    try writeResult(
        std.testing.allocator,
        result,
        .human,
        &stdout.writer,
        &stderr.writer,
    );
    try std.testing.expectEqualStrings("", stderr.written());
    try std.testing.expectEqualStrings(
        "debz apt: apt-shaped system result (not apt-compatible)\n" ++
            "Operation: install\n" ++
            "Outcome: success\n" ++
            "Exit status: 0\n" ++
            "Changed: yes\n" ++
            "Plan/change details: install curl; install ca-certificates\n" ++
            "Request SHA-256: 49546b6979b7bc700161b86bab36fb3ae38d3bb28432f7080e4b3fc1fe317b49\n" ++
            "Profile: /etc/debz/default.json\n" ++
            "Profile SHA-256: 1111111111111111111111111111111111111111111111111111111111111111\n" ++
            "Profile reference evidence SHA-256: 2222222222222222222222222222222222222222222222222222222222222222\n" ++
            "Exact lock: /var/lib/debz/exact-lock.json\n" ++
            "Exact lock schema: https://debz.dev/schema/exact-lock-v2 v2\n" ++
            "Exact lock SHA-256: 3333333333333333333333333333333333333333333333333333333333333333\n" ++
            "Transaction result: /var/lib/debz/transaction-result.json\n" ++
            "Transaction result schema: https://debz.dev/schema/transaction-result-v2 v2\n" ++
            "Transaction result SHA-256: 4444444444444444444444444444444444444444444444444444444444444444\n" ++
            "Root operation completion: /var/lib/debz/root-completion.json\n" ++
            "Root operation completion schema: https://debz.dev/schema/root-operation-completion-v1 v1\n" ++
            "Root operation completion SHA-256: 5555555555555555555555555555555555555555555555555555555555555555\n" ++
            "Completed attempt ID: 6666666666666666666666666666666666666666666666666666666666666666\n" ++
            "Active operation state: /var/lib/debz/active-operation.json\n" ++
            "Result SHA-256: dabe23ea1aac8f4b4dd7a23b9ebfb181408e7a0834ddb77ebad934709485f915\n",
        stdout.written(),
    );

    const failed = try api.failure(
        command.request,
        .planning,
        .planning_failed,
        "plan",
        "no candidate version",
    );
    stdout.clearRetainingCapacity();
    stderr.clearRetainingCapacity();
    try writeResult(
        std.testing.allocator,
        failed,
        .human,
        &stdout.writer,
        &stderr.writer,
    );
    try std.testing.expectEqualStrings("", stdout.written());
    try std.testing.expect(std.mem.indexOf(
        u8,
        stderr.written(),
        "Diagnostic [planning_failed] (planning) phase=plan: no candidate version",
    ) != null);
}

test "apt_system_cli.test.json rendering is exactly one canonical result document" {
    const command = try expectCommand(
        &.{ "--json", "install", "-y", "curl" },
        .install,
        .json,
        true,
        &.{"curl"},
    );
    const result = try fixtureResult(command.request);
    const canonical = try result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);
    var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout.deinit();
    var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr.deinit();
    try writeResult(
        std.testing.allocator,
        result,
        .json,
        &stdout.writer,
        &stderr.writer,
    );
    try std.testing.expectEqualStrings("", stderr.written());
    try std.testing.expectEqual(canonical.len + 1, stdout.written().len);
    try std.testing.expectEqualStrings(
        canonical,
        stdout.written()[0..canonical.len],
    );
    try std.testing.expectEqual(@as(u8, '\n'), stdout.written()[canonical.len]);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        stdout.written()[0..canonical.len],
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        api.result_schema_id,
        parsed.value.object.get("schema").?.string,
    );
}

test "apt_system_cli.test.confirmation decisions never prompt early or in JSON" {
    const human = try expectCommand(
        &.{ "install", "curl" },
        .install,
        .human,
        false,
        &.{"curl"},
    );
    try std.testing.expectEqual(
        ConfirmationDecision.await_plan,
        confirmationDecision(human, false),
    );
    try std.testing.expectEqual(
        ConfirmationDecision.request_tty_confirmation,
        confirmationDecision(human, true),
    );

    const json = try expectCommand(
        &.{ "--json", "remove", "curl" },
        .remove,
        .json,
        false,
        &.{"curl"},
    );
    try std.testing.expectEqual(
        ConfirmationDecision.await_plan,
        confirmationDecision(json, false),
    );
    try std.testing.expectEqual(
        ConfirmationDecision.return_confirmation_required,
        confirmationDecision(json, true),
    );
    const required = try confirmationRequiredResult(json);
    try std.testing.expectEqual(api.Outcome.usage, required.outcome);
    try std.testing.expectEqual(
        api.DiagnosticId.confirmation_required,
        required.diagnostics[0].id,
    );

    const assumed = try expectCommand(
        &.{ "upgrade", "-y" },
        .upgrade,
        .human,
        true,
        &.{},
    );
    try std.testing.expectEqual(
        ConfirmationDecision.proceed_without_prompt,
        confirmationDecision(assumed, false),
    );
    const non_mutating = try expectCommand(
        &.{"update"},
        .update,
        .human,
        false,
        &.{},
    );
    try std.testing.expectEqual(
        ConfirmationDecision.proceed_without_prompt,
        confirmationDecision(non_mutating, false),
    );
    try std.testing.expectError(
        error.ConfirmationNotRequired,
        confirmationRequiredResult(non_mutating),
    );
}

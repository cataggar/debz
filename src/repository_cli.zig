const std = @import("std");
const debz = @import("debz");
const api = debz.repository_api;

pub const OutputFormat = enum {
    human,
    json,
};

pub const ParsedAdd = struct {
    request: api.Request,
    output: OutputFormat = .human,
};

pub const ParseError = error{
    DuplicateArgument,
    InvalidDigest,
    InvalidNumber,
    MissingUrl,
    MissingValue,
    OutOfMemory,
    UnexpectedArgument,
    UnknownArgument,
};

const Option = enum {
    url,
    root,
    sha256,
    no_refresh,
    missing_valid_until_max_age_seconds,
    json,
    architecture,
    cache_path,
    state_path,
    proxy,
    connect_timeout_ms,
    read_timeout_ms,
    deadline_ms,
    redirect_limit,
    retry_attempts,
    retry_backoff_ms,
    maximum_descriptor_bytes,
    maximum_package_bytes,
    maximum_release_bytes,
    maximum_compressed_index_bytes,
    maximum_decompressed_index_bytes,
    maximum_decoder_memory,
    maximum_cache_object_bytes,
    lock_wait_ms,
    maximum_operation_state_bytes,
    maximum_repositories,
    maximum_actions,
    maximum_total_metadata_bytes,
    maximum_total_package_bytes,
    maximum_retained_package_bytes,
    maximum_cache_growth_bytes,
};

pub fn parseAdd(arguments: []const []const u8) ParseError!ParsedAdd {
    var parsed: ParsedAdd = .{
        .request = .{
            .root = "/",
            .descriptor_url = "",
        },
    };
    var seen: std.EnumSet(Option) = .initEmpty();
    var index: usize = 0;
    var options = true;
    while (index < arguments.len) : (index += 1) {
        const argument = arguments[index];
        if (options and std.mem.eql(u8, argument, "--")) {
            options = false;
            continue;
        }
        if (!options) return error.UnexpectedArgument;
        if (!std.mem.startsWith(u8, argument, "--"))
            return error.UnexpectedArgument;

        if (std.mem.eql(u8, argument, "--url")) {
            try setOnce(&seen, .url);
            parsed.request.descriptor_url = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--root")) {
            try setOnce(&seen, .root);
            parsed.request.root = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--sha256")) {
            try setOnce(&seen, .sha256);
            parsed.request.expected_sha256 = try digest(try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--no-refresh")) {
            try setOnce(&seen, .no_refresh);
            parsed.request.no_refresh = true;
        } else if (std.mem.eql(
            u8,
            argument,
            "--missing-valid-until-max-age-seconds",
        )) {
            try setOnce(&seen, .missing_valid_until_max_age_seconds);
            parsed.request.missing_valid_until_max_age_seconds =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--json")) {
            try setOnce(&seen, .json);
            parsed.output = .json;
        } else if (std.mem.eql(u8, argument, "--architecture")) {
            try setOnce(&seen, .architecture);
            parsed.request.architecture = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--cache-path")) {
            try setOnce(&seen, .cache_path);
            parsed.request.cache.path = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--state-path")) {
            try setOnce(&seen, .state_path);
            parsed.request.state.path = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--proxy")) {
            try setOnce(&seen, .proxy);
            parsed.request.network.proxy_url = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--connect-timeout-ms")) {
            try setOnce(&seen, .connect_timeout_ms);
            parsed.request.network.connect_timeout_ms =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--read-timeout-ms")) {
            try setOnce(&seen, .read_timeout_ms);
            parsed.request.network.read_timeout_ms =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--deadline-ms")) {
            try setOnce(&seen, .deadline_ms);
            parsed.request.network.overall_timeout_ms =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--redirect-limit")) {
            try setOnce(&seen, .redirect_limit);
            parsed.request.network.redirect_limit =
                try number(u16, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--retry-attempts")) {
            try setOnce(&seen, .retry_attempts);
            parsed.request.network.retry_attempts =
                try number(u16, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--retry-backoff-ms")) {
            try setOnce(&seen, .retry_backoff_ms);
            parsed.request.network.retry_backoff_ms =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-descriptor-bytes")) {
            try setOnce(&seen, .maximum_descriptor_bytes);
            parsed.request.network.maximum_descriptor_bytes =
                try number(usize, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-package-bytes")) {
            try setOnce(&seen, .maximum_package_bytes);
            parsed.request.network.maximum_package_bytes =
                try number(usize, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-release-bytes")) {
            try setOnce(&seen, .maximum_release_bytes);
            parsed.request.network.maximum_release_bytes =
                try number(usize, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-compressed-index-bytes")) {
            try setOnce(&seen, .maximum_compressed_index_bytes);
            parsed.request.network.maximum_compressed_index_bytes =
                try number(usize, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-decompressed-index-bytes")) {
            try setOnce(&seen, .maximum_decompressed_index_bytes);
            parsed.request.network.maximum_decompressed_index_bytes =
                try number(usize, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-decoder-memory")) {
            try setOnce(&seen, .maximum_decoder_memory);
            parsed.request.network.maximum_decoder_memory =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-cache-object-bytes")) {
            try setOnce(&seen, .maximum_cache_object_bytes);
            parsed.request.cache.maximum_object_bytes =
                try number(usize, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--lock-wait-ms")) {
            try setOnce(&seen, .lock_wait_ms);
            parsed.request.state.lock_wait_ms =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-operation-state-bytes")) {
            try setOnce(&seen, .maximum_operation_state_bytes);
            parsed.request.state.maximum_operation_state_bytes =
                try number(usize, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-repositories")) {
            try setOnce(&seen, .maximum_repositories);
            parsed.request.resources.maximum_repositories =
                try number(usize, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-actions")) {
            try setOnce(&seen, .maximum_actions);
            parsed.request.resources.maximum_actions =
                try number(usize, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-total-metadata-bytes")) {
            try setOnce(&seen, .maximum_total_metadata_bytes);
            parsed.request.resources.maximum_total_metadata_bytes =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-total-package-bytes")) {
            try setOnce(&seen, .maximum_total_package_bytes);
            parsed.request.resources.maximum_total_package_bytes =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-retained-package-bytes")) {
            try setOnce(&seen, .maximum_retained_package_bytes);
            parsed.request.resources.maximum_retained_package_bytes =
                try number(u64, try next(arguments, &index));
        } else if (std.mem.eql(u8, argument, "--maximum-cache-growth-bytes")) {
            try setOnce(&seen, .maximum_cache_growth_bytes);
            parsed.request.resources.maximum_cache_growth_bytes =
                try number(u64, try next(arguments, &index));
        } else return error.UnknownArgument;
    }
    if (!seen.contains(.url) or parsed.request.descriptor_url.len == 0)
        return error.MissingUrl;
    return parsed;
}

fn setOnce(seen: *std.EnumSet(Option), option: Option) ParseError!void {
    if (seen.contains(option)) return error.DuplicateArgument;
    seen.insert(option);
}

fn next(arguments: []const []const u8, index: *usize) ParseError![]const u8 {
    index.* += 1;
    if (index.* >= arguments.len) return error.MissingValue;
    return arguments[index.*];
}

fn number(comptime T: type, value: []const u8) ParseError!T {
    return std.fmt.parseInt(T, value, 10) catch error.InvalidNumber;
}

fn digest(value: []const u8) ParseError![32]u8 {
    if (value.len != 64) return error.InvalidDigest;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    return result;
}

test "repo add parser applies host defaults and explicit overrides" {
    const defaults = try parseAdd(&.{
        "--url",
        "https://packages.microsoft.test/config.deb",
    });
    try std.testing.expectEqualStrings("/", defaults.request.root);
    try std.testing.expect(defaults.request.architecture == null);
    try std.testing.expect(defaults.request.cache.path == null);
    try std.testing.expect(defaults.request.state.path == null);
    try std.testing.expect(!defaults.request.no_refresh);
    try std.testing.expectEqual(OutputFormat.human, defaults.output);

    const overridden = try parseAdd(&.{
        "--url",
        "https://packages.microsoft.test/config.deb",
        "--root",
        "/image",
        "--sha256",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--architecture",
        "arm64",
        "--cache-path",
        "/custom/cache",
        "--state-path",
        "/custom/state",
        "--proxy",
        "https://proxy.test",
        "--no-refresh",
        "--missing-valid-until-max-age-seconds",
        "604800",
        "--json",
        "--connect-timeout-ms",
        "11",
        "--read-timeout-ms",
        "12",
        "--deadline-ms",
        "13",
        "--redirect-limit",
        "3",
        "--retry-attempts",
        "4",
        "--retry-backoff-ms",
        "5",
        "--maximum-descriptor-bytes",
        "101",
        "--maximum-package-bytes",
        "102",
        "--maximum-release-bytes",
        "103",
        "--maximum-compressed-index-bytes",
        "104",
        "--maximum-decompressed-index-bytes",
        "105",
        "--maximum-decoder-memory",
        "106",
        "--maximum-cache-object-bytes",
        "107",
        "--lock-wait-ms",
        "14",
        "--maximum-operation-state-bytes",
        "108",
        "--maximum-repositories",
        "6",
        "--maximum-actions",
        "7",
        "--maximum-total-metadata-bytes",
        "109",
        "--maximum-total-package-bytes",
        "110",
        "--maximum-retained-package-bytes",
        "111",
        "--maximum-cache-growth-bytes",
        "112",
    });
    try std.testing.expectEqualStrings("/image", overridden.request.root);
    try std.testing.expectEqualStrings("arm64", overridden.request.architecture.?);
    try std.testing.expectEqualStrings("/custom/cache", overridden.request.cache.path.?);
    try std.testing.expectEqualStrings("/custom/state", overridden.request.state.path.?);
    try std.testing.expect(overridden.request.expected_sha256 != null);
    try std.testing.expect(overridden.request.no_refresh);
    try std.testing.expectEqual(
        @as(?u64, 604800),
        overridden.request.missing_valid_until_max_age_seconds,
    );
    try std.testing.expectEqual(OutputFormat.json, overridden.output);
    try std.testing.expectEqual(@as(u64, 13), overridden.request.network.overall_timeout_ms);
    try std.testing.expectEqual(@as(usize, 107), overridden.request.cache.maximum_object_bytes);
    try std.testing.expectEqual(@as(u64, 14), overridden.request.state.lock_wait_ms);
    try std.testing.expectEqual(@as(usize, 7), overridden.request.resources.maximum_actions);
    try std.testing.expectEqual(@as(u64, 112), overridden.request.resources.maximum_cache_growth_bytes);
}

test "repo add parser rejects missing duplicate malformed and positional inputs" {
    try std.testing.expectError(error.MissingUrl, parseAdd(&.{}));
    try std.testing.expectError(error.MissingValue, parseAdd(&.{"--url"}));
    try std.testing.expectError(error.DuplicateArgument, parseAdd(&.{
        "--url",
        "https://one.test/config.deb",
        "--url",
        "https://two.test/config.deb",
    }));
    try std.testing.expectError(error.InvalidDigest, parseAdd(&.{
        "--url",
        "https://packages.test/config.deb",
        "--sha256",
        "xyz",
    }));
    try std.testing.expectError(error.InvalidNumber, parseAdd(&.{
        "--url",
        "https://packages.test/config.deb",
        "--redirect-limit",
        "65536",
    }));
    try std.testing.expectError(error.UnknownArgument, parseAdd(&.{
        "--url",
        "https://packages.test/config.deb",
        "--refresh",
    }));
    try std.testing.expectError(error.UnexpectedArgument, parseAdd(&.{
        "--url",
        "https://packages.test/config.deb",
        "--",
        "operand",
    }));
}

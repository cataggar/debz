const std = @import("std");
const fs = @import("debz").root_fs;

const version = "1.22.22";
const schema_id = "https://debz.dev/schema/dpkg-oracle-execution-evidence-v1";
const receipt_schema = "https://debz.dev/schema/native-dpkg-reference-receipt-v1";
const prefix = ".cache/native-dpkg-reference/1.22.22/arm64";
const archive_url = "https://deb.debian.org/debian/pool/main/d/dpkg/dpkg_1.22.22_arm64.deb";
const archive_digest = "1142468e57f69e13d174f517dff739508c61ee97d81c182c120cd6b281d8cdfa";
const tool_names = [_][]const u8{ "dpkg", "dpkg-query", "update-alternatives" };
const tool_digests = [_][]const u8{
    "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79",
    "a5377f6b04e6d251d013c13a2399cb83db8462bf249949b5d76ae0e22842e83a",
    "35616ec58ba58f3fb8b4820bdf893c47a842d56684b3335ba6ebf6df86b27cc5",
};
const maximum_tool_bytes = 8 * 1024 * 1024;
const maximum_observation_bytes = 2 * 1024 * 1024;
const maximum_output_bytes = 32 * 1024;
const maximum_evidence_bytes = 128 * 1024;
const maximum_document_depth = 64;
const references = [_][]const u8{
    "tools/fixtures/vendor-state/dpkg-config-reference-v1.json",
    "tools/fixtures/vendor-state/dpkg-alternatives-reference-v1.json",
};
const reference_schemas = [_][]const u8{
    "https://debz.dev/schema/dpkg-config-reference-v1",
    "https://debz.dev/schema/dpkg-alternatives-reference-v1",
};

// Field order preserves the existing Python-sorted canonical evidence bytes.
const FileBinding = struct { sha256: []const u8, size: u64 };
const Archive = struct { sha256: []const u8, size: u64, url: []const u8 };
const Receipt = struct {
    architecture: []const u8,
    archive: Archive,
    dpkg: FileBinding,
    dpkg_query: FileBinding,
    schema: []const u8,
    update_alternatives: FileBinding,
    version: []const u8,
};
const Artifact = struct { path: []const u8, sha256: []const u8, size: u64 };
const Tool = struct { path: []const u8, sha256: []const u8, size: u64, version: []const u8 };
const Output = struct { sha256: []const u8, size: u64, text: []const u8 };
const Oracle = struct {
    command: []const []const u8,
    exit: u8,
    observation: Artifact,
    published_reference: Artifact,
    reference_schema: []const u8,
    stderr: Output,
    stdout: Output,
};
const Evidence = struct {
    architecture: []const u8,
    invocation_clock: []const u8,
    oracles: struct { direct_dpkg_config: Oracle, dpkg_update_alternatives: Oracle },
    runner: struct { label: []const u8, machine: []const u8, runner_arch: []const u8 },
    schema: []const u8,
    source: struct {
        commit: []const u8,
        job: []const u8,
        repository: []const u8,
        run_attempt: std.json.Value,
        run_id: std.json.Value,
        workflow: []const u8,
        workflow_path: []const u8,
    },
    tools: struct {
        archive: Archive,
        dpkg: Tool,
        receipt: Artifact,
        update_alternatives: Tool,
    },
    version: u8,
};

fn equal(left: []const u8, right: []const u8) !void {
    if (!std.mem.eql(u8, left, right)) return error.EvidenceIdentityMismatch;
}

fn validHex(text: []const u8, length: usize) bool {
    if (text.len != length) return false;
    for (text) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    return true;
}

fn validName(text: []const u8) bool {
    if (text.len == 0 or !std.ascii.isLower(text[0]) and !std.ascii.isDigit(text[0])) return false;
    for (text) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '.' and byte != '-') return false;
    return true;
}

fn tokenAfter(text: []const u8, marker: []const u8, minimum: usize, underscores: bool) bool {
    var offset: usize = 0;
    while (std.mem.indexOf(u8, text[offset..], marker)) |found| {
        const start = offset + found + marker.len;
        var end = start;
        while (end < text.len and (std.ascii.isAlphanumeric(text[end]) or (underscores and text[end] == '_'))) : (end += 1) {}
        if (end - start >= minimum) return true;
        offset = start;
    }
    return false;
}

fn validatePrivacy(text: []const u8) !void {
    for ([_][]const u8{ "/home/runner/work/", "/Users/runner/", "ACTIONS_ID_TOKEN", "RUNNER_TRACKING_ID" }) |marker| {
        if (std.mem.indexOf(u8, text, marker) != null) return error.PrivateEvidence;
    }
    if (tokenAfter(text, "github_pat_", 1, true)) return error.PrivateEvidence;
    for ("pousr") |kind| {
        const marker = [_]u8{ 'g', 'h', kind, '_' };
        if (tokenAfter(text, &marker, 20, true)) return error.PrivateEvidence;
    }
    for (0..text.len) |index| {
        const marker = "authorization:";
        if (text.len - index <= marker.len) continue;
        if (std.ascii.eqlIgnoreCase(text[index..][0..marker.len], marker) and
            text[index + marker.len] != '\r' and text[index + marker.len] != '\n')
            return error.PrivateEvidence;
    }
}

fn decimal(text: []const u8, minimum: u16, maximum: u16) !u16 {
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidInvocationClock;
    const value = std.fmt.parseInt(u16, text, 10) catch return error.InvalidInvocationClock;
    if (value < minimum or value > maximum) return error.InvalidInvocationClock;
    return value;
}

fn validateClock(text: []const u8) !void {
    if (text.len < 20 or text[4] != '-' or text[7] != '-' or
        (text[10] != 'T' and text[10] != 't') or text[13] != ':' or text[16] != ':')
        return error.InvalidInvocationClock;
    const year = try decimal(text[0..4], 1, 9999);
    const month = try decimal(text[5..7], 1, 12);
    const days = [_]u16{ 31, if (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    _ = try decimal(text[8..10], 1, days[month - 1]);
    _ = try decimal(text[11..13], 0, 23);
    _ = try decimal(text[14..16], 0, 59);
    _ = try decimal(text[17..19], 0, 59);
    var at: usize = 19;
    if (text[at] == '.') {
        at += 1;
        const start = at;
        while (at < text.len and std.ascii.isDigit(text[at])) : (at += 1) {}
        if (at == start) return error.InvalidInvocationClock;
    }
    if (at == text.len) return error.InvalidInvocationClock;
    if ((text[at] == 'Z' or text[at] == 'z') and at + 1 == text.len) return;
    if (text.len - at != 6 or (text[at] != '+' and text[at] != '-') or text[at + 3] != ':')
        return error.InvalidInvocationClock;
    _ = try decimal(text[at + 1 ..][0..2], 0, 23);
    _ = try decimal(text[at + 4 ..][0..2], 0, 59);
}

fn validateBinding(binding: FileBinding, maximum: usize, empty: bool) !void {
    if (!validHex(binding.sha256, 64) or binding.size > maximum or (!empty and binding.size == 0))
        return error.InvalidEvidenceBinding;
}

fn validateEvidence(document: Evidence) !void {
    try equal(document.architecture, "arm64");
    try equal(document.schema, schema_id);
    if (document.version != 1) return error.EvidenceIdentityMismatch;
    try validateClock(document.invocation_clock);
    try equal(document.runner.label, "ubuntu-24.04-arm");
    try equal(document.runner.machine, "aarch64");
    try equal(document.runner.runner_arch, "ARM64");
    if (!validHex(document.source.commit, 40)) return error.EvidenceIdentityMismatch;
    try validateNatural(document.source.run_id);
    try validateNatural(document.source.run_attempt);
    try equal(document.source.job, "arm64-dpkg-oracles");
    try equal(document.source.repository, "cataggar/debz");
    try equal(document.source.workflow, "CI");
    try equal(document.source.workflow_path, ".github/workflows/ci.yml");
    try validateBinding(.{ .sha256 = document.tools.archive.sha256, .size = document.tools.archive.size }, maximum_tool_bytes, false);
    try equal(document.tools.archive.sha256, archive_digest);
    try equal(document.tools.archive.url, archive_url);
    for ([_]Tool{ document.tools.dpkg, document.tools.update_alternatives }) |tool| {
        try validateBinding(.{ .sha256 = tool.sha256, .size = tool.size }, maximum_tool_bytes, false);
        try equal(tool.version, version);
        if (!std.mem.eql(u8, tool.path, prefix ++ "/usr/bin/dpkg") and
            !std.mem.eql(u8, tool.path, prefix ++ "/usr/bin/update-alternatives"))
            return error.EvidenceIdentityMismatch;
    }
    try equal(document.tools.receipt.path, prefix ++ "/reference-receipt-v1.json");
    try validateBinding(.{ .sha256 = document.tools.receipt.sha256, .size = document.tools.receipt.size }, 4096, false);
    for ([_]Oracle{ document.oracles.direct_dpkg_config, document.oracles.dpkg_update_alternatives }) |oracle| {
        if (oracle.exit != 0 or oracle.command.len < 8 or oracle.command.len > 32)
            return error.EvidenceIdentityMismatch;
        for (oracle.command) |argument| {
            const length = try std.unicode.utf8CountCodepoints(argument);
            if (length == 0 or length > 4096) return error.InvalidEvidenceCommand;
        }
        if (!validName(oracle.observation.path)) return error.InvalidArtifactPath;
        try validateBinding(.{ .sha256 = oracle.observation.sha256, .size = oracle.observation.size }, maximum_observation_bytes, false);
        if (!std.mem.eql(u8, oracle.published_reference.path, references[0]) and
            !std.mem.eql(u8, oracle.published_reference.path, references[1]))
            return error.EvidenceIdentityMismatch;
        try validateBinding(.{ .sha256 = oracle.published_reference.sha256, .size = oracle.published_reference.size }, maximum_observation_bytes, false);
        if (!std.mem.eql(u8, oracle.reference_schema, reference_schemas[0]) and
            !std.mem.eql(u8, oracle.reference_schema, reference_schemas[1]))
            return error.EvidenceIdentityMismatch;
        for ([_]Output{ oracle.stderr, oracle.stdout }) |output| {
            try validateBinding(.{ .sha256 = output.sha256, .size = output.size }, maximum_output_bytes, true);
            if (try std.unicode.utf8CountCodepoints(output.text) > maximum_output_bytes)
                return error.InvalidEvidenceOutput;
        }
    }
}

fn canonicalBytes(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{ .whitespace = .indent_2, .escape_unicode = true }, &output.writer);
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

fn validateNatural(value: std.json.Value) !void {
    switch (value) {
        .integer => |number| if (number < 1) return error.InvalidEvidenceInteger,
        .float => |number| if (!std.math.isFinite(number) or number < 1 or @trunc(number) != number) return error.InvalidEvidenceInteger,
        .number_string => |text| {
            if (text.len == 0 or text[0] == '-') return error.InvalidEvidenceInteger;
            if (std.mem.indexOfAny(u8, text, ".eE") == null) {
                var nonzero = false;
                for (text) |byte| {
                    if (!std.ascii.isDigit(byte)) return error.InvalidEvidenceInteger;
                    nonzero = nonzero or byte != '0';
                }
                if (!nonzero) return error.InvalidEvidenceInteger;
            } else {
                const number = std.fmt.parseFloat(f64, text) catch return error.InvalidEvidenceInteger;
                if (!std.math.isFinite(number) or number < 1 or @trunc(number) != number)
                    return error.InvalidEvidenceInteger;
            }
        },
        else => return error.InvalidEvidenceInteger,
    }
}

fn invocationInteger(text: []const u8) !std.json.Value {
    var digits = text;
    if (std.mem.startsWith(u8, digits, "+")) digits = digits[1..];
    while (digits.len > 1 and digits[0] == '0') digits = digits[1..];
    const value: std.json.Value = .{ .number_string = digits };
    if (std.mem.indexOfAny(u8, digits, ".eE") != null) return error.InvalidEvidenceInteger;
    try validateNatural(value);
    return value;
}

fn pythonNumber(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (std.mem.indexOfAny(u8, text, ".eE") == null)
        return allocator.dupe(u8, if (std.mem.eql(u8, text, "-0")) "0" else text);
    const number = try std.fmt.parseFloat(f64, text);
    if (!std.math.isFinite(number)) return error.InvalidEvidenceInteger;
    const magnitude = @abs(number);
    if (magnitude == 0 or (magnitude >= 0.0001 and magnitude < 1.0e16)) {
        const fixed = try std.fmt.allocPrint(allocator, "{d}", .{number});
        if (std.mem.indexOfScalar(u8, fixed, '.') != null) return fixed;
        defer allocator.free(fixed);
        return std.fmt.allocPrint(allocator, "{s}.0", .{fixed});
    }
    const scientific = try std.fmt.allocPrint(allocator, "{e}", .{number});
    defer allocator.free(scientific);
    const exponent_at = std.mem.indexOfScalar(u8, scientific, 'e') orelse return error.InvalidEvidenceInteger;
    const exponent = try std.fmt.parseInt(i16, scientific[exponent_at + 1 ..], 10);
    return std.fmt.allocPrint(allocator, "{s}e{s}{d:0>2}", .{
        scientific[0..exponent_at], if (exponent < 0) "-" else "+", @abs(exponent),
    });
}

fn canonicalValue(value: std.json.Value, stream: *std.json.Stringify, allocator: std.mem.Allocator, depth: usize) anyerror!void {
    if (depth > maximum_document_depth) return error.EvidenceDepthExceeded;
    switch (value) {
        .object => |object| {
            const keys = try allocator.dupe([]const u8, object.keys());
            defer allocator.free(keys);
            std.mem.sort([]const u8, keys, {}, struct {
                fn less(_: void, left: []const u8, right: []const u8) bool {
                    return std.mem.order(u8, left, right) == .lt;
                }
            }.less);
            try stream.beginObject();
            for (keys) |key| {
                try stream.objectField(key);
                try canonicalValue(object.get(key).?, stream, allocator, depth + 1);
            }
            try stream.endObject();
        },
        .array => |array| {
            try stream.beginArray();
            for (array.items) |item| try canonicalValue(item, stream, allocator, depth + 1);
            try stream.endArray();
        },
        .number_string => |number| {
            const formatted = try pythonNumber(allocator, number);
            defer allocator.free(formatted);
            try stream.write(std.json.Value{ .number_string = formatted });
        },
        else => try stream.write(value),
    }
}

fn canonicalDocument(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(std.json.Value) {
    try validatePrivacy(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .max_value_len = maximum_observation_bytes,
        .parse_numbers = false,
    });
    errdefer parsed.deinit();
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var stream: std.json.Stringify = .{
        .writer = &output.writer,
        .options = .{ .whitespace = .indent_2, .escape_unicode = true },
    };
    try canonicalValue(parsed.value, &stream, allocator, 0);
    try output.writer.writeByte('\n');
    if (!std.mem.eql(u8, bytes, output.written())) return error.NoncanonicalEvidence;
    return parsed;
}

const Context = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    repository: []const u8,

    fn absolutePath(self: Context, path: []const u8) ![]u8 {
        return std.fs.path.resolve(self.allocator, &.{ self.repository, path });
    }

    fn read(self: Context, path: []const u8, maximum: usize) ![]u8 {
        const absolute = try self.absolutePath(path);
        defer self.allocator.free(absolute);
        var root = try fs.openAbsoluteRoot(self.io, std.fs.path.dirname(absolute) orelse return error.InvalidArtifactPath);
        defer root.close();
        var pin = try root.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(absolute)));
        defer pin.close();
        if ((try pin.metadata()).entry.link_count != 1) return error.HardLinkedEvidence;
        return (try pin.observeStableAlloc(self.allocator, maximum)).bytes;
    }

    fn digest(self: Context, bytes: []const u8) ![]const u8 {
        var result: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
        return self.allocator.dupe(u8, &std.fmt.bytesToHex(result, .lower));
    }

    fn fileBinding(self: Context, bytes: []const u8) !FileBinding {
        return .{ .sha256 = try self.digest(bytes), .size = bytes.len };
    }

    fn artifact(self: Context, path: []const u8, directory: []const u8) !Artifact {
        const absolute = try self.absolutePath(path);
        defer self.allocator.free(absolute);
        try equal(std.fs.path.dirname(absolute) orelse return error.InvalidArtifactPath, directory);
        const name = std.fs.path.basename(absolute);
        if (!validName(name)) return error.InvalidArtifactPath;
        const bytes = try self.read(absolute, maximum_observation_bytes);
        defer self.allocator.free(bytes);
        try validatePrivacy(bytes);
        return .{ .path = try self.allocator.dupe(u8, name), .sha256 = try self.digest(bytes), .size = bytes.len };
    }

    fn tool(self: Context, index: usize) !FileBinding {
        const path = try std.fmt.allocPrint(self.allocator, "{s}/usr/bin/{s}", .{ prefix, tool_names[index] });
        defer self.allocator.free(path);
        const bytes = try self.read(path, maximum_tool_bytes);
        defer self.allocator.free(bytes);
        const binding = try self.fileBinding(bytes);
        try equal(binding.sha256, tool_digests[index]);
        if (bytes.len == 0) return error.InvalidEvidenceBinding;
        return binding;
    }

    fn output(self: Context, path: []const u8) !Output {
        const bytes = try self.read(path, maximum_output_bytes);
        try validatePrivacy(bytes);
        if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidOutputEncoding;
        return .{ .sha256 = try self.digest(bytes), .size = bytes.len, .text = bytes };
    }

    fn receipt(self: Context, path: []const u8) !Receipt {
        const expected = try self.absolutePath(prefix ++ "/reference-receipt-v1.json");
        defer self.allocator.free(expected);
        const absolute = try self.absolutePath(path);
        defer self.allocator.free(absolute);
        try equal(absolute, expected);
        const bytes = try self.read(absolute, 4096);
        defer self.allocator.free(bytes);
        var parsed = try std.json.parseFromSlice(Receipt, self.allocator, bytes, .{ .allocate = .alloc_always });
        defer parsed.deinit();
        const canonical = try canonicalBytes(self.allocator, parsed.value);
        defer self.allocator.free(canonical);
        try equal(bytes, canonical);
        const value = parsed.value;
        try equal(value.architecture, "arm64");
        try equal(value.schema, receipt_schema);
        try equal(value.version, version);
        try equal(value.archive.url, archive_url);
        try equal(value.archive.sha256, archive_digest);
        try validateBinding(.{ .sha256 = value.archive.sha256, .size = value.archive.size }, maximum_tool_bytes, false);
        const observed = [_]FileBinding{ try self.tool(0), try self.tool(1), try self.tool(2) };
        const expected_files = [_]FileBinding{ value.dpkg, value.dpkg_query, value.update_alternatives };
        for (observed, expected_files) |actual, pin| {
            try equal(actual.sha256, pin.sha256);
            if (actual.size != pin.size) return error.ToolBindingMismatch;
        }
        return .{
            .architecture = "arm64",
            .archive = .{ .sha256 = archive_digest, .size = value.archive.size, .url = archive_url },
            .dpkg = observed[0],
            .dpkg_query = observed[1],
            .schema = receipt_schema,
            .update_alternatives = observed[2],
            .version = version,
        };
    }

    fn observe(self: Context, path: []const u8, index: usize) !void {
        const observed_bytes = try self.read(path, maximum_observation_bytes);
        defer self.allocator.free(observed_bytes);
        var observed = try canonicalDocument(self.allocator, observed_bytes);
        defer observed.deinit();
        const reference_bytes = try self.read(references[index], maximum_observation_bytes);
        defer self.allocator.free(reference_bytes);
        var reference = try canonicalDocument(self.allocator, reference_bytes);
        defer reference.deinit();
        if (reference.value != .object or observed.value != .object) return error.InvalidObservation;
        const expected = reference.value.object.get("observed_behavior") orelse return error.InvalidObservation;
        if (expected != .object or expected.object.count() != observed.value.object.count()) return error.InvalidObservation;
        for (expected.object.keys()) |key| if (!observed.value.object.contains(key)) return error.InvalidObservation;
        if (observed.value.object.get("package_inputs")) |inputs| {
            if (inputs != .object) return error.InvalidObservation;
            const architecture = inputs.object.get("architecture") orelse return error.InvalidObservation;
            if (architecture != .string) return error.InvalidObservation;
            try equal(architecture.string, "arm64");
        }
        if (observed.value.object.get("direct_dpkg")) |direct| {
            const bytes = try canonicalBytes(self.allocator, direct);
            defer self.allocator.free(bytes);
            if (std.mem.indexOf(u8, bytes, "\"architecture\": \"arm64\"") == null)
                return error.InvalidObservation;
        }
    }
};

const Arguments = struct {
    architecture: ?[]const u8 = null,
    source_commit: ?[]const u8 = null,
    invocation_clock: ?[]const u8 = null,
    repository: ?[]const u8 = null,
    workflow: ?[]const u8 = null,
    run_id: ?[]const u8 = null,
    run_attempt: ?[]const u8 = null,
    job: ?[]const u8 = null,
    runner_label: ?[]const u8 = null,
    runner_arch: ?[]const u8 = null,
    machine: ?[]const u8 = null,
    dpkg: ?[]const u8 = null,
    update_alternatives: ?[]const u8 = null,
    receipt: ?[]const u8 = null,
    config_observation: ?[]const u8 = null,
    config_stdout: ?[]const u8 = null,
    config_stderr: ?[]const u8 = null,
    alternatives_observation: ?[]const u8 = null,
    alternatives_stdout: ?[]const u8 = null,
    alternatives_stderr: ?[]const u8 = null,
    output: ?[]const u8 = null,
    evidence: ?[]const u8 = null,
    artifact_root: ?[]const u8 = null,
};

fn command(allocator: std.mem.Allocator, operation: []const u8, observation: []const u8) ![]const []const u8 {
    var arguments: std.ArrayList([]const u8) = .empty;
    try arguments.appendSlice(allocator, &.{
        "sudo",                    "-n",                                        "/usr/bin/unshare",   "--mount",                           "--propagation", "private",
        "/usr/bin/env",            "-i",                                        "PATH=/usr/bin:/bin", "LANG=C",                            "LC_ALL=C",      "PYTHONDONTWRITEBYTECODE=1",
        "TMPDIR=$REPOSITORY/.tmp", "XDG_CACHE_HOME=$REPOSITORY/.cache",         "/bin/sh",            "tools/run-dpkg-oracle-isolated.sh", "$REPOSITORY",   operation,
        "arm64",                   "$REPOSITORY/" ++ prefix ++ "/usr/bin/dpkg",
    });
    try arguments.append(allocator, try std.fmt.allocPrint(allocator, "$REPOSITORY/.tmp/arm64-dpkg-oracles/{s}", .{std.fs.path.basename(observation)}));
    if (std.mem.eql(u8, operation, "alternatives"))
        try arguments.append(allocator, "$REPOSITORY/" ++ prefix ++ "/usr/bin/update-alternatives");
    return arguments.toOwnedSlice(allocator);
}

fn makeOracle(ctx: Context, args: Arguments, directory: []const u8, index: usize) !Oracle {
    const observation = if (index == 0) args.config_observation.? else args.alternatives_observation.?;
    try ctx.observe(observation, index);
    const reference = try ctx.read(references[index], maximum_observation_bytes);
    defer ctx.allocator.free(reference);
    return .{
        .command = try command(ctx.allocator, if (index == 0) "config" else "alternatives", observation),
        .exit = 0,
        .observation = try ctx.artifact(observation, directory),
        .published_reference = .{ .path = references[index], .sha256 = try ctx.digest(reference), .size = reference.len },
        .reference_schema = reference_schemas[index],
        .stderr = try ctx.output(if (index == 0) args.config_stderr.? else args.alternatives_stderr.?),
        .stdout = try ctx.output(if (index == 0) args.config_stdout.? else args.alternatives_stdout.?),
    };
}

fn create(ctx: Context, args: Arguments) !void {
    try equal(args.architecture.?, "arm64");
    const output = try ctx.absolutePath(args.output.?);
    defer ctx.allocator.free(output);
    const directory = std.fs.path.dirname(output) orelse return error.InvalidArtifactPath;
    const parent = try std.fmt.allocPrint(ctx.allocator, "{s}/.tmp", .{ctx.repository});
    defer ctx.allocator.free(parent);
    try equal(std.fs.path.dirname(directory) orelse return error.InvalidArtifactPath, parent);
    const receipt = try ctx.receipt(args.receipt.?);
    for ([_][]const u8{ args.dpkg.?, args.update_alternatives.? }, [_][]const u8{ prefix ++ "/usr/bin/dpkg", prefix ++ "/usr/bin/update-alternatives" }) |path, pin| {
        const actual = try ctx.absolutePath(path);
        defer ctx.allocator.free(actual);
        const expected = try ctx.absolutePath(pin);
        defer ctx.allocator.free(expected);
        try equal(actual, expected);
    }
    const receipt_bytes = try ctx.read(args.receipt.?, 4096);
    defer ctx.allocator.free(receipt_bytes);
    const document: Evidence = .{
        .architecture = "arm64",
        .invocation_clock = args.invocation_clock.?,
        .oracles = .{
            .direct_dpkg_config = try makeOracle(ctx, args, directory, 0),
            .dpkg_update_alternatives = try makeOracle(ctx, args, directory, 1),
        },
        .runner = .{ .label = args.runner_label.?, .machine = args.machine.?, .runner_arch = args.runner_arch.? },
        .schema = schema_id,
        .source = .{
            .commit = args.source_commit.?,
            .job = args.job.?,
            .repository = args.repository.?,
            .run_attempt = try invocationInteger(args.run_attempt.?),
            .run_id = try invocationInteger(args.run_id.?),
            .workflow = args.workflow.?,
            .workflow_path = ".github/workflows/ci.yml",
        },
        .tools = .{
            .archive = receipt.archive,
            .dpkg = .{ .path = prefix ++ "/usr/bin/dpkg", .sha256 = receipt.dpkg.sha256, .size = receipt.dpkg.size, .version = version },
            .receipt = .{ .path = prefix ++ "/reference-receipt-v1.json", .sha256 = try ctx.digest(receipt_bytes), .size = receipt_bytes.len },
            .update_alternatives = .{ .path = prefix ++ "/usr/bin/update-alternatives", .sha256 = receipt.update_alternatives.sha256, .size = receipt.update_alternatives.size, .version = version },
        },
        .version = 1,
    };
    try validateEvidence(document);
    const encoded = try canonicalBytes(ctx.allocator, document);
    defer ctx.allocator.free(encoded);
    if (encoded.len > maximum_evidence_bytes) return error.EvidenceTooLarge;
    try validatePrivacy(encoded);
    var root = try fs.openAbsoluteRoot(ctx.io, directory);
    defer root.close();
    const file = try root.root.createRegularFile(try fs.Path.init(std.fs.path.basename(output)), .{ .permissions = .fromMode(0o600) });
    defer file.close(ctx.io);
    try file.writeStreamingAll(ctx.io, encoded);
    try file.sync(ctx.io);
}

fn verify(ctx: Context, path: []const u8, directory: []const u8) !void {
    const bytes = try ctx.read(path, maximum_evidence_bytes);
    defer ctx.allocator.free(bytes);
    var canonical = try canonicalDocument(ctx.allocator, bytes);
    defer canonical.deinit();
    var parsed = try std.json.parseFromSlice(Evidence, ctx.allocator, bytes, .{ .allocate = .alloc_always, .parse_numbers = false });
    defer parsed.deinit();
    try validateEvidence(parsed.value);
    for ([_]Oracle{ parsed.value.oracles.direct_dpkg_config, parsed.value.oracles.dpkg_update_alternatives }) |record| {
        const observation_path = try std.fs.path.join(ctx.allocator, &.{ directory, record.observation.path });
        defer ctx.allocator.free(observation_path);
        const observation = try ctx.read(observation_path, maximum_observation_bytes);
        defer ctx.allocator.free(observation);
        const digest = try ctx.digest(observation);
        defer ctx.allocator.free(digest);
        try equal(digest, record.observation.sha256);
        if (observation.len != record.observation.size) return error.ObservationBindingMismatch;
        try validatePrivacy(observation);
    }
}

pub fn main(init: std.process.Init) !void {
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    const operation = iterator.next() orelse return error.MissingOperation;
    const creating = std.mem.eql(u8, operation, "create");
    if (!creating and !std.mem.eql(u8, operation, "verify")) return error.InvalidOperation;
    var args: Arguments = .{};
    while (iterator.next()) |flag| {
        var matched = false;
        inline for (std.meta.fields(Arguments)) |field| {
            const spelling = "--" ++ field.name;
            var name: [spelling.len]u8 = spelling.*;
            std.mem.replaceScalar(u8, &name, '_', '-');
            if (std.mem.eql(u8, flag, &name)) {
                if (@field(args, field.name) != null) return error.DuplicateArgument;
                @field(args, field.name) = iterator.next() orelse return error.MissingArgument;
                matched = true;
            }
        }
        if (!matched) return error.InvalidArgument;
    }
    inline for (std.meta.fields(Arguments)) |field| {
        const verify_argument = comptime std.mem.eql(u8, field.name, "evidence") or std.mem.eql(u8, field.name, "artifact_root");
        if ((@field(args, field.name) != null) != (creating != verify_argument)) return error.MissingOrUnexpectedArgument;
    }
    const ctx: Context = .{
        .io = init.io,
        .allocator = init.arena.allocator(),
        .repository = try std.Io.Dir.cwd().realPathFileAlloc(init.io, ".", init.arena.allocator()),
    };
    if (creating) try create(ctx, args) else try verify(ctx, args.evidence.?, args.artifact_root.?);
}

test "oracle canonical JSON preserves Python sorting, Unicode and newline contract" {
    const allocator = std.testing.allocator;
    const bytes = "{\n  \"a\": {\n    \"emoji\": \"\\ud83d\\ude00\"\n  },\n  \"z\": 1\n}\n";
    var parsed = try canonicalDocument(allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectError(error.NoncanonicalEvidence, canonicalDocument(allocator, "{\"z\": 1, \"a\": {}}\n"));
    try std.testing.expectError(error.DuplicateField, canonicalDocument(allocator, "{\"a\": 1, \"a\": 2}\n"));
    for ([_][]const u8{
        "{\n  \"number\": 1.0\n}\n",
        "{\n  \"number\": -0.0\n}\n",
        "{\n  \"number\": 0.0001\n}\n",
        "{\n  \"number\": 1e-05\n}\n",
        "{\n  \"number\": 1e+16\n}\n",
        "{\n  \"number\": 184467440737095516160\n}\n",
    }) |document| {
        var number = try canonicalDocument(allocator, document);
        number.deinit();
    }
    try std.testing.expectError(error.NoncanonicalEvidence, canonicalDocument(allocator, "{\n  \"number\": 1e0\n}\n"));
    try validateNatural(try invocationInteger("184467440737095516160"));
    try std.testing.expectError(error.InvalidEvidenceInteger, invocationInteger("0"));
}

test "oracle evidence refuses private outputs and malformed clocks before publication" {
    for ([_][]const u8{
        "/home/runner/work/private",
        "/Users/runner/private",
        "github_pat_abc",
        "ghp_12345678901234567890",
        "ghp_1234567890_1234567890",
        "Authorization: bearer private",
        "ACTIONS_ID_TOKEN",
        "RUNNER_TRACKING_ID",
    }) |text| try std.testing.expectError(error.PrivateEvidence, validatePrivacy(text));
    try validatePrivacy("ordinary independent oracle output\n");
    try validateClock("2026-09-20T16:29:21.965+00:00");
    try validateClock("2024-02-29T16:29:21Z");
    for ([_][]const u8{ "2026-09-20T16:29:21.965", "2026-02-29T16:29:21Z", "2026-09-20T25:29:21Z", "2026-09-20T16:29:21.+00:00" }) |text|
        try std.testing.expectError(error.InvalidInvocationClock, validateClock(text));
}

test "oracle rooted reads refuse aliases, hardlinks and oversized inputs without truncation" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const ctx: Context = .{ .io = io, .allocator = allocator, .repository = path };
    try temporary.dir.writeFile(io, .{ .sub_path = "original", .data = "original" });
    var root = try fs.openAbsoluteRoot(io, path);
    defer root.close();
    try root.root.createSymbolicLink(try fs.Path.init("alias"), "original");
    try root.root.createHardLink(try fs.Path.init("original"), try fs.Path.init("hardlink"));
    try std.testing.expectError(error.HardLinkedEvidence, ctx.read("original", 10));
    if (ctx.read("alias", 10)) |bytes| {
        allocator.free(bytes);
        return error.AcceptedSymlinkEvidence;
    } else |_| {}
    try root.root.removeFile(try fs.Path.init("hardlink"));
    try std.testing.expectError(error.FileTooLarge, ctx.read("original", 3));
    const bytes = try ctx.read("original", 10);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("original", bytes);
    const output = try root.root.createRegularFile(try fs.Path.init("exclusive"), .{ .permissions = .fromMode(0o600) });
    defer output.close(io);
    try output.writeStreamingAll(io, "unchanged");
    try std.testing.expectError(error.PathAlreadyExists, root.root.createRegularFile(try fs.Path.init("exclusive"), .{}));
}

test "native oracle verifier binds both raw observations and refuses changed typed v1 claims" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    const ctx: Context = .{ .io = io, .allocator = allocator, .repository = path };
    const observation = "{\n  \"fixture\": \"independent observation\"\n}\n";
    try temporary.dir.writeFile(io, .{ .sub_path = "observation.json", .data = observation });
    const empty_output: Output = .{ .text = "", .size = 0, .sha256 = try ctx.digest("") };
    const record: Oracle = .{
        .command = &.{ "sudo", "-n", "unshare", "--mount", "env", "-i", "reference", "fixture" },
        .exit = 0,
        .observation = .{ .path = "observation.json", .sha256 = try ctx.digest(observation), .size = observation.len },
        .published_reference = .{ .path = references[0], .sha256 = tool_digests[0], .size = 1 },
        .reference_schema = reference_schemas[0],
        .stderr = empty_output,
        .stdout = empty_output,
    };
    var document: Evidence = .{
        .architecture = "arm64",
        .invocation_clock = "2026-09-20T16:29:21.965+00:00",
        .oracles = .{ .direct_dpkg_config = record, .dpkg_update_alternatives = record },
        .runner = .{ .label = "ubuntu-24.04-arm", .machine = "aarch64", .runner_arch = "ARM64" },
        .schema = schema_id,
        .source = .{
            .commit = "a" ** 40,
            .job = "arm64-dpkg-oracles",
            .repository = "cataggar/debz",
            .run_attempt = .{ .integer = 1 },
            .run_id = .{ .integer = 123 },
            .workflow = "CI",
            .workflow_path = ".github/workflows/ci.yml",
        },
        .tools = .{
            .archive = .{ .sha256 = archive_digest, .size = 1, .url = archive_url },
            .dpkg = .{ .path = prefix ++ "/usr/bin/dpkg", .sha256 = tool_digests[0], .size = 1, .version = version },
            .receipt = .{ .path = prefix ++ "/reference-receipt-v1.json", .sha256 = tool_digests[0], .size = 1 },
            .update_alternatives = .{ .path = prefix ++ "/usr/bin/update-alternatives", .sha256 = tool_digests[2], .size = 1, .version = version },
        },
        .version = 1,
    };
    const encoded = try canonicalBytes(allocator, document);
    try temporary.dir.writeFile(io, .{ .sub_path = "evidence.json", .data = encoded });
    try verify(ctx, "evidence.json", path);
    document.oracles.dpkg_update_alternatives.observation.sha256 = "0" ** 64;
    try temporary.dir.writeFile(io, .{ .sub_path = "evidence.json", .data = try canonicalBytes(allocator, document) });
    try std.testing.expectError(error.EvidenceIdentityMismatch, verify(ctx, "evidence.json", path));
    document.oracles.dpkg_update_alternatives.observation.sha256 = record.observation.sha256;
    document.oracles.direct_dpkg_config.observation.size = maximum_observation_bytes + 1;
    try temporary.dir.writeFile(io, .{ .sub_path = "evidence.json", .data = try canonicalBytes(allocator, document) });
    try std.testing.expectError(error.InvalidEvidenceBinding, verify(ctx, "evidence.json", path));
    document.oracles.direct_dpkg_config.observation.size = record.observation.size;
    document.runner.label = "self-hosted";
    try temporary.dir.writeFile(io, .{ .sub_path = "evidence.json", .data = try canonicalBytes(allocator, document) });
    try std.testing.expectError(error.EvidenceIdentityMismatch, verify(ctx, "evidence.json", path));
}

test "native oracle constructor consumes published observation shapes and refuses changed architecture or shape" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    const ctx: Context = .{ .io = io, .allocator = allocator, .repository = path };
    try temporary.dir.createDirPath(io, "tools/fixtures/vendor-state");
    try temporary.dir.createDirPath(io, ".tmp/oracles");
    const directory = try ctx.absolutePath(".tmp/oracles");
    const source_references = [_][]const u8{
        @embedFile("fixtures/vendor-state/dpkg-config-reference-v1.json"),
        @embedFile("fixtures/vendor-state/dpkg-alternatives-reference-v1.json"),
    };
    const observation_paths = [_][]const u8{ ".tmp/oracles/config.json", ".tmp/oracles/alternatives.json" };
    const project = struct {
        fn arm(value: *std.json.Value) void {
            switch (value.*) {
                .object => |*object| for (object.values()) |*child| arm(child),
                .array => |*array| for (array.items) |*child| arm(child),
                .string => |text| if (std.mem.eql(u8, text, "amd64")) {
                    value.* = .{ .string = "arm64" };
                },
                else => {},
            }
        }
    };
    for (source_references, observation_paths, 0..) |source, observation_path, index| {
        try temporary.dir.writeFile(io, .{ .sub_path = references[index], .data = source });
        var reference = try canonicalDocument(allocator, source);
        defer reference.deinit();
        var observation = reference.value.object.get("observed_behavior").?;
        project.arm(&observation);
        try temporary.dir.writeFile(io, .{ .sub_path = observation_path, .data = try canonicalBytes(allocator, observation) });
    }
    try temporary.dir.writeFile(io, .{ .sub_path = "stdout", .data = "independent unit output\n" });
    try temporary.dir.writeFile(io, .{ .sub_path = "stderr", .data = "" });
    const args: Arguments = .{
        .config_observation = observation_paths[0],
        .alternatives_observation = observation_paths[1],
        .config_stdout = "stdout",
        .alternatives_stdout = "stdout",
        .config_stderr = "stderr",
        .alternatives_stderr = "stderr",
    };
    for (0..source_references.len) |index| {
        const record = try makeOracle(ctx, args, directory, index);
        try std.testing.expectEqualStrings("independent unit output\n", record.stdout.text);
        try std.testing.expectEqualStrings(std.fs.path.basename(observation_paths[index]), record.observation.path);
    }
    const config_bytes = try ctx.read(observation_paths[0], maximum_observation_bytes);
    var config = try canonicalDocument(allocator, config_bytes);
    defer config.deinit();
    const inputs = config.value.object.getPtr("package_inputs").?;
    inputs.object.getPtr("architecture").?.* = .{ .string = "amd64" };
    try temporary.dir.writeFile(io, .{ .sub_path = observation_paths[0], .data = try canonicalBytes(allocator, config.value) });
    try std.testing.expectError(error.EvidenceIdentityMismatch, makeOracle(ctx, args, directory, 0));
    _ = config.value.object.orderedRemove("package_inputs");
    try temporary.dir.writeFile(io, .{ .sub_path = observation_paths[0], .data = try canonicalBytes(allocator, config.value) });
    try std.testing.expectError(error.InvalidObservation, makeOracle(ctx, args, directory, 0));
}

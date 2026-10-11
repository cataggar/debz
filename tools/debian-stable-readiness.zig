const std = @import("std");
const builtin = @import("builtin");
const debz = @import("debz");
const fs = debz.root_fs;
const options = @import("debian_readiness_options");

const maximum_release_bytes = 256 * 1024;
const maximum_key_bytes = 32 * 1024;
const maximum_index_bytes = 20 * 1024 * 1024;
const maximum_packages_bytes = 128 * 1024 * 1024;
const Index = struct {
    index_path: []const u8,
    index_size: usize,
    index_sha256: []const u8,
    package_records: usize,

    fn identity(self: Index) IndexIdentity {
        return .{ .index_size = self.index_size, .index_sha256 = self.index_sha256, .package_records = self.package_records };
    }
};
const IndexIdentity = struct { index_size: usize, index_sha256: []const u8, package_records: usize };
const Signer = struct {
    url: []const u8,
    armor_sha256: []const u8,
    binary_sha256: []const u8,
    primary_fingerprint: []const u8,
};
const Pin = struct {
    schema: []const u8,
    snapshot_uri: []const u8,
    suite: []const u8,
    component: []const u8,
    release: struct {
        inrelease_sha256: []const u8,
        date: []const u8,
        valid_until: ?[]const u8,
        freshness_mode: []const u8,
        maximum_release_age_seconds: u64,
    },
    signer: Signer,
    architectures: struct { amd64: Index, arm64: Index },

    fn index(self: Pin, architecture: []const u8) !Index {
        if (std.mem.eql(u8, architecture, "amd64")) return self.architectures.amd64;
        if (std.mem.eql(u8, architecture, "arm64")) return self.architectures.arm64;
        return error.UnsupportedReadinessArchitecture;
    }
};

fn hash(comptime Algorithm: type, bytes: []const u8) [Algorithm.digest_length * 2]u8 {
    var digest: [Algorithm.digest_length]u8 = undefined;
    Algorithm.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn decodeKey(allocator: std.mem.Allocator, armor: []const u8, pin: Signer) ![]u8 {
    if (armor.len > maximum_key_bytes) return error.KeyInputLimit;
    if (!std.mem.eql(u8, &hash(std.crypto.hash.sha2.Sha256, armor), pin.armor_sha256))
        return error.SignerArmorDigestChanged;
    for (armor) |byte| if (byte > 127) return error.InvalidSignerArmor;
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, armor, "\r\n"), '\n');
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, lines.next() orelse "", "\r"), "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        return error.InvalidSignerArmor;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var body = false;
    var stopped = false;
    var ended = false;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (!body) {
            if (line.len == 0) body = true;
            continue;
        }
        if (std.mem.eql(u8, line, "-----END PGP PUBLIC KEY BLOCK-----")) {
            if (lines.next() != null) return error.InvalidSignerArmor;
            ended = true;
            break;
        }
        if (std.mem.startsWith(u8, line, "=")) stopped = true;
        if (!stopped) try encoded.appendSlice(allocator, line);
    }
    if (!body or !ended) return error.InvalidSignerArmor;
    const size = std.base64.standard.Decoder.calcSizeForSlice(encoded.items) catch return error.InvalidSignerArmor;
    const key = try allocator.alloc(u8, size);
    errdefer allocator.free(key);
    std.base64.standard.Decoder.decode(key, encoded.items) catch return error.InvalidSignerArmor;
    if (!std.mem.eql(u8, &hash(std.crypto.hash.sha2.Sha256, key), pin.binary_sha256))
        return error.SignerBinaryDigestChanged;
    if (key.len < 4 or (key[0] != 0x98 and key[0] != 0x99)) return error.InvalidPrimaryKey;
    const prefix: usize = if (key[0] == 0x98) 2 else 3;
    const length = if (prefix == 2) @as(usize, key[1]) else std.mem.readInt(u16, key[1..3], .big);
    if (length == 0 or length > key.len - prefix or key[prefix] != 4) return error.InvalidPrimaryKey;
    const digest = debz.openpgp_verifier.fingerprintV4(key[prefix..][0..length]);
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), pin.primary_fingerprint))
        return error.SignerFingerprintChanged;
    return key;
}

const Sections = struct {
    MD5Sum: ?struct { []const u8, usize } = null,
    SHA256: struct { []const u8, usize },
    SHA512: ?struct { []const u8, usize } = null,
};

fn releaseIndex(allocator: std.mem.Allocator, armored: []const u8, pin: Pin, architecture: []const u8, now: i64) !Sections {
    if (armored.len > maximum_release_bytes) return error.ReleaseInputLimit;
    if (!std.mem.eql(u8, &hash(std.crypto.hash.sha2.Sha256, armored), pin.release.inrelease_sha256))
        return error.InReleaseDigestChanged;
    const signature = std.mem.indexOf(u8, armored, "-----BEGIN PGP SIGNATURE-----") orelse return error.InvalidReleaseEnvelope;
    const start = std.mem.indexOf(u8, armored[0..signature], "\n\n") orelse return error.InvalidReleaseEnvelope;
    const clear = armored[start + 2 .. signature];
    var metadata = switch (try debz.release_metadata.parse(allocator, clear, .{ .max_input_bytes = maximum_release_bytes })) {
        .metadata => |value| value,
        .diagnostic => return error.InvalidReleaseMetadata,
    };
    defer metadata.deinit();
    for ([_]struct { field: ?debz.release_metadata.LocatedString, value: []const u8 }{
        .{ .field = metadata.origin, .value = "Debian" },
        .{ .field = metadata.suite, .value = "stable" },
        .{ .field = metadata.codename, .value = pin.suite },
    }) |expected| {
        if (expected.field == null or !std.mem.eql(u8, expected.field.?.value, expected.value))
            return error.SignedReleaseFieldChanged;
    }
    const date = metadata.date orelse return error.SignedReleaseDateChanged;
    if (!std.mem.eql(u8, date.span.slice(clear), pin.release.date)) return error.SignedReleaseDateChanged;
    if ((metadata.valid_until == null) != (pin.release.valid_until == null)) return error.SignedReleaseExpiryChanged;
    if (metadata.valid_until) |expiry| {
        if (!std.mem.eql(u8, expiry.span.slice(clear), pin.release.valid_until.?)) return error.SignedReleaseExpiryChanged;
    }
    var component = false;
    for (metadata.components) |entry| if (std.mem.eql(u8, entry.value, pin.component)) {
        component = true;
    };
    if (!component) return error.SignedReleaseComponentChanged;
    if (!std.mem.eql(u8, pin.release.freshness_mode, "allow_missing_valid_until_with_max_age_seconds") or
        pin.release.maximum_release_age_seconds > 31 * 86400)
        return error.ReadinessFreshnessPolicyChanged;
    const dated = debz.repository_refresh.timestampUnix(date.value);
    _ = debz.repository_refresh.validateFutureDate(dated, now, 300) catch return error.ReleaseDatedInFuture;
    const expiry = if (metadata.valid_until) |value| debz.repository_refresh.timestampUnix(value.value) else std.math.add(i64, dated, @intCast(pin.release.maximum_release_age_seconds)) catch return error.ReadinessFreshnessPolicyChanged;
    if (now > expiry) return error.ReleaseNotFresh;
    const index = try pin.index(architecture);
    var result: ?Sections = null;
    for (metadata.sha256_entries) |entry| {
        if (!std.mem.eql(u8, entry.path.value, index.index_path)) continue;
        const digest = std.fmt.bytesToHex(entry.digest.bytes, .lower);
        if (!std.mem.eql(u8, &digest, index.index_sha256) or entry.size != index.index_size)
            return error.SignedIndexIdentityChanged;
        result = .{ .SHA256 = .{ index.index_sha256, index.index_size } };
    }
    var sections = result orelse return error.SignedIndexIdentityChanged;
    for (metadata.sha512_entries) |entry| {
        if (!std.mem.eql(u8, entry.path.value, index.index_path)) continue;
        if (entry.size != index.index_size) return error.SignedIndexSha512Changed;
        sections.SHA512 = .{ try allocator.dupe(u8, &std.fmt.bytesToHex(entry.digest.bytes, .lower)), index.index_size };
    }
    // Preserve the reference function's non-authoritative MD5 observation.
    var md5_section = false;
    var lines = std.mem.splitScalar(u8, clear, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, line, "MD5Sum:")) {
            md5_section = true;
        } else if (line.len > 0 and line[0] != ' ' and line[0] != '\t') {
            md5_section = false;
        } else if (md5_section) {
            var fields = std.mem.tokenizeAny(u8, line, " \t\r");
            const digest = fields.next() orelse continue;
            const size = fields.next() orelse continue;
            const path = fields.next() orelse continue;
            if (!std.mem.eql(u8, path, index.index_path)) continue;
            if (fields.next() != null) return error.InvalidReleaseMetadata;
            sections.MD5Sum = .{ digest, try std.fmt.parseInt(usize, size, 10) };
        }
    }
    return sections;
}

fn indexCounts(allocator: std.mem.Allocator, compressed: []const u8, index: IndexIdentity, published_sha512: ?[]const u8) ![3]usize {
    if (compressed.len != index.index_size or
        !std.mem.eql(u8, &hash(std.crypto.hash.sha2.Sha256, compressed), index.index_sha256))
        return error.SignedIndexIdentityChanged;
    if (published_sha512) |digest| {
        if (!std.mem.eql(u8, &hash(std.crypto.hash.sha2.Sha512, compressed), digest)) return error.SignedIndexSha512Changed;
    }
    const packages = try debz.metadata_decompression.decompress(allocator, .xz, compressed, .{
        .maximum_compressed_bytes = maximum_index_bytes,
        .maximum_decompressed_bytes = maximum_packages_bytes,
        .maximum_decoder_memory = 256 * 1024 * 1024,
    });
    defer allocator.free(packages);
    var records = std.mem.splitSequence(u8, packages, "\n\n");
    var counts: [3]usize = .{ 0, 0, 0 };
    while (records.next()) |record| {
        if (!std.mem.startsWith(u8, record, "Package: ")) continue;
        counts[0] += 1;
        if (std.mem.indexOf(u8, record, "\nSHA256: ")) |offset| {
            counts[1] += 1;
            const value = record[offset + 9 ..];
            const digest = value[0 .. std.mem.indexOfScalar(u8, value, '\n') orelse value.len];
            if (digest.len != 2 * std.crypto.hash.sha2.Sha256.digest_length) return error.MalformedPublishedSha256;
            for (digest) |byte| if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f')))
                return error.MalformedPublishedSha256;
        }
        if (std.mem.indexOf(u8, record, "\nSHA512: ") != null) counts[2] += 1;
    }
    if (counts[0] != index.package_records or counts[1] != counts[0]) return error.PackageRecordsChanged;
    return counts;
}

const Binding = struct { status: []const u8, archive_binding: ?[]const u8 };

fn archiveBinding(published: bool, records: usize, sha512: usize) Binding {
    if (published and sha512 == records) return .{ .status = "eligible_signed_sha512", .archive_binding = "published_digests" };
    if (sha512 == 0) return .{ .status = "eligible_signed_sha256_derived_sha512", .archive_binding = "signed_sha256_derived_sha512" };
    return .{ .status = "refused_partial_published_sha512", .archive_binding = null };
}

fn fetch(io: std.Io, allocator: std.mem.Allocator, url: []const u8, limit: usize) ![]u8 {
    var production: debz.repository_acquisition.Production = .{ .io = io };
    const result = try debz.repository_acquisition.acquire(allocator, .{
        .uri = try std.Uri.parse(url),
        .deadlines = .{ .connect_ms = 90_000, .read_ms = 90_000, .overall_ms = 90_000 },
        .redirect_limit = 10,
        .max_response_bytes = limit,
        .require_https = true,
    }, production.dependencies());
    var provenance = result.provenance;
    provenance.deinit(allocator);
    return result.bytes;
}

fn read(io: std.Io, allocator: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    var root = try fs.openAbsoluteRoot(io, std.fs.path.dirname(path) orelse return error.InvalidReadinessPath);
    defer root.close();
    var pin = try root.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(path)));
    defer pin.close();
    const observed = try pin.observeStableAlloc(allocator, limit);
    return observed.bytes;
}

fn write(io: std.Io, root: fs.Root, path: []const u8, bytes: []const u8, mode: u32) !void {
    var parent = try root.openParent(try fs.Path.init(path));
    defer parent.close(io);
    const file = try parent.dir.createFile(io, parent.leaf, .{
        .exclusive = true,
        .permissions = .fromMode(mode),
        .resolve_beneath = true,
    });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn json(allocator: std.mem.Allocator, value: anytype, pretty: bool) ![]u8 {
    return std.mem.concat(allocator, u8, &.{
        try std.json.Stringify.valueAlloc(allocator, value, .{ .whitespace = if (pretty) .indent_2 else .minified, .escape_unicode = true }),
        "\n",
    });
}

fn sourceUrl(allocator: std.mem.Allocator, pin: Pin, architecture: []const u8, index: bool) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/dists/{s}/{s}", .{
        pin.snapshot_uri, pin.suite, if (index) (try pin.index(architecture)).index_path else "InRelease",
    });
}

fn retainRefresh(io: std.Io, allocator: std.mem.Allocator, root: fs.Root, result: std.process.RunResult) !void {
    try write(io, root, "evidence/refresh.json", result.stdout, 0o644);
    try write(io, root, "evidence/refresh.stderr", result.stderr, 0o644);
    if (result.term != .exited or result.term.exited != 0) return error.AuthenticatedRefreshRefused;
    const refresh = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer refresh.deinit();
    if (refresh.value != .object or (refresh.value.object.get("exit_status") orelse return error.InvalidRefreshReport) != .integer or
        refresh.value.object.get("exit_status").?.integer != 0)
        return error.AuthenticatedRefreshRefused;
}

fn requireEmptyRoot(io: std.Io, root: fs.Root) !void {
    var empty_root = try root.openDirectory(try fs.Path.init("root"));
    defer empty_root.close(io);
    var iterator = empty_root.iterate();
    if (try iterator.next(io) != null) return error.ReadOnlyRefreshMutatedRoot;
}

fn run(io: std.Io, allocator: std.mem.Allocator, pin: Pin, requested_binary: []const u8, architecture: []const u8, requested_workspace: []const u8) !Binding {
    const native = switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => return error.UnsupportedReadinessArchitecture,
    };
    if (!std.mem.eql(u8, architecture, native)) return error.NativeReadinessRunnerRequired;
    const binary = try std.Io.Dir.cwd().realPathFileAlloc(io, requested_binary, allocator);
    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    const workspace = try std.fs.path.resolve(allocator, &.{ cwd, requested_workspace });
    const checkout = try std.Io.Dir.cwd().realPathFileAlloc(io, options.repository, allocator);
    const scratch = try std.fs.path.join(allocator, &.{ checkout, ".tmp" });
    if (!std.mem.eql(u8, std.fs.path.dirname(workspace) orelse "", scratch))
        return error.NewDirectChildWorkspaceRequired;
    _ = try fs.Path.fromAbsolute(workspace);
    var checkout_root = try fs.openAbsoluteRoot(io, checkout);
    defer checkout_root.close();
    if (try checkout_root.root.entryIfExists(try fs.Path.init(".tmp"))) |entry| {
        if (!entry.isDirectory()) return error.InvalidScratchDirectory;
    } else try checkout_root.root.createDirectory(try fs.Path.init(".tmp"), .fromMode(0o700));
    var scratch_root = try fs.openAbsoluteRoot(io, scratch);
    defer scratch_root.close();
    try scratch_root.root.createDirectory(try fs.Path.init(std.fs.path.basename(workspace)), .fromMode(0o700));
    var workspace_root = try fs.openAbsoluteRoot(io, workspace);
    defer workspace_root.close();
    for ([_][]const u8{ "root", "cache", "state", "evidence" }) |name|
        try workspace_root.root.createDirectory(try fs.Path.init(name), .fromMode(0o700));
    var executable_root = try fs.openAbsoluteRoot(io, std.fs.path.dirname(binary).?);
    defer executable_root.close();
    var executable = try executable_root.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(binary)));
    defer executable.close();
    const program = try executable.observeStableAlloc(allocator, 256 * 1024 * 1024);
    const key = try decodeKey(allocator, try fetch(io, allocator, pin.signer.url, maximum_key_bytes), pin.signer);
    const key_name = "debian-261-trixie-release-13.gpg";
    const keyring = try std.fs.path.join(allocator, &.{ scratch, key_name });
    if (try scratch_root.root.entryIfExists(try fs.Path.init(key_name)) == null)
        write(io, scratch_root.root, key_name, key, 0o600) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    if (!std.mem.eql(u8, try read(io, allocator, keyring, maximum_key_bytes), key)) return error.ReviewedKeyringPathChanged;
    const source = try std.fmt.allocPrint(allocator, "Types: deb\nURIs: {s}\nSuites: {s}\nComponents: {s}\nArchitectures: {s}\nSigned-By: {s}\n", .{ pin.snapshot_uri, pin.suite, pin.component, architecture, keyring });
    try write(io, workspace_root.root, "debian.sources", source, 0o644);
    const config = try json(allocator, .{
        .source_path = try std.fs.path.join(allocator, &.{ workspace, "debian.sources" }),
        .priority = @as(u32, 500),
        .default_release = pin.suite,
        .immutable = true,
        .freshness = .{ .mode = pin.release.freshness_mode, .maximum_release_age_seconds = pin.release.maximum_release_age_seconds },
    }, false);
    try write(io, workspace_root.root, "debian.json", config, 0o644);
    const result = try std.process.run(allocator, io, .{
        .argv = &.{
            binary,           "refresh",                                                 "--install-root", try std.fs.path.join(allocator, &.{ workspace, "root" }),
            "--cache-path",   try std.fs.path.join(allocator, &.{ workspace, "cache" }), "--state-path",   try std.fs.path.join(allocator, &.{ workspace, "state" }),
            "--architecture", architecture,                                              "--config",       try std.fs.path.join(allocator, &.{ workspace, "debian.json" }),
            "--keyring",      keyring,                                                   "--assume-yes",   "--deadline-ms",
            "300000",         "--json",
        },
        .timeout = .{ .duration = .{ .raw = .fromSeconds(360), .clock = .awake } },
        .stdout_limit = .limited(16 * 1024 * 1024),
        .stderr_limit = .limited(16 * 1024 * 1024),
    });
    try retainRefresh(io, allocator, workspace_root.root, result);
    const armored = try fetch(io, allocator, try sourceUrl(allocator, pin, architecture, false), maximum_release_bytes);
    const now: i64 = @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    const sections = try releaseIndex(allocator, armored, pin, architecture, now);
    const compressed = try fetch(io, allocator, try sourceUrl(allocator, pin, architecture, true), maximum_index_bytes);
    const counts = try indexCounts(allocator, compressed, (try pin.index(architecture)).identity(), if (sections.SHA512) |entry| entry[0] else null);
    try requireEmptyRoot(io, workspace_root.root);
    _ = try executable.metadata();
    const binding = archiveBinding(sections.SHA512 != null, counts[0], counts[2]);
    const key_digest = hash(std.crypto.hash.sha2.Sha256, key);
    const source_digest = hash(std.crypto.hash.sha2.Sha256, source);
    const config_digest = hash(std.crypto.hash.sha2.Sha256, config);
    const program_digest = hash(std.crypto.hash.sha2.Sha256, program.bytes);
    const release_digest = hash(std.crypto.hash.sha2.Sha256, armored);
    const index_digest = hash(std.crypto.hash.sha2.Sha256, compressed);
    const report = .{
        .schema = pin.schema,
        .architecture = architecture,
        .snapshot_uri = pin.snapshot_uri,
        .suite = pin.suite,
        .signer_primary_fingerprint = pin.signer.primary_fingerprint,
        .signed_by_path = keyring,
        .keyring_sha256 = key_digest[0..],
        .source_sha256 = source_digest[0..],
        .config_sha256 = config_digest[0..],
        .program_sha256 = program_digest[0..],
        .inrelease_sha256 = release_digest[0..],
        .index_sha256 = index_digest[0..],
        .index_published_sha512 = sections.SHA512 != null,
        .package_records = counts[0],
        .sha256_package_records = counts[1],
        .sha512_package_records = counts[2],
        .root_mutated = false,
        .exact_lock_published = false,
        .status = binding.status,
        .archive_binding = binding.archive_binding,
    };
    try write(io, workspace_root.root, "evidence/readiness.json", try json(allocator, report, true), 0o644);
    try std.Io.File.stdout().writeStreamingAll(io, try json(allocator, report, false));
    return binding;
}

fn execute(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    const pin = (try std.json.parseFromSlice(Pin, allocator, @embedFile("fixtures/debian-stable-readiness-v1.json"), .{})).value;
    var args = init.minimal.args.iterate();
    _ = args.next();
    var mode: ?[]const u8 = null;
    var architecture: ?[]const u8 = null;
    var binary: ?[]const u8 = null;
    var workspace: ?[]const u8 = null;
    var now: ?i64 = null;
    var published: ?[]const u8 = null;
    var index_identity: ?[]const u8 = null;
    while (args.next()) |argument| {
        if (std.mem.eql(u8, argument, "--help")) {
            try std.Io.File.stdout().writeStreamingAll(init.io,
                \\Usage: debz-debian-stable-readiness --debz PATH --architecture amd64|arm64 --workspace PATH
                \\Read-only authenticated preflight using the real clock and reviewed Debian pin.
                \\Workspace must be a new direct child of this checkout's .tmp directory.
                \\Verification handoffs read bounded bytes from stdin:
                \\  --check-key
                \\  --check-release --architecture amd64|arm64 [--now UNIX_SECONDS]
                \\  --check-index --architecture amd64|arm64 [--published-sha512 HEX]
                \\  --check-index --index-identity JSON [--published-sha512 HEX]
                \\HTTPS acquisition handoffs: --fetch-key, --fetch-release, --fetch-index.
                \\Release and index acquisition require --architecture amd64|arm64.
                \\
            );
            return 0;
        }
        if (std.mem.eql(u8, argument, "--fetch-key") or std.mem.eql(u8, argument, "--fetch-release") or
            std.mem.eql(u8, argument, "--fetch-index") or std.mem.eql(u8, argument, "--check-key") or
            std.mem.eql(u8, argument, "--check-release") or std.mem.eql(u8, argument, "--check-index"))
        {
            if (mode != null) return error.InvalidReadinessArguments;
            mode = argument;
        } else if (std.mem.eql(u8, argument, "--now")) {
            if (now != null) return error.InvalidReadinessArguments;
            now = std.fmt.parseInt(i64, args.next() orelse return error.InvalidReadinessArguments, 10) catch return error.InvalidReadinessArguments;
        } else {
            const value: *?[]const u8 = if (std.mem.eql(u8, argument, "--architecture")) &architecture else if (std.mem.eql(u8, argument, "--debz")) &binary else if (std.mem.eql(u8, argument, "--workspace")) &workspace else if (std.mem.eql(u8, argument, "--published-sha512")) &published else if (std.mem.eql(u8, argument, "--index-identity")) &index_identity else return error.InvalidReadinessArguments;
            if (value.* != null) return error.InvalidReadinessArguments;
            value.* = args.next() orelse return error.InvalidReadinessArguments;
        }
    }
    if (mode) |selected| {
        if (binary != null or workspace != null) return error.InvalidReadinessArguments;
        const key_mode = std.mem.endsWith(u8, selected, "-key");
        if (key_mode and architecture != null) return error.InvalidReadinessArguments;
        const arch = if (key_mode) "amd64" else architecture orelse if (index_identity != null and std.mem.eql(u8, selected, "--check-index")) "" else return error.InvalidReadinessArguments;
        if (arch.len != 0) _ = try pin.index(arch);
        if (now != null and !std.mem.eql(u8, selected, "--check-release")) return error.InvalidReadinessArguments;
        if (published != null and !std.mem.eql(u8, selected, "--check-index")) return error.InvalidReadinessArguments;
        if (index_identity != null and !std.mem.eql(u8, selected, "--check-index")) return error.InvalidReadinessArguments;
        if (std.mem.startsWith(u8, selected, "--fetch-")) {
            const url = if (key_mode) pin.signer.url else try sourceUrl(allocator, pin, arch, std.mem.eql(u8, selected, "--fetch-index"));
            const limit: usize = if (key_mode) maximum_key_bytes else if (std.mem.eql(u8, selected, "--fetch-index")) maximum_index_bytes else maximum_release_bytes;
            try std.Io.File.stdout().writeStreamingAll(init.io, try fetch(init.io, allocator, url, limit));
            return 0;
        }
        var reader = std.Io.File.stdin().reader(init.io, &.{});
        const limit: usize = if (key_mode) maximum_key_bytes else if (std.mem.eql(u8, selected, "--check-index")) maximum_index_bytes else maximum_release_bytes;
        const bytes = try reader.interface.allocRemaining(allocator, .limited(limit + 1));
        if (bytes.len > limit) return error.ReadinessInputLimit;
        const output = if (key_mode) try decodeKey(allocator, bytes, pin.signer) else if (std.mem.eql(u8, selected, "--check-release")) blk: {
            const sections = try releaseIndex(allocator, bytes, pin, arch, now orelse @intCast(@divFloor(std.Io.Clock.real.now(init.io).nanoseconds, std.time.ns_per_s)));
            break :blk try std.mem.concat(allocator, u8, &.{
                try std.json.Stringify.valueAlloc(allocator, sections, .{ .emit_null_optional_fields = false }), "\n",
            });
        } else blk: {
            if (index_identity) |document| if (document.len > 4096) return error.ReadinessInputLimit;
            const index = if (index_identity) |document|
                (try std.json.parseFromSlice(IndexIdentity, allocator, document, .{ .max_value_len = 4096 })).value
            else
                (try pin.index(arch)).identity();
            break :blk try json(allocator, try indexCounts(allocator, bytes, index, published), false);
        };
        try std.Io.File.stdout().writeStreamingAll(init.io, output);
        return 0;
    }
    if (now != null or published != null or index_identity != null) return error.InvalidReadinessArguments;
    const binding = try run(init.io, allocator, pin, binary orelse return error.InvalidReadinessArguments, architecture orelse return error.InvalidReadinessArguments, workspace orelse return error.InvalidReadinessArguments);
    if (binding.archive_binding == null) {
        std.log.err("refusing a repository whose signed index and package records publish SHA512 only partially", .{});
        return 3;
    }
    return 0;
}

pub fn main(init: std.process.Init) void {
    const code = execute(init) catch |err| {
        std.log.err("debian-stable-readiness: {s}", .{@errorName(err)});
        std.process.exit(2);
    };
    if (code != 0) std.process.exit(code);
}

fn fixturePin(allocator: std.mem.Allocator) !Pin {
    return (try std.json.parseFromSlice(Pin, allocator, @embedFile("fixtures/debian-stable-readiness-v1.json"), .{})).value;
}

fn fixtureRelease(allocator: std.mem.Allocator, pin: Pin, architecture: []const u8, origin: []const u8, suite: []const u8, codename: []const u8) ![]u8 {
    const index = try pin.index(architecture);
    return std.fmt.allocPrint(allocator, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" ++
        "Origin: {s}\nSuite: {s}\nCodename: {s}\nDate: {s}\nComponents: main\n" ++
        "SHA256:\n {s} {d} {s}\n-----BEGIN PGP SIGNATURE-----\n", .{ origin, suite, codename, pin.release.date, index.index_sha256, index.index_size, index.index_path });
}

test "official key decoding refuses changed armor, binary identity and primary fingerprint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const key = "\x98\x07\x04\x00\x00\x00\x00\x00\x01";
    const armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmAcEAAAAAAAB\n-----END PGP PUBLIC KEY BLOCK-----\n";
    const armor_digest = hash(std.crypto.hash.sha2.Sha256, armor);
    const key_digest = hash(std.crypto.hash.sha2.Sha256, key);
    const pin: Signer = .{
        .url = "https://example.invalid/key",
        .armor_sha256 = &armor_digest,
        .binary_sha256 = &key_digest,
        .primary_fingerprint = "2fd872a25a64c62a2bd3f556dbaf95e72f016f0a",
    };
    try std.testing.expectEqualStrings(key, try decodeKey(allocator, armor, pin));
    try std.testing.expectError(error.SignerArmorDigestChanged, decodeKey(allocator, armor ++ "tampered", pin));
    var changed = pin;
    changed.binary_sha256 = "0" ** 64;
    try std.testing.expectError(error.SignerBinaryDigestChanged, decodeKey(allocator, armor, changed));
    changed = pin;
    changed.primary_fingerprint = "0" ** 40;
    try std.testing.expectError(error.SignerFingerprintChanged, decodeKey(allocator, armor, changed));
}

test "both Release indexes require exact pins and bounded real freshness" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_][]const u8{ "amd64", "arm64" }) |architecture| {
        var pin = try fixturePin(allocator);
        const armor = try fixtureRelease(allocator, pin, architecture, "Debian", "stable", "trixie");
        pin.release.inrelease_sha256 = try allocator.dupe(u8, &hash(std.crypto.hash.sha2.Sha256, armor));
        const now: i64 = 1790553600;
        const sections = try releaseIndex(allocator, armor, pin, architecture, now);
        try std.testing.expectEqualStrings((try pin.index(architecture)).index_sha256, sections.SHA256[0]);
        try std.testing.expect(sections.SHA512 == null);
        try std.testing.expectError(error.ReleaseNotFresh, releaseIndex(allocator, armor, pin, architecture, 1792022400));
        try std.testing.expectError(error.ReleaseDatedInFuture, releaseIndex(allocator, armor, pin, architecture, 0));
        try std.testing.expectError(error.InReleaseDigestChanged, releaseIndex(allocator, try std.mem.concat(allocator, u8, &.{ armor, "changed" }), pin, architecture, now));
        if (std.mem.eql(u8, architecture, "amd64")) pin.architectures.amd64.index_sha256 = "0" ** 64 else pin.architectures.arm64.index_sha256 = "0" ** 64;
        try std.testing.expectError(error.SignedIndexIdentityChanged, releaseIndex(allocator, armor, pin, architecture, now));
    }
}

test "reviewed digest cannot authorize substituted Ubuntu Origin, suite or codename" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_][3][]const u8{
        .{ "Ubuntu", "stable", "trixie" }, .{ "Ubuntu", "noble", "noble" },
        .{ "Debian", "noble", "trixie" },  .{ "Debian", "stable", "noble" },
    }) |fields| {
        var pin = try fixturePin(allocator);
        const armor = try fixtureRelease(allocator, pin, "amd64", fields[0], fields[1], fields[2]);
        pin.release.inrelease_sha256 = try allocator.dupe(u8, &hash(std.crypto.hash.sha2.Sha256, armor));
        try std.testing.expectError(error.SignedReleaseFieldChanged, releaseIndex(allocator, armor, pin, "amd64", 1790553600));
    }
}

const original_xz_samples = [_][]const u8{
    "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\xe0\x00\xf2\x00\x50\x5d\x00\x28\x18\x48\x66\xdb\xda\x30\x85\xfe\x16\xe2\xa3\x2b\xad\xc3\x8b\x8c\xbc\xfb\x91\xb4\x3e\x4a\x0f\x46\x78\xc8\x9d\x2b\x4a\xa1\x35\xd8\xbc\x36\xd4\x41\xfd\xac\x93\xe2\x23\x32\x3b\x99\x2c\xdf\xf0\x6c\x69\xf2\x1b\x71\xc8\xa4\x43\xa9\x71\xd0\x09\xc4\x3f\xc0\x0c\xaf\x0f\x27\x2c\xbb\x75\xa4\xb0\x97\xb3\x5a\xc4\x7d\x06\x20\x00\x00\x3c\x6e\xc9\x5b\xbe\x37\x0d\x53\x00\x01\x6c\xf3\x01\x00\x00\x00\x14\x56\x4b\x0b\xb1\xc4\x67\xfb\x02\x00\x00\x00\x00\x04\x59\x5a",
    "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\xe0\x00\x59\x00\x23\x5d\x00\x28\x18\x48\x66\xdb\xda\x30\x85\xfe\x16\xe2\xa3\x2b\xad\xc3\x8b\x8c\xbc\xfa\xd8\xb8\x2f\xd2\x95\xbd\x3a\x87\x4f\x20\x31\x03\xb6\x3c\x80\x00\x00\x00\xb8\xea\x1c\x72\x4f\x6e\xca\x05\x00\x01\x3f\x5a\xfd\x27\xe6\xf3\x1f\xb6\xf3\x7d\x01\x00\x00\x00\x00\x04\x59\x5a",
    "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\xe0\x00\x5b\x00\x23\x5d\x00\x28\x18\x48\x66\xdb\xda\x30\x85\xfe\x16\xe2\xa3\x2b\xad\xc3\x8b\x8c\xbc\xfa\xd8\xb8\x2f\xd2\x95\xbd\x3a\x87\x4f\x20\x84\x85\xb6\x3c\x80\x00\x00\x00\xc0\x09\x97\x0c\x2c\x36\xb8\xb4\x00\x01\x3f\x5c\xc8\x82\x85\x1a\x1f\xb6\xf3\x7d\x01\x00\x00\x00\x00\x04\x59\x5a",
    "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\xe0\x00\x5a\x00\x23\x5d\x00\x28\x18\x48\x66\xdb\xda\x30\x85\xfe\x16\xe2\xa3\x2b\xad\xc3\x8b\x8c\xbc\xfa\xd8\xb8\x2f\xd2\x95\xbd\x3a\x87\xff\x0d\x43\x4e\xcd\xe2\x00\x00\x00\x00\x10\xd1\x8d\x19\xfa\x46\x39\xdc\x00\x01\x3f\x5b\x6b\x17\xe1\x84\x1f\xb6\xf3\x7d\x01\x00\x00\x00\x00\x04\x59\x5a",
    "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\xe0\x00\x5a\x00\x23\x5d\x00\x28\x18\x48\x66\xdb\xda\x30\x85\xfe\x16\xe2\xa3\x2b\xad\xc3\x8b\x8c\xbc\xfa\xd8\xb8\x2f\xd2\x95\xbd\x3a\x89\x61\x00\x43\x57\x11\x1f\x80\x00\x00\x00\xe0\x42\x14\x53\x7b\x86\xb2\x30\x00\x01\x3f\x5b\x6b\x17\xe1\x84\x1f\xb6\xf3\x7d\x01\x00\x00\x00\x00\x04\x59\x5a",
};

fn fixtureIndexIdentity(allocator: std.mem.Allocator, compressed: []const u8, count: usize) !IndexIdentity {
    return .{
        .index_size = compressed.len,
        .index_sha256 = try allocator.dupe(u8, &hash(std.crypto.hash.sha2.Sha256, compressed)),
        .package_records = count,
    };
}

test "index counts bind complete compressed bytes, signed SHA512 and every lowercase SHA256" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const compressed = original_xz_samples[0];
    const index = try fixtureIndexIdentity(allocator, compressed, 2);
    try std.testing.expectEqual([3]usize{ 2, 2, 0 }, try indexCounts(allocator, compressed, index, null));
    try std.testing.expectEqual([3]usize{ 2, 2, 0 }, try indexCounts(allocator, compressed, index, &hash(std.crypto.hash.sha2.Sha512, compressed)));
    try std.testing.expectError(error.SignedIndexSha512Changed, indexCounts(allocator, compressed, index, "0" ** 128));
    try std.testing.expectError(error.SignedIndexIdentityChanged, indexCounts(allocator, try std.mem.concat(allocator, u8, &.{ compressed, "changed" }), index, null));
    var changed = index;
    changed.package_records = 3;
    try std.testing.expectError(error.PackageRecordsChanged, indexCounts(allocator, compressed, changed, null));
    for (original_xz_samples[1..]) |malformed| {
        try std.testing.expectError(error.MalformedPublishedSha256, indexCounts(allocator, malformed, try fixtureIndexIdentity(allocator, malformed, 1), null));
    }
    const trailing = try std.mem.concat(allocator, u8, &.{ compressed, "x" });
    try std.testing.expectError(error.TrailingData, indexCounts(allocator, trailing, try fixtureIndexIdentity(allocator, trailing, 2), null));
    const truncated = compressed[0 .. compressed.len - 5];
    try std.testing.expectError(error.Truncated, indexCounts(allocator, truncated, try fixtureIndexIdentity(allocator, truncated, 2), null));
}

test "partial published SHA512 remains refused instead of receiving derived authority" {
    try std.testing.expectEqualStrings("published_digests", archiveBinding(true, 2, 2).archive_binding.?);
    for ([_]bool{ false, true }) |published| {
        try std.testing.expectEqualStrings("signed_sha256_derived_sha512", archiveBinding(published, 2, 0).archive_binding.?);
        try std.testing.expect(archiveBinding(published, 2, 1).archive_binding == null);
    }
    try std.testing.expect(archiveBinding(false, 2, 2).archive_binding == null);
}

test "original pre-decision and derived-binding evidence remains read-only with no lock or CAS" {
    const Evidence = struct {
        inrelease_sha256: []const u8,
        index_sha256: []const u8,
        signed_by_sha256: []const u8,
        package_records: usize,
        sha256_package_records: usize,
        sha512_package_records: usize,
        index_published_sha512: bool,
        exact_lock_published: bool,
        install_root_empty: bool,
        cas_archive_count: usize,
        status: ?[]const u8 = null,
        archive_binding: ?[]const u8 = null,
        runs: []struct { refresh_exit_status: u8, preflight_exit_status: u8, refresh_repository_identity: []const u8 },
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const pin = try fixturePin(allocator);
    for ([_][]const u8{
        @embedFile("fixtures/debian-stable-readiness-arm64-evidence-v1.json"),
        @embedFile("fixtures/debian-stable-readiness-arm64-evidence-v2.json"),
    }, 0..) |document, version| {
        const evidence = (try std.json.parseFromSlice(Evidence, allocator, document, .{ .ignore_unknown_fields = true })).value;
        try std.testing.expectEqualStrings(pin.release.inrelease_sha256, evidence.inrelease_sha256);
        try std.testing.expectEqualStrings(pin.architectures.arm64.index_sha256, evidence.index_sha256);
        try std.testing.expectEqualStrings(pin.signer.binary_sha256, evidence.signed_by_sha256);
        try std.testing.expectEqual(pin.architectures.arm64.package_records, evidence.package_records);
        try std.testing.expectEqual(evidence.package_records, evidence.sha256_package_records);
        try std.testing.expectEqual(@as(usize, 0), evidence.sha512_package_records);
        try std.testing.expect(!evidence.index_published_sha512 and !evidence.exact_lock_published and evidence.install_root_empty);
        try std.testing.expectEqual(@as(usize, 0), evidence.cas_archive_count);
        try std.testing.expectEqual(@as(usize, 2), evidence.runs.len);
        for (evidence.runs) |attempt| {
            try std.testing.expectEqual(@as(u8, 0), attempt.refresh_exit_status);
            try std.testing.expectEqual(@as(u8, if (version == 0) 3 else 0), attempt.preflight_exit_status);
            try std.testing.expectEqualStrings(evidence.runs[0].refresh_repository_identity, attempt.refresh_repository_identity);
        }
        if (version == 1) {
            const binding = archiveBinding(evidence.index_published_sha512, evidence.package_records, evidence.sha512_package_records);
            try std.testing.expectEqualStrings(binding.status, evidence.status.?);
            try std.testing.expectEqualStrings(binding.archive_binding.?, evidence.archive_binding.?);
        }
    }
}

test "failed refresh retains original diagnostics and root mutation cannot produce readiness" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { exit: u8, stdout: []const u8 }{
        .{ .exit = 9, .stdout = "{\"exit_status\":0}\n" },
        .{ .exit = 0, .stdout = "{\"exit_status\":2}\n" },
    }) |attempt| {
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const directory = try temporary.dir.realPathFileAlloc(io, ".", allocator);
        var root = try fs.openAbsoluteRoot(io, directory);
        defer root.close();
        try root.root.createDirectory(try fs.Path.init("evidence"), .fromMode(0o700));
        try root.root.createDirectory(try fs.Path.init("root"), .fromMode(0o700));
        try std.testing.expectError(error.AuthenticatedRefreshRefused, retainRefresh(io, allocator, root.root, .{
            .term = .{ .exited = attempt.exit },
            .stdout = try allocator.dupe(u8, attempt.stdout),
            .stderr = try allocator.dupe(u8, "original refresh diagnostics\n"),
        }));
        try std.testing.expectEqualStrings(attempt.stdout, try read(io, allocator, try std.fs.path.join(allocator, &.{ directory, "evidence/refresh.json" }), 1024));
        try std.testing.expectEqualStrings("original refresh diagnostics\n", try read(io, allocator, try std.fs.path.join(allocator, &.{ directory, "evidence/refresh.stderr" }), 1024));
        try std.testing.expect(try root.root.entryIfExists(try fs.Path.init("evidence/readiness.json")) == null);
        try requireEmptyRoot(io, root.root);
        try write(io, root.root, "root/unexpected", "mutation", 0o644);
        try std.testing.expectError(error.ReadOnlyRefreshMutatedRoot, requireEmptyRoot(io, root.root));
    }
}

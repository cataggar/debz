const std = @import("std");
const builtin = @import("builtin");

const archive_application = @import("archive_application.zig");
const content_digest = @import("content_digest.zig");
const exact_lock_v3 = @import("exact_lock_v3.zig");
const maintainer_script = @import("maintainer_script.zig");
const metadata_cache = @import("metadata_cache.zig");
const native_authorization = @import("native_authorization.zig");
const native_execution_request = @import("native_execution_request.zig");
const native_helper = @import("native_helper.zig");
const native_program = @import("native_program.zig");
const native_provenance = @import("native_provenance.zig");
const native_recovery = @import("native_recovery.zig");
const native_transaction_result = @import("native_transaction_result.zig");
const native_unpack = @import("native_unpack.zig");
const package_acquisition = @import("package_acquisition.zig");
const package_database = @import("package_database.zig");
const repository_acquisition = @import("repository_acquisition.zig");
const repository_plan = @import("repository_plan.zig");
const repository_refresh = @import("repository_refresh.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const root_operation_completion = @import("root_operation_completion.zig");
const solver = @import("solver.zig");
const source = @import("source.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");

const testing = std.testing;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Ed25519 = std.crypto.sign.Ed25519;

const repository_id: source.RepositoryId = .{ .bytes = @splat('a') };
const base_uri_text = "https://sha512.invalid/debian";
const package_path = "pool/main/d/demo/demo_1.0_amd64.deb";
const created: u32 = 1_790_100_000;
const verification_time: i64 = 1_790_109_000;

const SignedRepository = struct {
    allocator: std.mem.Allocator,
    archive: []u8,
    substitute_archive: []u8,
    packages: []u8,
    release: []u8,
    signature: []u8,
    keyring: []u8,
    fingerprint: [20]u8,

    fn init(allocator: std.mem.Allocator) !SignedRepository {
        const uid: u64 = if (builtin.os.tag == .linux) std.os.linux.getuid() else 0;
        const gid: u64 = if (builtin.os.tag == .linux) std.os.linux.getgid() else 0;
        var data = [_]archive_application.test_fixtures.Entry{
            .{ .path = "usr", .kind = '5', .mode = 0o755, .uid = uid, .gid = gid },
            .{ .path = "usr/share", .kind = '5', .mode = 0o755, .uid = uid, .gid = gid },
            .{
                .path = "usr/share/sha512-e2e",
                .content = "verified SHA512 transaction\n",
                .mode = 0o644,
                .uid = uid,
                .gid = gid,
            },
        };
        const archive = try archive_application.test_fixtures.build(allocator, .{
            .package = "demo",
            .version = "1.0",
            .architecture = "amd64",
            .data = &data,
        });
        errdefer allocator.free(archive);

        var substitute_data = data;
        substitute_data[2].content = "cache substitution payload\n";
        const substitute_archive = try archive_application.test_fixtures.build(allocator, .{
            .package = "demo",
            .version = "1.0",
            .architecture = "amd64",
            .data = &substitute_data,
        });
        errdefer allocator.free(substitute_archive);

        const archive_sha512 = content_digest.Value.of(.sha512, archive);
        var archive_hex: [128]u8 = undefined;
        const packages = try std.fmt.allocPrint(
            allocator,
            "Package: demo\n" ++
                "Version: 1.0\n" ++
                "Architecture: amd64\n" ++
                "Maintainer: debz fixture <fixture.invalid>\n" ++
                "Description: hermetic SHA512 transaction fixture\n" ++
                "Filename: " ++ package_path ++ "\n" ++
                "Size: {d}\n" ++
                "Installed-Size: 1\n" ++
                "SHA512: {s}\n\n",
            .{ archive.len, archive_sha512.hex(&archive_hex) },
        );
        errdefer allocator.free(packages);

        const index_identity = content_digest.Identity.ofSupported(packages);
        var index_sha256_hex: [128]u8 = undefined;
        var index_sha512_hex: [128]u8 = undefined;
        const release = try std.fmt.allocPrint(
            allocator,
            "Suite: stable\n" ++
                "Codename: stable\n" ++
                "Date: Tue, 22 Sep 2026 20:00:00 UTC\n" ++
                "Valid-Until: Wed, 23 Sep 2026 20:00:00 UTC\n" ++
                "Architectures: amd64\n" ++
                "Components: main\n" ++
                "Acquire-By-Hash: no\n" ++
                "SHA256:\n {s} {d} main/binary-amd64/Packages\n" ++
                "SHA512:\n {s} {d} main/binary-amd64/Packages\n",
            .{
                (content_digest.Value{ .sha256 = index_identity.digests.sha256.? }).hex(&index_sha256_hex),
                packages.len,
                (content_digest.Value{ .sha512 = index_identity.digests.sha512.? }).hex(&index_sha512_hex),
                packages.len,
            },
        );
        errdefer allocator.free(release);

        const signer = try TestSigner.init(allocator);
        errdefer allocator.free(signer.keyring);
        const signature = try signer.signDocument(allocator, release);
        errdefer allocator.free(signature);
        return .{
            .allocator = allocator,
            .archive = archive,
            .substitute_archive = substitute_archive,
            .packages = packages,
            .release = release,
            .signature = signature,
            .keyring = signer.keyring,
            .fingerprint = signer.fingerprint,
        };
    }

    fn deinit(self: *SignedRepository) void {
        self.allocator.free(self.keyring);
        self.allocator.free(self.signature);
        self.allocator.free(self.release);
        self.allocator.free(self.packages);
        self.allocator.free(self.substitute_archive);
        self.allocator.free(self.archive);
        self.* = undefined;
    }
};

const TestSigner = struct {
    key_pair: Ed25519.KeyPair,
    fingerprint: [20]u8,
    keyring: []u8,

    fn init(allocator: std.mem.Allocator) !TestSigner {
        const seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x42);
        const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);
        const public_key = key_pair.public_key.toBytes();

        var key_body: std.ArrayList(u8) = .empty;
        defer key_body.deinit(allocator);
        try key_body.append(allocator, 4);
        try appendInt(&key_body, allocator, u32, created);
        try key_body.append(allocator, 22);
        const oid = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01 };
        try key_body.append(allocator, oid.len);
        try key_body.appendSlice(allocator, &oid);
        var point: [33]u8 = undefined;
        point[0] = 0x40;
        point[1..].* = public_key;
        try appendMpi(&key_body, allocator, &point);

        var fingerprint_input: std.ArrayList(u8) = .empty;
        defer fingerprint_input.deinit(allocator);
        try fingerprint_input.append(allocator, 0x99);
        try appendInt(&fingerprint_input, allocator, u16, @intCast(key_body.items.len));
        try fingerprint_input.appendSlice(allocator, key_body.items);
        var fingerprint: [20]u8 = undefined;
        Sha1.hash(fingerprint_input.items, &fingerprint, .{});

        const uid = "debz SHA512 e2e fixture <fixture.invalid>";
        var keyring: std.ArrayList(u8) = .empty;
        errdefer keyring.deinit(allocator);
        try appendPacket(&keyring, allocator, 6, key_body.items);
        try appendPacket(&keyring, allocator, 13, uid);

        var certification_input: std.ArrayList(u8) = .empty;
        defer certification_input.deinit(allocator);
        try certification_input.appendSlice(allocator, fingerprint_input.items);
        try certification_input.append(allocator, 0xb4);
        try appendInt(&certification_input, allocator, u32, uid.len);
        try certification_input.appendSlice(allocator, uid);
        const certification = try signPacket(
            allocator,
            key_pair,
            fingerprint,
            0x13,
            certification_input.items,
            0x03,
        );
        defer allocator.free(certification);
        try keyring.appendSlice(allocator, certification);

        return .{
            .key_pair = key_pair,
            .fingerprint = fingerprint,
            .keyring = try keyring.toOwnedSlice(allocator),
        };
    }

    fn signDocument(self: TestSigner, allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
        return signPacket(
            allocator,
            self.key_pair,
            self.fingerprint,
            0x00,
            bytes,
            null,
        );
    }
};

fn signPacket(
    allocator: std.mem.Allocator,
    key_pair: Ed25519.KeyPair,
    fingerprint: [20]u8,
    signature_type: u8,
    signed_bytes: []const u8,
    key_flags: ?u8,
) ![]u8 {
    var hashed: std.ArrayList(u8) = .empty;
    defer hashed.deinit(allocator);
    var created_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &created_bytes, created, .big);
    try appendSubpacket(&hashed, allocator, 2, &created_bytes);
    var issuer: [21]u8 = undefined;
    issuer[0] = 4;
    issuer[1..].* = fingerprint;
    try appendSubpacket(&hashed, allocator, 33, &issuer);
    if (key_flags) |flags| try appendSubpacket(&hashed, allocator, 27, &.{flags});

    var prefix: std.ArrayList(u8) = .empty;
    defer prefix.deinit(allocator);
    try prefix.appendSlice(allocator, &.{ 4, signature_type, 22, 10 });
    try appendInt(&prefix, allocator, u16, @intCast(hashed.items.len));
    try prefix.appendSlice(allocator, hashed.items);

    var hash = Sha512.init(.{});
    hash.update(signed_bytes);
    hash.update(prefix.items);
    var trailer: [6]u8 = .{ 4, 0xff, 0, 0, 0, 0 };
    std.mem.writeInt(u32, trailer[2..6], @intCast(prefix.items.len), .big);
    hash.update(&trailer);
    const digest = hash.finalResult();
    const signature = try key_pair.sign(&digest, null);
    const encoded = signature.toBytes();

    var unhashed: std.ArrayList(u8) = .empty;
    defer unhashed.deinit(allocator);
    try appendSubpacket(&unhashed, allocator, 16, fingerprint[12..20]);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, prefix.items);
    try appendInt(&body, allocator, u16, @intCast(unhashed.items.len));
    try body.appendSlice(allocator, unhashed.items);
    try body.appendSlice(allocator, digest[0..2]);
    try appendMpi(&body, allocator, encoded[0..32]);
    try appendMpi(&body, allocator, encoded[32..64]);

    var packet: std.ArrayList(u8) = .empty;
    errdefer packet.deinit(allocator);
    try appendPacket(&packet, allocator, 2, body.items);
    return packet.toOwnedSlice(allocator);
}

fn appendPacket(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    tag: u8,
    body: []const u8,
) !void {
    try output.append(allocator, 0xc0 | tag);
    if (body.len < 192) {
        try output.append(allocator, @intCast(body.len));
    } else if (body.len < 8384) {
        const adjusted = body.len - 192;
        try output.append(allocator, @intCast((adjusted >> 8) + 192));
        try output.append(allocator, @intCast(adjusted & 0xff));
    } else {
        try output.append(allocator, 0xff);
        try appendInt(output, allocator, u32, @intCast(body.len));
    }
    try output.appendSlice(allocator, body);
}

fn appendSubpacket(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    kind: u8,
    body: []const u8,
) !void {
    const len = body.len + 1;
    if (len >= 192) return error.TestFixtureTooLarge;
    try output.append(allocator, @intCast(len));
    try output.append(allocator, kind);
    try output.appendSlice(allocator, body);
}

fn appendMpi(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    raw: []const u8,
) !void {
    var first: usize = 0;
    while (first < raw.len and raw[first] == 0) : (first += 1) {}
    if (first == raw.len) {
        try appendInt(output, allocator, u16, 0);
        return;
    }
    const significant = raw[first..];
    const leading_bits: u16 = @intCast(8 - @clz(significant[0]));
    const bit_len: u16 = @intCast((significant.len - 1) * 8 + leading_bits);
    try appendInt(output, allocator, u16, bit_len);
    try output.appendSlice(allocator, significant);
}

fn appendInt(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try output.appendSlice(allocator, &bytes);
}

const RepositoryTransport = struct {
    fixture: *const SignedRepository,
    requests: usize = 0,

    fn dependencies(self: *RepositoryTransport) repository_acquisition.Dependencies {
        return .{
            .transport = .{ .context = self, .requestFn = request },
            .files = .{ .context = self, .readFn = readFile },
            .clock = .{
                .context = self,
                .nowMsFn = nowMs,
                .sleepMsFn = sleepMs,
            },
        };
    }

    fn request(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        request_value: repository_acquisition.HttpRequest,
    ) !repository_acquisition.HttpResponse {
        const self: *RepositoryTransport = @ptrCast(@alignCast(context.?));
        self.requests += 1;
        const path = switch (request_value.uri.path) {
            .raw => |value| value,
            .percent_encoded => |value| value,
        };
        const bytes = if (std.mem.endsWith(u8, path, "/dists/stable/Release"))
            self.fixture.release
        else if (std.mem.endsWith(u8, path, "/dists/stable/Release.gpg"))
            self.fixture.signature
        else if (std.mem.endsWith(u8, path, "/dists/stable/main/binary-amd64/Packages"))
            self.fixture.packages
        else if (std.mem.endsWith(u8, path, "/" ++ package_path))
            self.fixture.archive
        else
            return .{ .status = 404, .body = try allocator.alloc(u8, 0) };
        if (bytes.len > request_value.max_response_bytes)
            return error.ResponseTooLarge;
        return .{ .status = 200, .body = try allocator.dupe(u8, bytes) };
    }

    fn readFile(
        _: ?*anyopaque,
        _: std.mem.Allocator,
        _: []const u8,
        _: usize,
        _: repository_acquisition.Deadlines,
    ) !repository_acquisition.FileRead {
        return error.NotFound;
    }

    fn nowMs(_: ?*anyopaque) u64 {
        return 0;
    }

    fn sleepMs(_: ?*anyopaque, _: u64) !void {}
};

fn refreshNow(_: ?*anyopaque) i64 {
    return verification_time;
}

fn refreshPolicy() repository_refresh.RefreshPolicy {
    return .{
        .mode = .online,
        .compression_order = &.{.uncompressed},
        .by_hash_fallback = .disabled,
        .maximum_future_seconds = 300,
        .expiry_policy = .require_valid_until,
        .maximum_compressed_bytes = 1024 * 1024,
        .maximum_decompressed_bytes = 4 * 1024 * 1024,
        .maximum_decoder_memory = 4 * 1024 * 1024,
    };
}

fn acquisitionPolicy() repository_refresh.AcquisitionPolicy {
    return .{
        .deadlines = .{ .connect_ms = 100, .read_ms = 100, .overall_ms = 1000 },
        .redirect_limit = 0,
        .maximum_release_bytes = 1024 * 1024,
    };
}

fn packagePolicy(mode: package_acquisition.Mode) package_acquisition.Policy {
    return .{
        .mode = mode,
        .maximum_package_bytes = 32 * 1024 * 1024,
        .deadlines = .{ .connect_ms = 100, .read_ms = 100, .overall_ms = 1000 },
        .redirect_limit = 0,
    };
}

fn createLock(
    allocator: std.mem.Allocator,
    refresh: *const repository_refresh.AuthenticatedResult,
    action: solver.PlanAction,
    identity: content_digest.Identity,
    request_sha256: [32]u8,
    policy_sha256: [32]u8,
) !exact_lock_v3.OwnedLock {
    return exact_lock_v3.create(allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = request_sha256,
        .policy_sha256 = policy_sha256,
        .repositories = &.{.{
            .id = repository_id.bytes,
            .snapshot_sha256 = repository_refresh.snapshotDigest(refresh),
            .release_sha256 = refresh.snapshot.provenance.release_digest.bytes,
            .index_identity = refresh.snapshot.provenance.index_identity,
            .signer_fingerprints = &.{refresh.snapshot.provenance.authentication_evidence.signatures[0].primary_fingerprint.?},
        }},
        .local_artifacts = &.{},
        .packages = &.{.{
            .name = action.package,
            .version = action.version,
            .architecture = action.architecture,
            .origin = .{ .authenticated_repository = .{
                .repository_id = repository_id.bytes,
                .repository_snapshot_sha256 = repository_refresh.snapshotDigest(refresh),
            } },
            .archive_identity = identity,
            .declared_size = action.package_size.?,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }},
        .verified_origins = true,
    });
}

fn initializeRoot(root: root_fs.Root) !void {
    for ([_][]const u8{
        "var",
        "var/lib",
        "var/lib/dpkg",
        "var/lib/dpkg/info",
        "var/lib/dpkg/updates",
        "var/lib/dpkg/triggers",
        "usr",
        "usr/bin",
    }) |path| {
        try root.ensureDirectory(
            try root_fs.Path.init(path),
            root_fs.default_directory_permissions,
        );
    }
    try root.publishFile(
        try root_fs.Path.init("var/lib/dpkg/status"),
        "",
        .{},
    );
    try root.publishFile(
        try root_fs.Path.init(native_helper.target_path),
        native_helper.bundled().bytes,
        .{ .permissions = .fromMode(0o755) },
    );
    var format_path: [256]u8 = undefined;
    const format = try std.fmt.bufPrint(
        &format_path,
        "var/lib/dpkg/info/{s}",
        .{package_database.info_format_name},
    );
    try root.publishFile(
        try root_fs.Path.init(format),
        package_database.supported_info_format ++ "\n",
        .{},
    );
}

const RecoveryClock = struct {
    root: root_fs.Root,

    fn now(context: ?*anyopaque) u64 {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        const active = self.root.entryIfExists(
            root_fs.Path.init(native_recovery.intent_path) catch return 1,
        ) catch return 1;
        return if (active != null) 1 else 0;
    }
};

const HermeticMechanics = struct {
    probes: usize = 0,

    fn probe(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        root: root_fs.Root,
        helper: native_helper.Binding,
        _: maintainer_script.Cancellation,
    ) !void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        try helper.matches(native_helper.bundled());
        const staged = try root.readFileAlloc(
            allocator,
            try root_fs.Path.init(helper.source_path),
            native_helper.maximum_bytes,
        );
        defer allocator.free(staged);
        if (!std.mem.eql(u8, staged, native_helper.bundled().bytes))
            return error.NativeHelperDigestMismatch;
        self.probes += 1;
    }
};

const MutationHarness = struct {
    bytes: []const u8,
    root_validations: usize = 0,
    root_normalizations: usize = 0,
    artifact_reads: usize = 0,
    lock_acquires: usize = 0,
    process_invocations: usize = 0,
    journal_writes: usize = 0,

    fn dependencies(self: *@This()) transaction_executor.Dependencies {
        return .{
            .filesystem = .{
                .context = self,
                .validateRootFn = validateRoot,
                .normalizeBootstrapRootFn = normalizeRoot,
                .validateArtifactPathFn = validateArtifactPath,
                .readArtifactFn = readArtifact,
            },
            .locks = .{
                .context = self,
                .acquireFn = acquire,
                .heldFn = held,
                .releaseFn = release,
            },
            .process = .{ .context = self, .runFn = run },
            .journal = .{
                .context = self,
                .loadFn = loadJournal,
                .writeAtomicFn = writeJournal,
                .archiveAtomicFn = archiveJournal,
            },
            .status = .{ .context = self, .readFn = readStatus },
        };
    }

    fn validateRoot(context: *anyopaque, _: []const u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.root_validations += 1;
    }

    fn normalizeRoot(context: *anyopaque, _: []const u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.root_normalizations += 1;
    }

    fn validateArtifactPath(_: *anyopaque, _: []const u8) !void {}

    fn readArtifact(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        maximum: usize,
    ) ![]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.artifact_reads += 1;
        if (self.bytes.len > maximum) return error.ArtifactTooLarge;
        return allocator.dupe(u8, self.bytes);
    }

    fn acquire(
        context: *anyopaque,
        _: []const u8,
        _: u64,
    ) !transaction_executor.LockToken {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.lock_acquires += 1;
        return self;
    }

    fn held(_: *anyopaque, _: transaction_executor.LockToken) bool {
        return true;
    }

    fn release(_: *anyopaque, _: transaction_executor.LockToken) void {}

    fn run(
        context: *anyopaque,
        _: transaction_executor.Invocation,
    ) !transaction_executor.ProcessResult {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.process_invocations += 1;
        return .{ .termination = .{ .exited = 0 } };
    }

    fn loadJournal(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: []const u8,
    ) !?[]u8 {
        return null;
    }

    fn writeJournal(context: *anyopaque, _: []const u8, _: []const u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.journal_writes += 1;
    }

    fn archiveJournal(context: *anyopaque, _: []const u8, _: []const u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.journal_writes += 1;
    }

    fn readStatus(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        _: usize,
    ) ![]u8 {
        return allocator.alloc(u8, 0);
    }

    fn expectNoMutation(self: @This()) !void {
        try testing.expectEqual(@as(usize, 0), self.root_validations);
        try testing.expectEqual(@as(usize, 0), self.root_normalizations);
        try testing.expectEqual(@as(usize, 0), self.lock_acquires);
        try testing.expectEqual(@as(usize, 0), self.process_invocations);
        try testing.expectEqual(@as(usize, 0), self.journal_writes);
    }
};

fn expectExecutorRefusal(
    allocator: std.mem.Allocator,
    plan: *const solver.Plan,
    lock: *const exact_lock_v3.Lock,
    artifacts: []const transaction_executor.Artifact,
    bytes: []const u8,
) !MutationHarness {
    var harness: MutationHarness = .{ .bytes = bytes };
    var result = try transaction_executor.execute(allocator, .{
        .plan = plan,
        .install_root = "/hermetic-root",
        .artifacts = artifacts,
        .policy = .{
            .conffile = .keep_existing,
            .exact_lock_verification = .locked_packages,
        },
        .exact_lock_v3 = lock,
    }, harness.dependencies());
    defer result.deinit();
    try testing.expect(!result.succeeded());
    try harness.expectNoMutation();
    return harness;
}

fn expectLegacySha256RequestBytes(allocator: std.mem.Allocator) !void {
    var document: native_execution_request.Document = .{
        .install_root = "/legacy-sha256-root",
        .root_identity_sha256 = native_recovery.hexDigest(
            transaction_recovery.rootIdentity("/legacy-sha256-root"),
        ),
        .root_inode = 42,
        .architecture = "amd64",
        .caller = .{
            .attempt_id = @splat('2'),
            .operation = .{ .package_transaction = .install },
            .request_sha256 = @splat('3'),
            .policy_sha256 = @splat('4'),
        },
        .program = .{
            .request_sha256 = @splat('3'),
            .solver_policy_sha256 = @splat('5'),
            .executor_policy_sha256 = @splat('4'),
            .plan_sha256 = @splat('6'),
            .authorization_sha256 = @splat('7'),
            .program_sha256 = @splat('8'),
            .exact_lock_sha256 = @splat('9'),
            .artifact_evidence_sha256 = @splat('a'),
            .database_generation_sha256 = @splat('b'),
            .script_policy_sha256 = @splat('c'),
        },
        .operation = .install,
        .policy = .keep_existing,
        .triggers = true,
        .defer_triggers = true,
    };
    native_execution_request.seal(&document);
    const bytes = try native_execution_request.encode(allocator, document);
    defer allocator.free(bytes);
    var decoded = try native_execution_request.decode(allocator, bytes);
    defer decoded.deinit();
    const replayed = try native_execution_request.encode(allocator, decoded.document);
    defer allocator.free(replayed);
    try testing.expectEqualStrings(bytes, replayed);
    var observed: [32]u8 = undefined;
    Sha256.hash(bytes, &observed, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "01b77ba4e4517f7b224bfe903267a211eb801df158b4c635722c15a8fdd3ed23",
    );
    try testing.expectEqualSlices(u8, &expected, &observed);
}

test "sha512_e2e.test.hermetic signed SHA512-only transaction verifies recovery and fail-closed identities" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;

    var fixture = try SignedRepository.init(allocator);
    defer fixture.deinit();
    var transport: RepositoryTransport = .{ .fixture = &fixture };

    var metadata_tmp = testing.tmpDir(.{});
    defer metadata_tmp.cleanup();
    var metadata = try metadata_cache.Cache.initFromDir(testing.io, metadata_tmp.dir, .{
        .max_object_bytes = 4 * 1024 * 1024,
    });
    defer metadata.deinit();

    const base_uri = try repository_acquisition.Uri.parse(base_uri_text);
    var refreshed = try repository_refresh.refreshAuthenticated(
        allocator,
        .{
            .id = repository_id,
            .base_uri = base_uri,
            .suite = "stable",
            .component = "main",
            .architecture = "amd64",
        },
        .{ .detached_release = .{
            .keyrings = .{ .one = .{ .bytes = fixture.keyring } },
            .accepted_primary_fingerprints = &.{fixture.fingerprint},
            .verification_time = verification_time,
        } },
        acquisitionPolicy(),
        refreshPolicy(),
        .{
            .acquisition = transport.dependencies(),
            .cache = &metadata,
            .clock = .{ .context = null, .nowUnixFn = refreshNow },
            .io = testing.io,
        },
    );
    defer refreshed.deinit();
    try testing.expectEqual(repository_refresh.AuthenticationStatus.openpgp_verified, refreshed.snapshot.provenance.authentication);
    try testing.expectEqual(@as(u8, 10), refreshed.snapshot.provenance.authentication_evidence.signatures[0].hash_algorithm);
    try testing.expectEqualSlices(
        u8,
        &fixture.fingerprint,
        &refreshed.snapshot.provenance.authentication_evidence.signatures[0].primary_fingerprint.?,
    );
    try testing.expectEqual(content_digest.Algorithm.sha512, refreshed.snapshot.provenance.index_identity.primary);
    try testing.expect(refreshed.snapshot.provenance.index_identity.digests.sha256 != null);
    try testing.expect(refreshed.snapshot.provenance.index_identity.digests.sha512 != null);
    try refreshed.snapshot.provenance.index_identity.verify(fixture.packages);

    const repository = solver.RepositoryInput.fromRefresh(&refreshed, 500);
    var planning = try solver.planTransaction(allocator, .{
        .repositories = &.{repository},
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = &.{.{ .name = "demo", .architecture = "amd64" }} },
        .output_schema_version = .v4,
    });
    var plan = switch (planning) {
        .plan => |value| value,
        .failure => |*failure| {
            defer failure.deinit();
            std.debug.print("unexpected solver failure: {any}\n", .{failure.problems});
            return error.TestUnexpectedResult;
        },
    };
    defer plan.deinit();
    try testing.expectEqual(@as(u32, 4), plan.schema_version);
    try testing.expectEqual(@as(usize, 1), plan.actions.len);
    const action = plan.actions[0];
    try testing.expect(action.sha256 == null);
    try testing.expect(action.archive_identity != null);
    try testing.expectEqual(content_digest.Algorithm.sha512, action.archive_identity.?.primary);
    try testing.expect(action.archive_identity.?.digests.sha256 == null);
    try action.archive_identity.?.verify(fixture.archive);

    var request_sha256: [32]u8 = undefined;
    Sha256.hash("install demo", &request_sha256, .{});
    const policy: transaction_executor.Policy = .{
        .conffile = .keep_existing,
        .exact_lock_verification = .locked_packages,
    };
    const policy_sha256 = transaction_executor.policyDigest(policy);
    var lock = try createLock(
        allocator,
        &refreshed,
        action,
        action.archive_identity.?,
        request_sha256,
        policy_sha256,
    );
    defer lock.deinit();
    const lock_json = try lock.lock.canonicalJson(allocator);
    defer allocator.free(lock_json);
    var decoded_lock = try exact_lock_v3.decode(
        allocator,
        lock_json,
        exact_lock_v3.maximum_document_bytes,
    );
    defer decoded_lock.deinit();
    try testing.expect(decoded_lock.lock.packages[0].archive_identity.digests.sha256 == null);
    const replayed_lock_json = try decoded_lock.lock.canonicalJson(allocator);
    defer allocator.free(replayed_lock_json);
    try testing.expectEqualStrings(lock_json, replayed_lock_json);

    const plan_json = try plan.canonicalJson(allocator);
    defer allocator.free(plan_json);
    var decoded_plan = try repository_plan.decode(allocator, plan_json);
    defer decoded_plan.deinit();
    const replayed_plan_json = try decoded_plan.canonicalJson(allocator);
    defer allocator.free(replayed_plan_json);
    try testing.expectEqualStrings(plan_json, replayed_plan_json);

    var package_tmp = testing.tmpDir(.{});
    defer package_tmp.cleanup();
    var cache = try package_acquisition.Cache.initFromDir(testing.io, package_tmp.dir, .{
        .maximum_object_bytes = 32 * 1024 * 1024,
    });
    defer cache.deinit();
    const selected = try package_acquisition.SelectedPackage.fromSolverSelection(
        repository,
        action.selected_origin.?,
        base_uri,
    );
    var acquired = try package_acquisition.acquirePackage(
        allocator,
        &cache,
        .{
            .selected = selected,
            .policy = packagePolicy(.online),
            .exact_lock_v3_package = lock.lock.packages[0],
        },
        transport.dependencies(),
    );
    defer acquired.deinit();
    try testing.expectEqual(package_acquisition.Outcome.downloaded, acquired.provenance.outcome);
    try testing.expect(acquired.provenance.expected_sha256 == null);
    try testing.expect(std.mem.startsWith(u8, acquired.provenance.cache_key, "sha512-"));
    try testing.expectEqualStrings(fixture.archive, acquired.bytes);

    var offline_transport: RepositoryTransport = .{ .fixture = &fixture };
    var cached = try package_acquisition.acquirePackage(
        allocator,
        &cache,
        .{
            .selected = selected,
            .policy = packagePolicy(.cache_only),
            .exact_lock_v3_package = lock.lock.packages[0],
        },
        offline_transport.dependencies(),
    );
    defer cached.deinit();
    try testing.expectEqual(package_acquisition.Outcome.cache_hit, cached.provenance.outcome);
    try testing.expectEqual(@as(usize, 0), offline_transport.requests);

    const artifact: transaction_executor.Artifact = .{
        .package = action.package,
        .version = action.version,
        .architecture = action.architecture,
        .path = "/cache/sha512-demo.deb",
    };
    _ = try expectExecutorRefusal(
        allocator,
        &plan,
        &lock.lock,
        &.{},
        fixture.archive,
    );

    var wrong_sha512 = action.archive_identity.?.digests.sha512.?;
    wrong_sha512[0] ^= 0xff;
    const mismatched_identity = try content_digest.Identity.init(
        .{ .sha512 = wrong_sha512 },
        .sha512,
    );
    var mismatched_actions = [_]solver.PlanAction{action};
    mismatched_actions[0].archive_identity = mismatched_identity;
    var mismatched_plan = plan;
    mismatched_plan.actions = &mismatched_actions;
    _ = try expectExecutorRefusal(
        allocator,
        &mismatched_plan,
        &lock.lock,
        &.{artifact},
        fixture.archive,
    );

    var unknown_plan = plan;
    unknown_plan.schema_version = 99;
    _ = try expectExecutorRefusal(
        allocator,
        &unknown_plan,
        &lock.lock,
        &.{artifact},
        fixture.archive,
    );

    var archive_sha256: [32]u8 = undefined;
    Sha256.hash(fixture.archive, &archive_sha256, .{});
    const sha256_identity = try content_digest.Identity.init(
        .{ .sha256 = archive_sha256 },
        .sha256,
    );
    var downgraded_actions = [_]solver.PlanAction{action};
    downgraded_actions[0].sha256 = std.fmt.bytesToHex(archive_sha256, .lower);
    downgraded_actions[0].archive_identity = sha256_identity;
    var downgraded_plan = plan;
    downgraded_plan.schema_version = 3;
    downgraded_plan.actions = &downgraded_actions;
    _ = try expectExecutorRefusal(
        allocator,
        &downgraded_plan,
        &lock.lock,
        &.{artifact},
        fixture.archive,
    );

    var wrong_sha256 = archive_sha256;
    wrong_sha256[0] ^= 0xff;
    const mixed_identity = try content_digest.Identity.init(
        .{ .sha256 = wrong_sha256, .sha512 = action.archive_identity.?.digests.sha512.? },
        .sha512,
    );
    var mixed_actions = [_]solver.PlanAction{action};
    mixed_actions[0].sha256 = std.fmt.bytesToHex(wrong_sha256, .lower);
    mixed_actions[0].archive_identity = mixed_identity;
    var mixed_plan = plan;
    mixed_plan.actions = &mixed_actions;
    var mixed_lock = try createLock(
        allocator,
        &refreshed,
        mixed_actions[0],
        mixed_identity,
        request_sha256,
        policy_sha256,
    );
    defer mixed_lock.deinit();
    const mixed_refusal = try expectExecutorRefusal(
        allocator,
        &mixed_plan,
        &mixed_lock.lock,
        &.{artifact},
        fixture.archive,
    );
    try testing.expectEqual(@as(usize, 1), mixed_refusal.artifact_reads);

    const substituted = try expectExecutorRefusal(
        allocator,
        &plan,
        &lock.lock,
        &.{artifact},
        fixture.substitute_archive,
    );
    try testing.expectEqual(@as(usize, 1), substituted.artifact_reads);

    var root_tmp = testing.tmpDir(.{ .iterate = true });
    defer root_tmp.cleanup();
    const root = root_fs.Root.init(testing.io, root_tmp.dir);
    try initializeRoot(root);
    var install_root_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    const install_root_len = try root_tmp.dir.realPath(testing.io, &install_root_buffer);
    const install_root = install_root_buffer[0..install_root_len];

    var locks: root_operation.TestLockBackend = .{ .allocator = allocator };
    defer locks.deinit();
    var coordinator = try root_operation.Coordinator.open(
        testing.io,
        root,
        install_root,
        locks.interface(),
    );
    var attempt = try coordinator.acquire(allocator, .{
        .backend = .native,
        .operation = .{ .package_transaction = .install },
        .request_sha256 = request_sha256,
        .policy_sha256 = policy_sha256,
        .target_architecture = "amd64",
        .attempt_id = @splat(0x91),
    });
    var attempt_released = false;
    defer if (!attempt_released) attempt.release();

    var preparation = try native_unpack.Runtime.prepare(allocator, .{
        .attempt = &attempt,
        .plan = &plan,
        .exact_lock = &lock.lock,
        .archives = &.{cached.bytes},
        .policy = policy,
    });
    defer preparation.deinit();
    const prepared = switch (preparation) {
        .prepared => |*value| value,
        .diagnostic => |value| {
            std.debug.print("unexpected native preparation diagnostic: {any}\n", .{value.diagnostic});
            return error.TestUnexpectedResult;
        },
        .unchanged => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(native_authorization.schema_v2_version, prepared.authorization.authorization.wire_version);
    try testing.expectEqual(native_program.schema_v2_version, prepared.program.program.version);
    try testing.expectEqualStrings(native_program.schema_v2_id, prepared.program.program.schema);
    try testing.expect(prepared.authorization.authorization.actions[0].artifact.?.archive_identity.?.digests.sha256 == null);
    try testing.expect(prepared.program.program.artifacts[0].identity().?.digests.sha256 == null);

    const authorization_json = try prepared.authorization.authorization.canonicalJson(allocator);
    defer allocator.free(authorization_json);
    var decoded_authorization = try native_authorization.decode(
        allocator,
        authorization_json,
        native_authorization.maximum_document_bytes,
    );
    defer decoded_authorization.deinit();
    const replayed_authorization_json = try decoded_authorization.authorization.canonicalJson(allocator);
    defer allocator.free(replayed_authorization_json);
    try testing.expectEqualStrings(authorization_json, replayed_authorization_json);
    const program_json = try prepared.program.program.canonicalJson(allocator);
    defer allocator.free(program_json);
    var decoded_program = try native_program.decode(
        allocator,
        program_json,
        native_program.maximum_document_bytes,
    );
    defer decoded_program.deinit();
    const replayed_program_json = try decoded_program.program.canonicalJson(allocator);
    defer allocator.free(replayed_program_json);
    try testing.expectEqualStrings(program_json, replayed_program_json);

    var deadline_clock: RecoveryClock = .{ .root = root };
    var mechanics: HermeticMechanics = .{};
    const external_mechanics: native_unpack.Runtime.ExternalMechanics = .{
        .context = &mechanics,
        .probe_helper_fn = HermeticMechanics.probe,
    };
    var interrupted = try native_unpack.Runtime.execute(allocator, .{
        .attempt = &attempt,
        .prepared = prepared,
        .archives = &.{cached.bytes},
        .operation = .install,
        .deadline = .{
            .context = &deadline_clock,
            .nowMsFn = RecoveryClock.now,
            .expires_at_ms = 1,
        },
        .external_mechanics = external_mechanics,
    });
    defer interrupted.deinit();
    try testing.expectEqual(native_unpack.Runtime.Outcome.recovery_required, interrupted.outcome);
    try testing.expectEqual(@as(usize, 1), mechanics.probes);
    try testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) != null);
    try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/sha512-e2e")) == null);

    var intent = try native_recovery.readIntent(allocator, root);
    defer intent.deinit();
    try testing.expectEqualStrings(native_recovery.authorization_v2_name, intent.intent.authorization_path);
    try testing.expectEqualStrings(native_recovery.program_v2_name, intent.intent.program_path);
    var namespace = try root.openDirectory(try root_fs.Path.init(root_operation.namespace_path));
    defer namespace.close(testing.io);
    const authorization_store = try native_authorization.Store.init(
        testing.io,
        namespace,
        intent.intent.authorization_path,
    );
    var persisted_authorization = try authorization_store.read(
        allocator,
        native_authorization.maximum_document_bytes,
    );
    defer persisted_authorization.deinit();
    try testing.expectEqual(
        native_authorization.schema_v2_version,
        persisted_authorization.authorization.wire_version,
    );
    try testing.expectEqualStrings(
        &prepared.authorization.authorization.digest_sha256,
        &persisted_authorization.authorization.digest_sha256,
    );
    const program_store = try native_program.Store.init(
        testing.io,
        namespace,
        intent.intent.program_path,
    );
    var persisted_program = try program_store.read(allocator, native_program.maximum_document_bytes);
    defer persisted_program.deinit();
    try testing.expectEqual(native_program.schema_v2_version, persisted_program.program.version);
    try testing.expectEqualStrings(
        &prepared.program.program.digest_sha256,
        &persisted_program.program.digest_sha256,
    );
    var saw_request = false;
    for (intent.intent.blobs) |blob| {
        const bytes = try native_recovery.verifyBlob(allocator, root, blob);
        defer allocator.free(bytes);
        if (std.mem.eql(u8, blob.logical_path, native_execution_request.authority_logical_path)) {
            var execution_request = try native_execution_request.decodePersisted(allocator, bytes);
            defer execution_request.deinit();
            try execution_request.validateAuthorityDocuments(
                prepared.authorization.authorization,
                prepared.program.program,
            );
            try testing.expect(execution_request == .authority_v2);
            try testing.expectEqualStrings(
                native_execution_request.authority_logical_path,
                execution_request.logicalPath(),
            );
            try testing.expectEqualStrings(
                native_execution_request.authority_schema_id,
                execution_request.authority_v2.document.schema,
            );
            saw_request = true;
        }
    }
    try testing.expect(saw_request);

    var recovered = try native_unpack.Runtime.recoverWithExternalMechanics(
        allocator,
        &attempt,
        external_mechanics,
    );
    defer recovered.deinit();
    try testing.expectEqual(native_unpack.Runtime.Outcome.succeeded, recovered.outcome);
    const receipt = recovered.receipt.?.document;
    try testing.expectEqual(native_provenance.schema_version, receipt.version);
    try testing.expectEqual(native_provenance.Outcome.succeeded, receipt.outcome);
    try testing.expectEqualStrings(
        native_execution_request.authority_schema_id,
        receipt.authority.?.execution_request_schema,
    );
    try testing.expectEqualStrings(
        native_authorization.schema_v2_id,
        receipt.authority.?.authorization_schema,
    );
    try testing.expectEqualStrings(
        native_program.schema_v2_id,
        receipt.authority.?.program_schema,
    );
    try testing.expectEqualStrings(exact_lock_v3.schema_id, receipt.authority.?.exact_lock_schema);
    try native_unpack.Runtime.verifyCompletedState(
        allocator,
        root,
        prepared.authorization.authorization,
        receipt,
    );
    const payload = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init("usr/share/sha512-e2e"),
        4096,
    );
    defer allocator.free(payload);
    try testing.expectEqualStrings("verified SHA512 transaction\n", payload);
    const status = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init("var/lib/dpkg/status"),
        1024 * 1024,
    );
    defer allocator.free(status);
    try testing.expect(std.mem.indexOf(u8, status, "Package: demo\n") != null);
    try testing.expect(std.mem.indexOf(u8, status, "Status: install ok installed\n") != null);

    var replayed = try native_unpack.Runtime.recoverWithExternalMechanics(
        allocator,
        &attempt,
        external_mechanics,
    );
    defer replayed.deinit();
    try testing.expectEqual(native_unpack.Runtime.Outcome.succeeded, replayed.outcome);
    try testing.expectEqualStrings(receipt.digest_sha256[0..], replayed.receipt.?.document.digest_sha256[0..]);

    switch (attempt.record().state) {
        .mutating => try attempt.advance(allocator, .{ .state = .verifying, .phase = .verification }),
        .recovery_required => try attempt.beginRecovery(allocator, attempt.record().phase),
        .verifying, .recovering => {},
        else => return error.TestUnexpectedResult,
    }
    try attempt.complete(allocator, .succeeded);
    const receipt_digest = native_recovery.parseDigest(receipt.digest_sha256) orelse
        return error.TestUnexpectedResult;
    var completion = try root_operation_completion.create(allocator, .{
        .record = attempt.record(),
        .transaction_provenance = .{
            .status = .already_present,
            .schema = native_provenance.schema_id,
            .version = native_provenance.schema_version,
            .document_sha256 = receipt_digest,
            .detail = "verified terminal native receipt",
        },
        .journal = .{
            .status = .absent,
            .detail = "native receipt binds native phase journals; no command journal",
        },
        .discharge = .{
            .surface = .package_transaction,
            .operation = "install",
            .request_sha256 = request_sha256,
        },
    });
    defer completion.deinit();
    const completion_store = root_operation_completion.Store.init(root);
    try completion_store.publish(allocator, completion.document);
    try attempt.publishProvenance(allocator, completion.document.digest_sha256);
    try native_unpack.Runtime.acknowledge(allocator, &attempt, receipt.digest_sha256);
    try testing.expect(!try native_unpack.Runtime.hasActiveEvidence(allocator, root));
    try attempt.clear();
    attempt.release();
    attempt_released = true;

    // The in-memory lock adapter models exclusion only; settled verification
    // also requires the persistent lock-file anchor provided by production.
    try root.publishFile(try root_fs.Path.init(root_operation.lock_path), "", .{});
    const result = try native_transaction_result.verify(
        allocator,
        root,
        install_root,
        lock.lock,
        "amd64",
        locks.interface(),
    );
    try testing.expectEqualSlices(u8, &lock.lock.digest_sha256, &result.lock_sha256);
    try testing.expectEqualSlices(u8, &receipt_digest, &result.transaction_digest_sha256);
    try testing.expectEqualSlices(u8, &completion.document.digest_sha256, &result.completion_digest_sha256);
    try testing.expectEqual(@as(usize, 1), result.package_count);
    const result_json = try result.canonicalJson(allocator);
    defer allocator.free(result_json);
    try testing.expect(std.mem.indexOf(
        u8,
        result_json,
        "\"final_verification_status\":\"exact_match\"",
    ) != null);
    try expectLegacySha256RequestBytes(allocator);
}

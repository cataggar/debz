const std = @import("std");
const builtin = @import("builtin");
const debz = @import("debz");
const fs = debz.root_fs;
const linux = std.os.linux;
const options = @import("debian_closure_options");

const pin_bytes = @embedFile("fixtures/debian-stable-readiness-v1.json");
const evidence_schema = "https://debz.dev/test/debian-stable-closure-evidence-v1";
const manifest_schema = "https://debz.dev/test/debian-closure-manifest-v1";
const inventory_schema = "https://debz.dev/test/debian-closure-inventory-v1";
const lock_schema = "https://debz.dev/schema/exact-closure-lock-v3";
const architectures = [_][]const u8{ "amd64", "arm64" };
const requests = [_][]const u8{ "apt", "systemd-sysv" };
const keyring_path = "/usr/share/keyrings/debian-archive-trixie-stable.pgp";
const archive_binding = "signed_sha256_derived_sha512";
const derived_provenance = "derived_from_signed_sha256";
const max_packages_per_lock: usize = 128;
const max_bytes_per_lock: u64 = 64 * 1024 * 1024;
const deadline_ms: u64 = 300_000;
const pin_expired_exit: u8 = 75;
const maximum_index_bytes: usize = 20 * 1024 * 1024;
const maximum_packages_bytes: usize = 128 * 1024 * 1024;
const maximum_json_bytes: usize = 16 * 1024 * 1024;
const maximum_archive_bytes: usize = 64 * 1024 * 1024;

const Index = struct {
    index_path: []const u8,
    index_size: usize,
    index_sha256: []const u8,
    package_records: usize,
};

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
        return error.UnsupportedArchitecture;
    }
};

const CategoryRule = struct {
    category: []const u8,
    status: []const u8,
};

const category_status = [_]CategoryRule{
    .{ .category = "native_archive_rejected", .status = "native archive admission refuses the archive before mutation" },
    .{ .category = "alternatives_script_authority", .status = "native lifecycle refuses the script before launch; only exact Ubuntu script and dpkg tool digests carry update-alternatives authority" },
    .{ .category = "debconf_frontend", .status = "no Debian debconf database/frontend authority; only exact Ubuntu staged-script allowances exist" },
    .{ .category = "kernel_filesystem", .status = "runner provides no /proc or /sys; only exact Ubuntu proc views exist" },
    .{ .category = "device_node", .status = "runner creates no device nodes and the archive profile rejects them" },
    .{ .category = "accounts", .status = "script mutates account databases outside the dpkg database; no Debian execution evidence" },
    .{ .category = "service_manager", .status = "service enablement/invocation in a chroot without a running manager; no Debian execution evidence" },
    .{ .category = "system_registry", .status = "script updates a system registry outside the dpkg database; no Debian execution evidence" },
    .{ .category = "capabilities", .status = "file capabilities are not modeled by the native archive profile" },
    .{ .category = "environment_probe", .status = "script probes the runtime environment; the native runner result is unobserved for Debian" },
    .{ .category = "dpkg_database_helper", .status = "modeled natively (diversions, statoverrides, triggers, maintscript helpers) but without Debian parity evidence" },
    .{ .category = "conffile_helper", .status = "ucf-managed configuration is outside dpkg conffile tracking" },
    .{ .category = "ldconfig", .status = "modeled as an ordinary in-root command; no Debian parity evidence" },
    .{ .category = "trigger_declaration", .status = "declared trigger interests/activations are modeled; Debian processing parity is unobserved" },
    .{ .category = "remove_on_upgrade_conffile", .status = "modeled declaration; Debian upgrade parity is unobserved" },
    .{ .category = "ownership_and_mode", .status = "supported metadata recorded for review against statoverrides" },
};

fn categoryStatus(category: []const u8) ![]const u8 {
    for (category_status) |rule| {
        if (std.mem.eql(u8, rule.category, category)) return rule.status;
    }
    return error.UnreviewedGapCategory;
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn sha512Hex(bytes: []const u8) [128]u8 {
    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn isHexLen(value: []const u8, expected_len: usize) bool {
    if (value.len != expected_len) return false;
    for (value) |ch| {
        if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'))) return false;
    }
    return true;
}

fn loadPin(allocator: std.mem.Allocator) !Pin {
    return (try std.json.parseFromSlice(Pin, allocator, pin_bytes, .{})).value;
}

fn parseReleaseDate(text: []const u8) ?debz.release_metadata.Timestamp {
    var tokens: [6][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.tokenizeAny(u8, text, " \t");
    while (it.next()) |token| {
        if (count == tokens.len) return null;
        tokens[count] = token;
        count += 1;
    }
    const offset: usize = if (count == 6) 1 else if (count == 5) 0 else return null;
    const day = std.fmt.parseUnsigned(u8, tokens[offset], 10) catch return null;
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const month: u8 = blk: {
        for (months, 1..) |m, idx| {
            if (std.ascii.eqlIgnoreCase(tokens[offset + 1], m)) break :blk @intCast(idx);
        }
        return null;
    };
    const year = std.fmt.parseUnsigned(u16, tokens[offset + 2], 10) catch return null;
    const time_str = tokens[offset + 3];
    if (time_str.len != 8 or time_str[2] != ':' or time_str[5] != ':') return null;
    const hour = std.fmt.parseUnsigned(u8, time_str[0..2], 10) catch return null;
    const minute = std.fmt.parseUnsigned(u8, time_str[3..5], 10) catch return null;
    const second = std.fmt.parseUnsigned(u8, time_str[6..8], 10) catch return null;
    const zone = tokens[offset + 4];
    const utc_offset_minutes: i16 = if (std.ascii.eqlIgnoreCase(zone, "UTC") or std.ascii.eqlIgnoreCase(zone, "GMT") or std.mem.eql(u8, zone, "+0000") or std.mem.eql(u8, zone, "-0000"))
        0
    else
        return null;
    return .{
        .weekday = null,
        .year = year,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
        .utc_offset_minutes = utc_offset_minutes,
    };
}

fn releaseExpiry(pin: Pin) !i64 {
    if (pin.release.valid_until != null) return error.UnexpectedValidUntil;
    const parsed_date = parseReleaseDate(pin.release.date) orelse return error.InvalidReleaseDate;
    const dated = debz.repository_refresh.timestampUnix(parsed_date);
    return std.math.add(i64, dated, @intCast(pin.release.maximum_release_age_seconds)) catch return error.InvalidReleaseExpiry;
}

fn formatIsoUtc(allocator: std.mem.Allocator, unix_seconds: i64) ![]u8 {
    if (unix_seconds < 0) return error.InvalidTimestamp;
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix_seconds) };
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
}

fn requireFresh(pin: Pin, now: i64) !i64 {
    const expiry = try releaseExpiry(pin);
    if (now > expiry) return error.PinExpired;
    return expiry;
}

fn readinessExecutable(allocator: std.mem.Allocator) ![]const u8 {
    if (std.c.getenv("DEBZ_DEBIAN_STABLE_READINESS")) |raw| {
        const value = std.mem.span(raw);
        if (value.len > 0) return allocator.dupe(u8, value);
    }
    return std.fs.path.join(allocator, &.{ options.repository, "zig-out/bin/debz-debian-stable-readiness" });
}

fn nativeReadiness(
    io: std.Io,
    allocator: std.mem.Allocator,
    readiness: []const u8,
    arguments: []const []const u8,
    input: ?[]const u8,
) ![]u8 {
    if (!std.fs.path.isAbsolute(readiness)) return error.RelativeReadinessPath;
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, readiness);
    try argv.appendSlice(allocator, arguments);

    var env: std.process.Environ.Map = .init(allocator);
    defer env.deinit();
    try env.put("PATH", "/no-host-interpreters");

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = &env,
        .stdin = if (input != null) .pipe else .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    errdefer child.kill(io);
    if (input) |bytes| {
        var stdin_file = child.stdin.?;
        child.stdin = null;
        stdin_file.writeStreamingAll(io, bytes) catch {};
        stdin_file.close(io);
    }
    var stdout_reader = child.stdout.?.reader(io, &.{});
    const stdout = try stdout_reader.interface.allocRemaining(allocator, .limited(maximum_index_bytes + 4096));
    var stderr_reader = child.stderr.?.reader(io, &.{});
    const stderr = try stderr_reader.interface.allocRemaining(allocator, .limited(64 * 1024));
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        if (std.mem.indexOf(u8, stderr, "SignedIndexIdentityChanged") != null)
            return error.SignedIndexIdentityChanged;
        return error.NativeReadinessRefused;
    }
    return stdout;
}

fn readinessFetch(
    io: std.Io,
    allocator: std.mem.Allocator,
    readiness: []const u8,
    kind: []const u8,
    architecture: ?[]const u8,
) ![]u8 {
    const flag = try std.fmt.allocPrint(allocator, "--fetch-{s}", .{kind});
    if (architecture) |arch| {
        return nativeReadiness(io, allocator, readiness, &.{ flag, "--architecture", arch }, null);
    }
    return nativeReadiness(io, allocator, readiness, &.{flag}, null);
}

fn readinessIndexCounts(
    io: std.Io,
    allocator: std.mem.Allocator,
    readiness: []const u8,
    compressed: []const u8,
    index: Index,
) ![3]usize {
    const identity_json = try std.fmt.allocPrint(
        allocator,
        "{{\"index_size\":{d},\"index_sha256\":\"{s}\",\"package_records\":{d}}}",
        .{ index.index_size, index.index_sha256, index.package_records },
    );
    const out = try nativeReadiness(
        io,
        allocator,
        readiness,
        &.{ "--check-index", "--index-identity", identity_json },
        compressed,
    );
    return (try std.json.parseFromSlice([3]usize, allocator, std.mem.trim(u8, out, " \t\r\n"), .{})).value;
}

fn lstatPath(allocator: std.mem.Allocator, path: []const u8) !linux.Statx {
    const path_z = try std.fmt.allocPrintSentinel(allocator, "{s}", .{path}, 0);
    defer allocator.free(path_z);
    var stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const rc = linux.statx(
        linux.AT.FDCWD,
        path_z.ptr,
        linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT,
        linux.STATX.BASIC_STATS,
        &stx,
    );
    if (linux.errno(rc) != .SUCCESS) return error.KeyringStatFailed;
    return stx;
}

fn readRegularFileAlloc(io: std.Io, allocator: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    var root = try fs.openAbsoluteRoot(io, std.fs.path.dirname(path) orelse return error.InvalidPath);
    defer root.close();
    var pin = try root.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(path)));
    defer pin.close();
    const observed = try pin.observeStableAlloc(allocator, limit);
    return observed.bytes;
}

fn verifyKeyring(io: std.Io, allocator: std.mem.Allocator, path: []const u8, expected_key: []const u8) !void {
    if (!std.fs.path.isAbsolute(path)) return error.RelativeKeyringPath;
    const root_stx = try lstatPath(allocator, "/");
    if ((root_stx.mode & linux.S.IFMT) == linux.S.IFLNK) return error.KeyringPathSymlink;
    if (root_stx.uid != 0 or (root_stx.mode & 0o022) != 0) return error.KeyringPathNotRootOwnedOrProtected;

    var current: std.ArrayList(u8) = .empty;
    defer current.deinit(allocator);
    var parts = std.mem.tokenizeScalar(u8, path, '/');
    while (parts.next()) |part| {
        try current.append(allocator, '/');
        try current.appendSlice(allocator, part);
        const stx = try lstatPath(allocator, current.items);
        if ((stx.mode & linux.S.IFMT) == linux.S.IFLNK) return error.KeyringPathSymlink;
        if (stx.uid != 0 or (stx.mode & 0o022) != 0) return error.KeyringPathNotRootOwnedOrProtected;
    }
    const final_stx = try lstatPath(allocator, path);
    if ((final_stx.mode & linux.S.IFMT) != linux.S.IFREG) return error.KeyringNotRegularFile;
    const bytes = try readRegularFileAlloc(io, allocator, path, 64 * 1024);
    if (!std.mem.eql(u8, bytes, expected_key)) return error.KeyringBytesMismatch;
}

fn getStringField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return if (val == .string) val.string else null;
}

const LockReview = struct {
    packages: usize,
    total_bytes: u64,
};

fn reviewLock(lock_val: std.json.Value, pin: Pin, architecture: []const u8, request: []const u8) !LockReview {
    if (lock_val != .object) return error.InvalidLockFormat;
    const lock = lock_val.object;
    const schema = getStringField(lock, "schema") orelse return error.InvalidLockFormat;
    const version_val = lock.get("version") orelse return error.InvalidLockFormat;
    if (!std.mem.eql(u8, schema, lock_schema) or version_val != .integer or version_val.integer != 3)
        return error.InvalidLockSchemaOrVersion;

    const target_arch = getStringField(lock, "target_architecture") orelse return error.TargetArchitectureMismatch;
    if (!std.mem.eql(u8, target_arch, architecture)) return error.TargetArchitectureMismatch;

    const local_artifacts = lock.get("local_artifacts") orelse return error.LocalArtifactsPresent;
    if (local_artifacts != .array or local_artifacts.array.items.len != 0)
        return error.LocalArtifactsPresent;

    const repositories_val = lock.get("repositories") orelse return error.InvalidRepositoryCount;
    if (repositories_val != .array or repositories_val.array.items.len != 1 or repositories_val.array.items[0] != .object)
        return error.InvalidRepositoryCount;
    const repository = repositories_val.array.items[0].object;

    const signers = repository.get("signer_fingerprints") orelse return error.SignerFingerprintMismatch;
    if (signers != .array or signers.array.items.len != 1 or signers.array.items[0] != .string or
        !std.mem.eql(u8, signers.array.items[0].string, pin.signer.primary_fingerprint))
        return error.SignerFingerprintMismatch;

    const binding = getStringField(repository, "archive_binding") orelse return error.ArchiveBindingMismatch;
    if (!std.mem.eql(u8, binding, archive_binding)) return error.ArchiveBindingMismatch;

    const expected_index = (try pin.index(architecture)).index_sha256;
    const index_id_val = repository.get("index_identity") orelse return error.IndexIdentityMismatch;
    if (index_id_val != .object or index_id_val.object.count() != 2) return error.IndexIdentityMismatch;
    const idx_primary = getStringField(index_id_val.object, "primary") orelse return error.IndexIdentityMismatch;
    const idx_digests = index_id_val.object.get("digests") orelse return error.IndexIdentityMismatch;
    if (!std.mem.eql(u8, idx_primary, "sha256") or idx_digests != .array or idx_digests.array.items.len != 1 or idx_digests.array.items[0] != .object)
        return error.IndexIdentityMismatch;
    const idx_digest_obj = idx_digests.array.items[0].object;
    if (idx_digest_obj.count() != 2 or
        !std.mem.eql(u8, getStringField(idx_digest_obj, "algorithm") orelse "", "sha256") or
        !std.mem.eql(u8, getStringField(idx_digest_obj, "digest") orelse "", expected_index))
        return error.IndexIdentityMismatch;

    inline for (.{ "id", "snapshot_sha256", "release_sha256" }) |field| {
        const val = getStringField(repository, field) orelse return error.MalformedRepositoryDigest;
        if (!isHexLen(val, 64)) return error.MalformedRepositoryDigest;
    }
    const repo_id = getStringField(repository, "id").?;
    const repo_snap = getStringField(repository, "snapshot_sha256").?;

    const packages_val = lock.get("packages") orelse return error.PackageCountOutOfBounds;
    if (packages_val != .array or packages_val.array.items.len == 0 or packages_val.array.items.len > max_packages_per_lock)
        return error.PackageCountOutOfBounds;

    var prev_name: ?[]const u8 = null;
    var requested_count: usize = 0;
    var requested_matches = false;
    var total_bytes: u64 = 0;

    for (packages_val.array.items) |pkg_val| {
        if (pkg_val != .object) return error.InvalidPackageEntry;
        const pkg = pkg_val.object;
        const name = getStringField(pkg, "name") orelse return error.InvalidPackageEntry;
        if (prev_name) |prev| {
            if (std.mem.order(u8, prev, name) != .lt) return error.PackagesNotCanonicallyOrdered;
        }
        prev_name = name;

        if (getStringField(pkg, "retention")) |ret| {
            if (std.mem.eql(u8, ret, "requested")) {
                requested_count += 1;
                if (std.mem.eql(u8, name, request)) requested_matches = true;
            }
        }

        const pkg_arch = getStringField(pkg, "architecture") orelse return error.ForeignPackageArchitecture;
        if (!std.mem.eql(u8, pkg_arch, architecture) and !std.mem.eql(u8, pkg_arch, "all"))
            return error.ForeignPackageArchitecture;

        const origin_val = pkg.get("origin") orelse return error.OriginMismatch;
        if (origin_val != .object or origin_val.object.count() != 3 or
            !std.mem.eql(u8, getStringField(origin_val.object, "type") orelse "", "authenticated_repository") or
            !std.mem.eql(u8, getStringField(origin_val.object, "repository_id") orelse "", repo_id) or
            !std.mem.eql(u8, getStringField(origin_val.object, "repository_snapshot_sha256") orelse "", repo_snap))
            return error.OriginMismatch;

        const identity_val = pkg.get("archive_identity") orelse return error.ArchiveIdentityMismatch;
        if (identity_val != .object or identity_val.object.count() != 2 or
            !std.mem.eql(u8, getStringField(identity_val.object, "primary") orelse "", "sha256"))
            return error.ArchiveIdentityMismatch;
        const digests_val = identity_val.object.get("digests") orelse return error.ArchiveIdentityMismatch;
        if (digests_val != .array or digests_val.array.items.len != 1 or digests_val.array.items[0] != .object)
            return error.ArchiveIdentityMismatch;
        const d0 = digests_val.array.items[0].object;
        if (d0.count() != 2 or
            !std.mem.eql(u8, getStringField(d0, "algorithm") orelse "", "sha256") or
            !isHexLen(getStringField(d0, "digest") orelse "", 64))
            return error.ArchiveIdentityMismatch;

        const derived_val = pkg.get("derived_archive_identity") orelse return error.DerivedProvenanceMismatch;
        if (derived_val != .object or derived_val.object.count() != 3 or
            !std.mem.eql(u8, getStringField(derived_val.object, "provenance") orelse "", derived_provenance) or
            !std.mem.eql(u8, getStringField(derived_val.object, "algorithm") orelse "", "sha512") or
            !isHexLen(getStringField(derived_val.object, "digest") orelse "", 128))
            return error.DerivedProvenanceMismatch;

        const size_val = pkg.get("declared_size") orelse return error.MalformedDeclaredSize;
        if (size_val != .integer or size_val.integer <= 0) return error.MalformedDeclaredSize;
        total_bytes = std.math.add(u64, total_bytes, @intCast(size_val.integer)) catch return error.LockBytesExceedBound;
    }

    if (requested_count != 1 or !requested_matches) return error.RequestedPackageMismatch;
    if (total_bytes > max_bytes_per_lock) return error.LockBytesExceedBound;
    return .{ .packages = packages_val.array.items.len, .total_bytes = total_bytes };
}

const SignedRecord = struct {
    filename: []const u8,
    size: u64,
    sha256: []const u8,
};

fn recordKey(allocator: std.mem.Allocator, name: []const u8, version: []const u8, arch: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}\x00{s}\x00{s}", .{ name, version, arch });
}

fn signedRecords(
    io: std.Io,
    allocator: std.mem.Allocator,
    readiness: []const u8,
    compressed: []const u8,
    index: Index,
) !std.StringArrayHashMapUnmanaged(SignedRecord) {
    _ = try readinessIndexCounts(io, allocator, readiness, compressed, index);
    const decompressed = try debz.metadata_decompression.decompress(allocator, .xz, compressed, .{
        .maximum_compressed_bytes = maximum_index_bytes,
        .maximum_decompressed_bytes = maximum_packages_bytes,
        .maximum_decoder_memory = 256 * 1024 * 1024,
    });
    var records: std.StringArrayHashMapUnmanaged(SignedRecord) = .empty;
    var paragraphs = std.mem.splitSequence(u8, decompressed, "\n\n");
    while (paragraphs.next()) |paragraph| {
        if (!std.mem.startsWith(u8, paragraph, "Package: ")) continue;
        var pkg_name: ?[]const u8 = null;
        var pkg_version: ?[]const u8 = null;
        var pkg_arch: ?[]const u8 = null;
        var filename: ?[]const u8 = null;
        var size_str: ?[]const u8 = null;
        var sha256_str: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, paragraph, '\n');
        while (lines.next()) |line| {
            if (line.len == 0 or line[0] == ' ' or line[0] == '\t') continue;
            const sep = std.mem.indexOf(u8, line, ": ") orelse continue;
            const field = line[0..sep];
            const val = line[sep + 2 ..];
            if (std.mem.eql(u8, field, "Package")) pkg_name = val else if (std.mem.eql(u8, field, "Version")) pkg_version = val else if (std.mem.eql(u8, field, "Architecture")) pkg_arch = val else if (std.mem.eql(u8, field, "Filename")) filename = val else if (std.mem.eql(u8, field, "Size")) size_str = val else if (std.mem.eql(u8, field, "SHA256")) sha256_str = val;
        }
        const key = try recordKey(
            allocator,
            pkg_name orelse return error.IncompleteSignedRecord,
            pkg_version orelse return error.IncompleteSignedRecord,
            pkg_arch orelse return error.IncompleteSignedRecord,
        );
        const gop = try records.getOrPut(allocator, key);
        if (gop.found_existing) return error.DuplicateSignedRecord;
        gop.value_ptr.* = .{
            .filename = filename orelse return error.IncompleteSignedRecord,
            .size = try std.fmt.parseInt(u64, size_str orelse return error.IncompleteSignedRecord, 10),
            .sha256 = sha256_str orelse return error.IncompleteSignedRecord,
        };
    }
    return records;
}

fn matchSigned(
    allocator: std.mem.Allocator,
    lock_val: std.json.Value,
    records: std.StringArrayHashMapUnmanaged(SignedRecord),
) ![][]const u8 {
    const packages = lock_val.object.get("packages").?.array.items;
    const matched = try allocator.alloc([]const u8, packages.len);
    for (packages, 0..) |pkg_val, idx| {
        const pkg = pkg_val.object;
        const name = getStringField(pkg, "name") orelse return error.InvalidPackageEntry;
        const version = getStringField(pkg, "version") orelse return error.InvalidPackageEntry;
        const arch = getStringField(pkg, "architecture") orelse return error.InvalidPackageEntry;
        const key = try recordKey(allocator, name, version, arch);
        const record = records.get(key) orelse return error.PackageAbsentFromSignedIndex;
        const lock_digest = getStringField(
            pkg.get("archive_identity").?.object.get("digests").?.array.items[0].object,
            "digest",
        ).?;
        const declared_size: u64 = @intCast(pkg.get("declared_size").?.integer);
        if (!std.mem.eql(u8, record.sha256, lock_digest) or record.size != declared_size)
            return error.LockIdentityMismatch;
        if (!std.mem.startsWith(u8, record.filename, "pool/"))
            return error.FilenameOutsidePool;
        matched[idx] = record.filename;
    }
    return matched;
}

fn sourceBytes(allocator: std.mem.Allocator, pin: Pin, architecture: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "Types: deb\nURIs: {s}\nSuites: {s}\nComponents: {s}\nArchitectures: {s}\nSigned-By: {s}\n",
        .{ pin.snapshot_uri, pin.suite, pin.component, architecture, keyring_path },
    );
}

fn isPermittedRetryLine(line: []const u8) bool {
    const prefix = "debz acquisition retry failed_attempt=";
    if (!std.mem.startsWith(u8, line, prefix)) return false;
    var rest = line[prefix.len..];
    if (rest.len < 3 or rest[0] < '1' or rest[0] > '6' or !std.mem.startsWith(u8, rest[1..], "/6 delay_ms="))
        return false;
    rest = rest[1 + "/6 delay_ms=".len ..];
    if (rest.len == 0 or rest[0] < '1' or rest[0] > '9') return false;
    var digits: usize = 0;
    while (digits < rest.len and std.ascii.isDigit(rest[digits])) : (digits += 1) {}
    if (digits == 0 or digits > 6 or digits >= rest.len or rest[digits] != ' ') return false;
    rest = rest[digits + 1 ..];
    if (std.mem.startsWith(u8, rest, "http_status=")) {
        const status = rest["http_status=".len..];
        return std.mem.eql(u8, status, "429") or
            std.mem.eql(u8, status, "500") or
            std.mem.eql(u8, status, "502") or
            std.mem.eql(u8, status, "503") or
            std.mem.eql(u8, status, "504");
    }
    if (std.mem.startsWith(u8, rest, "error=")) {
        const err_name = rest["error=".len..];
        if (err_name.len == 0 or err_name.len > 64 or !std.ascii.isUpper(err_name[0])) return false;
        for (err_name[1..]) |ch| {
            if (!std.ascii.isAlphabetic(ch)) return false;
        }
        return true;
    }
    return false;
}

fn newWorkspace(io: std.Io, allocator: std.mem.Allocator, requested_path: []const u8) ![]u8 {
    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    const workspace = if (std.fs.path.isAbsolute(requested_path))
        try allocator.dupe(u8, requested_path)
    else
        try std.fs.path.join(allocator, &.{ cwd, requested_path });
    if (std.mem.indexOf(u8, workspace, "/../") != null or std.mem.indexOf(u8, workspace, "/./") != null)
        return error.WorkspaceMustBeNewDirectChildOfScratch;

    const checkout = try std.Io.Dir.cwd().realPathFileAlloc(io, options.repository, allocator);
    var checkout_root = try fs.openAbsoluteRoot(io, checkout);
    defer checkout_root.close();
    if (try checkout_root.root.entryIfExists(try fs.Path.init(".tmp"))) |entry| {
        if (!entry.isDirectory()) return error.WorkspaceMustBeNewDirectChildOfScratch;
    } else {
        try checkout_root.root.createDirectory(try fs.Path.init(".tmp"), .fromMode(0o700));
    }
    const scratch = try std.fs.path.join(allocator, &.{ checkout, ".tmp" });
    const scratch_stx = try lstatPath(allocator, scratch);
    if ((scratch_stx.mode & linux.S.IFMT) == linux.S.IFLNK) return error.WorkspaceMustBeNewDirectChildOfScratch;

    const parent = std.fs.path.dirname(workspace) orelse return error.WorkspaceMustBeNewDirectChildOfScratch;
    const resolved_parent = std.Io.Dir.cwd().realPathFileAlloc(io, parent, allocator) catch return error.WorkspaceMustBeNewDirectChildOfScratch;
    const resolved_scratch = try std.Io.Dir.cwd().realPathFileAlloc(io, scratch, allocator);
    if (!std.mem.eql(u8, resolved_parent, resolved_scratch))
        return error.WorkspaceMustBeNewDirectChildOfScratch;

    const leaf = std.fs.path.basename(workspace);
    if (leaf.len == 0 or std.mem.eql(u8, leaf, ".") or std.mem.eql(u8, leaf, ".."))
        return error.WorkspaceMustBeNewDirectChildOfScratch;

    var scratch_root = try fs.openAbsoluteRoot(io, resolved_scratch);
    defer scratch_root.close();
    if (try scratch_root.root.entryIfExists(try fs.Path.init(leaf)) != null)
        return error.WorkspaceMustBeNewDirectChildOfScratch;

    try scratch_root.root.createDirectory(try fs.Path.init(leaf), .fromMode(0o700));
    const canonical_workspace = try std.fs.path.join(allocator, &.{ resolved_scratch, leaf });
    var workspace_root = try fs.openAbsoluteRoot(io, canonical_workspace);
    defer workspace_root.close();
    for ([_][]const u8{ "root", "cache", "state", "evidence" }) |subdir| {
        try workspace_root.root.createDirectory(try fs.Path.init(subdir), .fromMode(0o700));
    }
    return canonical_workspace;
}

fn writeCanonicalValue(writer: anytype, value: std.json.Value, indent: usize) !void {
    switch (value) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.writeAll(if (b) "true" else "false"),
        .integer => |i| try writer.print("{d}", .{i}),
        .float => |f| try writer.print("{d}", .{f}),
        .number_string => |s| try writer.writeAll(s),
        .string => |s| {
            try writer.writeByte('"');
            for (s) |ch| {
                switch (ch) {
                    '"' => try writer.writeAll("\\\""),
                    '\\' => try writer.writeAll("\\\\"),
                    '\x08' => try writer.writeAll("\\b"),
                    '\x0c' => try writer.writeAll("\\f"),
                    '\n' => try writer.writeAll("\\n"),
                    '\r' => try writer.writeAll("\\r"),
                    '\t' => try writer.writeAll("\\t"),
                    else => {
                        if (ch < 0x20) {
                            try writer.print("\\u{x:0>4}", .{ch});
                        } else {
                            try writer.writeByte(ch);
                        }
                    },
                }
            }
            try writer.writeByte('"');
        },
        .array => |arr| {
            if (arr.items.len == 0) {
                try writer.writeAll("[]");
                return;
            }
            try writer.writeAll("[\n");
            for (arr.items, 0..) |item, idx| {
                try writer.writeByteNTimes(' ', (indent + 1) * 2);
                try writeCanonicalValue(writer, item, indent + 1);
                if (idx + 1 < arr.items.len) try writer.writeByte(',');
                try writer.writeByte('\n');
            }
            try writer.writeByteNTimes(' ', indent * 2);
            try writer.writeByte(']');
        },
        .object => |obj| {
            if (obj.count() == 0) {
                try writer.writeAll("{}");
                return;
            }
            const allocator = writer.alloc;
            const keys = try allocator.alloc([]const u8, obj.count());
            defer allocator.free(keys);
            for (obj.keys(), 0..) |k, idx| keys[idx] = k;
            std.mem.sort([]const u8, keys, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.order(u8, a, b) == .lt;
                }
            }.lessThan);
            try writer.writeAll("{\n");
            for (keys, 0..) |k, idx| {
                try writer.writeByteNTimes(' ', (indent + 1) * 2);
                try writeCanonicalValue(writer, .{ .string = k }, indent + 1);
                try writer.writeAll(": ");
                try writeCanonicalValue(writer, obj.get(k).?, indent + 1);
                if (idx + 1 < keys.len) try writer.writeByte(',');
                try writer.writeByte('\n');
            }
            try writer.writeByteNTimes(' ', indent * 2);
            try writer.writeByte('}');
        },
    }
}

fn canonicalJsonAlloc(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const Writer = struct {
        list: *std.ArrayList(u8),
        alloc: std.mem.Allocator,
        pub fn writeAll(self: @This(), bytes: []const u8) !void {
            try self.list.appendSlice(self.alloc, bytes);
        }
        pub fn writeByte(self: @This(), byte: u8) !void {
            try self.list.append(self.alloc, byte);
        }
        pub fn writeByteNTimes(self: @This(), byte: u8, n: usize) !void {
            try self.list.appendNTimes(self.alloc, byte, n);
        }
        pub fn print(self: @This(), comptime fmt: []const u8, args: anytype) !void {
            const slice = try std.fmt.allocPrint(self.alloc, fmt, args);
            defer self.alloc.free(slice);
            try self.list.appendSlice(self.alloc, slice);
        }
    };
    try writeCanonicalValue(Writer{ .list = &out, .alloc = allocator }, value, 0);
    try out.append(allocator, '\n');
    return out.toOwnedSlice(allocator);
}

fn writeFile(io: std.Io, dir_path: []const u8, rel_path: []const u8, bytes: []const u8, mode: u32) !void {
    var root = try fs.openAbsoluteRoot(io, dir_path);
    defer root.close();
    var parent = try root.root.openParent(try fs.Path.init(rel_path));
    defer parent.close(io);
    parent.dir.deleteFile(io, parent.leaf) catch {};
    const file = try parent.dir.createFile(io, parent.leaf, .{
        .exclusive = true,
        .permissions = .fromMode(mode),
        .resolve_beneath = true,
    });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn compareRuns(io: std.Io, allocator: std.mem.Allocator, first_workspace: []const u8, second_workspace: []const u8) !std.json.Value {
    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    const first_abs = if (std.fs.path.isAbsolute(first_workspace)) first_workspace else try std.fs.path.join(allocator, &.{ cwd, first_workspace });
    const second_abs = if (std.fs.path.isAbsolute(second_workspace)) second_workspace else try std.fs.path.join(allocator, &.{ cwd, second_workspace });
    const left_dir = try std.fs.path.join(allocator, &.{ first_abs, "evidence" });
    const right_dir = try std.fs.path.join(allocator, &.{ second_abs, "evidence" });

    const left_closure_raw = try readRegularFileAlloc(io, allocator, try std.fs.path.join(allocator, &.{ left_dir, "closure.json" }), maximum_json_bytes);
    const right_closure_raw = try readRegularFileAlloc(io, allocator, try std.fs.path.join(allocator, &.{ right_dir, "closure.json" }), maximum_json_bytes);
    const left_parsed = try std.json.parseFromSlice(std.json.Value, allocator, left_closure_raw, .{});
    const right_parsed = try std.json.parseFromSlice(std.json.Value, allocator, right_closure_raw, .{});
    const left_canonical = try canonicalJsonAlloc(allocator, left_parsed.value);
    const right_canonical = try canonicalJsonAlloc(allocator, right_parsed.value);
    if (!std.mem.eql(u8, left_canonical, right_canonical)) return error.RunEvidenceDiffers;

    for ([_][]const u8{ "apt.lock.json", "systemd-sysv.lock.json", "cas.json", "inventory.json" }) |name| {
        const left_bytes = try readRegularFileAlloc(io, allocator, try std.fs.path.join(allocator, &.{ left_dir, name }), maximum_json_bytes);
        const right_bytes = try readRegularFileAlloc(io, allocator, try std.fs.path.join(allocator, &.{ right_dir, name }), maximum_json_bytes);
        if (!std.mem.eql(u8, left_bytes, right_bytes)) return error.RunArtifactDiffers;
    }
    return left_parsed.value;
}

const AggregatedGap = struct {
    priority: []const u8,
    category: []const u8,
    native_status: []const u8,
    packages: std.StringArrayHashMapUnmanaged(std.ArrayList([]const u8)),
    evidence: std.ArrayList([]const u8),
};

fn appendUniqueString(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8), item: []const u8) !void {
    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, item)) return;
    }
    try list.append(allocator, item);
}

fn aggregateGaps(allocator: std.mem.Allocator, inventories: std.json.ObjectMap) !std.json.Value {
    const arch_keys = try allocator.alloc([]const u8, inventories.count());
    for (inventories.keys(), 0..) |k, idx| arch_keys[idx] = k;
    std.mem.sort([]const u8, arch_keys, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    var entries: std.StringArrayHashMapUnmanaged(AggregatedGap) = .empty;
    for (arch_keys) |arch| {
        const inv = inventories.get(arch).?.object;
        const packages = inv.get("packages").?.array.items;
        for (packages) |pkg_val| {
            const pkg = pkg_val.object;
            const pkg_name = pkg.get("package").?.string;
            const gaps = pkg.get("gaps").?.array.items;
            for (gaps) |gap_val| {
                const gap = gap_val.object;
                const category = gap.get("category").?.string;
                const priority = gap.get("priority").?.string;
                const status = try categoryStatus(category);
                const gop = try entries.getOrPut(allocator, category);
                if (!gop.found_existing) {
                    gop.value_ptr.* = .{
                        .priority = priority,
                        .category = category,
                        .native_status = status,
                        .packages = .empty,
                        .evidence = .empty,
                    };
                } else if (!std.mem.eql(u8, gop.value_ptr.priority, priority)) {
                    return error.InconsistentGapPriority;
                }
                const arch_gop = try gop.value_ptr.packages.getOrPut(allocator, arch);
                if (!arch_gop.found_existing) arch_gop.value_ptr.* = .empty;
                try arch_gop.value_ptr.append(allocator, pkg_name);
                for (gap.get("evidence").?.array.items) |ev_val| {
                    const formatted = try std.fmt.allocPrint(allocator, "{s} {s}", .{ pkg_name, ev_val.string });
                    try appendUniqueString(allocator, &gop.value_ptr.evidence, formatted);
                }
            }
        }
    }

    const ordered_entries = try allocator.alloc(AggregatedGap, entries.count());
    for (entries.values(), 0..) |v, idx| ordered_entries[idx] = v;
    std.mem.sort(AggregatedGap, ordered_entries, {}, struct {
        fn lessThan(_: void, a: AggregatedGap, b: AggregatedGap) bool {
            const p = std.mem.order(u8, a.priority, b.priority);
            if (p != .eq) return p == .lt;
            return std.mem.order(u8, a.category, b.category) == .lt;
        }
    }.lessThan);

    var out_array = std.json.Array.init(allocator);
    for (ordered_entries) |*entry| {
        std.mem.sort([]const u8, entry.evidence.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lessThan);

        var pkgs_obj: std.json.ObjectMap = .empty;
        for (entry.packages.keys()) |arch| {
            const list = entry.packages.getPtr(arch).?;
            std.mem.sort([]const u8, list.items, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.order(u8, a, b) == .lt;
                }
            }.lessThan);
            var arch_arr = std.json.Array.init(allocator);
            for (list.items) |name| try arch_arr.append(.{ .string = name });
            try pkgs_obj.put(allocator, arch, .{ .array = arch_arr });
        }

        var ev_arr = std.json.Array.init(allocator);
        for (entry.evidence.items) |ev| try ev_arr.append(.{ .string = ev });

        var gap_obj: std.json.ObjectMap = .empty;
        try gap_obj.put(allocator, "category", .{ .string = entry.category });
        try gap_obj.put(allocator, "evidence", .{ .array = ev_arr });
        try gap_obj.put(allocator, "native_status", .{ .string = entry.native_status });
        try gap_obj.put(allocator, "packages", .{ .object = pkgs_obj });
        try gap_obj.put(allocator, "priority", .{ .string = entry.priority });
        try out_array.append(.{ .object = gap_obj });
    }
    return .{ .array = out_array };
}

fn checkEvidence(io: std.Io, allocator: std.mem.Allocator, directory: []const u8) !std.json.Value {
    const pin = try loadPin(allocator);
    const evidence_path = try std.fs.path.join(allocator, &.{ directory, "evidence.json" });
    const raw_evidence = try readRegularFileAlloc(io, allocator, evidence_path, maximum_json_bytes);
    const parsed_doc = try std.json.parseFromSlice(std.json.Value, allocator, raw_evidence, .{});
    const document = parsed_doc.value.object;

    const expected_pin_sha = sha256Hex(pin_bytes);
    if (!std.mem.eql(u8, getStringField(document, "schema") orelse "", evidence_schema) or
        !std.mem.eql(u8, getStringField(document, "pin_sha256") orelse "", &expected_pin_sha))
        return error.UnboundClosureEvidence;

    const reqs = document.get("requests") orelse return error.ClosureRequestsOrKeyringChanged;
    const keyring_obj = document.get("keyring") orelse return error.ClosureRequestsOrKeyringChanged;
    if (reqs != .array or reqs.array.items.len != requests.len or
        !std.mem.eql(u8, reqs.array.items[0].string, requests[0]) or
        !std.mem.eql(u8, reqs.array.items[1].string, requests[1]) or
        keyring_obj != .object or
        !std.mem.eql(u8, getStringField(keyring_obj.object, "path") orelse "", keyring_path))
        return error.ClosureRequestsOrKeyringChanged;

    const freshness = document.get("freshness").?.object;
    const expected_expiry = try formatIsoUtc(allocator, try releaseExpiry(pin));
    if (!std.mem.eql(u8, getStringField(freshness, "expires_at") orelse "", expected_expiry))
        return error.FreshnessExpiryMismatch;

    var inventories: std.json.ObjectMap = .empty;
    const archs_obj = document.get("architectures").?.object;
    for (architectures) |architecture| {
        const entry = archs_obj.get(architecture).?.object;
        const expected_source_sha = sha256Hex(try sourceBytes(allocator, pin, architecture));
        if (!std.mem.eql(u8, getStringField(entry, "source_sha256") orelse "", &expected_source_sha))
            return error.RecordedSourceMismatch;

        const runs = entry.get("runs").?.array.items;
        if (runs.len != 2 or std.mem.eql(u8, runs[0].string, runs[1].string))
            return error.RequiresTwoDistinctCleanRuns;

        var cas_map: std.StringArrayHashMapUnmanaged(std.json.ObjectMap) = .empty;
        var cas_bytes_sum: u64 = 0;
        for (entry.get("cas").?.array.items) |row_val| {
            const row = row_val.object;
            try cas_map.put(allocator, row.get("package").?.string, row);
            cas_bytes_sum += @intCast(row.get("size").?.integer);
        }

        var seen: std.StringArrayHashMapUnmanaged(void) = .empty;
        const locks_obj = entry.get("locks").?.object;
        const repo_id = entry.get("repository").?.object.get("id").?.string;

        for (requests) |request| {
            const item = locks_obj.get(request).?.object;
            const rel_lock = item.get("path").?.string;
            const raw_lock = try readRegularFileAlloc(
                io,
                allocator,
                try std.fs.path.join(allocator, &.{ directory, rel_lock }),
                maximum_json_bytes,
            );
            const actual_lock_sha = sha256Hex(raw_lock);
            if (!std.mem.eql(u8, &actual_lock_sha, item.get("file_sha256").?.string))
                return error.CommittedLockBytesChanged;

            const lock_parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_lock, .{});
            const lock = lock_parsed.value.object;
            if (!std.mem.eql(u8, lock.get("digest_sha256").?.string, item.get("digest_sha256").?.string))
                return error.LockDigestChanged;

            const reviewed = try reviewLock(lock_parsed.value, pin, architecture, request);
            if (reviewed.packages != @as(usize, @intCast(item.get("packages").?.integer)) or
                reviewed.total_bytes != @as(u64, @intCast(item.get("total_bytes").?.integer)))
                return error.LockBoundsChanged;

            const lock_repo_id = lock.get("repositories").?.array.items[0].object.get("id").?.string;
            if (!std.mem.eql(u8, lock_repo_id, repo_id)) return error.RepositoryIdentityChanged;

            for (lock.get("packages").?.array.items) |pkg_val| {
                const pkg = pkg_val.object;
                const pkg_name = pkg.get("name").?.string;
                const row = cas_map.get(pkg_name) orelse return error.CasEvidenceDiffersFromLock;
                const lock_sha256 = pkg.get("archive_identity").?.object.get("digests").?.array.items[0].object.get("digest").?.string;
                const lock_sha512 = pkg.get("derived_archive_identity").?.object.get("digest").?.string;
                if (!std.mem.eql(u8, row.get("version").?.string, pkg.get("version").?.string) or
                    row.get("size").?.integer != pkg.get("declared_size").?.integer or
                    !std.mem.eql(u8, row.get("sha256").?.string, lock_sha256) or
                    !std.mem.eql(u8, row.get("derived_sha512").?.string, lock_sha512))
                    return error.CasEvidenceDiffersFromLock;
                try seen.put(allocator, pkg_name, {});
            }
        }

        if (seen.count() != cas_map.count() or
            @as(usize, @intCast(entry.get("cas_objects").?.integer)) != cas_map.count() or
            @as(u64, @intCast(entry.get("cas_bytes").?.integer)) != cas_bytes_sum)
            return error.CasEvidenceNotExactLockUnion;

        const inv_meta = entry.get("inventory").?.object;
        const raw_inv = try readRegularFileAlloc(
            io,
            allocator,
            try std.fs.path.join(allocator, &.{ directory, inv_meta.get("path").?.string }),
            maximum_json_bytes,
        );
        const actual_inv_sha = sha256Hex(raw_inv);
        if (!std.mem.eql(u8, &actual_inv_sha, inv_meta.get("sha256").?.string))
            return error.CommittedInventoryBytesChanged;

        const inv_parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_inv, .{});
        const inv = inv_parsed.value.object;
        if (!std.mem.eql(u8, getStringField(inv, "schema") orelse "", inventory_schema))
            return error.InventoryCoverageMismatch;
        const inv_pkgs = inv.get("packages").?.array.items;
        if (inv_pkgs.len != cas_map.count()) return error.InventoryCoverageMismatch;
        for (inv_pkgs, cas_map.keys()) |pkg_val, cas_key| {
            const pkg = pkg_val.object;
            const pkg_name = pkg.get("package").?.string;
            if (!std.mem.eql(u8, pkg_name, cas_key)) return error.InventoryCoverageMismatch;
            const row = cas_map.get(pkg_name).?;
            if (!std.mem.eql(u8, pkg.get("sha256").?.string, row.get("sha256").?.string) or
                !std.mem.eql(u8, pkg.get("derived_sha512").?.string, row.get("derived_sha512").?.string) or
                pkg.get("size").?.integer != row.get("size").?.integer)
                return error.InventoryIdentityDiffersFromCas;
        }
        const inv_summary_canon = try canonicalJsonAlloc(allocator, inv.get("summary").?);
        const entry_summary_canon = try canonicalJsonAlloc(allocator, inv_meta.get("summary").?);
        if (!std.mem.eql(u8, inv_summary_canon, entry_summary_canon))
            return error.InventorySummaryChanged;
        try inventories.put(allocator, architecture, inv_parsed.value);
    }

    const expected_gaps = try aggregateGaps(allocator, inventories);
    const expected_gaps_canon = try canonicalJsonAlloc(allocator, expected_gaps);
    const actual_gaps_canon = try canonicalJsonAlloc(allocator, document.get("gaps").?);
    if (!std.mem.eql(u8, expected_gaps_canon, actual_gaps_canon))
        return error.GapListNotDerivedFromInventories;

    return parsed_doc.value;
}

const RunOptions = struct {
    debz_path: []const u8,
    inventory_path: []const u8,
    architecture: []const u8,
    workspace_path: []const u8,
};

const LocatedObject = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    object: []const u8,
    mode: []const u8,
    size: u64,
    sha256: []const u8,
    derived_sha512: []const u8,
};

fn findArchiveRecursive(
    io: std.Io,
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    rel_prefix: []const u8,
    target_name: []const u8,
    found: *std.ArrayList([]const u8),
) !void {
    const current_abs = if (rel_prefix.len == 0) base_dir else try std.fs.path.join(allocator, &.{ base_dir, rel_prefix });
    var root = try fs.openAbsoluteRoot(io, current_abs);
    defer root.close();
    var dir = try root.root.openDirectory(try fs.Path.init("."));
    defer dir.close(io);
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        const child_rel = if (rel_prefix.len == 0)
            try allocator.dupe(u8, entry.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rel_prefix, entry.name });
        const child_abs = try std.fs.path.join(allocator, &.{ base_dir, child_rel });
        const stx = try lstatPath(allocator, child_abs);
        const ftype = stx.mode & linux.S.IFMT;
        if (ftype == linux.S.IFLNK) continue;
        if (ftype == linux.S.IFDIR) {
            try findArchiveRecursive(io, allocator, base_dir, child_rel, target_name, found);
        } else if (ftype == linux.S.IFREG and std.mem.eql(u8, entry.name, target_name)) {
            try found.append(allocator, child_rel);
        }
    }
}

fn locateObjects(
    io: std.Io,
    allocator: std.mem.Allocator,
    cache_path: []const u8,
    packages: []const std.json.Value,
) !struct { rows: []LocatedObject, object_dir: []const u8 } {
    const rows = try allocator.alloc(LocatedObject, packages.len);
    var object_dir: ?[]const u8 = null;
    for (packages, 0..) |pkg_val, idx| {
        const pkg = pkg_val.object;
        const identity = pkg.get("archive_identity").?.object;
        const primary = identity.get("primary").?.string;
        const digest = identity.get("digests").?.array.items[0].object.get("digest").?.string;
        const target_name = try std.fmt.allocPrint(allocator, "{s}-{s}", .{ primary, digest });

        var matches: std.ArrayList([]const u8) = .empty;
        try findArchiveRecursive(io, allocator, cache_path, "", target_name, &matches);
        if (matches.items.len != 1) return error.CachedArchiveMissingOrAmbiguous;
        const rel_object = matches.items[0];
        const abs_object = try std.fs.path.join(allocator, &.{ cache_path, rel_object });
        const parent_dir = std.fs.path.dirname(abs_object) orelse return error.CachedArchiveMissingOrAmbiguous;
        if (object_dir) |existing| {
            if (!std.mem.eql(u8, existing, parent_dir)) return error.MultipleObjectDirectories;
        } else {
            object_dir = try allocator.dupe(u8, parent_dir);
        }

        const stx = try lstatPath(allocator, abs_object);
        const data = try readRegularFileAlloc(io, allocator, abs_object, maximum_archive_bytes);
        const actual_sha256 = sha256Hex(data);
        const actual_sha512 = sha512Hex(data);
        const declared_size: u64 = @intCast(pkg.get("declared_size").?.integer);
        const expected_sha512 = pkg.get("derived_archive_identity").?.object.get("digest").?.string;
        if (data.len != declared_size or
            !std.mem.eql(u8, &actual_sha256, digest) or
            !std.mem.eql(u8, &actual_sha512, expected_sha512))
            return error.CachedArchiveIdentityMismatch;

        rows[idx] = .{
            .package = pkg.get("name").?.string,
            .version = pkg.get("version").?.string,
            .architecture = pkg.get("architecture").?.string,
            .object = rel_object,
            .mode = try std.fmt.allocPrint(allocator, "{o:0>4}", .{stx.mode & 0o7777}),
            .size = data.len,
            .sha256 = try allocator.dupe(u8, &actual_sha256),
            .derived_sha512 = try allocator.dupe(u8, &actual_sha512),
        };
    }
    return .{ .rows = rows, .object_dir = object_dir orelse return error.MultipleObjectDirectories };
}

fn runDebzCommand(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    evidence_dir: []const u8,
    name: []const u8,
) !void {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .timeout = .{ .duration = .{ .raw = .fromSeconds(1800), .clock = .awake } },
        .stdout_limit = .limited(maximum_json_bytes),
        .stderr_limit = .limited(maximum_json_bytes),
    });
    try writeFile(io, evidence_dir, try std.fmt.allocPrint(allocator, "{s}.json", .{name}), result.stdout, 0o600);
    try writeFile(io, evidence_dir, try std.fmt.allocPrint(allocator, "{s}.stderr", .{name}), result.stderr, 0o600);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, result.stderr, "\r\n"), '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (!isPermittedRetryLine(line)) return error.DebzCommandRefused;
    }
    if (result.term != .exited or result.term.exited != 0) return error.DebzCommandRefused;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    if (parsed.value != .object or
        (parsed.value.object.get("exit_status") orelse return error.DebzCommandRefused) != .integer or
        parsed.value.object.get("exit_status").?.integer != 0)
        return error.DebzCommandRefused;
}

fn requireEmptyDirectory(io: std.Io, path: []const u8) !void {
    var root = try fs.openAbsoluteRoot(io, path);
    defer root.close();
    var dir = try root.root.openDirectory(try fs.Path.init("."));
    defer dir.close(io);
    var iter = dir.iterate();
    if (try iter.next(io) != null) return error.RootMutated;
}

fn runClosure(io: std.Io, allocator: std.mem.Allocator, opts: RunOptions, now: i64) !void {
    const pin = try loadPin(allocator);
    _ = try pin.index(opts.architecture);
    _ = try requireFresh(pin, now);

    const debz_bin = try std.Io.Dir.cwd().realPathFileAlloc(io, opts.debz_path, allocator);
    const inventory_bin = try std.Io.Dir.cwd().realPathFileAlloc(io, opts.inventory_path, allocator);
    const debz_stx = try lstatPath(allocator, debz_bin);
    const inv_stx = try lstatPath(allocator, inventory_bin);
    if ((debz_stx.mode & linux.S.IFMT) != linux.S.IFREG or (inv_stx.mode & linux.S.IFMT) != linux.S.IFREG)
        return error.ExecutableMustBeRegularFile;

    const readiness = try readinessExecutable(allocator);
    const key = try nativeReadiness(io, allocator, readiness, &.{"--check-key"}, try readinessFetch(io, allocator, readiness, "key", null));
    try verifyKeyring(io, allocator, keyring_path, key);

    const workspace = try newWorkspace(io, allocator, opts.workspace_path);
    const evidence_dir = try std.fs.path.join(allocator, &.{ workspace, "evidence" });
    const source_path = try std.fs.path.join(allocator, &.{ workspace, "debian.sources" });
    const source = try sourceBytes(allocator, pin, opts.architecture);
    try writeFile(io, workspace, "debian.sources", source, 0o600);

    const config = try std.fmt.allocPrint(
        allocator,
        "{{\"source_path\":\"{s}\",\"priority\":500,\"default_release\":\"{s}\",\"immutable\":true,\"freshness\":{{\"mode\":\"{s}\",\"maximum_release_age_seconds\":{d}}},\"archive_binding\":\"{s}\"}}\n",
        .{ source_path, pin.suite, pin.release.freshness_mode, pin.release.maximum_release_age_seconds, archive_binding },
    );
    const config_path = try std.fs.path.join(allocator, &.{ workspace, "debian.json" });
    try writeFile(io, workspace, "debian.json", config, 0o600);

    const root_path = try std.fs.path.join(allocator, &.{ workspace, "root" });
    const cache_path = try std.fs.path.join(allocator, &.{ workspace, "cache" });
    const state_path = try std.fs.path.join(allocator, &.{ workspace, "state" });
    const deadline_str = try std.fmt.allocPrint(allocator, "{d}", .{deadline_ms});

    const refresh_argv = [_][]const u8{
        debz_bin,          "refresh",        "--install-root", root_path,
        "--cache-path",    cache_path,       "--state-path",   state_path,
        "--architecture",  opts.architecture, "--config",      config_path,
        "--keyring",       keyring_path,     "--deadline-ms",  deadline_str,
        "--lock-wait-ms",  "30000",          "--json",         "--assume-yes",
    };
    try runDebzCommand(io, allocator, &refresh_argv, evidence_dir, "refresh");

    for (requests) |request| {
        const lock_out = try std.fs.path.join(allocator, &.{ evidence_dir, try std.fmt.allocPrint(allocator, "{s}.lock.json", .{request}) });
        const repro_out = try std.fs.path.join(allocator, &.{ evidence_dir, try std.fmt.allocPrint(allocator, "{s}.reproduced.lock.json", .{request}) });
        const plan_argv = [_][]const u8{
            debz_bin,                 "plan",           "--install-root", root_path,
            "--cache-path",           cache_path,       "--state-path",   state_path,
            "--architecture",         opts.architecture, "--config",      config_path,
            "--keyring",              keyring_path,     "--deadline-ms",  deadline_str,
            "--lock-wait-ms",         "30000",          "--json",         "--transaction-backend",
            "native",                 "--lock-output",  lock_out,         request,
        };
        try runDebzCommand(io, allocator, &plan_argv, evidence_dir, try std.fmt.allocPrint(allocator, "plan-{s}", .{request}));

        const repro_argv = [_][]const u8{
            debz_bin,                 "plan",           "--install-root", root_path,
            "--cache-path",           cache_path,       "--state-path",   state_path,
            "--architecture",         opts.architecture, "--config",      config_path,
            "--keyring",              keyring_path,     "--deadline-ms",  deadline_str,
            "--lock-wait-ms",         "30000",          "--json",         "--transaction-backend",
            "native",                 "--lock-input",   lock_out,         "--lock-output",
            repro_out,                request,
        };
        try runDebzCommand(io, allocator, &repro_argv, evidence_dir, try std.fmt.allocPrint(allocator, "reproduce-{s}", .{request}));

        const download_argv = [_][]const u8{
            debz_bin,                 "download",       "--install-root", root_path,
            "--cache-path",           cache_path,       "--state-path",   state_path,
            "--architecture",         opts.architecture, "--config",      config_path,
            "--keyring",              keyring_path,     "--deadline-ms",  deadline_str,
            "--lock-wait-ms",         "30000",          "--json",         "--transaction-backend",
            "native",                 "--lock-input",   lock_out,         request,
        };
        try runDebzCommand(io, allocator, &download_argv, evidence_dir, try std.fmt.allocPrint(allocator, "download-{s}", .{request}));
    }

    try requireEmptyDirectory(io, root_path);
    const armored = try readinessFetch(io, allocator, readiness, "release", opts.architecture);
    const now_text = try std.fmt.allocPrint(allocator, "{d}", .{now});
    _ = try nativeReadiness(io, allocator, readiness, &.{ "--check-release", "--architecture", opts.architecture, "--now", now_text }, armored);
    const index = try pin.index(opts.architecture);
    const records = try signedRecords(io, allocator, readiness, try readinessFetch(io, allocator, readiness, "index", opts.architecture), index);

    for (requests) |request| {
        const lock_file = try std.fs.path.join(allocator, &.{ evidence_dir, try std.fmt.allocPrint(allocator, "{s}.lock.json", .{request}) });
        const repro_file = try std.fs.path.join(allocator, &.{ evidence_dir, try std.fmt.allocPrint(allocator, "{s}.reproduced.lock.json", .{request}) });
        const raw = try readRegularFileAlloc(io, allocator, lock_file, maximum_json_bytes);
        const repro = try readRegularFileAlloc(io, allocator, repro_file, maximum_json_bytes);
        if (!std.mem.eql(u8, raw, repro)) return error.LockReproductionMismatch;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
        _ = try reviewLock(parsed.value, pin, opts.architecture, request);
        _ = try matchSigned(allocator, parsed.value, records);
        _ = try locateObjects(io, allocator, cache_path, parsed.value.object.get("packages").?.array.items);
    }
}

fn recordEvidence(
    io: std.Io,
    allocator: std.mem.Allocator,
    amd64_runs: [2][]const u8,
    arm64_runs: [2][]const u8,
    program_version: []const u8,
    source_commit: []const u8,
    recorded_on: []const u8,
) !void {
    const pin = try loadPin(allocator);
    const evidence_dir = try std.fs.path.join(allocator, &.{ options.repository, "tools/fixtures/debian-stable-closure-v1" });
    var archs_obj: std.json.ObjectMap = .empty;
    var inventories: std.json.ObjectMap = .empty;
    var program_sha: ?[]const u8 = null;
    var commands_val: ?std.json.Value = null;

    inline for (.{ .{ "amd64", amd64_runs }, .{ "arm64", arm64_runs } }) |pair| {
        const arch = pair[0];
        const runs = pair[1];
        const closure_val = try compareRuns(io, allocator, runs[0], runs[1]);
        const closure = closure_val.object;
        if (!std.mem.eql(u8, closure.get("architecture").?.string, arch)) return error.RunArchitectureMismatch;
        const prog = closure.get("program_sha256").?.string;
        if (program_sha) |existing| {
            if (!std.mem.eql(u8, existing, prog)) return error.DifferentDebzExecutables;
        } else {
            program_sha = prog;
        }
        if (commands_val) |existing| {
            const c1 = try canonicalJsonAlloc(allocator, existing);
            const c2 = try canonicalJsonAlloc(allocator, closure.get("commands").?);
            if (!std.mem.eql(u8, c1, c2)) return error.DifferentCommandTemplates;
        } else {
            commands_val = closure.get("commands").?;
        }

        const cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
        const first_abs = if (std.fs.path.isAbsolute(runs[0])) runs[0] else try std.fs.path.join(allocator, &.{ cwd, runs[0] });
        const run_evidence = try std.fs.path.join(allocator, &.{ first_abs, "evidence" });

        var locks_out: std.json.ObjectMap = .empty;
        for (requests) |request| {
            const dest_name = try std.fmt.allocPrint(allocator, "{s}-{s}.lock.json", .{ arch, request });
            const lock_bytes = try readRegularFileAlloc(
                io,
                allocator,
                try std.fs.path.join(allocator, &.{ run_evidence, try std.fmt.allocPrint(allocator, "{s}.lock.json", .{request}) }),
                maximum_json_bytes,
            );
            try writeFile(io, evidence_dir, dest_name, lock_bytes, 0o644);
            var lock_entry: std.json.ObjectMap = .empty;
            const src_lock = closure.get("locks").?.object.get(request).?.object;
            try lock_entry.put(allocator, "path", .{ .string = dest_name });
            for (src_lock.keys()) |k| try lock_entry.put(allocator, k, src_lock.get(k).?);
            try locks_out.put(allocator, request, .{ .object = lock_entry });
        }

        const inv_name = try std.fmt.allocPrint(allocator, "{s}-inventory.json", .{arch});
        const inv_bytes = try readRegularFileAlloc(io, allocator, try std.fs.path.join(allocator, &.{ run_evidence, "inventory.json" }), maximum_json_bytes);
        try writeFile(io, evidence_dir, inv_name, inv_bytes, 0o644);
        const inv_parsed = try std.json.parseFromSlice(std.json.Value, allocator, inv_bytes, .{});
        try inventories.put(allocator, arch, inv_parsed.value);

        const cas_bytes = try readRegularFileAlloc(io, allocator, try std.fs.path.join(allocator, &.{ run_evidence, "cas.json" }), maximum_json_bytes);
        const cas_parsed = try std.json.parseFromSlice(std.json.Value, allocator, cas_bytes, .{});
        var cas_arr = std.json.Array.init(allocator);
        for (cas_parsed.value.array.items) |row_val| {
            const row = row_val.object;
            var stripped: std.json.ObjectMap = .empty;
            inline for (.{ "package", "version", "architecture", "filename", "size", "sha256", "derived_sha512", "mode" }) |k| {
                try stripped.put(allocator, k, row.get(k).?);
            }
            try cas_arr.append(.{ .object = stripped });
        }

        var runs_arr = std.json.Array.init(allocator);
        try runs_arr.append(.{ .string = std.fs.path.basename(runs[0]) });
        try runs_arr.append(.{ .string = std.fs.path.basename(runs[1]) });

        var inv_obj: std.json.ObjectMap = .empty;
        try inv_obj.put(allocator, "path", .{ .string = inv_name });
        try inv_obj.put(allocator, "sha256", closure.get("inventory_sha256").?);
        try inv_obj.put(allocator, "summary", inv_parsed.value.object.get("summary").?);

        var arch_entry: std.json.ObjectMap = .empty;
        try arch_entry.put(allocator, "source_sha256", closure.get("source_sha256").?);
        try arch_entry.put(allocator, "repository", closure.get("repository").?);
        try arch_entry.put(allocator, "locks", .{ .object = locks_out });
        try arch_entry.put(allocator, "runs", .{ .array = runs_arr });
        try arch_entry.put(allocator, "cas_sha256", closure.get("cas_sha256").?);
        try arch_entry.put(allocator, "cas_objects", closure.get("cas_objects").?);
        try arch_entry.put(allocator, "cas_bytes", closure.get("cas_bytes").?);
        try arch_entry.put(allocator, "cas", .{ .array = cas_arr });
        try arch_entry.put(allocator, "inventory", .{ .object = inv_obj });
        try archs_obj.put(allocator, arch, .{ .object = arch_entry });
    }

    const expiry_iso = try formatIsoUtc(allocator, try releaseExpiry(pin));
    const pin_sha = sha256Hex(pin_bytes);
    var doc: std.json.ObjectMap = .empty;
    try doc.put(allocator, "schema", .{ .string = evidence_schema });
    try doc.put(allocator, "issue", .{ .integer = 261 });
    try doc.put(allocator, "pin_sha256", .{ .string = &pin_sha });
    var reqs_arr = std.json.Array.init(allocator);
    for (requests) |r| try reqs_arr.append(.{ .string = r });
    try doc.put(allocator, "requests", .{ .array = reqs_arr });
    var bounds_obj: std.json.ObjectMap = .empty;
    try bounds_obj.put(allocator, "max_packages_per_lock", .{ .integer = @intCast(max_packages_per_lock) });
    try bounds_obj.put(allocator, "max_bytes_per_lock", .{ .integer = @intCast(max_bytes_per_lock) });
    try doc.put(allocator, "bounds", .{ .object = bounds_obj });
    var prog_obj: std.json.ObjectMap = .empty;
    try prog_obj.put(allocator, "sha256", .{ .string = program_sha.? });
    try prog_obj.put(allocator, "version", .{ .string = program_version });
    try prog_obj.put(allocator, "optimize", .{ .string = "ReleaseSafe" });
    try prog_obj.put(allocator, "source_commit", .{ .string = source_commit });
    try doc.put(allocator, "program", .{ .object = prog_obj });
    try doc.put(allocator, "host_machine", .{ .string = @tagName(builtin.cpu.arch) });
    var kr_obj: std.json.ObjectMap = .empty;
    try kr_obj.put(allocator, "path", .{ .string = keyring_path });
    try kr_obj.put(allocator, "sha256", .{ .string = pin.signer.binary_sha256 });
    try kr_obj.put(allocator, "fingerprint", .{ .string = pin.signer.primary_fingerprint });
    try doc.put(allocator, "keyring", .{ .object = kr_obj });
    var fresh_obj: std.json.ObjectMap = .empty;
    try fresh_obj.put(allocator, "release_date", .{ .string = pin.release.date });
    try fresh_obj.put(allocator, "valid_until", if (pin.release.valid_until) |v| .{ .string = v } else .null);
    try fresh_obj.put(allocator, "mode", .{ .string = pin.release.freshness_mode });
    try fresh_obj.put(allocator, "maximum_release_age_seconds", .{ .integer = @intCast(pin.release.maximum_release_age_seconds) });
    try fresh_obj.put(allocator, "expires_at", .{ .string = expiry_iso });
    try fresh_obj.put(allocator, "recorded_on", .{ .string = recorded_on });
    try doc.put(allocator, "freshness", .{ .object = fresh_obj });
    try doc.put(allocator, "commands", commands_val.?);
    try doc.put(allocator, "architectures", .{ .object = archs_obj });
    const gaps_val = try aggregateGaps(allocator, inventories);
    try doc.put(allocator, "gaps", gaps_val);

    const out_bytes = try canonicalJsonAlloc(allocator, .{ .object = doc });
    try writeFile(io, evidence_dir, "evidence.json", out_bytes, 0o644);
    const summary = try std.fmt.allocPrint(
        allocator,
        "{{\"evidence\": \"{s}/evidence.json\", \"gaps\": {d}}}\n",
        .{ evidence_dir, gaps_val.array.items.len },
    );
    try std.Io.File.stdout().writeStreamingAll(io, summary);
}

fn execute(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const command = args.next() orelse return error.InvalidArguments;
    if (std.mem.eql(u8, command, "check")) {
        if (args.next() != null) return error.InvalidArguments;
        const evidence_dir = try std.fs.path.join(allocator, &.{ options.repository, "tools/fixtures/debian-stable-closure-v1" });
        _ = try checkEvidence(init.io, allocator, evidence_dir);
        try std.Io.File.stdout().writeStreamingAll(init.io, "debian-stable-closure: committed evidence verified\n");
        return 0;
    }
    if (std.mem.eql(u8, command, "compare")) {
        const first = args.next() orelse return error.InvalidArguments;
        const second = args.next() orelse return error.InvalidArguments;
        if (args.next() != null) return error.InvalidArguments;
        const closure = try compareRuns(init.io, allocator, first, second);
        const locks_canon = try canonicalJsonAlloc(allocator, closure.object.get("locks").?);
        try std.Io.File.stdout().writeStreamingAll(init.io, locks_canon);
        return 0;
    }
    if (std.mem.eql(u8, command, "run")) {
        var debz_path: ?[]const u8 = null;
        var inventory_path: ?[]const u8 = null;
        var architecture: ?[]const u8 = null;
        var workspace_path: ?[]const u8 = null;
        while (args.next()) |arg| {
            const slot: *?[]const u8 = if (std.mem.eql(u8, arg, "--debz"))
                &debz_path
            else if (std.mem.eql(u8, arg, "--inventory"))
                &inventory_path
            else if (std.mem.eql(u8, arg, "--architecture"))
                &architecture
            else if (std.mem.eql(u8, arg, "--workspace"))
                &workspace_path
            else
                return error.InvalidArguments;
            if (slot.* != null) return error.InvalidArguments;
            slot.* = args.next() orelse return error.InvalidArguments;
        }
        const now: i64 = @intCast(@divFloor(std.Io.Clock.real.now(init.io).nanoseconds, std.time.ns_per_s));
        try runClosure(init.io, allocator, .{
            .debz_path = debz_path orelse return error.InvalidArguments,
            .inventory_path = inventory_path orelse return error.InvalidArguments,
            .architecture = architecture orelse return error.InvalidArguments,
            .workspace_path = workspace_path orelse return error.InvalidArguments,
        }, now);
        return 0;
    }
    if (std.mem.eql(u8, command, "record")) {
        var amd64_runs: ?[2][]const u8 = null;
        var arm64_runs: ?[2][]const u8 = null;
        var program_version: ?[]const u8 = null;
        var source_commit: ?[]const u8 = null;
        var recorded_on: ?[]const u8 = null;
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--amd64")) {
                if (amd64_runs != null) return error.InvalidArguments;
                amd64_runs = .{ args.next() orelse return error.InvalidArguments, args.next() orelse return error.InvalidArguments };
            } else if (std.mem.eql(u8, arg, "--arm64")) {
                if (arm64_runs != null) return error.InvalidArguments;
                arm64_runs = .{ args.next() orelse return error.InvalidArguments, args.next() orelse return error.InvalidArguments };
            } else {
                const slot: *?[]const u8 = if (std.mem.eql(u8, arg, "--program-version"))
                    &program_version
                else if (std.mem.eql(u8, arg, "--source-commit"))
                    &source_commit
                else if (std.mem.eql(u8, arg, "--recorded-on"))
                    &recorded_on
                else
                    return error.InvalidArguments;
                if (slot.* != null) return error.InvalidArguments;
                slot.* = args.next() orelse return error.InvalidArguments;
            }
        }
        try recordEvidence(
            init.io,
            allocator,
            amd64_runs orelse return error.InvalidArguments,
            arm64_runs orelse return error.InvalidArguments,
            program_version orelse return error.InvalidArguments,
            source_commit orelse return error.InvalidArguments,
            recorded_on orelse return error.InvalidArguments,
        );
        return 0;
    }
    return error.InvalidArguments;
}

pub fn main(init: std.process.Init) void {
    const code = execute(init) catch |err| {
        if (err == error.PinExpired) {
            std.log.err(
                "debian-stable-closure: pin_expired: pinned Release expired at 2026-10-13T07:55:41Z; awaiting the next Debian point release or the #330 frozen-pocket freshness policy, then review a newer snapshot pin",
                .{},
            );
            std.process.exit(pin_expired_exit);
        }
        std.log.err("debian-stable-closure: {s}", .{@errorName(err)});
        std.process.exit(2);
    };
    if (code != 0) std.process.exit(code);
}

// ============================================================================
// Unit Tests (replacing tools/test_debian_stable_closure.py)
// ============================================================================

const ubuntu_signer = "f6ecb3762474eda9d21b7022871920d1991bc93c";
const xz_single = "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\xe0\x00\xa8\x00\x64\x5d\x00\x28\x18\x48\x66\xdb\xda\x30\x85\xfe\x16\xde\xe9\xca\x40\x71\x9a\x51\x6d\x75\xa0\xb8\x49\x94\xe7\xb4\x46\x26\x31\xee\xa5\xa9\x5d\x48\xbd\x8f\x33\x8d\xcf\xdd\xa1\x95\x5f\x74\x72\xc5\x77\x03\x47\xe7\xa7\xd5\x6e\xd3\xca\xd6\xa0\x0c\xc6\x34\x01\x44\x4f\xf3\x35\x46\xd8\x32\x17\x5b\xf9\x7b\x70\x5d\x5c\x2a\x71\xac\xd8\x72\x38\x84\xc4\xd6\x09\x60\x68\xd9\x3c\xcb\x9f\x5b\x6e\xa1\x65\x80\x84\xab\x9f\x1e\x00\x00\x4f\x7f\x18\x09\xc6\xdb\x7e\x95\x00\x01\x80\x01\xa9\x01\x00\x00\x0d\xd5\x24\xd1\xb1\xc4\x67\xfb\x02\x00\x00\x00\x00\x04\x59\x5a";
const xz_repeated = "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\xe0\x01\x51\x00\x67\x5d\x00\x28\x18\x48\x66\xdb\xda\x30\x85\xfe\x16\xde\xe9\xca\x40\x71\x9a\x51\x6d\x75\xa0\xb8\x49\x94\xe7\xb4\x46\x26\x31\xee\xa5\xa9\x5d\x48\xbd\x8f\x33\x8d\xcf\xdd\xa1\x95\x5f\x74\x72\xc5\x77\x03\x47\xe7\xa7\xd5\x6e\xd3\xca\xd6\xa0\x0c\xc6\x34\x01\x44\x4f\xf3\x35\x46\xd8\x32\x17\x5b\xf9\x7b\x70\x5d\x5c\x2a\x71\xac\xd8\x72\x38\x84\xc4\xd6\x09\x60\x68\xd9\x3c\xcb\x9f\x5b\x6e\xa1\x65\x80\x88\x72\xa4\xb2\x9f\xa9\x60\x00\x00\x00\x54\xc6\x23\x36\x13\x86\xf6\xd2\x00\x01\x83\x01\xd2\x02\x00\x00\x67\x3e\xc8\xe9\xb1\xc4\x67\xfb\x02\x00\x00\x00\x00\x04\x59\x5a";
const xz_size_11 = "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\xe0\x00\xa8\x00\x64\x5d\x00\x28\x18\x48\x66\xdb\xda\x30\x85\xfe\x16\xde\xe9\xca\x40\x71\x9a\x51\x6d\x75\xa0\xb8\x49\x94\xe7\xb4\x46\x26\x31\xee\xa5\xa9\x5d\x48\xbd\x8f\x33\x8d\xcf\xdd\xa1\x95\x5f\x74\x72\xc5\x77\x03\x47\xe7\xa7\xd5\x6e\xd3\xca\xd6\xa0\x0c\xc6\x34\x01\x44\x4f\xf3\x35\x46\xd8\x32\x17\x5b\xf9\x7b\x70\x5d\x5c\x2a\x71\xac\xd8\x72\x38\x84\xc4\xdd\x2b\xc0\x3c\x0b\x8a\x38\xb2\xe8\x2b\x96\xb9\xf6\x8b\x0a\x7a\x13\x00\x00\x50\x5a\xa3\x1a\x6e\x0e\x73\xb0\x00\x01\x80\x01\xa9\x01\x00\x00\x0d\xd5\x24\xd1\xb1\xc4\x67\xfb\x02\x00\x00\x00\x00\x04\x59\x5a";

fn committedEvidenceDir(allocator: std.mem.Allocator) ![]u8 {
    return std.fs.path.join(allocator, &.{ options.repository, "tools/fixtures/debian-stable-closure-v1" });
}

fn committedLockValue(io: std.Io, allocator: std.mem.Allocator, architecture: []const u8, request: []const u8) !std.json.Value {
    const dir = try committedEvidenceDir(allocator);
    const filename = try std.fmt.allocPrint(allocator, "{s}-{s}.lock.json", .{ architecture, request });
    const raw = try readRegularFileAlloc(io, allocator, try std.fs.path.join(allocator, &.{ dir, filename }), maximum_json_bytes);
    return (try std.json.parseFromSlice(std.json.Value, allocator, raw, .{})).value;
}

fn signedRecordsForLock(allocator: std.mem.Allocator, lock_val: std.json.Value) !std.StringArrayHashMapUnmanaged(SignedRecord) {
    var records: std.StringArrayHashMapUnmanaged(SignedRecord) = .empty;
    for (lock_val.object.get("packages").?.array.items) |pkg_val| {
        const pkg = pkg_val.object;
        const name = pkg.get("name").?.string;
        const version = pkg.get("version").?.string;
        const arch = pkg.get("architecture").?.string;
        const key = try recordKey(allocator, name, version, arch);
        try records.put(allocator, key, .{
            .filename = try std.fmt.allocPrint(allocator, "pool/main/{c}/{s}/{s}_{s}_{s}.deb", .{ name[0], name, name, version, arch }),
            .size = @intCast(pkg.get("declared_size").?.integer),
            .sha256 = pkg.get("archive_identity").?.object.get("digests").?.array.items[0].object.get("digest").?.string,
        });
    }
    return records;
}

test "committed evidence revalidates offline and CLI check succeeds without host interpreters" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const pin = try loadPin(allocator);
    const evidence_dir = try committedEvidenceDir(allocator);
    const doc_val = try checkEvidence(io, allocator, evidence_dir);
    const doc = doc_val.object;

    try std.testing.expectEqual(@as(i64, 261), doc.get("issue").?.integer);
    try std.testing.expectEqualStrings("2026-10-13T07:55:41Z", doc.get("freshness").?.object.get("expires_at").?.string);
    try std.testing.expectEqualStrings("ReleaseSafe", doc.get("program").?.object.get("optimize").?.string);
    try std.testing.expectEqualStrings(pin.signer.binary_sha256, doc.get("keyring").?.object.get("sha256").?.string);

    var amd64_arch_hashes: std.StringArrayHashMapUnmanaged(void) = .empty;
    for (architectures) |architecture| {
        const entry = doc.get("architectures").?.object.get(architecture).?.object;
        const runs = entry.get("runs").?.array.items;
        try std.testing.expectEqual(@as(usize, 2), runs.len);
        try std.testing.expect(!std.mem.eql(u8, runs[0].string, runs[1].string));
        const repo = entry.get("repository").?.object;
        try std.testing.expectEqualStrings(archive_binding, repo.get("archive_binding").?.string);
        try std.testing.expectEqualStrings((try pin.index(architecture)).index_sha256, repo.get("index_sha256").?.string);
        try std.testing.expectEqualStrings(pin.release.inrelease_sha256, repo.get("inrelease_sha256").?.string);
        const summary = entry.get("inventory").?.object.get("summary").?.object;
        try std.testing.expectEqual(summary.get("packages").?.integer, summary.get("admitted").?.integer);
        try std.testing.expectEqual(@as(i64, 0), summary.get("rejected").?.integer);
        for (entry.get("cas").?.array.items) |row_val| {
            const row = row_val.object;
            try std.testing.expect(std.mem.startsWith(u8, row.get("filename").?.string, "pool/main/"));
            try std.testing.expect(isHexLen(row.get("derived_sha512").?.string, 128));
            if (!std.mem.eql(u8, row.get("architecture").?.string, "all")) {
                const sha = row.get("sha256").?.string;
                if (std.mem.eql(u8, architecture, "amd64")) {
                    try amd64_arch_hashes.put(allocator, sha, {});
                } else {
                    try std.testing.expect(!amd64_arch_hashes.contains(sha));
                }
            }
        }
    }

    var prev_prio: ?[]const u8 = null;
    for (doc.get("gaps").?.array.items) |gap_val| {
        const prio = gap_val.object.get("priority").?.string;
        if (prev_prio) |prev| {
            try std.testing.expect(std.mem.order(u8, prev, prio) != .gt);
        }
        prev_prio = prio;
    }

    if (std.c.getenv("DEBZ_DEBIAN_STABLE_CLOSURE")) |raw_cli| {
        const cli = std.mem.span(raw_cli);
        var env: std.process.Environ.Map = .init(allocator);
        defer env.deinit();
        try env.put("PATH", "/no-host-interpreters");
        const result = try std.process.run(allocator, io, .{
            .argv = &.{ cli, "check" },
            .environ_map = &env,
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try std.testing.expectEqualStrings("debian-stable-closure: committed evidence verified\n", result.stdout);
    }
}

test "tampered committed evidence is refused across all twelve invariants" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const src_dir = try committedEvidenceDir(allocator);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try tmp.dir.realPathFileAlloc(io, ".", allocator);

    const Helper = struct {
        fn copyEvidence(io_ctx: std.Io, alloc: std.mem.Allocator, src: []const u8, base: []const u8, label: []const u8) ![]u8 {
            const target = try std.fs.path.join(alloc, &.{ base, label });
            var base_root = try fs.openAbsoluteRoot(io_ctx, base);
            defer base_root.close();
            try base_root.root.createDirectory(try fs.Path.init(label), .fromMode(0o700));
            for ([_][]const u8{
                "evidence.json",
                "amd64-apt.lock.json",
                "amd64-systemd-sysv.lock.json",
                "amd64-inventory.json",
                "arm64-apt.lock.json",
                "arm64-systemd-sysv.lock.json",
                "arm64-inventory.json",
            }) |name| {
                const bytes = try readRegularFileAlloc(io_ctx, alloc, try std.fs.path.join(alloc, &.{ src, name }), maximum_json_bytes);
                try writeFile(io_ctx, target, name, bytes, 0o600);
            }
            return target;
        }
    };

    // 1. flip lock bytes
    {
        const dir = try Helper.copyEvidence(io, allocator, src_dir, tmp_root, "c1");
        const lock_path = try std.fs.path.join(allocator, &.{ dir, "amd64-apt.lock.json" });
        const raw = try readRegularFileAlloc(io, allocator, lock_path, maximum_json_bytes);
        const mutated = try std.mem.replaceOwned(u8, allocator, raw, "\"requested\"", "\"retained\"");
        try writeFile(io, dir, "amd64-apt.lock.json", mutated, 0o600);
        try std.testing.expectError(error.CommittedLockBytesChanged, checkEvidence(io, allocator, dir));
    }
    // 2. flip inventory bytes
    {
        const dir = try Helper.copyEvidence(io, allocator, src_dir, tmp_root, "c2");
        const inv_path = try std.fs.path.join(allocator, &.{ dir, "arm64-inventory.json" });
        const raw = try readRegularFileAlloc(io, allocator, inv_path, maximum_json_bytes);
        const mutated = try std.mem.replaceOwned(u8, allocator, raw, "\"admitted\": true", "\"admitted\": false");
        try writeFile(io, dir, "arm64-inventory.json", mutated, 0o600);
        try std.testing.expectError(error.CommittedInventoryBytesChanged, checkEvidence(io, allocator, dir));
    }
    // 3..12 JSON document mutations
    const raw_doc = try readRegularFileAlloc(io, allocator, try std.fs.path.join(allocator, &.{ src_dir, "evidence.json" }), maximum_json_bytes);
    for (0..10) |case_idx| {
        const label = try std.fmt.allocPrint(allocator, "json_{d}", .{case_idx});
        const dir = try Helper.copyEvidence(io, allocator, src_dir, tmp_root, label);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_doc, .{});
        var doc = parsed.value.object;
        switch (case_idx) {
            0 => {
                var runs = doc.getPtr("architectures").?.object.getPtr("amd64").?.object.getPtr("runs").?.array;
                runs.items[1] = runs.items[0];
            },
            1 => {
                _ = doc.getPtr("architectures").?.object.getPtr("arm64").?.object.getPtr("cas").?.array.pop();
            },
            2 => {
                const ubuntu_sha = sha256Hex("ubuntu");
                try doc.getPtr("architectures").?.object.getPtr("amd64").?.object.getPtr("cas").?.array.items[0].object.put(allocator, "sha256", .{ .string = &ubuntu_sha });
            },
            3 => {
                try doc.getPtr("architectures").?.object.getPtr("arm64").?.object.getPtr("cas").?.array.items[0].object.put(allocator, "derived_sha512", .{ .string = &@as([128]u8, @splat('0')) });
            },
            4 => {
                _ = doc.getPtr("gaps").?.array.pop();
            },
            5 => {
                try doc.getPtr("gaps").?.array.items[0].object.put(allocator, "priority", .{ .string = "P4" });
            },
            6 => {
                try doc.getPtr("freshness").?.object.put(allocator, "expires_at", .{ .string = "2027-01-01T00:00:00Z" });
            },
            7 => {
                try doc.put(allocator, "pin_sha256", .{ .string = &@as([64]u8, @splat('0')) });
            },
            8 => {
                try doc.getPtr("keyring").?.object.put(allocator, "path", .{ .string = "/tmp/debian.pgp" });
            },
            9 => {
                const amd64_src = doc.get("architectures").?.object.get("amd64").?.object.get("source_sha256").?;
                try doc.getPtr("architectures").?.object.getPtr("arm64").?.object.put(allocator, "source_sha256", amd64_src);
            },
            else => unreachable,
        }
        try writeFile(io, dir, "evidence.json", try canonicalJsonAlloc(allocator, .{ .object = doc }), 0o600);
        try std.testing.expectError(switch (case_idx) {
            0 => error.RequiresTwoDistinctCleanRuns,
            1 => error.CasEvidenceDiffersFromLock,
            2, 3 => error.CasEvidenceDiffersFromLock,
            4, 5 => error.GapListNotDerivedFromInventories,
            6 => error.FreshnessExpiryMismatch,
            7 => error.UnboundClosureEvidence,
            8 => error.ClosureRequestsOrKeyringChanged,
            9 => error.RecordedSourceMismatch,
            else => unreachable,
        }, checkEvidence(io, allocator, dir));
    }
}

test "committed locks pass review and match signed records while substituted or unbound locks refuse" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const pin = try loadPin(allocator);

    for (architectures) |architecture| {
        for (requests) |request| {
            const lock = try committedLockValue(io, allocator, architecture, request);
            const reviewed = try reviewLock(lock, pin, architecture, request);
            try std.testing.expectEqual(lock.object.get("packages").?.array.items.len, reviewed.packages);
            try std.testing.expect(reviewed.total_bytes <= max_bytes_per_lock);
            const records = try signedRecordsForLock(allocator, lock);
            const matched = try matchSigned(allocator, lock, records);
            try std.testing.expectEqual(reviewed.packages, matched.len);
        }
    }

    const dir = try committedEvidenceDir(allocator);
    const raw_lock = try readRegularFileAlloc(io, allocator, try std.fs.path.join(allocator, &.{ dir, "amd64-apt.lock.json" }), maximum_json_bytes);
    for (0..24) |case_idx| {
        const lock_val = (try std.json.parseFromSlice(std.json.Value, allocator, raw_lock, .{})).value;
        var lock = lock_val.object;
        var repo = &lock.getPtr("repositories").?.array.items[0].object;
        var first_pkg = &lock.getPtr("packages").?.array.items[0].object;
        switch (case_idx) {
            0 => {
                repo.getPtr("signer_fingerprints").?.array.items[0] = .{ .string = ubuntu_signer };
            },
            1 => {
                try repo.getPtr("signer_fingerprints").?.array.append(.{ .string = ubuntu_signer });
            },
            2 => {
                _ = repo.orderedRemove("archive_binding");
            },
            3 => {
                try repo.put(allocator, "archive_binding", .{ .string = "published_digests" });
            },
            4 => {
                try repo.getPtr("index_identity").?.object.getPtr("digests").?.array.items[0].object.put(allocator, "digest", .{ .string = &@as([64]u8, @splat('0')) });
            },
            5 => {
                try lock.put(allocator, "target_architecture", .{ .string = "arm64" });
            },
            6 => {
                try lock.getPtr("local_artifacts").?.array.append(.{ .string = "relabelled" });
            },
            7 => {
                const first_repo = lock.get("repositories").?.array.items[0];
                try lock.getPtr("repositories").?.array.append(first_repo);
            },
            8 => {
                _ = first_pkg.orderedRemove("derived_archive_identity");
            },
            9 => {
                try first_pkg.getPtr("derived_archive_identity").?.object.put(allocator, "provenance", .{ .string = "signed_sha512" });
            },
            10 => {
                try first_pkg.getPtr("derived_archive_identity").?.object.put(allocator, "algorithm", .{ .string = "sha256" });
            },
            11 => {
                try first_pkg.getPtr("derived_archive_identity").?.object.put(allocator, "digest", .{ .string = &@as([64]u8, @splat('0')) });
            },
            12 => {
                const derived = first_pkg.get("derived_archive_identity").?.object.get("digest").?;
                try first_pkg.getPtr("archive_identity").?.object.put(allocator, "primary", .{ .string = "sha512" });
                try first_pkg.getPtr("archive_identity").?.object.getPtr("digests").?.array.items[0].object.put(allocator, "algorithm", .{ .string = "sha512" });
                try first_pkg.getPtr("archive_identity").?.object.getPtr("digests").?.array.items[0].object.put(allocator, "digest", derived);
            },
            13 => {
                var extra: std.json.ObjectMap = .empty;
                try extra.put(allocator, "algorithm", .{ .string = "sha512" });
                try extra.put(allocator, "digest", first_pkg.get("derived_archive_identity").?.object.get("digest").?);
                try first_pkg.getPtr("archive_identity").?.object.getPtr("digests").?.array.append(.{ .object = extra });
            },
            14 => {
                try first_pkg.getPtr("origin").?.object.put(allocator, "repository_id", .{ .string = &@as([64]u8, @splat('0')) });
            },
            15 => {
                try first_pkg.getPtr("origin").?.object.put(allocator, "type", .{ .string = "local_artifact" });
            },
            16 => {
                try first_pkg.put(allocator, "architecture", .{ .string = "i386" });
            },
            17 => {
                try first_pkg.put(allocator, "declared_size", .{ .integer = 0 });
            },
            18 => {
                try first_pkg.put(allocator, "declared_size", .{ .integer = @intCast(max_bytes_per_lock) });
            },
            19 => {
                std.mem.reverse(std.json.Value, lock.getPtr("packages").?.array.items);
            },
            20 => {
                const last = lock.get("packages").?.array.items[lock.get("packages").?.array.items.len - 1];
                try lock.getPtr("packages").?.array.append(last);
            },
            21 => {
                for (lock.getPtr("packages").?.array.items) |*p| {
                    try p.object.put(allocator, "retention", .{ .string = "dependency" });
                }
            },
            22 => {
                lock.getPtr("packages").?.array.clearRetainingCapacity();
            },
            23 => {
                try lock.put(allocator, "version", .{ .integer = 2 });
            },
            else => unreachable,
        }
        try std.testing.expectError(switch (case_idx) {
            0, 1 => error.SignerFingerprintMismatch,
            2, 3 => error.ArchiveBindingMismatch,
            4 => error.IndexIdentityMismatch,
            5 => error.TargetArchitectureMismatch,
            6 => error.LocalArtifactsPresent,
            7 => error.InvalidRepositoryCount,
            8, 9, 10, 11 => error.DerivedProvenanceMismatch,
            12, 13 => error.ArchiveIdentityMismatch,
            14, 15 => error.OriginMismatch,
            16 => error.ForeignPackageArchitecture,
            17 => error.MalformedDeclaredSize,
            18 => error.LockBytesExceedBound,
            19, 20 => error.PackagesNotCanonicallyOrdered,
            21 => error.RequestedPackageMismatch,
            22 => error.PackageCountOutOfBounds,
            23 => error.InvalidLockSchemaOrVersion,
            else => unreachable,
        }, reviewLock(.{ .object = lock }, pin, "amd64", "apt"));
    }

    const base_lock = try committedLockValue(io, allocator, "amd64", "apt");
    try std.testing.expectError(error.RequestedPackageMismatch, reviewLock(base_lock, pin, "amd64", "systemd-sysv"));
}

test "ubuntu or mismatched archives never match the signed debian index and signed records bind identity" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;

    const lock = try committedLockValue(io, allocator, "amd64", "apt");
    const first_pkg = lock.object.get("packages").?.array.items[0].object;
    const first_key = try recordKey(
        allocator,
        first_pkg.get("name").?.string,
        first_pkg.get("version").?.string,
        first_pkg.get("architecture").?.string,
    );

    // 1. wrong sha256
    {
        var records = try signedRecordsForLock(allocator, lock);
        const ubuntu_sha = sha256Hex("ubuntu");
        records.getPtr(first_key).?.sha256 = &ubuntu_sha;
        try std.testing.expectError(error.LockIdentityMismatch, matchSigned(allocator, lock, records));
    }
    // 2. wrong size
    {
        var records = try signedRecordsForLock(allocator, lock);
        records.getPtr(first_key).?.size += 1;
        try std.testing.expectError(error.LockIdentityMismatch, matchSigned(allocator, lock, records));
    }
    // 3. filename outside pool/
    {
        var records = try signedRecordsForLock(allocator, lock);
        records.getPtr(first_key).?.filename = "../ubuntu/pool/main/a/apt.deb";
        try std.testing.expectError(error.FilenameOutsidePool, matchSigned(allocator, lock, records));
    }
    // 4. absent package
    {
        var records = try signedRecordsForLock(allocator, lock);
        _ = records.orderedRemove(first_key);
        try std.testing.expectError(error.PackageAbsentFromSignedIndex, matchSigned(allocator, lock, records));
    }

    const readiness = try readinessExecutable(allocator);
    const single_sha = sha256Hex(xz_single);
    const single_index: Index = .{
        .index_path = "main/binary-amd64/Packages.xz",
        .index_size = xz_single.len,
        .index_sha256 = &single_sha,
        .package_records = 1,
    };
    const parsed_records = try signedRecords(io, allocator, readiness, xz_single, single_index);
    const apt_rec = parsed_records.get(try recordKey(allocator, "apt", "3", "amd64")).?;
    try std.testing.expectEqualStrings("pool/main/a/apt/apt_3_amd64.deb", apt_rec.filename);
    try std.testing.expectEqual(@as(u64, 10), apt_rec.size);
    try std.testing.expectEqualStrings(&@as([64]u8, @splat('0')), apt_rec.sha256);

    const repeated_sha = sha256Hex(xz_repeated);
    try std.testing.expectError(error.DuplicateSignedRecord, signedRecords(io, allocator, readiness, xz_repeated, .{
        .index_path = "main/binary-amd64/Packages.xz",
        .index_size = xz_repeated.len,
        .index_sha256 = &repeated_sha,
        .package_records = 2,
    }));

    try std.testing.expectError(error.SignedIndexIdentityChanged, signedRecords(io, allocator, readiness, xz_size_11, single_index));
}

test "expired release, keyring, retry lines, workspace, compare and gap aggregation enforce fail-closed contracts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const pin = try loadPin(allocator);

    // 1. Freshness and expiry before network or workspace
    const expiry = try releaseExpiry(pin);
    try std.testing.expectEqual(@as(i64, 1791878141), expiry);
    try std.testing.expectEqualStrings("2026-10-13T07:55:41Z", try formatIsoUtc(allocator, expiry));
    try std.testing.expectEqual(expiry, try requireFresh(pin, expiry));
    try std.testing.expectError(error.PinExpired, requireFresh(pin, expiry + 1));

    const expired_ws = try std.fs.path.join(allocator, &.{ options.repository, ".tmp/debian-261-closure-expired-test" });
    try std.testing.expectError(error.PinExpired, runClosure(io, allocator, .{
        .debz_path = "/nonexistent/debz",
        .inventory_path = "/nonexistent/inventory",
        .architecture = "amd64",
        .workspace_path = expired_ws,
    }, expiry + 1));
    try std.testing.expectError(error.KeyringStatFailed, lstatPath(allocator, expired_ws));

    var valid_until_pin = pin;
    valid_until_pin.release.valid_until = "Sat, 12 Dec 2026 07:55:41 UTC";
    try std.testing.expectError(error.UnexpectedValidUntil, releaseExpiry(valid_until_pin));

    // 2. Keyring validation
    try std.testing.expectError(error.RelativeKeyringPath, verifyKeyring(io, allocator, "keyring.pgp", "key"));
    try std.testing.expectError(error.KeyringPathSymlink, verifyKeyring(io, allocator, "/proc/self/exe", "key"));
    try std.testing.expectError(error.KeyringNotRegularFile, verifyKeyring(io, allocator, "/etc", "key"));
    try std.testing.expectError(error.KeyringBytesMismatch, verifyKeyring(io, allocator, "/etc/passwd", "not the Debian key"));

    // 3. Retry lines
    try std.testing.expect(isPermittedRetryLine("debz acquisition retry failed_attempt=1/6 delay_ms=2000 error=NameServerFailure"));
    try std.testing.expect(isPermittedRetryLine("debz acquisition retry failed_attempt=6/6 delay_ms=64000 http_status=503"));
    try std.testing.expect(!isPermittedRetryLine("debz acquisition retry failed_attempt=1/6 delay_ms=2000 http_status=404"));
    try std.testing.expect(!isPermittedRetryLine("debz acquisition retry failed_attempt=7/6 delay_ms=2000 error=Timeout"));
    try std.testing.expect(!isPermittedRetryLine("debz acquisition retry failed_attempt=1/6 delay_ms=0 error=Timeout"));
    try std.testing.expect(!isPermittedRetryLine("warning: using unsigned index"));
    try std.testing.expect(!isPermittedRetryLine("debz acquisition retry failed_attempt=1/6 delay_ms=2000 error=x y"));

    // 4. Workspace validation
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    try std.testing.expectError(
        error.WorkspaceMustBeNewDirectChildOfScratch,
        newWorkspace(io, allocator, try std.fs.path.join(allocator, &.{ tmp_root, "run" })),
    );
    try std.testing.expectError(
        error.WorkspaceMustBeNewDirectChildOfScratch,
        newWorkspace(io, allocator, try std.fs.path.join(allocator, &.{ options.repository, ".tmp/nested/run" })),
    );

    // 5. Compare clean runs
    const Helper = struct {
        fn makeRun(io_ctx: std.Io, alloc: std.mem.Allocator, base: []const u8, name: []const u8, closure_json: []const u8, mutated_file: ?[]const u8) ![]u8 {
            const ws = try std.fs.path.join(alloc, &.{ base, name });
            const ev = try std.fs.path.join(alloc, &.{ ws, "evidence" });
            var base_root = try fs.openAbsoluteRoot(io_ctx, base);
            defer base_root.close();
            try base_root.root.createDirectory(try fs.Path.init(name), .fromMode(0o700));
            var ws_root = try fs.openAbsoluteRoot(io_ctx, ws);
            defer ws_root.close();
            try ws_root.root.createDirectory(try fs.Path.init("evidence"), .fromMode(0o700));
            try writeFile(io_ctx, ev, "closure.json", closure_json, 0o600);
            for ([_][2][]const u8{
                .{ "apt.lock.json", "apt" },
                .{ "systemd-sysv.lock.json", "systemd-sysv" },
                .{ "cas.json", "[]\n" },
                .{ "inventory.json", "{}\n" },
            }) |pair| {
                const content = if (mutated_file != null and std.mem.eql(u8, mutated_file.?, pair[0])) "changed" else pair[1];
                try writeFile(io_ctx, ev, pair[0], content, 0o600);
            }
            return ws;
        }
    };
    const r1 = try Helper.makeRun(io, allocator, tmp_root, "r1", "{\"architecture\":\"amd64\",\"locks\":{}}\n", null);
    const r2 = try Helper.makeRun(io, allocator, tmp_root, "r2", "{\"architecture\":\"amd64\",\"locks\":{}}\n", null);
    _ = try compareRuns(io, allocator, r1, r2);
    const r_diff_closure = try Helper.makeRun(io, allocator, tmp_root, "r_diff", "{\"architecture\":\"amd64\",\"cas_sha256\":\"0\",\"locks\":{}}\n", null);
    try std.testing.expectError(error.RunEvidenceDiffers, compareRuns(io, allocator, r1, r_diff_closure));
    for ([_][]const u8{ "apt.lock.json", "systemd-sysv.lock.json", "cas.json", "inventory.json" }) |fname| {
        const r_mut = try Helper.makeRun(io, allocator, tmp_root, fname, "{\"architecture\":\"amd64\",\"locks\":{}}\n", fname);
        try std.testing.expectError(error.RunArtifactDiffers, compareRuns(io, allocator, r1, r_mut));
    }

    // 6. Gap aggregation
    const inv_json =
        \\{
        \\  "arm64": {"packages": [
        \\    {"package": "libc6", "gaps": [{"priority": "P3", "category": "ldconfig", "evidence": ["postinst:ldconfig"]}]},
        \\    {"package": "bash", "gaps": [{"priority": "P1", "category": "alternatives_script_authority", "evidence": ["postinst:alternatives_script_authority"]}]}
        \\  ]},
        \\  "amd64": {"packages": [
        \\    {"package": "tar", "gaps": [{"priority": "P1", "category": "alternatives_script_authority", "evidence": ["postinst:alternatives_script_authority"]}]},
        \\    {"package": "base-files", "gaps": [{"priority": "P4", "category": "ownership_and_mode", "evidence": ["postinst:ownership_and_mode"]}]}
        \\  ]}
        \\}
    ;
    const inv_parsed = try std.json.parseFromSlice(std.json.Value, allocator, inv_json, .{});
    const gaps = (try aggregateGaps(allocator, inv_parsed.value.object)).array.items;
    try std.testing.expectEqual(@as(usize, 3), gaps.len);
    try std.testing.expectEqualStrings("P1", gaps[0].object.get("priority").?.string);
    try std.testing.expectEqualStrings("alternatives_script_authority", gaps[0].object.get("category").?.string);
    try std.testing.expectEqualStrings("P3", gaps[1].object.get("priority").?.string);
    try std.testing.expectEqualStrings("ldconfig", gaps[1].object.get("category").?.string);
    try std.testing.expectEqualStrings("P4", gaps[2].object.get("priority").?.string);
    try std.testing.expectEqualStrings("ownership_and_mode", gaps[2].object.get("category").?.string);

    const inconsistent_json =
        \\{
        \\  "amd64": {"packages": [{"package": "tar", "gaps": [{"priority": "P1", "category": "ldconfig", "evidence": ["postinst:ldconfig"]}]}]},
        \\  "arm64": {"packages": [{"package": "tar", "gaps": [{"priority": "P3", "category": "ldconfig", "evidence": ["postinst:ldconfig"]}]}]}
        \\}
    ;
    const inc_parsed = try std.json.parseFromSlice(std.json.Value, allocator, inconsistent_json, .{});
    try std.testing.expectError(error.InconsistentGapPriority, aggregateGaps(allocator, inc_parsed.value.object));

    const unknown_json =
        \\{"amd64": {"packages": [{"package": "tar", "gaps": [{"priority": "P1", "category": "unreviewed_category", "evidence": ["postinst:x"]}]}]}}
    ;
    const unk_parsed = try std.json.parseFromSlice(std.json.Value, allocator, unknown_json, .{});
    try std.testing.expectError(error.UnreviewedGapCategory, aggregateGaps(allocator, unk_parsed.value.object));
}

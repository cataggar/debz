//! Original ARM sources, not permission to execute a maintainer script.
const std = @import("std");
const debz = @import("debz");
const fs = debz.root_fs;
const lock_v3 = debz.exact_lock_v3;
const application = debz.archive_application;
const digest = debz.content_digest;

const pin_bytes = @embedFile("fixtures/real-snapshot/pin-v1.json");
const maximum_archive_bytes = 16 * 1024 * 1024;
const maximum_report_bytes = 16 * 1024 * 1024;
const perl_directory = "usr/lib/aarch64-linux-gnu/perl-base";
const packages = [_][]const u8{
    "dash",       "dpkg",              "init-system-helpers",
    "libblkid1",  "libc6",             "libcrypt1",
    "libmount1",  "libpcre2-8-0",      "libselinux1",
    "libssl3t64", "libsystemd-shared", "libtinfo6",
    "perl-base",  "systemd",           "util-linux",
};

const Source = struct {
    package: lock_v3.Package,
    model: application.Model,

    fn deinit(self: *Source) void {
        self.model.deinit();
    }
};

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidArmUtilLinuxPin;
    return value.object.get(name) orelse error.InvalidArmUtilLinuxPin;
}

fn text(value: std.json.Value) ![]const u8 {
    if (value != .string) return error.InvalidArmUtilLinuxPin;
    return value.string;
}

fn taggedSha256(value: std.json.Value) ![32]u8 {
    const bytes = try text(value);
    if (!std.mem.startsWith(u8, bytes, "sha256:"))
        return error.InvalidArmUtilLinuxPin;
    return (try digest.Value.parse(.sha256, bytes["sha256:".len..])).sha256;
}

fn verifyPackage(lock: lock_v3.Lock, package: lock_v3.Package) !void {
    if ((!std.mem.eql(u8, package.architecture, "arm64") and
        !std.mem.eql(u8, package.architecture, "all")) or
        lock.archiveAuthentication(package) != .signed_sha512 or
        package.archive_identity.primary != .sha512 or
        package.archive_identity.digests.sha512 == null or
        package.derived_sha512 != null or package.declared_size == 0)
        return error.InvalidArmUtilLinuxSource;
    const origin = switch (package.origin) {
        .authenticated_repository => |value| value,
        .local_artifact => return error.InvalidArmUtilLinuxSource,
    };
    const repository = lock.findRepository(origin.repository_id) orelse
        return error.InvalidArmUtilLinuxSource;
    if (!std.crypto.timing_safe.eql([32]u8, origin.repository_snapshot_sha256, repository.snapshot_sha256) or
        repository.signer_fingerprints.len == 0)
        return error.InvalidArmUtilLinuxSource;
}

fn closureDigest(lock: lock_v3.Lock) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var previous: ?[]const u8 = null;
    for (lock.packages) |package| {
        try verifyPackage(lock, package);
        if (previous) |name|
            if (std.mem.order(u8, name, package.name) != .lt)
                return error.InvalidArmUtilLinuxSource;
        previous = package.name;
        hash.update(package.name);
        hash.update("\x00");
        hash.update(package.version);
        hash.update("\x00");
        hash.update(package.architecture);
        hash.update("\x00sha512:");
        hash.update(&std.fmt.bytesToHex(package.archive_identity.digests.sha512.?, .lower));
        hash.update("\n");
    }
    return hash.finalResult();
}

fn verifyLock(allocator: std.mem.Allocator, lock: lock_v3.Lock, pin: []const u8, now: i64) !void {
    if (!std.mem.eql(u8, lock.target_architecture, "arm64") or lock.local_artifacts.len != 0)
        return error.InvalidArmUtilLinuxSource;
    var document = try std.json.parseFromSlice(std.json.Value, allocator, pin, .{});
    defer document.deinit();
    const series = try field(document.value, "series");
    const signer = try text(try field(series, "signer"));
    const snapshot = try field(document.value, "snapshot");
    const deadline = try field(snapshot, "admission_deadline");
    if (!std.mem.eql(u8, try text(try field(snapshot, "status")), "probed") or
        deadline != .integer or now < 0 or now >= deadline.integer)
        return error.ArmUtilLinuxSourceExpired;
    const closure = try field(try field(snapshot, "closures"), "arm64");
    const count = try field(closure, "package_count");
    if (count != .integer or count.integer < 1 or
        count.integer != lock.packages.len or
        !std.crypto.timing_safe.eql([32]u8, try closureDigest(lock), try taggedSha256(try field(closure, "digest"))))
        return error.InvalidArmUtilLinuxSource;
    const pockets = try field(snapshot, "pockets");
    if (pockets != .array) return error.InvalidArmUtilLinuxPin;
    for (lock.repositories) |repository| {
        for (repository.signer_fingerprints) |fingerprint|
            if (!std.mem.eql(u8, &std.fmt.bytesToHex(fingerprint, .lower), signer))
                return error.InvalidArmUtilLinuxSource;
        var bound = false;
        for (pockets.array.items) |pocket| {
            if (std.crypto.timing_safe.eql([32]u8, repository.release_sha256, try taggedSha256(try field(pocket, "release_sha256"))))
                bound = true;
        }
        if (!bound) return error.InvalidArmUtilLinuxSource;
    }
}

fn packageNamed(lock: lock_v3.Lock, name: []const u8) !lock_v3.Package {
    var found: ?lock_v3.Package = null;
    for (lock.packages) |package| {
        if (!std.mem.eql(u8, package.name, name)) continue;
        if (found != null) return error.InvalidArmUtilLinuxSource;
        found = package;
    }
    return found orelse error.InvalidArmUtilLinuxSource;
}

fn readStable(allocator: std.mem.Allocator, root: fs.Root, path: []const u8, maximum: usize, protected: bool) ![]u8 {
    var pinned = try root.pinRegularFile(try fs.Path.init(path));
    defer pinned.close();
    const observed = try pinned.observeStableAlloc(allocator, maximum);
    errdefer allocator.free(observed.bytes);
    if (observed.entry.link_count != 1 or
        (protected and (observed.entry.uid != 0 or observed.entry.gid != 0 or
            observed.entry.mode & 0o022 != 0)))
        return error.UnsafeArmUtilLinuxSource;
    return observed.bytes;
}

fn protectedPath(host: fs.Root, path: []const u8, directory: bool) !void {
    const normalized = try fs.Path.fromAbsolute(path);
    var offset: usize = 0;
    while (offset < normalized.text.len) {
        const end = if (std.mem.indexOfScalarPos(u8, normalized.text, offset, '/')) |value| value else normalized.text.len;
        const entry = try host.entry(try fs.Path.init(normalized.text[0..end]));
        const last = end == normalized.text.len;
        const expected: std.Io.File.Kind = if (last and !directory) .file else .directory;
        if (!entry.modeled or entry.uid != 0 or entry.gid != 0 or entry.mode & 0o022 != 0 or
            entry.kind != expected)
            return error.UnsafeArmUtilLinuxSource;
        offset = end + 1;
    }
}

fn source(allocator: std.mem.Allocator, lock: lock_v3.Lock, cache: fs.Root, name: []const u8, protected: bool) !Source {
    const package = try packageNamed(lock, name);
    try verifyPackage(lock, package);
    if (package.declared_size > maximum_archive_bytes)
        return error.ArmUtilLinuxSourceTooLarge;
    const object = try std.fmt.allocPrint(allocator, "sha512-{s}", .{
        std.fmt.bytesToHex(package.archive_identity.digests.sha512.?, .lower),
    });
    defer allocator.free(object);
    const bytes = try readStable(allocator, cache, object, maximum_archive_bytes, protected);
    defer allocator.free(bytes);
    try package.verifyArchive(bytes);
    const origin = package.origin.authenticated_repository;
    const version = if (std.mem.indexOfScalar(u8, package.version, ':')) |colon|
        package.version[colon + 1 ..]
    else
        package.version;
    const filename = try std.fmt.allocPrint(allocator, "{s}_{s}_{s}.deb", .{ name, version, package.architecture });
    defer allocator.free(filename);
    var model = switch (application.prepare(allocator, bytes, .{ .repository = .{
        .repository = &origin.repository_id,
        .package = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .requested_package = package.name,
        .requested_version = package.version,
        .requested_architecture = package.architecture,
        .filename = filename,
        .size = package.declared_size,
        .archive_identity = package.archive_identity,
    } }, .{ .payload = .{
        .max_control_compressed_bytes = 2 * 1024 * 1024,
        .max_control_decompressed_bytes = 8 * 1024 * 1024,
        .max_data_compressed_bytes = maximum_archive_bytes,
        .max_data_decompressed_bytes = 128 * 1024 * 1024,
        .max_entries_per_tar = 16384,
    } })) {
        .model => |value| value,
        .diagnostic => |value| {
            std.debug.print("ARM source {s} refused: {s}\n", .{ name, value.message() });
            return error.InvalidArmUtilLinuxSource;
        },
    };
    errdefer model.deinit();
    if (std.mem.eql(u8, name, "util-linux")) {
        const postinst = model.script(.postinst) orelse return error.InvalidArmUtilLinuxSource;
        if (postinst.mode != 0o755 or postinst.uid != 0 or postinst.gid != 0 or
            !debz.native_alternatives.matchesSnapshotUtilLinuxPostinst(model.scriptBytes(postinst.*)))
            return error.InvalidArmUtilLinuxSource;
    }
    if (std.mem.eql(u8, name, "perl-base")) {
        const interpreter = model.findFile("usr/bin/perl") orelse return error.InvalidArmUtilLinuxSource;
        const alias = model.findFile("usr/bin/perl5.40.1") orelse return error.InvalidArmUtilLinuxSource;
        if (interpreter.kind != .regular or alias.kind != .hardlink or
            !std.mem.eql(u8, alias.link_target orelse return error.InvalidArmUtilLinuxSource, interpreter.path) or
            interpreter.mode != 0o755 or interpreter.uid != 0 or interpreter.gid != 0 or
            try linkCount(&model, interpreter.path) != 2)
            return error.InvalidArmUtilLinuxSource;
    }
    return .{ .package = package, .model = model };
}

fn beneath(path: []const u8, directory: []const u8) bool {
    return std.mem.eql(u8, path, directory) or
        (std.mem.startsWith(u8, path, directory) and path.len > directory.len and path[directory.len] == '/');
}

fn selected(package: []const u8, path: []const u8) bool {
    if (std.mem.eql(u8, package, "perl-base"))
        return beneath(path, perl_directory) or std.mem.startsWith(u8, path, "usr/bin/perl");
    if (std.mem.eql(u8, package, "init-system-helpers"))
        return std.mem.eql(u8, path, "usr/bin/deb-systemd-helper") or std.mem.eql(u8, path, "usr/bin/deb-systemd-invoke");
    if (std.mem.eql(u8, package, "systemd"))
        return std.mem.eql(u8, path, "usr/bin/systemctl") or
            beneath(path, "usr/lib/systemd/system-preset") or
            std.mem.eql(u8, path, "usr/lib/systemd/system/timers.target");
    if (std.mem.eql(u8, package, "util-linux")) {
        for ([_][]const u8{
            "usr/bin/more",                          "usr/share/man/man1/more.1.gz",        "usr/sbin/fstrim",
            "usr/lib/systemd/system/fstrim.service", "usr/lib/systemd/system/fstrim.timer",
        }) |member| if (std.mem.eql(u8, path, member)) return true;
        return false;
    }
    if (std.mem.eql(u8, package, "dash")) return std.mem.eql(u8, path, "usr/bin/dash");
    if (std.mem.eql(u8, package, "dpkg")) return std.mem.eql(u8, path, "usr/bin/update-alternatives");
    return beneath(path, "usr/lib/aarch64-linux-gnu");
}

fn regular(model: *const application.Model, file: application.File) !application.File {
    if (file.kind == .regular) return file;
    if (file.kind != .hardlink) return error.InvalidArmUtilLinuxMember;
    const target = model.findFile(file.link_target orelse return error.InvalidArmUtilLinuxMember) orelse
        return error.InvalidArmUtilLinuxMember;
    if (target.kind != .regular) return error.InvalidArmUtilLinuxMember;
    return target.*;
}

fn linkCount(model: *const application.Model, path: []const u8) !u64 {
    var count: u64 = 1;
    for (model.files) |file| {
        if (file.kind != .hardlink) continue;
        const target = try regular(model, file);
        if (std.mem.eql(u8, target.path, path)) count += 1;
    }
    return count;
}

fn compareFile(allocator: std.mem.Allocator, root: fs.Root, model: *const application.Model, package: []const u8, file: application.File, protected: bool) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ package, file.path });
    defer allocator.free(path);
    if (file.uid != 0 or file.gid != 0) return error.InvalidArmUtilLinuxMember;
    const entry = try root.entry(try fs.Path.init(path));
    if (!entry.modeled or entry.mode != file.mode or
        (protected and (entry.uid != 0 or entry.gid != 0)))
        return error.ArmUtilLinuxMemberMismatch;
    switch (file.kind) {
        .regular, .hardlink => {
            const expected = try regular(model, file);
            if (entry.kind != .file or entry.size != expected.size or
                entry.link_count != try linkCount(model, expected.path))
                return error.ArmUtilLinuxMemberMismatch;
            var pinned = try root.pinRegularFile(try fs.Path.init(path));
            defer pinned.close();
            const observation = try pinned.observeStableAlloc(allocator, 16 * 1024 * 1024);
            defer allocator.free(observation.bytes);
            if (!std.meta.eql(entry, observation.entry))
                return error.ArmUtilLinuxMemberMismatch;
            var actual: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(observation.bytes, &actual, .{});
            if (!std.crypto.timing_safe.eql([32]u8, actual, expected.sha256 orelse return error.InvalidArmUtilLinuxMember))
                return error.ArmUtilLinuxMemberMismatch;
            if (file.kind == .hardlink) {
                const target = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ package, expected.path });
                defer allocator.free(target);
                const target_entry = try root.entry(try fs.Path.init(target));
                if (entry.device != target_entry.device or entry.inode != target_entry.inode)
                    return error.ArmUtilLinuxMemberMismatch;
            }
        },
        .symlink => {
            if (entry.kind != .sym_link or entry.link_count != 1)
                return error.ArmUtilLinuxMemberMismatch;
            var pinned = try root.pinSymbolicLink(try fs.Path.init(path));
            defer pinned.close();
            var buffer: [4096]u8 = undefined;
            const observation = try pinned.observe(&buffer);
            if (!std.mem.eql(u8, observation.target, file.link_literal orelse return error.InvalidArmUtilLinuxMember))
                return error.ArmUtilLinuxMemberMismatch;
        },
        .directory => {
            if (entry.kind != .directory) return error.ArmUtilLinuxMemberMismatch;
            var pinned = try root.pinDirectory(try fs.Path.init(path));
            defer pinned.close();
            var contents = try pinned.observeAlloc(allocator, 16384, 1024 * 1024);
            defer contents.deinit();
            for (contents.members) |member| {
                const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ file.path, member.name });
                defer allocator.free(child);
                if (model.findFile(child) == null)
                    return error.ArmUtilLinuxMemberMismatch;
            }
        },
        else => return error.InvalidArmUtilLinuxMember,
    }
}

fn appendJson(output: *std.Io.Writer.Allocating, value: anytype) !void {
    try std.json.Stringify.value(value, .{}, &output.writer);
    if (output.written().len > maximum_report_bytes)
        return error.ArmUtilLinuxSourceTooLarge;
}

fn report(allocator: std.mem.Allocator, lock: lock_v3.Lock, cache: fs.Root, extracted: ?fs.Root, protected: bool, output: *std.Io.Writer.Allocating) !void {
    try output.writer.writeAll("{\"schema\":\"https://debz.dev/schema/arm-util-linux-source-v1\",\"callback_admitted\":false,\"runtime_proved\":false,\"independent_extraction_compared\":");
    try appendJson(output, extracted != null);
    try output.writer.writeAll(",\"architecture\":\"arm64\",\"closure_digest\":");
    try appendJson(output, std.fmt.bytesToHex(try closureDigest(lock), .lower));
    try output.writer.writeAll(",\"sources\":[");
    for (packages, 0..) |name, package_index| {
        var original = try source(allocator, lock, cache, name, protected);
        defer original.deinit();
        if (package_index != 0) try output.writer.writeByte(',');
        try output.writer.writeAll("{\"package\":");
        try appendJson(output, name);
        try output.writer.writeAll(",\"version\":");
        try appendJson(output, original.package.version);
        try output.writer.writeAll(",\"archive_architecture\":");
        try appendJson(output, original.package.architecture);
        try output.writer.print(",\"archive_size\":{d},\"archive_sha512\":", .{original.package.declared_size});
        try appendJson(output, std.fmt.bytesToHex(original.package.archive_identity.digests.sha512.?, .lower));
        try output.writer.writeAll(",\"members\":[");
        var count: usize = 0;
        for (original.model.files) |file| {
            if (!selected(name, file.path)) continue;
            if (extracted) |root| try compareFile(allocator, root, &original.model, name, file, protected);
            if (count != 0) try output.writer.writeByte(',');
            count += 1;
            const resolved: ?application.File = switch (file.kind) {
                .regular, .hardlink => try regular(&original.model, file),
                else => null,
            };
            try appendJson(output, .{
                .path = file.path,
                .kind = @tagName(file.kind),
                .mode = file.mode,
                .uid = file.uid,
                .gid = file.gid,
                .size = if (resolved) |value| value.size else file.size,
                .sha256 = if (resolved) |value| std.fmt.bytesToHex(value.sha256.?, .lower) else null,
                .link_target = file.link_literal orelse file.link_target,
                .hardlink_count = if (resolved) |value| try linkCount(&original.model, value.path) else null,
            });
        }
        if (count == 0) return error.InvalidArmUtilLinuxSource;
        try output.writer.writeAll("]");
        if (original.model.script(.postinst)) |script| {
            try output.writer.writeAll(",\"original_postinst\":");
            try appendJson(output, .{ .mode = script.mode, .size = script.size, .sha256 = std.fmt.bytesToHex(script.sha256, .lower) });
        }
        try output.writer.writeByte('}');
    }
    try output.writer.writeAll("],\"remaining_authority\":[\"independently recorded original ARM helper/Perl/systemctl-preset execution and late loader/module inputs\",\"target-root unit/preset/helper-state/ld.so.cache ownership and immutable confinement bindings\",\"native callback versus independently pinned dpkg complete pager and fstrim/helper state proof\",\"fresh disposable authenticated 177-package native installation and transaction-result verify\"]}\n");
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);
    var offset: usize = 1;
    const protected = args.len > offset and std.mem.eql(u8, args[offset], "--protected");
    if (protected) offset += 1;
    if (args.len < offset + 1) return error.InvalidArguments;
    const compare = std.mem.eql(u8, args[offset], "compare");
    if ((!compare and !std.mem.eql(u8, args[offset], "source")) or
        args.len != offset + (if (compare) @as(usize, 5) else 4))
    {
        std.debug.print("usage: debz-arm-util-linux-authority [--protected] source LOCK CAS OUTPUT | compare LOCK CAS DPKG_EXTRACTED_ROOT OUTPUT\n", .{});
        return error.InvalidArguments;
    }
    var host = try fs.openAbsoluteRoot(init.io, "/");
    defer host.close();
    if (protected) {
        try protectedPath(host.root, args[offset + 1], false);
        try protectedPath(host.root, args[offset + 2], true);
        if (compare) try protectedPath(host.root, args[offset + 3], true);
        const destination_parent = std.fs.path.dirname(args[args.len - 1]) orelse return error.InvalidArguments;
        try protectedPath(host.root, destination_parent, true);
    }
    const lock_path = try fs.Path.fromAbsolute(args[offset + 1]);
    const lock_bytes = try readStable(allocator, host.root, lock_path.text, lock_v3.maximum_document_bytes, protected);
    defer allocator.free(lock_bytes);
    var lock = try lock_v3.decode(allocator, lock_bytes, lock_v3.maximum_document_bytes);
    defer lock.deinit();
    const now: i64 = @intCast(@divFloor(std.Io.Clock.real.now(init.io).nanoseconds, std.time.ns_per_s));
    try verifyLock(allocator, lock.lock, pin_bytes, now);
    var cache = try fs.openAbsoluteRoot(init.io, args[offset + 2]);
    defer cache.close();
    var extracted: ?fs.OwnedRoot = null;
    defer if (extracted) |*root| root.close();
    if (compare) extracted = try fs.openAbsoluteRoot(init.io, args[offset + 3]);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try report(allocator, lock.lock, cache.root, if (extracted) |root| root.root else null, protected, &output);
    const destination = try fs.Path.fromAbsolute(args[args.len - 1]);
    try host.root.publishFile(destination, output.written(), .{
        .permissions = .fromMode(0o600),
        .overwrite = .fail_if_exists,
    });
}

test "ARM util-linux original closure refuses borrowed architectures and unauthenticated repositories" {
    var package: lock_v3.Package = .{
        .name = "source",
        .version = "1",
        .architecture = "arm64",
        .origin = .{ .authenticated_repository = .{ .repository_id = @splat('1'), .repository_snapshot_sha256 = @splat(2) } },
        .archive_identity = try digest.Identity.init(.{ .sha512 = @splat(3) }, .sha512),
        .declared_size = 1,
        .retention = .dependency,
        .dpkg_selection_hold = false,
    };
    var lock: lock_v3.Lock = .{
        .target_architecture = "arm64",
        .request_sha256 = @splat(0),
        .policy_sha256 = @splat(0),
        .repositories = &.{.{
            .id = @splat('1'),
            .snapshot_sha256 = @splat(2),
            .release_sha256 = @splat(3),
            .index_identity = try digest.Identity.init(.{ .sha256 = @splat(4) }, .sha256),
            .signer_fingerprints = &.{@splat(5)},
        }},
        .local_artifacts = &.{},
        .packages = &.{package},
        .digest_sha256 = @splat(0),
    };
    _ = try closureDigest(lock);
    const pin = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"series":{{"signer":"{s}"}},"snapshot":{{"status":"probed","admission_deadline":100,"closures":{{"arm64":{{"package_count":1,"digest":"sha256:{s}"}}}},"pockets":[{{"release_sha256":"sha256:{s}"}}]}}}}
    , .{
        std.fmt.bytesToHex(lock.repositories[0].signer_fingerprints[0], .lower),
        std.fmt.bytesToHex(try closureDigest(lock), .lower),
        std.fmt.bytesToHex(lock.repositories[0].release_sha256, .lower),
    });
    defer std.testing.allocator.free(pin);
    try verifyLock(std.testing.allocator, lock, pin, 99);
    try std.testing.expectError(error.ArmUtilLinuxSourceExpired, verifyLock(std.testing.allocator, lock, pin, 100));
    lock.target_architecture = "amd64";
    try std.testing.expectError(error.InvalidArmUtilLinuxSource, verifyLock(std.testing.allocator, lock, pin, 99));
    lock.target_architecture = "arm64";
    package.architecture = "amd64";
    lock.packages = &.{package};
    try std.testing.expectError(error.InvalidArmUtilLinuxSource, closureDigest(lock));
    package.architecture = "arm64";
    package.origin.authenticated_repository.repository_snapshot_sha256[0] ^= 1;
    lock.packages = &.{package};
    try std.testing.expectError(error.InvalidArmUtilLinuxSource, closureDigest(lock));
}

test "ARM source comparison distinguishes genuine Perl hardlinks from equal-byte copies and foreign module entries" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = fs.Root.init(std.testing.io, temporary.dir);
    for ([_][]const u8{ "perl-base", "perl-base/usr", "perl-base/usr/bin", "perl-base/usr/lib", "perl-base/usr/lib/aarch64-linux-gnu" }) |path|
        try root.ensureDirectory(try fs.Path.init(path), fs.default_directory_permissions);
    const interpreter_path = try fs.Path.init("perl-base/usr/bin/perl");
    const alias_path = try fs.Path.init("perl-base/usr/bin/perl5.40.1");
    const bytes = "synthetic source comparison algorithm fixture; not original authority";
    try root.publishFile(interpreter_path, bytes, .{ .permissions = .fromMode(0o755) });
    try root.publishFile(alias_path, bytes, .{ .permissions = .fromMode(0o755) });
    var interpreter = std.mem.zeroes(application.File);
    interpreter.path = "usr/bin/perl";
    interpreter.kind = .regular;
    interpreter.mode = 0o755;
    interpreter.size = bytes.len;
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &expected, .{});
    interpreter.sha256 = expected;
    var alias = interpreter;
    alias.path = "usr/bin/perl5.40.1";
    alias.kind = .hardlink;
    alias.link_target = interpreter.path;
    var files = [_]application.File{ interpreter, alias };
    var model: application.Model = undefined;
    model.files = &files;
    try std.testing.expectError(error.ArmUtilLinuxMemberMismatch, compareFile(std.testing.allocator, root, &model, "perl-base", interpreter, false));
    try root.removeFile(alias_path);
    try root.createHardLink(interpreter_path, alias_path);
    try compareFile(std.testing.allocator, root, &model, "perl-base", interpreter, false);
    try compareFile(std.testing.allocator, root, &model, "perl-base", alias, false);
    try root.createHardLink(interpreter_path, try fs.Path.init("perl-base/usr/bin/unreviewed-third-link"));
    try std.testing.expectError(error.ArmUtilLinuxMemberMismatch, compareFile(std.testing.allocator, root, &model, "perl-base", alias, false));
    try root.removeFile(try fs.Path.init("perl-base/usr/bin/unreviewed-third-link"));
    try root.ensureDirectory(try fs.Path.init("perl-base/" ++ perl_directory), fs.default_directory_permissions);
    var directory = std.mem.zeroes(application.File);
    directory.path = perl_directory;
    directory.kind = .directory;
    directory.mode = 0o755;
    files[0] = directory;
    model.files = files[0..1];
    try compareFile(std.testing.allocator, root, &model, "perl-base", directory, false);
    try root.publishFile(try fs.Path.init("perl-base/" ++ perl_directory ++ "/Foreign.pm"), "foreign module", .{});
    try std.testing.expectError(error.ArmUtilLinuxMemberMismatch, compareFile(std.testing.allocator, root, &model, "perl-base", directory, false));
}

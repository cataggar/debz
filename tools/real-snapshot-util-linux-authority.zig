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

// Observation decodes an strace record of the original postinst executed by
// the pinned dpkg inside the protected chroot. It witnesses inputs and effects;
// it never admits a callback or proves the native runtime.
const maximum_trace_bytes = 64 * 1024 * 1024;
const maximum_postinst_bytes = 64 * 1024;
const observed_postinst = "/var/lib/dpkg/info/util-linux.postinst";

const TraceScope = enum { host, reference, postinst };

const TraceEvent = struct {
    seq: usize,
    pid: u32,
    kind: enum { call, exited, killed },
    text: []const u8,
};

const TracePending = struct { seq: usize, name: []const u8, text: []const u8 };

const TraceCall = struct { name: []const u8, args: []const []const u8, result: []const u8 };

const TracePlace = struct {
    attribution: enum { root, host, unresolved },
    path: []const u8,
    descriptor: ?[]const u8 = null,
};

const TraceProcess = struct {
    parent: ?u32,
    chrooted: bool,
    postinst: bool,
    cwd: ?TracePlace,
    exit: ?[]const u8 = null,
};

const TraceOperand = struct { directory: ?usize, path: ?usize };
const TracePathCall = struct { operands: []const TraceOperand, mutating: bool };
const trace_at_operand = [_]TraceOperand{.{ .directory = 0, .path = 1 }};
const trace_cwd_operand = [_]TraceOperand{.{ .directory = null, .path = 0 }};
const trace_pair_operands = [_]TraceOperand{ .{ .directory = 0, .path = 1 }, .{ .directory = 2, .path = 3 } };
const trace_descriptor_operand = [_]TraceOperand{.{ .directory = 0, .path = null }};
const trace_symlink_operand = [_]TraceOperand{.{ .directory = 1, .path = 2 }};
const trace_watch_operand = [_]TraceOperand{.{ .directory = null, .path = 1 }};
const trace_mark_operand = [_]TraceOperand{.{ .directory = 3, .path = 4 }};
const trace_path_calls = [_]struct { []const u8, TracePathCall }{
    .{ "openat", .{ .operands = &trace_at_operand, .mutating = false } },
    .{ "openat2", .{ .operands = &trace_at_operand, .mutating = false } },
    .{ "newfstatat", .{ .operands = &trace_at_operand, .mutating = false } },
    .{ "statx", .{ .operands = &trace_at_operand, .mutating = false } },
    .{ "faccessat", .{ .operands = &trace_at_operand, .mutating = false } },
    .{ "faccessat2", .{ .operands = &trace_at_operand, .mutating = false } },
    .{ "readlinkat", .{ .operands = &trace_at_operand, .mutating = false } },
    .{ "name_to_handle_at", .{ .operands = &trace_at_operand, .mutating = false } },
    .{ "execveat", .{ .operands = &trace_at_operand, .mutating = false } },
    .{ "mkdirat", .{ .operands = &trace_at_operand, .mutating = true } },
    .{ "mknodat", .{ .operands = &trace_at_operand, .mutating = true } },
    .{ "unlinkat", .{ .operands = &trace_at_operand, .mutating = true } },
    .{ "fchmodat", .{ .operands = &trace_at_operand, .mutating = true } },
    .{ "fchmodat2", .{ .operands = &trace_at_operand, .mutating = true } },
    .{ "fchownat", .{ .operands = &trace_at_operand, .mutating = true } },
    .{ "utimensat", .{ .operands = &trace_at_operand, .mutating = true } },
    .{ "renameat", .{ .operands = &trace_pair_operands, .mutating = true } },
    .{ "renameat2", .{ .operands = &trace_pair_operands, .mutating = true } },
    .{ "linkat", .{ .operands = &trace_pair_operands, .mutating = true } },
    .{ "symlinkat", .{ .operands = &trace_symlink_operand, .mutating = true } },
    .{ "execve", .{ .operands = &trace_cwd_operand, .mutating = false } },
    .{ "chdir", .{ .operands = &trace_cwd_operand, .mutating = false } },
    .{ "statfs", .{ .operands = &trace_cwd_operand, .mutating = false } },
    .{ "getxattr", .{ .operands = &trace_cwd_operand, .mutating = false } },
    .{ "lgetxattr", .{ .operands = &trace_cwd_operand, .mutating = false } },
    .{ "listxattr", .{ .operands = &trace_cwd_operand, .mutating = false } },
    .{ "llistxattr", .{ .operands = &trace_cwd_operand, .mutating = false } },
    .{ "truncate", .{ .operands = &trace_cwd_operand, .mutating = true } },
    .{ "setxattr", .{ .operands = &trace_cwd_operand, .mutating = true } },
    .{ "lsetxattr", .{ .operands = &trace_cwd_operand, .mutating = true } },
    .{ "removexattr", .{ .operands = &trace_cwd_operand, .mutating = true } },
    .{ "lremovexattr", .{ .operands = &trace_cwd_operand, .mutating = true } },
    .{ "inotify_add_watch", .{ .operands = &trace_watch_operand, .mutating = false } },
    .{ "fanotify_mark", .{ .operands = &trace_mark_operand, .mutating = false } },
    .{ "fchdir", .{ .operands = &trace_descriptor_operand, .mutating = false } },
    .{ "fchmod", .{ .operands = &trace_descriptor_operand, .mutating = true } },
    .{ "fchown", .{ .operands = &trace_descriptor_operand, .mutating = true } },
    .{ "ftruncate", .{ .operands = &trace_descriptor_operand, .mutating = true } },
};
const trace_confinement_calls = [_][]const u8{
    "chroot",   "mount",       "umount2",  "pivot_root", "open_tree", "move_mount", "mount_setattr", "fspick",
    "fsopen",   "fsmount",     "fsconfig", "unshare",    "setns",     "swapon",     "swapoff",       "acct",
    "quotactl", "quotactl_fd",
};
const trace_network_calls = [_][]const u8{ "socket", "connect", "bind" };
const trace_ignored_calls = [_][]const u8{
    "wait4",           "waitid",            "kill",            "tkill",  "tgkill",
    "pidfd_open",      "pidfd_send_signal", "pidfd_getfd",     "exit",   "exit_group",
    "rt_sigqueueinfo", "rt_tgsigqueueinfo", "restart_syscall", "getcwd",
};

const TracePathRecord = struct {
    scope: []const u8,
    call: []const u8,
    attribution: []const u8,
    path: []const u8,
    descriptor: ?[]const u8,
    mutating: bool,
    result: []const u8,
    count: usize = 1,
};
const TraceSymlinkRecord = struct { scope: []const u8, target: []const u8, attribution: []const u8, path: []const u8, result: []const u8, count: usize = 1 };
const TraceCallRecord = struct { scope: []const u8, call: []const u8, arguments: []const u8, result: []const u8, count: usize = 1 };
const TraceGapRecord = struct { scope: []const u8, call: []const u8, reason: []const u8, count: usize = 1 };
const TraceExecution = struct {
    pid: u32,
    scope: []const u8,
    attribution: []const u8,
    path: []const u8,
    argv: []const []const u8,
    environment: []const []const u8,
    result: []const u8,
};
const TraceProcessRecord = struct { pid: u32, parent: ?u32, scope: []const u8, exit: []const u8 };

fn TraceTally(comptime Record: type) type {
    return struct {
        index: std.array_hash_map.String(usize) = .empty,
        records: std.ArrayList(Record) = .empty,

        fn add(self: *@This(), arena: std.mem.Allocator, key: []const []const u8, record: Record) !void {
            const joined = try std.mem.join(arena, "\x00", key);
            const entry = try self.index.getOrPut(arena, joined);
            if (entry.found_existing) {
                self.records.items[entry.value_ptr.*].count += 1;
                return;
            }
            entry.value_ptr.* = self.records.items.len;
            try self.records.append(arena, record);
        }
    };
}

const TraceObservation = struct {
    lines: usize,
    postinst_pid: u32,
    postinst_parent: u32,
    postinst_exit: u8,
    postinst_argv: []const []const u8,
    postinst_environment: []const []const u8,
    processes: []const TraceProcessRecord,
    executions: []const TraceExecution,
    paths: []const TracePathRecord,
    host_descriptors: []const TracePathRecord,
    symlinks: []const TraceSymlinkRecord,
    confinement: []const TraceCallRecord,
    network: []const TraceCallRecord,
    calls_not_decoded: []const TraceGapRecord,
};

fn traceDigits(bytes: []const u8) bool {
    if (bytes.len == 0 or bytes.len > 10) return false;
    for (bytes) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}

fn traceEvents(arena: std.mem.Allocator, trace: []const u8) ![]TraceEvent {
    if (trace.len == 0 or trace[trace.len - 1] != '\n') return error.InvalidArmUtilLinuxTrace;
    var events: std.ArrayList(TraceEvent) = .empty;
    var pending: std.array_hash_map.Auto(u32, TracePending) = .empty;
    var finished: std.array_hash_map.Auto(u32, void) = .empty;
    var lines = std.mem.splitScalar(u8, trace[0 .. trace.len - 1], '\n');
    var seq: usize = 0;
    while (lines.next()) |line| : (seq += 1) {
        var index: usize = 0;
        while (index < line.len and std.ascii.isDigit(line[index])) index += 1;
        if (!traceDigits(line[0..index]) or index >= line.len or line[index] != ' ')
            return error.InvalidArmUtilLinuxTrace;
        const pid = std.fmt.parseInt(u32, line[0..index], 10) catch return error.InvalidArmUtilLinuxTrace;
        while (index < line.len and line[index] == ' ') index += 1;
        const rest = line[index..];
        if (pid == 0 or rest.len == 0 or finished.contains(pid)) return error.InvalidArmUtilLinuxTrace;
        if (std.mem.startsWith(u8, rest, "+++ ")) {
            if (rest.len < 8 or !std.mem.endsWith(u8, rest, " +++")) return error.InvalidArmUtilLinuxTrace;
            const body = rest[4 .. rest.len - 4];
            if (pending.fetchSwapRemove(pid)) |entry| try events.append(arena, .{
                .seq = entry.value.seq,
                .pid = pid,
                .kind = .call,
                .text = try std.mem.concat(arena, u8, &.{ entry.value.text, ") = ?" }),
            });
            if (std.mem.startsWith(u8, body, "exited with ")) {
                const status = body["exited with ".len..];
                if (!traceDigits(status)) return error.InvalidArmUtilLinuxTrace;
                _ = std.fmt.parseInt(u8, status, 10) catch return error.InvalidArmUtilLinuxTrace;
                try events.append(arena, .{ .seq = seq, .pid = pid, .kind = .exited, .text = status });
            } else if (std.mem.startsWith(u8, body, "killed by SIG")) {
                var signal = body["killed by ".len..];
                if (std.mem.endsWith(u8, signal, " (core dumped)")) signal = signal[0 .. signal.len - " (core dumped)".len];
                for (signal) |byte| if (!std.ascii.isUpper(byte) and !std.ascii.isDigit(byte) and byte != '+')
                    return error.InvalidArmUtilLinuxTrace;
                try events.append(arena, .{ .seq = seq, .pid = pid, .kind = .killed, .text = signal });
            } else return error.UnsupportedArmUtilLinuxTrace;
            try finished.put(arena, pid, {});
            continue;
        }
        if (std.mem.startsWith(u8, rest, "--- ")) continue;
        if (std.mem.startsWith(u8, rest, "<... ")) {
            const close = std.mem.indexOf(u8, rest, " resumed>") orelse return error.InvalidArmUtilLinuxTrace;
            const entry = pending.fetchSwapRemove(pid) orelse return error.InvalidArmUtilLinuxTrace;
            if (!std.mem.eql(u8, entry.value.name, rest["<... ".len..close])) return error.InvalidArmUtilLinuxTrace;
            var tail = rest[close + " resumed>".len ..];
            if (std.mem.startsWith(u8, tail, " <unfinished ...>")) tail = tail[" <unfinished ...>".len..];
            try events.append(arena, .{
                .seq = entry.value.seq,
                .pid = pid,
                .kind = .call,
                .text = try std.mem.concat(arena, u8, &.{ entry.value.text, tail }),
            });
            continue;
        }
        if (pending.contains(pid)) return error.InvalidArmUtilLinuxTrace;
        const open = std.mem.indexOfScalar(u8, rest, '(') orelse return error.InvalidArmUtilLinuxTrace;
        if (std.mem.endsWith(u8, rest, " <unfinished ...>")) {
            try pending.put(arena, pid, .{ .seq = seq, .name = rest[0..open], .text = rest[0 .. rest.len - " <unfinished ...>".len] });
            continue;
        }
        try events.append(arena, .{ .seq = seq, .pid = pid, .kind = .call, .text = rest });
    }
    if (pending.count() != 0) return error.InvalidArmUtilLinuxTrace;
    std.mem.sort(TraceEvent, events.items, {}, struct {
        fn lessThan(_: void, left: TraceEvent, right: TraceEvent) bool {
            return left.seq < right.seq;
        }
    }.lessThan);
    return events.items;
}

fn traceSkipString(line: []const u8, start: usize) !usize {
    var index = start + 1;
    while (index < line.len) : (index += 1) {
        switch (line[index]) {
            '\\' => index += 1,
            '"' => return index + 1,
            else => {},
        }
    }
    return error.InvalidArmUtilLinuxTrace;
}

fn traceSkipDecoration(line: []const u8, start: usize) !usize {
    var depth: usize = 0;
    var index = start;
    while (index < line.len) : (index += 1) {
        switch (line[index]) {
            '\\' => index += 1,
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if (depth == 0) return index + 1;
            },
            else => {},
        }
    }
    return error.InvalidArmUtilLinuxTrace;
}

fn traceCall(arena: std.mem.Allocator, line: []const u8) !TraceCall {
    const open = std.mem.indexOfScalar(u8, line, '(') orelse return error.InvalidArmUtilLinuxTrace;
    const name = line[0..open];
    if (name.len == 0) return error.InvalidArmUtilLinuxTrace;
    for (name) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '?')
        return error.InvalidArmUtilLinuxTrace;
    var args: std.ArrayList([]const u8) = .empty;
    var depth: usize = 0;
    var start = open + 1;
    var index = start;
    while (true) {
        if (index >= line.len) return error.InvalidArmUtilLinuxTrace;
        switch (line[index]) {
            '"' => {
                index = try traceSkipString(line, index);
                continue;
            },
            '<' => {
                index = try traceSkipDecoration(line, index);
                continue;
            },
            '/' => if (index + 1 < line.len and line[index + 1] == '*') {
                index = (std.mem.indexOfPos(u8, line, index + 2, "*/") orelse return error.InvalidArmUtilLinuxTrace) + 2;
                continue;
            },
            '(', '[', '{' => depth += 1,
            ']', '}' => {
                if (depth == 0) return error.InvalidArmUtilLinuxTrace;
                depth -= 1;
            },
            ')' => {
                if (depth == 0) break;
                depth -= 1;
            },
            ',' => if (depth == 0) {
                try args.append(arena, std.mem.trim(u8, line[start..index], " "));
                start = index + 1;
            },
            else => {},
        }
        index += 1;
    }
    const last = std.mem.trim(u8, line[start..index], " ");
    if (last.len != 0 or args.items.len != 0) try args.append(arena, last);
    const tail = std.mem.trimStart(u8, line[index + 1 ..], " ");
    if (!std.mem.startsWith(u8, tail, "= ")) return error.InvalidArmUtilLinuxTrace;
    const result = std.mem.trim(u8, tail[2..], " ");
    if (result.len == 0) return error.InvalidArmUtilLinuxTrace;
    return .{ .name = name, .args = args.items, .result = result };
}

fn traceUnescape(arena: std.mem.Allocator, body: []const u8) ![]const u8 {
    var bytes: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < body.len) {
        if (body[index] != '\\') {
            try bytes.append(arena, body[index]);
            index += 1;
            continue;
        }
        if (index + 1 >= body.len) return error.InvalidArmUtilLinuxTrace;
        const escape = body[index + 1];
        index += 2;
        const decoded: u8 = switch (escape) {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'v' => 0x0b,
            'f' => 0x0c,
            'a' => 0x07,
            'b' => 0x08,
            '\\', '"', '\'' => escape,
            'x' => hex: {
                if (index + 2 > body.len) return error.InvalidArmUtilLinuxTrace;
                const value = std.fmt.parseInt(u8, body[index .. index + 2], 16) catch return error.InvalidArmUtilLinuxTrace;
                index += 2;
                break :hex value;
            },
            '0'...'7' => octal: {
                var value: u16 = escape - '0';
                var digits: usize = 1;
                while (digits < 3 and index < body.len and body[index] >= '0' and body[index] <= '7') : (digits += 1) {
                    value = value * 8 + (body[index] - '0');
                    index += 1;
                }
                if (value > 0xff) return error.InvalidArmUtilLinuxTrace;
                break :octal @intCast(value);
            },
            else => return error.InvalidArmUtilLinuxTrace,
        };
        try bytes.append(arena, decoded);
    }
    if (!std.unicode.utf8ValidateSlice(bytes.items)) return error.UnsupportedArmUtilLinuxTrace;
    return bytes.items;
}

fn traceString(arena: std.mem.Allocator, token: []const u8) ![]const u8 {
    if (token.len < 2 or token[0] != '"') return error.UnsupportedArmUtilLinuxTrace;
    const end = try traceSkipString(token, 0);
    if (std.mem.eql(u8, token[end..], "...")) return error.TruncatedArmUtilLinuxTrace;
    if (end != token.len) return error.InvalidArmUtilLinuxTrace;
    return traceUnescape(arena, token[1 .. end - 1]);
}

fn traceStrings(arena: std.mem.Allocator, token: []const u8) ![]const []const u8 {
    if (std.mem.endsWith(u8, token, "...")) return error.TruncatedArmUtilLinuxTrace;
    if (token.len < 2 or token[0] != '[' or token[token.len - 1] != ']') return error.UnsupportedArmUtilLinuxTrace;
    const body = token[0 .. token.len - 1];
    var items: std.ArrayList([]const u8) = .empty;
    var index: usize = 1;
    while (true) {
        while (index < body.len and body[index] == ' ') index += 1;
        if (index == body.len) {
            if (items.items.len != 0) return error.InvalidArmUtilLinuxTrace;
            break;
        }
        if (std.mem.startsWith(u8, body[index..], "...")) return error.TruncatedArmUtilLinuxTrace;
        if (body[index] != '"') return error.InvalidArmUtilLinuxTrace;
        const close = try traceSkipString(body, index);
        if (std.mem.startsWith(u8, body[close..], "...")) return error.TruncatedArmUtilLinuxTrace;
        try items.append(arena, try traceUnescape(arena, body[index + 1 .. close - 1]));
        index = close;
        if (index == body.len) break;
        if (body[index] != ',') return error.InvalidArmUtilLinuxTrace;
        index += 1;
    }
    return items.items;
}

fn traceDescriptor(arena: std.mem.Allocator, token: []const u8) !?[]const u8 {
    const open = std.mem.indexOfScalar(u8, token, '<') orelse return null;
    if (!std.mem.eql(u8, token[0..open], "AT_FDCWD") and !traceDigits(token[0..open]))
        return error.InvalidArmUtilLinuxTrace;
    if (try traceSkipDecoration(token, open) != token.len) return error.InvalidArmUtilLinuxTrace;
    const inner = token[open + 1 .. token.len - 1];
    if (inner.len == 0 or inner[0] != '/' or std.mem.indexOfAny(u8, inner, "<>") != null or
        std.mem.endsWith(u8, inner, " (deleted)"))
        return null;
    return try traceUnescape(arena, inner);
}

fn traceNormalize(arena: std.mem.Allocator, base: []const u8, path: []const u8) ![]const u8 {
    var output: std.ArrayList(u8) = .empty;
    const pieces = [_][]const u8{ if (path.len != 0 and path[0] == '/') "" else base, path };
    for (pieces) |piece| {
        var parts = std.mem.tokenizeScalar(u8, piece, '/');
        while (parts.next()) |part| {
            if (std.mem.eql(u8, part, ".")) continue;
            try output.append(arena, '/');
            try output.appendSlice(arena, part);
        }
    }
    if (output.items.len == 0) return "/";
    return output.items;
}

fn traceHostPlace(process: TraceProcess, root: []const u8, host: []const u8, descriptor: []const u8) TracePlace {
    if (!process.chrooted) return .{ .attribution = .host, .path = host };
    if (std.mem.eql(u8, host, root)) return .{ .attribution = .root, .path = "/" };
    if (std.mem.startsWith(u8, host, root) and host.len > root.len and host[root.len] == '/')
        return .{ .attribution = .root, .path = host[root.len..] };
    return .{ .attribution = .unresolved, .path = host, .descriptor = descriptor };
}

fn traceResolve(arena: std.mem.Allocator, root: []const u8, process: TraceProcess, call: TraceCall, operand: TraceOperand) !TracePlace {
    var relative: ?[]const u8 = null;
    if (operand.path) |index| {
        if (index >= call.args.len) return error.InvalidArmUtilLinuxTrace;
        if (!std.mem.eql(u8, call.args[index], "NULL")) {
            const path = try traceString(arena, call.args[index]);
            if (path.len != 0) relative = path;
        }
    }
    if (relative) |path| if (path[0] == '/')
        return .{ .attribution = if (process.chrooted) .root else .host, .path = try traceNormalize(arena, "", path) };
    const base: TracePlace = if (operand.directory) |index| decorated: {
        if (index >= call.args.len) return error.InvalidArmUtilLinuxTrace;
        const token = call.args[index];
        const host = try traceDescriptor(arena, token) orelse
            break :decorated .{ .attribution = .unresolved, .path = "", .descriptor = token };
        break :decorated traceHostPlace(process, root, host, token);
    } else process.cwd orelse .{ .attribution = .unresolved, .path = "", .descriptor = "cwd" };
    if (base.attribution == .unresolved)
        return .{ .attribution = .unresolved, .path = relative orelse base.path, .descriptor = base.descriptor };
    return .{ .attribution = base.attribution, .path = if (relative) |path| try traceNormalize(arena, base.path, path) else base.path };
}

fn traceResult(result: []const u8) []const u8 {
    if (std.mem.eql(u8, result, "?")) return "?";
    for ([_][]const u8{ "-1 ", "? " }) |prefix| if (std.mem.startsWith(u8, result, prefix)) {
        const errno = result[prefix.len..];
        return errno[0 .. std.mem.indexOfScalar(u8, errno, ' ') orelse errno.len];
    };
    return "ok";
}

fn traceChild(result: []const u8) !?u32 {
    if (result[0] == '-' or result[0] == '?') return null;
    const end = std.mem.indexOfScalar(u8, result, ' ') orelse result.len;
    if (!traceDigits(result[0..end])) return error.InvalidArmUtilLinuxTrace;
    const local = std.fmt.parseInt(u32, result[0..end], 10) catch return error.InvalidArmUtilLinuxTrace;
    const comment = std.mem.trim(u8, result[end..], " ");
    if (comment.len == 0) return local;
    const prefix = "/* ";
    const suffix = " in strace's PID NS */";
    if (!std.mem.startsWith(u8, comment, prefix) or !std.mem.endsWith(u8, comment, suffix) or
        comment.len <= prefix.len + suffix.len or !traceDigits(comment[prefix.len .. comment.len - suffix.len]))
        return error.InvalidArmUtilLinuxTrace;
    return std.fmt.parseInt(u32, comment[prefix.len .. comment.len - suffix.len], 10) catch error.InvalidArmUtilLinuxTrace;
}

fn traceNamed(names: []const []const u8, name: []const u8) bool {
    for (names) |candidate| if (std.mem.eql(u8, candidate, name)) return true;
    return false;
}

fn traceScope(process: TraceProcess) TraceScope {
    if (process.postinst) return .postinst;
    if (process.chrooted) return .reference;
    return .host;
}

fn observeTrace(arena: std.mem.Allocator, trace: []const u8, root: []const u8) !TraceObservation {
    if (root.len < 2 or root[0] != '/' or root[root.len - 1] == '/') return error.InvalidArguments;
    const events = try traceEvents(arena, trace);
    var processes: std.array_hash_map.Auto(u32, TraceProcess) = .empty;
    var executions: std.ArrayList(TraceExecution) = .empty;
    var paths: TraceTally(TracePathRecord) = .{};
    var descriptors: TraceTally(TracePathRecord) = .{};
    var symlinks: TraceTally(TraceSymlinkRecord) = .{};
    var confinement: TraceTally(TraceCallRecord) = .{};
    var network: TraceTally(TraceCallRecord) = .{};
    var gaps: TraceTally(TraceGapRecord) = .{};
    var postinst_pid: ?u32 = null;
    var postinst_executions: usize = 0;
    var postinst_argv: []const []const u8 = &.{};
    var postinst_environment: []const []const u8 = &.{};
    for (events, 0..) |event, position| {
        if (!processes.contains(event.pid)) {
            if (position != 0) return error.InvalidArmUtilLinuxTrace;
            try processes.put(arena, event.pid, .{ .parent = null, .chrooted = false, .postinst = false, .cwd = null });
        }
        const process = processes.getPtr(event.pid).?;
        switch (event.kind) {
            .exited => {
                process.exit = try std.mem.concat(arena, u8, &.{ "exited ", event.text });
                continue;
            },
            .killed => {
                process.exit = try std.mem.concat(arena, u8, &.{ "killed ", event.text });
                continue;
            },
            .call => {},
        }
        const call = try traceCall(arena, event.text);
        const result = traceResult(call.result);
        var scope = @tagName(traceScope(process.*));
        if (traceNamed(&.{ "clone", "clone3", "fork", "vfork" }, call.name)) {
            const child = try traceChild(call.result) orelse continue;
            if (processes.contains(child)) return error.InvalidArmUtilLinuxTrace;
            const parent = process.*;
            try processes.put(arena, child, .{ .parent = event.pid, .chrooted = parent.chrooted, .postinst = parent.postinst, .cwd = parent.cwd });
            continue;
        }
        if (std.mem.eql(u8, call.name, "chroot")) {
            const place = try traceResolve(arena, root, process.*, call, trace_cwd_operand[0]);
            const arguments = try std.mem.join(arena, ", ", call.args);
            try confinement.add(arena, &.{ scope, call.name, arguments, call.result }, .{ .scope = scope, .call = call.name, .arguments = arguments, .result = call.result });
            if (!std.mem.eql(u8, call.result, "0")) continue;
            if (!process.chrooted) {
                if (!std.mem.eql(u8, try traceString(arena, call.args[0]), root))
                    return error.ArmUtilLinuxObservationOutsideRoot;
                process.chrooted = true;
                process.cwd = null;
            } else if (place.attribution != .root or !std.mem.eql(u8, place.path, "/")) {
                return error.UnsupportedArmUtilLinuxTrace;
            }
            continue;
        }
        if (traceNamed(&trace_confinement_calls, call.name) or traceNamed(&trace_network_calls, call.name)) {
            const arguments = try std.mem.join(arena, ", ", call.args);
            const tally = if (traceNamed(&trace_network_calls, call.name)) &network else &confinement;
            try tally.add(arena, &.{ scope, call.name, arguments, call.result }, .{ .scope = scope, .call = call.name, .arguments = arguments, .result = call.result });
            continue;
        }
        if (traceNamed(&trace_ignored_calls, call.name)) continue;
        var path_call: ?TracePathCall = null;
        for (trace_path_calls) |entry| {
            if (std.mem.eql(u8, entry[0], call.name)) path_call = entry[1];
        }
        const decoded = path_call orelse {
            try gaps.add(arena, &.{ scope, call.name, "unclassified" }, .{ .scope = scope, .call = call.name, .reason = "unclassified" });
            continue;
        };
        var places: [2]TracePlace = undefined;
        var undecoded = false;
        for (decoded.operands, 0..) |operand, index| {
            places[index] = traceResolve(arena, root, process.*, call, operand) catch |err| switch (err) {
                error.UnsupportedArmUtilLinuxTrace => {
                    undecoded = true;
                    break;
                },
                else => return err,
            };
        }
        if (undecoded) {
            try gaps.add(arena, &.{ scope, call.name, "undecoded path operand" }, .{ .scope = scope, .call = call.name, .reason = "undecoded path operand" });
            continue;
        }
        const execution = std.mem.eql(u8, call.name, "execve") or std.mem.eql(u8, call.name, "execveat");
        if (execution) {
            const first: usize = if (std.mem.eql(u8, call.name, "execve")) 1 else 2;
            if (call.args.len < first + 2) return error.InvalidArmUtilLinuxTrace;
            const argv = try traceStrings(arena, call.args[first]);
            const environment = try traceStrings(arena, call.args[first + 1]);
            if (process.chrooted and places[0].attribution == .root and std.mem.eql(u8, places[0].path, observed_postinst)) {
                postinst_executions += 1;
                if (postinst_pid == null and std.mem.eql(u8, call.result, "0")) {
                    process.postinst = true;
                    postinst_pid = event.pid;
                    postinst_argv = argv;
                    postinst_environment = environment;
                    scope = @tagName(TraceScope.postinst);
                }
            }
            try executions.append(arena, .{
                .pid = event.pid,
                .scope = scope,
                .attribution = @tagName(places[0].attribution),
                .path = places[0].path,
                .argv = argv,
                .environment = environment,
                .result = call.result,
            });
        }
        const mutating = decoded.mutating or
            ((std.mem.eql(u8, call.name, "openat") or std.mem.eql(u8, call.name, "openat2")) and call.args.len > 2 and
                (std.mem.indexOf(u8, call.args[2], "O_WRONLY") != null or std.mem.indexOf(u8, call.args[2], "O_RDWR") != null or
                    std.mem.indexOf(u8, call.args[2], "O_CREAT") != null or std.mem.indexOf(u8, call.args[2], "O_TRUNC") != null or
                    std.mem.indexOf(u8, call.args[2], "O_TMPFILE") != null));
        for (places[0..decoded.operands.len]) |place| {
            const record: TracePathRecord = .{
                .scope = scope,
                .call = call.name,
                .attribution = @tagName(place.attribution),
                .path = place.path,
                .descriptor = place.descriptor,
                .mutating = mutating,
                .result = result,
            };
            const key = [_][]const u8{ scope, call.name, record.attribution, place.path, place.descriptor orelse "", if (mutating) "m" else "r", result };
            if (place.attribution == .unresolved) try descriptors.add(arena, &key, record) else try paths.add(arena, &key, record);
        }
        if (std.mem.eql(u8, call.name, "symlinkat")) {
            const target = try traceString(arena, call.args[0]);
            try symlinks.add(arena, &.{ scope, target, @tagName(places[0].attribution), places[0].path, result }, .{
                .scope = scope,
                .target = target,
                .attribution = @tagName(places[0].attribution),
                .path = places[0].path,
                .result = result,
            });
        }
        if ((std.mem.eql(u8, call.name, "chdir") or std.mem.eql(u8, call.name, "fchdir")) and std.mem.eql(u8, call.result, "0"))
            process.cwd = if (places[0].attribution == .unresolved) null else places[0];
    }
    var records: std.ArrayList(TraceProcessRecord) = .empty;
    for (processes.keys(), processes.values()) |pid, process| {
        try records.append(arena, .{
            .pid = pid,
            .parent = process.parent,
            .scope = @tagName(traceScope(process)),
            .exit = process.exit orelse return error.InvalidArmUtilLinuxTrace,
        });
    }
    const pid = postinst_pid orelse return error.ArmUtilLinuxPostinstNotObserved;
    const postinst = processes.get(pid).?;
    const expected_argv = [_][]const u8{ observed_postinst, "configure", "" };
    if (postinst_executions != 1 or postinst.parent == null or postinst_argv.len != expected_argv.len)
        return error.ArmUtilLinuxPostinstNotObserved;
    for (expected_argv, postinst_argv) |expected, actual|
        if (!std.mem.eql(u8, expected, actual)) return error.ArmUtilLinuxPostinstNotObserved;
    for ([_][]const u8{ "DPKG_MAINTSCRIPT_PACKAGE=util-linux", "DPKG_MAINTSCRIPT_NAME=postinst", "DPKG_MAINTSCRIPT_ARCH=arm64" }) |required| {
        if (!traceNamed(postinst_environment, required)) return error.ArmUtilLinuxPostinstNotObserved;
    }
    const exit = postinst.exit.?;
    if (!std.mem.startsWith(u8, exit, "exited ")) return error.ArmUtilLinuxPostinstNotObserved;
    return .{
        .lines = std.mem.count(u8, trace, "\n"),
        .postinst_pid = pid,
        .postinst_parent = postinst.parent.?,
        .postinst_exit = std.fmt.parseInt(u8, exit["exited ".len..], 10) catch return error.InvalidArmUtilLinuxTrace,
        .postinst_argv = postinst_argv,
        .postinst_environment = postinst_environment,
        .processes = records.items,
        .executions = executions.items,
        .paths = paths.records.items,
        .host_descriptors = descriptors.records.items,
        .symlinks = symlinks.records.items,
        .confinement = confinement.records.items,
        .network = network.records.items,
        .calls_not_decoded = gaps.records.items,
    };
}

fn observationReport(lock: lock_v3.Lock, script: application.Script, root: []const u8, trace: []const u8, observation: TraceObservation, output: *std.Io.Writer.Allocating) !void {
    var trace_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(trace, &trace_sha256, .{});
    try appendJson(output, .{
        .schema = "https://debz.dev/schema/arm-util-linux-observation-v1",
        .observation_only = true,
        .callback_admitted = false,
        .runtime_proved = false,
        .architecture = "arm64",
        .closure_digest = std.fmt.bytesToHex(try closureDigest(lock), .lower),
        .original_postinst = .{ .mode = script.mode, .size = script.size, .sha256 = std.fmt.bytesToHex(script.sha256, .lower) },
        .root = root,
        .trace = .{ .bytes = trace.len, .lines = observation.lines, .sha256 = std.fmt.bytesToHex(trace_sha256, .lower) },
        .postinst = .{
            .pid = observation.postinst_pid,
            .parent = observation.postinst_parent,
            .exit_status = observation.postinst_exit,
            .argv = observation.postinst_argv,
            .environment = observation.postinst_environment,
        },
        .processes = observation.processes,
        .executions = observation.executions,
        .paths = observation.paths,
        .host_descriptors = observation.host_descriptors,
        .symlinks = observation.symlinks,
        .confinement = observation.confinement,
        .network = observation.network,
        .calls_not_decoded = observation.calls_not_decoded,
        .remaining_authority = [_][]const u8{
            "derive the ARM helper/Perl/systemctl-preset/loader input set from this observation joined with the original native root",
            "target-root unit/preset/helper-state/ld.so.cache ownership and immutable confinement bindings",
            "architecture-specific production profile/binding and callback admission",
            "native callback versus independently pinned dpkg complete pager and fstrim/helper state proof",
            "fresh disposable authenticated 177-package native installation and transaction-result verify",
        },
    });
    try output.writer.writeByte('\n');
}

fn observe(init: std.process.Init, allocator: std.mem.Allocator, args: []const [:0]const u8, offset: usize, protected: bool) !void {
    if (args.len != offset + 6) {
        std.debug.print("usage: debz-arm-util-linux-authority [--protected] observe LOCK CAS ROOT TRACE OUTPUT\n", .{});
        return error.InvalidArguments;
    }
    var host = try fs.openAbsoluteRoot(init.io, "/");
    defer host.close();
    _ = try fs.Path.fromAbsolute(args[offset + 3]);
    if (protected) {
        try protectedPath(host.root, args[offset + 1], false);
        try protectedPath(host.root, args[offset + 2], true);
        try protectedPath(host.root, args[offset + 3], true);
        try protectedPath(host.root, args[offset + 4], false);
        const destination_parent = std.fs.path.dirname(args[offset + 5]) orelse return error.InvalidArguments;
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
    var original = try source(allocator, lock.lock, cache.root, "util-linux", protected);
    defer original.deinit();
    const script = original.model.script(.postinst) orelse return error.InvalidArmUtilLinuxSource;
    var target = try fs.openAbsoluteRoot(init.io, args[offset + 3]);
    defer target.close();
    const staged = try readStable(allocator, target.root, observed_postinst[1..], maximum_postinst_bytes, protected);
    defer allocator.free(staged);
    if (!std.mem.eql(u8, staged, original.model.scriptBytes(script.*))) return error.ArmUtilLinuxPostinstNotObserved;
    const trace_path = try fs.Path.fromAbsolute(args[offset + 4]);
    const trace = try readStable(allocator, host.root, trace_path.text, maximum_trace_bytes, protected);
    defer allocator.free(trace);
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const observation = try observeTrace(arena.allocator(), trace, args[offset + 3]);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try observationReport(lock.lock, script.*, args[offset + 3], trace, observation, &output);
    const destination = try fs.Path.fromAbsolute(args[offset + 5]);
    try host.root.publishFile(destination, output.written(), .{
        .permissions = .fromMode(0o600),
        .overwrite = .fail_if_exists,
    });
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);
    var offset: usize = 1;
    const protected = args.len > offset and std.mem.eql(u8, args[offset], "--protected");
    if (protected) offset += 1;
    if (args.len < offset + 1) return error.InvalidArguments;
    if (std.mem.eql(u8, args[offset], "observe")) return observe(init, allocator, args, offset, protected);
    const compare = std.mem.eql(u8, args[offset], "compare");
    if ((!compare and !std.mem.eql(u8, args[offset], "source")) or
        args.len != offset + (if (compare) @as(usize, 5) else 4))
    {
        std.debug.print("usage: debz-arm-util-linux-authority [--protected] source LOCK CAS OUTPUT | compare LOCK CAS DPKG_EXTRACTED_ROOT OUTPUT | observe LOCK CAS ROOT TRACE OUTPUT\n", .{});
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

const observation_fixture =
    \\100   execve("/usr/bin/unshare", ["unshare", "--mount", "--net", "--pid", "--fork", "--", "/usr/bin/env", "-i", "chroot", "/w/root", "/bin/sh"], ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"]) = 0
    \\100   unshare(CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWPID) = 0
    \\100   mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL) = 0
    \\100   clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xffff9a) = 101
    \\100   wait4(101,  <unfinished ...>
    \\101   execve("/usr/sbin/chroot", ["chroot", "/w/root", "/bin/sh"], ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/", "LC_ALL=C"]) = 0
    \\101   chroot("/w/root")                 = 0
    \\101   chdir("/")                        = 0
    \\101   execve("/bin/sh", ["/bin/sh", "-c", "exec setpriv"], ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/", "LC_ALL=C"]) = 0
    \\101   execve("/var/lib/dpkg/producer-dpkg", ["/var/lib/dpkg/producer-dpkg", "--root=/", "--configure", "util-linux"], ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"]) = 0
    \\101   openat(AT_FDCWD</w/root>, "/var/lib/dpkg/status", O_RDONLY) = 3</w/root/var/lib/dpkg/status>
    \\101   clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xffff9a) = 2 /* 102 in strace's PID NS */
    \\101   wait4(2 /* 102 in strace's PID NS */,  <unfinished ...>
    \\102   chdir("/")                        = 0
    \\102   execve("/var/lib/dpkg/info/util-linux.postinst", ["/var/lib/dpkg/info/util-linux.postinst", "configure", ""], ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "DPKG_MAINTSCRIPT_PACKAGE=util-linux", "DPKG_MAINTSCRIPT_ARCH=arm64", "DPKG_MAINTSCRIPT_NAME=postinst"]) = 0
    \\102   newfstatat(AT_FDCWD</w/root>, "/usr/sbin/update-alternatives", 0xffffd0c9bcb8, 0) = -1 ENOENT (No such file or directory)
    \\102   clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xffff9b) = ? ERESTARTNOINTR (To be restarted)
    \\102   clone(child_stack=0xffffd0c9bcd0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>
    \\103   execve("/usr/bin/update-alternatives", ["update-alternatives", "--install", "/usr/bin/pager", "pager", "/bin/more", "50"], ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"] <unfinished ...>
    \\102   <... clone resumed>)              = 3 /* 103 in strace's PID NS */
    \\102   wait4(-1,  <unfinished ...>
    \\103   <... execve resumed>)             = 0
    \\103   openat(AT_FDCWD</w/root>, "/var/lib/dpkg/alternatives/pager", O_RDONLY) = -1 ENOENT (No such file or directory)
    \\103   symlinkat("/bin/more", AT_FDCWD</w/root>, "/etc/alternatives/pager.dpkg-tmp") = 0
    \\103   renameat(AT_FDCWD</w/root>, "/etc/alternatives/pager.dpkg-tmp", AT_FDCWD</w/root>, "/etc/alternatives/pager") = 0
    \\103   fchmod(1</host/evidence/util-linux-configure.stdout>, 0644) = 0
    \\103   exit_group(0)                     = ?
    \\103   +++ exited with 0 +++
    \\102   <... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 3 /* 103 in strace's PID NS */
    \\102   chdir("/usr")                     = 0
    \\102   openat(AT_FDCWD</w/root/usr>, "lib/aarch64-linux-gnu/perl5/5.40/Data/Dumper.pm", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
    \\102   statx(AT_FDCWD</w/root/usr>, "share/\303\251", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_MODE, {stx_mask=STATX_TYPE|STATX_MODE, stx_mode=S_IFDIR|0755, stx_size=4096, ...}) = 0
    \\102   statfs("lib", 0xffffdab6ed40) = 0
    \\102   socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 5<socket:[123]>
    \\102   getrandom("\x01\x02", 2, 0) = 2
    \\102   exit_group(0)                     = ?
    \\102   +++ exited with 0 +++
    \\101   <... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 2 /* 102 in strace's PID NS */
    \\101   exit_group(0)                     = ?
    \\101   +++ exited with 0 +++
    \\100   <... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 101
    \\100   exit_group(0)                     = ?
    \\100   +++ exited with 0 +++
    \\
;

fn expectObservedPath(observation: TraceObservation, scope: []const u8, call: []const u8, path: []const u8, mutating: bool, result: []const u8) !void {
    for (observation.paths) |record| {
        if (std.mem.eql(u8, record.scope, scope) and std.mem.eql(u8, record.call, call) and
            std.mem.eql(u8, record.attribution, "root") and std.mem.eql(u8, record.path, path) and
            record.mutating == mutating and std.mem.eql(u8, record.result, result))
            return;
    }
    return error.TestExpectedObservedPath;
}

test "ARM util-linux observation attributes the original postinst subtree inside the protected root without admission" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const observation = try observeTrace(arena.allocator(), observation_fixture, "/w/root");
    try std.testing.expectEqual(@as(u32, 102), observation.postinst_pid);
    try std.testing.expectEqual(@as(u32, 101), observation.postinst_parent);
    try std.testing.expectEqual(@as(u8, 0), observation.postinst_exit);
    try std.testing.expectEqualDeep(@as([]const []const u8, &.{ observed_postinst, "configure", "" }), observation.postinst_argv);
    try std.testing.expectEqual(@as(usize, 4), observation.processes.len);
    for (observation.processes, [_][]const u8{ "host", "reference", "postinst", "postinst" }) |process, scope|
        try std.testing.expectEqualStrings(scope, process.scope);
    try std.testing.expectEqual(@as(usize, 6), observation.executions.len);
    try std.testing.expectEqualStrings("/usr/bin/update-alternatives", observation.executions[5].path);
    try std.testing.expectEqualStrings("postinst", observation.executions[5].scope);
    try std.testing.expectEqualStrings("reference", observation.executions[3].scope);
    try expectObservedPath(observation, "postinst", "renameat", "/etc/alternatives/pager", true, "ok");
    try expectObservedPath(observation, "postinst", "openat", "/usr/lib/aarch64-linux-gnu/perl5/5.40/Data/Dumper.pm", false, "ENOENT");
    try expectObservedPath(observation, "postinst", "statx", "/usr/share/\u{e9}", false, "ok");
    try expectObservedPath(observation, "postinst", "statfs", "/usr/lib", false, "ok");
    try expectObservedPath(observation, "reference", "openat", "/var/lib/dpkg/status", false, "ok");
    try std.testing.expectEqual(@as(usize, 1), observation.host_descriptors.len);
    try std.testing.expectEqualStrings("fchmod", observation.host_descriptors[0].call);
    try std.testing.expectEqualStrings("/bin/more", observation.symlinks[0].target);
    try std.testing.expectEqualStrings("/etc/alternatives/pager.dpkg-tmp", observation.symlinks[0].path);
    try std.testing.expectEqual(@as(usize, 3), observation.confinement.len);
    try std.testing.expectEqualStrings("host", observation.confinement[2].scope);
    try std.testing.expectEqualStrings("chroot", observation.confinement[2].call);
    try std.testing.expectEqualStrings("postinst", observation.network[0].scope);
    try std.testing.expectEqualStrings("getrandom", observation.calls_not_decoded[0].call);
}

test "ARM util-linux observation refuses ambiguous, truncated, foreign-root and unobserved postinst traces" {
    const postinst_exec = "[\"/var/lib/dpkg/info/util-linux.postinst\", \"configure\", \"\"]";
    const cases = [_]struct { []const u8, []const u8, anyerror }{
        .{ postinst_exec, "[\"/var/lib/dpkg/info/util-linux.postinst\", \"conf\"...]", error.TruncatedArmUtilLinuxTrace },
        .{ postinst_exec, "[\"/var/lib/dpkg/info/util-linux.postinst\", \"configure\", \"2.40\"]", error.ArmUtilLinuxPostinstNotObserved },
        .{ "\"DPKG_MAINTSCRIPT_ARCH=arm64\", ", "", error.ArmUtilLinuxPostinstNotObserved },
        .{ "102   chdir(\"/usr\")", "102   execve(\"/var/lib/dpkg/info/util-linux.postinst\", " ++ postinst_exec ++ ", [\"DPKG_MAINTSCRIPT_ARCH=arm64\"]) = 0\n102   chdir(\"/usr\")", error.ArmUtilLinuxPostinstNotObserved },
        .{ "102   +++ exited with 0 +++", "102   +++ killed by SIGKILL +++", error.ArmUtilLinuxPostinstNotObserved },
        .{ "100   +++ exited with 0 +++\n", "", error.InvalidArmUtilLinuxTrace },
        .{ "102   chdir(\"/usr\")                     = 0", "102   <... read resumed>) = 0", error.InvalidArmUtilLinuxTrace },
        .{ "102   chdir(\"/usr\")                     = 0", "103   chdir(\"/usr\") = 0", error.InvalidArmUtilLinuxTrace },
        .{ "101   chdir(\"/\")                        = 0", "999   chdir(\"/\") = 0", error.InvalidArmUtilLinuxTrace },
        .{ "100   unshare(", "garbage\n100   unshare(", error.InvalidArmUtilLinuxTrace },
        .{ "103   +++ exited with 0 +++", "103   +++ superseded by execve in pid 102 +++", error.UnsupportedArmUtilLinuxTrace },
        .{ "chroot(\"/w/root\")", "chroot(\"/w/other\")", error.ArmUtilLinuxObservationOutsideRoot },
        .{ "102   chdir(\"/\")", "102   chroot(\"/var\")", error.UnsupportedArmUtilLinuxTrace },
        .{ "[\"PATH=/usr/sbin:/usr/bin:/sbin:/bin\", \"DPKG_MAINTSCRIPT_PACKAGE=util-linux\", \"DPKG_MAINTSCRIPT_ARCH=arm64\", \"DPKG_MAINTSCRIPT_NAME=postinst\"]", "0xffffeb6b56c8 /* 4 vars */", error.UnsupportedArmUtilLinuxTrace },
    };
    for (cases) |case| {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, observation_fixture, case[0]));
        const mutated = try std.mem.replaceOwned(u8, std.testing.allocator, observation_fixture, case[0], case[1]);
        defer std.testing.allocator.free(mutated);
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        try std.testing.expectError(case[2], observeTrace(arena.allocator(), mutated, "/w/root"));
    }
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidArmUtilLinuxTrace, observeTrace(arena.allocator(), observation_fixture[0 .. observation_fixture.len - 1], "/w/root"));
}

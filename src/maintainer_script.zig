//! Audited maintainer-script runner for the native transaction engine.
//!
//! The runner executes one already-validated Debian maintainer script as a
//! child process of the selected root without invoking `dpkg` or `dpkg-deb`
//! and without constructing a shell command. Alternate roots are entered with
//! a chroot-equivalent child setup and working directory `/`; the host root
//! requires the existing explicit host-root policy. Every request is rejected
//! before spawn unless the root, script path, script name, identity,
//! arguments, environment variables, and limits are exactly representable.
//!
//! Package lifecycle ordering, script selection, and filesystem mutation are
//! owned by other native-engine modules. This module owns only the audited
//! child-process boundary and its typed evidence.

const std = @import("std");
const builtin = @import("builtin");
const absolute_path = @import("absolute_path.zig");
const root_fs = @import("root_fs.zig");
const live_root = @import("live_root.zig");

pub const Kind = enum {
    preinst,
    postinst,
    prerm,
    postrm,

    pub fn fileName(self: Kind) []const u8 {
        return @tagName(self);
    }
};

pub const Capture = enum {
    /// Separate bounded stdout and stderr pipes.
    separate,
    /// One bounded pipe shared by stdout and stderr, preserving interleaving.
    combined,
};

/// Whether descendants that outlive the script are terminated with the script
/// process group. The bounded native-engine contract terminates them; `detach`
/// preserves dpkg's behavior of leaving a daemon started by a script running.
pub const DescendantPolicy = enum {
    terminate,
    detach,
};

pub const Limits = struct {
    /// Wall-clock budget for the complete script invocation.
    timeout_ms: u64 = 5 * 60 * 1000,
    /// Grace period between the process-group SIGTERM and the SIGKILL escalation.
    termination_grace_ms: u64 = 5_000,
    /// Bounded interval between cancellation, deadline, and readiness checks.
    poll_interval_ms: u32 = 10,
    /// Bounded window used to drain output written before the script exited.
    descendant_drain_ms: u32 = 100,
    /// Total captured bytes across every captured stream.
    maximum_output_bytes: usize = 64 * 1024,
    maximum_arguments: usize = 8,
    maximum_argument_bytes: usize = 512,
};

pub const maximum_output_limit = 1024 * 1024;
pub const maximum_script_path_bytes = 1024;
pub const maximum_variable_bytes = 256;
/// The umask dpkg's `dpkg_program_init` sets before it runs any script.
pub const script_umask: usize = 0o022;

/// Script directories the runner will execute from. `info` holds installed
/// scripts; `tmp.ci` holds the control members of the package being unpacked.
pub const default_script_directories = [_][]const u8{
    "var/lib/dpkg/info",
    "var/lib/dpkg/tmp.ci",
};

pub const Policy = struct {
    allow_host_root: bool = false,
    capture: Capture = .separate,
    descendants: DescendantPolicy = .terminate,
    snapshot_systemd_proc: bool = false,
    snapshot_udev_proc: bool = false,
    snapshot_sudo_proc: bool = false,
    limits: Limits = .{},
    script_directories: []const []const u8 = &default_script_directories,
};

const snapshot_systemd_sha256 = [32]u8{
    0xd9, 0xdf, 0x6a, 0x03, 0xcc, 0xb6, 0xb5, 0x57,
    0xc1, 0x6a, 0xc1, 0xc6, 0x74, 0x55, 0x7a, 0x66,
    0xc1, 0xdb, 0x29, 0x0f, 0x3c, 0x6d, 0x3c, 0xad,
    0xbe, 0xf3, 0x35, 0xe0, 0xce, 0x74, 0xe3, 0x1d,
};
const snapshot_systemd_postinst_size = 5037;

fn snapshotSystemdIdentity(identity: Identity, arguments: []const []const u8) bool {
    return std.mem.eql(u8, identity.package, "systemd") and
        std.mem.eql(u8, identity.version, "259.5-0ubuntu3.4") and
        std.mem.eql(u8, identity.architecture, "amd64") and
        identity.kind == .postinst and
        std.mem.eql(u8, identity.script_path, "var/lib/dpkg/info/systemd.postinst") and
        std.crypto.timing_safe.eql([32]u8, identity.script_sha256, snapshot_systemd_sha256) and
        arguments.len == 2 and
        std.mem.eql(u8, arguments[0], "configure") and
        arguments[1].len == 0;
}

const snapshot_udev_sha256: [32]u8 = .{
    0xb7, 0x89, 0x2e, 0x97, 0x5b, 0xcc, 0xe8, 0x96,
    0xc4, 0x93, 0x8c, 0x22, 0x19, 0xa2, 0x44, 0xfa,
    0x03, 0x86, 0x3d, 0x5e, 0xff, 0x37, 0xcd, 0x2e,
    0xb6, 0x6d, 0x2b, 0x85, 0x40, 0xf1, 0x46, 0x06,
};
const snapshot_udev_postinst_size = 2578;

fn snapshotUdevIdentity(identity: Identity, arguments: []const []const u8) bool {
    return std.mem.eql(u8, identity.package, "udev") and
        std.mem.eql(u8, identity.version, "259.5-0ubuntu3.4") and
        std.mem.eql(u8, identity.architecture, "amd64") and
        identity.kind == .postinst and
        std.mem.eql(u8, identity.script_path, "var/lib/dpkg/info/udev.postinst") and
        std.crypto.timing_safe.eql([32]u8, identity.script_sha256, snapshot_udev_sha256) and
        arguments.len == 2 and
        std.mem.eql(u8, arguments[0], "configure") and
        arguments[1].len == 0;
}

const snapshot_sudo_sha256: [32]u8 = .{
    0xfd, 0x4c, 0x65, 0x93, 0x2a, 0xb3, 0xab, 0x7c,
    0xe9, 0x0c, 0x36, 0x33, 0xc4, 0x2b, 0x8e, 0xe7,
    0xa3, 0x6a, 0xf2, 0xc8, 0x29, 0x21, 0x42, 0xd6,
    0xe0, 0xcd, 0x13, 0x4d, 0xda, 0x4c, 0x63, 0x83,
};
const snapshot_sudo_postinst_size = 1747;

fn snapshotSudoIdentity(identity: Identity, arguments: []const []const u8) bool {
    return std.mem.eql(u8, identity.package, "sudo") and
        std.mem.eql(u8, identity.version, "1.9.17p2-1ubuntu3.1") and
        std.mem.eql(u8, identity.architecture, "amd64") and
        identity.kind == .postinst and
        std.mem.eql(u8, identity.script_path, "var/lib/dpkg/info/sudo.postinst") and
        std.crypto.timing_safe.eql([32]u8, identity.script_sha256, snapshot_sudo_sha256) and
        arguments.len == 2 and
        std.mem.eql(u8, arguments[0], "configure") and
        arguments[1].len == 0;
}

pub const Identity = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    kind: Kind,
    /// Root-relative canonical path of the exact validated script file.
    script_path: []const u8,
    /// SHA-256 of the exact script bytes the caller validated before the request.
    script_sha256: [32]u8,
};

/// Additional maintainer-script variables the lifecycle caller may set. The
/// allowlist is closed; no ambient environment value is ever inherited.
pub const VariableName = enum {
    package_refcount,
    running_version,

    pub fn key(self: VariableName) []const u8 {
        return switch (self) {
            .package_refcount => "DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT",
            .running_version => "DPKG_RUNNING_VERSION",
        };
    }
};

pub const Variable = struct {
    name: VariableName,
    value: []const u8,
};

pub const EnvironmentEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const HelperEvidence = struct {
    source_path: []const u8,
    target_path: []const u8,
    sha256: [32]u8,
};

var helper_digest_count: std.atomic.Value(u64) = .init(0);

/// Test seam: pinned helper source hashes so far, at bind and at launch.
pub fn helperDigestCount() u64 {
    if (!builtin.is_test) @compileError("helperDigestCount is a test seam");
    return helper_digest_count.load(.monotonic);
}

/// One verified helper and existing target, pinned for a single invocation.
/// The caller keeps the root and this binding alive until execution returns.
pub const HelperMount = struct {
    allocator: std.mem.Allocator,
    root_path: []const u8,
    evidence: HelperEvidence,
    source: root_fs.PinnedRegularFile,
    target: root_fs.PinnedRegularFile,

    pub fn init(
        allocator: std.mem.Allocator,
        root: root_fs.Root,
        source_path: []const u8,
        target_path: []const u8,
        expected_sha256: [32]u8,
    ) !HelperMount {
        var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const root_length = try root.dir.realPath(root.io, &root_buffer);
        const root_path = try allocator.dupe(u8, root_buffer[0..root_length]);
        errdefer allocator.free(root_path);
        const source_name = try allocator.dupe(u8, source_path);
        errdefer allocator.free(source_name);
        const target_name = try allocator.dupe(u8, target_path);
        errdefer allocator.free(target_name);
        var source = try root.pinRegularFile(try root_fs.Path.init(source_name));
        errdefer source.close();
        var target = try root.pinRegularFile(try root_fs.Path.init(target_name));
        errdefer target.close();
        var result: HelperMount = .{
            .allocator = allocator,
            .root_path = root_path,
            .evidence = .{
                .source_path = source_name,
                .target_path = target_name,
                .sha256 = expected_sha256,
            },
            .source = source,
            .target = target,
        };
        try result.verify(allocator);
        return result;
    }

    pub fn verify(self: *const HelperMount, allocator: std.mem.Allocator) !void {
        const observed = try self.source.observeAlloc(allocator, 32 * 1024 * 1024);
        defer allocator.free(observed.bytes);
        if (observed.entry.mode & 0o111 == 0) return error.HelperNotExecutable;
        if (builtin.is_test) _ = helper_digest_count.fetchAdd(1, .monotonic);
        var sha256: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(observed.bytes, &sha256, .{});
        if (!std.mem.eql(u8, &sha256, &self.evidence.sha256))
            return error.HelperDigestMismatch;
        _ = try self.target.metadata();
    }

    pub fn deinit(self: *HelperMount) void {
        self.source.close();
        self.target.close();
        self.allocator.free(self.root_path);
        self.allocator.free(self.evidence.source_path);
        self.allocator.free(self.evidence.target_path);
        self.* = undefined;
    }
};

pub const SnapshotSystemdProc = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,
    directory: root_fs.PinnedDirectory,
    script: root_fs.PinnedRegularFile,
    boot_id: [37]u8,
    root_stat: std.os.linux.Statx,
    directory_stat: std.os.linux.Statx,

    pub fn init(
        allocator: std.mem.Allocator,
        root: root_fs.Root,
    ) !SnapshotSystemdProc {
        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path_length = try root.dir.realPath(root.io, &path_buffer);
        const root_path = try allocator.dupe(u8, path_buffer[0..path_length]);
        errdefer allocator.free(root_path);
        var directory = try root.pinDirectory(try root_fs.Path.init("proc"));
        errdefer directory.close();
        var contents = try directory.observeAlloc(allocator, 0, 0);
        contents.deinit();
        const entry = (try directory.metadata()).entry;
        if (!entry.modeled or entry.uid != 0 or entry.gid != 0 or
            entry.mode != 0o755 or entry.kind != .directory)
            return error.InvalidSnapshotProcMountpoint;
        var script = try root.pinRegularFile(
            try root_fs.Path.init("var/lib/dpkg/info/systemd.postinst"),
        );
        errdefer script.close();
        var result: SnapshotSystemdProc = .{
            .allocator = allocator,
            .root_path = root_path,
            .directory = directory,
            .script = script,
            .boot_id = try readKernelBootId(),
            .root_stat = undefined,
            .directory_stat = undefined,
        };
        try result.verify(allocator);
        if (helperStat(root.dir.handle, &result.root_stat) != .SUCCESS or
            helperStat(directory.dir.handle, &result.directory_stat) != .SUCCESS)
            return error.InvalidSnapshotProcMountpoint;
        if (result.root_stat.uid != 0 or result.root_stat.gid != 0)
            return error.InvalidSnapshotProcMountpoint;
        return result;
    }

    pub fn verify(self: *const SnapshotSystemdProc, allocator: std.mem.Allocator) !void {
        const entry = (try self.directory.metadata()).entry;
        if (!entry.modeled or entry.uid != 0 or entry.gid != 0 or
            entry.mode != 0o755 or entry.kind != .directory)
            return error.InvalidSnapshotProcMountpoint;
        var contents = try self.directory.observeAlloc(allocator, 0, 0);
        contents.deinit();
        const observed = try self.script.observeAlloc(allocator, 8192);
        defer allocator.free(observed.bytes);
        if (observed.entry.uid != 0 or observed.entry.gid != 0 or
            observed.entry.mode != 0o755 or observed.entry.link_count != 1 or
            observed.entry.size != snapshot_systemd_postinst_size)
            return error.InvalidSnapshotSystemdScript;
        if (!std.crypto.timing_safe.eql(
            [32]u8,
            hashBytes(observed.bytes),
            snapshot_systemd_sha256,
        )) return error.InvalidSnapshotSystemdScript;
        if (!std.mem.eql(u8, &self.boot_id, &(try readKernelBootId())))
            return error.SnapshotBootIdChanged;
    }

    pub fn deinit(self: *SnapshotSystemdProc) void {
        self.directory.close();
        self.script.close();
        self.allocator.free(self.root_path);
        self.* = undefined;
    }
};

const SnapshotUdevInput = struct {
    path: []const u8,
    size: u64,
    mode: u16,
    sha256: []const u8,
};

const snapshot_udev_inputs = [_]SnapshotUdevInput{
    .{ .path = "usr/bin/dash", .size = 129856, .mode = 0o755, .sha256 = "c626229526bb58ec2d0f585f3c3ae1412e6f973b4353385042d11c38d8426917" },
    .{ .path = "usr/bin/dpkg", .size = 322728, .mode = 0o755, .sha256 = "972003a11f3ae0f5b2556dce1d2c2721fb5119818b9bbef1124293024fdb6517" },
    .{ .path = "usr/bin/systemd-hwdb", .size = 14784, .mode = 0o755, .sha256 = "3502e34f903759c07465fc50b1e9406d89325cb6cc6605f4225d3231ba0a7dfc" },
    .{ .path = "usr/bin/systemd-sysusers", .size = 68224, .mode = 0o755, .sha256 = "09586bca83f4ea590a821c2bd712bef44f7b8b55f0186085cfdcd023b9d0da1f" },
    .{ .path = "usr/bin/systemd-tmpfiles", .size = 121544, .mode = 0o755, .sha256 = "13f968f41bac6dfdca7dc4fb346551b8a02e5ff148da3384f48fe04d37246fb4" },
    .{ .path = "usr/bin/dpkg-maintscript-helper", .size = 21123, .mode = 0o755, .sha256 = "1cd744cc0b6371329a6a5dbcf459329a08f8632b5f71e18463d0f0749fd0265d" },
    .{ .path = "usr/bin/deb-systemd-helper", .size = 24358, .mode = 0o755, .sha256 = "a895d5f077651960b6ca4ed9c53f8b36eae422ae170f61c972d0c6579e9f8732" },
    .{ .path = "usr/sbin/update-rc.d", .size = 18147, .mode = 0o755, .sha256 = "9a85792c1ee2714d34ad2f0dac9becd987cbaedbfe25519dede7378e6c9ebbf1" },
    .{ .path = "usr/bin/systemctl", .size = 302112, .mode = 0o755, .sha256 = "6394f5e8df92878184de9d4dfb7ac242471cb09daf89d23be4e81ae17e9c03b2" },
    .{ .path = "usr/bin/deb-systemd-invoke", .size = 7135, .mode = 0o755, .sha256 = "92eadae89f4df4cd6088f6316f5390b685faf8d0e312a4e5af3a507caaf81bdb" },
    .{ .path = "usr/lib/tmpfiles.d/static-nodes-permissions.conf", .size = 798, .mode = 0o644, .sha256 = "ca4849c27428fd648f6377dd51a3ab0eb79de69fce1bdc910670012c0cf26f85" },
    .{ .path = "usr/lib/sysusers.d/debian-udev.conf", .size = 143, .mode = 0o644, .sha256 = "e9493928a4ed5399c5619cee0559644099f0625075606baca35b40533286b5e0" },
};

const snapshot_udev_overrides = [_][]const u8{
    "etc/tmpfiles.d/static-nodes-permissions.conf",
    "run/tmpfiles.d/static-nodes-permissions.conf",
    "usr/local/lib/tmpfiles.d/static-nodes-permissions.conf",
    "etc/sysusers.d/debian-udev.conf",
    "run/sysusers.d/debian-udev.conf",
    "usr/local/lib/sysusers.d/debian-udev.conf",
};

const snapshot_udev_path_shadows = [_][]const u8{
    "usr/sbin/dpkg",
    "usr/sbin/systemd-hwdb",
    "usr/sbin/systemd-sysusers",
    "usr/sbin/systemd-tmpfiles",
    "usr/sbin/dpkg-maintscript-helper",
    "usr/sbin/deb-systemd-helper",
    "usr/sbin/systemctl",
    "usr/sbin/deb-systemd-invoke",
};

pub const SnapshotUdevProc = struct {
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    root_path: []u8,
    directory: root_fs.PinnedDirectory,
    script: root_fs.PinnedRegularFile,
    bin: root_fs.PinnedSymbolicLink,
    shell: root_fs.PinnedSymbolicLink,
    inputs: [snapshot_udev_inputs.len]root_fs.PinnedRegularFile,
    root_stat: std.os.linux.Statx,
    directory_stat: std.os.linux.Statx,

    pub fn init(allocator: std.mem.Allocator, root: root_fs.Root) !SnapshotUdevProc {
        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path_length = try root.dir.realPath(root.io, &path_buffer);
        const root_path = try allocator.dupe(u8, path_buffer[0..path_length]);
        errdefer allocator.free(root_path);
        var directory = try root.pinDirectory(try root_fs.Path.init("proc"));
        errdefer directory.close();
        var contents = try directory.observeAlloc(allocator, 0, 0);
        contents.deinit();
        var script = try root.pinRegularFile(
            try root_fs.Path.init("var/lib/dpkg/info/udev.postinst"),
        );
        errdefer script.close();
        var bin = try root.pinSymbolicLink(try root_fs.Path.init("bin"));
        errdefer bin.close();
        var shell = try root.pinSymbolicLink(try root_fs.Path.init("usr/bin/sh"));
        errdefer shell.close();
        var inputs: [snapshot_udev_inputs.len]root_fs.PinnedRegularFile = undefined;
        var count: usize = 0;
        errdefer for (inputs[0..count]) |*input| input.close();
        for (snapshot_udev_inputs, &inputs) |binding, *slot| {
            slot.* = try root.pinRegularFile(try root_fs.Path.init(binding.path));
            count += 1;
        }
        var result: SnapshotUdevProc = .{
            .allocator = allocator,
            .root = root,
            .root_path = root_path,
            .directory = directory,
            .script = script,
            .bin = bin,
            .shell = shell,
            .inputs = inputs,
            .root_stat = undefined,
            .directory_stat = undefined,
        };
        try result.verify(allocator);
        if (helperStat(root.dir.handle, &result.root_stat) != .SUCCESS or
            helperStat(directory.dir.handle, &result.directory_stat) != .SUCCESS or
            result.root_stat.uid != 0 or result.root_stat.gid != 0 or
            result.root_stat.mode != 0o40700)
            return error.InvalidSnapshotUdevRoot;
        return result;
    }

    pub fn verify(self: *const SnapshotUdevProc, allocator: std.mem.Allocator) !void {
        const entry = (try self.directory.metadata()).entry;
        if (!entry.modeled or entry.uid != 0 or entry.gid != 0 or
            entry.mode != 0o755 or entry.kind != .directory)
            return error.InvalidSnapshotUdevMountpoint;
        var contents = try self.directory.observeAlloc(allocator, 0, 0);
        contents.deinit();
        for (snapshot_udev_overrides) |path| {
            if (try self.root.entryIfExists(try root_fs.Path.init(path)) != null)
                return error.InvalidSnapshotUdevControl;
        }
        for (snapshot_udev_path_shadows) |path| {
            if (try self.root.entryIfExists(try root_fs.Path.init(path)) != null)
                return error.InvalidSnapshotUdevTool;
        }
        const observed = try self.script.observeStableAlloc(
            allocator,
            snapshot_udev_postinst_size,
        );
        defer allocator.free(observed.bytes);
        if (observed.entry.uid != 0 or observed.entry.gid != 0 or
            observed.entry.mode != 0o755 or observed.entry.link_count != 1 or
            observed.entry.size != snapshot_udev_postinst_size or
            !std.crypto.timing_safe.eql(
                [32]u8,
                hashBytes(observed.bytes),
                snapshot_udev_sha256,
            )) return error.InvalidSnapshotUdevScript;
        var bin_target: [16]u8 = undefined;
        const bin = try self.bin.observe(&bin_target);
        if (bin.entry.uid != 0 or bin.entry.gid != 0 or
            bin.entry.mode != 0o777 or bin.entry.link_count != 1 or
            !std.mem.eql(u8, bin.target, "usr/bin"))
            return error.InvalidSnapshotUdevTool;
        var shell_target: [16]u8 = undefined;
        const shell = try self.shell.observe(&shell_target);
        if (shell.entry.uid != 0 or shell.entry.gid != 0 or
            shell.entry.mode != 0o777 or shell.entry.link_count != 1 or
            !std.mem.eql(u8, shell.target, "dash"))
            return error.InvalidSnapshotUdevTool;
        for (snapshot_udev_inputs, &self.inputs) |binding, *file| {
            const input = try file.observeStableAlloc(allocator, @intCast(binding.size));
            defer allocator.free(input.bytes);
            var expected: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&expected, binding.sha256) catch unreachable;
            if (input.entry.uid != 0 or input.entry.gid != 0 or
                input.entry.mode != binding.mode or input.entry.link_count != 1 or
                input.entry.size != binding.size or
                !std.crypto.timing_safe.eql([32]u8, hashBytes(input.bytes), expected))
                return error.InvalidSnapshotUdevTool;
        }
    }

    pub fn deinit(self: *SnapshotUdevProc) void {
        for (&self.inputs) |*input| input.close();
        self.shell.close();
        self.bin.close();
        self.script.close();
        self.directory.close();
        self.allocator.free(self.root_path);
        self.* = undefined;
    }
};

const snapshot_sudo_inputs = [_]SnapshotUdevInput{
    .{ .path = "usr/bin/dash", .size = 129856, .mode = 0o755, .sha256 = "c626229526bb58ec2d0f585f3c3ae1412e6f973b4353385042d11c38d8426917" },
    .{ .path = "usr/bin/dpkg", .size = 322728, .mode = 0o755, .sha256 = "972003a11f3ae0f5b2556dce1d2c2721fb5119818b9bbef1124293024fdb6517" },
    .{ .path = "usr/bin/dpkg-query", .size = 142160, .mode = 0o755, .sha256 = "82a19acac53907f83faca7d6494289fe2d074514cf1b09933114635415c2e876" },
    .{ .path = "usr/bin/systemd-tmpfiles", .size = 121544, .mode = 0o755, .sha256 = "13f968f41bac6dfdca7dc4fb346551b8a02e5ff148da3384f48fe04d37246fb4" },
    .{ .path = "usr/bin/dpkg-maintscript-helper", .size = 21123, .mode = 0o755, .sha256 = "1cd744cc0b6371329a6a5dbcf459329a08f8632b5f71e18463d0f0749fd0265d" },
    .{ .path = "usr/share/dpkg/sh/dpkg-error.sh", .size = 3228, .mode = 0o644, .sha256 = "d4d4fd7712da692dbb21a10795f7e62046c90b506338768b5a93cf9f1897f528" },
    .{ .path = "usr/bin/update-alternatives", .size = 59864, .mode = 0o755, .sha256 = "023e1c2eef9f323f6f2c2f53aa22092cd118b1f087349ce133a677f94a03ed45" },
    .{ .path = "usr/bin/gnurm", .size = 64096, .mode = 0o755, .sha256 = "0362781f855d9de6396b71af947662758970ed09946c4a0a78ff740b20f5e6a6" },
    .{ .path = "usr/bin/gnuchown", .size = 68160, .mode = 0o755, .sha256 = "0e04f6401bfae9a5eafed1da2c738067b007d39a8538ea83ce22271b4cd58fbb" },
    .{ .path = "usr/bin/gnuchmod", .size = 60000, .mode = 0o755, .sha256 = "787b5abd2db66069fdd2467bf3b6acb089380aa0b4c05771f3c1b2471a24bf94" },
    .{ .path = "usr/lib/tmpfiles.d/sudo.conf", .size = 27, .mode = 0o644, .sha256 = "eed7eb9d7ddaccb3ae13d3225de1302a96754938fea4dc305c43b64cbcb5d0bc" },
    .{ .path = "var/lib/dpkg/info/sudo.list", .size = 2376, .mode = 0o644, .sha256 = "39fe94bdbeab0a80b3aaeae4cfa258be578949b791aeb06875ddf9d488387bc8" },
    .{ .path = "usr/bin/sudo.ws", .size = 282080, .mode = 0o4755, .sha256 = "e3886de6023478ef338471aca89d36888d84216484795035165aee9b142f6a43" },
    .{ .path = "usr/share/man/man8/sudo.ws.8.gz", .size = 12804, .mode = 0o644, .sha256 = "43b6a4b66f9eb6a430f64e2b25084a100b2e152cfd8896cb83f9ced170793d75" },
};

const snapshot_sudo_overrides = [_][]const u8{
    "etc/tmpfiles.d/sudo.conf",
    "run/tmpfiles.d/sudo.conf",
    "usr/local/lib/tmpfiles.d/sudo.conf",
};

const snapshot_sudo_shadows = [_][]const u8{
    "usr/sbin/dpkg",
    "usr/sbin/dpkg-query",
    "usr/sbin/systemd-tmpfiles",
    "usr/sbin/dpkg-maintscript-helper",
    "usr/sbin/update-alternatives",
    "usr/sbin/rm",
    "usr/sbin/chown",
    "usr/sbin/chmod",
};

const snapshot_sudo_aliases = [_]struct { path: []const u8, target: []const u8 }{
    .{ .path = "bin", .target = "usr/bin" },
    .{ .path = "sbin", .target = "usr/sbin" },
    .{ .path = "usr/bin/sh", .target = "dash" },
    .{ .path = "usr/bin/rm", .target = "gnurm" },
    .{ .path = "usr/bin/chown", .target = "gnuchown" },
    .{ .path = "usr/bin/chmod", .target = "gnuchmod" },
};

pub const SnapshotSudoProc = struct {
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    root_path: []u8,
    directory: root_fs.PinnedDirectory,
    script: root_fs.PinnedRegularFile,
    aliases: [snapshot_sudo_aliases.len]root_fs.PinnedSymbolicLink,
    inputs: [snapshot_sudo_inputs.len]root_fs.PinnedRegularFile,
    root_stat: std.os.linux.Statx,
    directory_stat: std.os.linux.Statx,

    pub fn init(allocator: std.mem.Allocator, root: root_fs.Root) !SnapshotSudoProc {
        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path_length = try root.dir.realPath(root.io, &path_buffer);
        const root_path = try allocator.dupe(u8, path_buffer[0..path_length]);
        errdefer allocator.free(root_path);
        var directory = try root.pinDirectory(try root_fs.Path.init("proc"));
        errdefer directory.close();
        var contents = try directory.observeAlloc(allocator, 0, 0);
        contents.deinit();
        var script = try root.pinRegularFile(
            try root_fs.Path.init("var/lib/dpkg/info/sudo.postinst"),
        );
        errdefer script.close();
        var aliases: [snapshot_sudo_aliases.len]root_fs.PinnedSymbolicLink = undefined;
        var alias_count: usize = 0;
        errdefer for (aliases[0..alias_count]) |*alias| alias.close();
        for (snapshot_sudo_aliases, &aliases) |binding, *slot| {
            slot.* = try root.pinSymbolicLink(try root_fs.Path.init(binding.path));
            alias_count += 1;
        }
        var inputs: [snapshot_sudo_inputs.len]root_fs.PinnedRegularFile = undefined;
        var input_count: usize = 0;
        errdefer for (inputs[0..input_count]) |*input| input.close();
        for (snapshot_sudo_inputs, &inputs) |binding, *slot| {
            slot.* = try root.pinRegularFile(try root_fs.Path.init(binding.path));
            input_count += 1;
        }
        var result: SnapshotSudoProc = .{
            .allocator = allocator,
            .root = root,
            .root_path = root_path,
            .directory = directory,
            .script = script,
            .aliases = aliases,
            .inputs = inputs,
            .root_stat = undefined,
            .directory_stat = undefined,
        };
        try result.verify(allocator);
        if (helperStat(root.dir.handle, &result.root_stat) != .SUCCESS or
            helperStat(directory.dir.handle, &result.directory_stat) != .SUCCESS or
            result.root_stat.uid != 0 or result.root_stat.gid != 0 or
            result.root_stat.mode != 0o40700)
            return error.InvalidSnapshotSudoRoot;
        return result;
    }

    pub fn verify(self: *const SnapshotSudoProc, allocator: std.mem.Allocator) !void {
        const entry = (try self.directory.metadata()).entry;
        if (!entry.modeled or entry.uid != 0 or entry.gid != 0 or
            entry.mode != 0o755 or entry.kind != .directory)
            return error.InvalidSnapshotSudoMountpoint;
        var contents = try self.directory.observeAlloc(allocator, 0, 0);
        contents.deinit();
        for (snapshot_sudo_overrides) |path| {
            if (try self.root.entryIfExists(try root_fs.Path.init(path)) != null)
                return error.InvalidSnapshotSudoControl;
        }
        for (snapshot_sudo_shadows) |path| {
            if (try self.root.entryIfExists(try root_fs.Path.init(path)) != null)
                return error.InvalidSnapshotSudoTool;
        }
        const observed = try self.script.observeStableAlloc(
            allocator,
            snapshot_sudo_postinst_size,
        );
        defer allocator.free(observed.bytes);
        if (observed.entry.uid != 0 or observed.entry.gid != 0 or
            observed.entry.mode != 0o755 or observed.entry.link_count != 1 or
            observed.entry.size != snapshot_sudo_postinst_size or
            !std.crypto.timing_safe.eql(
                [32]u8,
                hashBytes(observed.bytes),
                snapshot_sudo_sha256,
            )) return error.InvalidSnapshotSudoScript;
        for (snapshot_sudo_aliases, &self.aliases) |binding, *alias| {
            var target_buffer: [64]u8 = undefined;
            const link = try alias.observe(&target_buffer);
            if (link.entry.uid != 0 or link.entry.gid != 0 or
                link.entry.mode != 0o777 or link.entry.link_count != 1 or
                !std.mem.eql(u8, link.target, binding.target))
                return error.InvalidSnapshotSudoTool;
        }
        for (snapshot_sudo_inputs, &self.inputs) |binding, *file| {
            const input = try file.observeStableAlloc(allocator, @intCast(binding.size));
            defer allocator.free(input.bytes);
            var expected: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&expected, binding.sha256) catch unreachable;
            if (input.entry.uid != 0 or input.entry.gid != 0 or
                input.entry.mode != binding.mode or input.entry.link_count != 1 or
                input.entry.size != binding.size or
                !std.crypto.timing_safe.eql([32]u8, hashBytes(input.bytes), expected))
                return error.InvalidSnapshotSudoTool;
        }
    }

    pub fn deinit(self: *SnapshotSudoProc) void {
        for (&self.inputs) |*input| input.close();
        for (&self.aliases) |*alias| alias.close();
        self.script.close();
        self.directory.close();
        self.allocator.free(self.root_path);
        self.* = undefined;
    }
};

const SnapshotProcMode = enum { systemd, udev, sudo };
pub const SnapshotProcBinding = union(SnapshotProcMode) {
    systemd: *const SnapshotSystemdProc,
    udev: *const SnapshotUdevProc,
    sudo: *const SnapshotSudoProc,
};

fn readKernelBootId() ![37]u8 {
    const flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    };
    const how: MountOpenHow = .{
        .flags = @as(u32, @bitCast(flags)),
        .resolve = 0x02 | 0x04,
    };
    const opened = linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr("/proc/sys/kernel/random/boot_id"),
        @intFromPtr(&how),
        @sizeOf(MountOpenHow),
    );
    if (linux.errno(opened) != .SUCCESS) return error.KernelBootIdUnavailable;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);
    var metadata: linux.Statx = undefined;
    if (helperStat(fd, &metadata) != .SUCCESS or
        metadata.uid != 0 or metadata.gid != 0 or
        metadata.mode != 0o100444 or metadata.nlink != 1)
        return error.InvalidKernelBootId;
    var bytes: [38]u8 = undefined;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = linux.read(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (linux.errno(count)) {
            .SUCCESS => if (count == 0) break else {
                offset += count;
            },
            .INTR => continue,
            else => return error.KernelBootIdUnavailable,
        }
    }
    if (offset != 37 or bytes[36] != '\n') return error.InvalidKernelBootId;
    for (bytes[0..36], 0..) |byte, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (byte != '-') return error.InvalidKernelBootId;
        } else if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) {
            return error.InvalidKernelBootId;
        }
    }
    return bytes[0..37].*;
}

pub const Request = struct {
    /// Absolute canonical path of the selected root.
    root: []const u8,
    identity: Identity,
    /// Exact maintainer-script arguments, without argv[0].
    arguments: []const []const u8 = &.{},
    variables: []const Variable = &.{},
    policy: Policy = .{},
    helper_mount: ?*const HelperMount = null,
    snapshot_proc: ?SnapshotProcBinding = null,
};

pub const Isolation = enum {
    /// Alternate root entered with a chroot-equivalent child setup.
    chroot,
    /// Host root, permitted only by explicit policy.
    host_root,
};

pub const RejectionReason = enum {
    invalid_root,
    host_root_denied,
    invalid_script_path,
    script_directory_denied,
    invalid_script_name,
    invalid_package,
    invalid_version,
    invalid_architecture,
    invalid_argument,
    too_many_arguments,
    invalid_variable,
    duplicate_variable,
    invalid_timeout,
    invalid_output_limit,
    invalid_script_directory,
    invalid_snapshot_proc,
};

pub const SetupStage = enum {
    /// Output or status pipe creation failed.
    pipe,
    /// `/dev/null` could not be opened for the child's stdin.
    stdin_device,
    /// A private network namespace could not be created before spawn.
    network_namespace,
    fork,
    /// The child could not create its own session and process group.
    session,
    /// Child stdin/stdout/stderr installation failed.
    standard_streams,
    /// Root entry or private helper namespace setup failed.
    root_isolation,
    /// Private loopback setup failed inside the child namespace.
    network_setup,
    snapshot_proc,
    working_directory,
    /// `execve` of the script failed.
    execute,
    /// The injected launcher failed before or during the child lifecycle.
    launcher,
    /// The child could not be observed or reaped.
    wait,
};

pub const SetupFailure = struct {
    stage: SetupStage,
    /// Operating-system error number, or 0 when none was reported.
    errno: u32 = 0,
};

/// Outcome of a spawned script. Normal exit, signal, timeout, cancellation,
/// setup failure, and output-limit failure remain exactly distinguishable.
pub const LaunchOutcome = union(enum) {
    exited: u8,
    signaled: u32,
    timed_out,
    cancelled,
    setup_failed: SetupFailure,
    output_limit_exceeded,
};

/// Complete outcome, including requests rejected before any child existed.
pub const Outcome = union(enum) {
    exited: u8,
    signaled: u32,
    timed_out,
    cancelled,
    setup_failed: SetupFailure,
    output_limit_exceeded,
    rejected: RejectionReason,

    pub fn fromLaunch(outcome: LaunchOutcome) Outcome {
        return switch (outcome) {
            .exited => |code| .{ .exited = code },
            .signaled => |signal| .{ .signaled = signal },
            .timed_out => .timed_out,
            .cancelled => .cancelled,
            .setup_failed => |failure| .{ .setup_failed = failure },
            .output_limit_exceeded => .output_limit_exceeded,
        };
    }

    /// Whether a child process was actually created.
    pub fn spawned(self: Outcome) bool {
        return switch (self) {
            .exited, .signaled, .timed_out, .cancelled, .output_limit_exceeded => true,
            .setup_failed => |failure| switch (failure.stage) {
                .root_isolation,
                .working_directory,
                .execute,
                .session,
                .standard_streams,
                .network_setup,
                => true,
                .network_namespace,
                .snapshot_proc,
                .pipe,
                .stdin_device,
                .fork,
                .launcher,
                .wait,
                => false,
            },
            .rejected => false,
        };
    }
};

pub const Cancellation = struct {
    context: *anyopaque,
    cancelledFn: *const fn (*anyopaque) bool,

    pub fn cancelled(self: Cancellation) bool {
        return self.cancelledFn(self.context);
    }

    pub fn never() Cancellation {
        return .{
            .context = @ptrCast(@constCast(&never_context)),
            .cancelledFn = neverCancelled,
        };
    }

    fn neverCancelled(_: *anyopaque) bool {
        return false;
    }
};

const never_context: u8 = 0;

/// Fully validated child description. Nothing here is derived from ambient
/// process state: the environment is replaced, stdin is `/dev/null`, and the
/// program is an absolute path inside the selected root.
pub const Invocation = struct {
    /// Absolute host path of the selected root.
    root: []const u8,
    isolation: Isolation,
    /// Absolute path of the script as seen from inside the selected root.
    program: []const u8,
    /// Complete argv, including argv[0].
    argv: []const []const u8,
    environment: []const EnvironmentEntry,
    capture: Capture,
    descendants: DescendantPolicy,
    limits: Limits,
    cancellation: Cancellation,
    helper_mount: ?*const HelperMount = null,
    snapshot_proc: ?SnapshotProcBinding = null,
    identity: ?Identity = null,
};

pub const Execution = struct {
    outcome: LaunchOutcome,
    stdout: []u8 = &.{},
    stderr: []u8 = &.{},
    combined: []u8 = &.{},
    /// The runner had to terminate the still-running script's process group.
    terminated_process_group: bool = false,
    escalated_to_kill: bool = false,
    /// A final group-wide `SIGKILL` sweep was issued under the `terminate`
    /// descendant policy before the script was reaped. It records that the
    /// sweep was delivered to the process group, not that survivors existed:
    /// whether any descendant was still alive is not observable here.
    issued_descendant_sweep: bool = false,

    pub fn deinit(self: *Execution, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        allocator.free(self.combined);
        self.* = undefined;
    }
};

/// Injection seam for the audited child boundary. Hermetic tests replace it;
/// production uses `SystemLauncher`.
pub const Launcher = struct {
    context: *anyopaque,
    launchFn: *const fn (*anyopaque, std.mem.Allocator, Invocation) anyerror!Execution,

    pub fn launch(
        self: Launcher,
        allocator: std.mem.Allocator,
        invocation: Invocation,
    ) !Execution {
        return self.launchFn(self.context, allocator, invocation);
    }
};

pub const Dependencies = struct {
    launcher: Launcher,
    cancellation: Cancellation = Cancellation.never(),
};

pub const Evidence = struct {
    script_sha256: [32]u8,
    argv_sha256: [32]u8,
    environment_sha256: [32]u8,
    policy_sha256: [32]u8,
    invocation_sha256: [32]u8,
    stdout_sha256: [32]u8,
    stderr_sha256: [32]u8,
    combined_sha256: [32]u8,
};

pub const Report = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    identity: Identity,
    root: []const u8,
    isolation: Isolation,
    program: []const u8,
    argv: []const []const u8,
    environment: []const EnvironmentEntry,
    capture: Capture,
    descendants: DescendantPolicy,
    outcome: Outcome,
    stdout: []const u8,
    stderr: []const u8,
    combined: []const u8,
    output_bytes: usize,
    output_limit: usize,
    terminated_process_group: bool,
    escalated_to_kill: bool,
    /// A group-wide `SIGKILL` sweep was issued under the `terminate`
    /// descendant policy. It never claims that descendants existed.
    issued_descendant_sweep: bool,
    evidence: Evidence,
    helper: ?HelperEvidence = null,

    pub fn succeeded(self: Report) bool {
        return switch (self.outcome) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    pub fn deinit(self: *Report) void {
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
        self.* = undefined;
    }
};

/// Runs one maintainer script. Rejected requests never spawn a process and are
/// reported with an exact `rejected` outcome instead of an untyped error.
pub fn run(
    allocator: std.mem.Allocator,
    request: Request,
    dependencies: Dependencies,
) !Report {
    const arena_ptr = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena_ptr);
    arena_ptr.* = .init(allocator);
    errdefer arena_ptr.deinit();
    const arena = arena_ptr.allocator();

    // The report outlives the caller's request buffers, so every reported
    // string is owned by the report arena.
    const owned = try cloneRequest(arena, request);
    const isolation: Isolation = if (std.mem.eql(u8, owned.root, "/"))
        .host_root
    else
        .chroot;
    const program = try std.fmt.allocPrint(arena, "/{s}", .{owned.identity.script_path});
    const argv = try buildArgv(arena, program, owned.arguments);
    const environment = try buildEnvironment(arena, owned);
    const evidence_base = digests(owned, isolation, argv, environment);
    const helper: ?HelperEvidence = if (owned.helper_mount) |mount| .{
        .source_path = try arena.dupe(u8, mount.evidence.source_path),
        .target_path = try arena.dupe(u8, mount.evidence.target_path),
        .sha256 = mount.evidence.sha256,
    } else null;

    if (validate(owned)) |reason| {
        return .{
            .allocator = allocator,
            .arena = arena_ptr,
            .identity = owned.identity,
            .root = owned.root,
            .isolation = isolation,
            .program = program,
            .argv = argv,
            .environment = environment,
            .capture = owned.policy.capture,
            .descendants = owned.policy.descendants,
            .outcome = .{ .rejected = reason },
            .stdout = "",
            .stderr = "",
            .combined = "",
            .output_bytes = 0,
            .output_limit = owned.policy.limits.maximum_output_bytes,
            .terminated_process_group = false,
            .escalated_to_kill = false,
            .issued_descendant_sweep = false,
            .evidence = evidenceWithOutput(evidence_base, "", "", ""),
            .helper = helper,
        };
    }

    var execution = dependencies.launcher.launch(allocator, .{
        .root = owned.root,
        .isolation = isolation,
        .program = program,
        .argv = argv,
        .environment = environment,
        .capture = owned.policy.capture,
        .descendants = owned.policy.descendants,
        .limits = owned.policy.limits,
        .cancellation = dependencies.cancellation,
        .helper_mount = owned.helper_mount,
        .snapshot_proc = owned.snapshot_proc,
        .identity = owned.identity,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => Execution{ .outcome = .{ .setup_failed = .{ .stage = .launcher } } },
    };
    defer execution.deinit(allocator);

    const captured_stdout = try arena.dupe(u8, execution.stdout);
    const captured_stderr = try arena.dupe(u8, execution.stderr);
    const captured_combined = try arena.dupe(u8, execution.combined);

    return .{
        .allocator = allocator,
        .arena = arena_ptr,
        .identity = owned.identity,
        .root = owned.root,
        .isolation = isolation,
        .program = program,
        .argv = argv,
        .environment = environment,
        .capture = owned.policy.capture,
        .descendants = owned.policy.descendants,
        .outcome = Outcome.fromLaunch(execution.outcome),
        .stdout = captured_stdout,
        .stderr = captured_stderr,
        .combined = captured_combined,
        .output_bytes = captured_stdout.len + captured_stderr.len + captured_combined.len,
        .output_limit = owned.policy.limits.maximum_output_bytes,
        .terminated_process_group = execution.terminated_process_group,
        .escalated_to_kill = execution.escalated_to_kill,
        .issued_descendant_sweep = execution.issued_descendant_sweep,
        .evidence = evidenceWithOutput(
            evidence_base,
            captured_stdout,
            captured_stderr,
            captured_combined,
        ),
        .helper = helper,
    };
}

/// Returns the exact reason the request may not be spawned, or null.
pub fn validate(request: Request) ?RejectionReason {
    const policy = request.policy;
    if (!absolute_path.root(request.root)) return .invalid_root;
    const expected_proc: ?SnapshotProcMode =
        if (policy.snapshot_systemd_proc and
        snapshotSystemdIdentity(request.identity, request.arguments))
            .systemd
        else if (policy.snapshot_udev_proc and
        snapshotUdevIdentity(request.identity, request.arguments))
            .udev
        else if (policy.snapshot_sudo_proc and
        snapshotSudoIdentity(request.identity, request.arguments))
            .sudo
        else
            null;
    if (request.snapshot_proc) |proc| {
        if (expected_proc == null or std.meta.activeTag(proc) != expected_proc.? or
            policy.allow_host_root or policy.descendants != .terminate or
            !std.mem.eql(u8, request.root, switch (proc) {
                .systemd => |binding| binding.root_path,
                .udev => |binding| binding.root_path,
                .sudo => |binding| binding.root_path,
            }))
            return .invalid_snapshot_proc;
    } else if (expected_proc != null) return .invalid_snapshot_proc;
    if (request.helper_mount) |mount| {
        if (!std.mem.eql(u8, request.root, mount.root_path))
            return .invalid_root;
    }
    if (std.mem.eql(u8, request.root, "/") and !policy.allow_host_root) return .host_root_denied;

    if (policy.limits.timeout_ms == 0) return .invalid_timeout;
    if (policy.limits.maximum_output_bytes == 0 or
        policy.limits.maximum_output_bytes > maximum_output_limit)
        return .invalid_output_limit;

    for (policy.script_directories) |directory| {
        if (!validRelativePath(directory)) return .invalid_script_directory;
    }

    const identity = request.identity;
    if (!validPackageName(identity.package)) return .invalid_package;
    if (!validArchitecture(identity.architecture)) return .invalid_architecture;
    if (!validVersion(identity.version)) return .invalid_version;
    if (!validRelativePath(identity.script_path)) return .invalid_script_path;

    const directory = std.fs.path.dirname(identity.script_path) orelse "";
    var directory_allowed = false;
    for (policy.script_directories) |allowed| {
        if (std.mem.eql(u8, allowed, directory)) directory_allowed = true;
    }
    if (!directory_allowed) return .script_directory_denied;
    if (!validScriptName(std.fs.path.basename(identity.script_path), identity))
        return .invalid_script_name;

    if (request.arguments.len > policy.limits.maximum_arguments) return .too_many_arguments;
    for (request.arguments, 0..) |argument, index| {
        const allowed_empty = request.identity.kind == .postinst and
            request.arguments.len == 2 and index == 1 and
            std.mem.eql(u8, request.arguments[0], "configure");
        if ((!allowed_empty and argument.len == 0) or
            argument.len > policy.limits.maximum_argument_bytes or
            (argument.len != 0 and argument[0] == '-') or
            !validText(argument))
            return .invalid_argument;
    }

    var seen: [std.meta.fields(VariableName).len]bool = @splat(false);
    for (request.variables) |variable| {
        if (variable.value.len == 0 or
            variable.value.len > maximum_variable_bytes or
            !validText(variable.value))
            return .invalid_variable;
        const index = @intFromEnum(variable.name);
        if (seen[index]) return .duplicate_variable;
        seen[index] = true;
    }
    return null;
}

pub fn policyDigest(policy: Policy) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(if (policy.snapshot_sudo_proc)
        "debz-maintainer-script-policy-v4\x00"
    else if (policy.snapshot_udev_proc)
        "debz-maintainer-script-policy-v3\x00"
    else if (policy.snapshot_systemd_proc)
        "debz-maintainer-script-policy-v2\x00"
    else
        "debz-maintainer-script-policy-v1\x00");
    hash.update(if (policy.allow_host_root) "host-root\x00" else "root\x00");
    if (policy.snapshot_systemd_proc)
        hash.update("exact-systemd-boot-id-v1\x00");
    if (policy.snapshot_udev_proc)
        hash.update("exact-udev-pid-only-v1\x00");
    if (policy.snapshot_sudo_proc)
        hash.update("exact-sudo-pid-only-v1\x00");
    hash.update("private-network-loopback-v1\x00");
    hashString(&hash, @tagName(policy.capture));
    hashString(&hash, @tagName(policy.descendants));
    hashNumber(&hash, policy.limits.timeout_ms);
    hashNumber(&hash, policy.limits.termination_grace_ms);
    hashNumber(&hash, policy.limits.poll_interval_ms);
    hashNumber(&hash, policy.limits.descendant_drain_ms);
    hashNumber(&hash, policy.limits.maximum_output_bytes);
    hashNumber(&hash, policy.limits.maximum_arguments);
    hashNumber(&hash, policy.limits.maximum_argument_bytes);
    for (policy.script_directories) |directory| hashString(&hash, directory);
    return hash.finalResult();
}

fn cloneRequest(arena: std.mem.Allocator, request: Request) !Request {
    var identity = request.identity;
    identity.package = try arena.dupe(u8, request.identity.package);
    identity.version = try arena.dupe(u8, request.identity.version);
    identity.architecture = try arena.dupe(u8, request.identity.architecture);
    identity.script_path = try arena.dupe(u8, request.identity.script_path);

    const arguments = try arena.alloc([]const u8, request.arguments.len);
    for (request.arguments, arguments) |argument, *slot| slot.* = try arena.dupe(u8, argument);

    const variables = try arena.alloc(Variable, request.variables.len);
    for (request.variables, variables) |variable, *slot| slot.* = .{
        .name = variable.name,
        .value = try arena.dupe(u8, variable.value),
    };

    return .{
        .root = try arena.dupe(u8, request.root),
        .identity = identity,
        .arguments = arguments,
        .variables = variables,
        .policy = request.policy,
        .helper_mount = request.helper_mount,
        .snapshot_proc = request.snapshot_proc,
    };
}

fn buildArgv(
    arena: std.mem.Allocator,
    program: []const u8,
    arguments: []const []const u8,
) ![]const []const u8 {
    const argv = try arena.alloc([]const u8, arguments.len + 1);
    argv[0] = program;
    for (arguments, argv[1..]) |argument, *slot| slot.* = argument;
    return argv;
}

/// Builds the complete replacement environment. The set is closed, sorted by
/// key, and contains no ambient proxy, credential, or configuration value.
fn buildEnvironment(arena: std.mem.Allocator, request: Request) ![]const EnvironmentEntry {
    var entries: std.ArrayList(EnvironmentEntry) = .empty;
    try entries.appendSlice(arena, &.{
        .{ .key = "DEBIAN_FRONTEND", .value = "noninteractive" },
        .{ .key = "DPKG_ADMINDIR", .value = "/var/lib/dpkg" },
        .{ .key = "DPKG_COLORS", .value = "never" },
        .{ .key = "DPKG_MAINTSCRIPT_ARCH", .value = request.identity.architecture },
        .{ .key = "DPKG_MAINTSCRIPT_NAME", .value = request.identity.kind.fileName() },
        .{ .key = "DPKG_MAINTSCRIPT_PACKAGE", .value = request.identity.package },
        // The child already runs inside the selected root, so the in-root
        // instdir is always "/" and DPKG_ROOT stays empty as dpkg specifies.
        .{ .key = "DPKG_ROOT", .value = "" },
        .{ .key = "HOME", .value = "/nonexistent" },
        .{ .key = "LANG", .value = "C" },
        .{ .key = "LC_ALL", .value = "C" },
        .{ .key = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" },
    });
    for (request.variables) |variable|
        try entries.append(arena, .{ .key = variable.name.key(), .value = variable.value });
    const owned = try entries.toOwnedSlice(arena);
    std.mem.sort(EnvironmentEntry, owned, {}, lessThanKey);
    return owned;
}

fn lessThanKey(_: void, left: EnvironmentEntry, right: EnvironmentEntry) bool {
    return std.mem.lessThan(u8, left.key, right.key);
}

fn digests(
    request: Request,
    isolation: Isolation,
    argv: []const []const u8,
    environment: []const EnvironmentEntry,
) Evidence {
    const argv_sha256 = hashArgv(argv);
    const environment_sha256 = hashEnvironment(environment);
    const policy_sha256 = policyDigest(request.policy);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-maintainer-script-invocation-v1\x00");
    hashString(&hash, request.root);
    hashString(&hash, @tagName(isolation));
    hashString(&hash, request.identity.package);
    hashString(&hash, request.identity.version);
    hashString(&hash, request.identity.architecture);
    hashString(&hash, @tagName(request.identity.kind));
    hashString(&hash, request.identity.script_path);
    hash.update(&request.identity.script_sha256);
    hash.update(&argv_sha256);
    hash.update(&environment_sha256);
    hash.update(&policy_sha256);
    if (request.helper_mount) |mount| {
        hash.update("debz-maintainer-script-helper-mount-v1\x00");
        hashString(&hash, mount.evidence.source_path);
        hashString(&hash, mount.evidence.target_path);
        hash.update(&mount.evidence.sha256);
    }
    if (request.snapshot_proc) |proc| switch (proc) {
        .systemd => |binding| {
            hash.update("debz-maintainer-script-systemd-boot-id-v1\x00");
            hashString(&hash, "proc/sys/kernel/random/boot_id");
            hash.update(&hashBytes(&binding.boot_id));
        },
        .udev => {
            hash.update("debz-maintainer-script-udev-pid-only-v1\x00");
            for (snapshot_udev_inputs) |input| {
                hashString(&hash, input.path);
                hashString(&hash, input.sha256);
            }
            for (snapshot_udev_overrides) |path| hashString(&hash, path);
            for (snapshot_udev_path_shadows) |path| hashString(&hash, path);
        },
        .sudo => {
            hash.update("debz-maintainer-script-sudo-pid-only-v1\x00");
            for (snapshot_sudo_inputs) |input| {
                hashString(&hash, input.path);
                hashString(&hash, input.sha256);
            }
            for (snapshot_sudo_aliases) |alias| {
                hashString(&hash, alias.path);
                hashString(&hash, alias.target);
            }
            for (snapshot_sudo_overrides) |path| hashString(&hash, path);
            for (snapshot_sudo_shadows) |path| hashString(&hash, path);
        },
    };
    return .{
        .script_sha256 = request.identity.script_sha256,
        .argv_sha256 = argv_sha256,
        .environment_sha256 = environment_sha256,
        .policy_sha256 = policy_sha256,
        .invocation_sha256 = hash.finalResult(),
        .stdout_sha256 = @splat(0),
        .stderr_sha256 = @splat(0),
        .combined_sha256 = @splat(0),
    };
}

fn evidenceWithOutput(
    base: Evidence,
    captured_stdout: []const u8,
    captured_stderr: []const u8,
    captured_combined: []const u8,
) Evidence {
    var evidence = base;
    evidence.stdout_sha256 = hashBytes(captured_stdout);
    evidence.stderr_sha256 = hashBytes(captured_stderr);
    evidence.combined_sha256 = hashBytes(captured_combined);
    return evidence;
}

fn hashArgv(argv: []const []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-maintainer-script-argv-v1\x00");
    for (argv) |argument| hashString(&hash, argument);
    return hash.finalResult();
}

fn hashEnvironment(environment: []const EnvironmentEntry) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-maintainer-script-environment-v1\x00");
    for (environment) |entry| {
        hashString(&hash, entry.key);
        hashString(&hash, entry.value);
    }
    return hash.finalResult();
}

fn hashBytes(value: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(value);
    return hash.finalResult();
}

fn hashString(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, @intCast(value.len), .little);
    hash.update(&length);
    hash.update(value);
}

fn hashNumber(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, value, .little);
    hash.update(&number);
}

fn validRelativePath(path: []const u8) bool {
    if (path.len == 0 or path.len > maximum_script_path_bytes) return false;
    if (path[0] == '/') return false;
    var buffer: [maximum_script_path_bytes + 1]u8 = undefined;
    buffer[0] = '/';
    @memcpy(buffer[1 .. path.len + 1], path);
    return absolute_path.nonRoot(buffer[0 .. path.len + 1]);
}

fn validScriptName(name: []const u8, identity: Identity) bool {
    const kind = identity.kind.fileName();
    if (std.mem.eql(u8, name, kind)) return true;
    if (name.len <= kind.len + 1) return false;
    if (name[name.len - kind.len - 1] != '.') return false;
    if (!std.mem.eql(u8, name[name.len - kind.len ..], kind)) return false;
    const stem = name[0 .. name.len - kind.len - 1];
    if (std.mem.eql(u8, stem, identity.package)) return true;
    if (stem.len <= identity.package.len + 1) return false;
    if (!std.mem.startsWith(u8, stem, identity.package)) return false;
    if (stem[identity.package.len] != ':') return false;
    return std.mem.eql(u8, stem[identity.package.len + 1 ..], identity.architecture);
}

fn validText(value: []const u8) bool {
    if (!std.unicode.utf8ValidateSlice(value)) return false;
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    return true;
}

fn validPackageName(value: []const u8) bool {
    if (value.len < 2 or !lowerAlphaNumeric(value[0])) return false;
    for (value[1..]) |byte| {
        if (!lowerAlphaNumeric(byte) and byte != '+' and byte != '-' and byte != '.') return false;
    }
    return true;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or !lowerAlphaNumeric(value[0])) return false;
    for (value[1..]) |byte| {
        if (!lowerAlphaNumeric(byte) and byte != '-') return false;
    }
    return true;
}

fn validVersion(value: []const u8) bool {
    if (value.len == 0 or value.len > maximum_variable_bytes) return false;
    if (!std.ascii.isAlphanumeric(value[0])) return false;
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '.', '+', '-', ':', '~' => {},
            else => return false,
        }
    }
    return true;
}

fn lowerAlphaNumeric(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or std.ascii.isDigit(byte);
}

/// Production launcher. It forks, enters the selected root with a
/// chroot-equivalent child setup, replaces the environment, binds stdin to
/// `/dev/null`, captures bounded output, and terminates the whole script
/// process group with SIGTERM/SIGKILL escalation and an exact reap.
pub const SystemLauncher = struct {
    pub fn interface(self: *SystemLauncher) Launcher {
        return .{ .context = self, .launchFn = launchInterface };
    }

    fn launchInterface(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        invocation: Invocation,
    ) anyerror!Execution {
        return launch(allocator, invocation);
    }

    /// Exercises the complete helper/root setup without entering a script.
    /// Native callers require an exited-zero result before package mutation.
    pub fn probeHelper(
        allocator: std.mem.Allocator,
        mount: *const HelperMount,
        cancellation: Cancellation,
    ) !Execution {
        return launchConfigured(allocator, .{
            .root = mount.root_path,
            .isolation = if (std.mem.eql(u8, mount.root_path, "/")) .host_root else .chroot,
            .program = "/",
            .argv = &.{"/"},
            .environment = &.{},
            .capture = .separate,
            .descendants = .terminate,
            .limits = .{ .timeout_ms = 5_000 },
            .cancellation = cancellation,
            .helper_mount = mount,
        }, true);
    }
};

const linux = std.os.linux;

const child_status_bytes = 5;
const proc_mount_flags = linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC;
const proc_mask_flags = linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC;
const close_range_cloexec = 4;

fn launch(allocator: std.mem.Allocator, invocation: Invocation) !Execution {
    return launchConfigured(allocator, invocation, false);
}

fn launchConfigured(
    allocator: std.mem.Allocator,
    invocation: Invocation,
    setup_only: bool,
) !Execution {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    var strings: Strings = try .init(allocator, invocation);
    defer strings.deinit(allocator);
    var helper: HelperDescriptors = .{};
    defer helper.close();
    if (invocation.helper_mount) |mount| {
        if (!std.mem.eql(u8, invocation.root, mount.root_path))
            return error.InvalidHelperRoot;
        try mount.verify(allocator);
        const prepared = helper.prepare(mount);
        if (prepared != .SUCCESS)
            return setupFailure(.launcher, @intFromEnum(prepared));
        _ = try mount.source.metadata();
        _ = try mount.target.metadata();
    }
    if (invocation.snapshot_proc) |proc| {
        const identity = invocation.identity orelse return setupFailure(.snapshot_proc, 0);
        const bound = switch (proc) {
            .systemd => |binding| snapshotSystemdIdentity(identity, invocation.argv[1..]) and
                std.mem.eql(u8, invocation.program, "/var/lib/dpkg/info/systemd.postinst") and
                std.mem.eql(u8, invocation.root, binding.root_path),
            .udev => |binding| snapshotUdevIdentity(identity, invocation.argv[1..]) and
                std.mem.eql(u8, invocation.program, "/var/lib/dpkg/info/udev.postinst") and
                std.mem.eql(u8, invocation.root, binding.root_path),
            .sudo => |binding| snapshotSudoIdentity(identity, invocation.argv[1..]) and
                std.mem.eql(u8, invocation.program, "/var/lib/dpkg/info/sudo.postinst") and
                std.mem.eql(u8, invocation.root, binding.root_path),
        };
        if (invocation.isolation != .chroot or invocation.descendants != .terminate or
            !bound)
            return setupFailure(.snapshot_proc, 0);
        const verified = switch (proc) {
            .systemd => |binding| binding.verify(allocator),
            .udev => |binding| binding.verify(allocator),
            .sudo => |binding| binding.verify(allocator),
        };
        verified catch |err| {
            if (err == error.OutOfMemory) return err;
            std.log.err("signed proc binding changed before launch: {s}", .{
                @errorName(err),
            });
            return setupFailure(.snapshot_proc, @intFromEnum(switch (err) {
                error.KernelBootIdUnavailable => linux.E.NOENT,
                error.SnapshotBootIdChanged,
                error.InvalidSnapshotSystemdScript,
                error.InvalidSnapshotProcMountpoint,
                error.InvalidSnapshotUdevScript,
                error.InvalidSnapshotUdevTool,
                error.InvalidSnapshotUdevControl,
                error.InvalidSnapshotUdevMountpoint,
                error.InvalidSnapshotUdevRoot,
                error.InvalidSnapshotSudoScript,
                error.InvalidSnapshotSudoTool,
                error.InvalidSnapshotSudoControl,
                error.InvalidSnapshotSudoMountpoint,
                error.InvalidSnapshotSudoRoot,
                error.PathChanged,
                => linux.E.STALE,
                else => linux.E.IO,
            }));
        };
    }

    var output_pipe: [2]i32 = .{ -1, -1 };
    var error_pipe: [2]i32 = .{ -1, -1 };
    var status_pipe: [2]i32 = .{ -1, -1 };
    var control_pipe: [2]i32 = .{ -1, -1 };
    defer closePipe(&control_pipe);
    var null_fd: i32 = -1;
    var opened = false;
    defer if (!opened) {
        closePipe(&output_pipe);
        closePipe(&error_pipe);
        closePipe(&status_pipe);
        closeFd(&null_fd);
    };

    const output = createPipe();
    if (output.errno != 0) return setupFailure(.pipe, output.errno);
    output_pipe = output.fds;
    if (invocation.capture == .separate) {
        const errors = createPipe();
        if (errors.errno != 0) return setupFailure(.pipe, errors.errno);
        error_pipe = errors.fds;
    }
    const status = createPipe();
    if (status.errno != 0) return setupFailure(.pipe, status.errno);
    status_pipe = status.fds;
    if (invocation.snapshot_proc != null) {
        const control = createControlPipe();
        if (control.errno != 0) return setupFailure(.pipe, control.errno);
        control_pipe = control.fds;
    }

    const null_device = openNullDevice();
    if (null_device.errno != 0) return setupFailure(.stdin_device, null_device.errno);
    null_fd = null_device.fd;

    const separate = invocation.capture == .separate;
    const child: ChildDescriptor = .{
        .root = strings.root,
        .program = strings.program,
        .argv = strings.argv.ptr,
        .envp = strings.envp.ptr,
        .isolation = invocation.isolation,
        .null_fd = null_fd,
        .output_write = output_pipe[1],
        .error_write = if (separate) error_pipe[1] else output_pipe[1],
        .output_read = output_pipe[0],
        .error_read = if (separate) error_pipe[0] else output_pipe[0],
        .status_write = status_pipe[1],
        .status_read = status_pipe[0],
        .helper = if (invocation.helper_mount != null) helper else null,
        .helper_source = strings.helper_source,
        .helper_target = strings.helper_target,
        .setup_only = setup_only,
        .control_read = control_pipe[0],
        .control_write = control_pipe[1],
        .proc = if (invocation.snapshot_proc) |proc| switch (proc) {
            .systemd => |binding| .{
                .root_stat = binding.root_stat,
                .directory_stat = binding.directory_stat,
                .view = .{ .systemd = binding.boot_id },
            },
            .udev => |binding| .{
                .root_stat = binding.root_stat,
                .directory_stat = binding.directory_stat,
                .view = .udev,
            },
            .sudo => |binding| .{
                .root_stat = binding.root_stat,
                .directory_stat = binding.directory_stat,
                .view = .sudo,
            },
        } else null,
    };

    const clone_flags = linux.CLONE.NEWNET |
        if (invocation.snapshot_proc != null)
            linux.CLONE.NEWNS | linux.CLONE.NEWPID | @intFromEnum(linux.SIG.CHLD)
        else
            @intFromEnum(linux.SIG.CHLD);
    const forked = linux.clone2(clone_flags, 0);
    switch (linux.errno(forked)) {
        .SUCCESS => {},
        else => |err| return setupFailure(.network_namespace, @intFromEnum(err)),
    }
    const pid: i32 = @intCast(forked);
    if (pid == 0) childMain(child);
    opened = true;

    // Close the race between the parent's group signal and the child's setsid.
    _ = linux.setpgid(pid, pid);
    closeFd(&null_fd);
    closeFd(&output_pipe[1]);
    closeFd(&error_pipe[1]);
    closeFd(&status_pipe[1]);
    closeFd(&control_pipe[0]);

    return supervise(allocator, invocation, pid, .{
        .output = output_pipe[0],
        .errors = error_pipe[0],
        .status = status_pipe[0],
    });
}

fn setupFailure(stage: SetupStage, errno: u32) Execution {
    return .{ .outcome = .{ .setup_failed = .{ .stage = stage, .errno = errno } } };
}

fn createControlPipe() struct { fds: [2]i32, errno: u32 } {
    var fds: [2]i32 = undefined;
    const rc = linux.pipe2(&fds, .{ .CLOEXEC = true, .NONBLOCK = true });
    if (linux.errno(rc) != .SUCCESS)
        return .{ .fds = .{ -1, -1 }, .errno = @intFromEnum(linux.errno(rc)) };
    for (&fds) |*fd| {
        if (fd.* >= 3) continue;
        const moved = linux.fcntl(fd.*, linux.F.DUPFD_CLOEXEC, 3);
        if (linux.errno(moved) != .SUCCESS) {
            const err = @intFromEnum(linux.errno(moved));
            closePipe(&fds);
            return .{ .fds = .{ -1, -1 }, .errno = err };
        }
        _ = linux.close(fd.*);
        fd.* = @intCast(moved);
    }
    return .{ .fds = fds, .errno = 0 };
}

const Strings = struct {
    root: [:0]u8,
    program: [:0]u8,
    argv: [:null]?[*:0]const u8,
    envp: [:null]?[*:0]const u8,
    argv_storage: [][:0]u8,
    envp_storage: [][:0]u8,
    helper_source: ?[:0]u8,
    helper_target: ?[:0]u8,

    fn init(allocator: std.mem.Allocator, invocation: Invocation) !Strings {
        const root = try allocator.dupeZ(u8, invocation.root);
        errdefer allocator.free(root);
        const program = try allocator.dupeZ(u8, invocation.program);
        errdefer allocator.free(program);
        const helper_source = if (invocation.helper_mount) |mount|
            try allocator.dupeZ(u8, mount.evidence.source_path)
        else
            null;
        errdefer if (helper_source) |path| allocator.free(path);
        const helper_target = if (invocation.helper_mount) |mount|
            try allocator.dupeZ(u8, mount.evidence.target_path)
        else
            null;
        errdefer if (helper_target) |path| allocator.free(path);

        const argv_storage = try allocator.alloc([:0]u8, invocation.argv.len);
        errdefer allocator.free(argv_storage);
        var filled_argv: usize = 0;
        errdefer for (argv_storage[0..filled_argv]) |item| allocator.free(item);
        for (invocation.argv, argv_storage) |argument, *slot| {
            slot.* = try allocator.dupeZ(u8, argument);
            filled_argv += 1;
        }

        const envp_storage = try allocator.alloc([:0]u8, invocation.environment.len);
        errdefer allocator.free(envp_storage);
        var filled_envp: usize = 0;
        errdefer for (envp_storage[0..filled_envp]) |item| allocator.free(item);
        for (invocation.environment, envp_storage) |entry, *slot| {
            slot.* = try std.fmt.allocPrintSentinel(
                allocator,
                "{s}={s}",
                .{ entry.key, entry.value },
                0,
            );
            filled_envp += 1;
        }

        const argv = try allocator.allocSentinel(?[*:0]const u8, invocation.argv.len, null);
        errdefer allocator.free(argv);
        for (argv_storage, argv) |item, *slot| slot.* = item.ptr;
        const envp = try allocator.allocSentinel(?[*:0]const u8, invocation.environment.len, null);
        errdefer allocator.free(envp);
        for (envp_storage, envp) |item, *slot| slot.* = item.ptr;

        return .{
            .root = root,
            .program = program,
            .argv = argv,
            .envp = envp,
            .argv_storage = argv_storage,
            .envp_storage = envp_storage,
            .helper_source = helper_source,
            .helper_target = helper_target,
        };
    }

    fn deinit(self: *Strings, allocator: std.mem.Allocator) void {
        for (self.argv_storage) |item| allocator.free(item);
        for (self.envp_storage) |item| allocator.free(item);
        allocator.free(self.argv_storage);
        allocator.free(self.envp_storage);
        allocator.free(self.argv);
        allocator.free(self.envp);
        allocator.free(self.program);
        allocator.free(self.root);
        if (self.helper_source) |path| allocator.free(path);
        if (self.helper_target) |path| allocator.free(path);
        self.* = undefined;
    }
};

const HelperDescriptors = struct {
    root: i32 = -1,
    source: i32 = -1,
    target: i32 = -1,
    root_stat: linux.Statx = undefined,
    source_stat: linux.Statx = undefined,
    target_stat: linux.Statx = undefined,

    fn prepare(self: *HelperDescriptors, mount: *const HelperMount) linux.E {
        const originals = [_]i32{
            mount.source.root.dir.handle,
            mount.source.file.handle,
            mount.target.file.handle,
        };
        const copies = [_]*i32{ &self.root, &self.source, &self.target };
        const metadata = [_]*linux.Statx{ &self.root_stat, &self.source_stat, &self.target_stat };
        for (originals, copies, metadata) |original, copy, captured| {
            while (true) {
                const rc = linux.fcntl(original, linux.F.DUPFD_CLOEXEC, 3);
                switch (linux.errno(rc)) {
                    .SUCCESS => copy.* = @intCast(rc),
                    .INTR => continue,
                    else => |err| return err,
                }
                break;
            }
            const observed = helperStat(copy.*, captured);
            if (observed != .SUCCESS) return observed;
        }
        return .SUCCESS;
    }

    fn close(self: *HelperDescriptors) void {
        closeFd(&self.root);
        closeFd(&self.source);
        closeFd(&self.target);
    }
};

const ChildDescriptor = struct {
    root: [:0]const u8,
    program: [:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    isolation: Isolation,
    null_fd: i32,
    output_write: i32,
    error_write: i32,
    output_read: i32,
    error_read: i32,
    status_write: i32,
    status_read: i32,
    helper: ?HelperDescriptors = null,
    helper_source: ?[:0]const u8 = null,
    helper_target: ?[:0]const u8 = null,
    setup_only: bool = false,
    control_read: i32 = -1,
    control_write: i32 = -1,
    proc: ?ProcDescriptor = null,
};

const ProcDescriptor = struct {
    root_stat: linux.Statx,
    directory_stat: linux.Statx,
    view: union(SnapshotProcMode) {
        systemd: [37]u8,
        udev: void,
        sudo: void,
    },
};

/// Child half of the fork. Only async-signal-safe raw syscalls run here; no
/// allocation, no shell, and no ambient environment is consulted.
fn childMain(child: ChildDescriptor) noreturn {
    if (child.proc != null) {
        _ = linux.close(child.control_write);
        if (linux.getpid() != 1)
            childFail(child.status_write, .snapshot_proc, .INVAL);
        const death = linux.errno(linux.prctl(
            @intFromEnum(linux.PR.SET_PDEATHSIG),
            @intFromEnum(linux.SIG.KILL),
            0,
            0,
            0,
        ));
        if (death != .SUCCESS) childFail(child.status_write, .snapshot_proc, death);
        var alive: [1]u8 = undefined;
        const probe = linux.read(child.control_read, &alive, alive.len);
        if (probe == 0 or linux.errno(probe) != .AGAIN)
            childFail(child.status_write, .snapshot_proc, .CHILD);
        _ = linux.close(child.control_read);
        const private = linux.errno(linux.mount(
            null,
            "/",
            null,
            linux.MS.REC | linux.MS.PRIVATE,
            0,
        ));
        if (private != .SUCCESS)
            childFail(child.status_write, .snapshot_proc, private);
    }
    if (linux.errno(linux.setsid()) != .SUCCESS) {
        const grouped = linux.errno(linux.setpgid(0, 0));
        if (grouped != .SUCCESS) childFail(child.status_write, .session, grouped);
    }
    const network_ready = setupPrivateLoopback();
    if (network_ready != .SUCCESS) childFail(child.status_write, .network_setup, network_ready);

    var streams: ChildStreams = .{
        .input = child.null_fd,
        .output = child.output_write,
        .errors = child.error_write,
        .status = child.status_write,
    };
    // A parent with closed standard descriptors leaves fd 0, 1, or 2 free, so
    // the runner's own pipes can land there. `dup2(fd, fd)` is a no-op that
    // keeps CLOEXEC set, which would silently close the stream at execve, and
    // an aliased source could also be clobbered by an earlier mapping. Lift
    // every still-needed descriptor out of the standard range first.
    if (liftReservedDescriptors(&streams)) |err|
        childFail(child.status_write, .standard_streams, err);

    for ([_][2]i32{
        .{ streams.input, 0 },
        .{ streams.output, 1 },
        .{ streams.errors, 2 },
    }) |mapping| {
        const duplicated = linux.errno(linux.dup2(mapping[0], mapping[1]));
        if (duplicated != .SUCCESS)
            childFail(streams.status, .standard_streams, duplicated);
    }

    for ([_]i32{
        streams.input,
        streams.output,
        streams.errors,
        child.output_read,
        child.error_read,
    }) |fd| {
        if (fd > 2) _ = linux.close(fd);
    }

    var empty = linux.sigemptyset();
    _ = linux.sigprocmask(linux.SIG.SETMASK, &empty, null);
    for ([_]linux.SIG{ .PIPE, .INT, .QUIT, .HUP, .TERM, .CHLD }) |signal| {
        const action: linux.Sigaction = .{
            .handler = .{ .handler = linux.SIG.DFL },
            .mask = empty,
            .flags = 0,
        };
        _ = linux.sigaction(signal, &action, null);
    }

    var helper_root: i32 = -1;
    if (child.helper != null) {
        const exposed = exposeHelper(child);
        if (exposed.err != .SUCCESS)
            childFail(streams.status, .root_isolation, exposed.err);
        helper_root = exposed.root;
    }
    var proc_root: i32 = -1;
    if (child.proc) |proc| {
        const reopened = reopenMountPath(
            linux.AT.FDCWD,
            child.root,
            proc.root_stat,
            true,
        );
        if (reopened.err != .SUCCESS)
            childFail(streams.status, .snapshot_proc, reopened.err);
        proc_root = reopened.root;
    }
    switch (child.isolation) {
        .chroot => {
            // chdir first so the chroot target and the post-chroot working
            // directory cannot be raced through the inherited cwd.
            const entered = linux.errno(if (helper_root >= 0)
                linux.fchdir(helper_root)
            else if (proc_root >= 0)
                linux.fchdir(proc_root)
            else
                linux.chdir(child.root.ptr));
            if (entered != .SUCCESS) childFail(streams.status, .working_directory, entered);
            const isolated = linux.errno(linux.chroot("."));
            if (isolated != .SUCCESS) childFail(streams.status, .root_isolation, isolated);
        },
        .host_root => {},
    }
    const working = linux.errno(linux.chdir("/"));
    if (working != .SUCCESS) childFail(streams.status, .working_directory, working);
    if (helper_root >= 0) _ = linux.close(helper_root);
    if (proc_root >= 0) _ = linux.close(proc_root);
    if (child.proc) |proc| {
        const setup = setupSnapshotProc(proc, null);
        if (setup != .SUCCESS)
            childFail(streams.status, .snapshot_proc, setup);
    }
    const sealed = sealInheritedDescriptors();
    if (sealed != .SUCCESS)
        childFail(streams.status, .standard_streams, sealed);
    if (child.setup_only) linux.exit(0);

    // dpkg forces umask 022 process-wide (`lib/dpkg/program.c`
    // `dpkg_program_init`), so maintainer scripts never inherit the caller's
    // umask. umask(2) cannot fail.
    _ = linux.syscall1(.umask, script_umask);
    const executed = linux.errno(linux.execve(child.program.ptr, child.argv, child.envp));
    childFail(streams.status, .execute, executed);
}

fn setupSnapshotProc(proc: ProcDescriptor, failure_stage: ?*u8) linux.E {
    if (failure_stage) |stage| stage.* = 1;
    const directory = reopenMountPath(
        linux.AT.FDCWD,
        "/proc",
        proc.directory_stat,
        true,
    );
    if (directory.err != .SUCCESS) return directory.err;
    _ = linux.close(directory.root);
    if (failure_stage) |stage| stage.* = 2;
    const mounted = linux.errno(linux.mount(
        "proc",
        "/proc",
        "proc",
        proc_mount_flags,
        @intFromPtr(switch (proc.view) {
            .systemd => @as([*:0]const u8, "hidepid=2"),
            .udev, .sudo => @as([*:0]const u8, "hidepid=2,subset=pid"),
        }),
    ));
    if (mounted != .SUCCESS) return mounted;
    if (failure_stage) |stage| stage.* = 3;
    if (proc.view == .udev or proc.view == .sudo) {
        for ([_][*:0]const u8{
            "/proc/sys",
            "/proc/sys/kernel/random/boot_id",
        }) |path| {
            const unexpected = linux.open(
                path,
                .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true },
                0,
            );
            if (linux.errno(unexpected) == .SUCCESS) {
                _ = linux.close(@intCast(unexpected));
                return .EXIST;
            }
            if (linux.errno(unexpected) != .NOENT) return linux.errno(unexpected);
        }
        const visible = linux.open(
            "/proc/1/root",
            .{ .PATH = true, .CLOEXEC = true },
            0,
        );
        if (linux.errno(visible) != .SUCCESS) return linux.errno(visible);
        var observed: linux.Statx = undefined;
        const checked = helperStat(@intCast(visible), &observed);
        _ = linux.close(@intCast(visible));
        if (checked != .SUCCESS) return checked;
        if (observed.dev_major != proc.root_stat.dev_major or
            observed.dev_minor != proc.root_stat.dev_minor or
            observed.ino != proc.root_stat.ino)
            return .STALE;
        return restrictSnapshotProcPrivileges(failure_stage);
    }
    const boot_id = proc.view.systemd;
    const masked = linux.errno(linux.mount(
        "tmpfs",
        "/proc/sys",
        "tmpfs",
        proc_mask_flags,
        @intFromPtr("mode=0700,size=65536"),
    ));
    if (masked != .SUCCESS) return masked;
    if (failure_stage) |stage| stage.* = 4;
    for ([_][*:0]const u8{
        "/proc/sys/kernel",
        "/proc/sys/kernel/random",
    }) |path| {
        const made = linux.errno(linux.mkdir(path, 0o555));
        if (made != .SUCCESS) return made;
        const restricted = linux.errno(linux.chmod(path, 0o555));
        if (restricted != .SUCCESS) return restricted;
    }
    if (failure_stage) |stage| stage.* = 5;
    const created = linux.open(
        "/proc/sys/kernel/random/boot_id",
        .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        },
        0o400,
    );
    if (linux.errno(created) != .SUCCESS) return linux.errno(created);
    const file: i32 = @intCast(created);
    var offset: usize = 0;
    while (offset < boot_id.len) {
        const count = linux.write(file, boot_id[offset..].ptr, boot_id.len - offset);
        switch (linux.errno(count)) {
            .SUCCESS => {
                if (count == 0) {
                    _ = linux.close(file);
                    return .IO;
                }
                offset += count;
            },
            .INTR => {},
            else => |err| {
                _ = linux.close(file);
                return err;
            },
        }
    }
    const mode = linux.errno(linux.fchmod(file, 0o444));
    _ = linux.close(file);
    if (mode != .SUCCESS) return mode;
    if (failure_stage) |stage| stage.* = 6;
    const protected = linux.errno(linux.mount(
        null,
        "/proc/sys",
        null,
        linux.MS.REMOUNT | proc_mount_flags,
        0,
    ));
    if (protected != .SUCCESS) return protected;
    if (failure_stage) |stage| stage.* = 7;
    const observed = linux.open(
        "/proc/sys/kernel/random/boot_id",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true },
        0,
    );
    if (linux.errno(observed) != .SUCCESS) return linux.errno(observed);
    const read_fd: i32 = @intCast(observed);
    var bytes: [38]u8 = undefined;
    const count = linux.read(read_fd, &bytes, bytes.len);
    _ = linux.close(read_fd);
    if (linux.errno(count) != .SUCCESS) return linux.errno(count);
    if (count != boot_id.len or
        !std.mem.eql(u8, bytes[0..boot_id.len], &boot_id))
        return .STALE;
    if (failure_stage) |stage| stage.* = 8;
    for ([_][*:0]const u8{
        "/proc/sys/kernel/random/uuid",
        "/proc/sys/kernel/pid_max",
        "/proc/sys/vm",
        "/proc/sys/net",
    }) |path| {
        const unexpected = linux.open(
            path,
            .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true },
            0,
        );
        if (linux.errno(unexpected) == .SUCCESS) {
            _ = linux.close(@intCast(unexpected));
            return .EXIST;
        }
        if (linux.errno(unexpected) != .NOENT) return linux.errno(unexpected);
    }
    if (failure_stage) |stage| stage.* = 9;
    const writable = linux.open(
        "/proc/sys/extra",
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(writable) == .SUCCESS) {
        _ = linux.close(@intCast(writable));
        return .EXIST;
    }
    if (linux.errno(writable) != .ROFS) return linux.errno(writable);
    if (failure_stage) |stage| stage.* = 10;
    return restrictSnapshotProcPrivileges(failure_stage);
}

// Zig's linux.cap_user_header_t pads pid to offset 8; the kernel ABI uses offset 4.
const KernelCapabilityHeader = extern struct {
    version: u32,
    pid: i32,
};

fn restrictSnapshotProcPrivileges(failure_stage: ?*u8) linux.E {
    const dropped = linux.errno(linux.prctl(
        @intFromEnum(linux.PR.CAPBSET_DROP),
        linux.CAP.SYS_ADMIN,
        0,
        0,
        0,
    ));
    if (dropped != .SUCCESS) return dropped;
    if (failure_stage) |stage| stage.* = 11;
    const ambient = linux.errno(linux.prctl(
        @intFromEnum(linux.PR.CAP_AMBIENT),
        4,
        0,
        0,
        0,
    ));
    if (ambient != .SUCCESS) return ambient;
    if (failure_stage) |stage| stage.* = 12;
    const no_new_privs = linux.errno(linux.prctl(
        @intFromEnum(linux.PR.SET_NO_NEW_PRIVS),
        1,
        0,
        0,
        0,
    ));
    if (no_new_privs != .SUCCESS) return no_new_privs;
    if (failure_stage) |stage| stage.* = 13;
    var header: KernelCapabilityHeader = .{ .version = 0x20080522, .pid = 0 };
    var data: [2]linux.cap_user_data_t = undefined;
    const captured = linux.errno(linux.syscall2(
        .capget,
        @intFromPtr(&header),
        @intFromPtr(&data[0]),
    ));
    if (captured != .SUCCESS) return captured;
    if (failure_stage) |stage| stage.* = 14;
    const bit = linux.CAP.TO_MASK(linux.CAP.SYS_ADMIN);
    data[0].effective &= ~bit;
    data[0].permitted &= ~bit;
    data[0].inheritable &= ~bit;
    const removed = linux.errno(linux.syscall2(
        .capset,
        @intFromPtr(&header),
        @intFromPtr(&data[0]),
    ));
    if (removed != .SUCCESS) return removed;
    if (failure_stage) |stage| stage.* = 15;
    const checked = linux.errno(linux.syscall2(
        .capget,
        @intFromPtr(&header),
        @intFromPtr(&data[0]),
    ));
    if (checked != .SUCCESS) return checked;
    if (failure_stage) |stage| stage.* = 16;
    if (((data[0].effective | data[0].permitted | data[0].inheritable) & bit) != 0 or
        linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.SYS_ADMIN, 0, 0, 0) != 0 or
        linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) != 1)
        return .PERM;
    if (failure_stage) |stage| stage.* = 17;
    var parent_signal: u32 = 0;
    const death = linux.errno(linux.prctl(
        @intFromEnum(linux.PR.GET_PDEATHSIG),
        @intFromPtr(&parent_signal),
        0,
        0,
        0,
    ));
    if (death != .SUCCESS) return death;
    if (parent_signal != @intFromEnum(linux.SIG.KILL)) return .PERM;
    return .SUCCESS;
}

fn sealInheritedDescriptors() linux.E {
    // Keep the status pipe usable for exec failures, but pass no inherited
    // host-root or socket descriptor into the script.
    return linux.errno(linux.syscall3(
        .close_range,
        3,
        std.math.maxInt(u32),
        close_range_cloexec,
    ));
}

fn setupPrivateLoopback() linux.E {
    const fd_result = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(fd_result) != .SUCCESS) return linux.errno(fd_result);
    const fd: i32 = @intCast(fd_result);
    defer _ = linux.close(fd);
    var request: linux.ifreq = .{
        .ifrn = .{ .name = .{ 'l', 'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
        .ifru = undefined,
    };
    const fetched = linux.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&request)));
    if (fetched != .SUCCESS) return fetched;
    request.ifru.flags.UP = true;
    const applied = linux.errno(linux.ioctl(fd, linux.SIOCSIFFLAGS, @intFromPtr(&request)));
    if (applied != .SUCCESS) return applied;
    const verified = linux.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&request)));
    if (verified != .SUCCESS) return verified;
    if (!request.ifru.flags.UP or !request.ifru.flags.LOOPBACK) return .NODEV;
    return .SUCCESS;
}

const HelperExposure = struct { root: i32 = -1, err: linux.E = .SUCCESS };
const MountOpenHow = extern struct { flags: u64, mode: u64 = 0, resolve: u64 };

fn helperStat(fd: i32, metadata: *linux.Statx) linux.E {
    const result = linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, metadata));
    if (result != .SUCCESS) return result;
    const required: linux.STATX = .{
        .TYPE = true,
        .MODE = true,
        .NLINK = true,
        .UID = true,
        .GID = true,
        .MTIME = true,
        .CTIME = true,
        .INO = true,
        .SIZE = true,
    };
    const bits: u32 = @bitCast(required);
    if (@as(u32, @bitCast(metadata.mask)) & bits != bits) return .OPNOTSUPP;
    return .SUCCESS;
}

fn reopenMountPath(
    dirfd: i32,
    path: [*:0]const u8,
    expected: linux.Statx,
    directory: bool,
) HelperExposure {
    const flags: linux.O = .{ .PATH = true, .CLOEXEC = true, .DIRECTORY = directory };
    const how: MountOpenHow = .{
        .flags = @as(u32, @bitCast(flags)),
        // No magic links or symlinks; relative paths must remain below root.
        .resolve = 0x02 | 0x04 | @as(u64, if (directory) 0 else 0x08),
    };
    const opened = linux.syscall4(
        .openat2,
        @bitCast(@as(isize, dirfd)),
        @intFromPtr(path),
        @intFromPtr(&how),
        @sizeOf(MountOpenHow),
    );
    const opened_error = linux.errno(opened);
    if (opened_error != .SUCCESS) return .{ .err = opened_error };
    const fd: i32 = @intCast(opened);
    var observed: linux.Statx = undefined;
    const metadata_error = helperStat(fd, &observed);
    if (metadata_error != .SUCCESS) {
        _ = linux.close(fd);
        return .{ .err = metadata_error };
    }
    if (observed.dev_major != expected.dev_major or observed.dev_minor != expected.dev_minor or
        observed.ino != expected.ino or observed.mode != expected.mode or
        observed.uid != expected.uid or observed.gid != expected.gid or (!directory and
        (observed.size != expected.size or
            observed.nlink != expected.nlink or
            observed.mtime.sec != expected.mtime.sec or observed.mtime.nsec != expected.mtime.nsec or
            observed.ctime.sec != expected.ctime.sec or observed.ctime.nsec != expected.ctime.nsec)))
    {
        _ = linux.close(fd);
        return .{ .err = .STALE };
    }
    return .{ .root = fd };
}

fn exposeHelper(child: ChildDescriptor) HelperExposure {
    const helper = child.helper.?;
    const unshared = linux.errno(linux.unshare(linux.CLONE.NEWNS));
    if (unshared != .SUCCESS) return .{ .err = unshared };
    const isolated = linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0));
    if (isolated != .SUCCESS) return .{ .err = isolated };

    // FDs opened before unshare still refer to the old mount tree. Reopen in
    // the private tree without following links, then match the pinned inodes.
    const root = reopenMountPath(linux.AT.FDCWD, child.root, helper.root_stat, true);
    if (root.err != .SUCCESS) return root;
    var retain_root = false;
    defer if (!retain_root) {
        _ = linux.close(root.root);
    };
    const source = reopenMountPath(root.root, child.helper_source.?, helper.source_stat, false);
    if (source.err != .SUCCESS) return source;
    defer _ = linux.close(source.root);
    const target = reopenMountPath(root.root, child.helper_target.?, helper.target_stat, false);
    if (target.err != .SUCCESS) return target;
    defer _ = linux.close(target.root);

    const target_tree_result = live_root.cloneMountDescriptor(target.root, false);
    const target_tree_error = linux.errno(target_tree_result);
    if (target_tree_error != .SUCCESS) return .{ .err = target_tree_error };
    const target_tree: i32 = @intCast(target_tree_result);
    defer _ = linux.close(target_tree);
    const hidden_source_attributes: live_root.MountAttribute = .{
        .attr_set = 1 | 2 | 4 | 8,
        .attr_clear = 0,
        .propagation = 0,
    };
    const hidden_source_protected = linux.errno(
        live_root.setMountAttributes(target_tree, false, &hidden_source_attributes),
    );
    if (hidden_source_protected != .SUCCESS)
        return .{ .err = hidden_source_protected };

    const opened = live_root.cloneMountDescriptor(source.root, false);
    const opened_error = linux.errno(opened);
    if (opened_error != .SUCCESS) return .{ .err = opened_error };
    const tree: i32 = @intCast(opened);
    defer _ = linux.close(tree);
    // Read-only, nosuid and nodev, but executable even if staging is noexec.
    const attributes: live_root.MountAttribute = .{
        .attr_set = 1 | 2 | 4,
        .attr_clear = 8,
        .propagation = 0,
    };
    const protected = linux.errno(live_root.setMountAttributes(tree, false, &attributes));
    if (protected != .SUCCESS) return .{ .err = protected };
    const hidden = linux.errno(linux.move_mount(target_tree, "", source.root, "", .{
        .F_SYMLINKS = false,
        .F_AUTOMOUNTS = false,
        .F_EMPTY_PATH = true,
        .T_SYMLINKS = false,
        .T_AUTOMOUNTS = false,
        .T_EMPTY_PATH = true,
        .SET_GROUP = false,
    }));
    if (hidden != .SUCCESS) return .{ .err = hidden };
    const moved = linux.errno(linux.move_mount(tree, "", target.root, "", .{
        .F_SYMLINKS = false,
        .F_AUTOMOUNTS = false,
        .F_EMPTY_PATH = true,
        .T_SYMLINKS = false,
        .T_AUTOMOUNTS = false,
        .T_EMPTY_PATH = true,
        .SET_GROUP = false,
    }));
    if (moved != .SUCCESS) return .{ .err = moved };
    retain_root = true;
    return root;
}

const ChildStreams = struct {
    input: i32,
    output: i32,
    errors: i32,
    status: i32,
};

/// Moves every descriptor the child still needs above the standard range so
/// each later `dup2` into 0, 1, and 2 really duplicates the descriptor, which
/// also clears CLOEXEC, instead of aliasing or no-op'ing on it. Returns the
/// exact error when a descriptor cannot be moved.
fn liftReservedDescriptors(streams: *ChildStreams) ?linux.E {
    const slots = [_]*i32{ &streams.input, &streams.output, &streams.errors, &streams.status };
    for (slots) |slot| {
        while (slot.* >= 0 and slot.* < 3) {
            const rc = linux.fcntl(slot.*, linux.F.DUPFD_CLOEXEC, 3);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |err| return err,
            }
            const moved: i32 = @intCast(rc);
            const previous = slot.*;
            // Streams may share one descriptor, so every alias moves together.
            for (slots) |alias| {
                if (alias.* == previous) alias.* = moved;
            }
        }
    }
    return null;
}

fn childFail(status_write: i32, stage: SetupStage, err: linux.E) noreturn {
    var record: [child_status_bytes]u8 = undefined;
    record[0] = @intFromEnum(stage);
    std.mem.writeInt(u32, record[1..5], @intFromEnum(err), .little);
    var written: usize = 0;
    while (written < record.len) {
        const rc = linux.write(status_write, record[written..].ptr, record.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => written += rc,
            .INTR => {},
            else => break,
        }
    }
    linux.exit(127);
}

const ReadEnds = struct {
    output: i32,
    errors: i32,
    status: i32,
};

fn supervise(
    allocator: std.mem.Allocator,
    invocation: Invocation,
    pid: i32,
    ends: ReadEnds,
) !Execution {
    var fds = ends;
    defer closeFd(&fds.output);
    defer closeFd(&fds.errors);
    defer closeFd(&fds.status);

    var primary: std.ArrayList(u8) = .empty;
    defer primary.deinit(allocator);
    var secondary: std.ArrayList(u8) = .empty;
    defer secondary.deinit(allocator);

    var captured: usize = 0;
    var limit_exceeded = false;
    var setup: ?SetupFailure = null;
    var child_exited = false;
    var timed_out = false;
    var cancelled = false;
    var child_reaped = false;
    errdefer if (!child_reaped) {
        _ = linux.kill(-pid, .KILL);
        _ = linux.kill(pid, .KILL);
        _ = reapChild(pid, false) catch null;
    };

    const started = monotonicMs();
    var drain_deadline: ?u64 = null;
    var buffer: [4096]u8 = undefined;

    // The loop never ends merely because the captured streams closed: a script
    // that closes or redirects its own stdio keeps running, so the deadline and
    // the cancellation token stay authoritative until the child is observed to
    // have exited.
    while (true) {
        if (invocation.cancellation.cancelled()) {
            cancelled = true;
            break;
        }
        const elapsed = monotonicMs() - started;
        if (elapsed >= invocation.limits.timeout_ms) {
            timed_out = true;
            break;
        }
        if (drain_deadline) |deadline| {
            if (monotonicMs() >= deadline) break;
        }
        const streaming = fds.output >= 0 or fds.errors >= 0 or fds.status >= 0;
        if (child_exited and !streaming) break;

        var poll_fds: [3]linux.pollfd = undefined;
        var slots: [3]*i32 = undefined;
        var count: usize = 0;
        for ([_]*i32{ &fds.output, &fds.errors, &fds.status }) |slot| {
            if (slot.* < 0) continue;
            poll_fds[count] = .{ .fd = slot.*, .events = linux.POLL.IN, .revents = 0 };
            slots[count] = slot;
            count += 1;
        }

        const wait_ms = @min(
            @as(u64, invocation.limits.poll_interval_ms),
            invocation.limits.timeout_ms - elapsed,
        );
        const rc = linux.poll(&poll_fds, count, @intCast(wait_ms));
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => {
                setup = .{ .stage = .wait, .errno = @intFromEnum(linux.errno(rc)) };
                break;
            },
        }

        var progressed = false;
        for (poll_fds[0..count], slots[0..count]) |poll_fd, slot| {
            if (poll_fd.revents == 0) continue;
            progressed = true;
            const read_rc = linux.read(poll_fd.fd, &buffer, buffer.len);
            switch (linux.errno(read_rc)) {
                .SUCCESS => {},
                .INTR, .AGAIN => continue,
                else => {
                    closeFd(slot);
                    continue;
                },
            }
            if (read_rc == 0) {
                closeFd(slot);
                continue;
            }
            const chunk = buffer[0..read_rc];
            if (slot == &fds.status) {
                if (chunk.len >= child_status_bytes) setup = .{
                    .stage = @enumFromInt(chunk[0]),
                    .errno = std.mem.readInt(u32, chunk[1..5], .little),
                };
                continue;
            }
            const sink = if (slot == &fds.errors) &secondary else &primary;
            const remaining = invocation.limits.maximum_output_bytes - captured;
            const accepted = @min(remaining, chunk.len);
            try sink.appendSlice(allocator, chunk[0..accepted]);
            captured += accepted;
            if (accepted < chunk.len) {
                limit_exceeded = true;
                break;
            }
        }
        if (limit_exceeded) break;

        // The exit probe never reaps: the pid stays pinned by its zombie so the
        // process group remains safe to signal during finalization.
        if (!child_exited) child_exited = probeExited(pid);
        // An exited script whose descendants still hold the pipes only gets a
        // bounded drain window before the group is terminated.
        if (child_exited and !progressed and drain_deadline == null)
            drain_deadline = monotonicMs() + invocation.limits.descendant_drain_ms;
    }

    var operations: SystemGroupOperations = .{ .pid = pid };
    const finalized = finalizeGroup(&operations, .{
        .leader_exited = child_exited,
        .sweep = invocation.descendants == .terminate,
        .grace_ms = invocation.limits.termination_grace_ms,
        .poll_ms = group_poll_interval_ms,
    });
    const reaped = finalized.status;
    child_reaped = reaped != null;
    const terminated = finalized.terminated;
    const escalated = finalized.escalated;
    const issued_sweep = finalized.issued_sweep;

    const outcome: LaunchOutcome = if (setup) |failure|
        .{ .setup_failed = failure }
    else if (cancelled)
        .cancelled
    else if (timed_out)
        .timed_out
    else if (limit_exceeded)
        .output_limit_exceeded
    else if (reaped) |status|
        terminationOf(status)
    else
        .{ .setup_failed = .{ .stage = .wait } };

    var execution: Execution = .{
        .outcome = outcome,
        .terminated_process_group = terminated,
        .escalated_to_kill = escalated,
        .issued_descendant_sweep = issued_sweep,
    };
    switch (invocation.capture) {
        .separate => {
            execution.stdout = try primary.toOwnedSlice(allocator);
            errdefer allocator.free(execution.stdout);
            execution.stderr = try secondary.toOwnedSlice(allocator);
        },
        .combined => execution.combined = try primary.toOwnedSlice(allocator),
    }
    return execution;
}

fn terminationOf(status: u32) LaunchOutcome {
    if (linux.W.IFEXITED(status)) return .{ .exited = linux.W.EXITSTATUS(status) };
    if (linux.W.IFSIGNALED(status)) return .{ .signaled = @intFromEnum(linux.W.TERMSIG(status)) };
    if (linux.W.IFSTOPPED(status)) return .{ .signaled = @intFromEnum(linux.W.STOPSIG(status)) };
    return .{ .signaled = status };
}

const group_poll_interval_ms = 5;

const SignalScope = enum { leader, group };

const TerminationSignal = enum { term, kill };

const Finalization = struct {
    /// Whether the leader was already observed to have exited without reaping.
    leader_exited: bool,
    /// Whether the descendant policy signals the whole process group instead
    /// of the leader alone and issues a final group-wide sweep.
    sweep: bool,
    grace_ms: u64,
    poll_ms: u64,
};

const FinalizeResult = struct {
    status: ?u32 = null,
    terminated: bool = false,
    escalated: bool = false,
    /// The group-wide `SIGKILL` sweep was issued. Survivorship is unknowable:
    /// `kill` on the group cannot distinguish "no descendant was left" from
    /// "descendants were killed", so this only records the attempt.
    issued_sweep: bool = false,
};

/// Ordering-critical shutdown. Every signal is delivered while the leader pid
/// is still pinned by an unreaped child, and the reap is the final operation,
/// so neither a recycled pid nor a recycled process group can ever be
/// signalled by this runner.
fn finalizeGroup(operations: anytype, plan: Finalization) FinalizeResult {
    var result: FinalizeResult = .{};
    var exited = plan.leader_exited;
    const scope: SignalScope = if (plan.sweep) .group else .leader;
    if (!exited) {
        operations.signal(scope, .term);
        result.terminated = true;
        exited = awaitExit(operations, plan);
        if (!exited) {
            operations.signal(scope, .kill);
            result.escalated = true;
            exited = awaitExit(operations, plan);
        }
    }
    if (plan.sweep) {
        // Any survivor is removed before the reap, while the pid is still
        // pinned. The signal is issued unconditionally because a live
        // descendant cannot be observed without racing it; the recorded
        // evidence is therefore the sweep attempt, not a survivor count.
        operations.signal(.group, .kill);
        result.issued_sweep = true;
    }
    result.status = operations.reap(exited);
    return result;
}

fn awaitExit(operations: anytype, plan: Finalization) bool {
    const deadline = operations.now() + plan.grace_ms;
    while (true) {
        if (operations.exited()) return true;
        if (operations.now() >= deadline) return false;
        operations.sleep(plan.poll_ms);
    }
}

const SystemGroupOperations = struct {
    pid: i32,

    fn signal(self: *SystemGroupOperations, scope: SignalScope, number: TerminationSignal) void {
        const target: i32 = switch (scope) {
            .leader => self.pid,
            .group => -self.pid,
        };
        _ = linux.kill(target, switch (number) {
            .term => .TERM,
            .kill => .KILL,
        });
    }

    fn exited(self: *SystemGroupOperations) bool {
        return probeExited(self.pid);
    }

    fn reap(self: *SystemGroupOperations, known_exited: bool) ?u32 {
        return reapChild(self.pid, !known_exited) catch null;
    }

    fn now(_: *SystemGroupOperations) u64 {
        return monotonicMs();
    }

    fn sleep(_: *SystemGroupOperations, milliseconds: u64) void {
        sleepMs(milliseconds);
    }
};

/// Non-destructive exit probe. `WNOWAIT` leaves the zombie in place, so the
/// leader pid keeps its process-group identity reserved until the final reap.
fn probeExited(pid: i32) bool {
    while (true) {
        var info: linux.siginfo_t = std.mem.zeroes(linux.siginfo_t);
        const rc = linux.waitid(
            .PID,
            pid,
            &info,
            linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT,
            null,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => return info.fields.common.first.piduid.pid == pid,
            .INTR => continue,
            // No such child left to wait for: it can no longer be running.
            else => return true,
        }
    }
}

fn reapChild(pid: i32, nohang: bool) !?u32 {
    var status: u32 = 0;
    while (true) {
        const rc = linux.waitpid(pid, &status, if (nohang) linux.W.NOHANG else 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return null;
                return status;
            },
            .INTR => continue,
            .CHILD => return null,
            else => return error.WaitFailed,
        }
    }
}

fn createPipe() struct { fds: [2]i32, errno: u32 } {
    var fds: [2]i32 = undefined;
    const rc = linux.pipe2(&fds, .{ .CLOEXEC = true });
    return switch (linux.errno(rc)) {
        .SUCCESS => .{ .fds = fds, .errno = 0 },
        else => |err| .{ .fds = .{ -1, -1 }, .errno = @intFromEnum(err) },
    };
}

fn openNullDevice() struct { fd: i32, errno: u32 } {
    const rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => .{ .fd = @intCast(rc), .errno = 0 },
        else => |err| .{ .fd = -1, .errno = @intFromEnum(err) },
    };
}

fn closePipe(fds: *[2]i32) void {
    closeFd(&fds[0]);
    closeFd(&fds[1]);
}

fn closeFd(fd: *i32) void {
    if (fd.* < 0) return;
    _ = linux.close(fd.*);
    fd.* = -1;
}

fn monotonicMs() u64 {
    var value: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &value)) != .SUCCESS) return 0;
    return @as(u64, @intCast(value.sec)) * 1000 + @as(u64, @intCast(value.nsec)) / 1_000_000;
}

fn sleepMs(milliseconds: u64) void {
    const request: linux.timespec = .{
        .sec = @intCast(milliseconds / 1000),
        .nsec = @intCast((milliseconds % 1000) * 1_000_000),
    };
    _ = linux.nanosleep(&request, null);
}

const testing = std.testing;

const RecordingLauncher = struct {
    outcome: LaunchOutcome = .{ .exited = 0 },
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    combined: []const u8 = "",
    failure: ?anyerror = null,
    terminated_process_group: bool = false,
    escalated_to_kill: bool = false,
    issued_descendant_sweep: bool = false,
    launches: usize = 0,
    invocation: ?Invocation = null,

    fn interface(self: *RecordingLauncher) Launcher {
        return .{ .context = self, .launchFn = launchRecorded };
    }

    fn launchRecorded(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        invocation: Invocation,
    ) anyerror!Execution {
        const self: *RecordingLauncher = @ptrCast(@alignCast(context));
        self.launches += 1;
        self.invocation = invocation;
        if (self.failure) |err| return err;
        const captured_stdout = try allocator.dupe(u8, self.stdout);
        errdefer allocator.free(captured_stdout);
        const captured_stderr = try allocator.dupe(u8, self.stderr);
        errdefer allocator.free(captured_stderr);
        const captured_combined = try allocator.dupe(u8, self.combined);
        return .{
            .outcome = self.outcome,
            .stdout = captured_stdout,
            .stderr = captured_stderr,
            .combined = captured_combined,
            .terminated_process_group = self.terminated_process_group,
            .escalated_to_kill = self.escalated_to_kill,
            .issued_descendant_sweep = self.issued_descendant_sweep,
        };
    }
};

const CountingCancellation = struct {
    checks: usize = 0,
    cancel_after: usize,

    fn interface(self: *CountingCancellation) Cancellation {
        return .{ .context = self, .cancelledFn = cancelled };
    }

    fn cancelled(context: *anyopaque) bool {
        const self: *CountingCancellation = @ptrCast(@alignCast(context));
        self.checks += 1;
        return self.checks > self.cancel_after;
    }
};

fn testRequest() Request {
    return .{
        .root = "/srv/roots/target",
        .identity = .{
            .package = "demo",
            .version = "1.0-1",
            .architecture = "amd64",
            .kind = .postinst,
            .script_path = "var/lib/dpkg/info/demo.postinst",
            .script_sha256 = @splat(0x11),
        },
        .arguments = &.{ "configure", "0.9-1" },
    };
}

test "maintainer_script.test.fresh postinst preserves empty prior version argument" {
    var request = testRequest();
    request.arguments = &.{ "configure", "" };
    try testing.expect(validate(request) == null);
    request.identity.kind = .preinst;
    request.identity.script_path = "var/lib/dpkg/info/demo.preinst";
    try testing.expectEqual(RejectionReason.invalid_argument, validate(request).?);
}

test "maintainer_script.test.unsafe requests are rejected before any spawn" {
    const Case = struct {
        reason: RejectionReason,
        mutate: *const fn (*Request) void,
    };
    const cases = [_]Case{
        .{ .reason = .invalid_root, .mutate = struct {
            fn apply(request: *Request) void {
                request.root = "srv/roots/target";
            }
        }.apply },
        .{ .reason = .invalid_root, .mutate = struct {
            fn apply(request: *Request) void {
                request.root = "/srv/../roots";
            }
        }.apply },
        .{ .reason = .host_root_denied, .mutate = struct {
            fn apply(request: *Request) void {
                request.root = "/";
            }
        }.apply },
        .{ .reason = .invalid_script_path, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "/var/lib/dpkg/info/demo.postinst";
            }
        }.apply },
        .{ .reason = .invalid_script_path, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "var/lib/dpkg/info/../../../etc/demo.postinst";
            }
        }.apply },
        .{ .reason = .script_directory_denied, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "tmp/demo.postinst";
            }
        }.apply },
        .{ .reason = .invalid_script_name, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "var/lib/dpkg/info/other.postinst";
            }
        }.apply },
        .{ .reason = .invalid_script_name, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.script_path = "var/lib/dpkg/info/demo.prerm";
            }
        }.apply },
        .{ .reason = .invalid_package, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.package = "Demo Package";
            }
        }.apply },
        .{ .reason = .invalid_architecture, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.architecture = "amd64;rm";
            }
        }.apply },
        .{ .reason = .invalid_version, .mutate = struct {
            fn apply(request: *Request) void {
                request.identity.version = "1.0 -1";
            }
        }.apply },
        .{ .reason = .invalid_argument, .mutate = struct {
            fn apply(request: *Request) void {
                request.arguments = &.{"--force-all"};
            }
        }.apply },
        .{ .reason = .invalid_argument, .mutate = struct {
            fn apply(request: *Request) void {
                request.arguments = &.{"configure\n--"};
            }
        }.apply },
        .{ .reason = .too_many_arguments, .mutate = struct {
            fn apply(request: *Request) void {
                request.policy.limits.maximum_arguments = 1;
            }
        }.apply },
        .{ .reason = .invalid_variable, .mutate = struct {
            fn apply(request: *Request) void {
                request.variables = &.{.{ .name = .running_version, .value = "1.21\x00" }};
            }
        }.apply },
        .{ .reason = .duplicate_variable, .mutate = struct {
            fn apply(request: *Request) void {
                request.variables = &.{
                    .{ .name = .running_version, .value = "1.21" },
                    .{ .name = .running_version, .value = "1.22" },
                };
            }
        }.apply },
        .{ .reason = .invalid_timeout, .mutate = struct {
            fn apply(request: *Request) void {
                request.policy.limits.timeout_ms = 0;
            }
        }.apply },
        .{ .reason = .invalid_output_limit, .mutate = struct {
            fn apply(request: *Request) void {
                request.policy.limits.maximum_output_bytes = maximum_output_limit + 1;
            }
        }.apply },
        .{ .reason = .invalid_script_directory, .mutate = struct {
            fn apply(request: *Request) void {
                request.policy.script_directories = &.{"/var/lib/dpkg/info"};
            }
        }.apply },
    };

    var launcher: RecordingLauncher = .{};
    for (cases) |case| {
        var request = testRequest();
        case.mutate(&request);
        try testing.expectEqual(case.reason, validate(request).?);
        var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
        defer report.deinit();
        try testing.expectEqual(case.reason, report.outcome.rejected);
        try testing.expect(!report.succeeded());
        try testing.expect(!report.outcome.spawned());
    }
    try testing.expectEqual(@as(usize, 0), launcher.launches);

    const accepted = testRequest();
    try testing.expect(validate(accepted) == null);
}

test "maintainer_script.test.environment is a fixed allowlist without ambient inheritance" {
    var request = testRequest();
    request.variables = &.{
        .{ .name = .running_version, .value = "1.21.22" },
        .{ .name = .package_refcount, .value = "1" },
    };
    var launcher: RecordingLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();

    const expected = [_]EnvironmentEntry{
        .{ .key = "DEBIAN_FRONTEND", .value = "noninteractive" },
        .{ .key = "DPKG_ADMINDIR", .value = "/var/lib/dpkg" },
        .{ .key = "DPKG_COLORS", .value = "never" },
        .{ .key = "DPKG_MAINTSCRIPT_ARCH", .value = "amd64" },
        .{ .key = "DPKG_MAINTSCRIPT_NAME", .value = "postinst" },
        .{ .key = "DPKG_MAINTSCRIPT_PACKAGE", .value = "demo" },
        .{ .key = "DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT", .value = "1" },
        .{ .key = "DPKG_ROOT", .value = "" },
        .{ .key = "DPKG_RUNNING_VERSION", .value = "1.21.22" },
        .{ .key = "HOME", .value = "/nonexistent" },
        .{ .key = "LANG", .value = "C" },
        .{ .key = "LC_ALL", .value = "C" },
        .{ .key = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" },
    };
    try testing.expectEqual(expected.len, report.environment.len);
    for (expected, report.environment) |wanted, actual| {
        try testing.expectEqualStrings(wanted.key, actual.key);
        try testing.expectEqualStrings(wanted.value, actual.value);
    }
}

test "maintainer_script.test.invocation binds the selected root program and evidence" {
    var launcher: RecordingLauncher = .{};
    var report = try run(testing.allocator, testRequest(), .{ .launcher = launcher.interface() });
    defer report.deinit();

    try testing.expectEqual(@as(usize, 1), launcher.launches);
    const invocation = launcher.invocation.?;
    try testing.expectEqual(Isolation.chroot, invocation.isolation);
    try testing.expectEqualStrings("/srv/roots/target", invocation.root);
    try testing.expectEqualStrings("/var/lib/dpkg/info/demo.postinst", invocation.program);
    try testing.expectEqual(@as(usize, 3), invocation.argv.len);
    try testing.expectEqualStrings("/var/lib/dpkg/info/demo.postinst", invocation.argv[0]);
    try testing.expectEqualStrings("configure", invocation.argv[1]);
    try testing.expectEqualStrings("0.9-1", invocation.argv[2]);
    try testing.expectEqual(Capture.separate, invocation.capture);
    try testing.expectEqual(DescendantPolicy.terminate, invocation.descendants);
    try testing.expectEqualStrings("/var/lib/dpkg/info/demo.postinst", report.program);
    try testing.expect(report.succeeded());

    var host = testRequest();
    host.root = "/";
    host.policy.allow_host_root = true;
    var host_report = try run(testing.allocator, host, .{ .launcher = launcher.interface() });
    defer host_report.deinit();
    try testing.expectEqual(Isolation.host_root, host_report.isolation);
    try testing.expect(!std.mem.eql(
        u8,
        &report.evidence.invocation_sha256,
        &host_report.evidence.invocation_sha256,
    ));

    var renamed = testRequest();
    renamed.identity.script_sha256 = @splat(0x22);
    var renamed_report = try run(testing.allocator, renamed, .{ .launcher = launcher.interface() });
    defer renamed_report.deinit();
    try testing.expect(!std.mem.eql(
        u8,
        &report.evidence.invocation_sha256,
        &renamed_report.evidence.invocation_sha256,
    ));
    try testing.expectEqualSlices(
        u8,
        &report.evidence.argv_sha256,
        &renamed_report.evidence.argv_sha256,
    );

    var repeated = try run(testing.allocator, testRequest(), .{ .launcher = launcher.interface() });
    defer repeated.deinit();
    try testing.expectEqualSlices(
        u8,
        &report.evidence.invocation_sha256,
        &repeated.evidence.invocation_sha256,
    );
    try testing.expectEqualSlices(
        u8,
        &policyDigest(.{}),
        &report.evidence.policy_sha256,
    );
}

test "maintainer_script.test.launcher receives fresh postinst empty argument" {
    var request = testRequest();
    request.arguments = &.{ "configure", "" };
    var launcher: RecordingLauncher = .{};
    var report = try run(
        testing.allocator,
        request,
        .{ .launcher = launcher.interface() },
    );
    defer report.deinit();

    const invocation = launcher.invocation.?;
    try testing.expectEqual(@as(usize, 3), invocation.argv.len);
    try testing.expectEqualStrings("configure", invocation.argv[1]);
    try testing.expectEqualStrings("", invocation.argv[2]);
}

test "maintainer_script.test.outcomes remain exactly distinguishable" {
    const outcomes = [_]LaunchOutcome{
        .{ .exited = 0 },
        .{ .exited = 1 },
        .{ .signaled = 9 },
        .timed_out,
        .cancelled,
        .output_limit_exceeded,
        .{ .setup_failed = .{ .stage = .snapshot_proc, .errno = 1 } },
        .{ .setup_failed = .{ .stage = .root_isolation, .errno = 1 } },
        .{ .setup_failed = .{ .stage = .fork, .errno = 11 } },
    };
    for (outcomes) |outcome| {
        var launcher: RecordingLauncher = .{ .outcome = outcome, .stdout = "out", .stderr = "err" };
        var report = try run(testing.allocator, testRequest(), .{ .launcher = launcher.interface() });
        defer report.deinit();
        try testing.expectEqualStrings(
            @tagName(std.meta.activeTag(outcome)),
            @tagName(std.meta.activeTag(report.outcome)),
        );
        try testing.expectEqualStrings("out", report.stdout);
        try testing.expectEqualStrings("err", report.stderr);
        try testing.expectEqual(@as(usize, 6), report.output_bytes);
        try testing.expectEqualSlices(u8, &hashBytes("out"), &report.evidence.stdout_sha256);
        try testing.expectEqualSlices(u8, &hashBytes("err"), &report.evidence.stderr_sha256);
        switch (outcome) {
            .exited => |code| {
                try testing.expectEqual(code, report.outcome.exited);
                try testing.expectEqual(code == 0, report.succeeded());
            },
            .signaled => |signal| try testing.expectEqual(signal, report.outcome.signaled),
            .setup_failed => |failure| {
                try testing.expectEqual(failure.stage, report.outcome.setup_failed.stage);
                try testing.expectEqual(failure.errno, report.outcome.setup_failed.errno);
                try testing.expectEqual(
                    failure.stage == .root_isolation,
                    report.outcome.spawned(),
                );
            },
            else => try testing.expect(!report.succeeded()),
        }
    }
}

fn environmentValue(environment: []const EnvironmentEntry, key: []const u8) ?[]const u8 {
    for (environment) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry.value;
    }
    return null;
}

test "maintainer_script.test.report owns every reported string" {
    const allocator = testing.allocator;
    const root = try allocator.dupe(u8, "/srv/roots/target");
    const package = try allocator.dupe(u8, "demo");
    const script_path = try allocator.dupe(u8, "var/lib/dpkg/info/demo.postinst");
    const argument = try allocator.dupe(u8, "configure");
    const refcount = try allocator.dupe(u8, "1");

    var request = testRequest();
    request.root = root;
    request.identity.package = package;
    request.identity.script_path = script_path;
    request.arguments = &.{argument};
    request.variables = &.{.{ .name = .package_refcount, .value = refcount }};

    var launcher: RecordingLauncher = .{ .outcome = .{ .exited = 0 } };
    var report = try run(allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();

    allocator.free(root);
    allocator.free(package);
    allocator.free(script_path);
    allocator.free(argument);
    allocator.free(refcount);

    try testing.expectEqualStrings("/srv/roots/target", report.root);
    try testing.expectEqualStrings("demo", report.identity.package);
    try testing.expectEqualStrings("var/lib/dpkg/info/demo.postinst", report.identity.script_path);
    try testing.expectEqualStrings("/var/lib/dpkg/info/demo.postinst", report.argv[0]);
    try testing.expectEqualStrings("configure", report.argv[1]);
    const refcount_value = environmentValue(
        report.environment,
        "DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT",
    ).?;
    try testing.expectEqualStrings("1", refcount_value);
    try testing.expectEqualStrings("demo", environmentValue(report.environment, "DPKG_MAINTSCRIPT_PACKAGE").?);
}

test "maintainer_script.test.sweep evidence records the attempt, not survivors" {
    // A rejected request never spawns, so no signal of any kind was issued.
    var rejecting: RecordingLauncher = .{};
    var rejected_request = testRequest();
    rejected_request.identity.script_path = "etc/demo.postinst";
    var rejected = try run(testing.allocator, rejected_request, .{
        .launcher = rejecting.interface(),
    });
    defer rejected.deinit();
    try testing.expectEqual(@as(usize, 0), rejecting.launches);
    try testing.expect(!rejected.issued_descendant_sweep);
    try testing.expect(!rejected.terminated_process_group);

    // A script that exited on its own still gets the group-wide sweep under the
    // `terminate` policy. The report must say the sweep was issued without
    // claiming a descendant was alive, so termination stays false.
    var swept: RecordingLauncher = .{
        .outcome = .{ .exited = 0 },
        .issued_descendant_sweep = true,
    };
    var clean = try run(testing.allocator, testRequest(), .{ .launcher = swept.interface() });
    defer clean.deinit();
    try testing.expect(clean.succeeded());
    try testing.expect(clean.issued_descendant_sweep);
    try testing.expect(!clean.terminated_process_group);
    try testing.expect(!clean.escalated_to_kill);

    // An actually terminated process group is distinguishable from the sweep.
    var forced: RecordingLauncher = .{
        .outcome = .timed_out,
        .terminated_process_group = true,
        .escalated_to_kill = true,
        .issued_descendant_sweep = true,
    };
    var terminated = try run(testing.allocator, testRequest(), .{ .launcher = forced.interface() });
    defer terminated.deinit();
    try testing.expectEqualStrings("timed_out", @tagName(terminated.outcome));
    try testing.expect(terminated.terminated_process_group);
    try testing.expect(terminated.escalated_to_kill);
    try testing.expect(terminated.issued_descendant_sweep);

    // The `detach` policy never signals the group, so no sweep is issued.
    var detached_launcher: RecordingLauncher = .{ .outcome = .{ .exited = 0 } };
    var detached_request = testRequest();
    detached_request.policy.descendants = .detach;
    var detached = try run(testing.allocator, detached_request, .{
        .launcher = detached_launcher.interface(),
    });
    defer detached.deinit();
    try testing.expectEqual(DescendantPolicy.detach, detached_launcher.invocation.?.descendants);
    try testing.expect(!detached.issued_descendant_sweep);
}

test "maintainer_script.test.launcher failures become typed setup evidence" {
    var failing: RecordingLauncher = .{ .failure = error.AccessDenied };
    var report = try run(testing.allocator, testRequest(), .{ .launcher = failing.interface() });
    defer report.deinit();
    try testing.expectEqual(SetupStage.launcher, report.outcome.setup_failed.stage);
    try testing.expect(!report.outcome.spawned());
    try testing.expect(!report.succeeded());

    var exhausted: RecordingLauncher = .{ .failure = error.OutOfMemory };
    try testing.expectError(
        error.OutOfMemory,
        run(testing.allocator, testRequest(), .{ .launcher = exhausted.interface() }),
    );
}

fn skipUnlessPosixShell() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var shell = std.Io.Dir.openFileAbsolute(testing.io, "/bin/sh", .{ .mode = .read_only }) catch
        return error.SkipZigTest;
    shell.close(testing.io);
}

fn skipUnlessPython3() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var python = std.Io.Dir.openFileAbsolute(testing.io, "/usr/bin/python3", .{ .mode = .read_only }) catch
        return error.SkipZigTest;
    python.close(testing.io);
}

fn skipUnlessHostFile(path: []const u8) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var file = std.Io.Dir.openFileAbsolute(testing.io, path, .{ .mode = .read_only }) catch
        return error.SkipZigTest;
    file.close(testing.io);
}

fn writeExecutableScript(
    directory: *std.testing.TmpDir,
    sub_path: []const u8,
    body: []const u8,
) !void {
    if (std.fs.path.dirname(sub_path)) |parent|
        try directory.dir.createDirPath(testing.io, parent);
    try directory.dir.writeFile(testing.io, .{
        .sub_path = sub_path,
        .data = body,
        .flags = .{ .permissions = .executable_file },
    });
}

fn absoluteTempPath(
    allocator: std.mem.Allocator,
    directory: *std.testing.TmpDir,
    sub_path: []const u8,
) ![]u8 {
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ buffer[0..length], sub_path });
}

/// Hermetic host-root fixture. Host-root execution is the strongest script
/// execution unprivileged CI can perform; the alternate-root chroot contract is
/// exercised separately.
const HostScript = struct {
    absolute: []u8,
    directories: [1][]const u8,

    fn init(
        allocator: std.mem.Allocator,
        directory: *std.testing.TmpDir,
        sub_path: []const u8,
        body: []const u8,
    ) !HostScript {
        try writeExecutableScript(directory, sub_path, body);
        const absolute = try absoluteTempPath(allocator, directory, sub_path);
        errdefer allocator.free(absolute);
        const relative = absolute[1..];
        return .{
            .absolute = absolute,
            .directories = .{std.fs.path.dirname(relative) orelse return error.TestUnexpectedResult},
        };
    }

    fn deinit(self: *HostScript, allocator: std.mem.Allocator) void {
        allocator.free(self.absolute);
        self.* = undefined;
    }

    fn request(self: *const HostScript, arguments: []const []const u8) Request {
        return .{
            .root = "/",
            .identity = .{
                .package = "demo",
                .version = "1.0-1",
                .architecture = "amd64",
                .kind = .postinst,
                .script_path = self.absolute[1..],
                .script_sha256 = @splat(0),
            },
            .arguments = arguments,
            .policy = .{
                .allow_host_root = true,
                .script_directories = &self.directories,
                .limits = .{ .timeout_ms = 20_000, .termination_grace_ms = 500 },
            },
        };
    }
};

fn requirePrivateNetworkNamespace() bool {
    return std.c.getenv("DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE") != null;
}

fn skipIfPrivateNetworkUnavailable(report: *const Report) !bool {
    switch (report.outcome) {
        .setup_failed => |failure| if (failure.stage == .network_namespace and
            failure.errno == @intFromEnum(linux.E.PERM))
        {
            try testing.expect(!report.outcome.spawned());
            if (requirePrivateNetworkNamespace())
                return error.NativeHelperNamespaceRequired;
            return true;
        },
        else => {},
    }
    return false;
}

const SockaddrIn = extern struct {
    family: linux.sa_family_t,
    port: u16,
    addr: [4]u8,
    zero: [8]u8 = .{0} ** 8,
};

const SockaddrUn = extern struct {
    family: linux.sa_family_t,
    path: [108]u8,
};

const LoopbackListener = struct {
    fd: i32,
    port: u16,
};

fn openLoopbackListener() !LoopbackListener {
    const opened = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(opened) != .SUCCESS) return error.TestSocketUnavailable;
    const fd: i32 = @intCast(opened);
    errdefer _ = linux.close(fd);
    var address: SockaddrIn = .{
        .family = linux.AF.INET,
        .port = 0,
        .addr = .{ 127, 0, 0, 1 },
    };
    const bound = linux.errno(linux.bind(
        fd,
        @ptrCast(&address),
        @sizeOf(SockaddrIn),
    ));
    if (bound != .SUCCESS) return error.TestSocketUnavailable;
    const listened = linux.errno(linux.listen(fd, 1));
    if (listened != .SUCCESS) return error.TestSocketUnavailable;
    var observed: SockaddrIn = undefined;
    var length: linux.socklen_t = @sizeOf(SockaddrIn);
    const named = linux.errno(linux.getsockname(
        fd,
        @ptrCast(&observed),
        &length,
    ));
    if (named != .SUCCESS or length < @sizeOf(SockaddrIn)) return error.TestSocketUnavailable;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, observed.port) };
}

fn openAbstractUnixListener(name: []const u8) !i32 {
    if (name.len == 0 or name.len + 1 > 108) return error.TestSocketUnavailable;
    const opened = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(opened) != .SUCCESS) return error.TestSocketUnavailable;
    const fd: i32 = @intCast(opened);
    errdefer _ = linux.close(fd);
    var address: SockaddrUn = .{
        .family = linux.AF.UNIX,
        .path = .{0} ** 108,
    };
    @memcpy(address.path[1 .. 1 + name.len], name);
    const bound = linux.errno(linux.bind(
        fd,
        @ptrCast(&address),
        @intCast(@offsetOf(SockaddrUn, "path") + 1 + name.len),
    ));
    if (bound != .SUCCESS) return error.TestSocketUnavailable;
    const listened = linux.errno(linux.listen(fd, 1));
    if (listened != .SUCCESS) return error.TestSocketUnavailable;
    return fd;
}

fn countOpenFds() !usize {
    var dir = try std.Io.Dir.openDirAbsolute(testing.io, "/proc/self/fd", .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer dir.close(testing.io);
    var iterator = dir.iterate();
    var count: usize = 0;
    while (try iterator.next(testing.io)) |_| count += 1;
    return count;
}

fn currentNetworkNamespace(buffer: *[128]u8) ![]const u8 {
    const read = linux.readlink("/proc/self/ns/net", buffer, buffer.len);
    if (linux.errno(read) != .SUCCESS) return error.TestNetworkNamespaceUnavailable;
    return buffer[0..read];
}

test "maintainer_script.test.system launcher captures bounded output from a sanitized child" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\printf 'argument=%s\n' "$1"
        \\printf 'directory=%s\n' "$PWD"
        \\printf 'path=%s\n' "$PATH"
        \\printf 'locale=%s\n' "$LC_ALL"
        \\printf 'frontend=%s\n' "$DEBIAN_FRONTEND"
        \\printf 'package=%s\n' "$DPKG_MAINTSCRIPT_PACKAGE"
        \\printf 'name=%s\n' "$DPKG_MAINTSCRIPT_NAME"
        \\printf 'home=%s\n' "$HOME"
        \\printf 'ambient=[%s]\n' "${DEBZ_AMBIENT_TEST_VALUE-}"
        \\printf 'stdin=[%s]\n' "$(cat)"
        \\printf 'diagnostic\n' >&2
        \\exit 3
        \\
    );
    defer script.deinit(testing.allocator);

    var launcher: SystemLauncher = .{};
    var report = try run(
        testing.allocator,
        script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    );
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqual(@as(u8, 3), report.outcome.exited);
    try testing.expect(!report.succeeded());
    try testing.expectEqualStrings("diagnostic\n", report.stderr);
    try testing.expectEqualStrings("", report.combined);
    try testing.expectEqualStrings(
        \\argument=configure
        \\directory=/
        \\path=/usr/sbin:/usr/bin:/sbin:/bin
        \\locale=C
        \\frontend=noninteractive
        \\package=demo
        \\name=postinst
        \\home=/nonexistent
        \\ambient=[]
        \\stdin=[]
        \\
    , report.stdout);
    try testing.expectEqualSlices(u8, &hashBytes(report.stdout), &report.evidence.stdout_sha256);
    try testing.expect(!report.terminated_process_group);
    try testing.expect(!report.escalated_to_kill);
    // The script exited on its own, so nothing was terminated. The sweep is
    // still issued under the `terminate` policy, and the flag reports only
    // that: it never asserts that a descendant survived.
    try testing.expect(report.issued_descendant_sweep);
}

test "maintainer_script.test.system launcher forces dpkg's umask over the caller's" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\umask
        \\
    );
    defer script.deinit(testing.allocator);
    const caller = linux.syscall1(.umask, 0o077);
    defer _ = linux.syscall1(.umask, caller);

    var launcher: SystemLauncher = .{};
    var report = try run(
        testing.allocator,
        script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    );
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;
    try testing.expect(report.succeeded());
    try testing.expectEqualStrings("0022\n", report.stdout);
    try testing.expectEqual(@as(usize, 0o077), linux.syscall1(.umask, 0o077));
}

test "maintainer_script.test.system launcher uses private loopback and seals inherited sockets" {
    try skipUnlessPosixShell();
    try skipUnlessPython3();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    const listener = try openLoopbackListener();
    defer _ = linux.close(listener.fd);
    const abstract_name = try std.fmt.allocPrint(
        testing.allocator,
        "debz278-{d}-{d}",
        .{ linux.getpid(), monotonicMs() },
    );
    defer testing.allocator.free(abstract_name);
    const unix_listener = try openAbstractUnixListener(abstract_name);
    defer _ = linux.close(unix_listener);
    var leaked: [2]i32 = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&leaked, .{})));
    defer closePipe(&leaked);

    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\exec python3 - "$@" <<'PY'
        \\import errno, os, socket, sys
        \\port = int(sys.argv[1])
        \\abstract_name = sys.argv[2]
        \\leaked_fd = int(sys.argv[3])
        \\
        \\def emit(key, value):
        \\    print(f"{key}={value}")
        \\
        \\emit("proc_net", "present" if os.path.isdir("/proc/net") else "absent")
        \\interfaces = []
        \\try:
        \\    with open("/proc/net/dev", "r", encoding="utf-8") as handle:
        \\        for line in handle.readlines()[2:]:
        \\            if ":" in line:
        \\                interfaces.append(line.split(":", 1)[0].strip())
        \\except OSError as exc:
        \\    emit("interfaces_error", str(exc.errno))
        \\emit("interfaces", ",".join(sorted(interfaces)))
        \\default_route = "false"
        \\try:
        \\    with open("/proc/net/route", "r", encoding="utf-8") as handle:
        \\        for line in handle.readlines()[1:]:
        \\            fields = line.split()
        \\            if len(fields) >= 2 and fields[1] == "00000000":
        \\                default_route = "true"
        \\except OSError:
        \\    pass
        \\emit("default_route", default_route)
        \\
        \\try:
        \\    socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
        \\    emit("socket_tcp", "ok")
        \\except OSError as exc:
        \\    emit("socket_tcp", f"errno:{exc.errno}")
        \\
        \\try:
        \\    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        \\    probe.settimeout(0.2)
        \\    probe.connect(("127.0.0.1", port))
        \\    emit("host_tcp_connect", "ok")
        \\    probe.close()
        \\except OSError as exc:
        \\    emit("host_tcp_connect", f"denied:{exc.errno}")
        \\
        \\try:
        \\    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        \\    server.bind(("127.0.0.1", 0))
        \\    server.listen(1)
        \\    client = socket.create_connection(("127.0.0.1", server.getsockname()[1]), timeout=0.2)
        \\    accepted, _ = server.accept()
        \\    accepted.close()
        \\    client.close()
        \\    server.close()
        \\    emit("bind_loopback", "ok")
        \\except OSError as exc:
        \\    emit("bind_loopback", f"errno:{exc.errno}")
        \\
        \\try:
        \\    unix_probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        \\    unix_probe.settimeout(0.2)
        \\    unix_probe.connect("\\0" + abstract_name)
        \\    emit("abstract_unix_connect", "ok")
        \\    unix_probe.close()
        \\except OSError as exc:
        \\    emit("abstract_unix_connect", f"denied:{exc.errno}")
        \\
        \\try:
        \\    os.write(leaked_fd, b"x")
        \\    emit("inherited_fd", "ok")
        \\except OSError as exc:
        \\    emit("inherited_fd", f"sealed:{exc.errno}")
        \\PY
        \\
    );
    defer script.deinit(testing.allocator);
    const port = try std.fmt.allocPrint(testing.allocator, "{d}", .{listener.port});
    defer testing.allocator.free(port);
    const fd = try std.fmt.allocPrint(testing.allocator, "{d}", .{leaked[1]});
    defer testing.allocator.free(fd);

    var launcher: SystemLauncher = .{};
    var report = try run(
        testing.allocator,
        script.request(&.{ port, abstract_name, fd }),
        .{ .launcher = launcher.interface() },
    );
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqual(@as(u8, 0), report.outcome.exited);
    try testing.expectEqualStrings("", report.stderr);
    try testing.expect(std.mem.indexOf(u8, report.stdout, "proc_net=present\n") != null);
    try testing.expect(std.mem.indexOf(u8, report.stdout, "interfaces=lo\n") != null);
    try testing.expect(std.mem.indexOf(u8, report.stdout, "default_route=false\n") != null);
    try testing.expect(std.mem.indexOf(u8, report.stdout, "socket_tcp=ok\n") != null);
    try testing.expect(std.mem.indexOf(u8, report.stdout, "host_tcp_connect=denied:") != null);
    try testing.expect(std.mem.indexOf(u8, report.stdout, "bind_loopback=ok\n") != null);
    try testing.expect(std.mem.indexOf(u8, report.stdout, "abstract_unix_connect=denied:") != null);
    try testing.expect(std.mem.indexOf(u8, report.stdout, "inherited_fd=sealed:9\n") != null);
}

test "maintainer_script.test.debconf confmodule reexec works with sealed descriptors" {
    try skipUnlessPosixShell();
    try skipUnlessHostFile("/usr/share/debconf/confmodule");
    try skipUnlessHostFile("/usr/share/debconf/frontend");
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\. /usr/share/debconf/confmodule
        \\db_version 2.0 >/dev/null
        \\printf 'debconf-reexec=%s\n' "${DEBIAN_HAS_FRONTEND:-missing}"
        \\db_stop
        \\
    );
    defer script.deinit(testing.allocator);

    var launcher: SystemLauncher = .{};
    var report = try run(
        testing.allocator,
        script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    );
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    if (!report.succeeded())
        std.debug.print("debconf outcome={any} stdout={s} stderr={s}\n", .{
            report.outcome,
            report.stdout,
            report.stderr,
        });
    try testing.expect(report.succeeded());
    try testing.expect(std.mem.indexOf(u8, report.stderr, "debconf-reexec=1\n") != null);
}

test "maintainer_script.test.repeated private netns launches do not leak parent fds" {
    try skipUnlessPosixShell();
    try skipUnlessHostFile("/usr/bin/readlink");
    var parent_buffer: [128]u8 = undefined;
    const parent_netns = try currentNetworkNamespace(&parent_buffer);
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\exec /usr/bin/readlink /proc/self/ns/net
        \\
    );
    defer script.deinit(testing.allocator);
    const baseline_fds = try countOpenFds();
    const launches: usize = 200;
    var seen: std.StringHashMap(void) = .init(testing.allocator);
    defer {
        var iterator = seen.keyIterator();
        while (iterator.next()) |key| testing.allocator.free(key.*);
        seen.deinit();
    }
    var reused: usize = 0;
    const started = monotonicMs();
    for (0..launches) |_| {
        var launcher: SystemLauncher = .{};
        var report = try run(
            testing.allocator,
            script.request(&.{"configure"}),
            .{ .launcher = launcher.interface() },
        );
        if (try skipIfPrivateNetworkUnavailable(&report)) {
            report.deinit();
            return;
        }
        try testing.expect(report.succeeded());
        const child_netns = std.mem.trim(u8, report.stdout, &std.ascii.whitespace);
        try testing.expect(!std.mem.eql(u8, parent_netns, child_netns));
        const entry = try seen.getOrPut(child_netns);
        if (entry.found_existing) {
            reused += 1;
        } else {
            entry.key_ptr.* = try testing.allocator.dupe(u8, child_netns);
        }
        report.deinit();
        try testing.expectEqual(baseline_fds, try countOpenFds());
    }
    const elapsed_ms = monotonicMs() - started;
    if (std.c.getenv("DEBZ_SCRIPT_NETNS_BENCH_OUT")) |path| {
        var output = try std.Io.Dir.createFileAbsolute(testing.io, std.mem.span(path), .{
            .truncate = true,
            .permissions = .fromMode(0o644),
        });
        defer output.close(testing.io);
        var buffer: [256]u8 = undefined;
        const line = try std.fmt.bufPrint(&buffer,
            "script-netns launches={d} elapsed_ms={d} per_launch_us={d} unique_netns={d} reused_netns={d} parent_fds={d}\n",
            .{
                launches,
                elapsed_ms,
                (elapsed_ms * 1000) / launches,
                seen.count(),
                reused,
                baseline_fds,
            },
        );
        try output.writeStreamingAll(testing.io, line);
    }
}

test "maintainer_script.test.system launcher issues no sweep under the detach policy" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\exit 0
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.descendants = .detach;

    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqual(@as(u8, 0), report.outcome.exited);
    try testing.expect(!report.terminated_process_group);
    try testing.expect(!report.escalated_to_kill);
    try testing.expect(!report.issued_descendant_sweep);
}

test "maintainer_script.test.system launcher reports a script terminated by a signal" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\kill -9 $$
        \\
    );
    defer script.deinit(testing.allocator);

    var launcher: SystemLauncher = .{};
    var report = try run(
        testing.allocator,
        script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    );
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqual(@as(u32, 9), report.outcome.signaled);
    try testing.expect(report.outcome.spawned());
    try testing.expect(!report.succeeded());
}

test "maintainer_script.test.system launcher terminates the script process tree on timeout" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\sleep 300 &
        \\echo $! >"$1"
        \\sleep 300
        \\
    );
    defer script.deinit(testing.allocator);
    const pid_path = try absoluteTempPath(testing.allocator, &directory, "descendant.pid");
    defer testing.allocator.free(pid_path);

    var request = script.request(&.{pid_path});
    request.policy.limits.timeout_ms = 500;
    request.policy.limits.termination_grace_ms = 200;

    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqualStrings("timed_out", @tagName(report.outcome));
    try testing.expect(report.terminated_process_group);
    try testing.expect(report.issued_descendant_sweep);

    const recorded = try directory.dir.readFileAlloc(
        testing.io,
        "descendant.pid",
        testing.allocator,
        .limited(64),
    );
    defer testing.allocator.free(recorded);
    const descendant = try std.fmt.parseInt(
        i32,
        std.mem.trim(u8, recorded, &std.ascii.whitespace),
        10,
    );
    try expectProcessTerminated(descendant);
}

fn expectProcessTerminated(pid: i32) !void {
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        if (linux.errno(linux.kill(pid, @enumFromInt(0))) == .SRCH) return;
        sleepMs(10);
    }
    return error.TestDescendantSurvived;
}

test "maintainer_script.test.system launcher cancels a running script" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\sleep 300
        \\
    );
    defer script.deinit(testing.allocator);

    var cancellation: CountingCancellation = .{ .cancel_after = 3 };
    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, script.request(&.{"configure"}), .{
        .launcher = launcher.interface(),
        .cancellation = cancellation.interface(),
    });
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqualStrings("cancelled", @tagName(report.outcome));
    try testing.expect(report.terminated_process_group);
    try testing.expect(!report.succeeded());
}

test "maintainer_script.test.system launcher bounds a script that closed its own streams" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    // Redirecting the captured streams closes every pipe the supervisor holds
    // while the script keeps running, so only the deadline can end the run.
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\exec >/dev/null 2>&1
        \\sleep 300
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.limits.timeout_ms = 500;
    request.policy.limits.termination_grace_ms = 200;

    var launcher: SystemLauncher = .{};
    const started = monotonicMs();
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqualStrings("timed_out", @tagName(report.outcome));
    try testing.expect(report.terminated_process_group);
    try testing.expect(!report.succeeded());
    try testing.expect(monotonicMs() - started < 20_000);
}

test "maintainer_script.test.system launcher cancels a script that closed its own streams" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\exec >/dev/null 2>&1
        \\sleep 300
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.limits.termination_grace_ms = 200;

    var cancellation: CountingCancellation = .{ .cancel_after = 3 };
    var launcher: SystemLauncher = .{};
    const started = monotonicMs();
    var report = try run(testing.allocator, request, .{
        .launcher = launcher.interface(),
        .cancellation = cancellation.interface(),
    });
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqualStrings("cancelled", @tagName(report.outcome));
    try testing.expect(report.terminated_process_group);
    try testing.expect(monotonicMs() - started < 20_000);
}

const TraceEvent = enum {
    term_leader,
    term_group,
    kill_leader,
    kill_group,
    reap,
};

/// Deterministic stand-in for the child process group. It records the exact
/// order of signalling and reaping without depending on pid reuse.
const RecordingGroupOperations = struct {
    events: [8]TraceEvent = undefined,
    count: usize = 0,
    probes: usize = 0,
    /// Number of exit probes answered with "still running".
    running_probes: usize = 0,
    clock: u64 = 0,
    status: u32 = 0,
    reaped_at: ?usize = null,
    blocking_reap: ?bool = null,

    fn signal(self: *RecordingGroupOperations, scope: SignalScope, number: TerminationSignal) void {
        self.record(switch (scope) {
            .leader => switch (number) {
                .term => .term_leader,
                .kill => .kill_leader,
            },
            .group => switch (number) {
                .term => .term_group,
                .kill => .kill_group,
            },
        });
    }

    fn exited(self: *RecordingGroupOperations) bool {
        self.probes += 1;
        return self.probes > self.running_probes;
    }

    fn reap(self: *RecordingGroupOperations, known_exited: bool) ?u32 {
        self.blocking_reap = known_exited;
        self.reaped_at = self.count;
        self.record(.reap);
        return self.status;
    }

    fn now(self: *RecordingGroupOperations) u64 {
        return self.clock;
    }

    fn sleep(self: *RecordingGroupOperations, milliseconds: u64) void {
        self.clock += milliseconds;
    }

    fn record(self: *RecordingGroupOperations, event: TraceEvent) void {
        self.events[self.count] = event;
        self.count += 1;
    }

    fn trace(self: *const RecordingGroupOperations) []const TraceEvent {
        return self.events[0..self.count];
    }
};

fn expectTrace(expected: []const TraceEvent, operations: *const RecordingGroupOperations) !void {
    try testing.expectEqualSlices(TraceEvent, expected, operations.trace());
    // The reap must be the last operation: signalling afterwards could reach a
    // recycled pid or process group.
    try testing.expectEqual(operations.count - 1, operations.reaped_at.?);
}

test "maintainer_script.test.finalization never signals a group after reaping it" {
    const plan: Finalization = .{
        .leader_exited = false,
        .sweep = true,
        .grace_ms = 50,
        .poll_ms = 10,
    };

    var exited_cleanly: RecordingGroupOperations = .{ .status = 0 };
    const clean = finalizeGroup(&exited_cleanly, .{
        .leader_exited = true,
        .sweep = true,
        .grace_ms = plan.grace_ms,
        .poll_ms = plan.poll_ms,
    });
    try expectTrace(&.{ .kill_group, .reap }, &exited_cleanly);
    try testing.expect(!clean.terminated);
    try testing.expect(!clean.escalated);
    try testing.expect(clean.issued_sweep);
    try testing.expectEqual(true, exited_cleanly.blocking_reap.?);

    var detached: RecordingGroupOperations = .{ .status = 0 };
    const kept = finalizeGroup(&detached, .{
        .leader_exited = true,
        .sweep = false,
        .grace_ms = plan.grace_ms,
        .poll_ms = plan.poll_ms,
    });
    try expectTrace(&.{.reap}, &detached);
    try testing.expect(!kept.issued_sweep);

    var polite: RecordingGroupOperations = .{ .running_probes = 2 };
    const terminated = finalizeGroup(&polite, plan);
    try expectTrace(&.{ .term_group, .kill_group, .reap }, &polite);
    try testing.expect(terminated.terminated);
    try testing.expect(!terminated.escalated);
    try testing.expect(terminated.issued_sweep);

    var stubborn: RecordingGroupOperations = .{ .running_probes = 1_000 };
    const escalated = finalizeGroup(&stubborn, plan);
    try expectTrace(&.{ .term_group, .kill_group, .kill_group, .reap }, &stubborn);
    try testing.expect(escalated.terminated);
    try testing.expect(escalated.escalated);
    try testing.expectEqual(false, stubborn.blocking_reap.?);

    var detached_running: RecordingGroupOperations = .{ .running_probes = 1_000 };
    _ = finalizeGroup(&detached_running, .{
        .leader_exited = false,
        .sweep = false,
        .grace_ms = plan.grace_ms,
        .poll_ms = plan.poll_ms,
    });
    // The detach policy must never signal descendants.
    try expectTrace(&.{ .term_leader, .kill_leader, .reap }, &detached_running);
}

test "maintainer_script.test.system launcher fails closed when output exceeds the limit" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\count=0
        \\while [ "$count" -lt 512 ]; do
        \\  printf '0123456789012345678901234567890123456789012345678901234567890123\n'
        \\  count=$((count + 1))
        \\done
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.limits.maximum_output_bytes = 64;

    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqualStrings("output_limit_exceeded", @tagName(report.outcome));
    try testing.expectEqual(@as(usize, 64), report.output_bytes);
    try testing.expectEqual(@as(usize, 64), report.output_limit);
    try testing.expect(report.terminated_process_group);
}

/// Runs the script with fd 0, 1, and 2 closed and reports the result through
/// `channel`. It runs in a forked child so the test harness keeps its own
/// standard descriptors, and it never returns to the test runner.
fn reportWithoutStandardStreams(script: *const HostScript, channel: [2]i32) noreturn {
    _ = linux.close(channel[0]);
    for ([_]i32{ 0, 1, 2 }) |fd| _ = linux.close(fd);

    var launcher: SystemLauncher = .{};
    const report = run(
        std.heap.page_allocator,
        script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    ) catch linux.exit(91);

    const code: u8 = switch (report.outcome) {
        .exited => |value| value,
        .setup_failed => |failure| if (failure.stage == .network_namespace and
            failure.errno == @intFromEnum(linux.E.PERM))
            201
        else
            200,
        else => 200,
    };
    writeAllRaw(channel[1], &[_]u8{code});
    writeAllRaw(channel[1], report.stdout);
    writeAllRaw(channel[1], "|");
    writeAllRaw(channel[1], report.stderr);
    _ = linux.close(channel[1]);
    linux.exit(0);
}

fn writeAllRaw(fd: i32, bytes: []const u8) void {
    var written: usize = 0;
    while (written < bytes.len) {
        const rc = linux.write(fd, bytes[written..].ptr, bytes.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => written += rc,
            .INTR => {},
            else => return,
        }
    }
}

test "maintainer_script.test.system launcher installs standard streams the parent had closed" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\printf 'stdin=[%s]\n' "$(cat)"
        \\printf 'diagnostic\n' >&2
        \\exit 7
        \\
    );
    defer script.deinit(testing.allocator);

    const created = createPipe();
    try testing.expectEqual(@as(u32, 0), created.errno);
    var channel = created.fds;
    defer closePipe(&channel);

    const forked = linux.fork();
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(forked));
    const pid: i32 = @intCast(forked);
    if (pid == 0) reportWithoutStandardStreams(&script, channel);
    closeFd(&channel[1]);

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(testing.allocator);
    var buffer: [512]u8 = undefined;
    while (true) {
        const rc = linux.read(channel[0], &buffer, buffer.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => break,
        }
        if (rc == 0) break;
        try payload.appendSlice(testing.allocator, buffer[0..rc]);
    }
    const status = (try reapChild(pid, false)).?;
    try testing.expect(linux.W.IFEXITED(status));
    try testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
    if (payload.items.len >= 1 and payload.items[0] == 201) {
        if (requirePrivateNetworkNamespace())
            return error.NativeHelperNamespaceRequired;
        return;
    }

    // The script still saw an empty /dev/null stdin and both captured streams,
    // so the runner's pipes were installed on 0, 1, and 2 with CLOEXEC cleared.
    try testing.expect(payload.items.len > 1);
    try testing.expectEqual(@as(u8, 7), payload.items[0]);
    try testing.expectEqualStrings("stdin=[]\n|diagnostic\n", payload.items[1..]);
}

test "maintainer_script.test.system launcher combines interleaved output when requested" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\printf 'out\n'
        \\printf 'err\n' >&2
        \\
    );
    defer script.deinit(testing.allocator);

    var request = script.request(&.{"configure"});
    request.policy.capture = .combined;

    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqual(@as(u8, 0), report.outcome.exited);
    try testing.expect(report.succeeded());
    try testing.expectEqualStrings("", report.stdout);
    try testing.expectEqualStrings("", report.stderr);
    try testing.expectEqualStrings("out\nerr\n", report.combined);
    try testing.expectEqualSlices(
        u8,
        &hashBytes("out\nerr\n"),
        &report.evidence.combined_sha256,
    );
}

test "maintainer_script.test.system launcher enters the alternate root before executing" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    const script_path = "var/lib/dpkg/info/demo.postinst";
    try writeExecutableScript(&directory, script_path,
        \\#!/bin/sh
        \\exit 0
        \\
    );
    const root = try absoluteTempPath(testing.allocator, &directory, "");
    defer testing.allocator.free(root);
    const trimmed_root = std.mem.trimEnd(u8, root, "/");

    var launcher: SystemLauncher = .{};
    const identity: Identity = .{
        .package = "demo",
        .version = "1.0-1",
        .architecture = "amd64",
        .kind = .postinst,
        .script_path = script_path,
        .script_sha256 = @splat(0),
    };
    var report = try run(testing.allocator, .{
        .root = trimmed_root,
        .identity = identity,
        .arguments = &.{"configure"},
        .policy = .{ .limits = .{ .timeout_ms = 20_000, .termination_grace_ms = 500 } },
    }, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;

    try testing.expectEqual(Isolation.chroot, report.isolation);
    try testing.expect(report.outcome.spawned());
    switch (report.outcome) {
        // Unprivileged CI cannot enter an alternate root; the denial is exact.
        .setup_failed => |failure| switch (failure.stage) {
            .root_isolation => try testing.expectEqual(
                @intFromEnum(linux.E.PERM),
                failure.errno,
            ),
            // A privileged run does enter the root, where the fixture has no
            // interpreter. Reaching this proves the chroot took effect.
            .execute => try testing.expectEqual(
                @intFromEnum(linux.E.NOENT),
                failure.errno,
            ),
            else => return error.TestUnexpectedResult,
        },
        // A privileged root that does contain an interpreter runs the script.
        .exited => |code| try testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }

    // Positive control: the identical script is executable through the host
    // root, so the alternate-root outcome above is isolation, not a bad fixture.
    var host_script: HostScript = .{
        .absolute = try absoluteTempPath(testing.allocator, &directory, script_path),
        .directories = undefined,
    };
    defer host_script.deinit(testing.allocator);
    host_script.directories = .{std.fs.path.dirname(host_script.absolute[1..]).?};
    var host_report = try run(
        testing.allocator,
        host_script.request(&.{"configure"}),
        .{ .launcher = launcher.interface() },
    );
    defer host_report.deinit();
    try testing.expectEqual(Isolation.host_root, host_report.isolation);
    try testing.expectEqual(@as(u8, 0), host_report.outcome.exited);
}

test "maintainer_script.test.helper binding rejects changed source and target" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    try writeExecutableScript(&directory, "source", "native-helper");
    try writeExecutableScript(&directory, "target", "original-helper");
    const root = root_fs.Root.init(testing.io, directory.dir);
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("native-helper", &sha256, .{});
    try testing.expectError(
        error.HelperDigestMismatch,
        HelperMount.init(testing.allocator, root, "source", "target", @splat(0)),
    );
    var mount = try HelperMount.init(testing.allocator, root, "source", "target", sha256);
    defer mount.deinit();
    try mount.verify(testing.allocator);
    try writeExecutableScript(&directory, "target", "externally-changed-target");
    try testing.expectError(error.PathChanged, mount.verify(testing.allocator));
}

test "maintainer_script.test.helper binding rehashes the pinned source at every verify" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    try writeExecutableScript(&directory, "source", "native-helper");
    try writeExecutableScript(&directory, "target", "original-helper");
    const root = root_fs.Root.init(testing.io, directory.dir);
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("native-helper", &sha256, .{});
    const before = helperDigestCount();
    var mount = try HelperMount.init(testing.allocator, root, "source", "target", sha256);
    defer mount.deinit();
    try mount.verify(testing.allocator);
    try mount.verify(testing.allocator);
    try testing.expectEqual(before + 3, helperDigestCount());
    // Same-size bytes written through the pinned inode are refused by the
    // identity check or, within one timestamp tick, by the digest.
    try writeExecutableScript(&directory, "source", "native-HELPER");
    if (mount.verify(testing.allocator)) |_|
        return error.TestUnexpectedResult
    else |err| switch (err) {
        error.PathChanged, error.HelperDigestMismatch => {},
        else => return err,
    }
}

test "maintainer_script.test.helper identity is bound without changing the environment" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    try writeExecutableScript(&directory, "source", "native-helper");
    try writeExecutableScript(&directory, "target", "original-helper");
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("native-helper", &sha256, .{});
    var mount = try HelperMount.init(
        testing.allocator,
        root_fs.Root.init(testing.io, directory.dir),
        "source",
        "target",
        sha256,
    );
    defer mount.deinit();
    var recorder: RecordingLauncher = .{};
    var request = testRequest();
    request.root = mount.root_path;
    var original = try run(testing.allocator, request, .{ .launcher = recorder.interface() });
    defer original.deinit();
    request.helper_mount = &mount;
    var bound = try run(testing.allocator, request, .{ .launcher = recorder.interface() });
    defer bound.deinit();
    try testing.expect(!std.mem.eql(u8, &original.evidence.invocation_sha256, &bound.evidence.invocation_sha256));
    try testing.expectEqualSlices(u8, &original.evidence.environment_sha256, &bound.evidence.environment_sha256);
    try testing.expectEqualStrings("source", bound.helper.?.source_path);
    try testing.expectEqualSlices(u8, &sha256, &bound.helper.?.sha256);
    request.root = "/different-root";
    try testing.expectEqual(RejectionReason.invalid_root, validate(request).?);
}

test "maintainer_script.test.private helper namespace preserves target bytes" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    const native_body = "#!/bin/sh\nprintf 'native-helper\\n'\n";
    const original_body = "#!/bin/sh\nprintf 'original-helper\\n'\n";
    try writeExecutableScript(&directory, "helper", native_body);
    try writeExecutableScript(&directory, "bin/dpkg-trigger", original_body);
    const source = try absoluteTempPath(testing.allocator, &directory, "helper");
    defer testing.allocator.free(source);
    const target = try absoluteTempPath(testing.allocator, &directory, "bin/dpkg-trigger");
    defer testing.allocator.free(target);
    var host = try root_fs.openAbsoluteRoot(testing.io, "/");
    defer host.close();
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(native_body, &sha256, .{});
    var mount = try HelperMount.init(testing.allocator, host.root, source[1..], target[1..], sha256);
    defer mount.deinit();
    var probe = try SystemLauncher.probeHelper(testing.allocator, &mount, Cancellation.never());
    defer probe.deinit(testing.allocator);
    switch (probe.outcome) {
        .exited => |code| try testing.expectEqual(@as(u8, 0), code),
        .setup_failed => |failure| switch (failure.stage) {
            .network_namespace, .root_isolation => {
                try testing.expectEqual(@intFromEnum(linux.E.PERM), failure.errno);
                if (requirePrivateNetworkNamespace())
                    return error.NativeHelperNamespaceRequired;
                try mount.verify(testing.allocator);
                return;
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    var script = try HostScript.init(testing.allocator, &directory, "demo.postinst",
        \\#!/bin/sh
        \\"$2" || exit 81
        \\PATH="${2%/*}:$PATH"
        \\export PATH
        \\dpkg-trigger || exit 82
        \\if (printf 'changed\n' > "$2") 2>/dev/null; then exit 83; fi
        \\if "$3" 2>/dev/null; then exit 84; fi
        \\cat "$3" || exit 85
        \\
    );
    defer script.deinit(testing.allocator);
    var request = script.request(&.{ "configure", target, source });
    request.helper_mount = &mount;
    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (try skipIfPrivateNetworkUnavailable(&report)) return;
    try testing.expect(report.succeeded());
    try testing.expectEqualStrings(
        "native-helper\nnative-helper\n" ++ original_body,
        report.stdout,
    );
    try mount.verify(testing.allocator);
    const actual = try mount.target.observeAlloc(testing.allocator, 1024);
    defer testing.allocator.free(actual.bytes);
    try testing.expectEqualStrings(original_body, actual.bytes);
}

test "maintainer_script.test.helper namespace retains alternate-root isolation" {
    try skipUnlessPosixShell();
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    const helper_body = "#!/bin/sh\nexit 0\n";
    try writeExecutableScript(&directory, "var/lib/debz/helper", helper_body);
    try writeExecutableScript(&directory, "usr/bin/dpkg-trigger", "original");
    try writeExecutableScript(&directory, "var/lib/dpkg/info/demo.postinst", helper_body);
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(helper_body, &sha256, .{});
    var mount = try HelperMount.init(
        testing.allocator,
        root_fs.Root.init(testing.io, directory.dir),
        "var/lib/debz/helper",
        "usr/bin/dpkg-trigger",
        sha256,
    );
    defer mount.deinit();
    var request = testRequest();
    request.root = mount.root_path;
    request.helper_mount = &mount;
    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    switch (report.outcome) {
        .setup_failed => |failure| switch (failure.stage) {
            .network_namespace => {
                try testing.expectEqual(@intFromEnum(linux.E.PERM), failure.errno);
                if (requirePrivateNetworkNamespace())
                    return error.NativeHelperNamespaceRequired;
            },
            .root_isolation => {
                try testing.expectEqual(@intFromEnum(linux.E.PERM), failure.errno);
                if (requirePrivateNetworkNamespace())
                    return error.NativeHelperNamespaceRequired;
            },
            .execute => try testing.expectEqual(@intFromEnum(linux.E.NOENT), failure.errno),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try mount.verify(testing.allocator);
}

test "maintainer_script.test.snapshot systemd proc is bound to the exact signed invocation" {
    const hex = std.fmt.bytesToHex(snapshot_systemd_sha256, .lower);
    try testing.expectEqualStrings(
        "d9df6a03ccb6b557c16ac1c674557a66c1db290f3c6d3cadbef335e0ce74e31d",
        &hex,
    );
    try testing.expectEqual(@as(u64, 5037), snapshot_systemd_postinst_size);
    var binding: SnapshotSystemdProc = .{
        .allocator = testing.allocator,
        .root_path = @constCast("/srv/roots/target"),
        .directory = undefined,
        .script = undefined,
        .boot_id = @splat(0),
        .root_stat = undefined,
        .directory_stat = undefined,
    };
    var request = testRequest();
    request.identity = .{
        .package = "systemd",
        .version = "259.5-0ubuntu3.4",
        .architecture = "amd64",
        .kind = .postinst,
        .script_path = "var/lib/dpkg/info/systemd.postinst",
        .script_sha256 = snapshot_systemd_sha256,
    };
    request.arguments = &.{ "configure", "" };
    request.policy.snapshot_systemd_proc = true;
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.snapshot_proc = .{ .systemd = &binding };
    try testing.expect(validate(request) == null);
    var launcher: RecordingLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    try testing.expect(report.succeeded());
    try testing.expect(launcher.invocation.?.snapshot_proc != null);

    request.arguments = &.{ "triggered", "/usr/lib/sysctl.d" };
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.arguments = &.{ "configure", "" };
    request.identity.script_sha256 = @splat(0);
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.script_sha256 = snapshot_systemd_sha256;
    request.identity.package = "other";
    request.identity.script_path = "var/lib/dpkg/info/other.postinst";
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.package = "systemd";
    request.identity.script_path = "var/lib/dpkg/info/systemd.postinst";
    request.identity.version = "259.5-0ubuntu3.5";
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.version = "259.5-0ubuntu3.4";
    request.identity.architecture = "arm64";
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.architecture = "amd64";
    request.policy.descendants = .detach;
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.policy.descendants = .terminate;
    request.root = "/";
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.root = "/srv/roots/target";
    request.snapshot_proc = null;
    request.identity.package = "demo";
    request.identity.script_path = "var/lib/dpkg/info/demo.postinst";
    try testing.expect(validate(request) == null);
    try testing.expect(!std.mem.eql(u8, &policyDigest(.{}), &policyDigest(request.policy)));
    _ = &binding;
}

fn testSnapshotProcFailure(status_fd: i32, stage: u8, err: linux.E) noreturn {
    const failure = [_]u8{ 0, stage, @intCast(@intFromEnum(err)) };
    _ = linux.write(status_fd, &failure, failure.len);
    linux.exit(2);
}

test "maintainer_script.test.capability header matches the kernel ABI" {
    if (builtin.os.tag != .linux) return;
    try testing.expectEqual(@as(usize, 8), @sizeOf(KernelCapabilityHeader));
    try testing.expectEqual(@as(usize, 4), @offsetOf(KernelCapabilityHeader, "pid"));
    try testing.expectEqual(@as(usize, 12), @sizeOf(linux.cap_user_data_t));
    var header: KernelCapabilityHeader = .{ .version = 0x20080522, .pid = 0 };
    var data: [2]linux.cap_user_data_t = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.syscall2(
        .capget,
        @intFromPtr(&header),
        @intFromPtr(&data[0]),
    )));
}

test "maintainer_script.test.udev PID-only proc rejects unrelated and altered invocations" {
    const hex = std.fmt.bytesToHex(snapshot_udev_sha256, .lower);
    try testing.expectEqualStrings(
        "b7892e975bcce896c4938c2219a244fa03863d5eff37cd2eb66d2b8540f14606",
        &hex,
    );
    try testing.expectEqual(@as(u64, 2578), snapshot_udev_postinst_size);
    var binding: SnapshotUdevProc = .{
        .allocator = testing.allocator,
        .root = undefined,
        .root_path = @constCast("/srv/roots/target"),
        .directory = undefined,
        .script = undefined,
        .bin = undefined,
        .shell = undefined,
        .inputs = undefined,
        .root_stat = undefined,
        .directory_stat = undefined,
    };
    var request = testRequest();
    request.identity = .{
        .package = "udev",
        .version = "259.5-0ubuntu3.4",
        .architecture = "amd64",
        .kind = .postinst,
        .script_path = "var/lib/dpkg/info/udev.postinst",
        .script_sha256 = snapshot_udev_sha256,
    };
    request.arguments = &.{ "configure", "" };
    request.policy.snapshot_udev_proc = true;
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.snapshot_proc = .{ .udev = &binding };
    try testing.expect(validate(request) == null);
    var launcher: RecordingLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    try testing.expect(report.succeeded());
    try testing.expectEqual(SnapshotProcMode.udev, std.meta.activeTag(launcher.invocation.?.snapshot_proc.?));
    try testing.expect(!std.mem.eql(
        u8,
        &policyDigest(.{ .snapshot_systemd_proc = true }),
        &policyDigest(request.policy),
    ));

    request.arguments = &.{ "triggered", "/dev" };
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.arguments = &.{ "configure", "" };
    request.identity.script_sha256 = @splat(0);
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.script_sha256 = snapshot_udev_sha256;
    request.identity.script_path = "var/lib/debz-lifecycle-scripts/udev.postinst";
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.script_path = "var/lib/dpkg/info/udev.postinst";
    request.identity.package = "other";
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.package = "udev";
    request.identity.version = "259.5-0ubuntu3.5";
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.version = "259.5-0ubuntu3.4";
    request.identity.architecture = "arm64";
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.architecture = "amd64";
    request.identity.kind = .preinst;
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.identity.kind = .postinst;
    request.policy.descendants = .detach;
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.policy.descendants = .terminate;
    request.root = "/";
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.root = "/srv/roots/target";
    request.snapshot_proc = null;
    request.identity.package = "demo";
    request.identity.script_path = "var/lib/dpkg/info/demo.postinst";
    try testing.expect(validate(request) == null);
    request.snapshot_proc = .{ .udev = &binding };
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    _ = &binding;
}

test "maintainer_script.test.udev PID-only proc rejects occupied mountpoint" {
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDir(testing.io, "proc", .default_dir);
    try writeExecutableScript(&directory, "proc/occupied", "not empty");
    try testing.expectError(
        error.DirectoryTooLarge,
        SnapshotUdevProc.init(
            testing.allocator,
            root_fs.Root.init(testing.io, directory.dir),
        ),
    );
}

test "maintainer_script.test.sudo PID-only proc requires exact signed identity" {
    const hex = std.fmt.bytesToHex(snapshot_sudo_sha256, .lower);
    try testing.expectEqualStrings(
        "fd4c65932ab3ab7ce90c3633c42b8ee7a36af2c8292142d6e0cd134dda4c6383",
        &hex,
    );
    try testing.expectEqual(@as(u64, 1747), snapshot_sudo_postinst_size);
    var binding: SnapshotSudoProc = .{
        .allocator = testing.allocator,
        .root = undefined,
        .root_path = @constCast("/srv/roots/target"),
        .directory = undefined,
        .script = undefined,
        .aliases = undefined,
        .inputs = undefined,
        .root_stat = undefined,
        .directory_stat = undefined,
    };
    var request = testRequest();
    request.identity = .{
        .package = "sudo",
        .version = "1.9.17p2-1ubuntu3.1",
        .architecture = "amd64",
        .kind = .postinst,
        .script_path = "var/lib/dpkg/info/sudo.postinst",
        .script_sha256 = snapshot_sudo_sha256,
    };
    request.arguments = &.{ "configure", "" };
    request.policy.snapshot_sudo_proc = true;
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.snapshot_proc = .{ .sudo = &binding };
    try testing.expect(validate(request) == null);
    var launcher: RecordingLauncher = .{};
    var report = try run(testing.allocator, request, .{ .launcher = launcher.interface() });
    defer report.deinit();
    try testing.expect(report.succeeded());
    try testing.expectEqual(SnapshotProcMode.sudo, std.meta.activeTag(launcher.invocation.?.snapshot_proc.?));
    try testing.expect(!std.mem.eql(
        u8,
        &policyDigest(.{ .snapshot_udev_proc = true }),
        &policyDigest(request.policy),
    ));
    for ([_]struct {
        package: []const u8 = "sudo",
        version: []const u8 = "1.9.17p2-1ubuntu3.1",
        architecture: []const u8 = "amd64",
        kind: Kind = .postinst,
        path: []const u8 = "var/lib/dpkg/info/sudo.postinst",
        digest: [32]u8 = snapshot_sudo_sha256,
        arguments: []const []const u8 = &.{ "configure", "" },
    }{
        .{ .package = "sudo-rs" },
        .{ .version = "1.9.17p2-1ubuntu3.2" },
        .{ .architecture = "arm64" },
        .{ .kind = .preinst },
        .{ .path = "var/lib/debz-lifecycle-scripts/sudo.postinst" },
        .{ .digest = @splat(0) },
        .{ .arguments = &.{ "configure", "old-version" } },
        .{ .arguments = &.{ "triggered", "/proc/sys" } },
    }) |case| {
        request.identity.package = case.package;
        request.identity.version = case.version;
        request.identity.architecture = case.architecture;
        request.identity.kind = case.kind;
        request.identity.script_path = case.path;
        request.identity.script_sha256 = case.digest;
        request.arguments = case.arguments;
        try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    }
    request.snapshot_proc = null;
    request.identity.package = "demo";
    request.identity.script_path = "var/lib/dpkg/info/demo.postinst";
    request.identity.script_sha256 = snapshot_sudo_sha256;
    request.arguments = &.{ "configure", "" };
    try testing.expect(validate(request) == null);
    request.snapshot_proc = .{ .sudo = &binding };
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    request.snapshot_proc = .{ .udev = undefined };
    try testing.expectEqual(RejectionReason.invalid_snapshot_proc, validate(request).?);
    _ = &binding;
}

test "maintainer_script.test.sudo PID-only proc rejects occupied mountpoint" {
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDir(testing.io, "proc", .default_dir);
    try writeExecutableScript(&directory, "proc/occupied", "not empty");
    try testing.expectError(
        error.DirectoryTooLarge,
        SnapshotSudoProc.init(
            testing.allocator,
            root_fs.Root.init(testing.io, directory.dir),
        ),
    );
}

test "maintainer_script.test.private PID1 mounts masked read-only boot ID and tears down" {
    if (builtin.os.tag != .linux) return;
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDir(testing.io, "proc", .default_dir);
    const path = try absoluteTempPath(testing.allocator, &directory, "");
    defer testing.allocator.free(path);
    const root_path = try testing.allocator.dupeZ(u8, std.mem.trimEnd(u8, path, "/"));
    defer testing.allocator.free(root_path);
    const root = root_fs.Root.init(testing.io, directory.dir);
    var mountpoint = try root.pinDirectory(try root_fs.Path.init("proc"));
    defer mountpoint.close();
    var root_stat: linux.Statx = undefined;
    var directory_stat: linux.Statx = undefined;
    try testing.expectEqual(linux.E.SUCCESS, helperStat(directory.dir.handle, &root_stat));
    try testing.expectEqual(linux.E.SUCCESS, helperStat(mountpoint.dir.handle, &directory_stat));
    const boot_id = readKernelBootId() catch {
        if (std.c.getenv("DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE") != null)
            return error.NativeHelperNamespaceRequired;
        return;
    };
    var status: [2]i32 = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&status, .{ .CLOEXEC = true })));
    const forked = linux.clone2(
        linux.CLONE.NEWNET | linux.CLONE.NEWNS | linux.CLONE.NEWPID | @intFromEnum(linux.SIG.CHLD),
        0,
    );
    if (linux.errno(forked) != .SUCCESS) {
        _ = linux.close(status[0]);
        _ = linux.close(status[1]);
        if (linux.errno(forked) == .PERM and
            std.c.getenv("DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE") == null)
            return;
        return error.NativeHelperNamespaceRequired;
    }
    if (forked == 0) {
        _ = linux.close(status[0]);
        if (linux.getpid() != 1) testSnapshotProcFailure(status[1], 1, .CHILD);
        const death = linux.errno(linux.prctl(
            @intFromEnum(linux.PR.SET_PDEATHSIG),
            @intFromEnum(linux.SIG.KILL),
            0,
            0,
            0,
        ));
        if (death != .SUCCESS) testSnapshotProcFailure(status[1], 2, death);
        const network_ready = setupPrivateLoopback();
        if (network_ready != .SUCCESS) testSnapshotProcFailure(status[1], 18, network_ready);
        const private = linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0));
        if (private != .SUCCESS) testSnapshotProcFailure(status[1], 3, private);
        const entered = linux.errno(linux.chdir(root_path.ptr));
        if (entered != .SUCCESS) testSnapshotProcFailure(status[1], 4, entered);
        const chrooted = linux.errno(linux.chroot("."));
        if (chrooted != .SUCCESS) testSnapshotProcFailure(status[1], 5, chrooted);
        const at_root = linux.errno(linux.chdir("/"));
        if (at_root != .SUCCESS) testSnapshotProcFailure(status[1], 6, at_root);
        var setup_stage: u8 = 0;
        const setup = setupSnapshotProc(.{
            .root_stat = root_stat,
            .directory_stat = directory_stat,
            .view = .{ .systemd = boot_id },
        }, &setup_stage);
        if (setup != .SUCCESS) testSnapshotProcFailure(status[1], 20 + setup_stage, setup);
        const present = linux.open(
            "/proc/sys/kernel/random/boot_id",
            .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
            0,
        );
        if (linux.errno(present) != .SUCCESS)
            testSnapshotProcFailure(status[1], 8, linux.errno(present));
        _ = linux.close(@intCast(present));
        const hidden = linux.open(
            "/proc/sys/kernel/random/uuid",
            .{ .PATH = true, .CLOEXEC = true },
            0,
        );
        if (linux.errno(hidden) == .SUCCESS) {
            _ = linux.close(@intCast(hidden));
            testSnapshotProcFailure(status[1], 9, .EXIST);
        }
        if (linux.errno(hidden) != .NOENT)
            testSnapshotProcFailure(status[1], 9, linux.errno(hidden));
        const visible = linux.open(
            "/proc/1/root",
            .{ .PATH = true, .CLOEXEC = true },
            0,
        );
        if (linux.errno(visible) != .SUCCESS)
            testSnapshotProcFailure(status[1], 10, linux.errno(visible));
        var observed: linux.Statx = undefined;
        const verified = helperStat(@intCast(visible), &observed);
        if (verified != .SUCCESS) testSnapshotProcFailure(status[1], 11, verified);
        if (observed.ino != root_stat.ino or
            observed.dev_major != root_stat.dev_major or
            observed.dev_minor != root_stat.dev_minor)
            testSnapshotProcFailure(status[1], 11, .STALE);
        _ = linux.close(@intCast(visible));
        const result = [_]u8{ 1, 0, 0 };
        _ = linux.write(status[1], &result, result.len);
        linux.exit(0);
    }
    _ = linux.close(status[1]);
    var result: [3]u8 = .{ 0, 0, 0 };
    const received = linux.read(status[0], &result, result.len);
    _ = linux.close(status[0]);
    var waited: u32 = 0;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.waitpid(@intCast(forked), &waited, 0)));
    if (received != result.len or result[0] != 1)
        std.debug.print("snapshot proc PID1 stage={d} errno={d} bytes={d}\n", .{ result[1], result[2], received });
    try testing.expectEqual(@as(usize, result.len), received);
    try testing.expectEqual(@as(u8, 1), result[0]);
    try testing.expect(linux.W.IFEXITED(waited));
    try testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(waited));
    try testing.expect((try root.entryIfExists(try root_fs.Path.init("proc/sys"))) == null);
}

test "maintainer_script.test.private PID1 udev proc hides all sysctl and tears down" {
    if (builtin.os.tag != .linux) return;
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDir(testing.io, "proc", .default_dir);
    const path = try absoluteTempPath(testing.allocator, &directory, "");
    defer testing.allocator.free(path);
    const root_path = try testing.allocator.dupeZ(u8, std.mem.trimEnd(u8, path, "/"));
    defer testing.allocator.free(root_path);
    const root = root_fs.Root.init(testing.io, directory.dir);
    var mountpoint = try root.pinDirectory(try root_fs.Path.init("proc"));
    defer mountpoint.close();
    var descriptor: ProcDescriptor = .{
        .root_stat = undefined,
        .directory_stat = undefined,
        .view = .udev,
    };
    try testing.expectEqual(linux.E.SUCCESS, helperStat(directory.dir.handle, &descriptor.root_stat));
    try testing.expectEqual(linux.E.SUCCESS, helperStat(mountpoint.dir.handle, &descriptor.directory_stat));
    var status: [2]i32 = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&status, .{ .CLOEXEC = true })));
    const forked = linux.clone2(
        linux.CLONE.NEWNET | linux.CLONE.NEWNS | linux.CLONE.NEWPID | @intFromEnum(linux.SIG.CHLD),
        0,
    );
    if (linux.errno(forked) != .SUCCESS) {
        _ = linux.close(status[0]);
        _ = linux.close(status[1]);
        if (linux.errno(forked) == .PERM and
            std.c.getenv("DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE") == null)
            return;
        return error.NativeHelperNamespaceRequired;
    }
    if (forked == 0) {
        _ = linux.close(status[0]);
        var result: [1]u8 = .{1};
        if (linux.getpid() == 1 and
            linux.errno(linux.prctl(
                @intFromEnum(linux.PR.SET_PDEATHSIG),
                @intFromEnum(linux.SIG.KILL),
                0,
                0,
                0,
            )) == .SUCCESS and
            setupPrivateLoopback() == .SUCCESS and
            linux.errno(linux.mount(
                null,
                "/",
                null,
                linux.MS.REC | linux.MS.PRIVATE,
                0,
            )) == .SUCCESS and
            linux.errno(linux.chdir(root_path.ptr)) == .SUCCESS and
            linux.errno(linux.chroot(".")) == .SUCCESS and
            linux.errno(linux.chdir("/")) == .SUCCESS and
            setupSnapshotProc(descriptor, null) == .SUCCESS)
        {
            const sysctl = linux.open(
                "/proc/sys",
                .{ .PATH = true, .CLOEXEC = true },
                0,
            );
            const boot_id = linux.open(
                "/proc/sys/kernel/random/boot_id",
                .{ .PATH = true, .CLOEXEC = true },
                0,
            );
            const visible = linux.open(
                "/proc/1/root",
                .{ .PATH = true, .CLOEXEC = true },
                0,
            );
            if (linux.errno(visible) == .SUCCESS) {
                var observed: linux.Statx = undefined;
                if (helperStat(@intCast(visible), &observed) == .SUCCESS and
                    observed.ino == descriptor.root_stat.ino and
                    observed.dev_major == descriptor.root_stat.dev_major and
                    observed.dev_minor == descriptor.root_stat.dev_minor and
                    linux.errno(sysctl) == .NOENT and
                    linux.errno(boot_id) == .NOENT and
                    linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.SYS_ADMIN, 0, 0, 0) == 0 and
                    linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) == 1 and
                    linux.errno(linux.mount(
                        null,
                        "/proc",
                        null,
                        linux.MS.REMOUNT | proc_mount_flags,
                        0,
                    )) == .PERM)
                    result[0] = 0;
                _ = linux.close(@intCast(visible));
            }
            if (linux.errno(sysctl) == .SUCCESS) _ = linux.close(@intCast(sysctl));
            if (linux.errno(boot_id) == .SUCCESS) _ = linux.close(@intCast(boot_id));
        }
        _ = linux.write(status[1], &result, 1);
        linux.exit(result[0]);
    }
    _ = linux.close(status[1]);
    var result: [1]u8 = undefined;
    const received = linux.read(status[0], &result, 1);
    _ = linux.close(status[0]);
    var waited: u32 = 0;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.waitpid(@intCast(forked), &waited, 0)));
    try testing.expectEqual(@as(usize, 1), received);
    try testing.expectEqual(@as(u8, 0), result[0]);
    try testing.expect(linux.W.IFEXITED(waited));
    try testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(waited));
    try testing.expect((try root.entryIfExists(try root_fs.Path.init("proc/sys"))) == null);
}

test "maintainer_script.test.exec boundary seals inherited host-root descriptors" {
    if (builtin.os.tag != .linux) return;
    var status: [2]i32 = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&status, .{ .CLOEXEC = true })));
    const forked = linux.fork();
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(forked));
    if (forked == 0) {
        _ = linux.close(status[0]);
        const opened = linux.open("/", .{ .PATH = true }, 0);
        var result: [1]u8 = .{1};
        if (linux.errno(opened) == .SUCCESS) {
            const fd: i32 = @intCast(opened);
            const before = linux.fcntl(fd, linux.F.GETFD, 0);
            const sealed = sealInheritedDescriptors();
            const after = linux.fcntl(fd, linux.F.GETFD, 0);
            if (fd > 2 and linux.errno(before) == .SUCCESS and before == 0 and
                sealed == .SUCCESS and linux.errno(after) == .SUCCESS and after == 1)
                result[0] = 0;
            _ = linux.close(fd);
        }
        _ = linux.write(status[1], &result, 1);
        linux.exit(result[0]);
    }
    _ = linux.close(status[1]);
    var result: [1]u8 = undefined;
    const received = linux.read(status[0], &result, 1);
    _ = linux.close(status[0]);
    var waited: u32 = 0;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.waitpid(@intCast(forked), &waited, 0)));
    try testing.expectEqual(@as(usize, 1), received);
    try testing.expectEqual(@as(u8, 0), result[0]);
    try testing.expect(linux.W.IFEXITED(waited));
    try testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(waited));
}

test "maintainer_script.test.signed systemd postinst uses scoped masked proc" {
    if (builtin.os.tag != .linux) return;
    const configured = std.c.getenv("DEBZ_REQUIRE_SIGNED_SYSTEMD_PROC_ROOT") orelse return;
    const root_path = std.mem.span(configured);
    var root = try root_fs.openAbsoluteRoot(testing.io, root_path);
    defer root.close();
    var proc = try SnapshotSystemdProc.init(testing.allocator, root.root);
    defer proc.deinit();
    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, .{
        .root = root_path,
        .identity = .{
            .package = "systemd",
            .version = "259.5-0ubuntu3.4",
            .architecture = "amd64",
            .kind = .postinst,
            .script_path = "var/lib/dpkg/info/systemd.postinst",
            .script_sha256 = snapshot_systemd_sha256,
        },
        .arguments = &.{ "configure", "" },
        .policy = .{ .snapshot_systemd_proc = true },
        .snapshot_proc = .{ .systemd = &proc },
    }, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (!report.succeeded())
        std.debug.print("signed systemd proc outcome={any} stderr={s}\n", .{
            report.outcome,
            report.stderr,
        });
    try testing.expect(report.succeeded());
    try testing.expectEqual(@as(u8, 0), report.outcome.exited);
    try testing.expect((try root.root.entryIfExists(
        try root_fs.Path.init("proc/sys"),
    )) == null);
    try proc.verify(testing.allocator);
}

test "maintainer_script.test.signed udev postinst uses only PID proc and applies static permissions" {
    if (builtin.os.tag != .linux) return;
    const configured = std.c.getenv("DEBZ_REQUIRE_SIGNED_UDEV_PROC_ROOT") orelse return;
    const root_path = std.mem.span(configured);
    var root = try root_fs.openAbsoluteRoot(testing.io, root_path);
    defer root.close();
    var proc = try SnapshotUdevProc.init(testing.allocator, root.root);
    defer proc.deinit();
    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, .{
        .root = root_path,
        .identity = .{
            .package = "udev",
            .version = "259.5-0ubuntu3.4",
            .architecture = "amd64",
            .kind = .postinst,
            .script_path = "var/lib/dpkg/info/udev.postinst",
            .script_sha256 = snapshot_udev_sha256,
        },
        .arguments = &.{ "configure", "" },
        .policy = .{ .snapshot_udev_proc = true },
        .snapshot_proc = .{ .udev = &proc },
    }, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (!report.succeeded())
        std.debug.print("signed udev proc outcome={any} stderr={s}\n", .{
            report.outcome,
            report.stderr,
        });
    try testing.expect(report.succeeded());
    try testing.expectEqual(@as(u8, 0), report.outcome.exited);
    try testing.expect((try root.root.entryIfExists(
        try root_fs.Path.init("proc/sys"),
    )) == null);
    const kvm = try root.root.entry(try root_fs.Path.init("dev/kvm"));
    try testing.expectEqual(@as(u16, 0o660), kvm.mode);
    try testing.expectEqual(@as(u32, 992), kvm.gid);
    const fuse = try root.root.entry(try root_fs.Path.init("dev/fuse"));
    try testing.expectEqual(@as(u16, 0o666), fuse.mode);
    try testing.expectEqual(@as(u32, 0), fuse.uid);
    try proc.verify(testing.allocator);
}

test "maintainer_script.test.signed sudo postinst repairs only pinned alternatives with PID-only proc" {
    if (builtin.os.tag != .linux) return;
    const configured = std.c.getenv("DEBZ_REQUIRE_SIGNED_SUDO_PROC_ROOT") orelse return;
    const root_path = std.mem.span(configured);
    var root = try root_fs.openAbsoluteRoot(testing.io, root_path);
    defer root.close();
    var proc = try SnapshotSudoProc.init(testing.allocator, root.root);
    defer proc.deinit();
    var launcher: SystemLauncher = .{};
    var report = try run(testing.allocator, .{
        .root = root_path,
        .identity = .{
            .package = "sudo",
            .version = "1.9.17p2-1ubuntu3.1",
            .architecture = "amd64",
            .kind = .postinst,
            .script_path = "var/lib/dpkg/info/sudo.postinst",
            .script_sha256 = snapshot_sudo_sha256,
        },
        .arguments = &.{ "configure", "" },
        .policy = .{ .snapshot_sudo_proc = true },
        .snapshot_proc = .{ .sudo = &proc },
    }, .{ .launcher = launcher.interface() });
    defer report.deinit();
    if (!report.succeeded())
        std.debug.print("signed sudo proc outcome={any} stderr={s}\n", .{
            report.outcome,
            report.stderr,
        });
    try testing.expect(report.succeeded());
    try testing.expectEqual(@as(u8, 0), report.outcome.exited);
    try testing.expect((try root.root.entryIfExists(
        try root_fs.Path.init("proc/sys"),
    )) == null);
    const record = try root.root.readFileAlloc(
        testing.allocator,
        try root_fs.Path.init("var/lib/dpkg/alternatives/sudo"),
        1024,
    );
    defer testing.allocator.free(record);
    const record_hex = std.fmt.bytesToHex(hashBytes(record), .lower);
    try testing.expectEqualStrings(
        "c583a377d2d7bc241422c91f43738f8e278e159e8e3bb2aa53d5bdeaf782e845",
        &record_hex,
    );
    for ([_]struct { path: []const u8, target: []const u8 }{
        .{ .path = "usr/bin/sudoedit", .target = "/etc/alternatives/sudoedit" },
        .{ .path = "usr/share/man/man8/sudoedit.8.gz", .target = "/etc/alternatives/sudoedit.8.gz" },
    }) |expected| {
        var link = try root.root.pinSymbolicLink(try root_fs.Path.init(expected.path));
        defer link.close();
        var buffer: [64]u8 = undefined;
        const observed = try link.observe(&buffer);
        try testing.expectEqualStrings(expected.target, observed.target);
    }
    const sudo_dir = try root.root.entry(try root_fs.Path.init("run/sudo"));
    try testing.expectEqual(@as(u16, 0o711), sudo_dir.mode);
    try proc.verify(testing.allocator);
}

test "maintainer_script.test.signed sudo proc refuses tool alias and tmpfiles overrides" {
    if (builtin.os.tag != .linux) return;
    for ([_]struct { variable: [:0]const u8, reason: anyerror }{
        .{ .variable = "DEBZ_REQUIRE_SIGNED_SUDO_PROC_BAD_TOOL_ROOT", .reason = error.InvalidSnapshotSudoTool },
        .{ .variable = "DEBZ_REQUIRE_SIGNED_SUDO_PROC_BAD_FRAGMENT_ROOT", .reason = error.InvalidSnapshotSudoTool },
        .{ .variable = "DEBZ_REQUIRE_SIGNED_SUDO_PROC_MISSING_FRAGMENT_ROOT", .reason = error.FileNotFound },
        .{ .variable = "DEBZ_REQUIRE_SIGNED_SUDO_PROC_REDIRECTED_FRAGMENT_ROOT", .reason = error.NotRegularFile },
        .{ .variable = "DEBZ_REQUIRE_SIGNED_SUDO_PROC_BAD_ALIAS_ROOT", .reason = error.InvalidSnapshotSudoTool },
        .{ .variable = "DEBZ_REQUIRE_SIGNED_SUDO_PROC_OVERRIDE_ROOT", .reason = error.InvalidSnapshotSudoControl },
        .{ .variable = "DEBZ_REQUIRE_SIGNED_SUDO_PROC_SHADOW_ROOT", .reason = error.InvalidSnapshotSudoTool },
    }) |case| {
        const configured = std.c.getenv(case.variable) orelse continue;
        var root = try root_fs.openAbsoluteRoot(testing.io, std.mem.span(configured));
        defer root.close();
        try testing.expectError(
            case.reason,
            SnapshotSudoProc.init(testing.allocator, root.root),
        );
    }
}

test "maintainer_script.test.signed sudo tool changed after binding fails verification" {
    if (builtin.os.tag != .linux) return;
    const configured = std.c.getenv("DEBZ_REQUIRE_SIGNED_SUDO_PROC_CHANGED_ROOT") orelse return;
    var root = try root_fs.openAbsoluteRoot(testing.io, std.mem.span(configured));
    defer root.close();
    var proc = try SnapshotSudoProc.init(testing.allocator, root.root);
    defer proc.deinit();
    try root.root.dir.writeFile(testing.io, .{
        .sub_path = "usr/bin/systemd-tmpfiles",
        .data = "changed after binding",
    });
    try testing.expectError(error.PathChanged, proc.verify(testing.allocator));
}

test "maintainer_script.test.signed sudo sourced fragment changed after binding fails verification" {
    if (builtin.os.tag != .linux) return;
    const configured = std.c.getenv("DEBZ_REQUIRE_SIGNED_SUDO_PROC_CHANGED_FRAGMENT_ROOT") orelse return;
    var root = try root_fs.openAbsoluteRoot(testing.io, std.mem.span(configured));
    defer root.close();
    var proc = try SnapshotSudoProc.init(testing.allocator, root.root);
    defer proc.deinit();
    try root.root.dir.writeFile(testing.io, .{
        .sub_path = "usr/share/dpkg/sh/dpkg-error.sh",
        .data = "changed after binding",
    });
    try testing.expectError(error.PathChanged, proc.verify(testing.allocator));
}

test "maintainer_script.test.signed udev proc rejects altered tools and controls" {
    if (builtin.os.tag != .linux) return;
    for ([_][]const u8{
        "DEBZ_REQUIRE_SIGNED_UDEV_PROC_BAD_TOOL_ROOT",
        "DEBZ_REQUIRE_SIGNED_UDEV_PROC_BAD_CONTROL_ROOT",
    }) |variable| {
        const name = try testing.allocator.dupeZ(u8, variable);
        defer testing.allocator.free(name);
        const configured = std.c.getenv(name) orelse continue;
        var root = try root_fs.openAbsoluteRoot(testing.io, std.mem.span(configured));
        defer root.close();
        try testing.expectError(
            error.InvalidSnapshotUdevTool,
            SnapshotUdevProc.init(testing.allocator, root.root),
        );
    }
}

test "maintainer_script.test.signed udev proc rejects shadowing sidecars" {
    if (builtin.os.tag != .linux) return;
    for ([_]struct {
        variable: [:0]const u8,
        reason: anyerror,
    }{
        .{ .variable = "DEBZ_REQUIRE_SIGNED_UDEV_PROC_OVERRIDE_ROOT", .reason = error.InvalidSnapshotUdevControl },
        .{ .variable = "DEBZ_REQUIRE_SIGNED_UDEV_PROC_PATH_SHADOW_ROOT", .reason = error.InvalidSnapshotUdevTool },
        .{ .variable = "DEBZ_REQUIRE_SIGNED_UDEV_PROC_BAD_BIN_ROOT", .reason = error.InvalidSnapshotUdevTool },
    }) |case| {
        const configured = std.c.getenv(case.variable) orelse continue;
        var root = try root_fs.openAbsoluteRoot(testing.io, std.mem.span(configured));
        defer root.close();
        try testing.expectError(
            case.reason,
            SnapshotUdevProc.init(testing.allocator, root.root),
        );
    }
}

test "maintainer_script.test.signed udev tool changed after binding fails verification" {
    if (builtin.os.tag != .linux) return;
    const configured = std.c.getenv("DEBZ_REQUIRE_SIGNED_UDEV_PROC_CHANGED_ROOT") orelse return;
    const root_path = std.mem.span(configured);
    var root = try root_fs.openAbsoluteRoot(testing.io, root_path);
    defer root.close();
    var proc = try SnapshotUdevProc.init(testing.allocator, root.root);
    defer proc.deinit();
    try root.root.dir.writeFile(testing.io, .{
        .sub_path = "usr/bin/systemd-tmpfiles",
        .data = "changed after binding",
    });
    try testing.expectError(error.PathChanged, proc.verify(testing.allocator));
    try testing.expect((try root.root.entryIfExists(
        try root_fs.Path.init("usr/lib/udev/hwdb.bin"),
    )) == null);
}

test "maintainer_script.test.snapshot proc rejects an occupied mountpoint before launch" {
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDir(testing.io, "proc", .default_dir);
    try writeExecutableScript(&directory, "proc/occupied", "not empty");
    try testing.expectError(
        error.DirectoryTooLarge,
        SnapshotSystemdProc.init(
            testing.allocator,
            root_fs.Root.init(testing.io, directory.dir),
        ),
    );
}

fn testMaskedProcWorker(
    root_path: [:0]const u8,
    descriptor: ProcDescriptor,
    status_fd: i32,
    escape_group: bool,
) noreturn {
    if (linux.getpid() != 1) testSnapshotProcFailure(status_fd, 1, .CHILD);
    const death = linux.errno(linux.prctl(
        @intFromEnum(linux.PR.SET_PDEATHSIG),
        @intFromEnum(linux.SIG.KILL),
        0,
        0,
        0,
    ));
    if (death != .SUCCESS) testSnapshotProcFailure(status_fd, 2, death);
    const network_ready = setupPrivateLoopback();
    if (network_ready != .SUCCESS) testSnapshotProcFailure(status_fd, 18, network_ready);
    const private = linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0));
    if (private != .SUCCESS) testSnapshotProcFailure(status_fd, 3, private);
    const entered = linux.errno(linux.chdir(root_path.ptr));
    if (entered != .SUCCESS) testSnapshotProcFailure(status_fd, 4, entered);
    const chrooted = linux.errno(linux.chroot("."));
    if (chrooted != .SUCCESS) testSnapshotProcFailure(status_fd, 5, chrooted);
    const at_root = linux.errno(linux.chdir("/"));
    if (at_root != .SUCCESS) testSnapshotProcFailure(status_fd, 6, at_root);
    var setup_stage: u8 = 0;
    const setup = setupSnapshotProc(descriptor, &setup_stage);
    if (setup != .SUCCESS) testSnapshotProcFailure(status_fd, 20 + setup_stage, setup);
    if (escape_group) {
        const descendant = linux.fork();
        if (linux.errno(descendant) != .SUCCESS)
            testSnapshotProcFailure(status_fd, 8, linux.errno(descendant));
        if (descendant == 0) {
            _ = linux.setsid();
            const sleep: linux.timespec = .{ .sec = 10, .nsec = 0 };
            _ = linux.nanosleep(&sleep, null);
            linux.exit(0);
        }
    }
    const ready = [_]u8{ 1, 0, 0 };
    _ = linux.write(status_fd, &ready, ready.len);
    const sleep: linux.timespec = .{ .sec = 10, .nsec = 0 };
    _ = linux.nanosleep(&sleep, null);
    linux.exit(0);
}

test "maintainer_script.test.private proc views die on deadline and parent crash" {
    if (builtin.os.tag != .linux) return;
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDir(testing.io, "proc", .default_dir);
    const path = try absoluteTempPath(testing.allocator, &directory, "");
    defer testing.allocator.free(path);
    const root_path = try testing.allocator.dupeZ(u8, std.mem.trimEnd(u8, path, "/"));
    defer testing.allocator.free(root_path);
    var mountpoint = try root_fs.Root.init(testing.io, directory.dir).pinDirectory(
        try root_fs.Path.init("proc"),
    );
    defer mountpoint.close();
    const boot_id = readKernelBootId() catch {
        if (std.c.getenv("DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE") != null)
            return error.NativeHelperNamespaceRequired;
        return;
    };
    var descriptor: ProcDescriptor = .{
        .root_stat = undefined,
        .directory_stat = undefined,
        .view = .{ .systemd = boot_id },
    };
    try testing.expectEqual(linux.E.SUCCESS, helperStat(directory.dir.handle, &descriptor.root_stat));
    try testing.expectEqual(linux.E.SUCCESS, helperStat(mountpoint.dir.handle, &descriptor.directory_stat));
    for ([_]SnapshotProcMode{ .systemd, .udev, .sudo }) |mode| {
        descriptor.view = switch (mode) {
            .systemd => .{ .systemd = boot_id },
            .udev => .udev,
            .sudo => .sudo,
        };
        for ([_]bool{ false, true }) |parent_crash| {
            var status: [2]i32 = undefined;
            try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&status, .{ .CLOEXEC = true })));
            const owner = if (parent_crash)
                linux.fork()
            else
                linux.clone2(linux.CLONE.NEWNET | linux.CLONE.NEWNS | linux.CLONE.NEWPID | @intFromEnum(linux.SIG.CHLD), 0);
            if (linux.errno(owner) != .SUCCESS) {
                _ = linux.close(status[0]);
                _ = linux.close(status[1]);
                if (linux.errno(owner) == .PERM and
                    std.c.getenv("DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE") == null)
                    return;
                return error.NativeHelperNamespaceRequired;
            }
            if (owner == 0) {
                _ = linux.close(status[0]);
                if (!parent_crash)
                    testMaskedProcWorker(root_path, descriptor, status[1], true);
                const worker = linux.clone2(
                    linux.CLONE.NEWNET | linux.CLONE.NEWNS | linux.CLONE.NEWPID | @intFromEnum(linux.SIG.CHLD),
                    0,
                );
                if (linux.errno(worker) != .SUCCESS)
                    testSnapshotProcFailure(status[1], 9, linux.errno(worker));
                if (worker == 0)
                    testMaskedProcWorker(root_path, descriptor, status[1], false);
                var child_status: u32 = 0;
                _ = linux.waitpid(@intCast(worker), &child_status, 0);
                linux.exit(0);
            }
            _ = linux.close(status[1]);
            var ready: [3]u8 = .{ 0, 0, 0 };
            const received = linux.read(status[0], &ready, ready.len);
            if (received != ready.len or ready[0] != 1) {
                _ = linux.kill(@intCast(owner), .KILL);
                var abandoned: u32 = 0;
                _ = linux.waitpid(@intCast(owner), &abandoned, 0);
                _ = linux.close(status[0]);
                std.debug.print("snapshot proc teardown stage={d} errno={d} bytes={d}\n", .{ ready[1], ready[2], received });
                return error.NativeHelperNamespaceRequired;
            }
            _ = linux.kill(@intCast(owner), .KILL);
            var waited: u32 = 0;
            try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.waitpid(@intCast(owner), &waited, 0)));
            try testing.expect(linux.W.IFSIGNALED(waited));
            var pollfd: [1]linux.pollfd = .{.{ .fd = status[0], .events = linux.POLL.IN, .revents = 0 }};
            const drained = linux.poll(&pollfd, pollfd.len, 5_000);
            try testing.expectEqual(linux.E.SUCCESS, linux.errno(drained));
            try testing.expectEqual(@as(usize, 1), drained);
            var exhausted: [1]u8 = undefined;
            try testing.expectEqual(@as(usize, 0), linux.read(status[0], &exhausted, 1));
            _ = linux.close(status[0]);
            try testing.expect((try root_fs.Root.init(testing.io, directory.dir).entryIfExists(
                try root_fs.Path.init("proc/sys"),
            )) == null);
        }
    }
}

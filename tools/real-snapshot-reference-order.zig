const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const reference_paths = @import("reference_paths");

pub const maximum_packages: usize = 2000;
pub const maximum_probes: usize = 10000;
pub const maximum_probe_output: usize = 65536;
pub const maximum_control_bytes: usize = 1024 * 1024;
pub const maximum_log_bytes: usize = 16 * 1024 * 1024;
pub const maximum_archive_bytes: usize = 512 * 1024 * 1024;

pub const OrderError = error{
    NoncanonicalReferencePath,
    UnprotectedReferenceRoot,
    UnprotectedReferencePath,
    WrongReferenceFileType,
    ReferenceReadFailed,
    ReferenceSyscallRefused,
    EmptyPackageManifest,
    PackageManifestLimitExceeded,
    MalformedPackageManifestRow,
    InvalidManifestPackageIdentity,
    InvalidManifestArchitecture,
    InvalidManifestVersion,
    InvalidManifestSha512Digest,
    InvalidManifestDeclaredSize,
    DuplicateManifestPackageIdentity,
    PackageArchiveSizeMismatch,
    PackageArchiveMutatedDuringHashing,
    PackageArchiveSha512Mismatch,
    UnsupportedReferenceArchitecture,
    InvalidKbdCycleBreakPackages,
    KbdCycleBreakDisallowsRuntimeProfile,
    KbdCycleBreakRequiresPinnedAmd64,
    KbdCycleBreakPackageIdentityMismatch,
    InvalidOpensslCyclePackages,
    OpensslCycleDisallowsRuntimeProfile,
    OpensslCycleRequiresPinnedAmd64,
    OpensslCyclePackageIdentityMismatch,
    InvalidBaseCycleBreakPackages,
    BaseCycleBreakDisallowsRuntimeProfile,
    BaseCycleBreakRequiresPinnedAmd64,
    BaseCycleBreakPackageIdentityMismatch,
    InvalidTriggerHandlerPackages,
    TriggerProcessingDisallowsRuntimeProfile,
    TriggerProcessingRequiresPinnedAmd64,
    TriggerHandlerPackageIdentityMismatch,
    SinglePackageDpkgVerbRequired,
    RuntimeProfileSelectionMismatch,
    RuntimeProfileVersionMismatch,
    PackageArchitectureMismatch,
    ContinuePrestateRequiresProfilePackage,
    UnsupportedReferenceDpkgVerb,
    UnboundedPendingDpkgOperationRefused,
    ControlPayloadTooLarge,
    EmptyControlPayload,
    UnexpectedBlankControlLine,
    UnexpectedControlContinuationLine,
    ControlContinuationDisallowed,
    MalformedControlLine,
    InvalidControlFieldName,
    MissingSpaceAfterControlFieldSeparator,
    DuplicateControlField,
    StatusDatabaseExceedsPackageLimit,
    IncompleteDpkgStatusStanza,
    DuplicateDpkgStatusPackage,
    UnexpectedDpkgJournalEntries,
    DpkgTriggersDirectoryExceedsLimit,
    UnincorporatedDpkgTriggerState,
    ControlTarTooLarge,
    MalformedControlTarHeader,
    TruncatedControlTarMember,
    MissingBaseCyclePackages,
    BaseCycleOrderRequiresAmd64,
    BaseCyclePinMismatch,
    BaseCycleMissingControlMember,
    BaseCycleControlFieldMismatch,
    LibgccControlMembersMismatch,
    LibgccPostinstMustBeAbsent,
    LibgccTriggersContentMismatch,
    BaseCycleStatusNotReady,
    BaseCycleMutatedUnexpectedPackageStatus,
    BaseCycleDidNotInstallPinnedPair,
    MissingOpensslCyclePackages,
    OpensslCycleOrderRequiresAmd64,
    OpensslCyclePinMismatch,
    OpensslCycleMissingControlMember,
    OpensslCycleControlFieldMismatch,
    OpensslCyclePostinstMustBeAbsent,
    OpensslCycleStatusNotReady,
    OpensslCycleMutatedUnexpectedPackageStatus,
    OpensslCycleMutatedUnexpectedTriggerState,
    OpensslCycleDidNotInstallPinnedPair,
    MissingKbdCyclePackages,
    KbdCycleOrderRequiresAmd64,
    KbdCyclePinMismatch,
    KbdCycleControlMembersMismatch,
    KbdCycleControlFieldMismatch,
    KbdCyclePostinstMustBeAbsent,
    KbdCycleTriggersContentMismatch,
    KbdCycleStatusNotReady,
    KbdCycleMutatedUnexpectedPackageStatus,
    KbdCycleMutatedUnexpectedTriggerState,
    KbdCycleDidNotInstallKbd,
    MissingTriggerHandlerPackage,
    TriggerHandlerOrderRequiresAmd64,
    TriggerHandlerPinMismatch,
    TriggerHandlerProfileMismatch,
    TriggerHandlerControlMembersMismatch,
    TriggerHandlerControlFieldMismatch,
    TriggerHandlerPostinstMismatch,
    TriggerHandlerTriggersMismatch,
    TriggerHandlerInstalledPostinstMismatch,
    TriggerHandlerInstalledTriggersMismatch,
    TriggerHandlerStatusNotReady,
    TriggerHandlerPendingTriggerMissing,
    TriggerHandlerMutatedUnexpectedPackageStatus,
    TriggerHandlerMutatedUnexpectedTriggerState,
    TriggerHandlerDidNotInstallHandlers,
    TriggerHandlerDidNotDrainPendingTrigger,
    PrestateTargetRequiresPendingRuntimeProfile,
    PendingRuntimeRequiresCanonicalAbsolutePaths,
    PendingRuntimeTargetNotUnpacked,
    PendingRuntimeTargetPostinstMissing,
    InvalidPrestateTargetFormat,
    PrestateTargetNotInManifest,
    MissingSudoPrestateCompanion,
    ReferenceOrderStalled,
    ReferenceProbeBudgetExceeded,
    UnexpectedTriggersAwaitedState,
    UninstalledPackagesRemain,
    PendingTriggersRemain,
    InvalidCliArguments,
};

pub const ProfileVersionPin = struct {
    name: []const u8,
    version: []const u8,
};

pub const profile_versions = [_]ProfileVersionPin{
    .{ .name = "systemd", .version = "259.5-0ubuntu3.4" },
    .{ .name = "udev", .version = "259.5-0ubuntu3.4" },
    .{ .name = "sudo", .version = "1.9.17p2-1ubuntu3.1" },
};

pub const CyclePackagePin = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    size: usize,
    sha512: []const u8,
    depends: []const u8,
    pre_depends: []const u8 = "",
    status: []const u8,
    members: []const []const u8 = &.{},
};

pub const libgcc_triggers = "# Triggers added by dh_makeshlibs/13.31ubuntu1\nactivate-noawait ldconfig\n";

pub const base_cycle = [_]CyclePackagePin{
    .{
        .name = "libc6",
        .version = "2.43-2ubuntu2.4",
        .architecture = "amd64",
        .size = 2104056,
        .sha512 = "e27873bec6e0a7914834eac85748c31a360b44b0f0e971a7cd70439c2f9804e737f8f6113f15bb7f523d7a5d4a336173b43a5e22d804c440c8a11a5530bc6696",
        .depends = "libgcc-s1, libc-gconv-modules-extra (= 2.43-2ubuntu2.4)",
        .status = "install ok unpacked",
    },
    .{
        .name = "libgcc-s1",
        .version = "16-20260322-1ubuntu1",
        .architecture = "amd64",
        .size = 80312,
        .sha512 = "a34e93f253ca90bd331c5eee563be6ebcc14dbf08147e82b9479f972fe566c83263b644e348757af1853f8663cb8ca2349e2c013e4a0ca0e3ea3d631297576b2",
        .depends = "gcc-16-base (= 16-20260322-1ubuntu1), libc6 (>= 2.35)",
        .status = "install ok unpacked",
        .members = &.{ ".", "./control", "./md5sums", "./shlibs", "./symbols", "./triggers" },
    },
    .{
        .name = "gcc-16-base",
        .version = "16-20260322-1ubuntu1",
        .architecture = "amd64",
        .size = 38296,
        .sha512 = "0767f731e71e709736596d52dbe181245a8ca181cdadbac6226aad5aa7151d8ce5149ad28625facc61d8882e76fc387af5336dc289126a0bf830b9e599b3922c",
        .depends = "",
        .status = "install ok installed",
    },
    .{
        .name = "libc-gconv-modules-extra",
        .version = "2.43-2ubuntu2.4",
        .architecture = "amd64",
        .size = 1362202,
        .sha512 = "c385f1ca4f8054e59f977a38819e31d6f2429909ce0a88c734c874ce163851dfa7e565dded6c65c3feb3bc8cf074498b45a4c2226bb8e17a2bc8b95027a29692",
        .depends = "",
        .status = "install ok installed",
    },
};

pub const openssl_cycle = [_]CyclePackagePin{
    .{
        .name = "libssl3t64",
        .version = "3.5.5-1ubuntu3.6",
        .architecture = "amd64",
        .size = 2364586,
        .sha512 = "10df2f82619faff2ed4b890812313c35cd58abbfce858caf3403e1b654fac857bd7bc28e7a528a79a18ebfbfbdca5cffb3c2dd5b340c729fb7eb2470b76d528d",
        .depends = "libc6 (>= 2.38), libzstd1 (>= 1.5.5), zlib1g (>= 1:1.1.4), openssl-provider-legacy",
        .status = "install ok unpacked",
    },
    .{
        .name = "openssl-provider-legacy",
        .version = "3.5.5-1ubuntu3.6",
        .architecture = "amd64",
        .size = 39690,
        .sha512 = "cbb4f55a609576d99a1b52952a674e78b2cbb7026e54c765cfd964812b65bdcdea4f5ea67961159b737fcba3093b3b15de8b7a6aff3bbf08a85805a09290c470",
        .depends = "libc6 (>= 2.14), libssl3t64 (>= 3.0.3)",
        .status = "install ok unpacked",
    },
    .{
        .name = "libc6",
        .version = "2.43-2ubuntu2.4",
        .architecture = "amd64",
        .size = 2104056,
        .sha512 = "e27873bec6e0a7914834eac85748c31a360b44b0f0e971a7cd70439c2f9804e737f8f6113f15bb7f523d7a5d4a336173b43a5e22d804c440c8a11a5530bc6696",
        .depends = "libgcc-s1, libc-gconv-modules-extra (= 2.43-2ubuntu2.4)",
        .status = "install ok installed",
    },
    .{
        .name = "libzstd1",
        .version = "1.5.7+dfsg-3",
        .architecture = "amd64",
        .size = 308174,
        .sha512 = "284a44950a9caae10a6b7a06baead5db2d6dd2989fc01107c78c76ef5468cb489fc1a8e92d6cb84d44b5a371f8b1156bd2f5c232e79f1631dcf000a601e52183",
        .depends = "libc6 (>= 2.34)",
        .status = "install ok installed",
    },
    .{
        .name = "zlib1g",
        .version = "1:1.3.dfsg+really1.3.1-1ubuntu3.1",
        .architecture = "amd64",
        .size = 61612,
        .sha512 = "a0ad94daadd3099ee40766a62a42d3fa7f431c6d805e9108d1dde07d64bfe3e7da66a41a2294598917e5ef5435df7a239d011711dd6d18037bc9b61b530ed3d4",
        .depends = "libc6 (>= 2.14)",
        .status = "install ok installed",
    },
};

pub const kbd_triggers = "# Triggers added by dh_installinitramfs/13.24.2ubuntu1\nactivate-noawait update-initramfs\n";

pub const kbd_cycle = [_]CyclePackagePin{
    .{
        .name = "kbd",
        .version = "2.7.1-2ubuntu2",
        .architecture = "amd64",
        .size = 238014,
        .sha512 = "5a1fcb79b59441d380b4f6f38198ab4e7b04e50a759580302643ab1f138d88c900145612dfe0861eab37c5f9ebbb6218bc3a5585366be04d4cd00f85efa16050",
        .depends = "libc6 (>= 2.38), console-setup | console-setup-mini",
        .status = "install ok unpacked",
        .members = &.{ ".", "./control", "./md5sums", "./triggers" },
    },
    .{
        .name = "console-setup-linux",
        .version = "1.237ubuntu3.1",
        .architecture = "all",
        .size = 6206020,
        .sha512 = "511e2f220d1f2afb6c0ae80d9488b6863b884f2db26e54d9cd343ca212c8061e6fbf637131fbd6f93673f3f9d47fe22515b22eca96a1cdf65e9e768fd2bbbb5b",
        .depends = "kbd (>= 0.99-12) | console-tools (>= 1:0.2.3-16), keyboard-configuration (= 1.237ubuntu3.1), init-system-helpers (>= 1.29~) | initscripts",
        .status = "install ok unpacked",
        .members = &.{ ".", "./conffiles", "./control", "./md5sums", "./postinst", "./postrm", "./preinst", "./prerm" },
    },
    .{
        .name = "console-setup",
        .version = "1.237ubuntu3.1",
        .architecture = "all",
        .size = 102654,
        .sha512 = "776ebf749c2a621ff9835b86b69efe1c838e948ac8265fab0f2c5eb91875ae67f1313800854b3a8a962359dfa40bee3e59cc5cf956a215ed82e15529bf622832",
        .depends = "console-setup-linux | hurd, xkb-data (>= 0.9), keyboard-configuration (= 1.237ubuntu3.1), debconf (>= 0.5) | debconf-2.0",
        .pre_depends = "debconf | debconf-2.0",
        .status = "install ok unpacked",
        .members = &.{ ".", "./config", "./control", "./md5sums", "./postinst", "./postrm", "./templates" },
    },
    .{
        .name = "libc6",
        .version = "2.43-2ubuntu2.4",
        .architecture = "amd64",
        .size = 2104056,
        .sha512 = "e27873bec6e0a7914834eac85748c31a360b44b0f0e971a7cd70439c2f9804e737f8f6113f15bb7f523d7a5d4a336173b43a5e22d804c440c8a11a5530bc6696",
        .depends = "libgcc-s1, libc-gconv-modules-extra (= 2.43-2ubuntu2.4)",
        .status = "install ok installed",
        .members = &.{ ".", "./conffiles", "./control", "./md5sums", "./postinst", "./postrm", "./preinst", "./shlibs", "./symbols", "./templates", "./triggers" },
    },
};

pub const TriggerHandlerPin = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    size: usize,
    sha512: []const u8,
    profile: []const u8,
    pending: []const u8,
    members: []const []const u8,
    postinst_size: usize,
    postinst_sha256: []const u8,
    triggers_size: usize,
    triggers_sha256: []const u8,
};

pub const trigger_handlers = [_]TriggerHandlerPin{
    .{
        .name = "libc-bin",
        .version = "2.43-2ubuntu2.4",
        .architecture = "amd64",
        .size = 576224,
        .sha512 = "cb77d5f8849a20b56a0e68f9cc4e83a961657bbde9d1d1ba47462736d719f27a8b1a911be69f254f59f9dc71489b5a044162dbdc2a83029699ef1de1da986437",
        .profile = "none",
        .pending = "ldconfig",
        .members = &.{ ".", "./conffiles", "./control", "./md5sums", "./postinst", "./triggers" },
        .postinst_size = 622,
        .postinst_sha256 = "6fa11d1fb4cd5b56bcbb4f0ff9b7f5897d22a5cb960ef04eb010e7eb21b3fc50",
        .triggers_size = 64,
        .triggers_sha256 = "964d2b0d8958f1479ca6df40ee9f4a53d96c87a929aeafbeff51c5f9b5e4c2e1",
    },
    .{
        .name = "procps",
        .version = "2:4.0.4-9ubuntu3",
        .architecture = "amd64",
        .size = 860868,
        .sha512 = "457df633cd23885c1b9e6d881ca66fb6e375890f4568d8de2cf38b6b593c983952f5bd791f8dc079d9a4a8267dd2c9f15a2d02abbc8f561623be37f9292cc1a7",
        .profile = "none",
        .pending = "/usr/lib/sysctl.d",
        .members = &.{ ".", "./conffiles", "./control", "./md5sums", "./postinst", "./postrm", "./preinst", "./prerm", "./triggers" },
        .postinst_size = 905,
        .postinst_sha256 = "02b9bd7821242c8398e3d28070f5203594a59d295679124683b21c51500dd234",
        .triggers_size = 113,
        .triggers_sha256 = "6275cebe8c9a8ef1b2d5a0ff1c63c9a452699da428b29b4fbec6903bd46d6bf3",
    },
};

pub const sudo_prestate_companion = struct {
    pub const name = "sudo-rs";
    pub const version = "0.2.13-0ubuntu1.2";
    pub const architecture = "amd64";
};

pub const PackageKey = struct {
    name: []const u8,
    architecture: []const u8,

    pub fn eql(a: PackageKey, b: PackageKey) bool {
        return std.mem.eql(u8, a.name, b.name) and std.mem.eql(u8, a.architecture, b.architecture);
    }
};

pub const PackageKeyContext = struct {
    pub fn hash(_: PackageKeyContext, k: PackageKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(k.name);
        h.update(&.{0});
        h.update(k.architecture);
        return h.final();
    }
    pub fn eql(_: PackageKeyContext, a: PackageKey, b: PackageKey) bool {
        return PackageKey.eql(a, b);
    }
};

pub const Package = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    digest: []const u8,
    declared_size: usize,
    archive: []const u8,

    pub fn key(self: Package) PackageKey {
        return .{ .name = self.name, .architecture = self.architecture };
    }
};

pub fn validPackageName(value: []const u8) bool {
    if (value.len == 0) return false;
    const first = value[0];
    if (!((first >= 'a' and first <= 'z') or (first >= '0' and first <= '9'))) return false;
    for (value[1..]) |ch| {
        if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '+' or ch == '.' or ch == '-')) return false;
    }
    return true;
}

pub fn validHexDigest(value: []const u8, expected_len: usize) bool {
    if (value.len != expected_len) return false;
    for (value) |ch| {
        if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'))) return false;
    }
    return true;
}

pub fn packageProfile(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "systemd") or std.mem.eql(u8, name, "udev")) return "systemd";
    if (std.mem.eql(u8, name, "sudo")) return "sudo";
    return "none";
}

pub fn profilePinnedVersion(name: []const u8) ?[]const u8 {
    inline for (profile_versions) |pin| {
        if (std.mem.eql(u8, name, pin.name)) return pin.version;
    }
    return null;
}

fn findBaseCyclePin(name: []const u8) ?CyclePackagePin {
    for (base_cycle) |pin| {
        if (std.mem.eql(u8, pin.name, name)) return pin;
    }
    return null;
}

fn findOpensslCyclePin(name: []const u8) ?CyclePackagePin {
    for (openssl_cycle) |pin| {
        if (std.mem.eql(u8, pin.name, name)) return pin;
    }
    return null;
}

fn findKbdCyclePin(name: []const u8) ?CyclePackagePin {
    for (kbd_cycle) |pin| {
        if (std.mem.eql(u8, pin.name, name)) return pin;
    }
    return null;
}

fn findTriggerHandlerPin(name: []const u8) ?TriggerHandlerPin {
    for (trigger_handlers) |pin| {
        if (std.mem.eql(u8, pin.name, name)) return pin;
    }
    return null;
}

pub fn packagesFromManifest(
    allocator: std.mem.Allocator,
    manifest_path: []const u8,
    cache: []const u8,
    max_packages: usize,
) ![]Package {
    if (!std.mem.startsWith(u8, cache, "/")) return error.NoncanonicalReferencePath;
    const fd = try reference_paths.openAbsolute(manifest_path, false);
    defer _ = linux.close(fd);
    var raw = std.ArrayList(u8).empty;
    defer raw.deinit(allocator);
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(rc) != .SUCCESS) return error.ReferenceReadFailed;
        if (rc == 0) break;
        if (raw.items.len + rc > maximum_control_bytes) return error.ControlPayloadTooLarge;
        try raw.appendSlice(allocator, buf[0..rc]);
    }
    var packages = std.ArrayList(Package).empty;
    errdefer packages.deinit(allocator);
    var seen = std.HashMap(PackageKey, void, PackageKeyContext, 80).init(allocator);
    defer seen.deinit();

    var lines = std.mem.splitScalar(u8, raw.items, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0 and lines.rest().len == 0) break;
        if (packages.items.len >= max_packages) return error.PackageManifestLimitExceeded;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const name = fields.next() orelse return error.MalformedPackageManifestRow;
        const version = fields.next() orelse return error.MalformedPackageManifestRow;
        const architecture = fields.next() orelse return error.MalformedPackageManifestRow;
        const digest = fields.next() orelse return error.MalformedPackageManifestRow;
        const size_raw = fields.next() orelse return error.MalformedPackageManifestRow;
        if (fields.next() != null) return error.MalformedPackageManifestRow;

        if (!validPackageName(name)) return error.InvalidManifestPackageIdentity;
        if (!validPackageName(architecture)) return error.InvalidManifestArchitecture;
        if (version.len == 0 or std.mem.indexOfAny(u8, version, " \t\r\n") != null) return error.InvalidManifestVersion;
        if (!validHexDigest(digest, 128)) return error.InvalidManifestSha512Digest;
        for (size_raw) |ch| {
            if (ch < '0' or ch > '9') return error.InvalidManifestDeclaredSize;
        }
        const declared_size = std.fmt.parseInt(usize, size_raw, 10) catch return error.InvalidManifestDeclaredSize;
        if (declared_size == 0 or declared_size > maximum_archive_bytes) return error.InvalidManifestDeclaredSize;

        const pkg_key: PackageKey = .{
            .name = try allocator.dupe(u8, name),
            .architecture = try allocator.dupe(u8, architecture),
        };
        if ((try seen.getOrPut(pkg_key)).found_existing) return error.DuplicateManifestPackageIdentity;

        const trimmed_cache = std.mem.trimEnd(u8, cache, "/");
        const archive = try std.fmt.allocPrint(allocator, "{s}/{s}.deb", .{ trimmed_cache, digest });
        try packages.append(allocator, .{
            .name = pkg_key.name,
            .version = try allocator.dupe(u8, version),
            .architecture = pkg_key.architecture,
            .digest = try allocator.dupe(u8, digest),
            .declared_size = declared_size,
            .archive = archive,
        });
    }
    if (packages.items.len == 0) return error.EmptyPackageManifest;
    return packages.toOwnedSlice(allocator);
}

fn sameFileIdentity(a: linux.Statx, b: linux.Statx) bool {
    return a.dev_major == b.dev_major and
        a.dev_minor == b.dev_minor and
        a.ino == b.ino and
        a.size == b.size and
        a.mtime.sec == b.mtime.sec and
        a.mtime.nsec == b.mtime.nsec;
}

pub var test_after_fstat_hook: ?*const fn (fd: i32) anyerror!linux.Statx = null;
pub var test_verify_archive_hook: ?*const fn (pkg: Package) anyerror!void = null;

pub fn verifyArchive(package: Package) !void {
    if (builtin.is_test and test_verify_archive_hook != null) {
        return test_verify_archive_hook.?(package);
    }
    const meta = try reference_paths.protected(package.archive, false);
    if (meta.size != package.declared_size) return error.PackageArchiveSizeMismatch;
    const fd = try reference_paths.openAbsolute(package.archive, false);
    defer _ = linux.close(fd);
    const before = try reference_paths.fstat(fd);
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    var observed: usize = 0;
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const to_read = @min(buf.len, (package.declared_size + 1) -| observed);
        if (to_read == 0) break;
        const rc = linux.read(fd, &buf, to_read);
        if (linux.errno(rc) != .SUCCESS) return error.ReferenceReadFailed;
        if (rc == 0) break;
        observed += rc;
        if (observed > package.declared_size) return error.PackageArchiveSizeMismatch;
        hasher.update(buf[0..rc]);
    }
    const after = if (builtin.is_test and test_after_fstat_hook != null)
        try test_after_fstat_hook.?(fd)
    else
        try reference_paths.fstat(fd);
    if (!sameFileIdentity(before, meta) or !sameFileIdentity(after, before)) {
        return error.PackageArchiveMutatedDuringHashing;
    }
    if (observed != package.declared_size) return error.PackageArchiveSizeMismatch;
    var digest_bytes: [64]u8 = undefined;
    hasher.final(&digest_bytes);
    const hex = std.fmt.bytesToHex(digest_bytes, .lower);
    if (!std.mem.eql(u8, &hex, package.digest)) return error.PackageArchiveSha512Mismatch;
}

pub fn dpkgCommand(
    allocator: std.mem.Allocator,
    dpkg: []const u8,
    root: []const u8,
    verb: []const u8,
    packages: []const Package,
    architecture: []const u8,
    profile: []const u8,
) ![]const []const u8 {
    if (!std.mem.startsWith(u8, dpkg, "/") or !std.mem.startsWith(u8, root, "/")) {
        return error.NoncanonicalReferencePath;
    }
    if (!std.mem.eql(u8, architecture, "amd64") and !std.mem.eql(u8, architecture, "arm64")) {
        return error.UnsupportedReferenceArchitecture;
    }
    var command = std.ArrayList([]const u8).empty;
    errdefer command.deinit(allocator);
    const admindir = try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg", .{std.mem.trimEnd(u8, root, "/")});
    try command.appendSlice(allocator, &.{
        try allocator.dupe(u8, dpkg),
        "--root",
        try allocator.dupe(u8, root),
        "--admindir",
        admindir,
        "--log",
        "/dev/null",
        "--no-Overlay",
    });
    // Replace placeholder "--no-Overlay" with "--no-pager" to match exact argv.
    command.items[command.items.len - 1] = "--no-pager";

    if (std.mem.eql(u8, verb, "break_kbd_cycle")) {
        if (packages.len != 1) return error.InvalidKbdCycleBreakPackages;
        if (!std.mem.eql(u8, profile, "none")) return error.KbdCycleBreakDisallowsRuntimeProfile;
        if (!std.mem.eql(u8, architecture, "amd64")) return error.KbdCycleBreakRequiresPinnedAmd64;
        const pkg = packages[0];
        const expected = findKbdCyclePin("kbd").?;
        if (!std.mem.eql(u8, pkg.name, "kbd") or
            !std.mem.eql(u8, pkg.architecture, expected.architecture) or
            !std.mem.eql(u8, pkg.version, expected.version) or
            pkg.declared_size != expected.size or
            !std.mem.eql(u8, pkg.digest, expected.sha512))
        {
            return error.KbdCycleBreakPackageIdentityMismatch;
        }
        try command.appendSlice(allocator, &.{
            "--force-depends=console-setup",
            "--configure",
            try std.fmt.allocPrint(allocator, "{s}:{s}", .{ pkg.name, pkg.architecture }),
        });
    } else if (std.mem.eql(u8, verb, "configure_openssl_cycle")) {
        if (packages.len != 2) return error.InvalidOpensslCyclePackages;
        if (!std.mem.eql(u8, profile, "none")) return error.OpensslCycleDisallowsRuntimeProfile;
        if (!std.mem.eql(u8, architecture, "amd64")) return error.OpensslCycleRequiresPinnedAmd64;
        if (!std.mem.eql(u8, packages[0].name, "libssl3t64") or
            !std.mem.eql(u8, packages[1].name, "openssl-provider-legacy"))
        {
            return error.OpensslCyclePackageIdentityMismatch;
        }
        for (packages) |pkg| {
            const expected = findOpensslCyclePin(pkg.name) orelse return error.OpensslCyclePackageIdentityMismatch;
            if (!std.mem.eql(u8, pkg.architecture, expected.architecture) or
                !std.mem.eql(u8, pkg.version, expected.version) or
                pkg.declared_size != expected.size or
                !std.mem.eql(u8, pkg.digest, expected.sha512))
            {
                return error.OpensslCyclePackageIdentityMismatch;
            }
        }
        try command.appendSlice(allocator, &.{
            "--configure",
            try std.fmt.allocPrint(allocator, "{s}:{s}", .{ packages[0].name, packages[0].architecture }),
            try std.fmt.allocPrint(allocator, "{s}:{s}", .{ packages[1].name, packages[1].architecture }),
        });
    } else if (std.mem.eql(u8, verb, "break_base_cycle")) {
        if (packages.len != 2) return error.InvalidBaseCycleBreakPackages;
        if (!std.mem.eql(u8, profile, "none")) return error.BaseCycleBreakDisallowsRuntimeProfile;
        if (!std.mem.eql(u8, architecture, "amd64")) return error.BaseCycleBreakRequiresPinnedAmd64;
        if (!std.mem.eql(u8, packages[0].name, "libc6") or
            !std.mem.eql(u8, packages[1].name, "libgcc-s1"))
        {
            return error.BaseCycleBreakPackageIdentityMismatch;
        }
        for (packages) |pkg| {
            const expected = findBaseCyclePin(pkg.name) orelse return error.BaseCycleBreakPackageIdentityMismatch;
            if (!std.mem.eql(u8, pkg.architecture, expected.architecture) or
                !std.mem.eql(u8, pkg.version, expected.version) or
                pkg.declared_size != expected.size or
                !std.mem.eql(u8, pkg.digest, expected.sha512))
            {
                return error.BaseCycleBreakPackageIdentityMismatch;
            }
        }
        try command.appendSlice(allocator, &.{
            "--force-depends=libc6,libgcc-s1",
            "--configure",
            try std.fmt.allocPrint(allocator, "{s}:{s}", .{ packages[0].name, packages[0].architecture }),
            try std.fmt.allocPrint(allocator, "{s}:{s}", .{ packages[1].name, packages[1].architecture }),
        });
    } else if (std.mem.eql(u8, verb, "triggers_only")) {
        if (packages.len == 0 or packages.len > trigger_handlers.len) return error.InvalidTriggerHandlerPackages;
        if (!std.mem.eql(u8, profile, "none")) return error.TriggerProcessingDisallowsRuntimeProfile;
        if (!std.mem.eql(u8, architecture, "amd64")) return error.TriggerProcessingRequiresPinnedAmd64;
        var seen_names = std.StringHashMap(void).init(allocator);
        defer seen_names.deinit();
        for (packages) |pkg| {
            if ((try seen_names.getOrPut(pkg.name)).found_existing) return error.TriggerHandlerPackageIdentityMismatch;
            const expected = findTriggerHandlerPin(pkg.name) orelse return error.TriggerHandlerPackageIdentityMismatch;
            if (!std.mem.eql(u8, pkg.architecture, expected.architecture) or
                !std.mem.eql(u8, pkg.version, expected.version) or
                pkg.declared_size != expected.size or
                !std.mem.eql(u8, pkg.digest, expected.sha512))
            {
                return error.TriggerHandlerPackageIdentityMismatch;
            }
        }
        try command.append(allocator, "--triggers-only");
        for (packages) |pkg| {
            try command.append(allocator, try std.fmt.allocPrint(allocator, "{s}:{s}", .{ pkg.name, pkg.architecture }));
        }
    } else {
        if (packages.len != 1) return error.SinglePackageDpkgVerbRequired;
        const pkg = packages[0];
        if (!std.mem.eql(u8, profile, packageProfile(pkg.name))) return error.RuntimeProfileSelectionMismatch;
        if (!std.mem.eql(u8, profile, "none")) {
            const pinned_ver = profilePinnedVersion(pkg.name) orelse return error.RuntimeProfileVersionMismatch;
            if (!std.mem.eql(u8, pkg.version, pinned_ver)) return error.RuntimeProfileVersionMismatch;
        }
        if (!std.mem.eql(u8, pkg.architecture, architecture) and !std.mem.eql(u8, pkg.architecture, "all")) {
            return error.PackageArchitectureMismatch;
        }
        if (std.mem.startsWith(u8, verb, "probe_")) {
            try command.append(allocator, "--dry-run");
        }
        if (std.mem.eql(u8, verb, "probe_unpack") or std.mem.eql(u8, verb, "unpack")) {
            try command.appendSlice(allocator, &.{ "--unpack", try allocator.dupe(u8, pkg.archive) });
        } else if (std.mem.eql(u8, verb, "probe_configure") or std.mem.eql(u8, verb, "configure")) {
            try command.appendSlice(allocator, &.{
                "--configure",
                try std.fmt.allocPrint(allocator, "{s}:{s}", .{ pkg.name, pkg.architecture }),
            });
        } else if (std.mem.eql(u8, verb, "continue_prestate")) {
            if (std.mem.eql(u8, profile, "none")) return error.ContinuePrestateRequiresProfilePackage;
            try command.appendSlice(allocator, &.{
                "--configure",
                try std.fmt.allocPrint(allocator, "{s}:{s}", .{ pkg.name, pkg.architecture }),
            });
        } else {
            return error.UnsupportedReferenceDpkgVerb;
        }
    }
    for (command.items) |arg| {
        if (std.mem.eql(u8, arg, "--pending")) return error.UnboundedPendingDpkgOperationRefused;
    }
    return command.toOwnedSlice(allocator);
}

fn validFieldName(name: []const u8) bool {
    if (name.len == 0) return false;
    const first = name[0];
    if (!((first >= 'A' and first <= 'Z') or (first >= 'a' and first <= 'z') or (first >= '0' and first <= '9'))) return false;
    for (name[1..]) |ch| {
        if (!((ch >= 'A' and ch <= 'Z') or (ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '-')) return false;
    }
    return true;
}

fn isIdentityField(lower_name: []const u8) bool {
    return std.mem.eql(u8, lower_name, "package") or
        std.mem.eql(u8, lower_name, "architecture") or
        std.mem.eql(u8, lower_name, "version") or
        std.mem.eql(u8, lower_name, "status");
}

pub fn controlFields(allocator: std.mem.Allocator, text: []const u8) !std.StringHashMap([]const u8) {
    if (text.len > maximum_control_bytes) return error.ControlPayloadTooLarge;
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return error.EmptyControlPayload;

    var fields = std.StringHashMap([]const u8).init(allocator);
    errdefer fields.deinit();
    var current: ?[]const u8 = null;

    const without_trailing_nl = std.mem.trimEnd(u8, text, "\r\n");
    var lines = std.mem.splitScalar(u8, without_trailing_nl, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) return error.UnexpectedBlankControlLine;
        if (line[0] == ' ' or line[0] == '\t') {
            const key = current orelse return error.UnexpectedControlContinuationLine;
            if (isIdentityField(key)) return error.ControlContinuationDisallowed;
            const prev = fields.get(key).?;
            const cont = std.mem.trim(u8, line, " \t");
            const combined = if (prev.len == 0)
                try allocator.dupe(u8, cont)
            else
                try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ prev, cont });
            try fields.put(key, combined);
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedControlLine;
        const name = line[0..colon];
        const remainder = line[colon + 1 ..];
        if (!validFieldName(name)) return error.InvalidControlFieldName;
        if (remainder.len > 0 and remainder[0] != ' ') return error.MissingSpaceAfterControlFieldSeparator;
        const key = try std.ascii.allocLowerString(allocator, name);
        if (fields.contains(key)) return error.DuplicateControlField;
        const value = std.mem.trim(u8, remainder, " \t");
        try fields.put(key, try allocator.dupe(u8, value));
        current = key;
    }
    return fields;
}

pub fn databaseFields(allocator: std.mem.Allocator, text: []const u8) !std.StringHashMap([]const u8) {
    return controlFields(allocator, text);
}

pub const DatabasePackage = struct {
    name: []const u8,
    architecture: []const u8,
    version: []const u8,
    status: []const u8,
};

pub const DatabaseMap = std.HashMap(PackageKey, DatabasePackage, PackageKeyContext, 80);

pub fn databasePackages(allocator: std.mem.Allocator, text: []const u8) !DatabaseMap {
    var packages = DatabaseMap.init(allocator);
    errdefer packages.deinit();

    var start: usize = 0;
    while (start <= text.len) {
        const next_sep = std.mem.indexOfPos(u8, text, start, "\n\n");
        const stanza_raw = if (next_sep) |idx| text[start..idx] else text[start..];
        const stanza = std.mem.trim(u8, stanza_raw, " \t\r\n");
        if (stanza.len > 0) {
            if (packages.count() >= maximum_packages) return error.StatusDatabaseExceedsPackageLimit;
            var fields = try databaseFields(allocator, stanza);
            defer fields.deinit();
            const pkg_name = fields.get("package") orelse return error.IncompleteDpkgStatusStanza;
            const arch = fields.get("architecture") orelse return error.IncompleteDpkgStatusStanza;
            const version = fields.get("version") orelse return error.IncompleteDpkgStatusStanza;
            const status = fields.get("status") orelse return error.IncompleteDpkgStatusStanza;
            if (!validPackageName(pkg_name) or !validPackageName(arch) or version.len == 0 or status.len == 0) {
                return error.IncompleteDpkgStatusStanza;
            }
            const k: PackageKey = .{ .name = pkg_name, .architecture = arch };
            if ((try packages.getOrPut(k)).found_existing) return error.DuplicateDpkgStatusPackage;
            try packages.put(k, .{
                .name = pkg_name,
                .architecture = arch,
                .version = version,
                .status = status,
            });
        }
        if (next_sep) |idx| {
            start = idx + 2;
        } else break;
    }
    return packages;
}

pub fn packageStatusKey(
    pkg: Package,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    statuses: *const DatabaseMap,
    architecture: []const u8,
) PackageKey {
    if (statuses.contains(pkg.key())) return pkg.key();
    if (std.mem.eql(u8, pkg.architecture, "all")) {
        const arch_key: PackageKey = .{ .name = pkg.name, .architecture = architecture };
        if (!all_packages.contains(arch_key) and statuses.contains(arch_key)) return arch_key;
    }
    return pkg.key();
}

pub fn currentStatuses(allocator: std.mem.Allocator, root: []const u8) !DatabaseMap {
    const raw = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", maximum_control_bytes);
    defer allocator.free(raw);
    return databasePackages(allocator, raw);
}

pub const TriggerEntry = struct {
    size: usize,
    sha512: [128]u8,
};

pub const TriggerMap = std.StringHashMap(TriggerEntry);

const LinuxDirent64 = extern struct {
    ino: u64,
    off: i64,
    reclen: u16,
    type: u8,
    name: [1]u8,
};

fn listDirectoryBeneath(allocator: std.mem.Allocator, root_fd: i32, relative: []const u8) ![][]const u8 {
    const dir_fd = try reference_paths.openBeneath(root_fd, relative, true);
    defer _ = linux.close(dir_fd);
    var names = std.ArrayList([]const u8).empty;
    errdefer names.deinit(allocator);
    var buf: [8192]u8 align(@alignOf(LinuxDirent64)) = undefined;
    while (true) {
        const nread = linux.getdents64(dir_fd, &buf, buf.len);
        if (linux.errno(nread) != .SUCCESS) return error.ReferenceSyscallRefused;
        if (nread == 0) break;
        var pos: usize = 0;
        while (pos < nread) {
            const dirent: *const LinuxDirent64 = @ptrCast(@alignCast(&buf[pos]));
            const name_ptr: [*:0]const u8 = @ptrCast(&dirent.name);
            const name = std.mem.sliceTo(name_ptr, 0);
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                try names.append(allocator, try allocator.dupe(u8, name));
            }
            pos += dirent.reclen;
        }
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    return names.toOwnedSlice(allocator);
}

pub fn triggerDatabase(allocator: std.mem.Allocator, root: []const u8) !TriggerMap {
    const root_fd = try reference_paths.openAbsolute(root, true);
    defer _ = linux.close(root_fd);

    const updates = try listDirectoryBeneath(allocator, root_fd, "var/lib/dpkg/updates");
    defer allocator.free(updates);
    if (updates.len != 0) return error.UnexpectedDpkgJournalEntries;

    const names = try listDirectoryBeneath(allocator, root_fd, "var/lib/dpkg/triggers");
    defer allocator.free(names);
    if (names.len > maximum_packages) return error.DpkgTriggersDirectoryExceedsLimit;

    var entries = TriggerMap.init(allocator);
    errdefer entries.deinit();
    for (names) |name| {
        const rel = try std.fmt.allocPrint(allocator, "var/lib/dpkg/triggers/{s}", .{name});
        defer allocator.free(rel);
        const content = try reference_paths.readRootFile(allocator, root, rel, maximum_control_bytes);
        defer allocator.free(content);
        if (std.mem.eql(u8, name, "Unincorp") and std.mem.trim(u8, content, " \t\r\n").len != 0) {
            return error.UnincorporatedDpkgTriggerState;
        }
        var digest: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(content, &digest, .{});
        try entries.put(name, .{
            .size = content.len,
            .sha512 = std.fmt.bytesToHex(digest, .lower),
        });
    }
    return entries;
}

pub const ParsedControlTar = struct {
    members: [][]const u8,
    files: std.StringHashMap([]const u8),
};

fn parseOctalField(field: []const u8) !usize {
    const trimmed = std.mem.trim(u8, field, " \t\x00");
    if (trimmed.len == 0) return 0;
    return std.fmt.parseInt(usize, trimmed, 8) catch error.MalformedControlTarHeader;
}

pub fn parseControlTarBytes(allocator: std.mem.Allocator, raw: []const u8) !ParsedControlTar {
    if (raw.len > maximum_control_bytes) return error.ControlTarTooLarge;
    var members = std.ArrayList([]const u8).empty;
    errdefer members.deinit(allocator);
    var files = std.StringHashMap([]const u8).init(allocator);
    errdefer files.deinit();

    var offset: usize = 0;
    while (offset < raw.len) {
        if (raw.len - offset < 512) return error.MalformedControlTarHeader;
        const header = raw[offset .. offset + 512];
        var all_zero = true;
        for (header) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) break;

        const name_slice = std.mem.sliceTo(header[0..100], 0);
        const prefix_slice = std.mem.sliceTo(header[345..500], 0);
        const raw_name = if (prefix_slice.len > 0)
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix_slice, name_slice })
        else
            try allocator.dupe(u8, name_slice);
        const member_name = if (std.mem.eql(u8, raw_name, "./"))
            try allocator.dupe(u8, ".")
        else
            try allocator.dupe(u8, std.mem.trimEnd(u8, raw_name, "/"));

        const size = try parseOctalField(header[124..136]);
        const typeflag = header[156];
        offset += 512;
        if (size > raw.len - offset or size > maximum_control_bytes) return error.TruncatedControlTarMember;
        const payload = raw[offset .. offset + size];
        const padded = std.mem.alignForward(usize, size, 512);
        if (padded > raw.len - offset) return error.TruncatedControlTarMember;
        offset += padded;

        try members.append(allocator, member_name);
        if (typeflag == '0' or typeflag == 0) {
            try files.put(member_name, try allocator.dupe(u8, payload));
        }
    }
    return .{
        .members = try members.toOwnedSlice(allocator),
        .files = files,
    };
}

fn sliceEqlStrings(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x, y)) return false;
    }
    return true;
}

pub const ControlTarFetcher = *const fn (allocator: std.mem.Allocator, archive: []const u8) anyerror![]const u8;

pub const DpkgRunResult = struct {
    returncode: u8,
    stdout: []const u8,
    stderr: []const u8,
};

pub const DpkgRunner = *const fn (
    allocator: std.mem.Allocator,
    verb: []const u8,
    packages: []const Package,
    profile: []const u8,
) anyerror!DpkgRunResult;

pub fn baseCyclePackages(
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    architecture: []const u8,
) ![base_cycle.len]Package {
    var out: [base_cycle.len]Package = undefined;
    for (base_cycle, 0..) |pin, idx| {
        const k: PackageKey = .{ .name = pin.name, .architecture = architecture };
        out[idx] = all_packages.get(k) orelse return error.MissingBaseCyclePackages;
    }
    return out;
}

pub fn verifyBaseCycle(
    allocator: std.mem.Allocator,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    statuses: *const DatabaseMap,
    architecture: []const u8,
    fetch_ctrl_tar: ControlTarFetcher,
) ![2]Package {
    if (!std.mem.eql(u8, architecture, "amd64")) return error.BaseCycleOrderRequiresAmd64;
    const pkgs = try baseCyclePackages(all_packages, architecture);
    for (pkgs, base_cycle) |pkg, expected| {
        if (!std.mem.eql(u8, pkg.architecture, expected.architecture) or
            !std.mem.eql(u8, pkg.version, expected.version) or
            pkg.declared_size != expected.size or
            !std.mem.eql(u8, pkg.digest, expected.sha512))
        {
            return error.BaseCyclePinMismatch;
        }
        try verifyArchive(pkg);
        const raw_tar = try fetch_ctrl_tar(allocator, pkg.archive);
        const parsed = try parseControlTarBytes(allocator, raw_tar);
        const control_bytes = parsed.files.get("./control") orelse return error.BaseCycleMissingControlMember;
        var fields = try controlFields(allocator, control_bytes);
        defer fields.deinit();
        if (!std.mem.eql(u8, fields.get("package") orelse "", pkg.name) or
            !std.mem.eql(u8, fields.get("version") orelse "", expected.version) or
            !std.mem.eql(u8, fields.get("architecture") orelse "", expected.architecture) or
            !std.mem.eql(u8, fields.get("depends") orelse "", expected.depends) or
            !std.mem.eql(u8, fields.get("pre-depends") orelse "", expected.pre_depends))
        {
            return error.BaseCycleControlFieldMismatch;
        }
        if (std.mem.eql(u8, pkg.name, "libgcc-s1")) {
            if (!sliceEqlStrings(parsed.members, expected.members)) return error.LibgccControlMembersMismatch;
            if (parsed.files.contains("./postinst")) return error.LibgccPostinstMustBeAbsent;
            const triggers = parsed.files.get("./triggers") orelse return error.LibgccTriggersContentMismatch;
            if (!std.mem.eql(u8, triggers, libgcc_triggers)) return error.LibgccTriggersContentMismatch;
        }
        const st = statuses.get(pkg.key()) orelse return error.BaseCycleStatusNotReady;
        if (!std.mem.eql(u8, st.version, expected.version) or !std.mem.eql(u8, st.status, expected.status)) {
            return error.BaseCycleStatusNotReady;
        }
    }
    return .{ pkgs[0], pkgs[1] };
}

fn verifyStatusTransition(
    before: *const DatabaseMap,
    after: *const DatabaseMap,
    allowed_keys: []const PackageKey,
) bool {
    if (before.count() != after.count()) return false;
    var it = before.iterator();
    while (it.next()) |entry| {
        const k = entry.key_ptr.*;
        var is_allowed = false;
        for (allowed_keys) |ak| {
            if (PackageKey.eql(k, ak)) {
                is_allowed = true;
                break;
            }
        }
        if (is_allowed) continue;
        const after_val = after.get(k) orelse return false;
        if (!std.mem.eql(u8, entry.value_ptr.version, after_val.version) or
            !std.mem.eql(u8, entry.value_ptr.status, after_val.status))
        {
            return false;
        }
    }
    return true;
}

fn verifyTriggerMapIdentical(before: *const TriggerMap, after: *const TriggerMap) bool {
    if (before.count() != after.count()) return false;
    var it = before.iterator();
    while (it.next()) |entry| {
        const after_val = after.get(entry.key_ptr.*) orelse return false;
        if (entry.value_ptr.size != after_val.size or
            !std.mem.eql(u8, &entry.value_ptr.sha512, &after_val.sha512))
        {
            return false;
        }
    }
    return true;
}

pub fn breakBaseCycle(
    allocator: std.mem.Allocator,
    root: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    architecture: []const u8,
    fetch_ctrl_tar: ControlTarFetcher,
    run_dpkg: DpkgRunner,
) !DpkgRunResult {
    var before = try currentStatuses(allocator, root);
    defer before.deinit();
    const pair = try verifyBaseCycle(allocator, all_packages, &before, architecture, fetch_ctrl_tar);
    const result = try run_dpkg(allocator, "break_base_cycle", &pair, "none");
    var after = try currentStatuses(allocator, root);
    defer after.deinit();
    const allowed = [_]PackageKey{ pair[0].key(), pair[1].key() };
    if (!verifyStatusTransition(&before, &after, &allowed)) {
        return error.BaseCycleMutatedUnexpectedPackageStatus;
    }
    for (pair) |pkg| {
        const expected = findBaseCyclePin(pkg.name).?;
        const current = after.get(pkg.key()) orelse return error.BaseCycleDidNotInstallPinnedPair;
        if (!std.mem.eql(u8, current.version, expected.version) or
            !std.mem.eql(u8, current.status, "install ok installed"))
        {
            return error.BaseCycleDidNotInstallPinnedPair;
        }
    }
    return result;
}

pub fn opensslCyclePackages(
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    architecture: []const u8,
) ![openssl_cycle.len]Package {
    var out: [openssl_cycle.len]Package = undefined;
    for (openssl_cycle, 0..) |pin, idx| {
        const k: PackageKey = .{ .name = pin.name, .architecture = architecture };
        out[idx] = all_packages.get(k) orelse return error.MissingOpensslCyclePackages;
    }
    return out;
}

pub fn verifyOpensslCycle(
    allocator: std.mem.Allocator,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    statuses: *const DatabaseMap,
    architecture: []const u8,
    fetch_ctrl_tar: ControlTarFetcher,
) ![2]Package {
    if (!std.mem.eql(u8, architecture, "amd64")) return error.OpensslCycleOrderRequiresAmd64;
    const pkgs = try opensslCyclePackages(all_packages, architecture);
    for (pkgs, openssl_cycle) |pkg, expected| {
        if (!std.mem.eql(u8, pkg.architecture, expected.architecture) or
            !std.mem.eql(u8, pkg.version, expected.version) or
            pkg.declared_size != expected.size or
            !std.mem.eql(u8, pkg.digest, expected.sha512))
        {
            return error.OpensslCyclePinMismatch;
        }
        try verifyArchive(pkg);
        const raw_tar = try fetch_ctrl_tar(allocator, pkg.archive);
        const parsed = try parseControlTarBytes(allocator, raw_tar);
        const control_bytes = parsed.files.get("./control") orelse return error.OpensslCycleMissingControlMember;
        var fields = try controlFields(allocator, control_bytes);
        defer fields.deinit();
        if (!std.mem.eql(u8, fields.get("package") orelse "", pkg.name) or
            !std.mem.eql(u8, fields.get("version") orelse "", expected.version) or
            !std.mem.eql(u8, fields.get("architecture") orelse "", expected.architecture) or
            !std.mem.eql(u8, fields.get("depends") orelse "", expected.depends) or
            !std.mem.eql(u8, fields.get("pre-depends") orelse "", expected.pre_depends))
        {
            return error.OpensslCycleControlFieldMismatch;
        }
        if (std.mem.eql(u8, pkg.name, "libssl3t64") or std.mem.eql(u8, pkg.name, "openssl-provider-legacy")) {
            if (parsed.files.contains("./postinst")) return error.OpensslCyclePostinstMustBeAbsent;
        }
        const st = statuses.get(pkg.key()) orelse return error.OpensslCycleStatusNotReady;
        if (!std.mem.eql(u8, st.version, expected.version) or !std.mem.eql(u8, st.status, expected.status)) {
            return error.OpensslCycleStatusNotReady;
        }
    }
    return .{ pkgs[0], pkgs[1] };
}

pub fn configureOpensslCycle(
    allocator: std.mem.Allocator,
    root: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    architecture: []const u8,
    fetch_ctrl_tar: ControlTarFetcher,
    run_dpkg: DpkgRunner,
) !DpkgRunResult {
    var before = try currentStatuses(allocator, root);
    defer before.deinit();
    var before_triggers = try triggerDatabase(allocator, root);
    defer before_triggers.deinit();
    const pair = try verifyOpensslCycle(allocator, all_packages, &before, architecture, fetch_ctrl_tar);
    const result = try run_dpkg(allocator, "configure_openssl_cycle", &pair, "none");
    var after = try currentStatuses(allocator, root);
    defer after.deinit();
    var after_triggers = try triggerDatabase(allocator, root);
    defer after_triggers.deinit();

    const allowed = [_]PackageKey{ pair[0].key(), pair[1].key() };
    if (!verifyStatusTransition(&before, &after, &allowed)) {
        return error.OpensslCycleMutatedUnexpectedPackageStatus;
    }
    if (before_triggers.count() != after_triggers.count()) {
        return error.OpensslCycleMutatedUnexpectedTriggerState;
    }
    var trig_it = before_triggers.iterator();
    while (trig_it.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "Lock")) continue;
        const after_val = after_triggers.get(entry.key_ptr.*) orelse return error.OpensslCycleMutatedUnexpectedTriggerState;
        if (entry.value_ptr.size != after_val.size or !std.mem.eql(u8, &entry.value_ptr.sha512, &after_val.sha512)) {
            return error.OpensslCycleMutatedUnexpectedTriggerState;
        }
    }
    for (pair) |pkg| {
        const expected = findOpensslCyclePin(pkg.name).?;
        const current = after.get(pkg.key()) orelse return error.OpensslCycleDidNotInstallPinnedPair;
        if (!std.mem.eql(u8, current.version, expected.version) or
            !std.mem.eql(u8, current.status, "install ok installed"))
        {
            return error.OpensslCycleDidNotInstallPinnedPair;
        }
    }
    return result;
}

pub fn kbdCyclePackages(
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
) ![kbd_cycle.len]Package {
    var out: [kbd_cycle.len]Package = undefined;
    for (kbd_cycle, 0..) |pin, idx| {
        const k: PackageKey = .{ .name = pin.name, .architecture = pin.architecture };
        out[idx] = all_packages.get(k) orelse return error.MissingKbdCyclePackages;
    }
    return out;
}

pub fn verifyKbdCycle(
    allocator: std.mem.Allocator,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    statuses: *const DatabaseMap,
    architecture: []const u8,
    fetch_ctrl_tar: ControlTarFetcher,
) !Package {
    if (!std.mem.eql(u8, architecture, "amd64")) return error.KbdCycleOrderRequiresAmd64;
    const pkgs = try kbdCyclePackages(all_packages);
    for (pkgs, kbd_cycle) |pkg, expected| {
        if (!std.mem.eql(u8, pkg.architecture, expected.architecture) or
            !std.mem.eql(u8, pkg.version, expected.version) or
            pkg.declared_size != expected.size or
            !std.mem.eql(u8, pkg.digest, expected.sha512))
        {
            return error.KbdCyclePinMismatch;
        }
        try verifyArchive(pkg);
        const raw_tar = try fetch_ctrl_tar(allocator, pkg.archive);
        const parsed = try parseControlTarBytes(allocator, raw_tar);
        if (!sliceEqlStrings(parsed.members, expected.members)) return error.KbdCycleControlMembersMismatch;
        const control_bytes = parsed.files.get("./control") orelse return error.KbdCycleControlMembersMismatch;
        var fields = try controlFields(allocator, control_bytes);
        defer fields.deinit();
        if (!std.mem.eql(u8, fields.get("package") orelse "", pkg.name) or
            !std.mem.eql(u8, fields.get("version") orelse "", expected.version) or
            !std.mem.eql(u8, fields.get("architecture") orelse "", expected.architecture) or
            !std.mem.eql(u8, fields.get("depends") orelse "", expected.depends) or
            !std.mem.eql(u8, fields.get("pre-depends") orelse "", expected.pre_depends))
        {
            return error.KbdCycleControlFieldMismatch;
        }
        if (std.mem.eql(u8, pkg.name, "kbd")) {
            if (parsed.files.contains("./postinst")) return error.KbdCyclePostinstMustBeAbsent;
            const triggers = parsed.files.get("./triggers") orelse return error.KbdCycleTriggersContentMismatch;
            if (!std.mem.eql(u8, triggers, kbd_triggers)) return error.KbdCycleTriggersContentMismatch;
        }
        const st_key = packageStatusKey(pkg, all_packages, statuses, architecture);
        const st = statuses.get(st_key) orelse return error.KbdCycleStatusNotReady;
        if (!std.mem.eql(u8, st.version, expected.version) or !std.mem.eql(u8, st.status, expected.status)) {
            return error.KbdCycleStatusNotReady;
        }
    }
    return pkgs[0];
}

pub fn breakKbdCycle(
    allocator: std.mem.Allocator,
    root: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    architecture: []const u8,
    fetch_ctrl_tar: ControlTarFetcher,
    run_dpkg: DpkgRunner,
) !DpkgRunResult {
    var before = try currentStatuses(allocator, root);
    defer before.deinit();
    var before_triggers = try triggerDatabase(allocator, root);
    defer before_triggers.deinit();
    const kbd_pkg = try verifyKbdCycle(allocator, all_packages, &before, architecture, fetch_ctrl_tar);
    const single = [_]Package{kbd_pkg};
    const result = try run_dpkg(allocator, "break_kbd_cycle", &single, "none");
    var after = try currentStatuses(allocator, root);
    defer after.deinit();
    var after_triggers = try triggerDatabase(allocator, root);
    defer after_triggers.deinit();

    const allowed = [_]PackageKey{kbd_pkg.key()};
    if (!verifyStatusTransition(&before, &after, &allowed)) {
        return error.KbdCycleMutatedUnexpectedPackageStatus;
    }
    if (!verifyTriggerMapIdentical(&before_triggers, &after_triggers)) {
        return error.KbdCycleMutatedUnexpectedTriggerState;
    }
    const expected = findKbdCyclePin("kbd").?;
    const current = after.get(kbd_pkg.key()) orelse return error.KbdCycleDidNotInstallKbd;
    if (!std.mem.eql(u8, current.version, expected.version) or
        !std.mem.eql(u8, current.status, "install ok installed"))
    {
        return error.KbdCycleDidNotInstallKbd;
    }
    return result;
}

pub fn triggerHandlerPackages(
    allocator: std.mem.Allocator,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    statuses: *const DatabaseMap,
    architecture: []const u8,
) ![]Package {
    var ready = std.ArrayList(Package).empty;
    errdefer ready.deinit(allocator);
    for (trigger_handlers) |pin| {
        const k: PackageKey = .{ .name = pin.name, .architecture = architecture };
        const pkg = all_packages.get(k) orelse return error.MissingTriggerHandlerPackage;
        if (statuses.get(pkg.key())) |st| {
            if (std.mem.eql(u8, st.status, "install ok triggers-pending")) {
                try ready.append(allocator, pkg);
            }
        }
    }
    return ready.toOwnedSlice(allocator);
}

fn verifyInstalledControlFile(
    allocator: std.mem.Allocator,
    root: []const u8,
    pkg: Package,
    kind: []const u8,
    expected_bytes: []const u8,
    expected_size: usize,
    expected_sha256: []const u8,
) !void {
    const candidates = [_][]const u8{
        try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}.{s}", .{ pkg.name, kind }),
        try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}:{s}.{s}", .{ pkg.name, pkg.architecture, kind }),
    };
    defer {
        allocator.free(candidates[0]);
        allocator.free(candidates[1]);
    }
    for (candidates) |rel| {
        const raw = reference_paths.readRootFile(allocator, root, rel, maximum_control_bytes) catch continue;
        defer allocator.free(raw);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        if (!std.mem.eql(u8, raw, expected_bytes) or
            raw.len != expected_size or
            !std.mem.eql(u8, &hex, expected_sha256))
        {
            return if (std.mem.eql(u8, kind, "postinst"))
                error.TriggerHandlerInstalledPostinstMismatch
            else
                error.TriggerHandlerInstalledTriggersMismatch;
        }
        return;
    }
    return if (std.mem.eql(u8, kind, "postinst"))
        error.TriggerHandlerInstalledPostinstMismatch
    else
        error.TriggerHandlerInstalledTriggersMismatch;
}

pub fn verifyTriggerHandlers(
    allocator: std.mem.Allocator,
    root: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    statuses: *const DatabaseMap,
    architecture: []const u8,
    fetch_ctrl_tar: ControlTarFetcher,
) ![]Package {
    if (!std.mem.eql(u8, architecture, "amd64")) return error.TriggerHandlerOrderRequiresAmd64;
    const pkgs = try triggerHandlerPackages(allocator, all_packages, statuses, architecture);
    if (pkgs.len == 0) return error.TriggerHandlerStatusNotReady;
    for (pkgs) |pkg| {
        const expected = findTriggerHandlerPin(pkg.name) orelse return error.TriggerHandlerPinMismatch;
        if (!std.mem.eql(u8, pkg.architecture, expected.architecture) or
            !std.mem.eql(u8, pkg.version, expected.version) or
            pkg.declared_size != expected.size or
            !std.mem.eql(u8, pkg.digest, expected.sha512))
        {
            return error.TriggerHandlerPinMismatch;
        }
        if (!std.mem.eql(u8, packageProfile(pkg.name), expected.profile)) {
            return error.TriggerHandlerProfileMismatch;
        }
        try verifyArchive(pkg);
        const raw_tar = try fetch_ctrl_tar(allocator, pkg.archive);
        const parsed = try parseControlTarBytes(allocator, raw_tar);
        if (!sliceEqlStrings(parsed.members, expected.members)) {
            return error.TriggerHandlerControlMembersMismatch;
        }
        const control_bytes = parsed.files.get("./control") orelse return error.TriggerHandlerControlMembersMismatch;
        var fields = try controlFields(allocator, control_bytes);
        defer fields.deinit();
        if (!std.mem.eql(u8, fields.get("package") orelse "", pkg.name) or
            !std.mem.eql(u8, fields.get("version") orelse "", expected.version) or
            !std.mem.eql(u8, fields.get("architecture") orelse "", expected.architecture))
        {
            return error.TriggerHandlerControlFieldMismatch;
        }
        const postinst = parsed.files.get("./postinst") orelse return error.TriggerHandlerPostinstMismatch;
        var postinst_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(postinst, &postinst_digest, .{});
        const postinst_hex = std.fmt.bytesToHex(postinst_digest, .lower);
        if (postinst.len != expected.postinst_size or !std.mem.eql(u8, &postinst_hex, expected.postinst_sha256)) {
            return error.TriggerHandlerPostinstMismatch;
        }
        const triggers = parsed.files.get("./triggers") orelse return error.TriggerHandlerTriggersMismatch;
        var triggers_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(triggers, &triggers_digest, .{});
        const triggers_hex = std.fmt.bytesToHex(triggers_digest, .lower);
        if (triggers.len != expected.triggers_size or !std.mem.eql(u8, &triggers_hex, expected.triggers_sha256)) {
            return error.TriggerHandlerTriggersMismatch;
        }
        try verifyInstalledControlFile(allocator, root, pkg, "postinst", postinst, expected.postinst_size, expected.postinst_sha256);
        try verifyInstalledControlFile(allocator, root, pkg, "triggers", triggers, expected.triggers_size, expected.triggers_sha256);

        const status_raw = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", maximum_control_bytes);
        defer allocator.free(status_raw);
        var found_stanza = false;
        var start: usize = 0;
        while (start <= status_raw.len) {
            const next_sep = std.mem.indexOfPos(u8, status_raw, start, "\n\n");
            const stanza_raw = if (next_sep) |idx| status_raw[start..idx] else status_raw[start..];
            const stanza = std.mem.trim(u8, stanza_raw, " \t\r\n");
            if (stanza.len > 0) {
                var st_fields = try databaseFields(allocator, stanza);
                defer st_fields.deinit();
                if (std.mem.eql(u8, st_fields.get("package") orelse "", pkg.name) and
                    std.mem.eql(u8, st_fields.get("architecture") orelse "", pkg.architecture))
                {
                    found_stanza = true;
                    if (!std.mem.eql(u8, st_fields.get("version") orelse "", expected.version) or
                        !std.mem.eql(u8, st_fields.get("status") orelse "", "install ok triggers-pending"))
                    {
                        return error.TriggerHandlerStatusNotReady;
                    }
                    const pending_raw = std.mem.trim(u8, st_fields.get("triggers-pending") orelse "", " \t\r\n");
                    if (!std.mem.eql(u8, pending_raw, expected.pending)) {
                        return error.TriggerHandlerPendingTriggerMissing;
                    }
                }
            }
            if (next_sep) |idx| {
                start = idx + 2;
            } else break;
        }
        if (!found_stanza) return error.TriggerHandlerStatusNotReady;
    }
    return pkgs;
}

pub fn processTriggers(
    allocator: std.mem.Allocator,
    root: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    architecture: []const u8,
    fetch_ctrl_tar: ControlTarFetcher,
    run_dpkg: DpkgRunner,
) !DpkgRunResult {
    var before = try currentStatuses(allocator, root);
    defer before.deinit();
    var before_triggers = try triggerDatabase(allocator, root);
    defer before_triggers.deinit();
    const pkgs = try verifyTriggerHandlers(allocator, root, all_packages, &before, architecture, fetch_ctrl_tar);
    const result = try run_dpkg(allocator, "triggers_only", pkgs, "none");
    var after = try currentStatuses(allocator, root);
    defer after.deinit();
    var after_triggers = try triggerDatabase(allocator, root);
    defer after_triggers.deinit();

    var allowed = try allocator.alloc(PackageKey, pkgs.len);
    defer allocator.free(allowed);
    for (pkgs, 0..) |pkg, i| allowed[i] = pkg.key();
    if (!verifyStatusTransition(&before, &after, allowed)) {
        return error.TriggerHandlerMutatedUnexpectedPackageStatus;
    }
    if (before_triggers.count() != after_triggers.count()) {
        return error.TriggerHandlerMutatedUnexpectedTriggerState;
    }
    var trig_it = before_triggers.iterator();
    while (trig_it.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "Lock")) continue;
        const after_val = after_triggers.get(entry.key_ptr.*) orelse return error.TriggerHandlerMutatedUnexpectedTriggerState;
        if (entry.value_ptr.size != after_val.size or !std.mem.eql(u8, &entry.value_ptr.sha512, &after_val.sha512)) {
            return error.TriggerHandlerMutatedUnexpectedTriggerState;
        }
    }
    for (pkgs) |pkg| {
        const expected = findTriggerHandlerPin(pkg.name).?;
        const current = after.get(pkg.key()) orelse return error.TriggerHandlerDidNotInstallHandlers;
        if (!std.mem.eql(u8, current.version, expected.version) or
            !std.mem.eql(u8, current.status, "install ok installed"))
        {
            return error.TriggerHandlerDidNotInstallHandlers;
        }
    }
    const status_raw = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", maximum_control_bytes);
    defer allocator.free(status_raw);
    var start: usize = 0;
    while (start <= status_raw.len) {
        const next_sep = std.mem.indexOfPos(u8, status_raw, start, "\n\n");
        const stanza_raw = if (next_sep) |idx| status_raw[start..idx] else status_raw[start..];
        const stanza = std.mem.trim(u8, stanza_raw, " \t\r\n");
        if (stanza.len > 0) {
            var st_fields = try databaseFields(allocator, stanza);
            defer st_fields.deinit();
            const pkg_name = st_fields.get("package") orelse "";
            const pkg_arch = st_fields.get("architecture") orelse "";
            for (pkgs) |pkg| {
                if (std.mem.eql(u8, pkg.name, pkg_name) and std.mem.eql(u8, pkg.architecture, pkg_arch)) {
                    if (st_fields.contains("triggers-pending")) return error.TriggerHandlerDidNotDrainPendingTrigger;
                }
            }
        }
        if (next_sep) |idx| {
            start = idx + 2;
        } else break;
    }
    return result;
}

pub fn stagePendingRuntime(
    allocator: std.mem.Allocator,
    root: []const u8,
    runtime: []const u8,
    pkg: Package,
) !void {
    const profile = packageProfile(pkg.name);
    if (std.mem.eql(u8, profile, "none")) return error.PrestateTargetRequiresPendingRuntimeProfile;
    if (!std.mem.startsWith(u8, root, "/") or !std.mem.startsWith(u8, runtime, "/")) {
        return error.PendingRuntimeRequiresCanonicalAbsolutePaths;
    }
    _ = try reference_paths.protected(runtime, false);

    var statuses = try currentStatuses(allocator, root);
    defer statuses.deinit();
    const current = statuses.get(pkg.key()) orelse return error.PendingRuntimeTargetNotUnpacked;
    if (!std.mem.eql(u8, current.version, pkg.version) or
        !std.mem.eql(u8, current.status, "install ok unpacked"))
    {
        return error.PendingRuntimeTargetNotUnpacked;
    }

    const candidates = [_][]const u8{
        try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}.postinst", .{pkg.name}),
        try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}:{s}.postinst", .{ pkg.name, pkg.architecture }),
    };
    defer {
        allocator.free(candidates[0]);
        allocator.free(candidates[1]);
    }
    var found_postinst = false;
    for (candidates) |rel| {
        const bytes = reference_paths.readRootFile(allocator, root, rel, maximum_control_bytes) catch continue;
        allocator.free(bytes);
        found_postinst = true;
        break;
    }
    if (!found_postinst) return error.PendingRuntimeTargetPostinstMissing;

    const status_path = try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/status", .{std.mem.trimEnd(u8, root, "/")});
    defer allocator.free(status_path);
    const status_raw = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", maximum_control_bytes);
    defer allocator.free(status_raw);

    var updated = std.ArrayList(u8).empty;
    defer updated.deinit(allocator);
    var changed = false;
    var start: usize = 0;
    var first_stanza = true;
    while (start <= status_raw.len) {
        const next_sep = std.mem.indexOfPos(u8, status_raw, start, "\n\n");
        const stanza_raw = if (next_sep) |idx| status_raw[start..idx] else status_raw[start..];
        const stanza = std.mem.trim(u8, stanza_raw, " \t\r\n");
        if (stanza.len > 0) {
            if (!first_stanza) try updated.appendSlice(allocator, "\n\n");
            first_stanza = false;
            var fields = try databaseFields(allocator, stanza);
            defer fields.deinit();
            if (std.mem.eql(u8, fields.get("package") orelse "", pkg.name) and
                std.mem.eql(u8, fields.get("architecture") orelse "", pkg.architecture))
            {
                var lines = std.mem.splitScalar(u8, stanza, '\n');
                var first_line = true;
                while (lines.next()) |line| {
                    if (!first_line) try updated.append(allocator, '\n');
                    first_line = false;
                    if (std.mem.eql(u8, line, "Status: install ok unpacked")) {
                        try updated.appendSlice(allocator, "Status: install ok half-configured");
                        changed = true;
                    } else {
                        try updated.appendSlice(allocator, line);
                    }
                }
            } else {
                try updated.appendSlice(allocator, stanza);
            }
        }
        if (next_sep) |idx| {
            start = idx + 2;
        } else break;
    }
    if (!changed) return error.PendingRuntimeTargetNotUnpacked;
    try updated.append(allocator, '\n');

    var dir = try std.Io.Dir.openDirAbsolute(std.Options.debug_io, root, .{});
    defer dir.close(std.Options.debug_io);
    try dir.writeFile(std.Options.debug_io, .{
        .sub_path = "var/lib/dpkg/status",
        .data = updated.items,
    });
}

pub fn parsePrestate(value: []const u8) !?PackageKey {
    if (std.mem.eql(u8, value, "none")) return null;
    const colon = std.mem.indexOfScalar(u8, value, ':') orelse return error.InvalidPrestateTargetFormat;
    const name = value[0..colon];
    const arch = value[colon + 1 ..];
    if (std.mem.indexOfScalar(u8, arch, ':') != null) return error.InvalidPrestateTargetFormat;
    if (!validPackageName(name) or !validPackageName(arch)) return error.InvalidPrestateTargetFormat;
    return .{ .name = name, .architecture = arch };
}

pub const ConfigureStepTag = enum {
    configure_package,
    continue_prestate,
    break_kbd_cycle,
    configure_openssl_cycle,
    break_base_cycle,
    triggers_only,
};

pub const ConfigureAction = struct {
    tag: ConfigureStepTag,
    package: ?Package = null,
};

/// Simulates or executes one configure pass over `packages` given `prestate_target`,
/// returning the ordered actions taken when probe_configure succeeds for the given predicate.
pub fn planConfigurePassForTest(
    allocator: std.mem.Allocator,
    packages: []const Package,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    statuses: *DatabaseMap,
    architecture: []const u8,
    prestate_target: ?PackageKey,
    stage_runtime_fn: *const fn (pkg: Package) anyerror!void,
) ![]ConfigureAction {
    var actions = std.ArrayList(ConfigureAction).empty;
    errdefer actions.deinit(allocator);

    if (prestate_target) |target| {
        const target_pkg = all_packages.get(target) orelse return error.PrestateTargetNotInManifest;
        if (std.mem.eql(u8, packageProfile(target_pkg.name), "none")) {
            return error.PrestateTargetRequiresPendingRuntimeProfile;
        }
    }

    var deferred_prestate: ?Package = null;
    for (packages) |pkg| {
        const st_key = packageStatusKey(pkg, all_packages, statuses, architecture);
        const st = statuses.get(st_key) orelse continue;
        if (!std.mem.eql(u8, st.status, "install ok unpacked")) continue;

        if (prestate_target) |target| {
            if (PackageKey.eql(pkg.key(), target)) {
                deferred_prestate = pkg;
                continue;
            }
        }
        try statuses.put(st_key, .{
            .name = st.name,
            .architecture = st.architecture,
            .version = st.version,
            .status = "install ok installed",
        });
        try actions.append(allocator, .{ .tag = .configure_package, .package = pkg });
    }

    if (deferred_prestate) |pkg| {
        if (std.mem.eql(u8, pkg.name, "sudo")) {
            const companion_key: PackageKey = .{
                .name = sudo_prestate_companion.name,
                .architecture = sudo_prestate_companion.architecture,
            };
            const companion = all_packages.get(companion_key) orelse return error.MissingSudoPrestateCompanion;
            if (!std.mem.eql(u8, companion.version, sudo_prestate_companion.version) or
                !std.mem.eql(u8, companion.architecture, architecture))
            {
                return error.MissingSudoPrestateCompanion;
            }
            const comp_st = statuses.get(companion_key) orelse return error.MissingSudoPrestateCompanion;
            if (!std.mem.eql(u8, comp_st.status, "install ok installed")) {
                return error.MissingSudoPrestateCompanion;
            }
        }
        try stage_runtime_fn(pkg);
        const st_key = packageStatusKey(pkg, all_packages, statuses, architecture);
        const st = statuses.get(st_key).?;
        try statuses.put(st_key, .{
            .name = st.name,
            .architecture = st.architecture,
            .version = st.version,
            .status = "install ok installed",
        });
        try actions.append(allocator, .{ .tag = .continue_prestate, .package = pkg });
    }

    return actions.toOwnedSlice(allocator);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    var dpkg: ?[]const u8 = null;
    var root: ?[]const u8 = null;
    var cache: ?[]const u8 = null;
    var evidence: ?[]const u8 = null;
    var prove_base_cycle = false;
    var launcher: ?[]const u8 = null;
    var runtime: ?[]const u8 = null;
    var architecture: []const u8 = "amd64";
    var report_only = false;
    var prestate_raw: []const u8 = "none";

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--prove-base-cycle")) {
            prove_base_cycle = true;
        } else if (std.mem.eql(u8, arg, "--report-only")) {
            report_only = true;
        } else if (std.mem.eql(u8, arg, "--dpkg")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            dpkg = args[i];
        } else if (std.mem.eql(u8, arg, "--root")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            root = args[i];
        } else if (std.mem.eql(u8, arg, "--cache")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            cache = args[i];
        } else if (std.mem.eql(u8, arg, "--evidence")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            evidence = args[i];
        } else if (std.mem.eql(u8, arg, "--launcher")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            launcher = args[i];
        } else if (std.mem.eql(u8, arg, "--runtime")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            runtime = args[i];
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            architecture = args[i];
        } else if (std.mem.eql(u8, arg, "--prestate")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            prestate_raw = args[i];
        } else {
            return error.InvalidCliArguments;
        }
    }

    const root_path = root orelse return error.InvalidCliArguments;
    const cache_path = cache orelse return error.InvalidCliArguments;
    const evidence_path = evidence orelse return error.InvalidCliArguments;
    _ = dpkg orelse return error.InvalidCliArguments;
    if (!report_only) {
        _ = launcher orelse return error.InvalidCliArguments;
        _ = runtime orelse return error.InvalidCliArguments;
    }
    _ = try parsePrestate(prestate_raw);
    if (prove_base_cycle and !std.mem.eql(u8, architecture, "amd64")) {
        return error.BaseCycleOrderRequiresAmd64;
    }

    _ = try reference_paths.protected(cache_path, true);
    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/packages.tsv", .{std.mem.trimEnd(u8, cache_path, "/")});
    _ = try reference_paths.protected(manifest_path, false);
    const packages = try packagesFromManifest(allocator, manifest_path, cache_path, maximum_packages);
    for (packages) |pkg| try verifyArchive(pkg);

    if (report_only) {
        var statuses = try currentStatuses(allocator, root_path);
        defer statuses.deinit();
        var triggers = try triggerDatabase(allocator, root_path);
        defer triggers.deinit();
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.print(
            "{{\"schema\":\"io.github.cataggar.debz.real-snapshot.dpkg-execution.v1\",\"package_count\":{d},\"status_package_count\":{d},\"trigger_file_count\":{d}}}\n",
            .{ packages.len, statuses.count(), triggers.count() },
        );
        const parent = std.fs.path.dirname(evidence_path) orelse "/";
        const base = std.fs.path.basename(evidence_path);
        var dir = try std.Io.Dir.openDirAbsolute(init.io, parent, .{});
        defer dir.close(init.io);
        try dir.writeFile(init.io, .{ .sub_path = base, .data = out.written() });
    }
}

const TarFixtureMember = struct {
    name: []const u8,
    content: ?[]const u8 = null,
};

fn buildTestControlTar(allocator: std.mem.Allocator, entries: []const TarFixtureMember) ![]u8 {
    var tar = std.ArrayList(u8).empty;
    errdefer tar.deinit(allocator);
    for (entries) |entry| {
        var header: [512]u8 = @splat(0);
        @memcpy(header[0..entry.name.len], entry.name);
        const content = entry.content orelse "";
        const is_dir = entry.content == null;
        writeOctalTest(header[100..108], if (is_dir) 0o755 else 0o644);
        writeOctalTest(header[108..116], 0);
        writeOctalTest(header[116..124], 0);
        writeOctalTest(header[124..136], content.len);
        writeOctalTest(header[136..148], 0);
        @memset(header[148..156], ' ');
        header[156] = if (is_dir) '5' else '0';
        @memcpy(header[257..263], "ustar\x00");
        @memcpy(header[263..265], "00");
        var checksum: u64 = 0;
        for (header) |b| checksum += b;
        writeOctalTest(header[148..156], checksum);
        try tar.appendSlice(allocator, &header);
        if (!is_dir and content.len > 0) {
            try tar.appendSlice(allocator, content);
            const pad = (512 - (content.len % 512)) % 512;
            try tar.appendNTimes(allocator, 0, pad);
        }
    }
    try tar.appendNTimes(allocator, 0, 1024);
    return tar.toOwnedSlice(allocator);
}

fn writeOctalTest(field: []u8, value: u64) void {
    @memset(field, '0');
    field[field.len - 1] = 0;
    var index = field.len - 1;
    var remaining = value;
    while (remaining != 0 and index != 0) {
        index -= 1;
        field[index] = @intCast('0' + remaining % 8);
        remaining /= 8;
    }
}

test "reference order manifest validation and archive verification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    reference_paths.setTestRootOverride(try std.fs.path.join(allocator, &.{ root, "untrusted" }));
    defer reference_paths.setTestRootOverride(null);

    const payload = "archive-bytes";
    var digest_bytes: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(payload, &digest_bytes, .{});
    const digest = std.fmt.bytesToHex(digest_bytes, .lower);
    const deb_name = try std.fmt.allocPrint(allocator, "{s}.deb", .{digest});
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = deb_name, .data = payload });

    const manifest_path = try std.fs.path.join(allocator, &.{ root, "packages.tsv" });
    const valid_row = try std.fmt.allocPrint(allocator, "bash\t5.3-1\tamd64\t{s}\t{d}\n", .{ digest, payload.len });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "packages.tsv", .data = valid_row });

    const pkgs = try packagesFromManifest(allocator, manifest_path, root, maximum_packages);
    try std.testing.expectEqual(@as(usize, 1), pkgs.len);
    try verifyArchive(pkgs[0]);

    // Duplicate package identity refused
    const dup_rows = try std.fmt.allocPrint(allocator, "{s}{s}", .{ valid_row, valid_row });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "packages.tsv", .data = dup_rows });
    try std.testing.expectError(
        error.DuplicateManifestPackageIdentity,
        packagesFromManifest(allocator, manifest_path, root, maximum_packages),
    );

    // Package limit exceeded refused
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "packages.tsv", .data = valid_row });
    try std.testing.expectError(
        error.PackageManifestLimitExceeded,
        packagesFromManifest(allocator, manifest_path, root, 0),
    );

    // Archive mutation during hashing refused
    const MutateHook = struct {
        fn fstatMutated(fd: i32) !linux.Statx {
            var st = try reference_paths.fstat(fd);
            st.ino += 1;
            return st;
        }
    };
    test_after_fstat_hook = MutateHook.fstatMutated;
    defer test_after_fstat_hook = null;
    try std.testing.expectError(error.PackageArchiveMutatedDuringHashing, verifyArchive(pkgs[0]));
}

test "reference order databasePackages and dpkgCommand validation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const valid_status =
        "Package: bash\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 5.3-1\n" ++
        "Conffiles:\n" ++
        " /etc/bash.bashrc d41d8cd98f00b204e9800998ecf8427e\n" ++
        "Description: GNU Bourne Again SHell\n" ++
        " Status: ignored continuation text\n\n" ++
        "Package: base-files\n" ++
        "Status: install ok installed\n" ++
        "Architecture: amd64\n" ++
        "Version: 14ubuntu1\n";
    var parsed = try databasePackages(allocator, valid_status);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.count());
    try std.testing.expectEqualStrings(
        "install ok unpacked",
        parsed.get(.{ .name = "bash", .architecture = "amd64" }).?.status,
    );

    const invalid_cases = [_][]const u8{
        "Package: bash\nStatus: install ok installed\nArchitecture: amd64\n",
        "Package: bash\nStatus: install ok installed\nStatus: install ok unpacked\nArchitecture: amd64\nVersion: 1\n",
        "Package: bash\nStatus: install ok installed\n invalid-continuation\nArchitecture: amd64\nVersion: 1\n",
        "Package: bash\nStatus:install ok installed\nArchitecture: amd64\nVersion: 1\n",
        "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\nPackage: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n",
    };
    for (invalid_cases) |bad| {
        try std.testing.expectError(
            if (std.mem.indexOf(u8, bad, "Version:") == null)
                error.IncompleteDpkgStatusStanza
            else if (std.mem.indexOf(u8, bad, "Status: install ok unpacked") != null)
                error.DuplicateControlField
            else if (std.mem.indexOf(u8, bad, " invalid-continuation") != null)
                error.ControlContinuationDisallowed
            else if (std.mem.indexOf(u8, bad, "Status:install") != null)
                error.MissingSpaceAfterControlFieldSeparator
            else
                error.DuplicateDpkgStatusPackage,
            databasePackages(allocator, bad),
        );
    }

    const systemd_pkg: Package = .{
        .name = "systemd",
        .version = profile_versions[0].version,
        .architecture = "amd64",
        .digest = &@as([128]u8, @splat('a')),
        .declared_size = 1,
        .archive = "/cache/a.deb",
    };
    const unpack_cmd = try dpkgCommand(allocator, "/usr/bin/dpkg", "/root", "unpack", &.{systemd_pkg}, "amd64", "systemd");
    try std.testing.expectEqualStrings("--unpack", unpack_cmd[unpack_cmd.len - 2]);
    const cont_cmd = try dpkgCommand(allocator, "/usr/bin/dpkg", "/root", "continue_prestate", &.{systemd_pkg}, "amd64", "systemd");
    try std.testing.expectEqualStrings("--configure", cont_cmd[cont_cmd.len - 2]);
    try std.testing.expectEqualStrings("systemd:amd64", cont_cmd[cont_cmd.len - 1]);

    try std.testing.expectError(
        error.RuntimeProfileSelectionMismatch,
        dpkgCommand(allocator, "/usr/bin/dpkg", "/root", "configure", &.{systemd_pkg}, "amd64", "none"),
    );

    const wrong_ver_systemd: Package = .{
        .name = "systemd",
        .version = "0",
        .architecture = "amd64",
        .digest = &@as([128]u8, @splat('a')),
        .declared_size = 1,
        .archive = "/cache/a.deb",
    };
    try std.testing.expectError(
        error.RuntimeProfileVersionMismatch,
        dpkgCommand(allocator, "/usr/bin/dpkg", "/root", "configure", &.{wrong_ver_systemd}, "amd64", "systemd"),
    );

    const kbd_pin = kbd_cycle[0];
    const kbd_pkg: Package = .{
        .name = "kbd",
        .version = kbd_pin.version,
        .architecture = kbd_pin.architecture,
        .digest = kbd_pin.sha512,
        .declared_size = kbd_pin.size,
        .archive = "/cache/kbd.deb",
    };
    const kbd_cmd = try dpkgCommand(allocator, "/usr/bin/dpkg", "/root", "break_kbd_cycle", &.{kbd_pkg}, "amd64", "none");
    try std.testing.expectEqualStrings("--force-depends=console-setup", kbd_cmd[kbd_cmd.len - 3]);
    try std.testing.expectEqualStrings("--configure", kbd_cmd[kbd_cmd.len - 2]);
    try std.testing.expectEqualStrings("kbd:amd64", kbd_cmd[kbd_cmd.len - 1]);

    const libc6_pin = base_cycle[0];
    const libgcc_pin = base_cycle[1];
    const libc6_pkg: Package = .{
        .name = "libc6",
        .version = libc6_pin.version,
        .architecture = libc6_pin.architecture,
        .digest = libc6_pin.sha512,
        .declared_size = libc6_pin.size,
        .archive = "/cache/libc6.deb",
    };
    const libgcc_pkg: Package = .{
        .name = "libgcc-s1",
        .version = libgcc_pin.version,
        .architecture = libgcc_pin.architecture,
        .digest = libgcc_pin.sha512,
        .declared_size = libgcc_pin.size,
        .archive = "/cache/libgcc.deb",
    };
    const base_cmd = try dpkgCommand(
        allocator,
        "/usr/bin/dpkg",
        "/root",
        "break_base_cycle",
        &.{ libc6_pkg, libgcc_pkg },
        "amd64",
        "none",
    );
    try std.testing.expectEqualStrings("--force-depends=libc6,libgcc-s1", base_cmd[base_cmd.len - 4]);
    try std.testing.expectEqualStrings("libc6:amd64", base_cmd[base_cmd.len - 2]);
    try std.testing.expectEqualStrings("libgcc-s1:amd64", base_cmd[base_cmd.len - 1]);

    const libssl_pin = openssl_cycle[0];
    const legacy_pin = openssl_cycle[1];
    const libssl_pkg: Package = .{
        .name = "libssl3t64",
        .version = libssl_pin.version,
        .architecture = libssl_pin.architecture,
        .digest = libssl_pin.sha512,
        .declared_size = libssl_pin.size,
        .archive = "/cache/libssl.deb",
    };
    const legacy_pkg: Package = .{
        .name = "openssl-provider-legacy",
        .version = legacy_pin.version,
        .architecture = legacy_pin.architecture,
        .digest = legacy_pin.sha512,
        .declared_size = legacy_pin.size,
        .archive = "/cache/legacy.deb",
    };
    const openssl_cmd = try dpkgCommand(
        allocator,
        "/usr/bin/dpkg",
        "/root",
        "configure_openssl_cycle",
        &.{ libssl_pkg, legacy_pkg },
        "amd64",
        "none",
    );
    try std.testing.expectEqualStrings("--configure", openssl_cmd[openssl_cmd.len - 3]);
    try std.testing.expectEqualStrings("libssl3t64:amd64", openssl_cmd[openssl_cmd.len - 2]);
    try std.testing.expectEqualStrings("openssl-provider-legacy:amd64", openssl_cmd[openssl_cmd.len - 1]);

    const libc_bin_pin = trigger_handlers[0];
    const procps_pin = trigger_handlers[1];
    const libc_bin_pkg: Package = .{
        .name = "libc-bin",
        .version = libc_bin_pin.version,
        .architecture = libc_bin_pin.architecture,
        .digest = libc_bin_pin.sha512,
        .declared_size = libc_bin_pin.size,
        .archive = "/cache/libc-bin.deb",
    };
    const procps_pkg: Package = .{
        .name = "procps",
        .version = procps_pin.version,
        .architecture = procps_pin.architecture,
        .digest = procps_pin.sha512,
        .declared_size = procps_pin.size,
        .archive = "/cache/procps.deb",
    };
    const trig_cmd = try dpkgCommand(
        allocator,
        "/usr/bin/dpkg",
        "/root",
        "triggers_only",
        &.{ libc_bin_pkg, procps_pkg },
        "amd64",
        "none",
    );
    try std.testing.expectEqualStrings("--triggers-only", trig_cmd[trig_cmd.len - 3]);
    try std.testing.expectEqualStrings("libc-bin:amd64", trig_cmd[trig_cmd.len - 2]);
    try std.testing.expectEqualStrings("procps:amd64", trig_cmd[trig_cmd.len - 1]);
}

test "reference order pending runtime staging and prestate ordering" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    reference_paths.setTestRootOverride(try std.fs.path.join(allocator, &.{ root, "untrusted" }));
    defer reference_paths.setTestRootOverride(null);

    try tmp.dir.createDirPath(std.testing.io, "root/var/lib/dpkg/info");
    const runtime_path = try std.fs.path.join(allocator, &.{ root, "runtime" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "runtime", .data = "#!/bin/sh\nexit 0\n" });

    const sudo_ver = profile_versions[2].version;
    const initial_status = try std.fmt.allocPrint(
        allocator,
        "Package: sudo\nStatus: install ok unpacked\nArchitecture: amd64\nVersion: {s}\n\n" ++
            "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.3-1\n",
        .{sudo_ver},
    );
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/status", .data = initial_status });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/info/sudo.postinst", .data = "#!/bin/sh\nexit 0\n" });

    const sudo_pkg: Package = .{
        .name = "sudo",
        .version = sudo_ver,
        .architecture = "amd64",
        .digest = &@as([128]u8, @splat('a')),
        .declared_size = 1,
        .archive = "/cache/sudo.deb",
    };
    const root_dir = try std.fs.path.join(allocator, &.{ root, "root" });
    try stagePendingRuntime(allocator, root_dir, runtime_path, sudo_pkg);

    var after_stage = try currentStatuses(allocator, root_dir);
    defer after_stage.deinit();
    try std.testing.expectEqualStrings(
        "install ok half-configured",
        after_stage.get(.{ .name = "sudo", .architecture = "amd64" }).?.status,
    );

    // Prestate ordering defers target package until after non-target packages and requires sudo-rs before sudo
    const sudo_rs_pkg: Package = .{
        .name = sudo_prestate_companion.name,
        .version = sudo_prestate_companion.version,
        .architecture = sudo_prestate_companion.architecture,
        .digest = &@as([128]u8, @splat('b')),
        .declared_size = 1,
        .archive = "/cache/sudo-rs.deb",
    };
    var all_pkgs = std.HashMap(PackageKey, Package, PackageKeyContext, 80).init(allocator);
    try all_pkgs.put(sudo_pkg.key(), sudo_pkg);
    try all_pkgs.put(sudo_rs_pkg.key(), sudo_rs_pkg);

    var sim_statuses = DatabaseMap.init(allocator);
    try sim_statuses.put(sudo_pkg.key(), .{
        .name = "sudo",
        .architecture = "amd64",
        .version = sudo_ver,
        .status = "install ok unpacked",
    });
    try sim_statuses.put(sudo_rs_pkg.key(), .{
        .name = sudo_rs_pkg.name,
        .architecture = sudo_rs_pkg.architecture,
        .version = sudo_rs_pkg.version,
        .status = "install ok unpacked",
    });

    const NoopStage = struct {
        fn stage(_: Package) !void {}
    };
    const actions = try planConfigurePassForTest(
        allocator,
        &.{ sudo_pkg, sudo_rs_pkg },
        &all_pkgs,
        &sim_statuses,
        "amd64",
        try parsePrestate("sudo:amd64"),
        NoopStage.stage,
    );
    try std.testing.expectEqual(@as(usize, 2), actions.len);
    try std.testing.expectEqual(ConfigureStepTag.configure_package, actions[0].tag);
    try std.testing.expectEqualStrings("sudo-rs", actions[0].package.?.name);
    try std.testing.expectEqual(ConfigureStepTag.continue_prestate, actions[1].tag);
    try std.testing.expectEqualStrings("sudo", actions[1].package.?.name);
}

test "reference order base openssl kbd and trigger handler verification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    reference_paths.setTestRootOverride(try std.fs.path.join(allocator, &.{ root, "untrusted" }));
    defer reference_paths.setTestRootOverride(null);

    try tmp.dir.createDirPath(std.testing.io, "root/var/lib/dpkg/info");
    try tmp.dir.createDirPath(std.testing.io, "root/var/lib/dpkg/updates");
    try tmp.dir.createDirPath(std.testing.io, "root/var/lib/dpkg/triggers");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/File", .data = "/usr/lib/sysctl.d procps:amd64\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/Lock", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/Unincorp", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/ldconfig", .data = "libc-bin:amd64\n" });

    const root_dir = try std.fs.path.join(allocator, &.{ root, "root" });
    var triggers = try triggerDatabase(allocator, root_dir);
    defer triggers.deinit();
    try std.testing.expectEqual(@as(usize, 4), triggers.count());

    // Non-empty Unincorp is refused
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/Unincorp", .data = "pending\n" });
    try std.testing.expectError(error.UnincorporatedDpkgTriggerState, triggerDatabase(allocator, root_dir));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/Unincorp", .data = "" });

    // Non-empty updates journal is refused
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/updates/0000", .data = "journal\n" });
    try std.testing.expectError(error.UnexpectedDpkgJournalEntries, triggerDatabase(allocator, root_dir));
    try tmp.dir.deleteFile(std.testing.io, "root/var/lib/dpkg/updates/0000");

    const NoopArchive = struct {
        fn verify(_: Package) !void {}
    };
    test_verify_archive_hook = NoopArchive.verify;
    defer test_verify_archive_hook = null;

    var all_pkgs = std.HashMap(PackageKey, Package, PackageKeyContext, 80).init(allocator);
    for (base_cycle) |pin| {
        const pkg: Package = .{
            .name = pin.name,
            .version = pin.version,
            .architecture = pin.architecture,
            .digest = pin.sha512,
            .declared_size = pin.size,
            .archive = try std.fmt.allocPrint(allocator, "/cache/{s}.deb", .{pin.name}),
        };
        try all_pkgs.put(pkg.key(), pkg);
    }
    for (openssl_cycle) |pin| {
        const pkg: Package = .{
            .name = pin.name,
            .version = pin.version,
            .architecture = pin.architecture,
            .digest = pin.sha512,
            .declared_size = pin.size,
            .archive = try std.fmt.allocPrint(allocator, "/cache/{s}.deb", .{pin.name}),
        };
        try all_pkgs.put(pkg.key(), pkg);
    }
    for (kbd_cycle) |pin| {
        const pkg: Package = .{
            .name = pin.name,
            .version = pin.version,
            .architecture = pin.architecture,
            .digest = pin.sha512,
            .declared_size = pin.size,
            .archive = try std.fmt.allocPrint(allocator, "/cache/{s}.deb", .{pin.name}),
        };
        try all_pkgs.put(pkg.key(), pkg);
    }

    const FetchTar = struct {
        fn fetch(alloc: std.mem.Allocator, archive: []const u8) ![]const u8 {
            const base_name = std.fs.path.stem(archive);
            if (findBaseCyclePin(base_name)) |pin| {
                if (std.mem.eql(u8, base_name, "libgcc-s1")) {
                    const ctrl = try std.fmt.allocPrint(
                        alloc,
                        "Package: {s}\nVersion: {s}\nArchitecture: {s}\nDepends: {s}\n",
                        .{ pin.name, pin.version, pin.architecture, pin.depends },
                    );
                    return buildTestControlTar(alloc, &.{
                        .{ .name = ".", .content = null },
                        .{ .name = "./control", .content = ctrl },
                        .{ .name = "./md5sums", .content = "" },
                        .{ .name = "./shlibs", .content = "" },
                        .{ .name = "./symbols", .content = "" },
                        .{ .name = "./triggers", .content = libgcc_triggers },
                    });
                }
            }
            if (findKbdCyclePin(base_name)) |pin| {
                const ctrl = if (pin.pre_depends.len > 0)
                    try std.fmt.allocPrint(
                        alloc,
                        "Package: {s}\nVersion: {s}\nArchitecture: {s}\nDepends: {s}\nPre-Depends: {s}\n",
                        .{ pin.name, pin.version, pin.architecture, pin.depends, pin.pre_depends },
                    )
                else
                    try std.fmt.allocPrint(
                        alloc,
                        "Package: {s}\nVersion: {s}\nArchitecture: {s}\nDepends: {s}\n",
                        .{ pin.name, pin.version, pin.architecture, pin.depends },
                    );
                var entries = std.ArrayList(TarFixtureMember).empty;
                for (pin.members) |m| {
                    if (std.mem.eql(u8, m, ".")) {
                        try entries.append(alloc, .{ .name = ".", .content = null });
                    } else if (std.mem.eql(u8, m, "./control")) {
                        try entries.append(alloc, .{ .name = "./control", .content = ctrl });
                    } else if (std.mem.eql(u8, m, "./triggers") and std.mem.eql(u8, base_name, "kbd")) {
                        try entries.append(alloc, .{ .name = "./triggers", .content = kbd_triggers });
                    } else {
                        try entries.append(alloc, .{ .name = m, .content = "#!/bin/sh\n" });
                    }
                }
                return buildTestControlTar(alloc, entries.items);
            }
            if (findOpensslCyclePin(base_name)) |pin| {
                const ctrl = if (pin.depends.len > 0)
                    try std.fmt.allocPrint(
                        alloc,
                        "Package: {s}\nVersion: {s}\nArchitecture: {s}\nDepends: {s}\n",
                        .{ pin.name, pin.version, pin.architecture, pin.depends },
                    )
                else
                    try std.fmt.allocPrint(
                        alloc,
                        "Package: {s}\nVersion: {s}\nArchitecture: {s}\n",
                        .{ pin.name, pin.version, pin.architecture },
                    );
                return buildTestControlTar(alloc, &.{
                    .{ .name = ".", .content = null },
                    .{ .name = "./control", .content = ctrl },
                });
            }
            if (findBaseCyclePin(base_name)) |pin| {
                const ctrl = try std.fmt.allocPrint(
                    alloc,
                    "Package: {s}\nVersion: {s}\nArchitecture: {s}\n",
                    .{ pin.name, pin.version, pin.architecture },
                );
                return buildTestControlTar(alloc, &.{
                    .{ .name = ".", .content = null },
                    .{ .name = "./control", .content = ctrl },
                });
            }
            return error.MissingControlTarFixture;
        }
    };

    var base_statuses = DatabaseMap.init(allocator);
    for (base_cycle) |pin| {
        try base_statuses.put(.{ .name = pin.name, .architecture = pin.architecture }, .{
            .name = pin.name,
            .architecture = pin.architecture,
            .version = pin.version,
            .status = pin.status,
        });
    }
    const base_pair = try verifyBaseCycle(allocator, &all_pkgs, &base_statuses, "amd64", FetchTar.fetch);
    try std.testing.expectEqualStrings("libc6", base_pair[0].name);
    try std.testing.expectEqualStrings("libgcc-s1", base_pair[1].name);

    var openssl_statuses = DatabaseMap.init(allocator);
    for (openssl_cycle) |pin| {
        try openssl_statuses.put(.{ .name = pin.name, .architecture = pin.architecture }, .{
            .name = pin.name,
            .architecture = pin.architecture,
            .version = pin.version,
            .status = pin.status,
        });
    }
    const openssl_pair = try verifyOpensslCycle(allocator, &all_pkgs, &openssl_statuses, "amd64", FetchTar.fetch);
    try std.testing.expectEqualStrings("libssl3t64", openssl_pair[0].name);
    try std.testing.expectEqualStrings("openssl-provider-legacy", openssl_pair[1].name);

    var kbd_statuses = DatabaseMap.init(allocator);
    for (kbd_cycle) |pin| {
        try kbd_statuses.put(.{ .name = pin.name, .architecture = pin.architecture }, .{
            .name = pin.name,
            .architecture = pin.architecture,
            .version = pin.version,
            .status = pin.status,
        });
    }
    const kbd_verified = try verifyKbdCycle(allocator, &all_pkgs, &kbd_statuses, "amd64", FetchTar.fetch);
    try std.testing.expectEqualStrings("kbd", kbd_verified.name);
}

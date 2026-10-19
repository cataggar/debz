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

pub const debian_systemd_profile_version: ProfileVersionPin = .{
    .name = "systemd",
    .version = "257.13-1~deb13u1",
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
pub const debian_libgcc_triggers = "# Triggers added by dh_makeshlibs/13.24.1\nactivate-noawait ldconfig\n";
pub const debian_openssl_triggers = "# Triggers added by dh_makeshlibs/13.24.2\nactivate-noawait ldconfig\n";

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

pub const debian_base_cycle = [_]CyclePackagePin{
    .{
        .name = "libc6",
        .version = "2.41-12+deb13u4",
        .architecture = "amd64",
        .size = 2846580,
        .sha512 = "0ab52592ed75cd5731f9b065ff4ea9109d58ce4f80cfc044d3209219e88a79c904baacc8f48d49cb440376b172ef82e5875ae15d7de7336e9d93e7c3bc2f61e5",
        .depends = "libgcc-s1",
        .status = "install ok unpacked",
    },
    .{
        .name = "libgcc-s1",
        .version = "14.2.0-19",
        .architecture = "amd64",
        .size = 72772,
        .sha512 = "a772ead03f938d76c09b3efba8c77652262be015cf44a8cb881183769c5ab19138afb95125d4b9563ec682d15163df1d3d9317563cd7ac3633178f5ae81185e9",
        .depends = "gcc-14-base (= 14.2.0-19), libc6 (>= 2.35)",
        .status = "install ok unpacked",
        .members = &.{ ".", "./control", "./md5sums", "./shlibs", "./symbols", "./triggers" },
    },
    .{
        .name = "gcc-14-base",
        .version = "14.2.0-19",
        .architecture = "amd64",
        .size = 49432,
        .sha512 = "372defee254080b998da134bfe02ca1b8122ac28247776f7d2f3c36f1c18b2739232b6363c74d17217558e5c4326887ac2270fd642240a14eb391fd67ec532fe",
        .depends = "",
        .status = "install ok installed",
    },
};

pub const base_cycle_profile = "libgcc_cycle";
pub const openssl_cycle_profile = "openssl_cycle";
pub const kbd_cycle_profile = "kbd_cycle";
pub const maintainer_scripts = [_][]const u8{ "preinst", "postinst", "prerm", "postrm", "config" };

pub const openssl_cycle = [_]CyclePackagePin{
    .{
        .name = "libssl3t64",
        .version = "3.5.5-1ubuntu3.6",
        .architecture = "amd64",
        .size = 2364586,
        .sha512 = "10df2f82619faff2ed4b890812313c35cd58abbfce858caf3403e1b654fac857bd7bc28e7a528a79a18ebfbfbdca5cffb3c2dd5b340c729fb7eb2470b76d528d",
        .depends = "libc6 (>= 2.38), libzstd1 (>= 1.5.5), zlib1g (>= 1:1.1.4), openssl-provider-legacy",
        .status = "install ok unpacked",
        .members = &.{ ".", "./control", "./md5sums", "./shlibs", "./symbols", "./triggers" },
    },
    .{
        .name = "openssl-provider-legacy",
        .version = "3.5.5-1ubuntu3.6",
        .architecture = "amd64",
        .size = 39690,
        .sha512 = "cbb4f55a609576d99a1b52952a674e78b2cbb7026e54c765cfd964812b65bdcdea4f5ea67961159b737fcba3093b3b15de8b7a6aff3bbf08a85805a09290c470",
        .depends = "libc6 (>= 2.14), libssl3t64 (>= 3.0.3)",
        .status = "install ok unpacked",
        .members = &.{ ".", "./control", "./md5sums" },
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

pub const debian_openssl_cycle = [_]CyclePackagePin{
    .{
        .name = "libssl3t64",
        .version = "3.5.7-1~deb13u2",
        .architecture = "amd64",
        .size = 2453872,
        .sha512 = "b9451913054c60ebc1273439b944c95d441930a71aefb385033764541f70bb8238d637e595019793c759c923693675741267863b8f7a5d934a8e1b8a77780b26",
        .depends = "libc6 (>= 2.38), libzstd1 (>= 1.5.5), zlib1g (>= 1:1.1.4), openssl-provider-legacy",
        .status = "install ok unpacked",
        .members = &.{ ".", "./control", "./md5sums", "./shlibs", "./symbols", "./triggers" },
    },
    .{
        .name = "openssl-provider-legacy",
        .version = "3.5.7-1~deb13u2",
        .architecture = "amd64",
        .size = 316132,
        .sha512 = "808addd039e469876a893944288c3e7dfd39005943f2a1b955e40f558a97a268e901c724dd39774d9acc030880996c0d11932867a19f4d73defd0b0d1126ab68",
        .depends = "libc6 (>= 2.14), libssl3t64 (>= 3.0.3)",
        .status = "install ok unpacked",
        .members = &.{ ".", "./conffiles", "./control", "./md5sums" },
    },
    .{
        .name = "libc6",
        .version = "2.41-12+deb13u4",
        .architecture = "amd64",
        .size = 2846580,
        .sha512 = "0ab52592ed75cd5731f9b065ff4ea9109d58ce4f80cfc044d3209219e88a79c904baacc8f48d49cb440376b172ef82e5875ae15d7de7336e9d93e7c3bc2f61e5",
        .depends = "libgcc-s1",
        .status = "install ok installed",
    },
    .{
        .name = "libzstd1",
        .version = "1.5.7+dfsg-1",
        .architecture = "amd64",
        .size = 303836,
        .sha512 = "1f211445c1aa3a8e9dad19369bfcc3959a50720e386f53b49104a8fe9ff3aaa3a7ee44cce84f426178819f009e368ff0dff44fd79ef7f645a88449c8400a0d88",
        .depends = "libc6 (>= 2.34)",
        .status = "install ok installed",
    },
    .{
        .name = "zlib1g",
        .version = "1:1.3.dfsg+really1.3.1-1+b1",
        .architecture = "amd64",
        .size = 88892,
        .sha512 = "99707ae371d970a774a7e0fffcceb48ad7ae611ff8513488f8fab809a4eb69a3d9df734d1a211f7b6e9104ada25a75f9a86fcf137000001006ce64bf0d38057d",
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
        .size = 700954,
        .sha512 = "350969573c25805e77d2ab180ebb445da1be72266f9aa5a162c2c38ec52f6935a58d7810d5795ba5fad415f5fa12fefe9194ff7e0534e292d1f63a56811e420f",
        .profile = "none",
        .pending = "ldconfig",
        .members = &.{ ".", "./conffiles", "./control", "./md5sums", "./postinst", "./triggers" },
        .postinst_size = 847,
        .postinst_sha256 = "3daa7e3ffd429c1d77287f0fc840a490a607697906d2303452f70578647ce0d4",
        .triggers_size = 440,
        .triggers_sha256 = "c3d6b5df131336e54c31dc5687929467de7abea5c5798e3d6a6b2a64ef971fd4",
    },
    .{
        .name = "procps",
        .version = "2:4.0.4-9ubuntu1",
        .architecture = "amd64",
        .size = 710224,
        .sha512 = "09fc456161f965166a3c87dc6bc021cee539ac3729026250b161f24f552eb0a49bdd1029e3dfa13c18bec444a3a0bd1ce2dbb230a4a97e5c0ade92f1e3223542",
        .profile = "none",
        .pending = "/usr/lib/sysctl.d",
        .members = &.{ ".", "./conffiles", "./control", "./md5sums", "./postinst", "./postrm", "./preinst", "./prerm", "./triggers" },
        .postinst_size = 2757,
        .postinst_sha256 = "3dbc0b33e45028e59dca33a1f29e41cba3aebe369b6d67a2e26c40ef8ce383b8",
        .triggers_size = 35,
        .triggers_sha256 = "f07479758daa6be9525681d6bd884cb935bbacc9b6b0e3669b33bb7e83b8ca79",
    },
};

pub const debian_libc_bin_trigger_handler: TriggerHandlerPin = .{
    .name = "libc-bin",
    .version = "2.41-12+deb13u4",
    .architecture = "amd64",
    .size = 638452,
    .sha512 = "dd9704fa1935280a1a5418658c75cc45c8c646f9020229e72addde5bc9744ce75f46daeecc7a46c256cf2c4f08bc50bebbbd87e04848b55787f4ec304cfd41bc",
    .profile = "none",
    .pending = "ldconfig",
    .members = &.{ ".", "./conffiles", "./control", "./md5sums", "./postinst", "./triggers" },
    .postinst_size = 847,
    .postinst_sha256 = "3daa7e3ffd429c1d77287f0fc840a490a607697906d2303452f70578647ce0d4",
    .triggers_size = 440,
    .triggers_sha256 = "c3d6b5df131336e54c31dc5687929467de7abea5c5798e3d6a6b2a64ef971fd4",
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

    pub fn selector(self: Package, allocator: std.mem.Allocator) ![]u8 {
        return if (std.mem.eql(u8, self.architecture, "all"))
            allocator.dupe(u8, self.name)
        else
            std.fmt.allocPrint(allocator, "{s}:{s}", .{ self.name, self.architecture });
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
    if (std.mem.eql(u8, name, "systemd")) return "systemd";
    if (std.mem.eql(u8, name, "udev")) return "udev";
    if (std.mem.eql(u8, name, "sudo")) return "sudo";
    return "none";
}

pub fn profilePinnedVersion(name: []const u8) ?[]const u8 {
    inline for (profile_versions) |pin| {
        if (std.mem.eql(u8, name, pin.name)) return pin.version;
    }
    return null;
}

pub fn profileVersionMatches(name: []const u8, version: []const u8) bool {
    const pinned = profilePinnedVersion(name) orelse return false;
    if (std.mem.eql(u8, version, pinned)) return true;
    return std.mem.eql(u8, name, debian_systemd_profile_version.name) and
        std.mem.eql(u8, version, debian_systemd_profile_version.version);
}

fn findBaseCyclePin(name: []const u8) ?CyclePackagePin {
    for (base_cycle) |pin| {
        if (std.mem.eql(u8, pin.name, name)) return pin;
    }
    return null;
}

fn findBaseCyclePinFor(name: []const u8, version: []const u8) ?CyclePackagePin {
    for (base_cycle) |pin| {
        if (std.mem.eql(u8, pin.name, name) and std.mem.eql(u8, pin.version, version)) return pin;
    }
    for (debian_base_cycle) |pin| {
        if (std.mem.eql(u8, pin.name, name) and std.mem.eql(u8, pin.version, version)) return pin;
    }
    return findBaseCyclePin(name);
}

fn findOpensslCyclePin(name: []const u8) ?CyclePackagePin {
    for (openssl_cycle) |pin| {
        if (std.mem.eql(u8, pin.name, name)) return pin;
    }
    return null;
}

fn findOpensslCyclePinFor(name: []const u8, version: []const u8) ?CyclePackagePin {
    for (openssl_cycle) |pin| {
        if (std.mem.eql(u8, pin.name, name) and std.mem.eql(u8, pin.version, version)) return pin;
    }
    for (debian_openssl_cycle) |pin| {
        if (std.mem.eql(u8, pin.name, name) and std.mem.eql(u8, pin.version, version)) return pin;
    }
    return findOpensslCyclePin(name);
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

fn findTriggerHandlerPinFor(name: []const u8, version: []const u8) ?TriggerHandlerPin {
    if (std.mem.eql(u8, name, debian_libc_bin_trigger_handler.name) and
        std.mem.eql(u8, version, debian_libc_bin_trigger_handler.version))
    {
        return debian_libc_bin_trigger_handler;
    }
    return findTriggerHandlerPin(name);
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
        const archive = try std.fmt.allocPrint(allocator, "{s}/packages-v2/objects/sha512-{s}", .{ trimmed_cache, digest });
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
        const pins: []const CyclePackagePin = if (std.mem.eql(u8, packages[0].version, debian_openssl_cycle[0].version))
            &debian_openssl_cycle
        else
            &openssl_cycle;
        for (packages, pins[0..2]) |pkg, expected| {
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
        const pins: []const CyclePackagePin = if (std.mem.eql(u8, packages[0].version, debian_base_cycle[0].version))
            &debian_base_cycle
        else
            &base_cycle;
        for (packages, pins[0..2]) |pkg, expected| {
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
        var saw_debian = false;
        for (packages) |pkg| {
            if ((try seen_names.getOrPut(pkg.name)).found_existing) return error.TriggerHandlerPackageIdentityMismatch;
            const expected = findTriggerHandlerPinFor(pkg.name, pkg.version) orelse return error.TriggerHandlerPackageIdentityMismatch;
            if (std.mem.eql(u8, expected.version, debian_libc_bin_trigger_handler.version)) saw_debian = true;
            if (!std.mem.eql(u8, pkg.architecture, expected.architecture) or
                !std.mem.eql(u8, pkg.version, expected.version) or
                pkg.declared_size != expected.size or
                !std.mem.eql(u8, pkg.digest, expected.sha512))
            {
                return error.TriggerHandlerPackageIdentityMismatch;
            }
        }
        if (saw_debian and packages.len != 1) return error.TriggerHandlerPackageIdentityMismatch;
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
    std.sort.heap([]const u8, names.items, {}, struct {
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
    for (a) |x| {
        var found = false;
        for (b) |y| {
            if (std.mem.eql(u8, x, y)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    for (b) |y| {
        var found = false;
        for (a) |x| {
            if (std.mem.eql(u8, x, y)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
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

fn isDebianBaseCycleMap(
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    architecture: []const u8,
) bool {
    return all_packages.contains(.{ .name = "gcc-14-base", .architecture = architecture }) and
        !all_packages.contains(.{ .name = "gcc-16-base", .architecture = architecture }) and
        !all_packages.contains(.{ .name = "libc-gconv-modules-extra", .architecture = architecture });
}

fn debianBaseCyclePackages(
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    architecture: []const u8,
) ![debian_base_cycle.len]Package {
    var out: [debian_base_cycle.len]Package = undefined;
    for (debian_base_cycle, 0..) |pin, idx| {
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
    const is_debian = isDebianBaseCycleMap(all_packages, architecture);
    var ubuntu_pkgs: [base_cycle.len]Package = undefined;
    var debian_pkgs: [debian_base_cycle.len]Package = undefined;
    const pkgs: []const Package = if (is_debian) blk: {
        debian_pkgs = try debianBaseCyclePackages(all_packages, architecture);
        break :blk &debian_pkgs;
    } else blk: {
        ubuntu_pkgs = try baseCyclePackages(all_packages, architecture);
        break :blk &ubuntu_pkgs;
    };
    const pins: []const CyclePackagePin = if (is_debian) &debian_base_cycle else &base_cycle;
    const expected_triggers = if (is_debian) debian_libgcc_triggers else libgcc_triggers;
    for (pkgs, pins) |pkg, expected| {
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
            if (!std.mem.eql(u8, triggers, expected_triggers)) return error.LibgccTriggersContentMismatch;
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
        const expected = findBaseCyclePinFor(pkg.name, pkg.version).?;
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
    const pins: []const CyclePackagePin = if (std.mem.eql(u8, pkgs[0].version, debian_openssl_cycle[0].version))
        &debian_openssl_cycle
    else
        &openssl_cycle;
    for (pkgs, pins) |pkg, expected| {
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
        const expected = findOpensslCyclePinFor(pkg.name, pkg.version).?;
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
        if (std.mem.eql(u8, pkg.name, "kbd")) {
            if (!sliceEqlStrings(parsed.members, expected.members)) return error.KbdCycleControlMembersMismatch;
        }
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
    const libc_bin = all_packages.get(.{ .name = "libc-bin", .architecture = architecture }) orelse
        return error.MissingTriggerHandlerPackage;
    const handlers: []const TriggerHandlerPin = if (std.mem.eql(u8, libc_bin.version, debian_libc_bin_trigger_handler.version) and
        !all_packages.contains(.{ .name = "procps", .architecture = architecture }))
        &.{debian_libc_bin_trigger_handler}
    else
        &trigger_handlers;
    for (handlers) |pin| {
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
    var saw_debian = false;
    for (pkgs) |pkg| {
        const expected = findTriggerHandlerPinFor(pkg.name, pkg.version) orelse return error.TriggerHandlerPinMismatch;
        if (std.mem.eql(u8, expected.version, debian_libc_bin_trigger_handler.version)) saw_debian = true;
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
        if (!parsed.files.contains("./control") or
            !parsed.files.contains("./postinst") or
            !parsed.files.contains("./triggers"))
        {
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
    if (saw_debian and pkgs.len != 1) return error.TriggerHandlerPinMismatch;
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
        const expected = findTriggerHandlerPinFor(pkg.name, pkg.version).?;
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

pub const Launcher = struct {
    path: []const u8,
    runtime: []const u8,
};

pub const PrestateSpec = struct {
    selector: []const u8,
    status: []const u8,
    destination: []const u8,
};

pub fn parsePrestateSpec(value: []const u8) !PrestateSpec {
    const eq = std.mem.indexOfScalar(u8, value, '=') orelse return error.InvalidPrestateTargetFormat;
    const selector = value[0..eq];
    const rest = value[eq + 1 ..];
    const colon_sel = std.mem.indexOfScalar(u8, selector, ':') orelse return error.InvalidPrestateTargetFormat;
    const pkg_name = selector[0..colon_sel];
    const pkg_arch = selector[colon_sel + 1 ..];
    if (std.mem.indexOfScalar(u8, pkg_arch, ':') != null or !validPackageName(pkg_name) or !validPackageName(pkg_arch)) {
        return error.InvalidPrestateTargetFormat;
    }
    const colon_dest = std.mem.indexOfScalar(u8, rest, ':') orelse return error.InvalidPrestateTargetFormat;
    const status = rest[0..colon_dest];
    const destination = rest[colon_dest + 1 ..];
    if (!std.mem.eql(u8, status, "half-configured") and !std.mem.eql(u8, status, "unpacked")) {
        return error.InvalidPrestateTargetFormat;
    }
    if (destination.len < 2 or destination[0] != '/') {
        return error.InvalidPrestateTargetFormat;
    }
    return .{
        .selector = selector,
        .status = status,
        .destination = destination,
    };
}

pub fn launcherCommand(
    allocator: std.mem.Allocator,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    architecture: []const u8,
    profile: []const u8,
    verb: []const u8,
    package: ?Package,
    cycle: []const Package,
) ![]const []const u8 {
    if (!std.mem.startsWith(u8, dpkg, "/") or !std.mem.startsWith(u8, root, "/")) {
        return error.NoncanonicalReferencePath;
    }
    if (!std.mem.eql(u8, architecture, "amd64") and !std.mem.eql(u8, architecture, "arm64")) {
        return error.UnsupportedReferenceArchitecture;
    }
    var command = std.ArrayList([]const u8).empty;
    errdefer command.deinit(allocator);

    if (std.mem.eql(u8, verb, "break_kbd_cycle")) {
        if (!std.mem.eql(u8, architecture, "amd64") or
            !std.mem.eql(u8, profile, kbd_cycle_profile) or
            cycle.len != kbd_cycle.len or
            package == null or
            !PackageKey.eql(package.?.key(), cycle[0].key()))
        {
            return error.CycleIdentityChanged;
        }
        for (cycle, kbd_cycle) |pkg, pin| {
            if (!std.mem.eql(u8, pkg.name, pin.name) or
                !std.mem.eql(u8, pkg.version, pin.version) or
                !std.mem.eql(u8, pkg.architecture, pin.architecture) or
                pkg.declared_size != pin.size or
                !std.mem.eql(u8, pkg.digest, pin.sha512))
            {
                return error.CycleIdentityChanged;
            }
        }
        try command.appendSlice(allocator, &.{
            try allocator.dupe(u8, launcher.path),
            try allocator.dupe(u8, root),
            try allocator.dupe(u8, dpkg),
            try allocator.dupe(u8, architecture),
            try allocator.dupe(u8, profile),
            try allocator.dupe(u8, verb),
            try package.?.selector(allocator),
            try allocator.dupe(u8, launcher.runtime),
        });
        for (cycle) |pkg| try command.append(allocator, try allocator.dupe(u8, pkg.archive));
        return command.toOwnedSlice(allocator);
    }

    if (std.mem.eql(u8, verb, "configure_openssl_cycle")) {
        if (!std.mem.eql(u8, architecture, "amd64") or
            !std.mem.eql(u8, profile, openssl_cycle_profile) or
            cycle.len != openssl_cycle.len or
            package == null or
            !PackageKey.eql(package.?.key(), cycle[0].key()))
        {
            return error.CycleIdentityChanged;
        }
        const pins: []const CyclePackagePin = if (std.mem.eql(u8, cycle[0].version, debian_openssl_cycle[0].version))
            &debian_openssl_cycle
        else
            &openssl_cycle;
        for (cycle, pins) |pkg, pin| {
            if (!std.mem.eql(u8, pkg.name, pin.name) or
                !std.mem.eql(u8, pkg.version, pin.version) or
                !std.mem.eql(u8, pkg.architecture, "amd64") or
                pkg.declared_size != pin.size or
                !std.mem.eql(u8, pkg.digest, pin.sha512))
            {
                return error.CycleIdentityChanged;
            }
        }
        try command.appendSlice(allocator, &.{
            try allocator.dupe(u8, launcher.path),
            try allocator.dupe(u8, root),
            try allocator.dupe(u8, dpkg),
            try allocator.dupe(u8, architecture),
            try allocator.dupe(u8, profile),
            try allocator.dupe(u8, verb),
            try package.?.selector(allocator),
            try allocator.dupe(u8, launcher.runtime),
        });
        for (cycle) |pkg| try command.append(allocator, try allocator.dupe(u8, pkg.archive));
        return command.toOwnedSlice(allocator);
    }

    if (std.mem.eql(u8, verb, "break_base_cycle")) {
        if (!std.mem.eql(u8, architecture, "amd64") or
            !std.mem.eql(u8, profile, base_cycle_profile) or
            (cycle.len != base_cycle.len and cycle.len != debian_base_cycle.len) or
            package == null or
            !PackageKey.eql(package.?.key(), cycle[1].key()))
        {
            return error.CycleIdentityChanged;
        }
        const pins: []const CyclePackagePin = if (cycle.len == debian_base_cycle.len)
            &debian_base_cycle
        else
            &base_cycle;
        for (cycle, pins) |pkg, pin| {
            if (!std.mem.eql(u8, pkg.name, pin.name) or
                !std.mem.eql(u8, pkg.version, pin.version) or
                !std.mem.eql(u8, pkg.architecture, "amd64") or
                pkg.declared_size != pin.size or
                !std.mem.eql(u8, pkg.digest, pin.sha512))
            {
                return error.CycleIdentityChanged;
            }
        }
        try command.appendSlice(allocator, &.{
            try allocator.dupe(u8, launcher.path),
            try allocator.dupe(u8, root),
            try allocator.dupe(u8, dpkg),
            try allocator.dupe(u8, architecture),
            try allocator.dupe(u8, profile),
            try allocator.dupe(u8, verb),
            try package.?.selector(allocator),
            try allocator.dupe(u8, launcher.runtime),
        });
        for (cycle) |pkg| try command.append(allocator, try allocator.dupe(u8, pkg.archive));
        return command.toOwnedSlice(allocator);
    }

    if (cycle.len != 0) return error.CycleIdentityChanged;

    if (std.mem.eql(u8, verb, "triggers_only")) {
        const pkg = package orelse return error.TriggerHandlerPinMismatch;
        if (!std.mem.eql(u8, architecture, "amd64")) return error.TriggerHandlerPinMismatch;
        const binding = findTriggerHandlerPinFor(pkg.name, pkg.version) orelse return error.TriggerHandlerPinMismatch;
        if (!std.mem.eql(u8, pkg.version, binding.version) or
            !std.mem.eql(u8, pkg.architecture, binding.architecture) or
            pkg.declared_size != binding.size or
            !std.mem.eql(u8, pkg.digest, binding.sha512) or
            !std.mem.eql(u8, profile, binding.profile))
        {
            return error.TriggerHandlerPinMismatch;
        }
        try command.appendSlice(allocator, &.{
            try allocator.dupe(u8, launcher.path),
            try allocator.dupe(u8, root),
            try allocator.dupe(u8, dpkg),
            try allocator.dupe(u8, architecture),
            try allocator.dupe(u8, profile),
            try allocator.dupe(u8, verb),
            try pkg.selector(allocator),
            try allocator.dupe(u8, launcher.runtime),
            try allocator.dupe(u8, pkg.archive),
        });
        return command.toOwnedSlice(allocator);
    }

    if (!std.mem.eql(u8, verb, "probe_unpack") and
        !std.mem.eql(u8, verb, "unpack") and
        !std.mem.eql(u8, verb, "probe_configure") and
        !std.mem.eql(u8, verb, "configure") and
        !std.mem.eql(u8, verb, "continue_prestate"))
    {
        return error.UnsupportedReferenceDpkgVerb;
    }
    const pkg = package orelse return error.UnsupportedReferenceDpkgVerb;
    if (std.mem.eql(u8, verb, "continue_prestate") and
        !std.mem.eql(u8, profile, "systemd") and
        !std.mem.eql(u8, profile, "udev"))
    {
        return error.ContinuePrestateRequiresProfilePackage;
    }
    if (!std.mem.eql(u8, profile, "none")) {
        if (profilePinnedVersion(profile) == null) return error.RuntimeProfileSelectionMismatch;
        if ((!std.mem.eql(u8, verb, "configure") and !std.mem.eql(u8, verb, "continue_prestate")) or
            !std.mem.eql(u8, architecture, "amd64") or
            !std.mem.eql(u8, pkg.name, profile) or
            !std.mem.eql(u8, pkg.architecture, architecture) or
            !profileVersionMatches(profile, pkg.version))
        {
            return error.RuntimeProfileVersionMismatch;
        }
    } else if (std.mem.eql(u8, verb, "configure") and profilePinnedVersion(pkg.name) != null) {
        return error.RuntimeProfileSelectionMismatch;
    }

    try command.appendSlice(allocator, &.{
        try allocator.dupe(u8, launcher.path),
        try allocator.dupe(u8, root),
        try allocator.dupe(u8, dpkg),
        try allocator.dupe(u8, architecture),
        try allocator.dupe(u8, profile),
        try allocator.dupe(u8, verb),
        try pkg.selector(allocator),
        try allocator.dupe(u8, launcher.runtime),
    });
    if (std.mem.eql(u8, verb, "unpack") or std.mem.eql(u8, verb, "probe_unpack")) {
        try command.appendSlice(allocator, &.{
            try allocator.dupe(u8, pkg.archive),
            try allocator.dupe(u8, pkg.digest),
            try std.fmt.allocPrint(allocator, "{d}", .{pkg.declared_size}),
        });
    }
    return command.toOwnedSlice(allocator);
}

const oracle_env_z: [*:null]const ?[*:0]const u8 = &.{
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/",
    "LC_ALL=C",
    "DEBIAN_FRONTEND=noninteractive",
    "DEBCONF_NONINTERACTIVE_SEEN=true",
    "DPKG_COLORS=never",
    null,
};

fn cPath(path: []const u8, buf: *[std.fs.max_path_bytes]u8) ![*:0]const u8 {
    if (path.len == 0 or path.len >= buf.len or std.mem.indexOfScalar(u8, path, 0) != null) {
        return error.InvalidReferencePath;
    }
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0].ptr;
}

fn syscall(rc: usize) !usize {
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .NOENT => error.FileNotFound,
        .EXIST => error.PathAlreadyExists,
        .ACCES, .PERM => error.AccessDenied,
        else => error.ReferenceSyscallRefused,
    };
}

var temp_seq: usize = 0;

fn nextTempDir(allocator: std.mem.Allocator, parent_dir: []const u8, prefix: []const u8) ![]u8 {
    const pid = linux.getpid();
    while (true) {
        temp_seq += 1;
        const candidate = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}{d}-{d}",
            .{ std.mem.trimEnd(u8, parent_dir, "/"), prefix, pid, temp_seq },
        );
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const ptr = try cPath(candidate, &buf);
        const rc = linux.mkdirat(linux.AT.FDCWD, ptr, 0o700);
        switch (linux.errno(rc)) {
            .SUCCESS => return candidate,
            .EXIST => {
                allocator.free(candidate);
                continue;
            },
            else => {
                allocator.free(candidate);
                return error.ReferenceSyscallRefused;
            },
        }
    }
}

fn spawnWithRedirects(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    stdin_fd: i32,
    stdout_fd: i32,
    stderr_fd: i32,
) !u8 {
    var argv_z = try allocator.alloc(?[*:0]const u8, argv.len + 1);
    defer allocator.free(argv_z);
    for (argv, 0..) |arg, idx| {
        const copy = try std.fmt.allocPrintSentinel(allocator, "{s}", .{arg}, 0);
        argv_z[idx] = copy.ptr;
    }
    argv_z[argv.len] = null;

    const pid_rc = try syscall(linux.fork());
    if (pid_rc == 0) {
        if (stdin_fd != 0) {
            if (linux.errno(linux.dup2(stdin_fd, 0)) != .SUCCESS) linux.exit(126);
        } else {
            _ = linux.fcntl(0, linux.F.SETFD, 0);
        }
        if (stdout_fd != 1) {
            if (linux.errno(linux.dup2(stdout_fd, 1)) != .SUCCESS) linux.exit(126);
        } else {
            _ = linux.fcntl(1, linux.F.SETFD, 0);
        }
        if (stderr_fd != 2) {
            if (linux.errno(linux.dup2(stderr_fd, 2)) != .SUCCESS) linux.exit(126);
        } else {
            _ = linux.fcntl(2, linux.F.SETFD, 0);
        }
        _ = linux.execve(argv_z[0].?, @ptrCast(argv_z.ptr), oracle_env_z);
        linux.exit(127);
    }

    const child_pid: linux.pid_t = @intCast(pid_rc);
    var status: i32 = 0;
    while (true) {
        const wait_rc = linux.wait4(child_pid, &status, 0, null);
        switch (linux.errno(wait_rc)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.ReferenceSyscallRefused,
        }
    }
    const ustatus: u32 = @bitCast(status);
    if (linux.W.IFEXITED(ustatus)) return @intCast(linux.W.EXITSTATUS(ustatus));
    if (linux.W.IFSIGNALED(ustatus)) return @intCast(@min(@as(u32, 255), 128 + @as(u32, @backingInt(linux.W.TERMSIG(ustatus)))));
    return 255;
}

fn runCaptured(allocator: std.mem.Allocator, argv: []const []const u8, max_bytes: usize) !DpkgRunResult {
    var out_pipe: [2]i32 = .{ -1, -1 };
    var err_pipe: [2]i32 = .{ -1, -1 };
    _ = try syscall(linux.pipe2(&out_pipe, .{ .CLOEXEC = true }));
    errdefer {
        if (out_pipe[0] >= 0) _ = linux.close(out_pipe[0]);
        if (out_pipe[1] >= 0) _ = linux.close(out_pipe[1]);
    }
    _ = try syscall(linux.pipe2(&err_pipe, .{ .CLOEXEC = true }));
    errdefer {
        if (err_pipe[0] >= 0) _ = linux.close(err_pipe[0]);
        if (err_pipe[1] >= 0) _ = linux.close(err_pipe[1]);
    }

    const null_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        "/dev/null",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(null_fd);

    var argv_z = try allocator.alloc(?[*:0]const u8, argv.len + 1);
    defer allocator.free(argv_z);
    for (argv, 0..) |arg, idx| {
        const copy = try std.fmt.allocPrintSentinel(allocator, "{s}", .{arg}, 0);
        argv_z[idx] = copy.ptr;
    }
    argv_z[argv.len] = null;

    const pid_rc = try syscall(linux.fork());
    if (pid_rc == 0) {
        if (linux.errno(linux.dup2(null_fd, 0)) != .SUCCESS) linux.exit(126);
        if (linux.errno(linux.dup2(out_pipe[1], 1)) != .SUCCESS) linux.exit(126);
        if (linux.errno(linux.dup2(err_pipe[1], 2)) != .SUCCESS) linux.exit(126);
        _ = linux.execve(argv_z[0].?, @ptrCast(argv_z.ptr), oracle_env_z);
        linux.exit(127);
    }
    _ = linux.close(out_pipe[1]);
    out_pipe[1] = -1;
    _ = linux.close(err_pipe[1]);
    err_pipe[1] = -1;

    var stdout_buf = std.ArrayList(u8).empty;
    errdefer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayList(u8).empty;
    errdefer stderr_buf.deinit(allocator);

    var pfds: [2]linux.pollfd = .{
        .{ .fd = out_pipe[0], .events = linux.POLL.IN, .revents = 0 },
        .{ .fd = err_pipe[0], .events = linux.POLL.IN, .revents = 0 },
    };
    var open_count: usize = 2;
    var scratch: [65536]u8 = undefined;
    while (open_count > 0) {
        const poll_rc = linux.poll(&pfds, pfds.len, -1);
        switch (linux.errno(poll_rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReferenceSyscallRefused,
        }
        for (&pfds, 0..) |*pfd, idx| {
            if (pfd.fd < 0) continue;
            if ((pfd.revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR)) != 0) {
                const n = linux.read(pfd.fd, &scratch, scratch.len);
                switch (linux.errno(n)) {
                    .SUCCESS => {
                        if (n == 0) {
                            _ = linux.close(pfd.fd);
                            pfd.fd = -1;
                            if (idx == 0) out_pipe[0] = -1 else err_pipe[0] = -1;
                            open_count -= 1;
                        } else {
                            const target = if (idx == 0) &stdout_buf else &stderr_buf;
                            if (target.items.len < max_bytes + 1) {
                                const take = @min(n, (max_bytes + 1) - target.items.len);
                                try target.appendSlice(allocator, scratch[0..take]);
                            }
                        }
                    },
                    .INTR => continue,
                    else => return error.ReferenceSyscallRefused,
                }
            }
        }
    }

    const child_pid: linux.pid_t = @intCast(pid_rc);
    var status: i32 = 0;
    while (true) {
        const wait_rc = linux.wait4(child_pid, &status, 0, null);
        switch (linux.errno(wait_rc)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.ReferenceSyscallRefused,
        }
    }
    const ustatus: u32 = @bitCast(status);
    const rc: u8 = if (linux.W.IFEXITED(ustatus))
        @intCast(linux.W.EXITSTATUS(ustatus))
    else if (linux.W.IFSIGNALED(ustatus))
        @intCast(@min(@as(u32, 255), 128 + @as(u32, @backingInt(linux.W.TERMSIG(ustatus)))))
    else
        255;

    return .{
        .returncode = rc,
        .stdout = try stdout_buf.toOwnedSlice(allocator),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
    };
}

fn resolveSystemTool(comptime name: []const u8) []const u8 {
    const candidates = [_][:0]const u8{
        "/usr/bin/" ++ name,
        "/bin/" ++ name,
        "/usr/sbin/" ++ name,
        "/sbin/" ++ name,
    };
    for (candidates) |cand| {
        if (linux.errno(linux.faccessat(linux.AT.FDCWD, cand, linux.F_OK, 0)) == .SUCCESS) {
            return cand;
        }
    }
    return "/usr/bin/" ++ name;
}

fn runCheckedSystemCommand(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const res = try runCaptured(allocator, argv, maximum_probe_output);
    defer {
        allocator.free(res.stdout);
        allocator.free(res.stderr);
    }
    if (res.returncode != 0) return error.SystemCommandFailed;
}

fn removeTempDirWithFiles(allocator: std.mem.Allocator, dir_path: []const u8, files: []const []const u8) void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    for (files) |f| {
        const p = std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, f }) catch continue;
        defer allocator.free(p);
        if (cPath(p, &buf)) |ptr| {
            _ = linux.unlinkat(linux.AT.FDCWD, ptr, 0);
        } else |_| {}
    }
    if (cPath(dir_path, &buf)) |ptr| {
        _ = linux.unlinkat(linux.AT.FDCWD, ptr, linux.AT.REMOVEDIR);
    } else |_| {}
}

fn readFdBounded(allocator: std.mem.Allocator, fd: i32, max_bytes: usize) ![]u8 {
    const st = try reference_paths.fstat(fd);
    if (st.size > max_bytes) return error.ProbeOutputExceedsLimit;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    var buf: [65536]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(rc) != .SUCCESS) return error.ReferenceReadFailed;
        if (rc == 0) break;
        if (out.items.len + rc > max_bytes) return error.ProbeOutputExceedsLimit;
        try out.appendSlice(allocator, buf[0..rc]);
    }
    return out.toOwnedSlice(allocator);
}

const ProbeResult = struct {
    status: u8,
    output: []u8,
};

fn probe(allocator: std.mem.Allocator, command: []const []const u8, evidence: []const u8) !ProbeResult {
    const tmp_dir = try nextTempDir(allocator, evidence, "reference-probe-");
    defer removeTempDirWithFiles(allocator, tmp_dir, &.{"output"});

    const out_path = try std.fmt.allocPrint(allocator, "{s}/output", .{tmp_dir});
    var out_buf: [std.fs.max_path_bytes]u8 = undefined;
    const out_ptr = try cPath(out_path, &out_buf);

    const writer_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        out_ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .APPEND = true, .NOFOLLOW = true, .CLOEXEC = true },
        0o600,
    )));
    defer _ = linux.close(writer_fd);

    const reader_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        out_ptr,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(reader_fd);

    const null_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        "/dev/null",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(null_fd);

    const status = try spawnWithRedirects(allocator, command, null_fd, writer_fd, writer_fd);
    const output = try readFdBounded(allocator, reader_fd, maximum_probe_output);
    return .{ .status = status, .output = output };
}

fn apply(allocator: std.mem.Allocator, command: []const []const u8, stdout_path: []const u8, stderr_path: []const u8) !void {
    var out_buf: [std.fs.max_path_bytes]u8 = undefined;
    const out_ptr = try cPath(stdout_path, &out_buf);
    const out_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        out_ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .NOFOLLOW = true, .CLOEXEC = true },
        0o600,
    )));
    defer _ = linux.close(out_fd);

    var err_buf: [std.fs.max_path_bytes]u8 = undefined;
    const err_ptr = try cPath(stderr_path, &err_buf);
    const err_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        err_ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .NOFOLLOW = true, .CLOEXEC = true },
        0o600,
    )));
    defer _ = linux.close(err_fd);

    const null_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        "/dev/null",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(null_fd);

    const rc = try spawnWithRedirects(allocator, command, null_fd, out_fd, err_fd);
    if (rc != 0) return error.ReferenceDpkgApplyFailed;
    const out_st = try reference_paths.fstat(out_fd);
    const err_st = try reference_paths.fstat(err_fd);
    if (out_st.size > maximum_log_bytes or err_st.size > maximum_log_bytes) {
        return error.ReferenceLogExceedsLimit;
    }
}

fn appendToFile(path: []const u8, data: []const u8) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    const fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .NOFOLLOW = true, .CLOEXEC = true },
        0o600,
    )));
    defer _ = linux.close(fd);
    var written: usize = 0;
    while (written < data.len) {
        const rc = try syscall(linux.write(fd, data[written..].ptr, data.len - written));
        if (rc == 0) return error.ReferenceSyscallRefused;
        written += rc;
    }
}

fn writeFileMode(path: []const u8, data: []const u8, mode: linux.mode_t) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    const fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true, .CLOEXEC = true },
        mode,
    )));
    defer _ = linux.close(fd);
    var written: usize = 0;
    while (written < data.len) {
        const rc = try syscall(linux.write(fd, data[written..].ptr, data.len - written));
        if (rc == 0) return error.ReferenceSyscallRefused;
        written += rc;
    }
    _ = try syscall(linux.fchmod(fd, mode));
}

fn writeEvidenceFile(allocator: std.mem.Allocator, dir_path: []const u8, name: []const u8, data: []const u8) !void {
    const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ std.mem.trimEnd(u8, dir_path, "/"), name });
    defer allocator.free(full);
    try writeFileMode(full, data, 0o600);
}

fn sha256FileHex(allocator: std.mem.Allocator, path: []const u8) ![64]u8 {
    const fd = try reference_paths.openAbsolute(path, false);
    defer _ = linux.close(fd);
    const bytes = try readFdBounded(allocator, fd, maximum_archive_bytes);
    defer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn copyRegularFile(src: []const u8, dst: []const u8, mode: linux.mode_t) !void {
    const src_fd = try reference_paths.openAbsolute(src, false);
    defer _ = linux.close(src_fd);
    var dst_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dst_ptr = try cPath(dst, &dst_buf);
    const dst_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        dst_ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true, .CLOEXEC = true },
        mode,
    )));
    defer _ = linux.close(dst_fd);
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = try syscall(linux.read(src_fd, &buf, buf.len));
        if (n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const w = try syscall(linux.write(dst_fd, buf[off..n].ptr, n - off));
            if (w == 0) return error.ReferenceSyscallRefused;
            off += w;
        }
    }
    _ = try syscall(linux.fchmod(dst_fd, mode));
}

fn fetchCtrlTarViaDpkgDeb(allocator: std.mem.Allocator, archive: []const u8) ![]const u8 {
    const dpkg_deb = resolveSystemTool("dpkg-deb");
    const res = try runCaptured(allocator, &.{ dpkg_deb, "--ctrl-tarfile", archive }, maximum_control_bytes);
    defer allocator.free(res.stderr);
    if (res.returncode != 0 or res.stderr.len != 0 or res.stdout.len > maximum_control_bytes) {
        allocator.free(res.stdout);
        return error.ControlTarFetchFailed;
    }
    return res.stdout;
}

pub const StanzaRecord = struct {
    key: PackageKey,
    fields: std.StringHashMap([]const u8),
};

pub fn parseDatabaseRecords(allocator: std.mem.Allocator, text: []const u8) ![]StanzaRecord {
    var records = std.ArrayList(StanzaRecord).empty;
    errdefer records.deinit(allocator);
    var seen = std.HashMap(PackageKey, void, PackageKeyContext, 80).init(allocator);
    defer seen.deinit();

    var start: usize = 0;
    while (start <= text.len) {
        const next_sep = std.mem.indexOfPos(u8, text, start, "\n\n");
        const stanza_raw = if (next_sep) |idx| text[start..idx] else text[start..];
        const stanza = std.mem.trim(u8, stanza_raw, " \t\r\n");
        if (stanza.len > 0) {
            if (records.items.len >= maximum_packages) return error.StatusDatabaseExceedsPackageLimit;
            const fields = try databaseFields(allocator, stanza);
            const pkg_name = fields.get("package") orelse return error.IncompleteDpkgStatusStanza;
            const arch = fields.get("architecture") orelse return error.IncompleteDpkgStatusStanza;
            const version = fields.get("version") orelse return error.IncompleteDpkgStatusStanza;
            const status = fields.get("status") orelse return error.IncompleteDpkgStatusStanza;
            if (!validPackageName(pkg_name) or !validPackageName(arch) or version.len == 0 or status.len == 0) {
                return error.IncompleteDpkgStatusStanza;
            }
            const k: PackageKey = .{ .name = pkg_name, .architecture = arch };
            if ((try seen.getOrPut(k)).found_existing) return error.DuplicateDpkgStatusPackage;
            try records.append(allocator, .{ .key = k, .fields = fields });
        }
        if (next_sep) |idx| {
            start = idx + 2;
        } else break;
    }
    return records.toOwnedSlice(allocator);
}

fn readDatabaseRecords(allocator: std.mem.Allocator, root: []const u8) ![]StanzaRecord {
    const text = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", 4 * 1024 * 1024);
    defer allocator.free(text);
    return parseDatabaseRecords(allocator, text);
}

fn findRecord(records: []StanzaRecord, key: PackageKey) ?*StanzaRecord {
    for (records) |*rec| {
        if (PackageKey.eql(rec.key, key)) return rec;
    }
    return null;
}

fn findRecordConst(records: []const StanzaRecord, key: PackageKey) ?*const StanzaRecord {
    for (records) |*rec| {
        if (PackageKey.eql(rec.key, key)) return rec;
    }
    return null;
}

pub fn scheduleConserved(
    candidate: []const StanzaRecord,
    pending: []const StanzaRecord,
    half_configured: Package,
) bool {
    if (candidate.len != pending.len) return false;
    for (candidate) |expected| {
        const pkg_name = expected.fields.get("package") orelse return false;
        const pkg_arch = expected.fields.get("architecture") orelse return false;
        const exp_ver = expected.fields.get("version") orelse return false;
        const exp_status = expected.fields.get("status") orelse return false;
        const observed = findRecordConst(pending, .{ .name = pkg_name, .architecture = pkg_arch }) orelse return false;
        if (!std.mem.eql(u8, observed.fields.get("version") orelse "", exp_ver)) return false;
        if (std.mem.eql(u8, pkg_name, half_configured.name) and std.mem.eql(u8, pkg_arch, half_configured.architecture)) {
            if (!std.mem.eql(u8, exp_ver, half_configured.version) or
                !std.mem.eql(u8, exp_status, "install ok unpacked") or
                !std.mem.eql(u8, observed.fields.get("status") orelse "", "install ok half-configured"))
            {
                return false;
            }
        } else if (!std.mem.eql(u8, observed.fields.get("status") orelse "", exp_status)) {
            return false;
        }
    }
    return true;
}

fn cloneRecords(allocator: std.mem.Allocator, records: []const StanzaRecord) ![]StanzaRecord {
    var out = try allocator.alloc(StanzaRecord, records.len);
    for (records, 0..) |rec, idx| {
        var map = std.StringHashMap([]const u8).init(allocator);
        var it = rec.fields.iterator();
        while (it.next()) |entry| {
            try map.put(try allocator.dupe(u8, entry.key_ptr.*), try allocator.dupe(u8, entry.value_ptr.*));
        }
        out[idx] = .{
            .key = .{
                .name = try allocator.dupe(u8, rec.key.name),
                .architecture = try allocator.dupe(u8, rec.key.architecture),
            },
            .fields = map,
        };
    }
    return out;
}

fn recordsEqual(a: []const StanzaRecord, b: []const StanzaRecord) bool {
    if (a.len != b.len) return false;
    for (a) |rec_a| {
        var matched = false;
        for (b) |rec_b| {
            if (PackageKey.eql(rec_a.key, rec_b.key)) {
                matched = true;
                if (rec_a.fields.count() != rec_b.fields.count()) return false;
                var it = rec_a.fields.iterator();
                while (it.next()) |entry| {
                    const val_b = rec_b.fields.get(entry.key_ptr.*) orelse return false;
                    if (!std.mem.eql(u8, entry.value_ptr.*, val_b)) return false;
                }
                break;
            }
        }
        if (!matched) return false;
    }
    return true;
}

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20 or c >= 0x7f) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

fn writeJsonRecords(allocator: std.mem.Allocator, writer: anytype, records: []const StanzaRecord) !void {
    try writer.writeByte('[');
    for (records, 0..) |rec, idx| {
        if (idx > 0) try writer.writeByte(',');
        var keys = std.ArrayList([]const u8).empty;
        defer keys.deinit(allocator);
        var it = rec.fields.keyIterator();
        while (it.next()) |k| try keys.append(allocator, k.*);
        std.sort.heap([]const u8, keys.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);
        try writer.writeByte('{');
        for (keys.items, 0..) |k, k_idx| {
            if (k_idx > 0) try writer.writeByte(',');
            try writeJsonString(writer, k);
            try writer.writeByte(':');
            try writeJsonString(writer, rec.fields.get(k).?);
        }
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
}

fn writeJsonTriggers(allocator: std.mem.Allocator, writer: anytype, triggers: *const TriggerMap) !void {
    var keys = std.ArrayList([]const u8).empty;
    defer keys.deinit(allocator);
    var it = triggers.keyIterator();
    while (it.next()) |k| try keys.append(allocator, k.*);
    std.sort.heap([]const u8, keys.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    try writer.writeByte('{');
    for (keys.items, 0..) |k, idx| {
        if (idx > 0) try writer.writeByte(',');
        const entry = triggers.get(k).?;
        try writeJsonString(writer, k);
        try writer.print(":{{\"sha512\":\"{s}\",\"size\":{d}}}", .{ &entry.sha512, entry.size });
    }
    try writer.writeByte('}');
}

fn writeJsonStringSlice(writer: anytype, slice: []const []const u8) !void {
    try writer.writeByte('[');
    for (slice, 0..) |item, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writeJsonString(writer, item);
    }
    try writer.writeByte(']');
}

fn checkForbiddenInfoFiles(allocator: std.mem.Allocator, root: []const u8, names: []const []const u8) !void {
    for (names) |name| {
        const full = try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/info/{s}", .{ std.mem.trimEnd(u8, root, "/"), name });
        defer allocator.free(full);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const ptr = try cPath(full, &buf);
        var stx: linux.Statx = undefined;
        const rc = linux.statx(linux.AT.FDCWD, ptr, linux.AT.SYMLINK_NOFOLLOW, linux.STATX.BASIC_STATS, &stx);
        if (linux.errno(rc) == .SUCCESS) return error.UnexpectedCycleCallbackFile;
    }
}

fn verifyInstalledFieldsMatchControl(installed: *const std.StringHashMap([]const u8), control: *const std.StringHashMap([]const u8), check_triggers: bool) !void {
    const compare_fields = [_][]const u8{
        "depends",    "pre-depends", "provides",  "conflicts", "breaks", "replaces",
        "multi-arch", "protected",   "essential",
    };
    for (compare_fields) |field| {
        if (!std.mem.eql(u8, installed.get(field) orelse "", control.get(field) orelse "")) {
            return error.CycleControlFieldMismatch;
        }
    }
    if (check_triggers) {
        for ([_][]const u8{ "triggers-pending", "triggers-awaited", "config-version" }) |field| {
            if (!std.mem.eql(u8, installed.get(field) orelse "", "")) return error.UnexpectedCycleTriggerState;
        }
    }
}

fn buildPackageMap(allocator: std.mem.Allocator, packages: []const Package) !std.HashMap(PackageKey, Package, PackageKeyContext, 80) {
    var map = std.HashMap(PackageKey, Package, PackageKeyContext, 80).init(allocator);
    for (packages) |pkg| try map.put(pkg.key(), pkg);
    return map;
}

fn verifyFullBaseCycle(
    allocator: std.mem.Allocator,
    root: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    architecture: []const u8,
) ![]Package {
    var statuses = try currentStatuses(allocator, root);
    defer statuses.deinit();
    _ = try verifyBaseCycle(allocator, all_packages, &statuses, architecture, fetchCtrlTarViaDpkgDeb);
    const is_debian = isDebianBaseCycleMap(all_packages, architecture);
    const cycle = if (is_debian) blk: {
        const pkgs = try debianBaseCyclePackages(all_packages, architecture);
        break :blk try allocator.dupe(Package, &pkgs);
    } else blk: {
        const pkgs = try baseCyclePackages(all_packages, architecture);
        break :blk try allocator.dupe(Package, &pkgs);
    };
    const records = try readDatabaseRecords(allocator, root);
    for (cycle) |pkg| {
        const raw_tar = try fetchCtrlTarViaDpkgDeb(allocator, pkg.archive);
        const parsed = try parseControlTarBytes(allocator, raw_tar);
        const control = try controlFields(allocator, parsed.files.get("./control").?);
        const rec = findRecord(records, pkg.key()) orelse return error.BaseCycleStatusNotReady;
        try verifyInstalledFieldsMatchControl(&rec.fields, &control, true);
    }
    const installed_triggers = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/info/libgcc-s1:amd64.triggers", 1024);
    const expected_triggers = if (is_debian) debian_libgcc_triggers else libgcc_triggers;
    if (!std.mem.eql(u8, installed_triggers, expected_triggers)) return error.LibgccTriggersContentMismatch;
    var forbidden = std.ArrayList([]const u8).empty;
    try forbidden.append(allocator, "libgcc-s1.triggers");
    for ([_][]const u8{ "libgcc-s1", "libgcc-s1:amd64" }) |name| {
        for (maintainer_scripts) |script| {
            try forbidden.append(allocator, try std.fmt.allocPrint(allocator, "{s}.{s}", .{ name, script }));
        }
    }
    try checkForbiddenInfoFiles(allocator, root, forbidden.items);
    return cycle;
}

fn execBreakBaseCycle(
    allocator: std.mem.Allocator,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    evidence: []const u8,
    architecture: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    stdout_path: []const u8,
    stderr_path: []const u8,
) !Package {
    const cycle = try verifyFullBaseCycle(allocator, root, all_packages, architecture);
    const is_debian = cycle.len == debian_base_cycle.len;
    const before_records = try readDatabaseRecords(allocator, root);
    var before_triggers = try triggerDatabase(allocator, root);
    defer before_triggers.deinit();

    const status_before_bytes = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", 4 * 1024 * 1024);
    var status_before_digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(status_before_bytes, &status_before_digest, .{});
    const status_before_hex = std.fmt.bytesToHex(status_before_digest, .lower);
    const command = try launcherCommand(allocator, launcher, dpkg, root, architecture, base_cycle_profile, "break_base_cycle", cycle[1], cycle);
    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"callbacks\":[],\"force\":[\"--force-depends\"],\"graph\":{");
        const order_indices: []const usize = if (is_debian) &.{ 2, 0, 1 } else &.{ 2, 3, 0, 1 };
        const bindings: []const CyclePackagePin = if (is_debian) &debian_base_cycle else &base_cycle;
        for (order_indices, 0..) |c_idx, out_idx| {
            const pkg = cycle[c_idx];
            const binding = bindings[c_idx];
            if (out_idx > 0) try out.writer.writeByte(',');
            try writeJsonString(&out.writer, pkg.name);
            try out.writer.writeAll(":{\"archive_sha512\":");
            try writeJsonString(&out.writer, pkg.digest);
            try out.writer.writeAll(",\"depends\":");
            try writeJsonString(&out.writer, binding.depends);
            try out.writer.writeAll(",\"pre_depends\":\"\",\"status\":");
            try writeJsonString(&out.writer, if (c_idx < 2) "install ok unpacked" else "install ok installed");
            try out.writer.writeAll(",\"version\":");
            try writeJsonString(&out.writer, pkg.version);
            try out.writer.writeByte('}');
        }
        try out.writer.writeAll("},\"profile\":\"libgcc_cycle\",\"records\":");
        try writeJsonRecords(allocator, &out.writer, before_records);
        try out.writer.print(",\"selected\":\"libgcc-s1:amd64\",\"status_sha512\":\"{s}\",\"trigger_database\":", .{&status_before_hex});
        try writeJsonTriggers(allocator, &out.writer, &before_triggers);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, evidence, "base-cycle-before.json", out.written());
    }

    try apply(allocator, command, stdout_path, stderr_path);
    const after_records = try readDatabaseRecords(allocator, root);
    var after_triggers = try triggerDatabase(allocator, root);
    defer after_triggers.deinit();

    const expected = try cloneRecords(allocator, before_records);
    const libgcc_rec = findRecord(expected, cycle[1].key()) orelse return error.BaseCycleDidNotInstallPinnedPair;
    try libgcc_rec.fields.put("status", "install ok installed");
    if (!recordsEqual(after_records, expected) or !verifyTriggerMapIdentical(&before_triggers, &after_triggers)) {
        return error.BaseCycleMutatedUnexpectedPackageStatus;
    }

    const status_bytes = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", maximum_control_bytes);
    var status_digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(status_bytes, &status_digest, .{});
    const status_hex = std.fmt.bytesToHex(status_digest, .lower);
    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"callbacks\":[],\"operation\":");
        try writeJsonStringSlice(&out.writer, command[3..]);
        try out.writer.writeAll(",\"records\":");
        try writeJsonRecords(allocator, &out.writer, after_records);
        try out.writer.print(",\"status\":\"install ok installed\",\"status_sha512\":\"{s}\",\"trigger_database\":", .{&status_hex});
        try writeJsonTriggers(allocator, &out.writer, &after_triggers);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, evidence, "base-cycle-after.json", out.written());
    }
    return cycle[1];
}

fn execConfigureOpensslCycle(
    allocator: std.mem.Allocator,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    evidence: []const u8,
    architecture: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    stdout_path: []const u8,
    stderr_path: []const u8,
) ![2]Package {
    var statuses = try currentStatuses(allocator, root);
    defer statuses.deinit();
    _ = try verifyOpensslCycle(allocator, all_packages, &statuses, architecture, fetchCtrlTarViaDpkgDeb);
    const cycle = try opensslCyclePackages(all_packages, architecture);
    const is_debian = std.mem.eql(u8, cycle[0].version, debian_openssl_cycle[0].version);
    const active_openssl_cycle: []const CyclePackagePin = if (is_debian) &debian_openssl_cycle else &openssl_cycle;
    const expected_openssl_triggers = if (is_debian) debian_openssl_triggers else libgcc_triggers;
    const before_records = try readDatabaseRecords(allocator, root);
    var before_triggers = try triggerDatabase(allocator, root);
    defer before_triggers.deinit();

    var peer_multi_arch: [2][]const u8 = .{ "", "" };
    for (cycle, 0..) |pkg, index| {
        const raw_tar = try fetchCtrlTarViaDpkgDeb(allocator, pkg.archive);
        const parsed = try parseControlTarBytes(allocator, raw_tar);
        if (index < 2) {
            if (!sliceEqlStrings(parsed.members, active_openssl_cycle[index].members)) {
                return error.OpensslCycleControlMembersMismatch;
            }
            if (index == 0) {
                const trigs = parsed.files.get("./triggers") orelse return error.OpensslCycleTriggersMismatch;
                if (!std.mem.eql(u8, trigs, expected_openssl_triggers)) return error.OpensslCycleTriggersMismatch;
            }
        }
        const control = try controlFields(allocator, parsed.files.get("./control").?);
        if (index < 2) peer_multi_arch[index] = control.get("multi-arch") orelse "";
        const rec = findRecord(before_records, pkg.key()) orelse return error.OpensslCycleStatusNotReady;
        try verifyInstalledFieldsMatchControl(&rec.fields, &control, true);
    }
    const installed_triggers = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/info/libssl3t64:amd64.triggers", 1024);
    if (!std.mem.eql(u8, installed_triggers, expected_openssl_triggers)) return error.OpensslCycleTriggersMismatch;

    var forbidden = std.ArrayList([]const u8).empty;
    try forbidden.appendSlice(allocator, &.{
        "libssl3t64.triggers",
        "openssl-provider-legacy.triggers",
        "openssl-provider-legacy:amd64.triggers",
    });
    for ([_][]const u8{ "libssl3t64", "libssl3t64:amd64", "openssl-provider-legacy", "openssl-provider-legacy:amd64" }) |name| {
        for (maintainer_scripts) |script| {
            try forbidden.append(allocator, try std.fmt.allocPrint(allocator, "{s}.{s}", .{ name, script }));
        }
    }
    try checkForbiddenInfoFiles(allocator, root, forbidden.items);

    var refusals_json = std.Io.Writer.Allocating.init(allocator);
    defer refusals_json.deinit();
    try refusals_json.writer.writeByte('[');
    for ([_][2]usize{ .{ 0, 1 }, .{ 1, 0 } }, 0..) |pair_idx, r_idx| {
        const pkg = cycle[pair_idx[0]];
        const peer = cycle[pair_idx[1]];
        const probe_cmd = try launcherCommand(allocator, launcher, dpkg, root, architecture, "none", "probe_configure", pkg, &.{});
        const res = try probe(allocator, probe_cmd, evidence);
        if (r_idx > 0) try refusals_json.writer.writeByte(',');
        try refusals_json.writer.writeAll("{\"argv\":");
        try writeJsonStringSlice(&refusals_json.writer, probe_cmd[3..]);
        try refusals_json.writer.print(",\"exit_status\":{d},\"output\":", .{res.status});
        try writeJsonString(&refusals_json.writer, res.output);
        try refusals_json.writer.writeByte('}');

        var current_json = std.Io.Writer.Allocating.init(allocator);
        defer current_json.deinit();
        try current_json.writer.print("{s}]\n", .{refusals_json.written()});
        try writeEvidenceFile(allocator, evidence, "openssl-cycle-refusals.json", current_json.written());

        const peer_name = if (std.mem.eql(u8, peer.architecture, architecture) and
            !std.mem.eql(u8, peer_multi_arch[pair_idx[1]], "same"))
            peer.name
        else
            try peer.selector(allocator);
        const needle = try std.fmt.allocPrint(allocator, "Package {s} is not configured yet.", .{peer_name});
        if (res.status == 0 or
            std.mem.indexOf(u8, res.output, "dependency problems") == null or
            std.mem.indexOf(u8, res.output, needle) == null)
        {
            return error.OpensslCycleProbeChanged;
        }
    }

    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"callbacks\":[],\"force\":[],\"graph\":{");
        for ([_]usize{ 2, 0, 1 }, 0..) |c_idx, out_idx| {
            const pkg = cycle[c_idx];
            const binding = active_openssl_cycle[c_idx];
            const multi_arch = if (c_idx < 2) peer_multi_arch[c_idx] else "same";
            if (out_idx > 0) try out.writer.writeByte(',');
            try writeJsonString(&out.writer, pkg.name);
            try out.writer.writeAll(":{\"archive_sha512\":");
            try writeJsonString(&out.writer, pkg.digest);
            try out.writer.writeAll(",\"depends\":");
            try writeJsonString(&out.writer, binding.depends);
            try out.writer.writeAll(",\"multi_arch\":");
            try writeJsonString(&out.writer, multi_arch);
            try out.writer.writeAll(",\"pre_depends\":\"\",\"status\":");
            try writeJsonString(&out.writer, if (c_idx < 2) "install ok unpacked" else "install ok installed");
            try out.writer.writeAll(",\"version\":");
            try writeJsonString(&out.writer, pkg.version);
            try out.writer.writeByte('}');
        }
        try out.writer.writeAll("},\"profile\":\"openssl_cycle\",\"records\":");
        try writeJsonRecords(allocator, &out.writer, before_records);
        try out.writer.writeAll(",\"trigger_database\":");
        try writeJsonTriggers(allocator, &out.writer, &before_triggers);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, evidence, "openssl-cycle-before.json", out.written());
    }

    const command = try launcherCommand(allocator, launcher, dpkg, root, architecture, openssl_cycle_profile, "configure_openssl_cycle", cycle[0], &cycle);
    try apply(allocator, command, stdout_path, stderr_path);

    const after_records = try readDatabaseRecords(allocator, root);
    var after_triggers = try triggerDatabase(allocator, root);
    defer after_triggers.deinit();

    const expected = try cloneRecords(allocator, before_records);
    for (cycle[0..2]) |pkg| {
        const rec = findRecord(expected, pkg.key()) orelse return error.OpensslCycleDidNotInstallPinnedPair;
        try rec.fields.put("status", "install ok installed");
    }
    if (!recordsEqual(after_records, expected) or !verifyTriggerMapIdentical(&before_triggers, &after_triggers)) {
        return error.OpensslCycleMutatedUnexpectedPackageStatus;
    }

    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"callbacks\":[],\"force\":[],\"operation\":");
        try writeJsonStringSlice(&out.writer, command[3..]);
        try out.writer.writeAll(",\"records\":");
        try writeJsonRecords(allocator, &out.writer, after_records);
        try out.writer.writeAll(",\"trigger_database\":");
        try writeJsonTriggers(allocator, &out.writer, &after_triggers);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, evidence, "openssl-cycle-after.json", out.written());
    }
    return .{ cycle[0], cycle[1] };
}

fn execBreakKbdCycle(
    allocator: std.mem.Allocator,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    evidence: []const u8,
    architecture: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    stdout_path: []const u8,
    stderr_path: []const u8,
) !Package {
    var statuses = try currentStatuses(allocator, root);
    defer statuses.deinit();
    _ = try verifyKbdCycle(allocator, all_packages, &statuses, architecture, fetchCtrlTarViaDpkgDeb);
    const cycle = try kbdCyclePackages(all_packages);
    const before_records = try readDatabaseRecords(allocator, root);
    var before_triggers = try triggerDatabase(allocator, root);
    defer before_triggers.deinit();

    for (cycle) |pkg| {
        const raw_tar = try fetchCtrlTarViaDpkgDeb(allocator, pkg.archive);
        const parsed = try parseControlTarBytes(allocator, raw_tar);
        const control = try controlFields(allocator, parsed.files.get("./control").?);
        const rec = findRecord(before_records, pkg.key()) orelse return error.KbdCycleStatusNotReady;
        try verifyInstalledFieldsMatchControl(&rec.fields, &control, true);
    }
    const installed_triggers = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/info/kbd.triggers", 1024);
    if (!std.mem.eql(u8, installed_triggers, kbd_triggers)) return error.KbdCycleTriggersContentMismatch;

    var forbidden = std.ArrayList([]const u8).empty;
    try forbidden.append(allocator, "kbd:amd64.triggers");
    for ([_][]const u8{ "kbd", "kbd:amd64" }) |name| {
        for (maintainer_scripts) |script| {
            try forbidden.append(allocator, try std.fmt.allocPrint(allocator, "{s}.{s}", .{ name, script }));
        }
    }
    try checkForbiddenInfoFiles(allocator, root, forbidden.items);

    const probe_cmd = try launcherCommand(allocator, launcher, dpkg, root, architecture, "none", "probe_configure", cycle[0], &.{});
    const probe_res = try probe(allocator, probe_cmd, evidence);
    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"argv\":");
        try writeJsonStringSlice(&out.writer, probe_cmd[3..]);
        try out.writer.print(",\"exit_status\":{d},\"output\":", .{probe_res.status});
        try writeJsonString(&out.writer, probe_res.output);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, evidence, "kbd-cycle-refusal.json", out.written());
    }
    if (probe_res.status == 0 or
        std.mem.indexOf(u8, probe_res.output, "dependency problems") == null or
        std.mem.indexOf(u8, probe_res.output, "Package console-setup is not configured yet.") == null)
    {
        return error.KbdCycleProbeChanged;
    }

    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"callbacks\":[],\"force\":[\"--force-depends\"],\"graph\":{");
        for ([_]usize{ 2, 1, 0, 3 }, 0..) |c_idx, out_idx| {
            const pkg = cycle[c_idx];
            const binding = kbd_cycle[c_idx];
            if (out_idx > 0) try out.writer.writeByte(',');
            try writeJsonString(&out.writer, pkg.name);
            try out.writer.writeAll(":{\"architecture\":");
            try writeJsonString(&out.writer, pkg.architecture);
            try out.writer.writeAll(",\"archive_sha512\":");
            try writeJsonString(&out.writer, pkg.digest);
            try out.writer.writeAll(",\"depends\":");
            try writeJsonString(&out.writer, binding.depends);
            try out.writer.writeAll(",\"status\":");
            try writeJsonString(&out.writer, if (c_idx == 0 or c_idx == 2) "install ok unpacked" else "install ok installed");
            try out.writer.writeAll(",\"version\":");
            try writeJsonString(&out.writer, pkg.version);
            try out.writer.writeByte('}');
        }
        try out.writer.writeAll("},\"profile\":\"kbd_cycle\",\"records\":");
        try writeJsonRecords(allocator, &out.writer, before_records);
        try out.writer.writeAll(",\"trigger_database\":");
        try writeJsonTriggers(allocator, &out.writer, &before_triggers);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, evidence, "kbd-cycle-before.json", out.written());
    }

    const command = try launcherCommand(allocator, launcher, dpkg, root, architecture, kbd_cycle_profile, "break_kbd_cycle", cycle[0], &cycle);
    try apply(allocator, command, stdout_path, stderr_path);

    const after_records = try readDatabaseRecords(allocator, root);
    var after_triggers = try triggerDatabase(allocator, root);
    defer after_triggers.deinit();

    const expected = try cloneRecords(allocator, before_records);
    const kbd_rec = findRecord(expected, cycle[0].key()) orelse return error.KbdCycleDidNotInstallKbd;
    try kbd_rec.fields.put("status", "install ok installed");
    if (!recordsEqual(after_records, expected) or !verifyTriggerMapIdentical(&before_triggers, &after_triggers)) {
        return error.KbdCycleMutatedUnexpectedPackageStatus;
    }

    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"callbacks\":[],\"force\":[\"--force-depends\"],\"operation\":");
        try writeJsonStringSlice(&out.writer, command[3..]);
        try out.writer.writeAll(",\"records\":");
        try writeJsonRecords(allocator, &out.writer, after_records);
        try out.writer.writeAll(",\"trigger_database\":");
        try writeJsonTriggers(allocator, &out.writer, &after_triggers);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, evidence, "kbd-cycle-after.json", out.written());
    }
    return cycle[0];
}

fn execProcessTriggers(
    allocator: std.mem.Allocator,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    evidence: []const u8,
    architecture: []const u8,
    all_packages: *const std.HashMap(PackageKey, Package, PackageKeyContext, 80),
    stdout_path: []const u8,
    stderr_path: []const u8,
) !void {
    if (!std.mem.eql(u8, architecture, "amd64")) return error.TriggerHandlerOrderRequiresAmd64;
    var statuses = try currentStatuses(allocator, root);
    defer statuses.deinit();
    const handlers = try verifyTriggerHandlers(allocator, root, all_packages, &statuses, architecture, fetchCtrlTarViaDpkgDeb);
    const active_handlers: []const TriggerHandlerPin = if (handlers.len == 1 and
        std.mem.eql(u8, handlers[0].version, debian_libc_bin_trigger_handler.version))
        &.{debian_libc_bin_trigger_handler}
    else
        &trigger_handlers;
    if (handlers.len != active_handlers.len) return error.TriggerHandlerStatusNotReady;

    var current_records = try readDatabaseRecords(allocator, root);
    var before_triggers = try triggerDatabase(allocator, root);
    defer before_triggers.deinit();

    for (current_records) |rec| {
        var is_handler = false;
        for (handlers) |h| {
            if (PackageKey.eql(rec.key, h.key())) {
                is_handler = true;
                break;
            }
        }
        if (is_handler) {
            if (!std.mem.eql(u8, rec.fields.get("triggers-awaited") orelse "", "")) return error.TriggerHandlerStatusNotReady;
        } else {
            if (!std.mem.eql(u8, rec.fields.get("status") orelse "", "install ok installed") or
                !std.mem.eql(u8, rec.fields.get("triggers-pending") orelse "", "") or
                !std.mem.eql(u8, rec.fields.get("triggers-awaited") orelse "", "") or
                !std.mem.eql(u8, rec.fields.get("config-version") orelse "", ""))
            {
                return error.TriggerHandlerStatusNotReady;
            }
        }
    }

    const ldconfig_triggers = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/triggers/ldconfig", 1024);
    if (!std.mem.eql(u8, ldconfig_triggers, "libc-bin\n")) return error.TriggerHandlerStatusNotReady;
    if (active_handlers.len == trigger_handlers.len) {
        const file_triggers = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/triggers/File", maximum_control_bytes);
        var has_sysctl_trigger = false;
        var ft_lines = std.mem.splitScalar(u8, file_triggers, '\n');
        while (ft_lines.next()) |line| {
            if (std.mem.eql(u8, std.mem.trimEnd(u8, line, "\r"), "/usr/lib/sysctl.d procps/noawait")) {
                has_sysctl_trigger = true;
                break;
            }
        }
        if (!has_sysctl_trigger) return error.TriggerHandlerStatusNotReady;
    }

    for (handlers, active_handlers) |pkg, binding| {
        const rec = findRecord(current_records, pkg.key()) orelse return error.TriggerHandlerStatusNotReady;
        if (!std.mem.eql(u8, rec.fields.get("config-version") orelse "", pkg.version)) {
            return error.TriggerHandlerStatusNotReady;
        }
        const postinst_path = try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/info/{s}.postinst", .{ std.mem.trimEnd(u8, root, "/"), pkg.name });
        const triggers_path = try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/info/{s}.triggers", .{ std.mem.trimEnd(u8, root, "/"), pkg.name });
        const postinst_meta = try reference_paths.protected(postinst_path, false);
        const triggers_meta = try reference_paths.protected(triggers_path, false);
        if ((postinst_meta.mode & 0o7777) != 0o755 or (triggers_meta.mode & 0o7777) != 0o644) {
            return error.TriggerHandlerInstalledPostinstMismatch;
        }
        const forbidden = [_][]const u8{
            try std.fmt.allocPrint(allocator, "{s}:{s}.postinst", .{ pkg.name, pkg.architecture }),
            try std.fmt.allocPrint(allocator, "{s}:{s}.triggers", .{ pkg.name, pkg.architecture }),
        };
        try checkForbiddenInfoFiles(allocator, root, &forbidden);
        _ = binding;
    }

    const status_bytes = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", 4 * 1024 * 1024);
    var status_digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(status_bytes, &status_digest, .{});
    const status_hex = std.fmt.bytesToHex(status_digest, .lower);
    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"handlers\":[");
        for (handlers, active_handlers, 0..) |pkg, binding, h_idx| {
            if (h_idx > 0) try out.writer.writeByte(',');
            try out.writer.writeAll("{\"archive_sha512\":");
            try writeJsonString(&out.writer, pkg.digest);
            try out.writer.writeAll(",\"pending_triggers\":");
            try writeJsonString(&out.writer, binding.pending);
            try out.writer.writeAll(",\"postinst_sha256\":");
            try writeJsonString(&out.writer, binding.postinst_sha256);
            try out.writer.print(",\"postinst_size\":{d},\"profile\":", .{binding.postinst_size});
            try writeJsonString(&out.writer, binding.profile);
            try out.writer.writeAll(",\"selector\":");
            try writeJsonString(&out.writer, try pkg.selector(allocator));
            try out.writer.writeAll(",\"triggers_sha256\":");
            try writeJsonString(&out.writer, binding.triggers_sha256);
            try out.writer.print(",\"triggers_size\":{d},\"version\":", .{binding.triggers_size});
            try writeJsonString(&out.writer, pkg.version);
            try out.writer.writeByte('}');
        }
        try out.writer.writeAll("],\"records\":");
        try writeJsonRecords(allocator, &out.writer, current_records);
        try out.writer.print(",\"status_sha512\":\"{s}\",\"trigger_database\":", .{&status_hex});
        try writeJsonTriggers(allocator, &out.writer, &before_triggers);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, evidence, "triggers-before.json", out.written());
    }

    var steps_json = std.Io.Writer.Allocating.init(allocator);
    defer steps_json.deinit();
    try steps_json.writer.writeByte('[');
    for (handlers, active_handlers, 0..) |pkg, binding, idx| {
        const command = try launcherCommand(allocator, launcher, dpkg, root, architecture, binding.profile, "triggers_only", pkg, &.{});
        try apply(allocator, command, stdout_path, stderr_path);
        const after_records = try readDatabaseRecords(allocator, root);
        var after_triggers = try triggerDatabase(allocator, root);
        defer after_triggers.deinit();

        const expected = try cloneRecords(allocator, current_records);
        const rec = findRecord(expected, pkg.key()) orelse return error.TriggerHandlerDidNotInstallHandlers;
        try rec.fields.put("status", "install ok installed");
        _ = rec.fields.remove("triggers-pending");
        _ = rec.fields.remove("config-version");
        if (!recordsEqual(after_records, expected) or !verifyTriggerMapIdentical(&before_triggers, &after_triggers)) {
            return error.TriggerHandlerMutatedUnexpectedPackageStatus;
        }
        current_records = after_records;

        if (idx > 0) try steps_json.writer.writeByte(',');
        try steps_json.writer.print(
            "{{\"callbacks\":[\"{s}.postinst triggered {s}\"],\"force\":[],\"operation\":",
            .{ pkg.name, binding.pending },
        );
        try writeJsonStringSlice(&steps_json.writer, command[3..]);
        try steps_json.writer.print(",\"selector\":\"{s}\"}}", .{try pkg.selector(allocator)});
    }
    try steps_json.writer.writeByte(']');

    for (current_records) |rec| {
        if (!std.mem.eql(u8, rec.fields.get("status") orelse "", "install ok installed") or
            !std.mem.eql(u8, rec.fields.get("triggers-pending") orelse "", "") or
            !std.mem.eql(u8, rec.fields.get("triggers-awaited") orelse "", "") or
            !std.mem.eql(u8, rec.fields.get("config-version") orelse "", ""))
        {
            return error.TriggerHandlerDidNotDrainPendingTrigger;
        }
    }

    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"records\":");
        try writeJsonRecords(allocator, &out.writer, current_records);
        try out.writer.print(",\"steps\":{s},\"trigger_database\":", .{steps_json.written()});
        try writeJsonTriggers(allocator, &out.writer, &before_triggers);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, evidence, "triggers-after.json", out.written());
    }
}

fn stagePendingOracleRuntime(allocator: std.mem.Allocator, baseline: []const u8, setpriv: []const u8) ![]const u8 {
    const setpriv_dir = std.fs.path.dirname(setpriv) orelse return error.CycleProofRuntimeChanged;
    const source = try std.fmt.allocPrint(allocator, "{s}/libcap-ng.so.0.0.0", .{setpriv_dir});
    const meta = reference_paths.protected(source, false) catch return error.CycleProofRuntimeChanged;
    if (meta.size != 26928 or (meta.mode & 0o7777) != 0o644) return error.CycleProofRuntimeChanged;
    const data = reference_paths.readRootFile(allocator, setpriv_dir, "libcap-ng.so.0.0.0", 26928) catch return error.CycleProofRuntimeChanged;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &hex, "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f")) {
        return error.CycleProofRuntimeChanged;
    }
    const relative = "usr/lib/x86_64-linux-gnu/libcap-ng.so.0";
    const target = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ std.mem.trimEnd(u8, baseline, "/"), relative });
    const target_parent = std.fs.path.dirname(target) orelse return error.CycleProofRuntimeChanged;
    _ = reference_paths.protected(target_parent, true) catch return error.CycleProofRuntimeChanged;

    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const target_ptr = try cPath(target, &target_buf);
    const fd: i32 = @intCast(syscall(linux.openat(
        linux.AT.FDCWD,
        target_ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true },
        0o644,
    )) catch return error.CycleProofRuntimeChanged);
    defer _ = linux.close(fd);
    var written: usize = 0;
    while (written < data.len) {
        const rc = syscall(linux.write(fd, data[written..].ptr, data.len - written)) catch return error.CycleProofRuntimeChanged;
        if (rc == 0) return error.CycleProofRuntimeChanged;
        written += rc;
    }
    _ = syscall(linux.fchmod(fd, 0o644)) catch return error.CycleProofRuntimeChanged;
    return source;
}

fn proveBaseCycle(
    allocator: std.mem.Allocator,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    cache: []const u8,
    evidence: []const u8,
    setpriv: []const u8,
) !void {
    if (builtin.cpu.arch != .x86_64) return error.CycleProofPrestateInvalid;
    {
        var initial = try currentStatuses(allocator, root);
        defer initial.deinit();
        if (initial.count() != 0) return error.CycleProofPrestateInvalid;
    }
    _ = try reference_paths.protected(root, true);
    _ = try reference_paths.protected(setpriv, false);
    const setpriv_hex = try sha256FileHex(allocator, setpriv);
    if (!std.mem.eql(u8, &setpriv_hex, "86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993")) {
        return error.CycleProofRuntimeChanged;
    }

    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/reference-archives.tsv", .{std.mem.trimEnd(u8, evidence, "/")});
    const packages = try packagesFromManifest(allocator, manifest_path, cache, maximum_packages);
    var all_packages = try buildPackageMap(allocator, packages);
    defer all_packages.deinit();
    const cycle = try baseCyclePackages(&all_packages, "amd64");

    const proof = try std.fmt.allocPrint(allocator, "{s}/base-cycle-proof", .{std.mem.trimEnd(u8, evidence, "/")});
    var proof_buf: [std.fs.max_path_bytes]u8 = undefined;
    const proof_ptr = try cPath(proof, &proof_buf);
    _ = try syscall(linux.mkdirat(linux.AT.FDCWD, proof_ptr, 0o700));

    const cp_bin = resolveSystemTool("cp");
    const rm_bin = resolveSystemTool("rm");
    const mount_bin = resolveSystemTool("mount");
    const umount_bin = resolveSystemTool("umount");
    const unshare_bin = resolveSystemTool("unshare");

    const seed = try std.fmt.allocPrint(allocator, "{s}/seed", .{proof});
    const candidate = try std.fmt.allocPrint(allocator, "{s}/candidate", .{proof});
    const baseline = try std.fmt.allocPrint(allocator, "{s}/pending", .{proof});
    defer {
        for ([_][]const u8{ seed, candidate, baseline }) |dest| {
            runCheckedSystemCommand(allocator, &.{ rm_bin, "-rf", "--one-file-system", "--", dest }) catch {};
        }
    }

    try runCheckedSystemCommand(allocator, &.{ cp_bin, "-a", "--one-file-system", "--", root, seed });
    const unpack_stdout = try std.fmt.allocPrint(allocator, "{s}/unpack.stdout", .{proof});
    const unpack_stderr = try std.fmt.allocPrint(allocator, "{s}/unpack.stderr", .{proof});
    for ([_]Package{ cycle[2], cycle[3], cycle[0], cycle[1] }) |pkg| {
        try verifyArchive(pkg);
        const cmd = try launcherCommand(allocator, launcher, dpkg, seed, "amd64", "none", "unpack", pkg, &.{});
        try apply(allocator, cmd, unpack_stdout, unpack_stderr);
    }
    for (cycle[2..]) |pkg| {
        const cmd = try launcherCommand(allocator, launcher, dpkg, seed, "amd64", "none", "configure", pkg, &.{});
        try apply(allocator, cmd, unpack_stdout, unpack_stderr);
    }
    _ = try verifyFullBaseCycle(allocator, seed, &all_packages, "amd64");
    for (cycle[0..2]) |pkg| {
        const cmd = try launcherCommand(allocator, launcher, dpkg, seed, "amd64", "none", "probe_configure", pkg, &.{});
        const res = try probe(allocator, cmd, proof);
        if (res.status == 0 or std.mem.indexOf(u8, res.output, "dependency problems") == null) {
            return error.CycleProofMissingStall;
        }
    }

    for ([_][]const u8{ candidate, baseline }) |dest| {
        try runCheckedSystemCommand(allocator, &.{ cp_bin, "-a", "--one-file-system", "--", seed, dest });
    }

    const refused_cmd = try launcherCommand(allocator, launcher, dpkg, candidate, "amd64", base_cycle_profile, "break_base_cycle", cycle[1], &cycle);
    const before_refusal = try readDatabaseRecords(allocator, candidate);
    var before_triggers = try triggerDatabase(allocator, candidate);
    defer before_triggers.deinit();

    const injected = try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/info/libgcc-s1:amd64.postinst", .{candidate});
    try writeFileMode(injected, "#!/bin/sh\necho unbound-cycle-callback-executed\nexit 0\n", 0o755);
    const refusal_res = blk: {
        defer {
            var inj_buf: [std.fs.max_path_bytes]u8 = undefined;
            if (cPath(injected, &inj_buf)) |ptr| {
                _ = linux.unlinkat(linux.AT.FDCWD, ptr, 0);
            } else |_| {}
        }
        break :blk try probe(allocator, refused_cmd, proof);
    };
    const after_refusal = try readDatabaseRecords(allocator, candidate);
    var after_refusal_triggers = try triggerDatabase(allocator, candidate);
    defer after_refusal_triggers.deinit();
    if (refusal_res.status == 0 or
        std.mem.indexOf(u8, refusal_res.output, "unbound-cycle-callback-executed") != null or
        std.mem.indexOf(u8, refusal_res.output, "stage 11") == null or
        !recordsEqual(after_refusal, before_refusal) or
        !verifyTriggerMapIdentical(&before_triggers, &after_refusal_triggers))
    {
        return error.CycleProofCallbackChanged;
    }
    try writeEvidenceFile(allocator, proof, "callback-refusal.log", refusal_res.output);

    const cand_stdout = try std.fmt.allocPrint(allocator, "{s}/candidate.stdout", .{proof});
    const cand_stderr = try std.fmt.allocPrint(allocator, "{s}/candidate.stderr", .{proof});
    _ = try execBreakBaseCycle(allocator, launcher, dpkg, candidate, proof, "amd64", &all_packages, cand_stdout, cand_stderr);

    {
        var base_statuses = try currentStatuses(allocator, baseline);
        defer base_statuses.deinit();
        if (base_statuses.count() != 4) return error.CycleProofCallbackChanged;
    }
    _ = try verifyFullBaseCycle(allocator, baseline, &all_packages, "amd64");

    var script_rel: ?[]const u8 = null;
    for ([_][]const u8{ "var/lib/dpkg/info/libc6.postinst", "var/lib/dpkg/info/libc6:amd64.postinst" }) |rel| {
        const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ baseline, rel });
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const ptr = try cPath(full, &buf);
        if (linux.errno(linux.faccessat(linux.AT.FDCWD, ptr, linux.F_OK, 0)) == .SUCCESS) {
            if (script_rel != null) return error.CycleProofCallbackChanged;
            script_rel = rel;
        }
    }
    const found_script_rel = script_rel orelse return error.CycleProofCallbackChanged;
    const script_full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ baseline, found_script_rel });

    const libc6_ctrl_tar = try fetchCtrlTarViaDpkgDeb(allocator, cycle[0].archive);
    const libc6_parsed = try parseControlTarBytes(allocator, libc6_ctrl_tar);
    const signed_postinst = libc6_parsed.files.get("./postinst") orelse return error.CycleProofCallbackChanged;
    const installed_postinst = try reference_paths.readRootFile(allocator, baseline, found_script_rel, maximum_probe_output);
    if (signed_postinst.len == 0 or !std.mem.eql(u8, installed_postinst, signed_postinst)) {
        return error.CycleProofCallbackChanged;
    }

    try copyRegularFile(dpkg, try std.fmt.allocPrint(allocator, "{s}/usr/bin/dpkg", .{baseline}), 0o755);
    try copyRegularFile(setpriv, try std.fmt.allocPrint(allocator, "{s}/usr/bin/setpriv", .{baseline}), 0o755);
    const libcap_source = try stagePendingOracleRuntime(allocator, baseline, setpriv);
    const before_pending = try readDatabaseRecords(allocator, baseline);

    const pending_cmd = [_][]const u8{
        unshare_bin,
        "--mount",
        "--pid",
        "--fork",
        "--kill-child=SIGKILL",
        "--propagation",
        "private",
        "--",
        "chroot",
        baseline,
        "/usr/bin/setpriv",
        "--bounding-set=-all,+chown,+dac_override,+fowner,+fsetid,+setgid,+setuid,+setfcap",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        "/usr/bin/dpkg",
        "--root=/",
        "--force-not-root",
        "--force-bad-path",
        "--force-confold",
        "--no-triggers",
        "--configure",
        "--pending",
    };

    try runCheckedSystemCommand(allocator, &.{ mount_bin, "--bind", "--", script_full, script_full });
    const pending_res = blk: {
        defer runCheckedSystemCommand(allocator, &.{ umount_bin, "--", script_full }) catch {};
        try runCheckedSystemCommand(allocator, &.{ mount_bin, "-o", "remount,bind,ro,noexec,nosuid,nodev", "--", script_full });
        const res = try runCaptured(allocator, &pending_cmd, maximum_probe_output);
        try writeEvidenceFile(allocator, proof, "pending.stdout", res.stdout[0..@min(res.stdout.len, maximum_probe_output)]);
        try writeEvidenceFile(allocator, proof, "pending.stderr", res.stderr[0..@min(res.stderr.len, maximum_probe_output)]);
        {
            const truncated = res.stdout.len > maximum_probe_output or res.stderr.len > maximum_probe_output;
            var out = std.Io.Writer.Allocating.init(allocator);
            defer out.deinit();
            try out.writer.writeAll("{\"argv\":");
            try writeJsonStringSlice(&out.writer, &pending_cmd);
            try out.writer.print(
                ",\"output_truncated\":{s},\"returncode\":{d},\"schema\":\"io.github.cataggar.debz.base-cycle-pending-result.v1\",\"setpriv_runtime\":{{\"mode\":\"0644\",\"sha256\":\"60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f\",\"size\":26928,\"source\":",
                .{ if (truncated) "true" else "false", res.returncode },
            );
            try writeJsonString(&out.writer, libcap_source);
            try out.writer.print(
                ",\"target\":\"usr/lib/x86_64-linux-gnu/libcap-ng.so.0\"}},\"stderr_bytes\":{d},\"stdout_bytes\":{d}}}\n",
                .{ res.stderr.len, res.stdout.len },
            );
            try writeEvidenceFile(allocator, proof, "pending-result.json", out.written());
        }
        break :blk res;
    };

    const after_pending = try readDatabaseRecords(allocator, baseline);
    var pending_triggers = try triggerDatabase(allocator, baseline);
    defer pending_triggers.deinit();
    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"after\":");
        try writeJsonRecords(allocator, &out.writer, after_pending);
        try out.writer.writeAll(",\"before\":");
        try writeJsonRecords(allocator, &out.writer, before_pending);
        try out.writer.writeAll(",\"trigger_database\":");
        try writeJsonTriggers(allocator, &out.writer, &pending_triggers);
        try out.writer.writeAll("}\n");
        try writeEvidenceFile(allocator, proof, "pending-status.json", out.written());
    }

    if (pending_res.stdout.len > maximum_probe_output or
        pending_res.stderr.len > maximum_probe_output or
        pending_res.returncode == 0 or
        std.mem.indexOf(u8, pending_res.stderr, "Permission denied") == null or
        std.mem.indexOf(u8, pending_res.stderr, "post-installation script") == null)
    {
        return error.CycleProofCallbackChanged;
    }
    const postinst_after = try reference_paths.readRootFile(allocator, baseline, found_script_rel, maximum_probe_output);
    if (!std.mem.eql(u8, postinst_after, signed_postinst)) return error.CycleProofCallbackChanged;

    var observed_map = try currentStatuses(allocator, baseline);
    defer observed_map.deinit();
    var wanted_map = try currentStatuses(allocator, candidate);
    defer wanted_map.deinit();
    try wanted_map.put(.{ .name = "libc6", .architecture = "amd64" }, .{
        .name = "libc6",
        .architecture = "amd64",
        .version = cycle[0].version,
        .status = "install ok half-configured",
    });
    const cand_records = try readDatabaseRecords(allocator, candidate);
    if (!verifyStatusTransition(&wanted_map, &observed_map, &.{}) or !scheduleConserved(cand_records, after_pending, cycle[0])) {
        return error.CycleProofScheduleChanged;
    }

    var cand_triggers = try triggerDatabase(allocator, candidate);
    defer cand_triggers.deinit();
    {
        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();
        try out.writer.writeAll("{\"callback_denied\":\"libc6 postinst configure\",\"callbacks_executed\":[],\"candidate\":");
        try writeJsonRecords(allocator, &out.writer, cand_records);
        try out.writer.writeAll(",\"candidate_trigger_database\":");
        try writeJsonTriggers(allocator, &out.writer, &cand_triggers);
        try out.writer.writeAll(",\"difference\":\"pending attempts libc6 configure; single breaker leaves libc6 unpacked\",\"parity_claim\":false,\"pending\":");
        try writeJsonRecords(allocator, &out.writer, after_pending);
        try out.writer.writeAll(",\"pending_argv\":");
        try writeJsonStringSlice(&out.writer, &pending_cmd);
        try out.writer.writeAll(",\"pending_setpriv_runtime\":{\"mode\":\"0644\",\"sha256\":\"60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f\",\"size\":26928,\"source\":");
        try writeJsonString(&out.writer, libcap_source);
        try out.writer.writeAll(",\"target\":\"usr/lib/x86_64-linux-gnu/libcap-ng.so.0\"},\"pending_trigger_database\":");
        try writeJsonTriggers(allocator, &out.writer, &pending_triggers);
        try out.writer.writeAll(",\"schema\":\"io.github.cataggar.debz.base-cycle-proof.v1\"}\n");
        try writeEvidenceFile(allocator, proof, "comparison.json", out.written());
    }
}

fn queryPackageStatus(allocator: std.mem.Allocator, root: []const u8, selector: []const u8) ![]const u8 {
    const dpkg_query = resolveSystemTool("dpkg-query");
    const admindir_arg = try std.fmt.allocPrint(allocator, "--admindir={s}/var/lib/dpkg", .{std.mem.trimEnd(u8, root, "/")});
    const res = try runCaptured(allocator, &.{ dpkg_query, admindir_arg, "-W", "-f=${Version} ${Status}", selector }, 4096);
    defer allocator.free(res.stderr);
    if (res.returncode != 0 or res.stderr.len != 0 or res.stdout.len > 4096) {
        allocator.free(res.stdout);
        return error.ReferenceStatusQueryFailed;
    }
    return res.stdout;
}

fn interruptPostinst(
    allocator: std.mem.Allocator,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    evidence: []const u8,
    architecture: []const u8,
    package: Package,
    stdout_path: []const u8,
    stderr_path: []const u8,
) !void {
    const script = try std.fmt.allocPrint(
        allocator,
        "{s}/var/lib/dpkg/info/{s}.postinst",
        .{ std.mem.trimEnd(u8, root, "/"), package.name },
    );
    _ = try reference_paths.protected(script, false);
    const before_sha256 = try sha256FileHex(allocator, script);
    const profile = packageProfile(package.name);
    if (profilePinnedVersion(profile) == null or !profileVersionMatches(profile, package.version)) {
        return error.UnauthorizedInterruptedPrestatePackage;
    }

    const mount_bin = resolveSystemTool("mount");
    const umount_bin = resolveSystemTool("umount");
    try runCheckedSystemCommand(allocator, &.{ mount_bin, "--bind", "--", script, script });
    var observed_output: []u8 = &.{};
    var observed_errors: []u8 = &.{};
    var rc: u8 = 0;
    {
        defer runCheckedSystemCommand(allocator, &.{ umount_bin, "--", script }) catch {};
        try runCheckedSystemCommand(allocator, &.{ mount_bin, "-o", "remount,bind,ro,noexec,nosuid,nodev", "--", script });

        const tmp_dir = try nextTempDir(allocator, evidence, "reference-configure-");
        defer removeTempDirWithFiles(allocator, tmp_dir, &.{ "stdout", "stderr" });

        const out_file = try std.fmt.allocPrint(allocator, "{s}/stdout", .{tmp_dir});
        const err_file = try std.fmt.allocPrint(allocator, "{s}/stderr", .{tmp_dir});
        var out_buf: [std.fs.max_path_bytes]u8 = undefined;
        const out_ptr = try cPath(out_file, &out_buf);
        var err_buf: [std.fs.max_path_bytes]u8 = undefined;
        const err_ptr = try cPath(err_file, &err_buf);

        const out_writer_fd: i32 = @intCast(try syscall(linux.openat(
            linux.AT.FDCWD,
            out_ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .APPEND = true, .NOFOLLOW = true, .CLOEXEC = true },
            0o600,
        )));
        defer _ = linux.close(out_writer_fd);
        const err_writer_fd: i32 = @intCast(try syscall(linux.openat(
            linux.AT.FDCWD,
            err_ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .APPEND = true, .NOFOLLOW = true, .CLOEXEC = true },
            0o600,
        )));
        defer _ = linux.close(err_writer_fd);

        const out_reader_fd: i32 = @intCast(try syscall(linux.openat(
            linux.AT.FDCWD,
            out_ptr,
            .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        )));
        defer _ = linux.close(out_reader_fd);
        const err_reader_fd: i32 = @intCast(try syscall(linux.openat(
            linux.AT.FDCWD,
            err_ptr,
            .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        )));
        defer _ = linux.close(err_reader_fd);

        const null_fd: i32 = @intCast(try syscall(linux.openat(
            linux.AT.FDCWD,
            "/dev/null",
            .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
            0,
        )));
        defer _ = linux.close(null_fd);

        const cmd = try launcherCommand(allocator, launcher, dpkg, root, architecture, profile, "configure", package, &.{});
        rc = try spawnWithRedirects(allocator, cmd, null_fd, out_writer_fd, err_writer_fd);
        observed_output = try readFdBounded(allocator, out_reader_fd, maximum_probe_output);
        observed_errors = try readFdBounded(allocator, err_reader_fd, maximum_probe_output);
    }

    try appendToFile(stdout_path, observed_output);
    try appendToFile(stderr_path, observed_errors);
    if (rc == 0 or
        std.mem.indexOf(u8, observed_errors, "post-installation script") == null or
        std.mem.indexOf(u8, observed_errors, "Permission denied") == null)
    {
        return error.PrestatePostinstNotDenied;
    }
    const after_sha256 = try sha256FileHex(allocator, script);
    if (!std.mem.eql(u8, &after_sha256, &before_sha256)) return error.PrestatePostinstChanged;
}

fn isMountpoint(root: []const u8, sub: []const u8) !bool {
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_ptr = try cPath(root, &root_buf);
    var sub_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sub_ptr = try cPath(sub, &sub_buf);
    var root_stx: linux.Statx = undefined;
    var sub_stx: linux.Statx = undefined;
    _ = try syscall(linux.statx(linux.AT.FDCWD, root_ptr, linux.AT.SYMLINK_NOFOLLOW, linux.STATX.BASIC_STATS, &root_stx));
    _ = try syscall(linux.statx(linux.AT.FDCWD, sub_ptr, linux.AT.SYMLINK_NOFOLLOW, linux.STATX.BASIC_STATS, &sub_stx));
    return root_stx.dev_major != sub_stx.dev_major or root_stx.dev_minor != sub_stx.dev_minor;
}

fn capturePrestate(
    allocator: std.mem.Allocator,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    evidence: []const u8,
    architecture: []const u8,
    package: Package,
    prestate: PrestateSpec,
    stdout_path: []const u8,
    stderr_path: []const u8,
) !void {
    const destination = prestate.destination;
    var dest_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dest_ptr = try cPath(destination, &dest_buf);
    var dest_stx: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, dest_ptr, linux.AT.SYMLINK_NOFOLLOW, linux.STATX.BASIC_STATS, &dest_stx)) == .SUCCESS) {
        return error.PrestateDestinationAlreadyExists;
    }
    const parent = std.fs.path.dirname(destination) orelse return error.InvalidPrestateTargetFormat;
    _ = try reference_paths.protected(parent, true);

    if (std.mem.eql(u8, prestate.status, "half-configured")) {
        try interruptPostinst(allocator, launcher, dpkg, root, evidence, architecture, package, stdout_path, stderr_path);
    }
    const expected = try std.fmt.allocPrint(allocator, "{s} install ok {s}", .{ package.version, prestate.status });
    const selector = try package.selector(allocator);
    const actual_status = try queryPackageStatus(allocator, root, selector);
    if (!std.mem.eql(u8, actual_status, expected)) return error.UnexpectedPrestateStatus;

    const proc_path = try std.fmt.allocPrint(allocator, "{s}/proc", .{std.mem.trimEnd(u8, root, "/")});
    const mount_bin = resolveSystemTool("mount");
    const umount_bin = resolveSystemTool("umount");
    const cp_bin = resolveSystemTool("cp");

    const mounted = try isMountpoint(root, proc_path);
    if (mounted) {
        try runCheckedSystemCommand(allocator, &.{ umount_bin, "--", proc_path });
    }
    {
        defer if (mounted) {
            runCheckedSystemCommand(allocator, &.{ mount_bin, "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", proc_path }) catch {};
        };
        if (try isMountpoint(root, proc_path)) return error.PrestateProcMountpointNotEmpty;
        const root_fd = try reference_paths.openAbsolute(root, true);
        defer _ = linux.close(root_fd);
        const proc_entries = try listDirectoryBeneath(allocator, root_fd, "proc");
        if (proc_entries.len != 0) return error.PrestateProcMountpointNotEmpty;

        try runCheckedSystemCommand(allocator, &.{ cp_bin, "-a", "--one-file-system", "--", root, destination });
        _ = try syscall(linux.fchmodat(linux.AT.FDCWD, dest_ptr, 0o700));
    }

    const record_path = try std.fmt.allocPrint(allocator, "{s}/prestates.tsv", .{std.mem.trimEnd(u8, parent, "/")});
    const record_line = try std.fmt.allocPrint(allocator, "{s}\t{s}\t{s}\n", .{ selector, expected, destination });
    try appendToFile(record_path, record_line);
}

fn install(
    allocator: std.mem.Allocator,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    cache: []const u8,
    evidence: []const u8,
    architecture: []const u8,
    prestates: []const PrestateSpec,
) !void {
    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/reference-archives.tsv", .{std.mem.trimEnd(u8, evidence, "/")});
    const packages = try packagesFromManifest(allocator, manifest_path, cache, maximum_packages);
    var all_packages = try buildPackageMap(allocator, packages);
    defer all_packages.deinit();

    var targets = std.StringHashMap(PrestateSpec).init(allocator);
    defer targets.deinit();
    var dest_set = std.StringHashMap(void).init(allocator);
    defer dest_set.deinit();
    var closure_selectors = std.StringHashMap(void).init(allocator);
    defer closure_selectors.deinit();
    for (packages) |pkg| {
        try closure_selectors.put(try pkg.selector(allocator), {});
    }
    for (prestates) |ps| {
        if ((try targets.getOrPut(ps.selector)).found_existing) return error.DuplicatePrestateSelector;
        try targets.put(ps.selector, ps);
        if ((try dest_set.getOrPut(ps.destination)).found_existing) return error.DuplicatePrestateDestination;
        if (!closure_selectors.contains(ps.selector)) return error.PrestateTargetNotInManifest;
    }
    if (targets.contains("sudo:amd64")) {
        const comp_key: PackageKey = .{
            .name = sudo_prestate_companion.name,
            .architecture = sudo_prestate_companion.architecture,
        };
        const comp = all_packages.get(comp_key) orelse return error.MissingSudoPrestateCompanion;
        if (!std.mem.eql(u8, comp.version, sudo_prestate_companion.version) or
            !std.mem.eql(u8, comp.architecture, sudo_prestate_companion.architecture))
        {
            return error.MissingSudoPrestateCompanion;
        }
    }

    var pending = std.ArrayList(Package).empty;
    defer pending.deinit(allocator);
    try pending.appendSlice(allocator, packages);
    var unpacked = std.ArrayList(Package).empty;
    defer unpacked.deinit(allocator);
    var configured = std.HashMap(PackageKey, void, PackageKeyContext, 80).init(allocator);
    defer configured.deinit();

    const stdout_path = try std.fmt.allocPrint(allocator, "{s}/reference-install.stdout", .{std.mem.trimEnd(u8, evidence, "/")});
    const stderr_path = try std.fmt.allocPrint(allocator, "{s}/reference-install.stderr", .{std.mem.trimEnd(u8, evidence, "/")});
    var probes: usize = 0;
    var cycle_broken = false;
    var openssl_configured = false;
    var kbd_configured = false;

    const RefusalItem = struct {
        selector: []const u8,
        operation: []const u8,
        exit_status: u8,
        output_bytes: usize,
        output_prefix_hex: []const u8,
        output_sha512: [128]u8,
    };

    while (pending.items.len > 0 or unpacked.items.len > 0) {
        var progressed = false;
        var deferred = std.ArrayList([]const u8).empty;
        defer deferred.deinit(allocator);
        var refusals = std.ArrayList(RefusalItem).empty;
        defer refusals.deinit(allocator);

        const pending_snapshot = try allocator.dupe(Package, pending.items);
        for (pending_snapshot) |pkg| {
            const cmd = try launcherCommand(allocator, launcher, dpkg, root, architecture, "none", "probe_unpack", pkg, &.{});
            probes += 1;
            if (probes > maximum_probes) return error.ProbeLimitExceeded;
            const res = try probe(allocator, cmd, evidence);
            if (res.status != 0) {
                if (std.mem.indexOf(u8, res.output, "pre-dependency problem") == null) {
                    return error.ReferenceUnpackRefused;
                }
                const sel = try pkg.selector(allocator);
                try deferred.append(allocator, sel);
                const prefix_len = @min(res.output.len, 4096);
                var prefix_hex = try allocator.alloc(u8, prefix_len * 2);
                for (res.output[0..prefix_len], 0..) |b, bi| {
                    const h = std.fmt.bytesToHex([1]u8{b}, .lower);
                    prefix_hex[bi * 2] = h[0];
                    prefix_hex[bi * 2 + 1] = h[1];
                }
                var out_digest: [64]u8 = undefined;
                std.crypto.hash.sha2.Sha512.hash(res.output, &out_digest, .{});
                try refusals.append(allocator, .{
                    .selector = sel,
                    .operation = "probe_unpack",
                    .exit_status = res.status,
                    .output_bytes = res.output.len,
                    .output_prefix_hex = prefix_hex,
                    .output_sha512 = std.fmt.bytesToHex(out_digest, .lower),
                });
                continue;
            }
            try verifyArchive(pkg);
            const unpack_cmd = try launcherCommand(allocator, launcher, dpkg, root, architecture, "none", "unpack", pkg, &.{});
            try apply(allocator, unpack_cmd, stdout_path, stderr_path);
            for (pending.items, 0..) |item, idx| {
                if (PackageKey.eql(item.key(), pkg.key())) {
                    _ = pending.orderedRemove(idx);
                    break;
                }
            }
            try unpacked.append(allocator, pkg);
            progressed = true;
        }

        const unpacked_snapshot = try allocator.dupe(Package, unpacked.items);
        for (unpacked_snapshot) |pkg| {
            const cmd = try launcherCommand(allocator, launcher, dpkg, root, architecture, "none", "probe_configure", pkg, &.{});
            probes += 1;
            if (probes > maximum_probes) return error.ProbeLimitExceeded;
            const res = try probe(allocator, cmd, evidence);
            if (res.status != 0) {
                if (std.mem.indexOf(u8, res.output, "dependency problems") == null) {
                    return error.ReferenceConfigureRefused;
                }
                const sel = try pkg.selector(allocator);
                try deferred.append(allocator, sel);
                const prefix_len = @min(res.output.len, 4096);
                var prefix_hex = try allocator.alloc(u8, prefix_len * 2);
                for (res.output[0..prefix_len], 0..) |b, bi| {
                    const h = std.fmt.bytesToHex([1]u8{b}, .lower);
                    prefix_hex[bi * 2] = h[0];
                    prefix_hex[bi * 2 + 1] = h[1];
                }
                var out_digest: [64]u8 = undefined;
                std.crypto.hash.sha2.Sha512.hash(res.output, &out_digest, .{});
                try refusals.append(allocator, .{
                    .selector = sel,
                    .operation = "probe_configure",
                    .exit_status = res.status,
                    .output_bytes = res.output.len,
                    .output_prefix_hex = prefix_hex,
                    .output_sha512 = std.fmt.bytesToHex(out_digest, .lower),
                });
                continue;
            }

            {
                var statuses = try currentStatuses(allocator, root);
                defer statuses.deinit();
                const current = statuses.get(pkg.key()) orelse return error.ReferencePackageStateChanged;
                if (!std.mem.eql(u8, current.status, "install ok unpacked") or
                    !std.mem.eql(u8, current.version, pkg.version))
                {
                    return error.ReferencePackageStateChanged;
                }
            }

            const profile = packageProfile(pkg.name);
            if (!std.mem.eql(u8, profile, "none")) {
                if (profilePinnedVersion(profile) == null or !profileVersionMatches(profile, pkg.version)) {
                    return error.RuntimeProfileVersionMismatch;
                }
            }

            const sel = try pkg.selector(allocator);
            const prestate_opt = targets.get(sel);
            if (prestate_opt != null and std.mem.eql(u8, sel, "sudo:amd64")) {
                const comp_key: PackageKey = .{
                    .name = sudo_prestate_companion.name,
                    .architecture = sudo_prestate_companion.architecture,
                };
                var statuses = try currentStatuses(allocator, root);
                defer statuses.deinit();
                const comp_state = statuses.get(comp_key);
                if (comp_state == null or
                    !std.mem.eql(u8, comp_state.?.status, "install ok installed") or
                    !std.mem.eql(u8, comp_state.?.version, sudo_prestate_companion.version))
                {
                    if (configured.contains(comp_key) or
                        (comp_state != null and !std.mem.eql(u8, comp_state.?.version, sudo_prestate_companion.version)))
                    {
                        return error.MissingSudoPrestateCompanion;
                    }
                    try deferred.append(allocator, sel);
                    continue;
                }
            }
            _ = targets.remove(sel);
            var operation: []const u8 = "configure";
            if (prestate_opt) |ps| {
                try capturePrestate(allocator, launcher, dpkg, root, evidence, architecture, pkg, ps, stdout_path, stderr_path);
                if (targets.count() == 0) return;
                if (std.mem.eql(u8, ps.status, "half-configured")) {
                    var statuses = try currentStatuses(allocator, root);
                    defer statuses.deinit();
                    const after_cap = statuses.get(pkg.key()) orelse return error.CapturedPrestateStateChanged;
                    if (!std.mem.eql(u8, after_cap.status, "install ok half-configured") or
                        !std.mem.eql(u8, after_cap.version, pkg.version))
                    {
                        return error.CapturedPrestateStateChanged;
                    }
                    operation = "continue_prestate";
                }
            }

            const conf_cmd = try launcherCommand(allocator, launcher, dpkg, root, architecture, profile, operation, pkg, &.{});
            try apply(allocator, conf_cmd, stdout_path, stderr_path);
            for (unpacked.items, 0..) |item, idx| {
                if (PackageKey.eql(item.key(), pkg.key())) {
                    _ = unpacked.orderedRemove(idx);
                    break;
                }
            }
            try configured.put(pkg.key(), {});
            progressed = true;
        }

        if (!progressed) {
            {
                var out = std.Io.Writer.Allocating.init(allocator);
                defer out.deinit();
                try out.writer.print(
                    "{{\"base_cycle_applied\":{s},\"deferred\":",
                    .{if (cycle_broken) "true" else "false"},
                );
                try writeJsonStringSlice(&out.writer, deferred.items);
                try out.writer.print(
                    ",\"kbd_cycle_applied\":{s},\"openssl_cycle_applied\":{s},\"refusals\":[",
                    .{
                        if (kbd_configured) "true" else "false",
                        if (openssl_configured) "true" else "false",
                    },
                );
                const cap = @min(refusals.items.len, 128);
                for (refusals.items[0..cap], 0..) |r, r_idx| {
                    if (r_idx > 0) try out.writer.writeByte(',');
                    try out.writer.print(
                        "{{\"exit_status\":{d},\"operation\":\"{s}\",\"output_bytes\":{d},\"output_prefix_hex\":\"{s}\",\"output_sha512\":\"{s}\",\"selector\":",
                        .{ r.exit_status, r.operation, r.output_bytes, r.output_prefix_hex, &r.output_sha512 },
                    );
                    try writeJsonString(&out.writer, r.selector);
                    try out.writer.writeByte('}');
                }
                try out.writer.print(
                    "],\"refusals_truncated\":{s}}}\n",
                    .{if (refusals.items.len > 128) "true" else "false"},
                );
                try writeEvidenceFile(allocator, evidence, "reference-no-progress.json", out.written());
            }

            if (!cycle_broken) {
                const libgcc_key: PackageKey = .{ .name = "libgcc-s1", .architecture = architecture };
                if (!all_packages.contains(libgcc_key)) return error.MissingBaseCyclePackages;
                var found_libgcc = false;
                for (unpacked.items) |u| {
                    if (PackageKey.eql(u.key(), libgcc_key)) {
                        found_libgcc = true;
                        break;
                    }
                }
                if (!found_libgcc) return error.BaseCycleStatusNotReady;
                const selected = try execBreakBaseCycle(allocator, launcher, dpkg, root, evidence, architecture, &all_packages, stdout_path, stderr_path);
                for (unpacked.items, 0..) |item, idx| {
                    if (PackageKey.eql(item.key(), selected.key())) {
                        _ = unpacked.orderedRemove(idx);
                        break;
                    }
                }
                try configured.put(selected.key(), {});
                cycle_broken = true;
                continue;
            }

            var has_libssl = false;
            var has_legacy = false;
            var has_kbd = false;
            var has_cs_linux = false;
            var has_cs = false;
            for (unpacked.items) |u| {
                if (std.mem.eql(u8, u.name, "libssl3t64")) has_libssl = true;
                if (std.mem.eql(u8, u.name, "openssl-provider-legacy")) has_legacy = true;
                if (std.mem.eql(u8, u.name, "kbd")) has_kbd = true;
                if (std.mem.eql(u8, u.name, "console-setup-linux")) has_cs_linux = true;
                if (std.mem.eql(u8, u.name, "console-setup")) has_cs = true;
            }

            if (!openssl_configured and has_libssl and has_legacy) {
                probes += 2;
                if (probes > maximum_probes) return error.ProbeLimitExceeded;
                const selected = try execConfigureOpensslCycle(allocator, launcher, dpkg, root, evidence, architecture, &all_packages, stdout_path, stderr_path);
                for (selected) |sel_pkg| {
                    for (unpacked.items, 0..) |item, idx| {
                        if (PackageKey.eql(item.key(), sel_pkg.key())) {
                            _ = unpacked.orderedRemove(idx);
                            break;
                        }
                    }
                    try configured.put(sel_pkg.key(), {});
                }
                openssl_configured = true;
                continue;
            }

            if (!kbd_configured and has_kbd and has_cs_linux and has_cs) {
                probes += 1;
                if (probes > maximum_probes) return error.ProbeLimitExceeded;
                const selected = try execBreakKbdCycle(allocator, launcher, dpkg, root, evidence, architecture, &all_packages, stdout_path, stderr_path);
                for (unpacked.items, 0..) |item, idx| {
                    if (PackageKey.eql(item.key(), selected.key())) {
                        _ = unpacked.orderedRemove(idx);
                        break;
                    }
                }
                try configured.put(selected.key(), {});
                kbd_configured = true;
                continue;
            }

            return error.CycleNoProgress;
        }
    }

    if (targets.count() != 0) return error.PrestatePackageNeverConfigured;
    if (configured.count() != packages.len) return error.ClosureNotFullyConfigured;
    try execProcessTriggers(allocator, launcher, dpkg, root, evidence, architecture, &all_packages, stdout_path, stderr_path);
}

pub fn report(allocator: std.mem.Allocator, root: []const u8, cache: []const u8, evidence: []const u8) !void {
    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/reference-archives.tsv", .{std.mem.trimEnd(u8, evidence, "/")});
    const packages = try packagesFromManifest(allocator, manifest_path, cache, maximum_packages);
    var records = try currentStatuses(allocator, root);
    defer records.deinit();
    if (records.count() != packages.len) return error.DatabaseDiffersFromSignedClosure;

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    for (packages) |pkg| {
        const st = records.get(pkg.key()) orelse return error.PackageNotInstalledAtSignedVersion;
        if (!std.mem.eql(u8, st.status, "install ok installed") or
            !std.mem.eql(u8, st.version, pkg.version))
        {
            return error.PackageNotInstalledAtSignedVersion;
        }
        const sel = try pkg.selector(allocator);
        try out.writer.print("ii  {s} {s}\n", .{ sel, pkg.version });
    }
    try writeEvidenceFile(allocator, evidence, "reference-installed.txt", out.written());

    const root_fd = try reference_paths.openAbsolute(root, true);
    defer _ = linux.close(root_fd);
    const entries = try listDirectoryBeneath(allocator, root_fd, "var/lib/dpkg/info");
    if (entries.len > maximum_packages * 12) return error.InfoDirectoryExceedsBound;
    for (entries) |entry| {
        if (std.mem.endsWith(u8, entry, ".list")) {
            const rel = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}", .{entry});
            const data = try reference_paths.readRootFile(allocator, root, rel, 8 * 1024 * 1024);
            var lines = std.mem.splitAny(u8, data, "\r\n");
            while (lines.next()) |line| {
                if (std.mem.eql(u8, line, "/dev/null")) return error.PackageClaimsExcludedChrootDevice;
            }
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    var dpkg: ?[]const u8 = null;
    var root: ?[]const u8 = null;
    var cache: ?[]const u8 = null;
    var evidence: ?[]const u8 = null;
    var prove_base_cycle_setpriv: ?[]const u8 = null;
    var launcher_path: ?[]const u8 = null;
    var runtime_path: ?[]const u8 = null;
    var architecture: ?[]const u8 = null;
    var report_only = false;
    var prestates = std.ArrayList(PrestateSpec).empty;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--prove-base-cycle")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            prove_base_cycle_setpriv = args[i];
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
            launcher_path = args[i];
        } else if (std.mem.eql(u8, arg, "--runtime")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            runtime_path = args[i];
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            architecture = args[i];
        } else if (std.mem.eql(u8, arg, "--prestate")) {
            i += 1;
            if (i >= args.len) return error.InvalidCliArguments;
            try prestates.append(allocator, try parsePrestateSpec(args[i]));
        } else {
            return error.InvalidCliArguments;
        }
    }

    const root_path = root orelse return error.InvalidCliArguments;
    const cache_path = cache orelse return error.InvalidCliArguments;
    const evidence_path = evidence orelse return error.InvalidCliArguments;
    const arch = architecture orelse return error.InvalidCliArguments;
    if (!std.mem.eql(u8, arch, "amd64") and !std.mem.eql(u8, arch, "arm64")) {
        return error.UnsupportedReferenceArchitecture;
    }
    if (!std.mem.startsWith(u8, root_path, "/") or
        !std.mem.startsWith(u8, cache_path, "/") or
        !std.mem.startsWith(u8, evidence_path, "/"))
    {
        return error.NoncanonicalReferencePath;
    }

    if (report_only) {
        try report(allocator, root_path, cache_path, evidence_path);
        return;
    }

    const dpkg_path = dpkg orelse return error.InvalidCliArguments;
    const l_path = launcher_path orelse return error.InvalidCliArguments;
    const r_path = runtime_path orelse return error.InvalidCliArguments;
    if (!std.mem.startsWith(u8, dpkg_path, "/")) return error.NoncanonicalReferencePath;

    _ = try reference_paths.protected(l_path, false);
    _ = try reference_paths.protected(dpkg_path, false);
    _ = try reference_paths.protected(r_path, true);
    _ = try reference_paths.protected(cache_path, true);
    _ = try reference_paths.protected(evidence_path, true);

    const launcher: Launcher = .{ .path = l_path, .runtime = r_path };
    if (prove_base_cycle_setpriv) |setpriv_path| {
        if (!std.mem.eql(u8, arch, "amd64") or prestates.items.len != 0) {
            return error.CycleProofPrestateInvalid;
        }
        try proveBaseCycle(allocator, launcher, dpkg_path, root_path, cache_path, evidence_path, setpriv_path);
        return;
    }

    try install(allocator, launcher, dpkg_path, root_path, cache_path, evidence_path, arch, prestates.items);
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
    try tmp.dir.createDirPath(std.testing.io, "packages-v2/objects");
    const deb_name = try std.fmt.allocPrint(allocator, "packages-v2/objects/sha512-{s}", .{digest});
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

test "reference order launcherCommand and parsePrestateSpec" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const spec = try parsePrestateSpec("systemd:amd64=half-configured:/root/prestates/systemd");
    try std.testing.expectEqualStrings("systemd:amd64", spec.selector);
    try std.testing.expectEqualStrings("half-configured", spec.status);
    try std.testing.expectEqualStrings("/root/prestates/systemd", spec.destination);
    try std.testing.expectError(error.InvalidPrestateTargetFormat, parsePrestateSpec("systemd=unpacked:/dst"));
    try std.testing.expectError(error.InvalidPrestateTargetFormat, parsePrestateSpec("systemd:amd64=installed:/dst"));
    try std.testing.expectError(error.InvalidPrestateTargetFormat, parsePrestateSpec("systemd:amd64=unpacked:relative"));

    const launcher: Launcher = .{ .path = "/tools/reference-launcher", .runtime = "/tools/reference-runtime" };
    const systemd_pkg: Package = .{
        .name = "systemd",
        .version = profile_versions[0].version,
        .architecture = "amd64",
        .digest = &@as([128]u8, @splat('a')),
        .declared_size = 42,
        .archive = "/cache/packages-v2/objects/sha512-a",
    };
    const unpack_cmd = try launcherCommand(allocator, launcher, "/pinned/dpkg", "/root", "amd64", "none", "unpack", systemd_pkg, &.{});
    try std.testing.expectEqual(@as(usize, 11), unpack_cmd.len);
    try std.testing.expectEqualStrings("/tools/reference-launcher", unpack_cmd[0]);
    try std.testing.expectEqualStrings("unpack", unpack_cmd[5]);
    try std.testing.expectEqualStrings("42", unpack_cmd[10]);

    const conf_cmd = try launcherCommand(allocator, launcher, "/pinned/dpkg", "/root", "amd64", "systemd", "configure", systemd_pkg, &.{});
    try std.testing.expectEqual(@as(usize, 8), conf_cmd.len);
    try std.testing.expectEqualStrings("systemd", conf_cmd[4]);
    try std.testing.expectEqualStrings("configure", conf_cmd[5]);

    // kbd cycle and trigger handler launcherCommand and negative refusals
    try std.testing.expectEqual(@as(usize, 4), kbd_cycle.len);
    try std.testing.expectEqualStrings("kbd", kbd_cycle[0].name);
    try std.testing.expectEqualStrings("2.7.1-2ubuntu2", kbd_cycle[0].version);
    try std.testing.expectEqualStrings("console-setup-linux", kbd_cycle[1].name);
    try std.testing.expectEqualStrings("1.237ubuntu3.1", kbd_cycle[1].version);
    try std.testing.expectEqualStrings("console-setup", kbd_cycle[2].name);
    try std.testing.expectEqualStrings("1.237ubuntu3.1", kbd_cycle[2].version);
    try std.testing.expectEqualStrings("libc6", kbd_cycle[3].name);
    try std.testing.expectEqual(@as(usize, 2), trigger_handlers.len);
    try std.testing.expectEqualStrings("libc-bin", trigger_handlers[0].name);
    try std.testing.expectEqualStrings("ldconfig", trigger_handlers[0].pending);
    try std.testing.expectEqualStrings("procps", trigger_handlers[1].name);
    try std.testing.expectEqualStrings("/usr/lib/sysctl.d", trigger_handlers[1].pending);

    var kbd_pkgs: [4]Package = undefined;
    for (kbd_cycle, 0..) |pin, idx| {
        kbd_pkgs[idx] = .{
            .name = pin.name,
            .version = pin.version,
            .architecture = pin.architecture,
            .digest = pin.sha512,
            .declared_size = pin.size,
            .archive = try std.fmt.allocPrint(allocator, "/cache/{s}.deb", .{pin.name}),
        };
    }
    const kbd_launch = try launcherCommand(allocator, launcher, "/pinned/dpkg", "/root", "amd64", kbd_cycle_profile, "break_kbd_cycle", kbd_pkgs[0], &kbd_pkgs);
    try std.testing.expectEqual(@as(usize, 12), kbd_launch.len);
    try std.testing.expectEqualStrings("kbd_cycle", kbd_launch[4]);
    try std.testing.expectEqualStrings("break_kbd_cycle", kbd_launch[5]);
    try std.testing.expectEqualStrings("kbd:amd64", kbd_launch[6]);
    try std.testing.expectError(error.CycleIdentityChanged, launcherCommand(allocator, launcher, "/pinned/dpkg", "/root", "arm64", kbd_cycle_profile, "break_kbd_cycle", kbd_pkgs[0], &kbd_pkgs));
    try std.testing.expectError(error.CycleIdentityChanged, launcherCommand(allocator, launcher, "/pinned/dpkg", "/root", "amd64", "none", "break_kbd_cycle", kbd_pkgs[0], &kbd_pkgs));
    try std.testing.expectError(error.CycleIdentityChanged, launcherCommand(allocator, launcher, "/pinned/dpkg", "/root", "amd64", kbd_cycle_profile, "break_kbd_cycle", kbd_pkgs[1], &kbd_pkgs));

    for (trigger_handlers) |binding| {
        const handler_pkg: Package = .{
            .name = binding.name,
            .version = binding.version,
            .architecture = binding.architecture,
            .digest = binding.sha512,
            .declared_size = binding.size,
            .archive = try std.fmt.allocPrint(allocator, "/cache/{s}.deb", .{binding.name}),
        };
        const trig_launch = try launcherCommand(allocator, launcher, "/pinned/dpkg", "/root", "amd64", binding.profile, "triggers_only", handler_pkg, &.{});
        try std.testing.expectEqual(@as(usize, 9), trig_launch.len);
        try std.testing.expectEqualStrings(binding.profile, trig_launch[4]);
        try std.testing.expectEqualStrings("triggers_only", trig_launch[5]);
        try std.testing.expectError(error.TriggerHandlerPinMismatch, launcherCommand(allocator, launcher, "/pinned/dpkg", "/root", "arm64", binding.profile, "triggers_only", handler_pkg, &.{}));
        try std.testing.expectError(error.TriggerHandlerPinMismatch, launcherCommand(allocator, launcher, "/pinned/dpkg", "/root", "amd64", "systemd", "triggers_only", handler_pkg, &.{}));
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "evidence");
    const tmp_root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const evidence_dir = try std.fs.path.join(allocator, &.{ tmp_root, "evidence" });
    const probe_res = try probe(allocator, &.{ "/bin/sh", "-c", "printf 'probe-ok\\n'" }, evidence_dir);
    try std.testing.expectEqual(@as(u8, 0), probe_res.status);
    try std.testing.expectEqualStrings("probe-ok\n", probe_res.output);
    const root_fd = try reference_paths.openAbsolute(tmp_root, true);
    defer _ = linux.close(root_fd);
    const remaining = try listDirectoryBeneath(allocator, root_fd, "evidence");
    try std.testing.expectEqual(@as(usize, 0), remaining.len);
}

test "hosted base cycle pending keeps the original status and version schedule comparison" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const candidate_text =
        "Package: gcc-16-base\n" ++
        "Status: install ok installed\n" ++
        "Architecture: amd64\n" ++
        "Version: 16-20260405-0ubuntu1\n\n" ++
        "Package: libc6\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 2.42-2ubuntu2\n" ++
        "Conffiles:\n" ++
        " /etc/ld.so.conf.d/x86_64-linux-gnu.conf newconffile\n\n" ++
        "Package: libgcc-s1\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 16-20260405-0ubuntu1\n";
    const pending_text =
        "Package: gcc-16-base\n" ++
        "Status: install ok installed\n" ++
        "Architecture: amd64\n" ++
        "Version: 16-20260405-0ubuntu1\n\n" ++
        "Package: libc6\n" ++
        "Status: install ok half-configured\n" ++
        "Architecture: amd64\n" ++
        "Version: 2.42-2ubuntu2\n" ++
        "Conffiles:\n" ++
        " /etc/ld.so.conf.d/x86_64-linux-gnu.conf cadc57d8e0387642c3de4bb1edff3f02\n\n" ++
        "Package: libgcc-s1\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 16-20260405-0ubuntu1\n";

    const candidate = try parseDatabaseRecords(allocator, candidate_text);
    const pending = try parseDatabaseRecords(allocator, pending_text);
    const libc: Package = .{
        .name = "libc6",
        .version = "2.42-2ubuntu2",
        .architecture = "amd64",
        .digest = base_cycle[0].sha512,
        .declared_size = base_cycle[0].size,
        .archive = "/cache/libc6.deb",
    };

    try std.testing.expect(scheduleConserved(candidate, pending, libc));

    const unpacked_libc = try cloneRecords(allocator, pending);
    try findRecord(unpacked_libc, libc.key()).?.fields.put("status", "install ok unpacked");
    try std.testing.expect(!scheduleConserved(candidate, unpacked_libc, libc));

    const wrong_libc_ver = try cloneRecords(allocator, pending);
    try findRecord(wrong_libc_ver, libc.key()).?.fields.put("version", "2.42-2ubuntu3");
    try std.testing.expect(!scheduleConserved(candidate, wrong_libc_ver, libc));

    const installed_libgcc = try cloneRecords(allocator, pending);
    try findRecord(installed_libgcc, .{ .name = "libgcc-s1", .architecture = "amd64" }).?.fields.put("status", "install ok installed");
    try std.testing.expect(!scheduleConserved(candidate, installed_libgcc, libc));

    const wrong_gcc_ver = try cloneRecords(allocator, pending);
    try findRecord(wrong_gcc_ver, .{ .name = "gcc-16-base", .architecture = "amd64" }).?.fields.put("version", "16-0");
    try std.testing.expect(!scheduleConserved(candidate, wrong_gcc_ver, libc));

    try std.testing.expect(!scheduleConserved(candidate, pending[0..2], libc));

    var extra = try allocator.alloc(StanzaRecord, pending.len + 1);
    @memcpy(extra[0..pending.len], pending);
    var extra_fields = std.StringHashMap([]const u8).init(allocator);
    try extra_fields.put("package", "extra");
    try extra_fields.put("architecture", "amd64");
    try extra_fields.put("version", "1");
    try extra_fields.put("status", "install ok installed");
    extra[pending.len] = .{
        .key = .{ .name = "extra", .architecture = "amd64" },
        .fields = extra_fields,
    };
    try std.testing.expect(!scheduleConserved(candidate, extra, libc));
}

test "report splits dpkg .list files on bare CR and CRLF like bytes.splitlines and enforces signed closure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    reference_paths.setTestRootOverride(tmp_abs);
    defer reference_paths.setTestRootOverride(null);

    try tmp.dir.createDirPath(std.testing.io, "root/var/lib/dpkg/info");
    try tmp.dir.createDirPath(std.testing.io, "cache/packages-v2/objects");
    try tmp.dir.createDirPath(std.testing.io, "evidence");

    const archive_bytes = "fixture-deb-bytes";
    var archive_digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(archive_bytes, &archive_digest, .{});
    const archive_hex = std.fmt.bytesToHex(archive_digest, .lower);
    const obj_rel = try std.fmt.allocPrint(allocator, "cache/packages-v2/objects/sha512-{s}", .{&archive_hex});
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = obj_rel, .data = archive_bytes });

    const manifest = try std.fmt.allocPrint(allocator, "fixture\t1.0\tamd64\t{s}\t{d}\n", .{ &archive_hex, archive_bytes.len });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "evidence/reference-archives.tsv", .data = manifest });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "Package: fixture\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/info/fixture.list",
        .data = "/.\n/usr\n/usr/share/doc/fixture\n/dev/null0\r/usr/share/doc/fixture/README\r\n",
    });

    const root_dir = try std.fs.path.join(allocator, &.{ tmp_abs, "root" });
    const cache_dir = try std.fs.path.join(allocator, &.{ tmp_abs, "cache" });
    const evidence_dir = try std.fs.path.join(allocator, &.{ tmp_abs, "evidence" });

    try report(allocator, root_dir, cache_dir, evidence_dir);
    const installed = try reference_paths.readRootFile(allocator, evidence_dir, "reference-installed.txt", 4096);
    try std.testing.expectEqualStrings("ii  fixture:amd64 1.0\n", installed);

    for ([_][]const u8{
        "/dev/null\n",
        "/usr/share/doc/fixture\r/dev/null",
        "/dev/null\r/usr/share/doc/fixture\n",
        "/usr/share/doc/fixture\r\n/dev/null\r\n",
    }) |bad_list| {
        try tmp.dir.writeFile(std.testing.io, .{
            .sub_path = "root/var/lib/dpkg/info/fixture.list",
            .data = bad_list,
        });
        try std.testing.expectError(error.PackageClaimsExcludedChrootDevice, report(allocator, root_dir, cache_dir, evidence_dir));
    }
}

test "kbd cycle breaker and multi-handler trigger settlement enforce dpkg order and state conservation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    reference_paths.setTestRootOverride(tmp_abs);
    defer reference_paths.setTestRootOverride(null);

    try tmp.dir.createDirPath(std.testing.io, "root/var/lib/dpkg/info");
    try tmp.dir.createDirPath(std.testing.io, "root/var/lib/dpkg/triggers");
    try tmp.dir.createDirPath(std.testing.io, "root/var/lib/dpkg/updates");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/File", .data = "/usr/lib/sysctl.d procps/noawait\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/Lock", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/Unincorp", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/triggers/ldconfig", .data = "libc-bin\n" });

    const root_dir = try std.fs.path.join(allocator, &.{ tmp_abs, "root" });

    const NoopArchive = struct {
        fn verify(_: Package) !void {}
    };
    test_verify_archive_hook = NoopArchive.verify;
    defer test_verify_archive_hook = null;

    var all_pkgs = std.HashMap(PackageKey, Package, PackageKeyContext, 80).init(allocator);
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
    for (trigger_handlers) |pin| {
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
            return error.MissingControlTarFixture;
        }
    };

    const initial_kbd_status =
        "Package: kbd\nStatus: install ok unpacked\nArchitecture: amd64\nVersion: 2.7.1-2ubuntu2\n\n" ++
        "Package: console-setup-linux\nStatus: install ok unpacked\nArchitecture: all\nVersion: 1.237ubuntu3.1\n\n" ++
        "Package: console-setup\nStatus: install ok unpacked\nArchitecture: all\nVersion: 1.237ubuntu3.1\n\n" ++
        "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.43-2ubuntu2.4\n\n";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/status", .data = initial_kbd_status });

    const KbdRunner = struct {
        var dir: ?std.Io.Dir = null;
        var after_status: []const u8 = "";

        fn run(_: std.mem.Allocator, verb: []const u8, packages: []const Package, profile: []const u8) !DpkgRunResult {
            try std.testing.expectEqualStrings("break_kbd_cycle", verb);
            try std.testing.expectEqual(@as(usize, 1), packages.len);
            try std.testing.expectEqualStrings("kbd", packages[0].name);
            try std.testing.expectEqualStrings("none", profile);
            try dir.?.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/status", .data = after_status });
            return .{ .returncode = 0, .stdout = "", .stderr = "" };
        }
    };
    KbdRunner.dir = tmp.dir;
    KbdRunner.after_status =
        "Package: kbd\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.7.1-2ubuntu2\n\n" ++
        "Package: console-setup-linux\nStatus: install ok unpacked\nArchitecture: all\nVersion: 1.237ubuntu3.1\n\n" ++
        "Package: console-setup\nStatus: install ok unpacked\nArchitecture: all\nVersion: 1.237ubuntu3.1\n\n" ++
        "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.43-2ubuntu2.4\n\n";

    const kbd_res = try breakKbdCycle(allocator, root_dir, &all_pkgs, "amd64", FetchTar.fetch, KbdRunner.run);
    try std.testing.expectEqual(@as(u8, 0), kbd_res.returncode);

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/var/lib/dpkg/status", .data = initial_kbd_status });
    KbdRunner.after_status =
        "Package: kbd\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.7.1-2ubuntu2\n\n" ++
        "Package: console-setup-linux\nStatus: install ok unpacked\nArchitecture: all\nVersion: 1.237ubuntu3.1\n\n" ++
        "Package: console-setup\nStatus: install ok installed\nArchitecture: all\nVersion: 1.237ubuntu3.1\n\n" ++
        "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.43-2ubuntu2.4\n\n";
    try std.testing.expectError(
        error.KbdCycleMutatedUnexpectedPackageStatus,
        breakKbdCycle(allocator, root_dir, &all_pkgs, "amd64", FetchTar.fetch, KbdRunner.run),
    );

    var trig_statuses = DatabaseMap.init(allocator);
    for (trigger_handlers) |pin| {
        try trig_statuses.put(.{ .name = pin.name, .architecture = pin.architecture }, .{
            .name = pin.name,
            .architecture = pin.architecture,
            .version = pin.version,
            .status = "install ok triggers-pending",
        });
    }
    const ready_handlers = try triggerHandlerPackages(allocator, &all_pkgs, &trig_statuses, "amd64");
    try std.testing.expectEqual(@as(usize, 2), ready_handlers.len);
    try std.testing.expectEqualStrings("libc-bin", ready_handlers[0].name);
    try std.testing.expectEqualStrings("procps", ready_handlers[1].name);
}

test "debian stable amd64 base cycle, openssl cycle, trigger handler, and systemd profile bindings admit trixie closure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const NoopArchive = struct {
        fn verify(_: Package) !void {}
    };
    test_verify_archive_hook = NoopArchive.verify;
    defer test_verify_archive_hook = null;

    var all_pkgs = std.HashMap(PackageKey, Package, PackageKeyContext, 80).init(allocator);
    for (debian_base_cycle) |pin| {
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
    for (debian_openssl_cycle) |pin| {
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
    const debian_libc_bin: Package = .{
        .name = debian_libc_bin_trigger_handler.name,
        .version = debian_libc_bin_trigger_handler.version,
        .architecture = debian_libc_bin_trigger_handler.architecture,
        .digest = debian_libc_bin_trigger_handler.sha512,
        .declared_size = debian_libc_bin_trigger_handler.size,
        .archive = "/cache/libc-bin.deb",
    };
    try all_pkgs.put(debian_libc_bin.key(), debian_libc_bin);

    const FetchDebianTar = struct {
        fn fetch(alloc: std.mem.Allocator, archive: []const u8) ![]const u8 {
            const base_name = std.fs.path.stem(archive);
            for (debian_base_cycle) |pin| {
                if (std.mem.eql(u8, pin.name, base_name)) {
                    const ctrl = try std.fmt.allocPrint(
                        alloc,
                        "Package: {s}\nVersion: {s}\nArchitecture: {s}\nDepends: {s}\n",
                        .{ pin.name, pin.version, pin.architecture, pin.depends },
                    );
                    if (std.mem.eql(u8, base_name, "libgcc-s1")) {
                        var entries = std.ArrayList(TarFixtureMember).empty;
                        for (pin.members) |m| {
                            if (std.mem.eql(u8, m, ".")) {
                                try entries.append(alloc, .{ .name = ".", .content = null });
                            } else if (std.mem.eql(u8, m, "./control")) {
                                try entries.append(alloc, .{ .name = "./control", .content = ctrl });
                            } else if (std.mem.eql(u8, m, "./triggers")) {
                                try entries.append(alloc, .{ .name = "./triggers", .content = debian_libgcc_triggers });
                            } else {
                                try entries.append(alloc, .{ .name = m, .content = "fixture\n" });
                            }
                        }
                        return buildTestControlTar(alloc, entries.items);
                    }
                    return buildTestControlTar(alloc, &.{
                        .{ .name = ".", .content = null },
                        .{ .name = "./control", .content = ctrl },
                    });
                }
            }
            for (debian_openssl_cycle) |pin| {
                if (std.mem.eql(u8, pin.name, base_name)) {
                    const ctrl = try std.fmt.allocPrint(
                        alloc,
                        "Package: {s}\nVersion: {s}\nArchitecture: {s}\nDepends: {s}\n",
                        .{ pin.name, pin.version, pin.architecture, pin.depends },
                    );
                    return buildTestControlTar(alloc, &.{
                        .{ .name = ".", .content = null },
                        .{ .name = "./control", .content = ctrl },
                    });
                }
            }
            return error.MissingControlTarFixture;
        }
    };

    var base_statuses = DatabaseMap.init(allocator);
    for (debian_base_cycle) |pin| {
        try base_statuses.put(.{ .name = pin.name, .architecture = pin.architecture }, .{
            .name = pin.name,
            .architecture = pin.architecture,
            .version = pin.version,
            .status = pin.status,
        });
    }
    const base_pair = try verifyBaseCycle(allocator, &all_pkgs, &base_statuses, "amd64", FetchDebianTar.fetch);
    try std.testing.expectEqualStrings("libc6", base_pair[0].name);
    try std.testing.expectEqualStrings("libgcc-s1", base_pair[1].name);

    var openssl_statuses = DatabaseMap.init(allocator);
    for (debian_openssl_cycle) |pin| {
        try openssl_statuses.put(.{ .name = pin.name, .architecture = pin.architecture }, .{
            .name = pin.name,
            .architecture = pin.architecture,
            .version = pin.version,
            .status = pin.status,
        });
    }
    const openssl_pair = try verifyOpensslCycle(allocator, &all_pkgs, &openssl_statuses, "amd64", FetchDebianTar.fetch);
    try std.testing.expectEqualStrings("libssl3t64", openssl_pair[0].name);
    try std.testing.expectEqualStrings("openssl-provider-legacy", openssl_pair[1].name);

    var trig_statuses = DatabaseMap.init(allocator);
    try trig_statuses.put(debian_libc_bin.key(), .{
        .name = debian_libc_bin.name,
        .architecture = debian_libc_bin.architecture,
        .version = debian_libc_bin.version,
        .status = "install ok triggers-pending",
    });
    const ready_handlers = try triggerHandlerPackages(allocator, &all_pkgs, &trig_statuses, "amd64");
    try std.testing.expectEqual(@as(usize, 1), ready_handlers.len);
    try std.testing.expectEqualStrings("libc-bin", ready_handlers[0].name);

    const launcher: Launcher = .{ .path = "/bin/launcher", .runtime = "/runtime" };
    const deb_base_pkgs = try debianBaseCyclePackages(&all_pkgs, "amd64");
    const base_cmd = try launcherCommand(allocator, launcher, "/usr/bin/dpkg", "/root", "amd64", base_cycle_profile, "break_base_cycle", deb_base_pkgs[1], &deb_base_pkgs);
    try std.testing.expectEqual(@as(usize, 11), base_cmd.len);

    const deb_openssl_pkgs = try opensslCyclePackages(&all_pkgs, "amd64");
    const openssl_cmd = try launcherCommand(allocator, launcher, "/usr/bin/dpkg", "/root", "amd64", openssl_cycle_profile, "configure_openssl_cycle", deb_openssl_pkgs[0], &deb_openssl_pkgs);
    try std.testing.expectEqual(@as(usize, 13), openssl_cmd.len);

    const trig_cmd = try launcherCommand(allocator, launcher, "/usr/bin/dpkg", "/root", "amd64", "none", "triggers_only", debian_libc_bin, &.{});
    try std.testing.expectEqual(@as(usize, 9), trig_cmd.len);

    const debian_systemd: Package = .{
        .name = "systemd",
        .version = debian_systemd_profile_version.version,
        .architecture = "amd64",
        .digest = debian_base_cycle[0].sha512,
        .declared_size = 100,
        .archive = "/cache/systemd.deb",
    };
    const sysd_cmd = try launcherCommand(allocator, launcher, "/usr/bin/dpkg", "/root", "amd64", "systemd", "configure", debian_systemd, &.{});
    try std.testing.expectEqual(@as(usize, 8), sysd_cmd.len);
}



const std = @import("std");
const linux = std.os.linux;
const private_network = @import("private_network");
const reference_namespaces = linux.CLONE.NEWNS | linux.CLONE.NEWPID | linux.CLONE.NEWNET;
const runtime = @import("real-snapshot-reference-runtime.zig");

const OpenHow = extern struct { flags: u64, mode: u64 = 0, resolve: u64 };
const resolve_no_symlinks: u64 = 0x02 | 0x04;
const proc_flags = linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC;
const mask_flags = linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC;
const close_range_cloexec: usize = 4;
const Bpf = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 };
const BpfProgram = extern struct { len: u16, filter: [*]const Bpf };
const deny_syscalls = [_]linux.SYS{
    .mount,         .umount2,       .pivot_root,        .unshare,   .setns,
    .fsopen,        .fsconfig,      .fsmount,           .open_tree, .move_mount,
    .mount_setattr, .mknodat,       .open_by_handle_at, .chroot,    .init_module,
    .finit_module,  .delete_module, .kexec_load,        .reboot,    .swapon,
    .swapoff,
} ++ (if (@import("builtin").cpu.arch == .x86_64)
    [_]linux.SYS{ .mknod, .kexec_file_load }
else
    [_]linux.SYS{});
const namespace_flags = linux.CLONE.NEWUSER | linux.CLONE.NEWNS |
    linux.CLONE.NEWPID | linux.CLONE.NEWNET | linux.CLONE.NEWUTS |
    linux.CLONE.NEWIPC | linux.CLONE.NEWCGROUP | linux.CLONE.NEWTIME;
const filesystem_account_caps = .{
    linux.CAP.CHOWN,   linux.CAP.DAC_OVERRIDE, linux.CAP.FOWNER,
    linux.CAP.FSETID,  linux.CAP.SETGID,       linux.CAP.SETUID,
    linux.CAP.SETFCAP,
};
// The kernel reads pid at byte 4; linux.cap_user_header_t uses usize and pads it to byte 8.
const CapHeader = extern struct { version: u32 = 0x20080522, pid: i32 = 0 };
comptime {
    std.debug.assert(@sizeOf(CapHeader) == 8 and @offsetOf(CapHeader, "pid") == 4);
}
const filter = generateFilter();
const archive_target: [*:0]const u8 = "/.debz-reference-archive";
const MountAttribute = extern struct {
    attr_set: u64 = 0,
    attr_clear: u64 = 0,
    propagation: u64 = 0,
    user_namespace_fd: u64 = 0,
};

fn cloneMountDescriptor(fd: i32) usize {
    return linux.syscall3(
        .open_tree,
        @bitCast(@as(isize, fd)),
        @intFromPtr(@as([*:0]const u8, "")),
        1 | (1 << @bitOffsetOf(linux.O, "CLOEXEC")) | linux.AT.EMPTY_PATH,
    );
}

fn setMountAttributes(fd: i32, attributes: *const MountAttribute) usize {
    return linux.syscall5(
        .mount_setattr,
        @bitCast(@as(isize, fd)),
        @intFromPtr(@as([*:0]const u8, "")),
        linux.AT.EMPTY_PATH,
        @intFromPtr(attributes),
        @sizeOf(MountAttribute),
    );
}
const environment: [*:null]const ?[*:0]const u8 = &.{
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/",
    "LC_ALL=C",
    "DEBIAN_FRONTEND=noninteractive",
    "DEBCONF_NONINTERACTIVE_SEEN=true",
    "DPKG_COLORS=never",
    null,
};

const Profile = enum { none, systemd, udev, sudo, libgcc_cycle, openssl_cycle, kbd_cycle };
const Verb = enum { probe_unpack, unpack, probe_configure, configure, continue_prestate, break_base_cycle, configure_openssl_cycle, break_kbd_cycle };
const ScriptBinding = struct {
    name: []const u8,
    version: []const u8,
    size: usize,
    digest: []const u8,
};
const script_bindings = [_]ScriptBinding{
    .{ .name = "systemd", .version = "259.5-0ubuntu3.4", .size = 5037, .digest = "d9df6a03ccb6b557c16ac1c674557a66c1db290f3c6d3cadbef335e0ce74e31d" },
    .{ .name = "udev", .version = "259.5-0ubuntu3.4", .size = 2578, .digest = "b7892e975bcce896c4938c2219a244fa03863d5eff37cd2eb66d2b8540f14606" },
    .{ .name = "sudo", .version = "1.9.17p2-1ubuntu3.1", .size = 1747, .digest = "fd4c65932ab3ab7ce90c3633c42b8ee7a36af2c8292142d6e0cd134dda4c6383" },
};
const dpkg_digests = [_][]const u8{
    "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5",
    "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79",
};
const CycleBinding = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8 = "amd64",
    depends: []const u8,
    archive_size: usize,
    archive_sha512: []const u8,
};
const base_cycle = [_]CycleBinding{
    .{ .name = "libc6", .version = "2.43-2ubuntu2.4", .depends = "libgcc-s1, libc-gconv-modules-extra (= 2.43-2ubuntu2.4)", .archive_size = 2104056, .archive_sha512 = "e27873bec6e0a7914834eac85748c31a360b44b0f0e971a7cd70439c2f9804e737f8f6113f15bb7f523d7a5d4a336173b43a5e22d804c440c8a11a5530bc6696" },
    .{ .name = "libgcc-s1", .version = "16-20260322-1ubuntu1", .depends = "gcc-16-base (= 16-20260322-1ubuntu1), libc6 (>= 2.35)", .archive_size = 80312, .archive_sha512 = "a34e93f253ca90bd331c5eee563be6ebcc14dbf08147e82b9479f972fe566c83263b644e348757af1853f8663cb8ca2349e2c013e4a0ca0e3ea3d631297576b2" },
    .{ .name = "gcc-16-base", .version = "16-20260322-1ubuntu1", .depends = "", .archive_size = 38296, .archive_sha512 = "0767f731e71e709736596d52dbe181245a8ca181cdadbac6226aad5aa7151d8ce5149ad28625facc61d8882e76fc387af5336dc289126a0bf830b9e599b3922c" },
    .{ .name = "libc-gconv-modules-extra", .version = "2.43-2ubuntu2.4", .depends = "", .archive_size = 1362202, .archive_sha512 = "c385f1ca4f8054e59f977a38819e31d6f2429909ce0a88c734c874ce163851dfa7e565dded6c65c3feb3bc8cf074498b45a4c2226bb8e17a2bc8b95027a29692" },
};
const openssl_cycle = [_]CycleBinding{
    .{ .name = "libssl3t64", .version = "3.5.5-1ubuntu3.6", .depends = "libc6 (>= 2.38), libzstd1 (>= 1.5.5), zlib1g (>= 1:1.1.4), openssl-provider-legacy", .archive_size = 2364586, .archive_sha512 = "10df2f82619faff2ed4b890812313c35cd58abbfce858caf3403e1b654fac857bd7bc28e7a528a79a18ebfbfbdca5cffb3c2dd5b340c729fb7eb2470b76d528d" },
    .{ .name = "openssl-provider-legacy", .version = "3.5.5-1ubuntu3.6", .depends = "libc6 (>= 2.14), libssl3t64 (>= 3.0.3)", .archive_size = 39690, .archive_sha512 = "cbb4f55a609576d99a1b52952a674e78b2cbb7026e54c765cfd964812b65bdcdea4f5ea67961159b737fcba3093b3b15de8b7a6aff3bbf08a85805a09290c470" },
    base_cycle[0],
    .{ .name = "libzstd1", .version = "1.5.7+dfsg-3", .depends = "libc6 (>= 2.34)", .archive_size = 308174, .archive_sha512 = "284a44950a9caae10a6b7a06baead5db2d6dd2989fc01107c78c76ef5468cb489fc1a8e92d6cb84d44b5a371f8b1156bd2f5c232e79f1631dcf000a601e52183" },
    .{ .name = "zlib1g", .version = "1:1.3.dfsg+really1.3.1-1ubuntu3.1", .depends = "libc6 (>= 2.14)", .archive_size = 61612, .archive_sha512 = "a0ad94daadd3099ee40766a62a42d3fa7f431c6d805e9108d1dde07d64bfe3e7da66a41a2294598917e5ef5435df7a239d011711dd6d18037bc9b61b530ed3d4" },
};
const kbd_cycle = [_]CycleBinding{
    .{ .name = "kbd", .version = "2.7.1-2ubuntu2", .depends = "libc6 (>= 2.38), console-setup | console-setup-mini", .archive_size = 238014, .archive_sha512 = "5a1fcb79b59441d380b4f6f38198ab4e7b04e50a759580302643ab1f138d88c900145612dfe0861eab37c5f9ebbb6218bc3a5585366be04d4cd00f85efa16050" },
    .{ .name = "console-setup-linux", .version = "1.237ubuntu3.1", .architecture = "all", .depends = "kbd (>= 0.99-12) | console-tools (>= 1:0.2.3-16), keyboard-configuration (= 1.237ubuntu3.1), init-system-helpers (>= 1.29~) | initscripts", .archive_size = 6206020, .archive_sha512 = "511e2f220d1f2afb6c0ae80d9488b6863b884f2db26e54d9cd343ca212c8061e6fbf637131fbd6f93673f3f9d47fe22515b22eca96a1cdf65e9e768fd2bbbb5b" },
    .{ .name = "console-setup", .version = "1.237ubuntu3.1", .architecture = "all", .depends = "console-setup-linux | hurd, xkb-data (>= 0.9), keyboard-configuration (= 1.237ubuntu3.1), debconf (>= 0.5) | debconf-2.0", .archive_size = 102654, .archive_sha512 = "776ebf749c2a621ff9835b86b69efe1c838e948ac8265fab0f2c5eb91875ae67f1313800854b3a8a962359dfa40bee3e59cc5cf956a215ed82e15529bf622832" },
    base_cycle[0],
};
const kbd_triggers = "# Triggers added by dh_installinitramfs/13.24.2ubuntu1\nactivate-noawait update-initramfs\n";
const CycleKind = enum { base, openssl, kbd };
const libc6_breaks = "base-files (<< 13.3~), dhcpcd (<< 1:10.1.0-7~), libamdhip64-5 (<< 5.7.1-5+b1), libhiprtc-builtins5 (<< 5.7.1-5+b1), librccl1 (<< 5.4.3-3build1), libswupdate0.1 (<< 2024.12.1+dfsg-1+b3), locales (<< 2.43), locales-all (<< 2.43), lua-swupdate (<< 2024.12.1+dfsg-1+b3), nscd (<< 2.43), pd-scaf (<< 1:0.14.1+darcs20180201-6build5), postgresql-15-pllua (<< 1:2.0.12-4), postgresql-17-pllua (<< 1:2.0.12-3+b2), python3-mrgingham (<< 1.25-1), python3-onnxruntime (<< 1.20.1+dfsg-2~), sysvinit (<< 3.09-2~), sysvinit-core (<< 3.09-2~), uwsgi-plugin-pypy3 (<< 0.0.2+b1)";
const cycle_graph_keys = [_][]const u8{
    "Depends",    "Pre-Depends", "Breaks",    "Conflicts",        "Provides",         "Replaces",
    "Multi-Arch", "Protected",   "Essential", "Triggers-Pending", "Triggers-Awaited", "Config-Version",
};

fn cycleGraphField(index: usize, key: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(key, "Depends")) return base_cycle[index].depends;
    if (std.ascii.eqlIgnoreCase(key, "Breaks")) return switch (index) {
        0 => libc6_breaks,
        2 => "gnat (<< 7)",
        3 => "libc6 (<< 2.42-1)",
        else => "",
    };
    if (std.ascii.eqlIgnoreCase(key, "Replaces")) return switch (index) {
        0 => "libc6-amd64",
        1 => "libgcc1 (<< 1:10)",
        3 => "libc6 (<< 2.42-1)",
        else => "",
    };
    if (std.ascii.eqlIgnoreCase(key, "Provides")) return if (index == 1) "libgcc1 (= 1:16-20260322-1ubuntu1)" else "";
    if (std.ascii.eqlIgnoreCase(key, "Multi-Arch")) return "same";
    if (std.ascii.eqlIgnoreCase(key, "Protected")) return if (index == 1) "yes" else "";
    return "";
}

fn opensslGraphField(index: usize, key: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(key, "Depends")) return openssl_cycle[index].depends;
    if (index == 2) return cycleGraphField(0, key);
    if (std.ascii.eqlIgnoreCase(key, "Breaks")) return switch (index) {
        0 => "libssl3 (<< 3.5.5-1ubuntu3.6), openssh-client (<< 1:9.4p1), openssh-server (<< 1:9.4p1), python3-m2crypto (<< 0.38.0-4)",
        1 => "libssl3 (<< 3.3.1-5), libssl3t64 (<< 3.3.1-5)",
        4 => "libxml2 (<< 2.7.6.dfsg-2), texlive-binaries (<< 2023.20230311.66589-8)",
        else => "",
    };
    if (std.ascii.eqlIgnoreCase(key, "Replaces")) return switch (index) {
        0 => "libssl3",
        1 => "libssl3 (<< 3.3.1-5), libssl3t64 (<< 3.3.1-5)",
        else => "",
    };
    if (std.ascii.eqlIgnoreCase(key, "Provides")) return switch (index) {
        0 => "libssl3 (= 3.5.5-1ubuntu3.6)",
        4 => "libz1",
        else => "",
    };
    if (std.ascii.eqlIgnoreCase(key, "Conflicts")) return if (index == 4) "zlib1 (<= 1:1.0.4-7)" else "";
    if (std.ascii.eqlIgnoreCase(key, "Multi-Arch")) return if (index == 1) "foreign" else "same";
    return "";
}

fn kbdGraphField(index: usize, key: []const u8) []const u8 {
    if (index == 3) return cycleGraphField(0, key);
    if (std.ascii.eqlIgnoreCase(key, "Depends")) return kbd_cycle[index].depends;
    if (std.ascii.eqlIgnoreCase(key, "Pre-Depends")) return if (index == 2) "debconf | debconf-2.0" else "";
    if (std.ascii.eqlIgnoreCase(key, "Breaks")) return switch (index) {
        1 => "console-cyrillic (<= 0.9-11), console-setup (<< 1.71), console-terminus",
        2 => "lsb (<< 2.0-6), lsb-base (<< 3.0-6), lsb-core (<< 2.0-6)",
        else => "",
    };
    if (std.ascii.eqlIgnoreCase(key, "Conflicts")) return switch (index) {
        0 => "console-utilities",
        2 => "console-setup-mini",
        else => "",
    };
    if (std.ascii.eqlIgnoreCase(key, "Provides")) return switch (index) {
        0 => "console-utilities",
        1 => "console-terminus",
        else => "",
    };
    if (std.ascii.eqlIgnoreCase(key, "Replaces")) return if (index == 1) "console-setup (<< 1.71), console-terminus" else "";
    if (std.ascii.eqlIgnoreCase(key, "Multi-Arch")) return if (index == 1 or index == 2) "foreign" else "";
    return "";
}

fn scriptBinding(profile: Profile) ?ScriptBinding {
    return switch (profile) {
        .systemd, .udev, .sudo => script_bindings[@intFromEnum(profile) - 1],
        .none, .libgcc_cycle, .openssl_cycle, .kbd_cycle => null,
    };
}

const Pinned = struct { fd: i32, metadata: linux.Statx };
const Options = struct {
    root: [:0]const u8,
    dpkg: [:0]const u8,
    runtime: [:0]const u8,
    architecture: []const u8,
    profile: Profile,
    verb: Verb,
    selector: ?[:0]const u8 = null,
    archive: ?[:0]const u8 = null,
    archive_sha512: ?[]const u8 = null,
    archive_size: ?usize = null,
    cycle_archives: ?[base_cycle.len][:0]const u8 = null,
    openssl_archives: ?[openssl_cycle.len][:0]const u8 = null,
    kbd_archives: ?[kbd_cycle.len][:0]const u8 = null,
};

pub fn main(init: std.process.Init) !void {
    const supervisor = linux.getppid();
    if (supervisor <= 1) return error.MissingSupervisor;
    _ = try checked(linux.prctl(
        @intFromEnum(linux.PR.SET_PDEATHSIG),
        @intFromEnum(linux.SIG.KILL),
        0,
        0,
        0,
    ));
    if (linux.getppid() != supervisor) return error.SupervisorExited;
    try verifyStandardStreams();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const root = args.next() orelse return error.InvalidArguments;
    const dpkg = args.next() orelse return error.InvalidArguments;
    const architecture = args.next() orelse return error.InvalidArguments;
    const profile_name = args.next() orelse return error.InvalidArguments;
    const verb_name = args.next() orelse return error.InvalidArguments;
    const profile = std.meta.stringToEnum(Profile, profile_name) orelse return error.InvalidArguments;
    const verb = std.meta.stringToEnum(Verb, verb_name) orelse return error.InvalidArguments;
    const selector = args.next();
    const runtime_path = args.next() orelse return error.InvalidArguments;
    var cycle_archives: ?[base_cycle.len][:0]const u8 = null;
    var openssl_archives: ?[openssl_cycle.len][:0]const u8 = null;
    var kbd_archives: ?[kbd_cycle.len][:0]const u8 = null;
    if (verb == .break_base_cycle) {
        var paths: [base_cycle.len][:0]const u8 = undefined;
        for (&paths) |*path| {
            path.* = try init.arena.allocator().dupeZ(u8, args.next() orelse return error.InvalidArguments);
        }
        cycle_archives = paths;
    }
    if (verb == .configure_openssl_cycle) {
        var paths: [openssl_cycle.len][:0]const u8 = undefined;
        for (&paths) |*path| {
            path.* = try init.arena.allocator().dupeZ(u8, args.next() orelse return error.InvalidArguments);
        }
        openssl_archives = paths;
    }
    if (verb == .break_kbd_cycle) {
        var paths: [kbd_cycle.len][:0]const u8 = undefined;
        for (&paths) |*path| {
            path.* = try init.arena.allocator().dupeZ(u8, args.next() orelse return error.InvalidArguments);
        }
        kbd_archives = paths;
    }
    const normal = cycle_archives == null and openssl_archives == null and kbd_archives == null;
    const archive = if (normal) args.next() else null;
    const digest = if (normal) args.next() else null;
    const size_text = if (normal) args.next() else null;
    if (args.next() != null) return error.InvalidArguments;
    const options: Options = .{
        .root = try init.arena.allocator().dupeZ(u8, root),
        .dpkg = try init.arena.allocator().dupeZ(u8, dpkg),
        .runtime = try init.arena.allocator().dupeZ(u8, runtime_path),
        .architecture = architecture,
        .profile = profile,
        .verb = verb,
        .selector = if (selector) |value| try init.arena.allocator().dupeZ(u8, value) else null,
        .archive = if (archive) |value| try init.arena.allocator().dupeZ(u8, value) else null,
        .archive_sha512 = digest,
        .archive_size = if (size_text) |value| try std.fmt.parseInt(usize, value, 10) else null,
        .cycle_archives = cycle_archives,
        .openssl_archives = openssl_archives,
        .kbd_archives = kbd_archives,
    };
    try validateOptions(options);
    const status = try run(init.arena.allocator(), options);
    std.process.exit(status);
}

fn validAbsolute(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or
            std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn validateOptions(options: Options) !void {
    if (!validAbsolute(options.root) or !validAbsolute(options.dpkg) or !validAbsolute(options.runtime) or
        (options.archive != null and !validAbsolute(options.archive.?)))
        return error.InvalidArguments;
    const architecture_index: usize = if (std.mem.eql(u8, options.architecture, "amd64"))
        0
    else if (std.mem.eql(u8, options.architecture, "arm64"))
        1
    else
        return error.UnsupportedArchitecture;
    const unpacking = options.verb == .unpack or options.verb == .probe_unpack;
    const configuring = options.verb == .configure or options.verb == .continue_prestate or options.verb == .probe_configure or options.verb == .break_base_cycle or options.verb == .configure_openssl_cycle or options.verb == .break_kbd_cycle;
    if (unpacking != (options.archive != null) or
        unpacking != (options.archive_sha512 != null) or
        unpacking != (options.archive_size != null) or
        (unpacking or configuring) != (options.selector != null))
        return error.InvalidArguments;
    if ((options.verb == .break_base_cycle) != (options.cycle_archives != null))
        return error.InvalidArguments;
    if ((options.verb == .configure_openssl_cycle) != (options.openssl_archives != null))
        return error.InvalidArguments;
    if ((options.verb == .break_kbd_cycle) != (options.kbd_archives != null))
        return error.InvalidArguments;
    if (options.kbd_archives) |paths| {
        for (paths) |path| if (!validAbsolute(path)) return error.InvalidArguments;
        if (options.profile != .kbd_cycle or architecture_index != 0 or
            !std.mem.eql(u8, options.selector.?, "kbd:amd64"))
            return error.InvalidCycleProfile;
    } else if (options.profile == .kbd_cycle) {
        return error.InvalidCycleProfile;
    }
    if (options.openssl_archives) |paths| {
        for (paths) |path| if (!validAbsolute(path)) return error.InvalidArguments;
        if (options.profile != .openssl_cycle or architecture_index != 0 or
            !std.mem.eql(u8, options.selector.?, "libssl3t64:amd64"))
            return error.InvalidCycleProfile;
    } else if (options.profile == .openssl_cycle) {
        return error.InvalidCycleProfile;
    }
    if (options.cycle_archives) |paths| {
        for (paths) |path| if (!validAbsolute(path)) return error.InvalidArguments;
        if (options.profile != .libgcc_cycle or architecture_index != 0 or
            !std.mem.eql(u8, options.selector.?, "libgcc-s1:amd64"))
            return error.InvalidCycleProfile;
    } else if (options.profile == .libgcc_cycle) {
        return error.InvalidCycleProfile;
    }
    if (options.selector) |selector| {
        if (selector.len == 0 or selector.len > 120 or
            std.mem.indexOfAny(u8, selector, "/ \t\n\x00") != null or selector[0] == '-')
            return error.InvalidArguments;
    }
    if (options.verb == .continue_prestate and options.profile != .systemd and options.profile != .udev)
        return error.InvalidProfile;
    if (scriptBinding(options.profile)) |binding| {
        if ((options.verb != .configure and options.verb != .continue_prestate) or architecture_index != 0)
            return error.InvalidProfile;
        const selector_name = options.selector.?;
        if (selector_name.len != binding.name.len + ":amd64".len or
            !std.mem.startsWith(u8, selector_name, binding.name) or
            !std.mem.eql(u8, selector_name[binding.name.len..], ":amd64"))
            return error.InvalidProfile;
    } else if (options.verb == .configure) {
        for (script_bindings) |binding| {
            if (std.mem.eql(u8, options.selector.?, binding.name) or
                (options.selector.?.len > binding.name.len and
                    std.mem.startsWith(u8, options.selector.?, binding.name) and
                    options.selector.?[binding.name.len] == ':'))
                return error.InvalidProfile;
        }
    }
    if (unpacking) {
        if (options.archive_size.? == 0 or options.archive_size.? > 512 * 1024 * 1024 or
            options.archive_sha512.?.len != 128) return error.InvalidArguments;
        for (options.archive_sha512.?) |digit| {
            if (!std.ascii.isHex(digit) or std.ascii.isUpper(digit))
                return error.InvalidArguments;
        }
    }
}

fn checked(result: usize) !usize {
    return switch (linux.errno(result)) {
        .SUCCESS => result,
        else => |err| {
            std.log.err("reference launcher syscall refused: {s}", .{@tagName(err)});
            return error.ReferenceSetupFailed;
        },
    };
}

fn metadata(fd: i32) !linux.Statx {
    var value: linux.Statx = undefined;
    _ = try checked(linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &value));
    return value;
}

fn allowedStandardStream(slot: i32, info: linux.Statx, flags: usize) bool {
    const access = flags & 3;
    const path_flag: usize = 1 << @bitOffsetOf(linux.O, "PATH");
    if (flags & path_flag != 0 or info.uid != 0 or info.gid != 0) return false;
    if (slot == 0) {
        return (info.mode & 0o170000) == 0o020000 and
            info.rdev_major == 1 and info.rdev_minor == 3 and access == 0;
    }
    const append_flag: usize = 1 << @bitOffsetOf(linux.O, "APPEND");
    return (slot == 1 or slot == 2) and
        (info.mode & 0o170000) == 0o100000 and
        (info.mode & 0o022) == 0 and info.nlink <= 1 and
        access == 1 and flags & append_flag != 0;
}

fn verifyStandardStream(slot: i32, fd: i32) !void {
    const info = metadata(fd) catch return error.InvalidStandardStream;
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS or !allowedStandardStream(slot, info, flags))
        return error.InvalidStandardStream;
}

fn verifyStandardStreams() !void {
    inline for (0..3) |slot| try verifyStandardStream(@intCast(slot), @intCast(slot));
}

fn openPinned(path: [:0]const u8, directory: bool) !Pinned {
    const flags: linux.O = .{ .PATH = true, .CLOEXEC = true, .DIRECTORY = directory };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    errdefer _ = linux.close(fd);
    return .{ .fd = fd, .metadata = try metadata(fd) };
}

fn same(left: linux.Statx, right: linux.Statx) bool {
    return left.dev_major == right.dev_major and left.dev_minor == right.dev_minor and
        left.ino == right.ino and left.mode == right.mode and left.uid == right.uid and
        left.gid == right.gid and left.size == right.size and left.nlink == right.nlink and
        left.mtime.sec == right.mtime.sec and left.mtime.nsec == right.mtime.nsec and
        left.ctime.sec == right.ctime.sec and left.ctime.nsec == right.ctime.nsec;
}

fn protectedAncestors(path: [:0]const u8) !void {
    if (!validAbsolute(path)) return error.UnprotectedPath;
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (path.len >= buffer.len) return error.UnprotectedPath;
    @memcpy(buffer[0..path.len], path);
    for (buffer[0..path.len], 0..) |byte, index| {
        if (byte != '/' or index == 0) continue;
        buffer[index] = 0;
        const pinned = try openPinned(buffer[0..index :0], true);
        _ = linux.close(pinned.fd);
        if (pinned.metadata.uid != 0 or pinned.metadata.gid != 0 or
            (pinned.metadata.mode & 0o022) != 0) return error.UnprotectedPath;
        buffer[index] = '/';
    }
}

fn hashFile(fd: i32, comptime Hash: type, maximum: usize) ![Hash.digest_length]u8 {
    var hash = Hash.init(.{});
    var count: usize = 0;
    var bytes: [8192]u8 = undefined;
    while (true) {
        const got = try checked(linux.read(fd, &bytes, bytes.len));
        if (got == 0) break;
        count = std.math.add(usize, count, got) catch return error.FileTooLarge;
        if (count > maximum) return error.FileTooLarge;
        hash.update(bytes[0..got]);
    }
    var digest: [Hash.digest_length]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn openVerified(
    path: [:0]const u8,
    comptime Hash: type,
    expected: []const u8,
    size: ?usize,
    maximum: usize,
) !Pinned {
    try protectedAncestors(path);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    errdefer _ = linux.close(fd);
    const before = try metadata(fd);
    if (before.uid != 0 or before.gid != 0 or (before.mode & 0o170000) != 0o100000 or
        (before.mode & 0o022) != 0 or before.nlink != 1 or
        before.size > maximum or (size != null and before.size != size.?))
        return error.InvalidSourceFile;
    const digest = try hashFile(fd, Hash, maximum);
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), expected) or
        !same(before, try metadata(fd))) return error.SourceChanged;
    return .{ .fd = fd, .metadata = before };
}

fn bindingStatusMatches(status: []const u8, binding: ScriptBinding) bool {
    return bindingStatusMatchesFor(status, binding, .configure);
}

fn bindingStatusMatchesFor(status: []const u8, binding: ScriptBinding, verb: Verb) bool {
    const expected_state: []const u8 = switch (verb) {
        .configure => "install ok unpacked",
        .continue_prestate => if (std.mem.eql(u8, binding.name, "systemd") or std.mem.eql(u8, binding.name, "udev"))
            "install ok half-configured"
        else
            return false,
        else => return false,
    };
    var matched = false;
    var paragraphs = std.mem.splitSequence(u8, status, "\n\n");
    while (paragraphs.next()) |paragraph| {
        if (paragraph.len == 0) continue;
        var name: ?[]const u8 = null;
        var architecture: ?[]const u8 = null;
        var version: ?[]const u8 = null;
        var state: ?[]const u8 = null;
        var identity_field = false;
        var lines = std.mem.splitScalar(u8, paragraph, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (line[0] == ' ' or line[0] == '\t') {
                if (identity_field) return false;
                continue;
            }
            identity_field = false;
            const separator = std.mem.indexOfScalar(u8, line, ':') orelse return false;
            const key = line[0..separator];
            const rest = line[separator + 1 ..];
            if (rest.len > 0 and rest[0] != ' ') return false;
            const value = if (rest.len == 0) rest else rest[1..];
            if (std.ascii.eqlIgnoreCase(key, "Package")) {
                if (name != null) return false;
                name = value;
                identity_field = true;
            } else if (std.ascii.eqlIgnoreCase(key, "Architecture")) {
                if (architecture != null) return false;
                architecture = value;
                identity_field = true;
            } else if (std.ascii.eqlIgnoreCase(key, "Version")) {
                if (version != null) return false;
                version = value;
                identity_field = true;
            } else if (std.ascii.eqlIgnoreCase(key, "Status")) {
                if (state != null) return false;
                state = value;
                identity_field = true;
            }
        }
        if (name != null and std.mem.eql(u8, name.?, binding.name)) {
            if (matched or architecture == null or version == null or state == null or
                !std.mem.eql(u8, architecture.?, "amd64") or
                !std.mem.eql(u8, version.?, binding.version) or
                !std.mem.eql(u8, state.?, expected_state)) return false;
            matched = true;
        }
    }
    return matched;
}

fn readInstalledFile(path: [:0]const u8, maximum: usize) ![]u8 {
    try protectedAncestors(path);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    defer _ = linux.close(fd);
    const before = try metadata(fd);
    if (before.uid != 0 or before.gid != 0 or
        (before.mode & 0o170000) != 0o100000 or (before.mode & 0o022) != 0 or
        before.nlink != 1 or before.size > maximum)
        return error.InvalidInstalledBinding;
    const size: usize = @intCast(before.size);
    const bytes = try std.heap.page_allocator.alloc(u8, size);
    errdefer std.heap.page_allocator.free(bytes);
    var count: usize = 0;
    while (count < bytes.len) {
        const got = try checked(linux.read(fd, bytes[count..].ptr, bytes.len - count));
        if (got == 0) break;
        count += got;
    }
    if (count != size or !same(before, try metadata(fd))) return error.InvalidInstalledBinding;
    return bytes[0..count];
}

fn readInstalledStatus() ![]u8 {
    return readInstalledFile("/var/lib/dpkg/status", 4 * 1024 * 1024);
}

fn verifyInstalledBinding(binding: ScriptBinding, verb: Verb) !void {
    const bytes = try readInstalledStatus();
    defer std.heap.page_allocator.free(bytes);
    if (!bindingStatusMatchesFor(bytes, binding, verb)) return error.InvalidInstalledBinding;
    const script_path = try std.fmt.allocPrintSentinel(
        std.heap.page_allocator,
        "/var/lib/dpkg/info/{s}.postinst",
        .{binding.name},
        0,
    );
    defer std.heap.page_allocator.free(script_path);
    const script = try openVerified(
        script_path,
        std.crypto.hash.sha2.Sha256,
        binding.digest,
        binding.size,
        binding.size,
    );
    _ = linux.close(script.fd);
}

fn cycleStatusMatches(status: []const u8) bool {
    return cycleStatusMatchesFor(status, .base);
}

fn cycleStatusMatchesFor(status: []const u8, comptime kind: CycleKind) bool {
    const bindings = switch (kind) {
        .base => base_cycle,
        .openssl => openssl_cycle,
        .kbd => kbd_cycle,
    };
    const graphField = switch (kind) {
        .base => cycleGraphField,
        .openssl => opensslGraphField,
        .kbd => kbdGraphField,
    };
    var matched = [_]bool{false} ** bindings.len;
    var paragraphs = std.mem.splitSequence(u8, status, "\n\n");
    while (paragraphs.next()) |paragraph| {
        if (paragraph.len == 0) continue;
        var fields: [128]struct { key: []const u8, value: []const u8 } = undefined;
        var count: usize = 0;
        var lines = std.mem.splitScalar(u8, paragraph, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (line[0] == ' ' or line[0] == '\t') {
                if (count == 0) return false;
                const key = fields[count - 1].key;
                for ([_][]const u8{ "Package", "Architecture", "Version", "Status" } ++ cycle_graph_keys) |identity| {
                    if (std.ascii.eqlIgnoreCase(key, identity)) return false;
                }
                continue;
            }
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return false;
            const rest = line[colon + 1 ..];
            if (rest.len != 0 and rest[0] != ' ') return false;
            if (count == fields.len) return false;
            const key = line[0..colon];
            for (fields[0..count]) |field| {
                if (std.ascii.eqlIgnoreCase(field.key, key)) return false;
            }
            fields[count] = .{ .key = key, .value = if (rest.len == 0) rest else rest[1..] };
            count += 1;
        }
        var name: []const u8 = "";
        for (fields[0..count]) |field| {
            if (std.ascii.eqlIgnoreCase(field.key, "Package")) name = field.value;
        }
        for (bindings, 0..) |binding, index| {
            if (!std.mem.eql(u8, name, binding.name)) continue;
            if (matched[index]) return false;
            matched[index] = true;
            var architecture: []const u8 = "";
            var version: []const u8 = "";
            var state: []const u8 = "";
            var depends: []const u8 = "";
            var graph_seen = [_]bool{false} ** cycle_graph_keys.len;
            for (fields[0..count]) |field| {
                if (std.ascii.eqlIgnoreCase(field.key, "Architecture")) architecture = field.value;
                if (std.ascii.eqlIgnoreCase(field.key, "Version")) version = field.value;
                if (std.ascii.eqlIgnoreCase(field.key, "Status")) state = field.value;
                if (std.ascii.eqlIgnoreCase(field.key, "Depends")) depends = field.value;
                for (cycle_graph_keys, 0..) |key, graph_index| {
                    if (!std.ascii.eqlIgnoreCase(field.key, key)) continue;
                    graph_seen[graph_index] = true;
                    if (!std.mem.eql(u8, field.value, graphField(index, key))) return false;
                }
            }
            for (cycle_graph_keys, graph_seen) |key, seen| {
                if (!seen and graphField(index, key).len != 0) return false;
            }
            if (!std.mem.eql(u8, architecture, binding.architecture) or !std.mem.eql(u8, version, binding.version) or
                !std.mem.eql(u8, depends, binding.depends) or !std.mem.eql(u8, state, if (index < (if (kind == .kbd) @as(usize, 3) else 2))
                "install ok unpacked"
            else
                "install ok installed")) return false;
        }
    }
    return std.mem.allEqual(bool, &matched, true);
}

fn verifyCycle(comptime kind: CycleKind) !void {
    const bytes = try readInstalledStatus();
    defer std.heap.page_allocator.free(bytes);
    if (!cycleStatusMatchesFor(bytes, kind)) return error.CycleStateOrGraphChanged;
    protectedAncestors("/var/lib/dpkg/updates/.cycle-check") catch return error.CycleStateChanged;
    emptyDirectory("/var/lib/dpkg/updates") catch return error.CycleStateChanged;
    const unincorp_path: [:0]const u8 = "/var/lib/dpkg/triggers/Unincorp";
    try protectedAncestors(unincorp_path);
    const unincorp = linux.open(unincorp_path, .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(unincorp) == .SUCCESS) {
        _ = linux.close(@intCast(unincorp));
        const pending = readInstalledFile(unincorp_path, 0) catch return error.CycleCallbackChanged;
        std.heap.page_allocator.free(pending);
    } else if (linux.errno(unincorp) != .NOENT) return error.CycleCallbackChanged;
    const activation_name = switch (kind) {
        .base => "libgcc-s1",
        .openssl => "libssl3t64",
        .kbd => "kbd",
    };
    const activation_path = if (kind == .kbd)
        "/var/lib/dpkg/info/kbd.triggers"
    else
        "/var/lib/dpkg/info/" ++ activation_name ++ ":amd64.triggers";
    const triggers = readInstalledFile(activation_path, 1024) catch return error.CycleCallbackChanged;
    defer std.heap.page_allocator.free(triggers);
    if (!std.mem.eql(u8, triggers, if (kind == .kbd) kbd_triggers else "# Triggers added by dh_makeshlibs/13.31ubuntu1\nactivate-noawait ldconfig\n"))
        return error.CycleCallbackChanged;
    const other_path = if (kind == .kbd)
        "/var/lib/dpkg/info/kbd:amd64.triggers"
    else
        "/var/lib/dpkg/info/" ++ activation_name ++ ".triggers";
    const unqualified = linux.open(other_path, .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(unqualified) == .SUCCESS) {
        _ = linux.close(@intCast(unqualified));
        return error.CycleCallbackChanged;
    }
    if (linux.errno(unqualified) != .NOENT) return error.CycleCallbackChanged;
    if (kind == .openssl) {
        try verifyCycleAbsent("/var/lib/dpkg/info/openssl-provider-legacy.triggers");
        try verifyCycleAbsent("/var/lib/dpkg/info/openssl-provider-legacy:amd64.triggers");
    }
    const names = switch (kind) {
        .base => .{ "libgcc-s1", "libgcc-s1:amd64" },
        .openssl => .{ "libssl3t64", "libssl3t64:amd64", "openssl-provider-legacy", "openssl-provider-legacy:amd64" },
        .kbd => .{ "kbd", "kbd:amd64" },
    };
    inline for (names) |name| {
        inline for (.{ "preinst", "postinst", "prerm", "postrm", "config" }) |script| {
            const path = "/var/lib/dpkg/info/" ++ name ++ "." ++ script;
            try verifyCycleAbsent(path);
        }
    }
}

fn verifyCycleAbsent(path: [:0]const u8) !void {
    try protectedAncestors(path);
    const present = linux.open(path, .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(present) == .SUCCESS) {
        _ = linux.close(@intCast(present));
        return error.CycleCallbackChanged;
    }
    if (linux.errno(present) != .NOENT) return error.CycleCallbackChanged;
}
fn protectedRoot(root: [:0]const u8) !Pinned {
    try protectedAncestors(root);
    const pinned = try openPinned(root, true);
    errdefer _ = linux.close(pinned.fd);
    if (pinned.metadata.mode != 0o40700 or pinned.metadata.uid != 0 or
        pinned.metadata.gid != 0) return error.UnprotectedRoot;
    return pinned;
}

fn emptyDirectory(path: [:0]const u8) !void {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .DIRECTORY = true };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    defer _ = linux.close(fd);
    var bytes: [2048]u8 = undefined;
    while (true) {
        const count = try checked(linux.syscall3(.getdents64, @bitCast(@as(isize, fd)), @intFromPtr(&bytes), bytes.len));
        if (count == 0) return;
        var offset: usize = 0;
        while (offset < count) {
            if (count - offset < 20) return error.InvalidMountpoint;
            const entry_size = std.mem.readInt(u16, bytes[offset + 16 ..][0..2], .little);
            if (entry_size < 20 or entry_size > count - offset)
                return error.InvalidMountpoint;
            const name = std.mem.sliceTo(bytes[offset + 19 .. offset + entry_size], 0);
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, ".."))
                return error.MountpointNotEmpty;
            offset += entry_size;
        }
    }
}

fn readBootId() ![37]u8 {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr("/proc/sys/kernel/random/boot_id"),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    defer _ = linux.close(fd);
    const entry = try metadata(fd);
    if (entry.mode != 0o100444 or entry.uid != 0 or entry.gid != 0 or entry.nlink != 1)
        return error.InvalidBootId;
    var bytes: [38]u8 = undefined;
    const count = try checked(linux.read(fd, &bytes, bytes.len));
    if (count != 37 or bytes[36] != '\n') return error.InvalidBootId;
    for (bytes[0..36], 0..) |digit, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (digit != '-') return error.InvalidBootId;
        } else if (!std.ascii.isHex(digit) or std.ascii.isUpper(digit)) {
            return error.InvalidBootId;
        }
    }
    return bytes[0..37].*;
}

const RuntimeMountpoints = struct {
    directory_path: [:0]const u8,
    preload_path: [:0]const u8,
    directory: Pinned,
    preload: Pinned,
    root_parent: Pinned,
    etc_parent: Pinned,
    remove_preload: bool,

    fn create(allocator: std.mem.Allocator, root_path: [:0]const u8) !RuntimeMountpoints {
        const root = try protectedRoot(root_path);
        errdefer _ = linux.close(root.fd);
        errdefer restoreMtime(root.fd, root.metadata.mtime) catch |err| {
            std.log.err("reference root timestamp cleanup failed: {s}", .{@errorName(err)});
        };
        const directory_path = try std.fmt.allocPrintSentinel(allocator, "{s}{s}", .{ root_path, runtime.mountpoint }, 0);
        _ = try checked(linux.mkdirat(root.fd, ".debz-reference-runtime", 0o700));
        errdefer {
            const result = linux.errno(linux.unlinkat(linux.AT.FDCWD, directory_path, linux.AT.REMOVEDIR));
            if (result != .SUCCESS) std.log.err("reference runtime directory cleanup failed: {s}", .{@tagName(result)});
        }
        const directory = try openPinned(directory_path, true);
        errdefer _ = linux.close(directory.fd);
        if (directory.metadata.mode != 0o40700 or directory.metadata.uid != 0 or directory.metadata.gid != 0)
            return error.InvalidRuntimeMountpoint;
        const etc_path = try std.fmt.allocPrintSentinel(allocator, "{s}/etc", .{root_path}, 0);
        const etc = try openPinned(etc_path, true);
        errdefer _ = linux.close(etc.fd);
        errdefer restoreMtime(etc.fd, etc.metadata.mtime) catch |err| {
            std.log.err("reference etc timestamp cleanup failed: {s}", .{@errorName(err)});
        };
        if (etc.metadata.uid != 0 or etc.metadata.gid != 0 or etc.metadata.mode & 0o022 != 0)
            return error.InvalidRuntimeMountpoint;
        const preload_path = try std.fmt.allocPrintSentinel(allocator, "{s}/etc/ld.so.preload", .{root_path}, 0);
        const created = linux.openat(etc.fd, "ld.so.preload", .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, 0o600);
        const remove_preload = switch (linux.errno(created)) {
            .SUCCESS => blk: {
                _ = linux.close(@intCast(created));
                break :blk true;
            },
            .EXIST => false,
            else => return error.InvalidRuntimeMountpoint,
        };
        errdefer {
            if (remove_preload) {
                const result = linux.errno(linux.unlinkat(linux.AT.FDCWD, preload_path, 0));
                if (result != .SUCCESS) std.log.err("reference preload mountpoint cleanup failed: {s}", .{@tagName(result)});
            }
        }
        const preload = try openPinned(preload_path, false);
        errdefer _ = linux.close(preload.fd);
        if (preload.metadata.uid != 0 or preload.metadata.gid != 0 or preload.metadata.nlink != 1 or
            preload.metadata.mode & 0o022 != 0 or preload.metadata.size != 0)
            return error.UnboundRuntimePreload;
        try restoreMtime(root.fd, root.metadata.mtime);
        try restoreMtime(etc.fd, etc.metadata.mtime);
        return .{
            .directory_path = directory_path,
            .preload_path = preload_path,
            .directory = directory,
            .preload = preload,
            .remove_preload = remove_preload,
            .root_parent = root,
            .etc_parent = etc,
        };
    }

    fn close(self: RuntimeMountpoints) void {
        _ = linux.close(self.directory.fd);
        _ = linux.close(self.preload.fd);
        _ = linux.close(self.root_parent.fd);
        _ = linux.close(self.etc_parent.fd);
    }

    fn cleanup(self: RuntimeMountpoints) !void {
        const root_info = try metadata(self.root_parent.fd);
        const etc_info = try metadata(self.etc_parent.fd);
        const directory = try openPinned(self.directory_path, true);
        defer _ = linux.close(directory.fd);
        if (!same(directory.metadata, self.directory.metadata)) return error.RuntimeMountpointChanged;
        try emptyDirectory(self.directory_path);
        const preload = try openPinned(self.preload_path, false);
        defer _ = linux.close(preload.fd);
        if (!same(preload.metadata, self.preload.metadata)) return error.RuntimeMountpointChanged;
        if (self.remove_preload) _ = try checked(linux.unlinkat(linux.AT.FDCWD, self.preload_path, 0));
        _ = try checked(linux.unlinkat(linux.AT.FDCWD, self.directory_path, linux.AT.REMOVEDIR));
        try restoreMtime(self.root_parent.fd, root_info.mtime);
        try restoreMtime(self.etc_parent.fd, etc_info.mtime);
    }
};

fn restoreMtime(fd: i32, mtime: @FieldType(linux.Statx, "mtime")) !void {
    // Preserve package-induced changes, not temporary mountpoint mutations.
    const directory: i32 = @intCast(try checked(linux.openat(fd, ".", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0)));
    defer _ = linux.close(directory);
    const times = [2]linux.timespec{
        .{ .sec = 0, .nsec = 1073741822 },
        .{ .sec = mtime.sec, .nsec = mtime.nsec },
    };
    _ = try checked(linux.syscall4(.utimensat, @bitCast(@as(isize, directory)), 0, @intFromPtr(&times), 0));
}

const Child = struct {
    options: Options,
    root: Pinned,
    proc_mountpoint: Pinned,
    archive_mountpoint: Pinned,
    dpkg: Pinned,
    runtime: *const runtime.Bound,
    runtime_mountpoints: RuntimeMountpoints,
    archive: ?Pinned,
    boot_id: ?[37]u8,
    status_pipe: [2]i32,
    control_pipe: [2]i32,
};

fn stageRuntime(child: Child, allocator: std.mem.Allocator) !Pinned {
    const target = try openPinned(runtime.mountpoint, true);
    defer _ = linux.close(target.fd);
    if (!same(target.metadata, child.runtime_mountpoints.directory.metadata))
        return error.RuntimeMountpointChanged;
    try emptyDirectory(runtime.mountpoint);
    _ = try checked(linux.mount(
        "tmpfs",
        runtime.mountpoint,
        "tmpfs",
        linux.MS.NOSUID | linux.MS.NODEV,
        @intFromPtr(@as([*:0]const u8, "mode=0700,size=256m")),
    ));
    const directory = try runtime.openProtected(allocator, runtime.mountpoint, true);
    defer _ = linux.close(directory.fd);
    try runtime.populate(allocator, directory.fd, child.runtime.objects.items);
    const preload_source = try openPinned("/.debz-reference-runtime/preload", false);
    defer _ = linux.close(preload_source.fd);
    const preload_target = try openPinned("/etc/ld.so.preload", false);
    defer _ = linux.close(preload_target.fd);
    if (!same(preload_target.metadata, child.runtime_mountpoints.preload.metadata))
        return error.RuntimeMountpointChanged;
    const preload_tree: i32 = @intCast(try checked(cloneMountDescriptor(preload_source.fd)));
    defer _ = linux.close(preload_tree);
    const read_only: MountAttribute = .{ .attr_set = 1 | 2 | 4 };
    _ = try checked(setMountAttributes(preload_tree, &read_only));
    _ = try checked(linux.move_mount(preload_tree, "", preload_target.fd, "", .{
        .F_SYMLINKS = false,
        .F_AUTOMOUNTS = false,
        .F_EMPTY_PATH = true,
        .T_SYMLINKS = false,
        .T_AUTOMOUNTS = false,
        .T_EMPTY_PATH = true,
        .SET_GROUP = false,
    }));
    _ = try checked(setMountAttributes(directory.fd, &read_only));
    const loader_path = try std.fmt.allocPrintSentinel(
        allocator,
        "{s}/{s}",
        .{ runtime.mountpoint, child.runtime.manifest().loader },
        0,
    );
    return openPinned(loader_path, false);
}

fn fail(status: i32, stage: u8, err: linux.E) noreturn {
    var bytes: [5]u8 = .{ stage, 0, 0, 0, 0 };
    std.mem.writeInt(u32, bytes[1..5], @intFromEnum(err), .little);
    _ = linux.write(status, &bytes, bytes.len);
    linux.exit(125);
}

fn must(result: usize, fd: i32, stage: u8) void {
    if (linux.errno(result) != .SUCCESS) fail(fd, stage, linux.errno(result));
}

fn mountArchive(child: Child) linux.E {
    const archive = child.archive orelse return .SUCCESS;
    const tree_result = cloneMountDescriptor(archive.fd);
    if (linux.errno(tree_result) != .SUCCESS) return linux.errno(tree_result);
    const tree: i32 = @intCast(tree_result);
    defer _ = linux.close(tree);
    const attributes: MountAttribute = .{
        .attr_set = 1 | 2 | 4 | 8,
        .attr_clear = 0,
        .propagation = 0,
    };
    const attributes_result = setMountAttributes(tree, &attributes);
    if (linux.errno(attributes_result) != .SUCCESS)
        return linux.errno(attributes_result);
    const target = openPinned(archive_target[0..std.mem.len(archive_target) :0], false) catch return .STALE;
    defer _ = linux.close(target.fd);
    if (!same(target.metadata, child.archive_mountpoint.metadata)) return .STALE;
    return linux.errno(linux.move_mount(tree, "", target.fd, "", .{
        .F_SYMLINKS = false,
        .F_AUTOMOUNTS = false,
        .F_EMPTY_PATH = true,
        .T_SYMLINKS = false,
        .T_AUTOMOUNTS = false,
        .T_EMPTY_PATH = true,
        .SET_GROUP = false,
    }));
}

fn mountProc(child: Child) linux.E {
    if (child.options.profile == .none or child.options.profile == .libgcc_cycle or child.options.profile == .openssl_cycle or child.options.profile == .kbd_cycle) return .SUCCESS;
    const proc = openPinned("/proc", true) catch return .STALE;
    defer _ = linux.close(proc.fd);
    if (!same(proc.metadata, child.proc_mountpoint.metadata)) return .STALE;
    emptyDirectory("/proc") catch return .EXIST;
    const mounted = linux.errno(linux.mount(
        "proc",
        "/proc",
        "proc",
        proc_flags,
        @intFromPtr(if (child.options.profile == .systemd)
            @as([*:0]const u8, "hidepid=2")
        else
            @as([*:0]const u8, "hidepid=2,subset=pid")),
    ));
    if (mounted != .SUCCESS) return mounted;
    const visible = linux.open("/proc/1/root", .{ .PATH = true, .CLOEXEC = true }, 0);
    if (linux.errno(visible) != .SUCCESS) return linux.errno(visible);
    const observed = metadata(@intCast(visible)) catch {
        _ = linux.close(@intCast(visible));
        return .STALE;
    };
    _ = linux.close(@intCast(visible));
    if (observed.dev_major != child.root.metadata.dev_major or
        observed.dev_minor != child.root.metadata.dev_minor or
        observed.ino != child.root.metadata.ino)
        return .STALE;
    if (child.options.profile == .systemd) return maskBootId(child.boot_id.?);
    for ([_][*:0]const u8{ "/proc/sys", "/proc/sys/kernel/random/boot_id" }) |path| {
        const present = linux.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
        if (linux.errno(present) == .SUCCESS) {
            _ = linux.close(@intCast(present));
            return .EXIST;
        }
        if (linux.errno(present) != .NOENT) return linux.errno(present);
    }
    return .SUCCESS;
}

fn maskBootId(boot_id: [37]u8) linux.E {
    const masked = linux.errno(linux.mount(
        "tmpfs",
        "/proc/sys",
        "tmpfs",
        mask_flags,
        @intFromPtr("mode=0700,size=65536"),
    ));
    if (masked != .SUCCESS) return masked;
    for ([_][*:0]const u8{ "/proc/sys/kernel", "/proc/sys/kernel/random" }) |path| {
        const created = linux.errno(linux.mkdir(path, 0o555));
        if (created != .SUCCESS) return created;
        const mode = linux.errno(linux.chmod(path, 0o555));
        if (mode != .SUCCESS) return mode;
    }
    const file_result = linux.open(
        "/proc/sys/kernel/random/boot_id",
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true },
        0o444,
    );
    if (linux.errno(file_result) != .SUCCESS) return linux.errno(file_result);
    const file: i32 = @intCast(file_result);
    const wrote = linux.write(file, &boot_id, boot_id.len);
    if (linux.errno(wrote) != .SUCCESS or wrote != boot_id.len) {
        _ = linux.close(file);
        return .IO;
    }
    const mode = linux.errno(linux.fchmod(file, 0o444));
    _ = linux.close(file);
    if (mode != .SUCCESS) return mode;
    const protected = linux.errno(linux.mount(
        null,
        "/proc/sys",
        null,
        linux.MS.REMOUNT | proc_flags,
        0,
    ));
    if (protected != .SUCCESS) return protected;
    for ([_][*:0]const u8{
        "/proc/sys/kernel/random/uuid", "/proc/sys/kernel/pid_max",
        "/proc/sys/vm",                 "/proc/sys/net",
    }) |path| {
        const present = linux.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
        if (linux.errno(present) == .SUCCESS) {
            _ = linux.close(@intCast(present));
            return .EXIST;
        }
        if (linux.errno(present) != .NOENT) return linux.errno(present);
    }
    const present = linux.open(
        "/proc/sys/kernel/random/boot_id",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true },
        0,
    );
    if (linux.errno(present) != .SUCCESS) return linux.errno(present);
    var observed: [38]u8 = undefined;
    const got = linux.read(@intCast(present), &observed, observed.len);
    _ = linux.close(@intCast(present));
    if (linux.errno(got) != .SUCCESS or got != boot_id.len or
        !std.mem.eql(u8, observed[0..got], &boot_id)) return .STALE;
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
    return .SUCCESS;
}

fn allowedCapability(capability: u32) bool {
    inline for (filesystem_account_caps) |allowed| {
        if (capability == allowed) return true;
    }
    return false;
}

fn allowedCapabilityMask(word: usize) u32 {
    var mask: u32 = 0;
    inline for (filesystem_account_caps) |capability| {
        if (capability / 32 == word)
            mask |= @as(u32, 1) << @intCast(capability % 32);
    }
    return mask;
}

fn restrictCapabilityData(data: *[2]linux.cap_user_data_t) void {
    for (data, 0..) |*entry, word| {
        const mask = allowedCapabilityMask(word);
        entry.effective &= mask;
        entry.permitted &= mask;
        entry.inheritable &= mask;
    }
}

fn readCapabilities(data: *[2]linux.cap_user_data_t) linux.E {
    var header: CapHeader = .{};
    return linux.errno(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(data)));
}

fn writeCapabilities(data: *const [2]linux.cap_user_data_t) linux.E {
    var header: CapHeader = .{};
    return linux.errno(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(data)));
}

fn capabilityCount(out: *u32) linux.E {
    var capability: u32 = 0;
    while (capability <= 64) : (capability += 1) {
        const present = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), capability, 0, 0, 0);
        const result = linux.errno(present);
        if (result == .INVAL and capability != 0) {
            out.* = capability;
            return .SUCCESS;
        }
        if (result != .SUCCESS) return result;
        if (capability == 64) return .RANGE;
        if (present > 1) return .INVAL;
    }
    return .RANGE;
}

fn restrictReferencePrivileges() linux.E {
    var count: u32 = 0;
    const counted = capabilityCount(&count);
    if (counted != .SUCCESS) return counted;
    const ambient = linux.errno(linux.prctl(
        @intFromEnum(linux.PR.CAP_AMBIENT),
        4,
        0,
        0,
        0,
    ));
    if (ambient != .SUCCESS) return ambient;
    for (0..count) |index| {
        const capability: u32 = @intCast(index);
        if (allowedCapability(capability)) continue;
        const bounded = linux.errno(linux.prctl(
            @intFromEnum(linux.PR.CAPBSET_DROP),
            capability,
            0,
            0,
            0,
        ));
        if (bounded != .SUCCESS) return bounded;
    }
    const restricted = linux.errno(linux.prctl(
        @intFromEnum(linux.PR.SET_NO_NEW_PRIVS),
        1,
        0,
        0,
        0,
    ));
    if (restricted != .SUCCESS) return restricted;
    var data: [2]linux.cap_user_data_t = undefined;
    const captured = readCapabilities(&data);
    if (captured != .SUCCESS) return captured;
    restrictCapabilityData(&data);
    const removed = writeCapabilities(&data);
    if (removed != .SUCCESS) return removed;
    const checked_caps = readCapabilities(&data);
    if (checked_caps != .SUCCESS) return checked_caps;
    for (data, 0..) |entry, word| {
        if (((entry.effective | entry.permitted | entry.inheritable) &
            ~allowedCapabilityMask(word)) != 0) return .PERM;
    }
    if (linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) != 1)
        return .PERM;
    for (0..count) |index| {
        const capability: u32 = @intCast(index);
        const bounded = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), capability, 0, 0, 0);
        if (linux.errno(bounded) != .SUCCESS or bounded > 1 or
            (!allowedCapability(capability) and bounded != 0)) return .PERM;
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), 1, capability, 0, 0) != 0)
            return .PERM;
    }
    var policy: BpfProgram = .{ .len = filter.len, .filter = &filter };
    const installed = linux.errno(linux.syscall3(
        .seccomp,
        1,
        0,
        @intFromPtr(&policy),
    ));
    if (installed != .SUCCESS) return installed;
    return .SUCCESS;
}

fn generateFilter() [6 + deny_syscalls.len * 3 + 3 + 5 + 1]Bpf {
    const arch: u32 = switch (@import("builtin").cpu.arch) {
        .x86_64 => 0xc000003e,
        .aarch64 => 0xc00000b7,
        else => @compileError("reference launcher supports only native amd64 and arm64"),
    };
    var result: [6 + deny_syscalls.len * 3 + 3 + 5 + 1]Bpf = undefined;
    var index: usize = 0;
    result[index] = .{ .code = 0x20, .k = 4 }; // seccomp_data.arch
    index += 1;
    result[index] = .{ .code = 0x15, .jt = 1, .k = arch };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x80000000 };
    index += 1;
    result[index] = .{ .code = 0x20, .k = 0 };
    index += 1;
    result[index] = .{ .code = 0x35, .jf = 1, .k = 0x40000000 };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x80000000 }; // refuse x32 syscall aliases
    index += 1;
    inline for (deny_syscalls) |sys| {
        result[index] = .{ .code = 0x20, .k = 0 }; // syscall number
        index += 1;
        result[index] = .{ .code = 0x15, .jt = 0, .jf = 1, .k = @intFromEnum(sys) };
        index += 1;
        result[index] = .{ .code = 0x06, .k = 0x00050001 }; // EPERM
        index += 1;
    }
    result[index] = .{ .code = 0x20, .k = 0 };
    index += 1;
    result[index] = .{ .code = 0x15, .jf = 1, .k = @intFromEnum(linux.SYS.clone3) };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x00050026 }; // ENOSYS, libc may retry clone
    index += 1;
    result[index] = .{ .code = 0x20, .k = 0 };
    index += 1;
    result[index] = .{ .code = 0x15, .jf = 3, .k = @intFromEnum(linux.SYS.clone) };
    index += 1;
    result[index] = .{ .code = 0x20, .k = 16 }; // clone flags, first syscall argument
    index += 1;
    result[index] = .{ .code = 0x45, .jf = 1, .k = namespace_flags };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x00050001 };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x7fff0000 }; // allow ordinary syscalls
    return result;
}

fn evaluateFilter(architecture: u32, number: u32, flags: u32) !u32 {
    var pc: usize = 0;
    var value: u32 = 0;
    while (pc < filter.len) {
        const instruction = filter[pc];
        switch (instruction.code) {
            0x20 => value = switch (instruction.k) {
                0 => number,
                4 => architecture,
                16 => flags,
                else => return error.UnexpectedFilterInstruction,
            },
            0x15 => pc += if (value == instruction.k) instruction.jt else instruction.jf,
            0x35 => pc += if (value >= instruction.k) instruction.jt else instruction.jf,
            0x45 => pc += if (value & instruction.k != 0) instruction.jt else instruction.jf,
            0x06 => return instruction.k,
            else => return error.UnexpectedFilterInstruction,
        }
        pc += 1;
    }
    return error.UnterminatedFilter;
}

fn supervisorPipeAlive(fd: i32) bool {
    var probe: [1]u8 = undefined;
    return linux.errno(linux.read(fd, &probe, probe.len)) == .AGAIN;
}

fn childMain(input: Child) noreturn {
    var child = input;
    _ = linux.close(child.status_pipe[0]);
    _ = linux.close(child.control_pipe[1]);
    const status = child.status_pipe[1];
    if (linux.getpid() != 1) fail(status, 1, .INVAL);
    verifyStandardStreams() catch fail(status, 1, .BADF);
    must(linux.prctl(
        @intFromEnum(linux.PR.SET_PDEATHSIG),
        @intFromEnum(linux.SIG.KILL),
        0,
        0,
        0,
    ), status, 2);
    // PID 1 of the new PID namespace sees its supervisor as PID 0; the control
    // pipe then proves the supervisor did not exit before PDEATHSIG was armed.
    if (linux.getppid() != 0) fail(status, 2, .CHILD);
    if (!supervisorPipeAlive(child.control_pipe[0])) fail(status, 2, .CHILD);
    _ = linux.close(child.control_pipe[0]);
    must(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0), status, 3);
    const network_ready = private_network.setupLoopback();
    if (network_ready != .SUCCESS) fail(status, 15, network_ready);
    child.runtime.verify(child.options.root) catch |err| {
        std.log.err("reference runtime before-chroot refusal: {s}", .{@errorName(err)});
        fail(status, 12, .STALE);
    };
    if (child.options.archive) |path| {
        const reopened = openPinned(path, false) catch fail(status, 3, .STALE);
        if (!same(reopened.metadata, child.archive.?.metadata))
            fail(status, 3, .STALE);
        child.archive = reopened;
    }
    // Reopen the pinned root in the new mount namespace, then leave no outside cwd.
    const root = openPinned(child.options.root, true) catch fail(status, 4, .STALE);
    if (!same(root.metadata, child.root.metadata)) fail(status, 4, .STALE);
    must(linux.fchdir(root.fd), status, 4);
    must(linux.chroot("."), status, 4);
    must(linux.chdir("/"), status, 4);
    _ = linux.close(root.fd);
    child.runtime.verify("") catch |err| {
        std.log.err("reference runtime before-exec refusal: {s}", .{@errorName(err)});
        fail(status, 12, .STALE);
    };
    const allocator = std.heap.page_allocator;
    const loader = stageRuntime(child, allocator) catch |err| {
        std.log.err("reference runtime staging refused: {s}", .{@errorName(err)});
        fail(status, 13, .STALE);
    };
    if (scriptBinding(child.options.profile)) |binding| {
        verifyInstalledBinding(binding, child.options.verb) catch
            fail(status, 10, .STALE);
    }
    if (child.options.verb == .break_base_cycle)
        verifyCycle(.base) catch |err| {
            std.log.err("reference cycle operation refused: {s}", .{@errorName(err)});
            fail(status, 11, .STALE);
        };
    if (child.options.verb == .configure_openssl_cycle)
        verifyCycle(.openssl) catch |err| {
            std.log.err("reference OpenSSL operation refused: {s}", .{@errorName(err)});
            fail(status, 11, .STALE);
        };
    if (child.options.verb == .break_kbd_cycle)
        verifyCycle(.kbd) catch |err| {
            std.log.err("reference kbd cycle operation refused: {s}", .{@errorName(err)});
            fail(status, 11, .STALE);
        };
    const archive_setup = mountArchive(child);
    if (archive_setup != .SUCCESS) fail(status, 5, archive_setup);
    const proc_setup = mountProc(child);
    if (proc_setup != .SUCCESS) fail(status, 6, proc_setup);
    const dropped = restrictReferencePrivileges();
    if (dropped != .SUCCESS) fail(status, 7, dropped);
    verifyStandardStreams() catch fail(status, 8, .BADF);
    must(linux.syscall3(.close_range, 3, std.math.maxInt(u32), close_range_cloexec), status, 8);

    const common = [_]?[*:0]const u8{
        "dpkg", "--root=/", "--force-not-root", "--force-bad-path", "--force-confold",
    };
    const selector: ?[*:0]const u8 = if (child.options.selector) |value| value.ptr else null;
    const extra: [*:null]const ?[*:0]const u8 = switch (child.options.verb) {
        .probe_unpack => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--no-act", "--unpack", archive_target, null },
        .unpack => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--unpack", archive_target, null },
        .probe_configure => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--no-act", "--configure", selector, null },
        .configure, .continue_prestate => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--configure", selector, null },
        .break_base_cycle => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--force-depends", "--configure", selector, null },
        .configure_openssl_cycle => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--configure", "libssl3t64:amd64", "openssl-provider-legacy:amd64", null },
        .break_kbd_cycle => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--force-depends", "--configure", "kbd:amd64", null },
    };
    const loader_name = std.fmt.allocPrintSentinel(
        allocator,
        "{s}/{s}",
        .{ runtime.mountpoint, child.runtime.manifest().loader },
        0,
    ) catch fail(status, 14, .NOMEM);
    var arguments: [32]?[*:0]const u8 = @splat(null);
    const loader_arguments = [_][*:0]const u8{
        loader_name,                     "--inhibit-cache",  "--glibc-hwcaps-mask", "",
        "--library-path",                runtime.mountpoint, "--argv0",             "dpkg",
        "/.debz-reference-runtime/dpkg",
    };
    for (loader_arguments, 0..) |argument, index| arguments[index] = argument;
    var count: usize = loader_arguments.len;
    var index: usize = 1;
    while (extra[index]) |argument| : (index += 1) {
        if (count + 1 >= arguments.len) fail(status, 14, .@"2BIG");
        arguments[count] = argument;
        count += 1;
    }
    must(linux.syscall5(
        .execveat,
        @bitCast(@as(isize, loader.fd)),
        @intFromPtr(@as([*:0]const u8, "")),
        @intFromPtr(&arguments),
        @intFromPtr(environment),
        linux.AT.EMPTY_PATH,
    ), status, 9);
    fail(status, 9, .IO);
}

fn monotonicMilliseconds() !u64 {
    var timestamp: linux.timespec = undefined;
    _ = try checked(linux.clock_gettime(.MONOTONIC, &timestamp));
    if (timestamp.sec < 0) return error.ReferenceClockFailed;
    return @as(u64, @intCast(timestamp.sec)) * 1000 +
        @as(u64, @intCast(timestamp.nsec)) / 1_000_000;
}

fn killAndReap(pid: i32) !void {
    const signal = linux.errno(linux.kill(pid, .KILL));
    if (signal != .SUCCESS and signal != .SRCH) return error.ReferenceTeardownFailed;
    var status: u32 = 0;
    while (true) {
        const waited = linux.waitpid(pid, &status, 0);
        if (linux.errno(waited) == .INTR) continue;
        if (linux.errno(waited) != .SUCCESS or waited != @as(usize, @intCast(pid)))
            return error.ReferenceTeardownFailed;
        return;
    }
}

fn awaitNamespace(pid: i32, timeout_ms: u64) !u32 {
    const start = monotonicMilliseconds() catch {
        try killAndReap(pid);
        return error.ReferenceClockFailed;
    };
    var status: u32 = 0;
    while (true) {
        const waited = linux.waitpid(pid, &status, linux.W.NOHANG);
        if (linux.errno(waited) == .INTR) continue;
        if (linux.errno(waited) != .SUCCESS) return error.ReferenceWaitFailed;
        if (waited == @as(usize, @intCast(pid))) return status;
        if (waited != 0) return error.ReferenceWaitFailed;
        const now = monotonicMilliseconds() catch {
            try killAndReap(pid);
            return error.ReferenceClockFailed;
        };
        if (now < start or now - start >= timeout_ms) {
            try killAndReap(pid);
            return error.ReferenceDeadlineExceeded;
        }
        const delay: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
        _ = linux.nanosleep(&delay, null);
    }
}

fn run(allocator: std.mem.Allocator, options: Options) !u8 {
    const checked_root = try protectedRoot(options.root);
    _ = linux.close(checked_root.fd);
    const expected = dpkg_digests[
        if (std.mem.eql(u8, options.architecture, "amd64")) @as(usize, 0) else @as(usize, 1)
    ];
    var bound = try runtime.Bound.init(allocator, options.runtime, options.root, options.architecture, expected);
    defer bound.deinit();
    const mountpoints = try RuntimeMountpoints.create(allocator, options.root);
    defer mountpoints.close();
    const result = runBound(allocator, options, &bound, mountpoints) catch |err| {
        try mountpoints.cleanup();
        return err;
    };
    try mountpoints.cleanup();
    return result;
}

fn runBound(allocator: std.mem.Allocator, options: Options, bound: *const runtime.Bound, mountpoints: RuntimeMountpoints) !u8 {
    const root = try protectedRoot(options.root);
    defer _ = linux.close(root.fd);
    const expected_dpkg = dpkg_digests[
        if (std.mem.eql(u8, options.architecture, "amd64"))
            @as(usize, 0)
        else
            @as(usize, 1)
    ];
    const dpkg = try openVerified(
        options.dpkg,
        std.crypto.hash.sha2.Sha256,
        expected_dpkg,
        null,
        8 * 1024 * 1024,
    );
    defer _ = linux.close(dpkg.fd);
    const archive: ?Pinned = if (options.archive) |path|
        try openVerified(
            path,
            std.crypto.hash.sha2.Sha512,
            options.archive_sha512.?,
            options.archive_size.?,
            options.archive_size.?,
        )
    else
        null;
    defer {
        if (archive) |value| _ = linux.close(value.fd);
    }
    if (options.cycle_archives) |paths| {
        for (paths, base_cycle) |path, binding| {
            const source = openVerified(
                path,
                std.crypto.hash.sha2.Sha512,
                binding.archive_sha512,
                binding.archive_size,
                binding.archive_size,
            ) catch return error.CycleIdentityChanged;
            _ = linux.close(source.fd);
        }
    }
    if (options.openssl_archives) |paths| {
        for (paths, openssl_cycle) |path, binding| {
            const source = openVerified(
                path,
                std.crypto.hash.sha2.Sha512,
                binding.archive_sha512,
                binding.archive_size,
                binding.archive_size,
            ) catch return error.CycleIdentityChanged;
            _ = linux.close(source.fd);
        }
    }
    if (options.kbd_archives) |paths| {
        for (paths, kbd_cycle) |path, binding| {
            const source = openVerified(
                path,
                std.crypto.hash.sha2.Sha512,
                binding.archive_sha512,
                binding.archive_size,
                binding.archive_size,
            ) catch return error.CycleIdentityChanged;
            _ = linux.close(source.fd);
        }
    }
    const root_proc = try std.fmt.allocPrintSentinel(allocator, "{s}/proc", .{options.root}, 0);
    const proc = try openPinned(root_proc, true);
    defer _ = linux.close(proc.fd);
    if (proc.metadata.uid != 0 or proc.metadata.gid != 0 or proc.metadata.mode != 0o40755)
        return error.InvalidProcMountpoint;
    if (proc.metadata.dev_major != root.metadata.dev_major or
        proc.metadata.dev_minor != root.metadata.dev_minor) return error.InvalidProcMountpoint;
    try emptyDirectory(root_proc);
    const root_target = try std.fmt.allocPrintSentinel(allocator, "{s}{s}", .{ options.root, archive_target }, 0);
    const target = try openPinned(root_target, false);
    defer _ = linux.close(target.fd);
    if (target.metadata.uid != 0 or target.metadata.gid != 0 or
        target.metadata.mode != 0o100600 or target.metadata.size != 0 or
        target.metadata.nlink != 1 or target.metadata.dev_major != root.metadata.dev_major or
        target.metadata.dev_minor != root.metadata.dev_minor) return error.InvalidArchiveMountpoint;
    if (scriptBinding(options.profile)) |binding| {
        const script_path = try std.fmt.allocPrintSentinel(
            allocator,
            "{s}/var/lib/dpkg/info/{s}.postinst",
            .{ options.root, binding.name },
            0,
        );
        const script = try openVerified(
            script_path,
            std.crypto.hash.sha2.Sha256,
            binding.digest,
            binding.size,
            binding.size,
        );
        _ = linux.close(script.fd);
    }
    const boot_id = if (options.profile == .systemd) try readBootId() else null;

    var fds: [2]i32 = undefined;
    _ = try checked(linux.pipe2(&fds, .{ .CLOEXEC = true }));
    defer {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
    }
    var control: [2]i32 = undefined;
    _ = try checked(linux.pipe2(&control, .{ .CLOEXEC = true, .NONBLOCK = true }));
    defer {
        _ = linux.close(control[0]);
        _ = linux.close(control[1]);
    }
    const child: Child = .{
        .options = options,
        .root = root,
        .proc_mountpoint = proc,
        .archive_mountpoint = target,
        .dpkg = dpkg,
        .runtime = bound,
        .runtime_mountpoints = mountpoints,
        .archive = archive,
        .boot_id = boot_id,
        .status_pipe = fds,
        .control_pipe = control,
    };
    const clone_result = linux.clone2(
        reference_namespaces | @intFromEnum(linux.SIG.CHLD),
        0,
    );
    const cloned = referenceNamespaceResult(clone_result) catch |err| {
        std.log.err("required private reference namespaces unavailable: {s}", .{
            @tagName(linux.errno(clone_result)),
        });
        return err;
    };
    if (cloned == 0) childMain(child);
    const pid: i32 = @intCast(cloned);
    _ = linux.close(fds[1]);
    fds[1] = -1;
    _ = linux.close(control[0]);
    control[0] = -1;
    const probe = options.verb == .probe_unpack or options.verb == .probe_configure;
    const status = try awaitNamespace(pid, if (probe) 45_000 else 110_000);
    var failure: [5]u8 = undefined;
    const size = try checked(linux.read(fds[0], &failure, failure.len));
    if (size != 0) {
        if (size != failure.len) return error.InvalidSetupEvidence;
        std.log.err("reference namespace setup failed at stage {d}, errno {d}", .{
            failure[0], std.mem.readInt(u32, failure[1..5], .little),
        });
        if (failure[0] == 15) return error.ReferenceNetworkSetupFailed;
        return error.ReferenceSetupFailed;
    }
    if (!linux.W.IFEXITED(status)) return error.ReferenceProcessSignaled;
    return linux.W.EXITSTATUS(status);
}

fn referenceNamespaceResult(result: usize) !usize {
    if (linux.errno(result) != .SUCCESS) return error.ReferenceNamespaceUnavailable;
    return result;
}

test "reference namespace refusal never falls back to host networking" {
    for ([_]linux.E{ .PERM, .NOSYS, .INVAL, .OPNOTSUPP }) |err| {
        const result: usize = @bitCast(-@as(isize, @intFromEnum(err)));
        try std.testing.expectError(error.ReferenceNamespaceUnavailable, referenceNamespaceResult(result));
    }
}

fn cycleStatusFixture(allocator: std.mem.Allocator) ![]u8 {
    return cycleStatusFixtureFor(allocator, .base);
}

fn cycleStatusFixtureFor(allocator: std.mem.Allocator, comptime kind: CycleKind) ![]u8 {
    const source = switch (kind) {
        .base => @embedFile("fixtures/real-snapshot/base-cycle-controls-v1.json"),
        .openssl => @embedFile("fixtures/real-snapshot/openssl-cycle-controls-v1.json"),
        .kbd => @embedFile("fixtures/real-snapshot/kbd-cycle-controls-v1.json"),
    };
    const fixture = try std.json.parseFromSlice(struct {
        packages: []const struct { control: []const u8, status: []const u8 },
    }, allocator, source, .{ .ignore_unknown_fields = true });
    defer fixture.deinit();
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    for (fixture.value.packages) |package| {
        try output.appendSlice(allocator, package.control);
        const state = try std.fmt.allocPrint(allocator, "Status: {s}\n", .{package.status});
        defer allocator.free(state);
        try output.appendSlice(allocator, state);
        try output.appendSlice(allocator, "Conffiles:\n /etc/fixture abcdef\n\n");
    }
    return output.toOwnedSlice(allocator);
}

test "reference OpenSSL pair refuses changed signed graph, pending triggers and outside state" {
    const allocator = std.testing.allocator;
    const status = try cycleStatusFixtureFor(allocator, .openssl);
    defer allocator.free(status);
    try std.testing.expect(cycleStatusMatchesFor(status, .openssl));
    for ([_]struct { before: []const u8, after: []const u8 }{
        .{ .before = "Depends: libc6 (>= 2.14), libssl3t64", .after = "Depends: libc6 (>= 2.14), other" },
        .{ .before = "Package: libssl3t64", .after = "Package: libssl3t64\nPre-Depends: openssl-provider-legacy" },
        .{ .before = "Status: install ok installed", .after = "Status: install ok unpacked" },
        .{ .before = "Status: install ok unpacked", .after = "Status: install ok triggers-pending" },
        .{ .before = "Multi-Arch: foreign", .after = "Multi-Arch: same" },
        .{ .before = "Multi-Arch: foreign", .after = "Triggers-Pending: ldconfig\nMulti-Arch: foreign" },
        .{ .before = "Provides: libz1", .after = "Provides: other" },
        .{ .before = "Architecture: amd64", .after = "Architecture: arm64" },
        .{ .before = "Version: 3.5.5-1ubuntu3.6", .after = "Version: 3.5.5-1ubuntu3.7" },
        .{ .before = "Package: libssl3t64", .after = "Package: libssl3t64\npackage: libssl3t64" },
    }) |mutation| {
        const changed = try std.mem.replaceOwned(u8, allocator, status, mutation.before, mutation.after);
        defer allocator.free(changed);
        try std.testing.expect(!cycleStatusMatchesFor(changed, .openssl));
    }
    const missing = std.mem.indexOf(u8, status, "Package: zlib1g").?;
    try std.testing.expect(!cycleStatusMatchesFor(status[0..missing], .openssl));
}

test "reference kbd cycle binds original all-architecture peers and installed outside libc" {
    const allocator = std.testing.allocator;
    const status = try cycleStatusFixtureFor(allocator, .kbd);
    defer allocator.free(status);
    try std.testing.expect(cycleStatusMatchesFor(status, .kbd));
    for ([_]struct { before: []const u8, after: []const u8 }{
        .{ .before = "Architecture: all", .after = "Architecture: amd64" },
        .{ .before = "Depends: libc6 (>= 2.38), console-setup", .after = "Depends: libc6 (>= 2.38), other" },
        .{ .before = "Pre-Depends: debconf | debconf-2.0", .after = "Pre-Depends: other" },
        .{ .before = "Status: install ok installed", .after = "Status: install ok unpacked" },
        .{ .before = "Status: install ok unpacked", .after = "Status: install ok triggers-pending" },
        .{ .before = "Provides: console-utilities", .after = "Provides: console-utilities\nTriggers-Pending: update-initramfs" },
        .{ .before = "Version: 2.7.1-2ubuntu2", .after = "Version: 2.7.1-2ubuntu3" },
    }) |mutation| {
        const changed = try std.mem.replaceOwned(u8, allocator, status, mutation.before, mutation.after);
        defer allocator.free(changed);
        try std.testing.expect(!cycleStatusMatchesFor(changed, .kbd));
    }
}

test "reference kbd cycle operation never authorizes a console callback or another architecture" {
    const options: Options = .{
        .root = "/protected/root",
        .dpkg = "/protected/dpkg",
        .runtime = "/protected/runtime",
        .architecture = "amd64",
        .profile = .kbd_cycle,
        .verb = .break_kbd_cycle,
        .selector = "kbd:amd64",
        .kbd_archives = .{ "/protected/kbd", "/protected/linux", "/protected/console", "/protected/libc" },
    };
    try validateOptions(options);
    var changed = options;
    changed.selector = "console-setup-linux";
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.architecture = "arm64";
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.profile = .none;
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.verb = .configure;
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
    changed = options;
    changed.kbd_archives = null;
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
}

test "reference OpenSSL operation cannot become a generic batch or proc profile" {
    const options: Options = .{
        .root = "/protected/root",
        .dpkg = "/protected/dpkg",
        .runtime = "/protected/runtime",
        .architecture = "amd64",
        .profile = .openssl_cycle,
        .verb = .configure_openssl_cycle,
        .selector = "libssl3t64:amd64",
        .openssl_archives = .{ "/protected/ssl", "/protected/provider", "/protected/libc", "/protected/zstd", "/protected/zlib" },
    };
    try validateOptions(options);
    var changed = options;
    changed.verb = .configure;
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
    changed = options;
    changed.profile = .none;
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.profile = .systemd;
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.architecture = "arm64";
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.selector = "openssl-provider-legacy:amd64";
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.openssl_archives = null;
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
    changed = options;
    changed.cycle_archives = .{ "/protected/libc", "/protected/libgcc", "/protected/gcc", "/protected/gconv" };
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
}

test "reference cycle authority refuses changed graph, pre-depends, triggers and outside state" {
    const allocator = std.testing.allocator;
    const status = try cycleStatusFixture(allocator);
    defer allocator.free(status);
    try std.testing.expect(cycleStatusMatches(status));
    for ([_]struct { before: []const u8, after: []const u8 }{
        .{ .before = "Depends: libgcc-s1,", .after = "Depends: unknown-package," },
        .{ .before = "Depends: gcc-16-base", .after = "Pre-Depends: libc6\nDepends: gcc-16-base" },
        .{ .before = "Status: install ok installed", .after = "Status: install ok unpacked" },
        .{ .before = "Status: install ok unpacked", .after = "Status: install ok triggers-pending" },
        .{ .before = "Protected: yes", .after = "Protected: no" },
        .{ .before = "Protected: yes", .after = "Triggers-Pending: ldconfig\nProtected: yes" },
        .{ .before = "Protected: yes", .after = "Config-Version: previous\nProtected: yes" },
        .{ .before = "Architecture: amd64", .after = "Architecture: arm64" },
        .{ .before = "Multi-Arch: same", .after = "Multi-Arch: foreign" },
        .{ .before = "Multi-Arch: same\n", .after = "" },
        .{ .before = "Version: 16-20260322-1ubuntu1", .after = "Version: 16-20260322-1ubuntu2" },
        .{ .before = "Package: libgcc-s1", .after = "Package: libgcc-s1\npackage: libgcc-s1" },
        .{ .before = "Depends: gcc-16-base", .after = "Depends: gcc-16-base\n continued" },
    }) |mutation| {
        const changed = try std.mem.replaceOwned(u8, allocator, status, mutation.before, mutation.after);
        defer allocator.free(changed);
        try std.testing.expect(!cycleStatusMatches(changed));
    }
    const missing = std.mem.indexOf(u8, status, "Package: gcc-16-base").?;
    try std.testing.expect(!cycleStatusMatches(status[0..missing]));
}

test "reference cycle operation is not generic configure or a proc profile" {
    const options: Options = .{
        .root = "/protected/root",
        .dpkg = "/protected/dpkg",
        .runtime = "/protected/runtime",
        .architecture = "amd64",
        .profile = .libgcc_cycle,
        .verb = .break_base_cycle,
        .selector = "libgcc-s1:amd64",
        .cycle_archives = .{ "/protected/libc6", "/protected/libgcc", "/protected/gcc-base", "/protected/gconv" },
    };
    try validateOptions(options);
    try std.testing.expect(scriptBinding(options.profile) == null);
    var changed = options;
    changed.verb = .configure;
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
    changed = options;
    changed.profile = .none;
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.architecture = "arm64";
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.selector = "libc6:amd64";
    try std.testing.expectError(error.InvalidCycleProfile, validateOptions(changed));
    changed = options;
    changed.cycle_archives = null;
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
    changed = options;
    changed.archive = "/protected/extra";
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
}

test "reference capability transition fails closed without root authority" {
    try unprivilegedTransitionProbe();
}

test "prestate continuation accepts only exact systemd and udev half-configured bindings" {
    for ([_]Profile{ .systemd, .udev }) |profile| {
        const binding = scriptBinding(profile).?;
        const selector = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}:amd64", .{binding.name}, 0);
        defer std.testing.allocator.free(selector);
        const options: Options = .{
            .root = "/root/proof/root",
            .dpkg = "/root/proof/dpkg",
            .runtime = "/root/proof/runtime",
            .architecture = "amd64",
            .profile = profile,
            .verb = .continue_prestate,
            .selector = selector,
        };
        try validateOptions(options);
        for ([_][]const u8{ "half-configured", "unpacked", "installed", "triggers-pending" }) |state| {
            const bytes = try std.fmt.allocPrint(std.testing.allocator, "Package: {s}\nVersion: {s}\nArchitecture: amd64\nStatus: install ok {s}\n\n", .{ binding.name, binding.version, state });
            defer std.testing.allocator.free(bytes);
            try std.testing.expectEqual(std.mem.eql(u8, state, "half-configured"), bindingStatusMatchesFor(bytes, binding, .continue_prestate));
            try std.testing.expectEqual(std.mem.eql(u8, state, "unpacked"), bindingStatusMatchesFor(bytes, binding, .configure));
        }
        for ([_][3][]const u8{
            .{ "wrong", binding.version, "amd64" },
            .{ binding.name, "wrong", "amd64" },
            .{ binding.name, binding.version, "arm64" },
        }) |identity| {
            const bytes = try std.fmt.allocPrint(std.testing.allocator, "Package: {s}\nVersion: {s}\nArchitecture: {s}\nStatus: install ok half-configured\n\n", .{ identity[0], identity[1], identity[2] });
            defer std.testing.allocator.free(bytes);
            try std.testing.expect(!bindingStatusMatchesFor(bytes, binding, .continue_prestate));
        }
        var changed = options;
        changed.architecture = "arm64";
        try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
        changed = options;
        changed.selector = "sudo:amd64";
        try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
    }
    const sudo: Options = .{
        .root = "/root/proof/root",
        .dpkg = "/root/proof/dpkg",
        .runtime = "/root/proof/runtime",
        .architecture = "amd64",
        .profile = .sudo,
        .verb = .continue_prestate,
        .selector = "sudo:amd64",
    };
    try std.testing.expectError(error.InvalidProfile, validateOptions(sudo));
    try std.testing.expect(!bindingStatusMatchesFor(
        "Package: sudo\nVersion: 1.9.17p2-1ubuntu3.1\nArchitecture: amd64\nStatus: install ok half-configured\n\n",
        scriptBinding(.sudo).?,
        .continue_prestate,
    ));
    var none = sudo;
    none.profile = .none;
    try std.testing.expectError(error.InvalidProfile, validateOptions(none));
}

test "reference launcher rejects wider profiles and unsafe operation shapes" {
    const base: Options = .{
        .root = "/root/proof/root",
        .dpkg = "/root/proof/dpkg",
        .runtime = "/root/proof/runtime",
        .architecture = "amd64",
        .profile = .none,
        .verb = .configure,
        .selector = "demo:amd64",
    };
    try validateOptions(base);
    var changed = base;
    changed.profile = .systemd;
    try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
    changed.selector = "systemd:amd64";
    try validateOptions(changed);
    changed.selector = "udev:amd64";
    try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
    changed.profile = .udev;
    try validateOptions(changed);
    changed.profile = .sudo;
    changed.selector = "sudo:amd64";
    try validateOptions(changed);
    changed.profile = .none;
    try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
    changed.verb = .probe_configure;
    try validateOptions(changed);
    changed.verb = .configure;
    changed.profile = .sudo;
    changed.architecture = "arm64";
    try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
    changed = base;
    changed.selector = "--pending";
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
    changed = base;
    changed.verb = .unpack;
    changed.archive = "/root/proof/archive";
    changed.archive_sha512 = "0" ** 128;
    changed.archive_size = 1;
    try validateOptions(changed);
    changed.archive_sha512 = "G" ** 128;
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
    changed = base;
    try std.testing.expect(std.meta.stringToEnum(Verb, "configure_batch") == null);
    try std.testing.expect(std.meta.stringToEnum(Verb, "triggers") == null);
    changed = base;
    changed.root = "/root/../host";
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
}

test "reference syscall filter denies namespace changes and permits ordinary forks" {
    const arch: u32 = switch (@import("builtin").cpu.arch) {
        .x86_64 => 0xc000003e,
        .aarch64 => 0xc00000b7,
        else => unreachable,
    };
    try std.testing.expectEqual(@as(u32, 0x80000000), try evaluateFilter(0, @intFromEnum(linux.SYS.getpid), 0));
    try std.testing.expectEqual(@as(u32, 0x80000000), try evaluateFilter(arch, 0x40000000, 0));
    try std.testing.expectEqual(@as(u32, 0x7fff0000), try evaluateFilter(arch, @intFromEnum(linux.SYS.getpid), 0));
    inline for (deny_syscalls) |number| {
        try std.testing.expectEqual(@as(u32, 0x00050001), try evaluateFilter(arch, @intFromEnum(number), 0));
    }
    try std.testing.expectEqual(@as(u32, 0x00050001), try evaluateFilter(arch, @intFromEnum(linux.SYS.chroot), 0));
    try std.testing.expectEqual(@as(u32, 0x00050026), try evaluateFilter(arch, @intFromEnum(linux.SYS.clone3), 0));
    inline for (.{ linux.CLONE.NEWUSER, linux.CLONE.NEWNS, linux.CLONE.NEWPID, linux.CLONE.NEWNET, linux.CLONE.NEWUTS, linux.CLONE.NEWIPC, linux.CLONE.NEWCGROUP, linux.CLONE.NEWTIME }) |flag| {
        try std.testing.expectEqual(@as(u32, 0x00050001), try evaluateFilter(arch, @intFromEnum(linux.SYS.clone), flag));
    }
    try std.testing.expectEqual(@as(u32, 0x7fff0000), try evaluateFilter(arch, @intFromEnum(linux.SYS.clone), 0));
}

test "reference capability transition retains only filesystem and account authority" {
    const expected = linux.CAP.TO_MASK(linux.CAP.CHOWN) |
        linux.CAP.TO_MASK(linux.CAP.DAC_OVERRIDE) |
        linux.CAP.TO_MASK(linux.CAP.FOWNER) |
        linux.CAP.TO_MASK(linux.CAP.FSETID) |
        linux.CAP.TO_MASK(linux.CAP.SETGID) |
        linux.CAP.TO_MASK(linux.CAP.SETUID) |
        linux.CAP.TO_MASK(linux.CAP.SETFCAP);
    try std.testing.expectEqual(expected, allowedCapabilityMask(0));
    try std.testing.expectEqual(@as(u32, 0), allowedCapabilityMask(1));
    inline for (.{ linux.CAP.SYS_CHROOT, linux.CAP.SYS_ADMIN, linux.CAP.SYS_MODULE, linux.CAP.MKNOD }) |capability|
        try std.testing.expect(!allowedCapability(capability));
    try std.testing.expect(!allowedCapability(39)); // CAP_BPF, in the second capset word
    try std.testing.expect(!allowedCapability(40)); // CAP_CHECKPOINT_RESTORE

    var data: [2]linux.cap_user_data_t = .{
        .{ .effective = 0xffffffff, .permitted = 0xffffffff, .inheritable = 0xffffffff },
        .{ .effective = 0xffffffff, .permitted = 0xffffffff, .inheritable = 0xffffffff },
    };
    restrictCapabilityData(&data);
    try std.testing.expectEqual(expected, data[0].effective);
    try std.testing.expectEqual(expected, data[0].permitted);
    try std.testing.expectEqual(expected, data[0].inheritable);
    try std.testing.expectEqual(@as(u32, 0), data[1].effective);
    try std.testing.expectEqual(@as(u32, 0), data[1].permitted);
    try std.testing.expectEqual(@as(u32, 0), data[1].inheritable);
}

// The protected launcher runs as real root, so this probe does too: only
// `tools/real-snapshot-reference-launcher-root-test.zig`, run through `sudo -n`
// by `zig build test-real-snapshot-reference-launcher-root`, calls it. A user
// namespace is not a substitute: an LSM may confine it and filter its effective
// set but not its bounding set.
pub fn capabilityTransitionProbe() !void {
    const child = linux.fork();
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(child));
    if (child == 0) {
        if (linux.geteuid() != 0 or linux.getuid() != 0) linux.exit(14);
        var data: [2]linux.cap_user_data_t = undefined;
        if (readCapabilities(&data) != .SUCCESS) linux.exit(2);
        if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.SYS_MODULE, 0, 0, 0) == 1 and
            data[0].effective & linux.CAP.TO_MASK(linux.CAP.SYS_MODULE) == 0) linux.exit(12);
        if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), 39, 0, 0, 0) == 1 and
            data[1].effective & (@as(u32, 1) << 7) == 0) linux.exit(13);
        data[0].inheritable |= linux.CAP.TO_MASK(linux.CAP.CHOWN);
        if (writeCapabilities(&data) != .SUCCESS) linux.exit(3);
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), 2, linux.CAP.CHOWN, 0, 0) != 0)
            linux.exit(4);
        if (restrictReferencePrivileges() != .SUCCESS) linux.exit(5);
        if (readCapabilities(&data) != .SUCCESS) linux.exit(6);
        if (data[1].effective != 0 or data[1].permitted != 0 or data[1].inheritable != 0)
            linux.exit(7);
        inline for (.{
            linux.CAP.SYS_MODULE, linux.CAP.SYS_CHROOT, linux.CAP.SYS_ADMIN,
            linux.CAP.MKNOD,      linux.CAP.SETPCAP,
        }) |capability| {
            if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), capability, 0, 0, 0) != 0)
                linux.exit(8);
        }
        inline for (.{ @as(u32, 39), @as(u32, 40) }) |capability| {
            if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), capability, 0, 0, 0) != 0)
                linux.exit(9);
        }
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), 1, linux.CAP.CHOWN, 0, 0) != 0)
            linux.exit(10);
        if (linux.errno(linux.syscall0(.init_module)) != .PERM) linux.exit(11);
        const refused_namespace = linux.clone2(reference_namespaces | @intFromEnum(linux.SIG.CHLD), 0);
        if (linux.errno(refused_namespace) != .PERM) linux.exit(15);
        if (private_network.setupLoopback() != .PERM) linux.exit(16);
        linux.exit(0);
    }
    var status: u32 = 0;
    const waited = linux.syscall4(
        .wait4,
        @bitCast(@as(isize, @intCast(child))),
        @intFromPtr(&status),
        0,
        0,
    );
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(waited));
    try std.testing.expect(linux.W.IFEXITED(status));
    if (linux.W.EXITSTATUS(status) == 14) return error.CapabilityProbeRequiresRoot;
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

fn unprivilegedTransitionProbe() !void {
    const child = linux.fork();
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(child));
    if (child == 0) {
        if (linux.geteuid() == 0 or linux.getuid() == 0) {
            const nobody = [_]linux.gid_t{65534};
            if (linux.errno(linux.setgroups(nobody.len, &nobody)) != .SUCCESS) linux.exit(1);
            if (linux.errno(linux.setresgid(65534, 65534, 65534)) != .SUCCESS) linux.exit(1);
            if (linux.errno(linux.setresuid(65534, 65534, 65534)) != .SUCCESS) linux.exit(1);
        }
        var data: [2]linux.cap_user_data_t = undefined;
        if (readCapabilities(&data) != .SUCCESS) linux.exit(2);
        if (data[0].effective != 0 or data[0].permitted != 0 or
            data[1].effective != 0 or data[1].permitted != 0) linux.exit(3);
        if (restrictReferencePrivileges() != .PERM) linux.exit(4);
        if (linux.prctl(@intFromEnum(linux.PR.GET_SECCOMP), 0, 0, 0, 0) != 0) linux.exit(5);
        if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.DAC_READ_SEARCH, 0, 0, 0) != 1)
            linux.exit(6);
        linux.exit(0);
    }
    var status: u32 = 0;
    const waited = linux.syscall4(
        .wait4,
        @bitCast(@as(isize, @intCast(child))),
        @intFromPtr(&status),
        0,
        0,
    );
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(waited));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "installed reference filter refuses module, mount, re-chroot, and namespace syscalls" {
    const child = linux.fork();
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(child));
    if (child == 0) {
        const no_new_privileges = linux.errno(linux.prctl(
            @intFromEnum(linux.PR.SET_NO_NEW_PRIVS),
            1,
            0,
            0,
            0,
        ));
        if (no_new_privileges != .SUCCESS) linux.exit(1);
        var policy: BpfProgram = .{ .len = filter.len, .filter = &filter };
        const installed = linux.errno(linux.syscall3(.seccomp, 1, 0, @intFromPtr(&policy)));
        if (installed != .SUCCESS) linux.exit(2);
        inline for (.{
            linux.SYS.init_module,   linux.SYS.finit_module, linux.SYS.delete_module,
            linux.SYS.mount,         linux.SYS.open_tree,    linux.SYS.move_mount,
            linux.SYS.mount_setattr, linux.SYS.chroot,       linux.SYS.unshare,
            linux.SYS.setns,
        }) |call| {
            if (linux.errno(linux.syscall0(call)) != .PERM) linux.exit(3);
        }
        inline for (.{ linux.CLONE.NEWUSER, linux.CLONE.NEWNS, linux.CLONE.NEWPID, linux.CLONE.NEWNET, linux.CLONE.NEWUTS, linux.CLONE.NEWIPC, linux.CLONE.NEWCGROUP, linux.CLONE.NEWTIME }) |flag| {
            const clone = linux.clone2(flag | @intFromEnum(linux.SIG.CHLD), 0);
            if (linux.errno(clone) != .PERM) linux.exit(4);
        }
        if (linux.errno(linux.syscall0(.clone3)) != .NOSYS) linux.exit(5);
        const ordinary = linux.fork();
        if (linux.errno(ordinary) != .SUCCESS) linux.exit(6);
        if (ordinary == 0) linux.exit(0);
        var grandchild_status: u32 = 0;
        const reaped = linux.syscall4(
            .wait4,
            @bitCast(@as(isize, @intCast(ordinary))),
            @intFromPtr(&grandchild_status),
            0,
            0,
        );
        if (linux.errno(reaped) != .SUCCESS or
            !linux.W.IFEXITED(grandchild_status) or
            linux.W.EXITSTATUS(grandchild_status) != 0) linux.exit(7);
        linux.exit(0);
    }
    var status: u32 = 0;
    const waited = linux.syscall4(
        .wait4,
        @bitCast(@as(isize, @intCast(child))),
        @intFromPtr(&status),
        0,
        0,
    );
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(waited));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "reference PID 1 refuses an orphaned supervisor pipe" {
    var fds: [2]i32 = undefined;
    _ = try checked(linux.pipe2(&fds, .{ .CLOEXEC = true, .NONBLOCK = true }));
    defer _ = linux.close(fds[0]);
    try std.testing.expect(supervisorPipeAlive(fds[0]));
    _ = linux.close(fds[1]);
    try std.testing.expect(!supervisorPipeAlive(fds[0]));
}

test "reference deadline kills and reaps a hung child" {
    const child = linux.fork();
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(child));
    if (child == 0) {
        const delay: linux.timespec = .{ .sec = 10, .nsec = 0 };
        _ = linux.nanosleep(&delay, null);
        linux.exit(0);
    }
    const pid: i32 = @intCast(child);
    try std.testing.expectError(error.ReferenceDeadlineExceeded, awaitNamespace(pid, 30));
    var status: u32 = 0;
    try std.testing.expectEqual(linux.E.CHILD, linux.errno(linux.waitpid(pid, &status, linux.W.NOHANG)));
}

test "reference standard streams refuse directory-backed stdin and readable host output" {
    const directory = linux.open("/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(directory));
    defer _ = linux.close(@intCast(directory));
    const info = try metadata(@intCast(directory));
    const directory_flags = try checked(linux.fcntl(@intCast(directory), linux.F.GETFL, 0));
    try std.testing.expectEqual(@as(u32, 0o040000), info.mode & 0o170000);
    try std.testing.expectError(error.InvalidStandardStream, verifyStandardStream(0, @intCast(directory)));
    try std.testing.expect(same(info, try metadata(@intCast(directory))));
    try std.testing.expect(!allowedStandardStream(0, info, directory_flags));
    try std.testing.expect(!allowedStandardStream(1, info, directory_flags));

    var input = std.mem.zeroes(linux.Statx);
    input.mode = 0o020666;
    input.rdev_major = 1;
    input.rdev_minor = 3;
    try std.testing.expect(allowedStandardStream(0, input, 0));
    try std.testing.expect(!allowedStandardStream(0, input, 1));
    var output = std.mem.zeroes(linux.Statx);
    output.mode = 0o100600;
    output.nlink = 1;
    const append: usize = 1 << @bitOffsetOf(linux.O, "APPEND");
    try std.testing.expect(allowedStandardStream(1, output, 1 | append));
    try std.testing.expect(allowedStandardStream(2, output, 1 | append));
    try std.testing.expect(!allowedStandardStream(1, output, 2 | append));
    try std.testing.expect(!allowedStandardStream(2, output, 1));
    output.mode = 0o100622;
    try std.testing.expect(!allowedStandardStream(1, output, 1 | append));
}

test "reference stdin refuses the read-write /dev/null that subprocess.DEVNULL opens" {
    // CPython opens os.devnull with O_RDWR for subprocess.DEVNULL, so callers
    // that pass it hand the launcher a writable stdin.
    const read_write = linux.open("/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(read_write));
    defer _ = linux.close(@intCast(read_write));
    const writable = try metadata(@intCast(read_write));
    try std.testing.expectEqual(@as(u32, 0o020000), writable.mode & 0o170000);
    try std.testing.expectEqual(@as(u32, 1), writable.rdev_major);
    try std.testing.expectEqual(@as(u32, 3), writable.rdev_minor);
    try std.testing.expectError(
        error.InvalidStandardStream,
        verifyStandardStream(0, @intCast(read_write)),
    );

    const read_only = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(read_only));
    defer _ = linux.close(@intCast(read_only));
    try verifyStandardStream(0, @intCast(read_only));
}

test "reference proc profile is bound to the installed dpkg status version" {
    try std.testing.expectEqualStrings("systemd", script_bindings[0].name);
    try std.testing.expectEqualStrings("259.5-0ubuntu3.4", script_bindings[0].version);
    try std.testing.expectEqual(@as(u64, 5037), script_bindings[0].size);
    try std.testing.expectEqualStrings(
        "d9df6a03ccb6b557c16ac1c674557a66c1db290f3c6d3cadbef335e0ce74e31d",
        script_bindings[0].digest,
    );
    try std.testing.expectEqualStrings("udev", script_bindings[1].name);
    try std.testing.expectEqualStrings("259.5-0ubuntu3.4", script_bindings[1].version);
    try std.testing.expectEqual(@as(u64, 2578), script_bindings[1].size);
    try std.testing.expectEqualStrings(
        "b7892e975bcce896c4938c2219a244fa03863d5eff37cd2eb66d2b8540f14606",
        script_bindings[1].digest,
    );
    try std.testing.expectEqualStrings("sudo", script_bindings[2].name);
    try std.testing.expectEqualStrings("1.9.17p2-1ubuntu3.1", script_bindings[2].version);
    try std.testing.expectEqual(@as(u64, 1747), script_bindings[2].size);
    try std.testing.expectEqualStrings(
        "fd4c65932ab3ab7ce90c3633c42b8ee7a36af2c8292142d6e0cd134dda4c6383",
        script_bindings[2].digest,
    );
    const binding = script_bindings[0];
    const valid =
        "Package: other\nVersion: 1\nArchitecture: amd64\n" ++
        "Status: install ok installed\n\n" ++
        "Package: systemd\nVersion: 259.5-0ubuntu3.4\nArchitecture: amd64\n" ++
        "Status: install ok unpacked\n\n";
    try std.testing.expect(bindingStatusMatches(valid, binding));
    try std.testing.expect(bindingStatusMatches(valid ++
        "Package: conffile-owner\nVersion: 1\nArchitecture: amd64\n" ++
        "Status: install ok installed\nConffiles:\n /etc/fixture abcdef\n\n", binding));
    try std.testing.expect(!bindingStatusMatches(valid ++
        "Package: conffile-owner\nVersion: 1\nArchitecture: amd64\n" ++
        "Status: install ok installed\nConffiles:missing-space\n\n", binding));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 259.5-0ubuntu3.5\nArchitecture: amd64\n" ++
            "Status: install ok unpacked\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 259.5-0ubuntu3.4\nArchitecture: arm64\n" ++
            "Status: install ok unpacked\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 259.5-0ubuntu3.4\nArchitecture: amd64\n" ++
            "Status: install ok triggers-pending\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(valid ++
        "Package: systemd\nVersion: 259.5-0ubuntu3.4\nArchitecture: amd64\n" ++
        "Status: install ok unpacked\n\n", binding));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 259.5-0ubuntu3.4\nVersion: 259.5-0ubuntu3.4\n" ++
            "Architecture: amd64\nStatus: install ok unpacked\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nversion: 259.5-0ubuntu3.5\nVersion: 259.5-0ubuntu3.4\n" ++
            "Architecture: amd64\nStatus: install ok unpacked\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 259.5-0ubuntu3.4\nArchitecture: amd64\n" ++
            "Status: install ok unpacked\n continued\n\n",
        binding,
    ));
}

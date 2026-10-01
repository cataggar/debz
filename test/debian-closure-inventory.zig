//! Pre-mutation feature inventory of an authenticated Debian closure (#261).
//!
//! The input manifest is written by `tools/debian-stable-closure.py` only after
//! every package was matched to its signed Packages record. Each archive is read
//! once from the verified package cache, rechecked against its declared size,
//! signed SHA256, and derived SHA512, and then prepared with the same native
//! archive-application model that gates mutation. Control members and statically
//! detected maintainer-script tools are classified into a prioritized native gap
//! list. Nothing is extracted, written into a root, or executed.

const std = @import("std");
const debz = @import("debz");

const archive_application = debz.archive_application;
const native_alternatives = debz.native_alternatives;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;

const manifest_schema = "https://debz.dev/test/debian-closure-manifest-v1";
const inventory_schema = "https://debz.dev/test/debian-closure-inventory-v1";
const maximum_manifest_bytes = 4 * 1024 * 1024;
const maximum_archive_bytes = 256 * 1024 * 1024;
const maximum_packages = 1024;
const maximum_invocations_per_script = 1024;
const maximum_invocation_text = 160;

pub const Error = error{
    InvalidArguments,
    InvalidManifest,
    ArchiveSizeMismatch,
    SignedDigestMismatch,
    DerivedDigestMismatch,
    InventoryLimit,
    InvalidEvidence,
};

/// Gap categories in priority order. The priority states how far the native
/// engine is from executing the feature for Debian bytes, not how common it is.
pub const Category = enum {
    native_archive_rejected,
    alternatives_script_authority,
    debconf_frontend,
    kernel_filesystem,
    device_node,
    accounts,
    service_manager,
    system_registry,
    capabilities,
    environment_probe,
    dpkg_database_helper,
    conffile_helper,
    ldconfig,
    trigger_declaration,
    remove_on_upgrade_conffile,
    ownership_and_mode,

    pub fn priority(self: Category) []const u8 {
        return switch (self) {
            .native_archive_rejected => "P0",
            .alternatives_script_authority,
            .debconf_frontend,
            .kernel_filesystem,
            .device_node,
            => "P1",
            .accounts,
            .service_manager,
            .system_registry,
            .capabilities,
            .environment_probe,
            => "P2",
            .dpkg_database_helper,
            .conffile_helper,
            .ldconfig,
            .trigger_declaration,
            .remove_on_upgrade_conffile,
            => "P3",
            .ownership_and_mode => "P4",
        };
    }
};

const ToolRule = struct { name: []const u8, category: Category };

const tool_rules = [_]ToolRule{
    .{ .name = "update-alternatives", .category = .alternatives_script_authority },
    .{ .name = "debconf-set-selections", .category = .debconf_frontend },
    .{ .name = "debconf-communicate", .category = .debconf_frontend },
    .{ .name = "dpkg-reconfigure", .category = .debconf_frontend },
    .{ .name = "mknod", .category = .device_node },
    .{ .name = "mkfifo", .category = .device_node },
    .{ .name = "MAKEDEV", .category = .device_node },
    .{ .name = "adduser", .category = .accounts },
    .{ .name = "addgroup", .category = .accounts },
    .{ .name = "deluser", .category = .accounts },
    .{ .name = "delgroup", .category = .accounts },
    .{ .name = "useradd", .category = .accounts },
    .{ .name = "userdel", .category = .accounts },
    .{ .name = "usermod", .category = .accounts },
    .{ .name = "groupadd", .category = .accounts },
    .{ .name = "groupdel", .category = .accounts },
    .{ .name = "groupmod", .category = .accounts },
    .{ .name = "systemd-sysusers", .category = .accounts },
    .{ .name = "update-passwd", .category = .accounts },
    .{ .name = "pam-auth-update", .category = .accounts },
    .{ .name = "chpasswd", .category = .accounts },
    .{ .name = "shadowconfig", .category = .accounts },
    .{ .name = "pwconv", .category = .accounts },
    .{ .name = "grpconv", .category = .accounts },
    .{ .name = "getent", .category = .accounts },
    .{ .name = "deb-systemd-helper", .category = .service_manager },
    .{ .name = "deb-systemd-invoke", .category = .service_manager },
    .{ .name = "systemctl", .category = .service_manager },
    .{ .name = "invoke-rc.d", .category = .service_manager },
    .{ .name = "update-rc.d", .category = .service_manager },
    .{ .name = "systemd-tmpfiles", .category = .service_manager },
    .{ .name = "systemd-hwdb", .category = .service_manager },
    .{ .name = "systemd-machine-id-setup", .category = .service_manager },
    .{ .name = "udevadm", .category = .service_manager },
    .{ .name = "start-stop-daemon", .category = .service_manager },
    .{ .name = "add-shell", .category = .system_registry },
    .{ .name = "remove-shell", .category = .system_registry },
    .{ .name = "update-shells", .category = .system_registry },
    .{ .name = "update-ca-certificates", .category = .system_registry },
    .{ .name = "update-mime", .category = .system_registry },
    .{ .name = "install-info", .category = .system_registry },
    .{ .name = "locale-gen", .category = .system_registry },
    .{ .name = "update-locale", .category = .system_registry },
    .{ .name = "update-initramfs", .category = .system_registry },
    .{ .name = "depmod", .category = .system_registry },
    .{ .name = "mandb", .category = .system_registry },
    .{ .name = "setcap", .category = .capabilities },
    .{ .name = "ischroot", .category = .environment_probe },
    .{ .name = "systemd-detect-virt", .category = .environment_probe },
    .{ .name = "dpkg-divert", .category = .dpkg_database_helper },
    .{ .name = "dpkg-statoverride", .category = .dpkg_database_helper },
    .{ .name = "dpkg-maintscript-helper", .category = .dpkg_database_helper },
    .{ .name = "dpkg-trigger", .category = .dpkg_database_helper },
    .{ .name = "dpkg-query", .category = .dpkg_database_helper },
    .{ .name = "dpkg", .category = .dpkg_database_helper },
    .{ .name = "ucf", .category = .conffile_helper },
    .{ .name = "ucfr", .category = .conffile_helper },
    .{ .name = "ucfq", .category = .conffile_helper },
    .{ .name = "ldconfig", .category = .ldconfig },
    .{ .name = "chown", .category = .ownership_and_mode },
    .{ .name = "chgrp", .category = .ownership_and_mode },
    .{ .name = "chmod", .category = .ownership_and_mode },
};

const PathRule = struct { prefix: []const u8, tool: []const u8, category: Category };

const path_rules = [_]PathRule{
    .{ .prefix = "/proc", .tool = "/proc", .category = .kernel_filesystem },
    .{ .prefix = "/sys/", .tool = "/sys", .category = .kernel_filesystem },
    .{ .prefix = "/dev/", .tool = "/dev", .category = .device_node },
    .{ .prefix = "/run/", .tool = "/run", .category = .environment_probe },
};

/// Standard streams every runner root provides; redirecting to them is not a
/// device-node requirement.
const standard_devices = [_][]const u8{ "null", "stdin", "stdout", "stderr", "tty", "fd/" };

const command_prefixes = [_][]const u8{ "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/" };

pub const Expectation = struct {
    repository: []const u8,
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    filename: []const u8,
    size: u64,
    sha256: []const u8,
    sha512: []const u8,
};

pub const Invocation = struct {
    tool: []const u8,
    category: Category,
    line: usize,
    text: []const u8,
};

pub const ScriptReport = struct {
    kind: []const u8,
    lifecycle: bool,
    size: u64,
    sha256: []const u8,
    interpreter: []const u8,
    /// Result of the native engine's own pre-launch alternatives detector.
    alternatives_gate: bool,
    invocations: []const Invocation,
};

pub const ConffileReport = struct {
    path: []const u8,
    remove_on_upgrade: bool,
};

pub const TriggerReport = struct {
    directive: []const u8,
    target: []const u8,
};

pub const SystemPaths = struct {
    systemd_units: usize = 0,
    sysusers: []const []const u8 = &.{},
    tmpfiles: []const []const u8 = &.{},
    init_scripts: usize = 0,
    udev_rules: usize = 0,
    pam: usize = 0,
    cron: usize = 0,
};

pub const PayloadReport = struct {
    regular: usize = 0,
    directory: usize = 0,
    symlink: usize = 0,
    hardlink: usize = 0,
    setuid_or_setgid: []const []const u8 = &.{},
    non_root_owned: []const []const u8 = &.{},
    system_paths: SystemPaths = .{},
};

pub const NativeModel = struct {
    admitted: bool,
    application_sha256: ?[]const u8 = null,
    feature: ?[]const u8 = null,
    code: ?[]const u8 = null,
    payload_code: ?[]const u8 = null,
    entry_index: ?usize = null,
};

pub const GapReport = struct {
    priority: []const u8,
    category: Category,
    evidence: []const []const u8,
};

pub const PackageReport = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    filename: []const u8,
    size: u64,
    sha256: []const u8,
    derived_sha512: []const u8,
    native_model: NativeModel,
    essential: bool = false,
    protected: bool = false,
    priority: ?[]const u8 = null,
    payload: PayloadReport = .{},
    conffiles: []const ConffileReport = &.{},
    triggers: []const TriggerReport = &.{},
    metadata_members: []const []const u8 = &.{},
    scripts: []const ScriptReport = &.{},
    gaps: []const GapReport = &.{},
};

pub const NamedCount = struct { name: []const u8, count: usize };

pub const GapSummary = struct {
    priority: []const u8,
    category: Category,
    packages: []const []const u8,
};

pub const Summary = struct {
    packages: usize,
    admitted: usize,
    rejected: usize,
    total_bytes: u64,
    essential: usize,
    scripts: []const NamedCount,
    conffiles: usize,
    remove_on_upgrade_conffiles: usize,
    triggers: []const NamedCount,
    metadata_members: []const NamedCount,
    tools: []const NamedCount,
    gaps: []const GapSummary,
};

pub const Report = struct {
    schema: []const u8 = inventory_schema,
    version: u32 = 1,
    architecture: []const u8,
    repository: []const u8,
    packages: []const PackageReport,
    summary: Summary,
};

const ManifestPackage = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    filename: []const u8,
    size: u64,
    sha256: []const u8,
    sha512: []const u8,
    object: []const u8,
};

const Manifest = struct {
    schema: []const u8,
    version: u32,
    architecture: []const u8,
    repository: []const u8,
    packages: []const ManifestPackage,
};

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const command = args.next() orelse return error.InvalidArguments;
    if (!std.mem.eql(u8, command, "inventory")) return error.InvalidArguments;
    const manifest_path = args.next() orelse return error.InvalidArguments;
    const output_path = args.next() orelse return error.InvalidArguments;
    if (args.next() != null) return error.InvalidArguments;

    const arena = init.arena.allocator();
    const manifest_bytes = try readBounded(init.io, arena, manifest_path, maximum_manifest_bytes);
    const parsed = try std.json.parseFromSliceLeaky(Manifest, arena, manifest_bytes, .{
        .allocate = .alloc_always,
    });
    try validateManifest(parsed);

    const packages = try arena.alloc(PackageReport, parsed.packages.len);
    for (parsed.packages, packages) |item, *report| {
        const bytes = try readBounded(init.io, init.gpa, item.object, @min(item.size, maximum_archive_bytes));
        defer init.gpa.free(bytes);
        report.* = try inspectArchive(arena, init.gpa, bytes, .{
            .repository = parsed.repository,
            .name = item.name,
            .version = item.version,
            .architecture = item.architecture,
            .filename = item.filename,
            .size = item.size,
            .sha256 = item.sha256,
            .sha512 = item.sha512,
        });
    }
    const report: Report = .{
        .architecture = parsed.architecture,
        .repository = parsed.repository,
        .packages = packages,
        .summary = try summarize(arena, packages),
    };
    const encoded = try std.json.Stringify.valueAlloc(arena, report, .{ .whitespace = .indent_2 });
    var file = try std.Io.Dir.createFileAbsolute(init.io, output_path, .{ .exclusive = true });
    defer file.close(init.io);
    try file.writeStreamingAll(init.io, encoded);
    try file.writeStreamingAll(init.io, "\n");
    try file.sync(init.io);
}

fn validateManifest(manifest: Manifest) Error!void {
    if (!std.mem.eql(u8, manifest.schema, manifest_schema) or manifest.version != 1)
        return error.InvalidManifest;
    if (manifest.packages.len == 0 or manifest.packages.len > maximum_packages)
        return error.InvalidManifest;
    for (manifest.packages, 0..) |item, index| {
        if (!std.fs.path.isAbsolute(item.object) or item.size == 0 or
            item.size > maximum_archive_bytes)
            return error.InvalidManifest;
        if (!std.mem.eql(u8, item.architecture, manifest.architecture) and
            !std.mem.eql(u8, item.architecture, "all"))
            return error.InvalidManifest;
        if (index != 0 and std.mem.order(u8, manifest.packages[index - 1].name, item.name) != .lt)
            return error.InvalidManifest;
    }
}

fn readBounded(io: std.Io, allocator: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(limit + 1));
}

fn hexDigest(arena: std.mem.Allocator, digest: []const u8) ![]const u8 {
    const out = try arena.alloc(u8, digest.len * 2);
    const alphabet = "0123456789abcdef";
    for (digest, 0..) |byte, index| {
        out[index * 2] = alphabet[byte >> 4];
        out[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out;
}

/// Rechecks the bound identity and prepares the native application model. A
/// size, signed SHA256, or derived SHA512 mismatch is an error, never a gap.
pub fn inspectArchive(
    arena: std.mem.Allocator,
    scratch: std.mem.Allocator,
    bytes: []const u8,
    expected: Expectation,
) !PackageReport {
    if (bytes.len != expected.size) return error.ArchiveSizeMismatch;
    var signed: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &signed, .{});
    if (!std.mem.eql(u8, try hexDigest(arena, &signed), expected.sha256))
        return error.SignedDigestMismatch;
    var derived: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(bytes, &derived, .{});
    if (!std.mem.eql(u8, try hexDigest(arena, &derived), expected.sha512))
        return error.DerivedDigestMismatch;

    var report: PackageReport = .{
        .package = expected.name,
        .version = expected.version,
        .architecture = expected.architecture,
        .filename = expected.filename,
        .size = expected.size,
        .sha256 = expected.sha256,
        .derived_sha512 = expected.sha512,
        .native_model = .{ .admitted = false },
    };
    var result = archive_application.prepare(scratch, bytes, .{ .repository = .{
        .repository = expected.repository,
        .package = expected.name,
        .version = expected.version,
        .architecture = expected.architecture,
        .requested_package = expected.name,
        .filename = expected.filename,
        .size = expected.size,
        .sha256 = signed,
    } }, .{});
    switch (result) {
        .diagnostic => |diagnostic| {
            report.native_model = .{
                .admitted = false,
                .feature = @tagName(diagnostic.feature()),
                .code = @tagName(diagnostic.code),
                .payload_code = if (diagnostic.payload) |payload| @tagName(payload.code) else null,
                .entry_index = diagnostic.entry_index orelse
                    if (diagnostic.payload) |payload| payload.entry_index else null,
            };
            const evidence = try arena.alloc([]const u8, 1);
            evidence[0] = try std.fmt.allocPrint(arena, "{s}:{s}", .{
                @tagName(diagnostic.feature()), @tagName(diagnostic.code),
            });
            const gaps = try arena.alloc(GapReport, 1);
            gaps[0] = .{
                .priority = Category.native_archive_rejected.priority(),
                .category = .native_archive_rejected,
                .evidence = evidence,
            };
            report.gaps = gaps;
            return report;
        },
        .model => |*model| {
            defer model.deinit();
            try describeModel(arena, model, &report);
            return report;
        },
    }
}

const GapBuilder = struct {
    arena: std.mem.Allocator,
    evidence: [std.meta.fields(Category).len]std.ArrayList([]const u8) =
        @splat(.empty),

    fn add(self: *GapBuilder, category: Category, evidence: []const u8) !void {
        const list = &self.evidence[@intFromEnum(category)];
        for (list.items) |existing| {
            if (std.mem.eql(u8, existing, evidence)) return;
        }
        try list.append(self.arena, try self.arena.dupe(u8, evidence));
    }

    fn finish(self: *GapBuilder) ![]const GapReport {
        var gaps: std.ArrayList(GapReport) = .empty;
        for (self.evidence, 0..) |list, index| {
            if (list.items.len == 0) continue;
            const category: Category = @enumFromInt(index);
            try gaps.append(self.arena, .{
                .priority = category.priority(),
                .category = category,
                .evidence = list.items,
            });
        }
        return gaps.toOwnedSlice(self.arena);
    }
};

fn describeModel(
    arena: std.mem.Allocator,
    model: *const archive_application.Model,
    report: *PackageReport,
) !void {
    const hex = try hexDigest(arena, &model.digest);
    report.native_model = .{ .admitted = true, .application_sha256 = hex };
    report.essential = model.facts.essential;
    report.protected = model.facts.protected;
    report.priority = if (model.facts.priority) |value| @tagName(value) else null;

    var gaps: GapBuilder = .{ .arena = arena };

    var setuid: std.ArrayList([]const u8) = .empty;
    var owned: std.ArrayList([]const u8) = .empty;
    var sysusers: std.ArrayList([]const u8) = .empty;
    var tmpfiles: std.ArrayList([]const u8) = .empty;
    for (model.files) |file| {
        switch (file.kind) {
            .regular => report.payload.regular += 1,
            .directory => report.payload.directory += 1,
            .symlink => report.payload.symlink += 1,
            .hardlink => report.payload.hardlink += 1,
        }
        if (file.setuid() or file.setgid()) {
            try setuid.append(arena, try arena.dupe(u8, file.path));
            try gaps.add(.ownership_and_mode, "payload:setuid_or_setgid");
        }
        if (file.uid != 0 or file.gid != 0) {
            try owned.append(arena, try std.fmt.allocPrint(arena, "{s} {d}:{d}", .{
                file.path, file.uid, file.gid,
            }));
            try gaps.add(.ownership_and_mode, "payload:non_root_owner");
        }
        const system = &report.payload.system_paths;
        if (underAny(file.path, &.{ "usr/lib/systemd/system/", "lib/systemd/system/", "etc/systemd/system/" }) and
            endsWithAny(file.path, &.{ ".service", ".socket", ".timer", ".path", ".mount", ".target" }))
            system.systemd_units += 1;
        if (underAny(file.path, &.{ "usr/lib/sysusers.d/", "lib/sysusers.d/" }) and file.kind == .regular)
            try sysusers.append(arena, try arena.dupe(u8, file.path));
        if (underAny(file.path, &.{ "usr/lib/tmpfiles.d/", "lib/tmpfiles.d/" }) and file.kind == .regular)
            try tmpfiles.append(arena, try arena.dupe(u8, file.path));
        if (underAny(file.path, &.{"etc/init.d/"}) and file.kind == .regular) system.init_scripts += 1;
        if (underAny(file.path, &.{ "usr/lib/udev/rules.d/", "lib/udev/rules.d/" })) system.udev_rules += 1;
        if (underAny(file.path, &.{ "etc/pam.d/", "usr/lib/pam.d/" }) and file.kind != .directory) system.pam += 1;
        if (underAny(file.path, &.{"etc/cron."}) and file.kind != .directory) system.cron += 1;
    }
    report.payload.setuid_or_setgid = setuid.items;
    report.payload.non_root_owned = owned.items;
    report.payload.system_paths.sysusers = sysusers.items;
    report.payload.system_paths.tmpfiles = tmpfiles.items;

    const conffiles = try arena.alloc(ConffileReport, model.conffiles.len);
    for (model.conffiles, conffiles) |conffile, *out| {
        out.* = .{ .path = try arena.dupe(u8, conffile.path), .remove_on_upgrade = conffile.remove_on_upgrade };
        if (conffile.remove_on_upgrade) {
            const evidence = try std.fmt.allocPrint(arena, "conffiles:remove-on-upgrade {s}", .{conffile.path});
            try gaps.add(.remove_on_upgrade_conffile, evidence);
        }
    }
    report.conffiles = conffiles;

    const triggers = try arena.alloc(TriggerReport, model.triggers.len);
    for (model.triggers, triggers) |trigger, *out| {
        out.* = .{ .directive = @tagName(trigger.directive), .target = try arena.dupe(u8, trigger.target) };
        const evidence = try std.fmt.allocPrint(arena, "triggers:{s} {s}", .{ @tagName(trigger.directive), trigger.target });
        try gaps.add(.trigger_declaration, evidence);
    }
    report.triggers = triggers;

    const members = try arena.alloc([]const u8, model.metadata.len);
    for (model.metadata, members) |member, *out| out.* = try arena.dupe(u8, member.name);
    report.metadata_members = members;

    const scripts = try arena.alloc(ScriptReport, model.scripts.len);
    for (model.scripts, scripts) |script, *out| {
        const bytes = model.scriptBytes(script);
        const scan = try scanScript(arena, bytes);
        const gate = native_alternatives.scriptMayInvoke(bytes);
        out.* = .{
            .kind = script.kind.memberName(),
            .lifecycle = script.kind.lifecycle(),
            .size = script.size,
            .sha256 = try hexDigest(arena, &script.sha256),
            .interpreter = scan.interpreter,
            .alternatives_gate = gate,
            .invocations = scan.invocations,
        };
        if (gate) {
            const evidence = try std.fmt.allocPrint(arena, "{s}:update-alternatives", .{script.kind.memberName()});
            try gaps.add(.alternatives_script_authority, evidence);
        }
        if (script.kind == .config) {
            try gaps.add(.debconf_frontend, "config:debconf configuration script");
        }
        for (scan.invocations) |invocation| {
            const evidence = try std.fmt.allocPrint(arena, "{s}:{s}", .{ script.kind.memberName(), invocation.tool });
            try gaps.add(invocation.category, evidence);
        }
    }
    report.scripts = scripts;
    report.gaps = try gaps.finish();
}

fn underAny(path: []const u8, prefixes: []const []const u8) bool {
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, path, prefix) and path.len > prefix.len) return true;
    }
    return false;
}

fn endsWithAny(path: []const u8, suffixes: []const []const u8) bool {
    for (suffixes) |suffix| {
        if (std.mem.endsWith(u8, path, suffix)) return true;
    }
    return false;
}

pub const ScriptScan = struct {
    interpreter: []const u8,
    invocations: []const Invocation,
};

fn isSeparator(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\r', ';', '|', '&', '(', ')', '`', '{', '}', '<', '>', '"', '\'', '=', '$', '!', ',' => true,
        else => false,
    };
}

fn isPathByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '.' or byte == '-';
}

fn commandName(token: []const u8) ?[]const u8 {
    if (std.mem.indexOfScalar(u8, token, '/') == null) return token;
    for (command_prefixes) |prefix| {
        if (std.mem.startsWith(u8, token, prefix) and
            std.mem.indexOfScalar(u8, token[prefix.len..], '/') == null)
            return token[prefix.len..];
    }
    return null;
}

fn debconfCommand(token: []const u8) bool {
    if (!std.mem.startsWith(u8, token, "db_") or token.len == 3) return false;
    for (token[3..]) |byte| {
        if (!std.ascii.isLower(byte) and byte != '_') return false;
    }
    return true;
}

fn sanitizedLine(arena: std.mem.Allocator, line: []const u8) ![]const u8 {
    const bounded = line[0..@min(line.len, maximum_invocation_text)];
    const out = try arena.alloc(u8, bounded.len);
    for (bounded, out) |byte, *slot| {
        slot.* = if (byte >= 0x20 and byte < 0x7f) byte else '?';
    }
    return out;
}

/// Conservative static scan. Comment lines are skipped; every other line is
/// split on shell metacharacters and matched against known tools and paths. A
/// hit means the script may need the feature, not that it always runs.
pub fn scanScript(arena: std.mem.Allocator, bytes: []const u8) !ScriptScan {
    var invocations: std.ArrayList(Invocation) = .empty;
    var interpreter: []const u8 = "";
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var number: usize = 0;
    while (lines.next()) |raw| {
        number += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (number == 1 and std.mem.startsWith(u8, line, "#!")) {
            interpreter = try sanitizedLine(arena, std.mem.trim(u8, line[2..], " \t"));
            continue;
        }
        if (line.len == 0 or line[0] == '#') continue;

        var found: std.ArrayList(Invocation) = .empty;
        var tokens = std.mem.tokenizeAny(u8, line, " \t\r;|&()`{}<>\"'=$!,");
        while (tokens.next()) |token| {
            const name = commandName(token) orelse continue;
            if (debconfCommand(name)) {
                try appendUnique(arena, &found, name, .debconf_frontend, number);
                continue;
            }
            for (tool_rules) |rule| {
                if (std.mem.eql(u8, rule.name, name)) {
                    try appendUnique(arena, &found, rule.name, rule.category, number);
                    break;
                }
            }
        }
        if (std.mem.indexOf(u8, line, "/usr/share/debconf/confmodule") != null)
            try appendUnique(arena, &found, "confmodule", .debconf_frontend, number);
        for (path_rules) |rule| {
            if (pathReference(line, rule.prefix, rule.category == .device_node))
                try appendUnique(arena, &found, rule.tool, rule.category, number);
        }
        if (found.items.len == 0) continue;
        const text = try sanitizedLine(arena, line);
        for (found.items) |*item| item.text = text;
        if (invocations.items.len + found.items.len > maximum_invocations_per_script)
            return error.InventoryLimit;
        try invocations.appendSlice(arena, found.items);
    }
    return .{ .interpreter = interpreter, .invocations = try invocations.toOwnedSlice(arena) };
}

fn appendUnique(
    arena: std.mem.Allocator,
    found: *std.ArrayList(Invocation),
    tool: []const u8,
    category: Category,
    line: usize,
) !void {
    for (found.items) |item| {
        if (std.mem.eql(u8, item.tool, tool)) return;
    }
    try found.append(arena, .{
        .tool = try arena.dupe(u8, tool),
        .category = category,
        .line = line,
        .text = "",
    });
}

fn pathReference(line: []const u8, prefix: []const u8, skip_standard_devices: bool) bool {
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, line, start, prefix)) |index| {
        start = index + 1;
        if (index != 0 and isPathByte(line[index - 1])) continue;
        const rest = line[index + prefix.len ..];
        if (prefix[prefix.len - 1] != '/' and rest.len != 0 and isPathByte(rest[0])) continue;
        if (skip_standard_devices) {
            var standard = false;
            for (standard_devices) |device| {
                if (std.mem.startsWith(u8, rest, device) and
                    (device[device.len - 1] == '/' or rest.len == device.len or !isPathByte(rest[device.len])))
                {
                    standard = true;
                    break;
                }
            }
            if (standard) continue;
        }
        return true;
    }
    return false;
}

fn countInto(arena: std.mem.Allocator, counts: *std.StringArrayHashMapUnmanaged(usize), name: []const u8) !void {
    const entry = try counts.getOrPut(arena, name);
    if (!entry.found_existing) entry.value_ptr.* = 0;
    entry.value_ptr.* += 1;
}

fn sortedCounts(arena: std.mem.Allocator, counts: std.StringArrayHashMapUnmanaged(usize)) ![]const NamedCount {
    const out = try arena.alloc(NamedCount, counts.count());
    for (counts.keys(), counts.values(), out) |key, value, *slot| slot.* = .{ .name = key, .count = value };
    std.mem.sort(NamedCount, out, {}, struct {
        fn lessThan(_: void, left: NamedCount, right: NamedCount) bool {
            return std.mem.order(u8, left.name, right.name) == .lt;
        }
    }.lessThan);
    return out;
}

pub fn summarize(arena: std.mem.Allocator, packages: []const PackageReport) !Summary {
    var scripts: std.StringArrayHashMapUnmanaged(usize) = .empty;
    var triggers: std.StringArrayHashMapUnmanaged(usize) = .empty;
    var members: std.StringArrayHashMapUnmanaged(usize) = .empty;
    var tools: std.StringArrayHashMapUnmanaged(usize) = .empty;
    var gap_packages: [std.meta.fields(Category).len]std.ArrayList([]const u8) = @splat(.empty);
    var summary: Summary = .{
        .packages = packages.len,
        .admitted = 0,
        .rejected = 0,
        .total_bytes = 0,
        .essential = 0,
        .scripts = &.{},
        .conffiles = 0,
        .remove_on_upgrade_conffiles = 0,
        .triggers = &.{},
        .metadata_members = &.{},
        .tools = &.{},
        .gaps = &.{},
    };
    for (packages) |package| {
        if (package.native_model.admitted) summary.admitted += 1 else summary.rejected += 1;
        summary.total_bytes += package.size;
        if (package.essential) summary.essential += 1;
        for (package.scripts) |script| {
            try countInto(arena, &scripts, script.kind);
            for (script.invocations) |invocation| try countInto(arena, &tools, invocation.tool);
        }
        summary.conffiles += package.conffiles.len;
        for (package.conffiles) |conffile| {
            if (conffile.remove_on_upgrade) summary.remove_on_upgrade_conffiles += 1;
        }
        for (package.triggers) |trigger| try countInto(arena, &triggers, trigger.directive);
        for (package.metadata_members) |member| try countInto(arena, &members, member);
        for (package.gaps) |gap| try gap_packages[@intFromEnum(gap.category)].append(arena, package.package);
    }
    summary.scripts = try sortedCounts(arena, scripts);
    summary.triggers = try sortedCounts(arena, triggers);
    summary.metadata_members = try sortedCounts(arena, members);
    summary.tools = try sortedCounts(arena, tools);
    var gaps: std.ArrayList(GapSummary) = .empty;
    for (gap_packages, 0..) |list, index| {
        if (list.items.len == 0) continue;
        const category: Category = @enumFromInt(index);
        try gaps.append(arena, .{ .priority = category.priority(), .category = category, .packages = list.items });
    }
    summary.gaps = try gaps.toOwnedSlice(arena);
    return summary;
}

const testing = std.testing;
const fixtures = archive_application.test_fixtures;

fn fixtureExpectation(arena: std.mem.Allocator, bytes: []const u8, name: []const u8) !Expectation {
    var signed: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &signed, .{});
    var derived: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(bytes, &derived, .{});
    return .{
        .repository = "debian-trixie-fixture",
        .name = name,
        .version = "1.0",
        .architecture = "amd64",
        .filename = try std.fmt.allocPrint(arena, "pool/main/d/{s}/{s}_1.0_amd64.deb", .{ name, name }),
        .size = bytes.len,
        .sha256 = try hexDigest(arena, &signed),
        .sha512 = try hexDigest(arena, &derived),
    };
}

fn findGap(report: PackageReport, category: Category) ?GapReport {
    for (report.gaps) |gap| {
        if (gap.category == category) return gap;
    }
    return null;
}

fn hasEvidence(gap: GapReport, evidence: []const u8) bool {
    for (gap.evidence) |item| {
        if (std.mem.eql(u8, item, evidence)) return true;
    }
    return false;
}

test "debian closure inventory: scripts, conffiles, triggers, diversions, statoverrides and accounts are classified" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const postinst =
        \\#!/bin/sh
        \\set -e
        \\# update-rc.d in a comment is not an invocation
        \\. /usr/share/debconf/confmodule
        \\db_get demo/question
        \\dpkg-maintscript-helper rm_conffile /etc/demo/old.conf 0.9 -- "$@"
        \\dpkg-divert --package demo --rename --divert /usr/bin/tool.real /usr/bin/tool
        \\dpkg-statoverride --update --add root shadow 2755 /usr/bin/demo
        \\getent passwd _demo >/dev/null || adduser --system _demo
        \\systemd-sysusers demo.conf
        \\deb-systemd-helper enable demo.service
        \\if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
        \\read id < /proc/sys/kernel/random/boot_id
        \\/usr/sbin/update-alternatives --install /usr/bin/pager pager /usr/bin/demo 10
        \\/etc/demo/hook.sh
        \\ldconfig
        \\
    ;
    const bytes = try fixtures.build(testing.allocator, .{
        .package = "demo",
        .control = &.{
            .{ .path = "postinst", .mode = 0o755, .content = postinst },
            .{ .path = "conffiles", .content = "/etc/demo/demo.conf\nremove-on-upgrade /etc/demo/legacy.conf\n" },
            .{ .path = "triggers", .content = "interest-noawait /usr/lib/demo\nactivate-noawait ldconfig\n" },
            .{ .path = "templates", .content = "Template: demo/question\nType: boolean\n" },
        },
        .data = &.{
            .{ .path = "etc", .kind = '5', .mode = 0o755 },
            .{ .path = "etc/demo", .kind = '5', .mode = 0o755 },
            .{ .path = "etc/demo/demo.conf", .content = "value=1\n" },
            .{ .path = "usr", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/bin", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/bin/demo", .mode = 0o4755, .content = "binary" },
            .{ .path = "usr/lib", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/lib/sysusers.d", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/lib/sysusers.d/demo.conf", .content = "u _demo - -\n" },
            .{ .path = "usr/lib/systemd", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/lib/systemd/system", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/lib/systemd/system/demo.service", .content = "[Service]\n" },
        },
    });
    defer testing.allocator.free(bytes);
    const report = try inspectArchive(arena, testing.allocator, bytes, try fixtureExpectation(arena, bytes, "demo"));

    try testing.expect(report.native_model.admitted);
    try testing.expect(report.native_model.application_sha256 != null);
    try testing.expectEqual(@as(usize, 1), report.scripts.len);
    const script = report.scripts[0];
    try testing.expectEqualStrings("postinst", script.kind);
    try testing.expectEqualStrings("/bin/sh", script.interpreter);
    try testing.expect(script.alternatives_gate);

    const expected_tools = [_][]const u8{
        "confmodule",          "db_get",            "dpkg-maintscript-helper",
        "dpkg-divert",         "dpkg-statoverride", "getent",
        "adduser",             "systemd-sysusers",  "deb-systemd-helper",
        "systemctl",           "/run",              "/proc",
        "update-alternatives", "ldconfig",
    };
    var seen: usize = 0;
    for (script.invocations) |invocation| {
        try testing.expect(!std.mem.eql(u8, invocation.tool, "update-rc.d"));
        try testing.expect(!std.mem.eql(u8, invocation.tool, "/dev"));
        for (expected_tools) |tool| {
            if (std.mem.eql(u8, tool, invocation.tool)) seen += 1;
        }
    }
    try testing.expectEqual(expected_tools.len, seen);

    try testing.expect(hasEvidence(findGap(report, .alternatives_script_authority).?, "postinst:update-alternatives"));
    try testing.expect(hasEvidence(findGap(report, .debconf_frontend).?, "postinst:confmodule"));
    try testing.expect(hasEvidence(findGap(report, .kernel_filesystem).?, "postinst:/proc"));
    try testing.expect(hasEvidence(findGap(report, .accounts).?, "postinst:adduser"));
    try testing.expect(hasEvidence(findGap(report, .dpkg_database_helper).?, "postinst:dpkg-divert"));
    try testing.expect(hasEvidence(findGap(report, .dpkg_database_helper).?, "postinst:dpkg-statoverride"));
    try testing.expect(hasEvidence(findGap(report, .service_manager).?, "postinst:deb-systemd-helper"));
    try testing.expect(hasEvidence(findGap(report, .environment_probe).?, "postinst:/run"));
    try testing.expect(hasEvidence(findGap(report, .remove_on_upgrade_conffile).?, "conffiles:remove-on-upgrade etc/demo/legacy.conf"));
    try testing.expect(hasEvidence(findGap(report, .trigger_declaration).?, "triggers:interest_noawait /usr/lib/demo"));
    try testing.expect(hasEvidence(findGap(report, .ownership_and_mode).?, "payload:setuid_or_setgid"));
    try testing.expect(findGap(report, .native_archive_rejected) == null);
    try testing.expectEqualStrings("P1", findGap(report, .alternatives_script_authority).?.priority);
    try testing.expectEqualStrings("P3", findGap(report, .dpkg_database_helper).?.priority);

    try testing.expectEqual(@as(usize, 2), report.conffiles.len);
    try testing.expectEqual(@as(usize, 2), report.triggers.len);
    try testing.expectEqual(@as(usize, 1), report.payload.setuid_or_setgid.len);
    try testing.expectEqual(@as(usize, 1), report.payload.system_paths.systemd_units);
    try testing.expectEqualStrings("usr/lib/sysusers.d/demo.conf", report.payload.system_paths.sysusers[0]);
    try testing.expectEqualStrings("templates", report.metadata_members[0]);

    const summary = try summarize(arena, &.{report});
    try testing.expectEqual(@as(usize, 1), summary.admitted);
    try testing.expectEqual(@as(usize, 1), summary.remove_on_upgrade_conffiles);
    try testing.expectEqualStrings("P1", summary.gaps[0].priority);
    try testing.expectEqual(Category.alternatives_script_authority, summary.gaps[0].category);
}

test "debian closure inventory: FIFOs, devices and unsupported control members are native P0 gaps" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const Case = struct { entry: fixtures.Entry, feature: []const u8 };
    const cases = [_]Case{
        .{ .entry = .{ .path = "run-fifo", .kind = '6', .mode = 0o600 }, .feature = "file_type" },
        .{ .entry = .{ .path = "console", .kind = '3', .mode = 0o600 }, .feature = "file_type" },
        .{ .entry = .{ .path = "loop0", .kind = '4', .mode = 0o600 }, .feature = "file_type" },
    };
    for (cases) |case| {
        const bytes = try fixtures.build(testing.allocator, .{ .package = "special", .data = &.{case.entry} });
        defer testing.allocator.free(bytes);
        const report = try inspectArchive(arena, testing.allocator, bytes, try fixtureExpectation(arena, bytes, "special"));
        try testing.expect(!report.native_model.admitted);
        try testing.expectEqualStrings(case.feature, report.native_model.feature.?);
        try testing.expectEqualStrings("unsupported_file_type", report.native_model.payload_code.?);
        const gap = findGap(report, .native_archive_rejected).?;
        try testing.expectEqualStrings("P0", gap.priority);
        try testing.expectEqual(@as(usize, 0), report.scripts.len);
    }

    const unknown = try fixtures.build(testing.allocator, .{
        .package = "member",
        .control = &.{.{ .path = "isinstallable", .mode = 0o755, .content = "#!/bin/sh\n" }},
    });
    defer testing.allocator.free(unknown);
    const report = try inspectArchive(arena, testing.allocator, unknown, try fixtureExpectation(arena, unknown, "member"));
    try testing.expect(!report.native_model.admitted);
    try testing.expectEqualStrings("control_member", report.native_model.feature.?);
    const summary = try summarize(arena, &.{report});
    try testing.expectEqual(@as(usize, 1), summary.rejected);
    try testing.expectEqualStrings("P0", summary.gaps[0].priority);
}

test "debian closure inventory: tampered bytes and forged derived SHA512 are refused, never inventoried" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const bytes = try fixtures.build(testing.allocator, .{ .package = "bound" });
    defer testing.allocator.free(bytes);
    const expected = try fixtureExpectation(arena, bytes, "bound");
    _ = try inspectArchive(arena, testing.allocator, bytes, expected);

    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try testing.expectError(error.SignedDigestMismatch, inspectArchive(arena, testing.allocator, tampered, expected));
    try testing.expectError(error.ArchiveSizeMismatch, inspectArchive(arena, testing.allocator, bytes[0 .. bytes.len - 1], expected));

    var forged = expected;
    const derived = try arena.dupe(u8, expected.sha512);
    derived[0] = if (derived[0] == '0') '1' else '0';
    forged.sha512 = derived;
    try testing.expectError(error.DerivedDigestMismatch, inspectArchive(arena, testing.allocator, bytes, forged));

    var renamed = expected;
    renamed.filename = "pool/main/u/ubuntu-minimal/bound_1.0ubuntu1_amd64.deb";
    const report = try inspectArchive(arena, testing.allocator, bytes, renamed);
    try testing.expect(!report.native_model.admitted);
    try testing.expectEqualStrings("identity_binding", report.native_model.feature.?);
}

test "debian closure inventory: path references skip standard streams and embedded names" {
    try testing.expect(!pathReference("foo >/dev/null 2>&1", "/dev/", true));
    try testing.expect(!pathReference("exec 3>/dev/fd/1", "/dev/", true));
    try testing.expect(pathReference("mknod /dev/loop0 b 7 0", "/dev/", true));
    try testing.expect(!pathReference("rm -f /var/processes", "/proc", false));
    try testing.expect(!pathReference("cp /usr/lib/proc-helper", "/proc", false));
    try testing.expect(pathReference("[ -e /proc/self ]", "/proc", false));
    try testing.expect(pathReference("mountpoint -q /proc", "/proc", false));
    try testing.expect(!pathReference("cat /usr/lib/sysusers.d/x", "/sys/", false));
    try testing.expectEqualStrings("dpkg-divert", commandName("/usr/bin/dpkg-divert").?);
    try testing.expect(commandName("/etc/passwd") == null);
    try testing.expect(debconfCommand("db_input"));
    try testing.expect(!debconfCommand("db_"));
    try testing.expect(!debconfCommand("db_Input"));
}

const exact_lock_v3 = debz.exact_lock_v3;

const CommittedLock = struct {
    architecture: []const u8,
    request: []const u8,
    bytes: []const u8,
};

// The committed #261 evidence (tools/fixtures/debian-stable-closure-v1).
const committed_locks = [_]CommittedLock{
    .{ .architecture = "amd64", .request = "apt", .bytes = @embedFile("debian_closure_amd64_apt_lock") },
    .{ .architecture = "amd64", .request = "systemd-sysv", .bytes = @embedFile("debian_closure_amd64_systemd_sysv_lock") },
    .{ .architecture = "arm64", .request = "apt", .bytes = @embedFile("debian_closure_arm64_apt_lock") },
    .{ .architecture = "arm64", .request = "systemd-sysv", .bytes = @embedFile("debian_closure_arm64_systemd_sysv_lock") },
};
const debian_trixie_signer = "41587f7db8c774bccf131416762f67a0b2c39de4";
const ubuntu_archive_signer = "f6ecb3762474eda9d21b7022871920d1991bc93c";

fn decodeSubstituted(
    allocator: std.mem.Allocator,
    source: []const u8,
    needle: []const u8,
    replacement: []const u8,
) !exact_lock_v3.OwnedLock {
    try testing.expect(std.mem.indexOf(u8, source, needle) != null);
    const substituted = try std.mem.replaceOwned(u8, allocator, source, needle, replacement);
    defer allocator.free(substituted);
    return exact_lock_v3.decode(allocator, substituted, exact_lock_v3.maximum_document_bytes);
}

test "debian closure inventory: committed Debian locks are canonical signed-SHA256 bound; Ubuntu signer, stripped or forged bindings refuse" {
    const allocator = testing.allocator;
    for (committed_locks) |committed| {
        var decoded = try exact_lock_v3.decode(allocator, committed.bytes, exact_lock_v3.maximum_document_bytes);
        defer decoded.deinit();
        const lock = decoded.lock;
        try testing.expectEqualStrings(committed.architecture, lock.target_architecture);
        try testing.expectEqual(@as(usize, 0), lock.local_artifacts.len);
        try testing.expectEqual(@as(usize, 1), lock.repositories.len);
        const repository = lock.repositories[0];
        try testing.expectEqual(exact_lock_v3.ArchiveBinding.signed_sha256_derived_sha512, repository.archive_binding);
        try testing.expectEqual(@as(usize, 1), repository.signer_fingerprints.len);
        const signer = std.fmt.bytesToHex(repository.signer_fingerprints[0], .lower);
        try testing.expectEqualStrings(debian_trixie_signer, &signer);
        var requested: usize = 0;
        for (lock.packages) |package| {
            try testing.expectEqual(
                exact_lock_v3.ArchiveAuthentication.signed_sha256_derived_sha512,
                lock.archiveAuthentication(package),
            );
            try testing.expect(package.archive_identity.digests.sha512 == null);
            if (package.retention == .requested) {
                requested += 1;
                try testing.expectEqualStrings(committed.request, package.name);
            }
        }
        try testing.expectEqual(@as(usize, 1), requested);
        try lock.requireArchiveDigestPolicy(.sha512_identity_required);

        // Substituting Ubuntu's archive signer breaks the lock's own digest.
        try testing.expectError(error.DigestMismatch, decodeSubstituted(
            allocator,
            committed.bytes,
            "\"" ++ debian_trixie_signer ++ "\"",
            "\"" ++ ubuntu_archive_signer ++ "\"",
        ));
        // A lock whose binding was stripped cannot carry derived SHA512s.
        try testing.expectError(error.UnboundDerivedDigest, decodeSubstituted(
            allocator,
            committed.bytes,
            ",\"archive_binding\":\"signed_sha256_derived_sha512\"",
            "",
        ));
        // Derived provenance can never be relabelled as signed.
        try testing.expectError(error.UnsupportedArchiveBinding, decodeSubstituted(
            allocator,
            committed.bytes,
            "\"provenance\":\"derived_from_signed_sha256\"",
            "\"provenance\":\"signed_sha512\"",
        ));
        // Relabelling the target architecture breaks the digest.
        const amd64 = std.mem.eql(u8, committed.architecture, "amd64");
        try testing.expectError(error.DigestMismatch, decodeSubstituted(
            allocator,
            committed.bytes,
            if (amd64) "\"target_architecture\":\"amd64\"" else "\"target_architecture\":\"arm64\"",
            if (amd64) "\"target_architecture\":\"arm64\"" else "\"target_architecture\":\"amd64\"",
        ));
    }
}

// Offline verification of the committed #261 closure evidence. It runs in the
// required `test-workload-core` partition and never reads the wall clock: the
// evidence is evaluated at its recorded day, so required CI keeps passing after
// the pin's bounded missing-Valid-Until freshness lapses (2026-10-13T07:55:41Z).
// Live re-resolution is manual only (`tools/debian-stable-closure.py run`).

const committed_evidence = @embedFile("debian_closure_evidence");
const committed_pin = @embedFile("debian_stable_pin");
const evidence_schema = "https://debz.dev/test/debian-stable-closure-evidence-v1";
const bounded_missing_valid_until = "allow_missing_valid_until_with_max_age_seconds";
const seconds_per_day: i64 = 24 * 60 * 60;

pub const LiveFreshness = enum {
    fresh,
    /// Debian stable's Release has no Valid-Until and is re-signed only at
    /// point releases; a frozen-pocket freshness policy is tracked in #330.
    pin_expired_awaiting_point_release,
};

pub const EvidenceVerdict = struct {
    /// The recorded day the evidence is evaluated at, never the caller's clock.
    evaluated_at: i64,
    expires_at: i64,
    /// Diagnostic only: whether live re-resolution would still be admitted.
    live: LiveFreshness,
    locks: usize,
    packages: usize,
};

const EvidenceLock = struct {
    path: []const u8,
    file_sha256: []const u8,
    digest_sha256: []const u8,
    packages: usize,
    total_bytes: u64,
};

const EvidenceObject = struct {
    package: []const u8,
    version: []const u8,
    size: u64,
    sha256: []const u8,
    derived_sha512: []const u8,
};

const EvidenceArchitecture = struct {
    repository: struct { id: []const u8, archive_binding: []const u8 },
    locks: struct { apt: EvidenceLock, @"systemd-sysv": EvidenceLock },
    cas: []const EvidenceObject,
    cas_objects: usize,
    cas_bytes: u64,
};

const Evidence = struct {
    schema: []const u8,
    issue: u32,
    pin_sha256: []const u8,
    requests: []const []const u8,
    freshness: struct {
        release_date: []const u8,
        valid_until: ?[]const u8,
        mode: []const u8,
        maximum_release_age_seconds: u64,
        expires_at: []const u8,
        recorded_on: []const u8,
    },
    architectures: struct { amd64: EvidenceArchitecture, arm64: EvidenceArchitecture },
};

const Pin = struct {
    release: struct {
        date: []const u8,
        valid_until: ?[]const u8,
        freshness_mode: []const u8,
        maximum_release_age_seconds: u64,
    },
};

/// Rechecks the committed evidence against the reviewed pin and the committed
/// locks: pin binding, bounded freshness arithmetic, that the evidence was
/// recorded while the window was open, lock bytes and digests, the signed
/// SHA256 binding with derived SHA512, and that the archive objects are exactly
/// the lock union. `now` only selects `live`; it can never change the verdict.
pub fn verifyCommittedEvidence(
    allocator: std.mem.Allocator,
    evidence_bytes: []const u8,
    pin_bytes: []const u8,
    locks: []const CommittedLock,
    now: i64,
) !EvidenceVerdict {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true, .allocate = .alloc_always };
    const evidence = try std.json.parseFromSliceLeaky(Evidence, arena, evidence_bytes, options);
    const pin = try std.json.parseFromSliceLeaky(Pin, arena, pin_bytes, options);

    if (!std.mem.eql(u8, evidence.schema, evidence_schema) or evidence.issue != 261)
        return error.InvalidEvidence;
    try requireHex(evidence.pin_sha256, &sha256Of(pin_bytes));
    if (evidence.requests.len != 2 or
        !std.mem.eql(u8, evidence.requests[0], "apt") or
        !std.mem.eql(u8, evidence.requests[1], "systemd-sysv"))
        return error.InvalidEvidence;

    const freshness = evidence.freshness;
    if (!std.mem.eql(u8, freshness.mode, bounded_missing_valid_until) or
        !std.mem.eql(u8, pin.release.freshness_mode, bounded_missing_valid_until) or
        freshness.valid_until != null or pin.release.valid_until != null or
        !std.mem.eql(u8, freshness.release_date, pin.release.date) or
        freshness.maximum_release_age_seconds != pin.release.maximum_release_age_seconds or
        !debz.repository_refresh.validExpiryPolicy(.{
            .allow_missing_valid_until_with_max_age_seconds = freshness.maximum_release_age_seconds,
        }))
        return error.InvalidEvidence;
    const release_date = try parseReleaseDate(freshness.release_date);
    const expires_at = try parseInstant(freshness.expires_at);
    if (expires_at != release_date + @as(i64, @intCast(freshness.maximum_release_age_seconds)))
        return error.InvalidEvidence;
    const evaluated_at = try parseDay(freshness.recorded_on);
    if (evaluated_at + seconds_per_day <= release_date or evaluated_at > expires_at)
        return error.InvalidEvidence;

    var verified_locks: usize = 0;
    var verified_packages: usize = 0;
    inline for (.{ "amd64", "arm64" }) |architecture| {
        const entry = @field(evidence.architectures, architecture);
        if (!std.mem.eql(u8, entry.repository.archive_binding, "signed_sha256_derived_sha512"))
            return error.InvalidEvidence;
        const seen = try arena.alloc(bool, entry.cas.len);
        @memset(seen, false);
        inline for (.{ "apt", "systemd-sysv" }) |request| {
            const item = @field(entry.locks, request);
            if (!std.mem.eql(u8, item.path, architecture ++ "-" ++ request ++ ".lock.json"))
                return error.InvalidEvidence;
            const committed = findCommitted(locks, architecture, request) orelse return error.InvalidEvidence;
            try requireHex(item.file_sha256, &sha256Of(committed.bytes));
            var decoded = try exact_lock_v3.decode(allocator, committed.bytes, exact_lock_v3.maximum_document_bytes);
            defer decoded.deinit();
            const lock = decoded.lock;
            try requireHex(item.digest_sha256, &lock.digest_sha256);
            if (!std.mem.eql(u8, lock.target_architecture, architecture) or
                lock.repositories.len != 1 or lock.local_artifacts.len != 0 or
                lock.packages.len != item.packages)
                return error.InvalidEvidence;
            const repository = lock.repositories[0];
            if (repository.archive_binding != .signed_sha256_derived_sha512 or
                !std.mem.eql(u8, &repository.id, entry.repository.id))
                return error.InvalidEvidence;
            try lock.requireArchiveDigestPolicy(.sha512_identity_required);
            var total: u64 = 0;
            for (lock.packages) |package| {
                total = std.math.add(u64, total, package.declared_size) catch return error.InvalidEvidence;
                const index = findObject(entry.cas, package.name) orelse return error.InvalidEvidence;
                const object = entry.cas[index];
                const signed = package.archive_identity.digests.sha256 orelse return error.InvalidEvidence;
                const derived = package.derived_sha512 orelse return error.InvalidEvidence;
                if (!std.mem.eql(u8, object.version, package.version) or object.size != package.declared_size)
                    return error.InvalidEvidence;
                try requireHex(object.sha256, &signed);
                try requireHex(object.derived_sha512, &derived);
                seen[index] = true;
            }
            if (total != item.total_bytes) return error.InvalidEvidence;
            verified_locks += 1;
            verified_packages += lock.packages.len;
        }
        var object_bytes: u64 = 0;
        for (entry.cas, seen) |object, used| {
            if (!used) return error.InvalidEvidence;
            object_bytes = std.math.add(u64, object_bytes, object.size) catch return error.InvalidEvidence;
        }
        if (entry.cas_objects != entry.cas.len or entry.cas_bytes != object_bytes)
            return error.InvalidEvidence;
    }
    if (verified_locks != locks.len) return error.InvalidEvidence;
    return .{
        .evaluated_at = evaluated_at,
        .expires_at = expires_at,
        .live = if (now > expires_at) .pin_expired_awaiting_point_release else .fresh,
        .locks = verified_locks,
        .packages = verified_packages,
    };
}

fn findCommitted(locks: []const CommittedLock, architecture: []const u8, request: []const u8) ?CommittedLock {
    for (locks) |committed| {
        if (std.mem.eql(u8, committed.architecture, architecture) and std.mem.eql(u8, committed.request, request))
            return committed;
    }
    return null;
}

fn findObject(objects: []const EvidenceObject, name: []const u8) ?usize {
    for (objects, 0..) |object, index| {
        if (std.mem.eql(u8, object.package, name)) return index;
    }
    return null;
}

fn sha256Of(bytes: []const u8) [Sha256.digest_length]u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &out, .{});
    return out;
}

/// Lowercase hex text must encode exactly `expected`.
fn requireHex(text: []const u8, expected: []const u8) error{InvalidEvidence}!void {
    var decoded: [Sha512.digest_length]u8 = undefined;
    if (expected.len > decoded.len or text.len != 2 * expected.len) return error.InvalidEvidence;
    for (text) |c| {
        if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return error.InvalidEvidence;
    }
    const bytes = std.fmt.hexToBytes(decoded[0..expected.len], text) catch return error.InvalidEvidence;
    if (!std.mem.eql(u8, bytes, expected)) return error.InvalidEvidence;
}

fn decimal(text: []const u8) error{InvalidEvidence}!i64 {
    if (text.len == 0 or text.len > 4) return error.InvalidEvidence;
    var value: i64 = 0;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return error.InvalidEvidence;
        value = value * 10 + (c - '0');
    }
    return value;
}

fn daysInMonth(year: i64, month: i64) i64 {
    return switch (month) {
        2 => if (@mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0)) 29 else 28,
        4, 6, 9, 11 => 30,
        else => 31,
    };
}

/// Days since 1970-01-01 in the proleptic Gregorian calendar.
fn daysFromCivil(year: i64, month: i64, day: i64) i64 {
    const shifted_year = if (month <= 2) year - 1 else year;
    const era = @divFloor(shifted_year, 400);
    const year_of_era = shifted_year - era * 400;
    const day_of_year = @divFloor(153 * @mod(month + 9, 12) + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return era * 146097 + day_of_era - 719468;
}

fn civilDay(year: i64, month: i64, day: i64) error{InvalidEvidence}!i64 {
    if (year < 1970 or month < 1 or month > 12 or day < 1 or day > daysInMonth(year, month))
        return error.InvalidEvidence;
    return daysFromCivil(year, month, day);
}

/// `HH:MM:SS`
fn timeOfDay(text: []const u8) error{InvalidEvidence}!i64 {
    if (text.len != 8 or text[2] != ':' or text[5] != ':') return error.InvalidEvidence;
    const hour = try decimal(text[0..2]);
    const minute = try decimal(text[3..5]);
    const second = try decimal(text[6..8]);
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidEvidence;
    return hour * 3600 + minute * 60 + second;
}

/// `YYYY-MM-DD`, at 00:00:00Z.
fn parseDay(text: []const u8) error{InvalidEvidence}!i64 {
    if (text.len != 10 or text[4] != '-' or text[7] != '-') return error.InvalidEvidence;
    const days = try civilDay(try decimal(text[0..4]), try decimal(text[5..7]), try decimal(text[8..10]));
    return days * seconds_per_day;
}

/// `YYYY-MM-DDTHH:MM:SSZ`
fn parseInstant(text: []const u8) error{InvalidEvidence}!i64 {
    if (text.len != 20 or text[10] != 'T' or text[19] != 'Z') return error.InvalidEvidence;
    return try parseDay(text[0..10]) + try timeOfDay(text[11..19]);
}

/// The signed Release `Date` form `Sat, 12 Sep 2026 07:55:41 UTC`, including
/// a weekday that must agree with the date.
fn parseReleaseDate(text: []const u8) error{InvalidEvidence}!i64 {
    const weekdays = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    if (text.len != 29 or !std.mem.eql(u8, text[3..5], ", ") or text[7] != ' ' or text[11] != ' ' or
        text[16] != ' ' or !std.mem.eql(u8, text[25..], " UTC"))
        return error.InvalidEvidence;
    const month = for (months, 1..) |name, number| {
        if (std.mem.eql(u8, text[8..11], name)) break @as(i64, @intCast(number));
    } else return error.InvalidEvidence;
    const days = try civilDay(try decimal(text[12..16]), month, try decimal(text[5..7]));
    if (!std.mem.eql(u8, text[0..3], weekdays[@intCast(@mod(days, 7))])) return error.InvalidEvidence;
    return days * seconds_per_day + try timeOfDay(text[17..25]);
}

fn replaceOnce(allocator: std.mem.Allocator, source: []const u8, needle: []const u8, replacement: []const u8) ![]u8 {
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, source, needle));
    return std.mem.replaceOwned(u8, allocator, source, needle, replacement);
}

test "debian closure evidence: required offline checks pass at now = 2026-10-14, after the pin's bounded freshness lapsed" {
    const after_expiry = try parseInstant("2026-10-14T00:00:00Z");
    const verdict = try verifyCommittedEvidence(testing.allocator, committed_evidence, committed_pin, &committed_locks, after_expiry);
    try testing.expectEqual(LiveFreshness.pin_expired_awaiting_point_release, verdict.live);
    try testing.expectEqual(try parseInstant("2026-10-13T07:55:41Z"), verdict.expires_at);
    try testing.expectEqual(try parseReleaseDate("Sat, 12 Sep 2026 07:55:41 UTC") + 31 * seconds_per_day, verdict.expires_at);
    try testing.expectEqual(try parseDay("2026-09-30"), verdict.evaluated_at);
    try testing.expectEqual(committed_locks.len, verdict.locks);
    try testing.expectEqual(@as(usize, 73 + 69 + 73 + 69), verdict.packages);

    // `now` is diagnostic only: the verdict is identical while fresh, at the
    // exact boundary, one second later, and a decade later.
    for (
        [_][]const u8{ "2026-09-30T00:00:00Z", "2026-10-13T07:55:41Z", "2026-10-13T07:55:42Z", "2036-10-14T00:00:00Z" },
        [_]LiveFreshness{ .fresh, .fresh, .pin_expired_awaiting_point_release, .pin_expired_awaiting_point_release },
    ) |instant, live| {
        const other = try verifyCommittedEvidence(testing.allocator, committed_evidence, committed_pin, &committed_locks, try parseInstant(instant));
        try testing.expectEqual(live, other.live);
        try testing.expectEqual(verdict.evaluated_at, other.evaluated_at);
        try testing.expectEqual(verdict.expires_at, other.expires_at);
        try testing.expectEqual(verdict.locks, other.locks);
        try testing.expectEqual(verdict.packages, other.packages);
    }
}

test "debian closure evidence: tampered freshness, pin, lock or archive evidence refuses whatever now is" {
    const allocator = testing.allocator;
    for ([_][]const u8{ "2026-10-01T00:00:00Z", "2026-10-14T00:00:00Z" }) |instant| {
        const now = try parseInstant(instant);
        for ([_][2][]const u8{
            .{ "\"expires_at\": \"2026-10-13T07:55:41Z\"", "\"expires_at\": \"2027-01-01T00:00:00Z\"" },
            .{ "\"recorded_on\": \"2026-09-30\"", "\"recorded_on\": \"2026-10-14\"" },
            .{ "\"recorded_on\": \"2026-09-30\"", "\"recorded_on\": \"2026-09-11\"" },
            .{ "\"maximum_release_age_seconds\": 2678400", "\"maximum_release_age_seconds\": 5356800" },
            .{ "\"release_date\": \"Sat, 12 Sep 2026", "\"release_date\": \"Fri, 12 Sep 2026" },
            .{ "\"digest_sha256\": \"1de06853", "\"digest_sha256\": \"0de06853" },
            .{ "\"derived_sha512\": \"0bba33fb", "\"derived_sha512\": \"1bba33fb" },
            .{ "\"cas_bytes\": 37313912", "\"cas_bytes\": 37313911" },
        }) |edit| {
            const changed = try replaceOnce(allocator, committed_evidence, edit[0], edit[1]);
            defer allocator.free(changed);
            try testing.expectError(error.InvalidEvidence, verifyCommittedEvidence(allocator, changed, committed_pin, &committed_locks, now));
        }

        // A different pin, even one only lengthening the bound, is not the reviewed pin.
        const longer = try replaceOnce(allocator, committed_pin, "\"maximum_release_age_seconds\": 2678400", "\"maximum_release_age_seconds\": 2678401");
        defer allocator.free(longer);
        try testing.expectError(error.InvalidEvidence, verifyCommittedEvidence(allocator, committed_evidence, longer, &committed_locks, now));

        // Locks swapped between architectures or missing are refused.
        var swapped = committed_locks;
        swapped[0].bytes = committed_locks[2].bytes;
        try testing.expectError(error.InvalidEvidence, verifyCommittedEvidence(allocator, committed_evidence, committed_pin, &swapped, now));
        try testing.expectError(error.InvalidEvidence, verifyCommittedEvidence(allocator, committed_evidence, committed_pin, committed_locks[0..3], now));
    }
    try testing.expectError(error.InvalidEvidence, parseReleaseDate("Sat, 31 Sep 2026 07:55:41 UTC"));
    try testing.expectError(error.InvalidEvidence, parseInstant("2026-10-13T24:00:00Z"));
}

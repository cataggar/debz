//! Deterministic public test repositories, not production package authority.
const std = @import("std");
const fs = @import("debz").root_fs;
const archive = @import("integration-archive.zig");
const signing = @import("integration-signing.zig");
const maximum_bytes = 8 * 1024 * 1024;
const maximum_entries = 512;

const Config = struct {
    output: []const u8 = "",
    suite: []const u8 = "",
    architecture: []const u8 = "",
    signed_parity: bool = false,
    sha256_only: bool = false,
    extra_debs: std.ArrayList([]const u8) = .empty,
    descriptor_output: ?[]const u8 = null,
    repository_url: ?[]const u8 = null,
    script_case: enum { default, trace, known_failure, blocked } = .default,
};

fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn absolute(path: []const u8) !void {
    if (!std.fs.path.isAbsolute(path) or path.len > 4096) return error.AbsoluteFixturePathRequired;
    _ = try fs.Path.init(path[1..]);
}

fn parse(allocator: std.mem.Allocator, args: []const []const u8) !Config {
    var config: Config = .{};
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const argument = args[i];
        if (!equal(argument, "--extra-deb")) {
            if (seen.contains(argument)) return error.DuplicateFixtureArgument;
            try seen.put(argument, {});
        }
        if (equal(argument, "--signed-parity")) {
            config.signed_parity = true;
            continue;
        }
        if (equal(argument, "--sha256-only")) {
            config.sha256_only = true;
            continue;
        }
        i += 1;
        if (i >= args.len) return error.MissingFixtureArgument;
        const value = args[i];
        if (equal(argument, "--output")) {
            config.output = value;
        } else if (equal(argument, "--suite")) {
            config.suite = value;
        } else if (equal(argument, "--architecture")) {
            config.architecture = value;
        } else if (equal(argument, "--extra-deb")) {
            try absolute(value);
            if (config.extra_debs.items.len >= 64) return error.TooManyExtraPackages;
            try config.extra_debs.append(allocator, value);
        } else if (equal(argument, "--descriptor-output")) {
            try absolute(value);
            config.descriptor_output = value;
        } else if (equal(argument, "--descriptor-repository-url")) {
            if (value.len == 0 or value.len > 4096 or std.mem.indexOfAny(u8, value, "\r\n\x00") != null)
                return error.InvalidDescriptorRepositoryUrl;
            config.repository_url = value;
        } else if (equal(argument, "--descriptor-script-case")) {
            config.script_case = std.meta.stringToEnum(@TypeOf(config.script_case), value) orelse return error.InvalidDescriptorScriptCase;
        } else return error.UnexpectedFixtureArgument;
    }
    try absolute(config.output);
    if (!equal(config.suite, "debian-stable") and !equal(config.suite, "ubuntu-26.04")) return error.InvalidFixtureSuite;
    if (!equal(config.architecture, "amd64") and !equal(config.architecture, "arm64")) return error.InvalidFixtureArchitecture;
    if ((config.descriptor_output == null) != (config.repository_url == null)) return error.IncompleteDescriptorArguments;
    if (config.script_case != .default and config.descriptor_output == null) return error.MissingDescriptorOutput;
    if (config.signed_parity and config.sha256_only) return error.IncompatibleFixtureDigests;
    if (config.descriptor_output) |path| {
        if (equal(path, config.output) or
            (std.mem.startsWith(u8, path, config.output) and path.len > config.output.len and path[config.output.len] == '/'))
            return error.OverlappingFixtureOutputs;
    }
    return config;
}

const Field = struct { name: []const u8, value: []const u8 };
const Spec = struct {
    package: []const u8,
    version: []const u8 = "1.0-1",
    all: bool = false,
    fields: []const Field = &.{},
    payload: enum { regular, helper, literal, conffile } = .regular,
    control: enum { regular, retained, native_trigger, trigger, failure } = .regular,
};

fn specs(allocator: std.mem.Allocator, config: Config) ![]const Spec {
    const values = [_]Spec{
        .{ .package = "ca-certificates", .version = "20240203", .all = true },
        .{ .package = "base-dep" },
        .{ .package = "native-helper-target", .payload = .helper },
        .{ .package = "native-trigger-pkg", .control = .native_trigger },
        .{ .package = "literal-paths-pkg", .payload = .literal },
        .{ .package = "retained-metadata-pkg", .fields = &.{.{ .name = "Multi-Arch", .value = "same" }}, .control = .retained },
        .{ .package = "pre-app", .fields = &.{.{ .name = "Pre-Depends", .value = "base-dep" }} },
        .{ .package = "alt-a" },
        .{ .package = "alt-b", .version = "2.0-1" },
        .{ .package = "alt-consumer", .fields = &.{.{ .name = "Depends", .value = "alt-a | alt-b" }} },
        .{ .package = "virtual-provider", .version = "2.0-1", .fields = &.{.{ .name = "Provides", .value = "virtual-api (= 2.0)" }} },
        .{ .package = "virtual-consumer", .fields = &.{.{ .name = "Depends", .value = "virtual-api (>= 2.0)" }} },
        .{ .package = "recommended-addon", .all = true },
        .{ .package = "recommend-app", .fields = &.{.{ .name = "Recommends", .value = "recommended-addon" }} },
        .{ .package = "conflict-old", .fields = &.{.{ .name = "Conflicts", .value = "conflict-new" }} },
        .{ .package = "conflict-new", .version = "2.0-1", .fields = &.{
            .{ .name = "Conflicts", .value = "conflict-old" }, .{ .name = "Breaks", .value = "conflict-old" }, .{ .name = "Replaces", .value = "conflict-old" },
        } },
        .{ .package = "essential-core", .fields = &.{.{ .name = "Essential", .value = "yes" }} },
        .{ .package = "protected-core", .fields = &.{.{ .name = "Protected", .value = "yes" }} },
        .{ .package = "multi-lib", .fields = &.{.{ .name = "Multi-Arch", .value = "same" }} },
        .{ .package = "cycle-a", .fields = &.{.{ .name = "Depends", .value = "cycle-b" }} },
        .{ .package = "cycle-b", .fields = &.{.{ .name = "Depends", .value = "cycle-a" }} },
        .{ .package = "fixture-upgrade" },
        .{ .package = "fixture-upgrade", .version = "2.0-1" },
        .{ .package = "conffile-pkg", .payload = .conffile },
        .{ .package = "trigger-pkg", .version = if (equal(config.suite, "debian-stable")) "1.0-1debian1" else "1.0-1ubuntu1", .control = .trigger },
        .{ .package = "fail-script", .control = .failure },
        .{ .package = "scenario-main", .fields = &.{
            .{ .name = "Depends", .value = "base-dep" }, .{ .name = "Recommends", .value = "recommended-addon" },
        } },
        .{ .package = "pre-fail-app", .fields = &.{.{ .name = "Pre-Depends", .value = "fail-script" }} },
    };
    return allocator.dupe(Spec, values[0 .. values.len - @intFromBool(!config.signed_parity)]);
}

fn field(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    try out.appendSlice(allocator, try std.fmt.allocPrint(allocator, "{s}: {s}\n", .{ name, value }));
    if (out.items.len > maximum_bytes) return error.FixtureRepositoryTooLarge;
}

fn entry(allocator: std.mem.Allocator, name: []const u8, bytes: []const u8, mode: u16) !archive.Entry {
    return .{ .name = name, .hex = try std.fmt.allocPrint(allocator, "{x}", .{bytes}), .mode = mode };
}

fn buildDeb(io: std.Io, allocator: std.mem.Allocator, workspace: []const u8, spec: Spec, architecture: []const u8) ![]u8 {
    var control: std.ArrayList(u8) = .empty;
    try field(allocator, &control, "Package", spec.package);
    try field(allocator, &control, "Version", spec.version);
    try field(allocator, &control, "Architecture", architecture);
    try field(allocator, &control, "Maintainer", "debz fixture <fixture.invalid>");
    try field(allocator, &control, "Description", try std.fmt.allocPrint(allocator, "debz hermetic fixture {s}", .{spec.package}));
    for (spec.fields) |item| try field(allocator, &control, item.name, item.value);
    var entries: std.ArrayList(archive.Entry) = .empty;
    try entries.append(allocator, try entry(allocator, "./control", control.items, 0o644));
    switch (spec.control) {
        .regular => {},
        .retained => {
            try entries.append(allocator, try entry(allocator, "./templates", try std.fmt.allocPrint(allocator, "Template: {s}/value\nType: string\nDescription: inert metadata\n", .{spec.package}), 0o644));
            try entries.append(allocator, try entry(allocator, "./shlibs", try std.fmt.allocPrint(allocator, "libretained 1 {s} (>= {s})\n", .{ spec.package, spec.version }), 0o640));
            try entries.append(allocator, try entry(allocator, "./symbols", try std.fmt.allocPrint(allocator, "libretained.so.1 {s} #MINVER#\n symbol@Base 1\n\x00\xff", .{spec.package}), 0o644));
        },
        .failure => try entries.append(allocator, try entry(allocator, "./postinst", "#!/bin/sh\nexit 42\n", 0o755)),
        .trigger => try entries.append(allocator, try entry(allocator, "./triggers", "interest-noawait /usr/share/debz-fixtures\n", 0o644)),
        .native_trigger => {
            try entries.append(allocator, try entry(allocator, "./triggers", "interest-noawait native-fixture\nactivate-noawait native-fixture\n", 0o644));
            try entries.append(allocator, try entry(allocator, "./postinst", "#!/bin/sh\nset -e\nprintf \"%s\\n\" \"$*\" >>/native-trigger-trace\n" ++
                "if [ \"$1\" = configure ]; then /usr/bin/dpkg-trigger --no-await native-fixture; fi\n", 0o755));
        },
    }
    if (spec.payload == .conffile)
        try entries.append(allocator, try entry(allocator, "./conffiles", "/etc/debz-fixture.conf\n", 0o644));
    const payload_path = switch (spec.payload) {
        .regular => try std.fmt.allocPrint(allocator, "./usr/share/debz-fixtures/{s}", .{spec.package}),
        .helper => "./usr/bin/dpkg-trigger",
        .literal => "./usr/lib/systemd/system/system-debz\\x2dliteral.slice",
        .conffile => "./etc/debz-fixture.conf",
    };
    const payload = try std.fmt.allocPrint(allocator, "{s}={s}:{s}\n", .{ spec.package, spec.version, architecture });
    return archive.encode(io, allocator, workspace, .{ .control = entries.items, .data = &.{try entry(allocator, payload_path, payload, 0o644)} });
}

fn digest(comptime Hash: type, bytes: []const u8) [Hash.digest_length * 2]u8 {
    var value: [Hash.digest_length]u8 = undefined;
    Hash.hash(bytes, &value, .{});
    return std.fmt.bytesToHex(value, .lower);
}

const OutputFile = struct { name: []const u8, bytes: []const u8 };
const Repository = struct {
    files: std.ArrayList(OutputFile) = .empty,
    size: usize = 0,

    fn add(self: *Repository, allocator: std.mem.Allocator, name: []const u8, bytes: []const u8) !void {
        if (bytes.len > maximum_bytes - self.size) return error.FixtureRepositoryTooLarge;
        self.size += bytes.len;
        try self.files.append(allocator, .{ .name = name, .bytes = bytes });
    }
};

fn transport(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, bytes: []const u8, sha256_only: bool) !void {
    try field(allocator, out, "Filename", name);
    try field(allocator, out, "Size", try std.fmt.allocPrint(allocator, "{d}", .{bytes.len}));
    try field(allocator, out, "SHA256", &digest(std.crypto.hash.sha2.Sha256, bytes));
    if (!sha256_only) try field(allocator, out, "SHA512", &digest(std.crypto.hash.sha2.Sha512, bytes));
}

fn controlField(text: []const u8, name: []const u8) ![]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len > name.len + 2 and std.mem.startsWith(u8, line, name) and equal(line[name.len .. name.len + 2], ": "))
            return std.mem.trim(u8, line[name.len + 2 ..], " \t\r\x0b\x0c");
    }
    return error.MissingExtraPackageIdentity;
}

fn identity(package: []const u8, version: []const u8, architecture: []const u8, target: []const u8) !void {
    if (package.len < 2 or !std.ascii.isLower(package[0]) and !std.ascii.isDigit(package[0]))
        return error.InvalidExtraPackageIdentity;
    for (package[1..]) |byte|
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and std.mem.indexOfScalar(u8, "+.-", byte) == null)
            return error.InvalidExtraPackageIdentity;
    if (version.len == 0 or !std.ascii.isDigit(version[0])) return error.InvalidExtraPackageIdentity;
    for (version[1..]) |byte|
        if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, ".+~-", byte) == null)
            return error.InvalidExtraPackageIdentity;
    if (!equal(architecture, target) and !equal(architecture, "all")) return error.InvalidExtraPackageArchitecture;
}

fn readExtra(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var root = try fs.openAbsoluteRoot(io, std.fs.path.dirname(path).?);
    defer root.close();
    var pin = try root.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(path)));
    defer pin.close();
    const observation = try pin.observeStableAlloc(allocator, maximum_bytes);
    return observation.bytes;
}

fn repository(io: std.Io, allocator: std.mem.Allocator, workspace: []const u8, config: Config) !struct { repo: Repository, keyring: []const u8 } {
    var result: Repository = .{};
    var paragraphs: std.ArrayList(u8) = .empty;
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    for (try specs(allocator, config)) |spec| {
        const arch = if (spec.all) "all" else config.architecture;
        const bytes = try buildDeb(io, allocator, workspace, spec, arch);
        const filename = try std.fmt.allocPrint(allocator, "pool/main/{s}_{s}_{s}.deb", .{ spec.package, spec.version, arch });
        try result.add(allocator, filename, bytes);
        try seen.put(try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ spec.package, spec.version }), {});
        try field(allocator, &paragraphs, "Package", spec.package);
        try field(allocator, &paragraphs, "Version", spec.version);
        try field(allocator, &paragraphs, "Architecture", arch);
        try field(allocator, &paragraphs, "Maintainer", "debz fixture <fixture.invalid>");
        try field(allocator, &paragraphs, "Installed-Size", try std.fmt.allocPrint(allocator, "{d}", .{@max(1, bytes.len / 1024)}));
        for (spec.fields) |item| try field(allocator, &paragraphs, item.name, item.value);
        try transport(allocator, &paragraphs, filename, bytes, config.sha256_only);
        try field(allocator, &paragraphs, "Description", try std.fmt.allocPrint(allocator, "debz hermetic fixture {s}", .{spec.package}));
        try paragraphs.append(allocator, '\n');
    }
    for (config.extra_debs.items) |path| {
        const bytes = try readExtra(io, allocator, path);
        const control = try archive.extraControl(allocator, bytes);
        const package = try controlField(control, "Package");
        const version = try controlField(control, "Version");
        const arch = try controlField(control, "Architecture");
        try identity(package, version, arch, config.architecture);
        const key = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ package, version });
        if (seen.contains(key)) return error.DuplicateExtraPackageIdentity;
        try seen.put(key, {});
        const filename = try std.fmt.allocPrint(allocator, "pool/main/{s}_{s}_{s}.deb", .{ package, version, arch });
        try result.add(allocator, filename, bytes);
        try paragraphs.appendSlice(allocator, control);
        try transport(allocator, &paragraphs, filename, bytes, config.sha256_only);
        try paragraphs.append(allocator, '\n');
    }
    const packages_name = try std.fmt.allocPrint(allocator, "dists/{s}/main/binary-{s}/Packages", .{ config.suite, config.architecture });
    try result.add(allocator, packages_name, paragraphs.items);
    const release = try std.fmt.allocPrint(allocator, "Origin: debz hermetic {s}\nLabel: debz integration fixture\nSuite: {s}\nCodename: {s}\n" ++
        "Date: Mon, 01 Jan 2024 00:00:00 +0000\nValid-Until: Thu, 01 Jan 2037 00:00:00 +0000\n" ++
        "Architectures: {s}\nComponents: main\nAcquire-By-Hash: no\nSHA256:\n {s} {d} main/binary-{s}/Packages\n", .{ config.suite, config.suite, config.suite, config.architecture, digest(std.crypto.hash.sha2.Sha256, paragraphs.items), paragraphs.items.len, config.architecture });
    const signed = try signing.sign(allocator, release);
    try result.add(allocator, try std.fmt.allocPrint(allocator, "dists/{s}/InRelease", .{config.suite}), signed.in_release);
    try result.add(allocator, "fixture-keyring.gpg", signed.keyring);
    try result.add(allocator, "fixture-provenance.txt", try std.fmt.allocPrint(allocator, "suite={s}\narchitecture={s}\nrelease_sha256={s}\npackages_sha256={s}\nsigner={s}\n", .{ config.suite, config.architecture, digest(std.crypto.hash.sha2.Sha256, release), digest(std.crypto.hash.sha2.Sha256, paragraphs.items), std.fmt.bytesToHex(signed.fingerprint, .lower) }));
    return .{ .repo = result, .keyring = signed.keyring };
}

fn descriptor(io: std.Io, allocator: std.mem.Allocator, workspace: []const u8, config: Config, keyring: []const u8) ![]u8 {
    const source_path = "etc/apt/sources.list.d/microsoft-prod.list";
    const keyring_path = "usr/share/keyrings/microsoft-prod.gpg";
    const default_script = "#!/bin/sh\nset -e\nexit 0\n";
    const postinst = switch (config.script_case) {
        .default => default_script,
        .trace => "#!/bin/sh\nprintf 'postinst\\n' >>/repository-trace\n",
        .known_failure => "#!/bin/sh\nprintf 'postinst\\n' >>/repository-trace\nexit 42\n",
        .blocked => "#!/bin/sh\nprintf 'postinst\\n' >>/repository-trace\nprintf entered >/fixture/postinst-entered\n" ++
            "while [ ! -f /fixture/finish-script ]; do /bin/sleep 0.02; done\n",
    };
    return archive.encode(io, allocator, workspace, .{
        .control = &.{
            try entry(allocator, "./control", "Package: packages-microsoft-prod\nVersion: 1.2-fixture\nArchitecture: all\nDepends: ca-certificates\n" ++
                "Maintainer: debz fixture <fixture.invalid>\nDescription: Microsoft-shaped repository descriptor fixture\n", 0o644),
            try entry(allocator, "./conffiles", "/" ++ source_path ++ "\n", 0o644),
            try entry(allocator, "./preinst", if (config.script_case == .default) default_script else "#!/bin/sh\nprintf 'preinst\\n' >>/repository-trace\n", 0o755),
            try entry(allocator, "./postinst", postinst, 0o755),
            try entry(allocator, "./prerm", default_script, 0o755),
        },
        .data = &.{
            try entry(allocator, "./" ++ source_path, try std.fmt.allocPrint(allocator, "deb [arch={s} signed-by=/" ++ keyring_path ++ "] {s} {s} main\n", .{ config.architecture, config.repository_url.?, config.suite }), 0o644),
            try entry(allocator, "./" ++ keyring_path, keyring, 0o644),
            try entry(allocator, "./etc/debsig/policies/fixture/packages-microsoft-prod.pol", "<Policy xmlns=\"https://www.debian.org/debsig/1.0/\"/>\n", 0o644),
            try entry(allocator, "./usr/share/debsig/keyrings/fixture/debsig.gpg", keyring, 0o644),
            try entry(allocator, "./usr/share/doc/packages-microsoft-prod/README", "Hermetic Microsoft-shaped descriptor fixture.\n", 0o644),
        },
        .origin = "fixture structural signature member",
    });
}

fn directories(root: fs.Root, path: []const u8) !void {
    var end: usize = 0;
    while (std.mem.indexOfScalarPos(u8, path, end, '/')) |slash| {
        const directory = try fs.Path.init(path[0..slash]);
        if (try root.entryIfExists(directory)) |existing| {
            if (!existing.isDirectory()) return error.NotDirectory;
        } else {
            var parent = try root.openParent(directory);
            defer parent.close(root.io);
            try parent.dir.createDir(root.io, parent.leaf, .fromMode(0o755));
        }
        end = slash + 1;
    }
}

const Observed = struct { path: fs.Path, entry: fs.Entry };

fn tree(root: fs.Root, allocator: std.mem.Allocator, path: fs.Path, out: *std.ArrayList(Observed), size: *u64, depth: usize) !void {
    if (out.items.len >= maximum_entries or depth > 16) return error.FixtureDestinationTooLarge;
    const item = try root.entry(path);
    if (item.isRegularFile()) {
        if (item.link_count != 1) return error.HardLinkedFixtureDestination;
        if (item.size > maximum_bytes - size.*) return error.FixtureDestinationTooLarge;
        size.* += item.size;
    } else if (!item.isDirectory()) return error.UnsafeFixtureDestination;
    try out.append(allocator, .{ .path = path, .entry = item });
    if (item.isDirectory()) {
        var pin = try root.pinDirectory(path);
        defer pin.close();
        var observed = try pin.observeAlloc(allocator, maximum_entries, 64 * 1024);
        defer observed.deinit();
        for (observed.members) |member| {
            if (equal(member.name, ".git")) return error.UnsafeFixtureDestination;
            try tree(root, allocator, try fs.Path.init(try std.fmt.allocPrint(allocator, "{s}/{s}", .{ path.text, member.name })), out, size, depth + 1);
        }
        _ = try pin.metadata();
    }
}

fn removeTree(root: fs.Root, allocator: std.mem.Allocator, path: fs.Path) !void {
    var observed: std.ArrayList(Observed) = .empty;
    var size: u64 = 0;
    try tree(root, allocator, path, &observed, &size, 0);
    var i = observed.items.len;
    while (i > 0) {
        i -= 1;
        const item = observed.items[i];
        const current = try root.entry(item.path);
        if (current.device != item.entry.device or current.inode != item.entry.inode or current.kind != item.entry.kind)
            return error.FixtureDestinationChanged;
        if (current.isDirectory()) try root.removeDirectory(item.path) else try root.removeFile(item.path);
    }
}

const DescriptorDestination = struct {
    root: fs.Root,
    path: fs.Path,
    original: ?fs.Entry,

    fn check(self: DescriptorDestination) !void {
        if (!std.meta.eql(self.original, try self.root.entryIfExists(self.path)))
            return error.FixtureDestinationChanged;
    }

    fn observe(context: *anyopaque, point: fs.PublishPoint) !void {
        const self: *DescriptorDestination = @ptrCast(@alignCast(context));
        if (point == .before_rename) try self.check();
    }
};

fn generate(io: std.Io, allocator: std.mem.Allocator, config: Config) !void {
    var filesystem = try fs.openAbsoluteRoot(io, "/");
    defer filesystem.close();
    try directories(filesystem.root, config.output[1..]);
    var parent = try fs.openAbsoluteRoot(io, std.fs.path.dirname(config.output).?);
    defer parent.close();
    const output = try fs.Path.init(std.fs.path.basename(config.output));
    const original = try parent.root.entryIfExists(output);
    if (original) |value| {
        if (!value.isDirectory()) return error.UnsafeFixtureDestination;
        var observed: std.ArrayList(Observed) = .empty;
        var size: u64 = 0;
        try tree(parent.root, allocator, output, &observed, &size, 0);
    }
    var descriptor_original: ?fs.Entry = null;
    if (config.descriptor_output) |path| {
        try directories(filesystem.root, path[1..]);
        descriptor_original = try filesystem.root.entryIfExists(try fs.Path.init(path[1..]));
        if (descriptor_original) |value|
            if (!value.isRegularFile() or value.link_count != 1) return error.UnsafeDescriptorDestination;
    }
    var random: [16]u8 = undefined;
    try io.randomSecure(&random);
    const stage = try fs.Path.init(try std.fmt.allocPrint(allocator, ".debz-integration-{s}", .{std.fmt.bytesToHex(random, .lower)}));
    const backup = try fs.Path.init(try std.fmt.allocPrint(allocator, "{s}.old", .{stage.text}));
    try parent.root.createDirectory(stage, .fromMode(0o700));
    var stage_exists = true;
    errdefer if (stage_exists) {
        removeTree(parent.root, allocator, stage) catch |err|
            std.log.err("integration staging cleanup failed: {s}", .{@errorName(err)});
    };
    const workspace = try std.fs.path.join(allocator, &.{ std.fs.path.dirname(config.output).?, stage.text });
    const generated = try repository(io, allocator, workspace, config);
    const descriptor_bytes = if (config.descriptor_output != null) try descriptor(io, allocator, workspace, config, generated.keyring) else null;
    // The scratch directory remains private; published directories and files
    // retain the producer's ordinary mkdir/open modes under the caller's umask.
    const published = try fs.Path.init(try std.fmt.allocPrint(allocator, "{s}/repository", .{stage.text}));
    {
        var directory_parent = try parent.root.openParent(published);
        defer directory_parent.close(io);
        try directory_parent.dir.createDir(io, directory_parent.leaf, .fromMode(0o755));
    }
    const repository_path = try std.fs.path.join(allocator, &.{ workspace, "repository" });
    var destination = try fs.openAbsoluteRoot(io, repository_path);
    defer destination.close();
    for (generated.repo.files.items) |file| {
        try directories(destination.root, file.name);
        var file_parent = try destination.root.openParent(try fs.Path.init(file.name));
        defer file_parent.close(io);
        const handle = try file_parent.dir.createFile(io, file_parent.leaf, .{
            .exclusive = true,
            .truncate = false,
            .resolve_beneath = true,
            .permissions = .fromMode(0o644),
        });
        defer handle.close(io);
        try handle.writeStreamingAll(io, file.bytes);
    }
    if (!std.meta.eql(original, try parent.root.entryIfExists(output))) return error.FixtureDestinationChanged;
    if (config.descriptor_output) |path|
        if (!std.meta.eql(descriptor_original, try filesystem.root.entryIfExists(try fs.Path.init(path[1..]))))
            return error.FixtureDestinationChanged;
    if (original != null) try parent.root.rename(output, backup, .fail_if_exists);
    parent.root.rename(published, output, .fail_if_exists) catch |err| {
        if (original != null) parent.root.rename(backup, output, .fail_if_exists) catch |restore_error|
            std.log.err("integration destination restoration failed: {s}", .{@errorName(restore_error)});
        return err;
    };
    if (descriptor_bytes) |bytes| {
        const path = config.descriptor_output.?;
        var descriptor_target: DescriptorDestination = .{
            .root = filesystem.root,
            .path = try fs.Path.init(path[1..]),
            .original = descriptor_original,
        };
        const scratch = try fs.Path.init(try std.fmt.allocPrint(allocator, "{s}/descriptor.mode", .{stage.text}));
        var scratch_parent = try parent.root.openParent(scratch);
        defer scratch_parent.close(io);
        const file = try scratch_parent.dir.createFile(io, scratch_parent.leaf, .{
            .exclusive = true,
            .truncate = false,
            .resolve_beneath = true,
            .permissions = .fromMode(0o644),
        });
        defer file.close(io);
        const permissions = if (descriptor_original) |old| std.Io.File.Permissions.fromMode(old.mode) else (try file.stat(io)).permissions;
        try descriptor_target.check();
        try filesystem.root.publishFile(descriptor_target.path, bytes, .{
            .permissions = permissions,
            .observer = .{ .context = &descriptor_target, .hitFn = DescriptorDestination.observe },
        });
    }
    if (original != null) try removeTree(parent.root, allocator, backup);
    try removeTree(parent.root, allocator, stage);
    stage_exists = false;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var arguments: std.ArrayList([]const u8) = .empty;
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    while (iterator.next()) |arg| try arguments.append(allocator, arg);
    const config = parse(allocator, arguments.items) catch |err| {
        std.log.err("integration repository arguments refused: {s}", .{@errorName(err)});
        return err;
    };
    generate(init.io, allocator, config) catch |err| {
        std.log.err("native integration repository refused: {s}", .{@errorName(err)});
        return err;
    };
}

fn launch(allocator: std.mem.Allocator, arguments: []const []const u8) !std.process.RunResult {
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("PATH", "/no-host-interpreters");
    const command = try std.mem.concat(allocator, []const u8, &.{
        &.{@import("integration_repository_test_options").executable}, arguments,
    });
    return std.process.run(allocator, std.testing.io, .{
        .argv = command,
        .environ_map = &environment,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(8192),
    });
}

test "repository CLI reproduces independently original complete amd64 and arm64 repositories without interpreters" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const output = try std.fs.path.join(allocator, &.{ directory, "repository" });
    const descriptor_output = try std.fs.path.join(allocator, &.{ directory, "descriptor.deb" });
    for ([_]struct { arch: []const u8, inventory: []const u8, descriptor_digest: []const u8 }{
        .{ .arch = "amd64", .inventory = "0e4ce6a028df46e164ff39b3f5c671df4cfd383367c7ef4d651c1b3260f22680", .descriptor_digest = "d27e375d122095a9f023865437ac46ba8162077dcfe766bc74c237ca4b0de592" },
        .{ .arch = "arm64", .inventory = "8adffc169c743f7515d01a6d314cfa20d331e04e620637ad70138a034d135b8f", .descriptor_digest = "cba7a5d73e43744c3bd567a5e7300fc3b72636777b15aab0dacf578653f24acb" },
    }) |expected| {
        const result = try launch(allocator, &.{
            "--output",            output,            "--suite",                     "debian-stable",                     "--architecture", expected.arch,
            "--descriptor-output", descriptor_output, "--descriptor-repository-url", "http://127.0.0.1:12345/repository",
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try std.testing.expectEqual(@as(usize, 0), result.stdout.len);
        var root = try fs.openAbsoluteRoot(std.testing.io, output);
        defer root.close();
        var observed: std.ArrayList(Observed) = .empty;
        var size: u64 = 0;
        for ([_][]const u8{ "pool", "dists", "fixture-keyring.gpg", "fixture-provenance.txt" }) |path|
            try tree(root.root, allocator, try fs.Path.init(path), &observed, &size, 0);
        std.mem.sort(Observed, observed.items, {}, struct {
            fn less(_: void, a: Observed, b: Observed) bool {
                return std.mem.lessThan(u8, a.path.text, b.path.text);
            }
        }.less);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var count: usize = 0;
        for (observed.items) |item| {
            if (!item.entry.isRegularFile()) continue;
            var pin = try root.root.pinRegularFile(item.path);
            defer pin.close();
            const bytes = try pin.observeStableAlloc(allocator, maximum_bytes);
            hash.update(item.path.text);
            hash.update("\n");
            hash.update(&digest(std.crypto.hash.sha2.Sha256, bytes.bytes));
            hash.update("\n");
            count += 1;
        }
        var hashed: [32]u8 = undefined;
        hash.final(&hashed);
        try std.testing.expectEqual(@as(usize, 31), count);
        try std.testing.expectEqualStrings(expected.inventory, &std.fmt.bytesToHex(hashed, .lower));
        try std.testing.expectEqualStrings(expected.descriptor_digest, &digest(std.crypto.hash.sha2.Sha256, try temporary.dir.readFileAlloc(std.testing.io, "descriptor.deb", allocator, .limited(maximum_bytes))));
    }
}

fn refusal(allocator: std.mem.Allocator, output: []const u8, arguments: []const []const u8, message: []const u8) !void {
    const args = try std.mem.concat(allocator, []const u8, &.{
        &.{ "--output", output, "--suite", "debian-stable", "--architecture", "arm64" }, arguments,
    });
    const result = try launch(allocator, args);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try std.testing.expectEqual(@as(usize, 0), result.stdout.len);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, message) != null);
}

test "repository CLI rejects incompatible arguments and malformed extra identities before replacing output" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDir(std.testing.io, "repository", .fromMode(0o755));
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "repository/sentinel", .data = "original output\n" });
    const directory = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const output = try std.fs.path.join(allocator, &.{ directory, "repository" });
    try refusal(allocator, output, &.{ "--signed-parity", "--sha256-only" }, "IncompatibleFixtureDigests");
    try refusal(allocator, output, &.{ "--descriptor-script-case", "trace" }, "MissingDescriptorOutput");
    try refusal(allocator, output, &.{ "--extra-deb", "relative.deb" }, "AbsoluteFixturePathRequired");
    try refusal(allocator, output, &.{ "--archive-helper", "/retired-option" }, "UnexpectedFixtureArgument");
    const extra = try std.fs.path.join(allocator, &.{ directory, "extra.deb" });
    for ([_]struct { text: []const u8, message: []const u8 }{
        .{ .text = "Package: fixture-upgrade\nVersion: 1.0-1\nArchitecture: arm64\n", .message = "DuplicateExtraPackageIdentity" },
        .{ .text = "Package: extra-pkg\nVersion: bad\nArchitecture: arm64\n", .message = "InvalidExtraPackageIdentity" },
        .{ .text = "Package: extra-pkg\nVersion: 1.0-1\nArchitecture: amd64\n", .message = "InvalidExtraPackageArchitecture" },
        .{ .text = "Package: extra-pkg\nArchitecture: arm64\n", .message = "MissingExtraPackageIdentity" },
    }) |example| {
        const bytes = try archive.encode(std.testing.io, allocator, directory, .{
            .control = &.{try entry(allocator, "./control", example.text, 0o644)},
            .data = &.{},
        });
        try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "extra.deb", .data = bytes });
        try refusal(allocator, output, &.{ "--extra-deb", extra }, example.message);
        try std.testing.expectEqualStrings("original output\n", try temporary.dir.readFileAlloc(std.testing.io, "repository/sentinel", allocator, .limited(32)));
    }
}

test "repository CLI refuses destination and source aliases before clearing original output" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDir(std.testing.io, "repository", .fromMode(0o755));
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "repository/sentinel", .data = "original output\n" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "outside", .data = "external bytes\n" });
    try temporary.dir.symLink(std.testing.io, "outside", "descriptor.deb", .{});
    try temporary.dir.symLink(std.testing.io, "outside", "extra.deb", .{});
    const directory = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const output = try std.fs.path.join(allocator, &.{ directory, "repository" });
    const descriptor_path = try std.fs.path.join(allocator, &.{ directory, "descriptor.deb" });
    try refusal(allocator, output, &.{ "--descriptor-output", descriptor_path, "--descriptor-repository-url", "file:///repository" }, "UnsafeDescriptorDestination");
    const extra = try std.fs.path.join(allocator, &.{ directory, "extra.deb" });
    const result = try launch(allocator, &.{ "--output", output, "--suite", "debian-stable", "--architecture", "arm64", "--extra-deb", extra });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try temporary.dir.symLink(std.testing.io, "../outside", "repository/alias", .{});
    try refusal(allocator, output, &.{}, "UnsafeFixtureDestination");
    try std.testing.expectEqualStrings("original output\n", try temporary.dir.readFileAlloc(std.testing.io, "repository/sentinel", allocator, .limited(32)));
    try std.testing.expectEqualStrings("external bytes\n", try temporary.dir.readFileAlloc(std.testing.io, "outside", allocator, .limited(32)));
}

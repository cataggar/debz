const std = @import("std");
const order = @import("real-snapshot-reference-order.zig");
const paths = @import("real_snapshot_reference_paths.zig");
const linux = std.os.linux;
const A = std.mem.Allocator;
const eq = std.mem.eql;
const expect = std.testing.expect;
const expectError = std.testing.expectError;
const expectEqualStrings = std.testing.expectEqualStrings;
const io = std.testing.io;
const test_options = @import("reference_order_test_options");
fn expectStrings(expected: []const []const u8, actual: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |left, right| try expectEqualStrings(left, right);
}
fn replaceOne(a: A, bytes: []const u8, before: []const u8, after: []const u8) ![]const u8 {
    const at = std.mem.indexOf(u8, bytes, before) orelse return error.MissingOriginalUnitMutation;
    return std.fmt.allocPrint(a, "{s}{s}{s}", .{ bytes[0..at], after, bytes[at + before.len ..] });
}

const State = struct {
    a: A,
    packages: []order.Package,
    records: []order.Fields,
    controls: [][]order.Member = &.{},
    commands: std.ArrayList([]const []const u8) = .empty,
    captures: std.ArrayList(order.Prestate) = .empty,
    capture_states: std.ArrayList([]order.Fields) = .empty,
    cycle_calls: [3]usize = @splat(0),
    mode: enum { normal, stall, cycles, predepends, probe_budget, resume_cycles, bridge } = .normal,
    phase: usize = 0,
    captured_status: []const u8 = "half-configured",
    companion_status: []const u8 = "install ok installed",
    companion_version: ?[]const u8 = null,
    extra_transition: ?[]const u8 = null,
    after_status: ?[2][]const u8 = null,
    mutate_trigger: ?std.Io.Dir = null,
    trigger_name: []const u8 = "new",
    trigger_bytes: []const u8 = "unbound activation\n",
    probe_override: ?struct { selector: []const u8, result: order.Result } = null,
    no_progress: bool = false,
    constant_unpacked: bool = false,
    bad_refusal: bool = false,
    probe_count: usize = 0,
    fn get(pointer: *anyopaque) *State {
        return @ptrCast(@alignCast(pointer));
    }
    fn manifest(pointer: *anyopaque) ![]order.Package {
        return get(pointer).packages;
    }
    fn clone(self: *State, source: []order.Fields) ![]order.Fields {
        const result = try self.a.alloc(order.Fields, source.len);
        for (source, result) |record, *target| target.* = try record.clone(self.a);
        return result;
    }
    fn database(pointer: *anyopaque, _: []const u8) ![]order.Fields {
        const self = get(pointer);
        const result = try self.clone(self.records);
        if (self.constant_unpacked) for (result) |*record| try record.put(self.a, "status", .{ .string = "install ok unpacked" });
        return result;
    }
    fn package(self: *State, selector: []const u8) !order.Package {
        for (self.packages) |selected| if (eq(u8, selector, try selected.selector(self.a))) return selected;
        return error.UnknownTestSelector;
    }
    fn row(self: *State, name: []const u8) !*order.Fields {
        for (self.records) |*record| if (eq(u8, order.field(record.*, "package"), name)) return record;
        return error.UnknownTestPackage;
    }
    fn set(self: *State, name: []const u8, field: []const u8, value: []const u8) !void {
        try (try self.row(name)).put(self.a, field, .{ .string = value });
    }
    fn archive(_: *anyopaque, _: order.Package) !void {}
    fn control(pointer: *anyopaque, selected: order.Package) ![]order.Member {
        const self = get(pointer);
        for (self.packages, self.controls) |package_value, members| if (eq(u8, package_value.name, selected.name)) return members;
        return error.UnknownTestControl;
    }
    fn probe(pointer: *anyopaque, command: []const []const u8) !order.Result {
        const self = get(pointer);
        self.probe_count += 1;
        if (self.probe_override) |override| if (eq(u8, command[6], override.selector)) return override.result;
        const selected = try self.package(command[6]);
        if (eq(u8, command[5], "probe_unpack")) {
            if (self.mode == .bridge and self.phase == 0 and eq(u8, command[6], "systemd:amd64"))
                return .{ .code = 1, .stdout = "pre-dependency problem", .stderr = "" };
            if (self.mode == .probe_budget) {
                for (self.packages, 0..) |package_value, index| if (eq(u8, package_value.name, selected.name)) {
                    if (index + 1 < self.packages.len and !eq(u8, order.field((try self.row(self.packages[index + 1].name)).*, "status"), "install ok installed"))
                        return .{ .code = 1, .stdout = "pre-dependency problem", .stderr = "" };
                };
            }
            if (self.mode == .predepends and eq(u8, selected.name, "first") and !eq(u8, order.field((try self.row("second")).*, "status"), "install ok installed"))
                return .{ .code = 1, .stdout = "pre-dependency problem", .stderr = "" };
            if (self.mode == .cycles and eq(u8, selected.name, "systemd") and self.phase == 0)
                return .{ .code = 1, .stdout = "pre-dependency problem", .stderr = "" };
            return .{ .code = 0, .stdout = "", .stderr = "" };
        }
        if (self.mode == .bridge) return if (self.phase == 0 and (eq(u8, command[6], "libc6:amd64") or eq(u8, command[6], "libgcc-s1:amd64")))
            .{ .code = 1, .stdout = "dependency problems", .stderr = "" }
        else
            .{ .code = 0, .stdout = "", .stderr = "" };
        if (self.bad_refusal) return .{ .code = 1, .stdout = "dependency problems: another peer is not configured yet.", .stderr = "" };
        if (self.mode == .stall or ((self.mode == .cycles or self.mode == .resume_cycles) and
            (self.phase == 0 or eq(u8, selected.name, "libssl3t64") or eq(u8, selected.name, "openssl-provider-legacy") or
                (eq(u8, selected.name, "systemd") and self.phase != 2))))
            return .{ .code = 1, .stdout = "dependency problems", .stderr = "" };
        if (eq(u8, selected.name, "kbd"))
            return .{ .code = 1, .stdout = "dependency problems: Package console-setup is not configured yet.", .stderr = "" };
        if (eq(u8, selected.name, "libssl3t64") or eq(u8, selected.name, "openssl-provider-legacy")) {
            const peer = if (eq(u8, selected.name, "libssl3t64")) "openssl-provider-legacy" else "libssl3t64:amd64";
            return .{ .code = 1, .stdout = try std.fmt.allocPrint(self.a, "dependency problems: Package {s} is not configured yet.", .{peer}), .stderr = "" };
        }
        return .{ .code = 0, .stdout = "", .stderr = "" };
    }
    fn apply(pointer: *anyopaque, command: []const []const u8) !void {
        const self = get(pointer);
        try self.commands.append(self.a, command);
        const selected = try self.package(command[6]);
        const verb = command[5];
        if (std.mem.indexOf(u8, verb, "cycle") != null) {
            if (self.no_progress) return;
            try self.set(selected.name, "status", "install ok installed");
            if (eq(u8, verb, "configure_openssl_cycle")) try self.set("openssl-provider-legacy", "status", "install ok installed");
            if (self.extra_transition) |name| try self.set(name, "status", if (eq(u8, verb, "configure_openssl_cycle")) "install ok unpacked" else "install ok installed");
            if (self.after_status) |changed| try self.set(changed[0], "status", changed[1]);
            if (self.mutate_trigger) |directory| try directory.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(self.a, "var/lib/dpkg/triggers/{s}", .{self.trigger_name}), .data = self.trigger_bytes });
            return;
        }
        if (eq(u8, verb, "continue_prestate")) {
            try expect(eq(u8, selected.name, "systemd") or eq(u8, selected.name, "udev"));
            try expectEqualStrings(selected.name, command[4]);
            try expectEqualStrings("install ok half-configured", order.field((try self.row(selected.name)).*, "status"));
        }
        const status = if (eq(u8, verb, "unpack")) "install ok unpacked" else if (eq(u8, selected.name, "sudo-rs")) self.companion_status else "install ok installed";
        try self.set(selected.name, "status", status);
        if (!eq(u8, verb, "unpack") and eq(u8, selected.name, "sudo-rs")) if (self.companion_version) |version| try self.set(selected.name, "version", version);
    }
    fn transition(pointer: *anyopaque, kind: order.Cycle) ![]order.Package {
        const self = get(pointer);
        self.cycle_calls[@intFromEnum(kind)] += 1;
        try expect(self.cycle_calls[@intFromEnum(kind)] == 1);
        const cycle = try order.cyclePackages(self.a, self.packages, "amd64", kind);
        const selected = switch (kind) {
            .base => cycle[1..2],
            .openssl => cycle[0..2],
            .kbd => cycle[0..1],
        };
        for (selected) |package_value| try self.set(package_value.name, "status", "install ok installed");
        self.phase = if (kind == .base) 1 else 2;
        return selected;
    }
    fn capture(pointer: *anyopaque, selected: order.Package, prestate: order.Prestate) !void {
        const self = get(pointer);
        try expectEqualStrings("install ok unpacked", order.field((try self.row(selected.name)).*, "status"));
        if (eq(u8, selected.name, "sudo")) {
            const companion = (try self.row("sudo-rs")).*;
            try expectEqualStrings("install ok installed", order.field(companion, "status"));
            try expectEqualStrings("0.2.13-0ubuntu1.2", order.field(companion, "version"));
        }
        if (eq(u8, prestate.status, "half-configured"))
            try self.set(selected.name, "status", try std.fmt.allocPrint(self.a, "install ok {s}", .{self.captured_status}));
        try self.captures.append(self.a, prestate);
        try self.capture_states.append(self.a, try self.clone(self.records));
    }
    fn context(self: *State, root: []const u8, env: *const std.process.Environ.Map) order.Context {
        return .{ .a = self.a, .io = io, .environment = env, .launcher = .{ .path = "/protected/launcher", .runtime = "/protected/runtime" }, .dpkg = "/protected/dpkg", .root = root, .cache = root, .evidence = root, .architecture = "amd64", .test_hooks = .{ .state = self, .manifest = manifest, .database = database, .probe = probe, .apply = apply, .archive = archive, .control = control, .capture = capture } };
    }
};

fn rootPath(a: A, work: std.testing.TmpDir) ![]const u8 {
    var buffer: [4096]u8 = undefined;
    const count = try work.dir.realPath(io, &buffer);
    return a.dupe(u8, buffer[0..count]);
}
fn fixture(a: A, directory: std.Io.Dir, kind: order.Cycle) !State {
    const bytes = switch (kind) {
        .base => @embedFile("fixtures/real-snapshot/base-cycle-controls-v1.json"),
        .openssl => @embedFile("fixtures/real-snapshot/openssl-cycle-controls-v1.json"),
        .kbd => @embedFile("fixtures/real-snapshot/kbd-cycle-controls-v1.json"),
    };
    const value = try std.json.parseFromSlice(std.json.Value, a, bytes, .{ .allocate = .alloc_always });
    const entries = value.value.object.get("packages").?.array.items;
    const packages = try a.alloc(order.Package, entries.len);
    const records = try a.alloc(order.Fields, entries.len);
    const controls = try a.alloc([]order.Member, entries.len);
    for (entries, packages, records, controls, 0..) |entry, *package, *record, *members, index| {
        const object = entry.object;
        const control = object.get("control").?.string;
        record.* = (try order.controlFields(a, control))[0];
        package.* = .{ .name = order.field(record.*, "package"), .version = order.field(record.*, "version"), .architecture = order.field(record.*, "architecture"), .digest = object.get("archive_sha512").?.string, .size = @intCast(object.get("archive_size").?.integer), .archive = try std.fmt.allocPrint(a, "/original/{s}.deb", .{order.field(record.*, "package")}) };
        try record.put(a, "status", object.get("status").?);
        var list: std.ArrayList(order.Member) = .empty;
        try list.append(a, .{ .name = "./control", .bytes = control, .kind = '0' });
        if (kind == .kbd) {
            for (object.get("control_members").?.array.items) |member| {
                if (eq(u8, member.string, "./control")) continue;
                try list.append(a, .{ .name = member.string, .bytes = if (eq(u8, member.string, "./triggers")) order.kbd_triggers else "", .kind = if (eq(u8, member.string, ".")) '5' else '0' });
            }
        } else if ((kind == .base and index == 1) or (kind == .openssl and index == 0)) {
            for ([_][]const u8{ ".", "./md5sums", "./shlibs", "./symbols", "./triggers" }) |member|
                try list.append(a, .{ .name = member, .bytes = if (eq(u8, member, "./triggers")) order.libgcc_triggers else "", .kind = if (eq(u8, member, ".")) '5' else '0' });
        } else if (kind == .openssl and index == 1) {
            for ([_][]const u8{ ".", "./md5sums" }) |member| try list.append(a, .{ .name = member, .bytes = "", .kind = if (eq(u8, member, ".")) '5' else '0' });
        }
        members.* = try list.toOwnedSlice(a);
    }
    try directory.createDirPath(io, "var/lib/dpkg/info");
    try directory.createDirPath(io, "var/lib/dpkg/triggers");
    try directory.createDirPath(io, "var/lib/dpkg/updates");
    try directory.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = "synthetic unit fixture only\n" });
    const activation = switch (kind) {
        .base => "libgcc-s1:amd64",
        .openssl => "libssl3t64:amd64",
        .kbd => "kbd",
    };
    try directory.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(a, "var/lib/dpkg/info/{s}.triggers", .{activation}), .data = if (kind == .kbd) order.kbd_triggers else order.libgcc_triggers });
    return .{ .a = a, .packages = packages, .records = records, .controls = controls };
}
fn simple(a: A, names: []const []const u8) !State {
    const packages = try a.alloc(order.Package, names.len);
    const records = try a.alloc(order.Fields, names.len);
    for (names, packages, records) |name, *package, *record| {
        const version = if (eq(u8, name, "systemd") or eq(u8, name, "udev")) "259.5-0ubuntu3.4" else if (eq(u8, name, "sudo")) "1.9.17p2-1ubuntu3.1" else if (eq(u8, name, "sudo-rs")) "0.2.13-0ubuntu1.2" else "1";
        package.* = .{ .name = name, .version = version, .architecture = "amd64", .digest = "a" ** 128, .size = 42, .archive = try std.fmt.allocPrint(a, "/original/{s}.deb", .{name}) };
        record.* = .empty;
        for ([_][2][]const u8{ .{ "package", name }, .{ "architecture", "amd64" }, .{ "version", version }, .{ "status", "not yet unpacked" } }) |field|
            try record.put(a, field[0], .{ .string = field[1] });
    }
    return .{ .a = a, .packages = packages, .records = records };
}
fn selectedCommands(a: A, state: State, verb: []const u8) ![][]const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    for (state.commands.items) |command| if (eq(u8, command[5], verb)) try names.append(a, command[6]);
    return names.toOwnedSlice(a);
}
fn expectCycleRefusal(result: anytype) !void {
    if (result) |_| return error.AcceptedOriginalCycleRefusal else |err| if (!std.mem.startsWith(u8, @errorName(err), "Cycle")) return err;
}
fn expectOsRefusal(result: anytype) !void {
    if (result) |_| return error.AcceptedOriginalOsRefusal else |err| for ([_][]const u8{ "ReferencePathRefused", "FileNotFound", "PathAlreadyExists" }) |name| {
        if (eq(u8, @errorName(err), name)) return;
    } else return err;
}
fn samePackage(left: order.Package, right: order.Package) bool {
    return eq(u8, left.name, right.name) and eq(u8, left.version, right.version) and eq(u8, left.architecture, right.architecture) and
        eq(u8, left.digest, right.digest) and left.size == right.size and eq(u8, left.archive, right.archive);
}
fn evidenceJson(a: A, root: []const u8, relative: []const u8) !std.json.Value {
    return (try std.json.parseFromSlice(std.json.Value, a, try paths.readRootFile(a, root, relative, 4 * 1024 * 1024), .{})).value;
}

test "original manifest retains five-field TSV identity and all boundary refusals" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const valid = "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t42\n";
    const packages = try order.packagesFromManifest(a, valid, "/cache");
    try expect(packages.len == 1);
    try expectEqualStrings("/cache/packages-v2/objects/sha512-" ++ "a" ** 128, packages[0].archive);
    for ([_][]const u8{
        "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t42\textra\n", "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t\n",
        "demo\t1\tamd64\t" ++ "A" ** 128 ++ "\t42\n",        "demo\t\tamd64\t" ++ "a" ** 128 ++ "\t42\n",
        "Demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t42\n",        "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t+42\n",
        "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t٤٢\n",
        "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t0\n",         "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t536870913\n",
        "\n",                                                "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t42\n\n",
    }) |changed| {
        if (order.packagesFromManifest(a, changed, "/cache")) |_| return error.AcceptedChangedOriginalManifest else |_| {}
    }
    try expectError(error.EmptyReferenceClosure, order.packagesFromManifest(a, "", "/cache"));
    try expectError(error.DuplicateReferencePackage, order.packagesFromManifest(a, valid ++ valid, "/cache"));
    var many: std.Io.Writer.Allocating = .init(a);
    for (0..2000) |n| try many.writer.print("p{d}\t1\tamd64\t{s}\t536870912\n", .{ n, "a" ** 128 });
    try expect((try order.packagesFromManifest(a, many.written(), "/cache")).len == 2000);
    try many.writer.print("overflow\t1\tamd64\t{s}\t1\n", .{"a" ** 128});
    try expectError(error.ReferenceClosureExceedsPackageLimit, order.packagesFromManifest(a, many.written(), "/cache"));
}

test "original status rejects duplicate identity, redirected reads and accepts valueless fields" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const valid = "Package: demo\nArchitecture: amd64\nVersion: 1\nStatus: install ok unpacked\nConffiles:\nTriggers-Pending:\nDescription: original\n continuation\n";
    const records = try order.parseDatabase(a, valid);
    try expectEqualStrings("", order.field(records[0], "conffiles"));
    try expectEqualStrings("original\n continuation", order.field(records[0], "description"));
    try expectError(error.DuplicateReferenceDatabasePackage, order.parseDatabase(a, valid ++ "\n" ++ valid));
    try expectError(error.DuplicateReferenceDatabaseField, order.controlFields(a, "Package: demo\npackage: demo"));
    try expectError(error.InvalidReferenceIdentityContinuation, order.controlFields(a, "Package: demo\n redirected"));
    try expectError(error.MalformedReferenceDatabaseField, order.controlFields(a, "Package:demo"));
    try expectError(error.InvalidReferenceControlEncoding, order.controlFields(a, "\xff"));
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    try work.dir.symLink(io, "/etc", "var", .{ .is_directory = true });
    try expectError(error.ReferencePathRefused, paths.readRootFile(a, root, "var/lib/dpkg/status", 4 * 1024 * 1024));
    try expectError(error.NoncanonicalReferencePath, paths.openAbsolute(root[1..], true));
    try expectError(error.NoncanonicalReferencePath, paths.openAbsolute(try std.fmt.allocPrint(a, "{s}/../escape", .{root}), true));
}

test "original archive preflight rejects changed bytes and declared size" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const bytes = "exact fixture bytes";
    try work.dir.writeFile(io, .{ .sub_path = "fixture.deb", .data = bytes });
    const archive = try std.fmt.allocPrint(a, "{s}/fixture.deb", .{try rootPath(a, work)});
    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const package: order.Package = .{ .name = "fixture", .version = "1", .architecture = "amd64", .digest = &hex, .size = bytes.len, .archive = archive };
    {
        const pin = try paths.openAbsolute(archive, false);
        defer pin.close();
        try order.verifyPinnedArchive(package, pin);
    }
    try work.dir.writeFile(io, .{ .sub_path = "fixture.deb", .data = "x" ** bytes.len });
    {
        const pin = try paths.openAbsolute(archive, false);
        defer pin.close();
        try expectError(error.ReferenceArchiveDigestChanged, order.verifyPinnedArchive(package, pin));
    }
    try work.dir.writeFile(io, .{ .sub_path = "fixture.deb", .data = "different-size" });
    const pin = try paths.openAbsolute(archive, false);
    defer pin.close();
    try expectError(error.ReferenceArchiveSizeChanged, order.verifyPinnedArchive(package, pin));
}

test "original single-package launcher command refuses all unbound trigger and half-configured verbs" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var state = try simple(a, &.{"sudo"});
    const launcher: order.Launcher = .{ .path = "/launcher", .runtime = "/runtime" };
    const package = state.packages[0];
    const command = try order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "none", "unpack", package, &.{});
    try expectStrings(&.{ "amd64", "none", "unpack", "sudo:amd64", "/runtime", "/original/sudo.deb", "a" ** 128, "42" }, command[3..]);
    for ([_][]const u8{ "triggers_only", "triggers_pending", "--pending", "unknown" }) |verb|
        try expectError(error.NoSingleScriptBinding, order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "sudo", verb, package, &.{}));
    try expectError(error.SignedPackageRequired, order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "none", "configure", null, &.{}));
    try expectError(error.MissingExactConfigureProfile, order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "none", "configure", package, &.{}));
    for ([_]struct { name: []const u8, arch: []const u8, version: []const u8, profile: []const u8 }{
        .{ .name = "systemd", .arch = "amd64", .version = "259.5-0ubuntu3.4", .profile = "none" },
        .{ .name = "sudo", .arch = "amd64", .version = package.version, .profile = "sudo" },
        .{ .name = "udev", .arch = "amd64", .version = "259.5-0ubuntu3.4", .profile = "systemd" },
        .{ .name = "systemd", .arch = "arm64", .version = "259.5-0ubuntu3.4", .profile = "systemd" },
        .{ .name = "systemd", .arch = "amd64", .version = "wrong", .profile = "systemd" },
    }) |changed| {
        var selected = package;
        selected.name = changed.name;
        selected.architecture = changed.arch;
        selected.version = changed.version;
        if (order.dpkgCommand(a, launcher, "/dpkg", "/root", changed.arch, changed.profile, "continue_prestate", selected, &.{})) |_| return error.AcceptedUnboundContinuation else |err| if (std.mem.indexOf(u8, @errorName(err), "Unauthorized") == null) return err;
    }
    for ([_][]const u8{ "systemd", "udev" }) |name| {
        var selected = package;
        selected.name = name;
        selected.version = "259.5-0ubuntu3.4";
        try expectEqualStrings("continue_prestate", (try order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", name, "continue_prestate", selected, &.{}))[5]);
    }
    state.packages[0].architecture = "all";
    try expectError(error.UnauthorizedReferenceScriptProfile, order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "sudo", "configure", state.packages[0], &.{}));
}

test "all original cycle commands bind exact architecture, ordered archive set, profile and selector" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const launcher: order.Launcher = .{ .path = "/launcher", .runtime = "/runtime" };
    for ([_]order.Cycle{ .base, .openssl, .kbd }) |kind| {
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        const state = try fixture(a, work.dir, kind);
        const index: usize = if (kind == .base) 1 else 0;
        const profile = switch (kind) {
            .base => "libgcc_cycle",
            .openssl => "openssl_cycle",
            .kbd => "kbd_cycle",
        };
        const verb = switch (kind) {
            .base => "break_base_cycle",
            .openssl => "configure_openssl_cycle",
            .kbd => "break_kbd_cycle",
        };
        const cycle = state.packages;
        const command = try order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", profile, verb, cycle[index], cycle);
        try expectEqualStrings(try cycle[index].selector(a), command[6]);
        for (cycle, command[8..]) |package, archive| try expectEqualStrings(package.archive, archive);
        try expectError(error.CycleIdentityChanged, order.dpkgCommand(a, launcher, "/dpkg", "/root", "arm64", profile, verb, cycle[index], cycle));
        try expectError(error.CycleIdentityChanged, order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "none", verb, cycle[index], cycle));
        try expectError(error.CycleIdentityChanged, order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", profile, verb, cycle[if (index == 0) 1 else 0], cycle));
        try expectError(error.CycleIdentityChanged, order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", profile, verb, cycle[index], cycle[0 .. cycle.len - 1]));
        const changed = try a.dupe(order.Package, cycle);
        std.mem.swap(order.Package, &changed[0], &changed[1]);
        try expectError(error.CycleIdentityChanged, order.dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", profile, verb, cycle[index], changed));
        changed[0] = cycle[0];
        changed[1] = cycle[1];
        changed[0].digest = "0" ** 128;
        try expectError(error.CycleIdentityChanged, order.cyclePackages(a, changed, "amd64", kind));
        try expectError(error.UnknownCycle, order.cyclePackages(a, cycle, "arm64", kind));
    }
}

test "original signed cycle graph, callback, pending and outside dependency mutations refuse before apply" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    for ([_]order.Cycle{ .base, .openssl, .kbd }) |kind| {
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        var state = try fixture(a, work.dir, kind);
        const root = try rootPath(a, work);
        const ctx = state.context(root, &env);
        _ = try ctx.verifyCycle(root, state.packages, kind);
        for (state.records, 0..) |record, index| {
            for ([_][]const u8{ "depends", "pre-depends", "multi-arch", "status", "triggers-pending", "triggers-awaited", "config-version", "version" }) |key| {
                const saved = try state.records[index].clone(a);
                try state.records[index].put(a, key, .{ .string = "changed original graph" });
                if (ctx.verifyCycle(root, state.packages, kind)) |_| return error.AcceptedChangedSignedCycleGraph else |_| {}
                state.records[index] = saved;
            }
            _ = record;
        }
        const callback = switch (kind) {
            .base => "libgcc-s1",
            .openssl => "libssl3t64",
            .kbd => "kbd",
        };
        for ([_][]const u8{ "postinst", "config", "triggers" }) |script| {
            const name = try std.fmt.allocPrint(a, "var/lib/dpkg/info/{s}{s}.{s}", .{ callback, if (eq(u8, script, "triggers") or eq(u8, script, "config")) ":amd64" else "", script });
            // The legitimate amd64 activation is checked separately.
            if (kind != .kbd and eq(u8, script, "triggers")) continue;
            try work.dir.symLink(io, "/missing-unreviewed-callback", name, .{});
            try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, kind));
            try work.dir.deleteFile(io, name);
        }
        const activation = try std.fmt.allocPrint(a, "var/lib/dpkg/info/{s}{s}.triggers", .{ callback, if (kind == .kbd) "" else ":amd64" });
        try work.dir.writeFile(io, .{ .sub_path = activation, .data = "activate unbound-handler\n" });
        try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, kind));
        try work.dir.writeFile(io, .{ .sub_path = activation, .data = if (kind == .kbd) order.kbd_triggers else order.libgcc_triggers });
        try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/updates/0000", .data = "unincorporated state\n" });
        try expectError(error.CycleStateChanged, ctx.verifyCycle(root, state.packages, kind));
        try work.dir.deleteFile(io, "var/lib/dpkg/updates/0000");
        try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/triggers/Unincorp", .data = "unbound activation\n" });
        try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, kind));
        try expect(state.commands.items.len == 0);
    }
}

test "original one or two package transition conserves every other status field and trigger database" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    for ([_]order.Cycle{ .base, .openssl, .kbd }) |kind| {
        for (0..4) |mutation| {
            var work = std.testing.tmpDir(.{ .iterate = true });
            defer work.cleanup();
            var state = try fixture(a, work.dir, kind);
            const root = try rootPath(a, work);
            const ctx = state.context(root, &env);
            if (mutation == 1) state.extra_transition = if (kind == .base) "libc6" else if (kind == .openssl) "libc6" else "console-setup-linux";
            if (mutation == 2) state.no_progress = true;
            if (mutation == 3) state.mutate_trigger = work.dir;
            if (mutation == 0) {
                const selected = try ctx.transition(root, root, state.packages, kind, "out", "err");
                try expect(selected.len == (if (kind == .openssl) @as(usize, 2) else 1));
                try expect(state.commands.items.len == 1);
            } else try expectError(error.CycleNoProgress, ctx.transition(root, root, state.packages, kind, "out", "err"));
        }
    }
}

test "OpenSSL and kbd require exact independent peer refusals before applying cycle authority" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    for ([_]order.Cycle{ .openssl, .kbd }) |kind| {
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        var state = try fixture(a, work.dir, kind);
        state.bad_refusal = true;
        const root = try rootPath(a, work);
        const ctx = state.context(root, &env);
        try expectError(error.CycleProbeChanged, ctx.transition(root, root, state.packages, kind, "out", "err"));
        try expect(state.commands.items.len == 0);
    }
}

test "original full configured closure retains explicit unbound trigger closure refusal" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    // The original oracle reported a constant unpacked database; the scheduler-maintained database must agree.
    for ([_]bool{ false, true }) |constant_unpacked| {
        var state = try simple(a, &.{"fixture"});
        state.constant_unpacked = constant_unpacked;
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        const ctx = state.context(try rootPath(a, work), &env);
        try expectError(error.UnboundTriggerClosure, ctx.install(&.{}));
        try expect(state.commands.items.len == 2);
        try expectEqualStrings("unpack", state.commands.items[0][5]);
        try expectEqualStrings("configure", state.commands.items[1][5]);
    }
}

test "PreDepends retry preserves actual unpack order rather than original manifest order" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var state = try simple(a, &.{ "first", "second" });
    state.mode = .predepends;
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    try expectError(error.UnboundTriggerClosure, state.context(try rootPath(a, work), &env).install(&.{}));
    try expectStrings(&.{ "second:amd64", "first:amd64" }, try selectedCommands(a, state, "unpack"));
    try expectStrings(&.{ "second:amd64", "first:amd64" }, try selectedCommands(a, state, "configure"));
}

test "all capture orders continue only exact half-configured systemd and udev and stop at final target" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    for ([_][3][]const u8{
        .{ "systemd", "udev", "sudo" }, .{ "systemd", "sudo", "udev" }, .{ "udev", "systemd", "sudo" },
        .{ "udev", "sudo", "systemd" }, .{ "sudo", "systemd", "udev" }, .{ "sudo", "udev", "systemd" },
    }) |permutation| {
        for ([_][]const u8{ "half-configured", "unpacked", "installed" }) |captured_status| {
            var work = std.testing.tmpDir(.{ .iterate = true });
            defer work.cleanup();
            const root = try rootPath(a, work);
            var state = try simple(a, &.{ "sudo-rs", permutation[0], permutation[1], permutation[2] });
            state.captured_status = captured_status;
            var targets: [3]order.Prestate = undefined;
            for (permutation, &targets) |name, *target| target.* = .{ .selector = try std.fmt.allocPrint(a, "{s}:amd64", .{name}), .status = if (eq(u8, name, "sudo")) "unpacked" else "half-configured", .destination = try std.fmt.allocPrint(a, "{s}/saved-{s}", .{ root, name }) };
            const ctx = state.context(root, &env);
            if (eq(u8, captured_status, "half-configured")) {
                try ctx.install(&targets);
                try expect(state.captures.items.len == 3);
                const continued = try selectedCommands(a, state, "continue_prestate");
                try expect(continued.len == (if (eq(u8, permutation[2], "sudo")) @as(usize, 2) else 1));
                try expectEqualStrings(if (eq(u8, permutation[2], "sudo")) "install ok unpacked" else "install ok half-configured", order.field((try state.row(permutation[2])).*, "status"));
                const configured = try selectedCommands(a, state, "configure");
                try expect(configured.len == (if (eq(u8, permutation[2], "sudo")) @as(usize, 1) else 2));
                for (continued) |selector| try expect(eq(u8, selector, "systemd:amd64") or eq(u8, selector, "udev:amd64"));
            } else try expectError(error.CapturedPrestateStateVersionChanged, ctx.install(&targets));
        }
    }
}

test "sudo capture waits for exact companion without changing normal configure order" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    for ([_]bool{ true, false }) |capture_requested| {
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        const root = try rootPath(a, work);
        var state = try simple(a, &.{ "sudo", "sudo-rs" });
        const target: order.Prestate = .{ .selector = "sudo:amd64", .status = "unpacked", .destination = try std.fmt.allocPrint(a, "{s}/saved", .{root}) };
        if (capture_requested) {
            try state.context(root, &env).install(&.{target});
            try expectStrings(&.{"sudo-rs:amd64"}, try selectedCommands(a, state, "configure"));
            try expect(state.captures.items.len == 1);
        } else {
            try expectError(error.UnboundTriggerClosure, state.context(root, &env).install(&.{}));
            try expectStrings(&.{ "sudo:amd64", "sudo-rs:amd64" }, try selectedCommands(a, state, "configure"));
            try expect(state.captures.items.len == 0);
        }
    }
}

test "sudo missing changed architecture or version companion refuses before mutation and later drift cannot capture" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    for (0..6) |mutation| {
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        const root = try rootPath(a, work);
        var state = try simple(a, &.{ "sudo", "sudo-rs" });
        if (mutation == 0) state.packages = state.packages[0..1];
        if (mutation == 1) state.packages[1].version = "wrong";
        if (mutation == 2) state.packages[1].architecture = "arm64";
        if (mutation == 3) state.companion_status = "install ok unpacked";
        if (mutation == 4) state.companion_status = "install ok half-configured";
        if (mutation == 5) state.companion_version = "wrong";
        const target: order.Prestate = .{ .selector = "sudo:amd64", .status = "unpacked", .destination = try std.fmt.allocPrint(a, "{s}/saved", .{root}) };
        const ctx = state.context(root, &env);
        if (mutation < 3) {
            try expectError(error.SignedSudoPrestateExactCompanionRequired, ctx.install(&.{target}));
            try expect(state.commands.items.len == 0);
        } else try expectError(error.SignedSudoPrestateCompanionStateVersionChanged, ctx.install(&.{target}));
        try expect(state.captures.items.len == 0);
    }
}

test "second scheduler stall never repeats base or OpenSSL authority and preserves original refusal evidence" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    for ([_]bool{ false, true }) |openssl| {
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        var state = try fixture(a, work.dir, if (openssl) .openssl else .base);
        if (openssl) {
            var base_work = std.testing.tmpDir(.{ .iterate = true });
            defer base_work.cleanup();
            const base = try fixture(a, base_work.dir, .base);
            var package_list: std.ArrayList(order.Package) = .empty;
            var record_list: std.ArrayList(order.Fields) = .empty;
            try package_list.appendSlice(a, state.packages);
            try record_list.appendSlice(a, state.records);
            for (base.packages, base.records) |package, record| if (!eq(u8, package.name, "libc6")) {
                try package_list.append(a, package);
                try record_list.append(a, record);
            };
            const target = try simple(a, &.{"systemd"});
            try package_list.appendSlice(a, target.packages);
            try record_list.appendSlice(a, target.records);
            state.packages = try package_list.toOwnedSlice(a);
            state.records = try record_list.toOwnedSlice(a);
        }
        state.mode = .stall;
        const root = try rootPath(a, work);
        var ctx = state.context(root, &env);
        ctx.test_hooks.?.transition = State.transition;
        try expectError(error.CycleNoProgress, ctx.install(&.{}));
        try expect(state.cycle_calls[0] == 1 and state.cycle_calls[1] == @intFromBool(openssl));
        const evidence = try std.json.parseFromSlice(std.json.Value, a, try work.dir.readFileAlloc(io, "reference-no-progress.json", a, .limited(1024 * 1024)), .{});
        try expect(evidence.value.object.get("base_cycle_applied").?.bool);
        try expect(evidence.value.object.get("openssl_cycle_applied").?.bool == openssl);
        try expectEqualStrings("dependency problems", try decodePrefix(a, evidence.value.object.get("refusals").?.array.items[0].object.get("output_prefix_hex").?.string));
    }
}
fn decodePrefix(a: A, bytes: []const u8) ![]u8 {
    const decoded = try a.alloc(u8, bytes.len / 2);
    return std.fmt.hexToBytes(decoded, bytes);
}

test "cycle bridge retries normal schedule and never configures final prestate target" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var state = try fixture(a, work.dir, .openssl);
    var base_work = std.testing.tmpDir(.{ .iterate = true });
    defer base_work.cleanup();
    const base = try fixture(a, base_work.dir, .base);
    var package_list: std.ArrayList(order.Package) = .empty;
    var record_list: std.ArrayList(order.Fields) = .empty;
    try package_list.appendSlice(a, state.packages);
    try record_list.appendSlice(a, state.records);
    for (base.packages, base.records) |package, record| if (!eq(u8, package.name, "libc6")) {
        try package_list.append(a, package);
        try record_list.append(a, record);
    };
    const target = try simple(a, &.{"systemd"});
    try package_list.appendSlice(a, target.packages);
    try record_list.appendSlice(a, target.records);
    state.packages = try package_list.toOwnedSlice(a);
    state.records = try record_list.toOwnedSlice(a);
    state.mode = .cycles;
    state.constant_unpacked = true;
    const root = try rootPath(a, work);
    var ctx = state.context(root, &env);
    ctx.test_hooks.?.transition = State.transition;
    try ctx.install(&.{.{ .selector = "systemd:amd64", .status = "half-configured", .destination = try std.fmt.allocPrint(a, "{s}/saved", .{root}) }});
    try expect(state.cycle_calls[0] == 1 and state.cycle_calls[1] == 1 and state.captures.items.len == 1);
    for (try selectedCommands(a, state, "configure")) |selector| try expect(!eq(u8, selector, "systemd:amd64") and !eq(u8, selector, "libgcc-s1:amd64"));
}

test "child probe descriptors are write-only append with readonly dev-null stdin and readonly parent observation" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    try env.put("PATH", "/usr/bin:/bin");
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    const ctx: order.Context = .{ .a = a, .io = io, .environment = &env, .launcher = .{ .path = "", .runtime = "" }, .dpkg = "", .root = root, .cache = root, .evidence = root, .architecture = "amd64" };
    const child =
        \\[[ $(stat -Lc '%F:%t:%T' /proc/$$/fd/0) == 'character special file:1:3' ]] || exit 81
        \\for fd in 0 1 2; do
        \\  flags=$(sed -n 's/^flags:[[:space:]]*//p' /proc/$$/fdinfo/$fd)
        \\  n=$((8#$flags)); access=$((n & 3))
        \\  if ((fd==0)); then ((access==0)) || exit 82
        \\  else kind=$(stat -Lc '%F' /proc/$$/fd/$fd)
        \\    [[ $kind == 'regular file' || $kind == 'regular empty file' ]] && ((access==1 && (n & 1024)!=0)) || { printf 'fd=%s access=%s flags=%s type=%s\n' "$fd" "$access" "$flags" "$kind"; exit 83; }
        \\  fi
        \\done
        \\printf 'stdout witness\n'; printf 'stderr witness\n' >&2
    ;
    const result = try ctx.probe(&.{ "/bin/bash", "-c", child }, root);
    if (result.code != 0) std.debug.print("descriptor witness exit={d}: {s}\n", .{ result.code, result.stdout });
    try expect(result.code == 0);
    try expect(std.mem.indexOf(u8, result.stdout, "stdout witness") != null and std.mem.indexOf(u8, result.stdout, "stderr witness") != null);
    const pin = try paths.openAbsolute(root, true);
    defer pin.close();
    try expect((try paths.names(a, io, pin, 16)).len == 0);
}

test "pending loader failures retain original diagnostic bytes but never count as callback denial" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    const ctx: order.Context = .{ .a = a, .io = io, .environment = &env, .launcher = .{ .path = "", .runtime = "" }, .dpkg = "", .root = root, .cache = root, .evidence = root, .architecture = "amd64" };
    const diagnostic = "setpriv: error while loading shared libraries: libcap-ng.so.0: cannot open shared object file: No such file or directory\n";
    const result: order.Result = .{ .code = 127, .stdout = "pending stdout witness", .stderr = diagnostic, .stdout_bytes = "pending stdout witness".len, .stderr_bytes = diagnostic.len };
    const runtime: order.PendingRuntime = .{ .source = "/signed/libcap-ng.so.0.0.0", .target = "usr/lib/x86_64-linux-gnu/libcap-ng.so.0", .sha256 = "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f", .size = 26928, .mode = "0644" };
    try order.recordPendingResult(ctx, root, &.{ "dpkg", "--no-triggers", "--configure", "--pending" }, result, runtime);
    try expectError(error.CycleProofCallbackChanged, order.validatePendingResult(result));
    try expectEqualStrings(diagnostic, try ctx.read(root, "pending.stderr", 65536));
    try expectEqualStrings("pending stdout witness", try ctx.read(root, "pending.stdout", 65536));
    const receipt = try std.json.parseFromSlice(std.json.Value, a, try ctx.read(root, "pending-result.json", 4096), .{});
    try expect(receipt.value.object.get("returncode").?.integer == 127 and !receipt.value.object.get("output_truncated").?.bool);
    try expect(!try paths.exists(root, "comparison.json"));
}

test "pending oversized callback diagnostics are bounded retained and never accepted" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    const ctx: order.Context = .{ .a = a, .io = io, .environment = &env, .launcher = .{ .path = "", .runtime = "" }, .dpkg = "", .root = root, .cache = root, .evidence = root, .architecture = "amd64" };
    const diagnostic = try std.fmt.allocPrint(a, "post-installation script: Permission denied\n{s}", .{"x" ** 65536});
    const result: order.Result = .{ .code = 1, .stdout = "pending stdout witness", .stderr = diagnostic, .stdout_bytes = "pending stdout witness".len, .stderr_bytes = diagnostic.len };
    const runtime: order.PendingRuntime = .{ .source = "/signed/libcap-ng.so.0.0.0", .target = "usr/lib/x86_64-linux-gnu/libcap-ng.so.0", .sha256 = "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f", .size = 26928, .mode = "0644" };
    try order.recordPendingResult(ctx, root, &.{ "dpkg", "--no-triggers", "--configure", "--pending" }, result, runtime);
    try expectError(error.CycleProofCallbackChanged, order.validatePendingResult(result));
    try expectEqualStrings(diagnostic[0..65536], try ctx.read(root, "pending.stderr", 65536));
    const receipt = try std.json.parseFromSlice(std.json.Value, a, try ctx.read(root, "pending-result.json", 4096), .{});
    try expect(receipt.value.object.get("output_truncated").?.bool and receipt.value.object.get("stderr_bytes").?.integer == diagnostic.len);
    try expect(!try paths.exists(root, "comparison.json"));
    try order.validatePendingResult(.{ .code = 1, .stdout = "", .stderr = "post-installation script: Permission denied", .stderr_bytes = 43 });
    try expectError(error.CycleProofCallbackChanged, order.validatePendingResult(.{ .code = 0, .stdout = "", .stderr = "post-installation script: Permission denied" }));
}

test "actual probe output bound signal status and nofollow evidence conservation remain original" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    try env.put("PATH", "/usr/bin:/bin");
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    const ctx: order.Context = .{ .a = a, .io = io, .environment = &env, .launcher = .{ .path = "", .runtime = "" }, .dpkg = "", .root = root, .cache = root, .evidence = root, .architecture = "amd64" };
    try expect((try ctx.probe(&.{ "/bin/bash", "-c", "printf '%065536d' 0" }, root)).stdout.len == 65536);
    try expectError(error.ReferenceProbeOutputExceedsLimit, ctx.probe(&.{ "/bin/bash", "-c", "printf '%065537d' 0" }, root));
    try expect((try ctx.probe(&.{ "/bin/bash", "-c", "kill -TERM $$" }, root)).code == -15);
    try work.dir.writeFile(io, .{ .sub_path = "outside", .data = "original outside bytes" });
    try work.dir.symLink(io, "outside", "alias.json", .{});
    try expectError(error.ReferencePathRefused, ctx.json(root, "alias.json", .{ .changed = true }));
    try work.dir.createDir(io, "directory", .default_dir);
    try work.dir.symLink(io, "directory", "redirected", .{ .is_directory = true });
    try expectError(error.ReferencePathRefused, ctx.json(root, "redirected/aliased.json", .{ .changed = true }));
    try expectEqualStrings("original outside bytes", try ctx.read(root, "outside", 64));
}

test "raw controls and TSV keep original splitlines Unicode strip and tar validation" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const control = "\xc2\xa0Package: demo\r\nArchitecture: amd64\r\nVersion: 1\r\nStatus: install ok unpacked\xe2\x80\xa8Description: original\xc2\xa0";
    const records = try order.parseDatabase(a, control);
    try expectEqualStrings("original", order.field(records[0], "description"));
    const tsv = "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t42\rsecond\t1\tall\t" ++ "b" ** 128 ++ "\t43\xe2\x80\xa8";
    try expect((try order.packagesFromManifest(a, tsv, "/cache")).len == 2);
    var output: std.Io.Writer.Allocating = .init(a);
    var tar: std.tar.Writer = .{ .underlying_writer = &output.writer };
    try tar.writeDir(".", .{ .mode = 0o755 });
    try tar.writeFileBytes("./control", "Package: demo\n", .{ .mode = 0o644 });
    try tar.finishPedantically();
    const members = try order.tarMembers(a, output.written());
    try expect(members.len == 2);
    try expectEqualStrings("Package: demo\n", members[1].bytes);
    const corrupt = try a.dupe(u8, output.written());
    corrupt[0] ^= 1;
    try expectError(error.CycleControlChanged, order.tarMembers(a, corrupt));
    try expectError(error.CycleControlChanged, order.tarMembers(a, output.written()[0..520]));
}

test "actual reference compiler stanza binds explicit spaced compiler and protected library without widening PATH" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    try work.dir.createDir(io, "staged toolchain", .default_dir);
    const compiler = try std.fmt.allocPrint(a, "{s}/staged toolchain/zig", .{root});
    try work.dir.writeFile(io, .{ .sub_path = "staged toolchain/zig", .data = "#!/bin/bash\n[[ ! -v ZIG_LIB_DIR ]] || exit 50\nprintf '%s\\0' \"$0\" \"$@\" >\"$COMPILER_LOG\"\n" });
    const pin = try paths.openAbsolute(compiler, false);
    defer pin.close();
    _ = try paths.syscall(linux.fchmod(pin.fd, 0o755));
    const source = @embedFile("real-snapshot-reference.sh");
    const resolve_start = std.mem.indexOf(u8, source, "zig=${DEBZ_ZIG:").?;
    const resolve_end = resolve_start + std.mem.indexOfScalar(u8, source[resolve_start..], '\n').?;
    const command_start = std.mem.indexOf(u8, source, "\"$zig\" build-exe ").?;
    const command_end = std.mem.indexOfPos(u8, source, command_start, "chmod 0500 \"$launcher\"").?;
    const body = try std.fmt.allocPrint(a, "export PATH=/usr/sbin:/usr/bin:/sbin:/bin\nunset ZIG_LIB_DIR\n{s}\nworkspace=$1\nlauncher=$workspace/launcher\n{s}", .{ source[resolve_start..resolve_end], source[command_start..command_end] });
    var env: std.process.Environ.Map = .init(a);
    try env.put("DEBZ_ZIG", compiler);
    try env.put("COMPILER_LOG", try std.fmt.allocPrint(a, "{s}/compiler.argv", .{root}));
    try env.put("ZIG_LIB_DIR", "/untrusted/library");
    const observed = try std.process.run(a, io, .{ .argv = &.{ "/bin/bash", "-euo", "pipefail", "-c", body, "reference-compiler-fixture", root }, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(4096) });
    try expect(observed.term == .exited and observed.term.exited == 0);
    var argv: std.ArrayList([]const u8) = .empty;
    var arguments = std.mem.splitScalar(u8, try work.dir.readFileAlloc(io, "compiler.argv", a, .limited(65536)), 0);
    while (arguments.next()) |argument| if (argument.len != 0) try argv.append(a, argument);
    try expectEqualStrings(compiler, argv.items[0]);
    try expectEqualStrings("build-exe", argv.items[1]);
    var found_lib = false;
    var found_output = false;
    for (argv.items, 0..) |argument, i| {
        if (eq(u8, argument, "--zig-lib-dir")) {
            try expectEqualStrings(try std.fmt.allocPrint(a, "{s}/staged toolchain/lib", .{root}), argv.items[i + 1]);
            found_lib = true;
        }
        if (std.mem.startsWith(u8, argument, "-femit-bin=")) {
            try expectEqualStrings(try std.fmt.allocPrint(a, "-femit-bin={s}/launcher", .{root}), argument);
            found_output = true;
        }
    }
    try expect(found_lib and found_output);
}

test "actual shared checkout and foreign same-named reference scripts refuse before root creation or compiler execution" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    var env: std.process.Environ.Map = .init(a);
    try env.put("PATH", "/usr/bin:/bin");
    try env.put("DEBZ_ZIG", "/compiler-must-never-execute");
    const workspace = try std.fmt.allocPrint(a, "{s}/.real-snapshot/unused", .{root});
    const observed = try std.process.run(a, io, .{ .argv = &.{ "/bin/bash", "tools/real-snapshot-reference.sh", "/usr/bin/true", "/etc/passwd", root, "amd64", workspace }, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(4096) });
    try expect(observed.term == .exited and observed.term.exited != 0);
    try expect(std.mem.indexOf(u8, observed.stderr, "non-root or writable reference path") != null);
    try expect(!try paths.exists(root, ".real-snapshot/unused"));
    try work.dir.createDir(io, "tools", .default_dir);
    try work.dir.writeFile(io, .{ .sub_path = "tools/real-snapshot-reference.sh", .data = @embedFile("real-snapshot-reference.sh") });
    const foreign = try std.process.run(a, io, .{ .argv = &.{ "/bin/bash", try std.fmt.allocPrint(a, "{s}/tools/real-snapshot-reference.sh", .{root}), "/usr/bin/true", "/etc/passwd", root, "amd64", workspace }, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(4096) });
    try expect(foreign.term == .exited and foreign.term.exited == 2);
    try expectEqualStrings("run the protected reference script from its checkout root\n", foreign.stderr);
    try expect(!try paths.exists(root, ".real-snapshot/unused"));
}

test "signed capture receipt accepts every unchanged original order but refuses duplicate missing or drifted records without rewriting" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    try env.put("PATH", "/usr/bin:/bin");
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    const original = @embedFile("fixtures/real-snapshot/signed-proc-capture-record-v1.tsv");
    const source = @embedFile("real-snapshot-signed-proc-prestates.sh");
    const start = std.mem.indexOf(u8, source, "expected_record=$(printf").?;
    const end = std.mem.indexOfPos(u8, source, start, "\nrequire_control()").?;
    const first_tab = std.mem.indexOfScalar(u8, original, '\t').?;
    const second_tab = first_tab + 1 + std.mem.indexOfScalar(u8, original[first_tab + 1 ..], '\t').?;
    const first_newline = std.mem.indexOfScalar(u8, original, '\n').?;
    const destination = original[second_tab + 1 .. first_newline];
    try env.put("prestates", destination[0..std.mem.lastIndexOfScalar(u8, destination, '/').?]);
    try env.put("receipt", try std.fmt.allocPrint(a, "{s}/receipt.tsv", .{root}));
    var writer: std.Io.Writer.Allocating = .init(a);
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, source[start..end], at, "\"$prestates/prestates.tsv\"")) |index| {
        try writer.writer.writeAll(source[start..end][at..index]);
        try writer.writer.writeAll("\"$receipt\"");
        at = index + "\"$prestates/prestates.tsv\"".len;
    }
    try writer.writer.writeAll(source[start..end][at..]);
    var lines = std.mem.splitScalar(u8, original, '\n');
    const records: [3][]const u8 = .{ lines.next().?, lines.next().?, lines.next().? };
    for ([_][3]usize{ .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 }, .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 } }) |permutation| {
        const bytes = try std.fmt.allocPrint(a, "{s}\n{s}\n{s}\n", .{ records[permutation[0]], records[permutation[1]], records[permutation[2]] });
        try work.dir.writeFile(io, .{ .sub_path = "receipt.tsv", .data = bytes });
        const result = try std.process.run(a, io, .{ .argv = &.{ "/bin/bash", "-euo", "pipefail", "-c", writer.written() }, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(4096) });
        try expect(result.term == .exited and result.term.exited == 0);
        try expectEqualStrings(bytes, try paths.readRootFile(a, root, "receipt.tsv", 4096));
    }
    for ([_][]const u8{
        try std.fmt.allocPrint(a, "{s}\n{s}\n", .{ records[1], records[2] }),                  original ++ original,
        try std.fmt.allocPrint(a, "{s}\n{s}\n{s}\n", .{ records[0], records[0], records[2] }), original ++ "\n",
        original ++ "unknown:amd64\t1 install ok unpacked\t/outside\n",                        try replaceOne(a, original, "sudo:amd64\t", "sudo:arm64\t"),
        try replaceOne(a, original, "1.9.17p2-1ubuntu3.1", "1.9.17p2-1ubuntu3.2"),             try replaceOne(a, original, "install ok unpacked", "install ok installed"),
        try replaceOne(a, original, "prestates/sudo\n", "prestates/other\n"),
    }) |bytes| {
        try work.dir.writeFile(io, .{ .sub_path = "receipt.tsv", .data = bytes });
        const result = try std.process.run(a, io, .{ .argv = &.{ "/bin/bash", "-euo", "pipefail", "-c", writer.written() }, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(4096) });
        try expect(result.term == .exited and result.term.exited == 1);
        try expect(std.mem.indexOf(u8, result.stderr, "signed prestate record differs") != null);
        try expectEqualStrings(bytes, try paths.readRootFile(a, root, "receipt.tsv", 4096));
    }
}

test "installed custom-prefix ordering report is actual producer and protected harness refuses shared inputs without skips" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    try env.put("PATH", "/usr/bin:/bin");
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    try work.dir.createDirPath(io, "var/lib/dpkg/info");
    try work.dir.writeFile(io, .{ .sub_path = "reference-archives.tsv", .data = "fixture\t1\tamd64\t" ++ "a" ** 128 ++ "\t42\n" });
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = "Package: fixture\nArchitecture: amd64\nVersion: 1\nStatus: install ok installed\n" });
    const command: []const []const u8 = &.{ test_options.reference_order, "--report-only", "--architecture", "amd64", "--root", root, "--cache", root, "--evidence", root };
    for (0..2) |_| {
        const result = try std.process.run(a, io, .{ .argv = command, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(4096) });
        try expect(result.term == .exited and result.term.exited == 0);
        try expectEqualStrings("ii  fixture:amd64 1\n", try paths.readRootFile(a, root, "reference-installed.txt", 4096));
    }

    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/fixture.list", .data = "/dev/null\n" });
    const claims = try std.process.run(a, io, .{ .argv = command, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(4096) });
    try expect(claims.term == .exited and claims.term.exited != 0 and std.mem.indexOf(u8, claims.stderr, "ReferencePackageClaimsExcludedDevice") != null);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(a, test_options.protected_reference);
    for ([_][]const u8{ "--launcher", "--runtime", "--runtime-tool", "--dpkg", "--root-template", "--workspace", "--archive", "--escape-probe", "--escape-archive", "--profile-scripts" }) |flag|
        try argv.appendSlice(a, &.{ flag, try std.fmt.allocPrint(a, "{s}/unused", .{root}) });
    try argv.appendSlice(a, &.{ "--archive-sha512", "0" ** 128, "--archive-size", "1", "--escape-archive-sha512", "0" ** 128, "--escape-archive-size", "1", "--architecture", "amd64" });
    const refused = try std.process.run(a, io, .{ .argv = argv.items, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(16384) });
    try expect(refused.term == .exited and refused.term.exited != 0);
    try expect(std.mem.indexOf(u8, refused.stderr, "PermissionError") != null or std.mem.indexOf(u8, refused.stderr, "UnprotectedReferencePath") != null);
    try expect(std.mem.indexOf(u8, refused.stderr, "SKIP") == null);
    const path_refused = try std.process.run(a, io, .{ .argv = &.{ test_options.reference_paths, "protected", "file", try std.fmt.allocPrint(a, "{s}/reference-archives.tsv", .{root}) }, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(16384) });
    try expect(path_refused.term == .exited and path_refused.term.exited != 0);
}

test "original pending setpriv runtime rejects missing changed writable setgid or existing target without widening candidate" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    const approved = try a.alloc(u8, 26928);
    @memset(approved, 0);
    @memcpy(approved[0.."unit signed library".len], "unit signed library");
    const Hook = struct {
        fn digest(bytes: []const u8) ?[64]u8 {
            if (bytes.len == 26928 and std.mem.startsWith(u8, bytes, "unit signed library") and
                std.mem.allEqual(u8, bytes["unit signed library".len..], 0))
                return "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f".*;
            return null;
        }
    };
    for (0..6) |mutation| {
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        const root = try rootPath(a, work);
        try work.dir.createDirPath(io, "usr/lib/x86_64-linux-gnu");
        const setpriv = try std.fmt.allocPrint(a, "{s}/setpriv", .{root});
        const library = try std.fmt.allocPrint(a, "{s}/libcap-ng.so.0.0.0", .{root});
        const target = "usr/lib/x86_64-linux-gnu/libcap-ng.so.0";
        if (mutation != 0) {
            const payload = if (mutation == 1) "x" ** 26928 else approved;
            try work.dir.writeFile(io, .{ .sub_path = "libcap-ng.so.0.0.0", .data = payload });
            const pin = try paths.openAbsolute(library, false);
            defer pin.close();
            _ = try paths.syscall(linux.fchmod(pin.fd, if (mutation == 2) 0o666 else if (mutation == 3) 0o2644 else 0o644));
        }
        if (mutation == 4) try work.dir.writeFile(io, .{ .sub_path = target, .data = "unbound existing runtime" });
        const ctx: order.Context = .{ .a = a, .io = io, .environment = &env, .launcher = .{ .path = "", .runtime = "" }, .dpkg = "", .root = root, .cache = root, .evidence = root, .architecture = "amd64", .test_hooks = .{ .state = &env, .runtime_unprotected = true, .runtime_digest = Hook.digest } };
        if (mutation == 5) {
            const receipt = try order.stagePendingRuntime(ctx, root, setpriv);
            try expectEqualStrings(approved, try ctx.read(root, target, 26928));
            try expect(receipt.size == 26928);
            try expectEqualStrings("0644", receipt.mode);
            const installed = try paths.openAbsolute(try std.fmt.allocPrint(a, "{s}/{s}", .{ root, target }), false);
            defer installed.close();
            try expect(installed.metadata.mode & 0o7777 == 0o644);
        } else {
            try expectError(error.CycleProofRuntimeChanged, order.stagePendingRuntime(ctx, root, setpriv));
            if (mutation == 4) try expectEqualStrings("unbound existing runtime", try ctx.read(root, target, 64)) else try expect(!try paths.exists(root, target));
        }
    }
}

test "actual scheduler refuses the next child probe after exactly the original ten thousand probe budget" {
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    const names = try a.alloc([]const u8, 200);
    for (names, 0..) |*name, index| name.* = try std.fmt.allocPrint(a, "fixture-{d}", .{index});
    var state = try simple(a, names);
    state.mode = .probe_budget;
    try expectError(error.ReferenceDependencyProbeLimitExceeded, state.context(try rootPath(a, work), &env).install(&.{}));
    try expect(state.probe_count == 10000);
    try expect(state.commands.items.len > 0 and state.commands.items.len < 400);
}

test "actual independent install logs retain bytes but reject either original sixteen MiB bound" {
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    const root = try rootPath(a, work);
    const ctx: order.Context = .{ .a = a, .io = io, .environment = &env, .launcher = .{ .path = "", .runtime = "" }, .dpkg = "", .root = root, .cache = root, .evidence = root, .architecture = "amd64" };
    for ([_][]const u8{ "", " >&2" }, 0..) |destination, index| {
        const command = try std.fmt.allocPrint(a, "head -c 16777217 /dev/zero{s}", .{destination});
        const out = try std.fmt.allocPrint(a, "out-{d}", .{index});
        const err = try std.fmt.allocPrint(a, "err-{d}", .{index});
        try expectError(error.ReferenceDpkgOutputExceedsLimit, ctx.apply(&.{ "/bin/sh", "-c", command }, root, out, err));
        const log = try paths.openAbsolute(try std.fmt.allocPrint(a, "{s}/{s}", .{ root, if (index == 0) out else err }), false);
        defer log.close();
        try expect(log.metadata.size == 16777217);
    }
}

test "original no-follow database rejects symlinked ancestors" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    try work.dir.createDirPath(io, "var/lib");
    try work.dir.symLink(io, "/etc", "var/lib/dpkg", .{ .is_directory = true });
    try expectOsRefusal(paths.readRootFile(a, root, "var/lib/dpkg/passwd", 1024 * 1024));
    try work.dir.deleteFile(io, "var/lib/dpkg");
    try work.dir.createDir(io, "var/lib/dpkg", .default_dir);
    try work.dir.symLink(io, "/etc/passwd", "var/lib/dpkg/status", .{});
    try expectOsRefusal(paths.readRootFile(a, root, "var/lib/dpkg/status", 1024 * 1024));
}

test "original reference paths reject mutable ancestry and dotdot" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    const archive = try std.fmt.allocPrint(a, "{s}/archive", .{root});
    try work.dir.writeFile(io, .{ .sub_path = "archive", .data = "signed bytes" });
    try expectError(error.UnprotectedReferencePath, paths.protected(archive, false));
    try expectError(error.NoncanonicalReferencePath, paths.openAbsolute(try std.fmt.allocPrint(a, "{s}/../etc/passwd", .{root}), false));
    try expectError(error.NoncanonicalReferencePath, paths.readRootFile(a, root, "../etc/passwd", 1024));
    try work.dir.symLink(io, archive, "link", .{});
    try expectOsRefusal(paths.openAbsolute(try std.fmt.allocPrint(a, "{s}/link", .{root}), false));
}

test "original status read refuses duplicate malformed or redirected identity and accepts valueless fields" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    const ctx: order.Context = .{ .a = a, .io = io, .environment = &env, .launcher = .{ .path = "", .runtime = "" }, .dpkg = "", .root = root, .cache = root, .evidence = root, .architecture = "amd64" };
    try work.dir.createDirPath(io, "var/lib/dpkg");
    const status = "Package: demo\nArchitecture: amd64\nVersion: 1\nStatus: install ok unpacked\nDescription: fixture\n more text\n\n";
    const valueless = "Package: demo\nArchitecture: amd64\nVersion: 1\nStatus: install ok unpacked\nConffiles:\n /etc/demo.conf 0123456789abcdef\n\n";
    for ([_][]const u8{ status, valueless }) |bytes| {
        try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = bytes });
        const records = try ctx.database(root);
        try expect(records.len == 1);
        try expectStrings(&.{ "demo", "amd64", "install ok unpacked", "1" }, &.{ order.field(records[0], "package"), order.field(records[0], "architecture"), order.field(records[0], "status"), order.field(records[0], "version") });
    }
    for ([_][]const u8{ "Priority:optional", "Bad Key: x", "Conffiles" }) |malformed| {
        try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = try std.fmt.allocPrint(a, "Package: demo\nArchitecture: amd64\nVersion: 1\nStatus: install ok unpacked\n{s}\n\n", .{malformed}) });
        try expectError(error.MalformedReferenceDatabaseField, ctx.database(root));
    }
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = try replaceOne(a, status, "Package: demo", "Package: demo\npackage: other") });
    try expectError(error.DuplicateReferenceDatabaseField, ctx.database(root));
    try work.dir.deleteFile(io, "var/lib/dpkg/status");
    try work.dir.symLink(io, "/etc/passwd", "var/lib/dpkg/status", .{});
    try expectOsRefusal(ctx.database(root));
}

test "original launcher invocation stays single package and trigger verbs require a triggered script profile" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    const launcher: order.Launcher = .{ .path = try std.fmt.allocPrint(a, "{s}/launcher", .{root}), .runtime = try std.fmt.allocPrint(a, "{s}/runtime", .{root}) };
    const dpkg = try std.fmt.allocPrint(a, "{s}/dpkg", .{root});
    const target = try std.fmt.allocPrint(a, "{s}/root", .{root});
    const demo: order.Package = .{ .name = "demo", .version = "1", .architecture = "amd64", .digest = "a" ** 128, .size = 42, .archive = try std.fmt.allocPrint(a, "{s}/package.deb", .{root}) };
    const command = try order.dpkgCommand(a, launcher, dpkg, target, "amd64", "none", "unpack", demo, &.{});
    try expectStrings(&.{ "amd64", "none", "unpack", "demo:amd64" }, command[3..7]);
    try expectEqualStrings(launcher.runtime, command[7]);
    try expectStrings(&.{ demo.archive, demo.digest, "42" }, command[8..]);
    for (command) |argument| try expect(!eq(u8, argument, "--pending"));
    const sudo: order.Package = .{ .name = "sudo", .version = "1.9.17p2-1ubuntu3.1", .architecture = "amd64", .digest = "a" ** 128, .size = 42, .archive = try std.fmt.allocPrint(a, "{s}/sudo.deb", .{root}) };
    try expectStrings(&.{ "amd64", "sudo", "configure", "sudo:amd64" }, (try order.dpkgCommand(a, launcher, dpkg, target, "amd64", "sudo", "configure", sudo, &.{}))[3..7]);
    for ([_][]const u8{ "sudo", "none" }) |profile|
        try expectError(error.NoSingleScriptBinding, order.dpkgCommand(a, launcher, dpkg, target, "amd64", profile, "triggers_only", sudo, &.{}));
    try expectError(error.NoSingleScriptBinding, order.dpkgCommand(a, launcher, dpkg, target, "amd64", "sudo", "triggers_pending", sudo, &.{}));
    try expectError(error.SignedPackageRequired, order.dpkgCommand(a, launcher, dpkg, target, "amd64", "none", "configure", null, &.{}));
    try expectError(error.MissingExactConfigureProfile, order.dpkgCommand(a, launcher, dpkg, target, "amd64", "none", "configure", sudo, &.{}));
    for ([_][3][]const u8{ .{ "sudo", "different", "amd64" }, .{ "sudo", sudo.version, "all" }, .{ "not-sudo", sudo.version, "amd64" } }) |identity| {
        var changed = sudo;
        changed.name = identity[0];
        changed.version = identity[1];
        changed.architecture = identity[2];
        try expectError(error.UnauthorizedReferenceScriptProfile, order.dpkgCommand(a, launcher, dpkg, target, "amd64", "sudo", "configure", changed, &.{}));
    }
    try expectError(error.UnauthorizedReferenceScriptProfile, order.dpkgCommand(a, launcher, dpkg, target, "amd64", "sudo", "probe_configure", sudo, &.{}));
    try expectError(error.UnauthorizedReferenceScriptProfile, order.dpkgCommand(a, launcher, dpkg, target, "arm64", "sudo", "configure", sudo, &.{}));
}

test "original kbd base and OpenSSL cycle operations refuse each changed architecture profile selector and archive set" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try rootPath(a, work);
    const launcher: order.Launcher = .{ .path = try std.fmt.allocPrint(a, "{s}/launcher", .{root}), .runtime = try std.fmt.allocPrint(a, "{s}/runtime", .{root}) };
    const dpkg = try std.fmt.allocPrint(a, "{s}/dpkg", .{root});
    var kbd_work = std.testing.tmpDir(.{ .iterate = true });
    defer kbd_work.cleanup();
    var base_work = std.testing.tmpDir(.{ .iterate = true });
    defer base_work.cleanup();
    var openssl_work = std.testing.tmpDir(.{ .iterate = true });
    defer openssl_work.cleanup();
    const kbd = (try fixture(a, kbd_work.dir, .kbd)).packages;
    const base = (try fixture(a, base_work.dir, .base)).packages;
    const ssl = (try fixture(a, openssl_work.dir, .openssl)).packages;
    const Change = struct { []const u8, []const u8, order.Package, []const order.Package };

    try expectStrings(&.{ "amd64", "kbd_cycle", "break_kbd_cycle", "kbd:amd64" }, (try order.dpkgCommand(a, launcher, dpkg, root, "amd64", "kbd_cycle", "break_kbd_cycle", kbd[0], kbd))[3..7]);
    const kbd_reordered = [_]order.Package{ kbd[0], kbd[2], kbd[1], kbd[3] };
    for ([_]Change{
        .{ "arm64", "kbd_cycle", kbd[0], kbd },
        .{ "amd64", "none", kbd[0], kbd },
        .{ "amd64", "kbd_cycle", kbd[1], kbd },
        .{ "amd64", "kbd_cycle", kbd[0], kbd[0..3] },
        .{ "amd64", "kbd_cycle", kbd[0], &kbd_reordered },
    }) |changed| try expectCycleRefusal(order.dpkgCommand(a, launcher, dpkg, root, changed[0], changed[1], "break_kbd_cycle", changed[2], changed[3]));
    const kbd_changed = try a.dupe(order.Package, kbd);
    kbd_changed[0].digest = "0" ** 128;
    try expectError(error.CycleIdentityChanged, order.cyclePackages(a, kbd_changed, "amd64", .kbd));

    const base_command = try order.dpkgCommand(a, launcher, dpkg, root, "amd64", "libgcc_cycle", "break_base_cycle", base[1], base);
    try expectStrings(&.{ "amd64", "libgcc_cycle", "break_base_cycle", "libgcc-s1:amd64" }, base_command[3..7]);
    var base_archives: [4][]const u8 = undefined;
    for (base, &base_archives) |package, *archive| archive.* = package.archive;
    try expectStrings(&base_archives, base_command[8..]);
    for ([_]Change{
        .{ "arm64", "libgcc_cycle", base[1], base },
        .{ "amd64", "none", base[1], base },
        .{ "amd64", "libgcc_cycle", base[0], base },
        .{ "amd64", "libgcc_cycle", base[1], base[0..2] },
    }) |changed| try expectCycleRefusal(order.dpkgCommand(a, launcher, dpkg, root, changed[0], changed[1], "break_base_cycle", changed[2], changed[3]));
    try expectError(error.CycleIdentityChanged, order.cyclePackages(a, base[0 .. base.len - 1], "amd64", .base));

    try expectStrings(&.{ "amd64", "openssl_cycle", "configure_openssl_cycle", "libssl3t64:amd64" }, (try order.dpkgCommand(a, launcher, dpkg, root, "amd64", "openssl_cycle", "configure_openssl_cycle", ssl[0], ssl))[3..7]);
    const ssl_rotated = [_]order.Package{ ssl[1], ssl[2], ssl[3], ssl[4], ssl[0] };
    for ([_]Change{
        .{ "arm64", "openssl_cycle", ssl[0], ssl },
        .{ "amd64", "none", ssl[0], ssl },
        .{ "amd64", "sudo", ssl[0], ssl },
        .{ "amd64", "openssl_cycle", ssl[1], ssl },
        .{ "amd64", "openssl_cycle", ssl[0], ssl[0..2] },
        .{ "amd64", "openssl_cycle", ssl[0], &ssl_rotated },
    }) |changed| try expectCycleRefusal(order.dpkgCommand(a, launcher, dpkg, root, changed[0], changed[1], "configure_openssl_cycle", changed[2], changed[3]));
    const ssl_changed = try a.dupe(order.Package, ssl);
    ssl_changed[0].digest = "0" ** 128;
    try expectError(error.CycleIdentityChanged, order.cyclePackages(a, ssl_changed, "amd64", .openssl));
}

test "original kbd cycle refuses changed peers outside libc callbacks and pending activation before apply" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var state = try fixture(a, work.dir, .kbd);
    const root = try rootPath(a, work);
    const ctx = state.context(root, &env);
    _ = try ctx.verifyCycle(root, state.packages, .kbd);
    for ([_][3][]const u8{
        .{ "kbd", "depends", "unknown" },
        .{ "kbd", "triggers-pending", "update-initramfs" },
        .{ "console-setup-linux", "multi-arch", "same" },
        .{ "console-setup", "pre-depends", "" },
        .{ "console-setup", "status", "install ok installed" },
        .{ "libc6", "status", "install ok unpacked" },
    }) |change| {
        const record = try state.row(change[0]);
        const saved = try record.clone(a);
        try record.put(a, change[1], .{ .string = change[2] });
        try expectCycleRefusal(ctx.transition(root, root, state.packages, .kbd, "out", "err"));
        record.* = saved;
    }
    for ([_][]const u8{ "kbd.postinst", "kbd:amd64.config", "kbd:amd64.triggers" }) |name| {
        const path = try std.fmt.allocPrint(a, "var/lib/dpkg/info/{s}", .{name});
        try work.dir.symLink(io, "/missing-unreviewed-callback", path, .{});
        try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, .kbd));
        try work.dir.deleteFile(io, path);
    }
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/kbd.triggers", .data = "activate update-initramfs\n" });
    try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, .kbd));
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/kbd.triggers", .data = order.kbd_triggers });
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/triggers/Unincorp", .data = "update-initramfs kbd\n" });
    try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, .kbd));
    try expect(state.commands.items.len == 0);
}

test "original kbd success requires only its one real transition and unchanged trigger database" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var state = try fixture(a, work.dir, .kbd);
    const root = try rootPath(a, work);
    const ctx = state.context(root, &env);
    const saved = try state.clone(state.records);
    const selected = try ctx.transition(root, root, state.packages, .kbd, "out", "err");
    try expect(selected.len == 1 and samePackage(selected[0], state.packages[0]));
    try expect(state.commands.items.len == 1);
    try expectStrings(&.{ "break_kbd_cycle", "kbd:amd64" }, state.commands.items[0][5..7]);
    state.records = try state.clone(saved);
    state.extra_transition = "console-setup-linux";
    try expectError(error.CycleNoProgress, ctx.transition(root, root, state.packages, .kbd, "out", "err"));
    state.records = try state.clone(saved);
    state.extra_transition = null;
    state.mutate_trigger = work.dir;
    state.trigger_name = "unexpected";
    state.trigger_bytes = "";
    try expectError(error.CycleNoProgress, ctx.transition(root, root, state.packages, .kbd, "out", "err"));
}

test "original signed base cycle graph and callback mutations refuse with their exact original reasons before apply" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var state = try fixture(a, work.dir, .base);
    const root = try rootPath(a, work);
    const ctx = state.context(root, &env);
    _ = try ctx.verifyCycle(root, state.packages, .base);
    for ([_]struct { []const u8, []const u8, []const u8, anyerror }{
        .{ "libc6", "depends", "another-package", error.CycleControlChanged },
        .{ "libgcc-s1", "pre-depends", "libc6", error.CycleControlChanged },
        .{ "gcc-16-base", "status", "install ok unpacked", error.CycleOutsideDependency },
        .{ "gcc-16-base", "multi-arch", "foreign", error.CycleControlChanged },
        .{ "libc-gconv-modules-extra", "multi-arch", "", error.CycleControlChanged },
        .{ "libgcc-s1", "status", "install ok triggers-pending", error.CycleStateChanged },
        .{ "libgcc-s1", "triggers-pending", "ldconfig", error.CycleCallbackChanged },
    }) |change| {
        const record = try state.row(change[0]);
        const saved = try record.clone(a);
        try record.put(a, change[1], .{ .string = change[2] });
        try expectError(change[3], ctx.transition(root, root, state.packages, .base, "out", "err"));
        record.* = saved;
    }
    for ([_][]const u8{ "libgcc-s1.postinst", "libgcc-s1:amd64.postinst" }) |name| {
        const path = try std.fmt.allocPrint(a, "var/lib/dpkg/info/{s}", .{name});
        try work.dir.symLink(io, "/does-not-exist", path, .{});
        try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, .base));
        try work.dir.deleteFile(io, path);
    }
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/libgcc-s1:amd64.triggers", .data = "activate-noawait another-handler\n" });
    try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, .base));
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/libgcc-s1:amd64.triggers", .data = order.libgcc_triggers });
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/updates/0000", .data = "unincorporated state\n" });
    try expectError(error.CycleStateChanged, ctx.verifyCycle(root, state.packages, .base));
    try work.dir.deleteFile(io, "var/lib/dpkg/updates/0000");
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/triggers/Unincorp", .data = "ldconfig libc-bin\n" });
    try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, .base));
    try expect(state.commands.items.len == 0);
}

test "original base cycle transition requires exact progress not only successful exit" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var state = try fixture(a, work.dir, .base);
    const root = try rootPath(a, work);
    const ctx = state.context(root, &env);
    const saved = try state.clone(state.records);
    const selected = try ctx.transition(root, root, state.packages, .base, "out", "err");
    try expect(selected.len == 1 and samePackage(selected[0], state.packages[1]));
    try expect(state.commands.items.len == 1);
    try expectEqualStrings("break_base_cycle", state.commands.items[0][5]);
    try expect((try evidenceJson(a, root, "base-cycle-after.json")).object.get("callbacks").?.array.items.len == 0);
    state.records = try state.clone(saved);
    state.extra_transition = "libc6";
    try expectError(error.CycleNoProgress, ctx.transition(root, root, state.packages, .base, "out", "err"));
}

test "original OpenSSL cycle refuses graph callbacks triggers and outside state with exact reasons before apply" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var state = try fixture(a, work.dir, .openssl);
    const root = try rootPath(a, work);
    const ctx = state.context(root, &env);
    const verified = try ctx.verifyCycle(root, state.packages, .openssl);
    try expectEqualStrings("same", order.field(verified.graph.get("libssl3t64").?.object, "multi_arch"));
    try expectEqualStrings("foreign", order.field(verified.graph.get("openssl-provider-legacy").?.object, "multi_arch"));
    for ([_]struct { []const u8, []const u8, []const u8, anyerror }{
        .{ "libssl3t64", "depends", "unknown-package", error.CycleControlChanged },
        .{ "openssl-provider-legacy", "pre-depends", "libssl3t64", error.CycleControlChanged },
        .{ "libc6", "status", "install ok unpacked", error.CycleOutsideDependency },
        .{ "libzstd1", "version", "other", error.CycleStateChanged },
        .{ "zlib1g", "conflicts", "", error.CycleControlChanged },
        .{ "openssl-provider-legacy", "multi-arch", "same", error.CycleControlChanged },
        .{ "libssl3t64", "triggers-pending", "ldconfig", error.CycleCallbackChanged },
        .{ "openssl-provider-legacy", "config-version", "other", error.CycleCallbackChanged },
    }) |change| {
        const record = try state.row(change[0]);
        const saved = try record.clone(a);
        try record.put(a, change[1], .{ .string = change[2] });
        try expectError(change[3], ctx.transition(root, root, state.packages, .openssl, "out", "err"));
        record.* = saved;
    }
    for ([_][]const u8{ "libssl3t64.postinst", "libssl3t64:amd64.postinst", "openssl-provider-legacy.postinst", "openssl-provider-legacy:amd64.config", "openssl-provider-legacy:amd64.triggers" }) |name| {
        const path = try std.fmt.allocPrint(a, "var/lib/dpkg/info/{s}", .{name});
        try work.dir.symLink(io, "/does-not-exist", path, .{});
        try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, .openssl));
        try work.dir.deleteFile(io, path);
    }
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/libssl3t64:amd64.triggers", .data = "activate ldconfig\n" });
    try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, .openssl));
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/libssl3t64:amd64.triggers", .data = order.libgcc_triggers });
    const members = try a.alloc(order.Member, state.controls[1].len + 1);
    members[0] = .{ .name = "./postinst", .bytes = "callbac", .kind = '0' };
    @memcpy(members[1..], state.controls[1]);
    state.controls[1] = members;
    try expectError(error.CycleCallbackChanged, ctx.verifyCycle(root, state.packages, .openssl));
    try expect(state.commands.items.len == 0);
}

test "original OpenSSL transition requires both exact refusals and exact two package progress" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var state = try fixture(a, work.dir, .openssl);
    const root = try rootPath(a, work);
    const ctx = state.context(root, &env);
    const saved = try state.clone(state.records);
    const selected = try ctx.transition(root, root, state.packages, .openssl, "out", "err");
    try expect(selected.len == 2 and samePackage(selected[0], state.packages[0]) and samePackage(selected[1], state.packages[1]));
    const after = try evidenceJson(a, root, "openssl-cycle-after.json");
    try expect(after.object.get("callbacks").?.array.items.len == 0 and after.object.get("force").?.array.items.len == 0);
    for ([_][]const u8{ "libssl3t64", "openssl-provider-legacy", "libc6" }) |name| {
        state.records = try state.clone(saved);
        state.after_status = .{ name, "install ok half-configured" };
        try expectError(error.CycleNoProgress, ctx.transition(root, root, state.packages, .openssl, "out", "err"));
    }
    state.after_status = null;
    state.records = try state.clone(saved);
    state.mutate_trigger = work.dir;
    state.trigger_name = "ldconfig";
    state.trigger_bytes = "";
    try expectError(error.CycleNoProgress, ctx.transition(root, root, state.packages, .openssl, "out", "err"));
    state.mutate_trigger = null;
    try work.dir.deleteFile(io, "var/lib/dpkg/triggers/ldconfig");
    state.records = try state.clone(saved);
    state.commands.clearRetainingCapacity();
    for ([_]struct { []const u8, i32, []const u8 }{
        .{ "libssl3t64:amd64", 0, "" },
        .{ "libssl3t64:amd64", 1, "dependency problems: Package unknown-package is not configured yet." },
        .{ "libssl3t64:amd64", 1, "dependency problems: Package openssl-provider-legacy:amd64 is not configured yet." },
        .{ "openssl-provider-legacy:amd64", 1, "dependency problems: Package libssl3t64 is not configured yet." },
        .{ "openssl-provider-legacy:amd64", 1, "dependency problems: Package unknown-package:amd64 is not configured yet." },
    }) |response| {
        state.probe_override = .{ .selector = response[0], .result = .{ .code = response[1], .stdout = response[2], .stderr = "" } };
        try expectError(error.CycleProbeChanged, ctx.transition(root, root, state.packages, .openssl, "out", "err"));
    }
    try expect(state.commands.items.len == 0);
}

test "original three target capture continues only exact half-configured systemd and udev" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    for ([_][]const u8{ "half-configured", "unpacked", "installed" }) |captured_status| {
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        const root = try rootPath(a, work);
        var state = try simple(a, &.{ "sudo-rs", "systemd", "udev", "sudo" });
        state.captured_status = captured_status;
        var targets: [3]order.Prestate = undefined;
        for ([_][]const u8{ "systemd", "udev", "sudo" }, &targets) |name, *target|
            target.* = .{ .selector = try std.fmt.allocPrint(a, "{s}:amd64", .{name}), .status = if (eq(u8, name, "sudo")) "unpacked" else "half-configured", .destination = try std.fmt.allocPrint(a, "{s}/saved-{s}", .{ root, name }) };
        const ctx = state.context(root, &env);
        if (!eq(u8, captured_status, "half-configured")) {
            try expectError(error.CapturedPrestateStateVersionChanged, ctx.install(&targets));
            try expect((try selectedCommands(a, state, "continue_prestate")).len == 0);
            continue;
        }
        try ctx.install(&targets);
        try expectStrings(&.{ "systemd:amd64", "udev:amd64" }, try selectedCommands(a, state, "continue_prestate"));
        for (state.commands.items) |command| {
            if (eq(u8, command[5], "unpack")) continue;
            if (eq(u8, command[6], "sudo-rs:amd64")) {
                try expectStrings(&.{ "none", "configure" }, command[4..6]);
            } else {
                try expectEqualStrings("continue_prestate", command[5]);
                try expect(eq(u8, command[6], "systemd:amd64") or eq(u8, command[6], "udev:amd64"));
                try expectEqualStrings(command[6][0..std.mem.indexOfScalar(u8, command[6], ':').?], command[4]);
            }
        }
        for ([_][2][]const u8{ .{ "systemd", "install ok half-configured" }, .{ "udev", "install ok half-configured" }, .{ "sudo", "install ok unpacked" } }) |expected| {
            const selector = try std.fmt.allocPrint(a, "{s}:amd64", .{expected[0]});
            const index = for (state.captures.items, 0..) |capture, i| {
                if (eq(u8, capture.selector, selector)) break i;
            } else return error.MissingOriginalCapture;
            const snapshot = for (state.capture_states.items[index]) |record| {
                if (eq(u8, order.field(record, "package"), expected[0])) break record;
            } else return error.MissingOriginalCaptureRecord;
            try expectEqualStrings(expected[1], order.field(snapshot, "status"));
        }
        try expectEqualStrings("install ok unpacked", order.field((try state.row("sudo")).*, "status"));
    }
}

test "original OpenSSL cycle resumes single package capture and never repeats authority" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var state = try fixture(a, work.dir, .openssl);
    var base_work = std.testing.tmpDir(.{ .iterate = true });
    defer base_work.cleanup();
    const base = try fixture(a, base_work.dir, .base);
    var package_list: std.ArrayList(order.Package) = .empty;
    var record_list: std.ArrayList(order.Fields) = .empty;
    try package_list.appendSlice(a, state.packages);
    try record_list.appendSlice(a, state.records);
    for (base.packages, base.records) |package, record| if (!eq(u8, package.name, "libc6")) {
        try package_list.append(a, package);
        try record_list.append(a, record);
    };
    const target = try simple(a, &.{"systemd"});
    try package_list.appendSlice(a, target.packages);
    try record_list.appendSlice(a, target.records);
    state.packages = try package_list.toOwnedSlice(a);
    state.records = try record_list.toOwnedSlice(a);
    state.mode = .resume_cycles;
    state.constant_unpacked = true;
    const root = try rootPath(a, work);
    var ctx = state.context(root, &env);
    ctx.test_hooks.?.transition = State.transition;
    try ctx.install(&.{.{ .selector = "systemd:amd64", .status = "half-configured", .destination = try std.fmt.allocPrint(a, "{s}/saved", .{root}) }});
    try expect(state.cycle_calls[0] == 1 and state.cycle_calls[1] == 1 and state.captures.items.len == 1);
    for (try selectedCommands(a, state, "configure")) |selector| try expect(!eq(u8, selector, "systemd:amd64"));
    state.cycle_calls = @splat(0);
    state.phase = 0;
    state.mode = .stall;
    try expectError(error.CycleNoProgress, ctx.install(&.{}));
    try expect(state.cycle_calls[0] == 1 and state.cycle_calls[1] == 1);
    const evidence = (try evidenceJson(a, root, "reference-no-progress.json")).object;
    try expect(evidence.get("base_cycle_applied").?.bool and evidence.get("openssl_cycle_applied").?.bool);
    for (evidence.get("deferred").?.array.items) |deferred| {
        if (eq(u8, deferred.string, "systemd:amd64")) break;
    } else return error.MissingOriginalDeferredTarget;
    try expectEqualStrings("dependency problems", try decodePrefix(a, evidence.get("refusals").?.array.items[0].object.get("output_prefix_hex").?.string));
}

test "original base cycle break retries normal schedule without configuring prestate target" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var state = try fixture(a, work.dir, .base);
    const target = try simple(a, &.{"systemd"});
    state.packages = try std.mem.concat(a, order.Package, &.{ state.packages, target.packages });
    state.records = try std.mem.concat(a, order.Fields, &.{ state.records, target.records });
    state.mode = .bridge;
    state.constant_unpacked = true;
    const root = try rootPath(a, work);
    var ctx = state.context(root, &env);
    ctx.test_hooks.?.transition = State.transition;
    try ctx.install(&.{.{ .selector = "systemd:amd64", .status = "half-configured", .destination = try std.fmt.allocPrint(a, "{s}/saved", .{root}) }});
    try expect(state.cycle_calls[0] == 1 and state.captures.items.len == 1);
    const configured = try selectedCommands(a, state, "configure");
    for (configured) |selector| try expect(!eq(u8, selector, "libgcc-s1:amd64") and !eq(u8, selector, "systemd:amd64"));
    for (configured) |selector| {
        if (eq(u8, selector, "libc6:amd64")) break;
    } else return error.MissingOriginalBridgeConfigure;
}

const oracle_postinst = "#!/bin/sh\nexit 0\n";
const Oracle = struct {
    a: A,
    base: State,
    image: []const u8,
    library: []const u8,
    stderr: []const u8,
    returncode: i32,
    configured: bool,
    probes: usize = 0,
    overrides: std.ArrayList([3][]const u8) = .empty,
    fn get(pointer: *anyopaque) *Oracle {
        return @ptrCast(@alignCast(pointer));
    }
    fn manifest(pointer: *anyopaque) ![]order.Package {
        return get(pointer).base.packages;
    }
    fn database(pointer: *anyopaque, root: []const u8) ![]order.Fields {
        const self = get(pointer);
        if (eq(u8, root, self.image)) return self.a.alloc(order.Fields, 0);
        const result = try self.base.clone(self.base.records);
        for (self.overrides.items) |override| if (eq(u8, override[0], std.fs.path.basename(root))) for (result) |*record| {
            if (eq(u8, order.field(record.*, "package"), override[1])) try record.put(self.a, "status", .{ .string = override[2] });
        };
        return result;
    }
    fn probe(pointer: *anyopaque, _: []const []const u8) !order.Result {
        const self = get(pointer);
        self.probes += 1;
        return switch (self.probes) {
            1, 2 => .{ .code = 1, .stdout = "dependency problems", .stderr = "" },
            3 => .{ .code = 1, .stdout = "stage 11", .stderr = "" },
            else => error.UnexpectedOriginalOracleProbe,
        };
    }
    fn apply(_: *anyopaque, _: []const []const u8) !void {}
    fn control(pointer: *anyopaque, selected: order.Package) ![]order.Member {
        const self = get(pointer);
        const members = try State.control(&self.base, selected);
        if (!eq(u8, selected.name, "libc6")) return members;
        const result = try self.a.alloc(order.Member, members.len + 1);
        @memcpy(result[0..members.len], members);
        result[members.len] = .{ .name = "./postinst", .bytes = oracle_postinst, .kind = '0' };
        return result;
    }
    fn transition(pointer: *anyopaque, kind: order.Cycle) ![]order.Package {
        const self = get(pointer);
        try expect(kind == .base);
        try self.overrides.append(self.a, .{ "candidate", "libgcc-s1", "install ok installed" });
        return self.base.packages[1..2];
    }
    fn run(pointer: *anyopaque, command: []const []const u8) !?order.Result {
        const self = get(pointer);
        for ([_][]const u8{ "cp", "rm", "chmod" }) |actual| if (eq(u8, command[0], actual)) return null;
        if (eq(u8, command[0], "mount") or eq(u8, command[0], "umount")) return .{ .code = 0, .stdout = "", .stderr = "" };
        try expectEqualStrings("unshare", command[0]);
        try expectStrings(&.{ "--no-triggers", "--configure", "--pending" }, command[command.len - 3 ..]);
        const baseline = for (command[0 .. command.len - 1], 0..) |argument, index| {
            if (eq(u8, argument, "chroot")) break command[index + 1];
        } else return error.MissingOriginalOracleChroot;
        if (self.configured) {
            const relative = "usr/lib/x86_64-linux-gnu/libcap-ng.so.0";
            try expectEqualStrings(self.library, try paths.readRootFile(self.a, baseline, relative, 26928));
            try expect(!try paths.exists(self.image, relative));
            try expect(!try paths.exists(try std.fmt.allocPrint(self.a, "{s}/candidate", .{std.fs.path.dirname(baseline).?}), relative));
            try self.overrides.append(self.a, .{ "pending", "libgcc-s1", "install ok installed" });
            try self.overrides.append(self.a, .{ "pending", "libc6", "install ok half-configured" });
        }
        return .{ .code = self.returncode, .stdout = "pending stdout witness", .stderr = self.stderr };
    }
    fn digest(bytes: []const u8) ?[64]u8 {
        if (bytes.len == 26928 and std.mem.startsWith(u8, bytes, "unit signed libcap-ng") and std.mem.allEqual(u8, bytes["unit signed libcap-ng".len..], 0))
            return "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f".*;
        if (eq(u8, bytes, "unit signed setpriv")) return "86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993".*;
        return null;
    }
};
fn pendingOracle(a: A, work: std.testing.TmpDir, stderr: []const u8, returncode: i32, configured: bool) !void {
    const root = try rootPath(a, work);
    try work.dir.createDir(io, "image", .default_dir);
    var image_dir = try work.dir.openDir(io, "image", .{});
    defer image_dir.close(io);
    const base = try fixture(a, image_dir, .base);
    try work.dir.createDirPath(io, "image/usr/bin");
    try work.dir.createDirPath(io, "image/usr/lib/x86_64-linux-gnu");
    try work.dir.writeFile(io, .{ .sub_path = "image/var/lib/dpkg/info/libc6:amd64.postinst", .data = oracle_postinst });
    try work.dir.createDir(io, "evidence", .default_dir);
    try work.dir.createDir(io, "tools", .default_dir);
    try work.dir.writeFile(io, .{ .sub_path = "tools/dpkg", .data = "unit dpkg" });
    try work.dir.writeFile(io, .{ .sub_path = "tools/setpriv", .data = "unit signed setpriv" });
    const library = try a.alloc(u8, 26928);
    @memset(library, 0);
    @memcpy(library[0.."unit signed libcap-ng".len], "unit signed libcap-ng");
    try work.dir.writeFile(io, .{ .sub_path = "tools/libcap-ng.so.0.0.0", .data = library });
    const tools = try std.fmt.allocPrint(a, "{s}/tools", .{root});
    {
        const pin = try paths.openAbsolute(try std.fmt.allocPrint(a, "{s}/libcap-ng.so.0.0.0", .{tools}), false);
        defer pin.close();
        _ = try paths.syscall(linux.fchmod(pin.fd, 0o644));
    }
    const image = try std.fmt.allocPrint(a, "{s}/image", .{root});
    var oracle: Oracle = .{ .a = a, .base = base, .image = image, .library = library, .stderr = stderr, .returncode = returncode, .configured = configured };
    var env: std.process.Environ.Map = .init(a);
    try env.put("PATH", "/usr/bin:/bin");
    const ctx: order.Context = .{
        .a = a,
        .io = io,
        .environment = &env,
        .launcher = .{ .path = try std.fmt.allocPrint(a, "{s}/launcher", .{tools}), .runtime = try std.fmt.allocPrint(a, "{s}/runtime", .{tools}) },
        .dpkg = try std.fmt.allocPrint(a, "{s}/dpkg", .{tools}),
        .root = image,
        .cache = tools,
        .evidence = try std.fmt.allocPrint(a, "{s}/evidence", .{root}),
        .architecture = "amd64",
        .test_hooks = .{ .state = &oracle, .manifest = Oracle.manifest, .database = Oracle.database, .probe = Oracle.probe, .apply = Oracle.apply, .archive = State.archive, .control = Oracle.control, .transition = Oracle.transition, .run = Oracle.run, .runtime_unprotected = true, .runtime_digest = Oracle.digest, .assume_x86_64 = true },
    };
    return order.proveBaseCycle(ctx, try std.fmt.allocPrint(a, "{s}/setpriv", .{tools}));
}

test "original pending oracle stages helper runtime without registering or widening candidate" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    try pendingOracle(a, work, "post-installation script: Permission denied", 1, true);
    const comparison = (try evidenceJson(a, try rootPath(a, work), "evidence/base-cycle-proof/comparison.json")).object;
    try expect(comparison.get("pending").?.array.items.len == 4);
    try expect(!comparison.get("parity_claim").?.bool);
    try expect(comparison.get("callbacks_executed").?.array.items.len == 0);
    try expect(comparison.get("pending_setpriv_runtime").?.object.get("size").?.integer == 26928);
}

test "original pending loader refusal retains evidence but never counts as callback denial" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const stderr = "setpriv: error while loading shared libraries: libcap-ng.so.0: cannot open shared object file: No such file or directory\n";
    try expectError(error.CycleProofCallbackChanged, pendingOracle(a, work, stderr, 127, false));
    const proof = try std.fmt.allocPrint(a, "{s}/evidence/base-cycle-proof", .{try rootPath(a, work)});
    try expectEqualStrings(stderr, try paths.readRootFile(a, proof, "pending.stderr", 65536));
    try expectEqualStrings("pending stdout witness", try paths.readRootFile(a, proof, "pending.stdout", 65536));
    const result = (try evidenceJson(a, proof, "pending-result.json")).object;
    try expect(result.get("returncode").?.integer == 127 and !result.get("output_truncated").?.bool);
    const status = (try evidenceJson(a, proof, "pending-status.json")).object;
    try expectEqualStrings(try std.json.Stringify.valueAlloc(a, status.get("before").?, .{}), try std.json.Stringify.valueAlloc(a, status.get("after").?, .{}));
    try expect(!try paths.exists(proof, "comparison.json"));
}

test "original pending oversized output is retained bounded and still refuses" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const stderr = try std.fmt.allocPrint(a, "post-installation script: Permission denied\n{s}", .{"x" ** 65536});
    try expectError(error.CycleProofCallbackChanged, pendingOracle(a, work, stderr, 1, true));
    const proof = try std.fmt.allocPrint(a, "{s}/evidence/base-cycle-proof", .{try rootPath(a, work)});
    try expectEqualStrings(stderr[0..65536], try paths.readRootFile(a, proof, "pending.stderr", 65536));
    const result = (try evidenceJson(a, proof, "pending-result.json")).object;
    try expect(result.get("output_truncated").?.bool and result.get("stderr_bytes").?.integer == stderr.len);
    try expect(!try paths.exists(proof, "comparison.json"));
}

const std = @import("std");
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

pub const name = "statoverride-lifecycle";
pub const base = "usr/share/" ++ name;
pub const literal = "etc/stato\\literal";
pub const passwd = "root:x:0:0:root:/root:/bin/sh\n_debzstat:x:42420:42421:fixture:/:/bin/sh\n";
pub const group = "root:x:0:\n_debzstat:x:42421:\n";
const hook =
    \\if [ "$DPKG_MAINTSCRIPT_NAME" = preinst ]; then
    \\    if [ -f /statoverride-passwd-replace ]; then
    \\        /stato-mv /statoverride-passwd-replace /etc/passwd || exit 26
    \\    fi
    \\    if [ -f /statoverride-preinst-replace ]; then
    \\        /stato-mv /statoverride-preinst-replace /var/lib/dpkg/statoverride || exit 27
    \\    fi
    \\fi
    \\if [ "$DPKG_MAINTSCRIPT_NAME" = postinst ] && [ "$1" = configure ] && [ -f /statoverride-postinst-replace ]; then
    \\    /stato-mv /statoverride-postinst-replace /var/lib/dpkg/statoverride || exit 28
    \\fi
    \\
;

pub fn archive(fixture: *foundation.Fixture, arch: []const u8, version: []const u8) ![]u8 {
    return archiveAt(fixture, arch, version, "packages/statoverride");
}

pub fn archiveAt(fixture: *foundation.Fixture, arch: []const u8, version: []const u8, workspace: []const u8) ![]u8 {
    const content = try std.fmt.allocPrint(fixture.allocator, "configuration {s}\n", .{version});
    defer fixture.allocator.free(content);
    const extra = try std.fmt.allocPrint(fixture.allocator, "literal version {s}\n", .{version});
    defer fixture.allocator.free(extra);
    return support.makePackage(fixture, arch, version, name, workspace, .{
        .full_payload = true,
        .conffile_content = content,
        .extra_files = &.{.{ .path = literal, .content = extra }},
        .scripts = .{ .before_failure = hook },
    });
}

pub fn both(case: *support.Scenario, relative: []const u8, content: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const location = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, relative });
        defer case.fixture.allocator.free(location);
        try support.fixtureFile(case.fixture, location, content, 0o644);
    }
}

pub fn seed(case: *support.Scenario, records: []const u8) !void {
    try both(case, "etc/passwd", passwd);
    try both(case, "etc/group", group);
    try both(case, "var/lib/dpkg/statoverride", records);
}

const Expected = struct { mode: u32, uid: u32, gid: u32 };

fn expectMetadata(case: *support.Scenario, target: []const u8, expected: Expected) !void {
    for ([_][]const u8{ case.reference_root, case.native_root }) |path| {
        var dir = try foundation.guardedRoot(case.fixture.io, path);
        defer dir.close(case.fixture.io);
        const root: root_fs.Root = .init(case.fixture.io, dir);
        const entry = try root.entry(try root_fs.Path.initPackage(target));
        if (entry.mode != expected.mode or entry.uid != expected.uid or entry.gid != expected.gid)
            return error.WrongStatoverrideMetadata;
        const data = try root.entry(try root_fs.Path.init(base ++ "/data"));
        const link = try root.entry(try root_fs.Path.init(base ++ "/data.link"));
        if (data.inode != link.inode or data.device != link.device) return error.BrokenPayloadHardlink;
    }
}

pub fn replace(case: *support.Scenario, marker: []const u8, content: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const root = try support.path(case.fixture.allocator, case.name, side);
        defer case.fixture.allocator.free(root);
        try support.copyProgram(case.fixture, root, "/bin/mv", "/stato-mv");
    }
    try both(case, marker, content);
}

fn installAlias(case: *support.Scenario, record: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const root_path = try support.path(case.fixture.allocator, case.name, side);
        defer case.fixture.allocator.free(root_path);
        const usr = try support.path(case.fixture.allocator, root_path, "usr");
        defer case.fixture.allocator.free(usr);
        try case.fixture.directory(usr);
        const old = try support.path(case.fixture.allocator, root_path, "bin");
        defer case.fixture.allocator.free(old);
        const moved = try support.path(case.fixture.allocator, root_path, "usr/bin");
        defer case.fixture.allocator.free(moved);
        try case.fixture.dir.rename(old, case.fixture.dir, moved, case.fixture.io);
        try case.fixture.dir.symLink(case.fixture.io, "usr/bin", old, .{});
        var root = try foundation.guardedRoot(case.fixture.io, if (std.mem.eql(u8, side, "reference")) case.reference_root else case.native_root);
        defer root.close(case.fixture.io);
        try (root_fs.Root.init(case.fixture.io, root)).applyMetadata(try root_fs.Path.init("bin"), .{
            .modified_nanoseconds = foundation.epoch * std.time.ns_per_s,
        });
    }
    try seed(case, record);
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first = try archive(fixture, arch, "1");
    defer fixture.allocator.free(first);
    const second = try archive(fixture, arch, "2");
    defer fixture.allocator.free(second);
    const chosen = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};

    const table = [_]struct {
        label: []const u8,
        records: []const u8,
        path: []const u8,
        expected: Expected,
        existing: bool = false,
    }{
        .{ .label = "numeric", .records = "#42420 #42421 4750 /" ++ base ++ "/mode\n", .path = base ++ "/mode", .expected = .{ .mode = 0o4750, .uid = 42420, .gid = 42421 } },
        .{ .label = "named", .records = "_debzstat _debzstat 4750 /" ++ base ++ "/mode\n", .path = base ++ "/mode", .expected = .{ .mode = 0o4750, .uid = 42420, .gid = 42421 } },
        .{ .label = "directory-new", .records = "#42420 #42421 2710 /" ++ base ++ "/empty\n", .path = base ++ "/empty", .expected = .{ .mode = 0o2710, .uid = 42420, .gid = 42421 } },
        .{ .label = "directory-existing", .records = "#42420 #42421 2710 /" ++ base ++ "/empty\n", .path = base ++ "/empty", .expected = .{ .mode = 0o700, .uid = 0, .gid = 0 }, .existing = true },
        .{ .label = "conffile", .records = "#42420 #42421 0640 /etc/debz-native.conf\n", .path = "etc/debz-native.conf", .expected = .{ .mode = 0o640, .uid = 42420, .gid = 42421 } },
        .{ .label = "symlink", .records = "#42420 #42421 0640 /" ++ base ++ "/current\n", .path = base ++ "/current", .expected = .{ .mode = 0o777, .uid = 42420, .gid = 42421 } },
        .{ .label = "literal", .records = "#42420 #42421 0640 /" ++ literal ++ "\n", .path = literal, .expected = .{ .mode = 0o640, .uid = 42420, .gid = 42421 } },
        .{ .label = "hardlink-source", .records = "#42420 #42421 0640 /" ++ base ++ "/data\n", .path = base ++ "/data", .expected = .{ .mode = 0o644, .uid = 0, .gid = 0 } },
        .{ .label = "hardlink-target", .records = "#42420 #42421 0640 /" ++ base ++ "/data.link\n", .path = base ++ "/data.link", .expected = .{ .mode = 0o640, .uid = 42420, .gid = 42421 } },
        .{ .label = "hardlink-both", .records = "#42420 #42421 0640 /" ++ base ++ "/data\n#42422 #42423 0600 /" ++ base ++ "/data.link\n", .path = base ++ "/data", .expected = .{ .mode = 0o600, .uid = 42422, .gid = 42423 } },
    };
    for (table) |entry| {
        const label = try std.fmt.allocPrint(fixture.allocator, "statoverride-{s}", .{entry.label});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try seed(&case, entry.records);
        if (entry.existing) {
            for ([_][]const u8{ "reference", "native" }) |side| {
                const target = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/{s}/empty", .{ case.name, side, base });
                defer fixture.allocator.free(target);
                try fixture.directory(target);
                try fixture.dir.setFilePermissions(fixture.io, target, .fromMode(0o700), .{});
            }
        }
        for ([_][]const u8{ "install", "upgrade", "reinstall", "downgrade" }, [_][]const u8{ first, second, second, first }) |operation, selected_archive| {
            try case.phase(.{ .operation = operation, .archives = &.{selected_archive}, .packages = &chosen }, false);
            try expectMetadata(&case, entry.path, entry.expected);
        }
        try case.phase(.{ .operation = "remove", .packages = &chosen }, false);
        try case.phase(.{ .operation = "purge", .packages = &chosen }, false);
        for ([_][]const u8{ "reference", "native" }) |side| {
            const path = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/var/lib/dpkg/statoverride", .{ case.name, side });
            defer fixture.allocator.free(path);
            const record = try support.read(fixture, path, 64 * 1024);
            defer fixture.allocator.free(record);
            if (!std.mem.eql(u8, record, entry.records)) return error.StatoverrideDatabaseChanged;
        }
    }

    const named = "_debzstat _debzstat 4750 /" ++ base ++ "/mode\n";
    for ([_]struct {
        label: []const u8,
        records: []const u8,
        marker: []const u8,
        content: []const u8,
        initial: Expected,
        next: Expected,
    }{
        .{ .label = "account-preinst", .records = named, .marker = "statoverride-passwd-replace", .content = "root:x:0:0:root:/root:/bin/sh\n_debzstat:x:42422:42421:fixture:/:/bin/sh\n", .initial = .{ .mode = 0o4750, .uid = 42420, .gid = 42421 }, .next = .{ .mode = 0o4750, .uid = 42422, .gid = 42421 } },
        .{ .label = "override-preinst", .records = named, .marker = "statoverride-preinst-replace", .content = "#42422 #42423 0640 /" ++ base ++ "/mode\n", .initial = .{ .mode = 0o4750, .uid = 42420, .gid = 42421 }, .next = .{ .mode = 0o640, .uid = 42422, .gid = 42423 } },
        .{ .label = "override-postinst", .records = named, .marker = "statoverride-postinst-replace", .content = "#42422 #42423 0640 /" ++ base ++ "/mode\n", .initial = .{ .mode = 0o4750, .uid = 42420, .gid = 42421 }, .next = .{ .mode = 0o640, .uid = 42422, .gid = 42423 } },
        .{ .label = "override-created", .records = "", .marker = "statoverride-preinst-replace", .content = named, .initial = .{ .mode = 0o600, .uid = 0, .gid = 0 }, .next = .{ .mode = 0o4750, .uid = 42420, .gid = 42421 } },
    }) |entry| {
        const label = try std.fmt.allocPrint(fixture.allocator, "statoverride-{s}", .{entry.label});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try seed(&case, entry.records);
        try replace(&case, entry.marker, entry.content);
        try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &chosen }, false);
        try expectMetadata(&case, base ++ "/mode", entry.initial);
        try case.phase(.{ .operation = "reinstall", .archives = &.{first}, .packages = &chosen }, false);
        try expectMetadata(&case, base ++ "/mode", entry.next);
    }

    const alias_archive = try support.makePackage(fixture, arch, "1", name, "packages/statoverride-alias", .{
        .extra_files = &.{.{ .path = "usr/bin/statoverride-mode", .content = "aliased payload\n" }},
        .scripts = .{ .before_failure = hook },
    });
    defer fixture.allocator.free(alias_archive);
    for ([_][]const u8{ "bin", "usr/bin" }) |spelling| {
        const label = try std.fmt.allocPrint(fixture.allocator, "statoverride-alias-{s}", .{if (std.mem.eql(u8, spelling, "bin")) "bin" else "usr-bin"});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        const records = try std.fmt.allocPrint(fixture.allocator, "#42420 #42421 4750 /{s}/statoverride-mode\n", .{spelling});
        defer fixture.allocator.free(records);
        try installAlias(&case, records);
        try case.phase(.{ .operation = "install", .archives = &.{alias_archive}, .packages = &chosen }, false);
        // The spelling in the override database, not the resolved alias, controls the applied metadata.
        const expected: Expected = if (std.mem.eql(u8, spelling, "bin"))
            .{ .mode = 0o644, .uid = 0, .gid = 0 }
        else
            .{ .mode = 0o4750, .uid = 42420, .gid = 42421 };
        try expectMetadata(&case, "usr/bin/statoverride-mode", expected);
    }

    for ([_][]const u8{ "keep_existing", "use_package_version" }) |policy| {
        const label = try std.fmt.allocPrint(fixture.allocator, "statoverride-conffile-{s}", .{policy});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try seed(&case, "#42420 #42421 0640 /etc/debz-native.conf\n");
        try case.seed(first);
        try both(&case, "etc/debz-native.conf", "administrator configuration\n");
        for ([_][]const u8{ case.reference_root, case.native_root }) |root_path| {
            var dir = try foundation.guardedRoot(fixture.io, root_path);
            defer dir.close(fixture.io);
            try (root_fs.Root.init(fixture.io, dir)).applyMetadata(try root_fs.Path.init("etc/debz-native.conf"), .{
                .mode = 0o600,
                .uid = 42424,
                .gid = 42425,
            });
        }
        try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &chosen, .policy = policy }, false);
        try expectMetadata(&case, "etc/debz-native.conf", .{ .mode = 0o600, .uid = 42424, .gid = 42425 });
    }

    if (fixture.oracle_only) return;
    for ([_]struct { label: []const u8, user: []const u8, group_name: []const u8 }{
        .{ .label = "missing-user", .user = "nobody", .group_name = "#42421" },
        .{ .label = "missing-group", .user = "#42420", .group_name = "nogroup" },
        .{ .label = "invalid-id", .user = "#4294967295", .group_name = "#42421" },
    }) |entry| {
        const label = try std.fmt.allocPrint(fixture.allocator, "statoverride-{s}", .{entry.label});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        const record = try std.fmt.allocPrint(fixture.allocator, "{s} {s} 0640 /{s}/mode\n", .{ entry.user, entry.group_name, base });
        defer fixture.allocator.free(record);
        try seed(&case, record);
        const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(before);
        const destination = try support.path(fixture.allocator, label, "refusal");
        defer fixture.allocator.free(destination);
        try fixture.directory(destination);
        var result = try support.native(fixture, driver, case.native_root, arch, .{
            .operation = "install",
            .archives = &.{first},
            .packages = &chosen,
        }, destination);
        defer result.deinit();
        if (!std.mem.eql(u8, result.value.outcome, "refused") or !std.mem.eql(u8, result.value.detail, "invalid_stat_override"))
            return error.UnexpectedStatoverrideRefusal;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.RefusalChangedRoot;
    }
}

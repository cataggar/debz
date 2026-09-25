const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

const metadata = "retained-metadata";
const literal = "literal-paths";
const literal_conf = "etc/literal\\config.conf";

fn identity(name: []const u8, arch: []const u8) [1]foundation.PackageIdentity {
    return .{.{ .name = name, .architecture = arch }};
}

fn metadataArchive(fixture: *foundation.Fixture, arch: []const u8, version: []const u8, qualified: bool, conffile: bool) ![]u8 {
    const workspace = if (qualified) "packages/metadata-qualified" else if (conffile) "packages/metadata" else "packages/metadata-data";
    const hook = try std.fmt.allocPrint(fixture.allocator,
        \\printf '%s' 'metadata:{s}@{s}:'"$DPKG_MAINTSCRIPT_NAME" >> /{s}
        \\for member in templates shlibs symbols; do
        \\    path="/var/lib/dpkg/info/{s}.$member"
        \\    if [ ! -f "$path" ]; then path="/var/lib/dpkg/info/{s}:$DPKG_MAINTSCRIPT_ARCH.$member"; fi
        \\    value='<absent>'
        \\    if [ -f "$path" ]; then IFS= read -r value < "$path"; fi
        \\    printf '\t%s=%s' "$member" "$value" >> /{s}
        \\done
        \\for member in config staging-config; do
        \\    if [ "$member" = config ]; then
        \\        path="/var/lib/dpkg/info/{s}.config"
        \\        if [ ! -f "$path" ]; then path="/var/lib/dpkg/info/{s}:$DPKG_MAINTSCRIPT_ARCH.config"; fi
        \\    else
        \\        path="/var/lib/dpkg/tmp.ci/config"
        \\    fi
        \\    value='<absent>'
        \\    if [ -f "$path" ]; then
        \\        {{ IFS= read -r first || :; IFS= read -r value || :; }} < "$path"
        \\    fi
        \\    printf '\t%s=%s' "$member" "$value" >> /{s}
        \\done
        \\printf '\n' >> /{s}
        \\
    , .{ metadata, version, support.trace, metadata, metadata, support.trace, metadata, metadata, support.trace, support.trace });
    defer fixture.allocator.free(hook);
    const conf = try std.fmt.allocPrint(fixture.allocator, "metadata configuration {s}\n", .{version});
    defer fixture.allocator.free(conf);
    const initial = try support.makePackage(fixture, arch, version, metadata, workspace, .{
        .full_payload = true,
        .conffile_content = if (conffile) conf else null,
        .control_fields = if (qualified) "Multi-Arch: same\n" else "",
        .scripts = .{ .before_failure = hook },
    });
    defer fixture.allocator.free(initial);
    const source = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_{s}_data.source", .{ workspace, metadata, version });
    defer fixture.allocator.free(source);
    if (!std.mem.eql(u8, version, "3")) {
        const alternative = try std.fmt.allocPrint(fixture.allocator, "package-alternatives:{s}\n\x00\xff", .{version});
        defer fixture.allocator.free(alternative);
        const config = try std.fmt.allocPrint(
            fixture.allocator,
            "#!/bin/sh\n# config:{s}\nprintf '%s\\n' 'config:{s}' >> /config-invoked\nexit 97\n",
            .{ version, version },
        );
        defer fixture.allocator.free(config);
        const templates = try std.fmt.allocPrint(fixture.allocator, "Template: {s}/v{s}\nType: string\nDescription: inert fixture\n", .{ metadata, version });
        defer fixture.allocator.free(templates);
        const shlibs = try std.fmt.allocPrint(fixture.allocator, "libretained-metadata 1 {s} (>= {s})\n", .{ metadata, version });
        defer fixture.allocator.free(shlibs);
        const names = [_][]const u8{ "alternatives", "config", "templates", "shlibs" };
        const contents = [_][]const u8{ alternative, config, templates, shlibs };
        for (names, contents) |kind, content| {
            const path = try std.fmt.allocPrint(fixture.allocator, "{s}/DEBIAN/{s}", .{ source, kind });
            defer fixture.allocator.free(path);
            try fixture.write(path, content, if (std.mem.eql(u8, kind, "config")) 0o755 else if (std.mem.eql(u8, kind, "alternatives") or std.mem.eql(u8, kind, "shlibs")) 0o640 else 0o644);
        }
        if (std.mem.eql(u8, version, "1")) {
            const path = try support.path(fixture.allocator, source, "DEBIAN/symbols");
            defer fixture.allocator.free(path);
            try fixture.write(path, "libretained-metadata.so.1 " ++ metadata ++ " #MINVER#\n symbol@Base 1\n\x00\xff", 0o644);
        }
    }
    const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_{s}_data.deb", .{ workspace, metadata, version });
    defer fixture.allocator.free(destination);
    return fixture.buildPackage(source, destination, .{});
}

fn metadataFailures(case: *support.Scenario, identities: []const []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const path = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, support.failure });
        defer case.fixture.allocator.free(path);
        if (identities.len == 0) {
            if (case.fixture.dir.statFile(case.fixture.io, path, .{ .follow_symlinks = false })) |_|
                try case.fixture.dir.deleteFile(case.fixture.io, path)
            else |err| if (err != error.FileNotFound) return err;
        } else {
            const text = try std.mem.join(case.fixture.allocator, "\n", identities);
            defer case.fixture.allocator.free(text);
            const content = try std.fmt.allocPrint(case.fixture.allocator, "{s}\n", .{text});
            defer case.fixture.allocator.free(content);
            try support.fixtureFile(case.fixture, path, content, 0o644);
        }
    }
}

fn literalArchive(fixture: *foundation.Fixture, arch: []const u8, version: []const u8) ![]u8 {
    const conf = try std.fmt.allocPrint(fixture.allocator, "literal configuration {s}\n", .{version});
    defer fixture.allocator.free(conf);
    const initial = try support.makePackage(fixture, arch, version, literal, "packages/literal", .{
        .conffile_content = conf,
        .conffile_path = literal_conf,
        .extra_files = &.{.{ .path = "usr/lib/systemd/system/system-systemd\\x2dmute.slice", .content = if (std.mem.eql(u8, version, "1")) "literal unit 1\n" else "literal unit 2\n" }},
    });
    defer fixture.allocator.free(initial);
    const source = try std.fmt.allocPrint(fixture.allocator, "packages/literal/{s}_{s}_data.source", .{ literal, version });
    defer fixture.allocator.free(source);
    const base = try support.path(fixture.allocator, source, "usr/share/literal\\directory");
    defer fixture.allocator.free(base);
    const content = try std.fmt.allocPrint(fixture.allocator, "literal payload {s}\n", .{version});
    defer fixture.allocator.free(content);
    const payload = try support.path(fixture.allocator, base, "..\\literal");
    defer fixture.allocator.free(payload);
    try fixture.write(payload, content, 0o644);
    const linked = try support.path(fixture.allocator, base, "hard\\link");
    defer fixture.allocator.free(linked);
    try std.Io.Dir.hardLink(fixture.dir, payload, fixture.dir, linked, fixture.io, .{});
    const symbolic = try support.path(fixture.allocator, base, "symbolic\\link");
    defer fixture.allocator.free(symbolic);
    try fixture.dir.symLink(fixture.io, "..\\literal", symbolic, .{});
    const destination = try std.fmt.allocPrint(fixture.allocator, "packages/literal/{s}_{s}_data.deb", .{ literal, version });
    defer fixture.allocator.free(destination);
    return fixture.buildPackage(source, destination, .{});
}

fn vendorBody(fixture: *foundation.Fixture, name: []const u8, version: []const u8, size: usize) ![]u8 {
    const prefix = try std.fmt.allocPrint(fixture.allocator, "#!/bin/sh\n# vendor-config:{s}:{s}\nprintf '%s\\n' '{s}:{s}' >> /vendor-config-called\nexit 97\n# ", .{ name, version, name, version });
    defer fixture.allocator.free(prefix);
    if (prefix.len > size or size > 1024 * 1024) return error.InvalidVendorConfigSize;
    const result = try fixture.allocator.alloc(u8, size);
    @memcpy(result[0..prefix.len], prefix);
    @memset(result[prefix.len..], 'x');
    return result;
}

fn runVendor(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    var file = try std.Io.Dir.cwd().openFile(fixture.io, "tools/fixtures/vendor-state/dpkg-config-reference-v1.json", .{});
    defer file.close(fixture.io);
    var reader = file.reader(fixture.io, &.{});
    const source_json = try reader.interface.allocRemaining(fixture.allocator, .limited(1024 * 1024));
    defer fixture.allocator.free(source_json);
    var reference = try std.json.parseFromSlice(std.json.Value, fixture.allocator, source_json, .{});
    defer reference.deinit();
    const members = reference.value.object.get("members") orelse return error.InvalidVendorReference;
    var packages: [2]std.ArrayList([]const u8) = .{ .empty, .empty };
    var identities: std.ArrayList(foundation.PackageIdentity) = .empty;
    defer identities.deinit(fixture.allocator);
    defer {
        for (&packages) |*versions| {
            for (versions.items) |item| fixture.allocator.free(item);
            versions.deinit(fixture.allocator);
        }
    }
    for (members.array.items) |member| {
        const package_name = member.object.get("owner").?.object.get("package").?.string;
        const arches = member.object.get("architectures").?.object;
        const info = arches.get(arch).?.object;
        const size: usize = @intCast(info.get("size").?.integer);
        if (!std.mem.eql(u8, info.get("mode").?.string, "0755")) return error.InvalidVendorReference;
        try identities.append(fixture.allocator, .{ .name = package_name, .architecture = arch });
        for ([_][]const u8{ "1", "2" }, 0..) |version, index| {
            const workspace = try std.fmt.allocPrint(fixture.allocator, "packages/vendor/{s}", .{version});
            defer fixture.allocator.free(workspace);
            const initial = try support.makePackage(fixture, arch, version, package_name, workspace, .{ .no_scripts = true });
            fixture.allocator.free(initial);
            const source = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_{s}_data.source", .{ workspace, package_name, version });
            defer fixture.allocator.free(source);
            const config = try support.path(fixture.allocator, source, "DEBIAN/config");
            defer fixture.allocator.free(config);
            const body = try vendorBody(fixture, package_name, version, size);
            defer fixture.allocator.free(body);
            try fixture.write(config, body, 0o755);
            const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_{s}_data.deb", .{ workspace, package_name, version });
            defer fixture.allocator.free(destination);
            try packages[index].append(fixture.allocator, try fixture.buildPackage(source, destination, .{}));
        }
    }
    var case = try support.Scenario.init(fixture, "pinned-vendor-config-members-zig", driver, dpkg, arch, false);
    defer case.deinit();
    try case.phase(.{ .operation = "install", .archives = packages[0].items, .packages = identities.items }, false);
    try case.phase(.{ .operation = "reinstall", .archives = packages[0].items, .packages = identities.items }, false);
    try case.phase(.{ .operation = "upgrade", .archives = packages[1].items, .packages = identities.items }, false);
    try case.phase(.{ .operation = "remove", .packages = identities.items }, false);
    try case.phase(.{ .operation = "purge", .packages = identities.items }, false);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const marker = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/vendor-config-called", .{ case.name, side });
        defer fixture.allocator.free(marker);
        try support.absent(fixture, marker);
    }
}

fn runMetadata(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    var sets: [3][3][]u8 = undefined;
    for ([_]bool{ false, true, false }, [_]bool{ true, true, false }, 0..) |qualified, conf, index| {
        for ([_][]const u8{ "1", "2", "3" }, 0..) |version, at| {
            sets[index][at] = try metadataArchive(fixture, arch, version, qualified, conf);
        }
    }
    defer for (&sets) |*archives| for (archives) |built| fixture.allocator.free(built);
    const names = identity(metadata, arch);
    for ([_]struct { label: []const u8, initial: usize, later: usize }{
        .{ .label = "unqualified", .initial = 0, .later = 0 },
        .{ .label = "qualified", .initial = 1, .later = 1 },
        .{ .label = "stem-change", .initial = 0, .later = 1 },
    }) |entry| {
        const label = try std.fmt.allocPrint(fixture.allocator, "retained-metadata-{s}", .{entry.label});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        for ([_][]const u8{ "install", "upgrade", "reinstall", "downgrade", "upgrade", "downgrade" }, [_]usize{ 0, 1, 1, 0, 2, 1 }, [_]bool{ false, true, true, false, true, true }) |operation, at, later| {
            try case.phase(.{ .operation = operation, .archives = &.{sets[if (later) entry.later else entry.initial][at]}, .packages = &names }, false);
        }
        try case.phase(.{ .operation = "remove", .packages = &names }, false);
        try case.phase(.{ .operation = "purge", .packages = &names }, false);
    }
    for ([_]struct { label: []const u8, seeded: bool, markers: []const []const u8, failed: bool }{
        .{ .label = "fresh-postinst-failure", .seeded = false, .markers = &.{metadata ++ "@1:postinst:configure"}, .failed = true },
        .{ .label = "upgrade-old-postrm-compensated", .seeded = true, .markers = &.{metadata ++ "@1:postrm:upgrade"}, .failed = false },
        .{ .label = "upgrade-old-postrm-failure", .seeded = true, .markers = &.{ metadata ++ "@1:postrm:upgrade", metadata ++ "@2:postrm:failed-upgrade" }, .failed = true },
    }) |entry| {
        const label = try std.fmt.allocPrint(fixture.allocator, "retained-metadata-{s}", .{entry.label});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        if (entry.seeded) try case.seed(sets[0][0]);
        try metadataFailures(&case, entry.markers);
        try case.phase(.{
            .operation = if (entry.seeded) "upgrade" else "install",
            .archives = &.{sets[0][if (entry.seeded) 1 else 0]},
            .packages = &names,
            .rollback_links = if (entry.markers.len == 2) &.{"usr/share/" ++ metadata ++ "/current"} else &.{},
        }, entry.failed);
    }
    {
        var case = try support.Scenario.init(fixture, "retained-metadata-direct-purge", driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(sets[0][0]);
        try case.phase(.{ .operation = "purge", .packages = &names }, false);
    }
    for ([_]usize{ 2, 0 }) |profile| {
        const label = try std.fmt.allocPrint(fixture.allocator, "retained-metadata-configure-retry-{s}", .{
            if (profile == 2) "data" else "conffile",
        });
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try metadataFailures(&case, &.{metadata ++ "@1:postinst:configure"});
        try case.phase(.{ .operation = "install", .archives = &.{sets[profile][0]}, .packages = &names }, true);
        try metadataFailures(&case, &.{});
        try case.phase(.{ .operation = "configure", .archives = &.{sets[profile][0]}, .packages = &names }, false);
    }
    for ([_]struct { operation: []const u8, profile: usize }{
        .{ .operation = "remove", .profile = 0 },
        .{ .operation = "purge", .profile = 2 },
        .{ .operation = "purge", .profile = 0 },
    }) |entry| {
        const label = try std.fmt.allocPrint(fixture.allocator, "retained-metadata-{s}-postrm-failure-{s}", .{
            entry.operation, if (entry.profile == 2) "data" else "conffile",
        });
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(sets[entry.profile][0]);
        const marker = try std.fmt.allocPrint(fixture.allocator, "{s}@1:postrm:{s}", .{ metadata, entry.operation });
        defer fixture.allocator.free(marker);
        try metadataFailures(&case, &.{marker});
        try case.phase(.{ .operation = entry.operation, .packages = &names }, true);
        if (std.mem.eql(u8, entry.operation, "purge")) {
            try metadataFailures(&case, &.{});
            try case.phase(.{ .operation = "purge", .packages = &names }, false);
        }
    }
}

fn runLiteral(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first = try literalArchive(fixture, arch, "1");
    defer fixture.allocator.free(first);
    const second = try literalArchive(fixture, arch, "2");
    defer fixture.allocator.free(second);
    const chosen = identity(literal, arch);
    for ([_][]const u8{ "keep_existing", "use_package_version" }) |policy| {
        const label = try std.fmt.allocPrint(fixture.allocator, "literal-package-paths-{s}", .{policy});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &chosen }, false);
        for ([_][]const u8{ "reference", "native" }) |side| {
            const path = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/{s}", .{ label, side, literal_conf });
            defer fixture.allocator.free(path);
            try support.fixtureFile(fixture, path, "administrator configuration\n", 0o644);
        }
        try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &chosen, .policy = policy }, false);
        try case.phase(.{ .operation = "reinstall", .archives = &.{second}, .packages = &chosen, .policy = policy }, false);
        try case.phase(.{ .operation = "remove", .packages = &chosen }, false);
        try case.phase(.{ .operation = "purge", .packages = &chosen }, false);
    }
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    try runVendor(fixture, driver, dpkg, arch);
    try runMetadata(fixture, driver, dpkg, arch);
    try runLiteral(fixture, driver, dpkg, arch);
}

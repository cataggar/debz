const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

const name = "conffile-lifecycle";
const paths = [_][]const u8{ "etc/debz-native.conf", "etc/conffile\\extra.conf" };

fn archive(fixture: *foundation.Fixture, arch: []const u8, version: []const u8, changed: bool) ![]u8 {
    const hook = try std.fmt.allocPrint(fixture.allocator,
        \\printf '%s' 'conffiles:{s}@{s}:'"$DPKG_MAINTSCRIPT_NAME" >> /{s}
        \\for path in /etc/debz-native.conf '/etc/conffile\extra.conf'; do
        \\    for suffix in '' .dpkg-new .dpkg-old .dpkg-dist; do
        \\        present=no
        \\        if [ -e "$path$suffix" ] || [ -L "$path$suffix" ]; then present=yes; fi
        \\        printf '\t%s%s=%s' "$path" "$suffix" "$present" >> /{s}
        \\    done
        \\done
        \\if [ "$DPKG_MAINTSCRIPT_NAME" = postrm ] && [ "$1" = purge ]; then
        \\    selected=no
        \\    declared=no
        \\    while IFS= read -r line; do
        \\        case "$line" in
        \\            'Package: {s}') selected=yes ;;
        \\            'Package: '*) selected=no ;;
        \\            'Conffiles:') if [ "$selected" = yes ]; then declared=yes; fi ;;
        \\        esac
        \\    done < /var/lib/dpkg/status
        \\    printf '\tdeclared=%s' "$declared" >> /{s}
        \\fi
        \\printf '\n' >> /{s}
        \\if [ "$DPKG_MAINTSCRIPT_NAME" = postrm ] && [ "$1" = purge ] && [ -f /conffile-recreate ]; then
        \\    /ln /administrator-configuration /etc/debz-native.conf || exit 24
        \\fi
        \\
    , .{ name, version, support.trace, support.trace, name, support.trace, support.trace });
    defer fixture.allocator.free(hook);
    const content = if (changed)
        "different archive configuration\n"
    else if (std.mem.eql(u8, version, "1"))
        "configuration 1\n"
    else
        "configuration 2\n";
    return support.makePackage(fixture, arch, version, name, if (changed) "packages/conffile-drift" else "packages/conffile-scripts", .{
        .conffile_content = content,
        .extra_conffile = .{
            .path = paths[1],
            .content = if (std.mem.eql(u8, version, "1")) "extra configuration 1\n" else "extra configuration 2\n",
        },
        .scripts = .{ .before_failure = hook },
    });
}

fn markers(case: *support.Scenario, failed: bool, version: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const relative = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, support.failure });
        defer case.fixture.allocator.free(relative);
        if (failed) {
            const content = try std.fmt.allocPrint(case.fixture.allocator, "{s}@{s}:{s}\n", .{
                name,                                                                            if (std.mem.eql(u8, version, "purge")) "1" else version,
                if (std.mem.eql(u8, version, "purge")) "postrm:purge" else "postinst:configure",
            });
            defer case.fixture.allocator.free(content);
            try support.fixtureFile(case.fixture, relative, content, 0o644);
        } else {
            if (case.fixture.dir.statFile(case.fixture.io, relative, .{ .follow_symlinks = false })) |_|
                try case.fixture.dir.deleteFile(case.fixture.io, relative)
            else |err| if (err != error.FileNotFound) return err;
        }
    }
}

fn editBoth(case: *support.Scenario, relative: []const u8, content: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const location = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, relative });
        defer case.fixture.allocator.free(location);
        try support.fixtureFile(case.fixture, location, content, 0o644);
    }
}

fn deleteBoth(case: *support.Scenario, relative: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const location = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, relative });
        defer case.fixture.allocator.free(location);
        try case.fixture.dir.deleteFile(case.fixture.io, location);
    }
}

fn assertRefusal(case: *support.Scenario, archive_path: []const u8, expected: []const u8, arch: []const u8) !void {
    const before = try foundation.capture(case.fixture.allocator, case.fixture.io, case.native_root);
    defer case.fixture.allocator.free(before);
    const destination = try support.path(case.fixture.allocator, case.name, "refusal");
    defer case.fixture.allocator.free(destination);
    try case.fixture.directory(destination);
    const chosen = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    var result = try support.native(case.fixture, case.executable, case.native_root, arch, .{
        .operation = "configure",
        .archives = &.{archive_path},
        .packages = &chosen,
    }, destination);
    defer result.deinit();
    if (!std.mem.eql(u8, result.value.outcome, "refused") or !std.mem.eql(u8, result.value.detail, expected))
        return error.UnexpectedConffileRefusal;
    const after = try foundation.capture(case.fixture.allocator, case.fixture.io, case.native_root);
    defer case.fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.RefusalChangedRoot;
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first = try archive(fixture, arch, "1", false);
    defer fixture.allocator.free(first);
    const second = try archive(fixture, arch, "2", false);
    defer fixture.allocator.free(second);
    const chosen = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};

    for ([_]bool{ false, true }) |removed| for ([_]bool{ false, true }) |failed| {
        const label = try std.fmt.allocPrint(fixture.allocator, "conffile-purge-removed-{s}-failure-{s}", .{
            if (removed) "true" else "false", if (failed) "true" else "false",
        });
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        if (removed) try case.phase(.{ .operation = "remove", .packages = &chosen }, false);
        if (failed) try markers(&case, true, "purge");
        try case.phase(.{ .operation = "purge", .packages = &chosen }, failed);
        if (failed) {
            for (paths) |path| {
                const conf = try std.fmt.allocPrint(fixture.allocator, "{s}/reference/{s}", .{ case.name, path });
                defer fixture.allocator.free(conf);
                try support.absent(fixture, conf);
            }
            try markers(&case, false, "");
            try case.phase(.{ .operation = "purge", .packages = &chosen }, false);
        }
    };

    for ([_]bool{ false, true }) |failed| {
        const label = if (failed) "conffile-purge-script-recreates-failure" else "conffile-purge-script-recreates-success";
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        for ([_][]const u8{ "reference", "native" }) |side| {
            const root = try support.path(fixture.allocator, case.name, side);
            defer fixture.allocator.free(root);
            try support.copyProgram(fixture, root, "/usr/bin/ln", "/ln");
        }
        try editBoth(&case, "administrator-configuration", "administrator configuration\n");
        try editBoth(&case, "conffile-recreate", "");
        if (failed) try markers(&case, true, "purge");
        try case.phase(.{ .operation = "purge", .packages = &chosen }, failed);
        if (failed) {
            try markers(&case, false, "");
            try deleteBoth(&case, "conffile-recreate");
            try case.phase(.{ .operation = "purge", .packages = &chosen }, false);
        }
    }

    for ([_][]const u8{ "keep_existing", "use_package_version" }) |policy|
        for ([_]bool{ false, true }) |upgrade|
            for ([_][]const u8{ "unchanged", "edited", "missing", "side-files" }) |mutation| {
                const label = try std.fmt.allocPrint(fixture.allocator, "conffile-configure-retry-{s}-upgrade-{s}-{s}", .{
                    policy, if (upgrade) "true" else "false", mutation,
                });
                defer fixture.allocator.free(label);
                var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
                defer case.deinit();
                const version: []const u8 = if (upgrade) "2" else "1";
                const chosen_archive = if (upgrade) second else first;
                if (upgrade) {
                    try case.seed(first);
                    for (paths) |path| try editBoth(&case, path, "administrator configuration\n");
                }
                try markers(&case, true, version);
                try case.phase(.{
                    .operation = if (upgrade) "upgrade" else "install",
                    .archives = &.{chosen_archive},
                    .packages = &chosen,
                    .policy = policy,
                }, true);
                try markers(&case, false, "");
                for (paths) |path| {
                    if (std.mem.eql(u8, mutation, "missing")) try deleteBoth(&case, path) else if (std.mem.eql(u8, mutation, "edited") or std.mem.eql(u8, mutation, "side-files")) {
                        const target = if (std.mem.eql(u8, mutation, "side-files"))
                            try std.fmt.allocPrint(fixture.allocator, "{s}.dpkg-new", .{path})
                        else
                            try fixture.allocator.dupe(u8, path);
                        defer fixture.allocator.free(target);
                        try editBoth(&case, target, "administrator edit after failure\n");
                    }
                }
                try case.phase(.{
                    .operation = "configure",
                    .archives = &.{chosen_archive},
                    .packages = &chosen,
                    .policy = policy,
                }, false);
            };

    const changed = try archive(fixture, arch, "1", true);
    defer fixture.allocator.free(changed);
    for ([_][]const u8{ "unpacked-missing-stage", "unpacked-changed-stage", "configured-changed-archive" }) |mode| {
        const label = try std.fmt.allocPrint(fixture.allocator, "conffile-refusal-{s}", .{mode});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        if (std.mem.startsWith(u8, mode, "unpacked")) {
            try case.seed(first);
            try case.seedWith(second, false);
            const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/native/{s}.dpkg-new", .{ label, paths[0] });
            defer fixture.allocator.free(relative);
            if (std.mem.eql(u8, mode, "unpacked-missing-stage")) {
                try fixture.dir.deleteFile(fixture.io, relative);
            } else try support.fixtureFile(fixture, relative, "changed staged configuration\n", 0o644);
            try assertRefusal(&case, second, "staged_conffile_mismatch", arch);
        } else {
            try markers(&case, true, "1");
            try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &chosen }, true);
            try markers(&case, false, "");
            try assertRefusal(&case, changed, "configured_conffile_mismatch", arch);
        }
    }
}

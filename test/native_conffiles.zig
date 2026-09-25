const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const root_fs = @import("debz").root_fs;
const options = @import("native_test_options");

const config = "etc/debz-native.conf";
const old_config = "configuration version one\n";
const new_config = "configuration version two\n";
const local_config = "administrator configuration\n";
const PackageIdentity = foundation.PackageIdentity;

fn join(allocator: std.mem.Allocator, prefix: []const u8, suffix: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, suffix });
}

fn localFile(fixture: *foundation.Fixture, path: []const u8, content: []const u8) !void {
    try fixture.write(path, content, 0o600);
    try fixture.dir.setTimestamps(fixture.io, path, .{
        .modify_timestamp = .{ .new = .{
            .nanoseconds = (foundation.epoch + 60) * std.time.ns_per_s,
        } },
    });
}

const Scenario = struct {
    fixture: *foundation.Fixture,
    executable: []const u8,
    dpkg: []const u8,
    architecture: []const u8,
    name: []const u8,
    expected: []u8,
    candidate: []u8,
    phases: *usize,
    index: usize = 0,

    fn init(
        fixture: *foundation.Fixture,
        name: []const u8,
        executable: []const u8,
        dpkg: []const u8,
        architecture: []const u8,
        phases: *usize,
    ) !Scenario {
        const left = try join(fixture.allocator, name, "reference");
        defer fixture.allocator.free(left);
        const right = try join(fixture.allocator, name, "native");
        defer fixture.allocator.free(right);
        const expected = try fixture.makeRoot(left, architecture);
        errdefer fixture.allocator.free(expected);
        const candidate = try fixture.makeRoot(right, architecture);
        return .{
            .fixture = fixture,
            .executable = executable,
            .dpkg = dpkg,
            .architecture = architecture,
            .name = name,
            .expected = expected,
            .candidate = candidate,
            .phases = phases,
        };
    }

    fn deinit(self: *Scenario) void {
        self.fixture.allocator.free(self.expected);
        self.fixture.allocator.free(self.candidate);
    }

    fn seed(self: *Scenario, archive: []const u8, configure: bool) !void {
        for ([_][]const u8{ self.expected, self.candidate }, [_][]const u8{ "reference", "native" }) |root, label| {
            const log = try std.fmt.allocPrint(self.fixture.allocator, "{s}/{s}-seed-{d}.log", .{
                self.name, label, self.index,
            });
            defer self.fixture.allocator.free(log);
            try foundation.reference(self.fixture.*, self.dpkg, root, archive, log, configure);
        }
        self.index += 1;
    }

    fn edit(self: *Scenario, state: []const u8) !void {
        for ([_][]const u8{ self.expected, self.candidate }, [_][]const u8{ "reference", "native" }) |_, label| {
            const relative = try std.fmt.allocPrint(self.fixture.allocator, "{s}/{s}/{s}", .{ self.name, label, config });
            defer self.fixture.allocator.free(relative);
            if (std.mem.eql(u8, state, "edited")) {
                try localFile(self.fixture, relative, local_config);
            } else if (std.mem.eql(u8, state, "missing")) {
                try self.fixture.dir.deleteFile(self.fixture.io, relative);
            } else if (std.mem.eql(u8, state, "packaged")) {
                try localFile(self.fixture, relative, new_config);
            } else if (!std.mem.eql(u8, state, "unmodified")) return error.UnknownConffileState;
        }
    }

    fn phase(
        self: *Scenario,
        operation: []const u8,
        archive: ?[]const u8,
        policy: []const u8,
        packages: ?[]const PackageIdentity,
    ) !void {
        const allocator = self.fixture.allocator;
        const destination = try std.fmt.allocPrint(allocator, "{s}/{d}-{s}", .{ self.name, self.index, operation });
        defer allocator.free(destination);
        try self.fixture.directory(destination);
        self.index += 1;
        const reference_log = try join(allocator, destination, "reference.log");
        defer allocator.free(reference_log);
        try foundation.referencePhase(
            self.fixture.*,
            self.dpkg,
            self.expected,
            archive,
            operation,
            policy,
            packages,
            reference_log,
        );
        const default_package = [_]PackageIdentity{.{
            .name = foundation.package,
            .architecture = self.architecture,
        }};
        const selected: ?[]const PackageIdentity = if (packages) |list| list else if (std.mem.eql(u8, operation, "remove") or
            std.mem.eql(u8, operation, "purge")) default_package[0..] else null;
        var report = try foundation.nativeOperation(
            self.fixture,
            self.executable,
            self.candidate,
            archive,
            self.architecture,
            operation,
            destination,
            .{
                .conffiles = true,
                .policy = policy,
                .packages = selected,
            },
        );
        defer report.deinit();
        if (!std.mem.eql(u8, report.value.outcome, "applied")) {
            std.debug.print("{s}/{s}: native returned {s}: {s}\n", .{
                self.name, operation, report.value.outcome, report.value.detail,
            });
            return error.NativeConffileNotApplied;
        }
        var root = try foundation.guardedRoot(self.fixture.io, self.candidate);
        defer root.close(self.fixture.io);
        const filesystem: root_fs.Root = .init(self.fixture.io, root);
        for ([_][]const u8{ "root-operation-v1.json", "root-mutation-v1.json" }) |evidence| {
            const relative = try join(allocator, "var/lib/debz", evidence);
            defer allocator.free(relative);
            if (try filesystem.entryIfExists(try root_fs.Path.init(relative)) != null)
                return error.StrandedActiveEvidence;
        }
        try foundation.compare(self.fixture.*, self.expected, self.candidate, destination);
        if (!std.mem.eql(u8, operation, "remove") and !std.mem.eql(u8, operation, "purge"))
            try foundation.assertDirectoryMtime(self.fixture.io, self.expected, self.candidate, foundation.payload ++ "/empty");
        self.phases.* += 1;
    }

    fn complete(self: Scenario) void {
        std.debug.print("{s}: native/dpkg parity passed\n", .{self.name});
    }
};

fn execute(
    fixture: *foundation.Fixture,
    executable: []const u8,
    dpkg: []const u8,
    architecture: []const u8,
) !void {
    const a = fixture.allocator;
    const first = try fixture.makePackageWith(architecture, "1", .conffile, .{
        .workspace = "packages/first",
        .conffile_content = old_config,
    });
    defer a.free(first);
    const changed = try fixture.makePackageWith(architecture, "2", .conffile, .{
        .workspace = "packages/changed",
        .conffile_content = new_config,
    });
    defer a.free(changed);
    const unchanged = try fixture.makePackageWith(architecture, "2", .conffile, .{
        .workspace = "packages/unchanged",
        .conffile_content = old_config,
    });
    defer a.free(unchanged);
    const obsolete = try fixture.makePackageWith(architecture, "2", .obsolete_conffile, .{
        .workspace = "packages/obsolete",
    });
    defer a.free(obsolete);
    const removed = try fixture.makePackageWith(architecture, "2", .remove_on_upgrade, .{
        .workspace = "packages/removed",
    });
    defer a.free(removed);
    const plain = try fixture.makePackageWith(architecture, "1", .data, .{
        .workspace = "packages/plain",
    });
    defer a.free(plain);
    const other = try fixture.makePackageWith(architecture, "1", .data, .{
        .workspace = "packages/other",
        .name = "debz-native-other",
    });
    defer a.free(other);

    var phases: usize = 0;
    for ([_][]const u8{ "keep_existing", "use_package_version" }) |policy| {
        {
            const name = try std.fmt.allocPrint(a, "fresh-{s}", .{policy});
            defer a.free(name);
            var case = try Scenario.init(fixture, name, executable, dpkg, architecture, &phases);
            defer case.deinit();
            try case.phase("install", first, policy, null);
            try case.phase("configure", first, policy, null);
            case.complete();
        }
        const upgrades = [_]struct { state: []const u8, archive: []const u8, suffix: []const u8 }{
            .{ .state = "unmodified", .archive = changed, .suffix = "changed" },
            .{ .state = "edited", .archive = changed, .suffix = "changed" },
            .{ .state = "missing", .archive = changed, .suffix = "changed" },
            .{ .state = "packaged", .archive = changed, .suffix = "changed" },
            .{ .state = "unmodified", .archive = unchanged, .suffix = "unchanged" },
            .{ .state = "edited", .archive = unchanged, .suffix = "unchanged" },
            .{ .state = "missing", .archive = unchanged, .suffix = "unchanged" },
        };
        for (upgrades) |item| {
            const name = try std.fmt.allocPrint(a, "{s}-{s}-{s}", .{ item.state, item.suffix, policy });
            defer a.free(name);
            var case = try Scenario.init(fixture, name, executable, dpkg, architecture, &phases);
            defer case.deinit();
            try case.seed(first, true);
            try case.edit(item.state);
            try case.phase("upgrade", item.archive, policy, null);
            try case.phase("configure", item.archive, policy, null);
            case.complete();
        }
        for ([_][]const u8{ "unmodified", "edited", "missing" }) |state| {
            for ([_]struct { feature: []const u8, archive: []const u8 }{
                .{ .feature = "obsolete", .archive = obsolete },
                .{ .feature = "remove-on-upgrade", .archive = removed },
            }) |item| {
                const name = try std.fmt.allocPrint(a, "{s}-{s}-{s}", .{ item.feature, state, policy });
                defer a.free(name);
                var case = try Scenario.init(fixture, name, executable, dpkg, architecture, &phases);
                defer case.deinit();
                try case.seed(first, true);
                try case.edit(state);
                try case.phase("upgrade", item.archive, policy, null);
                try case.phase("configure", item.archive, policy, null);
                try case.phase("purge", null, policy, null);
                case.complete();
            }
        }
        {
            const name = try std.fmt.allocPrint(a, "fresh-remove-on-upgrade-{s}", .{policy});
            defer a.free(name);
            var case = try Scenario.init(fixture, name, executable, dpkg, architecture, &phases);
            defer case.deinit();
            try case.phase("install", removed, policy, null);
            try case.phase("configure", removed, policy, null);
            case.complete();
        }
    }
    {
        var case = try Scenario.init(fixture, "repeated-unconfigured-conffiles", executable, dpkg, architecture, &phases);
        defer case.deinit();
        try case.phase("install", first, "keep_existing", null);
        try case.phase("upgrade", changed, "keep_existing", null);
        try case.phase("configure", changed, "keep_existing", null);
        try case.phase("downgrade", first, "keep_existing", null);
        try case.phase("configure", first, "keep_existing", null);
        try case.phase("reinstall", first, "keep_existing", null);
        try case.phase("configure", first, "keep_existing", null);
        case.complete();
    }
    for ([_]struct { archive: []const u8, feature: []const u8 }{
        .{ .archive = plain, .feature = "plain" },
        .{ .archive = first, .feature = "conffile" },
    }) |item| {
        for ([_]bool{ false, true }) |configured| {
            for ([_][]const u8{ "remove", "purge" }) |operation| {
                const name = try std.fmt.allocPrint(a, "{s}-{s}-{s}", .{
                    item.feature, if (configured) "installed" else "unpacked", operation,
                });
                defer a.free(name);
                var case = try Scenario.init(fixture, name, executable, dpkg, architecture, &phases);
                defer case.deinit();
                try case.seed(item.archive, configured);
                try case.phase(operation, null, "keep_existing", null);
                try case.phase(operation, null, "keep_existing", null);
                if (std.mem.eql(u8, operation, "remove"))
                    try case.phase("purge", null, "keep_existing", null);
                case.complete();
            }
        }
    }
    for ([_][]const u8{ "edited", "missing" }) |state| {
        const name = try std.fmt.allocPrint(a, "remove-{s}-conffile", .{state});
        defer a.free(name);
        var case = try Scenario.init(fixture, name, executable, dpkg, architecture, &phases);
        defer case.deinit();
        try case.seed(first, true);
        try case.edit(state);
        try case.phase("remove", null, "keep_existing", null);
        try case.phase("purge", null, "keep_existing", null);
        case.complete();
    }
    {
        var case = try Scenario.init(fixture, "purge-retains-local-and-coowned-directories", executable, dpkg, architecture, &phases);
        defer case.deinit();
        try case.seed(first, true);
        try case.seed(other, true);
        for ([_][]const u8{ "reference", "native" }) |root| {
            for ([_]struct { relative: []const u8, content: []const u8 }{
                .{ .relative = foundation.payload ++ "/administrator-file", .content = "retain me\n" },
                .{ .relative = "etc/administrator-file", .content = "retain me too\n" },
                .{ .relative = config ++ ".dpkg-old", .content = "old configuration artifact\n" },
                .{ .relative = config ++ ".dpkg-dist", .content = "old configuration artifact\n" },
                .{ .relative = config ++ ".dpkg-new", .content = "old configuration artifact\n" },
            }) |item| {
                const path = try std.fmt.allocPrint(a, "{s}/{s}/{s}", .{ case.name, root, item.relative });
                defer a.free(path);
                try localFile(fixture, path, item.content);
            }
        }
        try case.phase("purge", null, "keep_existing", null);
        case.complete();
    }
    {
        var case = try Scenario.init(fixture, "batch-purge-shared-directories", executable, dpkg, architecture, &phases);
        defer case.deinit();
        try case.seed(plain, true);
        try case.seed(other, true);
        const selection = [_]PackageIdentity{
            .{ .name = foundation.package, .architecture = architecture },
            .{ .name = "debz-native-other", .architecture = architecture },
        };
        try case.phase("purge", null, "keep_existing", &selection);
        case.complete();
    }
    if (phases != 105) return error.IncompleteConffilePhaseMatrix;

    var handoffs: usize = 0;
    for ([_][]const u8{
        "script",                    "unregistered-local",     "symlink-conffile",
        "generated-stage-collision", "foreign-owned-artifact",
    }) |feature| {
        const name = try std.fmt.allocPrint(a, "handoff-{s}", .{feature});
        defer a.free(name);
        var case = try Scenario.init(fixture, name, executable, dpkg, architecture, &phases);
        defer case.deinit();
        var archive: ?[]const u8 = first;
        var operation: []const u8 = "install";
        var extra: ?[]u8 = null;
        defer if (extra) |owned| a.free(owned);
        if (std.mem.eql(u8, feature, "script")) {
            extra = try fixture.makePackageWith(architecture, "1", .script, .{ .workspace = "packages/script" });
            archive = extra;
        } else if (std.mem.eql(u8, feature, "unregistered-local")) {
            const file = try join(a, name, "native/" ++ config);
            defer a.free(file);
            try localFile(fixture, file, local_config);
        } else if (std.mem.eql(u8, feature, "symlink-conffile")) {
            try case.seed(first, true);
            const file = try join(a, name, "native/" ++ config);
            defer a.free(file);
            try fixture.dir.deleteFile(fixture.io, file);
            const target = try join(a, name, "native/etc/local-target");
            defer a.free(target);
            try localFile(fixture, target, local_config);
            try fixture.dir.symLink(fixture.io, "local-target", file, .{});
            archive = changed;
            operation = "upgrade";
        } else if (std.mem.eql(u8, feature, "generated-stage-collision")) {
            extra = try fixture.makePackageWith(architecture, "1", .conffile, .{
                .workspace = "packages/collision",
                .conffile_content = old_config,
                .extra_files = &.{.{ .path = config ++ ".dpkg-new", .content = "ordinary owned payload\n" }},
            });
            archive = extra;
        } else {
            try case.seed(first, true);
            const foreign = try fixture.makePackageWith(architecture, "1", .data, .{
                .workspace = "packages/foreign-artifact",
                .name = "debz-native-other",
                .extra_files = &.{.{ .path = config ++ ".dpkg-dist", .content = "foreign owned payload\n" }},
            });
            defer a.free(foreign);
            try case.seed(foreign, true);
            archive = null;
            operation = "purge";
        }
        const before = try foundation.capture(a, fixture.io, case.candidate);
        defer a.free(before);
        const destination = try join(a, name, "refusal");
        defer a.free(destination);
        try fixture.directory(destination);
        const selected = [_]PackageIdentity{.{
            .name = foundation.package,
            .architecture = architecture,
        }};
        var report = try foundation.nativeOperation(
            fixture,
            executable,
            case.candidate,
            archive,
            architecture,
            operation,
            destination,
            .{
                .conffiles = true,
                .packages = if (std.mem.eql(u8, operation, "purge")) &selected else null,
            },
        );
        defer report.deinit();
        if (!std.mem.eql(u8, report.value.outcome, "handoff") and
            !std.mem.eql(u8, report.value.outcome, "refused"))
            return error.UnsafeConffileHandoff;
        const after = try foundation.capture(a, fixture.io, case.candidate);
        defer a.free(after);
        if (!std.mem.eql(u8, before, after)) return error.ConffileHandoffChangedRoot;
        var guarded = try foundation.guardedRoot(fixture.io, case.candidate);
        defer guarded.close(fixture.io);
        const root: root_fs.Root = .init(fixture.io, guarded);
        for ([_][]const u8{ "root-operation-v1.json", "root-mutation-v1.json" }) |evidence| {
            const relative = try join(a, "var/lib/debz", evidence);
            defer a.free(relative);
            if (try root.entryIfExists(try root_fs.Path.init(relative)) != null)
                return error.StrandedConffileHandoffEvidence;
        }
        handoffs += 1;
        std.debug.print("{s}: pre-mutation handoff passed\n", .{feature});
    }
    if (handoffs != 5) return error.IncompleteConffileHandoffMatrix;
    std.debug.print("conffiles: {d} executed phase comparisons; {d} pre-mutation handoffs\n", .{
        phases, handoffs,
    });
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const executable = args.next() orelse return error.MissingNativeTestExecutable;
    var reference_path: ?[]const u8 = null;
    if (args.next()) |option| {
        if (!std.mem.eql(u8, option, "--reference-dpkg")) return error.InvalidArguments;
        reference_path = args.next() orelse return error.InvalidArguments;
    }
    if (args.next() != null) return error.InvalidArguments;
    const host_dpkg = try foundation.hostDpkg(allocator, init.io, init.environ_map.get("PATH") orelse "/bin:/usr/bin");
    defer allocator.free(host_dpkg);
    const architecture = try foundation.hostArchitecture(allocator, init.io, host_dpkg);
    const dpkg = try foundation.selectReference(allocator, init.io, reference_path, architecture, host_dpkg);
    const status_before = try foundation.hostStatusDigest(allocator, init.io);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    try execute(&fixture, executable, dpkg, architecture);
    const status_after = try foundation.hostStatusDigest(allocator, init.io);
    if (!std.mem.eql(u8, &status_before, &status_after)) return error.HostDpkgStatusChanged;
}

test "conffile fixture declares remove-on-upgrade without shipping a conffile" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const archive = try fixture.makePackageWith("amd64", "2", .remove_on_upgrade, .{
        .workspace = "packages/removed",
    });
    defer std.testing.allocator.free(archive);
    try std.testing.expectError(
        error.FileNotFound,
        fixture.dir.statFile(std.testing.io, "packages/removed/debz-native-demo_2_remove_on_upgrade.source/" ++ config, .{}),
    );
    var file = try fixture.dir.openFile(
        std.testing.io,
        "packages/removed/debz-native-demo_2_remove_on_upgrade.source/DEBIAN/conffiles",
        .{},
    );
    defer file.close(std.testing.io);
    var reader = file.reader(std.testing.io, &.{});
    const content = try reader.interface.allocRemaining(std.testing.allocator, .limited(256));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("remove-on-upgrade /etc/debz-native.conf\n", content);
}

test "conffile fixture keeps its path while changing package content" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const archive = try fixture.makePackageWith("amd64", "2", .conffile, .{
        .workspace = "packages/changed",
        .conffile_content = new_config,
    });
    defer std.testing.allocator.free(archive);
    var file = try fixture.dir.openFile(
        std.testing.io,
        "packages/changed/debz-native-demo_2_conffile.source/" ++ config,
        .{},
    );
    defer file.close(std.testing.io);
    var reader = file.reader(std.testing.io, &.{});
    const content = try reader.interface.allocRemaining(std.testing.allocator, .limited(256));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings(new_config, content);
}

test "conffile reference phases require a guarded disposable root" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    for ([_][]const u8{ "configure", "remove", "purge" }) |operation| {
        try std.testing.expectError(error.NotDisposableRoot, foundation.referencePhase(
            fixture,
            "/usr/bin/dpkg",
            "/",
            null,
            operation,
            "keep_existing",
            null,
            "unused.log",
        ));
    }
}

test "native conffile request binds policy and selected package identities" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(root);
    try fixture.directory("phase");
    const script = try std.fmt.allocPrint(
        std.testing.allocator,
        "#!/bin/sh\nprintf '%s\\n' '{{\"outcome\":\"applied\",\"detail\":\"fake\"}}' > '{s}/phase/native.report.json'\n",
        .{fixture.path},
    );
    defer std.testing.allocator.free(script);
    try fixture.write("fake-native", script, 0o755);
    const executable = try fixture.absolute("fake-native");
    defer std.testing.allocator.free(executable);
    const packages = [_]PackageIdentity{.{
        .name = foundation.package,
        .architecture = "amd64",
    }};
    var report = try foundation.nativeOperation(
        &fixture,
        executable,
        root,
        null,
        "amd64",
        "purge",
        "phase",
        .{ .conffiles = true, .policy = "use_package_version", .packages = &packages },
    );
    defer report.deinit();
    try std.testing.expectEqualStrings("applied", report.value.outcome);
    var request = try fixture.dir.openFile(std.testing.io, "phase/native.request.json", .{});
    defer request.close(std.testing.io);
    var reader = request.reader(std.testing.io, &.{});
    const bytes = try reader.interface.allocRemaining(std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    const document = parsed.value.object;
    try std.testing.expectEqualStrings("purge", document.get("operation").?.string);
    try std.testing.expectEqualStrings("use_package_version", document.get("policy").?.string);
    try std.testing.expect(document.get("conffiles").?.bool);
    try std.testing.expectEqual(@as(usize, 0), document.get("archives").?.array.items.len);
    const selected = document.get("packages").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), selected.len);
    try std.testing.expectEqualStrings(foundation.package, selected[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("amd64", selected[0].object.get("architecture").?.string);
}

test "claimed success with a wrong conffile root is rejected by Scenario.phase" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    try fixture.write("reference-dpkg", "#!/bin/sh\nexit 0\n", 0o755);
    const dpkg = try fixture.absolute("reference-dpkg");
    defer std.testing.allocator.free(dpkg);
    const script = try std.fmt.allocPrint(
        std.testing.allocator,
        "#!/bin/sh\nprintf '%s\\n' '{{\"outcome\":\"applied\",\"detail\":\"fixture\"}}' > '{s}/case/0-purge/native.report.json'\n",
        .{fixture.path},
    );
    defer std.testing.allocator.free(script);
    try fixture.write("fake-native", script, 0o755);
    const native = try fixture.absolute("fake-native");
    defer std.testing.allocator.free(native);
    var phases: usize = 0;
    var scenario = try Scenario.init(&fixture, "case", native, dpkg, "amd64", &phases);
    defer scenario.deinit();
    try fixture.write("case/reference/" ++ config, old_config, 0o644);
    try std.testing.expectError(
        error.NativeDpkgMismatch,
        scenario.phase("purge", null, "keep_existing", null),
    );
    try std.testing.expectEqual(@as(usize, 0), phases);
    var file = try fixture.dir.openFile(std.testing.io, "case/0-purge/native.report.json", .{});
    defer file.close(std.testing.io);
    var reader = file.reader(std.testing.io, &.{});
    const report = try reader.interface.allocRemaining(std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(report);
    try std.testing.expect(std.mem.indexOf(u8, report, "\"outcome\":\"applied\"") != null);
}

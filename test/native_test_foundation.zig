const std = @import("std");
const root_fs = @import("debz").root_fs;

pub const guard = ".debz-native-disposable";
pub const guard_content = "debz native materialization fixture v1\n";
pub const package = "debz-native-demo";
pub const epoch: i128 = 1_700_000_000;
pub const payload = "usr/share/" ++ package;
const max_database_bytes = 64 * 1024 * 1024;

pub const SnapshotLimits = struct {
    max_entries: usize = 500_000,
    max_file_bytes: usize = 4 * 1024 * 1024 * 1024,
    max_database_file_bytes: usize = max_database_bytes,
    max_total_regular_bytes: u64 = 16 * 1024 * 1024 * 1024,
    max_trace_bytes: usize = 16 * 1024 * 1024,
};

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    diagnostics: bool = true,
    retain: bool = false,
    path: []u8,
    name: []const u8,
    parent: std.Io.Dir,
    dir: std.Io.Dir,
    environment: std.process.Environ.Map,
    oracle_only: bool = false,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, repository: []const u8) !Fixture {
        return initWorkspace(allocator, io, repository, null);
    }

    pub fn initWorkspace(allocator: std.mem.Allocator, io: std.Io, repository: []const u8, requested: ?[]const u8) !Fixture {
        var repository_dir = try openRealDirectory(io, repository);
        defer repository_dir.close(io);
        try repository_dir.createDirPath(io, ".tmp");
        const parent = try repository_dir.openDir(io, ".tmp", .{
            .iterate = true,
            .follow_symlinks = false,
        });
        errdefer parent.close(io);
        const name = if (requested) |workspace| blk: {
            var cwd: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const cwd_len = try std.process.currentPath(io, &cwd);
            const resolved = try std.fs.path.resolve(allocator, &.{ cwd[0..cwd_len], workspace });
            defer allocator.free(resolved);
            const fixture_parent = try std.fs.path.join(allocator, &.{ repository, ".tmp" });
            defer allocator.free(fixture_parent);
            if (!std.mem.eql(u8, std.fs.path.dirname(resolved) orelse "", fixture_parent))
                return error.WorkspaceOutsideFixtureParent;
            const leaf = std.fs.path.basename(resolved);
            _ = try root_fs.Path.init(leaf);
            break :blk try allocator.dupe(u8, leaf);
        } else blk: {
            var random: [12]u8 = undefined;
            try io.randomSecure(&random);
            break :blk try std.fmt.allocPrint(allocator, "native-zig-{x}", .{std.fmt.bytesToHex(random, .lower)});
        };
        errdefer allocator.free(name);
        if (requested != null) {
            try parent.createDir(io, name, .fromMode(0o700));
            errdefer parent.deleteDir(io, name) catch {};
        }
        const dir = if (requested != null)
            try parent.openDir(io, name, .{ .iterate = true, .follow_symlinks = false })
        else
            try parent.createDirPathOpen(io, name, .{
                .open_options = .{ .iterate = true, .follow_symlinks = false },
            });
        errdefer {
            dir.close(io);
            parent.deleteTree(io, name) catch {};
        }
        const path = try std.fs.path.join(allocator, &.{ repository, ".tmp", name });
        errdefer allocator.free(path);
        var environment = std.process.Environ.Map.init(allocator);
        errdefer environment.deinit();
        const home = try std.fs.path.join(allocator, &.{ path, "home" });
        defer allocator.free(home);
        const temp = try std.fs.path.join(allocator, &.{ path, "tmp" });
        defer allocator.free(temp);
        try dir.createDirPath(io, "home");
        try dir.createDirPath(io, "tmp");
        try environment.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        try environment.put("LANG", "C");
        try environment.put("LC_ALL", "C");
        try environment.put("HOME", home);
        try environment.put("TMPDIR", temp);
        try environment.put("SOURCE_DATE_EPOCH", "1700000000");
        return .{
            .allocator = allocator,
            .io = io,
            .retain = requested != null,
            .path = path,
            .name = name,
            .parent = parent,
            .dir = dir,
            .environment = environment,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.environment.deinit();
        self.dir.close(self.io);
        if (self.retain) {
            std.debug.print("retained native fixture: {s}\n", .{self.path});
        } else {
            self.parent.deleteTree(self.io, self.name) catch |err|
                std.debug.print("failed to remove disposable fixture {s}: {s}\n", .{ self.path, @errorName(err) });
        }
        self.parent.close(self.io);
        self.allocator.free(self.path);
        self.allocator.free(self.name);
    }

    pub fn absolute(self: Fixture, relative: []const u8) ![]u8 {
        _ = try root_fs.Path.initPackage(relative);
        return std.fs.path.join(self.allocator, &.{ self.path, relative });
    }

    pub fn directory(self: Fixture, relative: []const u8) !void {
        _ = try root_fs.Path.initPackage(relative);
        try self.dir.createDirPath(self.io, relative);
    }

    pub fn write(self: Fixture, relative: []const u8, bytes: []const u8, mode: u32) !void {
        const path = try root_fs.Path.initPackage(relative);
        if (path.parent()) |parent_path|
            try self.dir.createDirPath(self.io, parent_path.text);
        var file = try self.dir.createFile(self.io, relative, .{
            .truncate = true,
            .permissions = .fromMode(mode),
        });
        defer file.close(self.io);
        try file.writeStreamingAll(self.io, bytes);
        try file.setPermissions(self.io, .fromMode(mode));
    }

    pub fn makeRoot(self: Fixture, relative: []const u8, architecture: []const u8) ![]u8 {
        const root_path = try self.absolute(relative);
        errdefer self.allocator.free(root_path);
        const admin = try std.fmt.allocPrint(self.allocator, "{s}/var/lib/dpkg", .{relative});
        defer self.allocator.free(admin);
        for ([_][]const u8{ "info", "updates", "triggers" }) |name| {
            const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ admin, name });
            defer self.allocator.free(path);
            try self.directory(path);
        }
        const mark = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ relative, guard });
        defer self.allocator.free(mark);
        try self.write(mark, guard_content, 0o600);
        const status = try std.fmt.allocPrint(self.allocator, "{s}/status", .{admin});
        defer self.allocator.free(status);
        try self.write(status, "", 0o644);
        const format = try std.fmt.allocPrint(self.allocator, "{s}/info/format", .{admin});
        defer self.allocator.free(format);
        try self.write(format, "1\n", 0o644);
        const arch_path = try std.fmt.allocPrint(self.allocator, "{s}/arch", .{admin});
        defer self.allocator.free(arch_path);
        const arch = try std.fmt.allocPrint(self.allocator, "{s}\n", .{architecture});
        defer self.allocator.free(arch);
        try self.write(arch_path, arch, 0o644);
        return root_path;
    }

    pub const Feature = enum { data, conffile, script, zero_time, obsolete_conffile, remove_on_upgrade };
    pub const ExtraFile = struct {
        path: []const u8,
        content: []const u8,
        mode: u32 = 0o644,
    };
    pub const PackageOptions = struct {
        workspace: []const u8 = "",
        name: []const u8 = package,
        conffile_content: []const u8 = "package configuration\n",
        extra_files: []const ExtraFile = &.{},
        control_fields: []const u8 = "",
    };

    pub fn makePackage(
        self: Fixture,
        architecture: []const u8,
        version: []const u8,
        feature: Feature,
    ) ![]u8 {
        return self.makePackageWith(architecture, version, feature, .{});
    }

    pub fn makePackageWith(
        self: Fixture,
        architecture: []const u8,
        version: []const u8,
        feature: Feature,
        options: PackageOptions,
    ) ![]u8 {
        const stem = try std.fmt.allocPrint(self.allocator, "{s}_{s}_{s}", .{ options.name, version, @tagName(feature) });
        defer self.allocator.free(stem);
        const source = if (options.workspace.len == 0)
            try std.fmt.allocPrint(self.allocator, "{s}.source", .{stem})
        else
            try std.fmt.allocPrint(self.allocator, "{s}/{s}.source", .{ options.workspace, stem });
        defer self.allocator.free(source);
        const data_payload = try std.fmt.allocPrint(self.allocator, "usr/share/{s}", .{options.name});
        defer self.allocator.free(data_payload);
        const control_path = try std.fmt.allocPrint(self.allocator, "{s}/DEBIAN/control", .{source});
        defer self.allocator.free(control_path);
        const control = try std.fmt.allocPrint(
            self.allocator,
            "Package: {s}\nVersion: {s}\nArchitecture: {s}\nMaintainer: debz fixture <fixture@example.invalid>\n{s}Description: native data-only materialization fixture\n",
            .{ options.name, version, architecture, options.control_fields },
        );
        defer self.allocator.free(control);
        try self.write(control_path, control, 0o644);
        const data_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}/data", .{ source, data_payload });
        defer self.allocator.free(data_path);
        const data = try std.fmt.allocPrint(self.allocator, "data version {s}\n", .{version});
        defer self.allocator.free(data);
        try self.write(data_path, data, 0o644);
        const link_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}/data.link", .{ source, data_payload });
        defer self.allocator.free(link_path);
        try std.Io.Dir.hardLink(self.dir, data_path, self.dir, link_path, self.io, .{});
        const current = try std.fmt.allocPrint(self.allocator, "{s}/{s}/current", .{ source, data_payload });
        defer self.allocator.free(current);
        try self.dir.symLink(self.io, "data", current, .{});
        const mode_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}/mode", .{ source, data_payload });
        defer self.allocator.free(mode_path);
        try self.write(mode_path, "permission-sensitive payload\n", if (std.mem.eql(u8, version, "1")) 0o600 else 0o640);
        const change_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/{s}",
            .{ source, data_payload, if (std.mem.eql(u8, version, "1")) "obsolete" else "introduced" },
        );
        defer self.allocator.free(change_path);
        const change = try std.fmt.allocPrint(self.allocator, "only in {s}\n", .{version});
        defer self.allocator.free(change);
        try self.write(change_path, change, 0o644);
        const empty = try std.fmt.allocPrint(self.allocator, "{s}/{s}/empty", .{ source, data_payload });
        defer self.allocator.free(empty);
        try self.directory(empty);
        try self.dir.setFilePermissions(self.io, empty, .fromMode(0o750), .{});
        if (feature == .conffile) {
            const conf = try std.fmt.allocPrint(self.allocator, "{s}/etc/debz-native.conf", .{source});
            defer self.allocator.free(conf);
            try self.write(conf, options.conffile_content, 0o644);
            const declaration = try std.fmt.allocPrint(self.allocator, "{s}/DEBIAN/conffiles", .{source});
            defer self.allocator.free(declaration);
            try self.write(declaration, "/etc/debz-native.conf\n", 0o644);
        } else if (feature == .script) {
            const script = try std.fmt.allocPrint(self.allocator, "{s}/DEBIAN/preinst", .{source});
            defer self.allocator.free(script);
            try self.write(script, "#!/bin/sh\nexit 99\n", 0o755);
        } else if (feature == .obsolete_conffile or feature == .remove_on_upgrade) {
            const etc = try std.fmt.allocPrint(self.allocator, "{s}/etc", .{source});
            defer self.allocator.free(etc);
            try self.directory(etc);
            if (feature == .remove_on_upgrade) {
                const declaration = try std.fmt.allocPrint(self.allocator, "{s}/DEBIAN/conffiles", .{source});
                defer self.allocator.free(declaration);
                try self.write(declaration, "remove-on-upgrade /etc/debz-native.conf\n", 0o644);
            }
        }
        for (options.extra_files) |file| {
            _ = try root_fs.Path.initPackage(file.path);
            const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ source, file.path });
            defer self.allocator.free(path);
            try self.write(path, file.content, file.mode);
        }
        const destination = if (options.workspace.len == 0)
            try std.fmt.allocPrint(self.allocator, "{s}.deb", .{stem})
        else
            try std.fmt.allocPrint(self.allocator, "{s}/{s}.deb", .{ options.workspace, stem });
        defer self.allocator.free(destination);
        const zero = try std.fmt.allocPrint(self.allocator, "{s}/empty", .{data_payload});
        defer self.allocator.free(zero);
        return self.buildPackage(source, destination, .{
            .zero_time_path = if (feature == .zero_time) zero else null,
        });
    }

    pub const BuildOptions = struct {
        zero_time_path: ?[]const u8 = null,
        compression: enum { gzip, none } = .gzip,
    };

    /// Assemble a package from a fixture-owned source tree, including the
    /// installed-file checksum manifest. Callers can add scripts, conffiles,
    /// triggers and custom payloads with write/directory before building.
    pub fn buildPackage(
        self: Fixture,
        source: []const u8,
        destination: []const u8,
        options: BuildOptions,
    ) ![]u8 {
        _ = try root_fs.Path.init(source);
        _ = try root_fs.Path.init(destination);
        if (options.zero_time_path) |path| _ = try root_fs.Path.init(path);
        var source_dir = try self.dir.openDir(self.io, source, .{ .iterate = true, .follow_symlinks = false });
        defer source_dir.close(self.io);
        const root: root_fs.Root = .init(self.io, source_dir);
        const Manifest = struct { path: []const u8, digest: [32]u8 };
        var files: std.ArrayList(Manifest) = .empty;
        defer {
            for (files.items) |file| self.allocator.free(file.path);
            files.deinit(self.allocator);
        }
        {
            var walker = try source_dir.walk(self.allocator);
            defer walker.deinit();
            while (try walker.next(self.io)) |entry| {
                if (entry.kind != .file or std.mem.eql(u8, entry.path, "DEBIAN") or
                    std.mem.startsWith(u8, entry.path, "DEBIAN/")) continue;
                const relative = try self.allocator.dupe(u8, entry.path);
                errdefer self.allocator.free(relative);
                const bytes = try root.readFileAlloc(self.allocator, try root_fs.Path.initPackage(relative), max_database_bytes);
                defer self.allocator.free(bytes);
                var md5: [16]u8 = undefined;
                std.crypto.hash.Md5.hash(bytes, &md5, .{});
                try files.append(self.allocator, .{ .path = relative, .digest = std.fmt.bytesToHex(md5, .lower) });
            }
        }
        std.mem.sort(Manifest, files.items, {}, struct {
            fn less(_: void, left: Manifest, right: Manifest) bool {
                return std.mem.lessThan(u8, left.path, right.path);
            }
        }.less);
        var checksums: std.ArrayList(u8) = .empty;
        defer checksums.deinit(self.allocator);
        for (files.items) |file| {
            const line = try std.fmt.allocPrint(self.allocator, "{s}  {s}\n", .{ file.digest, file.path });
            defer self.allocator.free(line);
            try checksums.appendSlice(self.allocator, line);
        }
        const md5_path = try std.fmt.allocPrint(self.allocator, "{s}/DEBIAN/md5sums", .{source});
        defer self.allocator.free(md5_path);
        try self.write(md5_path, checksums.items, 0o644);
        {
            var walker = try source_dir.walk(self.allocator);
            defer walker.deinit();
            while (try walker.next(self.io)) |entry| {
                const path = try root_fs.Path.initPackage(entry.path);
                try root.applyMetadata(path, .{
                    .modified_nanoseconds = (if (options.zero_time_path) |zero| (if (std.mem.eql(u8, entry.path, zero)) @as(i128, 0) else epoch) else epoch) * std.time.ns_per_s,
                });
            }
        }
        try source_dir.setTimestamps(self.io, ".", .{
            .modify_timestamp = .{ .new = .{ .nanoseconds = epoch * std.time.ns_per_s } },
        });

        const source_abs = try self.absolute(source);
        defer self.allocator.free(source_abs);
        const archive_abs = try self.absolute(destination);
        errdefer self.allocator.free(archive_abs);
        const log_name = try std.fmt.allocPrint(self.allocator, "{s}.build.log", .{destination});
        defer self.allocator.free(log_name);
        const argv: []const []const u8 = switch (options.compression) {
            .gzip => &.{ "dpkg-deb", "--build", "--uniform-compression", "-Zgzip", "-z1", source_abs, archive_abs },
            .none => &.{ "dpkg-deb", "--build", "--uniform-compression", "-Znone", source_abs, archive_abs },
        };
        try self.run(argv, log_name, 120);
        return archive_abs;
    }

    pub fn run(self: Fixture, argv: []const []const u8, log_path: []const u8, seconds: i64) !void {
        if (argv.len == 0 or seconds < 1 or seconds > 600) return error.InvalidProcessInvocation;
        const duration = try std.fmt.allocPrint(self.allocator, "{d}s", .{seconds});
        defer self.allocator.free(duration);
        var guarded_argv: std.ArrayList([]const u8) = .empty;
        defer guarded_argv.deinit(self.allocator);
        try guarded_argv.appendSlice(self.allocator, &.{ "/usr/bin/timeout", "--kill-after=2s", duration });
        try guarded_argv.appendSlice(self.allocator, argv);
        const result = std.process.run(self.allocator, self.io, .{
            .argv = guarded_argv.items,
            .environ_map = &self.environment,
            .stdout_limit = .limited(1024 * 1024),
            .stderr_limit = .limited(1024 * 1024),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(seconds + 5), .clock = .awake } },
        }) catch |err| {
            const message = try std.fmt.allocPrint(self.allocator, "{s}: {s}\n", .{ argv[0], @errorName(err) });
            defer self.allocator.free(message);
            try self.write(log_path, message, 0o644);
            return err;
        };
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        const timed_out = switch (result.term) {
            .exited => |code| code == 124,
            .signal => |signal| signal == .KILL,
            else => false,
        };
        const note = if (timed_out)
            try std.fmt.allocPrint(self.allocator, "{s}: timed out after {d}s\n", .{ argv[0], seconds })
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(note);
        const combined = try std.mem.concat(self.allocator, u8, &.{ result.stdout, result.stderr, note });
        defer self.allocator.free(combined);
        try self.write(log_path, combined, 0o644);
        if (timed_out) return error.Timeout;
        switch (result.term) {
            .exited => |code| if (code != 0) {
                if (self.diagnostics) std.debug.print("{s} exited {d}; {s}/{s}\n{s}\n", .{
                    argv[0], code, self.path, log_path, combined[0..@min(combined.len, 12_000)],
                });
                return error.ChildFailed;
            },
            else => return error.ChildFailed,
        }
    }
};

pub fn openRealDirectory(io: std.Io, absolute: []const u8) !std.Io.Dir {
    if (absolute.len < 2 or absolute[0] != '/' or absolute[absolute.len - 1] == '/')
        return error.NotDisposableRoot;
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .iterate = true, .follow_symlinks = false });
    errdefer current.close(io);
    var components = std.mem.splitScalar(u8, absolute[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.NotDisposableRoot;
        const next = current.openDir(io, component, .{ .iterate = true, .follow_symlinks = false }) catch
            return error.NotDisposableRoot;
        current.close(io);
        current = next;
    }
    return current;
}

pub fn guardedRoot(io: std.Io, root_path: []const u8) !std.Io.Dir {
    var dir = try openRealDirectory(io, root_path);
    errdefer dir.close(io);
    const root: root_fs.Root = .init(io, dir);
    const marker = root.readFileAlloc(std.heap.page_allocator, try root_fs.Path.init(guard), 128) catch
        return error.NotDisposableRoot;
    defer std.heap.page_allocator.free(marker);
    if (!std.mem.eql(u8, marker, guard_content)) return error.NotDisposableRoot;
    return dir;
}

pub fn hostDpkg(allocator: std.mem.Allocator, io: std.Io, search_path: []const u8) ![]u8 {
    var entries = std.mem.splitScalar(u8, search_path, ':');
    while (entries.next()) |entry| {
        const directory = if (std.fs.path.isAbsolute(entry))
            try allocator.dupe(u8, entry)
        else blk: {
            const cwd = try std.process.currentPathAlloc(io, allocator);
            defer allocator.free(cwd);
            break :blk try std.fs.path.join(allocator, &.{ cwd, entry });
        };
        defer allocator.free(directory);
        const candidate = try std.fs.path.join(allocator, &.{ directory, "dpkg" });
        const metadata = std.Io.Dir.cwd().statFile(io, candidate, .{ .follow_symlinks = true }) catch {
            allocator.free(candidate);
            continue;
        };
        if (metadata.kind != .file) {
            allocator.free(candidate);
            continue;
        }
        std.Io.Dir.cwd().access(io, candidate, .{ .execute = true }) catch {
            allocator.free(candidate);
            continue;
        };
        return candidate;
    }
    return error.ReferenceDpkgNotFound;
}

pub fn selectReference(allocator: std.mem.Allocator, io: std.Io, path: ?[]const u8, architecture: []const u8, host_dpkg: []const u8) ![]const u8 {
    if (!std.mem.eql(u8, architecture, "amd64") and !std.mem.eql(u8, architecture, "arm64"))
        return error.UnsupportedArchitecture;
    const selected = path orelse host_dpkg;
    if (path != null) {
        const digest_hex = if (std.mem.eql(u8, architecture, "amd64"))
            "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5"
        else
            "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79";
        const parent = std.fs.path.dirname(selected) orelse return error.InvalidReferencePath;
        var dir = try openRealDirectory(io, parent);
        defer dir.close(io);
        var file = try dir.openFile(io, std.fs.path.basename(selected), .{
            .follow_symlinks = false,
            .allow_directory = false,
        });
        defer file.close(io);
        const size = (try file.stat(io)).size;
        if (size > 8 * 1024 * 1024) return error.ReferenceTooLarge;
        var reader = file.reader(io, &.{});
        const bytes = try reader.interface.allocRemaining(allocator, .limited(8 * 1024 * 1024 + 1));
        defer allocator.free(bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), digest_hex))
            return error.ReferenceDigestMismatch;
    }
    const version = try std.process.run(allocator, io, .{
        .argv = &.{ selected, "--version" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer allocator.free(version.stdout);
    defer allocator.free(version.stderr);
    if (version.term != .exited or version.term.exited != 0 or
        std.mem.indexOf(u8, version.stdout, "version ") == null)
        return error.InvalidReferenceVersion;
    if (path != null and std.mem.indexOf(u8, version.stdout, "version 1.22.22") == null)
        return error.InvalidReferenceVersion;
    return selected;
}

pub fn hostArchitecture(allocator: std.mem.Allocator, io: std.Io, host_dpkg: []const u8) ![]u8 {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ host_dpkg, "--print-architecture" },
        .stdout_limit = .limited(64),
        .stderr_limit = .limited(1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) return error.NoHostArchitecture;
    const trimmed = std.mem.trim(u8, result.stdout, " \r\n");
    if (!std.mem.eql(u8, trimmed, "amd64") and !std.mem.eql(u8, trimmed, "arm64"))
        return error.UnsupportedArchitecture;
    const copy = try allocator.dupe(u8, trimmed);
    allocator.free(result.stdout);
    return copy;
}

pub fn hostStatusDigest(allocator: std.mem.Allocator, io: std.Io) ![32]u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, "/var/lib/dpkg/status", .{ .follow_symlinks = false });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    const bytes = try reader.interface.allocRemaining(allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

const FilesystemEntry = struct {
    path: []const u8,
    kind: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_ns: ?i128 = null,
    size: ?u64 = null,
    sha256: ?[64]u8 = null,
    device_major: ?u32 = null,
    device_minor: ?u32 = null,
    target: ?[]const u8 = null,
    hardlink_to: ?[]const u8 = null,
    xattrs: []const Attribute = &.{},
};

const Attribute = struct {
    name: []const u8,
    value_hex: []const u8,
};

const DatabaseEntry = struct {
    path: []const u8,
    kind: []const u8,
    mode: u32,
    uid: u32 = 0,
    gid: u32 = 0,
    content: []const u8,
    size: ?u64 = null,
};

const Dpkg = struct {
    present: bool,
    status: []const u8,
    status_old: []const u8,
    info: []const DatabaseEntry,
    triggers: []const DatabaseEntry,
    updates: []const DatabaseEntry,
    alternatives: []const DatabaseEntry,
    parts: []const DatabaseEntry,
    staging: []const DatabaseEntry,
    files: []const DatabaseEntry,
};

const Snapshot = struct {
    schema: []const u8 = "https://debz.dev/test/native-transaction-snapshot-v1",
    version: u32 = 1,
    filesystem: []const FilesystemEntry,
    dpkg: Dpkg,
    trace: []const []const u8,
};

fn lessPath(_: void, left: FilesystemEntry, right: FilesystemEntry) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

fn lessDatabase(_: void, left: DatabaseEntry, right: DatabaseEntry) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

fn lessText(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn lessAttribute(_: void, left: Attribute, right: Attribute) bool {
    return std.mem.lessThan(u8, left.name, right.name);
}

fn sha(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn readOptional(root: root_fs.Root, allocator: std.mem.Allocator, path: []const u8, limit: usize) ![]const u8 {
    const relative = try root_fs.Path.init(path);
    const entry = try root.entryIfExists(relative) orelse return "";
    if (entry.kind != .file or entry.size > limit) return error.UnsafeDatabaseEntry;
    return root.readFileAlloc(allocator, relative, limit);
}

fn normalizedLines(allocator: std.mem.Allocator, content: []const u8, path_list: bool) ![]const u8 {
    if (!std.unicode.utf8ValidateSlice(content)) return error.InvalidDatabaseText;
    var lines: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (path_list and (line[0] != '/' or std.mem.indexOfScalar(u8, line, 0) != null))
            return error.UnsafePackagePath;
        try lines.append(allocator, line);
    }
    std.mem.sort([]const u8, lines.items, {}, lessText);
    if (path_list and lines.items.len > 1) for (lines.items[1..], lines.items[0 .. lines.items.len - 1]) |after, before| {
        if (std.mem.eql(u8, after, before)) return error.DuplicatePackagePath;
    };
    return std.mem.join(allocator, "\n", lines.items);
}

fn normalizedMd5(allocator: std.mem.Allocator, content: []const u8) ![]const u8 {
    if (!std.unicode.utf8ValidateSlice(content)) return error.InvalidDatabaseText;
    var lines: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (line.len < 35 or line[32] != ' ' or line[33] != ' ' or
            line[34] == '/' or
            std.mem.indexOfScalar(u8, line, 0) != null)
            return error.InvalidMd5sums;
        _ = root_fs.Path.initPackage(line[34..]) catch return error.InvalidMd5sums;
        for (line[0..32]) |digit| {
            if (!std.ascii.isDigit(digit) and (digit < 'a' or digit > 'f'))
                return error.InvalidMd5sums;
        }
        try lines.append(allocator, try std.fmt.allocPrint(allocator, "{s} {s}", .{ line[34..], line[0..32] }));
    }
    std.mem.sort([]const u8, lines.items, {}, lessText);
    return std.mem.join(allocator, "\n", lines.items);
}

const Diversion = struct {
    path: []const u8,
    destination: []const u8,
    package_name: []const u8,
};

fn lessDiversion(_: void, left: Diversion, right: Diversion) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

fn normalizedDiversions(allocator: std.mem.Allocator, content: []const u8) ![]const u8 {
    if (!std.unicode.utf8ValidateSlice(content)) return error.InvalidDatabaseText;
    if (content.len == 0) return "";
    var lines: std.ArrayList([]const u8) = .empty;
    const text = if (content[content.len - 1] == '\n') content[0 .. content.len - 1] else content;
    var iterator = std.mem.splitScalar(u8, text, '\n');
    while (iterator.next()) |line| try lines.append(allocator, std.mem.trimEnd(u8, line, "\r"));
    if (lines.items.len % 3 != 0) return error.InvalidDiversions;
    var records: std.ArrayList(Diversion) = .empty;
    for (0..lines.items.len / 3) |index| {
        const line = lines.items[index * 3 ..][0..3];
        if (line[0].len == 0 or line[0][0] != '/' or
            line[1].len == 0 or line[1][0] != '/' or
            line[2].len == 0 or
            std.mem.indexOfScalar(u8, line[0], 0) != null or
            std.mem.indexOfScalar(u8, line[1], 0) != null)
            return error.InvalidDiversions;
        try records.append(allocator, .{ .path = line[0], .destination = line[1], .package_name = line[2] });
    }
    std.mem.sort(Diversion, records.items, {}, lessDiversion);
    var normalized: std.ArrayList([]const u8) = .empty;
    for (records.items, 0..) |record, index| {
        if (index > 0 and std.mem.eql(u8, record.path, records.items[index - 1].path))
            return error.InvalidDiversions;
        try normalized.append(allocator, try std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}", .{
            record.path, record.destination, record.package_name,
        }));
    }
    return std.mem.join(allocator, "\n", normalized.items);
}

const Override = struct {
    path: []const u8,
    owner: []const u8,
    group: []const u8,
    mode: []const u8,
};

fn lessOverride(_: void, left: Override, right: Override) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

fn normalizedStatoverride(allocator: std.mem.Allocator, content: []const u8) ![]const u8 {
    if (!std.unicode.utf8ValidateSlice(content)) return error.InvalidDatabaseText;
    if (content.len == 0) return "";
    var records: std.ArrayList(Override) = .empty;
    const text = if (content[content.len - 1] == '\n') content[0 .. content.len - 1] else content;
    var iterator = std.mem.splitScalar(u8, text, '\n');
    while (iterator.next()) |line| {
        const a = std.mem.indexOfScalar(u8, line, ' ') orelse return error.InvalidStatoverride;
        const b = std.mem.indexOfScalarPos(u8, line, a + 1, ' ') orelse return error.InvalidStatoverride;
        const c = std.mem.indexOfScalarPos(u8, line, b + 1, ' ') orelse return error.InvalidStatoverride;
        const mode = line[b + 1 .. c];
        if (a == 0 or a + 1 == b or mode.len < 3 or mode.len > 6 or
            c + 1 == line.len or line[c + 1] != '/' or
            std.mem.indexOfScalar(u8, line, 0) != null)
            return error.InvalidStatoverride;
        for (mode) |digit| if (digit < '0' or digit > '7') return error.InvalidStatoverride;
        try records.append(allocator, .{
            .owner = line[0..a],
            .group = line[a + 1 .. b],
            .mode = mode,
            .path = line[c + 1 ..],
        });
    }
    std.mem.sort(Override, records.items, {}, lessOverride);
    var normalized: std.ArrayList([]const u8) = .empty;
    for (records.items, 0..) |record, index| {
        if (index > 0 and std.mem.eql(u8, record.path, records.items[index - 1].path))
            return error.InvalidStatoverride;
        try normalized.append(allocator, try std.fmt.allocPrint(allocator, "{s} {s} {s} {s}", .{
            record.owner, record.group, record.mode, record.path,
        }));
    }
    return std.mem.join(allocator, "\n", normalized.items);
}

fn normalizedDeb822(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidDatabaseText;
    var paragraphs: std.ArrayList([]const u8) = .empty;
    var fields: std.StringHashMap([]const u8) = .init(allocator);
    defer fields.deinit();
    var previous: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) {
            if (fields.count() != 0) {
                try paragraphs.append(allocator, try sortedFields(allocator, &fields));
                fields.clearRetainingCapacity();
            }
            previous = null;
            continue;
        }
        if (line[0] == ' ' or line[0] == '\t') {
            const key = previous orelse return error.InvalidDeb822;
            const old = fields.get(key).?;
            try fields.put(key, try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ old, line[1..] }));
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidDeb822;
        if (colon == 0) return error.InvalidDeb822;
        const key = try std.ascii.allocLowerString(allocator, line[0..colon]);
        for (key) |c| if (std.ascii.isWhitespace(c)) return error.InvalidDeb822;
        if (fields.contains(key)) return error.InvalidDeb822;
        try fields.put(key, std.mem.trimStart(u8, line[colon + 1 ..], " \t"));
        previous = key;
    }
    if (fields.count() != 0) try paragraphs.append(allocator, try sortedFields(allocator, &fields));
    std.mem.sort([]const u8, paragraphs.items, {}, lessText);
    return std.mem.join(allocator, "\n\n", paragraphs.items);
}

fn sortedFields(allocator: std.mem.Allocator, fields: *std.StringHashMap([]const u8)) ![]const u8 {
    var keys: std.ArrayList([]const u8) = .empty;
    var iterator = fields.keyIterator();
    while (iterator.next()) |key| try keys.append(allocator, key.*);
    std.mem.sort([]const u8, keys.items, {}, lessText);
    var lines: std.ArrayList([]const u8) = .empty;
    for (keys.items) |key| {
        const value = try std.mem.replaceOwned(u8, allocator, fields.get(key).?, "\n", "\n ");
        try lines.append(allocator, try std.fmt.allocPrint(allocator, "{s}:{s}", .{ key, value }));
    }
    return std.mem.join(allocator, "\n", lines.items);
}

fn captureXattrs(allocator: std.mem.Allocator, absolute: []const u8) ![]const Attribute {
    const linux = std.os.linux;
    const path = try allocator.dupeZ(u8, absolute);
    const probe = linux.llistxattr(path, undefined, 0);
    const size = switch (linux.errno(probe)) {
        .SUCCESS => probe,
        .OPNOTSUPP => return &.{},
        else => return error.InvalidFilesystemXattrs,
    };
    if (size > 64 * 1024) return error.InvalidFilesystemXattrs;
    const names = try allocator.alloc(u8, size);
    const read = linux.llistxattr(path, names.ptr, names.len);
    if (linux.errno(read) != .SUCCESS or read != size) return error.InvalidFilesystemXattrs;
    var attributes: std.ArrayList(Attribute) = .empty;
    var start: usize = 0;
    var total: usize = 0;
    while (start < size) {
        if (attributes.items.len == 64) return error.InvalidFilesystemXattrs;
        const end = std.mem.indexOfScalarPos(u8, names, start, 0) orelse return error.InvalidFilesystemXattrs;
        const name = try allocator.dupeZ(u8, names[start..end]);
        const needed = linux.lgetxattr(path, name, undefined, 0);
        if (linux.errno(needed) != .SUCCESS or needed > 1024 * 1024) return error.InvalidFilesystemXattrs;
        total += name.len + needed;
        if (total > 1024 * 1024) return error.InvalidFilesystemXattrs;
        const value = try allocator.alloc(u8, needed);
        const got = linux.lgetxattr(path, name, value.ptr, value.len);
        if (linux.errno(got) != .SUCCESS or got != needed) return error.InvalidFilesystemXattrs;
        const value_hex = try allocator.alloc(u8, value.len * 2);
        const digits = "0123456789abcdef";
        for (value, 0..) |byte, index| {
            value_hex[2 * index] = digits[byte >> 4];
            value_hex[2 * index + 1] = digits[byte & 15];
        }
        try attributes.append(allocator, .{
            .name = name,
            .value_hex = value_hex,
        });
        start = end + 1;
    }
    std.mem.sort(Attribute, attributes.items, {}, lessAttribute);
    return attributes.items;
}

fn captureFilesystem(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    absolute: []const u8,
    limits: SnapshotLimits,
    excludes: []const []const u8,
) ![]const FilesystemEntry {
    const root: root_fs.Root = .init(io, root_dir);
    var entries: std.ArrayList(FilesystemEntry) = .empty;
    var identities: std.ArrayList(struct { device: u64, inode: u64 }) = .empty;
    var walker = try root_dir.walk(allocator);
    defer walker.deinit();
    var total_bytes: u64 = 0;
    while (try walker.next(io)) |child| {
        const path = child.path;
        var excluded = false;
        for (excludes) |prefix| {
            if (std.mem.eql(u8, path, prefix) or
                (std.mem.startsWith(u8, path, prefix) and path.len > prefix.len and path[prefix.len] == '/'))
            {
                excluded = true;
                break;
            }
        }
        if (excluded) {
            if (child.kind == .directory) walker.leave(io);
            continue;
        }
        if (entries.items.len >= limits.max_entries) return error.FilesystemEntryLimit;
        const relative = try allocator.dupe(u8, path);
        const metadata = try root.entry(try root_fs.Path.initPackage(relative));
        if (!metadata.modeled) return error.UnsupportedFilesystemMetadata;
        const full = try std.fs.path.join(allocator, &.{ absolute, relative });
        const item: FilesystemEntry = .{
            .path = relative,
            .kind = switch (metadata.kind) {
                .file => "regular",
                .directory => "directory",
                .sym_link => "symlink",
                .character_device => "character-device",
                .block_device => "block-device",
                .named_pipe => "fifo",
                .unix_domain_socket => "socket",
                else => "unknown",
            },
            .mode = metadata.mode,
            .uid = metadata.uid,
            .gid = metadata.gid,
            .mtime_ns = if (metadata.kind == .directory) null else metadata.modified_nanoseconds,
            .size = if (metadata.kind == .file) metadata.size else null,
            .xattrs = try captureXattrs(allocator, full),
        };
        var appended = item;
        if (metadata.kind == .file) {
            if (metadata.size > limits.max_file_bytes) return error.FilesystemFileLimit;
            total_bytes += metadata.size;
            if (total_bytes > limits.max_total_regular_bytes) return error.FilesystemFileLimit;
            var file = try root.openRegularFile(try root_fs.Path.initPackage(relative));
            defer file.close(io);
            const opened = try file.stat(io);
            if (opened.size != metadata.size or opened.inode != metadata.inode)
                return error.FilesystemChanged;
            var reader = file.reader(io, &.{});
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            var buffer: [64 * 1024]u8 = undefined;
            var read: u64 = 0;
            while (true) {
                const count = reader.interface.readSliceShort(&buffer) catch return reader.err.?;
                if (count == 0) break;
                read += count;
                if (read > metadata.size) return error.FilesystemChanged;
                hash.update(buffer[0..count]);
            }
            if (read != metadata.size or (try file.stat(io)).size != read)
                return error.FilesystemChanged;
            var digest: [32]u8 = undefined;
            hash.final(&digest);
            appended.sha256 = std.fmt.bytesToHex(digest, .lower);
        } else if (metadata.kind == .sym_link) {
            var buffer: [4096]u8 = undefined;
            appended.target = try allocator.dupe(u8, try root.readSymbolicLink(
                try root_fs.Path.initPackage(relative),
                &buffer,
            ));
        } else if (metadata.kind == .character_device or metadata.kind == .block_device) {
            const linux = std.os.linux;
            const path_z = try allocator.dupeZ(u8, relative);
            var info: linux.Statx = undefined;
            if (linux.errno(linux.statx(root_dir.handle, path_z, linux.AT.SYMLINK_NOFOLLOW, .{
                .TYPE = true,
                .MODE = true,
            }, &info)) != .SUCCESS) return error.UnsupportedFilesystemEntry;
            appended.device_major = info.rdev_major;
            appended.device_minor = info.rdev_minor;
        }
        try entries.append(allocator, appended);
        try identities.append(allocator, .{ .device = metadata.device, .inode = metadata.inode });
    }
    const Inode = struct { device: u64, inode: u64 };
    const Group = struct { count: usize, first: []const u8 };
    var groups: std.AutoHashMap(Inode, Group) = .init(allocator);
    defer groups.deinit();
    for (entries.items, identities.items) |entry, identity| {
        if (!std.mem.eql(u8, entry.kind, "regular")) continue;
        const selected = try groups.getOrPut(.{ .device = identity.device, .inode = identity.inode });
        if (selected.found_existing) {
            selected.value_ptr.count += 1;
            if (std.mem.lessThan(u8, entry.path, selected.value_ptr.first))
                selected.value_ptr.first = entry.path;
        } else selected.value_ptr.* = .{ .count = 1, .first = entry.path };
    }
    for (entries.items, identities.items) |*entry, identity| {
        if (!std.mem.eql(u8, entry.kind, "regular")) continue;
        const group = groups.get(.{ .device = identity.device, .inode = identity.inode }).?;
        if (group.count > 1) entry.hardlink_to = group.first;
    }
    std.mem.sort(FilesystemEntry, entries.items, {}, lessPath);
    return entries.items;
}

const DatabaseBudget = struct { entries: usize = 0, bytes: u64 = 0 };

fn countDatabase(budget: *DatabaseBudget, limits: SnapshotLimits, bytes: u64) !void {
    budget.entries += 1;
    budget.bytes += bytes;
    if (budget.entries > limits.max_entries) return error.DatabaseEntryLimit;
    if (budget.bytes > limits.max_total_regular_bytes) return error.DatabaseByteLimit;
}

fn captureDatabaseDirectory(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: root_fs.Root,
    relative: []const u8,
    limits: SnapshotLimits,
    budget: *DatabaseBudget,
) ![]const DatabaseEntry {
    const present = try root.entryIfExists(try root_fs.Path.init(relative)) orelse return &.{};
    if (present.kind != .directory) return error.UnsafeDatabaseEntry;
    var dir = try root.openDirectory(try root_fs.Path.init(relative));
    defer dir.close(io);
    var result: std.ArrayList(DatabaseEntry) = .empty;
    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (std.mem.eql(u8, relative, "var/lib/dpkg/triggers") and std.mem.eql(u8, entry.name, "Lock"))
            continue;
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ relative, entry.name });
        const metadata = try root.entry(try root_fs.Path.init(path));
        if (metadata.kind != .file or metadata.size > limits.max_database_file_bytes)
            return error.UnsafeDatabaseEntry;
        const bytes = try root.readFileAlloc(allocator, try root_fs.Path.init(path), limits.max_database_file_bytes);
        try countDatabase(budget, limits, bytes.len);
        var kind: []const u8 = "opaque";
        const content = if (std.mem.endsWith(u8, entry.name, ".list")) content: {
            kind = "path-list";
            break :content try normalizedLines(allocator, bytes, true);
        } else if (std.mem.endsWith(u8, entry.name, ".md5sums")) content: {
            kind = "md5sums";
            break :content try normalizedMd5(allocator, bytes);
        } else if (std.mem.eql(u8, relative, "var/lib/dpkg/triggers")) content: {
            kind = "line-set";
            break :content try normalizedLines(allocator, bytes, false);
        } else if (std.mem.eql(u8, relative, "var/lib/dpkg/updates")) content: {
            kind = "deb822";
            break :content try normalizedDeb822(allocator, bytes);
        } else content: {
            const digest = sha(bytes);
            break :content try allocator.dupe(u8, &digest);
        };
        try result.append(allocator, .{
            .path = path,
            .kind = kind,
            .mode = metadata.mode,
            .uid = metadata.uid,
            .gid = metadata.gid,
            .content = content,
            .size = if (std.mem.eql(u8, kind, "opaque")) bytes.len else null,
        });
    }
    std.mem.sort(DatabaseEntry, result.items, {}, lessDatabase);
    return result.items;
}

fn captureDpkg(allocator: std.mem.Allocator, io: std.Io, root: root_fs.Root, limits: SnapshotLimits) !Dpkg {
    const admin = "var/lib/dpkg";
    const status = try root.entryIfExists(try root_fs.Path.init(admin));
    if (status == null) return .{
        .present = false,
        .status = "",
        .status_old = "",
        .info = &.{},
        .triggers = &.{},
        .updates = &.{},
        .alternatives = &.{},
        .parts = &.{},
        .staging = &.{},
        .files = &.{},
    };
    if (status.?.kind != .directory) return error.UnsafeDatabaseEntry;
    const status_bytes = try readOptional(root, allocator, admin ++ "/status", limits.max_database_file_bytes);
    const old_bytes = try readOptional(root, allocator, admin ++ "/status-old", limits.max_database_file_bytes);
    var budget: DatabaseBudget = .{ .bytes = status_bytes.len + old_bytes.len };
    if (budget.bytes > limits.max_total_regular_bytes) return error.DatabaseByteLimit;
    var dir = try root.openDirectory(try root_fs.Path.init(admin));
    defer dir.close(io);
    var files: std.ArrayList(DatabaseEntry) = .empty;
    var iterator = dir.iterate();
    const known = [_][]const u8{
        "status", "status-old", "info", "triggers",      "updates", "alternatives",
        "parts",  "tmp.ci",     "lock", "lock-frontend",
    };
    while (try iterator.next(io)) |entry| {
        var skip = false;
        for (known) |name| if (std.mem.eql(u8, entry.name, name)) {
            skip = true;
            break;
        };
        if (skip) continue;
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ admin, entry.name });
        const metadata = try root.entry(try root_fs.Path.init(path));
        if (metadata.kind != .file or metadata.size > limits.max_database_file_bytes) return error.UnsafeDatabaseEntry;
        const bytes = try root.readFileAlloc(allocator, try root_fs.Path.init(path), limits.max_database_file_bytes);
        try countDatabase(&budget, limits, bytes.len);
        var kind: []const u8 = "opaque";
        const content = if (std.mem.eql(u8, entry.name, "arch")) content: {
            kind = "line-set";
            break :content try normalizedLines(allocator, bytes, false);
        } else if (std.mem.eql(u8, entry.name, "available")) content: {
            kind = "deb822";
            break :content try normalizedDeb822(allocator, bytes);
        } else if (std.mem.eql(u8, entry.name, "diversions")) content: {
            kind = "diversions";
            break :content try normalizedDiversions(allocator, bytes);
        } else if (std.mem.eql(u8, entry.name, "statoverride")) content: {
            kind = "statoverride";
            break :content try normalizedStatoverride(allocator, bytes);
        } else content: {
            const digest = sha(bytes);
            break :content try allocator.dupe(u8, &digest);
        };
        try files.append(allocator, .{
            .path = path,
            .kind = kind,
            .mode = metadata.mode,
            .content = content,
            .size = if (std.mem.eql(u8, kind, "opaque")) bytes.len else null,
        });
    }
    std.mem.sort(DatabaseEntry, files.items, {}, lessDatabase);
    return .{
        .present = true,
        .status = try normalizedDeb822(allocator, status_bytes),
        .status_old = try normalizedDeb822(allocator, old_bytes),
        .info = try captureDatabaseDirectory(allocator, io, root, admin ++ "/info", limits, &budget),
        .triggers = try captureDatabaseDirectory(allocator, io, root, admin ++ "/triggers", limits, &budget),
        .updates = try captureDatabaseDirectory(allocator, io, root, admin ++ "/updates", limits, &budget),
        .alternatives = try captureDatabaseDirectory(allocator, io, root, admin ++ "/alternatives", limits, &budget),
        .parts = try captureDatabaseDirectory(allocator, io, root, admin ++ "/parts", limits, &budget),
        .staging = try captureDatabaseDirectory(allocator, io, root, admin ++ "/tmp.ci", limits, &budget),
        .files = files.items,
    };
}

pub fn capture(allocator: std.mem.Allocator, io: std.Io, absolute: []const u8) ![]u8 {
    return captureWithLimits(allocator, io, absolute, .{});
}

pub fn captureWithLimits(
    allocator: std.mem.Allocator,
    io: std.Io,
    absolute: []const u8,
    limits: SnapshotLimits,
) ![]u8 {
    return captureImage(allocator, io, absolute, limits, true, &.{
        "var/lib/debz", "var/lib/dpkg", "var/log/debz-native-differential.trace", guard,
    });
}

pub fn captureRealRoot(
    allocator: std.mem.Allocator,
    io: std.Io,
    absolute: []const u8,
    limits: SnapshotLimits,
    extra_excludes: []const []const u8,
) ![]u8 {
    var excludes: std.ArrayList([]const u8) = .empty;
    defer excludes.deinit(allocator);
    try excludes.appendSlice(allocator, &.{
        "var/lib/debz", "var/lib/dpkg", "var/log/debz-native-differential.trace",
    });
    for (extra_excludes) |entry| {
        _ = try root_fs.Path.init(entry);
        try excludes.append(allocator, entry);
    }
    return captureImage(allocator, io, absolute, limits, false, excludes.items);
}

fn captureImage(
    allocator: std.mem.Allocator,
    io: std.Io,
    absolute: []const u8,
    limits: SnapshotLimits,
    guarded: bool,
    excludes: []const []const u8,
) ![]u8 {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var dir = if (guarded) try guardedRoot(io, absolute) else try openRealDirectory(io, absolute);
    defer dir.close(io);
    const root: root_fs.Root = .init(io, dir);
    const trace_bytes = try readOptional(root, a, "var/log/debz-native-differential.trace", limits.max_trace_bytes);
    if (trace_bytes.len > limits.max_trace_bytes) return error.TraceTooLong;
    if (!std.unicode.utf8ValidateSlice(trace_bytes)) return error.InvalidTrace;
    var trace: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, trace_bytes, '\n');
    var offset: usize = 0;
    while (lines.next()) |raw| {
        offset += raw.len + 1;
        if (raw.len == 0 and offset > trace_bytes.len) break;
        try trace.append(a, std.mem.trimEnd(u8, raw, "\r"));
    }
    const image: Snapshot = .{
        .filesystem = try captureFilesystem(a, io, dir, absolute, limits, excludes),
        .dpkg = try captureDpkg(a, io, root, limits),
        .trace = trace.items,
    };
    return std.json.Stringify.valueAlloc(allocator, image, .{ .whitespace = .indent_2 });
}

pub fn compare(
    fixture: Fixture,
    expected_root: []const u8,
    candidate: []const u8,
    destination: []const u8,
) !void {
    const expected = try capture(fixture.allocator, fixture.io, expected_root);
    defer fixture.allocator.free(expected);
    const actual = try capture(fixture.allocator, fixture.io, candidate);
    defer fixture.allocator.free(actual);
    const expected_file = try std.fmt.allocPrint(fixture.allocator, "{s}/reference.snapshot.json", .{destination});
    defer fixture.allocator.free(expected_file);
    const actual_file = try std.fmt.allocPrint(fixture.allocator, "{s}/native.snapshot.json", .{destination});
    defer fixture.allocator.free(actual_file);
    try fixture.write(expected_file, expected, 0o644);
    try fixture.write(actual_file, actual, 0o644);
    if (!std.mem.eql(u8, expected, actual)) {
        if (fixture.diagnostics) {
            var at: usize = 0;
            while (at < @min(expected.len, actual.len) and expected[at] == actual[at]) : (at += 1) {}
            std.debug.print("native/dpkg mismatch at byte {d}: expected {s}; actual {s}\n", .{
                at,
                expected[at..@min(expected.len, at + 120)],
                actual[at..@min(actual.len, at + 120)],
            });
        }
        return error.NativeDpkgMismatch;
    }
}

pub fn assertDirectoryMtime(
    io: std.Io,
    expected_root: []const u8,
    candidate: []const u8,
    relative_path: []const u8,
) !void {
    const relative = try root_fs.Path.init(relative_path);
    var left = try guardedRoot(io, expected_root);
    defer left.close(io);
    var right = try guardedRoot(io, candidate);
    defer right.close(io);
    const expected_empty = try (root_fs.Root.init(io, left)).entry(relative);
    const actual_empty = try (root_fs.Root.init(io, right)).entry(relative);
    if (expected_empty.kind != .directory or actual_empty.kind != .directory)
        return error.NotDirectory;
    if (expected_empty.modified_nanoseconds != actual_empty.modified_nanoseconds)
        return error.EmptyDirectoryMtimeMismatch;
}

pub fn reference(fixture: Fixture, executable: []const u8, root_path: []const u8, archive: []const u8, log: []const u8, configure: bool) !void {
    var root = try guardedRoot(fixture.io, root_path);
    root.close(fixture.io);
    const root_arg = try std.fmt.allocPrint(fixture.allocator, "--root={s}", .{root_path});
    defer fixture.allocator.free(root_arg);
    try fixture.run(&.{
        executable,                                 "--force-not-root", "--force-bad-path", "--no-triggers", root_arg,
        if (configure) "--install" else "--unpack", archive,
    }, log, 120);
}

pub const PackageIdentity = struct {
    name: []const u8,
    architecture: []const u8,
};

pub fn referencePhase(
    fixture: Fixture,
    executable: []const u8,
    root_path: []const u8,
    archive: ?[]const u8,
    operation: []const u8,
    policy: []const u8,
    packages: ?[]const PackageIdentity,
    log: []const u8,
) !void {
    var root = try guardedRoot(fixture.io, root_path);
    root.close(fixture.io);
    const root_arg = try std.fmt.allocPrint(fixture.allocator, "--root={s}", .{root_path});
    defer fixture.allocator.free(root_arg);
    const force = if (std.mem.eql(u8, policy, "keep_existing"))
        "--force-confold"
    else if (std.mem.eql(u8, policy, "use_package_version"))
        "--force-confnew"
    else
        return error.InvalidConffilePolicy;
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(fixture.allocator);
    try argv.appendSlice(fixture.allocator, &.{
        executable, "--force-not-root", "--force-bad-path", "--no-triggers", root_arg, force,
    });
    if (std.mem.eql(u8, operation, "install") or std.mem.eql(u8, operation, "upgrade") or
        std.mem.eql(u8, operation, "downgrade") or std.mem.eql(u8, operation, "reinstall"))
    {
        try argv.appendSlice(fixture.allocator, &.{ "--unpack", archive orelse return error.MissingArchive });
    } else if (std.mem.eql(u8, operation, "configure") or std.mem.eql(u8, operation, "remove") or
        std.mem.eql(u8, operation, "purge"))
    {
        const flag = try std.fmt.allocPrint(fixture.allocator, "--{s}", .{operation});
        defer fixture.allocator.free(flag);
        try argv.append(fixture.allocator, flag);
        var owned: std.ArrayList([]const u8) = .empty;
        defer {
            for (owned.items) |item| fixture.allocator.free(item);
            owned.deinit(fixture.allocator);
        }
        if (packages) |selected| {
            for (selected) |item| {
                const identity = try std.fmt.allocPrint(
                    fixture.allocator,
                    "{s}:{s}",
                    .{ item.name, item.architecture },
                );
                try owned.append(fixture.allocator, identity);
                try argv.append(fixture.allocator, identity);
            }
        } else try argv.append(fixture.allocator, package);
        try fixture.run(argv.items, log, 120);
        return;
    } else return error.InvalidReferenceOperation;
    try fixture.run(argv.items, log, 120);
}

pub const Outcome = struct {
    outcome: []const u8,
    detail: []const u8 = "",
};

pub fn native(
    fixture: *Fixture,
    executable: []const u8,
    root_path: []const u8,
    archive: []const u8,
    architecture: []const u8,
    operation: []const u8,
    destination: []const u8,
) !std.json.Parsed(Outcome) {
    return nativeOperation(fixture, executable, root_path, archive, architecture, operation, destination, .{});
}

pub const NativeOptions = struct {
    conffiles: bool = false,
    policy: []const u8 = "keep_existing",
    packages: ?[]const PackageIdentity = null,
};

pub fn nativeOperation(
    fixture: *Fixture,
    executable: []const u8,
    root_path: []const u8,
    archive: ?[]const u8,
    architecture: []const u8,
    operation: []const u8,
    destination: []const u8,
    options: NativeOptions,
) !std.json.Parsed(Outcome) {
    var root_dir = try guardedRoot(fixture.io, root_path);
    root_dir.close(fixture.io);
    const report_relative = try std.fmt.allocPrint(fixture.allocator, "{s}/native.report.json", .{destination});
    defer fixture.allocator.free(report_relative);
    if (fixture.dir.statFile(fixture.io, report_relative, .{ .follow_symlinks = false })) |_| {
        return error.StaleNativeReport;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const report = try fixture.absolute(report_relative);
    defer fixture.allocator.free(report);
    const request_relative = try std.fmt.allocPrint(fixture.allocator, "{s}/native.request.json", .{destination});
    defer fixture.allocator.free(request_relative);
    const request = try fixture.absolute(request_relative);
    defer fixture.allocator.free(request);
    const archives: []const []const u8 = if (archive) |item| &.{item} else &.{};
    const payload_json = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = root_path,
        .architecture = architecture,
        .archives = archives,
        .operation = operation,
        .report = report,
        .conffiles = options.conffiles,
        .policy = options.policy,
        .packages = options.packages orelse &.{},
    }, .{});
    defer fixture.allocator.free(payload_json);
    try fixture.write(request_relative, payload_json, 0o644);
    try fixture.environment.put("DEBZ_NATIVE_MATERIALIZATION_REQUEST", request);
    const log = try std.fmt.allocPrint(fixture.allocator, "{s}/native.log", .{destination});
    defer fixture.allocator.free(log);
    try fixture.run(&.{executable}, log, 120);
    var file = fixture.dir.openFile(fixture.io, report_relative, .{
        .follow_symlinks = false,
        .allow_directory = false,
    }) catch return error.MissingNativeReport;
    defer file.close(fixture.io);
    if ((try file.stat(fixture.io)).size > 64 * 1024) return error.InvalidNativeReport;
    var reader = file.reader(fixture.io, &.{});
    const bytes = try reader.interface.allocRemaining(fixture.allocator, .limited(64 * 1024 + 1));
    defer fixture.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(Outcome, fixture.allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    const permitted = [_][]const u8{ "applied", "rolled_back", "recovery_required", "handoff", "refused" };
    for (permitted) |item| if (std.mem.eql(u8, parsed.value.outcome, item)) return parsed;
    var bad = parsed;
    bad.deinit();
    return error.InvalidNativeReport;
}

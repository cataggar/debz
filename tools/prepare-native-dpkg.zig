const std = @import("std");
const builtin = @import("builtin");
const debz = @import("debz");
const fs = debz.root_fs;
const options = @import("native_dpkg_options");

pub const version = "1.22.22";
pub const receipt_name = "reference-receipt-v1.json";
const maximum_bytes = 8 * 1024 * 1024;
const schema = "https://debz.dev/schema/native-dpkg-reference-receipt-v1";
const base_url = "https://deb.debian.org/debian/pool/main/d/dpkg";
const guard_name = ".debz-native-disposable";
const guard_content = "debz native materialization fixture v1\n";

pub const Pins = struct {
    archive: []const u8,
    executable: []const u8,
    dpkg_query: []const u8,
    update_alternatives: []const u8,
};

pub fn pins(architecture: []const u8) !Pins {
    if (std.mem.eql(u8, architecture, "amd64")) return .{
        .archive = "3e800c6d75e8e709007ed1c356e5fa8509a75c1694fb0a1183709abc9cfdc1f3",
        .executable = "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5",
        .dpkg_query = "095817337215129933918cacae5fd62e86202fe238591bea207a75b73561e8c5",
        .update_alternatives = "b02b581c6a7f85679f32efe18c9aaeb05316847fa90d3d3fda30b57defab9b13",
    };
    if (std.mem.eql(u8, architecture, "arm64")) return .{
        .archive = "1142468e57f69e13d174f517dff739508c61ee97d81c182c120cd6b281d8cdfa",
        .executable = "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79",
        .dpkg_query = "a5377f6b04e6d251d013c13a2399cb83db8462bf249949b5d76ae0e22842e83a",
        .update_alternatives = "35616ec58ba58f3fb8b4820bdf893c47a842d56684b3335ba6ebf6df86b27cc5",
    };
    return error.UnsupportedReferenceArchitecture;
}

const Binding = struct { sha256: []const u8, size: u64 };
pub const Receipt = struct {
    architecture: []const u8,
    archive: struct { sha256: []const u8, size: u64, url: []const u8 },
    dpkg: Binding,
    dpkg_query: Binding,
    schema: []const u8,
    update_alternatives: Binding,
    version: []const u8,
};

const Tool = enum { dpkg, dpkg_query, update_alternatives };

fn toolName(tool: Tool) []const u8 {
    return switch (tool) {
        .dpkg => "dpkg",
        .dpkg_query => "dpkg-query",
        .update_alternatives => "update-alternatives",
    };
}

fn toolDigest(expected: Pins, tool: Tool) []const u8 {
    return switch (tool) {
        .dpkg => expected.executable,
        .dpkg_query => expected.dpkg_query,
        .update_alternatives => expected.update_alternatives,
    };
}

fn hostArchitecture() ![]const u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => error.UnsupportedReferenceArchitecture,
    };
}

fn absolute(path: []const u8) !fs.Path {
    if (path.len > 4096) return error.InvalidReferencePath;
    return fs.Path.fromAbsolute(path) catch return error.InvalidReferencePath;
}

fn hash(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn canonical(allocator: std.mem.Allocator, value: Receipt) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.json.Stringify.value(value, .{ .whitespace = .indent_2 }, &output.writer);
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root: fs.Root,
    environment: *const std.process.Environ.Map,
    architecture: []const u8,
    expected: Pins,

    fn read(self: Context, path: []const u8, maximum: usize, protected: bool) ![]u8 {
        var pin = try self.root.pinRegularFile(try absolute(path));
        defer pin.close();
        const observed = try pin.observeAlloc(self.allocator, maximum);
        errdefer self.allocator.free(observed.bytes);
        if (observed.entry.link_count != 1) return error.HardLinkedReferenceFile;
        if (protected and (observed.entry.uid != std.os.linux.geteuid() or
            observed.entry.gid != std.os.linux.getegid() or observed.entry.mode & 0o022 != 0))
            return error.UnprotectedReferenceFile;
        return observed.bytes;
    }

    pub fn verifyFile(self: Context, path: []const u8, digest: []const u8) !Binding {
        const bytes = try self.read(path, maximum_bytes, false);
        defer self.allocator.free(bytes);
        if (!std.mem.eql(u8, &hash(bytes), digest)) return error.ReferenceDigestMismatch;
        return .{ .sha256 = digest, .size = bytes.len };
    }

    fn run(self: Context, argv: []const []const u8, seconds: i64) ![]u8 {
        const result = try std.process.run(self.allocator, self.io, .{
            .argv = argv,
            .environ_map = self.environment,
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(seconds), .clock = .awake } },
        });
        defer self.allocator.free(result.stderr);
        errdefer self.allocator.free(result.stdout);
        if (result.term != .exited or result.term.exited != 0) {
            std.log.err("reference command failed ({s}): {s}", .{ argv[0], result.stderr });
            return error.ReferenceCommandFailed;
        }
        return result.stdout;
    }

    fn toolVersion(self: Context, executable: []const u8) ![3]u32 {
        const output = try self.run(&.{ executable, "--version" }, 10);
        defer self.allocator.free(output);
        const first = output[0 .. std.mem.indexOfScalar(u8, output, '\n') orelse output.len];
        var position: usize = 0;
        while (std.mem.indexOfPos(u8, first, position, "version ")) |found| {
            position = found + 8;
            if (found != 0 and (std.ascii.isAlphanumeric(first[found - 1]) or first[found - 1] == '_')) continue;
            var result: [3]u32 = undefined;
            for (&result, 0..) |*number, index| {
                const start = position;
                while (position < first.len and std.ascii.isDigit(first[position])) : (position += 1) {}
                if (start == position) return error.InvalidReferenceVersion;
                number.* = std.fmt.parseInt(u32, first[start..position], 10) catch return error.InvalidReferenceVersion;
                if (index < 2) {
                    if (position == first.len or first[position] != '.') return error.InvalidReferenceVersion;
                    position += 1;
                }
            }
            if (position < first.len and (std.ascii.isAlphanumeric(first[position]) or first[position] == '_'))
                return error.InvalidReferenceVersion;
            return result;
        }
        return error.InvalidReferenceVersion;
    }

    fn hostDpkg(self: Context) ![]u8 {
        var paths = std.mem.splitScalar(u8, self.environment.get("PATH") orelse "/bin:/usr/bin", ':');
        while (paths.next()) |directory| {
            const cwd = try std.process.currentPathAlloc(self.io, self.allocator);
            defer self.allocator.free(cwd);
            const path = try std.fs.path.resolve(self.allocator, &.{ cwd, directory, "dpkg" });
            errdefer self.allocator.free(path);
            const metadata = std.Io.Dir.cwd().statFile(self.io, path, .{ .follow_symlinks = true }) catch |err| switch (err) {
                error.FileNotFound, error.NotDir, error.AccessDenied => {
                    self.allocator.free(path);
                    continue;
                },
                else => return err,
            };
            if (metadata.kind == .file) {
                if (std.Io.Dir.cwd().access(self.io, path, .{ .execute = true })) |_| return path else |err| switch (err) {
                    error.AccessDenied, error.FileNotFound => {},
                    else => return err,
                }
            }
            self.allocator.free(path);
        }
        return error.ReferenceDpkgNotFound;
    }

    pub fn select(self: Context, executable: ?[]const u8, tool: Tool, root_accounts: bool) ![]const u8 {
        if (tool != .dpkg and executable == null) return error.MissingReferencePath;
        const selected = executable orelse try self.hostDpkg();
        errdefer if (executable == null) self.allocator.free(selected);
        if (executable != null) _ = try self.verifyFile(selected, toolDigest(self.expected, tool));
        const found = try self.toolVersion(selected);
        if (executable != null and !std.mem.eql(u32, &found, &.{ 1, 22, 22 })) return error.InvalidReferenceVersion;
        if (root_accounts and (found[0] < 1 or (found[0] == 1 and
            (found[1] < 22 or (found[1] == 22 and found[2] < 16)))))
            return error.OldStatoverrideReference;
        std.debug.print("{s} reference: {s} ({d}.{d}.{d})\n", .{
            switch (tool) {
                .dpkg => "Native",
                .dpkg_query => "Query",
                .update_alternatives => "Alternatives",
            },
            toolName(tool),
            found[0],
            found[1],
            found[2],
        });
        return selected;
    }

    fn url(self: Context) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/dpkg_{s}_{s}.deb", .{ base_url, version, self.architecture });
    }

    fn bindings(self: Context, prefix: []const u8) ![3]Binding {
        var result: [3]Binding = undefined;
        for ([_]Tool{ .dpkg, .dpkg_query, .update_alternatives }, &result) |tool, *binding| {
            const path = try std.fs.path.join(self.allocator, &.{ prefix, "usr/bin", toolName(tool) });
            defer self.allocator.free(path);
            binding.* = try self.verifyFile(path, toolDigest(self.expected, tool));
        }
        return result;
    }

    fn document(self: Context, prefix: []const u8, archive_size: u64) !Receipt {
        const tools = try self.bindings(prefix);
        return .{
            .architecture = self.architecture,
            .archive = .{ .sha256 = self.expected.archive, .size = archive_size, .url = try self.url() },
            .dpkg = tools[0],
            .dpkg_query = tools[1],
            .schema = schema,
            .update_alternatives = tools[2],
            .version = version,
        };
    }

    fn writeReceipt(self: Context, prefix: []const u8, archive_size: u64) !void {
        const receipt = try self.document(prefix, archive_size);
        defer self.allocator.free(receipt.archive.url);
        const bytes = try canonical(self.allocator, receipt);
        defer self.allocator.free(bytes);
        const path = try std.fs.path.join(self.allocator, &.{ prefix, receipt_name });
        defer self.allocator.free(path);
        var parent = try self.root.openParent(try absolute(path));
        defer parent.close(self.io);
        const file = try parent.dir.createFile(self.io, parent.leaf, .{
            .exclusive = true,
            .truncate = false,
            .permissions = .fromMode(0o644),
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        try file.writeStreamingAll(self.io, bytes);
    }

    pub fn verifyReceipt(self: Context, path: []const u8) ![]u8 {
        const raw = try self.read(path, 4096, false);
        errdefer self.allocator.free(raw);
        const parsed = try std.json.parseFromSlice(Receipt, self.allocator, raw, .{ .allocate = .alloc_always });
        defer parsed.deinit();
        const encoded = try canonical(self.allocator, parsed.value);
        defer self.allocator.free(encoded);
        if (!std.mem.eql(u8, raw, encoded)) return error.NonCanonicalReferenceReceipt;
        if (parsed.value.archive.size == 0 or parsed.value.archive.size > maximum_bytes) return error.InvalidReferenceReceipt;
        const expected = try self.document(std.fs.path.dirname(path).?, parsed.value.archive.size);
        defer self.allocator.free(expected.archive.url);
        const expected_bytes = try canonical(self.allocator, expected);
        defer self.allocator.free(expected_bytes);
        if (!std.mem.eql(u8, raw, expected_bytes)) return error.InvalidReferenceReceipt;
        return raw;
    }

    fn archiveMetadata(self: Context, path: []const u8) !void {
        const output = try self.run(&.{ "/usr/bin/dpkg-deb", "--field", path, "Version", "Architecture" }, 10);
        defer self.allocator.free(output);
        var lines = std.mem.splitScalar(u8, output, '\n');
        var version_seen = false;
        var architecture_seen = false;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidReferenceArchiveMetadata;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t\r");
            if (std.mem.eql(u8, line[0..colon], "Version") and !version_seen and std.mem.eql(u8, value, version)) {
                version_seen = true;
            } else if (std.mem.eql(u8, line[0..colon], "Architecture") and !architecture_seen and std.mem.eql(u8, value, self.architecture)) {
                architecture_seen = true;
            } else return error.InvalidReferenceArchiveMetadata;
        }
        if (!version_seen or !architecture_seen) return error.InvalidReferenceArchiveMetadata;
    }

    pub fn receiptFromArchive(self: Context, archive: []const u8, prefix: []const u8) !void {
        var directory = try fs.openAbsoluteRoot(self.io, prefix);
        defer directory.close();
        const raw = try self.read(archive, maximum_bytes, true);
        defer self.allocator.free(raw);
        if (!std.mem.eql(u8, &hash(raw), self.expected.archive)) return error.ReferenceArchiveDigestMismatch;
        for ([_]Tool{ .dpkg, .dpkg_query, .update_alternatives }) |tool| {
            const path = try std.fs.path.join(self.allocator, &.{ prefix, "usr/bin", toolName(tool) });
            defer self.allocator.free(path);
            const bytes = try self.read(path, maximum_bytes, true);
            defer self.allocator.free(bytes);
            if (!std.mem.eql(u8, &hash(bytes), toolDigest(self.expected, tool))) return error.ReferenceDigestMismatch;
        }
        try self.archiveMetadata(archive);
        try self.writeReceipt(prefix, raw.len);
        const receipt = try std.fs.path.join(self.allocator, &.{ prefix, receipt_name });
        defer self.allocator.free(receipt);
        self.allocator.free(try self.verifyReceipt(receipt));
    }

    fn fixture(self: Context, path: []const u8) !void {
        _ = try absolute(path);
        var root = try fs.openAbsoluteRoot(self.io, path);
        defer root.close();
        const marker = try std.fs.path.join(self.allocator, &.{ path, guard_name });
        defer self.allocator.free(marker);
        const bytes = self.read(marker, guard_content.len, false) catch return error.NotDisposableReferenceRoot;
        defer self.allocator.free(bytes);
        if (!std.mem.eql(u8, bytes, guard_content)) return error.NotDisposableReferenceRoot;
    }

    fn download(self: Context, fixture_root: ?[]const u8, fixture_archive: ?[]const u8) ![]u8 {
        const bytes = if (fixture_archive) |path| blk: {
            const root = fixture_root orelse return error.NotDisposableReferenceRoot;
            if (!std.mem.startsWith(u8, path, root) or path.len <= root.len or path[root.len] != '/')
                return error.EscapingReferenceFixtureArchive;
            break :blk self.read(path, maximum_bytes, false) catch return error.EscapingReferenceFixtureArchive;
        } else blk: {
            const source = try self.url();
            defer self.allocator.free(source);
            var production: debz.repository_acquisition.Production = .{ .io = self.io };
            const result = try debz.repository_acquisition.acquire(self.allocator, .{
                .uri = try std.Uri.parse(source),
                .deadlines = .{ .connect_ms = 60_000, .read_ms = 60_000, .overall_ms = 60_000 },
                .redirect_limit = 10,
                .max_response_bytes = maximum_bytes,
                .require_https = true,
            }, production.dependencies());
            var provenance = result.provenance;
            provenance.deinit(self.allocator);
            break :blk result.bytes;
        };
        errdefer self.allocator.free(bytes);
        if (!std.mem.eql(u8, &hash(bytes), self.expected.archive)) return error.ReferenceArchiveDigestMismatch;
        return bytes;
    }

    fn validatePrefix(self: Context, prefix: []const u8) !void {
        var directory = try fs.openAbsoluteRoot(self.io, prefix);
        defer directory.close();
        _ = try self.bindings(prefix);
        if (std.mem.eql(u8, self.architecture, try hostArchitecture())) {
            for ([_]Tool{ .dpkg, .dpkg_query, .update_alternatives }) |tool| {
                const path = try std.fs.path.join(self.allocator, &.{ prefix, "usr/bin", toolName(tool) });
                defer self.allocator.free(path);
                _ = try self.select(path, tool, tool == .dpkg);
            }
        } else std.debug.print("Foreign reference: dpkg {s} ({s}) not executed on {s}\n", .{ version, self.architecture, @tagName(builtin.cpu.arch) });
    }

    fn directories(self: Context, path: fs.Path) !void {
        var end: usize = 0;
        while (end < path.text.len) {
            end = std.mem.indexOfScalarPos(u8, path.text, end, '/') orelse path.text.len;
            const current = try fs.Path.init(path.text[0..end]);
            var parent = try self.root.openParent(current);
            defer parent.close(self.io);
            parent.dir.createDir(self.io, parent.leaf, .fromMode(0o755)) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    if (!(try self.root.entry(current)).isDirectory()) return error.InvalidReferencePath;
                },
                else => return err,
            };
            end += 1;
        }
    }

    pub fn prepare(self: Context, repository: []const u8, fixture_root: ?[]const u8, fixture_archive: ?[]const u8, simulate_root: bool) ![]u8 {
        if (std.os.linux.geteuid() == 0 or simulate_root) return error.RootReferencePreparation;
        if (fixture_root) |root| try self.fixture(root);
        const prefix = try std.fs.path.join(self.allocator, &.{
            fixture_root orelse repository, ".cache/native-dpkg-reference", version, self.architecture,
        });
        defer self.allocator.free(prefix);
        const prefix_path = try absolute(prefix);
        if (try self.root.entryIfExists(prefix_path) != null) {
            try self.validatePrefix(prefix);
            const receipt = try std.fs.path.join(self.allocator, &.{ prefix, receipt_name });
            defer self.allocator.free(receipt);
            if (try self.root.entryIfExists(try absolute(receipt)) == null) {
                const archive = try self.download(fixture_root, fixture_archive);
                defer self.allocator.free(archive);
                try self.writeReceipt(prefix, archive.len);
            }
            self.allocator.free(try self.verifyReceipt(receipt));
            return std.fs.path.join(self.allocator, &.{ prefix, "usr/bin/dpkg" });
        }
        const archive = try self.download(fixture_root, fixture_archive);
        defer self.allocator.free(archive);
        const parent_path = prefix_path.parent().?;
        try self.directories(parent_path);
        var parent = try fs.openAbsoluteRoot(self.io, std.fs.path.dirname(prefix).?);
        defer parent.close();
        var random: [16]u8 = undefined;
        try self.io.randomSecure(&random);
        const stage = try fs.Path.init(try std.fmt.allocPrint(self.allocator, "preparing-{s}", .{std.fmt.bytesToHex(random, .lower)}));
        defer self.allocator.free(stage.text);
        try parent.root.createDirectory(stage, .fromMode(0o700));
        defer {
            parent.root.dir.deleteTree(self.io, stage.text) catch |err|
                std.log.err("private reference staging cleanup failed: {s}", .{@errorName(err)});
        }
        const workspace = try std.fs.path.join(self.allocator, &.{ std.fs.path.dirname(prefix).?, stage.text });
        defer self.allocator.free(workspace);
        const archive_path = try std.fs.path.join(self.allocator, &.{ workspace, "dpkg.deb" });
        defer self.allocator.free(archive_path);
        {
            const file = try self.root.createRegularFile(try absolute(archive_path), .{ .permissions = .fromMode(0o600) });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, archive);
        }
        try self.archiveMetadata(archive_path);
        const staged = try std.fs.path.join(self.allocator, &.{ workspace, "prefix" });
        defer self.allocator.free(staged);
        self.allocator.free(try self.run(&.{ "/usr/bin/dpkg-deb", "--extract", archive_path, staged }, 60));
        try self.validatePrefix(staged);
        try self.writeReceipt(staged, archive.len);
        const staged_path = try fs.Path.init(try std.fmt.allocPrint(self.allocator, "{s}/prefix", .{stage.text}));
        defer self.allocator.free(staged_path.text);
        try parent.root.rename(staged_path, try fs.Path.init(prefix_path.basename()), .fail_if_exists);
        const receipt = try std.fs.path.join(self.allocator, &.{ prefix, receipt_name });
        defer self.allocator.free(receipt);
        self.allocator.free(try self.verifyReceipt(receipt));
        return std.fs.path.join(self.allocator, &.{ prefix, "usr/bin/dpkg" });
    }
};

fn cli(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    var architecture: ?[]const u8 = null;
    var verify_only: ?[]const u8 = null;
    var receipt_path: ?[]const u8 = null;
    var receipt_archive: ?[]const u8 = null;
    var prefix: ?[]const u8 = null;
    var fixture_root: ?[]const u8 = null;
    var fixture_archive: ?[]const u8 = null;
    var check_host = false;
    var root_accounts = false;
    var simulate_root = false;
    var tool: Tool = .dpkg;
    while (args.next()) |argument| {
        if (std.mem.eql(u8, argument, "--check-host")) {
            if (check_host) return error.InvalidArguments;
            check_host = true;
        } else if (std.mem.eql(u8, argument, "--root-accounts")) {
            if (root_accounts) return error.InvalidArguments;
            root_accounts = true;
        } else if (std.mem.eql(u8, argument, "--simulate-root")) {
            if (simulate_root) return error.InvalidArguments;
            simulate_root = true;
        } else if (std.mem.eql(u8, argument, "--tool")) {
            const name = args.next() orelse return error.InvalidArguments;
            tool = if (std.mem.eql(u8, name, "dpkg")) .dpkg else if (std.mem.eql(u8, name, "dpkg-query")) .dpkg_query else if (std.mem.eql(u8, name, "update-alternatives")) .update_alternatives else return error.InvalidArguments;
        } else {
            const destination: *?[]const u8 = if (std.mem.eql(u8, argument, "--architecture")) &architecture else if (std.mem.eql(u8, argument, "--verify-only")) &verify_only else if (std.mem.eql(u8, argument, "--verify-receipt")) &receipt_path else if (std.mem.eql(u8, argument, "--receipt-from-archive")) &receipt_archive else if (std.mem.eql(u8, argument, "--prefix")) &prefix else if (std.mem.eql(u8, argument, "--fixture-root")) &fixture_root else if (std.mem.eql(u8, argument, "--fixture-archive")) &fixture_archive else return error.InvalidArguments;
            if (destination.* != null) return error.InvalidArguments;
            destination.* = args.next() orelse return error.InvalidArguments;
        }
    }

    const modes = @as(u8, @intFromBool(check_host)) + @intFromBool(verify_only != null) +
        @intFromBool(receipt_path != null) + @intFromBool(receipt_archive != null);
    if (modes > 1 or (root_accounts and !check_host) or
        ((fixture_archive != null or simulate_root) and fixture_root == null) or
        (modes != 0 and (fixture_root != null or fixture_archive != null or simulate_root)) or
        ((receipt_archive != null) != (prefix != null)) or
        (tool != .dpkg and verify_only == null))
        return error.InvalidArguments;
    const allocator = init.arena.allocator();
    var filesystem = try fs.openAbsoluteRoot(init.io, "/");
    defer filesystem.close();
    var environment = try init.environ_map.clone(allocator);
    defer environment.deinit();
    try environment.put("LC_ALL", "C");
    const arch = architecture orelse try hostArchitecture();
    const context: Context = .{
        .allocator = allocator,
        .io = init.io,
        .root = filesystem.root,
        .environment = &environment,
        .architecture = arch,
        .expected = try pins(arch),
    };
    const output = if (receipt_path) |path|
        try context.verifyReceipt(path)
    else if (receipt_archive) |archive| blk: {
        try context.receiptFromArchive(archive, prefix.?);
        break :blk "";
    } else if (verify_only) |path| blk: {
        _ = try context.select(path, tool, tool == .dpkg);
        if (tool == .dpkg) {
            const directory = std.fs.path.dirname(std.fs.path.dirname(std.fs.path.dirname(path).?).?).?;
            const receipt = try std.fs.path.join(allocator, &.{ directory, receipt_name });
            allocator.free(try context.verifyReceipt(receipt));
        }
        break :blk "";
    } else if (check_host)
        try context.select(null, .dpkg, root_accounts)
    else
        try context.prepare(options.repository, fixture_root, fixture_archive, simulate_root);
    if (output.len != 0) {
        try std.Io.File.stdout().writeStreamingAll(init.io, output);
        if (!std.mem.endsWith(u8, output, "\n")) try std.Io.File.stdout().writeStreamingAll(init.io, "\n");
    }
}

pub fn main(init: std.process.Init) !void {
    cli(init) catch |err| {
        const diagnostic = switch (err) {
            error.ReferenceDigestMismatch => "pinned reference digest mismatch",
            error.InvalidReferencePath, error.SymbolicLink, error.NotRegularFile => "pinned reference must be a regular file at an absolute, non-symlink path",
            error.ReferenceArchiveDigestMismatch => "pinned reference archive digest mismatch",
            error.OldStatoverrideReference => "named statoverride acceptance requires dpkg >= 1.22.16",
            error.RootReferencePreparation => "prepare the private reference as the build user, not root",
            error.NotDisposableReferenceRoot => "reference preparation requires a disposable fixture root",
            error.EscapingReferenceFixtureArchive => "fixture archive must be a real file inside the disposable root",
            error.UnprotectedReferenceFile, error.HardLinkedReferenceFile => "reference receipt requires owned protected regular inputs without hardlinks",
            else => @errorName(err),
        };
        std.log.err("native dpkg reference refused: {s}", .{diagnostic});
        return err;
    };
}

test "reference receipt verifies all bound tools and refuses changed or noncanonical evidence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDirPath(io, "usr/bin");
    const bytes = "independent reference fixture\n";
    const digest = try allocator.dupe(u8, &hash(bytes));
    for ([_][]const u8{ "dpkg", "dpkg-query", "update-alternatives" }) |name| {
        const path = try std.fmt.allocPrint(allocator, "usr/bin/{s}", .{name});
        try temporary.dir.writeFile(io, .{ .sub_path = path, .data = bytes });
    }
    const prefix = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    var filesystem = try fs.openAbsoluteRoot(io, "/");
    defer filesystem.close();
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const context: Context = .{
        .allocator = allocator,
        .io = io,
        .root = filesystem.root,
        .environment = &environment,
        .architecture = "arm64",
        .expected = .{ .archive = digest, .executable = digest, .dpkg_query = digest, .update_alternatives = digest },
    };
    try context.writeReceipt(prefix, 1234);
    const receipt = try std.fs.path.join(allocator, &.{ prefix, receipt_name });
    const original = try context.verifyReceipt(receipt);
    try std.testing.expectError(error.PathAlreadyExists, context.writeReceipt(prefix, 1234));
    try std.testing.expectEqualSlices(u8, original, try context.verifyReceipt(receipt));
    try temporary.dir.writeFile(io, .{ .sub_path = "usr/bin/dpkg-query", .data = "changed" });
    try std.testing.expectError(error.ReferenceDigestMismatch, context.verifyReceipt(receipt));
    try std.testing.expectEqualSlices(u8, original, try temporary.dir.readFileAlloc(io, receipt_name, allocator, .limited(4096)));
    try temporary.dir.writeFile(io, .{ .sub_path = "usr/bin/dpkg-query", .data = bytes });
    try temporary.dir.writeFile(io, .{ .sub_path = receipt_name, .data = try std.fmt.allocPrint(allocator, " {s}", .{original}) });
    try std.testing.expectError(error.NonCanonicalReferenceReceipt, context.verifyReceipt(receipt));
    try temporary.dir.writeFile(io, .{ .sub_path = receipt_name, .data = original });
    try std.Io.Dir.hardLink(temporary.dir, receipt_name, temporary.dir, "receipt-alias", io, .{});
    try std.testing.expectError(error.HardLinkedReferenceFile, context.verifyReceipt(receipt));
}

test "extracted receipt requires protected independent archive and tool bindings before publication" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDirPath(io, "package/DEBIAN");
    try temporary.dir.createDirPath(io, "package/usr/bin");
    try temporary.dir.writeFile(io, .{
        .sub_path = "package/DEBIAN/control",
        .data = "Package: dpkg\nVersion: 1.22.22\nArchitecture: arm64\nMaintainer: fixture <fixture@example.invalid>\nDescription: Independent receipt fixture\n",
    });
    const bytes = "independent receipt tool\n";
    const digest = try allocator.dupe(u8, &hash(bytes));
    for ([_][]const u8{ "dpkg", "dpkg-query", "update-alternatives" }) |name|
        try temporary.dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(allocator, "package/usr/bin/{s}", .{name}), .data = bytes });
    const workspace = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    var filesystem = try fs.openAbsoluteRoot(io, "/");
    defer filesystem.close();
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("LC_ALL", "C");
    try environment.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    var context: Context = .{
        .allocator = allocator,
        .io = io,
        .root = filesystem.root,
        .environment = &environment,
        .architecture = "arm64",
        .expected = .{ .archive = digest, .executable = digest, .dpkg_query = digest, .update_alternatives = digest },
    };
    const package = try std.fs.path.join(allocator, &.{ workspace, "package" });
    const archive = try std.fs.path.join(allocator, &.{ workspace, "dpkg.deb" });
    allocator.free(try context.run(&.{ "/usr/bin/dpkg-deb", "--build", "--root-owner-group", package, archive }, 10));
    context.expected.archive = try allocator.dupe(u8, &hash(try temporary.dir.readFileAlloc(io, "dpkg.deb", allocator, .limited(maximum_bytes))));
    const prefix = try std.fs.path.join(allocator, &.{ workspace, "prefix" });
    allocator.free(try context.run(&.{ "/usr/bin/dpkg-deb", "--extract", archive, prefix }, 10));
    try context.receiptFromArchive(archive, prefix);
    const receipt = try std.fs.path.join(allocator, &.{ prefix, receipt_name });
    try context.root.removeFile(try absolute(receipt));
    try std.Io.Dir.hardLink(temporary.dir, "prefix/usr/bin/dpkg-query", temporary.dir, "tool-alias", io, .{});
    try std.testing.expectError(error.HardLinkedReferenceFile, context.receiptFromArchive(archive, prefix));
    try std.testing.expectEqual(@as(?fs.Entry, null), try context.root.entryIfExists(try absolute(receipt)));
    try temporary.dir.deleteFile(io, "tool-alias");
    const query = try temporary.dir.openFile(io, "prefix/usr/bin/dpkg-query", .{});
    defer query.close(io);
    try query.setPermissions(io, .fromMode(0o777));
    try std.testing.expectError(error.UnprotectedReferenceFile, context.receiptFromArchive(archive, prefix));
    try query.setPermissions(io, .fromMode(0o644));
    try temporary.dir.writeFile(io, .{ .sub_path = "prefix/usr/bin/dpkg-query", .data = "tampered" });
    try std.testing.expectError(error.ReferenceDigestMismatch, context.receiptFromArchive(archive, prefix));
    try std.testing.expectEqual(@as(?fs.Entry, null), try context.root.entryIfExists(try absolute(receipt)));
}

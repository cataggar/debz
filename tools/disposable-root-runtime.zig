const std = @import("std");
const fs = @import("debz").root_fs;
const maximum_file_bytes = 32 * 1024 * 1024;
const maximum_total_bytes = 128 * 1024 * 1024;

const Attribute = struct {
    name: [:0]u8,
    value: []u8,

    fn deinit(self: Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

fn attributes(allocator: std.mem.Allocator, file: std.Io.File) ![]Attribute {
    const linux = std.os.linux;
    var names: [64 * 1024]u8 = undefined;
    const count = linux.flistxattr(file.handle, &names, names.len);
    switch (linux.errno(count)) {
        .SUCCESS => {},
        .OPNOTSUPP => return try allocator.alloc(Attribute, 0),
        else => return error.FixtureAttributesUnreadable,
    }
    var result: std.ArrayList(Attribute) = .empty;
    errdefer {
        for (result.items) |attribute| attribute.deinit(allocator);
        result.deinit(allocator);
    }
    var offset: usize = 0;
    var value: [64 * 1024]u8 = undefined;
    while (offset < count) {
        if (result.items.len == 64) return error.FixtureAttributesTooLarge;
        const end = std.mem.indexOfScalarPos(u8, names[0..count], offset, 0) orelse return error.InvalidFixtureAttribute;
        const name = try allocator.dupeZ(u8, names[offset..end]);
        errdefer allocator.free(name);
        const length = linux.fgetxattr(file.handle, name, &value, value.len);
        if (linux.errno(length) != .SUCCESS) return error.FixtureAttributesUnreadable;
        const bytes = try allocator.dupe(u8, value[0..length]);
        errdefer allocator.free(bytes);
        try result.append(allocator, .{ .name = name, .value = bytes });
        offset = end + 1;
    }
    return try result.toOwnedSlice(allocator);
}

fn applyAttributes(file: std.Io.File, values: []const Attribute) !void {
    for (values) |attribute| {
        const result = std.os.linux.fsetxattr(file.handle, attribute.name, attribute.value.ptr, attribute.value.len, 0);
        if (std.os.linux.errno(result) != .SUCCESS) return error.FixtureAttributesUnwritable;
    }
}

fn interpreter(allocator: std.mem.Allocator, header: []const u8) !?[]u8 {
    if (!std.mem.startsWith(u8, header, "#!")) return null;
    const line = header[2 .. std.mem.indexOfScalar(u8, header, '\n') orelse header.len];
    if (!std.unicode.utf8ValidateSlice(line)) return error.InvalidFixtureInterpreter;
    var first: std.ArrayList(u8) = .empty;
    errdefer first.deinit(allocator);
    var quote: ?u8 = null;
    var word = false;
    var finished = false;
    var index: usize = 0;
    while (index < line.len) : (index += 1) {
        const byte = line[index];
        if (quote == null and (byte == ' ' or byte == '\t' or byte == '\r')) {
            if (word) finished = true;
            continue;
        }
        word = true;
        if (byte == '\\' and quote != '\'') {
            index += 1;
            if (index == line.len) return error.InvalidFixtureInterpreter;
            if (quote == '"' and line[index] != '\\' and line[index] != '"' and !finished)
                try first.append(allocator, '\\');
            if (!finished) try first.append(allocator, line[index]);
        } else if (byte == '\'' or byte == '"') {
            if (quote == byte) {
                quote = null;
            } else if (quote == null) {
                quote = byte;
            } else if (!finished) try first.append(allocator, byte);
        } else if (!finished) try first.append(allocator, byte);
    }
    if (quote != null or first.items.len == 0) return error.InvalidFixtureInterpreter;
    _ = fs.Path.fromAbsolute(first.items) catch return error.InvalidFixtureInterpreter;
    return try first.toOwnedSlice(allocator);
}

const Input = struct {
    directory: fs.OwnedRoot,
    pin: fs.PinnedRegularFile,
    source: [:0]u8,
    destination: fs.Path,
    original: ?fs.Entry,
    observed: fs.RegularFileObservation,
    xattrs: []Attribute,

    fn deinit(self: *Input, allocator: std.mem.Allocator) void {
        self.pin.close();
        self.directory.close();
        allocator.free(self.source);
        allocator.free(self.destination.text);
        allocator.free(self.observed.bytes);
        for (self.xattrs) |attribute| attribute.deinit(allocator);
        allocator.free(self.xattrs);
    }

    fn check(self: *const Input, root: fs.Root) !void {
        _ = try self.pin.metadata();
        const current = try root.entryIfExists(self.destination);
        if (current) |entry| {
            if (!entry.isRegularFile()) return error.InvalidFixtureDestination;
            if (entry.link_count != 1) return error.HardLinkedFixtureDestination;
        }
        if (!std.meta.eql(current, self.original)) return error.FixtureDestinationChanged;
    }

    fn checkParent(self: *const Input, root: fs.Root, directory: std.Io.Dir) !void {
        const bound = try fs.Root.init(root.io, directory).rootEntry();
        const current = if (self.destination.parent()) |parent| try root.entry(parent) else try root.rootEntry();
        if (bound.device != current.device or bound.inode != current.inode or bound.mode != current.mode or
            bound.uid != current.uid or bound.gid != current.gid)
            return error.FixtureParentChanged;
    }
};

const Copier = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    root: fs.Root,
    inputs: std.ArrayList(Input) = .empty,
    total: usize = 0,

    fn deinit(self: *Copier) void {
        for (self.inputs.items) |*input| input.deinit(self.allocator);
        self.inputs.deinit(self.allocator);
    }

    fn add(self: *Copier, source: []const u8, destination: fs.Path) !?usize {
        for (self.inputs.items, 0..) |input, index| {
            if (std.mem.eql(u8, input.destination.text, destination.text)) {
                if (!std.mem.eql(u8, input.source, source)) {
                    const canonical = try std.Io.Dir.cwd().realPathFileAlloc(self.io, source, self.allocator);
                    defer self.allocator.free(canonical);
                    if (!std.mem.eql(u8, input.source, canonical)) return error.ConflictingFixtureRuntimeInput;
                }
                return null;
            }
            if (index >= 63) return error.FixtureRuntimeTooLarge;
        }
        const original = try self.root.entryIfExists(destination);
        if (original) |entry| {
            if (!entry.isRegularFile()) return error.InvalidFixtureDestination;
            if (entry.link_count != 1) return error.HardLinkedFixtureDestination;
        }
        const canonical = try std.Io.Dir.cwd().realPathFileAlloc(self.io, source, self.allocator);
        errdefer self.allocator.free(canonical);
        var directory = try fs.openAbsoluteRoot(self.io, std.fs.path.dirname(canonical).?);
        errdefer directory.close();
        var pin = try directory.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(canonical)));
        errdefer pin.close();
        const observed = try pin.observeStableAlloc(self.allocator, maximum_file_bytes);
        errdefer self.allocator.free(observed.bytes);
        const xattrs = try attributes(self.allocator, pin.file);
        errdefer {
            for (xattrs) |attribute| attribute.deinit(self.allocator);
            self.allocator.free(xattrs);
        }
        _ = try pin.metadata();
        if (observed.bytes.len > maximum_total_bytes - self.total) return error.FixtureRuntimeTooLarge;
        const path = try self.allocator.dupe(u8, destination.text);
        errdefer self.allocator.free(path);
        const index = self.inputs.items.len;
        try self.inputs.append(self.allocator, .{
            .directory = directory,
            .pin = pin,
            .source = canonical,
            .destination = .{ .text = path },
            .original = original,
            .observed = observed,
            .xattrs = xattrs,
        });
        self.total += observed.bytes.len;
        return index;
    }

    fn plan(self: *Copier, source: []const u8, destination: fs.Path) !void {
        const index = (try self.add(source, destination)) orelse return;
        const input = &self.inputs.items[index];
        const command = try self.allocator.dupe(u8, input.source);
        defer self.allocator.free(command);
        const shebang = try interpreter(self.allocator, input.observed.bytes[0..@min(input.observed.bytes.len, 256)]);
        if (shebang) |name| {
            defer self.allocator.free(name);
            try self.plan(name, try fs.Path.fromAbsolute(name));
            return;
        }
        const result = try std.process.run(self.allocator, self.io, .{
            .argv = &.{ "/usr/bin/ldd", command },
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        const output = try std.mem.concat(self.allocator, u8, &.{ result.stdout, result.stderr });
        defer self.allocator.free(output);
        const static = std.mem.indexOf(u8, output, "not a dynamic executable") != null or
            std.mem.indexOf(u8, output, "statically linked") != null;
        if (std.mem.indexOf(u8, output, "=> not found") != null or
            (!static and (result.term != .exited or result.term.exited != 0)))
        {
            return error.MissingFixtureLibrary;
        }
        var lines = std.mem.splitScalar(u8, output, '\n');
        while (lines.next()) |line| {
            const start = if (std.mem.indexOf(u8, line, "=>")) |arrow| line[arrow + 2 ..] else line;
            var words = std.mem.tokenizeAny(u8, start, " \r\t");
            const name = words.next() orelse continue;
            if (name.len == 0 or name[0] != '/') continue;
            _ = try self.add(name, try fs.Path.fromAbsolute(name));
        }
        _ = try self.inputs.items[index].pin.metadata();
    }

    fn publish(self: *Copier) !void {
        for (self.inputs.items) |*input| try input.check(self.root);
        for (self.inputs.items) |*input| {
            if (input.destination.parent()) |parent|
                try self.parents(parent);
            var context: struct {
                input: *Input,
                root: fs.Root,
                directory: ?std.Io.Dir = null,
                fn observe(raw: *anyopaque, point: fs.PublishPoint) !void {
                    const context: *@This() = @ptrCast(@alignCast(raw));
                    if (point == .before_rename) {
                        try context.input.check(context.root);
                        try context.input.checkParent(context.root, context.directory.?);
                    }
                }
            } = .{ .input = input, .root = self.root };
            var staged = try self.root.stageFile(input.destination, .{
                .permissions = .fromMode(input.observed.entry.mode),
                .overwrite = if (input.original == null) .fail_if_exists else .replace,
                .observer = .{ .context = &context, .hitFn = @TypeOf(context).observe },
            });
            defer staged.deinit();
            context.directory = staged.parent.dir;
            try staged.writeAll(input.observed.bytes);
            try applyAttributes(staged.file, input.xattrs);
            try staged.file.setTimestamps(self.io, .{
                .modify_timestamp = .{ .new = .{
                    .nanoseconds = std.math.cast(i96, input.observed.entry.modified_nanoseconds) orelse return error.InvalidFixtureTimestamp,
                } },
            });
            try staged.commit();
        }
    }

    fn parents(self: *Copier, path: fs.Path) !void {
        var directory = self.root.dir;
        var owned = false;
        defer if (owned) directory.close(self.io);
        var parts = std.mem.splitScalar(u8, path.text, '/');
        while (parts.next()) |part| {
            // Match mkdir's inherited umask, without chmod of existing directories.
            directory.createDir(self.io, part, .fromMode(0o777)) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
            const next = try fs.Root.init(self.io, directory).openDirectory(try fs.Path.init(part));
            if (owned) directory.close(self.io);
            directory = next;
            owned = true;
        }
    }
};

fn copy(io: std.Io, allocator: std.mem.Allocator, root_path: []const u8, source: []const u8, destination: []const u8) !void {
    _ = try fs.Path.fromAbsolute(source);
    const path = try fs.Path.fromAbsolute(destination);
    if (std.mem.eql(u8, root_path, "/")) return error.DisposableRootRequired;
    var root = try fs.openAbsoluteRoot(io, root_path);
    defer root.close();
    if (try root.root.entryIfExists(path)) |entry| {
        if (!entry.isRegularFile()) return error.InvalidFixtureDestination;
        if (entry.link_count != 1) return error.HardLinkedFixtureDestination;
        return;
    }
    var copier: Copier = .{ .io = io, .allocator = allocator, .root = root.root };
    defer copier.deinit();
    try copier.plan(source, path);
    try copier.publish();
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const root = args.next() orelse return error.MissingFixtureArgument;
    const source = args.next() orelse return error.MissingFixtureArgument;
    const destination = args.next() orelse return error.MissingFixtureArgument;
    if (args.next() != null) return error.UnexpectedFixtureArgument;
    copy(init.io, init.arena.allocator(), root, source, destination) catch |err| {
        std.log.err("disposable runtime refused root={s} source={s} destination={s}: {s}", .{
            root, source, destination, @errorName(err),
        });
        return err;
    };
}

test "disposable runtime preserves quoted shebangs and refuses malformed interpreter words" {
    for ([_][]const u8{ "#!/bin/sh -e\n", "#! '/bin/sh' -e\n", "#! \"/bin/sh\" -e\n" }) |header| {
        const name = (try interpreter(std.testing.allocator, header)).?;
        defer std.testing.allocator.free(name);
        try std.testing.expectEqualStrings("/bin/sh", name);
    }
    try std.testing.expectError(error.InvalidFixtureInterpreter, interpreter(std.testing.allocator, "#! sh\n"));
    try std.testing.expectError(error.InvalidFixtureInterpreter, interpreter(std.testing.allocator, "#! /bin/sh 'unterminated\n"));
}

test "disposable runtime copies the original shell closure and preserves exact source modes and mtime" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try temporary.dir.createDir(std.testing.io, "poison", .fromMode(0o755));
    const poison = try std.fs.path.join(std.testing.allocator, &.{ root, "poison" });
    defer std.testing.allocator.free(poison);
    for ([_][]const u8{ "poison/python", "poison/python3" }) |path| {
        var file = try temporary.dir.createFile(std.testing.io, path, .{ .permissions = .fromMode(0o755) });
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "#!/bin/sh\nexit 91\n");
    }
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    const search_path = try std.fmt.allocPrint(std.testing.allocator, "{s}:/usr/sbin:/usr/bin:/sbin:/bin", .{poison});
    defer std.testing.allocator.free(search_path);
    try environment.put("PATH", search_path);
    const executed = try std.process.run(std.testing.allocator, std.testing.io, .{
        .argv = &.{ @import("disposable_runtime_test_options").executable, root, "/bin/sh", "/bin/sh" },
        .environ_map = &environment,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(120), .clock = .awake } },
    });
    defer std.testing.allocator.free(executed.stdout);
    defer std.testing.allocator.free(executed.stderr);
    try std.testing.expect(executed.term == .exited and executed.term.exited == 0);
    try std.testing.expectEqualStrings("", executed.stdout);
    try std.testing.expectEqualStrings("", executed.stderr);
    const source = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, "/bin/sh", std.testing.allocator);
    defer std.testing.allocator.free(source);
    var parent = try fs.openAbsoluteRoot(std.testing.io, std.fs.path.dirname(source).?);
    defer parent.close();
    var pin = try parent.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(source)));
    defer pin.close();
    const original = try pin.observeStableAlloc(std.testing.allocator, maximum_file_bytes);
    defer std.testing.allocator.free(original.bytes);
    var output = try fs.openAbsoluteRoot(std.testing.io, root);
    defer output.close();
    const copied = try output.root.readFileAlloc(std.testing.allocator, try fs.Path.init("bin/sh"), maximum_file_bytes);
    defer std.testing.allocator.free(copied);
    const metadata = try output.root.entry(try fs.Path.init("bin/sh"));
    try std.testing.expectEqualSlices(u8, original.bytes, copied);
    try std.testing.expectEqual(original.entry.mode, metadata.mode);
    try std.testing.expectEqual(original.entry.modified_nanoseconds, metadata.modified_nanoseconds);
    try copy(std.testing.io, std.testing.allocator, root, "/unneeded/nonexistent", "/bin/sh");
}

test "disposable runtime refuses destination links and invalid interpreters before publishing" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "hold", .data = "unchanged" });
    try temporary.dir.symLink(std.testing.io, "hold", "symbolic", .{});
    try std.testing.expectError(error.InvalidFixtureDestination, copy(std.testing.io, std.testing.allocator, root, "/bin/sh", "/symbolic"));
    try std.Io.Dir.hardLink(temporary.dir, "hold", temporary.dir, "hard", std.testing.io, .{});
    try std.testing.expectError(error.HardLinkedFixtureDestination, copy(std.testing.io, std.testing.allocator, root, "/bin/sh", "/hard"));
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "invalid", .data = "#! non-absolute\n" });
    const invalid = try std.fs.path.join(std.testing.allocator, &.{ root, "invalid" });
    defer std.testing.allocator.free(invalid);
    try std.testing.expectError(error.InvalidFixtureInterpreter, copy(std.testing.io, std.testing.allocator, root, invalid, "/absent"));
    try std.testing.expectError(error.FileNotFound, temporary.dir.statFile(std.testing.io, "absent", .{}));
}

test "disposable runtime preserves original nonempty extended attributes" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    var file = try temporary.dir.createFile(std.testing.io, "script", .{ .read = true });
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, "#!/bin/sh\nexit 0\n");
    const set = std.os.linux.fsetxattr(file.handle, "user.debz-fixture", "original".ptr, "original".len, 0);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(set));
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "script" });
    defer std.testing.allocator.free(source);
    try copy(std.testing.io, std.testing.allocator, root, source, "/copied");
    var output = try temporary.dir.openFile(std.testing.io, "copied", .{});
    defer output.close(std.testing.io);
    var value: [64]u8 = undefined;
    const length = std.os.linux.fgetxattr(output.handle, "user.debz-fixture", &value, value.len);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(length));
    try std.testing.expectEqualStrings("original", value[0..length]);
}

test "disposable runtime refuses changed source and a planted parent before publication" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root_path = try temporary.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_path);
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "script", .data = "#!/bin/sh\nexit 0\n" });
    const source = try std.fs.path.join(std.testing.allocator, &.{ root_path, "script" });
    defer std.testing.allocator.free(source);
    var root = try fs.openAbsoluteRoot(std.testing.io, root_path);
    defer root.close();
    var copier: Copier = .{ .io = std.testing.io, .allocator = std.testing.allocator, .root = root.root };
    defer copier.deinit();
    try copier.plan(source, try fs.Path.init("installed-script"));
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "script", .data = "#!/bin/sh\nexit 1\n" });
    try std.testing.expectError(error.PathChanged, copier.publish());
    try std.testing.expectError(error.FileNotFound, temporary.dir.statFile(std.testing.io, "installed-script", .{}));
    try root.root.createDirectory(try fs.Path.init("parent"), .fromMode(0o755));
    var staged = try root.root.stageFile(try fs.Path.init("parent/program"), .{});
    defer staged.deinit();
    var input = copier.inputs.items[0];
    input.destination = try fs.Path.init("parent/program");
    try input.checkParent(root.root, staged.parent.dir);
    try temporary.dir.rename("parent", temporary.dir, "old-parent", std.testing.io);
    try root.root.createDirectory(try fs.Path.init("parent"), .fromMode(0o755));
    try std.testing.expectError(error.FixtureParentChanged, input.checkParent(root.root, staged.parent.dir));
    try temporary.dir.createDir(std.testing.io, "outside", .fromMode(0o755));
    try temporary.dir.symLink(std.testing.io, "outside", "bin", .{});
    try std.testing.expectError(error.SymbolicLinkComponent, copy(std.testing.io, std.testing.allocator, root_path, "/bin/sh", "/bin/sh"));
    try std.testing.expectError(error.FileNotFound, temporary.dir.statFile(std.testing.io, "outside/sh", .{}));
}

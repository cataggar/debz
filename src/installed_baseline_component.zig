//! Installed component observations, never archive, action, or callback authority.
const std = @import("std");
const database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");
const status = @import("dpkg_status.zig");

pub const schema_id = "https://debz.dev/schema/installed-baseline-component-v1";
pub const maximum_files: usize = 100_000;
pub const maximum_bytes: usize = 256 * 1024 * 1024;
pub const maximum_work: usize = 16_000_000;

pub const Package = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    selection: status.Want,
};

pub const RootIdentity = struct {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
};

pub const File = struct {
    path: []const u8,
    kind: enum { regular, directory, symlink },
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: ?u64 = null,
    modified_nanoseconds: ?i128 = null,
    change_nanoseconds: ?i128 = null,
    sha512: ?[128]u8 = null,
};

pub const Component = struct {
    package: Package,
    status_fields_sha512: [128]u8,
    info_stem: []const u8,
    controls: []const File,
    payload: []const File,
};

pub const Manifest = struct {
    schema: []const u8 = schema_id,
    version: u32 = 1,
    authority: enum { installed_component_noop } = .installed_component_noop,
    root: RootIdentity,
    architecture: []const u8,
    components: []const Component,

    pub fn digest(self: Manifest) [128]u8 {
        var buffer: [4096]u8 = undefined;
        var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha512) = .init(&buffer);
        sink.writer.writeAll("debz installed component no-op v1\x00") catch unreachable;
        std.json.Stringify.value(self, .{}, &sink.writer) catch unreachable;
        sink.writer.flush() catch unreachable;
        return std.fmt.bytesToHex(sink.hasher.finalResult(), .lower);
    }

    pub fn find(self: Manifest, name: []const u8, architecture: []const u8) ?Component {
        for (self.components) |component| if (std.mem.eql(u8, component.package.name, name) and
            std.mem.eql(u8, component.package.architecture, architecture))
            return component;
        return null;
    }

    pub fn containsName(self: Manifest, name: []const u8) bool {
        for (self.components) |component| if (std.mem.eql(u8, component.package.name, name)) return true;
        return false;
    }
};

fn identity(root: root_fs.Root) !RootIdentity {
    const entry = try root.rootEntry();
    if (!entry.modeled or !entry.isDirectory() or entry.mode & 0o022 != 0)
        return error.UnsafeInstalledBaselineComponent;
    return .{ .device = entry.device, .inode = entry.inode, .uid = entry.uid, .gid = entry.gid, .mode = entry.mode };
}

const Capture = struct {
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bytes: usize = 0,
    files: usize = 0,

    fn file(self: *Capture, path: []const u8) !File {
        self.files += 1;
        if (self.files > maximum_files) return error.InstalledBaselineComponentLimit;
        const resolved = try root_fs.Path.init(path);
        const entry = try self.root.entry(resolved);
        if (!entry.modeled or !entry.isSupportedKind() or
            (!entry.isSymbolicLink() and entry.mode & 0o022 != 0))
            return error.UnsafeInstalledBaselineComponent;
        var result: File = .{
            .path = try self.allocator.dupe(u8, path),
            .kind = if (entry.isRegularFile()) .regular else if (entry.isDirectory()) .directory else .symlink,
            .device = entry.device,
            .inode = entry.inode,
            .uid = entry.uid,
            .gid = entry.gid,
            .mode = entry.mode,
        };
        if (entry.isDirectory()) {
            var pin = try self.root.pinDirectory(resolved);
            defer pin.close();
            const actual = (try pin.metadata()).entry;
            if (!actual.modeled or !actual.isDirectory() or actual.mode & 0o022 != 0)
                return error.UnsafeInstalledBaselineComponent;
            result.device = actual.device;
            result.inode = actual.inode;
            result.uid = actual.uid;
            result.gid = actual.gid;
            result.mode = actual.mode;
            // Shared-directory membership can change for authenticated new installs.
            return result;
        }
        var changed: i128 = undefined;
        var content: []const u8 = undefined;
        var observed: root_fs.Entry = undefined;
        if (entry.isRegularFile()) {
            if (entry.link_count != 1) return error.UnsafeInstalledBaselineComponent;
            if (entry.size > maximum_bytes -| self.bytes) return error.InstalledBaselineComponentLimit;
            var pin = try self.root.pinRegularFile(resolved);
            defer pin.close();
            const actual = try pin.observeStableAlloc(self.allocator, 64 * 1024 * 1024);
            content = actual.bytes;
            changed = actual.change_nanoseconds;
            observed = actual.entry;
        } else {
            var pin = try self.root.pinSymbolicLink(resolved);
            defer pin.close();
            var target: [root_fs.maximum_path_bytes]u8 = undefined;
            const actual = try pin.observe(&target);
            content = try self.allocator.dupe(u8, actual.target);
            changed = actual.change_nanoseconds;
            observed = actual.entry;
        }
        self.bytes = std.math.add(usize, self.bytes, content.len) catch return error.InstalledBaselineComponentLimit;
        if (self.bytes > maximum_bytes) return error.InstalledBaselineComponentLimit;
        if (!observed.modeled or (!observed.isSymbolicLink() and
            (observed.mode & 0o022 != 0 or observed.link_count != 1)))
            return error.UnsafeInstalledBaselineComponent;
        var digest: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(content, &digest, .{});
        result.device = observed.device;
        result.inode = observed.inode;
        result.uid = observed.uid;
        result.gid = observed.gid;
        result.mode = observed.mode;
        result.size = observed.size;
        result.modified_nanoseconds = observed.modified_nanoseconds;
        result.change_nanoseconds = changed;
        result.sha512 = std.fmt.bytesToHex(digest, .lower);
        return result;
    }
};

fn samePackage(left: Package, right: Package) bool {
    return std.mem.eql(u8, left.name, right.name) and
        std.mem.eql(u8, left.version, right.version) and
        std.mem.eql(u8, left.architecture, right.architecture) and left.selection == right.selection;
}

fn lessFile(_: void, left: File, right: File) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

fn statusDigest(fields: []const database.StatusField) [128]u8 {
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha512) = .init(&buffer);
    std.json.Stringify.value(fields, .{}, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return std.fmt.bytesToHex(sink.hasher.finalResult(), .lower);
}

pub fn captureFromDatabase(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
    packages: []const Package,
    model: database.Model,
    info: []const database.InfoEntry,
) !Manifest {
    if (packages.len == 0 or packages.len > (database.Options{}).limits.max_packages)
        return error.InvalidInstalledBaselineComponent;
    var reader: Capture = .{ .allocator = allocator, .root = root };
    const components = try allocator.alloc(Component, packages.len);
    var work: usize = 0;
    for (packages, 0..) |package, index| {
        work = std.math.add(usize, work, model.packages.len + info.len) catch return error.InstalledBaselineComponentLimit;
        if (work > maximum_work) return error.InstalledBaselineComponentLimit;
        const record = model.find(package.name, package.architecture) orelse return error.InstalledBaselineComponentChanged;
        if (!samePackage(package, .{
            .name = record.name,
            .version = record.version,
            .architecture = record.architecture,
            .selection = if (record.status.want == .hold) .hold else .install,
        }) or record.status.current != .installed or record.status.error_state != .ok or
            (record.status.want != .install and record.status.want != .hold))
            return error.InstalledBaselineComponentChanged;
        if (record.trigger_declarations) |declarations| if (declarations.len != 0)
            return error.InstalledBaselineCallbacksUnsupported;
        if (record.scripts.len != 0 or record.metadataMember(.config) != null or
            record.triggers_pending.len != 0 or record.triggers_awaited.len != 0)
            return error.InstalledBaselineCallbacksUnsupported;
        const paths = record.paths orelse return error.InstalledBaselineOwnershipUnavailable;
        var controls: std.ArrayList(File) = .empty;
        for (info) |member| {
            const dot = std.mem.lastIndexOfScalar(u8, member.name, '.') orelse continue;
            if (!std.mem.eql(u8, member.name[0..dot], record.info_stem)) continue;
            const path = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}", .{member.name});
            try controls.append(allocator, try reader.file(path));
        }
        std.mem.sort(File, controls.items, {}, lessFile);
        var payload: std.ArrayList(File) = .empty;
        for (paths) |listed| {
            const logical = database.logicalListPath(listed);
            if (std.mem.eql(u8, logical, "/")) continue;
            if (logical.len < 2 or logical[0] != '/' or database.reservedPayloadPath(logical[1..]))
                return error.InvalidInstalledBaselineComponent;
            try payload.append(allocator, try reader.file(logical[1..]));
        }
        std.mem.sort(File, payload.items, {}, lessFile);
        components[index] = .{
            .package = .{
                .name = try allocator.dupe(u8, package.name),
                .version = try allocator.dupe(u8, package.version),
                .architecture = try allocator.dupe(u8, package.architecture),
                .selection = package.selection,
            },
            .status_fields_sha512 = statusDigest(record.fields),
            .info_stem = try allocator.dupe(u8, record.info_stem),
            .controls = try controls.toOwnedSlice(allocator),
            .payload = try payload.toOwnedSlice(allocator),
        };
    }
    return .{
        .root = try identity(root),
        .architecture = try allocator.dupe(u8, architecture),
        .components = components,
    };
}

pub fn verifyFromDatabase(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    expected: Manifest,
    model: database.Model,
    info: []const database.InfoEntry,
) !void {
    if (!std.mem.eql(u8, expected.schema, schema_id) or expected.version != 1)
        return error.InvalidInstalledBaselineComponent;
    const packages = try allocator.alloc(Package, expected.components.len);
    for (expected.components, packages) |component, *package| package.* = component.package;
    const actual = try captureFromDatabase(allocator, root, expected.architecture, packages, model, info);
    if (!std.mem.eql(u8, &expected.digest(), &actual.digest()))
        return error.InstalledBaselineComponentChanged;
}

/// This root reader is intentionally narrower than native execution admission.
/// Full database/features/trigger admission remains the native runtime's job.
pub fn capture(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
    packages: []const Package,
) !Manifest {
    var info: std.ArrayList(database.InfoEntry) = .empty;
    var directory = try root.openDirectory(try root_fs.Path.init("var/lib/dpkg/info"));
    defer directory.close(root.io);
    var iterator = directory.iterate();
    var metadata_bytes: usize = 0;
    while (try iterator.next(root.io)) |member| {
        if (info.items.len >= maximum_files) return error.InstalledBaselineComponentLimit;
        const path = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}", .{member.name});
        const resolved = try root_fs.Path.init(path);
        const entry = try root.entry(resolved);
        if (!entry.modeled or !entry.isRegularFile() or entry.link_count != 1)
            return error.UnsafeInstalledBaselineComponent;
        if (entry.size > maximum_bytes -| metadata_bytes) return error.InstalledBaselineComponentLimit;
        const bytes = try root.readFileAlloc(allocator, resolved, @min(64 * 1024 * 1024, maximum_bytes -| metadata_bytes));
        metadata_bytes = std.math.add(usize, metadata_bytes, bytes.len) catch return error.InstalledBaselineComponentLimit;
        try info.append(allocator, .{
            .name = try allocator.dupe(u8, member.name),
            .bytes = bytes,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
        });
    }
    const status_bytes = try root.readFileAlloc(allocator, try root_fs.Path.init("var/lib/dpkg/status"), 64 * 1024 * 1024);
    var imported = switch (try database.importSnapshot(allocator, .{
        .native_architecture = architecture,
        .snapshot = .{ .status = database.regularFile(status_bytes), .info = info.items },
    }, .{})) {
        .database => |value| value,
        .diagnostic => return error.InvalidInstalledBaselineComponent,
    };
    defer imported.deinit();
    return captureFromDatabase(allocator, root, architecture, packages, imported.model, info.items);
}

pub fn verify(allocator: std.mem.Allocator, root: root_fs.Root, expected: Manifest) !void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    const packages = try owned.alloc(Package, expected.components.len);
    for (expected.components, packages) |component, *package| package.* = component.package;
    const actual = try capture(owned, root, expected.architecture, packages);
    if (!std.mem.eql(u8, &expected.digest(), &actual.digest()))
        return error.InstalledBaselineComponentChanged;
}

test "installed_baseline_component separates unchanged components from owned database additions" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const io = std.testing.io;
    const root = root_fs.Root.init(io, directory.dir);
    const initial_status = "Package: private-baseline\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\nDescription: retained metadata\n\n";
    try directory.dir.createDirPath(io, "var/lib/dpkg/info");
    try directory.dir.createDirPath(io, "usr/share");
    try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = initial_status });
    try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/" ++ database.info_format_name, .data = database.supported_info_format ++ "\n" });
    try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/private-baseline.list", .data = "/usr/share\n/usr/share/private-baseline\n" });
    try directory.dir.writeFile(io, .{ .sub_path = "usr/share/private-baseline", .data = "retained payload\n" });
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const expected = try capture(arena.allocator(), root, "amd64", &.{.{
        .name = "private-baseline",
        .version = "1.0",
        .architecture = "amd64",
        .selection = .install,
    }});
    try verify(std.testing.allocator, root, expected);
    try directory.dir.writeFile(io, .{ .sub_path = "usr/share/alpha", .data = "new authenticated package in runtime tests\n" });
    try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/alpha.list", .data = "/usr/share/alpha\n" });
    try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = initial_status ++ "Package: alpha\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n" });
    try verify(std.testing.allocator, root, expected);
    try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/private-baseline.extra.list", .data = "/usr/share/alpha\n" });
    try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = initial_status ++ "Package: alpha\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\nPackage: private-baseline.extra\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n" });
    try verify(std.testing.allocator, root, expected);
    try directory.dir.writeFile(io, .{ .sub_path = "usr/share/private-baseline", .data = "changed same-version payload\n" });
    try std.testing.expectError(error.InstalledBaselineComponentChanged, verify(std.testing.allocator, root, expected));
}

test "installed_baseline_component refuses status metadata controls callbacks and missing payload" {
    for ([_]enum { status_metadata, list, callback, missing }{ .status_metadata, .list, .callback, .missing }) |mutation| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        const io = std.testing.io;
        const root = root_fs.Root.init(io, directory.dir);
        const initial_status = "Package: private-baseline\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n";
        try directory.dir.createDirPath(io, "var/lib/dpkg/info");
        try directory.dir.createDirPath(io, "usr/share");
        try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = initial_status });
        try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/" ++ database.info_format_name, .data = database.supported_info_format ++ "\n" });
        try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/private-baseline.list", .data = "/usr/share/private-baseline\n" });
        try directory.dir.writeFile(io, .{ .sub_path = "usr/share/private-baseline", .data = "payload\n" });
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const expected = try capture(arena.allocator(), root, "amd64", &.{.{
            .name = "private-baseline",
            .version = "1.0",
            .architecture = "amd64",
            .selection = .install,
        }});
        switch (mutation) {
            .status_metadata => try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = "Package: private-baseline\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\nDescription: changed\n\n" }),
            .list => try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/private-baseline.list", .data = "/usr/share\n/usr/share/private-baseline\n" }),
            .callback => try directory.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/info/private-baseline.postinst", .data = "#!/bin/sh\nexit 0\n" }),
            .missing => try directory.dir.deleteFile(io, "usr/share/private-baseline"),
        }
        if (mutation == .callback)
            try std.testing.expectError(error.InvalidInstalledBaselineComponent, verify(std.testing.allocator, root, expected))
        else if (mutation == .missing)
            try std.testing.expectError(error.FileNotFound, verify(std.testing.allocator, root, expected))
        else
            try std.testing.expectError(error.InstalledBaselineComponentChanged, verify(std.testing.allocator, root, expected));
    }
}

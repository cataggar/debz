const std = @import("std");
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

pub const Pipe = struct { path: []const u8, mode: []const u8 };
pub const Link = struct { path: []const u8, target: []const u8 };

pub const Package = struct {
    workspace: []const u8 = "packages/fifo",
    name: []const u8,
    version: []const u8,
    control_fields: []const u8 = "",
    pipes: []const Pipe = &.{},
    links: []const Link = &.{},
    extra_files: []const foundation.Fixture.ExtraFile = &.{},
    conffile_path: []const u8 = "etc/debz-native.conf",
    conffile_content: ?[]const u8 = null,
};

/// Builds one scriptless FIFO fixture package. FIFOs and extra symbolic links
/// are added to the unpacked source after `makePackage` and the archive is
/// rebuilt, so the real `dpkg-deb` writes tar typeflag `6` exactly as a
/// distribution package would.
pub fn build(fixture: *foundation.Fixture, arch: []const u8, spec: Package) ![]u8 {
    const original = try support.makePackage(fixture, arch, spec.version, spec.name, spec.workspace, .{
        .no_scripts = true,
        .control_fields = spec.control_fields,
        .extra_files = spec.extra_files,
        .conffile_path = spec.conffile_path,
        .conffile_content = spec.conffile_content,
    });
    defer fixture.allocator.free(original);
    const source = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_{s}_data.source", .{ spec.workspace, spec.name, spec.version });
    defer fixture.allocator.free(source);
    for (spec.pipes) |pipe| {
        const relative = try support.path(fixture.allocator, source, pipe.path);
        defer fixture.allocator.free(relative);
        if (std.fs.path.dirname(relative)) |parent| try fixture.directory(parent);
        const absolute = try fixture.absolute(relative);
        defer fixture.allocator.free(absolute);
        const log = try std.fmt.allocPrint(fixture.allocator, "{s}/mkfifo-{s}-{s}.log", .{ spec.workspace, spec.name, spec.version });
        defer fixture.allocator.free(log);
        try fixture.run(&.{ "/usr/bin/mkfifo", absolute }, log, 10);
        // `mkfifo -m` refuses special bits, so the final mode is set apart.
        try fixture.run(&.{ "/usr/bin/chmod", pipe.mode, absolute }, log, 10);
    }
    for (spec.links) |link| {
        const relative = try support.path(fixture.allocator, source, link.path);
        defer fixture.allocator.free(relative);
        try fixture.dir.symLink(fixture.io, link.target, relative, .{});
    }
    const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_{s}_fifo.deb", .{ spec.workspace, spec.name, spec.version });
    defer fixture.allocator.free(destination);
    return fixture.buildPackage(source, destination, .{});
}

/// Requires a FIFO with exactly this mode and owner in every root.
pub fn expect(fixture: *foundation.Fixture, roots: []const []const u8, relative: []const u8, mode: u32, uid: u32, gid: u32) !void {
    for (roots) |root_path| {
        var dir = try foundation.guardedRoot(fixture.io, root_path);
        defer dir.close(fixture.io);
        const entry = try (root_fs.Root.init(fixture.io, dir)).entry(try root_fs.Path.initPackage(relative));
        if (entry.kind != .named_pipe) return error.FifoNotInstalled;
        if (entry.mode != mode or entry.uid != uid or entry.gid != gid) {
            std.debug.print("{s}: {s} mode {o} owner {d}:{d}\n", .{ root_path, relative, entry.mode, entry.uid, entry.gid });
            return error.WrongFifoMetadata;
        }
    }
}

/// Requires `relative` to be absent from every root.
pub fn expectAbsent(fixture: *foundation.Fixture, roots: []const []const u8, relative: []const u8) !void {
    for (roots) |root_path| {
        var dir = try foundation.guardedRoot(fixture.io, root_path);
        defer dir.close(fixture.io);
        if (try (root_fs.Root.init(fixture.io, dir)).entryIfExists(try root_fs.Path.initPackage(relative)) != null)
            return error.FifoLeftBehind;
    }
}

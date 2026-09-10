const std = @import("std");
const native_trigger = @import("native_trigger.zig");
const root_fs = @import("root_fs.zig");

fn environment(name: [*:0]const u8) ![]const u8 {
    const value = std.c.getenv(name) orelse return error.MissingEnvironment;
    return std.mem.span(value);
}

pub fn main(init: std.process.Init) !void {
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    var values: [native_trigger.maximum_helper_arguments + 1][]const u8 =
        undefined;
    var count: usize = 0;
    while (arguments.next()) |argument| {
        if (count == values.len) return error.InvalidArguments;
        values[count] = argument;
        count += 1;
    }
    const package = try environment("DPKG_MAINTSCRIPT_PACKAGE");
    const architecture = try environment("DPKG_MAINTSCRIPT_ARCH");
    const request = try native_trigger.parseHelperInvocation(
        values[0..count],
        .{
            .package = package,
            .architecture = architecture,
            .admindir = try environment("DPKG_ADMINDIR"),
        },
    );

    var owned_root = try root_fs.openAbsoluteRoot(init.io, "/");
    defer owned_root.close();
    try native_trigger.runHelper(
        std.heap.c_allocator,
        init.io,
        owned_root.root,
        request,
    );
}

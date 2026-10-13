//! Static host stand-in for a packaged `bin/debz` that answers only the
//! release smoke probes.
const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 2 and std.mem.eql(u8, args[1], "version"))
        return std.Io.File.stdout().writeStreamingAll(init.io, "debz 0.1.0\n");
    if (args.len == 2 and (std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "--help")))
        return std.Io.File.stdout().writeStreamingAll(init.io, "usage: debz <command> [options] [packages...]\n");
    std.process.exit(2);
}

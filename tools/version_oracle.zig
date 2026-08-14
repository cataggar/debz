const std = @import("std");
const debz = @import("debz");

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const left_text = args.next() orelse return error.MissingLeftVersion;
    const right_text = args.next() orelse return error.MissingRightVersion;
    if (args.next() != null) return error.TooManyArguments;

    const left = try debz.DebianVersion.parse(left_text);
    const right = try debz.DebianVersion.parse(right_text);
    std.debug.print("{s}\n", .{@tagName(left.order(right))});
}

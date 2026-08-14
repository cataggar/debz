const std = @import("std");
const debz = @import("debz");

const usage =
    \\Usage: debz <command> [options]
    \\
    \\Commands:
    \\  refresh install remove upgrade upgrade-all reinstall download plan
    \\  list-installed list-available info provides why clean recover
    \\
    \\This bootstrap CLI does not perform package-manager operations yet.
    \\
;

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const argument = args.next() orelse {
        std.debug.print("{s}", .{usage});
        return;
    };

    if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) {
        std.debug.print("{s}", .{usage});
        return;
    }
    if (std.mem.eql(u8, argument, "--version")) {
        std.debug.print("debz {s}\n", .{debz.version});
        return;
    }
    if (debz.parseOperation(argument) != null) {
        std.debug.print("debz: command '{s}' is not implemented yet\n", .{argument});
        std.process.exit(2);
    }

    std.debug.print("debz: unknown command '{s}'\n{s}", .{ argument, usage });
    std.process.exit(2);
}

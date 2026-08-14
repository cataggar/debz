const std = @import("std");
const solver = @import("solver.zig");

pub const version = "0.1.0";
pub const DebianVersion = @import("debian_version.zig").DebianVersion;
pub const DebianVersionParseError = @import("debian_version.zig").ParseError;
pub const SolverContext = solver.Context;
pub const deb822 = @import("deb822.zig");
pub const relation = @import("relation.zig");

pub const Architecture = enum {
    amd64,
    arm64,
};

pub const RecommendsPolicy = enum {
    exclude,
    include,
};

pub const Config = struct {
    install_root: []const u8,
    architecture: Architecture,
    recommends: RecommendsPolicy = .exclude,
    offline: bool = false,
};

pub const Operation = enum {
    refresh,
    install,
    remove,
    upgrade,
    upgrade_all,
    reinstall,
    download,
    plan,
    list_installed,
    list_available,
    info,
    provides,
    why,
    clean,
    recover,
};

pub const Request = struct {
    operation: Operation,
    packages: []const []const u8 = &.{},
};

pub fn parseOperation(name: []const u8) ?Operation {
    const names = std.StaticStringMap(Operation).initComptime(.{
        .{ "refresh", .refresh },
        .{ "install", .install },
        .{ "remove", .remove },
        .{ "upgrade", .upgrade },
        .{ "upgrade-all", .upgrade_all },
        .{ "reinstall", .reinstall },
        .{ "download", .download },
        .{ "plan", .plan },
        .{ "list-installed", .list_installed },
        .{ "list-available", .list_available },
        .{ "info", .info },
        .{ "provides", .provides },
        .{ "why", .why },
        .{ "clean", .clean },
        .{ "recover", .recover },
    });
    return names.get(name);
}

test "configuration defaults are explicit" {
    const config: Config = .{
        .install_root = "/",
        .architecture = .amd64,
    };

    try std.testing.expectEqual(RecommendsPolicy.exclude, config.recommends);
    try std.testing.expect(!config.offline);
}

test "CLI operations use stable spellings" {
    try std.testing.expectEqual(Operation.upgrade_all, parseOperation("upgrade-all").?);
    try std.testing.expect(parseOperation("unknown") == null);
}

test "empty solver context can be created and destroyed" {
    const context = SolverContext.create();
    context.destroy();
}

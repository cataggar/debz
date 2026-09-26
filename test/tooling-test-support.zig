const std = @import("std");

pub const io = std.testing.io;
pub const allocator = std.testing.allocator;
pub const maximum_file_bytes = 8 * 1024 * 1024;

pub const Work = struct {
    directory: std.testing.TmpDir,
    root: []const u8,

    pub fn init() !Work {
        var directory = std.testing.tmpDir(.{ .iterate = true });
        errdefer directory.cleanup();
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try directory.dir.realPath(io, &buffer);
        return .{
            .directory = directory,
            .root = try allocator.dupe(u8, buffer[0..length]),
        };
    }

    pub fn deinit(self: *Work) void {
        self.directory.cleanup();
        allocator.free(self.root);
    }

    pub fn path(self: *Work, relative: []const u8) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.root, relative });
    }

    pub fn write(self: *Work, relative: []const u8, bytes: []const u8) !void {
        if (std.fs.path.dirname(relative)) |parent|
            try self.directory.dir.createDirPath(io, parent);
        try self.directory.dir.writeFile(io, .{ .sub_path = relative, .data = bytes });
    }

    pub fn read(self: *Work, relative: []const u8) ![]u8 {
        return self.directory.dir.readFileAlloc(io, relative, allocator, .limited(maximum_file_bytes));
    }
};

pub const Result = struct {
    code: u8,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: Result) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }

    pub fn ok(self: Result) !void {
        if (self.code != 0) {
            std.debug.print("command failed ({d}):\nstdout: {s}\nstderr: {s}\n", .{
                self.code, self.stdout, self.stderr,
            });
            return error.UnexpectedCommandFailure;
        }
    }

    pub fn failsWith(self: Result, message: []const u8) !void {
        if (self.code == 0 or std.mem.indexOf(u8, self.stderr, message) == null) {
            std.debug.print("expected failure containing '{s}', got {d}:\nstdout: {s}\nstderr: {s}\n", .{
                message, self.code, self.stdout, self.stderr,
            });
            return error.MissingFailureDiagnostic;
        }
    }
};

pub fn run(argv: []const []const u8) !Result {
    return runIn(argv, .inherit);
}

pub fn runIn(argv: []const []const u8, cwd: std.process.Child.Cwd) !Result {
    return runWithTimeout(argv, cwd, 30);
}

pub fn runWithTimeout(argv: []const []const u8, cwd: std.process.Child.Cwd, seconds: u32) !Result {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .cwd = cwd,
        .stdout_limit = .limited(256 * 1024),
        .stderr_limit = .limited(256 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(seconds), .clock = .awake } },
    });
    return .{
        .code = switch (result.term) {
            .exited => |code| code,
            else => 255,
        },
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
}

pub fn contains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing '{s}' in:\n{s}\n", .{ needle, haystack });
        return error.MissingExpectedText;
    }
}

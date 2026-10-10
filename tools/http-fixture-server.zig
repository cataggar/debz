const std = @import("std");
const fs = @import("debz").root_fs;

const maximum_file_bytes = 128 * 1024 * 1024;
const maximum_request_bytes = 16 * 1024;

fn requestPath(target: []const u8) ![]const u8 {
    if (target.len == 0 or target[0] != '/') return error.InvalidRequestTarget;
    const end = std.mem.indexOfAny(u8, target, "?#") orelse target.len;
    const path = target[0..end];
    for (path) |byte| {
        if (byte < 0x20 or byte == 0x7f) return error.InvalidRequestTarget;
    }
    return path;
}

fn filePath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const decoded = try allocator.alloc(u8, path.len);
    var length: usize = 0;
    var index: usize = 1;
    while (index < path.len) {
        const byte = if (path[index] == '%') percent: {
            if (path.len - index < 3) return error.InvalidRequestTarget;
            const value = std.fmt.parseInt(u8, path[index + 1 ..][0..2], 16) catch
                return error.InvalidRequestTarget;
            index += 3;
            break :percent value;
        } else plain: {
            const value = path[index];
            index += 1;
            break :plain value;
        };
        decoded[length] = byte;
        length += 1;
    }
    const relative = decoded[0..length];
    _ = try fs.Path.init(relative);
    return relative;
}

fn readFixture(root: fs.Root, allocator: std.mem.Allocator, relative: []const u8) ![]u8 {
    var pin = try root.pinRegularFile(try fs.Path.init(relative));
    defer pin.close();
    const metadata = try pin.metadata();
    if (metadata.entry.link_count != 1) return error.HardLinkedFixture;
    return (try pin.observeStableAlloc(allocator, maximum_file_bytes)).bytes;
}

const FixtureServer = struct {
    io: std.Io,
    root: fs.Root,
    log: std.Io.File,
    log_mutex: std.Io.Mutex = .init,
    slots: std.Io.Semaphore = .{ .permits = 16 },

    fn record(self: *FixtureServer, path: []const u8) !void {
        try self.log_mutex.lock(self.io);
        defer self.log_mutex.unlock(self.io);
        try self.log.writeStreamingAll(self.io, path);
        try self.log.writeStreamingAll(self.io, "\n");
    }

    fn handle(self: *FixtureServer, stream: std.Io.net.Stream) !void {
        defer stream.close(self.io);
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var read_buffer: [maximum_request_bytes]u8 = undefined;
        var write_buffer: [8192]u8 = undefined;
        var reader = stream.reader(self.io, &read_buffer);
        var writer = stream.writer(self.io, &write_buffer);
        var http = std.http.Server.init(&reader.interface, &writer.interface);
        var request = http.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => return,
            error.ReadFailed => return reader.err.?,
            else => return err,
        };
        const path = try requestPath(request.head.target);
        try self.record(path);
        if (request.head.method != .GET and request.head.method != .HEAD) {
            try request.respond("unsupported fixture method\n", .{ .status = .not_implemented, .keep_alive = false });
            return;
        }
        const relative = filePath(allocator, path) catch |err| {
            if (err == error.OutOfMemory) return err;
            std.log.err("fixture path refused: {s}", .{@errorName(err)});
            try request.respond("invalid fixture path\n", .{ .status = .bad_request, .keep_alive = false });
            return;
        };
        const bytes = readFixture(self.root, allocator, relative) catch |err| {
            if (err == error.OutOfMemory) return err;
            if (err == error.FileNotFound) {
                try request.respond("fixture not found\n", .{ .status = .not_found, .keep_alive = false });
                return;
            }
            std.log.err("fixture read refused: {s}: {s}", .{ path, @errorName(err) });
            try request.respond("fixture read refused\n", .{ .status = .forbidden, .keep_alive = false });
            return;
        };
        try request.respond(bytes, .{
            .keep_alive = false,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/octet-stream" }},
        });
    }

    fn worker(self: *FixtureServer, stream: std.Io.net.Stream) void {
        defer self.slots.post(self.io);
        self.handle(stream) catch |err| {
            if (err == error.Canceled) return;
            std.log.err("fixture request failed: {s}", .{@errorName(err)});
        };
    }

    fn run(self: *FixtureServer, listener: *std.Io.net.Server) !void {
        var group: std.Io.Group = .init;
        defer group.cancel(self.io);
        while (true) {
            try self.slots.wait(self.io);
            const stream = listener.accept(self.io) catch |err| {
                self.slots.post(self.io);
                return err;
            };
            group.concurrent(self.io, worker, .{ self, stream }) catch |err| {
                stream.close(self.io);
                self.slots.post(self.io);
                return err;
            };
        }
    }
};

fn createOutput(io: std.Io, path: []const u8) !std.Io.File {
    if (!std.fs.path.isAbsolute(path)) return error.FixturePathsMustBeAbsolute;
    const parent_path = std.fs.path.dirname(path) orelse return error.InvalidOutputPath;
    var root = try fs.openAbsoluteRoot(io, parent_path);
    defer root.close();
    return root.root.createRegularFile(try fs.Path.init(std.fs.path.basename(path)), .{
        .permissions = .fromMode(0o600),
    });
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    var root_path: ?[]const u8 = null;
    var port_path: ?[]const u8 = null;
    var log_path: ?[]const u8 = null;
    while (args.next()) |argument| {
        const destination = if (std.mem.eql(u8, argument, "--root")) &root_path else if (std.mem.eql(u8, argument, "--port-file")) &port_path else if (std.mem.eql(u8, argument, "--request-log")) &log_path else return error.InvalidArguments;
        if (destination.* != null) return error.DuplicateArgument;
        destination.* = args.next() orelse return error.MissingArgument;
    }
    var root = try fs.openAbsoluteRoot(init.io, root_path orelse return error.MissingRoot);
    defer root.close();
    const log = try createOutput(init.io, log_path orelse return error.MissingRequestLog);
    defer log.close(init.io);
    const port_file = try createOutput(init.io, port_path orelse return error.MissingPortFile);
    defer port_file.close(init.io);
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var listener = try address.listen(init.io, .{});
    defer listener.deinit(init.io);
    var port_buffer: [16]u8 = undefined;
    try port_file.writeStreamingAll(init.io, try std.fmt.bufPrint(&port_buffer, "{d}\n", .{listener.socket.address.getPort()}));
    var server: FixtureServer = .{ .io = init.io, .root = root.root, .log = log };
    try server.run(&listener);
}

test "fixture request paths redact secrets and reject decoded traversal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expectEqualStrings("/pool/pkg%20name.deb", try requestPath("/pool/pkg%20name.deb?token=secret#private"));
    try std.testing.expectEqualStrings("pool/pkg name.deb", try filePath(allocator, "/pool/pkg%20name.deb"));
    for ([_][]const u8{ "/../secret", "/%2e%2e/secret", "/pkg%00", "/pkg%0a", "/pkg%zz", "/pkg%", "//outside", "/pkg%5csecret" }) |path| {
        if (filePath(allocator, path)) |_| return error.AcceptedUnsafeFixturePath else |_| {}
    }
}

fn exchange(server: *FixtureServer, request: []const u8) ![]u8 {
    const io = server.io;
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const accepted = try listener.accept(io);
    var future = try std.Io.concurrent(io, FixtureServer.handle, .{ server, accepted });
    defer future.cancel(io) catch |err| {
        std.debug.print("fixture handler cleanup: {s}\n", .{@errorName(err)});
    };
    var writer = client.writer(io, &.{});
    try writer.interface.writeAll(request);
    try writer.interface.flush();
    var buffer: [4096]u8 = undefined;
    var reader = client.reader(io, &buffer);
    const result = try reader.interface.allocRemaining(std.testing.allocator, .limited(64 * 1024));
    errdefer std.testing.allocator.free(result);
    try future.await(io);
    return result;
}

test "an idle fixture connection does not block another actual HTTP request" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(io, .{ .sub_path = "original", .data = "concurrent original bytes" });
    const log = try temporary.dir.createFile(io, "requests", .{});
    defer log.close(io);
    var server: FixtureServer = .{ .io = io, .root = .init(io, temporary.dir), .log = log };
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    var future = try std.Io.concurrent(io, FixtureServer.run, .{ &server, &listener });
    defer future.cancel(io) catch |err| {
        if (err != error.Canceled) std.debug.print("fixture server cleanup: {s}\n", .{@errorName(err)});
    };
    const idle = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer idle.close(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    var writer = client.writer(io, &.{});
    try writer.interface.writeAll("GET /original HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try writer.interface.flush();
    var buffer: [4096]u8 = undefined;
    var reader = client.reader(io, &buffer);
    const response = try reader.interface.allocRemaining(std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 "));
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nconcurrent original bytes"));
}

test "actual native HTTP serves exact binary GET and HEAD, redacts queries and retains missing requests" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const binary = "original\x00fixture\xffbytes";
    try temporary.dir.writeFile(io, .{ .sub_path = "pkg name.deb", .data = binary });
    const log = try temporary.dir.createFile(io, "requests", .{});
    defer log.close(io);
    var server: FixtureServer = .{ .io = io, .root = .init(io, temporary.dir), .log = log };
    const get = try exchange(&server, "GET /pkg%20name.deb?token=secret HTTP/1.1\r\nHost: localhost\r\n\r\n");
    defer std.testing.allocator.free(get);
    try std.testing.expect(std.mem.startsWith(u8, get, "HTTP/1.1 200 "));
    try std.testing.expectEqualStrings(binary, get[(std.mem.indexOf(u8, get, "\r\n\r\n") orelse return error.MissingHttpBody) + 4 ..]);
    const head = try exchange(&server, "HEAD /pkg%20name.deb HTTP/1.1\r\nHost: localhost\r\n\r\n");
    defer std.testing.allocator.free(head);
    try std.testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 200 "));
    try std.testing.expect(std.mem.endsWith(u8, head, "\r\n\r\n"));
    const length = try std.fmt.allocPrint(std.testing.allocator, "content-length: {d}\r\n", .{binary.len});
    defer std.testing.allocator.free(length);
    try std.testing.expect(std.mem.indexOf(u8, head, length) != null);
    const missing = try exchange(&server, "GET /missing?private=value HTTP/1.1\r\nHost: localhost\r\n\r\n");
    defer std.testing.allocator.free(missing);
    try std.testing.expect(std.mem.startsWith(u8, missing, "HTTP/1.1 404 "));
    const requests = try temporary.dir.readFileAlloc(io, "requests", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(requests);
    try std.testing.expectEqualStrings("/pkg%20name.deb\n/pkg%20name.deb\n/missing\n", requests);
}

test "fixture source links, pipes, oversize and output overwrites refuse without changing originals" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root: fs.Root = .init(io, temporary.dir);
    try temporary.dir.writeFile(io, .{ .sub_path = "original", .data = "original bytes" });
    try temporary.dir.symLink(io, "original", "alias", .{});
    try std.testing.expectError(error.NotRegularFile, readFixture(root, std.testing.allocator, "alias"));
    try root.createHardLink(try fs.Path.init("original"), try fs.Path.init("hardlink"));
    try std.testing.expectError(error.HardLinkedFixture, readFixture(root, std.testing.allocator, "hardlink"));
    try root.createNamedPipe(try fs.Path.init("pipe"));
    try std.testing.expectError(error.NotRegularFile, readFixture(root, std.testing.allocator, "pipe"));
    const oversized = try temporary.dir.createFile(io, "oversized", .{});
    defer oversized.close(io);
    try oversized.setLength(io, maximum_file_bytes + 1);
    try std.testing.expectError(error.FileTooLarge, readFixture(root, std.testing.allocator, "oversized"));
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temporary.dir.realPath(io, &path_buffer);
    for ([_][]const u8{ "original", "alias" }) |name| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/{s}", .{ path_buffer[0..length], name });
        defer std.testing.allocator.free(path);
        try std.testing.expectError(error.PathAlreadyExists, createOutput(io, path));
    }
    const original = try temporary.dir.readFileAlloc(io, "original", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(original);
    try std.testing.expectEqualStrings("original bytes", original);
}

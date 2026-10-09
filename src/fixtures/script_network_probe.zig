const std = @import("std");
const linux = std.os.linux;
const endian = @import("builtin").cpu.arch.endian();

const Header = extern struct {
    length: u32,
    kind: u16,
    flags: u16,
    sequence: u32,
    pid: u32,
};
const Link = extern struct {
    family: u8 = 0,
    padding: u8 = 0,
    kind: u16 = 0,
    index: i32 = 0,
    flags: u32 = 0,
    change: u32 = 0,
};
const Route = extern struct {
    family: u8 = 0,
    destination_bits: u8 = 0,
    source_bits: u8 = 0,
    tos: u8 = 0,
    table: u8 = 0,
    protocol: u8 = 0,
    scope: u8 = 0,
    kind: u8 = 0,
    flags: u32 = 0,
};
const NetlinkAddress = extern struct {
    family: u16 = linux.AF.NETLINK,
    padding: u16 = 0,
    pid: u32 = 0,
    groups: u32 = 0,
};

fn checked(result: usize) !usize {
    return switch (linux.errno(result)) {
        .SUCCESS => result,
        else => |err| {
            std.log.err("network observation refused: {s}", .{@tagName(err)});
            return error.NetworkObservationFailed;
        },
    };
}

fn waitReadable(fd: i32) !void {
    var descriptors = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    if (try checked(linux.poll(&descriptors, descriptors.len, 200)) != 1 or
        descriptors[0].revents & linux.POLL.IN == 0)
        return error.NetworkObservationTimeout;
}

const Topology = struct {
    links: usize = 0,
    loopback: bool = false,
    other_link: bool = false,
    default_route: bool = false,

    fn link(self: *Topology, payload: []const u8) !void {
        if (payload.len < @sizeOf(Link)) return error.MalformedNetworkObservation;
        const info = std.mem.bytesToValue(Link, payload[0..@sizeOf(Link)]);
        var offset: usize = @sizeOf(Link);
        var name: ?[]const u8 = null;
        while (offset < payload.len) {
            if (payload.len - offset < 4) return error.MalformedNetworkObservation;
            const size = std.mem.readInt(u16, payload[offset..][0..2], endian);
            const kind = std.mem.readInt(u16, payload[offset + 2 ..][0..2], endian);
            if (size < 4 or size > payload.len - offset) return error.MalformedNetworkObservation;
            if (kind == 3) {
                if (name != null) return error.MalformedNetworkObservation;
                const value = payload[offset + 4 .. offset + size];
                const end = std.mem.indexOfScalar(u8, value, 0) orelse
                    return error.MalformedNetworkObservation;
                name = value[0..end];
            }
            const next = std.mem.alignForward(usize, size, 4);
            if (next > payload.len - offset) return error.MalformedNetworkObservation;
            offset += next;
        }
        self.links += 1;
        if (name) |value| {
            if (std.mem.eql(u8, value, "lo") and info.flags & 0x9 == 0x9) {
                self.loopback = true;
                return;
            }
        } else return error.MalformedNetworkObservation;
        self.other_link = true;
    }

    fn route(self: *Topology, payload: []const u8) !void {
        if (payload.len < @sizeOf(Route)) return error.MalformedNetworkObservation;
        const info = std.mem.bytesToValue(Route, payload[0..@sizeOf(Route)]);
        if ((info.family == linux.AF.INET or info.family == linux.AF.INET6) and
            info.destination_bits == 0 and info.kind == 1)
            self.default_route = true;
    }
};

fn dump(topology: *Topology, comptime Payload: type, request_kind: u16, response_kind: u16) !void {
    const fd: i32 = @intCast(try checked(linux.socket(
        linux.AF.NETLINK,
        linux.SOCK.RAW | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    )));
    defer _ = linux.close(fd);
    const address: NetlinkAddress = .{};
    const Request = extern struct { header: Header, payload: Payload };
    const request: Request = .{
        .header = .{
            .length = @sizeOf(Request),
            .kind = request_kind,
            .flags = 0x301,
            .sequence = 1,
            .pid = 0,
        },
        .payload = .{},
    };
    const sent = try checked(linux.sendto(
        fd,
        @ptrCast(&request),
        @sizeOf(Request),
        0,
        @ptrCast(&address),
        @sizeOf(NetlinkAddress),
    ));
    if (sent != @sizeOf(Request)) return error.NetworkObservationFailed;
    var buffer: [16 * 1024]u8 = undefined;
    for (0..16) |_| {
        try waitReadable(fd);
        var sender: NetlinkAddress = .{};
        var size: linux.socklen_t = @sizeOf(NetlinkAddress);
        const received = try checked(linux.recvfrom(
            fd,
            &buffer,
            buffer.len,
            linux.MSG.TRUNC,
            @ptrCast(&sender),
            &size,
        ));
        if (received == 0 or received > buffer.len or sender.pid != 0 or
            size != @sizeOf(NetlinkAddress))
            return error.MalformedNetworkObservation;
        var offset: usize = 0;
        while (offset < received) {
            if (received - offset < @sizeOf(Header)) return error.MalformedNetworkObservation;
            const header = std.mem.bytesToValue(Header, buffer[offset..][0..@sizeOf(Header)]);
            if (header.length < @sizeOf(Header) or header.length > received - offset or
                header.sequence != 1 or header.flags & 0x10 != 0)
                return error.MalformedNetworkObservation;
            const payload = buffer[offset + @sizeOf(Header) .. offset + header.length];
            switch (header.kind) {
                3 => {
                    if (payload.len < 4 or
                        std.mem.readInt(i32, payload[0..4], endian) != 0)
                        return error.NetworkObservationFailed;
                    return;
                },
                2 => return error.NetworkObservationFailed,
                else => {
                    if (header.kind != response_kind) return error.MalformedNetworkObservation;
                    if (Payload == Link) try topology.link(payload) else try topology.route(payload);
                },
            }
            const next = std.mem.alignForward(usize, header.length, 4);
            if (next > received - offset) return error.MalformedNetworkObservation;
            offset += next;
        }
    }
    return error.NetworkObservationLimit;
}

fn connection(fd: i32, address: *const linux.sockaddr, length: linux.socklen_t) !linux.E {
    const result = linux.errno(linux.connect(fd, address, length));
    if (result != .INPROGRESS) return result;
    var descriptors = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    if (try checked(linux.poll(&descriptors, descriptors.len, 200)) != 1)
        return error.NetworkObservationTimeout;
    var value: i32 = 0;
    var size: linux.socklen_t = @sizeOf(i32);
    _ = try checked(linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&value), &size));
    if (size != @sizeOf(i32) or value < 0 or value > 4095)
        return error.MalformedNetworkObservation;
    return @enumFromInt(value);
}

fn tcp(port: u16) !linux.E {
    const fd: i32 = @intCast(try checked(linux.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    )));
    defer _ = linux.close(fd);
    const address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    return connection(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
}

fn abstractUnix(name: []const u8) !linux.E {
    if (name.len == 0 or name.len >= 107 or std.mem.indexOfScalar(u8, name, 0) != null)
        return error.InvalidNetworkProbeArguments;
    const fd: i32 = @intCast(try checked(linux.socket(
        linux.AF.UNIX,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    )));
    defer _ = linux.close(fd);
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(address.path[1..][0..name.len], name);
    return connection(fd, @ptrCast(&address), @intCast(2 + 1 + name.len));
}

fn privateLoopback() !void {
    const fd: i32 = @intCast(try checked(linux.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    )));
    defer _ = linux.close(fd);
    var address: linux.sockaddr.in = .{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    _ = try checked(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in)));
    _ = try checked(linux.listen(fd, 1));
    var size: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = try checked(linux.getsockname(fd, @ptrCast(&address), &size));
    if (size != @sizeOf(linux.sockaddr.in) or address.port == 0 or
        try tcp(std.mem.bigToNative(u16, address.port)) != .SUCCESS)
        return error.PrivateLoopbackUnavailable;
}

fn present(path: [*:0]const u8) !bool {
    const result = linux.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
    switch (linux.errno(result)) {
        .SUCCESS => {
            _ = linux.close(@intCast(result));
            return true;
        },
        .NOENT => return false,
        else => return error.NetworkObservationFailed,
    }
}

fn readProcNetwork(path: [*:0]const u8, buffer: []u8) ![]const u8 {
    const fd: i32 = @intCast(try checked(linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0)));
    defer _ = linux.close(fd);
    var length: usize = 0;
    while (length < buffer.len) {
        const size = try checked(linux.read(fd, buffer[length..].ptr, buffer.len - length));
        if (size == 0) return buffer[0..length];
        length += size;
    }
    return error.NetworkObservationTooLarge;
}

fn privateProcNetwork(devices: []const u8, routes: []const u8) !void {
    var lines = std.mem.splitScalar(u8, devices, '\n');
    if (!std.mem.startsWith(u8, lines.next() orelse return error.MalformedNetworkObservation, "Inter-") or
        !std.mem.startsWith(u8, std.mem.trim(u8, lines.next() orelse return error.MalformedNetworkObservation, " \t"), "face"))
        return error.MalformedNetworkObservation;
    var interfaces: usize = 0;
    while (lines.next()) |line| {
        const row = std.mem.trim(u8, line, " \t\r");
        if (row.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, row, ':') orelse return error.MalformedNetworkObservation;
        if (!std.mem.eql(u8, std.mem.trim(u8, row[0..colon], " \t"), "lo"))
            return error.ProcNetworkBoundaryFailed;
        interfaces += 1;
    }
    if (interfaces != 1) return error.ProcNetworkBoundaryFailed;
    lines = std.mem.splitScalar(u8, routes, '\n');
    if (!std.mem.startsWith(u8, lines.next() orelse return error.MalformedNetworkObservation, "Iface\tDestination\tGateway"))
        return error.MalformedNetworkObservation;
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const interface = fields.next() orelse continue;
        if (!std.mem.eql(u8, interface, "lo")) return error.ProcNetworkBoundaryFailed;
        var values: [10][]const u8 = undefined;
        for (&values) |*value| value.* = fields.next() orelse return error.MalformedNetworkObservation;
        if (fields.next() != null) return error.MalformedNetworkObservation;
        const destination = try std.fmt.parseInt(u32, values[0], 16);
        const mask = try std.fmt.parseInt(u32, values[6], 16);
        if (destination == 0 and mask == 0) return error.ProcNetworkBoundaryFailed;
    }
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const mode = args.next() orelse return error.InvalidNetworkProbeArguments;
    const port = try std.fmt.parseInt(u16, args.next() orelse return error.InvalidNetworkProbeArguments, 10);
    const unix_name = args.next() orelse return error.InvalidNetworkProbeArguments;
    const inherited = try std.fmt.parseInt(i32, args.next() orelse return error.InvalidNetworkProbeArguments, 10);
    if (port == 0 or inherited < 200 or args.next() != null)
        return error.InvalidNetworkProbeArguments;
    const host = std.mem.eql(u8, mode, "host");
    if (!host and !std.mem.eql(u8, mode, "systemd") and !std.mem.eql(u8, mode, "udev"))
        return error.InvalidNetworkProbeArguments;

    // Observe the inherited descriptor before new sockets could reuse its number.
    const inherited_result = linux.errno(linux.fcntl(inherited, linux.F.GETFD, 0));
    if (inherited_result != (if (host) linux.E.SUCCESS else linux.E.BADF))
        return error.InheritedDescriptorBoundaryFailed;
    const systemd = std.mem.eql(u8, mode, "systemd");
    if (try present("/proc/net") != (host or systemd)) return error.ProcNetworkBoundaryFailed;
    if (!host) {
        if (systemd) {
            // The existing full proc profile exposes this private network namespace.
            var devices: [16384]u8 = undefined;
            var routes: [16384]u8 = undefined;
            try privateProcNetwork(
                try readProcNetwork("/proc/net/dev", &devices),
                try readProcNetwork("/proc/net/route", &routes),
            );
            if (!try present("/proc/sys/kernel/random/boot_id") or
                try present("/proc/sys/kernel/random/uuid"))
                return error.SignedProcBoundaryFailed;
        } else {
            if (try present("/proc/net/dev") or try present("/proc/net/route"))
                return error.ProcNetworkBoundaryFailed;
            if (try present("/proc/sys")) return error.SignedProcBoundaryFailed;
        }
    }
    var topology: Topology = .{};
    try dump(&topology, Link, 18, 16);
    try dump(&topology, Route, 26, 24);
    if (!topology.loopback or topology.links == 0 or
        (!host and (topology.links != 1 or topology.other_link or topology.default_route)))
        return error.NetworkTopologyBoundaryFailed;
    const host_tcp = try tcp(port);
    const host_unix = try abstractUnix(unix_name);
    if (host) {
        if (host_tcp != .SUCCESS or host_unix != .SUCCESS)
            return error.HostNetworkControlFailed;
    } else if (host_tcp != .CONNREFUSED or host_unix != .CONNREFUSED) {
        return error.HostNetworkBoundaryFailed;
    }
    try privateLoopback();
    const receipt = if (host)
        "DEBZ_HOST_NETWORK_PROOF tcp=reachable abstract_unix=reachable inherited_fd=open\n"
    else if (systemd)
        "DEBZ_SIGNED_NETWORK_PROOF proc_net=private interfaces=lo default_route=false host_tcp=denied abstract_unix=denied inherited_fd=sealed loopback=ok\n"
    else
        "DEBZ_SIGNED_NETWORK_PROOF proc_net=absent interfaces=lo default_route=false host_tcp=denied abstract_unix=denied inherited_fd=sealed loopback=ok\n";
    if (try checked(linux.write(1, receipt.ptr, receipt.len)) != receipt.len)
        return error.NetworkReceiptFailed;
}

test "network probe observes routes instead of inferring isolation from hidden proc" {
    var topology: Topology = .{};
    const default: Route = .{ .family = linux.AF.INET, .kind = 1, .table = 254 };
    try topology.route(std.mem.asBytes(&default));
    try std.testing.expect(topology.default_route);
    topology = .{};
    const loopback: Route = .{ .family = linux.AF.INET, .kind = 2, .destination_bits = 32 };
    try topology.route(std.mem.asBytes(&loopback));
    try std.testing.expect(!topology.default_route);
    const default_v6: Route = .{ .family = linux.AF.INET6, .kind = 1 };
    try topology.route(std.mem.asBytes(&default_v6));
    try std.testing.expect(topology.default_route);
    try std.testing.expectError(error.MalformedNetworkObservation, topology.route("short"));
}

test "network probe rejects malformed or missing interface identity" {
    var topology: Topology = .{};
    const info: Link = .{ .flags = 0x9 };
    var bytes: [@sizeOf(Link) + 8]u8 = @splat(0);
    @memcpy(bytes[0..@sizeOf(Link)], std.mem.asBytes(&info));
    std.mem.writeInt(u16, bytes[@sizeOf(Link)..][0..2], 7, endian);
    std.mem.writeInt(u16, bytes[@sizeOf(Link) + 2 ..][0..2], 3, endian);
    @memcpy(bytes[@sizeOf(Link) + 4 ..][0..3], "lo\x00");
    try topology.link(&bytes);
    try std.testing.expect(topology.loopback);
    try std.testing.expectEqual(@as(usize, 1), topology.links);
    try std.testing.expectError(error.MalformedNetworkObservation, topology.link(std.mem.asBytes(&info)));
    bytes[bytes.len - 2] = 'x';
    try std.testing.expectError(error.MalformedNetworkObservation, topology.link(&bytes));
}

test "systemd proc network view must show only one private loopback interface" {
    const header = "Inter-| Receive | Transmit\n face |bytes packets\n";
    const routes = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";
    try privateProcNetwork(header ++ " lo: 0\n", routes);
    try std.testing.expectError(error.ProcNetworkBoundaryFailed, privateProcNetwork(header, routes));
    try std.testing.expectError(error.ProcNetworkBoundaryFailed, privateProcNetwork(header ++ " lo: 0\n eth0: 0\n", routes));
    try std.testing.expectError(error.ProcNetworkBoundaryFailed, privateProcNetwork(header ++ " lo: 0\n lo: 0\n", routes));
    try std.testing.expectError(error.MalformedNetworkObservation, privateProcNetwork("lo: 0\n", routes));
}

test "systemd proc routes must not contain external interfaces or a default route" {
    const devices = "Inter-| Receive | Transmit\n face |bytes packets\n lo: 0\n";
    const header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";
    try privateProcNetwork(devices, header ++ "lo 0000007F 00000000 0001 0 0 0 000000FF 0 0 0\n");
    try std.testing.expectError(error.ProcNetworkBoundaryFailed, privateProcNetwork(devices, header ++ "lo 00000000 00000000 0001 0 0 0 00000000 0 0 0\n"));
    try std.testing.expectError(error.ProcNetworkBoundaryFailed, privateProcNetwork(devices, header ++ "eth0 0000007F 00000000 0001 0 0 0 000000FF 0 0 0\n"));
    try std.testing.expectError(error.MalformedNetworkObservation, privateProcNetwork(devices, header ++ "lo 0000007F\n"));
}

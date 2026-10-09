const linux = @import("std").os.linux;

pub fn setupLoopback() linux.E {
    const opened = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(opened) != .SUCCESS) return linux.errno(opened);
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);
    var request: linux.ifreq = .{
        .ifrn = .{ .name = .{ 'l', 'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
        .ifru = undefined,
    };
    const fetched = linux.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&request)));
    if (fetched != .SUCCESS) return fetched;
    request.ifru.flags.UP = true;
    const applied = linux.errno(linux.ioctl(fd, linux.SIOCSIFFLAGS, @intFromPtr(&request)));
    if (applied != .SUCCESS) return applied;
    const verified = linux.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&request)));
    if (verified != .SUCCESS) return verified;
    if (!request.ifru.flags.UP or !request.ifru.flags.LOOPBACK) return .NODEV;
    return .SUCCESS;
}

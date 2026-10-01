const std = @import("std");

pub fn appendAr(allocator: std.mem.Allocator, ar: *std.ArrayList(u8), name: []const u8, content: []const u8) !void {
    var header: [60]u8 = @splat(' ');
    std.mem.copyForwards(u8, &header, name);
    header[16] = '0';
    header[28] = '0';
    header[34] = '0';
    std.mem.copyForwards(u8, header[40..], "100644");
    const size = try std.fmt.bufPrint(header[48..58], "{d}", .{content.len});
    @memset(header[48 + size.len .. 58], ' ');
    header[58] = '`';
    header[59] = '\n';
    try ar.appendSlice(allocator, &header);
    try ar.appendSlice(allocator, content);
    if (content.len % 2 != 0) try ar.append(allocator, '\n');
}

pub const TarEntry = struct {
    path: []const u8,
    kind: u8 = '0',
    mode: u32 = 0o644,
    content: []const u8 = "",
};

/// Appends one root-owned USTAR entry with an empty link field.
pub fn appendTar(allocator: std.mem.Allocator, tar: *std.ArrayList(u8), entry: TarEntry) !void {
    var header: [512]u8 = @splat(0);
    std.mem.copyForwards(u8, header[0..100], entry.path);
    writeOctal(header[100..108], entry.mode);
    writeOctal(header[108..116], 0);
    writeOctal(header[116..124], 0);
    writeOctal(header[124..136], entry.content.len);
    writeOctal(header[136..148], 0);
    @memset(header[148..156], ' ');
    header[156] = entry.kind;
    std.mem.copyForwards(u8, header[257..], "ustar\x00");
    std.mem.copyForwards(u8, header[263..], "00");
    var checksum: u64 = 0;
    for (header) |byte| checksum += byte;
    writeOctal(header[148..156], checksum);
    try tar.appendSlice(allocator, &header);
    try tar.appendSlice(allocator, entry.content);
    try tar.appendNTimes(allocator, 0, (512 - (entry.content.len % 512)) % 512);
}

/// Builds an uncompressed `.deb` whose control member carries `control_record`
/// plus `control_extra` entries and whose data member carries `data`.
pub fn deb(
    allocator: std.mem.Allocator,
    control_record: []const u8,
    control_extra: []const TarEntry,
    data: []const TarEntry,
) ![]u8 {
    var control: std.ArrayList(u8) = .empty;
    defer control.deinit(allocator);
    try appendTar(allocator, &control, .{ .path = "./control", .content = control_record });
    for (control_extra) |entry| try appendTar(allocator, &control, entry);
    try control.appendNTimes(allocator, 0, 1024);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    for (data) |entry| try appendTar(allocator, &payload, entry);
    try payload.appendNTimes(allocator, 0, 1024);
    var ar: std.ArrayList(u8) = .empty;
    errdefer ar.deinit(allocator);
    try ar.appendSlice(allocator, "!<arch>\n");
    try appendAr(allocator, &ar, "debian-binary/", "2.0\n");
    try appendAr(allocator, &ar, "control.tar/", control.items);
    try appendAr(allocator, &ar, "data.tar/", payload.items);
    return ar.toOwnedSlice(allocator);
}

fn writeOctal(field: []u8, value: u64) void {
    @memset(field, '0');
    field[field.len - 1] = 0;
    var index = field.len - 1;
    var remaining = value;
    while (remaining != 0 and index != 0) {
        index -= 1;
        field[index] = @intCast('0' + remaining % 8);
        remaining /= 8;
    }
}

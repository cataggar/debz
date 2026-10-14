const std = @import("std");
const telemetry = @import("native_phase_telemetry");

pub const std_options: std.Options = .{ .log_level = .info, .logFn = captureLog };

var log_count: usize = 0;
var log_buffer: [2048]u8 = undefined;
var log_length: usize = 0;

fn captureLog(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = level;
    _ = scope;
    log_length = (std.fmt.bufPrint(&log_buffer, format, args) catch unreachable).len;
    log_count += 1;
}

pub fn main(init: std.process.Init) !void {
    const enabled = std.mem.eql(u8, std.mem.span(std.c.getenv("EXPECT_NATIVE_PHASE_TELEMETRY").?), "1");
    var context = telemetry.Context.initConfigured(init.io, @splat(3));
    context.attach();
    defer context.detach();
    telemetry.start(.hash).end();
    try std.testing.expectEqual(@as(u64, if (enabled) 1 else 0), context.measurement(.hash).count);
    try std.testing.expectEqual(@as(usize, 0), log_count);
    telemetry.progressPublished("database", 7, 2, 3, "completed", "applied", .{
        .version = 4,
        .intent_sha256 = @splat('a'),
        .sequence = 9,
        .record_sha256 = @splat('b'),
        .document_sha256 = @splat('c'),
    });
    try std.testing.expectEqual(@as(u64, if (enabled) 1 else 0), context.sequence);
    try std.testing.expectEqual(@as(usize, if (enabled) 1 else 0), log_count);
    if (enabled) {
        const line = log_buffer[0..log_length];
        try std.testing.expect(std.mem.startsWith(u8, line, "native_phase attempt="));
        try std.testing.expect(std.mem.indexOf(u8, line, "kind=database program_step=7 substep=2 ordinal=3 stage=completed result=applied elapsed_ns=") != null);
        try std.testing.expect(std.mem.indexOf(u8, line, "hash_count=1 ") != null);
        try std.testing.expect(std.mem.indexOf(u8, line, "schema=" ++ telemetry.schema_id ++ " version=1 clock=awake published=true progress_version=4") != null);
        try std.testing.expect(std.mem.indexOf(u8, line, "progress_sequence=9 progress_record_sha256=") != null);
        try std.testing.expect(std.mem.indexOf(u8, line, "intent_sha256=" ++ ("a" ** 64) ++
            " progress_sequence=9 progress_record_sha256=" ++ ("b" ** 64) ++
            " progress_document_sha256=" ++ ("c" ** 64)) != null);
    }
    context.detach();
    try std.testing.expectEqual(@as(usize, if (enabled) 2 else 0), log_count);
    if (enabled) {
        const line = log_buffer[0..log_length];
        try std.testing.expect(std.mem.indexOf(u8, line, "kind=attempt_end ") != null);
        try std.testing.expect(std.mem.indexOf(u8, line, "published=false progress_version=0 intent_sha256=-") != null);
    }
}

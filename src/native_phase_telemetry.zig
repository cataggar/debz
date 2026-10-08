//! Bounded, diagnostic-only measurements. Never serialized into recovery,
//! provenance, deadlines or database generations.
const std = @import("std");
const builtin = @import("builtin");

pub const Phase = enum { capture, import, hash, mutation, fsync, progress_serialization };
pub const Measurement = struct {
    count: u64 = 0,
    nanoseconds: u64 = 0,
};

var epoch_state: std.atomic.Value(u8) = .init(0);
var process_epoch: [16]u8 = undefined;
var next_invocation: std.atomic.Value(u64) = .init(0);
threadlocal var active: ?*Context = null;

fn epoch(io: std.Io) [16]u8 {
    if (epoch_state.load(.acquire) != 2) {
        if (epoch_state.cmpxchgStrong(0, 1, .acq_rel, .acquire) == null) {
            std.Io.random(io, &process_epoch);
            epoch_state.store(2, .release);
        } else {
            while (epoch_state.load(.acquire) != 2) std.atomic.spinLoopHint();
        }
    }
    return process_epoch;
}

pub const Context = struct {
    io: std.Io,
    attempt_id: [32]u8,
    process_epoch: [16]u8,
    invocation: u64,
    started: std.Io.Timestamp,
    measurements: [std.enums.values(Phase).len]Measurement = @splat(.{}),
    sequence: u64 = 0,
    previous: ?*Context = null,
    attached: bool = false,
    enabled: bool = true,

    /// Opt-in logging preserves quiet/JSON consumer contracts and avoids
    /// measuring every small hash when no profiling was requested.
    pub fn initConfigured(io: std.Io, attempt_id: [32]u8) Context {
        if (builtin.link_libc) {
            if (std.c.getenv("DEBZ_NATIVE_PHASE_TELEMETRY")) |value| {
                if (std.mem.eql(u8, std.mem.span(value), "1")) return init(io, attempt_id);
            }
        }
        return .{
            .io = io,
            .attempt_id = attempt_id,
            .process_epoch = @splat(0),
            .invocation = 0,
            .started = .{ .nanoseconds = 0 },
            .enabled = false,
        };
    }

    pub fn init(io: std.Io, attempt_id: [32]u8) Context {
        return .{
            .io = io,
            .attempt_id = attempt_id,
            .process_epoch = epoch(io),
            .invocation = next_invocation.fetchAdd(1, .monotonic),
            .started = std.Io.Clock.awake.now(io),
        };
    }

    /// Nested lifecycle helpers retain the outer attempt's measurements.
    pub fn attach(self: *Context) void {
        if (!self.enabled) return;
        if (active) |current| {
            if (std.mem.eql(u8, &current.attempt_id, &self.attempt_id)) return;
        }
        self.previous = active;
        self.attached = true;
        active = self;
    }

    pub fn detach(self: *Context) void {
        if (!self.attached) return;
        self.emit("attempt_end", 0, 0, 0, "finished", "none");
        active = self.previous;
        self.attached = false;
    }

    pub fn measurement(self: *const Context, phase: Phase) Measurement {
        return self.measurements[@intFromEnum(phase)];
    }

    fn emit(self: *Context, kind: []const u8, step: u32, substep: u16, ordinal: u32, stage: []const u8, result: []const u8) void {
        const capture = self.measurement(.capture);
        const imported = self.measurement(.import);
        const hash = self.measurement(.hash);
        const mutation = self.measurement(.mutation);
        const fsync = self.measurement(.fsync);
        const serialization = self.measurement(.progress_serialization);
        std.log.info(
            "native_phase attempt={s} process_epoch={s} invocation={d} sequence={d} kind={s} program_step={d} substep={d} ordinal={d} stage={s} result={s} elapsed_ns={d} capture_count={d} capture_ns={d} import_count={d} import_ns={d} hash_count={d} hash_ns={d} mutation_count={d} mutation_ns={d} fsync_count={d} fsync_ns={d} progress_serialization_count={d} progress_serialization_ns={d}",
            .{
                std.fmt.bytesToHex(self.attempt_id, .lower),
                std.fmt.bytesToHex(self.process_epoch, .lower),
                self.invocation,
                self.sequence,
                kind,
                step,
                substep,
                ordinal,
                stage,
                result,
                elapsed(self.started, std.Io.Clock.awake.now(self.io)),
                capture.count,
                capture.nanoseconds,
                imported.count,
                imported.nanoseconds,
                hash.count,
                hash.nanoseconds,
                mutation.count,
                mutation.nanoseconds,
                fsync.count,
                fsync.nanoseconds,
                serialization.count,
                serialization.nanoseconds,
            },
        );
        self.sequence +|= 1;
    }
};

fn elapsed(started: std.Io.Timestamp, ended: std.Io.Timestamp) u64 {
    return std.math.cast(u64, @max(0, started.durationTo(ended).toNanoseconds())) orelse std.math.maxInt(u64);
}

pub const Span = struct {
    context: ?*Context,
    phase: Phase,
    started: ?std.Io.Timestamp,

    pub fn end(self: Span) void {
        const context = self.context orelse return;
        const measurement = &context.measurements[@intFromEnum(self.phase)];
        measurement.count +|= 1;
        measurement.nanoseconds +|= elapsed(self.started.?, std.Io.Clock.awake.now(context.io));
    }
};

pub fn start(phase: Phase) Span {
    return .{
        .context = active,
        .phase = phase,
        .started = if (active) |context| std.Io.Clock.awake.now(context.io) else null,
    };
}

/// Emitted only after durable progress publication; not an acknowledgment.
pub fn progress(kind: []const u8, step: u32, substep: u16, ordinal: u32, stage: []const u8, result: []const u8) void {
    if (active) |context| context.emit(kind, step, substep, ordinal, stage, result);
}

test "native_phase_telemetry.test.nested attempts and restarts do not share counters" {
    var first = Context.init(std.testing.io, @splat(1));
    first.attach();
    defer first.detach();
    var nested = Context.init(std.testing.io, @splat(1));
    nested.attach();
    start(.capture).end();
    nested.detach();
    try std.testing.expectEqual(@as(u64, 1), first.measurement(.capture).count);
    try std.testing.expectEqual(@as(u64, 0), nested.measurement(.capture).count);
    var other = Context.init(std.testing.io, @splat(2));
    other.attach();
    start(.capture).end();
    other.detach();
    try std.testing.expectEqual(@as(u64, 1), first.measurement(.capture).count);
    try std.testing.expectEqual(@as(u64, 1), other.measurement(.capture).count);
    first.detach();
    var resumed = Context.init(std.testing.io, @splat(1));
    resumed.attach();
    defer resumed.detach();
    start(.import).end();
    try std.testing.expectEqual(@as(u64, 0), resumed.measurement(.capture).count);
    try std.testing.expectEqual(@as(u64, 1), resumed.measurement(.import).count);
    try std.testing.expectEqual(first.process_epoch, resumed.process_epoch);
    try std.testing.expect(first.invocation != resumed.invocation);
}

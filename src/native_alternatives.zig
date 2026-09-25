//! Bounded native model of dpkg's update-alternatives administrative records.
//!
//! The administrative file is active package-manager state, not opaque
//! metadata. This module parses its exact line grammar, preserves the ordered
//! slave topology, canonicalizes candidate ordering, and computes the
//! selection/link settlement for the operations admitted by the pinned dpkg
//! 1.22.22 oracle. Filesystem capture and publication are layered below the
//! lifecycle integration so no ambient host alternatives state is consulted.

const std = @import("std");
const package_database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");
const root_mutation = @import("root_mutation.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const database_directory =
    package_database.database_directory ++ "/alternatives";
pub const selector_directory = "etc/alternatives";
pub const tool_path = "usr/bin/update-alternatives";

pub const Limits = struct {
    max_record_bytes: usize = 256 * 1024,
    max_groups: usize = 32,
    max_slaves: usize = 128,
    max_candidates: usize = 256,
    max_path_bytes: usize = 4096,
    max_name_bytes: usize = 128,
    max_script_commands: usize = 10,
};

pub const Mode = enum {
    auto,
    manual,
};

pub const Slave = struct {
    name: []const u8,
    link: []const u8,
};

pub const Candidate = struct {
    path: []const u8,
    priority: i32,
    /// Dense over `Record.slaves`. An empty target means this provider does
    /// not supply that slave.
    targets: []const []const u8,
};

pub const Record = struct {
    name: []const u8,
    mode: Mode,
    master_link: []const u8,
    slaves: []const Slave,
    candidates: []const Candidate,

    pub fn candidate(self: Record, path: []const u8) ?Candidate {
        for (self.candidates) |item| {
            if (std.mem.eql(u8, item.path, path)) return item;
        }
        return null;
    }

    pub fn slaveIndex(self: Record, name: []const u8) ?usize {
        for (self.slaves, 0..) |slave, index| {
            if (std.mem.eql(u8, slave.name, name)) return index;
        }
        return null;
    }
};

pub const OwnedRecord = struct {
    record: Record,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedRecord) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const ParseError = error{
    RecordTooLarge,
    InvalidGroupName,
    InvalidMode,
    InvalidRecord,
    InvalidPath,
    InvalidSlave,
    InvalidPriority,
    DuplicateSlave,
    DuplicateCandidate,
    CandidateOrder,
    LimitExceeded,
    NonCanonical,
};

fn validText(value: []const u8, maximum: usize, allow_empty: bool) bool {
    if ((!allow_empty and value.len == 0) or value.len > maximum) return false;
    for (value) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n' or
            byte < 0x20 or byte == 0x7f)
            return false;
    }
    return true;
}

pub fn validName(value: []const u8, limits: Limits) bool {
    if (!validText(value, limits.max_name_bytes, false)) return false;
    if (!std.ascii.isLower(value[0]) and !std.ascii.isDigit(value[0]))
        return false;
    for (value[1..]) |byte| {
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and
            byte != '+' and byte != '.' and byte != '-')
            return false;
    }
    return !std.mem.endsWith(u8, value, ".dpkg-tmp");
}

pub fn validAbsolutePath(value: []const u8, limits: Limits) bool {
    if (!validText(value, limits.max_path_bytes, false) or
        !package_database.validAbsolutePath(value))
        return false;
    _ = root_fs.Path.initPackage(value[1..]) catch return false;
    return true;
}

fn parsePriority(value: []const u8) ParseError!i32 {
    if (value.len == 0 or value[0] == '+' or
        (value.len > 1 and value[0] == '0') or
        (value.len > 2 and value[0] == '-' and value[1] == '0'))
        return error.InvalidPriority;
    if (value[0] == '-') {
        if (value.len == 1) return error.InvalidPriority;
        for (value[1..]) |byte| if (!std.ascii.isDigit(byte))
            return error.InvalidPriority;
    } else for (value) |byte| if (!std.ascii.isDigit(byte))
        return error.InvalidPriority;
    return std.fmt.parseInt(i32, value, 10) catch error.InvalidPriority;
}

fn addLength(total: *usize, amount: usize, limits: Limits) ParseError!void {
    total.* = std.math.add(usize, total.*, amount) catch
        return error.LimitExceeded;
    if (total.* > limits.max_record_bytes) return error.RecordTooLarge;
}

fn validateRecordModel(record: Record, limits: Limits) ParseError!void {
    if (!validName(record.name, limits)) return error.InvalidGroupName;
    if (!validAbsolutePath(record.master_link, limits))
        return error.InvalidPath;
    if (record.slaves.len > limits.max_slaves or
        record.candidates.len == 0 or
        record.candidates.len > limits.max_candidates)
        return error.LimitExceeded;
    var total: usize = @tagName(record.mode).len;
    try addLength(&total, 1 + record.master_link.len + 1, limits);
    for (record.slaves, 0..) |slave, index| {
        if (!validName(slave.name, limits) or
            std.mem.eql(u8, slave.name, record.name))
            return error.InvalidSlave;
        if (!validAbsolutePath(slave.link, limits))
            return error.InvalidPath;
        if (std.mem.eql(u8, slave.link, record.master_link))
            return error.DuplicateSlave;
        for (record.slaves[0..index]) |prior| {
            if (std.mem.eql(u8, prior.name, slave.name) or
                std.mem.eql(u8, prior.link, slave.link))
                return error.DuplicateSlave;
        }
        try addLength(
            &total,
            slave.name.len + 1 + slave.link.len + 1,
            limits,
        );
    }
    try addLength(&total, 1, limits);
    var previous: ?[]const u8 = null;
    for (record.candidates) |candidate| {
        if (!validAbsolutePath(candidate.path, limits))
            return error.InvalidPath;
        if (candidate.targets.len != record.slaves.len)
            return error.InvalidRecord;
        if (previous) |prior| switch (std.mem.order(
            u8,
            prior,
            candidate.path,
        )) {
            .lt => {},
            .eq => return error.DuplicateCandidate,
            .gt => return error.CandidateOrder,
        };
        var priority_buffer: [16]u8 = undefined;
        const priority = std.fmt.bufPrint(
            &priority_buffer,
            "{d}",
            .{candidate.priority},
        ) catch unreachable;
        try addLength(
            &total,
            candidate.path.len + 1 + priority.len + 1,
            limits,
        );
        for (candidate.targets) |target| {
            if (target.len != 0 and !validAbsolutePath(target, limits))
                return error.InvalidPath;
            try addLength(&total, target.len + 1, limits);
        }
        previous = candidate.path;
    }
    try addLength(&total, 1, limits);
}

const Lines = struct {
    bytes: []const u8,
    index: usize = 0,

    fn next(self: *Lines) ParseError!?[]const u8 {
        if (self.index == self.bytes.len) return null;
        const end = std.mem.indexOfScalarPos(
            u8,
            self.bytes,
            self.index,
            '\n',
        ) orelse return error.InvalidRecord;
        const value = self.bytes[self.index..end];
        self.index = end + 1;
        return value;
    }
};

fn createArena(
    allocator: std.mem.Allocator,
) std.mem.Allocator.Error!struct {
    arena: *std.heap.ArenaAllocator,
    owned: std.mem.Allocator,
} {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    return .{ .arena = arena, .owned = arena.allocator() };
}

pub fn parse(
    allocator: std.mem.Allocator,
    name: []const u8,
    bytes: []const u8,
    limits: Limits,
) (std.mem.Allocator.Error || ParseError)!OwnedRecord {
    if (bytes.len > limits.max_record_bytes) return error.RecordTooLarge;
    if (!validName(name, limits)) return error.InvalidGroupName;
    var storage = try createArena(allocator);
    errdefer {
        storage.arena.deinit();
        allocator.destroy(storage.arena);
    }
    const owned = storage.owned;
    var lines: Lines = .{ .bytes = bytes };
    const mode_text = (try lines.next()) orelse return error.InvalidRecord;
    const mode: Mode = if (std.mem.eql(u8, mode_text, "auto"))
        .auto
    else if (std.mem.eql(u8, mode_text, "manual"))
        .manual
    else
        return error.InvalidMode;
    const master_link = (try lines.next()) orelse return error.InvalidRecord;
    if (!validAbsolutePath(master_link, limits)) return error.InvalidPath;

    var slaves: std.ArrayList(Slave) = .empty;
    defer slaves.deinit(owned);
    while (true) {
        const slave_name = (try lines.next()) orelse return error.InvalidRecord;
        if (slave_name.len == 0) break;
        if (slaves.items.len >= limits.max_slaves or
            !validName(slave_name, limits))
            return error.InvalidSlave;
        if (std.mem.eql(u8, slave_name, name))
            return error.DuplicateSlave;
        const link = (try lines.next()) orelse return error.InvalidRecord;
        if (!validAbsolutePath(link, limits)) return error.InvalidPath;
        for (slaves.items) |prior| {
            if (std.mem.eql(u8, prior.name, slave_name) or
                std.mem.eql(u8, prior.link, link))
                return error.DuplicateSlave;
        }
        if (std.mem.eql(u8, master_link, link)) return error.DuplicateSlave;
        try slaves.append(owned, .{
            .name = try owned.dupe(u8, slave_name),
            .link = try owned.dupe(u8, link),
        });
    }

    var candidates: std.ArrayList(Candidate) = .empty;
    defer candidates.deinit(owned);
    var previous: ?[]const u8 = null;
    while (true) {
        const path = (try lines.next()) orelse return error.InvalidRecord;
        if (path.len == 0) break;
        if (candidates.items.len >= limits.max_candidates)
            return error.LimitExceeded;
        if (!validAbsolutePath(path, limits)) return error.InvalidPath;
        if (previous) |prior| {
            switch (std.mem.order(u8, prior, path)) {
                .lt => {},
                .eq => return error.DuplicateCandidate,
                .gt => return error.CandidateOrder,
            }
        }
        const priority_text = (try lines.next()) orelse
            return error.InvalidRecord;
        const priority = try parsePriority(priority_text);
        const targets = try owned.alloc([]const u8, slaves.items.len);
        for (targets) |*target| {
            const value = (try lines.next()) orelse return error.InvalidRecord;
            if (value.len != 0 and !validAbsolutePath(value, limits))
                return error.InvalidPath;
            target.* = try owned.dupe(u8, value);
        }
        const path_copy = try owned.dupe(u8, path);
        try candidates.append(owned, .{
            .path = path_copy,
            .priority = priority,
            .targets = targets,
        });
        previous = path_copy;
    }
    if (lines.index != bytes.len or candidates.items.len == 0)
        return error.InvalidRecord;

    const record: Record = .{
        .name = try owned.dupe(u8, name),
        .mode = mode,
        .master_link = try owned.dupe(u8, master_link),
        .slaves = try owned.dupe(Slave, slaves.items),
        .candidates = try owned.dupe(Candidate, candidates.items),
    };
    const canonical = try canonicalBytes(owned, record);
    if (!std.mem.eql(u8, canonical, bytes)) return error.NonCanonical;
    return .{
        .record = record,
        .arena = storage.arena,
        .backing_allocator = allocator,
    };
}

pub fn canonicalBytes(
    allocator: std.mem.Allocator,
    record: Record,
) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;
    writer.writeAll(@tagName(record.mode)) catch return error.OutOfMemory;
    writer.writeByte('\n') catch return error.OutOfMemory;
    writer.writeAll(record.master_link) catch return error.OutOfMemory;
    writer.writeByte('\n') catch return error.OutOfMemory;
    for (record.slaves) |slave| {
        writer.writeAll(slave.name) catch return error.OutOfMemory;
        writer.writeByte('\n') catch return error.OutOfMemory;
        writer.writeAll(slave.link) catch return error.OutOfMemory;
        writer.writeByte('\n') catch return error.OutOfMemory;
    }
    writer.writeByte('\n') catch return error.OutOfMemory;
    for (record.candidates) |candidate| {
        writer.writeAll(candidate.path) catch return error.OutOfMemory;
        writer.writeByte('\n') catch return error.OutOfMemory;
        writer.print("{d}\n", .{candidate.priority}) catch
            return error.OutOfMemory;
        for (candidate.targets) |target| {
            writer.writeAll(target) catch return error.OutOfMemory;
            writer.writeByte('\n') catch return error.OutOfMemory;
        }
    }
    writer.writeByte('\n') catch return error.OutOfMemory;
    return output.toOwnedSlice();
}

pub fn recordDigest(record: Record) [32]u8 {
    var digest = Sha256.init(.{});
    digest.update("debz-native-alternatives-record-v1\x00");
    digest.update(@tagName(record.mode));
    digest.update(&.{0});
    digest.update(record.name);
    digest.update(&.{0});
    digest.update(record.master_link);
    digest.update(&.{0});
    for (record.slaves) |slave| {
        digest.update(slave.name);
        digest.update(&.{0});
        digest.update(slave.link);
        digest.update(&.{0});
    }
    digest.update(&.{0xff});
    var number: [4]u8 = undefined;
    for (record.candidates) |candidate| {
        digest.update(candidate.path);
        digest.update(&.{0});
        std.mem.writeInt(i32, &number, candidate.priority, .big);
        digest.update(&number);
        for (candidate.targets) |target| {
            digest.update(&.{0});
            digest.update(target);
        }
        digest.update(&.{0xfe});
    }
    return digest.finalResult();
}

pub const RegistrationSlave = struct {
    name: []const u8,
    link: []const u8,
    target: []const u8,
};

pub const Registration = struct {
    master_link: []const u8,
    path: []const u8,
    priority: i32,
    master_target_present: bool = true,
    slaves: []const RegistrationSlave = &.{},
};

pub const Command = union(enum) {
    install: Registration,
    set: []const u8,
    auto,
    remove: []const u8,
    remove_all,
};

pub const MutationRequest = struct {
    name: []const u8,
    current: ?Record,
    /// Exact target currently stored by the master selector.
    selected: ?[]const u8,
    /// Candidate master targets known absent or broken at mutation time.
    missing_master_targets: []const []const u8 = &.{},
    command: Command,
    limits: Limits = .{},
};

pub const Mutation = struct {
    record: ?Record,
    selected: ?[]const u8,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Mutation) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

fn missing(request: MutationRequest, path: []const u8) bool {
    for (request.missing_master_targets) |item| {
        if (std.mem.eql(u8, item, path)) return true;
    }
    return false;
}

fn bestCandidate(
    candidates: []const Candidate,
    request: MutationRequest,
) ?[]const u8 {
    var best: ?Candidate = null;
    for (candidates) |candidate| {
        if (missing(request, candidate.path)) continue;
        if (best == null or candidate.priority > best.?.priority or
            (candidate.priority == best.?.priority and
                std.mem.order(u8, candidate.path, best.?.path) == .lt))
            best = candidate;
    }
    return if (best) |value| value.path else null;
}

fn cloneSlaves(
    allocator: std.mem.Allocator,
    source: []const Slave,
) std.mem.Allocator.Error![]Slave {
    const result = try allocator.alloc(Slave, source.len);
    for (source, result) |slave, *copy| copy.* = .{
        .name = try allocator.dupe(u8, slave.name),
        .link = try allocator.dupe(u8, slave.link),
    };
    return result;
}

fn cloneCandidate(
    allocator: std.mem.Allocator,
    candidate: Candidate,
) std.mem.Allocator.Error!Candidate {
    const targets = try allocator.alloc([]const u8, candidate.targets.len);
    for (candidate.targets, targets) |target, *copy|
        copy.* = try allocator.dupe(u8, target);
    return .{
        .path = try allocator.dupe(u8, candidate.path),
        .priority = candidate.priority,
        .targets = targets,
    };
}

fn candidateLess(_: void, left: Candidate, right: Candidate) bool {
    return std.mem.order(u8, left.path, right.path) == .lt;
}

fn slaveNameLess(_: void, left: Slave, right: Slave) bool {
    return std.mem.order(u8, left.name, right.name) == .lt;
}

fn validateRegistration(
    registration: Registration,
    limits: Limits,
) ParseError!void {
    if (!validAbsolutePath(registration.master_link, limits) or
        !validAbsolutePath(registration.path, limits))
        return error.InvalidPath;
    if (!registration.master_target_present) return error.InvalidPath;
    if (registration.slaves.len > limits.max_slaves)
        return error.LimitExceeded;
    for (registration.slaves, 0..) |slave, index| {
        if (!validName(slave.name, limits)) return error.InvalidSlave;
        if (!validAbsolutePath(slave.link, limits) or
            (slave.target.len != 0 and
                !validAbsolutePath(slave.target, limits)))
            return error.InvalidPath;
        if (std.mem.eql(u8, registration.master_link, slave.link))
            return error.DuplicateSlave;
        for (registration.slaves[0..index]) |prior| {
            if (std.mem.eql(u8, prior.name, slave.name) or
                std.mem.eql(u8, prior.link, slave.link))
                return error.DuplicateSlave;
        }
    }
}

fn installRecord(
    owned: std.mem.Allocator,
    request: MutationRequest,
    registration: Registration,
) (std.mem.Allocator.Error || ParseError)!struct {
    record: Record,
    previous_selected_valid: bool,
} {
    try validateRegistration(registration, request.limits);
    const current = request.current;
    if (current) |record| {
        if (!std.mem.eql(u8, record.name, request.name) or
            !std.mem.eql(u8, record.master_link, registration.master_link))
            return error.InvalidRecord;
    }

    var slave_list: std.ArrayList(Slave) = .empty;
    defer slave_list.deinit(owned);
    if (current) |record|
        try slave_list.appendSlice(owned, try cloneSlaves(owned, record.slaves));
    for (registration.slaves) |incoming| {
        var matched = false;
        for (slave_list.items) |slave| {
            if (std.mem.eql(u8, slave.name, incoming.name)) {
                if (!std.mem.eql(u8, slave.link, incoming.link))
                    return error.InvalidSlave;
                matched = true;
                break;
            }
            if (std.mem.eql(u8, slave.link, incoming.link))
                return error.DuplicateSlave;
        }
        if (!matched) try slave_list.append(owned, .{
            .name = try owned.dupe(u8, incoming.name),
            .link = try owned.dupe(u8, incoming.link),
        });
    }
    std.mem.sort(Slave, slave_list.items, {}, slaveNameLess);

    var candidates: std.ArrayList(Candidate) = .empty;
    defer candidates.deinit(owned);
    if (current) |record| {
        for (record.candidates) |candidate| {
            if (std.mem.eql(u8, candidate.path, registration.path)) continue;
            const targets = try owned.alloc([]const u8, slave_list.items.len);
            for (targets, slave_list.items) |*target, new_slave| {
                target.* = "";
                for (record.slaves, 0..) |old_slave, old_index| {
                    if (std.mem.eql(u8, old_slave.name, new_slave.name)) {
                        target.* = try owned.dupe(
                            u8,
                            candidate.targets[old_index],
                        );
                        break;
                    }
                }
            }
            try candidates.append(owned, .{
                .path = try owned.dupe(u8, candidate.path),
                .priority = candidate.priority,
                .targets = targets,
            });
        }
    }
    const incoming_targets = try owned.alloc([]const u8, slave_list.items.len);
    @memset(incoming_targets, "");
    for (registration.slaves) |incoming| {
        for (slave_list.items, 0..) |slave, index| {
            if (std.mem.eql(u8, slave.name, incoming.name)) {
                incoming_targets[index] = try owned.dupe(u8, incoming.target);
                break;
            }
        }
    }
    try candidates.append(owned, .{
        .path = try owned.dupe(u8, registration.path),
        .priority = registration.priority,
        .targets = incoming_targets,
    });
    std.mem.sort(Candidate, candidates.items, {}, candidateLess);

    // A slave definition disappears only when no remaining provider supplies
    // it. Re-registering one provider without a prior slave therefore removes
    // that provider's link while preserving another provider's declaration.
    var retained: std.ArrayList(usize) = .empty;
    defer retained.deinit(owned);
    for (slave_list.items, 0..) |_, index| {
        var supplied = false;
        for (candidates.items) |candidate| {
            if (candidate.targets[index].len != 0) {
                supplied = true;
                break;
            }
        }
        if (supplied) try retained.append(owned, index);
    }
    const slaves = try owned.alloc(Slave, retained.items.len);
    for (retained.items, slaves) |old_index, *slave|
        slave.* = slave_list.items[old_index];
    for (candidates.items) |*candidate| {
        const targets = try owned.alloc([]const u8, retained.items.len);
        for (retained.items, targets) |old_index, *target|
            target.* = candidate.targets[old_index];
        candidate.targets = targets;
    }
    var selected_valid = false;
    if (request.selected) |selected| {
        for (candidates.items) |candidate| {
            if (std.mem.eql(u8, candidate.path, selected) and
                !missing(request, candidate.path))
                selected_valid = true;
        }
    }
    return .{
        .record = .{
            .name = try owned.dupe(u8, request.name),
            .mode = if (current) |record| record.mode else .auto,
            .master_link = try owned.dupe(u8, registration.master_link),
            .slaves = slaves,
            .candidates = try owned.dupe(Candidate, candidates.items),
        },
        .previous_selected_valid = selected_valid,
    };
}

pub fn mutate(
    allocator: std.mem.Allocator,
    request: MutationRequest,
) (std.mem.Allocator.Error || ParseError)!Mutation {
    if (!validName(request.name, request.limits))
        return error.InvalidGroupName;
    if (request.current) |current| {
        try validateRecordModel(current, request.limits);
        if (!std.mem.eql(u8, current.name, request.name))
            return error.InvalidRecord;
    }
    var storage = try createArena(allocator);
    errdefer {
        storage.arena.deinit();
        allocator.destroy(storage.arena);
    }
    const owned = storage.owned;
    var result_record: ?Record = null;
    var selected: ?[]const u8 = null;

    switch (request.command) {
        .remove_all => {},
        .set => |path| {
            const current = request.current orelse return error.InvalidRecord;
            if (current.candidate(path) == null or missing(request, path))
                return error.InvalidPath;
            const candidates = try owned.alloc(Candidate, current.candidates.len);
            for (current.candidates, candidates) |candidate, *copy|
                copy.* = try cloneCandidate(owned, candidate);
            result_record = .{
                .name = try owned.dupe(u8, current.name),
                .mode = .manual,
                .master_link = try owned.dupe(u8, current.master_link),
                .slaves = try cloneSlaves(owned, current.slaves),
                .candidates = candidates,
            };
            selected = try owned.dupe(u8, path);
        },
        .auto => {
            const current = request.current orelse return error.InvalidRecord;
            var candidates: std.ArrayList(Candidate) = .empty;
            defer candidates.deinit(owned);
            for (current.candidates) |candidate| {
                if (missing(request, candidate.path)) continue;
                try candidates.append(owned, try cloneCandidate(
                    owned,
                    candidate,
                ));
            }
            if (candidates.items.len != 0) {
                result_record = .{
                    .name = try owned.dupe(u8, current.name),
                    .mode = .auto,
                    .master_link = try owned.dupe(u8, current.master_link),
                    .slaves = try cloneSlaves(owned, current.slaves),
                    .candidates = try owned.dupe(Candidate, candidates.items),
                };
                selected = bestCandidate(
                    result_record.?.candidates,
                    request,
                );
            }
        },
        .remove => |path| {
            const current = request.current orelse return error.InvalidRecord;
            var candidates: std.ArrayList(Candidate) = .empty;
            defer candidates.deinit(owned);
            var found = false;
            for (current.candidates) |candidate| {
                if (std.mem.eql(u8, candidate.path, path)) {
                    found = true;
                    continue;
                }
                try candidates.append(owned, try cloneCandidate(
                    owned,
                    candidate,
                ));
            }
            if (!found) return error.InvalidPath;
            if (candidates.items.len != 0) {
                var mode = current.mode;
                const removed_selected = if (request.selected) |value|
                    std.mem.eql(u8, value, path)
                else
                    false;
                if (removed_selected) mode = .auto;
                result_record = .{
                    .name = try owned.dupe(u8, current.name),
                    .mode = mode,
                    .master_link = try owned.dupe(u8, current.master_link),
                    .slaves = try cloneSlaves(owned, current.slaves),
                    .candidates = try owned.dupe(Candidate, candidates.items),
                };
                if (!removed_selected and request.selected != null and
                    result_record.?.candidate(request.selected.?) != null and
                    !missing(request, request.selected.?))
                {
                    selected = try owned.dupe(u8, request.selected.?);
                } else {
                    selected = bestCandidate(
                        result_record.?.candidates,
                        request,
                    );
                }
            }
        },
        .install => |registration| {
            const installed = try installRecord(owned, request, registration);
            result_record = installed.record;
            const record = result_record.?;
            if (record.mode == .manual and installed.previous_selected_valid) {
                selected = try owned.dupe(u8, request.selected.?);
            } else if (record.mode == .auto and
                installed.previous_selected_valid)
            {
                const previous = record.candidate(request.selected.?).?;
                const incoming = record.candidate(registration.path).?;
                selected = if (incoming.priority > previous.priority)
                    try owned.dupe(u8, incoming.path)
                else
                    try owned.dupe(u8, previous.path);
            } else {
                selected = bestCandidate(record.candidates, request);
            }
        },
    }

    if (result_record) |record| {
        if (selected == null) return error.InvalidRecord;
        const bytes = try canonicalBytes(owned, record);
        var checked = try parse(owned, record.name, bytes, request.limits);
        checked.deinit();
    }
    return .{
        .record = result_record,
        .selected = selected,
        .arena = storage.arena,
        .backing_allocator = allocator,
    };
}

pub const Link = struct {
    generic_path: []const u8,
    selector_name: []const u8,
    selector_target: []const u8,
};

pub fn selectedLinks(
    allocator: std.mem.Allocator,
    record: Record,
    selected: []const u8,
) (std.mem.Allocator.Error || ParseError)![]Link {
    try validateRecordModel(record, .{});
    const candidate = record.candidate(selected) orelse
        return error.InvalidPath;
    var count: usize = 1;
    for (candidate.targets) |target| count += @intFromBool(target.len != 0);
    const links = try allocator.alloc(Link, count);
    links[0] = .{
        .generic_path = record.master_link,
        .selector_name = record.name,
        .selector_target = candidate.path,
    };
    var index: usize = 1;
    for (record.slaves, candidate.targets) |slave, target| {
        if (target.len == 0) continue;
        links[index] = .{
            .generic_path = slave.link,
            .selector_name = slave.name,
            .selector_target = target,
        };
        index += 1;
    }
    return links;
}

pub const SettlementState = struct {
    record: Record,
    selected: []const u8,
};

pub const Settlement = struct {
    intents: []const root_mutation.Intent,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Settlement) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

fn selectorManagedPath(
    allocator: std.mem.Allocator,
    name: []const u8,
) ![]const u8 {
    if (!validName(name, .{})) return error.InvalidGroupName;
    return std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ selector_directory, name },
    );
}

fn genericPathInLinks(links: []const Link, generic_path: []const u8) bool {
    for (links) |link| {
        if (std.mem.eql(u8, link.generic_path, generic_path)) return true;
    }
    return false;
}

fn selectorNameInLinks(links: []const Link, selector_name: []const u8) bool {
    for (links) |link| {
        if (std.mem.eql(u8, link.selector_name, selector_name)) return true;
    }
    return false;
}

/// Builds one journalable database-and-link settlement. The returned intents
/// are consumed by `root_mutation.preflight`, which binds every precondition,
/// publishes one versioned write-ahead journal, fsyncs parents, and recovers
/// the complete set rather than repairing an individual alternatives path.
pub fn settlement(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    before: ?SettlementState,
    after: ?SettlementState,
    limits: Limits,
) !Settlement {
    if (before != null and after != null and
        !std.mem.eql(u8, before.?.record.name, after.?.record.name))
        return error.InvalidRecord;
    const state = after orelse before orelse return error.InvalidRecord;
    if (before) |value| try validateRecordModel(value.record, limits);
    if (after) |value| try validateRecordModel(value.record, limits);
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var intents: std.ArrayList(root_mutation.Intent) = .empty;
    defer intents.deinit(owned);

    const before_links = if (before) |value|
        try selectedLinks(owned, value.record, value.selected)
    else
        &.{};
    const after_links = if (after) |value|
        try selectedLinks(owned, value.record, value.selected)
    else
        &.{};

    if (after) |value| {
        const bytes = try canonicalBytes(owned, value.record);
        const record_path = try std.fmt.allocPrint(
            owned,
            "{s}/{s}",
            .{ database_directory, value.record.name },
        );
        try intents.append(owned, .{ .file = .{
            .path = record_path,
            .bytes = bytes,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
        } });
        for (after_links) |link| {
            const selector_path = try selectorManagedPath(
                owned,
                link.selector_name,
            );
            try intents.append(owned, .{ .symlink = .{
                .path = selector_path,
                .target = link.selector_target,
            } });
        }
        for (after_links) |link| {
            const generic_path = try physicalManagedPath(
                owned,
                root,
                link.generic_path[1..],
                limits,
            );
            const target = try std.fmt.allocPrint(
                owned,
                "/{s}/{s}",
                .{ selector_directory, link.selector_name },
            );
            try intents.append(owned, .{ .symlink = .{
                .path = generic_path,
                .target = target,
            } });
        }
    }
    for (before_links) |link| {
        if (!genericPathInLinks(after_links, link.generic_path)) {
            const generic_path = try physicalManagedPath(
                owned,
                root,
                link.generic_path[1..],
                limits,
            );
            try intents.append(owned, .{ .remove = .{
                .path = generic_path,
                .removal = .allow_absent,
            } });
        }
        if (!selectorNameInLinks(after_links, link.selector_name)) {
            const selector_path = try selectorManagedPath(
                owned,
                link.selector_name,
            );
            try intents.append(owned, .{ .remove = .{
                .path = selector_path,
                .removal = .allow_absent,
            } });
        }
    }
    if (after == null) {
        const record_path = try std.fmt.allocPrint(
            owned,
            "{s}/{s}",
            .{ database_directory, state.record.name },
        );
        try intents.append(owned, .{ .remove = .{
            .path = record_path,
            .removal = .allow_absent,
        } });
    }
    return .{
        .intents = try owned.dupe(root_mutation.Intent, intents.items),
        .arena = arena,
        .backing_allocator = allocator,
    };
}

pub fn fuzzOne(allocator: std.mem.Allocator, bytes: []const u8) void {
    if (discoverScriptAuthority(allocator, bytes, .{})) |authority_value| {
        var authority = authority_value;
        authority.deinit();
    } else |_| {}
    var parsed = parse(allocator, "fuzz", bytes, .{
        .max_record_bytes = 32 * 1024,
        .max_groups = 4,
        .max_slaves = 32,
        .max_candidates = 64,
        .max_path_bytes = 1024,
        .max_name_bytes = 128,
    }) catch return;
    defer parsed.deinit();
    const selected = parsed.record.candidates[0].path;
    const links = selectedLinks(
        allocator,
        parsed.record,
        selected,
    ) catch return;
    allocator.free(links);
    inline for (.{ Command.auto, Command{ .set = selected }, Command{
        .remove = selected,
    }, Command.remove_all }) |command| {
        if (mutate(allocator, .{
            .name = parsed.record.name,
            .current = parsed.record,
            .selected = selected,
            .command = command,
            .limits = .{
                .max_record_bytes = 32 * 1024,
                .max_groups = 4,
                .max_slaves = 32,
                .max_candidates = 64,
                .max_path_bytes = 1024,
                .max_name_bytes = 128,
            },
        })) |mutation_value| {
            var mutation = mutation_value;
            mutation.deinit();
        } else |_| {}
    }
    const canonical = canonicalBytes(allocator, parsed.record) catch return;
    defer allocator.free(canonical);
    var reparsed = parse(allocator, "fuzz", canonical, .{
        .max_record_bytes = 32 * 1024,
        .max_groups = 4,
        .max_slaves = 32,
        .max_candidates = 64,
        .max_path_bytes = 1024,
        .max_name_bytes = 128,
    }) catch return;
    reparsed.deinit();
}

pub const pinned_vendor_groups = [_][]const u8{
    "awk",
    "builtins.7.gz",
    "editor",
    "ex",
    "nc",
    "newt-palette",
    "pager",
    "rmt",
    "rview",
    "sudo",
    "vi",
    "view",
    "vtrgb",
    "which",
};

pub const pinned_vendor_group_count: usize = 14;
pub const pinned_vendor_relationship_count: usize = 72;
pub const pinned_vendor_requested_path_count: usize = 189;
pub const pinned_vendor_linked_entry_count: usize = 190;
pub const pinned_vendor_reference_sha256 =
    "73228f959a335956c58d48712c891ccc372082dfc4f78f4405c18a37f98efe08";
pub const pinned_oracle_sha256 =
    "2492f30fada7574fb6e9b07cbbf91cc0940d430322b35e94e744df7737e4a8db";

pub const ToolBinding = struct {
    architecture: []const u8,
    sha256: [32]u8,
};

fn digestLiteral(comptime text: []const u8) [32]u8 {
    var value: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&value, text) catch unreachable;
    return value;
}

pub const pinned_tools = [_]ToolBinding{
    .{
        .architecture = "amd64",
        .sha256 = digestLiteral(
            "b02b581c6a7f85679f32efe18c9aaeb05316847fa90d3d3fda30b57defab9b13",
        ),
    },
    .{
        .architecture = "arm64",
        .sha256 = digestLiteral(
            "35616ec58ba58f3fb8b4820bdf893c47a842d56684b3335ba6ebf6df86b27cc5",
        ),
    },
};

pub const snapshot_tools = [_]ToolBinding{.{
    .architecture = "amd64",
    .sha256 = digestLiteral(
        "3e5fbdcf3b36bcfb7af1b406152c3a088acccc27c7b3e42d59ca0527a6259d9d",
    ),
}};

const snapshot_less_preinst_sha256 = digestLiteral(
    "c72b2f152d56cae58b8f39efe22e6f0d85d676c4ac3060f40cfe0c463f1f8d94",
);
const snapshot_less_postinst_sha256 = digestLiteral(
    "a33a1e6ef5a22e63a66e42853fc0bcff3107b4653d7b5cea891354a5f28db6c4",
);
const snapshot_bash_postinst_sha256 = digestLiteral(
    "e9afaa3227a21e68002bd60a88e054d8f98d2d0e548d1d690c9bba5c3c9577ff",
);
const snapshot_procps_postinst_sha256 = digestLiteral(
    "7c2ba424ad233bd238474b9d6e565a719fbd6902fd75f617bc3e6e915084c9d3",
);

pub fn matchesSnapshotLessPreinst(bytes: []const u8) bool {
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    return std.crypto.timing_safe.eql(
        [32]u8,
        snapshot_less_preinst_sha256,
        sha256,
    );
}

pub fn matchesSnapshotLessPostinst(bytes: []const u8) bool {
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    return std.crypto.timing_safe.eql(
        [32]u8,
        snapshot_less_postinst_sha256,
        sha256,
    );
}

pub fn matchesSnapshotBashPostinst(bytes: []const u8) bool {
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    return std.crypto.timing_safe.eql(
        [32]u8,
        snapshot_bash_postinst_sha256,
        sha256,
    );
}

pub fn matchesSnapshotProcpsPostinst(bytes: []const u8) bool {
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    return std.crypto.timing_safe.eql(
        [32]u8,
        snapshot_procps_postinst_sha256,
        sha256,
    );
}

pub fn matchesSnapshotTool(
    architecture: []const u8,
    sha256: [32]u8,
) bool {
    return std.mem.eql(u8, architecture, "amd64") and
        std.crypto.timing_safe.eql(
            [32]u8,
            snapshot_tools[0].sha256,
            sha256,
        );
}

pub fn pinnedTool(architecture: []const u8) ?ToolBinding {
    for (pinned_tools) |binding| {
        if (std.mem.eql(u8, binding.architecture, architecture))
            return binding;
    }
    return null;
}

fn matchesPinnedTool(architecture: []const u8, sha256: [32]u8) bool {
    for (pinned_tools ++ snapshot_tools) |binding| {
        if (std.mem.eql(u8, binding.architecture, architecture) and
            std.crypto.timing_safe.eql([32]u8, binding.sha256, sha256))
            return true;
    }
    return false;
}

pub fn verifyPinnedTool(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
) ![32]u8 {
    _ = pinnedTool(architecture) orelse
        return error.UnsupportedAlternativesArchitecture;
    var pinned = try root.pinRegularFile(try root_fs.Path.init(tool_path));
    defer pinned.close();
    const observation = try pinned.observeStableAlloc(
        allocator,
        8 * 1024 * 1024,
    );
    defer allocator.free(observation.bytes);
    if (observation.entry.uid != 0 or observation.entry.gid != 0 or
        observation.entry.mode != 0o755 or
        observation.entry.link_count != 1)
        return error.InvalidAlternativesTool;
    var sha256: [32]u8 = undefined;
    Sha256.hash(observation.bytes, &sha256, .{});
    if (!matchesPinnedTool(architecture, sha256))
        return error.InvalidAlternativesTool;
    return sha256;
}

pub fn scriptMayInvoke(bytes: []const u8) bool {
    return std.mem.indexOf(u8, bytes, "update-alternatives") != null;
}

pub const ScriptAuthority = struct {
    groups: []const GroupAuthority,
    commands: []const ScriptCommand,
    paths: []const []const u8,
    immutable_targets: []const []const u8,
    require_targets_absent: bool = false,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *ScriptAuthority) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn group(self: ScriptAuthority, name: []const u8) ?GroupAuthority {
        for (self.groups) |item| {
            if (std.mem.eql(u8, item.name, name)) return item;
        }
        return null;
    }
};

pub const ScriptCommand = struct {
    name: []const u8,
    command: Command,
};

pub const Topology = struct {
    master_link: []const u8,
    slaves: []const Slave,
};

pub const GroupAuthority = struct {
    name: []const u8,
    topology: ?Topology = null,
    allow_slave_subset: bool = false,
    allow_absent: bool = false,
    mutable: bool = true,
};

pub const Authority = struct {
    groups: []const GroupAuthority,
    exact_group_set: bool = true,
    require_vendor_counts: bool = false,
    allow_retained_readme: bool = true,
    limits: Limits = .{},

    pub fn group(self: Authority, name: []const u8) ?GroupAuthority {
        for (self.groups) |item| {
            if (std.mem.eql(u8, item.name, name)) return item;
        }
        return null;
    }
};

fn appendScriptPath(
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]const u8),
    absolute: []const u8,
    limits: Limits,
) !void {
    const relative = try rootRelativeAbsolute(allocator, absolute, limits);
    try appendUniquePath(allocator, paths, relative);
}

fn shellTokenSafe(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| switch (byte) {
        '$', '`', '\'', '"', '\\', '<', '>', '|', '&', ';', '(', ')', '{', '}', '[', ']', '*', '?', '!', '\n', '\r', 0 => return false,
        else => if (byte < 0x20 or byte == 0x7f) return false,
    };
    return true;
}

fn commandEnd(token: []const u8) bool {
    return std.mem.eql(u8, token, ";") or
        std.mem.eql(u8, token, ";;");
}

fn validCommandPrefix(tokens: []const []const u8, command: usize) bool {
    if (command == 0) return true;
    if (command != 1) return false;
    const label = tokens[0];
    if (label.len < 2 or label[label.len - 1] != ')') return false;
    for (label[0 .. label.len - 1]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '_' and byte != '-' and byte != '*' and
            byte != '?' and byte != '|')
            return false;
    }
    return true;
}

fn validCommandTail(tokens: []const []const u8, first: usize) bool {
    return first == tokens.len or
        (first + 1 == tokens.len and commandEnd(tokens[first]));
}

fn snapshotLessPostinstCommand(
    bytes: []const u8,
    tokens: []const []const u8,
    command: usize,
) bool {
    if (!matchesSnapshotLessPostinst(bytes)) return false;
    const expected = [_][]const u8{
        "update-alternatives",
        "--quiet",
        "--install",
        "/usr/bin/pager",
        "pager",
        "/usr/bin/less",
        "77",
        "--slave",
        "/usr/share/man/man1/pager.1.gz",
        "pager.1.gz",
        "/usr/share/man/man1/less.1.gz",
    };
    if (command != 0 or tokens.len != expected.len) return false;
    for (tokens, &expected) |actual, literal| {
        if (!std.mem.eql(u8, actual, literal)) return false;
    }
    return true;
}

fn snapshotBashPostinstCommand(
    bytes: []const u8,
    tokens: []const []const u8,
    command: usize,
) bool {
    if (!matchesSnapshotBashPostinst(bytes)) return false;
    const expected = [_][]const u8{
        "update-alternatives",
        "--install",
        "/usr/share/man/man7/builtins.7.gz",
        "builtins.7.gz",
        "/usr/share/man/man7/bash-builtins.7.gz",
        "10",
        "||",
        "true",
    };
    if (command != 0 or tokens.len != expected.len) return false;
    for (tokens, &expected) |actual, literal| {
        if (!std.mem.eql(u8, actual, literal)) return false;
    }
    return true;
}

fn scriptGroup(
    allocator: std.mem.Allocator,
    groups: *std.ArrayList(GroupAuthority),
    name: []const u8,
    topology: ?Topology,
    limits: Limits,
) !void {
    if (!validName(name, limits)) return error.InvalidAlternativesScript;
    for (groups.items) |*existing| {
        if (!std.mem.eql(u8, existing.name, name)) continue;
        if (topology) |incoming| {
            if (existing.topology) |current| {
                if (!topologyMatches(current, .{
                    .name = name,
                    .mode = .auto,
                    .master_link = incoming.master_link,
                    .slaves = incoming.slaves,
                    .candidates = &.{},
                })) return error.InvalidAlternativesScript;
            } else existing.topology = incoming;
        }
        return;
    }
    try groups.append(allocator, .{
        .name = try allocator.dupe(u8, name),
        .topology = topology,
        .allow_absent = true,
        .mutable = true,
    });
}

/// Extracts only literal, direct update-alternatives commands. Dynamic shell
/// construction, substitutions, redirections in arguments, unknown options,
/// and inconsistent topology are rejected rather than granted authority.
pub fn discoverScriptAuthority(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !ScriptAuthority {
    if (bytes.len > (package_database.Limits{}).max_maintainer_script_bytes)
        return error.AlternativesScriptTooLarge;
    var storage = try createArena(allocator);
    errdefer {
        storage.arena.deinit();
        allocator.destroy(storage.arena);
    }
    const owned = storage.owned;
    if (matchesSnapshotProcpsPostinst(bytes)) {
        // The signed script's variable commands are unreachable when all four guards fail.
        const targets = &[_][]const u8{
            "/usr/bin/uptime.procps",
            "/usr/bin/vmstat.procps",
            "/usr/bin/w.procps",
            "/bin/ps.procps",
        };
        for (targets) |target| {
            if (!validAbsolutePath(target, limits))
                return error.InvalidAlternativesScript;
        }
        return .{
            .groups = &.{},
            .commands = &.{},
            .paths = &.{},
            .immutable_targets = try owned.dupe([]const u8, targets),
            .require_targets_absent = true,
            .arena = storage.arena,
            .backing_allocator = allocator,
        };
    }
    var normalized: std.ArrayList(u8) = .empty;
    defer normalized.deinit(owned);
    var index: usize = 0;
    while (index < bytes.len) {
        if (bytes[index] == '\\' and index + 1 < bytes.len and
            bytes[index + 1] == '\n')
        {
            try normalized.append(owned, ' ');
            index += 2;
            continue;
        }
        try normalized.append(owned, bytes[index]);
        index += 1;
    }
    var groups: std.ArrayList(GroupAuthority) = .empty;
    defer groups.deinit(owned);
    var commands: std.ArrayList(ScriptCommand) = .empty;
    defer commands.deinit(owned);
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(owned);
    var immutable_targets: std.ArrayList([]const u8) = .empty;
    defer immutable_targets.deinit(owned);
    var found = false;
    var lines = std.mem.splitScalar(u8, normalized.items, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t");
        if (std.mem.indexOf(u8, line, "update-alternatives") == null)
            continue;
        var tokens: std.ArrayList([]const u8) = .empty;
        defer tokens.deinit(owned);
        var words = std.mem.tokenizeAny(u8, line, " \t");
        while (words.next()) |word| try tokens.append(owned, word);
        var command_index: ?usize = null;
        for (tokens.items, 0..) |token, token_index| {
            if (std.mem.eql(u8, token, "update-alternatives") or
                std.mem.eql(u8, token, "/usr/bin/update-alternatives"))
            {
                command_index = token_index;
                break;
            }
        }
        var command = command_index orelse
            return error.InvalidAlternativesScript;
        if (!validCommandPrefix(tokens.items, command))
            return error.InvalidAlternativesScript;
        if (command + 1 >= tokens.items.len)
            return error.InvalidAlternativesScript;
        if (std.mem.eql(u8, tokens.items[command + 1], "--quiet")) {
            const preinst_remove = std.mem.eql(
                u8,
                line,
                "update-alternatives --quiet --remove pager /bin/less",
            ) and matchesSnapshotLessPreinst(bytes);
            if (!preinst_remove and !snapshotLessPostinstCommand(
                bytes,
                tokens.items,
                command,
            ))
                return error.InvalidAlternativesScript;
            command += 1;
        }
        const operation = tokens.items[command + 1];
        if (!shellTokenSafe(operation))
            return error.InvalidAlternativesScript;
        if (std.mem.eql(u8, operation, "--install") and
            snapshotBashPostinstCommand(bytes, tokens.items, command))
        {
            // Parse only the tool operands; the complete pinned script still runs.
            tokens.items = tokens.items[0 .. tokens.items.len - 2];
        }
        if (std.mem.eql(u8, operation, "--install")) {
            if (command + 6 > tokens.items.len)
                return error.InvalidAlternativesScript;
            const master = tokens.items[command + 2];
            const name = tokens.items[command + 3];
            const candidate = tokens.items[command + 4];
            const priority = tokens.items[command + 5];
            if (!shellTokenSafe(master) or !shellTokenSafe(name) or
                !shellTokenSafe(candidate))
                return error.InvalidAlternativesScript;
            _ = parsePriority(priority) catch
                return error.InvalidAlternativesScript;
            if (!validAbsolutePath(master, limits) or
                !validAbsolutePath(candidate, limits) or
                !validName(name, limits))
                return error.InvalidAlternativesScript;
            var slaves: std.ArrayList(Slave) = .empty;
            defer slaves.deinit(owned);
            var install_slaves: std.ArrayList(RegistrationSlave) = .empty;
            defer install_slaves.deinit(owned);
            var argument = command + 6;
            while (argument < tokens.items.len) {
                if (commandEnd(tokens.items[argument])) break;
                if (!std.mem.eql(u8, tokens.items[argument], "--slave") or
                    argument + 3 >= tokens.items.len)
                    return error.InvalidAlternativesScript;
                const link = tokens.items[argument + 1];
                const slave_name = tokens.items[argument + 2];
                const target = tokens.items[argument + 3];
                if (!shellTokenSafe(link) or
                    !shellTokenSafe(slave_name) or
                    !shellTokenSafe(target) or
                    !validAbsolutePath(link, limits) or
                    !validName(slave_name, limits) or
                    !validAbsolutePath(target, limits) or
                    std.mem.eql(u8, slave_name, name) or
                    std.mem.eql(u8, link, master))
                    return error.InvalidAlternativesScript;
                for (slaves.items) |prior| {
                    if (std.mem.eql(u8, prior.name, slave_name) or
                        std.mem.eql(u8, prior.link, link))
                        return error.InvalidAlternativesScript;
                }
                try slaves.append(owned, .{
                    .name = try owned.dupe(u8, slave_name),
                    .link = try owned.dupe(u8, link),
                });
                try install_slaves.append(owned, .{
                    .name = try owned.dupe(u8, slave_name),
                    .link = try owned.dupe(u8, link),
                    .target = try owned.dupe(u8, target),
                });
                try appendScriptPath(owned, &paths, link, limits);
                try appendScriptPath(owned, &paths, target, limits);
                try immutable_targets.append(
                    owned,
                    try owned.dupe(u8, target),
                );
                argument += 4;
            }
            if (!validCommandTail(tokens.items, argument))
                return error.InvalidAlternativesScript;
            try appendScriptPath(owned, &paths, master, limits);
            try appendScriptPath(owned, &paths, candidate, limits);
            try immutable_targets.append(
                owned,
                try owned.dupe(u8, candidate),
            );
            try paths.append(
                owned,
                try std.fmt.allocPrint(
                    owned,
                    "{s}/{s}",
                    .{ database_directory, name },
                ),
            );
            try paths.append(
                owned,
                try std.fmt.allocPrint(
                    owned,
                    "{s}/{s}",
                    .{ selector_directory, name },
                ),
            );
            for (slaves.items) |slave| try paths.append(
                owned,
                try std.fmt.allocPrint(
                    owned,
                    "{s}/{s}",
                    .{ selector_directory, slave.name },
                ),
            );
            try scriptGroup(
                owned,
                &groups,
                name,
                .{
                    .master_link = try owned.dupe(u8, master),
                    .slaves = try owned.dupe(Slave, slaves.items),
                },
                limits,
            );
            try commands.append(owned, .{
                .name = try owned.dupe(u8, name),
                .command = .{ .install = .{
                    .master_link = try owned.dupe(u8, master),
                    .path = try owned.dupe(u8, candidate),
                    .priority = parsePriority(priority) catch unreachable,
                    .slaves = try owned.dupe(
                        RegistrationSlave,
                        install_slaves.items,
                    ),
                } },
            });
            found = true;
        } else if (std.mem.eql(u8, operation, "--remove") or
            std.mem.eql(u8, operation, "--set"))
        {
            if (command + 4 > tokens.items.len or
                !shellTokenSafe(tokens.items[command + 2]) or
                !shellTokenSafe(tokens.items[command + 3]) or
                !validName(tokens.items[command + 2], limits) or
                !validAbsolutePath(tokens.items[command + 3], limits))
                return error.InvalidAlternativesScript;
            if (!validCommandTail(tokens.items, command + 4))
                return error.InvalidAlternativesScript;
            try scriptGroup(
                owned,
                &groups,
                tokens.items[command + 2],
                null,
                limits,
            );
            try appendScriptPath(
                owned,
                &paths,
                tokens.items[command + 3],
                limits,
            );
            try immutable_targets.append(
                owned,
                try owned.dupe(u8, tokens.items[command + 3]),
            );
            try commands.append(owned, .{
                .name = try owned.dupe(u8, tokens.items[command + 2]),
                .command = if (std.mem.eql(u8, operation, "--remove"))
                    .{ .remove = try owned.dupe(
                        u8,
                        tokens.items[command + 3],
                    ) }
                else
                    .{ .set = try owned.dupe(
                        u8,
                        tokens.items[command + 3],
                    ) },
            });
            found = true;
        } else if (std.mem.eql(u8, operation, "--auto") or
            std.mem.eql(u8, operation, "--remove-all"))
        {
            if (command + 3 > tokens.items.len or
                !shellTokenSafe(tokens.items[command + 2]) or
                !validName(tokens.items[command + 2], limits))
                return error.InvalidAlternativesScript;
            if (!validCommandTail(tokens.items, command + 3))
                return error.InvalidAlternativesScript;
            try scriptGroup(
                owned,
                &groups,
                tokens.items[command + 2],
                null,
                limits,
            );
            try commands.append(owned, .{
                .name = try owned.dupe(u8, tokens.items[command + 2]),
                .command = if (std.mem.eql(u8, operation, "--auto"))
                    .auto
                else
                    .remove_all,
            });
            found = true;
        } else return error.InvalidAlternativesScript;
    }
    if (!found) return error.InvalidAlternativesScript;
    if (groups.items.len > limits.max_groups)
        return error.AlternativesLimit;
    if (commands.items.len > limits.max_script_commands)
        return error.AlternativesLimit;
    std.mem.sort([]const u8, paths.items, {}, bytewisePathLess);
    var unique: std.ArrayList([]const u8) = .empty;
    defer unique.deinit(owned);
    for (paths.items) |path| try appendUniquePath(owned, &unique, path);
    std.mem.sort(
        []const u8,
        immutable_targets.items,
        {},
        bytewisePathLess,
    );
    var unique_targets: std.ArrayList([]const u8) = .empty;
    defer unique_targets.deinit(owned);
    for (immutable_targets.items) |path|
        try appendUniquePath(owned, &unique_targets, path);
    return .{
        .groups = try owned.dupe(GroupAuthority, groups.items),
        .commands = try owned.dupe(ScriptCommand, commands.items),
        .paths = try owned.dupe([]const u8, unique.items),
        .immutable_targets = try owned.dupe(
            []const u8,
            unique_targets.items,
        ),
        .arena = storage.arena,
        .backing_allocator = allocator,
    };
}

pub fn vendorAuthority() Authority {
    const groups = comptime block: {
        var result: [pinned_vendor_groups.len]GroupAuthority = undefined;
        for (pinned_vendor_groups, 0..) |name, index| {
            result[index] = .{ .name = name };
        }
        break :block result;
    };
    return .{
        .groups = &groups,
        .require_vendor_counts = true,
    };
}

pub const EntryKind = enum {
    absent,
    regular,
    symlink,
};

pub const EntryFact = struct {
    path: []const u8,
    kind: EntryKind,
    mode: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    device: u64 = 0,
    inode: u64 = 0,
    link_count: u64 = 0,
    size: u64 = 0,
    modified_nanoseconds: i128 = 0,
    change_nanoseconds: i128 = 0,
    sha256: ?[32]u8 = null,
    link_target: ?[]const u8 = null,
};

pub const GroupState = struct {
    name: []const u8,
    record: Record,
    record_fact: EntryFact,
    selected: []const u8,
    links: []const Link,
    missing_master_targets: []const []const u8,
    facts: []const EntryFact,
    digest: [32]u8,
};

pub const Snapshot = struct {
    groups: []const GroupState,
    paths: []const []const u8,
    digest: [32]u8,
    relationship_count: usize,
    parsed_records: []OwnedRecord,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Snapshot) void {
        for (self.parsed_records) |*record| record.deinit();
        self.backing_allocator.free(self.parsed_records);
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn group(self: Snapshot, name: []const u8) ?GroupState {
        for (self.groups) |item| {
            if (std.mem.eql(u8, item.name, name)) return item;
        }
        return null;
    }
};

pub const ListedGroups = struct {
    names: []const []const u8,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *ListedGroups) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn listGroups(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    limits: Limits,
) !ListedGroups {
    var storage = try createArena(allocator);
    errdefer {
        storage.arena.deinit();
        allocator.destroy(storage.arena);
    }
    const owned = storage.owned;
    var database = validateDirectory(
        root,
        database_directory,
    ) catch |err| switch (err) {
        error.FileNotFound => return .{
            .names = &.{},
            .arena = storage.arena,
            .backing_allocator = allocator,
        },
        else => return err,
    };
    defer database.close();
    const maximum_name_bytes = std.math.mul(
        usize,
        limits.max_groups,
        limits.max_name_bytes,
    ) catch return error.AlternativesLimit;
    var members = try database.observeAlloc(
        owned,
        limits.max_groups,
        maximum_name_bytes,
    );
    defer members.deinit();
    const names = try owned.alloc([]const u8, members.members.len);
    for (members.members, names) |member, *name| {
        if (member.kind != .file or !validName(member.name, limits))
            return error.UnsupportedAlternativesEntry;
        name.* = try owned.dupe(u8, member.name);
    }
    std.mem.sort([]const u8, names, {}, bytewisePathLess);
    return .{
        .names = names,
        .arena = storage.arena,
        .backing_allocator = allocator,
    };
}

fn rootRelativeAbsolute(
    allocator: std.mem.Allocator,
    value: []const u8,
    limits: Limits,
) ![]const u8 {
    if (!validAbsolutePath(value, limits)) return error.InvalidAlternativesPath;
    return allocator.dupe(u8, value[1..]);
}

fn expectedAliasTarget(component: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, component, "bin")) return "usr/bin";
    if (std.mem.eql(u8, component, "sbin")) return "usr/sbin";
    if (std.mem.eql(u8, component, "lib")) return "usr/lib";
    if (std.mem.eql(u8, component, "lib32")) return "usr/lib32";
    if (std.mem.eql(u8, component, "lib64")) return "usr/lib64";
    return null;
}

fn physicalPath(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    absolute: []const u8,
    limits: Limits,
) ![]const u8 {
    const relative = try rootRelativeAbsolute(allocator, absolute, limits);
    errdefer allocator.free(relative);
    const slash = std.mem.indexOfScalar(u8, relative, '/');
    const first = if (slash) |index| relative[0..index] else relative;
    const expected = expectedAliasTarget(first) orelse return relative;
    const entry = (try root.entryIfExists(
        try root_fs.Path.init(first),
    )) orelse return relative;
    if (!entry.isSymbolicLink()) return relative;
    var buffer: [root_fs.maximum_link_target_bytes]u8 = undefined;
    const target = try root.readSymbolicLink(
        try root_fs.Path.init(first),
        &buffer,
    );
    if (!std.mem.eql(u8, target, expected))
        return error.InvalidAlternativesAlias;
    const suffix = if (slash) |index| relative[index + 1 ..] else "";
    const result = if (suffix.len == 0)
        try allocator.dupe(u8, expected)
    else
        try std.fmt.allocPrint(allocator, "{s}/{s}", .{ expected, suffix });
    allocator.free(relative);
    return result;
}

pub fn physicalManagedPath(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
    limits: Limits,
) ![]const u8 {
    _ = try root_fs.Path.initPackage(path);
    const absolute = try std.fmt.allocPrint(allocator, "/{s}", .{path});
    defer allocator.free(absolute);
    return physicalPath(allocator, root, absolute, limits);
}

fn appendUniquePath(
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]const u8),
    path: []const u8,
) !void {
    for (paths.items) |existing| {
        if (std.mem.eql(u8, existing, path)) return;
    }
    try paths.append(allocator, path);
}

fn observeRegular(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
    maximum_bytes: usize,
) !EntryFact {
    var pinned = try root.pinRegularFile(try root_fs.Path.init(path));
    defer pinned.close();
    const observation = try pinned.observeStableAlloc(allocator, maximum_bytes);
    defer allocator.free(observation.bytes);
    var sha256: [32]u8 = undefined;
    Sha256.hash(observation.bytes, &sha256, .{});
    return .{
        .path = path,
        .kind = .regular,
        .mode = observation.entry.mode,
        .uid = observation.entry.uid,
        .gid = observation.entry.gid,
        .device = observation.entry.device,
        .inode = observation.entry.inode,
        .link_count = observation.entry.link_count,
        .size = observation.entry.size,
        .modified_nanoseconds = observation.entry.modified_nanoseconds,
        .change_nanoseconds = observation.change_nanoseconds,
        .sha256 = sha256,
    };
}

fn observeLink(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
) !EntryFact {
    var pinned = try root.pinSymbolicLink(try root_fs.Path.init(path));
    defer pinned.close();
    var buffer: [root_fs.maximum_link_target_bytes]u8 = undefined;
    const observation = try pinned.observe(&buffer);
    return .{
        .path = path,
        .kind = .symlink,
        .mode = observation.entry.mode,
        .uid = observation.entry.uid,
        .gid = observation.entry.gid,
        .device = observation.entry.device,
        .inode = observation.entry.inode,
        .link_count = observation.entry.link_count,
        .size = observation.entry.size,
        .modified_nanoseconds = observation.entry.modified_nanoseconds,
        .change_nanoseconds = observation.change_nanoseconds,
        .link_target = try allocator.dupe(u8, observation.target),
    };
}

fn observeOptionalEntry(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
) !EntryFact {
    const entry = (try root.entryIfExists(
        try root_fs.Path.init(path),
    )) orelse return .{ .path = path, .kind = .absent };
    if (!entry.modeled or (!entry.isRegularFile() and
        !entry.isSymbolicLink()))
        return error.UnsupportedAlternativesEntry;
    return if (entry.isRegularFile())
        observeRegular(
            allocator,
            root,
            path,
            (package_database.Limits{}).max_info_file_bytes,
        )
    else
        observeLink(allocator, root, path);
}

fn resolvedLinkTarget(
    allocator: std.mem.Allocator,
    current: []const u8,
    target: []const u8,
) ![]const u8 {
    if (!validText(target, root_fs.maximum_link_target_bytes, false))
        return error.InvalidAlternativesLinkTarget;
    var components: std.ArrayList([]const u8) = .empty;
    defer components.deinit(allocator);
    if (target[0] != '/') {
        if (std.mem.lastIndexOfScalar(u8, current, '/')) |index| {
            var base = std.mem.splitScalar(u8, current[0..index], '/');
            while (base.next()) |component| {
                if (component.len != 0)
                    try components.append(allocator, component);
            }
        }
    }
    const source = if (target[0] == '/') target[1..] else target;
    var iterator = std.mem.splitScalar(u8, source, '/');
    while (iterator.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, "."))
            continue;
        if (std.mem.eql(u8, component, "..")) {
            if (components.items.len == 0)
                return error.AlternativesTraversal;
            _ = components.pop();
            continue;
        }
        if (!validText(component, root_fs.maximum_component_bytes, false))
            return error.InvalidAlternativesLinkTarget;
        try components.append(allocator, component);
    }
    if (components.items.len == 0) return error.AlternativesTraversal;
    return std.mem.join(allocator, "/", components.items);
}

fn appendFact(
    allocator: std.mem.Allocator,
    facts: *std.ArrayList(EntryFact),
    fact: EntryFact,
) !void {
    for (facts.items) |existing| {
        if (std.mem.eql(u8, existing.path, fact.path)) return;
    }
    try facts.append(allocator, fact);
}

fn entryFactEqual(left: EntryFact, right: EntryFact) bool {
    if (!std.mem.eql(u8, left.path, right.path) or
        left.kind != right.kind or left.mode != right.mode or
        left.uid != right.uid or left.gid != right.gid or
        left.device != right.device or left.inode != right.inode or
        left.link_count != right.link_count or left.size != right.size or
        left.modified_nanoseconds != right.modified_nanoseconds or
        left.change_nanoseconds != right.change_nanoseconds)
        return false;
    if (left.sha256) |digest| {
        if (right.sha256 == null or
            !std.mem.eql(u8, &digest, &right.sha256.?))
            return false;
    } else if (right.sha256 != null) return false;
    if (left.link_target) |target| {
        if (right.link_target == null or
            !std.mem.eql(u8, target, right.link_target.?))
            return false;
    } else if (right.link_target != null) return false;
    return true;
}

fn updateFactDigest(digest: *Sha256, fact: EntryFact) void {
    digest.update(fact.path);
    digest.update(&.{ 0, @intFromEnum(fact.kind) });
    var number: [16]u8 = undefined;
    std.mem.writeInt(u32, number[0..4], fact.mode, .big);
    digest.update(number[0..4]);
    std.mem.writeInt(u32, number[0..4], fact.uid, .big);
    digest.update(number[0..4]);
    std.mem.writeInt(u32, number[0..4], fact.gid, .big);
    digest.update(number[0..4]);
    std.mem.writeInt(u64, number[0..8], fact.device, .big);
    digest.update(number[0..8]);
    std.mem.writeInt(u64, number[0..8], fact.inode, .big);
    digest.update(number[0..8]);
    std.mem.writeInt(u64, number[0..8], fact.link_count, .big);
    digest.update(number[0..8]);
    std.mem.writeInt(u64, number[0..8], fact.size, .big);
    digest.update(number[0..8]);
    std.mem.writeInt(
        i128,
        &number,
        fact.modified_nanoseconds,
        .big,
    );
    digest.update(&number);
    std.mem.writeInt(i128, &number, fact.change_nanoseconds, .big);
    digest.update(&number);
    if (fact.sha256) |sha256| {
        digest.update(&.{1});
        digest.update(&sha256);
    } else digest.update(&.{0});
    if (fact.link_target) |target| {
        digest.update(&.{1});
        digest.update(target);
    } else digest.update(&.{0});
    digest.update(&.{0xff});
}

fn observeTargetTopology(
    owned: std.mem.Allocator,
    root: root_fs.Root,
    absolute: []const u8,
    limits: Limits,
    paths: *std.ArrayList([]const u8),
    facts: *std.ArrayList(EntryFact),
) !void {
    var current = try physicalPath(owned, root, absolute, limits);
    var visited: std.ArrayList([]const u8) = .empty;
    defer visited.deinit(owned);
    var depth: usize = 0;
    while (true) : (depth += 1) {
        if (depth >= 64) return error.AlternativesLinkCycle;
        for (visited.items) |prior| {
            if (std.mem.eql(u8, prior, current))
                return error.AlternativesLinkCycle;
        }
        try visited.append(owned, current);
        try appendUniquePath(owned, paths, current);
        const fact = try observeOptionalEntry(owned, root, current);
        try appendFact(owned, facts, fact);
        switch (fact.kind) {
            .absent, .regular => return,
            .symlink => {
                try validateRootOwnedLink(fact);
                const next = try resolvedLinkTarget(
                    owned,
                    current,
                    fact.link_target.?,
                );
                const absolute_next = try std.fmt.allocPrint(
                    owned,
                    "/{s}",
                    .{next},
                );
                current = try physicalPath(
                    owned,
                    root,
                    absolute_next,
                    limits,
                );
            },
        }
    }
}

pub const ImmutableSnapshot = struct {
    facts: []const EntryFact,
    digest: [32]u8,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *ImmutableSnapshot) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

fn entryFactLess(_: void, left: EntryFact, right: EntryFact) bool {
    return std.mem.order(u8, left.path, right.path) == .lt;
}

fn retainedReadmePath(name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "README"))
        return selector_directory ++ "/README";
    if (std.mem.eql(u8, name, "README.dpkg-new"))
        return selector_directory ++ "/README.dpkg-new";
    return null;
}

fn exactRetainedReadme(fact: EntryFact) bool {
    const digest = fact.sha256 orelse return false;
    return fact.kind == .regular and fact.mode == 0o644 and
        fact.uid == 0 and fact.gid == 0 and fact.link_count == 1 and
        fact.size == 100 and std.mem.eql(
        u8,
        &digest,
        &digestLiteral(
            "a44afdb50eacfc09e45f6dac1e18ae231c179feec633c106e1060bae8ae11df1",
        ),
    );
}

fn immutableDigest(facts: []const EntryFact) [32]u8 {
    var digest = Sha256.init(.{});
    digest.update("debz-native-alternatives-immutable-v1\x00");
    for (facts) |fact| updateFactDigest(&digest, fact);
    return digest.finalResult();
}

fn requireNewAbsentTarget(facts: []const EntryFact, previous_count: usize) !void {
    if (facts.len != previous_count + 1 or
        facts[previous_count].kind != .absent)
        return error.InvalidAlternativesScriptAuthority;
}

pub fn captureScriptInputs(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    script: ScriptAuthority,
    before: Snapshot,
    limits: Limits,
) !ImmutableSnapshot {
    var storage = try createArena(allocator);
    errdefer {
        storage.arena.deinit();
        allocator.destroy(storage.arena);
    }
    const owned = storage.owned;
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(owned);
    var facts: std.ArrayList(EntryFact) = .empty;
    defer facts.deinit(owned);
    for (script.immutable_targets) |target| {
        const previous_count = facts.items.len;
        try observeTargetTopology(
            owned,
            root,
            target,
            limits,
            &paths,
            &facts,
        );
        if (script.require_targets_absent)
            try requireNewAbsentTarget(facts.items, previous_count);
    }
    for (before.groups) |group| {
        if (script.group(group.name) == null) continue;
        for (group.record.candidates) |candidate| {
            try observeTargetTopology(
                owned,
                root,
                candidate.path,
                limits,
                &paths,
                &facts,
            );
            for (candidate.targets) |target| {
                if (target.len == 0) continue;
                try observeTargetTopology(
                    owned,
                    root,
                    target,
                    limits,
                    &paths,
                    &facts,
                );
            }
        }
    }
    const tool = try observeRegular(
        owned,
        root,
        tool_path,
        8 * 1024 * 1024,
    );
    if (tool.uid != 0 or tool.gid != 0 or tool.mode != 0o755 or
        tool.link_count != 1)
        return error.InvalidAlternativesTool;
    try appendFact(owned, &facts, tool);
    std.mem.sort(EntryFact, facts.items, {}, entryFactLess);
    const result = try owned.dupe(EntryFact, facts.items);
    return .{
        .facts = result,
        .digest = immutableDigest(result),
        .arena = storage.arena,
        .backing_allocator = allocator,
    };
}

pub fn validateScriptInputs(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    script: ScriptAuthority,
    initial: Snapshot,
    before: ImmutableSnapshot,
    limits: Limits,
) !void {
    var after = try captureScriptInputs(
        allocator,
        root,
        script,
        initial,
        limits,
    );
    defer after.deinit();
    if (!std.mem.eql(u8, &before.digest, &after.digest) or
        before.facts.len != after.facts.len)
        return error.AlternativesInputChanged;
    for (before.facts, after.facts) |left, right| {
        if (!entryFactEqual(left, right))
            return error.AlternativesInputChanged;
    }
}

fn validateRootOwnedLink(fact: EntryFact) !void {
    if (fact.kind != .symlink or fact.mode != 0o777 or
        fact.uid != 0 or fact.gid != 0 or fact.link_count != 1 or
        fact.link_target == null)
        return error.InvalidAlternativesLink;
}

fn selectorPath(
    allocator: std.mem.Allocator,
    name: []const u8,
) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ selector_directory, name },
    );
}

fn recordPath(
    allocator: std.mem.Allocator,
    name: []const u8,
) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ database_directory, name },
    );
}

fn groupStateDigest(group: GroupState) [32]u8 {
    var digest = Sha256.init(.{});
    digest.update("debz-native-alternatives-group-state-v1\x00");
    digest.update(&recordDigest(group.record));
    digest.update(group.selected);
    digest.update(&.{0});
    for (group.facts) |fact| updateFactDigest(&digest, fact);
    return digest.finalResult();
}

fn snapshotDigest(groups: []const GroupState) [32]u8 {
    var digest = Sha256.init(.{});
    digest.update("debz-native-alternatives-snapshot-v1\x00");
    for (groups) |group| digest.update(&group.digest);
    return digest.finalResult();
}

fn topologyMatches(authority: Topology, record: Record) bool {
    if (!std.mem.eql(u8, authority.master_link, record.master_link))
        return false;
    if (authority.slaves.len != record.slaves.len) return false;
    for (record.slaves) |right| {
        var found = false;
        for (authority.slaves) |left| {
            if (std.mem.eql(u8, left.name, right.name) and
                std.mem.eql(u8, left.link, right.link))
            {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn topologyWithin(authority: GroupAuthority, record: Record) bool {
    const topology = authority.topology orelse return true;
    if (!std.mem.eql(u8, topology.master_link, record.master_link))
        return false;
    if (!authority.allow_slave_subset and
        topology.slaves.len != record.slaves.len)
        return false;
    for (record.slaves) |right| {
        var found = false;
        for (topology.slaves) |left| {
            if (std.mem.eql(u8, left.name, right.name) and
                std.mem.eql(u8, left.link, right.link))
            {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn validateAutomaticSelection(
    record: Record,
    selected: Candidate,
    missing_targets: []const []const u8,
) !void {
    if (record.mode != .auto) return;
    for (missing_targets) |path| {
        if (std.mem.eql(u8, path, selected.path)) return;
    }
    var highest_priority: ?i32 = null;
    for (record.candidates) |candidate| {
        var candidate_missing = false;
        for (missing_targets) |path| {
            if (std.mem.eql(u8, path, candidate.path)) {
                candidate_missing = true;
                break;
            }
        }
        if (!candidate_missing and
            (highest_priority == null or
                candidate.priority > highest_priority.?))
            highest_priority = candidate.priority;
    }
    if (highest_priority == null or
        selected.priority != highest_priority.?)
        return error.InvalidAlternativesSelection;
}

fn captureGroup(
    allocator: std.mem.Allocator,
    owned: std.mem.Allocator,
    root: root_fs.Root,
    authority: GroupAuthority,
    limits: Limits,
    parsed: *OwnedRecord,
    expected_record_sha256: [32]u8,
    paths: *std.ArrayList([]const u8),
) !GroupState {
    _ = allocator;
    const record = parsed.record;
    if (!topologyWithin(authority, record))
        return error.AlternativesTopologyChanged;
    const record_path = try recordPath(owned, record.name);
    const record_fact = try observeRegular(
        owned,
        root,
        record_path,
        limits.max_record_bytes,
    );
    if (record_fact.mode != 0o644 or record_fact.uid != 0 or
        record_fact.gid != 0 or record_fact.link_count != 1 or
        !std.mem.eql(
            u8,
            &record_fact.sha256.?,
            &expected_record_sha256,
        ))
        return error.InvalidAlternativesRecordMetadata;
    try appendUniquePath(owned, paths, record_path);

    const master_selector_path = try selectorPath(owned, record.name);
    const master_selector = try observeOptionalEntry(
        owned,
        root,
        master_selector_path,
    );
    try validateRootOwnedLink(master_selector);
    const selected = master_selector.link_target.?;
    const selected_candidate = record.candidate(selected) orelse
        return error.InvalidAlternativesSelection;
    const selected_links = try selectedLinks(
        owned,
        record,
        selected_candidate.path,
    );
    var facts: std.ArrayList(EntryFact) = .empty;
    defer facts.deinit(owned);
    try appendFact(owned, &facts, record_fact);
    try appendFact(owned, &facts, master_selector);
    try appendUniquePath(owned, paths, master_selector_path);

    for (record.slaves) |slave| {
        const path = try selectorPath(owned, slave.name);
        try appendUniquePath(owned, paths, path);
        const fact = try observeOptionalEntry(owned, root, path);
        const target = selected_candidate.targets[
            record.slaveIndex(slave.name).?
        ];
        if (target.len == 0) {
            if (fact.kind != .absent)
                return error.InvalidAlternativesSelection;
        } else {
            try validateRootOwnedLink(fact);
            if (!std.mem.eql(u8, fact.link_target.?, target))
                return error.InvalidAlternativesSelection;
        }
        try appendFact(owned, &facts, fact);
    }

    for (record.slaves) |slave| {
        const physical = try physicalPath(
            owned,
            root,
            slave.link,
            .{},
        );
        try appendUniquePath(owned, paths, physical);
        const fact = try observeOptionalEntry(owned, root, physical);
        const target = selected_candidate.targets[
            record.slaveIndex(slave.name).?
        ];
        if (target.len == 0) {
            if (fact.kind != .absent)
                return error.InvalidAlternativesSelection;
        } else {
            try validateRootOwnedLink(fact);
            const expected = try std.fmt.allocPrint(
                owned,
                "/etc/alternatives/{s}",
                .{slave.name},
            );
            if (!std.mem.eql(u8, fact.link_target.?, expected))
                return error.InvalidAlternativesSelection;
        }
        try appendFact(owned, &facts, fact);
    }
    const master_physical = try physicalPath(
        owned,
        root,
        record.master_link,
        .{},
    );
    try appendUniquePath(owned, paths, master_physical);
    const master_generic = try observeOptionalEntry(
        owned,
        root,
        master_physical,
    );
    try validateRootOwnedLink(master_generic);
    const expected_master = try std.fmt.allocPrint(
        owned,
        "/etc/alternatives/{s}",
        .{record.name},
    );
    if (!std.mem.eql(u8, master_generic.link_target.?, expected_master))
        return error.InvalidAlternativesSelection;
    try appendFact(owned, &facts, master_generic);

    for (record.candidates) |candidate| {
        try observeTargetTopology(
            owned,
            root,
            candidate.path,
            limits,
            paths,
            &facts,
        );
        for (candidate.targets) |target| {
            if (target.len == 0) continue;
            try observeTargetTopology(
                owned,
                root,
                target,
                limits,
                paths,
                &facts,
            );
        }
    }
    var missing_master_targets: std.ArrayList([]const u8) = .empty;
    defer missing_master_targets.deinit(owned);
    for (record.candidates) |candidate| {
        const physical = try physicalPath(
            owned,
            root,
            candidate.path,
            .{},
        );
        for (facts.items) |fact| {
            if (std.mem.eql(u8, fact.path, physical) and
                fact.kind == .absent)
            {
                try missing_master_targets.append(
                    owned,
                    candidate.path,
                );
                break;
            }
        }
    }
    try validateAutomaticSelection(
        record,
        selected_candidate,
        missing_master_targets.items,
    );
    var group: GroupState = .{
        .name = record.name,
        .record = record,
        .record_fact = record_fact,
        .selected = selected,
        .links = selected_links,
        .missing_master_targets = try owned.dupe(
            []const u8,
            missing_master_targets.items,
        ),
        .facts = try owned.dupe(EntryFact, facts.items),
        .digest = undefined,
    };
    group.digest = groupStateDigest(group);
    return group;
}

fn bytewiseGroupLess(_: void, left: GroupState, right: GroupState) bool {
    return std.mem.order(u8, left.name, right.name) == .lt;
}

fn bytewisePathLess(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn validateDirectory(
    root: root_fs.Root,
    path: []const u8,
) !root_fs.PinnedDirectory {
    var pinned = try root.pinDirectory(try root_fs.Path.init(path));
    errdefer pinned.close();
    const metadata = try pinned.metadata();
    if (metadata.entry.uid != 0 or metadata.entry.gid != 0 or
        metadata.entry.link_count < 1 or metadata.entry.mode != 0o755)
        return error.InvalidAlternativesDirectory;
    return pinned;
}

fn requireAbsent(root: root_fs.Root, path: []const u8) !void {
    if (try root.entryIfExists(try root_fs.Path.init(path)) != null)
        return error.PartialAlternativesState;
}

fn validateAbsentGroup(
    owned: std.mem.Allocator,
    root: root_fs.Root,
    group: GroupAuthority,
    limits: Limits,
) !void {
    try requireAbsent(root, try recordPath(owned, group.name));
    try requireAbsent(root, try selectorPath(owned, group.name));
    const topology = group.topology orelse return;
    try requireAbsent(
        root,
        try physicalPath(owned, root, topology.master_link, limits),
    );
    for (topology.slaves) |slave| {
        try requireAbsent(root, try selectorPath(owned, slave.name));
        try requireAbsent(
            root,
            try physicalPath(owned, root, slave.link, limits),
        );
    }
}

fn appendUniqueTopologyPath(
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]const u8),
    path: []const u8,
) !void {
    for (paths.items) |existing| {
        if (std.mem.eql(u8, existing, path))
            return error.AlternativesTopologyConflict;
    }
    try paths.append(allocator, path);
}

fn validateAuthorityNamespaces(
    owned: std.mem.Allocator,
    root: root_fs.Root,
    authority: Authority,
    groups: []const GroupState,
) !void {
    var selectors: std.ArrayList([]const u8) = .empty;
    defer selectors.deinit(owned);
    var generics: std.ArrayList([]const u8) = .empty;
    defer generics.deinit(owned);
    for (authority.groups) |allowed| {
        var topology = allowed.topology;
        for (groups) |group| {
            if (std.mem.eql(u8, group.name, allowed.name)) {
                topology = .{
                    .master_link = group.record.master_link,
                    .slaves = group.record.slaves,
                };
                break;
            }
        }
        const value = topology orelse continue;
        try appendUniqueTopologyPath(owned, &selectors, allowed.name);
        try appendUniqueTopologyPath(
            owned,
            &generics,
            try physicalPath(
                owned,
                root,
                value.master_link,
                authority.limits,
            ),
        );
        for (value.slaves) |slave| {
            try appendUniqueTopologyPath(owned, &selectors, slave.name);
            try appendUniqueTopologyPath(
                owned,
                &generics,
                try physicalPath(
                    owned,
                    root,
                    slave.link,
                    authority.limits,
                ),
            );
        }
    }
}

pub fn capture(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    authority: Authority,
) !Snapshot {
    if (authority.groups.len > authority.limits.max_groups)
        return error.AlternativesLimit;
    var storage = try createArena(allocator);
    errdefer {
        storage.arena.deinit();
        allocator.destroy(storage.arena);
    }
    const owned = storage.owned;
    var parsed_records: std.ArrayList(OwnedRecord) = .empty;
    errdefer {
        for (parsed_records.items) |*record| record.deinit();
        parsed_records.deinit(allocator);
    }
    var groups: std.ArrayList(GroupState) = .empty;
    defer groups.deinit(owned);
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(owned);

    var database: ?root_fs.PinnedDirectory = validateDirectory(
        root,
        database_directory,
    ) catch |err| switch (err) {
        error.FileNotFound => missing: {
            for (authority.groups) |group| {
                if (!group.allow_absent)
                    return error.AlternativesDatabaseMissing;
            }
            break :missing null;
        },
        else => return err,
    };
    defer if (database) |*directory| directory.close();
    if (database) |*directory| {
        const maximum_name_bytes = std.math.mul(
            usize,
            authority.limits.max_groups,
            authority.limits.max_name_bytes,
        ) catch return error.AlternativesLimit;
        var members = try directory.observeAlloc(
            owned,
            authority.limits.max_groups,
            maximum_name_bytes,
        );
        defer members.deinit();
        for (members.members) |member| {
            if (member.kind != .file or
                !validName(member.name, authority.limits))
                return error.UnsupportedAlternativesEntry;
            const group_authority = authority.group(member.name) orelse
                return error.UnsupportedAlternativesGroup;
            const path = try recordPath(owned, member.name);
            const bytes = try root.readFileAlloc(
                allocator,
                try root_fs.Path.init(path),
                authority.limits.max_record_bytes,
            );
            defer allocator.free(bytes);
            var parsed = try parse(
                allocator,
                member.name,
                bytes,
                authority.limits,
            );
            var record_sha256: [32]u8 = undefined;
            Sha256.hash(bytes, &record_sha256, .{});
            errdefer parsed.deinit();
            try parsed_records.append(allocator, parsed);
            parsed = undefined;
            try groups.append(
                owned,
                try captureGroup(
                    allocator,
                    owned,
                    root,
                    group_authority,
                    authority.limits,
                    &parsed_records.items[parsed_records.items.len - 1],
                    record_sha256,
                    &paths,
                ),
            );
        }
    }
    for (authority.groups) |group| {
        var found = false;
        for (groups.items) |observed| {
            if (std.mem.eql(u8, group.name, observed.name)) {
                found = true;
                break;
            }
        }
        if (found) continue;
        if (!group.allow_absent) return error.AlternativesGroupMissing;
        try validateAbsentGroup(
            owned,
            root,
            group,
            authority.limits,
        );
    }
    try validateAuthorityNamespaces(owned, root, authority, groups.items);

    var selectors = validateDirectory(
        root,
        selector_directory,
    ) catch |err| switch (err) {
        error.FileNotFound => {
            if (groups.items.len != 0)
                return error.AlternativesSelectorsMissing;
            std.mem.sort(GroupState, groups.items, {}, bytewiseGroupLess);
            std.mem.sort([]const u8, paths.items, {}, bytewisePathLess);
            return .{
                .groups = try owned.dupe(GroupState, groups.items),
                .paths = try owned.dupe([]const u8, paths.items),
                .digest = snapshotDigest(groups.items),
                .relationship_count = 0,
                .parsed_records = try parsed_records.toOwnedSlice(allocator),
                .arena = storage.arena,
                .backing_allocator = allocator,
            };
        },
        else => return err,
    };
    defer selectors.close();
    const relationships_per_group = std.math.add(
        usize,
        authority.limits.max_slaves,
        1,
    ) catch return error.AlternativesLimit;
    const selector_limit = std.math.add(
        usize,
        std.math.mul(
            usize,
            authority.limits.max_groups,
            relationships_per_group,
        ) catch return error.AlternativesLimit,
        2,
    ) catch return error.AlternativesLimit;
    const selector_name_limit = std.math.mul(
        usize,
        selector_limit,
        authority.limits.max_name_bytes,
    ) catch return error.AlternativesLimit;
    var selector_members = try selectors.observeAlloc(
        owned,
        selector_limit,
        selector_name_limit,
    );
    defer selector_members.deinit();
    for (selector_members.members) |member| {
        const readme_path = if (authority.allow_retained_readme)
            retainedReadmePath(member.name)
        else
            null;
        if (readme_path) |path| {
            if (member.kind != .file)
                return error.UnsupportedAlternativesEntry;
            const readme = try observeRegular(
                owned,
                root,
                path,
                1024,
            );
            if (!exactRetainedReadme(readme))
                return error.InvalidAlternativesRetainedMetadata;
            try appendUniquePath(
                owned,
                &paths,
                path,
            );
            continue;
        }
        if (member.kind != .sym_link)
            return error.UnsupportedAlternativesEntry;
        var expected = false;
        for (groups.items) |group| {
            if (std.mem.eql(u8, member.name, group.name))
                expected = true;
            for (group.record.slaves) |slave| {
                if (std.mem.eql(u8, member.name, slave.name))
                    expected = true;
            }
        }
        if (!expected) return error.UnsupportedAlternativesSelector;
    }

    std.mem.sort(GroupState, groups.items, {}, bytewiseGroupLess);
    std.mem.sort([]const u8, paths.items, {}, bytewisePathLess);
    var relationship_count: usize = 0;
    for (groups.items) |group| {
        relationship_count = std.math.add(
            usize,
            relationship_count,
            std.math.add(
                usize,
                1,
                group.record.slaves.len,
            ) catch return error.AlternativesLimit,
        ) catch return error.AlternativesLimit;
    }
    if (authority.require_vendor_counts and
        (groups.items.len != pinned_vendor_group_count or
            relationship_count != pinned_vendor_relationship_count or
            paths.items.len != pinned_vendor_linked_entry_count))
        return error.PinnedAlternativesInventoryMismatch;
    return .{
        .groups = try owned.dupe(GroupState, groups.items),
        .paths = try owned.dupe([]const u8, paths.items),
        .digest = snapshotDigest(groups.items),
        .relationship_count = relationship_count,
        .parsed_records = try parsed_records.toOwnedSlice(allocator),
        .arena = storage.arena,
        .backing_allocator = allocator,
    };
}

pub fn captureExisting(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    limits: Limits,
) !Snapshot {
    var listed = try listGroups(allocator, root, limits);
    defer listed.deinit();
    const groups = try allocator.alloc(GroupAuthority, listed.names.len);
    defer allocator.free(groups);
    for (listed.names, groups) |name, *group| group.* = .{
        .name = name,
        .mutable = false,
    };
    return capture(allocator, root, .{
        .groups = groups,
        .limits = limits,
    });
}

pub fn authorityFromSnapshot(
    allocator: std.mem.Allocator,
    snapshot: Snapshot,
) ![]GroupAuthority {
    const result = try allocator.alloc(GroupAuthority, snapshot.groups.len);
    for (snapshot.groups, result) |group, *authority| {
        authority.* = .{
            .name = group.name,
            .topology = .{
                .master_link = group.record.master_link,
                .slaves = group.record.slaves,
            },
            .allow_absent = true,
        };
    }
    return result;
}

pub fn validateTransition(
    before: Snapshot,
    after: Snapshot,
    authority: Authority,
) !void {
    for (after.groups) |group| {
        const allowed = authority.group(group.name) orelse
            return error.UnsupportedAlternativesGroup;
        if (!topologyWithin(allowed, group.record))
            return error.AlternativesTopologyChanged;
        if (!allowed.mutable) {
            const prior = before.group(group.name) orelse
                return error.AlternativesStateChanged;
            if (!std.mem.eql(u8, &prior.digest, &group.digest))
                return error.AlternativesStateChanged;
        }
    }
    for (before.groups) |group| {
        if (after.group(group.name) == null) {
            const allowed = authority.group(group.name) orelse
                return error.UnsupportedAlternativesGroup;
            if (!allowed.mutable) return error.AlternativesStateChanged;
        }
    }
}

fn transitionMatchesGroup(
    allocator: std.mem.Allocator,
    record: ?Record,
    selected: ?[]const u8,
    observed: ?GroupState,
) !bool {
    if (record == null) return observed == null;
    const group = observed orelse return false;
    if (selected == null or
        !std.mem.eql(u8, selected.?, group.selected))
        return false;
    const expected = try canonicalBytes(
        allocator,
        record.?,
    );
    defer allocator.free(expected);
    const actual = try canonicalBytes(allocator, group.record);
    defer allocator.free(actual);
    return std.mem.eql(u8, expected, actual);
}

/// Requires each changed group to equal an outcome reachable by executing a
/// bounded, source-ordered subset of that script's literal commands. The
/// subset accounts for shell branches without granting arbitrary record edits.
pub fn validateScriptTransition(
    allocator: std.mem.Allocator,
    before: Snapshot,
    after: Snapshot,
    script: ScriptAuthority,
    authority: Authority,
) !void {
    try validateTransition(before, after, authority);
    for (script.groups) |script_group| {
        var commands: [10]Command = undefined;
        var command_count: usize = 0;
        for (script.commands) |command| {
            if (!std.mem.eql(u8, command.name, script_group.name)) continue;
            if (command_count == commands.len)
                return error.AlternativesLimit;
            commands[command_count] = command.command;
            command_count += 1;
        }
        if (command_count == 0)
            return error.InvalidAlternativesScriptAuthority;
        const prior = before.group(script_group.name);
        const observed = after.group(script_group.name);
        const outcomes = @as(usize, 1) << @intCast(command_count);
        var matched = false;
        masks: for (0..outcomes) |mask| {
            var current_record: ?Record = if (prior) |group|
                group.record
            else
                null;
            var current_selected: ?[]const u8 = if (prior) |group|
                group.selected
            else
                null;
            var owned_transition: ?Mutation = null;
            defer if (owned_transition) |*transition| transition.deinit();
            for (commands[0..command_count], 0..) |command, index| {
                if (mask & (@as(usize, 1) << @intCast(index)) == 0)
                    continue;
                const next = mutate(allocator, .{
                    .name = script_group.name,
                    .current = current_record,
                    .selected = current_selected,
                    .missing_master_targets = if (prior) |group|
                        group.missing_master_targets
                    else
                        &.{},
                    .command = command,
                }) catch continue :masks;
                if (owned_transition) |*transition| transition.deinit();
                owned_transition = next;
                current_record = next.record;
                current_selected = next.selected;
            }
            if (owned_transition) |transition| {
                if (try transitionMatchesGroup(
                    allocator,
                    transition.record,
                    transition.selected,
                    observed,
                )) {
                    matched = true;
                    break;
                }
            } else {
                if (try transitionMatchesGroup(
                    allocator,
                    current_record,
                    current_selected,
                    observed,
                )) {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) return error.AlternativesStateChanged;
    }
}

test "native_alternatives.test.snapshot tool pin is exact and architecture bound" {
    const testing = std.testing;
    const snapshot = snapshot_tools[0].sha256;
    try testing.expect(matchesPinnedTool("amd64", pinned_tools[0].sha256));
    try testing.expect(matchesPinnedTool("arm64", pinned_tools[1].sha256));
    try testing.expect(matchesPinnedTool("amd64", snapshot));
    try testing.expect(!matchesPinnedTool("arm64", snapshot));
    try testing.expect(!matchesPinnedTool("i386", snapshot));
    try testing.expect(matchesSnapshotTool("amd64", snapshot));
    try testing.expect(!matchesSnapshotTool(
        "amd64",
        pinned_tools[0].sha256,
    ));
    try testing.expect(!matchesSnapshotTool("arm64", snapshot));
    var changed = snapshot;
    changed[0] ^= 1;
    try testing.expect(!matchesPinnedTool("amd64", changed));
    try testing.expect(!matchesSnapshotTool("amd64", changed));
}

test "native_alternatives.test.staged dpkg README retains exact immutable metadata" {
    const testing = std.testing;
    try testing.expectEqualStrings("etc/alternatives/README", retainedReadmePath("README").?);
    try testing.expectEqualStrings("etc/alternatives/README.dpkg-new", retainedReadmePath("README.dpkg-new").?);
    try testing.expect(retainedReadmePath("README.dpkg-tmp") == null);
    try testing.expect(retainedReadmePath("foreign.dpkg-new") == null);
    const expected: EntryFact = .{
        .path = "etc/alternatives/README.dpkg-new",
        .kind = .regular,
        .mode = 0o644,
        .uid = 0,
        .gid = 0,
        .link_count = 1,
        .size = 100,
        .sha256 = digestLiteral("a44afdb50eacfc09e45f6dac1e18ae231c179feec633c106e1060bae8ae11df1"),
    };
    try testing.expect(exactRetainedReadme(expected));
    var changed = expected;
    changed.mode = 0o666;
    try testing.expect(!exactRetainedReadme(changed));
    changed = expected;
    changed.link_count = 2;
    try testing.expect(!exactRetainedReadme(changed));
    changed = expected;
    changed.sha256 = null;
    try testing.expect(!exactRetainedReadme(changed));
}

test "native_alternatives.test.parser round trips auto manual priorities and empty slaves" {
    const testing = std.testing;
    const bytes =
        "manual\n" ++
        "/usr/bin/demo\n" ++
        "demo.1\n" ++
        "/usr/share/man/man1/demo.1\n" ++
        "\n" ++
        "/usr/lib/demo/a\n" ++
        "-10\n" ++
        "\n" ++
        "/usr/lib/demo/b\n" ++
        "20\n" ++
        "/usr/share/man/man1/demo-b.1\n" ++
        "\n";
    var parsed = try parse(testing.allocator, "demo", bytes, .{});
    defer parsed.deinit();
    try testing.expectEqual(Mode.manual, parsed.record.mode);
    try testing.expectEqual(@as(usize, 1), parsed.record.slaves.len);
    try testing.expectEqual(@as(usize, 2), parsed.record.candidates.len);
    try testing.expectEqual(@as(i32, -10), parsed.record.candidates[0].priority);
    try testing.expectEqualStrings("", parsed.record.candidates[0].targets[0]);
    const canonical = try canonicalBytes(testing.allocator, parsed.record);
    defer testing.allocator.free(canonical);
    try testing.expectEqualStrings(bytes, canonical);
}

test "native_alternatives.test.parser rejects malformed oversized and noncanonical records" {
    const testing = std.testing;
    try testing.expect(!validName("Demo", .{}));
    try testing.expect(!validName("demo_name", .{}));
    try testing.expect(validName("demo+name.1-gz", .{}));
    const cases = [_]struct {
        bytes: []const u8,
        expected: anyerror,
    }{
        .{ .bytes = "", .expected = error.InvalidRecord },
        .{ .bytes = "automatic\n/usr/bin/x\n\n/usr/bin/a\n1\n\n", .expected = error.InvalidMode },
        .{ .bytes = "auto\n/usr/bin/x\n\n/usr/bin/a\n01\n\n", .expected = error.InvalidPriority },
        .{ .bytes = "auto\n/usr/bin/x\n\n/usr/bin/b\n1\n/usr/bin/a\n2\n\n", .expected = error.CandidateOrder },
        .{ .bytes = "auto\n/usr/bin/../x\n\n/usr/bin/a\n1\n\n", .expected = error.InvalidPath },
        .{ .bytes = "auto\n/usr/bin/x\ns\n/usr/bin/s\ns\n/usr/bin/t\n\n/usr/bin/a\n1\n/a\n/b\n\n", .expected = error.DuplicateSlave },
        .{ .bytes = "auto\n/usr/bin/x\nx\n/usr/bin/s\n\n/usr/bin/a\n1\n/a\n\n", .expected = error.DuplicateSlave },
        .{ .bytes = "auto\n/usr/bin/x\n\n/usr/bin/a\n+1\n\n", .expected = error.InvalidPriority },
        .{ .bytes = "auto\n/usr/bin/x\n\n/usr/bin/a\n2147483648\n\n", .expected = error.InvalidPriority },
        .{ .bytes = "auto\n/usr/bin/x\n\n/usr/bin/a\n1\n", .expected = error.InvalidRecord },
        .{ .bytes = "auto\n/usr/bin/x\n\n/usr/bin/a\x001\n1\n\n", .expected = error.InvalidPath },
    };
    for (cases) |case| {
        try testing.expectError(
            case.expected,
            parse(testing.allocator, "x", case.bytes, .{}),
        );
    }
    try testing.expectError(
        error.RecordTooLarge,
        parse(
            testing.allocator,
            "x",
            "auto\n/usr/bin/x\n\n/usr/bin/a\n1\n\n",
            .{ .max_record_bytes = 4 },
        ),
    );
    const malformed_model: Record = .{
        .name = "x",
        .mode = .auto,
        .master_link = "/usr/bin/x",
        .slaves = &.{.{
            .name = "x.1",
            .link = "/usr/share/man/man1/x.1",
        }},
        .candidates = &.{.{
            .path = "/usr/lib/x",
            .priority = 1,
            .targets = &.{},
        }},
    };
    try testing.expectError(
        error.InvalidRecord,
        selectedLinks(
            testing.allocator,
            malformed_model,
            "/usr/lib/x",
        ),
    );
}

test "native_alternatives.test.selection matches ties manual preservation pruning and removal" {
    const testing = std.testing;
    const initial =
        "auto\n/usr/bin/demo\ndemo.1\n/usr/share/man/man1/demo.1\n\n" ++
        "/usr/lib/demo/b\n10\n/usr/share/man/man1/b.1\n\n";
    var parsed = try parse(testing.allocator, "demo", initial, .{});
    defer parsed.deinit();
    const tie_bytes =
        "auto\n/usr/bin/demo\n\n" ++
        "/usr/lib/demo/a\n10\n" ++
        "/usr/lib/demo/b\n10\n\n";
    var tie = try parse(testing.allocator, "demo", tie_bytes, .{});
    defer tie.deinit();
    try validateAutomaticSelection(
        tie.record,
        tie.record.candidates[1],
        &.{},
    );
    try validateAutomaticSelection(
        parsed.record,
        parsed.record.candidates[0],
        &.{parsed.record.candidates[0].path},
    );
    var equal = try mutate(testing.allocator, .{
        .name = "demo",
        .current = parsed.record,
        .selected = "/usr/lib/demo/b",
        .command = .{ .install = .{
            .master_link = "/usr/bin/demo",
            .path = "/usr/lib/demo/a",
            .priority = 10,
            .slaves = &.{.{
                .name = "demo.1",
                .link = "/usr/share/man/man1/demo.1",
                .target = "/usr/share/man/man1/a.1",
            }},
        } },
    });
    defer equal.deinit();
    try testing.expectEqualStrings("/usr/lib/demo/b", equal.selected.?);

    var higher = try mutate(testing.allocator, .{
        .name = "demo",
        .current = equal.record,
        .selected = equal.selected,
        .command = .{ .install = .{
            .master_link = "/usr/bin/demo",
            .path = "/usr/lib/demo/c",
            .priority = 20,
        } },
    });
    defer higher.deinit();
    try testing.expectEqualStrings("/usr/lib/demo/c", higher.selected.?);
    try testing.expectEqual(@as(usize, 1), higher.record.?.slaves.len);
    try testing.expectError(
        error.InvalidAlternativesSelection,
        validateAutomaticSelection(
            higher.record.?,
            higher.record.?.candidate("/usr/lib/demo/a").?,
            &.{},
        ),
    );
    try validateAutomaticSelection(
        higher.record.?,
        higher.record.?.candidate("/usr/lib/demo/a").?,
        &.{"/usr/lib/demo/a"},
    );

    var manual = try mutate(testing.allocator, .{
        .name = "demo",
        .current = higher.record,
        .selected = higher.selected,
        .command = .{ .set = "/usr/lib/demo/a" },
    });
    defer manual.deinit();
    var manual_higher = try mutate(testing.allocator, .{
        .name = "demo",
        .current = manual.record,
        .selected = manual.selected,
        .command = .{ .install = .{
            .master_link = "/usr/bin/demo",
            .path = "/usr/lib/demo/c",
            .priority = 30,
            .slaves = &.{.{
                .name = "demo.1",
                .link = "/usr/share/man/man1/demo.1",
                .target = "/usr/share/man/man1/c.1",
            }},
        } },
    });
    defer manual_higher.deinit();
    try testing.expectEqual(Mode.manual, manual_higher.record.?.mode);
    try testing.expectEqualStrings("/usr/lib/demo/a", manual_higher.selected.?);

    var automatic = try mutate(testing.allocator, .{
        .name = "demo",
        .current = manual_higher.record,
        .selected = manual_higher.selected,
        .command = .auto,
    });
    defer automatic.deinit();
    try testing.expectEqualStrings("/usr/lib/demo/c", automatic.selected.?);
    try testing.expectError(
        error.InvalidPath,
        mutate(testing.allocator, .{
            .name = "demo",
            .current = automatic.record,
            .selected = automatic.selected,
            .missing_master_targets = &.{"/usr/lib/demo/a"},
            .command = .{ .set = "/usr/lib/demo/a" },
        }),
    );

    var pruned = try mutate(testing.allocator, .{
        .name = "demo",
        .current = automatic.record,
        .selected = automatic.selected,
        .missing_master_targets = &.{"/usr/lib/demo/c"},
        .command = .auto,
    });
    defer pruned.deinit();
    try testing.expectEqual(@as(usize, 2), pruned.record.?.candidates.len);
    try testing.expectEqualStrings("/usr/lib/demo/a", pruned.selected.?);

    var removed = try mutate(testing.allocator, .{
        .name = "demo",
        .current = pruned.record,
        .selected = pruned.selected,
        .command = .{ .remove = "/usr/lib/demo/a" },
    });
    defer removed.deinit();
    try testing.expectEqualStrings("/usr/lib/demo/b", removed.selected.?);
}

test "native_alternatives.test.provider replacement removes only globally obsolete slaves" {
    const testing = std.testing;
    const initial =
        "auto\n/usr/bin/demo\none\n/usr/share/one\ntwo\n/usr/share/two\n\n" ++
        "/usr/lib/a\n10\n/usr/share/a-one\n/usr/share/a-two\n" ++
        "/usr/lib/b\n20\n/usr/share/b-one\n/usr/share/b-two\n\n";
    var parsed = try parse(testing.allocator, "demo", initial, .{});
    defer parsed.deinit();
    var replaced = try mutate(testing.allocator, .{
        .name = "demo",
        .current = parsed.record,
        .selected = "/usr/lib/b",
        .command = .{ .install = .{
            .master_link = "/usr/bin/demo",
            .path = "/usr/lib/b",
            .priority = 20,
            .slaves = &.{.{
                .name = "one",
                .link = "/usr/share/one",
                .target = "/usr/share/b-one-new",
            }},
        } },
    });
    defer replaced.deinit();
    try testing.expectEqual(@as(usize, 2), replaced.record.?.slaves.len);
    const provider = replaced.record.?.candidate("/usr/lib/b").?;
    try testing.expectEqualStrings("/usr/share/b-one-new", provider.targets[0]);
    try testing.expectEqualStrings("", provider.targets[1]);
    const links = try selectedLinks(
        testing.allocator,
        replaced.record.?,
        replaced.selected.?,
    );
    defer testing.allocator.free(links);
    try testing.expectEqual(@as(usize, 2), links.len);
}

test "native_alternatives.test.settlement journals database links replacement and removal together" {
    const testing = std.testing;
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    const before_bytes =
        "auto\n" ++
        "/usr/bin/demo\n" ++
        "demo.1\n" ++
        "/usr/share/man/man1/demo.1\n" ++
        "demo.help\n" ++
        "/usr/share/demo/help\n" ++
        "\n" ++
        "/usr/lib/demo/a\n" ++
        "10\n" ++
        "/usr/share/man/man1/demo-a.1\n" ++
        "/usr/share/demo/a.help\n" ++
        "\n";
    const after_bytes =
        "auto\n" ++
        "/usr/bin/demo\n" ++
        "demo.1\n" ++
        "/usr/share/man/man1/demo.1\n" ++
        "\n" ++
        "/usr/lib/demo/a\n" ++
        "10\n" ++
        "/usr/share/man/man1/demo-a.1\n" ++
        "\n";
    var before = try parse(testing.allocator, "demo", before_bytes, .{});
    defer before.deinit();
    var after = try parse(testing.allocator, "demo", after_bytes, .{});
    defer after.deinit();
    var replace = try settlement(
        testing.allocator,
        root,
        .{ .record = before.record, .selected = "/usr/lib/demo/a" },
        .{ .record = after.record, .selected = "/usr/lib/demo/a" },
        .{},
    );
    defer replace.deinit();
    try testing.expectEqual(@as(usize, 7), replace.intents.len);
    try testing.expectEqualStrings(
        "var/lib/dpkg/alternatives/demo",
        replace.intents[0].path(),
    );
    try testing.expectEqualStrings(
        "usr/share/demo/help",
        replace.intents[5].path(),
    );
    try testing.expectEqualStrings(
        "etc/alternatives/demo.help",
        replace.intents[6].path(),
    );

    var removal = try settlement(
        testing.allocator,
        root,
        .{ .record = before.record, .selected = "/usr/lib/demo/a" },
        null,
        .{},
    );
    defer removal.deinit();
    try testing.expectEqual(@as(usize, 7), removal.intents.len);
    try testing.expectEqualStrings(
        "var/lib/dpkg/alternatives/demo",
        removal.intents[6].path(),
    );
}

test "native_alternatives.test.script authority admits only literal bounded commands" {
    const testing = std.testing;
    const script =
        "#!/bin/sh\n" ++
        "case \"$1\" in\n" ++
        " configure) /usr/bin/update-alternatives --install /usr/bin/demo demo /usr/lib/demo 20 \\\n" ++
        "   --slave /usr/share/man/man1/demo.1 demo.1 /usr/share/man/man1/demo-real.1 ;;\n" ++
        " remove) /usr/bin/update-alternatives --remove demo /usr/lib/demo ;;\n" ++
        "esac\n";
    var authority = try discoverScriptAuthority(
        testing.allocator,
        script,
        .{},
    );
    defer authority.deinit();
    try testing.expectEqual(@as(usize, 1), authority.groups.len);
    try testing.expectEqualStrings("demo", authority.groups[0].name);
    try testing.expectEqualStrings(
        "/usr/bin/demo",
        authority.groups[0].topology.?.master_link,
    );
    try testing.expectEqual(@as(usize, 1), authority.groups[0].topology.?.slaves.len);
    try testing.expect(authority.paths.len >= 6);

    const rejected = [_][]const u8{
        "#!/bin/sh\nupdate-alternatives --install \"$link\" demo /usr/lib/demo 1\n",
        "#!/bin/sh\ncmd=update-alternatives\n$cmd --auto demo\n",
        "#!/bin/sh\nupdate-alternatives --display demo\n",
        "#!/bin/sh\nupdate-alternatives --install /usr/bin/../escape demo /usr/lib/demo 1\n",
        "#!/bin/sh\nupdate-alternatives --set demo /usr/lib/$(name)\n",
        "#!/bin/sh\n# update-alternatives --auto demo\n",
        "#!/bin/sh\necho update-alternatives --auto demo\n",
        "#!/bin/sh\nupdate-alternatives --auto demo ignored\n",
        "#!/bin/sh\nupdate-alternatives --auto demo; true\n",
        "#!/bin/sh\nupdate-alternatives --auto demo &&\ntrue\n",
        "#!/bin/sh\nupdate-alternatives --auto demo ||\ntrue\n",
        "#!/bin/sh\nif update-alternatives --auto demo\n",
    };
    for (rejected) |bytes| try testing.expectError(
        error.InvalidAlternativesScript,
        discoverScriptAuthority(testing.allocator, bytes, .{}),
    );
}

test "native_alternatives.test.snapshot less preinst pins one quiet removal" {
    const testing = std.testing;
    const script = @embedFile(
        "fixtures/ubuntu-stonking-less-668-1build1.preinst",
    );
    try testing.expect(matchesSnapshotLessPreinst(script));
    var authority = try discoverScriptAuthority(testing.allocator, script, .{});
    defer authority.deinit();
    try testing.expectEqual(@as(usize, 1), authority.commands.len);
    try testing.expectEqualStrings("pager", authority.commands[0].name);
    switch (authority.commands[0].command) {
        .remove => |path| try testing.expectEqualStrings("/bin/less", path),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), authority.groups.len);
    try testing.expectEqualStrings("pager", authority.groups[0].name);
    try testing.expect(authority.groups[0].topology == null);
    try testing.expectEqual(@as(usize, 1), authority.paths.len);
    try testing.expectEqualStrings("bin/less", authority.paths[0]);
    try testing.expectEqual(@as(usize, 1), authority.immutable_targets.len);
    try testing.expectEqualStrings(
        "/bin/less",
        authority.immutable_targets[0],
    );

    const rejected = [_][]const u8{
        "update-alternatives --quiet --remove pager /bin/less\n",
        "#!/bin/sh\nupdate-alternatives --quiet --auto pager\n",
        "#!/bin/sh\nupdate-alternatives --quiet --remove editor /bin/less\n",
        "#!/bin/sh\nupdate-alternatives --quiet --remove pager /usr/bin/less\n",
        "#!/bin/sh\nupdate-alternatives --quiet --remove pager /bin/less; true\n",
        "#!/bin/sh\nupdate-alternatives --quiet --remove pager /bin/less\nexit 0\n",
    };
    for (rejected) |bytes| {
        try testing.expect(!matchesSnapshotLessPreinst(bytes));
        try testing.expectError(
            error.InvalidAlternativesScript,
            discoverScriptAuthority(testing.allocator, bytes, .{}),
        );
    }
}

test "native_alternatives.test.snapshot less postinst pins one quiet install" {
    const testing = std.testing;
    const script = @embedFile(
        "fixtures/ubuntu-stonking-less-668-1build1.postinst",
    );
    try testing.expect(matchesSnapshotLessPostinst(script));
    var authority = try discoverScriptAuthority(testing.allocator, script, .{});
    defer authority.deinit();
    try testing.expectEqual(@as(usize, 1), authority.commands.len);
    try testing.expectEqualStrings("pager", authority.commands[0].name);
    switch (authority.commands[0].command) {
        .install => |install| {
            try testing.expectEqualStrings("/usr/bin/pager", install.master_link);
            try testing.expectEqualStrings("/usr/bin/less", install.path);
            try testing.expectEqual(@as(i32, 77), install.priority);
            try testing.expectEqual(@as(usize, 1), install.slaves.len);
            try testing.expectEqualStrings(
                "/usr/share/man/man1/pager.1.gz",
                install.slaves[0].link,
            );
            try testing.expectEqualStrings("pager.1.gz", install.slaves[0].name);
            try testing.expectEqualStrings(
                "/usr/share/man/man1/less.1.gz",
                install.slaves[0].target,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), authority.groups.len);
    try testing.expectEqualStrings("pager", authority.groups[0].name);
    try testing.expectEqualStrings(
        "/usr/bin/pager",
        authority.groups[0].topology.?.master_link,
    );
    try testing.expectEqual(@as(usize, 1), authority.groups[0].topology.?.slaves.len);
    try testing.expect(authority.paths.len >= 6);
    try testing.expectEqual(@as(usize, 2), authority.immutable_targets.len);

    const rejected = [_][]const u8{
        "#!/bin/sh\nupdate-alternatives --quiet --install /usr/bin/pager pager /usr/bin/less 77 --slave /usr/share/man/man1/pager.1.gz pager.1.gz /usr/share/man/man1/less.1.gz\n",
        "#!/bin/sh\nupdate-alternatives --quiet --install /usr/bin/pager pager /usr/bin/less 77\n",
        "#!/bin/sh\nupdate-alternatives --quiet --auto pager\n",
        "#!/bin/sh\nupdate-alternatives --quiet --remove pager /bin/less\n",
    };
    for (rejected) |bytes| {
        try testing.expect(!matchesSnapshotLessPostinst(bytes));
        try testing.expectError(
            error.InvalidAlternativesScript,
            discoverScriptAuthority(testing.allocator, bytes, .{}),
        );
    }
    var changed = try testing.allocator.dupe(u8, script);
    defer testing.allocator.free(changed);
    changed[changed.len - 1] = '1';
    try testing.expect(!matchesSnapshotLessPostinst(changed));
    try testing.expectError(
        error.InvalidAlternativesScript,
        discoverScriptAuthority(testing.allocator, changed, .{}),
    );
}

test "native_alternatives.test.snapshot less postinst registers only the pinned pager provider" {
    const testing = std.testing;
    var script = try discoverScriptAuthority(
        testing.allocator,
        @embedFile("fixtures/ubuntu-stonking-less-668-1build1.postinst"),
        .{},
    );
    defer script.deinit();
    const before: Snapshot = .{
        .groups = &.{},
        .paths = &.{},
        .digest = snapshotDigest(&.{}),
        .relationship_count = 0,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    for ([_]struct { priority: []const u8, allowed: bool }{
        .{ .priority = "77", .allowed = true },
        .{ .priority = "78", .allowed = false },
    }) |case| {
        const record = try std.fmt.allocPrint(
            testing.allocator,
            "auto\n/usr/bin/pager\npager.1.gz\n/usr/share/man/man1/pager.1.gz\n\n/usr/bin/less\n{s}\n/usr/share/man/man1/less.1.gz\n\n",
            .{case.priority},
        );
        defer testing.allocator.free(record);
        var parsed = try parse(testing.allocator, "pager", record, .{});
        defer parsed.deinit();
        var pager: GroupState = .{
            .name = "pager",
            .record = parsed.record,
            .record_fact = .{
                .path = "var/lib/dpkg/alternatives/pager",
                .kind = .regular,
            },
            .selected = "/usr/bin/less",
            .links = &.{},
            .missing_master_targets = &.{},
            .facts = &.{},
            .digest = undefined,
        };
        pager.digest = groupStateDigest(pager);
        const after: Snapshot = .{
            .groups = &.{pager},
            .paths = &.{},
            .digest = snapshotDigest(&.{pager}),
            .relationship_count = 2,
            .parsed_records = &.{},
            .arena = undefined,
            .backing_allocator = testing.allocator,
        };
        if (case.allowed) {
            try validateScriptTransition(
                testing.allocator,
                before,
                after,
                script,
                .{ .groups = script.groups },
            );
        } else {
            try testing.expectError(
                error.AlternativesStateChanged,
                validateScriptTransition(
                    testing.allocator,
                    before,
                    after,
                    script,
                    .{ .groups = script.groups },
                ),
            );
        }
    }
}

test "native_alternatives.test.snapshot bash postinst pins one masked builtins install" {
    const testing = std.testing;
    const bytes = @embedFile(
        "fixtures/ubuntu-stonking-bash-5.3-3ubuntu1.postinst",
    );
    try testing.expect(matchesSnapshotBashPostinst(bytes));
    var script = try discoverScriptAuthority(testing.allocator, bytes, .{});
    defer script.deinit();
    try testing.expectEqual(@as(usize, 1), script.commands.len);
    try testing.expectEqualStrings("builtins.7.gz", script.commands[0].name);
    switch (script.commands[0].command) {
        .install => |install| {
            try testing.expectEqualStrings(
                "/usr/share/man/man7/builtins.7.gz",
                install.master_link,
            );
            try testing.expectEqualStrings(
                "/usr/share/man/man7/bash-builtins.7.gz",
                install.path,
            );
            try testing.expectEqual(@as(i32, 10), install.priority);
            try testing.expectEqual(@as(usize, 0), install.slaves.len);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), script.groups.len);
    try testing.expectEqualStrings("builtins.7.gz", script.groups[0].name);
    try testing.expectEqualStrings(
        "/usr/share/man/man7/builtins.7.gz",
        script.groups[0].topology.?.master_link,
    );
    try testing.expectEqual(@as(usize, 1), script.immutable_targets.len);
    try testing.expectEqualStrings(
        "/usr/share/man/man7/bash-builtins.7.gz",
        script.immutable_targets[0],
    );

    const rejected = [_][]const u8{
        "#!/bin/sh\nupdate-alternatives --install /usr/share/man/man7/builtins.7.gz builtins.7.gz /usr/share/man/man7/bash-builtins.7.gz 10 || true\n",
        "#!/bin/sh\nupdate-alternatives --install /usr/share/man/man7/builtins.7.gz builtins.7.gz /usr/share/man/man7/bash-builtins.7.gz 10 || false\n",
        "#!/bin/sh\nupdate-alternatives --install /usr/share/man/man7/builtins.7.gz builtins.7.gz /usr/share/man/man7/bash-builtins.7.gz 11 || true\n",
        "#!/bin/sh\nupdate-alternatives --install /usr/share/man/man7/builtins.7.gz builtins.7.gz /usr/share/man/man7/bash-builtins.7.gz 10; true\n",
        "#!/bin/sh\nupdate-alternatives --auto builtins.7.gz || true\n",
    };
    for (rejected) |wrong| try testing.expectError(
        error.InvalidAlternativesScript,
        discoverScriptAuthority(testing.allocator, wrong, .{}),
    );
    var changed = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(changed);
    changed[changed.len - 1] = '1';
    try testing.expect(!matchesSnapshotBashPostinst(changed));
    try testing.expectError(
        error.InvalidAlternativesScript,
        discoverScriptAuthority(testing.allocator, changed, .{}),
    );
}

test "native_alternatives.test.snapshot bash postinst bounds masked tool failure and success" {
    const testing = std.testing;
    var script = try discoverScriptAuthority(
        testing.allocator,
        @embedFile("fixtures/ubuntu-stonking-bash-5.3-3ubuntu1.postinst"),
        .{},
    );
    defer script.deinit();
    const before: Snapshot = .{
        .groups = &.{},
        .paths = &.{},
        .digest = snapshotDigest(&.{}),
        .relationship_count = 0,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    try validateScriptTransition(
        testing.allocator,
        before,
        before,
        script,
        .{ .groups = script.groups },
    );
    for ([_]struct { priority: []const u8, allowed: bool }{
        .{ .priority = "10", .allowed = true },
        .{ .priority = "11", .allowed = false },
    }) |case| {
        const record = try std.fmt.allocPrint(
            testing.allocator,
            "auto\n/usr/share/man/man7/builtins.7.gz\n\n/usr/share/man/man7/bash-builtins.7.gz\n{s}\n\n",
            .{case.priority},
        );
        defer testing.allocator.free(record);
        var parsed = try parse(testing.allocator, "builtins.7.gz", record, .{});
        defer parsed.deinit();
        var group: GroupState = .{
            .name = "builtins.7.gz",
            .record = parsed.record,
            .record_fact = .{
                .path = "var/lib/dpkg/alternatives/builtins.7.gz",
                .kind = .regular,
            },
            .selected = "/usr/share/man/man7/bash-builtins.7.gz",
            .links = &.{},
            .missing_master_targets = &.{},
            .facts = &.{},
            .digest = undefined,
        };
        group.digest = groupStateDigest(group);
        const after: Snapshot = .{
            .groups = &.{group},
            .paths = &.{},
            .digest = snapshotDigest(&.{group}),
            .relationship_count = 1,
            .parsed_records = &.{},
            .arena = undefined,
            .backing_allocator = testing.allocator,
        };
        if (case.allowed) {
            try validateScriptTransition(
                testing.allocator,
                before,
                after,
                script,
                .{ .groups = script.groups },
            );
        } else {
            try testing.expectError(
                error.AlternativesStateChanged,
                validateScriptTransition(
                    testing.allocator,
                    before,
                    after,
                    script,
                    .{ .groups = script.groups },
                ),
            );
        }
    }
}

test "native_alternatives.test.signed netcat install matches pinned sorted nc record" {
    const testing = std.testing;
    const bytes = @embedFile(
        "fixtures/ubuntu-stonking-netcat-openbsd-1.238-1.postinst",
    );
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    try testing.expectEqualSlices(
        u8,
        &digestLiteral(
            "81abc862db99e322e5d6cda436769bc21b9394ce287ea35d057761b6313cb6ef",
        ),
        &sha256,
    );
    var script = try discoverScriptAuthority(testing.allocator, bytes, .{});
    defer script.deinit();
    try testing.expectEqual(@as(usize, 1), script.commands.len);
    try testing.expectEqualStrings("nc", script.commands[0].name);
    switch (script.commands[0].command) {
        .install => |install| {
            try testing.expectEqualStrings("/bin/nc", install.master_link);
            try testing.expectEqualStrings("/bin/nc.openbsd", install.path);
            try testing.expectEqual(@as(i32, 50), install.priority);
            try testing.expectEqual(@as(usize, 3), install.slaves.len);
            try testing.expectEqualStrings("netcat", install.slaves[0].name);
            try testing.expectEqualStrings("nc.1.gz", install.slaves[1].name);
            try testing.expectEqualStrings("netcat.1.gz", install.slaves[2].name);
        },
        else => return error.TestUnexpectedResult,
    }
    const pinned =
        "auto\n/bin/nc\n" ++
        "nc.1.gz\n/usr/share/man/man1/nc.1.gz\n" ++
        "netcat\n/bin/netcat\n" ++
        "netcat.1.gz\n/usr/share/man/man1/netcat.1.gz\n\n" ++
        "/bin/nc.openbsd\n50\n" ++
        "/usr/share/man/man1/nc_openbsd.1.gz\n" ++
        "/bin/nc.openbsd\n" ++
        "/usr/share/man/man1/nc_openbsd.1.gz\n\n";
    var installed = try mutate(testing.allocator, .{
        .name = script.commands[0].name,
        .current = null,
        .selected = null,
        .command = script.commands[0].command,
    });
    defer installed.deinit();
    const actual = try canonicalBytes(testing.allocator, installed.record.?);
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings(pinned, actual);
    try testing.expectEqualStrings(
        "/bin/nc.openbsd",
        installed.selected.?,
    );
    const before: Snapshot = .{
        .groups = &.{},
        .paths = &.{},
        .digest = snapshotDigest(&.{}),
        .relationship_count = 0,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    const variants = [_]struct { record: []const u8, allowed: bool }{
        .{ .record = pinned, .allowed = true },
        .{
            .record = "auto\n/bin/nc\n" ++
                "nc.1.gz\n/usr/share/man/man1/nc.1.gz\n" ++
                "netcat\n/bin/netcat\n" ++
                "netcat.1.gz\n/usr/share/man/man1/netcat.1.gz\n\n" ++
                "/bin/nc.openbsd\n51\n" ++
                "/usr/share/man/man1/nc_openbsd.1.gz\n" ++
                "/bin/nc.openbsd\n" ++
                "/usr/share/man/man1/nc_openbsd.1.gz\n\n",
            .allowed = false,
        },
        .{
            .record = "auto\n/bin/nc\n" ++
                "netcat\n/bin/netcat\n" ++
                "nc.1.gz\n/usr/share/man/man1/nc.1.gz\n" ++
                "netcat.1.gz\n/usr/share/man/man1/netcat.1.gz\n\n" ++
                "/bin/nc.openbsd\n50\n" ++
                "/bin/nc.openbsd\n" ++
                "/usr/share/man/man1/nc_openbsd.1.gz\n" ++
                "/usr/share/man/man1/nc_openbsd.1.gz\n\n",
            .allowed = false,
        },
    };
    for (variants) |case| {
        var parsed = try parse(testing.allocator, "nc", case.record, .{});
        defer parsed.deinit();
        var group: GroupState = .{
            .name = "nc",
            .record = parsed.record,
            .record_fact = .{
                .path = "var/lib/dpkg/alternatives/nc",
                .kind = .regular,
            },
            .selected = "/bin/nc.openbsd",
            .links = &.{},
            .missing_master_targets = &.{},
            .facts = &.{},
            .digest = undefined,
        };
        group.digest = groupStateDigest(group);
        const after: Snapshot = .{
            .groups = &.{group},
            .paths = &.{},
            .digest = snapshotDigest(&.{group}),
            .relationship_count = 4,
            .parsed_records = &.{},
            .arena = undefined,
            .backing_allocator = testing.allocator,
        };
        if (case.allowed) {
            try validateScriptTransition(
                testing.allocator,
                before,
                after,
                script,
                .{ .groups = script.groups },
            );
        } else {
            try testing.expectError(
                error.AlternativesStateChanged,
                validateScriptTransition(
                    testing.allocator,
                    before,
                    after,
                    script,
                    .{ .groups = script.groups },
                ),
            );
        }
    }
}

test "native_alternatives.test.signed procps only admits absent providers and immutable groups" {
    const testing = std.testing;
    const bytes = @embedFile(
        "fixtures/ubuntu-stonking-procps-4.0.6-3ubuntu1.postinst",
    );
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    try testing.expectEqualSlices(
        u8,
        &digestLiteral(
            "7c2ba424ad233bd238474b9d6e565a719fbd6902fd75f617bc3e6e915084c9d3",
        ),
        &sha256,
    );
    try testing.expect(matchesSnapshotProcpsPostinst(bytes));
    var script = try discoverScriptAuthority(testing.allocator, bytes, .{});
    defer script.deinit();
    try testing.expect(script.require_targets_absent);
    try testing.expectEqual(@as(usize, 0), script.groups.len);
    try testing.expectEqual(@as(usize, 0), script.commands.len);
    try testing.expectEqual(@as(usize, 0), script.paths.len);
    try testing.expectEqual(@as(usize, 4), script.immutable_targets.len);
    const targets = [_][]const u8{
        "/usr/bin/uptime.procps",
        "/usr/bin/vmstat.procps",
        "/usr/bin/w.procps",
        "/bin/ps.procps",
    };
    for (script.immutable_targets, &targets) |actual, expected|
        try testing.expectEqualStrings(expected, actual);

    const absent = [_]EntryFact{.{
        .path = "usr/bin/uptime.procps",
        .kind = .absent,
    }};
    try requireNewAbsentTarget(&absent, 0);
    try testing.expectError(
        error.InvalidAlternativesScriptAuthority,
        requireNewAbsentTarget(&.{}, 0),
    );
    for ([_]EntryKind{ .regular, .symlink }) |kind| {
        var occupied = absent;
        occupied[0].kind = kind;
        try testing.expectError(
            error.InvalidAlternativesScriptAuthority,
            requireNewAbsentTarget(&occupied, 0),
        );
    }
    try testing.expectError(
        error.InvalidAlternativesScriptAuthority,
        requireNewAbsentTarget(&.{ absent[0], absent[0] }, 0),
    );
    const changed = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(changed);
    changed[0] = ' ';
    try testing.expect(!matchesSnapshotProcpsPostinst(changed));
    try testing.expectError(
        error.InvalidAlternativesScript,
        discoverScriptAuthority(testing.allocator, changed, .{}),
    );
    try testing.expectError(
        error.InvalidAlternativesScript,
        discoverScriptAuthority(
            testing.allocator,
            bytes,
            .{ .max_path_bytes = 12 },
        ),
    );

    var parsed = try parse(
        testing.allocator,
        "unexpected",
        "auto\n/usr/bin/unexpected\n\n/usr/bin/provider\n10\n\n",
        .{},
    );
    defer parsed.deinit();
    var group: GroupState = .{
        .name = "unexpected",
        .record = parsed.record,
        .record_fact = .{
            .path = "var/lib/dpkg/alternatives/unexpected",
            .kind = .regular,
        },
        .selected = "/usr/bin/provider",
        .links = &.{},
        .missing_master_targets = &.{},
        .facts = &.{},
        .digest = undefined,
    };
    group.digest = groupStateDigest(group);
    const before: Snapshot = .{
        .groups = &.{},
        .paths = &.{},
        .digest = snapshotDigest(&.{}),
        .relationship_count = 0,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    const after: Snapshot = .{
        .groups = &.{group},
        .paths = &.{},
        .digest = snapshotDigest(&.{group}),
        .relationship_count = 1,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    try testing.expectError(
        error.UnsupportedAlternativesGroup,
        validateScriptTransition(
            testing.allocator,
            before,
            after,
            script,
            .{ .groups = &.{} },
        ),
    );
    try validateScriptTransition(
        testing.allocator,
        after,
        after,
        script,
        .{ .groups = &.{.{ .name = "unexpected", .mutable = false }} },
    );
    var changed_group = group;
    changed_group.digest[0] ^= 1;
    const changed_after: Snapshot = .{
        .groups = &.{changed_group},
        .paths = &.{},
        .digest = snapshotDigest(&.{changed_group}),
        .relationship_count = 1,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    try testing.expectError(
        error.AlternativesStateChanged,
        validateScriptTransition(
            testing.allocator,
            after,
            changed_after,
            script,
            .{ .groups = &.{.{ .name = "unexpected", .mutable = false }} },
        ),
    );
}

test "native_alternatives.test.sorted new slave preserves existing provider targets" {
    const testing = std.testing;
    var initial = try parse(
        testing.allocator,
        "sort-probe",
        "auto\n/usr/bin/sort-probe\n" ++
            "a-man\n/usr/share/man/man1/a.1.gz\n" ++
            "z-man\n/usr/share/man/man1/z.1.gz\n\n" ++
            "/usr/lib/sort-probe-a\n10\n" ++
            "/usr/lib/a-a\n/usr/lib/z-a\n\n",
        .{},
    );
    defer initial.deinit();
    var updated = try mutate(testing.allocator, .{
        .name = "sort-probe",
        .current = initial.record,
        .selected = "/usr/lib/sort-probe-a",
        .command = .{ .install = .{
            .master_link = "/usr/bin/sort-probe",
            .path = "/usr/lib/sort-probe-b",
            .priority = 20,
            .slaves = &.{
                .{
                    .name = "b-man",
                    .link = "/usr/share/man/man1/b.1.gz",
                    .target = "/usr/lib/b-b",
                },
                .{
                    .name = "a-man",
                    .link = "/usr/share/man/man1/a.1.gz",
                    .target = "/usr/lib/a-b",
                },
            },
        } },
    });
    defer updated.deinit();
    try testing.expectEqualStrings("/usr/lib/sort-probe-b", updated.selected.?);
    const actual = try canonicalBytes(testing.allocator, updated.record.?);
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings(
        "auto\n/usr/bin/sort-probe\n" ++
            "a-man\n/usr/share/man/man1/a.1.gz\n" ++
            "b-man\n/usr/share/man/man1/b.1.gz\n" ++
            "z-man\n/usr/share/man/man1/z.1.gz\n\n" ++
            "/usr/lib/sort-probe-a\n10\n" ++
            "/usr/lib/a-a\n\n/usr/lib/z-a\n" ++
            "/usr/lib/sort-probe-b\n20\n" ++
            "/usr/lib/a-b\n/usr/lib/b-b\n\n\n",
        actual,
    );
    try testing.expectError(
        error.InvalidSlave,
        mutate(testing.allocator, .{
            .name = "sort-probe",
            .current = initial.record,
            .selected = "/usr/lib/sort-probe-a",
            .command = .{ .install = .{
                .master_link = "/usr/bin/sort-probe",
                .path = "/usr/lib/sort-probe-b",
                .priority = 20,
                .slaves = &.{.{
                    .name = "a-man",
                    .link = "/usr/share/man/man1/other.1.gz",
                    .target = "/usr/lib/a-b",
                }},
            } },
        }),
    );
    try testing.expectError(
        error.DuplicateSlave,
        mutate(testing.allocator, .{
            .name = "sort-probe",
            .current = initial.record,
            .selected = "/usr/lib/sort-probe-a",
            .command = .{ .install = .{
                .master_link = "/usr/bin/sort-probe",
                .path = "/usr/lib/sort-probe-b",
                .priority = 20,
                .slaves = &.{
                    .{
                        .name = "a-man",
                        .link = "/usr/share/man/man1/a.1.gz",
                        .target = "/usr/lib/a-b",
                    },
                    .{
                        .name = "a-man",
                        .link = "/usr/share/man/man1/other.1.gz",
                        .target = "/usr/lib/a-b",
                    },
                },
            } },
        }),
    );
}

test "native_alternatives.test.snapshot less install cannot remove pager" {
    const testing = std.testing;
    var script = try discoverScriptAuthority(
        testing.allocator,
        @embedFile("fixtures/ubuntu-stonking-less-668-1build1.preinst"),
        .{},
    );
    defer script.deinit();
    const candidates = [_]Candidate{.{
        .path = "/bin/less",
        .priority = 50,
        .targets = &.{},
    }};
    var pager: GroupState = .{
        .name = "pager",
        .record = .{
            .name = "pager",
            .mode = .auto,
            .master_link = "/usr/bin/pager",
            .slaves = &.{},
            .candidates = &candidates,
        },
        .record_fact = .{
            .path = "var/lib/dpkg/alternatives/pager",
            .kind = .regular,
        },
        .selected = "/bin/less",
        .links = &.{},
        .missing_master_targets = &.{},
        .facts = &.{},
        .digest = undefined,
    };
    pager.digest = groupStateDigest(pager);
    const before: Snapshot = .{
        .groups = &.{pager},
        .paths = &.{},
        .digest = snapshotDigest(&.{pager}),
        .relationship_count = 1,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    const after: Snapshot = .{
        .groups = &.{},
        .paths = &.{},
        .digest = snapshotDigest(&.{}),
        .relationship_count = 0,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    const frozen: Authority = .{ .groups = &.{.{
        .name = "pager",
        .allow_absent = true,
        .mutable = false,
    }} };
    try validateScriptTransition(
        testing.allocator,
        before,
        before,
        script,
        frozen,
    );
    try testing.expectError(
        error.AlternativesStateChanged,
        validateScriptTransition(
            testing.allocator,
            before,
            after,
            script,
            frozen,
        ),
    );
    try validateScriptTransition(
        testing.allocator,
        before,
        after,
        script,
        .{ .groups = script.groups },
    );
}

test "native_alternatives.test.fact identity binds metadata content and timestamps" {
    const testing = std.testing;
    const digest: [32]u8 = @splat(0xaa);
    const baseline: EntryFact = .{
        .path = "usr/lib/demo",
        .kind = .regular,
        .mode = 0o755,
        .uid = 0,
        .gid = 0,
        .device = 4,
        .inode = 8,
        .link_count = 1,
        .size = 12,
        .modified_nanoseconds = 20,
        .change_nanoseconds = 21,
        .sha256 = digest,
    };
    try testing.expect(entryFactEqual(baseline, baseline));
    var changed = baseline;
    changed.mode = 0o700;
    try testing.expect(!entryFactEqual(baseline, changed));
    try testing.expect(!std.mem.eql(
        u8,
        &immutableDigest(&.{baseline}),
        &immutableDigest(&.{changed}),
    ));
    changed = baseline;
    changed.change_nanoseconds += 1;
    try testing.expect(!entryFactEqual(baseline, changed));
}

test "native_alternatives.test.script transition rejects direct record forgery" {
    const testing = std.testing;
    var script = try discoverScriptAuthority(
        testing.allocator,
        "#!/bin/sh\n/usr/bin/update-alternatives --install /usr/bin/demo demo /usr/lib/demo 10\n",
        .{},
    );
    defer script.deinit();
    const forged_bytes =
        "auto\n/usr/bin/demo\n\n/usr/lib/demo\n99\n\n";
    var forged = try parse(
        testing.allocator,
        "demo",
        forged_bytes,
        .{},
    );
    defer forged.deinit();
    var group: GroupState = .{
        .name = "demo",
        .record = forged.record,
        .record_fact = .{
            .path = "var/lib/dpkg/alternatives/demo",
            .kind = .regular,
        },
        .selected = "/usr/lib/demo",
        .links = &.{},
        .missing_master_targets = &.{},
        .facts = &.{},
        .digest = undefined,
    };
    group.digest = groupStateDigest(group);
    const before: Snapshot = .{
        .groups = &.{},
        .paths = &.{},
        .digest = snapshotDigest(&.{}),
        .relationship_count = 0,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    const after: Snapshot = .{
        .groups = &.{group},
        .paths = &.{},
        .digest = snapshotDigest(&.{group}),
        .relationship_count = 1,
        .parsed_records = &.{},
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    try testing.expectError(
        error.AlternativesStateChanged,
        validateScriptTransition(
            testing.allocator,
            before,
            after,
            script,
            .{ .groups = script.groups },
        ),
    );
}

test "native_alternatives.test.link target resolution rejects traversal" {
    const testing = std.testing;
    const resolved = try resolvedLinkTarget(
        testing.allocator,
        "usr/lib/demo/provider",
        "../real",
    );
    defer testing.allocator.free(resolved);
    try testing.expectEqualStrings("usr/lib/real", resolved);
    try testing.expectError(
        error.AlternativesTraversal,
        resolvedLinkTarget(testing.allocator, "provider", "../../escape"),
    );
}

//! Observed healthy package-database authority, never repository/archive authority.
const std = @import("std");
const baseline = @import("installed_baseline.zig");
const dpkg = @import("dpkg_status.zig");
const root_fs = @import("root_fs.zig");

pub const schema_id = "https://debz.dev/schema/healthy-installed-prestate-v1";
pub const Evidence = struct {
    schema: []const u8 = schema_id,
    version: u32 = 1,
    authority: enum { healthy_installed_prestate } = .healthy_installed_prestate,
    observed: baseline.Evidence,
};

pub const Verified = opaque {
    fn data(self: *const Verified) *const Data {
        return @ptrCast(@alignCast(self));
    }

    pub fn evidence(self: *const Verified) Evidence {
        return .{ .observed = self.data().baseline.evidence() };
    }

    /// Borrowed by the solver; only this owning healthy proof may deinitialize it.
    pub fn baselineProof(self: *const Verified) *baseline.Verified {
        return self.data().baseline;
    }

    pub fn requireOutputOutsideDatabase(self: *const Verified, directory: root_fs.Root) !void {
        try self.data().baseline.requireOutputOutsideDatabase(directory);
    }

    pub fn deinit(self: *Verified) void {
        const value: *Data = @ptrCast(@alignCast(self));
        value.baseline.deinit();
        value.allocator.destroy(value);
    }
};

const Data = struct { allocator: std.mem.Allocator, baseline: *baseline.Verified };

fn own(allocator: std.mem.Allocator, verified: *baseline.Verified) !*Verified {
    errdefer verified.deinit();
    const data = try allocator.create(Data);
    data.* = .{ .allocator = allocator, .baseline = verified };
    return @ptrCast(data);
}

pub fn requireHealthy(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var parsed = switch (try dpkg.parseBorrowed(allocator, bytes, .{})) {
        .database => |value| value,
        .diagnostic => return error.InvalidInstalledPrestate,
    };
    defer parsed.deinit();
    for (parsed.packages) |package| {
        if (package.status.error_state != .ok) return error.InstalledPrestateRecoveryRequired;
        if (package.status.isFullyInstalled()) {
            if (package.status.want != .install and package.status.want != .hold)
                return error.InstalledPrestateRecoveryRequired;
        } else if (package.status.current != .config_files or
            (package.status.want != .deinstall and package.status.want != .purge))
            return error.InstalledPrestateRecoveryRequired;
    }
    for (parsed.document.paragraphs) |paragraph| {
        for (paragraph.fields) |field| {
            if ((std.ascii.eqlIgnoreCase(field.name, "Triggers-Pending") or
                std.ascii.eqlIgnoreCase(field.name, "Triggers-Awaited")))
                for (field.value_lines) |line| {
                    if (std.mem.trim(u8, line.text, " \t\r\n").len != 0)
                        return error.InstalledPrestateRecoveryRequired;
                };
        }
    }
}

pub fn capture(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    architecture: []const u8,
    status: []const u8,
    packages: []const baseline.Package,
) !*Verified {
    try requireHealthy(allocator, status);
    return own(allocator, try baseline.captureHealthy(allocator, io, root, architecture, status, packages));
}

pub fn verify(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    architecture: []const u8,
    status: []const u8,
    evidence: Evidence,
) !*Verified {
    if (!std.mem.eql(u8, evidence.schema, schema_id) or evidence.version != 1)
        return error.UnsupportedInstalledPrestate;
    try requireHealthy(allocator, status);
    return own(allocator, try baseline.verifyHealthy(allocator, io, root, architecture, status, evidence.observed));
}

test "healthy_installed_prestate.test rejects incomplete and trigger-bearing unrelated state" {
    const allocator = std.testing.allocator;
    const healthy = "Package: private\nStatus: hold ok installed\nArchitecture: amd64\nVersion: 1.0\n\n";
    try requireHealthy(allocator, healthy);
    for ([_][]const u8{
        "Package: private\nStatus: install reinstreq installed\nArchitecture: amd64\nVersion: 1.0\n\n",
        "Package: private\nStatus: install ok unpacked\nArchitecture: amd64\nVersion: 1.0\n\n",
        "Package: private\nStatus: deinstall ok installed\nArchitecture: amd64\nVersion: 1.0\n\n",
        healthy ++ "Package: other\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2\nTriggers-Pending: ldconfig\n\n",
    }) |bytes| try std.testing.expectError(error.InstalledPrestateRecoveryRequired, requireHealthy(allocator, bytes));
}

test "healthy_installed_prestate.test healthy capture preserves historical identity without inheriting trigger work" {
    const allocator = std.testing.allocator;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "var/lib/dpkg/triggers");
    const status = "Package: private\nStatus: hold ok installed\nArchitecture: amd64\nVersion: 1.0\n\n";
    const packages = [_]baseline.Package{.{ .name = "private", .version = "1.0", .architecture = "amd64", .selection = .hold }};
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "var/lib/dpkg/status", .data = status });
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "var/lib/dpkg/triggers/Unincorp", .data = "ldconfig libc-bin\n" });
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_length = try directory.dir.realPath(std.testing.io, &path_buffer);
    const path = path_buffer[0..path_length];
    {
        const historical = try baseline.capture(allocator, std.testing.io, path, "amd64", status, &packages);
        defer historical.deinit();
        try std.testing.expectError(error.InstalledPrestateRecoveryRequired, capture(allocator, std.testing.io, path, "amd64", status, &packages));
        try std.testing.expectError(error.InstalledPrestateRecoveryRequired, verify(allocator, std.testing.io, path, "amd64", status, .{ .observed = historical.evidence() }));
        const original = try baseline.verify(allocator, std.testing.io, path, "amd64", status, historical.evidence());
        defer original.deinit();
    }
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "var/lib/dpkg/triggers/Unincorp", .data = "" });
    const historical = try baseline.capture(allocator, std.testing.io, path, "amd64", status, &packages);
    defer historical.deinit();
    const healthy = try capture(allocator, std.testing.io, path, "amd64", status, &packages);
    defer healthy.deinit();
    try std.testing.expectEqualStrings(historical.evidence().database_identity.value, healthy.evidence().observed.database_identity.value);
    const replay = try verify(allocator, std.testing.io, path, "amd64", status, healthy.evidence());
    defer replay.deinit();
    try std.testing.checkAllAllocationFailures(allocator, captureAllocationCase, .{ path, status, &packages });
}

fn captureAllocationCase(allocator: std.mem.Allocator, path: []const u8, status: []const u8, packages: []const baseline.Package) !void {
    const captured = try capture(allocator, std.testing.io, path, "amd64", status, packages);
    defer captured.deinit();
}

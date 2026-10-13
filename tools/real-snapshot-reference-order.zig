const std = @import("std");
const builtin = @import("builtin");
const paths = @import("real_snapshot_reference_paths.zig");
const linux = std.os.linux;
const A = std.mem.Allocator;
const eq = std.mem.eql;

pub const maximum_packages = 2000;
pub const maximum_probes = 10000;
pub const maximum_probe_output = 65536;
pub const maximum_control_bytes = 1024 * 1024;
pub const maximum_log_bytes = 16 * 1024 * 1024;
pub const maximum_archive_bytes = 512 * 1024 * 1024;
pub const libgcc_triggers = "# Triggers added by dh_makeshlibs/13.31ubuntu1\nactivate-noawait ldconfig\n";
pub const kbd_triggers = "# Triggers added by dh_installinitramfs/13.24.2ubuntu1\nactivate-noawait update-initramfs\n";
pub const trigger_refusal = "reference trigger closure refused: the launcher has no exact triggered postinst identity/profile or single-package trigger operation; --pending and multi-package ordering are not authorized";
const scripts = [_][]const u8{ "preinst", "postinst", "prerm", "postrm", "config" };
const graph_fields = [_][]const u8{ "depends", "pre-depends", "provides", "conflicts", "breaks", "replaces", "multi-arch", "protected", "essential" };

pub const Package = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    digest: []const u8,
    size: usize,
    archive: []const u8,

    pub fn selector(self: Package, a: A) ![]const u8 {
        return if (eq(u8, self.architecture, "all")) self.name else std.fmt.allocPrint(a, "{s}:{s}", .{ self.name, self.architecture });
    }
    fn same(self: Package, other: Package) bool {
        return eq(u8, self.name, other.name) and eq(u8, self.version, other.version) and
            eq(u8, self.architecture, other.architecture) and eq(u8, self.digest, other.digest) and
            self.size == other.size and eq(u8, self.archive, other.archive);
    }
};
pub const Launcher = struct { path: []const u8, runtime: []const u8 };
const Pin = struct { name: []const u8, version: []const u8, architecture: []const u8 = "amd64", size: usize, digest: []const u8, depends: []const u8 = "", pre_depends: []const u8 = "" };
const libc: Pin = .{ .name = "libc6", .version = "2.43-2ubuntu2.4", .size = 2104056, .digest = "e27873bec6e0a7914834eac85748c31a360b44b0f0e971a7cd70439c2f9804e737f8f6113f15bb7f523d7a5d4a336173b43a5e22d804c440c8a11a5530bc6696", .depends = "libgcc-s1, libc-gconv-modules-extra (= 2.43-2ubuntu2.4)" };
pub const base_cycle = [_]Pin{
    libc,
    .{ .name = "libgcc-s1", .version = "16-20260322-1ubuntu1", .size = 80312, .digest = "a34e93f253ca90bd331c5eee563be6ebcc14dbf08147e82b9479f972fe566c83263b644e348757af1853f8663cb8ca2349e2c013e4a0ca0e3ea3d631297576b2", .depends = "gcc-16-base (= 16-20260322-1ubuntu1), libc6 (>= 2.35)" },
    .{ .name = "gcc-16-base", .version = "16-20260322-1ubuntu1", .size = 38296, .digest = "0767f731e71e709736596d52dbe181245a8ca181cdadbac6226aad5aa7151d8ce5149ad28625facc61d8882e76fc387af5336dc289126a0bf830b9e599b3922c" },
    .{ .name = "libc-gconv-modules-extra", .version = "2.43-2ubuntu2.4", .size = 1362202, .digest = "c385f1ca4f8054e59f977a38819e31d6f2429909ce0a88c734c874ce163851dfa7e565dded6c65c3feb3bc8cf074498b45a4c2226bb8e17a2bc8b95027a29692" },
};
pub const openssl_cycle = [_]Pin{
    .{ .name = "libssl3t64", .version = "3.5.5-1ubuntu3.6", .size = 2364586, .digest = "10df2f82619faff2ed4b890812313c35cd58abbfce858caf3403e1b654fac857bd7bc28e7a528a79a18ebfbfbdca5cffb3c2dd5b340c729fb7eb2470b76d528d", .depends = "libc6 (>= 2.38), libzstd1 (>= 1.5.5), zlib1g (>= 1:1.1.4), openssl-provider-legacy" },
    .{ .name = "openssl-provider-legacy", .version = "3.5.5-1ubuntu3.6", .size = 39690, .digest = "cbb4f55a609576d99a1b52952a674e78b2cbb7026e54c765cfd964812b65bdcdea4f5ea67961159b737fcba3093b3b15de8b7a6aff3bbf08a85805a09290c470", .depends = "libc6 (>= 2.14), libssl3t64 (>= 3.0.3)" },
    libc,
    .{ .name = "libzstd1", .version = "1.5.7+dfsg-3", .size = 308174, .digest = "284a44950a9caae10a6b7a06baead5db2d6dd2989fc01107c78c76ef5468cb489fc1a8e92d6cb84d44b5a371f8b1156bd2f5c232e79f1631dcf000a601e52183", .depends = "libc6 (>= 2.34)" },
    .{ .name = "zlib1g", .version = "1:1.3.dfsg+really1.3.1-1ubuntu3.1", .size = 61612, .digest = "a0ad94daadd3099ee40766a62a42d3fa7f431c6d805e9108d1dde07d64bfe3e7da66a41a2294598917e5ef5435df7a239d011711dd6d18037bc9b61b530ed3d4", .depends = "libc6 (>= 2.14)" },
};
pub const kbd_cycle = [_]Pin{
    .{ .name = "kbd", .version = "2.7.1-2ubuntu2", .size = 238014, .digest = "5a1fcb79b59441d380b4f6f38198ab4e7b04e50a759580302643ab1f138d88c900145612dfe0861eab37c5f9ebbb6218bc3a5585366be04d4cd00f85efa16050", .depends = "libc6 (>= 2.38), console-setup | console-setup-mini" },
    .{ .name = "console-setup-linux", .version = "1.237ubuntu3.1", .architecture = "all", .size = 6206020, .digest = "511e2f220d1f2afb6c0ae80d9488b6863b884f2db26e54d9cd343ca212c8061e6fbf637131fbd6f93673f3f9d47fe22515b22eca96a1cdf65e9e768fd2bbbb5b", .depends = "kbd (>= 0.99-12) | console-tools (>= 1:0.2.3-16), keyboard-configuration (= 1.237ubuntu3.1), init-system-helpers (>= 1.29~) | initscripts" },
    .{ .name = "console-setup", .version = "1.237ubuntu3.1", .architecture = "all", .size = 102654, .digest = "776ebf749c2a621ff9835b86b69efe1c838e948ac8265fab0f2c5eb91875ae67f1313800854b3a8a962359dfa40bee3e59cc5cf956a215ed82e15529bf622832", .depends = "console-setup-linux | hurd, xkb-data (>= 0.9), keyboard-configuration (= 1.237ubuntu3.1), debconf (>= 0.5) | debconf-2.0", .pre_depends = "debconf | debconf-2.0" },
    libc,
};

fn nameValid(value: []const u8) bool {
    if (value.len == 0 or (!std.ascii.isLower(value[0]) and !std.ascii.isDigit(value[0]))) return false;
    for (value) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '+' and byte != '.' and byte != '-') return false;
    return true;
}
fn digestValid(value: []const u8) bool {
    if (value.len != 128) return false;
    for (value) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    return true;
}
fn hash(comptime H: type, bytes: []const u8) [H.digest_length * 2]u8 {
    var result: [H.digest_length]u8 = undefined;
    H.hash(bytes, &result, .{});
    return std.fmt.bytesToHex(result, .lower);
}
fn join(a: A, root: []const u8, path: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{s}{s}{s}", .{ root, if (eq(u8, root, "/")) "" else "/", path });
}
const Lines = struct {
    bytes: []const u8,
    index: usize = 0,
    fn next(self: *Lines) ?[]const u8 {
        if (self.index == self.bytes.len) return null;
        const start = self.index;
        while (self.index < self.bytes.len) {
            const at = self.index;
            const byte = self.bytes[at];
            const separator: usize = switch (byte) {
                '\n', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e' => 1,
                '\r' => if (at + 1 < self.bytes.len and self.bytes[at + 1] == '\n') 2 else 1,
                0xc2 => if (std.mem.startsWith(u8, self.bytes[at..], "\xc2\x85")) 2 else 0,
                0xe2 => if (std.mem.startsWith(u8, self.bytes[at..], "\xe2\x80\xa8") or std.mem.startsWith(u8, self.bytes[at..], "\xe2\x80\xa9")) 3 else 0,
                else => 0,
            };
            if (separator != 0) {
                self.index += separator;
                return self.bytes[start..at];
            }
            self.index += 1;
        }
        return self.bytes[start..];
    }
};
fn strip(data: []const u8) []const u8 {
    var first: usize = data.len;
    var last: usize = 0;
    var index: usize = 0;
    while (index < data.len) {
        const length = std.unicode.utf8ByteSequenceLength(data[index]) catch unreachable;
        const codepoint = std.unicode.utf8Decode(data[index..][0..length]) catch unreachable;
        const whitespace = switch (codepoint) {
            9...13, 28...32, 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
            else => false,
        };
        if (!whitespace) {
            first = @min(first, index);
            last = index + length;
        }
        index += length;
    }
    return if (last == 0) data[0..0] else data[first..last];
}

pub fn packagesFromManifest(a: A, bytes: []const u8, cache: []const u8) ![]Package {
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidReferenceArchiveManifest;
    var result: std.ArrayList(Package) = .empty;
    var lines: Lines = .{ .bytes = bytes };
    while (lines.next()) |line| {
        var columns = std.mem.splitScalar(u8, line, '\t');
        var fields: [5][]const u8 = undefined;
        for (&fields) |*column| column.* = columns.next() orelse return error.InvalidReferenceArchiveManifest;
        if (columns.next() != null) return error.InvalidReferenceArchiveManifest;
        if (!nameValid(fields[0]) or fields[1].len == 0 or !nameValid(fields[2]) or !digestValid(fields[3]) or fields[4].len == 0)
            return error.InvalidReferencePackageIdentity;
        for (fields[4]) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidReferencePackageIdentity;
        const size = std.fmt.parseInt(usize, fields[4], 10) catch return error.InvalidReferenceArchiveSize;
        if (size == 0 or size > maximum_archive_bytes) return error.InvalidReferenceArchiveSize;
        for (result.items) |package| if (eq(u8, package.name, fields[0]) and eq(u8, package.architecture, fields[2]))
            return error.DuplicateReferencePackage;
        if (result.items.len == maximum_packages) return error.ReferenceClosureExceedsPackageLimit;
        try result.append(a, .{ .name = fields[0], .version = fields[1], .architecture = fields[2], .digest = fields[3], .size = size, .archive = try std.fmt.allocPrint(a, "{s}/packages-v2/objects/sha512-{s}", .{ cache, fields[3] }) });
    }
    if (result.items.len == 0) return error.EmptyReferenceClosure;
    return result.toOwnedSlice(a);
}

pub fn verifyArchive(package: Package) !void {
    const pin = try paths.openProtected(package.archive, false);
    defer pin.close();
    return verifyPinnedArchive(package, pin);
}
pub fn verifyPinnedArchive(package: Package, pin: paths.Pinned) !void {
    if (pin.metadata.size != package.size) return error.ReferenceArchiveSizeChanged;
    const opened = try paths.openAbsolute(package.archive, false);
    defer opened.close();
    if (!paths.same(opened.metadata, pin.metadata)) return error.ReferenceArchiveIdentityChanged;
    var digest = std.crypto.hash.sha2.Sha512.init(.{});
    var buffer: [1024 * 1024]u8 = undefined;
    var offset: usize = 0;
    while (true) {
        const count = try paths.syscall(linux.pread(opened.fd, &buffer, buffer.len, @intCast(offset)));
        if (count == 0) break;
        offset += count;
        if (offset > package.size) return error.ReferenceArchiveChanged;
        digest.update(buffer[0..count]);
    }
    if (offset != package.size or !paths.same(pin.metadata, try paths.stat(opened.fd))) return error.ReferenceArchiveChanged;
    var actual: [64]u8 = undefined;
    digest.final(&actual);
    if (!eq(u8, &std.fmt.bytesToHex(actual, .lower), package.digest)) return error.ReferenceArchiveDigestChanged;
}

pub const script_profiles = [_][2][]const u8{
    .{ "systemd", "259.5-0ubuntu3.4" },
    .{ "udev", "259.5-0ubuntu3.4" },
    .{ "sudo", "1.9.17p2-1ubuntu3.1" },
};
fn profileVersion(profile: []const u8) ?[]const u8 {
    for (script_profiles) |entry| if (eq(u8, profile, entry[0])) return entry[1];
    return null;
}
pub const Cycle = enum {
    base,
    openssl,
    kbd,
    fn pins(self: Cycle) []const Pin {
        return switch (self) {
            .base => &base_cycle,
            .openssl => &openssl_cycle,
            .kbd => &kbd_cycle,
        };
    }
    fn profile(self: Cycle) []const u8 {
        return switch (self) {
            .base => "libgcc_cycle",
            .openssl => "openssl_cycle",
            .kbd => "kbd_cycle",
        };
    }
    fn verb(self: Cycle) []const u8 {
        return switch (self) {
            .base => "break_base_cycle",
            .openssl => "configure_openssl_cycle",
            .kbd => "break_kbd_cycle",
        };
    }
    fn stem(self: Cycle) []const u8 {
        return switch (self) {
            .base => "base-cycle",
            .openssl => "openssl-cycle",
            .kbd => "kbd-cycle",
        };
    }
    fn selected(self: Cycle) usize {
        return if (self == .base) 1 else 0;
    }
    fn transitions(self: Cycle) usize {
        return if (self == .openssl) 2 else 1;
    }
};
fn matchesPin(package: Package, pin: Pin) bool {
    return eq(u8, package.name, pin.name) and eq(u8, package.version, pin.version) and
        eq(u8, package.architecture, pin.architecture) and eq(u8, package.digest, pin.digest) and package.size == pin.size;
}
pub fn cyclePackages(a: A, packages: []const Package, architecture: []const u8, kind: Cycle) ![]Package {
    if (!eq(u8, architecture, "amd64")) return error.UnknownCycle;
    const cycle = try a.alloc(Package, kind.pins().len);
    for (kind.pins(), cycle) |binding, *selected| {
        var count: usize = 0;
        for (packages) |package| if (eq(u8, package.name, binding.name)) {
            count += 1;
            if (!matchesPin(package, binding)) return error.CycleIdentityChanged;
            selected.* = package;
        };
        if (count != 1) return error.CycleIdentityChanged;
    }
    return cycle;
}
pub fn dpkgCommand(a: A, launcher: Launcher, dpkg: []const u8, root: []const u8, architecture: []const u8, profile: []const u8, verb: []const u8, package: ?Package, cycle: []const Package) ![][]const u8 {
    var special: ?Cycle = null;
    inline for (.{ Cycle.base, Cycle.openssl, Cycle.kbd }) |kind| {
        if (eq(u8, verb, kind.verb())) special = kind;
    }
    if (special) |kind| {
        if (!eq(u8, architecture, "amd64") or !eq(u8, profile, kind.profile()) or cycle.len != kind.pins().len or
            package == null or !package.?.same(cycle[kind.selected()])) return error.CycleIdentityChanged;
        for (cycle, kind.pins()) |p, binding| if (!matchesPin(p, binding)) return error.CycleIdentityChanged;
    } else {
        if (cycle.len != 0) return error.CycleIdentityChanged;
        if (!eq(u8, verb, "probe_unpack") and !eq(u8, verb, "unpack") and !eq(u8, verb, "probe_configure") and
            !eq(u8, verb, "configure") and !eq(u8, verb, "continue_prestate")) return error.NoSingleScriptBinding;
        if (package == null) return error.SignedPackageRequired;
        if (eq(u8, verb, "continue_prestate") and !eq(u8, profile, "systemd") and !eq(u8, profile, "udev"))
            return error.UnauthorizedHalfConfiguredContinuation;
        if (!eq(u8, profile, "none")) {
            if ((!eq(u8, verb, "configure") and !eq(u8, verb, "continue_prestate")) or !eq(u8, architecture, "amd64") or
                profileVersion(profile) == null or !eq(u8, package.?.name, profile) or !eq(u8, package.?.architecture, architecture) or
                !eq(u8, package.?.version, profileVersion(profile).?)) return error.UnauthorizedReferenceScriptProfile;
        } else if (eq(u8, verb, "configure") and profileVersion(package.?.name) != null) return error.MissingExactConfigureProfile;
    }
    var command: std.ArrayList([]const u8) = .empty;
    try command.appendSlice(a, &.{ launcher.path, root, dpkg, architecture, profile, verb, try package.?.selector(a), launcher.runtime });
    if (special != null) {
        for (cycle) |p| try command.append(a, p.archive);
    } else if (eq(u8, verb, "unpack") or eq(u8, verb, "probe_unpack")) {
        try command.appendSlice(a, &.{ package.?.archive, package.?.digest, try std.fmt.allocPrint(a, "{d}", .{package.?.size}) });
    }
    return command.toOwnedSlice(a);
}

pub const Fields = std.json.ObjectMap;
pub fn controlFields(a: A, data: []const u8) ![]Fields {
    if (!std.unicode.utf8ValidateSlice(data)) return error.InvalidReferenceControlEncoding;
    var records: std.ArrayList(Fields) = .empty;
    var stanzas = std.mem.splitSequence(u8, strip(data), "\n\n");
    while (stanzas.next()) |stanza| {
        if (stanza.len == 0) continue;
        var fields: Fields = .empty;
        var previous: ?[]const u8 = null;
        var lines: Lines = .{ .bytes = stanza };
        while (lines.next()) |line| {
            if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
                const key = previous orelse return error.InvalidReferenceIdentityContinuation;
                for ([_][]const u8{ "package", "architecture", "version", "status" }) |identity|
                    if (eq(u8, key, identity)) return error.InvalidReferenceIdentityContinuation;
                const value = try std.fmt.allocPrint(a, "{s}\n{s}", .{ fields.get(key).?.string, line });
                try fields.put(a, key, .{ .string = value });
                continue;
            }
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedReferenceDatabaseField;
            const key = line[0..colon];
            if (key.len == 0 or !std.ascii.isAlphabetic(key[0])) return error.MalformedReferenceDatabaseField;
            for (key) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-') return error.MalformedReferenceDatabaseField;
            const raw_value = line[colon + 1 ..];
            if (raw_value.len > 0 and raw_value[0] != ' ') return error.MalformedReferenceDatabaseField;
            const lower = try a.dupe(u8, key);
            for (lower) |*byte| byte.* = std.ascii.toLower(byte.*);
            if (fields.contains(lower)) return error.DuplicateReferenceDatabaseField;
            try fields.put(a, lower, .{ .string = if (raw_value.len > 0) raw_value[1..] else "" });
            previous = lower;
        }
        try records.append(a, fields);
    }
    return records.toOwnedSlice(a);
}
pub fn field(record: Fields, key: []const u8) []const u8 {
    return if (record.get(key)) |value| value.string else "";
}
pub fn parseDatabase(a: A, data: []const u8) ![]Fields {
    const records = try controlFields(a, data);
    for (records, 0..) |record, index| {
        if (!nameValid(field(record, "package")) or !nameValid(field(record, "architecture")) or
            field(record, "version").len == 0 or !record.contains("status")) return error.InvalidReferenceDatabasePackage;
        for (records[0..index]) |previous| if (eq(u8, field(previous, "package"), field(record, "package")) and
            eq(u8, field(previous, "architecture"), field(record, "architecture"))) return error.DuplicateReferenceDatabasePackage;
    }
    return records;
}
fn findRecord(records: []Fields, package: Package) ?Fields {
    for (records) |record| if (eq(u8, field(record, "package"), package.name) and eq(u8, field(record, "architecture"), package.architecture)) return record;
    return null;
}
fn statusIs(records: []Fields, package: Package, status: []const u8) bool {
    const record = findRecord(records, package) orelse return false;
    return eq(u8, field(record, "version"), package.version) and eq(u8, field(record, "status"), status);
}
fn objectsEqual(a: Fields, b: Fields) bool {
    if (a.count() != b.count()) return false;
    for (a.keys(), a.values()) |key, value| {
        const other = b.get(key) orelse return false;
        if (value == .string and other == .string) {
            if (!eq(u8, value.string, other.string)) return false;
        } else if (value == .integer and other == .integer) {
            if (value.integer != other.integer) return false;
        } else if (value == .object and other == .object) {
            if (!objectsEqual(value.object, other.object)) return false;
        } else return false;
    }
    return true;
}
pub fn conserved(before: []Fields, after: []Fields, selected: []const Package) bool {
    if (before.len != after.len) return false;
    for (before) |record| {
        const package: Package = .{ .name = field(record, "package"), .architecture = field(record, "architecture"), .version = field(record, "version"), .digest = "", .size = 0, .archive = "" };
        const actual = findRecord(after, package) orelse return false;
        var changes = false;
        for (selected) |p| if (eq(u8, p.name, package.name) and eq(u8, p.architecture, package.architecture)) {
            changes = true;
        };
        if (record.count() != actual.count()) return false;
        for (record.keys(), record.values()) |key, value| {
            const expected = if (changes and eq(u8, key, "status")) "install ok installed" else value.string;
            if (!actual.contains(key) or !eq(u8, field(actual, key), expected)) return false;
        }
    }
    return true;
}

pub const Member = struct { name: []const u8, bytes: []const u8, kind: u8 };
pub fn tarMembers(a: A, data: []const u8) ![]Member {
    if (data.len > maximum_control_bytes) return error.CycleControlChanged;
    var members: std.ArrayList(Member) = .empty;
    var reader: std.Io.Reader = .fixed(data);
    var name_buffer: [4096]u8 = undefined;
    var link_buffer: [4096]u8 = undefined;
    var iterator: std.tar.Iterator = .init(&reader, .{ .file_name_buffer = &name_buffer, .link_name_buffer = &link_buffer });
    while (iterator.next() catch return error.CycleControlChanged) |entry| {
        var name: []const u8 = try a.dupe(u8, entry.name);
        if (eq(u8, name, "./")) name = ".";
        if (members.items.len >= 128) return error.CycleControlChanged;
        if (entry.size > maximum_control_bytes) return error.CycleControlChanged;
        const bytes = try a.alloc(u8, @intCast(entry.size));
        reader.readSliceAll(bytes) catch return error.CycleControlChanged;
        iterator.unread_file_bytes = 0;
        try members.append(a, .{ .name = name, .bytes = bytes, .kind = switch (entry.kind) {
            .file => '0',
            .directory => '5',
            .sym_link => '2',
        } });
    }
    return members.toOwnedSlice(a);
}
fn member(members: []const Member, name: []const u8) ![]const u8 {
    var found: ?[]const u8 = null;
    for (members) |entry| if (eq(u8, entry.name, name)) {
        found = entry.bytes;
    };
    return found orelse error.CycleControlChanged;
}
fn memberSet(members: []const Member, expected: []const []const u8) bool {
    for (members) |entry| {
        var included = false;
        for (expected) |name| if (eq(u8, entry.name, name)) {
            included = true;
        };
        if (!included) return false;
    }
    for (expected) |name| {
        var included = false;
        for (members) |entry| if (eq(u8, entry.name, name)) {
            included = true;
        };
        if (!included) return false;
    }
    return true;
}

pub const Prestate = struct { selector: []const u8, status: []const u8, destination: []const u8 };
pub fn parsePrestate(value: []const u8) !Prestate {
    const equal = std.mem.indexOfScalar(u8, value, '=') orelse return error.InvalidPrestate;
    const selector = value[0..equal];
    const colon = std.mem.indexOfScalar(u8, selector, ':') orelse return error.InvalidPrestate;
    if (!nameValid(selector[0..colon]) or !nameValid(selector[colon + 1 ..])) return error.InvalidPrestate;
    for (selector[colon + 1 ..]) |byte| if (byte == '+' or byte == '.') return error.InvalidPrestate;
    const tail = value[equal + 1 ..];
    const delimiter = std.mem.indexOfScalar(u8, tail, ':') orelse return error.InvalidPrestate;
    const status = tail[0..delimiter];
    const destination = tail[delimiter + 1 ..];
    if ((!eq(u8, status, "unpacked") and !eq(u8, status, "half-configured")) or destination.len < 2 or destination[0] != '/')
        return error.InvalidPrestate;
    return .{ .selector = selector, .status = status, .destination = destination };
}

pub const Result = struct { code: i32, stdout: []const u8, stderr: []const u8, stdout_bytes: usize = 0, stderr_bytes: usize = 0 };
const Refusal = struct { selector: []const u8, operation: []const u8, exit_status: i32, output_bytes: usize, output_prefix_hex: []const u8, output_sha512: []const u8 };
const TestHooks = if (builtin.is_test) struct {
    state: *anyopaque,
    manifest: ?*const fn (*anyopaque) anyerror![]Package = null,
    database: ?*const fn (*anyopaque, []const u8) anyerror![]Fields = null,
    probe: ?*const fn (*anyopaque, []const []const u8) anyerror!Result = null,
    apply: ?*const fn (*anyopaque, []const []const u8) anyerror!void = null,
    archive: ?*const fn (*anyopaque, Package) anyerror!void = null,
    control: ?*const fn (*anyopaque, Package) anyerror![]Member = null,
    transition: ?*const fn (*anyopaque, Cycle) anyerror![]Package = null,
    capture: ?*const fn (*anyopaque, Package, Prestate) anyerror!void = null,
    run: ?*const fn (*anyopaque, []const []const u8) anyerror!?Result = null,
    runtime_unprotected: bool = false,
    runtime_digest: ?*const fn ([]const u8) ?[64]u8 = null,
    assume_x86_64: bool = false,
} else void;
pub const Context = struct {
    a: A,
    io: std.Io,
    environment: *const std.process.Environ.Map,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    cache: []const u8,
    evidence: []const u8,
    architecture: []const u8,
    test_hooks: if (builtin.is_test) ?TestHooks else void = if (builtin.is_test) null else {},

    pub fn read(self: Context, root: []const u8, relative: []const u8, limit: usize) ![]u8 {
        return paths.readRootFile(self.a, root, relative, limit);
    }
    pub fn database(self: Context, root: []const u8) ![]Fields {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.database) |callback| return callback(hooks.state, root);
        return parseDatabase(self.a, try self.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024));
    }
    fn manifest(self: Context) ![]Package {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.manifest) |callback| return callback(hooks.state);
        return packagesFromManifest(self.a, try self.read(self.evidence, "reference-archives.tsv", std.math.maxInt(usize)), self.cache);
    }
    fn archive(self: Context, package: Package) !void {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.archive) |callback| return callback(hooks.state, package);
        return verifyArchive(package);
    }
    pub fn write(self: Context, root: []const u8, relative: []const u8, bytes: []const u8, append: bool) !void {
        _ = self;
        const fd = try paths.create(root, relative, 0o600, append);
        defer _ = linux.close(fd);
        try paths.writeAll(fd, bytes);
    }
    pub fn json(self: Context, root: []const u8, relative: []const u8, value: anytype) !void {
        var output: std.Io.Writer.Allocating = .init(self.a);
        var serializer: std.json.Stringify = .{ .writer = &output.writer, .options = .{ .whitespace = .indent_2 } };
        try jsonWrite(&serializer, value);
        try output.writer.writeByte('\n');
        try self.replace(root, relative, output.written());
    }
    pub fn replace(self: Context, root: []const u8, relative: []const u8, bytes: []const u8) !void {
        _ = self;
        const fd = try paths.create(root, relative, 0o600, true);
        defer _ = linux.close(fd);
        _ = try paths.syscall(linux.ftruncate(fd, 0));
        try paths.writeAll(fd, bytes);
    }
    pub fn argvFor(self: Context, root: []const u8, profile: []const u8, verb: []const u8, package: Package, cycle: []const Package) ![][]const u8 {
        return dpkgCommand(self.a, self.launcher, self.dpkg, root, self.architecture, profile, verb, package, cycle);
    }
    pub fn run(self: Context, argv: []const []const u8, seconds: i64, maximum: usize) !Result {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.run) |callback| if (try callback(hooks.state, argv)) |result| return result;
        const result = try std.process.run(self.a, self.io, .{ .argv = argv, .environ_map = self.environment, .stdout_limit = .limited(maximum), .stderr_limit = .limited(maximum), .timeout = .{ .duration = .{ .raw = .fromSeconds(seconds), .clock = .awake } } });
        return .{ .code = switch (result.term) {
            .exited => |code| code,
            .signal => |signal| -@as(i32, @intCast(@intFromEnum(signal))),
            else => -1,
        }, .stdout = result.stdout, .stderr = result.stderr, .stdout_bytes = result.stdout.len, .stderr_bytes = result.stderr.len };
    }
    pub fn checked(self: Context, argv: []const []const u8, seconds: i64) !void {
        const result = try self.run(argv, seconds, maximum_probe_output);
        if (result.code != 0) {
            try paths.writeAll(2, result.stderr);
            return error.ReferenceCommandFailed;
        }
    }
    pub fn runFiles(self: Context, command: []const []const u8, stdout_fd: i32, stderr_fd: i32, seconds: i64) !i32 {
        const input_null = try paths.openAbsolute("/dev/null", false);
        defer input_null.close();
        var child = try std.process.spawn(self.io, .{
            .argv = command,
            .environ_map = self.environment,
            .stdin = .{ .file = .{ .handle = input_null.fd, .flags = .{ .nonblocking = false } } },
            .stdout = .{ .file = .{ .handle = stdout_fd, .flags = .{ .nonblocking = false } } },
            .stderr = .{ .file = .{ .handle = stderr_fd, .flags = .{ .nonblocking = false } } },
        });
        defer child.kill(self.io);
        var start: linux.timespec = undefined;
        _ = try paths.syscall(linux.clock_gettime(linux.CLOCK.MONOTONIC, &start));
        while (true) {
            var status: u32 = undefined;
            const result = linux.wait4(child.id.?, &status, linux.W.NOHANG, null);
            if (linux.errno(result) == .INTR) continue;
            const pid = try paths.syscall(result);
            if (pid != 0) {
                child.id = null;
                if (linux.W.IFEXITED(status)) return linux.W.EXITSTATUS(status);
                if (linux.W.IFSIGNALED(status)) return -@as(i32, @intCast(@intFromEnum(linux.W.TERMSIG(status))));
                return -1;
            }
            var now: linux.timespec = undefined;
            _ = try paths.syscall(linux.clock_gettime(linux.CLOCK.MONOTONIC, &now));
            if (now.sec > start.sec + seconds or (now.sec == start.sec + seconds and now.nsec >= start.nsec))
                return error.ReferenceCommandTimedOut;
            try self.io.sleep(.fromMilliseconds(5), .awake);
        }
    }
    fn scratch(self: Context, evidence: []const u8, prefix: []const u8) ![]const u8 {
        var random: [16]u8 = undefined;
        self.io.random(&random);
        const name = try std.fmt.allocPrint(self.a, "{s}-{s}", .{ prefix, std.fmt.bytesToHex(random, .lower) });
        const pin = try paths.openAbsolute(evidence, true);
        defer pin.close();
        const z = try self.a.dupeZ(u8, name);
        _ = try paths.syscall(linux.mkdirat(pin.fd, z, 0o700));
        return join(self.a, evidence, name);
    }
    fn cleanupScratch(self: Context, directory: []const u8, names: []const []const u8) void {
        const pin = paths.openAbsolute(directory, true) catch return;
        defer pin.close();
        for (names) |name| {
            const z = self.a.dupeZ(u8, name) catch return;
            _ = linux.unlinkat(pin.fd, z, 0);
        }
        const z = self.a.dupeZ(u8, directory) catch return;
        _ = linux.rmdir(z);
    }
    pub fn probe(self: Context, command: []const []const u8, evidence: []const u8) !Result {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.probe) |callback| return callback(hooks.state, command);
        const scratch_dir = try self.scratch(evidence, "reference-probe");
        defer self.cleanupScratch(scratch_dir, &.{"output"});
        const output = try paths.create(scratch_dir, "output", 0o600, false);
        _ = linux.close(output);
        const reader = try paths.openAbsolute(try join(self.a, scratch_dir, "output"), false);
        defer reader.close();
        const writer = try paths.create(scratch_dir, "output", 0o600, true);
        defer _ = linux.close(writer);
        const code = try self.runFiles(command, writer, writer, 60);
        const current = try paths.stat(reader.fd);
        if (current.size > maximum_probe_output) return error.ReferenceProbeOutputExceedsLimit;
        const bytes = try paths.readPinned(self.a, .{ .fd = reader.fd, .metadata = current }, maximum_probe_output);
        return .{ .code = code, .stdout = bytes, .stderr = "", .stdout_bytes = bytes.len };
    }
    pub fn apply(self: Context, command: []const []const u8, evidence: []const u8, out: []const u8, err: []const u8) !void {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.apply) |callback| return callback(hooks.state, command);
        const output = try paths.create(evidence, out, 0o600, true);
        defer _ = linux.close(output);
        const errors = try paths.create(evidence, err, 0o600, true);
        defer _ = linux.close(errors);
        const code = try self.runFiles(command, output, errors, 120);
        if (code != 0) return error.ReferenceDpkgOperationFailed;
        if ((try paths.stat(output)).size > maximum_log_bytes or (try paths.stat(errors)).size > maximum_log_bytes)
            return error.ReferenceDpkgOutputExceedsLimit;
    }
    fn capture(self: Context, command: []const []const u8, directory: []const u8, out: []const u8, err: []const u8, seconds: i64) !Result {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.run) |callback| if (try callback(hooks.state, command)) |result|
            return .{ .code = result.code, .stdout = result.stdout[0..@min(result.stdout.len, maximum_probe_output)], .stderr = result.stderr[0..@min(result.stderr.len, maximum_probe_output)], .stdout_bytes = result.stdout.len, .stderr_bytes = result.stderr.len };
        const output = try paths.create(directory, out, 0o600, false);
        _ = linux.close(output);
        const errors = try paths.create(directory, err, 0o600, false);
        _ = linux.close(errors);
        const out_writer = try paths.create(directory, out, 0o600, true);
        defer _ = linux.close(out_writer);
        const err_writer = try paths.create(directory, err, 0o600, true);
        defer _ = linux.close(err_writer);
        const code = try self.runFiles(command, out_writer, err_writer, seconds);
        const out_pin = try paths.openAbsolute(try join(self.a, directory, out), false);
        defer out_pin.close();
        const err_pin = try paths.openAbsolute(try join(self.a, directory, err), false);
        defer err_pin.close();
        const out_size: usize = @intCast(out_pin.metadata.size);
        const err_size: usize = @intCast(err_pin.metadata.size);
        const stdout = try self.a.alloc(u8, @min(out_size, maximum_probe_output));
        const stderr = try self.a.alloc(u8, @min(err_size, maximum_probe_output));
        const out_file: std.Io.File = .{ .handle = out_pin.fd, .flags = .{ .nonblocking = false } };
        const err_file: std.Io.File = .{ .handle = err_pin.fd, .flags = .{ .nonblocking = false } };
        if (try out_file.readPositionalAll(self.io, stdout, 0) != stdout.len or
            try err_file.readPositionalAll(self.io, stderr, 0) != stderr.len) return error.ReferenceFileChanged;
        return .{ .code = code, .stdout = stdout, .stderr = stderr, .stdout_bytes = out_size, .stderr_bytes = err_size };
    }
    pub fn triggerDatabase(self: Context, root: []const u8) !Fields {
        const updates = try paths.openAbsolute(try join(self.a, root, "var/lib/dpkg/updates"), true);
        defer updates.close();
        if ((try paths.names(self.a, self.io, updates, maximum_packages)).len != 0) return error.CycleStateChanged;
        const directory = try paths.openAbsolute(try join(self.a, root, "var/lib/dpkg/triggers"), true);
        defer directory.close();
        var result: Fields = .empty;
        for (try paths.names(self.a, self.io, directory, maximum_packages)) |name| {
            const data = try self.read(root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/triggers/{s}", .{name}), maximum_control_bytes);
            if (eq(u8, name, "Unincorp") and data.len != 0) return error.CycleCallbackChanged;
            var binding: Fields = .empty;
            try binding.put(self.a, "size", .{ .integer = @intCast(data.len) });
            try binding.put(self.a, "sha512", .{ .string = try self.a.dupe(u8, &hash(std.crypto.hash.sha2.Sha512, data)) });
            try result.put(self.a, name, .{ .object = binding });
        }
        return result;
    }
    fn control(self: Context, package: Package) ![]Member {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.control) |callback| return callback(hooks.state, package);
        const result = try self.run(&.{ "dpkg-deb", "--ctrl-tarfile", package.archive }, 30, maximum_control_bytes);
        if (result.code != 0 or result.stderr.len != 0) return error.CycleControlChanged;
        return tarMembers(self.a, result.stdout);
    }
    pub fn verifyCycle(self: Context, root: []const u8, cycle: []const Package, kind: Cycle) !struct { graph: Fields, records: []Fields, trigger_database: Fields } {
        const records = try self.database(root);
        const triggers_before = try self.triggerDatabase(root);
        var graph: Fields = .empty;
        for (cycle, kind.pins(), 0..) |package, binding, index| {
            self.archive(package) catch return error.CycleIdentityChanged;
            const members = try self.control(package);
            const controls = try controlFields(self.a, try member(members, "./control"));
            if (controls.len != 1 or (try member(members, "./control")).len > maximum_probe_output) return error.CycleControlChanged;
            const fields = controls[0];
            const scriptless = if (kind == .base) index == 1 else if (kind == .openssl) index < 2 else index == 0;
            if (scriptless) {
                const expected: []const []const u8 = if (kind == .kbd) &.{ ".", "./control", "./md5sums", "./triggers" } else if (kind == .openssl and index == 1)
                    &.{ ".", "./control", "./md5sums" }
                else
                    &.{ ".", "./control", "./md5sums", "./shlibs", "./symbols", "./triggers" };
                if (!memberSet(members, expected)) return error.CycleCallbackChanged;
                if (!(kind == .openssl and index == 1) and !eq(u8, try member(members, "./triggers"), if (kind == .kbd) kbd_triggers else libgcc_triggers))
                    return error.CycleCallbackChanged;
            }
            if (!eq(u8, field(fields, "package"), package.name) or !eq(u8, field(fields, "version"), package.version) or
                !eq(u8, field(fields, "architecture"), package.architecture) or !eq(u8, field(fields, "depends"), binding.depends) or
                !eq(u8, field(fields, "pre-depends"), binding.pre_depends)) return error.CycleControlChanged;
            const installed = findRecord(records, package) orelse return error.CycleStateChanged;
            if (!eq(u8, field(installed, "version"), package.version)) return error.CycleStateChanged;
            const in_cycle = index < (if (kind == .kbd) @as(usize, 3) else 2);
            const expected = if (in_cycle) "install ok unpacked" else "install ok installed";
            if (!eq(u8, field(installed, "status"), expected)) return if (!in_cycle and kind != .kbd) error.CycleOutsideDependency else error.CycleStateChanged;
            for (graph_fields) |key| if (!eq(u8, field(installed, key), field(fields, key))) return error.CycleControlChanged;
            for ([_][]const u8{ "triggers-pending", "triggers-awaited", "config-version" }) |key| if (field(installed, key).len != 0) return error.CycleCallbackChanged;
            var item: Fields = .empty;
            try item.put(self.a, "version", .{ .string = package.version });
            try item.put(self.a, "archive_sha512", .{ .string = package.digest });
            try item.put(self.a, "depends", .{ .string = binding.depends });
            try item.put(self.a, "status", .{ .string = expected });
            if (kind == .kbd) try item.put(self.a, "architecture", .{ .string = package.architecture }) else try item.put(self.a, "pre_depends", .{ .string = "" });
            if (kind == .openssl) try item.put(self.a, "multi_arch", .{ .string = field(fields, "multi-arch") });
            try graph.put(self.a, package.name, .{ .object = item });
        }
        const activation = switch (kind) {
            .base => "libgcc-s1:amd64.triggers",
            .openssl => "libssl3t64:amd64.triggers",
            .kbd => "kbd.triggers",
        };
        if (!eq(u8, try self.read(root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}", .{activation}), 1024), if (kind == .kbd) kbd_triggers else libgcc_triggers)) return error.CycleCallbackChanged;
        const no_scripts: []const []const u8 = switch (kind) {
            .base => &.{ "libgcc-s1", "libgcc-s1:amd64" },
            .openssl => &.{ "libssl3t64", "libssl3t64:amd64", "openssl-provider-legacy", "openssl-provider-legacy:amd64" },
            .kbd => &.{ "kbd", "kbd:amd64" },
        };
        for (no_scripts) |name| {
            for (scripts) |script| if (try paths.exists(root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}.{s}", .{ name, script })))
                return error.CycleCallbackChanged;
            const name_activation = try std.fmt.allocPrint(self.a, "{s}.triggers", .{name});
            if (!eq(u8, name_activation, activation) and try paths.exists(root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}", .{name_activation})))
                return error.CycleCallbackChanged;
        }
        return .{ .graph = graph, .records = records, .trigger_database = triggers_before };
    }
    pub fn transition(self: Context, root: []const u8, evidence: []const u8, packages: []const Package, kind: Cycle, stdout: []const u8, stderr: []const u8) ![]Package {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.transition) |callback| return callback(hooks.state, kind);
        const cycle = try cyclePackages(self.a, packages, self.architecture, kind);
        const before = try self.verifyCycle(root, cycle, kind);
        if (kind != .base) {
            var refusals: std.ArrayList(struct { argv: [][]const u8, exit_status: i32, output: []const u8 }) = .empty;
            for (cycle[0..kind.transitions()], 0..) |package, index| {
                const command = try self.argvFor(root, "none", "probe_configure", package, &.{});
                const result = try self.probe(command, evidence);
                try refusals.append(self.a, .{ .argv = command[3..], .exit_status = result.code, .output = try utf8Replace(self.a, result.stdout) });
                const filename = if (kind == .kbd) "kbd-cycle-refusal.json" else "openssl-cycle-refusals.json";
                if (kind == .kbd) try self.json(evidence, filename, refusals.items[0]) else try self.json(evidence, filename, refusals.items);
                const peer = if (kind == .kbd) "console-setup" else blk: {
                    const p = cycle[1 - index];
                    break :blk if (eq(u8, field(before.graph.get(p.name).?.object, "multi_arch"), "same")) try p.selector(self.a) else p.name;
                };
                const exact = try std.fmt.allocPrint(self.a, "Package {s} is not configured yet.", .{peer});
                if (result.code == 0 or std.mem.indexOf(u8, result.stdout, "dependency problems") == null or std.mem.indexOf(u8, result.stdout, exact) == null)
                    return error.CycleProbeChanged;
            }
        }
        const force: []const []const u8 = if (kind == .openssl) &.{} else &.{"--force-depends"};
        const status_sha512 = hash(std.crypto.hash.sha2.Sha512, try self.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024));
        const before_name = try std.fmt.allocPrint(self.a, "{s}-before.json", .{kind.stem()});
        if (kind == .base) {
            try self.json(evidence, before_name, .{ .graph = before.graph, .records = before.records, .trigger_database = before.trigger_database, .callbacks = @as([]const []const u8, &.{}), .profile = kind.profile(), .force = force, .status_sha512 = &status_sha512 });
        } else try self.json(evidence, before_name, .{ .graph = before.graph, .records = before.records, .trigger_database = before.trigger_database, .callbacks = @as([]const []const u8, &.{}), .profile = kind.profile(), .force = force });
        const command = try self.argvFor(root, kind.profile(), kind.verb(), cycle[kind.selected()], cycle);
        try self.apply(command, evidence, stdout, stderr);
        const after = try self.database(root);
        const triggers_after = try self.triggerDatabase(root);
        const selected = if (kind == .openssl) cycle[0..2] else cycle[kind.selected()..][0..1];
        if (!conserved(before.records, after, selected) or !objectsEqual(before.trigger_database, triggers_after)) return error.CycleNoProgress;
        const after_name = try std.fmt.allocPrint(self.a, "{s}-after.json", .{kind.stem()});
        if (kind == .base) {
            try self.json(evidence, after_name, .{ .operation = command[3..], .callbacks = @as([]const []const u8, &.{}), .status = "install ok installed", .trigger_database = triggers_after, .status_sha512 = &hash(std.crypto.hash.sha2.Sha512, try self.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024)), .records = after });
        } else try self.json(evidence, after_name, .{ .operation = command[3..], .callbacks = @as([]const []const u8, &.{}), .force = force, .trigger_database = triggers_after, .records = after });
        return selected;
    }
    fn packageStatus(self: Context, root: []const u8, package: Package) ![]const u8 {
        const result = try self.run(&.{ "dpkg-query", try std.fmt.allocPrint(self.a, "--admindir={s}/var/lib/dpkg", .{root}), "-W", "-f=${Version} ${Status}", try package.selector(self.a) }, 60, 4096);
        if (result.code != 0 or result.stderr.len != 0 or !std.unicode.utf8ValidateSlice(result.stdout)) return error.InvalidReferenceStatusQuery;
        return result.stdout;
    }
    fn mounted(self: Context, path: []const u8) !bool {
        const result = try self.run(&.{ "mountpoint", "-q", "--", path }, 30, maximum_probe_output);
        if (result.code != 0 and result.code != 32) return error.ReferenceMountpointQueryFailed;
        return result.code == 0;
    }
    fn emptyDirectory(self: Context, path: []const u8) !bool {
        const pin = try paths.openAbsolute(path, true);
        defer pin.close();
        return (try paths.names(self.a, self.io, pin, maximum_packages)).len == 0;
    }
    pub fn interruptPostinst(self: Context, root: []const u8, package: Package, evidence: []const u8, out: []const u8, err: []const u8) !void {
        const relative = try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}.postinst", .{package.name});
        const script = try join(self.a, root, relative);
        const original = try self.read(root, relative, maximum_probe_output);
        const version = profileVersion(package.name) orelse return error.UnauthorizedInterruptedPrestatePackage;
        if (!eq(u8, package.version, version)) return error.UnauthorizedInterruptedPrestatePackage;
        try self.checked(&.{ "mount", "--bind", "--", script, script }, 30);
        const result = blk: {
            errdefer self.checked(&.{ "umount", "--", script }, 30) catch {};
            try self.checked(&.{ "mount", "-o", "remount,bind,ro,noexec,nosuid,nodev", "--", script }, 30);
            const scratch_dir = try self.scratch(evidence, "reference-configure");
            defer self.cleanupScratch(scratch_dir, &.{ "stdout", "stderr" });
            break :blk try self.capture(try self.argvFor(root, package.name, "configure", package, &.{}), scratch_dir, "stdout", "stderr", 120);
        };
        try self.checked(&.{ "umount", "--", script }, 30);
        if (result.stdout_bytes > maximum_probe_output or result.stderr_bytes > maximum_probe_output) return error.InterruptedConfigureOutputExceedsLimit;
        try self.write(evidence, out, result.stdout, true);
        try self.write(evidence, err, result.stderr, true);
        if (result.code == 0 or std.mem.indexOf(u8, result.stderr, "post-installation script") == null or
            std.mem.indexOf(u8, result.stderr, "Permission denied") == null) return error.PrestatePostinstNotDeniedBeforeExecution;
        if (!eq(u8, original, try self.read(root, relative, maximum_probe_output))) return error.PrestatePostinstChanged;
    }
    pub fn capturePrestate(self: Context, root: []const u8, package: Package, prestate: Prestate, evidence: []const u8, out: []const u8, err: []const u8) !void {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.capture) |callback| return callback(hooks.state, package, prestate);
        try paths.absolute(prestate.destination);
        const parent = std.fs.path.dirname(prestate.destination).?;
        if (try paths.exists(parent, std.fs.path.basename(prestate.destination))) return error.PrestateDestinationMustBeNew;
        if (eq(u8, prestate.status, "half-configured")) try self.interruptPostinst(root, package, evidence, out, err);
        const expected = try std.fmt.allocPrint(self.a, "{s} install ok {s}", .{ package.version, prestate.status });
        if (!eq(u8, try self.packageStatus(root, package), expected)) return error.UnexpectedPrestateStatus;
        const proc = try join(self.a, root, "proc");
        const was_mounted = try self.mounted(proc);
        if (was_mounted) try self.checked(&.{ "umount", "--", proc }, 30);
        {
            errdefer if (was_mounted) self.checked(&.{ "mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", proc }, 30) catch {};
            if (try self.mounted(proc) or !try self.emptyDirectory(proc)) return error.PrestateProcMountpointNotEmpty;
            try self.checked(&.{ "cp", "-a", "--one-file-system", "--", root, prestate.destination }, 600);
            const destination = try paths.openAbsolute(prestate.destination, true);
            defer destination.close();
            _ = try paths.syscall(linux.fchmod(destination.fd, 0o700));
        }
        if (was_mounted) try self.checked(&.{ "mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", proc }, 30);
        try self.write(parent, "prestates.tsv", try std.fmt.allocPrint(self.a, "{s}\t{s}\t{s}\n", .{ try package.selector(self.a), expected, prestate.destination }), true);
    }
    pub fn install(self: Context, prestates: []const Prestate) !void {
        const packages = try self.manifest();
        try validateTargets(self.a, packages, prestates);
        const states = try self.a.alloc(enum { pending, unpacked, configured }, packages.len);
        @memset(states, .pending);
        const captured = try self.a.alloc(bool, prestates.len);
        @memset(captured, false);
        var targets = prestates.len;
        var probes: usize = 0;
        var applied: [3]bool = @splat(false);
        var configured: usize = 0;
        var unpacked: std.ArrayList(usize) = .empty;
        while (configured != packages.len) {
            var progressed = false;
            var deferred: std.ArrayList([]const u8) = .empty;
            var refusals: std.ArrayList(Refusal) = .empty;
            for (packages, states, 0..) |package, *state, package_index| {
                if (state.* != .pending) continue;
                const command = try self.argvFor(self.root, "none", "probe_unpack", package, &.{});
                probes += 1;
                if (probes > maximum_probes) return error.ReferenceDependencyProbeLimitExceeded;
                const result = try self.probe(command, self.evidence);
                if (result.code != 0) {
                    if (std.mem.indexOf(u8, result.stdout, "pre-dependency problem") == null) return error.ReferenceDpkgUnpackRefused;
                    try deferred.append(self.a, try package.selector(self.a));
                    try refusals.append(self.a, try refusal(self.a, package, "probe_unpack", result));
                    continue;
                }
                try self.archive(package);
                try self.apply(try self.argvFor(self.root, "none", "unpack", package, &.{}), self.evidence, "reference-install.stdout", "reference-install.stderr");
                state.* = .unpacked;
                try unpacked.append(self.a, package_index);
                progressed = true;
            }
            var unpacked_index: usize = 0;
            while (unpacked_index < unpacked.items.len) {
                const package_index = unpacked.items[unpacked_index];
                const package = packages[package_index];
                probes += 1;
                if (probes > maximum_probes) return error.ReferenceDependencyProbeLimitExceeded;
                const result = try self.probe(try self.argvFor(self.root, "none", "probe_configure", package, &.{}), self.evidence);
                if (result.code != 0) {
                    if (std.mem.indexOf(u8, result.stdout, "dependency problems") == null) return error.ReferenceDpkgConfigureRefused;
                    try deferred.append(self.a, try package.selector(self.a));
                    try refusals.append(self.a, try refusal(self.a, package, "probe_configure", result));
                    unpacked_index += 1;
                    continue;
                }
                if (!statusIs(try self.database(self.root), package, "install ok unpacked")) return error.ReferencePackageStateVersionChanged;
                const profile = if (profileVersion(package.name) != null) package.name else "none";
                if (profileVersion(profile)) |version| if (!eq(u8, package.version, version)) return error.UnauthorizedReferenceScriptVersion;
                var selected: ?usize = null;
                const selector = try package.selector(self.a);
                for (prestates, captured, 0..) |prestate, done, index| if (!done and eq(u8, selector, prestate.selector)) {
                    selected = index;
                };
                if (selected != null and eq(u8, selector, "sudo:amd64")) {
                    const companion_index = findPackage(packages, "sudo-rs").?;
                    const companion = packages[companion_index];
                    const db = try self.database(self.root);
                    if (!statusIs(db, companion, "install ok installed")) {
                        const record = findRecord(db, companion);
                        if (states[companion_index] == .configured or (record != null and !eq(u8, field(record.?, "version"), companion.version)))
                            return error.SignedSudoPrestateCompanionStateVersionChanged;
                        try deferred.append(self.a, selector);
                        unpacked_index += 1;
                        continue;
                    }
                }
                var operation: []const u8 = "configure";
                if (selected) |index| {
                    captured[index] = true;
                    targets -= 1;
                    try self.capturePrestate(self.root, package, prestates[index], self.evidence, "reference-install.stdout", "reference-install.stderr");
                    if (targets == 0) return;
                    if (eq(u8, prestates[index].status, "half-configured")) {
                        if (!statusIs(try self.database(self.root), package, "install ok half-configured")) return error.CapturedPrestateStateVersionChanged;
                        operation = "continue_prestate";
                    }
                }
                try self.apply(try self.argvFor(self.root, profile, operation, package, &.{}), self.evidence, "reference-install.stdout", "reference-install.stderr");
                states[package_index] = .configured;
                _ = unpacked.orderedRemove(unpacked_index);
                configured += 1;
                progressed = true;
            }
            if (!progressed) {
                try self.json(self.evidence, "reference-no-progress.json", .{
                    .base_cycle_applied = applied[0],
                    .openssl_cycle_applied = applied[1],
                    .kbd_cycle_applied = applied[2],
                    .deferred = deferred.items,
                    .refusals = refusals.items[0..@min(refusals.items.len, 128)],
                    .refusals_truncated = refusals.items.len > 128,
                });
                var chosen: ?Cycle = null;
                if (!applied[0]) {
                    const cycle = try cyclePackages(self.a, packages, self.architecture, .base);
                    if (states[findPackage(packages, cycle[1].name).?] != .unpacked) return error.CycleStateChanged;
                    chosen = .base;
                } else if (!applied[1] and unpackedSet(packages, states, &.{ "libssl3t64", "openssl-provider-legacy" })) {
                    probes += 2;
                    chosen = .openssl;
                } else if (!applied[2] and unpackedSet(packages, states, &.{ "kbd", "console-setup-linux", "console-setup" })) {
                    probes += 1;
                    chosen = .kbd;
                }
                if (probes > maximum_probes) return error.ReferenceDependencyProbeLimitExceeded;
                const kind = chosen orelse return error.CycleNoProgress;
                for (try self.transition(self.root, self.evidence, packages, kind, "reference-install.stdout", "reference-install.stderr")) |p| {
                    const selected_index = findPackage(packages, p.name).?;
                    states[selected_index] = .configured;
                    for (unpacked.items, 0..) |unpacked_package, i| if (unpacked_package == selected_index) {
                        _ = unpacked.orderedRemove(i);
                        break;
                    };
                    configured += 1;
                }
                applied[@intFromEnum(kind)] = true;
            }
        }
        if (targets != 0) return error.PrestatePackageNeverConfigured;
        try paths.writeAll(2, trigger_refusal ++ "\n");
        return error.UnboundTriggerClosure;
    }
    pub fn report(self: Context) !void {
        const packages = try self.manifest();
        const records = try self.database(self.root);
        if (records.len != packages.len) return error.ReferenceDatabaseDiffersFromSignedClosure;
        var output: std.Io.Writer.Allocating = .init(self.a);
        for (packages) |package| {
            if (!statusIs(records, package, "install ok installed")) return error.ReferencePackageNotInstalledAtSignedVersion;
            try output.writer.print("ii  {s} {s}\n", .{ try package.selector(self.a), package.version });
        }
        try self.replace(self.evidence, "reference-installed.txt", output.written());
        const directory = try paths.openAbsolute(try join(self.a, self.root, "var/lib/dpkg/info"), true);
        defer directory.close();
        for (try paths.names(self.a, self.io, directory, maximum_packages * 12)) |entry| {
            if (!std.mem.endsWith(u8, entry, ".list")) continue;
            const data = try self.read(self.root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}", .{entry}), 8 * 1024 * 1024);
            var lines = std.mem.splitScalar(u8, data, '\n');
            while (lines.next()) |line| if (eq(u8, std.mem.trimEnd(u8, line, "\r"), "/dev/null")) return error.ReferencePackageClaimsExcludedDevice;
        }
    }
};

fn jsonWrite(serializer: *std.json.Stringify, value: anytype) !void {
    const T = @TypeOf(value);
    if (T == Fields) return serializer.write(std.json.Value{ .object = value });
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            try serializer.beginObject();
            inline for (info.fields) |item| {
                try serializer.objectField(item.name);
                try jsonWrite(serializer, @field(value, item.name));
            }
            try serializer.endObject();
        },
        .pointer => |info| switch (info.size) {
            .one => try jsonWrite(serializer, value.*),
            .slice => {
                if (info.child == u8) return serializer.write(value);
                try serializer.beginArray();
                for (value) |item| try jsonWrite(serializer, item);
                try serializer.endArray();
            },
            else => @compileError("unsupported reference evidence pointer"),
        },
        .array => |info| {
            if (info.child == u8) return serializer.write(&value);
            try serializer.beginArray();
            for (value) |item| try jsonWrite(serializer, item);
            try serializer.endArray();
        },
        else => try serializer.write(value),
    }
}

fn findPackage(packages: []const Package, name: []const u8) ?usize {
    for (packages, 0..) |package, index| if (eq(u8, package.name, name)) return index;
    return null;
}
fn unpackedSet(packages: []const Package, states: anytype, names: []const []const u8) bool {
    for (names) |name| {
        const index = findPackage(packages, name) orelse return false;
        if (states[index] != .unpacked) return false;
    }
    return true;
}
pub fn validateTargets(a: A, packages: []const Package, prestates: []const Prestate) !void {
    for (prestates, 0..) |target, index| {
        for (prestates[0..index]) |previous| {
            if (eq(u8, previous.selector, target.selector)) return error.DuplicatePrestateSelector;
            if (eq(u8, previous.destination, target.destination)) return error.DuplicatePrestateDestination;
        }
        var included = false;
        for (packages) |package| if (eq(u8, try package.selector(a), target.selector)) {
            included = true;
        };
        if (!included) return error.PrestatePackageNotInVerifiedClosure;
        if (eq(u8, target.selector, "sudo:amd64")) {
            var companions: usize = 0;
            for (packages) |package| if (eq(u8, package.name, "sudo-rs")) {
                companions += 1;
                if (!eq(u8, package.version, "0.2.13-0ubuntu1.2") or !eq(u8, package.architecture, "amd64")) return error.SignedSudoPrestateExactCompanionRequired;
            };
            if (companions != 1) return error.SignedSudoPrestateExactCompanionRequired;
        }
    }
}
fn utf8Replace(a: A, bytes: []const u8) ![]const u8 {
    var result: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < bytes.len) {
        const first = bytes[index];
        const size: usize = if (first < 0x80) 1 else if (first >= 0xc2 and first <= 0xdf) 2 else if (first >= 0xe0 and first <= 0xef) 3 else if (first >= 0xf0 and first <= 0xf4) 4 else 0;
        var prefix: usize = 1;
        while (prefix < size and prefix < bytes.len - index) : (prefix += 1) {
            const next = bytes[index + prefix];
            if (next < 0x80 or next > 0xbf) break;
            if (prefix == 1 and ((first == 0xe0 and next < 0xa0) or (first == 0xed and next > 0x9f) or
                (first == 0xf0 and next < 0x90) or (first == 0xf4 and next > 0x8f))) break;
        }
        if (size == 0 or prefix != size) {
            try result.appendSlice(a, "\xef\xbf\xbd");
        } else try result.appendSlice(a, bytes[index..][0..size]);
        index += prefix;
    }
    return result.toOwnedSlice(a);
}
fn refusal(a: A, package: Package, operation: []const u8, result: Result) !Refusal {
    const prefix = result.stdout[0..@min(result.stdout.len, 4096)];
    const hex = try a.alloc(u8, prefix.len * 2);
    const digits = "0123456789abcdef";
    for (prefix, 0..) |byte, index| {
        hex[2 * index] = digits[byte >> 4];
        hex[2 * index + 1] = digits[byte & 15];
    }
    return .{ .selector = try package.selector(a), .operation = operation, .exit_status = result.code, .output_bytes = result.stdout.len, .output_prefix_hex = hex, .output_sha512 = try a.dupe(u8, &hash(std.crypto.hash.sha2.Sha512, result.stdout)) };
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    var values: std.StringHashMap([]const u8) = .init(a);
    var prestates: std.ArrayList(Prestate) = .empty;
    var report_only = false;
    var index: usize = 1;
    while (index < args.len) {
        const key = args[index];
        index += 1;
        if (eq(u8, key, "--report-only")) {
            report_only = true;
            continue;
        }
        if (index == args.len) return error.InvalidReferenceOrderArguments;
        const value = args[index];
        index += 1;
        if (eq(u8, key, "--prestate")) {
            try prestates.append(a, try parsePrestate(value));
            continue;
        }
        var accepted = false;
        for ([_][]const u8{ "--dpkg", "--root", "--cache", "--evidence", "--prove-base-cycle", "--launcher", "--runtime", "--architecture" }) |allowed|
            if (eq(u8, key, allowed)) {
                accepted = true;
            };
        if (!accepted) return error.InvalidReferenceOrderArguments;
        try values.put(key, value);
    }
    var environment: std.process.Environ.Map = .init(a);
    for ([_][2][]const u8{
        .{ "PATH", "/usr/sbin:/usr/bin:/sbin:/bin" }, .{ "HOME", "/" },                           .{ "LC_ALL", "C" },
        .{ "DEBIAN_FRONTEND", "noninteractive" },     .{ "DEBCONF_NONINTERACTIVE_SEEN", "true" }, .{ "DPKG_COLORS", "never" },
    }) |entry| try environment.put(entry[0], entry[1]);
    const root = values.get("--root") orelse return error.InvalidReferenceOrderArguments;
    const cache = values.get("--cache") orelse return error.InvalidReferenceOrderArguments;
    const evidence = values.get("--evidence") orelse return error.InvalidReferenceOrderArguments;
    const architecture = values.get("--architecture") orelse return error.InvalidReferenceOrderArguments;
    if (!eq(u8, architecture, "amd64") and !eq(u8, architecture, "arm64")) return error.InvalidReferenceOrderArguments;
    for ([_][]const u8{ root, cache, evidence }) |path| try paths.absolute(path);
    const context: Context = .{ .a = a, .io = init.io, .environment = &environment, .root = root, .cache = cache, .evidence = evidence, .architecture = architecture, .dpkg = values.get("--dpkg") orelse "", .launcher = .{ .path = values.get("--launcher") orelse "", .runtime = values.get("--runtime") orelse "" } };
    if (report_only) return context.report();
    _ = try paths.protected(context.launcher.path, false);
    _ = try paths.protected(context.dpkg, false);
    _ = try paths.protected(context.launcher.runtime, true);
    _ = try paths.protected(cache, true);
    _ = try paths.protected(evidence, true);
    if (values.get("--prove-base-cycle")) |setpriv| {
        if (!eq(u8, architecture, "amd64") or prestates.items.len != 0) return error.CycleProofPrestate;
        return proveBaseCycle(context, setpriv);
    }
    return context.install(prestates.items);
}

pub fn proveBaseCycle(ctx: Context, setpriv: []const u8) !void {
    const unit_proof = if (builtin.is_test) if (ctx.test_hooks) |hooks| hooks.assume_x86_64 else false else false;
    if ((builtin.cpu.arch != .x86_64 and !unit_proof) or (try ctx.database(ctx.root)).len != 0) return error.CycleProofPrestate;
    const unit_source = if (builtin.is_test) if (ctx.test_hooks) |hooks| hooks.runtime_unprotected else false else false;
    if (!unit_source) _ = try paths.protected(ctx.root, true);
    const setpriv_pin = try (if (unit_source) paths.openAbsolute(setpriv, false) else paths.openProtected(setpriv, false));
    defer setpriv_pin.close();
    const setpriv_bytes = try paths.readPinned(ctx.a, setpriv_pin, maximum_control_bytes);
    var setpriv_digest = hash(std.crypto.hash.sha2.Sha256, setpriv_bytes);
    if (builtin.is_test) if (ctx.test_hooks) |hooks| if (hooks.runtime_digest) |callback| if (callback(setpriv_bytes)) |provided| {
        setpriv_digest = provided;
    };
    if (!eq(u8, &setpriv_digest, "86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993"))
        return error.CycleProofRuntimeChanged;
    const cycle = try cyclePackages(ctx.a, try ctx.manifest(), "amd64", .base);
    const proof = try join(ctx.a, ctx.evidence, "base-cycle-proof");
    const evidence_pin = try paths.openAbsolute(ctx.evidence, true);
    defer evidence_pin.close();
    _ = try paths.syscall(linux.mkdirat(evidence_pin.fd, "base-cycle-proof", 0o700));
    const seed = try join(ctx.a, proof, "seed");
    try ctx.checked(&.{ "cp", "-a", "--one-file-system", "--", ctx.root, seed }, 60);
    for ([_]usize{ 2, 3, 0, 1 }) |index| {
        try ctx.archive(cycle[index]);
        try ctx.apply(try ctx.argvFor(seed, "none", "unpack", cycle[index], &.{}), proof, "unpack.stdout", "unpack.stderr");
    }
    for (cycle[2..]) |package| try ctx.apply(try ctx.argvFor(seed, "none", "configure", package, &.{}), proof, "unpack.stdout", "unpack.stderr");
    _ = try ctx.verifyCycle(seed, cycle, .base);
    for (cycle[0..2]) |package| {
        const result = try ctx.probe(try ctx.argvFor(seed, "none", "probe_configure", package, &.{}), proof);
        if (result.code == 0 or std.mem.indexOf(u8, result.stdout, "dependency problems") == null) return error.CycleProofMissingStall;
    }
    const candidate = try join(ctx.a, proof, "candidate");
    const baseline = try join(ctx.a, proof, "pending");
    for ([_][]const u8{ candidate, baseline }) |destination| try ctx.checked(&.{ "cp", "-a", "--one-file-system", "--", seed, destination }, 60);
    const refused_command = try ctx.argvFor(candidate, Cycle.base.profile(), Cycle.base.verb(), cycle[1], cycle);
    const before_refusal = try ctx.database(candidate);
    const before_triggers = try ctx.triggerDatabase(candidate);
    const injected = "var/lib/dpkg/info/libgcc-s1:amd64.postinst";
    const injected_path = try join(ctx.a, candidate, injected);
    try ctx.write(candidate, injected, "#!/bin/sh\necho unbound-cycle-callback-executed\nexit 0\n", false);
    try ctx.checked(&.{ "chmod", "0755", "--", try join(ctx.a, candidate, injected) }, 30);
    const refusal_result = blk: {
        defer ctx.checked(&.{ "rm", "--", injected_path }, 30) catch {};
        const observed = try ctx.probe(refused_command, proof);
        if (observed.code == 0 or std.mem.indexOf(u8, observed.stdout, "unbound-cycle-callback-executed") != null or
            std.mem.indexOf(u8, observed.stdout, "stage 11") == null or !conserved(before_refusal, try ctx.database(candidate), &.{}) or
            !objectsEqual(before_triggers, try ctx.triggerDatabase(candidate))) return error.CycleProofCallbackChanged;
        break :blk observed;
    };
    try ctx.write(proof, "callback-refusal.log", refusal_result.stdout, false);
    _ = try ctx.transition(candidate, proof, cycle, .base, "candidate.stdout", "candidate.stderr");
    if ((try ctx.database(baseline)).len != 4) return error.CycleProofCallbackChanged;
    _ = try ctx.verifyCycle(baseline, cycle, .base);
    var script_relative: ?[]const u8 = null;
    for ([_][]const u8{ "var/lib/dpkg/info/libc6.postinst", "var/lib/dpkg/info/libc6:amd64.postinst" }) |relative| {
        if (try paths.exists(baseline, relative)) {
            if (script_relative != null) return error.CycleProofCallbackChanged;
            script_relative = relative;
        }
    }
    const relative = script_relative orelse return error.CycleProofCallbackChanged;
    const script = try join(ctx.a, baseline, relative);
    const signed_script = try member(try ctx.control(cycle[0]), "./postinst");
    if (signed_script.len == 0 or !eq(u8, signed_script, try ctx.read(baseline, relative, maximum_probe_output))) return error.CycleProofCallbackChanged;
    try ctx.checked(&.{ "cp", "--", ctx.dpkg, try join(ctx.a, baseline, "usr/bin/dpkg") }, 30);
    try ctx.checked(&.{ "cp", "--", setpriv, try join(ctx.a, baseline, "usr/bin/setpriv") }, 30);
    try ctx.checked(&.{ "chmod", "0755", "--", try join(ctx.a, baseline, "usr/bin/setpriv") }, 30);
    const runtime = try stagePendingRuntime(ctx, baseline, setpriv);
    const before_pending = try ctx.database(baseline);
    try ctx.checked(&.{ "mount", "--bind", "--", script, script }, 30);
    const command: []const []const u8 = &.{
        "unshare",          "--mount",                                                                           "--pid",           "--fork",              "--kill-child=SIGKILL", "--propagation", "private",  "--",               "chroot",           baseline,
        "/usr/bin/setpriv", "--bounding-set=-all,+chown,+dac_override,+fowner,+fsetid,+setgid,+setuid,+setfcap", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",       "/usr/bin/dpkg", "--root=/", "--force-not-root", "--force-bad-path", "--force-confold",
        "--no-triggers",    "--configure",                                                                       "--pending",
    };
    const observed = blk: {
        errdefer ctx.checked(&.{ "umount", "--", script }, 30) catch {};
        try ctx.checked(&.{ "mount", "-o", "remount,bind,ro,noexec,nosuid,nodev", "--", script }, 30);
        const scratch_dir = try ctx.scratch(proof, "reference-pending");
        defer ctx.cleanupScratch(scratch_dir, &.{ "stdout", "stderr" });
        const result = try ctx.capture(command, scratch_dir, "stdout", "stderr", 120);
        try recordPendingResult(ctx, proof, command, result, runtime);
        break :blk result;
    };
    try ctx.checked(&.{ "umount", "--", script }, 30);
    const after_pending = try ctx.database(baseline);
    try ctx.json(proof, "pending-status.json", .{ .before = before_pending, .after = after_pending, .trigger_database = try ctx.triggerDatabase(baseline) });
    try validatePendingResult(observed);
    if (!eq(u8, signed_script, try ctx.read(baseline, relative, maximum_probe_output))) return error.CycleProofCallbackChanged;
    const wanted = try ctx.database(candidate);
    const expected = try ctx.a.alloc(Fields, wanted.len);
    for (wanted, expected) |record, *copy| {
        copy.* = try record.clone(ctx.a);
        if (eq(u8, field(record, "package"), "libc6") and eq(u8, field(record, "architecture"), "amd64"))
            try copy.put(ctx.a, "status", .{ .string = "install ok half-configured" });
    }
    if (!conserved(expected, after_pending, &.{})) return error.CycleProofScheduleChanged;
    try ctx.json(proof, "comparison.json", .{
        .schema = "io.github.cataggar.debz.base-cycle-proof.v1",
        .callbacks_executed = @as([]const []const u8, &.{}),
        .callback_denied = "libc6 postinst configure",
        .candidate = wanted,
        .pending = after_pending,
        .candidate_trigger_database = try ctx.triggerDatabase(candidate),
        .pending_trigger_database = try ctx.triggerDatabase(baseline),
        .pending_argv = command,
        .pending_setpriv_runtime = runtime,
        .difference = "pending attempts libc6 configure; single breaker leaves libc6 unpacked",
        .parity_claim = false,
    });
    for ([_][]const u8{ seed, candidate, baseline }) |destination| try ctx.checked(&.{ "rm", "-rf", "--one-file-system", "--", destination }, 60);
}
pub const PendingRuntime = struct { source: []const u8, target: []const u8, sha256: []const u8, size: usize, mode: []const u8 };
pub fn recordPendingResult(ctx: Context, proof: []const u8, command: []const []const u8, result: Result, runtime: PendingRuntime) !void {
    try ctx.write(proof, "pending.stdout", result.stdout[0..@min(result.stdout.len, maximum_probe_output)], false);
    try ctx.write(proof, "pending.stderr", result.stderr[0..@min(result.stderr.len, maximum_probe_output)], false);
    try ctx.json(proof, "pending-result.json", .{
        .schema = "io.github.cataggar.debz.base-cycle-pending-result.v1",
        .argv = command,
        .returncode = result.code,
        .setpriv_runtime = runtime,
        .stdout_bytes = result.stdout_bytes,
        .stderr_bytes = result.stderr_bytes,
        .output_truncated = result.stdout_bytes > maximum_probe_output or result.stderr_bytes > maximum_probe_output,
    });
}
pub fn validatePendingResult(result: Result) !void {
    if (result.stdout_bytes > maximum_probe_output or result.stderr_bytes > maximum_probe_output or result.code == 0 or
        std.mem.indexOf(u8, result.stderr, "Permission denied") == null or std.mem.indexOf(u8, result.stderr, "post-installation script") == null)
        return error.CycleProofCallbackChanged;
}
pub fn stagePendingRuntime(ctx: Context, baseline: []const u8, setpriv: []const u8) !PendingRuntime {
    const parent = std.fs.path.dirname(setpriv).?;
    const source = try join(ctx.a, parent, "libcap-ng.so.0.0.0");
    const unit_source = if (builtin.is_test) if (ctx.test_hooks) |hooks| hooks.runtime_unprotected else false else false;
    const pin = (if (unit_source) paths.openAbsolute(source, false) else paths.openProtected(source, false)) catch return error.CycleProofRuntimeChanged;
    defer pin.close();
    if (pin.metadata.size != 26928 or pin.metadata.mode & 0o7777 != 0o644) return error.CycleProofRuntimeChanged;
    const data = try paths.readPinned(ctx.a, pin, 26928);
    var digest_bytes = hash(std.crypto.hash.sha2.Sha256, data);
    if (builtin.is_test) if (ctx.test_hooks) |hooks| if (hooks.runtime_digest) |callback| if (callback(data)) |provided| {
        digest_bytes = provided;
    };
    const digest = try ctx.a.dupe(u8, &digest_bytes);
    if (!eq(u8, digest, "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f")) return error.CycleProofRuntimeChanged;
    const target = "usr/lib/x86_64-linux-gnu/libcap-ng.so.0";
    if (!unit_source) _ = paths.protected(try join(ctx.a, baseline, "usr/lib/x86_64-linux-gnu"), true) catch return error.CycleProofRuntimeChanged;
    const fd = paths.create(baseline, target, 0o644, false) catch return error.CycleProofRuntimeChanged;
    defer _ = linux.close(fd);
    try paths.writeAll(fd, data);
    _ = try paths.syscall(linux.fchmod(fd, 0o644));
    return .{ .source = source, .target = target, .sha256 = digest, .size = data.len, .mode = "0644" };
}

test "original status records retain valueless continuations and reject ambiguous identities" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const valid = "Package: demo\nArchitecture: amd64\nVersion: 1\nStatus: install ok unpacked\nConffiles:\n /etc/demo.conf 0123456789abcdef\n\n";
    const records = try parseDatabase(a, valid);
    try std.testing.expectEqualStrings("\n /etc/demo.conf 0123456789abcdef", field(records[0], "conffiles"));
    for ([_][]const u8{ "Priority:optional", "Bad Key: x", "Conffiles" }) |malformed| {
        const data = try std.fmt.allocPrint(a, "{s}{s}\n", .{ valid[0 .. valid.len - 1], malformed });
        try std.testing.expectError(error.MalformedReferenceDatabaseField, controlFields(a, data));
    }
    try std.testing.expectError(error.DuplicateReferenceDatabaseField, controlFields(a, "Package: demo\npackage: other\n"));
    try std.testing.expectError(error.InvalidReferenceIdentityContinuation, controlFields(a, "Package: demo\n changed\n"));
}

test "normal command binding refuses triggers pending mixed selectors and wrong signed profiles" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const launcher: Launcher = .{ .path = "/launcher", .runtime = "/runtime" };
    const package: Package = .{ .name = "sudo", .version = "1.9.17p2-1ubuntu3.1", .architecture = "amd64", .digest = "a" ** 128, .size = 42, .archive = "/sudo.deb" };
    const command = try dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "sudo", "configure", package, &.{});
    try std.testing.expectEqualStrings("sudo:amd64", command[6]);
    for ([_][]const u8{ "triggers_only", "triggers_pending", "configure_pending" }) |verb|
        try std.testing.expectError(error.NoSingleScriptBinding, dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "sudo", verb, package, &.{}));
    try std.testing.expectError(error.MissingExactConfigureProfile, dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "none", "configure", package, &.{}));
    try std.testing.expectError(error.UnauthorizedReferenceScriptProfile, dpkgCommand(a, launcher, "/dpkg", "/root", "arm64", "sudo", "configure", package, &.{}));
    try std.testing.expectError(error.UnauthorizedHalfConfiguredContinuation, dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "sudo", "continue_prestate", package, &.{}));
}

test "five-field original TSV enforces duplicates decimal bounds and empty closures" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const line = "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t42\n";
    const package = (try packagesFromManifest(a, line, "/cache"))[0];
    try std.testing.expectEqualStrings("/cache/packages-v2/objects/sha512-" ++ "a" ** 128, package.archive);
    try std.testing.expectError(error.DuplicateReferencePackage, packagesFromManifest(a, line ++ line, "/cache"));
    try std.testing.expectError(error.InvalidReferenceArchiveManifest, packagesFromManifest(a, "demo\t1\tamd64\ta\t42\textra\n", "/cache"));
    try std.testing.expectError(error.InvalidReferenceArchiveSize, packagesFromManifest(a, "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t0\n", "/cache"));
    try std.testing.expectError(error.InvalidReferenceArchiveSize, packagesFromManifest(a, "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t536870913\n", "/cache"));
    try std.testing.expectError(error.InvalidReferencePackageIdentity, packagesFromManifest(a, "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t+42\n", "/cache"));
    try std.testing.expectError(error.EmptyReferenceClosure, packagesFromManifest(a, "", "/cache"));
}

test "original refusal diagnostics use Python replacement boundaries without altering raw observations" {
    const replacement = "\xef\xbf\xbd";
    for ([_][2][]const u8{
        .{ "ok\xc2\xa0\xe2\x82\xac\xf0\x90\x80\x80", "ok\xc2\xa0\xe2\x82\xac\xf0\x90\x80\x80" },
        .{ "\xe2\x82", replacement },
        .{ "\xf0\x90\x80", replacement },
        .{ "\xe2\x82!", replacement ++ "!" },
        .{ "\xe2!", replacement ++ "!" },
        .{ "\xe0\x9f\x80", replacement ** 3 },
        .{ "\xed\xa0\x80", replacement ** 3 },
        .{ "\xf4\x90\x80\x80", replacement ** 4 },
        .{ "\xf5\x80\x80\x80", replacement ** 4 },
        .{ "\xc0\x80\xff", replacement ** 3 },
    }) |example| {
        const observed = try utf8Replace(std.testing.allocator, example[0]);
        defer std.testing.allocator.free(observed);
        try std.testing.expectEqualStrings(example[1], observed);
    }
}

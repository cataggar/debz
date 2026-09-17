//! Canonical Linux package paths. Backslashes are literal filename bytes,
//! never separators or escape sequences. External authority paths use the
//! stricter grammar in absolute_path.zig.
const std = @import("std");

pub const absolute_schema_pattern =
    \\^/(?!\.{1,2}(?:/|$))[^/\u0000-\u001f\u007f]+(?:/(?!\.{1,2}(?:/|$))[^/\u0000-\u001f\u007f]+)*(?![\s\S])
;

pub fn relative(path: []const u8) bool {
    if (path.len == 0 or !std.unicode.utf8ValidateSlice(path)) return false;
    for (path) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

pub fn canonical(path: []const u8, allow_root: bool) bool {
    if (path.len == 0 or path[0] != '/') return false;
    if (path.len == 1) return allow_root;
    return relative(path[1..]);
}

pub fn nonRoot(path: []const u8) bool {
    return canonical(path, false);
}

test "package_path.test.literal Linux names retain traversal and encoding guards" {
    const path = "/usr/lib/systemd/system/system-systemd\\x2dmute\\x2dconsole.slice";
    try std.testing.expect(nonRoot(path));
    try std.testing.expect(relative(path[1..]));
    try std.testing.expect(relative("literal\\..\\name"));
    try std.testing.expect(nonRoot("/literal\\directory/file"));
    try std.testing.expect(!nonRoot("/"));
    try std.testing.expect(canonical("/", true));
    inline for ([_][]const u8{
        "",                        "/absolute",             "trailing/",   "double//component", ".",                 "..",
        "literal\\name/../escape", "literal\\name/./file",  "nul\x00byte", "line\nbreak",       "unit\x1fseparator", "delete\x7fcharacter",
        "invalid\xc3\x28utf8",     "surrogate\xed\xa0\x80",
    }) |invalid| try std.testing.expect(!relative(invalid));
}

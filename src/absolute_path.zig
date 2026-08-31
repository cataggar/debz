const std = @import("std");

pub const schema_pattern =
    \\^(?:/|/(?!\.{1,2}(?:/|$))[^/\\\u0000-\u001f\u007f]+(?:/(?!\.{1,2}(?:/|$))[^/\\\u0000-\u001f\u007f]+)*)$
;

pub fn canonical(path: []const u8, allow_root: bool) bool {
    if (!std.unicode.utf8ValidateSlice(path) or
        path.len == 0 or
        path[0] != '/' or
        std.mem.indexOfScalar(u8, path, '\\') != null)
        return false;
    for (path) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    if (path.len == 1) return allow_root;
    if (path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return false;
    }
    return true;
}

pub fn root(path: []const u8) bool {
    return canonical(path, true);
}

pub fn logical(path: []const u8) bool {
    return canonical(path, true);
}

pub fn nonRoot(path: []const u8) bool {
    return canonical(path, false);
}

test "absolute_path.test.canonical grammar rejects invalid unicode and controls" {
    try std.testing.expect(root("/"));
    try std.testing.expect(nonRoot("/srv/roots/\xc3\xa9"));
    inline for ([_][]const u8{
        "",
        "relative",
        "/trailing/",
        "/double//component",
        "/.",
        "/..",
        "/a/../b",
        "/back\\slash",
        "/nul\x00byte",
        "/line\nbreak",
        "/unit\x1fseparator",
        "/delete\x7fcharacter",
        "/invalid\xc3\x28utf8",
        "/surrogate\xed\xa0\x80",
    }) |invalid| try std.testing.expect(!root(invalid));
    try std.testing.expect(!nonRoot("/"));
}

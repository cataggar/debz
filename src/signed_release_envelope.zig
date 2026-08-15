const std = @import("std");

pub const ByteRange = struct {
    start: usize,
    end: usize,

    pub fn slice(self: ByteRange, source: []const u8) []const u8 {
        return source[self.start..self.end];
    }
};

pub const Limits = struct {
    max_input_bytes: usize = 16 * 1024 * 1024,
    max_cleartext_bytes: usize = 8 * 1024 * 1024,
    max_header_count: usize = 32,
    max_header_bytes: usize = 16 * 1024,
    max_header_line_bytes: usize = 4096,
    max_signature_count: usize = 16,
    max_signature_bytes: usize = 2 * 1024 * 1024,
    max_armor_line_bytes: usize = 76,
};

pub const InputPart = enum {
    in_release,
    release,
    detached_signature,
};

pub const DiagnosticCode = enum {
    input_too_large,
    missing_signed_message_begin,
    invalid_line_ending,
    missing_hash_header,
    invalid_cleartext_header,
    duplicate_header,
    too_many_headers,
    headers_too_large,
    header_line_too_large,
    missing_header_separator,
    cleartext_too_large,
    invalid_dash_escape,
    missing_signature_begin,
    missing_signature_end,
    trailing_garbage,
    invalid_armor_header,
    armor_line_too_large,
    invalid_base64,
    invalid_base64_padding,
    duplicate_crc,
    duplicate_armor_section,
    invalid_crc,
    crc_mismatch,
    signature_too_large,
    too_many_signatures,
    empty_signature,
    invalid_packet_header,
    truncated_packet,
    partial_packet_length,
    indeterminate_packet_length,
    non_signature_packet,
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    input: InputPart,
    range: ByteRange,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .input_too_large => "signed envelope input exceeds the configured byte limit",
            .missing_signed_message_begin => "InRelease must begin with the OpenPGP signed-message armor line",
            .invalid_line_ending => "armor uses a bare carriage return",
            .missing_hash_header => "cleartext armor must declare at least one Hash header",
            .invalid_cleartext_header => "only well-formed Hash headers are allowed before cleartext",
            .duplicate_header => "armor repeats a header name",
            .too_many_headers => "armor exceeds the configured header count",
            .headers_too_large => "armor headers exceed the configured byte limit",
            .header_line_too_large => "armor header exceeds the configured line limit",
            .missing_header_separator => "armor headers must be followed by an empty line",
            .cleartext_too_large => "cleartext exceeds the configured byte limit",
            .invalid_dash_escape => "cleartext line beginning with '-' must use exact '- ' dash escaping",
            .missing_signature_begin => "cleartext is not followed by a signature armor block",
            .missing_signature_end => "signature armor end line is missing",
            .trailing_garbage => "data follows the final signature armor block",
            .invalid_armor_header => "signature armor contains an invalid header",
            .armor_line_too_large => "signature armor line exceeds the configured limit",
            .invalid_base64 => "signature armor contains non-base64 data",
            .invalid_base64_padding => "signature armor has invalid base64 padding",
            .duplicate_crc => "signature armor contains more than one CRC24 line",
            .duplicate_armor_section => "detached signatures repeat an armor section",
            .invalid_crc => "signature armor CRC24 is not exactly four base64 characters",
            .crc_mismatch => "signature armor CRC24 does not match its decoded bytes",
            .signature_too_large => "signature bytes exceed the configured limit",
            .too_many_signatures => "signature input exceeds the configured signature count",
            .empty_signature => "signature input contains no signature packet",
            .invalid_packet_header => "signature blob contains an invalid OpenPGP packet header",
            .truncated_packet => "signature packet is truncated",
            .partial_packet_length => "partial body lengths are not accepted for signature packets",
            .indeterminate_packet_length => "indeterminate old-format packet lengths are not accepted",
            .non_signature_packet => "signature blob contains a packet other than a Signature packet",
        };
    }
};

pub const ArmorHeader = struct {
    name: ByteRange,
    value: ByteRange,
    line: ByteRange,
};

/// A declared digest name is syntax only. It is never a verification result or
/// an assertion that the named digest is acceptable.
pub const DeclaredHash = struct {
    value: ByteRange,
    line: ByteRange,
};

pub const SignatureEncoding = enum {
    binary,
    ascii_armor,
};

/// Owns `bytes`, `packet_ranges`, and `headers`. Source ranges refer to the
/// signature input passed to the parser.
pub const SignatureBlob = struct {
    encoding: SignatureEncoding,
    source_range: ByteRange,
    body_range: ByteRange,
    bytes: []u8,
    packet_ranges: []ByteRange,
    headers: []ArmorHeader,

    fn deinit(self: *SignatureBlob, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.packet_ranges);
        allocator.free(self.headers);
        self.* = undefined;
    }
};

/// Owns transformed cleartext and signature storage; `source` remains borrowed.
/// `display_cleartext` reverses only OpenPGP dash escaping and retains the
/// source line endings. `canonical_cleartext` contains the exact CRLF text
/// bytes to pass to an OpenPGP text-signature verifier.
pub const InReleaseEnvelope = struct {
    source: []const u8,
    envelope_range: ByteRange,
    cleartext_source_range: ByteRange,
    display_cleartext: []u8,
    canonical_cleartext: []u8,
    declared_hashes: []DeclaredHash,
    signature: SignatureBlob,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *InReleaseEnvelope) void {
        self.allocator.free(self.display_cleartext);
        self.allocator.free(self.canonical_cleartext);
        self.allocator.free(self.declared_hashes);
        self.signature.deinit(self.allocator);
        self.* = undefined;
    }
};

/// Borrows `release_bytes` exactly as provided and owns parsed signature blobs.
pub const DetachedEnvelope = struct {
    release_bytes: []const u8,
    release_range: ByteRange,
    signature_source: []const u8,
    signatures: []SignatureBlob,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DetachedEnvelope) void {
        for (self.signatures) |*signature| signature.deinit(self.allocator);
        self.allocator.free(self.signatures);
        self.* = undefined;
    }
};

pub const InReleaseResult = union(enum) {
    envelope: InReleaseEnvelope,
    diagnostic: Diagnostic,
};

pub const DetachedResult = union(enum) {
    envelope: DetachedEnvelope,
    diagnostic: Diagnostic,
};

const signed_begin = "-----BEGIN PGP SIGNED MESSAGE-----";
const signature_begin = "-----BEGIN PGP SIGNATURE-----";
const signature_end = "-----END PGP SIGNATURE-----";

const Line = struct {
    text: ByteRange,
    full: ByteRange,
    ending: enum { none, lf, crlf },
};

const LineResult = union(enum) {
    line: Line,
    diagnostic: Diagnostic,
};

fn nextLine(source: []const u8, start: usize, input: InputPart) LineResult {
    var index = start;
    while (index < source.len and source[index] != '\n' and source[index] != '\r') : (index += 1) {}
    if (index == source.len) return .{ .line = .{
        .text = .{ .start = start, .end = index },
        .full = .{ .start = start, .end = index },
        .ending = .none,
    } };
    if (source[index] == '\r') {
        if (index + 1 >= source.len or source[index + 1] != '\n') {
            return .{ .diagnostic = diag(.invalid_line_ending, input, index, index + 1) };
        }
        return .{ .line = .{
            .text = .{ .start = start, .end = index },
            .full = .{ .start = start, .end = index + 2 },
            .ending = .crlf,
        } };
    }
    return .{ .line = .{
        .text = .{ .start = start, .end = index },
        .full = .{ .start = start, .end = index + 1 },
        .ending = .lf,
    } };
}

fn diag(code: DiagnosticCode, input: InputPart, start: usize, end: usize) Diagnostic {
    return .{ .code = code, .input = input, .range = .{ .start = start, .end = end } };
}

pub fn parseInRelease(
    allocator: std.mem.Allocator,
    source: []const u8,
    limits: Limits,
) std.mem.Allocator.Error!InReleaseResult {
    if (source.len > limits.max_input_bytes)
        return .{ .diagnostic = diag(.input_too_large, .in_release, limits.max_input_bytes, source.len) };

    var offset: usize = 0;
    const first = switch (nextLine(source, offset, .in_release)) {
        .line => |line| line,
        .diagnostic => |value| return .{ .diagnostic = value },
    };
    if (!std.mem.eql(u8, first.text.slice(source), signed_begin))
        return .{ .diagnostic = diag(.missing_signed_message_begin, .in_release, first.text.start, first.text.end) };
    if (first.ending == .none)
        return .{ .diagnostic = diag(.missing_hash_header, .in_release, first.text.end, first.text.end) };
    offset = first.full.end;

    var hashes: std.ArrayList(DeclaredHash) = .empty;
    defer hashes.deinit(allocator);
    var header_bytes: usize = 0;
    while (true) {
        const line = switch (nextLine(source, offset, .in_release)) {
            .line => |value| value,
            .diagnostic => |value| return .{ .diagnostic = value },
        };
        if (line.text.start == line.text.end) {
            if (line.ending == .none)
                return .{ .diagnostic = diag(.missing_header_separator, .in_release, line.text.start, line.text.end) };
            offset = line.full.end;
            break;
        }
        if (line.text.end - line.text.start > limits.max_header_line_bytes)
            return .{ .diagnostic = diag(.header_line_too_large, .in_release, line.text.start, line.text.end) };
        header_bytes = std.math.add(usize, header_bytes, line.full.end - line.full.start) catch
            return .{ .diagnostic = diag(.headers_too_large, .in_release, line.text.start, line.text.end) };
        if (header_bytes > limits.max_header_bytes)
            return .{ .diagnostic = diag(.headers_too_large, .in_release, line.text.start, line.text.end) };
        if (hashes.items.len >= limits.max_header_count)
            return .{ .diagnostic = diag(.too_many_headers, .in_release, line.text.start, line.text.end) };
        const text = line.text.slice(source);
        if (!std.mem.startsWith(u8, text, "Hash:") or text.len == 5)
            return .{ .diagnostic = diag(.invalid_cleartext_header, .in_release, line.text.start, line.text.end) };
        var value_start = line.text.start + 5;
        while (value_start < line.text.end and (source[value_start] == ' ' or source[value_start] == '\t'))
            value_start += 1;
        if (value_start == line.text.end)
            return .{ .diagnostic = diag(.invalid_cleartext_header, .in_release, line.text.start, line.text.end) };
        if (!validHashList(source[value_start..line.text.end]))
            return .{ .diagnostic = diag(.invalid_cleartext_header, .in_release, value_start, line.text.end) };
        try hashes.append(allocator, .{
            .value = .{ .start = value_start, .end = line.text.end },
            .line = line.text,
        });
        offset = line.full.end;
    }
    if (hashes.items.len == 0)
        return .{ .diagnostic = diag(.missing_hash_header, .in_release, offset, offset) };

    const cleartext_start = offset;
    var display: std.ArrayList(u8) = .empty;
    defer display.deinit(allocator);
    var canonical: std.ArrayList(u8) = .empty;
    defer canonical.deinit(allocator);
    var cleartext_end = offset;
    var found_signature = false;
    while (offset < source.len) {
        const line = switch (nextLine(source, offset, .in_release)) {
            .line => |value| value,
            .diagnostic => |value| return .{ .diagnostic = value },
        };
        if (std.mem.eql(u8, line.text.slice(source), signature_begin)) {
            found_signature = true;
            cleartext_end = line.text.start;
            break;
        }
        if (line.ending == .none)
            return .{ .diagnostic = diag(.missing_signature_begin, .in_release, line.text.start, line.text.end) };

        var text = line.text.slice(source);
        if (std.mem.startsWith(u8, text, "- ")) {
            text = text[2..];
        } else if (std.mem.startsWith(u8, text, "-")) {
            return .{ .diagnostic = diag(.invalid_dash_escape, .in_release, line.text.start, @min(line.text.start + 2, line.text.end)) };
        }
        const display_needed = std.math.add(usize, display.items.len, text.len + line.full.end - line.text.end) catch
            return .{ .diagnostic = diag(.cleartext_too_large, .in_release, line.text.start, line.text.end) };
        const canonical_needed = std.math.add(usize, canonical.items.len, text.len + 2) catch
            return .{ .diagnostic = diag(.cleartext_too_large, .in_release, line.text.start, line.text.end) };
        if (display_needed > limits.max_cleartext_bytes or canonical_needed > limits.max_cleartext_bytes)
            return .{ .diagnostic = diag(.cleartext_too_large, .in_release, line.text.start, line.text.end) };
        try display.appendSlice(allocator, text);
        try display.appendSlice(allocator, source[line.text.end..line.full.end]);
        try canonical.appendSlice(allocator, std.mem.trimEnd(u8, text, " \t"));
        try canonical.appendSlice(allocator, "\r\n");
        offset = line.full.end;
    }
    if (!found_signature)
        return .{ .diagnostic = diag(.missing_signature_begin, .in_release, source.len, source.len) };

    const parsed_armor = try parseArmorBlock(allocator, source, offset, limits, .in_release);
    var signature = switch (parsed_armor) {
        .blob => |blob| blob,
        .diagnostic => |value| return .{ .diagnostic = value },
    };
    errdefer signature.deinit(allocator);
    if (signature.source_range.end != source.len)
        return .{ .diagnostic = diag(.trailing_garbage, .in_release, signature.source_range.end, source.len) };
    if (signature.packet_ranges.len != 1)
        return .{ .diagnostic = diag(.too_many_signatures, .in_release, signature.source_range.start, signature.source_range.end) };

    const display_owned = try display.toOwnedSlice(allocator);
    errdefer allocator.free(display_owned);
    const canonical_owned = try canonical.toOwnedSlice(allocator);
    errdefer allocator.free(canonical_owned);
    const hashes_owned = try hashes.toOwnedSlice(allocator);
    errdefer allocator.free(hashes_owned);
    return .{ .envelope = .{
        .source = source,
        .envelope_range = .{ .start = 0, .end = source.len },
        .cleartext_source_range = .{ .start = cleartext_start, .end = cleartext_end },
        .display_cleartext = display_owned,
        .canonical_cleartext = canonical_owned,
        .declared_hashes = hashes_owned,
        .signature = signature,
        .allocator = allocator,
    } };
}

pub fn parseDetached(
    allocator: std.mem.Allocator,
    release_bytes: []const u8,
    signature_source: []const u8,
    limits: Limits,
) std.mem.Allocator.Error!DetachedResult {
    if (release_bytes.len > limits.max_input_bytes)
        return .{ .diagnostic = diag(.input_too_large, .release, limits.max_input_bytes, release_bytes.len) };
    if (signature_source.len > limits.max_input_bytes)
        return .{ .diagnostic = diag(.input_too_large, .detached_signature, limits.max_input_bytes, signature_source.len) };
    if (signature_source.len == 0)
        return .{ .diagnostic = diag(.empty_signature, .detached_signature, 0, 0) };

    var blobs: std.ArrayList(SignatureBlob) = .empty;
    defer {
        for (blobs.items) |*blob| blob.deinit(allocator);
        blobs.deinit(allocator);
    }

    if (std.mem.startsWith(u8, signature_source, signature_begin)) {
        var offset: usize = 0;
        var signature_count: usize = 0;
        while (offset < signature_source.len) {
            const parsed = try parseArmorBlock(allocator, signature_source, offset, limits, .detached_signature);
            var blob = switch (parsed) {
                .blob => |value| value,
                .diagnostic => |value| return .{ .diagnostic = value },
            };
            signature_count = std.math.add(usize, signature_count, blob.packet_ranges.len) catch {
                blob.deinit(allocator);
                return .{ .diagnostic = diag(.too_many_signatures, .detached_signature, offset, signature_source.len) };
            };
            if (signature_count > limits.max_signature_count) {
                blob.deinit(allocator);
                return .{ .diagnostic = diag(.too_many_signatures, .detached_signature, offset, signature_source.len) };
            }
            for (blobs.items) |prior| {
                if (std.mem.eql(u8, prior.bytes, blob.bytes)) {
                    const duplicate_range = blob.source_range;
                    blob.deinit(allocator);
                    return .{ .diagnostic = diag(.duplicate_armor_section, .detached_signature, duplicate_range.start, duplicate_range.end) };
                }
            }
            blobs.append(allocator, blob) catch |err| {
                blob.deinit(allocator);
                return err;
            };
            offset = blob.source_range.end;
            if (offset < signature_source.len and !std.mem.startsWith(u8, signature_source[offset..], signature_begin))
                return .{ .diagnostic = diag(.trailing_garbage, .detached_signature, offset, signature_source.len) };
        }
    } else {
        const packet_result = try parsePackets(allocator, signature_source, limits, .detached_signature, 0);
        const ranges = switch (packet_result) {
            .ranges => |value| value,
            .diagnostic => |value| return .{ .diagnostic = value },
        };
        defer allocator.free(ranges);
        if (ranges.len > limits.max_signature_count)
            return .{ .diagnostic = diag(.too_many_signatures, .detached_signature, 0, signature_source.len) };
        for (ranges) |range| {
            const bytes = try allocator.dupe(u8, range.slice(signature_source));
            errdefer allocator.free(bytes);
            const local_ranges = try allocator.alloc(ByteRange, 1);
            errdefer allocator.free(local_ranges);
            local_ranges[0] = .{ .start = 0, .end = bytes.len };
            try blobs.append(allocator, .{
                .encoding = .binary,
                .source_range = range,
                .body_range = range,
                .bytes = bytes,
                .packet_ranges = local_ranges,
                .headers = &.{},
            });
        }
    }
    if (blobs.items.len == 0)
        return .{ .diagnostic = diag(.empty_signature, .detached_signature, 0, signature_source.len) };
    return .{ .envelope = .{
        .release_bytes = release_bytes,
        .release_range = .{ .start = 0, .end = release_bytes.len },
        .signature_source = signature_source,
        .signatures = try blobs.toOwnedSlice(allocator),
        .allocator = allocator,
    } };
}

const ArmorResult = union(enum) {
    blob: SignatureBlob,
    diagnostic: Diagnostic,
};

fn parseArmorBlock(
    allocator: std.mem.Allocator,
    source: []const u8,
    start: usize,
    limits: Limits,
    input: InputPart,
) std.mem.Allocator.Error!ArmorResult {
    var offset = start;
    const begin = switch (nextLine(source, offset, input)) {
        .line => |line| line,
        .diagnostic => |value| return .{ .diagnostic = value },
    };
    if (!std.mem.eql(u8, begin.text.slice(source), signature_begin))
        return .{ .diagnostic = diag(.missing_signature_begin, input, begin.text.start, begin.text.end) };
    if (begin.ending == .none)
        return .{ .diagnostic = diag(.missing_header_separator, input, begin.text.end, begin.text.end) };
    offset = begin.full.end;

    var headers: std.ArrayList(ArmorHeader) = .empty;
    defer headers.deinit(allocator);
    var header_bytes: usize = 0;
    while (true) {
        const line = switch (nextLine(source, offset, input)) {
            .line => |value| value,
            .diagnostic => |value| return .{ .diagnostic = value },
        };
        if (line.text.start == line.text.end) {
            if (line.ending == .none)
                return .{ .diagnostic = diag(.missing_header_separator, input, line.text.start, line.text.end) };
            offset = line.full.end;
            break;
        }
        if (line.text.end - line.text.start > limits.max_header_line_bytes)
            return .{ .diagnostic = diag(.header_line_too_large, input, line.text.start, line.text.end) };
        if (headers.items.len >= limits.max_header_count)
            return .{ .diagnostic = diag(.too_many_headers, input, line.text.start, line.text.end) };
        header_bytes = std.math.add(usize, header_bytes, line.full.end - line.full.start) catch
            return .{ .diagnostic = diag(.headers_too_large, input, line.text.start, line.text.end) };
        if (header_bytes > limits.max_header_bytes)
            return .{ .diagnostic = diag(.headers_too_large, input, line.text.start, line.text.end) };
        const text = line.text.slice(source);
        const colon = std.mem.indexOfScalar(u8, text, ':') orelse
            return .{ .diagnostic = diag(.invalid_armor_header, input, line.text.start, line.text.end) };
        if (colon == 0 or colon + 1 >= text.len or text[colon + 1] != ' ')
            return .{ .diagnostic = diag(.invalid_armor_header, input, line.text.start, line.text.end) };
        for (text[0..colon]) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '-')
                return .{ .diagnostic = diag(.invalid_armor_header, input, line.text.start, line.text.start + colon) };
        }
        for (text[colon + 2 ..]) |byte| {
            if (byte < 0x20 or byte > 0x7e)
                return .{ .diagnostic = diag(.invalid_armor_header, input, line.text.start + colon + 2, line.text.end) };
        }
        const name = ByteRange{ .start = line.text.start, .end = line.text.start + colon };
        for (headers.items) |prior| {
            if (std.ascii.eqlIgnoreCase(name.slice(source), prior.name.slice(source)))
                return .{ .diagnostic = diag(.duplicate_header, input, name.start, name.end) };
        }
        try headers.append(allocator, .{
            .name = name,
            .value = .{ .start = name.end + 2, .end = line.text.end },
            .line = line.text,
        });
        offset = line.full.end;
    }

    const body_start = offset;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const encoded_limit = std.math.mul(usize, limits.max_signature_bytes, 2) catch std.math.maxInt(usize);
    var crc_value: ?[3]u8 = null;
    var crc_range: ?ByteRange = null;
    var saw_data = false;
    var saw_padding = false;
    var end_line: ?Line = null;
    while (offset < source.len) {
        const line = switch (nextLine(source, offset, input)) {
            .line => |value| value,
            .diagnostic => |value| return .{ .diagnostic = value },
        };
        const text = line.text.slice(source);
        if (std.mem.eql(u8, text, signature_end)) {
            end_line = line;
            break;
        }
        if (text.len > limits.max_armor_line_bytes)
            return .{ .diagnostic = diag(.armor_line_too_large, input, line.text.start, line.text.end) };
        if (text.len == 0)
            return .{ .diagnostic = diag(.invalid_base64, input, line.text.start, line.text.end) };
        if (text[0] == '=') {
            if (crc_value != null)
                return .{ .diagnostic = diag(.duplicate_crc, input, line.text.start, line.text.end) };
            if (text.len != 5)
                return .{ .diagnostic = diag(.invalid_crc, input, line.text.start, line.text.end) };
            var decoded_crc: [3]u8 = undefined;
            std.base64.standard.Decoder.decode(&decoded_crc, text[1..]) catch
                return .{ .diagnostic = diag(.invalid_crc, input, line.text.start, line.text.end) };
            crc_value = decoded_crc;
            crc_range = line.text;
        } else {
            if (crc_value != null)
                return .{ .diagnostic = diag(.invalid_crc, input, line.text.start, line.text.end) };
            if (saw_padding)
                return .{ .diagnostic = diag(.invalid_base64_padding, input, line.text.start, line.text.end) };
            for (text) |byte| {
                if (!std.ascii.isAlphanumeric(byte) and byte != '+' and byte != '/' and byte != '=')
                    return .{ .diagnostic = diag(.invalid_base64, input, line.text.start, line.text.end) };
            }
            saw_padding = std.mem.indexOfScalar(u8, text, '=') != null;
            const next_encoded_len = std.math.add(usize, encoded.items.len, text.len) catch
                return .{ .diagnostic = diag(.signature_too_large, input, line.text.start, line.text.end) };
            if (next_encoded_len > encoded_limit)
                return .{ .diagnostic = diag(.signature_too_large, input, line.text.start, line.text.end) };
            try encoded.appendSlice(allocator, text);
            saw_data = true;
        }
        if (line.ending == .none)
            return .{ .diagnostic = diag(.missing_signature_end, input, line.text.end, line.text.end) };
        offset = line.full.end;
    }
    const ending = end_line orelse
        return .{ .diagnostic = diag(.missing_signature_end, input, source.len, source.len) };
    if (!saw_data)
        return .{ .diagnostic = diag(.empty_signature, input, body_start, ending.text.start) };

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded.items) catch
        return .{ .diagnostic = diag(.invalid_base64_padding, input, body_start, ending.text.start) };
    if (decoded_len > limits.max_signature_bytes)
        return .{ .diagnostic = diag(.signature_too_large, input, body_start, ending.text.start) };
    const bytes = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(bytes);
    std.base64.standard.Decoder.decode(bytes, encoded.items) catch
        return .{ .diagnostic = diag(.invalid_base64_padding, input, body_start, ending.text.start) };
    if (crc_value) |expected| {
        const actual = crc24(bytes);
        if (!std.mem.eql(u8, &actual, &expected)) {
            const range = crc_range.?;
            allocator.free(bytes);
            return .{ .diagnostic = diag(.crc_mismatch, input, range.start, range.end) };
        }
    }

    const packet_result = try parsePackets(allocator, bytes, limits, input, body_start);
    const packet_ranges = switch (packet_result) {
        .ranges => |value| value,
        .diagnostic => |value| {
            allocator.free(bytes);
            return .{ .diagnostic = diag(value.code, input, body_start, ending.text.start) };
        },
    };
    errdefer allocator.free(packet_ranges);
    const owned_headers = try headers.toOwnedSlice(allocator);
    errdefer allocator.free(owned_headers);
    const source_end = ending.full.end;
    return .{ .blob = .{
        .encoding = .ascii_armor,
        .source_range = .{ .start = start, .end = source_end },
        .body_range = .{ .start = body_start, .end = ending.text.start },
        .bytes = bytes,
        .packet_ranges = packet_ranges,
        .headers = owned_headers,
    } };
}

const PacketResult = union(enum) {
    ranges: []ByteRange,
    diagnostic: Diagnostic,
};

fn parsePackets(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
    input: InputPart,
    source_base: usize,
) std.mem.Allocator.Error!PacketResult {
    var ranges: std.ArrayList(ByteRange) = .empty;
    defer ranges.deinit(allocator);
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (ranges.items.len >= limits.max_signature_count)
            return .{ .diagnostic = diag(.too_many_signatures, input, source_base + offset, source_base + bytes.len) };
        const packet_start = offset;
        const first = bytes[offset];
        if (first & 0x80 == 0)
            return .{ .diagnostic = diag(.invalid_packet_header, input, source_base + offset, source_base + offset + 1) };
        offset += 1;
        var body_len: usize = 0;
        if (first & 0x40 != 0) {
            if (first & 0x3f != 2)
                return .{ .diagnostic = diag(.non_signature_packet, input, source_base + packet_start, source_base + offset) };
            if (offset >= bytes.len)
                return .{ .diagnostic = diag(.truncated_packet, input, source_base + offset, source_base + bytes.len) };
            const length_first = bytes[offset];
            offset += 1;
            if (length_first < 192) {
                body_len = length_first;
            } else if (length_first < 224) {
                if (offset >= bytes.len)
                    return .{ .diagnostic = diag(.truncated_packet, input, source_base + offset, source_base + bytes.len) };
                body_len = (@as(usize, length_first) - 192) * 256 + bytes[offset] + 192;
                offset += 1;
            } else if (length_first == 255) {
                if (offset + 4 > bytes.len)
                    return .{ .diagnostic = diag(.truncated_packet, input, source_base + offset, source_base + bytes.len) };
                body_len = std.mem.readInt(u32, bytes[offset..][0..4], .big);
                offset += 4;
            } else {
                return .{ .diagnostic = diag(.partial_packet_length, input, source_base + offset - 1, source_base + offset) };
            }
        } else {
            if ((first >> 2) & 0x0f != 2)
                return .{ .diagnostic = diag(.non_signature_packet, input, source_base + packet_start, source_base + offset) };
            const length_type = first & 0x03;
            const length_bytes: usize = switch (length_type) {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => return .{ .diagnostic = diag(.indeterminate_packet_length, input, source_base + packet_start, source_base + offset) },
                else => unreachable,
            };
            if (offset + length_bytes > bytes.len)
                return .{ .diagnostic = diag(.truncated_packet, input, source_base + offset, source_base + bytes.len) };
            body_len = switch (length_bytes) {
                1 => bytes[offset],
                2 => std.mem.readInt(u16, bytes[offset..][0..2], .big),
                4 => std.mem.readInt(u32, bytes[offset..][0..4], .big),
                else => unreachable,
            };
            offset += length_bytes;
        }
        const packet_end = std.math.add(usize, offset, body_len) catch
            return .{ .diagnostic = diag(.truncated_packet, input, source_base + offset, source_base + bytes.len) };
        if (packet_end > bytes.len)
            return .{ .diagnostic = diag(.truncated_packet, input, source_base + offset, source_base + bytes.len) };
        if (packet_end - packet_start > limits.max_signature_bytes)
            return .{ .diagnostic = diag(.signature_too_large, input, source_base + packet_start, source_base + packet_end) };
        try ranges.append(allocator, .{ .start = packet_start, .end = packet_end });
        offset = packet_end;
    }
    if (ranges.items.len == 0)
        return .{ .diagnostic = diag(.empty_signature, input, source_base, source_base) };
    return .{ .ranges = try ranges.toOwnedSlice(allocator) };
}

fn crc24(bytes: []const u8) [3]u8 {
    var crc: u32 = 0xB704CE;
    for (bytes) |byte| {
        crc ^= @as(u32, byte) << 16;
        for (0..8) |_| {
            crc <<= 1;
            if (crc & 0x1000000 != 0) crc ^= 0x1864CFB;
        }
    }
    return .{
        @intCast((crc >> 16) & 0xff),
        @intCast((crc >> 8) & 0xff),
        @intCast(crc & 0xff),
    };
}

fn validHashList(value: []const u8) bool {
    var rest = value;
    while (true) {
        rest = std.mem.trim(u8, rest, " \t");
        if (rest.len == 0) return false;
        const comma = std.mem.indexOfScalar(u8, rest, ',');
        const token = std.mem.trim(u8, if (comma) |index| rest[0..index] else rest, " \t");
        if (token.len == 0 or !std.ascii.isAlphanumeric(token[0])) return false;
        for (token[1..]) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
        }
        if (comma) |index| {
            rest = rest[index + 1 ..];
        } else {
            return true;
        }
    }
}

fn expectInReleaseDiagnostic(source: []const u8, code: DiagnosticCode) !void {
    const result = try parseInRelease(std.testing.allocator, source, .{});
    switch (result) {
        .diagnostic => |value| try std.testing.expectEqual(code, value.code),
        .envelope => |value| {
            var envelope = value;
            envelope.deinit();
            return error.TestExpectedError;
        },
    }
}

fn expectDetachedDiagnostic(source: []const u8, code: DiagnosticCode) !void {
    const result = try parseDetached(std.testing.allocator, "Release\n", source, .{});
    switch (result) {
        .diagnostic => |value| try std.testing.expectEqual(code, value.code),
        .envelope => |value| {
            var envelope = value;
            envelope.deinit();
            return error.TestExpectedError;
        },
    }
}

test "RFC-style cleartext fixture reverses dash escaping and canonicalizes LF" {
    const fixture = @embedFile("fixtures/signed-release/inrelease-lf.asc");
    const result = try parseInRelease(std.testing.allocator, fixture, .{});
    var envelope = switch (result) {
        .envelope => |value| value,
        .diagnostic => |value| {
            std.debug.print("unexpected {s} at {d}\n", .{ value.message(), value.range.start });
            return error.TestUnexpectedResult;
        },
    };
    defer envelope.deinit();
    try std.testing.expectEqualStrings("Suite: stable \t\n-dash\nFrom escaped\n", envelope.display_cleartext);
    try std.testing.expectEqualStrings("Suite: stable\r\n-dash\r\nFrom escaped\r\n", envelope.canonical_cleartext);
    try std.testing.expectEqualStrings("SHA256", envelope.declared_hashes[0].value.slice(fixture));
    try std.testing.expectEqualSlices(u8, &.{ 0xc2, 3, 1, 2, 3 }, envelope.signature.bytes);
}

test "RFC-style CRLF fixture preserves display text without newline ambiguity" {
    const fixture =
        "-----BEGIN PGP SIGNED MESSAGE-----\r\n" ++
        "Hash: SHA512\r\n\r\n" ++
        "Origin: Debian\r\n" ++
        "-----BEGIN PGP SIGNATURE-----\r\n\r\n" ++
        "wgA=\r\n" ++
        "-----END PGP SIGNATURE-----";
    const result = try parseInRelease(std.testing.allocator, fixture, .{});
    var envelope = switch (result) {
        .envelope => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer envelope.deinit();
    try std.testing.expectEqualStrings("Origin: Debian\r\n", envelope.display_cleartext);
    try std.testing.expectEqualStrings("Origin: Debian\r\n", envelope.canonical_cleartext);
}

test "detached Release bytes remain exact including missing final newline" {
    const release = "Suite: stable";
    const binary = [_]u8{ 0xc2, 1, 0, 0xc2, 0 };
    const result = try parseDetached(std.testing.allocator, release, &binary, .{});
    var envelope = switch (result) {
        .envelope => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer envelope.deinit();
    try std.testing.expect(envelope.release_bytes.ptr == release.ptr);
    try std.testing.expectEqualStrings(release, envelope.release_bytes);
    try std.testing.expectEqual(@as(usize, 2), envelope.signatures.len);
}

test "multiple armored detached signatures and CRC24 are accepted" {
    const fixture = @embedFile("fixtures/signed-release/detached-multiple.asc");
    const result = try parseDetached(std.testing.allocator, "Release\n", fixture, .{});
    var envelope = switch (result) {
        .envelope => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer envelope.deinit();
    try std.testing.expectEqual(@as(usize, 2), envelope.signatures.len);
    try std.testing.expectEqualStrings("fixture", envelope.signatures[0].headers[0].value.slice(fixture));
}

test "malformed armor CRC truncation and trailing data are rejected" {
    try expectDetachedDiagnostic(
        @embedFile("fixtures/signed-release/detached-bad-crc.asc"),
        .crc_mismatch,
    );
    try expectDetachedDiagnostic(
        "-----BEGIN PGP SIGNATURE-----\n\nwgE\n-----END PGP SIGNATURE-----",
        .invalid_base64_padding,
    );
    try expectDetachedDiagnostic(
        "-----BEGIN PGP SIGNATURE-----\n\nwgEA\n-----END PGP SIGNATURE-----\ngarbage",
        .trailing_garbage,
    );
    try expectDetachedDiagnostic(&.{ 0xc2, 4, 1 }, .truncated_packet);
    try expectDetachedDiagnostic(
        "-----BEGIN PGP SIGNATURE-----\n\nwg==\nAQ==\n-----END PGP SIGNATURE-----",
        .invalid_base64_padding,
    );
}

test "cleartext structure and dash escaping are strict" {
    try expectInReleaseDiagnostic(
        "-----BEGIN PGP SIGNED MESSAGE-----\n\ntext\n-----BEGIN PGP SIGNATURE-----\n\nwgA=\n-----END PGP SIGNATURE-----",
        .missing_hash_header,
    );
    try expectInReleaseDiagnostic(
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n-bad\n-----BEGIN PGP SIGNATURE-----\n\nwgA=\n-----END PGP SIGNATURE-----",
        .invalid_dash_escape,
    );
    try expectInReleaseDiagnostic(
        "-----BEGIN PGP SIGNED MESSAGE-----\rHash: SHA256\n",
        .invalid_line_ending,
    );
}

test "explicit limits cover input headers cleartext signatures and counts" {
    const header_limited = try parseInRelease(std.testing.allocator, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\nHash: SHA512\n\nx\n-----BEGIN PGP SIGNATURE-----\n\nwgA=\n-----END PGP SIGNATURE-----", .{ .max_header_count = 1 });
    switch (header_limited) {
        .diagnostic => |value| try std.testing.expectEqual(DiagnosticCode.too_many_headers, value.code),
        .envelope => |value| {
            var envelope = value;
            envelope.deinit();
            return error.TestExpectedError;
        },
    }
    const cleartext_limited = try parseInRelease(std.testing.allocator, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nlong\n-----BEGIN PGP SIGNATURE-----\n\nwgA=\n-----END PGP SIGNATURE-----", .{ .max_cleartext_bytes = 4 });
    switch (cleartext_limited) {
        .diagnostic => |value| try std.testing.expectEqual(DiagnosticCode.cleartext_too_large, value.code),
        .envelope => |value| {
            var envelope = value;
            envelope.deinit();
            return error.TestExpectedError;
        },
    }
    const count_limited = try parseDetached(std.testing.allocator, "R", &.{ 0xc2, 0, 0xc2, 0 }, .{ .max_signature_count = 1 });
    switch (count_limited) {
        .diagnostic => |value| try std.testing.expectEqual(DiagnosticCode.too_many_signatures, value.code),
        .envelope => |value| {
            var envelope = value;
            envelope.deinit();
            return error.TestExpectedError;
        },
    }
    const signature_limited = try parseDetached(std.testing.allocator, "R", &.{ 0xc2, 1, 0 }, .{ .max_signature_bytes = 2 });
    switch (signature_limited) {
        .diagnostic => |value| try std.testing.expectEqual(DiagnosticCode.signature_too_large, value.code),
        .envelope => |value| {
            var envelope = value;
            envelope.deinit();
            return error.TestExpectedError;
        },
    }
    const input_limited = try parseDetached(std.testing.allocator, "long", &.{ 0xc2, 0 }, .{ .max_input_bytes = 3 });
    switch (input_limited) {
        .diagnostic => |value| {
            try std.testing.expectEqual(DiagnosticCode.input_too_large, value.code);
            try std.testing.expectEqual(InputPart.release, value.input);
            try std.testing.expectEqual(@as(usize, 3), value.range.start);
        },
        .envelope => |value| {
            var envelope = value;
            envelope.deinit();
            return error.TestExpectedError;
        },
    }
}

test "duplicate armor sections headers and unsupported packet lengths are rejected" {
    const one = "-----BEGIN PGP SIGNATURE-----\n\nwgA=\n-----END PGP SIGNATURE-----";
    const duplicate = one ++ "\n" ++ one;
    try expectDetachedDiagnostic(duplicate, .duplicate_armor_section);
    try expectDetachedDiagnostic(
        "-----BEGIN PGP SIGNATURE-----\nVersion: one\nVersion: two\n\nwgA=\n-----END PGP SIGNATURE-----",
        .duplicate_header,
    );
    try expectDetachedDiagnostic(&.{ 0xc2, 0xe0 }, .partial_packet_length);
    try expectDetachedDiagnostic(&.{0x8b}, .indeterminate_packet_length);
    try expectDetachedDiagnostic(&.{ 0xc1, 0 }, .non_signature_packet);
}

test "typed source and packet ranges identify caller bytes" {
    const source = "-----BEGIN PGP SIGNATURE-----\n\nwgEA\n-----END PGP SIGNATURE-----";
    const result = try parseDetached(std.testing.allocator, "R", source, .{});
    var envelope = switch (result) {
        .envelope => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer envelope.deinit();
    const signature = envelope.signatures[0];
    try std.testing.expectEqualStrings(source, signature.source_range.slice(source));
    try std.testing.expectEqualSlices(u8, &.{ 0xc2, 1, 0 }, signature.packet_ranges[0].slice(signature.bytes));
}

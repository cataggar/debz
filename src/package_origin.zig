const std = @import("std");

pub const LocalArtifactTrustMode = enum {
    pinned_sha256,
    verified_https,
};

pub const LocalArtifactEvidence = struct {
    artifact_id: [64]u8,
    sha256: [32]u8,
    size: u64,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    acquisition_url: []const u8,
    trust_mode: LocalArtifactTrustMode,
};

pub const ValidationError = error{
    InvalidArtifactId,
    InvalidPackageIdentity,
    InvalidAcquisitionUrl,
    TrustModeMismatch,
};

pub fn validateLocalArtifact(evidence: LocalArtifactEvidence) ValidationError!void {
    if (!validLowerHex(&evidence.artifact_id)) return error.InvalidArtifactId;
    if (!validIdentity(evidence.package) or
        !validIdentity(evidence.version) or
        !validIdentity(evidence.architecture))
        return error.InvalidPackageIdentity;
    if (!validRedactedUrl(evidence.acquisition_url)) return error.InvalidAcquisitionUrl;
    if (evidence.trust_mode == .verified_https and
        (evidence.acquisition_url.len < "https://".len or
            !std.ascii.eqlIgnoreCase(
                evidence.acquisition_url[0.."https://".len],
                "https://",
            )))
        return error.TrustModeMismatch;
}

pub fn eqlLocalArtifact(left: LocalArtifactEvidence, right: LocalArtifactEvidence) bool {
    return std.mem.eql(u8, &left.artifact_id, &right.artifact_id) and
        std.mem.eql(u8, &left.sha256, &right.sha256) and
        left.size == right.size and
        std.mem.eql(u8, left.package, right.package) and
        std.mem.eql(u8, left.version, right.version) and
        std.mem.eql(u8, left.architecture, right.architecture) and
        std.mem.eql(u8, left.acquisition_url, right.acquisition_url) and
        left.trust_mode == right.trust_mode;
}

pub fn artifactIdFromSha256(sha256: [32]u8) [64]u8 {
    const alphabet = "0123456789abcdef";
    var result: [64]u8 = undefined;
    for (sha256, 0..) |byte, index| {
        result[index * 2] = alphabet[byte >> 4];
        result[index * 2 + 1] = alphabet[byte & 15];
    }
    return result;
}

fn validIdentity(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| if (byte <= 0x1f or byte == 0x7f) return false;
    return true;
}

fn validLowerHex(value: []const u8) bool {
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return false;
    }
    return true;
}

fn validRedactedUrl(value: []const u8) bool {
    if (value.len == 0 or std.mem.indexOfScalar(u8, value, '#') != null)
        return false;
    for (value) |byte| if (byte <= 0x20 or byte == 0x7f) return false;
    const scheme_end = std.mem.indexOf(u8, value, "://") orelse return false;
    if (scheme_end == 0) return false;
    const authority_start = scheme_end + 3;
    const authority_end = std.mem.indexOfAnyPos(u8, value, authority_start, "/?") orelse
        value.len;
    if (std.mem.indexOfScalar(u8, value[authority_start..authority_end], '@') != null)
        return false;
    if (std.mem.indexOfScalar(u8, value, '?')) |query|
        if (!std.mem.eql(u8, value[query + 1 ..], "REDACTED")) return false;
    return true;
}

test "package_origin.test.local artifact evidence is explicit and redacted" {
    const digest: [32]u8 = @splat(0xab);
    const evidence: LocalArtifactEvidence = .{
        .artifact_id = artifactIdFromSha256(digest),
        .sha256 = digest,
        .size = 123,
        .package = "vendor-repo",
        .version = "1.0",
        .architecture = "all",
        .acquisition_url = "https://example.test/vendor.deb?REDACTED",
        .trust_mode = .verified_https,
    };
    try validateLocalArtifact(evidence);

    var credentials = evidence;
    credentials.acquisition_url = "https://user:secret@example.test/vendor.deb";
    try std.testing.expectError(error.InvalidAcquisitionUrl, validateLocalArtifact(credentials));

    var wrong_trust = evidence;
    wrong_trust.acquisition_url = "http://example.test/vendor.deb";
    try std.testing.expectError(error.TrustModeMismatch, validateLocalArtifact(wrong_trust));
}

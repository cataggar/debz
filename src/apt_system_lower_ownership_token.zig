const std = @import("std");
const root_operation = @import("root_operation.zig");

pub const schema_id =
    "https://debz.dev/schema/apt-system-lower-ownership-token-v1";
pub const schema_version: u32 = 1;
pub const maximum_document_bytes: usize = 192 * 1024;

pub const Purpose = enum {
    reservation,
    execution,
    recovery_review,
    clean_reconciliation,
};

pub const Transition = enum {
    recovery_review_to_clean_reconciliation,
};

pub const Input = struct {
    purpose: Purpose,
    outer_attempt_id: [32]u8,
    outer_generation: u64,
    outer_state_sha256: [32]u8,
    request_sha256: [32]u8,
    profile_sha256: [32]u8,
    profile_reference_sha256: [32]u8,
    exact_lock_sha256: [32]u8,
    semantic_request_sha256: [32]u8,
    transition: ?Transition = null,
    prior_token_exact_identity_sha256: ?[32]u8 = null,
    prior_marker: ?root_operation.DeferredAcknowledgment = null,
    marker: root_operation.DeferredAcknowledgment,
};

pub const Document = struct {
    purpose: Purpose,
    outer_attempt_id: [32]u8,
    outer_generation: u64,
    outer_state_sha256: [32]u8,
    request_sha256: [32]u8,
    profile_sha256: [32]u8,
    profile_reference_sha256: [32]u8,
    exact_lock_sha256: [32]u8,
    semantic_request_sha256: [32]u8,
    transition: ?Transition,
    prior_token_exact_identity_sha256: ?[32]u8,
    prior_marker: ?root_operation.DeferredAcknowledgment,
    prior_marker_exact_identity_sha256: ?[32]u8,
    marker: root_operation.DeferredAcknowledgment,
    marker_exact_identity_sha256: [32]u8,
    digest_sha256: [32]u8,

    pub fn canonicalJson(
        self: Document,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try validate(self, allocator);
        const marker_source = try self.marker.canonicalJson(allocator);
        defer allocator.free(marker_source);
        const prior_source = if (self.prior_marker) |prior|
            try prior.canonicalJson(allocator)
        else
            null;
        defer if (prior_source) |source| allocator.free(source);
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writePayload(
            self,
            prior_source,
            marker_source,
            &output.writer,
        );
        output.writer.undo(1);
        try output.writer.writeAll(",\"digest_sha256\":");
        try writeHex(&output.writer, &self.digest_sha256);
        try output.writer.writeByte('}');
        const source = try output.toOwnedSlice();
        if (source.len > maximum_document_bytes) {
            allocator.free(source);
            return error.DocumentTooLarge;
        }
        return source;
    }
};

pub fn create(
    allocator: std.mem.Allocator,
    input: Input,
) !Document {
    if (input.outer_generation == 0 or
        input.marker.document_version !=
            root_operation.deferred_ack_v2_schema_version)
        return error.InvalidDocument;
    var result: Document = .{
        .purpose = input.purpose,
        .outer_attempt_id = input.outer_attempt_id,
        .outer_generation = input.outer_generation,
        .outer_state_sha256 = input.outer_state_sha256,
        .request_sha256 = input.request_sha256,
        .profile_sha256 = input.profile_sha256,
        .profile_reference_sha256 = input.profile_reference_sha256,
        .exact_lock_sha256 = input.exact_lock_sha256,
        .semantic_request_sha256 = input.semantic_request_sha256,
        .transition = input.transition,
        .prior_token_exact_identity_sha256 = input.prior_token_exact_identity_sha256,
        .prior_marker = input.prior_marker,
        .prior_marker_exact_identity_sha256 = if (input.prior_marker) |marker|
            root_operation.deferredAcknowledgmentExactIdentity(marker)
        else
            null,
        .marker = input.marker,
        .marker_exact_identity_sha256 = root_operation.deferredAcknowledgmentExactIdentity(input.marker),
        .digest_sha256 = undefined,
    };
    const marker_source = try result.marker.canonicalJson(allocator);
    defer allocator.free(marker_source);
    const prior_source = if (result.prior_marker) |prior|
        try prior.canonicalJson(allocator)
    else
        null;
    defer if (prior_source) |source| allocator.free(source);
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(
        &buffer,
    );
    writePayload(
        result,
        prior_source,
        marker_source,
        &sink.writer,
    ) catch unreachable;
    sink.writer.flush() catch unreachable;
    result.digest_sha256 = sink.hasher.finalResult();
    try validate(result, allocator);
    return result;
}

const Wire = struct {
    schema: []const u8,
    version: u32,
    purpose: Purpose,
    outer_attempt_id: []const u8,
    outer_generation: u64,
    outer_state_sha256: []const u8,
    request_sha256: []const u8,
    profile_sha256: []const u8,
    profile_reference_sha256: []const u8,
    exact_lock_sha256: []const u8,
    semantic_request_sha256: []const u8,
    transition: ?Transition,
    prior_token_exact_identity_sha256: ?[]const u8,
    prior_marker_exact_identity_sha256: ?[]const u8,
    prior_marker_canonical_hex: ?[]const u8,
    marker_exact_identity_sha256: []const u8,
    marker_canonical_hex: []const u8,
    digest_sha256: []const u8,
};

pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
) !Document {
    if (source.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(Wire, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.NonCanonicalDocument,
    };
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, schema_id) or
        wire.version != schema_version or
        wire.outer_generation == 0 or
        wire.marker_canonical_hex.len % 2 != 0 or
        wire.marker_canonical_hex.len / 2 >
            root_operation.maximum_document_bytes)
        return error.InvalidDocument;
    const marker_source = try allocator.alloc(
        u8,
        wire.marker_canonical_hex.len / 2,
    );
    defer allocator.free(marker_source);
    _ = std.fmt.hexToBytes(
        marker_source,
        wire.marker_canonical_hex,
    ) catch return error.InvalidDocument;
    const marker = try root_operation.decodeDeferredAcknowledgment(
        allocator,
        marker_source,
    );
    const prior_marker = if (wire.prior_marker_canonical_hex) |encoded| blk: {
        if (encoded.len % 2 != 0 or encoded.len / 2 >
            root_operation.maximum_document_bytes)
            return error.InvalidDocument;
        const prior_source = try allocator.alloc(u8, encoded.len / 2);
        defer allocator.free(prior_source);
        _ = std.fmt.hexToBytes(prior_source, encoded) catch
            return error.InvalidDocument;
        break :blk try root_operation.decodeDeferredAcknowledgment(
            allocator,
            prior_source,
        );
    } else null;
    const document: Document = .{
        .purpose = wire.purpose,
        .outer_attempt_id = try parseHex(wire.outer_attempt_id),
        .outer_generation = wire.outer_generation,
        .outer_state_sha256 = try parseHex(wire.outer_state_sha256),
        .request_sha256 = try parseHex(wire.request_sha256),
        .profile_sha256 = try parseHex(wire.profile_sha256),
        .profile_reference_sha256 = try parseHex(wire.profile_reference_sha256),
        .exact_lock_sha256 = try parseHex(wire.exact_lock_sha256),
        .semantic_request_sha256 = try parseHex(wire.semantic_request_sha256),
        .transition = wire.transition,
        .prior_token_exact_identity_sha256 = try parseOptionalHex(
            wire.prior_token_exact_identity_sha256,
        ),
        .prior_marker = prior_marker,
        .prior_marker_exact_identity_sha256 = try parseOptionalHex(
            wire.prior_marker_exact_identity_sha256,
        ),
        .marker = marker,
        .marker_exact_identity_sha256 = try parseHex(wire.marker_exact_identity_sha256),
        .digest_sha256 = try parseHex(wire.digest_sha256),
    };
    try validate(document, allocator);
    const canonical = try document.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source))
        return error.NonCanonicalDocument;
    return document;
}

pub fn matchesMarker(
    document: Document,
    marker: root_operation.DeferredAcknowledgment,
) bool {
    return root_operation.deferredAcknowledgmentExactEqual(
        document.marker,
        marker,
    ) and std.mem.eql(
        u8,
        &document.marker_exact_identity_sha256,
        &root_operation.deferredAcknowledgmentExactIdentity(marker),
    );
}

pub fn matchesPriorMarker(
    document: Document,
    marker: root_operation.DeferredAcknowledgment,
) bool {
    const prior = document.prior_marker orelse return false;
    const identity =
        document.prior_marker_exact_identity_sha256 orelse return false;
    return root_operation.deferredAcknowledgmentExactEqual(
        prior,
        marker,
    ) and std.mem.eql(
        u8,
        &identity,
        &root_operation.deferredAcknowledgmentExactIdentity(marker),
    );
}

pub fn exactIdentity(document: Document) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-apt-system-lower-ownership-token-exact-v1\x00");
    hash.update(&document.digest_sha256);
    return hash.finalResult();
}

pub fn exactEqual(left: Document, right: Document) bool {
    return left.purpose == right.purpose and
        std.mem.eql(u8, &left.outer_attempt_id, &right.outer_attempt_id) and
        left.outer_generation == right.outer_generation and
        std.mem.eql(
            u8,
            &left.outer_state_sha256,
            &right.outer_state_sha256,
        ) and
        std.mem.eql(u8, &left.request_sha256, &right.request_sha256) and
        std.mem.eql(u8, &left.profile_sha256, &right.profile_sha256) and
        std.mem.eql(
            u8,
            &left.profile_reference_sha256,
            &right.profile_reference_sha256,
        ) and
        std.mem.eql(
            u8,
            &left.exact_lock_sha256,
            &right.exact_lock_sha256,
        ) and
        std.mem.eql(
            u8,
            &left.semantic_request_sha256,
            &right.semantic_request_sha256,
        ) and left.transition == right.transition and optionalDigestEqual(
        left.prior_token_exact_identity_sha256,
        right.prior_token_exact_identity_sha256,
    ) and optionalMarkerEqual(left.prior_marker, right.prior_marker) and
        optionalDigestEqual(
            left.prior_marker_exact_identity_sha256,
            right.prior_marker_exact_identity_sha256,
        ) and root_operation.deferredAcknowledgmentExactEqual(
        left.marker,
        right.marker,
    ) and std.mem.eql(
        u8,
        &left.marker_exact_identity_sha256,
        &right.marker_exact_identity_sha256,
    ) and std.mem.eql(
        u8,
        &left.digest_sha256,
        &right.digest_sha256,
    );
}

pub fn sameOperationBinding(left: Document, right: Document) bool {
    return std.mem.eql(
        u8,
        &left.outer_attempt_id,
        &right.outer_attempt_id,
    ) and std.mem.eql(
        u8,
        &left.request_sha256,
        &right.request_sha256,
    ) and std.mem.eql(
        u8,
        &left.profile_sha256,
        &right.profile_sha256,
    ) and std.mem.eql(
        u8,
        &left.profile_reference_sha256,
        &right.profile_reference_sha256,
    ) and std.mem.eql(
        u8,
        &left.exact_lock_sha256,
        &right.exact_lock_sha256,
    ) and std.mem.eql(
        u8,
        &left.semantic_request_sha256,
        &right.semantic_request_sha256,
    );
}

pub fn legalPurposeTransition(from: Purpose, to: Purpose) bool {
    return switch (from) {
        .reservation => to == .reservation or
            to == .execution or
            to == .recovery_review,
        .execution => to == .execution or to == .recovery_review,
        .recovery_review => to == .execution or to == .recovery_review,
        .clean_reconciliation => false,
    };
}

pub fn legalAtomicTransition(
    expected: Document,
    replacement: Document,
) bool {
    return expected.purpose == .recovery_review and
        replacement.purpose == .clean_reconciliation and
        replacement.transition ==
            .recovery_review_to_clean_reconciliation and
        replacement.prior_marker == null and
        replacement.prior_marker_exact_identity_sha256 == null and
        optionalDigestEqual(
            replacement.prior_token_exact_identity_sha256,
            exactIdentity(expected),
        ) and sameOperationBinding(expected, replacement) and
        replacement.outer_generation >= expected.outer_generation and
        replacement.marker.document_version ==
            root_operation.deferred_ack_v2_schema_version and
        replacement.marker.state == .released and
        std.mem.eql(
            u8,
            &replacement.marker.acknowledgment_id,
            &expected.outer_attempt_id,
        ) and optionalDigestEqual(
        replacement.marker.recovery_review_claim_sha256,
        expected.marker.recovery_review_claim_sha256,
    ) and optionalDigestEqual(
        replacement.marker.recovery_review_claim_exact_identity_sha256,
        expected.marker.recovery_review_claim_exact_identity_sha256,
    ) and expected.marker.recovery_review_claim_sha256 != null and
        expected.marker.recovery_review_claim_exact_identity_sha256 != null;
}

fn validate(
    document: Document,
    allocator: std.mem.Allocator,
) !void {
    if (document.outer_generation == 0 or
        document.marker.document_version !=
            root_operation.deferred_ack_v2_schema_version or
        ((document.purpose == .clean_reconciliation) !=
            (document.transition ==
                .recovery_review_to_clean_reconciliation)) or
        ((document.purpose == .clean_reconciliation) !=
            (document.prior_token_exact_identity_sha256 != null)) or
        (document.purpose == .clean_reconciliation and
            (document.prior_marker != null or
                document.prior_marker_exact_identity_sha256 != null)) or
        (document.prior_marker == null) !=
            (document.prior_marker_exact_identity_sha256 == null) or
        !std.mem.eql(
            u8,
            &document.marker_exact_identity_sha256,
            &root_operation.deferredAcknowledgmentExactIdentity(
                document.marker,
            ),
        ))
        return error.InvalidDocument;
    const prior_source = if (document.prior_marker) |prior| source: {
        if (!std.mem.eql(
            u8,
            &document.prior_marker_exact_identity_sha256.?,
            &root_operation.deferredAcknowledgmentExactIdentity(prior),
        ))
            return error.InvalidDocument;
        break :source prior.canonicalJson(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidDocument,
        };
    } else null;
    defer if (prior_source) |source| allocator.free(source);
    const marker_source = document.marker.canonicalJson(
        allocator,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidDocument,
    };
    defer allocator.free(marker_source);
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(
        &buffer,
    );
    writePayload(document, prior_source, marker_source, &sink.writer) catch
        return error.InvalidDocument;
    sink.writer.flush() catch return error.InvalidDocument;
    if (!std.mem.eql(
        u8,
        &document.digest_sha256,
        &sink.hasher.finalResult(),
    )) return error.DigestMismatch;
}

fn writePayload(
    document: Document,
    prior_source: ?[]const u8,
    marker_source: []const u8,
    writer: *std.Io.Writer,
) !void {
    try writer.writeAll("{\"schema\":\"");
    try writer.writeAll(schema_id);
    try writer.writeAll("\",\"version\":1,\"purpose\":\"");
    try writer.writeAll(@tagName(document.purpose));
    try writer.writeAll("\",\"outer_attempt_id\":");
    try writeHex(writer, &document.outer_attempt_id);
    try writer.print(",\"outer_generation\":{d}", .{
        document.outer_generation,
    });
    try writer.writeAll(",\"outer_state_sha256\":");
    try writeHex(writer, &document.outer_state_sha256);
    try writer.writeAll(",\"request_sha256\":");
    try writeHex(writer, &document.request_sha256);
    try writer.writeAll(",\"profile_sha256\":");
    try writeHex(writer, &document.profile_sha256);
    try writer.writeAll(",\"profile_reference_sha256\":");
    try writeHex(writer, &document.profile_reference_sha256);
    try writer.writeAll(",\"exact_lock_sha256\":");
    try writeHex(writer, &document.exact_lock_sha256);
    try writer.writeAll(",\"semantic_request_sha256\":");
    try writeHex(writer, &document.semantic_request_sha256);
    try writer.writeAll(",\"transition\":");
    if (document.transition) |transition| {
        try writer.writeByte('"');
        try writer.writeAll(@tagName(transition));
        try writer.writeByte('"');
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"prior_token_exact_identity_sha256\":");
    if (document.prior_token_exact_identity_sha256) |identity|
        try writeHex(writer, &identity)
    else
        try writer.writeAll("null");
    try writer.writeAll(",\"prior_marker_exact_identity_sha256\":");
    if (document.prior_marker_exact_identity_sha256) |identity|
        try writeHex(writer, &identity)
    else
        try writer.writeAll("null");
    try writer.writeAll(",\"prior_marker_canonical_hex\":");
    if (prior_source) |source| {
        try writer.writeByte('"');
        try writeRawHex(writer, source);
        try writer.writeByte('"');
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"marker_exact_identity_sha256\":");
    try writeHex(writer, &document.marker_exact_identity_sha256);
    try writer.writeAll(",\"marker_canonical_hex\":\"");
    try writeRawHex(writer, marker_source);
    try writer.writeAll("\"}");
}

fn writeHex(writer: *std.Io.Writer, bytes: *const [32]u8) !void {
    try writer.writeByte('"');
    try writeRawHex(writer, bytes);
    try writer.writeByte('"');
}

fn writeRawHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
}

fn parseHex(source: []const u8) ![32]u8 {
    if (source.len != 64) return error.InvalidDocument;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, source) catch
        return error.InvalidDocument;
    return result;
}

fn parseOptionalHex(source: ?[]const u8) !?[32]u8 {
    return if (source) |value| try parseHex(value) else null;
}

fn optionalDigestEqual(left: ?[32]u8, right: ?[32]u8) bool {
    if ((left == null) != (right == null)) return false;
    return if (left) |value|
        std.mem.eql(u8, &value, &right.?)
    else
        true;
}

fn optionalMarkerEqual(
    left: ?root_operation.DeferredAcknowledgment,
    right: ?root_operation.DeferredAcknowledgment,
) bool {
    if ((left == null) != (right == null)) return false;
    return if (left) |marker|
        root_operation.deferredAcknowledgmentExactEqual(marker, right.?)
    else
        true;
}

test "apt_system_lower_ownership_token.test.canonical exact marker token rejects tampering" {
    const marker = try root_operation.createDeferredAcknowledgment(.{
        .document_version = root_operation.deferred_ack_v2_schema_version,
        .attempt_id = @splat(0x11),
        .acknowledgment_id = @splat(0x12),
    });
    const document = try create(std.testing.allocator, .{
        .purpose = .reservation,
        .outer_attempt_id = marker.acknowledgment_id,
        .outer_generation = 3,
        .outer_state_sha256 = @splat(0x13),
        .request_sha256 = @splat(0x14),
        .profile_sha256 = @splat(0x15),
        .profile_reference_sha256 = @splat(0x16),
        .exact_lock_sha256 = @splat(0x17),
        .semantic_request_sha256 = @splat(0x18),
        .marker = marker,
    });
    const source = try document.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(source);
    const decoded = try decode(std.testing.allocator, source);
    try std.testing.expect(matchesMarker(decoded, marker));
    const tampered = try std.testing.allocator.dupe(u8, source);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 4] = if (tampered[tampered.len - 4] == '0')
        '1'
    else
        '0';
    try std.testing.expectError(
        error.DigestMismatch,
        decode(std.testing.allocator, tampered),
    );
}

test "apt_system_lower_ownership_token.test.clean reconciliation transition binds exact prior token" {
    const base = try root_operation.createDeferredAcknowledgment(.{
        .document_version = root_operation.deferred_ack_v2_schema_version,
        .state = .bound,
        .attempt_id = @splat(0x21),
        .acknowledgment_id = @splat(0x22),
    });
    const claim = try root_operation.createRecoveryReviewClaim(.{
        .outer_attempt_id = base.acknowledgment_id,
        .outer_generation = 4,
        .outer_state_sha256 = @splat(0x23),
        .profile_sha256 = @splat(0x25),
        .profile_reference_sha256 = @splat(0x26),
        .exact_lock_sha256 = @splat(0x27),
        .semantic_request_sha256 = @splat(0x28),
        .mutation_status = .changed,
        .outer_transaction_sha256 = @splat(0x2b),
        .nonce = @splat(0x20),
    });
    const review_marker =
        try root_operation.bindDeferredAcknowledgmentToRecoveryReview(
            base,
            claim,
        );
    const review = try create(std.testing.allocator, .{
        .purpose = .recovery_review,
        .outer_attempt_id = review_marker.acknowledgment_id,
        .outer_generation = 4,
        .outer_state_sha256 = @splat(0x23),
        .request_sha256 = @splat(0x24),
        .profile_sha256 = @splat(0x25),
        .profile_reference_sha256 = @splat(0x26),
        .exact_lock_sha256 = @splat(0x27),
        .semantic_request_sha256 = @splat(0x28),
        .marker = review_marker,
    });
    const reconciliation_marker =
        try root_operation.transitionDeferredAcknowledgment(
            review_marker,
            .released,
        );
    const replacement = try create(std.testing.allocator, .{
        .purpose = .clean_reconciliation,
        .outer_attempt_id = review.outer_attempt_id,
        .outer_generation = 5,
        .outer_state_sha256 = @splat(0x29),
        .request_sha256 = review.request_sha256,
        .profile_sha256 = review.profile_sha256,
        .profile_reference_sha256 = review.profile_reference_sha256,
        .exact_lock_sha256 = review.exact_lock_sha256,
        .semantic_request_sha256 = review.semantic_request_sha256,
        .transition = .recovery_review_to_clean_reconciliation,
        .prior_token_exact_identity_sha256 = exactIdentity(review),
        .marker = reconciliation_marker,
    });
    try std.testing.expect(legalAtomicTransition(review, replacement));
    var foreign = review;
    foreign.outer_state_sha256 = @splat(0x2a);
    foreign = try create(std.testing.allocator, .{
        .purpose = foreign.purpose,
        .outer_attempt_id = foreign.outer_attempt_id,
        .outer_generation = foreign.outer_generation,
        .outer_state_sha256 = foreign.outer_state_sha256,
        .request_sha256 = foreign.request_sha256,
        .profile_sha256 = foreign.profile_sha256,
        .profile_reference_sha256 = foreign.profile_reference_sha256,
        .exact_lock_sha256 = foreign.exact_lock_sha256,
        .semantic_request_sha256 = foreign.semantic_request_sha256,
        .marker = foreign.marker,
    });
    try std.testing.expect(!legalAtomicTransition(foreign, replacement));
}

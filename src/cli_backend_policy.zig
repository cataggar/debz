const std = @import("std");
const debz = @import("debz");
const compat = debz.legacy_compat;

pub const Surface = enum {
    product,
    repository,
    transaction_result_verification,
};

pub fn select(
    runtime: compat.RuntimeMode,
    requested: ?debz.transaction_engine.Kind,
    surface: Surface,
) compat.PolicyError!debz.transaction_engine.Kind {
    const backend = requested orelse switch (runtime) {
        .legacy_capable => debz.transaction_engine.Kind.legacy_dpkg,
        .native_only => debz.transaction_engine.Kind.native,
    };
    const compatible: compat.Backend = switch (backend) {
        .legacy_dpkg => .legacy_dpkg,
        .native => .native,
    };
    const identity: compat.Identity = switch (surface) {
        .product => .{
            .schema = "io.github.cataggar.debz.command.v1",
            .version = 1,
            .backend = compatible,
        },
        .repository => .{
            .schema = "https://debz.dev/schema/repository-operation-result-v1",
            .version = 1,
            .backend = compatible,
        },
        .transaction_result_verification => if (backend == .native) .{
            .schema = "https://debz.dev/schema/transaction-result-v3",
            .version = 3,
            .backend = .native,
        } else .{
            .schema = "https://debz.dev/schema/transaction-result-v2",
            .version = 2,
            .backend = .legacy_dpkg,
        },
    };
    _ = try compat.decide(
        runtime,
        compatible,
        if (surface == .transaction_result_verification)
            .completed_historical_verification
        else
            .new_execution,
        identity,
    );
    return backend;
}

pub fn authorizeNativeV3(
    lock: compat.Identity,
    profile: compat.Identity,
    capability: compat.Identity,
) compat.PolicyError!void {
    for ([_]compat.Identity{ lock, profile, capability }) |identity|
        _ = try compat.decide(.native_only, .native, .new_execution, identity);
    if (!std.mem.eql(u8, lock.schema, "https://debz.dev/schema/exact-closure-lock-v3") or
        lock.version != 3 or
        !std.mem.eql(u8, profile.schema, "https://debz.dev/schema/system-profile-v2") or
        profile.version != 2 or
        !std.mem.eql(u8, capability.schema, "io.github.cataggar.debz.native-install-capability.v1") or
        capability.version != 1)
        return error.UnsupportedIdentity;
}

test "cli_backend_policy.test.native-only selection refuses new legacy but preserves completed verification" {
    for ([_]Surface{ .product, .repository }) |surface| {
        try std.testing.expectEqual(
            debz.transaction_engine.Kind.legacy_dpkg,
            try select(.legacy_capable, null, surface),
        );
        try std.testing.expectEqual(
            debz.transaction_engine.Kind.legacy_dpkg,
            try select(.legacy_capable, .legacy_dpkg, surface),
        );
        try std.testing.expectEqual(
            debz.transaction_engine.Kind.native,
            try select(.native_only, null, surface),
        );
        try std.testing.expectEqual(
            debz.transaction_engine.Kind.native,
            try select(.native_only, .native, surface),
        );
        try std.testing.expectError(
            error.LegacyCapabilityRequired,
            select(.native_only, .legacy_dpkg, surface),
        );
    }
    try std.testing.expectEqual(
        debz.transaction_engine.Kind.legacy_dpkg,
        try select(.legacy_capable, null, .transaction_result_verification),
    );
    try std.testing.expectEqual(
        debz.transaction_engine.Kind.native,
        try select(.native_only, null, .transaction_result_verification),
    );
    try std.testing.expectEqual(
        debz.transaction_engine.Kind.legacy_dpkg,
        try select(.native_only, .legacy_dpkg, .transaction_result_verification),
    );
    try std.testing.expectEqualStrings(
        "Recover this operation with debz >=0.3.0,<0.4.0 before installing a native-only release.",
        compat.recovery_guidance,
    );
}

test "cli_backend_policy.test.native v3 profile and capability are exact, never a legacy fallback" {
    const lock: compat.Identity = .{
        .schema = "https://debz.dev/schema/exact-closure-lock-v3",
        .version = 3,
        .backend = .native,
    };
    const profile: compat.Identity = .{
        .schema = "https://debz.dev/schema/system-profile-v2",
        .version = 2,
        .backend = .native,
    };
    const capability: compat.Identity = .{
        .schema = "io.github.cataggar.debz.native-install-capability.v1",
        .version = 1,
        .backend = .native,
    };
    try authorizeNativeV3(lock, profile, capability);
    var wrong_lock = lock;
    wrong_lock.version = 2;
    try std.testing.expectError(error.UnsupportedIdentity, authorizeNativeV3(wrong_lock, profile, capability));
    wrong_lock.version = 3;
    wrong_lock.backend = .legacy_dpkg;
    try std.testing.expectError(error.BackendMismatch, authorizeNativeV3(wrong_lock, profile, capability));
    var wrong_profile = profile;
    wrong_profile.backend = .legacy_dpkg;
    try std.testing.expectError(error.BackendMismatch, authorizeNativeV3(lock, wrong_profile, capability));
    wrong_profile = .{ .schema = "https://debz.dev/schema/system-profile-v1", .version = 1 };
    try std.testing.expectError(error.BackendMismatch, authorizeNativeV3(lock, wrong_profile, capability));
    var wrong_capability = capability;
    wrong_capability.backend = .legacy_dpkg;
    try std.testing.expectError(error.BackendMismatch, authorizeNativeV3(lock, profile, wrong_capability));
}

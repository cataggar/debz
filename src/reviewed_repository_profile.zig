const std = @import("std");
const repository_policy = @import("repository_policy.zig");
const repository_refresh = @import("repository_refresh.zig");
const source = @import("source.zig");

/// A reviewed, repository-specific exception for a signed moving feed whose
/// Release omits `Valid-Until`. A profile never matches on hostname alone: the
/// exact source path and format, every normalized entry, the declared keyring
/// path, and that keyring's complete primary-fingerprint set must all match.
pub const Profile = struct {
    name: []const u8,
    source_path: []const u8,
    source_format: source.Format,
    keyring_path: []const u8,
    uri: []const u8,
    suite: []const u8,
    component: []const u8,
    /// Every normalized entry of the source must name one of these.
    published_architectures: []const []const u8,
    /// The target's native architecture must be one of these and be declared.
    target_architectures: []const []const u8,
    primary_fingerprints: []const [20]u8,
    maximum_release_age_seconds: u64,

    pub fn freshness(self: Profile) repository_refresh.ExpiryPolicy {
        return .{ .allow_missing_valid_until_with_max_age_seconds = self.maximum_release_age_seconds };
    }
};

/// Owner-reviewed maximum signed-Release age for Microsoft's Noble feed.
pub const microsoft_maximum_release_age_seconds: u64 = 14 * 24 * 60 * 60;

/// "Microsoft (Release signing) <gpgsecurity@microsoft.com>", shipped as
/// `/usr/share/keyrings/microsoft-prod.gpg` by `packages-microsoft-prod`.
pub const microsoft_release_signing_fingerprint = fingerprint("BC528686B50D79E339D3721CEB3E94ADBE1229CF");

/// The source and keyring installed by
/// `https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb`.
pub const microsoft_ubuntu_noble_prod: Profile = .{
    .name = "microsoft-ubuntu-24.04-prod",
    .source_path = "/etc/apt/sources.list.d/microsoft-prod.list",
    .source_format = .legacy,
    .keyring_path = "/usr/share/keyrings/microsoft-prod.gpg",
    .uri = "https://packages.microsoft.com/ubuntu/24.04/prod",
    .suite = "noble",
    .component = "main",
    .published_architectures = &.{ "amd64", "arm64", "armhf" },
    .target_architectures = &.{ "amd64", "arm64" },
    .primary_fingerprints = &.{microsoft_release_signing_fingerprint},
    .maximum_release_age_seconds = microsoft_maximum_release_age_seconds,
};

pub const production_profiles: []const Profile = &.{microsoft_ubuntu_noble_prod};

pub const Source = struct {
    logical_path: []const u8,
    bytes: []const u8,
    format: source.Format,
};

pub const Keyring = struct {
    logical_path: []const u8,
    primary_fingerprints: []const [20]u8,
};

pub const ValidationError = error{InvalidReviewedRepositoryProfile};

pub fn validateProfiles(profiles: []const Profile) ValidationError!void {
    for (profiles, 0..) |profile, index| {
        if (profile.name.len == 0 or
            !validLogicalPath(profile.source_path) or
            !validLogicalPath(profile.keyring_path) or
            !std.mem.startsWith(u8, profile.uri, "https://") or
            profile.suite.len == 0 or
            profile.component.len == 0 or
            profile.published_architectures.len == 0 or
            profile.target_architectures.len == 0 or
            profile.primary_fingerprints.len == 0 or
            !repository_refresh.validExpiryPolicy(profile.freshness()))
            return error.InvalidReviewedRepositoryProfile;
        const expected_suffix: []const u8 = switch (profile.source_format) {
            .legacy => ".list",
            .deb822 => ".sources",
        };
        if (!std.mem.endsWith(u8, profile.source_path, expected_suffix))
            return error.InvalidReviewedRepositoryProfile;
        for (profile.target_architectures) |architecture| {
            if (!containsString(profile.published_architectures, architecture))
                return error.InvalidReviewedRepositoryProfile;
        }
        for (profiles[0..index]) |previous| {
            if (std.mem.eql(u8, previous.source_path, profile.source_path))
                return error.InvalidReviewedRepositoryProfile;
        }
    }
}

/// Returns the reviewed bounded policy only for an exact profile match and the
/// fail-closed default otherwise. `keyrings` must be the bytes the refresh will
/// actually authenticate with, already inspected for primary fingerprints.
pub fn sourceFreshness(
    allocator: std.mem.Allocator,
    profiles: []const Profile,
    candidate: Source,
    keyrings: []const Keyring,
    target_architecture: []const u8,
) std.mem.Allocator.Error!repository_refresh.ExpiryPolicy {
    for (profiles) |profile| {
        if (!std.mem.eql(u8, candidate.logical_path, profile.source_path)) continue;
        if (candidate.format == profile.source_format and
            containsString(profile.target_architectures, target_architecture) and
            keyringMatches(profile, keyrings) and
            try sourceMatches(allocator, profile, candidate, target_architecture))
            return profile.freshness();
        return .require_valid_until;
    }
    return .require_valid_until;
}

fn sourceMatches(
    allocator: std.mem.Allocator,
    profile: Profile,
    candidate: Source,
    target_architecture: []const u8,
) std.mem.Allocator.Error!bool {
    const normalized = try repository_policy.normalizeBinaryRefresh(
        allocator,
        &.{.{ .bytes = candidate.bytes, .format = candidate.format }},
        target_architecture,
        .{},
    );
    var configuration = switch (normalized) {
        .diagnostic => return false,
        .configuration => |value| value,
    };
    defer configuration.deinit();
    if (configuration.repositories.len == 0) return false;
    var declares_target = false;
    for (configuration.repositories) |repository| {
        if (!repository.enabled or
            !std.mem.eql(u8, repository.uri, profile.uri) or
            !std.mem.eql(u8, repository.suite, profile.suite) or
            !std.mem.eql(u8, repository.component, profile.component) or
            !containsString(profile.published_architectures, repository.architecture) or
            repository.immutability.kind != .moving or
            repository.signed_by.len != 1 or
            !std.mem.eql(u8, repository.signed_by[0], profile.keyring_path))
            return false;
        if (std.mem.eql(u8, repository.architecture, target_architecture))
            declares_target = true;
    }
    return declares_target;
}

fn keyringMatches(profile: Profile, keyrings: []const Keyring) bool {
    for (keyrings) |keyring| {
        if (!std.mem.eql(u8, keyring.logical_path, profile.keyring_path)) continue;
        if (keyring.primary_fingerprints.len == 0) return false;
        for (keyring.primary_fingerprints) |actual| {
            if (!containsFingerprint(profile.primary_fingerprints, actual)) return false;
        }
        for (profile.primary_fingerprints) |expected| {
            if (!containsFingerprint(keyring.primary_fingerprints, expected)) return false;
        }
        return true;
    }
    return false;
}

fn containsFingerprint(values: []const [20]u8, wanted: [20]u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, &value, &wanted)) return true;
    }
    return false;
}

fn containsString(values: []const []const u8, wanted: []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value, wanted)) return true;
    }
    return false;
}

fn validLogicalPath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
            return false;
    }
    return true;
}

fn fingerprint(comptime hex: []const u8) [20]u8 {
    var bytes: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

const reviewed_source_path = microsoft_ubuntu_noble_prod.source_path;
const sources_directory = reviewed_source_path[0 .. reviewed_source_path.len - "/microsoft-prod.list".len];

const live_microsoft_source =
    "deb [arch=amd64,arm64,armhf signed-by=/usr/share/keyrings/microsoft-prod.gpg] " ++
    "https://packages.microsoft.com/ubuntu/24.04/prod noble main\n";

const microsoft_keyring: Keyring = .{
    .logical_path = "/usr/share/keyrings/microsoft-prod.gpg",
    .primary_fingerprints = &.{microsoft_release_signing_fingerprint},
};

fn expectDefault(policy: repository_refresh.ExpiryPolicy) !void {
    try std.testing.expect(repository_refresh.expiryPoliciesEqual(policy, .require_valid_until));
}

fn freshnessOf(
    candidate_path: []const u8,
    bytes: []const u8,
    keyrings: []const Keyring,
    architecture: []const u8,
) !repository_refresh.ExpiryPolicy {
    return sourceFreshness(std.testing.allocator, production_profiles, .{
        .logical_path = candidate_path,
        .bytes = bytes,
        .format = if (std.mem.endsWith(u8, candidate_path, ".sources")) .deb822 else .legacy,
    }, keyrings, architecture);
}

test "reviewed Microsoft Noble profile is valid and bounded to 14 days" {
    try validateProfiles(production_profiles);
    try std.testing.expectEqual(@as(u64, 1_209_600), microsoft_ubuntu_noble_prod.maximum_release_age_seconds);
    try std.testing.expect(microsoft_ubuntu_noble_prod.maximum_release_age_seconds <
        repository_refresh.maximum_missing_valid_until_age_seconds);
    try std.testing.expect(repository_refresh.validExpiryPolicy(microsoft_ubuntu_noble_prod.freshness()));
}

test "reviewed profile accepts the exact Microsoft Noble source and pinned key" {
    for ([_][]const u8{ "amd64", "arm64" }) |architecture| {
        const policy = try freshnessOf(
            microsoft_ubuntu_noble_prod.source_path,
            live_microsoft_source,
            &.{microsoft_keyring},
            architecture,
        );
        try std.testing.expectEqual(
            @as(?u64, microsoft_maximum_release_age_seconds),
            repository_refresh.expiryPolicyMaxAge(policy),
        );
    }
    const target_only =
        "deb [arch=arm64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] " ++
        "https://packages.microsoft.com/ubuntu/24.04/prod noble main\n";
    const policy = try freshnessOf(
        microsoft_ubuntu_noble_prod.source_path,
        target_only,
        &.{microsoft_keyring},
        "arm64",
    );
    try std.testing.expect(repository_refresh.expiryPolicyMaxAge(policy) != null);
}

test "reviewed profile refuses other signers and incomplete keyring evidence" {
    const other: [20]u8 = @splat(0x42);
    const cases = [_][]const Keyring{
        &.{},
        &.{.{ .logical_path = microsoft_keyring.logical_path, .primary_fingerprints = &.{} }},
        &.{.{ .logical_path = microsoft_keyring.logical_path, .primary_fingerprints = &.{other} }},
        &.{.{
            .logical_path = microsoft_keyring.logical_path,
            .primary_fingerprints = &.{ microsoft_release_signing_fingerprint, other },
        }},
        &.{.{
            .logical_path = "/usr/share/keyrings/other.gpg",
            .primary_fingerprints = &.{microsoft_release_signing_fingerprint},
        }},
    };
    for (cases) |keyrings| try expectDefault(try freshnessOf(
        microsoft_ubuntu_noble_prod.source_path,
        live_microsoft_source,
        keyrings,
        "amd64",
    ));
}

test "reviewed profile never applies to other sources or targets" {
    const keyrings: []const Keyring = &.{microsoft_keyring};
    const signed = "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] ";
    const other_sources = [_][]const u8{
        signed ++ "https://packages.microsoft.com/ubuntu/22.04/prod jammy main\n",
        signed ++ "https://packages.microsoft.com/ubuntu/24.04/prod noble-insiders main\n",
        signed ++ "https://packages.microsoft.com/ubuntu/24.04/prod noble nightly\n",
        signed ++ "https://packages.microsoft.com/ubuntu/24.04/prod/ noble main\n",
        signed ++ "http://packages.microsoft.com/ubuntu/24.04/prod noble main\n",
        signed ++ "https://packages.microsoft.com.example/ubuntu/24.04/prod noble main\n",
        signed ++ "https://mirror.example/ubuntu/24.04/prod noble main\n",
        signed ++ "https://packages.microsoft.com/ubuntu/24.04/prod noble main contrib\n",
        "deb [arch=amd64 signed-by=/usr/share/keyrings/other.gpg] " ++
            "https://packages.microsoft.com/ubuntu/24.04/prod noble main\n",
        "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg,/usr/share/keyrings/other.gpg] " ++
            "https://packages.microsoft.com/ubuntu/24.04/prod noble main\n",
        "deb [arch=amd64] https://packages.microsoft.com/ubuntu/24.04/prod noble main\n",
        "deb [arch=amd64,riscv64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] " ++
            "https://packages.microsoft.com/ubuntu/24.04/prod noble main\n",
        "deb [arch=arm64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] " ++
            "https://packages.microsoft.com/ubuntu/24.04/prod noble main\n",
        live_microsoft_source ++
            signed ++ "https://packages.microsoft.com/ubuntu/22.04/prod jammy main\n",
        "deb [trusted=yes arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] " ++
            "https://packages.microsoft.com/ubuntu/24.04/prod noble main\n",
        "",
        "not a source\n",
    };
    for (other_sources) |bytes| try expectDefault(try freshnessOf(
        microsoft_ubuntu_noble_prod.source_path,
        bytes,
        keyrings,
        "amd64",
    ));

    for ([_][]const u8{
        sources_directory ++ "/other.list",
        sources_directory[0 .. sources_directory.len - ".d".len],
        reviewed_source_path ++ ".bak",
    }) |path| try expectDefault(try freshnessOf(path, live_microsoft_source, keyrings, "amd64"));

    try expectDefault(try freshnessOf(
        sources_directory ++ "/microsoft-prod.sources",
        "Types: deb\nURIs: https://packages.microsoft.com/ubuntu/24.04/prod\n" ++
            "Suites: noble\nComponents: main\nArchitectures: amd64\n" ++
            "Signed-By: /usr/share/keyrings/microsoft-prod.gpg\n",
        keyrings,
        "amd64",
    ));
    try expectDefault(try sourceFreshness(std.testing.allocator, production_profiles, .{
        .logical_path = microsoft_ubuntu_noble_prod.source_path,
        .bytes = live_microsoft_source,
        .format = .deb822,
    }, keyrings, "amd64"));

    for ([_][]const u8{ "armhf", "i386", "riscv64" }) |architecture|
        try expectDefault(try freshnessOf(
            microsoft_ubuntu_noble_prod.source_path,
            live_microsoft_source,
            keyrings,
            architecture,
        ));
    try expectDefault(try sourceFreshness(
        std.testing.allocator,
        &.{},
        .{
            .logical_path = microsoft_ubuntu_noble_prod.source_path,
            .bytes = live_microsoft_source,
            .format = .legacy,
        },
        keyrings,
        "amd64",
    ));
}

test "reviewed profile validation rejects unbounded or ambiguous profiles" {
    var profile = microsoft_ubuntu_noble_prod;
    profile.maximum_release_age_seconds = 0;
    try std.testing.expectError(error.InvalidReviewedRepositoryProfile, validateProfiles(&.{profile}));
    profile.maximum_release_age_seconds = repository_refresh.maximum_missing_valid_until_age_seconds + 1;
    try std.testing.expectError(error.InvalidReviewedRepositoryProfile, validateProfiles(&.{profile}));
    profile = microsoft_ubuntu_noble_prod;
    profile.primary_fingerprints = &.{};
    try std.testing.expectError(error.InvalidReviewedRepositoryProfile, validateProfiles(&.{profile}));
    profile = microsoft_ubuntu_noble_prod;
    profile.uri = "http://packages.microsoft.com/ubuntu/24.04/prod";
    try std.testing.expectError(error.InvalidReviewedRepositoryProfile, validateProfiles(&.{profile}));
    profile = microsoft_ubuntu_noble_prod;
    profile.target_architectures = &.{"riscv64"};
    try std.testing.expectError(error.InvalidReviewedRepositoryProfile, validateProfiles(&.{profile}));
    profile = microsoft_ubuntu_noble_prod;
    profile.source_path = sources_directory ++ "/microsoft-prod.sources";
    try std.testing.expectError(error.InvalidReviewedRepositoryProfile, validateProfiles(&.{profile}));
    profile = microsoft_ubuntu_noble_prod;
    profile.keyring_path = "usr/share/keyrings/microsoft-prod.gpg";
    try std.testing.expectError(error.InvalidReviewedRepositoryProfile, validateProfiles(&.{profile}));
    try std.testing.expectError(
        error.InvalidReviewedRepositoryProfile,
        validateProfiles(&.{ microsoft_ubuntu_noble_prod, microsoft_ubuntu_noble_prod }),
    );
    try validateProfiles(&.{});
}

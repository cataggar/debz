const std = @import("std");
const product = @import("product_api.zig");
const production = @import("production_backend.zig");
const transaction_engine = @import("transaction_engine.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const native_transaction_result = @import("native_transaction_result.zig");
const native_provenance = @import("native_provenance.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const solver = @import("solver.zig");
const dpkg_status = @import("dpkg_status.zig");
const native_operation = @import("native_operation.zig");
const native_runtime = @import("native_unpack.zig").Runtime;

pub const schema_version: u32 = 1;
pub const capability_schema = "io.github.cataggar.debz.package-family.capabilities.v1";
pub const request_schema = "io.github.cataggar.debz.package-family.request.v1";
pub const result_schema = "io.github.cataggar.debz.package-family.result.v1";
pub const provenance_basename = "transaction-result.json";
pub const native_schema_version: u32 = 2;
pub const native_capability_schema = "io.github.cataggar.debz.package-family.capabilities.v2";
pub const native_request_schema = "io.github.cataggar.debz.package-family.request.v2";
pub const native_result_schema = "io.github.cataggar.debz.package-family.result.v2";

pub const Architecture = enum {
    amd64,
    arm64,

    pub fn spelling(self: Architecture) []const u8 {
        return @tagName(self);
    }
};

pub const Operation = enum {
    resolve_lock,
    create,
    customize,
    update,
    recover,
    inspect,
};

pub const CacheMode = enum { online, prefer_cache, offline };
pub const RecoveryBehavior = enum { disposable_or_recoverable };

pub const Capabilities = struct {
    schema: []const u8 = capability_schema,
    version: u32 = schema_version,
    family: []const u8 = "debian",
    implementations: []const []const u8 = &.{ "ubuntu-26.04", "debian" },
    operations: []const []const u8 = &.{ "resolve-lock", "create", "customize", "update", "recover", "inspect" },
    architectures: []const []const u8 = &.{ "amd64", "arm64" },
    request_schema: []const u8 = request_schema,
    result_schema: []const u8 = result_schema,
    exact_lock_schema: []const u8 = "https://debz.dev/schema/exact-closure-lock-v1",
    provenance_schema: []const u8 = "https://debz.dev/schema/transaction-result-v1",
    recovery: RecoveryBehavior = .disposable_or_recoverable,
    invokes_apt: bool = false,

    pub fn canonicalJson(self: Capabilities, allocator: std.mem.Allocator) ![]u8 {
        return std.json.Stringify.valueAlloc(allocator, self, .{ .whitespace = .minified });
    }
};

pub fn capabilities() Capabilities {
    return .{};
}

pub const NativeCapabilities = struct {
    schema: []const u8 = native_capability_schema,
    version: u32 = native_schema_version,
    transaction_backend: transaction_engine.Kind = .native,
    family: []const u8 = "debian",
    implementations: []const []const u8 = capabilities().implementations,
    operations: []const []const u8 = &.{ "resolve-lock", "create", "customize", "update", "recover", "inspect" },
    architectures: []const []const u8 = capabilities().architectures,
    request_schema: []const u8 = native_request_schema,
    result_schema: []const u8 = native_result_schema,
    exact_lock_schema: []const u8 = exact_lock_v2.schema_id,
    provenance_schema: ?[]const u8 = native_provenance.schema_id,
    recovery: RecoveryBehavior = .disposable_or_recoverable,
    invokes_apt: bool = false,
    invokes_dpkg: bool = false,

    pub fn canonicalJson(self: @This(), allocator: std.mem.Allocator) ![]u8 {
        return std.json.Stringify.valueAlloc(allocator, self, .{ .whitespace = .minified });
    }
};

pub fn nativeCapabilities() NativeCapabilities {
    return .{};
}

pub fn parseCapabilitiesBackend(arguments: []const []const u8) !transaction_engine.Kind {
    if (arguments.len == 0) return .legacy_dpkg;
    if (arguments.len != 2 or !std.mem.eql(u8, arguments[0], "--transaction-backend"))
        return error.InvalidCapabilityOptions;
    return std.meta.stringToEnum(transaction_engine.Kind, arguments[1]) orelse error.InvalidTransactionBackend;
}

/// Stable image-builder boundary. Every host-sensitive input is explicit;
/// debz never inherits repository, trust, proxy, cache, state, or root policy.
pub const Request = struct {
    schema: []const u8 = request_schema,
    version: u32 = schema_version,
    operation: Operation,
    root: []const u8,
    architecture: Architecture,
    foreign_architectures: []const Architecture = &.{},
    sources: []const []const u8,
    keyrings: []const []const u8,
    configs: []const []const u8 = &.{},
    cache: []const u8,
    state: []const u8,
    package: ?[]const u8 = null,
    lock_input: ?[]const u8 = null,
    lock_output: ?[]const u8 = null,
    cache_mode: CacheMode = .online,
    repository_policy: product.RepositoryPolicy = .strict_priority,
    recommends: bool = false,
    allow_downgrade: bool = false,
    conffile: product.ConffilePolicy = .keep_existing,
    credential_reference: ?[]const u8 = null,
    proxy: ?[]const u8 = null,
    deadline_ms: ?u64 = null,
    lock_wait_ms: u64 = 30_000,
};

pub const ErrorId = enum {
    invalid_request,
    unsupported_architecture,
    backend_failed,
    lock_not_emitted,
    provenance_not_emitted,
    backend_unavailable,
    native_evidence_unavailable,
    native_inspection_unavailable,
};

pub const Diagnostic = struct {
    id: ErrorId,
    message: []const u8,
    recoverable: bool,
};

pub const Result = struct {
    schema: []const u8 = result_schema,
    version: u32 = schema_version,
    operation: Operation,
    succeeded: bool,
    changed: bool = false,
    exit_status: product.ExitStatus,
    lock_path: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
    diagnostic: ?Diagnostic = null,
};

pub const Backend = struct {
    product_backend: product.Backend,

    pub fn execute(self: Backend, allocator: std.mem.Allocator, request: Request) !Result {
        if (!validRequest(request, .legacy_dpkg))
            return failure(request.operation, .usage, .invalid_request, "invalid explicit package-family request", false);

        var mapped = try MappedRequest.init(allocator, request);
        defer mapped.deinit();
        const operation = mapped.request.operation;
        const response = try product.execute(allocator, mapped.request, self.product_backend);
        defer freePackageFamilyProductItems(allocator, response.items);
        if (response.exit_status != .success) {
            return failure(
                request.operation,
                response.exit_status,
                .backend_failed,
                response.summary,
                response.exit_status == .transaction or response.exit_status == .recovery,
            );
        }
        const provenance_path = if (operation.mutates() and operation != .recover and request.lock_input != null)
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ request.state, provenance_basename })
        else
            null;
        return .{
            .operation = request.operation,
            .succeeded = true,
            .changed = response.changed,
            .exit_status = .success,
            .lock_path = request.lock_output orelse request.lock_input,
            .provenance_path = provenance_path,
        };
    }
};

const MappedRequest = struct {
    request: product.Request,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, request: Request) !MappedRequest {
        const operation: product.Operation = switch (request.operation) {
            .resolve_lock => .plan,
            .create, .customize => .install,
            .update => if (request.package == null) .upgrade_all else .upgrade,
            .recover => .recover,
            .inspect => .list_installed,
        };
        const packages: []const []const u8 = if (request.package) |package|
            try allocator.dupe([]const u8, &.{package})
        else
            &.{};
        errdefer allocator.free(packages);

        const offline = request.cache_mode == .offline;
        const foreign_architectures = try allocator.alloc([]const u8, request.foreign_architectures.len);
        for (request.foreign_architectures, 0..) |architecture, index|
            foreign_architectures[index] = architecture.spelling();
        return .{ .allocator = allocator, .request = .{
            .operation = operation,
            .packages = packages,
            .options = .{
                .install_root = request.root,
                .source_paths = request.sources,
                .config_paths = request.configs,
                .keyring_paths = request.keyrings,
                .cache_path = request.cache,
                .state_path = request.state,
                .architecture = request.architecture.spelling(),
                .foreign_architectures = foreign_architectures,
                .repository_policy = request.repository_policy,
                .proxy = request.proxy,
                .credential_reference = request.credential_reference,
                .lock_input_path = request.lock_input,
                .lock_output_path = request.lock_output,
                .offline = offline,
                .cache_only = offline,
                .recommends = request.recommends,
                .allow_downgrade = request.allow_downgrade,
                .deadline_ms = request.deadline_ms,
                .lock_wait_ms = request.lock_wait_ms,
                .assume_yes = operation.mutates(),
                .noninteractive = operation.mutates(),
                .conffile = request.conffile,
            },
        } };
    }

    fn deinit(self: *MappedRequest) void {
        self.allocator.free(self.request.packages);
        self.allocator.free(self.request.options.foreign_architectures);
        self.* = undefined;
    }
};

pub const InspectedPackage = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    status: dpkg_status.Status,
};

/// Diagnostic observations, not an atomic database generation, completed
/// transaction proof, or authority to mutate or publish the root.
pub const NativeInspection = struct {
    root: []const u8,
    diagnostic_only: bool = true,
    status_database_present: bool,
    packages: []const InspectedPackage,
    observed_operation: ?struct {
        backend: root_operation.Backend,
        operation: root_operation.Operation,
        state: root_operation.State,
        mutation_started: bool,
    },
    deferred_owner: ?root_operation.DeferredAcknowledgmentState,
    native_active_evidence: bool,
};

pub const OwnedResult = struct {
    result: Result,
    arena: std.heap.ArenaAllocator,
    native_install: ?product.NativeInstallEvidence = null,
    native_completion: ?product.NativeCompletionEvidence = null,
    native_inspection: ?NativeInspection = null,

    pub fn deinit(self: *@This()) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const VerifiedNativeCompletion = struct {
    summary: native_transaction_result.Summary,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.summary.install_root);
        self.* = undefined;
    }
};

/// Native operations have no injectable command-oriented backend or legacy fallback.
pub const NativeBackend = struct {
    io: std.Io,
    now_unix: ?i64 = null,

    /// Read-only proof of a settled successful transaction, not execution,
    /// recovery, an unchanged result, or authority to publish an image.
    pub fn verifyCompletedSuccess(self: @This(), allocator: std.mem.Allocator, original: Request) !VerifiedNativeCompletion {
        return self.verifyCompleted(allocator, original, null);
    }

    pub fn verifyCompletedResultSuccess(
        self: @This(),
        allocator: std.mem.Allocator,
        original: Request,
        returned: product.NativeCompletionEvidence,
    ) !VerifiedNativeCompletion {
        if (returned.outcome != .succeeded or returned.settlement != .cleared)
            return error.InvalidNativeFamilyCompletion;
        return self.verifyCompleted(allocator, original, returned);
    }

    fn verifyCompleted(
        self: @This(),
        allocator: std.mem.Allocator,
        original: Request,
        returned: ?product.NativeCompletionEvidence,
    ) !VerifiedNativeCompletion {
        if (!validRequest(original, .native) or switch (original.operation) {
            .create, .customize, .update => false,
            else => true,
        }) return error.InvalidNativeFamilyVerificationRequest;
        var mapped = try MappedRequest.init(allocator, original);
        defer mapped.deinit();
        if (product.validate(mapped.request) != null)
            return error.InvalidNativeFamilyVerificationRequest;

        const path = original.lock_input.?;
        var parent = try root_fs.openAbsoluteRoot(self.io, std.fs.path.dirname(path).?);
        defer parent.close();
        const store = try exact_lock_v2.Store.init(self.io, parent.root.dir, std.fs.path.basename(path));
        var lock = try store.read(allocator, exact_lock_v2.maximum_document_bytes);
        defer lock.deinit();
        var root = try root_fs.openAbsoluteRoot(self.io, original.root);
        defer root.close();
        var locks: root_operation.SystemLockBackend = .{ .allocator = allocator, .io = self.io };
        var summary = native_transaction_result.verifyForCaller(
            allocator,
            root.root,
            original.root,
            lock.lock,
            original.architecture.spelling(),
            .{
                .operation = mapped.request.operation,
                .request_sha256 = production.productRequestDigest(mapped.request),
                .policy_sha256 = production.planningPolicyDigest(.native, mapped.request.options),
                .foreign_architectures = mapped.request.options.foreign_architectures,
                .completion = returned,
            },
            locks.interface(),
        ) catch |err| switch (err) {
            error.CallerRequestMismatch => return error.NativeFamilyRequestMismatch,
            error.CompletionResultMismatch => return error.NativeFamilyCompletionMismatch,
            else => return err,
        };
        summary.install_root = try allocator.dupe(u8, summary.install_root);
        return .{ .summary = summary, .allocator = allocator };
    }

    pub fn execute(self: @This(), allocator: std.mem.Allocator, request: Request) !OwnedResult {
        return self.executeInternal(allocator, request, false);
    }

    /// Resolve an update-bound lock using a resolve_lock request. An omitted
    /// package selects upgrade-all; ordinary execute resolution stays install-only.
    pub fn resolveUpdateLock(self: @This(), allocator: std.mem.Allocator, request: Request) !OwnedResult {
        return self.executeInternal(allocator, request, true);
    }

    fn executeInternal(self: @This(), allocator: std.mem.Allocator, request: Request, update_planning: bool) !OwnedResult {
        var arena: std.heap.ArenaAllocator = .init(allocator);
        errdefer arena.deinit();
        const owned = arena.allocator();
        var native_install: ?product.NativeInstallEvidence = null;
        var native_completion: ?product.NativeCompletionEvidence = null;
        var native_inspection: ?NativeInspection = null;
        var result: Result = output: {
            if (!std.mem.eql(u8, request.schema, native_request_schema) or request.version != native_schema_version)
                break :output failure(request.operation, .usage, .invalid_request, "native package-family requests require schema v2", false);
            if (update_planning and request.operation != .resolve_lock)
                break :output failure(request.operation, .usage, .invalid_request, "native update lock resolution requires a resolve_lock request", false);
            if (!validRequestFor(request, .native, update_planning))
                break :output failure(request.operation, .usage, .invalid_request, "invalid explicit native package-family request", false);

            var mapped = try MappedRequest.init(owned, request);
            defer mapped.deinit();
            if (request.operation == .inspect) {
                if (product.validate(mapped.request)) |invalid|
                    break :output failure(request.operation, invalid.exit_status, .invalid_request, invalid.summary, false);
                native_inspection = self.readInspection(owned, request) catch |err| {
                    if (err == error.OutOfMemory) return err;
                    break :output failure(
                        request.operation,
                        .unavailable,
                        .native_inspection_unavailable,
                        try std.fmt.allocPrint(owned, "native diagnostic inspection failed: {s}", .{@errorName(err)}),
                        false,
                    );
                };
                break :output .{ .operation = .inspect, .succeeded = true, .exit_status = .success };
            }
            const lock_path = if (request.lock_output orelse request.lock_input) |path|
                try owned.dupe(u8, path)
            else
                null;
            const provenance_path = if (request.operation != .resolve_lock)
                try std.fmt.allocPrint(owned, "{s}/{s}", .{ request.root, native_provenance.document_path })
            else
                null;
            var native: production.Backend = .{
                .io = self.io,
                .transaction_backend = .native,
                .now_unix = self.now_unix,
            };
            const response = if (update_planning) planning: {
                if (product.validate(mapped.request)) |invalid| break :planning invalid;
                var selectors: [1]solver.PackageSelector = undefined;
                if (request.package) |package| selectors[0] = production.parseSelector(package);
                break :planning try native.executeWorkflow(owned, .{
                    .operation = if (request.package == null) .upgrade_all else .upgrade,
                    .mode = .plan_only,
                    .selectors = selectors[0..@intFromBool(request.package != null)],
                    .options = mapped.request.options,
                });
            } else try product.execute(owned, mapped.request, native.interface());
            defer freePackageFamilyProductItems(owned, response.items);
            native_install = response.native_install;
            native_completion = response.native_completion;
            if (!consistentNativeEvidence(mapped.request, response))
                break :output nativeEvidenceFailure(request.operation, response.changed, "native package-family result evidence is inconsistent");

            if (response.exit_status != .success) {
                var failed = failure(
                    request.operation,
                    response.exit_status,
                    .backend_failed,
                    response.summary,
                    response.exit_status == .transaction or response.exit_status == .recovery,
                );
                failed.changed = response.changed;
                if (native_completion != null) failed.provenance_path = provenance_path;
                break :output failed;
            }
            if (response.changed and request.operation != .recover) {
                var verified = self.verifyCompletedResultSuccess(owned, request, native_completion.?) catch |err| {
                    if (err == error.OutOfMemory) return err;
                    break :output nativeEvidenceFailure(
                        request.operation,
                        response.changed,
                        try std.fmt.allocPrint(owned, "native completion verification failed: {s}", .{@errorName(err)}),
                    );
                };
                defer verified.deinit();
                if (native_install) |install|
                    if (verified.summary.package_count != install.package_count)
                        break :output nativeEvidenceFailure(request.operation, response.changed, "native completion package count differs from the returned install evidence");
            }
            break :output .{
                .operation = request.operation,
                .succeeded = true,
                .changed = response.changed,
                .exit_status = .success,
                .lock_path = lock_path,
                .provenance_path = if (native_completion != null) provenance_path else null,
            };
        };
        result.schema = native_result_schema;
        result.version = native_schema_version;
        return .{
            .result = result,
            .arena = arena,
            .native_install = native_install,
            .native_completion = native_completion,
            .native_inspection = native_inspection,
        };
    }

    fn readInspection(self: @This(), allocator: std.mem.Allocator, request: Request) !NativeInspection {
        const started_ns = std.Io.Clock.awake.now(self.io).nanoseconds;
        var root = try root_fs.openAbsoluteRoot(self.io, request.root);
        defer root.close();
        try native_operation.validateInstallRoot(self.io, root.root, request.root, null);
        const original = try root.root.rootEntry();
        try checkInspectionDeadline(started_ns, std.Io.Clock.awake.now(self.io).nanoseconds, request.deadline_ms);
        const status_path = try root_fs.Path.init("var/lib/dpkg/status");
        const present = try root.root.entryIfExists(status_path) != null;
        const options: dpkg_status.Options = .{};
        const bytes = if (present)
            try root.root.readFileAlloc(allocator, status_path, options.limits.deb822.max_total_bytes)
        else
            &.{};
        defer allocator.free(bytes);
        var parsed = try dpkg_status.parseBorrowed(allocator, bytes, options);
        defer if (parsed == .database) parsed.database.deinit();
        const database = switch (parsed) {
            .diagnostic => return error.InvalidInstalledState,
            .database => |value| value,
        };
        try checkInspectionDeadline(started_ns, std.Io.Clock.awake.now(self.io).nanoseconds, request.deadline_ms);
        const packages = try allocator.alloc(InspectedPackage, database.packages.len);
        for (database.packages, packages) |package, *item| item.* = .{
            .name = try allocator.dupe(u8, package.name.value),
            .version = try allocator.dupe(u8, package.version.spelling.value),
            .architecture = try allocator.dupe(u8, package.architecture.value),
            .status = package.status,
        };
        std.mem.sort(InspectedPackage, packages, {}, lessInspectedPackage);

        const store = root_operation.Store.init(root.root);
        var operation = try store.read(allocator);
        defer if (operation) |*value| value.deinit();
        const owner = try store.readDeferredAcknowledgment(allocator);
        const active = try native_runtime.hasActiveEvidence(allocator, root.root);
        var named = try root_fs.openAbsoluteRoot(self.io, request.root);
        defer named.close();
        const current = try named.root.rootEntry();
        if (original.inode != current.inode or original.device != current.device)
            return error.RootIdentityMismatch;
        try checkInspectionDeadline(started_ns, std.Io.Clock.awake.now(self.io).nanoseconds, request.deadline_ms);
        return .{
            .root = try allocator.dupe(u8, request.root),
            .status_database_present = present,
            .packages = packages,
            .observed_operation = if (operation) |value| .{
                .backend = value.record.backend,
                .operation = value.record.operation,
                .state = value.record.state,
                .mutation_started = value.record.mutation_started,
            } else null,
            .deferred_owner = if (owner) |value| value.state else null,
            .native_active_evidence = active,
        };
    }
};

fn lessInspectedPackage(_: void, left: InspectedPackage, right: InspectedPackage) bool {
    const name_order = std.mem.order(u8, left.name, right.name);
    if (name_order != .eq) return name_order == .lt;
    return std.mem.lessThan(u8, left.architecture, right.architecture);
}

fn checkInspectionDeadline(started_ns: i128, now_ns: i128, deadline_ms: ?u64) error{DeadlineExceeded}!void {
    if (deadline_ms) |limit|
        if (now_ns - started_ns >= @as(i128, limit) * std.time.ns_per_ms)
            return error.DeadlineExceeded;
}

fn nativeEvidenceFailure(operation: Operation, changed: bool, message: []const u8) Result {
    var result = failure(operation, .recovery, .native_evidence_unavailable, message, true);
    result.changed = changed;
    return result;
}

fn consistentNativeEvidence(request: product.Request, response: product.Result) bool {
    if (response.operation != request.operation) return false;
    if (response.native_completion) |completion| {
        if (!response.changed or completion.settlement != .cleared or
            (completion.outcome == .succeeded) != (response.exit_status == .success) or
            (completion.outcome == .failed and response.exit_status != .transaction))
            return false;
        if (request.operation != .recover and
            (completion.operation != request.operation or
                !std.mem.eql(u8, &completion.caller_request_sha256, &production.productRequestDigest(request)) or
                !std.mem.eql(u8, &completion.caller_policy_sha256, &production.planningPolicyDigest(.native, request.options))))
            return false;
    }
    if (request.operation == .plan)
        return !response.changed and response.native_install == null and response.native_completion == null;
    if (request.operation == .recover)
        return response.native_install == null and
            (response.exit_status != .success or response.changed == (response.native_completion != null));
    if (response.exit_status != .success) return response.native_install == null;
    if (request.operation == .upgrade or request.operation == .upgrade_all)
        return response.native_install == null and response.changed == (response.native_completion != null);
    const install = response.native_install orelse return false;
    if (!std.mem.eql(u8, &install.caller_request_sha256, &production.productRequestDigest(request)) or
        !std.mem.eql(u8, &install.caller_policy_sha256, &production.planningPolicyDigest(.native, request.options)) or
        response.changed != (install.receipt != null) or
        response.changed != (response.native_completion != null))
        return false;
    if (install.receipt) |receipt| {
        const completion = response.native_completion.?;
        return std.mem.eql(u8, &install.lock_sha256, &completion.lock_sha256) and
            std.mem.eql(u8, &receipt.transaction_digest_sha256, &completion.transaction_digest_sha256) and
            std.mem.eql(u8, &receipt.completion_digest_sha256, &completion.completion_digest_sha256) and
            std.mem.eql(u8, &receipt.program_sha256, &completion.program_sha256);
    }
    return true;
}

fn freePackageFamilyProductItems(allocator: std.mem.Allocator, items: []const product.Item) void {
    for (items) |item| {
        allocator.free(item.package);
        if (item.version) |value| allocator.free(value);
        if (item.architecture) |value| allocator.free(value);
    }
    allocator.free(items);
}

fn validRequest(request: Request, kind: transaction_engine.Kind) bool {
    return validRequestFor(request, kind, false);
}

fn validRequestFor(request: Request, kind: transaction_engine.Kind, update_planning: bool) bool {
    const expected_schema = if (kind == .native) native_request_schema else request_schema;
    const expected_version = if (kind == .native) native_schema_version else schema_version;
    if (!std.mem.eql(u8, request.schema, expected_schema) or request.version != expected_version) return false;
    if (update_planning and (kind != .native or request.operation != .resolve_lock)) return false;
    if (!absolute(request.root) or !absolute(request.cache) or !absolute(request.state)) return false;
    if (kind == .native and (request.operation == .recover or request.operation == .inspect)) {
        return request.package == null and request.lock_input == null and request.lock_output == null and
            request.sources.len == 0 and request.configs.len == 0 and request.keyrings.len == 0 and
            request.credential_reference == null and request.proxy == null and
            request.cache_mode == .online and request.repository_policy == .strict_priority and
            !request.recommends and !request.allow_downgrade and request.conffile == .keep_existing and
            (request.operation != .inspect or request.lock_wait_ms == 30_000) and
            (request.deadline_ms == null or request.deadline_ms.? != 0);
    }
    if ((request.sources.len == 0 and request.configs.len == 0) or
        request.keyrings.len == 0 or
        (request.deadline_ms != null and request.deadline_ms.? == 0)) return false;
    for (request.sources) |path| if (!absolute(path)) return false;
    for (request.configs) |path| if (!absolute(path)) return false;
    for (request.keyrings) |path| if (!absolute(path)) return false;
    for (request.foreign_architectures) |architecture|
        if (architecture == request.architecture) return false;
    if (((request.operation == .resolve_lock and !update_planning) or request.operation == .create or request.operation == .customize) and request.package == null) return false;
    if (request.operation == .resolve_lock) {
        if (request.lock_input != null or request.lock_output == null) return false;
    } else if (request.operation != .inspect and request.lock_input == null) return false;
    if (request.lock_output != null and request.lock_input == null and request.operation != .resolve_lock) return false;
    if (request.lock_input) |path| if (!absolute(path)) return false;
    if (request.lock_output) |path| if (!absolute(path)) return false;
    if (request.credential_reference) |path| if (!absolute(path)) return false;
    return true;
}

fn absolute(path: []const u8) bool {
    return path.len > 1 and path[0] == '/' and path[path.len - 1] != '/';
}

fn failure(
    operation: Operation,
    status: product.ExitStatus,
    id: ErrorId,
    message: []const u8,
    recoverable: bool,
) Result {
    return .{
        .operation = operation,
        .succeeded = false,
        .exit_status = status,
        .diagnostic = .{ .id = id, .message = message, .recoverable = recoverable },
    };
}

const Fake = struct {
    seen: bool = false,
    operation: ?product.Operation = null,
    return_item: bool = false,

    fn execute(context: *anyopaque, allocator: std.mem.Allocator, request: product.Request) !product.Result {
        const self: *Fake = @ptrCast(@alignCast(context));
        self.seen = true;
        self.operation = request.operation;
        try std.testing.expectEqualStrings("arm64", request.options.architecture);
        try std.testing.expect(request.options.cache_only);
        try std.testing.expectEqualStrings("ubuntu-minimal", request.packages[0]);
        try std.testing.expectEqual(@as(?u64, null), request.options.deadline_ms);
        const items = if (self.return_item) blk: {
            const result = try allocator.alloc(product.Item, 1);
            result[0] = .{
                .package = try allocator.dupe(u8, "ubuntu-minimal"),
                .version = try allocator.dupe(u8, "1"),
                .architecture = try allocator.dupe(u8, "arm64"),
                .detail = "install",
            };
            break :blk result;
        } else &.{};
        return .{
            .operation = request.operation,
            .exit_status = .success,
            .changed = request.operation.mutates(),
            .summary = "ok",
            .items = items,
        };
    }
};

test "capabilities are versioned and apt-free" {
    const value = capabilities();
    try std.testing.expectEqual(schema_version, value.version);
    try std.testing.expect(!value.invokes_apt);
    try std.testing.expectEqualStrings("amd64", value.architectures[0]);
    try std.testing.expectEqualStrings("arm64", value.architectures[1]);
}

test "native capabilities advertise integrated native family contracts" {
    const value = nativeCapabilities();
    try std.testing.expectEqual(native_schema_version, value.version);
    try std.testing.expectEqual(transaction_engine.Kind.native, value.transaction_backend);
    try std.testing.expectEqualStrings(exact_lock_v2.schema_id, value.exact_lock_schema);
    try std.testing.expectEqual(@as(usize, 6), value.operations.len);
    try std.testing.expectEqualStrings("resolve-lock", value.operations[0]);
    try std.testing.expectEqualStrings(native_provenance.schema_id, value.provenance_schema.?);
    try std.testing.expect(!value.invokes_apt and !value.invokes_dpkg);
    const bytes = try value.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"recovery\":\"disposable_or_recoverable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"operations\":[\"resolve-lock\",\"create\",\"customize\",\"update\",\"recover\",\"inspect\"]") != null);
}

test "capability backend selection preserves defaults and rejects ambiguous options" {
    try std.testing.expectEqual(transaction_engine.Kind.legacy_dpkg, try parseCapabilitiesBackend(&.{}));
    inline for (.{ "legacy_dpkg", "native" }) |value|
        try std.testing.expectEqual(std.meta.stringToEnum(transaction_engine.Kind, value).?, try parseCapabilitiesBackend(&.{ "--transaction-backend", value }));
    try std.testing.expectError(error.InvalidTransactionBackend, parseCapabilitiesBackend(&.{ "--transaction-backend", "other" }));
    for ([_][]const []const u8{
        &.{"--transaction-backend"},
        &.{ "--transaction-backend", "native", "--transaction-backend", "legacy_dpkg" },
        &.{ "--unknown", "native" },
        &.{"native"},
    }) |arguments| try std.testing.expectError(error.InvalidCapabilityOptions, parseCapabilitiesBackend(arguments));
}

test "native family version gates run before filesystem access" {
    const backend: NativeBackend = .{ .io = std.testing.io };
    var request: Request = .{
        .operation = .resolve_lock,
        .root = "/missing-native-family-root",
        .architecture = .amd64,
        .sources = &.{"/missing-family-source"},
        .keyrings = &.{"/missing-family-key"},
        .cache = "/missing-family-cache",
        .state = "/missing-family-state",
        .package = "hello",
        .lock_output = "/missing-family-lock",
    };
    var old = try backend.execute(std.testing.allocator, request);
    defer old.deinit();
    try std.testing.expectEqual(product.ExitStatus.usage, old.result.exit_status);
    try std.testing.expectEqualStrings(native_result_schema, old.result.schema);
    request.schema = native_request_schema;
    request.version = native_schema_version;
    var fake: Fake = .{};
    const legacy: Backend = .{ .product_backend = .{ .context = &fake, .executeFn = Fake.execute } };
    request.operation = .resolve_lock;
    const wrong = try legacy.execute(std.testing.allocator, request);
    try std.testing.expectEqual(product.ExitStatus.usage, wrong.exit_status);
    try std.testing.expectEqualStrings(result_schema, wrong.schema);
    try std.testing.expect(!fake.seen);
}

test "native family product refusal retains owned diagnostics and releases failed allocations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn exercise(allocator: std.mem.Allocator) !void {
            const backend: NativeBackend = .{ .io = std.testing.io };
            var result = try backend.execute(allocator, .{
                .schema = native_request_schema,
                .version = native_schema_version,
                .operation = .resolve_lock,
                .root = "/missing-native-family-root",
                .architecture = .amd64,
                .sources = &.{"/missing-family-source"},
                .keyrings = &.{"/missing-family-key"},
                .cache = "/missing-family-cache",
                .state = "/missing-family-state",
                .package = "",
                .lock_output = "/missing-family-lock",
            });
            defer result.deinit();
            try std.testing.expectEqual(product.ExitStatus.usage, result.result.exit_status);
            try std.testing.expectEqualStrings(native_result_schema, result.result.schema);
            try std.testing.expectEqual(ErrorId.backend_failed, result.result.diagnostic.?.id);
            try std.testing.expect(!result.result.succeeded and !result.result.changed);
            try std.testing.expect(!result.result.diagnostic.?.recoverable);
        }
    }.exercise, .{});
}

test "native family recovery rejects replacement inputs and execution policy before filesystem work" {
    const backend: NativeBackend = .{ .io = std.testing.io };
    const original: Request = .{
        .schema = native_request_schema,
        .version = native_schema_version,
        .operation = .recover,
        .root = "/missing-native-family-root",
        .architecture = .amd64,
        .sources = &.{},
        .keyrings = &.{},
        .cache = "/missing-family-cache",
        .state = "/missing-family-state",
    };
    try std.testing.expect(validRequest(original, .native));
    var variants: [12]Request = @splat(original);
    variants[0].package = "replacement";
    variants[1].sources = &.{"/replacement-source"};
    variants[2].configs = &.{"/replacement-config"};
    variants[3].keyrings = &.{"/replacement-key"};
    variants[4].lock_input = "/replacement-lock";
    variants[5].lock_output = "/replacement-output";
    variants[6].credential_reference = "/replacement-credential";
    variants[7].proxy = "http://example.invalid";
    variants[8].recommends = true;
    variants[9].allow_downgrade = true;
    variants[10].repository_policy = .best_version;
    variants[11].conffile = .use_package_version;
    for (variants) |request| {
        var refused = try backend.execute(std.testing.allocator, request);
        defer refused.deinit();
        try std.testing.expectEqual(product.ExitStatus.usage, refused.result.exit_status);
        try std.testing.expectEqual(ErrorId.invalid_request, refused.result.diagnostic.?.id);
        try std.testing.expect(!refused.result.changed and refused.result.provenance_path == null);
        try std.testing.expect(refused.native_completion == null and refused.native_install == null);
    }
}

test "native diagnostic inspection rejects execution inputs and lock waiting" {
    const backend: NativeBackend = .{ .io = std.testing.io };
    const original: Request = .{
        .schema = native_request_schema,
        .version = native_schema_version,
        .operation = .inspect,
        .root = "/missing-native-family-root",
        .architecture = .amd64,
        .sources = &.{},
        .keyrings = &.{},
        .cache = "/unused-family-cache",
        .state = "/unused-family-state",
    };
    try std.testing.expect(validRequest(original, .native));
    var variants: [17]Request = @splat(original);
    variants[0].root = "/";
    variants[1].package = "filter";
    variants[2].sources = &.{"/unused-source"};
    variants[3].configs = &.{"/unused-config"};
    variants[4].keyrings = &.{"/unused-key"};
    variants[5].lock_input = "/unused-lock";
    variants[6].lock_output = "/unused-output";
    variants[7].credential_reference = "/unused-credential";
    variants[8].proxy = "http://example.invalid";
    variants[9].recommends = true;
    variants[10].allow_downgrade = true;
    variants[11].repository_policy = .best_version;
    variants[12].conffile = .use_package_version;
    variants[13].cache_mode = .offline;
    variants[14].lock_wait_ms = 1;
    variants[15].deadline_ms = 0;
    variants[16].foreign_architectures = &.{.amd64};
    for (variants) |request| {
        var refused = try backend.execute(std.testing.allocator, request);
        defer refused.deinit();
        try std.testing.expectEqual(product.ExitStatus.usage, refused.result.exit_status);
        try std.testing.expect(!refused.result.changed);
        try std.testing.expect(refused.result.lock_path == null and refused.result.provenance_path == null);
        try std.testing.expect(refused.native_inspection == null and refused.native_install == null and refused.native_completion == null);
    }
}

test "native diagnostic deadline uses the complete elapsed budget without overflow" {
    try checkInspectionDeadline(10, 10 + std.time.ns_per_ms - 1, 1);
    try std.testing.expectError(error.DeadlineExceeded, checkInspectionDeadline(10, 10 + std.time.ns_per_ms, 1));
    try checkInspectionDeadline(0, std.math.maxInt(u64), std.math.maxInt(u64));
    try checkInspectionDeadline(0, std.math.maxInt(i128), null);
}

test "native update resolution is explicit and preserves ordinary request admission" {
    const backend: NativeBackend = .{ .io = std.testing.io };
    var request: Request = .{
        .schema = native_request_schema,
        .version = native_schema_version,
        .operation = .resolve_lock,
        .root = "/missing-native-family-root",
        .architecture = .amd64,
        .sources = &.{"/missing-family-source"},
        .keyrings = &.{"/missing-family-key"},
        .cache = "/missing-family-cache",
        .state = "/missing-family-state",
        .lock_output = "/missing-family-lock",
    };
    try std.testing.expect(validRequestFor(request, .native, true));
    try std.testing.expect(!validRequest(request, .native));
    var ordinary = try backend.execute(std.testing.allocator, request);
    defer ordinary.deinit();
    try std.testing.expectEqual(product.ExitStatus.usage, ordinary.result.exit_status);
    for ([_]Operation{ .create, .customize, .update, .recover, .inspect }) |operation| {
        request.operation = operation;
        var refused = try backend.resolveUpdateLock(std.testing.allocator, request);
        defer refused.deinit();
        try std.testing.expectEqual(product.ExitStatus.usage, refused.result.exit_status);
        try std.testing.expectEqual(ErrorId.invalid_request, refused.result.diagnostic.?.id);
        try std.testing.expect(!refused.result.changed and refused.result.lock_path == null);
        try std.testing.expect(refused.native_completion == null and refused.native_install == null);
    }
    request.operation = .resolve_lock;
    request.schema = request_schema;
    request.version = schema_version;
    try std.testing.expect(!validRequestFor(request, .legacy_dpkg, true));
    var old = try backend.resolveUpdateLock(std.testing.allocator, request);
    defer old.deinit();
    try std.testing.expectEqual(product.ExitStatus.usage, old.result.exit_status);
}

test "native update resolution releases invalid selector allocations without filesystem work" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn exercise(allocator: std.mem.Allocator) !void {
            const backend: NativeBackend = .{ .io = std.testing.io };
            var result = try backend.resolveUpdateLock(allocator, .{
                .schema = native_request_schema,
                .version = native_schema_version,
                .operation = .resolve_lock,
                .root = "/missing-native-family-root",
                .architecture = .amd64,
                .sources = &.{"/missing-family-source"},
                .keyrings = &.{"/missing-family-key"},
                .cache = "/missing-family-cache",
                .state = "/missing-family-state",
                .package = "",
                .lock_output = "/missing-family-lock",
            });
            defer result.deinit();
            try std.testing.expectEqual(product.ExitStatus.usage, result.result.exit_status);
            try std.testing.expectEqual(ErrorId.backend_failed, result.result.diagnostic.?.id);
            try std.testing.expect(!result.result.changed and result.result.lock_path == null);
        }
    }.exercise, .{});
}

test "native update completion does not invent install or unchanged receipt evidence" {
    for ([_]product.Operation{ .upgrade, .upgrade_all }) |operation| {
        const request: product.Request = .{
            .operation = operation,
            .packages = if (operation == .upgrade) &.{"hello"} else &.{},
            .options = .{
                .install_root = "/family-root",
                .cache_path = "/family-cache",
                .state_path = "/family-state",
                .architecture = "amd64",
                .conffile = .keep_existing,
            },
        };
        var response: product.Result = .{
            .operation = operation,
            .exit_status = .success,
            .summary = "no package changes",
        };
        try std.testing.expect(consistentNativeEvidence(request, response));
        response.changed = true;
        try std.testing.expect(!consistentNativeEvidence(request, response));
        response.native_completion = .{
            .operation = operation,
            .outcome = .succeeded,
            .settlement = .cleared,
            .attempt_id = @splat(1),
            .lock_sha256 = @splat(2),
            .caller_request_sha256 = production.productRequestDigest(request),
            .caller_policy_sha256 = production.planningPolicyDigest(.native, request.options),
            .transaction_digest_sha256 = @splat(3),
            .completion_digest_sha256 = @splat(4),
            .program_sha256 = @splat(5),
        };
        try std.testing.expect(consistentNativeEvidence(request, response));
        response.changed = false;
        try std.testing.expect(!consistentNativeEvidence(request, response));
        response.changed = true;
        response.native_completion.?.operation = .install;
        try std.testing.expect(!consistentNativeEvidence(request, response));
        response.native_completion.?.operation = operation;
        response.native_completion.?.caller_request_sha256[0] ^= 1;
        try std.testing.expect(!consistentNativeEvidence(request, response));
        response.native_completion.?.caller_request_sha256[0] ^= 1;
        response.native_completion.?.outcome = .failed;
        try std.testing.expect(!consistentNativeEvidence(request, response));
        response.exit_status = .transaction;
        try std.testing.expect(consistentNativeEvidence(request, response));
    }
}

test "native unchanged install evidence must remain bound and receipt-free" {
    const request: product.Request = .{
        .operation = .install,
        .packages = &.{"hello"},
        .options = .{
            .install_root = "/family-root",
            .cache_path = "/family-cache",
            .state_path = "/family-state",
            .architecture = "amd64",
            .conffile = .keep_existing,
        },
    };
    var response: product.Result = .{
        .operation = .install,
        .exit_status = .success,
        .summary = "no package changes",
        .native_install = .{
            .lock_sha256 = @splat(1),
            .caller_request_sha256 = production.productRequestDigest(request),
            .caller_policy_sha256 = production.planningPolicyDigest(.native, request.options),
            .package_count = 1,
        },
    };
    try std.testing.expect(consistentNativeEvidence(request, response));
    response.changed = true;
    try std.testing.expect(!consistentNativeEvidence(request, response));
    response.changed = false;
    response.native_install.?.caller_request_sha256[0] ^= 1;
    try std.testing.expect(!consistentNativeEvidence(request, response));
    response.native_install = null;
    try std.testing.expect(!consistentNativeEvidence(request, response));
}

test "native family completed verification admits only valid original native mutation requests" {
    const backend: NativeBackend = .{ .io = std.testing.io };
    var request: Request = .{
        .operation = .create,
        .root = "/missing-native-family-root",
        .architecture = .amd64,
        .sources = &.{"/missing-family-source"},
        .keyrings = &.{"/missing-family-key"},
        .cache = "/missing-family-cache",
        .state = "/missing-family-state",
        .package = "hello",
        .lock_input = "/missing-family-lock",
    };
    try std.testing.expectError(error.InvalidNativeFamilyVerificationRequest, backend.verifyCompletedSuccess(std.testing.allocator, request));
    request.schema = native_request_schema;
    request.version = native_schema_version;
    for ([_]Operation{ .resolve_lock, .recover, .inspect }) |operation| {
        request.operation = operation;
        try std.testing.expectError(error.InvalidNativeFamilyVerificationRequest, backend.verifyCompletedSuccess(std.testing.allocator, request));
    }
    request.operation = .create;
    request.root = "/missing/../root";
    try std.testing.expectError(error.InvalidNativeFamilyVerificationRequest, backend.verifyCompletedSuccess(std.testing.allocator, request));
    request.root = "/missing-native-family-root";
    request.foreign_architectures = &.{ .arm64, .arm64 };
    try std.testing.expectError(error.InvalidNativeFamilyVerificationRequest, backend.verifyCompletedSuccess(std.testing.allocator, request));
}

test "native family result verification refuses failed and retained completion before filesystem work" {
    const backend: NativeBackend = .{ .io = std.testing.io };
    const request: Request = .{
        .schema = native_request_schema,
        .version = native_schema_version,
        .operation = .create,
        .root = "/missing-native-family-root",
        .architecture = .amd64,
        .sources = &.{"/missing-family-source"},
        .keyrings = &.{"/missing-family-key"},
        .cache = "/missing-family-cache",
        .state = "/missing-family-state",
        .package = "hello",
        .lock_input = "/missing-family-lock",
    };
    var completion: product.NativeCompletionEvidence = .{
        .operation = .install,
        .outcome = .failed,
        .settlement = .cleared,
        .attempt_id = @splat(1),
        .lock_sha256 = @splat(2),
        .caller_request_sha256 = @splat(3),
        .caller_policy_sha256 = @splat(4),
        .transaction_digest_sha256 = @splat(5),
        .completion_digest_sha256 = @splat(6),
        .program_sha256 = @splat(7),
    };
    try std.testing.expectError(error.InvalidNativeFamilyCompletion, backend.verifyCompletedResultSuccess(std.testing.allocator, request, completion));
    completion.outcome = .succeeded;
    completion.settlement = .retained;
    try std.testing.expectError(error.InvalidNativeFamilyCompletion, backend.verifyCompletedResultSuccess(std.testing.allocator, request, completion));
}

test "native family verification request mapping propagates allocation failures without filesystem work" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn exercise(allocator: std.mem.Allocator) !void {
            const backend: NativeBackend = .{ .io = std.testing.io };
            var result = backend.verifyCompletedSuccess(allocator, .{
                .schema = native_request_schema,
                .version = native_schema_version,
                .operation = .create,
                .root = "/missing-native-family-root",
                .architecture = .amd64,
                .sources = &.{"/missing-family-source"},
                .keyrings = &.{"/missing-family-key"},
                .cache = "/missing-family-cache",
                .state = "/missing-family-state",
                .package = "",
                .lock_input = "/missing-family-lock",
                .foreign_architectures = &.{.arm64},
            }) catch |err| {
                if (err == error.InvalidNativeFamilyVerificationRequest) return;
                return err;
            };
            defer result.deinit();
            return error.ExpectedVerificationRefusal;
        }
    }.exercise, .{});
}

test "Ubuntu create maps explicit policy to product API" {
    var fake: Fake = .{ .return_item = true };
    const backend: Backend = .{ .product_backend = .{ .context = &fake, .executeFn = Fake.execute } };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .create,
        .root = "/build/root",
        .architecture = .arm64,
        .foreign_architectures = &.{.amd64},
        .sources = &.{"/build/sources"},
        .keyrings = &.{"/build/keyring.gpg"},
        .cache = "/build/cache",
        .state = "/build/state",
        .package = "ubuntu-minimal",
        .lock_input = "/build/core.lock.json",
        .cache_mode = .offline,
    });
    defer if (result.provenance_path) |path| std.testing.allocator.free(path);
    try std.testing.expect(result.succeeded);
    try std.testing.expectEqual(product.Operation.install, fake.operation.?);
}

test "initial lock resolution is non-mutating and requires a new lock path" {
    var fake: Fake = .{};
    const backend: Backend = .{ .product_backend = .{ .context = &fake, .executeFn = Fake.execute } };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .resolve_lock,
        .root = "/build/root",
        .architecture = .arm64,
        .sources = &.{"/build/sources"},
        .keyrings = &.{"/build/keyring.gpg"},
        .cache = "/build/cache",
        .state = "/build/state",
        .package = "ubuntu-minimal",
        .lock_output = "/build/core.lock.json",
        .cache_mode = .offline,
    });
    try std.testing.expect(result.succeeded);
    try std.testing.expectEqual(product.Operation.plan, fake.operation.?);
    try std.testing.expectEqualStrings("/build/core.lock.json", result.lock_path.?);
    try std.testing.expect(!result.changed);
}

test "immutable config can provide the repository source" {
    var fake: Fake = .{};
    const backend: Backend = .{ .product_backend = .{ .context = &fake, .executeFn = Fake.execute } };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .resolve_lock,
        .root = "/build/root",
        .architecture = .arm64,
        .sources = &.{},
        .configs = &.{"/build/immutable-source.json"},
        .keyrings = &.{"/build/keyring.gpg"},
        .cache = "/build/cache",
        .state = "/build/state",
        .package = "ubuntu-minimal",
        .lock_output = "/build/core.lock.json",
        .cache_mode = .offline,
    });
    try std.testing.expect(result.succeeded);
    try std.testing.expectEqual(product.Operation.plan, fake.operation.?);
}

test "mutations fail closed without required explicit inputs" {
    var fake: Fake = .{};
    const backend: Backend = .{ .product_backend = .{ .context = &fake, .executeFn = Fake.execute } };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .create,
        .root = "/build/root",
        .architecture = .amd64,
        .sources = &.{},
        .keyrings = &.{},
        .cache = "/build/cache",
        .state = "/build/state",
        .package = "ubuntu-minimal",
    });
    try std.testing.expect(!result.succeeded);
    try std.testing.expectEqual(ErrorId.invalid_request, result.diagnostic.?.id);
    try std.testing.expect(!fake.seen);
}

test "mutations require an exact lock before backend execution" {
    var fake: Fake = .{};
    const backend: Backend = .{ .product_backend = .{ .context = &fake, .executeFn = Fake.execute } };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .update,
        .root = "/build/root",
        .architecture = .amd64,
        .sources = &.{"/build/sources"},
        .keyrings = &.{"/build/keyring.gpg"},
        .cache = "/build/cache",
        .state = "/build/state",
    });
    try std.testing.expect(!result.succeeded);
    try std.testing.expectEqual(ErrorId.invalid_request, result.diagnostic.?.id);
    try std.testing.expect(!fake.seen);
}

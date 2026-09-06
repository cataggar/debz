//! Staged, in-memory change sets for the native package database.
//!
//! A change set turns typed database edits into a deterministic, fully
//! serialized publication plan: an ordered list of file intents relative to
//! `var/lib/dpkg`, each with its exact bytes and digest, bound to the exact
//! consumed database generation.
//!
//! Nothing here touches a filesystem. Planning is complete before the first
//! mutation, and the resulting model is validated with the same rules that
//! import uses, so a plan can never publish a database that would fail to
//! import. Executing a plan durably - staging, fsync, atomic rename, parent
//! directory fsync, `updates/` journalling, and crash recovery - belongs to
//! the mutation layer; performing a partial multi-file transaction here would
//! be unsafe, so this module deliberately refuses to do it.
const std = @import("std");
const database = @import("package_database.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Identity = database.Identity;
pub const Diagnostic = database.Diagnostic;
pub const Options = database.Options;
pub const CurrentState = database.CurrentState;

pub const StagedScript = struct {
    kind: database.ScriptKind,
    bytes: []const u8,
    mode: u32 = 0o755,
};

/// A complete package record plus every modeled `info` file it owns. A `null`
/// component means the file must not exist after publication; it is never
/// interpreted as "leave whatever is there".
pub const StagedPackage = struct {
    fields: []const database.StatusField,
    paths: ?[]const []const u8 = null,
    md5sums: ?[]const database.Md5sumEntry = null,
    declared_conffiles: ?[]const []const u8 = null,
    trigger_declarations: ?[]const database.TriggerDeclaration = null,
    scripts: []const StagedScript = &.{},
};

pub const StateChange = struct {
    identity: Identity,
    want: database.Want,
    error_state: database.ErrorState,
    current: CurrentState,
};

pub const FileListChange = struct {
    identity: Identity,
    paths: []const []const u8,
};

pub const Md5sumsChange = struct {
    identity: Identity,
    entries: []const database.Md5sumEntry,
};

pub const TriggerDeclarationsChange = struct {
    identity: Identity,
    declarations: []const database.TriggerDeclaration,
};

pub const InfoKind = enum {
    list,
    md5sums,
    conffiles,
    triggers,

    pub fn suffix(self: InfoKind) []const u8 {
        return @tagName(self);
    }
};

pub const InfoRemoval = struct {
    identity: Identity,
    kind: InfoKind,
};

pub const Change = union(enum) {
    /// Create or replace a complete package record and its modeled info files.
    put_package: StagedPackage,
    /// Publish a new package state without touching any other field.
    set_state: StateChange,
    put_file_list: FileListChange,
    put_md5sums: Md5sumsChange,
    put_trigger_declarations: TriggerDeclarationsChange,
    remove_info: InfoRemoval,
    /// Purge: drop the status record and every info file the package owns.
    remove_package: Identity,
    set_trigger_state: database.TriggerState,
    set_foreign_architectures: []const []const u8,
};

pub const WriteKind = enum {
    /// Atomically replace the target with `bytes`.
    replace,
    /// Remove the target if it exists.
    remove,
    /// Copy the current bytes of `source` to the target before `source` is
    /// republished, preserving the exact previous generation.
    copy,
};

pub const PlannedWrite = struct {
    /// Path relative to `var/lib/dpkg`.
    path: []const u8,
    kind: WriteKind,
    source: []const u8 = "",
    bytes: []const u8 = &.{},
    /// Content digest for `replace`, expected source digest for `copy`, and
    /// zero for `remove`.
    sha256: [32]u8 = @splat(0),
    mode: u32 = 0o644,
};

pub const Plan = struct {
    /// The exact generation the plan was authorized against.
    base_generation: database.Generation,
    base_status: database.StatusGeneration,
    resulting_status: database.StatusGeneration,
    writes: []const PlannedWrite,
    /// Stable digest over the base generation and every ordered intent.
    digest: [32]u8,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn find(self: Plan, path: []const u8) ?PlannedWrite {
        for (self.writes) |write| {
            if (std.mem.eql(u8, write.path, path)) return write;
        }
        return null;
    }
};

pub const PlanResult = union(enum) {
    plan: Plan,
    diagnostic: Diagnostic,
};

pub const Limits = struct {
    max_changes: usize = 100_000,
    max_writes: usize = 1_000_000,
};

pub const PlanOptions = struct {
    database: Options = .{},
    limits: Limits = .{},
};

/// Data-level guard for published state transitions. Lifecycle ordering,
/// script arguments, and trigger processing belong to the lifecycle engine;
/// this table only refuses transitions that dpkg's state machine never
/// publishes, such as a jump from `not-installed` straight to `installed`.
pub fn transitionAllowed(from: CurrentState, to: CurrentState) bool {
    if (from == to) return true;
    return switch (from) {
        .not_installed => switch (to) {
            .half_installed, .config_files => true,
            else => false,
        },
        .config_files => switch (to) {
            .half_installed, .not_installed => true,
            else => false,
        },
        .half_installed => switch (to) {
            .unpacked, .config_files, .not_installed => true,
            else => false,
        },
        .unpacked => switch (to) {
            .half_configured, .half_installed, .config_files, .not_installed => true,
            else => false,
        },
        .half_configured => switch (to) {
            .installed,
            .triggers_awaited,
            .triggers_pending,
            .unpacked,
            .half_installed,
            .config_files,
            => true,
            else => false,
        },
        .installed, .triggers_awaited, .triggers_pending => switch (to) {
            .installed,
            .triggers_awaited,
            .triggers_pending,
            .half_configured,
            .half_installed,
            .unpacked,
            .config_files,
            => true,
            else => false,
        },
    };
}

const PlanError = std.mem.Allocator.Error || error{Invalid};

const Builder = struct {
    arena: std.mem.Allocator,
    scratch: std.mem.Allocator,
    options: PlanOptions,
    base: database.Model,
    records: std.ArrayList(database.PackageRecord) = .empty,
    foreign: []const []const u8 = &.{},
    triggers: database.TriggerState = .{},
    writes: std.ArrayList(PlannedWrite) = .empty,
    targets: std.StringHashMapUnmanaged(void) = .empty,
    trigger_state_changed: bool = false,
    architectures_changed: bool = false,
    diagnostic: ?Diagnostic = null,

    fn deinit(self: *Builder) void {
        self.records.deinit(self.scratch);
        self.writes.deinit(self.scratch);
        var keys = self.targets.keyIterator();
        while (keys.next()) |key| self.scratch.free(key.*);
        self.targets.deinit(self.scratch);
    }

    fn fail(
        self: *Builder,
        code: database.Code,
        package: []const u8,
    ) error{Invalid} {
        self.diagnostic = .{
            .surface = .change_set,
            .code = code,
            .path = database.database_directory,
            .package = package,
        };
        return error.Invalid;
    }

    fn claim(self: *Builder, subject: []const u8) PlanError!void {
        const key = self.scratch.dupe(u8, subject) catch return error.OutOfMemory;
        const entry = self.targets.getOrPut(self.scratch, key) catch |err| {
            self.scratch.free(key);
            return err;
        };
        if (entry.found_existing) {
            self.scratch.free(key);
            return self.fail(.conflicting_change, subject);
        }
    }

    fn claimIdentity(self: *Builder, identity: Identity) PlanError!void {
        const subject = try std.fmt.allocPrint(
            self.scratch,
            "{s}:{s}",
            .{ identity.name, identity.architecture },
        );
        defer self.scratch.free(subject);
        try self.claim(subject);
    }

    fn indexOf(self: *Builder, identity: Identity) PlanError!usize {
        for (self.records.items, 0..) |record, index| {
            if (record.identity().eql(identity)) return index;
        }
        return self.fail(.unknown_package, identity.name);
    }

    fn stage(self: *Builder, write: PlannedWrite) PlanError!void {
        if (self.writes.items.len >= self.options.limits.max_writes) {
            return self.fail(.plan_limit, "");
        }
        try self.writes.append(self.scratch, write);
    }

    fn stageReplace(
        self: *Builder,
        path: []const u8,
        bytes: []const u8,
        mode: u32,
    ) PlanError!void {
        var digest: [32]u8 = undefined;
        Sha256.hash(bytes, &digest, .{});
        try self.stage(.{
            .path = path,
            .kind = .replace,
            .bytes = bytes,
            .sha256 = digest,
            .mode = mode,
        });
    }

    fn stageRemove(self: *Builder, path: []const u8) PlanError!void {
        try self.stage(.{ .path = path, .kind = .remove });
    }

    fn infoPath(self: *Builder, stem: []const u8, suffix: []const u8) PlanError![]const u8 {
        return std.fmt.allocPrint(self.arena, "{s}/{s}.{s}", .{
            database.info_directory,
            stem,
            suffix,
        });
    }

    fn validatePaths(self: *Builder, paths: []const []const u8, package: []const u8) PlanError!void {
        const limits = self.options.database.limits;
        if (paths.len > limits.max_paths_per_package) return self.fail(.path_limit, package);
        for (paths, 0..) |path, index| {
            if (path.len > limits.max_path_bytes) return self.fail(.path_too_long, package);
            if (!database.validListPath(path)) return self.fail(.invalid_path, package);
            for (paths[0..index]) |earlier| {
                if (std.mem.eql(u8, database.logicalListPath(earlier), database.logicalListPath(path))) {
                    return self.fail(.duplicate_path, package);
                }
            }
        }
    }

    fn validateMd5sums(
        self: *Builder,
        entries: []const database.Md5sumEntry,
        package: []const u8,
    ) PlanError!void {
        const limits = self.options.database.limits;
        if (entries.len > limits.max_md5sums_per_package) return self.fail(.checksum_limit, package);
        for (entries, 0..) |entry, index| {
            if (entry.path.len > limits.max_path_bytes) return self.fail(.path_too_long, package);
            if (!database.validRelativePath(entry.path)) return self.fail(.invalid_path, package);
            for (entries[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.path, entry.path)) {
                    return self.fail(.duplicate_checksum, package);
                }
            }
        }
    }

    fn validateDeclaredConffiles(
        self: *Builder,
        paths: []const []const u8,
        package: []const u8,
    ) PlanError!void {
        const limits = self.options.database.limits;
        if (paths.len > limits.max_conffiles_per_package) return self.fail(.conffile_limit, package);
        for (paths, 0..) |path, index| {
            if (path.len > limits.max_path_bytes) return self.fail(.path_too_long, package);
            if (!database.validAbsolutePath(path)) return self.fail(.invalid_path, package);
            for (paths[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier, path)) return self.fail(.duplicate_conffile, package);
            }
        }
    }

    fn validateDeclarations(
        self: *Builder,
        declarations: []const database.TriggerDeclaration,
        package: []const u8,
    ) PlanError!void {
        const limits = self.options.database.limits;
        if (declarations.len > limits.max_trigger_declarations_per_package) {
            return self.fail(.trigger_limit, package);
        }
        for (declarations, 0..) |declaration, index| {
            if (declaration.name.len > limits.max_trigger_name_bytes or
                !database.validTriggerName(declaration.name))
            {
                return self.fail(.invalid_trigger_name, package);
            }
            for (declarations[0..index]) |earlier| {
                if (earlier.kind == declaration.kind and
                    std.mem.eql(u8, earlier.name, declaration.name))
                {
                    return self.fail(.duplicate_trigger_declaration, package);
                }
            }
        }
    }

    fn guardCoverage(self: *Builder, record: database.PackageRecord) PlanError!void {
        for (self.base.diversions) |diversion| {
            if (diversion.package) |owner| {
                if (std.mem.eql(u8, owner, record.name)) {
                    return self.fail(.unsupported_diversion, record.name);
                }
                if (std.mem.startsWith(u8, owner, record.name) and
                    owner.len > record.name.len and owner[record.name.len] == ':')
                {
                    return self.fail(.unsupported_diversion, record.name);
                }
            }
            if (record.ownsPath(diversion.from) or record.ownsPath(diversion.to)) {
                return self.fail(.unsupported_diversion, record.name);
            }
        }
        for (self.base.stat_overrides) |override| {
            if (record.ownsPath(override.path)) {
                return self.fail(.unsupported_statoverride, record.name);
            }
        }
    }

    fn removeInfoFiles(
        self: *Builder,
        record: database.PackageRecord,
        keep: ?database.PackageRecord,
    ) PlanError!void {
        const kinds = [_]struct { kind: InfoKind, present: bool }{
            .{ .kind = .list, .present = record.paths != null },
            .{ .kind = .md5sums, .present = record.md5sums != null },
            .{ .kind = .conffiles, .present = record.declared_conffiles != null },
            .{ .kind = .triggers, .present = record.trigger_declarations != null },
        };
        for (kinds) |entry| {
            if (!entry.present) continue;
            if (keep) |replacement| {
                if (std.mem.eql(u8, replacement.info_stem, record.info_stem)) {
                    const still_present = switch (entry.kind) {
                        .list => replacement.paths != null,
                        .md5sums => replacement.md5sums != null,
                        .conffiles => replacement.declared_conffiles != null,
                        .triggers => replacement.trigger_declarations != null,
                    };
                    if (still_present) continue;
                }
            }
            try self.stageRemove(try self.infoPath(record.info_stem, entry.kind.suffix()));
        }
        for (record.scripts) |script| {
            if (keep) |replacement| {
                if (std.mem.eql(u8, replacement.info_stem, record.info_stem) and
                    replacement.script(script.kind) != null) continue;
            }
            try self.stageRemove(try self.infoPath(record.info_stem, script.kind.suffix()));
        }
        for (self.base.opaque_info) |entry| {
            const owner = entry.owner orelse continue;
            if (!owner.eql(record.identity())) continue;
            if (keep != null) continue;
            try self.stageRemove(try std.fmt.allocPrint(self.arena, "{s}/{s}", .{
                database.info_directory,
                entry.name,
            }));
        }
    }

    fn stagePackageInfo(
        self: *Builder,
        record: database.PackageRecord,
        scripts: []const StagedScript,
    ) PlanError!void {
        if (record.paths) |paths| {
            try self.stageReplace(
                try self.infoPath(record.info_stem, "list"),
                try database.writeFileList(self.arena, paths),
                0o644,
            );
        }
        if (record.md5sums) |entries| {
            try self.stageReplace(
                try self.infoPath(record.info_stem, "md5sums"),
                try database.writeMd5sums(self.arena, entries),
                0o644,
            );
        }
        if (record.declared_conffiles) |paths| {
            try self.stageReplace(
                try self.infoPath(record.info_stem, "conffiles"),
                try database.writeDeclaredConffiles(self.arena, paths),
                0o644,
            );
        }
        if (record.trigger_declarations) |declarations| {
            try self.stageReplace(
                try self.infoPath(record.info_stem, "triggers"),
                try database.writeTriggerDeclarations(self.arena, declarations),
                0o644,
            );
        }
        for (scripts) |script| {
            try self.stageReplace(
                try self.infoPath(record.info_stem, script.kind.suffix()),
                script.bytes,
                script.mode,
            );
        }
    }

    fn applyPut(self: *Builder, staged: StagedPackage) PlanError!void {
        const limits = self.options.database.limits;
        const interpreted = try database.interpretPackageFields(
            self.arena,
            staged.fields,
            self.options.database,
            .change_set,
        );
        var record = switch (interpreted) {
            .diagnostic => |diagnostic| {
                self.diagnostic = diagnostic;
                return error.Invalid;
            },
            .record => |value| value,
        };
        try self.claimIdentity(record.identity());
        if (staged.paths) |paths| try self.validatePaths(paths, record.name);
        if (staged.md5sums) |entries| try self.validateMd5sums(entries, record.name);
        if (staged.declared_conffiles) |paths| {
            try self.validateDeclaredConffiles(paths, record.name);
        }
        if (staged.trigger_declarations) |declarations| {
            try self.validateDeclarations(declarations, record.name);
        }
        record.paths = staged.paths;
        record.md5sums = staged.md5sums;
        record.declared_conffiles = staged.declared_conffiles;
        record.trigger_declarations = staged.trigger_declarations;

        const scripts = try self.arena.alloc(database.MaintainerScript, staged.scripts.len);
        for (staged.scripts, 0..) |script, index| {
            if (script.bytes.len == 0 or
                script.bytes.len > limits.max_maintainer_script_bytes or
                !database.safeFileMode(script.mode) or
                !database.executableFileMode(script.mode))
            {
                return self.fail(.invalid_script, record.name);
            }
            for (staged.scripts[0..index]) |earlier| {
                if (earlier.kind == script.kind) return self.fail(.invalid_script, record.name);
            }
            var digest: [32]u8 = undefined;
            Sha256.hash(script.bytes, &digest, .{});
            scripts[index] = .{
                .kind = script.kind,
                .mode = script.mode,
                .size = script.bytes.len,
                .sha256 = digest,
            };
        }
        record.scripts = scripts;
        try self.guardCoverage(record);

        var existing: ?database.PackageRecord = null;
        var position: ?usize = null;
        for (self.records.items, 0..) |candidate, index| {
            if (!candidate.identity().eql(record.identity())) continue;
            existing = candidate;
            position = index;
            break;
        }
        if (existing) |old| {
            if (!transitionAllowed(old.status.current, record.status.current)) {
                return self.fail(.invalid_transition, record.name);
            }
            // A stem change renames every info file. Modeled files and staged
            // scripts are republished under the new stem, but the bytes of
            // retained unmodeled info files are not part of the model, so
            // renaming them would either lose or orphan them.
            if (!std.mem.eql(u8, old.info_stem, record.info_stem)) {
                for (self.base.opaque_info) |entry| {
                    const owner = entry.owner orelse continue;
                    if (owner.eql(record.identity())) {
                        return self.fail(.unsupported_info_rename, record.name);
                    }
                }
            }
            try self.guardCoverage(old);
        }
        try self.stagePackageInfo(record, staged.scripts);
        if (existing) |old| {
            try self.removeInfoFiles(old, record);
            self.records.items[position.?] = record;
        } else {
            try self.records.append(self.scratch, record);
        }
    }

    fn applySetState(self: *Builder, change: StateChange) PlanError!void {
        try self.claimIdentity(change.identity);
        const index = try self.indexOf(change.identity);
        const old = self.records.items[index];
        if (!transitionAllowed(old.status.current, change.current)) {
            return self.fail(.invalid_transition, change.identity.name);
        }
        try self.guardCoverage(old);

        const lines = try self.arena.alloc([]const u8, 1);
        lines[0] = try std.fmt.allocPrint(self.arena, "{s} {s} {s}", .{
            @tagName(change.want),
            if (change.error_state == .ok) "ok" else "reinstreq",
            database.currentStateSpelling(change.current),
        });
        const fields = try self.arena.alloc(database.StatusField, old.fields.len);
        var replaced = false;
        for (old.fields, 0..) |field, position| {
            if (std.ascii.eqlIgnoreCase(field.name, "Status")) {
                fields[position] = .{ .name = field.name, .value_lines = lines };
                replaced = true;
            } else {
                fields[position] = field;
            }
        }
        if (!replaced) return self.fail(.missing_field, change.identity.name);

        var record = old;
        record.fields = fields;
        record.status = .{
            .want = change.want,
            .error_state = change.error_state,
            .current = change.current,
        };
        self.records.items[index] = record;
    }

    fn applyPutFileList(self: *Builder, change: FileListChange) PlanError!void {
        try self.claimIdentity(change.identity);
        const index = try self.indexOf(change.identity);
        try self.validatePaths(change.paths, change.identity.name);
        var record = self.records.items[index];
        try self.guardCoverage(record);
        record.paths = change.paths;
        try self.guardCoverage(record);
        self.records.items[index] = record;
        try self.stageReplace(
            try self.infoPath(record.info_stem, "list"),
            try database.writeFileList(self.arena, change.paths),
            0o644,
        );
    }

    fn applyPutMd5sums(self: *Builder, change: Md5sumsChange) PlanError!void {
        try self.claimIdentity(change.identity);
        const index = try self.indexOf(change.identity);
        try self.validateMd5sums(change.entries, change.identity.name);
        var record = self.records.items[index];
        record.md5sums = change.entries;
        self.records.items[index] = record;
        try self.stageReplace(
            try self.infoPath(record.info_stem, "md5sums"),
            try database.writeMd5sums(self.arena, change.entries),
            0o644,
        );
    }

    fn applyPutTriggerDeclarations(
        self: *Builder,
        change: TriggerDeclarationsChange,
    ) PlanError!void {
        try self.claimIdentity(change.identity);
        const index = try self.indexOf(change.identity);
        try self.validateDeclarations(change.declarations, change.identity.name);
        var record = self.records.items[index];
        record.trigger_declarations = change.declarations;
        self.records.items[index] = record;
        try self.stageReplace(
            try self.infoPath(record.info_stem, "triggers"),
            try database.writeTriggerDeclarations(self.arena, change.declarations),
            0o644,
        );
    }

    fn applyRemoveInfo(self: *Builder, change: InfoRemoval) PlanError!void {
        try self.claimIdentity(change.identity);
        const index = try self.indexOf(change.identity);
        var record = self.records.items[index];
        switch (change.kind) {
            .list => record.paths = null,
            .md5sums => record.md5sums = null,
            .conffiles => record.declared_conffiles = null,
            .triggers => record.trigger_declarations = null,
        }
        self.records.items[index] = record;
        try self.stageRemove(try self.infoPath(record.info_stem, change.kind.suffix()));
    }

    fn applyRemovePackage(self: *Builder, identity: Identity) PlanError!void {
        try self.claimIdentity(identity);
        const index = try self.indexOf(identity);
        const record = self.records.items[index];
        try self.guardCoverage(record);
        try self.removeInfoFiles(record, null);
        _ = self.records.orderedRemove(index);
    }

    fn applySetTriggerState(self: *Builder, state: database.TriggerState) PlanError!void {
        try self.claim("triggers");
        const limits = self.options.database.limits;
        if (state.interests.len > limits.max_trigger_interests or
            state.pending.len > limits.max_pending_triggers)
        {
            return self.fail(.trigger_limit, "");
        }
        for (state.interests) |interest| {
            if (interest.trigger.len == 0 or interest.trigger[0] != '/' or
                !database.validTriggerName(interest.trigger))
            {
                return self.fail(.invalid_trigger_name, interest.package.name);
            }
        }
        for (state.pending) |entry| {
            if (!database.validTriggerName(entry.trigger) or entry.packages.len == 0) {
                return self.fail(.invalid_trigger_record, "");
            }
        }
        self.triggers = state;
        self.trigger_state_changed = true;
    }

    fn applySetForeignArchitectures(self: *Builder, architectures: []const []const u8) PlanError!void {
        try self.claim("arch");
        const limits = self.options.database.limits;
        if (architectures.len > limits.max_foreign_architectures) {
            return self.fail(.architecture_limit, "");
        }
        for (architectures, 0..) |architecture, index| {
            if (architecture.len > limits.max_architecture_bytes or
                !database.validArchitecture(architecture))
            {
                return self.fail(.invalid_architecture_record, "");
            }
            if (std.mem.eql(u8, architecture, self.base.native_architecture)) {
                return self.fail(.native_architecture_listed, "");
            }
            for (architectures[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier, architecture)) {
                    return self.fail(.duplicate_architecture, "");
                }
            }
        }
        self.foreign = architectures;
        self.architectures_changed = true;
    }

    fn apply(self: *Builder, change: Change) PlanError!void {
        switch (change) {
            .put_package => |staged| try self.applyPut(staged),
            .set_state => |value| try self.applySetState(value),
            .put_file_list => |value| try self.applyPutFileList(value),
            .put_md5sums => |value| try self.applyPutMd5sums(value),
            .put_trigger_declarations => |value| try self.applyPutTriggerDeclarations(value),
            .remove_info => |value| try self.applyRemoveInfo(value),
            .remove_package => |value| try self.applyRemovePackage(value),
            .set_trigger_state => |value| try self.applySetTriggerState(value),
            .set_foreign_architectures => |value| try self.applySetForeignArchitectures(value),
        }
    }

    fn resultingModel(self: *Builder, status_bytes: []const u8) PlanError!database.Model {
        const packages = try self.arena.dupe(database.PackageRecord, self.records.items);
        var retained: std.ArrayList(database.OpaqueInfoFile) = .empty;
        defer retained.deinit(self.scratch);
        for (self.base.opaque_info) |entry| {
            const owner = entry.owner orelse {
                try retained.append(self.scratch, entry);
                continue;
            };
            for (packages) |record| {
                if (record.identity().eql(owner)) {
                    try retained.append(self.scratch, entry);
                    break;
                }
            }
        }
        var digest: [32]u8 = undefined;
        Sha256.hash(status_bytes, &digest, .{});
        return .{
            .native_architecture = self.base.native_architecture,
            .status = .{
                .sha256 = digest,
                .size = status_bytes.len,
                .package_count = packages.len,
            },
            .foreign_architectures = self.foreign,
            .packages = packages,
            .triggers = self.triggers,
            .diversions = self.base.diversions,
            .stat_overrides = self.base.stat_overrides,
            .opaque_info = try self.arena.dupe(database.OpaqueInfoFile, retained.items),
            .pending_updates = &.{},
            .status_old = self.base.status,
            .info_format_present = self.base.info_format_present,
        };
    }

    fn orderedWrites(self: *Builder, status_bytes: []const u8) PlanError![]const PlannedWrite {
        var ordered: std.ArrayList(PlannedWrite) = .empty;
        defer ordered.deinit(self.scratch);

        try ordered.append(self.scratch, .{
            .path = database.status_old_path,
            .kind = .copy,
            .source = database.status_path,
            .sha256 = self.base.status.sha256,
        });

        const info_writes = try self.scratch.dupe(PlannedWrite, self.writes.items);
        defer self.scratch.free(info_writes);
        std.mem.sort(PlannedWrite, info_writes, {}, lessWrite);
        for (info_writes, 0..) |write, index| {
            if (index != 0 and std.mem.eql(u8, info_writes[index - 1].path, write.path)) {
                return self.fail(.conflicting_change, "");
            }
            try ordered.append(self.scratch, write);
        }

        if (self.architectures_changed) {
            const bytes = try database.writeArchitectures(self.arena, self.foreign);
            var digest: [32]u8 = undefined;
            Sha256.hash(bytes, &digest, .{});
            try ordered.append(self.scratch, .{
                .path = database.arch_path,
                .kind = .replace,
                .bytes = bytes,
                .sha256 = digest,
            });
        }
        if (self.trigger_state_changed) {
            const interests = try database.writeTriggerInterests(self.arena, self.triggers.interests);
            var interests_digest: [32]u8 = undefined;
            Sha256.hash(interests, &interests_digest, .{});
            try ordered.append(self.scratch, .{
                .path = database.triggers_file_path,
                .kind = .replace,
                .bytes = interests,
                .sha256 = interests_digest,
            });
            const pending = try database.writePendingTriggers(self.arena, self.triggers.pending);
            var pending_digest: [32]u8 = undefined;
            Sha256.hash(pending, &pending_digest, .{});
            try ordered.append(self.scratch, .{
                .path = database.triggers_unincorp_path,
                .kind = .replace,
                .bytes = pending,
                .sha256 = pending_digest,
            });
        }

        var status_digest: [32]u8 = undefined;
        Sha256.hash(status_bytes, &status_digest, .{});
        try ordered.append(self.scratch, .{
            .path = database.status_path,
            .kind = .replace,
            .bytes = status_bytes,
            .sha256 = status_digest,
        });
        return try self.arena.dupe(PlannedWrite, ordered.items);
    }
};

fn lessWrite(_: void, left: PlannedWrite, right: PlannedWrite) bool {
    return std.mem.order(u8, left.path, right.path) == .lt;
}

fn planDigest(base: database.Generation, writes: []const PlannedWrite) [32]u8 {
    var buffer: [512]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    const writer = &sink.writer;
    writer.writeAll("debz.package-database.change-plan.v1\n") catch unreachable;
    writer.print("{x}\x00{d}\x00{d}\n", .{
        base.sha256,
        base.file_count,
        base.total_bytes,
    }) catch unreachable;
    for (writes) |write| {
        writer.print("{s}\x00{s}\x00{s}\x00{o}\x00{x}\n", .{
            write.path,
            @tagName(write.kind),
            write.source,
            write.mode,
            write.sha256,
        }) catch unreachable;
    }
    writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

/// Compile staged changes into one deterministic publication plan. The plan
/// is complete, validated, and bound to `source.generation`; the caller must
/// re-verify that generation immediately before applying it.
pub fn plan(
    allocator: std.mem.Allocator,
    source: database.Database,
    changes: []const Change,
    options: PlanOptions,
) std.mem.Allocator.Error!PlanResult {
    if (changes.len > options.limits.max_changes) {
        return .{ .diagnostic = .{
            .surface = .change_set,
            .code = .plan_limit,
            .path = database.database_directory,
        } };
    }
    if (source.model.pending_updates.len != 0) {
        return .{ .diagnostic = .{
            .surface = .updates,
            .code = .update_fragments_present,
            .path = database.updates_directory,
        } };
    }

    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = .init(allocator);
    var builder: Builder = .{
        .arena = arena.allocator(),
        .scratch = allocator,
        .options = options,
        .base = source.model,
        .foreign = source.model.foreign_architectures,
        .triggers = source.model.triggers,
    };
    defer builder.deinit();

    const built = build(&builder, source, changes) catch |err| {
        const diagnostic: Diagnostic = switch (err) {
            error.OutOfMemory => .{
                .surface = .change_set,
                .code = .out_of_memory,
                .path = database.database_directory,
            },
            error.Invalid => builder.diagnostic.?,
        };
        arena.deinit();
        allocator.destroy(arena);
        return .{ .diagnostic = diagnostic };
    };
    if (built.diagnostic) |diagnostic| {
        arena.deinit();
        allocator.destroy(arena);
        return .{ .diagnostic = diagnostic };
    }
    return .{ .plan = .{
        .base_generation = source.generation,
        .base_status = source.model.status,
        .resulting_status = built.resulting_status,
        .writes = built.writes,
        .digest = planDigest(source.generation, built.writes),
        .arena = arena,
        .backing_allocator = allocator,
    } };
}

const Built = struct {
    writes: []const PlannedWrite,
    resulting_status: database.StatusGeneration,
    diagnostic: ?Diagnostic = null,
};

fn build(
    builder: *Builder,
    source: database.Database,
    changes: []const Change,
) PlanError!Built {
    try builder.records.appendSlice(builder.scratch, source.model.packages);
    for (changes) |change| try builder.apply(change);

    const packages = try builder.arena.dupe(database.PackageRecord, builder.records.items);
    const status_bytes = try database.writeStatusDocument(builder.arena, packages);
    const model = try builder.resultingModel(status_bytes);
    if (try database.validateModel(builder.scratch, model, builder.options.database)) |diagnostic| {
        return .{
            .writes = &.{},
            .resulting_status = model.status,
            .diagnostic = diagnostic,
        };
    }
    return .{
        .writes = try builder.orderedWrites(status_bytes),
        .resulting_status = model.status,
    };
}

const testing = std.testing;

/// In-memory application of a plan, used to prove that a planned generation
/// imports cleanly. The mutation layer performs the durable equivalent.
const SimulatedRoot = struct {
    arena: std.heap.ArenaAllocator,
    status: []const u8,
    status_old: ?[]const u8 = null,
    arch: ?[]const u8 = null,
    triggers_file: ?[]const u8 = null,
    triggers_unincorp: ?[]const u8 = null,
    status_target: ?[]const u8 = null,
    info: std.ArrayList(database.InfoEntry) = .empty,

    fn init(allocator: std.mem.Allocator, source: database.Snapshot) !SimulatedRoot {
        var root: SimulatedRoot = .{
            .arena = .init(allocator),
            .status = source.status,
            .status_old = source.status_old,
            .arch = source.arch,
            .triggers_file = source.triggers_file,
            .triggers_unincorp = source.triggers_unincorp,
        };
        try root.info.appendSlice(root.arena.allocator(), source.info);
        return root;
    }

    fn deinit(self: *SimulatedRoot) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn find(self: *SimulatedRoot, name: []const u8) ?usize {
        for (self.info.items, 0..) |entry, index| {
            if (std.mem.eql(u8, entry.name, name)) return index;
        }
        return null;
    }

    fn apply(self: *SimulatedRoot, applied: Plan) !void {
        const allocator = self.arena.allocator();
        for (applied.writes) |write| {
            if (std.mem.startsWith(u8, write.path, database.info_directory ++ "/")) {
                const name = write.path[database.info_directory.len + 1 ..];
                const existing = self.find(name);
                switch (write.kind) {
                    .remove => {
                        if (existing) |index| _ = self.info.orderedRemove(index);
                    },
                    .replace => {
                        const entry: database.InfoEntry = .{
                            .name = try allocator.dupe(u8, name),
                            .bytes = try allocator.dupe(u8, write.bytes),
                            .mode = write.mode,
                        };
                        if (existing) |index| {
                            self.info.items[index] = entry;
                        } else {
                            try self.info.append(allocator, entry);
                        }
                    },
                    .copy => return error.TestUnexpectedResult,
                }
                continue;
            }
            if (std.mem.eql(u8, write.path, database.status_old_path)) {
                try testing.expectEqual(WriteKind.copy, write.kind);
                try testing.expectEqualStrings(database.status_path, write.source);
                self.status_old = try allocator.dupe(u8, self.status);
                continue;
            }
            const target: *?[]const u8 = if (std.mem.eql(u8, write.path, database.arch_path))
                &self.arch
            else if (std.mem.eql(u8, write.path, database.triggers_file_path))
                &self.triggers_file
            else if (std.mem.eql(u8, write.path, database.triggers_unincorp_path))
                &self.triggers_unincorp
            else if (std.mem.eql(u8, write.path, database.status_path)) &self.status_target else return error.TestUnexpectedResult;
            switch (write.kind) {
                .replace => target.* = try allocator.dupe(u8, write.bytes),
                .remove => target.* = null,
                .copy => return error.TestUnexpectedResult,
            }
            if (target == &self.status_target) self.status = self.status_target.?;
        }
    }

    fn snapshot(self: *SimulatedRoot) database.Snapshot {
        return .{
            .status = self.status,
            .status_old = self.status_old,
            .arch = self.arch,
            .triggers_file = self.triggers_file,
            .triggers_unincorp = self.triggers_unincorp,
            .info = self.info.items,
        };
    }
};

fn importFixture() !database.Database {
    const result = try database.importSnapshot(
        testing.allocator,
        database.test_fixtures.request(),
        .{},
    );
    return switch (result) {
        .diagnostic => error.TestUnexpectedResult,
        .database => |value| value,
    };
}

fn expectPlanDiagnostic(result: PlanResult, code: database.Code) !void {
    switch (result) {
        .plan => |value| {
            var owned = value;
            owned.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| try testing.expectEqual(code, diagnostic.code),
    }
}

const new_package_fields = [_]database.StatusField{
    .{ .name = "Package", .value_lines = &.{"newpkg"} },
    .{ .name = "Status", .value_lines = &.{"install ok unpacked"} },
    .{ .name = "Architecture", .value_lines = &.{"amd64"} },
    .{ .name = "Version", .value_lines = &.{"3.1"} },
    .{ .name = "Conffiles", .value_lines = &.{
        "",
        "/etc/newpkg.conf 5d41402abc4b2a76b9719d911017c592",
    } },
    .{ .name = "Description", .value_lines = &.{"new package"} },
};

const new_package_paths = [_][]const u8{
    "/.",
    "/etc",
    "/etc/newpkg.conf",
    "/usr",
    "/usr/bin",
    "/usr/bin/newpkg",
};

const new_package_md5sums = [_]database.Md5sumEntry{
    .{
        .path = "usr/bin/newpkg",
        .digest = .{
            0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
            0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61,
        },
    },
};

fn newPackage() StagedPackage {
    return .{
        .fields = &new_package_fields,
        .paths = &new_package_paths,
        .md5sums = &new_package_md5sums,
        .declared_conffiles = &.{"/etc/newpkg.conf"},
        .scripts = &.{.{ .kind = .postinst, .bytes = "#!/bin/sh\nexit 0\n" }},
    };
}

test "package_database_changes.test.staged install plans one deterministic generation" {
    var source = try importFixture();
    defer source.deinit();

    const result = try plan(testing.allocator, source, &.{.{ .put_package = newPackage() }}, .{});
    var staged = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer staged.deinit();

    try testing.expectEqualSlices(u8, &source.generation.sha256, &staged.base_generation.sha256);
    const expected = [_]struct { path: []const u8, kind: WriteKind }{
        .{ .path = "status-old", .kind = .copy },
        .{ .path = "info/newpkg.conffiles", .kind = .replace },
        .{ .path = "info/newpkg.list", .kind = .replace },
        .{ .path = "info/newpkg.md5sums", .kind = .replace },
        .{ .path = "info/newpkg.postinst", .kind = .replace },
        .{ .path = "status", .kind = .replace },
    };
    try testing.expectEqual(expected.len, staged.writes.len);
    for (expected, staged.writes) |want, write| {
        try testing.expectEqualStrings(want.path, write.path);
        try testing.expectEqual(want.kind, write.kind);
    }
    try testing.expectEqual(@as(u32, 0o755), staged.find("info/newpkg.postinst").?.mode);
    try testing.expectEqualStrings(
        "/.\n/etc\n/etc/newpkg.conf\n/usr\n/usr/bin\n/usr/bin/newpkg\n",
        staged.find("info/newpkg.list").?.bytes,
    );
    try testing.expectEqualSlices(
        u8,
        &source.model.status.sha256,
        &staged.writes[0].sha256,
    );

    var root = try SimulatedRoot.init(testing.allocator, database.test_fixtures.snapshot());
    defer root.deinit();
    try root.apply(staged);

    const published = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = root.snapshot() },
        .{},
    );
    var republished = switch (published) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer republished.deinit();

    try testing.expectEqual(@as(usize, 5), republished.model.packages.len);
    const record = republished.model.find("newpkg", "amd64").?;
    try testing.expectEqual(CurrentState.unpacked, record.status.current);
    try testing.expectEqual(@as(usize, 1), record.conffiles.len);
    try testing.expectEqual(@as(usize, 1), record.scripts.len);
    try testing.expectEqualSlices(
        u8,
        &staged.resulting_status.sha256,
        &republished.model.status.sha256,
    );
    var previous: [32]u8 = undefined;
    Sha256.hash(database.test_fixtures.status, &previous, .{});
    try testing.expectEqualSlices(u8, &previous, &republished.model.status_old.?.sha256);
}

test "package_database_changes.test.plan digests bind the base generation and intents" {
    var source = try importFixture();
    defer source.deinit();

    const first = try plan(testing.allocator, source, &.{.{ .put_package = newPackage() }}, .{});
    var first_plan = switch (first) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer first_plan.deinit();

    const second = try plan(testing.allocator, source, &.{.{ .put_package = newPackage() }}, .{});
    var second_plan = switch (second) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer second_plan.deinit();
    try testing.expectEqualSlices(u8, &first_plan.digest, &second_plan.digest);

    const third = try plan(testing.allocator, source, &.{.{ .set_state = .{
        .identity = .{ .name = "libfoo", .architecture = "amd64" },
        .want = .install,
        .error_state = .ok,
        .current = .half_configured,
    } }}, .{});
    var third_plan = switch (third) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer third_plan.deinit();
    try testing.expect(!std.mem.eql(u8, &first_plan.digest, &third_plan.digest));
}

test "package_database_changes.test.state changes republish only the status field" {
    var source = try importFixture();
    defer source.deinit();

    const result = try plan(testing.allocator, source, &.{
        .{ .set_state = .{
            .identity = .{ .name = "libfoo", .architecture = "amd64" },
            .want = .install,
            .error_state = .reinst_required,
            .current = .half_configured,
        } },
    }, .{});
    var staged = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer staged.deinit();
    try testing.expectEqual(@as(usize, 2), staged.writes.len);

    var root = try SimulatedRoot.init(testing.allocator, database.test_fixtures.snapshot());
    defer root.deinit();
    try root.apply(staged);
    const published = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = root.snapshot() },
        .{},
    );
    var republished = switch (published) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer republished.deinit();
    const record = republished.model.find("libfoo", "amd64").?;
    try testing.expectEqual(CurrentState.half_configured, record.status.current);
    try testing.expectEqual(database.ErrorState.reinst_required, record.status.error_state);
    try testing.expectEqualStrings(
        "retained unknown field",
        record.field("X-Vendor-Note").?.value_lines[0],
    );
}

test "package_database_changes.test.purge removes the record and every owned info file" {
    var source = try importFixture();
    defer source.deinit();

    const result = try plan(testing.allocator, source, &.{
        .{ .remove_package = .{ .name = "oldpkg", .architecture = "amd64" } },
    }, .{});
    var staged = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer staged.deinit();
    try testing.expect(staged.find("info/oldpkg.list").?.kind == .remove);
    try testing.expect(staged.find("info/oldpkg.conffiles").?.kind == .remove);

    var root = try SimulatedRoot.init(testing.allocator, database.test_fixtures.snapshot());
    defer root.deinit();
    try root.apply(staged);
    const published = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = root.snapshot() },
        .{},
    );
    var republished = switch (published) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer republished.deinit();
    try testing.expectEqual(@as(usize, 3), republished.model.packages.len);
    try testing.expect(republished.model.find("oldpkg", "amd64") == null);
    try testing.expect(root.find("oldpkg.list") == null);
}

test "package_database_changes.test.trigger and architecture state publish canonical files" {
    var source = try importFixture();
    defer source.deinit();

    const interests = [_]database.TriggerInterest{.{
        .trigger = "/usr/share/toolz",
        .package = .{ .name = "toolz", .architecture = "amd64" },
        .await_mode = .awaited,
    }};
    const result = try plan(testing.allocator, source, &.{
        .{ .set_trigger_state = .{ .interests = &interests, .pending = &.{} } },
        .{ .set_foreign_architectures = &.{ "i386", "arm64" } },
    }, .{});
    var staged = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer staged.deinit();

    try testing.expectEqualStrings("i386\narm64\n", staged.find("arch").?.bytes);
    try testing.expectEqualStrings(
        "/usr/share/toolz toolz:amd64\n",
        staged.find("triggers/File").?.bytes,
    );
    try testing.expectEqualStrings("", staged.find("triggers/Unincorp").?.bytes);

    var root = try SimulatedRoot.init(testing.allocator, database.test_fixtures.snapshot());
    defer root.deinit();
    try root.apply(staged);
    const published = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = root.snapshot() },
        .{},
    );
    var republished = switch (published) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer republished.deinit();
    try testing.expectEqual(@as(usize, 2), republished.model.foreign_architectures.len);
    try testing.expectEqual(@as(usize, 0), republished.model.triggers.pending.len);
}

test "package_database_changes.test.unsafe or ambiguous change sets fail before mutation" {
    var source = try importFixture();
    defer source.deinit();

    try expectPlanDiagnostic(try plan(testing.allocator, source, &.{
        .{ .put_package = newPackage() },
        .{ .put_package = newPackage() },
    }, .{}), .conflicting_change);

    try expectPlanDiagnostic(try plan(testing.allocator, source, &.{
        .{ .set_state = .{
            .identity = .{ .name = "ghost", .architecture = "amd64" },
            .want = .install,
            .error_state = .ok,
            .current = .installed,
        } },
    }, .{}), .unknown_package);

    try expectPlanDiagnostic(try plan(testing.allocator, source, &.{
        .{ .set_state = .{
            .identity = .{ .name = "oldpkg", .architecture = "amd64" },
            .want = .install,
            .error_state = .ok,
            .current = .installed,
        } },
    }, .{}), .invalid_transition);

    var unsafe_script = newPackage();
    unsafe_script.scripts = &.{.{
        .kind = .postinst,
        .bytes = "#!/bin/sh\nexit 0\n",
        .mode = 0o4755,
    }};
    try expectPlanDiagnostic(
        try plan(testing.allocator, source, &.{.{ .put_package = unsafe_script }}, .{}),
        .invalid_script,
    );

    var traversing = newPackage();
    traversing.paths = &.{"/usr/bin/../../etc/shadow"};
    try expectPlanDiagnostic(
        try plan(testing.allocator, source, &.{.{ .put_package = traversing }}, .{}),
        .invalid_path,
    );

    try expectPlanDiagnostic(try plan(testing.allocator, source, &.{
        .{ .put_md5sums = .{
            .identity = .{ .name = "toolz", .architecture = "amd64" },
            .entries = &.{.{ .path = "usr/bin/absent", .digest = @splat(0) }},
        } },
    }, .{}), .checksum_out_of_inventory);

    try expectPlanDiagnostic(try plan(testing.allocator, source, &.{
        .{ .remove_info = .{
            .identity = .{ .name = "toolz", .architecture = "amd64" },
            .kind = .list,
        } },
    }, .{}), .missing_file_list);

    try expectPlanDiagnostic(try plan(testing.allocator, source, &.{
        .{ .set_foreign_architectures = &.{ "i386", "i386" } },
    }, .{}), .duplicate_architecture);

    try expectPlanDiagnostic(
        try plan(
            testing.allocator,
            source,
            &.{.{ .put_package = newPackage() }},
            .{ .limits = .{ .max_changes = 0 } },
        ),
        .plan_limit,
    );
}

test "package_database_changes.test.interrupted or diverted state blocks planning" {
    var interrupted_snapshot = database.test_fixtures.snapshot();
    interrupted_snapshot.updates = &.{.{ .name = "0001", .bytes = database.test_fixtures.status }};
    const interrupted_result = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = interrupted_snapshot },
        .{ .updates_policy = .import_for_recovery },
    );
    var interrupted = switch (interrupted_result) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer interrupted.deinit();
    try expectPlanDiagnostic(
        try plan(testing.allocator, interrupted, &.{}, .{}),
        .update_fragments_present,
    );

    var diverted_snapshot = database.test_fixtures.snapshot();
    diverted_snapshot.diversions = "/usr/bin/toolz\n/usr/bin/toolz.real\nother\n";
    const diverted_result = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = diverted_snapshot },
        .{},
    );
    var diverted = switch (diverted_result) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer diverted.deinit();
    try expectPlanDiagnostic(try plan(testing.allocator, diverted, &.{
        .{ .remove_package = .{ .name = "toolz", .architecture = "amd64" } },
    }, .{}), .unsupported_diversion);
}

test "package_database_changes.test.transition table refuses impossible publications" {
    try testing.expect(transitionAllowed(.not_installed, .half_installed));
    try testing.expect(transitionAllowed(.half_installed, .unpacked));
    try testing.expect(transitionAllowed(.unpacked, .half_configured));
    try testing.expect(transitionAllowed(.half_configured, .installed));
    try testing.expect(transitionAllowed(.installed, .triggers_pending));
    try testing.expect(transitionAllowed(.triggers_awaited, .installed));
    try testing.expect(transitionAllowed(.installed, .config_files));
    try testing.expect(!transitionAllowed(.not_installed, .installed));
    try testing.expect(!transitionAllowed(.config_files, .installed));
    try testing.expect(!transitionAllowed(.half_installed, .installed));
    try testing.expect(!transitionAllowed(.installed, .not_installed));
}

test "package_database_changes.test.renaming info files of a package with retained files fails" {
    const allocator = testing.allocator;
    var entries = try allocator.alloc(database.InfoEntry, database.test_fixtures.info.len + 1);
    defer allocator.free(entries);
    @memcpy(entries[0..database.test_fixtures.info.len], database.test_fixtures.info);
    entries[database.test_fixtures.info.len] = .{
        .name = "toolz.templates",
        .bytes = "Template: toolz/question\nType: boolean\n",
    };
    var snapshot = database.test_fixtures.snapshot();
    snapshot.info = entries;

    const result = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{},
    );
    var source = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer source.deinit();
    try testing.expectEqual(@as(usize, 1), source.model.opaque_info.len);

    // `toolz` is published unqualified; declaring `Multi-Arch: same` would move
    // every info file to `toolz:amd64`, orphaning the retained templates file.
    const renamed = [_]database.StatusField{
        .{ .name = "Package", .value_lines = &.{"toolz"} },
        .{ .name = "Status", .value_lines = &.{"install ok unpacked"} },
        .{ .name = "Architecture", .value_lines = &.{"amd64"} },
        .{ .name = "Multi-Arch", .value_lines = &.{"same"} },
        .{ .name = "Version", .value_lines = &.{"2.0"} },
        .{ .name = "Description", .value_lines = &.{"example tool"} },
    };
    try expectPlanDiagnostic(try plan(testing.allocator, source, &.{
        .{ .put_package = .{
            .fields = &renamed,
            .paths = &.{ "/.", "/usr", "/usr/bin", "/usr/bin/toolz" },
        } },
    }, .{}), .unsupported_info_rename);

    const kept = try plan(testing.allocator, source, &.{
        .{ .put_package = .{
            .fields = &.{
                .{ .name = "Package", .value_lines = &.{"toolz"} },
                .{ .name = "Status", .value_lines = &.{"install ok unpacked"} },
                .{ .name = "Architecture", .value_lines = &.{"amd64"} },
                .{ .name = "Version", .value_lines = &.{"2.1"} },
                .{ .name = "Description", .value_lines = &.{"example tool"} },
            },
            .paths = &.{ "/.", "/usr", "/usr/bin", "/usr/bin/toolz" },
        } },
        // Dropping the trigger declarations also retires the file-trigger
        // interest that referenced them.
        .{ .set_trigger_state = .{} },
    }, .{});
    var staged = switch (kept) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer staged.deinit();
    try testing.expect(staged.find("info/toolz.templates") == null);
    try testing.expect(staged.find("info/toolz.md5sums").?.kind == .remove);
    try testing.expect(staged.find("info/toolz.triggers").?.kind == .remove);
    try testing.expect(staged.find("info/toolz.postinst").?.kind == .remove);

    var root = try SimulatedRoot.init(testing.allocator, snapshot);
    defer root.deinit();
    try root.apply(staged);
    const published = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = root.snapshot() },
        .{},
    );
    var republished = switch (published) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer republished.deinit();
    try testing.expectEqual(@as(usize, 1), republished.model.opaque_info.len);
    try testing.expectEqualStrings("2.1", republished.model.find("toolz", "amd64").?.version);
}

test "package_database_changes.test.purge removes retained unmodeled info files" {
    const allocator = testing.allocator;
    var entries = try allocator.alloc(database.InfoEntry, database.test_fixtures.info.len + 1);
    defer allocator.free(entries);
    @memcpy(entries[0..database.test_fixtures.info.len], database.test_fixtures.info);
    entries[database.test_fixtures.info.len] = .{
        .name = "oldpkg.templates",
        .bytes = "Template: oldpkg/question\nType: boolean\n",
    };
    var snapshot = database.test_fixtures.snapshot();
    snapshot.info = entries;

    const result = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{},
    );
    var source = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer source.deinit();

    const purged = try plan(testing.allocator, source, &.{
        .{ .remove_package = .{ .name = "oldpkg", .architecture = "amd64" } },
    }, .{});
    var staged = switch (purged) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer staged.deinit();
    try testing.expect(staged.find("info/oldpkg.templates").?.kind == .remove);

    var root = try SimulatedRoot.init(testing.allocator, snapshot);
    defer root.deinit();
    try root.apply(staged);
    const published = try database.importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = root.snapshot() },
        .{},
    );
    var republished = switch (published) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer republished.deinit();
    try testing.expectEqual(@as(usize, 0), republished.model.opaque_info.len);
}

const libsolv = @cImport({
    @cInclude("solv/evr.h");
    @cInclude("solv/pool.h");
    @cInclude("solv/solver.h");
});

pub const Context = opaque {
    pub fn create() *Context {
        const pool = libsolv.pool_create() orelse unreachable;
        const solver = libsolv.solver_create(pool) orelse unreachable;
        return @ptrCast(solver);
    }

    pub fn destroy(self: *Context) void {
        const solver: *libsolv.Solver = @ptrCast(@alignCast(self));
        const pool = solver.pool;
        libsolv.solver_free(solver);
        libsolv.pool_free(pool);
    }
};

test "context pool uses Debian version semantics" {
    const context = Context.create();
    defer context.destroy();

    const solver: *libsolv.Solver = @ptrCast(@alignCast(context));
    const pool = solver.pool;

    try @import("std").testing.expectEqual(@as(c_int, libsolv.DISTTYPE_DEB), pool.*.disttype);
    try @import("std").testing.expect(
        libsolv.pool_evrcmp_str(pool, "1+1", "1.1", libsolv.EVRCMP_COMPARE) < 0,
    );
}

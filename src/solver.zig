const libsolv = @cImport({
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

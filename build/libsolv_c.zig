pub const Offset = c_uint;
pub const Id = c_int;
pub const Hashtable = [*c]Id;
pub const Hashval = c_uint;
pub const struct_s_Stringpool = extern struct {
    strings: [*c]Offset = null,
    nstrings: c_int = 0,
    stringspace: [*c]u8 = null,
    sstrings: Offset = 0,
    stringhashtbl: Hashtable = null,
    stringhashmask: Hashval = 0,
};
pub const Stringpool = struct_s_Stringpool;
pub const struct_s_Reldep = extern struct {
    name: Id = 0,
    evr: Id = 0,
    flags: c_int = 0,
};
pub const Reldep = struct_s_Reldep;
pub const Pool = struct_s_Pool;
pub const struct_s_Repokey = extern struct {
    name: Id = 0,
    type: Id = 0,
    size: c_uint = 0,
    storage: c_uint = 0,
};
pub const Repokey = struct_s_Repokey;
pub const struct_s_Dirpool = extern struct {
    dirs: [*c]Id = null,
    ndirs: c_int = 0,
    dirtraverse: [*c]Id = null,
    dirhashtbl: Hashtable = null,
    dirhashmask: Hashval = 0,
};
pub const Dirpool = struct_s_Dirpool;
pub const struct__IO_FILE = opaque {};
pub const FILE = struct__IO_FILE;
pub const struct_s_Attrblobpage = extern struct {
    page_offset: c_uint = 0,
    page_size: c_uint = 0,
};
pub const Attrblobpage = struct_s_Attrblobpage;
pub const struct_s_Repopagestore = extern struct {
    pagefd: c_int = 0,
    file_offset: c_long = 0,
    blob_store: [*c]u8 = null,
    num_pages: c_uint = 0,
    mapped_at: [*c]c_uint = null,
    file_pages: [*c]Attrblobpage = null,
    mapped: [*c]c_uint = null,
    nmapped: c_uint = 0,
    rr_counter: c_uint = 0,
};
pub const Repopagestore = struct_s_Repopagestore;
pub const struct_dircache = opaque {};
pub const struct_s_Repodata = extern struct {
    repodataid: Id = 0,
    repo: [*c]Repo = null,
    state: c_int = 0,
    loadcallback: ?*const fn ([*c]Repodata) callconv(.c) void = null,
    start: c_int = 0,
    end: c_int = 0,
    keys: [*c]Repokey = null,
    nkeys: c_int = 0,
    keybits: [16 + 16]u8 = @import("std").mem.zeroes([16 + 16]u8),
    schemata: [*c]Id = null,
    nschemata: c_int = 0,
    schemadata: [*c]Id = null,
    spool: Stringpool = @import("std").mem.zeroes(Stringpool),
    localpool: c_int = 0,
    dirpool: Dirpool = @import("std").mem.zeroes(Dirpool),
    fp: ?*FILE = null,
    @"error": c_int = 0,
    filelisttype: c_int = 0,
    filelistfilter: [*c]Id = null,
    filelistfilterdata: [*c]u8 = null,
    schemadatalen: c_uint = 0,
    schematahash: [*c]Id = null,
    incoredata: [*c]u8 = null,
    incoredatalen: c_uint = 0,
    incoredatafree: c_uint = 0,
    mainschema: Id = 0,
    mainschemaoffsets: [*c]Id = null,
    incoreoffset: [*c]Id = null,
    verticaloffset: [*c]Id = null,
    lastverticaloffset: Id = 0,
    store: Repopagestore = @import("std").mem.zeroes(Repopagestore),
    storestate: Id = 0,
    vincore: [*c]u8 = null,
    vincorelen: c_uint = 0,
    attrs: [*c][*c]Id = null,
    xattrs: [*c][*c]Id = null,
    nxattrs: c_int = 0,
    attrdata: [*c]u8 = null,
    attrdatalen: c_uint = 0,
    attriddata: [*c]Id = null,
    attriddatalen: c_uint = 0,
    attrnum64data: [*c]c_ulonglong = null,
    attrnum64datalen: c_uint = 0,
    lasthandle: Id = 0,
    lastkey: Id = 0,
    lastdatalen: Id = 0,
    dircache: ?*struct_dircache = null,
};
pub const Repodata = struct_s_Repodata;
pub const struct_s_Repo = extern struct {
    name: [*c]const u8 = null,
    repoid: Id = 0,
    appdata: ?*anyopaque = null,
    pool: [*c]Pool = null,
    start: c_int = 0,
    end: c_int = 0,
    nsolvables: c_int = 0,
    disabled: c_int = 0,
    priority: c_int = 0,
    subpriority: c_int = 0,
    idarraydata: [*c]Id = null,
    idarraysize: c_int = 0,
    nrepodata: c_int = 0,
    rpmdbid: [*c]Id = null,
    repodata: [*c]Repodata = null,
    lastoff: Offset = 0,
    lastidhash: Hashtable = null,
    lastidhash_mask: Hashval = 0,
    lastidhash_idarraysize: c_int = 0,
    lastmarker: c_int = 0,
    lastmarkerpos: Offset = 0,
};
pub const Repo = struct_s_Repo;
pub const struct_s_Solvable = extern struct {
    name: Id = 0,
    arch: Id = 0,
    evr: Id = 0,
    vendor: Id = 0,
    repo: [*c]struct_s_Repo = null,
    provides: Offset = 0,
    obsoletes: Offset = 0,
    conflicts: Offset = 0,
    requires: Offset = 0,
    recommends: Offset = 0,
    suggests: Offset = 0,
    supplements: Offset = 0,
    enhances: Offset = 0,
};
pub const Solvable = struct_s_Solvable;
pub const struct_s_Queue = extern struct {
    elements: [*c]Id = null,
    count: c_int = 0,
    alloc: [*c]Id = null,
    left: c_int = 0,
};
pub const Queue = struct_s_Queue;
pub const struct_s_Map = extern struct {
    map: [*c]u8 = null,
    size: c_int = 0,
};
pub const Map = struct_s_Map;
pub const struct_s_Datapos = extern struct {
    repo: [*c]Repo = null,
    solvid: Id = 0,
    repodataid: Id = 0,
    schema: Id = 0,
    dp: Id = 0,
};
pub const Datapos = struct_s_Datapos;
pub const struct_s_Pool_tmpspace = extern struct {
    buf: [16][*c]u8 = @import("std").mem.zeroes([16][*c]u8),
    len: [16]c_int = @import("std").mem.zeroes([16]c_int),
    n: c_int = 0,
};
pub const struct_s_Pool = extern struct {
    appdata: ?*anyopaque = null,
    ss: Stringpool = @import("std").mem.zeroes(Stringpool),
    rels: [*c]Reldep = null,
    nrels: c_int = 0,
    repos: [*c][*c]Repo = null,
    nrepos: c_int = 0,
    urepos: c_int = 0,
    installed: [*c]Repo = null,
    solvables: [*c]Solvable = null,
    nsolvables: c_int = 0,
    languages: [*c][*c]const u8 = null,
    nlanguages: c_int = 0,
    disttype: c_int = 0,
    id2arch: [*c]Id = null,
    id2color: [*c]u8 = null,
    lastarch: Id = 0,
    vendormap: Queue = @import("std").mem.zeroes(Queue),
    vendorclasses: [*c][*c]const u8 = null,
    whatprovides: [*c]Offset = null,
    whatprovides_rel: [*c]Offset = null,
    whatprovidesdata: [*c]Id = null,
    whatprovidesdataoff: Offset = 0,
    whatprovidesdataleft: c_int = 0,
    considered: [*c]Map = null,
    nscallback: ?*const fn ([*c]Pool, data: ?*anyopaque, name: Id, evr: Id) callconv(.c) Id = null,
    nscallbackdata: ?*anyopaque = null,
    debugmask: c_int = 0,
    debugcallback: ?*const fn ([*c]Pool, data: ?*anyopaque, @"type": c_int, str: [*c]const u8) callconv(.c) void = null,
    debugcallbackdata: ?*anyopaque = null,
    loadcallback: ?*const fn ([*c]Pool, [*c]Repodata, ?*anyopaque) callconv(.c) c_int = null,
    loadcallbackdata: ?*anyopaque = null,
    pos: Datapos = @import("std").mem.zeroes(Datapos),
    pooljobs: Queue = @import("std").mem.zeroes(Queue),
    promoteepoch: c_int = 0,
    havedistepoch: c_int = 0,
    obsoleteusesprovides: c_int = 0,
    implicitobsoleteusesprovides: c_int = 0,
    obsoleteusescolors: c_int = 0,
    implicitobsoleteusescolors: c_int = 0,
    noinstalledobsoletes: c_int = 0,
    forbidselfconflicts: c_int = 0,
    noobsoletesmultiversion: c_int = 0,
    noarchid: Id = 0,
    relhashtbl: Hashtable = null,
    relhashmask: Hashval = 0,
    languagecache: [*c]Id = null,
    tmpspace: struct_s_Pool_tmpspace = @import("std").mem.zeroes(struct_s_Pool_tmpspace),
    errstr: [*c]u8 = null,
    errstra: c_int = 0,
    rootdir: [*c]u8 = null,
    custom_vendorcheck: ?*const fn ([*c]Pool, [*c]Solvable, [*c]Solvable) callconv(.c) c_int = null,
    addfileprovidesfiltered: c_int = 0,
    addedfileprovides: c_int = 0,
    lazywhatprovidesq: Queue = @import("std").mem.zeroes(Queue),
    nowhatprovidesaux: c_int = 0,
    whatprovidesaux: [*c]Offset = null,
    whatprovidesauxoff: Offset = 0,
    whatprovidesauxdata: [*c]Id = null,
    whatprovidesauxdataoff: Offset = 0,
    nonstd_ids: [*c]Id = null,
    nonstd_nids: c_int = 0,
    whatprovideswithdisabled: c_int = 0,
};
pub extern fn pool_evrcmp_str(pool: [*c]const Pool, evr1: [*c]const u8, evr2: [*c]const u8, mode: c_int) c_int;
pub extern fn pool_evrcmp(pool: [*c]const Pool, evr1id: Id, evr2id: Id, mode: c_int) c_int;
pub extern fn pool_strn2id(pool: [*c]Pool, [*c]const u8, c_uint, c_int) Id;
pub extern fn pool_rel2id(pool: [*c]Pool, Id, Id, c_int, c_int) Id;
pub extern fn pool_dep2str(pool: [*c]Pool, Id) [*c]const u8;
pub extern fn queue_alloc_one(q: [*c]Queue) void;
pub fn queue_push(arg_q: [*c]Queue, arg_id: Id) callconv(.c) void {
    var q = arg_q;
    _ = &q;
    var id = arg_id;
    _ = &id;
    if (!(q.*.left != 0)) {
        queue_alloc_one(q);
    }
    q.*.elements[
        @bitCast(@as(isize, @intCast(blk: {
            const ref = &q.*.count;
            const tmp = ref.*;
            ref.* += 1;
            break :blk tmp;
        })))
    ] = id;
    q.*.left -= 1;
}
pub fn queue_push2(arg_q: [*c]Queue, arg_id1: Id, arg_id2: Id) callconv(.c) void {
    var q = arg_q;
    _ = &q;
    var id1 = arg_id1;
    _ = &id1;
    var id2 = arg_id2;
    _ = &id2;
    queue_push(q, id1);
    queue_push(q, id2);
}
pub extern fn queue_init(q: [*c]Queue) void;
pub extern fn queue_free(q: [*c]Queue) void;
pub extern fn solvable_lookup_str(s: [*c]Solvable, keyname: Id) [*c]const u8;
pub extern fn solvable_add_deparray(s: [*c]Solvable, keyname: Id, dep: Id, marker: Id) void;
pub const SOLVABLE_PROVIDES: c_int = 6;
pub const SOLVABLE_OBSOLETES: c_int = 7;
pub const SOLVABLE_CONFLICTS: c_int = 8;
pub const SOLVABLE_REQUIRES: c_int = 9;
pub const SOLVABLE_RECOMMENDS: c_int = 10;
pub const SOLVABLE_PREREQMARKER: c_int = 15;
pub const ARCH_ANY: c_int = 28;
pub const SOLVABLE_MULTIARCH: c_int = 202;
pub extern fn pool_create() [*c]Pool;
pub extern fn pool_free(pool: [*c]Pool) void;
pub extern fn pool_set_installed(pool: [*c]Pool, repo: [*c]Repo) void;
pub fn pool_id2solvable(arg_pool: [*c]const Pool, arg_p: Id) callconv(.c) [*c]Solvable {
    var pool = arg_pool;
    _ = &pool;
    var p = arg_p;
    _ = &p;
    return pool.*.solvables + @as(usize, @bitCast(@as(isize, @intCast(p))));
}
pub extern fn pool_solvable2str(pool: [*c]Pool, s: [*c]Solvable) [*c]const u8;
pub fn pool_solvid2str(arg_pool: [*c]Pool, arg_p: Id) callconv(.c) [*c]const u8 {
    var pool = arg_pool;
    _ = &pool;
    var p = arg_p;
    _ = &p;
    return pool_solvable2str(pool, pool.*.solvables + @as(usize, @bitCast(@as(isize, @intCast(p)))));
}
pub extern fn pool_createwhatprovides(pool: [*c]Pool) void;
pub extern fn pool_addrelproviders(pool: [*c]Pool, d: Id) Id;
pub fn pool_whatprovides(arg_pool: [*c]Pool, arg_d: Id) callconv(.c) Id {
    var pool = arg_pool;
    _ = &pool;
    var d = arg_d;
    _ = &d;
    if (!((@as(c_uint, @bitCast(@as(c_int, d))) & @as(c_uint, 2147483648)) != @as(c_uint, 0))) {
        if (pool.*.whatprovides[@bitCast(@as(isize, @intCast(d)))] != 0) return @bitCast(@as(c_uint, @truncate(pool.*.whatprovides[@bitCast(@as(isize, @intCast(d)))])));
    } else {
        var v: Id = @bitCast(@as(c_uint, @truncate(@as(c_uint, @bitCast(@as(c_int, d))) ^ @as(c_uint, 2147483648))));
        _ = &v;
        if (pool.*.whatprovides_rel[@bitCast(@as(isize, @intCast(v)))] != 0) return @bitCast(@as(c_uint, @truncate(pool.*.whatprovides_rel[@bitCast(@as(isize, @intCast(v)))])));
    }
    return pool_addrelproviders(pool, d);
}
pub fn pool_whatprovides_ptr(arg_pool: [*c]Pool, arg_d: Id) callconv(.c) [*c]Id {
    var pool = arg_pool;
    _ = &pool;
    var d = arg_d;
    _ = &d;
    var off: Id = pool_whatprovides(pool, d);
    _ = &off;
    return pool.*.whatprovidesdata + @as(usize, @bitCast(@as(isize, @intCast(off))));
}
pub extern fn pool_setarch([*c]Pool, [*c]const u8) void;
pub extern fn pool_setarchpolicy([*c]Pool, [*c]const u8) void;
pub const struct_s_Rule = extern struct {
    p: Id = 0,
    d: Id = 0,
    w1: Id = 0,
    w2: Id = 0,
    n1: Id = 0,
    n2: Id = 0,
};
pub const Rule = struct_s_Rule;
pub const SOLVER_RULE_PKG_NOTHING_PROVIDES_DEP: c_int = 258;
pub const SOLVER_RULE_PKG_REQUIRES: c_int = 259;
pub const SOLVER_RULE_PKG_SELF_CONFLICT: c_int = 260;
pub const SOLVER_RULE_PKG_CONFLICTS: c_int = 261;
pub const SOLVER_RULE_PKG_OBSOLETES: c_int = 263;
pub const SOLVER_RULE_JOB_NOTHING_PROVIDES_DEP: c_int = 1025;
pub const SOLVER_RULE_JOB_UNKNOWN_PACKAGE: c_int = 1027;
pub const SOLVER_RULE_INFARCH: c_int = 1536;
pub const SolverRuleinfo = c_uint;
pub const struct_s_Solver = extern struct {
    pool: [*c]Pool = null,
    job: Queue = @import("std").mem.zeroes(Queue),
    solution_callback: ?*const fn (solv: [*c]struct_s_Solver, data: ?*anyopaque) callconv(.c) c_int = null,
    solution_callback_data: ?*anyopaque = null,
    pooljobcnt: c_int = 0,
    installed: [*c]Repo = null,
    rules: [*c]Rule = null,
    nrules: Id = 0,
    lastpkgrule: Id = 0,
    ruleassertions: Queue = @import("std").mem.zeroes(Queue),
    pkgrules_end: Id = 0,
    featurerules: Id = 0,
    featurerules_end: Id = 0,
    updaterules: Id = 0,
    updaterules_end: Id = 0,
    jobrules: Id = 0,
    jobrules_end: Id = 0,
    infarchrules: Id = 0,
    infarchrules_end: Id = 0,
    duprules: Id = 0,
    duprules_end: Id = 0,
    bestrules: Id = 0,
    bestrules_up: Id = 0,
    bestrules_end: Id = 0,
    bestrules_info: [*c]Id = null,
    yumobsrules: Id = 0,
    yumobsrules_end: Id = 0,
    yumobsrules_info: [*c]Id = null,
    blackrules: Id = 0,
    blackrules_end: Id = 0,
    strictrepopriorules: Id = 0,
    strictrepopriorules_end: Id = 0,
    choicerules: Id = 0,
    choicerules_end: Id = 0,
    choicerules_info: [*c]Id = null,
    recommendsrules: Id = 0,
    recommendsrules_end: Id = 0,
    recommendsrules_info: [*c]Id = null,
    learntrules: Id = 0,
    noupdate: Map = @import("std").mem.zeroes(Map),
    multiversion: Map = @import("std").mem.zeroes(Map),
    updatemap: Map = @import("std").mem.zeroes(Map),
    updatemap_all: c_int = 0,
    bestupdatemap: Map = @import("std").mem.zeroes(Map),
    bestupdatemap_all: c_int = 0,
    fixmap: Map = @import("std").mem.zeroes(Map),
    fixmap_all: c_int = 0,
    weakruleq: Queue = @import("std").mem.zeroes(Queue),
    weakrulemap: Map = @import("std").mem.zeroes(Map),
    watches: [*c]Id = null,
    ruletojob: Queue = @import("std").mem.zeroes(Queue),
    decisionq: Queue = @import("std").mem.zeroes(Queue),
    decisionq_why: Queue = @import("std").mem.zeroes(Queue),
    decisionq_reason: Queue = @import("std").mem.zeroes(Queue),
    decisionmap: [*c]Id = null,
    learnt_why: Queue = @import("std").mem.zeroes(Queue),
    learnt_pool: Queue = @import("std").mem.zeroes(Queue),
    branches: Queue = @import("std").mem.zeroes(Queue),
    propagate_index: c_int = 0,
    problems: Queue = @import("std").mem.zeroes(Queue),
    solutions: Queue = @import("std").mem.zeroes(Queue),
    orphaned: Queue = @import("std").mem.zeroes(Queue),
    stats_learned: c_int = 0,
    stats_unsolvable: c_int = 0,
    recommendsmap: Map = @import("std").mem.zeroes(Map),
    suggestsmap: Map = @import("std").mem.zeroes(Map),
    recommends_index: c_int = 0,
    recommendscplxq: [*c]Queue = null,
    suggestscplxq: [*c]Queue = null,
    obsoletes: [*c]Id = null,
    obsoletes_data: [*c]Id = null,
    specialupdaters: [*c]Id = null,
    allowdowngrade: c_int = 0,
    allownamechange: c_int = 0,
    allowarchchange: c_int = 0,
    allowvendorchange: c_int = 0,
    allowuninstall: c_int = 0,
    noupdateprovide: c_int = 0,
    needupdateprovide: c_int = 0,
    dosplitprovides: c_int = 0,
    dontinstallrecommended: c_int = 0,
    addalreadyrecommended: c_int = 0,
    dontshowinstalledrecommended: c_int = 0,
    noinfarchcheck: c_int = 0,
    keepexplicitobsoletes: c_int = 0,
    bestobeypolicy: c_int = 0,
    noautotarget: c_int = 0,
    focus_installed: c_int = 0,
    focus_best: c_int = 0,
    focus_new: c_int = 0,
    do_yum_obsoletes: c_int = 0,
    urpmreorder: c_int = 0,
    strongrecommends: c_int = 0,
    install_also_updates: c_int = 0,
    only_namespace_recommended: c_int = 0,
    strict_repo_priority: c_int = 0,
    process_orphans: c_int = 0,
    dupmap: Map = @import("std").mem.zeroes(Map),
    dupinvolvedmap: Map = @import("std").mem.zeroes(Map),
    dupinvolvedmap_all: c_int = 0,
    dup_allowdowngrade: c_int = 0,
    dup_allownamechange: c_int = 0,
    dup_allowarchchange: c_int = 0,
    dup_allowvendorchange: c_int = 0,
    droporphanedmap: Map = @import("std").mem.zeroes(Map),
    droporphanedmap_all: c_int = 0,
    cleandepsmap: Map = @import("std").mem.zeroes(Map),
    ruleinfoq: [*c]Queue = null,
    cleandeps_updatepkgs: [*c]Queue = null,
    cleandeps_mistakes: [*c]Queue = null,
    update_targets: [*c]Queue = null,
    installsuppdepq: [*c]Queue = null,
    addedmap_deduceq: Queue = @import("std").mem.zeroes(Queue),
    instbuddy: [*c]Id = null,
    keep_orphans: c_int = 0,
    break_orphans: c_int = 0,
    brokenorphanrules: [*c]Queue = null,
    allowuninstallmap: Map = @import("std").mem.zeroes(Map),
    allowuninstall_all: c_int = 0,
    excludefromweakmap: Map = @import("std").mem.zeroes(Map),
    favormap: [*c]Id = null,
    havedisfavored: c_int = 0,
    installedpos: c_int = 0,
    do_extra_reordering: c_int = 0,
    recommendsruleq: [*c]Queue = null,
};
pub extern fn solver_ruleinfo(solv: [*c]struct_s_Solver, rid: Id, fromp: [*c]Id, top: [*c]Id, depp: [*c]Id) SolverRuleinfo;
pub extern fn solver_problem_count(solv: [*c]struct_s_Solver) c_uint;
pub extern fn solver_next_problem(solv: [*c]struct_s_Solver, problem: Id) Id;
pub extern fn solver_findproblemrule(solv: [*c]struct_s_Solver, problem: Id) Id;
pub extern fn solver_problemruleinfo2str(solv: [*c]struct_s_Solver, @"type": SolverRuleinfo, source: Id, target: Id, dep: Id) [*c]const u8;
pub extern fn repo_create(pool: [*c]Pool, name: [*c]const u8) [*c]Repo;
pub extern fn repo_free(repo: [*c]Repo, reuseids: c_int) void;
pub extern fn repo_add_solvable(repo: [*c]Repo) Id;
pub extern fn repo_addid_dep(repo: [*c]Repo, olddeps: Offset, id: Id, marker: Id) Offset;
pub extern fn repo_set_str(repo: [*c]Repo, p: Id, keyname: Id, str: [*c]const u8) void;
pub extern fn repo_internalize(repo: [*c]Repo) void;
pub const struct_s_TransactionOrderdata = opaque {};
pub const struct_s_Transaction = extern struct {
    pool: [*c]Pool = null,
    steps: Queue = @import("std").mem.zeroes(Queue),
    transaction_info: Queue = @import("std").mem.zeroes(Queue),
    transaction_installed: [*c]Id = null,
    transactsmap: Map = @import("std").mem.zeroes(Map),
    multiversionmap: Map = @import("std").mem.zeroes(Map),
    orderdata: ?*struct_s_TransactionOrderdata = null,
};
pub const Transaction = struct_s_Transaction;
pub extern fn transaction_free(trans: [*c]Transaction) void;
pub extern fn transaction_type(trans: [*c]Transaction, p: Id, mode: c_int) Id;
pub extern fn transaction_order(trans: [*c]Transaction, flags: c_int) void;
pub const Solver = struct_s_Solver;
pub extern fn solver_create(pool: [*c]Pool) [*c]Solver;
pub extern fn solver_free(solv: [*c]Solver) void;
pub extern fn solver_solve(solv: [*c]Solver, job: [*c]Queue) c_int;
pub extern fn solver_create_transaction(solv: [*c]Solver) [*c]Transaction;
pub extern fn solver_set_flag(solv: [*c]Solver, flag: c_int, value: c_int) c_int;
pub extern fn solver_get_decisionlevel(solv: [*c]Solver, p: Id) c_int;
pub extern fn solver_describe_decision(solv: [*c]Solver, p: Id, infop: [*c]Id) c_int;
pub const EVRCMP_COMPARE: c_int = 0;
pub const DISTTYPE_DEB: c_int = 1;
pub const REL_GT: c_int = 1;
pub const REL_EQ: c_int = 2;
pub const REL_LT: c_int = 4;
pub const REL_AND: c_int = 16;
pub const REL_OR: c_int = 17;
pub const REL_MULTIARCH: c_int = 25;
pub const SOLVER_TRANSACTION_IGNORE: c_int = 0x00;
pub const SOLVER_TRANSACTION_ERASE: c_int = 0x10;
pub const SOLVER_TRANSACTION_REINSTALLED: c_int = 0x11;
pub const SOLVER_TRANSACTION_DOWNGRADED: c_int = 0x12;
pub const SOLVER_TRANSACTION_UPGRADED: c_int = 0x14;
pub const SOLVER_TRANSACTION_OBSOLETED: c_int = 0x15;
pub const SOLVER_TRANSACTION_REINSTALL: c_int = 0x21;
pub const SOLVER_TRANSACTION_DOWNGRADE: c_int = 0x22;
pub const SOLVER_TRANSACTION_UPGRADE: c_int = 0x24;
pub const SOLVER_TRANSACTION_SHOW_ACTIVE: c_int = 1 << 0;
pub const SOLVER_SOLVABLE: c_int = 0x01;
pub const SOLVER_SOLVABLE_NAME: c_int = 0x02;
pub const SOLVER_SELECTMASK: c_int = 0xff;
pub const SOLVER_INSTALL: c_int = 0x0100;
pub const SOLVER_ERASE: c_int = 0x0200;
pub const SOLVER_MULTIVERSION: c_int = 0x0500;
pub const SOLVER_LOCK: c_int = 0x0600;
pub const SOLVER_JOBMASK: c_int = 0xff00;
pub const SOLVER_ESSENTIAL: c_int = 0x020000;
pub const SOLVER_FORCEBEST: c_int = 0x100000;
pub const SOLVER_REASON_WEAKDEP: c_int = 7;
pub const SOLVER_FLAG_ALLOW_DOWNGRADE: c_int = 1;
pub const SOLVER_FLAG_ALLOW_UNINSTALL: c_int = 4;
pub const SOLVER_FLAG_IGNORE_RECOMMENDED: c_int = 7;
pub const SOLVER_FLAG_DUP_ALLOW_DOWNGRADE: c_int = 14;
pub const SOLVER_FLAG_FOCUS_BEST: c_int = 24;
pub const SOLVER_FLAG_STRONG_RECOMMENDS: c_int = 25;
pub const SOLVER_FLAG_STRICT_REPO_PRIORITY: c_int = 28;
pub const dircache = struct_dircache;

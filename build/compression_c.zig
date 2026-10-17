pub const lzma_reserved_enum = c_uint;
pub const LZMA_OK: c_int = 0;
pub const LZMA_STREAM_END: c_int = 1;
pub const LZMA_UNSUPPORTED_CHECK: c_int = 3;
pub const LZMA_MEM_ERROR: c_int = 5;
pub const LZMA_MEMLIMIT_ERROR: c_int = 6;
pub const LZMA_FORMAT_ERROR: c_int = 7;
pub const LZMA_OPTIONS_ERROR: c_int = 8;
pub const LZMA_DATA_ERROR: c_int = 9;
pub const LZMA_BUF_ERROR: c_int = 10;
pub const lzma_ret = c_uint;
pub const LZMA_FINISH: c_int = 3;
pub const lzma_action = c_uint;
pub const lzma_allocator = extern struct {
    alloc: ?*const fn (@"opaque": ?*anyopaque, nmemb: usize, size: usize) callconv(.c) ?*anyopaque = null,
    free: ?*const fn (@"opaque": ?*anyopaque, ptr: ?*anyopaque) callconv(.c) void = null,
    @"opaque": ?*anyopaque = null,
};
pub const struct_lzma_internal_s = opaque {};
pub const lzma_internal = struct_lzma_internal_s;
pub const lzma_stream = extern struct {
    next_in: [*c]const u8 = null,
    avail_in: usize = 0,
    total_in: u64 = 0,
    next_out: [*c]u8 = null,
    avail_out: usize = 0,
    total_out: u64 = 0,
    allocator: [*c]const lzma_allocator = null,
    internal: ?*lzma_internal = null,
    reserved_ptr1: ?*anyopaque = null,
    reserved_ptr2: ?*anyopaque = null,
    reserved_ptr3: ?*anyopaque = null,
    reserved_ptr4: ?*anyopaque = null,
    seek_pos: u64 = 0,
    reserved_int2: u64 = 0,
    reserved_int3: usize = 0,
    reserved_int4: usize = 0,
    reserved_enum1: lzma_reserved_enum = @import("std").mem.zeroes(lzma_reserved_enum),
    reserved_enum2: lzma_reserved_enum = @import("std").mem.zeroes(lzma_reserved_enum),
};
pub extern fn lzma_code(strm: [*c]lzma_stream, action: lzma_action) lzma_ret;
pub extern fn lzma_end(strm: [*c]lzma_stream) void;
pub const LZMA_CHECK_CRC64: c_int = 4;
pub const lzma_check = c_uint;
pub extern fn lzma_easy_encoder_memusage(preset: u32) u64;
pub extern fn lzma_easy_encoder(strm: [*c]lzma_stream, preset: u32, check: lzma_check) lzma_ret;
pub extern fn lzma_stream_decoder(strm: [*c]lzma_stream, memlimit: u64, flags: u32) lzma_ret;
pub extern fn ZSTD_isError(result: usize) c_uint;
pub const struct_ZSTD_DCtx_s = opaque {};
pub const ZSTD_DCtx = struct_ZSTD_DCtx_s;
pub const ZSTD_d_windowLogMax: c_int = 100;
pub const ZSTD_dParameter = c_uint;
pub extern fn ZSTD_DCtx_setParameter(dctx: ?*ZSTD_DCtx, param: ZSTD_dParameter, value: c_int) usize;
pub const struct_ZSTD_inBuffer_s = extern struct {
    src: ?*const anyopaque = null,
    size: usize = 0,
    pos: usize = 0,
};
pub const ZSTD_inBuffer = struct_ZSTD_inBuffer_s;
pub const struct_ZSTD_outBuffer_s = extern struct {
    dst: ?*anyopaque = null,
    size: usize = 0,
    pos: usize = 0,
};
pub const ZSTD_outBuffer = struct_ZSTD_outBuffer_s;
pub const ZSTD_DStream = ZSTD_DCtx;
pub extern fn ZSTD_createDStream() ?*ZSTD_DStream;
pub extern fn ZSTD_freeDStream(zds: ?*ZSTD_DStream) usize;
pub extern fn ZSTD_initDStream(zds: ?*ZSTD_DStream) usize;
pub extern fn ZSTD_decompressStream(zds: ?*ZSTD_DStream, output: [*c]ZSTD_outBuffer, input: [*c]ZSTD_inBuffer) usize;
pub extern fn ZSTD_getDictID_fromFrame(src: ?*const anyopaque, srcSize: usize) c_uint;
pub const LZMA_TELL_UNSUPPORTED_CHECK: u32 = 0x02;
pub const LZMA_FAIL_FAST: u32 = 0x20;

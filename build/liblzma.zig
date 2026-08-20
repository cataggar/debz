const std = @import("std");

const decoder_sources: []const []const u8 = &.{
    "src/common/tuklib_physmem.c",
    "src/liblzma/check/check.c",
    "src/liblzma/check/crc32_fast.c",
    "src/liblzma/check/crc64_fast.c",
    "src/liblzma/check/sha256.c",
    "src/liblzma/common/alone_decoder.c",
    "src/liblzma/common/auto_decoder.c",
    "src/liblzma/common/block_buffer_decoder.c",
    "src/liblzma/common/block_decoder.c",
    "src/liblzma/common/block_header_decoder.c",
    "src/liblzma/common/block_util.c",
    "src/liblzma/common/common.c",
    "src/liblzma/common/easy_decoder_memusage.c",
    "src/liblzma/common/easy_preset.c",
    "src/liblzma/common/file_info.c",
    "src/liblzma/common/filter_buffer_decoder.c",
    "src/liblzma/common/filter_common.c",
    "src/liblzma/common/filter_decoder.c",
    "src/liblzma/common/filter_flags_decoder.c",
    "src/liblzma/common/hardware_physmem.c",
    "src/liblzma/common/index.c",
    "src/liblzma/common/index_decoder.c",
    "src/liblzma/common/index_hash.c",
    "src/liblzma/common/stream_buffer_decoder.c",
    "src/liblzma/common/stream_decoder.c",
    "src/liblzma/common/stream_flags_common.c",
    "src/liblzma/common/stream_flags_decoder.c",
    "src/liblzma/common/string_conversion.c",
    "src/liblzma/common/vli_decoder.c",
    "src/liblzma/common/vli_size.c",
    "src/liblzma/delta/delta_common.c",
    "src/liblzma/delta/delta_decoder.c",
    "src/liblzma/lz/lz_decoder.c",
    "src/liblzma/lzma/lzma2_decoder.c",
    "src/liblzma/lzma/lzma_decoder.c",
    "src/liblzma/lzma/lzma_encoder_presets.c",
    "src/liblzma/simple/arm.c",
    "src/liblzma/simple/arm64.c",
    "src/liblzma/simple/armthumb.c",
    "src/liblzma/simple/ia64.c",
    "src/liblzma/simple/powerpc.c",
    "src/liblzma/simple/riscv.c",
    "src/liblzma/simple/simple_coder.c",
    "src/liblzma/simple/simple_decoder.c",
    "src/liblzma/simple/sparc.c",
    "src/liblzma/simple/x86.c",
};

const include_directories: []const []const u8 = &.{
    "src/liblzma/api",
    "src/liblzma/common",
    "src/liblzma/check",
    "src/liblzma/lz",
    "src/liblzma/rangecoder",
    "src/liblzma/lzma",
    "src/liblzma/delta",
    "src/liblzma/simple",
    "src/common",
};

const definitions: []const []const u8 = &.{
    "HAVE_STDBOOL_H",
    "HAVE__BOOL",
    "HAVE_STDINT_H",
    "HAVE_INTTYPES_H",
    "HAVE_CHECK_CRC32",
    "HAVE_CHECK_CRC64",
    "HAVE_CHECK_SHA256",
    "HAVE_DECODERS",
    "HAVE_DECODER_LZMA1",
    "HAVE_DECODER_LZMA2",
    "HAVE_DECODER_DELTA",
    "HAVE_DECODER_X86",
    "HAVE_DECODER_ARM",
    "HAVE_DECODER_ARMTHUMB",
    "HAVE_DECODER_ARM64",
    "HAVE_DECODER_POWERPC",
    "HAVE_DECODER_IA64",
    "HAVE_DECODER_SPARC",
    "HAVE_DECODER_RISCV",
};

pub fn addStaticLibrary(
    b: *std.Build,
    xz: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    for (include_directories) |directory| {
        module.addIncludePath(xz.path(directory));
    }
    for (definitions) |definition| {
        module.addCMacro(definition, "1");
    }
    module.addCMacro("_GNU_SOURCE", "1");
    module.addCMacro("HAVE_VISIBILITY", "0");
    module.addCMacro("LZMA_API_STATIC", "1");
    module.addCMacro("TUKLIB_SYMBOL_PREFIX", "lzma_");
    if (target.result.cpu.arch.endian() == .big) {
        module.addCMacro("WORDS_BIGENDIAN", "1");
    }
    if (target.result.os.tag != .windows and
        target.result.os.tag != .wasi and
        target.result.os.tag != .freestanding)
    {
        module.addCMacro("TUKLIB_PHYSMEM_SYSCONF", "1");
    }
    module.addCSourceFiles(.{
        .root = xz.path(""),
        .files = decoder_sources,
        .flags = &.{"-std=c99"},
    });

    return b.addLibrary(.{
        .name = "lzma",
        .linkage = .static,
        .root_module = module,
        .version = .{ .major = 5, .minor = 8, .patch = 3 },
    });
}

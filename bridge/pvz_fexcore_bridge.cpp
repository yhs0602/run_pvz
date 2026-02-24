#include <unicorn/unicorn.h>
#include <new>

namespace {
struct BridgeContext {
    uc_engine* uc = nullptr;
};

BridgeContext* as_ctx(void* opaque) {
    return reinterpret_cast<BridgeContext*>(opaque);
}
}

#if defined(__GNUC__) || defined(__clang__)
#define PVZ_FEX_EXPORT __attribute__((visibility("default")))
#else
#define PVZ_FEX_EXPORT
#endif

extern "C" {

PVZ_FEX_EXPORT const char* pvz_fex_bridge_backend_name() {
    return "unicorn-shim";
}

PVZ_FEX_EXPORT bool pvz_fex_open_x86_32(void** out_ctx) {
    if (!out_ctx) {
        return false;
    }

    BridgeContext* ctx = new (std::nothrow) BridgeContext();
    if (!ctx) {
        return false;
    }

    if (uc_open(UC_ARCH_X86, UC_MODE_32, &ctx->uc) != UC_ERR_OK) {
        delete ctx;
        return false;
    }

    *out_ctx = ctx;
    return true;
}

PVZ_FEX_EXPORT void pvz_fex_close(void* opaque_ctx) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx) {
        return;
    }
    if (ctx->uc) {
        uc_close(ctx->uc);
        ctx->uc = nullptr;
    }
    delete ctx;
}

PVZ_FEX_EXPORT uc_err pvz_fex_mem_map(void* opaque_ctx, uint64_t address, size_t size, uint32_t perms) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx || !ctx->uc) return UC_ERR_HANDLE;
    return uc_mem_map(ctx->uc, address, size, perms);
}

PVZ_FEX_EXPORT uc_err pvz_fex_mem_read(void* opaque_ctx, uint64_t address, void* bytes, size_t size) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx || !ctx->uc) return UC_ERR_HANDLE;
    return uc_mem_read(ctx->uc, address, bytes, size);
}

PVZ_FEX_EXPORT uc_err pvz_fex_mem_write(void* opaque_ctx, uint64_t address, const void* bytes, size_t size) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx || !ctx->uc) return UC_ERR_HANDLE;
    return uc_mem_write(ctx->uc, address, bytes, size);
}

PVZ_FEX_EXPORT uc_err pvz_fex_reg_read(void* opaque_ctx, int regid, void* value) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx || !ctx->uc) return UC_ERR_HANDLE;
    return uc_reg_read(ctx->uc, regid, value);
}

PVZ_FEX_EXPORT uc_err pvz_fex_reg_write(void* opaque_ctx, int regid, const void* value) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx || !ctx->uc) return UC_ERR_HANDLE;
    return uc_reg_write(ctx->uc, regid, value);
}

PVZ_FEX_EXPORT uc_err pvz_fex_emu_start(void* opaque_ctx, uint64_t begin, uint64_t until, uint64_t timeout, size_t count) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx || !ctx->uc) return UC_ERR_HANDLE;
    return uc_emu_start(ctx->uc, begin, until, timeout, count);
}

PVZ_FEX_EXPORT uc_err pvz_fex_emu_stop(void* opaque_ctx) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx || !ctx->uc) return UC_ERR_HANDLE;
    return uc_emu_stop(ctx->uc);
}

PVZ_FEX_EXPORT uc_err pvz_fex_flush_tb(void* opaque_ctx) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx || !ctx->uc) return UC_ERR_HANDLE;
    return uc_ctl_flush_tb(ctx->uc);
}

PVZ_FEX_EXPORT uc_err pvz_fex_hook_add(
    void* opaque_ctx,
    uc_hook* hook,
    int type,
    void* callback,
    void* user_data,
    uint64_t begin,
    uint64_t end
) {
    BridgeContext* ctx = as_ctx(opaque_ctx);
    if (!ctx || !ctx->uc) return UC_ERR_HANDLE;
    return uc_hook_add(ctx->uc, hook, type, callback, user_data, begin, end);
}

PVZ_FEX_EXPORT const char* pvz_fex_strerror(uc_err err) {
    return uc_strerror(err);
}

} // extern "C"

#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_GetFileTime(APIContext* ctx) {
    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_INVALID_HANDLE = 6u;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87u;
    constexpr uint32_t ERROR_NOACCESS = 998u;
    constexpr uint32_t INVALID_HANDLE_VALUE = 0xFFFFFFFFu;
    constexpr uint64_t BASE_FILETIME = 132271296000000000ull; // 2020-01-01 UTC
    constexpr uint64_t TICKS_PER_SECOND = 10000000ull;

    const uint32_t hFile = ctx->get_arg(0);
    const uint32_t lpCreationTime = ctx->get_arg(1);
    const uint32_t lpLastAccessTime = ctx->get_arg(2);
    const uint32_t lpLastWriteTime = ctx->get_arg(3);

    uint32_t result = 0u;
    uint32_t last_error = ERROR_SUCCESS;

    if (hFile == 0u || hFile == INVALID_HANDLE_VALUE) {
        last_error = ERROR_INVALID_HANDLE;
    } else if (lpCreationTime == 0u && lpLastAccessTime == 0u && lpLastWriteTime == 0u) {
        last_error = ERROR_INVALID_PARAMETER;
    } else {
        const std::string key_prefix = "GetFileTime_" + std::to_string(hFile) + "_";
        const uint64_t seed = BASE_FILETIME + static_cast<uint64_t>(hFile & 0xFFFFu) * 37ull * TICKS_PER_SECOND;

        auto get_or_init = [&](const std::string& key, uint64_t fallback) -> uint64_t {
            auto it = ctx->global_state.find(key);
            if (it == ctx->global_state.end()) {
                ctx->global_state[key] = fallback;
                return fallback;
            }
            return it->second;
        };

        uint64_t creation_time = get_or_init(key_prefix + "creation", seed);
        uint64_t access_time = get_or_init(key_prefix + "access", creation_time + 2ull * TICKS_PER_SECOND);
        uint64_t write_time = get_or_init(key_prefix + "write", creation_time + 4ull * TICKS_PER_SECOND);

        auto write_filetime = [&](uint32_t ptr, uint64_t value) -> bool {
            if (ptr == 0u) {
                return true;
            }
            uint32_t ft[2];
            ft[0] = static_cast<uint32_t>(value & 0xFFFFFFFFull);
            ft[1] = static_cast<uint32_t>(value >> 32);
            return uc_mem_write(ctx->uc, ptr, ft, sizeof(ft)) == UC_ERR_OK;
        };

        const bool ok =
            write_filetime(lpCreationTime, creation_time) &&
            write_filetime(lpLastAccessTime, access_time) &&
            write_filetime(lpLastWriteTime, write_time);

        if (ok) {
            access_time += TICKS_PER_SECOND;
            ctx->global_state[key_prefix + "access"] = access_time;
            result = 1u;
            last_error = ERROR_SUCCESS;
        } else {
            last_error = ERROR_NOACCESS;
        }
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 16 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
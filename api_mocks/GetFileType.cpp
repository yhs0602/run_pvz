#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_GetFileType(APIContext* ctx) {
    constexpr uint32_t FILE_TYPE_UNKNOWN = 0x0000u;
    constexpr uint32_t FILE_TYPE_DISK = 0x0001u;
    constexpr uint32_t FILE_TYPE_CHAR = 0x0002u;
    constexpr uint32_t INVALID_HANDLE_VALUE = 0xFFFFFFFFu;
    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_INVALID_HANDLE = 6u;

    const uint32_t hFile = ctx->get_arg(0);
    uint32_t result = FILE_TYPE_UNKNOWN;

    if (hFile == 0u || hFile == INVALID_HANDLE_VALUE) {
        result = FILE_TYPE_UNKNOWN;
        ctx->global_state["LastError"] = ERROR_INVALID_HANDLE;
    } else if (hFile == 0x00000020u || hFile == 0x00000024u || hFile == 0x00000028u) {
        result = FILE_TYPE_CHAR;
        ctx->global_state["LastError"] = ERROR_SUCCESS;
    } else {
        result = FILE_TYPE_DISK;
        ctx->global_state["LastError"] = ERROR_SUCCESS;
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
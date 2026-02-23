#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_GetFileVersionInfoSizeA(APIContext* ctx) {
    const uint32_t lptstrFilename = ctx->get_arg(0);
    const uint32_t lpdwHandle = ctx->get_arg(1);

    if (lpdwHandle != 0) {
        const uint32_t zero = 0;
        uc_mem_write(ctx->uc, lpdwHandle, &zero, sizeof(zero));
    }

    uint32_t result = 0;
    if (lptstrFilename != 0) {
        char ch = 0;
        if (uc_mem_read(ctx->uc, lptstrFilename, &ch, 1) == UC_ERR_OK && ch != '\0') {
            uint32_t hash = 2166136261u;
            for (uint32_t i = 0; i < 260; ++i) {
                if (uc_mem_read(ctx->uc, lptstrFilename + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
                    break;
                }
                hash ^= static_cast<uint8_t>(ch);
                hash *= 16777619u;
            }
            result = 0x300u + (hash & 0xFFu);
            ctx->global_state["LastError"] = 0;
        } else {
            ctx->global_state["LastError"] = 2;
        }
    } else {
        ctx->global_state["LastError"] = 2;
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
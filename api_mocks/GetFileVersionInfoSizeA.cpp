#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_GetFileVersionInfoSizeA(APIContext* ctx) {
    const uint32_t lptstrFilename = ctx->get_arg(0);
    const uint32_t lpdwHandle = ctx->get_arg(1);

    if (lpdwHandle != 0) {
        const uint32_t zero = 0;
        ctx->backend->mem_write(lpdwHandle, &zero, sizeof(zero));
    }

    uint32_t result = 0;
    if (lptstrFilename != 0) {
        char ch = 0;
        if (ctx->backend->mem_read(lptstrFilename, &ch, 1) == UC_ERR_OK && ch != '\0') {
            uint32_t hash = 2166136261u;
            for (uint32_t i = 0; i < 260; ++i) {
                if (ctx->backend->mem_read(lptstrFilename + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
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
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
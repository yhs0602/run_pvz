#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_GetStdHandle(APIContext* ctx) {
    const uint32_t nStdHandle = ctx->get_arg(0);

    uint32_t result;
    switch (nStdHandle) {
        case 0xFFFFFFF6u: // STD_INPUT_HANDLE  (-10)
            result = 0x00000020u;
            break;
        case 0xFFFFFFF5u: // STD_OUTPUT_HANDLE (-11)
            result = 0x00000024u;
            break;
        case 0xFFFFFFF4u: // STD_ERROR_HANDLE  (-12)
            result = 0x00000028u;
            break;
        default:
            result = 0xFFFFFFFFu; // INVALID_HANDLE_VALUE
            break;
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
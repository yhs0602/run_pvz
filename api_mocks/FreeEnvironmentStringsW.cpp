#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_FreeEnvironmentStringsW(APIContext* ctx) {
    uint32_t lpszEnvironmentBlock = static_cast<uint32_t>(ctx->get_arg(0));

    uint32_t result = (lpszEnvironmentBlock != 0) ? 1u : 0u;
    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
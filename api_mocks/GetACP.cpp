#include "api_context.hpp"

#include <cstdint>

extern "C" void mock_GetACP(APIContext* ctx) {
    const uint32_t ignored_arg0 = ctx->get_arg(0);
    (void)ignored_arg0;

    uint32_t acp = 1252;

    auto it = ctx->global_state.find("ACP");
    if (it != ctx->global_state.end()) {
        acp = static_cast<uint32_t>(it->second);
    } else {
        ctx->global_state["ACP"] = acp;
    }

    ctx->set_eax(acp);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 0 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
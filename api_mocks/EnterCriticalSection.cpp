#include "api_context.hpp"

extern "C" void mock_EnterCriticalSection(APIContext* ctx) {
    uint32_t lpCriticalSection = ctx->get_arg(0);
    (void)lpCriticalSection;

    ctx->set_eax(1);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
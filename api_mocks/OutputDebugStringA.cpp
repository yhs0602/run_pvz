#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_OutputDebugStringA(APIContext* ctx) {
    uint32_t lpOutputString = static_cast<uint32_t>(ctx->get_arg(0));
    (void)lpOutputString;

    ctx->set_eax(0);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
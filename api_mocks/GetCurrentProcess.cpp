#include "api_context.hpp"

extern "C" void mock_GetCurrentProcess(APIContext* ctx) {
    // GetCurrentProcess has no arguments.
    ctx->set_eax(0xFFFFFFFF); // Pseudo-handle for the current process

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 0 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
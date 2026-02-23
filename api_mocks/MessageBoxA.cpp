#include "api_context.hpp"

extern "C" void mock_MessageBoxA(APIContext* ctx) {
    uint32_t hWnd = static_cast<uint32_t>(ctx->get_arg(0));
    uint32_t lpText = static_cast<uint32_t>(ctx->get_arg(1));
    uint32_t lpCaption = static_cast<uint32_t>(ctx->get_arg(2));
    uint32_t uType = static_cast<uint32_t>(ctx->get_arg(3));
    (void)hWnd;
    (void)lpText;
    (void)lpCaption;
    (void)uType;

    ctx->set_eax(1); // IDOK

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 16 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
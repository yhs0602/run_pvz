#include "api_context.hpp"

extern "C" void mock_IDirectDraw7_Method_0(APIContext* ctx) {
    uint32_t this_ptr = static_cast<uint32_t>(ctx->get_arg(0));
    uint32_t riid = static_cast<uint32_t>(ctx->get_arg(1));
    uint32_t ppv_obj = static_cast<uint32_t>(ctx->get_arg(2));
    (void)riid;

    if (ppv_obj != 0) {
        ctx->backend->mem_write(ppv_obj, &this_ptr, 4);
        ctx->set_eax(0x00000000); // S_OK
    } else {
        ctx->set_eax(0x80004003); // E_POINTER
    }

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 12 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
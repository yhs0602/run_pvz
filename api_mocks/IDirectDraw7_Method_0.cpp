#include "api_context.hpp"

extern "C" void mock_IDirectDraw7_Method_0(APIContext* ctx) {
    uint32_t this_ptr = static_cast<uint32_t>(ctx->get_arg(0));
    uint32_t riid = static_cast<uint32_t>(ctx->get_arg(1));
    uint32_t ppv_obj = static_cast<uint32_t>(ctx->get_arg(2));
    (void)riid;

    if (ppv_obj != 0) {
        uc_mem_write(ctx->uc, ppv_obj, &this_ptr, 4);
        ctx->set_eax(0x00000000); // S_OK
    } else {
        ctx->set_eax(0x80004003); // E_POINTER
    }

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 12 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
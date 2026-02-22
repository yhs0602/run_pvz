#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_InterlockedDecrement(APIContext* ctx) {
    uint32_t addend_ptr = static_cast<uint32_t>(ctx->get_arg(0));

    int32_t value = 0;
    if (addend_ptr != 0) {
        if (uc_mem_read(ctx->uc, addend_ptr, &value, sizeof(value)) == UC_ERR_OK) {
            value -= 1;
            uc_mem_write(ctx->uc, addend_ptr, &value, sizeof(value));
        }
    }

    ctx->set_eax(static_cast<uint32_t>(value));

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
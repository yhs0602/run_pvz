#include "api_context.hpp"

extern "C" void mock_RaiseException(APIContext* ctx) {
    uint32_t dwExceptionCode = static_cast<uint32_t>(ctx->get_arg(0));
    uint32_t dwExceptionFlags = static_cast<uint32_t>(ctx->get_arg(1));
    uint32_t nNumberOfArguments = static_cast<uint32_t>(ctx->get_arg(2));
    uint32_t lpArguments = static_cast<uint32_t>(ctx->get_arg(3));

    (void)dwExceptionCode;
    (void)dwExceptionFlags;
    (void)nNumberOfArguments;
    (void)lpArguments;

    ctx->set_eax(0);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 16 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
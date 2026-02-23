#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_UnhandledExceptionFilter(APIContext* ctx) {
    const uint32_t lpExceptionInfo = ctx->get_arg(0);

    constexpr uint32_t EXCEPTION_CONTINUE_SEARCH = 0x00000000u;
    constexpr uint32_t EXCEPTION_EXECUTE_HANDLER = 0x00000001u;

    if (lpExceptionInfo != 0) {
        ctx->global_state["LastUnhandledExceptionInfo"] = static_cast<uint64_t>(lpExceptionInfo);
    }

    const uint32_t result = (lpExceptionInfo != 0) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
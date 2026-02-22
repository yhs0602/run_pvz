#include "api_context.hpp"
#include <cstdint>
#include <iostream>

extern "C" void mock_SetUnhandledExceptionFilter(APIContext* ctx) {
    const uint32_t lpTopLevelExceptionFilter = ctx->get_arg(0);

    uint32_t previous_filter = 0;
    auto it = ctx->global_state.find("UnhandledExceptionFilter");
    if (it != ctx->global_state.end()) {
        previous_filter = static_cast<uint32_t>(it->second);
    }

    ctx->global_state["UnhandledExceptionFilter"] = static_cast<uint64_t>(lpTopLevelExceptionFilter);
    ctx->set_eax(previous_filter);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    
    std::cout << "[mock_SetUnhandledExceptionFilter] Caller ret_addr: 0x" << std::hex << ret_addr << std::dec << "\n";
    
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
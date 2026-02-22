#include "api_context.hpp"
#include <iostream>

extern "C" void mock_InitializeCriticalSection(APIContext* ctx) {
    uint32_t lpCriticalSection = ctx->get_arg(0);

    if (lpCriticalSection != 0) {
        uint32_t debugInfo = 0;
        int32_t lockCount = -1;
        uint32_t recursionCount = 0;
        uint32_t owningThread = 0;
        uint32_t lockSemaphore = 0;
        uint32_t spinCount = 0;

        uc_mem_write(ctx->uc, lpCriticalSection + 0x00, &debugInfo, 4);
        uc_mem_write(ctx->uc, lpCriticalSection + 0x04, &lockCount, 4);
        uc_mem_write(ctx->uc, lpCriticalSection + 0x08, &recursionCount, 4);
        uc_mem_write(ctx->uc, lpCriticalSection + 0x0C, &owningThread, 4);
        uc_mem_write(ctx->uc, lpCriticalSection + 0x10, &lockSemaphore, 4);
        uc_mem_write(ctx->uc, lpCriticalSection + 0x14, &spinCount, 4);
    }

    ctx->set_eax(0);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    
    std::cout << "[mock_InitializeCriticalSection] Caller ret_addr: 0x" << std::hex << ret_addr << std::dec << "\n";
    
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
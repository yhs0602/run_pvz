#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_InitializeCriticalSectionAndSpinCount(APIContext* ctx) {
    const uint32_t lpCriticalSection = static_cast<uint32_t>(ctx->get_arg(0));
    const uint32_t dwSpinCount = static_cast<uint32_t>(ctx->get_arg(1));

    uint32_t result = 1;

    if (lpCriticalSection == 0) {
        result = 0;
    } else {
        struct CriticalSection32 {
            uint32_t DebugInfo;
            uint32_t LockCount;
            uint32_t RecursionCount;
            uint32_t OwningThread;
            uint32_t LockSemaphore;
            uint32_t SpinCount;
        } cs{};

        cs.DebugInfo = 0;
        cs.LockCount = 0xFFFFFFFFu; // -1 (unlocked)
        cs.RecursionCount = 0;
        cs.OwningThread = 0;
        cs.LockSemaphore = 0;
        cs.SpinCount = dwSpinCount;

        if (ctx->backend->mem_write(lpCriticalSection, &cs, sizeof(cs)) != UC_ERR_OK) {
            result = 0;
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
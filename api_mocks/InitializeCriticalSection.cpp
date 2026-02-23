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

        ctx->backend->mem_write(lpCriticalSection + 0x00, &debugInfo, 4);
        ctx->backend->mem_write(lpCriticalSection + 0x04, &lockCount, 4);
        ctx->backend->mem_write(lpCriticalSection + 0x08, &recursionCount, 4);
        ctx->backend->mem_write(lpCriticalSection + 0x0C, &owningThread, 4);
        ctx->backend->mem_write(lpCriticalSection + 0x10, &lockSemaphore, 4);
        ctx->backend->mem_write(lpCriticalSection + 0x14, &spinCount, 4);
    }

    ctx->set_eax(0);

}
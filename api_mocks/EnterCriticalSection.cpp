#include "api_context.hpp"

extern "C" void mock_EnterCriticalSection(APIContext* ctx) {
    uint32_t lpCriticalSection = ctx->get_arg(0);
    (void)lpCriticalSection;

    ctx->set_eax(1);
}
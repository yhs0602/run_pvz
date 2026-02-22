#include "api_context.hpp"

extern "C" void mock_SetHandleCount(APIContext* ctx) {
    uint32_t uNumber = static_cast<uint32_t>(ctx->get_arg(0));
    ctx->set_eax(uNumber);
}
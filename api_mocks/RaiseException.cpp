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
}
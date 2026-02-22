#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_FreeEnvironmentStringsW(APIContext* ctx) {
    uint32_t lpszEnvironmentBlock = static_cast<uint32_t>(ctx->get_arg(0));

    uint32_t result = (lpszEnvironmentBlock != 0) ? 1u : 0u;
    ctx->set_eax(result);
}
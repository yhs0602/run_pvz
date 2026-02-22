#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_GetStdHandle(APIContext* ctx) {
    const uint32_t nStdHandle = ctx->get_arg(0);

    uint32_t result;
    switch (nStdHandle) {
        case 0xFFFFFFF6u: // STD_INPUT_HANDLE  (-10)
            result = 0x00000020u;
            break;
        case 0xFFFFFFF5u: // STD_OUTPUT_HANDLE (-11)
            result = 0x00000024u;
            break;
        case 0xFFFFFFF4u: // STD_ERROR_HANDLE  (-12)
            result = 0x00000028u;
            break;
        default:
            result = 0xFFFFFFFFu; // INVALID_HANDLE_VALUE
            break;
    }

    ctx->set_eax(result);
}
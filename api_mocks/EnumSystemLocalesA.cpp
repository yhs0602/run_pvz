#include "api_context.hpp"

#include <cstdint>

extern "C" void mock_EnumSystemLocalesA(APIContext* ctx) {
    const uint32_t lpLocaleEnumProc = ctx->get_arg(0);
    const uint32_t dwFlags = ctx->get_arg(1);

    constexpr uint32_t LCID_INSTALLED = 0x00000001;
    constexpr uint32_t LCID_SUPPORTED = 0x00000002;

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t ERROR_INVALID_FLAGS = 1004;

    uint32_t result = 0;
    uint32_t last_error = ERROR_SUCCESS;

    const uint32_t invalid_mask = ~(LCID_INSTALLED | LCID_SUPPORTED);

    if (lpLocaleEnumProc == 0) {
        result = 0;
        last_error = ERROR_INVALID_PARAMETER;
    } else if ((dwFlags == 0) || ((dwFlags & invalid_mask) != 0)) {
        result = 0;
        last_error = ERROR_INVALID_FLAGS;
    } else {
        result = 1;
        last_error = ERROR_SUCCESS;

        ctx->global_state["LastEnumSystemLocalesA_Callback"] = lpLocaleEnumProc;
        ctx->global_state["LastEnumSystemLocalesA_Flags"] = dwFlags;
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);
}
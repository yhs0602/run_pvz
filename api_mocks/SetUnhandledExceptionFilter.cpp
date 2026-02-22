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

}
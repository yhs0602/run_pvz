#include "api_context.hpp"

#include <cstdint>

extern "C" void mock_GetACP(APIContext* ctx) {
    const uint32_t ignored_arg0 = ctx->get_arg(0);
    (void)ignored_arg0;

    uint32_t acp = 1252;

    auto it = ctx->global_state.find("ACP");
    if (it != ctx->global_state.end()) {
        acp = static_cast<uint32_t>(it->second);
    } else {
        ctx->global_state["ACP"] = acp;
    }

    ctx->set_eax(acp);
}
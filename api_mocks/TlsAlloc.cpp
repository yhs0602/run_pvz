#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_TlsAlloc(APIContext* ctx) {
    constexpr uint32_t TLS_OUT_OF_INDEXES = 0xFFFFFFFFu;
    constexpr uint32_t TLS_MAX_SLOTS = 1088u;
    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_NO_MORE_ITEMS = 259u;

    uint32_t result = TLS_OUT_OF_INDEXES;

    uint64_t next_index = 0;
    auto next_it = ctx->global_state.find("tls_next_alloc_index");
    if (next_it != ctx->global_state.end()) {
        next_index = next_it->second;
    }

    if (next_index < TLS_MAX_SLOTS) {
        result = static_cast<uint32_t>(next_index);
        ctx->global_state["tls_next_alloc_index"] = next_index + 1;
        ctx->global_state["tls_" + std::to_string(result)] = 0;
        ctx->global_state["LastError"] = ERROR_SUCCESS;
    } else {
        ctx->global_state["LastError"] = ERROR_NO_MORE_ITEMS;
    }

    ctx->set_eax(result);
}
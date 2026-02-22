#include "api_context.hpp"

#include <cstdint>
#include <string>
#include <iostream> // Added for std::cout

extern "C" void mock_TlsGetValue(APIContext* ctx) {
    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t TLS_MAX_SLOTS = 1088;

    const uint32_t dwTlsIndex = ctx->get_arg(0);
    uint32_t result = 0;

    std::cout << "[mock_TlsGetValue] dwTlsIndex: " << dwTlsIndex << "\n";
    
    if (dwTlsIndex == 0xFFFFFFFF) {
        ctx->set_eax(0);
        ctx->global_state["LastError"] = ERROR_INVALID_PARAMETER;
    } else {
        // Look up the value from the PE-loader initialized TLS entries or dynamically allocated TLS
        const std::string key = "tls_" + std::to_string(dwTlsIndex);
        auto it = ctx->global_state.find(key);
        if (it != ctx->global_state.end()) {
            result = static_cast<uint32_t>(it->second);
        }
        ctx->global_state["LastError"] = ERROR_SUCCESS;
        ctx->set_eax(result);
    }
}
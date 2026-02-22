#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_TlsSetValue(APIContext* ctx) {
    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t TLS_MAX_SLOTS = 1088;

    const uint32_t dwTlsIndex = ctx->get_arg(0);
    const uint32_t lpTlsValue = ctx->get_arg(1);

    uint32_t result = 0;
    if (dwTlsIndex < TLS_MAX_SLOTS) {
        const std::string key = "tls_" + std::to_string(dwTlsIndex);
        ctx->global_state[key] = static_cast<uint64_t>(lpTlsValue);
        ctx->global_state["LastError"] = ERROR_SUCCESS;
        result = 1;
    } else {
        ctx->global_state["LastError"] = ERROR_INVALID_PARAMETER;
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
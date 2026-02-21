#include "api_context.hpp"
#include <cstdint>
#include <string>

extern "C" void mock_TlsGetValue(APIContext* ctx) {
    const uint32_t dwTlsIndex = ctx->get_arg(0);

    uint32_t ret = 0;
    const std::string key = "tls_slot_" + std::to_string(dwTlsIndex);
    auto it = ctx->global_state.find(key);
    if (it != ctx->global_state.end()) {
        ret = static_cast<uint32_t>(it->second & 0xFFFFFFFFu);
    }

    // TlsGetValue clears last error on success, including NULL TLS values.
    ctx->global_state["LastError"] = 0;
    ctx->set_eax(ret);

    uint32_t esp = 0;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    esp += 4; // 1 argument * 4 bytes
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
}
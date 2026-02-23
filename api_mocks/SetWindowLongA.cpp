#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_SetWindowLongA(APIContext* ctx) {
    const uint32_t hWnd = ctx->get_arg(0);
    const int32_t nIndex = static_cast<int32_t>(ctx->get_arg(1));
    const uint32_t dwNewLong = ctx->get_arg(2);

    uint32_t previous_value = 0;

    if (hWnd == 0) {
        // Invalid window handle
        ctx->global_state["LastError"] = 1400; // ERROR_INVALID_WINDOW_HANDLE
    } else {
        const std::string key =
            "SetWindowLongA_" + std::to_string(hWnd) + "_" + std::to_string(nIndex);

        auto it = ctx->global_state.find(key);
        if (it != ctx->global_state.end()) {
            previous_value = static_cast<uint32_t>(it->second);
        }

        ctx->global_state[key] = static_cast<uint64_t>(dwNewLong);
        ctx->global_state["LastError"] = 0; // ERROR_SUCCESS
    }

    ctx->set_eax(previous_value);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 12 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_FlsSetValue(APIContext* ctx) {
    constexpr uint32_t FLS_OUT_OF_INDEXES = 0xFFFFFFFFu;
    constexpr uint32_t FLS_MAX_SLOTS = 128u;
    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87u;

    const uint32_t dwFlsIndex = ctx->get_arg(0);
    const uint32_t lpFlsData = ctx->get_arg(1);

    uint32_t result = 0;
    bool valid_index = (dwFlsIndex != FLS_OUT_OF_INDEXES) && (dwFlsIndex < FLS_MAX_SLOTS);

    auto next_it = ctx->global_state.find("fls_next_alloc_index");
    if (valid_index && next_it != ctx->global_state.end()) {
        valid_index = dwFlsIndex < static_cast<uint32_t>(next_it->second);
    }

    if (valid_index) {
        ctx->global_state["fls_" + std::to_string(dwFlsIndex)] = static_cast<uint64_t>(lpFlsData);
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
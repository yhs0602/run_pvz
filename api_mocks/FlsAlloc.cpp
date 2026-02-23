#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_FlsAlloc(APIContext* ctx) {
    constexpr uint32_t FLS_OUT_OF_INDEXES = 0xFFFFFFFFu;
    constexpr uint32_t FLS_MAX_SLOTS = 128u;
    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_NO_MORE_ITEMS = 259u;

    const uint32_t lpCallback = ctx->get_arg(0);

    uint32_t result = FLS_OUT_OF_INDEXES;

    uint64_t next_index = 0;
    auto next_it = ctx->global_state.find("fls_next_alloc_index");
    if (next_it != ctx->global_state.end()) {
        next_index = next_it->second;
    }

    if (next_index < FLS_MAX_SLOTS) {
        result = static_cast<uint32_t>(next_index);
        ctx->global_state["fls_next_alloc_index"] = next_index + 1;
        ctx->global_state["fls_" + std::to_string(result)] = 0;
        ctx->global_state["fls_cb_" + std::to_string(result)] = static_cast<uint64_t>(lpCallback);
        ctx->global_state["LastError"] = ERROR_SUCCESS;
    } else {
        ctx->global_state["LastError"] = ERROR_NO_MORE_ITEMS;
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
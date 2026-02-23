#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_CreateCursor(APIContext* ctx) {
    const uint32_t hInst = ctx->get_arg(0);
    const int32_t xHotSpot = static_cast<int32_t>(ctx->get_arg(1));
    const int32_t yHotSpot = static_cast<int32_t>(ctx->get_arg(2));
    const int32_t nWidth = static_cast<int32_t>(ctx->get_arg(3));
    const int32_t nHeight = static_cast<int32_t>(ctx->get_arg(4));
    const uint32_t pvANDPlane = ctx->get_arg(5);
    const uint32_t pvXORPlane = ctx->get_arg(6);

    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87u;

    uint32_t result = 0;
    const bool valid =
        (nWidth > 0) &&
        (nHeight > 0) &&
        (xHotSpot >= 0) &&
        (yHotSpot >= 0) &&
        (xHotSpot < nWidth) &&
        (yHotSpot < nHeight) &&
        (pvANDPlane != 0) &&
        (pvXORPlane != 0);

    if (valid) {
        uint64_t next_handle = 0x00020000u;
        auto it = ctx->global_state.find("CreateCursor_next_handle");
        if (it != ctx->global_state.end() && it->second != 0) {
            next_handle = it->second;
        }

        result = static_cast<uint32_t>(next_handle);
        ctx->global_state["CreateCursor_next_handle"] = static_cast<uint64_t>(result + 4u);
        ctx->global_state["CreateCursor_last_handle"] = result;
        ctx->global_state["CreateCursor_last_hInst"] = hInst;
        ctx->global_state["CreateCursor_last_width"] = static_cast<uint32_t>(nWidth);
        ctx->global_state["CreateCursor_last_height"] = static_cast<uint32_t>(nHeight);
        ctx->global_state["CreateCursor_last_hotspot_x"] = static_cast<uint32_t>(xHotSpot);
        ctx->global_state["CreateCursor_last_hotspot_y"] = static_cast<uint32_t>(yHotSpot);
        ctx->global_state["LastError"] = ERROR_SUCCESS;
    } else {
        ctx->global_state["LastError"] = ERROR_INVALID_PARAMETER;
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 28 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
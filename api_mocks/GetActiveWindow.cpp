#include "api_context.hpp"

#include <cstdint>

extern "C" void mock_GetActiveWindow(APIContext* ctx) {
    const uint32_t ignored_arg0 = ctx->get_arg(0);
    (void)ignored_arg0;

    uint32_t hwnd = 0;
    auto it = ctx->global_state.find("GetActiveWindow.hwnd");
    if (it != ctx->global_state.end() && it->second != 0) {
        hwnd = static_cast<uint32_t>(it->second);
    } else {
        auto active_it = ctx->global_state.find("ActiveWindow");
        if (active_it != ctx->global_state.end() && active_it->second != 0) {
            hwnd = static_cast<uint32_t>(active_it->second);
        } else {
            auto desktop_it = ctx->global_state.find("DesktopWindow");
            if (desktop_it != ctx->global_state.end() && desktop_it->second != 0) {
                hwnd = static_cast<uint32_t>(desktop_it->second);
            } else {
                hwnd = 0x00010020; // plausible top-level HWND
            }
        }
        ctx->global_state["GetActiveWindow.hwnd"] = static_cast<uint64_t>(hwnd);
    }

    ctx->global_state["ActiveWindow"] = static_cast<uint64_t>(hwnd);
    ctx->set_eax(hwnd);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 0 + 4;
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
#include "api_context.hpp"

#include <cstdint>

extern "C" void mock_GetDesktopWindow(APIContext* ctx) {
    const uint32_t ignored_arg0 = ctx->get_arg(0);
    (void)ignored_arg0;

    uint32_t hwnd = 0x00010010;
    auto it = ctx->global_state.find("DesktopWindow");
    if (it != ctx->global_state.end() && it->second != 0) {
        hwnd = static_cast<uint32_t>(it->second);
    } else {
        ctx->global_state["DesktopWindow"] = hwnd;
    }

    ctx->set_eax(hwnd);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 0 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
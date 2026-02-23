#include "api_context.hpp"

#include <cstdint>

extern "C" void mock_BASS_Init(APIContext* ctx) {
    const int32_t device = static_cast<int32_t>(ctx->get_arg(0));
    const uint32_t freq = ctx->get_arg(1);
    const uint32_t flags = ctx->get_arg(2);
    const uint32_t win = ctx->get_arg(3);
    const uint32_t dsguid = ctx->get_arg(4);

    uint32_t result = 1;
    if (freq < 8000 || freq > 384000) {
        result = 0;
    }

    ctx->global_state["BASS_Initialized"] = result ? 1u : 0u;
    ctx->global_state["BASS_Device"] = static_cast<uint32_t>(device);
    ctx->global_state["BASS_Freq"] = freq;
    ctx->global_state["BASS_Flags"] = flags;
    ctx->global_state["BASS_Window"] = win;
    ctx->global_state["BASS_DS_GUID"] = dsguid;
    ctx->global_state["LastError"] = result ? 0u : 87u;

    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 20 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
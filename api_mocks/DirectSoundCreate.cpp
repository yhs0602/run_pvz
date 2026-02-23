#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_DirectSoundCreate(APIContext* ctx) {
    const uint32_t pcGuidDevice = ctx->get_arg(0);
    const uint32_t ppDS = ctx->get_arg(1);
    const uint32_t pUnkOuter = ctx->get_arg(2);

    constexpr uint32_t DS_OK = 0x00000000;
    constexpr uint32_t DSERR_INVALIDPARAM = 0x88780064;
    constexpr uint32_t CLASS_E_NOAGGREGATION = 0x80040110;

    uint32_t hr = DS_OK;

    if (ppDS == 0) {
        hr = DSERR_INVALIDPARAM;
    } else if (pUnkOuter != 0) {
        hr = CLASS_E_NOAGGREGATION;
    } else {
        uint32_t ds_obj = 0x61000000;
        auto it = ctx->global_state.find("DirectSoundCreate_next_obj");
        if (it != ctx->global_state.end()) {
            ds_obj = static_cast<uint32_t>(it->second);
        }
        if (ds_obj == 0 || ds_obj == 0xFFFFFFFFu) {
            ds_obj = 0x61000000;
        }

        ctx->global_state["DirectSoundCreate_next_obj"] = static_cast<uint64_t>(ds_obj + 0x100);
        ctx->global_state["DirectSoundCreate_last_guid"] = static_cast<uint64_t>(pcGuidDevice);
        ctx->handle_map["dsound_" + std::to_string(ds_obj)] =
            reinterpret_cast<void*>(static_cast<uintptr_t>(ds_obj));

        if (ctx->backend->mem_write(ppDS, &ds_obj, 4) != UC_ERR_OK) {
            hr = DSERR_INVALIDPARAM;
        }
    }

    ctx->global_state["LastError"] = (hr == DS_OK) ? 0u : 87u;
    ctx->set_eax(hr);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 12 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
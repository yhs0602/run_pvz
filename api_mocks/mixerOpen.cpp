#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_mixerOpen(APIContext* ctx) {
    const uint32_t phmx = ctx->get_arg(0);
    const uint32_t uMxId = ctx->get_arg(1);
    const uint32_t dwCallback = ctx->get_arg(2);
    const uint32_t dwInstance = ctx->get_arg(3);
    const uint32_t fdwOpen = ctx->get_arg(4);

    constexpr uint32_t MMSYSERR_NOERROR = 0;
    constexpr uint32_t MMSYSERR_BADDEVICEID = 2;
    constexpr uint32_t MMSYSERR_INVALHANDLE = 5;
    constexpr uint32_t MMSYSERR_INVALPARAM = 11;

    constexpr uint32_t MIXER_OBJECTF_HANDLE = 0x80000000u;

    uint32_t result = MMSYSERR_NOERROR;
    uint32_t resolved_device_id = uMxId;

    if (phmx == 0) {
        result = MMSYSERR_INVALPARAM;
    }

    const bool open_from_handle = (fdwOpen & MIXER_OBJECTF_HANDLE) != 0;
    if (result == MMSYSERR_NOERROR) {
        if (open_from_handle) {
            const std::string valid_key = "mixer_valid_" + std::to_string(uMxId);
            auto valid_it = ctx->global_state.find(valid_key);
            if (valid_it == ctx->global_state.end() || valid_it->second == 0) {
                result = MMSYSERR_INVALHANDLE;
            } else {
                const std::string dev_key = "mixer_device_" + std::to_string(uMxId);
                auto dev_it = ctx->global_state.find(dev_key);
                if (dev_it != ctx->global_state.end()) {
                    resolved_device_id = static_cast<uint32_t>(dev_it->second);
                } else {
                    resolved_device_id = 0;
                }
            }
        } else {
            // Mock environment exposes a single mixer device (ID 0).
            if (uMxId != 0) {
                result = MMSYSERR_BADDEVICEID;
            }
        }
    }

    if (result == MMSYSERR_NOERROR) {
        uint32_t hmx = 0xA000u;
        auto next_it = ctx->global_state.find("mixer_next_handle");
        if (next_it != ctx->global_state.end()) {
            hmx = static_cast<uint32_t>(next_it->second);
        }
        if (hmx == 0 || hmx == 0xFFFFFFFFu) {
            hmx = 0xA000u;
        }

        if (ctx->backend->mem_write(phmx, &hmx, sizeof(hmx)) != UC_ERR_OK) {
            result = MMSYSERR_INVALPARAM;
        } else {
            ctx->global_state["mixer_next_handle"] = static_cast<uint64_t>(hmx + 4u);
            ctx->global_state["mixer_valid_" + std::to_string(hmx)] = 1u;
            ctx->global_state["mixer_device_" + std::to_string(hmx)] = static_cast<uint64_t>(resolved_device_id);
            ctx->global_state["mixer_callback_" + std::to_string(hmx)] = static_cast<uint64_t>(dwCallback);
            ctx->global_state["mixer_instance_" + std::to_string(hmx)] = static_cast<uint64_t>(dwInstance);
            ctx->global_state["mixer_flags_" + std::to_string(hmx)] = static_cast<uint64_t>(fdwOpen);

            uint64_t open_count = 0;
            auto open_it = ctx->global_state.find("mixer_open_count");
            if (open_it != ctx->global_state.end()) {
                open_count = open_it->second;
            }
            ctx->global_state["mixer_open_count"] = open_count + 1u;

            ctx->handle_map["mixer_" + std::to_string(hmx)] =
                reinterpret_cast<void*>(static_cast<uintptr_t>(hmx));
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 20 + 4;
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
#include "api_context.hpp"

#include <cstdint>
#include <string>

#pragma pack(push, 1)
struct MIXERCONTROLDETAILS_MOCK {
    uint32_t cbStruct;
    uint32_t dwControlID;
    uint32_t cChannels;
    uint32_t hwndOwner_or_cMultipleItems;
    uint32_t cbDetails;
    uint32_t paDetails;
};
#pragma pack(pop)

extern "C" void mock_mixerSetControlDetails(APIContext* ctx) {
    const uint32_t hmxobj = ctx->get_arg(0);
    const uint32_t pmxcd = ctx->get_arg(1);
    const uint32_t fdwDetails = ctx->get_arg(2);

    constexpr uint32_t MMSYSERR_NOERROR = 0;
    constexpr uint32_t MMSYSERR_BADDEVICEID = 2;
    constexpr uint32_t MMSYSERR_INVALHANDLE = 5;
    constexpr uint32_t MMSYSERR_INVALFLAG = 10;
    constexpr uint32_t MMSYSERR_INVALPARAM = 11;

    constexpr uint32_t MIXER_OBJECTF_HANDLE = 0x80000000u;
    constexpr uint32_t MIXER_SETCONTROLDETAILSF_VALUE = 0x00000000u;
    constexpr uint32_t MIXER_SETCONTROLDETAILSF_CUSTOM = 0x00000001u;
    constexpr uint32_t MIXER_SETCONTROLDETAILSF_QUERYMASK = 0x0000000Fu;

    uint32_t result = MMSYSERR_NOERROR;

    const uint32_t mode = (fdwDetails & MIXER_SETCONTROLDETAILSF_QUERYMASK);
    if (mode != MIXER_SETCONTROLDETAILSF_VALUE && mode != MIXER_SETCONTROLDETAILSF_CUSTOM) {
        result = MMSYSERR_INVALFLAG;
    }

    const bool from_handle = (fdwDetails & MIXER_OBJECTF_HANDLE) != 0;
    if (result == MMSYSERR_NOERROR) {
        if (from_handle) {
            if (hmxobj == 0) {
                result = MMSYSERR_INVALHANDLE;
            } else {
                const std::string valid_key = "mixer_valid_" + std::to_string(hmxobj);
                auto it = ctx->global_state.find(valid_key);
                if (it == ctx->global_state.end() || it->second == 0) {
                    result = MMSYSERR_INVALHANDLE;
                }
            }
        } else {
            // Mock environment exposes a single mixer device ID (0).
            if (hmxobj != 0) {
                result = MMSYSERR_BADDEVICEID;
            }
        }
    }

    MIXERCONTROLDETAILS_MOCK details{};
    if (result == MMSYSERR_NOERROR) {
        if (pmxcd == 0 ||
            ctx->backend->mem_read(pmxcd, &details, sizeof(details)) != UC_ERR_OK ||
            details.cbStruct < sizeof(MIXERCONTROLDETAILS_MOCK) ||
            details.cChannels == 0 ||
            details.paDetails == 0 ||
            details.cbDetails < 4) {
            result = MMSYSERR_INVALPARAM;
        }
    }

    if (result == MMSYSERR_NOERROR) {
        uint32_t count = details.cChannels;
        const uint32_t cMultipleItems = details.hwndOwner_or_cMultipleItems;
        if (cMultipleItems > 1) {
            // For multiple-item controls, details are laid out per item per channel.
            count *= cMultipleItems;
        }
        if (count == 0 || count > 256) {
            result = MMSYSERR_INVALPARAM;
        } else {
            uint64_t sum = 0;
            uint32_t first_value = 0;
            for (uint32_t i = 0; i < count; ++i) {
                const uint32_t entry_ptr = details.paDetails + (i * details.cbDetails);
                uint32_t v = 0;
                if (ctx->backend->mem_read(entry_ptr, &v, sizeof(v)) != UC_ERR_OK) {
                    result = MMSYSERR_INVALPARAM;
                    break;
                }
                if (i == 0) first_value = v;
                sum += v;
            }

            if (result == MMSYSERR_NOERROR) {
                const uint32_t avg_value = static_cast<uint32_t>(sum / count);
                const std::string base =
                    "mixer_control_" + std::to_string(details.dwControlID) + "_";

                ctx->global_state[base + "last_value"] = static_cast<uint64_t>(first_value);
                ctx->global_state[base + "avg_value"] = static_cast<uint64_t>(avg_value);
                ctx->global_state[base + "channels"] = static_cast<uint64_t>(details.cChannels);
                ctx->global_state[base + "multiple_items"] = static_cast<uint64_t>(cMultipleItems);
                ctx->global_state[base + "cb_details"] = static_cast<uint64_t>(details.cbDetails);
                ctx->global_state[base + "last_flags"] = static_cast<uint64_t>(fdwDetails);
                ctx->global_state["mixer_last_control_id"] = static_cast<uint64_t>(details.dwControlID);
                ctx->global_state["mixer_last_hmxobj"] = static_cast<uint64_t>(hmxobj);

                ctx->handle_map["mixer_control_" + std::to_string(details.dwControlID)] =
                    reinterpret_cast<void*>(static_cast<uintptr_t>(details.paDetails));
            }
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 12 + 4;
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
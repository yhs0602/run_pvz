#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_CreateEventA(APIContext* ctx) {
    const uint32_t lpEventAttributes = ctx->get_arg(0);
    const uint32_t bManualReset = ctx->get_arg(1);
    const uint32_t bInitialState = ctx->get_arg(2);
    const uint32_t lpName = ctx->get_arg(3);

    (void)lpEventAttributes;

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t ERROR_ALREADY_EXISTS = 183;

    uint32_t result = 0;
    uint32_t last_error = ERROR_SUCCESS;

    std::string event_name;
    bool name_read_ok = true;

    if (lpName != 0) {
        event_name.reserve(260);
        for (uint32_t i = 0; i < 260; ++i) {
            char ch = 0;
            if (uc_mem_read(ctx->uc, lpName + i, &ch, 1) != UC_ERR_OK) {
                name_read_ok = false;
                break;
            }
            if (ch == '\0') {
                break;
            }
            event_name.push_back(ch);
        }
    }

    if (!name_read_ok) {
        last_error = ERROR_INVALID_PARAMETER;
        result = 0;
    } else {
        bool reused_existing = false;

        if (!event_name.empty()) {
            const std::string name_key = "CreateEventA_name_" + event_name;
            auto it = ctx->global_state.find(name_key);
            if (it != ctx->global_state.end() && it->second != 0) {
                result = static_cast<uint32_t>(it->second);
                reused_existing = true;
                last_error = ERROR_ALREADY_EXISTS;
            }
        }

        if (!reused_existing) {
            uint32_t handle = 0x9000;
            auto it = ctx->global_state.find("CreateEventA_next_handle");
            if (it != ctx->global_state.end()) {
                handle = static_cast<uint32_t>(it->second);
            }
            if (handle == 0 || handle == 0xFFFFFFFFu) {
                handle = 0x9000;
            }

            ctx->global_state["CreateEventA_next_handle"] = static_cast<uint64_t>(handle + 4);
            ctx->global_state["CreateEventA_event_" + std::to_string(handle) + "_manual"] =
                static_cast<uint64_t>(bManualReset ? 1u : 0u);
            ctx->global_state["CreateEventA_event_" + std::to_string(handle) + "_state"] =
                static_cast<uint64_t>(bInitialState ? 1u : 0u);

            if (!event_name.empty()) {
                ctx->global_state["CreateEventA_name_" + event_name] = static_cast<uint64_t>(handle);
            }

            ctx->handle_map["event_" + std::to_string(handle)] =
                reinterpret_cast<void*>(static_cast<uintptr_t>(handle));

            result = handle;
            last_error = ERROR_SUCCESS;
        }
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 16 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
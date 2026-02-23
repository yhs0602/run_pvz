#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_CreateMutexA(APIContext* ctx) {
    const uint32_t lpMutexAttributes = ctx->get_arg(0);
    const uint32_t bInitialOwner = ctx->get_arg(1);
    const uint32_t lpName = ctx->get_arg(2);

    (void)lpMutexAttributes;

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t ERROR_ALREADY_EXISTS = 183;

    uint32_t result = 0;
    uint32_t last_error = ERROR_SUCCESS;

    std::string mutex_name;
    bool name_read_ok = true;

    if (lpName != 0) {
        mutex_name.reserve(260);
        for (uint32_t i = 0; i < 260; ++i) {
            char ch = 0;
            if (ctx->backend->mem_read(lpName + i, &ch, 1) != UC_ERR_OK) {
                name_read_ok = false;
                break;
            }
            if (ch == '\0') {
                break;
            }
            mutex_name.push_back(ch);
        }
    }

    if (!name_read_ok) {
        result = 0;
        last_error = ERROR_INVALID_PARAMETER;
    } else {
        bool reused_existing = false;

        if (!mutex_name.empty()) {
            const std::string name_key = "CreateMutexA_name_" + mutex_name;
            auto it = ctx->global_state.find(name_key);
            if (it != ctx->global_state.end() && it->second != 0) {
                result = static_cast<uint32_t>(it->second);
                reused_existing = true;
                last_error = ERROR_ALREADY_EXISTS;
            }
        }

        if (!reused_existing) {
            uint32_t handle = 0x9400;
            auto it = ctx->global_state.find("CreateMutexA_next_handle");
            if (it != ctx->global_state.end()) {
                handle = static_cast<uint32_t>(it->second);
            }
            if (handle == 0 || handle == 0xFFFFFFFFu) {
                handle = 0x9400;
            }

            ctx->global_state["CreateMutexA_next_handle"] = static_cast<uint64_t>(handle + 4);
            ctx->global_state["CreateMutexA_mutex_" + std::to_string(handle) + "_owned"] =
                static_cast<uint64_t>(bInitialOwner ? 1u : 0u);
            ctx->global_state["CreateMutexA_mutex_" + std::to_string(handle) + "_recursion"] =
                static_cast<uint64_t>(bInitialOwner ? 1u : 0u);
            ctx->global_state["CreateMutexA_mutex_" + std::to_string(handle) + "_abandoned"] = 0u;

            if (!mutex_name.empty()) {
                ctx->global_state["CreateMutexA_name_" + mutex_name] = static_cast<uint64_t>(handle);
            }

            ctx->handle_map["mutex_" + std::to_string(handle)] =
                reinterpret_cast<void*>(static_cast<uintptr_t>(handle));

            result = handle;
            last_error = ERROR_SUCCESS;
        }
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 12 + 4;
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
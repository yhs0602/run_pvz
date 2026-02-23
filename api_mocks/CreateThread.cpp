#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_CreateThread(APIContext* ctx) {
    const uint32_t lpThreadAttributes = ctx->get_arg(0);
    const uint32_t dwStackSize = ctx->get_arg(1);
    const uint32_t lpStartAddress = ctx->get_arg(2);
    const uint32_t lpParameter = ctx->get_arg(3);
    const uint32_t dwCreationFlags = ctx->get_arg(4);
    const uint32_t lpThreadId = ctx->get_arg(5);

    (void)lpThreadAttributes;
    (void)dwStackSize;
    (void)lpParameter;
    (void)dwCreationFlags;

    uint32_t result = 0;

    if (lpStartAddress == 0) {
        ctx->global_state["LastError"] = 87; // ERROR_INVALID_PARAMETER
    } else {
        uint32_t handle = 0x8000;
        auto hit = ctx->global_state.find("ThreadHandleTop");
        if (hit != ctx->global_state.end()) {
            handle = static_cast<uint32_t>(hit->second);
        }
        ctx->global_state["ThreadHandleTop"] = static_cast<uint64_t>(handle + 4);

        uint32_t tid = 1;
        auto tit = ctx->global_state.find("ThreadIdTop");
        if (tit != ctx->global_state.end()) {
            tid = static_cast<uint32_t>(tit->second);
        }
        ctx->global_state["ThreadIdTop"] = static_cast<uint64_t>(tid + 1);

        if (lpThreadId != 0) {
            uc_mem_write(ctx->uc, lpThreadId, &tid, 4);
        }

        ctx->handle_map["thread_" + std::to_string(handle)] =
            reinterpret_cast<void*>(static_cast<uintptr_t>(lpStartAddress));

        result = handle;
        ctx->global_state["LastError"] = 0;
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 24 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
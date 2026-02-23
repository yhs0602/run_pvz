#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_Direct3DCreate8(APIContext* ctx) {
    const uint32_t sdk_version = ctx->get_arg(0);

    constexpr uint32_t D3D_SDK_VERSION = 220;
    constexpr uint32_t E_INVALIDARG = 87u; // Win32 ERROR_INVALID_PARAMETER

    uint32_t d3d8_obj = 0;
    if (sdk_version == D3D_SDK_VERSION) {
        d3d8_obj = 0x62000000;
        auto it = ctx->global_state.find("Direct3DCreate8_next_obj");
        if (it != ctx->global_state.end()) {
            d3d8_obj = static_cast<uint32_t>(it->second);
        }
        if (d3d8_obj == 0 || d3d8_obj == 0xFFFFFFFFu) {
            d3d8_obj = 0x62000000;
        }

        ctx->global_state["Direct3DCreate8_next_obj"] = static_cast<uint64_t>(d3d8_obj + 0x100);
        ctx->global_state["Direct3DCreate8_last_sdk_version"] = static_cast<uint64_t>(sdk_version);
        ctx->global_state["LastError"] = 0u;
        ctx->handle_map["d3d8_" + std::to_string(d3d8_obj)] =
            reinterpret_cast<void*>(static_cast<uintptr_t>(d3d8_obj));
    } else {
        // Real API returns NULL for invalid SDK version.
        d3d8_obj = 0;
        ctx->global_state["Direct3DCreate8_last_sdk_version"] = static_cast<uint64_t>(sdk_version);
        ctx->global_state["LastError"] = E_INVALIDARG;
    }

    ctx->set_eax(d3d8_obj);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 4 + 4; // 1 argument (4 bytes) + return address (4 bytes)
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
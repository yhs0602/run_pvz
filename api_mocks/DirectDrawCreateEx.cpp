#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_DirectDrawCreateEx(APIContext* ctx) {
    const uint32_t lpGuid = ctx->get_arg(0);
    const uint32_t lplpDD = ctx->get_arg(1);
    const uint32_t iid = ctx->get_arg(2);
    const uint32_t pUnkOuter = ctx->get_arg(3);

    constexpr uint32_t DD_OK = 0x00000000;
    constexpr uint32_t E_POINTER = 0x80004003;
    constexpr uint32_t E_INVALIDARG = 0x80070057;
    constexpr uint32_t CLASS_E_NOAGGREGATION = 0x80040110;

    uint32_t hr = DD_OK;

    if (lplpDD == 0) {
        hr = E_POINTER;
    } else if (iid == 0) {
        hr = E_INVALIDARG;
    } else if (pUnkOuter != 0) {
        hr = CLASS_E_NOAGGREGATION;
    } else {
        uint32_t ddraw_obj = 0x60000000;
        auto it = ctx->global_state.find("DirectDrawCreateEx_next_obj");
        if (it != ctx->global_state.end()) {
            ddraw_obj = static_cast<uint32_t>(it->second);
        }
        if (ddraw_obj == 0 || ddraw_obj == 0xFFFFFFFFu) {
            ddraw_obj = 0x60000000;
        }

        ctx->global_state["DirectDrawCreateEx_next_obj"] = static_cast<uint64_t>(ddraw_obj + 0x100);
        ctx->global_state["DirectDrawCreateEx_last_guid"] = static_cast<uint64_t>(lpGuid);
        ctx->global_state["DirectDrawCreateEx_last_iid"] = static_cast<uint64_t>(iid);
        ctx->handle_map["ddraw_" + std::to_string(ddraw_obj)] =
            reinterpret_cast<void*>(static_cast<uintptr_t>(ddraw_obj));

        if (uc_mem_write(ctx->uc, lplpDD, &ddraw_obj, 4) != UC_ERR_OK) {
            hr = E_INVALIDARG;
        } else {
            hr = DD_OK;
        }
    }

    ctx->global_state["LastError"] = (hr == DD_OK) ? 0u : 87u;
    ctx->set_eax(hr);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 16 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
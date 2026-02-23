#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_OpenFileMappingA(APIContext* ctx) {
    const uint32_t dwDesiredAccess = ctx->get_arg(0);
    const uint32_t bInheritHandle = ctx->get_arg(1);
    const uint32_t lpName = ctx->get_arg(2);

    (void)dwDesiredAccess;
    (void)bInheritHandle;

    uint32_t result = 0;
    uint32_t last_error = 0;

    std::string mapping_name;
    if (lpName != 0) {
        mapping_name.reserve(64);
        for (uint32_t i = 0; i < 260; ++i) {
            char ch = 0;
            if (uc_mem_read(ctx->uc, lpName + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
                break;
            }
            mapping_name.push_back(ch);
        }
    }

    if (lpName == 0 || mapping_name.empty()) {
        last_error = 87; // ERROR_INVALID_PARAMETER
    } else {
        const std::string key_from_create = "filemap_name_a_" + mapping_name;
        auto it = ctx->global_state.find(key_from_create);
        if (it != ctx->global_state.end()) {
            result = static_cast<uint32_t>(it->second);
        } else {
            const std::string legacy_key = "OpenFileMap:" + mapping_name;
            auto legacy_it = ctx->global_state.find(legacy_key);
            if (legacy_it != ctx->global_state.end()) {
                result = static_cast<uint32_t>(legacy_it->second);
            } else {
                last_error = 2; // ERROR_FILE_NOT_FOUND
            }
        }
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 12 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
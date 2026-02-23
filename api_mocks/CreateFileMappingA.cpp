#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_CreateFileMappingA(APIContext* ctx) {
    const uint32_t hFile = ctx->get_arg(0);
    const uint32_t lpFileMappingAttributes = ctx->get_arg(1);
    const uint32_t flProtect = ctx->get_arg(2);
    const uint32_t dwMaximumSizeHigh = ctx->get_arg(3);
    const uint32_t dwMaximumSizeLow = ctx->get_arg(4);
    const uint32_t lpName = ctx->get_arg(5);

    (void)lpFileMappingAttributes;

    uint32_t result = 0;
    uint32_t last_error = 0;

    const uint64_t max_size =
        (static_cast<uint64_t>(dwMaximumSizeHigh) << 32) | static_cast<uint64_t>(dwMaximumSizeLow);

    if (flProtect == 0) {
        last_error = 87; // ERROR_INVALID_PARAMETER
    } else if (hFile == 0xFFFFFFFFu && max_size == 0) {
        last_error = 87; // ERROR_INVALID_PARAMETER
    } else if (hFile != 0xFFFFFFFFu) {
        const std::string file_key = "file_" + std::to_string(hFile);
        if (ctx->handle_map.find(file_key) == ctx->handle_map.end()) {
            last_error = 6; // ERROR_INVALID_HANDLE
        }
    }

    std::string mapping_name;
    if (lpName != 0) {
        mapping_name.reserve(64);
        for (uint32_t i = 0; i < 260; ++i) {
            char ch = 0;
            if (ctx->backend->mem_read(lpName + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
                break;
            }
            mapping_name.push_back(ch);
        }
    }

    if (last_error == 0 && !mapping_name.empty()) {
        const std::string name_key = "filemap_name_a_" + mapping_name;
        auto existing = ctx->global_state.find(name_key);
        if (existing != ctx->global_state.end()) {
            result = static_cast<uint32_t>(existing->second);
            last_error = 183; // ERROR_ALREADY_EXISTS
        }
    }

    if (last_error == 0 && result == 0) {
        uint32_t handle = 0x9000;
        auto it = ctx->global_state.find("MappingHandleTop");
        if (it != ctx->global_state.end()) {
            handle = static_cast<uint32_t>(it->second);
        }
        ctx->global_state["MappingHandleTop"] = static_cast<uint64_t>(handle + 4);

        uint64_t* meta = new uint64_t[3];
        meta[0] = static_cast<uint64_t>(hFile);
        meta[1] = max_size;
        meta[2] = static_cast<uint64_t>(flProtect);

        ctx->handle_map["mapping_" + std::to_string(handle)] = meta;

        if (!mapping_name.empty()) {
            ctx->global_state["filemap_name_a_" + mapping_name] = static_cast<uint64_t>(handle);
        }

        result = handle;
        last_error = 0;
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 24 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
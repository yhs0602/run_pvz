#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_FindFirstFileA(APIContext* ctx) {
    const uint32_t lpFileName = ctx->get_arg(0);
    const uint32_t lpFindFileData = ctx->get_arg(1);

    constexpr uint32_t INVALID_HANDLE_VALUE = 0xFFFFFFFFu;
    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_FILE_NOT_FOUND = 2;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t FILE_ATTRIBUTE_NORMAL = 0x80;
    constexpr uint32_t C_FILE_NAME_OFFSET = 44;

    uint32_t result = INVALID_HANDLE_VALUE;

    if (lpFileName == 0 || lpFindFileData == 0) {
        ctx->global_state["LastError"] = ERROR_INVALID_PARAMETER;
    } else {
        std::string pattern;
        pattern.reserve(260);

        for (uint32_t i = 0; i < 260; ++i) {
            char ch = 0;
            if (ctx->backend->mem_read(lpFileName + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
                break;
            }
            pattern.push_back(ch);
        }

        if (pattern.empty()) {
            ctx->global_state["LastError"] = ERROR_FILE_NOT_FOUND;
        } else {
            uint32_t handle = 0x7000;
            auto it = ctx->global_state.find("FindHandleTop");
            if (it != ctx->global_state.end()) {
                handle = static_cast<uint32_t>(it->second);
            }
            if (handle == 0 || handle == INVALID_HANDLE_VALUE) {
                handle = 0x7000;
            }
            ctx->global_state["FindHandleTop"] = static_cast<uint64_t>(handle + 4);

            std::string file_name = pattern;
            const size_t slash = file_name.find_last_of("\\/");
            if (slash != std::string::npos) {
                file_name = file_name.substr(slash + 1);
            }
            if (file_name.empty()) {
                file_name = "mock_file.dat";
            }
            if (file_name.find('*') != std::string::npos || file_name.find('?') != std::string::npos) {
                file_name = "mock_file.dat";
            }

            uint8_t zero[320] = {};
            ctx->backend->mem_write(lpFindFileData, zero, sizeof(zero));

            uint32_t attrs = FILE_ATTRIBUTE_NORMAL;
            ctx->backend->mem_write(lpFindFileData, &attrs, sizeof(attrs));

            size_t write_len = file_name.size();
            if (write_len > 259) {
                write_len = 259;
            }
            if (write_len > 0) {
                ctx->backend->mem_write(lpFindFileData + C_FILE_NAME_OFFSET, file_name.data(), write_len);
            }
            uint8_t nul = 0;
            ctx->backend->mem_write(lpFindFileData + C_FILE_NAME_OFFSET + static_cast<uint32_t>(write_len), &nul, 1);

            ctx->handle_map["find_" + std::to_string(handle)] =
                reinterpret_cast<void*>(static_cast<uintptr_t>(handle));

            result = handle;
            ctx->global_state["LastError"] = ERROR_SUCCESS;
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
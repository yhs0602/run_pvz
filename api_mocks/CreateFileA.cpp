#include "api_context.hpp"

#include <cctype>
#include <cstdint>
#include <string>

extern "C" void mock_CreateFileA(APIContext* ctx) {
    const uint32_t lpFileName = ctx->get_arg(0);
    const uint32_t dwDesiredAccess = ctx->get_arg(1);
    const uint32_t dwShareMode = ctx->get_arg(2);
    const uint32_t lpSecurityAttributes = ctx->get_arg(3);
    const uint32_t dwCreationDisposition = ctx->get_arg(4);
    const uint32_t dwFlagsAndAttributes = ctx->get_arg(5);
    const uint32_t hTemplateFile = ctx->get_arg(6);

    (void)lpSecurityAttributes;

    constexpr uint32_t INVALID_HANDLE_VALUE = 0xFFFFFFFFu;
    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_FILE_NOT_FOUND = 2u;
    constexpr uint32_t ERROR_INVALID_HANDLE = 6u;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87u;
    constexpr uint32_t ERROR_ALREADY_EXISTS = 183u;
    constexpr uint32_t ERROR_FILE_EXISTS = 80u;

    constexpr uint32_t CREATE_NEW = 1u;
    constexpr uint32_t CREATE_ALWAYS = 2u;
    constexpr uint32_t OPEN_EXISTING = 3u;
    constexpr uint32_t OPEN_ALWAYS = 4u;
    constexpr uint32_t TRUNCATE_EXISTING = 5u;

    auto read_guest_string = [&](uint32_t ptr) -> std::string {
        if (ptr == 0) return {};
        std::string out;
        out.reserve(260);
        for (uint32_t i = 0; i < 260; ++i) {
            char ch = 0;
            if (ctx->backend->mem_read(ptr + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
                break;
            }
            out.push_back(ch);
        }
        return out;
    };

    auto to_lower_ascii = [](std::string s) -> std::string {
        for (char& c : s) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return s;
    };

    uint32_t result = INVALID_HANDLE_VALUE;
    uint32_t last_error = ERROR_SUCCESS;

    const std::string path = read_guest_string(lpFileName);
    const std::string path_key = "file_path_a_" + to_lower_ascii(path);
    const bool exists = (ctx->global_state.find(path_key) != ctx->global_state.end());

    bool ok = true;
    if (lpFileName == 0 || path.empty()) {
        ok = false;
        last_error = ERROR_INVALID_PARAMETER;
    } else if (dwCreationDisposition < CREATE_NEW || dwCreationDisposition > TRUNCATE_EXISTING) {
        ok = false;
        last_error = ERROR_INVALID_PARAMETER;
    } else if (hTemplateFile != 0 && hTemplateFile != INVALID_HANDLE_VALUE &&
               ctx->handle_map.find("file_" + std::to_string(hTemplateFile)) == ctx->handle_map.end()) {
        ok = false;
        last_error = ERROR_INVALID_HANDLE;
    }

    if (ok) {
        switch (dwCreationDisposition) {
            case CREATE_NEW:
                if (exists) {
                    ok = false;
                    last_error = ERROR_FILE_EXISTS;
                }
                break;
            case CREATE_ALWAYS:
                last_error = exists ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS;
                break;
            case OPEN_EXISTING:
                if (!exists) {
                    ok = false;
                    last_error = ERROR_FILE_NOT_FOUND;
                }
                break;
            case OPEN_ALWAYS:
                last_error = exists ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS;
                break;
            case TRUNCATE_EXISTING:
                if (!exists) {
                    ok = false;
                    last_error = ERROR_FILE_NOT_FOUND;
                }
                break;
            default:
                ok = false;
                last_error = ERROR_INVALID_PARAMETER;
                break;
        }
    }

    if (ok) {
        uint32_t handle = 0xA000u;
        auto it = ctx->global_state.find("FileHandleTop");
        if (it != ctx->global_state.end()) {
            handle = static_cast<uint32_t>(it->second);
        }
        if (handle == 0 || handle == INVALID_HANDLE_VALUE) {
            handle = 0xA000u;
        }
        ctx->global_state["FileHandleTop"] = static_cast<uint64_t>(handle + 4u);

        ctx->global_state[path_key] = 1u;
        ctx->global_state["CreateFileA_LastHandle"] = static_cast<uint64_t>(handle);
        ctx->global_state["file_access_" + std::to_string(handle)] = static_cast<uint64_t>(dwDesiredAccess);
        ctx->global_state["file_share_" + std::to_string(handle)] = static_cast<uint64_t>(dwShareMode);
        ctx->global_state["file_disposition_" + std::to_string(handle)] = static_cast<uint64_t>(dwCreationDisposition);
        ctx->global_state["file_flags_" + std::to_string(handle)] = static_cast<uint64_t>(dwFlagsAndAttributes);
        ctx->global_state["file_template_" + std::to_string(handle)] = static_cast<uint64_t>(hTemplateFile);

        ctx->handle_map["file_" + std::to_string(handle)] = new std::string(path);
        result = handle;
    }

    ctx->global_state["LastError"] = static_cast<uint64_t>(last_error);
    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 28 + 4;
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
#include "api_context.hpp"

#include <cctype>
#include <cstdint>
#include <string>

extern "C" void mock_RegCreateKeyExA(APIContext* ctx) {
    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_INVALID_HANDLE = 6u;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87u;

    constexpr uint32_t REG_CREATED_NEW_KEY = 1u;
    constexpr uint32_t REG_OPENED_EXISTING_KEY = 2u;

    constexpr uint32_t HKEY_CLASSES_ROOT = 0x80000000u;
    constexpr uint32_t HKEY_CURRENT_USER = 0x80000001u;
    constexpr uint32_t HKEY_LOCAL_MACHINE = 0x80000002u;
    constexpr uint32_t HKEY_USERS = 0x80000003u;
    constexpr uint32_t HKEY_CURRENT_CONFIG = 0x80000005u;

    const uint32_t hKey = ctx->get_arg(0);
    const uint32_t lpSubKey = ctx->get_arg(1);
    const uint32_t Reserved = ctx->get_arg(2);
    const uint32_t lpClass = ctx->get_arg(3);
    const uint32_t dwOptions = ctx->get_arg(4);
    const uint32_t samDesired = ctx->get_arg(5);
    const uint32_t lpSecurityAttributes = ctx->get_arg(6);
    const uint32_t phkResult = ctx->get_arg(7);
    const uint32_t lpdwDisposition = ctx->get_arg(8);

    (void)Reserved;
    (void)lpClass;
    (void)dwOptions;
    (void)lpSecurityAttributes;

    auto normalize = [](std::string s) -> std::string {
        for (char& c : s) {
            if (c == '/') c = '\\';
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        while (!s.empty() && s.front() == '\\') s.erase(s.begin());
        while (!s.empty() && s.back() == '\\') s.pop_back();
        return s;
    };

    auto read_guest_ansi = [&](uint32_t ptr, std::string& out) -> bool {
        out.clear();
        if (ptr == 0) return true;
        out.reserve(128);
        for (uint32_t i = 0; i < 1024; ++i) {
            char ch = 0;
            if (ctx->backend->mem_read(ptr + i, &ch, 1) != UC_ERR_OK) {
                return false;
            }
            if (ch == '\0') return true;
            out.push_back(ch);
        }
        return true;
    };

    uint32_t result = ERROR_SUCCESS;
    uint32_t disposition = REG_OPENED_EXISTING_KEY;
    uint32_t out_handle = 0;

    std::string base_path;
    if (phkResult == 0) {
        result = ERROR_INVALID_PARAMETER;
    } else {
        switch (hKey) {
            case HKEY_CLASSES_ROOT:   base_path = "hkcr"; break;
            case HKEY_CURRENT_USER:   base_path = "hkcu"; break;
            case HKEY_LOCAL_MACHINE:  base_path = "hklm"; break;
            case HKEY_USERS:          base_path = "hku";  break;
            case HKEY_CURRENT_CONFIG: base_path = "hkcc"; break;
            default: {
                const std::string valid_key = "reg_handle_valid_" + std::to_string(hKey);
                auto valid_it = ctx->global_state.find(valid_key);
                if (valid_it == ctx->global_state.end() || valid_it->second == 0) {
                    result = ERROR_INVALID_HANDLE;
                    break;
                }

                const std::string handle_path_key = "reg_handle_path_" + std::to_string(hKey);
                auto path_it = ctx->handle_map.find(handle_path_key);
                if (path_it != ctx->handle_map.end() && path_it->second != nullptr) {
                    base_path = *reinterpret_cast<std::string*>(path_it->second);
                } else {
                    base_path = "hk_custom_" + std::to_string(hKey);
                }
                break;
            }
        }
    }

    std::string sub_key;
    if (result == ERROR_SUCCESS) {
        if (!read_guest_ansi(lpSubKey, sub_key)) {
            result = ERROR_INVALID_PARAMETER;
        } else {
            sub_key = normalize(sub_key);
        }
    }

    std::string full_path;
    if (result == ERROR_SUCCESS) {
        full_path = base_path;
        if (!sub_key.empty()) {
            full_path += "\\";
            full_path += sub_key;
        }

        const std::string path_key = "reg_path_" + full_path;
        const std::string exists_key = "reg_existing_" + full_path;

        auto existing = ctx->global_state.find(path_key);
        if (existing != ctx->global_state.end() && existing->second != 0) {
            out_handle = static_cast<uint32_t>(existing->second);
            disposition = REG_OPENED_EXISTING_KEY;
        } else {
            uint32_t next_handle = 0xA000u;
            auto top_it = ctx->global_state.find("RegHandleTop");
            if (top_it != ctx->global_state.end()) {
                next_handle = static_cast<uint32_t>(top_it->second);
            }
            if (next_handle == 0 || next_handle == 0xFFFFFFFFu) {
                next_handle = 0xA000u;
            }

            out_handle = next_handle;
            ctx->global_state["RegHandleTop"] = static_cast<uint64_t>(next_handle + 4u);
            ctx->global_state[path_key] = static_cast<uint64_t>(out_handle);
            ctx->global_state[exists_key] = 1u;
            disposition = REG_CREATED_NEW_KEY;
        }

        ctx->global_state["reg_handle_valid_" + std::to_string(out_handle)] = 1u;
        ctx->global_state["reg_sam_" + std::to_string(out_handle)] = static_cast<uint64_t>(samDesired);
        ctx->global_state["reg_options_" + std::to_string(out_handle)] = static_cast<uint64_t>(dwOptions);

        const std::string handle_path_key = "reg_handle_path_" + std::to_string(out_handle);
        auto hm_it = ctx->handle_map.find(handle_path_key);
        if (hm_it == ctx->handle_map.end() || hm_it->second == nullptr) {
            ctx->handle_map[handle_path_key] = new std::string(full_path);
        } else {
            *reinterpret_cast<std::string*>(hm_it->second) = full_path;
        }

        if (ctx->backend->mem_write(phkResult, &out_handle, sizeof(out_handle)) != UC_ERR_OK) {
            result = ERROR_INVALID_PARAMETER;
        } else if (lpdwDisposition != 0 &&
                   ctx->backend->mem_write(lpdwDisposition, &disposition, sizeof(disposition)) != UC_ERR_OK) {
            result = ERROR_INVALID_PARAMETER;
        }
    }

    ctx->global_state["LastError"] = static_cast<uint64_t>(result);
    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    constexpr uint32_t ARGS_BYTES = 9u * 4u;
    esp += ARGS_BYTES + 4;
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
#include "api_context.hpp"

#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>

extern "C" void mock_RegOpenKeyExA(APIContext* ctx) {
    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_FILE_NOT_FOUND = 2;
    constexpr uint32_t ERROR_INVALID_HANDLE = 6;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;

    constexpr uint32_t HKEY_CLASSES_ROOT = 0x80000000u;
    constexpr uint32_t HKEY_CURRENT_USER = 0x80000001u;
    constexpr uint32_t HKEY_LOCAL_MACHINE = 0x80000002u;
    constexpr uint32_t HKEY_USERS = 0x80000003u;
    constexpr uint32_t HKEY_CURRENT_CONFIG = 0x80000005u;

    const uint32_t hKey = ctx->get_arg(0);
    const uint32_t lpSubKey = ctx->get_arg(1);
    const uint32_t ulOptions = ctx->get_arg(2);
    const uint32_t samDesired = ctx->get_arg(3);
    const uint32_t phkResult = ctx->get_arg(4);

    (void)samDesired;

    auto normalize = [](std::string s) -> std::string {
        for (char& c : s) {
            if (c == '/') c = '\\';
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        while (!s.empty() && s.front() == '\\') s.erase(s.begin());
        while (!s.empty() && s.back() == '\\') s.pop_back();
        return s;
    };

    auto has_prefix = [](const std::string& s, const char* prefix) -> bool {
        const size_t n = std::strlen(prefix);
        return s.size() >= n && s.compare(0, n, prefix) == 0;
    };

    auto is_builtin_existing_key = [&](const std::string& full_path) -> bool {
        if (full_path == "hkcr" || full_path == "hkcu" || full_path == "hklm" ||
            full_path == "hku" || full_path == "hkcc") {
            return true;
        }
        if (has_prefix(full_path, "hkcu\\software")) return true;
        if (has_prefix(full_path, "hklm\\software")) return true;
        if (has_prefix(full_path, "hkcr\\")) return true;
        if (has_prefix(full_path, "hku\\.default")) return true;
        if (full_path == "hkcu\\software\\popcap" ||
            full_path == "hkcu\\software\\popcap\\plantsvszombies") {
            return true;
        }
        return false;
    };

    uint32_t result = ERROR_SUCCESS;
    std::string base_path;

    if (phkResult == 0) {
        result = ERROR_INVALID_PARAMETER;
    } else if (ulOptions != 0) {
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
                if (ctx->global_state.find(valid_key) == ctx->global_state.end()) {
                    result = ERROR_INVALID_HANDLE;
                } else {
                    const std::string handle_path_key = "reg_handle_path_" + std::to_string(hKey);
                    auto it = ctx->handle_map.find(handle_path_key);
                    if (it != ctx->handle_map.end() && it->second != nullptr) {
                        base_path = *reinterpret_cast<std::string*>(it->second);
                    } else {
                        base_path = "hk_custom_" + std::to_string(hKey);
                    }
                }
                break;
            }
        }
    }

    std::string sub_key;
    if (result == ERROR_SUCCESS && lpSubKey != 0) {
        sub_key.reserve(128);
        for (uint32_t i = 0; i < 1024; ++i) {
            char ch = 0;
            if (ctx->backend->mem_read(lpSubKey + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
                break;
            }
            sub_key.push_back(ch);
        }
    }

    if (result == ERROR_SUCCESS) {
        sub_key = normalize(sub_key);

        std::string full_path = base_path;
        if (!sub_key.empty()) {
            full_path += "\\";
            full_path += sub_key;
        }

        const std::string path_key = "reg_path_" + full_path;
        const std::string explicit_exists_key = "reg_existing_" + full_path;

        bool exists = false;
        if (ctx->global_state.find(path_key) != ctx->global_state.end()) {
            exists = true;
        }
        if (!exists) {
            auto ex = ctx->global_state.find(explicit_exists_key);
            if (ex != ctx->global_state.end() && ex->second != 0) {
                exists = true;
            }
        }
        if (!exists && is_builtin_existing_key(full_path)) {
            exists = true;
        }

        if (!exists) {
            result = ERROR_FILE_NOT_FOUND;
            uint32_t zero_handle = 0;
            ctx->backend->mem_write(phkResult, &zero_handle, sizeof(zero_handle));
        } else {
            uint32_t out_handle = 0;

            auto existing = ctx->global_state.find(path_key);
            if (existing != ctx->global_state.end()) {
                out_handle = static_cast<uint32_t>(existing->second);
            } else {
                uint32_t next_handle = 0xA000u;
                auto top_it = ctx->global_state.find("RegHandleTop");
                if (top_it != ctx->global_state.end()) {
                    next_handle = static_cast<uint32_t>(top_it->second);
                }
                ctx->global_state["RegHandleTop"] = static_cast<uint64_t>(next_handle + 4u);

                out_handle = next_handle;
                ctx->global_state[path_key] = static_cast<uint64_t>(out_handle);
                ctx->global_state["reg_handle_valid_" + std::to_string(out_handle)] = 1u;

                auto* stored_path = new std::string(full_path);
                ctx->handle_map["reg_handle_path_" + std::to_string(out_handle)] = stored_path;
            }

            if (ctx->backend->mem_write(phkResult, &out_handle, sizeof(out_handle)) != UC_ERR_OK) {
                result = ERROR_INVALID_PARAMETER;
            }
        }
    }

    ctx->global_state["LastError"] = result;
    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 20 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
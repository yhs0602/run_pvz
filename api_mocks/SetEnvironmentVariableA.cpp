#include "api_context.hpp"

#include <cctype>
#include <cstdint>
#include <new>
#include <string>

extern "C" void mock_SetEnvironmentVariableA(APIContext* ctx) {
    const uint32_t lpName = ctx->get_arg(0);
    const uint32_t lpValue = ctx->get_arg(1);

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t ERROR_NOT_ENOUGH_MEMORY = 8;

    auto read_ansi = [&](uint32_t ptr, std::string& out) -> bool {
        out.clear();
        if (ptr == 0) {
            return false;
        }
        out.reserve(64);
        for (uint32_t i = 0; i < 32767; ++i) {
            char ch = 0;
            if (ctx->backend->mem_read(ptr + i, &ch, 1) != UC_ERR_OK) {
                return false;
            }
            if (ch == '\0') {
                return true;
            }
            out.push_back(ch);
        }
        return false;
    };

    auto canonical_env_name = [](std::string s) -> std::string {
        for (char& ch : s) {
            ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        }
        return s;
    };

    uint32_t result = 0;
    uint32_t last_error = ERROR_SUCCESS;

    std::string name;
    if (!read_ansi(lpName, name) || name.empty() || name.find('=') != std::string::npos) {
        last_error = ERROR_INVALID_PARAMETER;
    } else {
        const std::string key = "envvara:" + canonical_env_name(name);

        if (lpValue == 0) {
            auto it = ctx->handle_map.find(key);
            if (it != ctx->handle_map.end()) {
                delete static_cast<std::string*>(it->second);
                ctx->handle_map.erase(it);
            }
            result = 1;
        } else {
            std::string value;
            if (!read_ansi(lpValue, value)) {
                last_error = ERROR_INVALID_PARAMETER;
            } else {
                std::string* stored = new (std::nothrow) std::string(value);
                if (stored == nullptr) {
                    last_error = ERROR_NOT_ENOUGH_MEMORY;
                } else {
                    auto it = ctx->handle_map.find(key);
                    if (it != ctx->handle_map.end()) {
                        delete static_cast<std::string*>(it->second);
                    }
                    ctx->handle_map[key] = stored;
                    result = 1;
                }
            }
        }
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
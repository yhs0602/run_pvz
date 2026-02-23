#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_RegisterWindowMessageA(APIContext* ctx) {
    const uint32_t lpString = ctx->get_arg(0);
    uint32_t result = 0;

    if (lpString != 0) {
        std::string message_name;
        message_name.reserve(256);

        bool read_ok = true;
        bool terminated = false;

        for (uint32_t i = 0; i < 1024; ++i) {
            char ch = 0;
            if (uc_mem_read(ctx->uc, lpString + i, &ch, 1) != UC_ERR_OK) {
                read_ok = false;
                break;
            }
            if (ch == '\0') {
                terminated = true;
                break;
            }
            message_name.push_back(ch);
        }

        if (read_ok && terminated && !message_name.empty()) {
            const std::string key = "RegisterWindowMessageA.msg." + message_name;
            const auto it = ctx->global_state.find(key);

            if (it != ctx->global_state.end()) {
                result = static_cast<uint32_t>(it->second);
            } else {
                uint32_t next_msg = 0xC000;
                const auto next_it = ctx->global_state.find("RegisterWindowMessageA.next");
                if (next_it != ctx->global_state.end()) {
                    next_msg = static_cast<uint32_t>(next_it->second);
                }
                if (next_msg < 0xC000 || next_msg > 0xFFFF) {
                    next_msg = 0xC000;
                }

                result = next_msg;
                ctx->global_state[key] = static_cast<uint64_t>(result);

                ++next_msg;
                if (next_msg > 0xFFFF) {
                    next_msg = 0xC000;
                }
                ctx->global_state["RegisterWindowMessageA.next"] = static_cast<uint64_t>(next_msg);
            }

            ctx->global_state["LastError"] = 0;
        } else {
            ctx->global_state["LastError"] = 87;
        }
    } else {
        ctx->global_state["LastError"] = 87;
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
#include "api_context.hpp"

#include <cstdint>
#include <vector>

extern "C" void mock_WideCharToMultiByte(APIContext* ctx) {
    constexpr uint32_t CP_ACP = 0;
    constexpr uint32_t CP_UTF8 = 65001;

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INSUFFICIENT_BUFFER = 122;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t ERROR_NO_UNICODE_TRANSLATION = 1113;

    const uint32_t code_page = ctx->get_arg(0);
    const uint32_t dw_flags = ctx->get_arg(1);
    const uint32_t lp_wide_char_str = ctx->get_arg(2);
    const int32_t cch_wide_char = static_cast<int32_t>(ctx->get_arg(3));
    const uint32_t lp_multi_byte_str = ctx->get_arg(4);
    const int32_t cb_multi_byte = static_cast<int32_t>(ctx->get_arg(5));
    const uint32_t lp_default_char = ctx->get_arg(6);
    const uint32_t lp_used_default_char = ctx->get_arg(7);

    (void)dw_flags;

    auto fail = [&](uint32_t err) {
        ctx->global_state["LastError"] = err;
        ctx->set_eax(0);
    };

    if (lp_wide_char_str == 0 || cch_wide_char == 0 || cch_wide_char < -1 || cb_multi_byte < 0) {
        fail(ERROR_INVALID_PARAMETER);
        uint32_t esp;
        uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
        uint32_t ret_addr;
        uc_mem_read(ctx->uc, esp, &ret_addr, 4);
        esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
        uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
        return;
    }

    if (code_page == CP_UTF8 && (lp_default_char != 0 || lp_used_default_char != 0)) {
        fail(ERROR_INVALID_PARAMETER);
        uint32_t esp;
        uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
        uint32_t ret_addr;
        uc_mem_read(ctx->uc, esp, &ret_addr, 4);
        esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
        uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
        return;
    }

    std::vector<uint16_t> wide;
    wide.reserve(256);

    auto read_u16 = [&](uint32_t addr, uint16_t& out) -> bool {
        return uc_mem_read(ctx->uc, addr, &out, sizeof(out)) == UC_ERR_OK;
    };

    if (cch_wide_char == -1) {
        constexpr uint32_t kMaxScan = 1u << 20;
        for (uint32_t i = 0; i < kMaxScan; ++i) {
            uint16_t w = 0;
            if (!read_u16(lp_wide_char_str + (i * 2), w)) {
                fail(ERROR_INVALID_PARAMETER);
                uint32_t esp;
                uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
                uint32_t ret_addr;
                uc_mem_read(ctx->uc, esp, &ret_addr, 4);
                esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
                uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
                uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
                return;
            }
            wide.push_back(w);
            if (w == 0) break;
        }
        if (wide.empty() || wide.back() != 0) {
            fail(ERROR_NO_UNICODE_TRANSLATION);
            uint32_t esp;
            uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            uc_mem_read(ctx->uc, esp, &ret_addr, 4);
            esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
            uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
            return;
        }
    } else {
        wide.reserve(static_cast<size_t>(cch_wide_char));
        for (int32_t i = 0; i < cch_wide_char; ++i) {
            uint16_t w = 0;
            if (!read_u16(lp_wide_char_str + (static_cast<uint32_t>(i) * 2), w)) {
                fail(ERROR_INVALID_PARAMETER);
                uint32_t esp;
                uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
                uint32_t ret_addr;
                uc_mem_read(ctx->uc, esp, &ret_addr, 4);
                esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
                uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
                uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
                return;
            }
            wide.push_back(w);
        }
    }

    bool used_default = false;
    std::vector<uint8_t> out;
    out.reserve(wide.size() * 3);

    if (code_page == CP_UTF8) {
        auto append_utf8 = [&](uint32_t cp) {
            if (cp <= 0x7F) {
                out.push_back(static_cast<uint8_t>(cp));
            } else if (cp <= 0x7FF) {
                out.push_back(static_cast<uint8_t>(0xC0u | (cp >> 6)));
                out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
            } else if (cp <= 0xFFFF) {
                out.push_back(static_cast<uint8_t>(0xE0u | (cp >> 12)));
                out.push_back(static_cast<uint8_t>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
            } else {
                out.push_back(static_cast<uint8_t>(0xF0u | (cp >> 18)));
                out.push_back(static_cast<uint8_t>(0x80u | ((cp >> 12) & 0x3Fu)));
                out.push_back(static_cast<uint8_t>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
            }
        };

        for (size_t i = 0; i < wide.size(); ++i) {
            uint16_t w1 = wide[i];
            uint32_t cp = 0;

            if (w1 >= 0xD800 && w1 <= 0xDBFF) {
                if ((i + 1) < wide.size()) {
                    uint16_t w2 = wide[i + 1];
                    if (w2 >= 0xDC00 && w2 <= 0xDFFF) {
                        cp = 0x10000u + (((static_cast<uint32_t>(w1) - 0xD800u) << 10)
                                        | (static_cast<uint32_t>(w2) - 0xDC00u));
                        ++i;
                    } else {
                        cp = 0xFFFDu;
                        used_default = true;
                    }
                } else {
                    cp = 0xFFFDu;
                    used_default = true;
                }
            } else if (w1 >= 0xDC00 && w1 <= 0xDFFF) {
                cp = 0xFFFDu;
                used_default = true;
            } else {
                cp = w1;
            }

            append_utf8(cp);
        }
    } else {
        char default_ch = '?';
        if (lp_default_char != 0) {
            char tmp = '?';
            if (uc_mem_read(ctx->uc, lp_default_char, &tmp, 1) == UC_ERR_OK && tmp != '\0') {
                default_ch = tmp;
            }
        }

        for (uint16_t w : wide) {
            if (w <= 0x00FF) {
                out.push_back(static_cast<uint8_t>(w & 0xFF));
            } else {
                out.push_back(static_cast<uint8_t>(default_ch));
                used_default = true;
            }
        }

        if (code_page != CP_ACP && code_page != 1252 && code_page != 1 && code_page != 3) {
            // Keep behavior practical for emulation: unsupported pages fall back to ACP-like conversion.
        }
    }

    const uint32_t required = static_cast<uint32_t>(out.size());

    if (cb_multi_byte == 0) {
        if (lp_used_default_char != 0) {
            uint32_t used = used_default ? 1u : 0u;
            uc_mem_write(ctx->uc, lp_used_default_char, &used, 4);
        }
        ctx->global_state["LastError"] = ERROR_SUCCESS;
        ctx->set_eax(required);

        uint32_t esp;
        uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
        uint32_t ret_addr;
        uc_mem_read(ctx->uc, esp, &ret_addr, 4);
        esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
        uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
        return;
    }

    if (lp_multi_byte_str == 0) {
        fail(ERROR_INVALID_PARAMETER);
        uint32_t esp;
        uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
        uint32_t ret_addr;
        uc_mem_read(ctx->uc, esp, &ret_addr, 4);
        esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
        uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
        return;
    }

    if (static_cast<uint32_t>(cb_multi_byte) < required) {
        fail(ERROR_INSUFFICIENT_BUFFER);
        uint32_t esp;
        uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
        uint32_t ret_addr;
        uc_mem_read(ctx->uc, esp, &ret_addr, 4);
        esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
        uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
        return;
    }

    if (required > 0 && uc_mem_write(ctx->uc, lp_multi_byte_str, out.data(), required) != UC_ERR_OK) {
        fail(ERROR_INVALID_PARAMETER);
        uint32_t esp;
        uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
        uint32_t ret_addr;
        uc_mem_read(ctx->uc, esp, &ret_addr, 4);
        esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
        uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
        return;
    }

    if (lp_used_default_char != 0) {
        uint32_t used = used_default ? 1u : 0u;
        uc_mem_write(ctx->uc, lp_used_default_char, &used, 4);
    }

    ctx->global_state["LastError"] = ERROR_SUCCESS;
    ctx->set_eax(required);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 32 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
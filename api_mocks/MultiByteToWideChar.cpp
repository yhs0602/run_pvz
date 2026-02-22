#include "api_context.hpp"

#include <cstdint>
#include <vector>

extern "C" void mock_MultiByteToWideChar(APIContext* ctx) {
    constexpr uint32_t CP_ACP = 0;
    constexpr uint32_t CP_UTF8 = 65001;
    constexpr uint32_t MB_ERR_INVALID_CHARS = 0x00000008;

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INSUFFICIENT_BUFFER = 122;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t ERROR_NO_UNICODE_TRANSLATION = 1113;

    const uint32_t code_page = ctx->get_arg(0);
    const uint32_t dw_flags = ctx->get_arg(1);
    const uint32_t lp_multi_byte_str = ctx->get_arg(2);
    const int32_t cb_multi_byte = static_cast<int32_t>(ctx->get_arg(3));
    const uint32_t lp_wide_char_str = ctx->get_arg(4);
    const int32_t cch_wide_char = static_cast<int32_t>(ctx->get_arg(5));

    uint32_t last_error = ERROR_SUCCESS;
    uint32_t result = 0;
    bool ok = true;

    auto fail = [&](uint32_t err) {
        last_error = err;
        result = 0;
        ok = false;
    };

    if (lp_multi_byte_str == 0 || cb_multi_byte == 0 || cb_multi_byte < -1 || cch_wide_char < 0) {
        fail(ERROR_INVALID_PARAMETER);
    }

    std::vector<uint8_t> input;
    if (ok) {
        if (cb_multi_byte == -1) {
            constexpr uint32_t kMaxScan = 1u << 20;
            bool found_nul = false;
            for (uint32_t i = 0; i < kMaxScan; ++i) {
                uint8_t b = 0;
                if (uc_mem_read(ctx->uc, lp_multi_byte_str + i, &b, 1) != UC_ERR_OK) {
                    fail(ERROR_INVALID_PARAMETER);
                    break;
                }
                input.push_back(b);
                if (b == 0) {
                    found_nul = true;
                    break;
                }
            }
            if (ok && !found_nul) {
                fail(ERROR_NO_UNICODE_TRANSLATION);
            }
        } else {
            input.resize(static_cast<size_t>(cb_multi_byte));
            if (!input.empty() &&
                uc_mem_read(ctx->uc, lp_multi_byte_str, input.data(), input.size()) != UC_ERR_OK) {
                fail(ERROR_INVALID_PARAMETER);
            }
        }
    }

    uint32_t acp = 1252;
    auto acp_it = ctx->global_state.find("ACP");
    if (acp_it != ctx->global_state.end()) {
        acp = static_cast<uint32_t>(acp_it->second);
    }

    std::vector<uint16_t> wide;
    if (ok) {
        const bool treat_as_utf8 = (code_page == CP_UTF8);
        const bool treat_as_acp =
            (code_page == CP_ACP || code_page == 1252 || code_page == acp || code_page == 1 || code_page == 3);

        if (treat_as_utf8) {
            auto append_cp = [&](uint32_t cp) {
                if (cp <= 0xFFFF) {
                    wide.push_back(static_cast<uint16_t>(cp));
                } else {
                    cp -= 0x10000;
                    wide.push_back(static_cast<uint16_t>(0xD800u + (cp >> 10)));
                    wide.push_back(static_cast<uint16_t>(0xDC00u + (cp & 0x3FFu)));
                }
            };

            size_t i = 0;
            while (i < input.size()) {
                uint8_t b0 = input[i];
                uint32_t cp = 0;
                size_t need = 0;
                bool valid = true;

                if ((b0 & 0x80u) == 0) {
                    cp = b0;
                    need = 1;
                } else if ((b0 & 0xE0u) == 0xC0u) {
                    need = 2;
                    if (i + 1 >= input.size()) {
                        valid = false;
                    } else {
                        uint8_t b1 = input[i + 1];
                        if ((b1 & 0xC0u) != 0x80u) {
                            valid = false;
                        } else {
                            cp = ((static_cast<uint32_t>(b0 & 0x1Fu) << 6) |
                                  static_cast<uint32_t>(b1 & 0x3Fu));
                            if (cp < 0x80u) valid = false;
                        }
                    }
                } else if ((b0 & 0xF0u) == 0xE0u) {
                    need = 3;
                    if (i + 2 >= input.size()) {
                        valid = false;
                    } else {
                        uint8_t b1 = input[i + 1];
                        uint8_t b2 = input[i + 2];
                        if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u) {
                            valid = false;
                        } else {
                            cp = ((static_cast<uint32_t>(b0 & 0x0Fu) << 12) |
                                  (static_cast<uint32_t>(b1 & 0x3Fu) << 6) |
                                  static_cast<uint32_t>(b2 & 0x3Fu));
                            if (cp < 0x800u || (cp >= 0xD800u && cp <= 0xDFFFu)) valid = false;
                        }
                    }
                } else if ((b0 & 0xF8u) == 0xF0u) {
                    need = 4;
                    if (i + 3 >= input.size()) {
                        valid = false;
                    } else {
                        uint8_t b1 = input[i + 1];
                        uint8_t b2 = input[i + 2];
                        uint8_t b3 = input[i + 3];
                        if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u || (b3 & 0xC0u) != 0x80u) {
                            valid = false;
                        } else {
                            cp = ((static_cast<uint32_t>(b0 & 0x07u) << 18) |
                                  (static_cast<uint32_t>(b1 & 0x3Fu) << 12) |
                                  (static_cast<uint32_t>(b2 & 0x3Fu) << 6) |
                                  static_cast<uint32_t>(b3 & 0x3Fu));
                            if (cp < 0x10000u || cp > 0x10FFFFu) valid = false;
                        }
                    }
                } else {
                    valid = false;
                }

                if (!valid) {
                    if ((dw_flags & MB_ERR_INVALID_CHARS) != 0) {
                        fail(ERROR_NO_UNICODE_TRANSLATION);
                        break;
                    }
                    cp = 0xFFFDu;
                    need = 1;
                }

                append_cp(cp);
                i += need;
            }
        } else {
            (void)treat_as_acp; // Unsupported pages degrade to ACP-like single-byte widening.
            wide.reserve(input.size());
            for (uint8_t b : input) {
                wide.push_back(static_cast<uint16_t>(b));
            }
        }
    }

    if (ok) {
        const uint32_t required = static_cast<uint32_t>(wide.size());

        if (cch_wide_char == 0) {
            result = required;
        } else {
            if (lp_wide_char_str == 0) {
                fail(ERROR_INVALID_PARAMETER);
            } else if (static_cast<uint32_t>(cch_wide_char) < required) {
                fail(ERROR_INSUFFICIENT_BUFFER);
            } else if (required > 0 &&
                       uc_mem_write(ctx->uc, lp_wide_char_str, wide.data(), static_cast<size_t>(required) * sizeof(uint16_t)) != UC_ERR_OK) {
                fail(ERROR_INVALID_PARAMETER);
            } else {
                result = required;
            }
        }
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 24 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
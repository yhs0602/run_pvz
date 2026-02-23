#include "api_context.hpp"

#include <cstdint>
#include <vector>

extern "C" void mock_GetStringTypeW(APIContext* ctx) {
    constexpr uint32_t CT_CTYPE1 = 0x00000001u;
    constexpr uint32_t CT_CTYPE2 = 0x00000002u;
    constexpr uint32_t CT_CTYPE3 = 0x00000004u;

    constexpr uint16_t C1_UPPER = 0x0001u;
    constexpr uint16_t C1_LOWER = 0x0002u;
    constexpr uint16_t C1_DIGIT = 0x0004u;
    constexpr uint16_t C1_SPACE = 0x0008u;
    constexpr uint16_t C1_PUNCT = 0x0010u;
    constexpr uint16_t C1_CNTRL = 0x0020u;
    constexpr uint16_t C1_BLANK = 0x0040u;
    constexpr uint16_t C1_XDIGIT = 0x0080u;
    constexpr uint16_t C1_ALPHA = 0x0100u;

    constexpr uint16_t C2_NOTAPPLICABLE = 0x0000u;
    constexpr uint16_t C2_LEFTTORIGHT = 0x0001u;
    constexpr uint16_t C2_EUROPENUMBER = 0x0003u;

    constexpr uint16_t C3_SYMBOL = 0x0008u;
    constexpr uint16_t C3_ALPHA = 0x8000u;

    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87u;

    const uint32_t dwInfoType = ctx->get_arg(0);
    const uint32_t lpSrcStr = ctx->get_arg(1);
    const int32_t cchSrc = static_cast<int32_t>(ctx->get_arg(2));
    const uint32_t lpCharType = ctx->get_arg(3);

    uint32_t result = 0;
    uint32_t last_error = ERROR_INVALID_PARAMETER;

    auto is_ascii_digit = [](uint16_t ch) -> bool {
        return ch >= static_cast<uint16_t>('0') && ch <= static_cast<uint16_t>('9');
    };
    auto is_ascii_upper = [](uint16_t ch) -> bool {
        return ch >= static_cast<uint16_t>('A') && ch <= static_cast<uint16_t>('Z');
    };
    auto is_ascii_lower = [](uint16_t ch) -> bool {
        return ch >= static_cast<uint16_t>('a') && ch <= static_cast<uint16_t>('z');
    };
    auto is_ascii_alpha = [&](uint16_t ch) -> bool {
        return is_ascii_upper(ch) || is_ascii_lower(ch);
    };
    auto is_ascii_space = [](uint16_t ch) -> bool {
        return ch == static_cast<uint16_t>(' ') ||
               ch == static_cast<uint16_t>('\t') ||
               ch == static_cast<uint16_t>('\n') ||
               ch == static_cast<uint16_t>('\r') ||
               ch == static_cast<uint16_t>('\v') ||
               ch == static_cast<uint16_t>('\f');
    };
    auto is_ascii_punct = [](uint16_t ch) -> bool {
        return (ch >= static_cast<uint16_t>('!') && ch <= static_cast<uint16_t>('/')) ||
               (ch >= static_cast<uint16_t>(':') && ch <= static_cast<uint16_t>('@')) ||
               (ch >= static_cast<uint16_t>('[') && ch <= static_cast<uint16_t>('`')) ||
               (ch >= static_cast<uint16_t>('{') && ch <= static_cast<uint16_t>('~'));
    };

    do {
        if (lpSrcStr == 0 || lpCharType == 0 || cchSrc == 0) {
            break;
        }

        if (dwInfoType != CT_CTYPE1 && dwInfoType != CT_CTYPE2 && dwInfoType != CT_CTYPE3) {
            break;
        }

        if (cchSrc < -1) {
            break;
        }

        std::vector<uint16_t> chars;
        if (cchSrc == -1) {
            constexpr uint32_t kMaxScanChars = 1u << 20;
            bool found_null = false;
            for (uint32_t i = 0; i < kMaxScanChars; ++i) {
                uint16_t ch = 0;
                if (ctx->backend->mem_read(lpSrcStr + (i * 2u), &ch, sizeof(ch)) != UC_ERR_OK) {
                    chars.clear();
                    break;
                }
                chars.push_back(ch);
                if (ch == 0) {
                    found_null = true;
                    break;
                }
            }
            if (!found_null || chars.empty()) {
                break;
            }
        } else {
            chars.resize(static_cast<size_t>(cchSrc));
            for (int32_t i = 0; i < cchSrc; ++i) {
                uint16_t ch = 0;
                if (ctx->backend->mem_read(lpSrcStr + (static_cast<uint32_t>(i) * 2u), &ch, sizeof(ch)) != UC_ERR_OK) {
                    chars.clear();
                    break;
                }
                chars[static_cast<size_t>(i)] = ch;
            }
            if (chars.empty()) {
                break;
            }
        }

        bool write_ok = true;
        for (size_t i = 0; i < chars.size(); ++i) {
            const uint16_t ch = chars[i];
            uint16_t out = 0;

            if (dwInfoType == CT_CTYPE1) {
                if (ch <= 0x001Fu || ch == 0x007Fu) out |= C1_CNTRL;
                if (is_ascii_space(ch)) out |= C1_SPACE;
                if (ch == static_cast<uint16_t>(' ') || ch == static_cast<uint16_t>('\t')) out |= C1_BLANK;
                if (is_ascii_digit(ch)) out |= (C1_DIGIT | C1_XDIGIT);
                if (is_ascii_upper(ch)) out |= (C1_UPPER | C1_ALPHA);
                if (is_ascii_lower(ch)) out |= (C1_LOWER | C1_ALPHA);
                if ((ch >= static_cast<uint16_t>('A') && ch <= static_cast<uint16_t>('F')) ||
                    (ch >= static_cast<uint16_t>('a') && ch <= static_cast<uint16_t>('f'))) {
                    out |= C1_XDIGIT;
                }
                if (is_ascii_punct(ch)) out |= C1_PUNCT;
            } else if (dwInfoType == CT_CTYPE2) {
                if (is_ascii_digit(ch)) {
                    out = C2_EUROPENUMBER;
                } else if (is_ascii_alpha(ch) || is_ascii_space(ch) || is_ascii_punct(ch)) {
                    out = C2_LEFTTORIGHT;
                } else {
                    out = C2_NOTAPPLICABLE;
                }
            } else {
                if (is_ascii_alpha(ch)) out |= C3_ALPHA;
                if (is_ascii_punct(ch)) out |= C3_SYMBOL;
            }

            if (ctx->backend->mem_write(lpCharType + static_cast<uint32_t>(i * 2u), &out, sizeof(out)) != UC_ERR_OK) {
                write_ok = false;
                break;
            }
        }

        if (!write_ok) {
            break;
        }

        result = 1;
        last_error = ERROR_SUCCESS;
    } while (false);

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);
}
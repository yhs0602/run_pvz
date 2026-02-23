#include "api_context.hpp"
#include <cstdint>
#include <string>

extern "C" void mock_GetLocaleInfoA(APIContext* ctx) {
    const uint32_t locale = ctx->get_arg(0);
    const uint32_t lc_type_raw = ctx->get_arg(1);
    const uint32_t lp_lc_data = ctx->get_arg(2);
    const uint32_t cch_data = ctx->get_arg(3);

    constexpr uint32_t LOCALE_NOUSEROVERRIDE = 0x80000000;
    constexpr uint32_t LOCALE_USE_CP_ACP = 0x40000000;
    constexpr uint32_t LOCALE_RETURN_NUMBER = 0x20000000;

    constexpr uint32_t LOCALE_ILANGUAGE = 0x00000001;
    constexpr uint32_t LOCALE_SLANGUAGE = 0x00000002;
    constexpr uint32_t LOCALE_SCOUNTRY = 0x00000006;
    constexpr uint32_t LOCALE_IDEFAULTANSICODEPAGE = 0x00001004;
    constexpr uint32_t LOCALE_SDECIMAL = 0x0000000E;
    constexpr uint32_t LOCALE_STHOUSAND = 0x0000000F;
    constexpr uint32_t LOCALE_SGROUPING = 0x00000010;
    constexpr uint32_t LOCALE_SDATE = 0x0000001D;
    constexpr uint32_t LOCALE_STIME = 0x0000001E;
    constexpr uint32_t LOCALE_SSHORTDATE = 0x0000001F;
    constexpr uint32_t LOCALE_SLONGDATE = 0x00000020;
    constexpr uint32_t LOCALE_SENGLANGUAGE = 0x00001001;
    constexpr uint32_t LOCALE_SENGCOUNTRY = 0x00001002;
    constexpr uint32_t LOCALE_SISO639LANGNAME = 0x00000059;
    constexpr uint32_t LOCALE_SISO3166CTRYNAME = 0x0000005A;

    const uint16_t lang_id = static_cast<uint16_t>(locale & 0xFFFF);
    const bool is_korean = (lang_id == 0x0412);

    const uint32_t lc_type = lc_type_raw & ~(LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP);
    const uint32_t base_type = lc_type & ~LOCALE_RETURN_NUMBER;

    uint32_t result = 0;

    if (lc_type & LOCALE_RETURN_NUMBER) {
        uint32_t numeric = 0;
        bool known_numeric = true;

        switch (base_type) {
            case LOCALE_ILANGUAGE:
                numeric = is_korean ? 0x0412 : 0x0409;
                break;
            default:
                known_numeric = false;
                break;
        }

        if (known_numeric && lp_lc_data != 0 && cch_data >= sizeof(uint32_t)) {
            uc_mem_write(ctx->uc, lp_lc_data, &numeric, sizeof(uint32_t));
            result = sizeof(uint32_t);
        }
    } else {
        std::string value;

        switch (base_type) {
            case LOCALE_ILANGUAGE:
                value = is_korean ? "0412" : "0409";
                break;
            case LOCALE_SLANGUAGE:
                value = is_korean ? "Korean (Korea)" : "English (United States)";
                break;
            case LOCALE_SCOUNTRY:
                value = is_korean ? "Korea" : "United States";
                break;
            case LOCALE_IDEFAULTANSICODEPAGE:
                value = is_korean ? "949" : "1252";
                break;
            case LOCALE_SDECIMAL:
                value = ".";
                break;
            case LOCALE_STHOUSAND:
                value = ",";
                break;
            case LOCALE_SGROUPING:
                value = "3;0";
                break;
            case LOCALE_SDATE:
                value = is_korean ? "-" : "/";
                break;
            case LOCALE_STIME:
                value = ":";
                break;
            case LOCALE_SSHORTDATE:
                value = is_korean ? "yyyy-MM-dd" : "M/d/yyyy";
                break;
            case LOCALE_SLONGDATE:
                value = is_korean ? "yyyy-MM-dd dddd" : "dddd, MMMM dd, yyyy";
                break;
            case LOCALE_SENGLANGUAGE:
                value = is_korean ? "Korean" : "English";
                break;
            case LOCALE_SENGCOUNTRY:
                value = is_korean ? "Korea" : "United States";
                break;
            case LOCALE_SISO639LANGNAME:
                value = is_korean ? "ko" : "en";
                break;
            case LOCALE_SISO3166CTRYNAME:
                value = is_korean ? "KR" : "US";
                break;
            default:
                break;
        }

        if (!value.empty()) {
            const uint32_t required = static_cast<uint32_t>(value.size() + 1);
            if (cch_data == 0) {
                result = required;
            } else if (lp_lc_data != 0 && cch_data >= required) {
                uc_mem_write(ctx->uc, lp_lc_data, value.c_str(), required);
                result = required;
            }
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 16 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
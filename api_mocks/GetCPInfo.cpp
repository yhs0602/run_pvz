#include "api_context.hpp"

#include <cstdint>

extern "C" void mock_GetCPInfo(APIContext* ctx) {
    constexpr uint32_t CP_ACP = 0;
    constexpr uint32_t CP_OEMCP = 1;
    constexpr uint32_t CP_MACCP = 2;
    constexpr uint32_t CP_THREAD_ACP = 3;
    constexpr uint32_t CP_UTF8 = 65001;

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;

    const uint32_t code_page_arg = ctx->get_arg(0);
    const uint32_t lpCPInfo = ctx->get_arg(1);

    uint32_t code_page = code_page_arg;
    if (code_page == CP_ACP || code_page == CP_THREAD_ACP) {
        auto it = ctx->global_state.find("ACP");
        code_page = (it != ctx->global_state.end()) ? static_cast<uint32_t>(it->second) : 1252u;
    } else if (code_page == CP_OEMCP) {
        auto it = ctx->global_state.find("OEMCP");
        code_page = (it != ctx->global_state.end()) ? static_cast<uint32_t>(it->second) : 437u;
    } else if (code_page == CP_MACCP) {
        code_page = 10000u;
    }

    uint32_t max_char_size = 1;
    uint8_t default_char[2] = {'?', 0};
    uint8_t lead_byte[12] = {0};

    bool supported = true;
    switch (code_page) {
        case 37:
        case 437:
        case 850:
        case 852:
        case 857:
        case 860:
        case 861:
        case 863:
        case 865:
        case 866:
        case 874:
        case 1250:
        case 1251:
        case 1252:
        case 1253:
        case 1254:
        case 1255:
        case 1256:
        case 1257:
        case 1258:
        case 20127:
        case 28591:
        case 65000:
            max_char_size = 1;
            break;
        case 932:
            max_char_size = 2;
            lead_byte[0] = 0x81; lead_byte[1] = 0x9F;
            lead_byte[2] = 0xE0; lead_byte[3] = 0xFC;
            break;
        case 936:
            max_char_size = 2;
            lead_byte[0] = 0x81; lead_byte[1] = 0xFE;
            break;
        case 949:
            max_char_size = 2;
            lead_byte[0] = 0x81; lead_byte[1] = 0xFE;
            break;
        case 950:
            max_char_size = 2;
            lead_byte[0] = 0x81; lead_byte[1] = 0xFE;
            break;
        case CP_UTF8:
            max_char_size = 4;
            break;
        default:
            supported = false;
            break;
    }

    uint32_t result = 0;
    uint32_t last_error = ERROR_INVALID_PARAMETER;

    if (lpCPInfo != 0 && supported) {
        bool ok = true;
        ok = ok && (uc_mem_write(ctx->uc, lpCPInfo + 0, &max_char_size, sizeof(max_char_size)) == UC_ERR_OK);
        ok = ok && (uc_mem_write(ctx->uc, lpCPInfo + 4, default_char, sizeof(default_char)) == UC_ERR_OK);
        ok = ok && (uc_mem_write(ctx->uc, lpCPInfo + 6, lead_byte, sizeof(lead_byte)) == UC_ERR_OK);

        if (ok) {
            result = 1;
            last_error = ERROR_SUCCESS;
        }
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);
}
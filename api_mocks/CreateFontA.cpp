#include "api_context.hpp"
#include <cstdint>
#include <string>

extern "C" void mock_CreateFontA(APIContext* ctx) {
    const int32_t cHeight = static_cast<int32_t>(ctx->get_arg(0));
    const int32_t cWidth = static_cast<int32_t>(ctx->get_arg(1));
    const int32_t cEscapement = static_cast<int32_t>(ctx->get_arg(2));
    const int32_t cOrientation = static_cast<int32_t>(ctx->get_arg(3));
    const int32_t cWeight = static_cast<int32_t>(ctx->get_arg(4));
    const uint32_t bItalic = ctx->get_arg(5);
    const uint32_t bUnderline = ctx->get_arg(6);
    const uint32_t bStrikeOut = ctx->get_arg(7);
    const uint32_t iCharSet = ctx->get_arg(8);
    const uint32_t iOutPrecision = ctx->get_arg(9);
    const uint32_t iClipPrecision = ctx->get_arg(10);
    const uint32_t iQuality = ctx->get_arg(11);
    const uint32_t iPitchAndFamily = ctx->get_arg(12);
    const uint32_t pszFaceName = ctx->get_arg(13);

    uint32_t result = 0;
    bool face_name_valid = true;
    std::string face_name;

    if (pszFaceName != 0) {
        face_name.reserve(32);
        for (uint32_t i = 0; i < 64; ++i) {
            char ch = 0;
            if (uc_mem_read(ctx->uc, pszFaceName + i, &ch, 1) != UC_ERR_OK) {
                face_name_valid = false;
                break;
            }
            if (ch == '\0') {
                break;
            }
            face_name.push_back(ch);
        }
    }

    if (face_name_valid) {
        uint64_t next_handle = 0x00050000ull;
        auto it = ctx->global_state.find("CreateFontA_next_handle");
        if (it != ctx->global_state.end() && it->second >= 0x10000ull) {
            next_handle = it->second;
        }

        result = static_cast<uint32_t>(next_handle);
        ctx->global_state["CreateFontA_next_handle"] = next_handle + 4ull;
        ctx->global_state["CreateFontA_last_handle"] = result;
        ctx->global_state["CreateFontA_last_cHeight"] = static_cast<uint32_t>(cHeight);
        ctx->global_state["CreateFontA_last_cWidth"] = static_cast<uint32_t>(cWidth);
        ctx->global_state["CreateFontA_last_cEscapement"] = static_cast<uint32_t>(cEscapement);
        ctx->global_state["CreateFontA_last_cOrientation"] = static_cast<uint32_t>(cOrientation);
        ctx->global_state["CreateFontA_last_cWeight"] = static_cast<uint32_t>(cWeight);
        ctx->global_state["CreateFontA_last_bItalic"] = bItalic;
        ctx->global_state["CreateFontA_last_bUnderline"] = bUnderline;
        ctx->global_state["CreateFontA_last_bStrikeOut"] = bStrikeOut;
        ctx->global_state["CreateFontA_last_iCharSet"] = iCharSet;
        ctx->global_state["CreateFontA_last_iOutPrecision"] = iOutPrecision;
        ctx->global_state["CreateFontA_last_iClipPrecision"] = iClipPrecision;
        ctx->global_state["CreateFontA_last_iQuality"] = iQuality;
        ctx->global_state["CreateFontA_last_iPitchAndFamily"] = iPitchAndFamily;
        ctx->global_state["CreateFontA_last_face_len"] = static_cast<uint64_t>(face_name.size());

        uint32_t face_hash = 2166136261u;
        for (char ch : face_name) {
            face_hash ^= static_cast<uint8_t>(ch);
            face_hash *= 16777619u;
        }
        ctx->global_state["CreateFontA_last_face_hash"] = (pszFaceName == 0) ? 0ull : static_cast<uint64_t>(face_hash);
        ctx->global_state["LastError"] = 0u;
    } else {
        ctx->global_state["LastError"] = 87u; // ERROR_INVALID_PARAMETER
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 56 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
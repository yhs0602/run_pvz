#include "api_context.hpp"

extern "C" void mock_IsValidCodePage(APIContext* ctx) {
    const uint32_t code_page = static_cast<uint32_t>(ctx->get_arg(0));

    bool is_valid = false;
    switch (code_page) {
        case 0:      // CP_ACP
        case 1:      // CP_OEMCP
        case 2:      // CP_MACCP
        case 3:      // CP_THREAD_ACP
        case 42:     // CP_SYMBOL
        case 37:
        case 437:
        case 500:
        case 708:
        case 709:
        case 710:
        case 720:
        case 737:
        case 775:
        case 850:
        case 852:
        case 855:
        case 857:
        case 858:
        case 860:
        case 861:
        case 862:
        case 863:
        case 864:
        case 865:
        case 866:
        case 869:
        case 874:
        case 875:
        case 932:
        case 936:
        case 949:
        case 950:
        case 1026:
        case 1047:
        case 1140:
        case 1141:
        case 1142:
        case 1143:
        case 1144:
        case 1145:
        case 1146:
        case 1147:
        case 1148:
        case 1149:
        case 1200:   // UTF-16LE
        case 1201:   // UTF-16BE
        case 1250:
        case 1251:
        case 1252:
        case 1253:
        case 1254:
        case 1255:
        case 1256:
        case 1257:
        case 1258:
        case 1361:
        case 10000:
        case 10001:
        case 10002:
        case 10003:
        case 10004:
        case 10005:
        case 10006:
        case 10007:
        case 10008:
        case 10010:
        case 10017:
        case 10021:
        case 10029:
        case 10079:
        case 10081:
        case 10082:
        case 12000:  // UTF-32LE
        case 12001:  // UTF-32BE
        case 20000:
        case 20001:
        case 20002:
        case 20003:
        case 20004:
        case 20005:
        case 20105:
        case 20106:
        case 20107:
        case 20108:
        case 20127:
        case 20261:
        case 20269:
        case 20273:
        case 20277:
        case 20278:
        case 20280:
        case 20284:
        case 20285:
        case 20290:
        case 20297:
        case 20420:
        case 20423:
        case 20424:
        case 20833:
        case 20838:
        case 20866:
        case 20871:
        case 20880:
        case 20905:
        case 20924:
        case 20932:
        case 20936:
        case 20949:
        case 21025:
        case 21866:
        case 28591:
        case 28592:
        case 28593:
        case 28594:
        case 28595:
        case 28596:
        case 28597:
        case 28598:
        case 28599:
        case 28603:
        case 28605:
        case 29001:
        case 38598:
        case 50220:
        case 50221:
        case 50222:
        case 50225:
        case 50227:
        case 50229:
        case 50930:
        case 50931:
        case 50933:
        case 50935:
        case 50936:
        case 50937:
        case 50939:
        case 51932:
        case 51936:
        case 51949:
        case 51950:
        case 52936:
        case 54936:
        case 57002:
        case 57003:
        case 57004:
        case 57005:
        case 57006:
        case 57007:
        case 57008:
        case 57009:
        case 57010:
        case 57011:
        case 65000:  // UTF-7
        case 65001:  // UTF-8
            is_valid = true;
            break;
        default:
            is_valid = false;
            break;
    }

    ctx->set_eax(is_valid ? 1u : 0u);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
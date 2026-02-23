#include "api_context.hpp"

#include <cstdint>

extern "C" void mock_GetSystemMetrics(APIContext* ctx) {
    const int32_t nIndex = static_cast<int32_t>(ctx->get_arg(0));

    uint32_t screen_w = 1920;
    uint32_t screen_h = 1080;

    auto it = ctx->global_state.find("screen_width");
    if (it != ctx->global_state.end() && it->second > 0 && it->second <= 0xFFFFFFFFull) {
        screen_w = static_cast<uint32_t>(it->second);
    } else {
        it = ctx->global_state.find("DesktopWidth");
        if (it != ctx->global_state.end() && it->second > 0 && it->second <= 0xFFFFFFFFull) {
            screen_w = static_cast<uint32_t>(it->second);
        }
    }

    it = ctx->global_state.find("screen_height");
    if (it != ctx->global_state.end() && it->second > 0 && it->second <= 0xFFFFFFFFull) {
        screen_h = static_cast<uint32_t>(it->second);
    } else {
        it = ctx->global_state.find("DesktopHeight");
        if (it != ctx->global_state.end() && it->second > 0 && it->second <= 0xFFFFFFFFull) {
            screen_h = static_cast<uint32_t>(it->second);
        }
    }

    uint32_t value = 0;

    switch (nIndex) {
        case 0:   // SM_CXSCREEN
        case 78:  // SM_CXVIRTUALSCREEN
            value = screen_w;
            break;
        case 1:   // SM_CYSCREEN
        case 79:  // SM_CYVIRTUALSCREEN
            value = screen_h;
            break;
        case 2:   // SM_CXVSCROLL
        case 3:   // SM_CYHSCROLL
        case 9:   // SM_CYVTHUMB
        case 10:  // SM_CXHTHUMB
        case 20:  // SM_CYVSCROLL
        case 21:  // SM_CXHSCROLL
            value = 17;
            break;
        case 4:   // SM_CYCAPTION
            value = 23;
            break;
        case 5:   // SM_CXBORDER
        case 6:   // SM_CYBORDER
            value = 1;
            break;
        case 7:   // SM_CXDLGFRAME / SM_CXFIXEDFRAME
        case 8:   // SM_CYDLGFRAME / SM_CYFIXEDFRAME
            value = 4;
            break;
        case 11:  // SM_CXICON
        case 12:  // SM_CYICON
        case 13:  // SM_CXCURSOR
        case 14:  // SM_CYCURSOR
        case 49:  // SM_CXSMICON
        case 50:  // SM_CYSMICON
            value = 32;
            break;
        case 15:  // SM_CYMENU
            value = 19;
            break;
        case 16:  // SM_CXFULLSCREEN
            value = (screen_w > 16) ? (screen_w - 16) : screen_w;
            break;
        case 17:  // SM_CYFULLSCREEN
            value = (screen_h > 88) ? (screen_h - 88) : screen_h;
            break;
        case 19:  // SM_MOUSEPRESENT
        case 72:  // SM_MOUSEWHEELPRESENT
            value = 1;
            break;
        case 22:  // SM_DEBUG
        case 23:  // SM_SWAPBUTTON
        case 24:  // SM_RESERVED1
        case 25:  // SM_RESERVED2
        case 26:  // SM_RESERVED3
        case 27:  // SM_RESERVED4
        case 41:  // SM_PENWINDOWS
        case 42:  // SM_DBCSENABLED
        case 67:  // SM_NETWORK
        case 71:  // SM_CLEANBOOT
        case 86:  // SM_TABLETPC
        case 87:  // SM_MEDIACENTER
        case 88:  // SM_STARTER
        case 89:  // SM_SERVERR2
        case 91:  // SM_MOUSEHORIZONTALWHEELPRESENT
        case 92:  // SM_CXPADDEDBORDER
        case 94:  // SM_DIGITIZER
        case 95:  // SM_MAXIMUMTOUCHES
        case 4096: // SM_REMOTESESSION
        case 8192: // SM_SHUTTINGDOWN
        case 8193: // SM_REMOTECONTROL
        case 8195: // SM_CONVERTIBLESLATEMODE
        case 8196: // SM_SYSTEMDOCKED
            value = 0;
            break;
        case 28:  // SM_CXMIN
            value = 112;
            break;
        case 29:  // SM_CYMIN
            value = 27;
            break;
        case 30:  // SM_CXSIZE
        case 31:  // SM_CYSIZE
            value = 30;
            break;
        case 32:  // SM_CXFRAME / SM_CXSIZEFRAME
        case 33:  // SM_CYFRAME / SM_CYSIZEFRAME
            value = 8;
            break;
        case 34:  // SM_CXMINTRACK
        case 35:  // SM_CYMINTRACK
            value = 120;
            break;
        case 36:  // SM_CXDOUBLECLK
        case 37:  // SM_CYDOUBLECLK
            value = 4;
            break;
        case 38:  // SM_CXICONSPACING
        case 39:  // SM_CYICONSPACING
            value = 75;
            break;
        case 40:  // SM_MENUDROPALIGNMENT
        case 56:  // SM_ARRANGE
            value = 0;
            break;
        case 43:  // SM_CMOUSEBUTTONS
            value = 3;
            break;
        case 44:  // SM_SECURE
            value = 1;
            break;
        case 45:  // SM_CXEDGE
        case 46:  // SM_CYEDGE
            value = 2;
            break;
        case 47:  // SM_CXMINSPACING
            value = 112;
            break;
        case 48:  // SM_CYMINSPACING
            value = 27;
            break;
        case 51:  // SM_CYSMCAPTION
            value = 18;
            break;
        case 52:  // SM_CXSMSIZE
        case 53:  // SM_CYSMSIZE
            value = 24;
            break;
        case 54:  // SM_CXMENUSIZE
        case 55:  // SM_CYMENUSIZE
            value = 18;
            break;
        case 57:  // SM_CXMINIMIZED
            value = 160;
            break;
        case 58:  // SM_CYMINIMIZED
            value = 27;
            break;
        case 59:  // SM_CXMAXTRACK
        case 61:  // SM_CXMAXIMIZED
            value = screen_w;
            break;
        case 60:  // SM_CYMAXTRACK
        case 62:  // SM_CYMAXIMIZED
            value = screen_h;
            break;
        case 73:  // SM_XVIRTUALSCREEN
        case 77:  // SM_YVIRTUALSCREEN
            value = 0;
            break;
        case 74:  // older SDK alias for SM_CMONITORS
        case 80:  // SM_CMONITORS
            value = 1;
            break;
        case 75:  // older SDK alias for SM_SAMEDISPLAYFORMAT
        case 81:  // SM_SAMEDISPLAYFORMAT
            value = 1;
            break;
        case 82:  // SM_IMMENABLED
            value = 1;
            break;
        case 83:  // SM_CXFOCUSBORDER
        case 84:  // SM_CYFOCUSBORDER
            value = 1;
            break;
        case 76:  // SM_CMETRICS (modern baseline)
            value = 96;
            break;
        default:
            value = 0;
            break;
    }

    ctx->set_eax(value);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
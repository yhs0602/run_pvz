#include "api_context.hpp"

#include <cstdint>
#include <cstring>

extern "C" void mock_SHGetFolderPathA(APIContext* ctx) {
    const uint32_t hwndOwner = ctx->get_arg(0);
    const int32_t nFolder = static_cast<int32_t>(ctx->get_arg(1));
    const uint32_t hToken = ctx->get_arg(2);
    const uint32_t dwFlags = ctx->get_arg(3);
    const uint32_t pszPath = ctx->get_arg(4);

    (void)hwndOwner;
    (void)hToken;
    (void)dwFlags;

    constexpr uint32_t S_OK = 0x00000000u;
    constexpr uint32_t E_FAIL = 0x80004005u;
    constexpr uint32_t E_INVALIDARG = 0x80070057u;
    constexpr size_t MAX_PATH_A = 260;

    uint32_t result = S_OK;
    const char* folder_path = nullptr;

    switch (static_cast<uint32_t>(nFolder) & 0x00FFu) {
        case 0x00: folder_path = "C:\\Users\\Player\\Desktop"; break;           // CSIDL_DESKTOP
        case 0x05: folder_path = "C:\\Users\\Player\\Documents"; break;         // CSIDL_PERSONAL
        case 0x1A: folder_path = "C:\\Users\\Player\\AppData\\Roaming"; break;  // CSIDL_APPDATA
        case 0x1C: folder_path = "C:\\Users\\Player\\AppData\\Local"; break;    // CSIDL_LOCAL_APPDATA
        case 0x23: folder_path = "C:\\ProgramData"; break;                       // CSIDL_COMMON_APPDATA
        case 0x24: folder_path = "C:\\Windows"; break;                           // CSIDL_WINDOWS
        case 0x25: folder_path = "C:\\Windows\\System32"; break;                 // CSIDL_SYSTEM
        case 0x26: folder_path = "C:\\Program Files"; break;                     // CSIDL_PROGRAM_FILES
        case 0x28: folder_path = "C:\\Users\\Player"; break;                     // CSIDL_PROFILE
        default: result = E_FAIL; break;
    }

    if (pszPath == 0) {
        result = E_INVALIDARG;
    } else if (result == S_OK && folder_path != nullptr) {
        const size_t len = std::strlen(folder_path);
        if (len + 1 > MAX_PATH_A) {
            result = E_FAIL;
        } else {
            char zero_buf[MAX_PATH_A] = {};
            if (ctx->backend->mem_write(pszPath, zero_buf, sizeof(zero_buf)) != UC_ERR_OK ||
                ctx->backend->mem_write(pszPath, folder_path, len + 1) != UC_ERR_OK) {
                result = E_FAIL;
            }
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 20 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
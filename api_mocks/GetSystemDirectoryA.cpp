#include "api_context.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>

extern "C" void mock_GetSystemDirectoryA(APIContext* ctx) {
    uint32_t lpBuffer = ctx->get_arg(0);
    uint32_t uSize = ctx->get_arg(1);

    const char* system_dir = "C:\\Windows\\System32";
    uint32_t path_len = static_cast<uint32_t>(std::strlen(system_dir));
    uint32_t required_size = path_len + 1; // Includes null terminator

    uint32_t ret_value = required_size;

    if (uSize != 0 && lpBuffer != 0) {
        if (uSize >= required_size) {
            uc_mem_write(ctx->uc, lpBuffer, system_dir, required_size);
            ret_value = path_len; // Success: length without null terminator
        } else {
            uint32_t to_copy = uSize - 1;
            if (to_copy > 0) {
                uc_mem_write(ctx->uc, lpBuffer, system_dir, to_copy);
            }
            char null_terminator = '\0';
            uc_mem_write(ctx->uc, lpBuffer + to_copy, &null_terminator, 1);
            ret_value = required_size; // Buffer too small: required size including null
        }
    }

    ctx->set_eax(ret_value);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
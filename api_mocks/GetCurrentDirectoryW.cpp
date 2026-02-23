#include "api_context.hpp"

#include <cstdint>
#include <string>
#include <vector>

extern "C" void mock_GetCurrentDirectoryW(APIContext* ctx) {
    const uint32_t nBufferLength = ctx->get_arg(0);
    const uint32_t lpBuffer = ctx->get_arg(1);

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t ERROR_INSUFFICIENT_BUFFER = 122;

    static const std::string kCurrentDirectory = "C:\\Program Files\\Plants vs. Zombies";

    std::vector<uint16_t> wide_dir;
    wide_dir.reserve(kCurrentDirectory.size() + 1);
    for (char ch : kCurrentDirectory) {
        wide_dir.push_back(static_cast<uint16_t>(static_cast<unsigned char>(ch)));
    }
    wide_dir.push_back(0);

    const uint32_t dir_len = static_cast<uint32_t>(wide_dir.size() - 1);
    const uint32_t required_size = dir_len + 1;

    uint32_t result = required_size;
    uint32_t last_error = ERROR_SUCCESS;

    if (nBufferLength == 0) {
        last_error = ERROR_INSUFFICIENT_BUFFER;
    } else if (lpBuffer == 0) {
        result = 0;
        last_error = ERROR_INVALID_PARAMETER;
    } else if (nBufferLength >= required_size) {
        if (ctx->backend->mem_write(lpBuffer, wide_dir.data(), required_size * sizeof(uint16_t)) == UC_ERR_OK) {
            result = dir_len;
            last_error = ERROR_SUCCESS;
        } else {
            result = 0;
            last_error = ERROR_INVALID_PARAMETER;
        }
    } else {
        const uint32_t to_copy = nBufferLength - 1;
        if (to_copy > 0) {
            ctx->backend->mem_write(lpBuffer, wide_dir.data(), to_copy * sizeof(uint16_t));
        }
        const uint16_t null_terminator = 0;
        ctx->backend->mem_write(lpBuffer + (to_copy * sizeof(uint16_t)), &null_terminator, sizeof(null_terminator));
        result = required_size;
        last_error = ERROR_INSUFFICIENT_BUFFER;
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
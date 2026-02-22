#include "api_context.hpp"
#include <cstdint>

extern "C" void mock_InterlockedDecrement(APIContext* ctx) {
    uint32_t addend_ptr = static_cast<uint32_t>(ctx->get_arg(0));

    int32_t value = 0;
    if (addend_ptr != 0) {
        if (uc_mem_read(ctx->uc, addend_ptr, &value, sizeof(value)) == UC_ERR_OK) {
            value -= 1;
            uc_mem_write(ctx->uc, addend_ptr, &value, sizeof(value));
        }
    }

    ctx->set_eax(static_cast<uint32_t>(value));
}
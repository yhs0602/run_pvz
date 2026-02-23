#include "api_context.hpp"

#include <cstdint>
#include <string>

extern "C" void mock_InterlockedIncrement(APIContext* ctx) {
    const uint32_t addend_ptr = ctx->get_arg(0);

    uint32_t current = 0;
    uint32_t result = 1;

    if (addend_ptr != 0 && ctx->backend->mem_read(addend_ptr, &current, sizeof(current)) == UC_ERR_OK) {
        result = current + 1;
        ctx->backend->mem_write(addend_ptr, &result, sizeof(result));
    } else {
        const std::string key = "interlocked_" + std::to_string(addend_ptr);
        auto it = ctx->global_state.find(key);
        if (it != ctx->global_state.end()) {
            result = static_cast<uint32_t>(it->second) + 1;
        }
        ctx->global_state[key] = static_cast<uint64_t>(result);
    }

    ctx->set_eax(result);
}
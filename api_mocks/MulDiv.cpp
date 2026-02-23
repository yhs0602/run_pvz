#include "api_context.hpp"
#include <cstdint>
#include <limits>

extern "C" void mock_MulDiv(APIContext* ctx) {
    const int32_t nNumber = static_cast<int32_t>(ctx->get_arg(0));
    const int32_t nNumerator = static_cast<int32_t>(ctx->get_arg(1));
    const int32_t nDenominator = static_cast<int32_t>(ctx->get_arg(2));

    int32_t result = -1;

    if (nDenominator != 0) {
        const int64_t product = static_cast<int64_t>(nNumber) * static_cast<int64_t>(nNumerator);
        const int64_t denom = static_cast<int64_t>(nDenominator);

        const int64_t abs_product = (product < 0) ? -product : product;
        const int64_t abs_denom = (denom < 0) ? -denom : denom;

        int64_t q = abs_product / abs_denom;
        const int64_t r = abs_product % abs_denom;

        if (r * 2 >= abs_denom) {
            ++q;
        }

        const bool negative = ((product < 0) != (denom < 0));
        if (negative) {
            q = -q;
        }

        if (q >= std::numeric_limits<int32_t>::min() && q <= std::numeric_limits<int32_t>::max()) {
            result = static_cast<int32_t>(q);
        }
    }

    ctx->set_eax(static_cast<uint32_t>(result));

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 12 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
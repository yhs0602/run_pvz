#include "api_context.hpp"

#include <chrono>
#include <cstdint>

extern "C" void mock_timeGetTime(APIContext* ctx) {
    // timeGetTime has no parameters; keep one stack-read for framework consistency.
    const uint32_t ignored_arg0 = ctx->get_arg(0);
    (void)ignored_arg0;

    using steady_clock = std::chrono::steady_clock;
    const uint64_t host_now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            steady_clock::now().time_since_epoch()).count());

    uint64_t host_base_ms = host_now_ms;
    auto host_base_it = ctx->global_state.find("timeGetTime.host_base_ms");
    if (host_base_it != ctx->global_state.end()) {
        host_base_ms = host_base_it->second;
    } else {
        ctx->global_state["timeGetTime.host_base_ms"] = host_base_ms;
    }

    uint64_t tick_base_ms = 0x00100000ull; // plausible non-zero uptime base (~17 min)
    auto tick_base_it = ctx->global_state.find("timeGetTime.tick_base_ms");
    if (tick_base_it != ctx->global_state.end()) {
        tick_base_ms = tick_base_it->second;
    } else {
        ctx->global_state["timeGetTime.tick_base_ms"] = tick_base_ms;
    }

    const uint64_t elapsed_ms = (host_now_ms >= host_base_ms) ? (host_now_ms - host_base_ms) : 0ull;
    uint32_t result = static_cast<uint32_t>((tick_base_ms + elapsed_ms) & 0xFFFFFFFFull);

    auto last_it = ctx->global_state.find("timeGetTime.last");
    if (last_it != ctx->global_state.end()) {
        const uint32_t last = static_cast<uint32_t>(last_it->second);
        if (result == last) {
            result = last + 1u; // preserve monotonic progress between very close calls
        }
    }
    ctx->global_state["timeGetTime.last"] = static_cast<uint64_t>(result);

    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 0 + 4;
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}
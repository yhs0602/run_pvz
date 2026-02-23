#include "api_context.hpp"

#include <cstdint>

extern "C" void mock_GetCommandLineA(APIContext* ctx) {
    const uint32_t ignored_arg0 = ctx->get_arg(0);
    (void)ignored_arg0;

    constexpr uint32_t kDefaultHeapBase = 0x20000000;
    constexpr uint32_t kPageSize = 0x1000;
    static constexpr char kCommandLine[] =
        "\"C:\\Program Files\\Plants vs. Zombies\\PlantsVsZombies.exe\"";

    uint32_t cmd_ptr = 0;
    auto it = ctx->global_state.find("GetCommandLineA_ptr");
    if (it != ctx->global_state.end()) {
        cmd_ptr = static_cast<uint32_t>(it->second);
    } else {
        uint32_t heap_top = kDefaultHeapBase;
        auto heap_it = ctx->global_state.find("HeapTop");
        if (heap_it != ctx->global_state.end()) {
            heap_top = static_cast<uint32_t>(heap_it->second);
        }

        cmd_ptr = heap_top;
        const uint32_t len = static_cast<uint32_t>(sizeof(kCommandLine));
        const uint32_t map_base = cmd_ptr & ~(kPageSize - 1);
        const uint32_t map_needed = (cmd_ptr - map_base) + len;
        const uint32_t map_size = (map_needed + (kPageSize - 1)) & ~(kPageSize - 1);

        uc_err map_err = ctx->backend->mem_map(map_base, map_size, UC_PROT_ALL);
        if (map_err != UC_ERR_OK && map_err != UC_ERR_MAP) {
            cmd_ptr = 0x00300000;
            ctx->backend->mem_map(cmd_ptr & ~(kPageSize - 1), kPageSize, UC_PROT_ALL);
        }

        if (ctx->backend->mem_write(cmd_ptr, kCommandLine, len) != UC_ERR_OK) {
            cmd_ptr = 0;
        } else {
            ctx->global_state["GetCommandLineA_ptr"] = cmd_ptr;
            ctx->global_state["HeapTop"] = static_cast<uint64_t>(cmd_ptr + ((len + 0xF) & ~0xF));
        }
    }

    ctx->set_eax(cmd_ptr);
}
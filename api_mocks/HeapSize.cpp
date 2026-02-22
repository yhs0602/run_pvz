#include "api_context.hpp"

#include <cstdint>
#include <string>
#include <iostream>

extern "C" void mock_HeapSize(APIContext* ctx) {
    const uint32_t hHeap = ctx->get_arg(0);
    const uint32_t dwFlags = ctx->get_arg(1);
    const uint32_t lpMem = ctx->get_arg(2);

    (void)hHeap;
    (void)dwFlags;

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_ADDRESS = 487;
    constexpr uint32_t INVALID_SIZE_T = 0xFFFFFFFF;
    constexpr uint32_t HEAP_BASE = 0x20000000;
    constexpr uint32_t HEAP_REGION_SIZE = 0x10000000;

    uint32_t result = INVALID_SIZE_T;

    if (lpMem != 0) {
        const std::string size_key = "heap_size_" + std::to_string(lpMem);
        const auto it = ctx->global_state.find(size_key);
        if (it != ctx->global_state.end()) {
            result = static_cast<uint32_t>(it->second);
        } else {
            const auto heap_top_it = ctx->global_state.find("HeapTop");
            const uint64_t heap_top = (heap_top_it != ctx->global_state.end()) ? heap_top_it->second : 0;

            if (lpMem >= HEAP_BASE &&
                lpMem < (HEAP_BASE + HEAP_REGION_SIZE) &&
                (heap_top == 0 || static_cast<uint64_t>(lpMem) < heap_top)) {
                result = 0x20; // Plausible default block size when allocation metadata is unavailable
            }
        }
    }

    ctx->global_state["LastError"] = (result == INVALID_SIZE_T) ? ERROR_INVALID_ADDRESS : ERROR_SUCCESS;
    
    std::cout << "[mock_HeapSize] lpMem: 0x" << std::hex << lpMem << ", returned size: " << std::dec << result << " (0xFFFFFFFF = ERROR)\n";
    ctx->set_eax(result);
}
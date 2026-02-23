#include "api_context.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <iostream>

extern "C" void mock_HeapReAlloc(APIContext* ctx) {
    const uint32_t hHeap = ctx->get_arg(0);
    const uint32_t dwFlags = ctx->get_arg(1);
    const uint32_t lpMem = ctx->get_arg(2);
    const uint32_t dwBytes = ctx->get_arg(3);

    (void)hHeap;

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t ERROR_NOT_ENOUGH_MEMORY = 8;
    constexpr uint32_t ERROR_INVALID_ADDRESS = 487;

    constexpr uint32_t HEAP_ZERO_MEMORY = 0x00000008;
    constexpr uint32_t HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010;

    constexpr uint32_t HEAP_BASE = 0x20000000;
    constexpr uint32_t HEAP_REGION_SIZE = 0x10000000;
    constexpr uint32_t HEAP_ALIGN = 0x10;

    auto align_up = [](uint32_t v) -> uint32_t {
        return (v + (HEAP_ALIGN - 1)) & ~(HEAP_ALIGN - 1);
    };

    uint32_t result = 0;

    if (lpMem == 0) {
        ctx->global_state["LastError"] = ERROR_INVALID_PARAMETER;
        result = 0;
    } else {
        const std::string old_size_key = "heap_size_" + std::to_string(lpMem);
        uint32_t old_size = 0;
        bool old_block_known = false;

        const auto old_it = ctx->global_state.find(old_size_key);
        if (old_it != ctx->global_state.end()) {
            old_size = static_cast<uint32_t>(old_it->second);
            old_block_known = true;
        } else {
            const auto heap_top_it = ctx->global_state.find("HeapTop");
            const uint64_t heap_top = (heap_top_it != ctx->global_state.end()) ? heap_top_it->second : 0;

            if (lpMem >= HEAP_BASE &&
                lpMem < (HEAP_BASE + HEAP_REGION_SIZE) &&
                (heap_top == 0 || static_cast<uint64_t>(lpMem) < heap_top)) {
                old_size = 0x20;
                old_block_known = true;
            }
        }

        if (!old_block_known) {
            ctx->global_state["LastError"] = ERROR_INVALID_ADDRESS;
            result = 0;
        } else {
            const uint32_t requested_size = (dwBytes == 0) ? 1u : dwBytes;

            if ((dwFlags & HEAP_REALLOC_IN_PLACE_ONLY) != 0) {
                if (requested_size <= old_size) {
                    ctx->global_state[old_size_key] = requested_size;
                    ctx->global_state["LastError"] = ERROR_SUCCESS;
                    result = lpMem;
                } else {
                    ctx->global_state["LastError"] = ERROR_NOT_ENOUGH_MEMORY;
                    result = 0;
                }
            } else if (requested_size <= old_size) {
                ctx->global_state[old_size_key] = requested_size;
                ctx->global_state["LastError"] = ERROR_SUCCESS;
                result = lpMem;
            } else {
                uint32_t heap_top = HEAP_BASE;
                const auto heap_top_it = ctx->global_state.find("HeapTop");
                if (heap_top_it != ctx->global_state.end()) {
                    heap_top = static_cast<uint32_t>(heap_top_it->second);
                }

                if (heap_top < HEAP_BASE || heap_top >= (HEAP_BASE + HEAP_REGION_SIZE)) {
                    heap_top = HEAP_BASE;
                }

                const uint32_t new_ptr = align_up(heap_top);
                const uint64_t region_end = static_cast<uint64_t>(HEAP_BASE) + HEAP_REGION_SIZE;
                const uint64_t new_end = static_cast<uint64_t>(new_ptr) + requested_size;

                if (new_end > region_end) {
                    ctx->global_state["LastError"] = ERROR_NOT_ENOUGH_MEMORY;
                    result = 0;
                } else {
                    bool io_ok = true;
                    const uint32_t copy_size = std::min(old_size, requested_size);

                    std::array<uint8_t, 256> buffer{};
                    uint32_t copied = 0;
                    while (copied < copy_size) {
                        const uint32_t chunk = std::min<uint32_t>(
                            static_cast<uint32_t>(buffer.size()),
                            copy_size - copied);

                        if (ctx->backend->mem_read(lpMem + copied, buffer.data(), chunk) != UC_ERR_OK ||
                            ctx->backend->mem_write(new_ptr + copied, buffer.data(), chunk) != UC_ERR_OK) {
                            io_ok = false;
                            break;
                        }
                        copied += chunk;
                    }

                    if (io_ok && (dwFlags & HEAP_ZERO_MEMORY) != 0 && requested_size > copy_size) {
                        const std::array<uint8_t, 256> zero_buf{};
                        uint32_t zeroed = copy_size;
                        while (zeroed < requested_size) {
                            const uint32_t chunk = std::min<uint32_t>(
                                static_cast<uint32_t>(zero_buf.size()),
                                requested_size - zeroed);

                            if (ctx->backend->mem_write(new_ptr + zeroed, zero_buf.data(), chunk) != UC_ERR_OK) {
                                io_ok = false;
                                break;
                            }
                            zeroed += chunk;
                        }
                    }

                    if (!io_ok) {
                        ctx->global_state["LastError"] = ERROR_INVALID_ADDRESS;
                        result = 0;
                    } else {
                        const std::string new_size_key = "heap_size_" + std::to_string(new_ptr);
                        ctx->global_state.erase(old_size_key);
                        ctx->global_state[new_size_key] = requested_size;
                        ctx->global_state["HeapTop"] = static_cast<uint64_t>(align_up(new_ptr + requested_size));
                        ctx->global_state["LastError"] = ERROR_SUCCESS;
                        result = new_ptr;
                    }
                }
            }
        }
    }

    std::cout << "[mock_HeapReAlloc] lpMem: 0x" << std::hex << lpMem << ", dwBytes: " << std::dec << dwBytes << ", returned ptr: 0x" << std::hex << result << std::dec << "\n";
    ctx->set_eax(result);
}
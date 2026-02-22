#include "api_context.hpp"

#include <cstdint>
#include <vector>

extern "C" void mock_GetEnvironmentStringsW(APIContext* ctx) {
    const uint32_t ignored_arg0 = ctx->get_arg(0);
    (void)ignored_arg0;

    constexpr uint32_t kDefaultHeapBase = 0x20000000;
    constexpr uint32_t kPageSize = 0x1000;
    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_NOT_ENOUGH_MEMORY = 8;

    uint32_t env_ptr = 0;

    auto it = ctx->global_state.find("GetEnvironmentStringsW_ptr");
    if (it != ctx->global_state.end()) {
        env_ptr = static_cast<uint32_t>(it->second);
    } else {
        const char* entries[] = {
            "ALLUSERSPROFILE=C:\\ProgramData",
            "ComSpec=C:\\Windows\\System32\\cmd.exe",
            "NUMBER_OF_PROCESSORS=4",
            "OS=Windows_NT",
            "Path=C:\\Windows\\System32;C:\\Windows",
            "SystemRoot=C:\\Windows",
            "TEMP=C:\\Temp",
            "TMP=C:\\Temp",
            "USERNAME=Player"
        };

        std::vector<uint16_t> env_block;
        for (const char* s : entries) {
            for (const char* p = s; *p != '\0'; ++p) {
                env_block.push_back(static_cast<uint16_t>(static_cast<unsigned char>(*p)));
            }
            env_block.push_back(0);
        }
        env_block.push_back(0); // Final extra NUL for double-NUL termination.

        const uint32_t bytes = static_cast<uint32_t>(env_block.size() * sizeof(uint16_t));

        uint32_t heap_top = kDefaultHeapBase;
        auto heap_it = ctx->global_state.find("HeapTop");
        if (heap_it != ctx->global_state.end()) {
            heap_top = static_cast<uint32_t>(heap_it->second);
        }
        env_ptr = heap_top;

        const uint32_t map_base = env_ptr & ~(kPageSize - 1);
        const uint32_t map_needed = (env_ptr - map_base) + bytes;
        const uint32_t map_size = (map_needed + (kPageSize - 1)) & ~(kPageSize - 1);

        uc_err map_err = uc_mem_map(ctx->uc, map_base, map_size, UC_PROT_ALL);
        if (map_err != UC_ERR_OK && map_err != UC_ERR_MAP) {
            env_ptr = 0x00310000;
            const uint32_t fallback_size = (bytes + (kPageSize - 1)) & ~(kPageSize - 1);
            uc_mem_map(ctx->uc, env_ptr, fallback_size, UC_PROT_ALL);
        }

        if (uc_mem_write(ctx->uc, env_ptr, env_block.data(), bytes) != UC_ERR_OK) {
            env_ptr = 0;
            ctx->global_state["LastError"] = ERROR_NOT_ENOUGH_MEMORY;
        } else {
            ctx->global_state["GetEnvironmentStringsW_ptr"] = env_ptr;
            ctx->global_state["HeapTop"] = static_cast<uint64_t>(env_ptr + ((bytes + 0xF) & ~0xF));
            ctx->global_state["LastError"] = ERROR_SUCCESS;
        }
    }

    ctx->set_eax(env_ptr);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 0 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
#include "api_context.hpp"
#include <iostream>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>

extern "C" void mock_GetModuleHandleA(APIContext* ctx) {
    const uint32_t lpModuleName = ctx->get_arg(0);
    uint32_t hModule = 0;
    std::string module_name;

    if (lpModuleName == 0) {
        hModule = 0x00400000; // Typical ImageBase for the main module
        module_name = "NULL";
    } else {
        module_name.reserve(64);

        for (uint32_t i = 0; i < 260; ++i) {
            char ch = 0;
            if (uc_mem_read(ctx->uc, lpModuleName + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
                break;
            }
            module_name.push_back(ch);
        }

        std::transform(
            module_name.begin(),
            module_name.end(),
            module_name.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (module_name == "kernel32" || module_name == "kernel32.dll") {
            hModule = 0x76000000;
            ctx->global_state["LastError"] = 0;
        } else if (module_name == "ntdll" || module_name == "ntdll.dll") {
            hModule = 0x77000000;
            ctx->global_state["LastError"] = 0;
        } else if (module_name == "user32" || module_name == "user32.dll") {
            hModule = 0x75000000;
            ctx->global_state["LastError"] = 0;
        } else {
            hModule = 0; // Module not found
            ctx->global_state["LastError"] = 126; // ERROR_MOD_NOT_FOUND
        }
    }

    std::cout << "[mock_GetModuleHandleA] Requested module: " << module_name << " -> 0x" << std::hex << hModule << std::dec << "\n";

    ctx->set_eax(hModule);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
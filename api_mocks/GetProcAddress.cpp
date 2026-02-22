#include "api_context.hpp"
#include <unicorn/unicorn.h>
#include <iostream>
#include <string>

extern "C" void mock_GetProcAddress(APIContext* ctx) {
    uint32_t hModule = ctx->get_arg(0);
    uint32_t lpProcName = ctx->get_arg(1);
    
    std::string proc_name;
    if (lpProcName > 0xFFFF) { // It's a string pointer
        char c;
        uint32_t addr = lpProcName;
        while (true) {
            uc_mem_read(ctx->uc, addr, &c, 1);
            if (c == '\0') break;
            proc_name += c;
            addr++;
        }
    } else {
        proc_name = "Ordinal_" + std::to_string(lpProcName);
    }
    
    std::cout << "[mock_GetProcAddress] hModule: 0x" << std::hex << hModule << std::dec 
              << ", ProcName: " << proc_name << std::endl;
              
    // Return NULL (0) for now to simulate "Proc Not Found"
    // The CRT usually handles missing newer APIs gracefully (e.g. FlsAlloc)
    ctx->set_eax(0);
    ctx->global_state["LastError"] = 127; // ERROR_PROC_NOT_FOUND
    
    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    // GetProcAddress is stdcall with 2 arguments (8 bytes)
    esp += 8 + 4; // pop arguments and the return address
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
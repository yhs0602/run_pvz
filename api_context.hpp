#pragma once

#include <unicorn/unicorn.h>
#include <string>
#include <unordered_map>

struct APIContext {
    uc_engine* uc;
    std::unordered_map<std::string, uint64_t> global_state;
    std::unordered_map<std::string, void*> handle_map;
    
    // Quick helper to read arguments from Windows x86 stack (stdcall)
    // index 0 is first argument
    uint32_t get_arg(int index) {
        uint32_t esp;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uint32_t val;
        // Skip return address (+4)
        uc_err err = uc_mem_read(uc, esp + 4 + (index * 4), &val, sizeof(val));
        if (err) return 0;
        return val;
    }

    // Set EAX return value
    void set_eax(uint32_t val) {
        uc_reg_write(uc, UC_X86_REG_EAX, &val);
    }
};

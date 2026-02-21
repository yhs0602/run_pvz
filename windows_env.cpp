#include "windows_env.hpp"

#include <vector>

uint64_t WindowsEnvironment::create_gdt_entry(uint32_t base, uint32_t limit, uint8_t access, uint8_t flags) {
    uint64_t base64 = base;
    uint64_t limit64 = limit & 0xfffff;
    
    uint64_t entry = (
        (limit64 & 0xffff) |
        ((base64 & 0xffffff) << 16) |
        (static_cast<uint64_t>(access & 0xff) << 40) |
        (((limit64 >> 16) & 0x0f) << 48) |
        (static_cast<uint64_t>(flags & 0x0f) << 52) |
        ((base64 >> 24) << 56)
    );
    return entry;
}

void WindowsEnvironment::setup_stack() {
    std::cout << "[*] Mapping Stack: Base=0x" << std::hex << STACK_BASE 
              << ", Size=0x" << STACK_SIZE << std::dec << "\n";
              
    uc_mem_map(uc, STACK_BASE, STACK_SIZE, UC_PROT_ALL);
    
    uint32_t stack_top = STACK_BASE + STACK_SIZE - 0x1000;
    uc_reg_write(uc, UC_X86_REG_ESP, &stack_top);
    uc_reg_write(uc, UC_X86_REG_EBP, &stack_top);
}

void WindowsEnvironment::setup_teb_peb() {
    std::cout << "[*] Setting up GDT (0x" << std::hex << GDT_BASE 
              << ") and TEB/PEB (0x" << TEB_BASE << ")\n";

    uc_mem_map(uc, TEB_BASE, 0x1000, UC_PROT_ALL);
    uc_mem_map(uc, PEB_BASE, 0x1000, UC_PROT_ALL);
    uc_mem_map(uc, GDT_BASE, 0x1000, UC_PROT_ALL);

    // 1. Setup GDT Entries
    std::vector<uint64_t> gdt = {
        create_gdt_entry(0, 0, 0, 0),                           // 0x00 Null
        create_gdt_entry(0, 0xFFFFF, 0x9B, 0xC),                // 0x08 Code32 Ring0
        create_gdt_entry(0, 0xFFFFF, 0x93, 0xC),                // 0x10 Data32 Ring0
        create_gdt_entry(TEB_BASE, 0xFFFFF, 0x93, 0xC)          // 0x18 TEB Ring0
    };

    for (size_t i = 0; i < gdt.size(); i++) {
        uc_mem_write(uc, GDT_BASE + (i * 8), &gdt[i], sizeof(uint64_t));
    }

    // 2. Load GDTR
    uc_x86_mmr gdtr;
    gdtr.base = GDT_BASE;
    gdtr.limit = static_cast<uint16_t>(gdt.size() * 8 - 1);
    gdtr.selector = 0;
    uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);

    // 3. Load Segment Registers
    uint32_t ds = 0x10, es = 0x10, ss = 0x10, fs = 0x18;
    uc_reg_write(uc, UC_X86_REG_DS, &ds);
    uc_reg_write(uc, UC_X86_REG_ES, &es);
    uc_reg_write(uc, UC_X86_REG_SS, &ss);
    uc_reg_write(uc, UC_X86_REG_FS, &fs);

    // 4. Populate TEB Fields
    uint32_t seh_head = 0xFFFFFFFF;
    uc_mem_write(uc, TEB_BASE + 0x00, &seh_head, 4);
    
    uint32_t stack_top;
    uc_reg_read(uc, UC_X86_REG_ESP, &stack_top);
    
    uc_mem_write(uc, TEB_BASE + 0x04, &stack_top, 4);
    
    uint32_t stack_base = STACK_BASE;
    uc_mem_write(uc, TEB_BASE + 0x08, &stack_base, 4);
    
    uint32_t teb_base = TEB_BASE;
    uc_mem_write(uc, TEB_BASE + 0x18, &teb_base, 4);
    
    uint32_t peb_base = PEB_BASE;
    uc_mem_write(uc, TEB_BASE + 0x30, &peb_base, 4);
}

void WindowsEnvironment::setup_system() {
    setup_stack();
    setup_teb_peb();
}

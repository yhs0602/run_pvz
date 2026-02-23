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
              
    backend.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL);
    
    uint32_t stack_top = STACK_BASE + STACK_SIZE - 0x1000;
    backend.reg_write(UC_X86_REG_ESP, &stack_top);
    backend.reg_write(UC_X86_REG_EBP, &stack_top);
}

void WindowsEnvironment::setup_teb_peb() {
    std::cout << "[*] Setting up GDT (0x" << std::hex << GDT_BASE 
              << ") and TEB/PEB (0x" << TEB_BASE << ")\n";

    backend.mem_map(TEB_BASE, 0x1000, UC_PROT_ALL);
    backend.mem_map(PEB_BASE, 0x1000, UC_PROT_ALL);
    backend.mem_map(GDT_BASE, 0x1000, UC_PROT_ALL);

    // 1. Setup GDT Entries
    std::vector<uint64_t> gdt = {
        create_gdt_entry(0, 0, 0, 0),                           // 0x00 Null
        create_gdt_entry(0, 0xFFFFF, 0x9B, 0xC),                // 0x08 Code32 Ring0
        create_gdt_entry(0, 0xFFFFF, 0x93, 0xC),                // 0x10 Data32 Ring0
        create_gdt_entry(TEB_BASE, 0xFFFFF, 0x93, 0xC)          // 0x18 TEB Ring0
    };

    for (size_t i = 0; i < gdt.size(); i++) {
        backend.mem_write(GDT_BASE + (i * 8), &gdt[i], sizeof(uint64_t));
    }

    // 2. Load GDTR
    uc_x86_mmr gdtr;
    gdtr.base = GDT_BASE;
    gdtr.limit = static_cast<uint16_t>(gdt.size() * 8 - 1);
    gdtr.selector = 0;
    backend.reg_write(UC_X86_REG_GDTR, &gdtr);

    // 3. Load Segment Registers
    uint32_t ds = 0x10, es = 0x10, ss = 0x10, fs = 0x18;
    backend.reg_write(UC_X86_REG_DS, &ds);
    backend.reg_write(UC_X86_REG_ES, &es);
    backend.reg_write(UC_X86_REG_SS, &ss);
    backend.reg_write(UC_X86_REG_FS, &fs);

    // 4. Populate TEB Fields
    uint32_t seh_head = 0xFFFFFFFF;
    backend.mem_write(TEB_BASE + 0x00, &seh_head, 4);
    
    uint32_t stack_top;
    backend.reg_read(UC_X86_REG_ESP, &stack_top);
    
    backend.mem_write(TEB_BASE + 0x04, &stack_top, 4);
    
    uint32_t stack_base = STACK_BASE;
    backend.mem_write(TEB_BASE + 0x08, &stack_base, 4);
    
    uint32_t teb_base = TEB_BASE;
    backend.mem_write(TEB_BASE + 0x18, &teb_base, 4);
    
    uint32_t peb_base = PEB_BASE;
    backend.mem_write(TEB_BASE + 0x30, &peb_base, 4);
}

void WindowsEnvironment::setup_system() {
    setup_stack();
    setup_teb_peb();
}

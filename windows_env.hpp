#pragma once

#include "cpu_backend_compat.hpp"
#include <cstdint>
#include <iostream>

class WindowsEnvironment {
private:
    uc_engine* uc;
    
    uint64_t create_gdt_entry(uint32_t base, uint32_t limit, uint8_t access, uint8_t flags);
    void setup_stack();
    void setup_teb_peb();

public:
    static constexpr uint32_t TEB_BASE = 0x7FFDF000;
    static constexpr uint32_t PEB_BASE = 0x7FFDE000;
    static constexpr uint32_t GDT_BASE = 0xC0000000;
    static constexpr uint32_t STACK_BASE = 0x80000000;
    static constexpr uint32_t STACK_SIZE = 2 * 1024 * 1024; // 2MB

    explicit WindowsEnvironment(uc_engine* engine) : uc(engine) {}
    
    void setup_system();
};

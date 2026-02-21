#include "api_handler.hpp"

const std::unordered_map<std::string, int> DummyAPIHandler::KNOWN_SIGNATURES = {
    {"KERNEL32.dll!GetSystemTimeAsFileTime", 4},
    {"KERNEL32.dll!GetCurrentProcessId", 0},
    {"KERNEL32.dll!GetCurrentThreadId", 0},
    {"KERNEL32.dll!GetTickCount", 0},
    {"KERNEL32.dll!QueryPerformanceCounter", 4},
    {"KERNEL32.dll!GetStartupInfoA", 4},
    {"KERNEL32.dll!GetProcessHeap", 0},
    {"KERNEL32.dll!HeapAlloc", 12},
    {"KERNEL32.dll!HeapCreate", 12},
    {"KERNEL32.dll!GetVersionExA", 4},
    {"KERNEL32.dll!HeapFree", 12},
    {"KERNEL32.dll!GetModuleFileNameA", 12},
    {"KERNEL32.dll!GetLastError", 0},
    {"KERNEL32.dll!SetLastError", 4},
    {"KERNEL32.dll!CloseHandle", 4}
};

DummyAPIHandler::DummyAPIHandler(uc_engine* engine) : uc(engine), current_addr(FAKE_API_BASE) {
    std::cout << "[*] Mapping FAKE_API boundary at 0x" << std::hex << FAKE_API_BASE << std::dec << "\n";
    uc_mem_map(uc, FAKE_API_BASE, 0x100000, UC_PROT_ALL); // 1MB

    uc_hook trace;
    uc_hook_add(uc, &trace, UC_HOOK_BLOCK, (void*)hook_api_call, this, 1, 0); // Catch all blocks
}

uint32_t DummyAPIHandler::register_fake_api(const std::string& full_name) {
    uint32_t api_addr = current_addr;
    fake_api_map[api_addr] = full_name;
    
    auto it = KNOWN_SIGNATURES.find(full_name);
    if (it != KNOWN_SIGNATURES.end() && it->second > 0) {
        int args_bytes = it->second;
        uint8_t instruction[3] = {0xC2, static_cast<uint8_t>(args_bytes & 0xFF), static_cast<uint8_t>((args_bytes >> 8) & 0xFF)};
        uc_mem_write(uc, api_addr, instruction, 3);
    } else {
        uint8_t instruction = 0xC3;
        uc_mem_write(uc, api_addr, &instruction, 1);
    }
    
    current_addr += 16;
    return api_addr;
}

void DummyAPIHandler::hook_api_call(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    DummyAPIHandler* handler = static_cast<DummyAPIHandler*>(user_data);
    
    auto it = handler->fake_api_map.find(address);
    if (it != handler->fake_api_map.end()) {
        const std::string& name = it->second;
        bool known = (KNOWN_SIGNATURES.find(name) != KNOWN_SIGNATURES.end());
        std::cout << "\n[API CALL] " << (known ? "[OK]" : "[WARN-UNKNOWN]") 
                  << " Intercepted call to " << name << std::endl;
    }
}

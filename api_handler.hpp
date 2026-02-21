#pragma once

#include <unicorn/unicorn.h>
#include <string>
#include <unordered_map>
#include <iostream>

class DummyAPIHandler {
private:
    uc_engine* uc;
    std::unordered_map<uint32_t, std::string> fake_api_map;
    uint32_t current_addr;
    
    static const std::unordered_map<std::string, int> KNOWN_SIGNATURES;

public:
    static constexpr uint32_t FAKE_API_BASE = 0x90000000;

    explicit DummyAPIHandler(uc_engine* engine);
    
    uint32_t register_fake_api(const std::string& full_name);
    
    static void hook_api_call(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
};

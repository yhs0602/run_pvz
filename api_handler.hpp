#pragma once

#include <unicorn/unicorn.h>
#include <string>
#include <unordered_map>
#include <iostream>
#include "api_context.hpp"

class DummyAPIHandler {
private:
    APIContext ctx;
    std::unordered_map<uint32_t, std::string> fake_api_map;
    std::unordered_map<std::string, void*> dylib_handles;
    std::unordered_map<std::string, void(*)(APIContext*)> dylib_funcs;
    uint32_t current_addr;
    
    static const std::unordered_map<std::string, int> KNOWN_SIGNATURES;

public:
    static constexpr uint32_t FAKE_API_BASE = 0x90000000;

    explicit DummyAPIHandler(uc_engine* engine);
    ~DummyAPIHandler();
    
    uint32_t register_fake_api(const std::string& full_name);
    
    static void hook_api_call(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    void handle_unknown_api(const std::string& api_name, uint32_t address);
    bool try_load_dylib(const std::string& api_name);
};

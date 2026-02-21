#include "api_handler.hpp"
#include <fstream>
#include <filesystem>
#include <dlfcn.h>
#include <unistd.h>

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

DummyAPIHandler::DummyAPIHandler(uc_engine* engine) : current_addr(FAKE_API_BASE) {
    ctx.uc = engine;
    std::filesystem::create_directories("api_requests");
    std::filesystem::create_directories("api_mocks");
    
    std::cout << "[*] Mapping FAKE_API boundary at 0x" << std::hex << FAKE_API_BASE << std::dec << "\n";
    uc_mem_map(ctx.uc, FAKE_API_BASE, 0x100000, UC_PROT_ALL); // 1MB

    uc_hook trace;
    uc_hook_add(ctx.uc, &trace, UC_HOOK_BLOCK, (void*)hook_api_call, this, 1, 0); // Catch all blocks
}

DummyAPIHandler::~DummyAPIHandler() {
    for (auto& pair : dylib_handles) {
        if (pair.second) dlclose(pair.second);
    }
}

uint32_t DummyAPIHandler::register_fake_api(const std::string& full_name) {
    uint32_t api_addr = current_addr;
    fake_api_map[api_addr] = full_name;
    
    auto it = KNOWN_SIGNATURES.find(full_name);
    if (it != KNOWN_SIGNATURES.end() && it->second > 0) {
        int args_bytes = it->second;
        uint8_t instruction[3] = {0xC2, static_cast<uint8_t>(args_bytes & 0xFF), static_cast<uint8_t>((args_bytes >> 8) & 0xFF)};
        uc_mem_write(ctx.uc, api_addr, instruction, 3);
    } else {
        uint8_t instruction = 0xC3; // ret
        uc_mem_write(ctx.uc, api_addr, &instruction, 1);
    }
    
    current_addr += 16;
    return api_addr;
}

bool DummyAPIHandler::try_load_dylib(const std::string& api_name) {
    if (dylib_funcs.find(api_name) != dylib_funcs.end()) return true;

    // Parse Just the function name (e.g., KERNEL32.dll!TlsGetValue -> TlsGetValue)
    size_t excla = api_name.find('!');
    std::string func_name = (excla != std::string::npos) ? api_name.substr(excla + 1) : api_name;
    
    std::string dylib_path = "api_mocks/" + func_name + ".dylib";
    if (std::filesystem::exists(dylib_path)) {
        void* handle = dlopen(dylib_path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (handle) {
            std::string sym_name = "mock_" + func_name;
            void* func_ptr = dlsym(handle, sym_name.c_str());
            if (func_ptr) {
                dylib_handles[api_name] = handle;
                dylib_funcs[api_name] = reinterpret_cast<void(*)(APIContext*)>(func_ptr);
                std::cout << "[+] Dynamically linked Mock Plugin for " << func_name << "\n";
                return true;
            } else {
                std::cerr << "[!] Failed to load symbol " << sym_name << ": " << dlerror() << "\n";
                dlclose(handle);
            }
        } else {
            std::cerr << "[!] Failed to load " << dylib_path << ": " << dlerror() << "\n";
        }
    }
    return false;
}

void DummyAPIHandler::handle_unknown_api(const std::string& api_name, uint32_t address) {
    size_t excla = api_name.find('!');
    std::string func_name = (excla != std::string::npos) ? api_name.substr(excla + 1) : api_name;
    std::string module_name = (excla != std::string::npos) ? api_name.substr(0, excla) : "UNKNOWN";

    std::string request_file = "api_requests/" + func_name + ".json";
    std::string dylib_path = "api_mocks/" + func_name + ".dylib";

    if (!std::filesystem::exists(dylib_path)) {
        std::ofstream out(request_file);
        if (out.is_open()) {
            out << "{\n";
            out << "  \"api_name\": \"" << func_name << "\",\n";
            out << "  \"module\": \"" << module_name << "\",\n";
            out << "  \"address\": \"0x" << std::hex << address << "\"\n";
            out << "}\n";
            out.close(); // CRITICAL: Flush to disk so Python watchdog can read it!
        }
        std::cout << "[!] Emitted API generation request to " << request_file << "\n";
        std::cout << "[*] C++ Engine Paused: Waiting for LLM API Compiler...\n";
        
        while (!std::filesystem::exists(dylib_path)) {
            usleep(250000); // Wait 0.25 seconds
        }
    }
    
    // Now load and execute directly!
    if (try_load_dylib(api_name)) {
        dylib_funcs[api_name](&ctx);
    } else {
        std::cerr << "[!] CRITICAL: Failed to load generated mock for " << api_name << "\n";
        uc_emu_stop(ctx.uc);
    }
}

void DummyAPIHandler::hook_api_call(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    DummyAPIHandler* handler = static_cast<DummyAPIHandler*>(user_data);
    
    auto it = handler->fake_api_map.find(address);
    if (it != handler->fake_api_map.end()) {
        const std::string& name = it->second;
        bool known = (KNOWN_SIGNATURES.find(name) != KNOWN_SIGNATURES.end());
        
        if (known) {
            std::cout << "\n[API CALL] [OK] Intercepted call to " << name << std::endl;
        } else {
            if (handler->try_load_dylib(name)) {
                std::cout << "\n[API CALL] [JIT MOCK] Redirecting to " << name << std::endl;
                // Dispatch to C++ JIT Mock!
                handler->dylib_funcs[name](&handler->ctx);
            } else {
                std::cout << "\n[API CALL] [UNKNOWN] Calling LLM API Compiler for " << name << std::endl;
                handler->handle_unknown_api(name, address);
            }
        }
    }
}

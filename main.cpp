#include "pe_loader.hpp"
#include "windows_env.hpp"
#include "api_handler.hpp"
#include <capstone/capstone.h>
#include <iostream>
#include <set>
#include <vector>
#include <unordered_map>
#include <string>
#include <fstream>
#include <iomanip>
#include <filesystem>
#include <SDL.h>

#if defined(__APPLE__) && defined(__aarch64__)
#include <sys/mman.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>
#endif

using namespace std;

// Capstone handle for LVA
csh cs_handle;

const char* reg_name_str(uint32_t reg_id) {
    const char* name = cs_reg_name(cs_handle, reg_id);
    return name ? name : "unknown";
}

struct BlockProfile {
    uint32_t execution_count = 0;
    uint32_t size = 0;
    vector<string> assembly;
    vector<string> live_in;
    vector<string> live_out;
    bool is_jitted = false;
};

// Global registry mapping Address -> Block Metadata
unordered_map<uint64_t, BlockProfile> block_registry;
const uint32_t JIT_THRESHOLD = 50; 

// ====== JIT DISPATCHER (Apple Silicon) ======

class JITDispatcher {
private:
    uint8_t* memory_pool;
    size_t pool_size;
    size_t current_offset;
    unordered_map<uint64_t, void*> compiled_blocks;

public:
    JITDispatcher(size_t size = 1024 * 1024 * 16) : pool_size(size), current_offset(0) {
#if defined(__APPLE__) && defined(__aarch64__)
        memory_pool = (uint8_t*)mmap(NULL, pool_size, 
                                     PROT_READ | PROT_WRITE | PROT_EXEC, 
                                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, 
                                     -1, 0);
        if (memory_pool == MAP_FAILED) {
            cerr << "[!] JIT mmap failed. Ensure you have the com.apple.security.cs.allow-jit entitlement." << endl;
            exit(1);
        }
#else
        cerr << "[!] JIT Dispatcher currently only supports Apple Silicon macOS." << endl;
        exit(1);
#endif
    }

    ~JITDispatcher() {
#if defined(__APPLE__) && defined(__aarch64__)
        munmap(memory_pool, pool_size);
#endif
    }

    bool load_compiled_block(uint64_t address) {
        char buf[128];
        snprintf(buf, sizeof(buf), "compiled_blocks/block_0x%llx.bin", (unsigned long long)address);
        ifstream file(buf, ios::binary | ios::ate);
        if (!file.is_open()) return false;
        
        streamsize size = file.tellg();
        file.seekg(0, ios::beg);

        if (current_offset + size > pool_size) {
            cerr << "[!] JIT Memory Pool Exhausted!" << endl;
            return false;
        }

        vector<char> buffer(size);
        if (file.read(buffer.data(), size)) {
#if defined(__APPLE__) && defined(__aarch64__)
            // macOS W^X Bypass: Open Write Access
            pthread_jit_write_protect_np(0);
            
            void* exec_ptr = memory_pool + current_offset;
            memcpy(exec_ptr, buffer.data(), size);
            
            // Clean Cache
            sys_icache_invalidate(exec_ptr, size);
            
            // macOS W^X Bypass: Lock Write, Open Exec Access
            pthread_jit_write_protect_np(1);
            
            compiled_blocks[address] = exec_ptr;
            current_offset += size;
            
            // Align to 4 bytes (ARM64 instruction size)
            if (current_offset % 4 != 0) current_offset += (4 - (current_offset % 4));
            
            return true;
#endif
        }
        return false;
    }

    bool execute_block(uint64_t address, uc_engine *uc) {
        if (compiled_blocks.find(address) != compiled_blocks.end()) {
            void (*func)() = (void (*)())compiled_blocks[address];
            
            cout << "  -> [JIT EXEC] Redirecting to ARM64 Block at 0x" << hex << address << dec << "\n";
            
            // 1. Read Unicorn State
            uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, eip;
            uc_reg_read(uc, UC_X86_REG_EAX, &eax);
            uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
            uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
            uc_reg_read(uc, UC_X86_REG_EDX, &edx);
            uc_reg_read(uc, UC_X86_REG_ESI, &esi);
            uc_reg_read(uc, UC_X86_REG_EDI, &edi);
            uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
            uc_reg_read(uc, UC_X86_REG_ESP, &esp);
            uc_reg_read(uc, UC_X86_REG_EIP, &eip);

            // 2. Perform Context Switch & Execute!
#if defined(__APPLE__) && defined(__aarch64__)
            __asm__ volatile (
                "mov w0, %w[eax]\n"
                "mov w1, %w[ecx]\n"
                "mov w2, %w[edx]\n"
                "mov w3, %w[ebx]\n"
                "mov w4, %w[esp]\n"
                "mov w5, %w[ebp]\n"
                "mov w6, %w[esi]\n"
                "mov w7, %w[edi]\n"
                "mov w8, %w[eip]\n"
                
                "blr %[func]\n" // Call JIT Function!

                "mov %w[eax], w0\n"
                "mov %w[ecx], w1\n"
                "mov %w[edx], w2\n"
                "mov %w[ebx], w3\n"
                "mov %w[esp], w4\n"
                "mov %w[ebp], w5\n"
                "mov %w[esi], w6\n"
                "mov %w[edi], w7\n"
                "mov %w[eip], w8\n"
                
                : [eax] "+r" (eax), [ecx] "+r" (ecx), [edx] "+r" (edx), [ebx] "+r" (ebx),
                  [esp] "+r" (esp), [ebp] "+r" (ebp), [esi] "+r" (esi), [edi] "+r" (edi), [eip] "+r" (eip)
                : [func] "r" (func)
                : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x30", "memory", "cc" // x30 is LR
            );
#endif

            // 3. Write modified state back to Unicorn
            uc_reg_write(uc, UC_X86_REG_EAX, &eax);
            uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
            uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
            uc_reg_write(uc, UC_X86_REG_EDX, &edx);
            uc_reg_write(uc, UC_X86_REG_ESI, &esi);
            uc_reg_write(uc, UC_X86_REG_EDI, &edi);
            uc_reg_write(uc, UC_X86_REG_EBP, &ebp);
            uc_reg_write(uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(uc, UC_X86_REG_EIP, &eip);

            return true;
        }
        return false;
    }
};

JITDispatcher* global_jit;

// ============================================


void dump_jit_request(uint64_t address, const BlockProfile& profile) {
    char buf[64];
    snprintf(buf, sizeof(buf), "jit_requests/block_0x%llx.json", (unsigned long long)address);
    string filename = buf;

    ofstream out(filename);
    if (!out.is_open()) return;

    out << "{\n";
    out << "  \"address\": \"0x" << hex << address << dec << "\",\n";
    out << "  \"size\": " << profile.size << ",\n";
    out << "  \"assembly\": [\n";
    for (size_t i = 0; i < profile.assembly.size(); ++i) {
        out << "    \"" << profile.assembly[i] << "\"";
        if (i < profile.assembly.size() - 1) out << ",";
        out << "\n";
    }
    out << "  ],\n";
    out << "  \"live_in\": [\n";
    for (size_t i = 0; i < profile.live_in.size(); ++i) {
        out << "    \"" << profile.live_in[i] << "\"";
        if (i < profile.live_in.size() - 1) out << ",";
        out << "\n";
    }
    out << "  ],\n";
    out << "  \"live_out\": [\n";
    for (size_t i = 0; i < profile.live_out.size(); ++i) {
        out << "    \"" << profile.live_out[i] << "\"";
        if (i < profile.live_out.size() - 1) out << ",";
        out << "\n";
    }
    out << "  ]\n}\n";
}

struct BlockTrace { uint64_t addr; uint32_t esp; };
BlockTrace last_blocks[50];
int block_idx = 0;



// Basic Block Hook for Capstone Live-Variable Analysis (LVA)
void hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    if (address >= 0x801fe81c && address < 0x801fe81c + 4) {
        uint32_t pc;
        uc_reg_read(uc, UC_X86_REG_EIP, &pc);
        std::cout << "\n[WATCHPOINT] Memory write at 0x" << std::hex << address 
                  << " with value 0x" << value << " from EIP 0x" << pc << std::dec << "\n";
    }
}

void hook_block_lva(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint32_t current_esp;
    uc_reg_read(uc, UC_X86_REG_ESP, &current_esp);
    last_blocks[block_idx % 50] = {address, current_esp};
    block_idx++;

    if (address >= DummyAPIHandler::FAKE_API_BASE) {
        return; 
    }

    auto& profile = block_registry[address];
    profile.execution_count++;

    // Try JIT Execution first if available
    // if (profile.is_jitted) {
    //    if (global_jit->execute_block(address, uc)) {
    //        // Stop unicorn so it doesn't execute the x86 block we just ran natively
    //        uc_emu_stop(uc);
    //    }
    //    return;
    // }

    // Only disassemble and calculate LVA on the VERY FIRST visit to this block.
    if (profile.execution_count == 1) {
        profile.size = size;
        vector<uint8_t> code(size);
        uc_err err = uc_mem_read(uc, address, code.data(), size);
        if (err) return;

        cs_insn *insn;
        size_t count = cs_disasm(cs_handle, code.data(), size, address, 0, &insn);
        
        set<uint32_t> live_in_set;
        set<uint32_t> live_out_set;

        if (count > 0) {
            for (size_t i = 0; i < count; i++) {
                string asmA = insn[i].mnemonic;
                string asmB = insn[i].op_str;
                profile.assembly.push_back(asmA + (asmB.empty() ? "" : " ") + asmB);
                
                cs_regs regs_read, regs_write;
                uint8_t read_count, write_count;
                
                if (cs_regs_access(cs_handle, &insn[i], regs_read, &read_count, regs_write, &write_count) == CS_ERR_OK) {
                    for (uint8_t j = 0; j < read_count; j++) {
                        if (live_out_set.find(regs_read[j]) == live_out_set.end()) {
                            live_in_set.insert(regs_read[j]);
                        }
                    }
                    for (uint8_t j = 0; j < write_count; j++) {
                        live_out_set.insert(regs_write[j]);
                    }
                }
            }
            cs_free(insn, count);
            
            for (auto r : live_in_set) profile.live_in.push_back(reg_name_str(r));
            for (auto r : live_out_set) profile.live_out.push_back(reg_name_str(r));
        }
    }

    // Dump payload when it hits the hot threshold
    if (profile.execution_count == JIT_THRESHOLD) {
        dump_jit_request(address, profile);
    }
    
    // Check if JIT translation has finished in the background (File `.bin` exists)
    if (profile.execution_count > JIT_THRESHOLD && !profile.is_jitted) {
        if (global_jit->load_compiled_block(address)) {
            profile.is_jitted = true;
            cout << "[+] JIT Dispatcher Linked ARM64 Block at 0x" << hex << address << dec << endl;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <PE file>" << endl;
        return 1;
    }

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS) != 0) {
        cerr << "[!] SDL2 Initialization failed: " << SDL_GetError() << endl;
        return 1;
    }

    SDL_Window* window = SDL_CreateWindow(
        "PvZ Hybrid Emulator",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        800, 600,
        SDL_WINDOW_SHOWN
    );

    if (!window) {
        cerr << "[!] SDL Window creation failed: " << SDL_GetError() << endl;
        SDL_Quit();
        return 1;
    }

    SDL_Renderer* renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        cerr << "[!] SDL accelerated renderer failed (" << SDL_GetError()
             << "), falling back to software renderer." << endl;
        renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_SOFTWARE);
    }
    if (!renderer) {
        cerr << "[!] SDL Renderer creation failed: " << SDL_GetError() << endl;
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }

    SDL_Texture* texture = SDL_CreateTexture(
        renderer,
        SDL_PIXELFORMAT_ARGB8888,
        SDL_TEXTUREACCESS_STREAMING,
        800, 600
    );
    if (!texture) {
        cerr << "[!] SDL Texture creation failed: " << SDL_GetError() << endl;
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }

    uint32_t guest_vram = 0xA0000000;
    
    uint32_t* host_vram = new uint32_t[800 * 600];
    memset(host_vram, 0, 800 * 600 * 4);

    // Initialize Capstone (DETAIL mode ON for LVA)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) return 1;
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Initialize Unicorn
    uc_engine *uc;
    if (uc_open(UC_ARCH_X86, UC_MODE_32, &uc)) return 1;

    // Map Guest VRAM
    uc_mem_map(uc, guest_vram, 800 * 600 * 4, UC_PROT_ALL);

    try {
        global_jit = new JITDispatcher();

        PEModule pe_module(argv[1]);
        WindowsEnvironment env(uc);
        DummyAPIHandler api_handler(uc);
        std::error_code path_ec;
        std::filesystem::path exe_path(argv[1]);
        std::filesystem::path exe_abs = std::filesystem::absolute(exe_path, path_ec);
        std::filesystem::path exe_dir = path_ec ? exe_path.parent_path() : exe_abs.parent_path();
        if (exe_dir.empty()) exe_dir = std::filesystem::current_path();
        api_handler.set_process_base_dir(exe_dir.string());
        cout << "[*] Process base dir: " << exe_dir.string() << "\n";
        api_handler.set_sdl_window(window);
        api_handler.set_sdl_renderer(renderer);
        api_handler.set_sdl_texture(texture);
        api_handler.set_guest_vram(guest_vram);
        api_handler.set_host_vram(host_vram);

        pe_module.map_into(uc);
        pe_module.resolve_imports(uc, api_handler);
        env.setup_system();

        uc_hook hook1, hook_mem;
        uc_hook_add(uc, &hook1, UC_HOOK_BLOCK, (void*)hook_block_lva, nullptr, 1, 0);
        uc_hook_add(uc, &hook_mem, UC_HOOK_MEM_WRITE, (void*)hook_mem_write, nullptr, 1, 0);

        cout << "\n[*] Starting C++ Engine Emulation at 0x" << hex << pe_module.entry_point << "...\n";
        
        uint32_t test_val;
        uc_err test_err = uc_mem_read(uc, 0x38b, &test_val, 4);
        if (test_err == UC_ERR_OK) {
            std::cout << "[!!!] ALERT: 0x38b IS MAPPED!!! Val: " << test_val << "\n";
        } else {
            std::cout << "[!!!] ALERT: 0x38b IS NOT MAPPED!!!\n";
        }

        cout << "[*] Profiler Active. JIT Memory Dispatcher Ready.\n";
        
        uint32_t pc = pe_module.entry_point;
        while (true) {
            uc_err err = uc_emu_start(uc, pc, 0, 0, 0);
            if (err) {
                std::cerr << "\n[!] Emulation stopped due to error: " << uc_strerror(err) << " (Code: " << err << ")\n";
                uint32_t val;
                uc_reg_read(uc, UC_X86_REG_EIP, &val); std::cerr << "[!] EIP = 0x" << std::hex << val << std::dec << "\n";
                uc_reg_read(uc, UC_X86_REG_EAX, &val); std::cerr << "EAX=0x" << std::hex << val << " ";
                uc_reg_read(uc, UC_X86_REG_EBX, &val); std::cerr << "EBX=0x" << std::hex << val << " ";
                uc_reg_read(uc, UC_X86_REG_ECX, &val); std::cerr << "ECX=0x" << std::hex << val << " ";
                uc_reg_read(uc, UC_X86_REG_EDX, &val); std::cerr << "EDX=0x" << std::hex << val << "\n";
                uint32_t esi, edi, esp, ebp;
                uc_reg_read(uc, UC_X86_REG_ESI, &esi);
                uc_reg_read(uc, UC_X86_REG_EDI, &edi);
                uc_reg_read(uc, UC_X86_REG_ESP, &esp);
                uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
                std::cerr << "ESI=0x" << std::hex << esi << " EDI=0x" << edi << " ESP=0x" << esp << " EBP=0x" << ebp << "\n";
        
                std::cerr << "--- Stack Dump ---\n";
                for (int i = 0; i < 8; i++) {
                    uint32_t stack_val = 0;
                    uc_err mem_err = uc_mem_read(uc, esp + (i * 4), &stack_val, 4);
                    if (mem_err == UC_ERR_OK) {
                        std::cerr << "  [ESP+" << std::hex << (i*4) << "] = 0x" << stack_val << "\n";
                    } else {
                        std::cerr << "  [ESP+" << std::hex << (i*4) << "] = UNMAPPED (" << uc_strerror(mem_err) << ")\n";
                    }
                }
                std::cerr << "------------------\n";
                
                cout << "--- Last 50 Basic Blocks Executed ---\n";
                int start_idx = block_idx > 50 ? block_idx - 50 : 0;
                for (int i = start_idx; i < block_idx; i++) {
                    cout << "  ADDR: 0x" << hex << last_blocks[i % 50].addr 
                         << "   ESP: 0x" << last_blocks[i % 50].esp << dec << "\n";
                }
                break;
            }
            uc_reg_read(uc, UC_X86_REG_EIP, &pc);
            
            if (pc == 0 || pc == 0xffffffff) {
                cout << "\n[+] Emulation cleanly finished at EIP = 0x" << hex << pc << endl;
                cout << "--- Last 50 Basic Blocks Executed ---\n";
                int start_idx = block_idx > 50 ? block_idx - 50 : 0;
                for (int i = start_idx; i < block_idx; i++) {
                    cout << "  ADDR: 0x" << hex << last_blocks[i % 50].addr 
                         << "   ESP: 0x" << last_blocks[i % 50].esp << dec << "\n";
                }
                break; 
            }
        }

    } catch (const exception& e) {
        cerr << "Exception caught: " << e.what() << endl;
    }

    delete global_jit;
    uc_close(uc);
    cs_close(&cs_handle);
    
    delete[] host_vram;
    SDL_DestroyTexture(texture);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}

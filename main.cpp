#include "pe_loader.hpp"
#include "windows_env.hpp"
#include "api_handler.hpp"
#include "backend/unicorn_backend.hpp"
#include "backend/fexcore_backend.hpp"
#include <capstone/capstone.h>
#include <iostream>
#include <algorithm>
#include <set>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <fstream>
#include <iomanip>
#include <filesystem>
#include <cstdlib>
#include <cctype>
#include <sstream>
#include <limits>
#include <SDL.h>
#include <sys/resource.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#include <sys/mman.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>
#endif

using namespace std;

static bool env_truthy(const char* name) {
    const char* v = std::getenv(name);
    if (!v) return false;
    std::string s(v);
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return !(s.empty() || s == "0" || s == "false" || s == "off" || s == "no");
}

static int env_int(const char* name, int default_value) {
    const char* v = std::getenv(name);
    if (!v || !*v) return default_value;
    char* end = nullptr;
    long parsed = std::strtol(v, &end, 10);
    if (!end || *end != '\0') return default_value;
    if (parsed > std::numeric_limits<int>::max()) return std::numeric_limits<int>::max();
    if (parsed < std::numeric_limits<int>::min()) return std::numeric_limits<int>::min();
    return static_cast<int>(parsed);
}

static bool parse_u32_auto(const std::string& token, uint32_t& out) {
    if (token.empty()) return false;
    char* end = nullptr;
    unsigned long parsed = std::strtoul(token.c_str(), &end, 0);
    if (!end || *end != '\0') return false;
    if (parsed > 0xFFFFFFFFul) return false;
    out = static_cast<uint32_t>(parsed);
    return true;
}

static std::vector<uint32_t> parse_u32_list_csv(const char* raw) {
    std::vector<uint32_t> out;
    if (!raw) return out;
    std::stringstream ss(raw);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        auto first = tok.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        auto last = tok.find_last_not_of(" \t\r\n");
        std::string trimmed = tok.substr(first, last - first + 1);
        uint32_t v = 0;
        if (parse_u32_auto(trimmed, v)) {
            out.push_back(v);
        }
    }
    return out;
}

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

    bool execute_block(uint64_t address, CpuBackend& backend) {
        if (compiled_blocks.find(address) != compiled_blocks.end()) {
            void (*func)() = (void (*)())compiled_blocks[address];
            
            cout << "  -> [JIT EXEC] Redirecting to ARM64 Block at 0x" << hex << address << dec << "\n";
            
            // 1. Read Unicorn State
            uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, eip;
            backend.reg_read(UC_X86_REG_EAX, &eax);
            backend.reg_read(UC_X86_REG_EBX, &ebx);
            backend.reg_read(UC_X86_REG_ECX, &ecx);
            backend.reg_read(UC_X86_REG_EDX, &edx);
            backend.reg_read(UC_X86_REG_ESI, &esi);
            backend.reg_read(UC_X86_REG_EDI, &edi);
            backend.reg_read(UC_X86_REG_EBP, &ebp);
            backend.reg_read(UC_X86_REG_ESP, &esp);
            backend.reg_read(UC_X86_REG_EIP, &eip);

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
            backend.reg_write(UC_X86_REG_EAX, &eax);
            backend.reg_write(UC_X86_REG_EBX, &ebx);
            backend.reg_write(UC_X86_REG_ECX, &ecx);
            backend.reg_write(UC_X86_REG_EDX, &edx);
            backend.reg_write(UC_X86_REG_ESI, &esi);
            backend.reg_write(UC_X86_REG_EDI, &edi);
            backend.reg_write(UC_X86_REG_EBP, &ebp);
            backend.reg_write(UC_X86_REG_ESP, &esp);
            backend.reg_write(UC_X86_REG_EIP, &eip);

            return true;
        }
        return false;
    }
};

JITDispatcher* global_jit;
bool g_enable_native_jit = true;
bool g_enable_llm_pipeline = false;
CpuBackend* g_backend = nullptr;
bool g_watchpoint_enabled = false;
bool g_vram_present_hook_enabled = true;
int g_max_jit_llm_requests = 24;
int g_jit_llm_requests_emitted = 0;
bool g_jit_budget_warned = false;
bool g_profile_blocks = false;
size_t g_max_profile_blocks = 250000;
bool g_profile_cap_warned = false;
uint64_t g_tb_flush_interval_blocks = 0;
uint64_t g_tb_flush_counter = 0;
bool g_tb_flush_warned = false;
uint64_t g_rss_guard_max_mb = 0;
uint64_t g_rss_guard_check_interval_blocks = 20000;
uint64_t g_rss_guard_counter = 0;
uint64_t g_rss_guard_last_mb = 0;
bool g_rss_guard_triggered = false;
bool g_block_hot_sample_enabled = false;
uint64_t g_block_hot_interval = 0;
uint64_t g_block_hot_counter = 0;
size_t g_block_hot_cap = 8192;
uint64_t g_block_hot_dropped = 0;
unordered_map<uint32_t, uint64_t> g_block_hot_hits;
bool g_block_focus_trace_enabled = false;
uint64_t g_block_focus_interval = 50000;
size_t g_block_focus_dump_bytes = 24;
unordered_set<uint32_t> g_block_focus_addrs;
unordered_map<uint32_t, uint64_t> g_block_focus_hits;
bool g_hot_loop_accel_enabled = false;
uint64_t g_hot_loop_accel_hits = 0;
uint64_t g_hot_loop_accel_bytes = 0;
uint32_t g_guest_vram_base = 0;
size_t g_guest_vram_size = 0;
uint32_t* g_host_vram_ptr = nullptr;
SDL_Renderer* g_renderer_ptr = nullptr;
SDL_Texture* g_texture_ptr = nullptr;
uint64_t g_vram_write_counter = 0;
uint64_t g_vram_present_stride = 20000;
uint32_t g_last_vram_present_ms = 0;
bool g_vram_present_logged = false;

static uint64_t current_rss_mb() {
#if defined(__APPLE__)
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS) {
        return static_cast<uint64_t>(info.resident_size / (1024ull * 1024ull));
    }
#endif
    struct rusage usage {};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#if defined(__APPLE__)
        // macOS reports ru_maxrss in bytes.
        return static_cast<uint64_t>(usage.ru_maxrss / (1024ull * 1024ull));
#else
        // Linux reports ru_maxrss in KiB.
        return static_cast<uint64_t>(usage.ru_maxrss / 1024ull);
#endif
    }
    return 0;
}

static void maybe_print_block_hot_stats() {
    if (!g_block_hot_sample_enabled || g_block_hot_interval == 0) return;
    if (g_block_hot_counter == 0 || (g_block_hot_counter % g_block_hot_interval) != 0) return;
    vector<pair<uint32_t, uint64_t>> items(g_block_hot_hits.begin(), g_block_hot_hits.end());
    if (items.empty()) return;
    sort(items.begin(), items.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    cout << "[BLOCK HOT] top_addrs:";
    size_t limit = min<size_t>(12, items.size());
    for (size_t i = 0; i < limit; ++i) {
        cout << " [0x" << hex << items[i].first << dec << ":" << items[i].second << "]";
    }
    if (g_block_hot_dropped > 0) {
        cout << " dropped=" << g_block_hot_dropped;
    }
    cout << "\n";
}

static void print_focus_mem_sample(const char* label, uint32_t addr, size_t bytes) {
    if (!g_backend || addr < 0x1000 || bytes == 0) return;
    vector<uint8_t> buf(bytes, 0);
    if (g_backend->mem_read(addr, buf.data(), bytes) != UC_ERR_OK) return;
    cout << " " << label << "=[";
    for (size_t i = 0; i < bytes; ++i) {
        if (i) cout << ' ';
        cout << hex << setw(2) << setfill('0') << static_cast<unsigned>(buf[i]);
    }
    cout << dec << setfill(' ') << "]";
}

static void maybe_print_block_focus(uint32_t addr32) {
    if (!g_block_focus_trace_enabled || g_block_focus_addrs.find(addr32) == g_block_focus_addrs.end()) return;
    uint64_t& hits = g_block_focus_hits[addr32];
    hits++;
    if (g_block_focus_interval == 0 || (hits % g_block_focus_interval) != 0) return;

    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0, esi = 0, edi = 0, esp = 0;
    g_backend->reg_read(UC_X86_REG_EAX, &eax);
    g_backend->reg_read(UC_X86_REG_EBX, &ebx);
    g_backend->reg_read(UC_X86_REG_ECX, &ecx);
    g_backend->reg_read(UC_X86_REG_EDX, &edx);
    g_backend->reg_read(UC_X86_REG_ESI, &esi);
    g_backend->reg_read(UC_X86_REG_EDI, &edi);
    g_backend->reg_read(UC_X86_REG_ESP, &esp);

    cout << "[BLOCK FOCUS] addr=0x" << hex << addr32 << dec
         << " hit=" << hits
         << " eax=0x" << hex << eax
         << " ebx=0x" << ebx
         << " ecx=0x" << ecx
         << " edx=0x" << edx
         << " esi=0x" << esi
         << " edi=0x" << edi
         << " esp=0x" << esp << dec;

    size_t bytes = max<size_t>(1, g_block_focus_dump_bytes);
    if (addr32 == 0x404470u) {
        print_focus_mem_sample("eax", eax, bytes);
    } else if (addr32 == 0x441a73u || addr32 == 0x441a79u) {
        print_focus_mem_sample("ecx", ecx, bytes);
        print_focus_mem_sample("edx", edx, bytes);
    } else if (addr32 == 0x5d8890u) {
        print_focus_mem_sample("ecx", ecx, bytes);
        print_focus_mem_sample("edx", edx, bytes);
    } else if (addr32 == 0x62456au) {
        print_focus_mem_sample("esi", esi, bytes);
        print_focus_mem_sample("edi", edi, bytes);
    } else {
        print_focus_mem_sample("ecx", ecx, bytes);
        print_focus_mem_sample("edx", edx, bytes);
    }
    cout << "\n";
}

static bool accelerate_xor_copy_loop(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x5d888cu && addr32 != 0x5d8890u) return false;

    uint32_t ecx = 0, edx = 0, esi = 0, edi = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    uc_reg_read(uc, UC_X86_REG_ESI, &esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &edi);

    uint32_t count = (addr32 == 0x5d888cu) ? edi : esi;
    if (count > (1u << 24)) return false;

    if (count > 0) {
        vector<uint8_t> buf(count, 0);
        if (g_backend->mem_read(ecx, buf.data(), count) != UC_ERR_OK) return false;
        for (uint8_t& b : buf) b ^= 0xF7u;
        if (g_backend->mem_write(edx, buf.data(), count) != UC_ERR_OK) return false;

        uint32_t eax = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        eax = (eax & 0xFFFFFF00u) | static_cast<uint32_t>(buf.back());
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    }

    ecx += count;
    edx += count;
    esi = 0;
    uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &edx);
    uc_reg_write(uc, UC_X86_REG_ESI, &esi);

    uint32_t eip = 0x5d88a1u;
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += count;
    return true;
}

static bool accelerate_rep_movsd(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x62456au) return false;

    uint32_t ecx = 0, esi = 0, edi = 0, eflags = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_ESI, &esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &edi);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    if ((eflags & 0x400u) != 0) return false; // DF=1 path not accelerated

    uint64_t byte_count64 = static_cast<uint64_t>(ecx) * 4ull;
    if (byte_count64 == 0) {
        uint32_t eip = 0x62456cu;
        uc_reg_write(uc, UC_X86_REG_EIP, &eip);
        uc_emu_stop(uc);
        g_hot_loop_accel_hits++;
        return true;
    }
    if (byte_count64 > (1ull << 27)) return false;
    size_t byte_count = static_cast<size_t>(byte_count64);

    vector<uint8_t> buf(byte_count, 0);
    if (g_backend->mem_read(esi, buf.data(), byte_count) != UC_ERR_OK) return false;
    if (g_backend->mem_write(edi, buf.data(), byte_count) != UC_ERR_OK) return false;

    esi += static_cast<uint32_t>(byte_count);
    edi += static_cast<uint32_t>(byte_count);
    ecx = 0;
    uc_reg_write(uc, UC_X86_REG_ESI, &esi);
    uc_reg_write(uc, UC_X86_REG_EDI, &edi);
    uc_reg_write(uc, UC_X86_REG_ECX, &ecx);

    uint32_t eip = 0x62456cu;
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += byte_count;
    return true;
}

static bool accelerate_memcmp_dword_loop(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x441a73u) return false;

    uint32_t eax = 0, ecx = 0, edx = 0, esi = 0;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    uc_reg_read(uc, UC_X86_REG_ESI, &esi);
    if (eax < 4) return false;

    uint32_t remaining = eax;
    uint32_t last_word = esi;
    while (remaining >= 4) {
        uint32_t lhs = 0;
        uint32_t rhs = 0;
        if (g_backend->mem_read(edx, &lhs, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_read(ecx, &rhs, 4) != UC_ERR_OK) return false;

        last_word = lhs;
        if (lhs != rhs) {
            uc_reg_write(uc, UC_X86_REG_ESI, &lhs);
            uint32_t eip = 0x441a8bu;
            uc_reg_write(uc, UC_X86_REG_EIP, &eip);
            uc_emu_stop(uc);
            g_hot_loop_accel_hits++;
            return true;
        }

        remaining -= 4;
        ecx += 4;
        edx += 4;
    }

    uc_reg_write(uc, UC_X86_REG_EAX, &remaining);
    uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &edx);
    uc_reg_write(uc, UC_X86_REG_ESI, &last_word);
    uint32_t eip = 0x441a87u;
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += static_cast<uint64_t>(eax - remaining);
    return true;
}

static bool accelerate_strlen_loop(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x404470u) return false;

    uint32_t eax = 0;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    if (eax < 0x1000u) return false;
    uint32_t start = eax;

    constexpr size_t kChunk = 4096;
    vector<uint8_t> buf(kChunk, 0);
    uint32_t cursor = eax;
    while (true) {
        if (g_backend->mem_read(cursor, buf.data(), buf.size()) != UC_ERR_OK) return false;
        auto it = std::find(buf.begin(), buf.end(), 0u);
        if (it != buf.end()) {
            size_t offset = static_cast<size_t>(std::distance(buf.begin(), it));
            eax = cursor + static_cast<uint32_t>(offset) + 1u; // loop exits after add eax,1 on NUL
            uc_reg_write(uc, UC_X86_REG_EAX, &eax);

            uint32_t ecx = 0;
            uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
            ecx = (ecx & 0xFFFFFF00u); // cl=0
            uc_reg_write(uc, UC_X86_REG_ECX, &ecx);

            uint32_t eip = 0x404479u;
            uc_reg_write(uc, UC_X86_REG_EIP, &eip);
            uc_emu_stop(uc);

            g_hot_loop_accel_hits++;
            g_hot_loop_accel_bytes += static_cast<uint64_t>(eax - start);
            return true;
        }
        cursor += static_cast<uint32_t>(buf.size());
    }
}

static bool maybe_accelerate_hot_loop_block(uc_engine* uc, uint32_t addr32) {
    if (!g_hot_loop_accel_enabled) return false;
    if (accelerate_xor_copy_loop(uc, addr32)) return true;
    if (accelerate_rep_movsd(uc, addr32)) return true;
    if (accelerate_memcmp_dword_loop(uc, addr32)) return true;
    if (accelerate_strlen_loop(uc, addr32)) return true;
    return false;
}

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
    if (g_vram_present_hook_enabled &&
        g_backend &&
        g_guest_vram_base != 0 &&
        g_guest_vram_size != 0 &&
        g_host_vram_ptr &&
        g_renderer_ptr &&
        g_texture_ptr &&
        address >= g_guest_vram_base &&
        address < (g_guest_vram_base + g_guest_vram_size)) {
        g_vram_write_counter++;
        uint32_t now = SDL_GetTicks();
        if ((g_vram_write_counter % g_vram_present_stride) == 0 && (now - g_last_vram_present_ms) >= 16) {
            if (g_backend->mem_read(g_guest_vram_base, g_host_vram_ptr, g_guest_vram_size) == UC_ERR_OK) {
                SDL_UpdateTexture(g_texture_ptr, nullptr, g_host_vram_ptr, 800 * 4);
                SDL_RenderClear(g_renderer_ptr);
                SDL_RenderCopy(g_renderer_ptr, g_texture_ptr, nullptr, nullptr);
                SDL_RenderPresent(g_renderer_ptr);
                if (!g_vram_present_logged) {
                    std::cout << "[*] VRAM present hook active.\n";
                    g_vram_present_logged = true;
                }
                g_last_vram_present_ms = now;
            }
        }
    }

    if (!g_watchpoint_enabled) return;
    if (address >= 0x801fe81c && address < 0x801fe81c + 4) {
        if (!g_backend) return;
        uint32_t pc;
        g_backend->reg_read(UC_X86_REG_EIP, &pc);
        std::cout << "\n[WATCHPOINT] Memory write at 0x" << std::hex << address 
                  << " with value 0x" << value << " from EIP 0x" << pc << std::dec << "\n";
    }
}

void hook_block_lva(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    if (!g_backend) return;
    uint32_t current_esp;
    g_backend->reg_read(UC_X86_REG_ESP, &current_esp);
    last_blocks[block_idx % 50] = {address, current_esp};
    block_idx++;

    if (g_block_hot_sample_enabled) {
        g_block_hot_counter++;
        uint32_t addr32 = static_cast<uint32_t>(address);
        auto it_hot = g_block_hot_hits.find(addr32);
        if (it_hot != g_block_hot_hits.end()) {
            it_hot->second++;
        } else if (g_block_hot_hits.size() >= g_block_hot_cap) {
            g_block_hot_dropped++;
        } else {
            g_block_hot_hits.emplace(addr32, 1);
        }
        maybe_print_block_hot_stats();
    }
    maybe_print_block_focus(static_cast<uint32_t>(address));
    if (maybe_accelerate_hot_loop_block(uc, static_cast<uint32_t>(address))) {
        if ((g_hot_loop_accel_hits % 50000u) == 0u) {
            cout << "[HOT ACCEL] hits=" << g_hot_loop_accel_hits
                 << " bytes=" << g_hot_loop_accel_bytes << "\n";
        }
        return;
    }

    if (g_tb_flush_interval_blocks > 0) {
        g_tb_flush_counter++;
        if ((g_tb_flush_counter % g_tb_flush_interval_blocks) == 0) {
            uc_err flush_err = g_backend->flush_tb_cache();
            if (flush_err != UC_ERR_OK && !g_tb_flush_warned) {
                g_tb_flush_warned = true;
                std::cerr << "[!] TB cache flush failed: " << g_backend->strerror(flush_err)
                          << " (Code: " << flush_err << ")\n";
            }
        }
    }
    if (g_rss_guard_max_mb > 0) {
        g_rss_guard_counter++;
        if ((g_rss_guard_counter % g_rss_guard_check_interval_blocks) == 0) {
            g_rss_guard_last_mb = current_rss_mb();
            if (g_rss_guard_last_mb >= g_rss_guard_max_mb) {
                std::cerr << "[!] RSS guard triggered: " << g_rss_guard_last_mb
                          << "MB >= " << g_rss_guard_max_mb
                          << "MB (PVZ_MAX_RSS_MB). Stopping emulation.\n";
                g_rss_guard_triggered = true;
                g_backend->emu_stop();
                return;
            }
        }
    }

    if (address >= DummyAPIHandler::FAKE_API_BASE) {
        return; 
    }

    if (!g_profile_blocks) {
        return;
    }

    auto it = block_registry.find(address);
    if (it == block_registry.end()) {
        if (g_max_profile_blocks > 0 && block_registry.size() >= g_max_profile_blocks) {
            if (!g_profile_cap_warned) {
                g_profile_cap_warned = true;
                cout << "[*] Block profiling cap reached (" << g_max_profile_blocks
                     << "). Skipping new block metadata collection.\n";
            }
            return;
        }
        it = block_registry.emplace(address, BlockProfile{}).first;
    }
    auto& profile = it->second;
    profile.execution_count++;

    // Try JIT Execution first if available
    // if (profile.is_jitted) {
    //    if (global_jit->execute_block(address, *g_backend)) {
    //        // Stop backend so it doesn't execute the x86 block we just ran natively
    //        g_backend->emu_stop();
    //    }
    //    return;
    // }

    // Only disassemble and calculate LVA on the VERY FIRST visit to this block.
    if (profile.execution_count == 1) {
        profile.size = size;
        vector<uint8_t> code(size);
        uc_err err = g_backend->mem_read(address, code.data(), size);
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
    if (g_enable_llm_pipeline && profile.execution_count == JIT_THRESHOLD) {
        bool budget_ok = (g_max_jit_llm_requests < 0) || (g_jit_llm_requests_emitted < g_max_jit_llm_requests);
        if (budget_ok) {
            dump_jit_request(address, profile);
            g_jit_llm_requests_emitted++;
        } else if (!g_jit_budget_warned) {
            g_jit_budget_warned = true;
            cout << "[*] JIT LLM request budget exhausted (" << g_max_jit_llm_requests
                 << "). Further jit_requests emission is disabled.\n";
        }
    }
    
    // Check if JIT translation has finished in the background (File `.bin` exists)
    if (g_enable_llm_pipeline && g_enable_native_jit && global_jit &&
        profile.execution_count > JIT_THRESHOLD && !profile.is_jitted) {
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

    bool headless_mode = false;
    const char* headless_env = std::getenv("PVZ_HEADLESS");
    if (headless_env && std::string(headless_env) != "0") {
        headless_mode = true;
    }
    bool boot_trace = false;
    const char* boot_trace_env = std::getenv("PVZ_BOOT_TRACE");
    if (boot_trace_env && std::string(boot_trace_env) != "0") {
        boot_trace = true;
    }
    auto trace = [&](const char* msg) {
        if (boot_trace) {
            cerr << "[TRACE] " << msg << endl;
        }
    };

    SDL_Window* window = nullptr;
    SDL_Renderer* renderer = nullptr;
    SDL_Texture* texture = nullptr;

    if (!headless_mode) {
        if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS) != 0) {
            cerr << "[!] SDL video init failed (" << SDL_GetError()
                 << "), falling back to headless mode.\n";
            headless_mode = true;
        }
    }

    if (headless_mode) {
        if (SDL_Init(SDL_INIT_EVENTS) != 0) {
            cerr << "[!] SDL2 events initialization failed in headless mode: " << SDL_GetError() << endl;
            return 1;
        }
        cout << "[*] Running in headless mode (PVZ_HEADLESS).\n";
    } else {
        window = SDL_CreateWindow(
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

        renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
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

        texture = SDL_CreateTexture(
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
    }

    uint32_t guest_vram = 0xA0000000;
    g_guest_vram_base = guest_vram;
    g_guest_vram_size = 800 * 600 * 4;

    uint32_t* host_vram = new uint32_t[800 * 600];
    g_host_vram_ptr = host_vram;
    g_renderer_ptr = renderer;
    g_texture_ptr = texture;
    memset(host_vram, 0, 800 * 600 * 4);
    trace("host_vram allocated");

    // Initialize Capstone (DETAIL mode ON for LVA)
    trace("before cs_open");
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) return 1;
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    trace("after cs_open");

    if (env_truthy("PVZ_DISABLE_NATIVE_JIT")) {
        g_enable_native_jit = false;
    }
    if (env_truthy("PVZ_ENABLE_LLM")) {
        g_enable_llm_pipeline = true;
    }
    if (env_truthy("PVZ_WATCHPOINT")) {
        g_watchpoint_enabled = true;
    }
    if (env_truthy("PVZ_DISABLE_VRAM_PRESENT_HOOK")) {
        g_vram_present_hook_enabled = false;
    }
    int vram_stride = env_int("PVZ_VRAM_PRESENT_STRIDE", 20000);
    if (vram_stride > 0) {
        g_vram_present_stride = static_cast<uint64_t>(vram_stride);
    }
    const char* profile_env = std::getenv("PVZ_PROFILE_BLOCKS");
    if (profile_env && *profile_env) {
        g_profile_blocks = env_truthy("PVZ_PROFILE_BLOCKS");
    } else {
        // Profiling is only needed for LLM/JIT payload generation.
        g_profile_blocks = g_enable_llm_pipeline;
    }
    int profile_cap = env_int("PVZ_MAX_PROFILE_BLOCKS", 250000);
    if (profile_cap > 0) {
        g_max_profile_blocks = static_cast<size_t>(profile_cap);
    }
    g_max_jit_llm_requests = env_int("PVZ_MAX_JIT_REQUESTS", 24);
    int tb_flush_blocks = env_int("PVZ_TB_FLUSH_INTERVAL_BLOCKS", 0);
    if (tb_flush_blocks > 0) {
        g_tb_flush_interval_blocks = static_cast<uint64_t>(tb_flush_blocks);
    }
    int rss_guard_default = 0;
#if defined(PVZ_CPU_BACKEND_FEXCORE)
    rss_guard_default = 12288; // 12GB safety cap for long-running unicorn-shim sessions.
#endif
    int rss_guard_mb = env_int("PVZ_MAX_RSS_MB", rss_guard_default);
    if (rss_guard_mb > 0) {
        g_rss_guard_max_mb = static_cast<uint64_t>(rss_guard_mb);
    }
    int rss_guard_blocks = env_int("PVZ_RSS_GUARD_INTERVAL_BLOCKS", 20000);
    if (rss_guard_blocks > 0) {
        g_rss_guard_check_interval_blocks = static_cast<uint64_t>(rss_guard_blocks);
    }
    if (env_truthy("PVZ_BLOCK_HOT_SAMPLE")) {
        g_block_hot_sample_enabled = true;
    }
    int block_hot_interval = env_int("PVZ_BLOCK_HOT_SAMPLE_INTERVAL", 200000);
    if (block_hot_interval > 0) {
        g_block_hot_interval = static_cast<uint64_t>(block_hot_interval);
    }
    int block_hot_cap = env_int("PVZ_BLOCK_HOT_CAP", 8192);
    if (block_hot_cap > 0) {
        g_block_hot_cap = static_cast<size_t>(block_hot_cap);
    }
    if (env_truthy("PVZ_BLOCK_FOCUS_TRACE")) {
        g_block_focus_trace_enabled = true;
    }
    if (env_truthy("PVZ_HOT_LOOP_ACCEL")) {
        g_hot_loop_accel_enabled = true;
    }
    int block_focus_interval = env_int("PVZ_BLOCK_FOCUS_INTERVAL", 50000);
    if (block_focus_interval > 0) {
        g_block_focus_interval = static_cast<uint64_t>(block_focus_interval);
    }
    int block_focus_dump = env_int("PVZ_BLOCK_FOCUS_DUMP_BYTES", 24);
    if (block_focus_dump > 0) {
        g_block_focus_dump_bytes = static_cast<size_t>(block_focus_dump);
    }
    if (g_block_focus_trace_enabled) {
        vector<uint32_t> addrs = parse_u32_list_csv(std::getenv("PVZ_BLOCK_FOCUS_ADDRS"));
        if (addrs.empty()) {
            addrs = {
                0x441a73u, 0x441a79u, 0x441d20u, 0x441d37u, 0x441d3fu, 0x441d4fu,
                0x441d66u, 0x441d77u, 0x441dd0u, 0x441dd9u, 0x5d8890u, 0x62456au, 0x404470u
            };
        }
        for (uint32_t a : addrs) {
            g_block_focus_addrs.insert(a);
        }
    }

    // Initialize CPU backend
    trace("before backend.open_x86_32");
    #if defined(PVZ_CPU_BACKEND_FEXCORE)
    FexCoreBackend fexcore_backend;
    CpuBackend& backend = fexcore_backend;
    cout << "[*] CPU backend: fexcore\n";
    #else
    UnicornBackend unicorn_backend;
    CpuBackend& backend = unicorn_backend;
    cout << "[*] CPU backend: unicorn\n";
    #endif
    g_backend = &backend;
    if (!backend.open_x86_32()) return 1;
    trace("after backend.open_x86_32");
    uc_engine* uc = backend.engine();

    // Map Guest VRAM
    trace("before guest_vram map");
    backend.mem_map(guest_vram, 800 * 600 * 4, UC_PROT_ALL);
    trace("after guest_vram map");

    if (env_truthy("PVZ_MAP_NULL_PAGE")) {
        // Optional compatibility mode for binaries that transiently dereference low/null pointers.
        backend.mem_map(0x0, 0x10000, UC_PROT_READ | UC_PROT_WRITE);
        cout << "[*] Null-page compatibility mapping enabled (PVZ_MAP_NULL_PAGE).\n";
    }

    try {
        trace("before jit dispatcher init");
        if (g_enable_native_jit) {
            global_jit = new JITDispatcher();
        } else {
            global_jit = nullptr;
            cout << "[*] Native ARM64 JIT dispatcher disabled (PVZ_DISABLE_NATIVE_JIT).\n";
        }
        if (!g_enable_llm_pipeline) {
            cout << "[*] LLM pipeline disabled (set PVZ_ENABLE_LLM=1 to enable).\n";
        } else {
            if (g_max_jit_llm_requests < 0) {
                cout << "[*] LLM JIT request budget: unlimited (PVZ_MAX_JIT_REQUESTS < 0).\n";
            } else {
                cout << "[*] LLM JIT request budget: " << g_max_jit_llm_requests
                     << " blocks (PVZ_MAX_JIT_REQUESTS).\n";
            }
        }
        cout << "[*] Block profiling: " << (g_profile_blocks ? "ON" : "OFF");
        if (g_profile_blocks) {
            cout << ", cap=" << g_max_profile_blocks << " (PVZ_MAX_PROFILE_BLOCKS)";
        }
        cout << "\n";
        if (g_tb_flush_interval_blocks > 0) {
            cout << "[*] TB cache flush interval: " << g_tb_flush_interval_blocks
                 << " blocks (PVZ_TB_FLUSH_INTERVAL_BLOCKS).\n";
        }
        if (g_rss_guard_max_mb > 0) {
            cout << "[*] RSS guard: max=" << g_rss_guard_max_mb
                 << "MB, check_interval_blocks=" << g_rss_guard_check_interval_blocks
                 << " (PVZ_MAX_RSS_MB / PVZ_RSS_GUARD_INTERVAL_BLOCKS).\n";
        }
        if (g_block_hot_sample_enabled) {
            cout << "[*] Block hot sampler enabled: interval=" << g_block_hot_interval
                 << ", cap=" << g_block_hot_cap
                 << " (PVZ_BLOCK_HOT_SAMPLE / PVZ_BLOCK_HOT_SAMPLE_INTERVAL / PVZ_BLOCK_HOT_CAP).\n";
        }
        if (g_block_focus_trace_enabled) {
            cout << "[*] Block focus trace enabled: interval=" << g_block_focus_interval
                 << ", dump_bytes=" << g_block_focus_dump_bytes << ", addrs=";
            size_t n = 0;
            for (uint32_t a : g_block_focus_addrs) {
                cout << (n == 0 ? "" : ",") << "0x" << hex << a << dec;
                n++;
            }
            cout << " (PVZ_BLOCK_FOCUS_TRACE / PVZ_BLOCK_FOCUS_ADDRS / PVZ_BLOCK_FOCUS_INTERVAL / PVZ_BLOCK_FOCUS_DUMP_BYTES).\n";
        }
        if (g_hot_loop_accel_enabled) {
            cout << "[*] Hot loop acceleration enabled (PVZ_HOT_LOOP_ACCEL): "
                 << "0x441a73(memcmp dword), 0x5d888c/0x5d8890(xor copy), "
                 << "0x62456a(rep movsd), 0x404470(strlen loop).\n";
        }
        trace("after jit dispatcher init");

        trace("before PE parse");
        PEModule pe_module(argv[1]);
        trace("after PE parse");
        WindowsEnvironment env(backend);
        DummyAPIHandler api_handler(backend);
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

        pe_module.map_into(backend);
        pe_module.resolve_imports(backend, api_handler);
        env.setup_system();

        uc_hook hook1, hook_mem;
        backend.hook_add(&hook1, UC_HOOK_BLOCK, (void*)hook_block_lva, nullptr, 1, 0);
        backend.hook_add(&hook_mem, UC_HOOK_MEM_WRITE, (void*)hook_mem_write, nullptr, 1, 0);

        cout << "\n[*] Starting C++ Engine Emulation at 0x" << hex << pe_module.entry_point << "...\n";
        
        uint32_t test_val;
        uc_err test_err = backend.mem_read(0x38b, &test_val, 4);
        if (test_err == UC_ERR_OK) {
            std::cout << "[!!!] ALERT: 0x38b IS MAPPED!!! Val: " << test_val << "\n";
        } else {
            std::cout << "[!!!] ALERT: 0x38b IS NOT MAPPED!!!\n";
        }

        cout << "[*] Profiler Active. JIT Memory Dispatcher Ready.\n";
        
        uint32_t pc = pe_module.entry_point;
        if (api_handler.coop_threads_enabled()) {
            backend.reg_write(UC_X86_REG_EIP, &pc);
            api_handler.coop_register_main_thread();
            uint32_t coop_pc = api_handler.coop_current_pc();
            if (coop_pc != 0) pc = coop_pc;
            cout << "[*] Cooperative scheduler: ON (timeslice=" << api_handler.coop_timeslice_count()
                 << " instructions, env=PVZ_COOP_THREADS).\n";
        }
        while (true) {
            size_t emu_count = 0;
            if (api_handler.coop_threads_enabled()) {
                pc = api_handler.coop_current_pc();
                if (pc == 0 || pc == 0xFFFFFFFFu) {
                    if (api_handler.coop_should_terminate()) {
                        cout << "\n[+] Cooperative scheduler finished (no runnable threads).\n";
                        break;
                    }
                }
                emu_count = api_handler.coop_timeslice_count();
                if (emu_count == 0) emu_count = 1;
            }

            uc_err err = backend.emu_start(pc, 0, 0, emu_count);
            if (err) {
                if (api_handler.coop_threads_enabled() && api_handler.coop_try_absorb_emu_error(err)) {
                    if (api_handler.coop_should_terminate()) {
                        cout << "\n[+] Cooperative scheduler finished after worker fault recovery.\n";
                        break;
                    }
                    pc = api_handler.coop_current_pc();
                    continue;
                }
                std::cerr << "\n[!] Emulation stopped due to error: " << backend.strerror(err) << " (Code: " << err << ")\n";
                uint32_t val;
                backend.reg_read(UC_X86_REG_EIP, &val); std::cerr << "[!] EIP = 0x" << std::hex << val << std::dec << "\n";
                backend.reg_read(UC_X86_REG_EAX, &val); std::cerr << "EAX=0x" << std::hex << val << " ";
                backend.reg_read(UC_X86_REG_EBX, &val); std::cerr << "EBX=0x" << std::hex << val << " ";
                backend.reg_read(UC_X86_REG_ECX, &val); std::cerr << "ECX=0x" << std::hex << val << " ";
                backend.reg_read(UC_X86_REG_EDX, &val); std::cerr << "EDX=0x" << std::hex << val << "\n";
                uint32_t esi, edi, esp, ebp;
                backend.reg_read(UC_X86_REG_ESI, &esi);
                backend.reg_read(UC_X86_REG_EDI, &edi);
                backend.reg_read(UC_X86_REG_ESP, &esp);
                backend.reg_read(UC_X86_REG_EBP, &ebp);
                std::cerr << "ESI=0x" << std::hex << esi << " EDI=0x" << edi << " ESP=0x" << esp << " EBP=0x" << ebp << "\n";
        
                std::cerr << "--- Stack Dump ---\n";
                for (int i = 0; i < 8; i++) {
                    uint32_t stack_val = 0;
                    uc_err mem_err = backend.mem_read(esp + (i * 4), &stack_val, 4);
                    if (mem_err == UC_ERR_OK) {
                        std::cerr << "  [ESP+" << std::hex << (i*4) << "] = 0x" << stack_val << "\n";
                    } else {
                        std::cerr << "  [ESP+" << std::hex << (i*4) << "] = UNMAPPED (" << backend.strerror(mem_err) << ")\n";
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
            if (g_rss_guard_triggered) {
                std::cerr << "[!] Stopped by RSS guard at approx " << g_rss_guard_last_mb << "MB.\n";
                break;
            }
            if (api_handler.coop_threads_enabled()) {
                api_handler.coop_on_timeslice_end();
                pc = api_handler.coop_current_pc();
                if (api_handler.coop_should_terminate()) {
                    cout << "\n[+] Cooperative scheduler reported completion.\n";
                    break;
                }
            } else {
                backend.reg_read(UC_X86_REG_EIP, &pc);
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
        }

    } catch (const exception& e) {
        cerr << "Exception caught: " << e.what() << endl;
    }

    if (g_hot_loop_accel_enabled && g_hot_loop_accel_hits > 0) {
        cout << "[*] Hot loop acceleration summary: hits=" << g_hot_loop_accel_hits
             << ", bytes=" << g_hot_loop_accel_bytes << "\n";
    }

    delete global_jit;
    backend.close();
    cs_close(&cs_handle);
    
    delete[] host_vram;
    SDL_DestroyTexture(texture);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}

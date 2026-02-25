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
bool g_crt_alloc_accel_enabled = false;
bool g_fast_worker_thread_enabled = false;
uint32_t g_crt_alloc_base = 0x48000000u;
uint32_t g_crt_alloc_limit = 0x50000000u; // 128MB arena
uint32_t g_crt_alloc_top = 0x48000000u;
uint32_t g_crt_alloc_mapped_end = 0x48000000u;
uint64_t g_crt_alloc_count = 0;
uint64_t g_crt_alloc_bytes = 0;
uint64_t g_crt_free_fast_count = 0;
uint64_t g_lock_wrapper_fast_count = 0;
uint64_t g_string_grow_fast_count = 0;
uint64_t g_substr_assign_fast_count = 0;
uint64_t g_stream_xor_decode_fast_count = 0;
uint64_t g_assign_ptr_fast_count = 0;
bool g_string_range_clamp_enabled = false;
bool g_string_range_trace_enabled = false;
uint64_t g_string_range_fast_count = 0;
uint64_t g_string_range_invalid_count = 0;
uint64_t g_string_range_clamped_count = 0;
bool g_wstring_append_accel_enabled = false;
uint64_t g_wstring_append_fast_count = 0;
bool g_iter_advance_accel_enabled = false;
uint64_t g_iter_advance_fast_count = 0;
bool g_memmove_s_accel_enabled = false;
uint64_t g_memmove_s_fast_count = 0;
uint64_t g_memmove_wrap_fast_count = 0;
bool g_string_insert_accel_enabled = false;
uint64_t g_string_insert_fast_count = 0;
bool g_insert_iter_accel_enabled = false;
uint64_t g_insert_iter_fast_count = 0;
bool g_wstr_to_str_accel_enabled = false;
uint64_t g_wstr_to_str_fast_count = 0;
bool g_stream_pop_accel_enabled = false;
uint64_t g_stream_pop_fast_count = 0;
bool g_streambuf_branch_accel_enabled = false;
uint64_t g_streambuf_branch_fast_count = 0;
bool g_xml_branch_accel_enabled = false;
uint64_t g_xml_branch_fast_count = 0;
bool g_text_norm_branch_accel_enabled = false;
uint64_t g_text_norm_branch_fast_count = 0;
uint64_t g_tiny_ctrl_fast_count = 0;
bool g_security_cookie_accel_enabled = false;
bool g_lock_gate_probe_accel_enabled = false;
uint64_t g_security_cookie_fast_count = 0;
uint64_t g_lock_gate_probe_fast_count = 0;
uint32_t g_guest_vram_base = 0;
size_t g_guest_vram_size = 0;
uint32_t* g_host_vram_ptr = nullptr;
SDL_Renderer* g_renderer_ptr = nullptr;
SDL_Texture* g_texture_ptr = nullptr;
uint64_t g_vram_write_counter = 0;
uint64_t g_vram_present_stride = 20000;
uint32_t g_last_vram_present_ms = 0;
bool g_vram_present_logged = false;
bool g_vram_snapshot_enabled = false;
uint64_t g_vram_snapshot_every = 1;
uint64_t g_vram_snapshot_counter = 0;
string g_vram_snapshot_prefix = "artifacts/vram_frame";

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

static void maybe_dump_vram_snapshot() {
    if (!g_vram_snapshot_enabled || !g_host_vram_ptr || g_guest_vram_size == 0) return;
    g_vram_snapshot_counter++;
    if (g_vram_snapshot_every == 0 || (g_vram_snapshot_counter % g_vram_snapshot_every) != 0) return;

    std::filesystem::path out_path(g_vram_snapshot_prefix + "_" + std::to_string(g_vram_snapshot_counter) + ".ppm");
    if (!out_path.parent_path().empty()) {
        std::filesystem::create_directories(out_path.parent_path());
    }
    std::ofstream out(out_path, std::ios::binary);
    if (!out.is_open()) return;

    const int w = 800;
    const int h = 600;
    out << "P6\n" << w << " " << h << "\n255\n";
    for (int i = 0; i < w * h; ++i) {
        uint32_t px = g_host_vram_ptr[i];
        uint8_t rgb[3] = {
            static_cast<uint8_t>((px >> 16) & 0xFFu),
            static_cast<uint8_t>((px >> 8) & 0xFFu),
            static_cast<uint8_t>(px & 0xFFu)
        };
        out.write(reinterpret_cast<const char*>(rgb), 3);
    }
    out.close();
    cout << "[VRAM SNAPSHOT] wrote " << out_path.string() << "\n";
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

    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0, esi = 0, edi = 0, ebp = 0, esp = 0;
    g_backend->reg_read(UC_X86_REG_EAX, &eax);
    g_backend->reg_read(UC_X86_REG_EBX, &ebx);
    g_backend->reg_read(UC_X86_REG_ECX, &ecx);
    g_backend->reg_read(UC_X86_REG_EDX, &edx);
    g_backend->reg_read(UC_X86_REG_ESI, &esi);
    g_backend->reg_read(UC_X86_REG_EDI, &edi);
    g_backend->reg_read(UC_X86_REG_EBP, &ebp);
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
    } else if (addr32 == 0x5d8850u) {
        print_focus_mem_sample("ret", esp, 4);
        print_focus_mem_sample("arg1", esp + 4u, 4);
        print_focus_mem_sample("arg2", esp + 8u, 4);
        print_focus_mem_sample("arg3", esp + 12u, 4);
        print_focus_mem_sample("arg4", esp + 16u, 4);
    } else if (addr32 == 0x621111u || addr32 == 0x62111fu || addr32 == 0x621182u || addr32 == 0x61c130u) {
        print_focus_mem_sample("arg", esp + 4u, 4);
        print_focus_mem_sample("fnptr", 0x65219cu, 4);
        print_focus_mem_sample("newmode", 0x6a6dd4u, 4);
    } else if (addr32 == 0x456610u || addr32 == 0x456650u) {
        print_focus_mem_sample("ret", esp, 4);
        print_focus_mem_sample("begin", esp + 4u, 4);
        print_focus_mem_sample("src_obj", esp + 8u, 4);
        print_focus_mem_sample("dst_obj", ecx, 8);
    } else if (addr32 == 0x5bd830u || addr32 == 0x5bd88au || addr32 == 0x5bf470u || addr32 == 0x5bf47bu) {
        print_focus_mem_sample("ret", esp, 4);
        print_focus_mem_sample("arg1", esp + 4u, 4);
        print_focus_mem_sample("arg2", esp + 8u, 4);
        print_focus_mem_sample("arg3", esp + 12u, 4);
        print_focus_mem_sample("this", ecx, 0x1cu);
    } else if (addr32 == 0x5bf4e0u || addr32 == 0x5bf4efu || addr32 == 0x5bf4f8u || addr32 == 0x5bf518u || addr32 == 0x5bf52fu) {
        print_focus_mem_sample("ret", esp, 4);
        print_focus_mem_sample("delta", esp + 4u, 4);
        print_focus_mem_sample("iter", ecx, 8);
        uint32_t owner = 0;
        if (ecx >= 0x1000u && g_backend->mem_read(ecx, &owner, 4) == UC_ERR_OK && owner >= 0x1000u) {
            print_focus_mem_sample("owner", owner, 0x1cu);
        }
    } else if (addr32 == 0x61be96u || addr32 == 0x61beebu) {
        print_focus_mem_sample("ret", esp, 4);
        print_focus_mem_sample("dst", esp + 4u, 4);
        print_focus_mem_sample("dstsz", esp + 8u, 4);
        print_focus_mem_sample("src", esp + 12u, 4);
        print_focus_mem_sample("count", esp + 16u, 4);
    } else if (addr32 == 0x55d410u) {
        print_focus_mem_sample("ret", esp, 4);
        print_focus_mem_sample("pos", esp + 4u, 4);
        print_focus_mem_sample("count", esp + 8u, 4);
        print_focus_mem_sample("value", esp + 12u, 4);
        print_focus_mem_sample("this", ecx, 0x1cu);
    } else if (addr32 == 0x5bba20u || addr32 == 0x5bbad0u || addr32 == 0x5bbb12u) {
        print_focus_mem_sample("ret", esp, 4);
        print_focus_mem_sample("arg1", esp + 4u, 4);
        print_focus_mem_sample("arg2", esp + 8u, 4);
        print_focus_mem_sample("arg3", esp + 12u, 4);
        print_focus_mem_sample("arg4", esp + 16u, 4);
        print_focus_mem_sample("esi_obj", esi, 0x1cu);
    } else if (addr32 == 0x5afbb0u || addr32 == 0x5afc06u || addr32 == 0x5afc0du || addr32 == 0x5afc26u) {
        print_focus_mem_sample("ret", esp, 4);
        print_focus_mem_sample("edi_obj", edi, 0x1cu);
        print_focus_mem_sample("ebx_src", ebx, 0x1cu);
        print_focus_mem_sample("esi_idx", esi, 4);
    } else if (addr32 == 0x5a1640u || addr32 == 0x5a16bdu) {
        print_focus_mem_sample("cookie", 0x699fe8u, 4);
        print_focus_mem_sample("gate70", 0x6a9f70u, 4);
        print_focus_mem_sample("gate74", 0x6a9f74u, 4);
    } else if (addr32 == 0x62b0d8u || addr32 == 0x62b0e5u || addr32 == 0x62b0e9u ||
               addr32 == 0x62b0f5u || addr32 == 0x62b0fdu || addr32 == 0x62b105u ||
               addr32 == 0x62b184u || addr32 == 0x62b185u) {
        if (ebp >= 0x1000u) {
            print_focus_mem_sample("src_cur_ptr", ebp + 0x10u, 4);
            print_focus_mem_sample("src_end_ptr", ebp - 0x10u, 4);
            uint32_t src_cur = 0;
            if (g_backend->mem_read(ebp + 0x10u, &src_cur, 4) == UC_ERR_OK && src_cur >= 0x1000u) {
                print_focus_mem_sample("src_cur", src_cur, bytes);
            }
        }
        if (ebx >= 0x1000u) {
            print_focus_mem_sample("dst_cur", ebx, bytes);
        }
    } else {
        print_focus_mem_sample("ecx", ecx, bytes);
        print_focus_mem_sample("edx", edx, bytes);
    }
    cout << "\n";
}

static uint32_t align_up_u32(uint32_t value, uint32_t align) {
    return (value + (align - 1u)) & ~(align - 1u);
}

static bool ensure_crt_alloc_mapped(uint32_t end_addr) {
    if (!g_backend) return false;
    if (end_addr <= g_crt_alloc_mapped_end) return true;
    uint32_t map_end = align_up_u32(end_addr, 0x1000u);
    if (map_end > g_crt_alloc_limit) return false;
    if (map_end <= g_crt_alloc_mapped_end) return true;
    uc_err err = g_backend->mem_map(g_crt_alloc_mapped_end, map_end - g_crt_alloc_mapped_end, UC_PROT_ALL);
    if (err != UC_ERR_OK) return false;
    g_crt_alloc_mapped_end = map_end;
    return true;
}

static bool crt_alloc_fast(uint32_t requested_bytes, uint32_t& out_ptr) {
    uint32_t bytes = requested_bytes == 0 ? 1u : requested_bytes;
    uint32_t aligned = align_up_u32(bytes, 16u);
    if (g_crt_alloc_top + aligned < g_crt_alloc_top) return false;
    uint32_t end = g_crt_alloc_top + aligned;
    if (end > g_crt_alloc_limit) return false;
    if (!ensure_crt_alloc_mapped(end)) return false;
    out_ptr = g_crt_alloc_top;
    g_crt_alloc_top = end;
    g_crt_alloc_count++;
    g_crt_alloc_bytes += aligned;
    return true;
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

static bool accelerate_stream_xor_decode_5d8850(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x5d8850u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    uint32_t dst_ptr = 0;
    uint32_t chunk = 0;
    uint32_t mul = 0;
    uint32_t state_ptr = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &dst_ptr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &chunk, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 12u, &mul, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 16u, &state_ptr, 4) != UC_ERR_OK) return false;
    if (state_ptr < 0x1000u) return false;
    if (dst_ptr < 0x1000u) return false;
    if (chunk == 0u) return false;

    uint32_t stream_ptr = 0;
    if (g_backend->mem_read(state_ptr, &stream_ptr, 4) != UC_ERR_OK) return false;
    uint32_t offset = 0;
    if (g_backend->mem_read(state_ptr + 4u, &offset, 4) != UC_ERR_OK) return false;
    if (stream_ptr == 0u) {
        uint32_t eax = 0u;
        uint32_t edx = 0u;
        uint32_t new_esp = esp + 20u; // ret 0x10
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_EDX, &edx);
        uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
        uc_emu_stop(uc);
        g_hot_loop_accel_hits++;
        return true;
    }
    if (stream_ptr < 0x1000u) return false;

    uint32_t stream_ctx = 0;
    uint32_t stream_base = 0;
    uint32_t stream_end = 0;
    if (g_backend->mem_read(stream_ptr, &stream_ctx, 4) != UC_ERR_OK) return false;
    if (stream_ctx < 0x1000u) return false;
    if (g_backend->mem_read(stream_ptr + 0x28u, &stream_base, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(stream_ptr + 0x2cu, &stream_end, 4) != UC_ERR_OK) return false;
    if (stream_end < offset) return false;
    uint32_t avail = stream_end - offset;

    uint32_t ctx_data = 0;
    if (g_backend->mem_read(stream_ctx + 8u, &ctx_data, 4) != UC_ERR_OK) return false;
    if (ctx_data < 0x1000u) return false;

    uint64_t requested64 = static_cast<uint64_t>(chunk) * static_cast<uint64_t>(mul);
    if (requested64 > 0xFFFFFFFFull) return false;
    uint32_t requested = static_cast<uint32_t>(requested64);
    uint32_t copy_bytes = std::min<uint32_t>(requested, avail);
    if (copy_bytes > (1u << 27)) return false;

    uint64_t src64 = static_cast<uint64_t>(ctx_data) + static_cast<uint64_t>(stream_base) + static_cast<uint64_t>(offset);
    if (src64 > 0xFFFFFFFFull) return false;
    uint32_t src_ptr = static_cast<uint32_t>(src64);
    if (src_ptr < 0x1000u && copy_bytes > 0u) return false;

    if (copy_bytes > 0u) {
        vector<uint8_t> buf(copy_bytes, 0);
        if (g_backend->mem_read(src_ptr, buf.data(), copy_bytes) != UC_ERR_OK) return false;
        for (uint8_t& b : buf) b ^= 0xF7u;
        if (g_backend->mem_write(dst_ptr, buf.data(), copy_bytes) != UC_ERR_OK) return false;
    }

    uint32_t new_offset = offset + copy_bytes;
    if (new_offset < offset) return false;
    if (g_backend->mem_write(state_ptr + 4u, &new_offset, 4) != UC_ERR_OK) return false;

    // Original tail does signed idiv by chunk and returns quotient in EAX.
    int32_t numer = static_cast<int32_t>(copy_bytes);
    int32_t denom = static_cast<int32_t>(chunk);
    if (denom == 0) return false;
    if (numer == std::numeric_limits<int32_t>::min() && denom == -1) return false;
    int32_t quot = numer / denom;
    int32_t rem = numer % denom;

    uint32_t eax = static_cast<uint32_t>(quot);
    uint32_t edx = static_cast<uint32_t>(rem);
    uint32_t new_esp = esp + 20u; // ret 0x10
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_EDX, &edx);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += copy_bytes;
    g_stream_xor_decode_fast_count++;
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

static bool accelerate_memcmp_function_441a60(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x441a60u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    uint32_t p1 = 0, p2 = 0, count = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4, &p1, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8, &p2, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 12, &count, 4) != UC_ERR_OK) return false;
    if (p1 < 0x1000u || p2 < 0x1000u) return false;
    if (count > (1u << 24)) return false;

    int32_t diff = 0;
    if (count > 0) {
        constexpr size_t kChunk = 4096;
        vector<uint8_t> b1(kChunk, 0);
        vector<uint8_t> b2(kChunk, 0);
        uint32_t offset = 0;
        while (offset < count) {
            size_t n = std::min<size_t>(kChunk, static_cast<size_t>(count - offset));
            if (g_backend->mem_read(p1 + offset, b1.data(), n) != UC_ERR_OK) return false;
            if (g_backend->mem_read(p2 + offset, b2.data(), n) != UC_ERR_OK) return false;
            for (size_t i = 0; i < n; ++i) {
                if (b1[i] != b2[i]) {
                    diff = static_cast<int32_t>(b1[i]) - static_cast<int32_t>(b2[i]);
                    offset = count;
                    break;
                }
            }
            offset += static_cast<uint32_t>(n);
        }
    }

    uint32_t eax = static_cast<uint32_t>(diff);
    uint32_t new_esp = esp + 4; // cdecl: caller pops args
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += count;
    return true;
}

static bool accelerate_compare_callsite_5d8f8x(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x5d8f8du && addr32 != 0x5d8f8fu) return false;

    uint32_t esp = 0, eax_reg = 0, ecx = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(uc, UC_X86_REG_EAX, &eax_reg);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

    uint32_t arg1 = eax_reg;
    uint32_t arg2 = 0;
    if (g_backend->mem_read(esp + 0x0cu, &arg2, 4) != UC_ERR_OK) return false;
    if (addr32 == 0x5d8f8du) {
        if (g_backend->mem_read(eax_reg, &arg1, 4) != UC_ERR_OK) return false;
    }
    uint32_t count = ecx;
    if (arg1 < 0x1000u || arg2 < 0x1000u) return false;
    if (count > (1u << 24)) return false;

    int32_t diff = 0;
    if (count > 0) {
        constexpr size_t kChunk = 4096;
        vector<uint8_t> b1(kChunk, 0);
        vector<uint8_t> b2(kChunk, 0);
        uint32_t offset = 0;
        while (offset < count) {
            size_t n = std::min<size_t>(kChunk, static_cast<size_t>(count - offset));
            if (g_backend->mem_read(arg1 + offset, b1.data(), n) != UC_ERR_OK) return false;
            if (g_backend->mem_read(arg2 + offset, b2.data(), n) != UC_ERR_OK) return false;
            for (size_t i = 0; i < n; ++i) {
                if (b1[i] != b2[i]) {
                    diff = static_cast<int32_t>(b1[i]) - static_cast<int32_t>(b2[i]);
                    offset = count;
                    break;
                }
            }
            offset += static_cast<uint32_t>(n);
        }
    }

    uint32_t eax = static_cast<uint32_t>(diff);
    uint32_t new_esp = esp - 12u; // emulate three pushes before call 0x441a60
    uint32_t eip = 0x5d8f9bu;     // continue at call return site
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += count;
    return true;
}

static bool accelerate_tree_lookup_loop_5d8f5x(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x5d8f50u && addr32 != 0x5d8f58u) return false;

    uint32_t esp = 0;
    uint32_t root = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(uc, UC_X86_REG_ESI, &root);
    if (esp < 0x1000u || root < 0x1000u) return false;

    uint32_t query_obj = 0;
    if (g_backend->mem_read(esp + 0x34u, &query_obj, 4) != UC_ERR_OK) return false;
    if (query_obj < 0x1000u) return false;

    uint32_t query_len = 0;
    uint32_t query_cap = 0;
    if (g_backend->mem_read(query_obj + 0x14u, &query_len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(query_obj + 0x18u, &query_cap, 4) != UC_ERR_OK) return false;
    uint32_t query_ptr = 0;
    if (query_cap < 0x10u) {
        query_ptr = query_obj + 4u;
    } else if (g_backend->mem_read(query_obj + 4u, &query_ptr, 4) != UC_ERR_OK) {
        return false;
    }
    if (query_ptr < 0x1000u) return false;

    constexpr uint32_t kMaxSteps = 8192u;
    uint32_t node = root;
    uint8_t al = 0;
    uint32_t traversed = 0;
    uint64_t compared_bytes = 0;

    for (uint32_t step = 0; step < kMaxSteps; ++step) {
        if (node < 0x1000u) return false;
        uint8_t marker = 0;
        if (g_backend->mem_read(node + 0x59u, &marker, 1) != UC_ERR_OK) return false;
        if (marker != 0u) {
            // Sentinel node: behave as if loop finished naturally.
            break;
        }

        // Save current node for the post-loop path (restored at 0x5d8fcc).
        if (g_backend->mem_write(esp + 0x20u, &node, 4) != UC_ERR_OK) return false;

        uint32_t node_len = 0;
        uint32_t node_cap = 0;
        if (g_backend->mem_read(node + 0x20u, &node_len, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_read(node + 0x24u, &node_cap, 4) != UC_ERR_OK) return false;
        uint32_t node_ptr = 0;
        if (node_cap < 0x10u) {
            node_ptr = node + 0x10u;
        } else if (g_backend->mem_read(node + 0x10u, &node_ptr, 4) != UC_ERR_OK) {
            return false;
        }
        if (node_ptr < 0x1000u) return false;

        uint32_t cmp_len = std::min<uint32_t>(query_len, node_len);
        int32_t cmp_result = 0;
        if (cmp_len > 0) {
            constexpr size_t kChunk = 4096;
            std::array<uint8_t, kChunk> lhs{};
            std::array<uint8_t, kChunk> rhs{};
            uint32_t off = 0;
            while (off < cmp_len) {
                size_t n = std::min<size_t>(kChunk, static_cast<size_t>(cmp_len - off));
                if (g_backend->mem_read(query_ptr + off, lhs.data(), n) != UC_ERR_OK) return false;
                if (g_backend->mem_read(node_ptr + off, rhs.data(), n) != UC_ERR_OK) return false;
                for (size_t i = 0; i < n; ++i) {
                    if (lhs[i] != rhs[i]) {
                        cmp_result = static_cast<int32_t>(lhs[i]) - static_cast<int32_t>(rhs[i]);
                        off = cmp_len;
                        break;
                    }
                }
                off += static_cast<uint32_t>(n);
            }
        }
        if (cmp_result == 0) {
            if (query_len < node_len) cmp_result = -1;
            else if (query_len != node_len) cmp_result = 1;
        }
        al = (cmp_result < 0) ? 1u : 0u;
        if (g_backend->mem_write(esp + 0x10u, &al, 1) != UC_ERR_OK) return false;

        uint32_t next = 0;
        if (g_backend->mem_read(node + (al ? 0u : 8u), &next, 4) != UC_ERR_OK) return false;
        node = next;
        traversed++;
        compared_bytes += cmp_len;
    }

    uint32_t eax = static_cast<uint32_t>(al);
    uint32_t eip = 0x5d8fccu; // restore ebp/edi and continue original tail
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_ESI, &node);
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += compared_bytes;
    g_hot_loop_accel_hits += traversed;
    return true;
}

static bool host_memmove_copy(uint32_t dst, uint32_t src, uint32_t len) {
    if (len == 0u) return true;
    if (src < 0x1000u || dst < 0x1000u) return false;

    constexpr size_t kChunk = 64 * 1024;
    std::array<uint8_t, kChunk> temp{};
    if (dst > src && dst - src < len) {
        // Backward copy for overlap.
        uint32_t remaining = len;
        while (remaining > 0) {
            size_t n = std::min<size_t>(kChunk, remaining);
            uint32_t off = remaining - static_cast<uint32_t>(n);
            if (g_backend->mem_read(src + off, temp.data(), n) != UC_ERR_OK) return false;
            if (g_backend->mem_write(dst + off, temp.data(), n) != UC_ERR_OK) return false;
            remaining -= static_cast<uint32_t>(n);
        }
    } else {
        uint32_t off = 0;
        while (off < len) {
            size_t n = std::min<size_t>(kChunk, len - off);
            if (g_backend->mem_read(src + off, temp.data(), n) != UC_ERR_OK) return false;
            if (g_backend->mem_write(dst + off, temp.data(), n) != UC_ERR_OK) return false;
            off += static_cast<uint32_t>(n);
        }
    }
    return true;
}

static bool host_memset_fill(uint32_t dst, uint8_t value, uint32_t len) {
    if (len == 0u) return true;
    constexpr size_t kChunk = 4096;
    vector<uint8_t> fill(kChunk, value);
    uint32_t off = 0;
    while (off < len) {
        size_t n = std::min<size_t>(kChunk, static_cast<size_t>(len - off));
        if (g_backend->mem_write(dst + off, fill.data(), n) != UC_ERR_OK) return false;
        off += static_cast<uint32_t>(n);
    }
    return true;
}

static bool accelerate_memmove_624510(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x624510u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    uint32_t dst = 0;
    uint32_t src = 0;
    uint32_t len = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &dst, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &src, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 12u, &len, 4) != UC_ERR_OK) return false;
    if (len > (1u << 27)) return false;

    if (!host_memmove_copy(dst, src, len)) return false;

    uint32_t new_esp = esp + 4u; // cdecl ret
    uc_reg_write(uc, UC_X86_REG_EAX, &dst);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += len;
    return true;
}

static bool accelerate_memmove_wrapper_61be1b(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x61be1bu) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    uint32_t dst = 0;
    uint32_t dst_size = 0;
    uint32_t src = 0;
    uint32_t count = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &dst, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &dst_size, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 12u, &src, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 16u, &count, 4) != UC_ERR_OK) return false;
    if (count > (1u << 27) || dst_size > (1u << 27)) return false;

    uint32_t eax = 0u;
    if (count == 0u) {
        eax = 0u;
    } else if (dst == 0u) {
        eax = 0x16u;
    } else if (src == 0u || dst_size < count) {
        if (!host_memset_fill(dst, 0u, dst_size)) return false;
        eax = (src == 0u) ? 0x16u : 0x22u;
    } else {
        if (!host_memmove_copy(dst, src, count)) return false;
        eax = 0u;
    }

    uint32_t new_esp = esp + 4u;
    uc_reg_write(uc, UC_X86_REG_EAX, &eax); // cdecl return
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_memmove_wrap_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += (count == 0u ? 1u : static_cast<uint64_t>(count));
    return true;
}

static bool read_basic_string_ptr(uint32_t obj, uint32_t cap, uint32_t& out_ptr) {
    if (obj < 0x1000u) return false;
    if (cap < 0x10u) {
        out_ptr = obj + 4u;
        return true;
    }
    if (g_backend->mem_read(obj + 4u, &out_ptr, 4) != UC_ERR_OK) return false;
    return out_ptr >= 0x1000u;
}

static bool accelerate_substr_assign_403e20(uc_engine* uc, uint32_t addr32) {
    if (!g_hot_loop_accel_enabled || !g_crt_alloc_accel_enabled) return false;
    if (addr32 != 0x403e20u) return false;

    uint32_t this_ptr = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &this_ptr);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (this_ptr < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t src_obj = 0;
    uint32_t pos = 0;
    uint32_t req_count = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &src_obj, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &pos, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 12u, &req_count, 4) != UC_ERR_OK) return false;
    if (src_obj < 0x1000u) return false;

    uint32_t src_len = 0, src_cap = 0;
    if (g_backend->mem_read(src_obj + 0x14u, &src_len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(src_obj + 0x18u, &src_cap, 4) != UC_ERR_OK) return false;
    if (pos > src_len) return false;
    uint32_t avail = src_len - pos;
    uint32_t new_len = (req_count < avail) ? req_count : avail;
    if (new_len >= 0xFFFFFFFEu) return false;

    uint32_t src_ptr = 0;
    if (!read_basic_string_ptr(src_obj, src_cap, src_ptr)) return false;
    if (src_ptr + pos < src_ptr) return false;

    uint32_t dst_cap = 0;
    if (g_backend->mem_read(this_ptr + 0x18u, &dst_cap, 4) != UC_ERR_OK) return false;
    uint32_t dst_ptr = 0;
    if (!read_basic_string_ptr(this_ptr, dst_cap, dst_ptr)) return false;

    if (dst_cap < new_len) {
        uint32_t new_cap = new_len | 0x0Fu;
        if (dst_cap <= 0xFFFFFFFDu) {
            uint32_t grow = dst_cap + (dst_cap >> 1);
            if (grow > new_cap) new_cap = grow;
        }
        if (new_cap < new_len || new_cap >= 0xFFFFFFFEu) return false;
        if (new_cap < 0x10u) return false;

        uint32_t new_ptr = 0;
        if (!crt_alloc_fast(new_cap + 1u, new_ptr)) return false;
        if (g_backend->mem_write(this_ptr + 4u, &new_ptr, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_write(this_ptr + 0x18u, &new_cap, 4) != UC_ERR_OK) return false;
        if (dst_cap >= 0x10u) {
            // Original path would free old heap storage.
            g_crt_free_fast_count++;
        }
        dst_cap = new_cap;
        dst_ptr = new_ptr;
    }

    if (new_len > 0u && !host_memmove_copy(dst_ptr, src_ptr + pos, new_len)) return false;
    uint8_t nul = 0;
    if (g_backend->mem_write(dst_ptr + new_len, &nul, 1) != UC_ERR_OK) return false;
    if (g_backend->mem_write(this_ptr + 0x14u, &new_len, 4) != UC_ERR_OK) return false;

    uint32_t new_esp = esp + 16u; // ret 0xC
    uc_reg_write(uc, UC_X86_REG_EAX, &this_ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_substr_assign_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += new_len;
    return true;
}

static bool accelerate_assign_ptr_404330(uc_engine* uc, uint32_t addr32) {
    if (!g_hot_loop_accel_enabled || !g_crt_alloc_accel_enabled) return false;
    if (addr32 != 0x404330u) return false;

    uint32_t this_ptr = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &this_ptr);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (this_ptr < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t src_ptr = 0;
    uint32_t new_len = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &src_ptr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &new_len, 4) != UC_ERR_OK) return false;
    if (new_len >= 0xFFFFFFFEu) return false;
    if (new_len > 0u && src_ptr < 0x1000u) return false;

    uint32_t cur_len = 0;
    uint32_t cur_cap = 0;
    if (g_backend->mem_read(this_ptr + 0x14u, &cur_len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(this_ptr + 0x18u, &cur_cap, 4) != UC_ERR_OK) return false;
    uint32_t old_ptr = 0;
    if (!read_basic_string_ptr(this_ptr, cur_cap, old_ptr)) return false;

    // Overlap path is subtle in original helper; keep it on guest path.
    if (new_len > 0u) {
        uint64_t old_begin = old_ptr;
        uint64_t old_end = old_begin + static_cast<uint64_t>(cur_len);
        uint64_t src = src_ptr;
        if (src >= old_begin && src < old_end) return false;
    }

    uint32_t dst_ptr = old_ptr;
    uint32_t dst_cap = cur_cap;
    if (dst_cap < new_len) {
        uint32_t new_cap = new_len | 0x0Fu;
        if (dst_cap <= 0xFFFFFFFDu) {
            uint32_t grow = dst_cap + (dst_cap >> 1);
            if (grow > new_cap) new_cap = grow;
        }
        if (new_cap < new_len || new_cap >= 0xFFFFFFFEu) return false;
        if (new_cap < 0x10u) return false;

        uint32_t new_ptr = 0;
        if (!crt_alloc_fast(new_cap + 1u, new_ptr)) return false;
        if (g_backend->mem_write(this_ptr + 4u, &new_ptr, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_write(this_ptr + 0x18u, &new_cap, 4) != UC_ERR_OK) return false;
        if (dst_cap >= 0x10u) {
            g_crt_free_fast_count++;
        }
        dst_ptr = new_ptr;
        dst_cap = new_cap;
    }

    if (new_len > 0u && !host_memmove_copy(dst_ptr, src_ptr, new_len)) return false;
    uint8_t nul = 0;
    if (g_backend->mem_write(dst_ptr + new_len, &nul, 1) != UC_ERR_OK) return false;
    if (g_backend->mem_write(this_ptr + 0x14u, &new_len, 4) != UC_ERR_OK) return false;

    uint32_t new_esp = esp + 12u; // ret 8
    uc_reg_write(uc, UC_X86_REG_EAX, &this_ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_assign_ptr_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += new_len;
    return true;
}

static bool accelerate_crt_alloc_helper_4041c0(uc_engine* uc, uint32_t addr32) {
    if (!g_crt_alloc_accel_enabled) return false;
    if (addr32 != 0x4041c0u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    uint32_t size = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &size, 4) != UC_ERR_OK) return false;
    if (size > (1u << 28)) return false;

    uint32_t ptr = 0;
    if (size > 0u) {
        if (!crt_alloc_fast(size, ptr)) return false;
    }

    uint32_t new_esp = esp + 4u; // plain ret
    uc_reg_write(uc, UC_X86_REG_EAX, &ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += size;
    return true;
}

static bool accelerate_crt_free_helper_61c19a(uc_engine* uc, uint32_t addr32) {
    if (!g_crt_alloc_accel_enabled) return false;
    if (addr32 != 0x61c19au && addr32 != 0x61c19fu && addr32 != 0x61fc66u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    uint32_t ptr = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &ptr, 4) != UC_ERR_OK) return false;

    bool owned_by_fast_arena = (ptr >= g_crt_alloc_base && ptr < g_crt_alloc_top);
    if (ptr != 0u && !owned_by_fast_arena) return false;

    uint32_t new_esp = esp + 4u; // cdecl ret
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_crt_free_fast_count++;
    g_hot_loop_accel_hits++;
    return true;
}

static bool accelerate_string_grow_404080(uc_engine* uc, uint32_t addr32) {
    if (!g_hot_loop_accel_enabled || !g_crt_alloc_accel_enabled) return false;
    if (addr32 != 0x404080u) return false;

    uint32_t this_ptr = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &this_ptr);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (this_ptr < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t requested = 0;
    uint32_t copy_len = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &requested, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &copy_len, 4) != UC_ERR_OK) return false;
    if (requested >= 0xFFFFFFFEu) return false;
    if (copy_len > (1u << 27)) return false;

    uint32_t old_cap = 0;
    if (g_backend->mem_read(this_ptr + 0x18u, &old_cap, 4) != UC_ERR_OK) return false;
    uint32_t old_ptr = 0;
    if (old_cap < 0x10u) {
        old_ptr = this_ptr + 4u;
    } else if (g_backend->mem_read(this_ptr + 4u, &old_ptr, 4) != UC_ERR_OK) {
        return false;
    }
    if (old_ptr < 0x1000u) return false;

    uint32_t new_cap = requested | 0x0Fu;
    if (old_cap <= 0xFFFFFFFDu) {
        uint32_t grow = old_cap + (old_cap >> 1);
        if (grow > new_cap) new_cap = grow;
    }
    if (new_cap < requested || new_cap >= 0xFFFFFFFEu) return false;
    if (new_cap < 0x10u) return false; // keep inline-buffer edge cases on original path
    if (copy_len > new_cap) return false;

    uint32_t new_ptr = 0;
    if (!crt_alloc_fast(new_cap + 1u, new_ptr)) return false;
    if (copy_len > 0u && !host_memmove_copy(new_ptr, old_ptr, copy_len)) return false;
    uint8_t nul = 0;
    if (g_backend->mem_write(new_ptr + copy_len, &nul, 1) != UC_ERR_OK) return false;

    if (g_backend->mem_write(this_ptr + 4u, &new_ptr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_write(this_ptr + 0x18u, &new_cap, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_write(this_ptr + 0x14u, &copy_len, 4) != UC_ERR_OK) return false;
    if (old_cap >= 0x10u) {
        // Original path would release old heap storage.
        g_crt_free_fast_count++;
    }

    uint32_t new_esp = esp + 12u; // ret 8
    uc_reg_write(uc, UC_X86_REG_EAX, &this_ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_string_grow_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += copy_len;
    return true;
}

static bool accelerate_crt_alloc_wrappers(uc_engine* uc, uint32_t addr32) {
    if (!g_crt_alloc_accel_enabled) return false;
    if (addr32 != 0x61c130u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    uint32_t size = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &size, 4) != UC_ERR_OK) return false;
    if (size > (1u << 28)) return false;
    uint32_t ptr = 0;
    if (!crt_alloc_fast(size, ptr)) return false;

    uint32_t new_esp = esp + 4u; // cdecl
    uc_reg_write(uc, UC_X86_REG_EAX, &ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += size;
    return true;
}

static bool accelerate_crt_heapalloc_callsite_621182(uc_engine* uc, uint32_t addr32) {
    if (!g_crt_alloc_accel_enabled) return false;
    if (addr32 != 0x621182u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t request_size = 0;
    if (g_backend->mem_read(esp, &request_size, 4) != UC_ERR_OK) return false;
    if (request_size > (1u << 28)) return false;

    uint32_t ptr = 0;
    if (!crt_alloc_fast(request_size, ptr)) return false;

    // call ebx (HeapAlloc stdcall) consumes 3 args, one of which (size) was already
    // pushed before entering 0x621182. Net effect at this block entry is ESP += 4.
    uint32_t new_esp = esp + 4u;
    uint32_t eip = 0x62118bu; // continue right after call ebx
    uc_reg_write(uc, UC_X86_REG_EAX, &ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += (request_size == 0u) ? 1u : static_cast<uint64_t>((request_size + 15u) & ~15u);
    return true;
}

static bool accelerate_crt_heapfree_callsite_61fccx(uc_engine* uc, uint32_t addr32) {
    if (!g_crt_alloc_accel_enabled) return false;
    if (addr32 != 0x61fcc5u && addr32 != 0x61fcc6u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t eax = 1u;         // HeapFree success
    uint32_t eip = 0x61fceeu;  // success continuation
    // 0x61fcc6 is a branch target where pointer arg was pushed before this block.
    // call [HeapFree] would consume that arg as part of stdcall cleanup.
    if (addr32 == 0x61fcc6u) {
        uint32_t new_esp = esp + 4u;
        uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    }
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);

    g_crt_free_fast_count++;
    g_hot_loop_accel_hits++;
    return true;
}

static bool accelerate_lock_wrappers_62ce88_62cf60(uc_engine* uc, uint32_t addr32) {
    if (!g_hot_loop_accel_enabled) return false;
    if (addr32 != 0x62ce88u && addr32 != 0x62cf60u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;

    uint32_t lock_id = 0;
    if (g_backend->mem_read(esp + 4u, &lock_id, 4) != UC_ERR_OK) return false;
    if (lock_id > 0x80u) return false;

    // Enter-lock wrapper may do one-time setup on empty slot.
    // Keep original path until slot is initialized.
    if (addr32 == 0x62cf60u) {
        uint32_t slot_addr = 0x69a8f8u + lock_id * 8u;
        uint32_t slot_lock_ptr = 0;
        if (g_backend->mem_read(slot_addr, &slot_lock_ptr, 4) != UC_ERR_OK) return false;
        if (slot_lock_ptr == 0u) return false;
    }

    uint32_t eax = 1u;
    uint32_t new_esp = esp + 4u; // plain ret
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_lock_wrapper_fast_count++;
    g_hot_loop_accel_hits++;
    return true;
}

static bool accelerate_tiny_control_blocks(uc_engine* uc, uint32_t addr32) {
    if (!g_hot_loop_accel_enabled) return false;

    if (addr32 == 0x62ce9bu) {
        uint32_t esp = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uint32_t new_ebp = 0;
        uint32_t ret_addr = 0;
        if (g_backend->mem_read(esp, &new_ebp, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_read(esp + 4u, &ret_addr, 4) != UC_ERR_OK) return false;
        uint32_t new_esp = esp + 8u;
        uc_reg_write(uc, UC_X86_REG_EBP, &new_ebp);
        uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
        uc_emu_stop(uc);
        g_tiny_ctrl_fast_count++;
        g_hot_loop_accel_hits++;
        return true;
    }

    if (addr32 == 0x62cf8eu) {
        uint32_t esp = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uint32_t new_esi = 0;
        uint32_t new_ebp = 0;
        uint32_t ret_addr = 0;
        if (g_backend->mem_read(esp, &new_esi, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_read(esp + 4u, &new_ebp, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_read(esp + 8u, &ret_addr, 4) != UC_ERR_OK) return false;
        uint32_t new_esp = esp + 12u;
        uc_reg_write(uc, UC_X86_REG_ESI, &new_esi);
        uc_reg_write(uc, UC_X86_REG_EBP, &new_ebp);
        uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
        uc_emu_stop(uc);
        g_tiny_ctrl_fast_count++;
        g_hot_loop_accel_hits++;
        return true;
    }

    if (addr32 == 0x62118bu) {
        uint32_t eax = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_ESI, &eax);
        uint32_t next = (eax != 0u) ? 0x6211b7u : 0x621191u;
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_tiny_ctrl_fast_count++;
        g_hot_loop_accel_hits++;
        return true;
    }

    if (addr32 == 0x61fcd4u) {
        uint32_t eax = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        uint32_t next = (eax != 0u) ? 0x61fceeu : 0x61fcd8u;
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_tiny_ctrl_fast_count++;
        g_hot_loop_accel_hits++;
        return true;
    }

    return false;
}

static bool accelerate_fast_worker_thread(uc_engine* uc, uint32_t addr32) {
    if (!g_fast_worker_thread_enabled) return false;
    if (addr32 != 0x5d5dc0u && addr32 != 0x5d5f20u && addr32 != 0x5d5f30u) return false;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 1;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (ret_addr != 0u) return false; // only synthetic CreateThread entry (ret sentinel=0)

    uint32_t eax = 0;
    uint32_t eip = 0;
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    return true;
}

static bool accelerate_string_range_view_456610(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x456610u) return false;

    uint32_t dest = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &dest);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (dest < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t begin_ptr = 0;
    uint32_t src_obj = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &begin_ptr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &src_obj, 4) != UC_ERR_OK) return false;

    uint32_t zero = 0;
    if (g_backend->mem_write(dest, &zero, 4) != UC_ERR_OK) return false;

    bool invalid_range = false;
    uint32_t data_ptr = 0;
    uint32_t data_end = 0;
    if (src_obj == 0u || begin_ptr == 0u || src_obj < 0x1000u) {
        invalid_range = true;
    } else {
        uint32_t len = 0;
        uint32_t cap = 0;
        if (g_backend->mem_read(src_obj + 0x14u, &len, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_read(src_obj + 0x18u, &cap, 4) != UC_ERR_OK) return false;
        if (cap < 0x10u) {
            data_ptr = src_obj + 4u;
        } else if (g_backend->mem_read(src_obj + 4u, &data_ptr, 4) != UC_ERR_OK) {
            return false;
        }
        if (data_ptr < 0x1000u) return false;
        if (data_ptr + len < data_ptr) return false;
        data_end = data_ptr + len;
        if (begin_ptr < data_ptr || begin_ptr > data_end) {
            invalid_range = true;
        }
    }

    if (invalid_range) {
        g_string_range_invalid_count++;
        if (g_string_range_clamp_enabled && data_ptr >= 0x1000u) {
            uint32_t clamped = begin_ptr;
            if (clamped < data_ptr) clamped = data_ptr;
            if (clamped > data_end) clamped = data_end;
            if (clamped != begin_ptr) {
                begin_ptr = clamped;
                g_string_range_clamped_count++;
            }
        }
        if (g_string_range_trace_enabled) {
            static uint64_t trace_count = 0;
            trace_count++;
            if (trace_count <= 32 || (trace_count % 1024u) == 0u) {
                cout << "[HOT ACCEL] string-range invalid caller=0x" << hex << ret_addr
                     << " src=0x" << src_obj
                     << " begin=0x" << begin_ptr
                     << " data=[0x" << data_ptr << ",0x" << data_end << "]"
                     << " clamp=" << (g_string_range_clamp_enabled ? "on" : "off")
                     << dec << "\n";
            }
        }
    }

    if (g_backend->mem_write(dest, &src_obj, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_write(dest + 4u, &begin_ptr, 4) != UC_ERR_OK) return false;

    uint32_t new_esp = esp + 12u; // ret 8
    uc_reg_write(uc, UC_X86_REG_EAX, &dest);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_string_range_fast_count++;
    g_hot_loop_accel_hits++;
    return true;
}

static bool accelerate_security_cookie_check_61efd1(uc_engine* uc, uint32_t addr32) {
    if (!g_security_cookie_accel_enabled) return false;
    if (addr32 != 0x61efd1u) return false;

    uint32_t ecx = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t cookie = 0;
    if (g_backend->mem_read(0x699fe8u, &cookie, 4) != UC_ERR_OK) return false;
    if (ecx != cookie) return false; // preserve mismatch/fail path

    uint32_t ret_addr = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    uint32_t new_esp = esp + 4u;
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_security_cookie_fast_count++;
    g_hot_loop_accel_hits++;
    return true;
}

static bool accelerate_lock_gate_probe_5a1640(uc_engine* uc, uint32_t addr32) {
    if (!g_lock_gate_probe_accel_enabled) return false;
    if (addr32 != 0x5a1640u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;

    uint32_t gate = 0;
    if (g_backend->mem_read(0x6a9f70u, &gate, 4) != UC_ERR_OK) return false;
    if (gate == 0u) return false; // preserve alternate branch semantics

    uint32_t gate_ptr = 0;
    if (g_backend->mem_read(0x6a9f74u, &gate_ptr, 4) != UC_ERR_OK) return false;
    if (gate_ptr < 0x1000u) return false;

    uint32_t gate_value = 0;
    if (g_backend->mem_read(gate_ptr, &gate_value, 4) != UC_ERR_OK) return false;

    uint32_t new_esp = esp + 4u;
    uc_reg_write(uc, UC_X86_REG_EAX, &gate_value);
    uc_reg_write(uc, UC_X86_REG_EDX, &gate_ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_lock_gate_probe_fast_count++;
    g_hot_loop_accel_hits++;
    return true;
}

static bool accelerate_wstring_append_fill_5bd830(uc_engine* uc, uint32_t addr32) {
    if (!g_wstring_append_accel_enabled) return false;
    if (addr32 != 0x5bd830u) return false;

    uint32_t this_ptr = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &this_ptr);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (this_ptr < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t append_count = 0;
    uint32_t append_value = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &append_count, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &append_value, 4) != UC_ERR_OK) return false;
    if (append_count > (1u << 24)) return false;

    uint32_t len = 0;
    uint32_t cap = 0;
    if (g_backend->mem_read(this_ptr + 0x14u, &len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(this_ptr + 0x18u, &cap, 4) != UC_ERR_OK) return false;

    if (len > 0x7ffffffeu) return false;
    if (append_count > 0x7ffffffeu - len) return false;
    uint32_t new_len = len + append_count;
    if (new_len > 0x7ffffffeu) return false;
    if (new_len > cap) return false; // preserve grow path semantics by falling back to guest

    uint32_t data_ptr = 0;
    if (cap < 8u) {
        data_ptr = this_ptr + 4u;
    } else if (g_backend->mem_read(this_ptr + 4u, &data_ptr, 4) != UC_ERR_OK) {
        return false;
    }
    if (data_ptr < 0x1000u) return false;

    uint32_t write_off = data_ptr + (len * 2u);
    if (append_count > 0u) {
        uint16_t ch = static_cast<uint16_t>(append_value & 0xFFFFu);
        constexpr size_t kChunkWchars = 1024;
        vector<uint16_t> chunk(kChunkWchars, ch);
        uint32_t remain = append_count;
        while (remain > 0u) {
            uint32_t step = std::min<uint32_t>(remain, static_cast<uint32_t>(kChunkWchars));
            size_t bytes = static_cast<size_t>(step) * sizeof(uint16_t);
            if (g_backend->mem_write(write_off, chunk.data(), bytes) != UC_ERR_OK) return false;
            write_off += static_cast<uint32_t>(bytes);
            remain -= step;
        }
    }

    uint16_t nul = 0;
    uint32_t nul_addr = data_ptr + (new_len * 2u);
    if (g_backend->mem_write(nul_addr, &nul, sizeof(nul)) != UC_ERR_OK) return false;
    if (g_backend->mem_write(this_ptr + 0x14u, &new_len, 4) != UC_ERR_OK) return false;

    uint32_t new_esp = esp + 12u; // ret 8
    uc_reg_write(uc, UC_X86_REG_EAX, &this_ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_wstring_append_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += static_cast<uint64_t>(append_count) * 2u;
    return true;
}

static bool accelerate_iter_advance_5bf4e0(uc_engine* uc, uint32_t addr32) {
    if (!g_iter_advance_accel_enabled) return false;
    if (addr32 != 0x5bf4e0u) return false;

    uint32_t this_ptr = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &this_ptr);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (this_ptr < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t delta = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &delta, 4) != UC_ERR_OK) return false;

    uint32_t owner = 0;
    uint32_t cur = 0;
    if (g_backend->mem_read(this_ptr, &owner, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(this_ptr + 4u, &cur, 4) != UC_ERR_OK) return false;

    uint32_t new_cur = cur + delta;
    if (owner != 0xFFFFFFFEu) {
        if (owner < 0x1000u) return false;
        uint32_t len = 0;
        uint32_t cap = 0;
        if (g_backend->mem_read(owner + 0x14u, &len, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_read(owner + 0x18u, &cap, 4) != UC_ERR_OK) return false;

        uint32_t data_ptr = 0;
        if (cap < 0x10u) {
            data_ptr = owner + 4u;
        } else if (g_backend->mem_read(owner + 4u, &data_ptr, 4) != UC_ERR_OK) {
            return false;
        }
        if (data_ptr < 0x1000u) return false;
        if (data_ptr + len < data_ptr) return false;
        uint32_t data_end = data_ptr + len;
        if (new_cur > data_end) return false;
        if (new_cur < data_ptr) return false;
    }

    if (g_backend->mem_write(this_ptr + 4u, &new_cur, 4) != UC_ERR_OK) return false;

    uint32_t new_esp = esp + 8u; // ret 4
    uc_reg_write(uc, UC_X86_REG_EAX, &this_ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_iter_advance_fast_count++;
    g_hot_loop_accel_hits++;
    uint64_t moved = (delta & 0x80000000u) ? 1u : static_cast<uint64_t>(delta);
    g_hot_loop_accel_bytes += (moved == 0u ? 1u : moved);
    return true;
}

static bool accelerate_memmove_s_61be96(uc_engine* uc, uint32_t addr32) {
    if (!g_memmove_s_accel_enabled) return false;
    if (addr32 != 0x61be96u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    uint32_t dst = 0;
    uint32_t dstsz = 0;
    uint32_t src = 0;
    uint32_t count = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &dst, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &dstsz, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 12u, &src, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 16u, &count, 4) != UC_ERR_OK) return false;

    if (count > (1u << 27)) return false;

    uint32_t eax = 0u;
    if (count == 0u) {
        eax = 0u;
    } else if (dst == 0u || src == 0u) {
        eax = 0x16u;
    } else if (dstsz < count) {
        eax = 0x22u;
    } else {
        if (!host_memmove_copy(dst, src, count)) return false;
        eax = 0u;
    }

    uint32_t new_esp = esp + 4u; // cdecl: pop return only
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_memmove_s_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += (count == 0u ? 1u : static_cast<uint64_t>(count));
    return true;
}

static bool accelerate_stream_pop_5bb880(uc_engine* uc, uint32_t addr32) {
    if (!g_stream_pop_accel_enabled) return false;
    if (addr32 != 0x5bb880u) return false;

    uint32_t this_ptr = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &this_ptr);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (this_ptr < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t out_ptr = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &out_ptr, 4) != UC_ERR_OK) return false;

    if (out_ptr == 0u) {
        uint32_t eax = 3u;
        uint32_t new_esp = esp + 8u; // ret 4
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
        uc_emu_stop(uc);
        g_stream_pop_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    uint32_t begin_ptr = 0;
    uint32_t end_ptr = 0;
    if (g_backend->mem_read(this_ptr + 0x0cu, &begin_ptr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(this_ptr + 0x10u, &end_ptr, 4) != UC_ERR_OK) return false;
    if (begin_ptr == 0u) return false;
    if (end_ptr < begin_ptr) return false;
    uint32_t avail_bytes = end_ptr - begin_ptr;
    if ((avail_bytes >> 1) == 0u) return false;
    if (end_ptr < 2u) return false;
    uint32_t src_ptr = end_ptr - 2u;
    if (src_ptr < begin_ptr || src_ptr >= end_ptr) return false;

    uint16_t ch = 0;
    if (g_backend->mem_read(src_ptr, &ch, 2) != UC_ERR_OK) return false;
    if (g_backend->mem_write(out_ptr, &ch, 2) != UC_ERR_OK) return false;

    uint32_t mark_ptr = 0;
    if (g_backend->mem_read(this_ptr + 0x0cu, &mark_ptr, 4) != UC_ERR_OK) return false;
    if (mark_ptr != 0u && end_ptr >= mark_ptr) {
        uint32_t remain = end_ptr - mark_ptr;
        if ((remain >> 1) != 0u) {
            uint32_t new_end = end_ptr - 2u;
            if (g_backend->mem_write(this_ptr + 0x10u, &new_end, 4) != UC_ERR_OK) return false;
        }
    }

    uint32_t eax = 0u;
    uint32_t new_esp = esp + 8u; // ret 4
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_stream_pop_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += 2u;
    return true;
}

static bool accelerate_streambuf_branch_blocks(uc_engine* uc, uint32_t addr32) {
    if (!g_streambuf_branch_accel_enabled) return false;

    if (addr32 == 0x5bb880u) {
        uint32_t esp = 0;
        uint32_t ecx = 0;
        uint32_t ebx = 0;
        uint32_t edi = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
        uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
        uc_reg_read(uc, UC_X86_REG_EDI, &edi);

        uint32_t arg_out = 0;
        if (g_backend->mem_read(esp + 4u, &arg_out, 4) != UC_ERR_OK) return false;

        uint32_t esp1 = esp - 4u;
        if (g_backend->mem_write(esp1, &ebx, 4) != UC_ERR_OK) return false; // push ebx
        uint32_t esp2 = esp1 - 4u;
        if (g_backend->mem_write(esp2, &edi, 4) != UC_ERR_OK) return false; // push edi

        ebx = arg_out;
        edi = ecx;
        uint32_t next = (ebx != 0u) ? 0x5bb894u : 0x5bb88cu;
        uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
        uc_reg_write(uc, UC_X86_REG_EDI, &edi);
        uc_reg_write(uc, UC_X86_REG_ESP, &esp2);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);

        g_streambuf_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x5bb894u) {
        uint32_t esp = 0;
        uint32_t edi = 0;
        uint32_t esi = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uc_reg_read(uc, UC_X86_REG_EDI, &edi);
        uc_reg_read(uc, UC_X86_REG_ESI, &esi);

        uint32_t eax = 0;
        if (g_backend->mem_read(edi + 0x0cu, &eax, 4) != UC_ERR_OK) return false;
        uint32_t esp2 = esp - 4u;
        if (g_backend->mem_write(esp2, &esi, 4) != UC_ERR_OK) return false; // push esi
        esi = edi + 8u;

        uint32_t next = (eax == 0u) ? 0x5bb8d5u : 0x5bb89fu;
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_ESI, &esi);
        uc_reg_write(uc, UC_X86_REG_ESP, &esp2);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);

        g_streambuf_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x5bb89fu) {
        uint32_t esi = 0;
        uint32_t eax = 0;
        uc_reg_read(uc, UC_X86_REG_ESI, &esi);
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);

        uint32_t ecx = 0;
        if (g_backend->mem_read(esi + 8u, &ecx, 4) != UC_ERR_OK) return false;
        int32_t diff = static_cast<int32_t>(ecx - eax);
        diff >>= 1;
        ecx = static_cast<uint32_t>(diff);
        uint32_t next = (ecx == 0u) ? 0x5bb8d5u : 0x5bb8a8u;
        uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);

        g_streambuf_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    return false;
}

static bool accelerate_xml_branch_blocks(uc_engine* uc, uint32_t addr32) {
    if (!g_xml_branch_accel_enabled) return false;

    if (addr32 == 0x5a1f72u) {
        uint32_t eax = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        uint32_t next = (eax != 0u) ? 0x5a2f78u : 0x5a1f7bu;
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_xml_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x5a1f7bu) {
        uint32_t esp = 0;
        uint32_t ebx = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uc_reg_read(uc, UC_X86_REG_EBX, &ebx);

        uint32_t edx = 0;
        if (g_backend->mem_read(esp + 0x24u, &edx, 4) != UC_ERR_OK) return false;
        ebx &= 0xFFFFFF00u; // xor bl, bl
        uint16_t dx = static_cast<uint16_t>(edx & 0xFFFFu);
        uint32_t next = (dx != 0x000Au) ? 0x5a1f8bu : 0x5a1f87u;
        uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
        uc_reg_write(uc, UC_X86_REG_EDX, &edx);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_xml_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x5a1f8bu) {
        uint32_t esp = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uint32_t ecx = 0;
        if (g_backend->mem_read(esp + 0x18u, &ecx, 4) != UC_ERR_OK) return false;
        uint32_t eax = 0;
        if (g_backend->mem_read(ecx, &eax, 4) != UC_ERR_OK) return false;
        uint32_t next = (eax != 5u) ? 0x5a2052u : 0x5a1f9au;
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_xml_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x5a2052u) {
        uint32_t eax = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        uint32_t next = (eax != 4u) ? 0x5a210au : 0x5a205bu;
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_xml_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x5a210au) {
        uint32_t edx = 0;
        uc_reg_read(uc, UC_X86_REG_EDX, &edx);
        uint16_t dx = static_cast<uint16_t>(edx & 0xFFFFu);
        uint32_t next = (dx != 0x0022u) ? 0x5a217du : 0x5a2110u;
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_xml_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    return false;
}

static bool accelerate_text_norm_branch_blocks(uc_engine* uc, uint32_t addr32) {
    if (!g_text_norm_branch_accel_enabled) return false;

    if (addr32 == 0x62b0d8u) {
        uint32_t ebp = 0;
        uint32_t eax = 0;
        uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);

        uint32_t ecx = 0;
        if (g_backend->mem_read(ebp + 0x10u, &ecx, 4) != UC_ERR_OK) return false;
        uint8_t al = 0;
        if (g_backend->mem_read(ecx, &al, 1) != UC_ERR_OK) return false;

        eax = (eax & 0xFFFFFF00u) | static_cast<uint32_t>(al);
        uint32_t next = (al == 0x1Au) ? 0x62b193u : 0x62b0e5u;
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_text_norm_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x62b0e5u) {
        uint32_t eax = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        uint8_t al = static_cast<uint8_t>(eax & 0xFFu);
        uint32_t next = (al == 0x0Du) ? 0x62b0f5u : 0x62b0e9u;
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_text_norm_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x62b0e9u) {
        uint32_t eax = 0;
        uint32_t ebx = 0;
        uint32_t ecx = 0;
        uint32_t ebp = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
        uc_reg_read(uc, UC_X86_REG_EBP, &ebp);

        uint8_t al = static_cast<uint8_t>(eax & 0xFFu);
        if (g_backend->mem_write(ebx, &al, 1) != UC_ERR_OK) return false;
        ebx += 1u;
        ecx += 1u;
        if (g_backend->mem_write(ebp + 0x10u, &ecx, 4) != UC_ERR_OK) return false;

        uint32_t next = 0x62b185u;
        uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
        uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_text_norm_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x62b0f5u) {
        uint32_t ebp = 0;
        uint32_t ecx = 0;
        uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

        uint32_t eax = 0;
        if (g_backend->mem_read(ebp - 0x10u, &eax, 4) != UC_ERR_OK) return false;
        eax -= 1u;
        uint32_t next = (ecx >= eax) ? 0x62b114u : 0x62b0fdu;
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_text_norm_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x62b0fdu) {
        uint32_t ecx = 0;
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

        uint32_t eax = ecx + 1u;
        uint8_t next_ch = 0;
        if (g_backend->mem_read(eax, &next_ch, 1) != UC_ERR_OK) return false;

        uint32_t next = (next_ch != 0x0Au) ? 0x62b10fu : 0x62b105u;
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_text_norm_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x62b105u) {
        uint32_t ebp = 0;
        uint32_t ebx = 0;
        uint32_t ecx = 0;
        uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
        uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

        ecx += 2u;
        if (g_backend->mem_write(ebp + 0x10u, &ecx, 4) != UC_ERR_OK) return false;
        uint8_t lf = 0x0A;
        if (g_backend->mem_write(ebx, &lf, 1) != UC_ERR_OK) return false;

        uint32_t next = 0x62b184u;
        uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_text_norm_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    if (addr32 == 0x62b184u || addr32 == 0x62b185u) {
        uint32_t ebp = 0;
        uint32_t ebx = 0;
        uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
        uc_reg_read(uc, UC_X86_REG_EBX, &ebx);

        if (addr32 == 0x62b184u) {
            ebx += 1u;
            uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
        }

        uint32_t eax = 0;
        uint32_t src_cur = 0;
        if (g_backend->mem_read(ebp - 0x10u, &eax, 4) != UC_ERR_OK) return false;
        if (g_backend->mem_read(ebp + 0x10u, &src_cur, 4) != UC_ERR_OK) return false;
        uint32_t next = (src_cur < eax) ? 0x62b0d8u : 0x62b191u;

        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_EIP, &next);
        uc_emu_stop(uc);
        g_text_norm_branch_fast_count++;
        g_hot_loop_accel_hits++;
        g_hot_loop_accel_bytes += 1u;
        return true;
    }

    return false;
}

static bool accelerate_string_insert_fill_55d410(uc_engine* uc, uint32_t addr32) {
    if (!g_string_insert_accel_enabled) return false;
    if (addr32 != 0x55d410u) return false;

    uint32_t this_ptr = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &this_ptr);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (this_ptr < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t pos = 0;
    uint32_t insert_count = 0;
    uint32_t value = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &pos, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &insert_count, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 12u, &value, 4) != UC_ERR_OK) return false;
    if (insert_count > (1u << 24)) return false;

    uint32_t len = 0;
    uint32_t cap = 0;
    if (g_backend->mem_read(this_ptr + 0x14u, &len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(this_ptr + 0x18u, &cap, 4) != UC_ERR_OK) return false;

    if (pos > len) return false;
    if (insert_count > 0x7ffffffeu - len) return false;
    uint32_t new_len = len + insert_count;
    if (new_len > 0x7ffffffeu) return false;
    if (new_len > cap) return false; // preserve grow path via guest fallback

    uint32_t data_ptr = 0;
    if (cap < 0x10u) {
        data_ptr = this_ptr + 4u;
    } else if (g_backend->mem_read(this_ptr + 4u, &data_ptr, 4) != UC_ERR_OK) {
        return false;
    }
    if (data_ptr < 0x1000u) return false;

    if (insert_count > 0u) {
        uint32_t tail_count = len - pos;
        if (tail_count > 0u) {
            vector<uint8_t> tail(tail_count, 0);
            uint32_t src = data_ptr + pos;
            uint32_t dst = data_ptr + pos + insert_count;
            if (g_backend->mem_read(src, tail.data(), tail.size()) != UC_ERR_OK) return false;
            if (g_backend->mem_write(dst, tail.data(), tail.size()) != UC_ERR_OK) return false;
        }

        uint8_t ch = static_cast<uint8_t>(value & 0xFFu);
        constexpr size_t kChunk = 4096;
        vector<uint8_t> fill(kChunk, ch);
        uint32_t remain = insert_count;
        uint32_t write_addr = data_ptr + pos;
        while (remain > 0u) {
            uint32_t step = std::min<uint32_t>(remain, static_cast<uint32_t>(kChunk));
            if (g_backend->mem_write(write_addr, fill.data(), step) != UC_ERR_OK) return false;
            write_addr += step;
            remain -= step;
        }
    }

    uint8_t nul = 0;
    if (g_backend->mem_write(data_ptr + new_len, &nul, 1) != UC_ERR_OK) return false;
    if (g_backend->mem_write(this_ptr + 0x14u, &new_len, 4) != UC_ERR_OK) return false;

    uint32_t new_esp = esp + 16u; // ret 0xC
    uc_reg_write(uc, UC_X86_REG_EAX, &this_ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_string_insert_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += (insert_count == 0u ? 1u : static_cast<uint64_t>(insert_count));
    return true;
}

static bool accelerate_insert_iter_5bba20(uc_engine* uc, uint32_t addr32) {
    if (!g_insert_iter_accel_enabled) return false;
    if (addr32 != 0x5bba20u) return false;

    uint32_t str_obj = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESI, &str_obj);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (str_obj < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t out_iter = 0;
    uint32_t value = 0;
    uint32_t iter_owner = 0;
    uint32_t iter_ptr = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &out_iter, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &value, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 12u, &iter_owner, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 16u, &iter_ptr, 4) != UC_ERR_OK) return false;
    if (out_iter < 0x1000u) return false;

    uint32_t len = 0;
    uint32_t cap = 0;
    if (g_backend->mem_read(str_obj + 0x14u, &len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(str_obj + 0x18u, &cap, 4) != UC_ERR_OK) return false;
    if (len > 0x7ffffffeu) return false;
    if (len + 1u > cap) return false; // preserve grow path via guest fallback

    uint32_t data_ptr = 0;
    if (cap < 0x10u) {
        data_ptr = str_obj + 4u;
    } else if (g_backend->mem_read(str_obj + 4u, &data_ptr, 4) != UC_ERR_OK) {
        return false;
    }
    if (data_ptr < 0x1000u) return false;

    uint32_t index = 0;
    if (iter_ptr != 0u) {
        if (iter_owner != 0xFFFFFFFEu) {
            if (iter_owner == 0u) return false;
            if (iter_owner != str_obj) return false;
        }
        if (iter_ptr < data_ptr) return false;
        index = iter_ptr - data_ptr;
    }
    if (index > len) return false;

    uint32_t tail_count = len - index;
    if (tail_count > 0u) {
        vector<uint8_t> tail(tail_count, 0);
        if (g_backend->mem_read(data_ptr + index, tail.data(), tail.size()) != UC_ERR_OK) return false;
        if (g_backend->mem_write(data_ptr + index + 1u, tail.data(), tail.size()) != UC_ERR_OK) return false;
    }

    uint8_t ch = static_cast<uint8_t>(value & 0xFFu);
    if (g_backend->mem_write(data_ptr + index, &ch, 1) != UC_ERR_OK) return false;
    uint8_t nul = 0;
    uint32_t new_len = len + 1u;
    if (g_backend->mem_write(data_ptr + new_len, &nul, 1) != UC_ERR_OK) return false;
    if (g_backend->mem_write(str_obj + 0x14u, &new_len, 4) != UC_ERR_OK) return false;

    uint32_t out_ptr_value = data_ptr + index;
    if (g_backend->mem_write(out_iter, &str_obj, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_write(out_iter + 4u, &out_ptr_value, 4) != UC_ERR_OK) return false;

    uint32_t new_esp = esp + 20u; // ret 0x10
    uc_reg_write(uc, UC_X86_REG_EAX, &out_iter);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_insert_iter_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += 1u;
    return true;
}

static bool accelerate_wstr_to_str_small_5afbb0(uc_engine* uc, uint32_t addr32) {
    if (!g_wstr_to_str_accel_enabled) return false;
    if (addr32 != 0x5afbb0u) return false;

    uint32_t dst_obj = 0;
    uint32_t src_obj = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_EDI, &dst_obj);
    uc_reg_read(uc, UC_X86_REG_EBX, &src_obj);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (dst_obj < 0x1000u || src_obj < 0x1000u) return false;

    uint32_t src_len = 0;
    uint32_t src_cap = 0;
    if (g_backend->mem_read(src_obj + 0x14u, &src_len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(src_obj + 0x18u, &src_cap, 4) != UC_ERR_OK) return false;
    if (src_len > 15u) return false; // keep to SSO-only fast-path

    uint32_t src_ptr = 0;
    if (src_cap < 8u) {
        src_ptr = src_obj + 4u;
    } else if (g_backend->mem_read(src_obj + 4u, &src_ptr, 4) != UC_ERR_OK) {
        return false;
    }
    if (src_ptr < 0x1000u) return false;

    vector<uint8_t> wbuf(static_cast<size_t>(src_len) * 2u, 0);
    if (!wbuf.empty()) {
        if (g_backend->mem_read(src_ptr, wbuf.data(), wbuf.size()) != UC_ERR_OK) return false;
    }

    uint32_t dst_cap = 15u;
    if (g_backend->mem_write(dst_obj + 0x18u, &dst_cap, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_write(dst_obj + 0x14u, &src_len, 4) != UC_ERR_OK) return false;

    vector<uint8_t> nbuf(static_cast<size_t>(src_len) + 1u, 0);
    for (uint32_t i = 0; i < src_len; ++i) {
        nbuf[i] = wbuf[static_cast<size_t>(i) * 2u];
    }
    nbuf[src_len] = 0;
    if (g_backend->mem_write(dst_obj + 4u, nbuf.data(), nbuf.size()) != UC_ERR_OK) return false;

    uint32_t ret_addr = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    uint32_t new_esp = esp + 4u; // ret
    uc_reg_write(uc, UC_X86_REG_EAX, &dst_obj);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_wstr_to_str_fast_count++;
    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += (src_len == 0u ? 1u : static_cast<uint64_t>(src_len));
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

static bool accelerate_toupper_cdecl(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x61e4e6u) return false;
    uint32_t locale_flag = 0;
    if (g_backend->mem_read(0x6a66f4u, &locale_flag, 4) != UC_ERR_OK) return false;
    if (locale_flag != 0u) return false;

    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = 0;
    uint32_t arg = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4, &arg, 4) != UC_ERR_OK) return false;

    uint32_t c = arg & 0xFFu;
    uint32_t result = arg;
    if (c >= static_cast<uint32_t>('a') && c <= static_cast<uint32_t>('z')) {
        result = (arg & 0xFFFFFF00u) | (c - 0x20u);
    }

    uint32_t new_esp = esp + 4; // cdecl: callee pops only return address
    uc_reg_write(uc, UC_X86_REG_EAX, &result);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += 1;
    return true;
}

static bool accelerate_single_char_store_helper_441dd0(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x441dd0u) return false;

    uint32_t ecx = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (ecx < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t index = 0;
    uint32_t count = 0;
    uint32_t value = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4u, &index, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8u, &count, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 12u, &value, 4) != UC_ERR_OK) return false;
    if (count != 1u) return false;

    uint32_t cap = 0;
    if (g_backend->mem_read(ecx + 0x18u, &cap, 4) != UC_ERR_OK) return false;
    uint32_t data_ptr = 0;
    if (cap < 0x10u) {
        data_ptr = ecx + 4u;
    } else if (g_backend->mem_read(ecx + 4u, &data_ptr, 4) != UC_ERR_OK) {
        return false;
    }
    if (data_ptr < 0x1000u) return false;

    uint8_t ch = static_cast<uint8_t>(value & 0xFFu);
    if (g_backend->mem_write(data_ptr + index, &ch, 1) != UC_ERR_OK) return false;

    uint32_t eax = 1u;
    uint32_t new_esp = esp + 16u; // ret + 3 args (ret 0xC)
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += 1;
    return true;
}

static bool accelerate_small_string_cap_branch_441dd9(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x441dd9u) return false;
    uint32_t ecx = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    if (ecx < 0x1000u) return false;
    uint32_t cap = 0;
    if (g_backend->mem_read(ecx + 0x18u, &cap, 4) != UC_ERR_OK) return false;
    uint32_t eip = (cap < 0x10u) ? 0x441df0u : 0x441ddfu;
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);
    g_hot_loop_accel_hits++;
    return true;
}

static bool accelerate_string_append_one_char(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x441d20u) return false;

    uint32_t this_ptr = 0;
    uint32_t esp = 0;
    uc_reg_read(uc, UC_X86_REG_ECX, &this_ptr);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    if (this_ptr < 0x1000u) return false;

    uint32_t ret_addr = 0;
    uint32_t count = 0;
    uint32_t value = 0;
    if (g_backend->mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 4, &count, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(esp + 8, &value, 4) != UC_ERR_OK) return false;
    if (count != 1u) return false;

    uint32_t len = 0;
    uint32_t cap = 0;
    if (g_backend->mem_read(this_ptr + 0x14u, &len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(this_ptr + 0x18u, &cap, 4) != UC_ERR_OK) return false;
    if (len >= cap || cap == 0xFFFFFFFFu) return false;

    uint32_t data_ptr = 0;
    if (cap < 0x10u) {
        data_ptr = this_ptr + 4u; // SSO buffer
    } else {
        if (g_backend->mem_read(this_ptr + 4u, &data_ptr, 4) != UC_ERR_OK) return false;
    }
    if (data_ptr < 0x1000u) return false;

    uint8_t ch = static_cast<uint8_t>(value & 0xFFu);
    uint8_t nul = 0;
    if (g_backend->mem_write(data_ptr + len, &ch, 1) != UC_ERR_OK) return false;
    if (g_backend->mem_write(data_ptr + len + 1u, &nul, 1) != UC_ERR_OK) return false;
    uint32_t new_len = len + 1u;
    if (g_backend->mem_write(this_ptr + 0x14u, &new_len, 4) != UC_ERR_OK) return false;

    // thiscall ret 8
    uint32_t new_esp = esp + 12u;
    uc_reg_write(uc, UC_X86_REG_EAX, &this_ptr);
    uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += 1;
    return true;
}

static bool accelerate_uppercase_append_loop(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x5d7c0du) return false;

    uint32_t src_obj = 0, dst_obj = 0, idx = 0;
    uc_reg_read(uc, UC_X86_REG_EBX, &src_obj);
    uc_reg_read(uc, UC_X86_REG_EDI, &dst_obj);
    uc_reg_read(uc, UC_X86_REG_ESI, &idx);
    if (src_obj < 0x1000u || dst_obj < 0x1000u) return false;

    uint32_t src_len = 0, src_cap = 0, dst_len = 0, dst_cap = 0;
    if (g_backend->mem_read(src_obj + 0x14u, &src_len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(src_obj + 0x18u, &src_cap, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(dst_obj + 0x14u, &dst_len, 4) != UC_ERR_OK) return false;
    if (g_backend->mem_read(dst_obj + 0x18u, &dst_cap, 4) != UC_ERR_OK) return false;
    if (idx >= src_len) {
        uint32_t eip = 0x5d7c43u;
        uc_reg_write(uc, UC_X86_REG_EIP, &eip);
        uc_emu_stop(uc);
        g_hot_loop_accel_hits++;
        return true;
    }

    uint32_t remaining = src_len - idx;
    if (remaining == 0) return false;
    if (dst_cap == 0xFFFFFFFFu || dst_len > dst_cap) return false;
    uint32_t available = dst_cap - dst_len;
    if (available == 0) return false;
    uint32_t to_copy = std::min<uint32_t>(remaining, available);
    if (to_copy == 0) return false;

    uint32_t src_ptr = 0, dst_ptr = 0;
    if (src_cap < 0x10u) {
        src_ptr = src_obj + 4u;
    } else if (g_backend->mem_read(src_obj + 4u, &src_ptr, 4) != UC_ERR_OK) {
        return false;
    }
    if (dst_cap < 0x10u) {
        dst_ptr = dst_obj + 4u;
    } else if (g_backend->mem_read(dst_obj + 4u, &dst_ptr, 4) != UC_ERR_OK) {
        return false;
    }
    if (src_ptr < 0x1000u || dst_ptr < 0x1000u) return false;

    vector<uint8_t> buf(to_copy, 0);
    if (g_backend->mem_read(src_ptr + idx, buf.data(), to_copy) != UC_ERR_OK) return false;
    for (uint8_t& ch : buf) {
        if (ch >= static_cast<uint8_t>('a') && ch <= static_cast<uint8_t>('z')) {
            ch = static_cast<uint8_t>(ch - 0x20u);
        }
    }
    if (g_backend->mem_write(dst_ptr + dst_len, buf.data(), to_copy) != UC_ERR_OK) return false;
    uint8_t nul = 0;
    if (g_backend->mem_write(dst_ptr + dst_len + to_copy, &nul, 1) != UC_ERR_OK) return false;
    uint32_t new_len = dst_len + to_copy;
    if (g_backend->mem_write(dst_obj + 0x14u, &new_len, 4) != UC_ERR_OK) return false;

    uint32_t new_idx = idx + to_copy;
    uint32_t eip = 0x5d7c43u; // function epilogue
    if (new_idx < src_len) {
        uint32_t esi_resume = new_idx - 1u;
        uc_reg_write(uc, UC_X86_REG_ESI, &esi_resume);
        eip = 0x5d7c39u; // continue loop after bulk append
    } else {
        uc_reg_write(uc, UC_X86_REG_ESI, &new_idx);
    }
    uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    uc_emu_stop(uc);

    g_hot_loop_accel_hits++;
    g_hot_loop_accel_bytes += to_copy;
    return true;
}

static bool accelerate_strlen_loop_5d8310(uc_engine* uc, uint32_t addr32) {
    if (addr32 != 0x5d8310u) return false;

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
            eax = cursor + static_cast<uint32_t>(offset) + 1u;
            uc_reg_write(uc, UC_X86_REG_EAX, &eax);

            uint32_t ecx = 0;
            uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
            ecx &= 0xFFFFFF00u; // cl = 0
            uc_reg_write(uc, UC_X86_REG_ECX, &ecx);

            uint32_t eip = 0x5d8319u;
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
    if (accelerate_stream_pop_5bb880(uc, addr32)) return true;
    if (accelerate_streambuf_branch_blocks(uc, addr32)) return true;
    if (accelerate_xml_branch_blocks(uc, addr32)) return true;
    if (accelerate_text_norm_branch_blocks(uc, addr32)) return true;
    if (accelerate_wstr_to_str_small_5afbb0(uc, addr32)) return true;
    if (accelerate_insert_iter_5bba20(uc, addr32)) return true;
    if (accelerate_string_insert_fill_55d410(uc, addr32)) return true;
    if (accelerate_memmove_s_61be96(uc, addr32)) return true;
    if (accelerate_iter_advance_5bf4e0(uc, addr32)) return true;
    if (accelerate_wstring_append_fill_5bd830(uc, addr32)) return true;
    if (accelerate_lock_gate_probe_5a1640(uc, addr32)) return true;
    if (accelerate_security_cookie_check_61efd1(uc, addr32)) return true;
    if (accelerate_string_range_view_456610(uc, addr32)) return true;
    if (accelerate_stream_xor_decode_5d8850(uc, addr32)) return true;
    if (accelerate_crt_free_helper_61c19a(uc, addr32)) return true;
    if (accelerate_assign_ptr_404330(uc, addr32)) return true;
    if (accelerate_substr_assign_403e20(uc, addr32)) return true;
    if (accelerate_string_grow_404080(uc, addr32)) return true;
    if (accelerate_crt_alloc_helper_4041c0(uc, addr32)) return true;
    if (accelerate_fast_worker_thread(uc, addr32)) return true;
    if (accelerate_lock_wrappers_62ce88_62cf60(uc, addr32)) return true;
    if (accelerate_tiny_control_blocks(uc, addr32)) return true;
    if (accelerate_crt_alloc_wrappers(uc, addr32)) return true;
    if (accelerate_crt_heapalloc_callsite_621182(uc, addr32)) return true;
    if (accelerate_crt_heapfree_callsite_61fccx(uc, addr32)) return true;
    if (accelerate_memmove_wrapper_61be1b(uc, addr32)) return true;
    if (accelerate_memmove_624510(uc, addr32)) return true;
    if (accelerate_tree_lookup_loop_5d8f5x(uc, addr32)) return true;
    if (accelerate_compare_callsite_5d8f8x(uc, addr32)) return true;
    if (accelerate_xor_copy_loop(uc, addr32)) return true;
    if (accelerate_rep_movsd(uc, addr32)) return true;
    if (accelerate_memcmp_function_441a60(uc, addr32)) return true;
    if (accelerate_memcmp_dword_loop(uc, addr32)) return true;
    if (accelerate_strlen_loop(uc, addr32)) return true;
    if (accelerate_toupper_cdecl(uc, addr32)) return true;
    if (accelerate_small_string_cap_branch_441dd9(uc, addr32)) return true;
    if (accelerate_single_char_store_helper_441dd0(uc, addr32)) return true;
    if (accelerate_string_append_one_char(uc, addr32)) return true;
    if (accelerate_uppercase_append_loop(uc, addr32)) return true;
    if (accelerate_strlen_loop_5d8310(uc, addr32)) return true;
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
                maybe_dump_vram_snapshot();
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
                 << " bytes=" << g_hot_loop_accel_bytes;
            if (g_crt_alloc_accel_enabled) {
                cout << " crt_allocs=" << g_crt_alloc_count;
            }
            if (g_string_grow_fast_count > 0) {
                cout << " strgrow=" << g_string_grow_fast_count;
            }
            if (g_substr_assign_fast_count > 0) {
                cout << " substr=" << g_substr_assign_fast_count;
            }
            if (g_stream_xor_decode_fast_count > 0) {
                cout << " xordec=" << g_stream_xor_decode_fast_count;
            }
            if (g_assign_ptr_fast_count > 0) {
                cout << " asgnptr=" << g_assign_ptr_fast_count;
            }
            if (g_wstring_append_fast_count > 0) {
                cout << " wstrapp=" << g_wstring_append_fast_count;
            }
            if (g_iter_advance_fast_count > 0) {
                cout << " iteradv=" << g_iter_advance_fast_count;
            }
            if (g_memmove_s_fast_count > 0) {
                cout << " memmove_s=" << g_memmove_s_fast_count;
            }
            if (g_memmove_wrap_fast_count > 0) {
                cout << " memwrap=" << g_memmove_wrap_fast_count;
            }
            if (g_string_insert_fast_count > 0) {
                cout << " strins=" << g_string_insert_fast_count;
            }
            if (g_insert_iter_fast_count > 0) {
                cout << " insiter=" << g_insert_iter_fast_count;
            }
            if (g_wstr_to_str_fast_count > 0) {
                cout << " wstr2str=" << g_wstr_to_str_fast_count;
            }
            if (g_stream_pop_fast_count > 0) {
                cout << " streampop=" << g_stream_pop_fast_count;
            }
            if (g_streambuf_branch_fast_count > 0) {
                cout << " sbbranch=" << g_streambuf_branch_fast_count;
            }
            if (g_xml_branch_fast_count > 0) {
                cout << " xmlbranch=" << g_xml_branch_fast_count;
            }
            if (g_text_norm_branch_fast_count > 0) {
                cout << " txtnorm=" << g_text_norm_branch_fast_count;
            }
            if (g_tiny_ctrl_fast_count > 0) {
                cout << " tinyctrl=" << g_tiny_ctrl_fast_count;
            }
            cout << "\n";
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
    if (env_truthy("PVZ_VRAM_SNAPSHOT")) {
        g_vram_snapshot_enabled = true;
    }
    int vram_snap_every = env_int("PVZ_VRAM_SNAPSHOT_EVERY", 1);
    if (vram_snap_every > 0) {
        g_vram_snapshot_every = static_cast<uint64_t>(vram_snap_every);
    }
    const char* vram_snap_prefix = std::getenv("PVZ_VRAM_SNAPSHOT_PREFIX");
    if (vram_snap_prefix && *vram_snap_prefix) {
        g_vram_snapshot_prefix = vram_snap_prefix;
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
    g_string_range_clamp_enabled = env_truthy("PVZ_STRING_RANGE_CLAMP");
    g_string_range_trace_enabled = env_truthy("PVZ_STRING_RANGE_TRACE");
    const char* wstr_append_accel_env = std::getenv("PVZ_WSTRING_APPEND_ACCEL");
    if (wstr_append_accel_env && *wstr_append_accel_env) {
        g_wstring_append_accel_enabled = env_truthy("PVZ_WSTRING_APPEND_ACCEL");
    } else {
        g_wstring_append_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* iter_advance_accel_env = std::getenv("PVZ_ITER_ADVANCE_ACCEL");
    if (iter_advance_accel_env && *iter_advance_accel_env) {
        g_iter_advance_accel_enabled = env_truthy("PVZ_ITER_ADVANCE_ACCEL");
    } else {
        g_iter_advance_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* memmove_s_accel_env = std::getenv("PVZ_MEMMOVE_S_ACCEL");
    if (memmove_s_accel_env && *memmove_s_accel_env) {
        g_memmove_s_accel_enabled = env_truthy("PVZ_MEMMOVE_S_ACCEL");
    } else {
        g_memmove_s_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* string_insert_accel_env = std::getenv("PVZ_STRING_INSERT_ACCEL");
    if (string_insert_accel_env && *string_insert_accel_env) {
        g_string_insert_accel_enabled = env_truthy("PVZ_STRING_INSERT_ACCEL");
    } else {
        g_string_insert_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* insert_iter_accel_env = std::getenv("PVZ_INSERT_ITER_ACCEL");
    if (insert_iter_accel_env && *insert_iter_accel_env) {
        g_insert_iter_accel_enabled = env_truthy("PVZ_INSERT_ITER_ACCEL");
    } else {
        // Experimental: keep opt-in only until semantics are validated.
        g_insert_iter_accel_enabled = false;
    }
    const char* wstr_to_str_accel_env = std::getenv("PVZ_WSTR_TO_STR_ACCEL");
    if (wstr_to_str_accel_env && *wstr_to_str_accel_env) {
        g_wstr_to_str_accel_enabled = env_truthy("PVZ_WSTR_TO_STR_ACCEL");
    } else {
        g_wstr_to_str_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* stream_pop_accel_env = std::getenv("PVZ_STREAM_POP_ACCEL");
    if (stream_pop_accel_env && *stream_pop_accel_env) {
        g_stream_pop_accel_enabled = env_truthy("PVZ_STREAM_POP_ACCEL");
    } else {
        g_stream_pop_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* streambuf_branch_accel_env = std::getenv("PVZ_STREAMBUF_BRANCH_ACCEL");
    if (streambuf_branch_accel_env && *streambuf_branch_accel_env) {
        g_streambuf_branch_accel_enabled = env_truthy("PVZ_STREAMBUF_BRANCH_ACCEL");
    } else {
        g_streambuf_branch_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* xml_branch_accel_env = std::getenv("PVZ_XML_BRANCH_ACCEL");
    if (xml_branch_accel_env && *xml_branch_accel_env) {
        g_xml_branch_accel_enabled = env_truthy("PVZ_XML_BRANCH_ACCEL");
    } else {
        g_xml_branch_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* text_norm_branch_accel_env = std::getenv("PVZ_TEXT_NORM_BRANCH_ACCEL");
    if (text_norm_branch_accel_env && *text_norm_branch_accel_env) {
        g_text_norm_branch_accel_enabled = env_truthy("PVZ_TEXT_NORM_BRANCH_ACCEL");
    } else {
        g_text_norm_branch_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* cookie_accel_env = std::getenv("PVZ_SECURITY_COOKIE_ACCEL");
    if (cookie_accel_env && *cookie_accel_env) {
        g_security_cookie_accel_enabled = env_truthy("PVZ_SECURITY_COOKIE_ACCEL");
    } else {
        g_security_cookie_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* gate_accel_env = std::getenv("PVZ_LOCK_GATE_ACCEL");
    if (gate_accel_env && *gate_accel_env) {
        g_lock_gate_probe_accel_enabled = env_truthy("PVZ_LOCK_GATE_ACCEL");
    } else {
        g_lock_gate_probe_accel_enabled = g_hot_loop_accel_enabled;
    }
    const char* crt_alloc_accel_env = std::getenv("PVZ_CRT_ALLOC_ACCEL");
    if (crt_alloc_accel_env && *crt_alloc_accel_env) {
        g_crt_alloc_accel_enabled = env_truthy("PVZ_CRT_ALLOC_ACCEL");
    } else {
        // Default-on with hot-loop acceleration to reduce startup heap churn.
        g_crt_alloc_accel_enabled = g_hot_loop_accel_enabled;
    }
    g_fast_worker_thread_enabled = env_truthy("PVZ_FAST_WORKER_THREAD");
    int crt_alloc_mb = env_int("PVZ_CRT_ALLOC_ARENA_MB", 128);
    if (crt_alloc_mb > 0) {
        uint64_t limit64 = static_cast<uint64_t>(g_crt_alloc_base) +
                           static_cast<uint64_t>(crt_alloc_mb) * 1024ull * 1024ull;
        if (limit64 > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
            limit64 = static_cast<uint64_t>(std::numeric_limits<uint32_t>::max());
        }
        if (limit64 > g_crt_alloc_base + 0x100000u) {
            g_crt_alloc_limit = static_cast<uint32_t>(limit64);
        }
    }
    g_crt_alloc_top = g_crt_alloc_base;
    g_crt_alloc_mapped_end = g_crt_alloc_base;
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
                0x441d66u, 0x441d77u, 0x441dd0u, 0x441dd9u, 0x5d8890u, 0x62456au, 0x404470u,
                0x456610u, 0x456650u, 0x5a1640u, 0x5a16bdu, 0x5bd830u, 0x5bd88au, 0x5bf470u, 0x5bf47bu,
                0x5bf4e0u, 0x5bf4efu, 0x5bf4f8u, 0x5bf518u, 0x5bf52fu, 0x61be96u, 0x61beebu, 0x55d410u,
                0x5bba20u, 0x5bb880u, 0x5bb894u, 0x5bb89fu, 0x5bbad0u, 0x5bbb12u, 0x61be1bu,
                0x5a1f72u, 0x5a1f7bu, 0x5a1f8bu, 0x5a2052u, 0x5a210au,
                0x62b0d8u, 0x62b0e5u, 0x62b0e9u, 0x62b0f5u, 0x62b0fdu, 0x62b105u, 0x62b184u, 0x62b185u,
                0x5afbb0u, 0x5afc06u, 0x5afc0du, 0x5afc26u,
                0x62ce9bu, 0x62cf8eu, 0x62118bu, 0x61fcd4u
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
    uint32_t guest_vram_map_size = align_up_u32(static_cast<uint32_t>(g_guest_vram_size), 0x1000u);
    uc_err guest_vram_map_err = backend.mem_map(guest_vram, guest_vram_map_size, UC_PROT_ALL);
    if (guest_vram_map_err != UC_ERR_OK) {
        cerr << "[!] Guest VRAM map failed: addr=0x" << hex << guest_vram
             << " size=0x" << guest_vram_map_size
             << " err=" << backend.strerror(guest_vram_map_err)
             << " (" << dec << static_cast<int>(guest_vram_map_err) << ")\n";
        return 1;
    }
    trace("after guest_vram map");

    if (env_truthy("PVZ_MAP_NULL_PAGE")) {
        // Optional compatibility mode for binaries that transiently dereference low/null pointers.
        uc_err null_page_err = backend.mem_map(0x0, 0x10000, UC_PROT_READ | UC_PROT_WRITE);
        if (null_page_err != UC_ERR_OK) {
            cerr << "[!] Null-page map failed: err=" << backend.strerror(null_page_err)
                 << " (" << static_cast<int>(null_page_err) << ")\n";
            return 1;
        }
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
        if (g_vram_snapshot_enabled) {
            cout << "[*] VRAM snapshot enabled: every=" << g_vram_snapshot_every
                 << ", prefix='" << g_vram_snapshot_prefix
                 << "' (PVZ_VRAM_SNAPSHOT / PVZ_VRAM_SNAPSHOT_EVERY / PVZ_VRAM_SNAPSHOT_PREFIX).\n";
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
                << "0x441a60(memcmp), 0x441a73(memcmp dword), 0x5d888c/0x5d8890(xor copy), "
                << "0x62456a(rep movsd), 0x404470(strlen loop), "
                << "0x61e4e6(toupper), 0x441d20(string append x1), "
                << "0x441dd0(char store), 0x441dd9(cap branch), "
                << "0x5d7c0d(uppercase append loop), 0x5d8310(strlen loop), "
                << "0x61efd1(security cookie), 0x5a1640(lock gate probe), "
                << "0x456610(string range view), "
                << "0x5bd830(wstring append fill), "
                << "0x5bf4e0(iterator advance), "
                << "0x61be96(memmove_s), "
                << "0x55d410(string insert fill), "
                << "0x5bba20(insert iterator), "
                << "0x5afbb0(wstr->str small), "
                << "0x5bb880(stream pop), 0x5bb880/0x5bb894/0x5bb89f(streambuf branches), "
                << "0x5a1f72/0x5a1f7b/0x5a1f8b/0x5a2052/0x5a210a(xml branches), "
                << "0x62b0d8/0x62b0e5/0x62b0e9/0x62b0f5/0x62b0fd/0x62b105/0x62b184/0x62b185(text norm branches), "
                << "0x5d8850(stream xor decode), "
                << "0x61be1b(memmove_s wrapper), 0x624510(memmove), "
                << "0x5d8f50(tree lookup loop), "
                << "0x61c19a(crt free helper), "
                << "0x403e20(substr assign), "
                << "0x404330(assign ptr,len), "
                << "0x404080(string grow), 0x4041c0(alloc helper), "
                << "0x62ce88/0x62cf60(lock wrappers), "
                << "0x62ce9b/0x62cf8e/0x62118b/0x61fcd4(tiny ctrl blocks).\n";
            if (g_crt_alloc_accel_enabled) {
                uint32_t arena_mb = (g_crt_alloc_limit - g_crt_alloc_base) / (1024u * 1024u);
                cout << "[*] CRT alloc accel enabled: base=0x" << hex << g_crt_alloc_base
                     << " limit=0x" << g_crt_alloc_limit << dec
                     << " (" << arena_mb
                     << "MB, PVZ_CRT_ALLOC_ACCEL / PVZ_CRT_ALLOC_ARENA_MB), "
                     << "fast callsites=0x61c130/0x621182/0x61fcc5/0x61fcc6.\n";
            }
            if (g_fast_worker_thread_enabled) {
                cout << "[*] Fast worker-thread short-circuit enabled (PVZ_FAST_WORKER_THREAD).\n";
            }
            if (g_string_range_clamp_enabled || g_string_range_trace_enabled) {
                cout << "[*] String-range accel options: clamp=" << (g_string_range_clamp_enabled ? "on" : "off")
                     << ", trace=" << (g_string_range_trace_enabled ? "on" : "off")
                     << " (PVZ_STRING_RANGE_CLAMP / PVZ_STRING_RANGE_TRACE).\n";
            }
            cout << "[*] Cookie/gate accel options: cookie="
                 << (g_security_cookie_accel_enabled ? "on" : "off")
                 << ", gate=" << (g_lock_gate_probe_accel_enabled ? "on" : "off")
                 << " (PVZ_SECURITY_COOKIE_ACCEL / PVZ_LOCK_GATE_ACCEL).\n";
            cout << "[*] Wstring append accel option: "
                 << (g_wstring_append_accel_enabled ? "on" : "off")
                 << " (PVZ_WSTRING_APPEND_ACCEL).\n";
            cout << "[*] Iterator advance accel option: "
                 << (g_iter_advance_accel_enabled ? "on" : "off")
                 << " (PVZ_ITER_ADVANCE_ACCEL).\n";
            cout << "[*] memmove_s accel option: "
                 << (g_memmove_s_accel_enabled ? "on" : "off")
                 << " (PVZ_MEMMOVE_S_ACCEL).\n";
            cout << "[*] String insert accel option: "
                 << (g_string_insert_accel_enabled ? "on" : "off")
                 << " (PVZ_STRING_INSERT_ACCEL).\n";
            cout << "[*] Insert-iterator accel option: "
                 << (g_insert_iter_accel_enabled ? "on" : "off")
                 << " (PVZ_INSERT_ITER_ACCEL).\n";
            cout << "[*] Wstr->str accel option: "
                 << (g_wstr_to_str_accel_enabled ? "on" : "off")
                 << " (PVZ_WSTR_TO_STR_ACCEL).\n";
            cout << "[*] Stream-pop accel option: "
                 << (g_stream_pop_accel_enabled ? "on" : "off")
                 << " (PVZ_STREAM_POP_ACCEL).\n";
            cout << "[*] Streambuf-branch accel option: "
                 << (g_streambuf_branch_accel_enabled ? "on" : "off")
                 << " (PVZ_STREAMBUF_BRANCH_ACCEL).\n";
            cout << "[*] XML-branch accel option: "
                 << (g_xml_branch_accel_enabled ? "on" : "off")
                 << " (PVZ_XML_BRANCH_ACCEL).\n";
            cout << "[*] Text-norm-branch accel option: "
                 << (g_text_norm_branch_accel_enabled ? "on" : "off")
                 << " (PVZ_TEXT_NORM_BRANCH_ACCEL).\n";
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
        bool pc_stall_trace_enabled = env_truthy("PVZ_PC_STALL_TRACE");
        uint64_t pc_stall_report_every =
            static_cast<uint64_t>(std::max(1, env_int("PVZ_PC_STALL_REPORT", 50000)));
        uint32_t pc_stall_last = 0;
        uint64_t pc_stall_run = 0;
        auto maybe_trace_pc_stall = [&](uint32_t cur_pc) {
            if (!pc_stall_trace_enabled) return;
            if (cur_pc == 0u || cur_pc == 0xFFFFFFFFu) {
                pc_stall_last = 0;
                pc_stall_run = 0;
                return;
            }
            if (cur_pc == pc_stall_last) {
                pc_stall_run++;
            } else {
                if (pc_stall_run >= pc_stall_report_every) {
                    cout << "[STALL TRACE] pc moved 0x" << hex << pc_stall_last
                         << " -> 0x" << cur_pc << dec
                         << " after run=" << pc_stall_run
                         << " tid=" << (api_handler.coop_threads_enabled()
                                        ? api_handler.coop_current_thread_id()
                                        : 1u)
                         << " hot_hits=" << g_hot_loop_accel_hits << "\n";
                }
                pc_stall_last = cur_pc;
                pc_stall_run = 1;
            }
            if (pc_stall_run == pc_stall_report_every ||
                (pc_stall_run > pc_stall_report_every &&
                 (pc_stall_run % pc_stall_report_every) == 0u)) {
                cout << "[STALL TRACE] pc=0x" << hex << cur_pc << dec
                     << " run=" << pc_stall_run
                     << " tid=" << (api_handler.coop_threads_enabled()
                                    ? api_handler.coop_current_thread_id()
                                    : 1u)
                     << " hot_hits=" << g_hot_loop_accel_hits << "\n";
            }
        };
        if (pc_stall_trace_enabled) {
            cout << "[*] PC stall trace enabled: report_every=" << pc_stall_report_every
                 << " slices (PVZ_PC_STALL_TRACE / PVZ_PC_STALL_REPORT).\n";
        }
        while (true) {
            size_t emu_count = 0;
            if (api_handler.coop_threads_enabled()) {
                api_handler.coop_prepare_to_run();
                pc = api_handler.coop_current_pc();
                if (pc == 0 || pc == 0xFFFFFFFFu) {
                    if (api_handler.coop_should_terminate()) {
                        cout << "\n[+] Cooperative scheduler finished (no runnable threads).\n";
                        break;
                    }
                    continue;
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
                maybe_trace_pc_stall(pc);
                if (api_handler.coop_should_terminate()) {
                    cout << "\n[+] Cooperative scheduler reported completion.\n";
                    break;
                }
            } else {
                backend.reg_read(UC_X86_REG_EIP, &pc);
                maybe_trace_pc_stall(pc);
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
        if (g_crt_alloc_accel_enabled && g_crt_alloc_count > 0) {
            cout << "[*] CRT alloc accel summary: allocs=" << g_crt_alloc_count
                 << ", bytes=" << g_crt_alloc_bytes
                 << ", used=0x" << hex << g_crt_alloc_top << dec << "\n";
        }
        if (g_crt_free_fast_count > 0) {
            cout << "[*] CRT free fast-path summary: frees=" << g_crt_free_fast_count << "\n";
        }
        if (g_lock_wrapper_fast_count > 0) {
            cout << "[*] Lock-wrapper fast-path summary: hits=" << g_lock_wrapper_fast_count << "\n";
        }
        if (g_string_grow_fast_count > 0) {
            cout << "[*] String-grow fast-path summary: hits=" << g_string_grow_fast_count << "\n";
        }
        if (g_substr_assign_fast_count > 0) {
            cout << "[*] Substr-assign fast-path summary: hits=" << g_substr_assign_fast_count << "\n";
        }
        if (g_stream_xor_decode_fast_count > 0) {
            cout << "[*] Stream-xor fast-path summary: hits=" << g_stream_xor_decode_fast_count << "\n";
        }
        if (g_assign_ptr_fast_count > 0) {
            cout << "[*] Assign-ptr fast-path summary: hits=" << g_assign_ptr_fast_count << "\n";
        }
        if (g_string_range_fast_count > 0) {
            cout << "[*] String-range fast-path summary: hits=" << g_string_range_fast_count
                 << ", invalid=" << g_string_range_invalid_count
                 << ", clamped=" << g_string_range_clamped_count << "\n";
        }
        if (g_wstring_append_fast_count > 0) {
            cout << "[*] Wstring-append fast-path summary: hits=" << g_wstring_append_fast_count << "\n";
        }
        if (g_iter_advance_fast_count > 0) {
            cout << "[*] Iterator-advance fast-path summary: hits=" << g_iter_advance_fast_count << "\n";
        }
        if (g_memmove_s_fast_count > 0) {
            cout << "[*] memmove_s fast-path summary: hits=" << g_memmove_s_fast_count << "\n";
        }
        if (g_memmove_wrap_fast_count > 0) {
            cout << "[*] memmove wrapper fast-path summary: hits=" << g_memmove_wrap_fast_count << "\n";
        }
        if (g_string_insert_fast_count > 0) {
            cout << "[*] String-insert fast-path summary: hits=" << g_string_insert_fast_count << "\n";
        }
        if (g_insert_iter_fast_count > 0) {
            cout << "[*] Insert-iterator fast-path summary: hits=" << g_insert_iter_fast_count << "\n";
        }
        if (g_wstr_to_str_fast_count > 0) {
            cout << "[*] Wstr->str fast-path summary: hits=" << g_wstr_to_str_fast_count << "\n";
        }
        if (g_stream_pop_fast_count > 0) {
            cout << "[*] Stream-pop fast-path summary: hits=" << g_stream_pop_fast_count << "\n";
        }
        if (g_streambuf_branch_fast_count > 0) {
            cout << "[*] Streambuf-branch fast-path summary: hits=" << g_streambuf_branch_fast_count << "\n";
        }
        if (g_xml_branch_fast_count > 0) {
            cout << "[*] XML-branch fast-path summary: hits=" << g_xml_branch_fast_count << "\n";
        }
        if (g_text_norm_branch_fast_count > 0) {
            cout << "[*] Text-norm-branch fast-path summary: hits=" << g_text_norm_branch_fast_count << "\n";
        }
        if (g_tiny_ctrl_fast_count > 0) {
            cout << "[*] Tiny-control fast-path summary: hits=" << g_tiny_ctrl_fast_count << "\n";
        }
        if (g_security_cookie_fast_count > 0) {
            cout << "[*] Security-cookie fast-path summary: hits=" << g_security_cookie_fast_count << "\n";
        }
        if (g_lock_gate_probe_fast_count > 0) {
            cout << "[*] Lock-gate fast-path summary: hits=" << g_lock_gate_probe_fast_count << "\n";
        }
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

#include "api_handler.hpp"
#include <fstream>
#include <filesystem>
#include <dlfcn.h>
#include <unistd.h>
#include <SDL.h>
#include <algorithm>
#include <array>
#include <vector>
#include <iterator>
#include <deque>
#include <map>
#include <unordered_set>
#include <sstream>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <limits>

// --- Win32 Message Mapping ---
constexpr uint32_t WM_NULL = 0x0000;
constexpr uint32_t WM_QUIT = 0x0012;
constexpr uint32_t WM_TIMER = 0x0113;
constexpr uint32_t WM_KEYDOWN = 0x0100;
constexpr uint32_t WM_KEYUP = 0x0101;
constexpr uint32_t WM_MOUSEMOVE = 0x0200;
constexpr uint32_t WM_LBUTTONDOWN = 0x0201;
constexpr uint32_t WM_LBUTTONUP = 0x0202;
constexpr uint32_t WM_RBUTTONDOWN = 0x0204;
constexpr uint32_t WM_RBUTTONUP = 0x0205;

struct Win32_MSG {
    uint32_t hwnd;
    uint32_t message;
    uint32_t wParam;
    uint32_t lParam;
    uint32_t time;
    int32_t pt_x;
    int32_t pt_y;
};

struct PendingWin32Message {
    Win32_MSG msg;
    uint32_t target_thread_id = 0; // 0 == any thread
};

struct HostFileHandle {
    std::vector<uint8_t> data;
    size_t pos = 0;
};

struct FindFileEntry {
    std::string file_name;
    uint64_t file_size = 0;
    bool is_dir = false;
};

struct FindHandle {
    std::vector<FindFileEntry> entries;
    size_t index = 0;
};

struct EventHandle {
    bool manual_reset = false;
    bool signaled = false;
};

struct ThreadHandle {
    uint32_t start_address = 0;
    uint32_t parameter = 0;
    uint32_t thread_id = 0;
    bool started = false;
    bool finished = false;
};

struct MappingHandle {
    uint32_t file_handle = 0xFFFFFFFFu; // INVALID_HANDLE_VALUE means page-file backed mapping
};

struct RegistryKeyHandle {
    std::string path;
};

struct Win32Timer {
    uint32_t hwnd = 0;
    uint32_t timer_id = 0;
    uint32_t interval_ms = 0;
    uint32_t callback = 0;
    uint32_t next_fire_ms = 0;
};

struct Win32ClassReg {
    uint16_t atom = 0;
    uint32_t wndproc = 0;
};

static std::unordered_map<std::string, std::vector<uint8_t>> g_registry_values;
static std::unordered_map<std::string, uint32_t> g_registry_types;
static std::unordered_map<uint32_t, uint32_t> g_heap_sizes;
static std::multimap<uint32_t, uint32_t> g_heap_free_by_size; // size -> ptr
static constexpr uint32_t kHeapBase = 0x20000000;
static constexpr uint32_t kHeapSize = 0x10000000; // 256MB
static size_t g_heap_free_entry_cap = 131072;
static bool g_heap_free_cap_warned = false;
static std::unordered_map<uint32_t, uint32_t> g_mapview_live_sizes; // base -> aligned size
static std::multimap<uint32_t, uint32_t> g_mapview_free_by_size;    // size -> base
static std::unordered_map<uint32_t, uint32_t> g_resource_ptr_by_handle;
static std::unordered_map<uint32_t, uint32_t> g_resource_size_by_handle;
static uint32_t g_resource_handle_top = 0xB000;
static uint32_t g_resource_heap_top = 0x36000000;
static bool g_resource_heap_mapped = false;
static std::deque<PendingWin32Message> g_win32_message_queue;
static std::unordered_map<uint64_t, Win32Timer> g_win32_timers;
static std::unordered_set<uint32_t> g_valid_hwnds;
static std::unordered_map<uint32_t, uint32_t> g_hwnd_owner_thread_id;
static std::unordered_map<uint64_t, int32_t> g_window_long_values;
static std::unordered_map<uint32_t, std::string> g_window_text_values;
static uint32_t g_synth_idle_timer_next_ms = 0;
static uint32_t g_hwnd_top = 0x12345678u;
static std::unordered_map<std::string, Win32ClassReg> g_win32_class_by_name;
static std::unordered_map<uint16_t, Win32ClassReg> g_win32_class_by_atom;
static uint16_t g_win32_class_atom_top = 1;
static std::unordered_map<uint32_t, uint32_t> g_thread_start_to_handle;
static std::unordered_map<std::string, uint32_t> g_module_handle_by_name;
static std::unordered_map<uint32_t, std::string> g_module_name_by_handle;
static uint32_t g_module_handle_top = 0x79000000u;

static std::string read_guest_c_string(APIContext& ctx, uint32_t guest_ptr, size_t max_len = 512) {
    if (guest_ptr == 0) return "";
    std::string out;
    out.reserve(64);
    for (size_t i = 0; i < max_len; ++i) {
        char ch = 0;
        if (!ctx.backend || ctx.backend->mem_read(guest_ptr + i, &ch, 1) != UC_ERR_OK || ch == '\0') break;
        out.push_back(ch);
    }
    return out;
}

static std::string read_guest_w_string(APIContext& ctx, uint32_t guest_ptr, size_t max_chars = 512) {
    if (guest_ptr == 0) return "";
    std::string out;
    out.reserve(64);
    for (size_t i = 0; i < max_chars; ++i) {
        uint16_t ch = 0;
        if (!ctx.backend || ctx.backend->mem_read(guest_ptr + static_cast<uint32_t>(i * 2), &ch, 2) != UC_ERR_OK || ch == 0) {
            break;
        }
        if (ch <= 0x7F) out.push_back(static_cast<char>(ch));
        else out.push_back('?');
    }
    return out;
}

static std::string to_lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static bool wildcard_match_ascii_ci(const std::string& pattern_raw, const std::string& text_raw) {
    const std::string pattern = to_lower_ascii(pattern_raw);
    const std::string text = to_lower_ascii(text_raw);
    size_t pi = 0;
    size_t ti = 0;
    size_t star = std::string::npos;
    size_t match = 0;
    while (ti < text.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' || pattern[pi] == text[ti])) {
            ++pi;
            ++ti;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star = pi++;
            match = ti;
        } else if (star != std::string::npos) {
            pi = star + 1;
            ti = ++match;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}

static void write_win32_find_data_a(APIContext& ctx, uint32_t lpFindFileData, const FindFileEntry& entry) {
    if (lpFindFileData == 0) return;
    // WIN32_FIND_DATAA is 320 bytes on Win32.
    std::array<uint8_t, 320> data{};
    uint32_t attrs = entry.is_dir ? 0x10u : 0x80u; // DIRECTORY or NORMAL
    std::memcpy(data.data() + 0, &attrs, 4);
    uint32_t size_high = static_cast<uint32_t>(entry.file_size >> 32);
    uint32_t size_low = static_cast<uint32_t>(entry.file_size & 0xFFFFFFFFu);
    std::memcpy(data.data() + 28, &size_high, 4);
    std::memcpy(data.data() + 32, &size_low, 4);
    const size_t copy_len = std::min<size_t>(entry.file_name.size(), 259);
    if (copy_len > 0) {
        std::memcpy(data.data() + 44, entry.file_name.data(), copy_len);
    }
    data[44 + copy_len] = 0;
    ctx.backend->mem_write(lpFindFileData, data.data(), data.size());
}

static bool starts_with_ascii_ci(const std::string& s, const char* prefix_lower) {
    std::string lower = to_lower_ascii(s);
    return lower.rfind(prefix_lower, 0) == 0;
}

static bool is_noisy_fastpath_api(const std::string& n) {
    return n == "KERNEL32.dll!EnterCriticalSection" ||
           n == "KERNEL32.dll!LeaveCriticalSection" ||
           n == "KERNEL32.dll!InitializeCriticalSection" ||
           n == "KERNEL32.dll!InitializeCriticalSectionAndSpinCount" ||
           n == "KERNEL32.dll!GetModuleHandleA" ||
           n == "KERNEL32.dll!GetModuleHandleW" ||
           n == "KERNEL32.dll!LoadLibraryA" ||
           n == "KERNEL32.dll!LoadLibraryW" ||
           n == "KERNEL32.dll!FreeLibrary" ||
           n == "KERNEL32.dll!HeapAlloc" ||
           n == "KERNEL32.dll!HeapFree" ||
           n == "KERNEL32.dll!HeapSize" ||
           n == "KERNEL32.dll!HeapReAlloc" ||
           n == "KERNEL32.dll!TlsGetValue" ||
           n == "KERNEL32.dll!TlsSetValue" ||
           n == "KERNEL32.dll!TlsAlloc" ||
           n == "KERNEL32.dll!FlsGetValue" ||
           n == "KERNEL32.dll!FlsSetValue" ||
           n == "KERNEL32.dll!FlsAlloc" ||
           n == "KERNEL32.dll!FlsFree" ||
           n == "KERNEL32.dll!GetLastError" ||
           n == "KERNEL32.dll!SetLastError" ||
           n == "KERNEL32.dll!OutputDebugStringA" ||
           n == "KERNEL32.dll!OutputDebugStringW" ||
           n == "KERNEL32.dll!InterlockedIncrement" ||
           n == "KERNEL32.dll!InterlockedDecrement" ||
           n == "KERNEL32.dll!InterlockedExchange" ||
           n == "KERNEL32.dll!InterlockedCompareExchange";
}

constexpr size_t kWin32MessageQueueMax = 4096;

static void enqueue_win32_message(const Win32_MSG& msg, uint32_t target_thread_id = 0) {
    if (g_win32_message_queue.size() >= kWin32MessageQueueMax) {
        g_win32_message_queue.pop_front();
    }
    PendingWin32Message pending = {};
    pending.msg = msg;
    pending.target_thread_id = target_thread_id;
    g_win32_message_queue.push_back(pending);
}

static uint64_t win32_timer_key(uint32_t hwnd, uint32_t timer_id) {
    return (static_cast<uint64_t>(hwnd) << 32) | static_cast<uint64_t>(timer_id);
}

static uint64_t win32_window_long_key(uint32_t hwnd, int32_t index) {
    return (static_cast<uint64_t>(hwnd) << 32) | static_cast<uint32_t>(index);
}

static std::string win32_class_key_from_arg(APIContext& ctx, uint32_t class_arg, bool wide) {
    if (class_arg == 0) return "";
    // MAKEINTATOMA/W: low word atom, high word zero
    if ((class_arg & 0xFFFF0000u) == 0) {
        uint16_t atom = static_cast<uint16_t>(class_arg & 0xFFFFu);
        auto it_atom = g_win32_class_by_atom.find(atom);
        if (it_atom == g_win32_class_by_atom.end()) return "";
        for (const auto& kv : g_win32_class_by_name) {
            if (kv.second.atom == atom) return kv.first;
        }
        return "";
    }
    std::string name = wide
        ? read_guest_w_string(ctx, class_arg, 256)
        : read_guest_c_string(ctx, class_arg, 256);
    return to_lower_ascii(name);
}

static uint32_t win32_class_wndproc_from_arg(APIContext& ctx, uint32_t class_arg, bool wide) {
    if (class_arg == 0) return 0;
    if ((class_arg & 0xFFFF0000u) == 0) {
        uint16_t atom = static_cast<uint16_t>(class_arg & 0xFFFFu);
        auto it_atom = g_win32_class_by_atom.find(atom);
        if (it_atom != g_win32_class_by_atom.end()) return it_atom->second.wndproc;
        return 0;
    }
    std::string key = win32_class_key_from_arg(ctx, class_arg, wide);
    if (key.empty()) return 0;
    auto it_name = g_win32_class_by_name.find(key);
    if (it_name == g_win32_class_by_name.end()) return 0;
    return it_name->second.wndproc;
}

static std::string normalize_module_name_ascii(std::string module_raw) {
    if (module_raw.empty()) return module_raw;
    std::replace(module_raw.begin(), module_raw.end(), '/', '\\');
    module_raw = to_lower_ascii(module_raw);

    size_t slash = module_raw.find_last_of('\\');
    if (slash != std::string::npos) {
        module_raw = module_raw.substr(slash + 1);
    }

    if (module_raw.size() >= 4 && module_raw.rfind(".dll") == module_raw.size() - 4) {
        return module_raw;
    }
    if (module_raw.find('.') == std::string::npos) {
        module_raw += ".dll";
    }
    return module_raw;
}

static uint32_t builtin_module_handle_from_name(const std::string& module_name_norm) {
    if (module_name_norm == "kernel32.dll") return 0x76000000u;
    if (module_name_norm == "ntdll.dll") return 0x77000000u;
    if (module_name_norm == "user32.dll") return 0x75000000u;
    if (module_name_norm == "ole32.dll") return 0x74000000u;
    if (module_name_norm == "oleaut32.dll") return 0x74100000u;
    if (module_name_norm == "ddraw.dll") return 0x73000000u;
    if (module_name_norm == "gdi32.dll") return 0x73100000u;
    if (module_name_norm == "winmm.dll") return 0x73200000u;
    if (module_name_norm == "dsound.dll") return 0x73300000u;
    if (module_name_norm == "bass.dll") return 0x73400000u;
    if (module_name_norm == "d3d8.dll") return 0x73500000u;
    if (module_name_norm == "advapi32.dll") return 0x73600000u;
    if (module_name_norm == "shell32.dll") return 0x73700000u;
    if (module_name_norm == "comdlg32.dll") return 0x73800000u;
    if (module_name_norm == "imm32.dll") return 0x73900000u;
    if (module_name_norm == "version.dll") return 0x73A00000u;
    if (module_name_norm == "shlwapi.dll") return 0x73B00000u;
    if (module_name_norm == "ws2_32.dll") return 0x73C00000u;
    if (module_name_norm == "wininet.dll") return 0x73D00000u;
    if (module_name_norm == "mscoree.dll") return 0x78000000u;
    return 0u;
}

static void remember_module_handle(const std::string& module_name_norm, uint32_t handle) {
    if (module_name_norm.empty() || handle == 0u) return;
    g_module_handle_by_name[module_name_norm] = handle;
    g_module_name_by_handle[handle] = module_name_norm;
    if (module_name_norm.size() > 4 && module_name_norm.rfind(".dll") == module_name_norm.size() - 4) {
        g_module_handle_by_name[module_name_norm.substr(0, module_name_norm.size() - 4)] = handle;
    }
}

static uint32_t lookup_module_handle_by_name(const std::string& module_raw, bool allow_dynamic_create) {
    if (module_raw.empty()) {
        return 0x00400000u;
    }

    std::string normalized = normalize_module_name_ascii(module_raw);
    auto it_existing = g_module_handle_by_name.find(normalized);
    if (it_existing != g_module_handle_by_name.end()) {
        return it_existing->second;
    }

    uint32_t builtin = builtin_module_handle_from_name(normalized);
    if (builtin != 0u) {
        remember_module_handle(normalized, builtin);
        return builtin;
    }

    if (!allow_dynamic_create) {
        return 0u;
    }

    uint32_t handle = g_module_handle_top;
    g_module_handle_top += 0x00100000u;
    if (g_module_handle_top < 0x79000000u || g_module_handle_top >= 0x7F000000u) {
        g_module_handle_top = 0x79000000u;
    }
    remember_module_handle(normalized, handle);
    return handle;
}

static std::string module_name_from_handle(uint32_t handle) {
    if (handle == 0x00400000u) return "pvz.exe";
    auto it_dyn = g_module_name_by_handle.find(handle);
    if (it_dyn != g_module_name_by_handle.end()) return it_dyn->second;

    switch (handle) {
        case 0x76000000u: return "kernel32.dll";
        case 0x77000000u: return "ntdll.dll";
        case 0x75000000u: return "user32.dll";
        case 0x74000000u: return "ole32.dll";
        case 0x74100000u: return "oleaut32.dll";
        case 0x73000000u: return "ddraw.dll";
        case 0x73100000u: return "gdi32.dll";
        case 0x73200000u: return "winmm.dll";
        case 0x73300000u: return "dsound.dll";
        case 0x73400000u: return "bass.dll";
        case 0x73500000u: return "d3d8.dll";
        case 0x73600000u: return "advapi32.dll";
        case 0x73700000u: return "shell32.dll";
        case 0x73800000u: return "comdlg32.dll";
        case 0x73900000u: return "imm32.dll";
        case 0x73A00000u: return "version.dll";
        case 0x73B00000u: return "shlwapi.dll";
        case 0x73C00000u: return "ws2_32.dll";
        case 0x73D00000u: return "wininet.dll";
        case 0x78000000u: return "mscoree.dll";
        default: break;
    }
    return "";
}

static void maybe_trim_heap_free_list() {
    if (g_heap_free_entry_cap == 0) return;
    if (g_heap_free_by_size.size() <= g_heap_free_entry_cap) return;
    g_heap_free_by_size.clear();
    if (!g_heap_free_cap_warned) {
        std::cout << "[HEAP MOCK] free-list cap reached, clearing recycle map (cap="
                  << g_heap_free_entry_cap << ")\n";
        g_heap_free_cap_warned = true;
    }
}

static void heap_push_free_block(uint32_t size, uint32_t ptr) {
    if (size == 0) return;
    g_heap_free_by_size.emplace(size, ptr);
    maybe_trim_heap_free_list();
}

static void heap_maybe_reset_if_idle(APIContext& ctx) {
    if (!g_heap_sizes.empty()) return;
    auto it_top = ctx.global_state.find("HeapTop");
    if (it_top != ctx.global_state.end()) {
        it_top->second = kHeapBase;
    }
    g_heap_free_by_size.clear();
}

static void enqueue_timer_message(uint32_t hwnd, uint32_t timer_id, uint32_t now_ms) {
    Win32_MSG msg = {};
    msg.hwnd = hwnd;
    msg.message = WM_TIMER;
    msg.wParam = timer_id;
    msg.lParam = 0;
    msg.time = now_ms;
    int mx = 0;
    int my = 0;
    SDL_GetMouseState(&mx, &my);
    msg.pt_x = mx;
    msg.pt_y = my;
    uint32_t target_thread_id = 0;
    auto it_owner = g_hwnd_owner_thread_id.find(hwnd);
    if (it_owner != g_hwnd_owner_thread_id.end()) {
        target_thread_id = it_owner->second;
    }
    enqueue_win32_message(msg, target_thread_id);
}

static void pump_due_win32_timers(uint32_t now_ms) {
    for (auto& kv : g_win32_timers) {
        Win32Timer& timer = kv.second;
        uint32_t interval = std::max<uint32_t>(1u, timer.interval_ms);
        int burst = 0;
        while (static_cast<int32_t>(now_ms - timer.next_fire_ms) >= 0 && burst < 4) {
            enqueue_timer_message(timer.hwnd, timer.timer_id, now_ms);
            timer.next_fire_ms += interval;
            burst++;
        }
    }
}

static bool win32_message_matches_filter(const Win32_MSG& msg, uint32_t hwnd_filter, uint32_t min_filter, uint32_t max_filter) {
    if (hwnd_filter != 0 && msg.hwnd != hwnd_filter) return false;
    if (min_filter == 0 && max_filter == 0) return true;
    uint32_t lo = min_filter;
    uint32_t hi = max_filter;
    if (hi != 0 && hi < lo) std::swap(lo, hi);
    if (msg.message < lo) return false;
    if (hi != 0 && msg.message > hi) return false;
    return true;
}

static bool win32_message_matches_filter(const PendingWin32Message& pending,
                                         uint32_t current_thread_id,
                                         uint32_t hwnd_filter,
                                         uint32_t min_filter,
                                         uint32_t max_filter) {
    if (pending.target_thread_id != 0 &&
        current_thread_id != 0 &&
        pending.target_thread_id != current_thread_id) {
        return false;
    }
    return win32_message_matches_filter(pending.msg, hwnd_filter, min_filter, max_filter);
}

static bool win32_queue_has_message_for_thread(uint32_t current_thread_id) {
    for (const auto& pending : g_win32_message_queue) {
        if (pending.target_thread_id == 0 || pending.target_thread_id == current_thread_id) {
            return true;
        }
    }
    return false;
}

static bool env_truthy(const char* name) {
    const char* v = std::getenv(name);
    if (!v) return false;
    std::string s = to_lower_ascii(v);
    return !(s.empty() || s == "0" || s == "false" || s == "off" || s == "no");
}

static bool thread_mock_trace_enabled() {
    static const bool enabled = env_truthy("PVZ_THREAD_MOCK_TRACE");
    return enabled;
}

static bool loader_trace_enabled() {
    static const bool enabled = env_truthy("PVZ_LOADER_TRACE");
    return enabled;
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

static uint32_t parse_u32_auto(const std::string& s, uint32_t fallback = 0) {
    if (s.empty()) return fallback;
    char* end = nullptr;
    unsigned long v = std::strtoul(s.c_str(), &end, 0);
    if (!end || *end != '\0') return fallback;
    if (v > 0xFFFFFFFFul) return 0xFFFFFFFFu;
    return static_cast<uint32_t>(v);
}

static std::vector<uint32_t> parse_u32_list_csv(const char* env_value) {
    std::vector<uint32_t> out;
    if (!env_value || !*env_value) return out;
    std::stringstream ss(env_value);
    std::string token;
    while (std::getline(ss, token, ',')) {
        size_t first = token.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        size_t last = token.find_last_not_of(" \t");
        token = token.substr(first, last - first + 1);
        uint32_t value = parse_u32_auto(token, 0);
        if (value != 0) out.push_back(value);
    }
    return out;
}

static std::string resolve_case_insensitive_path(const std::string& raw_path) {
    if (raw_path.empty()) return "";

    std::filesystem::path in(raw_path);
    std::filesystem::path current = in.is_absolute() ? in.root_path() : std::filesystem::path(".");

    for (const auto& part : in.relative_path()) {
        std::string needle = part.string();
        if (needle.empty() || needle == ".") continue;
        if (needle == "..") {
            current = current.parent_path();
            continue;
        }

        std::filesystem::path exact = current / needle;
        std::error_code ec;
        if (std::filesystem::exists(exact, ec) && !ec) {
            current = exact;
            continue;
        }

        if (!std::filesystem::exists(current, ec) || ec || !std::filesystem::is_directory(current, ec)) {
            return "";
        }

        const std::string needle_lower = to_lower_ascii(needle);
        bool matched = false;
        for (const auto& entry : std::filesystem::directory_iterator(current, ec)) {
            if (ec) break;
            std::string filename = entry.path().filename().string();
            if (to_lower_ascii(filename) == needle_lower) {
                current = entry.path();
                matched = true;
                break;
            }
        }
        if (!matched) return "";
    }

    std::error_code ec;
    if (std::filesystem::exists(current, ec) && !ec) {
        return current.string();
    }
    return "";
}

static std::string resolve_guest_path_to_host(const std::string& guest_path_raw, const std::string& process_base_dir) {
    if (guest_path_raw.empty()) return "";
    std::string p = guest_path_raw;
    std::replace(p.begin(), p.end(), '\\', '/');

    // Normalize "C:/foo/bar" to "foo/bar" for local lookup.
    if (p.size() >= 2 && p[1] == ':') {
        p = p.substr(2);
        while (!p.empty() && (p[0] == '/' || p[0] == '\\')) p.erase(p.begin());
    }

    std::vector<std::string> variants;
    if (!p.empty()) variants.push_back(p);
    if (p.rfind("./", 0) == 0) variants.push_back(p.substr(2));
    if (!p.empty() && p[0] == '/') variants.push_back(p.substr(1));

    auto add_image_extension_variants = [&](const std::string& src) {
        if (src.size() <= 4) return;
        std::string lower = to_lower_ascii(src);
        auto add_ext = [&](const char* ext) {
            variants.push_back(src.substr(0, src.size() - 4) + ext);
        };
        if (lower.rfind(".tga") == lower.size() - 4) {
            add_ext(".png");
            add_ext(".jpg");
        } else if (lower.rfind(".png") == lower.size() - 4) {
            add_ext(".tga");
            add_ext(".jpg");
        } else if (lower.rfind(".jpg") == lower.size() - 4) {
            add_ext(".png");
            add_ext(".tga");
        }
    };

    auto add_basename_underscore_variant = [&](const std::string& src) {
        size_t slash = src.find_last_of('/');
        std::string dir = (slash == std::string::npos) ? "" : src.substr(0, slash + 1);
        std::string base = (slash == std::string::npos) ? src : src.substr(slash + 1);
        if (!base.empty() && base[0] == '_') {
            variants.push_back(dir + base.substr(1));
        }
    };

    for (size_t i = 0; i < variants.size(); ++i) {
        add_image_extension_variants(variants[i]);
        add_basename_underscore_variant(variants[i]);
    }

    std::vector<std::string> roots;
    if (!process_base_dir.empty()) {
        roots.push_back(process_base_dir);
        std::filesystem::path base_path(process_base_dir);
        if (base_path.has_parent_path()) {
            roots.push_back(base_path.parent_path().string());
        }
    }
    roots.push_back("");
    roots.push_back("pvz");
    for (const auto& root : roots) {
        for (const auto& rel : variants) {
            if (rel.empty()) continue;
            std::string candidate = root.empty()
                ? rel
                : (std::filesystem::path(root) / rel).string();
            std::error_code ec;
            if (std::filesystem::exists(candidate, ec) && !ec) return candidate;
            std::string ci = resolve_case_insensitive_path(candidate);
            if (!ci.empty()) return ci;
        }
    }
    return "";
}

static std::string normalize_win_path(std::string p) {
    if (p.empty()) return p;
    std::replace(p.begin(), p.end(), '/', '\\');
    std::vector<std::string> parts;
    std::string drive;

    size_t i = 0;
    if (p.size() >= 2 && p[1] == ':') {
        drive = p.substr(0, 2);
        i = 2;
    }

    while (i < p.size() && (p[i] == '\\' || p[i] == '/')) i++;
    std::string cur;
    for (; i <= p.size(); ++i) {
        if (i == p.size() || p[i] == '\\' || p[i] == '/') {
            if (!cur.empty() && cur != ".") {
                if (cur == "..") {
                    if (!parts.empty()) parts.pop_back();
                } else {
                    parts.push_back(cur);
                }
            }
            cur.clear();
        } else {
            cur.push_back(p[i]);
        }
    }

    std::string out = drive;
    if (!out.empty()) out += "\\";
    for (size_t n = 0; n < parts.size(); ++n) {
        out += parts[n];
        if (n + 1 < parts.size()) out += "\\";
    }
    if (out.empty()) return ".";
    return out;
}

static std::string root_hkey_name(uint32_t hkey) {
    switch (hkey) {
        case 0x80000000u: return "HKCR";
        case 0x80000001u: return "HKCU";
        case 0x80000002u: return "HKLM";
        case 0x80000003u: return "HKU";
        default: return "";
    }
}

static std::string resolve_registry_path(APIContext& ctx, uint32_t hkey) {
    std::string root = root_hkey_name(hkey);
    if (!root.empty()) return root;
    auto it = ctx.handle_map.find("reg_" + std::to_string(hkey));
    if (it == ctx.handle_map.end()) return "";
    auto* rk = static_cast<RegistryKeyHandle*>(it->second);
    return rk ? rk->path : "";
}

// Modified KNOWN_SIGNATURES definition: removed 'const' and 'DummyAPIHandler::' scope
std::unordered_map<std::string, int> KNOWN_SIGNATURES = {
    {"KERNEL32.dll!GetSystemTimeAsFileTime", 4},
    {"KERNEL32.dll!GetCurrentProcessId", 0},
    {"KERNEL32.dll!GetCurrentProcess", 0},
    {"KERNEL32.dll!GetCurrentThreadId", 0},
    {"KERNEL32.dll!GetTickCount", 0},
    {"KERNEL32.dll!QueryPerformanceCounter", 4},
    {"KERNEL32.dll!GetStartupInfoA", 4},
    {"KERNEL32.dll!GetProcessHeap", 0},
    {"KERNEL32.dll!HeapAlloc", 12},
    {"KERNEL32.dll!HeapCreate", 12},
    {"KERNEL32.dll!GetVersionExA", 4},
    {"KERNEL32.dll!HeapFree", 12},
    {"KERNEL32.dll!Sleep", 4},
    {"KERNEL32.dll!SleepEx", 8},
    {"KERNEL32.dll!SwitchToThread", 0},
    {"KERNEL32.dll!GetModuleFileNameA", 12},
    {"KERNEL32.dll!GetLastError", 0},
    {"KERNEL32.dll!SetLastError", 4},
    {"KERNEL32.dll!CloseHandle", 4},
    {"KERNEL32.dll!CreateEventA", 16},
    {"KERNEL32.dll!CreateEventW", 16},
    {"KERNEL32.dll!CreateThread", 24},
    {"KERNEL32.dll!SetEvent", 4},
    {"KERNEL32.dll!ResetEvent", 4},
    {"KERNEL32.dll!WaitForSingleObject", 8},
    // User32 Trivial APIs (to bypass LLM overhead)
    {"USER32.dll!DestroyWindow", 4},
    {"USER32.dll!DefWindowProcA", 16},
    {"USER32.dll!DefWindowProcW", 16},
    {"USER32.dll!SetTimer", 16},
    {"USER32.dll!KillTimer", 8},
    {"USER32.dll!GetCursorPos", 4},
    {"USER32.dll!GetLastInputInfo", 4},
    {"USER32.dll!SetCursorPos", 8},
    {"USER32.dll!ShowCursor", 4},
    {"USER32.dll!ReleaseCapture", 0},
    {"USER32.dll!TranslateMessage", 4},
    {"USER32.dll!DispatchMessageA", 4},
    {"USER32.dll!DispatchMessageW", 4},
    {"USER32.dll!PostMessageA", 16},
    {"USER32.dll!PostMessageW", 16},
    {"USER32.dll!PostThreadMessageA", 16},
    {"USER32.dll!PostThreadMessageW", 16},
    {"USER32.dll!SendMessageA", 16},
    {"USER32.dll!SendMessageW", 16},
    {"USER32.dll!RegisterWindowMessageA", 4},
    {"USER32.dll!RegisterWindowMessageW", 4},
    {"USER32.dll!SystemParametersInfoA", 16},
    {"USER32.dll!GetSystemMetrics", 4},
    {"USER32.dll!LoadCursorA", 8},
    {"USER32.dll!CreateCursor", 28},
    {"USER32.dll!SetCursor", 4},
    {"USER32.dll!LoadIconA", 8},
    {"USER32.dll!RegisterClassA", 4},
    {"USER32.dll!RegisterClassW", 4},
    {"USER32.dll!RegisterClassExA", 4},
    {"USER32.dll!RegisterClassExW", 4},
    {"USER32.dll!IsWindow", 4},
    {"USER32.dll!IsWindowVisible", 4},
    {"USER32.dll!IsWindowEnabled", 4},
    {"USER32.dll!GetActiveWindow", 0},
    {"USER32.dll!GetLastActivePopup", 4},
    {"USER32.dll!GetForegroundWindow", 0},
    {"USER32.dll!GetProcessWindowStation", 0},
    {"USER32.dll!GetUserObjectInformationA", 20},
    {"USER32.dll!GetUserObjectInformationW", 20},
    {"USER32.dll!WaitMessage", 0},
    {"USER32.dll!MsgWaitForMultipleObjects", 20},
    {"USER32.dll!MsgWaitForMultipleObjectsEx", 20},
    {"USER32.dll!GetAsyncKeyState", 4},
    {"USER32.dll!MessageBoxA", 16},
    {"USER32.dll!MessageBoxW", 16},
    {"USER32.dll!SetWindowLongA", 12},
    {"USER32.dll!SetWindowLongW", 12},
    {"USER32.dll!GetWindowLongA", 8},
    {"USER32.dll!GetWindowLongW", 8},
    {"USER32.dll!GetWindowThreadProcessId", 8},
    {"USER32.dll!SetWindowTextA", 8},
    {"USER32.dll!SetWindowTextW", 8},
    {"USER32.dll!GetWindowTextA", 12},
    {"USER32.dll!GetWindowTextW", 12},
    {"USER32.dll!MoveWindow", 24},
    {"USER32.dll!GetDesktopWindow", 0},
    {"USER32.dll!GetActiveWindow", 0},
    {"USER32.dll!GetDC", 4},
    {"USER32.dll!ReleaseDC", 8},
    {"GDI32.dll!GetSystemPaletteEntries", 16},
    {"GDI32.dll!GetDeviceCaps", 8},
    {"GDI32.dll!CreateFontA", 56},
    {"GDI32.dll!CreateFontIndirectA", 4},
    {"GDI32.dll!SelectObject", 8},
    {"GDI32.dll!DeleteObject", 4},
    {"GDI32.dll!SetBkMode", 8},
    {"KERNEL32.dll!MulDiv", 12},
    {"WINMM.dll!mixerOpen", 20},
    {"WINMM.dll!mixerClose", 4},
    {"WINMM.dll!mixerGetDevCapsA", 12},
    {"WINMM.dll!mixerGetDevCapsW", 12},
    {"WINMM.dll!mixerGetLineInfoA", 12},
    {"WINMM.dll!mixerGetLineInfoW", 12},
    {"WINMM.dll!mixerGetLineControlsA", 12},
    {"WINMM.dll!mixerGetLineControlsW", 12},
    {"WINMM.dll!mixerGetControlDetailsA", 12},
    {"WINMM.dll!mixerGetControlDetailsW", 12},
    {"WINMM.dll!mixerSetControlDetails", 12},
    {"WINMM.dll!mixerGetNumDevs", 0},
    // DirectX / DirectDraw / Direct3D
    {"KERNEL32.dll!DirectDrawCreate", 12},
    {"KERNEL32.dll!DirectDrawCreateEx", 16},
    {"KERNEL32.dll!Direct3DCreate8", 4},
    {"D3D8.dll!Direct3DCreate8", 4},
    {"KERNEL32.dll!DirectSoundCreate", 12},
    {"DSOUND.dll!DirectSoundCreate", 12},
    {"KERNEL32.dll!BASS_Init", 20},
    {"KERNEL32.dll!BASS_SetConfig", 8},
    {"KERNEL32.dll!BASS_Start", 0},
    {"KERNEL32.dll!BASS_Free", 0},
    {"BASS.dll!BASS_Init", 20},
    {"BASS.dll!BASS_SetConfig", 8},
    {"BASS.dll!BASS_Start", 0},
    {"BASS.dll!BASS_Free", 0},
    {"DDRAW.dll!IDirectDraw7_Method_0", 12},
    {"DDRAW.dll!IDirectDraw7_Method_1", 4},
    {"DDRAW.dll!IDirectDraw7_Method_2", 4},
    {"DDRAW.dll!IDirectDraw7_Method_4", 16},
    {"DDRAW.dll!IDirectDraw7_Method_6", 16},
    {"DDRAW.dll!IDirectDraw7_Method_20", 12},
    {"DDRAW.dll!IDirectDraw7_Method_21", 24},
    {"DDRAW.dll!IDirectDraw7_Method_22", 12}, // WaitForVerticalBlank(this, flags, hEvent)
    {"DDRAW.dll!IDirectDraw7_Method_23", 16},
    {"DDRAW.dll!IDirectDraw7_Method_27", 12}, // GetDeviceIdentifier(this, outDeviceId, flags)
    {"DDRAW.dll!IDirectDraw7_Method_12", 8},  // GetDisplayMode(this, outSurfaceDesc)
    {"DDRAW.dll!IDirectDraw7_Method_17", 8},  // GetVerticalBlankStatus(this, outBool)
    {"DDRAW.dll!IDirectDraw_Method_0", 12},   // QueryInterface(this, riid, ppv)
    {"DDRAW.dll!IDirectDraw_Method_4", 16}, // CreateClipper(this, flags, outClipper, unkOuter)
    {"DDRAW.dll!IDirectDraw_Method_5", 20}, // CreatePalette(this, flags, colorTable, outPalette, unkOuter)
    {"DDRAW.dll!IDirectDraw_Method_6", 16}, // CreateSurface(this, desc, outSurface, unkOuter)
    {"DDRAW.dll!IDirectDraw_Method_15", 8}, // GetMonitorFrequency(this, outHz)
    {"DDRAW.dll!IDirectDraw_Method_20", 12}, // SetCooperativeLevel(this, hwnd, flags)
    {"DDRAW.dll!IDirectDraw_Method_21", 16}, // SetDisplayMode(this, w, h, bpp)
    {"DDRAW.dll!IDirectDraw_Method_22", 12}, // WaitForVerticalBlank(this, flags, hEvent)
    {"DDRAW.dll!IDirectDraw_Method_23", 16}, // GetAvailableVidMem(this, caps, total, free)
    {"DDRAW.dll!IDirectDraw2_Method_20", 12}, // SetCooperativeLevel
    {"DDRAW.dll!IDirectDraw2_Method_21", 24}, // SetDisplayMode
    {"DDRAW.dll!IDirectDrawSurface2_Method_22", 8}, // GetSurfaceDesc
    {"DDRAW.dll!IDirect3D7_Method_4", 16},
    {"DDRAW.dll!IDirect3DDevice7_Method_0", 12},
    {"DDRAW.dll!IDirect3DDevice7_Method_1", 4},
    {"DDRAW.dll!IDirectDraw_Method_10", 4}, // FlipToGDISurface (takes 1 arg: THIS)
    {"DDRAW.dll!IDirectDraw_Method_8", 16}, // EnumDisplayModes (takes 4 args: THIS, dwFlags, lpDDSurfaceDesc, lpContext, lpEnumCallback)
    {"DDRAW.dll!IDirect3DDevice7_Method_2", 4},
    {"DDRAW.dll!IDirect3DDevice7_Method_4", 12},
    {"DDRAW.dll!IDirect3D8_Method_0", 12},
    {"DDRAW.dll!IDirect3D8_Method_1", 4},
    {"DDRAW.dll!IDirect3D8_Method_2", 4},
    {"DDRAW.dll!IDirect3D8_Method_5", 16},
    {"DDRAW.dll!IDirect3D8_Method_13", 16},
    {"DDRAW.dll!IDirect3D8_Method_15", 28},
    {"DDRAW.dll!IDirectDrawSurface7_Method_5", 24},  // Blt
    {"DDRAW.dll!IDirectDrawSurface7_Method_11", 12}, // Flip
    {"DDRAW.dll!IDirectDrawSurface7_Method_28", 8},  // SetClipper
    {"DDRAW.dll!IDirectDrawSurface7_Method_31", 8},  // SetPalette
    {"DDRAW.dll!IDirectDrawSurface7_Method_25", 20}, // Lock
    {"DDRAW.dll!IDirectDrawSurface7_Method_32", 8},  // Unlock
    {"DDRAW.dll!IDDSurface_Method_28", 8}, // SetClipper(this, clipper)
    {"DDRAW.dll!IDDSurface_Method_31", 8}, // SetPalette(this, palette)
    {"DDRAW.dll!IDirectDrawSurface2_Method_28", 8},
    {"DDRAW.dll!IDirectDrawSurface2_Method_31", 8},
    {"DDRAW.dll!IDirectDrawClipper_Method_4", 8},  // GetHWnd(this, outHwnd)
    {"DDRAW.dll!IDirectDrawClipper_Method_8", 12}, // SetHWnd(this, flags, hwnd)
    {"DDRAW.dll!IDirectSound_Method_3", 16},       // CreateSoundBuffer
    {"DDRAW.dll!IDirectSound_Method_6", 12},       // SetCooperativeLevel
    {"DDRAW.dll!IDirectSoundBuffer_Method_3", 8},   // GetCaps
    {"DDRAW.dll!IDirectSoundBuffer_Method_4", 12},  // GetCurrentPosition
    {"DDRAW.dll!IDirectSoundBuffer_Method_9", 8},   // GetStatus
    {"DDRAW.dll!IDirectSoundBuffer_Method_11", 32}, // Lock
    {"DDRAW.dll!IDirectSoundBuffer_Method_12", 16}, // Play
    {"DDRAW.dll!IDirectSoundBuffer_Method_13", 8},  // SetCurrentPosition
    {"DDRAW.dll!IDirectSoundBuffer_Method_14", 8},  // SetFormat
    {"DDRAW.dll!IDirectSoundBuffer_Method_15", 8},  // SetVolume
    {"DDRAW.dll!IDirectSoundBuffer_Method_16", 8},  // SetPan
    {"DDRAW.dll!IDirectSoundBuffer_Method_17", 8},  // SetFrequency
    {"DDRAW.dll!IDirectSoundBuffer_Method_18", 4},  // Stop
    {"DDRAW.dll!IDirectSoundBuffer_Method_19", 20}, // Unlock
    // Dynamic Resolution and Pointer HLE
    {"KERNEL32.dll!GetProcAddress", 8},
    {"KERNEL32.dll!EncodePointer", 4},
    {"KERNEL32.dll!DecodePointer", 4},
    // Critical Sections (Trivial Stubs)
    {"KERNEL32.dll!InitializeCriticalSectionAndSpinCount", 8},
    {"KERNEL32.dll!InitializeCriticalSection", 4},
    {"KERNEL32.dll!InitializeCriticalSectionEx", 12},
    {"KERNEL32.dll!EnterCriticalSection", 4},
    {"KERNEL32.dll!LeaveCriticalSection", 4},
    {"KERNEL32.dll!DeleteCriticalSection", 4},
    {"KERNEL32.dll!TryEnterCriticalSection", 4},
    // FLS (Fiber Local Storage)
    {"KERNEL32.dll!FlsAlloc", 4},
    {"KERNEL32.dll!FlsGetValue", 4},
    {"KERNEL32.dll!FlsSetValue", 8},
    {"KERNEL32.dll!TlsSetValue", 8},
    {"KERNEL32.dll!GetModuleHandleA", 4},
    {"KERNEL32.dll!TlsAlloc", 0},
    {"KERNEL32.dll!TlsGetValue", 4},
    {"KERNEL32.dll!InterlockedIncrement", 4},
    {"KERNEL32.dll!InterlockedDecrement", 4},
    {"KERNEL32.dll!InterlockedExchange", 8},
    {"KERNEL32.dll!FlsFree", 4},
    // String & Locale (Trivial Stubs)
    {"KERNEL32.dll!GetLocaleInfoA", 16},
    {"KERNEL32.dll!GetLocaleInfoW", 16},
    {"KERNEL32.dll!GetStringTypeW", 16},
    {"KERNEL32.dll!GetStringTypeA", 16},
    {"KERNEL32.dll!LCMapStringW", 24},
    {"KERNEL32.dll!LCMapStringA", 24},
    {"KERNEL32.dll!MultiByteToWideChar", 24},
    {"KERNEL32.dll!WideCharToMultiByte", 32},
    {"KERNEL32.dll!HeapSize", 12},
    {"KERNEL32.dll!HeapReAlloc", 16},
    {"KERNEL32.dll!GetStdHandle", 4},
    {"KERNEL32.dll!GetFileType", 4},
    {"KERNEL32.dll!GetCommandLineA", 0},
    {"KERNEL32.dll!GetEnvironmentStrings", 0},
    {"KERNEL32.dll!GetEnvironmentStringsW", 0},
    {"KERNEL32.dll!FreeEnvironmentStringsA", 4},
    {"KERNEL32.dll!FreeEnvironmentStringsW", 4},
    {"KERNEL32.dll!GetACP", 0},
    {"KERNEL32.dll!GetCPInfo", 8},
    {"KERNEL32.dll!IsValidCodePage", 4},
    {"KERNEL32.dll!RaiseException", 16},
    {"KERNEL32.dll!SetHandleCount", 4},
    {"KERNEL32.dll!SetUnhandledExceptionFilter", 4},
    {"KERNEL32.dll!EnumSystemLocalesA", 8},
    {"KERNEL32.dll!WideCharToMultiByte", 32},
    {"KERNEL32.dll!GetCPInfo", 8},
    {"KERNEL32.dll!GetACP", 0},
    {"KERNEL32.dll!GetOEMCP", 0},
    {"KERNEL32.dll!IsValidCodePage", 4},
    {"KERNEL32.dll!FreeEnvironmentStringsW", 4},
    {"KERNEL32.dll!GetEnvironmentStringsW", 0},
    {"KERNEL32.dll!SetEnvironmentVariableA", 8},
    {"KERNEL32.dll!GetEnvironmentVariableA", 12},
    {"KERNEL32.dll!GetCommandLineA", 0},
    {"KERNEL32.dll!GetCommandLineW", 0},
    {"KERNEL32.dll!GetStdHandle", 4},
    {"KERNEL32.dll!GetFileType", 4},
    {"KERNEL32.dll!SetHandleCount", 4},
    {"KERNEL32.dll!RaiseException", 16},
    {"KERNEL32.dll!SetUnhandledExceptionFilter", 4},
    {"KERNEL32.dll!UnhandledExceptionFilter", 4},
    {"KERNEL32.dll!IsDebuggerPresent", 0},
    {"KERNEL32.dll!IsProcessorFeaturePresent", 4},
    {"KERNEL32.dll!ExitProcess", 4},
    {"KERNEL32.dll!TerminateProcess", 8},
    {"KERNEL32.dll!CorExitProcess", 4},
    // IPC and Memory
    {"KERNEL32.dll!CreateFileMappingA", 24},
    {"KERNEL32.dll!OpenFileMappingA", 12},
    {"KERNEL32.dll!MapViewOfFile", 20},
    {"KERNEL32.dll!UnmapViewOfFile", 4},
    {"KERNEL32.dll!GetSystemInfo", 4},
    {"KERNEL32.dll!CreateMutexA", 12},
    {"KERNEL32.dll!OpenMutexA", 12},
    {"KERNEL32.dll!ReleaseMutex", 4},
    // Dynamic Library Loading
    {"KERNEL32.dll!LoadLibraryA", 4},
    {"KERNEL32.dll!LoadLibraryW", 4},
    {"KERNEL32.dll!FreeLibrary", 4},
    {"KERNEL32.dll!GetModuleHandleW", 4},
    {"KERNEL32.dll!GetModuleFileNameW", 12},
    // Version Checking
    {"KERNEL32.dll!GetFileVersionInfoSizeA", 8},
    {"KERNEL32.dll!GetFileVersionInfoA", 16},
    {"KERNEL32.dll!VerQueryValueA", 16},
    {"VERSION.dll!GetFileVersionInfoSizeA", 8},
    {"VERSION.dll!GetFileVersionInfoA", 16},
    {"VERSION.dll!VerQueryValueA", 16},
    // Files & Directories
    {"KERNEL32.dll!GetCurrentDirectoryW", 8},
    {"KERNEL32.dll!GetCurrentDirectoryA", 8},
    {"KERNEL32.dll!SetCurrentDirectoryW", 4},
    {"KERNEL32.dll!SetCurrentDirectoryA", 4},
    {"KERNEL32.dll!GetSystemDirectoryW", 8},
    {"KERNEL32.dll!GetSystemDirectoryA", 8},
    {"KERNEL32.dll!GetWindowsDirectoryW", 8},
    {"KERNEL32.dll!GetWindowsDirectoryA", 8},
    {"KERNEL32.dll!GetFullPathNameW", 16},
    {"KERNEL32.dll!GetFullPathNameA", 16},
    {"KERNEL32.dll!GetFileAttributesW", 4},
    {"KERNEL32.dll!GetFileAttributesA", 4},
    {"KERNEL32.dll!GetFileAttributesExW", 12},
    {"KERNEL32.dll!GetFileAttributesExA", 12},
    {"KERNEL32.dll!SHGetFolderPathA", 20},
    {"SHELL32.dll!SHGetFolderPathA", 20},
    {"KERNEL32.dll!FindFirstFileA", 8},
    {"KERNEL32.dll!FindNextFileA", 8},
    {"KERNEL32.dll!FindClose", 4},
    {"KERNEL32.dll!GetDiskFreeSpaceA", 20},
    {"KERNEL32.dll!GetDiskFreeSpaceExA", 16},
    {"KERNEL32.dll!OutputDebugStringA", 4},
    {"KERNEL32.dll!OutputDebugStringW", 4},
    {"KERNEL32.dll!CreateFileA", 28},
    {"KERNEL32.dll!CreateFileW", 28},
    {"KERNEL32.dll!ReadFile", 20},
    {"KERNEL32.dll!WriteFile", 20},
    {"KERNEL32.dll!SetFilePointer", 16},
    {"KERNEL32.dll!GetFileSize", 8},
    {"KERNEL32.dll!FindResourceA", 12},
    {"KERNEL32.dll!LoadResource", 8},
    {"KERNEL32.dll!LockResource", 4},
    {"KERNEL32.dll!SizeofResource", 8},
    {"KERNEL32.dll!FreeResource", 4},
    {"KERNEL32.dll!GetFileTime", 16},
    {"KERNEL32.dll!SetFileTime", 16},
    {"KERNEL32.dll!FileTimeToSystemTime", 8},
    {"KERNEL32.dll!SystemTimeToFileTime", 8},
    {"KERNEL32.dll!FileTimeToLocalFileTime", 8},
    {"KERNEL32.dll!LocalFileTimeToFileTime", 8},
    {"KERNEL32.dll!GetSystemTime", 4},
    {"KERNEL32.dll!GetLocalTime", 4},
    // Media and Timing (WINMM)
    {"WINMM.dll!timeGetTime", 0},
    // Registry (ADVAPI32)
    {"ADVAPI32.dll!RegOpenKeyExA", 20},
    {"ADVAPI32.dll!RegQueryValueExA", 24},
    {"ADVAPI32.dll!RegCreateKeyExA", 36},
    {"ADVAPI32.dll!RegSetValueExA", 24},
    {"ADVAPI32.dll!RegDeleteValueA", 8},
    {"ADVAPI32.dll!RegCloseKey", 4},
    // COM (OLE32/OLEAUT32)
    {"ole32.dll!CoInitialize", 4},
    {"OLEAUT32.dll!Ordinal_9", 4}, // SysFreeString
    {"mscoree.dll!CorExitProcess", 4}
};

DummyAPIHandler::DummyAPIHandler(CpuBackend& backend_ref) : backend(backend_ref), current_addr(FAKE_API_BASE) {
    llm_pipeline_enabled = env_truthy("PVZ_ENABLE_LLM");
    dylib_mocks_enabled = env_truthy("PVZ_ENABLE_DYLIB_MOCKS");
    max_api_llm_requests = env_int("PVZ_MAX_API_REQUESTS", -1);
    api_stats_interval = static_cast<uint64_t>(std::max(0, env_int("PVZ_API_STATS_INTERVAL", 0)));
    eip_hot_sample_enabled = env_truthy("PVZ_EIP_HOT_SAMPLE");
    int hot_interval = env_int("PVZ_EIP_HOT_SAMPLE_INTERVAL", 50000);
    if (hot_interval > 0) eip_hot_sample_interval = static_cast<uint64_t>(hot_interval);
    int hot_cap = env_int("PVZ_EIP_HOT_PAGE_CAP", 4096);
    if (hot_cap > 0) eip_hot_page_cap = static_cast<size_t>(hot_cap);
    int hot_addr_cap = env_int("PVZ_EIP_HOT_ADDR_CAP", 16384);
    if (hot_addr_cap > 0) eip_hot_addr_cap = static_cast<size_t>(hot_addr_cap);
    hot_loop_api_trace_enabled = env_truthy("PVZ_HOT_LOOP_API_TRACE");
    int hot_loop_interval = env_int("PVZ_HOT_LOOP_API_TRACE_INTERVAL", 50000);
    if (hot_loop_interval > 0) hot_loop_api_trace_interval = static_cast<uint64_t>(hot_loop_interval);
    int hot_loop_cap = env_int("PVZ_HOT_LOOP_API_CAP", 4096);
    if (hot_loop_cap > 0) hot_loop_api_cap = static_cast<size_t>(hot_loop_cap);
    int hot_focus = env_int("PVZ_HOT_FOCUS_RANGE", 0x80);
    if (hot_focus > 0) hot_focus_range = static_cast<uint32_t>(hot_focus);
    hot_focus_centers = {0x62ce9b, 0x62cf8e, 0x62118b, 0x61fcd4};
    std::vector<uint32_t> hot_focus_env = parse_u32_list_csv(std::getenv("PVZ_HOT_FOCUS_ADDRS"));
    if (!hot_focus_env.empty()) {
        hot_focus_centers = std::move(hot_focus_env);
    }
    coop_threads_enabled_flag = env_truthy("PVZ_COOP_THREADS");
    coop_trace = env_truthy("PVZ_COOP_TRACE");
    int coop_timeslice = env_int("PVZ_COOP_TIMESLICE", 30000);
    if (coop_timeslice > 0) coop_timeslice_instructions = static_cast<uint64_t>(coop_timeslice);
    int coop_stack = env_int("PVZ_COOP_STACK_SIZE", 0x200000);
    if (coop_stack > 0) coop_default_stack_size = static_cast<uint32_t>(coop_stack);
    int heap_free_cap = env_int("PVZ_HEAP_FREE_CAP_ENTRIES", 131072);
    if (heap_free_cap < 0) {
        g_heap_free_entry_cap = 0;
    } else {
        g_heap_free_entry_cap = static_cast<size_t>(heap_free_cap);
    }
    std::cout << "[*] API LLM mode: " << (llm_pipeline_enabled ? "ON" : "OFF")
              << ", dylib mocks: " << (dylib_mocks_enabled ? "ON" : "OFF");
    if (llm_pipeline_enabled) {
        if (max_api_llm_requests < 0) {
            std::cout << ", api budget: unlimited";
        } else {
            std::cout << ", api budget: " << max_api_llm_requests;
        }
    }
    std::cout << "\n";
    if (eip_hot_sample_enabled) {
        std::cout << "[*] EIP hot sampler armed (trigger: resources.xml), interval="
                  << eip_hot_sample_interval << ", page_cap=" << eip_hot_page_cap
                  << ", addr_cap=" << eip_hot_addr_cap << "\n";
    }
    if (hot_loop_api_trace_enabled) {
        std::cout << "[*] Hot-loop API trace enabled, interval=" << hot_loop_api_trace_interval
                  << ", cap=" << hot_loop_api_cap << ", focus_range=0x" << std::hex
                  << hot_focus_range << std::dec << ", centers=";
        for (size_t i = 0; i < hot_focus_centers.size(); ++i) {
            std::cout << (i == 0 ? "" : ",") << "0x" << std::hex << hot_focus_centers[i] << std::dec;
        }
        std::cout << "\n";
    }
    if (coop_threads_enabled_flag) {
        std::cout << "[*] Cooperative threads enabled, timeslice_insns=" << coop_timeslice_instructions
                  << ", default_stack=0x" << std::hex << coop_default_stack_size << std::dec;
        if (coop_trace) std::cout << ", trace=on";
        std::cout << "\n";
    }
    if (g_heap_free_entry_cap == 0) {
        std::cout << "[*] Heap free-list cap: unlimited (PVZ_HEAP_FREE_CAP_ENTRIES)\n";
    } else {
        std::cout << "[*] Heap free-list cap: " << g_heap_free_entry_cap
                  << " entries (PVZ_HEAP_FREE_CAP_ENTRIES)\n";
    }
    ctx.backend = &backend;
    ctx.uc = backend.engine();
    std::filesystem::create_directories("api_requests");
    std::filesystem::create_directories("api_mocks");
    
    std::cout << "[*] Mapping FAKE_API boundary at 0x" << std::hex << FAKE_API_BASE << std::dec << "\n";
    backend.mem_map(FAKE_API_BASE, 0x100000, UC_PROT_ALL); // 1MB

    // --- BUILD FAKE KERNEL32.DLL PE HEADER ---
    uint32_t k32_base = 0x76000000;
    backend.mem_map(k32_base, 0x200000, UC_PROT_ALL);
    
    uint16_t mz_magic = 0x5A4D; // "MZ"
    backend.mem_write(k32_base, &mz_magic, 2);
    
    uint32_t e_lfanew = 0x40;
    backend.mem_write(k32_base + 0x3C, &e_lfanew, 4);
    uint32_t signature = 0x00004550; // "PE\0\0"
    backend.mem_write(k32_base + 0x40, &signature, 4);
    
    uint16_t opt_magic = 0x010B; // PE32
    backend.mem_write(k32_base + 0x40 + 0x18, &opt_magic, 2);
    
    uint32_t export_dir_rva = 0x1000;
    uint32_t export_dir_size = 0x1000;
    backend.mem_write(k32_base + 0x40 + 0x18 + 0x60, &export_dir_rva, 4);
    backend.mem_write(k32_base + 0x40 + 0x18 + 0x64, &export_dir_size, 4);
    
    uint32_t exp_dir[11] = {0, 0, 0, 0x1100, 1, 3, 3, 0x1200, 0x1300, 0x1400};
    backend.mem_write(k32_base + 0x1000, exp_dir, 40);
    
    const char* dll_name = "KERNEL32.dll";
    backend.mem_write(k32_base + 0x1100, dll_name, strlen(dll_name) + 1);
    
    const char* f1_name = "GetProcAddress";
    backend.mem_write(k32_base + 0x1310, f1_name, strlen(f1_name) + 1);
    const char* f2_name = "LoadLibraryA";
    backend.mem_write(k32_base + 0x1340, f2_name, strlen(f2_name) + 1);
    const char* f3_name = "VirtualAlloc";
    backend.mem_write(k32_base + 0x1370, f3_name, strlen(f3_name) + 1);
    
    uint32_t addr_names[3] = {0x1310, 0x1340, 0x1370};
    backend.mem_write(k32_base + 0x1300, addr_names, sizeof(addr_names));
    
    uint16_t ordinals[3] = {0, 1, 2};
    backend.mem_write(k32_base + 0x1400, ordinals, sizeof(ordinals));
    
    uint32_t addr_GetProcAddress = register_fake_api("KERNEL32.dll!GetProcAddress");
    uint32_t addr_LoadLibraryA = register_fake_api("KERNEL32.dll!LoadLibraryA");
    uint32_t addr_VirtualAlloc = register_fake_api("KERNEL32.dll!VirtualAlloc");
    
    auto write_jmp_stub = [&](uint32_t rva, uint32_t target_addr) {
        uint8_t jmp_stub[5] = {0xE9, 0, 0, 0, 0};
        uint32_t stub_addr = k32_base + rva;
        uint32_t rel_offset = target_addr - (stub_addr + 5);
        memcpy(&jmp_stub[1], &rel_offset, 4);
        backend.mem_write(stub_addr, jmp_stub, 5);
    };
    
    write_jmp_stub(0x2000, addr_GetProcAddress);
    write_jmp_stub(0x2010, addr_LoadLibraryA);
    write_jmp_stub(0x2020, addr_VirtualAlloc);
    
    uint32_t addr_funcs[3] = {0x2000, 0x2010, 0x2020};
    backend.mem_write(k32_base + 0x1200, addr_funcs, sizeof(addr_funcs));

    uc_hook trace;
    backend.hook_add(&trace, UC_HOOK_BLOCK, (void*)hook_api_call, this, 1, 0); // Catch all blocks
}

void DummyAPIHandler::cleanup_process_state() {
    for (auto& kv : ctx.handle_map) {
        const std::string& key = kv.first;
        void* ptr = kv.second;
        if (!ptr) continue;
        if (key.rfind("file_", 0) == 0) {
            delete static_cast<HostFileHandle*>(ptr);
        } else if (key.rfind("find_", 0) == 0) {
            delete static_cast<FindHandle*>(ptr);
        } else if (key.rfind("mapping_", 0) == 0) {
            delete static_cast<MappingHandle*>(ptr);
        } else if (key.rfind("event_", 0) == 0) {
            delete static_cast<EventHandle*>(ptr);
        } else if (key.rfind("thread_", 0) == 0) {
            delete static_cast<ThreadHandle*>(ptr);
        } else if (key.rfind("reg_", 0) == 0) {
            delete static_cast<RegistryKeyHandle*>(ptr);
        }
    }
    ctx.handle_map.clear();
    ctx.global_state.clear();

    g_win32_message_queue.clear();
    g_win32_timers.clear();
    g_valid_hwnds.clear();
    g_hwnd_owner_thread_id.clear();
    g_window_long_values.clear();
    g_window_text_values.clear();
    g_synth_idle_timer_next_ms = 0;
    g_hwnd_top = 0x12345678u;
    g_win32_class_by_name.clear();
    g_win32_class_by_atom.clear();
    g_win32_class_atom_top = 1;
    g_heap_sizes.clear();
    g_heap_free_by_size.clear();
    g_heap_free_cap_warned = false;
    g_mapview_live_sizes.clear();
    g_mapview_free_by_size.clear();
    g_registry_values.clear();
    g_registry_types.clear();
    g_resource_ptr_by_handle.clear();
    g_resource_size_by_handle.clear();
    g_resource_handle_top = 0xB000;
    g_resource_heap_top = 0x36000000;
    g_resource_heap_mapped = false;
    g_thread_start_to_handle.clear();
    g_module_handle_by_name.clear();
    g_module_name_by_handle.clear();
    g_module_handle_top = 0x79000000u;

    eip_hot_page_hits.clear();
    eip_hot_addr_hits.clear();
    eip_hot_page_dropped = 0;
    eip_hot_addr_dropped = 0;
    eip_hot_sample_started = false;
    hot_loop_api_counts.clear();
    hot_loop_api_eax_hist.clear();
    hot_loop_api_lasterror_hist.clear();
    hot_loop_api_dropped = 0;
    coop_threads.clear();
    coop_order.clear();
    coop_current_handle = 0;
    coop_thread_id_top = 1;
    coop_stack_cursor = 0x2F000000;
    coop_threads_initialized = false;
    coop_force_yield = false;
}

DummyAPIHandler::~DummyAPIHandler() {
    cleanup_process_state();
    for (auto& pair : dylib_handles) {
        if (pair.second) dlclose(pair.second);
    }
}

void DummyAPIHandler::maybe_print_api_stats() {
    if (api_stats_interval == 0 || api_call_total == 0 || (api_call_total % api_stats_interval) != 0) {
        return;
    }
    std::vector<std::pair<std::string, uint64_t>> items(api_call_counts.begin(), api_call_counts.end());
    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    std::cout << "\n[API STATS] total_calls=" << api_call_total << " top:";
    size_t limit = std::min<size_t>(12, items.size());
    for (size_t i = 0; i < limit; ++i) {
        std::cout << " [" << items[i].second << "] " << items[i].first;
    }
    std::cout << "\n";
    maybe_print_eip_hot_pages();
    maybe_print_hot_loop_api_stats();
}

void DummyAPIHandler::maybe_start_eip_hot_sample(const std::string& normalized_guest_path) {
    if (!eip_hot_sample_enabled || eip_hot_sample_started) return;
    if (normalized_guest_path != "properties/resources.xml") return;
    eip_hot_sample_started = true;
    eip_hot_page_hits.clear();
    eip_hot_addr_hits.clear();
    eip_hot_page_dropped = 0;
    eip_hot_addr_dropped = 0;
    std::cout << "[*] EIP hot sampler started after resources.xml open.\n";
}

uint32_t DummyAPIHandler::get_api_caller_ret_addr() {
    uint32_t esp = 0;
    if (backend.reg_read(UC_X86_REG_ESP, &esp) != UC_ERR_OK) return 0;
    uint32_t ret_addr = 0;
    if (backend.mem_read(esp, &ret_addr, 4) != UC_ERR_OK) return 0;
    return ret_addr;
}

bool DummyAPIHandler::is_hot_focus_ret(uint32_t ret_addr) const {
    if (ret_addr == 0 || ret_addr >= FAKE_API_BASE) return false;
    if (hot_focus_centers.empty()) return false;
    for (uint32_t center : hot_focus_centers) {
        uint32_t diff = (ret_addr > center) ? (ret_addr - center) : (center - ret_addr);
        if (diff <= hot_focus_range) return true;
    }
    return false;
}

void DummyAPIHandler::maybe_sample_eip_hot_caller(uint32_t ret_addr) {
    if (!eip_hot_sample_enabled || !eip_hot_sample_started) return;
    if (ret_addr == 0 || ret_addr >= FAKE_API_BASE) return;

    uint32_t page = ret_addr & ~0xFFFu;
    auto it = eip_hot_page_hits.find(page);
    if (it != eip_hot_page_hits.end()) {
        it->second++;
    } else if (eip_hot_page_hits.size() >= eip_hot_page_cap) {
        eip_hot_page_dropped++;
    } else {
        eip_hot_page_hits.emplace(page, 1);
    }

    auto it_addr = eip_hot_addr_hits.find(ret_addr);
    if (it_addr != eip_hot_addr_hits.end()) {
        it_addr->second++;
        return;
    }
    if (eip_hot_addr_hits.size() >= eip_hot_addr_cap) {
        eip_hot_addr_dropped++;
        return;
    }
    eip_hot_addr_hits.emplace(ret_addr, 1);
}

void DummyAPIHandler::record_hot_loop_api_stat(uint32_t ret_addr, const std::string& api_name) {
    if (!hot_loop_api_trace_enabled) return;
    if (!is_hot_focus_ret(ret_addr)) return;
    std::ostringstream oss;
    oss << "0x" << std::hex << ret_addr << std::dec << " " << api_name;
    const std::string key = oss.str();

    auto it = hot_loop_api_counts.find(key);
    if (it == hot_loop_api_counts.end()) {
        if (hot_loop_api_counts.size() >= hot_loop_api_cap) {
            hot_loop_api_dropped++;
            return;
        }
        it = hot_loop_api_counts.emplace(key, 0).first;
    }
    it->second++;
    uint32_t eax = 0;
    backend.reg_read(UC_X86_REG_EAX, &eax);
    hot_loop_api_eax_hist[key][eax]++;
    uint32_t last_error = 0;
    auto it_le = ctx.global_state.find("LastError");
    if (it_le != ctx.global_state.end()) {
        last_error = static_cast<uint32_t>(it_le->second);
    }
    hot_loop_api_lasterror_hist[key][last_error]++;
}

void DummyAPIHandler::maybe_print_hot_loop_api_stats() {
    if (!hot_loop_api_trace_enabled) return;
    if (hot_loop_api_trace_interval == 0 || api_call_total == 0 || (api_call_total % hot_loop_api_trace_interval) != 0) {
        return;
    }
    std::vector<std::pair<std::string, uint64_t>> items(hot_loop_api_counts.begin(), hot_loop_api_counts.end());
    if (items.empty()) {
        std::cout << "[HOT LOOP API] no samples yet\n";
        return;
    }
    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    std::cout << "[HOT LOOP API] top:";
    const size_t limit = std::min<size_t>(12, items.size());
    for (size_t i = 0; i < limit; ++i) {
        const std::string& key = items[i].first;
        uint32_t top_eax = 0;
        uint64_t top_eax_hits = 0;
        auto it_eax = hot_loop_api_eax_hist.find(key);
        if (it_eax != hot_loop_api_eax_hist.end()) {
            for (const auto& kv : it_eax->second) {
                if (kv.second > top_eax_hits) {
                    top_eax_hits = kv.second;
                    top_eax = kv.first;
                }
            }
        }
        uint32_t top_le = 0;
        uint64_t top_le_hits = 0;
        auto it_le = hot_loop_api_lasterror_hist.find(key);
        if (it_le != hot_loop_api_lasterror_hist.end()) {
            for (const auto& kv : it_le->second) {
                if (kv.second > top_le_hits) {
                    top_le_hits = kv.second;
                    top_le = kv.first;
                }
            }
        }
        std::cout << " [" << items[i].second << "] " << key
                  << " eax=0x" << std::hex << top_eax
                  << " le=" << std::dec << top_le;
    }
    if (hot_loop_api_dropped > 0) {
        std::cout << " dropped=" << hot_loop_api_dropped;
    }
    std::cout << "\n";
}

void DummyAPIHandler::maybe_print_eip_hot_pages() {
    if (!eip_hot_sample_enabled || !eip_hot_sample_started) return;
    if (eip_hot_sample_interval == 0 || api_call_total == 0 || (api_call_total % eip_hot_sample_interval) != 0) return;
    std::vector<std::pair<uint32_t, uint64_t>> pages(eip_hot_page_hits.begin(), eip_hot_page_hits.end());
    if (pages.empty()) {
        std::cout << "[EIP HOT] no samples yet\n";
        return;
    }
    std::sort(pages.begin(), pages.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    std::cout << "[EIP HOT] top_pages:";
    size_t limit = std::min<size_t>(10, pages.size());
    for (size_t i = 0; i < limit; ++i) {
        std::cout << " [0x" << std::hex << pages[i].first << std::dec << ":" << pages[i].second << "]";
    }
    if (eip_hot_page_dropped > 0) {
        std::cout << " dropped=" << eip_hot_page_dropped;
    }
    std::cout << "\n";

    std::vector<std::pair<uint32_t, uint64_t>> addrs(eip_hot_addr_hits.begin(), eip_hot_addr_hits.end());
    if (!addrs.empty()) {
        std::sort(addrs.begin(), addrs.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        std::cout << "[EIP HOT] top_addrs:";
        size_t addrs_limit = std::min<size_t>(10, addrs.size());
        for (size_t i = 0; i < addrs_limit; ++i) {
            std::cout << " [0x" << std::hex << addrs[i].first << std::dec << ":" << addrs[i].second << "]";
        }
        if (eip_hot_addr_dropped > 0) {
            std::cout << " dropped=" << eip_hot_addr_dropped;
        }
        std::cout << "\n";
    }
}

bool DummyAPIHandler::coop_read_regs(CoopThreadRegs& regs) {
    if (backend.reg_read(UC_X86_REG_EAX, &regs.eax) != UC_ERR_OK) return false;
    if (backend.reg_read(UC_X86_REG_EBX, &regs.ebx) != UC_ERR_OK) return false;
    if (backend.reg_read(UC_X86_REG_ECX, &regs.ecx) != UC_ERR_OK) return false;
    if (backend.reg_read(UC_X86_REG_EDX, &regs.edx) != UC_ERR_OK) return false;
    if (backend.reg_read(UC_X86_REG_ESI, &regs.esi) != UC_ERR_OK) return false;
    if (backend.reg_read(UC_X86_REG_EDI, &regs.edi) != UC_ERR_OK) return false;
    if (backend.reg_read(UC_X86_REG_EBP, &regs.ebp) != UC_ERR_OK) return false;
    if (backend.reg_read(UC_X86_REG_ESP, &regs.esp) != UC_ERR_OK) return false;
    if (backend.reg_read(UC_X86_REG_EIP, &regs.eip) != UC_ERR_OK) return false;
    if (backend.reg_read(UC_X86_REG_EFLAGS, &regs.eflags) != UC_ERR_OK) regs.eflags = 0x202;
    return true;
}

void DummyAPIHandler::coop_write_regs(const CoopThreadRegs& regs) {
    backend.reg_write(UC_X86_REG_EAX, &regs.eax);
    backend.reg_write(UC_X86_REG_EBX, &regs.ebx);
    backend.reg_write(UC_X86_REG_ECX, &regs.ecx);
    backend.reg_write(UC_X86_REG_EDX, &regs.edx);
    backend.reg_write(UC_X86_REG_ESI, &regs.esi);
    backend.reg_write(UC_X86_REG_EDI, &regs.edi);
    backend.reg_write(UC_X86_REG_EBP, &regs.ebp);
    backend.reg_write(UC_X86_REG_ESP, &regs.esp);
    backend.reg_write(UC_X86_REG_EIP, &regs.eip);
    backend.reg_write(UC_X86_REG_EFLAGS, &regs.eflags);
}

bool DummyAPIHandler::coop_save_current_thread_regs() {
    if (!coop_threads_enabled_flag || !coop_threads_initialized) return false;
    auto it = coop_threads.find(coop_current_handle);
    if (it == coop_threads.end()) return false;
    return coop_read_regs(it->second.regs);
}

bool DummyAPIHandler::coop_load_thread_regs(uint32_t handle) {
    auto it = coop_threads.find(handle);
    if (it == coop_threads.end()) return false;
    coop_current_handle = handle;
    coop_write_regs(it->second.regs);
    ctx.global_state["CurrentThreadHandle"] = handle;
    ctx.global_state["CurrentThreadId"] = it->second.thread_id;
    return true;
}

void DummyAPIHandler::coop_prune_finished_threads() {
    coop_order.erase(
        std::remove_if(coop_order.begin(), coop_order.end(), [&](uint32_t handle) {
            auto it = coop_threads.find(handle);
            if (it == coop_threads.end()) return true;
            return it->second.finished;
        }),
        coop_order.end());
}

bool DummyAPIHandler::coop_advance_to_next_runnable() {
    if (!coop_threads_enabled_flag || !coop_threads_initialized) return false;
    coop_prune_finished_threads();
    if (coop_order.empty()) return false;

    size_t start_index = 0;
    auto it_cur = std::find(coop_order.begin(), coop_order.end(), coop_current_handle);
    if (it_cur != coop_order.end()) {
        start_index = static_cast<size_t>(std::distance(coop_order.begin(), it_cur));
    }
    if (coop_force_yield || it_cur == coop_order.end()) {
        start_index = (start_index + 1) % coop_order.size();
    }

    for (size_t i = 0; i < coop_order.size(); ++i) {
        size_t idx = (start_index + i) % coop_order.size();
        uint32_t handle = coop_order[idx];
        auto it = coop_threads.find(handle);
        if (it == coop_threads.end()) continue;
        if (it->second.finished || !it->second.runnable) continue;
        return coop_load_thread_regs(handle);
    }
    return false;
}

bool DummyAPIHandler::coop_mark_thread_finished(uint32_t handle, const char* reason) {
    auto it = coop_threads.find(handle);
    if (it == coop_threads.end()) return false;
    if (it->second.finished) return true;
    it->second.finished = true;
    it->second.runnable = false;
    if (coop_trace) {
        std::cout << "[COOP] thread 0x" << std::hex << handle << std::dec
                  << " finished";
        if (reason && *reason) std::cout << " (" << reason << ")";
        std::cout << "\n";
    }
    return true;
}

void DummyAPIHandler::coop_register_main_thread() {
    if (!coop_threads_enabled_flag || coop_threads_initialized) return;

    CoopThreadState main_state{};
    main_state.handle = coop_main_handle;
    main_state.thread_id = coop_thread_id_top++;
    main_state.is_main = true;
    main_state.runnable = true;
    main_state.finished = false;
    if (!coop_read_regs(main_state.regs)) {
        std::cerr << "[COOP] failed to snapshot main thread registers. disabling cooperative threads.\n";
        coop_threads_enabled_flag = false;
        return;
    }

    coop_threads.clear();
    coop_order.clear();
    coop_threads.emplace(main_state.handle, main_state);
    coop_order.push_back(main_state.handle);
    coop_current_handle = main_state.handle;
    coop_threads_initialized = true;
    ctx.global_state["CurrentThreadHandle"] = main_state.handle;
    ctx.global_state["CurrentThreadId"] = main_state.thread_id;
    if (coop_trace) {
        std::cout << "[COOP] registered main thread handle=0x" << std::hex
                  << main_state.handle << std::dec
                  << " eip=0x" << std::hex << main_state.regs.eip << std::dec << "\n";
    }
}

uint32_t DummyAPIHandler::coop_current_pc() const {
    if (!coop_threads_enabled_flag || !coop_threads_initialized) return 0;
    auto it = coop_threads.find(coop_current_handle);
    if (it == coop_threads.end()) return 0;
    return it->second.regs.eip;
}

uint32_t DummyAPIHandler::coop_current_thread_id() const {
    if (!coop_threads_enabled_flag || !coop_threads_initialized) return 1;
    auto it = coop_threads.find(coop_current_handle);
    if (it == coop_threads.end()) return 1;
    return it->second.thread_id;
}

bool DummyAPIHandler::coop_spawn_thread(uint32_t handle, uint32_t start_address, uint32_t parameter, uint32_t requested_stack_size) {
    if (!coop_threads_enabled_flag) return false;
    if (!coop_threads_initialized) {
        coop_register_main_thread();
        if (!coop_threads_initialized) return false;
    }
    if (start_address == 0 || handle == 0) return false;
    if (coop_threads.find(handle) != coop_threads.end()) return true;

    uint32_t stack_size = requested_stack_size ? requested_stack_size : coop_default_stack_size;
    if (stack_size < 0x10000u) stack_size = 0x10000u;
    if (stack_size > 0x01000000u) stack_size = 0x01000000u;
    stack_size = (stack_size + 0xFFFu) & ~0xFFFu;
    uint32_t stack_base = 0;
    bool mapped = false;
    uint32_t cursor = coop_stack_cursor;
    for (int attempt = 0; attempt < 256; ++attempt) {
        if (cursor <= stack_size + 0x10000u) break;
        uint32_t candidate = (cursor - stack_size) & ~0xFFFu;
        uc_err map_err = backend.mem_map(candidate, stack_size, UC_PROT_READ | UC_PROT_WRITE);
        if (map_err == UC_ERR_OK) {
            stack_base = candidate;
            mapped = true;
            coop_stack_cursor = candidate - 0x10000u;
            break;
        }
        if (candidate <= 0x10000u) break;
        cursor = candidate - 0x10000u;
    }
    if (!mapped) {
        std::cerr << "[COOP] failed to map thread stack for handle 0x"
                  << std::hex << handle << std::dec << "\n";
        return false;
    }

    uint32_t esp = stack_base + stack_size - 8;
    uint32_t ret_addr = 0;
    backend.mem_write(esp, &ret_addr, 4);
    backend.mem_write(esp + 4, &parameter, 4);

    CoopThreadState thread{};
    thread.handle = handle;
    thread.thread_id = coop_thread_id_top++;
    thread.start_address = start_address;
    thread.parameter = parameter;
    thread.stack_base = stack_base;
    thread.stack_size = stack_size;
    thread.runnable = true;
    thread.finished = false;
    thread.regs.eax = 0;
    thread.regs.ebx = 0;
    thread.regs.ecx = 0;
    thread.regs.edx = 0;
    thread.regs.esi = 0;
    thread.regs.edi = 0;
    thread.regs.ebp = esp;
    thread.regs.esp = esp;
    thread.regs.eip = start_address;
    thread.regs.eflags = 0x202;

    coop_threads.emplace(handle, thread);
    coop_order.push_back(handle);
    coop_force_yield = true;
    if (coop_trace) {
        std::cout << "[COOP] spawned thread handle=0x" << std::hex << handle
                  << " tid=" << std::dec << thread.thread_id
                  << " start=0x" << std::hex << start_address
                  << " param=0x" << parameter
                  << " stack=[0x" << stack_base << ",0x" << (stack_base + stack_size)
                  << ")" << std::dec << "\n";
    }
    return true;
}

bool DummyAPIHandler::coop_is_thread_finished(uint32_t handle) const {
    auto it = coop_threads.find(handle);
    if (it == coop_threads.end()) return true;
    return it->second.finished;
}

void DummyAPIHandler::coop_on_timeslice_end() {
    if (!coop_threads_enabled_flag || !coop_threads_initialized) return;
    auto it = coop_threads.find(coop_current_handle);
    if (it == coop_threads.end()) return;

    // Fast-path: while only a single runnable guest thread exists, avoid
    // expensive save/load register churn every timeslice.
    if (!coop_force_yield && coop_order.size() == 1 && !it->second.finished) {
        uint32_t eip = 0;
        backend.reg_read(UC_X86_REG_EIP, &eip);
        it->second.regs.eip = eip;
        it->second.quanta++;
        if (eip == 0 || eip == 0xFFFFFFFFu) {
            coop_mark_thread_finished(coop_current_handle, "returned to null");
        }
        return;
    }

    if (!it->second.finished) {
        coop_save_current_thread_regs();
        it->second.quanta++;
        if (it->second.regs.eip == 0 || it->second.regs.eip == 0xFFFFFFFFu) {
            coop_mark_thread_finished(coop_current_handle, "returned to null");
        }
    }

    bool switched = false;
    if (coop_force_yield || coop_order.size() > 1 || it->second.finished) {
        switched = coop_advance_to_next_runnable();
    }
    coop_force_yield = false;

    if (!switched && !it->second.finished) {
        coop_load_thread_regs(coop_current_handle);
    }
}

bool DummyAPIHandler::coop_try_absorb_emu_error(uc_err err) {
    if (!coop_threads_enabled_flag || !coop_threads_initialized) return false;

    switch (err) {
        case UC_ERR_FETCH_UNMAPPED:
        case UC_ERR_READ_UNMAPPED:
        case UC_ERR_WRITE_UNMAPPED:
        case UC_ERR_INSN_INVALID:
        case UC_ERR_EXCEPTION:
            break;
        default:
            return false;
    }

    if (coop_current_handle == coop_main_handle) {
        return false;
    }

    uint32_t eip = 0;
    backend.reg_read(UC_X86_REG_EIP, &eip);
    if (coop_trace) {
        std::cout << "[COOP] worker fault absorbed handle=0x" << std::hex << coop_current_handle
                  << " eip=0x" << eip << " err=" << std::dec << err << "\n";
    }
    coop_mark_thread_finished(coop_current_handle, "fault");
    coop_force_yield = true;
    return coop_advance_to_next_runnable();
}

bool DummyAPIHandler::coop_should_terminate() const {
    if (!coop_threads_enabled_flag || !coop_threads_initialized) return false;
    auto it_main = coop_threads.find(coop_main_handle);
    if (it_main != coop_threads.end() && it_main->second.finished) {
        return true;
    }
    for (uint32_t handle : coop_order) {
        auto it = coop_threads.find(handle);
        if (it == coop_threads.end()) continue;
        if (!it->second.finished && it->second.runnable) return false;
    }
    return true;
}

uint32_t DummyAPIHandler::register_fake_api(const std::string& full_name) {
    uint32_t api_addr = 0;
    
    // Allocate Kernel32 functions inside the fake kernel32.dll .text section (0x76000000 + 0x10000)
    static uint32_t kernel32_addr = 0x76010000;
    if (full_name.find("KERNEL32.dll!") == 0) {
        api_addr = kernel32_addr;
        kernel32_addr += 16;
    } else {
        api_addr = current_addr;
        current_addr += 16;
    }

    fake_api_map[api_addr] = full_name;
    
    auto it = KNOWN_SIGNATURES.find(full_name);
    if (it != KNOWN_SIGNATURES.end() && it->second > 0) {
        int args_bytes = it->second;
        uint8_t instruction[3] = {0xC2, static_cast<uint8_t>(args_bytes & 0xFF), static_cast<uint8_t>((args_bytes >> 8) & 0xFF)};
        backend.mem_write(api_addr, instruction, 3);
    } else {
        uint8_t instruction = 0xC3; // ret
        backend.mem_write(api_addr, &instruction, 1);
    }
    
    return api_addr;
}

uint32_t DummyAPIHandler::create_fake_com_object(const std::string& class_name, int num_methods) {
    // 1. Allocate VTable space
    uint32_t vtable_addr = current_addr;
    current_addr += (num_methods * 4);
    
    // 2. Allocate Object space
    uint32_t object_addr = current_addr;
    current_addr += 32; 
    
    // Write VTable pointer to the start of the object
    backend.mem_write(object_addr, &vtable_addr, 4);
    
    // 3. Register fake APIs for each method
    for (int i = 0; i < num_methods; i++) {
        std::string method_name = "DDRAW.dll!" + class_name + "_Method_" + std::to_string(i);
        if (KNOWN_SIGNATURES.find(method_name) == KNOWN_SIGNATURES.end()) {
            if (i == 0) KNOWN_SIGNATURES[method_name] = 12;      // QueryInterface (this, riid, ppv)
            else if (i == 1) KNOWN_SIGNATURES[method_name] = 4; // AddRef (this)
            else if (i == 2) KNOWN_SIGNATURES[method_name] = 4; // Release (this)
            else KNOWN_SIGNATURES[method_name] = 0;             // Default unknown
        }
        uint32_t api_addr = register_fake_api(method_name);
        // Write the API address into the VTable at index i
        backend.mem_write(vtable_addr + (i * 4), &api_addr, 4);
    }
    
    return object_addr;
}

bool DummyAPIHandler::try_load_dylib(const std::string& api_name) {
    if (!dylib_mocks_enabled) {
        return false;
    }
    if (env_truthy("PVZ_DISABLE_DYLIB_MOCKS")) {
        return false;
    }
    if (KNOWN_SIGNATURES.find(api_name) != KNOWN_SIGNATURES.end()) {
        // Prefer native HLE for all known APIs. This keeps behavior deterministic
        // and avoids runtime drift from stale generated mocks.
        return false;
    }

    // Keep core loader APIs on native HLE path for predictable calling convention behavior.
    std::string api_lower = to_lower_ascii(api_name);
    auto is_core = [&](const char* suffix) {
        return api_lower.find(suffix) != std::string::npos;
    };
    if (is_core("!getprocaddress") ||
        is_core("!loadlibrarya") ||
        is_core("!loadlibraryw") ||
        is_core("!getmodulehandlea") ||
        is_core("!getmodulehandlew") ||
        is_core("!directdrawcreateex") ||
        is_core("!directdrawcreate") ||
        is_core("!direct3dcreate8") ||
        is_core("!directsoundcreate") ||
        is_core("!interlockedincrement") ||
        is_core("!interlockeddecrement") ||
        is_core("!interlockedexchange") ||
        is_core("!interlockedcompareexchange") ||
        is_core("!tlsalloc") ||
        is_core("!tlssetvalue") ||
        is_core("!tlsgetvalue") ||
        is_core("!flsalloc") ||
        is_core("!flssetvalue") ||
        is_core("!flsgetvalue") ||
        is_core("!flsfree")) {
        return false;
    }

    // Keep graphics COM paths on native HLE for deterministic behavior.
    if (api_lower.rfind("ddraw.dll!", 0) == 0 ||
        api_lower.rfind("dsound.dll!", 0) == 0 ||
        api_lower.rfind("d3d8.dll!", 0) == 0 ||
        is_core("!getmessagea") ||
        is_core("!getmessagew") ||
        is_core("!peekmessagea") ||
        is_core("!peekmessagew")) {
        return false;
    }

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
    if (!llm_pipeline_enabled) {
        std::string key = "unknown_fallback_seen:" + api_name;
        if (ctx.global_state.find(key) == ctx.global_state.end()) {
            ctx.global_state[key] = 1;
            std::cout << "[API CALL] [FALLBACK] Unknown API " << api_name
                      << " -> LLM disabled, returning generic success.\n";
        }
        ctx.set_eax(1);
        ctx.global_state["LastError"] = 0;
        return;
    }

    size_t excla = api_name.find('!');
    std::string func_name = (excla != std::string::npos) ? api_name.substr(excla + 1) : api_name;
    std::string module_name = (excla != std::string::npos) ? api_name.substr(0, excla) : "UNKNOWN";

    std::string request_file = "api_requests/" + func_name + ".json";
    std::string dylib_path = "api_mocks/" + func_name + ".dylib";

    if (!std::filesystem::exists(dylib_path)) {
        bool budget_ok = (max_api_llm_requests < 0) || (api_llm_requests_emitted < max_api_llm_requests);
        if (!budget_ok) {
            if (!api_budget_warned) {
                api_budget_warned = true;
                std::cout << "[*] API LLM request budget exhausted (" << max_api_llm_requests
                          << "). Unknown APIs will use generic fallback.\n";
            }
            ctx.set_eax(1);
            ctx.global_state["LastError"] = 0;
            return;
        }
        std::ofstream out(request_file);
        if (out.is_open()) {
            out << "{\n";
            out << "  \"api_name\": \"" << func_name << "\",\n";
            out << "  \"module\": \"" << module_name << "\",\n";
            out << "  \"address\": \"0x" << std::hex << address << "\"\n";
            out << "}\n";
            out.close(); // CRITICAL: Flush to disk so Python watchdog can read it!
        }
        api_llm_requests_emitted++;
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
        backend.emu_stop();
    }
}

void DummyAPIHandler::hook_api_call(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    DummyAPIHandler* handler = static_cast<DummyAPIHandler*>(user_data);

    auto it_thread_start = g_thread_start_to_handle.find(static_cast<uint32_t>(address));
    if (it_thread_start != g_thread_start_to_handle.end()) {
        uint32_t h = it_thread_start->second;
        auto it_thread = handler->ctx.handle_map.find("thread_" + std::to_string(h));
        if (it_thread != handler->ctx.handle_map.end()) {
            auto* th = static_cast<ThreadHandle*>(it_thread->second);
            if (!th->started) {
                th->started = true;
                if (thread_mock_trace_enabled()) {
                    std::cout << "[THREAD MOCK] observed execution of thread handle=0x" << std::hex << h
                              << " start=0x" << th->start_address << std::dec << "\n";
                }
            }
        }
    }
    
    auto it = handler->fake_api_map.find(address);
    if (it != handler->fake_api_map.end()) {
        const std::string& name = it->second;
        handler->api_call_total++;
        handler->api_call_counts[name]++;
        handler->maybe_print_api_stats();
        
        // --- HARDCODED HLE INTERCEPTS ---
        if (name == "USER32.dll!CreateWindowExA" || name == "USER32.dll!CreateWindowExW") {
            const bool wide = (name == "USER32.dll!CreateWindowExW");
            int width = handler->ctx.get_arg(6);
            int height = handler->ctx.get_arg(7);
            if (width > 0 && height > 0 && handler->ctx.sdl_window) {
                SDL_SetWindowSize((SDL_Window*)handler->ctx.sdl_window, width, height);
            }

            uint32_t hwnd = g_hwnd_top;
            g_hwnd_top += 4;
            if (g_hwnd_top < 0x10000u) {
                g_hwnd_top = 0x12345678u;
            }
            g_valid_hwnds.insert(hwnd);
            g_hwnd_owner_thread_id[hwnd] = handler->coop_threads_enabled()
                ? handler->coop_current_thread_id()
                : 1u;

            uint32_t class_arg = handler->ctx.get_arg(1);
            uint32_t wndproc = win32_class_wndproc_from_arg(handler->ctx, class_arg, wide);
            if (wndproc != 0) {
                g_window_long_values[win32_window_long_key(hwnd, -4)] = static_cast<int32_t>(wndproc); // GWL_WNDPROC
            }
            if (env_truthy("PVZ_WNDPROC_TRACE")) {
                std::cout << "[WNDPROC] CreateWindowEx hwnd=0x" << std::hex << hwnd
                          << " class=0x" << class_arg << " wndproc=0x" << wndproc
                          << std::dec << "\n";
            }

            uint32_t title_ptr = handler->ctx.get_arg(2);
            std::string title = wide
                ? read_guest_w_string(handler->ctx, title_ptr, 256)
                : read_guest_c_string(handler->ctx, title_ptr, 256);
            if (!title.empty()) {
                g_window_text_values[hwnd] = title;
                if (handler->ctx.sdl_window) {
                    SDL_SetWindowTitle(static_cast<SDL_Window*>(handler->ctx.sdl_window), title.c_str());
                }
            }

            handler->ctx.set_eax(hwnd);
            
            uint32_t esp;
            handler->backend.reg_read(UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            handler->backend.mem_read(esp, &ret_addr, 4);
            esp += 48 + 4; // 12 args
            handler->backend.reg_write(UC_X86_REG_ESP, &esp);
            handler->backend.reg_write(UC_X86_REG_EIP, &ret_addr);
            return;
        }

        if (name == "USER32.dll!MessageBoxA" || name == "USER32.dll!MessageBoxW") {
            uint32_t lpText = handler->ctx.get_arg(1);
            uint32_t lpCaption = handler->ctx.get_arg(2);
            uint32_t uType = handler->ctx.get_arg(3);

            const bool is_wide = (name.find("MessageBoxW") != std::string::npos);
            std::string text = is_wide
                ? read_guest_w_string(handler->ctx, lpText, 512)
                : read_guest_c_string(handler->ctx, lpText, 512);
            std::string caption = is_wide
                ? read_guest_w_string(handler->ctx, lpCaption, 128)
                : read_guest_c_string(handler->ctx, lpCaption, 128);
            if (caption.empty()) caption = "PvZ";
            if (text.empty()) text = "(empty)";

            std::cout << "\n[API CALL] [MSGBOX] " << name
                      << " caption='" << caption << "', text='" << text << "'\n";

            if (!env_truthy("PVZ_DISABLE_SDL_MESSAGEBOX")) {
                uint32_t flags = SDL_MESSAGEBOX_INFORMATION;
                if ((uType & 0x10u) != 0) flags = SDL_MESSAGEBOX_ERROR;       // MB_ICONERROR
                else if ((uType & 0x30u) == 0x30u) flags = SDL_MESSAGEBOX_WARNING; // MB_ICONWARNING
                else if ((uType & 0x40u) != 0) flags = SDL_MESSAGEBOX_INFORMATION; // MB_ICONINFORMATION

                SDL_Window* window = static_cast<SDL_Window*>(handler->ctx.sdl_window);
                if (SDL_ShowSimpleMessageBox(flags, caption.c_str(), text.c_str(), window) != 0) {
                    std::cerr << "[!] SDL_ShowSimpleMessageBox failed: " << SDL_GetError() << "\n";
                }
            }

            handler->ctx.set_eax(1); // IDOK

            uint32_t esp;
            handler->backend.reg_read(UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            handler->backend.mem_read(esp, &ret_addr, 4);
            esp += 4 + 16;
            handler->backend.reg_write(UC_X86_REG_ESP, &esp);
            handler->backend.reg_write(UC_X86_REG_EIP, &ret_addr);
            return;
        }

        if (name == "USER32.dll!RegisterClassA" || name == "USER32.dll!RegisterClassW" ||
            name == "USER32.dll!RegisterClassExA" || name == "USER32.dll!RegisterClassExW") {
            handler->ctx.set_eax(0xC000); // Dummy ATOM
            
            uint32_t esp;
            handler->backend.reg_read(UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            handler->backend.mem_read(esp, &ret_addr, 4);
            esp += 4 + 4; // 1 arg
            handler->backend.reg_write(UC_X86_REG_ESP, &esp);
            handler->backend.reg_write(UC_X86_REG_EIP, &ret_addr);
            return;
        }

        if (name == "USER32.dll!AdjustWindowRect" || name == "USER32.dll!AdjustWindowRectEx") {
            handler->ctx.set_eax(1); // Success
            
            uint32_t esp;
            handler->backend.reg_read(UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            handler->backend.mem_read(esp, &ret_addr, 4);
            esp += (name.find("Ex") != std::string::npos) ? 16 + 4 : 12 + 4; // 4 args vs 3 args
            handler->backend.reg_write(UC_X86_REG_ESP, &esp);
            handler->backend.reg_write(UC_X86_REG_EIP, &ret_addr);
            return;
        }

        if (name == "USER32.dll!GetClientRect") {
            uint32_t lpRect = handler->ctx.get_arg(1);
            if (lpRect && handler->ctx.sdl_window) {
                int w, h;
                SDL_GetWindowSize((SDL_Window*)handler->ctx.sdl_window, &w, &h);
                uint32_t rect[4] = {0, 0, (uint32_t)w, (uint32_t)h};
                handler->backend.mem_write(lpRect, rect, sizeof(rect));
            }
            handler->ctx.set_eax(1);
            
            uint32_t esp;
            handler->backend.reg_read(UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            handler->backend.mem_read(esp, &ret_addr, 4);
            esp += 8 + 4; // 2 args
            handler->backend.reg_write(UC_X86_REG_ESP, &esp);
            handler->backend.reg_write(UC_X86_REG_EIP, &ret_addr);
            return;
        }

        if (name == "USER32.dll!GetActiveWindow") {
            uint32_t hwnd = g_valid_hwnds.empty() ? 0x12345678u : *g_valid_hwnds.begin();
            handler->ctx.set_eax(hwnd);
            handler->ctx.pop_args(0);
            return;
        }

        // --- DIRECTDRAW HLE INTERCEPTS ---
        if (name == "DDRAW.dll!DirectDrawCreate" || name == "DDRAW.dll!DirectDrawCreateEx") {
            int is_ex = (name.find("Ex") != std::string::npos) ? 1 : 0;
            uint32_t lplpDD = is_ex ? handler->ctx.get_arg(1) : handler->ctx.get_arg(1);
            
            uint32_t pDD = handler->create_fake_com_object("IDirectDraw", 40);
            handler->backend.mem_write(lplpDD, &pDD, 4);
            
            handler->ctx.set_eax(0); // DD_OK
            handler->ctx.pop_args(is_ex ? 4 : 3);
            return;
        }

        if (name.find("DDRAW.dll!IDirectDraw_Method_") != std::string::npos) {
            int method_idx = std::stoi(name.substr(name.find_last_of('_') + 1));
            
            if (method_idx == 0) { // QueryInterface(this, riid, ppvObj)
                uint32_t riid = handler->ctx.get_arg(1);
                uint32_t ppvObj = handler->ctx.get_arg(2);
                uint8_t guid[16] = {0};
                if (riid != 0) handler->backend.mem_read(riid, guid, sizeof(guid));
                if (ppvObj != 0) {
                    uint32_t dummy_obj = 0;
                    if (guid[0] == 0x80) { // IID_IDirectDraw
                        dummy_obj = handler->create_fake_com_object("IDirectDraw", 50);
                    } else if (guid[0] == 0x77) { // IID_IDirect3D7
                        dummy_obj = handler->create_fake_com_object("IDirect3D7", 50);
                    } else {
                        dummy_obj = handler->create_fake_com_object("GenericCOM", 50);
                    }
                    handler->backend.mem_write(ppvObj, &dummy_obj, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(3);
                return;
            } else if (method_idx == 6) { // CreateSurface
                uint32_t lplpSurface = handler->ctx.get_arg(2);
                uint32_t pSurface = handler->create_fake_com_object("IDDSurface", 45);
                handler->backend.mem_write(lplpSurface, &pSurface, 4);
                std::cout << "[HLE DDRAW] CreateSurface Intercepted\n";
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(4);
                return;
            } else if (method_idx == 22) { // WaitForVerticalBlank
                uint32_t hEvent = handler->ctx.get_arg(2);
                if (hEvent != 0) {
                    auto it_ev = handler->ctx.handle_map.find("event_" + std::to_string(hEvent));
                    if (it_ev != handler->ctx.handle_map.end()) {
                        static_cast<EventHandle*>(it_ev->second)->signaled = true;
                    }
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(3);
                return;
            } else if (method_idx == 23) { // GetAvailableVidMem
                uint32_t total_mem_ptr = handler->ctx.get_arg(2);
                uint32_t free_mem_ptr = handler->ctx.get_arg(3);
                uint32_t bytes = 64u * 1024u * 1024u;
                if (total_mem_ptr != 0) handler->backend.mem_write(total_mem_ptr, &bytes, 4);
                if (free_mem_ptr != 0) handler->backend.mem_write(free_mem_ptr, &bytes, 4);
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(4);
                return;
            } else if (method_idx == 4) { // CreateClipper
                uint32_t lplpClipper = handler->ctx.get_arg(2);
                if (lplpClipper != 0) {
                    uint32_t pClipper = handler->create_fake_com_object("IDirectDrawClipper", 20);
                    handler->backend.mem_write(lplpClipper, &pClipper, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(4); // this, flags, outClipper, unkOuter
                return;
            } else if (method_idx == 5) { // CreatePalette
                uint32_t lplpPalette = handler->ctx.get_arg(3);
                if (lplpPalette != 0) {
                    uint32_t pPalette = handler->create_fake_com_object("IDirectDrawPalette", 20);
                    handler->backend.mem_write(lplpPalette, &pPalette, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(5); // this, flags, colorTable, outPalette, unkOuter
                return;
            } else if (method_idx == 10) { // FlipToGDISurface
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(1);
                return;
            } else if (method_idx == 15) { // GetMonitorFrequency
                uint32_t out_hz = handler->ctx.get_arg(1);
                if (out_hz != 0) {
                    uint32_t hz = 60;
                    handler->backend.mem_write(out_hz, &hz, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else if (method_idx == 20) { // SetCooperativeLevel for DD1? Actually SetCooperativeLevel is method 20 in DD1, SetDisplayMode is 21.
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(3); // HWND, flags + this
                return;
            } else if (method_idx == 21) { // SetDisplayMode
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(4); // width, height, bpp + this
                return;
            } else if (method_idx == 1 || method_idx == 2) { // AddRef, Release
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(1);
                return;
            } else {
                std::cout << "[HLE DDRAW] Unhandled IDirectDraw method " << method_idx << "\n";
                handler->ctx.set_eax(0);
                auto it = KNOWN_SIGNATURES.find(name);
                if (it != KNOWN_SIGNATURES.end() && it->second > 0) {
                    handler->ctx.pop_args(it->second / 4);
                } else {
                    // Fallback guessing it's 1 arg (THIS) if not in signatures
                    handler->ctx.pop_args(1);
                }
                return;
            }
        }

        if (name.find("DDRAW.dll!IDDSurface_Method_") != std::string::npos ||
            name.find("DDRAW.dll!IDirectDrawSurface2_Method_") != std::string::npos) {
            int method_idx = std::stoi(name.substr(name.find_last_of('_') + 1));
            
            if (method_idx == 0) { // QueryInterface(this, riid, ppvObj)
                uint32_t riid = handler->ctx.get_arg(1);
                uint32_t ppvObj = handler->ctx.get_arg(2);
                uint8_t guid[16] = {0};
                if (riid != 0) handler->backend.mem_read(riid, guid, sizeof(guid));
                if (ppvObj != 0) {
                    uint32_t dummy_obj = 0;
                    if (guid[0] == 0x81) { // IID_IDirectDrawSurface2
                        dummy_obj = handler->create_fake_com_object("IDirectDrawSurface2", 50);
                    } else {
                        dummy_obj = handler->create_fake_com_object("IDDSurface", 45);
                    }
                    handler->backend.mem_write(ppvObj, &dummy_obj, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(3);
                return;
            } else if (method_idx == 25 || method_idx == 20) { // Lock
                uint32_t lpDDSurfaceDesc = handler->ctx.get_arg(2);
                if (lpDDSurfaceDesc != 0) {
                    uint32_t ddsd_size = 124;
                    uint32_t ddsd_flags = 0x100F; // CAPS|HEIGHT|WIDTH|PITCH|PIXELFORMAT
                    uint32_t height = 600;
                    uint32_t width = 800;
                    uint32_t pitch = 800 * 4;
                    uint32_t pf_size = 32;
                    uint32_t pf_flags = 0x40; // DDPF_RGB
                    uint32_t bpp = 32;
                    uint32_t r_mask = 0x00FF0000;
                    uint32_t g_mask = 0x0000FF00;
                    uint32_t b_mask = 0x000000FF;
                    uint32_t a_mask = 0x00000000;
                    handler->backend.mem_write(lpDDSurfaceDesc + 0, &ddsd_size, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 4, &ddsd_flags, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 8, &height, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 12, &width, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 16, &pitch, 4); 
                    handler->backend.mem_write(lpDDSurfaceDesc + 36, &handler->ctx.guest_vram, 4);
                    // DDPIXELFORMAT at +72
                    handler->backend.mem_write(lpDDSurfaceDesc + 72, &pf_size, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 76, &pf_flags, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 84, &bpp, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 88, &r_mask, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 92, &g_mask, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 96, &b_mask, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 100, &a_mask, 4);
                }
                std::cout << "[HLE DDRAW] Surface Lock Intercepted\n";
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(5); 
                return;
            } else if (method_idx == 32 || method_idx == 26) { // Unlock
                if (handler->ctx.sdl_texture && handler->ctx.sdl_renderer && handler->ctx.host_vram) {
                    handler->backend.mem_read(handler->ctx.guest_vram, handler->ctx.host_vram, 800 * 600 * 4);
                    
                    SDL_UpdateTexture((SDL_Texture*)handler->ctx.sdl_texture, NULL, handler->ctx.host_vram, 800 * 4);
                    SDL_RenderClear((SDL_Renderer*)handler->ctx.sdl_renderer);
                    SDL_RenderCopy((SDL_Renderer*)handler->ctx.sdl_renderer, (SDL_Texture*)handler->ctx.sdl_texture, NULL, NULL);
                    SDL_RenderPresent((SDL_Renderer*)handler->ctx.sdl_renderer);
                }
                std::cout << "[HLE DDRAW] Surface Unlock (Present) Intercepted\n";
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2); 
                return;
            } else if (method_idx == 1 || method_idx == 2) { // AddRef, Release
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(1);
                return;
            } else if (method_idx == 22 || method_idx == 17) { // GetSurfaceDesc
                uint32_t lpDDSurfaceDesc = handler->ctx.get_arg(1);
                if (lpDDSurfaceDesc != 0) {
                    uint32_t ddsd_size = 124;
                    uint32_t ddsd_flags = 0x100F; // CAPS|HEIGHT|WIDTH|PITCH|PIXELFORMAT
                    uint32_t height = 600;
                    uint32_t width = 800;
                    uint32_t pitch = 800 * 4;
                    uint32_t pf_size = 32;
                    uint32_t pf_flags = 0x40; // DDPF_RGB
                    uint32_t bpp = 32;
                    uint32_t r_mask = 0x00FF0000;
                    uint32_t g_mask = 0x0000FF00;
                    uint32_t b_mask = 0x000000FF;
                    uint32_t a_mask = 0x00000000;
                    handler->backend.mem_write(lpDDSurfaceDesc + 0, &ddsd_size, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 4, &ddsd_flags, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 8, &height, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 12, &width, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 16, &pitch, 4); 
                    handler->backend.mem_write(lpDDSurfaceDesc + 36, &handler->ctx.guest_vram, 4);
                    // DDPIXELFORMAT at +72
                    handler->backend.mem_write(lpDDSurfaceDesc + 72, &pf_size, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 76, &pf_flags, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 84, &bpp, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 88, &r_mask, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 92, &g_mask, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 96, &b_mask, 4);
                    handler->backend.mem_write(lpDDSurfaceDesc + 100, &a_mask, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else if (method_idx == 12) { // GetAttachedSurface
                uint32_t pSurfaceOut = handler->ctx.get_arg(2);
                if (pSurfaceOut != 0) {
                    uint32_t this_surface = handler->ctx.get_arg(0);
                    // Return self as a stable attached surface for now.
                    handler->backend.mem_write(pSurfaceOut, &this_surface, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(3);
                return;
            } else if (method_idx == 21) { // GetPixelFormat
                uint32_t lpPixelFormat = handler->ctx.get_arg(1);
                if (lpPixelFormat != 0) {
                    uint32_t pf_size = 32;
                    uint32_t pf_flags = 0x40; // DDPF_RGB
                    uint32_t bpp = 32;
                    uint32_t r_mask = 0x00FF0000;
                    uint32_t g_mask = 0x0000FF00;
                    uint32_t b_mask = 0x000000FF;
                    uint32_t a_mask = 0x00000000;
                    handler->backend.mem_write(lpPixelFormat + 0, &pf_size, 4);
                    handler->backend.mem_write(lpPixelFormat + 4, &pf_flags, 4);
                    handler->backend.mem_write(lpPixelFormat + 12, &bpp, 4);
                    handler->backend.mem_write(lpPixelFormat + 16, &r_mask, 4);
                    handler->backend.mem_write(lpPixelFormat + 20, &g_mask, 4);
                    handler->backend.mem_write(lpPixelFormat + 24, &b_mask, 4);
                    handler->backend.mem_write(lpPixelFormat + 28, &a_mask, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else if (method_idx == 28 || method_idx == 31) { // SetClipper / SetPalette
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else {
                std::cout << "[HLE DDRAW] Unhandled IDDSurface method " << method_idx << "\n";
                handler->ctx.set_eax(0);
                auto it = KNOWN_SIGNATURES.find(name);
                if (it != KNOWN_SIGNATURES.end() && it->second > 0) {
                    handler->ctx.pop_args(it->second / 4);
                } else {
                    handler->ctx.pop_args(1);
                }
                return;
            }
        }

        if (name.find("DDRAW.dll!IDirectDrawClipper_Method_") != std::string::npos) {
            int method_idx = std::stoi(name.substr(name.find_last_of('_') + 1));
            if (method_idx == 1 || method_idx == 2) { // AddRef / Release
                handler->ctx.set_eax(1);
                handler->ctx.pop_args(1);
                return;
            } else if (method_idx == 4) { // GetHWnd
                uint32_t out_hwnd = handler->ctx.get_arg(1);
                if (out_hwnd != 0) {
                    uint32_t hwnd = 0x12345678;
                    handler->backend.mem_write(out_hwnd, &hwnd, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else if (method_idx == 8) { // SetHWnd
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(3);
                return;
            } else {
                std::cout << "[HLE DDRAW] Unhandled IDirectDrawClipper method " << method_idx << "\n";
                handler->ctx.set_eax(0);
                auto it = KNOWN_SIGNATURES.find(name);
                if (it != KNOWN_SIGNATURES.end() && it->second > 0) {
                    handler->ctx.pop_args(it->second / 4);
                } else {
                    handler->ctx.pop_args(1);
                }
                return;
            }
        }

        if (name.find("DDRAW.dll!IDirectSound_Method_") != std::string::npos) {
            int method_idx = std::stoi(name.substr(name.find_last_of('_') + 1));
            if (method_idx == 1 || method_idx == 2) { // AddRef / Release
                handler->ctx.set_eax(1);
                handler->ctx.pop_args(1);
                return;
            } else if (method_idx == 6) { // SetCooperativeLevel
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(3);
                return;
            } else if (method_idx == 3) { // CreateSoundBuffer
                uint32_t out_ds_buffer = handler->ctx.get_arg(2);
                if (out_ds_buffer != 0) {
                    uint32_t ds_buf = handler->create_fake_com_object("IDirectSoundBuffer", 40);
                    handler->backend.mem_write(out_ds_buffer, &ds_buf, 4);
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(4);
                return;
            } else {
                std::cout << "[HLE DSOUND] Unhandled IDirectSound method " << method_idx << "\n";
                handler->ctx.set_eax(0);
                auto it = KNOWN_SIGNATURES.find(name);
                if (it != KNOWN_SIGNATURES.end() && it->second > 0) {
                    handler->ctx.pop_args(it->second / 4);
                } else {
                    handler->ctx.pop_args(1);
                }
                return;
            }
        }

        if (name.find("DDRAW.dll!IDirectSoundBuffer_Method_") != std::string::npos) {
            int method_idx = std::stoi(name.substr(name.find_last_of('_') + 1));
            if (method_idx == 1 || method_idx == 2) { // AddRef / Release
                handler->ctx.set_eax(1);
                handler->ctx.pop_args(1);
                return;
            } else if (method_idx == 3) { // GetCaps
                uint32_t lpCaps = handler->ctx.get_arg(1);
                if (lpCaps != 0) {
                    uint32_t size = 0;
                    handler->backend.mem_read(lpCaps, &size, 4);
                    if (size >= 8) {
                        uint32_t flags = 0;
                        handler->backend.mem_write(lpCaps + 4, &flags, 4);
                    }
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else if (method_idx == 4) { // GetCurrentPosition
                uint32_t pPlay = handler->ctx.get_arg(1);
                uint32_t pWrite = handler->ctx.get_arg(2);
                uint32_t zero = 0;
                if (pPlay) handler->backend.mem_write(pPlay, &zero, 4);
                if (pWrite) handler->backend.mem_write(pWrite, &zero, 4);
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(3);
                return;
            } else if (method_idx == 9) { // GetStatus
                uint32_t pStatus = handler->ctx.get_arg(1);
                uint32_t status = 0;
                if (pStatus) handler->backend.mem_write(pStatus, &status, 4);
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else if (method_idx == 11) { // Lock
                uint32_t write_cursor = handler->ctx.get_arg(1);
                uint32_t write_bytes = handler->ctx.get_arg(2);
                uint32_t ppv1 = handler->ctx.get_arg(3);
                uint32_t pbytes1 = handler->ctx.get_arg(4);
                uint32_t ppv2 = handler->ctx.get_arg(5);
                uint32_t pbytes2 = handler->ctx.get_arg(6);
                if (handler->ctx.global_state.find("DirectSoundHeap") == handler->ctx.global_state.end()) {
                    handler->ctx.global_state["DirectSoundHeap"] = 0x34000000;
                    handler->backend.mem_map(0x34000000, 0x01000000, UC_PROT_ALL);
                }
                uint32_t base = static_cast<uint32_t>(handler->ctx.global_state["DirectSoundHeap"]);
                uint32_t ptr1 = base + (write_cursor & 0xFFFFF);
                uint32_t bytes1 = write_bytes;
                uint32_t ptr2 = 0;
                uint32_t bytes2 = 0;
                if (ppv1) handler->backend.mem_write(ppv1, &ptr1, 4);
                if (pbytes1) handler->backend.mem_write(pbytes1, &bytes1, 4);
                if (ppv2) handler->backend.mem_write(ppv2, &ptr2, 4);
                if (pbytes2) handler->backend.mem_write(pbytes2, &bytes2, 4);
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(8);
                return;
            } else if (method_idx == 12) { // Play
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(4);
                return;
            } else if (method_idx == 13) { // SetCurrentPosition
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else if (method_idx == 14 || method_idx == 15 ||
                       method_idx == 16 || method_idx == 17) { // SetFormat/SetVolume/SetPan/SetFrequency
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else if (method_idx == 18) { // Stop
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(1);
                return;
            } else if (method_idx == 19) { // Unlock
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(5);
                return;
            } else {
                std::cout << "[HLE DSOUND] Unhandled IDirectSoundBuffer method " << method_idx << "\n";
                handler->ctx.set_eax(0);
                auto it = KNOWN_SIGNATURES.find(name);
                if (it != KNOWN_SIGNATURES.end() && it->second > 0) {
                    handler->ctx.pop_args(it->second / 4);
                } else {
                    handler->ctx.pop_args(1);
                }
                return;
            }
        }

        if (name == "USER32.dll!GetMessageA" || name == "USER32.dll!PeekMessageA" || 
            name == "USER32.dll!GetMessageW" || name == "USER32.dll!PeekMessageW") {
            
            bool is_peek = (name.find("PeekMessage") != std::string::npos);
            static const bool verbose_msg_pump = env_truthy("PVZ_VERBOSE_MSG_PUMP");
            static const uint64_t msg_stats_interval = static_cast<uint64_t>(std::max(0, env_int("PVZ_MSG_STATS_INTERVAL", 0)));
            static std::unordered_map<uint32_t, uint64_t> msg_counts;
            static uint64_t msg_total = 0;
            auto record_msg = [&](uint32_t message_id) {
                if (msg_stats_interval == 0) return;
                msg_total++;
                msg_counts[message_id]++;
                if ((msg_total % msg_stats_interval) != 0) return;
                std::vector<std::pair<uint32_t, uint64_t>> items(msg_counts.begin(), msg_counts.end());
                std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
                std::cout << "[MSG STATS] total=" << msg_total << " top:";
                size_t limit = std::min<size_t>(8, items.size());
                for (size_t i = 0; i < limit; ++i) {
                    std::cout << " [0x" << std::hex << items[i].first << std::dec << ":" << items[i].second << "]";
                }
                std::cout << "\n";
            };
            if (verbose_msg_pump) {
                std::cout << "\n[API CALL] [HLE] Intercepted " << name << std::endl;
            }
            
            uint32_t lpMsg = handler->ctx.get_arg(0);
            uint32_t hWnd = handler->ctx.get_arg(1);
            uint32_t wMsgFilterMin = handler->ctx.get_arg(2);
            uint32_t wMsgFilterMax = handler->ctx.get_arg(3);
            uint32_t remove_flag = is_peek ? handler->ctx.get_arg(4) : 1;
            uint32_t current_tid = handler->coop_threads_enabled()
                ? handler->coop_current_thread_id()
                : 1u;
            
            SDL_Event event;
            bool has_event = false;
            bool from_queue = false;
            Win32_MSG msg = {0};
            SDL_PumpEvents();
            pump_due_win32_timers(SDL_GetTicks());

            for (auto it = g_win32_message_queue.begin(); it != g_win32_message_queue.end(); ++it) {
                if (!win32_message_matches_filter(*it, current_tid, hWnd, wMsgFilterMin, wMsgFilterMax)) {
                    continue;
                }
                msg = it->msg;
                if (!is_peek || (remove_flag & 0x0001u) != 0) {
                    g_win32_message_queue.erase(it);
                }
                has_event = true;
                from_queue = true;
                break;
            }
            
            if (!has_event && is_peek) {
                has_event = SDL_PollEvent(&event);
            } else if (!has_event) {
                // GetMessage blocks until an event is available
                // Use WaitEventTimeout to not freeze the whole JIT loop indefinitely
                has_event = SDL_WaitEventTimeout(&event, 50); 
                if (!has_event) {
                    pump_due_win32_timers(SDL_GetTicks());
                    for (auto it = g_win32_message_queue.begin(); it != g_win32_message_queue.end(); ++it) {
                        if (!win32_message_matches_filter(*it, current_tid, hWnd, wMsgFilterMin, wMsgFilterMax)) {
                            continue;
                        }
                        msg = it->msg;
                        g_win32_message_queue.erase(it);
                        has_event = true;
                        from_queue = true;
                        break;
                    }
                }
            }

            if (!has_event && !is_peek && g_win32_timers.empty() && !g_valid_hwnds.empty()) {
                uint32_t now_ms = SDL_GetTicks();
                if (g_synth_idle_timer_next_ms == 0 || static_cast<int32_t>(now_ms - g_synth_idle_timer_next_ms) >= 0) {
                    uint32_t hwnd = *g_valid_hwnds.begin();
                    enqueue_timer_message(hwnd, 1, now_ms);
                    g_synth_idle_timer_next_ms = now_ms + 16;
                    for (auto it = g_win32_message_queue.begin(); it != g_win32_message_queue.end(); ++it) {
                        if (!win32_message_matches_filter(*it, current_tid, hWnd, wMsgFilterMin, wMsgFilterMax)) {
                            continue;
                        }
                        msg = it->msg;
                        g_win32_message_queue.erase(it);
                        has_event = true;
                        from_queue = true;
                        break;
                    }
                }
            }

            if (has_event) {
                if (!from_queue) {
                    msg.hwnd = hWnd;
                    msg.time = SDL_GetTicks();
                    int mx, my;
                    SDL_GetMouseState(&mx, &my);
                    msg.pt_x = mx;
                    msg.pt_y = my;

                    if (event.type == SDL_QUIT) {
                        msg.message = WM_QUIT;
                        msg.wParam = 0;
                    } else if (event.type == SDL_MOUSEMOTION) {
                        msg.message = WM_MOUSEMOVE;
                        msg.lParam = (event.motion.y << 16) | (event.motion.x & 0xFFFF);
                    } else if (event.type == SDL_MOUSEBUTTONDOWN) {
                        if (event.button.button == SDL_BUTTON_LEFT) msg.message = WM_LBUTTONDOWN;
                        else if (event.button.button == SDL_BUTTON_RIGHT) msg.message = WM_RBUTTONDOWN;
                        msg.lParam = (event.button.y << 16) | (event.button.x & 0xFFFF);
                    } else if (event.type == SDL_MOUSEBUTTONUP) {
                        if (event.button.button == SDL_BUTTON_LEFT) msg.message = WM_LBUTTONUP;
                        else if (event.button.button == SDL_BUTTON_RIGHT) msg.message = WM_RBUTTONUP;
                        msg.lParam = (event.button.y << 16) | (event.button.x & 0xFFFF);
                    } else if (event.type == SDL_KEYDOWN) {
                        msg.message = WM_KEYDOWN;
                        msg.wParam = event.key.keysym.sym;
                    } else if (event.type == SDL_KEYUP) {
                        msg.message = WM_KEYUP;
                        msg.wParam = event.key.keysym.sym;
                    } else {
                        msg.message = WM_NULL;
                    }
                    if (!win32_message_matches_filter(msg, hWnd, wMsgFilterMin, wMsgFilterMax)) {
                        has_event = false;
                    }
                }

                handler->backend.mem_write(lpMsg, &msg, sizeof(msg));
                record_msg(msg.message);
                if (is_peek) {
                    handler->ctx.set_eax(1);
                } else {
                    handler->ctx.set_eax(msg.message != WM_QUIT ? 1 : 0);
                }
            } else {
                if (is_peek) {
                    handler->ctx.set_eax(0);
                } else {
                    // Win32 GetMessage should block; avoid returning 0 (WM_QUIT) on idle.
                    if (handler->coop_threads_enabled()) {
                        handler->coop_request_yield();
                    }
                    Win32_MSG msg = {0};
                    msg.hwnd = hWnd;
                    msg.message = WM_NULL;
                    msg.time = SDL_GetTicks();
                    int mx, my;
                    SDL_GetMouseState(&mx, &my);
                    msg.pt_x = mx;
                    msg.pt_y = my;
                    handler->backend.mem_write(lpMsg, &msg, sizeof(msg));
                    record_msg(msg.message);
                    handler->ctx.set_eax(1);
                }
            }

            // Clean up stack and return manually (stdcall)
            uint32_t esp;
            handler->backend.reg_read(UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            handler->backend.mem_read(esp, &ret_addr, 4);
            esp += (is_peek ? 24 : 20); // Peek arguments: 5 (20 bytes), Get arguments: 4 (16 bytes) + 4 for ret
            handler->backend.reg_write(UC_X86_REG_ESP, &esp);
            handler->backend.reg_write(UC_X86_REG_EIP, &ret_addr);
            return;
        }

        bool known = (KNOWN_SIGNATURES.find(name) != KNOWN_SIGNATURES.end());
        if (name.find("GetProcAddress") != std::string::npos) known = true;
        static const bool verbose_api_hook = env_truthy("PVZ_VERBOSE_API_HOOK");
        if (verbose_api_hook && !is_noisy_fastpath_api(name)) {
            std::cout << "\n[DEBUG] hook_api_call name='" << name << "', known=" << known << "\n";
        }

        uint32_t ret_addr = handler->get_api_caller_ret_addr();
        handler->maybe_sample_eip_hot_caller(ret_addr);
        handler->dispatch_known_or_unknown_api(name, address, known);
        handler->record_hot_loop_api_stat(ret_addr, name);
    }
}

void DummyAPIHandler::dispatch_known_or_unknown_api(const std::string& name, uint64_t address, bool known) {
    DummyAPIHandler* handler = this;
#include "api_handler_known_dispatch.inl"
}

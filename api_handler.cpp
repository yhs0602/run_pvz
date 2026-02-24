#include "api_handler.hpp"
#include <fstream>
#include <filesystem>
#include <dlfcn.h>
#include <unistd.h>
#include <SDL.h>
#include <algorithm>
#include <vector>
#include <iterator>
#include <deque>
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

struct HostFileHandle {
    std::vector<uint8_t> data;
    size_t pos = 0;
};

struct EventHandle {
    bool manual_reset = false;
    bool signaled = false;
};

struct MappingHandle {
    uint32_t file_handle = 0xFFFFFFFFu; // INVALID_HANDLE_VALUE means page-file backed mapping
};

struct RegistryKeyHandle {
    std::string path;
};

static std::unordered_map<std::string, std::vector<uint8_t>> g_registry_values;
static std::unordered_map<std::string, uint32_t> g_registry_types;
static std::unordered_map<uint32_t, uint32_t> g_heap_sizes;
static std::unordered_map<uint32_t, uint32_t> g_resource_ptr_by_handle;
static std::unordered_map<uint32_t, uint32_t> g_resource_size_by_handle;
static uint32_t g_resource_handle_top = 0xB000;
static uint32_t g_resource_heap_top = 0x36000000;
static bool g_resource_heap_mapped = false;
static std::deque<Win32_MSG> g_win32_message_queue;

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

static std::string to_lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static bool starts_with_ascii_ci(const std::string& s, const char* prefix_lower) {
    std::string lower = to_lower_ascii(s);
    return lower.rfind(prefix_lower, 0) == 0;
}

static bool env_truthy(const char* name) {
    const char* v = std::getenv(name);
    if (!v) return false;
    std::string s = to_lower_ascii(v);
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
    {"USER32.dll!SetCursorPos", 8},
    {"USER32.dll!ShowCursor", 4},
    {"USER32.dll!TranslateMessage", 4},
    {"USER32.dll!DispatchMessageA", 4},
    {"USER32.dll!DispatchMessageW", 4},
    {"USER32.dll!PostMessageA", 16},
    {"USER32.dll!PostMessageW", 16},
    {"USER32.dll!SendMessageA", 16},
    {"USER32.dll!SendMessageW", 16},
    {"USER32.dll!RegisterWindowMessageA", 4},
    {"USER32.dll!SystemParametersInfoA", 16},
    {"USER32.dll!GetSystemMetrics", 4},
    {"USER32.dll!LoadCursorA", 8},
    {"USER32.dll!CreateCursor", 28},
    {"USER32.dll!SetCursor", 4},
    {"USER32.dll!LoadIconA", 8},
    {"USER32.dll!RegisterClassA", 4},
    {"USER32.dll!RegisterClassExA", 4},
    {"USER32.dll!GetAsyncKeyState", 4},
    {"USER32.dll!MessageBoxA", 16},
    {"USER32.dll!SetWindowLongA", 12},
    {"USER32.dll!GetWindowLongA", 8},
    {"USER32.dll!SetWindowTextA", 8},
    {"USER32.dll!GetWindowTextA", 12},
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
    {"DDRAW.dll!IDirectDraw_Method_4", 16}, // CreateClipper(this, flags, outClipper, unkOuter)
    {"DDRAW.dll!IDirectDraw_Method_5", 20}, // CreatePalette(this, flags, colorTable, outPalette, unkOuter)
    {"DDRAW.dll!IDirectDraw_Method_15", 8}, // GetMonitorFrequency(this, outHz)
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

DummyAPIHandler::~DummyAPIHandler() {
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
    
    auto it = handler->fake_api_map.find(address);
    if (it != handler->fake_api_map.end()) {
        const std::string& name = it->second;
        handler->api_call_total++;
        handler->api_call_counts[name]++;
        handler->maybe_print_api_stats();
        
        // --- HARDCODED HLE INTERCEPTS ---
        if (name == "USER32.dll!CreateWindowExA" || name == "USER32.dll!CreateWindowExW") {
            int width = handler->ctx.get_arg(6);
            int height = handler->ctx.get_arg(7);
            if (width > 0 && height > 0 && handler->ctx.sdl_window) {
                SDL_SetWindowSize((SDL_Window*)handler->ctx.sdl_window, width, height);
            }
            handler->ctx.set_eax(0x12345678); // Dummy HWND
            
            uint32_t esp;
            handler->backend.reg_read(UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            handler->backend.mem_read(esp, &ret_addr, 4);
            esp += 48 + 4; // 12 args
            handler->backend.reg_write(UC_X86_REG_ESP, &esp);
            handler->backend.reg_write(UC_X86_REG_EIP, &ret_addr);
            return;
        }

        if (name == "USER32.dll!MessageBoxA") {
            uint32_t lpText = handler->ctx.get_arg(1);
            uint32_t lpCaption = handler->ctx.get_arg(2);
            char text[256] = {0};
            char caption[256] = {0};
            if (lpText) handler->backend.mem_read(lpText, text, 255);
            if (lpCaption) handler->backend.mem_read(lpCaption, caption, 255);
            std::cout << "\n[API CALL] [ERROR BOX] MessageBoxA: caption='" << caption << "', text='" << text << "'\n";
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
            handler->ctx.set_eax(0x12345678); // Dummy HWND
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
            
            if (method_idx == 6 || method_idx == 22) { // CreateSurface
                uint32_t lplpSurface = handler->ctx.get_arg(2);
                uint32_t pSurface = handler->create_fake_com_object("IDDSurface", 45);
                handler->backend.mem_write(lplpSurface, &pSurface, 4);
                std::cout << "[HLE DDRAW] CreateSurface Intercepted\n";
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
            
            if (method_idx == 25 || method_idx == 20) { // Lock
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
            std::cout << "\n[API CALL] [HLE] Intercepted " << name << std::endl;
            
            uint32_t lpMsg = handler->ctx.get_arg(0);
            uint32_t hWnd = handler->ctx.get_arg(1);
            uint32_t remove_flag = is_peek ? handler->ctx.get_arg(4) : 1;
            
            SDL_Event event;
            bool has_event = false;
            bool from_queue = false;
            Win32_MSG msg = {0};
            SDL_PumpEvents();

            if (!g_win32_message_queue.empty()) {
                msg = g_win32_message_queue.front();
                if (!is_peek || (remove_flag & 0x0001u) != 0) {
                    g_win32_message_queue.pop_front();
                }
                has_event = true;
                from_queue = true;
            }
            
            if (!has_event && is_peek) {
                has_event = SDL_PollEvent(&event);
            } else if (!has_event) {
                // GetMessage blocks until an event is available
                // Use WaitEventTimeout to not freeze the whole JIT loop indefinitely
                has_event = SDL_WaitEventTimeout(&event, 50); 
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
                }

                handler->backend.mem_write(lpMsg, &msg, sizeof(msg));
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
                    Win32_MSG msg = {0};
                    msg.hwnd = hWnd;
                    msg.message = WM_NULL;
                    msg.time = SDL_GetTicks();
                    int mx, my;
                    SDL_GetMouseState(&mx, &my);
                    msg.pt_x = mx;
                    msg.pt_y = my;
                    handler->backend.mem_write(lpMsg, &msg, sizeof(msg));
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

        auto is_noisy_fastpath_api = [&](const std::string& n) {
            return n == "KERNEL32.dll!EnterCriticalSection" ||
                   n == "KERNEL32.dll!LeaveCriticalSection" ||
                   n == "KERNEL32.dll!InitializeCriticalSection" ||
                   n == "KERNEL32.dll!InitializeCriticalSectionAndSpinCount" ||
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
                   n == "KERNEL32.dll!InterlockedIncrement" ||
                   n == "KERNEL32.dll!InterlockedDecrement" ||
                   n == "KERNEL32.dll!InterlockedExchange" ||
                   n == "KERNEL32.dll!InterlockedCompareExchange";
        };

        bool known = (KNOWN_SIGNATURES.find(name) != KNOWN_SIGNATURES.end());
        if (name.find("GetProcAddress") != std::string::npos) known = true;
        if (!is_noisy_fastpath_api(name)) {
            std::cout << "\n[DEBUG] hook_api_call name='" << name << "', known=" << known << "\n";
        }
        
        if (handler->try_load_dylib(name)) {
            std::cout << "\n[API CALL] [JIT MOCK] Redirecting to " << name << std::endl;
            handler->dylib_funcs[name](&handler->ctx);
        } else if (known) {
            if (name == "KERNEL32.dll!GetLastError") {
                uint32_t last_error = handler->ctx.global_state["LastError"];
                handler->ctx.set_eax(last_error);
                std::cout << "\n[API CALL] [OK] GetLastError -> " << last_error << std::endl;
            } else if (name == "KERNEL32.dll!SetLastError") {
                uint32_t err_code = handler->ctx.get_arg(0);
                handler->ctx.global_state["LastError"] = err_code;
                std::cout << "\n[API CALL] [OK] SetLastError(" << err_code << ")" << std::endl;
            } else if (name == "KERNEL32.dll!GetVersionExA") {
                uint32_t lpVersionInformation = handler->ctx.get_arg(0);
                if (lpVersionInformation) {
                    uint32_t size;
                    handler->backend.mem_read(lpVersionInformation, &size, 4);
                    if (size >= 20) { // OSVERSIONINFOA is 148 bytes
                        uint32_t major = 6;  // Windows 7 / Vista
                        uint32_t minor = 1;
                        uint32_t build = 7601;
                        uint32_t platformId = 2; // VER_PLATFORM_WIN32_NT
                        handler->backend.mem_write(lpVersionInformation + 4, &major, 4);
                        handler->backend.mem_write(lpVersionInformation + 8, &minor, 4);
                        handler->backend.mem_write(lpVersionInformation + 12, &build, 4);
                        handler->backend.mem_write(lpVersionInformation + 16, &platformId, 4);
                    }
                }
                handler->ctx.set_eax(1);
                std::cout << "\n[API CALL] [OK] GetVersionExA (Spoofed Win7)" << std::endl;
            } else if (name == "KERNEL32.dll!GetSystemDirectoryA" || name == "KERNEL32.dll!GetWindowsDirectoryA") {
                uint32_t lpBuffer = handler->ctx.get_arg(0);
                uint32_t uSize = handler->ctx.get_arg(1);
                const char* value = (name == "KERNEL32.dll!GetSystemDirectoryA")
                    ? "C:\\Windows\\System32"
                    : "C:\\Windows";
                uint32_t len = static_cast<uint32_t>(std::strlen(value));
                if (lpBuffer != 0 && uSize > 0) {
                    uint32_t to_copy = std::min<uint32_t>(len, uSize - 1);
                    handler->backend.mem_write(lpBuffer, value, to_copy);
                    char nul = '\0';
                    handler->backend.mem_write(lpBuffer + to_copy, &nul, 1);
                }
                handler->ctx.set_eax(len);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!GetSystemDirectoryW" || name == "KERNEL32.dll!GetWindowsDirectoryW") {
                uint32_t lpBuffer = handler->ctx.get_arg(0);
                uint32_t uSize = handler->ctx.get_arg(1); // WCHAR count
                const char* ascii = (name == "KERNEL32.dll!GetSystemDirectoryW")
                    ? "C:\\Windows\\System32"
                    : "C:\\Windows";
                std::u16string wide;
                for (const char* p = ascii; *p; ++p) wide.push_back(static_cast<char16_t>(*p));
                uint32_t len = static_cast<uint32_t>(wide.size());
                if (lpBuffer != 0 && uSize > 0) {
                    uint32_t to_copy = std::min<uint32_t>(len, uSize - 1);
                    handler->backend.mem_write(lpBuffer, wide.data(), to_copy * 2);
                    uint16_t nul = 0;
                    handler->backend.mem_write(lpBuffer + to_copy * 2, &nul, 2);
                }
                handler->ctx.set_eax(len);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!GetCurrentDirectoryA") {
                uint32_t nBufferLength = handler->ctx.get_arg(0);
                uint32_t lpBuffer = handler->ctx.get_arg(1);
                std::string cwd = handler->process_base_dir.empty()
                    ? std::filesystem::current_path().string()
                    : handler->process_base_dir;
                if (cwd.rfind("/", 0) == 0) cwd = "C:" + cwd;
                cwd = normalize_win_path(cwd);
                uint32_t len = static_cast<uint32_t>(cwd.size());
                if (lpBuffer != 0 && nBufferLength > 0) {
                    uint32_t to_copy = std::min<uint32_t>(len, nBufferLength - 1);
                    handler->backend.mem_write(lpBuffer, cwd.data(), to_copy);
                    char nul = '\0';
                    handler->backend.mem_write(lpBuffer + to_copy, &nul, 1);
                }
                handler->ctx.set_eax(len);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!GetFullPathNameA") {
                uint32_t lpFileName = handler->ctx.get_arg(0);
                uint32_t nBufferLength = handler->ctx.get_arg(1);
                uint32_t lpBuffer = handler->ctx.get_arg(2);
                uint32_t lpFilePartPtr = handler->ctx.get_arg(3);

                std::string in = read_guest_c_string(handler->ctx, lpFileName, 1024);
                std::string cwd = handler->process_base_dir.empty()
                    ? std::filesystem::current_path().string()
                    : handler->process_base_dir;
                if (cwd.rfind("/", 0) == 0) cwd = "C:" + cwd;
                cwd = normalize_win_path(cwd);

                std::string full;
                if (in.empty()) {
                    full = cwd;
                } else {
                    std::replace(in.begin(), in.end(), '/', '\\');
                    bool absolute = (in.size() >= 2 && in[1] == ':');
                    if (absolute) {
                        full = normalize_win_path(in);
                    } else {
                        std::string joined = cwd;
                        if (!joined.empty() && joined.back() != '\\') joined += "\\";
                        joined += in;
                        full = normalize_win_path(joined);
                    }
                }

                uint32_t len = static_cast<uint32_t>(full.size());
                if (lpBuffer != 0 && nBufferLength > 0) {
                    uint32_t to_copy = std::min<uint32_t>(len, nBufferLength - 1);
                    handler->backend.mem_write(lpBuffer, full.data(), to_copy);
                    char nul = '\0';
                    handler->backend.mem_write(lpBuffer + to_copy, &nul, 1);

                    if (lpFilePartPtr != 0) {
                        size_t slash = full.find_last_of('\\');
                        uint32_t file_part = (slash == std::string::npos)
                            ? lpBuffer
                            : (lpBuffer + static_cast<uint32_t>(slash + 1));
                        handler->backend.mem_write(lpFilePartPtr, &file_part, 4);
                    }
                }
                handler->ctx.set_eax(len);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!GetFileAttributesA") {
                uint32_t lpFileName = handler->ctx.get_arg(0);
                std::string guest_path = read_guest_c_string(handler->ctx, lpFileName, 1024);
                std::string host_path = resolve_guest_path_to_host(guest_path, handler->process_base_dir);
                if (host_path.empty()) {
                    handler->ctx.set_eax(0xFFFFFFFFu); // INVALID_FILE_ATTRIBUTES
                    handler->ctx.global_state["LastError"] = 2; // ERROR_FILE_NOT_FOUND
                } else {
                    std::error_code ec;
                    bool is_dir = std::filesystem::is_directory(host_path, ec);
                    uint32_t attrs = is_dir ? 0x10u : 0x80u; // DIRECTORY or NORMAL
                    handler->ctx.set_eax(attrs);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "ADVAPI32.dll!RegOpenKeyExA") {
                uint32_t hKey = handler->ctx.get_arg(0);
                uint32_t lpSubKey = handler->ctx.get_arg(1);
                uint32_t phkResult = handler->ctx.get_arg(4);
                std::string base = resolve_registry_path(handler->ctx, hKey);
                std::string sub = read_guest_c_string(handler->ctx, lpSubKey, 512);
                std::replace(sub.begin(), sub.end(), '/', '\\');
                if (!base.empty() && !sub.empty()) base += "\\" + sub;
                if (base.empty()) {
                    handler->ctx.set_eax(6); // ERROR_INVALID_HANDLE
                    handler->ctx.global_state["LastError"] = 6;
                } else {
                    uint32_t handle = 0xA000;
                    if (handler->ctx.global_state.find("RegHandleTop") != handler->ctx.global_state.end()) {
                        handle = static_cast<uint32_t>(handler->ctx.global_state["RegHandleTop"]);
                    }
                    handler->ctx.global_state["RegHandleTop"] = handle + 4;
                    auto* rk = new RegistryKeyHandle();
                    rk->path = base;
                    handler->ctx.handle_map["reg_" + std::to_string(handle)] = rk;
                    if (phkResult) handler->backend.mem_write(phkResult, &handle, 4);
                    handler->ctx.set_eax(0); // ERROR_SUCCESS
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "ADVAPI32.dll!RegCreateKeyExA") {
                uint32_t hKey = handler->ctx.get_arg(0);
                uint32_t lpSubKey = handler->ctx.get_arg(1);
                uint32_t phkResult = handler->ctx.get_arg(7);
                uint32_t lpdwDisposition = handler->ctx.get_arg(8);
                std::string base = resolve_registry_path(handler->ctx, hKey);
                std::string sub = read_guest_c_string(handler->ctx, lpSubKey, 512);
                std::replace(sub.begin(), sub.end(), '/', '\\');
                if (!base.empty() && !sub.empty()) base += "\\" + sub;
                if (base.empty()) {
                    handler->ctx.set_eax(6);
                    handler->ctx.global_state["LastError"] = 6;
                } else {
                    uint32_t handle = 0xA000;
                    if (handler->ctx.global_state.find("RegHandleTop") != handler->ctx.global_state.end()) {
                        handle = static_cast<uint32_t>(handler->ctx.global_state["RegHandleTop"]);
                    }
                    handler->ctx.global_state["RegHandleTop"] = handle + 4;
                    auto* rk = new RegistryKeyHandle();
                    rk->path = base;
                    handler->ctx.handle_map["reg_" + std::to_string(handle)] = rk;
                    if (phkResult) handler->backend.mem_write(phkResult, &handle, 4);
                    if (lpdwDisposition) {
                        uint32_t disp = 1; // REG_CREATED_NEW_KEY
                        handler->backend.mem_write(lpdwDisposition, &disp, 4);
                    }
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "ADVAPI32.dll!RegSetValueExA") {
                uint32_t hKey = handler->ctx.get_arg(0);
                uint32_t lpValueName = handler->ctx.get_arg(1);
                uint32_t dwType = handler->ctx.get_arg(3);
                uint32_t lpData = handler->ctx.get_arg(4);
                uint32_t cbData = handler->ctx.get_arg(5);
                std::string key_path = resolve_registry_path(handler->ctx, hKey);
                if (key_path.empty()) {
                    handler->ctx.set_eax(6);
                    handler->ctx.global_state["LastError"] = 6;
                } else {
                    std::string value_name = to_lower_ascii(read_guest_c_string(handler->ctx, lpValueName, 256));
                    std::string value_key = to_lower_ascii(key_path) + "|" + value_name;
                    std::vector<uint8_t> data;
                    if (lpData && cbData) {
                        data.resize(cbData);
                        handler->backend.mem_read(lpData, data.data(), cbData);
                    }
                    g_registry_values[value_key] = std::move(data);
                    g_registry_types[value_key] = dwType;
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "ADVAPI32.dll!RegDeleteValueA") {
                uint32_t hKey = handler->ctx.get_arg(0);
                uint32_t lpValueName = handler->ctx.get_arg(1);
                std::string key_path = resolve_registry_path(handler->ctx, hKey);
                std::string value_name = to_lower_ascii(read_guest_c_string(handler->ctx, lpValueName, 256));
                if (!key_path.empty()) {
                    std::string value_key = to_lower_ascii(key_path) + "|" + value_name;
                    g_registry_values.erase(value_key);
                    g_registry_types.erase(value_key);
                }
                handler->ctx.set_eax(0); // ERROR_SUCCESS
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "ADVAPI32.dll!RegQueryValueExA") {
                uint32_t hKey = handler->ctx.get_arg(0);
                uint32_t lpValueName = handler->ctx.get_arg(1);
                uint32_t lpType = handler->ctx.get_arg(3);
                uint32_t lpData = handler->ctx.get_arg(4);
                uint32_t lpcbData = handler->ctx.get_arg(5);
                std::string key_path = resolve_registry_path(handler->ctx, hKey);
                if (key_path.empty()) {
                    handler->ctx.set_eax(6);
                    handler->ctx.global_state["LastError"] = 6;
                } else {
                    std::string value_name = to_lower_ascii(read_guest_c_string(handler->ctx, lpValueName, 256));
                    std::string value_key = to_lower_ascii(key_path) + "|" + value_name;
                    auto itv = g_registry_values.find(value_key);
                    if (itv == g_registry_values.end()) {
                        uint32_t zero = 0;
                        if (lpcbData) handler->backend.mem_write(lpcbData, &zero, 4);
                        handler->ctx.set_eax(2); // ERROR_FILE_NOT_FOUND
                        handler->ctx.global_state["LastError"] = 2;
                    } else {
                        const std::vector<uint8_t>& data = itv->second;
                        uint32_t type = 1; // REG_SZ default
                        auto itt = g_registry_types.find(value_key);
                        if (itt != g_registry_types.end()) type = itt->second;
                        if (lpType) handler->backend.mem_write(lpType, &type, 4);

                        uint32_t inout = 0;
                        if (lpcbData) handler->backend.mem_read(lpcbData, &inout, 4);
                        uint32_t required = static_cast<uint32_t>(data.size());
                        if (lpcbData) handler->backend.mem_write(lpcbData, &required, 4);

                        if (lpData != 0) {
                            uint32_t to_copy = std::min<uint32_t>(inout, required);
                            if (to_copy > 0) handler->backend.mem_write(lpData, data.data(), to_copy);
                        }
                        handler->ctx.set_eax(0);
                        handler->ctx.global_state["LastError"] = 0;
                    }
                }
            } else if (name == "ADVAPI32.dll!RegCloseKey") {
                uint32_t hKey = handler->ctx.get_arg(0);
                auto it = handler->ctx.handle_map.find("reg_" + std::to_string(hKey));
                if (it != handler->ctx.handle_map.end()) {
                    delete static_cast<RegistryKeyHandle*>(it->second);
                    handler->ctx.handle_map.erase(it);
                }
                handler->ctx.set_eax(0);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!GetProcessHeap") {
                handler->ctx.set_eax(0x11000000); // Dummy Heap Handle
                std::cout << "\n[API CALL] [OK] GetProcessHeap" << std::endl;
            } else if (name == "KERNEL32.dll!HeapCreate") {
                handler->ctx.set_eax(0x11000000); 
                std::cout << "\n[API CALL] [OK] HeapCreate" << std::endl;
            } else if (name == "KERNEL32.dll!HeapAlloc") {
                uint32_t dwFlags = handler->ctx.get_arg(1);
                uint32_t dwBytes = handler->ctx.get_arg(2);
                
                // Extremely simple bump allocator
                if (handler->ctx.global_state.find("HeapTop") == handler->ctx.global_state.end()) {
                    handler->ctx.global_state["HeapTop"] = 0x20000000;
                    handler->backend.mem_map(0x20000000, 0x10000000, UC_PROT_ALL); // 256MB Heap
                }
                
                uint32_t ptr = handler->ctx.global_state["HeapTop"];
                // 16-byte align
                uint32_t aligned_bytes = (dwBytes + 15) & ~15;
                handler->ctx.global_state["HeapTop"] += aligned_bytes;
                
                if (dwFlags & 8) { // HEAP_ZERO_MEMORY
                    // Memory is already zeroed by uc_mem_map initially, but let's be safe
                    // For a bump allocator, fresh memory is zeroed.
                }
                
                handler->ctx.set_eax(ptr);
                g_heap_sizes[ptr] = dwBytes;
            } else if (name == "KERNEL32.dll!HeapFree") {
                uint32_t lpMem = handler->ctx.get_arg(2);
                g_heap_sizes.erase(lpMem);
                handler->ctx.set_eax(1); // Success
            } else if (name == "KERNEL32.dll!HeapSize") {
                uint32_t lpMem = handler->ctx.get_arg(2);
                auto it = g_heap_sizes.find(lpMem);
                if (it != g_heap_sizes.end()) {
                    handler->ctx.set_eax(it->second);
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    handler->ctx.set_eax(0xFFFFFFFFu); // (SIZE_T)-1 on failure
                    handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                }
            } else if (name == "KERNEL32.dll!HeapReAlloc") {
                uint32_t dwFlags = handler->ctx.get_arg(1);
                uint32_t lpMem = handler->ctx.get_arg(2);
                uint32_t dwBytes = handler->ctx.get_arg(3);

                if (dwBytes == 0) {
                    dwBytes = 1;
                }

                if (lpMem == 0) {
                    // Windows allows HeapReAlloc(NULL, ..) behavior similar to alloc in some runtimes.
                    if (handler->ctx.global_state.find("HeapTop") == handler->ctx.global_state.end()) {
                        handler->ctx.global_state["HeapTop"] = 0x20000000;
                        handler->backend.mem_map(0x20000000, 0x10000000, UC_PROT_ALL);
                    }
                    uint32_t ptr = static_cast<uint32_t>(handler->ctx.global_state["HeapTop"]);
                    uint32_t aligned = (dwBytes + 15) & ~15u;
                    handler->ctx.global_state["HeapTop"] = ptr + aligned;
                    g_heap_sizes[ptr] = dwBytes;
                    handler->ctx.set_eax(ptr);
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    auto it = g_heap_sizes.find(lpMem);
                    if (it == g_heap_sizes.end()) {
                        handler->ctx.set_eax(0);
                        handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                    } else {
                        uint32_t old_size = it->second;
                        if (dwBytes <= old_size) {
                            // Shrink in-place
                            g_heap_sizes[lpMem] = dwBytes;
                            handler->ctx.set_eax(lpMem);
                            handler->ctx.global_state["LastError"] = 0;
                        } else {
                            // Grow by allocating a new block and copying old bytes.
                            if (handler->ctx.global_state.find("HeapTop") == handler->ctx.global_state.end()) {
                                handler->ctx.global_state["HeapTop"] = 0x20000000;
                                handler->backend.mem_map(0x20000000, 0x10000000, UC_PROT_ALL);
                            }
                            uint32_t new_ptr = static_cast<uint32_t>(handler->ctx.global_state["HeapTop"]);
                            uint32_t aligned = (dwBytes + 15) & ~15u;
                            handler->ctx.global_state["HeapTop"] = new_ptr + aligned;

                            std::vector<uint8_t> temp(old_size, 0);
                            handler->backend.mem_read(lpMem, temp.data(), old_size);
                            handler->backend.mem_write(new_ptr, temp.data(), old_size);

                            if (dwFlags & 0x00000008u) { // HEAP_ZERO_MEMORY
                                std::vector<uint8_t> zeros(dwBytes - old_size, 0);
                                handler->backend.mem_write(new_ptr + old_size, zeros.data(), zeros.size());
                            }

                            g_heap_sizes.erase(lpMem);
                            g_heap_sizes[new_ptr] = dwBytes;
                            handler->ctx.set_eax(new_ptr);
                            handler->ctx.global_state["LastError"] = 0;
                        }
                    }
                }
            } else if (name == "KERNEL32.dll!CreateFileA") {
                uint32_t lpFileName = handler->ctx.get_arg(0);
                uint32_t creationDisposition = handler->ctx.get_arg(4);
                std::string guest_path = read_guest_c_string(handler->ctx, lpFileName, 1024);
                std::string host_path = resolve_guest_path_to_host(guest_path, handler->process_base_dir);
                if (host_path.empty()) {
                    std::string normalized = guest_path;
                    std::replace(normalized.begin(), normalized.end(), '\\', '/');
                    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    // Some PvZ builds probe adlist/popc registry files that may not exist yet.
                    bool allow_virtual = (normalized == "adlist.txt" ||
                                          normalized == "vhwb.dat" ||
                                          normalized == "vhw.dat" ||
                                          normalized == "../popcreg.dat" ||
                                          normalized == "popcreg.dat" ||
                                          normalized == "c:/windows/system32/" ||
                                          normalized == "windows/system32/");
                    // CREATE_NEW(1), CREATE_ALWAYS(2), OPEN_ALWAYS(4) can create a backing file.
                    if (creationDisposition == 1 || creationDisposition == 2 || creationDisposition == 4) {
                        allow_virtual = true;
                    }

                    if (allow_virtual) {
                        auto* fh = new HostFileHandle();
                        fh->pos = 0;
                        uint32_t handle = 0x5000;
                        if (handler->ctx.global_state.find("FileHandleTop") == handler->ctx.global_state.end()) {
                            handler->ctx.global_state["FileHandleTop"] = handle;
                        } else {
                            handle = static_cast<uint32_t>(handler->ctx.global_state["FileHandleTop"]);
                        }
                        handler->ctx.global_state["FileHandleTop"] = handle + 4;
                        handler->ctx.handle_map["file_" + std::to_string(handle)] = fh;
                        handler->ctx.set_eax(handle);
                        handler->ctx.global_state["LastError"] = 0;
                        std::cout << "\n[API CALL] [FILE] CreateFileA('" << guest_path
                                  << "') -> virtual empty file handle=0x"
                                  << std::hex << handle << std::dec
                                  << " (disp=" << creationDisposition << ")\n";
                    } else {
                        handler->ctx.set_eax(0xFFFFFFFFu); // INVALID_HANDLE_VALUE
                        handler->ctx.global_state["LastError"] = 2; // ERROR_FILE_NOT_FOUND
                        std::cout << "\n[API CALL] [FILE] CreateFileA('" << guest_path << "') -> NOT FOUND\n";
                    }
                } else {
                    auto* fh = new HostFileHandle();
                    std::ifstream in(host_path, std::ios::binary);
                    fh->data.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
                    fh->pos = 0;

                    uint32_t handle = 0x5000;
                    if (handler->ctx.global_state.find("FileHandleTop") == handler->ctx.global_state.end()) {
                        handler->ctx.global_state["FileHandleTop"] = handle;
                    } else {
                        handle = static_cast<uint32_t>(handler->ctx.global_state["FileHandleTop"]);
                    }
                    handler->ctx.global_state["FileHandleTop"] = handle + 4;
                    handler->ctx.handle_map["file_" + std::to_string(handle)] = fh;

                    handler->ctx.set_eax(handle);
                    handler->ctx.global_state["LastError"] = 0;
                    std::cout << "\n[API CALL] [FILE] CreateFileA('" << guest_path << "') -> handle=0x"
                              << std::hex << handle << std::dec << " (" << fh->data.size() << " bytes)\n";
                }
            } else if (name == "KERNEL32.dll!ReadFile") {
                uint32_t hFile = handler->ctx.get_arg(0);
                uint32_t lpBuffer = handler->ctx.get_arg(1);
                uint32_t nBytesToRead = handler->ctx.get_arg(2);
                uint32_t lpBytesRead = handler->ctx.get_arg(3);
                auto key = "file_" + std::to_string(hFile);
                auto itf = handler->ctx.handle_map.find(key);
                if (itf == handler->ctx.handle_map.end()) {
                    uint32_t zero = 0;
                    if (lpBytesRead) handler->backend.mem_write(lpBytesRead, &zero, 4);
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                } else {
                    auto* fh = static_cast<HostFileHandle*>(itf->second);
                    size_t remaining = (fh->pos < fh->data.size()) ? (fh->data.size() - fh->pos) : 0;
                    uint32_t to_read = static_cast<uint32_t>(std::min<size_t>(remaining, nBytesToRead));
                    if (to_read > 0) {
                        handler->backend.mem_write(lpBuffer, fh->data.data() + fh->pos, to_read);
                        fh->pos += to_read;
                    }
                    if (lpBytesRead) handler->backend.mem_write(lpBytesRead, &to_read, 4);
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "KERNEL32.dll!WriteFile") {
                uint32_t hFile = handler->ctx.get_arg(0);
                uint32_t lpBuffer = handler->ctx.get_arg(1);
                uint32_t nBytesToWrite = handler->ctx.get_arg(2);
                uint32_t lpBytesWritten = handler->ctx.get_arg(3);
                auto key = "file_" + std::to_string(hFile);
                auto itf = handler->ctx.handle_map.find(key);
                if (itf == handler->ctx.handle_map.end()) {
                    uint32_t zero = 0;
                    if (lpBytesWritten) handler->backend.mem_write(lpBytesWritten, &zero, 4);
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                } else {
                    auto* fh = static_cast<HostFileHandle*>(itf->second);
                    if (fh->pos > fh->data.size()) fh->data.resize(fh->pos, 0);
                    if (nBytesToWrite > 0) {
                        if (fh->pos + nBytesToWrite > fh->data.size()) fh->data.resize(fh->pos + nBytesToWrite);
                        handler->backend.mem_read(lpBuffer, fh->data.data() + fh->pos, nBytesToWrite);
                        fh->pos += nBytesToWrite;
                    }
                    if (lpBytesWritten) handler->backend.mem_write(lpBytesWritten, &nBytesToWrite, 4);
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "KERNEL32.dll!GetFileSize") {
                uint32_t hFile = handler->ctx.get_arg(0);
                auto key = "file_" + std::to_string(hFile);
                auto itf = handler->ctx.handle_map.find(key);
                if (itf == handler->ctx.handle_map.end()) {
                    handler->ctx.set_eax(0xFFFFFFFFu);
                    handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                } else {
                    auto* fh = static_cast<HostFileHandle*>(itf->second);
                    handler->ctx.set_eax(static_cast<uint32_t>(fh->data.size()));
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "KERNEL32.dll!SetFilePointer") {
                uint32_t hFile = handler->ctx.get_arg(0);
                int32_t distance = static_cast<int32_t>(handler->ctx.get_arg(1));
                uint32_t moveMethod = handler->ctx.get_arg(3); // FILE_BEGIN=0, FILE_CURRENT=1, FILE_END=2
                auto key = "file_" + std::to_string(hFile);
                auto itf = handler->ctx.handle_map.find(key);
                if (itf == handler->ctx.handle_map.end()) {
                    handler->ctx.set_eax(0xFFFFFFFFu);
                    handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                } else {
                    auto* fh = static_cast<HostFileHandle*>(itf->second);
                    int64_t base = 0;
                    if (moveMethod == 1) base = static_cast<int64_t>(fh->pos);
                    else if (moveMethod == 2) base = static_cast<int64_t>(fh->data.size());
                    int64_t next = base + static_cast<int64_t>(distance);
                    if (next < 0) next = 0;
                    fh->pos = static_cast<size_t>(next);
                    handler->ctx.set_eax(static_cast<uint32_t>(fh->pos));
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "KERNEL32.dll!FindResourceA") {
                if (!g_resource_heap_mapped) {
                    handler->backend.mem_map(g_resource_heap_top, 0x00100000, UC_PROT_ALL); // 1MB
                    g_resource_heap_mapped = true;
                }
                uint32_t handle = g_resource_handle_top;
                g_resource_handle_top += 4;
                uint32_t ptr = g_resource_heap_top;
                g_resource_heap_top += 512; // minimal placeholder blob
                g_resource_ptr_by_handle[handle] = ptr;
                g_resource_size_by_handle[handle] = 512;
                handler->ctx.set_eax(handle);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!LoadResource") {
                uint32_t hResInfo = handler->ctx.get_arg(1);
                if (g_resource_ptr_by_handle.find(hResInfo) != g_resource_ptr_by_handle.end()) {
                    handler->ctx.set_eax(hResInfo);
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 1812;
                }
            } else if (name == "KERNEL32.dll!LockResource") {
                uint32_t hResData = handler->ctx.get_arg(0);
                auto it = g_resource_ptr_by_handle.find(hResData);
                if (it != g_resource_ptr_by_handle.end()) {
                    handler->ctx.set_eax(it->second);
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 1812;
                }
            } else if (name == "KERNEL32.dll!SizeofResource") {
                uint32_t hResInfo = handler->ctx.get_arg(1);
                auto it = g_resource_size_by_handle.find(hResInfo);
                if (it != g_resource_size_by_handle.end()) {
                    handler->ctx.set_eax(it->second);
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 1812;
                }
            } else if (name == "KERNEL32.dll!FreeResource") {
                // Win32 compatibility: always succeeds for 32-bit apps.
                handler->ctx.set_eax(1);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!CreateEventA" || name == "KERNEL32.dll!CreateEventW") {
                uint32_t bManualReset = handler->ctx.get_arg(1);
                uint32_t bInitialState = handler->ctx.get_arg(2);
                auto* ev = new EventHandle();
                ev->manual_reset = (bManualReset != 0);
                ev->signaled = (bInitialState != 0);

                uint32_t handle = 0x7000;
                if (handler->ctx.global_state.find("EventHandleTop") == handler->ctx.global_state.end()) {
                    handler->ctx.global_state["EventHandleTop"] = handle;
                } else {
                    handle = static_cast<uint32_t>(handler->ctx.global_state["EventHandleTop"]);
                }
                handler->ctx.global_state["EventHandleTop"] = handle + 4;
                handler->ctx.handle_map["event_" + std::to_string(handle)] = ev;
                handler->ctx.set_eax(handle);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!CreateThread") {
                if (env_truthy("PVZ_CREATE_THREAD_FAIL")) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 8; // ERROR_NOT_ENOUGH_MEMORY
                    return;
                }
                uint32_t lpStartAddress = handler->ctx.get_arg(2);
                uint32_t lpParameter = handler->ctx.get_arg(3);
                uint32_t lpThreadId = handler->ctx.get_arg(5);
                uint32_t handle = 0x8000;
                if (handler->ctx.global_state.find("ThreadHandleTop") == handler->ctx.global_state.end()) {
                    handler->ctx.global_state["ThreadHandleTop"] = handle;
                } else {
                    handle = static_cast<uint32_t>(handler->ctx.global_state["ThreadHandleTop"]);
                }
                handler->ctx.global_state["ThreadHandleTop"] = handle + 4;
                if (lpThreadId != 0) {
                    uint32_t tid = 1;
                    handler->backend.mem_write(lpThreadId, &tid, 4);
                }
                // Cooperative thread emulation:
                // mark the thread-parameter block as "started" so waits and init gates can progress.
                if (lpParameter != 0) {
                    uint32_t one = 1;
                    handler->backend.mem_write(lpParameter, &one, 4);
                    handler->backend.mem_write(lpParameter + 4, &one, 4);
                }
                std::cout << "\n[API CALL] [OK] CreateThread(start=0x" << std::hex << lpStartAddress
                          << ", param=0x" << lpParameter << ", handle=0x" << handle << std::dec << ")\n";
                handler->ctx.set_eax(handle);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!SetEvent") {
                uint32_t h = handler->ctx.get_arg(0);
                auto it = handler->ctx.handle_map.find("event_" + std::to_string(h));
                if (it != handler->ctx.handle_map.end()) {
                    static_cast<EventHandle*>(it->second)->signaled = true;
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6;
                }
            } else if (name == "KERNEL32.dll!ResetEvent") {
                uint32_t h = handler->ctx.get_arg(0);
                auto it = handler->ctx.handle_map.find("event_" + std::to_string(h));
                if (it != handler->ctx.handle_map.end()) {
                    static_cast<EventHandle*>(it->second)->signaled = false;
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6;
                }
            } else if (name == "KERNEL32.dll!WaitForSingleObject") {
                uint32_t h = handler->ctx.get_arg(0);
                uint32_t timeout_ms = handler->ctx.get_arg(1);
                auto it = handler->ctx.handle_map.find("event_" + std::to_string(h));
                uint32_t wait_result = 0; // WAIT_OBJECT_0
                if (it != handler->ctx.handle_map.end()) {
                    auto* ev = static_cast<EventHandle*>(it->second);
                    if (ev->signaled) {
                        wait_result = 0; // WAIT_OBJECT_0
                        if (!ev->manual_reset) ev->signaled = false;
                    } else {
                        // Non-blocking emulation for unsignaled events.
                        // Infinite waits are treated as signaled to avoid deadlock,
                        // finite waits return WAIT_TIMEOUT.
                        wait_result = (timeout_ms == 0xFFFFFFFFu) ? 0 : 0x102;
                    }
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    // Treat non-event handles as already-signaled for compatibility.
                    wait_result = 0; // WAIT_OBJECT_0
                    handler->ctx.global_state["LastError"] = 0;
                }
                handler->ctx.set_eax(wait_result);
                std::cout << "\n[API CALL] [OK] WaitForSingleObject(handle=0x" << std::hex << h
                          << ", timeout=" << std::dec << timeout_ms << ") -> 0x" << std::hex
                          << wait_result << std::dec << "\n";
            } else if (name == "KERNEL32.dll!CloseHandle") {
                uint32_t h = handler->ctx.get_arg(0);
                auto itf = handler->ctx.handle_map.find("file_" + std::to_string(h));
                if (itf != handler->ctx.handle_map.end()) {
                    delete static_cast<HostFileHandle*>(itf->second);
                    handler->ctx.handle_map.erase(itf);
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    auto itm = handler->ctx.handle_map.find("mapping_" + std::to_string(h));
                    if (itm != handler->ctx.handle_map.end()) {
                        delete static_cast<MappingHandle*>(itm->second);
                        handler->ctx.handle_map.erase(itm);
                        handler->ctx.set_eax(1);
                        handler->ctx.global_state["LastError"] = 0;
                        return;
                    }
                    auto ite = handler->ctx.handle_map.find("event_" + std::to_string(h));
                    if (ite != handler->ctx.handle_map.end()) {
                        delete static_cast<EventHandle*>(ite->second);
                        handler->ctx.handle_map.erase(ite);
                        handler->ctx.set_eax(1);
                        handler->ctx.global_state["LastError"] = 0;
                    } else {
                        // Non-file handles are currently treated as success for compatibility.
                        handler->ctx.set_eax(1);
                        handler->ctx.global_state["LastError"] = 0;
                    }
                }
            } else if (name == "KERNEL32.dll!GetProcAddress") {
                uint32_t hModule = handler->ctx.get_arg(0);
                uint32_t lpProcName = handler->ctx.get_arg(1);
                
                std::string procName;
                if (lpProcName > 0xFFFF) { // Not an ordinal
                    char buf[256] = {0};
                    handler->backend.mem_read(lpProcName, buf, 255);
                    procName = buf;
                } else {
                    procName = "Ordinal_" + std::to_string(lpProcName);
                }
                
                std::string module_name = "KERNEL32.dll";
                switch (hModule) {
                    case 0x76000000: module_name = "KERNEL32.dll"; break;
                    case 0x77000000: module_name = "ntdll.dll"; break;
                    case 0x75000000: module_name = "USER32.dll"; break;
                    case 0x74000000: module_name = "ole32.dll"; break;
                    case 0x74100000: module_name = "OLEAUT32.dll"; break;
                    case 0x73000000: module_name = "DDRAW.dll"; break;
                    case 0x73100000: module_name = "GDI32.dll"; break;
                    case 0x73200000: module_name = "WINMM.dll"; break;
                    case 0x73300000: module_name = "DSOUND.dll"; break;
                    case 0x73400000: module_name = "BASS.dll"; break;
                    case 0x78000000: module_name = "mscoree.dll"; break;
                    default: break;
                }
                std::string full_name = module_name + "!" + procName;
                
                uint32_t found_addr = 0;
                for (const auto& pair : handler->fake_api_map) {
                    if (pair.second == full_name) {
                        found_addr = pair.first;
                        break;
                    }
                }
                
                if (found_addr == 0) {
                    found_addr = handler->register_fake_api(full_name);
                    std::cout << "\n[API CALL] [GetProcAddress] Dynamically assigned " << full_name << " to 0x" << std::hex << found_addr << std::dec << "\n";
                }
                
                handler->ctx.set_eax(found_addr);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "mscoree.dll!CorExitProcess" || name == "KERNEL32.dll!CorExitProcess") {
                uint32_t exit_code = handler->ctx.get_arg(0);
                std::cout << "\n[API CALL] [OK] Intercepted call to " << name
                          << " (exit_code=" << exit_code
                          << ") -> stopping emulation.\n";
                uint32_t finished_eip = 0;
                handler->backend.reg_write(UC_X86_REG_EIP, &finished_eip);
                handler->backend.emu_stop();
                return;
            } else if (name == "KERNEL32.dll!EncodePointer" || name == "KERNEL32.dll!DecodePointer") {
                uint32_t ptr = handler->ctx.get_arg(0);
                handler->ctx.set_eax(ptr);
                std::cout << "\n[API CALL] [OK] " << name << "(0x" << std::hex << ptr << std::dec << ") returning unchanged.\n";
            } else if (name == "KERNEL32.dll!InterlockedExchange") {
                uint32_t target_ptr = handler->ctx.get_arg(0);
                uint32_t val = handler->ctx.get_arg(1);
                uint32_t prev = 0;
                handler->backend.mem_read(target_ptr, &prev, 4);
                handler->backend.mem_write(target_ptr, &val, 4);
                handler->ctx.set_eax(prev);
            } else if (name == "KERNEL32.dll!InterlockedCompareExchange") {
                uint32_t target_ptr = handler->ctx.get_arg(0);
                uint32_t xchg = handler->ctx.get_arg(1);
                uint32_t comp = handler->ctx.get_arg(2);
                uint32_t prev = 0;
                handler->backend.mem_read(target_ptr, &prev, 4);
                if (prev == comp) {
                    handler->backend.mem_write(target_ptr, &xchg, 4);
                }
                handler->ctx.set_eax(prev);
            } else if (name == "KERNEL32.dll!InterlockedIncrement") {
                uint32_t target_ptr = handler->ctx.get_arg(0);
                uint32_t val = 0;
                handler->backend.mem_read(target_ptr, &val, 4);
                val++;
                handler->backend.mem_write(target_ptr, &val, 4);
                handler->ctx.set_eax(val);
            } else if (name == "KERNEL32.dll!InterlockedDecrement") {
                uint32_t target_ptr = handler->ctx.get_arg(0);
                uint32_t val = 0;
                handler->backend.mem_read(target_ptr, &val, 4);
                val--;
                handler->backend.mem_write(target_ptr, &val, 4);
                handler->ctx.set_eax(val);
            } else if (name == "KERNEL32.dll!EnterCriticalSection" ||
                       name == "KERNEL32.dll!LeaveCriticalSection" ||
                       name == "KERNEL32.dll!InitializeCriticalSection" ||
                       name == "KERNEL32.dll!InitializeCriticalSectionAndSpinCount") {
                // Hot-path sync APIs: treat as no-op success and keep logs quiet.
                handler->ctx.set_eax(1);
            } else if (name == "OLEAUT32.dll!Ordinal_9") {
                handler->ctx.set_eax(0);
                std::cout << "\n[API CALL] [OK] Intercepted SysFreeString.\n";
            } else if (name == "KERNEL32.dll!TlsAlloc" || name == "KERNEL32.dll!FlsAlloc") {
                const char* prefix = (name == "KERNEL32.dll!TlsAlloc") ? "tls_" : "fls_";
                const char* next_key = (name == "KERNEL32.dll!TlsAlloc") ? "tls_next_alloc_index" : "fls_next_alloc_index";
                uint64_t next_index = handler->ctx.global_state[next_key];
                if (next_index >= 1088u) {
                    handler->ctx.set_eax(0xFFFFFFFFu);
                    handler->ctx.global_state["LastError"] = 0x103u; // ERROR_NO_MORE_ITEMS
                } else {
                    uint32_t idx = static_cast<uint32_t>(next_index);
                    handler->ctx.global_state[next_key] = next_index + 1;
                    handler->ctx.global_state[std::string(prefix) + std::to_string(idx)] = 0;
                    handler->ctx.set_eax(idx);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "KERNEL32.dll!TlsSetValue" || name == "KERNEL32.dll!FlsSetValue") {
                uint32_t idx = handler->ctx.get_arg(0);
                uint32_t value = handler->ctx.get_arg(1);
                const char* prefix = (name == "KERNEL32.dll!TlsSetValue") ? "tls_" : "fls_";
                if (idx >= 1088u) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 87; // ERROR_INVALID_PARAMETER
                } else {
                    handler->ctx.global_state[std::string(prefix) + std::to_string(idx)] = value;
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "KERNEL32.dll!TlsGetValue" || name == "KERNEL32.dll!FlsGetValue") {
                uint32_t idx = handler->ctx.get_arg(0);
                const char* prefix = (name == "KERNEL32.dll!TlsGetValue") ? "tls_" : "fls_";
                uint32_t result = 0;
                if (idx < 1088u) {
                    auto itv = handler->ctx.global_state.find(std::string(prefix) + std::to_string(idx));
                    if (itv != handler->ctx.global_state.end()) {
                        result = static_cast<uint32_t>(itv->second);
                    }
                }
                handler->ctx.set_eax(result);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!FlsFree") {
                uint32_t idx = handler->ctx.get_arg(0);
                if (idx >= 1088u) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 87; // ERROR_INVALID_PARAMETER
                } else {
                    handler->ctx.global_state.erase("fls_" + std::to_string(idx));
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "KERNEL32.dll!GetLastError" ||
                       name == "KERNEL32.dll!GetFileVersionInfoSizeA" || name == "KERNEL32.dll!GetFileVersionInfoA" || name == "KERNEL32.dll!VerQueryValueA") {
                handler->ctx.set_eax(0);
                std::cout << "\n[API CALL] [OK] Intercepted call to " << name << " returning 0.\n";
            } else if (name == "KERNEL32.dll!GetEnvironmentStringsW" || name == "KERNEL32.dll!GetCommandLineA" || name == "KERNEL32.dll!GetCommandLineW") {
                handler->ctx.set_eax(0x76001500); // Pointing to guaranteed zeroed memory in our fake PE header
                std::cout << "\n[API CALL] [OK] Intercepted call to " << name << " returning static empty string.\n";
            } else if (name == "KERNEL32.dll!CreateFileMappingA") {
                uint32_t hFile = handler->ctx.get_arg(0);
                if (hFile != 0xFFFFFFFFu) {
                    auto itf = handler->ctx.handle_map.find("file_" + std::to_string(hFile));
                    if (itf == handler->ctx.handle_map.end()) {
                        handler->ctx.set_eax(0);
                        handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                        std::cout << "\n[API CALL] [FILEMAP] CreateFileMappingA invalid file handle 0x"
                                  << std::hex << hFile << std::dec << "\n";
                        return;
                    }
                }

                auto* mapping = new MappingHandle();
                mapping->file_handle = hFile;

                uint32_t handle = 0x9000;
                if (handler->ctx.global_state.find("MappingHandleTop") == handler->ctx.global_state.end()) {
                    handler->ctx.global_state["MappingHandleTop"] = handle;
                } else {
                    handle = static_cast<uint32_t>(handler->ctx.global_state["MappingHandleTop"]);
                }
                handler->ctx.global_state["MappingHandleTop"] = handle + 4;
                handler->ctx.handle_map["mapping_" + std::to_string(handle)] = mapping;

                handler->ctx.set_eax(handle);
                handler->ctx.global_state["LastError"] = 0;
                std::cout << "\n[API CALL] [FILEMAP] CreateFileMappingA(hFile=0x"
                          << std::hex << hFile << ") -> handle=0x" << handle << std::dec << "\n";
            } else if (name == "KERNEL32.dll!OpenFileMappingA") {
                uint32_t lpName = handler->ctx.get_arg(2);
                std::string map_name = read_guest_c_string(handler->ctx, lpName, 256);
                std::string key = "OpenFileMap:" + map_name;
                uint32_t handle = 0;
                auto it_existing = handler->ctx.global_state.find(key);
                if (it_existing != handler->ctx.global_state.end()) {
                    handle = static_cast<uint32_t>(it_existing->second);
                } else {
                    auto* mapping = new MappingHandle();
                    mapping->file_handle = 0xFFFFFFFFu; // anonymous/shared mapping

                    handle = 0x9000;
                    if (handler->ctx.global_state.find("MappingHandleTop") == handler->ctx.global_state.end()) {
                        handler->ctx.global_state["MappingHandleTop"] = handle;
                    } else {
                        handle = static_cast<uint32_t>(handler->ctx.global_state["MappingHandleTop"]);
                    }
                    handler->ctx.global_state["MappingHandleTop"] = handle + 4;
                    handler->ctx.handle_map["mapping_" + std::to_string(handle)] = mapping;
                    handler->ctx.global_state[key] = handle;
                }
                handler->ctx.set_eax(handle);
                handler->ctx.global_state["LastError"] = 0;
                std::cout << "\n[API CALL] [FILEMAP] OpenFileMappingA('" << map_name
                          << "') -> handle=0x" << std::hex << handle << std::dec << "\n";
            } else if (name == "KERNEL32.dll!MapViewOfFile") {
                uint32_t hMap = handler->ctx.get_arg(0);
                uint32_t offHigh = handler->ctx.get_arg(2);
                uint32_t offLow = handler->ctx.get_arg(3);
                uint32_t numBytes = handler->ctx.get_arg(4);
                auto itm = handler->ctx.handle_map.find("mapping_" + std::to_string(hMap));
                MappingHandle temp_mapping;
                MappingHandle* mapping = nullptr;
                if (itm == handler->ctx.handle_map.end()) {
                    // Some code paths use sentinel handles; allow anonymous zero-filled mapping.
                    temp_mapping.file_handle = 0xFFFFFFFFu;
                    mapping = &temp_mapping;
                    std::cout << "\n[API CALL] [FILEMAP] MapViewOfFile unknown handle 0x"
                              << std::hex << hMap << std::dec << " -> using anonymous mapping\n";
                } else {
                    mapping = static_cast<MappingHandle*>(itm->second);
                }
                uint64_t offset = (static_cast<uint64_t>(offHigh) << 32) | static_cast<uint64_t>(offLow);

                std::vector<uint8_t>* source = nullptr;
                if (mapping->file_handle != 0xFFFFFFFFu) {
                    auto itf = handler->ctx.handle_map.find("file_" + std::to_string(mapping->file_handle));
                    if (itf != handler->ctx.handle_map.end()) {
                        source = &static_cast<HostFileHandle*>(itf->second)->data;
                    }
                }

                uint32_t map_size = numBytes;
                if (map_size == 0) {
                    if (source && offset < source->size()) {
                        uint64_t remaining = source->size() - offset;
                        map_size = remaining > 0xFFFFFFFFu ? 0xFFFFFFFFu : static_cast<uint32_t>(remaining);
                    } else {
                        map_size = 0x1000;
                    }
                }
                if (map_size == 0) map_size = 0x1000;

                if (handler->ctx.global_state.find("MapViewBase") == handler->ctx.global_state.end()) {
                    uint32_t base = 0x32000000;
                    uint32_t size = 0x10000000; // 256MB map-view arena
                    handler->backend.mem_map(base, size, UC_PROT_ALL);
                    handler->ctx.global_state["MapViewBase"] = base;
                    handler->ctx.global_state["MapViewLimit"] = base + size;
                    handler->ctx.global_state["MapViewTop"] = base;
                }

                uint32_t aligned = (map_size + 0xFFFu) & ~0xFFFu;
                uint32_t view_ptr = static_cast<uint32_t>(handler->ctx.global_state["MapViewTop"]);
                uint32_t limit = static_cast<uint32_t>(handler->ctx.global_state["MapViewLimit"]);
                if (view_ptr + aligned < view_ptr || view_ptr + aligned > limit) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 8; // ERROR_NOT_ENOUGH_MEMORY
                    return;
                }
                handler->ctx.global_state["MapViewTop"] = view_ptr + aligned;

                std::vector<uint8_t> zeros(aligned, 0);
                handler->backend.mem_write(view_ptr, zeros.data(), zeros.size());

                if (source && offset < source->size()) {
                    size_t available = source->size() - static_cast<size_t>(offset);
                    size_t to_copy = std::min<size_t>(available, map_size);
                    if (to_copy > 0) {
                        handler->backend.mem_write(view_ptr, source->data() + static_cast<size_t>(offset), to_copy);
                    }
                }

                handler->ctx.set_eax(view_ptr);
                handler->ctx.global_state["LastError"] = 0;
                std::cout << "\n[API CALL] [FILEMAP] MapViewOfFile(hMap=0x" << std::hex << hMap
                          << ", off=0x" << offset << ", size=0x" << map_size
                          << ") -> 0x" << view_ptr << std::dec << "\n";
            } else if (name == "KERNEL32.dll!UnmapViewOfFile") {
                handler->ctx.set_eax(1);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "WINMM.dll!mixerOpen") {
                uint32_t phmx = handler->ctx.get_arg(0);
                if (phmx != 0) {
                    uint32_t hmx = 0x1;
                    handler->backend.mem_write(phmx, &hmx, 4);
                }
                handler->ctx.set_eax(0); // MMSYSERR_NOERROR
            } else if (name == "WINMM.dll!mixerClose") {
                handler->ctx.set_eax(0); // MMSYSERR_NOERROR
            } else if (name == "WINMM.dll!mixerGetDevCapsA" || name == "WINMM.dll!mixerGetDevCapsW") {
                uint32_t caps_ptr = handler->ctx.get_arg(1);
                uint32_t caps_size = handler->ctx.get_arg(2);
                if (caps_ptr != 0 && caps_size >= 16) {
                    std::vector<uint8_t> caps(caps_size, 0);
                    // cDestinations at offset 44 for MIXERCAPSA/W (after szPname[32])
                    if (caps_size > 48) {
                        uint32_t cDestinations = 0;
                        std::memcpy(caps.data() + 44, &cDestinations, sizeof(cDestinations));
                    }
                    handler->backend.mem_write(caps_ptr, caps.data(), caps.size());
                }
                handler->ctx.set_eax(0); // MMSYSERR_NOERROR
            } else if (name == "WINMM.dll!mixerGetNumDevs") {
                handler->ctx.set_eax(0); // no mixer devices
            } else if (name == "WINMM.dll!mixerGetLineInfoA" || name == "WINMM.dll!mixerGetLineInfoW" ||
                       name == "WINMM.dll!mixerGetLineControlsA" || name == "WINMM.dll!mixerGetLineControlsW" ||
                       name == "WINMM.dll!mixerGetControlDetailsA" || name == "WINMM.dll!mixerGetControlDetailsW") {
                // Return a graceful mixer failure to let the game continue without mixer controls.
                handler->ctx.set_eax(1); // MMSYSERR_ERROR
            } else if (name == "WINMM.dll!mixerSetControlDetails") {
                handler->ctx.set_eax(0); // MMSYSERR_NOERROR
            } else if (name == "DDRAW.dll!IDirectDraw7_Method_0") {
                // HRESULT QueryInterface(REFIID riid, void **ppvObj)
                uint32_t riid = handler->ctx.get_arg(1);
                uint32_t ppvObj = handler->ctx.get_arg(2);
                uint8_t guid[16];
                handler->backend.mem_read(riid, guid, 16);
                
                std::cout << "\n[API CALL] QueryInterface requested GUID: ";
                for (int i=0; i<16; i++) std::cout << std::hex << (int)guid[i] << " ";
                std::cout << std::dec << "\n";
                
                if (ppvObj) {
                    uint32_t dummy_obj = 0;
                    if (guid[0] == 0x80) { // IID_IDirectDraw (DX1)
                        dummy_obj = handler->create_fake_com_object("IDirectDraw", 50);
                    } else if (guid[0] == 0x77) { // IID_IDirect3D7
                        dummy_obj = handler->create_fake_com_object("IDirect3D7", 50);
                    } else {
                        dummy_obj = handler->create_fake_com_object("GenericCOM", 50);
                    }
                    handler->backend.mem_write(ppvObj, &dummy_obj, 4);
                }
                handler->ctx.set_eax(0); // S_OK
                std::cout << "[API CALL] [OK] IDirectDraw7::QueryInterface -> Wrote Object to 0x" << std::hex << ppvObj << std::dec << "\n";
            } else if (name == "DDRAW.dll!IDirect3D7_Method_4") {
                // HRESULT CreateDevice(REFCLSID rclsid, LPDIRECTDRAWSURFACE7 lpDDS, LPDIRECT3DDEVICE7 *lplpD3DDevice)
                uint32_t lplpD3DDevice = handler->ctx.get_arg(3);
                if (lplpD3DDevice) {
                    uint32_t dummy_device = handler->create_fake_com_object("IDirect3DDevice7", 100);
                    handler->backend.mem_write(lplpD3DDevice, &dummy_device, 4);
                }
                handler->ctx.set_eax(0); // D3D_OK
                std::cout << "\n[API CALL] [OK] IDirect3D7::CreateDevice -> Returned Dummy IDirect3DDevice7 object.\n";
            } else if (name == "DDRAW.dll!IDirectDraw7_Method_4") {
                // Expected by many titles as CreateClipper-style method.
                // COM call stack includes `this` as arg0, so out pointer may be arg3.
                uint32_t arg1 = handler->ctx.get_arg(1);
                uint32_t out_obj2 = handler->ctx.get_arg(2);
                uint32_t out_obj3 = handler->ctx.get_arg(3);
                uint32_t dummy_clipper = handler->create_fake_com_object("IDirectDrawClipper", 20);
                if (arg1 > 0x10000u) handler->backend.mem_write(arg1, &dummy_clipper, 4);
                if (out_obj2) handler->backend.mem_write(out_obj2, &dummy_clipper, 4);
                if (out_obj3) handler->backend.mem_write(out_obj3, &dummy_clipper, 4);
                handler->ctx.set_eax(0); // DD_OK
            } else if (name == "DDRAW.dll!IDirectDraw7_Method_12") {
                // HRESULT GetDisplayMode(LPDDSURFACEDESC2 outDesc)
                uint32_t out_desc = handler->ctx.get_arg(1);
                if (out_desc != 0) {
                    uint32_t ddsd_size = 124;
                    uint32_t ddsd_flags = 0x100F; // CAPS|HEIGHT|WIDTH|PITCH|PIXELFORMAT
                    uint32_t height = 600;
                    uint32_t width = 800;
                    uint32_t pitch = width * 4;
                    uint32_t pf_size = 32;
                    uint32_t pf_flags = 0x40; // DDPF_RGB
                    uint32_t bpp = 32;
                    uint32_t r_mask = 0x00FF0000;
                    uint32_t g_mask = 0x0000FF00;
                    uint32_t b_mask = 0x000000FF;
                    uint32_t a_mask = 0x00000000;
                    handler->backend.mem_write(out_desc + 0, &ddsd_size, 4);
                    handler->backend.mem_write(out_desc + 4, &ddsd_flags, 4);
                    handler->backend.mem_write(out_desc + 8, &height, 4);
                    handler->backend.mem_write(out_desc + 12, &width, 4);
                    handler->backend.mem_write(out_desc + 16, &pitch, 4);
                    handler->backend.mem_write(out_desc + 72, &pf_size, 4);
                    handler->backend.mem_write(out_desc + 76, &pf_flags, 4);
                    handler->backend.mem_write(out_desc + 84, &bpp, 4);
                    handler->backend.mem_write(out_desc + 88, &r_mask, 4);
                    handler->backend.mem_write(out_desc + 92, &g_mask, 4);
                    handler->backend.mem_write(out_desc + 96, &b_mask, 4);
                    handler->backend.mem_write(out_desc + 100, &a_mask, 4);
                }
                handler->ctx.set_eax(0);
            } else if (name == "DDRAW.dll!IDirectDraw7_Method_17") {
                // HRESULT GetVerticalBlankStatus(LPBOOL)
                uint32_t out_bool = handler->ctx.get_arg(1);
                if (out_bool != 0) {
                    uint32_t is_blank = 0;
                    handler->backend.mem_write(out_bool, &is_blank, 4);
                }
                handler->ctx.set_eax(0);
            } else if (name == "DDRAW.dll!IDirectDraw7_Method_21") {
                // HRESULT SetDisplayMode(width, height, bpp, refreshRate, flags)
                uint32_t width = handler->ctx.get_arg(1);
                uint32_t height = handler->ctx.get_arg(2);
                if (handler->ctx.sdl_window && width > 0 && height > 0) {
                    SDL_SetWindowSize(static_cast<SDL_Window*>(handler->ctx.sdl_window),
                                      static_cast<int>(width), static_cast<int>(height));
                }
                handler->ctx.set_eax(0);
            } else if (name == "DDRAW.dll!IDirectDraw7_Method_22") {
                // HRESULT WaitForVerticalBlank(dwFlags, hEvent)
                handler->ctx.set_eax(0);
            } else if (name == "DDRAW.dll!IDirectDraw7_Method_23") {
                // HRESULT GetAvailableVidMem(caps, *total, *free)
                uint32_t out_total = handler->ctx.get_arg(2);
                uint32_t out_free = handler->ctx.get_arg(3);
                uint32_t bytes = 64 * 1024 * 1024;
                if (out_total != 0) handler->backend.mem_write(out_total, &bytes, 4);
                if (out_free != 0) handler->backend.mem_write(out_free, &bytes, 4);
                handler->ctx.set_eax(0);
            } else if (name == "DDRAW.dll!IDirectDraw7_Method_27") {
                // HRESULT GetDeviceIdentifier(DDDEVICEIDENTIFIER2*, flags)
                uint32_t out_device_id = handler->ctx.get_arg(1);
                if (out_device_id != 0) {
                    std::vector<uint8_t> zero(512, 0);
                    handler->backend.mem_write(out_device_id, zero.data(), zero.size());
                }
                handler->ctx.set_eax(0);
            } else if (name == "DDRAW.dll!IDirectDraw7_Method_6") {
                // HRESULT CreateSurface(LPDDSURFACEDESC2, LPDIRECTDRAWSURFACE7*, IUnknown*)
                uint32_t lplpDDSurface = handler->ctx.get_arg(2);
                if (lplpDDSurface) {
                    uint32_t dummy_surface = handler->create_fake_com_object("IDirectDrawSurface7", 50);
                    handler->backend.mem_write(lplpDDSurface, &dummy_surface, 4);
                }
                handler->ctx.set_eax(0); // DD_OK
                std::cout << "\n[API CALL] [OK] IDirectDraw7::CreateSurface -> Wrote surface to 0x" << std::hex << lplpDDSurface << std::dec << ".\n";
            } else if (name == "DDRAW.dll!IDirectDrawSurface7_Method_0") {
                // HRESULT QueryInterface(REFIID riid, void **ppvObj)
                uint32_t riid = handler->ctx.get_arg(1);
                uint32_t ppvObj = handler->ctx.get_arg(2);
                uint8_t guid[16];
                handler->backend.mem_read(riid, guid, 16);
                
                std::cout << "\n[API CALL] IDirectDrawSurface7::QueryInterface requested GUID: ";
                for (int i=0; i<16; i++) std::cout << std::hex << (int)guid[i] << " ";
                std::cout << std::dec << "\n";
                
                if (ppvObj) {
                    uint32_t dummy_obj = 0;
                    if (guid[0] == 0x81) { // IID_IDirectDrawSurface2
                        dummy_obj = handler->create_fake_com_object("IDirectDrawSurface2", 50);
                    } else {
                        dummy_obj = handler->create_fake_com_object("GenericCOM", 50);
                    }
                    handler->backend.mem_write(ppvObj, &dummy_obj, 4);
                }
                handler->ctx.set_eax(0); // S_OK
                std::cout << "[API CALL] [OK] IDirectDrawSurface7::QueryInterface -> Wrote Object to 0x" << std::hex << ppvObj << std::dec << "\n";                
            } else if (name == "DDRAW.dll!IDirectDrawSurface7_Method_25") {
                // HRESULT Lock(LPRECT lpDestRect, LPDDSURFACEDESC2 lpDDSurfaceDesc, DWORD dwFlags, HANDLE hEvent)
                uint32_t surface_ptr = handler->ctx.get_arg(0);
                uint32_t lpDDSurfaceDesc = handler->ctx.get_arg(2);
                
                std::string key = "surface_buffer_" + std::to_string(surface_ptr);
                uint32_t pixel_buffer = 0;
                if (handler->ctx.global_state.find(key) != handler->ctx.global_state.end()) {
                    pixel_buffer = handler->ctx.global_state[key];
                } else {
                    if (handler->ctx.global_state.find("SurfaceHeap") == handler->ctx.global_state.end()) {
                        handler->ctx.global_state["SurfaceHeap"] = 0x30000000;
                        handler->backend.mem_map(0x30000000, 0x10000000, UC_PROT_ALL);
                    }
                    pixel_buffer = handler->ctx.global_state["SurfaceHeap"];
                    handler->ctx.global_state["SurfaceHeap"] += (800 * 600 * 4);
                    handler->ctx.global_state[key] = pixel_buffer;
                    std::cout << "\n[API CALL] Allocated late surface buffer at 0x" << std::hex << pixel_buffer << std::dec << "\n";
                }

	                if (lpDDSurfaceDesc) {
	                    uint32_t height = 600, width = 800;
	                    uint32_t pitch = width * 4;
                        uint32_t ddsd_size = 124;
                        uint32_t ddsd_flags = 0x100F; // CAPS|HEIGHT|WIDTH|PITCH|PIXELFORMAT

                        handler->backend.mem_write(lpDDSurfaceDesc + 0, &ddsd_size, 4);
                        handler->backend.mem_write(lpDDSurfaceDesc + 4, &ddsd_flags, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 8, &height, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 12, &width, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 16, &pitch, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 36, &pixel_buffer, 4);
	                    
                        uint32_t pf_size = 32;
	                    uint32_t pf_flags = 0x40; // DDPF_RGB
	                    uint32_t bpp = 32;
	                    uint32_t r_mask = 0x00FF0000;
	                    uint32_t g_mask = 0x0000FF00;
	                    uint32_t b_mask = 0x000000FF;
                        uint32_t a_mask = 0x00000000;
	                    
                        // DDPIXELFORMAT starts at +72
	                    handler->backend.mem_write(lpDDSurfaceDesc + 72, &pf_size, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 76, &pf_flags, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 84, &bpp, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 88, &r_mask, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 92, &g_mask, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 96, &b_mask, 4);
	                    handler->backend.mem_write(lpDDSurfaceDesc + 100, &a_mask, 4);
                }
                
                handler->ctx.set_eax(0);
                std::cout << "\n[API CALL] [OK] IDirectDrawSurface7::Lock -> Buffer: 0x" << std::hex << pixel_buffer << std::dec << "\n";
            } else if (name == "DDRAW.dll!IDirectDrawSurface7_Method_5") {
                // HRESULT Blt(LPRECT dst, LPDIRECTDRAWSURFACE7 src, LPRECT srcRect, DWORD flags, LPDDBLTFX fx)
                uint32_t dst_surface = handler->ctx.get_arg(0);
                uint32_t src_surface = handler->ctx.get_arg(2);
                std::string dst_key = "surface_buffer_" + std::to_string(dst_surface);
                std::string src_key = "surface_buffer_" + std::to_string(src_surface);
                uint32_t dst_buf = handler->ctx.global_state.count(dst_key) ? static_cast<uint32_t>(handler->ctx.global_state[dst_key]) : handler->ctx.guest_vram;
                uint32_t src_buf = handler->ctx.global_state.count(src_key) ? static_cast<uint32_t>(handler->ctx.global_state[src_key]) : handler->ctx.guest_vram;
                if (dst_buf != src_buf && dst_buf != 0 && src_buf != 0 && handler->ctx.host_vram) {
                    std::vector<uint8_t> tmp(800 * 600 * 4);
                    if (handler->backend.mem_read(src_buf, tmp.data(), tmp.size()) == UC_ERR_OK) {
                        handler->backend.mem_write(dst_buf, tmp.data(), tmp.size());
                    }
                }
                handler->ctx.set_eax(0);
            } else if (name == "DDRAW.dll!IDirectDrawSurface7_Method_11") {
                // HRESULT Flip(LPDIRECTDRAWSURFACE7 targetOverride, DWORD flags)
                handler->ctx.set_eax(0);
            } else if (name == "DDRAW.dll!IDirectDrawSurface7_Method_32") {
                // HRESULT Unlock(LPRECT lpRect)
                uint32_t surface_ptr = handler->ctx.get_arg(0);
                std::string key = "surface_buffer_" + std::to_string(surface_ptr);
                uint32_t source_ptr = handler->ctx.guest_vram;
                if (handler->ctx.global_state.find(key) != handler->ctx.global_state.end()) {
                    source_ptr = static_cast<uint32_t>(handler->ctx.global_state[key]);
                }

                if (handler->ctx.sdl_texture && handler->ctx.sdl_renderer && handler->ctx.host_vram) {
                    constexpr size_t kFrameBytes = 800 * 600 * 4;
                    if (handler->backend.mem_read(source_ptr, handler->ctx.host_vram, kFrameBytes) != UC_ERR_OK &&
                        source_ptr != handler->ctx.guest_vram) {
                        handler->backend.mem_read(handler->ctx.guest_vram, handler->ctx.host_vram, kFrameBytes);
                    }
                    SDL_UpdateTexture(static_cast<SDL_Texture*>(handler->ctx.sdl_texture), nullptr, handler->ctx.host_vram, 800 * 4);
                    SDL_RenderClear(static_cast<SDL_Renderer*>(handler->ctx.sdl_renderer));
                    SDL_RenderCopy(static_cast<SDL_Renderer*>(handler->ctx.sdl_renderer),
                                   static_cast<SDL_Texture*>(handler->ctx.sdl_texture), nullptr, nullptr);
                    SDL_RenderPresent(static_cast<SDL_Renderer*>(handler->ctx.sdl_renderer));
                    SDL_PumpEvents();
                }
                handler->ctx.set_eax(0);
                std::cout << "\n[API CALL] [OK] IDirectDrawSurface7::Unlock (present from 0x" << std::hex
                          << source_ptr << std::dec << ")\n";
            } else if (name == "DDRAW.dll!IDirectDrawSurface7_Method_28" ||
                       name == "DDRAW.dll!IDirectDrawSurface7_Method_31") {
                handler->ctx.set_eax(0);
            } else if (name == "KERNEL32.dll!DirectDrawCreateEx" || name == "KERNEL32.dll!DirectDrawCreate") {
                uint32_t lplpDD = handler->ctx.get_arg(1); // Arg 1 is out-pointer to interface
                if (lplpDD) {
                    uint32_t dummy_ddraw_obj = handler->create_fake_com_object("IDirectDraw7", 50);
                    handler->backend.mem_write(lplpDD, &dummy_ddraw_obj, 4);
                }
                handler->ctx.set_eax(0); // S_OK
                std::cout << "\n[API CALL] [OK] Intercepted DirectDrawCreateEx -> Wrote IDirectDraw7 to 0x" << std::hex << lplpDD << std::dec << "\n";
            } else if (name == "KERNEL32.dll!DirectSoundCreate" || name == "DSOUND.dll!DirectSoundCreate") {
                uint32_t lplpDS = handler->ctx.get_arg(1); // LPDIRECTSOUND*
                if (lplpDS) {
                    uint32_t dummy_ds_obj = handler->create_fake_com_object("IDirectSound", 40);
                    handler->backend.mem_write(lplpDS, &dummy_ds_obj, 4);
                }
                handler->ctx.set_eax(0); // DS_OK
                std::cout << "\n[API CALL] [OK] Intercepted DirectSoundCreate -> Wrote IDirectSound to 0x"
                          << std::hex << lplpDS << std::dec << "\n";
            } else if (name == "KERNEL32.dll!BASS_Init" || name == "BASS.dll!BASS_Init") {
                handler->ctx.set_eax(1);
            } else if (name == "KERNEL32.dll!BASS_SetConfig" || name == "BASS.dll!BASS_SetConfig") {
                handler->ctx.set_eax(1);
            } else if (name == "KERNEL32.dll!BASS_Start" || name == "BASS.dll!BASS_Start" ||
                       name == "KERNEL32.dll!BASS_Free" || name == "BASS.dll!BASS_Free") {
                handler->ctx.set_eax(1);
            } else if (name == "KERNEL32.dll!Direct3DCreate8") {
                uint32_t dummy_d3d_obj = handler->create_fake_com_object("IDirect3D8", 50);
                handler->ctx.set_eax(dummy_d3d_obj); // Returns the interface pointer directly in EAX
                std::cout << "\n[API CALL] [OK] Intercepted Direct3DCreate8 -> Returned Dummy IDirect3D8 Interface.\n";
            } else if (name == "DDRAW.dll!IDirect3D8_Method_5") {
                // HRESULT GetAdapterDisplayMode(UINT Adapter, D3DDISPLAYMODE *pMode)
                uint32_t pMode = handler->ctx.get_arg(1);
                if (pMode) {
                    uint32_t mode_data[4] = {800, 600, 60, 22}; // Width=800, Height=600, RefreshRate=60, Format=D3DFMT_X8R8G8B8 (22)
                    handler->backend.mem_write(pMode, mode_data, 16);
                }
                handler->ctx.set_eax(0); // D3D_OK
                std::cout << "\n[API CALL] [OK] IDirect3D8::GetAdapterDisplayMode spoofed 800x600.\n";
            } else if (name == "USER32.dll!MoveWindow") {
                uint32_t x = handler->ctx.get_arg(1);
                uint32_t y = handler->ctx.get_arg(2);
                uint32_t w = handler->ctx.get_arg(3);
                uint32_t h = handler->ctx.get_arg(4);
                if (handler->ctx.sdl_window && w > 0 && h > 0) {
                    SDL_SetWindowPosition(static_cast<SDL_Window*>(handler->ctx.sdl_window),
                                          static_cast<int>(x), static_cast<int>(y));
                    SDL_SetWindowSize(static_cast<SDL_Window*>(handler->ctx.sdl_window),
                                      static_cast<int>(w), static_cast<int>(h));
                }
                handler->ctx.set_eax(1); // BOOL success
            } else if (name == "USER32.dll!SetTimer") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                uint32_t timer_id = handler->ctx.get_arg(1);
                if (timer_id == 0) {
                    uint32_t top = 1;
                    if (handler->ctx.global_state.find("TimerIdTop") != handler->ctx.global_state.end()) {
                        top = static_cast<uint32_t>(handler->ctx.global_state["TimerIdTop"]);
                    }
                    timer_id = top;
                    handler->ctx.global_state["TimerIdTop"] = top + 1;
                }
                Win32_MSG msg = {};
                msg.hwnd = hwnd;
                msg.message = WM_TIMER;
                msg.wParam = timer_id;
                msg.time = SDL_GetTicks();
                int mx, my;
                SDL_GetMouseState(&mx, &my);
                msg.pt_x = mx;
                msg.pt_y = my;
                g_win32_message_queue.push_back(msg);
                handler->ctx.set_eax(timer_id);
            } else if (name == "USER32.dll!KillTimer") {
                handler->ctx.set_eax(1);
            } else if (name == "USER32.dll!PostMessageA" || name == "USER32.dll!PostMessageW") {
                Win32_MSG msg = {};
                msg.hwnd = handler->ctx.get_arg(0);
                msg.message = handler->ctx.get_arg(1);
                msg.wParam = handler->ctx.get_arg(2);
                msg.lParam = handler->ctx.get_arg(3);
                msg.time = SDL_GetTicks();
                int mx, my;
                SDL_GetMouseState(&mx, &my);
                msg.pt_x = mx;
                msg.pt_y = my;
                g_win32_message_queue.push_back(msg);
                handler->ctx.set_eax(1);
            } else if (name == "KERNEL32.dll!GetCurrentProcess") {
                handler->ctx.set_eax(-1); // Pseudo handle for current process
                std::cout << "\n[API CALL] [OK] Intercepted call to " << name << "\n";
            } else if (name == "KERNEL32.dll!ExitProcess") {
                uint32_t exit_code = handler->ctx.get_arg(0);
                std::cout << "\n[API CALL] [OK] Intercepted call to " << name
                          << " (exit_code=" << exit_code
                          << ") -> stopping emulation.\n";
                // ExitProcess never returns. Force a clean stop path.
                uint32_t finished_eip = 0;
                handler->backend.reg_write(UC_X86_REG_EIP, &finished_eip);
                handler->backend.emu_stop();
                return;
            } else if (name == "KERNEL32.dll!TerminateProcess") {
                uint32_t h_process = handler->ctx.get_arg(0);
                uint32_t exit_code = handler->ctx.get_arg(1);
                handler->ctx.set_eax(1); // success
                if (h_process == 0xFFFFFFFFu) {
                    std::cout << "\n[API CALL] [OK] TerminateProcess(current, exit_code="
                              << exit_code << ") -> stopping emulation.\n";
                    uint32_t finished_eip = 0;
                    handler->backend.reg_write(UC_X86_REG_EIP, &finished_eip);
                    handler->backend.emu_stop();
                    return;
                }
                std::cout << "\n[API CALL] [OK] TerminateProcess(0x" << std::hex << h_process
                          << std::dec << ", " << exit_code << ") mocked as success.\n";
            } else {
                // Default success policy:
                // - COM/DirectX style APIs generally expect HRESULT S_OK (0)
                // - Win32 BOOL style APIs generally use non-zero success
                bool hresult_success = starts_with_ascii_ci(name, "ddraw.dll!") ||
                                       starts_with_ascii_ci(name, "dsound.dll!") ||
                                       starts_with_ascii_ci(name, "d3d8.dll!");
                handler->ctx.set_eax(hresult_success ? 0 : 1);
                if (!is_noisy_fastpath_api(name)) {
                    std::cout << "\n[API CALL] [OK] Intercepted call to " << name << std::endl;
                }
            }
        } else {
            std::cout << "\n[API CALL] [UNKNOWN] Calling LLM API Compiler for " << name << std::endl;
            handler->handle_unknown_api(name, address);
        }
    }
}

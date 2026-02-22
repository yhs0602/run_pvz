#include "api_handler.hpp"
#include <fstream>
#include <filesystem>
#include <dlfcn.h>
#include <unistd.h>
#include <SDL.h>

// --- Win32 Message Mapping ---
constexpr uint32_t WM_QUIT = 0x0012;
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
    {"USER32.dll!GetDesktopWindow", 0},
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
    // DirectX / DirectDraw / Direct3D
    {"KERNEL32.dll!DirectDrawCreate", 12},
    {"KERNEL32.dll!DirectDrawCreateEx", 16},
    {"KERNEL32.dll!Direct3DCreate8", 4},
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
    // Media and Timing (WINMM)
    {"WINMM.dll!timeGetTime", 0},
    // Registry (ADVAPI32)
    {"ADVAPI32.dll!RegOpenKeyExA", 20},
    {"ADVAPI32.dll!RegQueryValueExA", 24},
    {"ADVAPI32.dll!RegCreateKeyExA", 36},
    {"ADVAPI32.dll!RegSetValueExA", 24},
    {"ADVAPI32.dll!RegCloseKey", 4},
    // COM (OLE32)
    {"ole32.dll!CoInitialize", 4}
};

DummyAPIHandler::DummyAPIHandler(uc_engine* engine) : current_addr(FAKE_API_BASE) {
    ctx.uc = engine;
    std::filesystem::create_directories("api_requests");
    std::filesystem::create_directories("api_mocks");
    
    std::cout << "[*] Mapping FAKE_API boundary at 0x" << std::hex << FAKE_API_BASE << std::dec << "\n";
    uc_mem_map(ctx.uc, FAKE_API_BASE, 0x100000, UC_PROT_ALL); // 1MB

    // --- BUILD FAKE KERNEL32.DLL PE HEADER ---
    uint32_t k32_base = 0x76000000;
    uc_mem_map(ctx.uc, k32_base, 0x200000, UC_PROT_ALL);
    
    uint16_t mz_magic = 0x5A4D; // "MZ"
    uc_mem_write(ctx.uc, k32_base, &mz_magic, 2);
    
    uint32_t e_lfanew = 0x40;
    uc_mem_write(ctx.uc, k32_base + 0x3C, &e_lfanew, 4);
    uint32_t signature = 0x00004550; // "PE\0\0"
    uc_mem_write(ctx.uc, k32_base + 0x40, &signature, 4);
    
    uint16_t opt_magic = 0x010B; // PE32
    uc_mem_write(ctx.uc, k32_base + 0x40 + 0x18, &opt_magic, 2);
    
    uint32_t export_dir_rva = 0x1000;
    uint32_t export_dir_size = 0x1000;
    uc_mem_write(ctx.uc, k32_base + 0x40 + 0x18 + 0x60, &export_dir_rva, 4);
    uc_mem_write(ctx.uc, k32_base + 0x40 + 0x18 + 0x64, &export_dir_size, 4);
    
    uint32_t exp_dir[11] = {0, 0, 0, 0x1100, 1, 3, 3, 0x1200, 0x1300, 0x1400};
    uc_mem_write(ctx.uc, k32_base + 0x1000, exp_dir, 40);
    
    const char* dll_name = "KERNEL32.dll";
    uc_mem_write(ctx.uc, k32_base + 0x1100, dll_name, strlen(dll_name) + 1);
    
    const char* f1_name = "GetProcAddress";
    uc_mem_write(ctx.uc, k32_base + 0x1310, f1_name, strlen(f1_name) + 1);
    const char* f2_name = "LoadLibraryA";
    uc_mem_write(ctx.uc, k32_base + 0x1340, f2_name, strlen(f2_name) + 1);
    const char* f3_name = "VirtualAlloc";
    uc_mem_write(ctx.uc, k32_base + 0x1370, f3_name, strlen(f3_name) + 1);
    
    uint32_t addr_names[3] = {0x1310, 0x1340, 0x1370};
    uc_mem_write(ctx.uc, k32_base + 0x1300, addr_names, sizeof(addr_names));
    
    uint16_t ordinals[3] = {0, 1, 2};
    uc_mem_write(ctx.uc, k32_base + 0x1400, ordinals, sizeof(ordinals));
    
    uint32_t addr_GetProcAddress = register_fake_api("KERNEL32.dll!GetProcAddress");
    uint32_t addr_LoadLibraryA = register_fake_api("KERNEL32.dll!LoadLibraryA");
    uint32_t addr_VirtualAlloc = register_fake_api("KERNEL32.dll!VirtualAlloc");
    
    auto write_jmp_stub = [&](uint32_t rva, uint32_t target_addr) {
        uint8_t jmp_stub[5] = {0xE9, 0, 0, 0, 0};
        uint32_t stub_addr = k32_base + rva;
        uint32_t rel_offset = target_addr - (stub_addr + 5);
        memcpy(&jmp_stub[1], &rel_offset, 4);
        uc_mem_write(ctx.uc, stub_addr, jmp_stub, 5);
    };
    
    write_jmp_stub(0x2000, addr_GetProcAddress);
    write_jmp_stub(0x2010, addr_LoadLibraryA);
    write_jmp_stub(0x2020, addr_VirtualAlloc);
    
    uint32_t addr_funcs[3] = {0x2000, 0x2010, 0x2020};
    uc_mem_write(ctx.uc, k32_base + 0x1200, addr_funcs, sizeof(addr_funcs));

    uc_hook trace;
    uc_hook_add(ctx.uc, &trace, UC_HOOK_BLOCK, (void*)hook_api_call, this, 1, 0); // Catch all blocks
}

DummyAPIHandler::~DummyAPIHandler() {
    for (auto& pair : dylib_handles) {
        if (pair.second) dlclose(pair.second);
    }
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
        uc_mem_write(ctx.uc, api_addr, instruction, 3);
    } else {
        uint8_t instruction = 0xC3; // ret
        uc_mem_write(ctx.uc, api_addr, &instruction, 1);
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
    uc_mem_write(ctx.uc, object_addr, &vtable_addr, 4);
    
    // 3. Register fake APIs for each method
    for (int i = 0; i < num_methods; i++) {
        std::string method_name = "DDRAW.dll!" + class_name + "_Method_" + std::to_string(i);
        KNOWN_SIGNATURES[method_name] = 0; // Add to fast-path dynamically
        uint32_t api_addr = register_fake_api(method_name);
        // Write the API address into the VTable at index i
        uc_mem_write(ctx.uc, vtable_addr + (i * 4), &api_addr, 4);
    }
    
    return object_addr;
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
        
        // --- HARDCODED HLE INTERCEPTS ---
        if (name == "USER32.dll!CreateWindowExA" || name == "USER32.dll!CreateWindowExW") {
            int width = handler->ctx.get_arg(6);
            int height = handler->ctx.get_arg(7);
            if (width > 0 && height > 0 && handler->ctx.sdl_window) {
                SDL_SetWindowSize((SDL_Window*)handler->ctx.sdl_window, width, height);
            }
            handler->ctx.set_eax(0x12345678); // Dummy HWND
            
            uint32_t esp;
            uc_reg_read(uc, UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            uc_mem_read(uc, esp, &ret_addr, 4);
            esp += 48 + 4; // 12 args
            uc_reg_write(uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
            return;
        }

        if (name == "USER32.dll!RegisterClassA" || name == "USER32.dll!RegisterClassW" ||
            name == "USER32.dll!RegisterClassExA" || name == "USER32.dll!RegisterClassExW") {
            handler->ctx.set_eax(0xC000); // Dummy ATOM
            
            uint32_t esp;
            uc_reg_read(uc, UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            uc_mem_read(uc, esp, &ret_addr, 4);
            esp += 4 + 4; // 1 arg
            uc_reg_write(uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
            return;
        }

        if (name == "USER32.dll!AdjustWindowRect" || name == "USER32.dll!AdjustWindowRectEx") {
            handler->ctx.set_eax(1); // Success
            
            uint32_t esp;
            uc_reg_read(uc, UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            uc_mem_read(uc, esp, &ret_addr, 4);
            esp += (name.find("Ex") != std::string::npos) ? 16 + 4 : 12 + 4; // 4 args vs 3 args
            uc_reg_write(uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
            return;
        }

        if (name == "USER32.dll!GetClientRect") {
            uint32_t lpRect = handler->ctx.get_arg(1);
            if (lpRect && handler->ctx.sdl_window) {
                int w, h;
                SDL_GetWindowSize((SDL_Window*)handler->ctx.sdl_window, &w, &h);
                uint32_t rect[4] = {0, 0, (uint32_t)w, (uint32_t)h};
                uc_mem_write(uc, lpRect, rect, sizeof(rect));
            }
            handler->ctx.set_eax(1);
            
            uint32_t esp;
            uc_reg_read(uc, UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            uc_mem_read(uc, esp, &ret_addr, 4);
            esp += 8 + 4; // 2 args
            uc_reg_write(uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
            return;
        }

        // --- DIRECTDRAW HLE INTERCEPTS ---
        if (name == "DDRAW.dll!DirectDrawCreate" || name == "DDRAW.dll!DirectDrawCreateEx") {
            int is_ex = (name.find("Ex") != std::string::npos) ? 1 : 0;
            uint32_t lplpDD = is_ex ? handler->ctx.get_arg(1) : handler->ctx.get_arg(1);
            
            uint32_t pDD = handler->create_fake_com_object("IDirectDraw", 40);
            uc_mem_write(uc, lplpDD, &pDD, 4);
            
            handler->ctx.set_eax(0); // DD_OK
            handler->ctx.pop_args(is_ex ? 4 : 3);
            return;
        }

        if (name.find("DDRAW.dll!IDirectDraw_Method_") != std::string::npos) {
            int method_idx = std::stoi(name.substr(name.find_last_of('_') + 1));
            
            if (method_idx == 6 || method_idx == 22) { // CreateSurface
                uint32_t lplpSurface = handler->ctx.get_arg(2);
                uint32_t pSurface = handler->create_fake_com_object("IDDSurface", 45);
                uc_mem_write(uc, lplpSurface, &pSurface, 4);
                std::cout << "[HLE DDRAW] CreateSurface Intercepted\n";
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(4);
                return;
            } else if (method_idx == 20) { // SetDisplayMode
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(6);
                return;
            } else if (method_idx == 21) { // SetCooperativeLevel
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(3);
                return;
            } else if (method_idx == 1 || method_idx == 2) { // AddRef, Release
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(1);
                return;
            } else {
                std::cout << "[HLE DDRAW] Unhandled IDirectDraw method " << method_idx << "\n";
                // Let it crash naturally to discover the exact args
            }
        }

        if (name.find("DDRAW.dll!IDDSurface_Method_") != std::string::npos) {
            int method_idx = std::stoi(name.substr(name.find_last_of('_') + 1));
            
            if (method_idx == 25 || method_idx == 20) { // Lock
                uint32_t lpDDSurfaceDesc = handler->ctx.get_arg(2);
                if (lpDDSurfaceDesc != 0) {
                    uint32_t pitch = 800 * 4;
                    uc_mem_write(uc, lpDDSurfaceDesc + 16, &pitch, 4); 
                    uc_mem_write(uc, lpDDSurfaceDesc + 36, &handler->ctx.guest_vram, 4); 
                }
                std::cout << "[HLE DDRAW] Surface Lock Intercepted\n";
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(5); 
                return;
            } else if (method_idx == 32 || method_idx == 26) { // Unlock
                if (handler->ctx.sdl_texture && handler->ctx.sdl_renderer && handler->ctx.host_vram) {
                    uc_mem_read(uc, handler->ctx.guest_vram, handler->ctx.host_vram, 800 * 600 * 4);
                    
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
                    uint32_t pitch = 800 * 4;
                    uc_mem_write(uc, lpDDSurfaceDesc + 16, &pitch, 4); 
                    uc_mem_write(uc, lpDDSurfaceDesc + 36, &handler->ctx.guest_vram, 4); 
                }
                handler->ctx.set_eax(0);
                handler->ctx.pop_args(2);
                return;
            } else {
                std::cout << "[HLE DDRAW] Unhandled IDDSurface method " << method_idx << "\n";
            }
        }

        if (name == "USER32.dll!GetMessageA" || name == "USER32.dll!PeekMessageA" || 
            name == "USER32.dll!GetMessageW" || name == "USER32.dll!PeekMessageW") {
            
            bool is_peek = (name.find("PeekMessage") != std::string::npos);
            std::cout << "\n[API CALL] [HLE] Intercepted " << name << std::endl;
            
            uint32_t lpMsg = handler->ctx.get_arg(0);
            uint32_t hWnd = handler->ctx.get_arg(1);
            
            SDL_Event event;
            bool has_event = false;
            
            if (is_peek) {
                has_event = SDL_PollEvent(&event);
            } else {
                // GetMessage blocks until an event is available
                // Use WaitEventTimeout to not freeze the whole JIT loop indefinitely
                has_event = SDL_WaitEventTimeout(&event, 50); 
            }

            if (has_event) {
                Win32_MSG msg = {0};
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
                    msg.message = 0; // Ignore
                }

                uc_mem_write(uc, lpMsg, &msg, sizeof(msg));
                handler->ctx.set_eax(msg.message != WM_QUIT ? 1 : 0);
            } else {
                handler->ctx.set_eax(0);
            }

            // Clean up stack and return manually (stdcall)
            uint32_t esp;
            uc_reg_read(uc, UC_X86_REG_ESP, &esp);
            uint32_t ret_addr;
            uc_mem_read(uc, esp, &ret_addr, 4);
            esp += (is_peek ? 24 : 20); // Peek arguments: 5 (20 bytes), Get arguments: 4 (16 bytes) + 4 for ret
            uc_reg_write(uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
            return;
        }

        bool known = (KNOWN_SIGNATURES.find(name) != KNOWN_SIGNATURES.end());
        std::cout << "\n[DEBUG] hook_api_call name='" << name << "', known=" << known << "\n";
        
        if (known) {
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
                    uc_mem_read(uc, lpVersionInformation, &size, 4);
                    if (size >= 20) { // OSVERSIONINFOA is 148 bytes
                        uint32_t major = 6;  // Windows 7 / Vista
                        uint32_t minor = 1;
                        uint32_t build = 7601;
                        uint32_t platformId = 2; // VER_PLATFORM_WIN32_NT
                        uc_mem_write(uc, lpVersionInformation + 4, &major, 4);
                        uc_mem_write(uc, lpVersionInformation + 8, &minor, 4);
                        uc_mem_write(uc, lpVersionInformation + 12, &build, 4);
                        uc_mem_write(uc, lpVersionInformation + 16, &platformId, 4);
                    }
                }
                handler->ctx.set_eax(1);
                std::cout << "\n[API CALL] [OK] GetVersionExA (Spoofed Win7)" << std::endl;
            } else if (name == "KERNEL32.dll!GetProcessHeap") {
                handler->ctx.set_eax(0x11000000); // Dummy Heap Handle
                std::cout << "\n[API CALL] [OK] GetProcessHeap" << std::endl;
            } else if (name == "KERNEL32.dll!HeapCreate") {
                handler->ctx.set_eax(0x11000000); 
                std::cout << "\n[API CALL] [OK] HeapCreate" << std::endl;
            } else if (name == "KERNEL32.dll!HeapAlloc") {
                uint32_t hHeap = handler->ctx.get_arg(0);
                uint32_t dwFlags = handler->ctx.get_arg(1);
                uint32_t dwBytes = handler->ctx.get_arg(2);
                
                // Extremely simple bump allocator
                if (handler->ctx.global_state.find("HeapTop") == handler->ctx.global_state.end()) {
                    handler->ctx.global_state["HeapTop"] = 0x20000000;
                    uc_mem_map(uc, 0x20000000, 0x10000000, UC_PROT_ALL); // 256MB Heap
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
                handler->ctx.global_state["heap_size_" + std::to_string(ptr)] = dwBytes;
                std::cout << "\n[API CALL] [OK] HeapAlloc(" << dwBytes << ") -> 0x" << std::hex << ptr << std::dec << std::endl;
            } else if (name == "KERNEL32.dll!HeapFree") {
                handler->ctx.set_eax(1); // Success
                std::cout << "\n[API CALL] [OK] HeapFree" << std::endl;
            } else if (name == "KERNEL32.dll!GetProcAddress") {
                uint32_t hModule = handler->ctx.get_arg(0);
                uint32_t lpProcName = handler->ctx.get_arg(1);
                
                std::string procName;
                if (lpProcName > 0xFFFF) { // Not an ordinal
                    char buf[256] = {0};
                    uc_mem_read(uc, lpProcName, buf, 255);
                    procName = buf;
                } else {
                    procName = "Ordinal_" + std::to_string(lpProcName);
                }
                
                std::string full_name = "KERNEL32.dll!" + procName;
                
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
            } else if (name == "KERNEL32.dll!EncodePointer" || name == "KERNEL32.dll!DecodePointer") {
                uint32_t ptr = handler->ctx.get_arg(0);
                handler->ctx.set_eax(ptr);
                std::cout << "\n[API CALL] [OK] " << name << "(0x" << std::hex << ptr << std::dec << ") returning unchanged.\n";
            } else if (name == "KERNEL32.dll!FlsGetValue" || name == "KERNEL32.dll!TlsGetValue" || name == "KERNEL32.dll!GetLastError" ||
                       name == "KERNEL32.dll!GetFileVersionInfoSizeA" || name == "KERNEL32.dll!GetFileVersionInfoA" || name == "KERNEL32.dll!VerQueryValueA") {
                handler->ctx.set_eax(0);
                std::cout << "\n[API CALL] [OK] Intercepted call to " << name << " returning 0.\n";
            } else if (name == "KERNEL32.dll!GetEnvironmentStringsW" || name == "KERNEL32.dll!GetCommandLineA" || name == "KERNEL32.dll!GetCommandLineW") {
                handler->ctx.set_eax(0x76001500); // Pointing to guaranteed zeroed memory in our fake PE header
                std::cout << "\n[API CALL] [OK] Intercepted call to " << name << " returning static empty string.\n";
            } else if (name == "KERNEL32.dll!MapViewOfFile") {
                // Return a valid pointer to a dummy 4KB shared memory block mapped at 0x76002000
                uint32_t shared_mem_ptr = 0x76002000;
                uint32_t zero = 0;
                uc_mem_write(handler->ctx.uc, shared_mem_ptr, &zero, 4); // Zero out the first dword so subsequent pointer reads fail safely
                handler->ctx.set_eax(shared_mem_ptr); 
                std::cout << "\n[API CALL] [OK] MapViewOfFile -> Dummy Shared Memory at 0x76002000\n";
            } else if (name == "KERNEL32.dll!DirectDrawCreateEx" || name == "KERNEL32.dll!DirectDrawCreate") {
                uint32_t lplpDD = handler->ctx.get_arg(1); // Arg 1 is out-pointer to interface
                if (lplpDD) {
                    uint32_t dummy_ddraw_obj = handler->create_fake_com_object("IDirectDraw7", 50);
                    uc_mem_write(handler->ctx.uc, lplpDD, &dummy_ddraw_obj, 4);
                }
                handler->ctx.set_eax(0); // S_OK
                std::cout << "\n[API CALL] [OK] Intercepted " << name << " -> Returned Dummy IDirectDraw7 Interface.\n";
            } else if (name == "KERNEL32.dll!Direct3DCreate8") {
                uint32_t dummy_d3d_obj = handler->create_fake_com_object("IDirect3D8", 50);
                handler->ctx.set_eax(dummy_d3d_obj); // Returns the interface pointer directly in EAX
                std::cout << "\n[API CALL] [OK] Intercepted Direct3DCreate8 -> Returned Dummy IDirect3D8 Interface.\n";
            } else if (name == "DDRAW.dll!IDirect3D8_Method_5") {
                // HRESULT GetAdapterDisplayMode(UINT Adapter, D3DDISPLAYMODE *pMode)
                uint32_t pMode = handler->ctx.get_arg(1);
                if (pMode) {
                    uint32_t mode_data[4] = {800, 600, 60, 22}; // Width=800, Height=600, RefreshRate=60, Format=D3DFMT_X8R8G8B8 (22)
                    uc_mem_write(handler->ctx.uc, pMode, mode_data, 16);
                }
                handler->ctx.set_eax(0); // D3D_OK
                std::cout << "\n[API CALL] [OK] IDirect3D8::GetAdapterDisplayMode spoofed 800x600.\n";
            } else if (name == "KERNEL32.dll!GetCurrentProcess") {
                handler->ctx.set_eax(-1); // Pseudo handle for current process
                std::cout << "\n[API CALL] [OK] Intercepted call to " << name << "\n";
            } else if (name == "KERNEL32.dll!TerminateProcess") {
                uint32_t ret_addr = 0;
                uint32_t esp;
                uc_reg_read(handler->ctx.uc, UC_X86_REG_ESP, &esp);
                uc_mem_read(handler->ctx.uc, esp, &ret_addr, 4);
                std::cout << "\n[!] Engine called TerminateProcess! Return address (caller): 0x" << std::hex << ret_addr << std::dec << "\n";
                handler->ctx.set_eax(1);
            } else {
                // For other trivial APIs, return 1 (Success) by default to avoid zero-checks failing
                handler->ctx.set_eax(1);
                std::cout << "\n[API CALL] [OK] Intercepted call to " << name << std::endl;
            }
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

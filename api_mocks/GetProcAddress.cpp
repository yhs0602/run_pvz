#include "api_context.hpp"

#include <cstdint>
#include <string>

static std::string read_ansi_string(uc_engine* uc, uint32_t ptr) {
    if (ptr == 0) {
        return {};
    }

    std::string out;
    out.reserve(64);
    for (uint32_t i = 0; i < 260; ++i) {
        char ch = 0;
        if (uc_mem_read(uc, ptr + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
            break;
        }
        out.push_back(ch);
    }
    return out;
}

static bool module_name_from_handle(uint32_t hModule, std::string& module_name) {
    switch (hModule) {
        case 0x76000000: module_name = "KERNEL32.dll"; return true;
        case 0x77000000: module_name = "ntdll.dll"; return true;
        case 0x75000000: module_name = "USER32.dll"; return true;
        case 0x74000000: module_name = "ole32.dll"; return true;
        case 0x74100000: module_name = "OLEAUT32.dll"; return true;
        case 0x73000000: module_name = "DDRAW.dll"; return true;
        case 0x73100000: module_name = "GDI32.dll"; return true;
        case 0x73200000: module_name = "WINMM.dll"; return true;
        case 0x73300000: module_name = "DSOUND.dll"; return true;
        case 0x73400000: module_name = "BASS.dll"; return true;
        case 0x78000000: module_name = "mscoree.dll"; return true;
        case 0x00400000: module_name = "main.exe"; return true;
        default: module_name.clear(); return false;
    }
}

extern "C" void mock_GetProcAddress(APIContext* ctx) {
    const uint32_t hModule = ctx->get_arg(0);
    const uint32_t lpProcName = ctx->get_arg(1);

    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_MOD_NOT_FOUND = 126u;
    constexpr uint32_t ERROR_PROC_NOT_FOUND = 127u;

    uint32_t result = 0;
    std::string module_name;
    const bool module_known = module_name_from_handle(hModule, module_name);

    if (!module_known) {
        ctx->global_state["LastError"] = ERROR_MOD_NOT_FOUND;
    } else if (lpProcName == 0) {
        ctx->global_state["LastError"] = ERROR_PROC_NOT_FOUND;
    } else {
        std::string proc_name;
        if ((lpProcName & 0xFFFF0000u) == 0) {
            proc_name = "Ordinal_" + std::to_string(lpProcName & 0xFFFFu);
        } else {
            proc_name = read_ansi_string(ctx->uc, lpProcName);
        }

        if (proc_name.empty()) {
            ctx->global_state["LastError"] = ERROR_PROC_NOT_FOUND;
        } else {
            if (module_name == "KERNEL32.dll") {
                if (proc_name == "GetProcAddress") result = 0x76010000u;
                else if (proc_name == "LoadLibraryA") result = 0x76010010u;
                else if (proc_name == "VirtualAlloc") result = 0x76010020u;
                else if (proc_name == "GetModuleHandleA") result = 0x76010030u;
                else if (proc_name == "GetLastError") result = 0x76010040u;
                else if (proc_name == "SetLastError") result = 0x76010050u;
                else if (proc_name == "TlsAlloc") result = 0x76010060u;
                else if (proc_name == "TlsGetValue") result = 0x76010070u;
                else if (proc_name == "TlsSetValue") result = 0x76010080u;
                else if (proc_name == "EncodePointer") result = 0x76010090u;
                else if (proc_name == "DecodePointer") result = 0x760100A0u;
            }

            const std::string key = "GetProcAddress:" + module_name + "!" + proc_name;
            auto it = ctx->global_state.find(key);
            if (it != ctx->global_state.end()) {
                result = static_cast<uint32_t>(it->second);
            } else if (result == 0) {
                const bool is_kernel32 = (module_name == "KERNEL32.dll");
                const std::string next_key = is_kernel32
                    ? "GetProcAddress_next_kernel32"
                    : "GetProcAddress_next_generic";

                uint64_t next_addr = is_kernel32 ? 0x76010100ull : 0x90010000ull;
                auto next_it = ctx->global_state.find(next_key);
                if (next_it != ctx->global_state.end() && next_it->second >= 0x10000ull) {
                    next_addr = next_it->second;
                }

                result = static_cast<uint32_t>(next_addr);
                ctx->global_state[next_key] = next_addr + 0x10ull;
            }

            if (result != 0) {
                ctx->global_state[key] = result;
                uint8_t ret_opcode = 0xC3;
                uc_mem_write(ctx->uc, result, &ret_opcode, 1);
                ctx->global_state["LastError"] = ERROR_SUCCESS;
            } else {
                ctx->global_state["LastError"] = ERROR_PROC_NOT_FOUND;
            }
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
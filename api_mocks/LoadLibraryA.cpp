#include "api_context.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>

extern "C" void mock_LoadLibraryA(APIContext* ctx) {
    const uint32_t lpLibFileName = ctx->get_arg(0);

    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87u;
    constexpr uint32_t ERROR_MOD_NOT_FOUND = 126u;

    uint32_t hModule = 0;
    uint32_t last_error = ERROR_SUCCESS;

    auto to_lower = [](std::string s) -> std::string {
        std::transform(
            s.begin(),
            s.end(),
            s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    };

    if (lpLibFileName == 0) {
        last_error = ERROR_INVALID_PARAMETER;
    } else {
        std::string module_name;
        module_name.reserve(260);

        bool read_ok = true;
        for (uint32_t i = 0; i < 260; ++i) {
            char ch = 0;
            if (uc_mem_read(ctx->uc, lpLibFileName + i, &ch, 1) != UC_ERR_OK) {
                read_ok = false;
                break;
            }
            if (ch == '\0') {
                break;
            }
            module_name.push_back(ch);
        }

        if (!read_ok || module_name.empty()) {
            last_error = read_ok ? ERROR_MOD_NOT_FOUND : ERROR_INVALID_PARAMETER;
        } else {
            module_name = to_lower(module_name);

            const size_t sep_pos = module_name.find_last_of("\\/");
            if (sep_pos != std::string::npos && sep_pos + 1 < module_name.size()) {
                module_name = module_name.substr(sep_pos + 1);
            }

            if (module_name.find('.') == std::string::npos) {
                module_name += ".dll";
            }

            if (module_name == "kernel32.dll") hModule = 0x76000000u;
            else if (module_name == "ntdll.dll") hModule = 0x77000000u;
            else if (module_name == "user32.dll") hModule = 0x75000000u;
            else if (module_name == "mscoree.dll") hModule = 0x78000000u;
            else if (module_name == "ole32.dll") hModule = 0x74000000u;
            else if (module_name == "oleaut32.dll") hModule = 0x74100000u;
            else if (module_name == "ddraw.dll") hModule = 0x73000000u;
            else if (module_name == "gdi32.dll") hModule = 0x73100000u;
            else if (module_name == "winmm.dll") hModule = 0x73200000u;
            else if (module_name == "dsound.dll") hModule = 0x73300000u;
            else if (module_name == "bass.dll") hModule = 0x73400000u;
            else if (module_name == "main.exe" || module_name == "pvz.exe") hModule = 0x00400000u;
            else hModule = 0u;

            if (hModule != 0) {
                const std::string module_key = "LoadLibraryA_module_" + module_name;
                const std::string ref_key = "LoadLibraryA_ref_" + std::to_string(hModule);

                ctx->global_state[module_key] = static_cast<uint64_t>(hModule);

                uint64_t ref_count = 1;
                auto ref_it = ctx->global_state.find(ref_key);
                if (ref_it != ctx->global_state.end()) {
                    ref_count = ref_it->second + 1;
                }
                ctx->global_state[ref_key] = ref_count;

                ctx->handle_map["module_" + module_name] =
                    reinterpret_cast<void*>(static_cast<uintptr_t>(hModule));

                last_error = ERROR_SUCCESS;
            } else {
                last_error = ERROR_MOD_NOT_FOUND;
            }
        }
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(hModule);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 4 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
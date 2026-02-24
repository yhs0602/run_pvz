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
            } else if (name == "KERNEL32.dll!GetLocaleInfoA" || name == "KERNEL32.dll!GetLocaleInfoW") {
                uint32_t locale = handler->ctx.get_arg(0);
                uint32_t lc_type_raw = handler->ctx.get_arg(1);
                uint32_t lp_data = handler->ctx.get_arg(2);
                uint32_t cch_data = handler->ctx.get_arg(3);
                bool wide = (name == "KERNEL32.dll!GetLocaleInfoW");

                constexpr uint32_t LOCALE_NOUSEROVERRIDE = 0x80000000u;
                constexpr uint32_t LOCALE_USE_CP_ACP = 0x40000000u;
                constexpr uint32_t LOCALE_RETURN_NUMBER = 0x20000000u;
                constexpr uint32_t LOCALE_ILANGUAGE = 0x00000001u;
                constexpr uint32_t LOCALE_SLANGUAGE = 0x00000002u;
                constexpr uint32_t LOCALE_SCOUNTRY = 0x00000006u;
                constexpr uint32_t LOCALE_IDEFAULTANSICODEPAGE = 0x00001004u;
                constexpr uint32_t LOCALE_SDECIMAL = 0x0000000Eu;
                constexpr uint32_t LOCALE_STHOUSAND = 0x0000000Fu;
                constexpr uint32_t LOCALE_SGROUPING = 0x00000010u;
                constexpr uint32_t LOCALE_SDATE = 0x0000001Du;
                constexpr uint32_t LOCALE_STIME = 0x0000001Eu;
                constexpr uint32_t LOCALE_SSHORTDATE = 0x0000001Fu;
                constexpr uint32_t LOCALE_SLONGDATE = 0x00000020u;
                constexpr uint32_t LOCALE_SENGLANGUAGE = 0x00001001u;
                constexpr uint32_t LOCALE_SENGCOUNTRY = 0x00001002u;
                constexpr uint32_t LOCALE_SISO639LANGNAME = 0x00000059u;
                constexpr uint32_t LOCALE_SISO3166CTRYNAME = 0x0000005Au;

                uint16_t lang_id = static_cast<uint16_t>(locale & 0xFFFFu);
                bool is_korean = (lang_id == 0x0412u);
                uint32_t lc_type = lc_type_raw & ~(LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP);
                uint32_t base_type = lc_type & ~LOCALE_RETURN_NUMBER;
                uint32_t result = 0;

                if (lc_type & LOCALE_RETURN_NUMBER) {
                    uint32_t numeric = 0;
                    bool known_numeric = true;
                    switch (base_type) {
                        case LOCALE_ILANGUAGE:
                            numeric = is_korean ? 0x0412u : 0x0409u;
                            break;
                        default:
                            known_numeric = false;
                            break;
                    }
                    if (known_numeric) {
                        if (lp_data != 0 && cch_data >= sizeof(uint32_t)) {
                            handler->backend.mem_write(lp_data, &numeric, sizeof(uint32_t));
                            result = sizeof(uint32_t);
                            handler->ctx.global_state["LastError"] = 0;
                        } else if (cch_data == 0) {
                            result = sizeof(uint32_t);
                            handler->ctx.global_state["LastError"] = 0;
                        } else {
                            handler->ctx.global_state["LastError"] = 122; // ERROR_INSUFFICIENT_BUFFER
                        }
                    }
                } else {
                    std::string value;
                    switch (base_type) {
                        case LOCALE_ILANGUAGE: value = is_korean ? "0412" : "0409"; break;
                        case LOCALE_SLANGUAGE: value = is_korean ? "Korean (Korea)" : "English (United States)"; break;
                        case LOCALE_SCOUNTRY: value = is_korean ? "Korea" : "United States"; break;
                        case LOCALE_IDEFAULTANSICODEPAGE: value = is_korean ? "949" : "1252"; break;
                        case LOCALE_SDECIMAL: value = "."; break;
                        case LOCALE_STHOUSAND: value = ","; break;
                        case LOCALE_SGROUPING: value = "3;0"; break;
                        case LOCALE_SDATE: value = is_korean ? "-" : "/"; break;
                        case LOCALE_STIME: value = ":"; break;
                        case LOCALE_SSHORTDATE: value = is_korean ? "yyyy-MM-dd" : "M/d/yyyy"; break;
                        case LOCALE_SLONGDATE: value = is_korean ? "yyyy-MM-dd dddd" : "dddd, MMMM dd, yyyy"; break;
                        case LOCALE_SENGLANGUAGE: value = is_korean ? "Korean" : "English"; break;
                        case LOCALE_SENGCOUNTRY: value = is_korean ? "Korea" : "United States"; break;
                        case LOCALE_SISO639LANGNAME: value = is_korean ? "ko" : "en"; break;
                        case LOCALE_SISO3166CTRYNAME: value = is_korean ? "KR" : "US"; break;
                        default: break;
                    }
                    if (!value.empty()) {
                        uint32_t required = static_cast<uint32_t>(value.size() + 1);
                        if (wide) {
                            if (cch_data == 0) {
                                result = required;
                                handler->ctx.global_state["LastError"] = 0;
                            } else if (lp_data != 0 && cch_data >= required) {
                                std::vector<uint16_t> wbuf(required, 0);
                                for (size_t i = 0; i < value.size(); ++i) {
                                    wbuf[i] = static_cast<uint16_t>(static_cast<unsigned char>(value[i]));
                                }
                                handler->backend.mem_write(lp_data, wbuf.data(), required * sizeof(uint16_t));
                                result = required;
                                handler->ctx.global_state["LastError"] = 0;
                            } else {
                                handler->ctx.global_state["LastError"] = 122;
                            }
                        } else {
                            if (cch_data == 0) {
                                result = required;
                                handler->ctx.global_state["LastError"] = 0;
                            } else if (lp_data != 0 && cch_data >= required) {
                                handler->backend.mem_write(lp_data, value.c_str(), required);
                                result = required;
                                handler->ctx.global_state["LastError"] = 0;
                            } else {
                                handler->ctx.global_state["LastError"] = 122;
                            }
                        }
                    }
                }
                handler->ctx.set_eax(result);
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

                if (dwBytes == 0) dwBytes = 1;
                uint32_t aligned_bytes = (dwBytes + 15u) & ~15u;

                if (handler->ctx.global_state.find("HeapTop") == handler->ctx.global_state.end()) {
                    handler->ctx.global_state["HeapTop"] = kHeapBase;
                    handler->ctx.global_state["HeapLimit"] = kHeapBase + kHeapSize;
                    handler->backend.mem_map(kHeapBase, kHeapSize, UC_PROT_ALL);
                }

                uint32_t ptr = 0;
                auto free_it = g_heap_free_by_size.lower_bound(aligned_bytes);
                if (free_it != g_heap_free_by_size.end()) {
                    uint32_t free_size = free_it->first;
                    ptr = free_it->second;
                    g_heap_free_by_size.erase(free_it);
                    // Split oversized free block so small allocations do not inherit huge payload sizes.
                    if (free_size > aligned_bytes) {
                        uint32_t remain_size = free_size - aligned_bytes;
                        uint32_t remain_ptr = ptr + aligned_bytes;
                        if (remain_size > 0) {
                            g_heap_free_by_size.emplace(remain_size, remain_ptr);
                        }
                    }
                    g_heap_sizes[ptr] = aligned_bytes;
                } else {
                    uint32_t heap_top = static_cast<uint32_t>(handler->ctx.global_state["HeapTop"]);
                    uint32_t heap_limit = static_cast<uint32_t>(handler->ctx.global_state["HeapLimit"]);
                    if (heap_top + aligned_bytes < heap_top || heap_top + aligned_bytes > heap_limit) {
                        handler->ctx.set_eax(0);
                        handler->ctx.global_state["LastError"] = 8; // ERROR_NOT_ENOUGH_MEMORY
                        return;
                    }
                    ptr = heap_top;
                    handler->ctx.global_state["HeapTop"] = heap_top + aligned_bytes;
                    g_heap_sizes[ptr] = aligned_bytes;
                }

                if (dwFlags & 0x00000008u) { // HEAP_ZERO_MEMORY
                    constexpr size_t kZeroChunk = 64 * 1024;
                    static const std::array<uint8_t, kZeroChunk> zeros{};
                    uint32_t zero_off = 0;
                    while (zero_off < aligned_bytes) {
                        size_t chunk = std::min<size_t>(zeros.size(), aligned_bytes - zero_off);
                        handler->backend.mem_write(ptr + zero_off, zeros.data(), chunk);
                        zero_off += static_cast<uint32_t>(chunk);
                    }
                }

                handler->ctx.set_eax(ptr);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!HeapFree") {
                uint32_t lpMem = handler->ctx.get_arg(2);
                auto it = g_heap_sizes.find(lpMem);
                if (it != g_heap_sizes.end()) {
                    g_heap_free_by_size.emplace(it->second, lpMem);
                    g_heap_sizes.erase(it);
                }
                handler->ctx.set_eax(1); // Success
                handler->ctx.global_state["LastError"] = 0;
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
                uint32_t aligned_new = (dwBytes + 15u) & ~15u;

                if (lpMem == 0) {
                    // Windows allows HeapReAlloc(NULL, ..) behavior similar to alloc in some runtimes.
                    if (handler->ctx.global_state.find("HeapTop") == handler->ctx.global_state.end()) {
                        handler->ctx.global_state["HeapTop"] = kHeapBase;
                        handler->ctx.global_state["HeapLimit"] = kHeapBase + kHeapSize;
                        handler->backend.mem_map(kHeapBase, kHeapSize, UC_PROT_ALL);
                    }
                    uint32_t ptr = 0;
                    auto free_it = g_heap_free_by_size.lower_bound(aligned_new);
                    if (free_it != g_heap_free_by_size.end()) {
                        uint32_t free_size = free_it->first;
                        ptr = free_it->second;
                        g_heap_free_by_size.erase(free_it);
                        if (free_size > aligned_new) {
                            uint32_t remain_size = free_size - aligned_new;
                            uint32_t remain_ptr = ptr + aligned_new;
                            if (remain_size > 0) {
                                g_heap_free_by_size.emplace(remain_size, remain_ptr);
                            }
                        }
                        g_heap_sizes[ptr] = aligned_new;
                    } else {
                        uint32_t heap_top = static_cast<uint32_t>(handler->ctx.global_state["HeapTop"]);
                        uint32_t heap_limit = static_cast<uint32_t>(handler->ctx.global_state["HeapLimit"]);
                        if (heap_top + aligned_new < heap_top || heap_top + aligned_new > heap_limit) {
                            handler->ctx.set_eax(0);
                            handler->ctx.global_state["LastError"] = 8;
                            return;
                        }
                        ptr = heap_top;
                        handler->ctx.global_state["HeapTop"] = heap_top + aligned_new;
                        g_heap_sizes[ptr] = aligned_new;
                    }
                    handler->ctx.set_eax(ptr);
                    handler->ctx.global_state["LastError"] = 0;
                } else {
                    auto it = g_heap_sizes.find(lpMem);
                    if (it == g_heap_sizes.end()) {
                        handler->ctx.set_eax(0);
                        handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                    } else {
                        uint32_t old_size = it->second;
                        if (aligned_new <= old_size) {
                            // Shrink in-place and return tail to free list.
                            g_heap_sizes[lpMem] = aligned_new;
                            if (old_size > aligned_new) {
                                uint32_t remain_ptr = lpMem + aligned_new;
                                uint32_t remain_size = old_size - aligned_new;
                                if (remain_size > 0) {
                                    g_heap_free_by_size.emplace(remain_size, remain_ptr);
                                }
                            }
                            handler->ctx.set_eax(lpMem);
                            handler->ctx.global_state["LastError"] = 0;
                        } else {
                            if (handler->ctx.global_state.find("HeapTop") == handler->ctx.global_state.end()) {
                                handler->ctx.global_state["HeapTop"] = kHeapBase;
                                handler->ctx.global_state["HeapLimit"] = kHeapBase + kHeapSize;
                                handler->backend.mem_map(kHeapBase, kHeapSize, UC_PROT_ALL);
                            }
                            uint32_t new_ptr = 0;
                            auto free_it = g_heap_free_by_size.lower_bound(aligned_new);
                            if (free_it != g_heap_free_by_size.end()) {
                                uint32_t free_size = free_it->first;
                                new_ptr = free_it->second;
                                g_heap_free_by_size.erase(free_it);
                                if (free_size > aligned_new) {
                                    uint32_t remain_size = free_size - aligned_new;
                                    uint32_t remain_ptr = new_ptr + aligned_new;
                                    if (remain_size > 0) {
                                        g_heap_free_by_size.emplace(remain_size, remain_ptr);
                                    }
                                }
                                g_heap_sizes[new_ptr] = aligned_new;
                            } else {
                                uint32_t heap_top = static_cast<uint32_t>(handler->ctx.global_state["HeapTop"]);
                                uint32_t heap_limit = static_cast<uint32_t>(handler->ctx.global_state["HeapLimit"]);
                                if (heap_top + aligned_new < heap_top || heap_top + aligned_new > heap_limit) {
                                    handler->ctx.set_eax(0);
                                    handler->ctx.global_state["LastError"] = 8;
                                    return;
                                }
                                new_ptr = heap_top;
                                handler->ctx.global_state["HeapTop"] = heap_top + aligned_new;
                                g_heap_sizes[new_ptr] = aligned_new;
                            }

                            // Copy in chunks to avoid large host allocations.
                            constexpr size_t kCopyChunk = 64 * 1024;
                            std::array<uint8_t, kCopyChunk> temp{};
                            uint32_t copied = 0;
                            while (copied < old_size) {
                                size_t chunk = std::min<size_t>(kCopyChunk, old_size - copied);
                                handler->backend.mem_read(lpMem + copied, temp.data(), chunk);
                                handler->backend.mem_write(new_ptr + copied, temp.data(), chunk);
                                copied += static_cast<uint32_t>(chunk);
                            }

                            if (dwFlags & 0x00000008u) { // HEAP_ZERO_MEMORY
                                constexpr size_t kZeroChunk = 64 * 1024;
                                static const std::array<uint8_t, kZeroChunk> zeros{};
                                uint32_t remain = aligned_new - old_size;
                                uint32_t off = 0;
                                while (off < remain) {
                                    size_t chunk = std::min<size_t>(zeros.size(), remain - off);
                                    handler->backend.mem_write(new_ptr + old_size + off, zeros.data(), chunk);
                                    off += static_cast<uint32_t>(chunk);
                                }
                            }

                            g_heap_free_by_size.emplace(old_size, lpMem);
                            g_heap_sizes.erase(lpMem);
                            handler->ctx.set_eax(new_ptr);
                            handler->ctx.global_state["LastError"] = 0;
                        }
                    }
                }
            } else if (name == "KERNEL32.dll!FindFirstFileA") {
                uint32_t lpFileName = handler->ctx.get_arg(0);
                uint32_t lpFindFileData = handler->ctx.get_arg(1);
                std::string guest_path = read_guest_c_string(handler->ctx, lpFileName, 1024);

                std::string normalized = guest_path;
                std::replace(normalized.begin(), normalized.end(), '/', '\\');
                size_t slash = normalized.find_last_of('\\');
                std::string dir_part = (slash == std::string::npos) ? "." : normalized.substr(0, slash);
                std::string pattern = (slash == std::string::npos) ? normalized : normalized.substr(slash + 1);
                if (pattern.empty()) pattern = "*";

                std::vector<FindFileEntry> matches;
                std::string host_exact = resolve_guest_path_to_host(normalized, handler->process_base_dir);
                if (host_exact.empty()) {
                    std::string host_dir = resolve_guest_path_to_host(dir_part, handler->process_base_dir);
                    if (!host_dir.empty()) {
                        std::error_code ec;
                        for (const auto& de : std::filesystem::directory_iterator(host_dir, ec)) {
                            if (ec) break;
                            std::string file_name = de.path().filename().string();
                            if (!wildcard_match_ascii_ci(pattern, file_name)) continue;
                            FindFileEntry entry;
                            entry.file_name = file_name;
                            entry.is_dir = de.is_directory(ec);
                            if (!entry.is_dir) {
                                entry.file_size = de.file_size(ec);
                                if (ec) entry.file_size = 0;
                            }
                            matches.push_back(std::move(entry));
                        }
                    }
                } else {
                    std::error_code ec;
                    std::filesystem::path p(host_exact);
                    FindFileEntry entry;
                    entry.file_name = p.filename().string();
                    entry.is_dir = std::filesystem::is_directory(p, ec);
                    if (!entry.is_dir) {
                        entry.file_size = std::filesystem::file_size(p, ec);
                        if (ec) entry.file_size = 0;
                    }
                    matches.push_back(std::move(entry));
                }

                if (matches.empty()) {
                    handler->ctx.set_eax(0xFFFFFFFFu); // INVALID_HANDLE_VALUE
                    handler->ctx.global_state["LastError"] = 2; // ERROR_FILE_NOT_FOUND
                } else {
                    auto* fh = new FindHandle();
                    fh->entries = std::move(matches);
                    fh->index = 0;
                    uint32_t handle = 0x6000;
                    if (handler->ctx.global_state.find("FindHandleTop") != handler->ctx.global_state.end()) {
                        handle = static_cast<uint32_t>(handler->ctx.global_state["FindHandleTop"]);
                    }
                    handler->ctx.global_state["FindHandleTop"] = handle + 4;
                    handler->ctx.handle_map["find_" + std::to_string(handle)] = fh;
                    write_win32_find_data_a(handler->ctx, lpFindFileData, fh->entries[0]);
                    handler->ctx.set_eax(handle);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "KERNEL32.dll!FindNextFileA") {
                uint32_t hFind = handler->ctx.get_arg(0);
                uint32_t lpFindFileData = handler->ctx.get_arg(1);
                auto itf = handler->ctx.handle_map.find("find_" + std::to_string(hFind));
                if (itf == handler->ctx.handle_map.end()) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                } else {
                    auto* fh = static_cast<FindHandle*>(itf->second);
                    if (fh->index + 1 >= fh->entries.size()) {
                        handler->ctx.set_eax(0);
                        handler->ctx.global_state["LastError"] = 18; // ERROR_NO_MORE_FILES
                    } else {
                        fh->index += 1;
                        write_win32_find_data_a(handler->ctx, lpFindFileData, fh->entries[fh->index]);
                        handler->ctx.set_eax(1);
                        handler->ctx.global_state["LastError"] = 0;
                    }
                }
            } else if (name == "KERNEL32.dll!FindClose") {
                uint32_t hFind = handler->ctx.get_arg(0);
                auto itf = handler->ctx.handle_map.find("find_" + std::to_string(hFind));
                if (itf == handler->ctx.handle_map.end()) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                } else {
                    delete static_cast<FindHandle*>(itf->second);
                    handler->ctx.handle_map.erase(itf);
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "KERNEL32.dll!CreateFileA") {
                uint32_t lpFileName = handler->ctx.get_arg(0);
                uint32_t creationDisposition = handler->ctx.get_arg(4);
                std::string guest_path = read_guest_c_string(handler->ctx, lpFileName, 1024);
                std::string normalized_guest_path = guest_path;
                std::replace(normalized_guest_path.begin(), normalized_guest_path.end(), '\\', '/');
                std::transform(normalized_guest_path.begin(), normalized_guest_path.end(), normalized_guest_path.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                handler->maybe_start_eip_hot_sample(normalized_guest_path);
                std::string host_path = resolve_guest_path_to_host(guest_path, handler->process_base_dir);
                if (host_path.empty()) {
                    // Some PvZ builds probe adlist/popc registry files that may not exist yet.
                    bool allow_virtual = (normalized_guest_path == "adlist.txt" ||
                                          normalized_guest_path == "vhwb.dat" ||
                                          normalized_guest_path == "vhw.dat" ||
                                          normalized_guest_path == "../popcreg.dat" ||
                                          normalized_guest_path == "popcreg.dat" ||
                                          normalized_guest_path == "c:/windows/system32/" ||
                                          normalized_guest_path == "windows/system32/");
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
                uint32_t low = handler->ctx.get_arg(1);
                uint32_t lpDistanceToMoveHigh = handler->ctx.get_arg(2);
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
                    int64_t distance = static_cast<int64_t>(static_cast<int32_t>(low));
                    if (lpDistanceToMoveHigh != 0) {
                        int32_t high = 0;
                        handler->backend.mem_read(lpDistanceToMoveHigh, &high, 4);
                        distance = (static_cast<int64_t>(high) << 32) | static_cast<uint64_t>(low);
                    }
                    int64_t next = base + distance;
                    if (next < 0) next = 0;
                    fh->pos = static_cast<size_t>(next);
                    uint32_t out_low = static_cast<uint32_t>(static_cast<uint64_t>(fh->pos) & 0xFFFFFFFFu);
                    if (lpDistanceToMoveHigh != 0) {
                        uint32_t out_high = static_cast<uint32_t>((static_cast<uint64_t>(fh->pos) >> 32) & 0xFFFFFFFFu);
                        handler->backend.mem_write(lpDistanceToMoveHigh, &out_high, 4);
                    }
                    handler->ctx.set_eax(out_low);
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
                    auto itfind = handler->ctx.handle_map.find("find_" + std::to_string(h));
                    if (itfind != handler->ctx.handle_map.end()) {
                        delete static_cast<FindHandle*>(itfind->second);
                        handler->ctx.handle_map.erase(itfind);
                        handler->ctx.set_eax(1);
                        handler->ctx.global_state["LastError"] = 0;
                        return;
                    }
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
                handler->cleanup_process_state();
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
                uint32_t view_ptr = 0;
                auto free_it = g_mapview_free_by_size.lower_bound(aligned);
                if (free_it != g_mapview_free_by_size.end()) {
                    uint32_t free_size = free_it->first;
                    view_ptr = free_it->second;
                    g_mapview_free_by_size.erase(free_it);
                    if (free_size > aligned) {
                        uint32_t remain_size = free_size - aligned;
                        uint32_t remain_ptr = view_ptr + aligned;
                        if (remain_size > 0) {
                            g_mapview_free_by_size.emplace(remain_size, remain_ptr);
                        }
                    }
                } else {
                    view_ptr = static_cast<uint32_t>(handler->ctx.global_state["MapViewTop"]);
                    uint32_t limit = static_cast<uint32_t>(handler->ctx.global_state["MapViewLimit"]);
                    if (view_ptr + aligned < view_ptr || view_ptr + aligned > limit) {
                        handler->ctx.set_eax(0);
                        handler->ctx.global_state["LastError"] = 8; // ERROR_NOT_ENOUGH_MEMORY
                        return;
                    }
                    handler->ctx.global_state["MapViewTop"] = view_ptr + aligned;
                }
                g_mapview_live_sizes[view_ptr] = aligned;

                // Zero-fill mapped region in chunks to avoid large transient allocations.
                constexpr size_t kZeroChunk = 64 * 1024;
                static const std::array<uint8_t, kZeroChunk> zeros{};
                uint32_t zero_off = 0;
                while (zero_off < aligned) {
                    size_t chunk = std::min<size_t>(zeros.size(), aligned - zero_off);
                    handler->backend.mem_write(view_ptr + zero_off, zeros.data(), chunk);
                    zero_off += static_cast<uint32_t>(chunk);
                }

                if (source && offset < source->size()) {
                    size_t available = source->size() - static_cast<size_t>(offset);
                    size_t to_copy = std::min<size_t>(available, map_size);
                    if (to_copy > 0) {
                        constexpr size_t kCopyChunk = 64 * 1024;
                        size_t copied = 0;
                        while (copied < to_copy) {
                            size_t chunk = std::min<size_t>(kCopyChunk, to_copy - copied);
                            handler->backend.mem_write(view_ptr + copied, source->data() + static_cast<size_t>(offset) + copied, chunk);
                            copied += chunk;
                        }
                    }
                }

                handler->ctx.set_eax(view_ptr);
                handler->ctx.global_state["LastError"] = 0;
                std::cout << "\n[API CALL] [FILEMAP] MapViewOfFile(hMap=0x" << std::hex << hMap
                          << ", off=0x" << offset << ", size=0x" << map_size
                          << ") -> 0x" << view_ptr << std::dec << "\n";
            } else if (name == "KERNEL32.dll!UnmapViewOfFile") {
                uint32_t lpBaseAddress = handler->ctx.get_arg(0);
                auto itv = g_mapview_live_sizes.find(lpBaseAddress);
                if (itv != g_mapview_live_sizes.end()) {
                    g_mapview_free_by_size.emplace(itv->second, lpBaseAddress);
                    g_mapview_live_sizes.erase(itv);
                }
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
            } else if (name == "USER32.dll!RegisterWindowMessageA" || name == "USER32.dll!RegisterWindowMessageW") {
                uint32_t lpString = handler->ctx.get_arg(0);
                bool wide = (name == "USER32.dll!RegisterWindowMessageW");
                std::string msg_name = wide
                    ? read_guest_w_string(handler->ctx, lpString, 256)
                    : read_guest_c_string(handler->ctx, lpString, 256);
                msg_name = to_lower_ascii(msg_name);
                if (msg_name.empty()) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 87; // ERROR_INVALID_PARAMETER
                } else {
                    std::string key = "RegWinMsg:" + msg_name;
                    uint32_t msg_id = 0;
                    auto it = handler->ctx.global_state.find(key);
                    if (it != handler->ctx.global_state.end()) {
                        msg_id = static_cast<uint32_t>(it->second);
                    } else {
                        uint32_t top = 0xC000u;
                        auto it_top = handler->ctx.global_state.find("RegWinMsgTop");
                        if (it_top != handler->ctx.global_state.end()) {
                            top = static_cast<uint32_t>(it_top->second);
                        }
                        if (top > 0xFFFFu) {
                            handler->ctx.set_eax(0);
                            handler->ctx.global_state["LastError"] = 8; // ERROR_NOT_ENOUGH_MEMORY (id space exhausted)
                            return;
                        }
                        msg_id = top;
                        handler->ctx.global_state["RegWinMsgTop"] = top + 1;
                        handler->ctx.global_state[key] = msg_id;
                        std::cout << "[API CALL] [USER32] RegisterWindowMessage '" << msg_name
                                  << "' -> 0x" << std::hex << msg_id << std::dec << "\n";
                    }
                    handler->ctx.set_eax(msg_id);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "USER32.dll!TranslateMessage") {
                handler->ctx.set_eax(1);
            } else if (name == "USER32.dll!DispatchMessageA" || name == "USER32.dll!DispatchMessageW") {
                handler->ctx.set_eax(0);
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
                enqueue_win32_message(msg);
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
                enqueue_win32_message(msg);

                // Cooperative wakeup: many bootstrap paths wait on an event that the
                // worker thread sets when it posts into the UI queue.
                for (auto& kv : handler->ctx.handle_map) {
                    if (kv.first.rfind("event_", 0) == 0) {
                        static_cast<EventHandle*>(kv.second)->signaled = true;
                    }
                }
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
                handler->cleanup_process_state();
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
                    handler->cleanup_process_state();
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

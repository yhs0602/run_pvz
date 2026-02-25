        if (handler->dispatch_dylib_mock(name)) {
        } else if (known) {
            if (name == "KERNEL32.dll!GetLastError") {
                uint32_t last_error = handler->ctx.global_state["LastError"];
                handler->ctx.set_eax(last_error);
            } else if (name == "KERNEL32.dll!SetLastError") {
                uint32_t err_code = handler->ctx.get_arg(0);
                handler->ctx.global_state["LastError"] = err_code;
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
                            heap_push_free_block(remain_size, remain_ptr);
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
                    heap_push_free_block(it->second, lpMem);
                    g_heap_sizes.erase(it);
                    heap_maybe_reset_if_idle(handler->ctx);
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
                                heap_push_free_block(remain_size, remain_ptr);
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
                                    heap_push_free_block(remain_size, remain_ptr);
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
                                        heap_push_free_block(remain_size, remain_ptr);
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

                            heap_push_free_block(old_size, lpMem);
                            g_heap_sizes.erase(lpMem);
                            heap_maybe_reset_if_idle(handler->ctx);
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
                if (thread_mock_trace_enabled()) {
                    std::cout << "[THREAD MOCK] CreateEvent(handle=0x" << std::hex << handle
                              << ", manual=" << (ev->manual_reset ? 1 : 0)
                              << ", initial=" << (ev->signaled ? 1 : 0) << std::dec << ")\n";
                }
            } else if (name == "KERNEL32.dll!CreateThread") {
                if (env_truthy("PVZ_CREATE_THREAD_FAIL")) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 8; // ERROR_NOT_ENOUGH_MEMORY
                    return;
                }
                uint32_t lpStartAddress = handler->ctx.get_arg(2);
                uint32_t lpParameter = handler->ctx.get_arg(3);
                uint32_t dwStackSize = handler->ctx.get_arg(1);
                uint32_t dwCreationFlags = handler->ctx.get_arg(4);
                uint32_t lpThreadId = handler->ctx.get_arg(5);
                static const bool fast_worker_enabled = env_truthy("PVZ_FAST_WORKER_THREAD");
                static const int fast_worker_create_cap = env_int(
                    "PVZ_WORKER_THREAD_CREATE_CAP",
                    fast_worker_enabled ? 512 : 0);
                if (fast_worker_create_cap > 0 && lpStartAddress == 0x5d5dc0u) {
                    uint64_t created = 0;
                    auto it_created = handler->ctx.global_state.find("FastWorkerCreateCount");
                    if (it_created != handler->ctx.global_state.end()) {
                        created = it_created->second;
                    }
                    if (created >= static_cast<uint64_t>(fast_worker_create_cap)) {
                        handler->ctx.set_eax(0);
                        handler->ctx.global_state["LastError"] = 8; // ERROR_NOT_ENOUGH_MEMORY
                        static uint64_t fast_cap_log_count = 0;
                        fast_cap_log_count++;
                        if (fast_cap_log_count <= 16 || (fast_cap_log_count % 512u) == 0u) {
                            std::cout << "[THREAD MOCK] Fast-worker CreateThread cap hit (start=0x"
                                      << std::hex << lpStartAddress << ", cap=" << std::dec
                                      << fast_worker_create_cap << ")\n";
                        }
                        return;
                    }
                    handler->ctx.global_state["FastWorkerCreateCount"] = created + 1;
                }
                static const int thread_handle_cap = env_int("PVZ_THREAD_HANDLE_CAP", 8192);
                if (thread_handle_cap > 0 && handler->thread_handle_count() >= static_cast<size_t>(thread_handle_cap)) {
                    size_t target_keep = static_cast<size_t>(std::max(1, thread_handle_cap - 1));
                    size_t reaped = handler->reap_finished_thread_handles(target_keep);
                    if (thread_mock_trace_enabled() && reaped > 0) {
                        std::cout << "[THREAD MOCK] reaped finished thread handles=" << reaped
                                  << " (count=" << handler->thread_handle_count() << ")\n";
                    }
                    if (handler->thread_handle_count() >= static_cast<size_t>(thread_handle_cap)) {
                        handler->ctx.set_eax(0);
                        handler->ctx.global_state["LastError"] = 8; // ERROR_NOT_ENOUGH_MEMORY
                        static uint64_t cap_block_log_count = 0;
                        cap_block_log_count++;
                        if (thread_mock_trace_enabled() ||
                            cap_block_log_count <= 16 ||
                            (cap_block_log_count % 512u) == 0u) {
                            std::cout << "[THREAD MOCK] CreateThread blocked by handle cap="
                                      << thread_handle_cap << " live_handles="
                                      << handler->thread_handle_count() << "\n";
                        }
                        return;
                    }
                }
                uint32_t handle = 0x8000;
                if (handler->ctx.global_state.find("ThreadHandleTop") == handler->ctx.global_state.end()) {
                    handler->ctx.global_state["ThreadHandleTop"] = handle;
                } else {
                    handle = static_cast<uint32_t>(handler->ctx.global_state["ThreadHandleTop"]);
                }
                handler->ctx.global_state["ThreadHandleTop"] = handle + 4;
                uint32_t tid = handle;
                if (lpThreadId != 0) {
                    handler->backend.mem_write(lpThreadId, &tid, 4);
                }
                auto* th = new ThreadHandle();
                th->start_address = lpStartAddress;
                th->parameter = lpParameter;
                th->thread_id = tid;
                th->started = false;
                th->finished = false;
                handler->ctx.handle_map["thread_" + std::to_string(handle)] = th;
                handler->note_thread_handle_created();
                g_thread_start_to_handle[lpStartAddress] = handle;
                if ((dwCreationFlags & 0x4u) == 0 && handler->coop_threads_enabled()) {
                    if (!handler->coop_spawn_thread(handle, lpStartAddress, lpParameter, dwStackSize)) {
                        if (thread_mock_trace_enabled()) {
                            std::cout << "[THREAD MOCK] coop spawn failed for handle=0x"
                                      << std::hex << handle << std::dec << "\n";
                        }
                        if (handler->coop_fail_create_on_spawn_failure()) {
                            g_thread_start_to_handle.erase(lpStartAddress);
                            handler->ctx.handle_map.erase("thread_" + std::to_string(handle));
                            delete th;
                            handler->note_thread_handle_closed();
                            handler->ctx.set_eax(0);
                            handler->ctx.global_state["LastError"] = 8; // ERROR_NOT_ENOUGH_MEMORY
                            return;
                        }
                    } else {
                        handler->coop_request_yield();
                        // Do not emu_stop() here: stopping before the API stub returns
                        // re-enters the same CreateThread call on next slice.
                        // Yield is handled at timeslice boundary by the coop scheduler.
                    }
                }
                // Legacy compatibility knob: some earlier experiments primed the
                // thread parameter block with sentinel ones. Keep it opt-in because
                // many real thread entry structs use offset 0/4 as meaningful fields.
                if (lpParameter != 0 && env_truthy("PVZ_CREATE_THREAD_PRIME_PARAM")) {
                    uint32_t one = 1;
                    handler->backend.mem_write(lpParameter, &one, 4);
                    handler->backend.mem_write(lpParameter + 4, &one, 4);
                }
                static uint64_t create_thread_log_count = 0;
                create_thread_log_count++;
                if (thread_mock_trace_enabled() ||
                    create_thread_log_count <= 32 ||
                    (create_thread_log_count % 1024u) == 0u) {
                    std::cout << "\n[API CALL] [OK] CreateThread(start=0x" << std::hex << lpStartAddress
                              << ", param=0x" << lpParameter << ", handle=0x" << handle
                              << ", flags=0x" << dwCreationFlags << std::dec << ")\n";
                }
                if (thread_mock_trace_enabled()) {
                    std::cout << "[THREAD MOCK] registered thread handle=0x" << std::hex << handle
                              << " start=0x" << lpStartAddress << " param=0x" << lpParameter
                              << " stack=0x" << dwStackSize << " flags=0x" << dwCreationFlags
                              << std::dec << "\n";
                }
                handler->ctx.set_eax(handle);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!SetEvent") {
                uint32_t h = handler->ctx.get_arg(0);
                auto it = handler->ctx.handle_map.find("event_" + std::to_string(h));
                if (it != handler->ctx.handle_map.end()) {
                    auto* ev = static_cast<EventHandle*>(it->second);
                    ev->signaled = true;
                    size_t woke = 0;
                    if (handler->coop_threads_enabled()) {
                        size_t max_wake = ev->manual_reset ? std::numeric_limits<size_t>::max() : 1u;
                        woke = handler->coop_wake_handle_waiters(h, max_wake);
                    }
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                    if (thread_mock_trace_enabled()) {
                        std::cout << "[THREAD MOCK] SetEvent(handle=0x" << std::hex << h
                                  << ") -> signaled"
                                  << (handler->coop_threads_enabled() ? (", woke=" + std::to_string(woke)) : "")
                                  << "\n" << std::dec;
                    }
                } else {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6;
                    if (thread_mock_trace_enabled()) {
                        std::cout << "[THREAD MOCK] SetEvent(handle=0x" << std::hex << h
                                  << ") -> invalid\n" << std::dec;
                    }
                }
            } else if (name == "KERNEL32.dll!ResetEvent") {
                uint32_t h = handler->ctx.get_arg(0);
                auto it = handler->ctx.handle_map.find("event_" + std::to_string(h));
                if (it != handler->ctx.handle_map.end()) {
                    static_cast<EventHandle*>(it->second)->signaled = false;
                    handler->ctx.set_eax(1);
                    handler->ctx.global_state["LastError"] = 0;
                    if (thread_mock_trace_enabled()) {
                        std::cout << "[THREAD MOCK] ResetEvent(handle=0x" << std::hex << h
                                  << ") -> nonsignaled\n" << std::dec;
                    }
                } else {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6;
                    if (thread_mock_trace_enabled()) {
                        std::cout << "[THREAD MOCK] ResetEvent(handle=0x" << std::hex << h
                                  << ") -> invalid\n" << std::dec;
                    }
                }
            } else if (name == "KERNEL32.dll!WaitForSingleObject") {
                uint32_t h = handler->ctx.get_arg(0);
                uint32_t timeout_ms = handler->ctx.get_arg(1);
                auto it = handler->ctx.handle_map.find("event_" + std::to_string(h));
                uint32_t wait_result = 0; // WAIT_OBJECT_0
                if (it != handler->ctx.handle_map.end()) {
                    auto* ev = static_cast<EventHandle*>(it->second);
                    bool signaled_before = ev->signaled;
                    if (ev->signaled) {
                        wait_result = 0; // WAIT_OBJECT_0
                        if (!ev->manual_reset) ev->signaled = false;
                    } else {
                        if (timeout_ms == 0u) {
                            wait_result = 0x102; // WAIT_TIMEOUT
                        } else if (handler->coop_threads_enabled()) {
                            if (handler->coop_block_current_thread_on_handle_wait(h)) {
                                handler->coop_request_yield();
                                handler->backend.emu_stop();
                                return;
                            }
                            // Fallback for unexpected cooperative state mismatch.
                            wait_result = (timeout_ms == 0xFFFFFFFFu) ? 0u : 0x102u;
                        } else {
                            // Legacy non-coop fallback.
                            wait_result = (timeout_ms == 0xFFFFFFFFu) ? 0 : 0x102;
                        }
                    }
                    handler->ctx.global_state["LastError"] = 0;
                    if (thread_mock_trace_enabled()) {
                        auto* ev = static_cast<EventHandle*>(it->second);
                        std::cout << "[THREAD MOCK] WaitForSingleObject(event=0x" << std::hex << h
                                  << ", manual=" << (ev->manual_reset ? 1 : 0)
                                  << ", signaled_before=" << (signaled_before ? 1 : 0)
                                  << ", timeout=" << std::dec << timeout_ms
                                  << ") -> 0x" << std::hex << wait_result << std::dec << "\n";
                    }
                    if (handler->coop_threads_enabled() && timeout_ms != 0) {
                        handler->coop_request_yield();
                    }
                } else if (auto it_thread = handler->ctx.handle_map.find("thread_" + std::to_string(h));
                           it_thread != handler->ctx.handle_map.end()) {
                    auto* th = static_cast<ThreadHandle*>(it_thread->second);
                    th->finished = handler->coop_is_thread_finished(h);
                    if (th->finished) {
                        wait_result = 0; // WAIT_OBJECT_0
                    } else if (timeout_ms == 0) {
                        wait_result = 0x102; // WAIT_TIMEOUT
                    } else if (handler->coop_threads_enabled()) {
                        if (handler->coop_block_current_thread_on_handle_wait(h)) {
                            handler->coop_request_yield();
                            handler->backend.emu_stop();
                            return;
                        }
                        wait_result = 0x102;
                    } else {
                        // Non-cooperative fallback: keep legacy behavior.
                        wait_result = 0;
                    }
                    handler->ctx.global_state["LastError"] = 0;
                    if (thread_mock_trace_enabled()) {
                        std::cout << "[THREAD MOCK] WaitForSingleObject(thread=0x" << std::hex << h
                                  << ", start=0x" << th->start_address
                                  << ", started=" << (th->started ? 1 : 0)
                                  << ", finished=" << (th->finished ? 1 : 0)
                                  << ", timeout=" << std::dec << timeout_ms
                                  << ") -> 0x" << std::hex << wait_result << std::dec << "\n";
                    }
                } else {
                    // Treat non-event handles as already-signaled for compatibility.
                    wait_result = 0; // WAIT_OBJECT_0
                    handler->ctx.global_state["LastError"] = 0;
                }
                handler->ctx.set_eax(wait_result);
                static uint64_t wait_log_count = 0;
                wait_log_count++;
                if (thread_mock_trace_enabled() ||
                    wait_log_count <= 32 ||
                    (wait_log_count % 512u) == 0u ||
                    wait_result != 0u) {
                    std::cout << "\n[API CALL] [OK] WaitForSingleObject(handle=0x" << std::hex << h
                              << ", timeout=" << std::dec << timeout_ms << ") -> 0x" << std::hex
                              << wait_result << std::dec << "\n";
                }
            } else if (name == "KERNEL32.dll!Sleep") {
                if (handler->coop_threads_enabled()) {
                    handler->coop_request_yield();
                    handler->backend.emu_stop();
                }
            } else if (name == "KERNEL32.dll!SleepEx") {
                if (handler->coop_threads_enabled()) {
                    handler->coop_request_yield();
                    handler->backend.emu_stop();
                }
                handler->ctx.set_eax(0); // timeout elapsed, not alerted
            } else if (name == "KERNEL32.dll!SwitchToThread") {
                if (handler->coop_threads_enabled()) {
                    handler->coop_request_yield();
                    handler->backend.emu_stop();
                }
                handler->ctx.set_eax(1); // switched
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
                        auto itt = handler->ctx.handle_map.find("thread_" + std::to_string(h));
                        if (itt != handler->ctx.handle_map.end()) {
                        auto* th = static_cast<ThreadHandle*>(itt->second);
                        handler->coop_mark_thread_finished(h, "CloseHandle");
                        g_thread_start_to_handle.erase(th->start_address);
                        delete th;
                        handler->ctx.handle_map.erase(itt);
                        handler->note_thread_handle_closed();
                        handler->ctx.set_eax(1);
                        handler->ctx.global_state["LastError"] = 0;
                        } else {
                            // Non-file handles are currently treated as success for compatibility.
                            handler->ctx.set_eax(1);
                            handler->ctx.global_state["LastError"] = 0;
                        }
                    }
                }
            } else if (name == "KERNEL32.dll!LoadLibraryA" || name == "KERNEL32.dll!LoadLibraryW") {
                const bool wide = (name == "KERNEL32.dll!LoadLibraryW");
                uint32_t lpLibFileName = handler->ctx.get_arg(0);
                std::string module_name_raw = wide
                    ? read_guest_w_string(handler->ctx, lpLibFileName, 260)
                    : read_guest_c_string(handler->ctx, lpLibFileName, 260);

                uint32_t h_module = 0;
                if (!module_name_raw.empty()) {
                    h_module = lookup_module_handle_by_name(module_name_raw, false);
                    if (h_module == 0) {
                        std::string host_path = resolve_guest_path_to_host(module_name_raw, handler->process_base_dir);
                        if (!host_path.empty()) {
                            h_module = lookup_module_handle_by_name(module_name_raw, true);
                        }
                    }
                }

                handler->ctx.set_eax(h_module);
                handler->ctx.global_state["LastError"] = (h_module != 0) ? 0u : 126u; // ERROR_MOD_NOT_FOUND
                if (loader_trace_enabled()) {
                    std::cout << "[LOADER] " << name << "('" << module_name_raw
                              << "') -> 0x" << std::hex << h_module << std::dec << "\n";
                }
            } else if (name == "KERNEL32.dll!GetModuleHandleA" || name == "KERNEL32.dll!GetModuleHandleW") {
                const bool wide = (name == "KERNEL32.dll!GetModuleHandleW");
                uint32_t lpModuleName = handler->ctx.get_arg(0);
                std::string module_name_raw = wide
                    ? read_guest_w_string(handler->ctx, lpModuleName, 260)
                    : read_guest_c_string(handler->ctx, lpModuleName, 260);

                uint32_t h_module = lookup_module_handle_by_name(module_name_raw, false);
                handler->ctx.set_eax(h_module);
                handler->ctx.global_state["LastError"] = (h_module != 0) ? 0u : 126u; // ERROR_MOD_NOT_FOUND
                if (loader_trace_enabled()) {
                    std::cout << "[LOADER] " << name << "("
                              << (lpModuleName == 0 ? "NULL" : ("'" + module_name_raw + "'"))
                              << ") -> 0x" << std::hex << h_module << std::dec << "\n";
                }
            } else if (name == "KERNEL32.dll!FreeLibrary") {
                uint32_t h_module = handler->ctx.get_arg(0);
                bool success = false;
                std::string module_name = module_name_from_handle(h_module);
                if (!module_name.empty()) {
                    auto it_builtin = g_module_name_by_handle.find(h_module);
                    if (it_builtin == g_module_name_by_handle.end()) {
                        // Built-in pseudo modules are always "loaded" and FreeLibrary is a no-op success.
                        success = true;
                    } else {
                        g_module_name_by_handle.erase(it_builtin);
                        for (auto it = g_module_handle_by_name.begin(); it != g_module_handle_by_name.end();) {
                            if (it->second == h_module) it = g_module_handle_by_name.erase(it);
                            else ++it;
                        }
                        success = true;
                    }
                }
                handler->ctx.set_eax(success ? 1u : 0u);
                handler->ctx.global_state["LastError"] = success ? 0u : 6u; // ERROR_INVALID_HANDLE
                if (loader_trace_enabled()) {
                    std::cout << "[LOADER] FreeLibrary(0x" << std::hex << h_module
                              << ") -> " << std::dec << (success ? 1 : 0) << "\n";
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
                
                std::string module_norm = module_name_from_handle(hModule);
                if (module_norm.empty()) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                    if (loader_trace_enabled()) {
                        std::cout << "[LOADER] GetProcAddress invalid module handle 0x"
                                  << std::hex << hModule << std::dec << "\n";
                    }
                    return;
                }

                std::string module_name = module_norm;
                if (module_norm == "kernel32.dll") module_name = "KERNEL32.dll";
                else if (module_norm == "user32.dll") module_name = "USER32.dll";
                else if (module_norm == "oleaut32.dll") module_name = "OLEAUT32.dll";
                else if (module_norm == "ddraw.dll") module_name = "DDRAW.dll";
                else if (module_norm == "gdi32.dll") module_name = "GDI32.dll";
                else if (module_norm == "winmm.dll") module_name = "WINMM.dll";
                else if (module_norm == "dsound.dll") module_name = "DSOUND.dll";
                else if (module_norm == "bass.dll") module_name = "BASS.dll";
                else if (module_norm == "d3d8.dll") module_name = "D3D8.dll";
                else if (module_norm == "version.dll") module_name = "VERSION.dll";
                else if (module_norm == "shell32.dll") module_name = "SHELL32.dll";
                else if (module_norm == "advapi32.dll") module_name = "ADVAPI32.dll";
                else if (module_norm == "comdlg32.dll") module_name = "COMDLG32.dll";
                else if (module_norm == "imm32.dll") module_name = "IMM32.dll";
                else if (module_norm == "shlwapi.dll") module_name = "SHLWAPI.dll";
                std::string full_name = module_name + "!" + procName;
                bool noisy_getproc = starts_with_ascii_ci(full_name, "bass.dll!") ||
                                     starts_with_ascii_ci(full_name, "dsound.dll!");
                
                uint32_t found_addr = 0;
                for (const auto& pair : handler->fake_api_map) {
                    if (pair.second == full_name) {
                        found_addr = pair.first;
                        break;
                    }
                }
                
                if (found_addr == 0) {
                    found_addr = handler->register_fake_api(full_name);
                    if (!noisy_getproc || loader_trace_enabled()) {
                        std::cout << "\n[API CALL] [GetProcAddress] Dynamically assigned " << full_name
                                  << " to 0x" << std::hex << found_addr << std::dec << "\n";
                    }
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
            } else if (name == "KERNEL32.dll!EnterCriticalSection") {
                uint32_t cs_ptr = handler->ctx.get_arg(0);
                if (handler->coop_threads_enabled()) {
                    if (!handler->coop_enter_critical_section(cs_ptr, true)) {
                        // Keep EIP at this API stub and yield; the call should only return
                        // after lock ownership is granted.
                        handler->coop_request_yield();
                        handler->backend.emu_stop();
                        return;
                    }
                }
                handler->ctx.set_eax(1);
            } else if (name == "KERNEL32.dll!TryEnterCriticalSection") {
                uint32_t cs_ptr = handler->ctx.get_arg(0);
                bool acquired = true;
                if (handler->coop_threads_enabled()) {
                    acquired = handler->coop_enter_critical_section(cs_ptr, false);
                }
                handler->ctx.set_eax(acquired ? 1u : 0u);
            } else if (name == "KERNEL32.dll!LeaveCriticalSection") {
                if (handler->coop_threads_enabled()) {
                    uint32_t cs_ptr = handler->ctx.get_arg(0);
                    handler->coop_leave_critical_section(cs_ptr);
                }
                handler->ctx.set_eax(1);
            } else if (name == "KERNEL32.dll!DeleteCriticalSection") {
                if (handler->coop_threads_enabled()) {
                    uint32_t cs_ptr = handler->ctx.get_arg(0);
                    handler->coop_delete_critical_section(cs_ptr);
                }
                handler->ctx.set_eax(1);
            } else if (name == "KERNEL32.dll!InitializeCriticalSection" ||
                       name == "KERNEL32.dll!InitializeCriticalSectionAndSpinCount" ||
                       name == "KERNEL32.dll!InitializeCriticalSectionEx") {
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
                       name == "KERNEL32.dll!GetFileVersionInfoSizeA" || name == "KERNEL32.dll!GetFileVersionInfoA" || name == "KERNEL32.dll!VerQueryValueA" ||
                       name == "VERSION.dll!GetFileVersionInfoSizeA" || name == "VERSION.dll!GetFileVersionInfoA" || name == "VERSION.dll!VerQueryValueA") {
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
            } else if (name == "KERNEL32.dll!Direct3DCreate8" || name == "D3D8.dll!Direct3DCreate8") {
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
            } else if (name == "USER32.dll!RegisterClassA" || name == "USER32.dll!RegisterClassW" ||
                       name == "USER32.dll!RegisterClassExA" || name == "USER32.dll!RegisterClassExW") {
                uint32_t pClass = handler->ctx.get_arg(0);
                bool wide = (name == "USER32.dll!RegisterClassW" || name == "USER32.dll!RegisterClassExW");
                bool ex = (name == "USER32.dll!RegisterClassExA" || name == "USER32.dll!RegisterClassExW");
                uint32_t wndproc = 0;
                uint32_t class_name_ptr = 0;
                if (pClass != 0) {
                    if (ex) {
                        handler->backend.mem_read(pClass + 8u, &wndproc, 4);
                        handler->backend.mem_read(pClass + 40u, &class_name_ptr, 4);
                    } else {
                        uint32_t wndproc_a = 0;
                        uint32_t wndproc_b = 0;
                        uint32_t class_a = 0;
                        uint32_t class_b = 0;
                        handler->backend.mem_read(pClass + 4u, &wndproc_a, 4);
                        handler->backend.mem_read(pClass + 8u, &wndproc_b, 4);
                        handler->backend.mem_read(pClass + 36u, &class_a, 4);
                        handler->backend.mem_read(pClass + 40u, &class_b, 4);

                        auto valid_proc = [](uint32_t p) {
                            return p >= 0x10000u && p < DummyAPIHandler::FAKE_API_BASE;
                        };
                        wndproc = valid_proc(wndproc_a) ? wndproc_a : wndproc_b;
                        class_name_ptr = (class_a != 0) ? class_a : class_b;
                    }
                }

                std::string class_name;
                if ((class_name_ptr & 0xFFFF0000u) == 0 && class_name_ptr != 0) {
                    class_name = "#" + std::to_string(class_name_ptr & 0xFFFFu);
                } else {
                    class_name = wide
                        ? read_guest_w_string(handler->ctx, class_name_ptr, 256)
                        : read_guest_c_string(handler->ctx, class_name_ptr, 256);
                }
                class_name = to_lower_ascii(class_name);

                if (wndproc == 0 || class_name.empty()) {
                    if (env_truthy("PVZ_WNDPROC_TRACE")) {
                        std::cout << "[WNDPROC] RegisterClass parse-fail p=0x" << std::hex << pClass
                                  << " wndproc=0x" << wndproc
                                  << " class_ptr=0x" << class_name_ptr
                                  << " name='" << class_name << "'" << std::dec << "\n";
                    }
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 87; // ERROR_INVALID_PARAMETER
                } else {
                    uint16_t atom = 0;
                    auto it_existing = g_win32_class_by_name.find(class_name);
                    if (it_existing != g_win32_class_by_name.end()) {
                        atom = it_existing->second.atom;
                    } else {
                        atom = g_win32_class_atom_top++;
                        if (g_win32_class_atom_top == 0) g_win32_class_atom_top = 1;
                    }

                    Win32ClassReg reg = {};
                    reg.atom = atom;
                    reg.wndproc = wndproc;
                    g_win32_class_by_name[class_name] = reg;
                    g_win32_class_by_atom[atom] = reg;

                    if (env_truthy("PVZ_WNDPROC_TRACE")) {
                        std::cout << "[WNDPROC] RegisterClass name='" << class_name
                                  << "' atom=0x" << std::hex << atom
                                  << " wndproc=0x" << wndproc << std::dec << "\n";
                    }
                    handler->ctx.set_eax(atom);
                    handler->ctx.global_state["LastError"] = 0;
                }
            } else if (name == "USER32.dll!GetLastInputInfo") {
                uint32_t pLastInputInfo = handler->ctx.get_arg(0);
                bool ok = false;
                if (pLastInputInfo != 0) {
                    uint32_t cb_size = 0;
                    handler->backend.mem_read(pLastInputInfo, &cb_size, 4);
                    if (cb_size >= 8) {
                        uint32_t now = SDL_GetTicks();
                        handler->backend.mem_write(pLastInputInfo + 4, &now, 4); // dwTime
                        ok = true;
                    }
                }
                handler->ctx.set_eax(ok ? 1u : 0u);
                handler->ctx.global_state["LastError"] = ok ? 0u : 87u; // ERROR_INVALID_PARAMETER
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
                static const bool wndproc_trace = env_truthy("PVZ_WNDPROC_TRACE");
                uint32_t lpMsg = handler->ctx.get_arg(0);
                Win32_MSG msg = {};
                if (lpMsg != 0 && handler->backend.mem_read(lpMsg, &msg, sizeof(msg)) == UC_ERR_OK) {
                    auto it_wndproc = g_window_long_values.find(win32_window_long_key(msg.hwnd, -4)); // GWL_WNDPROC
                    if (it_wndproc != g_window_long_values.end() && it_wndproc->second != 0 && msg.message != WM_NULL) {
                        uint32_t wndproc = static_cast<uint32_t>(it_wndproc->second);
                        if (wndproc >= DummyAPIHandler::FAKE_API_BASE || wndproc < 0x10000u) {
                            handler->ctx.set_eax(0);
                            return;
                        }
                        if (wndproc_trace) {
                            std::cout << "[WNDPROC] Dispatch hwnd=0x" << std::hex << msg.hwnd
                                      << " msg=0x" << msg.message << " -> 0x" << wndproc
                                      << std::dec << "\n";
                        }
                        uint32_t esp = 0;
                        handler->backend.reg_read(UC_X86_REG_ESP, &esp);
                        uint32_t caller_ret = 0;
                        handler->backend.mem_read(esp, &caller_ret, 4);

                        // Build a stdcall frame for WndProc and jump directly.
                        // We shift ESP by -12 so WndProc(ret 16) lands on Dispatch caller's expected ESP (+8).
                        uint32_t call_esp = esp - 12;
                        uint32_t frame[5] = {caller_ret, msg.hwnd, msg.message, msg.wParam, msg.lParam};
                        handler->backend.mem_write(call_esp, frame, sizeof(frame));
                        handler->backend.reg_write(UC_X86_REG_ESP, &call_esp);
                        handler->backend.reg_write(UC_X86_REG_EIP, &wndproc);
                        return;
                    }
                }
                handler->ctx.set_eax(0);
            } else if (name == "USER32.dll!SendMessageA" || name == "USER32.dll!SendMessageW") {
                static const bool wndproc_trace = env_truthy("PVZ_WNDPROC_TRACE");
                uint32_t hwnd = handler->ctx.get_arg(0);
                uint32_t msg = handler->ctx.get_arg(1);
                auto it_wndproc = g_window_long_values.find(win32_window_long_key(hwnd, -4)); // GWL_WNDPROC
                if (it_wndproc != g_window_long_values.end() && it_wndproc->second != 0 && msg != WM_NULL) {
                    uint32_t wndproc = static_cast<uint32_t>(it_wndproc->second);
                    if (wndproc < DummyAPIHandler::FAKE_API_BASE && wndproc >= 0x10000u) {
                        if (wndproc_trace) {
                            std::cout << "[WNDPROC] SendMessage hwnd=0x" << std::hex << hwnd
                                      << " msg=0x" << msg << " -> 0x" << wndproc
                                      << std::dec << "\n";
                        }
                        handler->backend.reg_write(UC_X86_REG_EIP, &wndproc);
                        return;
                    }
                }
                handler->ctx.set_eax(0);
            } else if (name == "USER32.dll!DestroyWindow") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                g_valid_hwnds.erase(hwnd);
                g_hwnd_owner_thread_id.erase(hwnd);
                g_window_text_values.erase(hwnd);
                for (auto it_w = g_window_long_values.begin(); it_w != g_window_long_values.end(); ) {
                    if (static_cast<uint32_t>(it_w->first >> 32) == hwnd) {
                        it_w = g_window_long_values.erase(it_w);
                    } else {
                        ++it_w;
                    }
                }
                handler->ctx.set_eax(1);
            } else if (name == "USER32.dll!IsWindow" ||
                       name == "USER32.dll!IsWindowVisible" ||
                       name == "USER32.dll!IsWindowEnabled") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                bool exists = (g_valid_hwnds.find(hwnd) != g_valid_hwnds.end());
                if (!exists && hwnd == 0x12345678u) exists = true;
                handler->ctx.set_eax(exists ? 1u : 0u);
                if (thread_mock_trace_enabled() || env_truthy("PVZ_WNDPROC_TRACE")) {
                    std::cout << "[WNDPROC] " << name << "(hwnd=0x" << std::hex << hwnd
                              << ") -> " << (exists ? "1" : "0") << std::dec << "\n";
                }
            } else if (name == "USER32.dll!GetActiveWindow" ||
                       name == "USER32.dll!GetForegroundWindow") {
                if (!g_valid_hwnds.empty()) {
                    handler->ctx.set_eax(*g_valid_hwnds.begin());
                } else {
                    handler->ctx.set_eax(0x12345678u);
                }
            } else if (name == "USER32.dll!GetLastActivePopup") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                bool exists = (g_valid_hwnds.find(hwnd) != g_valid_hwnds.end());
                if (exists) {
                    handler->ctx.set_eax(hwnd);
                } else if (!g_valid_hwnds.empty()) {
                    handler->ctx.set_eax(*g_valid_hwnds.begin());
                } else {
                    handler->ctx.set_eax(0x12345678u);
                }
            } else if (name == "USER32.dll!GetProcessWindowStation") {
                uint32_t h_winsta = 0xB100u;
                auto it = handler->ctx.global_state.find("ProcessWindowStationHandle");
                if (it != handler->ctx.global_state.end()) {
                    h_winsta = static_cast<uint32_t>(it->second);
                } else {
                    handler->ctx.global_state["ProcessWindowStationHandle"] = h_winsta;
                }
                handler->ctx.set_eax(h_winsta);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "USER32.dll!GetUserObjectInformationA" ||
                       name == "USER32.dll!GetUserObjectInformationW") {
                uint32_t h_obj = handler->ctx.get_arg(0);
                uint32_t n_index = handler->ctx.get_arg(1);
                uint32_t pv_info = handler->ctx.get_arg(2);
                uint32_t n_length = handler->ctx.get_arg(3);
                uint32_t p_needed = handler->ctx.get_arg(4);
                bool wide = (name == "USER32.dll!GetUserObjectInformationW");

                uint32_t expected = 0xB100u;
                auto it = handler->ctx.global_state.find("ProcessWindowStationHandle");
                if (it != handler->ctx.global_state.end()) {
                    expected = static_cast<uint32_t>(it->second);
                }
                if (h_obj != expected && h_obj != 0xFFFFFFFFu) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 6; // ERROR_INVALID_HANDLE
                    return;
                }

                std::vector<uint8_t> payload;
                if (n_index == 1u) { // UOI_FLAGS
                    payload.resize(12, 0);
                    uint32_t flags = 1u;
                    std::memcpy(payload.data() + 8, &flags, 4); // USEROBJECTFLAGS.dwFlags
                } else if (n_index == 2u) { // UOI_NAME
                    const char* name_ascii = "WinSta0";
                    if (wide) {
                        std::u16string w;
                        for (const char* p = name_ascii; *p; ++p) w.push_back(static_cast<char16_t>(*p));
                        w.push_back(0);
                        payload.resize(w.size() * sizeof(char16_t), 0);
                        std::memcpy(payload.data(), w.data(), payload.size());
                    } else {
                        size_t len = std::strlen(name_ascii) + 1;
                        payload.resize(len, 0);
                        std::memcpy(payload.data(), name_ascii, len);
                    }
                } else if (n_index == 3u) { // UOI_TYPE
                    const char* type_ascii = "WindowStation";
                    if (wide) {
                        std::u16string w;
                        for (const char* p = type_ascii; *p; ++p) w.push_back(static_cast<char16_t>(*p));
                        w.push_back(0);
                        payload.resize(w.size() * sizeof(char16_t), 0);
                        std::memcpy(payload.data(), w.data(), payload.size());
                    } else {
                        size_t len = std::strlen(type_ascii) + 1;
                        payload.resize(len, 0);
                        std::memcpy(payload.data(), type_ascii, len);
                    }
                } else {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 87; // ERROR_INVALID_PARAMETER
                    return;
                }

                uint32_t needed = static_cast<uint32_t>(payload.size());
                if (p_needed != 0) {
                    handler->backend.mem_write(p_needed, &needed, 4);
                }
                if (pv_info == 0 || n_length < needed) {
                    handler->ctx.set_eax(0);
                    handler->ctx.global_state["LastError"] = 122; // ERROR_INSUFFICIENT_BUFFER
                    return;
                }
                handler->backend.mem_write(pv_info, payload.data(), payload.size());
                handler->ctx.set_eax(1);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "USER32.dll!SetWindowLongA" || name == "USER32.dll!SetWindowLongW") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                int32_t index = static_cast<int32_t>(handler->ctx.get_arg(1));
                int32_t value = static_cast<int32_t>(handler->ctx.get_arg(2));
                uint64_t key = win32_window_long_key(hwnd, index);
                int32_t prev = 0;
                auto it_prev = g_window_long_values.find(key);
                if (it_prev != g_window_long_values.end()) {
                    prev = it_prev->second;
                }
                g_window_long_values[key] = value;
                if (g_valid_hwnds.find(hwnd) == g_valid_hwnds.end()) {
                    g_valid_hwnds.insert(hwnd);
                }
                if (g_hwnd_owner_thread_id.find(hwnd) == g_hwnd_owner_thread_id.end()) {
                    g_hwnd_owner_thread_id[hwnd] = handler->coop_threads_enabled()
                        ? handler->coop_current_thread_id()
                        : 1u;
                }
                if (env_truthy("PVZ_WNDPROC_TRACE")) {
                    std::cout << "[WNDPROC] SetWindowLong hwnd=0x" << std::hex << hwnd
                              << " index=" << std::dec << index
                              << " prev=0x" << std::hex << static_cast<uint32_t>(prev)
                              << " new=0x" << static_cast<uint32_t>(value)
                              << std::dec << "\n";
                }
                handler->ctx.set_eax(static_cast<uint32_t>(prev));
            } else if (name == "USER32.dll!GetWindowLongA" || name == "USER32.dll!GetWindowLongW") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                int32_t index = static_cast<int32_t>(handler->ctx.get_arg(1));
                uint64_t key = win32_window_long_key(hwnd, index);
                int32_t value = 0;
                auto it_val = g_window_long_values.find(key);
                if (it_val != g_window_long_values.end()) {
                    value = it_val->second;
                }
                handler->ctx.set_eax(static_cast<uint32_t>(value));
            } else if (name == "USER32.dll!GetWindowThreadProcessId") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                uint32_t ppid = handler->ctx.get_arg(1);
                uint32_t tid = 1;
                auto it_tid = g_hwnd_owner_thread_id.find(hwnd);
                if (it_tid != g_hwnd_owner_thread_id.end()) {
                    tid = it_tid->second;
                }
                uint32_t pid = 1;
                auto it_pid = handler->ctx.global_state.find("ProcessId");
                if (it_pid != handler->ctx.global_state.end()) {
                    pid = static_cast<uint32_t>(it_pid->second);
                }
                if (ppid != 0) {
                    handler->backend.mem_write(ppid, &pid, 4);
                }
                handler->ctx.set_eax(tid);
            } else if (name == "USER32.dll!SetWindowTextA" || name == "USER32.dll!SetWindowTextW") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                uint32_t p = handler->ctx.get_arg(1);
                std::string title = (name == "USER32.dll!SetWindowTextW")
                    ? read_guest_w_string(handler->ctx, p, 256)
                    : read_guest_c_string(handler->ctx, p, 256);
                g_window_text_values[hwnd] = title;
                if (handler->ctx.sdl_window && !title.empty()) {
                    SDL_SetWindowTitle(static_cast<SDL_Window*>(handler->ctx.sdl_window), title.c_str());
                }
                handler->ctx.set_eax(1);
            } else if (name == "USER32.dll!GetWindowTextA" || name == "USER32.dll!GetWindowTextW") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                uint32_t p = handler->ctx.get_arg(1);
                uint32_t cch = handler->ctx.get_arg(2);
                auto it_title = g_window_text_values.find(hwnd);
                std::string title = (it_title != g_window_text_values.end()) ? it_title->second : "";
                if (cch == 0 || p == 0) {
                    handler->ctx.set_eax(0);
                } else if (name == "USER32.dll!GetWindowTextW") {
                    uint32_t max_chars = (cch > 0) ? (cch - 1) : 0;
                    uint32_t n = std::min<uint32_t>(max_chars, static_cast<uint32_t>(title.size()));
                    std::vector<uint16_t> wbuf(n + 1, 0);
                    for (uint32_t i = 0; i < n; ++i) {
                        wbuf[i] = static_cast<uint16_t>(static_cast<unsigned char>(title[i]));
                    }
                    handler->backend.mem_write(p, wbuf.data(), (n + 1) * sizeof(uint16_t));
                    handler->ctx.set_eax(n);
                } else {
                    uint32_t max_chars = (cch > 0) ? (cch - 1) : 0;
                    uint32_t n = std::min<uint32_t>(max_chars, static_cast<uint32_t>(title.size()));
                    if (n > 0) {
                        handler->backend.mem_write(p, title.data(), n);
                    }
                    uint8_t nul = 0;
                    handler->backend.mem_write(p + n, &nul, 1);
                    handler->ctx.set_eax(n);
                }
            } else if (name == "USER32.dll!WaitMessage") {
                SDL_Event evt;
                if (!SDL_PollEvent(&evt)) {
                    SDL_WaitEventTimeout(&evt, 16);
                }
                pump_due_win32_timers(SDL_GetTicks());
                if (handler->coop_threads_enabled() && !handler->coop_current_thread_is_main()) {
                    uint32_t current_tid = handler->coop_current_thread_id();
                    if (!win32_queue_has_message_for_thread(current_tid)) {
                        handler->coop_block_current_thread_on_message_wait(0, 0, 0);
                    } else {
                        handler->coop_request_yield();
                    }
                }
                handler->ctx.set_eax(1);
            } else if (name == "USER32.dll!MsgWaitForMultipleObjects" ||
                       name == "USER32.dll!MsgWaitForMultipleObjectsEx") {
                uint32_t dwMilliseconds = 0;
                if (name == "USER32.dll!MsgWaitForMultipleObjects") {
                    dwMilliseconds = handler->ctx.get_arg(3);
                } else {
                    dwMilliseconds = handler->ctx.get_arg(2);
                }
                uint32_t now = SDL_GetTicks();
                pump_due_win32_timers(now);
                uint32_t wait_ms = (dwMilliseconds == 0xFFFFFFFFu) ? 16u : std::min<uint32_t>(dwMilliseconds, 16u);
                SDL_Event evt;
                if (wait_ms > 0) {
                    SDL_WaitEventTimeout(&evt, static_cast<int>(wait_ms));
                    pump_due_win32_timers(SDL_GetTicks());
                }
                uint32_t current_tid = handler->coop_threads_enabled()
                    ? handler->coop_current_thread_id()
                    : 1u;
                bool has_message = win32_queue_has_message_for_thread(current_tid);
                if (has_message) {
                    handler->ctx.set_eax(0); // WAIT_OBJECT_0 + nCount(0)
                } else {
                    if (handler->coop_threads_enabled() && !handler->coop_current_thread_is_main()) {
                        handler->coop_block_current_thread_on_message_wait(0, 0, 0);
                    }
                    handler->ctx.set_eax(0x102); // WAIT_TIMEOUT
                }
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
                uint32_t elapse_ms = handler->ctx.get_arg(2);
                uint32_t callback = handler->ctx.get_arg(3);
                if (elapse_ms == 0) elapse_ms = 1;
                uint32_t now = SDL_GetTicks();
                Win32Timer timer = {};
                timer.hwnd = hwnd;
                timer.timer_id = timer_id;
                timer.interval_ms = elapse_ms;
                timer.callback = callback;
                timer.next_fire_ms = now + elapse_ms;
                g_win32_timers[win32_timer_key(hwnd, timer_id)] = timer;
                handler->ctx.set_eax(timer_id);
            } else if (name == "USER32.dll!KillTimer") {
                uint32_t hwnd = handler->ctx.get_arg(0);
                uint32_t timer_id = handler->ctx.get_arg(1);
                size_t erased = g_win32_timers.erase(win32_timer_key(hwnd, timer_id));
                handler->ctx.set_eax(erased > 0 ? 1u : 0u);
            } else if (name == "USER32.dll!PostThreadMessageA" || name == "USER32.dll!PostThreadMessageW") {
                uint32_t id_thread = handler->ctx.get_arg(0);
                Win32_MSG msg = {};
                msg.hwnd = 0;
                msg.message = handler->ctx.get_arg(1);
                msg.wParam = handler->ctx.get_arg(2);
                msg.lParam = handler->ctx.get_arg(3);
                msg.time = SDL_GetTicks();
                int mx = 0;
                int my = 0;
                SDL_GetMouseState(&mx, &my);
                msg.pt_x = mx;
                msg.pt_y = my;
                enqueue_win32_message(msg, id_thread);
                if (thread_mock_trace_enabled()) {
                    std::cout << "[THREAD MOCK] PostThreadMessage(tid=" << id_thread
                              << ", msg=0x" << std::hex << msg.message << ", queue="
                              << std::dec << g_win32_message_queue.size() << ")\n";
                }
                if (handler->coop_threads_enabled()) {
                    handler->coop_request_yield();
                }
                handler->ctx.set_eax(1);
                handler->ctx.global_state["LastError"] = 0;
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
                bool broadcast = (msg.hwnd == 0x0000FFFFu || msg.hwnd == 0xFFFFFFFFu);
                size_t queued_count = 0;
                if (broadcast && !g_valid_hwnds.empty()) {
                    for (uint32_t hwnd : g_valid_hwnds) {
                        Win32_MSG per_hwnd = msg;
                        per_hwnd.hwnd = hwnd;
                        uint32_t target_tid = 0;
                        auto it_owner = g_hwnd_owner_thread_id.find(hwnd);
                        if (it_owner != g_hwnd_owner_thread_id.end()) {
                            target_tid = it_owner->second;
                        }
                        enqueue_win32_message(per_hwnd, target_tid);
                        queued_count++;
                    }
                } else {
                    uint32_t target_tid = 0;
                    auto it_owner = g_hwnd_owner_thread_id.find(msg.hwnd);
                    if (it_owner != g_hwnd_owner_thread_id.end()) {
                        target_tid = it_owner->second;
                    }
                    enqueue_win32_message(msg, target_tid);
                    queued_count = 1;
                }

                // Cooperative wakeup: many bootstrap paths wait on an event that the
                // worker thread sets when it posts into the UI queue.
                for (auto& kv : handler->ctx.handle_map) {
                    if (kv.first.rfind("event_", 0) == 0) {
                        static_cast<EventHandle*>(kv.second)->signaled = true;
                    }
                }
                if (thread_mock_trace_enabled()) {
                    std::cout << "[THREAD MOCK] PostMessage(hwnd=0x" << std::hex << msg.hwnd
                              << ", msg=0x" << msg.message << ", queued=" << std::dec
                              << queued_count << ", queue=" << g_win32_message_queue.size() << ")\n";
                }
                if (handler->coop_threads_enabled()) {
                    handler->coop_request_yield();
                }
                handler->ctx.set_eax(1);
                handler->ctx.global_state["LastError"] = 0;
            } else if (name == "KERNEL32.dll!GetCurrentThreadId") {
                uint32_t tid = handler->coop_threads_enabled()
                    ? handler->coop_current_thread_id()
                    : 1u;
                handler->ctx.set_eax(tid);
            } else if (name == "KERNEL32.dll!GetCurrentProcessId") {
                uint32_t pid = 1;
                auto it_pid = handler->ctx.global_state.find("ProcessId");
                if (it_pid != handler->ctx.global_state.end()) {
                    pid = static_cast<uint32_t>(it_pid->second);
                } else {
                    handler->ctx.global_state["ProcessId"] = pid;
                }
                handler->ctx.set_eax(pid);
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

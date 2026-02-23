import unicorn

class DummyAPIHandler:
    """Manages faux API endpoints and automatically cleans stdcall stacks."""
    
    FAKE_API_BASE = 0x90000000
    
    # Map 'DLL!Function' -> Number of argument bytes to pop from stack
    KNOWN_SIGNATURES = {
        "KERNEL32.dll!GetSystemTimeAsFileTime": 4,
        "KERNEL32.dll!GetCurrentProcessId": 0,
        "KERNEL32.dll!GetCurrentThreadId": 0,
        "KERNEL32.dll!GetTickCount": 0,
        "KERNEL32.dll!QueryPerformanceCounter": 4,
        "KERNEL32.dll!GetStartupInfoA": 4,
        "KERNEL32.dll!GetProcessHeap": 0,
        "KERNEL32.dll!HeapAlloc": 12,
        "KERNEL32.dll!HeapCreate": 12,
        "KERNEL32.dll!GetVersionExA": 4,
        "KERNEL32.dll!HeapFree": 12,
        "KERNEL32.dll!GetModuleFileNameA": 12,
        "KERNEL32.dll!GetLastError": 0,
        "KERNEL32.dll!SetLastError": 4,
        "KERNEL32.dll!CloseHandle": 4,
        # Default fallback for unknown APIs is 0
    }

    def __init__(self, uc, logger=print):
        self.uc = uc
        self.log = logger
        self.fake_api_map = {}
        self.current_addr = self.FAKE_API_BASE
        
        self.log(f"Mapping FAKE_API boundary at 0x{self.FAKE_API_BASE:x}")
        self.uc.mem_map(self.FAKE_API_BASE, 0x100000) # 1MB

        # Intercept block hook specifically for the Fake API range
        self.uc.hook_add(unicorn.UC_HOOK_BLOCK, self._hook_api_call)

    def register_fake_api(self, full_name):
        """Builds a faux endpoint. Returns the mapped fake address."""
        api_addr = self.current_addr
        self.fake_api_map[api_addr] = full_name
        
        # Write instruction logic at fake address
        args_bytes = self.KNOWN_SIGNATURES.get(full_name)
        
        if args_bytes is not None and args_bytes > 0:
            # ret N (stdcall)
            # opcode C2 <low> <high>
            instruction = bytes([0xC2, args_bytes & 0xFF, (args_bytes >> 8) & 0xFF])
        else:
            # ret (cdecl / 0 arg stdcall)
            instruction = b"\xc3"
            
        self.uc.mem_write(api_addr, instruction)
        self.current_addr += 16 # spacing out APIs
        return api_addr

    def _hook_api_call(self, uc, address, size, user_data):
        """Tracing callback to notify when an API is hit."""
        if address in self.fake_api_map:
            name = self.fake_api_map[address]
            known = name in self.KNOWN_SIGNATURES
            tag = "[OK]" if known else "[WARN-UNKNOWN]"
            self.log(f"\n[API CALL] {tag} Intercepted call to {name}")

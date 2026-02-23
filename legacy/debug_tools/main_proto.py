import unicorn
import capstone

from winenv import WindowsEnvironment
from peldr import PEModule
from api_handler import DummyAPIHandler

class MainEmulator:
    def __init__(self, pe_path):
        self.pe_path = pe_path
        
        # Initialize Capstone
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.cs.detail = True
        
        # Initialize Unicorn
        print("[*] Initializing Unicorn x86 32-bit...")
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        
        # Sub-modules
        self.env = WindowsEnvironment(self.uc)
        self.api_handler = DummyAPIHandler(self.uc)
        self.pe_module = PEModule(self.pe_path)

    def _reg_name(self, reg_id):
        name = self.cs.reg_name(reg_id)
        return name if name else str(reg_id)

    def hook_block_lva(self, uc, address, size, user_data):
        # We don't want to disassemble fake API blocks
        if address >= DummyAPIHandler.FAKE_API_BASE:
            return
            
        print(f"\n--- Basic Block Hook: 0x{address:10x}, size: {size} ---")
        try:
            code = uc.mem_read(address, size)
        except unicorn.UcError as e:
            print(f"Failed to read memory at 0x{address:x}: {e}")
            return

        live_in = set()
        live_out = set()
        
        print("Disassembly:")
        try:
            for instr in self.cs.disasm(code, address):
                print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
                (regs_read, regs_write) = instr.regs_access()
                
                for r in regs_read:
                    if r not in live_out:
                        live_in.add(r)
                for r in regs_write:
                    live_out.add(r)
        except capstone.CsError as e:
            print(f"Capstone error during disassembly: {e}")

        # Reduce logging noise for demonstration, only print live-in/out explicitly
        in_str = ", ".join([self._reg_name(r) for r in live_in]) if live_in else "(None)"
        out_str = ", ".join([self._reg_name(r) for r in live_out]) if live_out else "(None)"
        print(f"Live-In : {in_str}")
        print(f"Live-Out: {out_str}")

    def run(self):
        # 1. Map Executable
        self.pe_module.map_into(self.uc)
        
        # 2. Resolve Imports
        self.pe_module.resolve_imports(self.uc, self.api_handler)
        
        # 3. Setup OS Environment
        self.env.setup_system()
        
        # 4. Attach Capstone LVA Hook
        self.uc.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block_lva)
        
        # 5. Start Execution
        print(f"[*] Starting emulation at 0x{self.pe_module.entry_point:x}...")
        try:
            # Run indefinitely or until crash
            self.uc.emu_start(self.pe_module.entry_point, 0)
        except unicorn.UcError as e:
            pc = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
            print(f"\n[!] Emulation stopped due to error: {e}")
            print(f"[!] EIP = 0x{pc:x}")

if __name__ == "__main__":
    emulator = MainEmulator("pvz/main.exe")
    emulator.run()

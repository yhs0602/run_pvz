import unicorn
import capstone
from capstone import x86

# 1. Initialize Capstone (x86 32-bit, DETAIL mode ON)
try:
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
except capstone.CsError as e:
    print(f"ERROR: Failed to initialize Capstone: {e}")
    exit(1)

# 2. Test Shellcode
# Simple sequence of x86-32 instructions to test LVA
# mov eax, 10
# add eax, ebx
# mov ecx, eax
# test ecx, ecx
# jz +2 (skip next if 0)
# nop
# nop
X86_CODE = b"\xb8\x0a\x00\x00\x00\x01\xd8\x89\xc1\x85\xc9\x74\x02\x90\x90"

# Addresses and sizes
ADDRESS = 0x1000000
SIZE = 2 * 1024 * 1024

def reg_name(reg_id):
    name = cs.reg_name(reg_id)
    return name if name else str(reg_id)

# 3. Hook Logic & LVA
def hook_block(uc, address, size, user_data):
    print(f"\n--- Basic Block Hook: 0x{address:x}, size: {size} ---")
    
    # Read the instruction bytes from memory
    code = uc.mem_read(address, size)
    
    live_in = set()
    live_out = set()
    
    print("Disassembly:")
    try:
        for instr in cs.disasm(code, address):
            print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
            
            # Extract implicitly and explicitly read/written registers
            (regs_read, regs_write) = instr.regs_access()
            
            # Live-In: Registers read before being written in this block.
            for r in regs_read:
                if r not in live_out:
                    live_in.add(r)
            
            # Live-Out: Registers written in this block (conservative approach)
            for r in regs_write:
                live_out.add(r)
    except capstone.CsError as e:
        print(f"Capstone error during disassembly: {e}")

    print("\nLive-In (Context required before block):")
    print("  " + (", ".join([reg_name(r) for r in live_in]) if live_in else "(None)"))
    
    print("Live-Out (Registers modified by block):")
    print("  " + (", ".join([reg_name(r) for r in live_out]) if live_out else "(None)"))

# 4. Unicorn Execution Environment setup
try:
    print("Initializing Unicorn x86 32-bit...")
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    
    # Map 2MB of memory for the code
    uc.mem_map(ADDRESS, SIZE)
    
    # Write code into memory
    uc.mem_write(ADDRESS, X86_CODE)
    
    # Initialize some registers to simulate a running state
    uc.reg_write(unicorn.x86_const.UC_X86_REG_EBX, 0x20)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0x0)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_ECX, 0x0)
    
    # Register the block hook
    uc.hook_add(unicorn.UC_HOOK_BLOCK, hook_block)
    
    print("Starting emulation...")
    uc.emu_start(ADDRESS, ADDRESS + len(X86_CODE))
    print("Emulation sequence completed successfully.")
    
except unicorn.UcError as e:
    print(f"ERROR: Unicorn emulation failed: {e}")

import struct
import pefile
import unicorn
import capstone

# Initialize Capstone
try:
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
except capstone.CsError as e:
    print(f"ERROR: Failed to initialize Capstone: {e}")
    exit(1)

def reg_name(reg_id):
    name = cs.reg_name(reg_id)
    return name if name else str(reg_id)

def align(value, alignment):
    if value % alignment == 0:
        return value
    return value + (alignment - (value % alignment))

# Hook Logic & LVA (reused from prototype)
def hook_block(uc, address, size, user_data):
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
        for instr in cs.disasm(code, address):
            print(f"  0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
            (regs_read, regs_write) = instr.regs_access()
            for r in regs_read:
                if r not in live_out:
                    live_in.add(r)
            for r in regs_write:
                live_out.add(r)
    except capstone.CsError as e:
        print(f"Capstone error during disassembly: {e}")

    in_str = ", ".join([reg_name(r) for r in live_in]) if live_in else "(None)"
    out_str = ", ".join([reg_name(r) for r in live_out]) if live_out else "(None)"
    print(f"Live-In : {in_str}")
    print(f"Live-Out: {out_str}")

# Load PE File
PE_FILE = "pvz/main.exe"
print(f"Parsing PE file: {PE_FILE}")
pe = pefile.PE(PE_FILE)

# Unicorn Initialization
print("Initializing Unicorn x86 32-bit...")
uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

# Memory Mapping
# pefile provides OPTIONAL_HEADER ImageBase and SizeOfImage
image_base = pe.OPTIONAL_HEADER.ImageBase
size_of_image = align(pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)

print(f"Mapping image: Base=0x{image_base:x}, Size=0x{size_of_image:x}")
uc.mem_map(image_base, size_of_image)

# We should also map a dummy memory for the PE header itself if needed
header_size = align(pe.OPTIONAL_HEADER.SizeOfHeaders, 0x1000)
print(f"Writing PE headers ({header_size} bytes)")
uc.mem_write(image_base, pe.header)

# Map Sections
print("\nMapping Sections:")
for section in pe.sections:
    # Get physical data
    data = section.get_data()
    vaddr = image_base + section.VirtualAddress
    vsize = align(section.Misc_VirtualSize, 0x1000)
    
    print(f"  {section.Name.decode('utf-8').strip('\x00'):8} VAddr: 0x{vaddr:08x} VSize: 0x{vsize:08x} RawSize: 0x{len(data):08x}")
    
    if len(data) > 0:
        # Write data to virtual address
        try:
            uc.mem_write(vaddr, data)
        except unicorn.UcError as e:
            print(f"  ERROR mapping section {section.Name}: {e}")

# Stack Setup
STACK_BASE = 0x80000000
STACK_SIZE = 2 * 1024 * 1024 # 2MB
print(f"\nMapping Stack: Base=0x{STACK_BASE:x}, Size=0x{STACK_SIZE:x}")
uc.mem_map(STACK_BASE, STACK_SIZE)

# Initialize Stack Pointer (top of the stack)
stack_top = STACK_BASE + STACK_SIZE - 0x1000 # leave a little padding
uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, stack_top)
uc.reg_write(unicorn.x86_const.UC_X86_REG_EBP, stack_top)

# Set Entry Point
entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f"\nEntry Point: 0x{entry_point:x}")

# Windows TEB (Thread Environment Block) & PEB (Process Environment Block) Setup
TEB_BASE = 0x7FFDF000
PEB_BASE = 0x7FFDE000
GDT_BASE = 0xC0000000

print(f"\nSetting up GDT (0x{GDT_BASE:x}) and TEB/PEB (0x{TEB_BASE:x})")
uc.mem_map(TEB_BASE, 0x1000)
uc.mem_map(PEB_BASE, 0x1000)
uc.mem_map(GDT_BASE, 0x1000)

def create_gdt_entry(base, limit, access, flags):
    limit = limit & 0xfffff
    entry = (
        (limit & 0xffff) |
        ((base & 0xffffff) << 16) |
        ((access & 0xff) << 40) |
        (((limit >> 16) & 0x0f) << 48) |
        ((flags & 0x0f) << 52) |
        ((base >> 24) << 56)
    )
    return struct.pack('<Q', entry)

# 1. Setup GDT Entries
gdt = [
    create_gdt_entry(0, 0, 0, 0),                   # 0x00 Null
    create_gdt_entry(0, 0xFFFFF, 0x9B, 0xC),        # 0x08 Code32 Ring0
    create_gdt_entry(0, 0xFFFFF, 0x93, 0xC),        # 0x10 Data32 Ring0
    create_gdt_entry(TEB_BASE, 0xFFFFF, 0x93, 0xC)  # 0x18 TEB Ring0
]

for i, entry in enumerate(gdt):
    uc.mem_write(GDT_BASE + (i * 8), entry)

# 2. Load GDTR
uc.reg_write(unicorn.x86_const.UC_X86_REG_GDTR, (0, GDT_BASE, len(gdt) * 8 - 1, 0))

# 3. Load Segment Registers
uc.reg_write(unicorn.x86_const.UC_X86_REG_DS, 0x10)
uc.reg_write(unicorn.x86_const.UC_X86_REG_ES, 0x10)
uc.reg_write(unicorn.x86_const.UC_X86_REG_SS, 0x10)
FS_SELECTOR = 0x18 # Index 3, TI=0, RPL=0
uc.reg_write(unicorn.x86_const.UC_X86_REG_FS, FS_SELECTOR)

# 4. Populate TEB Fields
uc.mem_write(TEB_BASE + 0x00, struct.pack("<I", 0xFFFFFFFF)) # fs:[0] SEH Head (ExceptionList)
uc.mem_write(TEB_BASE + 0x04, struct.pack("<I", stack_top))  # fs:[4] Stack Base
uc.mem_write(TEB_BASE + 0x08, struct.pack("<I", STACK_BASE)) # fs:[8] Stack Limit
uc.mem_write(TEB_BASE + 0x18, struct.pack("<I", TEB_BASE))   # fs:[0x18] TEB pointer
uc.mem_write(TEB_BASE + 0x30, struct.pack("<I", PEB_BASE))   # fs:[0x30] PEB pointer

# IAT Stubbing (Import Address Table)
FAKE_API_BASE = 0x90000000
uc.mem_map(FAKE_API_BASE, 0x100000) # 1MB for fake DLLs

fake_api_map = {}
current_fake_addr = FAKE_API_BASE

print("\nParsing Imports and Stubbing IAT:")
try:
    pe.parse_data_directories()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        print(f"  [{dll_name}]")
        for imp in entry.imports:
            func_name = imp.name.decode('utf-8') if imp.name else f"Ordinal_{imp.ordinal}"
            
            # Map a fake address for this API
            api_addr = current_fake_addr
            fake_api_map[api_addr] = f"{dll_name}!{func_name}"
            
            # Write a `RET` instruction at the fake address so it just returns immediately if executed
            uc.mem_write(api_addr, b"\xc3") # ret
            
            # Overwrite the IAT entry with our fake address
            # The IAT entry is located at ImageBase + imp.address
            # In pefile, imp.address is a VirtualAddress? No, in pefile, imp.address is ImageBase + VirtualAddress or similar? Wait, imp.address is the actual RVA + ImageBase or just RVA?
            # Actually, let's just write to ImageBase + imp.address - NO, imp.address is VA.
            iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase # Actually imp.address is an absolute address in pefile by default: imp.address
            
            # Let's write the fake address to the actual memory mapped in Unicorn
            uc.mem_write(imp.address, struct.pack("<I", api_addr))
            
            current_fake_addr += 16
            
except AttributeError:
    print("No imports found.")

# API Intercept Hook
def hook_api(uc, address, size, user_data):
    if address in fake_api_map:
        print(f"\n[API CALL] Intercepted call to {fake_api_map[address]}")
        # Note: We placed a `ret` instruction there, so Unicorn will just execute `ret` and continue.
        # But `ret` only pops EIP. Most Windows APIs are `stdcall` and need to pop arguments `ret N`.
        # Since we don't know N, the stack will get corrupted quickly!
        # For a simple prototype, it might crash soon after, which is fine for now.

uc.hook_add(unicorn.UC_HOOK_BLOCK, hook_api)

# Add LVA hook
uc.hook_add(unicorn.UC_HOOK_BLOCK, hook_block)

print("Starting emulation...")
try:
    # Run from entry point until an error occurs or it exits
    uc.emu_start(entry_point, entry_point + size_of_image)
except unicorn.UcError as e:
    pc = uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
    print(f"\n[!] Emulation stopped due to error: {e}")
    print(f"[!] EIP = 0x{pc:x}")

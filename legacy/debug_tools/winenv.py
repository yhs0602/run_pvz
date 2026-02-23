import unicorn
import struct

class WindowsEnvironment:
    """Manages the OS-level memory structures, GDT, registers, and stack for Unicorn x86."""
    
    TEB_BASE = 0x7FFDF000
    PEB_BASE = 0x7FFDE000
    GDT_BASE = 0xC0000000
    STACK_BASE = 0x80000000
    STACK_SIZE = 2 * 1024 * 1024 # 2MB

    def __init__(self, uc, logger=print):
        self.uc = uc
        self.log = logger

    def setup_system(self):
        """Initializes Stack and OS TEB/PEB/GDT scaffolding for SEH."""
        self._setup_stack()
        self._setup_teb_peb()

    def _setup_stack(self):
        self.log(f"Mapping Stack: Base=0x{self.STACK_BASE:x}, Size=0x{self.STACK_SIZE:x}")
        self.uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
        
        stack_top = self.STACK_BASE + self.STACK_SIZE - 0x1000 # Pad slightly below boundary
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, stack_top)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_EBP, stack_top)

    def _create_gdt_entry(self, base, limit, access, flags):
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

    def _setup_teb_peb(self):
        self.log(f"Setting up GDT (0x{self.GDT_BASE:x}) and TEB/PEB (0x{self.TEB_BASE:x})")
        
        # Map OS Regions
        self.uc.mem_map(self.TEB_BASE, 0x1000)
        self.uc.mem_map(self.PEB_BASE, 0x1000)
        self.uc.mem_map(self.GDT_BASE, 0x1000)

        # 1. Setup GDT Entries
        gdt = [
            self._create_gdt_entry(0, 0, 0, 0),                         # 0x00 Null
            self._create_gdt_entry(0, 0xFFFFF, 0x9B, 0xC),              # 0x08 Code32 Ring0
            self._create_gdt_entry(0, 0xFFFFF, 0x93, 0xC),              # 0x10 Data32 Ring0
            self._create_gdt_entry(self.TEB_BASE, 0xFFFFF, 0x93, 0xC)   # 0x18 TEB Ring0
        ]

        for i, entry in enumerate(gdt):
            self.uc.mem_write(self.GDT_BASE + (i * 8), entry)

        # 2. GDTR Load
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_GDTR, (0, self.GDT_BASE, len(gdt) * 8 - 1, 0))

        # 3. Segments Load
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_DS, 0x10)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ES, 0x10)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_SS, 0x10)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_FS, 0x18)

        # 4. TEB Minimum Population
        # fs:[0] SEH head (ExceptionList) = -1 (End)
        self.uc.mem_write(self.TEB_BASE + 0x00, struct.pack("<I", 0xFFFFFFFF)) 
        
        stack_top = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP)
        self.uc.mem_write(self.TEB_BASE + 0x04, struct.pack("<I", stack_top))       # Stack Base
        self.uc.mem_write(self.TEB_BASE + 0x08, struct.pack("<I", self.STACK_BASE)) # Stack Limit
        self.uc.mem_write(self.TEB_BASE + 0x18, struct.pack("<I", self.TEB_BASE))   # TEB ptr
        self.uc.mem_write(self.TEB_BASE + 0x30, struct.pack("<I", self.PEB_BASE))   # PEB ptr

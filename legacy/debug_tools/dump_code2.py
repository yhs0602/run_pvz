import sys
import capstone
import pefile

pe = pefile.PE("pvz/main.exe")
image_base = pe.OPTIONAL_HEADER.ImageBase

def dump(addr, size):
    for sec in pe.sections:
        if sec.VirtualAddress <= addr - image_base < sec.VirtualAddress + sec.Misc_VirtualSize:
            offset = (addr - image_base) - sec.VirtualAddress
            data = sec.get_data()[offset:offset+size]
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            for i in md.disasm(data, addr):
                print(f"0x{i.address:x}: {i.mnemonic}\t{i.op_str}")

dump(0x62120f, 60)

with open("pvz/main.exe", "rb") as f:
    data = f.read()
    import re
    # find calls to 0x61dbe2 (E8 XX XX XX XX)
    target = 0x61dbe2
    import struct
    for match in re.finditer(b'\xE8', data):
        offset = match.start() + 1
        if offset + 4 <= len(data):
            rel = struct.unpack('<i', data[offset:offset+4])[0]
            if 0x400 <= offset < 0x250000:
                va = 0x401000 + (offset - 0x400)
                if va + 4 + rel == target:
                    print(f"Call to 0x61dbe2 at VA 0x{va:x}")

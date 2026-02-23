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

dump(0x628800, 100)

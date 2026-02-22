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
            print(f"--- DUMPING 0x{addr:x} ---")
            for i in md.disasm(data, addr):
                b_str = ' '.join(f'{b:02X}' for b in i.bytes)
                print(f"0x{i.address:x}: {b_str:<20} {i.mnemonic}\t{i.op_str}")

dump(0x5ba8d0, 150)

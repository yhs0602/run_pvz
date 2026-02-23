import pefile, capstone
pe = pefile.PE("pvz/main.exe")
image_base = pe.OPTIONAL_HEADER.ImageBase
rva = 0x60cfd0 - image_base
data = pe.get_memory_mapped_image()[rva:rva+160]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.skipdata = True
for i in md.disasm(data, 0x60cfd0):
    print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

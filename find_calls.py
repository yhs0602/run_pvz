import pefile
import re
import struct

pe = pefile.PE("pvz/main.exe")
image_base = pe.OPTIONAL_HEADER.ImageBase

def find_calls(target_va):
    print(f"Finding calls to 0x{target_va:x}")
    for sec in pe.sections:
        if b'.text' in sec.Name:
            data = sec.get_data()
            va_start = image_base + sec.VirtualAddress
            
            for match in re.finditer(b'\xE8', data):
                offset = match.start()
                if offset + 5 <= len(data):
                    rel = struct.unpack('<i', data[offset+1:offset+5])[0]
                    call_target = va_start + offset + 5 + rel
                    if call_target == target_va:
                        print(f"  -> Called from 0x{va_start + offset:x}")

find_calls(0x628790)

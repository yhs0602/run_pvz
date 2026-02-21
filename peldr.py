import pefile
import unicorn
import struct

def align(value, alignment):
    if value % alignment == 0:
        return value
    return value + (alignment - (value % alignment))

class PEModule:
    """Manages parsing, memory mapping, and IAT resolution for a Windows PE executable."""

    def __init__(self, filepath, logger=print):
        self.filepath = filepath
        self.log = logger
        self.log(f"Parsing PE file: {self.filepath}")
        self.pe = pefile.PE(self.filepath)
        
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size_of_image = align(self.pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)
        self.entry_point = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def map_into(self, uc):
        """Maps the PE image and all its sections into the Unicorn memory space."""
        self.log(f"Mapping image: Base=0x{self.image_base:x}, Size=0x{self.size_of_image:x}")
        uc.mem_map(self.image_base, self.size_of_image)

        header_size = align(self.pe.OPTIONAL_HEADER.SizeOfHeaders, 0x1000)
        self.log(f"Writing PE headers ({header_size} bytes)")
        uc.mem_write(self.image_base, self.pe.header)

        self.log("Mapping Sections:")
        for section in self.pe.sections:
            data = section.get_data()
            vaddr = self.image_base + section.VirtualAddress
            vsize = align(section.Misc_VirtualSize, 0x1000)
            
            name = section.Name.decode('utf-8').strip('\x00')
            self.log(f"  {name:8} VAddr: 0x{vaddr:08x} VSize: 0x{vsize:08x} RawSize: 0x{len(data):08x}")
            
            if len(data) > 0:
                try:
                    uc.mem_write(vaddr, data)
                except unicorn.UcError as e:
                    self.log(f"  ERROR mapping section {name}: {e}")

    def resolve_imports(self, uc, api_handler):
        """Parses the IAT and redirects external DLL calls to the DummyAPIHandler."""
        self.log("Parsing Imports and Stubbing IAT:")
        try:
            self.pe.parse_data_directories()
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                self.log(f"  [{dll_name}]")
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8') if imp.name else f"Ordinal_{imp.ordinal}"
                    full_name = f"{dll_name}!{func_name}"
                    
                    # Register fake API returning a memory address block
                    api_addr = api_handler.register_fake_api(full_name)
                    
                    # Overwrite the actual IAT entry with our fake address
                    uc.mem_write(imp.address, struct.pack("<I", api_addr))
                    
        except AttributeError:
            self.log("No imports found.")

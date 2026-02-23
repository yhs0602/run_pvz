#include "pe_loader.hpp"
#include <iostream>

uint32_t align_size(uint32_t value, uint32_t alignment) {
    if (value % alignment == 0) return value;
    return value + (alignment - (value % alignment));
}

PEModule::PEModule(const std::string& filepath) {
    std::cout << "[*] Parsing PE file: " << filepath << "\n";
    binary = LIEF::PE::Parser::parse(filepath);
    
    if (!binary) {
        throw std::runtime_error("Failed to parse PE file");
    }
    
    image_base = binary->optional_header().imagebase();
    size_of_image = align_size(binary->optional_header().sizeof_image(), 0x1000);
    entry_point = image_base + binary->optional_header().addressof_entrypoint();
}

void PEModule::map_into(CpuBackend& backend) {
    std::cout << "[*] Mapping image: Base=0x" << std::hex << image_base 
              << ", Size=0x" << size_of_image << std::dec << "\n";
              
    backend.mem_map(image_base, size_of_image, UC_PROT_ALL);

    std::cout << "Mapping Sections:\n";
    for (const auto& section : binary->sections()) {
        auto data = section.content();
        if (data.empty()) continue;
        
        uint32_t vaddr = image_base + section.virtual_address();
        uint32_t vsize = align_size(section.virtual_size(), 0x1000);
        
        std::cout << "  " << section.name() << " VAddr: 0x" << std::hex << vaddr 
                  << " VSize: 0x" << vsize << " RawSize: 0x" << data.size() << std::dec << "\n";
                  
        backend.mem_write(vaddr, data.data(), data.size());
    }
}

void PEModule::resolve_imports(CpuBackend& backend, DummyAPIHandler& api_handler) {
    std::cout << "[*] Parsing Imports and Stubbing IAT:\n";
    for (const auto& import : binary->imports()) {
        std::string dll_name = import.name();
        std::cout << "  [" << dll_name << "]\n";
        
        for (const auto& entry : import.entries()) {
            std::string func_name = entry.name();
            if (func_name.empty()) {
                func_name = "Ordinal_" + std::to_string(entry.ordinal());
            }
            std::string full_name = dll_name + "!" + func_name;
            
            uint32_t api_addr = api_handler.register_fake_api(full_name);
            uint32_t iat_vaddr = image_base + entry.iat_address();
            
            backend.mem_write(iat_vaddr, &api_addr, sizeof(uint32_t));
        }
    }
}

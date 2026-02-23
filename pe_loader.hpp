#pragma once

#include "cpu_backend_compat.hpp"
#include <LIEF/PE.hpp>
#include <string>
#include <memory>
#include "api_handler.hpp"

class PEModule {
private:
    std::unique_ptr<LIEF::PE::Binary> binary;
    
public:
    uint32_t image_base;
    uint32_t size_of_image;
    uint32_t entry_point;

    explicit PEModule(const std::string& filepath);
    
    void map_into(uc_engine* uc);
    void resolve_imports(uc_engine* uc, DummyAPIHandler& api_handler);
};

#pragma once

#include "backend/cpu_backend.hpp"
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
    
    void map_into(CpuBackend& backend);
    void resolve_imports(CpuBackend& backend, DummyAPIHandler& api_handler);
};

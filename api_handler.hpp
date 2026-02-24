#pragma once

#include "backend/cpu_backend.hpp"
#include <string>
#include <unordered_map>
#include <iostream>
#include "api_context.hpp"

// Move to an actual dynamic map for late injection (e.g. COM Objects)
extern std::unordered_map<std::string, int> KNOWN_SIGNATURES;

class DummyAPIHandler {
private:
    CpuBackend& backend;
    APIContext ctx;
    bool llm_pipeline_enabled = false;
    bool dylib_mocks_enabled = false;
    int max_api_llm_requests = -1;
    int api_llm_requests_emitted = 0;
    bool api_budget_warned = false;
    std::unordered_map<uint32_t, std::string> fake_api_map;
    std::unordered_map<std::string, void*> dylib_handles;
    std::unordered_map<std::string, void(*)(APIContext*)> dylib_funcs;
    std::unordered_map<std::string, uint64_t> api_call_counts;
    std::unordered_map<uint32_t, uint64_t> eip_hot_page_hits;
    uint64_t api_call_total = 0;
    uint64_t api_stats_interval = 0;
    uint64_t eip_hot_sample_interval = 50000;
    size_t eip_hot_page_cap = 4096;
    uint64_t eip_hot_page_dropped = 0;
    bool eip_hot_sample_enabled = false;
    bool eip_hot_sample_started = false;
    uint32_t current_addr;
    std::string process_base_dir;
    void cleanup_process_state();
    void maybe_start_eip_hot_sample(const std::string& normalized_guest_path);
    void maybe_sample_eip_hot_caller();
    void maybe_print_eip_hot_pages();
    void dispatch_known_or_unknown_api(const std::string& name, uint64_t address, bool known);
    

public:
    static constexpr uint32_t FAKE_API_BASE = 0x90000000;

    explicit DummyAPIHandler(CpuBackend& backend_ref);
    ~DummyAPIHandler();
    
    void set_sdl_window(void* window) { ctx.sdl_window = window; }
    void set_sdl_renderer(void* renderer) { ctx.sdl_renderer = renderer; }
    void set_sdl_texture(void* texture) { ctx.sdl_texture = texture; }
    void set_guest_vram(uint32_t vram) { ctx.guest_vram = vram; }
    void set_host_vram(void* host_buffer) { ctx.host_vram = host_buffer; }
    void set_process_base_dir(const std::string& base_dir) { process_base_dir = base_dir; }
    
    uint32_t register_fake_api(const std::string& full_name);
    uint32_t create_fake_com_object(const std::string& class_name, int num_methods);
    void maybe_print_api_stats();
    
    static void hook_api_call(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    void handle_unknown_api(const std::string& api_name, uint32_t address);
    bool try_load_dylib(const std::string& api_name);
};

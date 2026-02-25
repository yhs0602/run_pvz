#pragma once

#include "backend/cpu_backend.hpp"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <map>
#include <iostream>
#include "api_context.hpp"

// Move to an actual dynamic map for late injection (e.g. COM Objects)
extern std::unordered_map<std::string, int> KNOWN_SIGNATURES;

class DummyAPIHandler {
private:
    struct CoopThreadRegs {
        uint32_t eax = 0;
        uint32_t ebx = 0;
        uint32_t ecx = 0;
        uint32_t edx = 0;
        uint32_t esi = 0;
        uint32_t edi = 0;
        uint32_t ebp = 0;
        uint32_t esp = 0;
        uint32_t eip = 0;
        uint32_t eflags = 0x202;
    };

    struct CoopThreadState {
        uint32_t handle = 0;
        uint32_t thread_id = 0;
        uint32_t start_address = 0;
        uint32_t parameter = 0;
        uint32_t stack_base = 0;
        uint32_t stack_size = 0;
        bool is_main = false;
        bool runnable = true;
        bool finished = false;
        bool waiting_message = false;
        uint32_t wait_hwnd_filter = 0;
        uint32_t wait_min_filter = 0;
        uint32_t wait_max_filter = 0;
        uint64_t quanta = 0;
        CoopThreadRegs regs;
    };

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
    std::unordered_map<std::string, int> dylib_mock_audit_cache; // 1=pass, -1=suspicious
    std::unordered_set<std::string> dylib_mock_audit_warned;
    std::unordered_set<std::string> dylib_mock_runtime_noop_warned;
    bool dylib_mock_audit_enabled = true;
    bool dylib_mock_reject_noop = true;
    bool dylib_mock_runtime_noop_reject = false;
    std::unordered_map<std::string, uint64_t> api_call_counts;
    std::unordered_map<uint32_t, uint64_t> eip_hot_page_hits;
    std::unordered_map<uint32_t, uint64_t> eip_hot_addr_hits;
    bool hot_loop_api_trace_enabled = false;
    uint64_t hot_loop_api_trace_interval = 50000;
    uint32_t hot_focus_range = 0x80;
    std::vector<uint32_t> hot_focus_centers;
    size_t hot_loop_api_cap = 4096;
    uint64_t hot_loop_api_dropped = 0;
    std::unordered_map<std::string, uint64_t> hot_loop_api_counts;
    std::unordered_map<std::string, std::unordered_map<uint32_t, uint64_t>> hot_loop_api_eax_hist;
    std::unordered_map<std::string, std::unordered_map<uint32_t, uint64_t>> hot_loop_api_lasterror_hist;
    uint64_t api_call_total = 0;
    uint64_t api_stats_interval = 0;
    uint64_t eip_hot_sample_interval = 50000;
    size_t eip_hot_page_cap = 4096;
    size_t eip_hot_addr_cap = 16384;
    uint64_t eip_hot_page_dropped = 0;
    uint64_t eip_hot_addr_dropped = 0;
    bool eip_hot_sample_enabled = false;
    bool eip_hot_sample_started = false;
    bool coop_threads_enabled_flag = false;
    bool coop_threads_initialized = false;
    bool coop_trace = false;
    bool coop_force_yield = false;
    bool coop_fail_create_thread_on_spawn_failure = true;
    uint64_t coop_timeslice_instructions = 30000;
    uint32_t coop_max_live_threads = 256;
    uint32_t coop_main_handle = 0x1000;
    uint32_t coop_current_handle = 0;
    uint32_t coop_thread_id_top = 1;
    uint32_t coop_default_stack_size = 0x200000;
    uint32_t coop_stack_cursor = 0x2F000000;
    uint32_t coop_live_threads = 0;
    uint64_t coop_spawn_fail_count = 0;
    size_t guest_thread_handle_count = 0;
    std::multimap<uint32_t, uint32_t> coop_free_stacks_by_size; // size -> stack base
    std::vector<uint32_t> coop_order;
    std::unordered_map<uint32_t, CoopThreadState> coop_threads;
    uint32_t current_addr;
    std::string process_base_dir;
    bool coop_read_regs(CoopThreadRegs& regs);
    void coop_write_regs(const CoopThreadRegs& regs);
    bool coop_save_current_thread_regs();
    bool coop_load_thread_regs(uint32_t handle);
    bool coop_advance_to_next_runnable();
    void coop_prune_finished_threads();
    bool coop_mark_thread_finished(uint32_t handle, const char* reason);
    bool coop_try_reuse_stack(uint32_t stack_size, uint32_t& stack_base);
    void coop_recycle_thread_stack(CoopThreadState& thread);
    size_t reap_finished_thread_handles(size_t target_keep);
    size_t thread_handle_count() const { return guest_thread_handle_count; }
    void note_thread_handle_created() { guest_thread_handle_count++; }
    void note_thread_handle_closed() { if (guest_thread_handle_count > 0) guest_thread_handle_count--; }
    void cleanup_process_state();
    uint32_t get_api_caller_ret_addr();
    bool is_hot_focus_ret(uint32_t ret_addr) const;
    void maybe_start_eip_hot_sample(const std::string& normalized_guest_path);
    void maybe_sample_eip_hot_caller(uint32_t ret_addr);
    void maybe_print_eip_hot_pages();
    void record_hot_loop_api_stat(uint32_t ret_addr, const std::string& api_name);
    void maybe_print_hot_loop_api_stats();
    void dispatch_known_or_unknown_api(const std::string& name, uint64_t address, bool known);
    bool audit_dylib_mock_source(const std::string& api_name, std::string* reason_out);
    bool dispatch_dylib_mock(const std::string& api_name);
    

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
    bool coop_threads_enabled() const { return coop_threads_enabled_flag; }
    size_t coop_timeslice_count() const { return static_cast<size_t>(coop_timeslice_instructions); }
    void coop_register_main_thread();
    uint32_t coop_current_pc() const;
    uint32_t coop_current_thread_id() const;
    bool coop_current_thread_is_main() const;
    bool coop_prepare_to_run();
    bool coop_spawn_thread(uint32_t handle, uint32_t start_address, uint32_t parameter, uint32_t requested_stack_size);
    bool coop_is_thread_finished(uint32_t handle) const;
    bool coop_fail_create_on_spawn_failure() const { return coop_fail_create_thread_on_spawn_failure; }
    void coop_block_current_thread_on_message_wait(uint32_t hwnd_filter, uint32_t min_filter, uint32_t max_filter);
    void coop_notify_message_enqueued(uint32_t target_thread_id, uint32_t msg_hwnd, uint32_t msg_id);
    void coop_wake_message_waiter(uint32_t thread_id);
    void coop_wake_all_message_waiters();
    void coop_request_yield() { coop_force_yield = true; }
    void coop_on_timeslice_end();
    bool coop_try_absorb_emu_error(uc_err err);
    bool coop_should_terminate() const;
    
    static void hook_api_call(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    void handle_unknown_api(const std::string& api_name, uint32_t address);
    bool try_load_dylib(const std::string& api_name);
};

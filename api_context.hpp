#pragma once

#include "backend/cpu_backend.hpp"
#include <string>
#include <unordered_map>

struct APIContext {
    CpuBackend* backend = nullptr;
    uc_engine* uc = nullptr; // Kept for compatibility with generated api_mocks.
    void* sdl_window; // Opaque pointer to SDL_Window
    void* sdl_renderer; // Opaque pointer to SDL_Renderer
    void* sdl_texture; // Opaque pointer to SDL_Texture
    uint32_t guest_vram; // 32-bit Unicorn memory pointer for IDirectDrawSurface
    void* host_vram; // Opaque Host pixel buffer for SDL_UpdateTexture
    std::unordered_map<std::string, uint64_t> global_state;
    std::unordered_map<std::string, void*> handle_map;
    
    // Quick helper to read arguments from Windows x86 stack (stdcall)
    // index 0 is first argument
    uint32_t get_arg(int index) {
        if (!backend) return 0;
        uint32_t esp;
        backend->reg_read(UC_X86_REG_ESP, &esp);
        uint32_t val;
        // Skip return address (+4)
        uc_err err = backend->mem_read(esp + 4 + (index * 4), &val, sizeof(val));
        if (err) return 0;
        return val;
    }

    // Set EAX return value
    void set_eax(uint32_t val) {
        if (!backend) return;
        backend->reg_write(UC_X86_REG_EAX, &val);
    }

    // Emulate stdcall return
    void pop_args(int num_args) {
        if (!backend) return;
        uint32_t esp;
        backend->reg_read(UC_X86_REG_ESP, &esp);
        uint32_t ret_addr;
        backend->mem_read(esp, &ret_addr, 4);
        esp += (num_args * 4) + 4;
        backend->reg_write(UC_X86_REG_ESP, &esp);
        backend->reg_write(UC_X86_REG_EIP, &ret_addr);
    }
};

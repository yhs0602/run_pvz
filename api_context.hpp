#pragma once

#include "cpu_backend_compat.hpp"
#include <string>
#include <unordered_map>

struct APIContext {
    uc_engine* uc;
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
        uint32_t esp;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uint32_t val;
        // Skip return address (+4)
        uc_err err = uc_mem_read(uc, esp + 4 + (index * 4), &val, sizeof(val));
        if (err) return 0;
        return val;
    }

    // Set EAX return value
    void set_eax(uint32_t val) {
        uc_reg_write(uc, UC_X86_REG_EAX, &val);
    }

    // Emulate stdcall return
    void pop_args(int num_args) {
        uint32_t esp;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uint32_t ret_addr;
        uc_mem_read(uc, esp, &ret_addr, 4);
        esp += (num_args * 4) + 4;
        uc_reg_write(uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    }
};

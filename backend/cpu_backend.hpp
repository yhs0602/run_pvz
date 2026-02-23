#pragma once

#include "../cpu_backend_compat.hpp"

class CpuBackend {
public:
    virtual ~CpuBackend() = default;

    virtual bool open_x86_32() = 0;
    virtual void close() = 0;
    virtual uc_engine* engine() const = 0;

    virtual uc_err mem_map(uint64_t address, size_t size, uint32_t perms) = 0;
    virtual uc_err mem_read(uint64_t address, void* bytes, size_t size) = 0;
    virtual uc_err mem_write(uint64_t address, const void* bytes, size_t size) = 0;

    virtual uc_err reg_read(int regid, void* value) = 0;
    virtual uc_err reg_write(int regid, const void* value) = 0;

    virtual uc_err emu_start(uint64_t begin, uint64_t until, uint64_t timeout, size_t count) = 0;
    virtual uc_err emu_stop() = 0;

    virtual uc_err hook_add(uc_hook* hook, int type, void* callback, void* user_data, uint64_t begin, uint64_t end) = 0;
    virtual const char* strerror(uc_err err) const = 0;
};


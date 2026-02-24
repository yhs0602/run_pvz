#pragma once

#include "cpu_backend.hpp"

class UnicornBackend : public CpuBackend {
public:
    UnicornBackend() = default;
    ~UnicornBackend();

    bool open_x86_32() override;
    void close() override;
    uc_engine* engine() const override { return uc_; }

    uc_err mem_map(uint64_t address, size_t size, uint32_t perms) override;
    uc_err mem_read(uint64_t address, void* bytes, size_t size) override;
    uc_err mem_write(uint64_t address, const void* bytes, size_t size) override;

    uc_err reg_read(int regid, void* value) override;
    uc_err reg_write(int regid, const void* value) override;

    uc_err emu_start(uint64_t begin, uint64_t until, uint64_t timeout, size_t count) override;
    uc_err emu_stop() override;
    uc_err flush_tb_cache() override;

    uc_err hook_add(uc_hook* hook, int type, void* callback, void* user_data, uint64_t begin, uint64_t end) override;

    const char* strerror(uc_err err) const override;

private:
    uc_engine* uc_ = nullptr;
};

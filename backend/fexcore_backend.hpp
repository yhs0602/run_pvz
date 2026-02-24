#pragma once

#include "cpu_backend.hpp"
#include "unicorn_backend.hpp"
#include <memory>
#include <string>

class FexCoreBackend : public CpuBackend {
public:
    FexCoreBackend() = default;
    ~FexCoreBackend() override;

    bool open_x86_32() override;
    void close() override;
    uc_engine* engine() const override;

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
    bool open_bridge();
    void close_bridge();

    struct BridgeAPI {
        void* handle = nullptr;
        bool (*open_x86_32)(void**) = nullptr;
        void (*close)(void*) = nullptr;
        uc_err (*mem_map)(void*, uint64_t, size_t, uint32_t) = nullptr;
        uc_err (*mem_read)(void*, uint64_t, void*, size_t) = nullptr;
        uc_err (*mem_write)(void*, uint64_t, const void*, size_t) = nullptr;
        uc_err (*reg_read)(void*, int, void*) = nullptr;
        uc_err (*reg_write)(void*, int, const void*) = nullptr;
        uc_err (*emu_start)(void*, uint64_t, uint64_t, uint64_t, size_t) = nullptr;
        uc_err (*emu_stop)(void*) = nullptr;
        uc_err (*flush_tb)(void*) = nullptr;
        uc_err (*hook_add)(void*, uc_hook*, int, void*, void*, uint64_t, uint64_t) = nullptr;
        const char* (*strerror)(uc_err) = nullptr;
        const char* (*backend_name)() = nullptr;
    };

    BridgeAPI bridge_;
    void* bridge_ctx_ = nullptr;
    bool using_bridge_ = false;

    std::unique_ptr<UnicornBackend> unicorn_fallback_;
    std::string bridge_path_;
};

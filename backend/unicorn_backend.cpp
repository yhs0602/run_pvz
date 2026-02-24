#include "unicorn_backend.hpp"

UnicornBackend::~UnicornBackend() {
    close();
}

bool UnicornBackend::open_x86_32() {
    if (uc_) {
        return true;
    }
    return uc_open(UC_ARCH_X86, UC_MODE_32, &uc_) == UC_ERR_OK;
}

void UnicornBackend::close() {
    if (uc_) {
        uc_close(uc_);
        uc_ = nullptr;
    }
}

uc_err UnicornBackend::mem_map(uint64_t address, size_t size, uint32_t perms) {
    return uc_mem_map(uc_, address, size, perms);
}

uc_err UnicornBackend::mem_read(uint64_t address, void* bytes, size_t size) {
    return uc_mem_read(uc_, address, bytes, size);
}

uc_err UnicornBackend::mem_write(uint64_t address, const void* bytes, size_t size) {
    return uc_mem_write(uc_, address, bytes, size);
}

uc_err UnicornBackend::reg_read(int regid, void* value) {
    return uc_reg_read(uc_, regid, value);
}

uc_err UnicornBackend::reg_write(int regid, const void* value) {
    return uc_reg_write(uc_, regid, value);
}

uc_err UnicornBackend::emu_start(uint64_t begin, uint64_t until, uint64_t timeout, size_t count) {
    return uc_emu_start(uc_, begin, until, timeout, count);
}

uc_err UnicornBackend::emu_stop() {
    return uc_emu_stop(uc_);
}

uc_err UnicornBackend::flush_tb_cache() {
    if (!uc_) return UC_ERR_HANDLE;
    return uc_ctl_flush_tb(uc_);
}

uc_err UnicornBackend::hook_add(uc_hook* hook, int type, void* callback, void* user_data, uint64_t begin, uint64_t end) {
    return uc_hook_add(uc_, hook, type, callback, user_data, begin, end);
}

const char* UnicornBackend::strerror(uc_err err) const {
    return uc_strerror(err);
}

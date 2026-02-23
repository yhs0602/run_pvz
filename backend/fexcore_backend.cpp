#include "fexcore_backend.hpp"

#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits.h>
#include <string>
#include <vector>

namespace {
template <typename T>
T load_sym(void* handle, const char* name) {
    return reinterpret_cast<T>(dlsym(handle, name));
}

bool env_truthy(const char* name) {
    const char* v = std::getenv(name);
    if (!v || !*v) return false;
    std::string s(v);
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return !(s == "0" || s == "false" || s == "off" || s == "no");
}

std::string executable_dir() {
    char local[PATH_MAX];
    uint32_t size = sizeof(local);
    std::vector<char> dynamic_buf;
    char* raw = local;
    if (_NSGetExecutablePath(local, &size) != 0) {
        dynamic_buf.assign(size + 1, '\0');
        if (_NSGetExecutablePath(dynamic_buf.data(), &size) != 0) {
            return {};
        }
        raw = dynamic_buf.data();
    }

    std::error_code ec;
    std::filesystem::path exe_path(raw);
    std::filesystem::path normalized = std::filesystem::weakly_canonical(exe_path, ec);
    if (ec) {
        normalized = exe_path;
    }
    return normalized.parent_path().string();
}
}

FexCoreBackend::~FexCoreBackend() {
    close();
}

bool FexCoreBackend::open_bridge() {
    if (bridge_.handle) {
        return true;
    }

    const char* env_path = std::getenv("PVZ_FEXCORE_BRIDGE_PATH");
    std::vector<std::string> candidates;
    if (env_path && *env_path) {
        candidates.emplace_back(env_path);
    } else {
        candidates.emplace_back("libpvz_fexcore_bridge.dylib");

        std::string exe_dir = executable_dir();
        if (!exe_dir.empty()) {
            candidates.emplace_back((std::filesystem::path(exe_dir) / "libpvz_fexcore_bridge.dylib").string());
        }

        std::error_code ec;
        std::filesystem::path cwd = std::filesystem::current_path(ec);
        if (!ec) {
            candidates.emplace_back((cwd / "libpvz_fexcore_bridge.dylib").string());
        }
    }

    for (const std::string& candidate : candidates) {
        bridge_.handle = dlopen(candidate.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (bridge_.handle) {
            bridge_path_ = candidate;
            break;
        }
    }

    if (!bridge_.handle) {
        return false;
    }

    bridge_.open_x86_32 = load_sym<bool (*)(void**)>(bridge_.handle, "pvz_fex_open_x86_32");
    bridge_.close = load_sym<void (*)(void*)>(bridge_.handle, "pvz_fex_close");
    bridge_.mem_map = load_sym<uc_err (*)(void*, uint64_t, size_t, uint32_t)>(bridge_.handle, "pvz_fex_mem_map");
    bridge_.mem_read = load_sym<uc_err (*)(void*, uint64_t, void*, size_t)>(bridge_.handle, "pvz_fex_mem_read");
    bridge_.mem_write = load_sym<uc_err (*)(void*, uint64_t, const void*, size_t)>(bridge_.handle, "pvz_fex_mem_write");
    bridge_.reg_read = load_sym<uc_err (*)(void*, int, void*)>(bridge_.handle, "pvz_fex_reg_read");
    bridge_.reg_write = load_sym<uc_err (*)(void*, int, const void*)>(bridge_.handle, "pvz_fex_reg_write");
    bridge_.emu_start = load_sym<uc_err (*)(void*, uint64_t, uint64_t, uint64_t, size_t)>(bridge_.handle, "pvz_fex_emu_start");
    bridge_.emu_stop = load_sym<uc_err (*)(void*)>(bridge_.handle, "pvz_fex_emu_stop");
    bridge_.hook_add = load_sym<uc_err (*)(void*, uc_hook*, int, void*, void*, uint64_t, uint64_t)>(bridge_.handle, "pvz_fex_hook_add");
    bridge_.strerror = load_sym<const char* (*)(uc_err)>(bridge_.handle, "pvz_fex_strerror");
    bridge_.backend_name = load_sym<const char* (*)()>(bridge_.handle, "pvz_fex_bridge_backend_name");

    const bool complete =
        bridge_.open_x86_32 &&
        bridge_.close &&
        bridge_.mem_map &&
        bridge_.mem_read &&
        bridge_.mem_write &&
        bridge_.reg_read &&
        bridge_.reg_write &&
        bridge_.emu_start &&
        bridge_.emu_stop &&
        bridge_.hook_add &&
        bridge_.strerror;

    if (!complete) {
        std::cerr << "[!] FEX bridge loaded but missing required symbols: " << bridge_path_ << "\n";
        close_bridge();
        return false;
    }

    std::cout << "[*] FEX bridge loaded: " << bridge_path_ << "\n";
    if (bridge_.backend_name) {
        const char* impl = bridge_.backend_name();
        if (impl && *impl) {
            std::cout << "[*] FEX bridge backend implementation: " << impl << "\n";
        }
    }

    if (env_truthy("PVZ_FEXCORE_STRICT")) {
        const char* impl = bridge_.backend_name ? bridge_.backend_name() : nullptr;
        if (!impl || std::string(impl) != "fexcore") {
            std::cerr << "[!] PVZ_FEXCORE_STRICT=1 but bridge backend is not 'fexcore'.\n";
            close_bridge();
            return false;
        }
    }
    return true;
}

void FexCoreBackend::close_bridge() {
    if (bridge_ctx_ && bridge_.close) {
        bridge_.close(bridge_ctx_);
    }
    bridge_ctx_ = nullptr;
    using_bridge_ = false;

    if (bridge_.handle) {
        dlclose(bridge_.handle);
    }
    bridge_ = {};
}

bool FexCoreBackend::open_x86_32() {
    const bool strict_mode = env_truthy("PVZ_FEXCORE_STRICT");

    if (using_bridge_) {
        return true;
    }
    if (unicorn_fallback_) {
        return true;
    }

    if (open_bridge()) {
        if (bridge_.open_x86_32(&bridge_ctx_)) {
            using_bridge_ = true;
            return true;
        }
        if (strict_mode) {
            std::cerr << "[!] PVZ_FEXCORE_STRICT=1 and bridge open failed.\n";
            close_bridge();
            return false;
        }
        std::cerr << "[!] FEX bridge open failed. Falling back to Unicorn backend.\n";
        close_bridge();
    } else {
        if (strict_mode) {
            std::cerr << "[!] PVZ_FEXCORE_STRICT=1 and FEX bridge could not be loaded.\n";
            return false;
        }
        std::cerr << "[*] FEX bridge unavailable. Falling back to Unicorn backend.\n";
    }

    unicorn_fallback_ = std::make_unique<UnicornBackend>();
    return unicorn_fallback_->open_x86_32();
}

void FexCoreBackend::close() {
    if (unicorn_fallback_) {
        unicorn_fallback_->close();
        unicorn_fallback_.reset();
    }
    close_bridge();
}

uc_engine* FexCoreBackend::engine() const {
    if (using_bridge_) {
        // Existing hooks/API code expects a uc_engine* token.
        // In bridge mode this is an opaque context pointer.
        return reinterpret_cast<uc_engine*>(bridge_ctx_);
    }
    return unicorn_fallback_ ? unicorn_fallback_->engine() : nullptr;
}

uc_err FexCoreBackend::mem_map(uint64_t address, size_t size, uint32_t perms) {
    if (using_bridge_) return bridge_.mem_map(bridge_ctx_, address, size, perms);
    return unicorn_fallback_->mem_map(address, size, perms);
}

uc_err FexCoreBackend::mem_read(uint64_t address, void* bytes, size_t size) {
    if (using_bridge_) return bridge_.mem_read(bridge_ctx_, address, bytes, size);
    return unicorn_fallback_->mem_read(address, bytes, size);
}

uc_err FexCoreBackend::mem_write(uint64_t address, const void* bytes, size_t size) {
    if (using_bridge_) return bridge_.mem_write(bridge_ctx_, address, bytes, size);
    return unicorn_fallback_->mem_write(address, bytes, size);
}

uc_err FexCoreBackend::reg_read(int regid, void* value) {
    if (using_bridge_) return bridge_.reg_read(bridge_ctx_, regid, value);
    return unicorn_fallback_->reg_read(regid, value);
}

uc_err FexCoreBackend::reg_write(int regid, const void* value) {
    if (using_bridge_) return bridge_.reg_write(bridge_ctx_, regid, value);
    return unicorn_fallback_->reg_write(regid, value);
}

uc_err FexCoreBackend::emu_start(uint64_t begin, uint64_t until, uint64_t timeout, size_t count) {
    if (using_bridge_) return bridge_.emu_start(bridge_ctx_, begin, until, timeout, count);
    return unicorn_fallback_->emu_start(begin, until, timeout, count);
}

uc_err FexCoreBackend::emu_stop() {
    if (using_bridge_) return bridge_.emu_stop(bridge_ctx_);
    return unicorn_fallback_->emu_stop();
}

uc_err FexCoreBackend::hook_add(uc_hook* hook, int type, void* callback, void* user_data, uint64_t begin, uint64_t end) {
    if (using_bridge_) return bridge_.hook_add(bridge_ctx_, hook, type, callback, user_data, begin, end);
    return unicorn_fallback_->hook_add(hook, type, callback, user_data, begin, end);
}

const char* FexCoreBackend::strerror(uc_err err) const {
    if (using_bridge_) return bridge_.strerror(err);
    return unicorn_fallback_ ? unicorn_fallback_->strerror(err) : "backend not initialized";
}

#include "api_context.hpp"

#include <cstdint>
#include <string>

static std::string read_ansi_z(APIContext* ctx, uint32_t ptr) {
    if (ptr == 0) {
        return {};
    }

    std::string out;
    out.reserve(64);
    for (uint32_t i = 0; i < 260; ++i) {
        char ch = 0;
        if (!ctx->backend || ctx->backend->mem_read(ptr + i, &ch, 1) != UC_ERR_OK || ch == '\0') {
            break;
        }
        out.push_back(ch);
    }
    return out;
}

extern "C" void mock_LoadCursorA(APIContext* ctx) {
    const uint32_t hInstance = ctx->get_arg(0);
    const uint32_t lpCursorName = ctx->get_arg(1);

    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87u;
    constexpr uint32_t ERROR_RESOURCE_NAME_NOT_FOUND = 1814u;

    auto alloc_cursor_handle = [&](const std::string& key) -> uint32_t {
        auto it = ctx->global_state.find(key);
        if (it != ctx->global_state.end() && it->second != 0) {
            return static_cast<uint32_t>(it->second);
        }

        uint64_t next_handle = 0x00030000ull;
        auto next_it = ctx->global_state.find("LoadCursorA_next_handle");
        if (next_it != ctx->global_state.end() && next_it->second >= 0x10000ull) {
            next_handle = next_it->second;
        }

        const uint32_t handle = static_cast<uint32_t>(next_handle);
        ctx->global_state[key] = static_cast<uint64_t>(handle);
        ctx->global_state["LoadCursorA_next_handle"] = next_handle + 4ull;
        return handle;
    };

    uint32_t result = 0;

    if (lpCursorName == 0) {
        ctx->global_state["LastError"] = ERROR_INVALID_PARAMETER;
    } else if ((lpCursorName & 0xFFFF0000u) == 0) {
        const uint32_t cursor_id = lpCursorName & 0xFFFFu;

        bool is_system_cursor_id = false;
        switch (cursor_id) {
            case 32512u: // IDC_ARROW / OCR_NORMAL
            case 32513u: // IDC_IBEAM / OCR_IBEAM
            case 32514u: // IDC_WAIT / OCR_WAIT
            case 32515u: // IDC_CROSS / OCR_CROSS
            case 32516u: // IDC_UPARROW / OCR_UP
            case 32642u: // IDC_SIZENWSE / OCR_SIZENWSE
            case 32643u: // IDC_SIZENESW / OCR_SIZENESW
            case 32644u: // IDC_SIZEWE / OCR_SIZEWE
            case 32645u: // IDC_SIZENS / OCR_SIZENS
            case 32646u: // IDC_SIZEALL / OCR_SIZEALL
            case 32648u: // IDC_NO / OCR_NO
            case 32649u: // IDC_HAND / OCR_HAND
            case 32650u: // IDC_APPSTARTING / OCR_APPSTARTING
            case 32651u: // IDC_HELP / OCR_HELP
                is_system_cursor_id = true;
                break;
            default:
                break;
        }

        if (hInstance == 0) {
            if (is_system_cursor_id) {
                const std::string key = "LoadCursorA:sys:id:" + std::to_string(cursor_id);
                result = alloc_cursor_handle(key);
                ctx->global_state["LastError"] = ERROR_SUCCESS;
            } else {
                ctx->global_state["LastError"] = ERROR_RESOURCE_NAME_NOT_FOUND;
            }
        } else {
            const std::string key =
                "LoadCursorA:mod:" + std::to_string(hInstance) + ":id:" + std::to_string(cursor_id);
            result = alloc_cursor_handle(key);
            ctx->global_state["LastError"] = ERROR_SUCCESS;
        }
    } else {
        const std::string name = read_ansi_z(ctx, lpCursorName);

        if (name.empty()) {
            ctx->global_state["LastError"] = ERROR_INVALID_PARAMETER;
        } else if (hInstance == 0) {
            // System cursors are typically requested via MAKEINTRESOURCE IDs when hInstance is NULL.
            ctx->global_state["LastError"] = ERROR_RESOURCE_NAME_NOT_FOUND;
        } else {
            const std::string key =
                "LoadCursorA:mod:" + std::to_string(hInstance) + ":name:" + name;
            result = alloc_cursor_handle(key);
            ctx->global_state["LastError"] = ERROR_SUCCESS;
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    ctx->backend->mem_read(esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
    ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
}

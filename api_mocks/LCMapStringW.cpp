#include "api_context.hpp"

#include <cstdint>
#include <vector>

extern "C" void mock_LCMapStringW(APIContext* ctx) {
    constexpr uint32_t LCMAP_LOWERCASE = 0x00000100;
    constexpr uint32_t LCMAP_UPPERCASE = 0x00000200;
    constexpr uint32_t LCMAP_SORTKEY = 0x00000400;
    constexpr uint32_t LCMAP_BYTEREV = 0x00000800;

    constexpr uint32_t ERROR_SUCCESS = 0;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
    constexpr uint32_t ERROR_INSUFFICIENT_BUFFER = 122;

    const uint32_t locale = ctx->get_arg(0);
    const uint32_t dw_map_flags = ctx->get_arg(1);
    const uint32_t lp_src_str = ctx->get_arg(2);
    const int32_t cch_src = static_cast<int32_t>(ctx->get_arg(3));
    const uint32_t lp_dest_str = ctx->get_arg(4);
    const int32_t cch_dest = static_cast<int32_t>(ctx->get_arg(5));

    (void)locale;

    uint32_t last_error = ERROR_SUCCESS;
    uint32_t result = 0;
    bool ok = true;

    auto fail = [&](uint32_t err) {
        last_error = err;
        result = 0;
        ok = false;
    };

    if (lp_src_str == 0 || cch_src == 0 || cch_src < -1 || cch_dest < 0) {
        fail(ERROR_INVALID_PARAMETER);
    }

    std::vector<uint16_t> source;
    bool src_is_nul_terminated = false;

    if (ok) {
        if (cch_src == -1) {
            constexpr uint32_t kMaxScan = 1u << 20;
            bool found_nul = false;
            for (uint32_t i = 0; i < kMaxScan; ++i) {
                uint16_t ch = 0;
                if (uc_mem_read(ctx->uc, lp_src_str + (i * 2), &ch, sizeof(ch)) != UC_ERR_OK) {
                    fail(ERROR_INVALID_PARAMETER);
                    break;
                }
                source.push_back(ch);
                if (ch == 0) {
                    found_nul = true;
                    break;
                }
            }
            if (ok && !found_nul) {
                fail(ERROR_INVALID_PARAMETER);
            }
            src_is_nul_terminated = true;
        } else {
            source.resize(static_cast<size_t>(cch_src));
            if (!source.empty() &&
                uc_mem_read(ctx->uc, lp_src_str, source.data(), source.size() * sizeof(uint16_t)) != UC_ERR_OK) {
                fail(ERROR_INVALID_PARAMETER);
            }
        }
    }

    if (ok) {
        const bool use_lower = (dw_map_flags & LCMAP_LOWERCASE) != 0;
        const bool use_upper = (dw_map_flags & LCMAP_UPPERCASE) != 0;
        const bool use_sortkey = (dw_map_flags & LCMAP_SORTKEY) != 0;
        const bool use_byterev = (dw_map_flags & LCMAP_BYTEREV) != 0;

        if (use_lower && use_upper) {
            fail(ERROR_INVALID_PARAMETER);
        }

        if (ok && use_sortkey) {
            std::vector<uint8_t> sort_key;
            size_t char_count = source.size();
            if (src_is_nul_terminated && char_count > 0 && source.back() == 0) {
                --char_count;
            }

            sort_key.reserve(char_count * 2 + 1);
            for (size_t i = 0; i < char_count; ++i) {
                uint16_t ch = source[i];
                if (ch >= static_cast<uint16_t>('A') && ch <= static_cast<uint16_t>('Z')) {
                    ch = static_cast<uint16_t>(ch + 32);
                }

                uint8_t lo = static_cast<uint8_t>(ch & 0xFFu);
                uint8_t hi = static_cast<uint8_t>((ch >> 8) & 0xFFu);

                if (use_byterev) {
                    sort_key.push_back(hi);
                    sort_key.push_back(lo);
                } else {
                    sort_key.push_back(lo);
                    sort_key.push_back(hi);
                }
            }
            sort_key.push_back(0);

            const uint32_t required = static_cast<uint32_t>(sort_key.size());

            if (cch_dest == 0) {
                result = required;
            } else if (lp_dest_str == 0) {
                fail(ERROR_INVALID_PARAMETER);
            } else if (static_cast<uint32_t>(cch_dest) < required) {
                fail(ERROR_INSUFFICIENT_BUFFER);
            } else if (required > 0 && uc_mem_write(ctx->uc, lp_dest_str, sort_key.data(), required) != UC_ERR_OK) {
                fail(ERROR_INVALID_PARAMETER);
            } else {
                result = required;
            }
        }

        if (ok && !use_sortkey) {
            std::vector<uint16_t> mapped = source;

            size_t map_count = mapped.size();
            if (src_is_nul_terminated && map_count > 0 && mapped.back() == 0) {
                --map_count;
            }

            for (size_t i = 0; i < map_count; ++i) {
                uint16_t ch = mapped[i];
                if (use_upper) {
                    if (ch >= static_cast<uint16_t>('a') && ch <= static_cast<uint16_t>('z')) {
                        ch = static_cast<uint16_t>(ch - 32);
                    }
                } else if (use_lower) {
                    if (ch >= static_cast<uint16_t>('A') && ch <= static_cast<uint16_t>('Z')) {
                        ch = static_cast<uint16_t>(ch + 32);
                    }
                }

                if (use_byterev) {
                    ch = static_cast<uint16_t>(((ch & 0x00FFu) << 8) | ((ch & 0xFF00u) >> 8));
                }
                mapped[i] = ch;
            }

            const uint32_t required = static_cast<uint32_t>(mapped.size());

            if (cch_dest == 0) {
                result = required;
            } else if (lp_dest_str == 0) {
                fail(ERROR_INVALID_PARAMETER);
            } else if (static_cast<uint32_t>(cch_dest) < required) {
                fail(ERROR_INSUFFICIENT_BUFFER);
            } else if (required > 0 &&
                       uc_mem_write(ctx->uc, lp_dest_str, mapped.data(), mapped.size() * sizeof(uint16_t)) != UC_ERR_OK) {
                fail(ERROR_INVALID_PARAMETER);
            } else {
                result = required;
            }
        }
    }

    ctx->global_state["LastError"] = last_error;
    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 24 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
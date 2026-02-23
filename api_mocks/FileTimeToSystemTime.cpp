#include "api_context.hpp"

#include <cstdint>

namespace {
struct SystemTimeLayout {
    uint16_t wYear;
    uint16_t wMonth;
    uint16_t wDayOfWeek;
    uint16_t wDay;
    uint16_t wHour;
    uint16_t wMinute;
    uint16_t wSecond;
    uint16_t wMilliseconds;
};

static void civil_from_days(int64_t z, int32_t& year, uint32_t& month, uint32_t& day) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const uint32_t doe = static_cast<uint32_t>(z - era * 146097);
    const uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    year = static_cast<int32_t>(yoe + era * 400);
    const uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const uint32_t mp = (5 * doy + 2) / 153;
    const int32_t m = static_cast<int32_t>(mp) + (mp < 10 ? 3 : -9);
    day = doy - (153 * mp + 2) / 5 + 1;
    month = static_cast<uint32_t>(m);
    year += (m <= 2);
}
} // namespace

extern "C" void mock_FileTimeToSystemTime(APIContext* ctx) {
    constexpr uint32_t ERROR_SUCCESS = 0u;
    constexpr uint32_t ERROR_INVALID_PARAMETER = 87u;
    constexpr uint32_t ERROR_NOACCESS = 998u;
    constexpr uint64_t TICKS_PER_SECOND = 10000000ull;
    constexpr uint64_t TICKS_PER_MILLISECOND = 10000ull;
    constexpr uint64_t SECONDS_PER_DAY = 86400ull;
    constexpr int64_t DAYS_1601_TO_1970 = 134774; // 1601-01-01 -> 1970-01-01

    const uint32_t lpFileTime = ctx->get_arg(0);
    const uint32_t lpSystemTime = ctx->get_arg(1);

    uint32_t result = 0;

    if (lpFileTime == 0 || lpSystemTime == 0) {
        ctx->global_state["LastError"] = ERROR_INVALID_PARAMETER;
    } else {
        uint32_t low = 0;
        uint32_t high = 0;
        const uc_err r0 = uc_mem_read(ctx->uc, lpFileTime, &low, sizeof(low));
        const uc_err r1 = uc_mem_read(ctx->uc, lpFileTime + 4, &high, sizeof(high));

        if (r0 != UC_ERR_OK || r1 != UC_ERR_OK) {
            ctx->global_state["LastError"] = ERROR_NOACCESS;
        } else {
            const uint64_t ft = (static_cast<uint64_t>(high) << 32) | static_cast<uint64_t>(low);
            const uint64_t total_seconds = ft / TICKS_PER_SECOND;
            const uint32_t milliseconds = static_cast<uint32_t>((ft / TICKS_PER_MILLISECOND) % 1000ull);
            const uint64_t days_since_1601 = total_seconds / SECONDS_PER_DAY;
            const uint64_t sec_of_day = total_seconds % SECONDS_PER_DAY;

            int32_t year = 0;
            uint32_t month = 0;
            uint32_t day = 0;
            civil_from_days(static_cast<int64_t>(days_since_1601) - DAYS_1601_TO_1970, year, month, day);

            if (year < 1601 || year > 30827) {
                ctx->global_state["LastError"] = ERROR_INVALID_PARAMETER;
            } else {
                SystemTimeLayout st{};
                st.wYear = static_cast<uint16_t>(year);
                st.wMonth = static_cast<uint16_t>(month);
                st.wDayOfWeek = static_cast<uint16_t>((days_since_1601 + 1ull) % 7ull); // 0=Sunday
                st.wDay = static_cast<uint16_t>(day);
                st.wHour = static_cast<uint16_t>(sec_of_day / 3600ull);
                st.wMinute = static_cast<uint16_t>((sec_of_day % 3600ull) / 60ull);
                st.wSecond = static_cast<uint16_t>(sec_of_day % 60ull);
                st.wMilliseconds = static_cast<uint16_t>(milliseconds);

                if (uc_mem_write(ctx->uc, lpSystemTime, &st, sizeof(st)) == UC_ERR_OK) {
                    result = 1;
                    ctx->global_state["LastError"] = ERROR_SUCCESS;
                } else {
                    ctx->global_state["LastError"] = ERROR_NOACCESS;
                }
            }
        }
    }

    ctx->set_eax(result);

    uint32_t esp;
    uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr;
    uc_mem_read(ctx->uc, esp, &ret_addr, 4);
    esp += 8 + 4; // Add arg size + 4 bytes for the return address itself
    uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);
}
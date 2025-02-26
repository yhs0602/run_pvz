#include <ctime>
#include <cstdint>
#include <sys/time.h>

typedef struct _FILETIME {
    uint32_t dwLowDateTime;
    uint32_t dwHighDateTime;
} FILETIME;

void GetSystemTimeAsFileTime(FILETIME* lpSystemTimeAsFileTime) {
    if (!lpSystemTimeAsFileTime) return;  // NULL 체크

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);  // 현재 UTC 시간 가져오기 (초 + 나노초)

    // 1970년 기준으로 FILETIME 변환 (1601년 기준으로 보정)
    uint64_t unix_time_100ns = (uint64_t)ts.tv_sec * 10000000 + (ts.tv_nsec / 100);
    uint64_t filetime_value = unix_time_100ns + 116444736000000000ULL;

    // FILETIME 구조체에 저장 (64비트 값을 32비트 두 개로 분할)
    lpSystemTimeAsFileTime->dwLowDateTime = (uint32_t)(filetime_value & 0xFFFFFFFF);
    lpSystemTimeAsFileTime->dwHighDateTime = (uint32_t)(filetime_value >> 32);
}

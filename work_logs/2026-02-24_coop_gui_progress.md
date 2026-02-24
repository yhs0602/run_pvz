# 2026-02-24 Cooperative GUI Progress

## 오늘 반영한 변경
- `USER32` 경로 보강:
  - `PostThreadMessageA/W`, `SendMessageA/W`, `GetWindowThreadProcessId` 처리 추가.
  - `CreateWindowExA/W`에서 HWND를 고정값이 아니라 증가 핸들로 발급하도록 변경.
  - 윈도우별 owner thread id 추적(`g_hwnd_owner_thread_id`) 추가.
- WndProc 브릿지 보강:
  - `CreateWindowEx` 시 등록된 클래스 WndProc를 `GWL_WNDPROC(-4)` 슬롯으로 연결.
  - `DispatchMessage`/`SendMessage`에서 해당 WndProc로 직접 점프하는 브릿지 유지.
  - `PVZ_WNDPROC_TRACE=1`로 `RegisterClass/CreateWindowEx/Dispatch/SendMessage` 로그 추가.
- heap 장기실행 안정화:
  - free-list 메타데이터 상한(`PVZ_HEAP_FREE_CAP_ENTRIES`, 기본 131072) 추가.
  - cap 초과 시 recycle map clear 가드 추가.
  - heap active allocation이 0일 때 `HeapTop`/free-list 정리 루틴 추가.
- 루프 추적 도구 추가:
  - `PVZ_BLOCK_FOCUS_TRACE` / `PVZ_BLOCK_FOCUS_ADDRS` / `PVZ_BLOCK_FOCUS_INTERVAL` / `PVZ_BLOCK_FOCUS_DUMP_BYTES`.
  - 포커스 주소 히트 시 레지스터 + 샘플 메모리 출력.

## 오늘 런타임 관찰
- `CreateThread(start=0x5d5dc0)` cooperative spawn/entry 관측은 지속적으로 성공.
- `ReleaseCapture`는 UNKNOWN 경로에서 제거(known API로 처리됨).
- 여전히 주요 API hot path는 `HeapAlloc/HeapFree`, `Enter/LeaveCriticalSection`.
- block focus 샘플에서 문자열 처리 루프(0x441a/0x441d/0x404470/0x5d8890/0x62456a) 반복 확인.
- `IDirectDrawSurface7::Lock/Unlock` 호출은 아직 미관측.

## 현재 결론
- 병목은 “CreateThread 미진입”이 아니라, 스레드 진입 후 초기 경로에서 렌더 루프로 넘어가기 전 상태/메시지 정합성에 있음.
- 다음 집중점:
  1. `0x5d5dc0` worker에서 `RegisterClass/CreateWindowEx/GetMessage`까지 더 진행하도록 장시간 샘플/스케줄러 페어니스 재확인.
  2. `SendMessage/PostThreadMessage` 실제 호출 여부와 payload 정합성 확인.
  3. `Lock/Unlock` 직전 조건(API 반환값, 이벤트/메시지 상태) 추적 강화.

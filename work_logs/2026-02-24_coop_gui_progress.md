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

## 22:50 이후 추가 진행
- loader/HLE 정합성 보강:
  - `GetModuleHandleA/W`, `LoadLibraryA/W`, `FreeLibrary`, `GetProcAddress`를 native known-path로 구현.
  - `PVZ_LOADER_TRACE` 추가로 module handle 해상 결과를 추적 가능하게 함.
  - `VERSION.dll`, `SHELL32.dll`, `D3D8.dll` 등 module-case 정합성 보강으로 `GetProcAddress`가 unknown으로 빠지는 경로 축소.
  - `VERSION.dll!GetFileVersionInfo*`, `VERSION.dll!VerQueryValueA`, `USER32.dll!GetLastInputInfo`를 known-path에 추가.
- DDRAW old-interface 안정화:
  - `IDirectDraw_Method_0/6/20/21/22/23` 시그니처 및 처리 보강.
  - `IDDSurface/IDirectDrawSurface2`의 `Method_0(QueryInterface)` 처리 추가.
  - 기존 크래시 포인트(`UC_ERR_READ_UNMAPPED`)가 `IDirectDraw_Method_23`, `IDDSurface_Method_0` unhandled 구간에서 발생하던 문제를 제거.
- 런타임 결과:
  - 120초 런에서 Direct3D/DirectSound/BASS export 해상 단계까지 진행, unknown/fallback 없이 유지.
  - 300초 런에서도 `Unknown API` 로그 없이 진행하며 초기 그래픽/오디오 초기화 단계가 더 깊게 진행됨.
  - 현재는 `CreateSurface` 반복 및 BASS export 해상 이후 단계로 넘어가는 장주기 구간을 계속 추적 중.

## 23:20 이후 추가 관찰
- 로그 폭증/실행속도 영향 완화:
  - `GetLastError/SetLastError`, `OutputDebugStringA/W`, `BASS/DSOUND GetProcAddress` noisy 로그를 기본적으로 축소.
- 장주기 동작:
  - 크래시는 재현되지 않고(`UC_ERR_READ_UNMAPPED` 미재현), 120~300초 런은 timeout 강제 종료 전까지 진행 유지.
  - 다만 `CreateThread/Wait/PostMessage` 구간 진입 전, 자원 처리 hot block에서 시간 소모가 큼.
- block-hot 결과(120초 샘플):
  - 상위 루프: `0x441a73`, `0x5d8890`, `0x62456a`, `0x441dd0`, `0x404470`.
  - focus snapshot에서 `REANIM\\...PNG`, `IM\\ZOMBIE_...PNG` 등 리소스 문자열이 지속적으로 변화.
  - 결론: 완전 정체라기보다, 리소스 문자열/패스 처리 단계가 매우 길게 이어지는 상태.

## 23:50 이후 추가 진행
- cooperative 메시지 큐 정합성 보강:
  - 내부 Win32 메시지 큐를 thread-aware 엔벨로프(`target_thread_id`)로 변경.
  - `PostThreadMessage`는 지정 thread id로 라우팅, `PostMessage`/`WM_TIMER`는 `hwnd -> owner thread` 기준 라우팅.
  - `GetMessage/PeekMessage/MsgWaitForMultipleObjects`가 현재 cooperative thread id 기준으로 메시지를 소비하도록 수정.
- 런타임 관찰(90s/240s):
  - `CreateThread/Wait/PostMessage` 구간은 해당 샘플 구간에서 아직 미진입.
  - hot block는 계속 `0x441a73 / 0x5d8890 / 0x62456a / 0x441dd0 / 0x404470` 중심.
  - `0x62ce9b/0x62cf8e/0x62118b/0x61fcd4`는 이번 샘플에서 관측되지 않음(해당 단계 이전).
- 추가 성능 가드 도입:
  - `PVZ_HOT_LOOP_ACCEL=1` 옵션 추가(기본 OFF).
  - 주소별 fast-path:
    - `0x441a73` dword memcmp 루프,
    - `0x5d888c/0x5d8890` XOR copy 루프,
    - `0x62456a` `rep movsd` 루프,
    - `0x404470` strlen 루프.
  - 목적: 리소스 전처리 구간 체류 시간을 줄여 GUI thread/message 경로까지 더 빨리 도달하도록 가속.
  - 가속 적용 후 hot set가 `0x441dd0/0x441dd9/0x441d2x..0x441d7x`, `0x61e4e6/0x61e4ef`, `0x5d7c0d/0x5d7c24`로 이동.

## 00:10 이후 추가 진행
- non-blocking 운영 보강:
  - `PVZ_AUTO_ACK_MESSAGEBOX` 추가(비대화 세션 기본 ON): `MessageBoxA/W` 팝업 없이 로그만 남기고 `IDOK` 반환.
  - 기존 `PVZ_DISABLE_SDL_MESSAGEBOX`와 함께 unattended 장시간 런에서 메시지박스 블로킹 제거.
- GUI 검증 도구 보강:
  - `PVZ_VRAM_SNAPSHOT` / `PVZ_VRAM_SNAPSHOT_EVERY` / `PVZ_VRAM_SNAPSHOT_PREFIX` 추가.
  - VRAM present 훅에서 PPM 프레임 덤프 저장 가능(렌더링 루프 진입 여부 시각 확인용).
  - `PVZ_SYNTH_CLICK` / `PVZ_SYNTH_CLICK_DELAY_MS` / `PVZ_SYNTH_CLICK_X/Y` 추가:
    - 지정 시점에 `WM_LBUTTONDOWN/UP`를 queue에 1회 주입해 버튼 반응 경로 테스트 가능.
- hot set 추가 가속:
  - `0x61e4e6`(toupper 계열) 함수 엔트리 fast-path.
  - `0x441d20`(문자 1개 append) fast-path.
  - 결과적으로 `0x404470`가 top hot set에서 이탈하고, 현재는 `0x441dd0/0x441dd9` 및 `0x5d7cxx` 체인이 주요 잔여 병목.

## 2026-02-25 추가 진행 (CreateThread/Wait 경로 안정화)
- cooperative 스레드 안정화/메모리 가드
  - `PVZ_COOP_MAX_LIVE_THREADS`(기본 256) 추가: live guest thread 상한.
  - finished thread stack 재사용 풀(`size -> base`) 추가: stack map 폭증 방지.
  - `CloseHandle(thread)`/thread finish 시 stack recycle 경로 연결.
  - `PVZ_COOP_FAIL_CREATE_THREAD_ON_SPAWN_FAILURE`(기본 ON) 추가: cooperative spawn 실패 시 `CreateThread=0`, `LastError=8` 반환.
- CreateThread 장기 실행 보호
  - `PVZ_THREAD_HANDLE_CAP`(기본 8192) 추가.
  - cap 도달 시 finished thread handle reap 시도 후, 여전히 초과면 `CreateThread` 실패 반환.
  - `CreateThread`/`WaitForSingleObject` 로그를 샘플링 출력(초기 N회 + 주기)으로 축소.
- fast-worker 진단 가드
  - `PVZ_WORKER_THREAD_CREATE_CAP` 추가(기본: `PVZ_FAST_WORKER_THREAD=1`이면 512).
  - fast-worker 폭주 시 무한 CreateThread 루프를 cap 이후 실패로 전환.
- 메시지 루프 정합성 보강
  - `PostMessage(HWND_BROADCAST)`를 실제 유효 윈도우들로 fan-out 큐잉하도록 수정.
- hot set 가속/정합성
  - `0x441dd0`(single-char store helper) fast-path 추가.
  - `0x61e4e6` fast-path에 locale flag(`0x6a66f4`) 분기 조건 반영.

### 런타임 관찰
- `logs_fex_fastworker_cap_20260225_015805.log`
  - fast-worker cap hit 이후 `WaitForSingleObject(0x7000/0x7004)` 및 `CreateFileA('properties\\resources.xml')` 재확인.
  - 기존 stack-map OOM으로 진행하던 경로를 제어 가능한 cap 기반으로 재현 가능.
- `logs_fex_fastworker_cap_long_20260225_020532.log`, `logs_fex_fastworker_cap240_20260225_020850.log`
  - cap 이후에도 `resources.xml` 단계까지는 안정적으로 진입.
  - 본 샘플 구간에서는 `PostMessage/GetMessage` 재관측은 아직 없음.
- `logs_fex_full_progress2_20260225_020313.log`
  - fast-worker OFF full mode는 120초 샘플에서 여전히 초기 리소스/DirectX 초기화 구간 체류.

### 메모
- 로그가 GB 단위로 커지는 경우가 있어(특히 fast-worker + thread trace) 전체 스캔 대신:
  - `wc -c`, `tail`, 키워드 샘플링(`rg ... | tail`) 방식으로 분석.
  - 과대 로그는 삭제하고 요약만 업무일지에 남김.

### 2026-02-25 추가 미세 가속
- `0x441dd9` small-string capacity branch fast-path 추가(분기만 직접 계산).
- `0x441dd0/0x441dd9/0x5d7c0d/0x61e4e6` 요청 hot set에 대해 모두 가속/정합성 경로 확보.

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

### 2026-02-25 LLM API Mock 감사 강화
- `api_mocks/<Func>.cpp` 소스 정적 감사 추가:
  - `set_eax/pop_args/memory-reg write/global_state` 등 상태 변경 토큰이 전혀 없으면 no-op 의심으로 분류.
- 런타임 동작:
  - `PVZ_REJECT_NOOP_DYLIB_MOCKS=1`(기본)일 때 의심 mock은 로딩 후 실행하지 않고 generic success fallback.
  - 감사 자체를 끄려면 `PVZ_DISABLE_DYLIB_MOCK_AUDIT=1`.
- 기존 mock 소스 75개를 스캔해 현재 시점 no-op 의심 0개 확인.

### 2026-02-25 GUI 루프 병목 추가 정리
- `PostThreadMessage/PostMessage` cooperative 경로에서 `emu_stop()` 강제 중단 제거:
  - 기존에는 post 호출마다 즉시 중단이 걸려 producer 쪽 과선점 + 큐 포화(`queue=4096`)가 반복될 수 있었음.
  - 현재는 `coop_request_yield()`만 남겨 timeslice 기반 전환에 맡김.
- Win32 메시지 큐 backpressure 보강:
  - queue tail 동일 메시지(`hwnd/msg/wParam/lParam/target_tid`) 중복 enqueue dedup 추가.
  - queue full(4096) 시 동일 tail 메시지는 drop, 아니면 oldest drop 후 enqueue.
  - `PVZ_MSG_DEDUP_START`(기본 1024), `PVZ_DISABLE_MSG_DEDUP` 환경변수 추가.
- Win32 메시지 큐 계측:
  - `enqueued/dequeued/drop_full/drop_dedup` 누적 카운터 추가.
  - `PVZ_MSG_QUEUE_STATS_INTERVAL`로 주기 출력 가능.
- LLM dylib mock 의심 강화(런타임):
  - mock 호출 전후 `EAX/ESP/LastError/global_state/handle_map` 변화가 모두 없으면 runtime no-op 의심 로그 1회 출력.
  - 기본은 경고만, `PVZ_REJECT_RUNTIME_NOOP_DYLIB_MOCKS=1`에서 fallback success로 강제 거부.

### 2026-02-25 검증 러닝 (queue guard / mock suspicion)
- 빌드: `cmake --build build-fex -j8` 성공.
- 실행 로그:
  - `logs_fex_msgqueue_guard_20260225_082248.log`
  - `logs_fex_msgqueue_guard_long_20260225_082329.log`
  - `logs_fex_msgqueue_stats100_20260225_082521.log`
- 관찰:
  - 이번 샘플에서도 `CreateThread(cap hit) -> WaitForSingleObject(0x7000/0x7004) -> CreateFileA('properties\\resources.xml')` 경로까지 확인.
  - 샘플 구간 내 `PostMessage/GetMessage` 진입은 아직 미관측(큐 통계 로그도 미발생).
  - 따라서 queue dedup/backpressure는 코드 레벨로 적용 완료, 실제 포화 재현 로그는 다음 장기 샘플에서 추가 확인 필요.

### 2026-02-25 렌더링 진입 가속 추가
- 임시 우회 백로그 분리:
  - `work_logs/2026-02-25_temp_workarounds_backlog.md` 추가.
  - hot-loop/CRT allocator/message queue/mock audit 등 임시 처리 항목을 P0~P2로 정리.
- hot 주소 기반 가속 확장(`main.cpp`):
  - `0x621182` CRT `HeapAlloc` callsite fast-path 추가(`PVZ_CRT_ALLOC_ACCEL`).
  - `0x61fcc5/0x61fcc6` CRT `HeapFree` callsite fast-success 분기 추가.
  - `0x62ce88/0x62cf60` lock wrapper steady-state short-circuit 추가(enter wrapper는 slot 미초기화 시 원경로 유지).
  - 요약 카운터(`CRT free fast-path`, `Lock-wrapper fast-path`) 출력 추가.
- 설정 기본값 조정:
  - `PVZ_CRT_ALLOC_ACCEL` 미지정 시 `PVZ_HOT_LOOP_ACCEL=1`이면 자동 ON.
  - README에 `PVZ_CRT_ALLOC_ACCEL` / `PVZ_CRT_ALLOC_ARENA_MB` 사용법 추가.

### 2026-02-25 정체 구간(0x562742 이후) 추가 추적/가속
- `PVZ_BLOCK_HOT_SAMPLE=1` 샘플 결과:
  - 정체 이후 hot top이 `0x5d8f50/0x5d8f6d/0x5d8f7b/0x5d8f9b/0x5d8fb4/0x5d8fc3` 트리 탐색 루프로 수렴.
  - `0x62118b/0x61fcd4`보다 `0x5d8fxx` 비중이 크게 증가.
- 조치:
  - `main.cpp`에 `0x5d8f50/0x5d8f58` 트리 lookup loop fast-path 추가.
  - guest 트리 노드 순회 + 문자열 비교(min(len) memcmp + 길이 tie-break) 로직을 host 루프로 수행 후 `0x5d8fcc`로 복귀.
  - `main.cpp`에 `0x61be1b` memmove_s wrapper fast-path 추가(정상 인자 경로만 단축, 오류 경로는 원본 유지).
  - `main.cpp`에 `0x624510` memmove fast-path 추가(겹침 영역 포함).
  - 목적: resources 단계 container lookup 병목 단축으로 렌더링 루프 진입 시간 단축.
- 버그 수정:
  - 초기 구현에서 `0x621182` fast-path의 stdcall stack 정리(`ESP += 4`)가 누락되어 `EIP=0x1` 조기 크래시 발생.
  - 즉시 수정 후 동일 조기 크래시 재현되지 않음(DDRAW 초기화 구간 재진입 확인).

### 2026-02-25 추가 진행 (WndProc/메시지 루프 정합성)
- `RegisterClass*` 조기 dummy intercept 제거:
  - `hook_api_call`의 hardcoded `RegisterClass` 우회 반환을 제거하여 known-dispatch 경로로 일원화.
  - 목적: 클래스 등록 파싱/저장(`g_win32_class_by_name/by_atom`)이 실제로 반영되도록 정합성 회복.
- `CreateWindowEx` strict fail 기본 해제:
  - 미등록 클래스는 기본적으로 `fallback` 진행(엄격 실패는 `PVZ_STRICT_CREATEWINDOW_CLASS=1`에서만).
  - 이유: strict 모드에서 `SetWindowLong(hwnd=0, -21, ...)` 패턴이 반복되어 GUI 루프 진입이 막힘.
- `GetMessage` idle synthetic timer 기본 OFF:
  - `PVZ_FORCE_IDLE_TIMER=1`일 때만 idle `WM_TIMER` 합성하도록 변경.
  - 이유: 실제 timer 등록 없이 synthetic `WM_TIMER`가 과도하게 생성되어 `DispatchMessage` 루프를 장시간 점유.

### 2026-02-25 11:49 KST 렌더링 진입 가속 추가(문자열 병목)
- `main.cpp`에 `0x5bd830` wide-string append/fill fast-path 추가(`PVZ_WSTRING_APPEND_ACCEL`).
  - 적용 조건: `new_len <= cap`인 grow 불필요 정상 경로만 host-side bulk write 수행.
  - 폴백 정책: capacity 부족/오버플로/비정상 포인터는 즉시 guest 원본 경로로 반환.
  - side effect 반영: `[this+0x14]` length, terminator(`wchar_t NUL`), `EAX=this`, `ret 8` 정합 유지.
- 블록 집중 추적 대상 확대:
  - `PVZ_BLOCK_FOCUS_ADDRS` 기본 세트에 `0x5bd830/0x5bd88a/0x5bf470/0x5bf47b` 추가.
  - 해당 주소에서 stack args/this 객체 메모리 샘플 출력 보강.
- 임시 우회 백로그 반영:
  - `work_logs/2026-02-25_temp_workarounds_backlog.md`에 위 fast-path를 P0로 등록.

### 2026-02-25 12:00 KST 추가 가속(Iterator Advance)
- `resources.xml` 이후 hot set에서 `0x5bf4e0/0x5bf4ef/0x5bf4f8/0x5bf518/0x5bf52f` 군집이 급상승하는 것 확인.
- `main.cpp`에 `0x5bf4e0` iterator advance fast-path 추가(`PVZ_ITER_ADVANCE_ACCEL`, 기본: hot-loop와 동행 ON).
  - owner sentinel(`-2`) 경로: 검사 없이 `cur += delta` 수행.
  - 일반 owner 경로: `[owner+0x14/0x18]` 기반 범위 검증(`base <= new_cur <= base+len`) 통과 시만 단축, 실패 시 guest 폴백.
  - 반환 규약: `EAX=this`, `ret 4` 유지.
- block focus 기본 주소에 `0x5bf4e0/0x5bf4ef/0x5bf4f8/0x5bf518/0x5bf52f` 추가.

### 2026-02-25 12:10 KST 추가 가속(memmove_s + string insert)
- `0x5bf4e0` 가속 후 상위 hot set이 `0x61be96/0x61beeb`, `0x55d410/0x55d4xx`, `0x5bba20/0x5bba..`로 이동한 것 확인.
- `main.cpp`에 `0x61be96` memmove_s fast-path 추가(`PVZ_MEMMOVE_S_ACCEL`, 기본 ON).
  - 정상 인자에서 host-side overlap-safe copy 후 성공 리턴.
  - 오류 조건(`NULL`, `destsz<count`)은 guest 폴백으로 유지.
- `main.cpp`에 `0x55d410` string insert/fill fast-path 추가(`PVZ_STRING_INSERT_ACCEL`, 기본 ON).
  - `pos <= len`, `new_len <= cap` 경로에서 tail shift + fill + terminator + length 갱신.
  - grow/예외 경로는 guest 폴백.
- block focus 기본 주소에 `0x61be96/0x61beeb/0x55d410` 추가.

### 2026-02-25 12:20 KST 추가 가속(insert iterator)
- `0x5bba20/0x5bba..` 군집이 상위 hot에 고정되는 것을 확인해 함수 단위 fast-path 추가.
- `main.cpp`에 `0x5bba20` insert+iterator fast-path 추가(`PVZ_INSERT_ITER_ACCEL`, 기본 ON).
  - 입력 iterator(owner/pointer)에서 index를 산출해 1-byte insert를 직접 수행.
  - 결과 iterator(`out_iter`)를 `{string_obj, data_ptr+index}`로 갱신.
  - owner mismatch/범위 초과/capacity 부족은 guest 폴백 유지.
- block focus 기본 주소에 `0x5bba20/0x5bbad0/0x5bbb12` 추가.

### 2026-02-25 12:25 KST 실행 검증 요약(연속 2분 샘플)
- 실행 로그:
  - `logs_render_push_iteradv_20260225_115536.log`
  - `logs_render_push_insert_20260225_120031.log`
  - `logs_render_push_insiter_20260225_120454.log`
- 공통 관찰:
  - `CreateThread cap hit -> WaitForSingleObject(0x7000/0x7004) -> CreateFileA('properties\\resources.xml')` 경로는 안정 재현.
  - 샘플 구간 내 `IDirectDrawSurface7::Lock/Unlock` 미진입.
- 병목 이동:
  - `0x61be96/0x55d410/0x5bba20` 직접 병목은 fast-path hit 증가로 완화.
  - 새 상위 hot set은 `0x5afc0d/0x5afc26/0x5afc06`, `0x5bbad0/0x5bbb12/0x5bbafa`, `0x61be1b`, `0x441a60` 군집으로 이동.
- 결론:
  - 문자열 helper 체인은 단계적으로 단축되고 있으나, parser/iterator 상위 루프가 여전히 렌더링 루프 진입을 막고 있음.

### 2026-02-25 12:35 KST 회귀 대응
- `0x5bba20` insert+iterator fast-path ON 샘플(`logs_render_push_insiter_20260225_120454.log`)에서
  - 동일 시간 기준 hot-accel hit 처리량이 이전 대비 저하(대략 1.05M -> 0.85M 수준).
  - parser 루프(`0x5afc0d/0x5afc26/0x5bbad0/0x5bbb12`) 집중이 강화됨.
- 조치:
  - `PVZ_INSERT_ITER_ACCEL` 기본값을 OFF로 롤백(명시 opt-in일 때만 활성화).
  - 해당 fast-path는 실험 옵션으로 유지하고, 기본 경로는 안정적 가속 세트로 계속 진행.

### 2026-02-25 12:45 KST 추가 가속(wide->narrow small)
- `PVZ_INSERT_ITER_ACCEL=off` 검증 로그(`logs_render_push_insiter_off_20260225_120847.log`)에서
  - 처리량이 이전 안정 패턴(2분 기준 약 1.05M hit)으로 복귀 확인.
- 새 상위 병목인 `0x5afc06/0x5afc0d/0x5afc26`(wide 문자열 순회 + `0x5bbad0` append 체인) 대응:
  - `main.cpp`에 `0x5afbb0` 함수 단위 fast-path 추가(`PVZ_WSTR_TO_STR_ACCEL`, 기본 ON).
  - 우선 안전 범위 `len <= 15`(SSO 목적지)에서 wide->narrow 변환을 host에서 일괄 처리.
  - 장문 문자열(`len > 15`)은 guest 폴백 유지.

### 2026-02-25 13:20 KST 추가 가속(브랜치 블록 + memmove wrapper 정합)
- `main.cpp` `0x61be1b` memmove_s wrapper fast-path를 오류 경로까지 확장.
  - `dst==NULL -> 0x16`, `src==NULL -> dst zero-fill + 0x16`, `destsz<count -> dst zero-fill + 0x22`를 host 경로에서 직접 반영.
  - 기존 정상 경로 copy만 단축하던 상태에서 invalid-arg 루프 fallback을 줄임.
- `main.cpp` `0x61be96` memmove_s fast-path도 오류 리턴(`0x16/0x22`)까지 포함하도록 확장.
- `main.cpp` `0x5bb880` stream pop 함수 fast-path 추가(`PVZ_STREAM_POP_ACCEL`).
  - 비어있지 않은 버퍼에서 `wchar` pop + 포인터 갱신 경로를 직접 처리.
- `main.cpp` 블록 단위 정합 가속 추가:
  - streambuf 브랜치 블록: `0x5bb880/0x5bb894/0x5bb89f` (`PVZ_STREAMBUF_BRANCH_ACCEL`)
  - xml parser 브랜치 블록: `0x5a1f72/0x5a1f7b/0x5a1f8b/0x5a2052/0x5a210a` (`PVZ_XML_BRANCH_ACCEL`)
  - 의도: 함수 semantics를 유지한 채 branch-only 핫 블록의 에뮬레이션 오버헤드를 줄여 `resources.xml` 파서 진행률 개선.
- 새 카운터/옵션/요약 로그 추가:
  - `memwrap`, `streampop`, `sbbranch`, `xmlbranch`
  - `PVZ_STREAM_POP_ACCEL`, `PVZ_STREAMBUF_BRANCH_ACCEL`, `PVZ_XML_BRANCH_ACCEL`

### 2026-02-25 13:35 KST 실행 검증 요약(장시간 샘플)
- 검증 로그:
  - `logs_render_push_streampop_20260225_122021.log` (90s)
  - `logs_render_push_xmlbranch_20260225_122638.log` (75s)
  - `logs_render_push_long_20260225_122815.log` (150s)
  - `logs_render_push_5min_20260225_123143.log` (장시간 샘플)
- 관찰:
  - `resources.xml` 진입 경로 안정 재현: `CreateThread -> WaitForSingleObject(0x7000/0x7004) -> CreateFileA('properties\\resources.xml')`.
  - `IDirectDrawSurface7::Lock/Unlock`는 샘플 구간에서 여전히 미관측.
  - 다만 처리율은 유의미하게 증가:
    - `xmlbranch/sbbranch` 카운터가 빠르게 누적(`xmlbranch` 수십만, `sbbranch` 수십만)되며 parser 브랜치 단위 가속이 실제로 동작.
    - `memwrap` 카운터도 지속 증가해 `0x61be1b` 오류/정상 혼합 경로 fallback 비율이 감소.
- 결론:
  - 렌더링 루프 전 단계(`resources.xml` 이후 parser 체인) throughput은 확실히 개선.
  - 다음 병목은 여전히 parser 루프 상위 체인(`0x456610`, `0x5a1640`, `0x5bd830`, `0x61be1b`, `0x5bb88x`, `0x5a1fxx`)이며, `Lock/Unlock` 진입까지는 추가 압축이 필요.

### 2026-02-25 21:50 KST 추가 진행(text-normalize 루프 + coop 재검증)
- `main.cpp`에 text normalize branch-block fast-path 추가:
  - 대상: `0x62b0d8/0x62b0e5/0x62b0e9/0x62b0f5/0x62b0fd/0x62b105/0x62b184/0x62b185`
  - 옵션: `PVZ_TEXT_NORM_BRANCH_ACCEL` (미지정 시 hot-loop와 동행 ON)
  - 계측: `txtnorm` 카운터/요약, block-focus 기본 주소셋에 `0x62b0xx` 추가
- 실행 안정화 보강:
  - guest VRAM 매핑 크기를 페이지 정렬(`align_up(guest_vram_size, 0x1000)`)로 변경.
  - guest/null-page 매핑 실패 시 즉시 원인 로그를 출력하도록 보강.
- non-coop 검증(`logs_render_push_textnorm_noncoop_20260225_213039.log`):
  - `CreateThread -> WaitForSingleObject(0x7000/0x7004) -> CreateFileA('properties\\resources.xml')` 재확인.
  - `txtnorm` 누적이 지속 증가(샘플 종료 시 `txtnorm=233584`, `hits=1700000`).
  - 상위 hot set은 여전히 `0x456610/0x5a1640/0x5bd830/0x61be1b/0x5bb880/0x5a1f72...` 중심.
  - `IDirectDrawSurface7::Lock/Unlock`는 이번 샘플에서도 미관측.
- coop 경로 관찰:
  - 추적 로그(`logs_coop_thread_diag_20260225_213512.log`)에서 worker thread spawn/실행 관측(`start=0x5d5dc0`, `SetEvent(0x7000)` 확인).
  - 그러나 장시간 coop 샘플(`logs_render_push_textnorm_escalated_long_20260225_212128.log`, `logs_coop_default7500_probe_20260225_213839.log`)은 `CreateThread` 구간 체류가 길어 `Wait/resources.xml` 재진입까지 충분히 진행하지 못함.
  - 다음 액션: coop scheduler 공정성/worker bootstrap 완료 조건을 별도 계측으로 추가 분해.

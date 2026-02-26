# x86-to-ARM64 Hybrid JIT Emulator

세계 최초의 **Unicorn 기반 인공지능 보조 하이브리드 JIT 컴파일러**입니다.
이 엔진은 macOS (Apple Silicon) 상에서 Windows 32-bit x86 바이너리를 구동하며, 핫스팟 기본 블록을 감지해 LLM 언어 모델을 통해 ARM64 네이티브 코드로 크로스 컴파일 후 실행합니다. 

현재 `pvz/main.exe` (Plants vs. Zombies) 바이너리를 엔진 위에 올려서 에뮬레이션을 구동하는 테스트 파이프라인이 완성되어 있습니다.

## 🚀 파이프라인 구동 방법 (How to Run)

기본 모드는 **저비용/저지연(LLM OFF)** 입니다.  
LLM 번역 파이프라인을 사용할 때만 아래 Python 데몬 2개를 함께 실행하세요.

### 1단계: JIT 어셈블리 번역 데몬 실행 (터미널 1)
에뮬레이터가 자주 실행되는 병목 구간(Hotspot)을 발견하면 이 데몬이 ARM64 기계어로 실시간 번역합니다.
```bash
# 가상 환경 활성화 후 실행
source .venv/bin/activate
python llm_compiler.py
```

### 2단계: 동적 API 모킹 데몬 실행 (터미널 2)
에뮬레이터가 실행 중 모르는 Windows API(예: `TlsGetValue`, `GetModuleHandleA`)를 마주쳐서 일시 정지되면, 이 데몬이 실시간으로 C++ 확장 플러그인 모듈(`.dylib`)을 코딩하고 컴파일해줍니다.
```bash
source .venv/bin/activate
python api_compiler.py
```

### 3단계: C++ Core JIT 엔진 구동 (터미널 3)
메인 엔진 단독으로 실행해도 됩니다(기본: LLM OFF).
```bash
# 이전에 컴파일된 캐시 파일들을 지우고 새로 처음부터 런타임을 감상하려면 아래 명령어로 정리하세요.
rm -rf compiled_blocks/* llm_cache/* jit_requests/* api_requests/* api_mocks/*

# 메인 실행
./build/runner pvz/main.exe

# LLM 파이프라인 ON (필요할 때만)
PVZ_ENABLE_LLM=1 PVZ_ENABLE_DYLIB_MOCKS=1 ./build/runner pvz/main.exe
```

### 4단계: `PVZ_CPU_BACKEND=fexcore` 빌드/실행 (full mode)
`fexcore` 백엔드 경로를 타려면 전용 빌드 디렉토리를 사용하세요.
```bash
# fexcore 백엔드 빌드
cmake -S . -B build-fex -DPVZ_CPU_BACKEND=fexcore
cmake --build build-fex -j8

# full mode 실행 (headless 아님)
DYLD_LIBRARY_PATH="$PWD:/usr/local/lib:/opt/homebrew/lib" \
PVZ_DISABLE_NATIVE_JIT=1 \
PVZ_ENABLE_DYLIB_MOCKS=1 \
PVZ_MAP_NULL_PAGE=1 \
./build-fex/runner pvz/main.exe
```

`build-fex/libpvz_fexcore_bridge.dylib`가 자동 빌드되며, 실행 로그에 아래가 보이면 브리지 경유입니다.
- `[*] CPU backend: fexcore`
- `[*] FEX bridge loaded: ...`
- `[*] FEX bridge backend implementation: ...`

실제 libfexcore 구현만 강제하려면 아래처럼 strict 모드를 사용하세요.
```bash
PVZ_FEXCORE_STRICT=1 ./build-fex/runner pvz/main.exe
```
이때 브리지 구현명이 `fexcore`가 아니면 즉시 종료됩니다.

### (선택) 디버그/헤드리스 실행 옵션
디스플레이가 없는 환경이나 코어 부팅 추적이 필요할 때 사용합니다.
```bash
# 창 없이 이벤트만 초기화
PVZ_HEADLESS=1 ./build/runner pvz/main.exe

# 네이티브 ARM64 JIT 디스패처 비활성화
PVZ_DISABLE_NATIVE_JIT=1 ./build/runner pvz/main.exe

# 부팅 체크포인트 로그 활성화
PVZ_BOOT_TRACE=1 ./build/runner pvz/main.exe

# JIT 동적 mock(.dylib) 비활성화 (내장 HLE만 사용)
PVZ_DISABLE_DYLIB_MOCKS=1 ./build/runner pvz/main.exe

# LLM 파이프라인 활성화 (기본 OFF)
PVZ_ENABLE_LLM=1 ./build/runner pvz/main.exe

# 동적 API mock(.dylib) 로더 활성화 (기본 OFF)
PVZ_ENABLE_DYLIB_MOCKS=1 ./build/runner pvz/main.exe

# dylib mock 소스 감사 비활성화 (기본 감사 ON)
PVZ_DISABLE_DYLIB_MOCK_AUDIT=1 ./build/runner pvz/main.exe

# no-op 의심 dylib mock 거부 비활성화 (기본 거부 ON)
PVZ_REJECT_NOOP_DYLIB_MOCKS=0 ./build/runner pvz/main.exe

# 런타임 no-op 의심 dylib mock도 거부 (기본은 경고만)
PVZ_REJECT_RUNTIME_NOOP_DYLIB_MOCKS=1 ./build/runner pvz/main.exe

# LLM 요청 예산 제한 (비용 상한, API mock은 기본 무제한)
PVZ_ENABLE_LLM=1 PVZ_MAX_JIT_REQUESTS=24 PVZ_MAX_API_REQUESTS=200 ./build/runner pvz/main.exe

# 예산 무제한
PVZ_ENABLE_LLM=1 PVZ_MAX_JIT_REQUESTS=-1 PVZ_MAX_API_REQUESTS=-1 ./build/runner pvz/main.exe

# API 호출 상위 통계 출력(루프 병목 추적)
PVZ_API_STATS_INTERVAL=50000 ./build/runner pvz/main.exe

# null-page 호환 매핑(특정 null 근처 역참조 우회)
PVZ_MAP_NULL_PAGE=1 ./build/runner pvz/main.exe

# 블록 프로파일링 강제 ON/OFF (기본: LLM ON일 때만 ON)
PVZ_PROFILE_BLOCKS=1 ./build/runner pvz/main.exe
PVZ_PROFILE_BLOCKS=0 ./build/runner pvz/main.exe

# 블록 프로파일링 메타데이터 상한 (기본 250000)
PVZ_MAX_PROFILE_BLOCKS=300000 ./build/runner pvz/main.exe

# VRAM 쓰기 기반 강제 프리젠트 훅(기본 ON) 비활성화
PVZ_DISABLE_VRAM_PRESENT_HOOK=1 ./build/runner pvz/main.exe

# VRAM 프리젠트 훅 stride 조정(기본 20000 write마다)
PVZ_VRAM_PRESENT_STRIDE=8000 ./build/runner pvz/main.exe

# MessageBoxA/W의 SDL 팝업 표시 비활성화
PVZ_DISABLE_SDL_MESSAGEBOX=1 ./build/runner pvz/main.exe

# MessageBoxA/W를 팝업 없이 자동 IDOK 처리(기본: 항상 ON)
PVZ_AUTO_ACK_MESSAGEBOX=1 ./build/runner pvz/main.exe

# MessageBoxA/W를 실제 SDL 팝업으로 강제(자동 승인 비활성화)
PVZ_INTERACTIVE_MESSAGEBOX=1 ./build/runner pvz/main.exe

# VRAM present 시점 프레임 덤프(PPM) 저장
PVZ_VRAM_SNAPSHOT=1 PVZ_VRAM_SNAPSHOT_EVERY=1 PVZ_VRAM_SNAPSHOT_PREFIX=artifacts/vram_frame ./build-fex/runner pvz/main.exe

# D3D8 생성을 강제로 실패시켜 DirectDraw fallback 경로 유도(렌더 경로 분기 진단용)
PVZ_FORCE_DDRAW_FALLBACK=1 ./build-fex/runner pvz/main.exe

# D3D7 CreateDevice도 실패시켜 software/DDraw Lock-Unlock 경로 강제 유도(진단용)
PVZ_FORCE_DDRAW_FALLBACK=1 PVZ_FORCE_SOFTWARE_DDRAW=1 ./build-fex/runner pvz/main.exe

# 테스트용 가짜 좌클릭 1회 주입(메시지 큐): 딜레이/좌표 커스텀 가능
PVZ_SYNTH_CLICK=1 PVZ_SYNTH_CLICK_DELAY_MS=4000 PVZ_SYNTH_CLICK_X=400 PVZ_SYNTH_CLICK_Y=300 ./build-fex/runner pvz/main.exe

# API 훅 디버그 로그 출력 활성화 (기본 OFF)
PVZ_VERBOSE_API_HOOK=1 ./build/runner pvz/main.exe

# (실험) Unicorn TB 캐시 주기적 flush (기본 OFF)
PVZ_TB_FLUSH_INTERVAL_BLOCKS=20000 ./build/runner pvz/main.exe

# resources.xml 이후 API caller EIP hot-page 샘플링
PVZ_EIP_HOT_SAMPLE=1 PVZ_EIP_HOT_SAMPLE_INTERVAL=50000 ./build/runner pvz/main.exe

# EIP hot-page 샘플 map cap (기본 4096)
PVZ_EIP_HOT_PAGE_CAP=8192 ./build/runner pvz/main.exe

# EIP hot-address 샘플 map cap (기본 16384)
PVZ_EIP_HOT_ADDR_CAP=20000 ./build/runner pvz/main.exe

# hot-range(기본: 0x62ce9b/0x62cf8e/0x62118b/0x61fcd4) API 반환 통계
PVZ_HOT_LOOP_API_TRACE=1 PVZ_HOT_LOOP_API_TRACE_INTERVAL=50000 ./build/runner pvz/main.exe

# hot-range 중심/반경 커스텀 (쉼표 구분, 10진/16진 허용)
PVZ_HOT_FOCUS_ADDRS=0x62ce9b,0x62cf8e,0x62118b,0x61fcd4 PVZ_HOT_FOCUS_RANGE=0x20 ./build/runner pvz/main.exe

# 블록 핫샘플(전체) + 포커스 주소 레지스터/메모리 샘플
PVZ_BLOCK_HOT_SAMPLE=1 PVZ_BLOCK_HOT_SAMPLE_INTERVAL=200000 ./build-fex/runner pvz/main.exe
PVZ_BLOCK_FOCUS_TRACE=1 PVZ_BLOCK_FOCUS_ADDRS=0x441a73,0x441a79,0x441dd0,0x5d8890,0x62456a PVZ_BLOCK_FOCUS_INTERVAL=50000 PVZ_BLOCK_FOCUS_DUMP_BYTES=16 ./build-fex/runner pvz/main.exe

# 리소스 단계 hot-loop 가속(선택): 0x441a73/0x5d888c/0x5d8890/0x62456a/0x404470/0x61e4e6/0x441d20 루프를 호스트 빠른 경로로 처리
PVZ_HOT_LOOP_ACCEL=1 ./build-fex/runner pvz/main.exe

# CRT alloc/free 핫경로 가속(기본: `PVZ_HOT_LOOP_ACCEL=1`일 때 자동 ON, 명시값이 우선)
PVZ_CRT_ALLOC_ACCEL=1 ./build-fex/runner pvz/main.exe

# CRT alloc fast arena 크기(MB, 기본 128)
PVZ_CRT_ALLOC_ACCEL=1 PVZ_CRT_ALLOC_ARENA_MB=256 ./build-fex/runner pvz/main.exe

# WndProc 브릿지 상세 추적(RegisterClass/CreateWindowEx/Dispatch/SendMessage)
PVZ_WNDPROC_TRACE=1 ./build-fex/runner pvz/main.exe

# Loader 경로 상세 추적(LoadLibrary/GetModuleHandle/GetProcAddress 핸들 매핑 확인)
PVZ_LOADER_TRACE=1 ./build-fex/runner pvz/main.exe

# thread/event/postmessage 모킹 상세 추적 로그
PVZ_THREAD_MOCK_TRACE=1 ./build/runner pvz/main.exe

# 메시지 큐 enqueue/dequeue/drop 통계 주기 출력
PVZ_MSG_QUEUE_STATS_INTERVAL=20000 ./build-fex/runner pvz/main.exe

# 메시지 큐 tail 중복 dedup 시작 크기(기본 1024, 0이면 비활성)
PVZ_MSG_DEDUP_START=512 ./build-fex/runner pvz/main.exe

# 메시지 dedup 강제 비활성화
PVZ_DISABLE_MSG_DEDUP=1 ./build-fex/runner pvz/main.exe

# cooperative guest thread scheduler 활성화 (CreateThread worker를 실제 guest 코드로 timeslice 실행)
# 참고: PVZ_COOP_TIMESLICE 기본값은 120000 (미지정 시 자동 적용)
PVZ_COOP_THREADS=1 PVZ_COOP_TIMESLICE=20000 ./build-fex/runner pvz/main.exe

# CRT lock wrapper 가속 토글(기본 ON, 문제 시 0으로 비활성화)
PVZ_LOCK_WRAPPER_ACCEL=0 ./build-fex/runner pvz/main.exe

# cooperative scheduler 상세 trace
PVZ_COOP_THREADS=1 PVZ_COOP_TRACE=1 ./build-fex/runner pvz/main.exe

# cooperative thread 기본 스택 크기(bytes, 기본 0x200000)
PVZ_COOP_THREADS=1 PVZ_COOP_STACK_SIZE=2097152 ./build-fex/runner pvz/main.exe

# cooperative scheduler 동시 live thread 상한(기본 256)
PVZ_COOP_THREADS=1 PVZ_COOP_MAX_LIVE_THREADS=192 ./build-fex/runner pvz/main.exe

# cooperative spawn 실패 시 CreateThread 실패 반환 여부(기본 ON)
PVZ_COOP_THREADS=1 PVZ_COOP_FAIL_CREATE_THREAD_ON_SPAWN_FAILURE=1 ./build-fex/runner pvz/main.exe

# thread handle map 상한(기본 8192, 초과 시 finished handle reaping 후 실패)
PVZ_THREAD_HANDLE_CAP=8192 ./build-fex/runner pvz/main.exe

# fast-worker(short-circuit) 진단 시 CreateThread 총량 상한(기본: fast-worker ON일 때 512)
PVZ_FAST_WORKER_THREAD=1 PVZ_WORKER_THREAD_CREATE_CAP=240 ./build-fex/runner pvz/main.exe

# 장기 실행 메모리 가드 (fexcore 기본 12288MB, 0이면 비활성화)
PVZ_MAX_RSS_MB=8192 PVZ_RSS_GUARD_INTERVAL_BLOCKS=20000 ./build/runner pvz/main.exe

# Heap free-list 메타데이터 상한 (0이면 무제한)
PVZ_HEAP_FREE_CAP_ENTRIES=131072 ./build-fex/runner pvz/main.exe

# 특정 watchpoint 로그 활성화 (기본 OFF)
PVZ_WATCHPOINT=1 ./build/runner pvz/main.exe

# (디버그) CreateThread를 실패로 강제
PVZ_CREATE_THREAD_FAIL=1 ./build/runner pvz/main.exe

# 권장 디버그 조합 (헤드리스 + 네이티브JIT off + dylib mock off)
PVZ_HEADLESS=1 PVZ_DISABLE_NATIVE_JIT=1 PVZ_DISABLE_DYLIB_MOCKS=1 ./build/runner pvz/main.exe
```

---

## 🛑 현재 구동 가능 한계 (Current Status)

**질문:** "지금 바로 게임(pvz.exe) 화면이 뜨고 플레이가 가능한가요?"

**답변:** **아닙니다. 현재는 게임의 초기 C 런타임/환경 설정 코드가 엔진에서 실행 및 네이티브 변환을 거쳐 구동되고 있는 단계입니다.**

엔진 인프라 자체(PE 로더, JIT 디스패처, W^X 우회, M1 ARM64 컨텍스트 스위칭, 동적 DLL API 자동 생성)는 완벽히 구축되었습니다. 
하지만 PvZ와 같은 복잡한 상용 게임이 렌더링 화면을 띄우려면, 단순한 레지스터(상태)를 모킹하는 것을 넘어서 **OS의 본질적인 입출력 장치와 연결되는 하위 시스템의 뒷단 코딩(Backend Porting)**이 필요합니다.

### 💡 DLL 로딩 및 메시지(입력) 루프의 모킹 한계

1. **동적 DLL 로딩 (`LoadLibrary`, `GetProcAddress`)**:
   - **이 부분은 모킹이 매우 잘 됩니다!** 게임이 동적으로 DLL을 부르면 LLM이 가짜 핸들(Handle)을 반환하는 코드를 짜줍니다. 이후 `GetProcAddress`를 부르면 엔진 내부의 가짜 API 공간(`FAKE_API_BASE`) 주소를 반환하여, 호출될 때 다시 LLM이 그 API를 모킹하도록 하는 **재귀적인 완벽한 우회가 가능**합니다.
   
2. **이벤트/입력 루프 (`GetMessage`, `PeekMessage` 등)**:
   - **이 부분은 순수 LLM만으로는 한계가 명확합니다.** LLM이 `GetMessage` API를 단순히 "성공(1)"으로 반환하고 마우스가 움직였다는 더미 데이터(Dummy)를 구조체에 채워 넣도록 코드를 짤 수는 있습니다. 에뮬레이터는 안 터지겠지만, 사용자가 실제로 Mac에서 마우스를 움직이는 입력값은 게임에 들어가지 않습니다.
   - 실제 입력을 받으려면 모킹을 넘어 C++ 엔진 내부에서 macOS의 `Cocoa`나 `SDL2` 라이브러리를 통해 화면 창을 열고, 실제 Mac의 키보드 이벤트를 윈도우의 `MSG` 구조체로 변환해주는 **하드코딩된 브릿지 백엔드**가 구현되어야 합니다.

3. **그래픽 렌더링 (`DirectDraw` / `DirectX`)**:
   - LLM이 그래픽 호출에 대해 `S_OK`(성공)를 반환하도록 모킹하여 게임 코드가 넘어갈 수는 있지만, 실제로 Mac 화면에 식물을 그리려면 엔진 단에서 Metal이나 OpenGL로 번역해서 쏴주는 에뮬레이션 레이어(마치 Wine이나 CrossOver처럼)가 물리적으로 필요합니다.

즉, **자동차의 엔진과 번역기 AI는 세계 최고 수준으로 완성되었으나, 화면을 보여주는 '디스플레이 모니터'와 실제 핸들(키보드/마우스 훅) 부품이 아직 에뮬레이터에 장착되지 않은 상태**라고 보시면 됩니다. 

기본 실행은 내장 HLE 중심의 저비용 모드이며, `PVZ_ENABLE_LLM=1`을 켜면 기존의 실시간 LLM 보조 JIT/API 생성 파이프라인을 다시 사용할 수 있습니다.

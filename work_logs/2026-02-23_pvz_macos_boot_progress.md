# 2026-02-23 PvZ macOS 부팅 진행 일지

## 목표
- Plants vs. Zombies(Win32) 부팅 경로를 macOS 에뮬레이터에서 더 깊게 진행.
- 즉시 크래시(`RaiseException`/`ResourceManagerException`) 구간을 우회하고 리소스 로드 단계 안정화.

## 오늘 수행한 작업
1. `pvz/properties/resources.xml` 교체
- 기존 임시 최소 XML(78 bytes)을 원본 형태(58,937 bytes)로 교체.
- 결과: `ResourceManagerException` 트리거 구간이 뒤로 밀리거나 사라짐.

2. 파일 경로 해석기 강화 (`api_handler.cpp`)
- `resolve_guest_path_to_host` 개선:
  - Windows 드라이브 경로(`C:\...`) 정규화.
  - 대소문자 무시(case-insensitive) 경로 탐색 추가.
  - 이미지 확장자 대체 탐색 추가 (`.tga/.png/.jpg` 상호 변환).
  - basename 선행 `_` 변형 탐색 추가 (`_blank` -> `blank`).
- 목적: Windows 기준 느슨한 파일명/확장자 차이를 macOS 파일시스템에서 흡수.

3. 최소 리소스 보강
- `pvz/images/blank.tga` (1x1 더미 TGA) 생성.
- `pvz/images/blank.jpg` (1x1 JPEG) 생성.

4. 파일 매핑 HLE 고도화 (`api_handler.cpp`)
- `CreateFileMappingA`, `OpenFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile`를 단순 더미 포인터 방식에서 실제 파일 핸들 기반 매핑으로 변경.
- 매핑 핸들(`mapping_*`) 수명 관리 추가 (`CloseHandle`에서 정리).
- `MapViewOfFile`는 파일 맵이면 실제 바이트를 Unicorn 메모리로 복사, 익명 맵이면 zero-filled 페이지 반환.
- 효과: 기존 `MapViewOfFile invalid mapping handle 0x1`로 인한 `UC_ERR_READ_UNMAPPED` 크래시 해소.

5. 추가 안정화
- `CreateFileA("C:\\Windows\\System32\\")` 요청을 가상 핸들로 흡수하도록 예외 케이스 추가.
- 결과: 20초 샘플 런 기준 `NOT FOUND` 로그가 관측되지 않음.

6. 상대경로 기준점 수정 (exe 디렉토리 우선)
- `main.cpp`에서 실행 대상(`argv[1]`)의 절대 경로 부모를 계산해 `Process base dir`로 주입.
- `api_handler.cpp`의 `CreateFileA` 경로 해석이 해당 베이스 디렉토리(예: `<repo>/pvz`)를 우선으로 사용하도록 변경.
- 검증 로그: `[*] Process base dir: /Users/yanghyeonseo/Developer/pvz/pvz`

## 재현/검증 결과
- 이전 상태:
  - `CreateFileA('images/blank.tga') -> NOT FOUND`
  - 이후 `TerminateProcess(current, exit_code=0xC000000D)`로 조기 종료.
- 개선 후:
  - `CreateFileA('images/blank.tga')` 성공.
  - `CreateFileA('images/blank.jpg')` 성공.
  - `CreateFileA('images/_blank.tga')`도 경로 변형 규칙으로 대응 가능하도록 로직 추가.
  - 미지 API(`known=0`)는 새로 발생하지 않음.
  - 강제 종료 전까지 런너가 장시간 실행(즉시 비정상 종료/예외 중단 없음).
  - 60초 샘플 런에서도 프로세스 생존(`RUNNING_AFTER_60S`), 크래시/자체 종료 없음.
  - 로그 진행량이 크게 증가(약 96만 라인), 미해결 파일 누락은 `C:\\Windows\\System32\\` 단일 케이스만 관찰.

## 현재 상태 요약
- 부팅 안정성은 확실히 향상됨.
- 치명적 즉시 종료 루프에서 벗어남.
- 아직 실제 게임 화면 진입은 미확인(프로세스 장시간 실행 상태).

## 다음 액션
1. 실행 중 누락 파일 자동 수집
- `boot_trace.txt`에서 `NOT FOUND` 패턴 추출 후, 우선순위 파일(이미지/폰트/사운드) 순차 보강.

2. 로더 관찰성 개선
- `CreateFileA/ReadFile/GetFileSize`에 요청 경로별 통계 로깅(중복 집계) 추가.
- 어떤 리소스가 병목인지 빠르게 식별.

3. 화면 진입 검증
- SDL 렌더러 이벤트 루프와 첫 프레임(텍스처 업데이트) 시점에 명시 로그 추가.
- “실행 유지”가 아닌 “렌더링 시작” 기준으로 단계 게이팅.

## 추가 업데이트 (2026-02-23 밤)
1. CPU 백엔드 교체 준비 작업 착수
- Unicorn 헤더 include를 `cpu_backend_compat.hpp`로 집중.
- CMake 옵션 `PVZ_CPU_BACKEND`(기본값 `unicorn`) 추가.
- 현재 `fexcore` 선택은 아직 미구현으로 빌드 타임 차단(안전장치).

2. libfexcore 전환 전략 문서 작성
- 문서: `work_logs/2026-02-23_libfexcore_migration_strategy.md`
- 내용: 단계별 마이그레이션(Phase 0~4), 리스크, 성공 지표, 즉시 실행 항목.

3. Phase 2 선행 착수 (main 실행루프 래핑)
- 파일 추가:
  - `backend/cpu_backend.hpp`
  - `backend/unicorn_backend.hpp`
  - `backend/unicorn_backend.cpp`
- `main.cpp`를 `CpuBackend` 인터페이스 타입 기반으로 실행:
  - `CpuBackend& backend = unicorn_backend`
- `main.cpp`의 Unicorn 직접 호출 일부를 백엔드 호출로 교체:
  - 엔진 open/close
  - emu_start
  - reg read
  - mem map/read
  - hook_add
- 검증:
  - `cmake --build build -j4` 성공
  - 5초 스모크 런에서 기존과 동일하게 부팅 로그 진행 확인

4. Phase 0 지표 샘플(단독 런, 60초 관찰)
- 로그: `/tmp/pvz_run_60s_backend.log`
- 지표:
  - `known=0`: 0
  - `NOT FOUND`: 0
  - `API CALL`: 24
  - `UC_ERR`: 1 (`UC_ERR_FETCH_UNMAPPED`)
- 정지 지점:
  - `EIP = 0x1`
  - 직전 호출 흐름: `TlsSetValue` 이후 fetch unmapped 발생

5. Phase 2 추가 이관 (main 외곽 모듈)
- `windows_env`를 `CpuBackend` 참조 기반으로 변경:
  - `windows_env.hpp/.cpp`에서 `uc_engine*` 직접 의존 제거
  - `mem_map/mem_write/reg_read/reg_write`를 백엔드 호출로 전환
- `pe_loader`를 `CpuBackend` 기반으로 변경:
  - `map_into`, `resolve_imports` 시그니처/구현을 backend 경유로 전환
- `main.cpp` 연결 변경:
  - `WindowsEnvironment env(backend);`
  - `pe_module.map_into(backend);`
  - `pe_module.resolve_imports(backend, api_handler);`
- 검증:
  - `cmake --build build -j4` 성공

6. 검증 환경 제약 메모
- 현재 세션에서 SDL 디스플레이 접근 제약으로 GUI 런타임 검증이 불안정함:
  - 예: `SDL2 Initialization failed: The video driver did not add any displays`
  - 예: `SDL Window creation failed: Could not initialize OpenGL / GLES library`
- 따라서 이번 턴의 런타임 검증은 "컴파일 성공 + 코드 경로 이관" 중심으로 기록.

7. 헤드리스/디버그 실행 옵션 추가
- `main.cpp`에 환경변수 기반 실행 제어 추가:
  - `PVZ_HEADLESS=1`: SDL 이벤트 전용 초기화(창/렌더러 미생성)
  - `PVZ_DISABLE_NATIVE_JIT=1`: ARM64 네이티브 JIT 디스패처 비활성화
  - `PVZ_BOOT_TRACE=1`: 부팅 체크포인트 로그 출력
- 목적:
  - 디스플레이가 없는 환경에서도 코어 부팅 경로를 관찰 가능하게 하기 위함.

8. 헤드리스 부팅 추적 결과 (현재 샌드박스)
- 커맨드:
  - `PVZ_HEADLESS=1 PVZ_DISABLE_NATIVE_JIT=1 PVZ_BOOT_TRACE=1 stdbuf -oL -eL ./build/runner pvz/main.exe`
- 관찰:
  - `[TRACE] after backend.open_x86_32` 까지 통과
  - `[TRACE] before guest_vram map` 직후 `EXIT:132(SIGILL)`
- 해석:
  - 현 샌드박스에서는 `uc_mem_map` 시점에서 프로세스가 SIGILL로 중단되는 제약이 존재.
  - 동일 코드의 기능 검증은 로컬 GUI 세션/비제약 환경에서 재확인 필요.

9. 로더 API 안정화(내장 HLE 우선)
- `api_handler.cpp::try_load_dylib`에 코어 로더 API 예외 추가:
  - `GetProcAddress`, `LoadLibraryA/W`, `GetModuleHandleA/W`
- 의도:
  - 해당 API는 호출 규약/핸들 정책의 일관성이 중요하므로, LLM 플러그인 대신 내장 HLE 경로를 우선 사용.
- 상태:
  - 컴파일 성공 (`cmake --build build -j4`)
  - 후속 헤드리스 재검증에서 해당 정책이 반영되어 `GetProcAddress`/`Tls*`가 내장 HLE 경로로 처리됨.

10. API 레이어 백엔드 이관 완료
- `api_context.hpp`
  - `CpuBackend* backend` 추가
  - `get_arg/set_eax/pop_args`가 `uc_*` 직접 호출 대신 backend API 사용
  - `uc_engine* uc`는 기존 `api_mocks/*.dylib` 호환을 위해 보존
- `api_handler.hpp/.cpp`
  - 생성자 시그니처 변경: `DummyAPIHandler(CpuBackend&)`
  - 내부 메모리/레지스터/훅/emu 제어를 backend 경유로 전환
  - non-backend 직접 `uc_*` 호출 제거 (코어 코드 기준)

11. 동적 mock 안정화 옵션/정책
- 새 옵션:
  - `PVZ_DISABLE_DYLIB_MOCKS=1`
- 정책 보강:
  - 코어 API(`GetProcAddress`, `LoadLibrary*`, `GetModuleHandle*`)
  - TLS/FLS(`Tls*`, `Fls*`)
  - 원자 연산(`Interlocked*`)
  - 위 함수들은 내장 HLE 우선 처리

12. 최신 헤드리스 검증 결과
- 명령:
  - `PVZ_HEADLESS=1 PVZ_DISABLE_NATIVE_JIT=1 PVZ_DISABLE_DYLIB_MOCKS=1 ./build/runner pvz/main.exe`
- 결과:
  - 세그폴트(139) 제거
  - 진행 후 중단 지점: `UC_ERR_WRITE_UNMAPPED`
  - `EIP=0x61df1c` (`/tmp/pvz_iface_exit3.log` 기준)

13. `UC_ERR_WRITE_UNMAPPED(EIP=0x61df1c)` 원인/조치
- 디스어셈블 기준 실패 명령:
  - `0x61df1c: mov dword ptr [edi], eax`
  - 크래시 당시 `EDI=0x1` (잘못된 포인터)
- 원인:
  - `HeapReAlloc`/`HeapSize` 미구현으로 기본 성공값(1) 반환 -> 포인터 오염
- 조치:
  - `KERNEL32.dll!HeapSize` 구현: `heap_size_<ptr>` 조회, 실패 시 `(SIZE_T)-1`
  - `KERNEL32.dll!HeapReAlloc` 구현: shrink in-place / grow allocate+copy / NULL 입력 처리
- 결과:
  - 해당 크래시 사라지고 프로세스 장시간 생존 확인 (`/tmp/pvz_iface_exit4.log`, 약 90만 라인)

14. `api_mocks` 인터페이스 의존화
- `api_mocks/*.cpp` 내 `uc_*` 직접 호출을 `ctx->backend->...` 호출로 일괄 치환
- 잔여 `ctx->uc` 참조(2건)도 helper 함수 backend 경유로 변경:
  - `api_mocks/GetProcAddress.cpp`
  - `api_mocks/LoadCursorA.cpp`
- 샘플 플러그인 컴파일 확인:
  - `GetProcAddress.cpp`, `LoadCursorA.cpp`, `TlsAlloc.cpp` (`-DPVZ_CPU_BACKEND_UNICORN=1`)

15. 고빈도 API 로그 노이즈 억제
- `Enter/LeaveCriticalSection`, `Interlocked*` 계열 디버그 출력 억제
- 효과:
  - 동일 8초 런에서 critical-section 로그 0건
  - 여전히 `HeapAlloc/HeapFree` 핫루프 로그는 많음(후속 억제 후보)

16. 로그 폭주 추가 정리 + 관측 모드 개선
- `HeapAlloc/HeapFree/HeapSize/HeapReAlloc`, `Tls/Fls`, `GetLastError/SetLastError`를 noisy API 목록으로 묶어 디버그 출력 억제.
- `Heap*` 개별 성공 로그 제거(핫루프에서 로그 병목 방지).
- watchpoint 출력 기본 OFF로 변경, `PVZ_WATCHPOINT=1`일 때만 활성화.

17. 최신 안정성 지표 (헤드리스, no-native-jit, no-dylib-mocks)
- 명령:
  - `PVZ_HEADLESS=1 PVZ_DISABLE_NATIVE_JIT=1 PVZ_DISABLE_DYLIB_MOCKS=1 ./build/runner pvz/main.exe`
- 8초 샘플:
  - 라인 수: 약 3,318 (이전 15만+에서 감소)
  - `watch_hits`: 0
  - `Heap*` 로그: 0
- 30초 샘플:
  - `RUNNING_AFTER_30S`
  - `known=0`: 0
  - `unknown API`: 0
  - `UC_ERR`: 0

18. LLM 비용 절감 모드 고도화 (기본 OFF + 요청 예산)
- 목적:
  - LLM 대기 시간/비용을 기본 실행 경로에서 제거하고, 필요할 때만 명시적으로 활성화.
- 코드 변경:
  - `main.cpp`
    - `PVZ_ENABLE_LLM` 기본 OFF 유지.
    - `PVZ_MAX_JIT_REQUESTS` 도입(기본 `24`, `-1`이면 무제한).
    - 예산 소진 시 추가 `jit_requests/*.json` 생성 중단.
  - `api_handler.cpp/.hpp`
    - `PVZ_MAX_API_REQUESTS` 도입(기본 `24`, `-1`이면 무제한).
    - 미지 API LLM 요청 예산 소진 시 generic fallback(`EAX=1`, `LastError=0`)으로 자동 전환.
    - 시작 로그에 LLM/dylib/API budget 상태 출력.
  - 환경변수 파서 정리:
    - `0/false/off/no`를 false로 해석.
- 검증:
  - 빌드: `cmake --build build -j8` 성공.
  - 8초 런 (LLM OFF):
    - 명령: `PVZ_HEADLESS=1 PVZ_DISABLE_NATIVE_JIT=1 ./build/runner pvz/main.exe`
    - 로그: `[*] LLM pipeline disabled...`, `[*] API LLM mode: OFF, dylib mocks: OFF`
    - 신규 파일: `new jit_requests=0`, `new api_requests=0`
    - `[JIT MOCK]` 출력: 0건
  - 8초 런 (LLM ON + dylib ON):
    - 명령: `PVZ_HEADLESS=1 PVZ_DISABLE_NATIVE_JIT=1 PVZ_ENABLE_LLM=1 PVZ_ENABLE_DYLIB_MOCKS=1 ./build/runner pvz/main.exe`
    - 로그: `API LLM mode: ON, dylib mocks: ON`
    - 기존 mock 플러그인 경로는 정상 동작(`[JIT MOCK]` 관측)

19. `PVZ_CPU_BACKEND=fexcore` 실제 런타임 경로 추가
- 구현:
  - `backend/fexcore_backend.hpp/.cpp` 추가.
  - `FexCoreBackend`는 우선 `libpvz_fexcore_bridge.dylib`(또는 `PVZ_FEXCORE_BRIDGE_PATH`)를 동적 로딩해 실행 엔진을 연결.
  - 브리지 미존재/실패 시 Unicorn으로 자동 fallback 하도록 설계(런타임 중단 방지).
- 빌드 시스템:
  - `CMakeLists.txt`에서 `PVZ_CPU_BACKEND=unicorn|fexcore` 둘 다 허용.
  - `PVZ_CPU_BACKEND=fexcore` 빌드 시 `PVZ_CPU_BACKEND_FEXCORE` 정의.
- 실행 선택:
  - `main.cpp`에서 컴파일 타임 선택으로 `UnicornBackend`/`FexCoreBackend` 인스턴스 연결.
- 검증:
  - `cmake -S . -B build && cmake --build build -j8` 성공.
  - `cmake -S . -B build-fex -DPVZ_CPU_BACKEND=fexcore && cmake --build build-fex -j8` 성공.
  - `build-fex/runner` 6초 스모크:
    - `[*] CPU backend: fexcore`
    - `[*] FEX bridge unavailable. Falling back to Unicorn backend.`

20. API mock 재생성/재컴파일 파이프라인 정비 + 완전 검증
- `api_compiler.py` 재작성:
  - 최신 `APIContext` 규약 반영(`ctx->backend->reg_read/mem_read/reg_write` 사용 지침).
  - LLM 캐시 추가: `llm_cache/api_mocks/<api>.cpp`.
  - 기존 소스 우선 재사용(이미 생성된 `api_mocks/<api>.cpp`는 LLM 호출 생략).
  - 운영 모드 추가:
    - `--rebuild-all`: `api_mocks/*.cpp` 일괄 재컴파일
    - `--once`: 현재 요청만 처리 후 종료
    - `--no-llm`: 캐시/기존 소스만 사용
- 요청 처리:
  - 누락 API 6개(`Direct3DCreate8`, `GetActiveWindow`, `RegCreateKeyExA`, `mixerOpen`, `mixerSetControlDetails`, `timeGetTime`)를 LLM으로 생성 후 컴파일 완료.
  - 처리 후 `api_requests/*.json` 잔여 0개.
- 런타임 검증(12초):
  - 명령: `PVZ_HEADLESS=1 PVZ_DISABLE_NATIVE_JIT=1 PVZ_ENABLE_DYLIB_MOCKS=1 ./build/runner pvz/main.exe`
  - 결과:
    - `[JIT MOCK]` 522건 관측
    - 동적 mock 로딩 성공 로그 39건
    - mock 로드 실패/심볼 에러 0건
    - 모드 확인: `API LLM mode: OFF, dylib mocks: ON`
- 정책 반영:
  - API mocking은 제한하지 않도록 `PVZ_MAX_API_REQUESTS` 기본값을 `-1`(무제한)로 변경.

21. 파일/레지스트리 루프 추적 및 HLE 보강
- `PVZ_API_STATS_INTERVAL` 진단 모드 추가:
  - 일정 호출마다 상위 API 카운트를 출력해 병목을 추적.
  - 20초 샘플에서 주요 병목: `HeapAlloc/HeapFree`, `Enter/LeaveCriticalSection`.
- 파일/레지스트리 API 실동작화:
  - `GetCurrentDirectoryA`, `GetFullPathNameA`, `GetFileAttributesA`
  - `RegOpenKeyExA`, `RegCreateKeyExA`, `RegSetValueExA`, `RegQueryValueExA`, `RegDeleteValueA`, `RegCloseKey`
- 리소스 API 보강:
  - `FindResourceA`, `LoadResource`, `LockResource`, `SizeofResource`, `FreeResource`
  - placeholder resource handle/ptr/size 관리로 null dereference 유발 경로 완화.
- DirectDraw 안정화:
  - `DDRAW.dll!IDirectDraw7_Method_4` 시그니처/핸들러 보강.
  - `try_load_dylib`에서 `DirectDrawCreateEx/Create`, `Direct3DCreate8`는 내장 HLE 우선.

22. 렌더링 진입 근접 구간 검증 + null-page 호환 옵션
- 관찰:
  - DDRAW 경로가 `IDirectDraw7_Method_6(CreateSurface)`, `IDirectDrawSurface7_Method_0(QueryInterface)`, `IDirectDrawSurface7_Method_2`까지 반복 진입.
  - null 근처 역참조로 `UC_ERR_READ_UNMAPPED`가 발생하는 케이스 확인.
- 조치:
  - `main.cpp`에 `PVZ_MAP_NULL_PAGE=1` 옵션 추가(기본 OFF).
  - 활성화 시 0x00000000~0x0000FFFF를 호환 매핑.
- 검증:
  - 명령: `PVZ_HEADLESS=1 PVZ_DISABLE_NATIVE_JIT=1 PVZ_ENABLE_DYLIB_MOCKS=1 PVZ_MAP_NULL_PAGE=1 ./build/runner pvz/main.exe`
  - 결과: `UC_ERR` 없이 `Emulation cleanly finished at EIP = 0x0`.

23. `build-fex` 브리지 실체화 + full mode(fexcore 경로) 실행 검증
- 구현:
  - `bridge/pvz_fexcore_bridge.cpp` 추가.
  - `CMakeLists.txt`에 `pvz_fexcore_bridge` shared library 타깃 추가.
  - 출력물: `build-fex/libpvz_fexcore_bridge.dylib`.
  - 현재 브리지 구현체는 `unicorn-shim`이며, ABI는 `pvz_fex_*` 시그니처를 준수.
- `FexCoreBackend` 개선:
  - 브리지 탐색 경로 확장:
    - `PVZ_FEXCORE_BRIDGE_PATH`
    - 실행 파일 디렉토리의 `libpvz_fexcore_bridge.dylib`
    - 현재 작업 디렉토리의 `libpvz_fexcore_bridge.dylib`
  - 선택된 브리지 구현명을 로그로 출력:
    - `[*] FEX bridge backend implementation: ...`
  - `PVZ_FEXCORE_STRICT=1` 추가:
    - 브리지 구현명이 `fexcore`가 아니거나 브리지 로드 실패 시 fallback 없이 즉시 종료.
- 빌드/실행 검증:
  - 빌드:
    - `cmake -S . -B build-fex -DPVZ_CPU_BACKEND=fexcore`
    - `cmake --build build-fex -j8`
  - full mode 런(15초 샘플):
    - `DYLD_LIBRARY_PATH="/Users/yanghyeonseo/Developer/pvz:/usr/local/lib:/opt/homebrew/lib" PVZ_DISABLE_NATIVE_JIT=1 PVZ_ENABLE_DYLIB_MOCKS=1 PVZ_MAP_NULL_PAGE=1 ./build-fex/runner pvz/main.exe`
    - 로그 확인:
      - `[*] CPU backend: fexcore`
      - `[*] FEX bridge loaded: libpvz_fexcore_bridge.dylib`
      - `[*] FEX bridge backend implementation: unicorn-shim`
      - `[*] Starting C++ Engine Emulation...` 이후 API 흐름 정상 진행
  - strict 모드 검증:
    - `PVZ_FEXCORE_STRICT=1 ./build-fex/runner pvz/main.exe`
    - 기대대로 `backend is not 'fexcore'`로 종료(무의식 fallback 방지).

24. GUI 연동 안정화 라운드 (2026-02-24)
- 목표:
  - display 접근 허용 환경에서 full mode GUI 진입 경로를 더 안정적으로 밀기.
  - 동적 mock 편차를 줄이고 DDRAW/USER32 메시지 경로를 내장 HLE 중심으로 고정.
- 적용:
  - `api_handler.cpp`
    - `try_load_dylib` 정책 변경:
      - `KNOWN_SIGNATURES`에 있는 API는 dylib mock 대신 내장 HLE만 사용.
      - `DDRAW/DSOUND/D3D8` 및 `GetMessage/PeekMessage`는 dylib 우회.
    - 메시지 큐 추가:
      - `USER32!PostMessageA/W`, `SetTimer`, `KillTimer` 구현.
      - `GetMessage/PeekMessage`에서 내부 큐를 SDL 이벤트보다 우선 처리.
      - idle `GetMessage`에서 `WM_NULL` 반환(조기 `WM_QUIT` 방지).
    - 스레드/동기화 보강:
      - `CreateThread` 로그/파라미터 기반 cooperative 초기화 보강.
      - `WaitForSingleObject`를 event signaled 상태/timeout에 맞게 `WAIT_OBJECT_0` 또는 `WAIT_TIMEOUT(0x102)` 반환.
    - DDRAW/D3D HLE 보강:
      - `IDirectDraw7_Method_12/17/22/23/27` 핸들링 추가.
      - `IDirectDrawSurface7_Method_5/11/28/31/25/32` 시그니처/핸들링 보강.
      - `Surface7::Unlock`에서 SDL present 경로 연결.
    - COM 기본 반환 정책 보정:
      - DDRAW/DSOUND/D3D8 계열 generic fallback은 `HRESULT S_OK(0)` 기본.
  - `main.cpp`
    - VRAM write 기반 강제 present 훅 추가:
      - `UC_HOOK_MEM_WRITE`에서 guest VRAM 영역 write 감지 시 주기적으로 SDL texture 업데이트.
      - 옵션:
        - `PVZ_DISABLE_VRAM_PRESENT_HOOK=1`
        - `PVZ_VRAM_PRESENT_STRIDE=<N>`
- 관찰:
  - known API가 JIT mock으로 섞이던 현상은 제거됨(동작 경로 결정성이 높아짐).
  - `DirectSoundCreate` plugin 경유 `UC_ERR_READ_UNMAPPED` 크래시는 재현되지 않음.
  - 현재 120~140초 샘플 기준 병목:
    - `CreateThread -> WaitForSingleObject(event) -> PostMessage -> WaitForSingleObject(timeout)` 이후 구간에서 렌더링 API(`Surface7::Lock/Unlock`) 진입이 확인되지 않음.
    - 즉, GUI 프레젠트 루프까지는 아직 미도달.
- 다음 액션:
  1. `CreateThread` 실제 start routine 진행(또는 equivalent state transition) 보강.
  2. `IDirect3DDevice7_Method_*` 최소 동작(특히 Method_4 주변) 추가로 렌더 진입 유도.
  3. `SetTimer/PostMessage` 기반 내부 메시지 소비 루프(`Peek/GetMessage`) 진입 여부를 block trace와 결합해 추적.

25. MessageBox(SDL) 점검 + 메모리 사용량(100GB+) 완화 작업
- `MessageBoxA/W` 모킹 점검:
  - 기존: 콘솔 로그만 출력하고 즉시 `IDOK` 반환.
  - 변경: SDL `ShowSimpleMessageBox`를 실제 호출하도록 보강.
    - 구현 파일: `api_handler.cpp`
    - `MessageBoxW`도 추가 지원.
    - `PVZ_DISABLE_SDL_MESSAGEBOX=1`로 팝업 비활성화 가능.
- 메모리 사용량 완화(주요 후보 경로 대응):
  1. 블록 프로파일링 기본 정책 변경 (`main.cpp`)
     - 기존: 항상 `block_registry`에 기본블록 메타데이터(assembly/live-in/out) 축적.
     - 변경: 기본 OFF, `PVZ_ENABLE_LLM=1`일 때만 자동 ON.
     - 수동 제어: `PVZ_PROFILE_BLOCKS=0/1`
     - 상한 추가: `PVZ_MAX_PROFILE_BLOCKS` (기본 `250000`)
  2. 메시지 큐 무한 성장 방지 (`api_handler.cpp`)
     - `PostMessage/SetTimer` 내부 큐에 최대치(`4096`) 적용.
     - 초과 시 oldest drop.
  3. 대형 임시 버퍼 제거 (`api_handler.cpp`)
     - `MapViewOfFile` zero-fill/copy를 chunk(64KB) 기반으로 변경.
     - `HeapReAlloc` grow/copy도 chunk 기반으로 변경.
- 관측 샘플(40초, full mode):
  - `Block profiling: OFF`
  - `maximum resident set size: 1,277,952 KB` (약 1.22GB)
  - 동조건에서 `PVZ_PROFILE_BLOCKS=1`도 단기 샘플에서는 동일 RSS였으나, 장기 런에서는 `block_registry` 성장 억제 효과가 기대됨.

26. GUI 루프 병목 후속 추적 + 메모리(대용량 RSS) 추가 완화 시도 (2026-02-24)
- 병목 추적 런(Full mode, fexcore/unicorn-shim, `PVZ_DISABLE_NATIVE_JIT=1`) 결과:
  - `CreateThread -> WaitForSingleObject(event) -> PostMessage -> WaitForSingleObject(timeout)` 이후 구간은 계속 진행됨.
  - 이후 `main.pak`/`properties\\resources.xml` 파일 경로로 진입하고, DDRAW `CreateSurface/QueryInterface`까지는 확인됨.
  - 아직 `IDirectDrawSurface7::Lock/Unlock` 호출은 미확인(실렌더 루프는 미도달).
- 파일/메시지 경로 보강:
  - `MapViewOfFile/UnmapViewOfFile`에 free-list 재사용 추가(해제된 view 재활용).
  - `PostMessageA/W` 후 event handle을 signal 처리해 `WaitForSingleObject` 진행성 보강.
- 힙 재사용 정책 보정:
  - `HeapAlloc/HeapReAlloc` free-list 재사용 시 블록 분할(splitting) 적용.
  - 작은 alloc이 큰 free block 전체 크기를 상속하지 않도록 수정.
  - `HeapReAlloc` shrink 시 tail 블록을 free-list로 환원.
- 로그/디버그 비용 절감:
  - API 훅 디버그 출력은 `PVZ_VERBOSE_API_HOOK=1`일 때만 활성화(기본 OFF).
- 백엔드 인터페이스 확장:
  - `CpuBackend::flush_tb_cache()` 추가.
  - `UnicornBackend`, `FexCoreBackend`, `pvz_fexcore_bridge`에 TB flush 경로 구현.
  - `PVZ_TB_FLUSH_INTERVAL_BLOCKS` 실험 옵션 추가(기본 OFF).
- 메모리 관측:
  - 60초 샘플 RSS: 대략 4.2~4.7GB 범위.
  - `vmmap`(35초 시점) 기준 `DefaultMallocZone`의 `MALLOC_LARGE` 비중이 지배적(번역/런타임 내부 대형 할당 누적 추정).
  - `PVZ_TB_FLUSH_INTERVAL_BLOCKS=20000` 기본화 실험은 RSS 악화 경향이 있어 기본값 OFF로 유지.
- 결론/다음 액션:
  1. `resources.xml` 이후 루프에서 heap/chritical hot path 원인을 block-level로 좁히기(특정 EIP 범위 샘플링).
  2. `IDirectDrawSurface7::Lock/Unlock` 경로 강제 진입을 위해 `CreateSurface` 생성 객체/flags 반환값 정합성 추가 보강.
  3. (근본) `unicorn-shim` 대신 실제 libfexcore 엔진 브릿지 구현 우선순위 상향(메모리/성능 공통 해결 가능성).

27. 파일 열람 API 정합성 보강 (`FindFirstFileA/FindNextFileA/FindClose`)
- 배경:
  - `KNOWN_SIGNATURES`에 등록된 `FindFirstFileA/FindNextFileA/FindClose`가 실제 구현 없이 generic success 경로로 빠져 파일 탐색 결과가 왜곡될 수 있었음.
- 적용(`api_handler.cpp`):
  - Win32 find-handle 상태(`find_` handle) 추가.
  - `FindFirstFileA`:
    - guest 경로/패턴(`*`,`?`)을 host 디렉토리에 매칭.
    - 첫 엔트리를 `WIN32_FIND_DATAA`(320B) 구조로 채워 반환.
    - 미매치 시 `INVALID_HANDLE_VALUE`, `ERROR_FILE_NOT_FOUND(2)`.
  - `FindNextFileA`:
    - 다음 엔트리 순회 및 `ERROR_NO_MORE_FILES(18)` 처리.
  - `FindClose` + `CloseHandle` 경유 cleanup:
    - find handle 메모리 해제 및 `LastError` 정합성 유지.
- 효과:
  - 파일/리소스 열람 경로의 반환값 결정성 향상.
  - 향후 `resources/main.pak` 진입 이후 파일 루프 추적 시 false-positive(success-only) 가능성 감소.

28. `SetFilePointer` 64-bit 오프셋 처리 보강
- 문제:
  - 기존 구현은 `lpDistanceToMoveHigh`를 무시하고 low 32-bit만 사용.
  - 대형 파일/맵(`main.pak`) 경로에서 seek 동작 왜곡 가능성 존재.
- 변경(`api_handler.cpp`):
  - `lpDistanceToMoveHigh`가 제공되면 high/low를 결합한 64-bit distance로 이동.
  - 반환 시 low DWORD를 `EAX`로 반환하고, high DWORD를 `*lpDistanceToMoveHigh`에 기록.
  - `LastError`는 성공 시 0으로 유지.
- 효과:
  - 파일 seek 관련 Win32 정합성 개선(특히 큰 오프셋 처리).

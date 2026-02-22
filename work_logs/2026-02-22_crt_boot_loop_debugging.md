# 2026-02-22: CRT 부트 루프 디버깅 및 SDL2 Host 브릿지 구축

## 1. 작업 배경 및 목표

이전 세션(2026-02-21)에서 C++ 엔진 OOP 리팩토링 및 LLM 기반 API 모킹 파이프라인의 기본 틀 구현을 완료하였다.  
이번 세션의 목표는 다음 두 가지였다:

1. **게스트가 실제로 동작하는 창(Window)을 만들고 사용자 입력을 받을 수 있도록** macOS(Host)와의 브릿지를 구축한다.
2. **`boot_trace.txt`가 수 GB에 달하는 무한 루프 문제를 진단하고**, CRT(C Runtime) 초기화 중 발생하는 API 처리 오류를 수정한다.

---

## 2. SDL2 Host 브릿지 구축 (Phase 5 — user32 최소 집합)

### 2-1. 설계 결정

PvZ(Plants vs. Zombies)의 실행 흐름을 분석한 결과, 게임은 다음과 같은 순서로 Host OS의 자원을 요구한다:

```
CreateWindowExA → ShowWindow → GetMessage/PeekMessage 루프 진입
 → SDL_PollEvent로 macOS 이벤트 수신 → Win32 MSG 큐로 변환 → DispatchMessage → WndProc
```

이를 "LLM 모킹"에 맡기면 매번 번역이 바뀌고 이벤트 루프가 결정론적으로 작동하지 않는다.  
따라서 다음 API들은 **C++ 엔진에 직접 하드코딩(Intercept)** 하기로 결정하였다.

| 카테고리 | API 목록 |
|---|---|
| 창/클래스 | `RegisterClassExA/W`, `CreateWindowExA/W`, `DestroyWindow`, `DefWindowProcA/W`, `GetClientRect`, `AdjustWindowRect` |
| 메시지 루프 | `GetMessageA/W`, `PeekMessageA/W`, `TranslateMessage`, `DispatchMessageA/W`, `PostMessageA/W`, `SendMessageA/W` |
| 타이머/시간 | `SetTimer`, `KillTimer`, `GetTickCount`, `QueryPerformanceCounter/Frequency` |
| 포커스/커서 | `GetCursorPos`, `SetCursorPos`, `ShowCursor` |

SDL2를 백엔드로 선택한 이유: 크로스플랫폼 지원, `SDL_PollEvent` 기반 이벤트 루프, 텍스처 기반 프레임버퍼 표시 모두 지원.

### 2-2. Win32 MSG 구조체 가상 매핑

`api_handler.cpp`에 `Win32_MSG` 구조체를 정의하고, SDL 이벤트를 Win32 메시지 포맷으로 변환하는 테이블을 구현하였다:

```cpp
// api_handler.cpp
struct Win32_MSG {
    uint32_t hwnd;
    uint32_t message;  // WM_KEYDOWN(0x100), WM_LBUTTONDOWN(0x201), ...
    uint32_t wParam;
    uint32_t lParam;
    uint32_t time;
    int32_t  pt_x;
    int32_t  pt_y;
};
```

이 구조체를 Unicorn 가상 메모리의 고정 주소에 할당하고, 게스트가 `GetMessageA`를 호출하면 SDL에서 실제 이벤트를 받아 해당 메모리 주소에 기록 후 반환하도록 설계하였다.

### 2-3. Fake KERNEL32.dll PE 헤더 구축

게스트가 `GetProcAddress(hKernel32, "SomeFunc")` 형태로 내부 함수를 동적으로 조회하는 경우를 처리하기 위해, `api_handler.cpp` 생성자에서 `0x76000000` 주소에 **Fake KERNEL32.dll의 MZ/PE 헤더 및 Export Directory**를 직접 메모리에 기록하였다.

- Export Directory에 `GetProcAddress`, `LoadLibraryA`, `VirtualAlloc`의 이름 및 함수 주소 매핑
- 각 함수 주소는 `FAKE_API` 영역의 실제 핸들러 스텁을 가리키는 `JMP` 명령어(`0xE9 REL_OFFSET`)로 연결
- 이를 통해 게스트가 Kernel32 내부를 탐색해도 실제 에뮬레이터 핸들러로 리다이렉트됨

---

## 3. CRT 부트 루프 디버깅

### 3-1. 문제 발견: boot_trace.txt 2.3 GB 폭증

`./build/runner pvz/main.exe` 실행 후 로그를 파일로 리다이렉션(`> boot_trace.txt`)하였더니 파일 크기가 **2.3 GB**에 달하는 것을 확인하였다. 디스크 공간 부족까지 발생.

이는 CRT 초기화 단계에서 특정 구간이 무한 루프에 빠졌음을 의미한다.

### 3-2. 디버깅 도구 제작

직접 trace 파일을 파싱하거나 바이너리를 분석하기 위해 여러 Python 스크립트를 제작하였다:

- **`dump_addrs.py`**: 특정 가상 주소(`VA`)의 x86 코드를 `pefile` + `capstone`으로 디스어셈블하여 출력
- **`find_calls.py`**: 특정 함수로의 `CALL E8 XX XX XX XX` 지점을 PE 바이너리에서 역산하여 탐색
- **`parse_trace.py`**: `boot_trace.txt`에서 API 호출 패턴을 파싱하여 통계 출력
- **`head_trace.py`**: 대용량 trace 파일의 앞부분만 파싱하여 초기 호출 순서 분석

### 3-3. 루프 원인 분석

`dump_addrs.py`로 루프 의심 구간(`0x628810`, `0x6289c6` 등)의 코드를 분석한 결과, 문제는 **MSVC CRT의 전역 객체 초기화 루틴** (`__cinit`, `__initterm`)에서 발생하는 것으로 추정되었다.

핵심 원인:

1. **`InitializeCriticalSectionAndSpinCount`** 의 반환값 처리 오류  
   이 함수는 `BOOL`(성공 시 `TRUE` = `1`)을 반환해야 하나, 기존 스텁이 `0`을 반환하여 CRT 초기화 로직이 재시도 루프에 빠짐.

2. **`GetLocaleInfoA`** 처리 혼선  
   LLM이 생성한 `api_mocks/GetLocaleInfoA.cpp` 모크가 불완전하여, `api_requests/GetLocaleInfoA.json.processed` 상태가 되었음에도 에뮬레이터는 계속 대기 루프를 돌고 있었음.  
   수동으로 `.processed` 파일을 원본 `.json`으로 복구하고 모크를 재컴파일하여 해결.

3. **`GetProcAddress`** HLE(High-Level Emulation) 처리 누락  
   게스트가 `GetProcAddress(hKernel32, "EncodePointer")` 등을 호출할 때, 핸들러가 이 요청을 `api_requests/`로 내보내지 않고 스텁으로 처리하여 잘못된 함수 포인터가 반환됨.  
   `KNOWN_SIGNATURES` 테이블에 `GetProcAddress`, `EncodePointer`, `DecodePointer`를 직접 처리하는 HLE 로직을 추가함.

4. **`FlsAlloc` / `OpenFileMappingA`** 미등록 API  
   CRT 초기화에서 호출되는 이 두 API가 `KNOWN_SIGNATURES`에 없어 LLM 요청 큐로 빠졌고, 처리 대기 중 타임아웃이 발생하였음.  
   두 API를 `KNOWN_SIGNATURES`에 추가하고 간단한 HLE 스텁을 직접 구현함.

### 3-4. 수정 내역

#### `api_handler.cpp` 주요 변경사항

| API | 변경 내용 |
|---|---|
| `InitializeCriticalSectionAndSpinCount` | 반환값을 `1(TRUE)`로 수정, CRITICAL_SECTION 구조체를 가상 메모리에 초기화 |
| `InitializeCriticalSection` | 동일하게 구조체 초기화 스텁 추가 |
| `EnterCriticalSection` / `LeaveCriticalSection` | No-op 스텁으로 처리 (싱글 스레드 에뮬레이션 환경이므로 안전) |
| `TryEnterCriticalSection` | `TRUE(1)` 반환 스텁으로 처리 |
| `FlsAlloc` | 순차 FLS 인덱스를 할당하고 반환하는 내부 카운터 HLE 추가 |
| `FlsGetValue` / `FlsSetValue` | APIContext 공유 맵에 인덱스별 값을 저장/반환하는 HLE 추가 |
| `GetLocaleInfoA` | `api_requests/GetLocaleInfoA.json` 재발급 및 수동 모크 재컴파일 |
| `GetProcAddress` | 에뮬레이터 내부 `fake_api_map`을 역조회하여 실제 스텁 주소 반환하는 HLE 구현 |
| `EncodePointer` / `DecodePointer` | XOR 기반 포인터 인코딩/디코딩 패스스루 HLE 추가 |
| `TlsGetValue` / `TlsSetValue` | `APIContext`의 TLS 맵에 저장/반환 HLE 추가 |

#### `api_requests/GetLocaleInfoA.json` 재발급

```json
{
  "function_name": "GetLocaleInfoA",
  "dll": "KERNEL32.dll",
  "args": ["Locale(LCID)", "LCType(DWORD)", "lpLCData(LPSTR)", "cchData(int)"]
}
```

#### `api_requests/InitializeCriticalSectionAndSpinCount.json` 재발급

```json
{
  "function_name": "InitializeCriticalSectionAndSpinCount",
  "dll": "KERNEL32.dll",
  "args": ["lpCriticalSection(LPCRITICAL_SECTION)", "dwSpinCount(DWORD)"]
}
```

---

## 4. 동적 API 모킹 파이프라인 안정화

### 4-1. api_compiler.py 캐싱 검증

LLM 호출 비용 절감을 위해 구현된 `llm_cache/` SHA256 캐싱이 API 모킹에도 동일하게 적용됨을 확인:

1. `api_compiler.py`가 `api_requests/FUNC.json`을 발견
2. JSON 페이로드의 SHA256 해시를 계산
3. `llm_cache/HASH.cpp` 파일이 존재하면 LLM 호출 없이 캐시에서 복원
4. 없으면 `codex exec` CLI를 통해 LLM 호출 → C++ 코드 생성 → `api_mocks/FUNC.cpp` 저장
5. `clang++ -dynamiclib`으로 `api_mocks/FUNC.dylib` 컴파일
6. 에뮬레이터가 `dlopen()`으로 즉시 로드

### 4-2. Stateful API 처리 전략

`TlsGetValue`/`TlsSetValue`, `HeapAlloc`/`HeapFree`, `FlsAlloc`/`FlsGetValue` 등 **상태를 공유해야 하는 API**들은 `APIContext` 구조체를 통해 공유 메모리에 기록된다.

```cpp
// api_context.hpp (핵심 상태 공유 구조체)
struct APIContext {
    uc_engine* uc;
    std::unordered_map<uint32_t, uint32_t> tls_values;   // TLS 인덱스 → 값
    std::unordered_map<uint32_t, uint32_t> fls_values;   // FLS 인덱스 → 값
    std::unordered_map<uint32_t, size_t>   heap_sizes;   // 힙 포인터 → 크기
    uint32_t next_fls_index;
    // ... 기타 핸들 테이블
};
```

동적으로 로드된 `.dylib` 모크 함수가 `extern APIContext* ctx` 포인터를 통해 이 구조체에 접근함으로써, 여러 API 간의 일관된 상태를 유지한다.

---

## 5. 현재 진행 상황 (Phase 5 진척도)

| 항목 | 상태 |
|---|---|
| C++ 코어 엔진 (Unicorn + LIEF + Capstone) | ✅ 완료 |
| PE 로더 (섹션 매핑, IAT 패치) | ✅ 완료 |
| Windows 환경 (GDT, TEB, PEB, FS 세그먼트) | ✅ 완료 |
| Fake KERNEL32.dll PE 헤더 구축 | ✅ 완료 |
| 정적 KNOWN_SIGNATURES API 스텁 (~50개) | ✅ 완료 |
| LLM 기반 동적 API 모킹 파이프라인 | ✅ 완료 |
| JIT 핫스팟 프로파일러 (UC_HOOK_BLOCK) | ✅ 완료 |
| LLM ARM64 번역 + Keystone 어셈블 | ✅ 완료 |
| W^X 우회 + 인라인 어셈 컨텍스트 스위칭 | ✅ 완료 |
| SDL2 창 생성 및 Win32 MSG 루프 브릿지 | 🔄 진행 중 |
| CRT 부트 루프 디버깅 및 안정화 | 🔄 진행 중 |
| DirectDraw 2D 프레임버퍼 구현 | ⏳ 미착수 |
| 파일 입출력 VFS (CreateFileA, ReadFile) | ⏳ 미착수 |
| 오디오 브릿지 (winmm waveOut → SDL_Audio) | ⏳ 미착수 |

---

## 6. 현재 부트 진행 상황 (트레이스 분석)

`head_trace.py`를 통해 초기 100~200개 API 호출 순서를 파악한 결과, PvZ의 CRT 초기화 흐름은 다음과 같이 진행된다:

```
[CRT 진입]
GetSystemTimeAsFileTime
GetCurrentProcessId
GetCurrentThreadId
QueryPerformanceCounter
GetStartupInfoA
GetModuleHandleA       ← 핸들러 HLE 처리
TlsGetValue            ← 동적 모크 로드
InitializeCriticalSectionAndSpinCount  ← 수정됨
HeapCreate / HeapAlloc / HeapReAlloc   ← APIContext 기반 처리
EnumSystemLocalesA     ← LLM 모크 생성
GetLocaleInfoA         ← 수동 모크 재컴파일
FlsAlloc               ← HLE 추가
...
SetUnhandledExceptionFilter
IsDebuggerPresent
→ (이후 게임 초기화 코드 진입 기대)
```

아직 `GetModuleHandleA` 반환값 처리, `EncodePointer`/`DecodePointer` 쌍 처리 부분에서 간헐적으로 잘못된 주소 역참조가 발생하는 것이 확인되었다.

---

## 7. 다음 세션 할 일 (Next Steps)

### 즉시 해결 (Critical Bugs)

1. **`GetModuleHandleA` 반환값 검증**  
   `GetModuleHandleA(NULL)` 호출 시 현재 실행 중인 PE의 ImageBase(`0x400000`)를 반환해야 하나, 현재 Fake KERNEL32 주소(`0x76000000`)를 반환하는 버그가 존재함. `pe_loader.cpp`에서 실제 ImageBase를 `APIContext`에 저장하고 핸들러에 전달해야 함.

2. **`EncodePointer` / `DecodePointer` 일관성 보장**  
   두 함수가 서로 역함수 관계임을 보장해야 한다. 현재 패스스루(Pass-through)로 구현되어 있으나, MSVC CRT가 이 두 함수로 보호된 함수 포인터를 검증하는 경우 실패한다. 고정된 XOR 키를 `APIContext`에 저장하고 양방향으로 적용해야 함.

3. **CRT 루프 완전 탈출 확인**  
   수정 후 `./build/runner pvz/main.exe`를 3초간 실행 후 kill하여 `tail boot_trace.txt`로 진척도를 확인. 더 이상 같은 API가 반복되지 않아야 함.

### 이후 작업 (High Priority)

4. **SDL2 `GetMessageA`/`PeekMessageA` 실제 연동**  
   SDL_PollEvent를 호출하여 실제 키/마우스 이벤트를 Win32 MSG로 변환하는 로직을 `api_handler.cpp`에 직접 구현.

5. **DirectDraw 2D 최소 구현**  
   PvZ의 DirectDrawCreate → CreateSurface → Lock/Unlock → Blt 호출 체인을 처리.  
   Surface는 호스트 메모리 버퍼(`RGBA8888`)로 구현하고, `present()`는 `SDL_UpdateTexture` + `SDL_RenderCopy`로 macOS 창에 표시.

6. **가상 파일 시스템(VFS) 구축**  
   `CreateFileA("C:\\ProgramFiles\\PvZ\\main.pak")` 형태의 Windows 경로를 macOS 실제 경로로 매핑하는 VFS 레이어를 `api_handler.cpp`에 추가. `ReadFile`, `CloseHandle`(파일 핸들)도 함께 처리 필요.

---

## 8. 기술 메모

### macOS W^X (JIT 메모리) 처리

Apple Silicon에서 쓰기(W)와 실행(X) 권한이 동시에 적용된 메모리 페이지는 기본적으로 허용되지 않는다. 이를 우회하기 위해 다음 패턴을 사용:

```cpp
// MAP_JIT 플래그로 JIT 전용 메모리 할당
void* jit_mem = mmap(nullptr, size, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_JIT, -1, 0);
// 쓰기 전 보호 해제
pthread_jit_write_protect_np(0);
memcpy(jit_mem, arm64_code, code_size);
// 쓰기 완료 후 재보호
pthread_jit_write_protect_np(1);
sys_icache_invalidate(jit_mem, code_size); // I-cache 무효화
```

### Indirect Jump 처리 전략 (미구현)

`jmp eax`, `call ebx` 같은 레지스터 간접 점프는 현재 Unicorn이 전담 처리 중이다. 향후 JIT 네이티브 실행 시:

- LLM이 생성한 ARM64 코드 끝에 `x86 목표 주소`를 `w8` 레지스터에 담고 `ret` 하도록 강제
- C++ JIT Dispatcher가 `w8` 값을 `compiled_blocks` 캐시에서 조회
  - 있으면: 해당 ARM64 블록 함수 포인터로 직접 점프 (Block Chaining)
  - 없으면: Unicorn EIP를 업데이트하고 폴백 에뮬레이션 재개

### 동적 모킹 API 개발 흐름 (SOP)

```
에뮬레이터 실행 → 미지 API 호출 발생
 → api_requests/FUNCNAME.json 생성 (함수명, DLL, 인자 서명 포함)
 → api_compiler.py가 watchdog으로 파일 감지
 → codex exec로 LLM에게 C++ Mock 코드 요청
 → api_mocks/FUNCNAME.cpp 생성
 → clang++ -dynamiclib으로 api_mocks/FUNCNAME.dylib 컴파일
 → 에뮬레이터가 dlopen()/dlsym()으로 즉시 로드
 → 동일 API 재호출 시 네이티브 속도로 실행
```

---

*작성일: 2026-02-22*  
*관련 파일: `api_handler.cpp`, `api_handler.hpp`, `api_context.hpp`, `windows_env.cpp`, `pe_loader.cpp`, `llm_compiler.py`, `api_compiler.py`, `dump_addrs.py`*

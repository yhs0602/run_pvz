# x86-to-ARM64 하이브리드 JIT 에뮬레이터 (Phase 1~4 아키텍처 정리)

이 문서는 본 프로젝트에서 구축한 **"LLM 기반 x86-to-ARM64 JIT(Just-In-Time) 컴파일 파이프라인"** 의 전체적인 기술 아키텍처와 통합 과정을 상세히 기록한 한글 명세서입니다.

---

## 🚀 프로젝트 개요 (Overview)
본 프로젝트는 기존 x86 32-bit Windows PE(`main.exe` 등) 바이너리를 macOS Apple Silicon (ARM64) 환경에서 구동하기 위해 설계되었습니다.
단순한 인터프리터 방식(순수 에뮬레이션)의 한계를 극복하기 위해, **Unicorn Engine**을 베이스로 사용하되, 반복 실행되는 구간(Loop Hotspots)을 실시간으로 식별하여 **LLM(대형 언어 모델)을 통해 ARM64 네이티브 기계어로 번역하여 직접 실행**하는 세계 최초의 "LLM-Assisted Hybrid JIT" 파이프라인입니다.

---

## 🏛 1. C++ 코어 엔진 아키텍처 (Core Engine)
엔진의 핵심부는 C++로 작성되었으며, 객체지향(OOP) 형태로 구조화되었습니다.

- **`PEModule` (`pe_loader.cpp`)**: 
  - `LIEF::PE` 라이브러리를 사용하여 타겟 바이너리의 헤더를 파싱하고, 각 섹션(`.text`, `.data`, `.rdata` 등)을 Unicorn 가상 메모리에 정확한 주소(ImageBase)로 매핑합니다.
- **`WindowsEnvironment` (`windows_env.cpp`)**: 
  - x86 Windows 환경이 부팅되기 위해 필수적인 GDT(Global Descriptor Table), TEB(Thread Environment Block), PEB(Process Environment Block) 메모리를 가상으로 구성하고 `FS` 세그먼트 레지스터와 연결합니다. 이를 통해 Windows 내부 안티디버깅/SEH 우회 로직을 통과합니다.
- **`DummyAPIHandler` (`api_handler.cpp`)**: 
  - 바이너리가 `KERNEL32.dll` 등 존재하지 않는 외부 라이브러리 함수를 호출할 때 이를 가로채어, 실제 API가 호출된 것처럼 레지스터를 조작하고 `stdcall` 콜링 컨벤션에 맞춰 스택(`ret N`)을 안전하게 정리해 줍니다.

---

## 🔍 2. 핫스팟 프로파일러 & LLM 추출기 (JIT Profiler)
모든 x86 명령어를 번역하는 것은 비효율적이므로, C++ 에뮬레이터는 런타임에 "자주 실행되는 블록(핫스팟)"만을 골라냅니다.

1. **블록 후킹 (Block Hooking)**: Unicorn의 `UC_HOOK_BLOCK`을 활용하여 기본 블록(Basic Block) 진입 시마다 실행 횟수를 카운트합니다.
2. **LVA (Live-Variable Analysis)**: 
   - Capstone 디스어셈블러를 이용해 해당 블록 내에서 x86 레지스터가 어떻게 읽히고(`Live-In`), 어떻게 쓰이는지(`Live-Out`)를 상세하게 분석합니다.
3. **JSON 컨텍스트 추출**: 
   - 특정 블록의 실행 횟수가 임계값(Threshold, 예: 50번)을 넘으면, 해당 블록의 어셈블리 코드와 `Live-In`, `Live-Out` 레지스터 목록을 JSON 포맷으로 묶어 `jit_requests/block_0xADDR.json` 파일로 디스크에 내보냅니다(Dump).

---

## 🤖 3. LLM 트랜슬레이터 봇 (LLM Compiler Daemon)
C++ 엔진이 멈추지 않고 계속 실행되는 동안, 백그라운드에서는 파이썬 기반의 LLM 번역 봇(`llm_compiler.py`)이 동작합니다.

1. **비동기 감시 (Watchdog)**: `jit_requests/` 폴더를 실시간으로 감시하다가 새 JSON 파일이 등장하면 번역을 시작합니다.
2. **컨텍스트 기반 프롬프팅 (Prompt Engineering)**:
   - x86 코드 전체를 단순히 변환하는 것이 아니라, C++ 트램폴린이 매핑할 **레지스터 규칙 (e.g., `eax` -> `w0`, `eip` -> `w8`)** 을 엄격하게 따르도록 LLM에게 지시합니다.
   - 분기문(Branching) 발생 시 절대주소 점프명령어(`b.eq` 등) 대신, `csel`(조건부 선택)을 사용하여 다음 실행할 x86 주소(`Next EIP`)를 `w8` 레지스터에 담고 `ret` 하도록 강제합니다.
3. **네이티브 어셈블 (Keystone Engine)**:
   - LLM이 출력한 ARM64 어셈블리를 `keystone-engine`을 통해 순수한 기계어 바이너리(Raw Hex)로 변환한 후, `compiled_blocks/block_0xADDR.bin` 으로 저장합니다.

---

## ⚡ 4. JIT 디스패처 & 컨텍스트 스위칭 (JIT Trampoline)
LLM 봇이 만들어낸 ARM64 기계어 코드를 C++ 에뮬레이터가 넘겨받아 실제로 macOS CPU 위에서 실행하는 가장 정밀한 단계입니다.

1. **W^X 보호기법 우회**: 
   - macOS Apple Silicon은 "쓰기(W)"와 "실행(X)"이 동시에 허용되는 메모리를 강력히 차단합니다.
   - `MAP_JIT`으로 메모리를 할당한 뒤, Apple 전용 커널 API인 `pthread_jit_write_protect_np(0)`를 호출해 잠시 쓰기 권한을 열어 `.bin` 코드를 복사하고 다시 `pthread_jit_write_protect_np(1)`로 잠그는 트릭을 사용합니다.
2. **컨텍스트 스위칭 구조체 (Inline Assembly Trampoline)**:
   - Unicorn 에뮬레이터의 x86 레지스터들(`EAX~EDI`, `EIP`)을 통째로 읽어와, C++ 인라인 어셈블리(`__asm__ volatile`)를 통해 네이티브 ARM64 레지스터(`w0~w8`)로 매핑시킵니다.
   - `blr` 명령어를 통해 JIT 메모리 구역으로 점프하여 기계어를 네이티브 속도로 실행합니다.
3. **상태 복원 및 이음새 매끄러움**:
   - 네이티브 실행이 끝나면(`ret`), 연산 결과가 담긴 ARM64 레지스터들을 다시 x86 Unicorn 컨텍스트에 덮어씌웁니다.
   - 가장 중요한 다음 명령어 주소(Next EIP) 역시 `w8`에서 가져와 Unicorn의 `EIP`에 업데이트한 뒤, 에뮬레이터 제어권을 자연스럽게 다시 Unicorn에게 넘깁니다.

이 과정을 통해 순수 에뮬레이션과 네이티브 ARM64 하드웨어 가속이 완전히 투명하게 결합된 하이브리드 엔진이 완성되었습니다!

---

## 🛠 5. 리소스 최적화 및 동적 API 모킹 (Phase 5)
사전 설계된 JIT 엔진을 더욱 빠르고 유연하게 만들기 위해 두 가지 고급 최적화/자동화 레이어가 적용되었습니다.

1. **JIT 블록 해시 알고리즘 캐싱 (`llm_cache/`)**:
   - `llm_compiler.py`가 입력된 x86 어셈블리 루틴 전체의 `SHA256` 해시를 추출합니다.
   - 기존에 번역된 데이터 기록이 존재할 경우 느린 LLM 호출을 우회하고, 해시 파일(`HASH.bin`)로 캐시된 기계어를 즉각 반환하여 실시간 JIT 성능을 증명합니다.
   
2. **동적 C++ API JIT 컴파일러 (Dynamic API Mocking)**:
   - Unicorn 에뮬레이터 구동 도중 사전 정의되지 않은 Win32 API (예: `TlsGetValue`, `GetModuleHandleA`)를 마주치면, C++ 코어 브릿지가 유니콘 스레드를 잠시 일시 정지(`usleep()`) 상태로 전환하고 JSON 요청을 내보냅니다.
   - 백그라운드의 Python 데몬 워치독(`api_compiler.py`)이 파일 쓰기 이벤트를 가로채어 LLM에게 실시간 구동이 가능한 C++ Mock 코드를 요청합니다.
   - LLM이 출력한 C++ 코드를 `clang++`을 통해 런타임에 즉석에서 macOS용 네이티브 확장 라이브러리(`.dylib`)로 컴파일시킵니다.
   - 일시 정지되었던 C++ 에뮬레이터는 상태를 해제하고, 새로 빌드된 macOS 동적 라이브러리 플러그인을 `dlopen()`과 `dlsym()` 시스템 콜을 통해 프로세스 메모리에 연동시켜 네이티브 머신에서 투명하게 재실행합니다.
   - 이 때, 동적 C++ 모듈 간의 영속적인 로컬 상태 관리를 위해 핵심 데이터를 `APIContext` 구조체로 공유하여 안정적인 Windows Heap/Handle State 처리를 보장합니다.

**🎉 이로써 기획된 모든 목표 마일스톤 구현이 완료되었으며, 세계 최초의 하이브리드 OS 런타임 JIT 에뮬레이터 아키텍처 파이프라인이 성공적으로 가동되었습니다!**

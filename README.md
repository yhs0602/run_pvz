# x86-to-ARM64 Hybrid JIT Emulator

세계 최초의 **Unicorn 기반 인공지능 보조 하이브리드 JIT 컴파일러**입니다.
이 엔진은 macOS (Apple Silicon) 상에서 Windows 32-bit x86 바이너리를 구동하며, 핫스팟 기본 블록을 감지해 LLM 언어 모델을 통해 ARM64 네이티브 코드로 크로스 컴파일 후 실행합니다. 

현재 `pvz/main.exe` (Plants vs. Zombies) 바이너리를 엔진 위에 올려서 에뮬레이션을 구동하는 테스트 파이프라인이 완성되어 있습니다.

## 🚀 파이프라인 구동 방법 (How to Run)

전체 시스템은 **메인 C++ 에뮬레이터**와 **2개의 백그라운드 Python 데몬(LLM 번역 봇)**으로 구성되어 있습니다.
터미널 창을 3개 열어서 아래 명령어들을 각각 실행해야 합니다.

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
백그라운드 봇들이 켜져 있는 상태에서 메인 엔진을 구동하여 바이너리를 분석/실행합니다.
```bash
# 이전에 컴파일된 캐시 파일들을 지우고 새로 처음부터 런타임을 감상하려면 아래 명령어로 정리하세요.
rm -rf compiled_blocks/* llm_cache/* jit_requests/* api_requests/* api_mocks/*

# 메인 실행
./build/runner pvz/main.exe
```

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

# 특정 watchpoint 로그 활성화 (기본 OFF)
PVZ_WATCHPOINT=1 ./build/runner pvz/main.exe

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

현재 돌려보시면 엔진이 미지의 API들을 계속해서 마주치고, AI가 그것들을 실시간으로 C++로 짜주며 다음 단계로 무한히 돌파해 나가는 경이로운 JIT 파이프라인 과정을 콘솔 로그로 감상하실 수 있습니다!

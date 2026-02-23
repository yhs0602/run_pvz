# 2026-02-23 Unicorn + LLM -> libfexcore 전환 전략

## 가설
- 현재 구조에서 병목은 `x86 실행 자체`보다 `Unicorn 단일스텝/훅 + JIT 우회 처리` 결합 복잡도다.
- `libfexcore`를 CPU 실행 엔진으로 쓰면 x86 실행 성능과 안정성(특히 메모리 접근 패턴)이 개선될 가능성이 있다.
- 단, 현재 엔진의 강점인 `Windows API HLE(api_handler.cpp)`를 깨지 않으려면 CPU 백엔드 교체를 단계적으로 해야 한다.

## 핵심 원칙
- 목표는 "전면 재작성"이 아니라 "백엔드 교체 가능한 구조"다.
- 1차 성공 조건은 FPS/성능이 아니라 `PvZ 부팅 경로를 현재 수준 이상으로 재현`하는 것이다.
- API/HLE 레이어(`DummyAPIHandler`)는 최대한 유지하고 CPU 실행부만 분리한다.

## 목표 아키텍처
- `Execution Backend`: x86 코드 실행/재개/중단/PC 조회.
- `Memory Backend`: map/read/write/protect.
- `Register Backend`: GPR/segment/GDTR read/write.
- `Trap/Hook Backend`: API 진입 지점, 예외 지점, 블록/메모리 이벤트 브리지.
- `Windows HLE Layer`: 기존 `api_handler.cpp` 유지 (백엔드 인터페이스만 의존).

## 단계별 계획
1. **Phase 0: 기준선 고정**
- 동일 바이너리(`pvz/main.exe`)로 60초 부팅 런 기준 로그 수집.
- 지표: 프로세스 생존, 미해결 API 수, `NOT FOUND` 파일 수, `UC_ERR_*` 유무.

2. **Phase 1: 백엔드 경계 만들기 (현재 진행 시작)**
- Unicorn include를 단일 호환 헤더(`cpu_backend_compat.hpp`)로 집중.
- CMake에 `PVZ_CPU_BACKEND` 스위치 추가 (`unicorn` 기본).
- 결과: 추후 `fexcore` 백엔드 추가 시 파일 전역 치환 리스크 감소.

3. **Phase 2: 최소 인터페이스 추출**
- `main.cpp`의 직접 `uc_*` 호출을 `CpuBackend` 래퍼로 이전.
- 1차 범위: `open/close`, `emu_start/stop`, `reg read/write`, `mem map/read/write`.
- 성공 기준: 기존 부팅 로그와 동등 레벨 유지.

4. **Phase 3: libfexcore Spike**
- 별도 `fex_spike_runner` 타겟으로 엔트리 실행/재개/중단만 연결.
- API trampoline 호출 경로가 보존되는지 검증.
- 실패 시 원인 분류:
  - 훅/트랩 모델 차이
  - 세그먼트/TEB/PEB 모델 차이
  - 메모리 권한/페이지 정렬 차이

5. **Phase 4: 본선 통합**
- `PVZ_CPU_BACKEND=fexcore` 빌드 경로 추가.
- `windows_env`, `pe_loader`, `api_handler`를 backend-neutral API로 이관.
- 1차 런타임 목표: 크래시 없이 메인 루프 진입.

## 리스크와 대응
- 리스크: FEX 훅 모델이 Unicorn처럼 세밀하지 않을 수 있음.
- 대응: 블록 훅 의존 기능(`hook_block_lva`)은 선택 기능으로 다운그레이드하고, 필수 기능(API 진입/반환) 먼저 이식.

- 리스크: 세그먼트/FS/TEB 동작 차이로 CRT 초기화 실패 가능.
- 대응: `windows_env`를 가장 먼저 backend API로 분리하고, TEB/PEB write 검증 로깅 추가.

- 리스크: 초기에는 성능 이득보다 통합 비용이 더 클 수 있음.
- 대응: Phase 3을 별도 바이너리로 분리해 본선 안정성을 보호.

## 즉시 실행 항목 (다음 커밋 단위)
1. `CpuBackend` 인터페이스 골격 추가 (`backend/cpu_backend.hpp`).
2. Unicorn 구현체 추가 (`backend/unicorn_backend.cpp`).
3. `main.cpp`만 우선 이관해서 기능 동등성 검증.
4. 60초 부팅 비교 리포트 작성.

## 진행 상태 (2026-02-23 밤)
- 완료:
  - `cpu_backend_compat.hpp` 도입
  - CMake `PVZ_CPU_BACKEND` 스위치 도입
  - `backend/cpu_backend.hpp` 추가
  - `backend/unicorn_backend.*` 추가
  - `main.cpp` 실행 루프를 `CpuBackend` 기반으로 일부 이관
  - `windows_env`를 `CpuBackend` 기반으로 이관
  - `pe_loader`를 `CpuBackend` 기반으로 이관
  - `api_context` helper를 `CpuBackend` 기반으로 이관
  - `api_handler` 생성/메모리/레지스터/훅 경로를 `CpuBackend` 기반으로 이관
  - 헤드리스/디버그 실행 플래그 도입 (`PVZ_HEADLESS`, `PVZ_DISABLE_NATIVE_JIT`, `PVZ_BOOT_TRACE`)
  - mock 안정화 플래그 도입 (`PVZ_DISABLE_DYLIB_MOCKS`)
  - `GetProcAddress/LoadLibrary/GetModuleHandle` 계열을 내장 HLE 우선 경로로 고정
  - `Tls/Fls/Interlocked` 계열을 내장 HLE 우선 경로로 확장
  - `HeapSize/HeapReAlloc` 내장 HLE 구현으로 포인터 오염 크래시 제거
  - `api_mocks/*.cpp`를 `ctx->backend` 호출 기반으로 치환
  - hot-path sync + heap/tls/fls 로그 억제(관측/성능 개선)
  - watchpoint 로그를 opt-in(`PVZ_WATCHPOINT`)으로 전환
  - 60초 지표 샘플 1회 수집 (`known=0:0`, `NOT FOUND:0`, `UC_ERR_FETCH_UNMAPPED:1`)
- 미완료:
  - `HeapAlloc/HeapFree` 핫루프 로그 억제(선택적 디버그 플래그화)
  - `PVZ_CPU_BACKEND=fexcore` 실제 구현

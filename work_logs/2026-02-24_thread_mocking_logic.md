# PvZ Runner Thread Mocking Logic (Current)

## 1. 목적
현재 러너는 단일 백엔드 인스턴스 위에서 guest thread를 협조적(cooperative)으로 스케줄링합니다.  
Win32 스레드/동기화 API는 `api_handler_known_dispatch.inl`, 스케줄러 본체는 `api_handler.cpp`/`main.cpp`에 있습니다.

## 2. 현재 모킹 동작

### 2.1 `CreateEventA/W`
- `EventHandle` 객체를 생성해 `event_<handle>`로 `handle_map`에 저장.
- `manual_reset`, `signaled(initial state)`를 저장.
- 반환값: 생성 핸들(0x7000부터 증가), `LastError=0`.

### 2.2 `CreateThread`
- `ThreadHandle`(`start_address`, `parameter`, `thread_id`, `started`, `finished`)를 `thread_<handle>`로 등록.
- `g_thread_start_to_handle[start_address] = handle`로 진입 관측용 매핑 유지.
- `PVZ_COOP_THREADS=1`이면 cooperative scheduler에 worker를 실제 등록:
  - thread register context 생성(`EIP=start_address`, `ESP=guest stack`).
  - guest stack을 별도 가상영역에 매핑 후 인자(`lpParameter`)를 push.
  - 다음 timeslice에서 worker가 실제 guest 코드 실행.
- `lpParameter`가 있으면 parameter block의 앞 8바이트를 `1,1`로 세팅해 초기화 게이트를 통과시키는 협조적 처리 수행.
- 반환값: 스레드 핸들/ThreadId(현재 handle 기반), `LastError=0`.

### 2.3 `WaitForSingleObject`
- event handle:
  - signaled면 `WAIT_OBJECT_0(0)` 반환.
  - auto-reset event는 성공 반환 후 `signaled=false`로 내립니다.
  - unsignaled일 때:
    - `INFINITE`면 deadlock 회피용으로 `WAIT_OBJECT_0(0)` 강제.
    - finite timeout이면 `WAIT_TIMEOUT(0x102)`.
- thread handle:
  - cooperative scheduler에서 해당 worker가 종료됐으면 `WAIT_OBJECT_0(0)`.
  - 아직 실행 중이면:
    - `timeout==0` -> `WAIT_TIMEOUT(0x102)`
    - 그 외 -> 호환성 우선으로 `WAIT_OBJECT_0(0)` + scheduler yield 요청.
- 그 외 handle:
  - 호환성 우선으로 `WAIT_OBJECT_0(0)` 반환.

### 2.4 `PostMessageA/W`
- 내부 Win32 메시지 큐에 메시지를 넣습니다.
- cooperative wakeup으로 모든 `event_` 핸들을 `signaled=true`로 설정합니다.
  - 목적: worker->UI 신호 대기를 빠르게 통과시켜 부팅 정체를 줄이기 위함.

### 2.5 thread entry 실제 실행 관측
- 블록 훅에서 현재 EIP가 `g_thread_start_to_handle`에 등록된 시작 주소와 같으면
  `ThreadHandle.started=true`로 마킹하고 trace를 출력합니다.
- 즉, "스레드 시작 주소가 guest에서 실제 실행됐는지"를 런타임에서 확인할 수 있습니다.

### 2.6 cooperative scheduler (신규)
- 활성화: `PVZ_COOP_THREADS=1`
- 실행 방식:
  - 메인 루프가 `emu_start(..., count=PVZ_COOP_TIMESLICE)`로 짧은 timeslice 실행.
  - slice 종료마다 현재 thread register를 저장하고 다음 runnable thread register를 로드.
  - `CreateThread/Sleep/SleepEx/SwitchToThread` 등에서 yield 요청 시 조기 전환.
- 한계:
  - 실제 선점형 병렬 실행이 아니라 단일 엔진 위 round-robin 컨텍스트 전환.
  - 동기화 의미론은 Win32 완전 동일하지 않음.

## 3. Win32 대비 차이(중요)
- 실제 host 병렬 스레딩이 아니라 cooperative guest 스케줄링입니다.
- `WaitForSingleObject(INFINITE, unsignaled event)`를 성공으로 우회합니다.
- `PostMessage`가 모든 event를 깨우는 broad wakeup을 수행합니다.
- 결과적으로 동기화 의미론이 단순화되어, 특정 상태기계에서 분기 왜곡 가능성이 있습니다.

## 4. 렌더링 루프와의 연관
최근 추적에서 다음이 확인되었습니다.
- `CreateThread(start=0x5d5dc0, ...)`는 호출됨.
- `PVZ_COOP_THREADS=1`에서 `0x5d5dc0` thread entry 실제 실행 관측됨.
- 이벤트/메시지 경로는 모킹 성공값으로 진행됨.
- 이후 루프는 여전히 `0x62ce9b/0x62cf8e/0x62118b/0x61fcd4`
  (`Enter/LeaveCriticalSection + HeapAlloc/HeapFree`)가 지배적이지만,
  별도로 `USER32!GetMessageA` 소비 루프가 가시적으로 증가.
- `IDirectDrawSurface7::Lock/Unlock` 호출은 관측되지 않음.

즉 기존 병목이었던 "worker 미실행"은 완화됐고,
현재 병목은 "메시지 루프 이후 렌더 호출(`Lock/Unlock`)로 연결되는 조건/상태값 정합성"으로 좁혀졌습니다.

## 5. 디버깅 플래그
- `PVZ_COOP_THREADS=1`
  - cooperative scheduler 활성화
- `PVZ_COOP_TIMESLICE=<insns>`
  - thread timeslice instruction count(기본 30000)
- `PVZ_COOP_TRACE=1`
  - scheduler register switch/spawn/fault trace
- `PVZ_THREAD_MOCK_TRACE=1`
  - `CreateEvent/CreateThread/WaitForSingleObject/PostMessage` 상태 로그 출력
  - thread start-address 실제 진입 관측 로그 출력
- `PVZ_HOT_LOOP_API_TRACE=1`
  - hot address 주변 API별 `EAX/LastError` 누적 통계 출력
- `PVZ_EIP_HOT_SAMPLE=1`
  - `resources.xml` 이후 지배적 EIP 주소/페이지 샘플 출력

## 6. 다음 구현 우선순위
1. event wait semantics 정밀화:
   - 무조건 성공 우회 줄이고, timeout/pending을 더 Win32 유사하게 반영.
2. `PostMessage` wakeup 범위 축소:
   - 모든 event가 아니라 연관 handle만 signal 하도록 좁히기.
3. `GetMessage/Dispatch` 경로에서 렌더 진입 전 조건 API(파일/타이밍/윈도우 상태) 정합성 집중 보강.

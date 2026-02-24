# PvZ Runner Thread Mocking Logic (Current)

## 1. 목적
현재 러너는 단일 에뮬레이션 스레드 기반으로 PvZ를 부팅하고 있으며, Win32 스레드/동기화 API는 `api_handler_known_dispatch.inl`에서 협조적(cooperative) 모킹으로 처리합니다.

## 2. 현재 모킹 동작

### 2.1 `CreateEventA/W`
- `EventHandle` 객체를 생성해 `event_<handle>`로 `handle_map`에 저장.
- `manual_reset`, `signaled(initial state)`를 저장.
- 반환값: 생성 핸들(0x7000부터 증가), `LastError=0`.

### 2.2 `CreateThread`
- 실제 guest thread를 스케줄링하지 않습니다.
- `ThreadHandle`(`start_address`, `parameter`, `started`, `finished`)를 `thread_<handle>`로 등록.
- `g_thread_start_to_handle[start_address] = handle`로 진입 관측용 매핑 유지.
- `lpParameter`가 있으면 parameter block의 앞 8바이트를 `1,1`로 세팅해 초기화 게이트를 통과시키는 협조적 처리 수행.
- 반환값: 스레드 핸들(0x8000부터 증가), `LastError=0`.

### 2.3 `WaitForSingleObject`
- event handle:
  - signaled면 `WAIT_OBJECT_0(0)` 반환.
  - auto-reset event는 성공 반환 후 `signaled=false`로 내립니다.
  - unsignaled일 때:
    - `INFINITE`면 deadlock 회피용으로 `WAIT_OBJECT_0(0)` 강제.
    - finite timeout이면 `WAIT_TIMEOUT(0x102)`.
- thread handle:
  - 현재 cooperative 모드에서는 실제 실행 완료 상태를 반영하지 못하므로 `WAIT_OBJECT_0(0)`를 반환합니다.
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

## 3. Win32 대비 차이(중요)
- `CreateThread`가 실제 병렬 실행을 만들지 않습니다.
- `WaitForSingleObject(INFINITE, unsignaled event)`를 성공으로 우회합니다.
- `PostMessage`가 모든 event를 깨우는 broad wakeup을 수행합니다.
- 결과적으로 동기화 의미론이 단순화되어, 특정 상태기계에서 분기 왜곡 가능성이 있습니다.

## 4. 렌더링 루프와의 연관
최근 추적에서 다음이 확인되었습니다.
- `CreateThread(start=0x5d5dc0, ...)`는 호출됨.
- 이벤트/메시지 경로는 모킹 성공값으로 진행됨.
- 그러나 `0x5d5dc0` thread entry의 실제 실행 관측 로그가 없음.
- 이후 hot loop는 `0x62ce9b/0x62cf8e/0x62118b/0x61fcd4`에서
  `Enter/LeaveCriticalSection + HeapAlloc/HeapFree`만 반복.
- `IDirectDrawSurface7::Lock/Unlock` 호출은 관측되지 않음.

즉 현재 병목은 파일/타이밍 API 실패보다는
"렌더 경로를 담당할 가능성이 큰 worker thread 본체가 실제 실행되지 않는 구조"가 더 직접적인 원인입니다.

## 5. 디버깅 플래그
- `PVZ_THREAD_MOCK_TRACE=1`
  - `CreateEvent/CreateThread/WaitForSingleObject/PostMessage` 상태 로그 출력
  - thread start-address 실제 진입 관측 로그 출력
- `PVZ_HOT_LOOP_API_TRACE=1`
  - hot address 주변 API별 `EAX/LastError` 누적 통계 출력
- `PVZ_EIP_HOT_SAMPLE=1`
  - `resources.xml` 이후 지배적 EIP 주소/페이지 샘플 출력

## 6. 다음 구현 우선순위
1. cooperative thread scheduler(최소형) 도입:
   - `CreateThread`된 start routine을 제한된 스텝으로 실제 실행.
2. event wait semantics 정밀화:
   - 무조건 성공 우회 줄이고, timeout/pending을 더 Win32 유사하게 반영.
3. `PostMessage` wakeup 범위 축소:
   - 모든 event가 아니라 연관 handle만 signal 하도록 좁히기.

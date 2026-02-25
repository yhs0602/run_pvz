# PvZ Emulator Temporary Workarounds Backlog (2026-02-25)

목적: 임시 우회 로직을 한 곳에 모아, 렌더링 루프 진입 이후 순차적으로 제거/정식화한다.

## P0 (렌더링 진입 직결)

- `main.cpp` hot-loop block acceleration (`PVZ_HOT_LOOP_ACCEL`)
  - 내용: 특정 주소 블록(문자열/복사/CRT/lock wrapper)을 host fast-path로 단축 실행.
  - 리스크: guest 부작용/호출 규약을 완전 재현하지 못할 가능성.
  - 종료 조건: 해당 주소들이 더 이상 top-hot이 아니거나, 정식 JIT/정확 구현으로 대체.

- `main.cpp` tree lookup loop fast-path (`0x5d8f50/0x5d8f58`)
  - 내용: resource/container 비교 탐색 루프를 host 순회로 단축 후 원래 tail(`0x5d8fcc`) 복귀.
  - 리스크: 트리 비교/순회 semantics 불일치 시 잘못된 lookup 가능.
  - 종료 조건: guest 원본 루프에서도 실시간 성능 확보 또는 정확한 native translation으로 대체.

- `main.cpp` stream xor decode fast-path (`0x5d8850`)
  - 내용: 스트림 디코드(복사+`xor 0xF7`) 함수 엔트리를 host bulk copy로 단축하고 tail 산술 결과를 직접 반환.
  - 리스크: 경계/오류 분기에서 원본 대비 미세 동작 차이 가능.
  - 종료 조건: 원본 블록(`0x5d8850~0x5d88a1`) 병목 해소 또는 정식 native translation 적용.

- `main.cpp` memmove fast-path (`0x624510`)
  - 내용: guest memmove 구현 루프를 host chunk copy(겹침 대응)로 대체.
  - 리스크: 특수 정렬/예외 경로와 미세한 동작 차이 가능.
  - 종료 조건: guest 원본 memmove 경로 성능 확보 또는 native JIT로 동일 성능 확보.

- `main.cpp` memmove_s wrapper fast-path (`0x61be1b`)
  - 내용: 정상 인자(`dst/src != NULL`, `destsz >= count`)에서 직접 copy 후 즉시 성공 반환.
  - 리스크: 오류 보고 분기와 미세한 side effect 차이 가능.
  - 종료 조건: guest wrapper 경로 성능 확보 또는 wrapper 전체를 정확 번역/JIT로 대체.

- `main.cpp` CRT alloc/free fast callsite (`0x61c130`, `0x621182`, `0x61fcc5`, `0x61fcc6`)
  - 내용: `PVZ_CRT_ALLOC_ACCEL`에서 CRT heap 호출을 arena allocator/성공 분기로 우회.
  - 리스크: 장기 실행 메모리 회수 불완전, allocator semantics 차이.
  - 종료 조건: guest CRT allocator 경로 안정화(실제 HeapAlloc/HeapFree 호출로도 성능/정합성 확보).

- `main.cpp` CRT free helper fast-path (`0x61c19a`, `0x61c19f`, `0x61fc66`)
  - 내용: arena 소유 포인터/NULL 해제 경로를 즉시 `ret`로 우회.
  - 리스크: arena 외 포인터 분류 오판 시 해제 semantics 이탈 가능.
  - 종료 조건: free helper의 guest 실행 부담 제거 또는 CRT free 경로 정식 구현으로 대체.

- `main.cpp` lock wrapper short-circuit (`0x62ce88`, `0x62cf60`)
  - 내용: steady-state 잠금 래퍼를 빠른 `ret` 경로로 우회.
  - 리스크: lock 초기화/동기화 side effect 누락 가능.
  - 종료 조건: cooperative scheduler + Win32 sync 정합성 고도화 후 제거.

- `main.cpp` string grow helper fast-path (`0x404080`)
  - 내용: `std::string` 계열 grow helper를 host-side realloc/copy/terminator 갱신으로 단축.
  - 리스크: SSO(작은 버퍼) 경계/예외 경로 미세 semantics 불일치 가능.
  - 종료 조건: 해당 함수의 guest 경로가 병목에서 사라지거나 정식 native translation로 대체.

- `main.cpp` substring assign helper fast-path (`0x403e20`)
  - 내용: 문자열 부분 복사 assign helper를 host-side 경계검사/복사/종단 갱신으로 단축.
  - 리스크: 원본 함수의 alias/예외 경로와 미세 차이 가능.
  - 종료 조건: guest 경로에서도 병목이 해소되거나 string helper 계열을 정식 번역으로 대체.

- `main.cpp` assign(ptr,len) helper fast-path (`0x404330`)
  - 내용: 겹침 없는 일반 `assign(ptr,len)` 경로를 host-side 복사/용량 확장으로 단축.
  - 리스크: 겹침(alias) 및 예외 분기의 세부 semantics 차이 가능.
  - 종료 조건: `0x404330/0x40437f/0x40438e` 병목이 해소되거나 정식 번역 경로로 대체.

- `main.cpp` alloc helper fast-path (`0x4041c0`)
  - 내용: grow helper의 내부 할당 헬퍼를 arena allocator로 직접 처리.
  - 리스크: arena 고갈 시 fallback 정책과 실제 CRT 정책 차이 가능.
  - 종료 조건: CRT allocator 전체 정합 구현 또는 원본 경로 성능 확보.

- `main.cpp` wide-string append/fill fast-path (`0x5bd830`, `PVZ_WSTRING_APPEND_ACCEL`)
  - 내용: grow가 필요 없는 경로(`new_len <= cap`)에서 wide-char 반복 append를 host bulk write로 단축하고 종단 NUL/length를 직접 갱신.
  - 리스크: 용량 확장 분기/예외 처리 경로는 guest 원본에 의존하므로 혼합 실행 시 경계 semantics 차이 가능.
  - 종료 조건: `0x5bd830/0x5bf470` 계열이 top-hot에서 벗어나거나 문자열 helper를 정식 번역/JIT로 대체.

- `main.cpp` iterator advance fast-path (`0x5bf4e0`, `PVZ_ITER_ADVANCE_ACCEL`)
  - 내용: iterator owner sentinel/범위 검사 통과 경로에서 `[iter+4] += delta`를 host에서 직접 수행하고 `ret 4`로 단축.
  - 리스크: invalid-parameter 분기 직전의 예외 보고 side effect는 guest 원본에 의존(검사 실패 시 폴백).
  - 종료 조건: `0x5bf4e0/0x5bf4ef/0x5bf4f8/0x5bf518/0x5bf52f` 계열이 top-hot에서 이탈하거나 정식 번역/JIT로 대체.

- `main.cpp` memmove_s fast-path (`0x61be96`, `PVZ_MEMMOVE_S_ACCEL`)
  - 내용: 정상 인자(`dst/src != NULL`, `destsz >= count`)에서 host memmove 후 즉시 성공 반환.
  - 리스크: 오류 경로에서 errno/invalid parameter 보고는 guest 원본에 의존(실패 조건에서 폴백).
  - 종료 조건: `0x61be96/0x61beeb` 병목이 해소되거나 정식 CRT wrapper 번역으로 대체.

- `main.cpp` string insert/fill fast-path (`0x55d410`, `PVZ_STRING_INSERT_ACCEL`)
  - 내용: grow 불필요 경로(`new_len <= cap`)에서 tail move + fill + terminator 갱신을 host에서 직접 수행.
  - 리스크: grow/예외 분기와 혼합 실행 시 경계 semantics 차이 가능.
  - 종료 조건: `0x55d410/0x55d4xx` 계열 병목이 사라지거나 정식 string helper 번역으로 대체.

- `main.cpp` insert+iterator fast-path (`0x5bba20`, `PVZ_INSERT_ITER_ACCEL`)
  - 내용: iterator 기반 1-byte insert 경로를 host에서 직접 계산(인덱스 산출 + 삽입 + out iterator 갱신)해 내부 helper 체인을 단축.
  - 운영 상태: **기본 OFF(opt-in)**. 회귀 가능성 확인 전까지 실험 플래그로만 사용.
  - 리스크: iterator owner/sentinel 경계 분기와 혼합 실행 시 세부 semantics 차이 가능.
  - 종료 조건: `0x5bba20/0x5bba..` 계열 병목이 해소되거나 정식 parser/string 경로 번역으로 대체.

- `main.cpp` wide->narrow small-string fast-path (`0x5afbb0`, `PVZ_WSTR_TO_STR_ACCEL`)
  - 내용: `len <= 15`인 wide-string을 host에서 바로 byte 변환해 small-string 목적지에 한 번에 기록.
  - 리스크: 장문 문자열(`len > 15`)은 guest 폴백이므로 혼합 실행에서 경계 semantics 차이 가능.
  - 종료 조건: `0x5afc06/0x5afc0d/0x5afc26` 루프 병목이 해소되거나 정식 파서/문자열 경로 번역으로 대체.

## P1 (안정화/운영성)

- `api_handler_known_dispatch.inl` MessageBox auto-ack 기본 ON
  - 내용: unattended 실행에서 MessageBox를 로그만 남기고 `IDOK`.
  - 리스크: 사용자 상호작용 필요 분기 누락.
  - 종료 조건: UI 이벤트 자동화 테스트가 완료되고 interactive mode가 기본이 되어도 장기 실행이 막히지 않을 때.

- `api_handler.cpp` Win32 message queue dedup/backpressure
  - 내용: queue tail dedup, full 시 drop, 통계 로그.
  - 리스크: 메시지 유실로 인한 guest 상태 차이.
  - 종료 조건: 메시지 소비 경로 정합성 확보 후 dedup/drop 의존 제거.

- `api_handler.cpp` dylib mock source/runtime no-op audit
  - 내용: no-op 의심 LLM mock 경고/거부 후 generic success fallback.
  - 리스크: 보수적 판단으로 정상 mock 차단 가능.
  - 종료 조건: 핵심 API를 native HLE/검증된 mock으로 대체하고 감사 우회 필요가 없어질 때.

## P2 (디버그 전용)

- fast-worker thread short-circuit (`PVZ_FAST_WORKER_THREAD`)
  - 내용: 특정 worker thread entry를 즉시 종료시켜 병목 위치 파악.
  - 리스크: 실제 동작 경로와 괴리.
  - 종료 조건: cooperative thread 실행으로 동일 병목 분석이 가능해지면 디버그 전용으로만 유지.

- thread/message trace 대량 로그 옵션들
  - 내용: `PVZ_THREAD_MOCK_TRACE`, 집중 trace 옵션들.
  - 리스크: GB 단위 로그/분석 비용 증가.
  - 종료 조건: 샘플링 기반 지표로 대체, 항상-on trace 제거.

- `api_handler.cpp` CreateWindowEx unregistered class fallback (default)
  - 내용: `PVZ_STRICT_CREATEWINDOW_CLASS=1`이 아닐 때 미등록 클래스라도 HWND를 생성해 진행.
  - 리스크: Win32의 엄격 클래스 등록 semantics와 차이, 클래스 초기화 누락을 숨길 수 있음.
  - 종료 조건: `RegisterClass*` 경로 정합성 완비 후 fallback 제거.

- `api_handler.cpp` idle WM_TIMER 합성 옵트인 (`PVZ_FORCE_IDLE_TIMER`)
  - 내용: `GetMessage` idle fallback에서 timer 메시지 합성을 기본 OFF, 필요 시에만 ON.
  - 리스크: 일부 경로에서 wakeup 빈도 감소로 진행 속도 저하 가능.
  - 종료 조건: 실제 timer/message 동작이 안정화되면 옵션 자체 제거.

- `api_handler_known_dispatch.inl` CreateThread parameter priming (`PVZ_CREATE_THREAD_PRIME_PARAM`)
  - 내용: 과거 호환 해킹(`lpParameter +0/+4 = 1`)을 기본 OFF로 전환하고 opt-in env로만 유지.
  - 리스크: 과거에 이 priming에 의존하던 경로가 있으면 진행 속도 저하 가능.
  - 종료 조건: thread bootstrap 정합성이 확보되면 옵션 자체 제거.

- `main.cpp` memmove_s wrapper extended fast-path (`0x61be1b`)
  - 내용: 기존 정상 copy 경로 외에 invalid-arg 반환(`0x16/0x22`) + `dst` zero-fill 경로까지 host에서 직접 처리.
  - 리스크: CRT invalid-parameter 핸들러/errno 부수효과를 완전 재현하지 않음.
  - 종료 조건: wrapper 전체를 guest 정식 경로/JIT로 대체하거나, invalid-parameter side effect를 정식 구현.

- `main.cpp` memmove_s extended fast-path (`0x61be96`)
  - 내용: 정상 copy + invalid-arg 반환(`0x16/0x22`)을 host에서 처리.
  - 리스크: invalid-parameter report/errno 부수효과 생략 가능.
  - 종료 조건: CRT memmove_s 경로 정식 번역으로 대체.

- `main.cpp` stream pop fast-path (`0x5bb880`, `PVZ_STREAM_POP_ACCEL`)
  - 내용: 비어있지 않은 stream 버퍼에서 `wchar` pop 경로를 직접 수행.
  - 리스크: underflow callback(버퍼 비어있을 때)의 세부 semantics는 guest 경로 의존.
  - 종료 조건: streambuf/reader 경로 정식 번역으로 대체.

- `main.cpp` streambuf branch-block accel (`0x5bb880/0x5bb894/0x5bb89f`, `PVZ_STREAMBUF_BRANCH_ACCEL`)
  - 내용: push/mov/cmp/jcc 블록을 의미보존 형태로 한 번에 에뮬레이션.
  - 리스크: 플래그/stack side effect의 미세 불일치 가능.
  - 종료 조건: 해당 블록이 병목에서 이탈하거나 native/JIT 경로가 안정화.

- `main.cpp` xml parser branch-block accel (`0x5a1f72/0x5a1f7b/0x5a1f8b/0x5a2052/0x5a210a`, `PVZ_XML_BRANCH_ACCEL`)
  - 내용: parser 상태머신의 고빈도 분기 블록을 의미보존 형태로 단축.
  - 리스크: 분기 블록에서의 레지스터/조건 플래그 미세 차이가 누적될 가능성.
  - 종료 조건: parser 루프가 병목에서 벗어나거나 parser 경로를 정식 번역으로 대체.

- `main.cpp` text normalize branch-block accel (`0x62b0d8/0x62b0e5/0x62b0e9/0x62b0f5/0x62b0fd/0x62b105/0x62b184/0x62b185`, `PVZ_TEXT_NORM_BRANCH_ACCEL`)
  - 내용: CR/LF/EOF 정규화 문자 루프의 분기 블록을 의미보존 형태로 단축.
  - 리스크: 블록 경계의 플래그/미세 side effect 불일치가 누적될 가능성.
  - 종료 조건: `0x62b0xx` 군집이 top-hot에서 이탈하거나 parser 경로가 정식 번역/JIT로 대체.

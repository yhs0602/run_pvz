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

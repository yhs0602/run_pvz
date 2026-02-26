# 2026-02-26 Wine 실행 PoC (macOS)

## 목표
- PvZ(`pvz/main.exe`)를 에뮬레이터 경로 외에 Wine 경로로도 실제 실행 가능한지 확인.

## 수행 내용
1. 로컬 Wine 탐지:
- 초기 상태: `wine`, `wine64`, `wineserver` 미설치.
- 환경: macOS 15.7.3 (arm64), Rosetta 설치됨(`oahd` 실행 확인).

2. 설치 시도:
- `brew install --cask --no-quarantine wine-stable`
  - 실패: `gstreamer-runtime` 설치 과정에서 sudo 비밀번호 요구.
- 대안: `brew install --cask --no-quarantine gcenx/wine/wine-crossover`
  - 성공.
  - 버전: `wine-8.0.1 (CrossOverFOSS 23.7.1)`.

3. 실행 검증:
- prefix 초기화:
  - `WINEPREFIX=/Users/yanghyeonseo/Developer/pvz/artifacts/wine/prefix-pvz WINEDEBUG=-all wineboot -u`
- PvZ 실행(상대경로 기반):
  - `cd /Users/yanghyeonseo/Developer/pvz/pvz`
  - `WINEPREFIX=... WINEDEBUG=-all wine ./main.exe`
- 관측:
  - 25초/40초 시점 모두 프로세스 생존.
  - `main.exe`가 Wine 하위 프로세스로 실제 기동 확인:
    - `... wine-preloader Z:\\Users\\yanghyeonseo\\Developer\\pvz\\pvz\\main.exe ...`
  - 단기 실행에서는 치명적 크래시 시그널 미확인.

## 산출물
- 실행 로그:
  - `/Users/yanghyeonseo/Developer/pvz/logs_wine/wineboot_20260226_201541.log`
  - `/Users/yanghyeonseo/Developer/pvz/logs_wine/pvz_wine_run_20260226_201611.log`
  - `/Users/yanghyeonseo/Developer/pvz/logs_wine/pvz_wine_diag_20260226_201651.log`
  - `/Users/yanghyeonseo/Developer/pvz/logs_wine/pvz_wine_run40_20260226_201717.log`
- 재현 스크립트:
  - `/Users/yanghyeonseo/Developer/pvz/tools/run_pvz_wine.sh`

## 메모
- `wine-crossover`는 32/64-bit 실행은 지원하지만 32-bit prefix 생성은 미지원(cask caveat).
- 현재 목표(실행 가능성 확인)는 충족. 실제 렌더링/입력 품질 평가는 장시간 GUI 관찰 단계에서 추가 필요.


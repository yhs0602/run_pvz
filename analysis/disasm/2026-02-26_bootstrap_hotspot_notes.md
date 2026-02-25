# PvZ bootstrap hotspot notes (2026-02-26)

## Key observation
- SDL/DirectDraw initialization is not the immediate blocker.
- Runtime reaches Direct3D/DirectDraw setup APIs, but does not reach `IDirectDrawSurface7::Lock/Unlock` in current runs.
- After `CreateThread(start=0x5d5dc0)` + `WaitForSingleObject` + `CreateFileA('properties\\resources.xml')`, execution remains dominated by text/xml normalization hot paths.

## Message-loop symptom
- With `PVZ_VERBOSE_MSG_PUMP=1`, worker thread (`tid=2`) repeatedly calls `GetMessageA(hwnd=0,min=0,max=0)` and receives idle `WM_NULL` while parked.
- 25s sample showed ~392 `GetMessageA tid=2` idle cycles.

## Disassembly anchors
- `0x5d5dc0`: worker thread entry / bootstrap callback orchestration.
- `0x62ce88..0x62cf8f`: CRT lock wrapper family around internal lock table (`0x69a8f8`), not direct render path.
- `0x62118b`: allocation/lock branch continuation (`mov esi,eax; test esi,esi; jne ...`).
- `0x61fcd4`: `test eax,eax; jne ...` branch in lock-related helper.

## Immediate debugging hypothesis
1. Worker message wait is still effectively busy-looping due scheduler semantics around parked thread progress.
2. Render loop is gated behind completion of parser/bootstrap path and/or message-state rendezvous, so no `Lock/Unlock` yet.

## Next checks
1. Add coop scheduler trace for runnable set transitions at timeslice boundaries.
2. Ensure a parked thread cannot continue executing when no valid switch happened.
3. Validate `RegisterWindowMessageA` posted messages are consumed by owning thread queue (not broadcast wake side effects).

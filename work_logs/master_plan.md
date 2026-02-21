# JIT Emulator Agent Workflow Journal

This log tracks the high-level progress, decisions, and future milestones of the x86-to-ARM64 LLM-assisted JIT Emulator project.

## Phase 1: PoC (Proof of Concept) & Initial Loaders
- **[DONE]** Validate LVA (Live-Variable Analysis) via Capstone `CS_OPT_DETAIL` on basic blocks.
- **[DONE]** Build `pe_loader.py` using `pefile` to parse `main.exe` into Unicorn memory.
- **[DONE]** Implement structural Windows dependencies (TEB, PEB, GDT, FS segment) to support SEH setup routines.

## Phase 2: Refactoring & Architecture Solidification (Current)
- **[DONE]** Modularize procedural Python scripts into structured Object-Oriented representations (e.g., `Emulator`, `WindowsEnv`, `PELoader` classes).
- **[DONE]** Implement a robust Dummy API Handler (stdcall stack cleanup `ret N` resolution based on known API signatures).
- **[DONE]** Extend the C++ runner project (`CMakeLists.txt` and `main.cpp`) to bridge the Python prototype metrics back to the core C++ architecture using Capstone and Unicorn C APIs natively.

## Phase 3: JIT Profiler & Payload Extraction (Current)
- **[DONE]** Implement a dynamic Basic Block Profiler in C++ using `Unicorn` hooks.
- **[DONE]** Extract Hotspot thresholds (`execution_count >= 50`) to reduce Capstone LVA overhead.
- **[DONE]** Export Hotspot context payloads to JSON (Address, Size, Assembly, Live-In, Live-Out) inside `jit_requests/` directory.

## Phase 4: LLM ARM64 Compilation & JIT Dispatcher (Upcoming)
- **[TODO]** Create an LLM Translation Script: A Python agent that consumes `jit_requests/*.json` and prompts the LLM for equivalent ARM64 instructions, strictly honoring the Live-In/Live-Out constraints.
- **[TODO]** Implement a JIT Dispatcher (Trampoline) in C++:
  - Allocate executable memory (RWX) for translated ARM64 blocks.
  - Intercept x86 execution in Unicorn when reaching a translated block's address, and divert execution to the native ARM64 block.
- **[TODO]** Handle Indirect Jumps (`jmp eax`, `call ebx`):
  - Ensure the LLM translates indirect jumps to return control to the C++ JIT Dispatcher with the target address (e.g., in a specific context register).
  - The Dispatcher looks up the target address in a translated block registry:
    - If found: Jump to the native ARM64 block (Block Chaining).
    - If not found: Fallback to Unicorn emulation.

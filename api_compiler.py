import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

API_REQUESTS_DIR = Path("api_requests")
API_MOCKS_DIR = Path("api_mocks")
API_CACHE_DIR = Path("llm_cache/api_mocks")

PROMPT_TEMPLATE = """
You are an expert C++ Windows API reverse engineer.
Write a C++ mock function for the Win32 API: {api_name} (Module: {module}).

Requirements:
1. The function signature MUST be:
   extern "C" void mock_{api_name}(APIContext* ctx)
2. You must `#include "api_context.hpp"`.
3. Inside the function, retrieve arguments using `ctx->get_arg(index)` where index 0 is the first argument.
4. Set return value in EAX using `ctx->set_eax(value)`.
5. Emulate stdcall return by popping arguments and manually setting EIP using backend APIs:
   uint32_t esp;
   ctx->backend->reg_read(UC_X86_REG_ESP, &esp);
   uint32_t ret_addr;
   ctx->backend->mem_read(esp, &ret_addr, 4);
   esp += <ARGS_BYTES> + 4;
   ctx->backend->reg_write(UC_X86_REG_ESP, &esp);
   ctx->backend->reg_write(UC_X86_REG_EIP, &ret_addr);
6. Use realistic values and preserve state via `ctx->global_state` / `ctx->handle_map` if needed.
7. Return only C++ code in a ```cpp block.
"""


def backend_define() -> str:
    selected = os.environ.get("PVZ_CPU_BACKEND", "unicorn").strip().lower()
    if selected == "fexcore":
        return "-DPVZ_CPU_BACKEND_FEXCORE=1"
    return "-DPVZ_CPU_BACKEND_UNICORN=1"


def compile_mock(cpp_path: Path, dylib_path: Path) -> None:
    pkg_cflags = subprocess.check_output(["pkg-config", "--cflags", "unicorn"]).decode().strip().split()
    compile_cmd = [
        "clang++",
        "-dynamiclib",
        "-std=c++20",
        backend_define(),
        "-I.",
        "-undefined",
        "dynamic_lookup",
    ] + pkg_cflags + [str(cpp_path), "-o", str(dylib_path)]
    subprocess.run(compile_cmd, check=True)


def parse_cpp_block(llm_response: str) -> str:
    match = re.search(r"```(?:cpp|c\+\+|c)?\n(.*?)\n```", llm_response, re.DOTALL)
    if match:
        return match.group(1).strip()
    return llm_response.strip()


def llm_generate(api_name: str, module: str) -> str:
    prompt = PROMPT_TEMPLATE.format(api_name=api_name, module=module)
    prompt_file = Path(f"temp_prompt_api_{api_name}.txt")
    output_file = Path(f"temp_out_api_{api_name}.txt")

    prompt_file.write_text(prompt)
    try:
        cmd = ["codex", "exec", "--ephemeral", "-o", str(output_file)]
        with prompt_file.open("r") as p_in:
            subprocess.run(cmd, stdin=p_in, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        llm_response = output_file.read_text()
    finally:
        if prompt_file.exists():
            prompt_file.unlink()
        if output_file.exists():
            output_file.unlink()
    return parse_cpp_block(llm_response)


def ensure_dirs() -> None:
    API_REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
    API_MOCKS_DIR.mkdir(parents=True, exist_ok=True)
    API_CACHE_DIR.mkdir(parents=True, exist_ok=True)


def load_request(filepath: Path) -> dict:
    for _ in range(10):
        if filepath.exists() and filepath.stat().st_size > 0:
            break
        time.sleep(0.2)
    return json.loads(filepath.read_text())


class APICompilerHandler(FileSystemEventHandler):
    def __init__(self, allow_llm: bool) -> None:
        super().__init__()
        self.allow_llm = allow_llm

    def process_request(self, filepath: Path) -> None:
        print(f"[*] Processing API request: {filepath}")
        try:
            data = load_request(filepath)
            api_name = data["api_name"]
            module = data.get("module", "UNKNOWN")

            cpp_filepath = API_MOCKS_DIR / f"{api_name}.cpp"
            dylib_filepath = API_MOCKS_DIR / f"{api_name}.dylib"
            cache_cpp = API_CACHE_DIR / f"{api_name}.cpp"

            if cpp_filepath.exists():
                print(f"[*] Reusing existing mock source: {cpp_filepath}")
                cpp_source = cpp_filepath.read_text()
            elif cache_cpp.exists():
                print(f"[*] Cache hit for {api_name}: {cache_cpp}")
                cpp_source = cache_cpp.read_text()
                cpp_filepath.write_text(cpp_source)
            elif self.allow_llm:
                print(f"[*] Sending {api_name} to Codex LLM...")
                cpp_source = llm_generate(api_name, module)
                cpp_filepath.write_text(cpp_source)
                cache_cpp.write_text(cpp_source)
            else:
                raise RuntimeError(f"Missing source for {api_name} and LLM disabled")

            print(f"[*] Compiling {cpp_filepath} -> {dylib_filepath}")
            compile_mock(cpp_filepath, dylib_filepath)
            print(f"[+] Successfully compiled API Mock plugin: {dylib_filepath}\n")

            processed = filepath.with_suffix(filepath.suffix + ".processed")
            if filepath.exists():
                filepath.rename(processed)
        except Exception as e:
            print(f"[!] Error processing {filepath}: {e}")

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix == ".json":
            time.sleep(0.1)
            self.process_request(path)


def rebuild_all_mocks() -> None:
    print("[*] Rebuilding all api_mocks/*.cpp -> *.dylib ...")
    rebuilt = 0
    failed = 0
    for cpp in sorted(API_MOCKS_DIR.glob("*.cpp")):
        dylib = cpp.with_suffix(".dylib")
        try:
            compile_mock(cpp, dylib)
            rebuilt += 1
        except Exception as e:
            failed += 1
            print(f"[!] Rebuild failed: {cpp} ({e})")
    print(f"[*] Rebuild summary: ok={rebuilt}, failed={failed}")


def drain_existing_requests(handler: APICompilerHandler) -> None:
    print("[*] Checking for existing API mock requests...")
    for json_file in sorted(API_REQUESTS_DIR.glob("*.json")):
        handler.process_request(json_file)


def main() -> None:
    parser = argparse.ArgumentParser(description="API mock generator/compiler")
    parser.add_argument("--once", action="store_true", help="Process existing requests then exit")
    parser.add_argument("--rebuild-all", action="store_true", help="Recompile all api_mocks/*.cpp before request handling")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM generation (cache/source reuse only)")
    args = parser.parse_args()

    ensure_dirs()
    handler = APICompilerHandler(allow_llm=not args.no_llm)

    if args.rebuild_all:
        rebuild_all_mocks()
    drain_existing_requests(handler)

    if args.once:
        return

    observer = Observer()
    observer.schedule(handler, str(API_REQUESTS_DIR), recursive=False)
    observer.start()
    print(f"[*] LLM API Compiler Bot listening on {API_REQUESTS_DIR}/")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()


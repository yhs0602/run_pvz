import os
import json
import time
import subprocess
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

API_REQUESTS_DIR = "api_requests"
API_MOCKS_DIR = "api_mocks"

PROMPT_TEMPLATE = """
You are an expert C++ Windows API reverse engineer.
Write a C++ mock function for the Win32 API: {api_name} (Module: {module}).

Requirements:
1. The function signature MUST be:
   extern "C" void mock_{api_name}(APIContext* ctx)
2. You must `#include "api_context.hpp"`.
3. Inside the function, retrieve arguments using `ctx->get_arg(index)` where index 0 is the first argument.
4. Set the return value (usually in EAX) using `ctx->set_eax(value)`.
5. Emulate the `stdcall` return by popping arguments off the stack. To do this, modify the ESP register:
   uint32_t esp;
   uc_reg_read(ctx->uc, UC_X86_REG_ESP, &esp);
   esp += <number of argument bytes>;
   uc_reg_write(ctx->uc, UC_X86_REG_ESP, &esp);
6. For example, TlsGetValue takes 1 arg (4 bytes) -> esp += 4; GetModuleHandleA takes 1 arg -> esp += 4.
7. Return realistic values. If you need dynamic allocation or persistent state, use `ctx->global_state` or `ctx->handle_map`.
   Example: GetModuleHandleA(NULL) should return 0x400000 (ImageBase).
8. RETURN ONLY THE C++ SOURCE CODE inside a ```cpp block. No explanations or markdown.
"""

class APICompilerHandler(FileSystemEventHandler):
    def process_request(self, filepath):
        print(f"[*] Processing API request: {filepath}")
        try:
            for _ in range(10):
                if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                    break
                time.sleep(0.2)
                
            with open(filepath, "r") as f:
                data = json.load(f)
            
            api_name = data["api_name"]
            prompt = PROMPT_TEMPLATE.format(api_name=api_name, module=data.get("module", "UNKNOWN"))
            
            print(f"[*] Sending {api_name} to Codex LLM...")
            
            prompt_file = f"temp_prompt_api_{api_name}.txt"
            output_file = f"temp_out_api_{api_name}.txt"
            with open(prompt_file, "w") as f:
                f.write(prompt)
                
            cmd = ["codex", "exec", "--ephemeral", "-o", output_file]
            with open(prompt_file, "r") as p_in:
                subprocess.run(cmd, stdin=p_in, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            with open(output_file, "r") as f:
                llm_response = f.read()
                
            os.remove(prompt_file)
            os.remove(output_file)
            
            match = re.search(r'```(?:cpp|c\+\+|c)?\n(.*?)\n```', llm_response, re.DOTALL)
            if match:
                cpp_source = match.group(1).strip()
            else:
                cpp_source = llm_response.strip()
                
            cpp_filepath = os.path.join(API_MOCKS_DIR, f"{api_name}.cpp")
            dylib_filepath = os.path.join(API_MOCKS_DIR, f"{api_name}.dylib")
            
            with open(cpp_filepath, "w") as f:
                f.write(cpp_source)
                
            print(f"[*] Compiling {cpp_filepath} to {dylib_filepath}...")
            # Compile command for macOS dynamic library
            pkg_cflags = subprocess.check_output(["pkg-config", "--cflags", "unicorn"]).decode().strip().split()
            compile_cmd = [
                "clang++", "-dynamiclib", "-std=c++17",
                "-I.", "-undefined", "dynamic_lookup"
            ] + pkg_cflags + [cpp_filepath, "-o", dylib_filepath]
            
            subprocess.run(compile_cmd, check=True)
            
            print(f"[+] Successfully compiled API Mock plugin: {dylib_filepath}\n")
            
            # Rename the request file to mark as processed
            os.rename(filepath, filepath + ".processed")
            
        except Exception as e:
            print(f"[!] Error processing {filepath}: {e}")

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".json"):
            time.sleep(0.1)
            self.process_request(event.src_path)

if __name__ == "__main__":
    os.makedirs(API_REQUESTS_DIR, exist_ok=True)
    os.makedirs(API_MOCKS_DIR, exist_ok=True)
    
    event_handler = APICompilerHandler()
    
    print("[*] Checking for existing API mock requests...")
    for filename in os.listdir(API_REQUESTS_DIR):
        if filename.endswith(".json"):
            event_handler.process_request(os.path.join(API_REQUESTS_DIR, filename))

    observer = Observer()
    observer.schedule(event_handler, API_REQUESTS_DIR, recursive=False)
    observer.start()
    print(f"[*] LLM API Compiler Bot listening on {API_REQUESTS_DIR}/")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

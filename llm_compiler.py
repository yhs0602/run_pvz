import os
import json
import time
import subprocess
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

JIT_REQUESTS_DIR = "jit_requests"
COMPILED_BLOCKS_DIR = "compiled_blocks"

# Register mapping idea:
# eax->x0, ecx->x1, edx->x2, ebx->x3, esp->x4, ebp->x5, esi->x6, edi->x7
PROMPT_TEMPLATE = """
You are an expert assembly translator for JIT compilers. Translate the following 32-bit x86 basic block into Apple Silicon ARM64 assembly.
Requirements:
1. ONLY return the ARM64 assembly instructions enclosed in a ```arm64 code block. No explanations.
2. You must translate the logic preserving the Live-In and Live-Out registers.
3. Use this STRICT register mapping:
   eax -> w0
   ecx -> w1
   edx -> w2
   ebx -> w3
   esp -> w4
   ebp -> w5
   esi -> w6
   edi -> w7
   EIP (Instruction Pointer) -> w8
4. CONTROL FLOW & EIP: 
   - You MUST update w8 with the Next x86 Execution Address before returning!
   - If the block ends with a Conditional Branch (e.g. jne 0x6312a8), evaluate the condition in ARM64:
       If true, set w8 to the branch target (e.g., mov w8, #0x12a8; movk w8, #0x63, lsl #16).
       If false, set w8 to the Fallthrough Address (Block Address + Size).
       Use conditional moves (csel) to set w8!
   - If there is no branch, simply set w8 to the Fallthrough Address (e.g., mov w8, #0x12ac; movk w8, #0x63, lsl #16).
   - NEVER use ARM64 branch instructions (b, bl, b.ne) to jump to x86 addresses.
5. For memory accesses, use the correct ARM64 addressing. Zero-extend to 64-bit if using it as a base address.

JSON Context:
{json_context}
"""

class JITCompilerHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        os.makedirs(COMPILED_BLOCKS_DIR, exist_ok=True)

    def process_request(self, filepath):
        print(f"[*] Processing new JIT request: {filepath}")
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            address = data["address"]
            prompt = PROMPT_TEMPLATE.format(json_context=json.dumps(data, indent=2))
            
            # Use codex exec
            print(f"[*] Sending block {address} to Codex LLM...")
            
            # Write prompt to a temporary file is safer
            prompt_file = f"temp_prompt_{address}.txt"
            output_file = f"temp_out_{address}.txt"
            with open(prompt_file, "w") as f:
                f.write(prompt)
                
            cmd = ["codex", "exec", "--ephemeral", "-o", output_file]
            
            with open(prompt_file, "r") as p_in:
                subprocess.run(cmd, stdin=p_in, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            with open(output_file, "r") as f:
                llm_response = f.read()
                
            os.remove(prompt_file)
            os.remove(output_file)
            
            # Extract ARM64 assembly
            match = re.search(r'```(?:arm64|asm|assembly)?\n(.*?)\n```', llm_response, re.DOTALL)
            if match:
                assembly = match.group(1).strip()
            else:
                assembly = llm_response.strip() # Fallback if no codeblocks used
                
            # MUST append `ret` so the C++ dispatcher can `blr` and return!
            assembly += "\nret\n"
                
            print(f"[*] Generated ARM64 Assembly for {address}:\n{assembly}")
            
            # Compile with Keystone
            print(f"[*] Compiling to machine code...")
            encoding, count = self.ks.asm(assembly)
            
            if encoding:
                bin_filepath = os.path.join(COMPILED_BLOCKS_DIR, f"block_{address}.bin")
                with open(bin_filepath, "wb") as f:
                    f.write(bytearray(encoding))
                print(f"[+] Successfully compiled {address} to {bin_filepath} ({len(encoding)} bytes)\n")
            else:
                print(f"[!] Keystone failed to assemble {address}\n")
                
            # Rename the request file to mark as processed
            os.rename(filepath, filepath + ".processed")
            
        except Exception as e:
            print(f"[!] Error processing {filepath}: {e}")

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".json"):
            # Give it a tiny delay to ensure file is fully written
            time.sleep(0.1)
            self.process_request(event.src_path)

if __name__ == "__main__":
    os.makedirs(JIT_REQUESTS_DIR, exist_ok=True)
    os.makedirs(COMPILED_BLOCKS_DIR, exist_ok=True)
    
    event_handler = JITCompilerHandler()
    
    # Process any existing files
    print("[*] Checking for existing JIT requests...")
    for filename in os.listdir(JIT_REQUESTS_DIR):
        if filename.endswith(".json"):
            event_handler.process_request(os.path.join(JIT_REQUESTS_DIR, filename))

    observer = Observer()
    observer.schedule(event_handler, JIT_REQUESTS_DIR, recursive=False)
    observer.start()
    print(f"[*] LLM Compiler Bot listening on {JIT_REQUESTS_DIR}/")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

import glob
import os

for filepath in glob.glob("api_mocks/*.cpp"):
    with open(filepath, "r") as f:
        lines = f.readlines()
    
    new_lines = []
    skip = False
    for line in lines:
        if "uint32_t esp;" in line:
            skip = True
        
        if not skip:
            new_lines.append(line)
            
        if "uc_reg_write(ctx->uc, UC_X86_REG_EIP, &ret_addr);" in line:
            if skip:
                skip = False
                continue
    
    new_content = "".join(new_lines)
    if new_content != "".join(lines):
        with open(filepath, "w") as f:
            f.write(new_content)
        print(f"Sanitized: {filepath}")


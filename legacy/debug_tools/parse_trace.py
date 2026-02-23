lines = []
with open("boot_trace.txt", "r") as f:
    for line in f:
        if "GetProcAddress" in line or "EncodePointer" in line or "DecodePointer" in line:
            lines.append(line.strip())

for l in lines[-50:]:
    print(l)

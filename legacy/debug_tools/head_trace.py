lines = []
count = 0
with open("boot_trace.txt", "r") as f:
    for line in f:
        count += 1
        if count > 100000: break
        if "GetProcAddress" in line or "EncodePointer" in line or "DecodePointer" in line:
            lines.append(line.strip())

for l in lines:
    print(l)

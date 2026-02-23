lines = []
with open("boot_trace.txt", "r") as f:
    count = 0
    for line in f:
        count += 1
        if count > 50000: break
        if "DEBUG" in line and "GetProcAddress" in line:
            lines.append(line.strip())

for l in lines:
    print(l)

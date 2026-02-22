lines = []
with open("boot_trace.txt", "r") as f:
    for line in f:
        if "[API CALL]" in line and "TlsGetValue" not in line:
            lines.append(line.strip())

for l in lines[-40:]:
    print(l)

lines = []
with open("boot_trace.txt") as f:
    lines = f.read().split("\n")

for line in lines:
    if line.startswith("ADDR: 0x561"):
        print(line)
        pass # Not using python script now, writing a C++ hook for full coverage!

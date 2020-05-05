import sys
mallocs = {}
frees = {}
with open(sys.argv[1], "r") as f:
    for i, line in enumerate(f.readlines()):
        if line.startswith("MY MALLOC") or line.startswith("MY FREE"):
            ptr = line.split("=")[1].strip().split(" ")[0]
            source_location = line.split(" ")[2]

        if line.startswith("MY MALLOC"):
            mallocs[line.split(" ")[-1]] = mallocs.get(line.split(" ")[-1], []) + [i+1]
        elif line.startswith("MY FREE"):
            frees[line.split(" ")[-1]] = frees.get(line.split(" ")[-1], []) + [i+1]
n_leaks = 0
total_mallocs = 0
total_frees = 0
for m in mallocs:
    total_mallocs += len(mallocs[m])
    total_frees += len(frees.get(m, []))
    if not m in frees or len(frees[m]) < len(mallocs[m]):
        print(m, "not freed at lines", mallocs[m])
        n_leaks += 1
    elif m in frees and len(frees[m]) > len(mallocs[m]):
        print(m, "double freed", mallocs[m])

print(n_leaks, "non-freed blocks")
print(total_mallocs, "mallocs,", total_frees, "frees")

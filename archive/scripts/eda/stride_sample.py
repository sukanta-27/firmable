import sys

stride = int(sys.argv[1])
out_path = sys.argv[2]

n = 0
total_bytes = 0
with open(out_path, "wb") as out:
    for line in sys.stdin.buffer:
        n += 1
        total_bytes += len(line)
        if n % stride == 1:
            out.write(line)
        if n % 1_000_000 == 0:
            print(f"progress lines={n} bytes={total_bytes}", file=sys.stderr, flush=True)

print(f"DONE lines={n} bytes={total_bytes}", file=sys.stderr, flush=True)

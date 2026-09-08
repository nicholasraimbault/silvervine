#!/usr/bin/env bash
# Usage: scripts/perf_scoreboard.sh <path-to-musl-silvervine-binary>
set -euo pipefail
BIN="${1:?binary}"
test -x "$BIN"
echo "binary=$BIN"
echo "size_bytes=$(stat -c%s "$BIN")"
echo "version=$("$BIN" --version)"
python3 - "$BIN" <<'PY'
import os, subprocess, time, sys
bin = sys.argv[1]
cmds = [
    ("version", [bin, "--version"]),
    ("help", [bin, "--help"]),
    ("list", [bin, "--json", "list-browsers", "--all"]),
    ("status", [bin, "--json", "status"]),
    ("doctor", [bin, "--json", "doctor"]),
    ("media", [bin, "--json", "doctor", "--media-stack"]),
]
def nine(args):
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    walls, rss = [], []
    for _ in range(9):
        p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.perf_counter()
        _, _, ru = os.wait4(p.pid, 0)
        walls.append((time.perf_counter() - t0) * 1000)
        rss.append(ru.ru_maxrss / 1024)
    walls.sort()
    print(f"{args[-1] if args[-1] != '--media-stack' else 'media-stack'}: median_ms={walls[4]:.2f} max_ms={max(walls):.2f} peak_rss_mib={max(rss):.2f}")
for name, args in cmds:
    nine(args)
PY

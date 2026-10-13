"""Splits a sandbox Bridge log into the phases group_sandbox marked, and sums each phase's requests per method.

    docker logs privmx_e2e_worker_900 > bridge.log 2>&1
    python3 -I perf_parse.py bridge.log markers.txt [cpu.log] > phases.json

markers.txt holds one "<tag>|<key>> <epoch ms>" / "<tag>|<key>< <epoch ms>" line per marker call, in call order; the
k-th `context/getContext` request in the log is the k-th marker. Per phase: {method: [calls, failures, server ms sum,
server ms max, bytes in, bytes out]}, failure messages, and the Bridge container's mean/max CPU % from cpu.log
("<epoch s> <cpu%> <mem>" lines) over the phase's wall-clock window.
"""
import json
import re
import sys

MARKER = "context/getContext"
RECORD = re.compile(r"\[[0-9:\- ]+\] \w+ \([^)]*RequestLogger[^)]*\): \S+ request #\d+ finished in [0-9.]+ms\n\s+request: (\{.*?\n    \})", re.S)


def main(log_path, markers_path, cpu_path=None):
    text = re.sub(r"\x1b\[[0-9;]*m", "", open(log_path, errors="replace").read())
    markers = [line.rsplit(" ", 1) for line in open(markers_path).read().splitlines() if line.strip()]
    cpu = []
    if cpu_path:
        for line in open(cpu_path):
            parts = line.split()
            if len(parts) >= 2 and parts[1].endswith("%"):
                cpu.append((float(parts[0]), float(parts[1][:-1])))
    phases, opened, seen = {}, {}, 0
    current = None
    for m in RECORD.finditer(text):
        try:
            r = json.loads(m.group(1))
        except ValueError:
            continue
        methods = r.get("methods", [])
        if any(x.get("method") == MARKER for x in methods):
            if seen >= len(markers):
                raise SystemExit(f"more markers in the log than in {markers_path}: is the log from another run?")
            name, at = markers[seen]
            seen += 1
            key, edge = name[:-1], name[-1]
            if edge == ">":
                current = key
                opened[key] = int(at)
                phases.setdefault(key, {"methods": {}, "failures": {}})
            else:
                current = None
                phases[key]["wall_ms"] = int(at) - opened[key]
                window = [c for t, c in cpu if opened[key] / 1000 - 1 <= t <= int(at) / 1000 + 1]
                if window:
                    phases[key]["cpu_mean"] = round(sum(window) / len(window), 1)
                    phases[key]["cpu_max"] = max(window)
            continue
        if current is None:
            continue
        for i, x in enumerate(methods):
            row = phases[current]["methods"].setdefault(x["method"], [0, 0, 0.0, 0.0, 0, 0])
            row[0] += 1
            row[1] += 0 if x.get("success") else 1
            row[2] += x.get("durationMs", 0)
            row[3] = max(row[3], x.get("durationMs", 0))
            if i == 0:
                row[4] += r.get("bytesIn", 0)
                row[5] += r.get("bytesOut", 0)
            if not x.get("success"):
                err = json.dumps(x.get("error", {}))
                reason = "STALE_BASE_GENERATION" if "STALE_BASE_GENERATION" in err else x.get("error", {}).get("message", "?")
                k = x["method"] + ": " + reason[:120]
                phases[current]["failures"][k] = phases[current]["failures"].get(k, 0) + 1
    if seen != len(markers):
        print(f"warning: {len(markers) - seen} markers not found in the log", file=sys.stderr)
    for p in phases.values():
        for row in p["methods"].values():
            row[2], row[3] = round(row[2], 1), round(row[3], 1)
    json.dump(phases, sys.stdout, indent=1)


if __name__ == "__main__":
    main(*sys.argv[1:])

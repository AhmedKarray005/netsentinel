"""Measure how fast NetSentinel analyses captures and how much memory it needs.

    python -m pip install -e ".[bench]"
    python scripts/benchmark.py                          # synthetic 100k / 300k / 1M packets
    python scripts/benchmark.py --sizes 100000 --real lab/02_web/web_dns_tracert.pcapng

Each measurement runs in a FRESH Python process (so imports, caches and memory from one run do
not affect the next) and reports: wall time, CPU time, packets per second, peak memory (peak
working set on Windows, max RSS on Linux), and the numbers of flows and alerts.

Synthetic captures: the labelled `normal_browsing` + `port_scan_connect` scenarios (RFC 5737
addresses, nothing is sent on a network) are repeated with their timestamps shifted by 400 s
per copy, written record by record. Each copy therefore makes new flows, like a longer capture
of the same kind of traffic. It is a repeatable load, not a model of a real network.
"""

import argparse
import json
import platform
import struct
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

CHILD = r"""
import json, sys, time, psutil
t0, c0 = time.perf_counter(), time.process_time()
from netsentinel.analysis import run_analysis
t_import = time.perf_counter() - t0
t1, c1 = time.perf_counter(), time.process_time()
result = run_analysis(sys.argv[1])
wall, cpu = time.perf_counter() - t1, time.process_time() - c1
mem = psutil.Process().memory_info()
peak = getattr(mem, "peak_wset", None)
if peak is None:  # Linux / macOS
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
print(json.dumps({
    "packets": result.summary.packet_count, "flows": len(result.flows),
    "alerts": len(result.alerts), "wall_s": wall, "cpu_s": cpu,
    "import_s": t_import, "peak_mem_mb": peak / 2**20,
}))
"""

PCAP_HEADER = struct.Struct("<IHHiIII")
RECORD_HEADER = struct.Struct("<IIII")


def read_records(path: Path) -> tuple[bytes, list[tuple[float, bytes]]]:
    """Minimal classic-PCAP reader (little-endian, microseconds: what Scapy's wrpcap writes)."""
    data = path.read_bytes()
    header, offset, records = data[:24], 24, []
    if header[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError(f"{path}: expected a little-endian microsecond PCAP")
    while offset < len(data):
        sec, usec, incl, _orig = RECORD_HEADER.unpack_from(data, offset)
        offset += 16
        records.append((sec + usec / 1e6, data[offset : offset + incl]))
        offset += incl
    return header, records


def write_synthetic(out: Path, target_packets: int, base: list[tuple[float, bytes]], header):
    base = sorted(base, key=lambda r: r[0])
    span = 400.0  # > the 300 s TCP idle timeout: every copy starts new flows
    written, copy = 0, 0
    with out.open("wb") as f:
        f.write(header)
        while written < target_packets:
            for ts, raw in base:
                if written == target_packets:
                    break
                t = ts + copy * span
                sec, usec = int(t), int(round((t - int(t)) * 1e6))
                if usec == 1_000_000:
                    sec, usec = sec + 1, 0
                f.write(RECORD_HEADER.pack(sec, usec, len(raw), len(raw)))
                f.write(raw)
                written += 1
            copy += 1


def measure(pcap: Path, repeats: int) -> dict:
    runs = []
    for _ in range(repeats):
        proc = subprocess.run(
            [sys.executable, "-c", CHILD, str(pcap)], capture_output=True, text=True, check=True
        )
        runs.append(json.loads(proc.stdout.strip().splitlines()[-1]))
    best = min(runs, key=lambda r: r["wall_s"])  # least disturbed by other programs
    return {
        "file": pcap.name,
        "size_mb": round(pcap.stat().st_size / 2**20, 1),
        "packets": best["packets"],
        "flows": best["flows"],
        "alerts": best["alerts"],
        "runs": repeats,
        "wall_s_best": round(best["wall_s"], 2),
        "wall_s_all": [round(r["wall_s"], 2) for r in runs],
        "cpu_s": round(best["cpu_s"], 2),
        "packets_per_s": round(best["packets"] / best["wall_s"]),
        "peak_mem_mb": round(max(r["peak_mem_mb"] for r in runs), 1),
        "import_s": round(best["import_s"], 2),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sizes", type=int, nargs="*", default=[100_000, 300_000, 1_000_000])
    parser.add_argument("--real", type=Path, nargs="*", default=[], help="Own captures to time")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--json", type=Path, help="Write the results as JSON")
    args = parser.parse_args()

    import psutil

    from netsentinel.scenarios import write_scenarios

    results = []
    with tempfile.TemporaryDirectory(prefix="ns_bench_") as tmp:
        tmp_dir = Path(tmp)
        write_scenarios(tmp_dir / "scenarios")
        header, base = read_records(tmp_dir / "scenarios" / "normal_browsing.pcap")
        _, scan = read_records(tmp_dir / "scenarios" / "port_scan_connect.pcap")
        base += scan
        for size in args.sizes:
            pcap = tmp_dir / f"synthetic_{size}.pcap"
            write_synthetic(pcap, size, base, header)
            results.append(measure(pcap, args.repeats) | {"kind": "synthetic"})
            print(json.dumps(results[-1]), flush=True)
            pcap.unlink()
    for path in args.real:
        results.append(measure(path, args.repeats) | {"kind": "real"})
        print(json.dumps(results[-1]), flush=True)

    machine = {
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "os": platform.platform(),
        "cpu": platform.processor(),
        "logical_cpus": psutil.cpu_count(),
        "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
    }
    print("\n" + json.dumps(machine))
    print("\n| capture | packets | MB | flows | alerts | best wall s | packets/s | peak MB |")
    print("|---|---|---|---|---|---|---|---|")
    for r in results:
        print(
            f"| {r['file']} | {r['packets']:,} | {r['size_mb']} | {r['flows']:,} | "
            f"{r['alerts']} | {r['wall_s_best']} | {r['packets_per_s']:,} | {r['peak_mem_mb']} |"
        )
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({"machine": machine, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

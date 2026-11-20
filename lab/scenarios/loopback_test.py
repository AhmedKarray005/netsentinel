"""Generate REAL scan-like traffic against THIS computer only (127.0.0.1), for lab captures.

    python lab/scenarios/loopback_test.py scan     # connect to ports 1-200   -> NS-001 expected
    python lab/scenarios/loopback_test.py retry    # 15 attempts to port 9999 -> NS-003 expected

Capture it in Wireshark on "Adapter for loopback traffic capture".
Safety: the target is hard-coded to the loopback address; there is no option to change it.
"""

import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

TARGET = "127.0.0.1"  # loopback only - never change this to another host


def try_connect(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((TARGET, port)) == 0  # 0 = connection accepted


def scan() -> None:
    ports = range(1, 201)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = dict(zip(ports, pool.map(try_connect, ports), strict=True))
    open_ports = [p for p, ok in results.items() if ok]
    print(f"Tried {len(results)} ports on {TARGET} in {time.perf_counter() - started:.1f} s")
    print(f"Open ports: {open_ports or 'none'}")


def retry() -> None:
    for attempt in range(1, 16):
        ok = try_connect(9999)
        print(f"attempt {attempt:>2}: port 9999 {'accepted' if ok else 'refused'}")
        time.sleep(1)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "scan":
        scan()
    elif mode == "retry":
        retry()
    else:
        print(__doc__)
        sys.exit(1)

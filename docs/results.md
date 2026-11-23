# Measured results (Phase 8)

Everything on this page was measured on 2026-11-23 and can be re-run with the commands given.
Raw numbers: [`results/benchmark_2026-11-23.json`](results/benchmark_2026-11-23.json).

## 1. Detection quality on labelled scenarios

```powershell
netsentinel make-scenarios scenarios_out
netsentinel evaluate scenarios_out
```

14 synthetic scenarios (RFC 5737 addresses, nothing sent on a network), each with the truth
(rule + the host it should blame) and a prediction written before running it. Full table and
explanation: [detection.md](detection.md#measured-results).

| Rule | Attacks noticed | Scenarios with a false alarm | Known misses / false alarms |
|---|---|---|---|
| NS-001 port scan | 3 / 5 | 1 | misses slow scan (1 port / 5 s) and horizontal scan (1 port, 60 hosts); fires on a monitoring server checking 25 ports |
| NS-002 traffic spike | 2 / 3 | 0 | misses a flood spread over 20 sources |
| NS-003 failed connections | 2 / 2 | 0 | (brute force against an open service is out of reach without logs) |

**14 / 14 scenarios behaved as predicted**, including the 3 predicted misses and the predicted
false alarm. This shows the rules do what they were designed to do and fail where expected;
it is **not** a real-world accuracy figure, since the scenarios and the rules have the same author.

## 2. Real captures from my own lab

| Capture (own laptop, not in Git) | Packets | Expected | Got |
|---|---|---|---|
| `scan.pcapng`: loopback scan of ports 1-200 | 660 | NS-001 | NS-001 high, 199 ports in 4.6 s |
| `retry.pcapng`: 15 connections to a closed port | 64 | NS-003 | NS-003 low, 15 failures |
| `ping_gateway.pcapng`: ping + normal use | 28 867 | nothing | 0 alerts |
| `web_dns_tracert.pcapng`: web, DNS, traceroute | 58 437 | nothing | 0 alerts |
| `refused_port.pcapng` | 21 | nothing | 0 alerts |

Before the NS-002 "unsolicited packets" change, `ping_gateway.pcapng` gave 1 false alarm (a QUIC
download at 1 191 packets/s): see [detection.md](detection.md).

## 3. Speed and memory

```powershell
python -m pip install -e ".[bench]"
python scripts/benchmark.py --real lab\01_ping\ping_gateway.pcapng lab\02_web\web_dns_tracert.pcapng
```

Each figure is the best of 3 runs, each in a fresh Python process (CLI analysis: parse, flows,
summary, detection; no API, no database). Machine: Windows 11 laptop, Intel CPU with 12 logical
cores, 15.8 GB RAM, Python 3.13.12, other programs open.

| Capture | Packets | File | Flows | Alerts | Time | Packets/s | Peak memory |
|---|---|---|---|---|---|---|---|
| synthetic x 100k | 100 000 | 23.6 MB | 27 670 | 99 | 19.1 s | 5 249 | 75 MB |
| synthetic x 300k | 300 000 | 70.9 MB | 82 862 | 296 | 58.7 s | 5 111 | 109 MB |
| synthetic x 1M | 1 000 000 | 236.4 MB | 276 164 | 987 | 219.3 s | 4 560 | 228 MB |
| real: `ping_gateway.pcapng` | 28 867 | 23.4 MB | 321 | 0 | 5.6 s | 5 200 | 58 MB |
| real: `web_dns_tracert.pcapng` | 58 437 | 36.6 MB | 1 063 | 0 | 10.9 s | 5 340 | 59 MB |

Synthetic = the `normal_browsing` + `port_scan_connect` scenarios repeated with timestamps 400 s
apart (a repeatable load, not a model of a real network). Each copy contains one scan, and the
alerts follow it (99, 296, 987).

**What the numbers say:**
- About **5 000 packets/s, single core** (CPU time = wall time). Time grows linearly with the
  number of packets. The 1 M run was the slowest per packet (4 560/s); its 3 runs varied by
  14 % (219-250 s), the others by under 10 %.
- Memory grows with the number of **flows**, not the file size: the whole flow table is kept
  in memory (~0.6 KB per flow on top of a ~55 MB base). 276 000 flows -> 228 MB.
- **Where the time goes** (cProfile on `ping_gateway.pcapng`): **~81 % inside Scapy's packet
  decoding**, ~5 % in NetSentinel's own parsing, flow, summary and detection code. Speeding
  this up means a faster decoder (e.g. dpkt or reading only headers), not changing the rules.
- In practice: a capture at the 50 MB API upload limit takes about 12 s (big packets, like
  `ping_gateway.pcapng`, ~810 bytes each) to 45 s (small packets, like the synthetic set,
  ~240 bytes each). This is a tool for
  analysing captures after the fact, not for live traffic on a busy link (1 Gbit/s can be
  80 000+ packets/s).

## Not measured

- Detection quality on traffic not produced by me (public labelled datasets such as CIC-IDS2017
  would be the next step; they are large and were not downloaded).
- The API/dashboard under load (concurrent uploads).
- Linux performance (CI runs the tests on Linux, but the benchmark ran on Windows only).

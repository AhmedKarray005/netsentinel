# Demo script (about 5 minutes)

For an interview or a screen recording. Everything runs on one laptop; no traffic is sent to
any other machine. Commands are PowerShell, from `D:\projects\netsentinel`.

## Before the demo (once)

```powershell
docker compose up -d --build --wait     # dashboard + API, healthy in under a minute
.\.venv\Scripts\Activate.ps1            # for the CLI part
netsentinel make-scenarios demo_out     # labelled synthetic captures, written locally
```

Open http://localhost:8080 in a browser.

## 1. The problem (30 s)

"Network metadata shows who talks to whom, on which ports, how often. NetSentinel reads a
packet capture, rebuilds the connections (flows), and runs three detection rules that point an
analyst at suspicious patterns, with the evidence behind each alert. Alerts are indicators, not
proof."

## 2. A real capture from my own lab (1 min 30)

Dashboard -> **Upload** -> `lab\04_loopback_scan\scan.pcapng` (a scan I ran against my own
laptop's loopback address, 127.0.0.1, with `lab/scenarios/loopback_test.py`).

- **Overview**: 660 packets, protocol mix, timeline.
- **Alerts**: NS-001 port scan, high: 199 distinct ports in 4.6 s. Open the alert: evidence
  (ports, refused vs open, the thresholds that applied), MITRE ATT&CK T1046.
- Point out the honest details: 199, not 200 (no packet was seen for port 137), and a Windows
  quirk the flow code had to handle (a refused SYN is re-sent once from the same port).

## 3. How good are the rules? (1 min 30)

```powershell
netsentinel evaluate demo_out
```

- 14 labelled scenarios, each with the truth (rule + the host to blame) and a prediction
  written before running it.
- Show a hit (`scan_in_background_traffic`: the scanner is blamed, not the busy workstation),
  a predicted miss (`horizontal_scan`: one port on 60 hosts, the rule counts ports per
  destination), and a predicted false alarm (`monitoring_checks`).
- "14 out of 14 behaved as predicted. That means the rules do what I designed, and I know where
  they fail. It is not a real-world accuracy figure."

## 4. Engineering (1 min)

- GitHub Actions: lint, 99 tests on Python 3.13 and 3.15, frontend tests, Trivy scans of the code
  and both images, then a real upload through the containers. CI found a Linux-only bug on its
  first run.
- Containers: non-root, read-only filesystem, all Linux capabilities dropped, ports on
  127.0.0.1 only (there is no authentication yet).
- Performance: see `docs/results.md` (measured on this laptop).

## 5. Limits and next steps (30 s)

No TLS or login, so local use only. Analysis runs inside the upload request. Rules miss slow,
horizontal and distributed attacks (measured). Next: per-host baselines, a job queue,
horizontal-scan rule.

## After the demo

```powershell
docker compose down
```

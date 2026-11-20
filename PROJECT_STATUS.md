# Project status

Last updated: 2026-11-20

## Current phase: 0 — Planning and environment setup (in progress)

### Done
- Brief reviewed; MVP and phase completion criteria agreed (see below).
- Tools on the laptop checked (2026-11-20): Python 3.13.12, Git 2.56, Node 26.13, WSL2 Ubuntu 22.04
  (tcpdump, dig, ip, ss), Npcap present. Missing: Wireshark, nmap/traceroute in WSL, gh CLI.
  Docker Desktop 20.10.22 installed but old and not running.
- Repository skeleton: `pyproject.toml`, `src/netsentinel/` (version + CLI stub), smoke tests,
  `.gitignore`, README draft, `docs/architecture.md`, `docs/conventions.md`.

### Tests executed
- See the latest entry in "Test log".

### Remaining in Phase 0
- Install Wireshark on Windows (Npcap already present).
- First commit; create the GitHub repository (private until Phase 8).
- Free space on C: (1.9 GB free on 2026-11-20) or move Docker's disk image to D: before Phase 7.

## MVP (end of Phase 4)
`netsentinel analyze capture.pcap --out report.json` producing packet statistics, flows, and
alerts from 3 tested rules (port scan, traffic spike, failed-connection pattern), thresholds
from config.

## Phase completion criteria
| Phase | Done when |
|---|---|
| 0 | Repo, venv, smoke test, README, status file, architecture diagram committed |
| 1 | ~6 lab experiments each with capture + screenshot + notes |
| 2 | CLI stats match fixtures exactly; malformed PCAP handled cleanly |
| 3 | Flow table matches hand-checked lab capture; timeout/direction rules tested |
| 4 | 3 rules, each with positive + negative tests and documented false positives |
| 5 | API endpoints validated, size-limited, paginated, tested |
| 6 | 4 dashboard pages against the real API, screenshots |
| 7 | `docker compose up` from clean clone; CI green |
| 8 | Labelled scenarios with measured results; final README |

## Technical decisions
- Single Python package with modules, no microservices.
- `PacketRecord` boundary: only `parsing` imports Scapy.
- Streaming PCAP reading; synchronous analysis first.
- Windows-native Python for code, WSL Ubuntu for the lab.

## Problems encountered
- (none yet)

## Test log
| Date | Command | Result |
|---|---|---|
| 2026-11-20 | `pytest -q` | 3 passed |
| 2026-11-20 | `ruff check .` / `ruff format --check .` | clean |

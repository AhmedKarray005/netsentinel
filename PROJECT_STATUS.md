# Project status

Last updated: 2026-11-20

## Current phase: 1 — Networking lab (almost done)

Experiments run by Ahmed on 2026-11-20 (results reported by him; captures in `lab/`, git-ignored):
- `lab/01_ping/ping_gateway.pcapng`: ping to home gateway 192.168.1.254 (/24 Wi-Fi). 4 request/reply
  pairs, TTL 128 out (Windows) / 64 back (Linux box), 74-byte frames, first reply slow (~287 ms).
- `lab/02_web/web_dns_tracert.pcapng`: DNS (UDP/53), HTTP to example.com (handshake + clear-text page),
  HTTPS (TLS, SNI `example.com` visible), `tracert -d -h 6 1.1.1.1` (hops 2 and 5 silent, hop 6 Cloudflare).
  Also used for MAC/ARP (Ethernet II, `arp -a`) and UDP-vs-TCP reading.
- `lab/03_refused/refused_port.pcapng`: `curl 127.0.0.1:9999` on loopback -> SYN / RST,ACK (port scan basis).
- `netstat -ano` LISTENING/ESTABLISHED + `tasklist` to map a connection to its program.

Remaining in Phase 1: NAT explanation; optional short lab notes per experiment.
Next: Phase 2, packet analyzer (Ahmed writes the code, Claude guides).

## Phase 0 — Planning and environment setup (done 2026-11-20)

### Done
- Brief reviewed; MVP and phase completion criteria agreed (see below).
- Tools on the laptop checked (2026-11-20): Python 3.13.12, Git 2.56, Node 26.13, WSL2 Ubuntu 22.04
  (tcpdump, dig, ip, ss), Npcap present. Missing: Wireshark, nmap/traceroute in WSL, gh CLI.
  Docker Desktop 20.10.22 installed but old and not running.
- Repository skeleton: `pyproject.toml`, `src/netsentinel/` (version + CLI stub), smoke tests,
  `.gitignore`, README draft, `docs/architecture.md`, `docs/conventions.md`.

### Tests executed
- See the latest entry in "Test log".

- Wireshark 4.6.10 installed; first commit `db1e937`.

### Still open from Phase 0
- Create the GitHub repository (private until Phase 8).
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

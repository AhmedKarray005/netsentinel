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

Remaining in Phase 1: optional short lab notes per experiment (NAT explained 2026-11-20).

## Phase 2 — Packet analyzer (in progress, started 2026-11-20)
Done (uncommitted):
- `parsing/models.py` `PacketRecord`; `parsing/pcap_reader.py` `read_pcap` (streaming, pcap+pcapng,
  classification by the layer directly above IP so ICMP errors quoting TCP/UDP stay ICMP,
  DNS question names, `PcapReadError` for missing/invalid files). Scapy 2.8.0.
- `summary.py` `TrafficSummary` (counts, bytes, min/max/mean length, time range, rate, protocol mix,
  top src/dst IPs, top dst ports as `PROTO/port`, top DNS queries) and `netsentinel analyze FILE
  [--top N] [--json OUT]` (exit code 2 on bad input).
- Tests: synthetic 8-packet capture built in `tests/conftest.py`; parsing, summary and CLI tests.
Real-capture check: `ping_gateway.pcapng` = 28 867 packets (matches Wireshark), 8 ICMP, 6 ARP,
analyzed in ~5.8 s (~5 000 packets/s, Scapy is the bottleneck).
Committed by Ahmed as `4e470a9`.

## Phase 3 — Traffic flows (done 2026-11-20, uncommitted)
- `flows/models.py` `Flow` (client/server, fwd/bwd packets+bytes, TCP state ESTABLISHED / CLOSED /
  REJECTED / NO_REPLY / HALF_OPEN / MIDSTREAM); `flows/aggregator.py` `FlowAggregator`
  (bidirectional key, idle timeouts 60 s UDP/ICMP + 300 s TCP, new flow on SYN after close);
  `flows/stats.py` (flow report, top conversations, top talkers).
- `summary.py`: timeline (packets/bytes per bucket, peak). `analysis.py` `analyze_file`: one pass,
  summary + flows (to be reused by the API). CLI: `--idle-timeout`, `--tcp-idle-timeout`, `--bucket`;
  JSON is now `{"summary": ..., "flows": ...}`.
- Rules and limits documented in `docs/flows.md`.
- Real captures: `refused_port.pcapng` -> 1 TCP flow REJECTED (port 9999). `web_dns_tracert.pcapng`
  58 437 packets -> 1 063 flows (783 CLOSED, 49 MIDSTREAM, 45 ESTABLISHED, 17 HALF_OPEN, 1 NO_REPLY),
  ~10 s. TCP timeout 60 s -> 300 s removed 42 keep-alive splits. Most of the laptop's traffic is IPv6.
Committed by Ahmed as `5e2e890`.

## Phase 4 — Detection engine (done 2026-11-20; main work committed by Ahmed as `d6b3771`)
Live lab done: `lab/04_loopback_scan/scan.pcapng` -> NS-001 high (199 ports, 4.6 s);
`retry.pcapng` -> NS-003 low (15 failures). Fix after it (uncommitted): Windows SYN retry 0.5 s
after RST was counted as a new connection (29 failures for 15 attempts) -> `SYN_RETRY_SECONDS`
in `flows/aggregator.py` + 2 tests. Port 137 never seen in the scan capture (not investigated).
64 tests pass; 0 alerts on the 3 earlier lab captures; scenarios TP 4 / FP 0 / FN 1.
- `detection/`: `models.py` (Rule, Alert), `config.py` (defaults + TOML override with validation,
  `config/rules.example.toml`, CLI `--rules`), `windows.py` (sliding window, merged episodes),
  `rules.py` NS-001 port scan / NS-002 unsolicited traffic spike / NS-003 repeated failed
  connections, `engine.py`. `analysis.py` report now has `alerts`.
- `scenarios.py` + `evaluation.py`: `netsentinel make-scenarios DIR`, `netsentinel evaluate DIR`
  (7 labelled synthetic PCAPs, RFC 5737 addresses): TP 4, FP 0, FN 1 (slow scan, documented).
- NS-002 changed twice after measurements: counting all packets -> FP on bulk download scenario;
  excluding TCP ACK -> still FP on a real QUIC download in `ping_gateway.pcapng`; final rule =
  "receiver spoke first = solicited" + TCP ACK skip -> 0 alerts on all 3 lab captures. Also no
  baseline when capture < 10 buckets (else a capture of only the attack hides it).
- `lab/scenarios/loopback_test.py` (scan / retry, 127.0.0.1 hard-coded).
- Docs: `docs/detection.md` (logic, thresholds, FP/FN, measured results).
## Phase 5 — Backend and database (done 2026-11-20, uncommitted)
- `analysis.py`: `run_analysis` -> `AnalysisResult` (all flows + alerts); `analyze_file` unchanged.
- `storage/db.py`: sqlite3, tables analyses / flows / alerts (cascade delete), filtered and
  paginated queries with placeholders + sort whitelist.
- `api/`: `settings.py` (env vars), `uploads.py` (extension, size, magic number, random temp
  name, cleaned display name, sha256), `schemas.py` (Pydantic responses), `app.py` (health,
  rules, analyses CRUD, flows, alerts; CORS for the dashboard). CLI `netsentinel serve`
  (127.0.0.1 by default). Deps: fastapi, uvicorn, python-multipart; dev: httpx.
- Bug found by tests: Scapy left the file open when rejecting a truncated capture -> Windows
  could not delete the upload. `read_pcap` now opens the file itself.
- Live check: real `scan.pcapng` uploaded via curl -> 201 in 0.18 s, NS-001 high, 0 temp files.
- Docs: `docs/api.md`. 87 tests pass.
- Open: our own log lines are not shown under `serve` (Phase 7 logging); Starlette warns that
  TestClient + httpx is deprecated ("install httpx2"), not acted on.
Next: Phase 6 (React + TypeScript dashboard).

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
| 2026-11-20 | `pytest -q` (Phase 2) | 18 passed |
| 2026-11-20 | `netsentinel analyze lab/01_ping/ping_gateway.pcapng` | 28 867 packets, ~5.8 s |
| 2026-11-20 | `netsentinel analyze README.md` | clean error, exit code 2 |
| 2026-11-20 | `pytest -q` (Phase 3) | 33 passed |
| 2026-11-20 | `netsentinel analyze lab/02_web/web_dns_tracert.pcapng` | 1 063 flows, ~10 s |
| 2026-11-20 | `pytest -q` (Phase 4) | 62 passed (~16 s) |
| 2026-11-20 | `netsentinel evaluate` on 7 scenarios | TP 4, FP 0, FN 1 |
| 2026-11-20 | `netsentinel analyze` on the 3 lab captures | 0 alerts each |
| 2026-11-20 | `pytest -q` (Phase 5) | 87 passed (~20 s) |
| 2026-11-20 | `netsentinel serve` + curl upload of `scan.pcapng` | 201, 0.18 s, NS-001 high |

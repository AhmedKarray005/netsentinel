# Development conventions

## Environment

- Code runs on **Windows-native Python** (venv in `.venv/`). Scapy reads PCAP files on Windows
  without a capture driver.
- **WSL2 Ubuntu** is the network lab: generating and capturing traffic (`tcpdump`, `dig`, `ip`, `ss`).
- **Wireshark** (Windows) is used to inspect captures.
- **Docker** arrives in Phase 7.

## Code

- Python 3.12+, type hints, `ruff check .` clean before every commit.
- Every feature comes with tests. Detection rules need a positive test (alerts) **and** a
  negative test (normal traffic does not alert).
- Test fixtures are small and synthetic (built with Scapy in code) so expected numbers are exact.

## Git

- Small commits, imperative messages: `Add flow timeout handling`, `Fix DNS query parsing`.
- No packet captures in Git except reviewed fixtures under `tests/fixtures/`.
- `PROJECT_STATUS.md` is updated at the end of each phase.

## Lab safety boundaries

- Only traffic from machines and networks we own: this laptop, its WSL instance, and Docker
  networks created for the lab.
- Scan simulations target **only our own lab containers/namespaces**, never the campus network,
  home network devices we do not control, or any public/third-party host.
- Public sample PCAPs are read offline only, never replayed onto a network.
- No exploitation features, no malware execution.
- Packet payloads are not logged or stored by default; captures stay out of Git.

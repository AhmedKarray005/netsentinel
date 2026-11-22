# Detection engine

NetSentinel's rules raise **indicators**: patterns worth an analyst's look. An alert is never
proof of an attack, and the absence of alerts is never proof of safety.

The engine only sees packet **metadata** (IPs, ports, TCP flags, sizes, timing). It cannot see
inside encrypted traffic and cannot tell, for example, whether an SSH password was wrong:
that needs host logs.

## Alert format

Every alert has: `rule_id`, `rule_name`, `rule_description`, `mitre_attack` (closest ATT&CK
technique, a hint), `severity` (low / medium / high), `start` / `end` / `start_iso`,
`src_ip`, `dst_ip`, `dst_port`, a one-line `summary`, the `thresholds` that applied, and
`evidence` (the numbers behind the decision, so an analyst can verify it).

## Sliding window (`detection/windows.py`)

"Within any W seconds, did the count reach N?" Overlapping windows that all pass are merged
into **one episode**, so a 200-port scan gives one alert, not 181.

## Rules

Thresholds are in `config/rules.example.toml` (defaults) and can be overridden with
`--rules FILE`.

### NS-001 Port scan indicator (T1046 Network Service Discovery)

- **Logic:** per (source, destination) pair, count **distinct destination ports** (TCP and UDP
  flows started by the source) in a sliding window.
- **Fires:** >= 20 distinct ports within 60 s. Severity high from 100 ports.
- **Evidence:** distinct ports, peak in one window, attempts, failed attempts, TCP states,
  a sample of ports.
- **False positives:** vulnerability scanners and monitoring tools you run on purpose; some
  peer-to-peer or VoIP software; passive FTP. Browsing does not trigger it: many servers on
  the same port 443 is the opposite pattern.
- **False negatives:** slow scans (measured: 30 ports at 1 every 5 s is missed with the
  default window; a 300 s window catches it). Horizontal scans (one port across many hosts)
  and scans spread across many source IPs are not covered by this rule.

### NS-002 Traffic spike, unsolicited packets (T1498 Network Denial of Service, possible)

- **Logic:** per source, packets per 1 s bucket, counting only **unsolicited** packets:
  a packet is solicited (ignored) when its receiver already sent a packet in the same
  conversation (same protocol, IPs and ports, reversed), and TCP packets with ACK are
  ignored too.
- **Fires:** a bucket reaches max(1000 packets, 10 x the source's median packets per bucket over
  the capture, silent buckets counting as 0). If the capture is shorter than 10 buckets there
  is no reliable baseline and only the 1000 floor applies. Consecutive buckets = one alert.
  Severity high at >= 5000 packets per bucket.
- **Evidence:** peak, baseline, packets during the spike, number of intervals, top destinations.
- **Why "unsolicited":** the first version counted every packet. Measured on the labelled
  `bulk_download` scenario it raised a false alert (TCP download). After excluding TCP ACK
  packets, it still fired on a real QUIC (HTTP/3 over UDP 443) download in
  `lab/01_ping/ping_gateway.pcapng` (1 191 packets/s). The "receiver spoke first" rule fixed
  both: 0 alerts on the 3 lab captures.
- **False positives:** legitimate one-way UDP streams nobody requested in this capture
  (multicast video, syslog/NetFlow exporters, the start of a stream whose request was not captured).
- **False negatives:** floods inside a conversation the victim started, ACK floods,
  application-layer (HTTP) floods, slow low-rate floods under 1000 packets/s, attacks spread
  over many source IPs (each one under the threshold).

### NS-003 Repeated failed connections (T1110 Brute Force, possible / misconfiguration)

- **Logic:** per (source, destination IP, destination port), count TCP flows whose state is
  REJECTED, NO_REPLY or HALF_OPEN (see `docs/flows.md`) in a sliding window.
- **Fires:** >= 10 failures within 60 s. Severity medium from 50.
- **Evidence:** failed attempts, peak in one window, TCP states, distinct source ports.
- **False positives:** an application retrying a stopped service (database down, wrong port),
  a service restarting, a firewall blocking a legitimate client. In practice this rule finds
  misconfigurations at least as often as attacks.
- **False negatives:** brute force against an **open** service (e.g. SSH logins with wrong
  passwords): the TCP connections succeed, so they are not "failed" at network level.
  Detecting that needs authentication logs.
- **Overlap:** a SYN flood to one port also creates many unanswered SYNs, so NS-002 and
  NS-003 can both fire on it (tested).

## Measured results

### Labelled synthetic scenarios (`netsentinel make-scenarios DIR` then `netsentinel evaluate DIR`)

Packets are crafted in memory and written to PCAP files: nothing is sent on a network.
Addresses are RFC 5737 documentation ranges. Result on 2026-11-20 with default thresholds:

| Scenario | Truth | Detected | Result |
|---|---|---|---|
| normal_browsing (40 HTTPS sessions + DNS) | - | - | PASS |
| port_scan_connect (200 ports, 10 s) | NS-001 | NS-001 | PASS |
| port_scan_syn (100 ports, half-open) | NS-001 | NS-001 | PASS |
| slow_port_scan (30 ports, 1 every 5 s) | NS-001 | - | **FN** (known limit) |
| udp_flood (5000 packets in 1 s) | NS-002 | NS-002 | PASS |
| bulk_download (5 s at 1500 packets/s) | - | - | PASS |
| repeated_failed_connections (25 to port 5432) | NS-003 | NS-003 | PASS |

Totals: TP = 4, FP = 0, FN = 1. These scenarios were written by us together with the rules, so
they show the rules behave as designed, not real-world accuracy.

### Real traffic (own laptop, 2026-11-20)

`ping_gateway.pcapng` (28 867 packets), `web_dns_tracert.pcapng` (58 437) and
`refused_port.pcapng` (21): **0 alerts** after the NS-002 fix (1 false positive before it).

## Live lab test (own machine only)

`lab/scenarios/loopback_test.py` connects to ports 1-200 (`scan`) or 15 times to port 9999
(`retry`) on 127.0.0.1 only; the target is hard-coded. Capture on the loopback adapter, then
run `netsentinel analyze` on the capture.

Results on 2026-11-20 (captures in `lab/04_loopback_scan/`, not in Git):

| Capture | Expected | Got |
|---|---|---|
| `scan.pcapng` (660 packets) | NS-001 | **NS-001 high**: 199 distinct ports in 4.6 s, 198 refused + port 135 open (Windows RPC) |
| `retry.pcapng` (64 packets) | NS-003 | **NS-003 low**: 15 failed connections to 127.0.0.1:9999 in 21.1 s |

Discrepancies found and explained:
- First run counted 29 failures for 15 attempts (and 326 for the scan): Windows re-sends a
  refused SYN once, 0.5 s later, from the same source port. The flow aggregator treated it as a
  new connection. Fixed: a SYN within 3 s of a refused, never-established attempt on the same
  ports stays in the same flow (`SYN_RETRY_SECONDS`, tested).
- Port 137 (NetBIOS) never appears in the scan capture (199 ports, not 200): no packet was
  seen for it. Probably handled inside the Windows network stack; not investigated further.

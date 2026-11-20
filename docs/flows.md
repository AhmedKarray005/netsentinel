# How NetSentinel builds flows

## Packet vs flow

A **packet** is one unit on the wire. A **flow** is every packet of one conversation between
two endpoints, in both directions. A single HTTPS page load is ~10-4000 packets but **one** flow.
Detection rules reason about flows ("how many connections did this host try?"), not raw packets.

## Flow key

`(protocol, endpoint A, endpoint B)` where an endpoint is `(IP, port)`.
The two endpoints are **sorted**, so `A -> B` and `B -> A` give the same key and land in the same flow.
ICMP has no ports: port 0 is used in the key, so a ping and its reply form one flow per host pair.
ARP is not an IP conversation and is not turned into flows.

## Direction

- The **client** is the sender of the first packet seen in the flow; packets from it are
  *forward* (`packets_fwd`, `bytes_fwd`), packets to it are *backward*.
- Exception: if the first TCP packet seen is a SYN-ACK, the SYN was missed, so its sender is
  the **server**.

## When a flow ends

| Rule | Why |
|---|---|
| No packet for `idle_timeout` (UDP/ICMP, default 60 s) | UDP has no "close": silence is the only signal |
| No packet for `tcp_idle_timeout` (TCP, default 300 s) | Idle TCP connections send keep-alives every 1-2 min; a short timeout cuts one connection into pieces |
| A new SYN after the flow saw FIN from both sides or a RST | The same ports are being reused for a new connection |
| End of the capture | Remaining flows are closed as they are |

A late ACK after FIN/FIN does **not** start a new flow (only a SYN does).

Measured on `lab/02_web/web_dns_tracert.pcapng` (58 437 packets, 2026-11-20):
TCP timeout 60 s gave 1 105 flows, 91 of them MIDSTREAM. TCP timeout 300 s gave 1 063 flows,
49 MIDSTREAM. 42 connections had been split by keep-alive gaps.

## TCP state (from flags only)

| State | Seen | Typical meaning |
|---|---|---|
| ESTABLISHED | SYN, SYN-ACK, ACK | Connection open at capture end or timeout |
| CLOSED | handshake, then FIN both ways or RST | Normal finished connection |
| REJECTED | SYN then RST, no SYN-ACK | Port closed: nothing listens there (port-scan signal) |
| NO_REPLY | SYN only | Filtered by a firewall, host down, or capture ended too early |
| HALF_OPEN | SYN, SYN-ACK, no client ACK | Client gave up, or packet lost (SYN-scan signal) |
| MIDSTREAM | no SYN | Capture started after the connection opened |

## Rates and rankings

- `bytes_per_second` of a flow = total bytes / (last packet time - first packet time).
  `None` for single-packet flows (duration 0).
- Timeline: packets and bytes per fixed time bucket (default 1 s, `--bucket`); `peak` is the
  busiest bucket. Average rate = packets / capture duration.
- Top conversations: flows grouped by host pair (all ports and protocols), ranked by bytes.
- Top talkers: per host, bytes sent + received across all its flows.

## Limitations

- No TCP sequence-number tracking: retransmissions and out-of-order packets are counted as-is.
- IP fragments, tunnels (VPN, GRE) and IPv6 extension headers are not reassembled or unwrapped.
- No active timeout: a connection that never goes silent stays one flow for the whole capture.
- Direction is a guess when the capture starts mid-connection (the first packet seen wins).

"""The internal representation of one packet. Nothing after parsing uses Scapy."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PacketRecord:
    timestamp: float  # seconds since 1970-01-01 UTC (Unix time)
    length: int  # frame size in bytes, same as Wireshark's "Length" column
    protocol: str  # "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "OTHER_IP" or "OTHER"
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None  # only TCP and UDP have ports
    dst_port: int | None = None
    tcp_flags: str | None = None  # Scapy notation: "S" SYN, "SA" SYN-ACK, "RA" RST-ACK, "A" ACK
    dns_query: str | None = None  # queried name, only on DNS questions (not answers)

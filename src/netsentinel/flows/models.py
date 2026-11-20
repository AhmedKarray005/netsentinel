"""A flow = all packets of one conversation between two endpoints, in both directions."""

from dataclasses import dataclass
from typing import Any

# TCP states we can infer from packet metadata only (see docs/flows.md).
ESTABLISHED = "ESTABLISHED"  # handshake completed, connection still open at capture end / timeout
CLOSED = "CLOSED"  # handshake completed, then FIN from both sides or a RST
REJECTED = "REJECTED"  # SYN answered by RST: nothing listens on that port
NO_REPLY = "NO_REPLY"  # SYN never answered (filtered, host down, or capture ended)
HALF_OPEN = "HALF_OPEN"  # SYN and SYN-ACK seen, but never the client's final ACK
MIDSTREAM = "MIDSTREAM"  # capture started after the connection was opened (no SYN seen)


@dataclass
class Flow:
    protocol: str
    client_ip: str  # the side that started the conversation ("forward" direction)
    client_port: int | None
    server_ip: str
    server_port: int | None
    start: float
    end: float
    packets_fwd: int = 0  # client -> server
    packets_bwd: int = 0  # server -> client
    bytes_fwd: int = 0
    bytes_bwd: int = 0
    # TCP observations
    syn_seen: bool = False
    syn_ack_seen: bool = False
    handshake_done: bool = False
    fin_fwd: bool = False
    fin_bwd: bool = False
    rst_seen: bool = False

    @property
    def packets(self) -> int:
        return self.packets_fwd + self.packets_bwd

    @property
    def bytes(self) -> int:
        return self.bytes_fwd + self.bytes_bwd

    @property
    def duration(self) -> float:
        return self.end - self.start

    @property
    def is_closed(self) -> bool:
        return self.rst_seen or (self.fin_fwd and self.fin_bwd)

    @property
    def tcp_state(self) -> str | None:
        if self.protocol != "TCP":
            return None
        if self.handshake_done:
            return CLOSED if self.is_closed else ESTABLISHED
        if self.syn_seen and self.syn_ack_seen:
            return HALF_OPEN
        if self.syn_seen:
            return REJECTED if self.rst_seen else NO_REPLY
        return MIDSTREAM

    def to_dict(self) -> dict[str, Any]:
        duration = self.duration
        return {
            "protocol": self.protocol,
            "client": _endpoint(self.client_ip, self.client_port),
            "server": _endpoint(self.server_ip, self.server_port),
            "start": self.start,
            "end": self.end,
            "duration_seconds": round(duration, 6),
            "packets_fwd": self.packets_fwd,
            "packets_bwd": self.packets_bwd,
            "bytes_fwd": self.bytes_fwd,
            "bytes_bwd": self.bytes_bwd,
            "bytes_per_second": round(self.bytes / duration, 1) if duration > 0 else None,
            "tcp_state": self.tcp_state,
        }


def _endpoint(ip: str, port: int | None) -> str:
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"  # IPv6 needs brackets

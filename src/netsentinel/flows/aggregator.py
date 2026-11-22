"""Group PacketRecords into bidirectional flows, with idle timeout and TCP close handling."""

from netsentinel.flows.models import Flow
from netsentinel.parsing.models import PacketRecord

FLOW_PROTOCOLS = {"TCP", "UDP", "ICMP", "ICMPv6", "OTHER_IP"}  # ARP is not an IP conversation

FlowKey = tuple[str, tuple[str, int], tuple[str, int]]

SYN_RETRY_SECONDS = 3.0  # a SYN this soon after a refused attempt is an OS retry, same flow


def flow_key(record: PacketRecord) -> FlowKey:
    """Same key for both directions: (protocol, lower endpoint, higher endpoint).

    A -> B and B -> A must land in the same flow, so the two endpoints are sorted.
    Protocols without ports (ICMP) use port 0 in the key.
    """
    a = (record.src_ip, record.src_port or 0)
    b = (record.dst_ip, record.dst_port or 0)
    low, high = sorted([a, b])
    return (record.protocol, low, high)


def _is_syn(flags: str | None) -> bool:
    return flags is not None and "S" in flags and "A" not in flags


def _is_syn_ack(flags: str | None) -> bool:
    return flags is not None and "S" in flags and "A" in flags


class FlowAggregator:
    """Feed records one by one with add(), then call finish() to get every flow."""

    def __init__(self, idle_timeout: float = 60.0, tcp_idle_timeout: float = 300.0) -> None:
        # TCP connections can stay open but silent for minutes (keep-alives), so TCP gets a
        # longer timeout than UDP/ICMP. Defaults follow Zeek: 5 min TCP, 1 min others.
        self.idle_timeout = idle_timeout
        self.tcp_idle_timeout = tcp_idle_timeout
        self._active: dict[FlowKey, Flow] = {}
        self._finished: list[Flow] = []

    def add(self, record: PacketRecord) -> None:
        if record.protocol not in FLOW_PROTOCOLS or not record.src_ip or not record.dst_ip:
            return

        key = flow_key(record)
        flow = self._active.get(key)
        if flow is not None and self._starts_new_flow(flow, record):
            self._finished.append(self._active.pop(key))
            flow = None
        if flow is None:
            flow = self._new_flow(record)
            self._active[key] = flow
        self._update(flow, record)

    def finish(self) -> list[Flow]:
        """Close every flow still open and return all flows sorted by start time."""
        self._finished.extend(self._active.values())
        self._active.clear()
        return sorted(self._finished, key=lambda f: f.start)

    def _starts_new_flow(self, flow: Flow, record: PacketRecord) -> bool:
        timeout = self.tcp_idle_timeout if flow.protocol == "TCP" else self.idle_timeout
        if record.timestamp - flow.end > timeout:
            return True  # silence longer than the timeout: a new conversation
        if flow.protocol != "TCP" or not flow.is_closed or not _is_syn(record.tcp_flags):
            return False  # (a late ACK after FIN/FIN is NOT a new flow: only a SYN can split)
        # Windows re-sends a refused SYN once, ~0.5 s later, from the same port: that is the
        # same connection attempt, not a new one (seen in lab/04_loopback_scan, 2026-11-20).
        if not flow.handshake_done and record.timestamp - flow.end <= SYN_RETRY_SECONDS:
            return False
        # Otherwise a fresh SYN after the old connection closed = the ports are being reused.
        return True

    @staticmethod
    def _new_flow(record: PacketRecord) -> Flow:
        client = (record.src_ip, record.src_port)
        server = (record.dst_ip, record.dst_port)
        if record.protocol == "TCP" and _is_syn_ack(record.tcp_flags):
            # We missed the SYN: the sender of a SYN-ACK is the server.
            client, server = server, client
        return Flow(
            protocol=record.protocol,
            client_ip=client[0],
            client_port=client[1],
            server_ip=server[0],
            server_port=server[1],
            start=record.timestamp,
            end=record.timestamp,
        )

    @staticmethod
    def _update(flow: Flow, record: PacketRecord) -> None:
        forward = (record.src_ip, record.src_port) == (flow.client_ip, flow.client_port)
        if forward:
            flow.packets_fwd += 1
            flow.bytes_fwd += record.length
        else:
            flow.packets_bwd += 1
            flow.bytes_bwd += record.length
        flow.start = min(flow.start, record.timestamp)
        flow.end = max(flow.end, record.timestamp)

        flags = record.tcp_flags
        if record.protocol != "TCP" or flags is None:
            return
        if _is_syn(flags):
            flow.syn_seen = True
        elif _is_syn_ack(flags):
            flow.syn_ack_seen = True
        elif forward and "A" in flags and flow.syn_ack_seen:
            flow.handshake_done = True  # SYN -> SYN-ACK -> ACK
        if "F" in flags:
            if forward:
                flow.fin_fwd = True
            else:
                flow.fin_bwd = True
        if "R" in flags:
            flow.rst_seen = True

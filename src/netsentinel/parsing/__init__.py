"""PCAP parsing: turns raw packets into PacketRecord objects. Only this package imports Scapy."""

from netsentinel.parsing.models import PacketRecord
from netsentinel.parsing.pcap_reader import PcapReadError, read_pcap, to_record

__all__ = ["PacketRecord", "PcapReadError", "read_pcap", "to_record"]

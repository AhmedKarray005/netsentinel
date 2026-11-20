"""Command-line entry point: `netsentinel analyze capture.pcapng`."""

import argparse
import json
import sys
from pathlib import Path

from netsentinel import __version__
from netsentinel.analysis import analyze_file
from netsentinel.parsing import PcapReadError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="Analyze PCAP files and detect suspicious network patterns.",
    )
    parser.add_argument("--version", action="version", version=f"netsentinel {__version__}")
    commands = parser.add_subparsers(dest="command")

    analyze = commands.add_parser(
        "analyze", help="Print traffic and flow statistics for a capture."
    )
    analyze.add_argument("pcap", type=Path, help="Path to a .pcap or .pcapng file")
    analyze.add_argument("--top", type=int, default=10, help="Size of each ranking (default 10)")
    analyze.add_argument(
        "--idle-timeout", type=float, default=60.0,
        help="Seconds of silence that end a UDP/ICMP flow (default 60)",
    )  # fmt: skip
    analyze.add_argument(
        "--tcp-idle-timeout", type=float, default=300.0,
        help="Seconds of silence that end a TCP flow (default 300)",
    )  # fmt: skip
    analyze.add_argument(
        "--bucket", type=float, default=1.0,
        help="Timeline bucket size in seconds (default 1)",
    )  # fmt: skip
    analyze.add_argument("--json", type=Path, metavar="FILE", help="Also write the report as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    print(f"netsentinel {__version__} - use 'netsentinel analyze <file>' (see --help).")
    return 0


def _analyze(args: argparse.Namespace) -> int:
    try:
        report = analyze_file(
            args.pcap,
            top=args.top,
            idle_timeout=args.idle_timeout,
            tcp_idle_timeout=args.tcp_idle_timeout,
            bucket_seconds=args.bucket,
        )
    except PcapReadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(_format_summary(args.pcap, report["summary"]))
    print(_format_flows(report["flows"]))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.json}")
    return 0


def _ranking(title: str, items: dict) -> list[str]:
    return [f"\n{title}:"] + ([f"  {n:>8}  {name}" for name, n in items.items()] or ["  (none)"])


def _format_summary(pcap: Path, s: dict) -> str:
    length = s["packet_length"]
    peak = s["timeline"]["peak"]
    lines = [
        "=== PACKETS ===",
        f"File        : {pcap}",
        f"Packets     : {s['packet_count']}  ({s['total_bytes']} bytes)",
        f"Time range  : {s['start_time']} -> {s['end_time']}  ({s['duration_seconds']:.3f} s)",
        f"Avg rate    : {s['packets_per_second']} packets/s",
        f"Peak        : {peak['packets'] if peak else 0} packets in one "
        f"{s['timeline']['bucket_seconds']:g} s bucket at {peak['start'] if peak else '-'}",
        f"Length      : min {length['min']}  max {length['max']}  mean {length['mean']} bytes",
    ]
    lines += _ranking("Protocols", s["protocols"])
    lines += _ranking("Top source IPs", s["top_src_ips"])
    lines += _ranking("Top destination IPs", s["top_dst_ips"])
    lines += _ranking("Top destination ports", s["top_dst_ports"])
    lines += _ranking("Top DNS queries", s["top_dns_queries"])
    return "\n".join(lines)


def _format_flows(f: dict) -> str:
    lines = ["\n=== FLOWS ===", f"Flows       : {f['flow_count']}"]
    lines += _ranking("Flows by protocol", f["by_protocol"])
    lines += _ranking("TCP connection states", f["tcp_states"])
    lines.append("\nTop flows by bytes:")
    for flow in f["top_flows_by_bytes"]:
        lines.append(
            f"  {flow['protocol']:<6} {flow['client']:>28} -> {flow['server']:<28} "
            f"{flow['packets_fwd']:>6}/{flow['packets_bwd']:<6} pkts  "
            f"{flow['bytes_fwd'] + flow['bytes_bwd']:>10} B  "
            f"{flow['duration_seconds']:>8.1f} s  {flow['tcp_state'] or ''}"
        )
    lines.append("\nTop conversations (host pairs, all ports):")
    for c in f["top_conversations"]:
        hosts = " <-> ".join(c["hosts"])
        lines.append(f"  {hosts:<60} {c['flows']:>5} flows {c['bytes']:>12} B")
    lines.append("\nTop talkers (bytes sent + received):")
    for t in f["top_talkers"]:
        lines.append(
            f"  {t['host']:<40} {t['bytes']:>12} B  "
            f"(sent {t['bytes_sent']}, received {t['bytes_received']})"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())

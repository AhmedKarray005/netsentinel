"""Command-line entry point: `netsentinel analyze capture.pcapng`."""

import argparse
import json
import sys
from pathlib import Path

from netsentinel import __version__
from netsentinel.parsing import PcapReadError, read_pcap
from netsentinel.summary import summarize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="Analyze PCAP files and detect suspicious network patterns.",
    )
    parser.add_argument("--version", action="version", version=f"netsentinel {__version__}")
    commands = parser.add_subparsers(dest="command")

    analyze = commands.add_parser("analyze", help="Print traffic statistics for a capture file.")
    analyze.add_argument("pcap", type=Path, help="Path to a .pcap or .pcapng file")
    analyze.add_argument("--top", type=int, default=10, help="Size of each ranking (default 10)")
    analyze.add_argument("--json", type=Path, metavar="FILE", help="Also write the report as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return _analyze(args.pcap, args.top, args.json)
    print(f"netsentinel {__version__} - use 'netsentinel analyze <file>' (see --help).")
    return 0


def _analyze(pcap: Path, top: int, json_path: Path | None) -> int:
    try:
        report = summarize(read_pcap(pcap)).to_dict(top=top)
    except PcapReadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(_format_report(pcap, report))
    if json_path:
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report written to {json_path}")
    return 0


def _format_report(pcap: Path, r: dict) -> str:
    length = r["packet_length"]
    lines = [
        f"File        : {pcap}",
        f"Packets     : {r['packet_count']}  ({r['total_bytes']} bytes)",
        f"Time range  : {r['start_time']} -> {r['end_time']}  ({r['duration_seconds']:.3f} s)",
        f"Rate        : {r['packets_per_second']} packets/s",
        f"Length      : min {length['min']}  max {length['max']}  mean {length['mean']} bytes",
    ]
    for title, key in [
        ("Protocols", "protocols"),
        ("Top source IPs", "top_src_ips"),
        ("Top destination IPs", "top_dst_ips"),
        ("Top destination ports", "top_dst_ports"),
        ("Top DNS queries", "top_dns_queries"),
    ]:
        lines.append(f"\n{title}:")
        lines += [f"  {count:>8}  {name}" for name, count in r[key].items()] or ["  (none)"]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())

"""Command-line entry point. The `analyze` command arrives in Phase 2."""

import argparse

from netsentinel import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="Analyze PCAP files and detect suspicious network patterns.",
    )
    parser.add_argument("--version", action="version", version=f"netsentinel {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    print(f"netsentinel {__version__} - no commands yet (Phase 2 adds 'analyze').")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

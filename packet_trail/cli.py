"""Command-line analysis with the same parser and rules as the browser."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from packet_trail.analysis import analyze, conversations_csv
from packet_trail.parser import MAX_CAPTURE_BYTES, CaptureError


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a classic Ethernet PCAP without contacting any network."
    )
    parser.add_argument("capture", type=Path)
    parser.add_argument(
        "--format", choices=("json", "csv"), default="json", help="CSV exports directional conversations"
    )
    parser.add_argument("--output", "-o", type=Path, help="Write report to this path instead of stdout")
    args = parser.parse_args()
    try:
        with args.capture.open("rb") as capture_file:
            data = capture_file.read(MAX_CAPTURE_BYTES + 1)
        report = analyze(data, args.capture.name)
        content = conversations_csv(report) if args.format == "csv" else json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.write_text(content, encoding="utf-8")
        else:
            sys.stdout.write(content)
    except (OSError, CaptureError) as error:
        print(f"packet-trail: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

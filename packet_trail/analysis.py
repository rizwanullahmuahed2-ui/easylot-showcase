"""Aggregate capture metadata and explain small, explicit heuristics."""

from __future__ import annotations

import csv
import io
import math
from collections import Counter, defaultdict
from datetime import UTC, datetime

from packet_trail.parser import MAX_CAPTURE_BYTES, MAX_ISSUES, MAX_PACKETS, parse_capture

MAX_CONVERSATIONS = 500
SYN_MINIMUM = 20
SYN_FRACTION = 0.8
RATE_THRESHOLD = 100


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def analyze(data: bytes, name: str = "capture.pcap") -> dict:
    capture = parse_capture(data)
    packets = capture.packets
    timestamps = [packet.timestamp for packet in packets]
    first, last = (min(timestamps), max(timestamps)) if packets else (0, 0)
    protocol_stats: dict = defaultdict(lambda: {"packets": 0, "bytes": 0})
    conversations: dict = defaultdict(lambda: {"packets": 0, "bytes": 0, "syn_packets": 0})
    source_packets: Counter = Counter()
    source_syns: Counter = Counter()
    seconds: Counter = Counter()
    # At most 120 equal-width bins, even when a capture spans years.
    width = max(1, math.ceil((last - first) / 119))
    bins: dict = defaultdict(lambda: {"packets": 0, "bytes": 0, "syn_packets": 0})
    issues = []
    issue_count = 0
    for index, packet in enumerate(packets, 1):
        protocol_stats[packet.protocol]["packets"] += 1
        protocol_stats[packet.protocol]["bytes"] += packet.captured_bytes
        slot = int((packet.timestamp - first) // width)
        bins[slot]["packets"] += 1
        bins[slot]["bytes"] += packet.captured_bytes
        bins[slot]["syn_packets"] += int(packet.initial_syn)
        seconds[int(packet.timestamp)] += 1
        if packet.source and not packet.malformed:
            source_packets[packet.source] += 1
            source_syns[packet.source] += int(packet.initial_syn)
            key = (
                packet.source,
                packet.destination,
                packet.source_port,
                packet.destination_port,
                packet.protocol,
            )
            conversations[key]["packets"] += 1
            conversations[key]["bytes"] += packet.captured_bytes
            conversations[key]["syn_packets"] += int(packet.initial_syn)
        if packet.issue:
            issue_count += 1
            if len(issues) < MAX_ISSUES:
                issues.append({"packet_index": index, "reason": packet.issue})

    flags = []
    for source, count in source_syns.most_common():
        fraction = count / source_packets[source]
        if count >= SYN_MINIMUM and fraction >= SYN_FRACTION:
            flags.append(
                {
                    "id": f"syn-concentration-{source}",
                    "severity": "attention",
                    "title": "TCP SYN concentration",
                    "detail": f"{source} sent {count} initial SYN packets ({fraction:.0%} of its IPv4 packets). This can indicate connection retries, a workload test, or unwanted traffic; the capture alone cannot determine intent.",
                    "evidence": {
                        "source": source,
                        "initial_syn_packets": count,
                        "source_packets": source_packets[source],
                        "fraction": round(fraction, 4),
                        "minimum_syn_packets": SYN_MINIMUM,
                        "minimum_fraction": SYN_FRACTION,
                    },
                }
            )
    if seconds:
        peak_second, peak_count = max(seconds.items(), key=lambda item: item[1])
        if peak_count >= RATE_THRESHOLD:
            flags.append(
                {
                    "id": "packet-rate",
                    "severity": "attention",
                    "title": "Busy one-second interval",
                    "detail": f"{peak_count} packets share the UTC second beginning {_iso(peak_second)}. This is a fixed-volume heuristic, not an anomaly model or a link-capacity measurement.",
                    "evidence": {
                        "timestamp": _iso(peak_second),
                        "packets": peak_count,
                        "threshold_packets_per_second": RATE_THRESHOLD,
                    },
                }
            )
    rows = [
        {
            "source": key[0],
            "destination": key[1],
            "source_port": key[2],
            "destination_port": key[3],
            "protocol": key[4],
            **counts,
        }
        for key, counts in conversations.items()
    ]
    rows.sort(key=lambda row: (-row["packets"], row["source"], row["destination"], row["source_port"] or 0))
    return {
        "schema_version": 1,
        "name": name,
        "summary": {
            "packet_count": len(packets),
            "captured_bytes": sum(p.captured_bytes for p in packets),
            "wire_bytes": sum(p.wire_bytes for p in packets),
            "duration_seconds": round(last - first, 6),
            "first_seen": _iso(first) if packets else None,
            "last_seen": _iso(last) if packets else None,
            "ipv4_packets": sum(p.ipv4 for p in packets),
            "unsupported_packets": sum(p.unsupported for p in packets),
            "malformed_packets": sum(p.malformed for p in packets),
            "truncated_packets": sum(p.truncated for p in packets),
        },
        "protocols": [
            {"name": protocol, **counts}
            for protocol, counts in sorted(
                protocol_stats.items(), key=lambda item: (-item[1]["packets"], item[0])
            )
        ],
        "series": [
            {
                "timestamp": _iso(first + slot * width),
                **bins.get(slot, {"packets": 0, "bytes": 0, "syn_packets": 0}),
            }
            for slot in range(max(bins, default=-1) + 1)
        ],
        "series_interval_seconds": width,
        "conversations": rows[:MAX_CONVERSATIONS],
        "conversation_count": len(rows),
        "flags": flags,
        "issues": issues,
        "issue_count": issue_count,
        "limits": {
            "max_capture_bytes": MAX_CAPTURE_BYTES,
            "max_packets": MAX_PACKETS,
            "shown_conversations": MAX_CONVERSATIONS,
            "shown_issues": MAX_ISSUES,
            "timestamp_precision": capture.timestamp_precision,
            "snaplen": capture.snaplen,
        },
        "notes": [
            "Heuristic flags are review prompts, not intrusion verdicts.",
            "Conversations are directional IP/port tuples; payloads are not inspected or reassembled.",
            "Bytes refer to captured frame bytes unless explicitly marked as original wire bytes.",
            "Checksums are not verified; capture offload can affect recorded headers.",
        ],
    }


def conversations_csv(report: dict) -> str:
    output = io.StringIO(newline="")
    fields = [
        "source",
        "destination",
        "source_port",
        "destination_port",
        "protocol",
        "packets",
        "bytes",
        "syn_packets",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(report["conversations"])
    return output.getvalue()

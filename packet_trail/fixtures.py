"""Create deterministic PCAP files from bytes; this module never opens a socket."""

from __future__ import annotations

import argparse
import ipaddress
import struct
from pathlib import Path

BASE_TIME = 1_760_616_000  # Fixed UTC time, independent of the machine clock.


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_ipv4(source: str, destination: str, protocol: int, segment: bytes, ident: int = 1) -> bytes:
    src, dst = ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), ident, 0x4000, 64, protocol, 0, src, dst
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + segment


def tcp_frame(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    flags: int = 0x10,
    payload: bytes = b"",
    sequence: int = 1,
) -> bytes:
    segment = (
        struct.pack("!HHIIBBHHH", source_port, destination_port, sequence, 1, 0x50, flags, 64240, 0, 0)
        + payload
    )
    pseudo = ipaddress.IPv4Address(source).packed + ipaddress.IPv4Address(destination).packed
    pseudo += struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    return ethernet_ipv4(source, destination, 6, segment)


def udp_frame(
    source: str, destination: str, source_port: int, destination_port: int, payload: bytes
) -> bytes:
    # A zero UDP checksum is valid for IPv4.
    segment = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    return ethernet_ipv4(source, destination, 17, segment)


def encode_pcap(records: list[tuple[float, bytes]], endian: str = "<", nanoseconds: bool = False) -> bytes:
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    output = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1))
    scale = 1_000_000_000 if nanoseconds else 1_000_000
    for timestamp, frame in records:
        seconds = int(timestamp)
        fraction = min(scale - 1, round((timestamp - seconds) * scale))
        output.extend(struct.pack(endian + "IIII", seconds, fraction, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def normal_records() -> list[tuple[float, bytes]]:
    records = []
    client, server, resolver = "192.0.2.10", "198.51.100.20", "192.0.2.53"
    question = bytes.fromhex("000101000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
    for index in range(18):
        start = BASE_TIME + index * 1.1
        port = 50000 + index
        records.extend(
            [
                (start, udp_frame(client, resolver, 53000 + index, 53, question)),
                (
                    start + 0.02,
                    udp_frame(resolver, client, 53, 53000 + index, question[:2] + b"\x81\x80" + question[4:]),
                ),
                (start + 0.05, tcp_frame(client, server, port, 443, 0x02)),
                (start + 0.07, tcp_frame(server, client, 443, port, 0x12)),
                (start + 0.08, tcp_frame(client, server, port, 443, 0x10)),
                (start + 0.11, tcp_frame(client, server, port, 443, 0x18, b"demo application bytes" * 8)),
                (start + 0.15, tcp_frame(server, client, 443, port, 0x18, b"sample response bytes" * 30)),
                (start + 0.18, tcp_frame(client, server, port, 443, 0x11)),
            ]
        )
    return records


def build_normal_capture() -> bytes:
    return encode_pcap(normal_records())


def build_syn_burst_capture() -> bytes:
    records = normal_records()
    for index in range(240):
        records.append(
            (
                BASE_TIME + 8.1 + index * 0.002,
                tcp_frame("203.0.113.77", "198.51.100.20", 40000 + index, 443, 0x02),
            )
        )
    return encode_pcap(sorted(records, key=lambda item: item[0]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "samples")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for name, builder in (("normal", build_normal_capture), ("syn-burst", build_syn_burst_capture)):
        target = args.output / f"{name}.pcap"
        target.write_bytes(builder())
        print(f"Wrote {target} ({target.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()

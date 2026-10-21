"""A small, bounded classic-PCAP reader. No payloads leave this module."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_PACKET_BYTES = 262_144
MAX_PACKETS = 50_000
MAX_ISSUES = 100


class CaptureError(ValueError):
    """The capture container is invalid or outside supported bounds."""


@dataclass(frozen=True, slots=True)
class Packet:
    timestamp: float
    captured_bytes: int
    wire_bytes: int
    protocol: str
    source: str | None = None
    destination: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    initial_syn: bool = False
    ipv4: bool = False
    unsupported: bool = False
    malformed: bool = False
    truncated: bool = False
    issue: str | None = None


@dataclass(frozen=True, slots=True)
class Capture:
    packets: tuple[Packet, ...]
    timestamp_precision: str
    snaplen: int


def _decode_frame(frame: bytes, timestamp: float, wire_bytes: int) -> Packet:
    values: dict = {
        "timestamp": timestamp,
        "captured_bytes": len(frame),
        "wire_bytes": wire_bytes,
        "protocol": "Unknown",
        "truncated": len(frame) < wire_bytes,
    }

    def incomplete(reason: str) -> Packet:
        # Snaplen omissions are different from contradictory packet headers.
        return Packet(**values, malformed=not values["truncated"], issue=reason)

    def malformed(reason: str) -> Packet:
        return Packet(**values, malformed=True, issue=reason)

    if len(frame) < 14:
        return incomplete("Ethernet header is incomplete")
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    for _ in range(2):
        if ethertype not in (0x8100, 0x88A8):
            break
        if len(frame) < offset + 4:
            return incomplete("VLAN header is incomplete")
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ethertype != 0x0800:
        values["protocol"] = {0x0806: "ARP", 0x86DD: "IPv6 (unsupported)"}.get(
            ethertype, f"EtherType 0x{ethertype:04x}"
        )
        return Packet(**values, unsupported=True)

    values.update(protocol="IPv4", ipv4=True)
    if len(frame) < offset + 20:
        return incomplete("IPv4 header is incomplete")
    version_ihl, _, total_length, _, fragment, _, protocol = struct.unpack_from("!BBHHHBB", frame, offset)
    ihl = (version_ihl & 0x0F) * 4
    if version_ihl >> 4 != 4 or ihl < 20 or total_length < ihl:
        return malformed("Invalid IPv4 version, header length, or total length")
    if wire_bytes < offset + total_length:
        return malformed("IPv4 total length exceeds original frame length")
    if len(frame) < offset + ihl:
        return incomplete("IPv4 options are incomplete")
    values["source"] = str(ipaddress.IPv4Address(frame[offset + 12 : offset + 16]))
    values["destination"] = str(ipaddress.IPv4Address(frame[offset + 16 : offset + 20]))
    if fragment & 0x3FFF:
        values["protocol"] = "IPv4 fragment"
        return Packet(**values, unsupported=True, issue="Fragmented IPv4 is not reassembled")

    transport_start = offset + ihl
    transport_length = total_length - ihl
    available = min(len(frame) - transport_start, transport_length)
    if protocol == 6:
        values["protocol"] = "TCP"
        if transport_length < 20:
            return malformed("TCP segment is shorter than its minimum header")
        if available < 20:
            return incomplete("TCP header is incomplete")
        tcp_header_length = (frame[transport_start + 12] >> 4) * 4
        if tcp_header_length < 20 or tcp_header_length > transport_length:
            return malformed("Invalid TCP data offset")
        if available < tcp_header_length:
            return incomplete("TCP options are incomplete")
        source_port, destination_port = struct.unpack_from("!HH", frame, transport_start)
        flags = frame[transport_start + 13]
        values.update(
            source_port=source_port,
            destination_port=destination_port,
            initial_syn=bool(flags & 0x02 and not flags & 0x10),
        )
    elif protocol == 17:
        values["protocol"] = "UDP"
        if transport_length < 8:
            return malformed("UDP datagram is shorter than its minimum header")
        if available < 8:
            return incomplete("UDP header is incomplete")
        source_port, destination_port, udp_length = struct.unpack_from("!HHH", frame, transport_start)
        if udp_length < 8 or udp_length > transport_length:
            return malformed("Invalid UDP length")
        values.update(source_port=source_port, destination_port=destination_port)
    elif protocol == 1:
        values["protocol"] = "ICMP"
        if transport_length < 8:
            return malformed("ICMP message is shorter than its minimum header")
        if available < 8:
            return incomplete("ICMP header is incomplete")
    else:
        values["protocol"] = f"IPv4 protocol {protocol}"
        values["unsupported"] = True
    return Packet(**values)


def parse_capture(data: bytes) -> Capture:
    """Read Ethernet classic PCAP, rejecting broken containers before analysis.

    Per-frame problems are reported as evidence. A corrupt record boundary is a
    capture error because continuing could interpret payload bytes as records.
    """
    if len(data) > MAX_CAPTURE_BYTES:
        raise CaptureError("Capture exceeds the 8 MiB limit")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        raise CaptureError("PCAPNG is not supported; export classic Ethernet PCAP")
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000, "microseconds"),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000, "microseconds"),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000, "nanoseconds"),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000, "nanoseconds"),
    }
    if len(data) < 24:
        raise CaptureError("Capture is missing a complete 24-byte PCAP header")
    if data[:4] not in formats:
        raise CaptureError("Unknown capture format; classic PCAP is required")
    endian, scale, precision = formats[data[:4]]
    major, minor, _, _, snaplen, network = struct.unpack_from(endian + "HHiIII", data, 4)
    if (major, minor) != (2, 4):
        raise CaptureError("Only PCAP version 2.4 is supported")
    if network != 1:
        raise CaptureError("Only Ethernet link type 1 is supported")
    if not 1 <= snaplen <= MAX_PACKET_BYTES:
        raise CaptureError("PCAP snapshot length must be between 1 and 262144 bytes")
    packets: list[Packet] = []
    offset = 24
    while offset < len(data):
        if len(packets) >= MAX_PACKETS:
            raise CaptureError("Capture exceeds the 50000-packet limit")
        if len(data) - offset < 16:
            raise CaptureError(f"Record {len(packets) + 1} has an incomplete record header")
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if fraction >= scale:
            raise CaptureError(f"Record {len(packets) + 1} has an invalid timestamp fraction")
        if captured > snaplen or captured > MAX_PACKET_BYTES or captured > original:
            raise CaptureError(f"Record {len(packets) + 1} has inconsistent captured/original lengths")
        if original > MAX_PACKET_BYTES:
            raise CaptureError(f"Record {len(packets) + 1} exceeds the maximum original frame size")
        if len(data) - offset < captured:
            raise CaptureError(f"Record {len(packets) + 1} is cut off before its declared length")
        frame = data[offset : offset + captured]
        packets.append(_decode_frame(frame, seconds + fraction / scale, original))
        offset += captured
    return Capture(tuple(packets), precision, snaplen)

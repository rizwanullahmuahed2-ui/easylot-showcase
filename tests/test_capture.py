import json
import struct
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from packet_trail.analysis import analyze, conversations_csv
from packet_trail.app import app
from packet_trail.fixtures import (
    BASE_TIME,
    build_normal_capture,
    build_syn_burst_capture,
    encode_pcap,
    tcp_frame,
)
from packet_trail.parser import MAX_CAPTURE_BYTES, CaptureError, parse_capture


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nano", [False, True])
def test_container_byte_orders_and_timestamp_units(endian, nano):
    frame = tcp_frame("192.0.2.1", "198.51.100.2", 1234, 443, 0x02)
    capture = parse_capture(encode_pcap([(BASE_TIME + 0.125, frame)], endian, nano))
    packet = capture.packets[0]
    assert packet.source == "192.0.2.1"
    assert packet.destination_port == 443
    assert packet.initial_syn
    assert packet.timestamp == BASE_TIME + 0.125
    assert capture.timestamp_precision == ("nanoseconds" if nano else "microseconds")


def test_sample_counts_and_heuristic_evidence():
    normal = analyze(build_normal_capture())
    burst = analyze(build_syn_burst_capture())
    assert normal["summary"]["packet_count"] == 144
    assert normal["flags"] == []
    assert burst["summary"]["packet_count"] == 384
    assert len(burst["flags"]) == 2
    concentration = next(flag for flag in burst["flags"] if "source" in flag["evidence"])
    assert concentration["evidence"]["initial_syn_packets"] == 240
    assert concentration["evidence"]["fraction"] == 1
    assert sum(item["packets"] for item in burst["protocols"]) == 384
    assert sum(item["packets"] for item in burst["series"]) == 384
    assert sum(item["bytes"] for item in burst["series"]) == burst["summary"]["captured_bytes"]
    assert "source,destination" in conversations_csv(burst)


@pytest.mark.parametrize(
    "payload,match",
    [
        (b"", "header"),
        (b"\x0a\x0d\x0d\x0a" + bytes(24), "PCAPNG"),
        (bytes(24), "format"),
        (build_normal_capture()[:-1], "cut off"),
        (build_normal_capture()[:25], "record header"),
        (bytes(MAX_CAPTURE_BYTES + 1), "8 MiB"),
    ],
)
def test_broken_containers_fail_closed(payload, match):
    with pytest.raises(CaptureError, match=match):
        parse_capture(payload)


def test_record_lengths_cannot_read_past_container():
    payload = bytearray(build_normal_capture())
    struct.pack_into("<I", payload, 32, 999999)
    with pytest.raises(CaptureError, match="length"):
        parse_capture(bytes(payload))


def test_snaplen_truncation_is_distinct_from_malformed_frame():
    frame = tcp_frame("192.0.2.1", "198.51.100.2", 1234, 443)
    header = encode_pcap([])
    truncated = header + struct.pack("<IIII", BASE_TIME, 0, 24, len(frame)) + frame[:24]
    packet = parse_capture(truncated).packets[0]
    assert packet.truncated and not packet.malformed
    assert packet.issue == "IPv4 header is incomplete"
    malformed = parse_capture(encode_pcap([(BASE_TIME, b"bad")])).packets[0]
    assert malformed.malformed and not malformed.truncated


def test_fragments_are_counted_without_guessing_transport_ports():
    frame = bytearray(tcp_frame("192.0.2.1", "198.51.100.2", 1234, 443))
    struct.pack_into("!H", frame, 20, 0x2000)
    packet = parse_capture(encode_pcap([(BASE_TIME, bytes(frame))])).packets[0]
    assert packet.unsupported
    assert packet.source_port is None
    assert not packet.initial_syn


def test_empty_capture_and_sparse_time_range_are_bounded():
    assert analyze(encode_pcap([]))["summary"]["first_seen"] is None
    frame = tcp_frame("192.0.2.1", "198.51.100.2", 1234, 443)
    report = analyze(encode_pcap([(1, frame), (4_000_000_000, frame)]))
    assert len(report["series"]) <= 120


def test_http_upload_samples_and_validation():
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/health").json()["mode"] == "offline"
        assert client.get("/api/samples/not-a-sample/download").status_code == 404
        response = client.post("/api/analyze", files={"file": ("../../demo.pcap", build_syn_burst_capture())})
        assert response.status_code == 200
        assert response.json()["name"] == "demo.pcap"
        assert response.json()["summary"]["packet_count"] == 384
        assert response.headers["cache-control"] == "no-store"
        assert client.post("/api/analyze", files={"file": ("bad.pcap", b"bad")}).status_code == 422
        assert client.post("/api/analyze", json={}).status_code == 415
        assert (
            client.post("/api/analyze", files={"other": ("x.pcap", build_normal_capture())}).status_code
            == 400
        )
        assert (
            client.post("/api/analyze", files=[("file", ("a", b"x")), ("file", ("b", b"x"))]).status_code
            == 400
        )
        assert (
            client.post(
                "/api/analyze", content=b"", headers={"content-length": str(MAX_CAPTURE_BYTES + 100000)}
            ).status_code
            == 413
        )


def test_cli_exports_report_and_returns_nonzero_on_bad_input(tmp_path):
    capture = tmp_path / "sample.pcap"
    capture.write_bytes(build_normal_capture())
    result = subprocess.run(
        [sys.executable, "-m", "packet_trail", str(capture)], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["summary"]["packet_count"] == 144
    capture.write_bytes(b"bad")
    failed = subprocess.run(
        [sys.executable, "-m", "packet_trail", str(capture)], capture_output=True, text=True
    )
    assert failed.returncode == 2
    assert "PCAP" in failed.stderr


def test_packet_count_limit_is_enforced_before_unbounded_analysis():
    from packet_trail.parser import MAX_PACKETS

    frame = tcp_frame("192.0.2.1", "198.51.100.2", 1234, 443)
    payload = encode_pcap([(BASE_TIME, frame)] * (MAX_PACKETS + 1))
    with pytest.raises(CaptureError, match="50000-packet"):
        parse_capture(payload)


def test_actual_oversize_upload_is_rejected():
    with TestClient(app) as client:
        response = client.post("/api/analyze", files={"file": ("large.pcap", bytes(MAX_CAPTURE_BYTES + 1))})
        assert response.status_code == 413

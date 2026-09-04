"""Unit tests for M10 — attacker client pure logic (no network)."""

import base64

import pytest

import tools.attacker_client as atk
from exfiltrap import config


def decode_labels(qname: str) -> bytes:
    """Inverse of the attacker's encoding for roundtrip checks."""
    labels = qname.split(".")
    candidate = "".join(labels[:-2])  # drop tunnel.example
    candidate += "=" * (-len(candidate) % 8)
    return base64.b32decode(candidate.upper())


class TestEncodePayload:
    @pytest.mark.parametrize("size", [1, 5, 12, 55, 90, 2048])
    def test_roundtrip_various_sizes(self, size):
        payload = bytes(range(256))[:size]
        labels = atk.encode_payload(payload)
        joined = "".join(labels)
        joined += "=" * (-len(joined) % 8)
        assert base64.b32decode(joined) == payload

    def test_labels_are_dns_legal(self):
        payload = b"x" * 1000
        for label in atk.encode_payload(payload, chunk_chars=59):
            assert 1 <= len(label) <= 63
            assert "=" not in label

    def test_rejects_empty_payload(self):
        with pytest.raises(ValueError):
            atk.encode_payload(b"")

    def test_rejects_bad_chunk(self):
        with pytest.raises(ValueError):
            atk.encode_payload(b"abc", chunk_chars=64)


class TestBuildQueries:
    def test_packs_labels_in_order(self):
        queries = atk.build_queries(["l1", "l2", "l3", "l4", "l5"],
                                    labels_per_query=3)
        assert queries == [
            "l1.l2.l3.tunnel.example",
            "l4.l5.tunnel.example",
        ]

    def test_qname_length_limit(self):
        long_labels = ["a" * 60] * 4  # 4 x 61 chars + domain > 253
        with pytest.raises(ValueError):
            atk.build_queries(long_labels, labels_per_query=4)


class TestGenerateTraffic:
    def test_fast_counts_and_intervals(self):
        records = atk.generate_traffic("fast", b"payload" * 20, duration=10.0)
        assert len(records) == int(10.0 / config.FAST_QUERY_INTERVAL)
        stamps = [r.query.timestamp for r in records]
        assert stamps == sorted(stamps)
        assert all(b_i - a_i == pytest.approx(config.FAST_QUERY_INTERVAL)
                   for a_i, b_i in zip(stamps, stamps[1:]))

    def test_slow_drip_query_count_follows_interval(self):
        duration = 7200.0
        records = atk.generate_traffic("slow-drip", b"data" * 10, duration=duration)
        assert len(records) == int(duration / config.SLOW_DRIP_QUERY_INTERVAL)
        assert all(r.meta["mode"] == "slow-drip" for r in records)

    def test_all_malicious_and_decodable(self):
        payload = b"Z" * 500
        records = atk.generate_traffic("fast", payload, duration=5.0)
        assert all(r.is_malicious for r in records)
        # Each cycle carries a 4-byte random prefix, so the first query's
        # decoded chunk is prefix + payload[:bytes_per_query-4].
        first = decode_labels(records[0].query.qname)
        assert len(first) == config.FAST_BYTES_PER_QUERY
        assert first[4:] == payload[: config.FAST_BYTES_PER_QUERY - 4]

    def test_deterministic_given_seed(self):
        args = ("fast", b"same payload", 30.0)
        a = atk.generate_traffic(*args, seed=1)
        b = atk.generate_traffic(*args, seed=1)
        c = atk.generate_traffic(*args, seed=2)
        assert [r.query.qname for r in a] == [r.query.qname for r in b]
        assert [r.query.qname for r in a] != [r.query.qname for r in c]

    def test_payload_cycles_when_duration_demands_more(self):
        tiny = b"0123456789"  # 10 bytes -> few chunks per cycle
        records = atk.generate_traffic("slow-drip", tiny, duration=7200.0)
        assert len(records) == int(7200.0 / config.SLOW_DRIP_QUERY_INTERVAL)
        cycles = {r.meta["cycle"] for r in records}
        assert len(cycles) > 1  # payload had to repeat

    def test_unknown_mode_raises(self):
        with pytest.raises(ValueError):
            atk.generate_traffic("spray", b"x", 10.0)

    def test_virtual_timestamps_start_at_zero(self):
        records = atk.generate_traffic("slow-drip", b"x" * 20, duration=130.0)
        assert records[0].query.timestamp == 0.0
        assert records[-1].query.timestamp == pytest.approx(
            config.SLOW_DRIP_QUERY_INTERVAL)


class TestLabSafety:
    def test_refuses_public_target(self, capsys):
        with pytest.raises(SystemExit) as exc:
            atk._validate_lab_target("8.8.8.8")
        assert exc.value.code == 2

    def test_accepts_lab_targets(self):
        atk._validate_lab_target("10.99.0.1")
        atk._validate_lab_target("192.168.1.1")
        atk._validate_lab_target("127.0.0.1")

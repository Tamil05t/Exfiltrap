"""Integration tests — full pipeline over synthetic query streams.

Uses a deterministic stub classifier (no trained artifact needed) to verify
the M2 -> M5 -> M3 -> M6 -> M7 -> M8/M9 wiring behaves as designed:

* benign streams stay LOW,
* fast tunneling is CONFIRMED via payload decode,
* slow-drip (RF probability deliberately below the decode trigger) is still
  caught HIGH by the stateful session tracker,
* the RF-only control run misses the slow drip — exactly the gap the
  stateful modules close.
"""

import base64

from exfiltrap.events import DNSQuery
from exfiltrap.pipeline import ExfilTrapPipeline
from exfiltrap.storage import NullStorage


def b32(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=")


class StubClassifier:
    """Deterministic RF stand-in.

    Fast tunneling (long, high-entropy labels) -> 0.95.
    Slow drip (20-char labels) -> 0.45 (below the 0.5 decode trigger).
    Benign -> 0.02.
    """

    def predict_proba(self, features) -> float:
        if features.entropy > 4.2 and features.length > 40:
            return 0.95
        if features.entropy > 3.8:  # 20-char base32 labels of mixed data
            return 0.45
        return 0.02


def make_pipeline(**kwargs) -> ExfilTrapPipeline:
    kwargs.setdefault("classifier", StubClassifier())
    kwargs.setdefault("storage", NullStorage())
    return ExfilTrapPipeline(**kwargs)


def benign_queries(n=200, start=0.0, src="10.99.0.2"):
    import random

    rng = random.Random(99)
    names = ["www.google.com", "api.cloudflare.com", "cdn.jsdelivr.net",
             "mail.proton.me", "static.example.org"]
    out = []
    t = start
    for i in range(n):
        # Bursty Poisson-like arrivals — real resolvers are not metronomes
        # (perfectly periodic benign traffic WOULD trip the beacon detector).
        t += rng.expovariate(1.0 / 5.0)
        out.append(DNSQuery(src_ip=src, qname=names[i % len(names)],
                            timestamp=t))
    return out


def fast_queries(n=30, start=1000.0, src="10.99.0.9"):
    payload = b"fast-mode exfiltration payload " * 4  # 124 bytes -> 199 b32 chars
    encoded = b32(payload)
    # Split at DNS-legal label boundaries; the decoder re-joins all labels
    # before re-adding stripped padding, so concatenation must be the full
    # encoding (never truncate base32 mid-stream).
    labels = [encoded[i:i + 63] for i in range(0, len(encoded), 63)]
    qname = ".".join(labels) + ".tunnel.example"
    return [
        DNSQuery(src_ip=src, qname=qname, timestamp=start + i * 0.05)
        for i in range(n)
    ]


def slow_drip_queries(n=60, start=2000.0, src="10.99.0.5"):
    # 12 raw NON-printable bytes -> 20 base32 chars. Non-printable on purpose:
    # when M6 is triggered it must NOT confirm, isolating the M3 slow-drip
    # path under test.
    out = []
    for i in range(n):
        chunk = bytes([0x80 + (i * 7 + k * 3) % 0x60 for k in range(12)])
        out.append(DNSQuery(src_ip=src, qname=f"{b32(chunk)}.tunnel.example",
                            timestamp=start + i * 30.0))
    return out


class TestFullPipeline:
    def test_benign_stream_stays_low(self):
        p = make_pipeline()
        results = p.run_synthetic(benign_queries(150))
        assert all(a.risk_level == "LOW" for a in results)

    def test_fast_tunnel_confirmed_with_decoded_payload(self):
        p = make_pipeline()
        results = p.run_synthetic(fast_queries())
        assert results[-1].risk_level == "CONFIRMED"
        assert results[-1].confirmed_exfiltration
        assert results[-1].decoded_preview is not None

    def test_slow_drip_caught_by_stateful_tracker(self):
        # RF probability 0.45 < decode trigger 0.5, so only M3's accumulated
        # entropy-weighted mass can flag this source.
        p = make_pipeline()
        p.run_synthetic(benign_queries(150))  # warm the baseline with normal traffic
        results = p.run_synthetic(slow_drip_queries(60))
        levels = [a.risk_level for a in results]
        assert levels[0] == "LOW"  # min_queries guard: first query can't flag
        escalated = [i for i, l in enumerate(levels) if l in ("HIGH", "CONFIRMED")]
        assert escalated, f"slow drip never escalated: {set(levels)}"
        # Once flagged it stays flagged (mass keeps accumulating in-window).
        assert levels[-1] in ("HIGH", "CONFIRMED")
        # Payloads are non-printable: M6 must NOT have confirmed these.
        assert levels[-1] == "HIGH"

    def test_rf_only_control_misses_slow_drip(self):
        full = make_pipeline()
        control = make_pipeline(rf_only=True)
        # The baseline needs a normal population before the drip starts —
        # identical benign warmup for both pipelines.
        drip = slow_drip_queries(60)
        full.run_synthetic(benign_queries(150))
        control.run_synthetic(benign_queries(150))
        full_levels = [a.risk_level for a in full.run_synthetic(drip)]
        control_levels = [a.risk_level for a in control.run_synthetic(drip)]
        # Control sees only P=0.45 < 0.5 -> LOW everywhere.
        assert control_levels == ["LOW"] * len(drip)
        # While the full pipeline escalates (stateful contribution > 0).
        assert any(l in ("HIGH", "CONFIRMED") for l in full_levels)

    def test_rf_only_flags_fast(self):
        control = make_pipeline(rf_only=True)
        results = control.run_synthetic(fast_queries())
        assert all(a.risk_level == "HIGH" for a in results)

    def test_storage_records_events_and_blocks(self, tmp_path):
        from exfiltrap.storage import Storage

        store = Storage(tmp_path / "it.sqlite3")
        p = make_pipeline(storage=store)
        p.run_synthetic(fast_queries())
        totals = store.totals()
        assert totals["queries"] == 30
        assert totals["flagged"] == 30
        assert totals["confirmed"] >= 1
        assert totals["blocked"] == 1  # the fast-tunnel source got blocked
        events = store.recent_events(5)
        assert any(e["confirmed"] for e in events)
        store.close()

    def test_mitigation_notified_only_for_high_risk(self):
        from exfiltrap.mitigation import LogOnlyMitigation

        mit = LogOnlyMitigation()
        p = make_pipeline(mitigation=mit)
        p.run_synthetic(benign_queries(20))
        assert mit.blocked_ips == set()
        p.run_synthetic(fast_queries())
        assert mit.blocked_ips == {"10.99.0.9"}

    def test_mitigation_failure_never_kills_detection(self):
        class ExplodingMitigation:
            def notify(self, assessment):
                raise RuntimeError("safety refusal or dead binary")

        p = make_pipeline(mitigation=ExplodingMitigation())
        results = p.run_synthetic(fast_queries())
        # Every query still got a full assessment; the loop survived.
        assert len(results) == 30
        assert results[-1].risk_level == "CONFIRMED"

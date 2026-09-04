"""ExfilTrap pipeline — wires M1..M8 into one detector.

Two run modes:

* **live** — M1 scapy capture on an interface (``--iface veth-gw`` inside
  namespace nsA in the lab) feeding the processing loop from a queue.
* **synthetic** — an in-process stream of :class:`~exfiltrap.events.DNSQuery`
  records with virtual timestamps. Same detection code path, no root and no
  network required; this is what the evaluation harness (M11) drives.

``rf_only=True`` disables M3/M6/M7 and flags on the raw RF probability
alone — the control run that isolates this project's stateful contribution
from the base paper's RF-only method.
"""

from __future__ import annotations

import argparse
import logging
import queue
import threading
import time
from typing import Iterable

from exfiltrap import config
from exfiltrap.baseline_engine import BaselineEngine
from exfiltrap.classifier import DNSClassifier
from exfiltrap.events import DNSQuery, DNSResponse, LabeledQuery
from exfiltrap.features import FeatureExtractor
from exfiltrap.mitigation import LogOnlyMitigation
from exfiltrap.payload_decoder import decode_query_payload
from exfiltrap.risk_engine import RiskAssessment, RiskEngine
from exfiltrap.session_tracker import SessionTracker
from exfiltrap.storage import NullStorage, Storage

log = logging.getLogger("exfiltrap")


class ExfilTrapPipeline:
    """The full detection chain for one deployment/run."""

    def __init__(
        self,
        rf_only: bool = False,
        classifier_path=None,
        classifier=None,
        mitigation=None,
        storage=None,
        extractor: FeatureExtractor | None = None,
        baseline: BaselineEngine | None = None,
        tracker: SessionTracker | None = None,
        risk_engine: RiskEngine | None = None,
        alerter=None,
    ):
        self.rf_only = rf_only
        self.classifier = (
            classifier if classifier is not None else DNSClassifier.load(classifier_path)
        )
        self.mitigation = mitigation if mitigation is not None else LogOnlyMitigation()
        self.storage = storage if storage is not None else NullStorage()
        self.extractor = extractor if extractor is not None else FeatureExtractor()
        self.baseline = baseline if baseline is not None else BaselineEngine()
        self.tracker = (
            tracker if tracker is not None else SessionTracker(baseline=self.baseline)
        )
        self.risk_engine = risk_engine if risk_engine is not None else RiskEngine()
        self.alerter = alerter
        self._index = 0

    # ------------------------------------------------------------------
    def process_query(self, q: DNSQuery) -> RiskAssessment:
        """Full chain for one query: M2 -> M5 -> M3 -> M6 -> M7 -> M8/M9."""
        features = self.extractor.extract(q.qname, q.timestamp)
        prob = self.classifier.predict_proba(features)
        return self._decide(q, features, prob)

    def process_response(self, resp) -> object | None:
        """Download/C2 channel: heavy high-entropy answers per session.

        Responses are NOT inserted into the queries table (that would skew
        per-query metrics); a flagged response becomes a risk event + alert.
        """
        state = self.tracker.update_response(
            resp.client_ip, resp.timestamp,
            resp.answer_bytes, resp.answer_entropy)
        if not state.resp_flag or self.rf_only:
            return None
        from exfiltrap.risk_engine import RiskAssessment

        self._index += 1
        assessment = RiskAssessment(
            src_ip=resp.client_ip, qname=resp.qname,
            timestamp=resp.timestamp, risk_level="HIGH",
            reasons=[f"response channel: answer mass "
                     f"{state.resp_answer_bytes}B in window, "
                     "entropy-weighted z above baseline"],
            rf_probability=0.0, query_index=self._index)
        self.storage.log_risk_event(assessment)
        if self.alerter is not None:
            self.alerter.send(assessment)
        log.info("RESPONSE-channel flag for %s: %dB answers on %s",
                 resp.client_ip, state.resp_answer_bytes, resp.qname)
        return assessment

    def process_many(self, events: list[DNSQuery]) -> list[RiskAssessment]:
        """Batched live path: identical decisions to process_query, but all
        RF probabilities are computed in one vectorized call — ~8x the
        sustained query rate of per-row scoring (17 -> ~130 q/s here)."""
        vectors = [self.extractor.extract(q.qname, q.timestamp) for q in events]
        rows = [[v.entropy, v.length, v.subdomain_count, v.frequency]
                for v in vectors]
        batch = getattr(self.classifier, "predict_proba_many", None)
        probs = (batch(rows) if batch is not None
                 else [self.classifier.predict_proba(v) for v in vectors])
        return [self._decide(q, v, p)
                for q, v, p in zip(events, vectors, probs)]

    def _decide(self, q: DNSQuery, features, prob: float) -> RiskAssessment:
        """Stateful decision chain given precomputed features + probability."""
        self._index += 1
        if self.rf_only:
            return self._process_rf_only(q, prob)

        estimated_bytes = len(features.leftmost_label) * config.BASE32_BITS_PER_CHAR
        state = self.tracker.update(
            q.src_ip, q.timestamp, estimated_bytes, features.entropy
        )

        decode_result = None
        if (prob > config.RF_DECODE_TRIGGER_THRESHOLD
                or state.slow_drip_candidate or state.beacon_candidate):
            decode_result = decode_query_payload(q.qname)

        assessment = self.risk_engine.assess(
            q, prob, state.slow_drip_candidate, decode_result,
            query_index=self._index,
            beacon_candidate=state.beacon_candidate,
        )

        self.storage.log_query(assessment)
        if assessment.risk_level in ("HIGH", "CONFIRMED"):
            self.storage.log_risk_event(assessment)
            if self.alerter is not None:
                self.alerter.send(assessment)
            # A mitigation failure (safety refusal, missing binary, hung
            # subprocess) must NEVER take down the detection loop: log it
            # and keep detecting.
            try:
                already = getattr(self.mitigation, "is_blocked", None)
                if self.mitigation.notify(assessment):
                    self.storage.log_block(q.timestamp, q.src_ip,
                                           assessment.risk_level)
                elif already is not None and already(q.src_ip):
                    pass  # duplicate: block already in place, by design
                else:
                    log.error("mitigation REFUSED block for %s (risk=%s) — "
                              "check backend errors/allowlist",
                              q.src_ip, assessment.risk_level)
            except Exception as exc:  # noqa: BLE001 — resilience boundary
                log.error("mitigation failed for %s: %s", q.src_ip, exc)
            if assessment.confirmed_exfiltration:
                log.info(
                    "CONFIRMED exfil from %s: %s decoded=%s",
                    q.src_ip, q.qname, assessment.decoded_preview,
                )
        return assessment

    def _process_rf_only(self, q: DNSQuery, prob: float) -> RiskAssessment:
        """Control run: RF probability is the whole decision (M3/M6/M7 off)."""
        level = "HIGH" if prob > config.RF_DECODE_TRIGGER_THRESHOLD else "LOW"
        assessment = RiskAssessment(
            src_ip=q.src_ip,
            qname=q.qname,
            timestamp=q.timestamp,
            risk_level=level,
            reasons=[f"RF-only control: P(malicious)={prob:.3f}"],
            rf_probability=prob,
            query_index=self._index,
        )
        self.storage.log_query(assessment)
        return assessment

    # ------------------------------------------------------------------
    def run_synthetic(
        self, records: Iterable[DNSQuery | LabeledQuery]
    ) -> list[RiskAssessment]:
        """Process a pre-generated (virtual-timestamp) query stream.

        Features are extracted sequentially (the frequency window is
        stateful), then all RF probabilities are computed in ONE vectorized
        batch — same features, same model, same decision chain as
        :meth:`process_query`, just without per-row sklearn dispatch
        overhead (which dominates single-row calls by ~30x).
        """
        recs = [r.query if isinstance(r, LabeledQuery) else r for r in records]
        return self.process_many(recs)

    def run_live(self, iface: str, duration: float | None = None) -> None:
        """M1 live capture loop: sniff ``iface``, process every DNS query."""
        import exfiltrap.capture as capture  # scapy needed only for live runs

        out_queue: queue.Queue = queue.Queue()
        stop_event = threading.Event()
        sniffer = capture.make_sniffer(iface, out_queue)
        worker = threading.Thread(
            target=capture.drain_loop,
            args=(out_queue, self.process_query, stop_event),
            daemon=True,
        )
        sniffer.start()
        worker.start()
        log.info("capturing on %s (filter: %s)", iface, config.CAPTURE_BPF_FILTER)
        try:
            if duration is not None:
                time.sleep(duration)
            else:
                while sniffer.running:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            log.info("interrupted")
        finally:
            sniffer.stop()
            stop_event.set()
            worker.join(timeout=3.0)
            log.info("capture stopped after %d queries", self._index)


# ----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m exfiltrap.pipeline",
        description="ExfilTrap DNS exfiltration detector",
    )
    parser.add_argument("--iface", help="interface to capture (e.g. veth-gw inside nsA)")
    parser.add_argument("--rf-only", action="store_true",
                        help="control run: RF probability only, M3/M6/M7 disabled")
    parser.add_argument("--mitigation", choices=("log", "iptables"), default="log",
                        help="log: record blocks only; iptables: apply DROP rules")
    parser.add_argument("--i-know-this-is-isolated", action="store_true",
                        help="explicit override required for any host-firewall path")
    parser.add_argument("--execute-iptables", action="store_true",
                        help="actually execute iptables commands (default: dry-run)")
    parser.add_argument("--duration", type=float, default=None,
                        help="stop after N seconds (live mode)")
    parser.add_argument("--db", default=None, help="SQLite path (default: data/exfiltrap.db)")
    parser.add_argument("--no-db", action="store_true", help="disable persistence")
    parser.add_argument("--classifier", default=None, help="model path override")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.no_db:
        storage = NullStorage()
    else:
        storage = Storage(args.db)

    mitigation = None
    if args.mitigation == "iptables":
        from exfiltrap.mitigation import IptablesMitigation

        mitigation = IptablesMitigation(
            dry_run=not args.execute_iptables,
            override_flag=(
                config.IPTABLES_OVERRIDE_FLAG
                if args.i_know_this_is_isolated else ""
            ),
        )

    pipeline = ExfilTrapPipeline(
        rf_only=args.rf_only,
        classifier_path=args.classifier,
        mitigation=mitigation,
        storage=storage,
    )

    if args.iface:
        pipeline.run_live(args.iface, duration=args.duration)
    else:
        parser.error("--iface is required for live mode; "
                     "use eval/run_evaluation.py for the synthetic pipeline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

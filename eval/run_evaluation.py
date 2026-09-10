#!/usr/bin/env python3
"""M11 — evaluation harness.

Runs the REAL detection pipeline over REAL generated traffic streams and
computes the spec's metrics from the actual outcomes — nothing here is
hardcoded or simulated.

Default mode is **synthetic/in-process**: the same generators and the same
pipeline as the live deployment, driven with virtual timestamps (a 2-hour
slow-drip profile executes in seconds). ``--live`` prints the manual
namespace-based procedure instead of pretending to orchestrate root.

# ASSUMPTION: attack profiles mix benign background traffic with the
# attacker stream — the confusion matrix needs true negatives to compute
# accuracy and FPR at all, and a monitoring vantage point always sees
# ordinary resolver traffic alongside any tunnel.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from exfiltrap import config  # noqa: E402
from exfiltrap.classifier import DNSClassifier  # noqa: E402
from exfiltrap.events import LabeledQuery  # noqa: E402
from exfiltrap.pipeline import ExfilTrapPipeline  # noqa: E402
from exfiltrap.storage import NullStorage  # noqa: E402

_TOOLS = Path(__file__).resolve().parent.parent / "tools"


def _import_tool(name: str):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


attacker = _import_tool("attacker_client")
benign_gen = _import_tool("benign_traffic_gen")

FLAGGED_LEVELS = ("HIGH", "CONFIRMED")

# Benign background runs on distinct lab client IPs: session accounting is
# per-source, and a compromised host must be judged against the normal
# population, not blended into it. # ASSUMPTION: 5 background clients.
BENIGN_CLIENT_IPS = tuple(f"10.99.0.{i}" for i in range(51, 56))

# Fixed seeds per profile: reproducible, identical streams for the
# full-pipeline run and the RF-only control run (fair comparison).
PROFILES = {
    "fast": {"duration": 600.0, "attack": "fast", "attack_seed": 1337},
    "slow-drip": {"duration": 7200.0, "attack": "slow-drip", "attack_seed": 1338},
    "benign": {"duration": 7200.0, "attack": None, "attack_seed": None},
}
BENIGN_QPS = config.BENIGN_BASE_QPS
BENIGN_SEED = config.BENIGN_RANDOM_SEED
# Same payload family as training (mixed text+binary pseudo-documents);
# distinct seed so the eval document itself is unseen during training.
ATTACK_PAYLOAD = attacker.make_sample_payload(seed=999, size=3072)


# ----------------------------------------------------------------------
# Pure metric helpers (unit-tested in tests/test_eval_metrics.py)
# ----------------------------------------------------------------------
def confusion(pairs: list[tuple[bool, bool]]) -> tuple[int, int, int, int]:
    """(is_malicious, flagged) pairs -> (tp, tn, fp, fn)."""
    tp = tn = fp = fn = 0
    for is_mal, flagged in pairs:
        if is_mal and flagged:
            tp += 1
        elif not is_mal and flagged:
            fp += 1
        elif not is_mal and not flagged:
            tn += 1
        else:
            fn += 1
    return tp, tn, fp, fn


def compute_metrics(tp: int, tn: int, fp: int, fn: int) -> dict:
    """Spec Section 9 formulas; zero-divisions evaluate to 0.0."""
    total = tp + tn + fp + fn
    return {
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
    }


def detection_latency(pairs: list[tuple[float, bool, bool]],
                      attack_start: float) -> float | None:
    """(timestamp, is_malicious, flagged) -> t_first_flag - attack_start."""
    for ts, is_mal, flagged in pairs:
        if is_mal and flagged:
            return ts - attack_start
    return None


# ----------------------------------------------------------------------
# Profile execution
# ----------------------------------------------------------------------
def build_stream(profile: str, slow_drip_duration: float | None = None,
                 benign_seed: int | None = None,
                 attack_seed: int | None = None,
                 payload_seed: int | None = None) -> list[LabeledQuery]:
    """Deterministic merged (benign [+ attack]) stream for one profile.

    Seed overrides exist for --multiseed: every trial rolls fresh seeds so
    the statistics are computed over genuinely different traffic, while the
    full-pipeline run and its RF-only control within one trial always see
    the IDENTICAL stream (fair paired comparison).
    """
    spec = PROFILES[profile]
    duration = slow_drip_duration if (profile == "slow-drip"
                                      and slow_drip_duration) else spec["duration"]
    stream = benign_gen.generate_traffic(
        duration=duration, qps=BENIGN_QPS,
        seed=BENIGN_SEED if benign_seed is None else benign_seed,
        src_ip=config.ATTACKER_IP,
    )
    # Spread the benign background across distinct client IPs.
    stream = [
        replace(rec, query=replace(rec.query, src_ip=BENIGN_CLIENT_IPS[i % len(BENIGN_CLIENT_IPS)]))
        for i, rec in enumerate(stream)
    ]
    if spec["attack"]:
        payload = (ATTACK_PAYLOAD if payload_seed is None
                   else attacker.make_sample_payload(seed=payload_seed,
                                                     size=3072))
        stream += attacker.generate_traffic(
            spec["attack"], payload, duration=duration,
            seed=spec["attack_seed"] if attack_seed is None else attack_seed,
            src_ip=config.ATTACKER_IP,
        )
    stream.sort(key=lambda r: r.query.timestamp)
    return stream


def run_profile(profile: str, rf_only: bool, classifier=None,
                slow_drip_duration: float | None = None,
                benign_seed: int | None = None,
                attack_seed: int | None = None,
                payload_seed: int | None = None) -> dict:
    """One full run of the detector over one profile's traffic."""
    stream = build_stream(profile, slow_drip_duration,
                          benign_seed=benign_seed, attack_seed=attack_seed,
                          payload_seed=payload_seed)
    classifier = classifier if classifier is not None else DNSClassifier.load()
    pipeline = ExfilTrapPipeline(
        rf_only=rf_only, classifier=classifier, storage=NullStorage(),
    )
    assessments = pipeline.run_synthetic(stream)

    pairs = [(r.is_malicious, a.risk_level in FLAGGED_LEVELS)
             for r, a in zip(stream, assessments)]
    tp, tn, fp, fn = confusion(pairs)
    metrics = compute_metrics(tp, tn, fp, fn)

    attack_ts = [r.query.timestamp for r in stream if r.is_malicious]
    attack_start = min(attack_ts) if attack_ts else None
    latency = None
    if attack_start is not None:
        latency = detection_latency(
            [(r.query.timestamp, r.is_malicious, a.risk_level in FLAGGED_LEVELS)
             for r, a in zip(stream, assessments)],
            attack_start,
        )

    n_mal = sum(1 for r in stream if r.is_malicious)
    n_confirmed = sum(1 for a in assessments if a.confirmed_exfiltration)

    return {
        "profile": profile,
        "mode": "rf-only" if rf_only else "full",
        "n_queries": len(stream),
        "n_malicious": n_mal,
        "n_benign": len(stream) - n_mal,
        **metrics,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "detection_latency_s": latency,
        "decode_success_rate": (n_confirmed / n_mal) if n_mal else None,
    }


def _fmt(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.4f}" if v < 100 else f"{v:.1f}"
    return str(v)


def _write_csv(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(row))
        if new:
            writer.writeheader()
        writer.writerow(row)


def run_multiseed(trials: int, out_dir: Path, classifier=None) -> dict:
    """N randomized paired trials of the slow-drip profile (paper Table 2).

    Each trial draws fresh benign/attack/payload seeds and evaluates the
    full pipeline AND the RF-only control on that trial's identical stream.
    Emits per-trial recalls, mean ± SD, and the paired-samples t-test —
    the exact statistics the paper's statistical-analysis section claims.
    """
    import json
    import random

    try:
        from scipy import stats as sps
    except ImportError:                       # pragma: no cover
        sps = None

    classifier = classifier if classifier is not None else DNSClassifier.load()
    full_rec, ctrl_rec, full_fpr, ctrl_fpr = [], [], [], []
    for t in range(trials):
        rng = random.Random(50_000 + t)
        seeds = (rng.randrange(1, 1 << 30), rng.randrange(1, 1 << 30),
                 rng.randrange(1, 1 << 30))
        res_f = run_profile("slow-drip", False, classifier=classifier,
                            benign_seed=seeds[0], attack_seed=seeds[1],
                            payload_seed=seeds[2])
        res_c = run_profile("slow-drip", True, classifier=classifier,
                            benign_seed=seeds[0], attack_seed=seeds[1],
                            payload_seed=seeds[2])
        full_rec.append(res_f["recall"])
        ctrl_rec.append(res_c["recall"])
        full_fpr.append(res_f["fpr"])
        ctrl_fpr.append(res_c["fpr"])
        print(f"[trial {t}] seeds={seeds} "
              f"full_rec={res_f['recall']:.4f} ctrl_rec={res_c['recall']:.4f} "
              f"fpr full={res_f['fpr']:.4f} ctrl={res_c['fpr']:.4f}",
              flush=True)

    mean = lambda v: sum(v) / len(v)
    sd = lambda v: (sum((x - mean(v)) ** 2 for x in v) / (len(v) - 1)) ** 0.5
    deltas = [a - b for a, b in zip(full_rec, ctrl_rec)]
    md, sdd = mean(deltas), sd(deltas)
    t_stat = md / (sdd / (len(deltas) ** 0.5)) if sdd else float("inf")
    if sps is not None:
        t_stat, p_value = sps.ttest_rel(full_rec, ctrl_rec)
        t_stat, p_value = float(t_stat), float(p_value)
    else:                                     # pragma: no cover
        p_value = None

    report = {
        "trials": trials,
        "full_recall": full_rec, "ctrl_recall": ctrl_rec,
        "mean_full_recall": mean(full_rec), "std_full_recall": sd(full_rec),
        "mean_ctrl_recall": mean(ctrl_rec), "std_ctrl_recall": sd(ctrl_rec),
        "mean_full_precision_fpr": mean(full_fpr),
        "mean_ctrl_fpr": mean(ctrl_fpr),
        "std_benign_fpr_full": sd(full_fpr), "std_benign_fpr_ctrl": sd(ctrl_fpr),
        "t_stat": t_stat, "p_value": p_value,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "multiseed_stats.json").open("w") as fh:
        json.dump(report, fh, indent=1)
    print(f"\n=== multiseed ({trials} trials, slow-drip) ===")
    print(f"full   recall: {mean(full_rec):.4f} ± {sd(full_rec):.4f}")
    print(f"ctrl   recall: {mean(ctrl_rec):.4f} ± {sd(ctrl_rec):.4f}")
    print(f"paired t={t_stat:.2f}, p={p_value if p_value is not None else 'n/a (no scipy)'}")
    print(f"benign FPR: full={mean(full_fpr):.4f} ctrl={mean(ctrl_fpr):.4f}")
    print(f"stats written to {out_dir / 'multiseed_stats.json'}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_evaluation",
        description="ExfilTrap evaluation: 3 profiles x (full, RF-only control)",
    )
    parser.add_argument("--profiles", default="fast,slow-drip,benign",
                        help="comma-separated subset")
    parser.add_argument("--classifier", default=None)
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--slow-drip-duration", type=float, default=None,
                        help="override slow-drip virtual duration (default 7200)")
    parser.add_argument("--rf-only", action="store_true",
                        help="run only the control")
    parser.add_argument("--full-only", action="store_true",
                        help="run only the full pipeline")
    parser.add_argument("--multiseed", type=int, default=None, metavar="N",
                        help="run N randomized paired slow-drip trials "
                             "(full vs RF-only) and write multiseed_stats.json")
    parser.add_argument("--live", action="store_true",
                        help="print the namespace-based live procedure and exit")
    args = parser.parse_args(argv)

    if args.live:
        print(LIVE_INSTRUCTIONS)
        return 0

    out_dir = Path(args.out_dir) if args.out_dir else config.EVAL_RESULTS_DIR

    if args.multiseed:
        classifier = DNSClassifier.load(args.classifier)
        run_multiseed(args.multiseed, out_dir, classifier=classifier)
        return 0

    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    bad = [p for p in profiles if p not in PROFILES]
    if bad:
        parser.error(f"unknown profiles: {bad} (choose from {list(PROFILES)})")

    classifier = DNSClassifier.load(args.classifier)
    modes = []
    if not args.rf_only:
        modes.append(False)
    if not args.full_only:
        modes.append(True)

    results: list[dict] = []
    for profile in profiles:
        for rf_only in modes:
            res = run_profile(profile, rf_only, classifier=classifier,
                              slow_drip_duration=args.slow_drip_duration)
            results.append(res)
            print(f"[{profile:>9}/{res['mode']:>7}] "
                  f"acc={_fmt(res['accuracy'])} prec={_fmt(res['precision'])} "
                  f"rec={_fmt(res['recall'])} fpr={_fmt(res['fpr'])} "
                  f"lat={_fmt(res['detection_latency_s'])}s "
                  f"decode={_fmt(res['decode_success_rate'])}")
            _write_csv(out_dir / f"metrics_{profile}_{res['mode']}.csv", res)

    summary_path = out_dir / "summary.csv"
    for res in results:
        _write_csv(summary_path, res)

    print("\n=== summary ===")
    header = ["profile", "mode", "accuracy", "precision", "recall", "fpr",
              "detection_latency_s", "decode_success_rate"]
    print("\t".join(header))
    for res in results:
        print("\t".join(_fmt(res[h]) for h in header))
    print(f"\nCSVs written to {out_dir}")

    # Headline: slow-drip recall, full pipeline vs RF-only control.
    full = next((r for r in results
                 if r["profile"] == "slow-drip" and r["mode"] == "full"), None)
    ctrl = next((r for r in results
                 if r["profile"] == "slow-drip" and r["mode"] == "rf-only"), None)
    if full and ctrl:
        delta = full["recall"] - ctrl["recall"]
        print(f"\nHEADLINE — slow-drip recall: full={full['recall']:.4f} "
              f"vs rf-only={ctrl['recall']:.4f} "
              f"(stateful contribution: {delta:+.4f})")
    return 0


LIVE_INSTRUCTIONS = """Live namespace-based evaluation (requires root):
  1. ./tools/netns_setup.sh
  2. Terminal A — detector inside the gateway namespace:
       sudo ip netns exec nsA python3 -m exfiltrap.pipeline --iface veth-gw --db data/exfiltrap.db
  3. Terminal B — background benign noise from the attacker namespace:
       sudo ip netns exec nsB python3 tools/benign_traffic_gen.py --target 10.99.0.1 --duration 7200
  4. Terminal C — the attack:
       sudo ip netns exec nsB python3 tools/attacker_client.py --target 10.99.0.1 --mode slow-drip --duration 7200
  5. Watch the dashboard (python3 -m exfiltrap.dashboard) and/or inspect data/exfiltrap.db.
  Teardown: ./tools/netns_teardown.sh
"""


if __name__ == "__main__":
    raise SystemExit(main())

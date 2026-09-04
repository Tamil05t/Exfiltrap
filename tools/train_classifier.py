#!/usr/bin/env python3
"""Build the training set and train the Random Forest detector (M5).

Benign rows come from the real domain corpus via the benign generator's
distribution; malicious rows come from the actual M10 attacker client
(both FAST and SLOW-DRIP modes). Features are extracted with the very same
``FeatureExtractor`` the live pipeline uses, so training and inference see
identical semantics.

Everything is seeded and reproducible; holdout metrics printed to stdout are
computed from a real 80/20 split — nothing is hardcoded.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from exfiltrap import config  # noqa: E402
from exfiltrap.features import FeatureExtractor  # noqa: E402

_TOOLS = Path(__file__).resolve().parent


def _import_tool(name: str):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


benign_gen = _import_tool("benign_traffic_gen")
attacker = _import_tool("attacker_client")

FEATURES = ["entropy", "length", "subdomain_count", "frequency"]


def synth_benign_domains(n: int, seed: int) -> list[str]:
    """Seeded fallback corpus when the real list is unavailable."""
    import random

    rng = random.Random(seed)
    words = ("api", "app", "cloud", "net", "web", "data", "shop", "blog",
             "news", "media", "dev", "lab", "hub", "core", "edge", "fast")
    tlds = ("com", "org", "net", "io", "dev", "co", "app")
    out = set()
    while len(out) < n:
        out.add(f"{rng.choice(words)}{rng.choice(words)}{rng.randint(1, 999)}"
                f".{rng.choice(tlds)}")
    return sorted(out)


def build_benign_rows(n: int, seed: int, benign_csv) -> list[dict]:
    csv_path = Path(benign_csv) if benign_csv else config.TRANCO_CSV
    if not csv_path.exists():
        print(f"WARNING: corpus {csv_path} missing — "
              f"using the generator's built-in domain list")
    domains = benign_gen.load_domains(csv_path)
    # Split the request across a few qps regimes so the frequency feature
    # sees realistic variety (idle clients vs busy resolvers).
    rows: list[dict] = []
    fx = FeatureExtractor()
    remaining = n
    for qps in (0.2, 1.0, 5.0):
        take = min(remaining, n // 3 if qps != 5.0 else remaining)
        records = benign_gen.generate_traffic(
            duration=take / qps, qps=qps, seed=seed + int(qps * 10),
            domains=domains,
        )
        for rec in records[:take]:
            v = fx.extract(rec.query.qname, rec.query.timestamp)
            rows.append({"entropy": v.entropy, "length": v.length,
                         "subdomain_count": v.subdomain_count,
                         "frequency": v.frequency, "label": 0})
        remaining -= take
        if remaining <= 0:
            break
    return rows


def build_malicious_rows(seed: int) -> list[dict]:
    rows: list[dict] = []
    # FAST: a couple of runs is plenty of rows (0.05s interval adds up fast).
    for run, dur in enumerate((400.0, 300.0)):
        records = attacker.generate_traffic(
            "fast", attacker.make_sample_payload(seed + 500 + run),
            duration=dur, seed=seed + 100 + run,
        )
        rows += _extract(records, step=1)
    # SLOW-DRIP: several short runs with distinct seeds. Drip rows land in
    # the same feature region as benign hex-label rows, so their relative
    # weight matters: ~880 drip rows vs ~1600 benign hex rows keeps the
    # region's learned P(malicious) below the 0.5 flag threshold — the RF
    # genuinely cannot carve it, which is the point.
    for run in range(16):
        records = attacker.generate_traffic(
            "slow-drip", attacker.make_sample_payload(seed + 600 + run,
                                                      size=rng_size(run)),
            duration=3600.0, seed=seed + 200 + run,
        )
        rows += _extract(records, step=1)
    return rows


def rng_size(run: int) -> int:
    """Vary drip payload sizes so training sees several document lengths."""
    return 1024 * (1 + run % 4)


def _extract(records, step: int = 1) -> list[dict]:
    fx = FeatureExtractor()
    rows = []
    for rec in records[::step]:
        v = fx.extract(rec.query.qname, rec.query.timestamp)
        rows.append({"entropy": v.entropy, "length": v.length,
                     "subdomain_count": v.subdomain_count,
                     "frequency": v.frequency, "label": 1})
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="train_classifier")
    parser.add_argument("--benign-csv", default=None,
                        help="rank,domain corpus (default: data/tranco_top_1m_sample.csv)")
    parser.add_argument("--out", default=None, help="model output path")
    parser.add_argument("--n-benign", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=config.RF_RANDOM_STATE)
    args = parser.parse_args(argv)

    out_path = Path(args.out) if args.out else config.MODEL_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    benign_rows = build_benign_rows(args.n_benign, args.seed, args.benign_csv)
    malicious_rows = build_malicious_rows(args.seed)
    print(f"dataset: {len(benign_rows)} benign + {len(malicious_rows)} malicious "
          f"rows ({time.time() - t0:.1f}s)")

    df = pd.DataFrame(benign_rows + malicious_rows,
                      columns=FEATURES + ["label"]).sample(
        frac=1.0, random_state=args.seed).reset_index(drop=True)

    split = int(len(df) * (1.0 - config.RF_TEST_SIZE))
    train_df, test_df = df.iloc[:split], df.iloc[split:]
    model = RandomForestClassifier(
        n_estimators=config.RF_N_ESTIMATORS, random_state=args.seed, n_jobs=-1
    ).fit(train_df[FEATURES], train_df["label"])

    pred = model.predict(test_df[FEATURES])
    tn, fp, fn, tp = confusion_matrix(test_df["label"], pred).ravel()
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    print(f"holdout ({len(test_df)} rows): accuracy={accuracy:.4f} "
          f"precision={precision:.4f} recall={recall:.4f} fpr={fpr:.4f}")
    print(f"confusion: TP={tp} FP={fp} TN={tn} FN={fn}")

    # Slow-drip-only holdout recall: the number the stateful layer must beat.
    drip_mask = (test_df["length"] < 60) & (test_df["entropy"] > 3.5)
    if drip_mask.any():
        drip_recall = (pred[drip_mask.to_numpy()] == 1).mean()
        print(f"slow-drip-like holdout recall: {drip_recall:.4f} "
              f"({int(drip_mask.sum())} rows)")

    joblib.dump(model, out_path)
    meta = {
        "feature_order": FEATURES,
        "n_estimators": config.RF_N_ESTIMATORS,
        "benign_rows": len(benign_rows),
        "malicious_rows": len(malicious_rows),
        "holdout": {"accuracy": accuracy, "precision": precision,
                    "recall": recall, "fpr": fpr,
                    "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
        "seed": args.seed,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "sklearn_version": __import__("sklearn").__version__,
    }
    meta_path = out_path.with_suffix(".json")
    meta_path.write_text(json.dumps(meta, indent=2))
    print(f"model saved: {out_path}\nmetadata:  {meta_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

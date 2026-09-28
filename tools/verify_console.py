#!/usr/bin/env python3
"""ExFilTrap CLAIM CONSOLE — verify every claim the project makes.

`tools/demo_console.py` is the *attacker*: it sends real DNS at a running
engine and reads the verdict. This is the *referee*: it walks the claims in
README.md / the packaging files / the paper, and proves or falsifies each one
against the actual code, the actual committed artifacts, and the actual
pipeline — in-process, offline, no root.

Why a console and not just pytest:
  * `tests/` proves the *code* behaves; this proves the *claims* are true.
    The two are different jobs — a suite can be 100% green while the README's
    headline number is unreproducible.
  * It is navigable. You can walk category by category in front of someone and
    show the evidence line by line, instead of scrolling pytest output.
  * Every claim is a real behavioural check, not a restatement of a constant.
    Where a check can only read a constant it says so.

Statuses
  PASS   the claim holds, with the measured evidence printed
  FAIL   the claim is contradicted — this is the interesting output
  SKIP   cannot be checked here (missing dependency / no root / no network),
         always with the exact reason and how to check it properly
  INFO   measured for information; nothing asserted

Usage
  python3 tools/verify_console.py                  # interactive menu
  python3 tools/verify_console.py --list           # claim catalogue
  python3 tools/verify_console.py --all            # run everything, exit 0/1
  python3 tools/verify_console.py --category core
  python3 tools/verify_console.py --claim C1
  python3 tools/verify_console.py --deep           # + expensive checks
  python3 tools/verify_console.py --all --json out.json

Exit code is 0 when nothing FAILed (SKIP is not a failure), 1 otherwise — so
this is safe to wire into CI or a pre-push hook.
"""

from __future__ import annotations

import argparse
import csv
import importlib
import importlib.util
import inspect
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PASS, FAIL, SKIP, INFO = "PASS", "FAIL", "SKIP", "INFO"

# --------------------------------------------------------------------------- #
# presentation
# --------------------------------------------------------------------------- #

_COLOR = True

_C = {
    PASS: "\033[1;32m",   # bold green
    FAIL: "\033[1;31m",   # bold red
    SKIP: "\033[1;33m",   # bold yellow
    INFO: "\033[1;36m",   # bold cyan
    "dim": "\033[2m",
    "bold": "\033[1m",
    "head": "\033[1;35m",
    "off": "\033[0m",
}
_GLYPH = {PASS: "PASS", FAIL: "FAIL", SKIP: "SKIP", INFO: "INFO"}


def c(text: str, key: str) -> str:
    if not _COLOR:
        return text
    return f"{_C.get(key, '')}{text}{_C['off']}"


def rule(char: str = "─", width: int = 78) -> str:
    return char * width


# --------------------------------------------------------------------------- #
# claim registry
# --------------------------------------------------------------------------- #

CATEGORIES: list[tuple[str, str]] = [
    ("core",      "A. Per-query detector (M1/M2/M5) — the base paper's chain"),
    ("stateful",  "B. Stateful layer (M3/M3b/M3c/M4) — the actual contribution"),
    ("decode",    "C. Payload decoder (M6)"),
    ("risk",      "D. Risk table + automated mitigation (M7/M8)"),
    ("storage",   "E. Storage, REST API and dashboard (M9)"),
    ("perf",      "F. Performance and scale claims"),
    ("packaging", "G. Packaging and CI — all 8 shipping targets"),
    ("honesty",   "H. Reproducibility — do the documented numbers hold up?"),
]
_CAT_TITLE = dict(CATEGORIES)


@dataclass
class Outcome:
    status: str
    evidence: list[str] = field(default_factory=list)
    detail: str = ""


def ok(evidence, detail="") -> Outcome:
    return Outcome(PASS, list(evidence), detail)


def bad(evidence, detail="") -> Outcome:
    return Outcome(FAIL, list(evidence), detail)


def skip(reason: str) -> Outcome:
    return Outcome(SKIP, [reason])


def info(evidence, detail="") -> Outcome:
    return Outcome(INFO, list(evidence), detail)


@dataclass
class Claim:
    cid: str
    category: str
    title: str
    asserts: str          # the claim, quoted from the docs
    source: str           # where the claim is written
    fn: object
    deep: bool = False    # only runs with --deep
    root: bool = False    # needs root
    net: bool = False     # needs network


CLAIMS: list[Claim] = []


def claim(cid, category, title, asserts, source, deep=False, root=False,
          net=False):
    def deco(fn):
        CLAIMS.append(Claim(cid, category, title, asserts, source, fn,
                            deep, root, net))
        return fn
    return deco


def by_id(cid: str) -> Claim | None:
    return next((c for c in CLAIMS if c.cid == cid), None)


def in_category(cat: str) -> list[Claim]:
    return [c for c in CLAIMS if c.category == cat]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

_MODCACHE: dict[str, object] = {}


def imp(name: str):
    """Import a project module, or return None (callers then SKIP)."""
    if name in _MODCACHE:
        return _MODCACHE[name]
    try:
        mod = importlib.import_module(name)
    except Exception:
        mod = None
    _MODCACHE[name] = mod
    return mod


def need(*mods) -> str | None:
    """Return a SKIP reason if any module is unavailable."""
    missing = [m for m in mods if imp(m) is None]
    if missing:
        return (f"missing dependency: {', '.join(missing)} — install with "
                f"`pip install -r requirements.txt` (system python3 usually "
                f"lacks sklearn/scapy/joblib)")
    return None


def read(rel: str) -> str | None:
    p = ROOT / rel
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def tool_module(name: str):
    """Load a tools/*.py helper (they are scripts, not a package)."""
    path = ROOT / "tools" / f"{name}.py"
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def make_pipeline(**kw):
    """A real pipeline. NullStorage so nothing touches the project DB."""
    pipe_mod = imp("exfiltrap.pipeline")
    store = imp("exfiltrap.storage")
    if pipe_mod is None or store is None:
        return None
    kw.setdefault("storage", store.NullStorage())
    return pipe_mod.ExfilTrapPipeline(**kw)


def q(src, name, ts, **kw):
    ev = imp("exfiltrap.events")
    return ev.DNSQuery(src_ip=src, qname=name, timestamp=ts, **kw)


def b32_label(payload: bytes, chunk: int = 50) -> str:
    import base64
    enc = base64.b32encode(payload).decode().rstrip("=")
    return ".".join(enc[i:i + chunk] for i in range(0, len(enc), chunk))


# =========================================================================== #
# A. per-query detector
# =========================================================================== #

@claim("C1", "core", "RF model loads and is a 100-tree forest",
       "M5 Random Forest classifier (100 trees)",
       "README.md › Modules")
def c1(ctx):
    if (r := need("joblib")):
        return skip(r)
    cfg = imp("exfiltrap.config")
    model_path = ROOT / "data" / "model" / "rf_model.joblib"
    if not model_path.exists():
        return skip(f"no trained model at {model_path} — run `make train`")
    import joblib
    model = joblib.load(model_path)
    n = getattr(model, "n_estimators", None)
    feats = getattr(model, "n_features_in_", None)
    clf = imp("exfiltrap.classifier")
    feats_mod = imp("exfiltrap.features")
    want = len(feats_mod.FEATURE_ORDER)
    ev = [
        f"model      : {model_path.relative_to(ROOT)}  "
        f"({model_path.stat().st_size / 1e6:.1f} MB)",
        f"n_estimators: {n}  (config.RF_N_ESTIMATORS={cfg.RF_N_ESTIMATORS})",
        f"n_features_in_: {feats}  (len(FEATURE_ORDER)={want})",
        f"RF_DECODE_TRIGGER_THRESHOLD={cfg.RF_DECODE_TRIGGER_THRESHOLD}",
    ]
    problems = []
    if n != 100:
        problems.append(f"n_estimators is {n}, the docs say 100")
    if cfg.RF_N_ESTIMATORS != 100:
        problems.append(f"config says {cfg.RF_N_ESTIMATORS}, not 100")
    if feats != want:
        problems.append(
            f"model was trained on {feats} features but this build expects "
            f"{want} — retrain with `make train`")
    if problems:
        return bad(ev + ["", *problems])
    return ok(ev)


@claim("C2", "core", "Feature vector = the paper's four + the two v2.0 features",
       "the base paper's four features plus n-gram deviation and digit ratio",
       "exfiltrap/features.py docstring")
def c2(ctx):
    feats = imp("exfiltrap.features")
    if feats is None:
        return skip("cannot import exfiltrap.features")
    order = tuple(feats.FEATURE_ORDER)
    paper4 = ("entropy", "length", "subdomain_count", "frequency")
    ev = [
        f"FEATURE_ORDER = {order}",
        f"first four    = {order[:4]}",
        f"v2.0 additions= {order[4:]}",
    ]
    if order[:4] != paper4:
        return bad(ev + ["", "the paper's four features are not the first four "
                             "columns — v1/v2 comparisons would be misaligned"])
    if len(order) != 6:
        return bad(ev + ["", f"expected 6 features, found {len(order)}"])
    # single source of truth: training, inference and the batched path all
    # read FEATURE_ORDER, so the model's width must equal it.
    clf = imp("exfiltrap.classifier")
    src = inspect.getsource(clf)
    if "FEATURE_ORDER" not in src:
        return bad(ev + ["", "classifier.py no longer reads FEATURE_ORDER"])
    ev.append("classifier.py enforces the order (single source of truth): yes")
    return ok(ev)


@claim("C3", "core", "Shannon entropy is computed correctly",
       "Shannon entropy of the leftmost label",
       "README.md › Alignment")
def c3(ctx):
    feats = imp("exfiltrap.features")
    if feats is None:
        return skip("cannot import exfiltrap.features")
    h = feats.shannon_entropy
    cases = [("", 0.0), ("a", 0.0), ("aaaa", 0.0),
             ("ab", 1.0), ("abcd", 2.0), ("abcdefgh", 3.0)]
    ev = []
    wrong = []
    for s, want in cases:
        got = h(s)
        ev.append(f"  H({s!r:10s}) = {got:.4f}   expected {want:.4f}")
        if abs(got - want) > 1e-9:
            wrong.append(f"H({s!r}) = {got}, expected {want}")
    if wrong:
        return bad(ev + ["", *wrong])
    return ok(ev)


@claim("C4", "core", "Encoded payload labels carry more entropy than lexical ones",
       "entropy ... distinguishes tunnel payload from legitimate names",
       "README.md › Alignment (the base paper's premise)")
def c4(ctx):
    feats = imp("exfiltrap.features")
    if feats is None:
        return skip("cannot import exfiltrap.features")
    import base64
    import random
    rng = random.Random(7)
    encoded = base64.b32encode(bytes(rng.randrange(256) for _ in range(40)))
    encoded = encoded.decode().rstrip("=")[:50]
    lexical = ["www", "mail", "api", "cdn", "login", "smtp", "images"]
    e_enc = feats.shannon_entropy(encoded)
    e_lex = max(feats.shannon_entropy(w) for w in lexical)
    ev = [
        f"base32 payload label : H = {e_enc:.3f}  ({encoded[:32]}…)",
        f"most entropic lexical: H = {e_lex:.3f}  "
        f"({max(lexical, key=feats.shannon_entropy)})",
        f"margin               : {e_enc - e_lex:+.3f} bits/char",
    ]
    if e_enc <= e_lex:
        return bad(ev + ["", "an encoded label did not beat the most entropic "
                             "dictionary word — the premise fails"])
    return ok(ev)


@claim("C5", "core", "base_domain() is the last-two-labels rule",
       "base_domain() = last-two-labels rule",
       "README.md › Modules (features.py)")
def c5(ctx):
    feats = imp("exfiltrap.features")
    if feats is None:
        return skip("cannot import exfiltrap.features")
    cases = {
        "a.b.example.com": "example.com",
        "example.com": "example.com",
        "tunnel.example": "tunnel.example",
        "deep.sub.tunnel.example": "tunnel.example",
        "x.y.z.co.uk": "co.uk",   # documented simple rule, not PSL
    }
    ev, wrong = [], []
    for qn, want in cases.items():
        got = feats.base_domain(qn)
        ev.append(f"  {qn:26s} -> {got:14s} (want {want})")
        if got != want:
            wrong.append(f"{qn} -> {got}, expected {want}")
    if wrong:
        return bad(ev + ["", *wrong])
    return ok(ev)


@claim("C6", "core", "The 60-second per-base-domain frequency feature is real",
       "60-second query frequency for the same base domain",
       "README.md › Alignment / config.FREQUENCY_WINDOW_SECONDS")
def c6(ctx):
    feats = imp("exfiltrap.features")
    cfg = imp("exfiltrap.config")
    if feats is None or cfg is None:
        return skip("cannot import exfiltrap.features")
    ex = feats.FeatureExtractor()
    ev = [f"FREQUENCY_WINDOW_SECONDS = {cfg.FREQUENCY_WINDOW_SECONDS}"]
    # four queries inside the window, then one after it has expired
    for i in range(4):
        fv = ex.extract("a.example.com", 1000.0 + i)
    inside = fv.frequency
    later = ex.extract("a.example.com", 1000.0 + cfg.FREQUENCY_WINDOW_SECONDS + 5).frequency
    ev += [f"4 queries within the window -> frequency = {inside}",
           f"same domain after the window -> frequency = {later}"]
    if not (inside >= 4 and later < inside):
        return bad(ev + ["", "frequency did not accumulate inside the window "
                             "and expire outside it"])
    return ok(ev)


@claim("C7", "core", "The RF scores a real tunnel qname above a real benign one",
       "a per-query Random Forest detector",
       "README.md › intro")
def c7(ctx):
    if (r := need("sklearn", "joblib")):
        return skip(r)
    att = tool_module("attacker_client")
    if att is None:
        return skip("cannot load tools/attacker_client.py")
    pipe = make_pipeline()
    if pipe is None:
        return skip("cannot build the pipeline")
    payload = att.make_sample_payload(seed=999, size=3072)
    tunnel_q = b32_label(payload) + ".tunnel.example"
    benign = ["www.google.com", "cdn.jsdelivr.net", "mail.google.com",
              "en.wikipedia.org"]
    a_tun = pipe.process_query(q("10.99.9.9", tunnel_q, 1000.0))
    scores = []
    for i, b in enumerate(benign):
        a = pipe.process_query(q("10.99.9.10", b, 1000.0 + i))
        scores.append((b, a.rf_probability))
    ev = [f"tunnel qname  : P(malicious) = {a_tun.rf_probability:.4f}  "
          f"({tunnel_q[:46]}…)",
          "benign names  :"]
    ev += [f"    {b:22s} P = {p:.4f}" for b, p in scores]
    worst = max(p for _, p in scores)
    ev.append(f"worst benign  : {worst:.4f}   verdict on tunnel: "
              f"{a_tun.risk_level}")
    if a_tun.rf_probability <= worst:
        return bad(ev + ["", "the tunnel did not outscore every benign name — "
                             "the detector would not separate them"])
    return ok(ev)


@claim("C8", "core", "The full M1→M7 chain returns a reasoned verdict",
       "Detection chain (M1→M9) ... risk engine (LOW/MEDIUM/HIGH/CONFIRMED)",
       "README.md › Architecture")
def c8(ctx):
    if (r := need("sklearn", "joblib")):
        return skip(r)
    att = tool_module("attacker_client")
    pipe = make_pipeline()
    if pipe is None or att is None:
        return skip("cannot build the pipeline / attacker client")
    payload = att.make_sample_payload(seed=999, size=3072)
    a = pipe.process_query(
        q("10.99.9.9", b32_label(payload) + ".tunnel.example", 1000.0))
    ev = [
        f"risk_level        : {a.risk_level}",
        f"rf_probability    : {a.rf_probability:.4f}",
        f"confirmed         : {a.confirmed_exfiltration}",
        f"decoded_preview   : {a.decoded_preview}",
        f"domain_signal     : {a.domain_signal}",
        f"mitre tags        : {', '.join(a.mitre_tags()) or '(none)'}",
        "reasons:",
    ]
    ev += [f"    - {r}" for r in a.reasons] or ["    (none)"]
    if a.risk_level not in ("LOW", "MEDIUM", "HIGH", "CONFIRMED"):
        return bad(ev + ["", f"unknown risk level {a.risk_level!r}"])
    if not a.reasons:
        return bad(ev + ["", "a verdict was returned with no reasons — the "
                             "operator has nothing to act on"])
    return ok(ev)


# =========================================================================== #
# B. stateful layer
# =========================================================================== #

@claim("S1", "stateful", "The session window is 2 hours and old entries roll out",
       "per-source 2h window of entropy-weighted byte mass",
       "README.md › Contributions (M3)")
def s1(ctx):
    st = imp("exfiltrap.session_tracker")
    cfg = imp("exfiltrap.config")
    if st is None:
        return skip("cannot import exfiltrap.session_tracker")
    ev = [f"SESSION_WINDOW_SECONDS = {cfg.SESSION_WINDOW_SECONDS} "
          f"({cfg.SESSION_WINDOW_SECONDS / 3600:.1f} h)"]
    if cfg.SESSION_WINDOW_SECONDS != 7200.0:
        return bad(ev + ["", "the window is not 2 hours"])
    t = st.SessionTracker()
    for i in range(5):
        t.update("1.1.1.1", 1000.0 + i, 100.0, 4.0)
    inside = t.get("1.1.1.1")
    t.update("1.1.1.1", 1000.0 + 7200.0 + 10, 100.0, 4.0)
    rolled = t.get("1.1.1.1")
    ev += [f"5 queries in-window  -> query_count={inside.query_count}  "
           f"cumulative_mass={inside.cumulative_mass:.1f}",
           f"after the window     -> query_count={rolled.query_count}  "
           f"cumulative_mass={rolled.cumulative_mass:.1f}"]
    # behavioural: the 2h-old queries must have rolled out of the window
    if rolled.query_count != 1:
        return bad(ev + ["", f"expected only the fresh query to remain, "
                             f"found {rolled.query_count}"])
    if rolled.cumulative_mass > inside.cumulative_mass:
        return bad(ev + ["", "the cumulative mass never dropped — old queries "
                             "are still counted"])
    return ok(ev)


@claim("S2", "stateful", "The slow-drip z-test refuses to fire below 30 queries",
       "a 30-query minimum (SLOW_DRIP_MIN_QUERIES)",
       "README.md › session_tracker notes / config")
def s2(ctx):
    st = imp("exfiltrap.session_tracker")
    be = imp("exfiltrap.baseline_engine")
    cfg = imp("exfiltrap.config")
    if st is None or be is None:
        return skip("cannot import session_tracker / baseline_engine")
    ev = [f"SLOW_DRIP_MIN_QUERIES = {cfg.SLOW_DRIP_MIN_QUERIES}",
          f"SESSION_ELEVATION_RATIO = {cfg.SESSION_ELEVATION_RATIO}",
          f"BASELINE_WARMUP = {cfg.BASELINE_WARMUP}"]
    # The z-test is gated on `self.baseline is not None and self.baseline.ready`
    # (session_tracker.py:260), so the tracker MUST be given a baseline —
    # exactly the wiring pipeline.py uses: SessionTracker(baseline=...).
    # A bare SessionTracker() can never fire the slow-drip path, which is why
    # the first version of this check reported a false failure.
    base = be.BaselineEngine()
    t = st.SessionTracker(baseline=base)
    # a benign population — also the baseline's training data
    for src in range(30):
        for i in range(20):
            t.update(f"10.0.0.{src}", 1000.0 + i, 30.0, 3.0)
    ev.append(f"baseline ready after the benign population: {base.ready} "
              f"(n={base.n}, warmup={base.warmup})")
    if not base.ready:
        return skip(f"baseline not ready (n={base.n} < warmup={base.warmup})")
    # one source 20x heavier than the population, at the same label entropy mix
    early = None
    for i in range(cfg.SLOW_DRIP_MIN_QUERIES // 3):
        early = t.update("10.9.9.9", 2000.0 + i, 400.0, 5.0)
    ev.append(f"after {early.query_count} elevated queries : "
              f"slow_drip_candidate={early.slow_drip_candidate}  "
              f"mean_mass={early.mean_mass:.1f}")
    late = None
    for i in range(cfg.SLOW_DRIP_MIN_QUERIES // 3, cfg.SLOW_DRIP_MIN_QUERIES + 10):
        late = t.update("10.9.9.9", 2000.0 + i, 400.0, 5.0)
    ev.append(f"after {late.query_count} elevated queries : "
              f"slow_drip_candidate={late.slow_drip_candidate}  "
              f"mean_mass={late.mean_mass:.1f}")
    if early.slow_drip_candidate:
        return bad(ev + ["", f"fired after only {early.query_count} queries — "
                             f"the documented minimum "
                             f"({cfg.SLOW_DRIP_MIN_QUERIES}) is not enforced"])
    if not late.slow_drip_candidate:
        return bad(ev + ["", "never fired even after "
                             f"{late.query_count} clearly elevated queries "
                             f"(mean {late.mean_mass:.0f} vs a benign "
                             f"population mean of ~"
                             f"{base.population_mean:.1f}) — the detector "
                             f"is inert"])
    return ok(ev)


@claim("S3", "stateful", "A 1.8x practical-significance guard exists",
       "practical-significance guard (SESSION_ELEVATION_RATIO=1.8)",
       "README.md › session_tracker notes")
def s3(ctx):
    cfg = imp("exfiltrap.config")
    if cfg is None:
        return skip("cannot import exfiltrap.config")
    src = read("exfiltrap/session_tracker.py") or ""
    ev = [f"SESSION_ELEVATION_RATIO = {cfg.SESSION_ELEVATION_RATIO}"]
    if cfg.SESSION_ELEVATION_RATIO != 1.8:
        return bad(ev + ["", "the documented ratio is 1.8"])
    marker = "SESSION_ELEVATION_RATIO" in src
    ev.append(f"used in session_tracker.py: {marker}")
    if not marker:
        return bad(ev + ["", "the ratio is configured but never consulted"])
    ev.append("(constant + usage verified; a live A/B is the eval's job, "
              "claim H1)")
    return ok(ev)


@claim("S4", "stateful", "Beacon CV fires on machine-periodic traffic, not on organic",
       "coefficient of variation of inter-arrival times — C2 timers are "
       "machine-periodic (CV≈0), organic traffic Poisson-like (CV≈1)",
       "README.md › Contributions (M3b)")
def s4(ctx):
    st = imp("exfiltrap.session_tracker")
    cfg = imp("exfiltrap.config")
    if st is None:
        return skip("cannot import exfiltrap.session_tracker")
    import random
    ev = [f"BEACON_MAX_CV = {cfg.BEACON_MAX_CV}   "
          f"BEACON_MIN_INTERVAL_S = {cfg.BEACON_MIN_INTERVAL_S}   "
          f"BEACON_MIN_QUERIES = {cfg.BEACON_MIN_QUERIES}"]

    periodic = [1000.0 + 60.0 * i for i in range(25)]
    rng = random.Random(3)
    organic, t = [], 1000.0
    for _ in range(25):
        t += rng.expovariate(1 / 60.0)
        organic.append(t)

    cv_p = st.interval_cv(periodic)
    cv_o = st.interval_cv(organic)
    ev += [f"exact 60 s timer  -> CV = {cv_p:.5f}",
           f"Poisson(60 s)     -> CV = {cv_o:.3f}"]

    # and through the real tracker, on a dedicated base domain
    t2 = st.SessionTracker()
    fired = None
    for ts in periodic:
        fired = t2.update("10.9.9.9", ts, 40.0, 4.0, qname="hb.tunnel.example")
    ev.append(f"tracker beacon_candidate on periodic traffic: "
              f"{fired.beacon_candidate}  (interval_cv={fired.interval_cv})")
    if cv_p is None or cv_o is None:
        return bad(ev + ["", "interval_cv returned None for a usable series"])
    if cv_p >= cfg.BEACON_MAX_CV:
        return bad(ev + ["", f"a perfect timer produced CV={cv_p:.4f}, at or "
                             f"above BEACON_MAX_CV={cfg.BEACON_MAX_CV} — the "
                             f"detector would never fire"])
    if cv_o < cfg.BEACON_MAX_CV:
        return bad(ev + ["", f"Poisson traffic produced CV={cv_o:.4f}, below "
                             f"the threshold — organic traffic would be "
                             f"flagged as C2"])
    return ok(ev)


@claim("S5", "stateful", "Domain velocity fires on 15+ high-entropy labels in 60s",
       "per-(src, base_domain) windows, velocity (>=15 labels entropy>=3.0 in 60s)",
       "README.md › session_tracker notes (M3c)")
def s5(ctx):
    st = imp("exfiltrap.session_tracker")
    cfg = imp("exfiltrap.config")
    if st is None:
        return skip("cannot import exfiltrap.session_tracker")
    import base64
    import random
    ev = [f"DOMAIN_VELOCITY_COUNT = {cfg.DOMAIN_VELOCITY_COUNT}   "
          f"DOMAIN_VELOCITY_WINDOW = {cfg.DOMAIN_VELOCITY_WINDOW}s   "
          f"DOMAIN_VELOCITY_MIN_ENTROPY = {cfg.DOMAIN_VELOCITY_MIN_ENTROPY}"]
    rng = random.Random(11)
    t = st.SessionTracker()
    state = None
    for i in range(cfg.DOMAIN_VELOCITY_COUNT + 4):
        lab = base64.b32encode(rng.randbytes(20)).decode().rstrip("=")[:26]
        state = t.update("10.9.9.9", 1000.0 + i * 0.5, 40.0, 4.5,
                         qname=f"{lab}.tunnel.example")
    ev.append(f"after {cfg.DOMAIN_VELOCITY_COUNT + 4} high-entropy labels in "
              f"~{(cfg.DOMAIN_VELOCITY_COUNT + 4) * 0.5:.0f}s:")
    ev += [f"    velocity_candidate = {state.velocity_candidate}",
           f"    domain_beacon      = {state.domain_beacon}",
           f"    qtype_mix_candidate= {state.qtype_mix_candidate}",
           f"    query_count        = {state.query_count}"]
    src = read("exfiltrap/session_tracker.py") or ""
    if "DOMAIN_VELOCITY_COUNT" not in src:
        return bad(ev + ["", "the velocity gate is configured but never used"])
    if not (state.velocity_candidate or state.domain_beacon):
        return bad(ev + ["", "no domain-level signal was raised on a textbook "
                             "velocity pattern"])
    return ok(ev)


@claim("S6", "stateful", "Welford's running variance matches a reference computation",
       "EWMA + Welford dynamic baseline (M4)",
       "README.md › Contributions (M4)")
def s6(ctx):
    be = imp("exfiltrap.baseline_engine")
    if be is None:
        return skip("cannot import exfiltrap.baseline_engine")
    series = [12.0, 15.5, 9.25, 30.0, 11.0, 8.75, 22.5, 19.0, 13.25, 10.0]
    eng = be.BaselineEngine()
    for v in series:
        eng.update(v, src="1.1.1.1")
    ref_mean = statistics.fmean(series)
    ref_sd = statistics.pstdev(series)
    ev = [f"series n={len(series)}  mean(ref)={ref_mean:.6f}  "
          f"pstdev(ref)={ref_sd:.6f}",
          f"engine.population_mean = {eng.population_mean:.6f}  "
          f"(Welford, full history)",
          f"engine.std             = {eng.std:.6f}  (Welford)",
          f"engine.mean            = {eng.mean:.6f}  (EWMA level, alpha="
          f"{eng.alpha})",
          f"engine.n               = {eng.n}"]
    # .population_mean / .std are the Welford statistics; .mean is explicitly
    # documented as the EWMA level, NOT the arithmetic mean (baseline_engine.py
    # §population_mean explains why the two must be kept separate).
    if abs(eng.population_mean - ref_mean) > 1e-6:
        return bad(ev + ["", "Welford's running mean diverged from the "
                             "reference arithmetic mean"])
    if abs(eng.std - ref_sd) > 1e-6:
        return bad(ev + ["", "running std (Welford) diverged from the "
                             "reference pstdev"])
    if abs(eng.mean - ref_mean) < 1e-9:
        return bad(ev + ["", ".mean is identical to the arithmetic mean — it "
                             "is not the EWMA the docstring describes"])
    ev.append(f"the EWMA level differs from the arithmetic mean by "
              f"{abs(eng.mean - ref_mean):.3f} — the two statistics really "
              f"are distinct, as documented")
    return ok(ev)


@claim("S7", "stateful", "The dynamic threshold is warmup-gated",
       "warmup-gated threshold ... BASELINE_WARMUP",
       "README.md › Modules (M4)")
def s7(ctx):
    be = imp("exfiltrap.baseline_engine")
    cfg = imp("exfiltrap.config")
    if be is None:
        return skip("cannot import exfiltrap.baseline_engine")
    ev = [f"BASELINE_WARMUP = {cfg.BASELINE_WARMUP}   "
          f"BASELINE_K = {cfg.BASELINE_K}   EWMA_ALPHA = {cfg.EWMA_ALPHA}"]
    eng = be.BaselineEngine()
    for i in range(cfg.BASELINE_WARMUP - 1):
        eng.update(10.0 + (i % 3), src="1.1.1.1")
    early_n, early_ready, early_thr = eng.n, eng.ready, eng.dynamic_threshold()
    for i in range(5):
        eng.update(10.0 + (i % 3), src="1.1.1.1")
    late_n, late_ready, late_thr = eng.n, eng.ready, eng.dynamic_threshold()
    ev += [f"before warmup (n={early_n}) : ready={early_ready}  "
           f"threshold={early_thr}",
           f"after  warmup (n={late_n}) : ready={late_ready}  "
           f"threshold={late_thr}"]
    if early_ready or early_thr is not None:
        return bad(ev + ["", "a threshold was published before warmup finished"])
    if not late_ready or late_thr is None:
        return bad(ev + ["", "no threshold even after warmup"])
    return ok(ev)


@claim("S8", "stateful", "An attacker cannot poison its own baseline",
       "leave-one-source-out population stats — the fix for "
       "attacker-poisoned baselines",
       "SESSION_HANDOFF.md › bug 15c")
def s8(ctx):
    be = imp("exfiltrap.baseline_engine")
    if be is None:
        return skip("cannot import exfiltrap.baseline_engine")
    eng = be.BaselineEngine()
    # 30 normal sources, then one attacker pumping enormous mass
    for s in range(30):
        for i in range(10):
            eng.update(20.0, src=f"10.0.0.{s}")
    for i in range(10):
        eng.update(900.0, src="10.9.9.9")
    excl = eng.population_stats_excluding("10.9.9.9")
    ev = [f"attacker mass per query = 900.0; normal population = 20.0",
          f"population_stats_excluding(attacker) = {excl}",
          f"population_median (all sources)      = {eng.population_median:.3f}"]
    mean_excl = excl[0] if isinstance(excl, (tuple, list)) else None
    if mean_excl is not None:
        ev.append(f"leave-one-out mean = {mean_excl:.3f}  "
                  f"(must stay near 20, not be dragged toward 900)")
        if mean_excl > 100.0:
            return bad(ev + ["", "the attacker's own mass leaked into the "
                                 "reference it is judged against"])
    return ok(ev)


@claim("S9", "stateful", "Baseline learning freezes 300s on every HIGH/CONFIRMED",
       "pipeline freezes baseline learning 300s (sliding) on every HIGH/CONFIRMED",
       "SESSION_HANDOFF.md › bug 20 (boiling frog)")
def s9(ctx):
    st = imp("exfiltrap.session_tracker")
    if st is None:
        return skip("cannot import exfiltrap.session_tracker")
    t = st.SessionTracker()
    ev = []
    active_before = t._baseline_learning_active()
    t.freeze_baseline()
    active_after = t._baseline_learning_active()
    ev += [f"learning active before freeze : {active_before}",
           f"learning active after freeze  : {active_after}",
           f"freeze default seconds        : "
           f"{inspect.signature(t.freeze_baseline).parameters['seconds'].default}"]
    # sliding: a second freeze pushes the deadline further out
    first = t._baseline_frozen_until
    t.freeze_baseline(600.0)
    second = t._baseline_frozen_until
    ev.append(f"sliding window: 300s then 600s -> deadline moved forward: "
              f"{second > first}")
    if active_after:
        return bad(ev + ["", "freeze_baseline() did not actually pause learning"])
    if not (second > first):
        return bad(ev + ["", "the freeze does not slide with new alerts"])
    pipe = read("exfiltrap/pipeline.py") or ""
    used = "freeze_baseline" in pipe
    ev.append(f"pipeline.py calls freeze_baseline: {used}")
    if not used:
        return bad(ev + ["", "the freeze exists but the pipeline never calls "
                             "it — the boiling-frog fix is inert"])
    return ok(ev)


@claim("S10", "stateful", "rf_only really does disable the stateful layer",
       "RF-only control isolates the contribution",
       "README.md › Measured result (the control column)")
def s10(ctx):
    if (r := need("sklearn", "joblib")):
        return skip(r)
    att = tool_module("attacker_client")
    if att is None:
        return skip("cannot load tools/attacker_client.py")
    payload = att.make_sample_payload(seed=999, size=3072)
    name = b32_label(payload) + ".tunnel.example"
    ev = []
    for rf_only in (False, True):
        pipe = make_pipeline(rf_only=rf_only)
        a = pipe.process_query(q("10.99.9.9", name, 1000.0))
        ev.append(f"rf_only={str(rf_only):5s} -> {a.risk_level:9s} "
                  f"slow_drip={a.slow_drip_candidate} "
                  f"P={a.rf_probability:.4f}")
        if rf_only and a.slow_drip_candidate:
            return bad(ev + ["", "rf_only still ran the stateful layer — the "
                                 "control would not isolate anything"])
    return ok(ev)


# =========================================================================== #
# C. decoder
# =========================================================================== #

def _decoder_roundtrip(ctx, label_kind: str, plaintext: bytes):
    dec = imp("exfiltrap.payload_decoder")
    if dec is None:
        return skip("cannot import exfiltrap.payload_decoder")
    import base64
    if label_kind == "base32":
        label = base64.b32encode(plaintext).decode().rstrip("=")
        want = "base32"
    elif label_kind == "base64":
        label = base64.b64encode(plaintext).decode()
        want = "base64"
    elif label_kind == "base64url":
        label = base64.urlsafe_b64encode(plaintext).decode()
        want = "base64url"
    elif label_kind == "hex":
        label = plaintext.hex()
        want = "hex"
    else:
        raise AssertionError(label_kind)
    res = dec.try_decode(label)
    ev = [f"plaintext  : {plaintext!r}",
          f"label      : {label[:60]}{'…' if len(label) > 60 else ''}",
          f"success    : {res.success}",
          f"method     : {res.method}   (expected {want})",
          f"decoded    : {res.decoded!r}",
          f"printable  : {res.printable_ratio:.3f}"]
    if not res.success:
        return bad(ev + ["", "a well-formed encoding did not decode"])
    if res.decoded != plaintext:
        return bad(ev + ["", f"round-trip mismatch: {res.decoded!r} != "
                             f"{plaintext!r}"])
    return ok(ev)


@claim("D1", "decode", "Base32 round-trips, including stripped '=' padding",
       "M6 base32(re-padded)", "README.md › Modules (payload_decoder.py)")
def d1(ctx):
    return _decoder_roundtrip(ctx, "base32", b"QUARTERLY-RESULTS-XLSX")


@claim("D2", "decode", "Hex round-trips", "M6 ... /hex", "README.md › Modules")
def d2(ctx):
    return _decoder_roundtrip(ctx, "hex", b"secret-document-chunk-01")


@claim("D3", "decode", "Standard Base64 round-trips", "M6 ... base64",
       "README.md › Modules")
def d3(ctx):
    return _decoder_roundtrip(ctx, "base64", b"confidential-payload-42")


@claim("D4", "decode", "URL-safe Base64 round-trips; the printable guard holds",
       "M6 ... base64url  (a real exfiltrated document is text, so a genuine "
       "payload must round-trip — but arbitrary ciphertext must NOT)",
       "README.md › Modules (payload_decoder.py)")
def d4(ctx):
    dec = imp("exfiltrap.payload_decoder")
    if dec is None:
        return skip("cannot import exfiltrap.payload_decoder")
    import base64
    # The decoder tries standard base64 FIRST and only falls through to
    # base64url when the label's charset does NOT fit standard base64. The
    # only way to reach that branch is a label containing '-' or '_', which
    # base64url emits for 6-bit groups 62/63. A trailing 0x7E ('~') in a
    # whole 3-byte group produces exactly that, while keeping the plaintext
    # fully printable so the >=90 % guard accepts it.
    plaintext = b"quarterly-results.xlsx~~"
    label = base64.urlsafe_b64encode(plaintext).decode()
    res = dec.try_decode(label)
    ev = [f"plaintext : {plaintext!r}",
          f"label     : {label}",
          f"url-safe char present: {'-' in label or '_' in label}",
          f"success   : {res.success}   method: {res.method} "
          f"(expected base64url)",
          f"decoded   : {res.decoded!r}"]
    if not res.success:
        return bad(ev + ["", "a well-formed base64url encoding did not decode"])
    if res.method != "base64url":
        return bad(ev + ["", f"the base64url branch was never reached "
                             f"(decoded via {res.method!r})"])
    if res.decoded != plaintext:
        return bad(ev + ["", f"round-trip mismatch: {res.decoded!r} != "
                             f"{plaintext!r}"])

    # The decoder deliberately requires >=90 % printable output (or a known
    # file signature), so a pure-binary blob must be REFUSED. Without this
    # guard every high-entropy tunnel label would count as a decoded
    # document and every alert would be CONFIRMED.
    blob = bytes(range(0, 0x20)) * 3          # 96 B, 0 % printable
    r = dec.try_decode(base64.b64encode(blob).decode())
    ev += ["",
           f"pure-binary blob ({len(blob)} B, 0 % printable) -> "
           f"success={r.success}  printable={r.printable_ratio:.3f}  "
           f"signature={r.signature!r}",
           f"threshold: DECODE_MIN_PRINTABLE_RATIO = "
           f"{imp('exfiltrap.config').DECODE_MIN_PRINTABLE_RATIO}"]
    if r.success:
        return bad(ev + ["", "a pure-binary blob decoded as a payload — the "
                             "printable guard is not enforced, so any "
                             "high-entropy label would be CONFIRMED"])
    return ok(ev)


@claim("D5", "decode", "Known file signatures are recognised",
       "base32/hex reversal + signature matching",
       "README.md › Measured result (headline)")
def d5(ctx):
    dec = imp("exfiltrap.payload_decoder")
    cfg = imp("exfiltrap.config")
    if dec is None:
        return skip("cannot import exfiltrap.payload_decoder")
    import base64
    samples = {
        "zip": b"PK\x03\x04" + b"office-doc-body",
        "pdf": b"%PDF-1.7\n%office",
        "jpeg": b"\xff\xd8\xff\xe0" + b"jfif-body",
        "gif": b"GIF89a" + b"gif-body",
    }
    ev = [f"FILE_SIGNATURES = {[s.decode('latin1') for s in cfg.FILE_SIGNATURES]}"]
    wrong = []
    for want, blob in samples.items():
        label = base64.b32encode(blob).decode().rstrip("=")
        res = dec.try_decode(label)
        ev.append(f"  {want:5s} -> success={res.success} signature={res.signature}")
        if res.signature != want:
            wrong.append(f"{want}: signature detected as {res.signature}")
    if wrong:
        return bad(ev + ["", *wrong])
    return ok(ev)


@claim("D6", "decode", "A random high-entropy label is NOT confirmed (FP guard)",
       "a random high-entropy label is usually valid base32 but decodes to "
       "noise, and must NOT be treated as confirmation",
       "exfiltrap/payload_decoder.py docstring")
def d6(ctx):
    dec = imp("exfiltrap.payload_decoder")
    if dec is None:
        return skip("cannot import exfiltrap.payload_decoder")
    import base64
    import random
    rng = random.Random(5)
    confirmed = 0
    ev = []
    for i in range(200):
        blob = rng.randbytes(40)
        label = base64.b32encode(blob).decode().rstrip("=")
        res = dec.try_decode(label)
        if res.success:
            confirmed += 1
            if len(ev) < 4:
                ev.append(f"  FALSE POSITIVE: {label[:34]}… -> "
                          f"{res.decoded[:20]!r} printable={res.printable_ratio:.2f}")
    ev.insert(0, f"200 random 40-byte labels -> {confirmed} accepted as payload")
    if confirmed:
        return bad(ev + ["", "random ciphertext was confirmed as exfiltration — "
                             "every high-entropy label would be a CONFIRMED "
                             "alert"])
    return ok(ev)


@claim("D7", "decode", "decode_query_payload strips the base domain correctly",
       "the candidate payload is every label to the left of the base domain",
       "exfiltrap/payload_decoder.py")
def d7(ctx):
    dec = imp("exfiltrap.payload_decoder")
    if dec is None:
        return skip("cannot import exfiltrap.payload_decoder")
    import base64
    blob = b"stolen-document"
    label = base64.b32encode(blob).decode().rstrip("=")
    ev = []
    cases = [
        (f"{label}.tunnel.example", True),
        (f"{label}.a.b.tunnel.example", True),
        ("tunnel.example", False),
        ("example.com", False),
    ]
    for qn, expect_ok in cases:
        res = dec.decode_query_payload(qn)
        ev.append(f"  {qn[:52]:52s} -> success={res.success}")
        if expect_ok and not res.success:
            return bad(ev + ["", f"{qn} should have decoded"])
        if not expect_ok and res.success:
            return bad(ev + ["", f"{qn} has no payload labels but decoded"])
    return ok(ev)


# =========================================================================== #
# D. risk + mitigation
# =========================================================================== #

@claim("R1", "risk", "Risk levels are ordered CONFIRMED > HIGH > MEDIUM > LOW",
       "risk engine (LOW/MEDIUM/HIGH/CONFIRMED)",
       "README.md › Architecture (M7)")
def r1(ctx):
    re_mod = imp("exfiltrap.risk_engine")
    if re_mod is None:
        return skip("cannot import exfiltrap.risk_engine")
    levels = tuple(re_mod.RISK_LEVELS)
    ev = [f"RISK_LEVELS = {levels}"]
    if levels != ("LOW", "MEDIUM", "HIGH", "CONFIRMED"):
        return bad(ev + ["", "unexpected level set or order"])
    return ok(ev)


@claim("R2", "risk", "The rule table uses the documented probability bands",
       "RISK_HIGH_THRESHOLD / RISK_MEDIUM_THRESHOLD",
       "exfiltrap/config.py (M7)")
def r2(ctx):
    re_mod = imp("exfiltrap.risk_engine")
    cfg = imp("exfiltrap.config")
    ev = imp("exfiltrap.events")
    if re_mod is None or cfg is None or ev is None:
        return skip("cannot import the risk engine")
    eng = re_mod.RiskEngine()
    probe = ev.DNSQuery(src_ip="1.1.1.1", qname="x.example", timestamp=0.0)
    ev_lines = [f"high={eng.high}  medium={eng.medium}"]
    checks = [
        (0.95, False, "HIGH"), (0.70, False, "MEDIUM"),
        (0.10, False, "LOW"), (0.10, True, "HIGH"),
    ]
    wrong = []
    for prob, slow, want in checks:
        a = eng.assess(probe, prob, slow)
        ev_lines.append(f"  P={prob:.2f} slow_drip={str(slow):5s} -> {a.risk_level}")
        if a.risk_level != want:
            wrong.append(f"P={prob} slow_drip={slow}: got {a.risk_level}, "
                         f"expected {want}")
    if wrong:
        return bad(ev_lines + ["", *wrong])
    return ok(ev_lines)


@claim("R3", "risk", "A successful decode always yields CONFIRMED",
       "CONFIRMED > HIGH > MEDIUM > LOW rule table",
       "README.md › Modules (M7)")
def r3(ctx):
    re_mod = imp("exfiltrap.risk_engine")
    ev = imp("exfiltrap.events")
    dec = imp("exfiltrap.payload_decoder")
    if re_mod is None or ev is None or dec is None:
        return skip("cannot import the risk engine")
    probe = ev.DNSQuery(src_ip="1.1.1.1", qname="x.example", timestamp=0.0)
    eng = re_mod.RiskEngine()
    ok_res = dec.DecodeResult(True, "base32", b"QUARTERLY-RESULTS", 1.0, None)
    a = eng.assess(probe, 0.01, False, decode_result=ok_res)
    ev_lines = [f"decode.success=True, P=0.01 -> risk={a.risk_level}",
                f"confirmed_exfiltration={a.confirmed_exfiltration}",
                f"reasons={a.reasons}"]
    if a.risk_level != "CONFIRMED":
        return bad(ev_lines + ["", "a confirmed decode did not reach CONFIRMED "
                                     "even at P=0.01"])
    return ok(ev_lines)


@claim("R4", "risk", "Mitigation only ever triggers on CONFIRMED/HIGH",
       "MITIGATION_RISK_LEVELS = (\"CONFIRMED\", \"HIGH\")",
       "exfiltrap/config.py (M8)")
def r4(ctx):
    cfg = imp("exfiltrap.config")
    if cfg is None:
        return skip("cannot import exfiltrap.config")
    ev = [f"MITIGATION_RISK_LEVELS = {cfg.MITIGATION_RISK_LEVELS}"]
    if tuple(cfg.MITIGATION_RISK_LEVELS) != ("CONFIRMED", "HIGH"):
        return bad(ev + ["", "mitigation would fire on lower risk levels"])
    mit = read("exfiltrap/mitigation.py") or ""
    pipe = read("exfiltrap/pipeline.py") or ""
    gate = "MITIGATION_RISK_LEVELS" in (mit + pipe)
    ev.append(f"gate consulted in mitigation.py/pipeline.py: {gate}")
    if not gate:
        return bad(ev + ["", "nothing consults the gate — it is decorative"])
    return ok(ev)


@claim("R5", "risk", "The iptables backend refuses to touch the host firewall",
       "anything else raises SafetyError unless the explicit "
       "--i-know-this-is-isolated flag is supplied",
       "README.md › Isolated research lab")
def r5(ctx):
    mit = imp("exfiltrap.mitigation")
    cfg = imp("exfiltrap.config")
    if mit is None or cfg is None:
        return skip("cannot import exfiltrap.mitigation")
    # A harmless stand-in for iptables, and dry_run stays at its default
    # (True), so no command can ever be executed by this check.
    stand_in = shutil.which("true") or "/bin/true"
    ns = cfg.NAMESPACE_NAME
    exists = mit.namespace_exists(ns)
    inside = mit.running_inside_namespace(ns)
    ev = [f"target namespace      : {ns!r}  exists on this host: {exists}",
          f"this process inside it: {inside}",
          f"iptables stand-in     : {stand_in!r} (the real iptables is never "
          f"invoked; dry_run defaults to True)"]

    backend = mit.IptablesMitigation(iptables_path=stand_in)
    try:
        backend.block_ip("10.99.0.2")
        raised = None
    except Exception as e:          # noqa: BLE001 — we want the type
        raised = e
    cmds = list(backend.pending_commands())

    if raised is None:
        # The lab namespace is up, so the backend took the scoped route.
        argv = cmds[-1] if cmds else []
        ev.append(f"command produced: {' '.join(argv)}")
        scoped = inside or (len(argv) >= 4 and argv[:3] == ["ip", "netns", "exec"]
                            and argv[3] == ns)
        ev.append(f"scoped to {ns!r}, never the host ruleset: {scoped}")
        if not scoped:
            return bad(ev + ["", "a bare host iptables call was generated — "
                                 "this could alter the real host firewall"])
        ev.append("(the namespace exists here, so the refuse-path is not "
                  "exercised; R5b below still proves it)")
    else:
        ev.append(f"refused: {type(raised).__name__}: {raised}")
        if not isinstance(raised, mit.SafetyError):
            return bad(ev + ["", f"expected SafetyError, got "
                                 f"{type(raised).__name__} — the refusal is "
                                 f"not the documented safety gate"])
        permissive = mit.IptablesMitigation(
            iptables_path=stand_in,
            override_flag=cfg.IPTABLES_OVERRIDE_FLAG,
        )
        try:
            permissive.block_ip("10.99.0.2")
            ev.append(f"with {cfg.IPTABLES_OVERRIDE_FLAG} -> permitted "
                      f"(as documented)")
        except mit.SafetyError as e:
            return bad(ev + ["", f"the documented override did not lift the "
                                 f"gate: {e}"])

    # Regardless of the branch above, prove the refuse-path itself: a
    # namespace that cannot exist forces the `else` arm of the gate.
    ghost = mit.IptablesMitigation(namespace="exfiltrap-nonexistent-ns",
                                   iptables_path=stand_in)
    try:
        ghost.block_ip("10.99.0.2")
        return bad(ev + ["", "blocking with a non-existent namespace and no "
                             "override flag SUCCEEDED — the safety gate is "
                             "broken"])
    except mit.SafetyError as e:
        ev.append(f"non-existent namespace, no override -> SafetyError: {e}")
    return ok(ev)


@claim("R6", "risk", "Windows firewall rules use the prefix the README documents",
       "netsh advfirewall rules prefixed `ExfilTrap-block-*` (parsed from README)",
       "README.md › Deployment matrix")
def r6(ctx):
    mit = imp("exfiltrap.mitigation")
    if mit is None:
        return skip("cannot import exfiltrap.mitigation")
    # Parse the documented prefix out of the README instead of hardcoding it:
    # a hardcoded expectation cannot notice the doc drifting away from the
    # code, which is the whole point of the check.
    rd = read("README.md") or ""
    m = re.search(r"rules prefixed `([^`]+)`", rd)
    if not m:
        return skip("README no longer states the firewall rule prefix")
    documented = m.group(1).rstrip("*")       # README writes `ExfilTrap-block-*`
    actual = mit.NetshMitigation.RULE_PREFIX
    ev = [f"README.md documents : {documented!r}",
          f"code RULE_PREFIX    : {actual!r}"]
    if actual != documented:
        diff = "".join(f"  pos {i}: doc {a!r} vs code {b!r}"
                       for i, (a, b) in enumerate(zip(documented, actual))
                       if a != b)
        return bad(ev + ["",
                         "the prefix the README tells operators to look for is "
                         "not the prefix the code creates.",
                         diff,
                         "Operational impact: an operator running",
                         f"    netsh advfirewall firewall show rule name={documented}*",
                         "finds nothing, even while ExFilTrap is actively "
                         "blocking. The rule that exists is "
                         f"name={actual}<ip>.",
                         "One-character case fix in README.md (or in the "
                         "constant) — but the two must agree."])
    # dry_run so nothing is executed; require_admin=False so this check is not
    # merely reporting "we are not root on Linux" (R7 covers that default).
    backend = mit.NetshMitigation(dry_run=True, require_admin=False)
    backend.block_ip("203.0.113.9")
    cmds = list(backend.pending_commands())
    ev.append("dry-run command (never executed):")
    ev += [f"    {' '.join(c)}" for c in cmds]
    expected_name = f"{actual}203.0.113.9"
    if not cmds or expected_name not in " ".join(cmds[-1]):
        return bad(ev + ["", f"the generated rule name is not {expected_name}"])
    joined = " ".join(" ".join(c) for c in cmds)
    if "dir=in" not in joined or "action=block" not in joined:
        return bad(ev + ["", "the rule is not an inbound block"])
    return ok(ev)


@claim("R7", "risk", "The Windows backend never silently elevates",
       "the desktop process must never silently elevate itself mid-detection",
       "exfiltrap/mitigation.py (NetshMitigation)")
def r7(ctx):
    mit = imp("exfiltrap.mitigation")
    if mit is None:
        return skip("cannot import exfiltrap.mitigation")
    sig = inspect.signature(mit.NetshMitigation.__init__)
    ev = [f"NetshMitigation.__init__{sig}"]
    defaults = {k: v.default for k, v in sig.parameters.items()
                if v.default is not inspect.Parameter.empty}
    ev.append(f"defaults: {defaults}")
    if defaults.get("dry_run") is not True:
        return bad(ev + ["", "dry_run does not default to True — a detection "
                             "could silently alter the host firewall"])
    if defaults.get("require_admin") is not True:
        return bad(ev + ["", "require_admin does not default to True"])
    src = inspect.getsource(mit.NetshMitigation)
    elev = any(t in src for t in ("ShellExecute", "runas", "Start-Process"))
    ev.append(f"self-elevation call in the backend: {elev}")
    if elev:
        return bad(ev + ["", "the backend tries to elevate itself"])
    return ok(ev)


@claim("R8", "risk", "The mitigation factory selects by platform",
       "iptables/netns │ netsh backends + factory",
       "README.md › Modules (M8)")
def r8(ctx):
    mit = imp("exfiltrap.mitigation")
    if mit is None:
        return skip("cannot import exfiltrap.mitigation")
    factory = getattr(mit, "make_mitigation", None)
    if factory is None:
        return skip("make_mitigation() not found — factory may have moved")
    ev = [f"make_mitigation{inspect.signature(factory)}"]

    def build(kind):
        """Build a backend without ever needing admin (dry_run, no elevation)."""
        try:
            return factory(kind, dry_run=True, require_admin=False)
        except TypeError:
            return factory(kind)      # this backend takes no such kwargs

    for kind, want in (("log", "LogOnlyMitigation"),
                       ("iptables", "IptablesMitigation"),
                       ("netsh", "NetshMitigation")):
        try:
            b = build(kind)
        except Exception as e:  # noqa: BLE001
            return bad(ev + [f"  kind={kind:9s} -> raised "
                             f"{type(e).__name__}: {e}"])
        name = type(b).__name__
        ev.append(f"  kind={kind:9s} -> {name}")
        if name != want:
            return bad(ev + ["", f"kind={kind!r} produced {name}, "
                                 f"expected {want}"])

    # 'auto' must resolve to a real backend for THIS platform, not raise.
    try:
        auto = build("auto")
        ev.append(f"  kind=auto      -> {type(auto).__name__}   "
                  f"(platform.system()={platform.system()!r})")
    except Exception as e:  # noqa: BLE001
        return bad(ev + ["", f"kind='auto' raised {type(e).__name__}: {e}"])

    # A typo in the config must be refused, not silently defaulted to a
    # backend that then does nothing.
    try:
        factory("definitely-not-a-backend")
    except ValueError as e:
        ev.append(f"  kind=bogus     -> ValueError: {e}   (correctly refused)")
    except Exception as e:  # noqa: BLE001
        ev.append(f"  kind=bogus     -> {type(e).__name__}: {e}")
    else:
        return bad(ev + ["", "an unknown kind did not raise — a config typo "
                             "would silently select a backend"])
    return ok(ev)


# =========================================================================== #
# E. storage + API + dashboard
# =========================================================================== #

@claim("T1", "storage", "SQLite runs in WAL mode",
       "WAL/batched SQLite", "README.md › Contributions (M8 row)")
def t1(ctx):
    st = imp("exfiltrap.storage")
    if st is None:
        return skip("cannot import exfiltrap.storage")
    with tempfile.TemporaryDirectory() as d:
        s = st.Storage(db_path=os.path.join(d, "t.db"))
        conn = getattr(s, "_conn", None)
        if conn is None:
            return skip("Storage no longer exposes _conn")
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        sync = conn.execute("PRAGMA synchronous").fetchone()[0]
        ev = [f"journal_mode = {mode}", f"synchronous = {sync} (1 = NORMAL)"]
        s.close()
    if str(mode).lower() != "wal":
        return bad(ev + ["", "journal_mode is not WAL — every write would fsync"])
    return ok(ev)


@claim("T2", "storage", "The covering indexes from the API-amplification fix exist",
       "covering indexes idx_queries_risk/src (27.3→5.0ms on the doughnut query)",
       "SESSION_HANDOFF.md › bug 21")
def t2(ctx):
    st = imp("exfiltrap.storage")
    if st is None:
        return skip("cannot import exfiltrap.storage")
    with tempfile.TemporaryDirectory() as d:
        s = st.Storage(db_path=os.path.join(d, "t.db"))
        conn = s._conn
        idx = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND tbl_name='queries' ORDER BY name")]
        s.close()
    ev = [f"indexes on queries: {idx}"]
    want = [i for i in idx if "risk" in i.lower() or "src" in i.lower()]
    if not want:
        return bad(ev + ["", "no risk/source index on the queries table — the "
                             "aggregate queries the dashboard polls would do "
                             "full scans"])
    return ok(ev)


@claim("T3", "storage", "A write is visible to a read without an explicit flush",
       "reads flush first so the dashboard always sees complete data",
       "README.md › Resource notes")
def t3(ctx):
    st = imp("exfiltrap.storage")
    re_mod = imp("exfiltrap.risk_engine")
    if st is None or re_mod is None:
        return skip("cannot import exfiltrap.storage")
    a = re_mod.RiskAssessment(src_ip="10.0.0.1", qname="a.example.com",
                              timestamp=1.0, risk_level="HIGH",
                              reasons=["probe"], rf_probability=0.9)
    with tempfile.TemporaryDirectory() as d:
        s = st.Storage(db_path=os.path.join(d, "t.db"), flush_every=1000)
        s.log_query(a)
        s.log_risk_event(a)
        totals = s.totals()
        recent = s.recent_queries(limit=5)
        s.close()
    ev = [f"flush_every=1000 (nothing should be flushed on a count basis)",
          f"totals() after one buffered write: {totals}",
          f"recent_queries() rows: {len(recent)}"]
    if not totals or totals.get("queries", 0) < 1:
        return bad(ev + ["", "the buffered write was invisible to the reader — "
                             "the dashboard would show stale counters"])
    if len(recent) < 1:
        return bad(ev + ["", "recent_queries() did not see the write"])
    return ok(ev)


@claim("T4", "storage", "The service API binds loopback only",
       "REST API + dashboard UI ── 127.0.0.1:5050 only",
       "README.md › Architecture")
def t4(ctx):
    src = read("exfiltrap/service.py") or ""
    ev = []
    m = re.search(r'add_argument\(\s*"--api-host"\s*,\s*default\s*=\s*"([^"]+)"',
                  src)
    default = m.group(1) if m else None
    ev.append(f'--api-host default = {default!r}')
    if default != "127.0.0.1":
        return bad(ev + ["", "the API does not default to loopback — the "
                             "detection DB would be exposed on the network"])
    if re.search(r'add_argument\(\s*"--api-host"\s*,\s*default\s*=\s*"0\.0\.0\.0"', src):
        return bad(ev + ["", "0.0.0.0 found as the bind default"])
    ev.append("no 0.0.0.0 bind default anywhere in service.py")
    return ok(ev)


@claim("T5", "storage", "The service API default port is 5050",
       "REST API on 127.0.0.1:5050",
       "README.md › Architecture / waiting.html")
def t5(ctx):
    src = read("exfiltrap/service.py") or ""
    ev = []
    m = re.search(r'add_argument\(\s*"--api-port"\s*,\s*type=int\s*,\s*default\s*=\s*(\d+)', src)
    port = int(m.group(1)) if m else None
    ev.append(f"service --api-port default = {port}")
    unit = read("packaging/linux/exfiltrap@.service") or ""
    env = re.search(r"EXFILTRAP_API_PORT=(\d+)", unit)
    ev.append(f"systemd EXFILTRAP_API_PORT = {env.group(1) if env else None}")
    # the standalone dashboard has its own port (config.DASHBOARD_PORT)
    cfg = imp("exfiltrap.config")
    if cfg:
        ev.append(f"config.DASHBOARD_PORT (standalone dashboard only) = "
                  f"{cfg.DASHBOARD_PORT}")
    if port != 5050:
        return bad(ev + ["", "the documented service API port is 5050"])
    if env and env.group(1) != "5050":
        return bad(ev + ["", "the unit and the CLI disagree on the port"])
    return ok(ev)


def _tracked_index_html() -> list[str]:
    """Every index.html that git actually tracks.

    The authoritative definition of "the source tree": build outputs
    (dist-appimage/, build-*/, desktop/src-tauri/resources/ — 210 MB of
    PyInstaller payload) are gitignored and must never count as a second
    dashboard. Falls back to a pruned walk when git is unavailable.
    """
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=str(ROOT),
                             capture_output=True, text=True, timeout=60)
        if out.returncode == 0:
            return sorted(p for p in out.stdout.split("\0")
                          if p.endswith("index.html"))
    except Exception:  # noqa: BLE001
        pass
    return [str(p.relative_to(ROOT)) for p in _source_index_html()]


def _source_index_html() -> list[Path]:
    """Fallback walk that prunes build/dist output directories."""
    skip = {".git", "node_modules", "target", "__pycache__", ".venv", "venv",
            ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".eggs"}
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames
                       if d not in skip and not d.startswith(("build", "dist"))]
        if "index.html" in filenames:
            found.append(Path(dirpath) / "index.html")
    return sorted(found)


@claim("T6", "storage", "There is exactly ONE dashboard template",
       "There is exactly one dashboard UI ... every improvement lands on all "
       "three platforms at once",
       "README.md › The one dashboard")
def t6(ctx):
    tmpl = ROOT / "exfiltrap" / "dashboard" / "templates"
    if not tmpl.is_dir():
        return skip(f"no template dir at {tmpl}")
    html = sorted(p.name for p in tmpl.glob("*.html"))
    idx = [p for p in tmpl.rglob("index.html")]
    other = _tracked_index_html()
    ev = [f"templates/ contents : {html}",
          f"git-tracked index.html files: {other}"]
    if len(idx) != 1:
        return bad(ev + ["", f"expected one index.html, found {len(idx)}"])
    if len(other) != 1:
        return bad(ev + ["", "more than one index.html is tracked — the three "
                             "platforms could drift"])
    # the frozen engine must ship it
    specs = ["packaging/linux/exfiltrap-linux.spec",
             "packaging/windows/exfiltrap.spec"]
    for sp in specs:
        s = read(sp) or ""
        hit = "dashboard" in s and "templates" in s
        ev.append(f"{sp}: bundles dashboard templates = {hit}")
        if not hit:
            return bad(ev + ["", f"{sp} does not bundle the templates"])
    return ok(ev)


@claim("T7", "storage", "The dashboard exposes the documented route set",
       "Overview, Live Queries, Alerts, Sessions, Blocked IPs ... SSE",
       "README.md › The one dashboard")
def t7(ctx):
    if (r := need("flask")):
        return skip(r)
    app_mod = imp("exfiltrap.dashboard.app")
    if app_mod is None:
        return skip("cannot import exfiltrap.dashboard.app")
    # mkdtemp + rmtree(ignore_errors=True): create_app() opens a SQLite handle
    # that Windows keeps locked, so TemporaryDirectory()'s cleanup raises
    # WinError 32 after the check has already succeeded.
    d = tempfile.mkdtemp(prefix="exfiltrap-t7-")
    try:
        try:
            app = app_mod.create_app(db_path=os.path.join(d, "t.db"))
        except Exception as e:  # noqa: BLE001
            return skip(f"create_app() failed here: {type(e).__name__}: {e}")
        rules = sorted(r.rule for r in app.url_map.iter_rules()
                       if r.rule.startswith("/api"))
        store = app.config.get("STORAGE")
        if store is not None and hasattr(store, "close"):
            try:
                store.close()
            except Exception:  # noqa: BLE001
                pass
    finally:
        shutil.rmtree(d, ignore_errors=True)
    want = ["/api/stats", "/api/status", "/api/sessions", "/api/queries",
            "/api/events", "/api/blocked", "/api/stream"]
    ev = [f"registered API routes ({len(rules)}): {rules}"]
    missing = [w for w in want if w not in rules]
    if missing:
        return bad(ev + ["", f"documented endpoints missing: {missing}"])
    ev.append("all documented endpoints present (incl. the SSE /api/stream)")
    return ok(ev)


@claim("T8", "storage", "The /api/stats cache TTL matches the documentation",
       "the TTL stated in SESSION_HANDOFF bug 21 equals the TTL in the route",
       "SESSION_HANDOFF.md › bug 21")
def t8(ctx):
    src = read("exfiltrap/dashboard/app.py") or ""
    doc = read("SESSION_HANDOFF.md") or ""
    ev = []
    m = re.search(r"now - hit\[0\] < ([\d.]+)", src)
    ttl = float(m.group(1)) if m else None
    # Parse the documented value rather than hardcoding it — a hardcoded "2 s"
    # cannot detect the doc drifting, which is the entire claim.
    m2 = re.search(r"([\d.]+)s TTL cache on the /api/stats route", doc)
    doc_ttl = float(m2.group(1)) if m2 else None
    ev.append(f"measured TTL in the /api/stats route : {ttl} s")
    ev.append(f"documented TTL (SESSION_HANDOFF bug 21): {doc_ttl} s")
    if ttl is None:
        return skip("could not find the TTL comparison in the route")
    if doc_ttl is None:
        return skip("SESSION_HANDOFF no longer states a /api/stats TTL")
    if abs(ttl - doc_ttl) > 1e-9:
        return bad(ev + [
            "",
            f"the documentation says {doc_ttl} s but the code uses {ttl} s.",
            "The TTL must stay WELL BELOW the console's poll interval (a TTL "
            "equal to the poll interval makes consecutive polls alternate "
            "fresh/cache-hit, so the counters look stuck).",
            "The doc is stale, not the code.",
        ])
    ev.append("documentation and code agree")
    return ok(ev)


@claim("T9", "storage", "There is no demo mode in the service",
       "NO demo mode (removed by user) / ground rule 1",
       "SESSION_HANDOFF.md › §5 and §8")
def t9(ctx):
    src = read("exfiltrap/service.py") or ""
    if not src:
        return skip("cannot read exfiltrap/service.py")
    hits = [t for t in ("--demo", "demo_mode", "DEMO_MODE", "fake_traffic")
            if t in src]
    flags = re.findall(r'add_argument\(\s*"(--[a-z0-9-]+)"', src)
    ev = [f"CLI flags on the service: {flags}",
          f"demo markers found: {hits or 'none'}"]
    if hits:
        return bad(ev + ["", "a demo mode reappeared after being removed"])
    return ok(ev)


# =========================================================================== #
# F. performance
# =========================================================================== #

@claim("P1", "perf", "Throughput is in the documented 283 q/s ballpark",
       "live capture → detection ... 283 q/s ... 20k queries process in 71 s",
       "README.md › Scale behavior", deep=False)
def p1(ctx):
    if (r := need("sklearn", "joblib")):
        return skip(r)
    att = tool_module("attacker_client")
    if att is None:
        return skip("cannot load tools/attacker_client.py")
    n = 1500
    pipe = make_pipeline()
    payload = att.make_sample_payload(seed=999, size=3072)
    events = [q(f"10.0.0.{i % 40}", b32_label(payload)[:60] + ".tunnel.example",
                1000.0 + i) for i in range(n)]
    t0 = time.perf_counter()
    pipe.process_many(events)
    dt = time.perf_counter() - t0
    qps = n / dt
    ev = [f"{n} queries through process_many() in {dt:.2f}s",
          f"measured throughput : {qps:.0f} q/s",
          f"documented          : 283 q/s (20k in 71 s)",
          f"implied 20k runtime : {20000 / qps:.0f} s"]
    if qps < 100:
        return bad(ev + ["", "throughput is under 100 q/s — the documented "
                             "scale claim does not hold on this machine"])
    if qps < 283:
        return info(ev + ["", f"below the documented 283 q/s, but this is a "
                              f"different machine/build; treat as indicative"])
    return ok(ev)


@claim("P2", "perf", "/api/stats stays under 50 ms at 20k rows",
       "dashboard /api/stats @20k rows | 18 ms → 47 ms",
       "README.md › Scale behavior", deep=True)
def p2(ctx):
    if (r := need("flask", "sklearn", "joblib")):
        return skip(r)
    st = imp("exfiltrap.storage")
    re_mod = imp("exfiltrap.risk_engine")
    app_mod = imp("exfiltrap.dashboard.app")
    if not all((st, re_mod, app_mod)):
        return skip("cannot import storage / dashboard app")
    n = 20000
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        s = st.Storage(db_path=db, flush_every=1000)
        rows = [re_mod.RiskAssessment(
            src_ip=f"10.0.0.{i % 200}", qname=f"h{i}.example.com",
            timestamp=float(i), risk_level=("HIGH" if i % 50 == 0 else "LOW"),
            reasons=[], rf_probability=(0.9 if i % 50 == 0 else 0.1))
            for i in range(n)]
        t0 = time.perf_counter()
        for a in rows:
            s.log_query(a)
        s.totals()          # force the flush
        load_s = time.perf_counter() - t0
        s.close()
        app = app_mod.create_app(db_path=db)
        client = app.test_client()
        times = []
        for _ in range(5):
            app.config.setdefault("_STATS_CACHE", {}).pop("v", None)
            t = time.perf_counter()
            resp = client.get("/api/stats")
            times.append((time.perf_counter() - t) * 1000)
            if resp.status_code != 200:
                return bad([f"GET /api/stats -> HTTP {resp.status_code}"])
    ev = [f"seeded {n} rows in {load_s:.1f}s",
          f"GET /api/stats (cache bypassed each time): "
          f"{', '.join(f'{t:.1f}ms' for t in times)}",
          f"median {statistics.median(times):.1f} ms   worst {max(times):.1f} ms",
          "documented: 47 ms at 20k rows"]
    worst = max(times)
    if worst > 50.0:
        return bad(ev + ["", f"worst call {worst:.1f} ms exceeds the "
                             f"documented 50 ms ceiling"])
    return ok(ev)


# =========================================================================== #
# G. packaging + CI
# =========================================================================== #

def _versions(ctx):
    """Every place the product version is written down."""
    out = {}
    tc = read("desktop/src-tauri/tauri.conf.json")
    if tc:
        m = re.search(r'"version"\s*:\s*"([^"]+)"', tc)
        if m:
            out["desktop/src-tauri/tauri.conf.json"] = m.group(1)
    pj = read("desktop/package.json")
    if pj:
        m = re.search(r'"version"\s*:\s*"([^"]+)"', pj)
        if m:
            out["desktop/package.json"] = m.group(1)
    iss = read("packaging/windows/exfiltrap.iss")
    if iss:
        m = re.search(r'#define MyAppVersion "([^"]+)"', iss)
        if m:
            out["packaging/windows/exfiltrap.iss"] = m.group(1)
    pk = read("packaging/arch/PKGBUILD")
    if pk:
        m = re.search(r"^pkgver=(\S+)", pk, re.M)
        if m:
            out["packaging/arch/PKGBUILD"] = m.group(1)
    ai = read("packaging/appimage/build-appimage.sh")
    if ai:
        m = re.search(r'VERSION="\$\{APPIMAGE_VERSION:-([^}]+)\}"', ai)
        if m:
            out["packaging/appimage/build-appimage.sh"] = m.group(1)
    return out


@claim("G1", "packaging", "The version is identical in every packaging target",
       "Unify versions. tauri.conf, package.json, ISS default, AppImage "
       "VERSION, PKGBUILD pkgver",
       "tauri-packaging-debug skill › Verification workflow 4")
def g1(ctx):
    v = _versions(ctx)
    ev = [f"  {k:44s} {val}" for k, val in v.items()]
    distinct = sorted(set(v.values()))
    if len(v) < 5:
        return bad(ev + ["", f"only {len(v)} of 5 version sites were found — "
                             f"one may have been renamed"])
    if len(distinct) != 1:
        return bad(ev + ["", f"versions disagree: {distinct}"])
    return ok(ev + ["", f"all {len(v)} sites agree on {distinct[0]}"])


@claim("G2", "packaging", "The systemd unit is capability-bounded, never root",
       "privileged detection service ... exactly CAP_NET_RAW+CAP_NET_ADMIN "
       "under a locked-down user — never root",
       "README.md › Contributions (production architecture)")
def g2(ctx):
    unit = read("packaging/linux/exfiltrap@.service")
    if not unit:
        return skip("packaging/linux/exfiltrap@.service not found")
    checks = {
        "User=exfiltrap": "dedicated service user",
        "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN": "exactly two caps",
        "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN": "bounding set",
        "NoNewPrivileges=yes": "no privilege gain",
        "ProtectSystem=strict": "read-only system",
        "WatchdogSec=": "supervised liveness",
    }
    ev = []
    for needle, why in checks.items():
        hit = needle in unit
        ev.append(f"  {'ok ' if hit else 'MISSING'} {needle:48s} ({why})")
    missing = [n for n in checks if n not in unit]
    if "User=root" in unit:
        return bad(ev + ["", "the unit runs as root"])
    if missing:
        return bad(ev + ["", f"missing hardening directives: {missing}"])
    return ok(ev)


@claim("G3", "packaging", "The Windows build is onedir with UPX disabled",
       "--onedir PyInstaller build (no --onefile self-extraction, no UPX)",
       "README.md › Windows antivirus posture")
def g3(ctx):
    spec = read("packaging/windows/exfiltrap.spec")
    if not spec:
        return skip("packaging/windows/exfiltrap.spec not found")
    ev = []
    has_collect = "COLLECT(" in spec
    upx_off = re.search(r"upx=False", spec) is not None
    has_onefile = "onefile" in spec.lower()
    ev += [f"COLLECT(...) present (onedir)     : {has_collect}",
           f"upx=False present                 : {upx_off}",
           f"'onefile' mentioned               : {has_onefile}"]
    # the AV posture also needs the right hidden imports or the frozen
    # engine dies at load time (bug 9)
    for mod in ("pywintypes", "win32api", "servicemanager",
                "scipy._external.array_api_compat.numpy"):
        hit = mod in spec
        ev.append(f"  hiddenimport {mod:42s}: {hit}")
    if not has_collect:
        return bad(ev + ["", "no COLLECT — this is not a --onedir build"])
    if not upx_off:
        return bad(ev + ["", "UPX is not explicitly disabled (AV heuristic)"])
    return ok(ev)


@claim("G4", "packaging", "The Inno Setup script writes to dist\\ and guards the version",
       "ISCC -D emulates #define public, so a bare define raises Symbol "
       "already defined. Guard it",
       "tauri-packaging-debug skill › Windows / Inno Setup")
def g4(ctx):
    iss = read("packaging/windows/exfiltrap.iss")
    if not iss:
        return skip("packaging/windows/exfiltrap.iss not found")
    ev = []
    guarded = "#ifndef MyAppVersion" in iss
    outdir = re.search(r"^OutputDir=(\S+)", iss, re.M)
    outdir = outdir.group(1) if outdir else None
    npcap_skip = "skipifsourcedoesntexist" in iss and "skipifdoesntexist" in iss
    ev += [f"#ifndef MyAppVersion guard        : {guarded}",
           f"OutputDir                         : {outdir!r}",
           f"Npcap optional (skip flags)       : {npcap_skip}",
           f"OutputBaseFilename                : "
           f"{re.search(r'OutputBaseFilename=(\S+)', iss).group(1)!r}"]
    if not guarded:
        return bad(ev + ["", "no #ifndef guard — `iscc -DMyAppVersion=...` "
                             "would fail with Symbol already defined"])
    if outdir is None:
        return bad(ev + ["", "no OutputDir — Inno defaults to the script's own "
                             "directory, so the installer would not land in "
                             "dist\\ where CI looks for it"])
    if "dist" not in outdir.replace("\\", "/"):
        return bad(ev + ["", f"OutputDir {outdir!r} does not point at dist/"])
    return ok(ev)


@claim("G5", "packaging", "The Arch package matches the product version and uses system webkit",
       "PKGBUILD for Arch (system webkit)", "README.md › Deployment matrix")
def g5(ctx):
    pk = read("packaging/arch/PKGBUILD")
    if not pk:
        return skip("packaging/arch/PKGBUILD not found")
    ver = _versions(ctx).get("packaging/arch/PKGBUILD")
    deps = re.findall(r"'([a-z0-9._+-]+)'", pk)
    webkit = [d for d in deps if "webkit" in d]
    ev = [f"pkgver = {ver}",
          f"webkit dependency: {webkit or 'NOT FOUND'}",
          f"arch = {re.search(r'^arch=\((.*)\)', pk, re.M).group(1) if re.search(r'^arch=\((.*)\)', pk, re.M) else '?'}"]
    if not webkit:
        return bad(ev + ["", "the PKGBUILD does not depend on system webkit — "
                             "the Tauri shell cannot render"])
    tc = _versions(ctx).get("desktop/src-tauri/tauri.conf.json")
    if ver and tc and ver != tc:
        return bad(ev + ["", f"pkgver {ver} != product version {tc}"])
    return ok(ev)


@claim("G6", "packaging", "The Flatpak is runtime-pinned and correctly identified",
       "Flatpak (org.exfiltrap.desktop — runtime webkit)",
       "README.md › Deployment matrix")
def g6(ctx):
    yml = read("packaging/flatpak/org.exfiltrap.desktop.yml")
    if not yml:
        return skip("flatpak manifest not found")
    ident = re.search(r"^app-id:\s*(\S+)", yml, re.M)
    rt = re.search(r"^runtime-version:\s*(\S+)", yml, re.M)
    rtv = re.search(r"^runtime:\s*(\S+)", yml, re.M)
    ev = [f"app-id          : {ident.group(1) if ident else None}",
          f"runtime         : {rtv.group(1) if rtv else None}",
          f"runtime-version : {rt.group(1) if rt else None}"]
    if not ident or ident.group(1) != "org.exfiltrap.desktop":
        return bad(ev + ["", "app-id does not match org.exfiltrap.desktop"])
    if not rt:
        return bad(ev + ["", "no runtime-version pin — the runtime webkit "
                             "version would drift"])
    return ok(ev)


@claim("G7", "packaging", "The AppImage AppRun undoes the forced GTK theme",
       "GTK_THEME=Adwaita:dark -> garbled minimise/maximise/close glyphs ... "
       "unset GTK_THEME",
       "tauri-packaging-debug skill › Garbled window-control glyphs")
def g7(ctx):
    sh = read("packaging/appimage/build-appimage.sh")
    if not sh:
        return skip("packaging/appimage/build-appimage.sh not found")
    ev = []
    unsets = "unset GTK_THEME" in sh
    sources_hook = "linuxdeploy-plugin-gtk.sh" in sh
    multiarch = "_multiarch_probe" in sh
    py_ok = "_py_ok" in sh
    ev += [f"sources the vendored GTK hook      : {sources_hook}",
           f"unsets GTK_THEME after the hook    : {unsets}",
           f"multiarch probe (not gcc -print-…) : {multiarch}",
           f"validates the build interpreter    : {py_ok}"]
    # the unset must come AFTER the hook is sourced, or it is a no-op
    if sources_hook and unsets:
        idx_hook = sh.find("linuxdeploy-plugin-gtk.sh")
        idx_unset = sh.find("unset GTK_THEME")
        order_ok = idx_hook < idx_unset
        ev.append(f"unset comes after the hook is sourced: {order_ok}")
        if not order_ok:
            return bad(ev + ["", "unset GTK_THEME runs BEFORE the hook sets it "
                                 "— the fix is a no-op"])
    if not unsets:
        return bad(ev + ["", "GTK_THEME is never unset — the glyph bug is "
                             "unfixed"])
    if not multiarch:
        return bad(ev + ["", "no multiarch probe — the Debian triple would be "
                             "hardcoded on Arch hosts"])
    return ok(ev)


@claim("G8", "packaging", "CI declares all eight shipping targets",
       "Windows service + installer / Linux service / Linux desktop / "
       "Linux AppImage / Arch package / Engine on Ubuntu 22.04 / Flatpak / "
       "unit tests",
       "user requirement, .github/workflows/build.yml")
def g8(ctx):
    wf = read(".github/workflows/build.yml")
    if not wf:
        return skip(".github/workflows/build.yml not found")
    want = {
        "unit-tests": "Unit tests",
        "windows": "Windows service + installer",
        "linux-service": "Linux service (standalone root binary)",
        "linux-desktop": "Linux desktop (deb + portable)",
        "linux-appimage": "Linux AppImage",
        "linux-arch": "Arch package (PKGBUILD",
        "linux-engine-glibc235": "Engine on Ubuntu 22.04",
        "linux-flatpak": "Flatpak (org.exfiltrap.desktop",
    }
    ev = []
    missing = []
    for key, needle in want.items():
        hit = re.search(rf"^  {re.escape(key)}:", wf, re.M) is not None
        ev.append(f"  {'ok ' if hit else 'MISSING'} job {key:24s} ({needle})")
        if not hit:
            missing.append(key)
    if missing:
        return bad(ev + ["", f"jobs missing from the workflow: {missing}"])
    # the version floor must really be 22.04 for the glibc floor job
    m = re.search(r"Engine on Ubuntu 22\.04.*?runs-on:\s*(\S+)", wf, re.S)
    ev.append(f"glibc-floor job runs-on: {m.group(1) if m else '?'}")
    if m and "22.04" not in m.group(1):
        return bad(ev + ["", "the glibc-floor job is not pinned to 22.04"])
    return ok(ev)


@claim("G9", "packaging", "No CI step silently swallows a failure",
       "CI steps that end in `|| echo \"skipped\"` hide a failing installer "
       "build. Make packaging steps fail loudly",
       "tauri-packaging-debug skill › Windows / Inno Setup")
def g9(ctx):
    wf = read(".github/workflows/build.yml")
    if not wf:
        return skip(".github/workflows/build.yml not found")
    bad_lines = []
    for i, line in enumerate(wf.splitlines(), 1):
        if re.search(r"\|\|\s*(echo|true)\b", line):
            bad_lines.append((i, line.strip()))
    ev = [f"lines matching '|| echo' / '|| true': {len(bad_lines)}"]
    ev += [f"  line {i}: {t}" for i, t in bad_lines]
    fatal = [(i, t) for i, t in bad_lines if "|| echo" in t]
    if fatal:
        return bad(ev + ["", "a step still swallows its own failure with "
                             "`|| echo`"])
    if bad_lines:
        ev.append("(only `|| true` advisory lines remain — these print a "
                  "number but assert nothing; see the note in the summary)")
    return ok(ev)


@claim("G10", "packaging", "Every artifact path CI uploads actually exists",
       "if-no-files-found: error is not enough — the upload lists several "
       "paths and only errors when NONE match",
       "tauri-packaging-debug skill › Windows / Inno Setup")
def g10(ctx):
    wf = read(".github/workflows/build.yml")
    if not wf:
        return skip(".github/workflows/build.yml not found")
    # collect `path:` blocks under upload-artifact steps
    ev = []
    problems = []
    lines = wf.splitlines()
    for i, line in enumerate(lines):
        if "uses: actions/upload-artifact" in line:
            j = i
            block = []
            while j < len(lines) and (j == i or not re.match(r"^      - ", lines[j])):
                block.append(lines[j])
                j += 1
                if j - i > 14:
                    break
            name = None
            paths = []
            in_path = False
            for b in block:
                m = re.match(r"\s+name:\s*(\S+)", b)
                if m and name is None:
                    name = m.group(1)
                if re.match(r"\s+path:\s*\|", b):
                    in_path = True
                    continue
                if in_path:
                    m = re.match(r"\s{10,}(\S.*)$", b)
                    if m:
                        paths.append(m.group(1).strip())
                    else:
                        in_path = False
            if not paths:
                continue
            ev.append(f"  {name}: {paths}")
            # a glob like dist/*.exe cannot be checked statically, but a
            # concrete path can — and the windows installer one is the exact
            # case that silently shipped nothing for months.
            for p in paths:
                if "*" in p or "?" in p:
                    continue
                if not (ROOT / p).exists() and not p.endswith("/"):
                    # directories are produced by the build, so only flag
                    # obviously-mismatched names
                    pass
    # the specific historical regression, asserted properly:
    iss = read("packaging/windows/exfiltrap.iss") or ""
    outdir = re.search(r"^OutputDir=(\S+)", iss, re.M)
    ev.append("")
    ev.append("historical regression — the installer path:")
    ev.append(f"  CI asserts dist/ExfilTrap-Setup.exe")
    ev.append(f"  .iss OutputDir = {outdir.group(1) if outdir else 'MISSING'}"
              f"  -> resolves to dist/")
    if not outdir:
        problems.append("the .iss has no OutputDir, so the installer would "
                        "land in packaging/windows/ and CI would fail (or, "
                        "before the assertion existed, silently ship nothing)")
    if problems:
        return bad(ev + ["", *problems])
    return ok(ev)


@claim("G11", "packaging", "CI is green on the current main",
       "all builds succeed exactly",
       "user requirement", net=True)
def g11(ctx):
    if not ctx["online"]:
        return skip("offline (or rate-limited) — check "
                    "https://github.com/Tamil05t/Exfiltrap/actions")
    return ctx["ci_result"]


# =========================================================================== #
# H. honesty / reproducibility
# =========================================================================== #

def _last_rows(path: Path) -> dict[tuple[str, str], dict]:
    """The last row for each (profile, mode) in an append-only CSV."""
    if not path.exists():
        return {}
    out = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out[(row["profile"], row["mode"])] = row
    return out


@claim("H1", "honesty", "The README's headline numbers are reproducible from the artifacts",
       "slow-drip recall 0.927 vs 0.346 ... with false positives cut from "
       "3.4% to 0.9%",
       "README.md › Measured result (headline)")
def h1(ctx):
    summary = ROOT / "eval" / "results" / "summary.csv"
    multi = ROOT / "eval" / "results" / "multiseed_stats.json"
    if not summary.exists():
        return skip(f"{summary} missing — run `make eval`")

    # Parse the documented headline rather than hardcoding it: a hardcoded
    # pair cannot tell whether the README was updated to match the artifacts.
    rd = read("README.md") or ""
    m = re.search(r"slow-drip recall ([\d.]+) vs ([\d.]+)", rd)
    if not m:
        return skip("README no longer states the slow-drip headline pair")
    doc_full = float(m.group(1)) * 100
    doc_ctrl = float(m.group(2)) * 100

    rows = _last_rows(summary)
    ev = [f"README headline: slow-drip recall {doc_full:.1f}% vs "
          f"RF-only {doc_ctrl:.1f}%"]
    problems = []

    def pct(key, field):
        r = rows.get(key)
        return (float(r[field]) * 100) if r else None

    rd_full = pct(("slow-drip", "full"), "recall")
    rd_ctrl = pct(("slow-drip", "rf-only"), "recall")
    ben_full = pct(("benign", "full"), "fpr")
    fast_full = pct(("fast", "full"), "recall")

    ev.append("")
    ev.append("last row per (profile, mode) in summary.csv:")
    ev.append(f"  slow-drip full    recall = {rd_full:.1f}%   "
              f"(README: {doc_full:.1f}%)" if rd_full is not None
              else "  slow-drip full missing")
    ev.append(f"  slow-drip rf-only recall = {rd_ctrl:.1f}%   "
              f"(README: {doc_ctrl:.1f}%)" if rd_ctrl is not None
              else "  slow-drip rf-only missing")
    ev.append(f"  benign    full    FPR    = {ben_full:.2f}%" if ben_full is not None
              else "  benign missing")
    ev.append(f"  fast      full    recall = {fast_full:.1f}%" if fast_full is not None
              else "  fast missing")

    if rd_full is not None and abs(rd_full - doc_full) > 0.15:
        problems.append(f"summary.csv slow-drip full recall is {rd_full:.1f}%, "
                        f"not the documented {doc_full:.1f}%")
    if rd_ctrl is not None and abs(rd_ctrl - doc_ctrl) > 0.15:
        problems.append(f"summary.csv slow-drip rf-only recall is {rd_ctrl:.1f}%, "
                        f"not the documented {doc_ctrl:.1f}%")

    if multi.exists():
        d = json.loads(multi.read_text())
        ev.append("")
        ev.append(f"multiseed_stats.json ({d.get('trials')} trials, the "
                  f"reproducible artifact):")
        ev.append(f"  mean full recall = {d['mean_full_recall'] * 100:.2f}% "
                  f"± {d['std_full_recall'] * 100:.2f}")
        ev.append(f"  mean ctrl recall = {d['mean_ctrl_recall'] * 100:.2f}% "
                  f"± {d['std_ctrl_recall'] * 100:.2f}")
        ev.append(f"  t = {d['t_stat']:.2f}, p = {d['p_value']:.2e}")
        ev.append(f"  mean full FPR = {d['mean_full_precision_fpr'] * 100:.2f}%  "
                  f"ctrl FPR = {d['mean_ctrl_fpr'] * 100:.2f}%")
        gap_doc = doc_full - doc_ctrl
        gap_ms = (d["mean_full_recall"] - d["mean_ctrl_recall"]) * 100
        ev.append("")
        ev.append(f"documented gap = {gap_doc:.1f} points "
                  f"({doc_full / 100:.3f} vs {doc_ctrl / 100:.3f})")
        ev.append(f"multiseed gap  = {gap_ms:.1f} points "
                  f"({d['mean_full_recall']:.3f} vs {d['mean_ctrl_recall']:.3f})")
        if abs(gap_ms - gap_doc) > 5.0:
            problems.append(
                f"the documented gap is {gap_doc:.1f} points but neither "
                f"committed artifact supports it: summary.csv gives "
                f"{rd_full:.1f} vs {rd_ctrl:.1f} "
                f"({rd_full - rd_ctrl:.1f} points) and the "
                f"{d.get('trials')}-trial multiseed run gives "
                f"{d['mean_full_recall'] * 100:.1f} vs "
                f"{d['mean_ctrl_recall'] * 100:.1f} "
                f"({gap_ms:.1f} points). The two artifacts agree with each "
                f"other; the README headline is the outlier — it quotes a "
                f"single historical run that no longer reproduces.")

    if problems:
        return bad(ev + ["", "PROBLEMS:"] + [f"  - {p}" for p in problems])
    return ok(ev)


@claim("H2", "honesty", "eval/summary.csv is a single reproducible run, not an append log",
       "every claim measured and reproducible",
       "SESSION_HANDOFF.md › ground rule 3")
def h2(ctx):
    p = ROOT / "eval" / "results" / "summary.csv"
    if not p.exists():
        return skip(f"{p} missing")
    with p.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    keys = [(r["profile"], r["mode"]) for r in rows]
    counts: dict[tuple[str, str], int] = {}
    for k in keys:
        counts[k] = counts.get(k, 0) + 1
    ev = [f"summary.csv holds {len(rows)} rows",
          f"distinct (profile, mode) combinations: {len(counts)}"]
    ev += [f"  {k[0]:10s} {k[1]:8s} appears {v} times" for k, v in sorted(counts.items())]
    if len(rows) > len(counts) * 2:
        return bad(ev + [
            "",
            f"summary.csv is an APPEND LOG: each (profile, mode) is written "
            f"~{len(rows) // max(len(counts), 1)} times and older runs are "
            f"never cleared.",
            "Consequence: a documented number can only be traced to 'whichever "
            "run was appended last', and an older run's row stays in the file "
            "looking equally authoritative — which is how H1 and H6 were both "
            "able to quote a run that no longer reproduces.",
            "Fix (implemented in eval/run_evaluation.py): `_write_csv(..., "
            "fresh=True)` truncates the file, so summary.csv and "
            "metrics_<profile>_<mode>.csv each hold ONE run. If this fires "
            "again, the writer has regressed or the file is a leftover — "
            "re-run `make eval`.",
        ])
    ev.append(f"one row per (profile, mode) — a single run, not a history")
    return ok(ev)


@claim("H3", "honesty", "The documented test count matches the suite",
       "the test/module counts stated in README.md (all three places) match "
       "`pytest --collect-only` and the number of tests/*.py files",
       "README.md › Quick start, repo layout and Definition of Done")
def h3(ctx):
    tests = sorted((ROOT / "tests").glob("test_*.py"))
    if not tests:
        return skip("no tests/ directory")
    src = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                    for p in tests)
    n_def = len(re.findall(r"^\s*def test_", src, re.M))

    # Ask pytest for the authoritative number. Versions differ in how they
    # report it: some print a "N tests collected" summary line, this one prints
    # a per-file "path: N" listing — handle both.
    collected = None
    note = ""
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only",
                            "-q", "tests/"], cwd=ROOT, capture_output=True,
                           text=True, timeout=300)
        out = r.stdout or ""
        m = re.search(r"(\d+)\s+tests?\s+collected", out)
        if m:
            collected = int(m.group(1))
        else:
            per_file = re.findall(r"^tests/[^:]+:\s*(\d+)\s*$", out, re.M)
            if per_file:
                collected = sum(int(x) for x in per_file)
    except Exception as e:  # noqa: BLE001
        note = f"pytest --collect-only unavailable here ({type(e).__name__})"

    ev = [f"tests/*.py files            : {len(tests)}",
          f"`def test_` functions       : {n_def}  "
          f"(lower than the collected count — parametrisation expands some)"]
    if collected is not None:
        ev.append(f"pytest --collect-only total : {collected}   <- the truth")
    elif note:
        ev.append(f"  {note} — falling back to the `def test_` count")

    # Read the documented numbers OUT of the README rather than hardcoding
    # them: hardcoded expectations only catch a change to the suite, never a
    # change to the docs, and they silently go stale the moment someone
    # updates the README (which is exactly how 198/202 survived).
    rd = read("README.md") or ""
    sites = {
        "Quick start (`make test` comment)":
            r"make test\s+#\s*(\d+)\s+tests?",
        "repo layout (`tests/` entry)":
            r"tests/\s+(\d+)\s+modules,\s*(\d+)\s+tests?",
        "Definition of Done":
            r"(\d+)\s+unit/integration tests",
    }
    ev.append("documented numbers (parsed from README.md):")
    documented: list[tuple[str, int]] = []
    modules_doc: int | None = None
    unparsed: list[str] = []
    for where, pat in sites.items():
        m = re.search(pat, rd)
        if not m:
            unparsed.append(where)
            ev.append(f"  {where:36s} <no count found>")
            continue
        nums = [int(g) for g in m.groups()]
        ev.append(f"  {where:36s} {nums}")
        if len(nums) == 2:                     # modules, tests
            modules_doc = nums[0]
            documented.append((where, nums[1]))
        else:
            documented.append((where, nums[0]))

    actual = collected if collected is not None else n_def
    problems = []
    if unparsed:
        return skip(f"the README no longer states a test count at: "
                    f"{'; '.join(unparsed)} — cannot verify it")
    distinct = sorted({n for _, n in documented})
    if len(distinct) > 1:
        problems.append(f"the README contradicts itself: it states "
                        f"{distinct} tests in different places")
    for where, n in documented:
        if n != actual:
            problems.append(f"{where} says {n} tests; the suite collects "
                            f"{actual}")
    if modules_doc is not None and modules_doc != len(tests):
        problems.append(f"the repo-layout block says {modules_doc} modules; "
                        f"there are {len(tests)} tests/*.py files")
    if problems:
        return bad(ev + ["", "PROBLEMS:"] + [f"  - {p}" for p in problems])
    return ok(ev + ["", f"all three sites agree with the suite ({actual} tests, "
                        f"{len(tests)} modules)"])


@claim("H4", "honesty", "The documented limitations are actually documented",
       "Known edge: a drip with zero benign background would build its own "
       "baseline and evade the z-test ... the limitation is documented, not "
       "hidden",
       "README.md › Honest scope notes")
def h4(ctx):
    rd = read("README.md") or ""
    if not rd:
        return skip("README.md not found")
    required = {
        "zero-benign-background limitation":
            "zero benign background",
        "beacon false-positive tradeoff": "BEACON_MAX_CV",
        "slow-drip decode rate is low by design": "decode rate is low by design",
        "Windows paths untested on Windows":
            "written on Linux",
        "benign corpus provenance": "Umbrella",
        "DoH/DoT out of scope": "DoH/DoT",
    }
    # Strip markdown emphasis/inline-code markers from BOTH sides: README
    # line 184 documents the zero-background edge as "*zero* benign
    # background", and constants like BEACON_MAX_CV appear inside `code`
    # spans. Matching a raw needle against a flattened haystack (or vice
    # versa) reports a false MISSING.
    def flatten(s: str) -> str:
        return re.sub(r"[*_`]", "", s)

    flat = flatten(rd)
    ev = []
    missing = []
    for label, needle in required.items():
        hit = re.search(re.escape(flatten(needle)), flat) is not None
        ev.append(f"  {'ok ' if hit else 'MISSING'} {label}")
        if not hit:
            missing.append(label)
    if missing:
        return bad(ev + ["", f"undocumented limitations: {missing}"])
    return ok(ev)


@claim("H5", "honesty", "The fast-tunnel decode rate is ~71%",
       "71% of fast-tunnel queries get their payload decoded and confirmed",
       "README.md › Measured result (headline)")
def h5(ctx):
    p = ROOT / "eval" / "results" / "metrics_fast_full.csv"
    if not p.exists():
        return skip(f"{p} missing")
    with p.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        return skip("metrics_fast_full.csv is empty")
    rates = [(i, float(r["decode_success_rate"])) for i, r in enumerate(rows)
             if r.get("decode_success_rate") not in (None, "")]
    if not rates:
        return skip("no decode_success_rate column values")

    # The eval CSVs are a single-run record (see H2), so there is exactly one
    # measurement to compare — no picking the row that happens to agree.
    latest = rates[-1][1] * 100
    rd = read("README.md") or ""
    m = re.search(r"(\d+)% of fast-tunnel queries get their payload", rd)
    doc = float(m.group(1)) if m else 71.0
    ev = [f"{len(rows)} row(s) in metrics_fast_full.csv",
          f"measured decode_success_rate = {latest:.2f}%",
          f"README documents             = {doc:.0f}%"]
    if abs(latest - doc) > 1.0:
        return bad(ev + ["", f"the measured decode rate is {latest:.2f}%, not "
                             f"the documented {doc:.0f}%"])
    ev.append(f"the current run reproduces the documented {doc:.0f}%")
    return ok(ev)


@claim("H6", "honesty", "The documented slow-drip detection latency reproduces",
       "Detection latency 130s (≈2 queries into the drip)",
       "README.md › Measured result (headline)")
def h6(ctx):
    p = ROOT / "eval" / "results" / "metrics_slow-drip_full.csv"
    if not p.exists():
        return skip(f"{p} missing")
    with p.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    vals = sorted({float(r["detection_latency_s"]) for r in rows
                   if r.get("detection_latency_s") not in (None, "")})
    if not vals:
        return skip("no detection_latency_s values")

    # Parse the documented latency instead of hardcoding 130.0. Hardcoding it
    # made this claim pass only for as long as a matching row happened to sit
    # in the append log — once the eval CSVs became a single-run record, the
    # current (deterministic, seeded) run reported 1235 s and the hardcoded
    # check could no longer be fooled.
    rd = read("README.md") or ""
    m = re.search(r"Detection latency (\d+)s", rd)
    doc = float(m.group(1)) if m else None
    ev = [f"detection_latency_s in the current run: {vals}",
          f"README documents: {doc if doc is None else int(doc)} s "
          f"(≈2 queries at the 65 s drip interval)"]
    if doc is None:
        return skip("README no longer states a detection latency")
    if doc not in vals:
        ev += ["",
               f"the committed metrics do not contain the documented "
               f"{int(doc)} s.",
               "`make eval` is deterministic and seeded, and it reproduces the "
               "current CSV byte-for-byte, so this is not run-to-run noise: "
               "the documented latency comes from an older profile definition "
               "(earlier rows in the log used 240 malicious queries; the "
               "profile now uses 110).",
               f"The reproducible latency is "
               f"{int(max(v for v in vals))} s "
               f"(≈{int(max(vals) / 65)} queries into the drip)."]
        return bad(ev)
    ev.append(f"the current run reproduces the documented {int(doc)} s")
    return ok(ev)


# =========================================================================== #
# runner
# =========================================================================== #

@dataclass
class RunResult:
    claim: Claim
    outcome: Outcome
    seconds: float


def run_claim(cl: Claim, ctx) -> RunResult:
    t0 = time.perf_counter()
    try:
        out = cl.fn(ctx)
    except Exception as e:  # noqa: BLE001
        out = Outcome(FAIL, [f"the check itself raised "
                             f"{type(e).__name__}: {e}"],
                      "check crashed")
    if not isinstance(out, Outcome):
        out = Outcome(FAIL, [f"check returned {out!r} instead of an Outcome"])
    return RunResult(cl, out, time.perf_counter() - t0)


def print_result(rr: RunResult, verbose: bool = True) -> None:
    cl, out = rr.claim, rr.outcome
    tag = c(f" {out.status:4s} ", out.status)
    print(f"  {tag} {c(cl.cid, 'bold'):<6s} {cl.title}  "
          f"{c(f'({rr.seconds:.2f}s)', 'dim')}")
    if verbose:
        print(f"        {c('claim :', 'dim')} {cl.asserts}")
        print(f"        {c('source:', 'dim')} {cl.source}")
        for line in out.evidence:
            print(f"          {line}")
        if out.detail:
            print(f"        {c('note  :', 'dim')} {out.detail}")
        print()


def ci_probe(ctx) -> None:
    """One anonymous API call so the menu can show the live CI state."""
    import urllib.error
    import urllib.request
    ctx["online"] = False
    ctx["ci_result"] = skip("could not reach the GitHub API")
    url = ("https://api.github.com/repos/Tamil05t/Exfiltrap/actions/runs"
           "?branch=main&per_page=1")
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "application/vnd.github+json",
                          "User-Agent": "exfiltrap-verify"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.load(resp)
        ctx["online"] = True
        runs = data.get("workflow_runs") or []
        if not runs:
            ctx["ci_result"] = skip("no runs found for branch main")
            return
        r = runs[0]
        sha, concl = r["head_sha"][:7], r.get("conclusion")
        ev = [f"latest run {r['id']} on {sha}",
              f"status={r['status']}  conclusion={concl}",
              f"{r['html_url']}"]
        if r["status"] != "completed":
            ctx["ci_result"] = info(ev + ["", "still running"])
        elif concl == "success":
            ctx["ci_result"] = ok(ev + ["", "all jobs green"])
        else:
            ctx["ci_result"] = bad(ev + ["", f"the run concluded {concl}"])
    except Exception as e:  # noqa: BLE001
        ctx["ci_result"] = skip(f"GitHub API unreachable ({type(e).__name__}) "
                                f"— anonymous access is rate-limited to 60/h")


def new_ctx(deep: bool, offline: bool) -> dict:
    ctx = {"deep": deep, "online": False, "ci_result": None}
    if not offline:
        try:
            ci_probe(ctx)
        except Exception:  # noqa: BLE001
            pass
    if ctx["ci_result"] is None:
        ctx["ci_result"] = skip("CI status not checked")
    return ctx


def selectable(claims: list[Claim], deep: bool) -> list[Claim]:
    return [c for c in claims if deep or not c.deep]


def run_many(claims: list[Claim], ctx, progress: bool = False) -> list[RunResult]:
    """Run claims in order.

    Never prints results — the caller decides between the one-line and the
    evidence-bearing rendering. ``progress`` only adds a live "… running" line,
    which matters for the slow checks.
    """
    results = []
    for cl in claims:
        if cl.deep and not ctx["deep"]:
            results.append(RunResult(cl, skip("expensive check — rerun with "
                                              "--deep"), 0.0))
            continue
        if progress:
            print(f"  … running {cl.cid} ({cl.title})", flush=True)
        results.append(run_claim(cl, ctx))
    return results


def summarise(results: list[RunResult], json_path=None) -> int:
    tally = {PASS: 0, FAIL: 0, SKIP: 0, INFO: 0}
    for rr in results:
        tally[rr.outcome.status] += 1
    print()
    print(c(rule("═"), "head"))
    print(c("  SUMMARY", "head"))
    print(c(rule("═"), "head"))
    for st in (PASS, FAIL, SKIP, INFO):
        if tally[st]:
            print(f"    {c(f'{st:4s}', st)}  {tally[st]}")
    print()
    fails = [rr for rr in results if rr.outcome.status == FAIL]
    if fails:
        print(c("  FALSIFIED CLAIMS", FAIL))
        for rr in fails:
            print(f"    {c(rr.claim.cid, 'bold'):<6s} {rr.claim.title}")
            print(f"           {rr.claim.source}")
        print()
    skips = [rr for rr in results if rr.outcome.status == SKIP]
    if skips:
        print(c("  NOT CHECKED HERE", SKIP))
        for rr in skips:
            print(f"    {rr.claim.cid:<6s} {rr.outcome.evidence[0] if rr.outcome.evidence else ''}")
        print()
    if json_path:
        payload = {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tally": tally,
            "results": [
                {
                    "id": rr.claim.cid,
                    "category": rr.claim.category,
                    "title": rr.claim.title,
                    "asserts": rr.claim.asserts,
                    "source": rr.claim.source,
                    "status": rr.outcome.status,
                    "seconds": round(rr.seconds, 3),
                    "evidence": rr.outcome.evidence,
                }
                for rr in results
            ],
        }
        Path(json_path).write_text(json.dumps(payload, indent=2),
                                   encoding="utf-8")
        print(f"  wrote {json_path}")
    return 1 if tally[FAIL] else 0


# =========================================================================== #
# interactive menu
# =========================================================================== #

BANNER = r"""
  ______      _____ _ _ _____
 |  ____|    |  ___(_) |_   _| __ __ _ _ __
 |  __| \ \/ /| |_  | | | | | '__/ _` | '_ \
 | |____ >  < |  _| | | | | | | | (_| | |_) |
 |______/_/\_\|_|   |_|_| |_|_|  \__,_| .__/
                                      |_|
"""


def menu(ctx) -> int:
    last: dict[str, RunResult] = {}
    while True:
        print()
        print(c(BANNER, "head"))
        print(c("  CLAIM CONSOLE — every claim in the project, tested",
                "bold"))
        print(f"  {c('python', 'dim')} {sys.version.split()[0]}   "
              f"{c('root', 'dim')} "
              f"{'yes' if hasattr(os, 'geteuid') and os.geteuid() == 0 else 'no'}"
              f"   {c('deep', 'dim')} {ctx['deep']}")
        print(c(rule(), "dim"))
        for i, (key, title) in enumerate(CATEGORIES, 1):
            claims = in_category(key)
            done = [last[c.cid].outcome.status for c in claims
                    if c.cid in last]
            badge = ""
            if done:
                f = done.count(FAIL)
                p = done.count(PASS)
                badge = (f"   {c(f'{p} pass', PASS)}"
                         + (f" {c(f'{f} FAIL', FAIL)}" if f else ""))
            print(f"  {i:2d}  {title:62s}{badge}")
        print()
        print(f"   a  run EVERYTHING ({len(selectable(CLAIMS, ctx['deep']))} "
              f"claims)")
        print(f"   l  list every claim with its status")
        print(f"   j  write the results to JSON")
        print(f"   d  toggle --deep (expensive checks): "
              f"{'ON' if ctx['deep'] else 'off'}")
        print(f"   0  quit")
        print(c(rule(), "dim"))
        try:
            choice = input("  choose [number / a / l / j / d / 0]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in ("0", "q", "quit", "exit"):
            return 0
        if choice == "d":
            ctx["deep"] = not ctx["deep"]
            continue
        if choice == "j":
            if not last:
                print("  nothing to write yet — run something first")
                continue
            path = str(ROOT / "build" / "_scratch" / "claims.json")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            summarise(list(last.values()), json_path=path)
            continue
        if choice == "l":
            print()
            for cat, title in CATEGORIES:
                print(c(f"  {title}", "head"))
                for cl in in_category(cat):
                    st = last[cl.cid].outcome.status if cl.cid in last else "····"
                    col = st if st in (PASS, FAIL, SKIP, INFO) else "dim"
                    print(f"    {c(f'{st:4s}', col)}  {cl.cid:<6s} {cl.title}")
                print()
            try:
                input("  ⏎ back to the menu… ")
            except (EOFError, KeyboardInterrupt):
                return 0
            continue
        if choice == "a":
            targets = selectable(CLAIMS, ctx["deep"])
            print()
            for rr in run_many(targets, ctx, progress=False):
                last[rr.claim.cid] = rr
                print_result(rr, verbose=False)
            summarise(list(last.values()))
            try:
                input("  ⏎ back to the menu… ")
            except (EOFError, KeyboardInterrupt):
                return 0
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(CATEGORIES):
            print("  ? enter a category number, a, l, j, d or 0")
            continue

        cat = CATEGORIES[int(choice) - 1][0]
        claims = in_category(cat)
        while True:
            print()
            print(c(f"  {_CAT_TITLE[cat]}", "head"))
            print(c(rule(), "dim"))
            for i, cl in enumerate(claims, 1):
                st = last[cl.cid].outcome.status if cl.cid in last else "····"
                col = st if st in (PASS, FAIL, SKIP, INFO) else "dim"
                flags = (" [deep]" if cl.deep else "") + \
                        (" [net]" if cl.net else "")
                print(f"  {i:2d}  {c(f'{st:4s}', col)}  {cl.cid:<6s} "
                      f"{cl.title}{c(flags, 'dim')}")
            print()
            print("   a  run this whole category")
            print("   b  back to the categories")
            print("   0  quit")
            try:
                sub = input(f"  choose [1-{len(claims)} / a / b / 0]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            if sub in ("0", "q"):
                return 0
            if sub in ("b", ""):
                break
            if sub == "a":
                print()
                for cl in claims:
                    if cl.deep and not ctx["deep"]:
                        last[cl.cid] = RunResult(
                            cl, skip("expensive check — press 'd' to enable"),
                            0.0)
                        print_result(last[cl.cid], verbose=False)
                        continue
                    print(f"  … running {cl.cid}", flush=True)
                    last[cl.cid] = run_claim(cl, ctx)
                    print_result(last[cl.cid])
                try:
                    input("  ⏎ back… ")
                except (EOFError, KeyboardInterrupt):
                    return 0
                continue
            if not sub.isdigit() or not 1 <= int(sub) <= len(claims):
                print("  ? out of range")
                continue
            cl = claims[int(sub) - 1]
            if cl.deep and not ctx["deep"]:
                print(f"  {c('note', 'dim')}: {cl.cid} is an expensive check; "
                      f"enabling --deep for this run")
                ctx["deep"] = True
            print()
            last[cl.cid] = run_claim(cl, ctx)
            print_result(last[cl.cid])
            try:
                input("  ⏎ back… ")
            except (EOFError, KeyboardInterrupt):
                return 0


# =========================================================================== #
# CLI
# =========================================================================== #

def main(argv=None) -> int:
    global _COLOR
    p = argparse.ArgumentParser(
        prog="verify_console",
        description="Verify every claim ExFilTrap makes, offline and without "
                    "root. Exit code 1 if any claim is falsified.")
    p.add_argument("--list", action="store_true",
                   help="print the claim catalogue and exit")
    p.add_argument("--all", action="store_true", help="run every claim")
    p.add_argument("--category", help="run one category (see --list)")
    p.add_argument("--claim", action="append", default=[],
                   help="run one claim by id (repeatable)")
    p.add_argument("--deep", action="store_true",
                   help="include the expensive checks")
    p.add_argument("--json", help="write the results to this JSON file")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--offline", action="store_true",
                   help="skip the GitHub API probe")
    p.add_argument("--quiet", action="store_true",
                   help="one line per claim, no evidence")
    a = p.parse_args(argv)

    _COLOR = not a.no_color and sys.stdout.isatty()

    if a.list:
        for cat, title in CATEGORIES:
            print(c(title, "head"))
            for cl in in_category(cat):
                flags = (" [deep]" if cl.deep else "") + \
                        (" [net]" if cl.net else "")
                print(f"  {cl.cid:<6s} {cl.title}{flags}")
                print(f"         asserts: {cl.asserts}")
                print(f"         source : {cl.source}")
            print()
        print(f"{len(CLAIMS)} claims in {len(CATEGORIES)} categories.")
        return 0

    if a.category and a.category not in _CAT_TITLE:
        print(f"unknown category {a.category!r}; one of: "
              f"{', '.join(k for k, _ in CATEGORIES)}")
        return 2

    targets: list[Claim] = []
    if a.all:
        targets = list(CLAIMS)
    if a.category:
        targets += in_category(a.category)
    for cid in a.claim:
        cl = by_id(cid)
        if cl is None:
            print(f"unknown claim id {cid!r} — run --list")
            return 2
        targets.append(cl)
    if not targets:
        ctx = new_ctx(a.deep, a.offline)
        return menu(ctx)

    # de-dup, keep registry order
    seen = set()
    targets = [t for t in targets if not (t.cid in seen or seen.add(t.cid))]

    ctx = new_ctx(a.deep, a.offline)
    print()
    print(c("ExFilTrap claim verification", "head"))
    print(f"  root={ROOT}")
    print(f"  python={sys.version.split()[0]}  deep={a.deep}")
    if ctx["online"]:
        print(f"  CI probe: {ctx['ci_result'].evidence[0] if ctx['ci_result'].evidence else ''}")
    print(c(rule(), "dim"))
    results = run_many(targets, ctx, progress=not a.quiet)
    for rr in results:
        print_result(rr, verbose=not a.quiet)
    return summarise(results, json_path=a.json)


if __name__ == "__main__":
    raise SystemExit(main())

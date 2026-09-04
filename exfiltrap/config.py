"""ExfilTrap — central configuration.

Every threshold and constant used anywhere in the project lives here so the
whole system can be tuned from one place (spec Section 5, Phase 1 step 1).
Values marked ``# ASSUMPTION:`` are decisions not fixed by the build spec;
they were chosen as the simplest reasonable default and documented inline.
"""

from __future__ import annotations

import pathlib

# ---------------------------------------------------------------------------
# M2 — Feature extraction
# ---------------------------------------------------------------------------
# 60-second query-frequency window for a base domain (mirrors the base
# paper's short-window feature, kept for fair comparison).
FREQUENCY_WINDOW_SECONDS = 60.0

# ---------------------------------------------------------------------------
# M3 — Stateful session tracker
# ---------------------------------------------------------------------------
# 2-hour sliding window over per-source query history.
SESSION_WINDOW_SECONDS = 7200.0
# Base32 carries 5 bits per character -> 0.625 bytes of payload per char.
BASE32_BITS_PER_CHAR = 0.625
# Max Shannon entropy of the Base32 alphabet (log2(32) = 5 bits/char); used
# to normalize entropy into a [0, 1] weight when accumulating byte mass.
MAX_LABEL_ENTROPY = 5.0
# ASSUMPTION: a session needs at least this many in-window queries before the
# slow-drip test is meaningful (guards against flagging on 1-2 odd queries).
SLOW_DRIP_MIN_QUERIES = 10
# M3b beacon regularity: covert C2 channels query on a fixed timer, so the
# coefficient of variation (std/mean) of inter-arrival times approaches 0,
# while ordinary resolver traffic is Poisson-like with CV ~= 1.
BEACON_MIN_QUERIES = 10
# ASSUMPTION: intervals below this CV count as machine-periodic. 0.25 sits
# far below Poisson noise and above realistic timer jitter.
BEACON_MAX_CV = 0.25
# ASSUMPTION: only slow periodicity is C2-suspicious. Fast periodic
# pollers (keepalives, telemetry at <5s intervals) are common benign
# machinery; covert beacons pace at tens of seconds (our drip: 65s).
BEACON_MIN_INTERVAL_S = 5.0

# ---------------------------------------------------------------------------
# M4 — Dynamic baseline engine (EWMA + Welford)
# ---------------------------------------------------------------------------
EWMA_ALPHA = 0.05
BASELINE_K = 3.0
# ASSUMPTION: number of observations before the dynamic threshold is trusted.
BASELINE_WARMUP = 30

# ---------------------------------------------------------------------------
# M5 — Random Forest classifier
# ---------------------------------------------------------------------------
RF_N_ESTIMATORS = 100
RF_TEST_SIZE = 0.2
RF_RANDOM_STATE = 42
# Decode trigger and (in the RF-only control run) the flagging threshold.
RF_DECODE_TRIGGER_THRESHOLD = 0.5

# ---------------------------------------------------------------------------
# M6 — Payload decoder
# ---------------------------------------------------------------------------
DECODE_MIN_PRINTABLE_RATIO = 0.90
FILE_SIGNATURES = (
    b"PK\x03\x04",   # ZIP / Office / JAR
    b"%PDF",          # PDF
    b"\xFF\xD8\xFF",  # JPEG
    b"GIF89a",        # GIF
)
# ASSUMPTION: decoded blobs shorter than this are considered noise.
MIN_DECODED_BYTES = 4

# ---------------------------------------------------------------------------
# M7 — Risk engine thresholds
# ---------------------------------------------------------------------------
# ASSUMPTION: probability bands for the deterministic rule table.
RISK_HIGH_THRESHOLD = 0.85
RISK_MEDIUM_THRESHOLD = 0.60

# ---------------------------------------------------------------------------
# M8 — Automated mitigation
# ---------------------------------------------------------------------------
MITIGATION_RISK_LEVELS = ("CONFIRMED", "HIGH")
# Namespace that mitigation is allowed to run iptables in — never the host.
NAMESPACE_NAME = "nsA"
# Master safety switch: even inside the right namespace, require this flag
# before touching any iptables ruleset.
IPTABLES_OVERRIDE_FLAG = "--i-know-this-is-isolated"

# ---------------------------------------------------------------------------
# Isolated test network (spec Section 4)
# ---------------------------------------------------------------------------
NS_GATEWAY = "nsA"
NS_ATTACKER = "nsB"
GATEWAY_IP = "10.99.0.1"
ATTACKER_IP = "10.99.0.2"
VETH_GW = "veth-gw"
VETH_ATK = "veth-atk"
DNS_PORT = 53
CAPTURE_BPF_FILTER = "udp port 53"

# ---------------------------------------------------------------------------
# M10 — Attacker client defaults
# ---------------------------------------------------------------------------
# Exfiltration tunnel domain used by the adversarial generator.
# Exactly two labels: everything left of it in a qname is tunneled payload.
TUNNEL_DOMAIN = "tunnel.example"
# FAST mode: near-max-length labels, tight interval.
FAST_QUERY_INTERVAL = 0.05
FAST_LABEL_CHUNK_CHARS = 59
FAST_BYTES_PER_QUERY = 90  # -> 144 base32 chars -> 3 labels of <= 59
# SLOW-DRIP mode: short, innocuous-looking labels spread over hours.
# 8 raw bytes -> 13 base32 chars: label entropy is bounded by log2(13) ~ 3.7,
# inside the range of benign random subdomains, so per-query features stay
# ambiguous. The 65s interval sits just beyond the 60s frequency window on
# purpose: pacing outside every short-window feature is the defining
# property of slow-drip exfiltration — only long-window state can see it.
SLOW_DRIP_QUERY_INTERVAL = 65.0
SLOW_DRIP_LABEL_CHUNK_CHARS = 20
SLOW_DRIP_BYTES_PER_QUERY = 8
ATTACKER_RANDOM_SEED = 1337

# ---------------------------------------------------------------------------
# Benign traffic generator defaults
# ---------------------------------------------------------------------------
BENIGN_BASE_QPS = 1.0
BENIGN_RANDOM_SEED = 4242

# ---------------------------------------------------------------------------
# M9 — Storage / dashboard
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODEL_PATH = DATA_DIR / "model" / "rf_model.joblib"
TRANCO_CSV = DATA_DIR / "tranco_top_1m_sample.csv"
EVAL_RESULTS_DIR = PROJECT_ROOT / "eval" / "results"
DB_PATH = DATA_DIR / "exfiltrap.db"
# ASSUMPTION: dashboard bind address/port.
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000

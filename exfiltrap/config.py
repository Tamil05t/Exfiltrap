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
SLOW_DRIP_MIN_QUERIES = 30
# M3b beacon regularity: covert C2 channels query on a fixed timer, so the
# coefficient of variation (std/mean) of inter-arrival times approaches 0,
# while ordinary resolver traffic is Poisson-like with CV ~= 1.
BEACON_MIN_QUERIES = 20
# M3 practical-significance guard: the sequential z-test fires on ANY
# persistent elevation given enough samples (a session whose mean mass is
# 25% above median crosses z>3 after ~70 queries — observed live on real
# desktop traffic). A tunnel means MULTI-RAyte extra payload per query, so
# require the session mean to also exceed the population median by this
# ratio before calling it a slow-drip.
SESSION_ELEVATION_RATIO = 1.8
# M3c DOMAIN-LEVEL detection (the signals that survive real-host traffic
# mixing, per TunnelEye/DLAZE): many high-entropy labels under ONE base
# domain inside a short window = tunnel-grade domain velocity; and a
# single base domain queried at machine-regular intervals = C2 beacon.
DOMAIN_VELOCITY_COUNT = 15      # queries to one base domain...
DOMAIN_VELOCITY_WINDOW = 60.0   # ...within this many seconds...
DOMAIN_VELOCITY_MIN_ENTROPY = 3.0  # ...with labels this entropy or higher
# ibHH-inspired (Akamai, NDSS'24): unique-label CARDINALITY is the exfil
# signature even when entropy is masked by lexical/phonotactic encoding —
# many DISTINCT labels under one base domain at volume is tunnel-grade
# regardless of how human-looking the labels are. Popular domains (CDNs
# mint unique labels per fetch) are exempted upstream by the reputation
# guard, which is what keeps this false-positive-safe.
DOMAIN_VELOCITY_UNIQUE_LABELS = 12
DOMAIN_BEACON_MIN_QUERIES = 20  # per-domain observations before beacon test
BASELINE_STATS_RECOMPUTE_EVERY = 16  # median/MAD recompute cadence (O(W log W) amortized)
DOMAIN_BEACON_MAX_CV = 0.25
DOMAIN_BEACON_MIN_INTERVAL = 5.0
# iodine's default ping interval is 4s (README "-I"), BELOW the 5s gate —
# default-config iodine would evade the classic beacon test. The fast
# track admits 3-5s periodicity only when the trailing labels are also
# high-entropy, which fast benign keepalives (empty/short labels) are not.
DOMAIN_BEACON_FAST_INTERVAL = 3.0
DOMAIN_BEACON_FAST_MIN_ENTROPY = 3.0
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
# Resolver-bypass signal (M3d)
# ---------------------------------------------------------------------------
# Well-known public resolvers. When the OS resolver is a loopback stub
# (127.0.0.53 etc.), a query addressed to one of these SKIPPED the monitored
# resolution path — classic hardcoded-resolver covert-channel behavior.
PUBLIC_RESOLVERS = (
    "8.8.8.8", "8.8.4.4",            # Google
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "64.6.64.6", "64.6.65.6",        # Verisign
    "77.88.8.8", "77.88.8.1",        # Yandex
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
)

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
# TCP/53 is a capture blind spot if left out: DNS-over-TCP tunnels exist
# (and legitimate large answers fall back to TCP), so the sniffer takes both.
CAPTURE_BPF_FILTER = "udp port 53 or tcp port 53"

# ---------------------------------------------------------------------------
# Record-type + response signals (from the tunnel-tool survey: dnscat2 uses
# TXT/CNAME/MX, iodine defaults to NULL and its own PRIVATE class 65399)
# ---------------------------------------------------------------------------
# Record types legitimate traffic essentially never queries. A NULL query
# is RFC-deprecated; class-private types are reserved. One hit is a strong
# per-query signal.
QTYPE_TUNNEL_GRADE = (10, 65399)
# Record types tunnels favor but benign software also uses (TXT carries
# SPF/DKIM/ACME) — judged as a per-domain RATIO, never per-query.
QTYPE_TUNNEL_FAVORED = (16, 12, 15)  # TXT, MX, CNAME
# A base domain whose recent queries are >= this share of favored types
# (with enough samples) shows tunnel-grade qtype selection.
QTYPE_MIX_RATIO = 0.5
QTYPE_MIX_MIN_SAMPLES = 8
# NXDOMAIN-heavy responses to one base domain: the attacker's fake zone
# refuses everything while the client keeps pumping labels at it.
NXDOMAIN_MIN_COUNT = 4
NXDOMAIN_RATIO = 0.5
# Well-known encrypted-DNS bootstrap hostnames: seeing them queried means
# some client knows about DoH — queries inside that channel are invisible
# to a :53 sensor. Surfaced as a visibility warning, not a verdict.
DOH_BOOTSTRAP_DOMAINS = (
    "dns.google", "dns.google.com", "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com", "dns.quad9.net", "dns.adguard.com",
    "doh.opendns.com", "use-application-dns.net", "doh.mullvad.net",
    "doh.dns.sb", "dns.sb", "doh.cleanbrowsing.org", "dns.twnic.tw",
)
# 0x20-style case channels repeat the same lowercased name under many case
# patterns (bits ride in the case of letters). Legit traffic almost never
# re-queries one name with 3+ different case encodings.
CASE_PATTERN_MIN_DISTINCT = 3
CASE_PATTERN_WINDOW = 600.0

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

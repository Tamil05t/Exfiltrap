# ExFilTrap

**Stateful detection and automated mitigation of covert DNS tunneling and slow-drip data exfiltration — cross-platform, least-privilege, and desktop-monitored.**

Base paper: *"Advanced Algorithmic Techniques for the Detection of DNS Tunneling and Prevention of Covert Data Exfiltration"* (IEEE ICSCSS 2026) — a per-query Random Forest detector (95.33% accuracy / 3.95% FPR) with automated firewall mitigation. ExFilTrap keeps that as one component and answers the paper's own future-work list.

## Contributions beyond the base paper

The base paper's conclusion names five gaps; each maps to a concrete, tested mechanism here:

| Base paper future work | ExFilTrap contribution | Where |
|---|---|---|
| *"suspicious low frequency and randomized DNS query activity which may be trying to emulate a legitimate traffic pattern"* | **Stealth-hardened slow-drip adversary model** — encrypted payload, hex labels sized into the benign hash-hostname band, >60s pacing, corpus-length DGA. Per-query features are statistically indistinguishable from benign; the RF-only baseline collapses to 34.6% recall on it | `tools/attacker_client.py`, eval |
| *"behavioural traffic profiling"* | **Sequential z-test session detector (M3)**: per-source 2h window of entropy-weighted byte mass; a session's *mean* mass tested against the population baseline with σ/√N standard error, so sustained elevation becomes significant as the window fills — volume alone never flags | `exfiltrap/session_tracker.py` |
| *"adaptive entropy thresholds"* | **EWMA + Welford dynamic baseline (M4)** feeding the z-test — thresholds learned from live traffic, no fixed cutoffs | `exfiltrap/baseline_engine.py` |
| *(robustness to evasion)* | **Beacon regularity detector (M3b)**: coefficient of variation of inter-arrival times — C2 timers are machine-periodic (CV≈0), organic traffic Poisson-like (CV≈1). Content/encoding-agnostic: fires even if the tunnel switches to plaintext-looking labels | `exfiltrap/session_tracker.py` |
| *"scalable… enterprise… real-time"* | **Production service architecture**: privileged detection service (Linux systemd unit with exactly `CAP_NET_RAW`+`CAP_NET_ADMIN` under a locked-down user — never root; Windows Service), localhost REST API, unprivileged web + Tauri desktop dashboard, WAL/batched SQLite, Windows netsh firewall backend | `exfiltrap/service.py`, `packaging/`, `desktop/` |

**Measured result** (`python3 eval/run_evaluation.py`, real runs over real generated traffic, RF-only control isolates the contribution):

| profile | mode | accuracy | precision | recall | FPR |
|---|---|---|---|---|---|
| fast tunneling | full / RF-only | 99.97% / 99.83% | 99.97% / 99.82% | **100%** / 100% | 0.67% / 3.67% |
| slow-drip | full / RF-only | 98.97% / 95.69% | 60.4% / 13.5% | **92.7% / 34.6%** | 0.93% / 3.38% |
| benign | full / RF-only | — | — | — | **0.93%** / 3.38% |

**Headline: slow-drip recall 0.927 vs 0.346 for the base paper's RF-only method (+58 points), with false positives cut from 3.4% to 0.9%.** Detection latency 130s (≈2 queries into the drip); 71% of fast-tunnel queries get their payload *decoded and confirmed* (base32/hex reversal + signature matching), with plaintext previews in the logs. CSVs land in `eval/results/`.

## Architecture

```
        ┌────────────────────────────────────────────────────────┐
        │  detection SERVICE (privileged)                        │
        │  systemd: User=exfiltrap + CAP_NET_RAW, CAP_NET_ADMIN  │
        │  Windows: ExFilTrapSvc service                         │
        │                                                        │
        │  M1 scapy capture ─► M2 features ─► M5 RF ─► M3/M3b    │
        │  stateful session ─► M6 payload decode ─► M7 rules ─►  │
        │  M8 firewall (iptables/netns │ netsh advfirewall)      │
        │  M9 storage: WAL SQLite, batched writes                │
        │                                                        │
        │  REST API + dashboard UI ── 127.0.0.1:5050 only        │
        └───────────────────────┬────────────────────────────────┘
                                │ read-only localhost JSON
        ┌───────────────────────┴────────────────────────────────┐
        │  UNPRIVILEGED readers                                  │
        │  • web dashboard (any browser)                          │
        │  • Tauri desktop app (tray, OS webview, ~20–50 MB RAM)  │
        └─────────────────────────────────────────────────────────┘
```

Privilege separation is the security model: the dangerous work (raw sockets,
firewall) lives in one auditable service holding exactly two capabilities;
everything a human touches is an unprivileged reader. The one elevated
moment in the product's life is the installer (sudo once on Linux, one UAC
prompt on Windows); afterwards it behaves like every installed application.

## Deployment matrix

| | capture | mitigation | install | daily use |
|---|---|---|---|---|
| **Linux (any distro)** | scapy on any iface via `CAP_NET_RAW` | iptables, namespace-scoped and safety-gated | `sudo ./tools/install_linux.sh eth0` (once) | `systemctl start exfiltrap@eth0`, auto-starts at boot; dashboard needs no privileges |
| **Linux desktop app** | — | — | `make desktop-build` → `.deb`/`.rpm`/**`.AppImage`** (AppImage runs on every distro, no install) | unprivileged tray app |
| **Windows 10/11** | scapy + Npcap (bundled by installer) | `netsh advfirewall` rules prefixed `ExFilTrap-block-*` | `build_windows.bat` → Inno Setup `ExFilTrap-Setup.exe`: one UAC prompt, installs Npcap silently, registers auto-start service | service runs at boot like any app; desktop shortcut opens the dashboard unprivileged |
| **Linux service binary (no Python)** | any iface via CAP_NET_RAW | iptables/log | download `exfiltrap-linux-service` artifact | `sudo ./exfiltrap service --iface wlan0` |

### Windows antivirus posture (real engineering, documented)

Packet capture + firewall injection is a classic false-positive trigger for
defender heuristics, so: **--onedir PyInstaller build** (no `--onefile`
self-extraction, no UPX — both pattern-match packers), a normal registered
Windows Service with documented behavior, logs in `%PROGRAMDATA%`, and the
build script's signtool hooks for **Authenticode signing** (the single
biggest SmartScreen lever — provide your cert in
`packaging/windows/build_windows.bat`). Nothing here hides from scanners; it
avoids looking like malware in the first place.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# NOTE: always run ExFilTrap through .venv/bin/python — the system
# python3 does not have the dependencies (joblib, sklearn, scapy...).
# To use the system python instead:
#   python3 -m pip install --break-system-packages -r requirements.txt
make test            # 198 tests, no root needed
make train           # trains data/model/rf_model.joblib (reproducible, seeded)
make eval            # reproduces the results table
sudo make service               # live service (iface auto-detected)
```

Single-entry CLI (what the packaged executables expose):

```bash
python -m exfiltrap privileges        # what can this process do?
python -m exfiltrap service --iface eth0   # live capture (needs service privileges)
python -m exfiltrap service --iface wlan0  # live capture (sudo for raw sockets)
python -m exfiltrap dashboard              # standalone UI against a DB
python -m exfiltrap winservice install     # Windows only (elevated)
```

### Isolated research lab (namespaces)

```bash
./tools/netns_setup.sh        # nsA=10.99.0.1 gateway, nsB=10.99.0.2 attacker
sudo ip netns exec nsA .venv/bin/python -m exfiltrap.service --iface veth-gw --mitigation iptables --execute
sudo ip netns exec nsB .venv/bin/python tools/attacker_client.py --target 10.99.0.1 --mode slow-drip
./tools/netns_teardown.sh
```

The iptables backend refuses every path that could touch the host firewall:
it runs plain `iptables` only from *inside* the target namespace, or via
`ip netns exec nsA` from the host; anything else raises `SafetyError`
unless the explicit `--i-know-this-is-isolated` flag is supplied.

## Modules

```
exfiltrap/capture.py          M1  scapy capture → queue (live only)
exfiltrap/features.py         M2  entropy/length/labels/60s-frequency
exfiltrap/session_tracker.py  M3  byte-mass z-test + M3b beacon CV
exfiltrap/baseline_engine.py  M4  EWMA + Welford, warmup-gated threshold
exfiltrap/classifier.py       M5  RF wrapper (100 trees, 4 base-paper features)
exfiltrap/payload_decoder.py  M6  base32(re-padded)/base64/base64url/hex + signatures
exfiltrap/risk_engine.py      M7  CONFIRMED > HIGH > MEDIUM > LOW rule table
exfiltrap/mitigation.py       M8  iptables/netns │ netsh backends + factory
exfiltrap/storage.py          M9a WAL SQLite, batched writes
exfiltrap/dashboard/          M9b web UI (visibility-aware polling)
exfiltrap/service.py          detection service + localhost REST API
exfiltrap/winservice.py       Windows Service wrapper (pywin32, lazy import)
exfiltrap/privileges.py       capability/admin discovery + CLI report
exfiltrap/pipeline.py         full chain wiring, RF-only control switch
tools/                        attacker client, benign generator, trainer,
                              netns lab, Linux install/uninstall
eval/run_evaluation.py        M11: 3 profiles × (full, RF-only), CSV outputs
packaging/linux|windows/      systemd unit, PyInstaller spec, Inno Setup
desktop/                      Tauri shell (tray + health-gated window)
tests/                        15 modules, 198 tests
```

## Resource notes (nothing was removed to get them)

* RF inference: batched vectorized scoring on the synthetic path, and
  `n_jobs=1` at load time (per-row thread dispatch cost 30× the trees).
* Storage: WAL + `synchronous=NORMAL` + buffered batched inserts — the
  capture loop no longer pays an fsync per query; reads flush first so the
  dashboard always sees complete data.
* Dashboard: 5s polling, paused automatically when the tab is hidden.
* Desktop shell: Tauri (OS webview) ≈ tens of MB RAM vs Electron's
  100–200 MB; no dashboard code changed.
* Service hardening is nearly free: the systemd unit adds
  `ProtectSystem=strict`, `NoNewPrivileges`, seccomp-adjacent syscall
  restrictions, and a locked-down service user.

## Honest scope notes

* **Benign corpus**: top 50k of the Cisco Umbrella top-1M (Tranco's daily
  endpoint requires per-day list IDs; Umbrella is the equivalent public
  corpus). Seeded synthetic fallback with a loud warning if the file is
  missing.
* **Evaluation mode**: default is synthetic/in-process — same generators,
  same pipeline, same decisions as live, with virtual timestamps (a 2h drip
  runs in seconds) and no root. `--live` prints the namespace procedure.
* **Windows builds**: the code paths (netsh backend, service wrapper,
  installer scripts) are complete and unit-tested with mocks, but were
  written on Linux — run `packaging/windows/build_windows.bat` on a Windows
  machine to produce the actual artifacts. Same for Tauri icons/builds
  (need Rust + platform webview libs).
* **Slow-drip decode rate is low by design**: the stealthy drip encrypts
  its payload, so M6 triggers but cannot confirm (ciphertext is neither
  printable nor signed). Fast tunneling confirms at 71% with logged
  previews.
* **Known edge**: a drip with *zero* benign background would build its own
  baseline and evade the z-test (the beacon detector still fires on its
  timing). Real networks always carry benign DNS; the evaluation mixes it
  in and the limitation is documented, not hidden.
* **Beacon tradeoff**: perfectly periodic *legitimate* traffic (some
  keepalives) can trip M3b; `BEACON_MAX_CV` (0.25) is the documented knob,
  and both stateful signals independently feed the same risk level.

## Alignment with the base paper

The base paper (ICSCSS 2026) specifies: entropy/domain-length/subdomain/
query-repetition features, a Random Forest classifier, risk levels,
automated firewall mitigation, and a monitoring dashboard. ExFilTrap
implements all of it, then extends where the paper's own future-work
section points (contributions table above). Where numbers differ, the
setups differ honestly: the paper evaluates loud tunneling (95.33%
accuracy / 3.95% FPR); ExFilTrap's fast profile reproduces that regime at
99.97%/0.67% **and** adds a stealth-hardened slow-drip adversary the paper
does not test, where per-query RF alone drops to 34.6% recall and the
stateful layer restores 92.7%. DoH/DoT stay out of scope in both papers.

## Scale behavior (measured, not estimated)

Question this project had to answer: *what happens at 20,000+ queries?*

| path | before | after | notes |
|---|---|---|---|
| live capture → detection | 17 q/s | **283 q/s** | capture loop now micro-batches (64) into one vectorized RF call; 20k queries process in **71 s** instead of 20 min |
| batched/replay path | 129 q/s | 283 q/s | sklearn per-call overhead removed (warnings + batching) |
| dashboard `/api/stats` @20k rows | 18 ms | 47 ms | now also computes risk distribution + top-talkers |
| dashboard worst endpoint @20k rows | 27 ms | <50 ms | queries/alerts feeds: 3–6 ms |
| storage | — | WAL + batched commits | no per-query fsync; flush every N or on read |

At 283 q/s a single service instance sustains ~24M queries/day on one
core; multi-Gbps enterprise resolvers (100k+ qps) shard by forwarder —
noted as future work. The dashboard polls only while visible and pauses
on hidden tabs.

## The one dashboard (web, Linux, Windows)

There is exactly **one** dashboard UI — the web console served by the
detection service. The Linux desktop app (Tauri/WebKitGTK) and the
Windows app (WebView2) are thin native windows around that same page, so
every improvement lands on all three platforms at once. Current console:
Overview (live KPIs, queries-vs-flagged flow, risk doughnut, top talkers,
latest alerts), Live Queries (search + risk filter over a 200-row feed),
Alerts (filterable, decoded payload column), Sessions (live M3 state:
mean mass, interval CV, MASS/BEACON signal badges), Blocked IPs, plus a
status header (mode, uptime, capture heartbeat) and pausable 5s refresh.

## Definition of Done

- [x] 202 unit/integration tests pass (one root-only live-sniff skip).
- [x] Full pipeline runs end-to-end (synthetic evaluation; live lab
      procedure + scripts; service smoke-tested live with HTTP
      API verified).
- [x] **Live deployment validated on a real host** (namespace lab, real
      packets, real firewall): 1,857 packets processed, 664 payloads decoded
      and CONFIRMED, automated iptables block installed inside nsA, host
      firewall byte-identical afterwards — see
      `eval/results/live_deployment_report.md` (rerun: `bash tools/deploy_live.sh`).
- [x] Metrics for all three profiles + RF-only control from real runs.
- [x] Slow-drip recall 0.927 ≫ RF-only 0.346.
- [x] Confirmed decoded payload samples in logs (`decoded_preview`).
- [x] Mitigation proven namespace-scoped (iptables) / admin-gated (netsh).
- [x] Runs as root or capability-bounded service — installer elevates
      once, daily use never does.

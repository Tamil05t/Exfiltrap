# SESSION HANDOFF — read this FIRST in any new session

**Project:** ExfilTrap — stateful DNS tunneling & slow-drip exfiltration detection
**Owner:** final-year student (Tamil05t on GitHub, user `tamilarasu` on the machine)
**Repo:** https://github.com/Tamil05t/Exfiltrap (branch `main`, CI: `.github/workflows/build.yml`)
**Local:** `/home/tamilarasu/Exfiltrap` — venv at `.venv/` (always use `.venv/bin/python`; system python3 lacks deps)
**State at handoff:** see §9 — 2026-09-10 soak: shipped-product validation, 4 live bugs found & fixed, paper numbers refreshed. 253 tests passing. Local commits NOT yet pushed (token lost in reboot — user must provide a fresh one).

---

## 9. 2026-09-10 SOAK + BUG LEDGER (latest session — read after §1)

**What ran:** 2h+ three-track validation. GitHub-CI builds (1.3.2 deb + AppImage,
run #44 — engine byte-identical to run #45) exercised in unprivileged
`unshare -Urn` sandboxes (root userns → real AF_PACKET capture, fake DNS
resolver, virgin DBs) while the user's live engine (wlo1, real LAN) ran the
same scenario driver on the host. All results in /tmp/soak-exfiltrap/
(wiped on reboot; key numbers below).

**Product results:** sandbox tracks 136 attack rounds — every loud attack
CAUGHT, every control clean. Host track 205 rounds — 153 CAUGHT, 18 control
passes, 34 misses (all = the beacon bug below + known hard phonotactic/mass
case on a busy shared IP). Fresh-install check: virgin DB = clean dashboard
(0 rows); BUT the deb ships no maintainer scripts → /var/lib/exfiltrap
DB persists across reinstalls (user's "old queries on fresh open" complaint
— measured: 33k stale rows). Host DB reset needs the user's sudo.

**Bugs found & fixed (all unit-tested + live-verified in the sandbox):**
16. **M3b beacon never fires in shipped builds** (a) CV over ALL 2h-window
    gaps → one 10-min idle gap between sessions kills it forever → now
    trailing MIN_QUERIES-1 gaps (session_tracker.py). (b) AF_PACKET on lo
    double-delivers every packet (88 queries → 176 rows) → alternating
    0/5.5s gaps, CV≈1 → DuplicateFilter in capture.py prn path.
17. **CaptureSupervisor never started sniffers** (spawn factory returned an
    unstarted sniffer; thread=None → eternal restart loop). Factory now
    starts; found by the supervisor's own restart-loop log on first run.
18. **O(N²) pipeline** — per-query full-window sums (session mass, response
    mass), full-window beacon CV, and median/MAD recompute per query →
    20k-query flood scored at ~25 q/s. Now: O(1) running cumulative sums,
    trailing-gap CV, MAD cache (recompute every 16 obs) → **571 q/s**
    benign mix / 241 q/s unique-DGA flood in-process (paper claimed 283).
19. **Paper draft was stale** — claimed 92.36%/36.55%/t=42.78 from a
    pre-robustness-fix JSON. Reproduced with `make eval` (85.45%/37.27%)
    and new `--multiseed N` mode (84.73%±0.76 vs 40.36%±4.53, t=25.94,
    p=1.31e-5). Paper updated everywhere; multiseed_stats.json refreshed.

**Verified live in sandbox after fixes:** beacon rounds on lo fire M3b
("beacon regularity" HIGH) AND re-fire after a 3-min idle gap.

**Still pending:** push the 5 local commits (user token); fresh CI build
= 1.3.3 with all fixes; host-DB reset paste-block for the user; Windows
install untested (no host); scapy veth capture sees no packets (kernel
RX-ring quirk — lab-only note, real NICs fine).

---

## 1. WHAT THE PROJECT IS

Detection engine + product for DNS tunneling / slow-drip data exfiltration.
Extends a base paper (per-query Random Forest, ICSCSS 2026) — the paper's
own future-work list maps 1:1 to the contributions (see README "Alignment").

Detection chain (M1→M9): scapy capture → features (entropy/length/labels/
60s freq) → Random Forest (100 trees) → stateful session layer (entropy-
weighted byte mass z-test) → beacon CV detector → **domain-level signals
(velocity + per-domain beacon — newest, v1.3.0)** → payload decoder
(base32/base64/hex + file signatures) → risk engine (LOW/MEDIUM/HIGH/
CONFIRMED) → policy mitigation (iptables namespace-scoped / netsh on
Windows; allowlist + TTL auto-unban + unblock API) → WAL SQLite storage →
localhost REST API + dashboard (web/Tauri desktop).

Key evaluation numbers (5-seed, reproducible via `make eval`):
- slow-drip recall **85.45%** (full) vs **37.27%** (RF-only control) — +48pt
- benign FPR **0.71%** (full) vs 4.03% (control)
- fast tunneling: 100% recall, 71.43% payload decode
- throughput 283 q/s after micro-batching; ~220 MiB RSS steady

## 2. HOW TO WORK WITH THE USER (learned over 30+ sessions)

- User speaks casually, sometimes with typos — parse intent, don't correct.
- User HATES apologies + monitoring GitHub passively. Wants: research FIRST
  (real docs/issues, e.g. Tauri upstream), then targeted fixes, then verify
  by RUNNING things. "Do real work, not act like fixing."
- User was burned by: repeated "install libfuse2" on Kali (removed from
  repos), AppImage debugging loops, silent CI artifact regressions.
  NEVER tell them to install libfuse2 on Kali. NEVER ship a package
  without an in-app error surface.
- Popups (zenity) for sudo sometimes get missed/closed. The reliable path
  is a terminal paste-block the user runs themselves, OR a one-click
  script (`~/Desktop/START-EXFILTRAP.sh` exists on Mint for this).
- User communicates test results via pasted terminal output — READ IT
  COMPLETELY before acting; it has contained the smoking gun every time.
- GitHub token used for pushes: user pasted `ghp_tGIb...` in chat —
  REMIND THEM TO REVOKE IT. Generate a new one (repo+workflow scopes) for
  future pushes, or have them push manually.

## 3. CURRENT ARCHITECTURE (files that matter)

```
exfiltrap/
  capture.py       M1 scapy; packet_to_query + packet_to_response;
                   make_sniffer accepts iface LIST (str|list[str])
  features.py      M2 entropy/length/subdomain/frequency; base_domain()
                   = last-two-labels rule
  baseline_engine.py  EWMA + Welford + rolling window with (mass, src)
                   tuples; CRITICAL: population_stats_excluding(src) =
                   leave-one-source-out (mean, MAD, n) — the fix for
                   attacker-poisoned baselines
  session_tracker.py  M3: per-source 2h window; sequential z-test with
                   robust MAD scale + practical-significance guard
                   (SESSION_ELEVATION_RATIO=1.8) + 30-query minimum;
                   M3b beacon CV (>=20 q, CV<0.25, mean gap >=5s);
                   M3c DOMAIN-LEVEL: per-(src, base_domain) windows,
                   velocity (>=15 labels entropy>=3.0 in 60s) and
                   per-domain beacon — thread-safe (RLock, stress-found
                   race); save/load state (warm restart)
  classifier.py    M5 RF wrapper; load() sets n_jobs=1; predict_proba_many
                   batched; suppresses sklearn UserWarnings
  payload_decoder.py M6 base32(re-padded)/base64/hex + signatures
  risk_engine.py   M7 rule table; beacon_candidate param
  mitigation.py    M8 iptables (namespace-scoped, stat-based ns detection)
                   + NetshMitigation (Windows) + factory; unblock_ip
  policy.py        TTL auto-unban wrapper (PolicyMitigation, reap_expired)
  alerting.py      syslog (RFC3164 lines, dedup 1/src/level/hour)
  storage.py       WAL, autocommit + busy_timeout=5000 (multi-connection
                   lock fix), batched commits, remove_block, analytics
  dashboard/       Flask app + templates/index.html (tabbed console:
                   Overview/Live Queries/Alerts/Sessions/Blocked; RESP
                   badges; clickable detail rows) + waiting.html (desktop
                   start screen with Start button + engine log surface)
  service.py       the daemon: --iface (auto-detect via netif -> [uplink,
                   lo]), batched worker, warm restart, watchdog, policy,
                   alerting; --fresh-db; NO demo mode (removed by user)
  winservice.py    Windows service wrapper (pywin32)
  privileges.py    capability/admin discovery
  netif.py         default-route interface detection (/proc/net/route,
                   PowerShell on Windows)
  pipeline.py      ExfilTrapPipeline: process_query/process_many (batched)
                   /process_response (M3 response channel); rf_only switch
tools/
  attacker_client.py   M10: fast/slow-drip modes; slow-drip = ENCRYPTED
                       keystream-XOR + hex + 4-10B variable chunks +
                       corpus-length DGA; send via DNS-message bytes only
                       (raw-socket send = double-encapsulation bug);
                       make_sample_payload() shared by train+eval
  benign_traffic_gen.py  top-50k corpus, Poisson arrivals, --source-ip
  stress_traffic.py    random-DGA profile for stress tests
  train_classifier.py  RF trainer; NOW includes text_tunnel_rows() —
                       base32/hex of ASCII documents (entropy 2.8-4.3),
                       added after live red-team found the gap
  deploy_live.sh       namespace lab deploy (sudo popup via zenity)
  stress_test.sh       stress suite v2
  netif helpers, install/uninstall scripts, make_icon.py
eval/run_evaluation.py  3 profiles x (full, rf-only); PROFILES dict seeds
desktop/            Tauri v2 app (WebView: waiting.html -> dashboard);
                    bundles the PyInstaller engine as a resource;
                    start_service via pkexec from root-owned copy at
                    /var/lib/exfiltrap/engine
packaging/          linux (systemd unit w/ AmbientCapabilities+watchdog,
                    PyInstaller spec) + windows (Inno Setup + PyInstaller
                    spec --onedir, no UPX)
```

## 4. THE BUG LEDGER (every live-found bug and its fix — cite these)

1. Wire format: senders sent whole IP packets through UDP sockets ->
   double encapsulation -> garbage qnames. Fix: DNS-message bytes only.
2. Metronome traffic tripped beacon (CV=0) -> BEACON_MIN_INTERVAL_S=5
   (only slow periodicity is C2-like).
3. Mitigation namespace self-check failed under restricted readlink ->
   stat(2) dev/inode keys + safe `ip netns exec` fallback.
4. Mitigation exceptions killed the processing thread -> try/except
   resilience boundary + "REFUSED" logging (and duplicate-blocks are NOT
   logged as refusals).
5. Thread race: "deque mutated during iteration" between capture and
   snapshot threads -> RLock serialization in SessionTracker.
6. SIGTERM orphan bug -> 5s graceful finalizer + os._exit.
7. Multi-connection SQLite deadlock -> autocommit + busy_timeout.
8. Per-query thread dispatch 17 q/s -> batched 283 q/s.
9. sklearn missing from frozen builds -> hiddenimports incl. private
   pickle submodules; CI smoke = real model load.
10. Tauri config schema drift (v1/v2) -> v2 with correct key placement.
11. Blank/frozen webview on Linux -> WEBKIT_DISABLE_DMABUF_RENDERER=1 +
    WEBKIT_DISABLE_COMPOSITING_MODE=1 set in main(); LIBGL_ALWAYS_SOFTWARE
    and EXCLUDE_LIBRARIES experiments REVERTED (they caused the failure).
12. pkexec self-kill: `pkill -f exfiltrap` matched the script's own
    cmdline -> `pkill -x exfiltrap`.
13. Engine Permission denied from deb/AppImage resources -> copy to
    /var/lib/exfiltrap/engine, chmod +x, launch from there.
14. apt upgrades were no-ops (all builds "1.0.0") -> version bumps.
15. THE DETECTION GAPS (most important — found by live red-teaming):
    a. base32-of-TEXT tunnels (entropy 2.8-4.3) absent from training
       corpus (random bytes only) -> live tunnel scored 0.01 -> trainer
       now includes text-document tunnels.
    b. per-source mass z-test drowned in real host variance (session CV
       4-7, heavy ambient labels) -> robust MAD scale + practical
       significance (1.8x) + 30-query minimum.
    c. attacker poisoned its own baseline (mean dragged to 21.6) ->
       leave-one-source-out population stats.
    d. on real hosts the attack session MIXES with legitimate traffic ->
       per-source signals insufficient -> NEW domain-level signals
       (velocity + per-domain beacon), validated offline: velocity fires
       at query 15 on the real captured attack stream.

## 5. PENDING / KNOWN ISSUES

- **User must run the final bring-up on Mint** (v1.3.0 deb in
  ~/Downloads, or double-click ~/Desktop/START-EXFILTRAP.sh). Last check:
  engine ran 16+ min healthy; needs restart on the newest code.
- **Kali: v1.3.0 deb** also in ~/Downloads (run #38 or later); engine
  start verified working there previously.
- **AppImage on Linux is REMOVED** (bundled webkit EGL cannot work in
  GPU-less VMs — upstream limitation, tauri#11994). Linux formats: .deb
  (primary) + portable tarball (FUSE-free). AppImage remains only for
  distros with libfuse2 and working GL.
- **Windows Setup installer** builds but has never been run on a real
  Windows machine (no Windows host available). Needs: Npcap install,
  service registration test, antivirus observation.
- **Version bump note**: every fix so far shipped inside version strings
  that sometimes lagged; current version is 1.3.0 — bump on next release.
- **Response channel (M3-resp)**: implemented + unit-tested, fires on
  real traffic (seen on Mint: "answer mass 361321B" alerts on github.com
  — TUNING NEEDED: ambient HTTPS-adjacent DNS volume triggers it too
  easily; consider entropy threshold raise or per-domain whitelisting).
- **Known limitation (documented)**: rotating the tunnel BASE domain
  (>=10 domains) defeats per-domain timing. Future: second-level
  reputation windows.

## 6. KEY COMMANDS

```bash
cd /home/tamilarasu/Exfiltrap
.venv/bin/python -m pytest              # 245 tests (no root)
make train                              # retrain RF (includes text tunnels)
make eval                               # eval: slow-drip 85.45% vs 37.27%
sudo make service                       # live engine (iface auto-detect)
sudo make service IFACE=wlo1            # explicit iface
python3 -m exfiltrap.service --help     # all flags
sudo ./tools/install_linux.sh IFACE     # production install (systemd)
bash tools/deploy_live.sh               # namespace lab fire test
bash tools/stress_test.sh               # stress suite
bash tools/live_adversarial_test.py     # 5-phase red-team vs live engine
git push                                # after committing (token needed)
```

CI: pushing to main auto-builds Windows exe+installer, Linux deb +
portable + service tarball. Artifacts appear on the Actions tab.
Note: artifact filenames are natural now (ExFilTrap_<ver>_amd64.deb).

## 7. USER'S PAPER

- Base paper: "Advanced Algorithmic Techniques for the Detection of DNS
  Tunneling..." ICSCSS 2026 (their docx sample shows the expected
  structure: Aim/Materials-Methods/Result/Conclusion abstract, Group 1 =
  existing vs Group 2 = proposed, SPSS-style t-test tables).
- Draft exists: paper/EXFILTRAP_PAPER.md (full sections written; numbers
  from the 5-seed run: recall 92.36%±0.73 vs 36.55%±2.60, t=42.78,
  p<0.001 — NOTE: after the v1.2.0/v1.3.0 robustness fixes the numbers
  changed to 85.45% vs 37.27%; the paper draft tables need updating).
- 75 references collected (see 'Exfiltrap References.docx' in user's
  Downloads). Key citations to weave in: Sandhya '25 (accuracy trap),
  Al Musa '26 (ML-resistant phonotactic channel), James '26 (adversarial
  mutation), Nadler '19 (low-and-slow), Mahdavifar '21 (CIC-Bell dataset).
- Google Scholar workflow for Chicago citations was explained to user.

## 8. GROUND RULES (user-confirmed)

1. Root-only product; no demo mode (user removed it deliberately).
2. Everything must work as installed products (.deb/.exe), not just
   from source. Research current docs before changing packaging.
3. No fake numbers anywhere. Every claim measured and reproducible.
4. Verify OFFLINE first, then package, then live-test. Never push and
   "monitor GitHub hoping".
5. When user reports an issue: read their ENTIRE paste — the evidence
   has always been in it.
```

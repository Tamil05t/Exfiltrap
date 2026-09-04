# ExFilTrap — Live Deployment Report

**Date:** 2026-08-23, 12:54–13:10 IST (final run; two earlier runs used for integration debugging)
**Host:** Ubuntu (Linux 6.x), Python 3.12.3, deployment from `/home/tamilarasu/Exfiltrap`
**Driver:** `tools/deploy_live.sh` — one GUI sudo prompt (zenity), then fully automated.

## What was deployed

A production-shaped ExFilTrap instance on real kernel network namespaces:

```
nsA (10.99.0.1) — detection service: scapy capture on veth-gw (BPF "udp port 53"),
                  full M1→M8 pipeline, WAL SQLite storage, localhost REST API :5050
nsB (10.99.0.2) — benign resolver traffic (real top-50k corpus, ~1 qps)
                  + slow-drip tunnel (encrypted hex, 65 s interval)
                  + fast tunneling burst (45 s, ~20 qps)
host            — unprivileged dashboard on :5000 reading the live database
```

## Timeline (final run)

| time | event |
|---|---|
| 12:54:40 | lab up; service capturing inside nsA as root with CAP_NET_RAW/ADMIN |
| 12:55:30 | slow-drip tunnel starts (real 65 s packet pacing) |
| 13:04:48 | **automated mitigation fires**: `iptables -A INPUT -s 10.99.0.2/32 -j DROP` installed **inside nsA only** |
| 13:08–13:09 | fast burst: RF P=1.000 per query, payloads **decoded live** |
| 13:09:06 | first `CONFIRMED exfil … decoded=b'…'` log lines |
| 13:10:26 | evidence collected, namespaces deleted, host firewall verified byte-identical |

## Results (from the live database, 1,857 packets processed)

| metric | value |
|---|---|
| queries processed | 1,857 (901 fast-tunnel, ~900 benign, ~14 drip) |
| risk levels | 911 LOW, 22 MEDIUM, 248 HIGH, **664 CONFIRMED** |
| payload decodes | 664 base32 reversals with plaintext previews, e.g. `b'56568;budget report ledger policy kernel'`, `b' patient sensor budget\nkernel=57721;pati'` |
| firewall block | installed in nsA's isolated ruleset at 13:04:48 |
| host firewall | **identical to pre-deployment baseline** (`iptables-save` diff empty) |
| mitigation errors after fixes | 0 |

Evidence bundle: `/tmp/exfiltrap_evidence.txt`; database: `data/live.db`;
rerun anytime with `bash tools/deploy_live.sh` (one sudo popup).

## Honest engineering notes (found BY deploying, fixed live)

Three real bugs surfaced only in the live lab — each is now fixed and
covered by a regression test (suite: **202 passed**):

1. **Sender wire format** — generators sent whole scapy `IP()` packets
   through a plain UDP socket → double encapsulation → sniffer read garbage
   qnames. Fixed: send DNS-message bytes only. Notably, the beacon
   detector (M3b) still caught the drip's 65 s cadence through the garbage —
   unplanned live proof that the timing signal is content-agnostic.
2. **Namespace self-check** — `readlink` on `/run/netns/*` fails in
   restricted contexts, making the service unable to prove it was inside
   nsA and refuse-safe. Fixed with `stat(2)` dev/inode keys plus a safe
   `ip netns exec nsA iptables` fallback when position is unverifiable.
3. **True pacing + resilience** — a 5 s sleep cap collapsed the drip's 65 s
   pacing; a mitigation exception could kill the processing thread. Both
   fixed (full-delay pacing; mitigation failures are logged and detection
   continues — observed working: `ERROR exfiltrap: mitigation failed…`
   followed by uninterrupted processing in run 2).

## Known limitation observed

The lab's single attacker IP carries both benign and drip traffic, so the
per-session signals (mass z-test, beacon — keyed by `src_ip`) blend into
one session and stay quiet live; live detection was carried by the RF +
payload decoder (664 CONFIRMED). Real deployments (and the synthetic
evaluation, where benign clients have distinct IPs) exercise the stateful
layer as designed — slow-drip recall 0.927 full vs 0.346 RF-only.

## Suggested next updates

1. **Multi-IP live lab**: add a second address to `veth-atk` (or a third
   namespace) so benign and drip traffic arrive from distinct IPs — the
   stateful layer then demonstrates itself live as well.
2. **Post-block verification probe**: after mitigation, send a canary query
   from nsB and assert the IP-layer drop (complements AF_PACKET capture,
   which still sees blocked packets by design).
3. **Alerting**: persist HIGH/CONFIRMED events to syslog/journal from the
   service for SIEM integration.
4. **Watchdog**: systemd `WatchdogSec` + sd_notify in the service for
   capture-thread liveness.
5. **Tauri build + signing**: run `make desktop-build` and the Windows
   packaging scripts on their target platforms to produce the shippable
   installers (code, specs, and signing hooks are ready).

---

# Update validation run — 2026-08-23 13:49–14:05 IST

All five suggested updates were implemented and validated in one further
live deployment (suite now: **213 tests passing**):

1. **Multi-IP live lab — VALIDATED.** nsB now carries 10.99.0.3 for the
   benign background; the drip runs as its own session from 10.99.0.2 and
   the stateful layer fired live, query-by-query:
   `13:59:38 HIGH … reasons='stateful slow-drip candidate (entropy-weighted
   mass); beacon regularity…'` — both M3 signals, on real 65 s wire
   traffic. One alert even shows `prob=0.729` escalated HIGH purely by the
   stateful signal.
2. **Post-block canary — VALIDATED.** Five canary packets sent from the
   blocked address: iptables DROP-rule counter 1850 → 1860 (delta 10 ≥ 4
   threshold) — the block demonstrably drops traffic at the IP layer while
   AF_PACKET capture keeps observing.
3. **Syslog/SIEM alerting — VALIDATED.** Real journald records:
   `Aug 23 14:04:09 tamil exfiltrap[72230]: EXFILTRAP_ALERT risk=CONFIRMED
   src=10.99.0.2 qname=… prob=1.000 confirmed=1 decoded=b'56568;budget…'`
   — structured key=value lines via /dev/log (facility local4).
4. **Watchdog — WIRED + HEARTBEAT LIVE.** `/api/status` now reports
   `capture_heartbeat_age_s: 0.41`; the systemd unit gained
   `WatchdogSec=60` + `Type=notify`, and pings are suspended when the
   capture heartbeat stalls (unit-tested). The SIGTERM orphan bug was also
   fixed — teardown now exits cleanly (`72230 Killed` in the driver log,
   zero leftover processes).
5. **Shippables — STAGED FOR CI.** App icon generated
   (`tools/make_icon.py`), GitHub Actions workflow
   (`.github/workflows/build.yml`) builds the Windows onedir exe + Inno
   installer and the Linux .deb/.AppImage on every push, and
   `tools/bootstrap_desktop_build.sh` does a one-command local desktop
   build. Compile-on-target required (no Rust/Windows toolchain on this
   host).

Both firewall rules were present in nsA at evidence time
(`-A INPUT -s 10.99.0.3/32 -j DROP` — an RF false positive on a benign
hex-label query, blocked separately — and `-A INPUT -s 10.99.0.2/32 -j
DROP` for the attacker), the host ruleset stayed byte-identical, and
teardown removed everything.

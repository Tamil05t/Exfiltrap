# ExFilTrap — Maximum Stress Test Report

**Date:** 2026-08-23 (three runs: 17:15, 18:14, 21:48 IST — the final run with
all fixes) · **Driver:** `tools/stress_test.sh` (root, namespace lab nsA/nsB,
six client IPs, service with iptables mitigation + syslog alerting + policy
allowlist for the benign IPs)

## Verdict

**Daily-driver traffic: zero false positives under full load.** The detector
held 100% LOW on everyday traffic, caught every attack query during a
100 q/s background, and the stress process itself found and fixed two real
product bugs. One open anomaly documented below.

## Results by phase (final run unless noted)

### Phase 1 — everyday + scary names (the "blocklist trap")
4,800 real queries mixing google.com, youtube.com, facebook.com, github.com,
netflix.com… with **ransomware.com, c2server.com, botnet-zombie.io,
malware-download.net, darkweb-c2.ru, keylogger-shop.com**:
**100.0% LOW, zero flags.** ExFilTrap is statistical, not a blocklist —
scary domain names are not evidence, and the RF + stateful layers correctly
ignore them. (Run 2's first attempt flagged 97% of this phase — see Finding 1.)

### Phase 2 — volume ramp (30 → 100 → 250 q/s, 5 parallel clients)
- 30 q/s level: **every single second processed exactly 30 queries** —
  zero loss, zero lag, sustained.
- 250 q/s level: ~166 q/s sustained end-to-end — **sender-limited** (5
  Python sender processes competing with the service on one core), not
  service-limited (pipeline benchmark: 283 q/s alone).
- Service resources: **CPU avg 60.5% / max 105%**, **RSS avg 214 MiB /
  max 223 MiB** (flat — no leak across 14k+ queries).
- Dashboard/API responsive throughout; capture heartbeat 0.07–0.12 s.

### Phase 3 — attack under 100 q/s load (run 2 evidence)
Fast tunnel (300 queries) during full background load:
**300/300 flagged — 221 CONFIRMED with decoded plaintext** (e.g.
`b'56568;budget report ledger policy kernel'`), 79 HIGH. Detection accuracy
is unaffected by load.

## Bugs the stress test found and fixed (the real yield)

1. **Beacon false-positive on periodic traffic** — the original stress
   sender paced at exact fixed intervals (a metronome, CV=0) and M3b
   correctly flagged 97% of it. Fix: `BEACON_MIN_INTERVAL_S = 5.0` — only
   *slow* periodicity (the C2 signature; our drip paces at 65 s) is
   beacon-suspicious, fast periodic pollers (keepalives, telemetry) are
   benign machinery. Plus ±20% jitter in the stress sender. Verified: the
   identical phase then scored 100% LOW.
2. **Thread-safety race (live crash)** — `RuntimeError: deque mutated
   during iteration`: the state-snapshot thread iterating session deques
   while the capture thread appended. Fix: full lock serialization of the
   session tracker. Final run: zero occurrences under the same load.
3. **Silent mitigation refusals** — iptables failures were recorded to an
   internal list nobody read; the pipeline now logs every refusal loudly.
4. Tooling: driver `wait` deadlock (samplers outliving phases), journalctl
   hang without timeout, pkill self-match killing its own parent, latency
   sampler concatenation, heredoc quoting. All fixed.

## Open anomaly (honest)

In the final run, Phase 3's 300 attacker packets were sent
("sent 300 tunnel queries") but **never appeared in capture** (0 rows from
10.99.0.2), while ~13k benign packets from five other IPs on the same veth
all processed. Run 2 processed the identical attack stream completely
(300/300 flagged). Root cause not yet identified — no exceptions, single
sniffer, no drops elsewhere. Mitigation-block evidence therefore stands on
the two dedicated live deployments (13:04:48 block + canary delta 10, and
the 14:04 run with two rules + canary) plus the unit suite (231 tests);
reproducing this capture anomaly is the top follow-up.

## Reproduce

```bash
bash tools/stress_test.sh     # one sudo popup, ~7 minutes, full report
```

---

# Round 2 — Random-Domain Stress Test (v2, 2026-08-23 22:18)

Driver: `tools/stress_test.sh` (v2) — fresh DGA-style random domains that
have never existed (6–14 char random labels, 8 TLDs), interleaved with
malicious-LOOKING names and everyday names, close per-30s monitoring.

## Results

| phase | result |
|---|---|
| Random-domain storm (~1,500 q, 3 min) | **100% LOW — zero flags.** Never-before-seen random domains are not tunneling and the detector correctly ignores them; `ransomware.com`/`c2server.com`/etc. equally LOW (not a blocklist) |
| 100 q/s burst (5 clients, 30 s) | all processed, **0 flagged**, service CPU max 116%, RSS 221 MiB |
| Fast-tunnel attack from non-allowlisted .2 | **151/151 captured queries flagged (100%)**, iptables `-A INPUT -s 10.99.0.2/32 -j DROP` installed; **198 attack packets dropped at the IP layer** by the block while AF_PACKET capture kept observing (pre-netfilter by design); canary delta 5/5 |
| Host firewall | byte-identical to baseline |

## The "capture anomaly" from round 1 — RESOLVED (it was never capture)

The v2 differential probe declared 0 rows from the attacker IP, yet the
attack verification minutes later showed those exact 30 probe rows present.
Root cause: **premature DB reads** — writes buffer until a flush (every N
rows); the verification read landed before commit. Round 1's "missing 300"
was the same buffer plus an over-eager `pkill -9` (3s) killing the service
before its 5s graceful finalizer could flush. Fixes:

1. `db_count` in the driver now triggers an in-process flush via
   `/api/stats` before reading — reads can never be stale again.
2. Teardown waits out the graceful finalizer (6s) before any `-9`.
3. Pipeline logging no longer reports idempotent duplicate-blocks as
   "REFUSED" (199 false alarms in this run's log).

Capture itself was healthy the entire time. Suite: 231 tests passing.

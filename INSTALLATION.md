# ExFilTrap — Installation Guide

How to install, what to configure, and how to verify it works — for every
distribution format. **Read section 1 first**: two decisions are yours to
make on any platform.

---

## 1. What YOU must configure (the only two decisions)

| decision | default | where to change |
|---|---|---|
| **Which network interface to monitor** | Windows: read from `service.ini` (falls back to demo mode); Linux: the name you pass to `systemctl start exfiltrap@<iface>` | Windows: `%PROGRAMDATA%\ExFilTrap\service.ini` → `[service] iface = Ethernet` · Linux: the unit instance name |
| **Whether mitigation actually blocks** | **log-only** (safe default: detections logged, nothing blocked) | Windows: `service.ini` → `mitigation = netsh` / `execute = yes` · Linux: systemd drop-in `Environment=EXFILTRAP_MITIGATION=iptables` + `EXFILTRAP_EXECUTE=1` |

Everything else works out of the box with sane defaults. Optional knobs are
in section 6.

**Privilege model (why you enter a password once):** packet capture and
firewall rules need elevated rights, so the *installer/service* elevates
once. The dashboard is always unprivileged — it only reads the local API on
`127.0.0.1:5050`/`:5000`.

---

## 2. Windows — `ExFilTrap-Setup.exe` (Inno Setup installer)

**Prerequisites:** Windows 10/11, admin rights for the install only.
Npcap (the capture driver Wireshark uses) is bundled and installed
silently — no separate download.

1. Double-click **`ExFilTrap-Setup.exe`** → accept the single **UAC prompt**.
2. The installer: copies to `Program Files\ExFilTrap`, silently installs
   Npcap if absent, writes `%PROGRAMDATA%\ExFilTrap\service.ini`, registers
   the **ExFilTrapSvc** Windows Service (auto-start at boot) and starts it.
3. Edit the interface if needed (see section 1):
   ```ini
   [%PROGRAMDATA%\ExFilTrap\service.ini]
   [service]
   iface = Ethernet          ; run `exfiltrap.exe service --demo` to see interfaces, or check adapter names in ncpa.cpl
   mitigation = log          ; log | netsh
   execute = no              ; yes = actually create firewall rules
   ```
4. Restart the service after editing:
   `exfiltrap.exe winservice stop` then `start` (elevated prompt).
5. Open the dashboard: Start Menu → **ExFilTrap** (or any browser →
   `http://127.0.0.1:5050`).

**Portable alternative (no install):** unzip the `exfiltrap/` onedir build
and run `exfiltrap.exe service --demo` — a full synthetic-incident demo
with zero capture rights needed. Live capture without the installer:
`exfiltrap.exe service --iface Ethernet` from an elevated prompt (Npcap
must already be installed).

**Verify:** `exfiltrap.exe privileges` → `can_capture: true`;
`curl http://127.0.0.1:5050/api/status` → `"mode": "live:..."`.

**Uninstall:** Settings → Apps → ExFilTrap (stops and removes the service
and `%PROGRAMDATA%\ExFilTrap`).

---

## 3. Linux — pick one of three

### 3a. `.deb` package (Debian/Ubuntu)
```bash
sudo apt install ./exfiltrap-desktop_1.0.0_amd64.deb   # desktop app only
```
The service itself installs from source (3c) or via the install script; the
`.deb`/`.AppImage` carry the **desktop monitor**.

### 3b. AppImage (any distro, no install, no root)
```bash
chmod +x ExFilTrap-1.0.0.AppImage
./ExFilTrap-1.0.0.AppImage
```
It lives in the system tray and attaches to a running service's API. If no
service is running it stays in the tray and keeps polling — start the
service (3c) and the window opens automatically.

### 3c. The detection service (from source — the normal route)
```bash
git clone <your-repo> && cd exfiltrap
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tools/train_classifier.py     # one-time: trains the RF model

sudo ./tools/install_linux.sh eth0             # ONE sudo prompt, then never again
sudo systemctl start exfiltrap@eth0            # start (also: enable = boot start)
```
The installer creates a locked-down `exfiltrap` user, installs a hardened
systemd unit granting **only** `CAP_NET_RAW`+`CAP_NET_ADMIN` (the service
is never root), trains the model if needed, and enables the unit.

Dashboard: any browser → `http://127.0.0.1:5050` (served by the service).

**No-root demo/laptop mode:**
```bash
.venv/bin/python -m exfiltrap.service --demo      # synthetic incident + UI
```

**Uninstall:** `sudo ./tools/uninstall_linux.sh eth0`.

---

## 4. First-run verification checklist (any platform)

```bash
exfiltrap privileges                    # (source: .venv/bin/python -m exfiltrap.privileges)
curl http://127.0.0.1:5050/api/status   # mode, uptime, capture_heartbeat_age_s
```
Open the dashboard: the header should show the mode and a **green heartbeat
dot**; send any DNS traffic from the machine and watch the Overview counters
move. To see detection immediately, run the demo mode — it replays a staged
slow-drip + fast-tunnel incident through the real pipeline.

---

## 5. Where the data lives

| what | where |
|---|---|
| detection database (WAL SQLite) | Linux service: `/var/lib/exfiltrap/exfiltrap.db` · manual runs: `data/exfiltrap.db` (or `--db`) |
| session/baseline snapshot (warm restart) | next to the DB: `<db>.state.json` |
| logs | systemd: `journalctl -t exfiltrap` · Windows: service log + journal/alerts via syslog |
| SIEM alerts | `EXFILTRAP_ALERT ...` lines in syslog/journal (facility local4), one per source/level/hour |

---

## 6. Optional configuration reference

Linux systemd drop-in (`sudo systemctl edit exfiltrap@eth0`):
```ini
[Service]
Environment=EXFILTRAP_MITIGATION=iptables   # firewall backend (default log)
Environment=EXFILTRAP_EXECUTE=1             # 1 = install rules, 0 = dry-run
Environment=EXFILTRAP_ALERT=syslog          # SIEM alerting on
Environment=EXFILTRAP_API_PORT=5050
```
Service flags (all platforms): `--allowlist ip1,ip2` (never blocked),
`--block-ttl 3600` (auto-unban seconds), `--alert none|syslog`,
`--api-host 127.0.0.1` (do NOT expose beyond localhost without adding auth).

Detection thresholds live in `exfiltrap/config.py` — every constant is
commented; `BEACON_MAX_CV`, `RISK_HIGH_THRESHOLD`, `BASELINE_K` are the ones
you'd tune first.

---

## 7. Troubleshooting

| symptom | fix |
|---|---|
| "this process cannot capture packets" | run via the installed service, or `sudo` interactively; check `exfiltrap privileges` |
| Windows: capture dead | Npcap missing → reinstall it (bundled in Setup), check `iface` name in `service.ini` |
| dashboard shows stale heartbeats / nothing | service down → `systemctl status exfiltrap@<iface>` / `exfiltrap.exe winservice start` |
| port 5050 busy | another instance running, or set `--api-port` |
| a benign host got blocked | use the Blocked tab's unblock button (TTL also auto-unbans), then add it to `--allowlist` |
| benched/CI machine without syslog | alerts degrade to a no-op silently; UI and DB are unaffected |

---

## 8. Quick reference — one line each

```bash
# source checkout
make test && make train && make eval
sudo ./tools/install_linux.sh eth0 && sudo systemctl start exfiltrap@eth0
make demo                                    # root-free demo + dashboard
bash tools/deploy_live.sh                    # full isolated live-fire test
bash tools/stress_test.sh                    # randomized stress suite
```

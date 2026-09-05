# ExFilTrap — Installation Guide

How to install, what to configure, and how to verify it works — for every
distribution format. **Read section 1 first**: two decisions are yours to
make on any platform.

---

## 1. What YOU must configure (the only two decisions)

| decision | default | where to change |
|---|---|---|
| **Which network interface to monitor** | Windows: read from `service.ini` (falls back to the first active adapter); Linux: the name you pass to `systemctl start exfiltrap@<iface>` | Windows: `%PROGRAMDATA%\ExFilTrap\service.ini` → `[service] iface = Ethernet` · Linux: the unit instance name |
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
   iface = Ethernet          ; adapter names: ncpa.cpl (or `ipconfig`)
   mitigation = log          ; log | netsh
   execute = no              ; yes = actually create firewall rules
   ```
4. Restart the service after editing:
   `exfiltrap.exe winservice stop` then `start` (elevated prompt).
5. Open the dashboard: Start Menu → **ExFilTrap** (or any browser →
   `http://127.0.0.1:5050`).

**Portable alternative (no install):** unzip the `exfiltrap/` onedir build
and run from an elevated prompt (Npcap required):
`exfiltrap.exe service --iface Ethernet`.

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
# NOTE: always run ExFilTrap through .venv/bin/python — the system
# python3 does not have the dependencies (joblib, sklearn, scapy...).
# To use the system python instead:
#   python3 -m pip install --break-system-packages -r requirements.txt
.venv/bin/python tools/train_classifier.py     # one-time: trains the RF model

sudo ./tools/install_linux.sh eth0             # ONE sudo prompt, then never again
sudo systemctl start exfiltrap@eth0            # start (also: enable = boot start)
```
The installer creates a locked-down `exfiltrap` user, installs a hardened
systemd unit granting **only** `CAP_NET_RAW`+`CAP_NET_ADMIN` (the service
is never root), trains the model if needed, and enables the unit.

Dashboard: any browser → `http://127.0.0.1:5050` (served by the service).

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
sudo make service IFACE=wlan0                # live service + dashboard
bash tools/deploy_live.sh                    # full isolated live-fire test
bash tools/stress_test.sh                    # randomized stress suite
```

---

## 9. Desktop app (AppImage/deb) troubleshooting

**Nothing happens when I open the AppImage** — work through this list in order:

1. Mark it executable: `chmod +x ExFilTrap-*.AppImage`
2. FUSE is required (Ubuntu 22.04+ no longer ships it):
   `sudo apt install libfuse2`
3. Still nothing? Extract-and-run bypasses FUSE entirely:
   ```bash
   ./ExFilTrap-*.AppImage --appimage-extract
   ./squashfs-root/AppRun
   ```
4. WebKitGTK runtime libraries (the app renders with the system webview):
   ```bash
   sudo apt install libwebkit2gtk-4.0-37 libgtk-3-0 libayatana-appindicator3-1
   ```
5. **Important — the window behavior:** the desktop app is the *monitor*
   for the detection service. On launch it shows a "ExfilTrap is starting…"
   screen and automatically switches to the dashboard the moment the
   service answers on `127.0.0.1:5050`. **If no service is running you get
   the waiting screen, not a dashboard.** Start a service first:
   ```bash
   sudo .venv/bin/python -m exfiltrap.service --fresh-db   # fresh data, iface auto-detected
   # or, for live capture (needs the installed service or sudo):
   sudo .venv/bin/python -m exfiltrap.service --iface YOUR_INTERFACE
   ```
   Find your interface name with `ip -br link` (e.g. `eth0`, `wlan0`, `enp3s0`).
6. The `.deb` installs the same desktop app system-wide (Start menu entry);
   the service itself is installed via `tools/install_linux.sh` (section 3c).

**Live capture "from source" fails with a privileges error** — that is by
design: packet capture needs elevated rights. Either run interactively with
`sudo` (as above), or use the one-time installer so daily use needs no
password (`systemctl start exfiltrap@<iface>`).

**Dashboard shows old test runs / the unblock button does nothing** —
upgrade to ≥ this version: `--fresh-db` starts with an empty database
(`--fresh-db`), the Blocked tab reads live data, and Unblock now
works in every mode (it clears the block row; with an active firewall
backend it also removes the actual rule). Old test databases can simply be
deleted: `rm data/exfiltrap.db*`.

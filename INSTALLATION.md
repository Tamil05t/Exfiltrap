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
once. The desktop app and any browser are always unprivileged readers — they
only talk to the local API on `127.0.0.1:5050` (the standalone
`exfiltrap dashboard` DB viewer uses `:5000`).

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
   `iface = auto` (what the installer writes) resolves to the default-route
   adapter at service start.
4. Restart the service after editing:
   `exfiltrap.exe winservice stop` then `start` (elevated prompt).
5. Open the dashboard: Start Menu → **ExFilTrap**, or `Win+R` → `exfiltrap`.
   This launches the **desktop shell** — a real application window, the
   Windows counterpart of the Linux AppImage — which attaches to the service
   on `127.0.0.1:5050` and switches to the dashboard as soon as the API
   answers. Any browser can also open `http://127.0.0.1:5050` directly.

**Portable alternative (no install):** unzip the `exfiltrap/` onedir build
and run from an elevated prompt (Npcap required):
`exfiltrap.exe service --iface Ethernet`.

**Verify:** `exfiltrap.exe privileges` → `can_capture: true`;
`curl http://127.0.0.1:5050/api/status` → `"mode": "live:..."`.

**Where the evidence lives:** `%PROGRAMDATA%\ExFilTrap\exfiltrap.db`. It must
sit outside `Program Files` — SQLite WAL journaling creates `-wal`/`-shm`
files beside the database, and `Program Files` is read-only for the
unprivileged console.

**Building the installer yourself:** `packaging\windows\build_windows.bat`
builds the engine, the Tauri desktop shell (needs
[Rust](https://rustup.rs); without it the shell is skipped and the Start Menu
entry falls back to opening the console in a browser) and then the Inno Setup
installer.

**Uninstall:** Settings → Apps → ExFilTrap (stops and removes the service
and `%PROGRAMDATA%\ExFilTrap`).

---

## 3. Linux — pick one

**Which package for which distro (read this first):**

| your distro | use | why |
|---|---|---|
| **Arch, CachyOS, EndeavourOS, Manjaro** | **PKGBUILD** (`packaging/arch/`) | shell compiles against the **system** `webkit2gtk-4.1` — nothing bundled to collide with rolling libraries |
| **any distro with Flatpak** (Fedora, Debian, Ubuntu, Mint…) | **Flatpak** (`org.exfiltrap.desktop`) | GNOME runtime pins the exact webkit/GLib versions; native window everywhere |
| **Kali, Debian 13+, Ubuntu 24.04+** | **`.deb`** (`sudo apt install ./ExFilTrap_*.deb`) | native format, desktop entry + engine included |
| single-file, compatible host | **AppImage** (`ExFilTrap-*.AppImage`) | one file, no install — rebuilt in v1.4.0 to ship the new console UI and auto-start the engine on launch |
| headless/server | `exfiltrap-linux-service.tar.gz` | engine only, no GUI |

> **AppImage status (v1.4.0):** the bundled-WebKit AppImage is **rebuilt and
> supported again**. Two defects made it appear "static": the engine was
> packaged at a path Tauri never resolves, and the shell waited on a splash
> instead of starting the engine. Both are fixed — the engine now ships at
> `$APPDIR/usr/lib/ex-fil-trap/resources/exfiltrap-engine` and the shell
> auto-starts it on launch. On rolling-release distros and GPU-less VMs the
> *preferred* formats remain the PKGBUILD and Flatpak (native/runtime-managed
> webviews, with no frozen GLib snapshot to collide with), because a bundled
> WebKitGTK can still hit symbol conflicts that no packaging fix can remove.
> Use the AppImage when you want a single file and your host's GL/WebKit is
> compatible; the `.deb`, Arch and Flatpak packages are unchanged.

### 3a. `.deb` package (Debian/Ubuntu)
```bash
sudo apt install ./ExFilTrap_1.4.0_amd64.deb           # desktop app
```
The service itself installs from source (3d) or via the install script; the
`.deb` carries the **desktop monitor**.

### 3b. Arch family — PKGBUILD (Arch, CachyOS, EndeavourOS, Manjaro)
```bash
git clone https://github.com/Tamil05t/Exfiltrap.git && cd Exfiltrap/packaging/arch
makepkg -f                       # compiles the shell + freezes the engine
pacman -U ex-fil-trap-git-*.pkg.tar.zst
```
What you get: `/usr/bin/ex-fil-trap` (wrapper) → `/usr/lib/exfiltrap/`
(shell binary + engine payload), desktop entry, and the same one-pkexec
Start flow as the deb — the engine is staged to `/var/lib/exfiltrap/engine`
on first Start. Because the shell links the system `webkit2gtk-4.1`,
rendering follows your rolling updates instead of fighting them.

### 3c. Flatpak (universal Linux)
```bash
# from the repo: build a single-file bundle (see packaging/flatpak/)
bash packaging/flatpak/build-flatpak.sh --bundle
flatpak install --user ExFilTrap_1.4.0_amd64.flatpak
flatpak run org.exfiltrap.desktop
```
The monitor renders inside the GNOME runtime's guaranteed webkit2gtk-4.1;
the Start button uses `flatpak-spawn --host pkexec` to launch the engine on
the host with root + capture rights (the sandbox hole is explicit in the
manifest: `--talk-name=org.freedesktop.Flatpak`).

### 3d. The detection service (from source — the normal route)
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
Open the dashboard: the status bar should show the mode and a **green
capture dot**; send any DNS traffic from the machine and watch the Overview
counters move. To exercise the detector deterministically, drive real
traffic with the bundled attacker client (there is **no demo mode** — the
project deliberately ships none):

```bash
.venv/bin/python tools/attacker_client.py --help   # fast + slow-drip modes
```

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
| a benign host got blocked | use the Response → Ledger unblock button (TTL also auto-unbans), then add it to `--allowlist` |
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

## 9. Desktop app troubleshooting (deb / AppImage / Arch / Flatpak)

**Blank window / EGL errors** — a bundled WebKitGTK snapshot can collide
with rolling-release system libraries, and WebKit's EGL path may not
initialize in a GPU-less VM. The AppImage bundles its own WebKit, so if it
renders blank, use the `.deb`, PKGBUILD or Flatpak instead — those always
render against a system- or runtime-managed WebKit. The shell also sets
`WEBKIT_DISABLE_DMABUF_RENDERER=1` / `WEBKIT_DISABLE_COMPOSITING_MODE=1`
automatically to mitigate this.

**Nothing happens when I open the desktop app** — work through this list:

1. **Window behavior:** the desktop app is the *monitor* for the detection
   service. On launch it shows a "starting…" screen and **auto-starts the
   bundled engine**, then switches to the dashboard the moment the service
   answers on `127.0.0.1:5050`. If auto-start is declined (pkexec prompt
   cancelled) you get the waiting screen, not a dashboard — press Start to
   retry, or start a service manually:
   ```bash
   sudo .venv/bin/python -m exfiltrap.service --fresh-db   # fresh data; captures ALL interfaces
   # or, for live capture (needs the installed service or sudo):
   sudo .venv/bin/python -m exfiltrap.service --iface YOUR_INTERFACE
   ```
   Find your interface name with `ip -br link` (e.g. `eth0`, `wlan0`, `enp3s0`).
2. Engine/start failures surface in the waiting screen with the engine log
   tail; the full log is `/tmp/exfiltrap-service.log`.
3. **Flatpak:** auto-start escapes the sandbox via
   `flatpak-spawn --host pkexec` — if it fails, check that the
   `--talk-name=org.freedesktop.Flatpak` permission is present
   (`flatpak info org.exfiltrap.desktop | grep shared`).
4. The `.deb` installs the same desktop app system-wide (Start menu entry);
   the service itself is installed via `tools/install_linux.sh` (section 3d).

**Live capture "from source" fails with a privileges error** — that is by
design: packet capture needs elevated rights. Either run interactively with
`sudo` (as above), or use the one-time installer so daily use needs no
password (`systemctl start exfiltrap@<iface>`).

**Dashboard shows old test runs / the unblock button does nothing** —
upgrade to ≥ this version: `--fresh-db` starts with an empty database, the
Response → Ledger reads live data, and Unblock posts the correct
`{src_ip}` payload (older builds sent `{target}`, which the API ignored, so
Unblock silently no-op'd). Old test databases can simply be deleted:
`rm data/exfiltrap.db*`.

---

## 10. Uninstall / full reset

```bash
sudo pkill -f exfiltrap                 # stop any running engine
sudo apt remove ex-fil-trap             # uninstall (Linux, .deb)
# full reset: also delete history, sessions and the engine copy
sudo rm -rf /var/lib/exfiltrap
```

Windows: Settings → Apps → ExFilTrap. The desktop Start button also stops
any previous engine automatically before starting a fresh one.

# ExFilTrap Desktop

Native-feeling desktop monitor for ExFilTrap, wrapping the detection
service's local web UI (`http://127.0.0.1:5050`) in an OS webview.

## Why Tauri (and not Electron / Qt)

| option | engine | typical RAM | binary size |
|---|---|---|---|
| **Tauri (chosen)** | OS webview (WebView2 / WebKitGTK) | ~20–50 MB | a few MB |
| Electron | bundled Chromium | 100–200+ MB | 100+ MB |
| Qt6 + QWebEngine | bundled Chromium | comparable to Electron | large |

Qt6+QScintilla isn't an option — QScintilla is a source-code editor widget,
not a dashboard framework. The dashboard is already a web UI, so the light
wrapper wins on every axis, and no dashboard code had to change.

The desktop app is **unprivileged by design**: it never elevates, never
captures packets, and never touches the firewall. All privileged work
belongs to the installed service (systemd unit with
`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` on Linux; the ExFilTrapSvc
Windows Service on Windows). The app just opens a window on the service's
localhost API — if the service is down it stays in the system tray and
keeps polling until it's back.

## Prerequisites

* Rust 1.70+ (`rustup`)
* Linux: `libwebkit2gtk-4.0-dev libgtk-3-dev libayatana-appindicator3-dev`
* Windows: Microsoft C++ Build Tools + WebView2 (preinstalled on Win 10/11)

## Develop

Terminal 1 — the detection service (as root, live capture):

    sudo ../.venv/bin/python -m exfiltrap.service --iface <your-interface>

Terminal 2 — the desktop shell:

    npm install
    npm run tauri dev

## Build installers

    npm run tauri build

Output in `src-tauri/target/release/bundle/`:

* Linux: `.deb`, `.rpm`, and **`.AppImage`** — the AppImage runs on every
  distro without installation, which answers cross-distro distribution.
* Windows: `.msi` and NSIS `.exe` setup. For the full Windows product
  (service registration + Npcap + signing) use
  `packaging/windows/build_windows.bat`, which builds the Python service
  and compiles `packaging/windows/exfiltrap.iss`.

Generate icons first (one-time): see `src-tauri/icons/README.md`.

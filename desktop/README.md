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

* Linux: `.deb` (and `.rpm` via `--bundles rpm`).
* Windows: NSIS `.exe` setup. `src-tauri/tauri.windows.conf.json` overrides
  the bundle target and icon for Windows (`tauri.conf.json` keeps `deb` +
  `icon.png` for Linux). For the full Windows product (service registration +
  Npcap + signing) use `packaging/windows/build_windows.bat`, which builds
  the Python service, runs `cargo build --release` for this shell, and
  compiles `packaging/windows/exfiltrap.iss`.

### Windows specifics

`packaging/windows/exfiltrap.iss` ships this shell as **`ExFilTrap.exe`** and
points the Start Menu entry, the optional desktop icon and the `App Paths`
registry keys at it, so ExFilTrap launches as an application window exactly
as it does on Linux (and `Win+R` → `exfiltrap` works, the same way `chrome`
does). Both shortcuts are `Check`-guarded on the shell being present, so a
build without Rust still produces a working installer that falls back to
opening the console in a browser.

Two things differ from Linux:

* The shell does **not** start the engine. On Windows the installed
  `ExFilTrapSvc` service (auto-start, SYSTEM) owns the engine, so
  `bundle.resources` is emptied in the Windows config and the launch-time
  auto-start path is skipped (`cfg!(not(target_os = "windows"))`).
* `tauri-build` still validates the resource path at compile time, so
  `build_windows.bat` stages `dist\exfiltrap` into `src-tauri\resources\`
  before `cargo build` even though the staged copy is not shipped.

Generate icons first (one-time): see `src-tauri/icons/README.md`.
`icon.ico` (16–256 px, 7 sizes) is committed alongside the PNGs.

## Linux distribution formats

| format | webview | targets |
|---|---|---|
| `.deb` | **system** WebKitGTK 4.1 | Debian 13+, Ubuntu 24.04+, Kali |
| **PKGBUILD** (`packaging/arch/`) | **system** WebKitGTK 4.1, compiled on install | Arch, CachyOS, EndeavourOS, Manjaro |
| **Flatpak** (`packaging/flatpak/`) | runtime-pinned WebKitGTK (`org.gnome.Platform//49`) | every distro with Flatpak |
| **AppImage** (`packaging/appimage/`) | **bundled** WebKitGTK snapshot | single-file, compatible hosts (see note) |

The AppImage bundles its own WebKitGTK/GLib snapshot, which can collide
with rolling-release system libraries (glib symbol errors, blank windows on
Kali/Debian 13), and WebKit's EGL path cannot initialize in GPU-less VMs
(upstream tauri#11994). It is therefore the *fallback* format: prefer the
`.deb`, PKGBUILD or Flatpak, which always render against a system- or
runtime-managed webview.

In v1.4.0 the AppImage build was fixed so it is no longer a dead splash:
the bundled engine now lands at the path Tauri actually resolves
(`$APPDIR/usr/lib/ex-fil-trap/resources/exfiltrap-engine`) and the shell
**auto-starts** it on launch (see `build-appimage.sh` and the auto-start
path in `src-tauri/src/main.rs`).

Flatpak privilege note: the sandbox cannot reach the host polkit, so
auto-start / the Start button escapes deliberately via
`flatpak-spawn --host pkexec` (see the `FLATPAK_ID` branch in
`src-tauri/src/main.rs` and the manifest's `--talk-name=org.freedesktop.Flatpak`);
the engine runs on the host with root + capture rights, exactly like the
deb's staged engine.

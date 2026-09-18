#!/bin/bash
# Build the ExFilTrap Flatpak (org.exfiltrap.desktop).
#
# Usage: build-flatpak.sh [--bundle]
#   --bundle  additionally export a single-file .flatpak for distribution
#
# Stages two payloads into this directory, then runs flatpak-builder:
#   engine-prebuilt/  PyInstaller engine onedir. Built on Ubuntu 22.04
#                     (glibc 2.35 floor) because the engine RUNS ON THE
#                     HOST via flatpak-spawn --host pkexec — an engine
#                     built on a newer distro would fail there with
#                     "GLIBC_x.xx not found".
#   app-prebuilt/     Tauri shell binary (links the runtime's
#                     webkit2gtk-4.1), wrapper, desktop entry, icon.
#
# Payload sources, in order of preference:
#   engine: $ENGINE_PREBUILT_DIR, else existing ./engine-prebuilt, else
#           built in an ubuntu:22.04 docker container (requires docker)
#   shell:  $SHELL_BIN (tauri binary), else from $DEB_FILE (dpkg-deb -x),
#           else existing ./app-prebuilt/ex-fil-trap, else built locally
#           with npm/tauri (requires rust+node)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
WANT_BUNDLE=0
[ "${1:-}" = "--bundle" ] && WANT_BUNDLE=1

mkdir -p "$HERE/app-prebuilt"

# ---- engine payload ------------------------------------------------------
# CANONICAL LAYOUT: engine-prebuilt/ IS the PyInstaller onedir — the
# engine binary sits at engine-prebuilt/exfiltrap (a FILE, not a dir).
# ENGINE_PREBUILT_DIR may point at the onedir itself or at a dir
# CONTAINING it (a raw tarball extraction); both are normalized here.
if [ -n "${ENGINE_PREBUILT_DIR:-}" ]; then
    rm -rf "$HERE/engine-prebuilt"
    SRC="$ENGINE_PREBUILT_DIR"
    if [ -d "$SRC/exfiltrap" ] && [ -f "$SRC/exfiltrap/exfiltrap" ]; then
        SRC="$SRC/exfiltrap"          # dir containing the onedir
    fi
    mkdir -p "$HERE/engine-prebuilt"
    cp -r "$SRC/." "$HERE/engine-prebuilt/"
elif [ ! -f "$HERE/engine-prebuilt/exfiltrap" ]; then
    echo "== Building the engine in ubuntu:22.04 (glibc 2.35 floor)…"
    rm -rf "$HERE/engine-prebuilt"
    docker run --rm -v "$REPO_ROOT":/src:ro -v "$HERE":/out ubuntu:22.04 bash -c '
        set -e
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv python3-pip > /dev/null
        cd /src
        python3 -m venv /venv
        /venv/bin/pip install -q -r requirements.txt pyinstaller
        /venv/bin/pyinstaller packaging/linux/exfiltrap-linux.spec \
            --noconfirm --distpath /engine --workpath /engine-build
        /engine/exfiltrap/exfiltrap privileges
        mkdir -p /out/engine-prebuilt && cp -r /engine/exfiltrap/. /out/engine-prebuilt/
    '
fi
[ -f "$HERE/engine-prebuilt/exfiltrap" ] || { echo "engine payload missing (no exfiltrap binary at engine-prebuilt/ root)" >&2; exit 1; }

# ---- shell binary --------------------------------------------------------
if [ -n "${SHELL_BIN:-}" ]; then
    cp "$SHELL_BIN" "$HERE/app-prebuilt/ex-fil-trap"
elif [ -n "${DEB_FILE:-}" ]; then
    TMP="$(mktemp -d)"
    dpkg-deb -x "$DEB_FILE" "$TMP"
    find "$TMP" -type f -name 'ex-fil-trap' | head -1 | xargs -I{} cp {} "$HERE/app-prebuilt/ex-fil-trap"
    rm -rf "$TMP"
elif [ ! -f "$HERE/app-prebuilt/ex-fil-trap" ]; then
    echo "== Building the Tauri shell locally (rust + node required)…"
    ( cd "$REPO_ROOT/desktop" && npm ci && npx tauri build --no-bundle )
    find "$REPO_ROOT/desktop/src-tauri/target/release" -maxdepth 1 -type f \
        \( -name 'ex-fil-trap' -o -name 'exfiltrap-desktop' \) | head -1 \
        | xargs -I{} cp {} "$HERE/app-prebuilt/ex-fil-trap"
fi
[ -f "$HERE/app-prebuilt/ex-fil-trap" ] || { echo "shell binary missing" >&2; exit 1; }
chmod 755 "$HERE/app-prebuilt/ex-fil-trap"

# ---- wrapper, desktop entry, icon ---------------------------------------
# The wrapper exports the engine location the shell resolves via
# EXFILTRAP_SERVICE_BIN; the FLATPAK_ID branch in main.rs rewrites it to
# the host-visible path and escapes the sandbox with flatpak-spawn.
cat > "$HERE/app-prebuilt/wrapper.sh" <<'EOF'
#!/bin/sh
export EXFILTRAP_SERVICE_BIN=/app/lib/exfiltrap-engine/exfiltrap
exec /app/lib/ex-fil-trap "$@"
EOF
chmod 755 "$HERE/app-prebuilt/wrapper.sh"

cat > "$HERE/app-prebuilt/org.exfiltrap.desktop.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=ExFilTrap
GenericName=DNS Exfiltration Detector
Comment=Detect and mitigate DNS tunneling & slow-drip data exfiltration
Exec=ex-fil-trap
Icon=org.exfiltrap.desktop
Terminal=false
Categories=Network;Security;Monitor;
StartupNotify=true
StartupWMClass=org.exfiltrap.desktop
X-Flatpak=org.exfiltrap.desktop
EOF

# Flatpak export rejects icons above 512x512 (the source icon is 1024) —
# downscale to 256x256, with tool fallbacks and a loud warning if none.
ICON_SRC="$REPO_ROOT/desktop/src-tauri/icons/icon.png"
if command -v magick >/dev/null 2>&1; then
    magick "$ICON_SRC" -resize 256x256 "$HERE/app-prebuilt/icon.png"
elif command -v convert >/dev/null 2>&1; then
    convert "$ICON_SRC" -resize 256x256 "$HERE/app-prebuilt/icon.png"
elif python3 -c "import PIL" 2>/dev/null; then
    python3 - "$ICON_SRC" "$HERE/app-prebuilt/icon.png" <<'PY'
import sys
from PIL import Image
Image.open(sys.argv[1]).resize((256, 256)).save(sys.argv[2])
PY
else
    cp "$ICON_SRC" "$HERE/app-prebuilt/icon.png"
    echo "WARNING: no ImageMagick/Pillow found — icon stays 1024px;" \
         "flatpak export will reject it" >&2
fi

# ---- build ----------------------------------------------------------------
cd "$HERE"
flatpak-builder --force-clean --repo repo --state-dir .flatpak-builder \
    build-dir org.exfiltrap.desktop.yml
echo "Flatpak built into repo/ — install with:"
echo "  flatpak-builder --user --install --force-clean org.exfiltrap.desktop.yml"
echo "  (from this directory) or run: flatpak run org.exfiltrap.desktop"

if [ "$WANT_BUNDLE" = 1 ]; then
    VERSION="$(python3 -c "import json;print(json.load(open('$REPO_ROOT/desktop/src-tauri/tauri.conf.json'))['version'])" 2>/dev/null || echo dev)"
    OUT="ExFilTrap_${VERSION}_amd64.flatpak"
    flatpak build-bundle repo "$OUT" org.exfiltrap.desktop
    echo "single-file bundle: $HERE/$OUT"
fi

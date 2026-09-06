#!/usr/bin/env bash
# One-command local build of the ExFilTrap desktop app (Linux).
# Installs the toolchain if missing (needs sudo for system packages);
# produces .deb and .AppImage under desktop/src-tauri/target/release/bundle.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

echo "== 1. system dependencies (sudo, skipped when already present)"
if ! pkg-config --exists webkit2gtk-4.0 2>/dev/null; then
    SUDO=""
    [[ ${EUID} -ne 0 ]] && SUDO="sudo"
    $SUDO apt-get update
    $SUDO apt-get install -y libwebkit2gtk-4.0-dev libgtk-3-dev \
        libayatana-appindicator3-dev librsvg2-dev nodejs npm
fi

echo "== 2. Rust toolchain (user-local, no sudo)"
if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"
fi

echo "== 3. icons"
"$REPO/.venv/bin/python" tools/make_icon.py desktop/src-tauri/icons/icon-source.png
cd desktop
npm install
npx tauri icon src-tauri/icons/icon-source.png

echo "== 4. build (deb + AppImage)"
export EXCLUDE_LIBRARIES="libwebkit2gtk-4.1.so.100 libjavascriptcoregtk-4.1.so.0 libsoup-3.0.so.0 libgtk-3.so.0 libgdk-3.so.0 libglib-2.0.so.0 libgobject-2.0.so.0 libgio-2.0.so.0 libgmodule-2.0.so.0 libgdk_pixbuf-2.0.so.0 libpango-1.0.so.0 libpangocairo-1.0.so.0 libpangoft2-1.0.so.0 libharfbuzz.so.0 libharfbuzz-subpage.so.0 libatk-1.0.so.0 libatk-bridge-2.0.so.0 libcairo.so.2 libcairo-gobject.so.2 libepoxy.so.0"
npm run tauri build

echo "Bundles:"
ls -1 src-tauri/target/release/bundle/deb/ \
      src-tauri/target/release/bundle/appimage/ 2>/dev/null || true

#!/usr/bin/env bash
# Build the ExFilTrap AppImage — the cross-distro single-file Linux build.
#
# Stack (matching what working Tauri projects ship):
#   * PyInstaller onedir engine  -> AppDir/usr/bin/exfiltrap-engine/
#   * cargo release Tauri shell  -> AppDir/usr/bin/ex-fil-trap
#   * linuxdeploy (APPIMAGE_EXTRACT_AND_RUN=1 — no FUSE needed to BUILD)
#       walks the ELF dependency tree of the shell and bundles
#       GTK3 + WebKitGTK 4.1 + everything else, so the image carries its
#       own rendering stack instead of trusting the host distro.
#   * custom AppRun exporting the WebKit GPU-workaround env vars that fix
#     GPU-less VMs (tauri#11994: DMABUF renderer crash) — the same env the
#     Rust shell already sets at startup, applied before it runs too.
#
# Users on distros without libfuse2 (Kali removed it) run the image with
#   ./ExFilTrap.AppImage --appimage-extract-and-run
# which needs no FUSE at all. The waiting screen / README document this.
#
# Usage: packaging/appimage/build-appimage.sh [output-dir]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/dist-appimage}"
APPDIR="$OUT_DIR/AppDir"
PY="$ROOT/.venv/bin/python"

echo "== 1/5 engine (PyInstaller onedir) =="
cd "$ROOT"
"$PY" -m PyInstaller --noconfirm --clean packaging/linux/exfiltrap-linux.spec
ENGINE_DIR="$ROOT/dist/exfiltrap"
test -x "$ENGINE_DIR/exfiltrap"

echo "== 2/5 desktop shell (cargo release) =="
# Root-free builds: a local extracted -dev prefix (see gtk-dev/env.sh)
# supplies the headers/pkg-config files when system -dev packages are not
# installed. On CI runners the system packages win and this is a no-op.
if [ -f "$HOME/gtk-dev/env.sh" ]; then . "$HOME/gtk-dev/env.sh"; fi
cd "$ROOT/desktop/src-tauri"
cargo build --release
# cargo names the binary after the crate; the tauri bundler would rename
# it to mainBinaryName — we bundle ourselves, so we rename here.
SHELL_BIN="target/release/exfiltrap-desktop"
test -x "$SHELL_BIN"

echo "== 3/5 assembling AppDir =="
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp "$ROOT/desktop/src-tauri/target/release/exfiltrap-desktop" \
   "$APPDIR/usr/bin/ex-fil-trap"
cp -r "$ENGINE_DIR" "$APPDIR/usr/bin/exfiltrap-engine"
chmod +x "$APPDIR/usr/bin/exfiltrap-engine/exfiltrap"
cp "$ROOT/packaging/arch/ex-fil-trap.desktop" \
   "$APPDIR/usr/share/applications/ex-fil-trap.desktop"
cp "$APPDIR/usr/share/applications/ex-fil-trap.desktop" "$APPDIR/"
cp "$ROOT/desktop/src-tauri/icons/icon-256.png" \
   "$APPDIR/usr/share/icons/hicolor/256x256/apps/ex-fil-trap.png"
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/ex-fil-trap.png" \
   "$APPDIR/ex-fil-trap.png"

echo "== 4/5 AppRun (GPU-workaround env + engine path) =="
cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/sh
# ExFilTrap AppRun: linuxdeploy's default layout plus the WebKit flags
# that make the shell render on GPU-less machines (VMs, servers).
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export EXFILTRAP_SERVICE_BIN="$HERE/usr/bin/exfiltrap-engine/exfiltrap"
export LD_LIBRARY_PATH="$HERE/usr/lib:${LD_LIBRARY_PATH:-}"
exec "$HERE/usr/bin/ex-fil-trap" "$@"
APPRUN
chmod +x "$APPDIR/AppRun"

echo "== 5/5 linuxdeploy (bundles the ELF tree, produces the image) =="
TOOLS_DIR="$OUT_DIR/tools"
mkdir -p "$TOOLS_DIR"
LINUXDEPLOY="$TOOLS_DIR/linuxdeploy-x86_64.AppImage"
if [ ! -x "$LINUXDEPLOY" ]; then
  echo "downloading linuxdeploy..."
  curl -fsSL -o "$LINUXDEPLOY" \
    "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
  chmod +x "$LINUXDEPLOY"
fi
export APPIMAGE_EXTRACT_AND_RUN=1   # no FUSE required to run the tooling
export NO_STRIP=1                   # stripping PyInstaller/GTK libs breaks them
export VERSION="${APPIMAGE_VERSION:-2.0.0}"
cd "$OUT_DIR"
"$LINUXDEPLOY" --appdir "$APPDIR" \
  --output appimage
mv "$OUT_DIR"/ExFilTrap-"$VERSION"-x86_64.AppImage \
   "$OUT_DIR/ExFilTrap-$VERSION-x86_64.AppImage" 2>/dev/null || true
echo "done: $(ls "$OUT_DIR"/*.AppImage 2>/dev/null || echo 'check output')"

#!/usr/bin/env bash
# Build the ExFilTrap AppImage — the cross-distro single-file Linux build.
#
# Stack (mirrors what the Tauri bundler itself does — verified against
# tauri-apps/tauri crates/tauri-bundler/src/bundle/linux/appimage/):
#   * PyInstaller onedir engine  -> AppDir/usr/bin/exfiltrap-engine/
#   * cargo release Tauri shell  -> AppDir/usr/bin/ex-fil-trap
#   * webkit HELPER PROCESSES copied explicitly (WebKitNetworkProcess,
#     WebKitWebProcess, injected-bundle/) — linuxdeploy only walks linked
#     ELF deps and would never pick them up; without them the GUI dies at
#     first paint ("Unable to spawn WebKitNetworkProcess").
#   * linuxdeploy + linuxdeploy-plugin-gtk with APPIMAGE_EXTRACT_AND_RUN=1
#     (no FUSE needed to BUILD). plugin-gtk wires GIO modules, typelibs
#     and fontconfig (fixes the "without calling FcInit()" warning).
#   * AFTER bundling: binary-patch every libwebkit*.so with s|/usr|././|g
#     (the exact transform from Tauri's vendored plugin) so the compiled-in
#     absolute helper paths resolve inside the mounted AppDir.
#
# Users on distros without libfuse2 (Kali removed it) run:
#   ./ExFilTrap.AppImage --appimage-extract-and-run
#
# Usage: packaging/appimage/build-appimage.sh [output-dir]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/dist-appimage}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"   # CI passes relative args; cd breaks them
APPDIR="$OUT_DIR/AppDir"
TOOLS_DIR="$OUT_DIR/tools"
MULTIARCH="$(gcc -print-multiarch 2>/dev/null || echo x86_64-linux-gnu)"

# repo venv when present (local builds); CI installs into system python
if [ -n "${EXFILTRAP_PY:-}" ]; then PY="$EXFILTRAP_PY"
elif [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"
else PY="$(command -v python3)"; fi

echo "== 1/5 engine (PyInstaller onedir) =="
cd "$ROOT"
"$PY" -m PyInstaller --noconfirm --clean packaging/linux/exfiltrap-linux.spec
ENGINE_DIR="$ROOT/dist/exfiltrap"
test -x "$ENGINE_DIR/exfiltrap"

echo "== 2/5 desktop shell (cargo release) =="
# tauri-build VALIDATES the resources paths in tauri.conf.json at compile
# time — the engine must be staged into resources/ before cargo runs
# (the same thing every other packaging job does).
mkdir -p "$ROOT/desktop/src-tauri/resources"
rm -rf "$ROOT/desktop/src-tauri/resources/exfiltrap-engine"
cp -r "$ENGINE_DIR" "$ROOT/desktop/src-tauri/resources/exfiltrap-engine"
# Root-free builds: a local extracted -dev prefix (see gtk-dev/env.sh)
# supplies the headers/pkg-config files when system -dev packages are not
# installed. On CI runners the system packages win and this is a no-op.
if [ -f "$HOME/gtk-dev/env.sh" ]; then . "$HOME/gtk-dev/env.sh"; fi
cd "$ROOT/desktop/src-tauri"
cargo build --release
# cargo names the binary after the crate; the tauri bundler would rename
# it to mainBinaryName — we bundle ourselves, so we rename here.
test -x "target/release/exfiltrap-desktop"

echo "== 3/5 assembling AppDir (shell + engine + webkit helpers) =="
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps" \
         "$APPDIR/usr/lib/$MULTIARCH"
cp target/release/exfiltrap-desktop "$APPDIR/usr/bin/ex-fil-trap"
cp -r "$ENGINE_DIR" "$APPDIR/usr/bin/exfiltrap-engine"
chmod +x "$APPDIR/usr/bin/exfiltrap-engine/exfiltrap"
# webkit helpers: same set Tauri's bundler copies (see linuxdeploy.rs)
WEBKIT_HELPER_DIR="/usr/lib/$MULTIARCH/webkit2gtk-4.1"
mkdir -p "$APPDIR/usr/lib/$MULTIARCH/webkit2gtk-4.1/injected-bundle"
for helper in WebKitNetworkProcess WebKitWebProcess; do
  cp "$WEBKIT_HELPER_DIR/$helper" \
     "$APPDIR/usr/lib/$MULTIARCH/webkit2gtk-4.1/$helper"
done
cp "$WEBKIT_HELPER_DIR/injected-bundle/libwebkit2gtkinjectedbundle.so" \
   "$APPDIR/usr/lib/$MULTIARCH/webkit2gtk-4.1/injected-bundle/"
# Tray-icon stack: tauri dlopen()s libayatana-appindicator3 at RUNTIME
# (invisible to linuxdeploy's linked-deps walk). Without bundling it, a
# host that HAS appindicator loads its copy against the bundle's older
# glib -> "undefined symbol: g_once_init_leave_pointer" crash. Bundle the
# whole chain from the build machine so it always matches the bundled
# glib. Missing libs on exotic runners are non-fatal (tray only).
for lib in libayatana-appindicator3.so.1 libayatana-ido3-0.4.so.0 \
           libayatana-indicator3.so.7 libdbusmenu-glib.so.4 \
           libdbusmenu-gtk3.so.4; do
  src="/usr/lib/$MULTIARCH/$lib"
  [ -e "$src" ] && cp -L "$src" "$APPDIR/usr/lib/$MULTIARCH/" || true
done
# desktop + icon
cp "$ROOT/packaging/arch/ex-fil-trap.desktop" \
   "$APPDIR/usr/share/applications/ex-fil-trap.desktop"
cp "$APPDIR/usr/share/applications/ex-fil-trap.desktop" "$APPDIR/"
cp "$ROOT/desktop/src-tauri/icons/icon-256.png" \
   "$APPDIR/usr/share/icons/hicolor/256x256/apps/ex-fil-trap.png"
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/ex-fil-trap.png" \
   "$APPDIR/ex-fil-trap.png"
# AppRun hook: linuxdeploy's generated AppRun cd's into the AppDir (required
# by the patched relative webkit paths) and sources every hook in here.
mkdir -p "$APPDIR/apprun-hooks"
cat > "$APPDIR/apprun-hooks/exfiltrap.sh" <<'HOOK'
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export EXFILTRAP_SERVICE_BIN="${APPDIR}/usr/bin/exfiltrap-engine/exfiltrap"
HOOK

echo "== 4/5 tooling (linuxdeploy + vendored plugin-gtk) =="
mkdir -p "$TOOLS_DIR"
LINUXDEPLOY="$TOOLS_DIR/linuxdeploy-x86_64.AppImage"
APPIMAGETOOL="$TOOLS_DIR/appimagetool-x86_64.AppImage"
if [ ! -x "$LINUXDEPLOY" ]; then
  echo "downloading linuxdeploy..."
  curl -fsSL -o "$LINUXDEPLOY" \
    "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
  chmod +x "$LINUXDEPLOY"
fi
if [ ! -x "$APPIMAGETOOL" ]; then
  echo "downloading appimagetool..."
  curl -fsSL -o "$APPIMAGETOOL" \
    "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
  chmod +x "$APPIMAGETOOL"
fi
# plugin-gtk is vendored from the Tauri bundler (upstream ships no release
# asset; Tauri embeds this exact script in their binary) — linuxdeploy
# discovers plugins named linuxdeploy-plugin-* on PATH.
PLUGIN_GTK="$ROOT/packaging/appimage/linuxdeploy-plugin-gtk.sh"
test -x "$PLUGIN_GTK"
export PATH="$TOOLS_DIR:$ROOT/packaging/appimage:$PATH"
export APPIMAGE_EXTRACT_AND_RUN=1   # no FUSE required to run the tooling
export NO_STRIP=1                   # stripping PyInstaller/GTK libs breaks them
export VERSION="${APPIMAGE_VERSION:-2.0.0}"

echo "== 5/5 bundle + patch webkit paths + final AppRun =="
# The plugin queries pkg-config for REAL runtime dirs (gio modules,
# immodules, pixbuf loaders). The sysroot rewrite that helped compilation
# would point those into the extracted -dev prefix — unset it so the
# plugin sees the host system like it does on CI.
unset PKG_CONFIG_SYSROOT_DIR
cd "$OUT_DIR"
"$LINUXDEPLOY" --appdir "$APPDIR" --plugin gtk
# The Tauri-bundler transform: absolute /usr paths inside the bundled
# libwebkit (helper processes, data dirs) become AppDir-relative.
find "$APPDIR"/usr/lib* -name 'libwebkit*' \
  -exec sed -i -e "s|/usr|././|g" '{}' \;
# The relative helper path "././lib/..." resolves from the AppDir root:
# expose usr/lib there and make the AppRun cd + export everything the
# shell and the plugin hook need (linuxdeploy regenerates AppRun on every
# run, so ours is installed AFTER the last bundling pass).
ln -sfn usr/lib "$APPDIR/lib"
cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/bash
APPDIR="$(readlink -f "$(dirname "$0")")"
cd "$APPDIR"
export APPDIR
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export EXFILTRAP_SERVICE_BIN="$APPDIR/usr/bin/exfiltrap-engine/exfiltrap"
export LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
if [ -f "$APPDIR/apprun-hooks/linuxdeploy-plugin-gtk.sh" ]; then
  . "$APPDIR/apprun-hooks/linuxdeploy-plugin-gtk.sh"
fi
exec "$APPDIR/usr/bin/ex-fil-trap" "$@"
APPRUN
chmod +x "$APPDIR/AppRun"
# Package with appimagetool directly — it never rewrites AppRun.
APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGETOOL" "$APPDIR" \
  "$OUT_DIR/ExFilTrap-${VERSION}-x86_64.AppImage"
ls -la "$OUT_DIR"/ExFilTrap-*.AppImage

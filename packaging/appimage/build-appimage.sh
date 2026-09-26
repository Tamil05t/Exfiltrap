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
# Multiarch triple. Some toolchains report a triple (e.g. Debian/Ubuntu's
# "x86_64-linux-gnu") and nest libraries under /usr/lib/<triple>; others
# print nothing and keep them directly in /usr/lib. Detect a lib dir that
# actually exists rather than assuming either layout — an empty triple is a
# valid answer meaning "libraries live directly in /usr/lib".
_multiarch_probe="$(gcc -print-multiarch 2>/dev/null || true)"
if [ -n "$_multiarch_probe" ] && [ -d "/usr/lib/$_multiarch_probe" ]; then
  MULTIARCH="$_multiarch_probe"
elif [ -d "/usr/lib/x86_64-linux-gnu" ]; then
  MULTIARCH="x86_64-linux-gnu"
else
  MULTIARCH=""
fi
# Helper dir to build lib paths that may or may not carry the triple.
libdir() { if [ -n "$MULTIARCH" ]; then echo "/usr/lib/$MULTIARCH"; else echo "/usr/lib"; fi; }
# webkit2gtk-4.1 lives under the triple when one exists, otherwise directly
# in /usr/lib; resolve it once so every later copy uses the real path.
WEBKIT_HELPER_DIR=""
for _cand in "$(libdir)/webkit2gtk-4.1" "/usr/lib/webkit2gtk-4.1"; do
  if [ -d "$_cand" ]; then WEBKIT_HELPER_DIR="$_cand"; break; fi
done

# Python selection. A repo .venv is only usable if its interpreter actually
# RUNS on this machine AND can import everything PyInstaller must trace — a
# venv copied from another box (its pyvenv.cfg records a different home/user,
# or its base interpreter is gone) looks fine on disk but dies on exec.
# Validate, then fall back to the system interpreter.
#
# PyInstaller imports each of these to build the dependency graph; if one is
# missing it fails deep inside the analysis phase with a confusing traceback,
# so we check up front. Override with EXFILTRAP_BUILD_MODULES.
BUILD_MODULES="${EXFILTRAP_BUILD_MODULES:-PyInstaller sklearn scipy joblib flask scapy pandas numpy}"
_py_ok() {
  [ -x "$1" ] || return 1
  "$1" -c "
import importlib.util, sys
missing = [m for m in '$BUILD_MODULES'.split() if importlib.util.find_spec(m) is None]
sys.exit(1 if missing else 0)
" >/dev/null 2>&1
}
_py_missing() {
  [ -x "$1" ] || { echo "(not executable)"; return; }
  "$1" -c "
import importlib.util
print(' '.join(m for m in '$BUILD_MODULES'.split() if importlib.util.find_spec(m) is None) or '(none)')
" 2>/dev/null || echo "(interpreter failed)"
}
if [ -n "${EXFILTRAP_PY:-}" ]; then
  PY="$EXFILTRAP_PY"
  _py_ok "$PY" || {
    echo "ERROR: EXFILTRAP_PY=$PY cannot build this project." >&2
    echo "       missing modules: $(_py_missing "$PY")" >&2
    exit 1
  }
elif _py_ok "$ROOT/.venv/bin/python"; then
  PY="$ROOT/.venv/bin/python"
elif _py_ok "$(command -v python3)"; then
  PY="$(command -v python3)"
else
  SYS_PY="$(command -v python3 || echo /usr/bin/python3)"
  echo "ERROR: no Python interpreter can build this project." >&2
  echo "       required modules: $BUILD_MODULES" >&2
  if [ -x "$SYS_PY" ]; then
    echo "       system $SYS_PY is missing: $(_py_missing "$SYS_PY")" >&2
  fi
  if [ -e "$ROOT/.venv/bin/python" ]; then
    echo "       repo .venv is missing:     $(_py_missing "$ROOT/.venv/bin/python")" >&2
  fi
  echo "       Install them for that interpreter, e.g.:" >&2
  echo "         python3 -m pip install pyinstaller scikit-learn scipy joblib flask scapy pandas" >&2
  echo "       (or your distro's packaged equivalents), then re-run." >&2
  exit 1
fi
echo "   python: $PY"

echo "== 1/5 engine (PyInstaller onedir) =="
cd "$ROOT"
"$PY" -m PyInstaller --noconfirm --clean packaging/linux/exfiltrap-linux.spec
ENGINE_DIR="$ROOT/dist/exfiltrap"
test -x "$ENGINE_DIR/exfiltrap"

echo "== 2/5 desktop shell (cargo release) =="
command -v cargo >/dev/null 2>&1 || {
  echo "ERROR: cargo not found. Install Rust: https://rustup.rs" >&2; exit 1; }
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
         "$APPDIR/usr/lib"
cp target/release/exfiltrap-desktop "$APPDIR/usr/bin/ex-fil-trap"
cp -r "$ENGINE_DIR" "$APPDIR/usr/bin/exfiltrap-engine"
chmod +x "$APPDIR/usr/bin/exfiltrap-engine/exfiltrap"
# Tauri resolves `BaseDirectory::Resource` in an AppImage to
#   ${APPDIR}/usr/lib/<exe_name>
# where <exe_name> is mainBinaryName ("ex-fil-trap"). bundle.resources is
# ["resources/exfiltrap-engine"], and Tauri preserves the source path
# structure, so the bundled engine MUST land at
#   $APPDIR/usr/lib/ex-fil-trap/resources/exfiltrap-engine/
# Without this the shell's service_binary() lookup finds nothing, the
# waiting screen never gets an engine to start, and the AppImage just sits
# on the splash ("static" — the bug this fix addresses). We keep the
# usr/bin copy too because AppRun exports EXFILTRAP_SERVICE_BIN to it,
# which service_binary() checks first (most robust of the two).
RES_DIR="$APPDIR/usr/lib/ex-fil-trap/resources"
mkdir -p "$RES_DIR"
cp -r "$ENGINE_DIR" "$RES_DIR/exfiltrap-engine"
# Only the launcher (and any .so) needs the execute bit; the deb/AppImage
# resource copy must be executable or pkexec's root-side cp+launch fails.
chmod +x "$RES_DIR/exfiltrap-engine/exfiltrap"
find "$RES_DIR/exfiltrap-engine" -name '*.so*' -exec chmod +x {} + 2>/dev/null || true
# webkit helpers: same set Tauri's bundler copies (see linuxdeploy.rs).
# WEBKIT_HELPER_DIR was resolved above (with or without a multiarch triple).
# The DESTINATION mirrors the source layout: the helper path compiled into
# libwebkit2gtk is `/usr/lib/webkit2gtk-4.1/...` where libraries sit directly
# in /usr/lib, and `/usr/lib/<triple>/webkit2gtk-4.1/...` where a triple is
# used. The later `s|/usr|././|g` patch rewrites that string verbatim, so the
# copy must land exactly where the patched string expects it — hence deriving
# the destination from WEBKIT_HELPER_DIR.
test -n "$WEBKIT_HELPER_DIR" || {
  echo "ERROR: webkit2gtk-4.1 helper dir not found; install webkit2gtk-4.1" >&2
  exit 1
}
echo "   webkit helpers from: $WEBKIT_HELPER_DIR"
WEBKIT_REL="${WEBKIT_HELPER_DIR#/usr/lib/}"          # webkit2gtk-4.1 | <triple>/webkit2gtk-4.1
WEBKIT_DEST="$APPDIR/usr/lib/$WEBKIT_REL"
mkdir -p "$WEBKIT_DEST/injected-bundle"
for helper in WebKitNetworkProcess WebKitWebProcess; do
  cp "$WEBKIT_HELPER_DIR/$helper" "$WEBKIT_DEST/$helper"
done
cp "$WEBKIT_HELPER_DIR/injected-bundle/libwebkit2gtkinjectedbundle.so" \
   "$WEBKIT_DEST/injected-bundle/"
# Tray-icon stack: tauri dlopen()s libayatana-appindicator3 at RUNTIME
# (invisible to linuxdeploy's linked-deps walk). Without bundling it, a
# host that HAS appindicator loads its copy against the bundle's older
# glib -> "undefined symbol: g_once_init_leave_pointer" crash. Bundle the
# whole chain from the build machine so it always matches the bundled
# glib. Missing libs on exotic runners are non-fatal (tray only).
for lib in libayatana-appindicator3.so.1 libayatana-ido3-0.4.so.0 \
           libayatana-indicator3.so.7 libdbusmenu-glib.so.4 \
           libdbusmenu-gtk3.so.4; do
  # try the multiarch dir first, then plain /usr/lib
  src=""
  for _d in "$(libdir)" "/usr/lib"; do
    if [ -e "$_d/$lib" ]; then src="$_d/$lib"; break; fi
  done
  [ -n "$src" ] && cp -L "$src" "$APPDIR/usr/lib/" || true
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
# Reuse a copy already sitting in the default output dir: the tools are
# ~35 MB together and users routinely rebuild into a custom output dir.
_fetch_tool() {
  # $1 = dest path, $2 = filename, $3 = url
  [ -x "$1" ] && return 0
  local cached="$ROOT/dist-appimage/tools/$2"
  if [ -x "$cached" ] && [ "$cached" != "$1" ]; then
    echo "   reusing cached $2"
    cp -f "$cached" "$1"
    chmod +x "$1"
    return 0
  fi
  echo "   downloading $2 ..."
  curl -fsSL -o "$1" "$3"
  chmod +x "$1"
}
_fetch_tool "$LINUXDEPLOY" "linuxdeploy-x86_64.AppImage" \
  "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
_fetch_tool "$APPIMAGETOOL" "appimagetool-x86_64.AppImage" \
  "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
# plugin-gtk is vendored from the Tauri bundler (upstream ships no release
# asset; Tauri embeds this exact script in their binary) — linuxdeploy
# discovers plugins named linuxdeploy-plugin-* on PATH.
PLUGIN_GTK="$ROOT/packaging/appimage/linuxdeploy-plugin-gtk.sh"
test -x "$PLUGIN_GTK"
export PATH="$TOOLS_DIR:$ROOT/packaging/appimage:$PATH"
export APPIMAGE_EXTRACT_AND_RUN=1   # no FUSE required to run the tooling
export NO_STRIP=1                   # stripping PyInstaller/GTK libs breaks them
export VERSION="${APPIMAGE_VERSION:-1.4.0}"

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
# The hook above is the stock linuxdeploy-plugin-gtk script.  Its last line
# forces GTK_THEME="Adwaita:<variant>" (overridable via APPIMAGE_GTK_THEME) on
# the theory that custom themes are broken.  Adwaita is NOT installed
# everywhere: on CachyOS/Arch with a KDE session /usr/share/themes/Adwaita does
# not exist, only Breeze does.  When GTK is told to load a theme that is not
# there it cannot resolve that theme's client-side-decoration assets, and the
# window-control buttons come out as garbled blobs.
#
# Measured A/B on this exact build, same machine, same session:
#   GTK_THEME=Adwaita:dark  -> garbled minimise/maximise/close glyphs
#   GTK_THEME=Breeze        -> clean
# Dropping the forced name is therefore the fix: GTK falls back to the theme
# the desktop is actually configured with (gtk-theme-name from XSettings, i.e.
# Breeze here), exactly like every other application on the machine.
#
# Only GTK_THEME is touched.  GTK_DATA_PREFIX, XDG_DATA_DIRS,
# GDK_PIXBUF_MODULE_FILE, GIO_MODULE_DIR, GTK_PATH, GI_TYPELIB_PATH and
# GSETTINGS_SCHEMA_DIR are left as the plugin set them -- the bundle does need
# its own typelibs, GIO modules and GTK modules, and the Breeze A/B above was
# run with all of those still pointed at the AppDir.
unset GTK_THEME
exec "$APPDIR/usr/bin/ex-fil-trap" "$@"
APPRUN
chmod +x "$APPDIR/AppRun"
# Package with appimagetool directly — it never rewrites AppRun.
APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGETOOL" "$APPDIR" \
  "$OUT_DIR/ExFilTrap-${VERSION}-x86_64.AppImage"
ls -la "$OUT_DIR"/ExFilTrap-*.AppImage

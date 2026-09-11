#!/bin/bash
# Build the ExFilTrap browser-dashboard AppImage (no WebKit/EGL/GTK).
#
# Usage: build_appimage.sh <pyinstaller-engine-dir> <icon.png> <version> <out-dir>
#
# The engine is the PyInstaller --onedir output (dist/exfiltrap); it is
# self-contained, so no linuxdeploy dependency bundling is needed — only
# appimagetool to squash the AppDir. Works without FUSE on CI (extract
# trick) and locally.
set -euo pipefail

ENGINE_DIR=$1
ICON=$2
VERSION=$3
OUT_DIR=$4
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[ -x "$ENGINE_DIR/exfiltrap" ] || { echo "engine binary missing in $ENGINE_DIR"; exit 1; }
[ -f "$ICON" ] || { echo "icon missing: $ICON"; exit 1; }

# ---- assemble the AppDir -------------------------------------------------
mkdir -p "$WORK/AppDir/usr/lib" \
         "$WORK/AppDir/usr/share/applications" \
         "$WORK/AppDir/usr/share/icons/hicolor/256x256/apps"

cp -r "$ENGINE_DIR" "$WORK/AppDir/usr/lib/exfiltrap-engine"
chmod +x "$WORK/AppDir/usr/lib/exfiltrap-engine/exfiltrap"
cp "$HERE/AppRun" "$WORK/AppDir/AppRun"
chmod +x "$WORK/AppDir/AppRun"
cp "$HERE/ex-fil-trap.desktop" "$WORK/AppDir/ex-fil-trap.desktop"
cp "$HERE/ex-fil-trap.desktop" \
   "$WORK/AppDir/usr/share/applications/ex-fil-trap.desktop"
cp "$ICON" "$WORK/AppDir/ex-fil-trap.png"
cp "$ICON" "$WORK/AppDir/usr/share/icons/hicolor/256x256/apps/ex-fil-trap.png"
sed -i "s/^X-AppImage-Version=.*/X-AppImage-Version=$VERSION/" \
    "$WORK/AppDir/ex-fil-trap.desktop" \
    "$WORK/AppDir/usr/share/applications/ex-fil-trap.desktop"

# ---- sanity: no GUI-stack libs in the payload ---------------------------
if ls "$WORK/AppDir/usr/lib/exfiltrap-engine/_internal" 2>/dev/null | \
       grep -qiE "webkit|gtk"; then
    echo "ERROR: GUI libraries leaked into the engine payload" >&2
    exit 1
fi

# ---- squash it -----------------------------------------------------------
OUT="$OUT_DIR/ExFilTrap_${VERSION}_amd64.AppImage"
mkdir -p "$OUT_DIR"
TOOL="$WORK/appimagetool.AppImage"
wget -q https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage -O "$TOOL"
chmod +x "$TOOL"
( cd "$WORK" && "$TOOL" --appimage-extract > /dev/null )   # FUSE-free
ARCH=x86_64 "$WORK/squashfs-root/AppRun" "$WORK/AppDir" "$OUT"
echo "built: $OUT"

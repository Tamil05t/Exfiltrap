#!/usr/bin/env python3
"""Generate the ExFilTrap application icon as a PNG (no dependencies).

Draws a stylized shield/radar "E" on a dark blue gradient, 1024x1024 RGBA —
the source image `tauri icon` turns into every platform icon (ico/icns/png).
Run from anywhere: python3 tools/make_icon.py [output.png]
"""

from __future__ import annotations

import struct
import sys
import zlib

SIZE = 1024


def _chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def write_png(path: str, pixels: list[list[list[int]]]) -> None:
    raw = b"".join(b"\x00" + b"".join(bytes(px) for px in row)
                   for row in pixels)
    png = (b"\x89PNG\r\n\x1a\n"
           + _chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
           + _chunk(b"IDAT", zlib.compress(raw, 9))
           + _chunk(b"IEND", b""))
    with open(path, "wb") as fh:
        fh.write(png)


def lerp(a: float, b: float, t: float) -> int:
    return int(a + (b - a) * t)


def main(argv: list[str]) -> int:
    out = argv[1] if len(argv) > 1 else "icon.png"
    cx, cy = SIZE / 2, SIZE / 2
    # Letter "E" strokes (in unit coords 0..1 of the glyph box)
    strokes = [
        (0.18, 0.10, 0.82, 0.10),  # top bar
        (0.18, 0.47, 0.68, 0.47),  # middle bar
        (0.18, 0.84, 0.82, 0.84),  # bottom bar
        (0.18, 0.10, 0.18, 0.84),  # spine
    ]
    # Radar sweep arcs (three concentric, upper-right quadrant feel)
    pixels = []
    for y in range(SIZE):
        row = []
        for x in range(SIZE):
            dx, dy = x - cx, y - cy
            r = (dx * dx + dy * dy) ** 0.5
            # vertical gradient: deep navy -> steel blue
            base_r = lerp(13, 31, y / SIZE)
            base_g = lerp(27, 58, y / SIZE)
            base_b = lerp(62, 122, y / SIZE)
            color = [base_r, base_g, base_b, 255]
            # radar rings
            for ring in (0.32, 0.42):
                if abs(r / SIZE - ring) < 0.006:
                    color = [88, 166, 255, 255]
            # sweep wedge (upper right)
            import math

            ang = math.degrees(math.atan2(-(dy), dx)) % 360
            if 0 <= ang <= 60 and 0.10 < r / SIZE < 0.44:
                t = 1 - (ang / 60)
                color = [lerp(88, 248, t), lerp(166, 81, t),
                         lerp(255, 41, t), 255]
            # letter E inside a central box
            gx, gy = x / SIZE, y / SIZE
            if 0.30 <= gx <= 0.74 and 0.24 <= gy <= 0.76:
                u, v = (gx - 0.30) / 0.44, (gy - 0.24) / 0.52
                for (x0, y0, x1, y1) in strokes:
                    if (min(x0, x1) - 0.06 <= u <= max(x0, x1) + 0.06
                            and min(y0, y1) - 0.055 <= v <= max(y0, y1) + 0.055
                            and (x0 - 0.06 <= u <= x0 + 0.06
                                 or y0 - 0.055 <= v <= y0 + 0.055)):
                        color = [235, 245, 255, 255]
            row.append(color)
        pixels.append(row)
    write_png(out, pixels)
    print(f"wrote {out} ({SIZE}x{SIZE} RGBA)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

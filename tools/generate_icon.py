"""Render the code-native LiWeTun mark to ICO without third-party packages.

Geometry mirrors assets/brand/liwetun.svg. No external images or fonts.
Run from repository root: python3 tools/generate_icon.py
"""

from pathlib import Path
import math
import struct
import zlib


def capsule(x, y, ax, ay, bx, by, radius):
    dx, dy = bx - ax, by - ay
    t = max(0, min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(x - ax - t * dx, y - ay - t * dy) <= radius


def color(x, y):
    if math.hypot(max(abs(x - 32) - 16, 0), max(abs(y - 32) - 16, 0)) > 16:
        return (0, 0, 0, 0)
    ring = y <= 30 and abs(math.hypot(x - 32, y - 30) - 14) <= 3
    mint = ring or capsule(x, y, 18, 30, 18, 46, 3) or capsule(x, y, 46, 30, 46, 46, 3)
    white = capsule(x, y, 30, 30, 30, 46, 2.5) or capsule(x, y, 30, 46, 37, 46, 2.5)
    return (244, 246, 241, 255) if white else (132, 213, 181, 255) if mint else (17, 43, 39, 255)


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xFFFFFFFF)


def png(size):
    raw = bytearray()
    for row in range(size):
        raw.append(0)
        for col in range(size):
            samples = [color((col + (sx + .5) / 4) * 64 / size,
                             (row + (sy + .5) / 4) * 64 / size)
                       for sx in range(4) for sy in range(4)]
            raw.extend(round(sum(p[c] for p in samples) / 16) for c in range(4))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


def main():
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [png(size) for size in sizes]
    offset = 6 + 16 * len(sizes)
    directory = bytearray(struct.pack('<HHH', 0, 1, len(sizes)))
    for size, image in zip(sizes, images):
        directory.extend(struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(image), offset))
        offset += len(image)
    target = Path('windows/runner/resources/app_icon.ico')
    target.write_bytes(directory + b''.join(images))


if __name__ == '__main__':
    main()

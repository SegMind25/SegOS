"""Prints the size of a PNG and the colour at a few points, by name.

Used by `cargo xtask test` inside SegOS (with Ubuntu's python3) to check
Firefox's `--screenshot` of a test page: python3 pngcheck.py shot.png
prints e.g. "PNG 1366x768 top=red middle=red bottom=blue". Only the
standard library (zlib) is needed; 8-bit RGB and RGBA images.
"""
import struct
import sys
import zlib


def load(path):
    data = open(path, 'rb').read()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        sys.exit('not a PNG')
    at, idat = 8, b''
    while at < len(data):
        n, kind = struct.unpack('>I4s', data[at:at + 8])
        body = data[at + 8:at + 8 + n]
        at += 12 + n
        if kind == b'IHDR':
            w, h, depth, ctype = struct.unpack('>IIBB', body[:10])
        elif kind == b'IDAT':
            idat += body
    if depth != 8 or ctype not in (2, 6):
        sys.exit('unsupported PNG: depth %d, colour type %d' % (depth, ctype))
    bpp = 3 if ctype == 2 else 4
    raw = zlib.decompress(idat)
    stride = w * bpp
    rows, prev, p = [], bytearray(stride), 0
    for _ in range(h):
        f, line = raw[p], bytearray(raw[p + 1:p + 1 + stride])
        p += 1 + stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            b = prev[x]
            c = prev[x - bpp] if x >= bpp else 0
            if f == 1:
                line[x] = (line[x] + a) & 255
            elif f == 2:
                line[x] = (line[x] + b) & 255
            elif f == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif f == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pred = a if pa <= pb and pa <= pc else b if pb <= pc else c
                line[x] = (line[x] + pred) & 255
        rows.append(line)
        prev = line
    return w, h, bpp, rows


def name(r, g, b):
    if r > 200 and g < 50 and b < 50:
        return 'red'
    if g > 200 and r < 50 and b < 50:
        return 'green'
    if b > 200 and r < 50 and g < 50:
        return 'blue'
    return '%02x%02x%02x' % (r, g, b)


w, h, bpp, rows = load(sys.argv[1])
points = [('top', 0.1), ('middle', 0.4), ('bottom', 0.9)]
out = ['PNG %dx%d' % (w, h)]
for label, fy in points:
    x, y = w // 2 * bpp, int(h * fy)
    out.append('%s=%s' % (label, name(*rows[y][x:x + 3])))
print(' '.join(out))

"""
SUPERFILE — lightweight pure-Python image operations.

Pixels are 8-bit RGBA rows (4 bytes/pixel), the internal decoded form used by
the IMAGE object type.  No external dependencies.
"""

from __future__ import annotations


def _px(buf, w, x, y):
    i = (y * w + x) * 4
    return buf[i], buf[i + 1], buf[i + 2], buf[i + 3]


def crop_rgba(buf: bytes, w: int, h: int, x: int, y: int, cw: int, ch: int) -> bytes:
    out = bytearray(cw * ch * 4)
    for row in range(ch):
        src = ((y + row) * w + x) * 4
        dst = row * cw * 4
        out[dst:dst + cw * 4] = buf[src:src + cw * 4]
    return bytes(out)


def resize_rgba(buf: bytes, w: int, h: int, nw: int, nh: int, smooth: bool = True) -> bytes:
    if (nw, nh) == (w, h):
        return bytes(buf)
    out = bytearray(nw * nh * 4)
    if not smooth:
        for oy in range(nh):
            sy = min(h - 1, oy * h // nh)
            for ox in range(nw):
                sx = min(w - 1, ox * w // nw)
                si = (sy * w + sx) * 4
                di = (oy * nw + ox) * 4
                out[di:di + 4] = buf[si:si + 4]
        return bytes(out)
    # bilinear
    xr = (w - 1) / max(1, nw - 1) if nw > 1 else 0.0
    yr = (h - 1) / max(1, nh - 1) if nh > 1 else 0.0
    for oy in range(nh):
        fy = oy * yr
        y0 = int(fy)
        y1 = min(h - 1, y0 + 1)
        wy = fy - y0
        for ox in range(nw):
            fx = ox * xr
            x0 = int(fx)
            x1 = min(w - 1, x0 + 1)
            wx = fx - x0
            di = (oy * nw + ox) * 4
            for c in range(4):
                p00 = buf[(y0 * w + x0) * 4 + c]
                p01 = buf[(y0 * w + x1) * 4 + c]
                p10 = buf[(y1 * w + x0) * 4 + c]
                p11 = buf[(y1 * w + x1) * 4 + c]
                top = p00 * (1 - wx) + p01 * wx
                bot = p10 * (1 - wx) + p11 * wx
                out[di + c] = int(top * (1 - wy) + bot * wy + 0.5)
    return bytes(out)


def rotate_rgba(buf: bytes, w: int, h: int, degrees: int) -> tuple:
    degrees %= 360
    if degrees == 0:
        return bytes(buf), w, h
    if degrees == 180:
        out = bytearray(len(buf))
        for y in range(h):
            for x in range(w):
                si = (y * w + x) * 4
                di = ((h - 1 - y) * w + (w - 1 - x)) * 4
                out[di:di + 4] = buf[si:si + 4]
        return bytes(out), w, h
    nw, nh = h, w
    out = bytearray(nw * nh * 4)
    for y in range(h):
        for x in range(w):
            si = (y * w + x) * 4
            if degrees == 90:      # clockwise
                nx, ny = h - 1 - y, x
            else:                  # 270 clockwise == 90 counter-clockwise
                nx, ny = y, w - 1 - x
            di = (ny * nw + nx) * 4
            out[di:di + 4] = buf[si:si + 4]
    return bytes(out), nw, nh


def flip_rgba(buf: bytes, w: int, h: int, axis: str = "horizontal") -> bytes:
    out = bytearray(len(buf))
    for y in range(h):
        for x in range(w):
            si = (y * w + x) * 4
            if axis == "vertical":
                nx, ny = x, h - 1 - y
            else:
                nx, ny = w - 1 - x, y
            di = (ny * w + nx) * 4
            out[di:di + 4] = buf[si:si + 4]
    return bytes(out)


def grayscale_rgba(buf: bytes) -> bytes:
    out = bytearray(len(buf))
    for i in range(0, len(buf), 4):
        r, g, b, a = buf[i:i + 4]
        lum = (r * 299 + g * 587 + b * 114) // 1000
        out[i] = out[i + 1] = out[i + 2] = lum
        out[i + 3] = a
    return bytes(out)


def flatten_white(buf: bytes) -> bytes:
    """RGBA → RGB over white (for BMP/JPEG-style encoders)."""
    out = bytearray(len(buf) // 4 * 3)
    j = 0
    for i in range(0, len(buf), 4):
        r, g, b, a = buf[i:i + 4]
        if a < 255:
            r = (r * a + 255 * (255 - a)) // 255
            g = (g * a + 255 * (255 - a)) // 255
            b = (b * a + 255 * (255 - a)) // 255
        out[j:j + 3] = bytes((r, g, b))
        j += 3
    return bytes(out)

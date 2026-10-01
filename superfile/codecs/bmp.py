"""
SUPERFILE — BMP codec (24-bit uncompressed encode, 24/32-bit decode).
"""

from __future__ import annotations

import struct

from ..security import UnsafeInputError, LIMITS, LimitExceededError


def decode(data: bytes) -> dict:
    if data[:2] != b"BM":
        raise UnsafeInputError("not a BMP file")
    (file_size, _r1, _r2, pix_off) = struct.unpack_from("<IHHI", data, 2)
    hdr_size = struct.unpack_from("<I", data, 14)[0]
    if hdr_size < 40:
        raise UnsafeInputError("unsupported BMP header")
    width, height = struct.unpack_from("<ii", data, 18)
    planes, bpp = struct.unpack_from("<HH", data, 26)
    compression = struct.unpack_from("<I", data, 30)[0]
    if compression not in (0, 3):   # BI_RGB or BI_BITFIELDS (treat as raw)
        raise UnsafeInputError(f"compressed BMP (method {compression}) not supported")
    if bpp not in (24, 32):
        raise UnsafeInputError(f"{bpp}-bit BMP not supported by pure decoder")
    flip = height > 0
    height = abs(height)
    if width <= 0 or width * height > LIMITS.max_image_pixels:
        raise LimitExceededError("BMP pixel count exceeds decode limit")

    row_bytes = ((width * (bpp // 8) + 3) // 4) * 4
    rgba = bytearray(width * height * 4)
    src = pix_off
    for row in range(height):
        y = (height - 1 - row) if flip else row
        base = src + row * row_bytes
        for x in range(width):
            i = base + x * (bpp // 8)
            if i + (bpp // 8) > len(data):
                raise UnsafeInputError("BMP pixel data truncated")
            b, g, r = data[i], data[i + 1], data[i + 2]
            a = data[i + 3] if bpp == 32 else 255
            di = (y * width + x) * 4
            rgba[di:di + 4] = bytes((r, g, b, a))
    return {"width": width, "height": height, "mode": "RGBA", "pixels": bytes(rgba)}


def encode_rgb(pixels_rgb: bytes, width: int, height: int) -> bytes:
    row_bytes = ((width * 3 + 3) // 4) * 4
    img_size = row_bytes * height
    header = struct.pack("<2sIHHI", b"BM", 54 + img_size, 0, 0, 54)
    info = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, img_size, 2835, 2835, 0, 0)
    body = bytearray()
    pad = b"\x00" * (row_bytes - width * 3)
    for y in range(height - 1, -1, -1):
        row = bytearray()
        base = y * width * 3
        for x in range(width):
            r, g, b = pixels_rgb[base + x * 3:base + x * 3 + 3]
            row += bytes((b, g, r))
        body += row + pad
    return header + info + bytes(body)


def encode_from_rgba(pixels: bytes, width: int, height: int) -> bytes:
    from .imageops import flatten_white
    return encode_rgb(flatten_white(pixels), width, height)

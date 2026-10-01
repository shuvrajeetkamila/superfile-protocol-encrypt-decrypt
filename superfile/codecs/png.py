"""
SUPERFILE — pure-Python PNG codec (subset).

Decode: 8-bit greyscale/RGB/palette/RGBA, non-interlaced (color types
0, 2, 3, 4, 6).  Interlaced or 16-bit PNGs fall back to Pillow when present.
Encode: 8-bit RGB/RGBA/greyscale, filter 0, single IDAT.

This keeps baseline image editing functional with zero dependencies.
"""

from __future__ import annotations

import struct
import zlib

from ..security import LimitExceededError, UnsafeInputError, LIMITS

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _chunks(data: bytes):
    if data[:8] != PNG_SIG:
        raise UnsafeInputError("not a PNG file")
    pos = 8
    while pos + 8 <= len(data):
        (length,) = struct.unpack_from(">I", data, pos)
        tag = data[pos + 4:pos + 8]
        payload = data[pos + 8:pos + 8 + length]
        crc_data = data[pos + 8 + length:pos + 12 + length]
        if len(payload) != length or len(crc_data) != 4:
            raise UnsafeInputError("truncated PNG chunk")
        crc = struct.unpack(">I", crc_data)[0]
        if zlib.crc32(tag + payload) & 0xFFFFFFFF != crc:
            raise UnsafeInputError(f"PNG chunk {tag!r} CRC mismatch")
        yield tag, payload
        pos += 12 + length
        if tag == b"IEND":
            return


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def decode(data: bytes) -> dict:
    """
    Returns {"width", "height", "mode": "RGBA", "pixels": rgba_bytes}.
    Raises UnsafeInputError for unsupported variants (caller may fall back).
    """
    width = height = None
    bit_depth = color_type = interlace = None
    palette = b""
    trns = b""
    idat = bytearray()

    for tag, payload in _chunks(data):
        if tag == b"IHDR":
            width, height, bit_depth, color_type, _comp, _filt, interlace = struct.unpack(
                ">IIBBBBB", payload)
        elif tag == b"PLTE":
            palette = payload
        elif tag == b"tRNS":
            trns = payload
        elif tag == b"IDAT":
            idat += payload
        elif tag == b"IEND":
            break

    if width is None:
        raise UnsafeInputError("PNG missing IHDR")
    if interlace != 0:
        raise UnsafeInputError("interlaced PNG not supported by pure decoder")
    if bit_depth not in (8,):
        raise UnsafeInputError(f"PNG bit depth {bit_depth} not supported by pure decoder")
    if width * height > LIMITS.max_image_pixels:
        raise LimitExceededError("PNG pixel count exceeds decode limit")
    if width <= 0 or height <= 0 or width > 32768 or height > 32768:
        raise UnsafeInputError("unreasonable PNG dimensions")

    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type)
    if channels is None:
        raise UnsafeInputError(f"PNG color type {color_type} not supported")

    raw = zlib.decompress(bytes(idat))
    stride = width * channels
    expected = (stride + 1) * height
    if len(raw) < expected:
        raise UnsafeInputError("PNG pixel data truncated")

    # un-filter
    out = bytearray(stride * height)
    prev = bytearray(stride)
    pos = 0
    for y in range(height):
        ftype = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if ftype == 0:
            pass
        elif ftype == 1:    # Sub
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif ftype == 2:    # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:    # Average
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:    # Paeth
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                ul = prev[i - channels] if i >= channels else 0
                line[i] = (line[i] + _paeth(left, prev[i], ul)) & 0xFF
        else:
            raise UnsafeInputError(f"bad PNG filter type {ftype}")
        out[y * stride:(y + 1) * stride] = line
        prev = line

    # to RGBA
    rgba = bytearray(width * height * 4)
    if color_type == 6 and channels == 4:
        rgba[:] = out
    elif color_type == 2:    # RGB
        for i in range(width * height):
            rgba[i * 4:i * 4 + 3] = out[i * 3:i * 3 + 3]
            rgba[i * 4 + 3] = 255
    elif color_type == 0:    # grey
        for i in range(width * height):
            g = out[i]
            rgba[i * 4] = rgba[i * 4 + 1] = rgba[i * 4 + 2] = g
            rgba[i * 4 + 3] = 255
    elif color_type == 4:    # grey + alpha
        for i in range(width * height):
            g, a = out[i * 2], out[i * 2 + 1]
            rgba[i * 4] = rgba[i * 4 + 1] = rgba[i * 4 + 2] = g
            rgba[i * 4 + 3] = a
    elif color_type == 3:    # palette
        if not palette:
            raise UnsafeInputError("paletted PNG without PLTE")
        for i in range(width * height):
            idx = out[i]
            if idx * 3 + 3 > len(palette):
                raise UnsafeInputError("palette index out of range")
            rgba[i * 4:i * 4 + 3] = palette[idx * 3:idx * 3 + 3]
            rgba[i * 4 + 3] = trns[idx] if idx < len(trns) else 255

    return {"width": width, "height": height, "mode": "RGBA", "pixels": bytes(rgba)}


def encode_rgba(pixels: bytes, width: int, height: int) -> bytes:
    return _encode(pixels, width, height, 6, 4)


def encode_rgb(pixels: bytes, width: int, height: int) -> bytes:
    return _encode(pixels, width, height, 2, 3)


def encode_gray(pixels: bytes, width: int, height: int) -> bytes:
    return _encode(pixels, width, height, 0, 1)


def _encode(pixels: bytes, width: int, height: int, color_type: int, channels: int) -> bytes:
    stride = width * channels
    if len(pixels) < stride * height:
        raise UnsafeInputError("pixel buffer too small")
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type 0
        raw += pixels[y * stride:(y + 1) * stride]
    idat = zlib.compress(bytes(raw), 6)

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload +
                struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    return PNG_SIG + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def encode_from_rgba(pixels: bytes, width: int, height: int, mode: str = "RGBA") -> bytes:
    """Encode from internal RGBA buffer, choosing the smallest honest PNG form."""
    opaque = all(pixels[i + 3] == 255 for i in range(0, len(pixels), 4)) if pixels else True
    grey = opaque and all(
        pixels[i] == pixels[i + 1] == pixels[i + 2]
        for i in range(0, len(pixels), 4))
    if grey:
        g = bytearray(width * height)
        for i in range(width * height):
            g[i] = pixels[i * 4]
        return encode_gray(bytes(g), width, height)
    if opaque:
        rgb = bytearray(width * height * 3)
        for i in range(width * height):
            rgb[i * 3:i * 3 + 3] = pixels[i * 4:i * 4 + 3]
        return encode_rgb(bytes(rgb), width, height)
    return encode_rgba(pixels, width, height)

"""
SUPERFILE — GIF codec (pure Python).

Decode: full frame extraction for GIF87a/89a (LZW, local palettes, graphic
control extensions, disposal, transparency), including animation timing.

Encode: palette images (exact palette when colours <= 256, otherwise a fixed
6x6x6 colour cube + greys), LZW compression, multi-frame animation with
delays and transparency.

Used for: GIF inspection, animation playback metadata, frame extraction and
"Create basic animation".
"""

from __future__ import annotations

import struct

from ..security import UnsafeInputError, LIMITS, LimitExceededError


# ---------------------------------------------------------------------------
# LZW
# ---------------------------------------------------------------------------

def _lzw_decode(data: bytes, min_code_size: int, npix: int) -> bytes:
    clear = 1 << min_code_size
    eoi = clear + 1
    code_size = min_code_size + 1
    dict_ = {}

    def reset_dict():
        dict_.clear()
        for i in range(clear):
            dict_[i] = bytes((i,))
        dict_[clear] = b""
        dict_[eoi] = b""

    reset_dict()
    out = bytearray()
    prev = None
    bitpos = 0
    total_bits = len(data) * 8
    next_code = eoi + 1

    while bitpos + code_size <= total_bits:
        # read variable-length code (LSB-first)
        byte_i = bitpos >> 3
        chunk = int.from_bytes(data[byte_i:byte_i + 3].ljust(3, b"\x00"), "little")
        code = (chunk >> (bitpos & 7)) & ((1 << code_size) - 1)
        bitpos += code_size

        if code == clear:
            reset_dict()
            code_size = min_code_size + 1
            next_code = eoi + 1
            prev = None
            continue
        if code == eoi:
            break
        if prev is None:
            entry = dict_.get(code)
            if entry is None:
                raise UnsafeInputError("GIF LZW: invalid first code")
            out += entry
            prev = entry
            continue
        if code in dict_:
            entry = dict_[code]
        elif code == next_code:
            entry = prev + prev[:1]
        else:
            raise UnsafeInputError("GIF LZW: corrupt code stream")
        out += entry
        if next_code < 4096:
            dict_[next_code] = prev + entry[:1]
            next_code += 1
            if next_code >= (1 << code_size) and code_size < 12:
                code_size += 1
        prev = entry
        if len(out) >= npix:
            break
    return bytes(out[:npix])


def _lzw_encode(pixels: bytes, min_code_size: int) -> bytes:
    clear = 1 << min_code_size
    eoi = clear + 1
    code_size = min_code_size + 1
    dictionary = {bytes((i,)): i for i in range(clear)}
    next_code = eoi + 1
    out = bytearray()
    bitbuf = 0
    bitcount = 0

    def emit(code: int):
        nonlocal bitbuf, bitcount
        bitbuf |= code << bitcount
        bitcount += code_size
        while bitcount >= 8:
            out.append(bitbuf & 0xFF)
            bitbuf >>= 8
            bitcount -= 8

    emit(clear)
    w = b""
    for ch in pixels:
        wc = w + bytes((ch,))
        if wc in dictionary:
            w = wc
            continue
        emit(dictionary[w])
        if next_code < 4096:
            dictionary[wc] = next_code
            next_code += 1
            # GIF quirk: the ENCODER grows the code size one entry later than
            # the decoder (bump only once next_code > 2^code_size).
            if next_code > (1 << code_size) and code_size < 12:
                code_size += 1
        else:
            emit(clear)
            dictionary = {bytes((i,)): i for i in range(clear)}
            next_code = eoi + 1
            code_size = min_code_size + 1
        w = bytes((ch,))
    if w:
        emit(dictionary[w])
    emit(eoi)
    if bitcount:
        out.append(bitbuf & 0xFF)
    return bytes(out)


def _pack_sub_blocks(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(data):
        n = min(255, len(data) - pos)
        out.append(n)
        out += data[pos:pos + n]
        pos += n
    out.append(0)
    return bytes(out)


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------

def decode(data: bytes) -> dict:
    """
    Returns {"width","height","loop","frames":[{"x","y","w","h","delay_ms",
    "disposal","transparent","pixels"(RGBA),"palette_index"}], "global_palette"}.
    """
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        raise UnsafeInputError("not a GIF file")
    width, height, flags, bg, _aspect = struct.unpack_from("<HHBBB", data, 6)
    if width * height > LIMITS.max_image_pixels:
        raise LimitExceededError("GIF pixel count exceeds decode limit")
    gpal_size = 2 << (flags & 7) if flags & 0x80 else 0
    pos = 13
    global_palette = data[pos:pos + gpal_size * 3]
    pos += gpal_size * 3

    loop = 0
    frames = []
    gce = {"delay": 100, "disposal": 0, "transparent": None}
    canvas = bytearray(width * height * 4)   # composited RGBA (simple, no disposal render)

    while pos < len(data):
        b = data[pos]
        if b == 0x3B:                        # trailer
            break
        if b == 0x21:                        # extension
            if pos + 2 > len(data):
                break
            label = data[pos + 1]
            pos += 2
            blocks, pos2 = _read_sub_blocks(data, pos)
            pos = pos2
            if label == 0xF9 and blocks:      # graphic control
                packed = blocks[0]
                (delay,) = struct.unpack_from("<H", blocks, 1)
                tidx = blocks[3]
                gce = {
                    "delay": max(20, delay * 10),
                    "disposal": (packed >> 2) & 7,
                    "transparent": tidx if packed & 1 else None,
                }
            elif label == 0xFF and blocks.startswith(b"NETSCAPE"):
                if len(blocks) >= 10:
                    loop = struct.unpack_from("<H", blocks, 7)[0] & 0x7FFF
            continue
        if b == 0x2C:                        # image descriptor
            if pos + 10 > len(data):
                raise UnsafeInputError("truncated GIF image descriptor")
            fx, fy, fw, fh, fflags = struct.unpack_from("<HHHHB", data, pos + 1)
            pos += 10
            lpal_size = 2 << (fflags & 7) if fflags & 0x80 else 0
            local_palette = data[pos:pos + lpal_size * 3]
            pos += lpal_size * 3
            if pos >= len(data):
                raise UnsafeInputError("truncated GIF before LZW data")
            min_code = data[pos]
            pos += 1
            lzw_data, pos = _read_sub_blocks(data, pos)
            if fw * fh > LIMITS.max_image_pixels:
                raise LimitExceededError("GIF frame too large")
            indexed = _lzw_decode(lzw_data, min_code, fw * fh)
            pal = local_palette if lpal_size else global_palette
            interlaced = bool(fflags & 0x40)
            rows = _deinterlace(indexed, fw, fh) if interlaced else indexed

            frame_rgba = bytearray(fw * fh * 4)
            for i in range(fw * fh):
                idx = rows[i]
                di = i * 4
                if idx * 3 + 3 <= len(pal):
                    frame_rgba[di:di + 3] = pal[idx * 3:idx * 3 + 3]
                if gce["transparent"] is not None and idx == gce["transparent"]:
                    frame_rgba[di + 3] = 0
                else:
                    frame_rgba[di + 3] = 255

            # simple canvas composition (source-over at frame origin)
            for yy in range(fh):
                cy = fy + yy
                if cy < 0 or cy >= height:
                    continue
                for xx in range(fw):
                    cx = fx + xx
                    if cx < 0 or cx >= width:
                        continue
                    si = (yy * fw + xx) * 4
                    if frame_rgba[si + 3] == 0:
                        continue
                    ci = (cy * width + cx) * 4
                    canvas[ci:ci + 4] = frame_rgba[si:si + 4]

            frames.append({
                "x": fx, "y": fy, "w": fw, "h": fh,
                "delay_ms": gce["delay"], "disposal": gce["disposal"],
                "transparent": gce["transparent"],
                "pixels": bytes(frame_rgba),
                "composited": bytes(canvas),
            })
            gce = {"delay": 100, "disposal": 0, "transparent": None}
            continue
        # unknown byte — resynchronise
        pos += 1

    return {
        "width": width, "height": height, "loop": loop,
        "global_palette": global_palette,
        "frames": frames,
    }


def _read_sub_blocks(data: bytes, pos: int) -> tuple:
    out = bytearray()
    while pos < len(data):
        n = data[pos]
        pos += 1
        if n == 0:
            break
        out += data[pos:pos + n]
        pos += n
    return bytes(out), pos


def _deinterlace(indexed: bytes, w: int, h: int) -> bytes:
    out = bytearray(w * h)
    passes = [(0, 8), (4, 8), (2, 4), (1, 2)]
    src_row = 0
    for start, step in passes:
        for y in range(start, h, step):
            out[y * w:(y + 1) * w] = indexed[src_row * w:(src_row + 1) * w]
            src_row += 1
    return bytes(out)


# ---------------------------------------------------------------------------
# encode
# ---------------------------------------------------------------------------

_WEB_SAFE = []
for _r in (0, 51, 102, 153, 204, 255):
    for _g in (0, 51, 102, 153, 204, 255):
        for _b in (0, 51, 102, 153, 204, 255):
            _WEB_SAFE.append((_r, _g, _b))
for _i in range(8):
    _v = _i * 255 // 7
    _WEB_SAFE.append((_v, _v, _v))
_WEB_SAFE += [(0, 0, 0), (255, 255, 255)]


def _build_palette(frames_rgba: list, transparent: bool) -> tuple:
    """Return (palette_bytes_rgb, mapper(rgba)->index, has_transparent)."""
    colors = {}
    for rgba in frames_rgba:
        for i in range(0, len(rgba), 4):
            if transparent and rgba[i + 3] == 0:
                continue
            colors[(rgba[i], rgba[i + 1], rgba[i + 2])] = None
            if len(colors) > 4096:
                break
    if len(colors) <= 254:
        keys = list(colors.keys())
        pal = bytearray()
        for c in keys:
            pal += bytes(c)
        lut = {c: i for i, c in enumerate(keys)}

        def mapper(rgba, lut=lut, tr=transparent):
            if tr and rgba[3] == 0:
                return 255
            return lut.get((rgba[0], rgba[1], rgba[2]), 0)
        # pad palette to 256 entries
        n = max(2, len(keys))
        bits = 1
        while (1 << bits) < n:
            bits += 1
        pal += b"\x00" * ((1 << bits) - len(keys)) * 3
        return bytes(pal), mapper, transparent, bits
    # quantise to fixed cube
    cube = {c: i for i, c in enumerate(_WEB_SAFE[:216])}
    grey_start = 216

    def mapper(rgba, cube=cube, gs=grey_start, tr=transparent):
        if tr and rgba[3] == 0:
            return 255
        r, g, b = rgba[0], rgba[1], rgba[2]
        if r == g == b:
            return gs + min(7, r * 8 // 256)
        return cube.get((r // 51 * 51, g // 51 * 51, b // 51 * 51), 0)
    pal = bytearray()
    for c in _WEB_SAFE[:224]:
        pal += bytes(c)
    pal += b"\x00" * (256 - 224) * 3
    return bytes(pal), mapper, transparent, 8


def encode_animation(frames_rgba: list, width: int, height: int,
                     delays_ms: list, loop: int = 0, transparent: bool = True) -> bytes:
    pal, mapper, has_tr, bits = _build_palette(frames_rgba, transparent)
    out = bytearray(b"GIF89a")
    out += struct.pack("<HHBBB", width, height, 0x80 | (bits - 1), 0, 0)
    out += pal[: (1 << bits) * 3]
    # netscape loop
    out += b"\x21\xFF\x0bNETSCAPE2.0\x03\x01" + struct.pack("<H", loop) + b"\x00"
    min_code = max(2, bits)
    for idx, rgba in enumerate(frames_rgba):
        delay = int(delays_ms[idx] / 10) if idx < len(delays_ms) else 10
        out += b"\x21\xF9\x04"
        packed = 0x08 | (1 << 2)   # disposal=1, transparency flag if needed
        if has_tr:
            packed |= 0x01
        out += bytes((packed,))
        out += struct.pack("<H", delay)
        out += bytes((255 if has_tr else 0, 0))  # transparent index 255
        out += b"\x2c" + struct.pack("<HHHHB", 0, 0, width, height, 0)
        out += bytes((min_code,))
        indexed = bytearray(width * height)
        for i in range(width * height):
            r, g, b, a = rgba[i * 4:i * 4 + 4]
            indexed[i] = mapper((r, g, b, a))
        lzw = _lzw_encode(bytes(indexed), min_code)
        out += _pack_sub_blocks(lzw)
    out += b"\x3b"
    return bytes(out)


def encode_static(rgba: bytes, width: int, height: int) -> bytes:
    return encode_animation([rgba], width, height, [1000], loop=0)

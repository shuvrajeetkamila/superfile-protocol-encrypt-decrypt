"""
SUPERFILE — Image adapters: PNG BMP GIF JPEG WebP TIFF SVG

PNG / BMP / GIF are FULL or PARTIAL via pure-Python codecs (zero deps).
JPEG / WebP / TIFF decode+encode use Pillow when available and degrade to
honest INSPECTION ONLY (original bytes preserved) otherwise.
SVG is text with structural parsing.
"""

from __future__ import annotations

import io
import math
import re

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..codecs import bmp as bmp_codec
from ..codecs import gif as gif_codec
from ..codecs import png as png_codec
from ..codecs.imageops import flatten_white
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import LIMITS, LimitExceededError, UnsafeInputError, hex_preview, sha256

try:  # optional accelerated/extra codecs
    from PIL import Image as PILImage
    HAS_PIL = True
except Exception:
    PILImage = None
    HAS_PIL = False


def _store_pixels(obj: UniversalObject, decoded: dict) -> None:
    obj.content.update({
        "kind": "image",
        "width": decoded["width"],
        "height": decoded["height"],
        "mode": decoded.get("mode", "RGBA"),
        "pixels": obj.blob_ref(decoded["pixels"]),
    })


def _make(fmt, spec, otype, data, filename) -> UniversalObject:
    obj = UniversalObject(
        object_type=otype,
        original_filename=filename,
        original_extension=fmt,
        detected_format=fmt,
        mime=spec.mime,
        size=len(data),
        original_bytes=data,
        checksum=sha256(data),
        support_level=spec.support,
    )
    obj.record("import", f"imported {filename or fmt}")
    return obj


class RasterAdapter(FormatAdapter):
    """PNG / BMP / GIF (pure) + JPEG / WebP / TIFF (Pillow-optional)."""

    name = "image"
    version = "1.1"
    _pil = HAS_PIL
    formats = {
        "png": FormatSpec("png", "PNG image", ["png"], "image/png", "IMAGE",
                          SupportLevel.FULL, read=True, create=True, edit=True, export=True,
                          detection="magic", notes="pure-Python codec (8-bit, non-interlaced)"),
        "bmp": FormatSpec("bmp", "BMP image", ["bmp"], "image/bmp", "IMAGE",
                          SupportLevel.FULL, read=True, create=True, edit=True, export=True,
                          detection="magic", notes="24/32-bit uncompressed"),
        "gif": FormatSpec("gif", "GIF image/animation", ["gif"], "image/gif", "ANIMATION",
                          SupportLevel.FULL, read=True, create=True, edit=True, export=True,
                          detection="magic", notes="pure LZW codec — frames, timing, extraction"),
        "jpeg": FormatSpec("jpeg", "JPEG image", ["jpg", "jpeg"], "image/jpeg", "IMAGE",
                           SupportLevel.PARTIAL if HAS_PIL else SupportLevel.INSPECTION,
                           read=True, create=HAS_PIL, edit=HAS_PIL, export=HAS_PIL,
                           detection="magic",
                           notes="decoded via Pillow" if HAS_PIL else
                                 "INSPECTION ONLY without Pillow — original bytes preserved"),
        "webp": FormatSpec("webp", "WebP image", ["webp"], "image/webp", "IMAGE",
                           SupportLevel.PARTIAL if HAS_PIL else SupportLevel.INSPECTION,
                           read=True, create=HAS_PIL, edit=HAS_PIL, export=HAS_PIL,
                           detection="magic",
                           notes="decoded via Pillow" if HAS_PIL else
                                 "INSPECTION ONLY without Pillow — original bytes preserved"),
        "tiff": FormatSpec("tiff", "TIFF image", ["tiff", "tif"], "image/tiff", "IMAGE",
                           SupportLevel.INSPECTION if not HAS_PIL else SupportLevel.PARTIAL,
                           read=True, export=HAS_PIL, detection="magic",
                           notes="header/IFD inspection" + (" + Pillow decode" if HAS_PIL else "")),
    }
    capabilities = {
        "png": {"detect", "read", "parse", "decode", "create", "edit", "encode", "export", "inspect"},
        "bmp": {"detect", "read", "parse", "decode", "create", "edit", "encode", "export", "inspect"},
        "gif": {"detect", "read", "parse", "decode", "create", "edit", "encode", "export", "inspect"},
        "jpeg": {"detect", "read", "parse", "decode", "create", "edit", "encode", "export", "inspect"}
        if HAS_PIL else {"detect", "read", "parse", "inspect"},
        "webp": {"detect", "read", "parse", "decode", "create", "edit", "encode", "export", "inspect"}
        if HAS_PIL else {"detect", "read", "parse", "inspect"},
        "tiff": {"detect", "read", "parse", "decode", "export", "inspect"} if HAS_PIL
        else {"detect", "read", "parse", "inspect"},
    }
    input_types = [ObjectType.IMAGE, ObjectType.ANIMATION]
    output_types = [ObjectType.IMAGE, ObjectType.ANIMATION]

    # ------------------------------------------------------------------
    def read(self, data: bytes, filename: str = "", detection=None) -> UniversalObject:
        fmt = detection.format_id if detection else _fmt_from_name(filename)
        spec = self.formats.get(fmt) or self.formats["png"]
        otype = ObjectType.ANIMATION if fmt == "gif" else ObjectType.IMAGE
        obj = _make(fmt, spec, otype, data, filename)
        try:
            if fmt == "png":
                decoded = png_codec.decode(data)
                _store_pixels(obj, decoded)
            elif fmt == "bmp":
                decoded = bmp_codec.decode(data)
                _store_pixels(obj, decoded)
            elif fmt == "gif":
                self._read_gif(obj, data)
            elif fmt in ("jpeg", "webp", "tiff"):
                self._read_pil(obj, data, fmt)
            else:
                raise UnsafeInputError(f"raster adapter cannot read {fmt}")
        except (UnsafeInputError, LimitExceededError) as exc:
            obj.warnings.append(str(exc))
            obj.support_level = SupportLevel.INSPECTION
            obj.content = {"kind": "image", "decoded": False, "note": str(exc),
                           "hex_preview": hex_preview(data)}
        return obj

    def _read_gif(self, obj: UniversalObject, data: bytes) -> None:
        g = gif_codec.decode(data)
        frames_meta = []
        for i, fr in enumerate(g["frames"]):
            key = obj.add_blob(fr["composited"], f"frame{i}")
            frames_meta.append({
                "index": i, "x": fr["x"], "y": fr["y"], "w": fr["w"], "h": fr["h"],
                "delay_ms": fr["delay_ms"], "disposal": fr["disposal"],
                "transparent": fr["transparent"],
                "pixels": {"__blob__": key},
            })
        obj.content.update({
            "kind": "animation",
            "width": g["width"], "height": g["height"], "mode": "RGBA",
            "loop": g["loop"],
            "frame_count": len(g["frames"]),
            "frames": frames_meta,
            "pixels": obj.blob_ref(g["frames"][-1]["composited"] if g["frames"] else b""),
        })
        obj.metadata["frame_count"] = len(g["frames"])
        obj.metadata["loop_count"] = g["loop"]

    def _read_pil(self, obj: UniversalObject, data: bytes, fmt: str) -> None:
        if not HAS_PIL:
            raise UnsafeInputError(f"{fmt} needs Pillow for decoding — inspection only")
        im = PILImage.open(io.BytesIO(data))
        im.load()
        if im.width * im.height > LIMITS.max_image_pixels:
            raise LimitExceededError("image too large to decode")
        obj.metadata["pil_mode"] = im.mode
        obj.metadata["format_version"] = (im.format or fmt).upper()
        if fmt == "gif" and getattr(im, "is_animated", False):
            raise UnsafeInputError("use GIF path")
        if fmt == "tiff":
            obj.metadata["tiff_frames"] = getattr(im, "n_frames", 1)
        rgba = im.convert("RGBA")
        _store_pixels(obj, {"width": rgba.width, "height": rgba.height,
                            "mode": "RGBA", "pixels": rgba.tobytes()})
        if fmt == "jpeg":
            ex = {}
            try:
                raw = getattr(im, "getexif", lambda: {})()
                ex = {str(k): str(v)[:120] for k, v in dict(raw).items()}
            except Exception:
                pass
            if ex:
                obj.metadata["exif"] = ex

    # ------------------------------------------------------------------
    def create(self, object_type=ObjectType.IMAGE, params=None) -> UniversalObject:
        """Create Image: procedural pattern (gradient/checker) as PNG object."""
        p = params or {}
        w = max(1, min(2048, int(p.get("width", 256))))
        h = max(1, min(2048, int(p.get("height", 256))))
        pattern = p.get("pattern", "gradient")
        pixels = bytearray(w * h * 4)
        for y in range(h):
            for x in range(w):
                i = (y * w + x) * 4
                if pattern == "checker":
                    on = ((x // 16) + (y // 16)) % 2 == 0
                    pixels[i:i + 3] = b"\x20\x60\xc0" if on else b"\xe8\xe8\xf0"
                elif pattern == "plasma":
                    v = math.sin(x / 8.0) + math.sin(y / 8.0) + math.sin((x + y) / 12.0)
                    pixels[i] = int(127 + 127 * math.sin(v + 0))
                    pixels[i + 1] = int(127 + 127 * math.sin(v + 2))
                    pixels[i + 2] = int(127 + 127 * math.sin(v + 4))
                else:  # gradient
                    pixels[i] = x * 255 // max(1, w - 1)
                    pixels[i + 1] = y * 255 // max(1, h - 1)
                    pixels[i + 2] = 160
                pixels[i + 3] = 255
        png = png_codec.encode_from_rgba(bytes(pixels), w, h)
        obj = self.read(png, p.get("filename", "created.png"), None)
        obj.record("create", f"generated {pattern} {w}x{h}", ConversionKind.RECONSTRUCTED)
        return obj

    def edit(self, obj, op, params=None):
        raise UnsafeInputError("image edits go through the transform engine")

    # ------------------------------------------------------------------
    def _rgba(self, obj):
        ref = obj.content.get("pixels")
        buf = obj.get_blob(ref)
        if buf is None or not obj.content.get("width"):
            raise UnsafeInputError("object has no decoded pixels (inspection-only image)")
        return buf, int(obj.content["width"]), int(obj.content["height"])

    def encode(self, obj, fmt) -> bytes:
        buf, w, h = self._rgba(obj)
        if fmt == "png":
            return png_codec.encode_from_rgba(buf, w, h)
        if fmt == "bmp":
            return bmp_codec.encode_from_rgba(buf, w, h)
        if fmt == "gif":
            frames_meta = obj.content.get("frames") or []
            if frames_meta and len(frames_meta) > 1:
                # re-encode the full animation from frame composites
                flist = []
                delays = []
                for f in frames_meta:
                    px = obj.get_blob(f.get("pixels"))
                    if px is None:
                        raise UnsafeInputError("animation frame pixels missing")
                    flist.append(px)
                    delays.append(int(f.get("delay_ms", 100)))
                return gif_codec.encode_animation(
                    flist, w, h, delays,
                    loop=int(obj.content.get("loop", 0)))
            return gif_codec.encode_static(buf, w, h)
        if fmt in ("jpeg", "webp", "tiff"):
            if not HAS_PIL:
                raise UnsafeInputError(f"{fmt} encoding requires Pillow — not available")
            im = PILImage.frombytes("RGBA", (w, h), buf)
            bio = io.BytesIO()
            if fmt == "jpeg":
                im.convert("RGB").save(bio, "JPEG", quality=90)
            elif fmt == "webp":
                im.save(bio, "WEBP", quality=90)
            else:
                im.save(bio, "TIFF")
            return bio.getvalue()
        raise UnsafeInputError(f"image adapter cannot encode {fmt}")

    def export_formats(self, obj) -> list:
        has_pixels = bool(obj.get_blob(obj.content.get("pixels")))
        out = []
        if has_pixels:
            out += [
                opt("png", "PNG image (.png)", ConversionKind.LOSSLESS,
                    "lossless re-encode of decoded pixels"),
                opt("bmp", "BMP image (.bmp)", ConversionKind.LOSSLESS,
                    "uncompressed 24-bit"),
                opt("gif", "GIF image (.gif)", ConversionKind.LOSSY,
                    "≤256-colour quantisation"),
                opt("ppm", "PPM image (.ppm)", ConversionKind.LOSSLESS,
                    "via example PPM adapter (plugin)"),
            ]
            if HAS_PIL:
                out.append(opt("jpeg", "JPEG image (.jpg)", ConversionKind.LOSSY, "quality 90"))
                out.append(opt("webp", "WebP image (.webp)", ConversionKind.LOSSY, "quality 90"))
                out.append(opt("tiff", "TIFF image (.tiff)", ConversionKind.STRUCTURAL, "via Pillow"))
            out.append(opt("svg", "SVG wrapper (.svg)", ConversionKind.RECONSTRUCTED,
                           "pixels embedded as base64 PNG in an SVG document"))
        out.append(opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                       "UniversalObject graph incl. original bytes"))
        return out

    def export(self, obj, fmt):
        stem = (obj.original_filename or "object").rsplit(".", 1)[0]
        if fmt == "svg":
            buf, w, h = self._rgba(obj)
            import base64
            png = png_codec.encode_from_rgba(buf, w, h)
            b64 = base64.b64encode(png).decode()
            svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
                   f'viewBox="0 0 {w} {h}"><title>{obj.original_filename or "image"}</title>'
                   f'<image width="{w}" height="{h}" '
                   f'href="data:image/png;base64,{b64}"/></svg>')
            return ExportResult(svg.encode(), stem + ".svg", "image/svg+xml",
                                ConversionKind.RECONSTRUCTED.value,
                                "raster pixels embedded as PNG data URI")
        data = self.encode(obj, fmt)
        mimes = {"png": "image/png", "bmp": "image/bmp", "gif": "image/gif",
                 "jpeg": "image/jpeg", "webp": "image/webp", "tiff": "image/tiff",
                 "ppm": "image/x-portable-pixmap"}
        kinds = {"png": ConversionKind.LOSSLESS, "bmp": ConversionKind.LOSSLESS,
                 "gif": ConversionKind.LOSSY, "jpeg": ConversionKind.LOSSY,
                 "webp": ConversionKind.LOSSY, "tiff": ConversionKind.STRUCTURAL}
        exts = {"jpeg": "jpg"}
        return ExportResult(data, f"{stem}.{exts.get(fmt, fmt)}", mimes.get(fmt, "application/octet-stream"),
                            kinds.get(fmt, ConversionKind.STRUCTURAL).value)

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        c = obj.content
        rep["structure"] = {
            "width": c.get("width"), "height": c.get("height"),
            "mode": c.get("mode"), "decoded": bool(c.get("pixels")),
            "frames": c.get("frame_count"),
            "loop": c.get("loop"),
        }
        rep["format"]["pillow"] = HAS_PIL
        return rep


class SvgAdapter(FormatAdapter):
    name = "svg"
    version = "1.0"
    formats = {
        "svg": FormatSpec("svg", "SVG image", ["svg"], "image/svg+xml", "IMAGE",
                          SupportLevel.PARTIAL, read=True, create=True, edit=True, export=True,
                          detection="text-heuristic", notes="structural parse; no full render engine"),
    }
    capabilities = {"svg": {"detect", "read", "parse", "create", "edit", "encode", "export", "inspect"}}
    input_types = [ObjectType.IMAGE, ObjectType.TEXT]
    output_types = [ObjectType.IMAGE, ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        spec = self.formats["svg"]
        text = data.decode("utf-8", "replace")
        obj = _make("svg", spec, ObjectType.IMAGE, data, filename)
        tags = {}
        for m in re.finditer(r"<(\w+)", text):
            tags[m.group(1)] = tags.get(m.group(1), 0) + 1
        vb = re.search(r'viewBox="([^"]+)"', text)
        wh = (re.search(r'\bwidth="([^"]+)"', text), re.search(r'\bheight="([^"]+)"', text))
        obj.content.update({
            "kind": "vector", "text": text, "raw": text,
            "element_counts": dict(sorted(tags.items())),
            "viewBox": vb.group(1) if vb else None,
            "width": wh[0].group(1) if wh[0] else None,
            "height": wh[1].group(1) if wh[1] else None,
        })
        return obj

    def create(self, object_type=ObjectType.IMAGE, params=None) -> UniversalObject:
        p = params or {}
        size = int(p.get("size", 128))
        svg = p.get("text") or (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
            f'viewBox="0 0 {size} {size}">'
            f'<rect width="{size}" height="{size}" fill="#101828"/>'
            f'<circle cx="{size/2}" cy="{size/2}" r="{size/3}" fill="#38bdf8"/>'
            f'<text x="{size/2}" y="{size/2+4}" text-anchor="middle" '
            f'font-family="monospace" font-size="{max(8, size//8)}" fill="#101828">SFP</text></svg>')
        return self.read(svg.encode(), p.get("filename", "created.svg"), None)

    def edit(self, obj, op, params=None):
        if op == "set_text":
            text = str((params or {}).get("text", ""))
            obj.content["text"] = text
            obj.content["raw"] = text
            obj.content["edited_bytes"] = {"__blob__": obj.add_blob(text.encode("utf-8"))}
            obj.record("edit.set_text", "SVG source replaced")
            return obj
        raise UnsafeInputError(f"svg adapter: unsupported edit {op!r}")

    def encode(self, obj, fmt) -> bytes:
        if fmt == "svg":
            got = obj.get_blob(obj.content.get("edited_bytes"))
            return got if got is not None else obj.content.get("raw", "").encode("utf-8")
        raise UnsafeInputError("svg adapter only encodes svg")

    def export_formats(self, obj) -> list:
        out = [opt("svg", "SVG (.svg)", ConversionKind.LOSSLESS, "native format")]
        if HAS_PIL:
            out.append(opt("png", "PNG image (.png)", ConversionKind.RENDERED,
                           "rasterised by Pillow's SVG-less path is NOT available — use browser render"))
        out.append(opt("txt", "SVG source (.txt)", ConversionKind.STRUCTURAL, "source text"))
        out.append(opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                       "UniversalObject graph incl. original bytes"))
        return out

    def export(self, obj, fmt):
        stem = (obj.original_filename or "object").rsplit(".", 1)[0]
        if fmt == "svg":
            return ExportResult(self.encode(obj, "svg"), stem + ".svg", "image/svg+xml",
                                ConversionKind.LOSSLESS.value)
        if fmt == "txt":
            return ExportResult(self.encode(obj, "svg"), stem + ".txt", "text/plain",
                                ConversionKind.STRUCTURAL.value)
        if fmt == "png":
            raise UnsafeInputError(
                "SVG → PNG rasterisation is not implemented server-side (Pillow cannot render SVG). "
                "The UI can render SVG via the browser and capture it (RENDERED).")
        raise UnsafeInputError(f"svg adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = obj.content.get("element_counts", {})
        return rep


def _gif_frame_to_child(obj: UniversalObject, index: int) -> UniversalObject:
    """Build a standalone IMAGE child from one GIF frame (used by transform)."""
    frames = obj.content.get("frames", [])
    fr = frames[index]
    w, h = int(fr["w"]), int(fr["h"])
    # frame blob is full-canvas compositing; crop to frame box when it is smaller
    canvas_w, canvas_h = int(obj.content["width"]), int(obj.content["height"])
    src = obj.get_blob(fr["pixels"]) or b""
    if (w, h) == (canvas_w, canvas_h):
        pixels = src
    else:
        from ..codecs.imageops import crop_rgba
        x, y = int(fr["x"]), int(fr["y"])
        full = obj.get_blob(fr["pixels"])
        # fr["pixels"] stored as full-canvas composite in _read_gif
        pixels = crop_rgba(full, canvas_w, canvas_h, x, y, w, h)
    png = png_codec.encode_from_rgba(pixels, w, h)
    child = UniversalObject(
        object_type=ObjectType.IMAGE,
        original_filename=f"{obj.original_filename or 'anim'}_frame{index}.png",
        original_extension="png",
        detected_format="png",
        mime="image/png",
        size=len(png),
        original_bytes=png,
        checksum=sha256(png),
        support_level=SupportLevel.FULL,
    )
    child.content = {"kind": "image", "width": w, "height": h, "mode": "RGBA",
                     "pixels": child.blob_ref(pixels)}
    child.record("transform", f"extracted from {obj.original_filename} frame {index}",
                 ConversionKind.LOSSLESS)
    child.adapter_name = "image"
    child.adapter_version = RasterAdapter.version
    return child


def _fmt_from_name(name: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return {"jpg": "jpeg", "jpeg": "jpeg", "tif": "tiff", "tiff": "tiff",
            "png": "png", "bmp": "bmp", "gif": "gif", "webp": "webp"}.get(ext, "png")


ADAPTERS = [RasterAdapter(), SvgAdapter()]

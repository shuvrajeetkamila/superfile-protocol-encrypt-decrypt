"""
SUPERFILE — WORKED EXAMPLE: adding a NEW FORMAT via an adapter
==============================================================

This file teaches the plugin API by supporting a format that the core does
NOT ship with: **PPM** (Netpbm portable pixmap, P3/P6).

Copy this file into the ``plugins/`` directory (or any path listed in
``SUPERFILE_PLUGIN_DIR``) and SUPERFILE can immediately import, create,
edit-via-transform, inspect and export PPM images — without touching the
protocol, the object model or the UI.

    cp examples/new_format_adapter/ppm_adapter.py plugins/ppm_adapter.py

Everything an adapter must declare is marked STEP 1 … STEP 6.

(There is also a full walk-through in docs/ADAPTER_API.md.)
"""

from __future__ import annotations

# STEP 1 — import the adapter contract and object model.
from superfile.adapters.base import FormatAdapter, FormatSpec, ExportResult, opt
from superfile.object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from superfile.security import UnsafeInputError, sha256


# STEP 2 — implement the adapter: one class per format family.
class PpmAdapter(FormatAdapter):
    """PPM (Netpbm pixmap P3 ascii / P6 binary) — FULL SUPPORT example."""

    # -- STEP 2a: identity + manifest fields -------------------------------
    name = "ppm"
    version = "1.0"

    # -- STEP 2b: the format registry entries this adapter provides --------
    formats = {
        "ppm": FormatSpec(
            format_id="ppm",
            display="PPM image (Netpbm)",
            extensions=["ppm"],
            mime="image/x-portable-pixmap",
            category="IMAGE",
            support=SupportLevel.FULL,      # be truthful: we really do all verbs
            read=True, create=True, edit=True, export=True,
            detection="text-heuristic",     # P3/P6 magic words
            notes="example adapter demonstrating the SUPERFILE plugin API",
        ),
    }

    # -- STEP 2c: advertise capabilities per format ------------------------
    capabilities = {
        "ppm": {"detect", "read", "parse", "decode", "create", "edit",
                "encode", "export", "inspect"},
    }

    # -- STEP 2d: object types in/out --------------------------------------
    input_types = [ObjectType.IMAGE]
    output_types = [ObjectType.IMAGE]

    # ------------------------------------------------------------------
    # STEP 3 — implement the verbs you advertise.  Anything you do NOT
    # override raises NotImplementedError — honest by construction.
    # ------------------------------------------------------------------
    def detect(self, data: bytes, filename: str = "") -> float:
        """Confidence 0..1 that these bytes are ours (magic words P3/P6)."""
        head = data[:2]
        if head in (b"P3", b"P6") and len(data) > 3 and data[2:3] in (b" ", b"\n", b"\t"):
            return 0.95
        return 0.0

    def read(self, data: bytes, filename: str = "", detection=None) -> UniversalObject:
        obj = UniversalObject(
            object_type=ObjectType.IMAGE,
            original_filename=filename or "image.ppm",
            original_extension="ppm",
            detected_format="ppm",
            mime="image/x-portable-pixmap",
            size=len(data),
            original_bytes=data,          # LOSSLESS-PRESERVATION: keep the source bytes
            checksum=sha256(data),
            support_level=SupportLevel.FULL,
        )
        pixels, width, height, variant = self._decode(data)
        # decoded RGBA pixels go into a blob; content stays JSON-safe
        obj.content = {
            "kind": "image",
            "width": width, "height": height, "mode": "RGBA",
            "variant": variant,
            "pixels": obj.blob_ref(pixels),
        }
        obj.adapter_name = self.name
        obj.adapter_version = self.version
        obj.capabilities = sorted(self.caps("ppm"))
        obj.export_formats = self.export_formats(obj)
        obj.record("import", f"imported PPM ({variant}) {width}x{height}")
        return obj

    def create(self, object_type=None, params: dict | None = None) -> UniversalObject:
        """Create a small two-tone checker image."""
        p = params or {}
        w = int(p.get("width", 32))
        h = int(p.get("height", 32))
        pixels = bytearray()
        for y in range(h):
            for x in range(w):
                on = ((x // 4) + (y // 4)) % 2 == 0
                pixels += bytes((30, 120, 220, 255) if on else (240, 240, 240, 255))
        raw = self._encode_p6(bytes(pixels), w, h)
        obj = self.read(raw, p.get("filename", "created.ppm"))
        obj.record("create", f"generated {w}x{h} checker", ConversionKind.RECONSTRUCTED)
        return obj

    def edit(self, obj: UniversalObject, op: str, params: dict | None = None) -> UniversalObject:
        """Optional: simple edit verbs.  Image maths normally goes through
        the transform engine (image.resize etc. work on any RGBA image)."""
        if op == "set_pixel":
            p = params or {}
            return self._set_pixel(obj, int(p.get("x", 0)), int(p.get("y", 0)),
                                  tuple(p.get("rgba", (255, 0, 0, 255))))
        raise UnsafeInputError(f"ppm adapter: unsupported edit op {op!r}")

    def encode(self, obj: UniversalObject, fmt: str) -> bytes:
        if fmt != "ppm":
            raise UnsafeInputError(f"ppm adapter cannot encode {fmt!r}")
        pixels = obj.get_blob(obj.content.get("pixels"))
        if pixels is None:
            raise UnsafeInputError("no decoded pixels")
        return self._encode_p6(pixels, int(obj.content["width"]), int(obj.content["height"]))

    # ------------------------------------------------------------------
    # STEP 4 — export matrix: list ONLY real conversions.
    # ------------------------------------------------------------------
    def export_formats(self, obj) -> list:
        return [
            opt("ppm", "PPM image (.ppm)", ConversionKind.LOSSLESS,
                "P6 binary pixmap (alpha flattened)"),
            opt("png", "PNG image (.png)", ConversionKind.LOSSLESS,
                "via core raster adapter"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "object graph + original bytes"),
        ]

    def export(self, obj: UniversalObject, fmt: str) -> ExportResult:
        stem = (obj.original_filename or "image").rsplit(".", 1)[0]
        if fmt == "ppm":
            return ExportResult(self.encode(obj, "ppm"), stem + ".ppm",
                                "image/x-portable-pixmap",
                                ConversionKind.LOSSLESS.value)
        if fmt == "png":
            from superfile.codecs import png as png_codec
            pixels = obj.get_blob(obj.content.get("pixels"))
            data = png_codec.encode_from_rgba(pixels, int(obj.content["width"]),
                                              int(obj.content["height"]))
            return ExportResult(data, stem + ".png", "image/png",
                                ConversionKind.LOSSLESS.value,
                                "cross-adapter export via core PNG codec")
        raise UnsafeInputError(f"ppm adapter cannot export {fmt!r}")

    # ------------------------------------------------------------------
    # STEP 5 — inspection report (GENERAL / STRUCTURE / FORMAT sections).
    # ------------------------------------------------------------------
    def inspect(self, obj: UniversalObject) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "width": obj.content.get("width"),
            "height": obj.content.get("height"),
            "variant": obj.content.get("variant"),
            "mode": obj.content.get("mode"),
        }
        rep["format"]["note"] = "example plugin adapter — see examples/new_format_adapter/"
        return rep

    # ------------------------------------------------------------------
    # STEP 6 — private format internals stay inside the adapter.
    # ------------------------------------------------------------------
    def _decode(self, data: bytes):
        variant = data[:2].decode("ascii", "replace")
        if variant not in ("P3", "P6"):
            raise UnsafeInputError("not a PPM file (expected P3/P6)")
        # token scan: width, height, maxval (comments allowed)
        pos = 2
        tokens = []
        while len(tokens) < 3 and pos < len(data):
            ch = data[pos:pos + 1]
            if ch in b" \t\r\n":
                pos += 1
                continue
            if ch == b"#":
                while pos < len(data) and data[pos] != 0x0A:
                    pos += 1
                continue
            start = pos
            while pos < len(data) and data[pos] not in b" \t\r\n":
                pos += 1
            tokens.append(data[start:pos])
        width, height, maxval = (int(t) for t in tokens)
        if width <= 0 or height <= 0 or width * height > 40_000_000:
            raise UnsafeInputError("unreasonable PPM dimensions")
        rgba = bytearray(width * height * 4)
        if variant == "P6":
            pos += 1  # exactly one whitespace after maxval
            need = width * height * 3
            raw = data[pos:pos + need]
            if len(raw) < need * (2 if maxval > 255 else 1):
                raise UnsafeInputError("PPM pixel data truncated")
            step = 2 if maxval > 255 else 1
            for i in range(width * height):
                o = i * 3 * step
                if step == 2:
                    r = (raw[o] << 8 | raw[o + 1]) * 255 // maxval
                    g = (raw[o + 2] << 8 | raw[o + 3]) * 255 // maxval
                    b = (raw[o + 4] << 8 | raw[o + 5]) * 255 // maxval
                else:
                    r, g, b = raw[o] * 255 // maxval, raw[o + 1] * 255 // maxval, raw[o + 2] * 255 // maxval
                rgba[i * 4:i * 4 + 4] = bytes((r, g, b, 255))
        else:  # P3 ascii
            vals = data[pos:].split()
            need = width * height * 3
            if len(vals) < need:
                raise UnsafeInputError("PPM pixel data truncated")
            scale = 255 / maxval
            for i in range(width * height):
                r, g, b = (int(vals[i * 3 + k]) * scale for k in range(3))
                rgba[i * 4:i * 4 + 4] = bytes((int(r), int(g), int(b), 255))
        return bytes(rgba), width, height, variant

    def _encode_p6(self, rgba: bytes, width: int, height: int) -> bytes:
        out = bytearray(f"P6\n{width} {height}\n255\n".encode())
        for i in range(width * height):
            out += rgba[i * 4:i * 4 + 3]     # drop alpha (PPM has none)
        return bytes(out)

    def _set_pixel(self, obj, x, y, rgba):
        w, h = int(obj.content["width"]), int(obj.content["height"])
        if not (0 <= x < w and 0 <= y < h):
            raise UnsafeInputError("pixel out of bounds")
        buf = bytearray(obj.get_blob(obj.content["pixels"]))
        i = (y * w + x) * 4
        buf[i:i + 4] = bytes(rgba[:4])
        obj.content["pixels"] = obj.blob_ref(bytes(buf))
        obj.record("edit.set_pixel", f"pixel ({x},{y}) = {tuple(rgba[:4])}",
                   ConversionKind.LOSSY if rgba[3] != 255 else ConversionKind.LOSSLESS)
        return obj


# STEP 7 — export ADAPTERS for the plugin loader.
# (Alternatively define a `register(registry)` function.)
ADAPTERS = [PpmAdapter()]

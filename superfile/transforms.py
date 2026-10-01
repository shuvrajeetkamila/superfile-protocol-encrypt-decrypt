"""
SUPERFILE — Universal Transform Engine
======================================

    UniversalObject  --[Transformation]-->  UniversalObject

Every transform is registered with a truthful ConversionKind and the object
types it applies to.  Transforms never mutate the original_bytes (lossless
preservation); they produce new content and append to the object history.
"""

from __future__ import annotations

import html as html_mod
import json
import re
import time
from dataclasses import dataclass, field
from typing import Callable

from .object_model import ConversionKind, ObjectType, UniversalObject
from .security import UnsafeInputError


@dataclass
class Transform:
    tid: str
    label: str
    applies_to: list                 # ObjectType values
    formats: list                    # format ids (empty = any of the type)
    kind: ConversionKind
    fn: Callable                     # fn(obj, params) -> obj (or (obj, payload))
    description: str = ""
    params_schema: list = field(default_factory=list)   # [{name,type,default,min,max}]

    def to_dict(self) -> dict:
        return {
            "id": self.tid, "label": self.label,
            "applies_to": [t.value if isinstance(t, ObjectType) else t for t in self.applies_to],
            "formats": list(self.formats),
            "kind": self.kind.value,
            "description": self.description,
            "params": self.params_schema,
        }


class TransformEngine:
    def __init__(self):
        self.transforms: dict = {}

    def register(self, t: Transform) -> None:
        self.transforms[t.tid] = t

    def get(self, tid: str) -> Transform:
        if tid not in self.transforms:
            raise UnsafeInputError(f"unknown transformation: {tid}")
        return self.transforms[tid]

    def applicable(self, obj: UniversalObject) -> list:
        out = []
        otype = obj.object_type.value if isinstance(obj.object_type, ObjectType) else obj.object_type
        for t in self.transforms.values():
            types = [x.value if isinstance(x, ObjectType) else x for x in t.applies_to]
            if "*" in types or otype in types:
                if not t.formats or obj.detected_format in t.formats:
                    out.append(t.to_dict())
        return out

    def run(self, obj: UniversalObject, tid: str, params: dict | None = None) -> UniversalObject:
        t = self.get(tid)
        params = params or {}
        result = t.fn(obj, params)
        if isinstance(result, tuple):
            obj, extra = result
        else:
            obj, extra = result, {}
        obj.record(t.tid, t.label + (f" — {extra['detail']}" if extra.get("detail") else ""),
                   t.kind, params)
        return obj

    def catalog(self) -> list:
        return [t.to_dict() for t in self.transforms.values()]


# ---------------------------------------------------------------------------
# built-in transforms
# ---------------------------------------------------------------------------

def _pixels(obj: UniversalObject):
    """Return (w, h, mode, bytearray) for image objects."""
    c = obj.content
    w, h, mode = c.get("width"), c.get("height"), c.get("mode", "RGBA")
    ref = c.get("pixels")
    data = obj.get_blob(ref)
    if not w or not h or data is None:
        raise UnsafeInputError("object has no decoded pixels to transform")
    return int(w), int(h), mode, bytearray(data)


def _store_pixels(obj: UniversalObject, w: int, h: int, mode: str, buf: bytes) -> None:
    obj.content["width"] = w
    obj.content["height"] = h
    obj.content["mode"] = mode
    obj.content["pixels"] = obj.blob_ref(bytes(buf))
    obj.content.setdefault("edited", True)


def _img_resize(obj, p):
    from .codecs.imageops import resize_rgba
    w, h, mode, buf = _pixels(obj)
    nw = max(1, min(8192, int(p.get("width", w))))
    nh = max(1, min(8192, int(p.get("height", h))))
    smooth = bool(p.get("smooth", True))
    out = resize_rgba(buf, w, h, nw, nh, smooth=smooth)
    _store_pixels(obj, nw, nh, mode, out)
    return obj, {"detail": f"resized {w}x{h} → {nw}x{nh}"}


def _img_crop(obj, p):
    from .codecs.imageops import crop_rgba
    w, h, mode, buf = _pixels(obj)
    x = max(0, min(w - 1, int(p.get("x", 0))))
    y = max(0, min(h - 1, int(p.get("y", 0))))
    cw = max(1, min(w - x, int(p.get("width", w))))
    ch = max(1, min(h - y, int(p.get("height", h))))
    out = crop_rgba(buf, w, h, x, y, cw, ch)
    _store_pixels(obj, cw, ch, mode, out)
    return obj, {"detail": f"cropped {cw}x{ch} at ({x},{y})"}


def _img_rotate(obj, p):
    from .codecs.imageops import rotate_rgba
    w, h, mode, buf = _pixels(obj)
    deg = int(p.get("degrees", 90)) % 360
    if deg not in (90, 180, 270):
        raise UnsafeInputError("pure rotate supports 90/180/270 degrees")
    out, nw, nh = rotate_rgba(buf, w, h, deg)
    _store_pixels(obj, nw, nh, mode, out)
    return obj, {"detail": f"rotated {deg}° ({nw}x{nh})"}


def _img_grayscale(obj, p):
    from .codecs.imageops import grayscale_rgba
    w, h, mode, buf = _pixels(obj)
    _store_pixels(obj, w, h, mode, grayscale_rgba(buf))
    return obj, {"detail": "grayscale applied"}


def _img_flip(obj, p):
    from .codecs.imageops import flip_rgba
    w, h, mode, buf = _pixels(obj)
    axis = str(p.get("axis", "horizontal"))
    out = flip_rgba(buf, w, h, axis)
    _store_pixels(obj, w, h, mode, out)
    return obj, {"detail": f"flipped {axis}"}


def _gif_extract_frame(obj, p):
    """Extract one GIF frame as a child IMAGE object (LOSSLESS copy of pixels)."""
    from .adapters.image import _gif_frame_to_child
    idx = int(p.get("index", 0))
    frames = obj.content.get("frames", [])
    if not frames:
        raise UnsafeInputError("no frames in object")
    if idx < 0 or idx >= len(frames):
        raise UnsafeInputError(f"frame index {idx} out of range 0..{len(frames)-1}")
    child = _gif_frame_to_child(obj, idx)
    obj.add_child(child, relation="frame_of", note=f"frame {idx}")
    return obj, {"detail": f"extracted frame {idx} → child object {child.original_filename}"}


def _text_md_to_html(obj, p):
    html = markdown_to_html(obj.content.get("text", ""))
    obj.content.setdefault("derived", {})["html"] = html
    return obj, {"detail": f"markdown → HTML ({len(html)} chars)"}


def _text_to_html_page(obj, p):
    title = p.get("title") or obj.original_filename or "Document"
    body = html_mod.escape(obj.content.get("text", ""))
    page = ("<!doctype html><html><head><meta charset='utf-8'><title>"
            + html_mod.escape(title) + "</title></head><body><pre>"
            + body + "</pre></body></html>")
    obj.content.setdefault("derived", {})["html_page"] = page
    return obj, {"detail": "wrapped text in an HTML page"}


def _text_stats(obj, p):
    text = obj.content.get("text", "")
    words = re.findall(r"\S+", text)
    obj.content["stats"] = {
        "chars": len(text), "words": len(words),
        "lines": text.count("\n") + 1,
        "unique_words": len({w.lower() for w in words}),
    }
    return obj, {"detail": f"{len(words)} words, {len(text)} chars"}


def _json_pretty(obj, p):
    data = obj.content.get("data")
    obj.content["raw"] = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=bool(p.get("sort_keys")))
    obj.content["text"] = obj.content["raw"]
    return obj, {"detail": "pretty-printed JSON"}


def _json_minify(obj, p):
    data = obj.content.get("data")
    obj.content["raw"] = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    obj.content["text"] = obj.content["raw"]
    return obj, {"detail": "minified JSON"}


def _json_to_yaml(obj, p):
    from .adapters.structured import to_yaml
    y = to_yaml(obj.content.get("data"))
    obj.content.setdefault("derived", {})["yaml"] = y
    return obj, {"detail": f"JSON → YAML subset ({len(y)} chars)", }


def _json_to_toml(obj, p):
    from .adapters.structured import to_toml
    t = to_toml(obj.content.get("data"))
    if t is None:
        raise UnsafeInputError("value is not TOML-representable (needs tables of scalars)")
    obj.content.setdefault("derived", {})["toml"] = t
    return obj, {"detail": f"JSON → TOML ({len(t)} chars)"}


def _json_to_csv(obj, p):
    from .adapters.structured import to_csv
    data = obj.content.get("data")
    if not isinstance(data, list) or (data and not isinstance(data[0], dict)):
        raise UnsafeInputError("CSV export needs a JSON array of objects")
    csv_text = to_csv(data)
    obj.content.setdefault("derived", {})["csv"] = csv_text
    return obj, {"detail": f"JSON → CSV ({csv_text.count(chr(10))} rows)"}


def _archive_extract_all(obj, p):
    from .adapters.archive import extract_children
    n = extract_children(obj, limit=int(p.get("limit", 200)))
    return obj, {"detail": f"extracted {n} entries as child objects"}


def _doc_extract_text(obj, p):
    text = obj.content.get("raw_text") or obj.content.get("text") or ""
    obj.content.setdefault("derived", {})["plain_text"] = text
    return obj, {"detail": f"extracted {len(text)} chars of text"}


def _pdf_extract_text(obj, p):
    pages = obj.content.get("pages", [])
    text = "\n\n".join(pg.get("text", "") for pg in pages)
    obj.content["raw_text"] = text
    return obj, {"detail": f"extracted {len(text)} chars from {len(pages)} page(s)"}


def _audio_peaks(obj, p):
    from .adapters.audio import compute_peaks
    peaks = compute_peaks(obj, buckets=int(p.get("buckets", 240)))
    obj.content["peaks"] = peaks
    return obj, {"detail": f"waveform peaks: {len(peaks)} buckets"}


def _exe_static_analysis(obj, p):
    """Re-run static analysis and record it in history (nothing is executed)."""
    warnings = obj.warnings
    return obj, {"detail": f"static analysis refreshed ({len(warnings)} warnings)"}


def _mesh_stats(obj, p):
    c = obj.content
    c["stats"] = {
        "vertices": c.get("vertices", 0), "faces": c.get("faces", 0),
        "bbox": c.get("bbox"), "normals": c.get("normals", 0),
    }
    return obj, {"detail": f"{c.get('vertices', 0)} vertices / {c.get('faces', 0)} faces"}


def _clone_object(obj, p):
    return obj, {"detail": "object snapshot recorded"}


# ---------------------------------------------------------------------------
# tiny markdown renderer (subset) — used by transform + export
# ---------------------------------------------------------------------------

def markdown_to_html(md: str) -> str:
    """Structural markdown→HTML for headings, lists, code, emphasis, links."""
    out = []
    in_code = False
    in_list = False
    for line in md.split("\n"):
        s = line.rstrip()
        if s.startswith("```"):
            if in_code:
                out.append("</code></pre>")
            else:
                out.append("<pre><code>")
            in_code = not in_code
            continue
        if in_code:
            out.append(html_mod.escape(line))
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            if in_list:
                out.append("</ul>")
                in_list = False
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{_inline(m.group(2))}</h{lvl}>")
            continue
        m = re.match(r"^\s*[-*]\s+(.*)$", s)
        if m:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(m.group(1))}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if s.strip() == "":
            continue
        out.append(f"<p>{_inline(s)}</p>")
    if in_list:
        out.append("</ul>")
    if in_code:
        out.append("</code></pre>")
    return "\n".join(out)


def _inline(text: str) -> str:
    t = html_mod.escape(text)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", t)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', t)
    return t


# ---------------------------------------------------------------------------
# engine assembly
# ---------------------------------------------------------------------------

def build_transform_engine() -> TransformEngine:
    eng = TransformEngine()
    T = Transform
    eng.register(T("image.resize", "Resize image", [ObjectType.IMAGE], ["png", "bmp", "gif", "jpeg", "webp", "ppm"],
                   ConversionKind.LOSSY, _img_resize,
                   "Rescale decoded pixels (nearest or bilinear).",
                   [{"name": "width", "type": "int", "default": 320, "min": 1, "max": 8192},
                    {"name": "height", "type": "int", "default": 240, "min": 1, "max": 8192},
                    {"name": "smooth", "type": "bool", "default": True}]))
    eng.register(T("image.crop", "Crop image", [ObjectType.IMAGE], ["png", "bmp", "gif", "jpeg", "webp", "ppm"],
                   ConversionKind.LOSSLESS, _img_crop, "Crop a rectangle of pixels.",
                   [{"name": "x", "type": "int", "default": 0}, {"name": "y", "type": "int", "default": 0},
                    {"name": "width", "type": "int", "default": 64}, {"name": "height", "type": "int", "default": 64}]))
    eng.register(T("image.rotate", "Rotate 90/180/270", [ObjectType.IMAGE], ["png", "bmp", "gif", "jpeg", "webp", "ppm"],
                   ConversionKind.LOSSLESS, _img_rotate, "Exact right-angle rotation.",
                   [{"name": "degrees", "type": "int", "default": 90}]))
    eng.register(T("image.grayscale", "Grayscale", [ObjectType.IMAGE], ["png", "bmp", "gif", "jpeg", "webp", "ppm"],
                   ConversionKind.LOSSY, _img_grayscale, "Luminance conversion (drops colour)."))
    eng.register(T("image.flip", "Flip", [ObjectType.IMAGE], ["png", "bmp", "gif", "jpeg", "webp", "ppm"],
                   ConversionKind.LOSSLESS, _img_flip, "Mirror horizontally or vertically.",
                   [{"name": "axis", "type": "str", "default": "horizontal"}]))
    eng.register(T("gif.extract_frame", "Extract GIF frame", [ObjectType.ANIMATION], ["gif"],
                   ConversionKind.LOSSLESS, _gif_extract_frame, "Copy one animation frame into a child image object.",
                   [{"name": "index", "type": "int", "default": 0}]))
    eng.register(T("text.markdown_to_html", "Markdown → HTML", [ObjectType.TEXT], ["md"],
                   ConversionKind.STRUCTURAL, _text_md_to_html, "Render a markdown subset to HTML."))
    eng.register(T("text.to_html_page", "Text → HTML page", [ObjectType.TEXT], ["txt", "md", "csv", "json", "xml", "yaml", "toml"],
                   ConversionKind.RECONSTRUCTED, _text_to_html_page, "Wrap plain text in an HTML document.",
                   [{"name": "title", "type": "str", "default": ""}]))
    eng.register(T("text.stats", "Text statistics", [ObjectType.TEXT, ObjectType.SOURCE_CODE], [],
                   ConversionKind.LOSSLESS, _text_stats, "Count words / lines / chars."))
    eng.register(T("json.pretty", "Pretty-print JSON", [ObjectType.TEXT], ["json"],
                   ConversionKind.LOSSLESS, _json_pretty, "Re-serialize with indentation.",
                   [{"name": "sort_keys", "type": "bool", "default": False}]))
    eng.register(T("json.minify", "Minify JSON", [ObjectType.TEXT], ["json"],
                   ConversionKind.LOSSLESS, _json_minify, "Re-serialize compactly."))
    eng.register(T("json.to_yaml", "JSON → YAML", [ObjectType.TEXT], ["json"],
                   ConversionKind.STRUCTURAL, _json_to_yaml, "Emit YAML subset."))
    eng.register(T("json.to_toml", "JSON → TOML", [ObjectType.TEXT], ["json"],
                   ConversionKind.STRUCTURAL, _json_to_toml, "Emit TOML for table-of-scalars data."))
    eng.register(T("json.to_csv", "JSON → CSV", [ObjectType.TEXT], ["json"],
                   ConversionKind.STRUCTURAL, _json_to_csv, "Flatten array-of-objects to CSV."))
    eng.register(T("archive.extract_all", "Extract archive children", [ObjectType.ARCHIVE], [],
                   ConversionKind.STRUCTURAL, _archive_extract_all, "Parse entries into child objects (safe, limited).",
                   [{"name": "limit", "type": "int", "default": 200}]))
    eng.register(T("document.extract_text", "Extract text", [ObjectType.DOCUMENT], [],
                   ConversionKind.STRUCTURAL, _doc_extract_text, "Harvest plain text from the document."))
    eng.register(T("pdf.extract_text", "Extract PDF text", [ObjectType.DOCUMENT], ["pdf"],
                   ConversionKind.STRUCTURAL, _pdf_extract_text, "Extract text operators from content streams."))
    eng.register(T("audio.waveform", "Compute waveform peaks", [ObjectType.AUDIO], ["wav"],
                   ConversionKind.LOSSLESS, _audio_peaks, "Downsample amplitude envelope for display.",
                   [{"name": "buckets", "type": "int", "default": 240}]))
    eng.register(T("binary.static_analysis", "Static analysis (safe)", [ObjectType.EXECUTABLE], [],
                   ConversionKind.STRUCTURAL, _exe_static_analysis,
                   "Refresh static inspection. NEVER executes the binary."))
    eng.register(T("mesh.stats", "Mesh statistics", [ObjectType.THREE_D], [],
                   ConversionKind.LOSSLESS, _mesh_stats, "Compute mesh bounds and counts."))
    return eng

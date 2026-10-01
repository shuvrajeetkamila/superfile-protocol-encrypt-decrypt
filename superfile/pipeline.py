"""
SUPERFILE — Pipeline: the universal import/detect/parse/export orchestrator.

    FILE → FORMAT DETECTION → FORMAT ADAPTER → UNIVERSAL OBJECT
         → OBJECT GRAPH → TRANSFORMATION → EXPORT ADAPTER → TARGET FILE

This module is the ONLY place that wires detection + adapters + transforms
together.  The UI and protocol never branch on format names.
"""

from __future__ import annotations

import json
import os
import time

from . import detection as det_mod
from . import crypto
from . import protocol
from .adapters.base import ExportResult
from .object_model import (
    ConversionKind, ExportOption, ObjectType, SupportLevel, UniversalObject,
)
from .registry import FormatRegistry, build_registry
from .security import LIMITS, UnsafeInputError, sha256
from .transforms import TransformEngine, build_transform_engine

# ---------------------------------------------------------------------------
# shared engine singletons (adapters are stateless)
# ---------------------------------------------------------------------------

_registry: FormatRegistry | None = None
_transforms: TransformEngine | None = None


def get_registry() -> FormatRegistry:
    global _registry
    if _registry is None:
        plugin_dir = os.environ.get("SUPERFILE_PLUGIN_DIR",
                                    os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                                 "plugins"))
        _registry = build_registry(plugin_dir)
    return _registry


def get_transforms() -> TransformEngine:
    global _transforms
    if _transforms is None:
        _transforms = build_transform_engine()
    return _transforms


def reset_engines() -> None:
    """Test helper: force re-creation of the singletons."""
    global _registry, _transforms
    _registry = None
    _transforms = None


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------

def import_bytes(name: str, data: bytes, detection=None) -> UniversalObject:
    """Detect + parse bytes into a UniversalObject (never executes anything)."""
    if len(data) > LIMITS.max_file_bytes:
        raise UnsafeInputError(
            f"file exceeds import limit of {LIMITS.max_file_bytes} bytes")
    det = detection or det_mod.detect_format(data, name)

    reg = get_registry()
    adapter = reg.adapter_for(det.format_id)
    if adapter is None:
        # fall back to blob adapter — honest 'unknown binary'
        adapter = reg.adapter_for("blob")
        det = det_mod.Detection("blob", "Unknown binary", "application/octet-stream",
                                det.extension, 0.3, det.method,
                                f"no adapter for {det.format_id} — preserved as bytes", "BINARY")

    # adapters may confirm detection (raise confidence)
    try:
        conf = adapter.detect(data, name)
        if conf and conf > det.confidence:
            det.confidence = min(0.99, conf)
    except Exception:
        pass

    obj = adapter.read(data, name, det)
    obj.metadata.setdefault("detection", det.to_dict())
    obj.metadata.setdefault("pipeline", {})["adapter"] = adapter.name
    obj.size = obj.size or len(data)
    if not obj.checksum:
        obj.checksum = sha256(data)
    if not obj.capabilities:
        obj.capabilities = sorted(adapter.caps(det.format_id))
    if not obj.export_formats:
        obj.export_formats = [o for o in adapter.export_formats(obj)
                              if isinstance(o, ExportOption) or isinstance(o, dict)]
        obj.export_formats = [o if isinstance(o, ExportOption) else ExportOption(**o)
                              for o in obj.export_formats]
    # always be able to save as SUPERFILE
    if not any(o.format == "sfp" for o in obj.export_formats):
        obj.export_formats.append(ExportOption(
            format="sfp", label="SUPERFILE container (.sfp)",
            kind=ConversionKind.LOSSLESS.value,
            notes="full object graph + original bytes"))
    if not obj.transformations:
        obj.record("import", f"detected {det.format_id} ({det.confidence:.0%} via {det.method})")
    return obj


def import_file(path: str) -> UniversalObject:
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise UnsafeInputError(f"not a file: {path}")
    size = os.path.getsize(path)
    if size > LIMITS.max_file_bytes:
        raise UnsafeInputError(f"file exceeds import limit ({size} bytes)")
    with open(path, "rb") as fh:
        data = fh.read(LIMITS.max_file_bytes + 1)
    return import_bytes(os.path.basename(path), data)


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

CREATOR_TARGETS = [
    {"id": "text", "label": "Create Text", "formats": ["txt", "md", "csv"],
     "object_type": "TEXT"},
    {"id": "json", "label": "Create JSON", "formats": ["json"],
     "object_type": "TEXT"},
    {"id": "yaml_toml", "label": "Create structured data", "formats": ["yaml", "toml"],
     "object_type": "TEXT"},
    {"id": "image", "label": "Create Image", "formats": ["png"],
     "object_type": "IMAGE"},
    {"id": "svg", "label": "Create SVG", "formats": ["svg"],
     "object_type": "IMAGE"},
    {"id": "animation", "label": "Create basic animation", "formats": ["gif"],
     "object_type": "ANIMATION"},
    {"id": "audio", "label": "Create audio tone (WAV)", "formats": ["wav"],
     "object_type": "AUDIO"},
    {"id": "archive", "label": "Create ZIP / archive", "formats": ["zip", "tar"],
     "object_type": "ARCHIVE"},
    {"id": "html", "label": "Create simple HTML", "formats": ["html"],
     "object_type": "TEXT"},
    {"id": "source", "label": "Create source-code file", "formats": ["python", "javascript",
                                                                     "c", "java", "rust",
                                                                     "go", "csharp", "css"],
     "object_type": "SOURCE_CODE"},
    {"id": "mesh", "label": "Create 3D object", "formats": ["obj", "stl", "glb"],
     "object_type": "3D"},
    {"id": "pdf", "label": "Create PDF document", "formats": ["pdf"],
     "object_type": "DOCUMENT"},
    {"id": "docx", "label": "Create Word document", "formats": ["docx"],
     "object_type": "DOCUMENT"},
    {"id": "epub", "label": "Create EPUB book", "formats": ["epub"],
     "object_type": "DOCUMENT"},
    {"id": "project", "label": "Create Universal Object / SUPERFILE", "formats": ["sfp"],
     "object_type": "PROTOCOL"},
]


def create_object(kind: str, params: dict | None = None) -> UniversalObject:
    """Universal Creator — dispatch to the right adapter's create()."""
    p = dict(params or {})
    reg = get_registry()
    fmt = p.get("format")

    if kind == "animation":
        return _create_animation(p)
    if kind == "project" or (fmt == "sfp"):
        adapter = reg.adapter_for("sfp")
        obj = adapter.create(ObjectType.PROTOCOL, p)
        obj.export_formats = adapter.export_formats(obj)
        obj.capabilities = sorted(adapter.caps("sfp"))
        return _finalize_created(obj)
    if kind in ("text", "html") or (fmt in ("txt", "md", "csv", "html")):
        p.setdefault("format", "html" if kind == "html" else (fmt or "txt"))
        adapter = reg.adapter_by_any("html" if p["format"] == "html" else "text", "txt")
    elif kind in ("json", "yaml_toml") or (fmt in ("json", "yaml", "toml")):
        p.setdefault("format", fmt or ("json" if kind == "json" else "yaml"))
        adapter = reg.adapter_by_any("json" if p["format"] == "json" else "yaml-toml",
                                     p["format"])
    elif kind in ("image", "svg") or (fmt in ("png", "svg")):
        p.setdefault("format", fmt or ("svg" if kind == "svg" else "png"))
        adapter = reg.adapter_by_any("svg" if p["format"] == "svg" else "png", "image")
    elif kind == "audio":
        adapter = reg.adapter_by_any("wav", "audio")
    elif kind == "archive":
        p.setdefault("format", fmt or "zip")
        adapter = reg.adapter_by_any("zip" if p["format"] == "zip" else
                                     ("tar" if p["format"] == "tar" else "gzip"),
                                     p["format"])
    elif kind == "source":
        p.setdefault("format", fmt or "python")
        adapter = reg.adapter_by_any(p["format"], "source", "python")
    elif kind == "mesh":
        p.setdefault("format", fmt or "obj")
        adapter = reg.adapter_by_any({"glb": "gltf", "gltf": "gltf"}.get(p["format"],
                                                                        p["format"]),
                                     "obj", "stl", "gltf")
    elif kind == "pdf":
        adapter = reg.adapter_by_any("pdf")
    elif kind == "docx":
        adapter = reg.adapter_by_any("docx")
    elif kind == "epub":
        adapter = reg.adapter_by_any("epub")
    else:
        raise UnsafeInputError(f"unknown create kind: {kind!r}")
    if adapter is None:
        raise UnsafeInputError(f"no adapter available to create {kind!r}/{p.get('format')!r}")

    obj = adapter.create(None, p)
    obj.record("create", f"created via Universal Creator ({kind})",
               ConversionKind.RECONSTRUCTED)
    obj.export_formats = [o if isinstance(o, ExportOption) else ExportOption(**o)
                          for o in adapter.export_formats(obj)]
    if not any(o.format == "sfp" for o in obj.export_formats):
        obj.export_formats.append(ExportOption(
            "sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS.value,
            "full object graph + original bytes"))
    obj.capabilities = sorted(adapter.caps(obj.detected_format))
    _finalize_created(obj)
    return obj


def _finalize_created(obj: UniversalObject) -> UniversalObject:
    """Ensure created objects have a checksum (bytes hash, else content hash)."""
    if not obj.checksum:
        if obj.original_bytes is not None:
            obj.checksum = sha256(obj.original_bytes)
        else:
            canon = json.dumps(obj.content, sort_keys=True, ensure_ascii=False,
                               default=str).encode("utf-8")
            obj.checksum = sha256(canon)
            obj.metadata.setdefault("checksum_basis", "content-json")
    return obj


def _create_animation(p: dict) -> UniversalObject:
    """Procedural bouncing-box GIF animation (pure encoder)."""
    from .codecs import gif as gif_codec
    from .codecs import png as png_codec
    w = int(p.get("width", 96))
    h = int(p.get("height", 96))
    nframes = max(2, min(24, int(p.get("frames", 8))))
    frames = []
    delays = []
    for i in range(nframes):
        buf = bytearray(w * h * 4)
        for y in range(h):
            for x in range(w):
                idx = (y * w + x) * 4
                buf[idx:idx + 3] = b"\x10\x18\x28"
                buf[idx + 3] = 255
        t = i / max(1, nframes - 1)
        bx = int((w - 16) * abs(1 - 2 * t))
        by = int((h - 16) * (0.5 - 0.5 * (1 - 2 * t) ** 2) * 2)
        by = max(0, min(h - 16, by))
        for y in range(16):
            for x in range(16):
                idx = ((by + y) * w + (bx + x)) * 4
                buf[idx:idx + 3] = b"\x38\xbd\xf8"
        frames.append(bytes(buf))
        delays.append(60)
    data = gif_codec.encode_animation(frames, w, h, delays, loop=0)
    reg = get_registry()
    adapter = reg.adapter_for("gif")
    obj = adapter.read(data, p.get("filename", "created.gif"), None)
    obj.record("create", f"generated {nframes}-frame bouncing-box animation",
               ConversionKind.RECONSTRUCTED)
    obj.export_formats = [o if isinstance(o, ExportOption) else ExportOption(**o)
                          for o in adapter.export_formats(obj)]
    if not any(o.format == "sfp" for o in obj.export_formats):
        obj.export_formats.append(ExportOption(
            "sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS.value,
            "full object graph + original bytes"))
    obj.capabilities = sorted(adapter.caps("gif"))
    return _finalize_created(obj)


# ---------------------------------------------------------------------------
# edit / transform / export
# ---------------------------------------------------------------------------

def edit_object(obj: UniversalObject, op: str, params: dict | None = None) -> UniversalObject:
    reg = get_registry()
    adapter = reg.adapter_for(obj.detected_format)
    if adapter is None:
        raise UnsafeInputError(f"no adapter for {obj.detected_format}")
    return adapter.edit(obj, op, params)


def transform_object(obj: UniversalObject, tid: str, params: dict | None = None) -> UniversalObject:
    return get_transforms().run(obj, tid, params)


def export_object(obj: UniversalObject, fmt: str) -> ExportResult:
    if fmt == "sfp":
        data = protocol.dumps(obj)
        stem = (obj.original_filename or "object").rsplit(".", 1)[0]
        return ExportResult(data, f"{stem}.sfp", "application/x-superfile",
                            ConversionKind.LOSSLESS.value,
                            "SUPERFILE container: graph + original bytes + checksum")
    reg = get_registry()
    adapter = reg.adapter_for(obj.detected_format)
    if adapter is None:
        raise UnsafeInputError(f"no adapter for {obj.detected_format}")
    result = adapter.export(obj, fmt)
    obj.record(f"export:{fmt}", f"exported to {result.filename} [{result.kind}]",
               result.kind, {"format": fmt, "notes": result.notes})
    return result


# ---------------------------------------------------------------------------
# encryption (AES-256-GCM container encryption — see superfile/crypto.py)
# ---------------------------------------------------------------------------

def encrypt_object(obj: UniversalObject, mode: str,
                   password: str | None = None,
                   kdf: str = crypto.KDF_PBKDF2) -> tuple:
    """Encrypt the whole container for this object.

    Returns (encrypted .sfp bytes, suggested filename).  Every payload chunk
    (OBYT, CONT, BLOB, KIDS, META, HIST, RTBL, OTBL, OFMT) is encrypted — the
    object itself is left untouched in memory so the user can keep working.
    """
    plain = protocol.dumps(obj)
    data = crypto.encrypt_container(plain, mode, password, kdf)
    stem = (obj.original_filename or "object").rsplit(".", 1)[0]
    return data, f"{stem}.encrypted.sfp"


def decrypt_container_bytes(data: bytes, mode: str,
                            password: str | None = None) -> tuple:
    """Decrypt + verify + parse a container.

    Returns (obj, plain .sfp bytes, suggested filename).  Nothing is trusted:
    the decrypted container must verify its own checksum and parse cleanly.
    """
    plain = crypto.decrypt_container(data, mode, password)
    obj = protocol.loads(plain)                  # checksum + structure verified here
    stem = (obj.original_filename or "object").rsplit(".", 1)[0]
    return obj, plain, f"{stem}-decrypted.sfp"


def save_sfp(obj: UniversalObject, path: str) -> int:
    return protocol.write_file(path, obj)


def load_sfp(path: str) -> UniversalObject:
    return protocol.read_file(path)


# ---------------------------------------------------------------------------
# inspection & protocol explorer
# ---------------------------------------------------------------------------

def inspect_object(obj: UniversalObject) -> dict:
    reg = get_registry()
    adapter = reg.adapter_for(obj.detected_format)
    if adapter is None:
        adapter = reg.adapter_for("blob")
    rep = adapter.inspect(obj)
    rep["general"]["hash"] = obj.checksum
    rep["general"]["size"] = obj.size
    rep["general"]["object_id"] = obj.object_id
    rep["general"]["children"] = [c.summary() for c in obj.children]
    rep["general"]["warnings"] = obj.warnings
    rep["general"]["relationships"] = [r.to_dict() for r in obj.relationships]
    rep["general"]["transformations"] = [t.to_dict() for t in obj.transformations]
    rep["general"]["original_bytes_preserved"] = obj.original_bytes is not None
    rep["format"]["support_level"] = (obj.support_level.value
                                      if isinstance(obj.support_level, SupportLevel)
                                      else obj.support_level)
    rep["format"]["capabilities"] = obj.capabilities
    rep["format"]["adapter_manifest"] = adapter.manifest()
    return rep


def describe_pipeline(obj: UniversalObject) -> list:
    """Live values for the PROTOCOL EXPLORER pipeline diagram."""
    det = obj.metadata.get("detection", {})
    graph_children = sum(1 for _ in obj.walk()) - 1
    return [
        {"stage": "FILE", "title": "Original file",
         "detail": f"{obj.original_filename or '(unnamed)'} — {obj.size} bytes",
         "data": {"name": obj.original_filename, "size": obj.size,
                  "sha256": obj.checksum}},
        {"stage": "FORMAT DETECTION", "title": "Magic-byte detection",
         "detail": f"{det.get('display', obj.detected_format)} "
                   f"({det.get('confidence', 0):.0%} via {det.get('method', '?')})",
         "data": det},
        {"stage": "FORMAT ADAPTER", "title": "Adapter read()/parse()/decode()",
         "detail": f"{obj.adapter_name or '?'} adapter v{obj.adapter_version or '?'}",
         "data": {"adapter": obj.adapter_name, "capabilities": obj.capabilities,
                  "support_level": obj.support_level.value}},
        {"stage": "UNIVERSAL OBJECT", "title": "UniversalObject",
         "detail": f"{obj.object_type.value} — content '{obj.content.get('kind', '?')}'",
         "data": obj.summary()},
        {"stage": "OBJECT GRAPH", "title": "Nested children & relationships",
         "detail": f"{len(obj.children)} direct children, {graph_children} total descendants, "
                   f"{len(obj.relationships)} relationships",
         "data": {"children": [c.summary() for c in obj.children],
                  "relationships": [r.to_dict() for r in obj.relationships]}},
        {"stage": "TRANSFORMATION", "title": "Transform history",
         "detail": f"{len(obj.transformations)} recorded operations",
         "data": [t.to_dict() for t in obj.transformations]},
        {"stage": "EXPORT ADAPTER", "title": "Available export adapters",
         "detail": f"{len(obj.export_formats)} real export targets",
         "data": [e.to_dict() if isinstance(e, ExportOption) else e for e in obj.export_formats]},
        {"stage": "TARGET FILE", "title": "Awaiting export choice",
         "detail": "choose an EXPORT AS target above",
         "data": {}},
    ]


# ---------------------------------------------------------------------------
# object store (application-level recents)
# ---------------------------------------------------------------------------

class ObjectStore:
    """In-memory store for the application's Recent Objects."""

    def __init__(self, limit: int = 50):
        self.items: dict = {}
        self.order: list = []
        self.limit = limit

    def put(self, obj: UniversalObject) -> None:
        self.items[obj.object_id] = obj
        if obj.object_id in self.order:
            self.order.remove(obj.object_id)
        self.order.insert(0, obj.object_id)
        while len(self.order) > self.limit:
            self.items.pop(self.order.pop(), None)

    def get(self, object_id: str) -> UniversalObject:
        if object_id not in self.items:
            raise UnsafeInputError(f"unknown object id {object_id}")
        return self.items[object_id]

    def recent(self, n: int = 20) -> list:
        return [self.items[i].summary() | {
            "time": self.items[i].transformations[0].timestamp
            if self.items[i].transformations else self.items[i].created_at
        } for i in self.order[:n]]


STORE = ObjectStore()

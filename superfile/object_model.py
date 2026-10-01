"""
SUPERFILE — Universal Object Model
==================================

The UniversalObject is the common internal representation for every digital
object handled by the SUPERFILE protocol, regardless of its original format.

Design principles
-----------------
1.  One object model for all formats.  Format specifics live in ``content``
    (produced by adapters) and in ``original_bytes`` (lossless preservation).
2.  Nesting is first class: ``children`` holds further UniversalObjects
    (video streams, archive entries, document pages, project members ...).
3.  Everything is JSON-serializable except raw binary payloads, which are kept
    in ``blobs`` and referenced from ``content`` with ``{"__blob__": key}``.
4.  Nothing here executes code or trusts its input — see security.py.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class ObjectType(str, Enum):
    """The closed set of universal object types."""

    TEXT = "TEXT"
    DOCUMENT = "DOCUMENT"
    IMAGE = "IMAGE"
    AUDIO = "AUDIO"
    VIDEO = "VIDEO"
    ANIMATION = "ANIMATION"
    THREE_D = "3D"
    ARCHIVE = "ARCHIVE"
    EXECUTABLE = "EXECUTABLE"
    SOURCE_CODE = "SOURCE_CODE"
    DATABASE = "DATABASE"
    BINARY = "BINARY"
    DIRECTORY = "DIRECTORY"
    MULTIMEDIA_CONTAINER = "MULTIMEDIA_CONTAINER"
    PROTOCOL = "PROTOCOL"          # a SUPERFILE (.sfp) object graph itself
    UNKNOWN = "UNKNOWN"


class SupportLevel(str, Enum):
    """How completely a format is supported.  Always shown to the user."""

    FULL = "FULL SUPPORT"                 # read + create + edit + export
    PARTIAL = "PARTIAL SUPPORT"           # read/parse + some edit/export
    INSPECTION = "INSPECTION ONLY"        # safe static analysis, no round-trip
    UNSUPPORTED = "UNSUPPORTED"           # detected only / preserved as bytes


class ConversionKind(str, Enum):
    """Truthful classification of what a conversion/transform actually does."""

    LOSSLESS = "LOSSLESS"            # identical information (re-encode/container only)
    LOSSY = "LOSSY"                  # information is discarded (quality, resolution)
    STRUCTURAL = "STRUCTURAL"        # structural re-representation (archive repack, tree)
    RENDERED = "RENDERED"            # produced by rendering (frame capture, PDF raster)
    RECONSTRUCTED = "RECONSTRUCTED"  # rebuilt from a model (text -> HTML page, mesh preview)


# Capability verbs every adapter may advertise (see adapters/base.py).
CAPABILITIES = (
    "detect", "read", "parse", "decode", "create", "edit", "encode", "export", "inspect",
)

BLOB_REF = "__blob__"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class TransformationRecord:
    """One entry in an object's transformation history."""

    step: int
    action: str                       # e.g. "import", "image.resize", "export"
    detail: str = ""
    kind: str = ConversionKind.STRUCTURAL.value
    params: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "TransformationRecord":
        return cls(
            step=int(d.get("step", 0)),
            action=str(d.get("action", "")),
            detail=str(d.get("detail", "")),
            kind=str(d.get("kind", ConversionKind.STRUCTURAL.value)),
            params=dict(d.get("params") or {}),
            timestamp=float(d.get("timestamp", 0.0)),
        )


@dataclass
class Relationship:
    """A typed link between UniversalObjects (by object_id)."""

    relation: str          # e.g. "contains", "derived_from", "stream_of", "page_of"
    target_id: str
    note: str = ""

    def to_dict(self) -> dict:
        return {"relation": self.relation, "target_id": self.target_id, "note": self.note}

    @classmethod
    def from_dict(cls, d: dict) -> "Relationship":
        return cls(
            relation=str(d.get("relation", "references")),
            target_id=str(d.get("target_id", "")),
            note=str(d.get("note", "")),
        )


@dataclass
class ExportOption:
    """One entry of the per-object conversion matrix (only real options)."""

    format: str                    # target format id, e.g. "png"
    label: str                     # human label, e.g. "PNG image"
    kind: str = ConversionKind.STRUCTURAL.value
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ExportOption":
        return cls(
            format=str(d.get("format", "")),
            label=str(d.get("label", "")),
            kind=str(d.get("kind", ConversionKind.STRUCTURAL.value)),
            notes=str(d.get("notes", "")),
        )


@dataclass
class UniversalObject:
    """
    The universal intermediate representation of a digital object.

    ``content`` is a JSON-safe dict produced by the format adapter.  Binary
    payloads (decoded pixels, extracted frames ...) live in ``blobs`` and are
    referenced from ``content`` as ``{"__blob__": "<key>"}``.
    """

    object_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    object_type: ObjectType = ObjectType.UNKNOWN
    version: int = 1
    original_filename: str = ""
    original_extension: str = ""
    detected_format: str = ""
    mime: str = ""
    size: int = 0
    metadata: dict = field(default_factory=dict)
    content: dict = field(default_factory=dict)
    children: list = field(default_factory=list)          # list[UniversalObject]
    relationships: list = field(default_factory=list)     # list[Relationship]
    transformations: list = field(default_factory=list)   # list[TransformationRecord]
    original_bytes: bytes | None = None
    checksum: str = ""
    capabilities: list = field(default_factory=list)
    export_formats: list = field(default_factory=list)    # list[ExportOption]
    support_level: SupportLevel = SupportLevel.UNSUPPORTED
    warnings: list = field(default_factory=list)
    blobs: dict = field(default_factory=dict)             # key -> bytes
    adapter_name: str = ""
    adapter_version: str = ""
    created_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def add_blob(self, data: bytes, key: str | None = None) -> str:
        if key is None:
            key = sha256_hex(data)[:16]
        self.blobs[key] = data
        return key

    def blob_ref(self, data: bytes, key: str | None = None) -> dict:
        return {BLOB_REF: self.add_blob(data, key)}

    def get_blob(self, ref: Any) -> bytes | None:
        if isinstance(ref, dict) and BLOB_REF in ref:
            return self.blobs.get(ref[BLOB_REF])
        return None

    def record(self, action: str, detail: str = "",
               kind: str | ConversionKind = ConversionKind.STRUCTURAL,
               params: dict | None = None) -> None:
        """Append an entry to the transformation history."""
        kind_val = kind.value if isinstance(kind, ConversionKind) else str(kind)
        self.transformations.append(TransformationRecord(
            step=len(self.transformations) + 1,
            action=action, detail=detail, kind=kind_val, params=params or {},
        ))

    def add_child(self, child: "UniversalObject", relation: str = "contains",
                  note: str = "") -> "UniversalObject":
        self.children.append(child)
        self.relationships.append(Relationship(relation=relation, target_id=child.object_id, note=note))
        return child

    def find(self, object_id: str) -> "UniversalObject | None":
        if self.object_id == object_id:
            return self
        for c in self.children:
            hit = c.find(object_id)
            if hit is not None:
                return hit
        return None

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def summary(self) -> dict:
        return {
            "object_id": self.object_id,
            "object_type": self.object_type.value if isinstance(self.object_type, ObjectType) else self.object_type,
            "original_filename": self.original_filename,
            "detected_format": self.detected_format,
            "mime": self.mime,
            "size": self.size,
            "support_level": self.support_level.value if isinstance(self.support_level, SupportLevel) else self.support_level,
            "children": len(self.children),
        }

    # ------------------------------------------------------------------
    # (de)serialisation  (blobs are handled separately by protocol.py)
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "object_id": self.object_id,
            "object_type": self.object_type.value if isinstance(self.object_type, ObjectType) else self.object_type,
            "version": self.version,
            "original_filename": self.original_filename,
            "original_extension": self.original_extension,
            "detected_format": self.detected_format,
            "mime": self.mime,
            "size": self.size,
            "metadata": self.metadata,
            "content": self.content,
            "relationships": [r.to_dict() for r in self.relationships],
            "transformations": [t.to_dict() for t in self.transformations],
            "checksum": self.checksum,
            "capabilities": list(self.capabilities),
            "export_formats": [e.to_dict() if isinstance(e, ExportOption) else e for e in self.export_formats],
            "support_level": self.support_level.value if isinstance(self.support_level, SupportLevel) else self.support_level,
            "warnings": list(self.warnings),
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "created_at": self.created_at,
            "has_original_bytes": self.original_bytes is not None,
            "blob_keys": sorted(self.blobs.keys()),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "UniversalObject":
        obj = cls(
            object_id=str(d.get("object_id") or uuid.uuid4()),
            object_type=ObjectType(d.get("object_type", "UNKNOWN")),
            version=int(d.get("version", 1)),
            original_filename=str(d.get("original_filename", "")),
            original_extension=str(d.get("original_extension", "")),
            detected_format=str(d.get("detected_format", "")),
            mime=str(d.get("mime", "")),
            size=int(d.get("size", 0)),
            metadata=dict(d.get("metadata") or {}),
            content=dict(d.get("content") or {}),
            relationships=[Relationship.from_dict(r) for r in (d.get("relationships") or [])],
            transformations=[TransformationRecord.from_dict(t) for t in (d.get("transformations") or [])],
            checksum=str(d.get("checksum", "")),
            capabilities=list(d.get("capabilities") or []),
            export_formats=[ExportOption.from_dict(e) for e in (d.get("export_formats") or [])],
            support_level=SupportLevel(d.get("support_level", "UNSUPPORTED")),
            warnings=list(d.get("warnings") or []),
            adapter_name=str(d.get("adapter_name", "")),
            adapter_version=str(d.get("adapter_version", "")),
            created_at=float(d.get("created_at", 0.0)),
        )
        return obj

"""
SUPERFILE — Format adapter interface
====================================

Every format is supported through a FormatAdapter.  The protocol, object model
and UI never contain format-specific logic; they only talk to adapters.

Required manifest fields (class attributes):

    name            adapter name, e.g. "jpeg"
    version         adapter version string
    formats         dict  format_id -> FormatSpec
    capabilities    dict  format_id -> set of capability verbs
    input_types     list of ObjectTypes this adapter can read
    output_types    list of ObjectTypes this adapter can produce

Capability verbs: detect read parse decode create edit encode export inspect

Support levels (must be truthful):

    FULL SUPPORT      read + create + edit + export round-trip
    PARTIAL SUPPORT   read/parse + some edit/export
    INSPECTION ONLY   safe static analysis only
    UNSUPPORTED       detected + original bytes preserved

Adapters NEVER execute content.  See docs/ADAPTER_API.md for the full contract
and examples/new_format_adapter/ppm_adapter.py for a worked example.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..object_model import (
    ConversionKind, ExportOption, ObjectType, SupportLevel, UniversalObject,
)


@dataclass
class FormatSpec:
    format_id: str
    display: str
    extensions: list
    mime: str
    category: str                       # ObjectType value / family name
    support: SupportLevel
    read: bool = False
    create: bool = False
    edit: bool = False
    export: bool = False
    detection: str = "magic"            # magic | container | text-heuristic | extension
    notes: str = ""

    def registry_row(self) -> dict:
        return {
            "format": self.format_id,
            "display": self.display,
            "extension": ",".join(self.extensions),
            "category": self.category,
            "mime": self.mime,
            "read": self.read,
            "create": self.create,
            "edit": self.edit,
            "export": self.export,
            "detection": self.detection,
            "support": self.support.value,
            "notes": self.notes,
        }


@dataclass
class ExportResult:
    data: bytes
    filename: str
    mime: str
    kind: str = ConversionKind.STRUCTURAL.value
    notes: str = ""


class FormatAdapter:
    """Base class — subclasses override the verbs they can honestly support."""

    name: str = "base"
    version: str = "0.0"
    formats: dict = {}                  # format_id -> FormatSpec
    capabilities: dict = {}             # format_id -> set[str]
    input_types: list = []
    output_types: list = []
    is_example: bool = False            # True for the tutorial example adapter

    # ------------------------------------------------------------------
    # manifest
    # ------------------------------------------------------------------
    def manifest(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "formats": [fid for fid in self.formats],
            "capabilities": {fid: sorted(caps) for fid, caps in self.capabilities.items()},
            "input_types": [t.value if isinstance(t, ObjectType) else t for t in self.input_types],
            "output_types": [t.value if isinstance(t, ObjectType) else t for t in self.output_types],
            "is_example": self.is_example,
        }

    def supports(self, fmt: str) -> bool:
        return fmt in self.formats

    def caps(self, fmt: str) -> set:
        return set(self.capabilities.get(fmt, set()))

    # ------------------------------------------------------------------
    # verbs (default: unsupported — adapters opt in)
    # ------------------------------------------------------------------
    def detect(self, data: bytes, filename: str = "") -> float:
        """Return detection confidence 0..1 (0 = not mine)."""
        return 0.0

    def read(self, data: bytes, filename: str = "",
             detection=None) -> UniversalObject:
        """Parse + decode bytes into a UniversalObject (original_bytes preserved)."""
        raise NotImplementedError(f"{self.name}: read() not implemented")

    def parse(self, obj: UniversalObject) -> UniversalObject:
        return obj

    def decode(self, obj: UniversalObject) -> UniversalObject:
        return obj

    def create(self, object_type, params: dict | None = None) -> UniversalObject:
        raise NotImplementedError(f"{self.name}: create() not implemented")

    def edit(self, obj: UniversalObject, op: str, params: dict | None = None) -> UniversalObject:
        raise NotImplementedError(f"{self.name}: edit({op}) not implemented")

    def encode(self, obj: UniversalObject, fmt: str) -> bytes:
        raise NotImplementedError(f"{self.name}: encode({fmt}) not implemented")

    def export(self, obj: UniversalObject, fmt: str) -> ExportResult:
        """Export to a target format.  Must state an honest ConversionKind."""
        data = self.encode(obj, fmt)
        spec = self.formats.get(fmt)
        return ExportResult(
            data=data,
            filename=_stem(obj.original_filename or obj.detected_format or "object") + "." +
                    (spec.extensions[0] if spec and spec.extensions else fmt),
            mime=spec.mime if spec else "application/octet-stream",
            kind=ConversionKind.STRUCTURAL.value,
        )

    def export_formats(self, obj: UniversalObject) -> list:
        """Return only formats that genuinely can be produced from this object."""
        return []

    def inspect(self, obj: UniversalObject) -> dict:
        """Rich static inspection report (never executes anything)."""
        return {
            "general": {
                "name": obj.original_filename,
                "extension": obj.original_extension,
                "type": obj.object_type.value,
                "mime": obj.mime,
                "size": obj.size,
                "hash": obj.checksum,
            },
            "structure": {},
            "format": {
                "parser": self.name,
                "adapter_version": self.version,
                "detected_format": obj.detected_format,
                "capabilities": sorted(self.caps(obj.detected_format)),
            },
        }


def _stem(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if "." in base:
        return base.rsplit(".", 1)[0]
    return base or "object"


def opt(fmt: str, label: str, kind: ConversionKind, notes: str = "") -> ExportOption:
    return ExportOption(format=fmt, label=label, kind=kind.value, notes=notes)

"""
SUPERFILE — the .sfp SUPERFILE container adapter.

Opening a .sfp yields the root UniversalObject of its object graph, with all
nested objects, blobs and original bytes restored.
"""

from __future__ import annotations

import json

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import UnsafeInputError, sha256
from .. import protocol


class SfpAdapter(FormatAdapter):
    name = "sfp"
    version = "1.0"
    formats = {
        "sfp": FormatSpec("sfp", "SUPERFILE container", ["sfp"], "application/x-superfile",
                          "PROTOCOL", SupportLevel.FULL, read=True, create=True,
                          edit=True, export=True, detection="magic",
                          notes="universal object graph with preserved original bytes"),
    }
    capabilities = {"sfp": {"detect", "read", "parse", "decode", "create", "encode",
                            "export", "inspect"}}
    input_types = [ObjectType.PROTOCOL]
    output_types = [ObjectType.PROTOCOL]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = protocol.loads(data, verify=True)
        obj.original_filename = filename or obj.original_filename
        obj.metadata.setdefault("sfp", {})["container_file_size"] = len(data)
        # the container file itself is this object's original representation
        if obj.original_bytes is None:
            obj.original_bytes = data
        if not obj.size:
            obj.size = len(data)
        obj.record("import", f"opened SUPERFILE container {filename or ''}".strip())
        return obj

    def create(self, object_type=ObjectType.PROTOCOL, params=None) -> UniversalObject:
        """Create a SUPERFILE project object holding children from params."""
        p = params or {}
        root = UniversalObject(
            object_type=ObjectType.PROTOCOL,
            original_filename=p.get("filename", "project.sfp"),
            original_extension="sfp",
            detected_format="sfp",
            mime="application/x-superfile",
            support_level=SupportLevel.FULL,
        )
        root.content = {"kind": "project", "title": p.get("title", "SUPERFILE Project"),
                        "note": p.get("note", "Object graph created inside SUPERFILE")}
        root.adapter_name = self.name
        root.adapter_version = self.version
        root.export_formats = self.export_formats(root)
        root.capabilities = sorted(self.caps("sfp"))
        root.record("create", "created Universal Object / SUPERFILE project")
        return root

    def encode(self, obj, fmt) -> bytes:
        if fmt != "sfp":
            raise UnsafeInputError("sfp adapter only encodes sfp")
        return protocol.dumps(obj)

    def export_formats(self, obj) -> list:
        return [
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "full object graph + original bytes + checksum"),
            opt("json", "Graph manifest (.json)", ConversionKind.STRUCTURAL,
                "object graph as JSON (no binary payloads)"),
            opt("txt", "Graph report (.txt)", ConversionKind.STRUCTURAL,
                "human-readable tree + history"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "object").rsplit(".", 1)[0]
        if fmt == "sfp":
            return ExportResult(protocol.dumps(obj), stem + ".sfp", "application/x-superfile",
                                ConversionKind.LOSSLESS.value, "lossless: full graph preserved")
        if fmt == "json":
            manifest = {
                "root": obj.summary(),
                "tree": _tree(obj),
                "history": [t.to_dict() for t in obj.transformations],
                "relationships": [r.to_dict() for r in obj.relationships],
            }
            return ExportResult(json.dumps(manifest, indent=2, default=str).encode(),
                                stem + "_graph.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        if fmt == "txt":
            lines = ["SUPERFILE object graph", "=" * 40, ""]
            _tree_text(obj, lines, 0)
            lines += ["", "TRANSFORMATION HISTORY", "-" * 40]
            for t in obj.transformations:
                lines.append(f"{t.step}. [{t.kind}] {t.action}: {t.detail}")
            return ExportResult("\n".join(lines).encode(), stem + "_graph.txt", "text/plain",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError(f"sfp adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = protocol.describe_container(protocol.dumps(obj))
        rep["structure"]["object_graph"] = _tree(obj)
        return rep


def _tree(obj) -> dict:
    return {
        "id": obj.object_id,
        "name": obj.original_filename or obj.detected_format,
        "type": obj.object_type.value if isinstance(obj.object_type, ObjectType) else obj.object_type,
        "format": obj.detected_format,
        "size": obj.size,
        "children": [_tree(c) for c in obj.children],
    }


def _tree_text(obj, lines, depth):
    pad = "  " * depth
    label = obj.original_filename or obj.detected_format or "object"
    lines.append(f"{pad}- {label} [{obj.object_type.value}] ({obj.detected_format}, {obj.size} bytes)")
    for c in obj.children:
        _tree_text(c, lines, depth + 1)


ADAPTERS = [SfpAdapter()]

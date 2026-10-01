"""
SUPERFILE — Data adapters: SQLite database (read-only!) + generic binary blob.

SQLite files are opened with the immutable read-only URI — SUPERFILE never
writes to imported databases and never loads extensions.
"""

from __future__ import annotations

import json
import sqlite3
from urllib.parse import quote

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import UnsafeInputError, hex_preview, sha256


class SqliteAdapter(FormatAdapter):
    name = "sqlite"
    version = "1.0"
    formats = {
        "sqlite": FormatSpec("sqlite", "SQLite database", ["sqlite", "sqlite3", "db"],
                             "application/vnd.sqlite3", "DATABASE",
                             SupportLevel.PARTIAL, read=True, export=True,
                             detection="magic",
                             notes="read-only immutable; schema + sample rows"),
    }
    capabilities = {"sqlite": {"detect", "read", "parse", "export", "inspect"}}
    input_types = [ObjectType.DATABASE]
    output_types = [ObjectType.DATABASE, ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = UniversalObject(
            object_type=ObjectType.DATABASE,
            original_filename=filename,
            original_extension="sqlite",
            detected_format="sqlite",
            mime="application/vnd.sqlite3",
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=SupportLevel.PARTIAL,
        )
        obj.record("import", f"imported {filename or 'database'} (read-only)")
        obj.content = {"kind": "database"}
        try:
            if data[:16] != b"SQLite format 3\x00":
                raise UnsafeInputError("missing SQLite signature")
            page_size = int.from_bytes(data[16:18], "big")
            if page_size == 1:
                page_size = 65536
            obj.content.update({
                "page_size": page_size,
                "user_version": int.from_bytes(data[60:64], "big"),
                "application_id": int.from_bytes(data[68:72], "big"),
                "text_encoding": {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(
                    int.from_bytes(data[56:60], "big"), "?"),
            })
        except Exception as exc:
            obj.warnings.append(f"header issue: {exc}")

        # schema + samples through read-only immutable connection on a temp copy
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
            tf.write(data)
            tmp = tf.name
        try:
            uri = f"file:{quote(tmp)}?mode=ro&immutable=1"
            con = sqlite3.connect(uri, uri=True)
            con.row_factory = sqlite3.Row
            try:
                cur = con.execute("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
                schema = [{"type": r[0], "name": r[1], "sql": r[2]} for r in cur.fetchall()]
                tables = []
                for item in schema:
                    entry = dict(item)
                    if item["type"] == "table":
                        try:
                            n = con.execute(f'SELECT COUNT(*) FROM "{item["name"]}"').fetchone()[0]
                            entry["row_count"] = n
                            rows = con.execute(f'SELECT * FROM "{item["name"]}" LIMIT 5').fetchall()
                            entry["sample_rows"] = [dict(r) for r in rows]
                            entry["sample_rows"] = json.loads(json.dumps(
                                entry["sample_rows"], default=str))
                        except sqlite3.Error as exc:
                            entry["error"] = str(exc)
                    tables.append(entry)
                obj.content["schema"] = tables
                obj.content["table_count"] = sum(1 for s in schema if s["type"] == "table")
                obj.content["index_count"] = sum(1 for s in schema if s["type"] == "index")
            finally:
                con.close()
        except sqlite3.Error as exc:
            obj.warnings.append(f"SQLite open issue: {exc}")
            obj.support_level = SupportLevel.INSPECTION
            obj.content["hex_preview"] = hex_preview(data)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return obj

    def export_formats(self, obj) -> list:
        return [
            opt("sqlite", "SQLite database (.sqlite)", ConversionKind.LOSSLESS,
                "original bytes preserved (read-only)"),
            opt("json", "Schema + samples (.json)", ConversionKind.STRUCTURAL,
                "tables, row counts, sample rows"),
            opt("sql", "Schema DDL (.sql)", ConversionKind.STRUCTURAL,
                "CREATE statements from sqlite_master"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "data").rsplit(".", 1)[0]
        if fmt == "sqlite":
            return ExportResult(obj.original_bytes or b"", stem + ".sqlite",
                                "application/vnd.sqlite3", ConversionKind.LOSSLESS.value)
        if fmt == "json":
            payload = {k: v for k, v in obj.content.items() if not k.startswith("_")}
            return ExportResult(json.dumps(payload, indent=2, default=str).encode(),
                                stem + "_schema.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        if fmt == "sql":
            ddl = [s["sql"] + ";" for s in obj.content.get("schema", []) if s.get("sql")]
            return ExportResult("\n\n".join(ddl).encode() + b"\n", stem + "_schema.sql",
                                "application/sql", ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError(f"sqlite adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "tables": [s["name"] for s in obj.content.get("schema", [])
                       if s.get("type") == "table"],
            "indexes": [s["name"] for s in obj.content.get("schema", [])
                        if s.get("type") == "index"],
            "page_size": obj.content.get("page_size"),
            "text_encoding": obj.content.get("text_encoding"),
        }
        return rep


class BlobAdapter(FormatAdapter):
    """Generic binary blob — honest 'unknown binary' handling."""

    name = "blob"
    version = "1.0"
    formats = {
        "blob": FormatSpec("blob", "Binary blob", ["bin", "dat", ""], "application/octet-stream",
                           "BINARY", SupportLevel.PARTIAL, read=True, create=True, export=True,
                           detection="extension", notes="hex preview + entropy; bytes preserved"),
        "empty": FormatSpec("empty", "Empty file", [""], "application/x-empty", "BINARY",
                            SupportLevel.PARTIAL, read=True, create=True,
                            detection="magic", notes="zero-byte files"),
    }
    capabilities = {"blob": {"detect", "read", "parse", "create", "encode", "export", "inspect"},
                    "empty": {"detect", "read", "create", "export", "inspect"}}
    input_types = [ObjectType.BINARY]
    output_types = [ObjectType.BINARY, ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        fmt = "empty" if len(data) == 0 else "blob"
        spec = self.formats[fmt]
        obj = UniversalObject(
            object_type=ObjectType.BINARY,
            original_filename=filename,
            original_extension=(filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"),
            detected_format=fmt,
            mime=spec.mime,
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=spec.support,
        )
        obj.record("import", f"imported {filename or 'blob'} ({len(data)} bytes)")
        # byte histogram + simple entropy
        hist = [0] * 256
        for b in data[:1_000_000]:
            hist[b] += 1
        n = min(len(data), 1_000_000) or 1
        import math
        entropy = -sum((c / n) * math.log2(c / n) for c in hist if c)
        obj.content = {
            "kind": "blob",
            "hex_preview": hex_preview(data),
            "entropy": round(entropy, 3),
            "printable_ratio": round(sum(hist[32:127]) / n, 3),
        }
        return obj

    def create(self, object_type=ObjectType.BINARY, params=None) -> UniversalObject:
        p = params or {}
        raw = p.get("data")
        if raw is None:
            size = max(0, min(1_000_000, int(p.get("size", 256))))
            raw = bytes((i * 37 + 11) & 0xFF for i in range(size))
        return self.read(raw, p.get("filename", "created.bin"), None)

    def export_formats(self, obj) -> list:
        return [
            opt("blob", "Binary (.bin)", ConversionKind.LOSSLESS, "original bytes"),
            opt("txt", "Hex dump (.txt)", ConversionKind.STRUCTURAL, "hex preview"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "blob").rsplit(".", 1)[0]
        if fmt == "blob":
            return ExportResult(obj.original_bytes or b"", stem + ".bin",
                                "application/octet-stream", ConversionKind.LOSSLESS.value)
        if fmt == "txt":
            return ExportResult(obj.content.get("hex_preview", "").encode(),
                                stem + "_hex.txt", "text/plain", ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError(f"blob adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "entropy": obj.content.get("entropy"),
            "printable_ratio": obj.content.get("printable_ratio"),
            "hex_preview": obj.content.get("hex_preview", "")[:400],
        }
        return rep


ADAPTERS = [SqliteAdapter(), BlobAdapter()]

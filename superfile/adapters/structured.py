"""
SUPERFILE — Structured data adapters: JSON YAML TOML BSON

YAML/TOML are honestly PARTIAL (common subset); BSON gets a structural parser.
"""

from __future__ import annotations

import json
import re
import struct

from .base import FormatAdapter, FormatSpec
from ..object_model import ConversionKind, ObjectType, SupportLevel, UniversalObject
from ..security import LIMITS, UnsafeInputError, sha256


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace")


def _obj(fmt, spec: FormatSpec, data, filename, text, otype=ObjectType.TEXT) -> UniversalObject:
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
    obj.content = {"kind": "structured", "format": fmt, "text": text, "raw": text}
    obj.record("import", f"imported {filename or fmt}")
    return obj


# ---------------------------------------------------------------------------
# YAML subset writer (for JSON → YAML export) and reader
# ---------------------------------------------------------------------------

def _yaml_scalar(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    s = str(v)
    if s == "" or re.search(r"[:#\n\-\{\}\[\],&*?|<>=!%@`]", s) or s.strip() != s:
        return json.dumps(s, ensure_ascii=False)
    if _yaml_would_coerce(s):
        return json.dumps(s, ensure_ascii=False)   # keep it a string on re-read
    return s


def _yaml_would_coerce(s: str) -> bool:
    """True when from_yaml would read plain *s* back as a non-string type."""
    if s in ("null", "~", "true", "True", "false", "False"):
        return True
    if s.startswith(('"', "'")):
        return True
    try:
        int(s)
        return True
    except ValueError:
        pass
    try:
        float(s)
        return True
    except ValueError:
        return False


def to_yaml(data, indent: int = 0) -> str:
    """Emit a YAML subset for dict/list/scalar trees."""
    pad = "  " * indent
    if isinstance(data, dict):
        if not data:
            return pad + "{}\n"
        out = []
        for k, v in data.items():
            key = str(k)
            if isinstance(v, (dict, list)) and v:
                out.append(f"{pad}{key}:")
                out.append(to_yaml(v, indent + 1).rstrip("\n"))
            else:
                out.append(f"{pad}{key}: {_yaml_scalar(v) if not isinstance(v, (dict, list)) else ('{}' if isinstance(v, dict) else '[]')}")
        return "\n".join(out) + "\n"
    if isinstance(data, list):
        if not data:
            return pad + "[]\n"
        out = []
        for v in data:
            if isinstance(v, (dict, list)) and v:
                sub = to_yaml(v, indent + 1).rstrip("\n")
                first, *rest = sub.split("\n")
                out.append(f"{pad}- {first.strip()}" if first.strip().startswith("-") is False
                           else f"{pad}{first}")
                out.extend(rest)
            else:
                out.append(f"{pad}- {_yaml_scalar(v)}")
        return "\n".join(out) + "\n"
    return pad + _yaml_scalar(data) + "\n"


def from_yaml(text: str):
    """Parse a YAML subset: nested maps, lists, scalars.  No anchors/aliases."""
    lines = []
    for raw in text.split("\n"):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        lines.append(raw.rstrip())

    def parse_block(idx: int, indent: int):
        container = None
        while idx < len(lines):
            line = lines[idx]
            cur = len(line) - len(line.lstrip(" "))
            if cur < indent:
                break
            body = line.strip()
            if body.startswith("- "):
                if container is None:
                    container = []
                elif not isinstance(container, list):
                    break
                item = body[2:].strip()
                if ":" in item and not item.startswith(("'", '"')):
                    # inline map item:  - key: value
                    k, _, v = item.partition(":")
                    sub = {k.strip(): _scalar(v.strip())}
                    idx += 1
                    # continuation lines of the same map item
                    while idx < len(lines):
                        nl = lines[idx]
                        nind = len(nl) - len(nl.lstrip(" "))
                        if nind <= cur or nl.strip().startswith("- "):
                            break
                        if ":" in nl:
                            k2, _, v2 = nl.strip().partition(":")
                            sub[k2.strip()] = _scalar(v2.strip())
                        idx += 1
                    container.append(sub)
                    continue
                elif item.endswith(":"):
                    sub, idx = parse_block(idx + 1, cur + 2)
                    container.append({item[:-1].strip(): sub})
                    continue
                else:
                    container.append(_scalar(item))
                    idx += 1
                    continue
            if ":" in body:
                if container is None:
                    container = {}
                elif not isinstance(container, dict):
                    break
                k, _, v = body.partition(":")
                key = k.strip().strip('"').strip("'")
                val = v.strip()
                if val == "":
                    sub, idx = parse_block(idx + 1, cur + 1)
                    container[key] = sub if sub is not None else {}
                    continue
                container[key] = _scalar(val)
                idx += 1
                continue
            idx += 1
        return container, idx

    result, _ = parse_block(0, 0)
    return result


def _scalar(s: str):
    if s.startswith(("'", '"')) and s.endswith(("'", '"')) and len(s) >= 2:
        try:
            return json.loads(s) if s.startswith('"') else s[1:-1]
        except Exception:
            return s[1:-1]
    if s in ("null", "~", ""):
        return None
    if s in ("true", "True"):
        return True
    if s in ("false", "False"):
        return False
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


# ---------------------------------------------------------------------------
# TOML subset writer + reader
# ---------------------------------------------------------------------------

def to_toml(data) -> str | None:
    """dict of scalars/arrays-of-scalars/nested tables → TOML."""
    if not isinstance(data, dict):
        return None
    out = []

    def scalar(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return repr(v)
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False)
        return None

    def emit_table(d: dict, path: str):
        scalars = []
        tables = []
        for k, v in d.items():
            if isinstance(v, dict):
                tables.append((k, v))
            elif isinstance(v, list):
                parts = []
                ok = True
                for item in v:
                    s = scalar(item)
                    if s is None:
                        ok = False
                        break
                    parts.append(s)
                if not ok:
                    return False
                scalars.append(f"{k} = [{', '.join(parts)}]")
            else:
                s = scalar(v)
                if s is None and v is not None:
                    return False
                scalars.append(f"{k} = {s if v is not None else '""'}")
        if path:
            out.append(f"[{path}]")
        out.extend(scalars)
        for k, v in tables:
            sub = f"{path}.{k}" if path else k
            if not emit_table(v, sub):
                return False
        return True

    if not emit_table(data, ""):
        return None
    return "\n".join(out) + "\n"


def from_toml(text: str):
    data = {}
    cur = data
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"\[([\w.\-]+)\]", line)
        if m:
            cur = data
            for part in m.group(1).split("."):
                cur = cur.setdefault(part, {})
            continue
        m = re.match(r"([\w.\-]+)\s*=\s*(.+)", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).split("#")[0].strip()
        if val.startswith("["):
            items = [x.strip() for x in val.strip("[]").split(",") if x.strip()]
            cur[key] = [_scalar(x) for x in items]
        else:
            cur[key] = _scalar(val)
    return data


# ---------------------------------------------------------------------------
# CSV writer (JSON → CSV)
# ---------------------------------------------------------------------------

def to_csv(rows: list) -> str:
    import csv, io
    cols = []
    for r in rows:
        for k in r.keys():
            if k not in cols:
                cols.append(k)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols)
    for r in rows:
        w.writerow(["" if r.get(c) is None else (json.dumps(r[c]) if isinstance(r[c], (dict, list)) else r[c])
                    for c in cols])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# BSON reader (structural)
# ---------------------------------------------------------------------------

_BSON_TYPES = {
    0x01: ("double", 8), 0x02: ("string", None), 0x03: ("document", None),
    0x04: ("array", None), 0x05: ("binary", None), 0x07: ("objectid", 12),
    0x08: ("bool", 1), 0x09: ("datetime", 8), 0x0A: ("null", 0),
    0x10: ("int32", 4), 0x11: ("timestamp", 8), 0x12: ("int64", 8),
}


def parse_bson(data: bytes, depth: int = 0) -> dict:
    if depth > LIMITS.max_bson_depth:
        raise UnsafeInputError("BSON nesting too deep")
    if len(data) < 5:
        raise UnsafeInputError("BSON document too small")
    (size,) = struct.unpack_from("<I", data, 0)
    if size != len(data):
        raise UnsafeInputError(f"BSON declared size {size} != actual {len(data)}")
    pos = 4
    doc = {}
    while pos < len(data) - 1:
        etype = data[pos]
        pos += 1
        end = data.index(0, pos) if 0 in data[pos:] else len(data)
        name = data[pos:end].decode("utf-8", "replace")
        pos = end + 1
        info = _BSON_TYPES.get(etype)
        if info is None:
            doc[name] = f"<unsupported element type 0x{etype:02x}>"
            break
        tname, fixed = info
        if tname == "double":
            doc[name] = struct.unpack_from("<d", data, pos)[0]
            pos += 8
        elif tname == "string":
            (ln,) = struct.unpack_from("<I", data, pos)
            pos += 4
            doc[name] = data[pos:pos + ln - 1].decode("utf-8", "replace")
            pos += ln
        elif tname in ("document", "array"):
            (ln,) = struct.unpack_from("<I", data, pos)
            sub = parse_bson(data[pos:pos + ln], depth + 1)
            doc[name] = list(sub.values()) if tname == "array" else sub
            pos += ln
        elif tname == "binary":
            (ln,) = struct.unpack_from("<I", data, pos)
            pos += 5 + ln
            doc[name] = f"<binary {ln} bytes>"
        elif tname == "bool":
            doc[name] = bool(data[pos])
            pos += 1
        elif tname == "null":
            doc[name] = None
        elif tname == "int32":
            doc[name] = struct.unpack_from("<i", data, pos)[0]
            pos += 4
        elif tname == "int64":
            doc[name] = struct.unpack_from("<q", data, pos)[0]
            pos += 8
        elif tname in ("objectid", "datetime", "timestamp"):
            raw = data[pos:pos + fixed]
            doc[name] = f"<{tname} {raw.hex()}>"
            pos += fixed
    return doc


# ---------------------------------------------------------------------------
# adapters
# ---------------------------------------------------------------------------

class JsonAdapter(FormatAdapter):
    name = "json"
    version = "1.0"
    formats = {
        "json": FormatSpec("json", "JSON data", ["json", "jsonl"], "application/json", "TEXT",
                           SupportLevel.FULL, read=True, create=True, edit=True, export=True,
                           detection="text-heuristic"),
    }
    capabilities = {"json": {"detect", "read", "parse", "decode", "create", "edit",
                             "encode", "export", "inspect"}}
    input_types = [ObjectType.TEXT]
    output_types = [ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        text = _decode(data)
        obj = _obj("json", self.formats["json"], data, filename, text)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            # JSON Lines fallback
            parsed = []
            ok = True
            for line in text.split("\n"):
                if not line.strip():
                    continue
                try:
                    parsed.append(json.loads(line))
                except json.JSONDecodeError:
                    ok = False
                    break
            if not ok:
                obj.warnings.append(f"JSON parse error: {exc}")
                obj.support_level = SupportLevel.INSPECTION
                obj.content["data"] = None
                return obj
            obj.content["jsonl"] = True
        obj.content["data"] = parsed
        obj.content["kind"] = "structured"
        return obj

    def create(self, object_type=ObjectType.TEXT, params=None) -> UniversalObject:
        p = params or {}
        data = p.get("data", {})
        text = p.get("text") or json.dumps(data, indent=2, ensure_ascii=False)
        return self.read(text.encode("utf-8"), p.get("filename", "untitled.json"), None)

    def edit(self, obj, op, params=None):
        p = params or {}
        if op == "set_text":
            text = str(p.get("text", ""))
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise UnsafeInputError(f"invalid JSON: {exc}")
            obj.content["text"] = text
            obj.content["raw"] = text
            obj.content["data"] = parsed
            obj.content["edited_bytes"] = {"__blob__": obj.add_blob(text.encode("utf-8"))}
            obj.record("edit.set_text", "JSON replaced", ConversionKind.STRUCTURAL)
            return obj
        raise UnsafeInputError(f"json adapter: unsupported edit {op!r}")

    def _bytes(self, obj) -> bytes:
        ref = obj.content.get("edited_bytes")
        got = obj.get_blob(ref)
        return got if got is not None else obj.content.get("raw", "").encode("utf-8")

    def export_formats(self, obj) -> list:
        from .base import opt
        return [
            opt("json", "JSON (.json)", ConversionKind.LOSSLESS, "canonical re-serialization"),
            opt("yaml", "YAML (.yaml)", ConversionKind.STRUCTURAL, "subset writer"),
            opt("toml", "TOML (.toml)", ConversionKind.STRUCTURAL, "tables of scalars only"),
            opt("csv", "CSV (.csv)", ConversionKind.STRUCTURAL, "only for arrays of objects"),
            opt("txt", "Plain text (.txt)", ConversionKind.RECONSTRUCTED, "raw JSON text"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        from .base import ExportResult
        stem = (obj.original_filename or "object").rsplit(".", 1)[0]
        if fmt == "json":
            return ExportResult(json.dumps(obj.content.get("data"), indent=2, ensure_ascii=False).encode(),
                                stem + ".json", "application/json", ConversionKind.LOSSLESS.value)
        if fmt == "yaml":
            return ExportResult(to_yaml(obj.content.get("data")).encode(), stem + ".yaml",
                                "application/yaml", ConversionKind.STRUCTURAL.value, "YAML subset")
        if fmt == "toml":
            t = to_toml(obj.content.get("data"))
            if t is None:
                raise UnsafeInputError("data is not representable in TOML subset (nested lists etc.)")
            return ExportResult(t.encode(), stem + ".toml", "application/toml",
                                ConversionKind.STRUCTURAL.value, "TOML subset")
        if fmt == "csv":
            data = obj.content.get("data")
            if not isinstance(data, list) or (data and not isinstance(data[0], dict)):
                raise UnsafeInputError("CSV export needs a JSON array of objects")
            return ExportResult(to_csv(data).encode(), stem + ".csv", "text/csv",
                                ConversionKind.STRUCTURAL.value)
        if fmt == "txt":
            return ExportResult(self._bytes(obj), stem + ".txt", "text/plain",
                                ConversionKind.RECONSTRUCTED.value)
        raise UnsafeInputError(f"json adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        data = obj.content.get("data")

        def shape(v, depth=0):
            if depth > 6:
                return "..."
            if isinstance(v, dict):
                return {k: shape(x, depth + 1) for k, x in list(v.items())[:40]}
            if isinstance(v, list):
                return [shape(v[0], depth + 1), f"... {len(v)} items"] if v else []
            return type(v).__name__
        rep["structure"] = {"shape": shape(data), "top_level_type": type(data).__name__}
        return rep


class YamlTomlAdapter(FormatAdapter):
    name = "yaml-toml"
    version = "1.0"
    formats = {
        "yaml": FormatSpec("yaml", "YAML data", ["yaml", "yml"], "application/yaml", "TEXT",
                           SupportLevel.PARTIAL, read=True, create=True, edit=True, export=True,
                           detection="text-heuristic", notes="indentation subset — no anchors/tags"),
        "toml": FormatSpec("toml", "TOML data", ["toml"], "application/toml", "TEXT",
                           SupportLevel.PARTIAL, read=True, create=True, edit=True, export=True,
                           detection="text-heuristic", notes="tables/scalars subset (stdlib tomllib read)"),
    }
    capabilities = {
        "yaml": {"detect", "read", "parse", "create", "edit", "export", "inspect"},
        "toml": {"detect", "read", "parse", "create", "edit", "export", "inspect"},
    }
    input_types = [ObjectType.TEXT]
    output_types = [ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        fmt = detection.format_id if detection else (
            "toml" if filename.lower().endswith(".toml") else "yaml")
        spec = self.formats[fmt]
        text = _decode(data)
        obj = _obj(fmt, spec, data, filename, text)
        try:
            if fmt == "toml":
                import tomllib
                obj.content["data"] = tomllib.loads(text)
                obj.content["parser"] = "tomllib (stdlib, full read)"
            else:
                obj.content["data"] = from_yaml(text)
                obj.content["parser"] = "superfile YAML subset parser"
                obj.warnings.append("YAML parsed with subset parser (no anchors, tags or multi-doc)")
        except Exception as exc:
            obj.warnings.append(f"{fmt.upper()} parse error: {exc}")
            obj.support_level = SupportLevel.INSPECTION
            obj.content["data"] = None
        return obj

    def create(self, object_type=ObjectType.TEXT, params=None) -> UniversalObject:
        p = params or {}
        fmt = p.get("format", "yaml")
        text = p.get("text", "")
        return self.read(text.encode("utf-8"), p.get("filename", f"untitled.{fmt}"), _F(fmt))

    def edit(self, obj, op, params=None):
        if op == "set_text":
            text = str((params or {}).get("text", ""))
            obj.content["text"] = text
            obj.content["raw"] = text
            obj.content["edited_bytes"] = {"__blob__": obj.add_blob(text.encode("utf-8"))}
            obj.record("edit.set_text", "source replaced")
            return obj
        raise UnsafeInputError(f"yaml/toml adapter: unsupported edit {op!r}")

    def export_formats(self, obj) -> list:
        from .base import opt
        fid = obj.detected_format
        out = [
            opt("txt", "Plain text (.txt)", ConversionKind.LOSSLESS, "raw source"),
            opt("json", "JSON (.json)", ConversionKind.STRUCTURAL, "parsed data re-serialized"),
        ]
        out.append(opt(fid or "yaml", f"{fid.upper()} (.{fid})", ConversionKind.LOSSLESS, "same format"))
        out.append(opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                       "UniversalObject graph incl. original bytes"))
        return out

    def export(self, obj, fmt):
        from .base import ExportResult
        stem = (obj.original_filename or "object").rsplit(".", 1)[0]
        data = obj.content.get("data")
        raw = obj.get_blob(obj.content.get("edited_bytes")) or obj.content.get("raw", "").encode("utf-8")
        if fmt == obj.detected_format:
            return ExportResult(raw, f"{stem}.{fmt}", obj.mime, ConversionKind.LOSSLESS.value)
        if fmt == "txt":
            return ExportResult(raw, stem + ".txt", "text/plain", ConversionKind.LOSSLESS.value)
        if fmt == "json":
            return ExportResult(json.dumps(data, indent=2, ensure_ascii=False).encode(),
                                stem + ".json", "application/json", ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError(f"yaml/toml adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "parser": obj.content.get("parser"),
            "data_keys": list(obj.content.get("data", {}) or {})[:50]
            if isinstance(obj.content.get("data"), dict) else None,
        }
        return rep


class _F:
    def __init__(self, fid):
        self.format_id = fid


class BsonAdapter(FormatAdapter):
    name = "bson"
    version = "1.0"
    formats = {
        "bson": FormatSpec("bson", "BSON document", ["bson"], "application/bson", "TEXT",
                           SupportLevel.INSPECTION, read=True, create=False, edit=False, export=False,
                           detection="text-heuristic", notes="structural decode of element types"),
    }
    capabilities = {"bson": {"detect", "read", "parse", "inspect"}}
    input_types = [ObjectType.TEXT, ObjectType.BINARY]
    output_types = [ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = _obj("bson", self.formats["bson"], data, filename, "", ObjectType.BINARY)
        try:
            parsed = parse_bson(data)
            obj.content["data"] = parsed
            obj.content["kind"] = "structured"
            obj.content["text"] = json.dumps(parsed, indent=2, ensure_ascii=False, default=str)
        except UnsafeInputError as exc:
            obj.warnings.append(str(exc))
            obj.content["data"] = None
        return obj

    def export_formats(self, obj) -> list:
        from .base import opt
        return [opt("json", "JSON (.json)", ConversionKind.RECONSTRUCTED,
                    "BSON values decoded to JSON (binary values summarised)")]

    def export(self, obj, fmt):
        from .base import ExportResult
        if fmt != "json":
            raise UnsafeInputError("bson adapter only exports json")
        stem = (obj.original_filename or "object").rsplit(".", 1)[0]
        return ExportResult(json.dumps(obj.content.get("data"), indent=2, default=str).encode(),
                            stem + ".json", "application/json", ConversionKind.RECONSTRUCTED.value)


ADAPTERS = [JsonAdapter(), YamlTomlAdapter(), BsonAdapter()]

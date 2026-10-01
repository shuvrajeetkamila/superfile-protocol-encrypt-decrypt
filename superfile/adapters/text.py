"""
SUPERFILE — Text & simple document adapters: TXT MD CSV RTF HTML XML
"""

from __future__ import annotations

import csv as csv_mod
import io
import json
import re
import xml.etree.ElementTree as ET

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import LIMITS, UnsafeInputError, sha256
from ..transforms import markdown_to_html


def _decode_text(data: bytes) -> tuple:
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", "replace"), "latin-1"


def _base_object(fmt: str, otype: ObjectType, data: bytes, filename: str,
                 text: str, encoding: str, spec: FormatSpec) -> UniversalObject:
    obj = UniversalObject(
        object_type=otype,
        original_filename=filename,
        original_extension=(filename.rsplit(".", 1)[-1].lower() if "." in filename else spec.extensions[0]),
        detected_format=fmt,
        mime=spec.mime,
        size=len(data),
        original_bytes=data,
        checksum=sha256(data),
        support_level=spec.support,
    )
    obj.content = {"kind": "text", "text": text, "encoding": encoding}
    obj.metadata["encoding"] = encoding
    obj.metadata["format_version"] = ""
    obj.record("import", f"imported {filename or fmt}")
    obj.adapter_name = "text"
    obj.adapter_version = TextAdapter.version
    return obj


class TextAdapter(FormatAdapter):
    """TXT / MD / CSV / RTF — plain-text family."""

    name = "text"
    version = "1.0"
    formats = {
        "txt": FormatSpec("txt", "Plain text", ["txt", "log"], "text/plain", "TEXT",
                          SupportLevel.FULL, read=True, create=True, edit=True, export=True,
                          detection="text-heuristic"),
        "md": FormatSpec("md", "Markdown", ["md", "markdown"], "text/markdown", "TEXT",
                         SupportLevel.FULL, read=True, create=True, edit=True, export=True,
                         detection="text-heuristic"),
        "csv": FormatSpec("csv", "CSV table", ["csv", "tsv"], "text/csv", "TEXT",
                          SupportLevel.PARTIAL, read=True, create=True, edit=True, export=True,
                          detection="text-heuristic", notes="RFC4180 subset via stdlib csv"),
        "rtf": FormatSpec("rtf", "RTF document", ["rtf"], "application/rtf", "DOCUMENT",
                          SupportLevel.PARTIAL, read=True, create=False, edit=False, export=True,
                          detection="text-heuristic", notes="text extraction + minimal writer"),
    }
    capabilities = {
        "txt": {"detect", "read", "parse", "decode", "create", "edit", "encode", "export", "inspect"},
        "md": {"detect", "read", "parse", "decode", "create", "edit", "encode", "export", "inspect"},
        "csv": {"detect", "read", "parse", "decode", "create", "edit", "encode", "export", "inspect"},
        "rtf": {"detect", "read", "parse", "export", "inspect"},
    }
    input_types = [ObjectType.TEXT, ObjectType.DOCUMENT]
    output_types = [ObjectType.TEXT, ObjectType.DOCUMENT]

    def detect(self, data: bytes, filename: str = "") -> float:
        return 0.0   # detection module handles text heuristics; adapters confirm on read

    # ------------------------------------------------------------------
    def read(self, data: bytes, filename: str = "", detection=None) -> UniversalObject:
        fmt = (detection.format_id if detection else "") or (
            filename.rsplit(".", 1)[-1].lower() if "." in filename else "txt")
        if fmt in ("markdown",):
            fmt = "md"
        if fmt in ("log", "text"):
            fmt = "txt"
        if fmt in ("tsv",):
            fmt = "csv"
        text, enc = _decode_text(data)
        if len(text) > LIMITS.max_text_chars:
            text = text[:LIMITS.max_text_chars]
        if fmt == "md":
            obj = _base_object("md", ObjectType.TEXT, data, filename, text, enc, self.formats["md"])
            headings = [{"level": len(m.group(1)), "text": m.group(2)}
                        for m in re.finditer(r"^(#{1,6})\s+(.+)$", text, re.M)]
            obj.content["headings"] = headings
            obj.content["derived"] = {"html": markdown_to_html(text)}
            return obj
        if fmt == "csv":
            return self._read_csv(data, filename, text, enc)
        if fmt == "rtf":
            return self._read_rtf(data, filename, text)
        obj = _base_object("txt", ObjectType.TEXT, data, filename, text, enc, self.formats["txt"])
        obj.content["stats"] = {"lines": text.count("\n") + 1, "chars": len(text)}
        return obj

    def _read_csv(self, data, filename, text, enc) -> UniversalObject:
        delim = "\t" if (filename.endswith(".tsv") or (
            text.count("\t") > text.count(",") and text.count("\t") > 0)) else ","
        rows = list(csv_mod.reader(io.StringIO(text), delimiter=delim))
        if len(rows) > 20000:
            rows = rows[:20000]
        columns = rows[0] if rows else []
        body = rows[1:] if len(rows) > 1 else []
        obj = _base_object("csv", ObjectType.TEXT, data, filename, text, enc, self.formats["csv"])
        obj.content.update({
            "kind": "table", "delimiter": delim,
            "columns": columns, "rows": body,
            "row_count": len(body),
        })
        return obj

    def _read_rtf(self, data, filename, text) -> UniversalObject:
        plain, meta = rtf_extract(text)
        obj = _base_object("rtf", ObjectType.DOCUMENT, data, filename, text, "ascii", self.formats["rtf"])
        obj.content.update({"kind": "document", "text": plain, "raw_text": plain, "rtf_meta": meta})
        obj.object_type = ObjectType.DOCUMENT
        return obj

    # ------------------------------------------------------------------
    def create(self, object_type=ObjectType.TEXT, params: dict | None = None) -> UniversalObject:
        p = params or {}
        fmt = p.get("format", "txt")
        text = p.get("text", "")
        name = p.get("filename", f"untitled.{fmt}")
        data = text.encode("utf-8")
        if fmt == "md":
            return self.read(data, name, _Det("md"))
        if fmt == "csv":
            return self.read(data, name, _Det("csv"))
        return self.read(data, name, _Det("txt"))

    def edit(self, obj: UniversalObject, op: str, params: dict | None = None) -> UniversalObject:
        p = params or {}
        if op == "set_text":
            text = str(p.get("text", ""))
            obj.content["text"] = text
            if obj.detected_format in ("txt", "md", "csv", "rtf"):
                obj.content.setdefault("derived", {})
            new_bytes = text.encode("utf-8")
            obj.size = len(new_bytes)
            # edited representation replaces export bytes but original_bytes stay preserved
            obj.content["edited_bytes"] = {"__blob__": obj.add_blob(new_bytes)}
            obj.record("edit.set_text", f"text replaced ({len(text)} chars)", ConversionKind.STRUCTURAL)
            return obj
        raise UnsafeInputError(f"text adapter: unsupported edit op {op!r}")

    # ------------------------------------------------------------------
    def _export_bytes(self, obj: UniversalObject) -> bytes:
        ref = obj.content.get("edited_bytes")
        data = obj.get_blob(ref)
        if data is not None:
            return data
        return (obj.content.get("text", "")).encode("utf-8")

    def export_formats(self, obj) -> list:
        fid = getattr(obj, "detected_format", "")
        out = [opt("txt", "Plain text (.txt)", ConversionKind.RECONSTRUCTED,
                   "Text content only; layout dropped")]
        if fid in ("txt", "md", "csv", ""):
            out.append(opt("md", "Markdown (.md)", ConversionKind.RECONSTRUCTED,
                           "Text wrapped as markdown"))
        out.append(opt("html", "HTML page (.html)", ConversionKind.RECONSTRUCTED,
                       "Escaped text/markdown rendered into an HTML document"))
        out.append(opt("rtf", "RTF document (.rtf)", ConversionKind.RECONSTRUCTED,
                       "Minimal RTF writer (text only)"))
        if fid == "csv":
            out.append(opt("json", "JSON rows (.json)", ConversionKind.STRUCTURAL,
                           "Table → array of row objects"))
        if fid == "md":
            out.append(opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                           "UniversalObject graph incl. original bytes"))
        out.append(opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                       "UniversalObject graph incl. original bytes"))
        return out

    def export(self, obj: UniversalObject, fmt: str) -> ExportResult:
        stem = _stem(obj.original_filename)
        if fmt == "txt":
            return ExportResult(self._export_bytes(obj), stem + ".txt", "text/plain",
                                ConversionKind.RECONSTRUCTED.value, "content text only")
        if fmt == "md":
            text = obj.content.get("text", "")
            if obj.detected_format == "md":
                return ExportResult(self._export_bytes(obj), stem + ".md", "text/markdown",
                                    ConversionKind.LOSSLESS.value, "already markdown")
            return ExportResult(f"# {obj.original_filename or 'Document'}\n\n```\n{text}\n```\n".encode(),
                                stem + ".md", "text/markdown", ConversionKind.RECONSTRUCTED.value,
                                "text embedded in a markdown fence")
        if fmt == "html":
            from ..transforms import _inline
            import html as html_mod
            title = obj.original_filename or "Document"
            if obj.detected_format == "md":
                body = markdown_to_html(obj.content.get("text", ""))
            else:
                body = "<pre>" + html_mod.escape(obj.content.get("text", "")) + "</pre>"
            page = ("<!doctype html><html><head><meta charset='utf-8'><title>"
                    + html_mod.escape(title) + f"</title></head><body>{body}</body></html>")
            return ExportResult(page.encode(), stem + ".html", "text/html",
                                ConversionKind.RECONSTRUCTED.value,
                                "markdown rendered" if obj.detected_format == "md" else "text wrapped in HTML")
        if fmt == "rtf":
            return ExportResult(rtf_write(obj.content.get("text", "")), stem + ".rtf",
                                "application/rtf", ConversionKind.RECONSTRUCTED.value,
                                "minimal RTF writer")
        if fmt == "json" and obj.detected_format == "csv":
            rows = []
            cols = obj.content.get("columns", [])
            for r in obj.content.get("rows", []):
                rows.append({c: (r[i] if i < len(r) else "") for i, c in enumerate(cols)})
            payload = json.dumps(rows, indent=2, ensure_ascii=False).encode()
            return ExportResult(payload, stem + ".json", "application/json",
                                ConversionKind.STRUCTURAL.value, "rows → JSON array")
        raise UnsafeInputError(f"text adapter cannot export {fmt!r}")

    def inspect(self, obj: UniversalObject) -> dict:
        rep = super().inspect(obj)
        text = obj.content.get("text", "")
        rep["structure"] = {
            "chars": len(text),
            "lines": text.count("\n") + 1,
            "headings": obj.content.get("headings", []),
            "columns": obj.content.get("columns", []),
            "row_count": obj.content.get("row_count"),
        }
        return rep


class _Det:
    def __init__(self, fid):
        self.format_id = fid


class MarkupAdapter(FormatAdapter):
    """HTML / XML — structured text documents."""

    name = "markup"
    version = "1.0"
    formats = {
        "html": FormatSpec("html", "HTML document", ["html", "htm"], "text/html", "TEXT",
                           SupportLevel.PARTIAL, read=True, create=True, edit=True, export=True,
                           detection="text-heuristic", notes="lenient parse via html.parser"),
        "xml": FormatSpec("xml", "XML document", ["xml"], "application/xml", "TEXT",
                          SupportLevel.PARTIAL, read=True, create=True, edit=True, export=True,
                          detection="text-heuristic", notes="ElementTree parse + raw text"),
    }
    capabilities = {
        "html": {"detect", "read", "parse", "edit", "export", "inspect"},
        "xml": {"detect", "read", "parse", "edit", "export", "inspect"},
    }
    input_types = [ObjectType.TEXT]
    output_types = [ObjectType.TEXT]

    def read(self, data: bytes, filename: str = "", detection=None) -> UniversalObject:
        fmt = detection.format_id if detection else (
            "html" if filename.lower().endswith((".html", ".htm")) else "xml")
        spec = self.formats[fmt]
        text, enc = _decode_text(data)
        obj = UniversalObject(
            object_type=ObjectType.TEXT,
            original_filename=filename,
            original_extension=fmt,
            detected_format=fmt,
            mime=spec.mime,
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=spec.support,
            adapter_name=self.name,
            adapter_version=self.version,
        )
        obj.content = {"kind": "structured", "format": fmt, "text": text, "raw": text}
        if fmt == "xml":
            try:
                root = ET.fromstring(text)
                obj.content["tree"] = _elem_to_dict(root)
                obj.content["root_tag"] = root.tag
            except ET.ParseError as exc:
                obj.warnings.append(f"XML parse error: {exc}")
                obj.support_level = SupportLevel.INSPECTION
        else:
            from html.parser import HTMLParser

            class _P(HTMLParser):
                def __init__(self):
                    super().__init__(convert_charrefs=True)
                    self.tags = {}
                    self.links = []
                    self.text = []
                    self.title = ""

                def handle_starttag(self, tag, attrs):
                    self.tags[tag] = self.tags.get(tag, 0) + 1
                    if tag == "a":
                        for k, v in attrs:
                            if k == "href":
                                self.links.append(v)

                def handle_data(self, d):
                    self.text.append(d)

            p = _P()
            try:
                p.feed(text)
                obj.content["tag_counts"] = dict(sorted(p.tags.items()))
                obj.content["links"] = p.links[:200]
                obj.content["text"] = "".join(p.text)[:LIMITS.max_text_chars]
            except Exception as exc:
                obj.warnings.append(f"HTML parse issue: {exc}")
        obj.record("import", f"imported {filename or fmt}")
        return obj

    def create(self, object_type=ObjectType.TEXT, params=None) -> UniversalObject:
        p = params or {}
        fmt = p.get("format", "html")
        body = p.get("text", "<html><head><title>New</title></head><body></body></html>")
        return self.read(body.encode(), p.get("filename", f"untitled.{fmt}"), _Det(fmt))

    def edit(self, obj, op, params=None):
        if op == "set_text":
            text = str((params or {}).get("text", ""))
            obj.content["text"] = text
            obj.content["raw"] = text
            obj.content["edited_bytes"] = {"__blob__": obj.add_blob(text.encode("utf-8"))}
            obj.record("edit.set_text", f"source replaced ({len(text)} chars)")
            return obj
        raise UnsafeInputError(f"markup adapter: unsupported edit {op!r}")

    def export_formats(self, obj) -> list:
        fid = getattr(obj, "detected_format", "")
        out = [opt("txt", "Plain text (.txt)", ConversionKind.STRUCTURAL, "text content only"),
               opt("html", "HTML document (.html)", ConversionKind.LOSSLESS if fid == "html" else ConversionKind.RECONSTRUCTED,
                    "as HTML")]
        if fid == "html":
            out.append(opt("md", "Markdown (.md)", ConversionKind.RECONSTRUCTED, "basic tag mapping"))
        out.append(opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                       "UniversalObject graph incl. original bytes"))
        return out

    def export(self, obj, fmt):
        stem = _stem(obj.original_filename)
        raw = obj.get_blob(obj.content.get("edited_bytes")) or obj.content.get("raw", "").encode("utf-8")
        if fmt in ("html", "xml"):
            ext = "html" if fmt == "html" else "xml"
            return ExportResult(raw, f"{stem}.{ext}", obj.mime or "text/html",
                                ConversionKind.LOSSLESS.value if fmt == obj.detected_format
                                else ConversionKind.RECONSTRUCTED.value)
        if fmt == "txt":
            return ExportResult(obj.content.get("text", "").encode("utf-8"), stem + ".txt",
                                "text/plain", ConversionKind.STRUCTURAL.value, "visible text only")
        if fmt == "md":
            text = obj.content.get("text", "")
            return ExportResult(f"<!-- converted from HTML -->\n\n{text}\n".encode(),
                                stem + ".md", "text/markdown", ConversionKind.RECONSTRUCTED.value,
                                "HTML text dumped to markdown (structure approximate)")
        raise UnsafeInputError(f"markup adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "root_tag": obj.content.get("root_tag"),
            "tag_counts": obj.content.get("tag_counts", {}),
            "links": len(obj.content.get("links", [])),
            "chars": len(obj.content.get("text", "")),
        }
        return rep


def _elem_to_dict(el) -> dict:
    return {
        "tag": el.tag,
        "attrs": dict(el.attrib),
        "text": (el.text or "").strip() or None,
        "children": [_elem_to_dict(c) for c in list(el)[:200]],
    }


# ---------------------------------------------------------------------------
# RTF helpers (subset)
# ---------------------------------------------------------------------------

_RTF_DESTS = ("fonttbl", "colortbl", "stylesheet", "info", "pict", "object",
              "header", "footer", "themedata", "colorschememapping", "latentstyles")

def rtf_extract(text: str) -> tuple:
    """Extract plain text + simple metadata from RTF (control-word subset)."""
    out = []
    meta = {}
    i = 0
    n = len(text)
    dest_skip = 0
    group_stack = []
    uc_skip = 0
    m = re.search(r"\\createtime\s+f(\d+)", text)
    if m:
        meta["has_createtime"] = True
    for word in ("createtim", "modtim", "revtim", "operator"):
        mm = re.search(r"\\" + word + r"([^\\{}]*)", text)
        if mm:
            meta[word] = mm.group(1).strip()[:40]

    while i < n:
        ch = text[i]
        if ch == "{":
            group_stack.append(dest_skip)
            i += 1
            continue
        if ch == "}":
            if group_stack:
                dest_skip = group_stack.pop()
            i += 1
            continue
        if ch == "\\":
            m = re.match(r"\\([a-zA-Z]+)(-?\d+)?[ ]?", text[i:])
            if m:
                word = m.group(1)
                i += m.end()
                if word == "destination" or word in _RTF_DESTS:
                    dest_skip += 1
                if word in ("par", "line", "pard") and not dest_skip:
                    out.append("\n")
                elif word == "tab" and not dest_skip:
                    out.append("\t")
                elif word == "emdash" and not dest_skip:
                    out.append("\u2014")
                elif word == "endash" and not dest_skip:
                    out.append("\u2013")
                elif word == "uc":
                    uc_skip = int(m.group(2) or 1)
                elif word == "u" and not dest_skip:
                    cp = int(m.group(2) or 32)
                    out.append(chr(cp if cp >= 0 else cp + 65536))
                continue
            m = re.match(r"\\'([0-9a-fA-F]{2})", text[i:])
            if m:
                if not dest_skip:
                    out.append(bytes([int(m.group(1), 16)]).decode("cp1252", "replace"))
                i += m.end()
                continue
            m = re.match(r"\\(.)", text[i:])
            if m:
                if not dest_skip and m.group(1) in ("{", "}", "\\"):
                    out.append(m.group(1))
                i += m.end()
                continue
            i += 1
            continue
        if not dest_skip:
            out.append(ch)
        i += 1
    plain = re.sub(r"\n{3,}", "\n\n", "".join(out)).strip()
    return plain, meta


def rtf_write(text: str) -> bytes:
    body = []
    for ch in text:
        if ch == "\\":
            body.append("\\\\")
        elif ch == "{":
            body.append("\\{")
        elif ch == "}":
            body.append("\\}")
        elif ch == "\n":
            body.append("\\par ")
        elif ord(ch) < 128:
            body.append(ch)
        else:
            body.append(f"\\u{ord(ch)}?")
    return ("{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Helvetica;}}\\f0 "
            + "".join(body) + "}").encode("ascii", "replace")


def _stem(name: str) -> str:
    base = (name or "object").replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[0] if "." in base else base


ADAPTERS = [TextAdapter(), MarkupAdapter()]

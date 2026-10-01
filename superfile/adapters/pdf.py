"""
SUPERFILE — PDF adapter (lightweight, zero-dependency).

Structural parse of the PDF xref-less object graph:

*  document info dictionary (/Producer /Creator /Title ...)
*  page tree (/Type /Page, MediaBox, Resources)
*  text extraction from content streams: uncompressed and FlateDecode,
   Tj / TJ / ' operators with WinAnsi-ish decoding

Honest limits: no font/CMap decoding (non-Latin encodings approximate),
no rendering (the UI embeds the PDF in the browser's viewer — RENDERED),
no encryption support (flagged instead).
"""

from __future__ import annotations

import re
import zlib

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import UnsafeInputError, hex_preview, sha256

MAX_STREAMS = 400
MAX_PAGES = 500


class PdfAdapter(FormatAdapter):
    name = "pdf"
    version = "1.0"
    formats = {
        "pdf": FormatSpec("pdf", "PDF document", ["pdf"], "application/pdf", "DOCUMENT",
                          SupportLevel.PARTIAL, read=True, create=True, export=True,
                          detection="magic",
                          notes="objects/pages/text extraction; render via browser (RENDERED)"),
    }
    capabilities = {"pdf": {"detect", "read", "parse", "decode", "create", "export", "inspect"}}
    input_types = [ObjectType.DOCUMENT]
    output_types = [ObjectType.DOCUMENT, ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = UniversalObject(
            object_type=ObjectType.DOCUMENT,
            original_filename=filename,
            original_extension="pdf",
            detected_format="pdf",
            mime="application/pdf",
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=SupportLevel.PARTIAL,
        )
        obj.record("import", f"imported {filename or 'pdf'}")
        obj.content = {"kind": "document", "format": "pdf"}
        text_head = data[:4096].decode("latin-1", "replace")
        m = re.search(r"%PDF-(\d\.\d)", text_head)
        obj.content["pdf_version"] = m.group(1) if m else "?"
        if re.search(r"/Encrypt\b", data[:20000].decode("latin-1", "replace")):
            obj.warnings.append("PDF is encrypted — content not parsed (bytes preserved)")
            obj.support_level = SupportLevel.INSPECTION
            return obj

        try:
            objects = _parse_objects(data)
            obj.content["object_count"] = len(objects)
            info = {}
            for oid, body in objects.items():
                if "/Info" in body or ("/Producer" in body and "/Title" in body):
                    for key in ("Title", "Author", "Subject", "Creator", "Producer",
                                "CreationDate", "ModDate", "Keywords"):
                        mm = re.search(rf"/{key}\s*\(((?:\\.|[^\\)])*)\)", body)
                        if mm:
                            info[key] = _pdf_unescape(mm.group(1))[:200]
            # follow trailer /Info reference
            tm = re.search(rb"/Info\s+(\d+)\s+\d+\s+R", data)
            if tm and not info:
                info_body = objects.get(int(tm.group(1)), b"")
                for key in ("Title", "Author", "Subject", "Creator", "Producer",
                            "CreationDate", "ModDate", "Keywords"):
                    mm = re.search(rf"/{key}\s*\(((?:\\.|[^\\)])*)\)", info_body)
                    if mm:
                        info[key] = _pdf_unescape(mm.group(1))[:200]
            obj.content["info"] = info
            obj.metadata.update(info)

            pages = []
            page_objs = [(oid, body) for oid, body in objects.items()
                         if re.search(r"/Type\s*/Page[^s]", body)][:MAX_PAGES]
            for idx, (oid, body) in enumerate(page_objs):
                mb = re.search(r"/MediaBox\s*\[\s*([-\d.\s]+)]", body)
                media = None
                if mb:
                    try:
                        media = [float(x) for x in mb.group(1).split()]
                    except ValueError:
                        media = None
                pages.append({"index": idx, "object": oid, "media_box": media, "text": ""})

            # text extraction from content streams
            texts = _extract_texts(data, objects)
            for i, page in enumerate(pages):
                if i < len(texts):
                    page["text"] = texts[i]
            if not pages and texts:
                pages = [{"index": i, "object": None, "media_box": None, "text": t}
                         for i, t in enumerate(texts)]
            obj.content["pages"] = pages
            obj.content["page_count"] = len(pages)
            obj.content["raw_text"] = "\n\n".join(p["text"] for p in pages)
            if not pages:
                obj.warnings.append("no page objects recognised (non-standard PDF structure)")
        except Exception as exc:
            obj.warnings.append(f"PDF parse issue: {exc}")
            obj.content["hex_preview"] = hex_preview(data)
        return obj

    def create(self, object_type=ObjectType.DOCUMENT, params=None) -> UniversalObject:
        """Create a minimal valid one-page PDF with text."""
        p = params or {}
        text = p.get("text", "Hello from SUPERFILE")
        title = p.get("title", "SUPERFILE document")
        data = build_simple_pdf(text, title)
        return self.read(data, p.get("filename", "created.pdf"), None)

    def export_formats(self, obj) -> list:
        return [
            opt("pdf", "PDF document (.pdf)", ConversionKind.LOSSLESS,
                "original bytes preserved"),
            opt("txt", "Extracted text (.txt)", ConversionKind.STRUCTURAL,
                "text operators only (no layout)"),
            opt("json", "Document report (.json)", ConversionKind.STRUCTURAL,
                "info + pages + media boxes"),
            opt("html", "Text in HTML (.html)", ConversionKind.RECONSTRUCTED,
                "extracted text wrapped in HTML"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "document").rsplit(".", 1)[0]
        if fmt == "pdf":
            return ExportResult(obj.original_bytes or b"", stem + ".pdf", "application/pdf",
                                ConversionKind.LOSSLESS.value)
        if fmt == "txt":
            return ExportResult(obj.content.get("raw_text", "").encode("utf-8"),
                                stem + ".txt", "text/plain", ConversionKind.STRUCTURAL.value,
                                "text operators only")
        if fmt == "json":
            import json
            payload = {k: v for k, v in obj.content.items()
                       if k in ("pdf_version", "info", "page_count", "pages")}
            return ExportResult(json.dumps(payload, indent=2, ensure_ascii=False).encode(),
                                stem + "_report.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        if fmt == "html":
            import html as html_mod
            body = "<pre>" + html_mod.escape(obj.content.get("raw_text", "")) + "</pre>"
            page = ("<!doctype html><html><head><meta charset='utf-8'><title>"
                    + html_mod.escape(stem) + "</title></head><body>" + body + "</body></html>")
            return ExportResult(page.encode(), stem + ".html", "text/html",
                                ConversionKind.RECONSTRUCTED.value)
        raise UnsafeInputError(f"pdf adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "pdf_version": obj.content.get("pdf_version"),
            "page_count": obj.content.get("page_count"),
            "object_count": obj.content.get("object_count"),
            "info": obj.content.get("info", {}),
            "extracted_chars": len(obj.content.get("raw_text", "")),
        }
        rep["format"]["render"] = "browser embed in UI (RENDERED) — no server-side rasteriser"
        return rep


# ---------------------------------------------------------------------------
# PDF internals
# ---------------------------------------------------------------------------

def _pdf_unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            mapping = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
                       "(": "(", ")": ")", "\\": "\\"}
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
            if nxt.isdigit():
                oct_ = s[i + 1:i + 4]
                out.append(chr(int(oct_, 8) & 0xFF))
                i += 1 + len(oct_)
                continue
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_objects(data: bytes) -> dict:
    """Collect 'N 0 obj ... endobj' bodies (regex-level, tolerant)."""
    objects = {}
    for m in re.finditer(rb"(\d+)\s+\d+\s+obj\b", data):
        oid = int(m.group(1))
        start = m.end()
        end = data.find(b"endobj", start)
        if end < 0:
            end = min(len(data), start + 200000)
        objects[oid] = data[start:end].decode("latin-1", "replace")
        if len(objects) > 5000:
            break
    return objects


def _stream_bodies(data: bytes, objects: dict) -> list:
    """Decompressed content streams (Flate or raw), capped."""
    streams = []
    for m in re.finditer(rb"stream\r?\n", data):
        if len(streams) >= MAX_STREAMS:
            break
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        raw = data[start:end]
        # look back at the dict for /Filter
        dict_start = data.rfind(b"<<", max(0, m.start() - 2000), m.start())
        dict_bytes = data[dict_start:m.start()] if dict_start >= 0 else b""
        try:
            if b"/FlateDecode" in dict_bytes:
                dec = zlib.decompress(raw)
            elif b"/Filter" in dict_bytes:
                continue  # unsupported filter — skip stream
            else:
                dec = raw
        except zlib.error:
            continue
        if b"Tj" in dec or b"TJ" in dec or b"Td" in dec:
            streams.append(dec)
    return streams


def _extract_texts(data: bytes, objects: dict) -> list:
    texts = []
    for stream in _stream_bodies(data, objects):
        texts.append(_text_from_content(stream))
    return texts


def _text_from_content(stream: bytes) -> str:
    """Pull strings out of Tj / TJ / ' operators, with T*/Td line breaks."""
    out = []
    src = stream.decode("latin-1", "replace")
    token_re = re.compile(
        r"\((?:\\.|[^\\)])*\)\s*(?:Tj|')|\[(?:[^\[\]]*)\]\s*TJ|T\*|T[dDm]\b", re.S)
    for m in token_re.finditer(src):
        tok = m.group(0)
        if tok.endswith(("Tj", "'")):
            inner = tok[1:tok.rindex(")")]
            out.append(_pdf_unescape(inner))
        elif tok.endswith("TJ"):
            for sm in re.finditer(r"\((?:\\.|[^\\)])*\)", tok):
                out.append(_pdf_unescape(sm.group(0)[1:-1]))
        else:
            out.append("\n")
    text = "".join(out)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:20000]


def build_simple_pdf(text: str, title: str = "SUPERFILE document") -> bytes:
    """Minimal valid single-page PDF with Helvetica text (uncompressed)."""
    import datetime
    now = datetime.datetime.utcnow().strftime("D:%Y%m%d%H%M%SZ")
    safe_title = title.replace("\\", "").replace("(", "").replace(")", "")[:80]
    lines = [ln[:90] for ln in text.split("\n")[:20]]
    content_parts = ["BT /F1 12 Tf 50 750 Td 14 TL"]
    for i, ln in enumerate(lines):
        esc = ln.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
        if i:
            content_parts.append("T*")
        content_parts.append(f"({esc}) Tj")
    content_parts.append("ET")
    stream = " ".join(content_parts).encode("latin-1", "replace")

    objs = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>")
    objs.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    info = (f"<< /Title ({safe_title}) /Producer (SUPERFILE prototype) "
            f"/CreationDate ({now}) /Creator (SUPERFILE) >>").encode()
    objs.append(info)

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objs)+1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R /Info 6 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n").encode()
    return bytes(out)


ADAPTERS = [PdfAdapter()]

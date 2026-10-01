"""
SUPERFILE — Document adapters: DOCX (OOXML) and EPUB.

Both are ZIP-based; we parse the XML parts for text and structure without any
Office library.  Honest support: PARTIAL (text + structure, no layout/render).
"""

from __future__ import annotations

import io
import json
import re
import zipfile
import xml.etree.ElementTree as ET

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import (
    LIMITS, UnsafeInputError, sanitize_archive_path, sha256,
)

_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


class DocxAdapter(FormatAdapter):
    name = "docx"
    version = "1.0"
    formats = {
        "docx": FormatSpec("docx", "Word document (OOXML)", ["docx"],
                           "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                           "DOCUMENT", SupportLevel.PARTIAL, read=True, create=True, export=True,
                           detection="container", notes="paragraph text + media list (no layout)"),
    }
    capabilities = {"docx": {"detect", "read", "parse", "decode", "create", "export", "inspect"}}
    input_types = [ObjectType.DOCUMENT]
    output_types = [ObjectType.DOCUMENT, ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = UniversalObject(
            object_type=ObjectType.DOCUMENT,
            original_filename=filename,
            original_extension="docx",
            detected_format="docx",
            mime=self.formats["docx"].mime,
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=SupportLevel.PARTIAL,
        )
        obj.record("import", f"imported {filename or 'docx'}")
        obj.content = {"kind": "document", "format": "docx"}
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            obj.warnings.append(f"invalid OOXML package: {exc}")
            return obj
        with zf:
            names = [sanitize_archive_path(n) for n in zf.namelist()]
            parts = [n for n in names if n]
            obj.content["parts"] = parts[:200]
            obj.content["media"] = [n for n in parts if n.startswith("word/media/")][:50]
            core = {}
            if "docProps/core.xml" in zf.namelist():
                try:
                    root = ET.fromstring(zf.read("docProps/core.xml"))
                    for el in root:
                        tag = el.tag.rsplit("}", 1)[-1]
                        if el.text:
                            core[tag] = el.text[:200]
                except ET.ParseError:
                    pass
            obj.content["core_properties"] = core
            obj.metadata.update(core)
            paragraphs = []
            if "word/document.xml" in zf.namelist():
                xml = zf.read("word/document.xml")[:4_000_000]
                try:
                    root = ET.fromstring(xml)
                    for p in root.iter(_W_NS + "p"):
                        runs = [t.text or "" for t in p.iter(_W_NS + "t")]
                        para = "".join(runs).strip()
                        if para:
                            paragraphs.append(para)
                        if len(paragraphs) >= 3000:
                            break
                except ET.ParseError as exc:
                    obj.warnings.append(f"document.xml parse issue: {exc}")
            obj.content["paragraphs"] = paragraphs
            obj.content["paragraph_count"] = len(paragraphs)
            obj.content["raw_text"] = "\n".join(paragraphs)
        return obj

    def create(self, object_type=ObjectType.DOCUMENT, params=None) -> UniversalObject:
        """Create a minimal valid DOCX package."""
        p = params or {}
        text = p.get("text", "Hello from SUPERFILE")
        paras = "".join(
            f"<w:p><w:r><w:t>{_xml_esc(line)}</w:t></w:r></w:p>"
            for line in text.split("\n")[:50])
        document = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body>{paras}</w:body></w:document>").encode()
        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd'
            '.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>").encode()
        rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/officeDocument" Target="word/document.xml"/></Relationships>').encode()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", content_types)
            zf.writestr("_rels/.rels", rels)
            zf.writestr("word/document.xml", document)
        return self.read(buf.getvalue(), p.get("filename", "created.docx"), None)

    def export_formats(self, obj) -> list:
        return [
            opt("docx", "Word document (.docx)", ConversionKind.LOSSLESS,
                "original package preserved"),
            opt("txt", "Plain text (.txt)", ConversionKind.STRUCTURAL, "paragraphs only"),
            opt("html", "HTML (.html)", ConversionKind.RECONSTRUCTED, "paragraphs as <p>"),
            opt("json", "Document report (.json)", ConversionKind.STRUCTURAL,
                "parts + paragraphs + properties"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        import html as html_mod
        stem = (obj.original_filename or "document").rsplit(".", 1)[0]
        if fmt == "docx":
            return ExportResult(obj.original_bytes or b"", stem + ".docx", self.formats["docx"].mime,
                                ConversionKind.LOSSLESS.value)
        if fmt == "txt":
            return ExportResult(obj.content.get("raw_text", "").encode("utf-8"),
                                stem + ".txt", "text/plain", ConversionKind.STRUCTURAL.value)
        if fmt == "html":
            paras = "".join(f"<p>{html_mod.escape(p)}</p>"
                            for p in obj.content.get("paragraphs", []))
            page = ("<!doctype html><html><head><meta charset='utf-8'><title>" +
                    html_mod.escape(stem) + "</title></head><body>" + paras + "</body></html>")
            return ExportResult(page.encode(), stem + ".html", "text/html",
                                ConversionKind.RECONSTRUCTED.value,
                                "text only — layout/styles dropped")
        if fmt == "json":
            payload = {k: v for k, v in obj.content.items() if k != "paragraphs"}
            return ExportResult(json.dumps(payload, indent=2, ensure_ascii=False).encode(),
                                stem + "_report.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError(f"docx adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "paragraph_count": obj.content.get("paragraph_count"),
            "parts": obj.content.get("parts", [])[:30],
            "media": obj.content.get("media", []),
            "core_properties": obj.content.get("core_properties", {}),
        }
        return rep


class EpubAdapter(FormatAdapter):
    name = "epub"
    version = "1.0"
    formats = {
        "epub": FormatSpec("epub", "EPUB book", ["epub"], "application/epub+zip", "DOCUMENT",
                           SupportLevel.PARTIAL, read=True, create=True, export=True,
                           detection="container", notes="OPF/spine parse + chapter text"),
    }
    capabilities = {"epub": {"detect", "read", "parse", "decode", "create", "export", "inspect"}}
    input_types = [ObjectType.DOCUMENT]
    output_types = [ObjectType.DOCUMENT, ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = UniversalObject(
            object_type=ObjectType.DOCUMENT,
            original_filename=filename,
            original_extension="epub",
            detected_format="epub",
            mime="application/epub+zip",
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=SupportLevel.PARTIAL,
        )
        obj.record("import", f"imported {filename or 'epub'}")
        obj.content = {"kind": "document", "format": "epub"}
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            obj.warnings.append(f"invalid EPUB package: {exc}")
            return obj
        with zf:
            names = zf.namelist()
            obj.content["parts"] = [sanitize_archive_path(n) for n in names if sanitize_archive_path(n)][:200]
            opf_path = None
            if "META-INF/container.xml" in names:
                try:
                    root = ET.fromstring(zf.read("META-INF/container.xml"))
                    for el in root.iter():
                        if el.tag.endswith("rootfile"):
                            opf_path = el.attrib.get("full-path")
                            break
                except ET.ParseError:
                    pass
            meta = {}
            spine = []
            if opf_path and opf_path in names:
                opf = zf.read(opf_path)[:1_000_000]
                try:
                    root = ET.fromstring(opf)
                    for el in root.iter():
                        tag = el.tag.rsplit("}", 1)[-1]
                        if tag in ("title", "creator", "language", "publisher", "date",
                                   "identifier") and el.text:
                            meta[tag] = el.text[:200]
                    ids = {}
                    for el in root.iter():
                        if el.tag.endswith("item"):
                            ids[el.attrib.get("id")] = el.attrib.get("href")
                    for el in root.iter():
                        if el.tag.endswith("itemref"):
                            href = ids.get(el.attrib.get("idref"))
                            if href:
                                spine.append(href)
                except ET.ParseError as exc:
                    obj.warnings.append(f"OPF parse issue: {exc}")
            obj.content["metadata"] = meta
            obj.content["spine"] = spine[:100]
            obj.metadata.update(meta)
            chapters = []
            base = opf_path.rsplit("/", 1)[0] + "/" if opf_path and "/" in opf_path else ""
            for href in spine[:30]:
                full = base + href.split("#")[0]
                if full in zf.namelist():
                    raw = zf.read(full)[:500_000]
                    text = _html_to_text(raw.decode("utf-8", "replace"))
                    chapters.append({"href": href, "chars": len(text), "text": text[:20000]})
                    obj.add_child(_text_child(href, text), relation="page_of",
                                  note="chapter text")
            obj.content["chapters"] = [{k: c[k] for k in ("href", "chars")} for c in chapters]
            obj.content["raw_text"] = "\n\n".join(c["text"] for c in chapters)
        return obj

    def create(self, object_type=ObjectType.DOCUMENT, params=None) -> UniversalObject:
        p = params or {}
        title = p.get("title", "SUPERFILE Book")
        text = p.get("text", "Hello from SUPERFILE")
        chapter = ("<?xml version='1.0' encoding='utf-8'?><html xmlns='http://www.w3.org/1999/xhtml'>"
                   f"<head><title>{_xml_esc(title)}</title></head><body><p>{_xml_esc(text)}</p></body></html>").encode()
        opf = (
            "<?xml version='1.0' encoding='utf-8'?>"
            "<package xmlns='http://www.idpf.org/2007/opf' version='2.0' unique-identifier='bid'>"
            "<metadata xmlns:dc='http://purl.org/dc/elements/1.1/'>"
            f"<dc:title>{_xml_esc(title)}</dc:title><dc:identifier id='bid'>superfile-demo</dc:identifier>"
            "<dc:language>en</dc:language></metadata>"
            "<manifest><item id='c1' href='chapter1.xhtml' media-type='application/xhtml+xml'/></manifest>"
            "<spine><itemref idref='c1'/></spine></package>").encode()
        container = (
            "<?xml version='1.0'?><container version='1.0' "
            "xmlns='urn:oasis:names:tc:opendocument:xmlns:container'><rootfiles>"
            "<rootfile full-path='OEBPS/content.opf' media-type='application/oebps-package+xml'/>"
            "</rootfiles></container>").encode()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("mimetype", "application/epub+zip", compress_type=zipfile.ZIP_STORED)
            zf.writestr("META-INF/container.xml", container)
            zf.writestr("OEBPS/content.opf", opf)
            zf.writestr("OEBPS/chapter1.xhtml", chapter)
        return self.read(buf.getvalue(), p.get("filename", "created.epub"), None)

    def export_formats(self, obj) -> list:
        return [
            opt("epub", "EPUB book (.epub)", ConversionKind.LOSSLESS, "original package preserved"),
            opt("txt", "Plain text (.txt)", ConversionKind.STRUCTURAL, "chapter text"),
            opt("html", "HTML (.html)", ConversionKind.RECONSTRUCTED, "chapter text as HTML"),
            opt("json", "Book report (.json)", ConversionKind.STRUCTURAL, "metadata + spine"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        import html as html_mod
        stem = (obj.original_filename or "book").rsplit(".", 1)[0]
        if fmt == "epub":
            return ExportResult(obj.original_bytes or b"", stem + ".epub", "application/epub+zip",
                                ConversionKind.LOSSLESS.value)
        if fmt == "txt":
            return ExportResult(obj.content.get("raw_text", "").encode("utf-8"),
                                stem + ".txt", "text/plain", ConversionKind.STRUCTURAL.value)
        if fmt == "html":
            body = "<pre>" + html_mod.escape(obj.content.get("raw_text", "")) + "</pre>"
            page = ("<!doctype html><html><head><meta charset='utf-8'><title>" +
                    html_mod.escape(stem) + "</title></head><body>" + body + "</body></html>")
            return ExportResult(page.encode(), stem + ".html", "text/html",
                                ConversionKind.RECONSTRUCTED.value)
        if fmt == "json":
            payload = {k: v for k, v in obj.content.items() if k != "raw_text"}
            return ExportResult(json.dumps(payload, indent=2, ensure_ascii=False).encode(),
                                stem + "_report.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError(f"epub adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "metadata": obj.content.get("metadata", {}),
            "spine": obj.content.get("spine", []),
            "chapters": obj.content.get("chapters", []),
        }
        return rep


def _html_to_text(html: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<br\s*/?>|</p>|</div>|</h[1-6]>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    import html as html_mod
    return re.sub(r"\n{3,}", "\n\n", html_mod.unescape(text)).strip()


def _text_child(name: str, text: str) -> UniversalObject:
    obj = UniversalObject(
        object_type=ObjectType.TEXT,
        original_filename=name.rsplit("/", 1)[-1] + ".txt",
        original_extension="txt",
        detected_format="txt",
        mime="text/plain",
        size=len(text.encode("utf-8")),
        checksum=sha256(text.encode("utf-8")),
        support_level=SupportLevel.FULL,
    )
    obj.content = {"kind": "text", "text": text, "encoding": "utf-8"}
    obj.record("import", f"extracted chapter {name}")
    return obj


def _xml_esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


ADAPTERS = [DocxAdapter(), EpubAdapter()]

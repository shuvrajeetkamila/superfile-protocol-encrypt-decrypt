"""
SUPERFILE — Source code adapters: C C++ Python JS Java Rust Go C# CSS (+ext)

Source is TEXT with language-aware stats and editor support.  Scripts are
treated as DATA — never executed.
"""

from __future__ import annotations

import re

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import UnsafeInputError, sha256

_LANGS = {
    "c": ("c", "C source", ["c", "h"], "text/x-c"),
    "cpp": ("cpp", "C++ source", ["cpp", "cc", "hpp", "cxx"], "text/x-c++"),
    "python": ("python", "Python source", ["py"], "text/x-python"),
    "javascript": ("javascript", "JavaScript source", ["js", "mjs"], "text/javascript"),
    "java": ("java", "Java source", ["java"], "text/x-java"),
    "rust": ("rust", "Rust source", ["rs"], "text/x-rust"),
    "go": ("go", "Go source", ["go"], "text/x-go"),
    "csharp": ("csharp", "C# source", ["cs"], "text/x-csharp"),
    "css": ("css", "CSS stylesheet", ["css"], "text/css"),
    "typescript": ("typescript", "TypeScript source", ["ts"], "text/x-typescript"),
    "shell": ("shell", "Shell script", ["sh"], "text/x-shellscript"),
    "ruby": ("ruby", "Ruby source", ["rb"], "text/x-ruby"),
    "c-header": ("c-header", "C header", ["h"], "text/x-c"),
    "cpp-header": ("cpp-header", "C++ header", ["hpp"], "text/x-c++"),
}

_FUNC_PATTERNS = {
    "python": re.compile(r"^\s*(def|class)\s+\w+", re.M),
    "javascript": re.compile(r"^\s*(function\s+\w+|const\s+\w+\s*=\s*(async\s*)?\(|class\s+\w+)", re.M),
    "c": re.compile(r"^\s*[\w\*]+\s+\**\w+\s*\([^;]*\)\s*\{?", re.M),
    "cpp": re.compile(r"^\s*[\w\:\*\&\s]+\s+\**\w+\s*\([^;]*\)\s*(const\s*)?\{?", re.M),
    "c-header": re.compile(r"^\s*[\w\*]+\s+\**\w+\s*\([^;]*\)\s*;", re.M),
    "cpp-header": re.compile(r"^\s*[\w\:\*\&\s]+\s+\**\w+\s*\([^;]*\)\s*;", re.M),
    "java": re.compile(r"^\s*(public|private|protected|static|class|interface|enum)[\w\s\<\>\[\]]*\(",
                       re.M),
    "rust": re.compile(r"^\s*(pub\s+)?(fn|struct|enum|trait|impl)\s+\w+", re.M),
    "go": re.compile(r"^\s*func\s+(\(\w+\s+\*?\w+\)\s+)?\w+\s*\(", re.M),
    "csharp": re.compile(r"^\s*(public|private|protected|internal|static|class|namespace)[\w\s\<\>\[\]]*[\(\{]",
                         re.M),
    "css": re.compile(r"^[^\s@\/\*][^{}]*\{", re.M),
    "shell": re.compile(r"^\s*(function\s+\w+|\w+\s*\(\)\s*\{)", re.M),
    "ruby": re.compile(r"^\s*(def|class|module)\s+\w+", re.M),
    "typescript": re.compile(r"^\s*(function\s+\w+|class\s+\w+|interface\s+\w+|type\s+\w+)", re.M),
}


class SourceAdapter(FormatAdapter):
    name = "source"
    version = "1.0"
    formats = {
        lang: FormatSpec(lang, disp, exts, mime, "SOURCE_CODE",
                         SupportLevel.FULL, read=True, create=True, edit=True, export=True,
                         detection="text-heuristic", notes="syntax-aware stats; never executed")
        for lang, (_fid, disp, exts, mime) in
        ((k, (k, v[1], v[2], v[3])) for k, v in _LANGS.items())
    }
    capabilities = {lang: {"detect", "read", "parse", "create", "edit", "encode", "export", "inspect"}
                    for lang in _LANGS}
    input_types = [ObjectType.SOURCE_CODE, ObjectType.TEXT]
    output_types = [ObjectType.SOURCE_CODE, ObjectType.TEXT]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        lang = None
        if detection and detection.format_id in _LANGS:
            lang = detection.format_id
        if lang is None:
            for k, v in _LANGS.items():
                if ext in v[2]:
                    lang = k
                    break
        lang = lang or "python"
        fid, disp, exts, mime = _LANGS[lang][0], _LANGS[lang][1], _LANGS[lang][2], _LANGS[lang][3]
        text = data.decode("utf-8", "replace")
        spec = self.formats.get(lang) or self.formats["python"]
        obj = UniversalObject(
            object_type=ObjectType.SOURCE_CODE,
            original_filename=filename,
            original_extension=ext or exts[0],
            detected_format=lang,
            mime=mime,
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=SupportLevel.FULL,
        )
        pat = _FUNC_PATTERNS.get(lang)
        defs = pat.findall(text) if pat else []
        if defs and isinstance(defs[0], tuple):
            defs = ["".join(d) for d in defs]
        obj.content = {
            "kind": "source", "language": lang, "text": text, "raw": text,
            "stats": {
                "lines": text.count("\n") + 1,
                "chars": len(text),
                "comment_lines": sum(1 for l in text.split("\n")
                                     if l.strip().startswith(("//", "#", "*", "/*"))),
                "blank_lines": sum(1 for l in text.split("\n") if not l.strip()),
                "definition_like": len(list(pat.finditer(text))) if pat else 0,
            },
            "declarations_sample": [str(d)[:60] for d in defs[:30]],
        }
        obj.record("import", f"imported {filename or lang} source ({lang})")
        obj.warnings.append("Source code is DATA — SUPERFILE never executes scripts")
        return obj

    def create(self, object_type=ObjectType.SOURCE_CODE, params=None) -> UniversalObject:
        p = params or {}
        lang = p.get("language", p.get("format", "python"))
        templates = {
            "python": "# SUPERFILE created source\n\ndef main():\n    print('hello from superfile')\n\nif __name__ == '__main__':\n    main()\n",
            "javascript": "// SUPERFILE created source\nfunction main() {\n  console.log('hello from superfile');\n}\nmain();\n",
            "c": "/* SUPERFILE created source */\n#include <stdio.h>\n\nint main(void) {\n    printf(\"hello from superfile\\n\");\n    return 0;\n}\n",
            "java": "// SUPERFILE created source\npublic class Main {\n    public static void main(String[] args) {\n        System.out.println(\"hello from superfile\");\n    }\n}\n",
            "rust": "// SUPERFILE created source\nfn main() {\n    println!(\"hello from superfile\");\n}\n",
            "go": "// SUPERFILE created source\npackage main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello from superfile\")\n}\n",
            "csharp": "// SUPERFILE created source\nusing System;\nclass Program {\n    static void Main() {\n        Console.WriteLine(\"hello from superfile\");\n    }\n}\n",
            "css": "/* SUPERFILE created stylesheet */\nbody {\n  font-family: monospace;\n  background: #101828;\n  color: #e6edf3;\n}\n",
        }
        text = p.get("text", templates.get(lang, templates["python"]))
        exts = _LANGS.get(lang, _LANGS["python"])[2]
        return self.read(text.encode(), p.get("filename", f"created.{exts[0]}"), _F(lang))

    def edit(self, obj, op, params=None):
        if op == "set_text":
            text = str((params or {}).get("text", ""))
            obj.content["text"] = text
            obj.content["raw"] = text
            obj.content["edited_bytes"] = {"__blob__": obj.add_blob(text.encode("utf-8"))}
            obj.record("edit.set_text", f"source replaced ({len(text)} chars)")
            return obj
        raise UnsafeInputError(f"source adapter: unsupported edit {op!r}")

    def export_formats(self, obj) -> list:
        lang = obj.detected_format
        ext = _LANGS.get(lang, (0, 0, ["txt"], 0))[2][0]
        out = [
            opt(lang, f"{_LANGS.get(lang, (0, 'Source'))[1]} (.{ext})",
                ConversionKind.LOSSLESS, "native source"),
            opt("txt", "Plain text (.txt)", ConversionKind.LOSSLESS, "source text"),
            opt("html", "HTML highlight page (.html)", ConversionKind.RECONSTRUCTED,
                "regex-based highlight render"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]
        return out

    def export(self, obj, fmt):
        import html as html_mod
        stem = (obj.original_filename or "source").rsplit(".", 1)[0]
        raw = obj.get_blob(obj.content.get("edited_bytes")) or obj.content.get("raw", "").encode()
        if fmt in (obj.detected_format, "txt"):
            ext = "txt" if fmt == "txt" else _LANGS.get(obj.detected_format, (0, 0, ["src"], 0))[2][0]
            return ExportResult(raw, f"{stem}.{ext}", "text/plain", ConversionKind.LOSSLESS.value)
        if fmt == "html":
            body = html_mod.escape(obj.content.get("text", ""))
            page = (f"<!doctype html><html><head><meta charset='utf-8'>"
                    f"<title>{html_mod.escape(obj.original_filename or 'source')}</title>"
                    f"<style>body{{background:#0d1117;color:#e6edf3;font:13px/1.5 monospace;"
                    f"padding:16px}} pre{{white-space:pre-wrap}}</style></head>"
                    f"<body><h3>{html_mod.escape(obj.original_filename or '')}"
                    f" <small>({obj.detected_format})</small></h3><pre>{body}</pre></body></html>")
            return ExportResult(page.encode(), stem + ".html", "text/html",
                                ConversionKind.RECONSTRUCTED.value)
        raise UnsafeInputError(f"source adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {"language": obj.content.get("language"),
                            "stats": obj.content.get("stats"),
                            "declarations_sample": obj.content.get("declarations_sample")}
        rep["format"]["note"] = "never executed — static representation only"
        return rep


class _F:
    def __init__(self, fid):
        self.format_id = fid


ADAPTERS = [SourceAdapter()]

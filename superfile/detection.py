"""
SUPERFILE — Format detection (magic bytes / file signatures)
============================================================

Detection NEVER relies on the file extension alone.  Every import runs through:

1.  magic-byte / structural signature matching (offset-aware),
2.  container sniffing (ZIP subtypes, RIFF form types, EBML doctypes ...),
3.  text/source heuristics,
4.  extension fallback *with reduced confidence*.

The result is a :class:`Detection` with an explicit confidence in [0, 1] and
the method that produced it, so the UI can show exactly why a format was
chosen.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from .security import looks_like_text


@dataclass
class Detection:
    format_id: str            # canonical id, e.g. "jpeg"
    display: str              # "JPEG image"
    mime: str
    extension: str            # canonical extension without dot
    confidence: float         # 0..1
    method: str               # "magic", "container", "text-heuristic", "extension"
    notes: str = ""
    family: str = ""          # object-type family hint

    def to_dict(self) -> dict:
        return {
            "format_id": self.format_id, "display": self.display, "mime": self.mime,
            "extension": self.extension, "confidence": self.confidence,
            "method": self.method, "notes": self.notes, "family": self.family,
        }


def _ext(name: str) -> str:
    if "." in name:
        return name.rsplit(".", 1)[-1].lower()
    return ""


# ---------------------------------------------------------------------------
# signature table: (sig, offset, format_id, display, mime, ext, family, notes)
# ---------------------------------------------------------------------------

_SIMPLE_SIGNATURES: list[tuple[bytes, int, str, str, str, str, str]] = [
    (b"\x89PNG\r\n\x1a\n", 0, "png", "PNG image", "image/png", "png", "IMAGE"),
    (b"\xff\xd8\xff", 0, "jpeg", "JPEG image", "image/jpeg", "jpg", "IMAGE"),
    (b"GIF87a", 0, "gif", "GIF image", "image/gif", "gif", "ANIMATION"),
    (b"GIF89a", 0, "gif", "GIF image", "image/gif", "gif", "ANIMATION"),
    (b"BM", 0, "bmp", "BMP image", "image/bmp", "bmp", "IMAGE"),
    (b"II*\x00", 0, "tiff", "TIFF image", "image/tiff", "tiff", "IMAGE"),
    (b"MM\x00*", 0, "tiff", "TIFF image", "image/tiff", "tiff", "IMAGE"),
    (b"%PDF-", 0, "pdf", "PDF document", "application/pdf", "pdf", "DOCUMENT"),
    (b"PK\x03\x04", 0, "zip", "ZIP archive", "application/zip", "zip", "ARCHIVE"),
    (b"PK\x05\x06", 0, "zip", "ZIP archive (empty)", "application/zip", "zip", "ARCHIVE"),
    (b"\x1f\x8b", 0, "gzip", "GZIP stream", "application/gzip", "gz", "ARCHIVE"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", "7-Zip archive", "application/x-7z-compressed", "7z", "ARCHIVE"),
    (b"\x7fELF", 0, "elf", "ELF binary", "application/x-elf", "elf", "EXECUTABLE"),
    (b"\x00asm", 0, "wasm", "WebAssembly module", "application/wasm", "wasm", "EXECUTABLE"),
    (b"fLaC", 0, "flac", "FLAC audio", "audio/flac", "flac", "AUDIO"),
    (b"OggS", 0, "ogg", "OGG container", "audio/ogg", "ogg", "AUDIO"),
    (b"RIFF", 0, "__riff__", "RIFF container", "application/octet-stream", "", "MULTIMEDIA_CONTAINER"),
    (b"\x1aE\xdf\xa3", 0, "__ebml__", "EBML / Matroska", "video/x-matroska", "mkv", "VIDEO"),
    (b"\x00\x00\x00\x00", 0, "__skip__", "", "", "", ""),
    (b"SQLite format 3\x00", 0, "sqlite", "SQLite database", "application/vnd.sqlite3", "sqlite", "DATABASE"),
    (b"glTF", 0, "glb", "glTF binary (GLB)", "model/gltf-binary", "glb", "3D"),
    (b"\x8bSFP\x0d\x0a\x1a\x0a", 0, "sfp", "SUPERFILE container", "application/x-superfile", "sfp", "PROTOCOL"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole", "OLE compound document", "application/x-ole-storage", "doc", "DOCUMENT"),
    (b"ID3", 0, "mp3", "MP3 audio (ID3 tag)", "audio/mpeg", "mp3", "AUDIO"),
    (b"\x10\x00\x00\x00wOFF", 0, "woff", "WOFF font", "font/woff", "woff", "BINARY"),
    (b"wOF2", 0, "woff2", "WOFF2 font", "font/woff2", "woff2", "BINARY"),
]

_STL_ASCII_RE = re.compile(rb"^\s*solid[\x20-\x7e]{0,80}?\s*(facet|endsolid)", re.S)

_SOURCE_EXT = {
    "py": ("python", "Python source", "text/x-python"),
    "js": ("javascript", "JavaScript source", "text/javascript"),
    "mjs": ("javascript", "JavaScript module", "text/javascript"),
    "ts": ("typescript", "TypeScript source", "text/x-typescript"),
    "c": ("c", "C source", "text/x-c"),
    "h": ("c-header", "C header", "text/x-c"),
    "cpp": ("cpp", "C++ source", "text/x-c++"),
    "cc": ("cpp", "C++ source", "text/x-c++"),
    "hpp": ("cpp-header", "C++ header", "text/x-c++"),
    "java": ("java", "Java source", "text/x-java"),
    "rs": ("rust", "Rust source", "text/x-rust"),
    "go": ("go", "Go source", "text/x-go"),
    "cs": ("csharp", "C# source", "text/x-csharp"),
    "css": ("css", "CSS stylesheet", "text/css"),
    "sh": ("shell", "Shell script", "text/x-shellscript"),
    "rb": ("ruby", "Ruby source", "text/x-ruby"),
}

_TEXT_EXT = {
    "txt": ("txt", "Plain text", "text/plain"),
    "log": ("txt", "Log text", "text/plain"),
    "md": ("md", "Markdown", "text/markdown"),
    "markdown": ("md", "Markdown", "text/markdown"),
    "csv": ("csv", "CSV table", "text/csv"),
    "tsv": ("csv", "TSV table", "text/tab-separated-values"),
    "json": ("json", "JSON data", "application/json"),
    "jsonl": ("json", "JSON Lines", "application/x-ndjson"),
    "xml": ("xml", "XML document", "application/xml"),
    "html": ("html", "HTML document", "text/html"),
    "htm": ("html", "HTML document", "text/html"),
    "svg": ("svg", "SVG image", "image/svg+xml"),
    "yaml": ("yaml", "YAML data", "application/yaml"),
    "yml": ("yaml", "YAML data", "application/yaml"),
    "toml": ("toml", "TOML data", "application/toml"),
    "rtf": ("rtf", "RTF document", "application/rtf"),
    "ini": ("ini", "INI config", "text/plain"),
    "obj": ("obj", "Wavefront OBJ mesh", "model/obj"),
    "stl": ("stl", "STL mesh", "model/stl"),
    "gltf": ("gltf", "glTF scene", "model/gltf+json"),
    "bson": ("bson", "BSON document", "application/bson"),
    "docx": ("docx", "Word document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "epub": ("epub", "EPUB book", "application/epub+zip"),
}

_AUDIO_EXT = {
    "wav": ("wav", "WAV audio", "audio/wav"),
    "mp3": ("mp3", "MP3 audio", "audio/mpeg"),
    "flac": ("flac", "FLAC audio", "audio/flac"),
    "ogg": ("ogg", "OGG audio", "audio/ogg"),
    "aac": ("aac", "AAC audio", "audio/aac"),
    "m4a": ("mp4", "MPEG-4 audio", "audio/mp4"),
}

_VIDEO_EXT = {
    "mp4": ("mp4", "MPEG-4 video", "video/mp4"),
    "m4v": ("mp4", "MPEG-4 video", "video/mp4"),
    "mkv": ("mkv", "Matroska video", "video/x-matroska"),
    "webm": ("webm", "WebM video", "video/webm"),
    "avi": ("avi", "AVI video", "video/x-msvideo"),
    "mov": ("mov", "QuickTime video", "video/quicktime"),
    "webp": ("webp", "WebP image", "image/webp"),
}

_EXEC_EXT = {
    "exe": ("pe", "PE executable", "application/vnd.microsoft.portable-executable"),
    "dll": ("pe", "PE library", "application/vnd.microsoft.portable-executable"),
    "sys": ("pe", "PE driver", "application/vnd.microsoft.portable-executable"),
    "elf": ("elf", "ELF binary", "application/x-elf"),
    "so": ("elf", "ELF shared object", "application/x-elf"),
    "o": ("elf", "ELF object", "application/x-elf"),
    "wasm": ("wasm", "WebAssembly module", "application/wasm"),
}

_ARCHIVE_EXT = {
    "zip": ("zip", "ZIP archive", "application/zip"),
    "jar": ("zip", "Java archive (ZIP)", "application/java-archive"),
    "tar": ("tar", "TAR archive", "application/x-tar"),
    "gz": ("gzip", "GZIP stream", "application/gzip"),
    "tgz": ("gzip", "GZIP stream (tarball)", "application/gzip"),
    "7z": ("7z", "7-Zip archive", "application/x-7z-compressed"),
}


def _ext_lookup(name: str) -> Detection | None:
    ext = _ext(name)
    for table in (_TEXT_EXT, _SOURCE_EXT, _AUDIO_EXT, _VIDEO_EXT, _EXEC_EXT, _ARCHIVE_EXT):
        if ext in table:
            fmt, disp, mime = table[ext]
            family = ""
            if table is _SOURCE_EXT:
                family = "SOURCE_CODE"
            elif table is _ARCHIVE_EXT:
                family = "ARCHIVE"
            elif table is _EXEC_EXT:
                family = "EXECUTABLE"
            elif table in (_AUDIO_EXT,):
                family = "AUDIO"
            elif table is _VIDEO_EXT:
                family = "VIDEO" if fmt not in ("webp",) else "IMAGE"
            elif table is _TEXT_EXT:
                family = {
                    "md": "TEXT", "txt": "TEXT", "csv": "TEXT",
                    "json": "TEXT", "xml": "TEXT", "html": "TEXT", "svg": "IMAGE",
                    "yaml": "TEXT", "toml": "TEXT", "rtf": "DOCUMENT",
                    "obj": "3D", "stl": "3D", "gltf": "3D", "glb": "3D",
                    "docx": "DOCUMENT", "epub": "DOCUMENT", "bson": "TEXT",
                }.get(fmt, "TEXT")
            return Detection(fmt, disp, mime, ext, 0.4, "extension",
                             "extension match only (no strong signature)", family)
    return None


def _sniff_riff(data: bytes) -> Detection | None:
    if len(data) < 12:
        return None
    form = data[8:12]
    if form == b"WAVE":
        return Detection("wav", "WAV audio", "audio/wav", "wav", 0.99, "magic",
                         "RIFF/WAVE container", "AUDIO")
    if form == b"AVI ":
        return Detection("avi", "AVI video", "video/x-msvideo", "avi", 0.99, "magic",
                         "RIFF/AVI container", "VIDEO")
    if form == b"WEBP":
        return Detection("webp", "WebP image", "image/webp", "webp", 0.99, "magic",
                         "RIFF/WEBP container", "IMAGE")
    return Detection("riff", "RIFF container", "application/octet-stream", "riff", 0.8,
                     "magic", "RIFF form: " + form.decode("latin-1", "replace"),
                     "MULTIMEDIA_CONTAINER")


def _sniff_ebml(data: bytes) -> Detection | None:
    """Distinguish Matroska vs WebM by DocType string."""
    head = data[:4096]
    if b"webm" in head:
        return Detection("webm", "WebM video", "video/webm", "webm", 0.95, "container",
                         "EBML DocType 'webm'", "VIDEO")
    if b"matroska" in head:
        return Detection("mkv", "Matroska video", "video/x-matroska", "mkv", 0.95, "container",
                         "EBML DocType 'matroska'", "VIDEO")
    return Detection("mkv", "Matroska/EBML container", "video/x-matroska", "mkv", 0.7,
                     "magic", "EBML header without recognised DocType", "VIDEO")


def _sniff_mp4_family(data: bytes) -> Detection | None:
    """ISO-BMFF: [size][ftyp][brand]."""
    if len(data) < 12 or data[4:8] != b"ftyp":
        return None
    brand = data[8:12]
    brands = {b"qt  ": ("mov", "QuickTime video", "video/quicktime", "mov", "VIDEO"),
              b"isom": ("mp4", "MPEG-4 video", "video/mp4", "mp4", "VIDEO"),
              b"mp41": ("mp4", "MPEG-4 video", "video/mp4", "mp4", "VIDEO"),
              b"mp42": ("mp4", "MPEG-4 video", "video/mp4", "mp4", "VIDEO"),
              b"avc1": ("mp4", "MPEG-4 video", "video/mp4", "mp4", "VIDEO"),
              b"M4A ": ("mp4", "MPEG-4 audio", "audio/mp4", "m4a", "AUDIO"),
              b"M4V ": ("mp4", "MPEG-4 video", "video/mp4", "m4v", "VIDEO"),
              b"3gp4": ("mp4", "3GPP video", "video/3gpp", "3gp", "VIDEO"),
              b"heic": ("heic", "HEIF image", "image/heic", "heic", "IMAGE"),
              b"avif": ("avif", "AVIF image", "image/avif", "avif", "IMAGE"),
              }
    info = brands.get(brand)
    if info:
        fmt, disp, mime, ext, fam = info
        return Detection(fmt, disp, mime, ext, 0.97, "container", f"ISO-BMFF ftyp brand '{brand.decode('latin-1')}'", fam)
    return Detection("mp4", "ISO-BMFF container", "video/mp4", "mp4", 0.85, "container",
                     f"ISO-BMFF ftyp brand '{brand.decode('latin-1', 'replace')}'", "MULTIMEDIA_CONTAINER")


def _sniff_zip(data: bytes) -> Detection | None:
    """Look inside a ZIP to identify OOXML / EPUB / JAR vs plain ZIP."""
    names: list[bytes] = []
    pos = 0
    while pos + 30 < len(data) and len(names) < 40:
        if data[pos:pos + 4] != b"PK\x03\x04":
            break
        nlen = struct.unpack_from("<H", data, pos + 26)[0]
        elen = struct.unpack_from("<H", data, pos + 28)[0]
        csize = struct.unpack_from("<I", data, pos + 18)[0]
        name = data[pos + 30:pos + 30 + nlen]
        names.append(name)
        # cannot reliably skip compressed data without central directory;
        # scan forward for the next local header instead
        nxt = data.find(b"PK\x03\x04", pos + 30 + nlen + elen)
        if nxt < 0:
            break
        pos = nxt
    joined = b"\n".join(names)
    if b"mimetype" in joined and b"application/epub+zip" in data[:8192]:
        return Detection("epub", "EPUB book", "application/epub+zip", "epub", 0.95,
                         "container", "ZIP with EPUB mimetype entry", "DOCUMENT")
    if b"word/document.xml" in joined or b"[Content_Types].xml" in joined and b"word/" in joined:
        return Detection("docx", "Word document (OOXML)",
                         "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                         "docx", 0.95, "container", "ZIP with OOXML word/ part", "DOCUMENT")
    if b"ppt/" in joined:
        return Detection("pptx", "PowerPoint (OOXML)",
                         "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                         "pptx", 0.9, "container", "ZIP with OOXML ppt/ part", "DOCUMENT")
    if b"xl/" in joined:
        return Detection("xlsx", "Excel (OOXML)",
                         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         "xlsx", 0.9, "container", "ZIP with OOXML xl/ part", "DOCUMENT")
    if b"META-INF/MANIFEST.MF" in joined:
        return Detection("jar", "Java archive (ZIP)", "application/java-archive", "jar", 0.9,
                         "container", "ZIP with Java manifest", "ARCHIVE")
    return Detection("zip", "ZIP archive", "application/zip", "zip", 0.97, "magic",
                     "PKZIP local headers", "ARCHIVE")


def _sniff_gzip_inner(data: bytes) -> Detection | None:
    """GZIP that wraps a tar is really a tarball."""
    det = Detection("gzip", "GZIP stream", "application/gzip", "gz", 0.97, "magic",
                    "GZIP member header", "ARCHIVE")
    # 10-byte header + optional fields then payload; check for 'ustar' near start
    # of the decompressed stream is left to the adapter — detection stays cheap.
    if _ext("") == "":
        pass
    return det


def _sniff_text(data: bytes, name: str) -> Detection | None:
    ok, conf = looks_like_text(data)
    if not ok:
        return None
    try:
        sample = data[:4096].decode("utf-8", "strict")
    except UnicodeDecodeError:
        sample = data[:4096].decode("latin-1", "replace")
    stripped = sample.lstrip()
    ext = _ext(name)

    # strong text magics first (before structural heuristics)
    if stripped.startswith("{\\rtf"):
        return Detection("rtf", "RTF document", "application/rtf", "rtf",
                         min(0.95, conf), "text-heuristic", "{\\rtf header", "DOCUMENT")

    if stripped.startswith("{") or stripped.startswith("["):
        if ext in ("json", "jsonl") or _looks_json(sample):
            return Detection("json", "JSON data", "application/json", "json",
                             min(0.9, conf), "text-heuristic", "JSON punctuation + structure", "TEXT")
    if stripped.startswith("<?xml") or (stripped.startswith("<") and ext == "xml"):
        return Detection("xml", "XML document", "application/xml", "xml",
                         min(0.85, conf), "text-heuristic", "XML declaration/structure", "TEXT")
    if ext in ("html", "htm") or re.search(r"<!doctype\s+html|<html[\s>]", sample[:1024], re.I):
        return Detection("html", "HTML document", "text/html", "html",
                         min(0.9, conf), "text-heuristic", "HTML structure", "TEXT")
    if ext == "svg" or ("<svg" in sample[:2048] and "xmlns" in sample[:4096]):
        return Detection("svg", "SVG image", "image/svg+xml", "svg",
                         min(0.9, conf), "text-heuristic", "<svg> root element", "IMAGE")
    if ext in ("yaml", "yml") or (re.match(r"^[A-Za-z_][\w\-]*:\s*\S", sample[:2000], re.M) and ":" in sample.split("\n")[0]):
        if ext in ("yaml", "yml", "txt", ""):
            return Detection("yaml", "YAML data", "application/yaml", "yaml",
                             min(0.7, conf) if ext in ("yaml", "yml") else 0.45,
                             "text-heuristic", "key: value structure", "TEXT")
    if ext == "toml" or stripped.startswith("["):
        if ext == "toml" or re.match(r"^\[[\w.\-]+\]", stripped):
            return Detection("toml", "TOML data", "application/toml", "toml",
                             min(0.75, conf), "text-heuristic", "[table] + key = value", "TEXT")
    if ext == "csv" or ("," in sample.split("\n")[0] and sample.count("\n") >= 1
                        and _looks_like_csv(sample)):
        return Detection("csv", "CSV table", "text/csv", "csv",
                         min(0.8, conf) if ext == "csv" else 0.55,
                         "text-heuristic", "delimited rows of equal field count", "TEXT")
    if ext == "md" or re.search(r"^#{1,6}\s|\*\*.+\*\*|\[.+\]\(.+\)", sample[:2000], re.M):
        if ext in ("md", "markdown", "txt", ""):
            return Detection("md", "Markdown", "text/markdown", "md",
                             min(0.8, conf) if ext in ("md", "markdown") else 0.5,
                             "text-heuristic", "markdown constructs", "TEXT")
    if ext == "obj" or sample.lstrip().startswith(("v ", "o ", "# Wavefront")):
        if ext == "obj" or re.search(r"^v\s+-?\d", sample[:2000], re.M):
            return Detection("obj", "Wavefront OBJ mesh", "model/obj", "obj",
                             min(0.8, conf), "text-heuristic", "OBJ vertex records", "3D")
    if ext == "rtf" or stripped.startswith("{\\rtf"):
        return Detection("rtf", "RTF document", "application/rtf", "rtf",
                         min(0.9, conf), "text-heuristic", "{\\rtf header", "DOCUMENT")
    if ext in _SOURCE_EXT:
        fmt, disp, mime = _SOURCE_EXT[ext]
        return Detection(fmt, disp, mime, ext, min(0.75, conf), "text-heuristic",
                         "text + known source extension", "SOURCE_CODE")
    if ext in ("txt", "log", ""):
        return Detection("txt", "Plain text", "text/plain", "txt", conf,
                         "text-heuristic", "printable text", "TEXT")
    return Detection("txt", "Plain text (unknown subtype)", "text/plain", "txt",
                     round(conf * 0.8, 2), "text-heuristic", "printable text, no structure matched",
                     "TEXT")


def _looks_json(sample: str) -> bool:
    s = sample.strip()
    if s[:1] not in "[{\"":
        return False
    if s.startswith("{\\"):      # RTF and friends
        return False
    depth = 0
    in_str = False
    esc = False
    for ch in s[:2000]:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
    return depth <= 0


def _looks_like_csv(sample: str) -> bool:
    rows = [r for r in sample.splitlines() if r.strip()][:12]
    if len(rows) < 2:
        return False
    counts = [r.count(",") for r in rows]
    return len(set(counts)) == 1 and counts[0] >= 1


def detect_format(data: bytes, filename: str = "") -> Detection:
    """Master detection routine.  Never trusts the extension alone."""
    if not data:
        return Detection("empty", "Empty file", "application/x-empty", _ext(filename),
                         1.0, "magic", "zero-byte file", "BINARY")

    # 1. simple signatures
    for sig, off, fmt, disp, mime, ext, family in _SIMPLE_SIGNATURES:
        if fmt == "__skip__":
            continue
        if data[off:off + len(sig)] == sig:
            if fmt == "__riff__":
                return _sniff_riff(data)
            if fmt == "__ebml__":
                return _sniff_ebml(data)
            det = Detection(fmt, disp, mime, ext or _ext(filename), 0.99, "magic",
                            f"signature {sig[:8]!r}", family)
            if fmt == "zip":
                sub = _sniff_zip(data)
                return sub or det
            if fmt == "gzip":
                return _sniff_gzip_inner(data)
            return det

    # 2. ISO-BMFF family (mp4/mov/m4a...)
    det = _sniff_mp4_family(data)
    if det:
        return det

    # 3. TAR (ustar magic at offset 257)
    if len(data) > 262 and data[257:262] in (b"ustar", b"ustar\x00"[:5]):
        return Detection("tar", "TAR archive", "application/x-tar", "tar", 0.95,
                         "magic", "ustar magic at offset 257", "ARCHIVE")

    # 4. STL ascii
    if _STL_ASCII_RE.match(data[:256]):
        return Detection("stl", "STL mesh (ASCII)", "model/stl", "stl", 0.85,
                         "text-heuristic", "ASCII 'solid ... facet' structure", "3D")

    # 5. binary STL: 80-byte header + u32 triangle count consistent with size
    if len(data) >= 84 and len(data) < 200_000_000:
        (ntri,) = struct.unpack_from("<I", data, 80)
        if ntri > 0 and 84 + ntri * 50 == len(data):
            return Detection("stl", "STL mesh (binary)", "model/stl", "stl", 0.95,
                             "magic", "binary STL triangle table matches file size", "3D")

    # 6. PE / MZ
    if data[:2] == b"MZ":
        det = Detection("pe", "PE executable", "application/vnd.microsoft.portable-executable",
                        "exe", 0.9, "magic", "MZ DOS stub", "EXECUTABLE")
        if len(data) > 0x40:
            (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
            if 0 < e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\0\0":
                det.confidence = 0.99
                det.notes = "MZ + PE\\0\\0 signature"
                det.extension = "dll" if _ext(filename) == "dll" else "exe"
                return det
        return det

    # 7. AAC ADTS sync
    if len(data) > 2 and data[0] == 0xFF and (data[1] & 0xF6) == 0xF0:
        return Detection("aac", "AAC audio (ADTS)", "audio/aac", "aac", 0.7,
                         "magic", "ADTS syncword", "AUDIO")

    # 8. MP3 frame sync (no ID3)
    if len(data) > 4 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
        return Detection("mp3", "MP3 audio (MPEG frame)", "audio/mpeg", "mp3", 0.7,
                         "magic", "MPEG audio frame sync", "AUDIO")

    # 9. BSON heuristic: little-endian doc size == len(data)
    if 5 <= len(data) <= 16_000_000:
        (dsize,) = struct.unpack_from("<I", data, 0)
        if dsize == len(data) and data[-1] == 0x00:
            return Detection("bson", "BSON document", "application/bson", "bson", 0.6,
                             "text-heuristic", "BSON document length prefix", "TEXT")

    # 10. text / source heuristics
    det = _sniff_text(data, filename)
    if det:
        return det

    # 11. extension fallback (low confidence)
    det = _ext_lookup(filename)
    if det:
        return det

    return Detection("blob", "Unknown binary", "application/octet-stream", _ext(filename),
                     0.3, "extension", "no signature matched — preserved as raw bytes", "BINARY")


def detect_magic_report(data: bytes, filename: str = "") -> dict:
    """Richer report for the inspector: matched signature + first bytes."""
    det = detect_format(data, filename)
    report = det.to_dict()
    report["head_bytes_hex"] = data[:16].hex(" ")
    report["head_bytes_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:16])
    report["extension"] = _ext(filename)
    return report

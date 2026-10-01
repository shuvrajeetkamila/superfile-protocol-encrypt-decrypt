"""
SUPERFILE — Archive adapters: ZIP TAR GZIP 7Z

Security: path traversal sanitised, expansion ratio + absolute size capped,
symlink/hardlink entries never extracted, entry count limited.  Extracted
entries become nested UniversalObjects (children).
"""

from __future__ import annotations

import gzip
import io
import json
import struct
import tarfile
import zipfile

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import (
    LIMITS, LimitExceededError, UnsafeInputError, check_extraction_budget,
    hex_preview, safe_filename, sanitize_archive_path, sha256,
)
from ..detection import detect_format


def _make(fmt, spec, data, filename) -> UniversalObject:
    obj = UniversalObject(
        object_type=ObjectType.ARCHIVE,
        original_filename=filename,
        original_extension=fmt,
        detected_format=fmt,
        mime=spec.mime,
        size=len(data),
        original_bytes=data,
        checksum=sha256(data),
        support_level=spec.support,
    )
    obj.record("import", f"imported {filename or fmt}")
    obj.content = {"kind": "archive", "format": fmt, "entries": []}
    return obj


def _entry(path, size, csize=None, is_dir=False, extra=None) -> dict:
    e = {"path": path, "size": size, "compressed_size": csize, "is_dir": is_dir}
    if extra:
        e.update(extra)
    return e


class ZipAdapter(FormatAdapter):
    name = "zip"
    version = "1.0"
    formats = {
        "zip": FormatSpec("zip", "ZIP archive", ["zip", "jar"], "application/zip", "ARCHIVE",
                          SupportLevel.FULL, read=True, create=True, edit=False, export=True,
                          detection="magic", notes="zipfile + safe extraction into child objects"),
    }
    capabilities = {"zip": {"detect", "read", "parse", "create", "encode", "export", "inspect"}}
    input_types = [ObjectType.ARCHIVE]
    output_types = [ObjectType.ARCHIVE, ObjectType.DIRECTORY]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = _make("zip", self.formats["zip"], data, filename)
        entries = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            obj.warnings.append(f"invalid ZIP: {exc}")
            obj.support_level = SupportLevel.INSPECTION
            obj.content["hex_preview"] = hex_preview(data)
            return obj
        with zf:
            infos = zf.infolist()
            if len(infos) > LIMITS.max_archive_entries:
                raise LimitExceededError("too many ZIP entries")
            total_unc = 0
            for info in infos:
                name = sanitize_archive_path(info.filename)
                if not name and info.filename not in ("", ".", "./"):
                    obj.warnings.append(f"skipped unsafe path: {info.filename!r}")
                    continue
                if info.is_dir() or name.endswith("/"):
                    entries.append(_entry(name or info.filename, 0, 0, True))
                    continue
                if stat_is_symlink(info):
                    obj.warnings.append(f"skipped symlink entry: {info.filename!r}")
                    continue
                total_unc += info.file_size
                entries.append(_entry(name or safe_filename(info.filename),
                                      info.file_size, info.compress_size,
                                      False, {"crc": f"{info.CRC:08x}"}))
                if len(entries) >= LIMITS.max_archive_entries:
                    break
            check_extraction_budget(total_unc, len(data), len(entries))
            obj.content["entries"] = entries
            obj.content["entry_count"] = len(entries)
            obj.content["total_uncompressed"] = total_unc
        return obj

    def create(self, object_type=ObjectType.ARCHIVE, params=None) -> UniversalObject:
        p = params or {}
        items = p.get("items") or [{"name": "readme.txt",
                                    "data": b"SUPERFILE demo archive\n"}]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for it in items:
                name = sanitize_archive_path(it.get("name", "file.txt")) or "file.txt"
                zf.writestr(name, it.get("data", b""))
        return self.read(buf.getvalue(), p.get("filename", "created.zip"), None)

    def export_formats(self, obj) -> list:
        return [
            opt("zip", "ZIP archive (.zip)", ConversionKind.STRUCTURAL, "original archive preserved"),
            opt("json", "Entry listing (.json)", ConversionKind.STRUCTURAL, "paths + sizes"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "entries as nested UniversalObjects + original bytes"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "archive").rsplit(".", 1)[0]
        if fmt == "zip":
            return ExportResult(obj.original_bytes or b"", stem + ".zip", "application/zip",
                                ConversionKind.LOSSLESS.value, "original bytes preserved")
        if fmt == "json":
            return ExportResult(json.dumps(obj.content.get("entries", []), indent=2).encode(),
                                stem + "_entries.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError(f"zip adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "entry_count": obj.content.get("entry_count"),
            "total_uncompressed": obj.content.get("total_uncompressed"),
            "entries": [e["path"] for e in obj.content.get("entries", [])][:100],
        }
        return rep


def stat_is_symlink(info) -> bool:
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


class TarGzAdapter(FormatAdapter):
    name = "tar-gz"
    version = "1.0"
    formats = {
        "tar": FormatSpec("tar", "TAR archive", ["tar"], "application/x-tar", "ARCHIVE",
                          SupportLevel.FULL, read=True, create=True, export=True,
                          detection="magic", notes="tarfile, safe member listing"),
        "gzip": FormatSpec("gzip", "GZIP stream", ["gz", "tgz"], "application/gzip", "ARCHIVE",
                           SupportLevel.PARTIAL, read=True, create=True, export=True,
                           detection="magic", notes="single-member decompress (capped)"),
    }
    capabilities = {
        "tar": {"detect", "read", "parse", "create", "encode", "export", "inspect"},
        "gzip": {"detect", "read", "parse", "create", "encode", "export", "inspect"},
    }
    input_types = [ObjectType.ARCHIVE]
    output_types = [ObjectType.ARCHIVE, ObjectType.TEXT, ObjectType.BINARY]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        fmt = detection.format_id if detection else (
            "gzip" if data[:2] == b"\x1f\x8b" else "tar")
        if fmt == "gzip":
            return self._read_gzip(data, filename)
        return self._read_tar(data, filename)

    def _read_tar(self, data, filename) -> UniversalObject:
        obj = _make("tar", self.formats["tar"], data, filename)
        entries = []
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        except tarfile.TarError as exc:
            obj.warnings.append(f"invalid TAR: {exc}")
            obj.content["hex_preview"] = hex_preview(data)
            return obj
        with tf:
            total = 0
            for member in tf.getmembers()[:LIMITS.max_archive_entries]:
                name = sanitize_archive_path(member.name)
                if not name:
                    obj.warnings.append(f"skipped unsafe path: {member.name!r}")
                    continue
                if member.issym() or member.islnk():
                    obj.warnings.append(f"skipped link entry: {member.name!r}")
                    continue
                entries.append(_entry(name, member.size, None, member.isdir(),
                                      {"mtime": member.mtime, "mode": oct(member.mode)}))
                total += max(0, member.size)
            check_extraction_budget(total, len(data), len(entries))
        obj.content.update({"entries": entries, "entry_count": len(entries),
                            "total_uncompressed": total})
        return obj

    def _read_gzip(self, data, filename) -> UniversalObject:
        obj = _make("gzip", self.formats["gzip"], data, filename)
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                # capped read — refuse zip-bombs
                unc = gz.read(LIMITS.max_extract_entry_bytes + 1)
            if len(unc) > LIMITS.max_extract_entry_bytes:
                raise LimitExceededError("gzip member expands beyond extract limit")
            check_extraction_budget(len(unc), len(data), 1)
        except (OSError, LimitExceededError) as exc:
            obj.warnings.append(f"gzip issue: {exc}")
            obj.content["hex_preview"] = hex_preview(data)
            return obj
        obj.content["entries"] = [_entry("member", len(unc), len(data))]
        obj.content["entry_count"] = 1
        obj.content["total_uncompressed"] = len(unc)
        obj.content["_member"] = obj.blob_ref(unc)
        # is the member a tar?
        if len(unc) > 262 and unc[257:262] == b"ustar":
            obj.content["member_kind"] = "tar"
            obj.detected_format = "gzip"
            obj.content["inner"] = "tar"
            try:
                inner = self._read_tar(unc, (filename or "member") + ".tar")
                obj.add_child(inner, relation="contains", note="decompressed tar member")
                obj.content["entries"] = inner.content.get("entries", [])
                obj.content["entry_count"] = inner.content.get("entry_count", 0)
            except Exception as exc:
                obj.warnings.append(f"inner tar parse failed: {exc}")
        else:
            det = detect_format(unc, "")
            obj.content["member_kind"] = det.format_id
            obj.content["member_detection"] = det.to_dict()
        return obj

    def create(self, object_type=ObjectType.ARCHIVE, params=None) -> UniversalObject:
        p = params or {}
        items = p.get("items") or [{"name": "readme.txt", "data": b"SUPERFILE tar demo\n"}]
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for it in items:
                name = sanitize_archive_path(it.get("name", "file.txt")) or "file.txt"
                raw = it.get("data", b"")
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                tf.addfile(info, io.BytesIO(raw))
        if p.get("gzip", True):
            gz = io.BytesIO()
            with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
                g.write(buf.getvalue())
            return self.read(gz.getvalue(), p.get("filename", "created.tar.gz"), _F("gzip"))
        return self.read(buf.getvalue(), p.get("filename", "created.tar"), _F("tar"))

    def export_formats(self, obj) -> list:
        fid = obj.detected_format
        return [
            opt(fid, f"{fid.upper()} (.{fid})", ConversionKind.LOSSLESS, "original bytes preserved"),
            opt("json", "Entry listing (.json)", ConversionKind.STRUCTURAL, "paths + sizes"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "entries as nested UniversalObjects + original bytes"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "archive").split(".")[0]
        if fmt in ("tar", "gzip"):
            return ExportResult(obj.original_bytes or b"", f"{stem}.{fmt}",
                                self.formats[fmt].mime, ConversionKind.LOSSLESS.value)
        if fmt == "json":
            return ExportResult(json.dumps(obj.content.get("entries", []), indent=2).encode(),
                                stem + "_entries.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError(f"tar adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "entry_count": obj.content.get("entry_count"),
            "member_kind": obj.content.get("member_kind"),
            "entries": [e["path"] for e in obj.content.get("entries", [])][:100],
        }
        return rep


class SevenZAdapter(FormatAdapter):
    """7Z — header/signature inspection only (no LZMA SDK bundled)."""

    name = "7z"
    version = "1.0"
    formats = {
        "7z": FormatSpec("7z", "7-Zip archive", ["7z"], "application/x-7z-compressed", "ARCHIVE",
                         SupportLevel.INSPECTION, read=True,
                         detection="magic", notes="signature + version header (no decompression)"),
    }
    capabilities = {"7z": {"detect", "read", "parse", "inspect"}}
    input_types = [ObjectType.ARCHIVE]
    output_types = [ObjectType.ARCHIVE]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = _make("7z", self.formats["7z"], data, filename)
        if data[:6] == b"7z\xbc\xaf\x27\x1c":
            ver = f"{data[6]}.{data[7]}"
            (start_hdr_crc,) = struct.unpack_from("<I", data, 8)
            (next_off, next_size, next_crc) = struct.unpack_from("<QQI", data, 12)
            obj.content.update({
                "version": ver,
                "start_header_crc": f"{start_hdr_crc:08x}",
                "next_header_offset": next_off,
                "next_header_size": next_size,
                "next_header_crc": f"{next_crc:08x}",
            })
            obj.warnings.append(
                "7Z: signature and header parsed; decompression is NOT implemented "
                "(no LZMA SDK bundled) — original bytes preserved")
        else:
            obj.warnings.append("not a 7Z signature")
        obj.content["hex_preview"] = hex_preview(data)
        return obj

    def export_formats(self, obj) -> list:
        return [opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                    "original bytes preserved inside SUPERFILE")]

    def export(self, obj, fmt):
        raise UnsafeInputError("7z adapter: only .sfp export (use the SUPERFILE saver)")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {k: obj.content.get(k) for k in
                            ("version", "next_header_offset", "next_header_size")}
        return rep


class _F:
    def __init__(self, fid):
        self.format_id = fid


# ---------------------------------------------------------------------------
# shared extraction: archive entries -> child UniversalObjects
# ---------------------------------------------------------------------------

def extract_children(obj: UniversalObject, limit: int = 200) -> int:
    """Parse archive entries into nested UniversalObjects (safe + limited)."""
    from ..pipeline import import_bytes  # late import (pipeline uses adapters)
    data = obj.original_bytes
    if data is None:
        raise UnsafeInputError("archive original bytes missing")
    count = 0
    names = []

    def _add(name: str, raw: bytes):
        nonlocal count
        if count >= limit:
            return
        det = detect_format(raw, name)
        child = import_bytes(name, raw, detection=det)
        obj.add_child(child, relation="contains", note=f"archive entry ({det.format_id})")
        names.append(name)
        count += 1

    if obj.detected_format == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if count >= limit:
                    break
                name = sanitize_archive_path(info.filename)
                if not name or info.is_dir() or stat_is_symlink(info):
                    continue
                if info.file_size > LIMITS.max_extract_entry_bytes:
                    obj.warnings.append(f"entry too large to extract: {name}")
                    continue
                raw = zf.read(info)
                if len(raw) > LIMITS.max_extract_entry_bytes:
                    obj.warnings.append(f"entry expanded beyond limit: {name}")
                    continue
                _add(name, raw)
    elif obj.detected_format == "tar":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            for member in tf.getmembers():
                if count >= limit:
                    break
                name = sanitize_archive_path(member.name)
                if not name or not member.isfile():
                    continue
                if member.size > LIMITS.max_extract_entry_bytes:
                    obj.warnings.append(f"entry too large to extract: {name}")
                    continue
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                raw = fh.read(LIMITS.max_extract_entry_bytes + 1)
                if len(raw) > LIMITS.max_extract_entry_bytes:
                    continue
                _add(name, raw)
    elif obj.detected_format == "gzip":
        raw = obj.get_blob(obj.content.get("_member"))
        if raw is None:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                raw = gz.read(LIMITS.max_extract_entry_bytes + 1)
        _add("member", raw)
    else:
        raise UnsafeInputError(f"cannot extract {obj.detected_format}")

    obj.record("archive.extract_all", f"extracted {count} entries: " + ", ".join(names[:10]),
               ConversionKind.STRUCTURAL)
    return count


ADAPTERS = [ZipAdapter(), TarGzAdapter(), SevenZAdapter()]

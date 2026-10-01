"""
SUPERFILE — Security model (prototype)
======================================

Every imported file is treated as untrusted data.

Hard rules enforced here and in the adapters:

*  Nothing is ever executed.  EXE/DLL/ELF/WASM/scripts are static data only.
*  Archive entry paths are sanitised (no absolute paths, no ``..``, no drive
   letters, no symlink/hardlink extraction).
*  Decompression expansion is capped (ratio + absolute ceiling) — no zip bombs.
*  Declared sizes are validated against actual data.
*  File signatures are validated against declared/detected formats.
*  All objects are hashed (SHA-256).
*  Parsers run with strict input limits and never follow embedded references.

``SafeLimits`` centralises the numeric caps so they can be audited in one place.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SafeLimits:
    max_file_bytes: int = 64 * 1024 * 1024          # single import cap (64 MiB)
    max_upload_bytes: int = 64 * 1024 * 1024
    max_archive_entries: int = 10_000
    max_archive_total_uncompressed: int = 256 * 1024 * 1024
    max_compression_ratio: int = 200                # uncompressed / compressed
    max_extract_entry_bytes: int = 64 * 1024 * 1024
    max_json_depth: int = 200
    max_text_chars: int = 8 * 1024 * 1024
    max_image_pixels: int = 40_000_000              # decode cap (width * height)
    max_child_objects: int = 10_000
    max_bson_depth: int = 100


LIMITS = SafeLimits()


class UnsafeInputError(Exception):
    """Raised when untrusted input violates the security model."""


class LimitExceededError(UnsafeInputError):
    """Raised when a parser/extractor limit would be exceeded."""


# ---------------------------------------------------------------------------
# hashing / identity
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_declared_size(declared: int, actual: int, what: str = "size") -> None:
    if declared != actual:
        raise UnsafeInputError(
            f"declared {what} {declared} does not match actual {actual}"
        )


# ---------------------------------------------------------------------------
# archive safety
# ---------------------------------------------------------------------------

_BAD_PATH = re.compile(r"(^|/)\.\.(/|$)")

def sanitize_archive_path(name: str) -> str:
    """
    Make an archive entry name safe to display / extract.

    *  converts backslashes, strips drive letters and leading slashes
    *  rejects ``..`` traversal
    *  collapses duplicate slashes
    Returns the sanitised relative path ('' means the entry must be skipped).
    """
    if not isinstance(name, str):
        return ""
    name = name.replace("\\", "/")
    # strip windows drive letters like C:
    if len(name) >= 2 and name[1] == ":":
        name = name[2:]
    while name.startswith("/"):
        name = name[1:]
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return ""
    if _BAD_PATH.search("/".join(parts)):
        return ""
    return "/".join(parts)


def check_extraction_budget(total_uncompressed: int, compressed_size: int,
                            entry_count: int, limits: SafeLimits = LIMITS) -> None:
    if entry_count > limits.max_archive_entries:
        raise LimitExceededError(
            f"archive has more than {limits.max_archive_entries} entries")
    if total_uncompressed > limits.max_archive_total_uncompressed:
        raise LimitExceededError(
            f"archive expands beyond {limits.max_archive_total_uncompressed} bytes")
    if compressed_size > 0:
        ratio = total_uncompressed / max(1, compressed_size)
        if total_uncompressed > 4 * 1024 * 1024 and ratio > limits.max_compression_ratio:
            raise LimitExceededError(
                f"suspicious compression ratio {ratio:.0f}:1 (> {limits.max_compression_ratio}:1)")


# ---------------------------------------------------------------------------
# signature validation
# ---------------------------------------------------------------------------

def signature_matches(data: bytes, signatures: list[bytes], offset: int = 0) -> bool:
    for sig in signatures:
        if data[offset:offset + len(sig)] == sig:
            return True
    return False


def looks_like_text(data: bytes, sample: int = 4096) -> tuple[bool, float]:
    """Heuristic: is this plausibly text?  Returns (ok, confidence)."""
    chunk = data[:sample]
    if not chunk:
        return True, 0.5
    if b"\x00" in chunk:
        return False, 0.95
    # ratio of printable / whitespace bytes
    printable = sum(1 for b in chunk if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / len(chunk)
    return (ratio > 0.92, round(min(0.99, 0.5 + ratio / 2), 2))


# ---------------------------------------------------------------------------
# suspicious executable heuristics (inspection-time warnings only)
# ---------------------------------------------------------------------------

def pe_suspicious_traits(dos_ok: bool, has_wx_section: bool, has_tls: bool,
                         is_dll: bool, subsystem: int) -> list[str]:
    out = []
    if not dos_ok:
        out.append("Malformed DOS header — possible crafted/corrupt sample")
    if has_wx_section:
        out.append("Section with WRITE+EXECUTE permissions (common in packers/shellcode loaders)")
    if has_tls:
        out.append("TLS directory present (TLS callbacks run before entry point)")
    if subsystem == 2:
        out.append("GUI subsystem — no console")
    if is_dll:
        out.append("Dynamic-link library — loaded by other programs, never run directly")
    out.append("UNTRUSTED BINARY — static inspection only; SUPERFILE never executes files")
    return out


def elf_suspicious_traits(has_wx_segment: bool, has_rpath: bool, is_shared: bool) -> list[str]:
    out = []
    if has_wx_segment:
        out.append("Segment with PF_W+PF_X (writable executable memory)")
    if has_rpath:
        out.append("DT_RPATH/DT_RUNPATH present (library search-path override)")
    if is_shared:
        out.append("Shared object / library — never loaded or executed by SUPERFILE")
    out.append("UNTRUSTED BINARY — static inspection only; SUPERFILE never executes files")
    return out


def hex_preview(data: bytes, limit: int = 256) -> str:
    """Small, safe hex+ascii dump used by the binary inspector."""
    lines = []
    chunk = data[:limit]
    for off in range(0, len(chunk), 16):
        row = chunk[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{off:08x}  {hexpart:<47}  {asc}")
    return "\n".join(lines)


def safe_filename(name: str) -> str:
    """Reduce any name to a safe basename (for downloads / extraction)."""
    name = os.path.basename((name or "file").replace("\\", "/"))
    name = re.sub(r"[^\w.\- ]+", "_", name).strip(" .") or "file"
    return name[:120]

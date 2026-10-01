"""
SUPERFILE PROTOCOL — .sfp container implementation (v1.0)
=========================================================

Binary layout (all integers big-endian):

    +----------------------------------------------------------+
    | FIXED HEADER (32 bytes)                                   |
    |   magic          8  b"\\x8bSFP\\r\\n\\x1a\\n"                  |
    |   version_major  2  u16  (=1)                             |
    |   version_minor  2  u16  (=0)                             |
    |   header_size    4  u32  (=32, bytes until first chunk)   |
    |   flags          4  u32  bit0 CONT zlib, bit1 OBYT zlib,  |
    |                          bit2 BLOB zlib                   |
    |   reserved      12  zero bytes (future use)               |
    +----------------------------------------------------------+
    | CHUNKS ...                                                |
    |   tag     4 ascii bytes                                    |
    |   length  u64 (payload bytes)                             |
    |   payload length bytes                                    |
    |   ...                                                     |
    |   CKSM chunk (MUST be last)                               |
    |     tag    4  "CKSM"                                      |
    |     length 8  32                                          |
    |     payload 32 = SHA-256 over every byte BEFORE this chunk|
    +----------------------------------------------------------+

Defined chunk tags (all optional except META, CONT, OFMT and CKSM):

    META  JSON   core object fields + metadata dict
    CONT  JSON   content representation (blob refs allowed)
    HIST  JSON   transformation history
    RTBL  JSON   relationship table
    OTBL  JSON   object table (summaries of children, for fast listing)
    OFMT  JSON   original-representation record (format, name, hash, ...)
    OBYT  bin    original bytes (lossless preservation) — may be zlib
    BLOB  bin    blob table: (u16 keylen + key + u64 len + data) * — may be zlib
    KIDS  bin    nested SFP documents: (u64 len + sfp bytes) *
    CKSM  bin    32-byte SHA-256 integrity checksum

Forward compatibility
---------------------
Readers MUST skip chunks with unknown tags.  Readers accept any minor version
and any header_size >= 32 (extra header bytes are skipped).  Major version
bumps are refused unless explicitly overridden.  Writers never emit flags or
chunks that would break v1.0 readers.
"""

from __future__ import annotations

import io
import json
import struct
import zlib

from .object_model import (
    ExportOption, ObjectType, Relationship, SupportLevel,
    TransformationRecord, UniversalObject, sha256_hex,
)
from .security import UnsafeInputError, sha256

MAGIC = b"\x8bSFP\x0d\x0a\x1a\x0a"
VERSION_MAJOR = 1
VERSION_MINOR = 0
HEADER_SIZE = 32

FLAG_CONT_ZLIB = 1 << 0
FLAG_OBYT_ZLIB = 1 << 1
FLAG_BLOB_ZLIB = 1 << 2

CHUNK_META = b"META"
CHUNK_CONT = b"CONT"
CHUNK_HIST = b"HIST"
CHUNK_RTBL = b"RTBL"
CHUNK_OTBL = b"OTBL"
CHUNK_OFMT = b"OFMT"
CHUNK_OBYT = b"OBYT"
CHUNK_BLOB = b"BLOB"
CHUNK_KIDS = b"KIDS"
CHUNK_CKSM = b"CKSM"
CHUNK_ENCR = b"ENCR"          # container encryption header (see superfile/crypto.py)

_KNOWN_CHUNKS = {CHUNK_META, CHUNK_CONT, CHUNK_HIST, CHUNK_RTBL, CHUNK_OTBL,
                 CHUNK_OFMT, CHUNK_OBYT, CHUNK_BLOB, CHUNK_KIDS, CHUNK_CKSM,
                 CHUNK_ENCR}

# shown verbatim by the normal OPEN / IMPORT PATH flow when an encrypted
# container is opened without unlocking it first (see loads())
ENCRYPTED_CONTAINER_MESSAGE = ("this .sfp is encrypted — use the DECRYPT tab "
                               "to unlock it first")


class ProtocolError(UnsafeInputError):
    pass


# ---------------------------------------------------------------------------
# chunk primitives
# ---------------------------------------------------------------------------

def _pack_chunk(tag: bytes, payload: bytes) -> bytes:
    return tag + struct.pack(">Q", len(payload)) + payload


def _maybe_compress(payload: bytes, enabled: bool) -> tuple[bytes, bool]:
    if not enabled or len(payload) < 128:
        return payload, False
    packed = zlib.compress(payload, 6)
    if len(packed) < len(payload):
        return packed, True
    return payload, False


def _iter_chunks(buf: bytes, start: int):
    """Yield (tag, payload, payload_offset, chunk_offset). Validates bounds."""
    pos = start
    n = len(buf)
    while pos < n:
        if n - pos < 12:
            raise ProtocolError("truncated chunk header")
        tag = buf[pos:pos + 4]
        (length,) = struct.unpack_from(">Q", buf, pos + 4)
        payload_off = pos + 12
        end = payload_off + length
        if end > n:
            raise ProtocolError(f"chunk {tag!r} claims {length} bytes, file truncated")
        yield tag, buf[payload_off:end], payload_off, pos
        pos = end
        if tag == CHUNK_CKSM:
            return


# ---------------------------------------------------------------------------
# writer
# ---------------------------------------------------------------------------

def dumps(obj: UniversalObject) -> bytes:
    """Serialise a UniversalObject (and its children) to .sfp bytes."""
    flags = 0

    meta = {
        "sfmeta": 1,
        "object_id": obj.object_id,
        "object_type": obj.object_type.value if isinstance(obj.object_type, ObjectType) else obj.object_type,
        "object_version": obj.version,
        "original_filename": obj.original_filename,
        "original_extension": obj.original_extension,
        "detected_format": obj.detected_format,
        "mime": obj.mime,
        "size": obj.size,
        "checksum": obj.checksum,
        "capabilities": list(obj.capabilities),
        "export_formats": [e.to_dict() if isinstance(e, ExportOption) else dict(e)
                           for e in obj.export_formats],
        "support_level": obj.support_level.value if isinstance(obj.support_level, SupportLevel) else obj.support_level,
        "warnings": list(obj.warnings),
        "metadata": obj.metadata,
        "adapter_name": obj.adapter_name,
        "adapter_version": obj.adapter_version,
        "created_at": obj.created_at,
    }
    ofmt = {
        "original_format": obj.detected_format,
        "mime": obj.mime,
        "filename": obj.original_filename,
        "extension": obj.original_extension,
        "size": obj.size,
        "checksum": obj.checksum,
        "preserved_bytes": obj.original_bytes is not None,
        "detection": obj.metadata.get("detection", {}),
        "format_version": obj.metadata.get("format_version", ""),
    }
    hist = [t.to_dict() if isinstance(t, TransformationRecord) else dict(t)
            for t in obj.transformations]
    rtbl = [r.to_dict() if isinstance(r, Relationship) else dict(r)
            for r in obj.relationships]
    otbl = [c.summary() for c in obj.children]

    cont_raw = json.dumps(obj.content, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    cont_payload, cont_z = _maybe_compress(cont_raw, True)
    if cont_z:
        flags |= FLAG_CONT_ZLIB

    out = io.BytesIO()
    out.write(MAGIC)
    out.write(struct.pack(">HHII12s", VERSION_MAJOR, VERSION_MINOR, HEADER_SIZE,
                          flags, b"\x00" * 12))
    out.write(_pack_chunk(CHUNK_META, json.dumps(meta, ensure_ascii=False).encode("utf-8")))
    out.write(_pack_chunk(CHUNK_CONT, cont_payload))
    out.write(_pack_chunk(CHUNK_HIST, json.dumps(hist, ensure_ascii=False).encode("utf-8")))
    out.write(_pack_chunk(CHUNK_RTBL, json.dumps(rtbl, ensure_ascii=False).encode("utf-8")))
    out.write(_pack_chunk(CHUNK_OTBL, json.dumps(otbl, ensure_ascii=False).encode("utf-8")))
    out.write(_pack_chunk(CHUNK_OFMT, json.dumps(ofmt, ensure_ascii=False).encode("utf-8")))

    if obj.original_bytes is not None:
        # A SUPERFILE container does not embed its own bytes (that would nest
        # infinitely on re-save) — the container IS the preservation.
        if obj.detected_format != "sfp":
            obyt, obyt_z = _maybe_compress(obj.original_bytes, True)
            if obyt_z:
                flags |= FLAG_OBYT_ZLIB
            out.write(_pack_chunk(CHUNK_OBYT, obyt))

    if obj.blobs:
        table = io.BytesIO()
        for key, data in obj.blobs.items():
            kb = key.encode("utf-8")
            table.write(struct.pack(">H", len(kb)))
            table.write(kb)
            table.write(struct.pack(">Q", len(data)))
            table.write(data)
        blob_payload, blob_z = _maybe_compress(table.getvalue(), True)
        if blob_z:
            flags |= FLAG_BLOB_ZLIB
        out.write(_pack_chunk(CHUNK_BLOB, blob_payload))

    if obj.children:
        kids = io.BytesIO()
        for child in obj.children:
            sub = dumps(child)
            kids.write(struct.pack(">Q", len(sub)))
            kids.write(sub)
        out.write(_pack_chunk(CHUNK_KIDS, kids.getvalue()))

    body = bytearray(out.getvalue())
    # patch flags (they were finalised while writing)
    struct.pack_into(">I", body, 16, flags)
    digest = sha256(bytes(body))
    body += _pack_chunk(CHUNK_CKSM, bytes.fromhex(digest))
    return bytes(body)


def write_file(path: str, obj: UniversalObject) -> int:
    data = dumps(obj)
    with open(path, "wb") as fh:
        fh.write(data)
    return len(data)


# ---------------------------------------------------------------------------
# reader
# ---------------------------------------------------------------------------

def loads(data: bytes, verify: bool = True, allow_future: bool = False) -> UniversalObject:
    if len(data) < HEADER_SIZE + 12:
        raise ProtocolError("file too small to be a SUPERFILE container")
    if data[:8] != MAGIC:
        raise ProtocolError("bad magic — not a SUPERFILE container")

    vmaj, vmin, hdr_size, flags, _res = struct.unpack_from(">HHII12s", data, 8)
    if vmaj > VERSION_MAJOR and not allow_future:
        raise ProtocolError(
            f"container major version {vmaj} is newer than supported {VERSION_MAJOR}")
    if hdr_size < HEADER_SIZE or hdr_size > len(data):
        raise ProtocolError("invalid header_size")

    chunks: dict[bytes, list[tuple[bytes, int]]] = {}
    unknown = []
    cksm_off = None
    for tag, payload, poff, coff in _iter_chunks(data, hdr_size):
        if tag == CHUNK_CKSM:
            cksm_off = coff
            chunks.setdefault(tag, []).append((payload, poff))
            break
        chunks.setdefault(tag, []).append((payload, poff))

    if cksm_off is None:
        raise ProtocolError("missing CKSM checksum chunk")
    if verify:
        payload = chunks[CHUNK_CKSM][0][0]
        if len(payload) != 32:
            raise ProtocolError("bad CKSM length")
        actual = sha256(data[:cksm_off])
        if actual != payload.hex():
            raise ProtocolError("checksum mismatch — container is corrupt or was modified")
        if cksm_off + 12 + 32 != len(data):
            raise ProtocolError("trailing data after checksum")

    # An encrypted container keeps its payload chunks (META/CONT/.../KIDS) as
    # AES-256-GCM ciphertext, so parsing them here would crash with a confusing
    # json/decode error.  Detect it first and fail with a clear instruction.
    if CHUNK_ENCR in chunks:
        raise ProtocolError(ENCRYPTED_CONTAINER_MESSAGE)

    if CHUNK_META not in chunks or CHUNK_CONT not in chunks:
        raise ProtocolError("missing required META/CONT chunks")

    def _json_chunk(tag: bytes, default):
        if tag not in chunks:
            return default
        raw = chunks[tag][0][0]
        return json.loads(raw.decode("utf-8"))

    meta = _json_chunk(CHUNK_META, {})
    cont_raw = chunks[CHUNK_CONT][0][0]
    if flags & FLAG_CONT_ZLIB:
        cont_raw = zlib.decompress(cont_raw)
    content = json.loads(cont_raw.decode("utf-8"))
    hist = _json_chunk(CHUNK_HIST, [])
    rtbl = _json_chunk(CHUNK_RTBL, [])
    ofmt = _json_chunk(CHUNK_OFMT, {})

    obj = UniversalObject.from_dict({
        "object_id": meta.get("object_id"),
        "object_type": meta.get("object_type", "UNKNOWN"),
        "version": meta.get("object_version", 1),
        "original_filename": meta.get("original_filename", ofmt.get("filename", "")),
        "original_extension": meta.get("original_extension", ofmt.get("extension", "")),
        "detected_format": meta.get("detected_format", ofmt.get("original_format", "")),
        "mime": meta.get("mime", ofmt.get("mime", "")),
        "size": meta.get("size", ofmt.get("size", 0)),
        "checksum": meta.get("checksum", ofmt.get("checksum", "")),
        "capabilities": meta.get("capabilities", []),
        "export_formats": meta.get("export_formats", []),
        "support_level": meta.get("support_level", "UNSUPPORTED"),
        "warnings": meta.get("warnings", []),
        "metadata": meta.get("metadata", {}),
        "adapter_name": meta.get("adapter_name", ""),
        "adapter_version": meta.get("adapter_version", ""),
        "created_at": meta.get("created_at", 0.0),
    })
    obj.content = content
    obj.transformations = [TransformationRecord.from_dict(t) for t in hist]
    obj.relationships = [Relationship.from_dict(r) for r in rtbl]

    if CHUNK_OBYT in chunks:
        obyt = chunks[CHUNK_OBYT][0][0]
        if flags & FLAG_OBYT_ZLIB:
            obyt = zlib.decompress(obyt)
        obj.original_bytes = obyt

    if CHUNK_BLOB in chunks:
        raw = chunks[CHUNK_BLOB][0][0]
        if flags & FLAG_BLOB_ZLIB:
            raw = zlib.decompress(raw)
        view = memoryview(raw)
        pos = 0
        while pos < len(raw):
            if pos + 2 > len(raw):
                raise ProtocolError("truncated blob table")
            (klen,) = struct.unpack_from(">H", raw, pos)
            pos += 2
            key = bytes(view[pos:pos + klen]).decode("utf-8")
            pos += klen
            (dlen,) = struct.unpack_from(">Q", raw, pos)
            pos += 8
            if pos + dlen > len(raw):
                raise ProtocolError("truncated blob data")
            obj.blobs[key] = bytes(view[pos:pos + dlen])
            pos += dlen

    if CHUNK_KIDS in chunks:
        raw = chunks[CHUNK_KIDS][0][0]
        pos = 0
        while pos < len(raw):
            if pos + 8 > len(raw):
                raise ProtocolError("truncated KIDS chunk")
            (clen,) = struct.unpack_from(">Q", raw, pos)
            pos += 8
            if pos + clen > len(raw):
                raise ProtocolError("truncated child container")
            child = loads(raw[pos:pos + clen], verify=verify, allow_future=allow_future)
            obj.children.append(child)
            pos += clen

    # remember unknown chunk tags for introspection (forward compatibility)
    unknown = [t.decode("latin-1") for t in chunks if t not in _KNOWN_CHUNKS]
    if unknown:
        obj.metadata.setdefault("sfp", {})["unknown_chunks"] = unknown
    obj.metadata.setdefault("sfp", {}).update({
        "container_version": f"{vmaj}.{vmin}",
        "flags": flags,
    })
    return obj


def read_file(path: str, verify: bool = True) -> UniversalObject:
    with open(path, "rb") as fh:
        return loads(fh.read(), verify=verify)


# ---------------------------------------------------------------------------
# introspection (used by the inspector / protocol explorer)
# ---------------------------------------------------------------------------

def describe_container(data: bytes) -> dict:
    """Parse chunk structure without building objects (safe introspection)."""
    if data[:8] != MAGIC:
        return {"is_sfp": False}
    vmaj, vmin, hdr_size, flags, _ = struct.unpack_from(">HHII12s", data, 8)
    chunks = []
    try:
        for tag, payload, poff, coff in _iter_chunks(data, hdr_size):
            chunks.append({
                "tag": tag.decode("latin-1"),
                "offset": coff,
                "length": len(payload),
                "known": tag in _KNOWN_CHUNKS,
            })
            if tag == CHUNK_CKSM:
                break
    except ProtocolError as exc:
        return {"is_sfp": True, "error": str(exc)}
    return {
        "is_sfp": True,
        "encrypted": any(c["tag"] == "ENCR" for c in chunks),
        "version": f"{vmaj}.{vmin}",
        "header_size": hdr_size,
        "flags": flags,
        "chunks": chunks,
        "total_size": len(data),
    }

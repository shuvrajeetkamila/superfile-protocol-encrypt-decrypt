"""
SUPERFILE — Video adapters: MP4/MOV (ISO-BMFF), MKV/WebM (EBML), AVI (RIFF).

All video support is INSPECTION ONLY: structural container parsers that
extract tracks, codecs, dimensions and duration where recorded.  No codec
decoding.  Playback is delegated to the browser runtime in the UI when the
container is natively playable (MP4/WebM), and frame extraction there is
labelled RENDERED.  Original bytes are always preserved.
"""

from __future__ import annotations

import struct

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import UnsafeInputError, hex_preview, sha256

# cap on boxes/elements walked to keep hostile files cheap to inspect
MAX_BOXES = 4000
MAX_EBML_ELEMENTS = 20000


class IsoBmffAdapter(FormatAdapter):
    """MP4 / MOV / M4A family — box-tree parser."""

    name = "mp4"
    version = "1.0"
    formats = {
        "mp4": FormatSpec("mp4", "MPEG-4 video", ["mp4", "m4v", "m4a", "3gp"], "video/mp4",
                          "VIDEO", SupportLevel.INSPECTION, read=True,
                          detection="container", notes="ISO-BMFF box tree + track tables"),
        "mov": FormatSpec("mov", "QuickTime video", ["mov"], "video/quicktime", "VIDEO",
                          SupportLevel.INSPECTION, read=True,
                          detection="container", notes="ISO-BMFF (qt brand) box tree"),
    }
    capabilities = {f: {"detect", "read", "parse", "inspect"} for f in formats}
    input_types = [ObjectType.VIDEO, ObjectType.MULTIMEDIA_CONTAINER]
    output_types = [ObjectType.VIDEO]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        fmt = detection.format_id if detection else (
            "mov" if filename.lower().endswith(".mov") else "mp4")
        spec = self.formats.get(fmt, self.formats["mp4"])
        obj = UniversalObject(
            object_type=ObjectType.VIDEO,
            original_filename=filename,
            original_extension=fmt,
            detected_format=fmt,
            mime=spec.mime,
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=SupportLevel.INSPECTION,
        )
        obj.record("import", f"imported {filename or fmt} (container inspection)")
        obj.content = {"kind": "video", "container": "ISO-BMFF", "decoded": False}
        try:
            tree, warn = _walk_boxes(data, 0, len(data), 0)
            obj.content["boxes"] = tree
            tracks, info = _extract_tracks(data, tree)
            obj.content["tracks"] = tracks
            obj.content.update(info)
            obj.metadata.update({k: info[k] for k in
                                 ("duration_sec", "timescale") if k in info})
            for w in warn:
                obj.warnings.append(w)
        except Exception as exc:
            obj.warnings.append(f"box walk issue: {exc}")
            obj.content["boxes"] = []
        obj.content["hex_preview"] = hex_preview(data)
        return obj

    def export_formats(self, obj) -> list:
        import json
        return [
            opt("json", "Container report (.json)", ConversionKind.STRUCTURAL,
                "box tree + track table"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        import json
        stem = (obj.original_filename or "video").rsplit(".", 1)[0]
        if fmt == "json":
            payload = {k: v for k, v in obj.content.items()
                       if k not in ("hex_preview",)}
            return ExportResult(json.dumps(payload, indent=2, default=str).encode(),
                                stem + "_boxes.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError("mp4 adapter only exports json")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "top_level_boxes": [b["type"] for b in obj.content.get("boxes", [])][:20],
            "tracks": obj.content.get("tracks", []),
            "duration_sec": obj.content.get("duration_sec"),
        }
        return rep


def _walk_boxes(data: bytes, start: int, end: int, depth: int, counter=None):
    if counter is None:
        counter = [0]
    out = []
    warnings = []
    pos = start
    while pos + 8 <= end and counter[0] < MAX_BOXES and depth < 8:
        counter[0] += 1
        (size,) = struct.unpack_from(">I", data, pos)
        typ = data[pos + 4:pos + 8]
        hdr = 8
        if size == 1:
            if pos + 16 > end:
                break
            (size,) = struct.unpack_from(">Q", data, pos + 8)
            hdr = 16
        elif size == 0:
            size = end - pos
        if size < hdr or pos + size > end:
            warnings.append(f"box {typ!r} at {pos} has invalid size {size} — stopped")
            break
        node = {"type": typ.decode("latin-1", "replace"), "offset": pos, "size": size}
        payload_start = pos + hdr
        if typ in (b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta", b"edts",
                   b"dinf", b"mvex", b"moof", b"traf", b"meta"):
            children, w = _walk_boxes(data, payload_start, pos + size, depth + 1, counter)
            node["children"] = children
            warnings.extend(w)
        elif typ == b"ftyp":
            node["brand"] = data[payload_start:payload_start + 4].decode("latin-1", "replace")
        out.append(node)
        pos += size
    return out, warnings


def _find_boxes(nodes, typ, out=None):
    if out is None:
        out = []
    for n in nodes:
        if n["type"] == typ:
            out.append(n)
        _find_boxes(n.get("children", []), typ, out)
    return out


def _extract_tracks(data, tree):
    tracks = []
    info = {}
    for mvhd in _find_boxes(tree, "mvhd"):
        p = mvhd["offset"] + 8
        ver = data[p]
        if ver == 1:
            ts, dur = struct.unpack_from(">IQ", data, p + 20)
        else:
            ts, dur = struct.unpack_from(">II", data, p + 12)
        info["timescale"] = ts
        if ts:
            info["duration_sec"] = round(dur / ts, 3)
        break
    for trak in _find_boxes(tree, "trak"):
        t = {"type": "unknown"}
        for tkhd in _find_boxes([trak], "tkhd"):
            p = tkhd["offset"] + 8
            ver = data[p]
            if ver == 1:
                (track_id,) = struct.unpack_from(">I", data, p + 20)
                w, h = struct.unpack_from(">II", data, p + 88)
            else:
                (track_id,) = struct.unpack_from(">I", data, p + 12)
                w, h = struct.unpack_from(">II", data, p + 76)
            t["track_id"] = track_id
            t["width"] = w >> 16
            t["height"] = h >> 16
        for hdlr in _find_boxes([trak], "hdlr"):
            p = hdlr["offset"] + 8 + 8
            handler = data[p:p + 4].decode("latin-1", "replace")
            t["type"] = {"vide": "video", "soun": "audio", "text": "subtitle",
                         "subp": "subtitle", "meta": "metadata"}.get(handler, handler)
        for stsd in _find_boxes([trak], "stsd"):
            p = stsd["offset"] + 8 + 8
            if p + 8 <= len(data):
                codec = data[p + 4:p + 8].decode("latin-1", "replace")
                t["codec"] = codec
        for stsz in _find_boxes([trak], "stsz"):
            p = stsz["offset"] + 8 + 8
            (cnt,) = struct.unpack_from(">I", data, p + 8)
            t["sample_count"] = cnt
        for mdhd in _find_boxes([trak], "mdhd"):
            p = mdhd["offset"] + 8
            ver = data[p]
            if ver == 1:
                ts, dur = struct.unpack_from(">IQ", data, p + 20)
            else:
                ts, dur = struct.unpack_from(">II", data, p + 12)
            t["timescale"] = ts
            t["duration_sec"] = round(dur / ts, 3) if ts else 0
        tracks.append(t)
    return tracks, info


class MkvAdapter(FormatAdapter):
    """MKV / WebM — EBML element walker."""

    name = "mkv"
    version = "1.0"
    formats = {
        "mkv": FormatSpec("mkv", "Matroska video", ["mkv"], "video/x-matroska", "VIDEO",
                          SupportLevel.INSPECTION, read=True,
                          detection="container", notes="EBML walk: Info + Tracks + Tags"),
        "webm": FormatSpec("webm", "WebM video", ["webm"], "video/webm", "VIDEO",
                           SupportLevel.INSPECTION, read=True,
                           detection="container", notes="EBML walk: Info + Tracks + Tags"),
    }
    capabilities = {f: {"detect", "read", "parse", "inspect"} for f in formats}
    input_types = [ObjectType.VIDEO, ObjectType.MULTIMEDIA_CONTAINER]
    output_types = [ObjectType.VIDEO]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        fmt = detection.format_id if detection else (
            "webm" if filename.lower().endswith(".webm") else "mkv")
        spec = self.formats.get(fmt, self.formats["mkv"])
        obj = UniversalObject(
            object_type=ObjectType.VIDEO,
            original_filename=filename,
            original_extension=fmt,
            detected_format=fmt,
            mime=spec.mime,
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=SupportLevel.INSPECTION,
        )
        obj.record("import", f"imported {filename or fmt} (EBML inspection)")
        obj.content = {"kind": "video", "container": "EBML/Matroska", "decoded": False}
        try:
            tree, warn = _walk_ebml(data, 0, len(data), 0, [0])
            obj.content["elements"] = tree
            for w in warn[:20]:
                obj.warnings.append(w)
            info, tracks, tags = _ebml_summary(tree, data)
            obj.content.update(info)
            obj.content["tracks"] = tracks
            obj.content["tags"] = tags
            obj.metadata.update(tags)
        except Exception as exc:
            obj.warnings.append(f"EBML walk issue: {exc}")
        obj.content["hex_preview"] = hex_preview(data)
        return obj

    def export_formats(self, obj) -> list:
        return [
            opt("json", "Container report (.json)", ConversionKind.STRUCTURAL,
                "element tree + track table"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        import json
        stem = (obj.original_filename or "video").rsplit(".", 1)[0]
        if fmt == "json":
            payload = {k: v for k, v in obj.content.items() if k != "hex_preview"}
            return ExportResult(json.dumps(payload, indent=2, default=str).encode(),
                                stem + "_elements.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError("mkv adapter only exports json")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "elements": [e["name"] for e in obj.content.get("elements", [])][:20],
            "tracks": obj.content.get("tracks", []),
            "duration_sec": obj.content.get("duration_sec"),
            "tags": obj.content.get("tags", {}),
        }
        return rep


# EBML ids we care about (name -> id)
_EBML_IDS = {
    0x1A45DFA3: "EBML", 0x4286: "EBMLVersion", 0x4282: "DocType",
    0x18538067: "Segment", 0x1549A966: "Info", 0x2AD7B1: "TimecodeScale",
    0x4489: "Duration", 0x4D80: "MuxingApp", 0x5741: "WritingApp",
    0x1654AE6B: "Tracks", 0xAE: "TrackEntry", 0xD7: "TrackNumber",
    0x73C5: "TrackUID", 0x83: "TrackType", 0x86: "CodecID",
    0xE0: "Video", 0xB0: "PixelWidth", 0xBA: "PixelHeight",
    0xE1: "Audio", 0x9F: "Channels", 0xB5: "SamplingFrequency",
    0x1254C367: "Tags", 0x7373: "Tag", 0x63C0: "Targets", 0x67C8: "SimpleTag",
    0x45A3: "TagName", 0x4487: "TagString",
    0x114D9B74: "SeekHead", 0x1C53BB6B: "Cues", 0x1F43B675: "Cluster",
}

_EBML_CONTAINERS = {0x1A45DFA3, 0x18538067, 0x1549A966, 0x1654AE6B, 0xAE,
                    0xE0, 0xE1, 0x1254C367, 0x7373, 0x63C0, 0x67C8,
                    0x114D9B74, 0x1C53BB6B, 0x1F43B675}


def _read_vint(data: bytes, pos: int, keep_marker: bool = False):
    """Read an EBML variable-length integer.  Returns (value, new_pos) or None."""
    if pos >= len(data):
        return None
    first = data[pos]
    if first == 0:
        return None
    length = 8 - first.bit_length() + 1
    if length > 8 or pos + length > len(data):
        return None
    val = first if keep_marker else first & (0xFF >> length)
    for i in range(1, length):
        val = (val << 8) | data[pos + i]
    return val, pos + length


def _walk_ebml(data, start, end, depth, counter):
    out = []
    warnings = []
    pos = start
    while pos < end and counter[0] < MAX_EBML_ELEMENTS and depth < 6:
        idv = _read_vint(data, pos, keep_marker=True)
        if idv is None:
            break
        eid, pos2 = idv
        sz = _read_vint(data, pos2)
        if sz is None:
            break
        size, pos3 = sz
        payload_end = pos3 + size if size != (1 << (7 * 8)) - 1 else end
        if payload_end > end:
            warnings.append(f"element 0x{eid:X} size overruns parent — stopped")
            break
        counter[0] += 1
        node = {
            "id": f"0x{eid:X}",
            "name": _EBML_IDS.get(eid, f"unknown-0x{eid:X}"),
            "offset": pos, "size": size,
        }
        if eid in _EBML_CONTAINERS and size < 50_000_000:
            children, w = _walk_ebml(data, pos3, payload_end, depth + 1, counter)
            node["children"] = children
            warnings.extend(w)
        else:
            raw = data[pos3:payload_end]
            if eid == 0x4282:
                node["value"] = raw.decode("latin-1", "replace").strip("\x00")
            elif eid in (0xB0, 0xBA, 0xD7, 0x9F, 0x73C5, 0x2AD7B1):
                node["value"] = int.from_bytes(raw, "big")
            elif eid in (0xB5, 0x4489):
                node["value"] = struct.unpack(">f", raw)[0] if len(raw) == 4 else (
                    struct.unpack(">d", raw)[0] if len(raw) == 8 else None)
            elif eid in (0x86, 0x45A3, 0x4487, 0x4D80, 0x5741):
                node["value"] = raw.decode("utf-8", "replace")[:300]
            elif eid == 0x83:
                node["value"] = int.from_bytes(raw, "big")
        out.append(node)
        pos = payload_end
    return out, warnings


def _ebml_find(nodes, name, out=None):
    if out is None:
        out = []
    for n in nodes:
        if n["name"] == name:
            out.append(n)
        _ebml_find(n.get("children", []), name, out)
    return out


def _ebml_summary(tree, data):
    info = {}
    tracks = []
    tags = {}
    for n in _ebml_find(tree, "DocType"):
        info["doctype"] = n.get("value")
    for n in _ebml_find(tree, "TimecodeScale"):
        info["timescale_ns"] = n.get("value")
    for n in _ebml_find(tree, "Duration"):
        info["duration_ticks"] = n.get("value")
        scale = info.get("timescale_ns", 1000000)
        if n.get("value") and scale:
            info["duration_sec"] = round(n["value"] * scale / 1e9, 3)
    for entry in _ebml_find(tree, "TrackEntry"):
        t = {}
        for key, field in (("TrackNumber", "track_id"), ("TrackType", "type_raw"),
                           ("CodecID", "codec"), ("PixelWidth", "width"),
                           ("PixelHeight", "height"), ("Channels", "channels"),
                           ("SamplingFrequency", "sample_rate")):
            found = _ebml_find([entry], key)
            if found:
                t[field] = found[0].get("value")
        tt = t.pop("type_raw", None)
        t["type"] = {1: "video", 2: "audio", 17: "subtitle", 3: "complex"}.get(tt, str(tt))
        tracks.append(t)
    for st in _ebml_find(tree, "SimpleTag"):
        names = _ebml_find([st], "TagName")
        vals = _ebml_find([st], "TagString")
        if names and vals:
            tags[str(names[0].get("value"))[:40]] = str(vals[0].get("value"))[:300]
    return info, tracks, tags


class AviAdapter(FormatAdapter):
    """AVI — RIFF chunk walker."""

    name = "avi"
    version = "1.0"
    formats = {
        "avi": FormatSpec("avi", "AVI video", ["avi"], "video/x-msvideo", "VIDEO",
                          SupportLevel.INSPECTION, read=True,
                          detection="magic", notes="RIFF avih/strl stream tables"),
    }
    capabilities = {"avi": {"detect", "read", "parse", "inspect"}}
    input_types = [ObjectType.VIDEO, ObjectType.MULTIMEDIA_CONTAINER]
    output_types = [ObjectType.VIDEO]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = UniversalObject(
            object_type=ObjectType.VIDEO,
            original_filename=filename,
            original_extension="avi",
            detected_format="avi",
            mime="video/x-msvideo",
            size=len(data),
            original_bytes=data,
            checksum=sha256(data),
            support_level=SupportLevel.INSPECTION,
        )
        obj.record("import", f"imported {filename or 'avi'} (RIFF inspection)")
        obj.content = {"kind": "video", "container": "RIFF/AVI", "decoded": False}
        try:
            chunks, warn = _walk_riff(data, 0, len(data), 0, [0])
            obj.content["chunks"] = chunks
            obj.warnings.extend(warn[:20])
            streams = []
            for avih in _riff_find(chunks, "avih"):
                p = avih["offset"]
                (usec, _bps, _pad, flags, total, init, streams, _buf, w, h) = struct.unpack_from(
                    "<10I", data, p)
                obj.content["frame_count"] = total
                obj.content["width"], obj.content["height"] = w, h
                if usec:
                    obj.content["fps"] = round(1_000_000 / usec, 3)
                    obj.content["duration_sec"] = round(total * usec / 1e6, 3)
            for strh in _riff_find(chunks, "strh"):
                p = strh["offset"]
                fcc_type = data[p:p + 4].decode("latin-1", "replace")
                fcc_handler = data[p + 4:p + 8].decode("latin-1", "replace")
                streams.append({"type": fcc_type, "codec": fcc_handler})
            obj.content["tracks"] = streams
        except Exception as exc:
            obj.warnings.append(f"AVI walk issue: {exc}")
        obj.content["hex_preview"] = hex_preview(data)
        return obj

    def export_formats(self, obj) -> list:
        return [
            opt("json", "Container report (.json)", ConversionKind.STRUCTURAL, "chunk tree + streams"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        import json
        if fmt != "json":
            raise UnsafeInputError("avi adapter only exports json")
        stem = (obj.original_filename or "video").rsplit(".", 1)[0]
        payload = {k: v for k, v in obj.content.items() if k != "hex_preview"}
        return ExportResult(json.dumps(payload, indent=2, default=str).encode(),
                            stem + "_chunks.json", "application/json",
                            ConversionKind.STRUCTURAL.value)

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {
            "chunks": [c["type"] for c in obj.content.get("chunks", [])][:20],
            "tracks": obj.content.get("tracks", []),
            "frames": obj.content.get("frame_count"),
        }
        return rep


def _walk_riff(data, start, end, depth, counter):
    out = []
    warnings = []
    pos = start
    while pos + 8 <= end and counter[0] < MAX_BOXES and depth < 6:
        counter[0] += 1
        typ = data[pos:pos + 4]
        (size,) = struct.unpack_from("<I", data, pos + 4)
        payload = pos + 8
        nxt = payload + size + (size & 1)
        if nxt > end:
            warnings.append(f"RIFF chunk {typ!r} overruns — stopped")
            break
        node = {"type": typ.decode("latin-1", "replace"), "offset": payload, "size": size}
        if typ in (b"RIFF", b"LIST"):
            node["form"] = data[payload:payload + 4].decode("latin-1", "replace")
            children, w = _walk_riff(data, payload + 4, nxt, depth + 1, counter)
            node["children"] = children
            warnings.extend(w)
        out.append(node)
        pos = nxt
    return out, warnings


def _riff_find(nodes, typ, out=None):
    if out is None:
        out = []
    for n in nodes:
        if n["type"] == typ:
            out.append(n)
        _riff_find(n.get("children", []), typ, out)
    return out


ADAPTERS = [IsoBmffAdapter(), MkvAdapter(), AviAdapter()]

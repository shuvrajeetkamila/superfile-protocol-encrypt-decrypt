"""
SUPERFILE — Audio adapters: WAV (full via stdlib wave) + MP3/FLAC/OGG/AAC
(metadata / container inspection — no codec decoding).
"""

from __future__ import annotations

import io
import struct
import wave

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import UnsafeInputError, hex_preview, sha256


def _make(fmt, spec, data, filename, level=None) -> UniversalObject:
    obj = UniversalObject(
        object_type=ObjectType.AUDIO,
        original_filename=filename,
        original_extension=fmt,
        detected_format=fmt,
        mime=spec.mime,
        size=len(data),
        original_bytes=data,
        checksum=sha256(data),
        support_level=level or spec.support,
    )
    obj.record("import", f"imported {filename or fmt}")
    return obj


class WavAdapter(FormatAdapter):
    name = "wav"
    version = "1.0"
    formats = {
        "wav": FormatSpec("wav", "WAV audio", ["wav"], "audio/wav", "AUDIO",
                          SupportLevel.FULL, read=True, create=True, edit=False, export=True,
                          detection="magic", notes="PCM via stdlib wave; waveform peaks"),
    }
    capabilities = {"wav": {"detect", "read", "parse", "decode", "create", "encode", "export", "inspect"}}
    input_types = [ObjectType.AUDIO]
    output_types = [ObjectType.AUDIO]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = _make("wav", self.formats["wav"], data, filename)
        try:
            w = wave.open(io.BytesIO(data), "rb")
        except Exception as exc:
            obj.warnings.append(f"WAV parse error: {exc}")
            obj.support_level = SupportLevel.INSPECTION
            obj.content = {"kind": "audio", "hex_preview": hex_preview(data)}
            return obj
        with w:
            nch, sw, rate, nframes = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
            frames = w.readframes(min(nframes, rate * 60))  # cap at 60s of decode
        obj.content.update({
            "kind": "audio", "format": "wav",
            "channels": nch, "sample_width": sw, "sample_rate": rate,
            "frames": nframes,
            "duration": round(nframes / rate, 4) if rate else 0,
            "compression": "PCM",
        })
        obj.metadata.update({"duration_sec": obj.content["duration"],
                             "sample_rate": rate, "channels": nch})
        obj.content["peaks"] = compute_peaks(obj, 240, frames, nch, sw)
        obj.content["_pcm"] = obj.blob_ref(frames)
        return obj

    def create(self, object_type=ObjectType.AUDIO, params=None) -> UniversalObject:
        """Generate a sine tone WAV."""
        p = params or {}
        freq = float(p.get("freq", 440.0))
        dur = max(0.05, min(10.0, float(p.get("duration", 0.5))))
        rate = int(p.get("sample_rate", 22050))
        import math
        n = int(dur * rate)
        frames = bytearray()
        for i in range(n):
            v = int(20000 * math.sin(2 * math.pi * freq * i / rate))
            frames += struct.pack("<h", v)
        buf = io.BytesIO()
        w = wave.open(buf, "wb")
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames))
        w.close()
        return self.read(buf.getvalue(), p.get("filename", "tone.wav"), None)

    def encode(self, obj, fmt) -> bytes:
        if fmt != "wav":
            raise UnsafeInputError("wav adapter only encodes wav")
        ref = obj.content.get("edited_bytes") or obj.content.get("_pcm")
        # rebuild a wav from original bytes by default (lossless passthrough)
        if obj.original_bytes and obj.detected_format == "wav":
            return obj.original_bytes
        raise UnsafeInputError("no WAV data available")

    def export_formats(self, obj) -> list:
        return [
            opt("wav", "WAV audio (.wav)", ConversionKind.LOSSLESS, "original PCM preserved"),
            opt("json", "Audio metadata (.json)", ConversionKind.STRUCTURAL, "tags + stream info"),
            opt("txt", "Waveform peaks (.json)", ConversionKind.RENDERED, "amplitude envelope"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        import json
        stem = (obj.original_filename or "audio").rsplit(".", 1)[0]
        if fmt == "wav":
            return ExportResult(self.encode(obj, "wav"), stem + ".wav", "audio/wav",
                                ConversionKind.LOSSLESS.value)
        if fmt == "json":
            meta = {k: v for k, v in obj.content.items()
                    if k not in ("peaks", "_pcm", "kind")}
            meta["metadata"] = obj.metadata
            return ExportResult(json.dumps(meta, indent=2, default=str).encode(),
                                stem + ".json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        if fmt == "txt":
            import json
            return ExportResult(json.dumps(obj.content.get("peaks", [])).encode(),
                                stem + "_peaks.json", "application/json",
                                ConversionKind.RENDERED.value, "waveform envelope")
        raise UnsafeInputError(f"wav adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {k: obj.content.get(k) for k in
                            ("channels", "sample_rate", "sample_width", "frames", "duration")}
        return rep


def compute_peaks(obj: UniversalObject, buckets: int = 240,
                  frames: bytes | None = None, nch: int | None = None,
                  sw: int | None = None) -> list:
    """Amplitude envelope for waveform display (16-bit PCM)."""
    data = frames
    if data is None:
        data = obj.get_blob(obj.content.get("_pcm"))
    nch = nch or obj.content.get("channels", 1)
    sw = sw or obj.content.get("sample_width", 2)
    if not data or sw != 2:
        return []
    nsamp = len(data) // (2 * nch)
    if nsamp == 0:
        return []
    peaks = []
    step = max(1, nsamp // buckets)
    for b in range(0, nsamp, step):
        seg = data[b * 2 * nch:(b + step) * 2 * nch]
        if not seg:
            break
        vals = struct.unpack(f"<{len(seg)//2}h", seg[:len(seg) // 2 * 2])
        peak = max((abs(v) for v in vals), default=0)
        peaks.append(round(peak / 32768, 3))
        if len(peaks) >= buckets:
            break
    return peaks


class CompressedAudioAdapter(FormatAdapter):
    """MP3 / FLAC / OGG / AAC — metadata & container inspection only."""

    name = "audio-meta"
    version = "1.0"
    formats = {
        "mp3": FormatSpec("mp3", "MP3 audio", ["mp3"], "audio/mpeg", "AUDIO",
                          SupportLevel.INSPECTION, read=True, export=False,
                          detection="magic", notes="ID3 tags + frame-header walk (no decode)"),
        "flac": FormatSpec("flac", "FLAC audio", ["flac"], "audio/flac", "AUDIO",
                           SupportLevel.INSPECTION, read=True, export=False,
                           detection="magic", notes="STREAMINFO + VORBIS_COMMENT"),
        "ogg": FormatSpec("ogg", "OGG container", ["ogg", "oga"], "audio/ogg", "AUDIO",
                          SupportLevel.INSPECTION, read=True, export=False,
                          detection="magic", notes="page walk + Vorbis/Opus identification"),
        "aac": FormatSpec("aac", "AAC audio (ADTS)", ["aac"], "audio/aac", "AUDIO",
                          SupportLevel.INSPECTION, read=True, export=False,
                          detection="magic", notes="ADTS frame headers"),
    }
    capabilities = {f: {"detect", "read", "parse", "inspect"} for f in formats}
    input_types = [ObjectType.AUDIO, ObjectType.MULTIMEDIA_CONTAINER]
    output_types = [ObjectType.AUDIO]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        fmt = detection.format_id if detection else filename.rsplit(".", 1)[-1].lower()
        fmt = {"oga": "ogg"}.get(fmt, fmt)
        spec = self.formats.get(fmt, self.formats["mp3"])
        obj = _make(fmt, spec, data, filename)
        obj.content = {"kind": "audio", "format": fmt, "decoded": False}
        try:
            if fmt == "mp3":
                self._mp3(obj, data)
            elif fmt == "flac":
                self._flac(obj, data)
            elif fmt == "ogg":
                self._ogg(obj, data)
            elif fmt == "aac":
                self._aac(obj, data)
        except Exception as exc:
            obj.warnings.append(f"{fmt} metadata parse issue: {exc}")
        obj.content["hex_preview"] = hex_preview(data)
        return obj

    def _mp3(self, obj, data):
        tags = {}
        pos = 0
        if data[:3] == b"ID3" and len(data) > 10:
            vmaj = data[3]
            flags = data[5]
            size = ((data[6] & 0x7F) << 21 | (data[7] & 0x7F) << 14 |
                    (data[8] & 0x7F) << 7 | (data[9] & 0x7F))
            tags["id3_version"] = f"2.{vmaj}"
            tags["id3_size"] = size
            pos = 10
            end = min(len(data), 10 + size)
            id3, _pos = _id3v2_frames(data, pos, end, vmaj)
            tags.update(id3)
            pos = 10 + size
        frames = 0
        first = None
        total_ms = 0.0
        while pos + 4 <= len(data) and frames < 200000:
            h = data[pos:pos + 4]
            if h[0] == 0xFF and (h[1] & 0xE0) == 0xE0:
                info = _mp3_frame_info(h)
                if info:
                    if first is None:
                        first = info
                    frames += 1
                    total_ms += info["duration_ms"]
                    pos += info["frame_bytes"]
                    continue
            pos += 1
        if first:
            obj.content.update({
                "codec": "MPEG-" + first["mpeg"], "layer": first["layer"],
                "bitrate_kbps": first["bitrate_kbps"], "sample_rate": first["sample_rate"],
                "channels": first["channels"], "mode": first["mode"],
                "frame_count": frames,
                "duration": round(total_ms / 1000, 3),
            })
        obj.content["tags"] = tags
        obj.metadata.update(tags)

    def _flac(self, obj, data):
        if data[:4] != b"fLaC":
            raise UnsafeInputError("not FLAC")
        pos = 4
        tags = {}
        while pos + 4 <= len(data):
            b0 = data[pos]
            last = bool(b0 & 0x80)
            btype = b0 & 0x7F
            blen = int.from_bytes(data[pos + 1:pos + 4], "big")
            body = data[pos + 4:pos + 4 + blen]
            pos += 4 + blen
            if btype == 0 and len(body) >= 18:  # STREAMINFO
                min_bs, max_bs = struct.unpack_from(">HH", body, 0)
                sr = int.from_bytes(body[10:13], "big") << 4 | (body[13] >> 4)
                ch = ((body[13] >> 1) & 0x7) + 1
                bps = (((body[13] & 1) << 4) | (body[14] >> 4)) + 1
                total = ((body[14] & 0xF) << 32) | int.from_bytes(body[15:19], "big")
                obj.content.update({
                    "sample_rate": sr, "channels": ch, "bits_per_sample": bps,
                    "total_samples": total,
                    "duration": round(total / sr, 3) if sr else 0,
                    "min_blocksize": min_bs, "max_blocksize": max_bs,
                })
            elif btype == 4:  # VORBIS_COMMENT
                tags.update(_vorbis_comments(body))
            if last:
                break
        obj.content["tags"] = tags
        obj.metadata.update(tags)

    def _ogg(self, obj, data):
        pages = 0
        pos = 0
        codec = None
        info = {}
        while pos + 27 <= len(data):
            if data[pos:pos + 4] != b"OggS":
                break
            nseg = data[pos + 26]
            segs = data[pos + 27:pos + 27 + nseg]
            body_len = sum(segs)
            body_off = pos + 27 + nseg
            body = data[body_off:body_off + body_len]
            pages += 1
            if pages == 1:
                if body[1:7] == b"vorbis":
                    codec = "Vorbis"
                    if len(body) >= 16:
                        ver, ch, sr = struct.unpack_from("<IBI", body, 7)
                        info.update({"channels": ch, "sample_rate": sr,
                                     "vorbis_version": ver})
                elif body[:8] == b"OpusHead":
                    codec = "Opus"
                    ver, ch = body[8], body[9]
                    sr = struct.unpack_from("<I", body, 12)[0]
                    info.update({"channels": ch, "sample_rate": sr,
                                 "opus_version": ver, "input_sample_rate": sr})
            if codec == "Vorbis" and body[:7] == b"\x03vorbis":
                obj.content["tags"] = _vorbis_comments(body[7:])
            if codec == "Opus" and body[:8] == b"OpusTags":
                obj.content["tags"] = _vorbis_comments(body[8:])
            pos = body_off + body_len
            if pages > 50000:
                break
        obj.content.update({"codec": codec, "pages": pages, **info})
        obj.content.setdefault("tags", {})

    def _aac(self, obj, data):
        frames = 0
        pos = 0
        first = None
        total = 0.0
        while pos + 7 <= len(data):
            if data[pos] == 0xFF and (data[pos + 1] & 0xF6) == 0xF0:
                hdr = data[pos:pos + 7]
                profile = ((hdr[2] >> 6) & 3) + 1
                sfi = (hdr[2] >> 2) & 0xF
                sr = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
                      16000, 12000, 11025, 8000, 7350][min(sfi, 12)]
                ch = ((hdr[2] & 1) << 2) | (hdr[3] >> 6)
                flen = ((hdr[3] & 3) << 11) | (hdr[4] << 3) | (hdr[5] >> 5)
                if flen < 7:
                    break
                if first is None:
                    first = {"profile": profile, "sample_rate": sr, "channels": ch}
                frames += 1
                total += 1024 / sr * 1000
                pos += flen
            else:
                pos += 1
        if first:
            obj.content.update({**first, "frame_count": frames,
                                "duration": round(total / 1000, 3)})
        obj.content.setdefault("tags", {})

    def export_formats(self, obj) -> list:
        return [
            opt("json", "Audio metadata (.json)", ConversionKind.STRUCTURAL,
                "stream info + tags (no audio decode)"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        import json
        stem = (obj.original_filename or "audio").rsplit(".", 1)[0]
        if fmt == "json":
            meta = {k: v for k, v in obj.content.items() if k != "hex_preview"}
            return ExportResult(json.dumps(meta, indent=2, default=str).encode(),
                                stem + ".json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError("audio-meta adapter only exports json")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {k: obj.content.get(k) for k in
                            ("codec", "channels", "sample_rate", "bitrate_kbps",
                             "duration", "frame_count", "pages")}
        rep["structure"]["tags"] = obj.content.get("tags", {})
        return rep


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _id3v2_frames(data, pos, end, vmaj):
    tags = {}
    while pos + 10 <= end:
        fid = data[pos:pos + 4]
        if fid == b"\x00\x00\x00\x00":
            break
        if vmaj >= 4:
            size = ((data[pos + 4] & 0x7F) << 21 | (data[pos + 5] & 0x7F) << 14 |
                    (data[pos + 6] & 0x7F) << 7 | (data[pos + 7] & 0x7F))
        else:
            size = int.from_bytes(data[pos + 4:pos + 8], "big")
        body = data[pos + 10:pos + 10 + size]
        pos += 10 + size
        name = fid.decode("latin-1", "replace")
        if not name.strip() or not all(c.isalnum() for c in name):
            break
        if body:
            enc = body[0]
            text = body[1:]
            if enc in (0, 3):
                val = text.decode("utf-8" if enc == 3 else "latin-1", "replace")
            elif enc == 1:
                val = text.decode("utf-16", "replace")
            else:
                val = text.decode("latin-1", "replace")
            tags[name] = val.strip("\x00").strip()[:300]
        if len(tags) > 60:
            break
    return tags, pos


def _mp3_frame_info(h: bytes):
    if len(h) < 4 or h[0] != 0xFF:
        return None
    version_bits = (h[1] >> 3) & 3
    layer_bits = (h[1] >> 1) & 3
    if version_bits == 1 or layer_bits == 0:
        return None
    mpeg = {3: "1", 2: "2", 0: "2.5"}[version_bits]
    layer = {3: "III", 2: "II", 1: "I"}[layer_bits]
    br_idx = (h[2] >> 4) & 0xF
    sr_idx = (h[2] >> 2) & 3
    if br_idx in (0, 15) or sr_idx == 3:
        return None
    rates = {"1": [44100, 48000, 32000], "2": [22050, 24000, 16000],
             "2.5": [11025, 12000, 8000]}[mpeg]
    sr = rates[sr_idx]
    br_table = {
        ("1", "I"): [32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
        ("1", "II"): [32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
        ("1", "III"): [32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    }
    key = ("1", layer) if mpeg == "1" else ("2", "III" if layer == "III" else layer)
    brs = br_table.get(key) or br_table[("1", "III")]
    br = brs[min(br_idx - 1, len(brs) - 1)]
    mode = ("mono", "stereo", "joint", "ms")[(h[3] >> 6) & 3]
    channels = 1 if mode == "mono" else 2
    spf = {"I": 384, "II": 1152, "III": 1152}[layer]
    if mpeg != "1" and layer == "III":
        spf = 576
    frame_bytes = int(spf / 8 * br * 1000 / sr)
    pad = (h[2] >> 1) & 1
    frame_bytes += pad
    dur_ms = spf / sr * 1000
    return {"mpeg": mpeg, "layer": layer, "bitrate_kbps": br, "sample_rate": sr,
            "channels": channels, "mode": mode, "frame_bytes": max(4, frame_bytes),
            "duration_ms": dur_ms}


def _vorbis_comments(body: bytes) -> dict:
    tags = {}
    try:
        if len(body) < 8:
            return tags
        vlen = int.from_bytes(body[:4], "little")
        pos = 4 + vlen
        count = int.from_bytes(body[pos:pos + 4], "little")
        pos += 4
        for _ in range(min(count, 200)):
            ln = int.from_bytes(body[pos:pos + 4], "little")
            pos += 4
            item = body[pos:pos + ln].decode("utf-8", "replace")
            pos += ln
            if "=" in item:
                k, _, v = item.partition("=")
                tags[k.upper()[:40]] = v[:300]
    except Exception:
        pass
    return tags


ADAPTERS = [WavAdapter(), CompressedAudioAdapter()]

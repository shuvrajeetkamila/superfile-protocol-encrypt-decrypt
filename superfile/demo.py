"""
SUPERFILE — demonstration sample generator.

Generates tiny, self-made sample files covering the supported format families.
Everything is produced programmatically (no bundled third-party media):

*  real files: TXT MD CSV JSON YAML TOML HTML RTF SVG PNG BMP GIF WAV
   OBJ STL GLB ZIP TAR.GZ SQLITE PDF DOCX EPUB WASM source files blobs
*  synthetic structural skeletons (clearly labelled): MP4/MKV container
   skeletons for inspector demos, minimal PE/ELF headers for static
   inspection demos
*  JPEG: generated via Pillow when available, else a tiny embedded sample

Run:  python3 -m superfile.demo      → writes ./demo/
"""

from __future__ import annotations

import gzip
import io
import json
import os
import struct
import tarfile
import zipfile

NOTE = {}  # filename -> note shown in the demo table


def generate_all(out_dir: str | None = None) -> list:
    out_dir = out_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo")
    os.makedirs(out_dir, exist_ok=True)
    created = []

    def put(name: str, data: bytes, note: str):
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(data)
        NOTE[name] = note
        created.append({"name": name, "size": len(data), "note": note})

    # ── TEXT / DOCUMENT ────────────────────────────────────────────
    put("hello.txt", b"Hello from SUPERFILE!\n\nThis is a plain text sample.\n"
                     b"It demonstrates TEXT import, editing and export.\n", "plain text")
    put("readme.md", b"# SUPERFILE Demo\n\nA *markdown* sample with:\n\n"
                     b"- bullet one\n- bullet two\n\n```python\nprint('code block')\n```\n\n"
                     b"**Bold** and [a link](https://example.invalid).\n", "markdown")
    put("table.csv", b"name,type,count,alpha,pixel,text\n"
                     b"formats,protocol,42,0.5,255,ok\n"
                     b"adapters,plugin,13,1.5,128,partial\n"
                     b"objects,universal,7,2.5,64,lossless\n", "CSV table")
    put("data.json", json.dumps({
        "app": "SUPERFILE", "version": "1.0", "capabilities":
        ["open", "create", "edit", "inspect", "transform", "export"],
        "nested": {"lossless": True, "kinds": ["LOSSLESS", "LOSSY", "STRUCTURAL"]},
        "numbers": [1, 2, 3, 5, 8, 13],
    }, indent=2).encode(), "JSON data")
    put("config.yaml", b"# SUPERFILE YAML subset sample\napp: superfile\nversion: \"1.0\"\n"
                       b"debug: false\nwindow:\n  width: 1280\n  height: 720\n"
                       b"formats:\n  - png\n  - jpeg\n  - gif\n", "YAML (subset)")
    put("config.toml", b"# SUPERFILE TOML sample\n"
                       b"title = \"SUPERFILE demo\"\nversion = \"1.0\"\nactive = true\n"
                       b"tags = [\"protocol\", \"universal\"]\n\n[window]\nwidth = 1280\nheight = 720\n",
        "TOML (subset)")
    put("page.html", b"<!doctype html><html><head><title>SUPERFILE page</title></head>"
                     b"<body><h1>Universal Object</h1><p>HTML sample document.</p>"
                     b"<a href='#'>link</a></body></html>", "HTML document")
    put("notes.rtf", b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Helvetica;}}{\\info{\\title SUPERFILE RTF}}"
                     b"\\f0 SUPERFILE RTF sample.\\par Second paragraph with plain text.\\par}",
        "RTF document")
    put("letter.pdf", _demo_pdf(), "PDF (one page, text extractable)")
    put("doc.docx", _demo_docx(), "Word OOXML package (real zip)")
    put("book.epub", _demo_epub(), "EPUB package (real zip)")

    # ── IMAGE ──────────────────────────────────────────────────────
    from .codecs import bmp as bmp_codec
    from .codecs import gif as gif_codec
    from .codecs import png as png_codec

    px = bytearray()
    for y in range(64):
        for x in range(64):
            px += bytes((x * 4 % 256, y * 4 % 256, 160, 255))
    put("pixel.png", png_codec.encode_from_rgba(bytes(px), 64, 64),
        "PNG 64×64 gradient (pure codec)")
    put("icon.bmp", bmp_codec.encode_from_rgba(bytes(px), 64, 64), "BMP 24-bit")
    frames = []
    for f in range(4):
        buf = bytearray()
        for y in range(48):
            for x in range(48):
                on = abs(x - (8 + f * 10)) < 8 and abs(y - 24) < 8
                buf += bytes((56, 189, 248, 255) if on else (16, 24, 40, 255))
        frames.append(bytes(buf))
    put("anim.gif", gif_codec.encode_animation(frames, 48, 48, [120, 120, 120, 120], loop=0),
        "GIF animation, 4 frames (pure LZW codec)")
    put("logo.svg", (
        '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120" viewBox="0 0 120 120">'
        '<rect width="120" height="120" rx="16" fill="#101828"/>'
        '<path d="M30 85V40l30 22 30-22v45" stroke="#38bdf8" stroke-width="8" fill="none" '
        'stroke-linejoin="round"/><text x="60" y="110" text-anchor="middle" '
        'font-family="monospace" font-size="12" fill="#7f93b0">SUPERFILE</text></svg>').encode(),
        "SVG vector image")
    put("photo.jpg", _demo_jpeg(px), "JPEG image (Pillow-generated or tiny sample)")

    # ── AUDIO / VIDEO ──────────────────────────────────────────────
    put("tone.wav", _demo_wav(), "WAV PCM sine tone (real audio)")
    put("movie.mp4", _demo_mp4_skeleton(),
        "MP4 container SKELETON (synthetic — structural inspection demo)")
    put("clip.mkv", _demo_mkv_skeleton(),
        "Matroska SKELETON (synthetic — EBML inspection demo)")

    # ── 3D ─────────────────────────────────────────────────────────
    put("mesh.obj", (
        "# SUPERFILE demo cube\n"
        "o Cube\nv -1 -1 -1\nv 1 -1 -1\nv 1 1 -1\nv -1 1 -1\n"
        "v -1 -1 1\nv 1 -1 1\nv 1 1 1\nv -1 1 1\n"
        "vn 0 0 -1\nvn 0 0 1\n"
        "f 1//1 2//1 3//1 4//1\nf 5//2 8//2 7//2 6//2\n"
        "f 1 5 6 2\nf 2 6 7 3\nf 3 7 8 4\nf 5 1 4 8\n").encode(),
        "Wavefront OBJ cube")
    put("part.stl", _demo_stl(), "binary STL cube (12 triangles)")
    put("scene.glb", _demo_glb(), "glTF binary — one triangle")

    # ── ARCHIVES ───────────────────────────────────────────────────
    put("bundle.zip", _demo_zip(), "ZIP with nested txt + png + obj")
    put("archive.tar.gz", _demo_targz(), "TAR.GZ with source + text")

    # ── EXECUTABLE (safe static inspection samples) ────────────────
    put("demo.wasm", _demo_wasm(),
        "WebAssembly module (real empty module + name section)")
    put("sample.exe", _demo_pe(),
        "SYNTHETIC PE headers — static inspection demo (not a runnable program)")
    put("sample.elf", _demo_elf(),
        "SYNTHETIC ELF64 headers — static inspection demo (not a runnable program)")

    # ── SOURCE CODE ────────────────────────────────────────────────
    put("hello.py", b'"""SUPERFILE python sample."""\n\n\ndef greet(name: str) -> str:\n'
                    b'    return f"hello, {name}"\n\n\nif __name__ == "__main__":\n'
                    b'    print(greet("superfile"))\n', "Python source")
    put("app.js", b"// SUPERFILE javascript sample\nfunction greet(name) {\n"
                  b"  return `hello, ${name}`;\n}\n\nconsole.log(greet('superfile'));\n",
        "JavaScript source")
    put("main.c", b"/* SUPERFILE C sample */\n#include <stdio.h>\n\n"
                  b"int main(void) {\n    printf(\"hello, superfile\\n\");\n    return 0;\n}\n",
        "C source")
    put("Main.java", b"// SUPERFILE Java sample\npublic class Main {\n"
                     b"    public static void main(String[] args) {\n"
                     b"        System.out.println(\"hello, superfile\");\n    }\n}\n",
        "Java source")
    put("lib.rs", b"// SUPERFILE Rust sample\npub fn greet(name: &str) -> String {\n"
                  b"    format!(\"hello, {}\", name)\n}\n", "Rust source")
    put("main.go", b"// SUPERFILE Go sample\npackage main\n\nimport \"fmt\"\n\n"
                   b"func main() {\n\tfmt.Println(\"hello, superfile\")\n}\n", "Go source")
    put("Program.cs", b"// SUPERFILE C# sample\nusing System;\nclass Program {\n"
                      b"    static void Main() {\n"
                      b"        Console.WriteLine(\"hello, superfile\");\n    }\n}\n",
        "C# source")
    put("style.css", b"/* SUPERFILE CSS sample */\nbody {\n  font-family: monospace;\n"
                     b"  background: #101828;\n  color: #e6edf3;\n}\n", "CSS source")

    # ── DATA ───────────────────────────────────────────────────────
    put("data.sqlite", _demo_sqlite(), "SQLite database (3 tables)")
    put("blob.bin", bytes((i * 37 + 11) & 0xFF for i in range(512)),
        "unknown binary blob (hex + entropy inspection)")

    # ── SUPERFILE project (object graph demo) ──────────────────────
    put("project.sfp", _demo_project(os.path.join(out_dir, "project.sfp")),
        "SUPERFILE container — nested object graph with preserved originals")

    with open(os.path.join(out_dir, "SAMPLES.json"), "w") as fh:
        json.dump({"samples": [{"name": n, "note": NOTE[n]} for n in sorted(NOTE)]},
                  fh, indent=2)
    return created


def list_samples(demo_dir: str) -> list:
    out = []
    if not os.path.isdir(demo_dir):
        return out
    for name in sorted(os.listdir(demo_dir)):
        if name == "SAMPLES.json":
            continue
        path = os.path.join(demo_dir, name)
        if os.path.isfile(path):
            note = NOTE.get(name, "")
            meta_path = os.path.join(demo_dir, "SAMPLES.json")
            if not note and os.path.isfile(meta_path):
                try:
                    with open(meta_path) as fh:
                        meta = {m["name"]: m["note"]
                                for m in json.load(fh).get("samples", [])}
                    note = meta.get(name, "")
                except Exception:
                    pass
            out.append({"name": name, "path": path,
                        "size": os.path.getsize(path), "note": note})
    return out


# ---------------------------------------------------------------------------
# individual sample builders
# ---------------------------------------------------------------------------

def _demo_pdf() -> bytes:
    from .adapters.pdf import build_simple_pdf
    return build_simple_pdf(
        "SUPERFILE PDF sample\nSecond line of extracted text.\n"
        "PDF text extraction is structural (Tj/TJ operators).",
        "SUPERFILE demo letter")


def _demo_docx() -> bytes:
    from .adapters.document import DocxAdapter
    return DocxAdapter().create(None, {
        "text": "SUPERFILE DOCX sample\nA second paragraph.\nA third paragraph.",
        "filename": "doc.docx"}).original_bytes


def _demo_epub() -> bytes:
    from .adapters.document import EpubAdapter
    return EpubAdapter().create(None, {
        "title": "SUPERFILE Demo Book",
        "text": "Chapter one text from the SUPERFILE EPUB sample.",
        "filename": "book.epub"}).original_bytes


def _demo_jpeg(px: bytearray) -> bytes:
    try:
        import io as _io
        from PIL import Image
        im = Image.frombytes("RGBA", (64, 64), bytes(px)).convert("RGB")
        buf = _io.BytesIO()
        im.save(buf, "JPEG", quality=85)
        return buf.getvalue()
    except Exception:
        # tiny embedded 1x1 JPEG fallback (standard minimal baseline JPEG)
        return bytes.fromhex(
            "ffd8ffe000104a46494600010100000100010000ffdb004300100b0c0e0c0a100e0d0e1211101318281a18"
            "1616183123251d283a333d3c3933383740485c4e404457453738506d51575f626768673e4d71797064785c65"
            "6763ffc0000b080001000101011100ffc40014000100000000000000000000000000000009ffc400141001"
            "00000000000000000000000000000000ffda00080001000100003f00d2cf20ffd9")


def _demo_wav() -> bytes:
    from .adapters.audio import WavAdapter
    return WavAdapter().create(None, {"freq": 440.0, "duration": 0.5,
                                      "sample_rate": 22050,
                                      "filename": "tone.wav"}).original_bytes


def _box(typ: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def _demo_mp4_skeleton() -> bytes:
    """Structurally valid ISO-BMFF skeleton (no samples — not playable)."""
    ftyp = _box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2mp41")
    # mvhd v0
    mvhd_pl = (struct.pack(">IIIII", 0, 0, 0, 1000, 2500) +   # verflags, c, m, ts, dur
               struct.pack(">IHH", 0x00010000, 0x0100, 0) +   # rate, volume, reserved
               b"\x00" * 8 +                                   # reserved
               struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
               b"\x00" * 24 + struct.pack(">I", 3))
    mvhd = _box(b"mvhd", mvhd_pl)
    # tkhd v0 (track 1)
    tkhd_pl = (struct.pack(">IIIII", 0, 0, 0, 1, 0) +          # verflags, c, m, id, res
               struct.pack(">I", 2500) +                        # duration
               b"\x00" * 8 + struct.pack(">HHHH", 0, 0, 0, 0) +
               struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
               struct.pack(">II", 320 << 16, 240 << 16))        # width, height 16.16
    tkhd = _box(b"tkhd", tkhd_pl)
    mdhd_pl = struct.pack(">IIIII", 0, 0, 0, 1000, 2500) + struct.pack(">HH", 0x55c4, 0)
    mdhd = _box(b"mdhd", mdhd_pl)
    hdlr_pl = struct.pack(">II", 0, 0) + b"vide" + b"\x00" * 12 + b"VideoHandler\x00"
    hdlr = _box(b"hdlr", hdlr_pl)
    # stsd with one avc1 entry (visual sample entry prefix)
    avc1_pl = (b"\x00" * 6 + struct.pack(">H", 1) + b"\x00" * 16 +
               struct.pack(">HH", 320, 240) + struct.pack(">II", 0x00480000, 0x00480000) +
               b"\x00" * 4 + struct.pack(">H", 1) + b"\x00" * 32 +
               struct.pack(">H", 24) + struct.pack(">h", -1) + b"avc1" + b"\x00" * 40)
    stsd = _box(b"stsd", struct.pack(">II", 0, 1) + _box(b"avc1", avc1_pl))
    stts = _box(b"stts", struct.pack(">III", 0, 0, 0))
    stsc = _box(b"stsc", struct.pack(">I", 0))
    stsz = _box(b"stsz", struct.pack(">III", 0, 0, 0))
    stco = _box(b"stco", struct.pack(">I", 0))
    stbl = _box(b"stbl", stsd + stts + stsc + stsz + stco)
    minf = _box(b"minf", stbl)
    mdia = _box(b"mdia", mdhd + hdlr + minf)
    trak = _box(b"trak", tkhd + mdia)
    moov = _box(b"moov", mvhd + trak)
    mdat = _box(b"mdat", b"")
    return ftyp + moov + mdat


def _ebml_vint(value: int, min_len: int = 1) -> bytes:
    """Encode an EBML VINT (data size)."""
    for length in range(min_len, 9):
        max_val = (1 << (7 * length)) - 1
        if value < max_val:
            marker = 1 << (8 - length)
            raw = value | (marker << (8 * (length - 1)))
            return raw.to_bytes(length, "big")
    raise ValueError("vint too large")


def _ebml_id(eid: int) -> bytes:
    return eid.to_bytes((eid.bit_length() + 7) // 8, "big")


def _ebml(eid: int, payload: bytes) -> bytes:
    return _ebml_id(eid) + _ebml_vint(len(payload)) + payload


def _ebml_uint(eid: int, value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return _ebml(eid, raw)


def _ebml_str(eid: int, s: str) -> bytes:
    return _ebml(eid, s.encode())


def _demo_mkv_skeleton() -> bytes:
    """Structurally valid Matroska skeleton (Info + one video track)."""
    head = (_ebml_uint(0x4286, 1) + _ebml_uint(0x42F7, 1) +
            _ebml_str(0x4282, "matroska") + _ebml_uint(0x42F2, 4) +
            _ebml_uint(0x42F3, 8))
    ebml = _ebml(0x1A45DFA3, head)
    info = (_ebml_uint(0x2AD7B1, 1000000) +          # TimecodeScale 1ms
            _ebml(0x4489, struct.pack(">f", 2500.0)) +  # Duration (ticks)
            _ebml_str(0x4D80, "SUPERFILE") + _ebml_str(0x5741, "SUPERFILE"))
    video = _ebml_uint(0xB0, 320) + _ebml_uint(0xBA, 240)
    track = (_ebml_uint(0xD7, 1) + _ebml_uint(0x73C5, 1) + _ebml_uint(0x83, 1) +
             _ebml_str(0x86, "V_MPEG4/ISO/AVC") + _ebml(0xE0, video))
    tracks = _ebml(0x1654AE6B, _ebml(0xAE, track))
    seg = _ebml(0x18538067, _ebml(0x1549A966, info) + tracks)
    return ebml + seg


def _demo_stl() -> bytes:
    from .adapters.three_d import obj_to_triangles, tris_to_stl
    cube = (b"v -1 -1 -1\nv 1 -1 -1\nv 1 1 -1\nv -1 1 -1\n"
            b"v -1 -1 1\nv 1 -1 1\nv 1 1 1\nv -1 1 1\n"
            b"f 1 2 3 4\nf 5 8 7 6\nf 1 5 6 2\nf 2 6 7 3\nf 3 7 8 4\nf 5 1 4 8\n")
    return tris_to_stl(obj_to_triangles(cube))


def _demo_glb() -> bytes:
    gltf = {
        "asset": {"version": "2.0", "generator": "SUPERFILE demo"},
        "scene": 0, "scenes": [{"nodes": [0]}],
        "nodes": [{"mesh": 0, "name": "triangle"}],
        "meshes": [{"name": "tri", "primitives": [{"attributes": {"POSITION": 0}}]}],
        "accessors": [{"bufferView": 0, "componentType": 5126, "count": 3,
                       "type": "VEC3", "min": [0, 0, 0], "max": [1, 1, 0]}],
        "bufferViews": [{"buffer": 0, "byteOffset": 0, "byteLength": 36}],
        "buffers": [{"byteLength": 36}],
    }
    raw = struct.pack("<9f", 0, 0, 0, 1, 0, 0, 0, 1, 0)
    j = json.dumps(gltf, separators=(",", ":")).encode()
    j += b" " * ((4 - len(j) % 4) % 4)
    raw += b"\x00" * ((4 - len(raw) % 4) % 4)
    total = 12 + 8 + len(j) + 8 + len(raw)
    return (struct.pack("<4sII", b"glTF", 2, total) +
            struct.pack("<I4s", len(j), b"JSON") + j +
            struct.pack("<I4s", len(raw), b"BIN\0") + raw)


def _demo_zip() -> bytes:
    from .codecs import png as png_codec
    px = bytearray()
    for y in range(16):
        for x in range(16):
            px += bytes((x * 16 % 256, y * 16 % 256, 160, 255))
    png = png_codec.encode_from_rgba(bytes(px), 16, 16)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", "Nested text inside the SUPERFILE demo ZIP.\n")
        zf.writestr("images/mini.png", png)
        zf.writestr("models/tri.obj", b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n")
    return buf.getvalue()


def _demo_targz() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in (("notes.txt", b"Archive notes for SUPERFILE demo.\n"),
                           ("hello.py", b"print('inside tarball')\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
        g.write(raw.getvalue())
    return gz.getvalue()


def _demo_wasm() -> bytes:
    from .adapters.executable import _uleb
    name = b"superfile-demo"
    custom = bytes([0]) + _uleb(1 + len(name)) + _uleb(len(name)) + name
    return b"\x00asm\x01\x00\x00\x00" + custom


def _demo_pe() -> bytes:
    """Minimal PE32 header skeleton for static-inspection demos."""
    out = bytearray()
    out += b"MZ" + b"\x00" * 58
    out += struct.pack("<I", 0x80)                     # e_lfanew
    out += b"\x00" * (0x80 - len(out))
    out += b"PE\0\0"
    # COFF header
    out += struct.pack("<HHIIIHH", 0x14C, 1, 0x60000000, 0, 0, 0xE0, 0x2102)
    # optional header (PE32)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)              # magic PE32
    opt[2], opt[3] = 14, 0                             # linker
    struct.pack_into("<I", opt, 16, 0x1000)            # entry point
    struct.pack_into("<I", opt, 28, 0x400000)          # image base
    struct.pack_into("<I", opt, 32, 0x1000)            # section alignment
    struct.pack_into("<I", opt, 36, 0x200)             # file alignment
    struct.pack_into("<HH", opt, 40, 6, 0)             # os version
    struct.pack_into("<I", opt, 56, 0x3000)            # size of image
    struct.pack_into("<I", opt, 60, 0x200)             # size of headers
    struct.pack_into("<H", opt, 68, 3)                 # subsystem CUI
    struct.pack_into("<I", opt, 92, 16)                # number of rva/sizes
    struct.pack_into("<II", opt, 96 + 8, 0x2000, 0x28) # import dir
    out += opt
    # one section .text
    sect = bytearray(40)
    sect[0:5] = b".text"
    struct.pack_into("<IIII", sect, 8, 0x200, 0x1000, 0x200, 0x200)  # vsize,va,rawsize,rawptr
    struct.pack_into("<I", sect, 36, 0x60000020)       # CODE|EXECUTE|READ
    out += sect
    # pad to raw pointer + section content with import strings
    out += b"\x00" * (0x400 - len(out))
    import_table = (struct.pack("<IIIII", 0x20A0, 0, 0, 0x20C0, 0x20A0) +
                    b"\x00" * 20)
    out += import_table
    out += b"KERNEL32.dll\x00\x00\x00\x00LoadLibraryA\x00\x00ExitProcess\x00"
    return bytes(out)


def _demo_elf() -> bytes:
    """Minimal ELF64 header skeleton for static-inspection demos."""
    out = bytearray()
    out += b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8   # e_ident
    out += struct.pack("<HHIQQQIHHHHHH",
                       2,        # e_type EXEC
                       0x3E,     # e_machine x86-64
                       1,        # e_version
                       0x401000, # e_entry
                       64,       # e_phoff
                       0,        # e_shoff (none)
                       0,        # e_flags
                       64,       # e_ehsize
                       56,       # e_phentsize
                       2,        # e_phnum
                       64,       # e_shentsize
                       0,        # e_shnum
                       0)        # e_shstrndx
    # program headers: PT_LOAD + PT_DYNAMIC
    out += struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x200, 0x200, 0x1000)  # LOAD R+X
    out += struct.pack("<IIQQQQQQ", 2, 6, 0x200, 0x400200, 0x400200, 0x100, 0x100, 8)   # DYNAMIC
    out += b"\x00" * (0x200 - len(out))
    # dynamic entries: NEEDED libc.so.6, SONAME sample.elf
    def dyn(tag, val):
        return struct.pack("<qQ", tag, val)
    out += dyn(1, 0x230)     # NEEDED -> strtab offset
    out += dyn(14, 0x23C)    # SONAME
    out += dyn(5, 0x230)     # STRTAB
    out += dyn(0, 0)         # NULL
    out += b"\x00" * (0x230 - len(out))
    out += b"\x00libc.so.6\x00sample.elf\x00"
    return bytes(out)


def _demo_sqlite() -> bytes:
    import sqlite3
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "sf_tmp_demo.sqlite")
    if os.path.exists(tmp):
        os.unlink(tmp)
    con = sqlite3.connect(tmp)
    cur = con.cursor()
    cur.execute("CREATE TABLE formats (id INTEGER PRIMARY KEY, name TEXT, family TEXT)")
    cur.executemany("INSERT INTO formats (name, family) VALUES (?, ?)",
                    [("png", "IMAGE"), ("wav", "AUDIO"), ("zip", "ARCHIVE")])
    cur.execute("CREATE TABLE objects (id INTEGER PRIMARY KEY, label TEXT, size INTEGER)")
    cur.executemany("INSERT INTO objects (label, size) VALUES (?, ?)",
                    [("alpha", 1024), ("beta", 2048)])
    cur.execute("CREATE TABLE notes (body TEXT)")
    cur.execute("INSERT INTO notes VALUES ('hello from the SUPERFILE sqlite sample')")
    con.commit()
    con.close()
    with open(tmp, "rb") as fh:
        data = fh.read()
    try:
        os.unlink(tmp)
    except OSError:
        pass
    return data


def _demo_project(target_path: str) -> bytes:
    """Build a SUPERFILE object graph: project → txt + png + obj + meta."""
    from . import pipeline, protocol

    root = pipeline.create_object("project", {
        "filename": "project.sfp",
        "title": "SUPERFILE Demo Project",
        "note": "An entire project as one object: document + image + mesh + metadata.",
    })
    txt = pipeline.import_bytes("readme.txt", b"Project notes preserved inside SUPERFILE.\n")
    px = bytearray()
    for y in range(24):
        for x in range(24):
            px += bytes((x * 10 % 256, 80, y * 10 % 256, 255))
    from .codecs import png as png_codec
    png = png_codec.encode_from_rgba(bytes(px), 24, 24)
    img = pipeline.import_bytes("cover.png", png)
    obj = pipeline.import_bytes("tri.obj", b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n")
    root.add_child(txt, relation="contains", note="project document")
    root.add_child(img, relation="contains", note="project image")
    root.add_child(obj, relation="contains", note="project mesh")
    return protocol.dumps(root)


if __name__ == "__main__":
    import sys
    out = generate_all(sys.argv[1] if len(sys.argv) > 1 else None)
    print(json.dumps({"created": out}, indent=2))

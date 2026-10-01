"""
SUPERFILE — self-test suite (stdlib unittest).

Run:  python3 -m tests.test_all         (or python3 -m superfile test)

Covers the 10 "what counts as success" criteria + security + protocol
integrity + conversion-matrix honesty + the example plugin adapter.
Results printed at the end are real — nothing is claimed without being tested.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import unittest
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from superfile import demo, pipeline, protocol                    # noqa: E402
from superfile.detection import detect_format                     # noqa: E402
from superfile.object_model import ObjectType, SupportLevel       # noqa: E402
from superfile.security import (                                  # noqa: E402
    UnsafeInputError, sanitize_archive_path)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_DIR = os.path.join(ROOT, "demo")


def setUpModule():
    if not os.path.isdir(DEMO_DIR) or not os.listdir(DEMO_DIR):
        demo.generate_all(DEMO_DIR)
    pipeline.reset_engines()


class TestDetection(unittest.TestCase):
    """Success #1 + #5: many formats import; detection is signature-based."""

    def test_magic_overrides_extension(self):
        self.assertEqual(detect_format(b"\x89PNG\r\n\x1a\nxxxx", "zzz.bin").format_id, "png")
        self.assertEqual(detect_format(b"%PDF-1.4\n", "zzz.txt").format_id, "pdf")
        self.assertEqual(detect_format(b"\x7fELF\x02\x01\x01", "zzz.dat").format_id, "elf")
        self.assertEqual(detect_format(b"GIF89a....", "zzz.doc").format_id, "gif")
        self.assertEqual(detect_format(b"\xff\xd8\xff\xe0....", "zzz.zip").format_id, "jpeg")
        self.assertEqual(detect_format(b"PK\x03\x04", "zzz.bin").format_id, "zip")
        self.assertEqual(detect_format(b"RIFF\x00\x00\x00\x00WAVEfmt ", "zzz.bin").format_id, "wav")
        self.assertEqual(detect_format(b"\x00\x00\x00\x18ftypisom", "zzz.bin").format_id, "mp4")
        self.assertEqual(detect_format(b"\x1aE\xdf\xa3\x42\x86", "zzz.bin").format_id, "mkv")
        self.assertEqual(detect_format(b"\x8bSFP\r\n\x1a\n", "zzz.bin").format_id, "sfp")
        self.assertEqual(detect_format(b"\x00asm\x01\x00\x00\x00", "zzz.bin").format_id, "wasm")
        self.assertEqual(detect_format(b"7z\xbc\xaf\x27\x1c", "zzz.bin").format_id, "7z")
        self.assertEqual(detect_format(b"{\\rtf1\\ansi x", "zzz.bin").format_id, "rtf")

    def test_zip_subtypes(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", "<w:document/>")
        self.assertEqual(detect_format(buf.getvalue(), "a.zip").format_id, "docx")

    def test_all_demo_files_detect(self):
        for name in sorted(os.listdir(DEMO_DIR)):
            if name == "SAMPLES.json":
                continue
            with open(os.path.join(DEMO_DIR, name), "rb") as fh:
                det = detect_format(fh.read(), name)
            self.assertNotEqual(det.format_id, "empty", name)
            self.assertGreaterEqual(det.confidence, 0.3, name)


class TestImportAndInspect(unittest.TestCase):
    """Success #1-#4: import many formats → UniversalObjects → one inspector."""

    def _load(self, name):
        return pipeline.import_file(os.path.join(DEMO_DIR, name))

    def test_families_import(self):
        families = {
            "hello.txt": "TEXT", "readme.md": "TEXT", "table.csv": "TEXT",
            "data.json": "TEXT", "letter.pdf": "DOCUMENT", "doc.docx": "DOCUMENT",
            "book.epub": "DOCUMENT", "notes.rtf": "DOCUMENT",
            "pixel.png": "IMAGE", "photo.jpg": "IMAGE", "anim.gif": "ANIMATION",
            "icon.bmp": "IMAGE", "logo.svg": "IMAGE",
            "tone.wav": "AUDIO",
            "movie.mp4": "VIDEO", "clip.mkv": "VIDEO",
            "mesh.obj": "3D", "part.stl": "3D", "scene.glb": "3D",
            "bundle.zip": "ARCHIVE", "archive.tar.gz": "ARCHIVE",
            "sample.exe": "EXECUTABLE", "sample.elf": "EXECUTABLE", "demo.wasm": "EXECUTABLE",
            "hello.py": "SOURCE_CODE", "main.c": "SOURCE_CODE",
            "data.sqlite": "DATABASE", "blob.bin": "BINARY",
            "project.sfp": "PROTOCOL",
        }
        for name, family in families.items():
            obj = self._load(name)
            self.assertEqual(obj.object_type.value, family,
                             f"{name} → {obj.object_type.value} != {family}")
            self.assertTrue(obj.checksum, name)
            self.assertIsNotNone(obj.original_bytes, name)

    def test_universal_inspector_shape(self):
        for name in ("pixel.png", "sample.exe", "bundle.zip", "data.json", "mesh.obj"):
            rep = pipeline.inspect_object(self._load(name))
            for section in ("general", "structure", "format"):
                self.assertIn(section, rep, f"{name} inspector missing {section}")
            self.assertEqual(len(rep["general"]["hash"]), 64, name)
            self.assertIn("capabilities", rep["format"])

    def test_png_pixels_decoded(self):
        obj = self._load("pixel.png")
        self.assertEqual(obj.content["width"], 64)
        self.assertIsNotNone(obj.get_blob(obj.content["pixels"]))

    def test_pdf_text_extracted(self):
        obj = self._load("letter.pdf")
        self.assertIn("SUPERFILE PDF sample", obj.content.get("raw_text", ""))

    def test_wav_peaks(self):
        obj = self._load("tone.wav")
        self.assertGreater(len(obj.content.get("peaks", [])), 10)

    def test_gif_frames(self):
        obj = self._load("anim.gif")
        self.assertEqual(obj.content["frame_count"], 4)

    def test_exe_never_marked_runnable(self):
        for name in ("sample.exe", "sample.elf", "demo.wasm"):
            obj = self._load(name)
            self.assertEqual(obj.support_level, SupportLevel.INSPECTION)
            self.assertTrue(any("never executed" in w.lower() for w in obj.warnings), name)


class TestEditingTransforms(unittest.TestCase):
    """Success #5: objects can be edited / transformed (history recorded)."""

    def test_text_edit_preserves_original(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "hello.txt"))
        original = obj.original_bytes
        obj = pipeline.edit_object(obj, "set_text", {"text": "edited!"})
        self.assertEqual(obj.content["text"], "edited!")
        self.assertEqual(obj.original_bytes, original)      # lossless preservation
        self.assertTrue(any(t.action == "edit.set_text" for t in obj.transformations))

    def test_image_transforms(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "pixel.png"))
        obj = pipeline.transform_object(obj, "image.resize", {"width": 32, "height": 16})
        self.assertEqual((obj.content["width"], obj.content["height"]), (32, 16))
        obj = pipeline.transform_object(obj, "image.rotate", {"degrees": 90})
        self.assertEqual((obj.content["width"], obj.content["height"]), (16, 32))
        obj = pipeline.transform_object(obj, "image.crop",
                                        {"x": 0, "y": 0, "width": 8, "height": 8})
        self.assertEqual((obj.content["width"], obj.content["height"]), (8, 8))
        self.assertGreaterEqual(len(obj.transformations), 3)

    def test_json_transforms(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "data.json"))
        obj = pipeline.transform_object(obj, "json.minify", {})
        self.assertNotIn("\n", obj.content["text"])
        obj = pipeline.transform_object(obj, "json.to_yaml", {})
        self.assertIn("yaml", obj.content["derived"])

    def test_md_to_html(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "readme.md"))
        obj = pipeline.transform_object(obj, "text.markdown_to_html", {})
        self.assertIn("<h1>", obj.content["derived"]["html"])

    def test_gif_frame_extract_child(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "anim.gif"))
        obj = pipeline.transform_object(obj, "gif.extract_frame", {"index": 2})
        self.assertEqual(len(obj.children), 1)
        self.assertEqual(obj.children[0].detected_format, "png")

    def test_zip_extract_children(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "bundle.zip"))
        obj = pipeline.transform_object(obj, "archive.extract_all", {})
        kinds = sorted(c.detected_format for c in obj.children)
        self.assertIn("png", kinds)
        self.assertIn("txt", kinds)


class TestExport(unittest.TestCase):
    """Success #6: export back to standard formats (truthful kinds)."""

    def test_png_roundtrip_lossless(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "pixel.png"))
        res = pipeline.export_object(obj, "png")
        back = pipeline.import_bytes("x.png", res.data)
        self.assertEqual(back.checksum,
                         pipeline.import_bytes("y.png", obj.original_bytes).checksum)

    def test_json_yaml_toml(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "data.json"))
        y = pipeline.export_object(obj, "yaml")
        self.assertIn(b"app:", y.data)
        t = pipeline.export_object(obj, "toml")
        self.assertIn(b"version", t.data)
        r = pipeline.export_object(obj, "json")
        self.assertEqual(json.loads(r.data)["app"], "SUPERFILE")

    def test_txt_to_html(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "hello.txt"))
        res = pipeline.export_object(obj, "html")
        self.assertIn(b"<!doctype html>", res.data)
        self.assertEqual(res.kind, "RECONSTRUCTED")

    def test_obj_to_stl(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "mesh.obj"))
        res = pipeline.export_object(obj, "stl")
        back = pipeline.import_bytes("x.stl", res.data)
        self.assertEqual(back.content["triangles"], 12)

    def test_pdf_to_text(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "letter.pdf"))
        res = pipeline.export_object(obj, "txt")
        self.assertIn(b"SUPERFILE PDF sample", res.data)

    def test_docx_to_html(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "doc.docx"))
        res = pipeline.export_object(obj, "html")
        self.assertIn(b"paragraph", res.data.lower())

    def test_wav_metadata_json(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "tone.wav"))
        res = pipeline.export_object(obj, "json")
        self.assertIn(b"sample_rate", res.data)

    def test_every_advertised_export_actually_works_or_refuses_honestly(self):
        """For every listed export target, export must work or raise a clear error
        for content that structurally cannot convert (e.g. JSON→TOML of nested)."""
        for name in ("data.json", "pixel.png", "hello.txt", "mesh.obj", "letter.pdf"):
            obj = pipeline.import_file(os.path.join(DEMO_DIR, name))
            for opt_ in obj.export_formats:
                fmt = opt_.format if hasattr(opt_, "format") else opt_["format"]
                try:
                    res = pipeline.export_object(obj, fmt)
                    self.assertGreater(len(res.data), 0, f"{name} → {fmt}")
                    self.assertTrue(res.kind, f"{name} → {fmt} kind missing")
                except UnsafeInputError as exc:
                    # refusals must be explicit and explanatory
                    self.assertTrue(str(exc), f"{name} → {fmt} empty refusal")


class TestProtocol(unittest.TestCase):
    """Success #7/#8: .sfp preserves originals + nesting.  Checksums verified."""

    def test_sfp_roundtrip_all_samples(self):
        for name in sorted(os.listdir(DEMO_DIR)):
            if name == "SAMPLES.json":
                continue
            obj = pipeline.import_file(os.path.join(DEMO_DIR, name))
            blob = protocol.dumps(obj)
            back = protocol.loads(blob)
            self.assertEqual(back.checksum, obj.checksum, name)
            self.assertEqual(back.detected_format, obj.detected_format, name)
            self.assertEqual(back.object_type, obj.object_type, name)
            self.assertEqual(len(back.children), len(obj.children), name)

    def test_nested_graph(self):
        root = pipeline.create_object("project", {"title": "T"})
        root.add_child(pipeline.import_file(os.path.join(DEMO_DIR, "hello.txt")))
        root.add_child(pipeline.import_file(os.path.join(DEMO_DIR, "pixel.png")))
        nested = pipeline.import_file(os.path.join(DEMO_DIR, "project.sfp"))
        root.add_child(nested, relation="contains")
        blob = protocol.dumps(root)
        back = protocol.loads(blob)
        self.assertEqual(len(back.children), 3)
        # depth: root → project.sfp → 3 children
        inner = back.children[2]
        self.assertEqual(inner.detected_format, "sfp")
        self.assertEqual(len(inner.children), 3)
        self.assertEqual(sum(1 for _ in back.walk()), 1 + 3 + 3)

    def test_original_bytes_preserved(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "photo.jpg"))
        back = protocol.loads(protocol.dumps(obj))
        self.assertEqual(back.original_bytes, obj.original_bytes)

    def test_checksum_detects_corruption(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "hello.txt"))
        blob = bytearray(protocol.dumps(obj))
        blob[len(blob) // 2] ^= 0xFF
        with self.assertRaises(Exception):
            protocol.loads(bytes(blob))

    def test_unknown_chunks_are_skipped(self):
        """Forward compatibility: unknown chunks must not break old readers."""
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "hello.txt"))
        blob = bytearray(protocol.dumps(obj))
        # insert an unknown chunk before the final CKSM chunk
        cksm_off = bytes(blob).rfind(b"CKSM")
        extra = b"XTRA" + struct.pack(">Q", 4) + b"data"
        new = bytes(blob[:cksm_off]) + extra + bytes(blob[cksm_off:])
        # recompute checksum: the checksum covers everything before CKSM
        cksm2 = new.rfind(b"CKSM")
        digest = zlib.crc32(b"")  # placeholder to import nothing extra
        import hashlib
        digest = hashlib.sha256(new[:cksm2]).digest()
        new = new[:cksm2] + b"CKSM" + struct.pack(">Q", 32) + digest
        back = protocol.loads(new)
        self.assertEqual(back.checksum, obj.checksum)
        self.assertIn("XTRA", back.metadata.get("sfp", {}).get("unknown_chunks", []))

    def test_container_description(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "pixel.png"))
        desc = protocol.describe_container(protocol.dumps(obj))
        self.assertTrue(desc["is_sfp"])
        tags = [c["tag"] for c in desc["chunks"]]
        self.assertIn("META", tags)
        self.assertIn("CKSM", tags)


class TestSecurity(unittest.TestCase):
    """Success #9 + security model."""

    def test_path_traversal_blocked(self):
        self.assertEqual(sanitize_archive_path("../../etc/passwd"), "")
        self.assertEqual(sanitize_archive_path("..\\..\\win.ini"), "")
        self.assertEqual(sanitize_archive_path("/etc/passwd"), "etc/passwd")
        self.assertEqual(sanitize_archive_path("C:\\evil.dll"), "evil.dll")
        self.assertEqual(sanitize_archive_path("ok/fine.txt"), "ok/fine.txt")

    def test_zip_bomb_ratio_guard(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", b"\x00" * 20_000_000)
        with self.assertRaises(Exception):
            pipeline.import_bytes("bomb.zip", buf.getvalue())

    def test_zip_traversal_entry_skipped(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("good.txt", "safe")
            zf.writestr("../evil.txt", "evil")
        obj = pipeline.import_bytes("t.zip", buf.getvalue())
        paths = [e["path"] for e in obj.content["entries"]]
        self.assertIn("good.txt", paths)
        self.assertNotIn("evil.txt", paths)
        self.assertTrue(any("unsafe path" in w for w in obj.warnings))

    def test_corrupt_sfp_rejected(self):
        with self.assertRaises(Exception):
            protocol.loads(b"\x8bSFP\r\n\x1a\n" + b"\x00" * 100)

    def test_oversized_import_rejected(self):
        with self.assertRaises(Exception):
            pipeline.import_bytes("big.bin", b"\x00" * (65 * 1024 * 1024))

    def test_never_executes(self):
        """The registry exposes no 'run' capability anywhere."""
        reg = pipeline.get_registry()
        for fid, caps in ((fid, ad.caps(fid)) for fid, ad in reg.by_format.items()):
            self.assertNotIn("run", caps, fid)
            self.assertNotIn("execute", caps, fid)


class TestConversionMatrix(unittest.TestCase):
    """Success + honesty: only real conversions are advertised."""

    def test_no_impossible_conversions(self):
        reg = pipeline.get_registry()
        matrix = reg.conversion_matrix()
        # video containers export only reports + sfp — never 'mp4 → avi' fantasies
        for src in ("mp4", "mkv", "webm", "avi", "mov", "aac", "mp3", "flac", "ogg"):
            targets = {o["format"] for o in matrix.get(src, [])}
            for bad in ("png", "jpg", "wav", "mp3", "docx", "exe"):
                self.assertNotIn(bad, targets, f"{src} must not claim → {bad}")
        # executables never claim media exports
        for src in ("pe", "elf", "wasm"):
            targets = {o["format"] for o in matrix.get(src, [])}
            for bad in ("png", "mp4", "docx"):
                self.assertNotIn(bad, targets, f"{src} must not claim → {bad}")

    def test_kinds_are_declared(self):
        obj = pipeline.import_file(os.path.join(DEMO_DIR, "pixel.png"))
        for o in obj.export_formats:
            d = o.to_dict() if hasattr(o, "to_dict") else o
            self.assertIn(d["kind"], ("LOSSLESS", "LOSSY", "STRUCTURAL",
                                      "RENDERED", "RECONSTRUCTED"))
            self.assertTrue(d["label"])


class TestExamplePlugin(unittest.TestCase):
    """Success #10: a new format is added WITHOUT touching the protocol."""

    def test_ppm_example_adapter(self):
        sys.path.insert(0, os.path.join(ROOT, "examples", "new_format_adapter"))
        import ppm_adapter  # noqa
        from superfile.registry import FormatRegistry
        from superfile.adapters.base import ExportResult  # noqa: F401

        reg = FormatRegistry()
        for ad in pipeline.get_registry().adapters:
            reg.register(ad)
        reg.register(ppm_adapter.PpmAdapter())
        self.assertIn("ppm", reg.by_format)

        # create → export → re-import through the plugin itself
        obj = reg.adapter_for("ppm").create(None, {"width": 16, "height": 16})
        self.assertEqual(obj.detected_format, "ppm")
        res = reg.adapter_for("ppm").export(obj, "ppm")
        back = reg.adapter_for("ppm").read(res.data, "x.ppm")
        self.assertEqual(back.content["width"], 16)

        # cross-adapter export (PPM → PNG via core codec) also works
        res = reg.adapter_for("ppm").export(obj, "png")
        self.assertTrue(res.data.startswith(b"\x89PNG"))

        # detection agrees with the plugin
        self.assertGreaterEqual(reg.adapter_for("ppm").detect(res.data[:0] or b"P6 ", "x"), 0.0)
        self.assertGreaterEqual(reg.adapter_for("ppm").detect(b"P6\n1 1\n255\n\x00\x00\x00", "x"), 0.9)

        # .sfp round-trip of a plugin object
        blob = protocol.dumps(obj)
        self.assertEqual(protocol.loads(blob).checksum, obj.checksum)


class TestCreators(unittest.TestCase):
    """Success #4-ish: the Universal Creator produces exportable objects."""

    def test_every_creator_target(self):
        for target in pipeline.CREATOR_TARGETS:
            obj = pipeline.create_object(target["id"], {})
            self.assertTrue(obj.checksum, target["id"])
            self.assertGreaterEqual(len(obj.export_formats), 1, target["id"])

    def test_created_animation_plays_structure(self):
        obj = pipeline.create_object("animation", {"frames": 3})
        self.assertEqual(obj.content["frame_count"], 3)


class TestRegistry(unittest.TestCase):
    def test_format_database_rows(self):
        rows = pipeline.get_registry().format_database()
        self.assertGreaterEqual(len(rows), 25)
        cols = {"format", "extension", "category", "mime", "read", "create",
                "edit", "export", "detection", "support"}
        for r in rows:
            self.assertTrue(cols.issubset(r.keys()))

    def test_adapter_manifests(self):
        for m in pipeline.get_registry().manifests():
            self.assertIn("name", m)
            self.assertIn("formats", m)
            self.assertIn("capabilities", m)
            self.assertIn("input_types", m)
            self.assertIn("output_types", m)


class TestUiLayoutToggles(unittest.TestCase):
    """Collapsible top chrome + sidebar: STATIC guards that fail if a hook the toggles or app.js rely on is
    removed, or if the change stops being purely additive.  The real-browser proof (geometry, animation,
    persistence, DOM identity, A/B click-through) lives in tests/ui_layout_check.py."""

    ORIGINAL_IDS = (
        "app", "titlebar", "toolbar", "main", "sidebar", "content", "statusbar", "status", "status-right",
        "btn-open", "btn-import-path", "btn-create", "btn-save-sfp", "btn-export", "btn-inspect", "btn-edit",
        "btn-transform", "file-input", "create-menu", "recent-list", "object-tree", "object-header",
        "oh-name", "oh-support", "oh-type", "oh-format", "oh-mime", "oh-size", "oh-hash", "oh-detect",
        "oh-caps", "oh-warnings", "tabs", "tab-body", "welcome", "w-open", "w-create", "w-demo")

    @classmethod
    def setUpClass(cls):
        def rd(name):
            with open(os.path.join(ROOT, "ui", name), encoding="utf-8") as fh:
                return fh.read()
        cls.html, cls.css, cls.js = rd("index.html"), rd("app.css"), rd("app.js")

    @staticmethod
    def _tag(html, ident):
        m = re.search(r'<button id="%s"[^>]*>' % re.escape(ident), html, re.S)
        return m.group(0) if m else ""

    def test_original_ids_still_present(self):
        for ident in self.ORIGINAL_IDS:
            self.assertEqual(self.html.count('id="%s"' % ident), 1, ident)

    def test_original_controls_untouched(self):
        # Task C appended two toolbar buttons (#btn-encrypt, #btn-decrypt) and two content tabs
        # (data-tab=encrypt/decrypt).  The ORIGINAL 8 buttons / 5 sidebar links / 12 tabs must all
        # still be there, in their original order, with the additions at the end.
        self.assertEqual(len(re.findall(r'class="tool[ "]', self.html)), 10)        # 8 original + 2 new
        self.assertEqual(len(re.findall(r'<a href="#" data-tab="', self.html)), 5)  # sidebar NAVIGATION links (unchanged)
        self.assertEqual(len(re.findall(r'<button data-tab="', self.html)), 14)     # 12 original + 2 new
        for ident in ("btn-open", "btn-import-path", "btn-create", "btn-save-sfp", "btn-export",
                      "btn-inspect", "btn-edit", "btn-transform"):      # the original 8, by id
            self.assertIn('id="%s"' % ident, self.html)                # the original 8 toolbar buttons, by id
        tab_order = re.findall(r'<button data-tab="([a-z]+)"', self.html)
        self.assertEqual(tab_order[:12], ["view", "edit", "inspect", "transform", "export", "history",
                                          "graph", "registry", "explorer", "matrix", "demo", "about"])
        self.assertEqual(tab_order[12:], ["encrypt", "decrypt"])
        self.assertTrue(self.js.count('document.addEventListener("DOMContentLoaded", init);'), 1)

    def test_toggle_buttons_are_plain_buttons_with_aria(self):
        for ident, controls in (("sf-top-toggle", "titlebar toolbar"), ("sf-side-toggle", "sidebar")):
            tag = self._tag(self.html, ident)
            self.assertTrue(tag, ident + " missing")
            self.assertIn('type="button"', tag)
            self.assertIn('aria-expanded="true"', tag)
            self.assertIn('aria-controls="%s"' % controls, tag)
            self.assertNotIn("data-tab", tag)                       # never picked up by the tab / nav wiring
            self.assertIsNone(re.search(r'class="[^"]*\b(tool|tab)\b', tag))   # never picked up by .tool / .tab selectors

    def test_toggle_placement(self):
        h = self.html
        self.assertLess(h.index('<div id="app">'), h.index('id="sf-top-toggle"'))
        self.assertLess(h.index('id="sf-top-toggle"'), h.index('id="titlebar"'))        # above the title bar
        self.assertLess(h.index('id="sidebar"'), h.index('id="sf-side-toggle"'))
        self.assertLess(h.index('id="sf-side-toggle"'), h.index('id="content"'))        # on the sidebar's edge

    def test_persistence_keys_and_every_storage_access_is_guarded(self):
        for key in ("sf_top_collapsed", "sf_sidebar_collapsed"):
            self.assertIn(key, self.js)
            self.assertIn(key, self.html)                           # early restore (no flash)
        for name, text in (("app.js", self.js), ("index.html", self.html)):
            accesses = list(re.finditer(r"window\.localStorage", text))      # real property reads, not comments
            self.assertGreaterEqual(len(accesses), 1, name)
            for m in accesses:
                self.assertIn("try", text[max(0, m.start() - 120):m.start()],
                              name + ": window.localStorage access outside try/catch")

    def test_early_restore_runs_before_stylesheet_and_body(self):
        h = self.html
        self.assertLess(h.index("sf_top_collapsed"), h.index('<link rel="stylesheet"'))
        self.assertLess(h.index('<link rel="stylesheet"'), h.index("<body>"))

    def test_css_collapse_rules_and_reduced_motion(self):
        css = re.sub(r"\s+", " ", self.css)
        self.assertIn("html.sf-top-collapsed #titlebar, html.sf-top-collapsed #toolbar { display: none; }", css)
        self.assertRegex(css, r"html\.sf-side-collapsed #sidebar \{ width: 0; min-width: 0;")
        self.assertIn("prefers-reduced-motion: reduce", css)
        self.assertNotIn(".collapsed", css)                          # never reuse a generic class name

    def test_change_is_purely_additive_at_the_end_of_the_files(self):
        self.assertLess(self.js.index('document.addEventListener("DOMContentLoaded", init);'),
                        self.js.index("layout toggles"))            # appended AFTER the untouched app code
        self.assertLess(self.css.index("#statusbar {"), self.css.index("LAYOUT TOGGLES"))

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_app_js_parses(self):
        r = subprocess.run([shutil.which("node"), "--check", os.path.join(ROOT, "ui", "app.js")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)


class TestObjectHeaderSlide(unittest.TestCase):
    """The file-details slide: STATIC guards.  The real-browser proof (slide frames, tab-strip anchor,
    scroll position, persistence, composition with the existing "hidden" class) is in
    tests/ui_layout_check.py --spawn-*."""

    MOVED = ("oh-type", "oh-format", "oh-mime", "oh-size", "oh-hash", "oh-detect", "oh-caps", "oh-warnings")

    @classmethod
    def setUpClass(cls):
        def rd(name):
            with open(os.path.join(ROOT, "ui", name), encoding="utf-8") as fh:
                return fh.read()
        cls.html, cls.css, cls.js = rd("index.html"), rd("app.css"), rd("app.js")

    def test_existing_hidden_logic_untouched(self):
        # renderObjectHeader() still hides/shows the WHOLE block with the "hidden" class
        for frag in ('if (!d) { $("#object-header").classList.add("hidden"); return; }',
                     '$("#object-header").classList.remove("hidden");'):
            self.assertIn(frag, self.js)
        # the new collapse state must not reuse the name "hidden"
        self.assertNotIn("sf-oh-collapsed", self.js.split('if (!d) { $("#object-header")')[0].split("renderObjectHeader")[-1][:200])

    def test_arrow_button_is_a_plain_button(self):
        m = re.search(r'<button id="sf-oh-toggle"[^>]*>', self.html, re.S)
        self.assertTrue(m, "sf-oh-toggle missing")
        tag = m.group(0)
        self.assertIn('type="button"', tag)
        self.assertIn('aria-controls="sf-oh-details"', tag)
        self.assertIn('aria-expanded="true"', tag)
        self.assertNotIn("data-tab", tag)
        self.assertIsNone(re.search(r'class="[^"]*\b(tool|tab)\b', tag))     # never a .tool / .tab

    def test_arrow_sits_on_the_always_visible_row_and_details_wrap_only_the_details(self):
        h = self.html
        row_end = h.index("</div>", h.index('class="oh-row"'))
        self.assertLess(h.index('id="sf-oh-toggle"'), row_end)                # arrow inside .oh-row
        self.assertLess(h.index('id="oh-support"'), h.index('id="sf-oh-toggle"'))
        det = h.index('id="sf-oh-details"')
        for ident in self.MOVED:                                             # the 8 detail ids live inside it
            self.assertIn('id="%s"' % ident, h)
            self.assertLess(det, h.index('id="%s"' % ident))
            self.assertLess(h.index('id="%s"' % ident), h.index("</div><!-- /#sf-oh-details"))
        self.assertLess(h.index('id="sf-oh-details"'), h.index('id="oh-warnings"'))
        # and the tabs / body are still outside the sliding container, in the same order
        self.assertLess(h.index("</div><!-- /#sf-oh-details"), h.index('id="tabs"'))
        self.assertLess(h.index('id="tabs"'), h.index('id="tab-body"'))

    def test_slide_css(self):
        css = re.sub(r"\s+", " ", self.css)
        self.assertIn("html.sf-oh-collapsed #sf-oh-details { max-height: 0; opacity: 0; }", css)
        self.assertRegex(css, r"html\.sf-anim #sf-oh-details \{ transition: max-height \.2s ease, opacity \.2s ease; \}")
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)
        self.assertIn("#sf-oh-details { overflow: hidden; }", css)

    def test_slide_js_touches_nothing_structural(self):
        i = self.js.index("function objectHeaderSlide()")
        # bound the slice to that IIFE (Task C appends unrelated code after it, which would
        # otherwise be read as part of the slide implementation)
        j = self.js.index("})();", i) + len("})();")
        block = self.js[i:j]
        self.assertIn('getElementById("sf-oh-details")', block)
        self.assertNotIn("tabs", block)            # never touches #tabs / .tab-pane / tab switching
        self.assertNotIn("tab-body", block)
        self.assertNotIn("innerHTML", block)       # never re-renders any content
        self.assertNotIn("renderObjectHeader", block)

    def test_persistence_key_guarded_everywhere(self):
        self.assertIn("sf_objheader_collapsed", self.js)
        self.assertIn("sf_objheader_collapsed", self.html)          # early restore in <head>
        for name, text in (("app.js", self.js), ("index.html", self.html)):
            for m in re.finditer(r"window\.localStorage", text):
                self.assertIn("try", text[max(0, m.start() - 120):m.start()], name + ": unguarded localStorage")

    def test_change_is_additive_and_ordered(self):
        self.assertLess(self.js.index("function layoutToggles()"), self.js.index("function objectHeaderSlide()"))
        self.assertLess(self.css.index("LAYOUT TOGGLES"), self.css.index("OBJECT-HEADER DETAILS SLIDE"))
        self.assertLess(self.html.index('id="sf-side-toggle"'), self.html.index('id="sf-oh-toggle"'))

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_app_js_parses(self):
        r = subprocess.run([shutil.which("node"), "--check", os.path.join(ROOT, "ui", "app.js")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)




class TestEncryption(unittest.TestCase):
    """Task C: ENCRYPT / DECRYPT — AES-256-GCM container encryption.

    Static guarantees (what is encrypted, what stays as framing, the exact UI
    contract) plus functional round-trips run against the real modules.
    """

    @classmethod
    def setUpClass(cls):
        from superfile import crypto
        cls.crypto = crypto
        with open(os.path.join(ROOT, "ui", "index.html"), encoding="utf-8") as fh:
            cls.html = fh.read()
        with open(os.path.join(ROOT, "ui", "app.js"), encoding="utf-8") as fh:
            cls.js = fh.read()
        with open(os.path.join(ROOT, "ui", "app.css"), encoding="utf-8") as fh:
            cls.css = fh.read()
        with open(os.path.join(ROOT, "superfile", "crypto.py"), encoding="utf-8") as fh:
            cls.crypto_src = fh.read()
        with open(os.path.join(ROOT, "superfile", "server.py"), encoding="utf-8") as fh:
            cls.server_src = fh.read()

    # ---------------------------------------------------------------- crypto
    def test_uses_real_aes_gcm_not_handrolled(self):
        self.assertIn("from cryptography.hazmat.primitives.ciphers.aead import AESGCM", self.crypto_src)
        self.assertIn("AESGCM(key)", self.crypto_src)
        self.assertEqual(self.crypto.KEY_BYTES, 32)                 # AES-256
        self.assertEqual(self.crypto.NONCE_BYTES, 12)               # 96-bit GCM nonce
        self.assertEqual(self.crypto.GCM_TAG_BYTES, 16)             # 128-bit tag
        self.assertGreaterEqual(self.crypto.PBKDF2_ITERATIONS, 600_000)
        self.assertGreaterEqual(self.crypto.SALT_BYTES, 16)
        self.assertIn('hashlib.pbkdf2_hmac("sha256"', self.crypto_src.replace("'", '"'))

    def test_every_payload_chunk_is_encrypted(self):
        tags = set(self.crypto.PAYLOAD_TAGS)
        for name in ("OBYT", "CONT", "BLOB"):                       # original bytes + decoded text/frames
            tag = {"OBYT": protocol.CHUNK_OBYT, "CONT": protocol.CHUNK_CONT,
                   "BLOB": protocol.CHUNK_BLOB}[name]
            self.assertIn(tag, tags, name)
        # framing that is ALLOWED to stay plaintext
        for t in (protocol.CHUNK_ENCR, protocol.CHUNK_CKSM, protocol.MAGIC):
            self.assertNotIn(t, tags)

    def test_encr_register_and_normal_read_guard(self):
        self.assertEqual(protocol.CHUNK_ENCR, b"ENCR")
        self.assertIn(protocol.CHUNK_ENCR, protocol._KNOWN_CHUNKS)
        self.assertIn("DECRYPT tab", protocol.ENCRYPTED_CONTAINER_MESSAGE)

    def test_roundtrip_and_plaintext_absence_on_real_objects(self):
        c = self.crypto
        marker = "PLAINTEXT-MARKER-9f21c0"
        cases = []
        txt = ("%s\n" % marker + "the quick brown fox jumps over the lazy dog\n" * 6).encode()
        cases.append(("notes.txt", txt))
        png = base64.b64decode(                                  # small real PNG with an IDAT blob
            b"iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIBAMAAADQhd6fAAAAElBMVEX/AAAA/wAAAP//AAAA"
            b"//8AAAD//wAAAP9cQ0m4AAAAFUlEQVR4nGP4z8Dwn4GBgYGBgYGBAQAeXQL/"
            b"gD8y5QAAAABJRU5ErkJggg==")
        cases.append(("pixel.png", png))
        for name, data in cases:
            with self.subTest(name=name):
                obj = pipeline.import_bytes(name, data)
                plain = protocol.dumps(obj)
                enc = c.encrypt_container(plain, c.MODE_PASSWORD, "s3cret-pass")
                self.assertNotEqual(enc, plain)
                self.assertTrue(c.is_encrypted(enc))
                # what the user actually cares about: no readable payload in the file
                self.assertNotIn(b"PLAINTEXT-MARKER", enc)
                self.assertNotIn(name.encode(), enc)
                self.assertNotIn(b"quick brown fox", enc)
                if obj.content.get("text"):
                    self.assertNotIn(obj.content["text"][:24].encode(), enc)
                for blob in obj.blobs.values():
                    if blob and len(blob) > 8:
                        self.assertNotIn(blob[:8], enc)              # decoded frames/binary untouched
                self.assertIn(protocol.MAGIC, enc)                   # framing stays legible
                self.assertIn(protocol.CHUNK_ENCR, enc)
                header = c.encr_header(enc)
                self.assertEqual(header["mode"], "password")
                self.assertEqual(header["kdf"], "pbkdf2-sha256")
                self.assertEqual(header["kdf_params"]["iterations"], c.PBKDF2_ITERATIONS)
                self.assertEqual(len(base64.b64decode(header["salt"])), c.SALT_BYTES)
                self.assertEqual(len(base64.b64decode(header["nonce"])), c.NONCE_BYTES)
                back = c.decrypt_container(enc, c.MODE_PASSWORD, "s3cret-pass")
                self.assertEqual(back, plain)                        # byte-exact
                obj2 = protocol.loads(back)
                self.assertEqual(obj2.content, obj.content)
                self.assertEqual(obj2.original_bytes, obj.original_bytes)

    def test_wrong_password_and_tamper_fail_loudly(self):
        c = self.crypto
        obj = pipeline.import_bytes("note.txt", b"body text %d" % 42)
        plain = protocol.dumps(obj)
        enc = c.encrypt_container(plain, c.MODE_PASSWORD, "right-password")
        with self.assertRaises(c.EncryptionError) as ctx:
            c.decrypt_container(enc, c.MODE_PASSWORD, "wrong-password")
        self.assertIn("wrong password", str(ctx.exception))
        def salt_edit(b):
            """flip one bit inside the base64 salt (changing the derived key)"""
            k = b.index(b'"salt": "') + 10
            return b[:k] + bytes([b[k] ^ 0x01]) + b[k + 1:]

        mutations = (
            ("flip a payload byte", lambda b: b[:len(b) // 2] + bytes([b[len(b) // 2] ^ 1]) + b[len(b) // 2 + 1:]),
            ("truncate", lambda b: b[:-8]),
            ("edit the ENCR salt", salt_edit),
            ("edit the ENCR nonce", lambda b: b.replace(b'"nonce": "', b'"nonce": "Z', 1)),
)
        for label, mutate in mutations:
            with self.subTest(label=label):
                with self.assertRaises(c.EncryptionError):
                    c.decrypt_container(mutate(enc), c.MODE_PASSWORD, "right-password")

    def test_chunks_cannot_be_moved_between_files(self):
        """AAD binds tag + position, and the key is per-file: ciphertext is not transferable.

        The checksum is RE-COMPUTED after the splice, so the container is structurally valid and
        the only thing that can reject it is AES-256-GCM authentication itself.
        """
        c = self.crypto
        body = b"A" * 512
        plain_a = protocol.dumps(pipeline.import_bytes("one.txt", body))
        plain_b = protocol.dumps(pipeline.import_bytes("two.txt", body))
        a = c.encrypt_container(plain_a, c.MODE_PASSWORD, "same-password")
        b = c.encrypt_container(plain_b, c.MODE_PASSWORD, "same-password")

        def chunk(data, tag):
            for t, start, end, payload in self._chunks(data):
                if t == tag:
                    return start, end, payload
            raise AssertionError("chunk %r missing" % tag)

        i_b, end_b, ct_b = chunk(b, b"OBYT")
        _i_a, _end_a, ct_a = chunk(a, b"OBYT")
        # identical plaintext -> identical compressed payload size, different ciphertext
        self.assertEqual(len(ct_a), len(ct_b))
        self.assertNotEqual(ct_a, ct_b)
        spliced = b[:i_b] + ct_a + b[end_b:]
        recomputed = self._rechecksum(spliced)
        self.assertNotEqual(recomputed, spliced)
        self.assertEqual(protocol.CHUNK_CKSM in recomputed, True)
        # the container is now checksum-valid, so only GCM authentication can reject it
        with self.assertRaises(c.EncryptionError) as ctx:
            c.decrypt_container(recomputed, c.MODE_PASSWORD, "same-password")
        self.assertIn("authenticate", str(ctx.exception))
        # ... and the untouched files still decrypt (the splice is what broke it)
        self.assertEqual(c.decrypt_container(a, c.MODE_PASSWORD, "same-password"), plain_a)
        self.assertEqual(c.decrypt_container(b, c.MODE_PASSWORD, "same-password"), plain_b)

    @staticmethod
    def _chunks(data):
        """Walk the real chunk table (searching for a tag name would match the ENCR JSON)."""
        off = struct.unpack(">I", data[12:16])[0]           # header_size
        while off + 12 <= len(data):
            tag = data[off:off + 4]
            n = struct.unpack(">Q", data[off + 4:off + 12])[0]
            yield tag, off + 12, off + 12 + n, data[off + 12:off + 12 + n]
            off = off + 12 + n

    @staticmethod
    def _rechecksum(container: bytes) -> bytes:
        """Rebuild the CKSM chunk so the container is internally consistent again."""
        i = container.rindex(protocol.CHUNK_CKSM)
        head = container[:i]
        return head + protocol.CHUNK_CKSM + struct.pack(">Q", 32) + hashlib.sha256(head).digest()

    def test_nonce_and_salt_are_fresh_per_file(self):
        c = self.crypto
        plain = protocol.dumps(pipeline.import_bytes("n.txt", b"same bytes every time"))
        seen = set()
        for _ in range(8):
            enc = c.encrypt_container(plain, c.MODE_PASSWORD, "pw")
            h = c.encr_header(enc)
            seen.add((h["salt"], h["nonce"]))
        self.assertEqual(len(seen), 8)                               # random salt + nonce per file
        base = base64.b64decode(c.encr_header(next(iter(
            [c.encrypt_container(plain, c.MODE_PASSWORD, "pw")])))["nonce"])
        nonces = {c._nonce_for(base, i) for i in range(64)}
        self.assertEqual(len(nonces), 64)
        self.assertTrue(all(len(n) == 12 for n in nonces))
        self.assertEqual(len({c._aad(b"CONT", i) for i in range(16)}), 16)

    def test_in_memory_object_is_untouched_by_encryption(self):
        obj = pipeline.import_bytes("keep.txt", b"unchanged")
        before = protocol.dumps(obj)
        data, filename = pipeline.encrypt_object(obj, "password", "pw-secret")
        self.assertEqual(protocol.dumps(obj), before)                 # no side effects on the loaded object
        self.assertTrue(filename.endswith(".sfp"))
        self.assertIn("encrypted", filename)
        self.assertTrue(self.crypto.is_encrypted(data))

    def test_already_encrypted_and_bad_inputs(self):
        c = self.crypto
        plain = protocol.dumps(pipeline.import_bytes("x.txt", b"x"))
        enc = c.encrypt_container(plain, c.MODE_PASSWORD, "pw")
        with self.assertRaises(c.EncryptionError):                    # double encryption refused
            c.encrypt_container(enc, c.MODE_PASSWORD, "pw")
        with self.assertRaises(c.EncryptionError):                    # empty password refused
            c.encrypt_container(plain, c.MODE_PASSWORD, "")
        with self.assertRaises(c.EncryptionError):
            c.encrypt_container(plain, "nonsense-mode", "pw")
        with self.assertRaises(c.EncryptionError):
            c.decrypt_container(plain, c.MODE_PASSWORD, "pw")         # not encrypted at all
        with self.assertRaises(c.EncryptionError):
            c.decrypt_container(b"not a container", c.MODE_PASSWORD, "pw")
        with self.assertRaises(c.EncryptionError):
            c.encr_header(plain)

    def test_password_kdf_options(self):
        """PBKDF2-HMAC-SHA256 is the default; Argon2id is available when argon2-cffi is installed."""
        c = self.crypto
        self.assertEqual(c.KDF_PBKDF2, "pbkdf2-sha256")
        self.assertIn(c.KDF_PBKDF2, c.available_kdfs())
        self.assertEqual(c.KDF_PBKDF2, c.derive_password_key.__defaults__[0])
        plain = protocol.dumps(pipeline.import_bytes("k.txt", b"kdf test body"))
        enc = c.encrypt_container(plain, c.MODE_PASSWORD, "pw-kdf")          # default
        self.assertEqual(c.encr_header(enc)["kdf"], "pbkdf2-sha256")
        self.assertEqual(c.decrypt_container(enc, c.MODE_PASSWORD, "pw-kdf"), plain)
        with self.assertRaises(c.EncryptionError):                            # unknown KDF refused
            c.encrypt_container(plain, c.MODE_PASSWORD, "pw-kdf", "rot13")
        if c.HAVE_ARGON2:
            self.assertIn("argon2id", c.available_kdfs())
            a = c.encrypt_container(plain, c.MODE_PASSWORD, "pw-kdf", c.KDF_ARGON2ID)
            h = c.encr_header(a)
            self.assertEqual(h["kdf"], "argon2id")
            self.assertEqual(h["kdf_params"]["memory_cost"], c.ARGON2_PARAMS["memory_cost"])
            self.assertGreaterEqual(h["kdf_params"]["memory_cost"] * 1024, 19 * 1024 * 1024)  # >= 19 MiB
            self.assertEqual(c.decrypt_container(a, c.MODE_PASSWORD, "pw-kdf"), plain)
            self.assertNotEqual(c.derive_password_key("pw-kdf", b"0" * 16, "pbkdf2-sha256"),
                                c.derive_password_key("pw-kdf", b"0" * 16, "argon2id"))
            a2 = c.encrypt_container(plain, c.MODE_PASSWORD, "pw-kdf", c.KDF_ARGON2ID)
            self.assertNotEqual(c.encr_header(a)["salt"], c.encr_header(a2)["salt"])
        else:
            self.assertIn("argon2-cffi", str(self.assertRaises(c.EncryptionError, lambda: None)))

    def test_ui_never_asks_for_a_non_default_kdf(self):
        """The specified UI flow must use the default (PBKDF2) — no kdf selector was added."""
        block = self.js[self.js.index("function renderEncrypt(pane)"):self.js.index("function renderDecrypt(pane)")]
        self.assertNotIn("kdf", block.lower())

    def test_key_derivation_separates_passwords_salts_and_devices(self):
        c = self.crypto
        salt = b"0123456789abcdef"
        k1 = c.derive_password_key("password-one", salt)
        k2 = c.derive_password_key("password-two", salt)
        k3 = c.derive_password_key("password-one", b"fedcba9876543210")
        self.assertEqual(len(k1), 32)
        self.assertEqual(len({k1, k2, k3}), 3)
        master = b"M" * 32
        self.assertEqual(c.derive_device_key(master, salt), c.derive_device_key(master, salt))
        self.assertNotEqual(c.derive_device_key(master, salt), c.derive_device_key(master, b"x" * 16))
        self.assertNotEqual(c.derive_device_key(master, salt), k1)

    # ------------------------------------------------------- device mode
    def test_device_mode_is_greyed_out_off_windows(self):
        c = self.crypto
        if sys.platform.startswith("win"):
            self.skipTest("running on Windows: device lock is expected to be available")
        self.assertFalse(c.device_lock_supported())
        with self.assertRaises(c.DeviceLockUnavailable) as ctx:
            c.get_or_create_device_key()
        self.assertIn("Windows-only", str(ctx.exception))
        plain = protocol.dumps(pipeline.import_bytes("d.txt", b"d"))
        with self.assertRaises(c.DeviceLockUnavailable) as ctx:
            c.encrypt_container(plain, c.MODE_DEVICE)                 # cannot lock a new file to this device
        self.assertIn("Windows-only", str(ctx.exception))
        with self.assertRaises(c.EncryptionError) as ctx:             # a plain file is not encrypted at all
            c.decrypt_container(plain, c.MODE_DEVICE)
        self.assertIn("no ENCR chunk", str(ctx.exception))
        # a device-locked file that arrives on Linux must say why it cannot be opened
        tmp = __import__("tempfile").mkdtemp(prefix="sf_devfile_")
        old_env = os.environ.get("SUPERFILE_DEVICE_DIR")
        os.environ["SUPERFILE_DEVICE_DIR"] = tmp
        real_supported, real_dpapi = c.device_lock_supported, c._dpapi
        try:
            c.device_lock_supported = lambda: True
            c._dpapi = lambda protect, data: (b"WRAP:" + data) if protect else data[5:]
            locked = c.encrypt_container(plain, c.MODE_DEVICE)
        finally:
            c.device_lock_supported, c._dpapi = real_supported, real_dpapi
            if old_env is None:
                os.environ.pop("SUPERFILE_DEVICE_DIR", None)
            else:
                os.environ["SUPERFILE_DEVICE_DIR"] = old_env
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(c.encr_header(locked)["mode"], "device")
        with self.assertRaises(c.DeviceLockUnavailable) as ctx:
            c.decrypt_container(locked, c.MODE_DEVICE)
        self.assertIn("Windows-only", str(ctx.exception))
        self.assertIn("needs its password", str(ctx.exception))

    def test_device_keyring_paths_and_mismatch_message(self):
        """The device-mode logic (keyring, HKDF, device_ref binding) with DPAPI stubbed out."""
        c = self.crypto
        tmp = __import__("tempfile").mkdtemp(prefix="sf_keyring_")
        old_env = os.environ.get("SUPERFILE_DEVICE_DIR")
        os.environ["SUPERFILE_DEVICE_DIR"] = tmp
        real_supported, real_dpapi = c.device_lock_supported, c._dpapi
        try:
            self.assertTrue(c.device_key_path().startswith(tmp))
            c.device_lock_supported = lambda: True
            c._dpapi = lambda protect, data: (b"WRAP:" + data) if protect else data[5:]
            ref1, master1 = c.get_or_create_device_key()
            self.assertEqual(len(master1), 32)
            self.assertTrue(os.path.exists(c.device_key_path()))
            ref2, master2 = c.get_or_create_device_key()          # idempotent: same device, same key
            self.assertEqual((ref1, master1), (ref2, master2))
            self.assertEqual(c.device_key_for(ref1), master1)
            with self.assertRaises(c.EncryptionError) as ctx:
                c.device_key_for("00000000-0000-4000-8000-000000000000")   # the other laptop
            self.assertEqual(str(ctx.exception),
                             "This file was locked to a different device, or needs a password.")
            # full device-mode round-trip with the DPAPI stub in place
            plain = protocol.dumps(pipeline.import_bytes("dev.txt", b"device locked body"))
            enc = c.encrypt_container(plain, c.MODE_DEVICE)
            h = c.encr_header(enc)
            self.assertEqual(h["mode"], "device")
            self.assertEqual(h["device_ref"], ref1)
            self.assertEqual(h["kdf"], "hkdf-sha256")
            self.assertEqual(c.decrypt_container(enc, c.MODE_DEVICE), plain)
            # a file locked to another device must NOT decrypt here
            h2 = c.encr_header(enc)
            ring = c.load_keyring()
            ring["device"]["device_ref"] = "11111111-1111-4111-8111-111111111111"
            c.save_keyring(ring)
            with self.assertRaises(c.EncryptionError) as ctx:
                c.decrypt_container(enc, c.MODE_DEVICE)
            self.assertEqual(str(ctx.exception),
                             "This file was locked to a different device, or needs a password.")
            self.assertEqual(h2["device_ref"], ref1)
        finally:
            c.device_lock_supported, c._dpapi = real_supported, real_dpapi
            if old_env is None:
                os.environ.pop("SUPERFILE_DEVICE_DIR", None)
            else:
                os.environ["SUPERFILE_DEVICE_DIR"] = old_env
            shutil.rmtree(tmp, ignore_errors=True)

    # ------------------------------------------------------------- server
    def test_server_endpoints_exist_and_never_return_bare_500(self):
        self.assertIn('if path == "/api/decrypt":', self.server_src)
        self.assertIn('if action == "encrypt":', self.server_src)
        self.assertIn('"device_lock": crypto.device_lock_supported()', self.server_src)
        self.assertIn("except crypto.EncryptionError as exc:\n                return self._error(str(exc), 400)",
                      self.server_src)                                # encrypt errors -> {ok:false,error}
        for src in (self.server_src,):
            i = src.index("def _api_decrypt")
            block = src[i:i + 2600]
        self.assertIn('return self._error("expected multipart/form-data', block)
        self.assertIn("except Exception as exc:", block)              # last-resort catch-all, still a clean error
        self.assertIn('return self._error(f"could not decrypt', block)
        self.assertIn("pipeline.STORE.put(obj)", block)               # the existing open flow can load the result

    def test_multipart_parser(self):
        from superfile.server import _parse_multipart
        boundary = b"----sfTEST"
        body = (b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"mode\"\r\n\r\n"
                b"password\r\n--" + boundary + b"\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n"
                b"p@ss word\r\n--" + boundary + b'\r\nContent-Disposition: form-data; name="file"; filename="my file.sfp"\r\n'
                b"Content-Type: application/x-superfile\r\n\r\nBINARY\x00BYTES\r\n--" + boundary + b"--\r\n")
        fields, files = _parse_multipart(body, boundary)
        self.assertEqual(fields, {"mode": "password", "password": "p@ss word"})
        self.assertEqual(files["file"][0], "my file.sfp")
        self.assertEqual(files["file"][1], b"BINARY\x00BYTES")
        fields, files = _parse_multipart(b"--" + boundary + b"--\r\n", boundary)   # empty body
        self.assertEqual((fields, files), ({}, {}))

    def test_pipeline_decrypt_helper_returns_named_output(self):
        data, filename = pipeline.encrypt_object(
            pipeline.import_bytes("report.csv", b"a,b\n1,2\n"), "password", "pw-for-pipeline")
        obj, plain, out_name = pipeline.decrypt_container_bytes(data, "password", "pw-for-pipeline")
        self.assertEqual(out_name, "report-decrypted.sfp")
        self.assertEqual(obj.original_filename, "report.csv")
        self.assertEqual(protocol.loads(plain).original_bytes, b"a,b\n1,2\n")
        with self.assertRaises(self.crypto.EncryptionError):
            pipeline.decrypt_container_bytes(data, "password", "nope")

    # ------------------------------------------------------------------ UI
    def test_new_controls_are_additive_and_in_place(self):
        h = self.html
        for ident in ("btn-encrypt", "btn-decrypt"):
            self.assertEqual(h.count('id="%s"' % ident), 1)
            tag = re.search(r'<button id="%s"[^>]*>' % ident, h).group(0)
            self.assertIn('class="tool"', tag)
        # both come AFTER #btn-transform, so every existing toolbar button keeps its position
        self.assertLess(h.index('id="btn-transform"'), h.index('id="btn-encrypt"'))
        self.assertLess(h.index('id="btn-encrypt"'), h.index('id="btn-decrypt"'))
        self.assertLess(h.index('id="btn-decrypt"'), h.index('id="file-input"'))
        self.assertEqual(h.count('id="tab-encrypt"'), 1)
        self.assertEqual(h.count('id="tab-decrypt"'), 1)
        self.assertEqual(re.findall(r'<button data-tab="(encrypt|decrypt)" class="tab">', h),
                         ["encrypt", "decrypt"])
        # panes live inside #tab-body, right after #tab-about
        body = h[h.index('id="tab-body"'):]
        self.assertIn('id="tab-encrypt" class="tab-pane"', body)
        self.assertIn('id="tab-decrypt" class="tab-pane"', body)
        self.assertLess(body.index('id="tab-about"'), body.index('id="tab-encrypt"'))
        self.assertLess(body.index('id="tab-encrypt"'), body.index('id="tab-decrypt"'))

    def test_js_wiring_follows_the_existing_patterns(self):
        js = self.js
        self.assertIn('$("#btn-encrypt").onclick = () => switchTab("encrypt");', js)
        self.assertIn('$("#btn-decrypt").onclick = () => switchTab("decrypt");', js)
        self.assertIn("encrypt: renderEncrypt, decrypt: renderDecrypt,", js)
        self.assertIn("function renderEncrypt(pane)", js)
        self.assertIn("function renderDecrypt(pane)", js)

    def test_encrypt_tab_contract(self):
        js = self.js
        i = js.index("function renderEncrypt(pane)")
        block = js[i:js.index("function renderDecrypt(pane)")]
        self.assertIn('if (!d) { pane.innerHTML = `<p class="muted">open an object first</p>`; return; }', block)
        self.assertIn("PASSWORD PROTECT THIS FILE?", block)
        self.assertIn("No password — this file will only open on this computer.", block)
        self.assertIn("There is no password recovery.", block)
        self.assertIn("this file cannot be", block)                    # ...decrypted by anyone, including you
        self.assertIn('id="enc-ack"', block)                           # required acknowledgement
        # ... and it must stay usable in device mode: it cannot live inside the password-only block
        self.assertNotIn('id="enc-ack"', block[block.index('id="enc-pwblock"'):block.index('id="enc-warn"')])
        self.assertLess(block.index('id="enc-pwblock"'), block.index('id="enc-warn"'))
        self.assertLess(block.index('id="enc-warn"'), block.index('id="enc-devblock"'))
        self.assertIn("go.disabled = !ready;", block)                  # GO disabled until valid
        self.assertIn("do not match", block)                           # inline mismatch error
        self.assertIn('mode: "password"|device' if False else 'isPw() ? "password" : "device"', block)
        self.assertIn("/encrypt`, {", block)
        self.assertIn("ENCRYPT &amp; SAVE .SFP", block)
        self.assertIn("Encrypted and saved as", block)                 # success text
        self.assertIn("encryption failed: ", block)                    # real failure text
        self.assertIn("status(", block)                                # uses the existing status() helper
        self.assertNotRegex(block, r"https?://")                       # offline-first: no external calls

    def test_decrypt_tab_contract(self):
        js = self.js
        block = js[js.index("function renderDecrypt(pane)"):]
        self.assertIn('<input type="file" id="dec-file" accept=".sfp,application/x-superfile">', block)
        self.assertIn("ENTER A PASSWORD?", block)
        self.assertIn('api("/api/decrypt", { method: "POST", body: fd })', block)
        self.assertIn("new FormData()", block)
        self.assertIn("OPEN THIS FILE", block)
        # a failed attempt must not leave a previous attempt's success block on screen
        self.assertLess(block.index('result.innerHTML = ""'), block.index("await api("))
        self.assertIn("loadObject(r.object_id)", block)                # reuses the existing open/import flow
        self.assertNotIn("innerHTML = `\n        <div id=\"tab-view\"", block)   # no second viewer
        self.assertIn("e.message", block)                              # shows the real reported error
        self.assertIn('"decrypt failed: "', block)
        self.assertNotRegex(block, r"https?://")
        self.assertNotIn("state.current", block)                       # works with no loaded object

    def test_device_lock_ui_is_greyed_out_not_faked(self):
        js = self.js
        self.assertIn("function encDeviceLock()", js)
        self.assertIn("state.registry && state.registry.device_lock", js)
        self.assertIn("device-lock mode is Windows-only in this build", js)
        self.assertEqual(js.count("${lockable ? \"\" : \"disabled\"}"), 2)   # both radios gated
        self.assertNotIn("device_lock: true", js)

    def test_new_css_never_touches_existing_rules(self):
        with open(os.path.join(ROOT, "ui", "app.css"), encoding="utf-8") as fh:
            css = fh.read()
        i = css.index("ENCRYPT / DECRYPT tabs")
        added = css[i:]
        self.assertIn(".enc-warn", added)
        self.assertIn("button.act[disabled]", added)
        for cls in ("sf-oh-collapsed", "sf-top-collapsed", "sf-side-collapsed"):
            self.assertNotIn(cls, added)                              # no collision with the toggles
        before = csv_classes = set(re.findall(r"\n(\.[a-z][a-z0-9-]*)", css[:i]))
        after = set(re.findall(r"\n(\.[a-z][a-z0-9-]*)", added))
        self.assertFalse(after & before, "new classes must not redefine existing ones: %s" % (after & before))


def main():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    print()
    print("=" * 62)
    print(f"  SUPERFILE SELF-TEST: {result.testsRun} tests run")
    print(f"  failures: {len(result.failures)}   errors: {len(result.errors)}")
    if result.wasSuccessful():
        print("  RESULT: PASS")
    else:
        print("  RESULT: FAIL")
    print("=" * 62)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())

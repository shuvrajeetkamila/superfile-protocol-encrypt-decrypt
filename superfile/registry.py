"""
SUPERFILE — Format registry & adapter loader
============================================

The registry is the single place that maps format ids to adapters.  The
protocol and UI never hard-code formats: they ask the registry.  Adding a new
format = adding a new adapter (see examples/new_format_adapter/).
"""

from __future__ import annotations

import importlib
import os
import sys

from .adapters.base import FormatAdapter, FormatSpec
from .object_model import SupportLevel
from .security import UnsafeInputError


class FormatRegistry:
    def __init__(self):
        self.adapters: list = []
        self.by_format: dict = {}       # format_id -> adapter
        self.specs: dict = {}           # format_id -> FormatSpec

    # ------------------------------------------------------------------
    def register(self, adapter: FormatAdapter) -> None:
        if not isinstance(adapter, FormatAdapter):
            raise TypeError("adapter must subclass FormatAdapter")
        self.adapters.append(adapter)
        for fid, spec in adapter.formats.items():
            # first registration wins for a format id (core adapters load first)
            if fid not in self.by_format:
                self.by_format[fid] = adapter
                self.specs[fid] = spec

    def adapter_for(self, fmt: str) -> FormatAdapter | None:
        return self.by_format.get(fmt)

    def adapter_by_any(self, *ids) -> FormatAdapter | None:
        """Lookup by format id first, then by adapter name (create dispatch)."""
        for i in ids:
            ad = self.by_format.get(i)
            if ad is not None:
                return ad
        for i in ids:
            for ad in self.adapters:
                if ad.name == i:
                    return ad
        return None

    def spec(self, fmt: str) -> FormatSpec | None:
        return self.specs.get(fmt)

    # ------------------------------------------------------------------
    def detect(self, data: bytes, filename: str = ""):
        """Ask every adapter to confirm the detection (raises confidence)."""
        best = None
        for ad in self.adapters:
            try:
                conf = ad.detect(data, filename)
            except Exception:
                conf = 0.0
            if conf and (best is None or conf > best[0]):
                best = (conf, ad)
        return best

    # ------------------------------------------------------------------
    def format_database(self) -> list:
        """Rows for the FORMAT SUPPORT DATABASE table."""
        rows = [spec.registry_row() for spec in self.specs.values()]
        rows.sort(key=lambda r: (r["category"], r["format"]))
        return rows

    def manifests(self) -> list:
        return [a.manifest() for a in self.adapters]

    def conversion_matrix(self) -> dict:
        """format_id -> list of export options (only real conversions)."""
        out = {}
        for fid, ad in self.by_format.items():
            try:
                opts = ad.export_formats(_DummyObj(fid))
                out[fid] = [o.to_dict() if hasattr(o, "to_dict") else dict(o) for o in opts]
            except Exception as exc:  # adapters must not break the matrix view
                out[fid] = []
                out.setdefault("_errors", {})[fid] = str(exc)
        return out


class _DummyObj:
    """Stand-in used to query generic export options per format id."""

    def __init__(self, fmt):
        self.detected_format = fmt
        self.object_type = None
        self.content = {}
        self.original_filename = f"probe.{fmt}"
        self.original_extension = fmt


# ---------------------------------------------------------------------------
# adapter loading
# ---------------------------------------------------------------------------

CORE_ADAPTERS = [
    "superfile.adapters.text",          # TXT MD CSV RTF HTML XML
    "superfile.adapters.structured",    # JSON YAML TOML BSON
    "superfile.adapters.image",         # PNG BMP GIF JPEG WebP TIFF SVG
    "superfile.adapters.audio",         # WAV MP3 FLAC OGG AAC
    "superfile.adapters.video",         # MP4 MKV WebM AVI MOV + GIF anim tools
    "superfile.adapters.three_d",       # OBJ STL GLTF GLB
    "superfile.adapters.archive",       # ZIP TAR GZIP 7Z
    "superfile.adapters.executable",    # PE DLL ELF WASM
    "superfile.adapters.source",        # C C++ Python JS Java Rust Go C# CSS
    "superfile.adapters.database",      # SQLite BLOB
    "superfile.adapters.pdf",           # PDF
    "superfile.adapters.document",      # DOCX EPUB
    "superfile.adapters.sfp_adapter",   # SUPERFILE container
]


def load_core_adapters(registry: FormatRegistry) -> FormatRegistry:
    for modname in CORE_ADAPTERS:
        try:
            mod = importlib.import_module(modname)
        except Exception as exc:
            print(f"[superfile] WARNING: could not load {modname}: {exc}", file=sys.stderr)
            continue
        for ad in getattr(mod, "ADAPTERS", []):
            registry.register(ad)
    return registry


def load_plugin_adapters(registry: FormatRegistry, plugin_dir: str) -> list:
    """
    Plugin system: any ``*_adapter.py`` in plugin_dir exposing either
    ``ADAPTERS = [FormatAdapter(), ...]`` or ``register(registry)`` is loaded.
    Returns names of loaded plugins.
    """
    loaded = []
    if not os.path.isdir(plugin_dir):
        return loaded
    for fname in sorted(os.listdir(plugin_dir)):
        if not fname.endswith("_adapter.py") and not fname.endswith(".py"):
            continue
        if fname.startswith("_"):
            continue
        path = os.path.join(plugin_dir, fname)
        modname = f"superfile_plugin_{fname[:-3]}"
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(modname, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # plugin code is trusted (admin-installed)
            if hasattr(mod, "register"):
                mod.register(registry)
            else:
                for ad in getattr(mod, "ADAPTERS", []):
                    registry.register(ad)
            loaded.append(fname)
        except Exception as exc:
            print(f"[superfile] WARNING: plugin {fname} failed: {exc}", file=sys.stderr)
    return loaded


def build_registry(plugin_dir: str | None = None) -> FormatRegistry:
    reg = FormatRegistry()
    load_core_adapters(reg)
    if plugin_dir:
        load_plugin_adapters(reg, plugin_dir)
    return reg

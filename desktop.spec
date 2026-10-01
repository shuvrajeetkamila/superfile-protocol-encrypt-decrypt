# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for SUPERFILE — ONE single-file desktop executable that
handles every supported format family (no per-file-type apps).

Cross-platform: run `pyinstaller desktop.spec` on Windows, Linux or macOS.
Outputs: dist/Superfile.exe (Windows) / dist/Superfile (Linux, macOS).

Packaging-trap notes (see docs/PACKAGING.md):
  * superfile/registry.py loads superfile.adapters.* via
    importlib.import_module() in a LOOP — PyInstaller cannot see that
    statically. collect_submodules('superfile') + explicit hiddenimports
    keep every adapter in the bundle (verified by `Superfile --self-test`).
  * ui/ static assets are bundled via datas=[("ui", "ui")]  — spec-file
    tuples, so there is no OS-dependent ';'-vs-':' separator to get wrong.
  * Heavy unrelated packages (numpy, matplotlib, ...) are excluded (§5).
  * UPX is deliberately NOT used (§5): binaries stay AV-friendly and
    debuggable; size is far below the 120 MB budget without it.
"""
import sys
from PyInstaller.utils.hooks import collect_submodules

# every submodule of the app package (belt: covers all adapters/codecs)
hiddenimports = collect_submodules("superfile")

# braces: explicitly re-list the dynamic-import modules and Pillow pieces
hiddenimports += [
    "superfile",
    "superfile.object_model", "superfile.security", "superfile.detection",
    "superfile.protocol", "superfile.registry", "superfile.transforms",
    "superfile.pipeline", "superfile.demo", "superfile.server",
    "superfile.adapters", "superfile.adapters.base",
    "superfile.adapters.text", "superfile.adapters.structured",
    "superfile.adapters.image", "superfile.adapters.audio",
    "superfile.adapters.video", "superfile.adapters.three_d",
    "superfile.adapters.archive", "superfile.adapters.executable",
    "superfile.adapters.source", "superfile.adapters.database",
    "superfile.adapters.pdf", "superfile.adapters.document",
    "superfile.adapters.sfp_adapter",
    "superfile.codecs", "superfile.codecs.png", "superfile.codecs.bmp",
    "superfile.codecs.gif", "superfile.codecs.imageops",
    # Pillow (optional at runtime; bundled for JPEG/WebP/TIFF decode+encode)
    "PIL", "PIL.Image", "PIL.ImageFile", "PIL.ImageOps", "PIL.ImageDraw",
    "PIL.ImageChops", "PIL.ImageMath", "PIL.ImagePalette",
    "PIL.JpegImagePlugin", "PIL.PngImagePlugin", "PIL.GifImagePlugin",
    "PIL.BmpImagePlugin", "PIL.WebPImagePlugin", "PIL.TiffImagePlugin",
    "PIL.MpoImagePlugin", "PIL.PpmImagePlugin", "PIL.XbmImagePlugin",
]
hiddenimports = sorted(set(hiddenimports))

excludes = [
    # §5: nothing heavy or unrelated may ride along
    "numpy", "matplotlib", "scipy", "pandas", "sympy", "statsmodels",
    "IPython", "jedi", "zmq", "tornado", "pytest", "setuptools", "pip",
    "torch", "tensorflow", "sklearn", "cv2",
    "tkinter", "PyQt5", "PyQt6", "PySide2", "PySide6", "wx",
    "PIL.ImageQt", "PIL.ImageTk", "PIL.ImageWin", "PIL.ImageGrab",
    "test", "lib2to3", "xmlrpc",
]

a = Analysis(
    ["desktop_launcher.py"],
    pathex=["."],
    binaries=[],
    datas=[("ui", "ui")],          # UI assets served from the bundle (§3)
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Superfile",              # -> Superfile.exe on Windows (§7)
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                     # §5: not used (see module docstring)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,                  # --self-test output + crash keypress (§1)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=["superfile.ico"] if sys.platform == "win32" else None,
    version="windows_version_info.txt" if sys.platform == "win32" else None,
)

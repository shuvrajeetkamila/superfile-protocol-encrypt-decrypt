# EXACT WINDOWS BUILD INSTRUCTIONS — Superfile.exe

Target: Windows 10/11 x64 · one single-file executable · version 1.0.0

## On a real Windows machine (the normal path)

```bat
:: 1. install Python 3.13 x64 from https://www.python.org/downloads/ (check "Add to PATH")

:: 2. get the source (git clone or unpack the project), then:
cd superfile

:: 3. build dependencies (std. libs + Pillow only)
python -m pip install --upgrade pip pyinstaller pillow

:: 4. source test gate (83 tests — must be 0 failures, 0 errors)
python -m tests.test_all

:: 5. build the single-file executable (ONE app, all format families)
python -m PyInstaller --clean --noconfirm desktop.spec
::    -> dist\Superfile.exe

:: 6. MANDATORY 12-point self-test (exit code 0 required)
dist\Superfile.exe --self-test

:: 7. full release battery: format matrix + E2E + security + SFP round-trip
::    + machine-generated verification report
python tests\packaged_e2e.py dist\Superfile.exe --report VERIFICATION_REPORT.txt

:: 7b. OPTIONAL real-browser check of the collapsible panels (pip install playwright; needs Chrome or Edge)
python tests\ui_layout_check.py --spawn-exe dist\Superfile.exe --browser "C:\Program Files\Google\Chrome\Application\chrome.exe"

:: 8. clean release output
mkdir release
copy dist\Superfile.exe release\Superfile.exe
```

Requirements: Python 3.10+ and PyInstaller. Pillow is optional at runtime
(JPEG/WebP/TIFF degrade honestly to INSPECTION ONLY without it) but IS bundled
in the release build.

## On Linux/macOS

The same commands build `dist/Superfile` (ELF / Mach-O). Linux x86-64 build
was verified in this project (see docs/PACKAGING.md).

## What the built exe must pass (do not skip)

1. `Superfile.exe --self-test` → 12/12 PASS, exit 0, zero "could not load"
2. `python tests\packaged_e2e.py dist\Superfile.exe` → OVERALL: ALL CHECKS PASS
3. File type is really PE: `file Superfile.exe` → "PE32+ executable ... x86-64"
   (or use the PE parse inside packaged_e2e's report)
4. Size < 125,829,120 bytes (120 MiB)

## CI

`.github/workflows/build.yml` performs exactly steps 4-7 on `windows-latest`
(plus ubuntu/macos) and attaches the verified `Superfile.exe` to a GitHub
Release when a `v*` tag is pushed. A failed self-test blocks the release.

## Version metadata embedded in the exe

Product Name: SUPERFILE · FileDescription: Universal Digital Object Protocol
ProductVersion/FileVersion: 1.0.0.0 · OriginalFilename: Superfile.exe
Icon: superfile.ico · verified present in the PE resource section.

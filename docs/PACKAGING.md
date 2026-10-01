# PACKAGING — single-file desktop executable

**Product:** ONE app, `Superfile` / `Superfile.exe` — every format family in a
single executable (Universal Digital Object Protocol). No per-file-type tools.

**Version:** 1.0.0 · **Build tool:** PyInstaller 6.22.3 (`--onefile`) ·
**UPX:** deliberately NOT used (AV friendliness + debuggability; size is far
under budget without it).

---

## 0. Honesty about cross-compilation

The local build environment used for this record is **Linux x86_64**
(kernel 6.1.158, glibc 2.41, verified with `uname -a`). PyInstaller cannot
cross-compile: a binary built here is an **ELF**, never a Windows PE. So:

* the **Linux** single-file binary was built AND fully verified here (below);
* the real **Windows `.exe`** and **macOS** binaries are produced by
  `.github/workflows/build.yml` on `windows-latest` / `macos-latest` runners,
  self-tested on those runners, and attached to a GitHub Release on tag push.
  *They are not claimed as verified until that workflow has run on GitHub.*

## Build (any OS)

```bash
python3 -m pip install pyinstaller pillow
python3 -m tests.test_all            # source gate: 83 tests
python3 -m PyInstaller --clean --noconfirm desktop.spec
./dist/Superfile --self-test         # dist\Superfile.exe --self-test on Windows
```

`desktop.spec` is cross-platform: UI assets are attached as spec-file tuples
`datas=[("ui", "ui")]` — no `;`-vs-`:` separator problem to get wrong.

## Entry point (`desktop_launcher.py`, section 1 of the brief)

* detects frozen mode (`getattr(sys, "frozen", False)`);
* persistent per-user data dir, OUTSIDE PyInstaller's wiped `_MEIxxxx`
  extraction dir: `%LOCALAPPDATA%\Superfile` (Windows),
  `~/.local/share/Superfile` (Linux/macOS). Sample data goes to
  `<data>/demo` via the `SUPERFILE_DEMO_DIR` hook;
* free-port scan 8765 → 8790 (observed falling back to 8766 when 8765 was
  busy during testing);
* starts the local server (binds 127.0.0.1) and auto-opens the default
  browser — no terminal interaction for a normal user;
* unhandled exception → traceback printed + “Press Enter to close...” so a
  double-clicked exe does not flash and vanish;
* `--self-test` flag (below). Extra debug flags: `--port`, `--no-browser`,
  `--host`, `--version`.

## Dynamic-adapter-import trap (section 2)

`superfile/registry.py` loads 13 `superfile.adapters.*` modules through
`importlib.import_module()` **in a loop** — invisible to PyInstaller's static
analysis. Fixed with `collect_submodules("superfile")` + explicit
`--hidden-import`-equivalents in `desktop.spec`. Verified at three levels:

1. `build/warn-desktop.txt`: **0** missing-module warnings for `superfile.*`
   or required `PIL.*` (remaining warnings: Windows-only stdlib branches and
   two optional Pillow extras — copy kept at `docs/build-warnings-linux.txt`);
2. byte-level PYZ TOC of the built binary: **all 13 adapters BUNDLED**
   (31 `superfile` + 77 `PIL` modules inside; `numpy`/`matplotlib`/`tkinter`
   module counts = **0**);
3. runtime: `--self-test` step 4 asserts registry counts
   (adapters=28, formats=59, transforms=20) and that the adapter-load log
   contains **zero** `WARNING: could not load` lines.

## Bundled data (section 3)

`ui/index.html`, `ui/app.js`, `ui/app.css` are inside the archive
(`pyi-archive_viewer -l -b` lists them) and served from the bundle — the
self-test fetches `/` and requires real HTML with `SUPERFILE` in the body.

## `--self-test` (section 4 — the release gate)

Headless, browser-free; exits 0/non-zero. Checks: 1) generate 38 sample
files into the persistent demo dir · 2) server on a background thread ·
3) `/api/health` · 4) `/api/registry` counts vs. source (adapter trap) +
zero load warnings · 5) real PNG import with expected `detected_format=png`
(+ JSON import) · 6) UI HTML reachable · 7) PE static inspection, never
executed · 8) 20 MB-zero zip bomb rejected · 9) `../` traversal entry
skipped + "unsafe path" warning. Both the unfrozen launcher and the frozen
binary were run here — 9/9 PASS each, `exit=0` (output in the chat record).

## Size (section 5) — measured, Linux binary

| artifact | bytes | MiB | `file` output |
|---|---|---|---|
| `dist/Superfile` (Linux x86-64, onefile) | **33 919 280** | **32.35** | `ELF 64-bit LSB executable, x86-64 ... stripped` |

Budget 120 MB = 125 829 120 bytes → binary uses ≈ **28 %** of budget. Bundled
by design: stdlib + project + Pillow (JPEG/WebP/TIFF). Excluded and confirmed
absent (PYZ counts = 0): numpy, matplotlib, tkinter, scipy, pandas. No UPX.

### Workspace size accounting (measured, final state)

Counted the way the arena meter counts it: generated/excluded directories (`build/`, `dist/`, `.cache`, `.local`,
`__pycache__`, the wine prefix, pip caches) are not part of the workspace and were deleted before measuring.

| what | bytes | |
|---|---|---|
| source workspace (code + UI + docs + tests + demo + screenshots), without `release/` | **1,745,333** (1704.4 KiB) | |
| `release/` (`Superfile.exe` + 4 reports/logs) | **21,388,113** (20.40 MiB) | the exe alone is 21,345,040 |
| **total persisted workspace** | **23,133,446** (22.06 MiB) | limit 120 MiB = 125,829,120 (97.94 MiB headroom) |

The exe is stored once (in `release/`, the directory that persists); `dist/` is a generated build directory and
was deleted.  Earlier figures in this file were different things: `du` of the whole disk tree including generated
dirs (≈35 MB), and the source-only workspace before `release/` and the UI tests existed (676.6 KiB).

## Safety carry-over (section 6)

* packaged `--self-test` steps 7–9 exercise one exe-inspection
  (warnings: “UNTRUSTED EXECUTABLE — inspected as data, never executed”)
  and two archive guard cases (bomb rejected; traversal entry skipped);
* source suite re-run after packaging work: **83 tests, 0 failures, PASS** (60 pre-existing: 43 core
  + 9 top-bar/sidebar guards + 8 file-details-slide guards; + 23 encryption guards added by Task C);
* full HTTP e2e against the packaged binary showed real JSON
  (PNG `FULL SUPPORT` import, JPEG **decoded 64×64 via bundled Pillow**,
  PE `INSPECTION ONLY`, `.sfp` export magic `\x8bSFP\r\n\x1a\n`).

## Naming & metadata (section 7)

`name="Superfile"` → `Superfile.exe` / `Superfile`. Windows builds carry
`windows_version_info.txt` (FileDescription/ProductName “SUPERFILE —
Universal Digital Object Protocol”, filevers 1.0.0.0) and `superfile.ico`
(16–256 px). Both applied **only** on `win32` builds to avoid cross-platform
fragility.

## Publishing (section 8)

`.github/workflows/build.yml`: `windows-latest` + `ubuntu-latest` +
`macos-latest` in parallel → source tests → build → **magic-byte file-type
check** → `--self-test` gate (fails job on failure AND on any
`WARNING: could not load`) → measured size check → artifact upload. On a
`v*` tag push, `release` attaches every verified binary to a GitHub Release
(`fail_on_unmatched_files: true`).

### Exact git commands to trigger the pipeline end to end

```bash
cd /home/user
git init
git add .
git commit -m "SUPERFILE v1.0.0 — universal digital object protocol + single-file desktop app"
git branch -M main
git remote add origin https://github.com/<your-account>/superfile.git
git push -u origin main

git tag v1.0.0
git push origin v1.0.0        # <- triggers 3-OS build + self-test + release
```

(`workflow_dispatch` on the Actions tab also runs a manual build without a tag.)

## STAGE 3 — release candidate results (Superfile.exe)

The **real Windows PE executable** `release/Superfile.exe` (21,347,608 bytes
= 20.36 MiB, PE32+ x86-64 console; sha256 `f8d5a831…453af5`) was built with the genuine Windows
toolchain — Windows CPython 3.13.1 + Windows PyInstaller 6.22.3 (win_amd64
wheels) — running under the **Wine 10.0 compatibility layer on Linux x86_64**
(Debian trixie). It was then **executed and fully tested as a Windows
program** (12/12 self-test + 34-format matrix + 5 E2E + 3 executable-safety +
3 archive-security + 2 SFP round-trips: **ALL CHECKS PASS** — see
`release/VERIFICATION_REPORT.txt` and `release/TEST-LOG.txt`). Honest caveat:
this was NOT executed on genuine Windows hardware; Windows CI
(`windows-latest`) reproduces the build + full battery and gates releases.

Rebuilt twice after the collapsible-panel UI work (`docs/UI_LAYOUT_TOGGLES.md`): +7,971 bytes for the top-bar
and sidebar toggles (17,534,866 → 17,542,837) and +4,461 bytes for the file-details slide
(17,542,837 → 17,547,298).  A later rebuild of the identical sources produced 17,546,556 bytes (sha256
`caeee285…948c80`) — PyInstaller output is not byte-reproducible across runs, so the release was re-verified
end to end after that rebuild; entry point `0x0000DCF0` and the PE32+ x86-64 console layout are unchanged.  The release
battery now runs `python -m tests.test_all` itself and derives the report's "Source tests" line from that run
(it used to be a constant).  The panels were additionally verified against the packaged exe in a real
browser — `release/UI_LAYOUT_CHECK.txt` (96 checks, A/B against the previous exe's own behaviour).

### Task C rebuild — ENCRYPT / DECRYPT (AES-256-GCM)

The encryption work added **+3,798,484 bytes** (17,546,556 → 21,345,040) because the executable now bundles
pyca `cryptography`, which is the AES-256-GCM implementation (never hand-rolled) and also removes any
runtime dependency on the host having it: `import cryptography` inside the bundle always succeeds.  The
optional Argon2id KDF (`argon2-cffi`) adds a measured **41,376 bytes** (21,306,232 without it, this build), so it was
kept; the without-build was measured and re-tested as a variant, not shipped.  Both are far below the
128 MB budget.  Rebuilds: 21,344,898 (first Task C build, before a UI fix) → 21,345,142 (second) →
**21,345,040**, and after a sandbox reset wiped the toolchain a further clean rebuild of the same tree produced
**21,347,608** (sha256 `f8d5a831…453af5`) — again not byte-reproducible, so the shipped binary was
re-verified from scratch: 12/12 self-test, packaged battery ALL CHECKS PASS, 135/135 browser checks against
the previous exe's own click-through, and 37/37 encryption checks including a real DPAPI device-lock
round-trip and the "different device" refusal.  Release artifacts re-generated from those runs
(`release/VERIFICATION_REPORT.txt`, `release/TEST-LOG.txt`, `release/UI_LAYOUT_CHECK.txt`,
`release/ENCRYPTION_VERIFICATION.txt`).

STAGE-3 fixes found by real execution (all re-verified after fixing):
* launcher `start_server` missing handler argument (regression, caught by
  unfrozen self-test before release);
* YAML writer now quotes number/bool-lookalike strings → JSON↔YAML round-trip
  is canonically lossless for string scalars (was `"1.0"` → `1.0`);
* self-test port-release probe now uses the server's own bind semantics.

## Verified here vs. not verified

| item | status |
|---|---|
| Windows `Superfile.exe` (PE32+ x86-64) | **built + PE-parsed + executed + full battery PASS** (under Wine 10 on Linux — not on genuine Windows hardware) |
| Linux x86-64 single-file build | built + self-tested in earlier stage; current binary rebuilt on CI (kept out of workspace to stay small) |
| macOS single-file build | **NOT built here** — CI workflow ready |
| GitHub Actions runs | **READY, NOT VERIFIED** (no GitHub credentials in this environment) |
| code signing / notarization | **not done** (unsigned; OS warnings possible) |
| genuine-Windows-hardware execution | **NOT VERIFIED** — see caveat above |

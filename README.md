# SUPERFILE

**One application. One object model. Many formats.**

SUPERFILE is a fully offline desktop application that opens *any* file as a single, uniform
**Universal Object** — bytes, decoded content, structure, metadata and history in one shape —
and then lets you inspect it, edit it, transform it, convert it and re-export it, all without
per-format applications and without ever running the code inside an imported file.
It ships as a **single Windows executable with no runtime dependencies** and as a plain
Python package you can run from source.

```
import anything → the same object model → inspect / transform / export / encrypt
```


[![Build (3 OS)](https://github.com/shuvrajeetkamila /<YOUR_REPO>/actions/workflows/build.yml/badge.svg)](https://github.com/<YOUR_GH_USERNAME>/<YOUR_REPO>/actions/workflows/build.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **Placeholders to fill in:** the badge URLs above use `shuvrajeetkamila/<YOUR_REPO>`; the
> download links in the next section do too. They are the only unfilled values in this file.

---

## DOWNLOAD

The ready-to-run Windows build lives in this repository **and** on the Releases page:

| | |
|---|---|
| In this repo | [`release/Superfile.exe`](release/Superfile.exe) |
| Releases page | `https://github.com/shuvrajeetkamila/<YOUR_REPO>/releases` |
| Platform | Windows 10/11, 64-bit (x86-64). Single file, no installer, no runtime, no dependencies. |
| Size | **21,347,608 bytes** (21.35 MB / 20.36 MiB) |
| SHA-256 | `f8d5a8317ff765c1b53c18dfa46d2ddbd48a59e9897212f7f4456f16e4453af5` |

Verify what you downloaded before running it:

```bat
certutil -hashfile release\Superfile.exe SHA256
```

then double-click it (or run `Superfile.exe --no-browser` and open <http://127.0.0.1:8765>).
The binary is **not code-signed**, so Windows SmartScreen may warn on first launch — that is
expected for an unsigned open-source build, and the hash above is the thing to compare.

---

## RUN FROM SOURCE

Requires CPython 3.13 (what CI and the release build use) and a browser. The UI is plain
HTML/CSS/JS served by the app itself — there is no build step, no bundler and no framework.

```bash
git clone https://github.com/<YOUR_GH_USERNAME>/<YOUR_REPO>.git
cd <YOUR_REPO>

pip install pillow cryptography          # image codecs + AES-256-GCM
pip install argon2-cffi                  # optional: enables the Argon2id KDF

python3 run.py                           # serve the UI on http://localhost:8765
python3 run.py --open                    # ...and open a browser window
python3 run.py --demo                    # generate the sample files first
python3 run.py --port=9000               # different port
```

The package entry point offers the same app plus CLI verbs:

```bash
python3 -m superfile serve  [--host=0.0.0.0] [--port=8765] [--open]
python3 -m superfile demo                 # write the demo sample set
python3 -m superfile info   <file>        # print the universal inspection report (JSON)
python3 -m superfile convert <in> <out> [fmt]
python3 -m superfile test                 # run the test suite
```

`run.py` binds `0.0.0.0` so the UI is also reachable from other devices on your LAN;
`python3 -m superfile serve` takes `--host=` if you want to restrict that. Everything is
local: the app never calls out to any network service, and there is no telemetry.

---

## FEATURES

### Every format family, one object model

**28 adapters covering 59 formats, 20 transforms, 15 creator targets**, all loaded with zero
warnings (measured by the packaged self-test and the release battery):

* **images** — PNG, JPEG, GIF, BMP (bit-exact codecs; resize/rotate/crop; GIF frame extraction)
* **documents** — PDF, DOCX, EPUB, RTF, plain text, Markdown, HTML
* **structured data** — JSON, YAML, TOML, CSV, XML, SQLite (read-only)
* **archives** — ZIP, TAR, GZIP (entries become child objects in the object graph)
* **audio** — WAV (PCM decode, spectrogram-free structural inspection)
* **3D / code / fonts / databases** — OBJ, STL, GLB, C, C#, Java, Go, Rust, Python, JS, CSS, WASM
* **executables** — PE/EXE, ELF: **static inspection only, never executed**

Conversions are honest by construction. Every export declares its kind —
`LOSSLESS`, `LOSSY`, `STRUCTURAL`, `RENDERED` or `RECONSTRUCTED` — and anything that cannot be
done without inventing data is refused with a specific, explanatory error instead of producing
a fake result (`docs/CONVERSION_MATRIX.md`).

### The `.sfp` container

`.sfp` is SUPERFILE's own container format: a versioned header, a chunk table
(`META`/`CONT`/`HIST`/`RTBL`/`OTBL`/`OFMT`/`OBYT`/`BLOB`/`KIDS`), and a mandatory SHA-256
checksum (`CKSM`) over everything before it. It preserves the original bytes *and* the decoded
content, so an `.sfp` round-trip returns the file byte-for-byte, and unknown chunks are skipped
rather than rejected (forward compatibility). Full byte-level specification:
[`docs/PROTOCOL_SPEC.md`](docs/PROTOCOL_SPEC.md).

### Encryption — two modes, AES-256-GCM

Two toolbar buttons (`ENCRYPT`, `DECRYPT`) and two tabs turn any open object into a locked
`.sfp`. The cryptography is deliberately boring:

| | |
|---|---|
| Cipher | **AES-256-GCM**, from the [`cryptography`](https://cryptography.io) package (never hand-rolled) |
| Password KDF (default) | **PBKDF2-HMAC-SHA256, 600,000 iterations**, random **16-byte** salt per file |
| Optional KDF | **Argon2id** (`argon2-cffi`, `time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`) — used only when a request asks for it |
| Nonce | fresh random **96-bit** base nonce per file, per-chunk variation, 16-byte GCM tag |
| AAD | binds each chunk's tag and index, so ciphertext chunks cannot be swapped, reordered or lifted into another file |
| Device mode | key wrapped with this machine's **Windows DPAPI** master key (`CryptProtectData`/`CryptUnprotectData` via `ctypes` — no `pywin32`, no `keyring` package), per-file key derived with HKDF-SHA256 |

* **Password mode** — type the password twice (inline mismatch error blocks the button) and
  tick an explicit *"there is no password recovery"* acknowledgement before
  `ENCRYPT & SAVE .SFP` enables. If you forget the password, nobody can decrypt the file,
  including you.
* **Device-locked mode** — no password at all: the file opens only on the computer that
  created it. **This mode is Windows-only in this build** (it is built on DPAPI). On macOS and
  Linux the radio button is greyed out and says so — the feature is reported as unavailable,
  never faked.

**What is encrypted:** every payload chunk — the original bytes (`OBYT`), the decoded text
(`CONT`, which holds the full decoded text of text/Markdown/JSON/CSV/XML objects), the decoded
frames (`BLOB`) and the graph/history/metadata chunks — is encrypted together. Only framing
stays legible: the container magic, header, chunk table, and the `ENCR` chunk (mode, KDF,
salt, nonce, device reference — none of which is secret). The checksum is computed *after*
encryption. The verification suite proves this by searching the produced bytes for the
original plaintext, decoded content and filename, and finding none of them.

Opening an encrypted `.sfp` through the normal **OPEN** flow never silently mis-parses it: it
fails with *"this .sfp is encrypted — use the DECRYPT tab to unlock it first"*.
Wrong password, wrong device and corrupted files each produce a specific message — never a
silent bad decode and never a false success.

---

## ARCHITECTURE

```
superfile/                the entire application (pure stdlib HTTP server + adapters)
  protocol.py             .sfp container: chunks, checksums, ENCR framing + encrypted-file guard
  crypto.py               AES-256-GCM, PBKDF2/Argon2id, DPAPI device keys (ctypes)
  object_model.py         UniversalObject, object graph, history, dedup
  detection.py            magic-byte sniffing with confidence (never trusts extensions)
  registry.py             adapter / format / transform / creator registry
  pipeline.py             import → inspect → transform → export, encrypt/decrypt plumbing
  transforms.py           the 20 transforms
  security.py             limits, path sanitisation, hashing, never-execute policy
  server.py               JSON API + static UI over http.server (no framework)
  demo.py                 generates the sample set (38 files)
  adapters/               28 format adapters (one file per family/format)
  codecs/                 bit-exact PNG / BMP / GIF / WAV helpers
ui/                       index.html + app.css + app.js — no framework, no build step
tests/                    test_all.py (83 tests), encryption_verify.py, packaged_e2e.py,
                          ui_layout_check.py (real-browser checks)
docs/                     PROTOCOL_SPEC, SECURITY_MODEL, ADAPTER_API, CONVERSION_MATRIX,
                          UI_LAYOUT_TOGGLES, PACKAGING, WINDOWS_BUILD
demo/                     39 sample files in ~40 formats
plugins/  examples/       plugin drop-in directory + worked PPM adapter example
release/                  the built Superfile.exe + the verification logs it passed
desktop.spec              PyInstaller one-file definition (the build recipe)
desktop_launcher.py       frozen entry point: server, CLI, and the 12-point --self-test gate
run.py  superfile/__main__.py   source entry points
.github/workflows/build.yml    3-OS build + test + release workflow
```

The adapter is the only place format-specific logic lives — adding a format never touches the
protocol, the object model, the transform engine or the UI. See
[`docs/ADAPTER_API.md`](docs/ADAPTER_API.md) and the runnable example in
`examples/new_format_adapter/`.

---

## BUILDING FROM SOURCE

The committed spec is the one that actually produces the release binary:

```bash
pip install pyinstaller pillow cryptography argon2-cffi
python -m PyInstaller --clean --noconfirm desktop.spec
#  -> dist/Superfile.exe
```

On Linux you can cross-build the identical Windows binary with the Windows toolchain under
Wine — this is exactly how `release/Superfile.exe` was produced (Windows CPython 3.13.1 +
Windows PyInstaller 6.22.3 wheels):

```bash
WINEPREFIX=~/.wine-superfile wine python-3.13.1-amd64.exe /quiet InstallAllUsers=0 \
    TargetDir='C:\Py313' Include_pip=1 PrependPath=0 Include_test=0 Include_doc=0 Shortcuts=0
WINEPREFIX=~/.wine-superfile wine 'C:\Py313\python.exe' -m pip install pyinstaller pillow cryptography argon2-cffi
WINEPREFIX=~/.wine-superfile xvfb-run -a wine 'C:\Py313\python.exe' -m PyInstaller --clean --noconfirm desktop.spec
```

The resulting file for this release: **`release/Superfile.exe` — 21,347,608 bytes (21.35 MB),
PE32+ x86-64 console, 7 sections, entry point `0x0000DCF0`**, verified on this machine with
`xvfb-run -a wine release/Superfile.exe --self-test` → 12/12 PASS.

> PyInstaller output is **not byte-reproducible** across runs (embedded timestamps), so a
> rebuild of the same sources produces a same-size, differently-hashed binary. Always re-run
> the self-test and the battery after building, and compare against the hash in *your* build's
> log, not against the number above. The Windows CI workflow
> ([`.github/workflows/build.yml`](.github/workflows/build.yml)) does exactly that on
> `windows-latest` and attaches the verified binary to a GitHub Release on a `v*` tag.

More detail: [`docs/PACKAGING.md`](docs/PACKAGING.md), [`docs/WINDOWS_BUILD.md`](docs/WINDOWS_BUILD.md).

---

## SECURITY

The full trust model is [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md); the short version:

* **Imported files are untrusted data.** SUPERFILE is a viewer/editor of digital objects, never
  an executor of them: no `exec`/`eval`, no subprocesses, no shell-outs anywhere, and EXE/DLL/
  ELF/WASM/script imports are parsed as data with a standing
  *"UNTRUSTED BINARY — static inspection only"* warning.
* **Bounded resource use** — import cap 64 MiB, per-entry decompression cap 64 MiB, 256 MiB
  total uncompressed, 200:1 compression-ratio guard, 10,000-entry cap, 40 M-pixel decode cap,
  JSON/BSON depth caps.
* **No filesystem escape** — archive entry names are sanitised (`..`, absolute paths and drive
  letters rejected, symlinks/hardlinks skipped); downloads use safe filenames; extraction never
  writes outside the object store.
* **Integrity** — SHA-256 on every object and a mandatory container checksum; corruption or
  tampering is a hard reject.
* **Encryption model** — AES-256-GCM with per-chunk AAD binding (tag + index), PBKDF2-HMAC-SHA256
  at 600,000 iterations and a 16-byte random salt by default, a fresh 96-bit nonce per file, and
  DPAPI-wrapped keys in device mode. The key material never leaves the process, and the stored
  device blob is DPAPI-protected — there is no plaintext master key on disk.
  There is **no password recovery by design**: if you forget the password, the file is gone.
* **Honest scope** — this is a **prototype-stage project**. It has not been audited, fuzzed at
  scale, or penetration-tested by a third party, it is not code-signed, and the crypto is
  implemented on top of a well-reviewed library rather than by a cryptography team. Treat it as
  a capable open-source tool, not a hardened product, and don't make it the only copy of
  anything you cannot afford to lose.

---

## SELF-TEST AND VERIFICATION

Everything here is re-runnable, and the outputs are committed alongside the binary:

```bash
python3 -m tests.test_all              # source suite: 83 tests
Superfile.exe --self-test              # the packaged 12-point release gate
python3 tests/encryption_verify.py     # byte-level AES-256-GCM checks (source tree)
```

The 12-point gate covers: demo data generation, server startup, `/api/health`,
`/api/registry` + adapter loading with zero warnings, UI resource loading, real PNG and JSON
imports, static EXE inspection (never executed), safe ZIP acceptance, path-traversal refusal,
decompression-bomb refusal and clean shutdown.

Results committed in this repository, produced from the binary in `release/`:

* [`release/VERIFICATION_REPORT.txt`](release/VERIFICATION_REPORT.txt) — the packaged release
  battery: **ALL CHECKS PASS** (format matrix, UI startup, PNG/JSON import, TXT edit/export,
  ZIP extraction, traversal + bomb protection, EXE static inspection, `.sfp` round-trip,
  clean-directory execution, size check).
* [`release/TEST-LOG.txt`](release/TEST-LOG.txt) — the full battery transcript, including the
  source suite running inside it (83 run, 0 failures, 0 errors, 3 skipped).
* [`release/ENCRYPTION_VERIFICATION.txt`](release/ENCRYPTION_VERIFICATION.txt) — the encryption
  proof: **37/37 checks** against the packaged exe, with the hexdump of a produced container,
  plaintext-absence searches, wrong/right password, Argon2id, tamper + cross-file-splice
  rejection, device-lock round-trip, the different-device refusal and the `EXPORT` regression.
* [`release/UI_LAYOUT_CHECK.txt`](release/UI_LAYOUT_CHECK.txt) — the real-browser check
  (Chromium, driven by Playwright) of the packaged exe: collapsible panels, the file-details
  slide, and the ENCRYPT/DECRYPT flows end to end.

Current status, stated plainly: the packaged binary passes its self-test (12/12), the release
battery (ALL CHECKS PASS), the encryption suite (37/37 against the exe, 33/33 against the
source tree) and the browser suites (128 checks against the exe, 120 against the source tree).
It was built and executed under Wine 10.0 on Linux with the genuine Windows toolchain — it has
**not** yet been run on genuine Windows hardware, and that caveat is repeated in every report
file. The GitHub Actions workflow is committed but has not been executed on GitHub yet.

---

## CONTRIBUTING

The lowest-friction contribution is a **new format adapter**: copy
`examples/new_format_adapter/ppm_adapter.py`, drop it into `plugins/`, and it is picked up with
no core changes. [`docs/ADAPTER_API.md`](docs/ADAPTER_API.md) documents the
`FormatAdapter` contract — `detect()`, `import_bytes()`, `inspect()`, `export()` and the
support levels. Bug reports are most useful with a sample file plus the output of
`Superfile.exe --self-test` and `python3 -m tests.test_all`; before sending a patch, please make
sure both are green.

---

## LICENSE

Dual-licensed, at your option, under either

* the **MIT License** — [`LICENSE-MIT`](LICENSE-MIT), or
* the **Apache License, Version 2.0** — [`LICENSE-APACHE`](LICENSE-APACHE).

See [`LICENSE`](LICENSE) for the dual-license statement. Unless you explicitly state otherwise,
any contribution intentionally submitted for inclusion in this project shall be dual-licensed
as above, without any additional terms or conditions.

Copyright (c) 2026 SHUVRAJEET KAMILA

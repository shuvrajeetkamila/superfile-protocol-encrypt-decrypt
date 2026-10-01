# Changelog

All notable changes to SUPERFILE are recorded here.  This project follows
[Semantic Versioning](https://semver.org/).

## 1.0.0 — 2026-10-01

First public release.  Everything below is implemented in the source tree in
this repository and was verified against the executable rebuilt from it
(`release/Superfile.exe`, 21,347,608 bytes, sha256
`f8d5a8317ff765c1b53c18dfa46d2ddbd48a59e9897212f7f4456f16e4453af5`).

### Added

* **Universal Object Model + `.sfp` protocol** — one object model for every
  input, with a documented, checksummed container format (`docs/PROTOCOL_SPEC.md`),
  28 adapters covering 59 formats, 20 transforms and 15 creator targets.
* **Format families** — images (PNG/JPEG/GIF/BMP), documents (PDF/DOCX/EPUB/RTF),
  structured data (JSON/YAML/TOML/CSV/SQLite), archives (ZIP/TAR/GZ),
  audio (WAV), video/3D/code/executables (static inspection only — never run).
* **Desktop packaging** — `desktop.spec` builds a single-file Windows
  executable that embeds the whole application (UI, adapters, codecs) with no
  runtime dependencies, plus a 12-point `--self-test` release gate.
* **Collapsible UI panels** — a top-bar strip that folds the title bar +
  toolbar, a sidebar rail that folds the 250 px sidebar to zero, and a
  file-details slide that stows the object header while keeping the filename
  and tab strip visible; all three animate, persist in `localStorage` and are
  UI-only additions (`docs/UI_LAYOUT_TOGGLES.md`).
* **AES-256-GCM encryption with two modes** — `ENCRYPT` / `DECRYPT` toolbar
  buttons and tabs turn any open object into a locked `.sfp`:
  * *password mode* — PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random
    salt, fresh 96-bit nonce per file, AES-256-GCM from the `cryptography`
    package (never hand-rolled), with a no-recovery warning and an explicit
    acknowledgement before the file can be written;
  * *device mode* (Windows only) — the file key is wrapped with this machine's
    DPAPI master key via `ctypes` (`CryptProtectData`), with no password and no
    extra dependency; on macOS/Linux the mode is greyed out and reported as
    unavailable instead of being faked.
  * Optional Argon2id KDF (`argon2-cffi`, t=3 / 64 MiB / p=4) for callers that
    request it; PBKDF2 remains the default.
  * The read path refuses to load an encrypted container through the normal
    open flow, with the explicit message *"this .sfp is encrypted — use the
    DECRYPT tab to unlock it first"*, so it can never be silently mis-parsed.

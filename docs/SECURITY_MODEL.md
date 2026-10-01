# SUPERFILE — SECURITY MODEL

> Imported files are **untrusted data**.  SUPERFILE is a viewer/editor of
> digital objects — never an executor of them.

This document is the trust model of the prototype, implemented primarily in
`superfile/security.py` and enforced by every adapter.

---

## 1. Threat model

Inputs: arbitrary attacker-supplied files (archives, media, documents,
executables, containers).  Goals:

1. no code execution (of file content or filenames),
2. no filesystem escape (traversal, symlink tricks),
3. no resource exhaustion (zip bombs, decompression bombs, pixel bombs,
   pathological structures),
4. integrity (detect corruption/tampering via checksums and signature checks),
5. clear user-visible warnings instead of silent risk.

Out of scope for the prototype: adversarial sandbox escapes of the Python
runtime itself, side channels, malicious *plugin* code (plugins are trusted
admin-installed extensions, §8).

## 2. Hard rules (enforced)

| Rule | Where |
|------|-------|
| **Never execute imported content** — no `exec`, `eval`, `subprocess`, no shell-outs, no import of file content as code. EXE/DLL/ELF/WASM/scripts are parsed as data only. | whole codebase; `TestSecurity.test_never_executes` asserts no `run`/`execute` capability exists |
| **Archive path sanitisation** — entry names reduced to safe relative paths; `..`, absolute paths, drive letters rejected; symlinks/hardlinks skipped; extraction never writes to disk in the prototype (entries become child objects). | `sanitize_archive_path()`, `stat_is_symlink()`, `extract_children()` |
| **Decompression limits** — per-entry cap 64 MiB, total uncompressed cap 256 MiB, max 10 000 entries, compression-ratio cap 200:1 (checked against actual data). | `SafeLimits`, `check_extraction_budget()` |
| **Declared-size validation** — sizes/counts in headers must match actual data (BSON doc length, STL triangle table, chunk lengths, SFP chunk bounds). | adapters, `protocol._iter_chunks` |
| **Signature validation** — magic-byte detection with confidence; declared/detected mismatches lower trust and raise warnings; corrupt SFP checksums are rejected. | `detection.py`, `protocol.loads(verify=True)` |
| **Hashing** — SHA-256 for every object (bytes, else canonical content). | `security.sha256`, pipeline |
| **Parser limits** — decode caps: 40 M pixels, text 8 MiB, JSON depth 200, BSON depth 100, boxes/elements walks bounded, import cap 64 MiB. | `SafeLimits` |
| **No auto-previews of active content** — HTML/SVG previews are script-stripped; nothing from a file is fetched over the network. | UI (`renderView`) |
| **Read-only database access** — SQLite opens with `mode=ro&immutable=1` URI on a temp copy; no extension loading; identifiers quoted. | `database.py` |
| **Safe filenames** — download/extract names pass `safe_filename()`. | `security.py`, server |

## 3. Executable handling

PE/ELF/WASM/scripts get `SupportLevel.INSPECTION` and a standing warning
("UNTRUSTED BINARY — static inspection only; SUPERFILE never executes files").
Static analysis covers headers, sections/segments, imports/exports, needed
libraries, entry point.  Suspicious traits raise extra warnings:

* W+X sections/segments (packer/shellcode hint)
* TLS directory (TLS callbacks run before entry point on Windows)
* `DT_RPATH`/`DT_RUNPATH` (library search override)
* DLL/shared-object nature

There is **no** execution feature in the prototype.  If one is ever added it
must be an explicitly separate, sandboxed component with its own threat model.

## 4. Container security (`.sfp`)

* Mandatory CKSM SHA-256 over all preceding bytes; corruption ⇒ hard reject.
* Chunk lengths validated against file bounds; truncated/overlong ⇒ reject.
* Recursive children are themselves verified (depth-limited by resources).
* Unknown chunk tags are skipped without interpretation.

## 5. Media/decode safety

* Pixel-count caps before allocation; dimensions sanity-checked.
* Our pure PNG/GIF/BMP parsers validate structure (CRC on PNG chunks, LZW
  bounds, filter types) and fail closed to `INSPECTION ONLY` + preserved bytes.
* Optional Pillow decoding is likewise capped by pixel limits.

## 6. UI safety

* Rendered HTML/SVG: scripts stripped before display.
* PDF display uses the browser's PDF viewer on local bytes (no remote loads).
* Downloads use attachment disposition + sanitised names.
* All warnings are surfaced prominently (never silently swallowed).

## 7. Data handling / privacy

* Fully offline: no telemetry, no cloud, no API keys, no external requests.
* Object store is in-memory; nothing is written except explicit exports.

## 8. Plugin trust

Plugins under `plugins/` are **trusted** admin-installed Python code (analogous
to browser extensions or Photoshop plugins).  They run with the app's
privileges.  Only install plugins you trust.  (Sandboxing plugin interpreters
is a listed future extension in PROTOCOL_SPEC §20.)

## 9. Residual risks (honest list)

* Parser bugs in our own code could still crash or mis-parse (fuzzing is a
  future item); fail-closed behaviour limits impact to denial of service.
* `IMPORT PATH` reads arbitrary *server-side* paths the OS user can read —
  it is a local desktop feature, guarded by explicit user action.
* Pillow's decoders (optional) are native code with a large surface — they are
  optional and capped, but a compromised Pillow would be out of this model.
* Browser-rendered previews trust the *browser* sandbox (video/PDF embeds).

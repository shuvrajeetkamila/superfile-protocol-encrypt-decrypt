# SUPERFILE — CONVERSION CAPABILITY MATRIX

> The live, per-object matrix is shown in the app (**MATRIX** tab and
> **EXPORT AS** tab).  This document summarises the *shipped* truth table as
> of protocol v1.0.  Impossible conversions are absent by design.

Legend — conversion kinds:  **L** = LOSSLESS · **Y** = LOSSY · **S** =
STRUCTURAL · **R** = RENDERED · **C** = RECONSTRUCTED

Every object can always be saved as **`.sfp`** (L) regardless of row below.

## TEXT / DATA

| Source | Real export targets |
|--------|---------------------|
| TXT    | txt (C) · md (C) · html (C) · rtf (C) · sfp (L) |
| MD     | md (L) · txt (C) · html (C) · rtf (C) · sfp (L) |
| CSV    | csv (L) · txt (C) · md (C) · html (C) · rtf (C) · json (S rows) · sfp (L) |
| JSON   | json (L) · yaml (S subset) · toml (S subset, only table-of-scalar data) · csv (S, only array-of-objects) · txt (C) · sfp (L) |
| YAML   | yaml (L) · txt (L) · json (S) · sfp (L) |
| TOML   | toml (L) · txt (L) · json (S) · sfp (L) |
| BSON   | json (C) · sfp (L) |
| XML    | xml (L) · txt (S) · html (C) · sfp (L) |
| HTML   | html (L) · txt (S) · md (C) · sfp (L) |
| RTF    | txt (S) · rtf (C writer) · html (C) · sfp (L) |

## DOCUMENT

| Source | Real export targets |
|--------|---------------------|
| PDF    | pdf (L bytes) · txt (S text-operators) · json (S report) · html (C) · sfp (L) |
| DOCX   | docx (L bytes) · txt (S paragraphs) · html (C) · json (S report) · sfp (L) |
| EPUB   | epub (L bytes) · txt (S chapters) · html (C) · json (S report) · sfp (L) |

PDF rasterisation and DOCX layout rendering are **not** offered server-side
(no renderer bundled).  The UI embeds PDFs in the browser's viewer — a
`RENDERED` experience, not a conversion.

## IMAGE / ANIMATION

| Source | Real export targets |
|--------|---------------------|
| PNG    | png (L) · bmp (L) · gif (Y ≤256 colours) · ppm (L, example plugin) · svg (C embed) · jpeg (Y, Pillow) · webp (Y, Pillow) · tiff (S, Pillow) · sfp (L) |
| BMP    | bmp (L) · png (L) · gif (Y) · ppm (L plugin) · svg (C) · jpeg/webp/tiff (Pillow) · sfp (L) |
| GIF    | gif (L frames+timing) · png (L last/composite frame) · bmp (L) · sfp (L) |
| JPEG   | with Pillow: jpeg (L bytes) · png (L decode) · bmp · gif (Y) · webp (Y) · sfp (L) — without Pillow: **inspection only** + sfp (L) |
| WebP   | with Pillow: webp (L bytes) · png (L) · gif (Y) · sfp (L) — without Pillow: inspection + sfp (L) |
| TIFF   | with Pillow: tiff (L bytes) · png (L) · sfp (L) — without Pillow: header inspection + sfp (L) |
| SVG    | svg (L) · txt (L source) · sfp (L). SVG→PNG is offered **only** as in-UI browser capture (`RENDERED`), never as a fake server conversion |

## AUDIO

| Source | Real export targets |
|--------|---------------------|
| WAV    | wav (L bytes) · json (S metadata) · txt (S peaks) · sfp (L) |
| MP3/FLAC/OGG/AAC | json (S metadata: tags/STREAMINFO/ADTS) · sfp (L). No re-encode (no codec bundled) — honest INSPECTION ONLY |

## VIDEO

| Source | Real export targets |
|--------|---------------------|
| MP4/MOV | json (S box tree + tracks) · sfp (L) |
| MKV/WebM | json (S element tree + tracks) · sfp (L) |
| AVI   | json (S chunk tree + streams) · sfp (L) |

Frame extraction: real for GIF (`LOSSLESS`); for browser-playable MP4/WebM the
UI offers `EXTRACT FRAME (RENDERED)` via canvas capture, recorded as a child
object with kind `RENDERED`.  Container re-mux (mp4→mkv etc.) is **not**
offered.

## 3D

| Source | Real export targets |
|--------|---------------------|
| OBJ    | obj (L) · stl (C triangulated) · json (S report) · sfp (L) |
| STL    | stl (L) · obj (C triangle soup) · json (S) · sfp (L) |
| GLTF/GLB | json/gltf (S) · obj (C positions) · sfp (L) |

## ARCHIVES

| Source | Real export targets |
|--------|---------------------|
| ZIP    | zip (L bytes) · json (S listing) · sfp (L with entries as children) |
| TAR/GZIP | tar/gz (L bytes) · json (S listing) · sfp (L) |
| 7Z     | sfp (L) only — decompression deliberately not implemented (inspection only) |

## EXECUTABLE / BINARY (static only — never executed)

| Source | Real export targets |
|--------|---------------------|
| PE/EXE/DLL | json (S analysis) · txt (S report+hex) · sfp (L) |
| ELF    | json (S analysis) · txt (S report+hex) · sfp (L) |
| WASM   | wasm (L bytes) · json (S analysis) · sfp (L) |
| BLOB   | bin (L) · txt (S hex) · sfp (L) |

## SOURCE CODE

| Source | Real export targets |
|--------|---------------------|
| C/C++/Python/JS/Java/Rust/Go/C#/CSS/… | src (L) · txt (L) · html (C highlight page) · sfp (L) |

## DATABASE

| Source | Real export targets |
|--------|---------------------|
| SQLite | sqlite (L bytes) · json (S schema+samples) · sql (S DDL) · sfp (L) |

---

### Deliberately absent (do not ask the UI for these)

re-encodes between lossy formats without a decoder (jpeg→png without Pillow) ·
video/audio transcodes (mp4→avi, mp3→wav) · SVG server-side rasterisation ·
PDF authoring from arbitrary layouts (only the minimal writer used by CREATE) ·
7Z decompression · executable "conversion" of any kind · DOCX layout render.

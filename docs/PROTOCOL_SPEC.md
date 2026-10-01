# SUPERFILE PROTOCOL SPECIFICATION

**Universal Digital Object Protocol — version 1.0**

> "One application. One object model. Many formats."

This document is the normative specification of the SUPERFILE superprotocol:
the Universal Object Model (§2), the `.sfp` binary container (§3–§11), and the
adapter/conversion architecture (§15–§17).  Everything described here is
implemented in this repository; implementation notes state where behaviour is
deliberately partial.

---

## 1. Philosophy

**Different digital file formats can be represented as interoperable
UniversalObjects through a common protocol while retaining their native
representations and format-specific capabilities.**

Concretely:

1. **One object model.**  Every imported/created digital object becomes a
   `UniversalObject`, whatever its origin format.
2. **Lossless preservation.**  Whenever possible the original bytes are kept
   verbatim inside the object (`original_bytes`), alongside the decoded,
   editable representation.  Opening a JPEG never destroys the JPEG.
3. **Truthful conversion.**  Conversions are classified as `LOSSLESS`, `LOSSY`,
   `STRUCTURAL`, `RENDERED` or `RECONSTRUCTED` (§16).  Impossible conversions
   are simply absent — the protocol never pretends.
4. **Extensibility without rewrites.**  A new format is a new *adapter*
   (§15).  The protocol, the object model and the UI do not change.
5. **Safety by construction.**  Imported files are untrusted data.  Nothing is
   ever executed (§18).
6. **Honest support levels.**  `FULL SUPPORT`, `PARTIAL SUPPORT`,
   `INSPECTION ONLY`, `UNSUPPORTED` are first-class, visible values.

The protocol does **not** claim that all formats become identical.  It claims
they become *interoperable through one representation* while remaining
themselves.

---

## 2. Universal Object Model

A `UniversalObject` is the common intermediate representation.

| Field              | Type                | Meaning                                            |
|--------------------|---------------------|----------------------------------------------------|
| `object_id`        | UUID string         | globally unique identity                           |
| `object_type`      | enum                | TEXT, DOCUMENT, IMAGE, AUDIO, VIDEO, ANIMATION, 3D, ARCHIVE, EXECUTABLE, SOURCE_CODE, DATABASE, BINARY, DIRECTORY, MULTIMEDIA_CONTAINER, PROTOCOL, UNKNOWN |
| `version`          | integer             | object model revision (1)                          |
| `original_filename`| string              | name at import/create time                         |
| `original_extension` | string            | extension without dot                              |
| `detected_format`  | format id           | e.g. `jpeg`, `mkv`, `elf`                          |
| `mime`             | string              | MIME type                                          |
| `size`             | integer             | original size in bytes                             |
| `metadata`         | map                 | format metadata, detection report, EXIF, tags …    |
| `content`          | map (JSON-safe)     | decoded/structured representation (adapter-made)   |
| `children`         | list of UniversalObject | nested objects (streams, entries, pages …)     |
| `relationships`    | list of {relation, target_id, note} | typed links between objects       |
| `transformations`  | list of records     | ordered, classified operation history              |
| `original_bytes`   | bytes (optional)    | verbatim original file — lossless preservation     |
| `checksum`         | hex SHA-256         | of original bytes, else canonical content JSON     |
| `capabilities`     | list of verbs       | detect read parse decode create edit encode export inspect |
| `export_formats`   | list of ExportOption| only *real* export targets (§12, §16)              |
| `support_level`    | enum                | FULL / PARTIAL / INSPECTION / UNSUPPORTED          |
| `warnings`         | list of strings     | safety & parsing warnings, shown prominently       |

Binary payloads referenced from `content` (decoded pixels, frame buffers …) are
stored in the object's **blob table** and referenced as `{"__blob__": "<key>"}`
so that `content` itself stays JSON-serialisable.

### Nesting

Nesting is first-class.  Examples of canonical decompositions:

```
VIDEO  ├── video stream │ audio stream │ subtitle stream │ metadata
ARCHIVE ├── document │ image │ executable │ directory
DOCUMENT ├── text │ images │ fonts │ metadata
SUPERFILE └── Project ├── document │ image │ video │ source │ executable │ metadata
```

Relationships are explicit (`contains`, `stream_of`, `page_of`, `frame_of`,
`derived_from`, …), so an object graph is queryable without walking bytes.

---

## 3. Container structure (`.sfp`)

The SUPERFILE container serialises a UniversalObject *graph* — the root object,
its content and metadata, its blobs, its original bytes and recursively its
children (each child is itself a complete SFP document).

```
SFP
├── HEADER          magic, version, flags, reserved
├── META            core object fields + metadata map        (JSON, required)
├── CONT            content representation                   (JSON, required)
├── HIST            transformation history                   (JSON)
├── RTBL            relationship table                       (JSON)
├── OTBL            object table — child summaries           (JSON)
├── OFMT            original representation record           (JSON, required)
├── OBYT            optional original bytes                  (binary)
├── BLOB            binary blob table                        (binary)
├── KIDS            nested SFP documents (children)          (binary)
└── CKSM            SHA-256 integrity checksum               (required, last)
```

File extension: `.sfp`  ·  MIME: `application/x-superfile`

### Fixed header (32 bytes, big-endian)

| Offset | Size | Field         | Value / meaning                                     |
|--------|------|---------------|-----------------------------------------------------|
| 0      | 8    | magic         | `8b 53 46 50 0d 0a 1a 0a` ("\x8bSFP\r\n\x1a\n")     |
| 8      | 2    | version_major | 1 — readers refuse newer majors (override possible) |
| 10     | 2    | version_minor | 0 — newer minors accepted                           |
| 12     | 4    | header_size   | 32; bytes from start until first chunk              |
| 16     | 4    | flags         | bit0 CONT-zlib, bit1 OBYT-zlib, bit2 BLOB-zlib      |
| 20     | 12   | reserved      | zero (future use)                                   |

### Chunk framing

Every chunk after the header:

```
tag     4 ASCII bytes
length  u64 big-endian (payload length)
payload length bytes
```

Readers MUST skip chunks with unknown tags (forward compatibility).  Writers
MUST place `CKSM` last.  Unknown flags MUST be ignored.

### Chunk payloads

* **META** — UTF-8 JSON: `object_id`, `object_type`, `object_version`,
  `original_filename`, `original_extension`, `detected_format`, `mime`, `size`,
  `checksum`, `capabilities`, `export_formats`, `support_level`, `warnings`,
  `metadata`, `adapter_name`, `adapter_version`, `created_at`.
* **CONT** — UTF-8 JSON content map (may be zlib-compressed when flag0 set).
* **HIST** — JSON array of transformation records (§9).
* **RTBL** — JSON array of `{relation, target_id, note}`.
* **OTBL** — JSON array of child summaries for fast listing without
  decompressing KIDS.
* **OFMT** — JSON original-representation record: `original_format`, `mime`,
  `filename`, `extension`, `size`, `checksum`, `preserved_bytes`,
  `detection` (full detection report), `format_version`.
* **OBYT** — the verbatim original file bytes (optional; zlib per flag1).
  A SUPERFILE container does **not** embed its own bytes as OBYT (that would
  nest infinitely on re-save) — the container itself is the preservation.
* **BLOB** — concatenated entries: `u16 key_len + key + u64 len + data`
  (whole table may be zlib per flag 2).
* **KIDS** — concatenated child documents: `u64 len + SFP bytes` (recursive).
* **CKSM** — 32 raw bytes: SHA-256 over **every byte of the file before this
  chunk**.  Any post-checksum trailing data is a violation.

---

## 4. Header

Covered in §3.  Design rules:

* `header_size` makes the header itself extensible — v1.0 readers skip extra
  header bytes in future minor versions.
* `flags` bits are assigned by the specification; unknown bits MUST be ignored.
* `reserved` bytes MUST be written as zero and ignored on read.

## 5. Metadata

The `metadata` map (inside META) is open-ended.  Conventional keys:

* `detection` — the format-detection report (method, confidence, notes)
* `encoding` — text encodings
* `exif`, `tags`, `core_properties` — format metadata as extracted
* `sfp` — container introspection (`container_version`, `flags`,
  `unknown_chunks`, `container_file_size`)
* `checksum_basis` — `content-json` when checksum covers content, not bytes

Adapters MAY add arbitrary keys.  Readers MUST NOT require keys beyond those
listed in §3/META.

## 6. Object IDs

`object_id` is a UUID v4 string generated at object creation.  IDs are stable
across container saves (they live in META).  Relationship targets reference
IDs, so a graph survives serialisation.  Collisions between two independent
objects are astronomically unlikely; a loader MUST NOT merge objects that
merely share an ID across *different* roots without explicit linking.

## 7. Relationships

`{relation, target_id, note}` triples, stored in RTBL.  Conventional relation
names: `contains`, `stream_of`, `page_of`, `frame_of`, `derived_from`,
`references`.  Relations are directional and typed; the inverse is implied.

## 8. Nested objects

Children live in KIDS as complete SFP documents (recursive application of this
entire specification).  Each child carries its own metadata, content, original
bytes and checksum.  OTBL mirrors lightweight summaries so a viewer can render
a tree without parsing all children.  Depth is limited only by resources;
adapters SHOULD cap pathological inputs (archive entry counts, pixel counts).

## 9. Original representation

Three levels of preservation, in order of preference:

1. **`original_bytes`** (OBYT) — the exact source file.  When present, the
   object can always be exported back to its original format *losslessly*.
2. **`content`** — the decoded/structured representation for editing and
   cross-format export.  May be lossier than the original (that is why (1)
   exists).
3. **Reconstruction** — for created (never imported) objects, `content` is the
   original; `checksum` covers the canonical content JSON (`checksum_basis:
   content-json`).

`OFMT` records the original format identity so that, e.g., a JPEG inside a
SUPERFILE still *knows* it is a JPEG, with its detection evidence.

## 10. Checksums

SHA-256.  Two checksums exist:

* **Object checksum** (`checksum` in META/OFMT) — of the original bytes
  (or canonical content for created objects).
* **Container checksum** (CKSM) — over all container bytes before CKSM.

Loaders MUST verify CKSM and MUST reject corrupt containers (a documented
override flag may exist for forensics).  The object checksum detects mismatch
between OFMT claims and OBYT reality.

## 11. Versioning

* **Container version** — `version_major.version_minor` in the header.
  Minor bumps are additive (new optional chunks/flags).  Major bumps may break
  compatibility; readers refuse newer majors by default.
* **Object model version** (`version` field) — currently 1.
* **Adapter versions** are independent (META records which adapter produced
  the content).
* New optional semantics go in **new chunk tags** or metadata keys — never in
  changed meanings of existing ones.

## 12. Compression

CONT, OBYT and BLOB payloads MAY be zlib-compressed (flags 0–2).  Writers
compress only when the payload shrinks.  Readers MUST honour the flags and
MUST enforce decompression size limits (§18).  KIDS children compress their
own internals; the KIDS framing itself is not compressed (streaming listing).

## 13. Encryption extension (reserved)

Reserved design (NOT implemented in this prototype):

* Flag bit 8 = `ENCRYPTED`.  A required `ENCR` chunk (before CKSM) carries an
  algorithm id (e.g. `AES-256-GCM`), KDF parameters (Argon2id), salt, nonce
  and tag.  Content chunks (`CONT`, `OBYT`, `BLOB`, `KIDS`) are ciphertext.
  META (unencrypted) carries only non-sensitive display fields; sensitive
  metadata goes into an encrypted `XENC` chunk.
* Passphrase-derived keys only in v1.1; public-key wrapping (age/HPKE) is a
  planned `XENC` profile.
* Unmodified CKSM covers ciphertext as usual (integrity of the container is
  still verifiable without keys).

## 14. Digital-signature extension (reserved)

Reserved design (NOT implemented in this prototype):

* A `SIGN` chunk after CKSM? — **no**: signatures live *before* CKSM as a
  `DSIG` chunk so CKSM still covers the whole file.  `DSIG` contains:
  signature algorithm (Ed25519), signer public key or certificate fingerprint,
  signed payload = SHA-256 over the file excluding the `DSIG` payload itself,
  and the signature bytes.
* Multiple `DSIG` chunks are allowed (co-signatures).
* Detached external signatures over the full `.sfp` file are equally valid and
  simpler; the chunk form exists for self-contained artefacts.

## 15. Adapter system

All format knowledge lives in adapters implementing:

```
detect()  read()  parse()  decode()  create()  edit()  encode()  export()  inspect()
```

Each adapter publishes a **manifest**: `name`, `version`, `formats`,
`capabilities` (per-format verb sets), `input_types`, `output_types`, and a
per-format `FormatSpec` (extensions, MIME, category, support level, detection
method, notes).  See `docs/ADAPTER_API.md` and the worked example in
`examples/new_format_adapter/ppm_adapter.py`.

Adding a format NEVER touches the protocol: `NEW FORMAT → NEW ADAPTER →
UniversalObject`.

## 16. Conversion semantics

`ExportOption.format` lists only real targets; `ExportOption.kind` states the
truth class of the conversion:

| Kind           | Meaning                                                     | Example |
|----------------|-------------------------------------------------------------|---------|
| `LOSSLESS`     | identical information survives (re-encode/container only)   | PNG→PNG, any→SFP |
| `LOSSY`        | information is discarded (quality, resolution, colours)     | PNG→JPEG q90, image→GIF |
| `STRUCTURAL`   | structural re-representation (tables, trees, containers)    | JSON→YAML, ZIP listing |
| `RENDERED`     | produced by rendering (frame capture, raster of a scene)    | video frame via browser |
| `RECONSTRUCTED`| rebuilt from a model (layout dropped, triangulated, wrapped)| MD→HTML, OBJ→STL |

UIs MUST show this classification per export target.

## 17. Lossless vs lossy operations

* **Import is lossless by default**: `original_bytes` preserved.
* **Edits** never mutate `original_bytes`; they update `content` (and the edit
  is appended to `transformations`).
* **Export to the original format** is lossless iff `original_bytes` exist
  (byte-identical passthrough); otherwise it is at best a re-encode (may be
  `LOSSY` for lossy codecs).
* **`.sfp` export** is always `LOSSLESS`: the full graph + originals + history.
* Transforms declare their own kinds (`image.resize` = LOSSY, `image.rotate`
  90/180/270 = LOSSLESS, `gif.extract_frame` = LOSSLESS, …).

## 18. Security model

Summary (full treatment in `docs/SECURITY_MODEL.md`):

* Imported files are untrusted data.  **Nothing is executed, ever.**
* Executables (PE/ELF/WASM/scripts) are static-inspection only.
* Archive paths are sanitised (no traversal/absolute/symlink extraction);
  decompression expansion is capped (ratio + absolute limits).
* Declared sizes/counts are validated against actual data.
* File signatures are validated; mismatches raise warnings and reduce
  confidence.
* SHA-256 hashes are computed for every object.
* Parsers run with strict limits (pixels, depth, entries, text length).
* Suspicious binaries raise visible warnings (W+X sections, TLS callbacks,
  DT_RPATH …).
* SQLite opens read-only/immutable; no extension loading.
* Containers verify their checksums; corrupt containers are rejected.

## 19. Compatibility

* **Forward**: unknown chunks skipped; unknown header bytes skipped; unknown
  flags ignored; unknown metadata keys retained.
* **Backward**: v1.0 readers accept any minor version; refuse newer majors
  unless explicitly overridden.
* **Round-trip**: `original_bytes` guarantee byte-identical export to the
  original format; container round-trip preserves ids, graph, history.
* **Degradation**: when an adapter cannot decode a payload it still produces a
  valid UniversalObject with `support_level: INSPECTION ONLY`/`UNSUPPORTED`,
  warnings, hex preview and preserved bytes.

## 20. Future extensions

* Encryption (`ENCR`/`XENC`, §13) and digital signatures (`DSIG`, §14)
* Streaming chunked transfer for huge media (OBYT sidecars)
* Shared blob deduplication across sibling children (content-addressing)
* Capability negotiation: `requires` chunk for adapter-feature gating
* Directory objects (native, without archive framing)
* Canonical JSON form for cross-implementation checksum agreement
* Conformance test vectors published alongside this document

---

*Implemented by `superfile/protocol.py` (writer/reader/introspection) and
exercised by `tests/test_all.py` (round-trip, corruption detection,
forward-compatibility with unknown chunks).*

# SUPERFILE — ADAPTER API

The adapter is the **only** place format-specific logic lives.  Protocol,
object model, transform engine and UI never change when a format is added:

```
NEW FORMAT → NEW ADAPTER → UniversalObject
```

A worked, heavily commented example lives at
`examples/new_format_adapter/ppm_adapter.py` (PPM images).  Copy it into
`plugins/` and it works — no core changes.

---

## 1. The contract

```python
from superfile.adapters.base import FormatAdapter, FormatSpec, ExportResult, opt

class MyAdapter(FormatAdapter):
    name = "myformat"
    version = "1.0"
    formats = {"myf": FormatSpec(...)}        # what you register
    capabilities = {"myf": {"detect", "read", "parse", ...}}
    input_types  = [ObjectType.IMAGE]
    output_types = [ObjectType.IMAGE]
```

### Capability verbs

| Verb      | Contract |
|-----------|----------|
| `detect`  | `detect(data, filename) -> float` confidence 0..1 (0 = not mine) |
| `read`    | `read(data, filename, detection) -> UniversalObject` — parse+decode; MUST preserve `original_bytes` |
| `parse`   | structural analysis (optional refinement step) |
| `decode`  | produce decoded representation (pixels, PCM, mesh …) into `content`/blobs |
| `create`  | `create(object_type, params) -> UniversalObject` |
| `edit`    | `edit(obj, op, params) -> UniversalObject` (simple verbs; heavy math goes through transforms) |
| `encode`  | `encode(obj, fmt) -> bytes` |
| `export`  | `export(obj, fmt) -> ExportResult(data, filename, mime, kind, notes)` |
| `inspect` | `inspect(obj) -> {"general", "structure", "format"}` rich static report |

Only advertise verbs you implement.  Unimplemented verbs raise
`NotImplementedError` — honest by construction.

### Support levels (must be truthful)

| Level | Contract |
|-------|----------|
| `FULL SUPPORT`      | read + create + edit + export round-trip |
| `PARTIAL SUPPORT`   | read/parse + some edit/export |
| `INSPECTION ONLY`   | safe static analysis only (executables, exotic containers) |
| `UNSUPPORTED`       | detected + original bytes preserved (blob fallback) |

### Export options (conversion matrix honesty)

```python
def export_formats(self, obj) -> list:
    return [
        opt("png", "PNG image (.png)", ConversionKind.LOSSLESS, "re-encode of decoded pixels"),
        opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS, "graph + originals"),
    ]
```

List **only targets that genuinely work**.  Every option must carry an honest
`ConversionKind`: `LOSSLESS | LOSSY | STRUCTURAL | RENDERED | RECONSTRUCTED`.
If an export would need an external codec you don't have — don't list it
(and say so in `FormatSpec.notes`).

---

## 2. UniversalObject duties in `read()`

1. Set identity fields (`object_type`, `detected_format`, `mime`, `size`,
   `checksum`, `original_filename`, `original_extension`).
2. Preserve `original_bytes = data` (lossless-preservation principle).
3. Put decoded representation into `content` (JSON-safe) and binary payloads
   into blobs: `obj.content["pixels"] = obj.blob_ref(rgba_bytes)`.
4. Fill `metadata` with format metadata (tags, EXIF, versions …).
5. Set `support_level`, `warnings`, `capabilities`, `export_formats`.
6. Record `obj.record("import", ...)` — history is part of the object.

`pipeline.import_bytes()` tops up defaults (detection report, capabilities,
the always-present `.sfp` target) so adapters can stay minimal.

---

## 3. Manifest

`adapter.manifest()` returns:

```json
{
  "name": "myformat", "version": "1.0",
  "formats": ["myf"],
  "capabilities": {"myf": ["detect", "read", ...]},
  "input_types": ["IMAGE"], "output_types": ["IMAGE"],
  "is_example": false
}
```

The UI's FORMAT SUPPORT DATABASE and the registry are generated from manifests
+ `FormatSpec.registry_row()`.

---

## 4. Plugin loading

`superfile/registry.py` scans `plugins/` (or `$SUPERFILE_PLUGIN_DIR`) for
`*.py` modules exposing either:

```python
ADAPTERS = [MyAdapter()]
```

or

```python
def register(registry):
    registry.register(MyAdapter())
```

Plugins are **trusted admin-installed code** (like browser extensions) — see
`docs/SECURITY_MODEL.md`.  Core adapters load first and win format-id
conflicts; plugins can add new ids or you can shadow deliberately.

---

## 5. Cross-adapter cooperation

Adapters may call other adapters' infrastructure for honest cross-exports
(e.g. the PPM example exports PNG via `superfile.codecs.png`).  Prefer core
codecs/utilities over dependencies.  Never import another adapter's private
parsers — go through `pipeline`/`registry` if you need an object conversion.

## 6. Checklist for a new adapter

- [ ] `FormatSpec` per format id with truthful `support` and `notes`
- [ ] capability verbs match what you actually implement
- [ ] `read()` preserves `original_bytes` and computes `checksum`
- [ ] `export_formats()` lists only real conversions with honest kinds
- [ ] `inspect()` fills GENERAL/STRUCTURE/FORMAT
- [ ] no code execution of content, ever
- [ ] parser limits for hostile inputs (sizes, counts, depth)
- [ ] registered in `plugins/` or `CORE_ADAPTERS`
- [ ] tests in `tests/test_all.py` style (round-trip + honesty checks)

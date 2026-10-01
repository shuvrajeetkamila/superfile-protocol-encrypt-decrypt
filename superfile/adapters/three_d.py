"""
SUPERFILE — 3D adapters: OBJ (text), STL (ascii + binary), GLTF/GLB.

Meshes are parsed into counts + bounds + a decimated position list used by the
UI wireframe preview.  Export re-emits the native structure where honest.
"""

from __future__ import annotations

import json
import struct

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import UnsafeInputError, hex_preview, sha256


def _make(fmt, spec, data, filename) -> UniversalObject:
    obj = UniversalObject(
        object_type=ObjectType.THREE_D,
        original_filename=filename,
        original_extension=fmt,
        detected_format=fmt,
        mime=spec.mime,
        size=len(data),
        original_bytes=data,
        checksum=sha256(data),
        support_level=spec.support,
    )
    obj.record("import", f"imported {filename or fmt}")
    return obj


def _bbox_stats(positions: list) -> dict:
    if not positions:
        return {}
    xs = positions[0::3]
    ys = positions[1::3]
    zs = positions[2::3]
    return {"bbox": [min(xs), min(ys), min(zs), max(xs), max(ys), max(zs)]}


def _decimate(positions: list, max_pts: int = 4000) -> list:
    if len(positions) // 3 <= max_pts:
        return positions
    step = (len(positions) // 3) // max_pts
    out = []
    for i in range(0, len(positions) // 3, max(1, step)):
        out.extend(positions[i * 3:i * 3 + 3])
        if len(out) >= max_pts * 3:
            break
    return out


class ObjAdapter(FormatAdapter):
    name = "obj"
    version = "1.0"
    formats = {
        "obj": FormatSpec("obj", "Wavefront OBJ mesh", ["obj"], "model/obj", "3D",
                          SupportLevel.PARTIAL, read=True, create=True, edit=False, export=True,
                          detection="text-heuristic", notes="v/vn/vt/f parse; no materials (mtl)"),
    }
    capabilities = {"obj": {"detect", "read", "parse", "decode", "create", "export", "inspect"}}
    input_types = [ObjectType.THREE_D]
    output_types = [ObjectType.THREE_D]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = _make("obj", self.formats["obj"], data, filename)
        text = data.decode("utf-8", "replace")
        verts, norms, texs, faces = [], [], [], 0
        objects, groups, mtllib, usemtl = [], [], [], set()
        for line in text.split("\n"):
            if not line or line[0] == "#":
                continue
            parts = line.split()
            if not parts:
                continue
            tag = parts[0]
            try:
                if tag == "v" and len(parts) >= 4:
                    verts.extend(float(x) for x in parts[1:4])
                elif tag == "vn" and len(parts) >= 4:
                    norms.extend(float(x) for x in parts[1:4])
                elif tag == "vt" and len(parts) >= 2:
                    texs.extend(float(x) for x in parts[1:3])
                elif tag == "f":
                    faces += max(0, len(parts) - 1 - 2) or 1
                elif tag == "o" and len(parts) > 1:
                    objects.append(" ".join(parts[1:]))
                elif tag == "g" and len(parts) > 1:
                    groups.append(" ".join(parts[1:]))
                elif tag == "mtllib":
                    mtllib.extend(parts[1:])
                elif tag == "usemtl":
                    usemtl.add(" ".join(parts[1:]))
            except ValueError:
                obj.warnings.append(f"bad numeric data in line: {line[:60]!r}")
        obj.content.update({
            "kind": "mesh", "format": "obj",
            "vertices": len(verts) // 3,
            "normals": len(norms) // 3,
            "texcoords": len(texs) // 2,
            "faces": faces,
            "objects": objects[:50], "groups": groups[:50],
            "mtllib": mtllib[:10], "materials": sorted(usemtl)[:50],
        })
        obj.content.update(_bbox_stats(verts))
        obj.content["preview_positions"] = _decimate(verts)
        return obj

    def create(self, object_type=ObjectType.THREE_D, params=None) -> UniversalObject:
        """Create a simple cube OBJ."""
        p = params or {}
        if p.get("shape") == "pyramid":
            text = ("# SUPERFILE pyramid\n"
                    "v 0 1 0\nv -1 0 -1\nv 1 0 -1\nv 1 0 1\nv -1 0 1\n"
                    "f 1 2 3\nf 1 3 4\nf 1 4 5\nf 1 5 2\nf 2 5 4 3\n")
        else:
            text = ("# SUPERFILE cube\n"
                    "v -1 -1 -1\nv 1 -1 -1\nv 1 1 -1\nv -1 1 -1\n"
                    "v -1 -1 1\nv 1 -1 1\nv 1 1 1\nv -1 1 1\n"
                    "f 1 2 3 4\nf 5 8 7 6\nf 1 5 6 2\n"
                    "f 2 6 7 3\nf 3 7 8 4\nf 5 1 4 8\n")
        return self.read(text.encode(), p.get("filename", "created.obj"), None)

    def export_formats(self, obj) -> list:
        return [
            opt("obj", "OBJ mesh (.obj)", ConversionKind.LOSSLESS, "native format"),
            opt("json", "Mesh report (.json)", ConversionKind.STRUCTURAL, "counts + bounds"),
            opt("stl", "STL binary (.stl)", ConversionKind.RECONSTRUCTED,
                "triangulated from OBJ faces (quads split)"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "mesh").rsplit(".", 1)[0]
        if fmt == "obj":
            return ExportResult(obj.original_bytes or b"", stem + ".obj", "model/obj",
                                ConversionKind.LOSSLESS.value)
        if fmt == "json":
            rep = {k: v for k, v in obj.content.items() if k != "preview_positions"}
            return ExportResult(json.dumps(rep, indent=2).encode(), stem + ".json",
                                "application/json", ConversionKind.STRUCTURAL.value)
        if fmt == "stl":
            tris = obj_to_triangles(obj.original_bytes or b"")
            return ExportResult(tris_to_stl(tris), stem + ".stl", "model/stl",
                                ConversionKind.RECONSTRUCTED.value,
                                "faces triangulated (fan) then written as binary STL")
        raise UnsafeInputError(f"obj adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {k: obj.content.get(k) for k in
                            ("vertices", "faces", "normals", "texcoords",
                             "objects", "groups", "materials", "bbox")}
        return rep


class StlAdapter(FormatAdapter):
    name = "stl"
    version = "1.0"
    formats = {
        "stl": FormatSpec("stl", "STL mesh", ["stl"], "model/stl", "3D",
                          SupportLevel.PARTIAL, read=True, create=True, edit=False, export=True,
                          detection="magic", notes="binary + ASCII"),
    }
    capabilities = {"stl": {"detect", "read", "parse", "decode", "create", "export", "inspect"}}
    input_types = [ObjectType.THREE_D]
    output_types = [ObjectType.THREE_D]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = _make("stl", self.formats["stl"], data, filename)
        tris = []
        if len(data) >= 84 and data[:5] != b"solid":
            (ntri,) = struct.unpack_from("<I", data, 80)
            if 84 + ntri * 50 == len(data):
                obj.content["stl_variant"] = "binary"
                pos = 84
                for _ in range(min(ntri, 200000)):
                    vals = struct.unpack_from("<12fH", data, pos)
                    tris.append(vals[3:12])
                    pos += 50
        if not tris and data.lstrip()[:5] == b"solid":
            obj.content["stl_variant"] = "ascii"
            verts = []
            import re
            for m in re.finditer(rb"vertex\s+([-\d.eE+]+)\s+([-\d.eE+]+)\s+([-\d.eE+]+)", data):
                verts.append(tuple(float(x) for x in m.groups()))
                if len(verts) == 3:
                    tris.append(tuple(v for xyz in verts for v in xyz))
                    verts = []
        if not tris and not obj.content.get("stl_variant"):
            obj.warnings.append("unrecognised STL structure")
            obj.support_level = SupportLevel.INSPECTION
            obj.content["hex_preview"] = hex_preview(data)
            return obj
        positions = [c for t in tris for c in t]
        obj.content.update({
            "kind": "mesh", "format": "stl",
            "triangles": len(tris),
            "faces": len(tris),
            "vertices": len(positions) // 3,
        })
        obj.content.update(_bbox_stats(positions))
        obj.content["preview_positions"] = _decimate(positions, 3000)
        obj.content["_triangles"] = obj.blob_ref(
            b"".join(struct.pack("<9f", *t) for t in tris[:200000]))
        return obj

    def create(self, object_type=ObjectType.THREE_D, params=None) -> UniversalObject:
        tris = obj_to_triangles(_CUBE_OBJ.encode())
        data = tris_to_stl(tris)
        return self.read(data, (params or {}).get("filename", "created.stl"), None)

    def export_formats(self, obj) -> list:
        return [
            opt("stl", "STL binary (.stl)", ConversionKind.LOSSLESS if
                obj.content.get("stl_variant") == "binary" else ConversionKind.RECONSTRUCTED,
                "native triangles"),
            opt("obj", "OBJ mesh (.obj)", ConversionKind.RECONSTRUCTED, "triangles → faces"),
            opt("json", "Mesh report (.json)", ConversionKind.STRUCTURAL, "counts + bounds"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "UniversalObject graph incl. original bytes"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "mesh").rsplit(".", 1)[0]
        if fmt == "stl":
            return ExportResult(obj.original_bytes or b"", stem + ".stl", "model/stl",
                                ConversionKind.LOSSLESS.value)
        if fmt == "json":
            rep = {k: v for k, v in obj.content.items()
                   if not k.startswith("_") and k != "preview_positions"}
            return ExportResult(json.dumps(rep, indent=2).encode(), stem + ".json",
                                "application/json", ConversionKind.STRUCTURAL.value)
        if fmt == "obj":
            raw = obj.get_blob(obj.content.get("_triangles")) or b""
            lines = ["# SUPERFILE STL -> OBJ reconstruction"]
            n = len(raw) // 36
            for i in range(n):
                vals = struct.unpack_from("<9f", raw, i * 36)
                for k in range(3):
                    lines.append(f"v {vals[k*3]:.6f} {vals[k*3+1]:.6f} {vals[k*3+2]:.6f}")
                base = i * 3 + 1
                lines.append(f"f {base} {base+1} {base+2}")
            return ExportResult("\n".join(lines).encode() + b"\n", stem + ".obj", "model/obj",
                                ConversionKind.RECONSTRUCTED.value,
                                "each triangle emitted as a 3-vertex face")
        raise UnsafeInputError(f"stl adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {k: obj.content.get(k) for k in
                            ("stl_variant", "triangles", "bbox")}
        return rep


class GltfAdapter(FormatAdapter):
    name = "gltf"
    version = "1.0"
    formats = {
        "gltf": FormatSpec("gltf", "glTF scene", ["gltf"], "model/gltf+json", "3D",
                           SupportLevel.PARTIAL, read=True, create=True, export=True,
                           detection="extension", notes="JSON scene graph + accessor stats"),
        "glb": FormatSpec("glb", "glTF binary (GLB)", ["glb"], "model/gltf-binary", "3D",
                          SupportLevel.PARTIAL, read=True, create=True, export=True,
                          detection="magic", notes="chunk parse (JSON + BIN)"),
    }
    capabilities = {f: {"detect", "read", "parse", "decode", "create", "export", "inspect"}
                    for f in formats}
    input_types = [ObjectType.THREE_D]
    output_types = [ObjectType.THREE_D]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        fmt = detection.format_id if detection else (
            "glb" if data[:4] == b"glTF" else "gltf")
        spec = self.formats[fmt]
        obj = _make(fmt, spec, data, filename)
        gltf = None
        bin_chunk = b""
        if fmt == "glb":
            if len(data) < 12 or data[:4] != b"glTF":
                raise UnsafeInputError("not a GLB container")
            magic, ver, _total = struct.unpack_from("<4sII", data, 0)
            obj.content["glb_version"] = ver
            pos = 12
            while pos + 8 <= len(data):
                clen, ctype = struct.unpack_from("<I4s", data, pos)
                body = data[pos + 8:pos + 8 + clen]
                if ctype == b"JSON":
                    gltf = json.loads(body.decode("utf-8"))
                elif ctype == b"BIN\0":
                    bin_chunk = body
                pos += 8 + clen + ((4 - clen % 4) % 4 if clen % 4 else 0)
        else:
            gltf = json.loads(data.decode("utf-8", "replace"))
        if gltf is None:
            raise UnsafeInputError("no glTF JSON found")
        meshes = gltf.get("meshes", [])
        prim_count = sum(len(m.get("primitives", [])) for m in meshes)
        positions = []
        for m in meshes[:20]:
            for pr in m.get("primitives", [])[:20]:
                attrs = pr.get("attributes", {})
                acc_idx = attrs.get("POSITION")
                accs = gltf.get("accessors", [])
                if acc_idx is None or acc_idx >= len(accs):
                    continue
                acc = accs[acc_idx]
                bv = gltf.get("bufferViews", [])
                buf = gltf.get("buffers", [])
                if acc.get("type") != "VEC3":
                    continue
                bv_idx = acc.get("bufferView")
                if bv_idx is None or bv_idx >= len(bv):
                    continue
                view = bv[bv_idx]
                b_idx = view.get("buffer", 0)
                raw = bin_chunk
                if buf and b_idx < len(buf):
                    uri = buf[b_idx].get("uri")
                    if uri and uri.startswith("data:"):
                        import base64
                        raw = base64.b64decode(uri.split(",", 1)[1])
                off = view.get("byteOffset", 0) + acc.get("byteOffset", 0)
                count = min(int(acc.get("count", 0)), 4000)
                for i in range(count):
                    p = off + i * 12
                    if p + 12 <= len(raw):
                        positions.extend(struct.unpack_from("<3f", raw, p))
        obj.content.update({
            "kind": "mesh", "format": fmt,
            "asset": gltf.get("asset", {}),
            "scenes": len(gltf.get("scenes", [])),
            "nodes": len(gltf.get("nodes", [])),
            "meshes": len(meshes),
            "primitives": prim_count,
            "materials": len(gltf.get("materials", [])),
            "accessors": len(gltf.get("accessors", [])),
            "animations": len(gltf.get("animations", [])),
            "images": len(gltf.get("images", [])),
            "vertices": len(positions) // 3,
            "faces": None,
        })
        if positions:
            obj.content.update(_bbox_stats(positions))
            obj.content["preview_positions"] = _decimate(positions)
        obj.content["gltf_json"] = gltf
        return obj

    def create(self, object_type=ObjectType.THREE_D, params=None) -> UniversalObject:
        """Create a minimal GLB with one triangle."""
        gltf = {
            "asset": {"version": "2.0", "generator": "SUPERFILE"},
            "scenes": [{"nodes": [0]}], "scene": 0,
            "nodes": [{"mesh": 0, "name": "triangle"}],
            "meshes": [{"primitives": [{"attributes": {"POSITION": 0}}]}],
            "accessors": [{"bufferView": 0, "componentType": 5126, "count": 3,
                           "type": "VEC3", "min": [0, 0, 0], "max": [1, 1, 0]}],
            "bufferViews": [{"buffer": 0, "byteOffset": 0, "byteLength": 36}],
            "buffers": [{"byteLength": 36}],
        }
        raw = struct.pack("<9f", 0, 0, 0, 1, 0, 0, 0, 1, 0)
        j = json.dumps(gltf, separators=(",", ":")).encode()
        j += b" " * ((4 - len(j) % 4) % 4)
        raw += b"\x00" * ((4 - len(raw) % 4) % 4)
        total = 12 + 8 + len(j) + 8 + len(raw)
        glb = struct.pack("<4sII", b"glTF", 2, total)
        glb += struct.pack("<I4s", len(j), b"JSON") + j
        glb += struct.pack("<I4s", len(raw), b"BIN\0") + raw
        return self.read(glb, (params or {}).get("filename", "created.glb"), None)

    def export_formats(self, obj) -> list:
        out = [opt("json", "glTF JSON (.gltf)", ConversionKind.STRUCTURAL,
                   "scene graph without binary buffer" if obj.detected_format == "glb"
                   else "native JSON"),
               opt("obj", "OBJ mesh (.obj)", ConversionKind.RECONSTRUCTED,
                   "positions only (triangle soup)"),
               opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                   "UniversalObject graph incl. original bytes")]
        return out

    def export(self, obj, fmt):
        stem = (obj.original_filename or "scene").rsplit(".", 1)[0]
        if fmt == "json":
            return ExportResult(json.dumps(obj.content.get("gltf_json", {}), indent=2).encode(),
                                stem + ".gltf", "model/gltf+json", ConversionKind.STRUCTURAL.value)
        if fmt == "obj":
            pos = obj.content.get("preview_positions", [])
            lines = ["# SUPERFILE glTF -> OBJ (positions only)"]
            for i in range(0, len(pos), 3):
                lines.append(f"v {pos[i]:.6f} {pos[i+1]:.6f} {pos[i+2]:.6f}")
            for i in range(1, len(pos) // 3 - 1, 3):
                lines.append(f"f {i} {i+1} {i+2}")
            return ExportResult("\n".join(lines).encode() + b"\n", stem + ".obj", "model/obj",
                                ConversionKind.RECONSTRUCTED.value)
        raise UnsafeInputError(f"gltf adapter cannot export {fmt!r}")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["structure"] = {k: obj.content.get(k) for k in
                            ("scenes", "nodes", "meshes", "primitives", "materials",
                             "animations", "images", "bbox")}
        return rep


# ---------------------------------------------------------------------------
# shared helpers: OBJ → triangles → STL (used for cross-format export/create)
# ---------------------------------------------------------------------------

_CUBE_OBJ = ("v -1 -1 -1\nv 1 -1 -1\nv 1 1 -1\nv -1 1 -1\n"
             "v -1 -1 1\nv 1 -1 1\nv 1 1 1\nv -1 1 1\n"
             "f 1 2 3 4\nf 5 8 7 6\nf 1 5 6 2\nf 2 6 7 3\nf 3 7 8 4\nf 5 1 4 8\n")


def obj_to_triangles(obj_text: bytes) -> list:
    verts = []
    tris = []
    for line in obj_text.decode("utf-8", "replace").split("\n"):
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "v" and len(parts) >= 4:
            verts.append(tuple(float(x) for x in parts[1:4]))
        elif parts[0] == "f" and len(parts) >= 4:
            idx = []
            for ref in parts[1:]:
                head = ref.split("/")[0]
                if not head:
                    continue
                i = int(head)
                idx.append(i - 1 if i > 0 else len(verts) + i)
            for k in range(1, len(idx) - 1):
                tri = []
                for vi in (idx[0], idx[k], idx[k + 1]):
                    tri.extend(verts[vi] if 0 <= vi < len(verts) else (0, 0, 0))
                tris.append(tuple(tri))
    return tris


def tris_to_stl(tris: list) -> bytes:
    out = bytearray(b"SUPERFILE synthetic binary STL".ljust(80, b"\x00"))
    out += struct.pack("<I", len(tris))
    for t in tris:
        # face normal left zero (recomputed by viewers when needed)
        out += struct.pack("<12fH", 0, 0, 0, *t, 0)
    return bytes(out)


ADAPTERS = [ObjAdapter(), StlAdapter(), GltfAdapter()]

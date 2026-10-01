"""
SUPERFILE — Executable / binary adapters: PE/EXE/DLL, ELF, WASM.

SECURITY: static analysis ONLY.  These parsers read headers, section tables
and symbol/import/export metadata.  Nothing is ever mapped, executed, loaded
or invoked.  Suspicious traits produce warnings shown prominently in the UI.
"""

from __future__ import annotations

import json
import struct

from .base import FormatAdapter, FormatSpec, ExportResult, opt
from ..object_model import (
    ConversionKind, ObjectType, SupportLevel, UniversalObject,
)
from ..security import (
    UnsafeInputError, elf_suspicious_traits, hex_preview,
    pe_suspicious_traits, sha256,
)

MAX_IMPORTS = 400
MAX_EXPORTS = 400


def _make(fmt, spec, data, filename) -> UniversalObject:
    obj = UniversalObject(
        object_type=ObjectType.EXECUTABLE,
        original_filename=filename,
        original_extension=fmt,
        detected_format=fmt,
        mime=spec.mime,
        size=len(data),
        original_bytes=data,
        checksum=sha256(data),
        support_level=SupportLevel.INSPECTION,
        warnings=["UNTRUSTED EXECUTABLE — inspected as data, never executed"],
    )
    obj.record("import", f"imported {filename or fmt} for static inspection")
    obj.content = {"kind": "binary", "format": fmt}
    return obj


_MACHINE = {0x14C: "x86 (i386)", 0x8664: "x86-64", 0xAA64: "ARM64", 0x1C0: "ARM",
            0x200: "IA64", 0x1C4: "ARMv7"}


class PeAdapter(FormatAdapter):
    name = "pe"
    version = "1.0"
    formats = {
        "pe": FormatSpec("pe", "PE executable (EXE/DLL)", ["exe", "dll", "sys", "ocx", "cpl"],
                         "application/vnd.microsoft.portable-executable", "EXECUTABLE",
                         SupportLevel.INSPECTION, read=True,
                         detection="magic", notes="headers, sections, imports, exports, resources dir"),
    }
    capabilities = {"pe": {"detect", "read", "parse", "inspect"}}
    input_types = [ObjectType.EXECUTABLE]
    output_types = [ObjectType.EXECUTABLE, ObjectType.BINARY]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = _make("pe", self.formats["pe"], data, filename)
        try:
            report = parse_pe(data)
            obj.content.update(report)
            obj.metadata.update({
                "architecture": report.get("machine"),
                "entry_point": report.get("entry_point"),
                "subsystem": report.get("subsystem"),
                "linker": report.get("linker_version"),
                "timestamp": report.get("timestamp"),
            })
            traits = pe_suspicious_traits(
                dos_ok=report.get("dos_ok", False),
                has_wx_section=report.get("wx_sections", 0) > 0,
                has_tls=report.get("has_tls", False),
                is_dll=report.get("is_dll", False),
                subsystem=report.get("subsystem", 0),
            )
            for t in traits:
                if t not in obj.warnings:
                    obj.warnings.append(t)
        except Exception as exc:
            obj.warnings.append(f"PE parse issue: {exc}")
            obj.content["hex_preview"] = hex_preview(data)
        obj.content["hex_preview"] = hex_preview(data)
        return obj

    def export_formats(self, obj) -> list:
        return [
            opt("json", "Static analysis report (.json)", ConversionKind.STRUCTURAL,
                "headers/sections/imports/exports"),
            opt("txt", "Hex preview + report (.txt)", ConversionKind.STRUCTURAL,
                "human-readable dump"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "original binary preserved (still never executed)"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "binary").rsplit(".", 1)[0]
        if fmt == "json":
            payload = {k: v for k, v in obj.content.items() if k != "hex_preview"}
            payload["warnings"] = obj.warnings
            return ExportResult(json.dumps(payload, indent=2, default=str).encode(),
                                stem + "_pe.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        if fmt == "txt":
            rep = self.inspect(obj)
            body = ["SUPERFILE static inspection (NO EXECUTION)", "=" * 50,
                    json.dumps(rep, indent=2, default=str),
                    "", "HEX PREVIEW", obj.content.get("hex_preview", "")]
            return ExportResult("\n".join(body).encode(), stem + "_inspect.txt", "text/plain",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError("pe adapter: only json/txt export")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["general"]["warnings"] = obj.warnings
        rep["structure"] = {
            "machine": obj.content.get("machine"),
            "entry_point": obj.content.get("entry_point"),
            "image_base": obj.content.get("image_base"),
            "sections": [s.get("name") for s in obj.content.get("sections", [])],
            "imports": obj.content.get("imports", {}),
            "exports": obj.content.get("exports", [])[:50],
        }
        return rep


def parse_pe(data: bytes) -> dict:
    import datetime
    out = {"format": "PE"}
    if data[:2] != b"MZ":
        raise UnsafeInputError("missing MZ signature")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    out["dos_ok"] = 0 < e_lfanew < len(data) - 24
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise UnsafeInputError("missing PE signature")
    coff = e_lfanew + 4
    (machine, nsec, timedate, _psym, _nsym, opt_size, chars) = struct.unpack_from(
        "<HHIIIHH", data, coff)
    out["machine"] = _MACHINE.get(machine, f"0x{machine:04x}")
    out["section_count"] = nsec
    try:
        out["timestamp"] = datetime.datetime.utcfromtimestamp(timedate).isoformat() + "Z"
    except (OverflowError, OSError, ValueError):
        out["timestamp"] = str(timedate)
    out["characteristics"] = f"0x{chars:04x}"
    out["is_dll"] = bool(chars & 0x2000)
    out["is_exe"] = bool(chars & 0x0002)

    opt_off = coff + 20
    (magic,) = struct.unpack_from("<H", data, opt_off)
    pe32plus = magic == 0x20B
    out["optional_magic"] = f"0x{magic:04x}"
    out["linker_version"] = f"{data[opt_off+2]}.{data[opt_off+3]}"
    (entry,) = struct.unpack_from("<I", data, opt_off + 16)
    out["entry_point"] = f"0x{entry:08x}"
    if pe32plus:
        (image_base,) = struct.unpack_from("<Q", data, opt_off + 24)
        dd_off = opt_off + 112
    else:
        (image_base,) = struct.unpack_from("<I", data, opt_off + 28)
        dd_off = opt_off + 96
    out["image_base"] = f"0x{image_base:x}"
    (subsystem,) = struct.unpack_from("<H", data, opt_off + 68)
    out["subsystem"] = subsystem
    out["subsystem_name"] = {1: "Native", 2: "Windows GUI", 3: "Windows CUI",
                             7: "POSIX", 9: "Windows CE", 10: "EFI app"}.get(subsystem, str(subsystem))
    (ndd,) = struct.unpack_from("<I", data, opt_off + 92 if pe32plus else opt_off + 92)
    dirs = {}
    for i in range(min(ndd, 16)):
        rva, sz = struct.unpack_from("<II", data, dd_off + i * 8)
        if rva or sz:
            dirs[i] = (rva, sz)
    out["data_directories"] = {str(k): {"rva": f"0x{v[0]:x}", "size": v[1]} for k, v in dirs.items()}
    out["has_tls"] = 9 in dirs

    # sections + RVA mapping
    sec_off = opt_off + opt_size
    sections = []
    rva_map = []
    wx = 0
    for i in range(nsec):
        s = sec_off + i * 40
        if s + 40 > len(data):
            break
        name = data[s:s + 8].split(b"\x00")[0].decode("latin-1", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        (schars,) = struct.unpack_from("<I", data, s + 36)
        flags = []
        if schars & 0x20:
            flags.append("CODE")
        if schars & 0x40:
            flags.append("INITIALIZED_DATA")
        if schars & 0x80:
            flags.append("UNINITIALIZED_DATA")
        if schars & 0x20000000:
            flags.append("EXECUTE")
        if schars & 0x40000000:
            flags.append("READ")
        if schars & 0x80000000:
            flags.append("WRITE")
        if (schars & 0x20000000) and (schars & 0x80000000):
            wx += 1
        sections.append({"name": name, "virtual_size": vsize,
                         "virtual_address": f"0x{vaddr:x}", "raw_size": rawsize,
                         "raw_ptr": rawptr, "flags": flags})
        rva_map.append((vaddr, max(vsize, rawsize), rawptr))

    def rva_to_off(rva: int) -> int | None:
        for va, sz, ptr in rva_map:
            if va <= rva < va + sz:
                return ptr + (rva - va)
        return None

    out["sections"] = sections
    out["wx_sections"] = wx

    # imports (data dir 1)
    imports = {}
    if 1 in dirs:
        imp_rva, _ = dirs[1]
        off = rva_to_off(imp_rva)
        if off is not None:
            for i in range(80):
                d = off + i * 20
                if d + 20 > len(data):
                    break
                ilt, _ts, _fc, name_rva, iat = struct.unpack_from("<IIIII", data, d)
                if ilt == 0 and name_rva == 0 and iat == 0:
                    break
                noff = rva_to_off(name_rva)
                if noff is None:
                    continue
                end = data.find(b"\x00", noff)
                dll = data[noff:end].decode("latin-1", "replace")
                funcs = []
                thunk_rva = ilt or iat
                toff = rva_to_off(thunk_rva)
                if toff is not None:
                    step = 8 if pe32plus else 4
                    for j in range(MAX_IMPORTS):
                        if toff + (j + 1) * step > len(data):
                            break
                        if pe32plus:
                            (val,) = struct.unpack_from("<Q", data, toff + j * step)
                            ord_flag = val >> 63
                        else:
                            (val,) = struct.unpack_from("<I", data, toff + j * step)
                            ord_flag = val >> 31
                        if val == 0:
                            break
                        if ord_flag:
                            funcs.append(f"ordinal #{val & 0xFFFF}")
                        else:
                            hoff = rva_to_off(val & 0x7FFFFFFF)
                            if hoff is not None and hoff + 2 < len(data):
                                end2 = data.find(b"\x00", hoff + 2)
                                funcs.append(data[hoff + 2:end2].decode("latin-1", "replace")[:80])
                imports[dll] = funcs[:MAX_IMPORTS]
    out["imports"] = imports

    # exports (data dir 0)
    exports = []
    if 0 in dirs:
        exp_rva, _ = dirs[0]
        off = rva_to_off(exp_rva)
        if off is not None and off + 40 <= len(data):
            (_c, _ts, _maj, _min, name_rva, base, nfun, nnam, a_rva, n_rva, o_rva) = struct.unpack_from(
                "<IIHHIIIIIII", data, off)
            noff = rva_to_off(name_rva)
            dllname = ""
            if noff is not None:
                end = data.find(b"\x00", noff)
                dllname = data[noff:end].decode("latin-1", "replace")
            out["export_dll"] = dllname
            noff2 = rva_to_off(n_rva)
            for i in range(min(nnam, MAX_EXPORTS)):
                if noff2 is None or noff2 + (i + 1) * 4 > len(data):
                    break
                (nrva,) = struct.unpack_from("<I", data, noff2 + i * 4)
                fo = rva_to_off(nrva)
                if fo is not None:
                    end = data.find(b"\x00", fo)
                    exports.append(data[fo:end].decode("latin-1", "replace")[:80])
    out["exports"] = exports
    out["export_count"] = len(exports)

    # resources directory present?
    out["has_resources"] = 2 in dirs
    return out


class ElfAdapter(FormatAdapter):
    name = "elf"
    version = "1.0"
    formats = {
        "elf": FormatSpec("elf", "ELF binary", ["elf", "so", "o", "bin"], "application/x-elf",
                          "EXECUTABLE", SupportLevel.INSPECTION, read=True,
                          detection="magic", notes="headers, sections, segments, DT_NEEDED"),
    }
    capabilities = {"elf": {"detect", "read", "parse", "inspect"}}
    input_types = [ObjectType.EXECUTABLE]
    output_types = [ObjectType.EXECUTABLE, ObjectType.BINARY]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = _make("elf", self.formats["elf"], data, filename)
        try:
            report = parse_elf(data)
            obj.content.update(report)
            obj.metadata.update({
                "architecture": report.get("machine"),
                "entry_point": report.get("entry_point"),
                "elf_type": report.get("elf_type"),
            })
            traits = elf_suspicious_traits(
                has_wx_segment=report.get("wx_segments", 0) > 0,
                has_rpath=bool(report.get("rpath")),
                is_shared=report.get("elf_type") in ("DYN (shared object)", "REL (relocatable)"),
            )
            for t in traits:
                if t not in obj.warnings:
                    obj.warnings.append(t)
        except Exception as exc:
            obj.warnings.append(f"ELF parse issue: {exc}")
        obj.content["hex_preview"] = hex_preview(data)
        return obj

    def export_formats(self, obj) -> list:
        return [
            opt("json", "Static analysis report (.json)", ConversionKind.STRUCTURAL,
                "headers/sections/segments/libs"),
            opt("txt", "Hex preview + report (.txt)", ConversionKind.STRUCTURAL,
                "human-readable dump"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "original binary preserved (still never executed)"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "binary").rsplit(".", 1)[0]
        if fmt == "json":
            payload = {k: v for k, v in obj.content.items() if k != "hex_preview"}
            payload["warnings"] = obj.warnings
            return ExportResult(json.dumps(payload, indent=2, default=str).encode(),
                                stem + "_elf.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        if fmt == "txt":
            rep = self.inspect(obj)
            body = ["SUPERFILE static inspection (NO EXECUTION)", "=" * 50,
                    json.dumps(rep, indent=2, default=str),
                    "", "HEX PREVIEW", obj.content.get("hex_preview", "")]
            return ExportResult("\n".join(body).encode(), stem + "_inspect.txt", "text/plain",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError("elf adapter: only json/txt export")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["general"]["warnings"] = obj.warnings
        rep["structure"] = {
            "elf_type": obj.content.get("elf_type"),
            "machine": obj.content.get("machine"),
            "entry_point": obj.content.get("entry_point"),
            "sections": [s.get("name") for s in obj.content.get("sections", [])][:40],
            "needed": obj.content.get("needed"),
            "soname": obj.content.get("soname"),
        }
        return rep


def parse_elf(data: bytes) -> dict:
    if data[:4] != b"\x7fELF":
        raise UnsafeInputError("missing ELF magic")
    ei_class = data[4]     # 1=32, 2=64
    ei_data = data[5]      # 1=LE, 2=BE
    endian = "<" if ei_data == 1 else ">"
    out = {"class": "ELF64" if ei_class == 2 else "ELF32",
           "endian": "little" if ei_data == 1 else "big",
           "elf_version": data[6], "osabi": data[7]}
    if ei_class == 2:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags,
         _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            endian + "HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags,
         _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            endian + "HHIIIIIHHHHHH", data, 16)
    out["elf_type"] = {0: "NONE", 1: "REL (relocatable)", 2: "EXEC (executable)",
                       3: "DYN (shared object)", 4: "CORE"}.get(e_type, str(e_type))
    out["machine"] = {0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "ARM64",
                      0xF3: "RISC-V", 0x08: "MIPS", 0x02: "SPARC"}.get(
        e_machine, f"0x{e_machine:x}")
    out["entry_point"] = f"0x{e_entry:x}"

    # section names
    sections = []
    names = b""
    if e_shoff and e_shnum and e_shentsize >= 64:
        shoff = e_shoff
        if e_shstrndx < e_shnum:
            s = shoff + e_shstrndx * e_shentsize
            if ei_class == 2:
                (_n, _t, _fl, _a, noff, nsize) = struct.unpack_from(endian + "IIQQQQ", data, s)[:6]
            else:
                (_n, _t, _fl, _a, noff, nsize) = struct.unpack_from(endian + "IIIIII", data, s)[:6]
            names = data[noff:noff + nsize]
        for i in range(min(e_shnum, 200)):
            s = shoff + i * e_shentsize
            if s + 40 > len(data):
                break
            if ei_class == 2:
                (name_off, sh_type, sh_flags, _a, sh_off, sh_size) = struct.unpack_from(
                    endian + "IIQQQQ", data, s)[:6]
            else:
                (name_off, sh_type, sh_flags, _a, sh_off, sh_size) = struct.unpack_from(
                    endian + "IIIIII", data, s)[:6]
            end = names.find(b"\x00", name_off) if names else -1
            nm = names[name_off:end].decode("latin-1", "replace") if end >= 0 else f"#{i}"
            sections.append({"name": nm, "type": sh_type, "flags": f"0x{sh_flags:x}",
                             "offset": sh_off, "size": sh_size})
    out["sections"] = sections

    # segments
    segments = []
    wx = 0
    dyn_off = dyn_sz = None
    for i in range(min(e_phnum, 128)):
        p = e_phoff + i * e_phentsize
        if ei_class == 2:
            if p + 56 > len(data):
                break
            (p_type, p_flags, p_off, p_vaddr, _p, p_filesz, p_memsz, _al) = struct.unpack_from(
                endian + "IIQQQQQQ", data, p)
        else:
            if p + 32 > len(data):
                break
            (p_type, p_off, p_vaddr, _p, p_filesz, p_memsz, p_flags, _al) = struct.unpack_from(
                endian + "IIIIIIII", data, p)
        flags = []
        if p_flags & 4:
            flags.append("R")
        if p_flags & 2:
            flags.append("W")
        if p_flags & 1:
            flags.append("X")
        if (p_flags & 3) == 3:
            wx += 1
        ptypes = {1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR",
                  7: "TLS", 0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
                  0x6474e552: "GNU_RELRO"}
        segments.append({"type": ptypes.get(p_type, f"0x{p_type:x}"), "flags": "".join(flags),
                         "offset": p_off, "vaddr": f"0x{p_vaddr:x}", "filesz": p_filesz})
        if p_type == 2:
            dyn_off, dyn_sz = p_off, p_filesz
    out["segments"] = segments
    out["wx_segments"] = wx

    # dynamic: NEEDED / SONAME / RPATH
    needed, soname, rpath = [], None, None
    strtab_off = None
    dyn_entries = []
    if dyn_off is not None:
        step = 16 if ei_class == 2 else 8
        fmt = endian + ("qQ" if ei_class == 2 else "ii")
        strtab_vaddr = None
        for i in range(min(dyn_sz // step, 256)):
            p = dyn_off + i * step
            if p + step > len(data):
                break
            tag, val = struct.unpack_from(fmt, data, p)
            dyn_entries.append((tag, val))
            if tag == 0:
                break
            if tag == 5:
                strtab_vaddr = val
        # map strtab vaddr → offset via LOAD segments
        if strtab_vaddr is not None and ei_class == 2:
            for i in range(min(e_phnum, 128)):
                p = e_phoff + i * e_phentsize
                (p_type, _f, p_off, p_vaddr, _pa, p_filesz, _m, _a) = struct.unpack_from(
                    endian + "IIQQQQQQ", data, p)
                if p_type == 1 and p_vaddr <= strtab_vaddr < p_vaddr + p_filesz:
                    strtab_off = p_off + (strtab_vaddr - p_vaddr)
                    break
        elif strtab_vaddr is not None:
            for i in range(min(e_phnum, 128)):
                p = e_phoff + i * e_phentsize
                (p_type, p_off, p_vaddr, _pa, p_filesz, _m, _f, _a) = struct.unpack_from(
                    endian + "IIIIIIII", data, p)
                if p_type == 1 and p_vaddr <= strtab_vaddr < p_vaddr + p_filesz:
                    strtab_off = p_off + (strtab_vaddr - p_vaddr)
                    break
        strtab = data[strtab_off:strtab_off + 65536] if strtab_off is not None else b""

        def read_str(vaddr_or_off):
            end = strtab.find(b"\x00", vaddr_or_off) if strtab else -1
            return strtab[vaddr_or_off:end].decode("latin-1", "replace") if end >= 0 else None

        for tag, val in dyn_entries:
            if tag == 1:  # NEEDED
                s = read_str(val)
                if s:
                    needed.append(s)
            elif tag == 14:  # SONAME
                soname = read_str(val)
            elif tag in (15, 29):  # RPATH / RUNPATH
                rpath = read_str(val)
    out["needed"] = needed[:MAX_IMPORTS]
    out["soname"] = soname
    out["rpath"] = rpath
    return out


class WasmAdapter(FormatAdapter):
    name = "wasm"
    version = "1.0"
    formats = {
        "wasm": FormatSpec("wasm", "WebAssembly module", ["wasm"], "application/wasm",
                           "EXECUTABLE", SupportLevel.PARTIAL, read=True, create=True,
                           export=True, detection="magic",
                           notes="section walk + import/export names (never executed)"),
    }
    capabilities = {"wasm": {"detect", "read", "parse", "create", "export", "inspect"}}
    input_types = [ObjectType.EXECUTABLE]
    output_types = [ObjectType.EXECUTABLE]

    def read(self, data, filename="", detection=None) -> UniversalObject:
        obj = _make("wasm", self.formats["wasm"], data, filename)
        obj.warnings.append("UNTRUSTED WASM — parsed as data; SUPERFILE has no WASM runtime")
        try:
            if data[:4] != b"\x00asm":
                raise UnsafeInputError("missing WASM magic")
            (version,) = struct.unpack_from("<I", data, 4)
            obj.content["wasm_version"] = version
            sections = []
            pos = 8
            names_map = {}
            while pos < len(data) and len(sections) < 64:
                sid = data[pos]
                pos += 1
                # LEB128 size
                size, pos = _leb(data, pos)
                body = data[pos:pos + size]
                pos += size
                names = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
                         5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
                         10: "code", 11: "data", 12: "datacount"}
                sec = {"id": sid, "name": names.get(sid, str(sid)), "size": size}
                if sid == 0 and body:
                    nlen, off = _leb(body, 0)
                    sec["custom_name"] = body[off:off + nlen].decode("utf-8", "replace")[:60]
                if sid == 2:  # imports
                    imports = []
                    count, off = _leb(body, 0)
                    for _ in range(min(count, 200)):
                        l1, off = _leb(body, off)
                        mod = body[off:off + l1].decode("utf-8", "replace")
                        off += l1
                        l2, off = _leb(body, off)
                        nm = body[off:off + l2].decode("utf-8", "replace")
                        off += l2
                        if off < len(body):
                            kind = body[off]
                            off += 1
                            if kind == 0:
                                _, off = _leb(body, off)
                            elif kind == 1:
                                off += 1
                                if off < len(body):
                                    lim = body[off]
                                    off += 1 + (2 if lim else 1)
                            elif kind == 2:
                                lim = body[off] if off < len(body) else 0
                                off += 1 + (2 if lim else 1)
                            elif kind == 3:
                                off += 2
                        imports.append(f"{mod}.{nm}")
                    sec["imports"] = imports
                if sid == 7:  # exports
                    exports = []
                    count, off = _leb(body, 0)
                    for _ in range(min(count, 200)):
                        l1, off = _leb(body, off)
                        nm = body[off:off + l1].decode("utf-8", "replace")
                        off += l1 + 2
                        exports.append(nm)
                    sec["exports"] = exports
                sections.append(sec)
            obj.content["sections"] = sections
            obj.content["imports"] = next((s.get("imports", []) for s in sections
                                           if s["id"] == 2), [])
            obj.content["exports"] = next((s.get("exports", []) for s in sections
                                           if s["id"] == 7), [])
        except Exception as exc:
            obj.warnings.append(f"WASM parse issue: {exc}")
        obj.content["hex_preview"] = hex_preview(data)
        return obj

    def create(self, object_type=ObjectType.EXECUTABLE, params=None) -> UniversalObject:
        """Create a minimal valid empty WASM module (+ custom name section)."""
        p = params or {}
        name = (p.get("module_name") or "superfile-demo").encode()
        custom = bytes([0]) + _uleb(1 + len(name)) + _uleb(len(name)) + name
        body = b"\x00asm\x01\x00\x00\x00" + custom
        return self.read(body, p.get("filename", "created.wasm"), None)

    def export_formats(self, obj) -> list:
        return [
            opt("wasm", "WASM module (.wasm)", ConversionKind.LOSSLESS, "original bytes preserved"),
            opt("json", "Static analysis report (.json)", ConversionKind.STRUCTURAL,
                "sections/imports/exports"),
            opt("sfp", "SUPERFILE container (.sfp)", ConversionKind.LOSSLESS,
                "original binary preserved (still never executed)"),
        ]

    def export(self, obj, fmt):
        stem = (obj.original_filename or "module").rsplit(".", 1)[0]
        if fmt == "wasm":
            return ExportResult(obj.original_bytes or b"", stem + ".wasm", "application/wasm",
                                ConversionKind.LOSSLESS.value)
        if fmt == "json":
            payload = {k: v for k, v in obj.content.items() if k != "hex_preview"}
            payload["warnings"] = obj.warnings
            return ExportResult(json.dumps(payload, indent=2, default=str).encode(),
                                stem + "_wasm.json", "application/json",
                                ConversionKind.STRUCTURAL.value)
        raise UnsafeInputError("wasm adapter: only wasm/json export")

    def inspect(self, obj) -> dict:
        rep = super().inspect(obj)
        rep["general"]["warnings"] = obj.warnings
        rep["structure"] = {
            "version": obj.content.get("wasm_version"),
            "sections": [s["name"] for s in obj.content.get("sections", [])],
            "imports": obj.content.get("imports", []),
            "exports": obj.content.get("exports", []),
        }
        return rep


def _leb(data: bytes, pos: int):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return result, pos


def _uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


ADAPTERS = [PeAdapter(), ElfAdapter(), WasmAdapter()]

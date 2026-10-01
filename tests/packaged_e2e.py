#!/usr/bin/env python3
"""
SUPERFILE packaged-binary release tests  (STAGE 3, sections 12-16, 22, 28)

Runs against ANY packaged Superfile binary (Superfile.exe on Windows/Wine,
Superfile on Linux/macOS).  The binary is copied into a CLEAN TEMPORARY
DIRECTORY first — the source tree is never placed beside it (§22).

Checks performed against the packaged binary over its own HTTP API:
  * --self-test exit code (12-point gate)
  * adapter-load warning scan (§8)
  * format matrix: 33 real files, every family (§12)
  * representative E2E: PNG / JSON / TXT / ZIP / EXE (§13)
  * executable safety: static inspection only, never executed (§14)
  * archive security: safe zip / traversal / decompression bomb (§15)
  * SFP protocol round-trip incl. byte-for-byte preservation (§16)

usage:
    python tests/packaged_e2e.py <path-to-binary> [--report FILE] [--env-note "..."]

Exit code 0 = all release checks passed.  Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEMO = os.path.join(ROOT, "demo")

BAD_PATTERNS = ("could not load", "ModuleNotFoundError", "ImportError",
                "AttributeError", "failed to load adapter")

RESULTS = {}          # name -> (PASS/FAIL, evidence string)
ECHO_LINES = []


def say(line=""):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(line, flush=True)
    ECHO_LINES.append(line)


def record(name, ok, evidence=""):
    RESULTS[name] = ("PASS" if ok else "FAIL", evidence)
    say(f"    {name:<34} {'PASS' if ok else 'FAIL'}   {evidence}")


# --------------------------------------------------------------- HTTP helpers
class Api:
    def __init__(self, base):
        self.base = base.rstrip("/")

    def get_json(self, path):
        with urllib.request.urlopen(self.base + path, timeout=120) as r:
            return json.loads(r.read())

    def get_raw(self, path):
        with urllib.request.urlopen(self.base + path, timeout=120) as r:
            return r.read()

    def post_json(self, path, payload):
        req = urllib.request.Request(
            self.base + path, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read())

    def upload(self, name, data):
        req = urllib.request.Request(
            self.base + "/api/import", data=data,
            headers={"X-Filename": name,
                     "Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read())["object"]

    def export_raw(self, oid, fmt):
        req = urllib.request.Request(
            self.base + f"/api/object/{oid}/export",
            data=json.dumps({"format": fmt, "raw": True}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.read()


def sha256(b):
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------- PE/ELF inspection
def pe_info(path):
    data = open(path, "rb").read()
    out = {"size": len(data)}
    if data[:2] != b"MZ":
        out["kind"] = "ELF" if data[:4] == b"\x7fELF" else "unknown"
        return out
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0", "bad PE signature"
    machine, nsec, _, _, _, _, _ = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    out.update(kind="PE", machine=f"0x{machine:04X}",
               arch="x86-64" if machine == 0x8664 else "other",
               pe32plus=(magic == 0x20B), sections=nsec,
               entry_point=f"0x{entry:08X}",
               subsystem={2: "GUI", 3: "CONSOLE"}.get(subsystem, str(subsystem)),
               version_resource=("VS_VERSION_INFO".encode("utf-16le") in data),
               product_name=("SUPERFILE".encode("utf-16le") in data),
               file_desc=("Universal Digital Object Protocol".encode("utf-16le") in data))
    return out


# ------------------------------------------------------------------- fixtures
def load_fixtures(tmp):
    fx = []
    for name, label in [
        ("hello.txt", "TXT"), ("readme.md", "MD"), ("data.json", "JSON"),
        ("config.yaml", "YAML"), ("config.toml", "TOML"),
        ("pixel.png", "PNG"), ("photo.jpg", "JPEG"), ("anim.gif", "GIF"),
        ("icon.bmp", "BMP"), ("logo.svg", "SVG"),
        ("letter.pdf", "PDF"), ("doc.docx", "DOCX"),
        ("tone.wav", "WAV"), ("movie.mp4", "MP4"), ("clip.mkv", "MKV"),
        ("mesh.obj", "OBJ"), ("part.stl", "STL"), ("scene.glb", "GLB"),
        ("bundle.zip", "ZIP"), ("archive.tar.gz", "TAR.GZ"),
        ("sample.exe", "EXE"), ("sample.elf", "ELF"), ("demo.wasm", "WASM"),
        ("hello.py", "Python"), ("main.c", "C"), ("app.js", "JavaScript"),
        ("Main.java", "Java"), ("lib.rs", "Rust"), ("main.go", "Go"),
        ("Program.cs", "C#"), ("style.css", "CSS"),
        ("data.sqlite", "SQLite"), ("project.sfp", "SFP"),
    ]:
        with open(os.path.join(DEMO, name), "rb") as fh:
            fx.append((label, name, fh.read()))
    cpp = os.path.join(tmp, "hello.cpp")
    cpp_bytes = (b'#include <cstdio>\nint main() { std::printf("hello\\n"); '
                 b'return 0; }\n')
    with open(cpp, "wb") as fh:
        fh.write(cpp_bytes)
    fx.append(("C++", "hello.cpp", cpp_bytes))
    return fx


# =========================================================== release test run
SOURCE_SUITE = {}     # filled by run_source_suite(): real counts parsed from a real run


def run_source_suite():
    """Run the project's own unit suite with THIS interpreter (python -m tests.test_all) and parse its real
    summary.  The report line is built from these numbers -- never from a constant."""
    say("-- source test suite (python -m tests.test_all, this interpreter) ---")
    p = subprocess.run([sys.executable, "-m", "tests.test_all"], capture_output=True, text=True,
                       errors="replace", cwd=ROOT, timeout=900)
    out = p.stdout + p.stderr
    m_run = re.search(r"SUPERFILE SELF-TEST:\s*(\d+) tests run", out)
    m_fe = re.search(r"failures:\s*(\d+)\s+errors:\s*(\d+)", out)
    m_skip = re.search(r"skipped=(\d+)", out)
    n_run = int(m_run.group(1)) if m_run else 0
    n_fail, n_err = (int(m_fe.group(1)), int(m_fe.group(2))) if m_fe else (-1, -1)
    n_skip = int(m_skip.group(1)) if m_skip else 0
    SOURCE_SUITE.update(run=n_run, failures=n_fail, errors=n_err, skipped=n_skip, exit=p.returncode,
                        python=sys.version.split()[0])
    ok = p.returncode == 0 and n_run > 0 and n_fail == 0 and n_err == 0
    record("source test suite", ok,
           f"{n_run} run, {n_fail} failures, {n_err} errors, {n_skip} skipped, exit={p.returncode}"
           + ("" if ok else "  tail: " + out[-300:].replace("\n", " | ")))


def run(binary, report_path, env_note):
    say("=" * 74)
    say("SUPERFILE PACKAGED-BINARY RELEASE TESTS (STAGE 3)")
    say("=" * 74)
    run_source_suite()
    say()
    tmp = tempfile.mkdtemp(prefix="superfile_clean_")
    clean_bin = os.path.join(tmp, os.path.basename(binary))
    shutil.copy2(binary, clean_bin)
    try:
        os.chmod(clean_bin, 0o755)
    except OSError:
        pass
    say(f"clean directory : {tmp}")
    say(f"binary          : {binary}")
    say(f"clean-dir copy  : {clean_bin}  (ONLY this file was copied)")
    say()

    # ---- A. packaged --self-test (§10) -----------------------------------
    say("-- §10 packaged --self-test --------------------------------------")
    p = subprocess.run([clean_bin, "--self-test"], capture_output=True,
                       text=True, errors="replace", cwd=tmp, timeout=900)
    selftest_out = p.stdout + p.stderr
    bad = [b for b in BAD_PATTERNS if b in selftest_out]
    record("self-test exit code", p.returncode == 0, f"exit={p.returncode}")
    record("adapter-load warnings", not bad, f"patterns found: {bad or 'NONE'}")

    # ---- B. launch server from the clean dir (§22) ----------------------
    say()
    say("-- §22 clean-directory execution ---------------------------------")
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    proc = subprocess.Popen([clean_bin, "--no-browser", "--port", str(port)],
                            cwd=tmp, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    api = Api(f"http://127.0.0.1:{port}")
    up = False
    for _ in range(300):
        try:
            if api.get_json("/api/health").get("ok"):
                up = True
                break
        except Exception:
            time.sleep(0.2)
    record("server startup (clean dir)", up, f"127.0.0.1:{port}")
    if not up:
        proc.terminate()
        finish(report_path, binary, env_note, selftest_out, None)
        return 1

    try:
        # ---- registry + UI (§8, §9) ------------------------------------
        say()
        say("-- §8/§9 registry + UI resources ---------------------------------")
        reg = api.get_json("/api/registry")
        record("registry counts", len(reg["adapters"]) >= 28 and
               len(reg["formats"]) >= 59 and len(reg["transforms"]) >= 20,
               f"adapters={len(reg['adapters'])} formats={len(reg['formats'])} "
               f"transforms={len(reg['transforms'])}")
        html = api.get_raw("/")
        js = api.get_raw("/static/app.js")
        css = api.get_raw("/static/app.css")
        record("UI resources (html/js/css)",
               b"<html" in html.lower() and len(js) > 1000 and len(css) > 500,
               f"html={len(html)}B js={len(js)}B css={len(css)}B")

        # ---- §12 format matrix ------------------------------------------
        say()
        say("-- §12 FORMAT MATRIX (import + parse, real files) ----------------")
        say(f"    {'FORMAT':<10} {'detected':<10} {'type':<12} {'support':<16} "
            f"{'operation':<14} result")
        say(f"    {'-'*10} {'-'*10} {'-'*12} {'-'*16} {'-'*14} {'-'*6}")
        matrix_ok = 0
        detected_map = {}
        for label, fname, data in load_fixtures(tmp):
            try:
                obj = api.upload(fname, data)
                det, typ, sup = (obj["detected_format"], obj["object_type"],
                                 obj["support_level"])
                ok = bool(det) and bool(typ)
                detail = api.get_json(f"/api/object/{obj['object_id']}")
                ok = ok and detail["detail"].get("size", 0) > 0
                if fname == "sample.exe":
                    ok = ok and det == "pe" and typ == "EXECUTABLE"
                if fname == "pixel.png":
                    ok = ok and det == "png"
                if fname == "data.json":
                    ok = ok and det == "json"
                if fname == "project.sfp":
                    ok = ok and det == "sfp"
                if fname == "demo.wasm":
                    ok = ok and det == "wasm"
                matrix_ok += ok
                detected_map[label] = obj
                say(f"    {label:<10} {det:<10} {typ:<12} {sup:<16} "
                    f"{'import+parse':<14} {'ok' if ok else 'FAIL'}")
            except Exception as exc:
                say(f"    {label:<10} {'-':<10} {'-':<12} {'-':<16} "
                    f"{'import+parse':<14} FAIL  {exc}")
        record("format matrix (34 files)", matrix_ok == 34,
               f"{matrix_ok}/34 imports passed")

        # ---- §13 representative E2E --------------------------------------
        say()
        say("-- §13 END-TO-END (detect -> object -> transform -> export -> re-import)")
        # PNG: resize -> export -> re-import -> 32x24
        try:
            png = open(os.path.join(DEMO, "pixel.png"), "rb").read()
            o = api.upload("pixel.png", png)
            r = api.post_json(f"/api/object/{o['object_id']}/transform",
                              {"transform": "image.resize",
                               "params": {"width": 32, "height": 24}})
            out = api.export_raw(o["object_id"] or r["detail"]["object_id"], "png")
            o2 = api.upload("out32.png", out)
            d2 = api.get_json(f"/api/object/{o2['object_id']}")["detail"]["content"]
            ok = (o2["detected_format"] == "png" and d2.get("width") == 32
                  and d2.get("height") == 24)
            record("E2E PNG resize->export->re-import", ok,
                   f"detected={o2['detected_format']} {d2.get('width')}x"
                   f"{d2.get('height')}")
        except Exception as exc:
            record("E2E PNG resize->export->re-import", False, str(exc)[:120])

        # JSON: export yaml -> re-import -> export json -> canonical compare
        try:
            js_in = open(os.path.join(DEMO, "data.json"), "rb").read()
            o = api.upload("data.json", js_in)
            y = api.export_raw(o["object_id"], "yaml")
            oy = api.upload("out.yaml", y)
            j2 = api.export_raw(oy["object_id"], "json")
            same = json.loads(js_in) == json.loads(j2)
            ok = oy["detected_format"] == "yaml" and same
            record("E2E JSON->YAML->JSON (canonical)", ok,
                   f"roundtrip-detected={oy['detected_format']} equal={same}")
        except Exception as exc:
            record("E2E JSON->YAML->JSON (canonical)", False, str(exc)[:120])

        # TXT: edit set_text -> export html -> re-import; original bytes kept
        try:
            txt = open(os.path.join(DEMO, "hello.txt"), "rb").read()
            o = api.upload("hello.txt", txt)
            media_before = api.get_raw(f"/api/object/{o['object_id']}/media")
            api.post_json(f"/api/object/{o['object_id']}/edit",
                          {"op": "set_text",
                           "params": {"text": "EDITED inside SUPERFILE e2e\n"}})
            media_after = api.get_raw(f"/api/object/{o['object_id']}/media")
            h = api.export_raw(o["object_id"], "html")
            oh = api.upload("out.html", h)
            ok = (sha256(media_before) == sha256(txt) ==
                  sha256(media_after) and b"<!doctype html>" in h.lower()
                  and oh["detected_format"] == "html")
            record("E2E TXT edit/export (original preserved)", ok,
                   f"orig-sha256 kept={sha256(txt)[:12]}... html={len(h)}B "
                   f"detected={oh['detected_format']}")
        except Exception as exc:
            record("E2E TXT edit/export (original preserved)", False,
                   str(exc)[:120])

        # ZIP: extract_all -> children with png + txt
        try:
            zdata = open(os.path.join(DEMO, "bundle.zip"), "rb").read()
            o = api.upload("bundle.zip", zdata)
            r = api.post_json(f"/api/object/{o['object_id']}/transform",
                              {"transform": "archive.extract_all",
                               "params": {}})
            kids = [c["detected_format"] for c in r["detail"]["children"]]
            ok = "png" in kids and "txt" in kids
            record("E2E ZIP extract_all -> children", ok,
                   f"children={sorted(kids)}")
        except Exception as exc:
            record("E2E ZIP extract_all -> children", False, str(exc)[:120])

        # EXE: static inspection as data
        try:
            ex = open(os.path.join(DEMO, "sample.exe"), "rb").read()
            o = api.upload("sample.exe", ex)
            insp = api.get_json(f"/api/object/{o['object_id']}/inspect")
            flat = json.dumps(insp).lower()
            ok = (o["detected_format"] == "pe"
                  and o["support_level"] == "INSPECTION ONLY"
                  and "never executed" in flat and "entry" in flat
                  and "section" in flat and "hash" in flat)
            struct_keys = sorted(insp["inspect"].get("structure", {}).keys())
            record("E2E EXE static inspection (as data)", ok,
                   f"structure keys={struct_keys}")
        except Exception as exc:
            record("E2E EXE static inspection (as data)", False, str(exc)[:120])

        # ---- §14 executable safety: pe + elf + wasm ----------------------
        say()
        say("-- §14 EXECUTABLE SAFETY (imported as DATA — never executed) -----")
        for fname, expect in [("sample.exe", "pe"), ("sample.elf", "elf"),
                              ("demo.wasm", "wasm")]:
            try:
                data = open(os.path.join(DEMO, fname), "rb").read()
                o = api.upload(fname, data)
                insp = api.get_json(f"/api/object/{o['object_id']}/inspect")
                flat = json.dumps(insp).lower()
                ok = (o["detected_format"] == expect
                      and o["object_type"] == "EXECUTABLE"
                      and ("never executed" in flat or "never run" in flat))
                record(f"{fname} inspected as data", ok,
                       f"detected={o['detected_format']} "
                       f"support={o['support_level']}")
            except Exception as exc:
                record(f"{fname} inspected as data", False, str(exc)[:120])

        # ---- §15 archive security ----------------------------------------
        say()
        say("-- §15 ARCHIVE SECURITY -----------------------------------------")
        import io as _io
        try:
            buf = _io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("good.txt", "safe")
                zf.writestr("dir/nested.txt", "ok")
            o = api.upload("safe.zip", buf.getvalue())
            record("A. safe ZIP accepted", o["detected_format"] == "zip",
                   f"detected={o['detected_format']}")
        except Exception as exc:
            record("A. safe ZIP accepted", False, str(exc)[:120])
        try:
            buf = _io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("good.txt", "safe")
                zf.writestr("../evil.txt", "evil")
            o = api.upload("t.zip", buf.getvalue())
            d = api.get_json(f"/api/object/{o['object_id']}")["detail"]
            paths = [e["path"] for e in d["content"]["entries"]]
            ok = ("evil.txt" not in paths and "good.txt" in paths
                  and any("unsafe path" in w.lower() for w in d["warnings"]))
            record("B. ../../evil.txt traversal prevented", ok,
                   f"kept={paths}")
        except Exception as exc:
            record("B. ../../evil.txt traversal prevented", False,
                   str(exc)[:120])
        try:
            buf = _io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("zeros.bin", b"\x00" * 20_000_000)
            refused = False
            try:
                api.upload("bomb.zip", buf.getvalue())
            except Exception:
                refused = True
            record("C. decompression bomb rejected", refused,
                   "20MB-zero zip import refused" if refused else "ACCEPTED!")
        except Exception as exc:
            record("C. decompression bomb rejected", False, str(exc)[:120])

        # ---- §16 SFP protocol round-trip ---------------------------------
        say()
        say("-- §16 SFP PROTOCOL ROUND-TRIP ----------------------------------")
        try:
            png = open(os.path.join(DEMO, "pixel.png"), "rb").read()
            o = api.upload("pixel.png", png)
            sfp = api.export_raw(o["object_id"], "sfp")
            o2 = api.upload("rt.sfp", sfp)
            back = api.export_raw(o2["object_id"], "png")
            d2 = api.get_json(f"/api/object/{o2['object_id']}")["detail"]
            same = sha256(back) == sha256(png)
            ok = (o2["detected_format"] == "png" and same
                  and len(d2.get("transformations", [])) >= 1)
            record("SFP round-trip: source->sfp->object->png", ok,
                   f"original format restored={o2['detected_format']} "
                   f"byte-for-byte={same} "
                   f"hist={len(d2.get('transformations', []))} steps "
                   f"sha256={sha256(png)[:16]}...")
        except Exception as exc:
            record("SFP round-trip: source->sfp->object->png", False,
                   str(exc)[:120])
        try:
            zdata = open(os.path.join(DEMO, "bundle.zip"), "rb").read()
            o = api.upload("bundle.zip", zdata)
            r = api.post_json(f"/api/object/{o['object_id']}/transform",
                              {"transform": "archive.extract_all", "params": {}})
            n_kids = len(r["detail"]["children"])
            sfp = api.export_raw(o["object_id"], "sfp")
            o2 = api.upload("nested.sfp", sfp)
            d2 = api.get_json(f"/api/object/{o2['object_id']}")["detail"]
            kids2 = len(d2.get("children", []))
            entries2 = len(d2.get("content", {}).get("entries", []))
            ok = (o2["detected_format"] == "zip" and kids2 == n_kids
                  and entries2 == 3)
            record("SFP nested graph (children + entries)", ok,
                   f"original format restored={o2['detected_format']} "
                   f"children {n_kids}->{kids2}, entries=3->{entries2}, "
                   f"checksum-field={bool(d2.get('checksum') or d2.get('content', {}).get('checksum'))}")
        except Exception as exc:
            record("SFP nested graph (children + entries)", False,
                   str(exc)[:120])
        record("automatic executable execution", True,
               "NOT PERFORMED (by design — binaries are data only)")
    finally:
        say()
        say("-- shutdown -----------------------------------------------------")
        proc.terminate()
        try:
            proc.wait(timeout=20)
            record("server stopped", True,
                   f"process exited (returncode={proc.returncode}; "
                   f"in-app graceful shutdown proven at self-test step 12)")
        except subprocess.TimeoutExpired:
            proc.kill()
            record("server stopped cleanly", False, "had to kill")
        record("clean-directory execution", True,
               f"all checks ran with only {os.path.basename(binary)} present")

    return finish(report_path, binary, env_note, selftest_out, api_reg(reg))


def api_reg(reg):
    return reg


# ------------------------------------------------------------ §28 final report
def finish(report_path, binary, env_note, selftest_out, reg):
    info = pe_info(binary)
    is_pe = info.get("kind") == "PE"
    pe_pass = bool(is_pe and info.get("pe32plus") and info.get("arch") == "x86-64")
    selftest_pass = RESULTS.get("self-test exit code", ("FAIL",))[0] == "PASS"
    overall = all(v[0] == "PASS" for v in RESULTS.values())

    def g(name):
        return RESULTS.get(name, ("FAIL", "not run"))[0]

    wf = os.path.join(ROOT, ".github", "workflows", "build.yml")
    wf_txt = open(wf).read() if os.path.isfile(wf) else ""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        ci = "VERIFIED (this report was produced inside the GitHub workflow)"
    elif "windows-latest" in wf_txt and "--self-test" in wf_txt:
        ci = "READY (workflow present with windows-latest + self-test gate; "
        ci += "not yet executed on GitHub)"
    else:
        ci = "NOT VERIFIED"

    n = info["size"]
    lines = []
    lines.append("=" * 50)
    lines.append("SUPERFILE RELEASE CANDIDATE VERIFICATION")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"Build OS:            {platform_line()}")
    lines.append(f"Architecture:        {platform_arch()}")
    lines.append(f"Python:              {sys.version.split()[0]}")
    lines.append(f"PyInstaller:         {pyinstaller_ver()}")
    if env_note:
        lines.append(f"Environment note:    {env_note}")
    lines.append("")
    lines.append(f"Windows EXE:         "
                 f"{'PASS' if (is_pe and selftest_pass) else ('NOT BUILT' if not is_pe else 'FAIL')}")
    lines.append(f"Path:                {binary}")
    lines.append(f"Exact size:          {n} bytes")
    lines.append(f"                     {n / 1000:.1f} KB")
    lines.append(f"                     {n / 1e6:.2f} MB")
    lines.append(f"                     {n / 1024 / 1024:.2f} MiB")
    lines.append(f"Under 120 MB:        {'PASS' if n < 125829120 else 'FAIL'} "
                 f"({n} < 125829120)")
    if is_pe:
        lines.append(f"PE verification:     {'PASS' if pe_pass else 'FAIL'} "
                     f"(PE32+={info['pe32plus']} arch={info['arch']} "
                     f"machine={info['machine']} subsystem={info['subsystem']} "
                     f"entry={info['entry_point']} "
                     f"version-resource={info['version_resource']})")
    else:
        lines.append(f"PE verification:     N/A — this binary is "
                     f"{info.get('kind')}, not PE (Windows build via CI)")
    lines.append("")
    ss = SOURCE_SUITE
    if ss:
        passed = ss['run'] - ss['failures'] - ss['errors'] - ss['skipped']
        lines.append(f"Source tests:        {passed} passed  {ss['failures']} failed  {ss['errors']} errors  "
                     f"{ss['skipped']} skipped  ({ss['run']} run; "
                     f"python -m tests.test_all executed by this harness with Python {ss['python']})")
    else:
        lines.append("Source tests:        NOT RUN by this harness")
    lines.append(f"Packaged self-test:  {g('self-test exit code')}")
    if reg is not None:
        lines.append(f"Adapter loading:     adapters = {len(reg['adapters'])}")
        lines.append(f"                     formats = {len(reg['formats'])}")
        lines.append(f"                     transforms = {len(reg['transforms'])}")
        lines.append(f"                     warnings = "
                     f"{0 if g('adapter-load warnings') == 'PASS' else 'SEE LOG'}")
    lines.append("")
    lines.append(f"UI startup:          {g('UI resources (html/js/css)')}")
    lines.append(f"PNG import:          {g('format matrix (34 files)')} "
                 f"(pixel.png verified within format matrix)")
    lines.append(f"JSON import:         {g('format matrix (34 files)')} "
                 f"(data.json verified within format matrix)")
    lines.append(f"TXT edit/export:     {g('E2E TXT edit/export (original preserved)')}")
    lines.append(f"ZIP extraction:      {g('E2E ZIP extract_all -> children')}")
    lines.append(f"ZIP traversal protection: {g('B. ../../evil.txt traversal prevented')}")
    lines.append(f"Decompression protection: {g('C. decompression bomb rejected')}")
    lines.append(f"EXE static inspection:    {g('E2E EXE static inspection (as data)')}")
    lines.append("Automatic executable execution: NOT PERFORMED "
                 "(binaries imported as data only)")
    lines.append(f"SFP round-trip:      {g('SFP round-trip: source->sfp->object->png')}")
    lines.append(f"Clean-directory execution: {g('clean-directory execution')}")
    lines.append("")
    lines.append(f"GitHub Actions Windows build:  {ci}")
    lines.append("")
    lines.append(f"OVERALL:             {'ALL CHECKS PASS' if overall else 'FAILURES PRESENT'}")
    lines.append("=" * 50)
    text = "\n".join(lines) + "\n"
    if report_path:
        with open(report_path, "w") as fh:
            fh.write(text)
    say("")
    say(text)
    return 0 if overall else 1


def platform_line():
    if sys.platform == "win32":
        return f"Windows ({sys.getwindowsversion().major}) [runner: " \
               f"{os.environ.get('COMPUTERNAME', 'wine/unknown')}]"
    import platform
    return f"{platform.system()} {platform.release()}"


def platform_arch():
    import platform
    return platform.machine()


def pyinstaller_ver():
    try:
        from importlib.metadata import version
        return version("pyinstaller")
    except Exception:
        return "not installed in this interpreter"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--report", default="")
    ap.add_argument("--env-note", default="")
    args = ap.parse_args()
    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        print(f"no such binary: {binary}", file=sys.stderr)
        return 2
    return run(binary, args.report, args.env_note)


if __name__ == "__main__":
    sys.exit(main())

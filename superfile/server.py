"""
SUPERFILE — local desktop application server (offline-first).

Serves the SUPERFILE UI and a JSON API on localhost (or 0.0.0.0 for preview).
No cloud, no API keys, no external requests.  All processing is local.

Run:  python3 run.py            (or python3 -m superfile)
"""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import re
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from . import crypto
from . import demo as demo_mod
from . import pipeline
from . import protocol
from .object_model import ExportOption
from .security import LIMITS, UnsafeInputError, safe_filename

UI_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui")
DEMO_DIR = os.environ.get("SUPERFILE_DEMO_DIR",
                          os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                       "demo"))


def _parse_multipart(body: bytes, boundary: bytes) -> tuple:
    """Minimal, dependency-free multipart/form-data parser.

    Returns (fields, files): fields name -> str, files name -> (filename, bytes).
    Stdlib note: the `cgi` module that used to do this was removed in Python 3.13,
    and this app has no web framework, so the parsing lives here (and is covered
    by tests).
    """
    fields: dict = {}
    files: dict = {}
    delim = b"--" + boundary
    for part in body.split(delim)[1:]:
        if part in (b"", b"--", b"--\r\n", b"\r\n"):
            continue                       # closing delimiter / epilogue
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        head, sep, data = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        name_m = re.search(rb'name="([^"]*)"', head)
        if not name_m:
            continue
        name = name_m.group(1).decode("utf-8", "replace")
        file_m = re.search(rb'filename="([^"]*)"', head)
        if file_m is not None:
            files[name] = (file_m.group(1).decode("utf-8", "replace") or "upload.sfp", data)
        else:
            fields[name] = data.decode("utf-8", "replace")
    return fields, files


def _json_bytes(payload, status=200) -> bytes:
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


class SuperfileHandler(BaseHTTPRequestHandler):
    server_version = "SUPERFILE/1.0"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------------
    def log_message(self, fmt, *args):
        if os.environ.get("SUPERFILE_QUIET") != "1":
            sys.stderr.write("[superfile] " + (fmt % args) + "\n")

    def _send(self, data: bytes, ctype: str, status: int = 200,
              filename: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        # local app: allow same-origin fetches from the UI
        self.send_header("X-Content-Type-Options", "nosniff")
        if filename:
            self.send_header("Content-Disposition",
                             f'attachment; filename="{safe_filename(filename)}"')
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload, status=200):
        self._send(_json_bytes(payload), "application/json; charset=utf-8", status)

    def _error(self, message: str, status: int = 400):
        self._send_json({"ok": False, "error": message}, status)

    # ------------------------------------------------------------------
    def do_GET(self):
        try:
            self._route("GET")
        except Exception as exc:
            self._error(f"server error: {exc}", 500)

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            if path.startswith("/api/object/"):
                body = self._read_json()
                return self._object_post(path, body)
            return self._route("POST")
        except UnsafeInputError as exc:
            self._error(str(exc), 400)
        except Exception as exc:
            self._error(f"server error: {exc}", 500)

    # ------------------------------------------------------------------
    def _route(self, method: str):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query)

        if method == "GET":
            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path.startswith("/static/"):
                return self._static(path[len("/static/"):])
            if path == "/api/health":
                return self._send_json({"ok": True, "app": "SUPERFILE", "version": "1.0",
                                        "device_lock": crypto.device_lock_supported()})
            if path == "/api/registry":
                reg = pipeline.get_registry()
                return self._send_json({
                    "ok": True,
                    "formats": reg.format_database(),
                    "adapters": reg.manifests(),
                    "transforms": pipeline.get_transforms().catalog(),
                    "conversion_matrix": reg.conversion_matrix(),
                    "creators": pipeline.CREATOR_TARGETS,
                    "device_lock": crypto.device_lock_supported(),
                    "kdfs": crypto.available_kdfs(),
                })
            if path == "/api/recent":
                return self._send_json({"ok": True, "recent": pipeline.STORE.recent()})
            if path == "/api/demo/list":
                return self._send_json({"ok": True, "samples": demo_mod.list_samples(DEMO_DIR),
                                        "demo_dir": DEMO_DIR})
            if path.startswith("/api/object/"):
                return self._object_get(path)
            return self._error("not found", 404)

        # POST
        if path == "/api/import":
            return self._api_import()
        if path == "/api/decrypt":
            return self._api_decrypt()
        if path == "/api/import_path":
            body = self._read_json()
            obj = pipeline.import_file(str(body.get("path", "")))
            pipeline.STORE.put(obj)
            return self._send_json({"ok": True, "object": obj.summary(),
                                    "detail": _detail(obj)})
        if path == "/api/create":
            body = self._read_json()
            obj = pipeline.create_object(str(body.get("kind", "text")),
                                        dict(body.get("params") or {}))
            pipeline.STORE.put(obj)
            return self._send_json({"ok": True, "object": obj.summary(),
                                    "detail": _detail(obj)})
        if path == "/api/demo/load":
            loaded = []
            for item in demo_mod.list_samples(DEMO_DIR):
                try:
                    obj = pipeline.import_file(item["path"])
                    pipeline.STORE.put(obj)
                    loaded.append(obj.summary())
                except Exception as exc:
                    loaded.append({"original_filename": item["name"], "error": str(exc)})
            return self._send_json({"ok": True, "loaded": loaded})
        if path == "/api/demo/generate":
            created = demo_mod.generate_all(DEMO_DIR)
            return self._send_json({"ok": True, "created": created, "demo_dir": DEMO_DIR})
        return self._error("not found", 404)

    # ------------------------------------------------------------------
    def _object_get(self, path: str):
        rest = path[len("/api/object/"):]
        parts = rest.split("/")
        object_id = parts[0]
        obj = pipeline.STORE.get(object_id)
        action = parts[1] if len(parts) > 1 else ""

        if action == "":
            return self._send_json({"ok": True, "detail": _detail(obj)})
        if action == "inspect":
            return self._send_json({"ok": True, "inspect": pipeline.inspect_object(obj)})
        if action == "pipeline":
            return self._send_json({"ok": True, "pipeline": pipeline.describe_pipeline(obj)})
        if action == "transforms":
            return self._send_json({"ok": True, "transforms":
                                    pipeline.get_transforms().applicable(obj)})
        if action == "media":
            # serve original bytes inline for preview (image/audio/video/pdf)
            ctype = obj.mime or "application/octet-stream"
            data = obj.original_bytes or b""
            self._send(data, ctype + "; charset=binary" if ctype.startswith("text") else ctype)
            return
        if action == "blob":
            key = parts[2] if len(parts) > 2 else ""
            want_png = key.endswith(".png")
            if want_png:
                key = key[:-4]
            data = obj.blobs.get(key)
            if data is None:
                return self._error("blob not found", 404)
            if want_png:
                w = int(obj.content.get("width") or 0)
                h = int(obj.content.get("height") or 0)
                if w and h and len(data) == w * h * 4:
                    from .codecs import png as png_codec
                    return self._send(png_codec.encode_rgba(data, w, h), "image/png")
                return self._error("blob is not raw RGBA at known dimensions", 400)
            return self._send(data, "application/octet-stream")
        return self._error("unknown object action", 404)

    # POST /api/object/<id>/<action>
    def _object_post(self, path: str, body: dict):
        rest = path[len("/api/object/"):]
        parts = rest.split("/")
        object_id = parts[0]
        action = parts[1] if len(parts) > 1 else ""
        obj = pipeline.STORE.get(object_id)

        if action == "edit":
            obj = pipeline.edit_object(obj, str(body.get("op", "set_text")),
                                       dict(body.get("params") or {}))
            pipeline.STORE.put(obj)
            return self._send_json({"ok": True, "detail": _detail(obj)})
        if action == "transform":
            obj = pipeline.transform_object(obj, str(body.get("transform", "")),
                                            dict(body.get("params") or {}))
            pipeline.STORE.put(obj)
            return self._send_json({"ok": True, "detail": _detail(obj)})
        if action == "export":
            fmt = str(body.get("format", ""))
            as_attachment = bool(body.get("download", False))
            try:
                result = pipeline.export_object(obj, fmt)
            except UnsafeInputError as exc:
                return self._error(str(exc), 400)
            pipeline.STORE.put(obj)
            if as_attachment or body.get("raw"):
                self._send(result.data, result.mime, filename=result.filename)
                return
            return self._send_json({"ok": True, "filename": result.filename,
                                    "mime": result.mime, "kind": result.kind,
                                    "notes": result.notes,
                                    "size": len(result.data),
                                    "base64": base64.b64encode(result.data).decode()})
        if action == "encrypt":
            mode = str(body.get("mode", crypto.MODE_PASSWORD))
            password = body.get("password")
            kdf = str(body.get("kdf") or crypto.KDF_PBKDF2)
            try:
                data, filename = pipeline.encrypt_object(obj, mode, password, kdf)
            except crypto.EncryptionError as exc:
                return self._error(str(exc), 400)
            self._send(data, "application/x-superfile", filename=filename)
            return
        if action == "add_child":
            # attach a rendered capture (e.g. video frame) as a child object
            raw = base64.b64decode(body.get("data_b64", ""))
            name = str(body.get("filename", "capture.png"))
            child = pipeline.import_bytes(name, raw)
            child.record("transform", "captured via browser render (RENDERED)",
                         "RENDERED")
            obj.add_child(child, relation="derived_from",
                          note="browser-rendered capture")
            pipeline.STORE.put(obj)
            pipeline.STORE.put(child)
            return self._send_json({"ok": True, "detail": _detail(obj)})
        return self._error("unknown object action", 404)

    # ------------------------------------------------------------------
    def _api_import(self):
        """Accepts JSON {name, data_b64} or multipart/raw body."""
        length = int(self.headers.get("Content-Length", 0))
        if length > LIMITS.max_upload_bytes:
            return self._error("upload too large", 413)
        ctype = self.headers.get("Content-Type", "")
        raw = self.rfile.read(length) if length else b""
        if "application/json" in ctype:
            body = json.loads(raw.decode("utf-8"))
            name = str(body.get("name", "upload.bin"))
            data = base64.b64decode(body.get("data_b64", ""))
        else:
            # treat entire body as the file (UI uses fetch with raw bytes)
            name = self.headers.get("X-Filename", "upload.bin")
            data = raw
        if len(data) > LIMITS.max_file_bytes:
            return self._error("file exceeds import limit", 413)
        obj = pipeline.import_bytes(name, data)
        pipeline.STORE.put(obj)
        return self._send_json({"ok": True, "object": obj.summary(),
                                "detail": _detail(obj)})

    # ------------------------------------------------------------------
    # encryption: decrypt an uploaded .sfp (multipart/form-data)
    # ------------------------------------------------------------------
    def _api_decrypt(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > LIMITS.max_upload_bytes:
            return self._error("upload too large", 413)
        ctype = self.headers.get("Content-Type", "")
        raw = self.rfile.read(length) if length else b""
        if "multipart/form-data" not in ctype:
            return self._error("expected multipart/form-data with the .sfp file")
        match = re.search(r'boundary="?([^";]+)"?', ctype)
        if not match:
            return self._error("multipart body without a boundary")
        fields, files = _parse_multipart(raw, match.group(1).encode("latin-1"))
        if "file" not in files:
            return self._error("no file part in the request")
        filename, data = files["file"]
        mode = str(fields.get("mode") or crypto.MODE_PASSWORD)
        password = fields.get("password") or None
        if not data:
            return self._error("the uploaded file is empty")
        if len(data) > LIMITS.max_file_bytes:
            return self._error("file exceeds import limit", 413)
        try:
            obj, plain, out_name = pipeline.decrypt_container_bytes(data, mode, password)
        except crypto.DeviceLockUnavailable as exc:
            return self._error(str(exc), 400)
        except crypto.EncryptionError as exc:
            return self._error(str(exc), 400)
        except UnsafeInputError as exc:
            return self._error(str(exc), 400)
        except Exception as exc:                       # genuinely unexpected
            return self._error(f"could not decrypt {safe_filename(filename)}: {exc}", 400)
        pipeline.STORE.put(obj)                        # so the existing OPEN flow can load it
        return self._send_json({"ok": True, "filename": out_name,
                                "object_id": obj.object_id,
                                "size": len(plain),
                                "encrypted_size": len(data),
                                "original_filename": obj.original_filename})

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length > 16 * 1024 * 1024:
            raise UnsafeInputError("request too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _static(self, name: str):
        name = safe_filename(name)
        path = os.path.join(UI_DIR, name)
        if not os.path.isfile(path):
            return self._error("not found", 404)
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        with open(path, "rb") as fh:
            self._send(fh.read(), ctype)


def _detail(obj) -> dict:
    """Full UI payload for one object (content + blobs addressed by key)."""
    d = obj.to_dict()
    d["content"] = obj.content
    d["children"] = [c.summary() for c in obj.children]
    d["transformations"] = [t.to_dict() for t in obj.transformations]
    d["relationships"] = [r.to_dict() for r in obj.relationships]
    d["export_formats"] = [e.to_dict() if isinstance(e, ExportOption) else e
                           for e in obj.export_formats]
    d["media_available"] = obj.original_bytes is not None
    return d


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def serve(host: str = "0.0.0.0", port: int = 8765, open_browser: bool = False):
    httpd = ThreadingHTTPServer((host, port), SuperfileHandler)
    url = f"http://localhost:{port}/"
    print("=" * 62)
    print("  SUPERFILE — Universal Digital Object Protocol")
    print("  One application. One object model. Many formats.")
    print("=" * 62)
    print(f"  UI:        {url}")
    print(f"  API:       {url}api/health")
    print(f"  Demo dir:  {DEMO_DIR}")
    print("  Offline-first: no cloud, no API keys. Ctrl+C to stop.")
    print("=" * 62)
    if open_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[superfile] shutting down.")
    finally:
        httpd.server_close()

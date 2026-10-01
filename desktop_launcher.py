#!/usr/bin/env python3
"""
SUPERFILE desktop launcher — THE single entry point for the packaged app.

ONE application for EVERY supported format family (Universal Digital Object
Protocol).  PyInstaller bundles THIS file as ``Superfile`` (Linux/macOS) or
``Superfile.exe`` (Windows) — there are no per-file-type executables.

Frozen-aware behavior (docs/PACKAGING.md, STAGE 3 hardened):

  * User / sample / generated data lives in a persistent, writable, per-user
    folder OUTSIDE the PyInstaller one-file temp extraction directory:
        Windows : %LOCALAPPDATA%\\Superfile
        Linux   : ~/.local/share/Superfile
        macOS   : ~/.local/share/Superfile
    (The PyInstaller _MEIxxxxxx extraction dir is wiped on every run — nothing
    user-visible is ever stored there.)
  * Binds 127.0.0.1 only (localhost) — never a public interface.
  * Picks a free local port automatically (8765, then 8766-8790) by really
    binding, so a busy port cannot be chosen by accident (Windows-safe).
  * Starts the offline UI server and opens the system default browser —
    no terminal interaction needed for a normal user.
  * On an unhandled exception: prints the traceback AND waits for a keypress
    before closing, so a double-clicked Superfile.exe does not flash and vanish.
  * Terminates cleanly on Ctrl+C / SIGTERM / Windows SIGBREAK.
  * ``--self-test``: 12-point headless verification used as the CI/release
    gate (exits 0 on success, non-zero with a clear message on any failure).

Usage:
    Superfile                            # start app + open browser
    Superfile --self-test                # verify THIS binary (CI gate)
    Superfile --no-browser --port 8777   # headless serve (debugging)
    Superfile --version
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import signal
import socket
import sys
import threading
import time
import traceback
import urllib.request
import zipfile

APP_NAME = "Superfile"
APP_TITLE = "SUPERFILE — Universal Digital Object Protocol"
VERSION = "1.0.0"
FROZEN = bool(getattr(sys, "frozen", False))

# Registry counts of the unpackaged source this binary was built from.
# --self-test FAILS if the packaged registry reports fewer than these —
# that is exactly the symptom of the dynamic-adapter-import packaging trap
# (PyInstaller silently omitting superfile.adapters.* loaded via
# importlib.import_module in a loop).
EXPECTED_ADAPTERS = 28
EXPECTED_FORMATS = 59
EXPECTED_TRANSFORMS = 20

PORT_RANGE = range(8765, 8791)          # 8765 first, then 8766-8790

# Any of these in the adapter-load log means the frozen bundle is broken.
BAD_LOAD_PATTERNS = ("could not load", "ModuleNotFoundError", "ImportError",
                     "AttributeError", "failed to load adapter")


# ---------------------------------------------------------------------------
# persistent per-user data (NEVER PyInstaller's temp extraction dir)
# ---------------------------------------------------------------------------

def user_data_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, APP_NAME)
    return os.path.join(os.path.expanduser("~"), ".local", "share", APP_NAME)


def setup_data() -> tuple:
    """Create the persistent data dir and point SUPERFILE_DEMO_DIR at it.

    MUST run before importing superfile.server (DEMO_DIR is read at import).
    """
    data = user_data_dir()
    os.makedirs(data, exist_ok=True)
    demo_dir = os.path.join(data, "demo")
    os.makedirs(demo_dir, exist_ok=True)
    os.environ["SUPERFILE_DEMO_DIR"] = demo_dir
    return data, demo_dir


def start_server(host: str, port: int = 0):
    """Return (httpd, bound_port).  Real binds only — no probe race.

    With port=0 the range 8765, 8766-8790 is tried in order and the first
    port that actually binds wins.
    """
    from http.server import ThreadingHTTPServer
    from superfile.server import SuperfileHandler
    if port:
        return ThreadingHTTPServer((host, port), SuperfileHandler), port
    last = None
    for p in PORT_RANGE:
        try:
            return ThreadingHTTPServer((host, p), SuperfileHandler), p
        except OSError as exc:
            last = exc
    raise RuntimeError(
        f"no free local port in {PORT_RANGE.start}-{PORT_RANGE.stop - 1}: "
        f"{last}")


def _install_signal_handlers() -> None:
    def _stop(signum, frame):
        raise KeyboardInterrupt
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), _stop)
            except (ValueError, OSError):
                pass


# ---------------------------------------------------------------------------
# normal run: serve + auto-open browser
# ---------------------------------------------------------------------------

def webbrowser_open(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception as exc:               # never fatal — server still runs
        print(f"[{APP_NAME}] could not open browser automatically: {exc}")
        print(f"[{APP_NAME}] open {url} manually.")


def run_app(args) -> int:
    data_dir, demo_dir = setup_data()
    from superfile import demo
    from superfile.server import serve

    if not os.listdir(demo_dir):
        demo.generate_all(demo_dir)      # first-run convenience samples

    try:
        httpd, port = start_server(args.host, args.port or 0)
    except OSError as exc:
        raise RuntimeError(
            f"could not bind {args.host}:{args.port or '8765-8790'} — "
            f"is another SUPERFILE running? ({exc})") from exc

    url = f"http://{args.host}:{port}/"
    print(f"[{APP_NAME}] version   : {VERSION} (frozen={FROZEN})")
    print(f"[{APP_NAME}] user data : {data_dir}")
    print(f"[{APP_NAME}] starting  : {url}")
    print(f"[{APP_NAME}] browser   : {'opening…' if not args.no_browser else 'disabled (--no-browser)'}")

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser_open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[{APP_NAME}] shutting down cleanly.")
    finally:
        httpd.server_close()
    return 0


# ---------------------------------------------------------------------------
# --self-test  (12 points; the release gate — section 10 of STAGE 3)
# ---------------------------------------------------------------------------

def _http_json(host: str, port: int, path: str, data: bytes | None = None,
               headers: dict | None = None) -> dict:
    req = urllib.request.Request(
        f"http://{host}:{port}{path}", data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_raw(host: str, port: int, path: str) -> bytes:
    with urllib.request.urlopen(f"http://{host}:{port}{path}", timeout=60) as r:
        return r.read()


def self_test(host: str = "127.0.0.1") -> int:
    print("=" * 70)
    print(f"  {APP_NAME} {VERSION}  --self-test  (12-point release gate)")
    print(f"  frozen={FROZEN}   python={sys.version.split()[0]}   "
          f"platform={sys.platform}")
    print("=" * 70)

    ok = True

    def report(n: int, title: str, detail: str = "") -> None:
        print(f"[{n:2d}] {title:<58} PASS  {detail}")

    def fail(n: int, title: str, exc) -> None:
        nonlocal ok
        ok = False
        print(f"[{n:2d}] {title:<58} FAIL  {exc}")

    data_dir, demo_dir = setup_data()

    # ---- 1. generate/load the sample data the app needs --------------------
    try:
        from superfile import demo
        created = demo.generate_all(demo_dir)
        assert len(created) >= 30, f"only {len(created)} samples generated"
        for name in ("hello.txt", "pixel.png", "data.json", "sample.exe"):
            assert os.path.isfile(os.path.join(demo_dir, name)), f"missing {name}"
        report(1, "generate/load sample data",
               f"{len(created)} files in {demo_dir}")
    except Exception as exc:
        fail(1, "generate/load sample data", exc)

    # ---- 2. start the application/server on a background thread ------------
    httpd = None
    port = None
    try:
        httpd, port = start_server(host, 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        report(2, "start application/server on background thread",
               f"{host}:{port}")
    except Exception as exc:
        fail(2, "start application/server on background thread", exc)

    try:
        if httpd is None:
            print("  SELF-TEST: FAIL — server did not start; remaining checks "
                  "cannot run.")
            return 1

        # ---- 3. hit own health endpoint ------------------------------------
        try:
            health = _http_json(host, port, "/api/health")
            assert health.get("ok") is True, f"unhealthy: {health}"
            report(3, "GET /api/health",
                   f"ok={health.get('ok')} app={health.get('app')} "
                   f"version={health.get('version')}")
        except Exception as exc:
            fail(3, "GET /api/health", exc)

        # ---- 4. registry + adapter loading (dynamic-import trap) -----------
        try:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                from superfile import pipeline
                reg = pipeline.get_registry()
            load_log = out.getvalue() + err.getvalue()
            bad = [p for p in BAD_LOAD_PATTERNS if p in load_log]
            assert not bad, f"adapter-load problems {bad} in log:\n{load_log}"
            for modname in ("superfile.adapters.text",
                            "superfile.adapters.executable",
                            "superfile.adapters.sfp_adapter"):
                __import__(modname)                     # explicit import check
            r = _http_json(host, port, "/api/registry")
            n_fmt, n_ad = len(r["formats"]), len(r["adapters"])
            n_tr = len(r["transforms"])
            assert n_ad >= EXPECTED_ADAPTERS, (
                f"adapters {n_ad} < expected {EXPECTED_ADAPTERS} "
                "(dynamic-import packaging trap?)")
            assert n_fmt >= EXPECTED_FORMATS, (
                f"formats {n_fmt} < expected {EXPECTED_FORMATS}")
            assert n_tr >= EXPECTED_TRANSFORMS, (
                f"transforms {n_tr} < expected {EXPECTED_TRANSFORMS}")
            report(4, "GET /api/registry + adapter loading",
                   f"adapters={n_ad} formats={n_fmt} transforms={n_tr} "
                   f"creators={len(r['creators'])}; zero load warnings")
        except Exception as exc:
            fail(4, "GET /api/registry + adapter loading", exc)

        # ---- 5. UI resource loading (HTML + JS + CSS from the bundle) ------
        try:
            html = _http_raw(host, port, "/").decode("utf-8", "replace")
            js = _http_raw(host, port, "/static/app.js")
            css = _http_raw(host, port, "/static/app.css")
            assert "<html" in html.lower() and "SUPERFILE" in html, "bad HTML"
            assert len(js) > 1000 and b"renderObject" in js or b"function" in js, \
                f"app.js looks wrong ({len(js)} bytes)"
            assert len(css) > 500 and b"{" in css, f"app.css looks wrong ({len(css)} bytes)"
            report(5, "UI resource loading (index.html + app.js + app.css)",
                   f"html={len(html)}B js={len(js)}B css={len(css)}B")
        except Exception as exc:
            fail(5, "UI resource loading (index.html + app.js + app.css)", exc)

        # ---- 6. import a real PNG ------------------------------------------
        try:
            with open(os.path.join(demo_dir, "pixel.png"), "rb") as fh:
                png_bytes = fh.read()
            r = _http_json(host, port, "/api/import", data=png_bytes,
                           headers={"X-Filename": "pixel.png",
                                    "Content-Type": "application/octet-stream"})
            obj = r["object"]
            assert obj["detected_format"] == "png", obj
            assert obj["object_type"] == "IMAGE", obj
            report(6, "import real PNG (demo/pixel.png)",
                   f"detected={obj['detected_format']} type={obj['object_type']} "
                   f"support={obj['support_level']}")
        except Exception as exc:
            fail(6, "import real PNG (demo/pixel.png)", exc)

        # ---- 7. import a real JSON file ------------------------------------
        try:
            with open(os.path.join(demo_dir, "data.json"), "rb") as fh:
                json_bytes = fh.read()
            r = _http_json(host, port, "/api/import", data=json_bytes,
                           headers={"X-Filename": "data.json",
                                    "Content-Type": "application/octet-stream"})
            obj = r["object"]
            assert obj["detected_format"] == "json", obj
            report(7, "import real JSON (demo/data.json)",
                   f"detected={obj['detected_format']} type={obj['object_type']} "
                   f"support={obj['support_level']}")
        except Exception as exc:
            fail(7, "import real JSON (demo/data.json)", exc)

        # ---- 8. inspect a real executable AS DATA (never executed) ---------
        try:
            with open(os.path.join(demo_dir, "sample.exe"), "rb") as fh:
                exe_bytes = fh.read()
            r = _http_json(host, port, "/api/import", data=exe_bytes,
                           headers={"X-Filename": "sample.exe",
                                    "Content-Type": "application/octet-stream"})
            obj = r["object"]
            assert obj["detected_format"] == "pe", obj
            assert obj["object_type"] == "EXECUTABLE", obj
            insp = _http_json(host, port, f"/api/object/{obj['object_id']}/inspect")
            flat = json.dumps(insp).lower()
            assert "never executed" in flat or "never run" in flat, \
                "no never-executed safety wording"
            assert ("entry" in flat and "section" in flat and "hash" in flat), \
                "inspection missing entry/sections/hash"
            report(8, "inspect real EXE as DATA (never executed)",
                   f"{obj['detected_format']}/{obj['object_type']}, "
                   f"entry+sections+hash present, safety wording present")
        except Exception as exc:
            fail(8, "inspect real EXE as DATA (never executed)", exc)

        # ---- 9. archive security: safe ZIP accepted ------------------------
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("good.txt", "safe content")
                zf.writestr("dir/nested.txt", "nested content")
            r = _http_json(host, port, "/api/import", data=buf.getvalue(),
                           headers={"X-Filename": "safe.zip",
                                    "Content-Type": "application/octet-stream"})
            assert r["object"]["detected_format"] == "zip", r["object"]
            report(9, "archive security: safe ZIP accepted",
                   f"detected=zip type={r['object']['object_type']} "
                   f"children={r['object']['children']}")
        except Exception as exc:
            fail(9, "archive security: safe ZIP accepted", exc)

        # ---- 10. path traversal protection ---------------------------------
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("good.txt", "safe")
                zf.writestr("../evil.txt", "evil")
            r = _http_json(host, port, "/api/import", data=buf.getvalue(),
                           headers={"X-Filename": "t.zip",
                                    "Content-Type": "application/octet-stream"})
            detail = _http_json(host, port,
                                f"/api/object/{r['object']['object_id']}")
            paths = [e["path"] for e in detail["detail"]["content"]["entries"]]
            assert "good.txt" in paths, paths
            assert "evil.txt" not in paths, f"traversal entry extracted: {paths}"
            assert any("unsafe path" in w.lower()
                       for w in detail["detail"].get("warnings", [])), \
                detail["detail"].get("warnings")
            report(10, "path traversal protection (../evil.txt)",
                   f"kept={paths}, 'unsafe path' warning present")
        except Exception as exc:
            fail(10, "path traversal protection (../evil.txt)", exc)

        # ---- 11. decompression-bomb protection -----------------------------
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("zeros.bin", b"\x00" * 20_000_000)
            raised = False
            try:
                _http_json(host, port, "/api/import", data=buf.getvalue(),
                           headers={"X-Filename": "bomb.zip",
                                    "Content-Type": "application/octet-stream"})
            except Exception:
                raised = True
            assert raised, "zip bomb was NOT rejected"
            report(11, "decompression-bomb protection (20MB-zero zip)",
                   "import refused")
        except Exception as exc:
            fail(11, "decompression-bomb protection (20MB-zero zip)", exc)

        # ---- 12. clean shutdown --------------------------------------------
        try:
            httpd.shutdown()
            httpd.server_close()
            httpd = None
            from http.server import ThreadingHTTPServer as _THS
            from superfile.server import SuperfileHandler as _SH
            probe = _THS((host, port), _SH)   # same bind semantics as the server
            probe.server_close()              # listener gone -> this must bind
            report(12, "clean shutdown (server stopped, port released)",
                   f"port {port} re-bindable")
        except Exception as exc:
            fail(12, "clean shutdown (server stopped, port released)", exc)

    finally:
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()

    print("=" * 70)
    if ok:
        print("  SELF-TEST: PASS — all 12 checks passed.")
        print("=" * 70)
        return 0
    print("  SELF-TEST: FAIL — see FAIL lines above.")
    print("=" * 70)
    return 1


# ---------------------------------------------------------------------------
# entry
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(prog=APP_NAME, description=APP_TITLE)
    ap.add_argument("--self-test", action="store_true",
                    help="verify this binary headlessly (CI/build gate)")
    ap.add_argument("--port", type=int, default=0,
                    help="serve on a fixed port (default: first free 8765-8790)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default: 127.0.0.1 — local only)")
    ap.add_argument("--no-browser", action="store_true",
                    help="do not auto-open the system browser")
    ap.add_argument("--version", action="store_true",
                    help="print version and exit")
    args = ap.parse_args()

    _install_signal_handlers()
    if args.version:
        print(f"{APP_NAME} {VERSION}")
        return 0
    if args.self_test:
        return self_test(host=args.host)
    return run_app(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print(f"\n[{APP_NAME}] stopped.")
        sys.exit(0)
    except Exception:
        traceback.print_exc()
        print()
        try:
            input("Press Enter to close...")
        except EOFError:
            pass
        sys.exit(1)

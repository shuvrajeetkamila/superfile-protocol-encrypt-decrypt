#!/usr/bin/env python3
"""
SUPERFILE -- real-browser check of the collapsible top chrome + sidebar.

Drives a REAL Chromium (Playwright) against a REAL SUPERFILE server (source tree
or packaged exe) and records what it actually observes: element geometry,
animation frames, DOM identity, localStorage persistence across reload AND across
a full browser+server restart, and an A/B click-through comparison against a
baseline run of the previous UI.  Nothing is simulated or hard-coded.

  # 1) baseline click-through of the PREVIOUS ui (a copy of the old source tree)
  python tests/ui_layout_check.py --spawn-source /path/to/old_tree --mode functional --dump base.json
  # 2) everything, on the current source tree
  python tests/ui_layout_check.py --spawn-source . --baseline base.json --orig-ui /path/to/old_tree/ui
  # 3) the same checks against the packaged exe (wine on Linux, native on Windows)
  python tests/ui_layout_check.py --spawn-exe release/Superfile.exe --baseline base.json

Needs: pip install playwright, plus Chromium/Chrome/Edge (--browser PATH, or
`playwright install chromium`).  Exit code 0 = every check passed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from html.parser import HTMLParser

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sys.exit("playwright is required: pip install playwright "
             "(then pass --browser PATH, or run `playwright install chromium`)")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_PNG = os.path.join(ROOT, "demo", "pixel.png")
DEMO_JSON = os.path.join(ROOT, "demo", "data.json")
RESULTS: list = []


# ---------------------------------------------------------------- reporting
def say(msg: str = "") -> None:
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode(), flush=True)


def check(ok: bool, name: str, detail: str = "") -> bool:
    RESULTS.append((bool(ok), name, detail))
    say(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))
    return bool(ok)


def section(title: str) -> None:
    say(f"\n=== {title} ===")


def near(a: float, b: float, tol: float = 0.6) -> bool:
    return abs(a - b) <= tol


# ---------------------------------------------------------------- server
class Server:
    """One SUPERFILE server process with its own throw-away per-user data dir."""

    def __init__(self, kind: str, target: str, port: int, tag: str, wine_prefix=None):
        self.kind, self.target, self.port = kind, os.path.abspath(target), port
        self.wine_prefix = wine_prefix
        self.home = tempfile.mkdtemp(prefix=f"sfui_{tag}_")
        self.proc = None
        self.logf = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def native(self, path: str) -> str:
        """Path as the *server* process sees it (Z:\\... for a Windows exe under wine)."""
        if self.kind == "exe" and sys.platform != "win32":
            return "Z:" + path.replace("/", "\\")
        return path

    def start(self) -> None:
        env = dict(os.environ)
        if self.kind == "source":
            # The throw-away HOME must not hide the real user site-packages: without this the source
            # app loses --user installed packages (cryptography, ...), exactly as a fresh HOME would.
            import site as _site
            user_site = _site.getusersitepackages()
            env["PYTHONPATH"] = os.pathsep.join(
                [p for p in (user_site, os.path.dirname(ROOT), env.get("PYTHONPATH", "")) if p])
            env["HOME"] = self.home
            cmd = [sys.executable, "desktop_launcher.py", "--no-browser", "--port", str(self.port)]
            cwd = self.target
        else:
            cwd = os.path.dirname(self.target)
            if sys.platform == "win32":
                env["LOCALAPPDATA"] = self.home
                cmd = [self.target, "--no-browser", "--port", str(self.port)]
            else:
                env.update(WINEDEBUG="-all", WINEDLLOVERRIDES="mscoree,mshtml=",
                           LOCALAPPDATA=self.native(self.home))
                if self.wine_prefix:
                    env["WINEPREFIX"] = self.wine_prefix
                cmd = ["wine", self.target, "--no-browser", "--port", str(self.port)]
        self.logf = open(os.path.join(self.home, "server.log"), "wb")
        self.proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=self.logf,
                                     stderr=subprocess.STDOUT,
                                     start_new_session=(sys.platform != "win32"))
        slow = self.kind == "exe" and sys.platform != "win32"
        deadline = time.time() + (180 if slow else 40)
        while time.time() < deadline and self.proc.poll() is None:
            try:
                with urllib.request.urlopen(self.url + "api/health", timeout=2) as r:
                    if json.loads(r.read()).get("ok"):
                        return
            except Exception:
                time.sleep(0.4)
        tail = open(self.logf.name, errors="replace").read()[-1500:]
        raise RuntimeError("server did not become healthy; log tail:\n" + tail)

    def stop(self) -> None:
        if not self.proc:
            return
        try:
            if sys.platform == "win32":
                self.proc.terminate()
            else:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            self.proc.wait(timeout=15)
        except Exception:
            try:
                if sys.platform == "win32":
                    self.proc.kill()
                else:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except Exception:
                pass
        if self.logf:
            self.logf.close()
        self.proc = None
        t0 = time.time()                      # the port must really be free again
        while time.time() - t0 < 10:
            try:
                urllib.request.urlopen(self.url + "api/health", timeout=1).close()
                time.sleep(0.3)
            except Exception:
                break

    def restart(self) -> None:
        self.stop()
        self.start()


# ---------------------------------------------------------------- browser helpers
def find_browser(arg):
    if arg:
        return arg
    for name in ("chromium", "chromium-browser", "google-chrome", "chrome", "msedge"):
        p = shutil.which(name)
        if p:
            return p
    return None


def launch(pw, args, profile, viewport=None):
    w, h = viewport or args.viewport
    kw = dict(user_data_dir=profile, headless=True, viewport={"width": w, "height": h},
              accept_downloads=True,
              args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--no-proxy-server"])
    exe = find_browser(args.browser)
    if exe:
        kw["executable_path"] = exe
    return pw.chromium.launch_persistent_context(**kw)


def attach(page, sink: list) -> None:
    page.on("console", lambda m: sink.append(f"console.error: {m.text}") if m.type == "error" else None)
    page.on("pageerror", lambda e: sink.append(f"pageerror: {e}"))


def sha(text) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:12]


def ready(page) -> None:
    page.wait_for_function(
        "() => { const s = document.querySelector('#status');"
        " return s && s.textContent.startsWith('ready'); }", timeout=30000)


def settle(page, sel: str, timeout: float = 4.0):
    """innerText of `sel` once it stopped changing (async renderers)."""
    last, stable, t0 = None, 0, time.time()
    while time.time() - t0 < timeout:
        cur = page.evaluate("s => { const e = document.querySelector(s); return e ? e.innerText : null; }", sel)
        stable = stable + 1 if cur == last else 0
        last = cur
        if stable >= 2:
            break
        page.wait_for_timeout(100)
    return last


# Per-run noise that is NOT UI behaviour (found by an A/A run of the same UI twice):
# the throw-away HOME dir name in the Demo pane, wall-clock times in History, random object UUIDs in Inspect.
_NOISE = ((re.compile(r"sfui_[a-z]+_\w+"), "<HOME>"),
          (re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\s?[AP]M)?"), "<TIME>"),
          (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "<UUID>"))


def norm(text):
    for rx, repl in _NOISE:
        text = rx.sub(repl, text or "")
    return text


def pane_obs(page) -> dict:
    a = page.evaluate("""() => ({
        tab: (document.querySelector('.tab.active') || {dataset: {}}).dataset.tab || null,
        pane: (document.querySelector('.tab-pane.active') || {}).id || null })""")
    txt = norm(settle(page, "#" + a["pane"])) if a["pane"] else ""
    a.update(sha=sha(txt), len=len(txt))
    return a


GEOM = """() => {
  const R = (s) => { const e = document.querySelector(s); if (!e) return null;
    const b = e.getBoundingClientRect(), c = getComputedStyle(e);
    return {x: +b.x.toFixed(2), y: +b.y.toFixed(2), w: +b.width.toFixed(2), h: +b.height.toFixed(2),
            display: c.display, visibility: c.visibility}; };
  return {vw: innerWidth, vh: innerHeight, cls: document.documentElement.className,
          strip: R('#sf-top-toggle'), titlebar: R('#titlebar'), toolbar: R('#toolbar'), main: R('#main'),
          sidebar: R('#sidebar'), handle: R('#sf-side-toggle'), content: R('#content'), status: R('#statusbar')};
}"""

SAMPLER = """(cfg) => { window.__samples = new Promise((res) => {
  const t0 = performance.now(), out = [];
  (function tick() {
    const t = performance.now() - t0, row = {t: +t.toFixed(1)};
    for (const [k, [sel, dim]] of Object.entries(cfg.probes))
      row[k] = +document.querySelector(sel).getBoundingClientRect()[dim].toFixed(2);
    out.push(row);
    if (t < cfg.ms) requestAnimationFrame(tick); else res(out);
  })(); }); }"""


def geom(page) -> dict:
    return page.evaluate(GEOM)


def idle(page, extra: int = 60) -> None:
    page.wait_for_function(
        "() => document.getAnimations().length === 0"
        " && !document.documentElement.classList.contains('sf-side-anim')", timeout=5000)
    page.wait_for_timeout(extra)


def sample_click(page, probes: dict, sel: str, ms: int = 700) -> list:
    page.evaluate(SAMPLER, {"probes": probes, "ms": ms})
    page.wait_for_timeout(60)                # a few frames BEFORE the click
    page.click(sel)
    return page.evaluate("window.__samples")


def analyse(samples: list, key: str, tol: float = 0.6):
    vals = [s[key] for s in samples]
    v0, v1 = vals[0], vals[-1]
    if abs(v1 - v0) < 2 * tol:
        return None
    ts = next((s["t"] for s in samples if abs(s[key] - v0) > tol), None)
    te = next((s["t"] for s in samples
               if ts is not None and s["t"] >= ts and abs(s[key] - v1) <= tol), None)
    span = [s for s in samples if ts is not None and ts <= s["t"] <= (te if te is not None else 1e9)]
    mid = [s[key] for s in span if abs(s[key] - v0) > tol and abs(s[key] - v1) > tol]
    sign = 1 if v1 > v0 else -1
    seq = [s[key] for s in span]
    return dict(v0=v0, v1=v1, t_start=ts, t_end=te,
                dur=(te - ts) if ts is not None and te is not None else None,
                mid_frames=len(mid),
                monotonic=all((b - a) * sign >= -tol for a, b in zip(seq, seq[1:])))


def rects_equal(a: dict, b: dict, keys, tol: float = 0.05):
    bad = [f"{k}.{d}: {a[k][d]} != {b[k][d]}" for k in keys for d in ("x", "y", "w", "h")
           if not near(a[k][d], b[k][d], tol)]
    return (not bad), "; ".join(bad[:4])


# ---------------------------------------------------------------- click-through ("functional") scenario
def functional(page, srv: Server) -> dict:
    """Everything a user can click in the existing UI; returns geometry-free observations."""
    obs: dict = {}
    ready(page)
    # init() sets "ready" right after FIRING (not awaiting) the /api/recent fetch: wait for that render too,
    # otherwise the first snapshot races it (found by negative-control runs)
    page.wait_for_function("() => !document.querySelector('#recent-list').innerText.includes('open or create a file')",
                           timeout=10000)
    obs["initial"] = page.evaluate(r"""() => ({
        toolbar: [...document.querySelectorAll('.tool')].map(b => [b.id, b.textContent.trim().replace(/\s+/g, ' '), b.disabled]),
        nav: [...document.querySelectorAll('#sidebar a[data-tab]')].map(a => [a.dataset.tab, a.textContent.trim()]),
        tabs: [...document.querySelectorAll('.tab')].map(b => [b.dataset.tab, b.textContent.trim()]),
        status_right: document.querySelector('#status-right').textContent,
        recent: document.querySelector('#recent-list').innerText,
        tree: document.querySelector('#object-tree').innerText,
        safety: document.querySelector('.safety-note').innerText })""")

    w: dict = {}                                               # welcome-screen buttons
    with page.expect_file_chooser(timeout=5000):
        page.click("#w-open")
    w["w-open opens file chooser"] = True
    page.click("#w-demo")
    w["w-demo"] = pane_obs(page)
    page.click('.tab[data-tab="view"]')
    page.click("#w-create")
    page.wait_for_timeout(250)
    w["w-create menu visible"] = page.evaluate(
        "() => !document.querySelector('#create-menu').classList.contains('hidden')")
    page.click("#statusbar")
    obs["welcome"] = w

    obs["sidebar_nav"] = {}                                    # sidebar NAVIGATION links
    for tab in ("registry", "explorer", "matrix", "demo", "about"):
        page.click(f'#sidebar a[data-tab="{tab}"]')
        obs["sidebar_nav"][tab] = pane_obs(page)

    obs["tabs_no_object"] = {}                                 # content tabs, nothing loaded
    for t in page.evaluate("[...document.querySelectorAll('.tab')].map(b => b.dataset.tab)"):
        page.click(f'.tab[data-tab="{t}"]')
        obs["tabs_no_object"][t] = pane_obs(page)

    tb: dict = {}                                              # toolbar buttons, nothing loaded
    page.click("#btn-create")
    page.wait_for_timeout(250)
    tb["create"] = page.evaluate(r"""() => ({
        open: !document.querySelector('#create-menu').classList.contains('hidden'),
        items: [...document.querySelectorAll('#create-menu button')].map(b => b.innerText.replace(/\s+/g, ' ').trim()) })""")
    page.click("#statusbar")
    tb["create closes on outside click"] = page.evaluate(
        "() => document.querySelector('#create-menu').classList.contains('hidden')")
    page.click("#btn-save-sfp")
    page.wait_for_timeout(200)
    tb["save_sfp status (no object)"] = page.inner_text("#status")
    for name in ("export", "inspect", "edit", "transform"):
        page.click(f"#btn-{name}")
        tb[name + " (no object)"] = pane_obs(page)
    obs["toolbar_no_object"] = tb

    with page.expect_file_chooser(timeout=5000) as fc:         # OPEN -> real PNG
        page.click("#btn-open")
    fc.value.set_files(DEMO_PNG)
    page.wait_for_function("() => document.querySelector('#oh-name').textContent.includes('pixel')", timeout=20000)
    settle(page, "#tab-view")
    hdr = r"""() => ({
        header_visible: !document.querySelector('#object-header').classList.contains('hidden'),
        name: document.querySelector('#oh-name').textContent, support: document.querySelector('#oh-support').textContent,
        type: document.querySelector('#oh-type').textContent, format: document.querySelector('#oh-format').textContent,
        mime: document.querySelector('#oh-mime').textContent, size: document.querySelector('#oh-size').textContent,
        hash: document.querySelector('#oh-hash').textContent, detect: document.querySelector('#oh-detect').textContent,
        caps: [...document.querySelectorAll('#oh-caps .cap')].map(c => c.textContent),
        recent: [...document.querySelectorAll('#recent-list li')].map(li => li.innerText.replace(/\s+/g, ' ').trim()),
        tree: document.querySelector('#object-tree').innerText })"""
    obs["after_open_png"] = page.evaluate(hdr)
    obs["after_open_png"]["view"] = pane_obs(page)

    with page.expect_download(timeout=15000) as dl:            # SAVE AS .SFP with an object
        page.click("#btn-save-sfp")
    data = open(dl.value.path(), "rb").read()
    obs["save_sfp"] = {"filename": dl.value.suggested_filename, "bytes>0": len(data) > 0,
                       "magic": data[:8].hex()}

    obs["toolbar_with_object"] = {}
    for name in ("export", "inspect", "edit", "transform"):
        page.click(f"#btn-{name}")
        obs["toolbar_with_object"][name] = pane_obs(page)

    obs["tabs_with_object"] = {}
    for t in page.evaluate("[...document.querySelectorAll('.tab')].map(b => b.dataset.tab)"):
        page.click(f'.tab[data-tab="{t}"]')
        obs["tabs_with_object"][t] = pane_obs(page)

    msgs: list = []                                            # IMPORT PATH (server-side path, prompt())
    page.once("dialog", lambda d: (msgs.append(d.message), d.accept(srv.native(DEMO_JSON))))
    page.click("#btn-import-path")
    page.wait_for_function("() => document.querySelector('#oh-name').textContent.includes('data.json')", timeout=20000)
    settle(page, "#tab-view")
    obs["after_import_path"] = page.evaluate(hdr)
    obs["after_import_path"]["prompt"] = msgs[0] if msgs else None

    page.click('#sidebar .rec-item:last-child')                # RECENT OBJECTS entry reloads an object
    page.wait_for_timeout(600)
    obs["recent_click"] = page.evaluate("() => document.querySelector('#oh-name').textContent")
    return obs


def leaves(o) -> int:
    if isinstance(o, dict):
        return sum(leaves(v) for v in o.values())
    if isinstance(o, list):
        return sum(leaves(v) for v in o) if o else 1
    return 1


def diff(a, b, path: str = "") -> list:
    out: list = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: only in {'A' if k in a else 'B'}")
            else:
                out += diff(a[k], b[k], f"{path}/{k}")
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, f"{path}[{i}]")
    elif a != b:
        out.append(f"{path}: {a!r} != {b!r}")
    return out


def expected_additions(base: dict, obs: dict, lines: list) -> tuple:
    """Task C appended two toolbar buttons and two content tabs.

    Returns (expected_lines, unexpected_lines).  The two inventory lists are checked structurally —
    the previous list must be an exact prefix of the new one and the appended tail must be exactly the
    two new controls — so a real change there still shows up as an unexpected difference.
    """
    expected: list = []
    suppressed: set = set()          # only suppress a diff line once the structural check has PASSED
    for key, tail in (("tabs", [["encrypt", "ENCRYPT"], ["decrypt", "DECRYPT"]]),
                      ("toolbar", [["btn-encrypt", "ENCRYPT", False], ["btn-decrypt", "DECRYPT", False]])):
        before = base.get("initial", {}).get(key)
        after = obs.get("initial", {}).get(key)
        if before is None or after is None:
            continue
        if after[:len(before)] == before and after[len(before):] == tail:
            expected.append(f"/initial/{key}: the previous {len(before)} entries are unchanged, +{tail} appended")
            suppressed.add(f"/initial/{key}")
    rest = [x for x in lines if x.split(":")[0] not in suppressed]
    dynamic = [x for x in rest if x.split(":")[0] in TASK_C_ADDED_OBS]   # the tab loops click every tab
    unexpected = [x for x in rest if x not in dynamic]
    return expected + dynamic, unexpected


def run_functional(pw, args, srv: Server, cycles: int = 0) -> tuple:
    profile = tempfile.mkdtemp(prefix="sfui_prof_")
    ctx = launch(pw, args, profile)
    errs: list = []
    try:
        page = ctx.new_page()
        attach(page, errs)
        page.goto(srv.url)
        ready(page)
        for _ in range(cycles):                                # toggle both panels, return to expanded
            page.click("#sf-top-toggle")
            page.click("#sf-side-toggle")
            idle(page)
            page.click("#sf-top-toggle")
            page.click("#sf-side-toggle")
            idle(page)
        obs = functional(page, srv)
    finally:
        ctx.close()
        shutil.rmtree(profile, ignore_errors=True)
    return obs, errs


# ---------------------------------------------------------------- static structure (original markup untouched)
# The file-details slide needs the detail elements in one sliding container, so exactly these 8 ids
# changed parent (.oh-grid/.oh-caps/#oh-warnings blocks) — their tags and attributes are untouched.
MOVED_INTO_DETAILS = {"oh-type", "oh-format", "oh-mime", "oh-size", "oh-hash", "oh-detect", "oh-caps", "oh-warnings"}

# Task C appended two toolbar buttons and two content tabs.  These are the ONLY ids added to the markup,
# and the only extra observation leaves the new UI may produce in the click-through A/B (the tab loops in
# functional() discover tabs dynamically, so the two new tabs are clicked there as well).
TASK_C_ADDED_IDS = {"btn-encrypt", "btn-decrypt", "tab-encrypt", "tab-decrypt"}
TASK_C_ADDED_OBS = {"/tabs_no_object/encrypt", "/tabs_no_object/decrypt",
                    "/tabs_with_object/encrypt", "/tabs_with_object/decrypt"}


class IdMap(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}

    def __init__(self):
        super().__init__()
        self.stack: list = []
        self.ids: dict = {}
        self.order: list = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        parent = next((i for i in reversed(self.stack) if i), None)
        if a.get("id"):
            self.ids[a["id"]] = (tag, tuple(sorted(a.items())), parent)
            self.order.append(a["id"])
        if tag not in self.VOID:
            self.stack.append(a.get("id"))

    def handle_endtag(self, tag):
        if tag not in self.VOID and self.stack:
            self.stack.pop()


def idmap(html: str) -> IdMap:
    p = IdMap()
    p.feed(html)
    return p


def check_served_ui(args, srv: Server, kind: str, target: str) -> None:
    """What the RUNNING server (source tree or packaged exe) actually serves == the source files, and the
    original markup / CSS / JS are untouched inside it."""
    section("2b. the UI the server really serves == the source files; original markup untouched")
    ui_dir = os.path.join(target if kind == "source" else ROOT, "ui")
    served = {}
    for name, url in (("index.html", ""), ("app.js", "static/app.js"), ("app.css", "static/app.css")):
        with urllib.request.urlopen(srv.url + url, timeout=20) as r:
            served[name] = r.read()
        disk = open(os.path.join(ui_dir, name), "rb").read()
        check(served[name] == disk, f"served {name} is byte-identical to the source file",
              f"{len(disk)} bytes, sha256 {hashlib.sha256(disk).hexdigest()[:16]}")
    if not args.orig_ui:
        return
    old = idmap(open(os.path.join(args.orig_ui, "index.html"), encoding="utf-8").read())
    new = idmap(served["index.html"].decode("utf-8"))
    missing = [i for i in old.ids if i not in new.ids]
    changed = [i for i in old.ids if i in new.ids and old.ids[i] != new.ids[i]]
    added = [i for i in new.ids if i not in old.ids]
    order_ok = [i for i in new.order if i in old.ids] == old.order
    say(f"  original ids: {len(old.ids)}   ids added: {added}")
    changed_attrs = [i for i in old.ids if i in new.ids and old.ids[i][:2] != new.ids[i][:2]]
    moved = [i for i in old.ids if i in new.ids and old.ids[i][:2] == new.ids[i][:2] and old.ids[i][2] != new.ids[i][2]]
    check(not missing and not changed_attrs and order_ok
          and all(a.startswith("sf-") or a in TASK_C_ADDED_IDS for a in added),
          "all original ids present with identical tag + attributes, original order kept; "
          "only the documented ids were added",
          f"missing={missing} tag/attr-changed={changed_attrs} added={added}")
    if "sf-oh-details" in old.ids:      # reference already is the Task B UI: Task C must move nothing
        check(not moved, "Task C moved NO existing element (reference already has #sf-oh-details); "
                         "the new controls are additions only", f"moved={sorted(moved)}")
    else:
        check(set(moved) == MOVED_INTO_DETAILS and all(new.ids[i][2] == "sf-oh-details" for i in moved),
              "the ONLY structural change is the documented one: the 8 file-detail ids now live inside "
              "the new #sf-oh-details wrapper", f"moved={sorted(moved)}")
    for fn_ in ("app.css",):
        o = open(os.path.join(args.orig_ui, fn_), "rb").read()
        n = served[fn_]
        check(n.startswith(o) and len(n) > len(o),
              f"{fn_}: the original {len(o)} bytes are an exact prefix of what is served -> purely additive (+{len(n) - len(o)} bytes)")
    # app.js needs three in-place wiring lines (renderers map + the two toolbar onclicks) plus the appended
    # renderers.  Prove those additions are ALL that changed by reconstruction: strip the appended block and
    # the 3 documented lines from what is served and the previous file must come back byte-for-byte.
    o = open(os.path.join(args.orig_ui, "app.js"), "rb").read()
    n = served["app.js"]
    marker = b"ENCRYPT / DECRYPT tabs"
    idx = n.find(marker)
    start = n.rfind(b"\n", 0, idx) + 1 if idx > 0 else -1
    wiring = [b'    encrypt: renderEncrypt, decrypt: renderDecrypt,\n',
              b'  $("#btn-encrypt").onclick = () => switchTab("encrypt");\n',
              b'  $("#btn-decrypt").onclick = () => switchTab("decrypt");\n']
    check(start > 0 and n[start:start + 2] == b"/*" and all(n.count(w) == 1 for w in wiring),
          "app.js: added code is exactly the 3 documented wiring lines + one appended block",
          f"block at byte {start}, wiring-line counts {[n.count(w) for w in wiring]}")
    body = n[:start] if start > 0 else n
    for w in wiring:
        body = body.replace(w, b"")
    check(body == o, "app.js: removing those 3 lines + the appended block reproduces the previous file "
                     "byte-for-byte -> nothing else changed",
          f"{len(body)} vs {len(o)} bytes")
    check(start > 0 and n[start:].count(b"function render") == 2 and start > len(o),
          "app.js: the new renderers are appended at the very end of the file",
          f"+{len(n) - len(o)} bytes total (3 wiring lines + {len(n) - start} byte block)")


# ---------------------------------------------------------------- toggle verification
def session_toggles(pw, args, srv: Server) -> None:
    profile = tempfile.mkdtemp(prefix="sfui_prof_")
    shots = args.shots
    if shots:
        os.makedirs(shots, exist_ok=True)
    ctx = launch(pw, args, profile)
    errs: list = []
    page = ctx.new_page()
    attach(page, errs)
    section("3a. load the real app, import a real PNG so every panel holds real data")
    say("  browser: " + page.evaluate("navigator.userAgent"))
    page.goto(srv.url)
    ready(page)
    with page.expect_file_chooser(timeout=5000) as fc:
        page.click("#btn-open")
    fc.value.set_files(DEMO_PNG)
    page.wait_for_function("() => document.querySelector('#oh-name').textContent.includes('pixel')", timeout=20000)
    settle(page, "#tab-view")
    page.wait_for_function("() => document.querySelector('#recent-list .rec-item')", timeout=10000)
    page.click("#btn-inspect")
    inspect_before = settle(page, "#tab-inspect")
    g0 = geom(page)
    say(f"  viewport {g0['vw']}x{g0['vh']}  strip h={g0['strip']['h']}  titlebar h={g0['titlebar']['h']}"
        f"  toolbar h={g0['toolbar']['h']}  sidebar w={g0['sidebar']['w']}  handle w={g0['handle']['w']}")
    say(f"  content {g0['content']['w']} x {g0['content']['h']} at ({g0['content']['x']}, {g0['content']['y']})"
        f"   statusbar h={g0['status']['h']}")
    check(g0["strip"]["y"] == 0 and g0["strip"]["h"] <= 14, "top toggle is the very first thing in #app: y=0, thin strip",
          f"y={g0['strip']['y']} h={g0['strip']['h']}")
    check(near(g0["titlebar"]["y"], g0["strip"]["h"]), "#titlebar sits directly under the strip")
    check(near(g0["handle"]["x"], g0["sidebar"]["x"] + g0["sidebar"]["w"])
          and near(g0["content"]["x"], g0["handle"]["x"] + g0["handle"]["w"]),
          "left toggle sits on #sidebar's right edge; #content starts right after it (no overlap)",
          f"sidebar right edge={g0['sidebar']['x'] + g0['sidebar']['w']} handle x={g0['handle']['x']}")
    check(g0["sidebar"]["w"] == 250, "#sidebar is still exactly 250px wide when expanded")
    check(page.evaluate("document.querySelectorAll('.tool').length") == 10
          and page.evaluate("document.querySelectorAll('#sidebar a[data-tab]').length") == 5,
          "10 toolbar .tool buttons (the original 8 + ENCRYPT/DECRYPT) and the same 5 sidebar data-tab "
          "links (the new buttons are not sidebar links)")
    if shots:
        page.screenshot(path=os.path.join(shots, "01_expanded.png"))

    # DOM identity markers + mutation counters: proves nothing is cleared or re-rendered
    page.evaluate(r"""() => {
      const ids = ['titlebar','toolbar','sidebar','content','recent-list','object-tree','object-header','oh-name',
                   'oh-hash','oh-caps','tabs','tab-body','tab-inspect','file-input','btn-open','btn-import-path',
                   'btn-create','btn-save-sfp','btn-export','btn-inspect','btn-edit','btn-transform'];
      window.__marks = {};
      for (const id of ids) { const e = document.getElementById(id);
        if (e) { e.__sfMark = id + ':' + Math.random().toString(36).slice(2); window.__marks[id] = e.__sfMark; } }
      const li = document.querySelector('#recent-list li'); if (li) { li.__sfMark = 'li0'; window.__marks['#recent-list li'] = 'li0'; }
      window.__clicks = {top: 0, side: 0};
      document.getElementById('sf-top-toggle').addEventListener('click', () => window.__clicks.top++);
      document.getElementById('sf-side-toggle').addEventListener('click', () => window.__clicks.side++);
      window.__mut = {child: 0, text: 0};
      window.__mo = new MutationObserver((recs) => { for (const r of recs)
        if (r.type === 'childList') window.__mut.child += r.addedNodes.length + r.removedNodes.length;
        else if (r.type === 'characterData') window.__mut.text++; });
      for (const id of ['sidebar','content','titlebar','toolbar'])
        window.__mo.observe(document.getElementById(id), {childList: true, characterData: true, subtree: true});
    }""")
    html_before = page.evaluate("""() => ({sidebar: document.querySelector('#sidebar').innerHTML,
        content: document.querySelector('#content').innerHTML, toolbar: document.querySelector('#toolbar').innerHTML,
        titlebar: document.querySelector('#titlebar').innerHTML})""")
    n_marks = page.evaluate("Object.keys(window.__marks).length")
    KEYS_ALL = ["strip", "titlebar", "toolbar", "main", "sidebar", "handle", "content", "status"]

    # ---- 3b TOP -------------------------------------------------------------------------------
    section("3b. collapse TOP (#titlebar + #toolbar as one unit)")
    probes = {"content_h": ("#content", "height"), "titlebar_h": ("#titlebar", "height"),
              "toolbar_h": ("#toolbar", "height")}
    s = sample_click(page, probes, "#sf-top-toggle")
    idle(page)
    g1 = geom(page)
    ac, at, ab = analyse(s, "content_h"), analyse(s, "titlebar_h"), analyse(s, "toolbar_h")
    check(g1["titlebar"]["display"] == "none" and g1["toolbar"]["display"] == "none",
          "both #titlebar and #toolbar are collapsed together")
    gain = g0["titlebar"]["h"] + g0["toolbar"]["h"]
    check(near(g1["content"]["h"], g0["content"]["h"] + gain),
          "#content grew by exactly titlebar+toolbar height",
          f"{g0['content']['h']} -> {g1['content']['h']} (+{g1['content']['h'] - g0['content']['h']:.1f}, expected +{gain:.1f})")
    check(near(g1["content"]["w"], g0["content"]["w"]) and near(g1["sidebar"]["w"], g0["sidebar"]["w"])
          and near(g1["status"]["y"], g0["status"]["y"]) and near(g1["strip"]["h"], g0["strip"]["h"]),
          "nothing else moved: content width, sidebar width, status bar, strip unchanged")
    check(near(g1["main"]["y"], g1["strip"]["h"]), "#main now starts right under the thin strip", f"main.y={g1['main']['y']}")
    st = page.evaluate("""() => ({exp: document.querySelector('#sf-top-toggle').getAttribute('aria-expanded'),
        ls: localStorage.getItem('sf_top_collapsed'), arrow: getComputedStyle(document.querySelector('#sf-top-toggle .sf-arrow')).transform})""")
    check(st["exp"] == "false" and st["ls"] == "1" and st["arrow"] not in ("none", "matrix(1, 0, 0, 1, 0, 0)"),
          "aria-expanded=false, localStorage sf_top_collapsed=1, arrow flipped (up -> down)", str(st))
    if ac:
        check(ac["mid_frames"] >= 4 and ac["monotonic"] and 120 <= ac["dur"] <= 330,
              "collapse is a smooth animation, not a snap",
              f"{ac['mid_frames']} in-between frames, {ac['dur']:.0f} ms, {ac['v0']} -> {ac['v1']} px, monotonic={ac['monotonic']}")
    else:
        check(False, "collapse animation sampled")
    if at and ab:
        check(abs(at["t_start"] - ab["t_start"]) <= 20 and abs(at["t_end"] - ab["t_end"]) <= 35,
              "titlebar and toolbar animate in lock-step (one unit)",
              f"titlebar {at['t_start']:.0f}-{at['t_end']:.0f} ms, toolbar {ab['t_start']:.0f}-{ab['t_end']:.0f} ms")
    else:
        check(False, "both bars animated")
    if shots:
        page.screenshot(path=os.path.join(shots, "02_top_collapsed.png"))

    s = sample_click(page, probes, "#sf-top-toggle")
    idle(page)
    g2 = geom(page)
    ok, why = rects_equal(g2, g0, KEYS_ALL)
    check(ok, "re-expanded TOP: every key rectangle is IDENTICAL to the original", why or "8 elements x (x,y,w,h) equal")
    check(page.evaluate("['titlebar','toolbar'].every(i => !document.getElementById(i).getAttribute('style'))")
          and page.evaluate("document.getAnimations().length") == 0,
          "no leftover inline style / running animation on the bars after expanding")
    ae = analyse(s, "content_h")
    check(bool(ae) and ae["mid_frames"] >= 4 and ae["monotonic"], "expand is animated too",
          f"{ae['mid_frames']} in-between frames, {ae['dur']:.0f} ms" if ae else "no data")

    # ---- 3c SIDEBAR ---------------------------------------------------------------------------
    section("3c. collapse LEFT SIDEBAR")
    probes2 = {"sidebar_w": ("#sidebar", "width"), "content_w": ("#content", "width")}
    s = sample_click(page, probes2, "#sf-side-toggle")
    idle(page)
    g3 = geom(page)
    asb, acw = analyse(s, "sidebar_w"), analyse(s, "content_w")
    check(g3["sidebar"]["w"] == 0 and g3["sidebar"]["visibility"] == "hidden",
          "#sidebar is width 0 (and out of the tab order / a11y tree)", f"w={g3['sidebar']['w']} visibility={g3['sidebar']['visibility']}")
    check(near(g3["content"]["w"], g0["content"]["w"] + g0["sidebar"]["w"]),
          "#content absorbed exactly the freed 250px without any JS sizing (flex:1 verified)",
          f"{g0['content']['w']} -> {g3['content']['w']} (+{g3['content']['w'] - g0['content']['w']:.0f})")
    check(near(g3["handle"]["x"], 0) and near(g3["handle"]["w"], g0["handle"]["w"]) and near(g3["handle"]["h"], g3["main"]["h"])
          and near(g3["content"]["x"], g3["handle"]["w"]),
          "slim rail with the re-open arrow stays at the left edge; content starts right after it",
          f"rail x={g3['handle']['x']} w={g3['handle']['w']}; content x={g3['content']['x']}")
    check(near(g3["content"]["h"], g0["content"]["h"]) and near(g3["titlebar"]["h"], g0["titlebar"]["h"]),
          "heights unchanged (no cross-talk with the top bar)")
    st = page.evaluate("""() => ({exp: document.querySelector('#sf-side-toggle').getAttribute('aria-expanded'),
        ls: localStorage.getItem('sf_sidebar_collapsed'), cls: document.documentElement.className})""")
    check(st["exp"] == "false" and st["ls"] == "1" and "sf-side-anim" not in st["cls"],
          "aria-expanded=false, localStorage sf_sidebar_collapsed=1, animation flag cleaned up", str(st))
    if asb:
        check(asb["mid_frames"] >= 4 and asb["monotonic"] and 120 <= asb["dur"] <= 330,
              "sidebar collapse is smooth", f"{asb['mid_frames']} in-between frames, {asb['dur']:.0f} ms, {asb['v0']} -> {asb['v1']} px")
    else:
        check(False, "sidebar animation sampled")
    if shots:
        page.screenshot(path=os.path.join(shots, "03_side_collapsed.png"))

    s = sample_click(page, probes2, "#sf-side-toggle")
    idle(page)
    g4 = geom(page)
    ok, why = rects_equal(g4, g0, KEYS_ALL)
    check(ok, "re-expanded SIDEBAR: every key rectangle is IDENTICAL to the original", why or "8 elements x (x,y,w,h) equal")
    check(g4["sidebar"]["visibility"] == "visible" and g4["sidebar"]["w"] == 250, "sidebar back at 250px and visible")

    # ---- 3d BOTH ------------------------------------------------------------------------------
    section("3d. collapse BOTH")
    page.click("#sf-top-toggle")
    page.click("#sf-side-toggle")
    idle(page)
    g5 = geom(page)
    fw, fh = g5["content"]["w"] / g5["vw"], g5["content"]["h"] / g5["vh"]
    a0, a5 = g0["content"]["w"] * g0["content"]["h"], g5["content"]["w"] * g5["content"]["h"]
    say(f"  #content = {g5['content']['w']:.0f} x {g5['content']['h']:.0f} px of a {g5['vw']}x{g5['vh']} window "
        f"= {fw * 100:.1f}% of the width, {fh * 100:.1f}% of the height; area x{a5 / a0:.2f} vs expanded")
    say(f"  what is left outside #content: top strip {g5['strip']['h']:.0f}px, left rail {g5['handle']['w']:.0f}px, "
        f"status bar {g5['status']['h']:.0f}px")
    check(fw > 0.98 and near(g5["content"]["h"] + g5["strip"]["h"] + g5["status"]["h"], g5["vh"], 1.0)
          and near(g5["content"]["w"] + g5["handle"]["w"], g5["vw"], 1.0),
          "#content fills the window except the thin strip, the slim rail and the (out-of-scope) status bar",
          f"w={fw * 100:.1f}% h={fh * 100:.1f}%")
    check(g5["content"]["w"] > g0["content"]["w"] and g5["content"]["h"] > g0["content"]["h"], "#content is larger in both axes")
    if shots:
        page.screenshot(path=os.path.join(shots, "04_both_collapsed.png"))

    # ---- 3d' expand again, then prove nothing was cleared or re-initialised ------------------------
    section("3d'. expand both again + extra rounds: nothing cleared or re-initialised")
    page.click("#sf-top-toggle")
    page.click("#sf-side-toggle")
    idle(page)
    g5b = geom(page)
    ok, why = rects_equal(g5b, g0, KEYS_ALL)
    check(ok, "both re-expanded together: every key rectangle IDENTICAL to the original", why or "8 elements x (x,y,w,h) equal")
    for _ in range(3):                                         # 3 more full collapse/expand rounds, both panels
        page.click("#sf-top-toggle")
        page.click("#sf-side-toggle")
        idle(page)
        page.click("#sf-top-toggle")
        page.click("#sf-side-toggle")
        idle(page)
    clicks = page.evaluate("window.__clicks")
    inspect_after = settle(page, "#tab-inspect")
    html_after = page.evaluate("""() => ({sidebar: document.querySelector('#sidebar').innerHTML,
        content: document.querySelector('#content').innerHTML, toolbar: document.querySelector('#toolbar').innerHTML,
        titlebar: document.querySelector('#titlebar').innerHTML})""")
    same = page.evaluate("Object.entries(window.__marks).filter(([id, m]) => { const e = id.startsWith('#') ? document.querySelector(id) : document.getElementById(id); return e && e.__sfMark === m; }).length")
    mut = page.evaluate("(() => { const r = window.__mo.takeRecords(); let c = window.__mut.child, t = window.__mut.text;"
                        " for (const x of r) { if (x.type === 'childList') c += x.addedNodes.length + x.removedNodes.length; else if (x.type === 'characterData') t++; }"
                        " return {child: c, text: t}; })()")
    say(f"  toggle clicks performed on this page: top x{clicks['top']}, sidebar x{clicks['side']}")
    check(same == n_marks, f"all {n_marks} marked DOM nodes (lists, tree, header, buttons, panes) are the SAME objects afterwards - none re-created", f"{same}/{n_marks}")
    check(mut["child"] == 0 and mut["text"] == 0, "zero childList/text mutations inside #sidebar, #content, #titlebar, #toolbar during ALL toggling",
          f"child={mut['child']} text={mut['text']}")
    check(all(html_after[k] == html_before[k] for k in html_before),
          "innerHTML of #sidebar, #content, #titlebar, #toolbar is byte-identical before vs after",
          ", ".join(f"{k}={len(html_before[k])}B" for k in html_before))
    check(inspect_after == inspect_before and len(inspect_before) > 50, "the loaded file's INSPECT data is intact",
          f"{len(inspect_before)} chars, sha {sha(inspect_before)}")
    hdr_ok = page.evaluate("document.querySelector('#oh-name').textContent.includes('pixel') && !document.querySelector('#object-header').classList.contains('hidden')")
    check(hdr_ok, "#object-header still shows the loaded object", page.inner_text("#oh-name"))
    rec = page.evaluate("document.querySelector('#recent-list').innerText")
    tree = page.evaluate("document.querySelector('#object-tree').innerText")
    check("pixel" in rec and "no object loaded" not in tree, "RECENT OBJECTS list and OBJECT GRAPH tree still populated",
          f"recent={rec.replace(chr(10), ' | ')[:60]!r} tree={tree.replace(chr(10), ' / ')[:40]!r}")
    page.click("#sf-top-toggle")                               # leave both collapsed for the persistence tests
    page.click("#sf-side-toggle")
    idle(page)

    # ---- 3e persistence -----------------------------------------------------------------------
    section("3e. persistence: reload, new tab, full browser+server restart")
    ctx.add_init_script("""(() => { window.__cls = [];
      new MutationObserver(() => window.__cls.push([performance.now(), document.documentElement.className]))
        .observe(document, {attributes: true, subtree: true, attributeFilter: ['class']}); })();""")
    page.reload()
    ready(page)
    # the paint entry is recorded by the browser asynchronously; without this the measurement below
    # can run a few ms too early and report null (observed under wine) even though the class was
    # applied at ~35 ms and the first paint follows at ~200 ms
    try:
        page.wait_for_function("() => performance.getEntriesByType('paint').some(e => e.name === 'first-paint')",
                               timeout=3000)
    except Exception:
        pass                       # the check below then reports the real (missing) values
    g6 = geom(page)
    t = page.evaluate("""() => { const fp = performance.getEntriesByType('paint').find(e => e.name === 'first-paint');
        const hit = window.__cls.find(c => c[1].includes('sf-side-collapsed'));
        return {first_paint: fp ? fp.startTime : null, class_applied: hit ? hit[0] : null,
                anim_running: document.getAnimations().length}; }""")
    ok, why = rects_equal(g6, g5, KEYS_ALL)
    check("sf-top-collapsed" in g6["cls"] and "sf-side-collapsed" in g6["cls"] and ok,
          "after page.reload() both panels are STILL collapsed, identical geometry", why or g6["cls"])
    check(t["anim_running"] == 0, "restored without playing an animation", f"running animations right after load: {t['anim_running']}")
    if t["first_paint"] is not None and t["class_applied"] is not None:
        check(t["class_applied"] <= t["first_paint"], "collapsed state applied BEFORE the first paint (no flash of the expanded layout)",
              f"class applied at {t['class_applied']:.1f} ms, first paint at {t['first_paint']:.1f} ms")
    else:
        check(False, "paint timing available", str(t))
    p2 = ctx.new_page()
    attach(p2, errs)
    p2.goto(srv.url)
    ready(p2)
    check("sf-top-collapsed" in geom(p2)["cls"] and "sf-side-collapsed" in geom(p2)["cls"],
          "a brand-new tab on the same origin opens collapsed")
    p2.close()

    ctx.close()                                                # ---- full restart: browser AND server
    srv.restart()
    ctx = launch(pw, args, profile)
    page = ctx.new_page()
    attach(page, errs)
    page.goto(srv.url)
    ready(page)
    g7 = geom(page)
    ok, why = rects_equal(g7, g5, KEYS_ALL)
    check("sf-top-collapsed" in g7["cls"] and "sf-side-collapsed" in g7["cls"] and ok,
          "after closing the browser AND restarting the server (same port) both panels are still collapsed",
          why or f"origin {srv.url}")
    say("  note: the server's object store is in-memory, so RECENT OBJECTS starts empty after a server restart "
        "(pre-existing behaviour, unrelated to the toggles)")
    page.click("#sf-top-toggle")
    page.click("#sf-side-toggle")
    idle(page)
    g8 = geom(page)
    ok, why = rects_equal(g8, g0, KEYS_ALL)
    check(ok and "sf-top-collapsed" not in g8["cls"] and "sf-side-collapsed" not in g8["cls"],
          "expanded again after the restart: geometry identical to the very first measurement", why or "8 elements equal")
    check(page.evaluate("localStorage.getItem('sf_top_collapsed')") == "0"
          and page.evaluate("localStorage.getItem('sf_sidebar_collapsed')") == "0", "localStorage now says 0 / 0")

    # ---- 3g robustness ------------------------------------------------------------------------------
    section("3g. keyboard, rapid clicks, scroll position, narrow window, blocked storage")
    page.focus("#sf-top-toggle")
    page.keyboard.press("Enter")
    idle(page)
    kb1 = page.evaluate("document.documentElement.classList.contains('sf-top-collapsed')")
    page.keyboard.press("Space")
    idle(page)
    kb2 = page.evaluate("document.documentElement.classList.contains('sf-top-collapsed')")
    check(kb1 and not kb2, "top toggle works from the keyboard (Enter collapses, Space expands)")
    gq = geom(page)
    page.click("#sf-top-toggle")                               # click, click again 80 ms later (mid-animation)
    page.wait_for_timeout(80)
    page.click("#sf-top-toggle")
    idle(page, 120)
    gr = geom(page)
    ok, why = rects_equal(gr, gq, KEYS_ALL)
    check(ok and page.evaluate("document.getAnimations().length") == 0
          and page.evaluate("['titlebar','toolbar'].every(i => !document.getElementById(i).getAttribute('style'))"),
          "double-click mid-animation ends cleanly expanded (no stuck half-state, no leftover styles)", why)
    page.click("#sf-top-toggle")                               # three quick clicks -> odd -> collapsed
    page.wait_for_timeout(50)
    page.click("#sf-top-toggle")
    page.wait_for_timeout(50)
    page.click("#sf-top-toggle")
    idle(page, 120)
    gt = geom(page)
    check(gt["titlebar"]["display"] == "none" and near(gt["content"]["h"], g0["content"]["h"] + gain),
          "three rapid clicks land on the correct (collapsed) state")
    page.click("#sf-top-toggle")
    idle(page)
    page.click("#sf-side-toggle")                              # same stress for the sidebar
    page.wait_for_timeout(70)
    page.click("#sf-side-toggle")
    page.wait_for_timeout(70)
    page.click("#sf-side-toggle")
    idle(page, 120)
    gs = geom(page)
    check(gs["sidebar"]["w"] == 0 and "sf-side-anim" not in gs["cls"], "three rapid sidebar clicks land on collapsed, flag cleaned up")
    page.click("#sf-side-toggle")
    idle(page)

    page.set_viewport_size({"width": 1280, "height": 380})     # sidebar now scrolls: scrollTop must survive
    page.wait_for_timeout(150)
    sc = page.evaluate("(() => { const s = document.getElementById('sidebar'); s.scrollTop = 90; "
                       "return [s.scrollTop, s.scrollHeight, s.clientHeight]; })()")
    page.click("#sf-side-toggle")
    idle(page)
    page.click("#sf-side-toggle")
    idle(page)
    sc2 = page.evaluate("document.getElementById('sidebar').scrollTop")
    check(sc[0] > 0 and sc2 == sc[0], "sidebar scroll position survives collapse -> expand",
          f"scrollTop {sc[0]} -> {sc2} (scrollHeight {sc[1]}, clientHeight {sc[2]})")
    page.set_viewport_size({"width": 620, "height": 800})      # toolbar wraps onto more rows
    page.wait_for_timeout(150)
    gn0 = geom(page)
    page.click("#sf-top-toggle")
    idle(page)
    page.set_viewport_size({"width": 1280, "height": 800})     # resize WHILE collapsed, then expand
    page.wait_for_timeout(150)
    page.click("#sf-top-toggle")
    idle(page)
    gn1 = geom(page)
    check(near(gn1["toolbar"]["h"], g0["toolbar"]["h"]) and near(gn0["toolbar"]["h"], g0["toolbar"]["h"]) is False,
          "wrapped toolbar (narrow window) is re-measured on expand: height follows the CURRENT width",
          f"620px wide: toolbar {gn0['toolbar']['h']}px (wrapped); resized to 1280 while collapsed -> {gn1['toolbar']['h']}px")
    ok, why = rects_equal(gn1, g0, KEYS_ALL)
    check(ok, "after resize-while-collapsed + expand the layout equals the original 1280x800 layout", why)

    # prefers-reduced-motion: the OS/browser asks for no animation -> both toggles must snap, and still be correct
    page.emulate_media(reduced_motion="reduce")
    page.wait_for_timeout(100)
    gpre = geom(page)
    sr_top = sample_click(page, probes, "#sf-top-toggle", ms=500)
    idle(page)
    gr1 = geom(page)
    sr_side = sample_click(page, probes2, "#sf-side-toggle", ms=500)
    idle(page)
    gr2 = geom(page)
    a_top, a_side = analyse(sr_top, "content_h"), analyse(sr_side, "sidebar_w")
    check(a_top is not None and a_top["mid_frames"] == 0 and gr1["titlebar"]["display"] == "none"
          and a_side is not None and a_side["mid_frames"] == 0 and gr2["sidebar"]["w"] == 0,
          "prefers-reduced-motion: both toggles snap instantly (0 in-between frames) and land on the correct state",
          f"top {a_top['mid_frames'] if a_top else '?'} frames, sidebar {a_side['mid_frames'] if a_side else '?'} frames")
    page.click("#sf-top-toggle")
    page.click("#sf-side-toggle")
    idle(page)
    ok, why = rects_equal(geom(page), gpre, KEYS_ALL)
    check(ok, "prefers-reduced-motion: expanding again restores the identical layout", why)
    page.emulate_media(reduced_motion="no-preference")

    # collapsed-state usability: the welcome-screen buttons live in #content, the file input in the collapsed toolbar
    p3 = ctx.new_page()
    attach(p3, errs)
    p3.goto(srv.url)
    ready(p3)
    p3.click("#sf-top-toggle")
    idle(p3)
    with p3.expect_file_chooser(timeout=5000) as fc3:
        p3.click("#w-open")
    check(fc3.value is not None, "top bar collapsed: the welcome screen's REAL 'OPEN A FILE' button still opens the file chooser "
          "(its <input> lives inside the hidden toolbar)")
    p3.click("#w-demo")
    check(pane_obs(p3)["tab"] == "demo", "top bar collapsed: welcome 'RUN THE DEMO' still switches to the DEMO tab")
    p3.click('#sidebar a[data-tab="registry"]')
    check(pane_obs(p3)["tab"] == "registry", "top bar collapsed: sidebar NAVIGATION links still work")
    p3.click("#sf-side-toggle")
    idle(p3)
    p3.click('.tab[data-tab="matrix"]')
    check(pane_obs(p3)["tab"] == "matrix", "both collapsed: content tabs keep working")
    p3.focus("#sf-side-toggle")
    p3.keyboard.press("Shift+Tab")
    back = p3.evaluate("document.activeElement.id")
    p3.focus("#sf-top-toggle")
    p3.keyboard.press("Tab")
    fwd = p3.evaluate("document.activeElement.id")
    check(back == "sf-top-toggle" and fwd == "sf-side-toggle",
          "both collapsed: Tab / Shift+Tab skip the hidden toolbar buttons and sidebar links entirely (out of tab order)",
          f"Shift+Tab from rail -> #{back}; Tab from strip -> #{fwd}")
    p3.click("#sf-top-toggle")
    p3.click("#sf-side-toggle")
    idle(p3)
    p3.click("#btn-create")                                    # CREATE menu open, then the top toggle is clicked
    p3.wait_for_timeout(250)
    was_open = p3.evaluate("!document.querySelector('#create-menu').classList.contains('hidden')")
    p3.click("#sf-top-toggle")
    idle(p3)
    p3.click("#sf-top-toggle")
    idle(p3)
    now_open = p3.evaluate("!document.querySelector('#create-menu').classList.contains('hidden')")
    check(was_open and not now_open, "an open CREATE menu is closed by the app's own outside-click rule when the toggle is used "
          "(no orphaned dropdown after re-expanding)", f"open before={was_open}, open after={now_open}")
    p3.close()

    ctx.close()                                                # blocked localStorage (cookies disabled / privacy mode)
    prof2 = tempfile.mkdtemp(prefix="sfui_prof_")
    ctx2 = launch(pw, args, prof2)
    ctx2.add_init_script("Object.defineProperty(window, 'localStorage', {get() { throw new DOMException('blocked', 'SecurityError'); }});")
    p4 = ctx2.new_page()
    e4: list = []
    attach(p4, e4)
    p4.goto(srv.url)
    ready(p4)
    p4.click("#sf-top-toggle")
    p4.click("#sf-side-toggle")
    idle(p4)
    g9 = geom(p4)
    check("sf-top-collapsed" in g9["cls"] and "sf-side-collapsed" in g9["cls"] and not e4,
          "with localStorage BLOCKED (access throws) both toggles still work for the session and raise no page error",
          f"errors={e4}")
    ctx2.close()
    shutil.rmtree(prof2, ignore_errors=True)

    check(not errs, "zero console errors / uncaught page errors during the whole session", "; ".join(errs[:3]) or f"{len(errs)} errors")
    shutil.rmtree(profile, ignore_errors=True)


# ---------------------------------------------------------------- details slide
GEOM_OH = """() => {
  const R = (s) => { const e = document.querySelector(s); if (!e) return null;
    const b = e.getBoundingClientRect(), c = getComputedStyle(e);
    return {x:+b.x.toFixed(2), y:+b.y.toFixed(2), w:+b.width.toFixed(2), h:+b.height.toFixed(2),
            bottom:+b.bottom.toFixed(2), display:c.display, visibility:c.visibility,
            opacity:+(+c.opacity).toFixed(3), maxH:c.maxHeight}; };
  return {vw: innerWidth, vh: innerHeight, cls: document.documentElement.className,
          header: R('#object-header'), row: R('.oh-row'), details: R('#sf-oh-details'),
          grid: R('.oh-grid'), caps: R('.oh-caps'), tabs: R('#tabs'), body: R('#tab-body'),
          content: R('#content'), btn: R('#sf-oh-toggle'), status: R('#statusbar'),
          aria: document.querySelector('#sf-oh-toggle').getAttribute('aria-expanded'),
          hidden_cls: document.querySelector('#object-header').classList.contains('hidden'),
          arrow: getComputedStyle(document.querySelector('#sf-oh-toggle .sf-arrow')).transform,
          ls: (() => { try { return localStorage.getItem('sf_objheader_collapsed'); } catch (e) { return null; } })(),
          scrollTop: document.querySelector('#tab-body').scrollTop}; }"""


def anchors_ok(g: dict, tol: float = 0.7) -> str:
    """#tabs sits exactly on the bottom edge of #object-header, #tab-body exactly under #tabs,
    and the three fill #content exactly.  Returns "" when all three hold."""
    bad = []
    if not near(g["tabs"]["y"], g["header"]["bottom"], tol):
        bad.append(f"tabs.y {g['tabs']['y']} != header.bottom {g['header']['bottom']}")
    if not near(g["body"]["y"], g["tabs"]["bottom"], tol):
        bad.append(f"body.y {g['body']['y']} != tabs.bottom {g['tabs']['bottom']}")
    if not near(g["header"]["h"] + g["tabs"]["h"] + g["body"]["h"], g["content"]["h"], 1.5):
        bad.append(f"{g['header']['h']}+{g['tabs']['h']}+{g['body']['h']} != content {g['content']['h']}")
    return "; ".join(bad)


def header_details(pw, args, srv: Server) -> None:
    """The file-details slide (#object-header + #sf-oh-details) and its composition with the existing
    "hidden" logic and with the top/sidebar toggles."""
    profile = tempfile.mkdtemp(prefix="sfui_prof_")
    ctx = launch(pw, args, profile)
    errs: list = []
    page = ctx.new_page()
    attach(page, errs)
    probes = {"details_h": ("#sf-oh-details", "height"), "tabs_y": ("#tabs", "y"),
              "tabs_h": ("#tabs", "height"), "tabs_w": ("#tabs", "width"),
              "body_h": ("#tab-body", "height"), "header_h": ("#object-header", "height")}

    shots = args.shots
    if shots:
        os.makedirs(shots, exist_ok=True)

    def set_details(collapsed: bool) -> None:
        """Put the details into a known state (never assume the toggle count)."""
        if page.evaluate("document.documentElement.classList.contains('sf-oh-collapsed')") != collapsed:
            page.click("#sf-oh-toggle")
            idle(page, 140)

    section("3h. #object-header details slide — no file loaded yet (existing behaviour)")
    page.goto(srv.url)
    ready(page)
    g = page.evaluate(GEOM_OH)
    check(g["header"]["display"] == "none" and g["hidden_cls"],
          "no file loaded: #object-header is display:none through the existing \"hidden\" class (untouched)", 
          f"display={g['header']['display']} class-hidden={g['hidden_cls']}")
    page.evaluate("document.getElementById('sf-oh-toggle').click()")     # arrow is inside the hidden block
    page.wait_for_timeout(150)
    g = page.evaluate(GEOM_OH)
    check("sf-oh-collapsed" in g["cls"] and g["header"]["display"] == "none",
          "clicking the arrow with NO file loaded cannot reveal the block — the two states compose, \"hidden\" wins",
          f"html class has sf-oh-collapsed={'sf-oh-collapsed' in g['cls']}, header display={g['header']['display']}")
    page.evaluate("document.getElementById('sf-oh-toggle').click()")     # back to the expanded preference
    page.wait_for_timeout(100)

    section("3h. open a file → details expanded by default, tabs anchored under the header")
    with page.expect_file_chooser(timeout=5000) as fc:
        page.click("#btn-open")
    fc.value.set_files(DEMO_PNG)
    page.wait_for_function("() => document.querySelector('#oh-name').textContent.includes('pixel')", timeout=20000)
    page.wait_for_function("() => document.querySelector('#recent-list .rec-item')", timeout=10000)
    g0 = page.evaluate(GEOM_OH)
    say(f"  header {g0['header']['h']}px (row {g0['row']['h']}, details {g0['details']['h']}) | tabs y={g0['tabs']['y']} "
        f"h={g0['tabs']['h']} | tab-body y={g0['body']['y']} h={g0['body']['h']} | content h={g0['content']['h']}")
    check(g0["aria"] == "true" and "sf-oh-collapsed" not in g0["cls"] and g0["details"]["h"] > 40
          and g0["grid"]["display"] == "grid" and g0["caps"]["h"] > 0,
          "a loaded file shows the details fully expanded by default (grid + capabilities visible)",
          f"aria={g0['aria']} details.h={g0['details']['h']}")
    check(g0["row"]["h"] > 10 and g0["btn"]["h"] > 10, "the .oh-row and the new arrow are visible on the header",
          f"row.h={g0['row']['h']} arrow={g0['btn']['w']}x{g0['btn']['h']}")
    check(not anchors_ok(g0), "#tabs is exactly on #object-header's bottom edge, #tab-body exactly under #tabs, and the three fill #content",
          anchors_ok(g0) or f"tabs.y={g0['tabs']['y']} == header.bottom={g0['header']['bottom']}")

    if shots:
        page.screenshot(path=os.path.join(shots, "05_details_expanded.png"))
    section("3h. collapse the details — smooth slide, tabs/body must not jump, resize or flicker")
    s = sample_click(page, probes, "#sf-oh-toggle")
    idle(page, 140)
    g1 = page.evaluate(GEOM_OH)
    ad, ab, aty = analyse(s, "details_h"), analyse(s, "body_h"), analyse(s, "tabs_y")
    if ad:
        check(ad["mid_frames"] >= 4 and ad["monotonic"] and 120 <= ad["dur"] <= 330,
              "the details slide up over ~0.2 s instead of snapping",
              f"{ad['mid_frames']} in-between frames, {ad['dur']:.0f} ms, {ad['v0']} -> {ad['v1']} px, monotonic={ad['monotonic']}")
    else:
        check(False, "details slide sampled")
    ah = analyse(s, "header_h")
    if ab and ah:
        check(ab["mid_frames"] >= 4 and ab["monotonic"] and near(ab["v1"] - ab["v0"], -(ah["v1"] - ah["v0"]), 2.0),
              "#tab-body grew by exactly the height #object-header gave up (the freed space went nowhere else)",
              f"body {ab['v0']} -> {ab['v1']} px, header {ah['v0']} -> {ah['v1']} px (details {ad['v0']} -> {ad['v1']} + 8 px of padding)")
    else:
        check(False, "#tab-body height sampled")
    if aty:
        check(aty["mid_frames"] >= 4 and aty["monotonic"],
              "#tabs followed the header's bottom edge smoothly (it is never pushed down or resized, only carried up with the block)",
              f"tabs.y {aty['v0']} -> {aty['v1']} px over {aty['mid_frames']} frames")
    else:
        check(False, "#tabs position sampled")
    th = [x["tabs_h"] for x in s]
    tw = [x["tabs_w"] for x in s]
    check(max(th) - min(th) <= 0.7 and max(tw) - min(tw) <= 0.7,
          "#tabs never resized or flickered during the slide (constant height and width across every frame)",
          f"height spread {max(th) - min(th):.2f} px, width spread {max(tw) - min(tw):.2f} px over {len(s)} frames")
    check(not anchors_ok(g1) and g1["tabs"]["h"] == g0["tabs"]["h"] and g1["tabs"]["w"] == g0["tabs"]["w"]
          and g1["tabs"]["x"] == g0["tabs"]["x"],
          "collapsed: the tab strip is still exactly anchored, same size, same x", anchors_ok(g1) or f"tabs {g1['tabs']['w']}x{g1['tabs']['h']} @x={g1['tabs']['x']}")
    check(g1["row"]["h"] > 10 and g1["btn"]["h"] > 10 and g1["header"]["h"] < g0["header"]["h"] - 40,
          "the filename/badge row and the arrow stay visible — they are the anchor to re-open the details",
          f"header {g0['header']['h']} -> {g1['header']['h']} px, row {g1['row']['h']} px")
    check(g1["aria"] == "false" and "sf-oh-collapsed" in g1["cls"] and g1["ls"] == "1"
          and g1["arrow"] not in ("none", "matrix(1, 0, 0, 1, 0, 0)"),
          "aria-expanded=false, localStorage sf_objheader_collapsed=1, arrow flipped down -> up", f"arrow transform {g1['arrow']}")
    check(page.evaluate("document.getElementById('sf-oh-details').getAttribute('aria-hidden')") == "true"
          and g1["details"]["maxH"] in ("0px",),
          "collapsed details are aria-hidden and max-height:0 — nothing left to read or tab into",
          f"aria-hidden=true, max-height={g1['details']['maxH']}")

    if shots:
        page.screenshot(path=os.path.join(shots, "06_details_collapsed.png"))

    section("3h. expand again — same slide back, data intact, scroll position untouched")
    page.click('.tab[data-tab="registry"]')                        # long pane for the scroll tests
    page.wait_for_timeout(500)
    mid = page.evaluate("""() => { const b = document.querySelector('#tab-body');
        b.scrollTop = Math.round((b.scrollHeight - b.clientHeight) / 2);
        return [b.scrollTop, b.scrollHeight, b.clientHeight]; }""")
    s = sample_click(page, probes, "#sf-oh-toggle")
    idle(page, 140)
    g2 = page.evaluate(GEOM_OH)
    ad = analyse(s, "details_h")
    st = page.evaluate("document.querySelector('#tab-body').scrollTop")
    check(ad and ad["mid_frames"] >= 4 and ad["monotonic"] and near(g2["details"]["h"], g0["details"]["h"], 1.0),
          "expanding slides the details back down to exactly their previous height",
          f"{ad['mid_frames']} in-between frames, {ad['dur']:.0f} ms, {ad['v0']} -> {ad['v1']} px (original {g0['details']['h']} px)")
    check(mid[0] > 0 and st == mid[0],
          "while scrolled mid-pane, expanding the details did NOT reset or shift #tab-body's scroll position",
          f"scrollTop {mid[0]} -> {st} (pane {mid[1]} px tall in a {mid[2]} px viewport)")
    check(not anchors_ok(g2) and page.evaluate("document.getAnimations().length") == 0
          and page.evaluate("!document.getElementById('sf-oh-details').getAttribute('style')"),
          "expanded: anchors hold and no inline style or animation is left behind", anchors_ok(g2) or "clean")
    hs = page.evaluate("""() => ({html: document.getElementById('object-header').innerHTML,
        name: document.getElementById('oh-name').textContent,
        details: document.getElementById('sf-oh-details').innerText,
        caps: document.querySelectorAll('#oh-caps .cap').length,
        hash: document.getElementById('oh-hash').textContent})""")
    for _ in range(3):                                             # 3 more collapse/expand rounds
        page.click("#sf-oh-toggle")
        idle(page, 140)
        page.click("#sf-oh-toggle")
        idle(page, 140)
    hs2 = page.evaluate("""() => ({html: document.getElementById('object-header').innerHTML,
        name: document.getElementById('oh-name').textContent,
        details: document.getElementById('sf-oh-details').innerText,
        caps: document.querySelectorAll('#oh-caps .cap').length,
        hash: document.getElementById('oh-hash').textContent})""")
    check(hs == hs2 and hs["caps"] > 0 and len(hs["hash"]) == 64,
          "after 3 more collapse/expand rounds the header HTML, filename, detail text, capability chips and SHA-256 are byte-identical (nothing blanked, stale or re-rendered)",
          f"innerHTML {len(hs['html'])} B, chips {hs['caps']}, hash {hs['hash'][:12]}…")
    bot = page.evaluate("""() => { const b = document.querySelector('#tab-body'); b.scrollTop = b.scrollHeight;
        return [b.scrollTop, b.scrollHeight - b.clientHeight]; }""")
    page.click("#sf-oh-toggle")
    idle(page, 140)
    bot2 = page.evaluate("""() => { const b = document.querySelector('#tab-body');
        return [b.scrollTop, b.scrollHeight - b.clientHeight]; }""")
    check(bot2[0] == bot2[1] and bot2[0] > 0,
          "scrolled to the very bottom: expanding clamps scrollTop to the new (smaller) maximum — inherent to a taller header, not a reset",
          f"scrollTop {bot[0]} -> {bot2[0]}, reachable max {bot[1]} -> {bot2[1]}")
    page.click("#sf-oh-toggle")
    idle(page, 140)

    section("3h. collapse, reload, and open another file — preference persists and composes with \"hidden\"")
    set_details(True)                                              # known state before the reload
    ctx.add_init_script("""(() => { window.__cls = [];
      new MutationObserver(() => window.__cls.push([performance.now(), document.documentElement.className]))
        .observe(document, {attributes: true, subtree: true, attributeFilter: ['class']}); })();""")
    page.reload()
    ready(page)
    try:                           # same race as above: wait for the browser to record the paint entry
        page.wait_for_function("() => performance.getEntriesByType('paint').some(e => e.name === 'first-paint')",
                               timeout=3000)
    except Exception:
        pass
    g3 = page.evaluate(GEOM_OH)
    t = page.evaluate("""() => { const fp = performance.getEntriesByType('paint').find(e => e.name === 'first-paint');
        const hit = window.__cls.find(c => c[1].includes('sf-oh-collapsed'));
        return {first_paint: fp ? fp.startTime : null, class_applied: hit ? hit[0] : null}; }""")
    check("sf-oh-collapsed" in g3["cls"] and g3["header"]["display"] == "none" and g3["hidden_cls"],
          "after reload with the details collapsed: the preference is restored AND the block stays hidden because no file is loaded",
          f"html='{g3['cls']}' header display={g3['header']['display']}")
    if t["first_paint"] is not None and t["class_applied"] is not None:
        check(t["class_applied"] <= t["first_paint"], "the details preference is applied before the first paint (no flash of the expanded block)",
              f"class at {t['class_applied']:.1f} ms, first paint at {t['first_paint']:.1f} ms")
    else:
        check(False, "paint timing available", str(t))
    page.click("#recent-list .rec-item")
    page.wait_for_function("() => document.querySelector('#oh-name').textContent.includes('pixel')", timeout=20000)
    page.wait_for_function("() => !document.querySelector('#object-header').classList.contains('hidden')", timeout=5000)
    g4 = page.evaluate(GEOM_OH)
    check(g4["aria"] == "false" and g4["details"]["h"] < 1.5 and g4["hidden_cls"] is False,
          "loading a file from RECENT re-shows the block respecting the collapsed preference",
          f"header visible, details.h={g4['details']['h']}, aria={g4['aria']}")
    with page.expect_file_chooser(timeout=5000) as fc:
        page.click("#btn-open")
    fc.value.set_files(DEMO_JSON)
    page.wait_for_function("() => document.querySelector('#oh-name').textContent.includes('data.json')", timeout=20000)
    g5 = page.evaluate(GEOM_OH)
    check(g5["aria"] == "false" and g5["details"]["h"] < 1.5
          and page.inner_text("#oh-format").startswith("json")
          and page.evaluate("document.querySelector('#oh-hash').textContent.length") == 64,
          "opening a DIFFERENT file: the new file's own data is shown (format json, fresh SHA-256) and the collapsed preference still applies",
          f"name={page.inner_text('#oh-name')} format={page.inner_text('#oh-format')}")
    set_details(False)
    g6 = page.evaluate(GEOM_OH)
    check(g6["details"]["h"] > 40 and not anchors_ok(g6)
          and page.evaluate("document.querySelectorAll('#oh-caps .cap').length") > 0,
          "expanding it shows the new file's details fully (capability chips populated, anchors intact)",
          anchors_ok(g6) or f"details.h={g6['details']['h']}")

    section("3h. keyboard, rapid clicks, reduced motion, and the other two toggles")
    set_details(False)
    page.focus("#sf-oh-toggle")
    page.keyboard.press("Enter")
    idle(page, 140)
    kb1 = page.evaluate("document.documentElement.classList.contains('sf-oh-collapsed')")
    page.keyboard.press("Space")
    idle(page, 140)
    kb2 = page.evaluate("document.documentElement.classList.contains('sf-oh-collapsed')")
    check(kb1 and not kb2, "the arrow works from the keyboard (Enter collapses, Space expands)")
    gq = page.evaluate(GEOM_OH)
    page.click("#sf-oh-toggle")
    page.wait_for_timeout(80)
    page.click("#sf-oh-toggle")
    idle(page, 150)
    gr = page.evaluate(GEOM_OH)
    ok, why = rects_equal({k: gr[k] for k in ("header", "tabs", "body", "content")},
                          {k: gq[k] for k in ("header", "tabs", "body", "content")},
                          ("header", "tabs", "body", "content"))
    check(ok and page.evaluate("document.getAnimations().length") == 0
          and page.evaluate("!document.getElementById('sf-oh-details').getAttribute('style')"),
          "double click mid-animation ends cleanly expanded (no stuck half-state, no leftover inline style)", why)
    set_details(False)                                          # start expanded
    page.emulate_media(reduced_motion="reduce")
    page.wait_for_timeout(150)
    sr = sample_click(page, probes, "#sf-oh-toggle", ms=500)
    idle(page, 140)
    ar = analyse(sr, "details_h")
    check(ar is not None and ar["mid_frames"] == 0 and ar["v1"] == 0
          and page.evaluate("document.documentElement.classList.contains('sf-oh-collapsed')")
          and page.evaluate("!document.getElementById('sf-oh-details').getAttribute('style')"),
          "prefers-reduced-motion: the details snap shut (0 in-between frames) and land in the right state",
          f"{ar['mid_frames'] if ar else '?'} in-between frames, {ar['v0'] if ar else '?'} -> {ar['v1'] if ar else '?'} px")
    page.emulate_media(reduced_motion="no-preference")
    set_details(False)
    gt0 = page.evaluate(GEOM_OH)
    page.click("#sf-top-toggle")
    page.click("#sf-side-toggle")
    idle(page, 140)
    gt1 = page.evaluate(GEOM_OH)
    set_details(True)
    gt2 = page.evaluate(GEOM_OH)
    check(not anchors_ok(gt1) and not anchors_ok(gt2)
          and near((gt1["header"]["h"] - gt2["header"]["h"]), (gt2["body"]["h"] - gt1["body"]["h"]), 2.0)
          and "sf-top-collapsed" in gt2["cls"] and "sf-side-collapsed" in gt2["cls"],
          "with the top bar AND the sidebar already collapsed the details still slide correctly (the freed space goes to #tab-body, the strip stays anchored)",
          f"header {gt1['header']['h']} -> {gt2['header']['h']}, body {gt1['body']['h']} -> {gt2['body']['h']}")
    set_details(False)
    page.click("#sf-top-toggle")
    page.click("#sf-side-toggle")
    idle(page, 140)
    gf = page.evaluate(GEOM_OH)
    check("sf-top-collapsed" not in gf["cls"] and "sf-side-collapsed" not in gf["cls"]
          and gf["aria"] == "true" and near(gf["header"]["h"], gt0["header"]["h"], 1.0),
          "restoring everything leaves all three toggles in the state they were asked for (no interference between them)",
          f"header back to {gf['header']['h']} px, aria={gf['aria']}")
    check(not errs, "zero console errors / uncaught page errors during this section", "; ".join(errs[:3]) or "0 errors")
    ctx.close()
    shutil.rmtree(profile, ignore_errors=True)


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="real-browser check of SUPERFILE's collapsible panels")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--spawn-source", metavar="DIR", help="run desktop_launcher.py --no-browser from this source tree")
    g.add_argument("--spawn-exe", metavar="EXE", help="run this packaged exe (through wine when not on Windows)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--mode", choices=["full", "functional"], default="full")
    ap.add_argument("--dump", help="write the click-through observations to this JSON file")
    ap.add_argument("--baseline", help="JSON written earlier by --dump (previous UI) to compare against")
    ap.add_argument("--orig-ui", help="directory with the previous index.html to prove the original markup is untouched")
    ap.add_argument("--browser", help="path to chromium/chrome/msedge (default: auto-detect, else Playwright's)")
    ap.add_argument("--wine-prefix", help="WINEPREFIX for --spawn-exe on Linux")
    ap.add_argument("--shots", help="directory for screenshots")
    ap.add_argument("--viewport", default="1280x800")
    args = ap.parse_args()
    args.viewport = tuple(int(x) for x in args.viewport.lower().split("x"))
    kind, target = ("source", args.spawn_source) if args.spawn_source else ("exe", args.spawn_exe)
    base = json.load(open(args.baseline)) if args.baseline else None

    with sync_playwright() as pw:
        section("1. click-through of every existing control (toggles untouched)")
        srv = Server(kind, target, args.port, "a", args.wine_prefix)
        srv.start()
        try:
            obs1, errs1 = run_functional(pw, args, srv, cycles=0)
        finally:
            srv.stop()
        say(f"  recorded {leaves(obs1)} observations; console errors: {len(errs1)}")
        check(not errs1, "click-through raised zero console/page errors", "; ".join(errs1[:2]))
        if args.dump:
            json.dump(obs1, open(args.dump, "w"), indent=1, sort_keys=True)
            say(f"  saved -> {args.dump}")
        if base is not None:
            expected, d = expected_additions(base, obs1, diff(base, obs1))
            for x in expected:
                say("      expected (Task C): " + x)
            check(not d, f"A/B: {leaves(obs1)} observations IDENTICAL to the previous UI's baseline "
                         f"({leaves(base)} leaves) apart from the {len(expected)} documented additions",
                  "; ".join(d[:3]) if d else f"{len(expected)} expected additions, 0 unexpected differences")
            for x in d[:12]:
                say("      diff " + x)
        if args.mode == "functional":
            return finish()

        section("2. same click-through AFTER 3 full collapse/expand cycles of both panels")
        srv = Server(kind, target, args.port, "b", args.wine_prefix)
        srv.start()
        try:
            obs2, errs2 = run_functional(pw, args, srv, cycles=3)
        finally:
            srv.stop()
        if base is not None:
            _expected2, d = expected_additions(base, obs2, diff(base, obs2))
        else:
            d = diff(obs1, obs2)
        check(not d, f"after toggling, {leaves(obs2)} observations still IDENTICAL to "
                     f"{'the previous UI baseline' if base is not None else 'the untouched run'} "
                     f"apart from the documented additions",
              "; ".join(d[:3]) if d else "0 unexpected differences")
        for x in d[:12]:
            say("      diff " + x)
        check(not errs2, "zero console/page errors", "; ".join(errs2[:2]))

        srv = Server(kind, target, args.port, "c", args.wine_prefix)
        srv.start()
        try:
            check_served_ui(args, srv, kind, target)
            session_toggles(pw, args, srv)
        finally:
            srv.stop()

        srv = Server(kind, target, args.port, "d", args.wine_prefix)
        srv.start()
        try:
            header_details(pw, args, srv)
        finally:
            srv.stop()

        srv = Server(kind, target, args.port, "e", args.wine_prefix)
        srv.start()
        try:
            session_encryption(pw, args, srv)
        finally:
            srv.stop()
    return finish()


# ---------------------------------------------------------------- Task C: encryption tabs
def session_encryption(pw, args, srv: Server) -> None:
    """Drive the new ENCRYPT / DECRYPT tabs like a user: encrypt a text object with a password,
    inspect the bytes that come out, decrypt it (wrong then right password), open the result through
    the EXISTING viewer, and — where the platform supports it — do a real device-lock round trip."""
    section("7. ENCRYPT / DECRYPT tabs (AES-256-GCM)")
    work = tempfile.mkdtemp(prefix="sf_enc_")
    marker = "ENC-MARKER-%s" % os.urandom(4).hex()
    secret = os.path.join(work, "secret-notes.txt")
    with open(secret, "w", encoding="utf-8") as fh:
        fh.write(marker + "\nthe quick brown fox jumps over the lazy dog\n" * 6)
    lockable = json.loads(urllib.request.urlopen(srv.url + "api/health", timeout=20).read())["device_lock"]
    deliberate_expected = 1        # the wrong-password attempt; +1 when device mode can be exercised too
    say(f"  server reports device_lock={lockable} (platform: {'Windows/wine' if lockable else 'not Windows'})")

    profile = tempfile.mkdtemp(prefix="sfui_prof_")
    ctx = launch(pw, args, profile)
    errs: list = []
    try:
        page = ctx.new_page()
        attach(page, errs)
        page.goto(srv.url)
        ready(page)

        # the two new controls exist where the spec puts them and behave like the other tabs
        page.click("#btn-encrypt")
        check(page.evaluate("() => document.querySelector('#tab-encrypt').classList.contains('active')"),
              "#btn-encrypt opens the ENCRYPT tab")
        check(page.inner_text("#tab-encrypt").strip() == "open an object first",
              "ENCRYPT with nothing loaded shows the defensive 'open an object first' message")
        page.click("#btn-decrypt")
        check(page.evaluate("() => document.querySelector('#tab-decrypt').classList.contains('active')"),
              "#btn-decrypt opens the DECRYPT tab with no object loaded")

        with page.expect_file_chooser(timeout=5000) as fc:      # load the secret through the normal OPEN
            page.click("#btn-open")
        fc.value.set_files(secret)
        page.wait_for_function("() => document.querySelector('#oh-name').textContent.includes('secret-notes')",
                               timeout=30000)
        settle(page, "#tab-view")
        page.click("#btn-encrypt")
        pane = settle(page, "#tab-encrypt")
        check("ENCRYPT & SAVE .SFP" in pane and "open an object first" not in pane,
              "with an object loaded the ENCRYPT tab renders the form (not the defensive message)",
              f"{len(pane)} chars of pane text, object label: {'secret-notes.txt' in pane}")

        # --- password entry gates GO ---
        check(page.evaluate("() => document.querySelector('#enc-go').disabled"),
              "GO starts disabled (no password, no acknowledgement)")
        page.fill("#enc-pw1", "correct-horse")
        page.fill("#enc-pw2", "battery-staple")
        check(page.evaluate("() => !document.querySelector('#enc-pwerr').classList.contains('hidden')")
              and "do not match" in page.inner_text("#enc-pwerr"),
              "mismatched confirmation shows the inline error")
        check(page.evaluate("() => document.querySelector('#enc-go').disabled"),
              "GO stays disabled while the two passwords differ")
        page.fill("#enc-pw2", "correct-horse")
        check(page.evaluate("() => document.querySelector('#enc-go').disabled"),
              "GO still disabled until the acknowledgement checkbox is ticked")
        check("There is no password recovery" in page.inner_text("#enc-warn")
              and "including you" in page.inner_text("#enc-warn"),
              "the no-recovery warning is shown next to the acknowledgement")
        page.check("#enc-ack")
        check(page.evaluate("() => !document.querySelector('#enc-go').disabled"),
              "GO becomes enabled once passwords match AND the warning is acknowledged")

        # --- a normal SAVE AS .SFP first, so the container magic can be compared like-for-like ---
        with page.expect_download(timeout=60000) as plain_dl:
            page.click("#btn-save-sfp")
        plain_magic = open(plain_dl.value.path(), "rb").read()[:8]
        check(plain_magic == b"\x8bSFP\r\n\x1a\n",      # the documented SUPERFILE container magic
              "SAVE AS .SFP (unchanged) still writes the .sfp magic", plain_magic.hex())

        # --- encrypt & save ---
        with page.expect_download(timeout=60000) as dl:
            page.click("#enc-go")
        out = dl.value.path()
        blob = open(out, "rb").read()
        name = dl.value.suggested_filename
        check(name == "secret-notes.encrypted.sfp", "download keeps the object's name with .encrypted.sfp", name)
        check(blob[:8] == plain_magic, "the encrypted download is a real .sfp container (same magic as SAVE AS)",
              blob[:8].hex())
        check(b"ENCR" in blob, "it carries the ENCR chunk (mode/kdf/salt/nonce framing, all non-secret)")
        check(marker.encode() not in blob, "THE PLAINTEXT IS GONE: the marker text does not appear in the bytes")
        check(b"quick brown fox" not in blob, "the file's decoded text does not appear in the bytes")
        check(b"secret-notes" not in blob, "not even the original filename is readable in the bytes")
        msg = page.inner_text("#enc-msg")
        check(msg.startswith("Encrypted and saved as"), "the tab reports success with the real filename", msg)
        if args.shots:
            page.screenshot(path=os.path.join(args.shots, "07_encrypt_tab.png"))

        # --- decrypt: wrong password first ---
        page.click("#btn-decrypt")
        page.set_input_files("#dec-file", out)
        page.fill("#dec-pw", "not-the-password")
        page.click("#dec-go")
        page.wait_for_function(
            "() => !document.querySelector('#dec-msg').innerText.match(/decrypting/)", timeout=60000)
        bad_msg = page.inner_text("#dec-msg")
        check("wrong password" in bad_msg, "wrong password reports the specific failure", bad_msg)
        check(page.evaluate("() => document.querySelector('#dec-result').innerHTML === ''"),
              "wrong password shows NO success block (no false success)")

        # --- decrypt: correct password, then open through the existing viewer ---
        page.fill("#dec-pw", "correct-horse")
        page.click("#dec-go")
        page.wait_for_function("() => !!document.querySelector('#dec-open')", timeout=60000)
        ok_msg = page.inner_text("#dec-msg")
        check("secret-notes-decrypted.sfp" in ok_msg, "correct password reports the decrypted filename", ok_msg)
        page.click("#dec-open")                                   # reuses loadObject()
        page.wait_for_function("() => document.querySelector('#tab-view').classList.contains('active')",
                               timeout=30000)
        page.wait_for_function("() => document.querySelector('#oh-name').textContent.includes('secret-notes')",
                               timeout=30000)
        viewed = settle(page, "#tab-view")
        check(marker in viewed, "OPEN THIS FILE lands in the normal VIEW tab with the content intact")
        check(viewed.count("quick brown fox") == 6 and marker in viewed,
              "the whole decoded text came back, not a stub",
              f"{len(viewed)} chars, {viewed.count('quick brown fox')} body lines (source file had 6)")
        if args.shots:
            page.screenshot(path=os.path.join(args.shots, "08_decrypted_view.png"))

        # --- device-lock mode: real DPAPI on Windows, honestly greyed out elsewhere ---
        page.click("#btn-encrypt")
        dev = page.evaluate("() => document.querySelector('#enc-mode-dev').disabled")
        if lockable:
            check(not dev, "device radio is available on this platform")
            page.check("#enc-mode-dev")
            note = page.inner_text("#tab-encrypt")
            check("No password — this file will only open on this computer." in note,
                  "device mode shows its own note instead of password fields")
            check(page.evaluate(
                      "() => document.querySelector('#enc-pwblock').classList.contains('hidden')"),
                  "the password inputs are hidden in device mode")
            check(page.evaluate("() => !document.querySelector('#enc-ack').closest('.hidden')"),
                  "the warning + acknowledgement stay visible in device mode")
            page.check("#enc-ack")
            with page.expect_download(timeout=60000) as dl:
                page.click("#enc-go")
            dev_out = dl.value.path()
            dev_blob = open(dev_out, "rb").read()
            check(marker.encode() not in dev_blob, "device-locked file holds no readable plaintext either")
            page.click("#btn-decrypt")
            page.set_input_files("#dec-file", dev_out)
            page.check("#dec-mode-dev")
            page.click("#dec-go")
            page.wait_for_function("() => !!document.querySelector('#dec-open')", timeout=60000)
            check("secret-notes" in page.inner_text("#dec-msg"),
                  "same machine unlocks its own device-locked file with no password")
            # the master key really is kept in this user's app dir, DPAPI-protected
            found = [os.path.join(dp, fn) for dp, _dn, fns in os.walk(srv.home)
                     for fn in fns if fn == "device-key.json"]
            if not found and srv.wine_prefix:
                # wine resolves %LOCALAPPDATA% from the prefix and ignores our override, so look the key
                # up by the EXACT rule superfile/crypto.py uses - a deep walk once picked up a stale
                # leftover keyring from an unrelated run and the "different device" test then hung.
                users = os.path.join(srv.wine_prefix, "drive_c", "users")
                for user in (sorted(os.listdir(users)) if os.path.isdir(users) else []):
                    cand = os.path.join(users, user, "AppData", "Local", "Superfile", "device-key.json")
                    if os.path.isfile(cand):
                        found.append(cand)
                if found:
                    say("      note: wine resolves %LOCALAPPDATA% itself -> " + found[0])
            check(bool(found), "the device key is kept in this user's app data dir (not in the project dir)",
                  found[0] if found else "no device-key.json found (looked under %s)" % srv.home)
            if found:
                ring = json.load(open(found[0]))
                blob = ring.get("device", {}).get("protected") or ""
                check(len(blob) > 100 and bool(ring["device"].get("device_ref")),
                      "the stored master key is a DPAPI-protected blob, not plaintext",
                      f"{len(blob)} chars of protected data, device_ref={ring['device'].get('device_ref')}")
                # --- simulated different device: a machine that does not hold this key ---
                hidden = found[0] + ".other-device"
                os.rename(found[0], hidden)
                try:
                    page.click("#dec-go")
                    page.wait_for_function(
                        "() => document.querySelector('#dec-msg').innerText.includes('different device')", timeout=60000)
                    check(page.inner_text("#dec-msg").strip()
                          == "This file was locked to a different device, or needs a password.",
                          "a DIFFERENT device (keyring absent, as on another computer) gets the exact message")
                    check(page.evaluate("() => document.querySelector('#dec-result').innerHTML === ''"),
                          "the different-device failure shows no success block")
                finally:
                    os.rename(hidden, found[0])               # put this machine's key back
                deliberate_expected = 2                   # + the different-device attempt
                page.click("#dec-go")                         # ... and it still works here
                page.wait_for_function("() => !!document.querySelector('#dec-open')", timeout=60000)
                check(True, "the original device still unlocks the file afterwards")
        else:
            check(dev, "device radio is disabled (not faked) on this platform")
            note = page.inner_text("#tab-encrypt")
            check("device-lock mode is Windows-only in this build" in note,
                  "the greyed-out radio says why", [l for l in note.splitlines() if "Windows-only" in l][:1])
            check(page.evaluate("() => encDeviceLock()") is False,
                  "the UI takes the capability from the server flag (encDeviceLock() === false)")
        # The wrong-password and different-device attempts are SUPPOSED to fail, and the server answers them
        # with a clean HTTP 400 + {ok:false,error:...}; Chromium logs every non-2xx response to the console.
        # So the real requirements are: no uncaught exception, no 5xx, exactly those two 400s.
        deliberate = [e for e in errs if e.startswith("console.error: Failed to load resource") and " 400 " in e + " "]
        real = [e for e in errs if e not in deliberate]
        check(not [e for e in errs if e.startswith("pageerror")],
              "no uncaught JavaScript exception anywhere in the encryption flow",
              "; ".join(e for e in errs if e.startswith("pageerror"))[:200] or "0 page errors")
        check(not real, "no unexpected console errors (the deliberate failures are filtered)",
              "; ".join(real[:2]) if real else f"{len(deliberate)} deliberate 400 responses filtered")
        check(len(deliberate) == deliberate_expected,
              f"exactly the {deliberate_expected} deliberate failure(s) came back as HTTP 400 — no hidden 5xx",
              "; ".join(deliberate)[:220] or f"{len(deliberate)} recorded")
    finally:
        ctx.close()
        shutil.rmtree(profile, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)


def finish() -> int:
    bad = [r for r in RESULTS if not r[0]]
    say("\n" + "=" * 72)
    say(f"RESULT: {len(RESULTS) - len(bad)} passed, {len(bad)} failed, {len(RESULTS)} checks")
    for ok, name, detail in bad:
        say(f"  FAILED: {name}  [{detail}]")
    say("=" * 72)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
